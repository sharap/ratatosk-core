//! Автоматический стенд: то же, что проверяется руками, но само.
//!
//! Ручной стенд (`crates/lab`) незаменим там, где нужны настоящие сокеты:
//! маяк в эфире, привязка к адресу в меше, порядок настроек при подъёме.
//! Но всё, что **выше** транспорта, он проверяет дорого — руками, по одному
//! разу и только то, о чём догадались потыкать. Здесь то же самое гоняется
//! на каждом прогоне.
//!
//! # Чем это отличается от `scenarios.rs`
//!
//! Тот файл про §16: перестановки, разделение сети, сходимость. Он молчит
//! про группы (§11) и не умеет перезапуска, а обе поломки этой недели жили
//! ровно там.
//!
//! # Почему настоящее хранилище, а не память
//!
//! Это главный урок последней поломки, и он стоил дня разбора. Копии
//! группового сообщения теряли всех получателей, кроме одного, потому что
//! `MemoryStore` держал очередь в карте по `MsgId`. Проверка на памяти
//! повторяла ошибку хранилища — и «все копии в очереди» было бы истинным
//! на пустом месте.
//!
//! Отсюда правило стенда: **`SqliteStore` на временном файле, как в жизни**.
//! Заодно это делает настоящим перезапуск: узел закрывает базу, открывает
//! заново и поднимается `restore` — тем же путём, что телефон после того,
//! как его убила система.
//!
//! # Что стенд не проверяет
//!
//! Сокетов здесь нет: сеть виртуальная, время виртуальное, рукопожатия
//! настоящие. Транспортная проводка — раннеры, привязки, порядок эффектов
//! при подъёме — остаётся ручному стенду и метелкам. Обещать больше, чем
//! проверяется, §14 запрещает и здесь.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, OsEntropy};
use ratatosk_crypto::Identity;
use ratatosk_proto::Transport;
use ratatosk_sim::{Ctx, LinkProfile, NodeId, Sim, SimNode, TransportKind};
use ratatosk_store::{FsBlobs, SqliteStore, Store};
use zeroize::Zeroizing;

type Node = ratatosk_core::Engine<SqliteStore>;

/// Каталог узла: база, вложения и всё, что переживает перезапуск.
///
/// Живёт до конца прогона и уносится с ним. Отдельный каталог на узел,
/// а не одна база на всех: два узла в одной базе — это не два устройства,
/// а одно, и половина сценариев потеряла бы смысл.
struct Home(PathBuf);

/// Счётчик каталогов — чтобы имя не зависело от сида.
///
/// **Ловушка, стоившая часа разбора.** Имя каталога складывалось из сида
/// и номера узла, а сид выбирает человек, пишущий сценарий. Два сценария
/// с одним сидом — а один из здешних перебирает сразу четыре — открывают
/// один каталог, и `remove_dir_all` в начале второго сносит базу
/// **из-под работающего первого**. Наружу это выходит как
/// `database disk image is malformed` на приёме кадра: сообщение, по
/// которому нипочём не догадаться, что дело в имени каталога.
///
/// Сид остаётся в имени — по нему удобно искать в `/tmp`, — но
/// единственность даёт счётчик. Порядковый номер процесса рядом с ним
/// затем, что `cargo test` в двух окнах это два процесса с одним
/// счётчиком.
static NEXT_HOME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Home {
    fn new(seed: u64, index: u16) -> Home {
        let unique = NEXT_HOME.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("ratatosk-stand-{seed:x}-{index}-{pid}-{unique}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("каталог узла");
        Home(dir)
    }

    fn db(&self) -> PathBuf {
        self.0.join("db.sqlite")
    }

    fn blobs(&self) -> PathBuf {
        self.0.join("files")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Узел стенда: настоящее ядро на настоящем хранилище.
struct Peer {
    /// Ядро. `Option` ровно ради перезапуска: прежнее ядро обязано
    /// **закрыться до** того, как откроется новое, — две ручки к одному
    /// файлу это не перезапуск, а два устройства. Без `Option` старое
    /// значение неоткуда вынуть, не поставив на его место новое.
    engine: Option<Node>,
    /// Куда слать: чужой `IK` → номер узла в симуляции.
    peers: BTreeMap<[u8; 32], NodeId>,
    /// Что ядро сказало UI. По этому и проверяется исход.
    events: Vec<Event>,
    /// Зерно личности — нужно перезапуску: личность обязана быть той же.
    seed: u8,
    home: Home,
    /// Заведена ли у узла почта. Перезапуск обязан поднять его таким же:
    /// узел, у которого ящика не было, после перезапуска его не заводит.
    mail: bool,
}

/// Ключ базы. Один на все узлы стенда: PIN здесь не изучается, а разные
/// ключи только добавили бы строк, ничего не проверяя.
fn db_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0x5a; 32])
}

impl Peer {
    fn new(seed: u8, run: u64, mail: bool) -> Peer {
        let home = Home::new(run, u16::from(seed));
        let engine = Peer::open(seed, &home, mail);
        Peer { engine: Some(engine), peers: BTreeMap::new(), events: Vec::new(), seed, home, mail }
    }

    /// Открывает ядро на каталоге узла — и при заведении, и при перезапуске.
    ///
    /// Одно место на оба случая нарочно: перезапуск обязан открывать базу
    /// **тем же** способом, что и первый запуск. Разойдись они, стенд
    /// проверял бы не перезапуск, а свою вторую редакцию его.
    fn open(seed: u8, home: &Home, mail: bool) -> Node {
        let mut store = SqliteStore::open(&home.db(), db_key()).expect("база открывается");
        store.migrate().expect("миграции");
        let name = format!("узел{seed}");
        let mut engine = Engine::new(
            Identity::from_seed([seed; 32]),
            store,
            Box::new(FsBlobs::new(home.blobs())),
            Box::new(OsEntropy),
            SelfAddresses {
                // Онион у всех есть: без адреса §5.4 честно отвечает «ехать
                // некуда», и половина сценариев проверяла бы это вместо
                // того, что в них написано.
                onion: ratatosk_crypto::OnionKey::from_seed([seed; 32]).address(),
                // Почта бывает и не заведена, и это не редкость: ящик
                // заводит человек сам, а до тех пор последней ступени §5.4
                // у него нет вовсе. Пустой адрес — ровно это и означает:
                // §4.1 не везёт его в карточке, `availability.has_chatmail`
                // у собеседников остаётся ложью, и почту §5.4 не выбирает.
                chatmail: if mail { format!("{name}@nine.example") } else { String::new() },
                display_name: name,
            },
        );
        engine.restore().expect("подъём с диска");
        engine
    }

    /// Ядро — там, где оно точно есть: между шагами стенда его не бывает
    /// пустым, пусто оно ровно на время перезапуска.
    fn engine(&self) -> &Node {
        self.engine.as_ref().expect("ядро на месте вне перезапуска")
    }

    fn engine_mut(&mut self) -> &mut Node {
        self.engine.as_mut().expect("ядро на месте вне перезапуска")
    }

    fn ik(&self) -> [u8; 32] {
        self.engine().own_card().ik
    }

    /// Исполняет эффекты ядра: отправки уходят в сеть, новости копятся.
    fn apply(&mut self, ctx: &mut Ctx<'_>, effects: Vec<Effect>) {
        // Подтверждения передачи собираются, а не исполняются на месте:
        // иначе `apply` звал бы сам себя из середины разбора, и порядок
        // отправок зависел бы от глубины этого зова.
        let mut handed = Vec::new();
        for effect in effects {
            match effect {
                Effect::Send { peer_ik, via, frame, handoff } => {
                    let Some(&to) = self.peers.get(&peer_ik) else {
                        panic!("некуда слать: узел с таким IK в стенде не заведён");
                    };
                    ctx.send(to, to_sim(via), frame);
                    if let Some(handoff) = handoff {
                        handed.push(Input::Handed { peer_ik, via, handoff });
                    }
                }
                Effect::Notify(event) => self.events.push(event),
                Effect::SetTimer { after_ms, token } => ctx.set_timer(after_ms, token),
                Effect::Connect { .. }
                | Effect::SetTransportEnabled { .. }
                | Effect::WatchLanPeers(_)
                | Effect::SetMailAccount(_)
                | Effect::SetYgg(_)
                | Effect::CreateMailAccount { .. }
                | Effect::RestartLan => {}
            }
        }
        for input in handed {
            let effects =
                self.engine_mut().step(ctx.now_ms(), input).expect("подтверждение передачи");
            self.apply(ctx, effects);
        }
    }

    fn command(&mut self, ctx: &mut Ctx<'_>, command: Command) {
        let effects = self
            .engine_mut()
            .step(ctx.now_ms(), Input::Command(command))
            .expect("команда не должна отказывать");
        self.apply(ctx, effects);
    }

    /// Что человек видит в чате, в порядке показа (§9.1).
    fn seen(&self, chat: [u8; 16]) -> Vec<String> {
        self.engine()
            .store()
            .messages(&chat, 1_000, None)
            .expect("история")
            .into_iter()
            .map(|m| String::from_utf8_lossy(&m.body).into_owned())
            .collect()
    }
}

impl SimNode for Peer {
    fn on_deliver(&mut self, ctx: &mut Ctx<'_>, _from: NodeId, kind: TransportKind, bytes: &[u8]) {
        let effects = self
            .engine_mut()
            .step(ctx.now_ms(), Input::Received { via: to_proto(kind), frame: bytes.to_vec() })
            .expect("приём кадра не должен отказывать");
        self.apply(ctx, effects);
    }

    fn on_timer(&mut self, ctx: &mut Ctx<'_>, token: u64) {
        let effects = self.engine_mut().step(ctx.now_ms(), Input::Timer { token }).expect("таймер");
        self.apply(ctx, effects);
    }

    fn on_send_failed(&mut self, ctx: &mut Ctx<'_>, to: NodeId, kind: TransportKind) {
        let Some((&peer_ik, _)) = self.peers.iter().find(|(_, id)| **id == to) else {
            return;
        };
        let effects = self
            .engine_mut()
            .step(ctx.now_ms(), Input::ConnectFailed { peer_ik, via: to_proto(kind) })
            .expect("отказ транспорта не должен ронять ядро");
        self.apply(ctx, effects);
    }
}

fn to_proto(kind: TransportKind) -> Transport {
    match kind {
        TransportKind::Lan => Transport::Lan,
        TransportKind::Ygg => Transport::Ygg,
        TransportKind::Onion => Transport::Onion,
        TransportKind::Mail => Transport::Mail,
    }
}

fn to_sim(transport: Transport) -> TransportKind {
    match transport {
        Transport::Lan => TransportKind::Lan,
        Transport::Ygg => TransportKind::Ygg,
        Transport::Onion => TransportKind::Onion,
        Transport::Mail => TransportKind::Mail,
    }
}

/// Стенд целиком: сеть, узлы и словарь действий.
///
/// Словарь нарочно похож на команды ручного стенда — `say`, `offline`,
/// `restart`, — чтобы сценарий читался как запись сеанса за консолью,
/// а не как обход внутренностей ядра.
struct Stand {
    sim: Sim<Peer>,
}

/// Предел шагов на одно «дать сети затихнуть».
///
/// Щедрый, и это не послабление: он ловит **кольцо** событий, а кольцо
/// не сходится ни при каком пределе. Честный разговор троих с почтой
/// в запасе стоит сотен шагов.
const MAX_STEPS: usize = 20_000;

impl Stand {
    /// Собирает стенд из `count` узлов и знакомит всех со всеми (§4.2).
    fn new(seed: u64, count: u16) -> Stand {
        Stand::build(seed, count, true)
    }

    /// То же, но **без почты ни у кого**.
    ///
    /// Так выглядит живое устройство, пока человек не завёл себе ящик: адрес
    /// пуст, §4.1 не везёт его в карточке, `has_chatmail` у собеседников
    /// остаётся ложью — и последней ступени §5.4 просто нет. Тогда сообщение
    /// недостижимому участнику обязано **ждать в очереди** и уехать, когда
    /// тот вернётся.
    ///
    /// Со включённой почтой этот путь не проверяется вовсе: письмо уходит
    /// в спул и доезжает само, минуя всю логику ожидания. А проверять его
    /// надо: именно так стоят стенды, на которых отлаживается меш.
    fn without_mail(seed: u64, count: u16) -> Stand {
        Stand::build(seed, count, false)
    }

    fn build(seed: u64, count: u16, mail: bool) -> Stand {
        let mut nodes: Vec<Peer> = (0..count)
            .map(|i| Peer::new(u8::try_from(i + 1).expect("узлов не больше 254"), seed, mail))
            .collect();

        let cards: Vec<(NodeId, [u8; 32], Vec<u8>)> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                (
                    NodeId(u16::try_from(i).expect("узлов не больше 65535")),
                    n.ik(),
                    n.engine().own_card().encode().expect("карточка кодируется"),
                )
            })
            .collect();
        for node in &mut nodes {
            for (id, ik, _) in &cards {
                node.peers.insert(*ik, *id);
            }
        }

        let mut sim = Sim::new(seed, nodes);

        // Потери на почте убраны, на прямых каналах — оставлены, и это
        // не половинчатость. Об отказе прямого канала транспорт сообщает,
        // и ядро обязано повторить попытку (§5.4) — пусть проверяется
        // на каждом прогоне. Почта же об отказе не сообщает и квитанций
        // не шлёт (§9.4): потерянное письмо обнаружить нечем, и требовать
        // от протокола устойчивости к такой потере значило бы требовать
        // того, чего v1 не обещает.
        sim.net_mut().set_profile(
            TransportKind::Mail,
            LinkProfile { loss_permille: 0, ..LinkProfile::MAIL },
        );

        sim.start();

        // Знакомство — как при встрече по QR: карточка каждому от каждого.
        for i in 0..count {
            for (_, ik, card) in &cards {
                if *ik == sim.node(NodeId(i)).ik() {
                    continue;
                }
                let card = card.clone();
                sim.act(NodeId(i), |node, ctx| {
                    node.command(
                        ctx,
                        Command::AddContact { card_bytes: card, met_in_person: true },
                    );
                });
            }
        }

        // Onion объявляется работающим сразу: стенд проверяет протокол,
        // а не подъём Tor. Почта — тоже, иначе последняя ступень §5.4
        // не выбиралась бы вовсе и осталась непроверенной молча.
        let ready: &[Transport] =
            if mail { &[Transport::Onion, Transport::Mail] } else { &[Transport::Onion] };
        for i in 0..count {
            for transport in ready {
                let transport = *transport;
                sim.act(NodeId(i), |node, ctx| {
                    let effects = node
                        .engine_mut()
                        .step(ctx.now_ms(), Input::TransportReady { transport })
                        .expect("готовность транспорта");
                    node.apply(ctx, effects);
                });
            }
        }

        let mut stand = Stand { sim };
        stand.settle();
        stand
    }

    /// Даёт сети затихнуть: всё, что в пути, доезжает, все сроки выходят.
    fn settle(&mut self) {
        match self.sim.run_to_idle(MAX_STEPS) {
            Ok(_) => {}
            Err(done) => panic!(
                "сеть не затихла за {done} шагов: кольцо событий или срок, взводящий сам себя \
                 (сид {:#x})",
                self.sim.seed()
            ),
        }
    }

    fn ik(&self, who: NodeId) -> [u8; 32] {
        self.sim.node(who).ik()
    }

    /// Заводит группу и отдаёт её идентификатор.
    fn create_group(&mut self, owner: NodeId, title: &str) -> [u8; 16] {
        let title = title.to_owned();
        let events = self.sim.act(owner, |node, ctx| {
            let before = node.events.len();
            node.command(ctx, Command::CreateGroup { title });
            node.events[before..].to_vec()
        });
        events
            .iter()
            .find_map(|e| match e {
                Event::GroupCreated { chat, .. } => Some(*chat),
                _ => None,
            })
            .expect("о заведении группы обязано прийти событие")
    }

    fn invite(&mut self, owner: NodeId, chat: [u8; 16], guest: NodeId) {
        let peer_ik = self.ik(guest);
        self.sim.act(owner, |node, ctx| {
            node.command(ctx, Command::InviteToGroup { chat, peer_ik });
        });
    }

    /// Исключает участника (§11.2 — вправе только создатель).
    fn evict(&mut self, owner: NodeId, chat: [u8; 16], guest: NodeId) {
        let peer_ik = self.ik(guest);
        self.sim.act(owner, |node, ctx| {
            node.command(ctx, Command::EvictFromGroup { chat, peer_ik });
        });
    }

    /// Говорит в чат — хоть в групповой, хоть в разговор двоих.
    fn say(&mut self, who: NodeId, chat: [u8; 16], text: &str) {
        let text = text.to_owned();
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::SendText { chat, text });
        });
    }

    /// Пересылает названные сообщения в чат — хоть в групповой, хоть в 1:1.
    fn forward(&mut self, who: NodeId, chat: [u8; 16], msg_ids: &[[u8; 16]]) {
        let msg_ids = msg_ids.to_vec();
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::ForwardMessages { chat, msg_ids: msg_ids.clone() });
        });
    }

    /// Делится карточкой известного человека — туда же, куда и говорит.
    fn share_contact(&mut self, who: NodeId, chat: [u8; 16], peer_ik: [u8; 32]) {
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::ShareContact { chat, peer_ik });
        });
    }

    /// Чат разговора двоих — по тому же правилу, что у ядра.
    fn chat_with(&self, whom: NodeId) -> [u8; 16] {
        Engine::<SqliteStore>::chat_id_for(&self.ik(whom))
    }

    fn offline(&mut self, who: NodeId) {
        self.sim.set_online(who, false);
    }

    fn online(&mut self, who: NodeId) {
        self.sim.set_online(who, true);
    }

    /// Перезапускает узел: база закрывается и открывается заново.
    ///
    /// Настоящий перезапуск, а не сброс полей: личность, контакты, группы
    /// и очередь поднимаются `restore` с диска — тем же путём, каким это
    /// делает телефон после того, как его убила система. Ровно здесь жили
    /// две поломки этой недели, и обе были невидимы для проверок в памяти.
    fn restart(&mut self, who: NodeId) {
        self.sim.act(who, |node, ctx| {
            // Прежнее ядро закрывается **до** открытия нового: две ручки
            // к одному файлу — это не перезапуск, а два устройства.
            let seed = node.seed;
            let mail = node.mail;
            // Порядок здесь и есть смысл: старое ядро закрывает базу,
            // и только потом открывается новое.
            drop(node.engine.take());
            let fresh = Peer::open(seed, &node.home, mail);
            node.engine = Some(fresh);

            // И то, ради чего перезапуск вообще проверяется: поднятое
            // с диска обязано доехать до транспортов и до собеседников.
            let effects = node.engine_mut().startup_effects();
            node.apply(ctx, effects);

            // Onion после перезапуска поднимается заново — как и в жизни.
            for transport in [Transport::Onion, Transport::Mail] {
                let effects = node
                    .engine_mut()
                    .step(ctx.now_ms(), Input::TransportReady { transport })
                    .expect("готовность транспорта");
                node.apply(ctx, effects);
            }
        });
    }

    /// Что человек видит в чате — то самое, ради чего всё остальное.
    ///
    /// При расхождении печатается состояние **всех** узлов, а не только
    /// провинившегося. Групповое сообщение теряется по одной из трёх
    /// причин, и различить их можно только глядя на обе стороны разом:
    /// его не поставили в очередь, оно не уехало, или оно приехало
    /// и не открылось. Утверждение без этой картины отправляет читать код
    /// с самого начала — что после первого же прогона и случилось.
    #[track_caller]
    fn assert_seen(&self, who: NodeId, chat: [u8; 16], expected: &[&str]) {
        let seen = self.sim.node(who).seen(chat);
        let expected: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
        if seen != expected {
            self.dump(chat);
        }
        assert_eq!(seen, expected, "узел {} видит не то (сид {:#x})", who.index(), self.sim.seed());
    }

    /// Печатает состояние стенда: кто что знает и что у кого застряло.
    ///
    /// Четыре вопроса на узел, и каждый отсекает свою причину:
    ///
    /// * **состав** — знает ли узел группу и всех ли в ней видит;
    /// * **цепочки отправителей** — есть ли чем открыть чужое слово (§11.1),
    ///   и на каком они номере; отсутствие цепочки и есть самая частая
    ///   причина тишины, а разошедшийся номер — вторая;
    /// * **очередь** — не лежит ли сказанное неотправленным;
    /// * **отложенное** — не лежит ли **принятое**. Кадр про группу, которой
    ///   узел ещё не знает, или от участника без карточки, или под ключом,
    ///   которого ещё нет, откладывается до появления недостающего. Снаружи
    ///   «не пришло» и «пришло и лежит» неотличимы ничем, кроме этой строки,
    ///   а починки у них разные;
    /// * **аномалии** — все четыре счётчика, а не один. Ненулевой при живой
    ///   сети означает, что кадр **дошёл и не открылся**, то есть ключ
    ///   разошёлся, а не потерялся. Уровни при этом разные: `тег` — сессия
    ///   1:1 (§8.3), `порча` — уже разбор содержимого. Печатай мы один,
    ///   второй случай читался бы как «не приходило вовсе», и разбор ушёл бы
    ///   искать потерю в сети, которой там нет. Именно этой слепотой обошёлся
    ///   первый круг разбора поломки 5яв.
    fn dump(&self, chat: [u8; 16]) {
        eprintln!("--- стенд, сид {:#x}, время {} мс", self.sim.seed(), self.sim.now_ms());
        let names: Vec<(NodeId, [u8; 32])> = (0..self.sim.len())
            .map(|i| {
                let id = NodeId(u16::try_from(i).expect("узлов не больше 65535"));
                (id, self.ik(id))
            })
            .collect();

        // Метка поворота у **владельца** каждой цепочки — эталон, с которым
        // сравнивается чужая копия. Без него «цепочка есть, номер верный»
        // ничего не говорит: разошедшийся ключ выглядит точно так же, как
        // сошедшийся, и первый круг разбора поломки 5яв ушёл ровно на это.
        let own: BTreeMap<[u8; 32], (u64, u32)> = names
            .iter()
            .filter_map(|(id, ik)| {
                self.sim
                    .node(*id)
                    .engine()
                    .store()
                    .sender_chain(&chat, ik)
                    .expect("своя цепочка")
                    .map(|c| (*ik, (c.chain_wall, c.chain_logical)))
            })
            .collect();

        for (id, _) in &names {
            let peer = self.sim.node(*id);
            let engine = peer.engine();
            eprint!("узел {}: ", id.index());
            match engine.groups().get(&chat) {
                Some(state) => {
                    let members: Vec<String> = state.group.members().map(short).collect();
                    eprint!("состав [{}]", members.join(" "));
                }
                None => eprint!("группы не знает"),
            }

            let chains: Vec<String> = engine
                .store()
                .sender_chains(&chat)
                .expect("цепочки")
                .iter()
                .map(|c| {
                    let mine = (c.chain_wall, c.chain_logical);
                    // `=` копия той же метки, что у владельца; `≠` отставшая
                    // или обогнавшая — то есть **не та** цепочка при верном
                    // номере; `?` владельца в стенде нет.
                    let verdict = match own.get(&c.member_ik) {
                        Some(theirs) if *theirs == mine => "=",
                        Some(_) => "≠",
                        None => "?",
                    };
                    format!("{}@{}#{}.{}{verdict}", short(&c.member_ik), c.counter, mine.0, mine.1)
                })
                .collect();
            eprint!("; цепочки [{}]", chains.join(" "));

            let queued: Vec<String> = engine
                .store()
                .outbox()
                .expect("очередь")
                .iter()
                .map(|e| format!("{}→{}", short_id(&e.msg_id), short(&e.recipient_ik)))
                .collect();
            eprint!("; очередь [{}]", queued.join(" "));

            let parked: Vec<String> = engine
                .parked_group_frames()
                .iter()
                .filter(|(group, _, _)| *group == chat)
                .map(|(_, from, kind)| format!("{}:{kind:?}", short(from)))
                .collect();
            eprint!("; отложено [{}]", parked.join(" "));

            // Все четыре счётчика, а не один. «Пришло и не открылось»
            // бывает на двух разных уровнях, и лечатся они по-разному:
            // `bad_tag` — сессия 1:1 (§8.3), `malformed` — уже разбор
            // содержимого. Печатай мы один, второй случай выглядел бы как
            // «кадр не приходил вовсе» — и разбор ушёл бы искать потерю
            // в сети, которой там нет.
            let noise: Vec<String> = names
                .iter()
                .filter(|(other, _)| other != id)
                .map(|(other, ik)| {
                    let a = engine.anomalies(ik);
                    format!(
                        "{}:{}/{}/{}/{}",
                        other.index(),
                        a.malformed,
                        a.bad_tag,
                        a.unknown_session,
                        a.handshake_replay
                    )
                })
                .collect();
            eprintln!("; аномалии (порча/тег/сессия/повтор) от [{}]", noise.join(" "));

            // **Ничьи аномалии — отдельной строкой, и без неё дамп врал.**
            // Кадр для неизвестной сессии не расшифрован, значит чей он —
            // неизвестно, и §7.3 пишет такую аномалию на нулевой ключ
            // (`on_frame`, ветка `Route::Unknown`). Перебор по известным
            // собеседникам её не видит **никогда**: получатель, у которого
            // нет сессии, показывает ровно те же нули, что и получатель,
            // до которого ничего не доехало.
            let orphan = engine.anomalies(&[0u8; 32]);
            if orphan.total() > 0 {
                eprintln!(
                    "        ничьих кадров: сессия неизвестна {}, набивка/прочее {}",
                    orphan.unknown_session,
                    orphan.total() - orphan.unknown_session
                );
            }
            eprintln!("        видит: {:?}", peer.seen(chat));
        }
        // Сводка сети — последнее, что отсекает «его не отправляли» от
        // «его не довезли». `spooled` при затихшей сети означает письмо,
        // так и лежащее в спуле: получатель, по мнению модели, всё ещё
        // не в сети. Без этой строки такой случай неотличим от потери.
        let stats = self.sim.stats();
        eprintln!(
            "сеть: доставлено {} потеряно {} в спуле {} отказов {} таймеров {}",
            stats.delivered, stats.dropped, stats.spooled, stats.send_failures, stats.timers_fired
        );
        eprintln!("---");
    }

    /// Состав группы, каким его знает этот узел.
    #[track_caller]
    /// Идентификатор сообщения по его тексту — так тест называет цель,
    /// не заглядывая в порядок окна.
    fn msg_id_of(&self, who: NodeId, chat: [u8; 16], text: &str) -> [u8; 16] {
        self.sim
            .node(who)
            .engine()
            .store()
            .messages(&chat, 1_000, None)
            .expect("история")
            .into_iter()
            .find(|m| m.body == text.as_bytes())
            .unwrap_or_else(|| panic!("сообщения «{text}» нет у узла {}", who.index()))
            .msg_id
    }

    /// Помечено ли сообщение пересланным — у того, кто его видит.
    fn is_forwarded(&self, who: NodeId, chat: [u8; 16], text: &str) -> bool {
        self.sim
            .node(who)
            .engine()
            .store()
            .messages(&chat, 1_000, None)
            .expect("история")
            .into_iter()
            .find(|m| m.body == text.as_bytes())
            .unwrap_or_else(|| panic!("сообщения «{text}» нет у узла {}", who.index()))
            .forwarded
    }

    fn assert_members(&self, who: NodeId, chat: [u8; 16], expected: usize) {
        let state = self.sim.node(who).engine().groups().get(&chat);
        let count = state.map_or(0, |state| state.group.members().count());
        assert_eq!(
            count,
            expected,
            "узел {} видит в группе {count} участников вместо {expected} (сид {:#x})",
            who.index(),
            self.sim.seed()
        );
    }
}

/// Начало отпечатка — чтобы в отчёте было видно, о ком речь.
fn short(peer_ik: &[u8; 32]) -> String {
    peer_ik[..3].iter().map(|b| format!("{b:02x}")).collect()
}

/// То же для номера сообщения.
fn short_id(msg_id: &[u8; 16]) -> String {
    msg_id[..3].iter().map(|b| format!("{b:02x}")).collect()
}

const A: NodeId = NodeId(0);
const B: NodeId = NodeId(1);
const C: NodeId = NodeId(2);
const D: NodeId = NodeId(3);

// --- разговор двоих ---------------------------------------------------------

#[test]
fn two_people_talk() {
    // Самое простое, что бывает, и потому первое: если это не работает,
    // разбирать остальное бессмысленно.
    let mut stand = Stand::new(0x5741, 2);
    let chat_from_a = stand.chat_with(B);
    let chat_from_b = stand.chat_with(A);

    stand.say(A, chat_from_a, "привет");
    stand.settle();
    stand.say(B, chat_from_b, "и тебе");
    stand.settle();

    stand.assert_seen(A, chat_from_a, &["привет", "и тебе"]);
    stand.assert_seen(B, chat_from_b, &["привет", "и тебе"]);
}

#[test]
fn a_message_waits_for_someone_who_is_away() {
    // Обещание «отправим, когда появится» (§14) — и его исполнение.
    let mut stand = Stand::new(0x5742, 2);
    let chat = stand.chat_with(B);

    stand.offline(B);
    stand.say(A, chat, "пока тебя не было");
    stand.settle();

    stand.online(B);
    stand.settle();
    stand.assert_seen(B, stand.chat_with(A), &["пока тебя не было"]);
}

#[test]
fn a_restart_does_not_lose_the_conversation() {
    // Перезапуск — не потеря памяти: история, контакты и знакомство
    // переживают его целиком.
    let mut stand = Stand::new(0x5743, 2);
    let chat = stand.chat_with(B);
    stand.say(A, chat, "до перезапуска");
    stand.settle();

    stand.restart(B);
    stand.settle();
    stand.assert_seen(B, stand.chat_with(A), &["до перезапуска"]);

    // И разговор продолжается: перезапуск не обязан стоить рукопожатия
    // человеку, но обязан быть пережит без потерь, если оно понадобится.
    stand.say(A, chat, "после");
    stand.settle();
    stand.assert_seen(B, stand.chat_with(A), &["до перезапуска", "после"]);
}

#[test]
fn a_message_written_before_a_restart_still_leaves() {
    // Очередь на диске существует ровно ради этого случая: человек написал,
    // сети не было, приложение убили. Обещание не должно умереть вместе
    // с процессом.
    let mut stand = Stand::new(0x5744, 2);
    let chat = stand.chat_with(B);

    stand.offline(B);
    stand.say(A, chat, "в очереди");
    stand.settle();

    stand.restart(A);
    stand.online(B);
    stand.settle();

    stand.assert_seen(B, stand.chat_with(A), &["в очереди"]);
}

// --- группы (§11) -----------------------------------------------------------

#[test]
fn a_group_of_three_hears_everyone() {
    // Основа основ для §11.3: копию каждому шлёт сам отправитель, и услышать
    // обязаны **все**, а не большинство.
    let mut stand = Stand::new(0x6741, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.assert_members(A, chat, 3);
    stand.assert_members(B, chat, 3);
    stand.assert_members(C, chat, 3);

    stand.say(A, chat, "от А");
    stand.settle();
    stand.say(B, chat, "от Б");
    stand.settle();

    for who in [A, B, C] {
        stand.assert_seen(who, chat, &["от А", "от Б"]);
    }
}

#[test]
fn a_member_who_was_away_gets_what_was_said() {
    // Ровно та поломка, что нашлась на стенде руками: сообщение теряли
    // участники, до которых в момент отправки было не достучаться, — и
    // теряли навсегда, потому что дошедшая копия уносила их из очереди.
    let mut stand = Stand::new(0x6742, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.offline(C);
    stand.say(A, chat, "пока В спал");
    stand.settle();
    // Б получил — и это важно: именно его получение и уносило копию В.
    stand.assert_seen(B, chat, &["пока В спал"]);

    stand.online(C);
    stand.settle();
    stand.assert_seen(C, chat, &["пока В спал"]);
}

#[test]
fn a_newcomer_hears_what_is_said_right_after_the_invitation() {
    // Вторая половина той же поломки: участник появляется в составе раньше
    // своей карточки (§11.5), и сказанное в это окно ему не доезжало.
    let mut stand = Stand::new(0x6743, 3);
    let chat = stand.create_group(A, "сперва двое");
    stand.invite(A, chat, B);
    stand.settle();
    stand.say(A, chat, "до третьего");
    stand.settle();

    // Приглашение и слово **без паузы между ними**: ровно так это и выглядит
    // у человека, который позвал и тут же продолжил разговор.
    stand.invite(A, chat, C);
    stand.say(A, chat, "сразу после приглашения");
    stand.settle();

    stand.assert_members(C, chat, 3);
    // Сказанное до вступления новичку не полагается (§11.5), сказанное
    // после — обязано дойти.
    stand.assert_seen(C, chat, &["сразу после приглашения"]);
    stand.assert_seen(B, chat, &["до третьего", "сразу после приглашения"]);
}

#[test]
fn two_invitations_in_a_row_do_not_bury_the_fresher_key() {
    // Названная поломка: §11.5 велит проворачивать цепочку при **каждом**
    // вступлении, а §9.2 разрешает переставлять кадры. Два приглашения
    // подряд — и до участника едут два объявления одной цепочки с
    // одинаковым (нулевым после поворота) номером. Пока у блока не было
    // метки старшинства, получатель брал пришедшее последним, и примерно
    // в половине случаев это опоздавшее: номер верный, ключ мёртвый.
    //
    // Дальше сообщения владельца у него **молча** не открывались — снаружи
    // несошедшийся тег неотличим от порчи, — и это ровно то, что человек
    // видел как «доходит не всегда и не до всех, потом чинится, а
    // недошедшие так и не доходят».
    //
    // Несколько сидов нарочно: одна перестановка ловится примерно через
    // раз, и на единственном сиде тест зеленел бы по удаче.
    for seed in [0x6746u64, 0x6747, 0x6748, 0x6749] {
        let mut stand = Stand::new(seed, 3);
        let chat = stand.create_group(A, "трое");
        // Без `settle` между ними: два поворота цепочки А оказываются
        // в проводе одновременно, а это и есть условие поломки.
        stand.invite(A, chat, B);
        stand.invite(A, chat, C);
        stand.settle();

        stand.say(A, chat, "после двух приглашений");
        stand.settle();

        for who in [B, C] {
            stand.assert_seen(who, chat, &["после двух приглашений"]);
        }
    }
}

#[test]
fn one_sleeping_member_does_not_silence_the_others() {
    // Жалоба с живых устройств: «если часть участников оффлайн, до остальных
    // онлайн не до всех доходит». Проверяется именно это — не то, что спящий
    // потом догонит (для этого есть свой сценарий), а то, что **бодрствующие
    // слышат все**. Неудача с одним получателем не говорит про других ничего,
    // и §11.3 не разрешает ей на них влиять.
    //
    // Четверо, а не трое: с тремя «не до всех» вырождается в «до одного
    // из одного», и разница между «слышат все» и «слышит кто-то» пропадает.
    for seed in [0x674au64, 0x674b, 0x674c] {
        let mut stand = Stand::new(seed, 4);
        let chat = stand.create_group(A, "четверо");
        stand.invite(A, chat, B);
        stand.invite(A, chat, C);
        stand.invite(A, chat, D);
        stand.settle();

        stand.offline(D);
        stand.say(A, chat, "пока Г спал");
        stand.settle();

        // Оба бодрствующих — и это главное утверждение сценария.
        stand.assert_seen(B, chat, &["пока Г спал"]);
        stand.assert_seen(C, chat, &["пока Г спал"]);

        stand.online(D);
        stand.settle();
        stand.assert_seen(D, chat, &["пока Г спал"]);
    }
}

#[test]
fn two_sleeping_members_do_not_silence_the_third() {
    // То же, но спящих **больше**, чем бодрствующих: у человека это выглядело
    // именно так — часть группы в сети, часть нет. Если неудача с получателем
    // всё-таки цепляет соседей по списку, здесь это заметнее всего.
    let mut stand = Stand::new(0x674d, 4);
    let chat = stand.create_group(A, "четверо");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.invite(A, chat, D);
    stand.settle();

    stand.offline(C);
    stand.offline(D);
    stand.say(A, chat, "двое спят");
    stand.settle();
    stand.assert_seen(B, chat, &["двое спят"]);

    stand.online(C);
    stand.online(D);
    stand.settle();
    stand.assert_seen(C, chat, &["двое спят"]);
    stand.assert_seen(D, chat, &["двое спят"]);
}

#[test]
fn a_sleeping_member_waits_in_the_queue_when_there_is_no_mail() {
    // Тот же случай, но **без почты** — так это и выглядит на живом
    // устройстве, пока человек не завёл себе ящик: адреса нет, §4.1 не везёт
    // его в карточке, и последней ступени §5.4 просто нет.
    //
    // Тогда обещание §14 держит очередь: копия обязана дождаться возвращения
    // участника. Со включённой почтой этот путь не проверяется вовсе —
    // письмо уходит в спул и доезжает само, минуя всю логику ожидания.
    // А проверять его надо: именно так стоят стенды, на которых отлаживается
    // меш, и именно оттуда пришла жалоба.
    let mut stand = Stand::without_mail(0x674e, 3);
    let chat = stand.create_group(A, "трое без почты");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.offline(C);
    stand.say(A, chat, "почты нет");
    stand.settle();
    stand.assert_seen(B, chat, &["почты нет"]);

    // В возвращается — и **сам подаёт голос**. Это не поблажка сценарию,
    // а честная модель меша: маяка §5.1 там нет, объявить «я вернулся»
    // нечем, и узнать о возвращении можно ровно одним способом — получить
    // от него кадр. Отсюда и правило в `on_data`: любой расшифровавшийся
    // кадр будит отложенное этому собеседнику, а не только пришедший
    // по локальной сети.
    //
    // Пока правила не было, копия лежала до постороннего повода — смены
    // сети, перезапуска, обновления карточки, — а без повода не уезжала
    // никогда.
    stand.online(C);
    stand.settle();
    stand.say(C, chat, "я вернулся");
    stand.settle();

    stand.assert_seen(C, chat, &["почты нет", "я вернулся"]);
    stand.assert_seen(B, chat, &["почты нет", "я вернулся"]);
}

#[test]
fn a_member_brought_back_learns_that_they_are_back() {
    // Вторая жалоба с живых устройств: «если удалить участника и добавить
    // заново, то он не всегда видит, что его вернули в группу».
    //
    // Проверяется и то, и другое: состав у вернувшегося (он снова видит
    // троих) и слух (сказанное после возвращения до него доходит). Первое
    // без второго — картинка, второе без первого — не бывает.
    //
    // Несколько сидов: «не всегда» в жалобе означает перестановку, а её
    // одним сидом не поймать.
    for seed in [0x674fu64, 0x6750, 0x6751] {
        let mut stand = Stand::new(seed, 3);
        let chat = stand.create_group(A, "трое");
        stand.invite(A, chat, B);
        stand.invite(A, chat, C);
        stand.settle();
        stand.say(A, chat, "до исключения");
        stand.settle();

        stand.evict(A, chat, B);
        stand.settle();
        // Исключённому говорят (§11.4): он обязан узнать, что вышел,
        // а не остаться с живой группой, в которой все молчат.
        stand.assert_members(B, chat, 2);

        stand.invite(A, chat, B);
        stand.settle();
        stand.assert_members(B, chat, 3);
        stand.assert_members(C, chat, 3);

        stand.say(A, chat, "после возвращения");
        stand.settle();
        stand.assert_seen(B, chat, &["до исключения", "после возвращения"]);
        stand.assert_seen(C, chat, &["до исключения", "после возвращения"]);
    }
}

#[test]
fn a_member_brought_back_is_heard_again() {
    // Вторая половина возвращения, и её легко забыть: вернувшийся обязан
    // не только слышать, но и **быть услышанным**. §11.5 проворачивает
    // цепочку у каждого при вступлении — значит после возвращения остальные
    // держат новую цепочку вернувшегося, а не ту, что помнили до исключения.
    let mut stand = Stand::new(0x6752, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.evict(A, chat, B);
    stand.settle();
    stand.invite(A, chat, B);
    stand.settle();

    stand.say(B, chat, "снова здесь");
    stand.settle();
    stand.assert_seen(A, chat, &["снова здесь"]);
    stand.assert_seen(C, chat, &["снова здесь"]);
}

#[test]
fn a_group_survives_a_restart() {
    // Группа, состав, цепочки отправителя и очередь — всё это лежит
    // на диске, и всё обязано подняться.
    let mut stand = Stand::new(0x6744, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();
    stand.say(A, chat, "до");
    stand.settle();

    stand.restart(B);
    stand.settle();
    stand.assert_members(B, chat, 3);
    stand.assert_seen(B, chat, &["до"]);

    stand.say(C, chat, "после");
    stand.settle();
    stand.assert_seen(B, chat, &["до", "после"]);
}

#[test]
fn a_message_to_a_sleeping_group_survives_the_senders_restart() {
    // Самый злой из простых случаев, и в нём сходится всё сегодняшнее:
    // копии в очереди, ключ очереди на диске, подъём и досылка.
    let mut stand = Stand::new(0x6745, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.offline(B);
    stand.offline(C);
    stand.say(A, chat, "всем спящим");
    stand.settle();

    stand.restart(A);
    stand.online(B);
    stand.online(C);
    stand.settle();

    stand.assert_seen(B, chat, &["всем спящим"]);
    stand.assert_seen(C, chat, &["всем спящим"]);
}

#[test]
fn a_message_forwarded_into_a_group_reaches_everyone_marked_as_forwarded() {
    // Поломка того же класса, что «файлы не отправляются в группы»: ветка
    // на группу была у текста, ответа, правки и реакции — и не было
    // у пересылки. `on_forward_messages` искал собеседника только среди
    // переписок и отвечал «контакт неизвестен».
    //
    // Починка не могла быть косметической: «переслано» один на один — это
    // отдельный тип нагрузки, а внутри группового сообщения под ключом
    // отправителя едет голый текст, и признаку там места нет. Поэтому
    // заведён свой вид действия, и проверяется здесь именно то, ради чего
    // он заведён: пометка доезжает до **участников**, а не только своя.
    let mut stand = Stand::new(0x6753, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    // Сперва А говорит с Б наедине — это и будет тем, что перешлют.
    let private = stand.chat_with(B);
    stand.say(A, private, "сказано наедине");
    stand.settle();

    let target = stand.msg_id_of(A, private, "сказано наедине");
    stand.forward(A, chat, &[target]);
    stand.settle();

    for who in [A, B, C] {
        stand.assert_seen(who, chat, &["сказано наедине"]);
        assert!(
            stand.is_forwarded(who, chat, "сказано наедине"),
            "узел {} обязан видеть пометку «переслано» (сид {:#x})",
            who.index(),
            stand.sim.seed()
        );
    }
}

#[test]
fn a_contact_shared_into_a_group_reaches_everyone() {
    // Вторая половина той же находки: «поделиться контактом» тоже искало
    // чат только среди переписок.
    let mut stand = Stand::new(0x6754, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    // Делимся карточкой В — той, что у А уже есть от приглашения.
    let card_of = stand.ik(C);
    stand.share_contact(A, chat, card_of);
    stand.settle();

    for who in [A, B, C] {
        // Тело пустое: карточка лежит записью рядом, как вложение, —
        // и это то же правило, что один на один. В окне она поэтому
        // видна пустой строкой.
        stand.assert_seen(who, chat, &[""]);
        let msg_id = stand.msg_id_of(who, chat, "");
        let share = stand
            .sim
            .node(who)
            .engine()
            .store()
            .contact_share_of(&msg_id)
            .expect("запись карточки")
            .unwrap_or_else(|| panic!("у узла {} карточки рядом с сообщением нет", who.index()));
        assert_eq!(share.ik, card_of, "карточка обязана быть о том, кем делились");
    }
}

#[test]
fn a_parked_group_frame_survives_a_restart_and_is_delivered_after() {
    // Поломка, найденная стендом рядом с 5яв и тогда лишь записанная:
    // очередь отложенных кадров жила только в памяти. Кадр про группу,
    // которой узел ещё не знает, ждёт в ней недостающего — и убийство
    // приложения уносило очередь целиком. Снаружи это «сообщение
    // не пришло», хотя оно приходило и лежало.
    //
    // Сценарий устраивает ровно ту гонку, ради которой очередь есть:
    // копия от Б доезжает до В **раньше**, чем представление группы от А.
    let mut stand = Stand::new(0x6755, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.settle();

    // В приглашают, пока его нет в сети: представление группы ложится
    // в очередь у А. Б при этом про В узнаёт — он в сети.
    stand.offline(C);
    stand.invite(A, chat, C);
    stand.settle();

    // Теперь наоборот: В появляется, А исчезает. Слово Б доезжает до В,
    // а представления группы у него всё ещё нет — кадр обязан лечь
    // в очередь, а не пропасть.
    stand.online(C);
    stand.offline(A);
    stand.say(B, chat, "пока А молчал");
    stand.settle();

    let parked = stand.sim.node(C).engine().parked_group_frames();
    assert!(
        parked.iter().any(|(group, _, _)| *group == chat),
        "кадр про незнакомую группу обязан лечь в очередь (сид {:#x})",
        stand.sim.seed()
    );
    // И лечь **на диск**: без этого перезапуск ниже ничего не проверяет.
    assert!(
        !stand.sim.node(C).engine().store().pending_group().expect("очередь").is_empty(),
        "очередь обязана быть на диске, а не только в памяти"
    );

    // Вот то, чего раньше не переживал ни один отложенный кадр.
    stand.restart(C);
    assert!(
        stand.sim.node(C).engine().parked_group_frames().iter().any(|(group, _, _)| *group == chat),
        "перезапуск не должен уносить отложенное"
    );

    // Недостающее приезжает — и отложенное разбирается тем же путём,
    // каким разбиралось бы без перезапуска.
    stand.online(A);
    stand.settle();
    stand.assert_members(C, chat, 3);
    stand.assert_seen(C, chat, &["пока А молчал"]);
    assert!(
        stand.sim.node(C).engine().parked_group_frames().is_empty(),
        "разобранное обязано уйти из очереди"
    );
    assert!(
        stand.sim.node(C).engine().store().pending_group().expect("очередь").is_empty(),
        "и с диска тоже — иначе перезапуск разобрал бы его во второй раз"
    );
}
