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

    /// Каталог под **исходники** отправляемых файлов.
    ///
    /// Отдельно от хранилища чанков нарочно: файл, который человек
    /// отправляет, лежит там, куда его положил хозяин, и ядро его
    /// не копирует (§10.2). Подмени мы это хранилищем — и проверка
    /// не заметила бы, что исходник читается своим путём.
    fn source(&self) -> PathBuf {
        self.0.join("source")
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
    /// Повторяет ли эфир объявления. Ложь у всех, кроме эфирных сценариев.
    beacons: bool,
    /// Сколько кадров узел отдал сети за прогон — им меряется рой (§7.1).
    sent: usize,
    /// Когда последний раз объявлялись. Чаще срока маяку незачем.
    beacon_at_ms: u64,
}

/// Как часто эфир повторяет объявление.
///
/// В живом BLE объявление приходит раз в несколько секунд; тридцать —
/// с запасом мелко против срока соседства (`PRESENCE_TTL_MS`,
/// полторы минуты) и достаточно крупно, чтобы не забивать стенд.
const BEACON_EVERY_MS: u64 = 30_000;

/// **Своего срока у маяка нет, и это главное в его устройстве.**
///
/// Взведи маяк сам себя — и стенд не затих бы никогда: `settle` ждёт
/// тишины, а маяк её не даёт. Ограничить маяк числом кругов тоже
/// не выходит: первый же `settle` их все и потратил бы, пустив двадцать
/// минут модельного времени до того, как сценарий начался.
///
/// Поэтому маяк едет на чужих колёсах — **на кадрах, и только на них**:
/// круг объявлений случается, когда узел принял кадр или не дозвался.
/// Пока в эфире идёт разговор, объявления идут вместе с ним; кончился
/// разговор — маяк молчит, стенд затихает, и соседство честно гаснет.
///
/// На сроках маяк не едет нарочно. Срок соседства выходит ровно тогда,
/// когда гасить уже пора; объявись стенд в ответ на него — соседство
/// зажигалось бы заново, следующий срок гасил бы его снова, и эти двое
/// качали бы друг друга до упора в предел шагов.

/// Ключ базы. Один на все узлы стенда: PIN здесь не изучается, а разные
/// ключи только добавили бы строк, ничего не проверяя.
fn db_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0x5a; 32])
}

impl Peer {
    fn new(seed: u8, run: u64, mail: bool) -> Peer {
        let home = Home::new(run, u16::from(seed));
        let engine = Peer::open(seed, &home, mail);
        Peer {
            engine: Some(engine),
            peers: BTreeMap::new(),
            events: Vec::new(),
            seed,
            home,
            mail,
            beacons: false,
            beacon_at_ms: 0,
            sent: 0,
        }
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
                    // Счёт кадров — то, чем меряется рой (§7.1). Шагов сети
                    // для этого мало: в них входят и квитанции, и таймеры,
                    // и «почему слово стоит восьми блоков вместо пяти»
                    // по ним не увидеть. Живой прогон меряет именно кадры,
                    // и стенд обязан мерить то же самое.
                    self.sent += 1;
                    ctx.send(to, to_sim(via), frame);
                    if let Some(handoff) = handoff {
                        handed.push(Input::Handed { peer_ik, via, handoff });
                    }
                }
                Effect::Notify(event) => self.events.push(event),
                Effect::SetTimer { after_ms, token } => ctx.set_timer(after_ms, token),
                Effect::Connect { .. }
                | Effect::SetTransportEnabled { .. }
                | Effect::WatchPeers(_)
                | Effect::SetMailAccount(_)
                | Effect::SetYgg(_)
                | Effect::SetNostr(_)
                | Effect::CreateMailAccount { .. }
                | Effect::Attributed { .. }
                | Effect::NetworkChanged => {}
            }
        }
        for input in handed {
            let effects =
                self.engine_mut().step(ctx.now_ms(), input).expect("подтверждение передачи");
            self.apply(ctx, effects);
        }
    }

    /// Круг объявлений: узел слышит в эфире всех, кого знает.
    ///
    /// **Объявление в эфире повторяется, и без этого повтора соседство
    /// проверять нечем.** Соседство живёт сроком в полторы минуты, а
    /// эфирные сценарии идут дольше: срок молчания на этой ступени
    /// удваивается — восемнадцать секунд, тридцать шесть, семьдесят
    /// две. Объяви стенд собеседника один раз на старте — и посреди
    /// сценария тот пропадал бы из эфира, хотя стоит в метре и
    /// исправно шлёт маяк. Проверки про молчащего отправителя после
    /// этого проходили бы по неверной причине: полоса освобождалась
    /// бы не уступкой ступени, а тем, что собеседника «не стало».
    fn beacon(&mut self, ctx: &mut Ctx<'_>) {
        if !self.beacons {
            return;
        }
        let now_ms = ctx.now_ms();
        if now_ms != 0 && now_ms.saturating_sub(self.beacon_at_ms) < BEACON_EVERY_MS {
            return;
        }
        self.beacon_at_ms = now_ms;
        let peers: Vec<[u8; 32]> = self.peers.keys().copied().collect();
        for peer_ik in peers {
            let effects = self
                .engine_mut()
                .step(ctx.now_ms(), Input::SeenOnBt { peer_ik })
                .expect("объявление услышано");
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
        self.beacon(ctx);
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
        self.beacon(ctx);
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
        TransportKind::Bt => Transport::Bt,
        TransportKind::Ygg => Transport::Ygg,
        TransportKind::Onion => Transport::Onion,
        TransportKind::Nostr => Transport::Nostr,
        TransportKind::Mail => Transport::Mail,
    }
}

fn to_sim(transport: Transport) -> TransportKind {
    match transport {
        Transport::Lan => TransportKind::Lan,
        Transport::Bt => TransportKind::Bt,
        Transport::Ygg => TransportKind::Ygg,
        Transport::Onion => TransportKind::Onion,
        Transport::Nostr => TransportKind::Nostr,
        Transport::Mail => TransportKind::Mail,
    }
}

/// Стенд целиком: сеть, узлы и словарь действий.
///
/// Словарь нарочно похож на команды ручного стенда — `say`, `offline`,
/// `restart`, — чтобы сценарий читался как запись сеанса за консолью,
/// а не как обход внутренностей ядра.
struct Stand {
    /// Сколько событий сети разобрано с начала сценария.
    ///
    /// Мера цены, а не отладочная мелочь: по ней видно, линейно ли растёт
    /// работа с числом читателей. Именно она показала, что слово в канале
    /// стоит двух шагов на читателя, а впуск — квадрата (§8ф).
    steps: usize,
    sim: Sim<Peer>,
}

/// Предел шагов на одно «дать сети затихнуть» — **на узел**.
///
/// Щедрый, и это не послабление: он ловит **кольцо** событий, а кольцо
/// не сходится ни при каком пределе. Честный разговор троих с почтой
/// в запасе стоит сотен шагов.
///
/// **Считается от числа узлов, а не плоским числом.** Плоские двадцать
/// тысяч означали, что сценарий на двадцати шести узлах падает с криком
/// «кольцо событий», хотя кольца там нет: впуск в канал стоит кадров
/// по числу уже впущенных, и тридцать тысяч шагов на двадцать пять
/// читателей — цена, а не поломка. Предел, срабатывающий от размера
/// сценария, ловит не кольцо, а собственную тесноту.
const MAX_STEPS_PER_NODE: usize = 20_000;

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

    /// Стенд, где узлы друг другу **никто** (§8.3).
    ///
    /// `Stand::new` знакомит всех со всеми — `O(n²)` карточек «как при
    /// встрече по QR». Для роя это не просто дорого: это **неверная
    /// посылка**. В канале узлы друг другу не контакты, в этом весь §8.3,
    /// и проверка, собранная на взаимных знакомствах, зеленела бы там,
    /// где живой рой упёрся бы в `UnknownPeer`.
    ///
    /// Здесь знакомства нет ни у кого: каждый знает только себя. Путь
    /// к чужому узлу открывает ссылка на канал (§10.1) — она заводит
    /// **пира**, — либо `introduce`, если сценарию нужна ровно одна пара.
    ///
    /// Почта выключена по той же причине, по какой её выключает
    /// `without_mail`: с ней всякое письмо доезжает спулом, и ожидание
    /// §5.4 не проверяется вовсе.
    fn strangers(seed: u64, count: u16) -> Stand {
        Stand::assemble(seed, count, false, false)
    }

    /// Незнакомцы, у каждого из которых есть почтовый адрес (§5.3).
    ///
    /// Нужно проверкам §8.4: асинхронная ступень меняет форму раздачи,
    /// и увидеть это можно лишь там, где почта — настоящая дорога,
    /// а не пустая строка в карточке.
    fn strangers_with_mail(seed: u64, count: u16) -> Stand {
        Stand::assemble(seed, count, true, false)
    }

    fn build(seed: u64, count: u16, mail: bool) -> Stand {
        Stand::assemble(seed, count, mail, true)
    }

    fn assemble(seed: u64, count: u16, mail: bool, introduce_everyone: bool) -> Stand {
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
        // Для роя его не бывает: см. `Stand::strangers`.
        for i in (0..count).filter(|_| introduce_everyone) {
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

        let mut stand = Stand { steps: 0, sim };
        stand.settle();
        stand
    }

    /// Даёт сети затихнуть: всё, что в пути, доезжает, все сроки выходят.
    fn settle(&mut self) {
        // **Эфир объявляется перед тем, как чему-то поехать.** В жизни
        // маяк не смолкал и всё это время; в стенде же между действиями
        // человека проходит сколько угодно модельного времени, и застать
        // соседство погасшим — обычное дело. Круг объявлений здесь и есть
        // то, что в жизни происходит само.
        self.beacons();
        match self.sim.run_to_idle(MAX_STEPS_PER_NODE * self.sim.len()) {
            Ok(done) => self.steps += done,
            Err(done) => panic!(
                "сеть не затихла за {done} шагов: кольцо событий или срок, взводящий сам себя \
                 (сид {:#x})",
                self.sim.seed()
            ),
        }
    }

    /// Крутит стенд заданное время — и всё это время эфир объявляется.
    ///
    /// Отличие от `sim.run_for` ровно в маяке. Десять минут подряд без
    /// единого объявления — это не «эфир», а «телефон выключили»:
    /// соседство погасло бы посреди отсчёта, и проверка про молчащего
    /// отправителя прошла бы по неверной причине — полосу освободило бы
    /// исчезновение собеседника, а не уступка ступени.
    fn run_for(&mut self, duration_ms: u64) {
        let until_ms = self.sim.now_ms() + duration_ms;
        while self.sim.now_ms() < until_ms {
            self.beacons();
            // Обслуживание — на каждом круге, как у драйвера: он
            // спрашивает после каждого пробуждения, а не по таймеру
            // (§6.4, §12).
            self.maintenance();
            let step_ms = BEACON_EVERY_MS.min(until_ms - self.sim.now_ms());
            self.sim.run_for(step_ms);
        }
    }

    /// Круг объявлений по всем узлам. У неэфирных молчит: `beacons` ложь.
    fn beacons(&mut self) {
        let count = u16::try_from(self.sim.len()).expect("узлов не больше 65535");
        for i in 0..count {
            self.sim.act(NodeId(i), |node, ctx| node.beacon(ctx));
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

    /// Заводит канал (фаза 2, §6.1) и отдаёт его идентификатор.
    ///
    /// Порода называется словом и здесь: она задаётся при заведении
    /// и не меняется никогда, а умолчание в заготовке стенда означало бы,
    /// что половина сценариев проверяет не ту породу, о которой написана.
    fn create_channel(&mut self, owner: NodeId, title: &str, open: bool) -> [u8; 16] {
        let title = title.to_owned();
        let events = self.sim.act(owner, |node, ctx| {
            let before = node.events.len();
            node.command(ctx, Command::CreateChannel { title, open });
            node.events[before..].to_vec()
        });
        events
            .iter()
            .find_map(|e| match e {
                Event::ChannelCreated { chat, .. } => Some(*chat),
                _ => None,
            })
            .expect("о заведении канала обязано прийти событие")
    }

    /// Ссылка на канал — та, которой владелец делится (§10.1).
    fn channel_link(&self, owner: NodeId, chat: [u8; 16]) -> String {
        self.sim.node(owner).engine().channel_link(chat).expect("ссылка собирается")
    }

    /// Переход по ссылке: подписка (§10.3, §10.4).
    fn subscribe(&mut self, who: NodeId, uri: &str) {
        let uri = uri.to_owned();
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::SubscribeToChannel { uri });
        });
        self.settle();
    }

    /// Объявляет узел раздающим этот канал (§7.5.1).
    fn announce_seeding(&mut self, who: NodeId, chat: [u8; 16]) {
        self.sim.act(who, |node, ctx| {
            node.command(
                ctx,
                Command::SetSeeding { chat, mode: ratatosk_proto::swarm::Seeding::Announced },
            );
        });
        self.settle();
    }

    /// Уводит аккаунт с экрана или возвращает на него (§5.1, §12).
    fn foreground(&mut self, who: NodeId, front: bool) {
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::SetForeground(front));
        });
        self.settle();
    }

    /// Просит историю глубже (§7.4, шаг 3) и отдаёт случившиеся новости.
    fn pull_older(&mut self, who: NodeId, chat: [u8; 16]) -> Vec<Event> {
        let before = self.sim.node(who).events.len();
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::PullOlderHistory { chat });
        });
        self.settle();
        self.sim.node(who).events[before..].to_vec()
    }

    /// Выдаёт право в канале (§6.2) на заданный срок.
    fn grant(&mut self, owner: NodeId, chat: [u8; 16], who: NodeId, rights: u32, until_ms: u64) {
        let peer_ik = self.ik(who);
        self.sim.act(owner, |node, ctx| {
            node.command(ctx, Command::SetChannelRight { chat, who: peer_ik, rights, until_ms });
        });
        self.settle();
    }

    /// Ставит пределы отдачи (§9.2): на пира и общий, в блоках за минуту.
    fn set_giving_limits(&mut self, who: NodeId, per_peer: u32, total: u32) {
        self.sim.act(who, |node, ctx| {
            node.command(
                ctx,
                Command::SetGivingLimits(ratatosk_proto::swarm::GivingLimits { per_peer, total }),
            );
        });
        self.settle();
    }

    /// Ставит уровень отдачи — на аккаунт (`chat: None`) или на канал (§12).
    fn set_sharing(
        &mut self,
        who: NodeId,
        chat: Option<[u8; 16]>,
        level: Option<ratatosk_proto::swarm::Sharing>,
    ) {
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::SetSharing { chat, level });
        });
        self.settle();
    }

    /// Сколько кадров отдали сети все узлы вместе (§7.1).
    fn frames_sent(&self) -> usize {
        self.sim.nodes().iter().map(|node| node.sent).sum()
    }

    /// Опустошает очередь доставки узла — «он сдался» (§12).
    ///
    /// Нужно, чтобы проверять **анти-энтропию** (§7.2), а не очередь
    /// §5.4. Пока в очереди лежит копия, слово доедет ею, и «вернулось
    /// через сида» будет неотличимо от «долежало в очереди». В жизни
    /// очередь сдаётся сама: уборка §12 выносит её по сроку, а процесс
    /// на телефоне убивают. Здесь это делается руками и сразу.
    fn drop_queue(&mut self, who: NodeId) {
        self.sim.act(who, |node, _| {
            let store = node.engine_mut().store_mut();
            let waiting = store.outbox().expect("очередь");
            for row in waiting {
                store.delete_outbox(&row.msg_id, &row.recipient_ik).expect("уборка очереди");
            }
        });
        // Очередь живёт и в памяти ядра, и на диске: после уборки диска
        // ядро поднимается заново — тем же путём, каким это делает
        // телефон после того, как его убила система.
        self.restart(who);
    }

    /// Каталог раздающих, каким его видит этот узел (§7.5).
    fn seeds(&self, who: NodeId, chat: [u8; 16]) -> Vec<[u8; 32]> {
        let now = self.sim.now_ms();
        let mut found: Vec<[u8; 32]> = self
            .sim
            .node(who)
            .engine()
            .seeds(chat, now)
            .expect("каталог")
            .into_iter()
            .map(|s| s.ik)
            .collect();
        found.sort_unstable();
        found
    }

    /// Впускает читателя в канал (фаза 2, §6.5).
    fn admit(&mut self, owner: NodeId, chat: [u8; 16], guest: NodeId) {
        let peer_ik = self.ik(guest);
        self.sim.act(owner, |node, ctx| {
            node.command(ctx, Command::AdmitToChannel { chat, peer_ik });
        });
    }

    /// Отписывается от канала (фаза 2, §10.6).
    fn unsubscribe(&mut self, who: NodeId, chat: [u8; 16]) {
        self.sim.act(who, |node, ctx| {
            node.command(ctx, Command::UnsubscribeFromChannel { chat });
        });
    }

    /// Гонит модельное время большими шагами, спрашивая обслуживание.
    ///
    /// Отдельно от `run_for` ровно из-за размера шага: тот идёт
    /// получасовыми кругами эфира, и месяц в нём — это восемьдесят тысяч
    /// кругов. Здесь шаг шестичасовой, а эфир молчит — как у телефона,
    /// пролежавшего ночь в кармане.
    ///
    /// Сроки §6.3 и §6.4 меряются месяцами, и другого способа их проверить
    /// нет: ждать квартал нельзя, а подделка часов превратила бы стенд
    /// в симулятор, только хуже.
    fn sleep_for(&mut self, duration_ms: u64) {
        let until_ms = self.sim.now_ms() + duration_ms;
        while self.sim.now_ms() < until_ms {
            self.maintenance();
            let step_ms = (6 * 60 * 60 * 1000).min(until_ms - self.sim.now_ms());
            self.sim.run_for(step_ms);
        }
        self.maintenance();
    }

    /// Новейшее поколение ключа чтения, каким его знает этот узел (§6.4).
    fn generation(&self, who: NodeId, chat: [u8; 16]) -> u64 {
        self.sim
            .node(who)
            .engine()
            .store()
            .archive_keys(&chat)
            .expect("поколения ключа чтения")
            .iter()
            .map(|key| key.generation)
            .max()
            .expect("хоть одно поколение у канала есть всегда")
    }

    /// Факты канала глазами этого узла (§6).
    fn facts(&self, who: NodeId, chat: [u8; 16]) -> ratatosk_core::engine::ChannelFacts {
        self.sim
            .node(who)
            .engine()
            .channel_facts(&chat, self.sim.now_ms())
            .expect("у канала обязаны быть факты канала")
    }

    /// Спрашивает у узла обслуживание по расписанию — то, что в жизни
    /// спрашивает драйвер после каждого пробуждения (§6.4).
    ///
    /// Без этого круга поворот ключа раз в месяц на стенде не случился бы
    /// вовсе: стенд гоняет `Engine` напрямую, а расписание живёт
    /// не таймером, а вопросом «не пора ли» — ровно потому, что телефон
    /// спит (§13.1).
    fn maintenance(&mut self) {
        let count = u16::try_from(self.sim.len()).expect("узлов не больше 65535");
        for i in 0..count {
            self.sim.act(NodeId(i), |node, ctx| {
                let now = ctx.now_ms();
                let effects = node.engine_mut().rotate_channels_if_due(now).expect("обход каналов");
                node.apply(ctx, effects);
            });
        }
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

    /// Отправляет файл: кладёт его на диск узла и просит ядро отправить.
    ///
    /// Байты настоящие и лежат настоящим файлом — иначе проверялась бы
    /// не передача, а заглушка: отправитель читает исходник с диска
    /// по смещению (§10.2), и ровно это здесь и должно работать.
    fn send_file(&mut self, who: NodeId, chat: [u8; 16], name: &str, bytes: &[u8]) {
        // Эфир объявляется перед отправкой: между действиями человека
        // модельного времени проходит сколько угодно, и застать соседство
        // погасшим — обычное дело (см. `Stand::settle`).
        self.beacons();
        let path = self.sim.node(who).home.source().join(name);
        std::fs::create_dir_all(path.parent().expect("у файла есть каталог"))
            .expect("каталог исходников");
        std::fs::write(&path, bytes).expect("исходник ложится на диск");
        self.sim.act(who, |node, ctx| {
            node.command(
                ctx,
                Command::SendFiles {
                    chat,
                    files: vec![ratatosk_core::OutgoingFile { path: path.clone(), preview: None }],
                    text: String::new(),
                },
            );
        });
    }

    /// Принимает все входящие вложения без вопросов — как порог §10.2.
    fn accept_everything(&mut self, who: NodeId) {
        self.sim.act(who, |node, ctx| {
            node.command(
                ctx,
                Command::SetAutoAcceptBytes(Some(ratatosk_proto::files::MAX_FILE_BYTES)),
            );
        });
    }

    /// Собранное содержимое принятого вложения с таким именем.
    ///
    /// `None` — вложения с таким именем нет или оно не собрано. Различать
    /// эти два случая вызывающему незачем: и то и другое означает «файл
    /// не доехал», а именно это проверки и спрашивают.
    fn received_file(&self, who: NodeId, chat: [u8; 16], name: &str) -> Option<Vec<u8>> {
        let node = self.sim.node(who).engine();
        let messages = node.store().messages(&chat, 200, None).ok()?;
        for message in messages {
            for file in node.store().files_of(&message.msg_id).ok()? {
                if !file.incoming || file.name != name || !file.complete {
                    continue;
                }
                let reader = node.open_file(&file.file_id).ok()??;
                let mut whole = Vec::with_capacity(file.size_bytes as usize);
                for index in 0..reader.chunk_total() {
                    whole.extend_from_slice(&reader.chunk(index).ok()??);
                }
                return Some(whole);
            }
        }
        None
    }

    /// Оставляет всем узлам единственную ступень — эфир.
    ///
    /// Именно ту, на которой живут все находки этой дуги: кадр там мелкий,
    /// очередь записи короткая, предел одновременных передач равен одному,
    /// и кадры теряются по-настоящему (профиль `LinkProfile::BT`).
    fn air_only(&mut self) {
        self.sim.net_mut().set_enabled(TransportKind::Lan, false);
        self.sim.net_mut().set_enabled(TransportKind::Onion, false);
        self.sim.net_mut().set_enabled(TransportKind::Mail, false);
        self.sim.net_mut().set_enabled(TransportKind::Bt, true);
        let count = u16::try_from(self.sim.len()).expect("узлов не больше 65535");
        for i in 0..count {
            let who = NodeId(i);
            self.sim.act(who, |node, ctx| {
                for transport in [Transport::Onion, Transport::Mail] {
                    let effects = node
                        .engine_mut()
                        .step(
                            ctx.now_ms(),
                            Input::Command(Command::SetTransportEnabled {
                                transport,
                                enabled: false,
                            }),
                        )
                        .expect("ступень выключается");
                    node.apply(ctx, effects);
                }
                let effects = node
                    .engine_mut()
                    .step(
                        ctx.now_ms(),
                        Input::Command(Command::SetTransportEnabled {
                            transport: Transport::Bt,
                            enabled: true,
                        }),
                    )
                    .expect("эфир включается");
                node.apply(ctx, effects);
                let effects = node
                    .engine_mut()
                    .step(ctx.now_ms(), Input::TransportReady { transport: Transport::Bt })
                    .expect("радио поднялось");
                node.apply(ctx, effects);
            });
        }
        // Маяки: в эфире адресуемость даёт объявление, а не карточка (0.4).
        // Заводится маяк, а не одно объявление, — почему именно так,
        // написано у `Peer::beacon`.
        for i in 0..count {
            self.sim.act(NodeId(i), |node, _ctx| {
                node.beacons = true;
            });
        }
        self.settle();
    }

    /// Оставляет узлу одну ступень — почту: onion выключается (§5.3).
    ///
    /// Нужно проверкам §8.4: асинхронная ступень меняет **форму**
    /// раздачи, а не только её скорость, и увидеть это можно лишь там,
    /// где другой дороги нет.
    fn mail_only(&mut self, who: NodeId) {
        self.sim.act(who, |node, ctx| {
            let effects = node
                .engine_mut()
                .step(
                    ctx.now_ms(),
                    Input::Command(Command::SetTransportEnabled {
                        transport: Transport::Onion,
                        enabled: false,
                    }),
                )
                .expect("ступень выключается");
            node.apply(ctx, effects);
        });
        self.settle();
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
fn a_word_reaches_a_reader_through_a_seed_when_the_owner_cannot_reach_him() {
    // **Первая настоящая ретрансляция** (§3.1, §7.1 шаг 2). До неё ядро
    // отвергало блок, принесённый не автором: «пересылать чужое некому».
    // Для группы это верно и сейчас (§11.3), а в канале на этой строке
    // стоял весь рой.
    //
    // Проверяется тем, ради чего заводился профиль на связь: путь
    // от владельца к читателю рвётся наглухо, и слово обязано прийти
    // **вторым путём** — через сида, к которому читатель привязался.
    let mut stand = Stand::strangers(0x7EED_5EED, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    // Узел 1 вызывается раздавать; узел 2 узнаёт о нём каталогом
    // и привязывается сам.
    stand.announce_seeding(NodeId(1), chat);

    // **Владелец больше не достаёт до второго читателя — ни одной
    // ступенью.** Так выглядит читатель за NAT, которому не дозвониться,
    // а почты у него нет.
    for kind in [TransportKind::Onion, TransportKind::Mail, TransportKind::Lan] {
        stand.sim.net_mut().set_link_profile(
            NodeId(0),
            NodeId(2),
            kind,
            LinkProfile { loss_permille: 1_000, ..LinkProfile::INSTANT },
        );
    }

    stand.say(NodeId(0), chat, "слово через сида");
    stand.settle();

    assert_eq!(
        stand.sim.node(NodeId(2)).seen(chat),
        vec!["слово через сида".to_owned()],
        "читатель обязан услышать владельца через сида; сид {:#x}",
        stand.sim.seed()
    );
    // И это именно ретрансляция, а не «дошло само»: прямого пути нет.
    assert_eq!(
        stand.sim.node(NodeId(1)).seen(chat),
        vec!["слово через сида".to_owned()],
        "сид услышал первым — он и переслал"
    );
}

#[test]
fn a_relayed_word_is_not_shown_twice() {
    // Обратная сторона ретрансляции: блок теперь приходит **двумя**
    // путями — звездой от владельца и от сида. Показать его дважды
    // означало бы менять переписку из-за устройства сети (§9.2).
    //
    // **Проверка опирается на то, что ретрансляция включена**: выключи
    // её — и она пройдёт по неверной причине, потому что путь останется
    // один. Что путь действительно второй, стережёт проверка выше;
    // здесь — что он не удваивает строку.
    let mut stand = Stand::strangers(0x2EED_2EED, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);

    stand.say(NodeId(0), chat, "одно слово");
    stand.settle();

    assert_eq!(
        stand.sim.node(NodeId(2)).seen(chat),
        vec!["одно слово".to_owned()],
        "две дороги — одна строка; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn with_a_seed_the_owner_stops_sending_a_copy_to_everyone() {
    // **То, ради чего дерево и нужно** (§7.1): владелец шлёт блок целиком
    // трём-пяти, остальным — зов `IHAVE`. Экономия считается шагами сети,
    // а не рассуждением: пара размеров показывает наклон.
    //
    // Число eager здесь **своё**, не из крейта: проверка стережёт
    // обещание «3–5» из §7.7, и возьми она константу, поднятие k_eager
    // подняло бы и её — а вместе с ним подорожало бы каждое слово.
    let mut stand = Stand::strangers(0x7E5E_7E5E, 8);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..8u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();

    // Пока сидов нет — чистая звезда: каждому по копии (§7.5.2).
    let (eager, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert!(eager.is_empty() && lazy.is_empty(), "дерево ещё не строилось");
    stand.say(NodeId(0), chat, "без роя");
    stand.settle();
    let (eager, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert_eq!(eager.len(), 7, "ноль сидов — это звезда, а не деградация (§7.5.2)");
    assert!(lazy.is_empty(), "ленивому некому прислать блок — зов был бы лишним кругом");

    // Появился сид — и дерево сжалось: кому-то теперь зов, а не блок.
    //
    // **Точного числа здесь не проверяется, и это не небрежность.**
    // Начальное деление даёт `k_eager` (у нас четыре), но дерево живое:
    // ленивый, не дождавшийся блока, зовёт `GRAFT` и переходит в eager
    // (§7.1, шаг 4), а получивший дубль подрезает ребро обратно. Числа
    // ходят вокруг `k_eager`, и требовать ровно его значило бы требовать,
    // чтобы дерево не чинилось.
    stand.announce_seeding(NodeId(1), chat);
    stand.say(NodeId(0), chat, "с роем");
    stand.settle();
    let (eager, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert!(eager.len() < 7, "владелец больше не шлёт копию каждому: eager={}", eager.len());
    assert!(!lazy.is_empty(), "кому-то теперь зов, а не блок");

    // И слово всё равно дошло до **всех**: ленивые получили его от сида
    // либо позвали `GRAFT` по сроку.
    for reader in 1..8u16 {
        assert!(
            stand.sim.node(NodeId(reader)).seen(chat).contains(&"с роем".to_owned()),
            "читатель {reader} остался без слова; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn when_the_last_seed_leaves_the_tree_becomes_a_star_again() {
    // §7.5.2: «переход звезда → рой → звезда проходит без отдельного
    // режима». Обратная сторона проверки про появление сида: ушёл
    // последний — и ленивые обязаны вернуться в eager. Иначе владелец
    // продолжал бы звать `IHAVE` туда, где блок больше взять негде,
    // и каждое слово стоило бы читателю лишнего круга «зов → срок →
    // `GRAFT`».
    let mut stand = Stand::strangers(0x57A5_0000, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.say(NodeId(0), chat, "при рое");
    stand.settle();
    let (eager, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert!(!lazy.is_empty(), "рой есть — дерево сжато: eager={}", eager.len());

    // Сид перестал раздавать, и запись выпала по сроку (§7.5).
    stand.sim.act(NodeId(1), |node, ctx| {
        node.command(
            ctx,
            Command::SetSeeding { chat, mode: ratatosk_proto::swarm::Seeding::Quiet },
        );
    });
    stand.sleep_for(8 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        stand.seeds(NodeId(0), chat).is_empty(),
        "запись сида обязана была выпасть — иначе проверка ниже пуста"
    );

    stand.say(NodeId(0), chat, "снова звезда");
    stand.settle();
    let (eager, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert_eq!(eager.len(), 6, "роя нет — снова всем целиком (§7.5.2)");
    assert!(lazy.is_empty(), "ленивому больше неоткуда взять блок");
    for reader in 1..7u16 {
        assert!(
            stand.sim.node(NodeId(reader)).seen(chat).contains(&"снова звезда".to_owned()),
            "читатель {reader} остался без слова; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn a_lazy_reader_grafts_when_the_block_does_not_come() {
    // §7.1, шаг 4: «`IHAVE` на неизвестный блок — таймер; не пришёл
    // за `T_graft` — `GRAFT`, перевод в eager, запрос блока. Дерево
    // чинится после обрыва».
    //
    // Обрыв здесь настоящий: сид, от которого ленивый ждёт блок, до него
    // не достаёт ни одной ступенью. Значит починить это может только
    // срок и зов — второго пути нет.
    let mut stand = Stand::strangers(0x6BAF_7000, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // Сид не достаёт ни до кого: остаётся только владелец и его зовы.
    for reader in 2..7u16 {
        for kind in [TransportKind::Onion, TransportKind::Mail, TransportKind::Lan] {
            stand.sim.net_mut().set_link_profile(
                NodeId(1),
                NodeId(reader),
                kind,
                LinkProfile { loss_permille: 1_000, ..LinkProfile::INSTANT },
            );
        }
    }

    stand.say(NodeId(0), chat, "через срок и зов");
    stand.settle();

    for reader in 1..7u16 {
        assert!(
            stand.sim.node(NodeId(reader)).seen(chat).contains(&"через срок и зов".to_owned()),
            "ленивый читатель {reader} не позвал GRAFT; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn a_duplicate_prunes_the_edge_it_came_by() {
    // §7.1, шаг 3: «чужой повторно — `PRUNE` приславшему, перевод его
    // в lazy. Лишние рёбра отмирают, дерево возникает само».
    //
    // Здесь дубль настоящий: читатель получает блок и от владельца,
    // и от сида, к которому привязан.
    let mut stand = Stand::strangers(0x9A9A_9A9A, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // **Порядок дублей задаётся связями, а не удачей.** Кто приедет
    // вторым, решает, чьё ребро подрежут, — и на случайных задержках
    // проверка мигала бы: приди копия сида первой, читатель подрезал бы
    // владельца, а владельца подрезать нельзя (он источник). Поэтому
    // путь от владельца быстрый, а от сида — заведомо медленнее.
    for kind in [TransportKind::Onion, TransportKind::Mail, TransportKind::Lan] {
        stand.sim.net_mut().set_link_profile(NodeId(0), NodeId(2), kind, LinkProfile::INSTANT);
        stand.sim.net_mut().set_link_profile(NodeId(0), NodeId(1), kind, LinkProfile::INSTANT);
        stand.sim.net_mut().set_link_profile(
            NodeId(1),
            NodeId(2),
            kind,
            LinkProfile { min_latency_ms: 1_000, max_latency_ms: 1_000, ..LinkProfile::INSTANT },
        );
    }

    stand.say(NodeId(0), chat, "двумя путями");
    stand.settle();

    // У сида второй читатель уехал в lazy: блок до него дошёл и без него.
    let (eager, lazy) = stand.sim.node(NodeId(1)).engine().swarm_tree(chat);
    let second = stand.ik(NodeId(2));
    assert!(
        lazy.contains(&second) || !eager.contains(&second),
        "ребро, по которому приехал дубль, обязано отмереть; сид {:#x}",
        stand.sim.seed()
    );
    // Владельца при этом никто не подрезает: он источник, и отрезав его,
    // читатель зависел бы от сида, которого завтра может не быть.
    let (owner_eager, _) = stand.sim.node(NodeId(2)).engine().swarm_tree(chat);
    let _ = owner_eager;
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"двумя путями".to_owned()),
        "и слово при этом дошло"
    );
}

#[test]
fn an_honest_seed_is_not_cooled_by_a_busy_channel() {
    // §7.7 стережёт **затопление** зовами, а не занятый канал. Сид,
    // честно зовущий на каждый новый блок, обязан остаться рабочим:
    // остыви мы его за живую ленту, рой ломался бы ровно там, где
    // он нужнее всего.
    //
    // Числа здесь свои: предел §7.7 — шестьдесят четыре зова за минуту,
    // и семьдесят слов подряд его перешагивают. Если проверка краснеет,
    // значит предел считает не то.
    let mut stand = Stand::strangers(0xB0_5EED, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    let owner = stand.ik(NodeId(0));
    let seed = stand.ik(NodeId(1));
    for i in 0..70 {
        stand.say(NodeId(0), chat, &format!("слово {i}"));
    }
    stand.settle();

    let now = stand.sim.now_ms();
    for reader in 1..7u16 {
        let node = stand.sim.node(NodeId(reader)).engine();
        assert!(
            !node.swarm_cooling(&owner, now),
            "владельца не остужают никогда: он источник; сид {:#x}",
            stand.sim.seed()
        );
        assert!(
            !node.swarm_cooling(&seed, now),
            "честный сид остался рабочим у читателя {reader}; сид {:#x}",
            stand.sim.seed()
        );
    }
    // И лента дошла: проверка выше была бы пуста, если бы слова
    // не ходили вовсе.
    assert!(
        stand.sim.node(NodeId(6)).seen(chat).contains(&"слово 69".to_owned()),
        "последнее слово обязано дойти; сид {:#x}",
        stand.sim.seed()
    );
}

/// Канал, в котором ленивым читателям раздаёт **только сид**.
///
/// Отдаёт стенд, канал, ключ сида и тех читателей, кого сид зовёт,
/// а не шлёт целиком. Нужно это обеим проверкам про «ложное have»:
/// ленивый у сида ленив и у владельца — зовут его оба, — а ждать блока
/// он будет от того, чей зов приехал первым. Приди копия владельца
/// вовремя, срок застал бы блок на месте, и «звал, а блока нет»
/// проверить было бы нечем: зов сида оказался бы просто опоздавшим.
/// Потеря здесь не годится — §10.5 повторяет, и копия доезжает
/// всё равно; поэтому владельцу до читателей кладётся путь длиной
/// в десять минут, а до сида он остаётся прежним.
fn a_channel_where_only_the_seed_calls(seed: u64) -> (Stand, [u8; 16], [u8; 32]) {
    let mut stand = Stand::strangers(seed, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    let seed_ik = stand.ik(NodeId(1));
    // Дерево у сида появляется, когда он впервые раздаёт: до первого
    // слова делить нечего.
    stand.say(NodeId(0), chat, "нулевое");
    stand.settle();

    let slow =
        LinkProfile { min_latency_ms: 600_000, max_latency_ms: 600_000, ..LinkProfile::INSTANT };
    for reader in 2..7u16 {
        for kind in [
            TransportKind::Onion,
            TransportKind::Mail,
            TransportKind::Lan,
            TransportKind::Bt,
            TransportKind::Ygg,
            TransportKind::Nostr,
        ] {
            stand.sim.net_mut().set_link_profile(NodeId(0), NodeId(reader), kind, slow);
        }
    }
    (stand, chat, seed_ik)
}

/// Кого узел зовёт, а не шлёт целиком, — прямо сейчас.
///
/// **Считается перед самой проверкой, а не в начале сценария.** Дерево
/// живое: обмен have-векторами (§7.2) чинит пропуски, и тот, кто был
/// ленивым на первом слове, к третьему получает блоки целиком. Первая
/// редакция брала список один раз — и требовала остывания от читателя,
/// которому сид к тому времени честно всё отдал.
fn lazy_readers(stand: &Stand, at: NodeId, chat: [u8; 16], readers: &[u16]) -> Vec<u16> {
    let (_, lazy) = stand.sim.node(at).engine().swarm_tree(chat);
    readers.iter().copied().filter(|i| lazy.contains(&stand.ik(NodeId(*i)))).collect()
}

/// Столько ждёт проверка, чтобы у зова вышли **оба** срока: ожидание
/// блока и ожидание ответа на просьбу.
///
/// Число здесь своё, а не из крейта: стереги оно константу, поднятие
/// срока подняло бы и проверку, и та смолчала бы о том, что остывание
/// перестало наступать.
const TWO_GRAFT_DEADLINES_MS: u64 = 400_000;

#[test]
fn a_seed_that_calls_and_disappears_cools_down() {
    // §7.7, «ложное have»: «счёт неудач, остывание, предпочтение
    // отвечавшим недавно». Звал, блока нет — звать этого пира снова
    // значит тратить `T_graft` на заведомое молчание.
    //
    // Сценарий честный: сид зовёт ленивых читателей и уходит из сети
    // между зовом и просьбой. Вторую половину имени — что **одного**
    // молчания мало — стережёт `a_single_silence_does_not_cool_a_seed`.
    let (mut stand, chat, seed) = a_channel_where_only_the_seed_calls(0xFA_15E0);

    // Два зова — и сид пропадает, не ответив ни на один.
    //
    // **Две секунды на слово, а не полсекунды.** Слово должно успеть
    // дойти до сида и уехать от него зовом; полсекунды хватало впритык,
    // и второй зов иногда не успевал родиться вовсе — проверка тогда
    // краснела на «одном молчании вместо двух», то есть врала о причине.
    stand.say(NodeId(0), chat, "раз");
    stand.sim.run_for(2_000);
    stand.say(NodeId(0), chat, "два");
    stand.sim.run_for(2_000);
    let lazy_nodes = lazy_readers(&stand, NodeId(1), chat, &[2, 3, 4, 5, 6]);
    assert!(!lazy_nodes.is_empty(), "у сида обязан быть ленивый читатель — иначе проверка пуста");
    stand.offline(NodeId(1));
    stand.sim.run_for(TWO_GRAFT_DEADLINES_MS);

    let now = stand.sim.now_ms();
    for reader in lazy_nodes {
        assert!(
            stand.sim.node(NodeId(reader)).engine().swarm_cooling(&seed, now),
            "два неответа подряд — остывание (§7.7), читатель {reader}; сид {:#x}",
            stand.sim.seed()
        );
    }
    // **Чего проверка не стережёт.** Что остывание когда-нибудь кончится:
    // это время (`COOLING_MS`), а не событие, и проверки на него нет.
    // И что остывший перестаёт получать зовы — это видно по ветке
    // `IHave`, но не по этому сценарию.
}

#[test]
fn the_owner_is_never_cooled_however_long_he_is_silent() {
    // §7.7 с оговоркой: владельца канала остужать нельзя. Остывание
    // отрезает от живой ленты на четверть часа, а другого пути у канала
    // может не быть вовсе (§7.5.2, «ноль сидов — это звезда»): остудив
    // владельца, читатель остался бы без канала совсем. Защищаться
    // от него бессмысленно и по второй причине — канал его, и «затопить»
    // нас он может просто словами.
    //
    // Сценарий тот же, что у пропавшего сида, но пропадает владелец:
    // зовёт дважды и уходит. Снимешь оговорку — читатели его остудят.
    let mut stand = Stand::strangers(0x0_4DEAD, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    // Сид нужен, чтобы дерево вообще делилось: без сидов канал — звезда,
    // и зовов в нём не бывает (§7.5.2). Сразу после объявления он уходит,
    // и звать остаётся одному владельцу.
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.say(NodeId(0), chat, "нулевое");
    stand.settle();
    let owner = stand.ik(NodeId(0));
    stand.offline(NodeId(1));

    stand.say(NodeId(0), chat, "раз");
    stand.sim.run_for(500);
    stand.say(NodeId(0), chat, "два");
    stand.sim.run_for(500);
    let lazy_nodes = lazy_readers(&stand, NodeId(0), chat, &[1, 2, 3, 4, 5, 6]);
    assert!(!lazy_nodes.is_empty(), "у владельца обязан быть ленивый читатель");
    stand.offline(NodeId(0));
    stand.sim.run_for(TWO_GRAFT_DEADLINES_MS);

    let now = stand.sim.now_ms();
    for reader in lazy_nodes {
        assert!(
            !stand.sim.node(NodeId(reader)).engine().swarm_cooling(&owner, now),
            "владельца не остужают никогда (§7.7), читатель {reader}; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn a_single_silence_does_not_cool_a_seed() {
    // Вторая половина §7.7: молчание **одного** зова виной не считается.
    // Пир мог моргнуть — сеть пропала на минуту, телефон уснул, — и
    // отрезать его от ленты на четверть часа за одно опоздание значит
    // ломать рой там, где он цел.
    //
    // Сценарий тот же, что у `a_seed_that_calls_and_disappears_cools_down`,
    // и отличается ровно одним словом вместо двух: разница между
    // проверками и есть то, что стережётся.
    let (mut stand, chat, seed) = a_channel_where_only_the_seed_calls(0x5117_0000);

    stand.say(NodeId(0), chat, "раз");
    stand.sim.run_for(500);
    let lazy_nodes = lazy_readers(&stand, NodeId(1), chat, &[2, 3, 4, 5, 6]);
    assert!(!lazy_nodes.is_empty(), "у сида обязан быть ленивый читатель — иначе проверка пуста");
    stand.offline(NodeId(1));
    stand.sim.run_for(TWO_GRAFT_DEADLINES_MS);

    let now = stand.sim.now_ms();
    for reader in lazy_nodes {
        assert!(
            !stand.sim.node(NodeId(reader)).engine().swarm_cooling(&seed, now),
            "одного молчания мало (§7.7), читатель {reader}; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn a_deferred_copy_tries_again_on_its_own_schedule() {
    // **Находка живого меша, и самая дорогая за этот круг.** В локальной
    // сети отложенное будит маяк §5.1: собеседник появился — копия
    // поехала. В меше и onion маяка нет вовсе, и «появился» узнать
    // неоткуда: обе стороны ждут события, которое может создать только
    // другая. Вернувшийся из перезапуска узел молчал три минуты —
    // и молчал бы час, до ближайшего обхода ядра.
    //
    // §10.5 отвечает на это расписанием: полминуты, пять минут, дальше
    // раз в четверть часа, и сутки спустя — «не отвечает».
    //
    // Числа здесь свои, не из крейта: проверка стережёт обещание §10.5,
    // и растянись расписание вдвое, она обязана покраснеть.
    let mut stand = Stand::strangers(0xD1_5EED, 2);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();

    // Читателя нет в сети, и слово ложится в очередь. **Без `settle`**:
    // тот гонит модельное время до тишины и успевает сжечь ступеньки
    // расписания, пока ждать ещё некого.
    stand.offline(NodeId(1));
    stand.say(NodeId(0), chat, "пока тебя нет");
    stand.sim.run_for(2_000);
    assert!(stand.sim.node(NodeId(1)).seen(chat).is_empty(), "оно и не могло дойти");

    // Читатель вернулся — **и ничего никому не сказал**: маяка в меше
    // нет, а сам он молчит. Дальше работает одно расписание.
    //
    // Полминуты — первая ступенька §10.5. Разброс ±20% укладывается
    // в минуту с запасом.
    stand.online(NodeId(1));
    stand.sim.run_for(60_000);
    stand.settle();

    assert_eq!(
        stand.sim.node(NodeId(1)).seen(chat),
        vec!["пока тебя нет".to_owned()],
        "расписание §10.5 обязано было повторить попытку; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_word_lost_by_the_tree_comes_back_from_a_seed() {
    // **То, ради чего анти-энтропия и нужна** (§7.2): «дерево
    // распространяет живое и не чинит долгое отсутствие».
    //
    // Сценарий взят такой, где звезда помочь не может **по построению**:
    // читателя не было в сети, когда владелец сказал слово, а потом
    // владелец ушёл сам. Очередь §5.4 у него есть, но доставить её
    // некому — процесс выключен. Единственный, у кого блок остался, —
    // сид, и вернуть его может только обмен have-векторами.
    let mut stand = Stand::strangers(0xA2E0_7207, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // Второй читатель выключен; владелец говорит; владелец выключен.
    stand.offline(NodeId(2));
    stand.say(NodeId(0), chat, "сказано без тебя");
    stand.settle();
    stand.offline(NodeId(0));
    // **Очереди сдались.** Пока копия лежит в очереди §5.4, слово доедет
    // ею — и проверка прошла бы, ничего не проверив: ровно так первая
    // её редакция и зеленела при снятой анти-энтропии.
    stand.drop_queue(NodeId(0));
    stand.drop_queue(NodeId(1));
    stand.online(NodeId(2));
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"сказано без тебя".to_owned()),
        "пока читателя не было, слово до него не дошло — иначе проверка ниже пуста"
    );

    // Читатель снова привязывается к сиду — и обмен have-векторами
    // возвращает пропущенное.
    //
    // **Час модельного времени здесь обязателен.** Обход ядра ходит
    // не чаще раза в час (`KEY_ROTATION_SCAN_MS`), и позови его раньше —
    // он честно ничего не сделает. Первая редакция проверки на этом
    // и споткнулась: привязка не повторялась, вектора не ехали, а
    // выглядело это как «анти-энтропия не работает».
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"сказано без тебя".to_owned()),
        "анти-энтропия обязана вернуть потерянное деревом; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_block_lost_on_the_mail_comes_back_with_the_next_packet() {
    // §8.4: «Асинхронным ступеням шлётся пакет блоков за окно
    // с избыточностью». Избыточность здесь — не запас прочности,
    // а замена `GRAFT`: на почте ответа не обещают, зова там нет вовсе
    // (`graft_wait_ms` — `None`), и потерянный блок ждал бы
    // анти-энтропии, то есть следующего обхода.
    //
    // Проверяется то, ради чего пакет и собран: письмо потеряно —
    // слово приезжает **следующим**, а не через час.
    let mut stand = Stand::strangers_with_mail(0x0_BA7C4, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    for node in 0..3u16 {
        stand.mail_only(NodeId(node));
    }

    // Первое слово теряется по дороге к читателю: письмо не дошло.
    stand.sim.net_mut().set_link_profile(
        NodeId(0),
        NodeId(1),
        TransportKind::Mail,
        LinkProfile { loss_permille: 1_000, ..LinkProfile::MAIL },
    );
    stand.say(NodeId(0), chat, "потерянное");
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(1)).seen(chat).contains(&"потерянное".to_owned()),
        "письмо и правда потеряно — иначе проверка пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Почта снова работает, и владелец говорит следующее слово.
    stand.sim.net_mut().set_link_profile(
        NodeId(0),
        NodeId(1),
        TransportKind::Mail,
        LinkProfile::MAIL,
    );
    stand.say(NodeId(0), chat, "следующее");
    stand.settle();

    let seen = stand.sim.node(NodeId(1)).seen(chat);
    assert!(
        seen.contains(&"следующее".to_owned()),
        "новое слово приехало; видно {seen:?}; сид {:#x}",
        stand.sim.seed()
    );
    assert!(
        seen.contains(&"потерянное".to_owned()),
        "и потерянное приехало с ним же — в том же пакете (§8.4); видно {seen:?}; сид {:#x}",
        stand.sim.seed()
    );
    // **И ни одного двойника.** Пакет везёт повторы нарочно (§8.4),
    // и съедать их обязано окно §9.2 — то же, что съедает всякий
    // повтор. Спроси мы окно только у обёртки, каждое слово ложилось бы
    // в историю столько раз, сколько пакетов его привезло.
    let words: Vec<&String> =
        seen.iter().filter(|w| *w == "потерянное" || *w == "следующее").collect();
    assert_eq!(
        words.len(),
        2,
        "каждое слово — по одному разу, хотя пакеты везли их дважды; видно {seen:?}; сид {:#x}",
        stand.sim.seed()
    );
    // **Чего проверка не стережёт.** Размера пакета: три блока — число
    // из крейта, а проверка смотрит на то, что предыдущий блок в пакете
    // есть, а не на то, сколько их там.
}

#[test]
fn a_reader_reachable_only_by_mail_is_never_lazy() {
    // §8.4 прямо: «почта, nostr — всегда eager, никогда lazy.
    // Асинхронные ступени не бывают lazy: `IHAVE` с ответом через часы
    // бессмыслен».
    //
    // Цена ошибки здесь — **молчание, а не задержка**. Ленивый на почте
    // получает зов, а завести по нему срок ему нечем (`graft_wait_ms`
    // у почты — `None`), и блок он попросит только анти-энтропией,
    // часы спустя. Снаружи это «слово не дошло».
    let mut stand = Stand::strangers_with_mail(0x0_0A17, 7);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..7u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    // Сид нужен, чтобы дерево вообще делилось: без сидов канал — звезда
    // (§7.5.2), и ленивых в нём не бывает ни на какой ступени.
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // **Почта остаётся единственной дорогой у всех**, а не у одного
    // владельца. Оставь мы onion сиду — его копия дошла бы до ленивых
    // и без просьбы, и проверка стерегла бы форму дерева, но не цену
    // ошибки: слово доезжало бы в обоих случаях.
    for node in 0..7u16 {
        stand.mail_only(NodeId(node));
    }
    stand.say(NodeId(0), chat, "почтой");
    stand.settle();

    let (_, lazy) = stand.sim.node(NodeId(0)).engine().swarm_tree(chat);
    assert!(
        lazy.is_empty(),
        "на почте ленивых не бывает (§8.4), а их {}; сид {:#x}",
        lazy.len(),
        stand.sim.seed()
    );
    for reader in 1..7u16 {
        assert!(
            stand.sim.node(NodeId(reader)).seen(chat).contains(&"почтой".to_owned()),
            "слово обязано дойти до читателя {reader} целиком; сид {:#x}",
            stand.sim.seed()
        );
    }
    // **Чего проверка не стережёт.** Пакета блоков «за окно
    // с избыточностью», который §8.4 предлагает асинхронным ступеням:
    // его нет, блоки едут по одному.
}

#[test]
fn the_total_limit_stops_giving_and_the_next_round_starts_it_again() {
    // §9.2: «сервера нет, значит ограничителя частоты нет ни у кого,
    // кроме нас самих. Нужны три числа и выключатель, все на диске».
    // Общий предел — четвёртое число и единственное, которое считает
    // не пира, а нас: предел на пира защищает от одного жадного, общий
    // — от десяти вежливых.
    //
    // Проверяется дважды: что предел **останавливает** и что окно
    // его **отпускает**. Имя обещает обе половины, и одной мало:
    // предел, который не отпускает, — это тихо умерший рой.
    let mut stand = Stand::strangers(0x0_1117, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    // Сид отдаёт **один блок за минуту** — число своё, не из крейта.
    stand.set_giving_limits(NodeId(1), 128, 1);
    // **А владелец не отдаёт из архива вовсе**, иначе он ответит вместо
    // сида: читатель привязывается и к нему тоже (§7.5.2, звезда как
    // рабочее состояние). Живую ленту это не трогает — предел стоит
    // на ответах по просьбе, а не на раздаче деревом.
    stand.set_giving_limits(NodeId(0), 0, 0);

    // Два слова мимо читателя: вернуть их может только сид.
    stand.offline(NodeId(2));
    stand.say(NodeId(0), chat, "первое без тебя");
    stand.settle();
    stand.say(NodeId(0), chat, "второе без тебя");
    stand.settle();
    // **Очереди обоих сдались** — и владельца, и сида. Пока копия лежит
    // в очереди §5.4, слово доедет ею, и «предел остановил отдачу» будет
    // неотличимо от «очередь ещё не дошла».
    stand.drop_queue(NodeId(0));
    stand.drop_queue(NodeId(1));
    stand.online(NodeId(2));
    stand.settle();

    // Первый обмен векторами: сид отдаёт ровно один блок и упирается
    // в предел.
    //
    // **Здесь нельзя `settle`**, и это разбор покрасневшей проверки.
    // Он гонит модельное время до тишины и сжигает ступеньки §10.5 —
    // за один такой заход проходит не минута, а часы, окно предела
    // успевает смениться, и сид отдаёт оба блока. Снаружи выглядело бы
    // как «общий предел не работает», а на деле работал: просто окон
    // было два. Поэтому дальше время двигается **руками**, отрезками
    // короче окна.
    stand.maintenance();
    stand.run_for(30_000);
    let after_first = stand.sim.node(NodeId(2)).seen(chat);
    let got = ["первое без тебя", "второе без тебя"]
        .iter()
        .filter(|word| after_first.contains(&(**word).to_owned()))
        .count();
    assert_eq!(
        got,
        1,
        "общий предел отдал ровно один блок за окно, а отдал {got}; видно {after_first:?}; \
         сид {:#x}",
        stand.sim.seed()
    );

    // Следующий обход — и остальное доезжает: предел **отпускает**.
    // Это вторая половина имени, и без неё правило было бы «рой,
    // умерший тихо»: предел, который не кончается, ничем не отличается
    // от выключенной раздачи.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.run_for(30_000);
    let after_second = stand.sim.node(NodeId(2)).seen(chat);
    for word in ["первое без тебя", "второе без тебя"] {
        assert!(
            after_second.contains(&word.to_owned()),
            "окно кончилось — отдача продолжилась: «{word}» не доехало; видно {after_second:?}; \
             сид {:#x}",
            stand.sim.seed()
        );
    }
    // **Чего проверка не стережёт — длины окна.** Между двумя половинами
    // проходит обход, то есть час модельного времени, и минута окна
    // в него входит с запасом. Значит проверено «предел отпускает»,
    // а не «отпускает ровно через минуту»: спросить отдачу чаще, чем
    // раз в час, ядру нечем — другого повода для обмена векторами нет.
}

#[test]
fn the_giving_limits_survive_a_restart() {
    // §9.2 велит держать числа **на диске**, и слово «на диске» здесь
    // не про удобство: настройка, не пережившая перезапуск, ограничивает
    // ровно до первого перезапуска. Проверяется настоящим перезапуском —
    // база закрывается и открывается заново.
    let mut stand = Stand::strangers(0x0_D15C, 2);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    stand.settle();
    let _ = chat;

    stand.set_giving_limits(NodeId(0), 7, 11);
    stand.restart(NodeId(0));
    stand.settle();

    let limits = stand.sim.node(NodeId(0)).engine().giving_limits().expect("пределы");
    assert_eq!(
        (limits.per_peer, limits.total),
        (7, 11),
        "пределы отдачи обязаны пережить перезапуск (§9.2); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn an_account_off_the_screen_stops_seeding_and_starts_again_when_it_returns() {
    // §12: «Активен ровно один аккаунт… неактивный аккаунт недостижим
    // напрямую, его сидирование прекращается, `PeerRecord` выпадает
    // по сроку».
    //
    // Довод не про вежливость к батарее. Второй аккаунт, раздающий
    // с того же устройства, отдаёт блоки тем же каналом и тем же радио,
    // что и первый: объём и время связывают их на проводе. §12 называет
    // это прямо — «не экономия, а связывание аккаунтов».
    //
    // Имя обещает две половины, и вторая не мелочь: фон, из которого
    // не возвращаются, — это рой, умерший от переключения экрана.
    let (mut stand, chat) = a_channel_where_the_reader_depends_on_the_seed(0x0_FA50FF, true);

    // На экране — раздаёт.
    stand.say(NodeId(0), chat, "на экране");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"на экране".to_owned()),
        "рой работает — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Человек переключился на другой аккаунт: этот ушёл в фон.
    stand.foreground(NodeId(1), false);
    stand.say(NodeId(0), chat, "в фоне");
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"в фоне".to_owned()),
        "фоновый аккаунт не раздаёт (§12); сид {:#x}",
        stand.sim.seed()
    );
    // Принимать при этом он не перестал: §12 начинается с того, что
    // принимать почти бесплатно, а платит отдающий.
    assert!(
        stand.sim.node(NodeId(1)).seen(chat).contains(&"в фоне".to_owned()),
        "в фоне он слушает канал по-прежнему; сид {:#x}",
        stand.sim.seed()
    );

    // Вернулся на экран — раздача продолжается.
    stand.foreground(NodeId(1), true);
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"в фоне".to_owned()),
        "вернувшийся на экран раздаёт снова, в том числе пропущенное; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_background_account_lets_its_record_fall_out_by_time() {
    // §12: «его сидирование прекращается, `PeerRecord` выпадает
    // по сроку». Выпадает — а не отзывается: отзыва §7.5 не знает вовсе,
    // и цена переключения названа заранее — читатели набирают погасший
    // адрес до конца недели.
    //
    // Числа здесь свои, не из крейта: запись живёт неделю и продлевается
    // за двое суток до конца. Восемь суток переживают и то, и другое.
    let mut stand = Stand::strangers(0x0_BAC6, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.seeds(NodeId(2), chat).is_empty(),
        "читатель знает сида — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Аккаунт ушёл с экрана и восемь суток не возвращался.
    stand.foreground(NodeId(1), false);
    stand.sleep_for(8 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    assert!(
        stand.seeds(NodeId(2), chat).is_empty(),
        "запись фонового аккаунта выпадает по сроку (§12); сид {:#x}",
        stand.sim.seed()
    );
    // И у самого себя тоже: держать в своём каталоге обещание, которого
    // больше не даём, — значит врать самому себе.
    assert!(
        stand.seeds(NodeId(1), chat).is_empty(),
        "своя протухшая запись не показывается и себе; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn files_and_reactions_travel_in_a_channel_and_bytes_find_a_second_source() {
    // Живая находка: «в канале по приглашению файлы и реакции доходят
    // только от владельца, от подписчиков — нет, хотя обычные сообщения
    // ходят нормально. В открытых каналах иначе — файлы от владельца
    // не загружаются».
    //
    // Одна причина на оба симптома: слово ходило **деревом**
    // (`push_block`), а действие о слове — веером по составу
    // (`fan_out_group`). У держателя права состава нет (§3.2), значит
    // его веер пуст; у владельца открытого канала состава не существует
    // вовсе (§6.1), значит пуст и его.
    let mut stand = Stand::strangers(0x0_F17E5, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
        stand.accept_everything(NodeId(reader));
    }
    stand.accept_everything(NodeId(0));
    stand.settle();
    let year = stand.sim.now_ms() + 365 * 24 * 60 * 60 * 1000;
    stand.grant(NodeId(0), chat, NodeId(1), ratatosk_proto::channel::Rights::WRITE.bits(), year);

    // Владелец говорит слово — на него отвечают реакцией и файлом.
    stand.say(NodeId(0), chat, "о чём речь");
    stand.settle();
    let target = stand
        .sim
        .node(NodeId(1))
        .engine()
        .store()
        .messages(&chat, 10, None)
        .expect("история")
        .into_iter()
        .find(|m| m.body == "о чём речь".as_bytes())
        .expect("слово владельца у читателя")
        .msg_id;

    stand.sim.act(NodeId(1), |node, ctx| {
        node.command(ctx, Command::SetReaction { chat, msg_id: target, emoji: "🔥".to_owned() });
    });
    stand.settle();
    stand.send_file(NodeId(1), chat, "от-читателя.bin", &[7u8; 2048]);
    stand.settle();

    // Реакция держателя права видна и владельцу, и второму читателю.
    for who in [NodeId(0), NodeId(2)] {
        let reactions = stand.sim.node(who).engine().store().reactions(&target).expect("реакции");
        assert!(
            reactions.iter().any(|r| r.emoji == "🔥"),
            "реакция читателя обязана дойти до {who:?}; сид {:#x}",
            stand.sim.seed()
        );
    }
    // И файл его доходит **до владельца**: до него читатель дотянуться
    // может — адрес владельца он знает из ссылки (§10.1).
    assert!(
        stand.received_file(NodeId(0), chat, "от-читателя.bin").is_some(),
        "файл читателя обязан дойти до владельца; сид {:#x}",
        stand.sim.seed()
    );
    // **И до второго читателя — тоже, хотя автора он набрать не может.**
    // Это §9.1: «отправитель выгружает файл один раз, дальше куски
    // расходятся между участниками». Владелец, собрав файл, объявил,
    // что он у него есть, и второй читатель взял байты у него —
    // читатели канала друг друга не знают (§3.2), и другого пути
    // у него не было.
    assert!(
        stand.received_file(NodeId(2), chat, "от-читателя.bin").is_some(),
        "второй читатель берёт байты у объявившегося держателя (§9.1); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_file_in_an_open_channel_reaches_the_subscriber() {
    // Вторая половина той же находки: в **открытом** канале состава
    // не существует (§6.1), и веер владельца пуст — файлы от него
    // не доходили ни до кого.
    let mut stand = Stand::strangers(0x0_F17E6, 2);
    let chat = stand.create_channel(NodeId(0), "открытая лента", true);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.accept_everything(NodeId(1));
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    stand.send_file(NodeId(0), chat, "от-владельца.bin", &[3u8; 2048]);
    stand.settle();

    assert!(
        stand.received_file(NodeId(1), chat, "от-владельца.bin").is_some(),
        "файл владельца обязан дойти до подписчика по ссылке; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_channel_avatar_reaches_the_readers() {
    // Живая находка: «аватарку канала поставить можно, а у подписчиков
    // она не показывается — при том что имя и его смену они видят».
    //
    // Имя едет представлением (§6.1), картинка — отдельным действием
    // (§11.2), и разница в путях: значит сторожить надо картинку,
    // а не «документ доехал».
    let mut stand = Stand::strangers(0x0_A7A2, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();

    let picture = {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.resize(24 * 1024, 7);
        bytes
    };
    let sent = picture.clone();
    stand.sim.act(NodeId(0), |node, ctx| {
        node.command(ctx, Command::SetGroupAvatar { chat, bytes: sent.clone() });
    });
    stand.settle();

    // **И тот, кого впустили уже после**, картинку тоже получает:
    // человек, пришедший в канал завтра, видит его таким же, как все.
    stand.subscribe(NodeId(2), &link);
    stand.admit(NodeId(0), chat, NodeId(2));
    stand.settle();

    for reader in 1..3u16 {
        let got = stand
            .sim
            .node(NodeId(reader))
            .engine()
            .store()
            .group_avatar(&chat)
            .expect("чтение")
            .map(|it| it.bytes);
        assert_eq!(
            got.as_deref(),
            Some(picture.as_slice()),
            "картинка канала обязана доехать до читателя {reader}; сид {:#x}",
            stand.sim.seed()
        );
    }
}

#[test]
fn a_reader_with_the_write_right_speaks_and_everyone_hears_him() {
    // §6.2 даёт право писать не одному владельцу — и до этой поставки
    // право было, а дороги не было: состав канала знает владелец (§3.2),
    // и держателю `WRITE` развозить было некому. Ядро честно отказывало
    // заранее («в канале публикует владелец»), а человек видел кнопку,
    // которая не работает.
    //
    // Дорога — рой: слово уезжает владельцу и своим сидам, владелец
    // развозит по составу, сид раздаёт деревом (§7.1, шаг 2). Проверяется
    // именно это: сказал **не владелец**, услышали все.
    let mut stand = Stand::strangers(0x0_9217E, 4);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..4u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();

    // Право выдаётся одному читателю — и уезжает представлением (§6.2).
    // Срок — год: §6.3 велит сроку быть всегда, а «навсегда» база
    // не примет (`i64`), да и §6.3 такого не знает.
    let year = stand.sim.now_ms() + 365 * 24 * 60 * 60 * 1000;
    stand.grant(NodeId(0), chat, NodeId(1), ratatosk_proto::channel::Rights::WRITE.bits(), year);

    stand.say(NodeId(1), chat, "говорю не владелец");
    stand.settle();

    for who in [NodeId(0), NodeId(2), NodeId(3)] {
        assert!(
            stand.sim.node(who).seen(chat).contains(&"говорю не владелец".to_owned()),
            "слово держателя права обязано дойти до узла {:?}; видно {:?}; сид {:#x}",
            who,
            stand.sim.node(who).seen(chat),
            stand.sim.seed()
        );
    }

    // **А без права — по-прежнему отказ**, и это вторая половина §6.2:
    // право пускает слово, а не порода канала.
    let refused = stand.sim.act(NodeId(2), |node, ctx| {
        node.engine_mut().step(
            ctx.now_ms(),
            Input::Command(Command::SendText { chat, text: "а я без права".to_owned() }),
        )
    });
    assert!(
        matches!(refused, Err(ratatosk_core::EngineError::NotAllowedInChannel)),
        "без права слово не уходит; вышло {refused:?}; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn an_open_channel_works_by_the_link_alone() {
    // **Главная проверка открытого канала, и заведена она по живой
    // поломке.** Человек подписывался по ссылке — и получал пустоту:
    // ни названия, ни породы, ни слова. Причин было две, и обе
    // из разных мест спеки:
    //
    // 1. §10.3, шаг 2 — «достать представление по адресам» — не делался
    //    вовсе. У открытого канала состава нет (§6.1), веер владельца
    //    до подписчика не доходит, и документ ему было взять неоткуда;
    // 2. слова канала запечатывались ключом позиции цепочки отправителя
    //    (§11.1), а цепочка выдаётся поимённо участникам. §10.4 же
    //    говорит обратное: «`AK` совпадает с ключом из ссылки» — значит
    //    открывать обязан ключ чтения, и только он.
    //
    // Проверяется поэтому весь путь: подписался по ссылке — увидел
    // название, услышал слово, и услышал сказанное **до** подписки.
    let mut stand = Stand::strangers(0x0_09E4, 3);
    let chat = stand.create_channel(NodeId(0), "открытая лента", true);
    stand.say(NodeId(0), chat, "сказано до подписки");
    stand.settle();

    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.settle();

    // §10.3: представление приезжает по просьбе, и канал перестаёт быть
    // безымянным.
    let title = stand
        .sim
        .node(NodeId(1))
        .engine()
        .store()
        .group(&chat)
        .expect("чтение")
        .expect("канал у подписчика")
        .title;
    assert_eq!(
        title,
        "открытая лента",
        "представление обязано приехать (§10.3); сид {:#x}",
        stand.sim.seed()
    );

    // Слово, сказанное после подписки, доходит: привязка (§7.5.1)
    // сказала владельцу, кому слать, а ключ чтения из ссылки его открыл.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    stand.say(NodeId(0), chat, "сказано после");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(1)).seen(chat).contains(&"сказано после".to_owned()),
        "слово открытого канала читается ключом из ссылки; видно {:?}; сид {:#x}",
        stand.sim.node(NodeId(1)).seen(chat),
        stand.sim.seed()
    );

    // **А сказанного до подписки он не видит, и это §7.4, а не крипто.**
    // Ключом чтения из ссылки оно открылось бы — архив канала для того
    // и хранится (§7.2, §7.6). Но «вступление не оплачивает историю,
    // которую никто не открыл»: обход просит только то, что новее нашего
    // начала. Попросит её прокрутка вверх (§7.4, шаг 3), когда появится;
    // до тех пор это честная неполнота, а не поломка.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(1)).seen(chat).contains(&"сказано до подписки".to_owned()),
        "истории до подписки обход не тянет (§7.4); видно {:?}; сид {:#x}",
        stand.sim.node(NodeId(1)).seen(chat),
        stand.sim.seed()
    );
}

#[test]
fn a_node_that_stopped_seeding_serves_no_one() {
    // §8.3, вторая половина — «право на обслуживание», и §7.5.1: «не
    // раздаём — никому». Выключатель обязан гасить **и уже начатую**
    // раздачу: привязка живёт в памяти, и проверяй мы право только
    // на входе, прежние читатели получали бы блоки дальше, то есть
    // кнопка врала бы человеку.
    let mut stand = Stand::strangers(0x0_FF5EED, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    // **Владелец до читателя не достаёт** — иначе «дошло через сида»
    // неотличимо от «дошло само» (тот же довод, что у ретрансляции).
    for kind in [
        TransportKind::Onion,
        TransportKind::Mail,
        TransportKind::Lan,
        TransportKind::Bt,
        TransportKind::Ygg,
        TransportKind::Nostr,
    ] {
        stand.sim.net_mut().set_link_profile(
            NodeId(0),
            NodeId(2),
            kind,
            LinkProfile { loss_permille: 1_000, ..LinkProfile::INSTANT },
        );
    }

    // Пока сид раздаёт — слово доходит через него.
    stand.say(NodeId(0), chat, "через сида");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"через сида".to_owned()),
        "рой работает — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Человек выключил раздачу.
    stand.sim.act(NodeId(1), |node, ctx| {
        node.command(ctx, Command::SetSeeding { chat, mode: ratatosk_proto::swarm::Seeding::Off });
    });
    stand.settle();

    stand.say(NodeId(0), chat, "после выключателя");
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"после выключателя".to_owned()),
        "выключивший раздачу не отдаёт ничего и никому (§7.5.1); сид {:#x}",
        stand.sim.seed()
    );
    // **Чего проверка не стережёт.** Что выключивший продолжает
    // **принимать**: раздача и чтение — разные вещи, и это видно
    // по следующей строке, а не по правилу.
    assert!(
        stand.sim.node(NodeId(1)).seen(chat).contains(&"после выключателя".to_owned()),
        "сам он слово принял: выключен не канал, а раздача; сид {:#x}",
        stand.sim.seed()
    );
}

/// Канал, где до читателя достаёт **только** сид: владелец оборван.
///
/// Отдаёт стенд, канал и узлы «сид» (1) и «читатель» (2). Нужен
/// проверкам про уровни отдачи (§12) и про выключатель: только так
/// «не отдал» отличимо от «дошло само».
fn a_channel_where_the_reader_depends_on_the_seed(seed: u64, strangers: bool) -> (Stand, [u8; 16]) {
    let mut stand = if strangers { Stand::strangers(seed, 3) } else { Stand::new(seed, 3) };
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    for kind in [
        TransportKind::Onion,
        TransportKind::Mail,
        TransportKind::Lan,
        TransportKind::Bt,
        TransportKind::Ygg,
        TransportKind::Nostr,
    ] {
        stand.sim.net_mut().set_link_profile(
            NodeId(0),
            NodeId(2),
            kind,
            LinkProfile { loss_permille: 1_000, ..LinkProfile::INSTANT },
        );
    }
    (stand, chat)
}

#[test]
fn a_seed_that_shares_only_with_contacts_does_not_serve_a_stranger() {
    // §12, «уровни отдачи»: всем (умолчание) / только контактам / только
    // сверенным. Читатель канала контактом сиду **не становится** (§8.3,
    // третий вид записи), и это ровно тот случай, ради которого §12
    // предупреждает: рой сворачивается в граф контактов.
    let (mut stand, chat) = a_channel_where_the_reader_depends_on_the_seed(0x0_5A6E, true);

    // Умолчание — «всем», и через сида слово доходит.
    stand.say(NodeId(0), chat, "при умолчании");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"при умолчании".to_owned()),
        "умолчание §12 открытое — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Человек сузил круг до контактов.
    stand.set_sharing(NodeId(1), Some(chat), Some(ratatosk_proto::swarm::Sharing::Contacts));
    stand.say(NodeId(0), chat, "после сужения");
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"после сужения".to_owned()),
        "«только контактам» не отдаёт незнакомому читателю (§12); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_seed_that_shares_only_with_contacts_still_serves_a_contact() {
    // Вторая половина того же правила: уровень отсекает **чужих**,
    // а не всех. Без этой проверки «только контактам» было бы
    // неотличимо от «не раздаю» — а §12 держит их разными.
    let (mut stand, chat) = a_channel_where_the_reader_depends_on_the_seed(0x0_C0A7AC7, false);
    stand.set_sharing(NodeId(1), Some(chat), Some(ratatosk_proto::swarm::Sharing::Contacts));

    stand.say(NodeId(0), chat, "своему");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"своему".to_owned()),
        "контакту отдаём и при суженном круге (§12); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_channel_override_beats_the_account_default() {
    // §12 держит уровень «на аккаунт, с переопределением на группу».
    // Проверяется то, ради чего переопределение и заведено: аккаунт
    // сужен, а один канал человек оставил открытым — и этот канал
    // раздаётся.
    //
    // Пустая клетка у канала обязана отличаться от кода «всем»: сотри
    // мы разницу, поднятое умолчание аккаунта не поднялось бы ни в одном
    // канале, где когда-то нажимали кнопку.
    let (mut stand, chat) = a_channel_where_the_reader_depends_on_the_seed(0x0_0BE11A, true);

    stand.set_sharing(NodeId(1), None, Some(ratatosk_proto::swarm::Sharing::Contacts));
    stand.say(NodeId(0), chat, "при суженном аккаунте");
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"при суженном аккаунте".to_owned()),
        "умолчание аккаунта действует и без переопределения; сид {:#x}",
        stand.sim.seed()
    );

    // Этот канал человек оставляет открытым — и только этот.
    stand.set_sharing(NodeId(1), Some(chat), Some(ratatosk_proto::swarm::Sharing::Everyone));
    stand.say(NodeId(0), chat, "с переопределением");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"с переопределением".to_owned()),
        "переопределение канала сильнее умолчания аккаунта (§12); сид {:#x}",
        stand.sim.seed()
    );

    // И снятое переопределение возвращает канал к умолчанию аккаунта —
    // а не к «всем».
    stand.set_sharing(NodeId(1), Some(chat), None);
    stand.say(NodeId(0), chat, "после снятия");
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).contains(&"после снятия".to_owned()),
        "пустая клетка значит «как у аккаунта», а не «всем» (§12); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn silent_seeding_gives_back_to_the_seed_it_dialled() {
    // §7.5.1, тихая раздача — умолчание: «адрес не раскрывается, набрать
    // нас нельзя, но по своим исходящим соединениям мы несём трафик
    // наравне со всеми». Проверяется именно это: читатель отдаёт блок
    // **своему** сиду — тому, к кому подключился сам.
    //
    // Сценарий обратный обычному: пропустил слово не читатель, а сид.
    let mut stand = Stand::strangers(0x51_1E17, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    // Сида нет в сети; слово доходит до читателя напрямую от владельца.
    stand.offline(NodeId(1));
    stand.say(NodeId(0), chat, "мимо сида");
    stand.settle();
    // **Очередь владельца сдалась** — иначе слово доедет до сида ею,
    // и «отдал читатель» будет неотличимо от «долежало в очереди».
    stand.drop_queue(NodeId(0));
    stand.online(NodeId(1));
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(1)).seen(chat).contains(&"мимо сида".to_owned()),
        "сид пропустил слово — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Обход: читатель привязывается заново и шлёт свой вектор. Сид видит,
    // что отстал, и просит — а читатель отдаёт, потому что это **его**
    // сид, тот, к кому он подключился сам.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        stand.sim.node(NodeId(1)).seen(chat).contains(&"мимо сида".to_owned()),
        "тихая раздача отдаёт тому, к кому подключились сами (§7.5.1); сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_hole_in_the_middle_is_asked_for_and_not_written_off() {
    // **§7.3 целиком**: «узел, имеющий 46 и 48, знает, что 47
    // существует, а не догадывается по молчанию».
    //
    // Поломка, из-за которой проверка заведена: анти-энтропия просила
    // только то, что **новее** нашего последнего, а have-вектор врал —
    // отдавал на автора одну строку от первого номера до последнего.
    // Читатель, пропавший на два слова и вернувшийся к третьему,
    // объявлял пропущенное своим и не просил его никогда. Снаружи:
    // «в середине ленты дырка, и она не зарастает».
    let mut stand = Stand::strangers(0x40_1E15, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    stand.say(NodeId(0), chat, "первое");
    stand.settle();

    // Читателя нет — два слова проходят мимо него, но не мимо сида.
    stand.offline(NodeId(2));
    stand.say(NodeId(0), chat, "второе");
    stand.settle();
    stand.say(NodeId(0), chat, "третье");
    stand.settle();

    // **Очереди сдались** — иначе пропущенное доедет §5.4, и проверка
    // пройдёт, ничего не проверив.
    stand.drop_queue(NodeId(0));
    stand.drop_queue(NodeId(1));
    stand.online(NodeId(2));
    stand.settle();

    // Живая лента продолжается, и **дыра оказывается посередине**:
    // четвёртое слово читатель принимает деревом, а второго и третьего
    // у него по-прежнему нет.
    stand.say(NodeId(0), chat, "четвёртое");
    stand.settle();
    let seen = stand.sim.node(NodeId(2)).seen(chat);
    assert!(seen.contains(&"четвёртое".to_owned()), "живая лента идёт мимо дыры");
    assert!(
        !seen.contains(&"второе".to_owned()),
        "пропущенное пока не вернулось — иначе проверка ниже пуста; сид {:#x}",
        stand.sim.seed()
    );

    // Обход привязывает читателя заново, и обмен векторами показывает
    // дыру **номером**. Час модельного времени обязателен: обход ходит
    // не чаще раза в час.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();

    let seen = stand.sim.node(NodeId(2)).seen(chat);
    for word in ["первое", "второе", "третье", "четвёртое"] {
        assert!(
            seen.contains(&word.to_owned()),
            "дыра обязана зарасти: «{word}» не вернулось, видно {seen:?}; сид {:#x}",
            stand.sim.seed()
        );
    }
    // **Чего проверка не стережёт.** Что дыра зарастает **раньше**
    // обхода: другого повода спросить у ядра нет, и полтора часа тишины
    // — честная цена. И что зарастёт дыра глубиной больше ста двадцати
    // восьми блоков: ответ ограничен (§7.2), а второй круг спросит
    // следующий кусок — но это уже про число обходов, а не про правило.
}

#[test]
fn scrolling_up_pulls_a_page_of_history_and_says_when_there_is_no_more() {
    // §7.4, шаг 3: «архив — по требованию, при прокрутке вверх».
    //
    // Второй шаг (§7.4) обход не делает нарочно: «вступление
    // не оплачивает историю, которую никто не открыл». Значит глубину
    // тянет человек, и проверяется тут обе половины имени: страница
    // приезжает — и когда её больше нет, об этом говорят словами,
    // а не молчанием.
    let mut stand = Stand::strangers(0x0_5C011, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // Лента прожила шесть десятков слов — их слышал первый читатель.
    // Число больше страницы (§7.4): одна прокрутка обязана принести
    // не всё, иначе «одно движение — одна страница» проверить нечем.
    for i in 0..60 {
        stand.say(NodeId(0), chat, &format!("слово {i}"));
    }
    stand.settle();

    // Второй приходит позже и видит пустоту: §7.4, шаг 3 ещё не позвали.
    stand.subscribe(NodeId(2), &link);
    stand.admit(NodeId(0), chat, NodeId(2));
    stand.settle();
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert!(
        !stand.sim.node(NodeId(2)).seen(chat).iter().any(|w| w.starts_with("слово")),
        "до просьбы истории не бывает (§7.4); сид {:#x}",
        stand.sim.seed()
    );

    // Человек долистал до начала и попросил ещё.
    let _ = stand.pull_older(NodeId(2), chat);
    let after_first = stand.sim.node(NodeId(2)).seen(chat);
    assert!(
        after_first.iter().any(|w| w.starts_with("слово")),
        "прокрутка обязана принести страницу; видно {after_first:?}; сид {:#x}",
        stand.sim.seed()
    );
    assert!(
        !after_first.contains(&"слово 0".to_owned()),
        "и ровно страницу, а не всю ленту; видно {} строк; сид {:#x}",
        after_first.len(),
        stand.sim.seed()
    );

    // **А сама по себе история дальше не тянется.** Обход проходит,
    // вектора едут — и ничего не прибавляется: §7.4 отдаёт глубину
    // по требованию, и требование было одно.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    assert_eq!(
        stand.sim.node(NodeId(2)).seen(chat).len(),
        after_first.len(),
        "без просьбы обход глубины не тянет (§7.4); сид {:#x}",
        stand.sim.seed()
    );

    // Листает дальше, пока лента не кончится — и тогда ему говорят
    // «дальше некуда», а не молчат.
    let mut ended = false;
    for _ in 0..8 {
        let events = stand.pull_older(NodeId(2), chat);
        if events.iter().any(|e| matches!(e, Event::ChannelHistoryEnd { chat: c } if *c == chat)) {
            ended = true;
            break;
        }
    }
    assert!(ended, "кончившаяся история объявляется словами; сид {:#x}", stand.sim.seed());
    let seen = stand.sim.node(NodeId(2)).seen(chat);
    assert!(
        seen.contains(&"слово 0".to_owned()),
        "долистали до начала — первое слово на месте; видно {seen:?}; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_newcomer_does_not_pay_for_the_history_nobody_asked_for() {
    // §7.4: «вступление не оплачивает историю, которую никто не открыл».
    //
    // **С тех пор как содержимое канала открывается ключом чтения**
    // (§6.1, §10.4), граница здесь перестала быть крипто и стала
    // политикой: прочесть новичок может всё, что ему отдадут, — вопрос
    // в том, что он просит. Не просит ничего: лента начинается с первого
    // живого слова, а прошлое дождётся прокрутки вверх (§7.4, шаг 3).
    //
    // Проверка — **замер**: считается, сколько кадров стоит появление
    // новичка в канале с прожитой историей. Иначе правило неразличимо:
    // по журналу «взяли страницу» и «взяли всё» выглядят одинаково,
    // если не считать кадры.
    let mut stand = Stand::strangers(0x0_7A1E, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // Двадцать слов до прихода новичка — история, которой ему не видать.
    for i in 0..20 {
        stand.say(NodeId(0), chat, &format!("слово {i}"));
    }
    stand.settle();

    let before = stand.frames_sent();
    stand.subscribe(NodeId(2), &link);
    stand.admit(NodeId(0), chat, NodeId(2));
    stand.settle();
    // Обход: новичок привязывается к сиду и меняется с ним векторами.
    stand.sleep_for(2 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    let joining = stand.frames_sent() - before;

    // **Число своё, не из крейта, и с запасом в обе стороны.** Замерено:
    // с границей §7.4 вступление стоит около сорока кадров, без всякой
    // границы — сто двадцать четыре: двадцать блоков истории, просьбы
    // за ними и квитанции. Порог посередине; сдвинется цена в любую
    // сторону — проверка скажет об этом.
    assert!(
        joining < 80,
        "вступление не оплачивает историю: {joining} кадров; сид {:#x}",
        stand.sim.seed()
    );
    // **И привязка при этом состоялась** — иначе замер был бы пуст:
    // не спросив никого, новичок не заплатил бы за историю и с самой
    // дырявой границей.
    assert!(
        !stand.seeds(NodeId(2), chat).is_empty(),
        "впущенному обязан приехать каталог: без него он не привяжется ни к кому; сид {:#x}",
        stand.sim.seed()
    );
    // И ленты до себя он не увидел: она есть в архиве и открылась бы
    // его ключом, но обход её не просит (§7.4).
    let seen = stand.sim.node(NodeId(2)).seen(chat);
    assert!(
        !seen.iter().any(|word| word.starts_with("слово")),
        "истории вступление не оплачивает; видно {seen:?}"
    );

    // А живую ленту — видит: проверка выше была бы пуста, если бы канал
    // просто не работал.
    stand.say(NodeId(0), chat, "после прихода");
    stand.settle();
    assert!(
        stand.sim.node(NodeId(2)).seen(chat).contains(&"после прихода".to_owned()),
        "новичок обязан слышать канал с момента вступления; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn the_archive_outlives_a_restart_and_answers_a_graft() {
    // **Хвост в памяти стал архивом на диске** (§9.3), и проверяется это
    // тем, ради чего замена делалась: перезапуском. Сид, поднявшийся
    // заново, обязан ответить на зов о блоке, который принял до того.
    //
    // Проверка **не** стережёт саму анти-энтропию (§7.2): have-вектора
    // и просьбы ещё нет. Она стережёт то, на чём та будет стоять.
    let mut stand = Stand::strangers(0xA5C0_FFEE, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.say(NodeId(0), chat, "в архив");
    stand.settle();

    let seed = NodeId(1);
    let archived = stand.sim.node(seed).engine().store().archive_have(&chat).expect("архив");
    let owner_ik = stand.ik(NodeId(0));
    assert!(!archived.is_empty(), "у читателя лёг журнал владельца");
    assert!(
        archived.iter().all(|range| range.author_ik == owner_ik),
        "в канале публикует владелец, и автор в векторе один; вектор: {archived:?}"
    );
    assert_eq!(archived[0].first_seq, 0, "префикс ещё не обрезан окном");
    // **Строк у одного автора бывает несколько, и это честность вектора.**
    // Адресный блок — ключ чтения впущенному — занимает позицию, но
    // до второго читателя не доезжает; вектор обязан показать провал,
    // а не объявить пропущенное своим (§7.3).
    // **У автора журнал непрерывен — у читателя нет, и это не поломка.**
    // §7.3 обещает: «узел, имеющий 46 и 48, знает, что 47 существует».
    // У нас цепочка отправителя одна на всё: и на то, что едет веером,
    // и на **адресные** блоки — ключ чтения впущенному, запись о впуске
    // владельцу. Адресный блок занимает позицию, но до остальных
    // не доезжает, и дыра у читателя означает «не мне», а не «потеряно».
    //
    // Значит непрерывность проверяется **у владельца**: у него лежит
    // всё, что он подписал.
    let at_owner = stand
        .sim
        .node(NodeId(0))
        .engine()
        .store()
        .archived_range(&chat, &stand.ik(NodeId(0)), 0, 1_000)
        .expect("кадры");
    let seqs: Vec<u64> = at_owner.iter().map(|b| b.seq).collect();
    assert_eq!(
        seqs,
        (0..seqs.len() as u64).collect::<Vec<_>>(),
        "у автора номера идут подряд; сид {:#x}",
        stand.sim.seed()
    );
    let all = stand
        .sim
        .node(seed)
        .engine()
        .store()
        .archived_range(&chat, &stand.ik(NodeId(0)), 0, 1_000)
        .expect("кадры");
    assert!(
        all.len() < at_owner.len(),
        "читателю адресные блоки чужих не достаются — дыры законны"
    );

    stand.restart(seed);
    let after = stand.sim.node(seed).engine().store().archive_have(&chat).expect("архив");
    assert_eq!(after, archived, "архив на диске: перезапуск его не трогает");

    // И сам кадр цел — им отвечают на `GRAFT`, а значит он обязан быть
    // ровно тем, что приехало, байт в байт.
    assert!(
        all.iter().all(|block| !block.frame.is_empty()),
        "кадры хранятся целиком, а не одними метками: отдавать придётся шифротекст (§7.6)"
    );
}

#[test]
fn the_window_from_the_representation_is_what_cuts_the_archive() {
    // §9.3: «для канала окно не технический параметр… значит лежит
    // в подписанном представлении». Обрезает обход, и берёт он окно
    // **оттуда** — не умолчание крейта и не своё число.
    let mut stand = Stand::strangers(0xB0_1111, 2);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();
    for word in ["раз", "два", "три"] {
        stand.say(NodeId(0), chat, word);
        stand.settle();
    }
    let reader = NodeId(1);
    let before = stand.sim.node(reader).engine().store().archive_have(&chat).expect("архив");
    // Последний номер берётся по всем строкам: у читателя вектор бывает
    // из нескольких кусков — адресные блоки чужих до него не доезжают
    // и оставляют провалы (§7.3).
    let last_before = before.iter().map(|range| range.last_seq).max().expect("журнал не пуст");
    assert_eq!(before[0].first_seq, 0, "журнал с начала");
    assert!(last_before >= 2, "три слова добавили три позиции");

    // Год спустя окно в тридцать суток (умолчание §9.3) снимает весь
    // прежний префикс, и делает это обход, а не показ.
    //
    // **Проверяется поднявшийся `first_seq`, а не пустой архив**, и это
    // не придирка: тот же обход поворачивает ключ чтения (§6.4), и его
    // блок ложится в архив свежим. Пустоты тут не бывает — бывает
    // сдвинутое начало, ровно как обещает §9.3: «удаляется префикс
    // журнала, `first_seq` в have-векторе поднимается».
    stand.sleep_for(365 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    let after = stand.sim.node(reader).engine().store().archive_have(&chat).expect("архив");
    assert!(
        after.iter().all(|range| range.first_seq > last_before),
        "окно обязано было снять весь прежний журнал: было {:?}, стало {after:?}; сид {:#x}",
        before,
        stand.sim.seed()
    );
}

#[test]
fn a_prune_at_a_seed_holds_and_the_second_word_costs_less() {
    // **Находка живого прогона на шести узлах поверх меша.** Дерево
    // подрезалось и тут же отрастало: каждое слово стоило восьми блоков
    // вместо пяти, читатели слали `PRUNE` сиду при каждом слове, и он
    // при каждом слове возвращал их в eager.
    //
    // Причина — в том, что «рой жив» считалось одинаково для всех.
    // Сид смотрел в каталог, видел там **только себя** и решал, что роя
    // нет, — а «роя нет» означает звезду (§7.5.2), то есть всем целиком.
    // Для владельца это верно: второй путь для ленивого есть, только
    // если в канале есть сид. Для всех остальных — неверно всегда:
    // первый путь у ленивого это сам владелец, а мы и есть второй.
    //
    // Проверка меряет **блоки**, а не форму дерева: форма — средство,
    // а обещание §7.1 — про цену.
    let mut stand = Stand::strangers(0x9EED_5EED, 6);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..6u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    stand.settle();

    // Первое слово: дерево ещё не подрезано, дубли законны.
    let before = stand.frames_sent();
    stand.say(NodeId(0), chat, "раз");
    stand.settle();
    let first = stand.frames_sent() - before;
    // Второе: `PRUNE` первого круга обязаны были осесть.
    let before = stand.frames_sent();
    stand.say(NodeId(0), chat, "два");
    stand.settle();
    let second = stand.frames_sent() - before;
    // Третье: дерево уже сошлось, и цена не растёт.
    let before = stand.frames_sent();
    stand.say(NodeId(0), chat, "три");
    stand.settle();
    let third = stand.frames_sent() - before;

    for reader in 1..6u16 {
        assert!(
            stand.sim.node(NodeId(reader)).seen(chat).contains(&"три".to_owned()),
            "читатель {reader} остался без слова; сид {:#x}",
            stand.sim.seed()
        );
    }
    // **Дерево сходится, и это видно по кадрам.** Первое слово дороже:
    // дубли ещё законны, и на них же едут `PRUNE`. Третье обязано стоить
    // заметно меньше первого — иначе подрезка не держится, и рой шумит
    // ровно столько же, сколько звезда, только с лишними кадрами.
    assert!(
        third < first,
        "дерево не сошлось: первое слово {first} кадров, третье {third}; сид {:#x}",
        stand.sim.seed()
    );
    assert_eq!(third, second, "сошлось — значит цена перестала меняться");
}

#[test]
fn a_seed_becomes_known_to_every_reader() {
    // **§7.5 целиком, на трёх узлах.** Читатель вызвался раздавать —
    // и об этом обязаны узнать остальные читатели, иначе спрашивать
    // блоки будет не у кого, когда появится дерево (§7.1).
    //
    // Везёт это владелец: состав канала знает он (§3.2), и сам читатель
    // развезти не может — других читателей он не знает. Здесь это
    // и проверяется: Кэрол узнаёт про Боба, **не зная Боба**.
    let mut stand = Stand::strangers(0x5EED_C0DE, 3);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    for reader in 1..3u16 {
        stand.subscribe(NodeId(reader), &link);
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();

    assert!(stand.seeds(NodeId(2), chat).is_empty(), "до объявления каталог пуст");

    stand.announce_seeding(NodeId(1), chat);

    let bob = stand.ik(NodeId(1));
    assert_eq!(stand.seeds(NodeId(0), chat), vec![bob], "владелец принял запись");
    assert_eq!(
        stand.seeds(NodeId(2), chat),
        vec![bob],
        "и развёз её читателю, который сида не знает; сид {:#x}",
        stand.sim.seed()
    );
    assert!(
        !stand.sim.node(NodeId(2)).engine().contacts().contains_key(&bob),
        "знакомым сид при этом не становится (§3.2, §8.3)"
    );
    // Подпись у Кэрол не сходится не потому, что запись плоха, а потому,
    // что карточки Боба у неё нет вовсе. Сказать это надо вслух: иначе
    // «не проверено» читается как «подделка».
    let at_carol =
        stand.sim.node(NodeId(2)).engine().seeds(chat, stand.sim.now_ms()).expect("каталог");
    assert!(!at_carol[0].verified, "карточки сида у читателя нет — проверять нечем (§3.2)");
    assert!(
        stand.sim.node(NodeId(0)).engine().seeds(chat, stand.sim.now_ms()).unwrap()[0].verified,
        "а у владельца карточка есть, и подпись сошлась"
    );
}

#[test]
fn a_catalogue_entry_dies_of_old_age() {
    // §7.5: «срок годности убирает ушедших — перестал продлевать, выпал».
    // Отзыва нет нарочно: ушедший чаще всего просто выключил телефон,
    // и дождаться от него отзыва было бы нельзя.
    //
    // Число здесь своё, а не из крейта: проверка стережёт обещание
    // «неделя», и возьми она константу, продление срока подняло бы и её.
    let mut stand = Stand::strangers(0x0DD_5EED, 2);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);
    assert_eq!(stand.seeds(NodeId(0), chat).len(), 1);

    // **Читатель перестал раздавать.** Отказ по сети не едет вовсе
    // (§7.5 отзыва не знает), и у владельца запись всё ещё лежит —
    // именно это и должно кончиться сроком, а не сообщением.
    stand.sim.act(NodeId(1), |node, ctx| {
        node.command(
            ctx,
            Command::SetSeeding { chat, mode: ratatosk_proto::swarm::Seeding::Quiet },
        );
    });
    stand.settle();
    assert_eq!(
        stand.seeds(NodeId(0), chat).len(),
        1,
        "отказ владельцу не уезжает: гасит объявление срок, а не кадр"
    );
    assert!(stand.seeds(NodeId(1), chat).is_empty(), "а у себя раздающий себя не держит");

    // Шесть суток спустя запись ещё жива...
    stand.sleep_for(6 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    assert_eq!(stand.seeds(NodeId(0), chat).len(), 1, "неделя ещё не вышла");

    // ...а на восьмые её нет, и убрала её уборка, а не показ.
    stand.sleep_for(2 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    assert!(
        stand.seeds(NodeId(0), chat).is_empty(),
        "запись обязана выпасть по сроку; сид {:#x}",
        stand.sim.seed()
    );
    assert!(
        stand.sim.node(NodeId(0)).engine().store().seeds(&chat).expect("диск").is_empty(),
        "и с диска тоже: иначе она вернулась бы после перезапуска"
    );
}

#[test]
fn a_seed_keeps_its_place_by_renewing() {
    // Вторая половина того же правила: **кто продлевает, тот остаётся**.
    // Без неё проверка выше зелена оттого, что запись умирает всегда.
    let mut stand = Stand::strangers(0xC0FFEE, 2);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);
    stand.subscribe(NodeId(1), &link);
    stand.admit(NodeId(0), chat, NodeId(1));
    stand.settle();
    stand.announce_seeding(NodeId(1), chat);

    // Шесть суток — внутри окна продления (двое суток до конца срока):
    // обслуживание обязано переподписать запись и разослать заново.
    stand.sleep_for(6 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    stand.settle();
    stand.sleep_for(3 * 24 * 60 * 60 * 1000);
    stand.maintenance();
    assert_eq!(
        stand.seeds(NodeId(0), chat).len(),
        1,
        "продлённая запись пережила свой первый срок; сид {:#x}",
        stand.sim.seed()
    );
}

#[test]
fn a_channel_lives_among_nodes_that_know_nobody() {
    // **Стенд для роя, первый его сценарий.** `Stand::new` знакомит всех
    // со всеми — «как при встрече по QR», — и на такой популяции канал
    // проверяется не тот: в канале узлы друг другу не контакты, в этом
    // весь §8.3. Здесь знакомства нет ни у кого, и единственный путь
    // к владельцу — ссылка (§10.1).
    //
    // Проверка **не** стережёт рой: раздача по-прежнему звездой, и слово
    // владельца развозит он сам (§7.5.2). Она стережёт посылку, на которой
    // рой будет строиться, — что узлы доходят друг до друга, никого
    // не заводя в знакомые.
    let mut stand = Stand::strangers(0x5EED_D00D, 4);
    let chat = stand.create_channel(NodeId(0), "лента", false);
    let link = stand.channel_link(NodeId(0), chat);

    for reader in 1..4u16 {
        stand.subscribe(NodeId(reader), &link);
    }
    // Заявки §10.4 доехали до владельца — по ссылке, без единого
    // знакомства.
    assert_eq!(
        stand.sim.node(NodeId(0)).engine().store().channel_requests(&chat).expect("заявки").len(),
        3,
        "трое попросились, и все трое дошли; сид {:#x}",
        stand.sim.seed()
    );

    for reader in 1..4u16 {
        stand.admit(NodeId(0), chat, NodeId(reader));
    }
    stand.settle();
    stand.say(NodeId(0), chat, "слово");
    stand.settle();

    for reader in 1..4u16 {
        let node = stand.sim.node(NodeId(reader));
        assert_eq!(
            node.seen(chat),
            vec!["слово".to_owned()],
            "читатель {reader} не услышал владельца; сид {:#x}",
            stand.sim.seed()
        );
        assert!(
            node.engine().contacts().is_empty(),
            "читатель {reader} завёл знакомых, хотя ни с кем не говорил (§8.3)"
        );
    }
    assert!(
        stand.sim.node(NodeId(0)).engine().contacts().is_empty(),
        "и у владельца: канал на сотню читателей — не сотня знакомых"
    );
    assert_eq!(
        stand.sim.node(NodeId(0)).engine().groups()[&chat].group.members().count(),
        4,
        "а состав у владельца полон — он его и ведёт (§3.2)"
    );
}

#[test]
fn files_cross_in_the_air_in_both_directions() {
    // **Разбор со стенда: «файлы ходят, но как-то в одну сторону».**
    //
    // Файлов в стенде не было вовсе — ни одного сценария, — и это само
    // по себе объяснение тому, почему файловые поломки доезжали до живых
    // устройств. Провод `pair.rs` проверяет протокол без потерь и без
    // времени; здесь есть и то и другое: профиль эфира теряет два кадра
    // из тысячи, сроки молчания выходят по-настоящему, а предел
    // одновременных передач на этой ступени равен одному (§10.2).
    //
    // Встречное движение здесь и есть проверка: у обеих передач один
    // канал, одни сроки и один предел.
    let mut stand = Stand::without_mail(0x5749, 2);
    stand.air_only();
    stand.accept_everything(A);
    stand.accept_everything(B);

    let chat_from_a = stand.chat_with(B);
    let chat_from_b = stand.chat_with(A);

    // Размеры взяты так, чтобы окно эфира (тринадцать чанков) закрывалось
    // не на первом же куске: иначе проверялась бы отправка, а не передача.
    let air = ratatosk_proto::files::chunk_bytes_for(Transport::Bt);
    let there: Vec<u8> = (0..air * 20 + 7).map(|i| (i % 251) as u8).collect();
    let back: Vec<u8> = (0..air * 17 + 3).map(|i| ((i * 7) % 241) as u8).collect();

    stand.send_file(A, chat_from_a, "tuda.bin", &there);
    stand.send_file(B, chat_from_b, "obratno.bin", &back);
    stand.settle();

    assert_eq!(
        stand.received_file(B, chat_from_b, "tuda.bin").as_deref(),
        Some(there.as_slice()),
        "файл туда обязан доехать целиком"
    );
    assert_eq!(
        stand.received_file(A, chat_from_a, "obratno.bin").as_deref(),
        Some(back.as_slice()),
        "и обратный тоже — «ходят в одну сторону» это и есть поломка"
    );
}

#[test]
fn several_files_cross_in_a_lossy_air() {
    // То же встречное движение, но по-настоящему тесно: по три файла
    // с каждой стороны и потери вдесятеро выше обычных для эфира.
    //
    // Десять кадров из тысячи — это не выдумка ради строгости: столько
    // теряет приёмный путь Android на классе M (0.4.8), и хотя чанки
    // теперь класса S, запас проверить дешевле, чем объяснять потом.
    // Каждая потеря стоит срока молчания, а срок — очереди: вот здесь
    // и видно, разбирается она или встаёт.
    let mut stand = Stand::without_mail(0x574a, 2);
    stand.air_only();
    stand
        .sim
        .net_mut()
        .set_profile(TransportKind::Bt, LinkProfile { loss_permille: 20, ..LinkProfile::BT });
    stand.accept_everything(A);
    stand.accept_everything(B);

    let chat_from_a = stand.chat_with(B);
    let chat_from_b = stand.chat_with(A);
    let air = ratatosk_proto::files::chunk_bytes_for(Transport::Bt);

    let mut sent: Vec<(NodeId, [u8; 16], String, Vec<u8>)> = Vec::new();
    for n in 1..=3usize {
        let there: Vec<u8> = (0..air * (n + 4) + n).map(|i| ((i + n) % 251) as u8).collect();
        let back: Vec<u8> = (0..air * (n + 2) + n).map(|i| ((i * 3 + n) % 241) as u8).collect();
        sent.push((B, chat_from_b, format!("tuda{n}.bin"), there));
        sent.push((A, chat_from_a, format!("obratno{n}.bin"), back));
    }
    for (who, chat, name, bytes) in &sent {
        // Отправляет тот, кто **не** назван: названный — получатель.
        let from = if *who == A { B } else { A };
        let chat_from_sender = if from == A { chat_from_a } else { chat_from_b };
        let _ = chat;
        stand.send_file(from, chat_from_sender, name, bytes);
    }
    stand.settle();

    for (who, chat, name, bytes) in &sent {
        assert_eq!(
            stand.received_file(*who, *chat, name).as_deref(),
            Some(bytes.as_slice()),
            "файл {name} не доехал целиком"
        );
    }
}

#[test]
fn a_silent_sender_does_not_block_the_whole_receiving_side() {
    // **Запирание канала.** Предел одновременных загрузок на эфире — один
    // файл (§10.2). Пока файл числится идущим, следующий стоит в очереди;
    // а числится он идущим и тогда, когда отдавать его перестали.
    //
    // Собеседник, **пропавший из сети**, полосу освобождает сам: канала
    // до него нет, и `ask_for_file` честно отвечает «ехать некуда». Беда
    // с тем, кто в сети и молчит, — а это обычное дело: у него исчез
    // исходник (человек переместил файл), и отдавать ему больше нечего.
    // Для получателя это неотличимо от потери кадра, и он ждёт: срок
    // молчания удваивается — восемнадцать секунд, тридцать шесть,
    // семьдесят две, — а вместе с ним стоит и очередь.
    //
    // Без уступки ступени (`YIELD_AFTER_STALLS`) файл от **второго**
    // собеседника не доезжает никогда.
    let mut stand = Stand::without_mail(0x574b, 3);
    stand.air_only();
    stand.accept_everything(A);

    let air = ratatosk_proto::files::chunk_bytes_for(Transport::Bt);
    let big: Vec<u8> = (0..air * 40 + 5).map(|i| (i % 251) as u8).collect();
    let small: Vec<u8> = (0..air * 4 + 9).map(|i| ((i * 5) % 241) as u8).collect();

    // Третий начинает первым и занимает единственную полосу эфира.
    stand.send_file(C, stand.chat_with(A), "propal.bin", &big);
    stand.run_for(1_500);

    // И тут его исходник исчезает. Отдавать больше нечего — но сказать
    // об этом получателю нечем: §10.2 не знает такого сообщения.
    let source = stand.sim.node(C).home.source().join("propal.bin");
    std::fs::remove_file(&source).expect("исходник убирается");

    // Второй предлагает свой файл. Он обязан доехать.
    stand.send_file(B, stand.chat_with(A), "ot_vtorogo.bin", &small);

    // **Ждём временем, а не тишиной.** Брошенная передача переспрашивает
    // вечно — это её честная работа, — и `settle` тут не дождётся никогда.
    // Десять минут заведомо больше и передачи мелкого файла, и двух
    // сроков молчания, после которых полоса уступается.
    stand.run_for(10 * 60 * 1000);

    assert_eq!(
        stand.received_file(A, stand.chat_with(B), "ot_vtorogo.bin").as_deref(),
        Some(small.as_slice()),
        "файл от живого собеседника обязан доехать, а не стоять за чужой замолчавшей передачей"
    );
}

#[test]
fn a_stalled_transfer_does_not_hold_the_rung_longer_and_longer() {
    // **Уступка сняла запирание, но не поделила ступень честно.**
    //
    // Срок молчания у безответной передачи удваивается — восемнадцать
    // секунд, тридцать шесть, семьдесят две, — и это правильно: долбить
    // ушедшего собеседника просьбами незачем. Неправильно другое: всё это
    // время передача **держит ступень**, а предел на эфире равен одному
    // (§10.2). Уступив по двум срокам, она тут же занимает место снова —
    // очередь-то пуста, — и следующий круг держит его вдвое дольше.
    // Через пять минут молчания круг равен пяти минутам, через час —
    // часу, а потолок отступления двенадцать часов.
    //
    // И вот тогда приходит живой собеседник. Ему ехать нечем ровно
    // столько, сколько мертвец досиживает свой очередной круг, — то есть
    // сколько угодно. Запирания нет, а толку от этого мало.
    //
    // Проверка про то, что удержание ступени **не растёт**: отступление
    // считает, как часто спрашивать, а не как долго не пускать других.
    let mut stand = Stand::without_mail(0x574c, 3);
    stand.air_only();
    stand.accept_everything(A);

    let air = ratatosk_proto::files::chunk_bytes_for(Transport::Bt);
    let big: Vec<u8> = (0..air * 40 + 5).map(|i| (i % 251) as u8).collect();
    let small: Vec<u8> = (0..air * 4 + 9).map(|i| ((i * 7) % 239) as u8).collect();

    // Третий занимает единственную полосу эфира и замолкает.
    stand.send_file(C, stand.chat_with(A), "propal.bin", &big);
    stand.run_for(1_500);
    let source = stand.sim.node(C).home.source().join("propal.bin");
    std::fs::remove_file(&source).expect("исходник убирается");

    // **Даём отступлению разойтись.** Очередь пуста, мешать некому:
    // мертвец уступает ступень и тут же занимает её снова, всякий раз
    // на вдвое больший срок. Семи минут хватает, чтобы круг перевалил
    // за минуту с запасом.
    stand.run_for(7 * 60 * 1000);

    // Теперь — живой. Его файл мелкий: на ступени он занял бы секунды.
    stand.send_file(B, stand.chat_with(A), "ot_zhivogo.bin", &small);
    stand.run_for(60 * 1000);

    assert_eq!(
        stand.received_file(A, stand.chat_with(B), "ot_zhivogo.bin").as_deref(),
        Some(small.as_slice()),
        "мертвец обязан уступить ступень за базовый срок, а не за свой разросшийся круг"
    );
}

#[test]
fn waiting_for_a_rung_is_not_paid_for_by_doubling() {
    // **Вторая половина того же правила.** Проверка выше стережёт случай,
    // когда срок держащего взведён давно и надолго: его укорачивают в тот
    // миг, когда кто-то встаёт в очередь. Здесь случай противоположный —
    // очередь появилась **раньше**, чем отступление успело начаться,
    // и укорачивать нечего.
    //
    // Тогда работает второе условие: пока ступени ждут, каждый срок
    // молчания равен базовому, а не вдвое большему предыдущего. Разница
    // ровно в один шаг отступления — на эфире восемнадцать секунд,
    // на почте тридцать восемь минут.
    let base = ratatosk_proto::files::stall_ms(Transport::Bt);
    let stalls = u64::from(ratatosk_proto::files::YIELD_AFTER_STALLS);

    let mut stand = Stand::without_mail(0x574d, 3);
    stand.air_only();
    stand.accept_everything(A);

    let air = ratatosk_proto::files::chunk_bytes_for(Transport::Bt);
    let big: Vec<u8> = (0..air * 40 + 5).map(|i| (i % 251) as u8).collect();
    let small: Vec<u8> = (0..air * 4 + 9).map(|i| ((i * 11) % 237) as u8).collect();

    stand.send_file(C, stand.chat_with(A), "propal.bin", &big);
    stand.run_for(1_500);
    let source = stand.sim.node(C).home.source().join("propal.bin");
    std::fs::remove_file(&source).expect("исходник убирается");

    // Живой встаёт в очередь сразу — отступление у мертвеца ещё нулевое.
    stand.send_file(B, stand.chat_with(A), "ot_zhivogo.bin", &small);

    // **Считаем по сроку, а не по круглому числу.** С правилом уступка
    // приходит через `YIELD_AFTER_STALLS` базовых сроков; без него —
    // через удвоения, то есть на целый срок позже. Половина срока сверху
    // оставлена мелкому файлу на дорогу.
    stand.run_for(base * stalls + base / 2);

    assert_eq!(
        stand.received_file(A, stand.chat_with(B), "ot_zhivogo.bin").as_deref(),
        Some(small.as_slice()),
        "пока ступени ждут, срок молчания обязан оставаться базовым, а не удваиваться"
    );
}

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
fn a_newcomer_gets_the_chain_where_it_stands_now() {
    // **Обещание §11.5 держится не поворотом, а позицией.** С фазы 2
    // вступление цепочку не трогает; закрывает прошлое то, что новичку
    // отдаётся состояние на **текущем** номере, а ретчет назад
    // не разворачивается.
    //
    // Значит стеречь надо именно позицию. Отдай мы цепочку с нуля — или
    // заведи новичку свежую, — он прочёл бы всё сказанное до него, и
    // проверка «не увидел старого» этого не заметила бы: старое ему просто
    // не слали.
    let mut stand = Stand::new(0x6754, 3);
    let chat = stand.create_group(A, "сперва двое");
    stand.invite(A, chat, B);
    stand.settle();
    stand.say(A, chat, "первое");
    stand.settle();
    stand.say(A, chat, "второе");
    stand.settle();

    let a_ik = stand.ik(A);
    let at_owner = stand
        .sim
        .node(A)
        .engine()
        .store()
        .sender_chain(&chat, &a_ik)
        .expect("хранилище")
        .expect("своя цепочка")
        .counter;
    assert!(at_owner >= 2, "два слова обязаны продвинуть номер: {at_owner}");

    stand.invite(A, chat, C);
    stand.settle();

    let at_newcomer = stand
        .sim
        .node(C)
        .engine()
        .store()
        .sender_chain(&chat, &a_ik)
        .expect("хранилище")
        .expect("новичку цепочку отдали")
        .counter;
    assert_eq!(
        at_newcomer, at_owner,
        "новичку цепочка обязана достаться на нынешнем номере, а не с начала"
    );

    // И то же самое с другой стороны: сказанного до него он не видит.
    stand.say(A, chat, "третье");
    stand.settle();
    stand.assert_seen(C, chat, &["третье"]);
    stand.assert_seen(B, chat, &["первое", "второе", "третье"]);
}

#[test]
fn the_evicted_cannot_read_what_the_group_says_afterwards() {
    // **Исключение перестало быть социальным (§11.4, фаза 2).**
    //
    // Раньше копии просто переставали приходить, а цепочки оставались
    // у исключённого на руках: перехвати он кадр — прочёл бы. Стенд этого
    // не показывал, потому что проверял «не пришло», а не «не открылось».
    //
    // Здесь исключённый остаётся в сети и продолжает получать кадры —
    // он по-прежнему контакт остальных, — но сказанное в группе после
    // исключения ему не открывается: цепочки повернулись.
    let mut stand = Stand::new(0x6753, 3);
    let chat = stand.create_group(A, "трое");
    stand.invite(A, chat, B);
    stand.invite(A, chat, C);
    stand.settle();

    stand.say(A, chat, "до исключения");
    stand.settle();
    stand.assert_seen(B, chat, &["до исключения"]);

    stand.evict(A, chat, B);
    stand.settle();

    // **Порознь, а не разом.** Сказанное в один миг стендового времени
    // получает равные метки HLC, и порядок между ними решает `msg_id`,
    // а он приходит из настоящей энтропии (у стенда `OsEntropy`). Проверка
    // на точный список стала бы тогда монеткой — и бросалась бы при каждом
    // прогоне.
    stand.say(A, chat, "после исключения");
    stand.settle();
    stand.say(C, chat, "и от третьего тоже");
    stand.settle();

    // Прошлое у него осталось — забрать прочитанное нельзя, и §14
    // обещает ровно это.
    stand.assert_seen(B, chat, &["до исключения"]);
    // А будущее — нет, и ни у одного из писателей.
    let seen = stand.sim.node(B).seen(chat);
    assert!(
        !seen.iter().any(|line| line.contains("после исключения")),
        "исключённый не должен прочесть сказанное владельцем после: {seen:?}"
    );
    assert!(
        !seen.iter().any(|line| line.contains("от третьего")),
        "и сказанное любым другим писателем — тоже: {seen:?}"
    );
    // **И главная половина: ключа у него нет.** Проверки выше показывают
    // только то, что копии не пришли, — а это и было старым, социальным
    // исключением. Отличить «не получил» от «не прочёл бы, получив»
    // можно единственным способом: сверить цепочку, которую он помнит,
    // с той, которой писатель пользуется теперь. Совпади они — перехват
    // кадра дал бы ему текст.
    for writer in [A, C] {
        let ik = stand.ik(writer);
        let now = stand
            .sim
            .node(writer)
            .engine()
            .store()
            .sender_chain(&chat, &ik)
            .expect("хранилище")
            .expect("своя цепочка есть");
        let remembered = stand
            .sim
            .node(B)
            .engine()
            .store()
            .sender_chain(&chat, &ik)
            .expect("хранилище")
            .expect("старая цепочка у него осталась");
        assert_ne!(
            remembered.chain, now.chain,
            "исключённый помнит ту же цепочку, какой пишут сейчас, — перехват дал бы ему текст"
        );
    }

    // Оставшиеся при этом слышат друг друга как ни в чём не бывало:
    // поворот не должен разорвать группу заодно с исключённым.
    let both = ["до исключения", "после исключения", "и от третьего тоже"];
    stand.assert_seen(C, chat, &both);
    stand.assert_seen(A, chat, &both);
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

// --- Каналы (фаза 2, §6, §10) --------------------------------------------
//
// Здесь и только здесь канал проверяется **настоящим хранилищем**
// и настоящим перезапуском. Проверки крейта (`groups.rs`, `pair.rs`) держат
// правила по одному; стенд стережёт то, что живёт между ними: что стёртое
// не возвращается с диска, что расписание срабатывает в модельном месяце
// и что сказанное каналом доезжает до читателя на другом узле.

/// Сутки в миллисекундах — чтобы сроки в сценариях читались.
///
/// Числа сроков ниже повторены **руками**, а не взяты из ядра: они
/// стерегут обещания §6.3 и §6.4, и возьми проверка константу, поднятие
/// месяца до квартала прошло бы молча (см. `CLAUDE.md`).
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[test]
fn an_unsubscribed_channel_does_not_come_back_after_a_restart() {
    // §10.6: «чат удаляется, ключи стираются». Проверяется именно
    // с диском: карта в памяти забывает что угодно, а поломка такого рода
    // выглядит как «отписался, перезапустил — канал снова здесь».
    let mut stand = Stand::new(0x6801, 2);
    let chat = stand.create_channel(A, "вестник", false);
    stand.admit(A, chat, B);
    stand.settle();
    stand.say(A, chat, "первое слово");
    stand.settle();
    stand.assert_seen(B, chat, &["первое слово"]);

    // До отписки читать есть чем — иначе следующая половина проверки
    // была бы истинной на пустом месте.
    let before = stand.sim.node(B).engine().store().archive_keys(&chat).expect("ключи чтения");
    assert!(!before.is_empty(), "до отписки поколение ключа чтения обязано быть");

    stand.unsubscribe(B, chat);
    stand.settle();

    let gone = |stand: &Stand, when: &str| {
        let node = stand.sim.node(B);
        assert!(!node.engine().groups().contains_key(&chat), "{when}: чат остался в памяти");
        let store = node.engine().store();
        assert!(
            store.archive_keys(&chat).expect("ключи чтения").is_empty(),
            "{when}: ключи чтения не стёрты — архив остался бы открытым"
        );
        assert!(store.channel(&chat).expect("представление").is_none(), "{when}: документ остался");
        assert!(
            store.subscription(&chat).expect("подписка").is_none(),
            "{when}: подписка осталась"
        );
        assert!(
            store.sender_chains(&chat).expect("цепочки").is_empty(),
            "{when}: цепочки отправителей остались"
        );
    };
    gone(&stand, "сразу после отписки");

    // Настоящий перезапуск: подъём идёт с диска, и ровно здесь жили
    // поломки этого класса.
    stand.restart(B);
    stand.settle();
    gone(&stand, "после перезапуска");

    // Блок ухода доехал: у владельца в составе снова он один (§10.6 —
    // «дешевле прислать блок ухода, чем ждать срока»).
    stand.assert_members(A, chat, 1);

    // И сказанное после ухода читателю больше не приходит.
    stand.say(A, chat, "после ухода");
    stand.settle();
    assert!(
        !stand.sim.node(B).engine().groups().contains_key(&chat),
        "ушедший не заводит канал заново от первого же слова"
    );
}

#[test]
fn the_owner_learns_about_a_leaving_reader_even_after_the_chat_is_wiped() {
    // Стык, который легко сломать уборкой: отписка **стирает чат**, а блок
    // ухода к этому моменту уже собран. Уход обязан дойти до владельца,
    // когда тот появится, — даже если у ушедшего этого чата больше нет
    // и не будет, и даже если он успел перезапуститься.
    //
    // **Чего проверка не различает, сказано вслух.** Где кадр пролежал
    // это время — в нашей очереди доставки или в спуле связи, — здесь
    // не видно: узел «не в сети» у стенда означает спул, как и у соседней
    // `a_message_waits_for_someone_who_is_away`. Проверено поломкой:
    // вычистить очередь целиком (и в памяти, и на диске) — тест остаётся
    // зелёным, потому что кадр к тому моменту уже ушёл в связь.
    // Стережёт она другое и важное: что уборка отписки не отменяет
    // **самого ухода**.
    let mut stand = Stand::new(0x6806, 2);
    let chat = stand.create_channel(A, "вестник", false);
    stand.admit(A, chat, B);
    stand.settle();

    stand.offline(A);
    stand.unsubscribe(B, chat);
    stand.settle();
    assert!(stand.sim.node(B).engine().groups().get(&chat).is_none(), "у ушедшего чата нет сразу");

    // И перезапуск ушедшего между уходом и доставкой: очередь поднимается
    // с диска, а чата, к которому она относилась, уже не существует.
    stand.restart(B);
    stand.online(A);
    stand.settle();

    stand.assert_members(A, chat, 1);
}

#[test]
fn the_read_key_turns_itself_after_a_month_and_not_before() {
    // §6.4: «раз в месяц по умолчанию». Расписание, а не таймер: ядро
    // спрашивают после каждого пробуждения, и месяц, проспанный
    // устройством, наступает при первом вопросе после него.
    //
    // Число повторено руками: возьми проверка константу ядра, растяжение
    // месяца до квартала прошло бы молча.
    let mut stand = Stand::new(0x6802, 2);
    let chat = stand.create_channel(A, "вестник", false);
    stand.admit(A, chat, B);
    stand.settle();

    stand.sleep_for(20 * DAY_MS);
    assert_eq!(
        stand.generation(A, chat),
        0,
        "раньше месяца ключ не поворачивается: каждый поворот стоит блока на читателя"
    );

    stand.sleep_for(15 * DAY_MS);
    stand.settle();
    assert_eq!(stand.generation(A, chat), 1, "через месяц ключ обязан повернуться сам");
    // И это не бухгалтерия у владельца: новое поколение доехало
    // до читателя, иначе он перестал бы читать канал на второй месяц.
    assert_eq!(stand.generation(B, chat), 1, "новое поколение обязано доехать до читателя");

    // Читатель по-прежнему читает — поворот не отрезал своего же.
    stand.say(A, chat, "после поворота");
    stand.settle();
    stand.assert_seen(B, chat, &["после поворота"]);
}

#[test]
fn an_open_channel_never_turns_its_key_by_itself() {
    // Вторая половина того же расписания, и без неё первая ничего
    // не значит: у открытого канала ключ лежит в ссылке и у всех, кому
    // её переслали (§6.1, §10.7). Поворот там — ложь о том, что доступ
    // закрыли.
    //
    // **Чего эта проверка не стережёт, сказано вслух.** Обещание держат
    // два слоя: отбор пород в обходе расписания и отказ самой команды
    // (`OpenChannelHasNoRotation`). Снятие **отбора** тест не роняет —
    // проверено поломкой: команда всё равно откажет, и поколение
    // останется нулевым. Отбор существует не ради поведения, а ради
    // журнала: без него открытый канал писал бы туда отказ каждый час
    // до скончания века. Сам отказ стережёт
    // `an_open_channel_refuses_rotation_with_words` в `pair.rs`.
    let mut stand = Stand::new(0x6803, 2);
    let chat = stand.create_channel(A, "открытый", true);
    stand.settle();

    stand.sleep_for(70 * DAY_MS);
    stand.settle();
    assert_eq!(
        stand.generation(A, chat),
        0,
        "в открытом канале поколение одно и не поворачивается никогда"
    );
}

#[test]
fn a_channel_owner_who_says_nothing_for_two_months_is_shown_as_silent() {
    // §6.3: метка «владельца не слышно» и её порог в два месяца. В ядре
    // она считается по **нашему приёму** — каталога пиров нет, — и
    // говорит поэтому «от владельца ничего не приходило».
    //
    // Порог повторён руками, и это то же правило, что у месяца выше.
    let mut stand = Stand::new(0x6804, 2);
    let chat = stand.create_channel(A, "вестник", false);
    stand.admit(A, chat, B);
    stand.settle();
    stand.say(A, chat, "последнее слово");
    stand.settle();

    stand.sleep_for(50 * DAY_MS);
    stand.settle();
    assert!(
        !stand.facts(B, chat).owner_unseen,
        "полтора месяца — ещё не отсутствие: §6.3 называет два"
    );

    stand.sleep_for(15 * DAY_MS);
    stand.settle();
    let facts = stand.facts(B, chat);
    assert!(facts.owner_unseen, "два месяца молчания обязаны стать меткой");
    assert!(
        facts.owner_quiet_ms.is_some_and(|quiet| quiet >= 60 * DAY_MS),
        "рядом с меткой едет и сам срок: человеку показывают факт, а не вывод"
    );

    // Владелец сказал слово — и метка снялась. Без этой половины проверка
    // стерегла бы только то, что счётчик растёт.
    stand.say(A, chat, "я здесь");
    stand.settle();
    assert!(!stand.facts(B, chat).owner_unseen, "услышали владельца — метки быть не должно");
}

#[test]
fn a_silent_owner_of_our_own_channel_is_not_a_thing() {
    // Своё молчание метки не заводит: владелец сам себе ничего
    // не присылает, и «от владельца ничего не приходило» на его же
    // экране означало бы поломку там, где связь не нужна.
    let mut stand = Stand::new(0x6805, 2);
    let chat = stand.create_channel(A, "вестник", false);
    stand.settle();

    stand.sleep_for(70 * DAY_MS);
    stand.settle();
    let facts = stand.facts(A, chat);
    assert!(!facts.owner_unseen, "владелец не бывает молчащим для себя");
    assert!(facts.owner_quiet_ms.is_none(), "и считать тут нечего");
}

// --- Канал на многих читателях (фаза 2, §7.5.2, §17.1) --------------------
//
// «До какого n держит звезда» — вопрос §17.1, и ответ на него меряется,
// а не угадывается. Здесь он и меряется: сколько шагов сети стоит слово
// и сколько стоит впуск. Руками это не проверить — двадцать узлов человек
// не разведёт, — и ровно за этим стенд и заведён.

#[test]
fn a_word_in_a_channel_costs_the_same_per_reader_however_many_there_are() {
    // **Звезда линейна, и это её обещание** (§7.5.2: «ноль сидов — это
    // звезда, и она обязана работать как состояние, а не как деградация»).
    // Слово владельца стоит по два шага сети на читателя — отправка
    // и квитанция, — и растёт ровно с числом читателей, а не быстрее.
    //
    // Проверяются **два размера разом**: одно число ничего не сказало бы
    // о росте, а пара говорит наклон.
    let mut cost = Vec::new();
    for readers in [4u16, 8] {
        let mut stand = Stand::new(0xA100 + u64::from(readers), readers + 1);
        let chat = stand.create_channel(A, "лента", false);
        for i in 1..=readers {
            stand.admit(A, chat, NodeId(i));
        }
        stand.settle();

        let before = stand.steps;
        stand.say(A, chat, "всем читателям");
        stand.settle();
        cost.push(stand.steps - before);

        // И услышать обязаны **все**: цена без доставки — не цена.
        for i in 1..=readers {
            stand.assert_seen(NodeId(i), chat, &["всем читателям"]);
        }
    }

    let [small, large] = [cost[0], cost[1]];
    assert_eq!(small, 8, "четыре читателя — по два шага на каждого");
    assert_eq!(large, 16, "восемь читателей — ровно вдвое, а не вчетверо");
}

#[test]
fn admitting_a_reader_costs_the_same_however_many_are_already_there() {
    // **Замер, ставший проверкой.** Впуск шёл групповой дорогой:
    // он рассказывал о новичке каждому уже впущенному и отдавал новичку
    // карточки и цепочки всех остальных. Цена росла быстрее квадрата —
    // 521 шаг на пятерых, 30 630 на двадцать пять, — и при двадцати
    // читателях очередь отложенных кадров у новичка переполнялась,
    // унося ключ чтения и представление: читатель оставался в составе
    // и навсегда глухим.
    //
    // Теперь впуск канальный (§3.2): о новичке не узнаёт никто, а он
    // получает только своё. Цена — постоянная на читателя.
    let mut cost = Vec::new();
    for readers in [4u16, 8] {
        let mut stand = Stand::new(0xA300 + u64::from(readers), readers + 1);
        let chat = stand.create_channel(A, "лента", false);
        stand.settle();
        let before = stand.steps;
        for i in 1..=readers {
            stand.admit(A, chat, NodeId(i));
        }
        stand.settle();
        cost.push((stand.steps - before) / usize::from(readers));
    }
    assert_eq!(cost[0], cost[1], "впуск обязан стоить одинаково при четырёх и при восьми");
}

#[test]
fn twenty_readers_all_hear_the_channel() {
    // Размер, на котором ломалось. Двадцать читателей — это больше, чем
    // вмещала очередь отложенных кадров у новичка (шестьдесят четыре),
    // и один из них глох навсегда. Проверка держит именно число: меньше
    // — и она перестанет стеречь то, ради чего написана.
    let readers = 20u16;
    let mut stand = Stand::new(0xA500, readers + 1);
    let chat = stand.create_channel(A, "лента", false);
    for i in 1..=readers {
        stand.admit(A, chat, NodeId(i));
    }
    stand.settle();
    stand.say(A, chat, "всем двадцати");
    stand.settle();

    for i in 1..=readers {
        stand.assert_seen(NodeId(i), chat, &["всем двадцати"]);
        let node = stand.sim.node(NodeId(i)).engine();
        assert!(
            node.store().pending_group().expect("очередь").is_empty(),
            "у читателя не должно оставаться отложенных кадров: они и терялись"
        );
        // И §3.2 разом: в своём составе читатель видит только себя.
        // Остальных девятнадцать он не знает — ни ключами, ни карточками.
        assert_eq!(
            node.groups().get(&chat).expect("канал").group.members().count(),
            1,
            "состав канала знает владелец, а не читатели"
        );
    }
    assert_eq!(
        stand.sim.node(A).engine().groups().get(&chat).expect("канал").group.members().count(),
        usize::from(readers) + 1,
        "владелец ведёт состав целиком: на нём держится звезда"
    );
}

#[test]
fn a_rotation_reaches_every_reader_and_leaves_the_one_who_left_behind() {
    // Поворот ключа (§6.4) в канале на десятке читателей: новое поколение
    // обязано доехать **до каждого**, кто в составе, и не доехать до того,
    // кого там нет. На двух узлах это проверено в `pair.rs`; здесь —
    // на десяти, с настоящим хранилищем, потому что рассылка по одному
    // запечатанному блоку на читателя это и есть то место, где цена
    // §6.4 становится видимой.
    let readers = 9u16;
    let mut stand = Stand::new(0xA200, readers + 1);
    let chat = stand.create_channel(A, "лента", false);
    for i in 1..=readers {
        stand.admit(A, chat, NodeId(i));
    }
    stand.settle();

    // Последний уходит сам — и поворот его уже не касается.
    stand.unsubscribe(NodeId(readers), chat);
    stand.settle();

    stand.sim.act(A, |node, ctx| {
        let effects = node
            .engine_mut()
            .step(ctx.now_ms(), Input::Command(Command::RotateChannelKey { chat }))
            .expect("поворот");
        node.apply(ctx, effects);
    });
    stand.settle();

    for i in 1..readers {
        assert_eq!(
            stand.generation(NodeId(i), chat),
            1,
            "новое поколение обязано доехать до каждого читателя"
        );
    }
    assert!(
        !stand.sim.node(NodeId(readers)).engine().groups().contains_key(&chat),
        "ушедшего поворот не касается: канала у него нет вовсе"
    );

    // И канал после поворота продолжает читаться — всеми, кто остался.
    stand.say(A, chat, "после поворота");
    stand.settle();
    for i in 1..readers {
        stand.assert_seen(NodeId(i), chat, &["после поворота"]);
    }
}
