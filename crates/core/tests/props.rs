//! Свойства уровня ядра: то, что обязано держаться на **любой**
//! последовательности входов, а не на одной выбранной руками.
//!
//! # Зачем отдельный файл
//!
//! `proptest` в этом дереве стоял у `crdt`, `codec` и `crypto` — то есть
//! ниже ядра, — и `TESTING.md` честно называл это самой дорогой дырой
//! в наборе: поломки, которые здесь находил стенд, а не проверки, жили
//! как раз в ядре. Пример ловит ту последовательность, которую придумал
//! автор; ядро ломалось на той, которой он не придумал.
//!
//! # Хранилище настоящее
//!
//! `SqliteStore` на временном файле, как в стенде и как в жизни. Для
//! лестницы статусов это не формальность: статус живёт в базе **числом**
//! (`DeliveryStatus::code`), и проверка на `MemoryStore` не увидела бы
//! расхождения кода с лестницей.
//!
//! # Алфавит проверяется сам
//!
//! Свойство, которое не достаёт до интересных состояний, зелено на пустом
//! месте — ровно как метелка, звавшаяся без аргументов. Первая редакция
//! этого файла так и зеленела: почти все случаи упирались в `Waiting`,
//! а до `Sent` и `Undeliverable` не доставали вовсе. Поэтому рядом
//! со свойством стоит проверка на сам алфавит
//! (`the_alphabet_reaches_the_whole_ladder`), и она поимённо называет
//! статусы, до которых скрипты обязаны доставать.
//!
//! **Она же исправила два моих объяснения, и оба были выдуманы
//! из чтения кода.** Первое: будто `Sent` ставится по `Input::Handed`
//! на любой ступени — на самом деле подтверждения передачи просит только
//! **непрямая** ступень (`arm_send`), и `Sent` — последняя ступень
//! почтовой доставки; по прямому каналу статус идёт
//! `Pending` → `Delivered` → `Read`, минуя её. Второе: будто
//! `Undeliverable` достигается удалением знакомого — на самом деле
//! удалённый остаётся в `peers` после рукопожатия, путь к нему всё ещё
//! может открыться, и ядро честно обещает «позже». `Undeliverable`
//! достаётся иначе: письмом тому, к кому путь не откроется никогда.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, OsEntropy, OutgoingFile};
use ratatosk_crypto::Identity;
use ratatosk_proto::receipts::{advance, DeliveryStatus};
use ratatosk_proto::Transport;
use ratatosk_store::{Blobs, FsBlobs, SqliteStore, Store};
use zeroize::Zeroizing;

type Node = Engine<SqliteStore>;

/// Ключ базы. Один на оба узла: PIN здесь не изучается.
fn db_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0x7c; 32])
}

/// Счётчик каталогов — та же ловушка, что в стенде: имя, зависящее
/// от сида, два прогона с одним сидом открывают один каталог, и второй
/// сносит базу из-под первого. `proptest` гоняет десятки случаев
/// в одном процессе, так что цена ошибки здесь выше.
static NEXT_HOME: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn fresh_home(who: u8) -> PathBuf {
    let unique = NEXT_HOME.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("ratatosk-props-{who}-{pid}-{unique}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("каталог узла");
    dir
}

/// Открывает ядро на каталоге — и при заведении, и при перезапуске.
///
/// Одно место на оба случая нарочно, как в стенде: разойдись они,
/// свойство проверяло бы не перезапуск, а свою вторую редакцию его.
fn open(seed: u8, home: &Path) -> Node {
    let mut store = SqliteStore::open(home.join("db.sqlite"), db_key()).expect("база");
    store.migrate().expect("миграции");
    let name = format!("узел{seed}");
    let mut engine = Engine::new(
        Identity::from_seed([seed; 32]),
        store,
        Box::new(FsBlobs::new(home.join("blobs"))),
        Box::new(OsEntropy),
        SelfAddresses {
            onion: ratatosk_crypto::OnionKey::from_seed([seed; 32]).address(),
            // **Почта нужна лестнице статусов.** `Sent` — её последняя
            // ступень и больше нигде не ставится: по прямому каналу статус
            // идёт `Pending` → `Delivered` → `Read`, а `Sent` означает
            // «письмо отдано ящику, дальше протокол не обещает ничего».
            // Без почтового адреса у обоих эта ступень недостижима, и
            // первая редакция этого файла её не проверяла, уверяя
            // в комментарии обратное.
            chatmail: format!("узел{seed}@nine.example"),
            display_name: name,
        },
    );
    engine.restore().expect("подъём с диска");
    // Onion — прямая ступень, и это здесь существенно: квитанции едут
    // только прямым каналом (`may_send_receipt`), а без них лестница
    // статусов не поднимается выше `Sent`, и половина правила осталась
    // бы непроверенной.
    for rung in [Transport::Onion, Transport::Mail] {
        engine.step(0, Input::TransportReady { transport: rung }).expect("объявление готовности");
    }
    engine
}

/// Карточка знакомого, к которому **никогда** не откроется путь.
///
/// Так выглядит человек, давший карточку со свежего устройства, на
/// котором ещё ничего не поднято: ни onion, ни ящика. Это единственная
/// дорога к `Undeliverable` в этом харнессе, и дорога честная —
/// обещать «отправим позже» тому, кому ехать нечем в принципе, §14
/// не разрешает, и ядро вместо обещания ставит «не доставлено».
///
/// Узел заводится ради карточки и шагов не делает ни одного.
fn card_of_nobody(home: &Path) -> (Vec<u8>, [u8; 32]) {
    let mut store = SqliteStore::open(home.join("db.sqlite"), db_key()).expect("база");
    store.migrate().expect("миграции");
    let mut engine = Engine::new(
        Identity::from_seed([9; 32]),
        store,
        Box::new(FsBlobs::new(home.join("blobs"))),
        Box::new(OsEntropy),
        SelfAddresses {
            onion: String::new(),
            chatmail: String::new(),
            display_name: "никто".to_owned(),
        },
    );
    engine.restore().expect("подъём");
    let card = engine.own_card();
    (card.encode().expect("карточка"), card.ik)
}

/// Что может случиться с парой узлов.
///
/// Алфавит выбран не «побольше», а по тому, какие переходы лестницы §9.4
/// он открывает: без `Hand` не бывает `Sent`, без потерь и перестановок —
/// запоздавших квитанций, без обрыва ступени — `Waiting`, без забытого
/// знакомого — `Undeliverable`, а без перезапуска не видно, что статус
/// переживает диск.
#[derive(Debug, Clone, Copy)]
enum Act {
    /// Первый пишет второму.
    Write,
    /// Транспорт подтверждает, что кадр у него — по номеру из очереди.
    ///
    /// Просит такого подтверждения только непрямая ступень (`arm_send`),
    /// и оно же единственный путь к `Sent`.
    Hand(usize),
    /// Провод отдаёт кадр по номеру, считая обе стороны: то есть не по порядку.
    Deliver(usize),
    /// Отдаёт только кадр первого — второй при этом копит свои.
    ///
    /// Нужно затем, что самый интересный случай лестницы — **запоздавшая
    /// квитанция**, а она бывает только тогда, когда у второго в очереди
    /// лежат сразу две: о доставке и о прочтении.
    DeliverOut(usize),
    /// И только кадр второго — тем самым порядок квитанций можно
    /// перевернуть нарочно.
    DeliverBack(usize),
    /// Кадр теряется.
    Lose(usize),
    /// Второй отмечает прочитанным всё, что у него есть.
    Read,
    /// У первого срабатывает взведённый срок.
    Fire(usize),
    /// Первый поднимается с диска заново.
    Restart,
    /// У первого отваливается прямая ступень.
    Unplug,
    /// И возвращается. Заодно будит отложенную очередь — её поднимает
    /// готовность ступени, а не срок.
    Plug,
    /// Отваливается и почта: только тогда ехать становится некуда вовсе.
    MailDown,
    /// И возвращается.
    MailUp,
    /// Первый пишет тому, к кому путь не откроется никогда.
    WriteNowhere,
    /// Первый отправляет файл: без него уборке сирот нечего стеречь.
    SendFile,
    /// Первый удаляет у себя самое старое видимое сообщение — надгробие.
    Delete,
    /// Часы прыгают вперёд на столько часов (до сорока пяти суток).
    ///
    /// Без прыжка уборка не наступает вовсе: её расписание требует
    /// шести часов между полными прогонами (`Schedule`), и свойство
    /// без этого проверяло бы «уборка, которой не было, ничего
    /// не испортила».
    Skip(u32),
    /// Уборка (§12) плюс выметание сирот — то, что в живом приложении
    /// делает драйвер после каждого шага.
    Tidy,
    /// Первый удаляет знакомого.
    ///
    /// К `Undeliverable` это **не** ведёт, и проверка алфавита это
    /// показала: после рукопожатия знакомый остаётся в `peers`, путь
    /// к нему может открыться, и ядро честно продолжает обещать «позже».
    /// Действие оставлено потому, что удаление посреди очереди — само
    /// по себе хорошая встряска для лестницы.
    Forget,
}

fn acts() -> impl Strategy<Value = Vec<Act>> {
    let act = prop_oneof![
        5 => Just(Act::Write),
        2 => Just(Act::WriteNowhere),
        6 => (0usize..6).prop_map(Act::Hand),
        8 => (0usize..6).prop_map(Act::Deliver),
        4 => (0usize..6).prop_map(Act::DeliverOut),
        4 => (0usize..6).prop_map(Act::DeliverBack),
        2 => (0usize..6).prop_map(Act::Lose),
        4 => Just(Act::Read),
        3 => (0usize..6).prop_map(Act::Fire),
        1 => Just(Act::Restart),
        2 => Just(Act::Unplug),
        2 => Just(Act::Plug),
        2 => Just(Act::MailDown),
        2 => Just(Act::MailUp),
        3 => Just(Act::SendFile),
        2 => Just(Act::Delete),
        4 => (1u32..1_080).prop_map(Act::Skip),
        5 => Just(Act::Tidy),
        1 => Just(Act::Forget),
    ];
    prop::collection::vec(act, 1..32)
}

/// Что узел наговорил и чего ждёт.
#[derive(Default)]
struct Side {
    /// Кадры, которые ещё не отданы собеседнику.
    frames: Vec<Vec<u8>>,
    /// Передачи, которые транспорт ещё не подтвердил.
    handoffs: Vec<([u8; 32], Transport, u64)>,
    /// Взведённые сроки.
    timers: Vec<u64>,
}

/// Разбирает последствия шага: кадры — в провод, подтверждения и сроки —
/// в списки, объявленные статусы — наружу.
fn sort_out(effects: Vec<Effect>, side: &mut Side, said: &mut Vec<([u8; 16], DeliveryStatus)>) {
    for effect in effects {
        match effect {
            Effect::Send { peer_ik, via, frame, handoff } => {
                side.frames.push(frame);
                if let Some(handoff) = handoff {
                    side.handoffs.push((peer_ik, via, handoff));
                }
            }
            Effect::SetTimer { token, .. } => {
                if !side.timers.contains(&token) {
                    side.timers.push(token);
                }
            }
            Effect::Notify(Event::StatusChanged { msg_id, status }) => said.push((msg_id, status)),
            _ => {}
        }
    }
}

/// Статусы исходящих сообщений первого узла, как они лежат в базе.
fn stored(node: &Node, chat: &[u8; 16], mine: &[u8; 32]) -> BTreeMap<[u8; 16], DeliveryStatus> {
    node.store()
        .messages(chat, 200, None)
        .expect("чтение чата")
        .into_iter()
        .filter(|message| &message.sender_ik == mine)
        .filter_map(|message| {
            let code = message.status?;
            // Неизвестный код — тоже находка: лестница живёт в `proto`,
            // и база не вправе держать то, чего в ней нет.
            Some((message.msg_id, DeliveryStatus::from_code(code).expect("код статуса известен")))
        })
        .collect()
}

/// Проверяет переходы по лестнице §9.4 между двумя снимками.
///
/// Правило взято у `advance` — у того места, где оно и сформулировано:
/// `Undeliverable` перекрывает только `Pending` и `Waiting`, остальное
/// идёт строго вверх.
fn chain_holds(
    was: &BTreeMap<[u8; 16], DeliveryStatus>,
    now: &BTreeMap<[u8; 16], DeliveryStatus>,
    whence: &str,
) -> Result<(), String> {
    for (msg_id, fresh) in now {
        let Some(old) = was.get(msg_id) else { continue };
        if old == fresh {
            continue;
        }
        if advance(Some(*old), *fresh) != Some(*fresh) {
            return Err(format!(
                "{whence}: статус сообщения {:x?} пошёл {old:?} → {fresh:?}, \
                 а лестница §9.4 такого перехода не разрешает",
                &msg_id[..4]
            ));
        }
    }
    Ok(())
}

/// Пара узлов, знакомых как при встрече, и провод между ними.
struct Pair {
    alice: Node,
    bob: Node,
    alice_ik: [u8; 32],
    bob_ik: [u8; 32],
    chat: [u8; 16],
    back: [u8; 16],
    /// Чат с тем, к кому путь не откроется никогда.
    nowhere: [u8; 16],
    home_a: PathBuf,
    home_b: PathBuf,
    home_c: PathBuf,
    a: Side,
    b: Side,
    /// Статусы, как они лежат в базе первого узла.
    seen: BTreeMap<[u8; 16], DeliveryStatus>,
    /// Статусы, как они объявлены наружу — экран живёт событиями.
    announced: BTreeMap<[u8; 16], DeliveryStatus>,
    /// Всё, через что статусы прошли: по этому списку проверяется алфавит.
    ladder: BTreeSet<DeliveryStatus>,
    /// Часы: двигаются и шагами, и прыжками `Skip`.
    clock_ms: u64,
    /// Каталог, из которого первый отправляет файлы.
    source: PathBuf,
    /// Второй взгляд на те же куски — тестовый, рядом с ядровым.
    blobs_a: FsBlobs,
    /// И у получателя: куски лежат именно у него.
    blobs_b: FsBlobs,
    /// Сколько строк убрала уборка за весь скрипт: ноль означает, что
    /// свойство ничего не проверило.
    tidied_rows: u64,
    /// Сколько раз уборка шла при живом файле, на который ссылается
    /// видимое сообщение.
    tidied_with_files: usize,
    /// И сколько раз — при живом надгробии.
    tombstones: usize,
}

/// Снимок того, что человеку показывают — у одного узла.
///
/// Нарочно **не** вся база: уборка §12 и обязана выбрасывать служебное —
/// пропущенные ключи, окно дедупликации, anti-replay, старые надгробия.
/// Стережётся то, что видно на экране: сообщения чатов и куски файлов,
/// на которые ссылается хоть одно такое сообщение.
/// Что видно про одно сообщение: тело, ответ-на, статус.
///
/// Псевдонимом, а не прямо в поле: clippy зовёт разводить составные
/// типы, и зовёт справедливо — тройку в углу `BTreeMap` не прочитать.
type Shown = (Vec<u8>, Option<[u8; 16]>, Option<u8>);

#[derive(Debug, PartialEq, Eq)]
struct Half {
    /// Номер сообщения → то, что про него видно.
    messages: BTreeMap<[u8; 16], Shown>,
    /// Файл → его куски, как они лежат на диске.
    files: BTreeMap<[u8; 16], Vec<(u64, u64)>>,
}

/// Снимок обеих сторон.
///
/// Обеих — потому что куски лежат у **получателя**. Отправитель читает
/// исходник с диска и своих кусков не держит: у него в снимке файл есть,
/// а список кусков пуст. Настоящий же страх, записанный в `files.rs`, —
/// что уборка сирот сотрёт **полученное** вложение, то есть то, что
/// человек уже скачал. Стереги только отправителя — эта половина
/// осталась бы непроверенной.
#[derive(Debug, PartialEq, Eq)]
struct View {
    alice: Half,
    bob: Half,
}

/// Снимок одного узла по названным чатам.
fn half_of(node: &Node, blobs: &FsBlobs, chats: &[[u8; 16]]) -> Half {
    let mut messages = BTreeMap::new();
    for chat in chats {
        for message in node.store().messages(chat, 500, None).expect("чтение чата") {
            messages.insert(message.msg_id, (message.body, message.reply_to, message.status));
        }
    }
    // Файл показывается вместе с сообщением, и только с ним: кусок,
    // на который не ссылается ни одно видимое сообщение, уборка вправе
    // вымести — он и есть сирота.
    let mut files = BTreeMap::new();
    for file_id in node.store().all_file_ids().expect("список файлов") {
        let mentioned = node
            .store()
            .messages_of_file(&file_id)
            .expect("ссылки на файл")
            .into_iter()
            .any(|msg_id| messages.contains_key(&msg_id));
        if mentioned {
            files.insert(file_id, blobs.stored_chunks(&file_id).expect("куски"));
        }
    }
    Half { messages, files }
}

impl Pair {
    fn new() -> Pair {
        let (home_a, home_b) = (fresh_home(1), fresh_home(2));
        let source = home_a.join("source");
        std::fs::create_dir_all(&source).expect("каталог исходников");
        let blobs_dir = home_a.join("blobs");
        let home_b_blobs = home_b.join("blobs");
        let mut alice = open(1, &home_a);
        let mut bob = open(2, &home_b);
        let alice_ik = alice.own_card().ik;
        let bob_ik = bob.own_card().ik;

        // Знакомство как при встрече (§4.2): иначе первый же шаг упрётся
        // в «кому писать», и скрипт проверял бы отказы, а не лестницу.
        let a_card = alice.own_card().encode().expect("своя карточка");
        let b_card = bob.own_card().encode().expect("своя карточка");
        alice
            .step(
                0,
                Input::Command(Command::AddContact { card_bytes: b_card, met_in_person: true }),
            )
            .expect("знакомство");
        bob.step(
            0,
            Input::Command(Command::AddContact { card_bytes: a_card, met_in_person: true }),
        )
        .expect("знакомство");

        // И третий знакомый — с карточкой без адресов.
        let home_c = fresh_home(9);
        let (nobody_card, nobody_ik) = card_of_nobody(&home_c);
        alice
            .step(
                0,
                Input::Command(Command::AddContact {
                    card_bytes: nobody_card,
                    met_in_person: true,
                }),
            )
            .expect("знакомство с тем, кого не достать");

        Pair {
            chat: Engine::<SqliteStore>::chat_id_for(&bob_ik),
            back: Engine::<SqliteStore>::chat_id_for(&alice_ik),
            nowhere: Engine::<SqliteStore>::chat_id_for(&nobody_ik),
            alice,
            bob,
            alice_ik,
            bob_ik,
            home_a,
            home_b,
            home_c,
            a: Side::default(),
            b: Side::default(),
            seen: BTreeMap::new(),
            announced: BTreeMap::new(),
            ladder: BTreeSet::new(),
            clock_ms: 1_000,
            source,
            blobs_a: FsBlobs::new(blobs_dir),
            blobs_b: FsBlobs::new(home_b_blobs),
            tidied_rows: 0,
            tidied_with_files: 0,
            tombstones: 0,
        }
    }

    /// Что человеку показывают — у обоих, из базы и с диска.
    fn view(&self) -> View {
        let chats = [self.chat, self.back, self.nowhere];
        View {
            alice: half_of(&self.alice, &self.blobs_a, &chats),
            bob: half_of(&self.bob, &self.blobs_b, &chats),
        }
    }

    /// Один шаг скрипта.
    ///
    /// Отказ шага — законный исход, а не падение: после `Forget` писать
    /// и правда некому, и лестница обязана держаться и в этом случае.
    fn play(&mut self, number: usize, act: Act) -> Result<(), String> {
        // Часы живут у пары, а не считаются от номера шага: `Skip`
        // двигает их прыжком, и уборка наступает только от этого.
        self.clock_ms += 1_000;
        let now_ms = self.clock_ms;
        // Статусы своих сообщений объявляет первый узел; что говорит
        // второй — про свои, и к этой лестнице не относится.
        let mut said: Vec<([u8; 16], DeliveryStatus)> = Vec::new();
        let mut theirs: Vec<([u8; 16], DeliveryStatus)> = Vec::new();

        match act {
            Act::Write => {
                let text = format!("письмо {number}");
                let command = Command::SendText { chat: self.chat, text };
                if let Ok(effects) = self.alice.step(now_ms, Input::Command(command)) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::WriteNowhere => {
                let text = format!("в пустоту {number}");
                let command = Command::SendText { chat: self.nowhere, text };
                if let Ok(effects) = self.alice.step(now_ms, Input::Command(command)) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::Hand(which) => {
                let mine = self.a.handoffs.len();
                let total = mine + self.b.handoffs.len();
                if total > 0 {
                    let k = which % total;
                    if k < mine {
                        let (peer_ik, via, handoff) = self.a.handoffs.remove(k);
                        let taken = Input::Handed { peer_ik, via, handoff };
                        if let Ok(effects) = self.alice.step(now_ms, taken) {
                            sort_out(effects, &mut self.a, &mut said);
                        }
                    } else {
                        let (peer_ik, via, handoff) = self.b.handoffs.remove(k - mine);
                        let taken = Input::Handed { peer_ik, via, handoff };
                        if let Ok(effects) = self.bob.step(now_ms, taken) {
                            sort_out(effects, &mut self.b, &mut theirs);
                        }
                    }
                }
            }
            Act::Deliver(which) => {
                let mine = self.a.frames.len();
                let total = mine + self.b.frames.len();
                if total > 0 {
                    let k = which % total;
                    if k < mine {
                        let frame = self.a.frames.remove(k);
                        let got = Input::Received { via: Transport::Onion, frame };
                        if let Ok(effects) = self.bob.step(now_ms, got) {
                            sort_out(effects, &mut self.b, &mut theirs);
                        }
                    } else {
                        let frame = self.b.frames.remove(k - mine);
                        let got = Input::Received { via: Transport::Onion, frame };
                        if let Ok(effects) = self.alice.step(now_ms, got) {
                            sort_out(effects, &mut self.a, &mut said);
                        }
                    }
                }
            }
            Act::DeliverOut(which) => {
                if !self.a.frames.is_empty() {
                    let frame = self.a.frames.remove(which % self.a.frames.len());
                    let got = Input::Received { via: Transport::Onion, frame };
                    if let Ok(effects) = self.bob.step(now_ms, got) {
                        sort_out(effects, &mut self.b, &mut theirs);
                    }
                }
            }
            Act::DeliverBack(which) => {
                if !self.b.frames.is_empty() {
                    let frame = self.b.frames.remove(which % self.b.frames.len());
                    let got = Input::Received { via: Transport::Onion, frame };
                    if let Ok(effects) = self.alice.step(now_ms, got) {
                        sort_out(effects, &mut self.a, &mut said);
                    }
                }
            }
            Act::Lose(which) => {
                let mine = self.a.frames.len();
                let total = mine + self.b.frames.len();
                if total > 0 {
                    let k = which % total;
                    if k < mine {
                        self.a.frames.remove(k);
                    } else {
                        self.b.frames.remove(k - mine);
                    }
                }
            }
            Act::Read => {
                let inbox = self.bob.store().messages(&self.back, 200, None).expect("чтение чата");
                if let Some(last) = inbox.last() {
                    let command = Command::MarkRead { chat: self.back, up_to: last.msg_id };
                    if let Ok(effects) = self.bob.step(now_ms, Input::Command(command)) {
                        sort_out(effects, &mut self.b, &mut theirs);
                    }
                }
            }
            Act::Fire(which) => {
                if !self.a.timers.is_empty() {
                    let token = self.a.timers.remove(which % self.a.timers.len());
                    if let Ok(effects) = self.alice.step(now_ms, Input::Timer { token }) {
                        sort_out(effects, &mut self.a, &mut said);
                    }
                }
            }
            Act::Restart => {
                self.alice = open(1, &self.home_a);
            }
            Act::Unplug => {
                let lost = Input::TransportLost { transport: Transport::Onion };
                if let Ok(effects) = self.alice.step(now_ms, lost) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::Plug => {
                let ready = Input::TransportReady { transport: Transport::Onion };
                if let Ok(effects) = self.alice.step(now_ms, ready) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::MailDown => {
                let lost = Input::TransportLost { transport: Transport::Mail };
                if let Ok(effects) = self.alice.step(now_ms, lost) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::MailUp => {
                let ready = Input::TransportReady { transport: Transport::Mail };
                if let Ok(effects) = self.alice.step(now_ms, ready) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::SendFile => {
                // Файл кладётся на диск: ядро читает исходник сам.
                let name = format!("gostinec-{number}.bin");
                let path = self.source.join(&name);
                let body: Vec<u8> = (0..4_096u32).map(|i| (i % 251) as u8).collect();
                std::fs::write(&path, &body).expect("исходник файла");
                let command = Command::SendFiles {
                    chat: self.chat,
                    files: vec![OutgoingFile { path, preview: None }],
                    text: format!("файл {number}"),
                };
                if let Ok(effects) = self.alice.step(now_ms, Input::Command(command)) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
            Act::Delete => {
                // Окно читается целиком: запрос отдаёт **хвост** чата,
                // и с `limit = 1` первым оказалось бы самое свежее.
                let inbox = self.alice.store().messages(&self.chat, 500, None);
                if let Ok(messages) = inbox {
                    if let Some(oldest) = messages.first() {
                        let command = Command::DeleteMessages {
                            chat: self.chat,
                            msg_ids: vec![oldest.msg_id],
                        };
                        if let Ok(effects) = self.alice.step(now_ms, Input::Command(command)) {
                            sort_out(effects, &mut self.a, &mut said);
                            self.tombstones += 1;
                        }
                    }
                }
            }
            Act::Skip(hours) => {
                self.clock_ms += u64::from(hours) * 60 * 60 * 1_000;
            }
            Act::Tidy => {
                // **Снимок до и после, и сличение целиком.** Уборка §12
                // вправе выбрасывать служебное, но не то, что видно
                // на экране.
                let before = self.view();
                // Считается живой файл **с кусками**: пустой список
                // у отправителя покрытием не считается.
                let had_files = before
                    .alice
                    .files
                    .values()
                    .chain(before.bob.files.values())
                    .any(|chunks| !chunks.is_empty());
                // Прибираются **оба**: в живом приложении это делает
                // драйвер на каждом устройстве, а куски лежат у получателя.
                let rows = self.alice.compact_if_due(self.clock_ms).expect("уборка")
                    + self.bob.compact_if_due(self.clock_ms).expect("уборка");
                let swept = self.alice.sweep_orphan_files().expect("выметание сирот");
                let swept_back = self.bob.sweep_orphan_files().expect("выметание сирот");
                let after = self.view();
                self.tidied_rows += rows;
                if had_files {
                    self.tidied_with_files += 1;
                }
                if before.alice.messages != after.alice.messages
                    || before.bob.messages != after.bob.messages
                {
                    return Err(format!(
                        "шаг {number}: уборка тронула показываемое. Было сообщений {}/{}, \
                         стало {}/{}; убрано строк {rows}, файлов выметено {}",
                        before.alice.messages.len(),
                        before.bob.messages.len(),
                        after.alice.messages.len(),
                        after.bob.messages.len(),
                        swept.files + swept_back.files
                    ));
                }
                if before.alice.files != after.alice.files || before.bob.files != after.bob.files {
                    return Err(format!(
                        "шаг {number}: уборка вымела куски файла, на который ссылается \
                         видимое сообщение. Было {:?} и {:?}, стало {:?} и {:?}",
                        before.alice.files, before.bob.files, after.alice.files, after.bob.files
                    ));
                }
            }
            Act::Forget => {
                // Переписку не трём: статусы нужны на месте, иначе проверять
                // станет нечего. Удаление знакомого и так снимает обещание
                // «отправим позже» — это и есть путь к `Undeliverable`.
                let forget = Command::DeleteContact { peer_ik: self.bob_ik, purge_history: false };
                if let Ok(effects) = self.alice.step(now_ms, Input::Command(forget)) {
                    sort_out(effects, &mut self.a, &mut said);
                }
            }
        }

        // Половина первая: база. Смотрятся **оба** чата: статус живёт
        // у сообщения, а не у собеседника, и лестница одна на все.
        let mut fresh = stored(&self.alice, &self.chat, &self.alice_ik);
        fresh.extend(stored(&self.alice, &self.nowhere, &self.alice_ik));
        chain_holds(&self.seen, &fresh, &format!("шаг {number} ({act:?}), база"))?;
        self.ladder.extend(fresh.values().copied());
        self.seen = fresh;

        // Половина вторая: то, что сказано наружу. Экран живёт событиями,
        // а не базой, и разойдись они — человек увидит откат там, где
        // на диске его нет.
        let mut after = self.announced.clone();
        for (msg_id, status) in &said {
            after.insert(*msg_id, *status);
        }
        chain_holds(&self.announced, &after, &format!("шаг {number} ({act:?}), событие"))?;
        self.ladder.extend(said.iter().map(|(_, status)| *status));
        self.announced = after;
        Ok(())
    }

    /// Дошло ли письмо до второго.
    ///
    /// Нужно проверке на перестановку квитанций: держать их у второго
    /// можно только **после** того, как письмо до него доехало, а до того
    /// кадры обязаны ходить в обе стороны — иначе не складывается
    /// рукопожатие, и письмо не уезжает вовсе.
    fn delivered_to_bob(&self) -> bool {
        self.bob
            .store()
            .messages(&self.back, 10, None)
            .map(|inbox| !inbox.is_empty())
            .unwrap_or(false)
    }

    /// Каталоги убираются только у прошедшего случая: упавший оставляет
    /// базу на месте, по ней и разбираться.
    fn tidy(&self) {
        let _ = std::fs::remove_dir_all(&self.home_a);
        let _ = std::fs::remove_dir_all(&self.home_b);
        let _ = std::fs::remove_dir_all(&self.home_c);
    }
}

/// Скрипт, который заведомо проходит лестницу целиком.
///
/// Руками, а не случайным поиском: это проверка на сам алфавит, и её
/// цена — в том, что она не зависит от сида.
///
/// Порядок здесь не произволен, и каждый кусок отвечает за свою ступень:
///
/// * `Write` — сообщение заведено, `Pending`;
/// * `Hand` вперемешку с `Deliver` — рукопожатие доезжает, и уже **после**
///   него транспорт подтверждает передачу самого сообщения: `Sent`.
///   Одного `Hand` сразу за `Write` не хватает — он подтверждает кадр
///   рукопожатия, а не письмо, и первая редакция этой проверки до `Sent`
///   поэтому не доставала;
/// * квитанции — `Delivered`, потом `Read`;
/// * `Unplug` плюс `Write` — ехать некуда, `Waiting`;
/// * `Forget` плюс `Fire` — `Undeliverable` ставится не самим удалением
///   знакомого, а повторным заходом по отложенной очереди: он и находит,
///   что отправлять больше некому.
fn whole_ladder() -> Vec<Act> {
    let mut script = vec![
        // Прямой канал: `Pending`, потом квитанции.
        Act::Write,
    ];
    for _ in 0..6 {
        script.push(Act::Deliver(0));
    }
    script.push(Act::Read);
    for _ in 0..4 {
        script.push(Act::Deliver(0));
    }
    // Прямая ступень отваливается — письмо едет почтой, и почта ждёт
    // подтверждения передачи: `Sent`.
    script.push(Act::Unplug);
    script.push(Act::Write);
    for _ in 0..3 {
        script.push(Act::Hand(0));
    }
    // Ехать некуда вовсе: `Waiting`.
    script.push(Act::MailDown);
    script.push(Act::Write);
    // И письмо тому, к кому путь не откроется никогда: обещать «позже»
    // нечем, и ядро ставит `Undeliverable`.
    script.push(Act::WriteNowhere);
    script
}

#[test]
fn the_alphabet_reaches_the_whole_ladder() {
    // **Проверка на проверку.** Свойство ниже зелено ровно настолько,
    // насколько его скрипты достают до интересных состояний. Первая
    // редакция этого файла до `Sent` не доставала вовсе — он ставится
    // по `Input::Handed`, а харнесс его не подавал, — и почти все случаи
    // упирались в `Waiting`. Зелень была на пустом месте.
    //
    // Чего эта проверка **не** стережёт: что до всех шести достают
    // случайные скрипты. Она стережёт, что до них достаёт алфавит, —
    // то есть что из этих действий движок в эти состояния попадает
    // вообще.
    let mut pair = Pair::new();
    for (number, act) in whole_ladder().iter().enumerate() {
        pair.play(number, *act).expect("лестница держится на ручном скрипте");
    }
    for status in [
        DeliveryStatus::Pending,
        DeliveryStatus::Sent,
        DeliveryStatus::Delivered,
        DeliveryStatus::Read,
        DeliveryStatus::Waiting,
        DeliveryStatus::Undeliverable,
    ] {
        assert!(
            pair.ladder.contains(&status),
            "алфавит не достаёт до {status:?}; достигнуто: {:?}",
            pair.ladder
        );
    }
    pair.tidy();
}

/// Квитанция о доставке, пришедшая **после** квитанции о прочтении.
///
/// Это тот самый случай, ради которого `advance` и написана, и он здесь
/// выписан руками, а не оставлен случайному поиску. Причина простая:
/// поиск его находит, но не всегда и не быстро — на обойдённой лестнице
/// он покраснел на пятистах двенадцати случаях и двадцати семи секундах,
/// а на шестидесяти четырёх проходил зелёным. Проверка, которая ловит
/// поломку только при удачном сиде, не стоит ничего.
///
/// Перестановка собирается нарочно: первому не отдают **ничего**, пока
/// второй не накопит обе квитанции, и дальше они едут задом наперёд.
#[test]
fn a_read_receipt_overtaking_the_delivered_one_does_not_push_the_status_back() {
    let mut pair = Pair::new();
    let mut number = 0;
    let mut step = |pair: &mut Pair, act: Act| {
        pair.play(number, act).expect("лестница держится");
        number += 1;
    };

    // Доводим письмо до второго. Кадры идут в обе стороны — иначе
    // не складывается рукопожатие, — но **по одному**: как только письмо
    // доехало, у второго в очереди остаётся его квитанция о доставке.
    step(&mut pair, Act::Write);
    for _ in 0..16 {
        if pair.delivered_to_bob() {
            break;
        }
        if pair.a.frames.is_empty() {
            step(&mut pair, Act::DeliverBack(0));
        } else {
            step(&mut pair, Act::DeliverOut(0));
        }
    }
    assert!(pair.delivered_to_bob(), "письмо до второго не доехало — проверять нечего");

    // Второй читает: теперь у него две квитанции — о доставке и о прочтении.
    step(&mut pair, Act::Read);
    assert!(
        pair.b.frames.len() >= 2,
        "перестановку собирать нечем: у второго {} кадров",
        pair.b.frames.len()
    );

    // И отдаём их задом наперёд: сперва последнюю.
    let last = pair.b.frames.len() - 1;
    step(&mut pair, Act::DeliverBack(last));
    while !pair.b.frames.is_empty() {
        step(&mut pair, Act::DeliverBack(0));
    }

    assert!(
        pair.ladder.contains(&DeliveryStatus::Read),
        "до «прочитано» дело не дошло, и перестановка ничего не проверила: {:?}",
        pair.ladder
    );
    pair.tidy();
}

/// Скрипт, который заведомо доводит уборку до работы.
///
/// Руками, как и лестница статусов: свойство ниже зелено ровно
/// настолько, насколько его скрипты доводят уборку до чего-то, что
/// она **может** выбросить. Уборка, которой не было, ничего не портит.
fn whole_tidy() -> Vec<Act> {
    let mut script = vec![Act::SendFile];
    // Файл уезжает: куски запечатываются и ложатся на диск.
    for _ in 0..12 {
        script.push(Act::Deliver(0));
    }
    // Тридцать один день: истекают окно дедупликации и anti-replay (§9.2,
    // §8.3) — тридцать суток у обоих. Без этого прыжка уборка идёт
    // и не находит ничего.
    script.push(Act::Skip(31 * 24));
    script.push(Act::Tidy);
    // Теперь надгробие: удаляем самое старое — то самое сообщение с файлом.
    script.push(Act::Write);
    script.push(Act::Delete);
    script.push(Act::Skip(48));
    script.push(Act::Tidy);
    script
}

#[test]
fn the_alphabet_makes_the_tidying_actually_tidy() {
    // **Вторая проверка на проверку.** Та же цена, что у лестницы
    // статусов: свойство «уборка не трогает показываемого» зелено
    // на пустом месте, если уборка не наступила или ничего не нашла.
    //
    // Чего она не стережёт: что до этого доходят **случайные** скрипты.
    // Стережётся проходимость алфавита.
    let mut pair = Pair::new();
    for (number, act) in whole_tidy().iter().enumerate() {
        pair.play(number, *act).expect("уборка не трогает показываемого");
    }
    assert!(
        pair.tidied_rows > 0,
        "уборка не выбросила ни одной строки — свойство ничего не проверило"
    );
    assert!(
        pair.tidied_with_files > 0,
        "ни одной уборки при живом файле, на который ссылается видимое сообщение"
    );
    assert!(pair.tombstones > 0, "ни одного надгробия: уборке надгробий нечего схлопывать");
    pair.tidy();
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Случаев немного нарочно: каждый открывает две базы SQLite
        // на диске. Поднять число легко; поднимать его без нужды значит
        // сделать прогон дольше, а находок не добавить.
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Статус сообщения ходит только по лестнице §9.4 — и в базе, и на экране.
    ///
    /// # Что именно стережётся
    ///
    /// Правило переходов живёт в `receipts::advance` и проверено там
    /// примерами. Чего не проверял никто — что **ядро через него и ходит**:
    /// `Engine::step` пишет статус и объявляет его наружу из нескольких
    /// разных мест (отправка, подтверждение передачи, квитанция, срок,
    /// пустая лестница §5.4, удаление знакомого), и достаточно одному
    /// из них записать статус мимо `advance`, чтобы на экране
    /// «доставлено» сменилось «ждёт отправки». Это ровно та нечестность,
    /// которую запрещает §14: обещание, отданное назад.
    ///
    /// # Чего не стережёт
    ///
    /// *Правильности самой лестницы.* Что `Undeliverable` должен
    /// перекрывать `Waiting`, а не наоборот, — решение §9.4, и проверки
    /// на него стоят в `proto`.
    ///
    /// *Статусов входящих сообщений.* Смотрятся только свои исходящие:
    /// у принятого сообщения статус заводит отправитель.
    ///
    /// *Того, что статус доедет до нужного.* Свойство запрещает движение
    /// вниз и не требует движения вверх: скрипт, в котором все кадры
    /// потерялись, честно оставляет `Waiting`. Что лестница **проходима**,
    /// держит `the_alphabet_reaches_the_whole_ladder`.
    #[test]
    fn a_message_status_only_walks_up_the_ladder_whatever_the_order_of_events(
        script in acts(),
    ) {
        let mut pair = Pair::new();
        for (number, act) in script.iter().enumerate() {
            if let Err(trouble) = pair.play(number, *act) {
                return Err(TestCaseError::fail(trouble));
            }
        }
        pair.tidy();
    }

    /// Уборка (§12) не трогает того, что показывается.
    ///
    /// # Что именно стережётся
    ///
    /// Уборка обязана выбрасывать служебное — пропущенные ключи, окно
    /// дедупликации, anti-replay, надгробия старше девяноста суток,
    /// причинные ссылки за окном, — и обязана **не** выбрасывать то, что
    /// видно на экране. Между этими двумя списками и живёт ошибка:
    /// в `files.rs` прямо записан страх, что «уборка сирот однажды сотрёт
    /// отправленный файл», и сирота от нужного файла отличается
    /// единственной ссылкой из сообщения.
    ///
    /// Снимок берётся до и после **каждой** уборки и сличается целиком:
    /// сообщения трёх чатов (номер, тело, ответ-на, статус) и куски
    /// файлов, на которые ссылается хоть одно видимое сообщение.
    ///
    /// # Чего не стережёт
    ///
    /// *Что уборка убирает.* Свойство запрещает лишнее и не требует
    /// нужного: уборка, не делающая ничего, его проходит. Что она
    /// доходит до работы, держит `the_alphabet_makes_the_tidying_actually_tidy`.
    ///
    /// *Надгробий.* Удалённое сообщение из `messages()` не возвращается
    /// (`tombstone_ms IS NULL` в запросе), в снимок не попадает,
    /// и свёртка надгробий через девяносто суток свойству невидима.
    /// Поэтому прыжки часов здесь любого размера.
    ///
    /// *Чужой половины.* Смотрится база первого узла.
    #[test]
    fn a_tidying_never_touches_what_is_shown(script in acts()) {
        let mut pair = Pair::new();
        for (number, act) in script.iter().enumerate() {
            if let Err(trouble) = pair.play(number, *act) {
                return Err(TestCaseError::fail(trouble));
            }
        }
        // **Уборка в конце — обязательна.** Случайный скрипт может
        // не позвать её ни разу, и тогда случай проверил бы только
        // лестницу статусов. Тридцать один день — чтобы уборке было
        // что найти.
        let last = script.len();
        for (number, act) in [Act::Skip(31 * 24), Act::Tidy].iter().enumerate() {
            if let Err(trouble) = pair.play(last + number, *act) {
                return Err(TestCaseError::fail(trouble));
            }
        }
        pair.tidy();
    }
}
