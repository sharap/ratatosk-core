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
use ratatosk_core::{Command, Effect, Engine, Event, Input, OsEntropy};
use ratatosk_crypto::Identity;
use ratatosk_proto::receipts::{advance, DeliveryStatus};
use ratatosk_proto::Transport;
use ratatosk_store::{FsBlobs, SqliteStore, Store};
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
}

impl Pair {
    fn new() -> Pair {
        let (home_a, home_b) = (fresh_home(1), fresh_home(2));
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
        }
    }

    /// Один шаг скрипта.
    ///
    /// Отказ шага — законный исход, а не падение: после `Forget` писать
    /// и правда некому, и лестница обязана держаться и в этом случае.
    fn play(&mut self, number: usize, act: Act) -> Result<(), String> {
        let now_ms = 1_000 + number as u64 * 1_000;
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
}
