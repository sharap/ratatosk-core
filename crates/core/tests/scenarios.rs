//! Обязательные сценарии §16 на настоящем ядре.
//!
//! До этого файла сценарии гоняли учебный узел с OR-Set и часами — он
//! показывал, что сходятся **структуры состояния**, но ничего не говорил
//! о ядре. Здесь в симулятор поставлен [`Engine`] целиком: рукопожатие,
//! ретчет, кодек, кадрирование и хранилище.
//!
//! Один сценарий §16 — «одновременное исключение участника в двух
//! сегментах» — остался в `crates/sim/tests/scenarios.rs` на учебном узле:
//! он требует групп (§11), а `Engine::step` пока ведёт только 1:1-текст.
//! Переносить его сюда нечего, а выбрасывать — значит терять покрытие.
//!
//! Про воспроизводимость надо знать одно ограничение. Сетевое расписание
//! задаётся сидом и повторяется точно, но эфемерные ключи Noise `snow`
//! берёт из `OsRng`, поэтому байты кадров от прогона к прогону разные.
//! Логика, которую сценарии проверяют, от этого не зависит; полная
//! воспроизводимость потребует собственного резолвера `snow`.

use std::collections::BTreeMap;

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, SeededEntropy};
use ratatosk_crypto::Identity;
use ratatosk_proto::Transport;
use ratatosk_sim::{Ctx, LinkProfile, NodeId, Sim, SimNode, TransportKind};
use ratatosk_store::{MemoryStore, Store};

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Обёртка вокруг ядра.
///
/// Нужна из-за правила сирот: `SimNode` определён в `ratatosk-sim`,
/// `Engine` — в `ratatosk-core`, а тест это третий крейт. Заодно обёртка
/// собирает события для UI, по которым и проверяется результат.
struct Node {
    engine: Engine<MemoryStore>,
    peers: BTreeMap<[u8; 32], NodeId>,
    events: Vec<Event>,
    /// Порядок, в котором кадры реально пришли. Отличается от порядка показа,
    /// и без этого различия сценарий перестановки нечего проверять.
    arrivals: Vec<[u8; 16]>,
}

/// Транспорт харнесса → транспорт протокола.
///
/// Два перечисления вместо одного — сознательно: `ratatosk-sim` не зависит
/// от `ratatosk-proto`, иначе харнесс нельзя было бы использовать отдельно
/// от протокола. Цена — вот эта пара функций.
fn to_proto(kind: TransportKind) -> Transport {
    match kind {
        TransportKind::Lan => Transport::Lan,
        TransportKind::Onion => Transport::Onion,
        TransportKind::Mail => Transport::Mail,
    }
}

fn to_sim(transport: Transport) -> TransportKind {
    match transport {
        Transport::Lan => TransportKind::Lan,
        Transport::Onion => TransportKind::Onion,
        Transport::Mail => TransportKind::Mail,
    }
}

impl Node {
    /// `mail_only` убирает onion-адрес из карточки.
    ///
    /// Откат «onion не ответил → почта» теперь есть, но он стоит 45 секунд
    /// виртуального времени на каждую попытку. Сценариям, которые изучают
    /// саму почту — перестановки и спул, — этот крюк не нужен: они должны
    /// гонять почту сразу, иначе половина прогона уходит на таймауты.
    fn new(index: u16, seed: u64, mail_only: bool) -> Node {
        let identity = Identity::from_seed([index as u8 + 1; 32]);
        let mut store = MemoryStore::new();
        store.migrate().expect("миграция");

        let name = format!("node{index}");
        let mut engine = Engine::new(
            identity,
            store,
            Box::new(ratatosk_store::MemoryBlobs::new()),
            Box::new(SeededEntropy::new(seed ^ u64::from(index))),
            SelfAddresses {
                onion: if mail_only {
                    String::new()
                } else {
                    format!("{name}wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww.onion")
                },
                chatmail: format!("{name}@nine.example"),
                display_name: name,
            },
        );
        // Onion объявляется работающим сразу: симуляция проверяет протокол,
        // а не подъём Tor. На устройстве этот вход приходит от транспорта
        // после публикации сервиса, десятками секунд позже включения.
        engine
            .step(0, Input::TransportReady { transport: ratatosk_proto::Transport::Onion })
            .expect("готовность транспорта");
        Node { engine, peers: BTreeMap::new(), events: Vec::new(), arrivals: Vec::new() }
    }

    fn ik(&self) -> [u8; 32] {
        self.engine.own_card().ik
    }

    /// Исполняет эффекты ядра: отправки уходят в сеть, уведомления копятся.
    fn apply(&mut self, ctx: &mut Ctx<'_>, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Send { peer_ik, via, frame } => {
                    let Some(&to) = self.peers.get(&peer_ik) else {
                        panic!("некуда слать: узел с таким IK не заведён в сценарии");
                    };
                    ctx.send(to, to_sim(via), frame);
                }
                Effect::Notify(event) => {
                    if let Event::MessageReceived { msg_id, .. } = &event {
                        self.arrivals.push(*msg_id);
                    }
                    self.events.push(event);
                }
                Effect::SetTimer { after_ms, token } => ctx.set_timer(after_ms, token),
                Effect::Connect { .. }
                | Effect::SetTransportEnabled { .. }
                | Effect::WatchLanPeers(_)
                | Effect::RestartLan => {}
            }
        }
    }

    fn command(&mut self, ctx: &mut Ctx<'_>, command: Command) {
        let effects = self
            .engine
            .step(ctx.now_ms(), Input::Command(command))
            .expect("команда не должна отказывать");
        self.apply(ctx, effects);
    }

    /// Сообщения чата в том порядке, в каком их показал бы UI (§9.1).
    fn chat_with(&self, peer_ik: &[u8; 32]) -> Vec<String> {
        let chat = Engine::<MemoryStore>::chat_id_for(peer_ik);
        self.engine
            .store()
            .messages(&chat, 1_000, None)
            .unwrap()
            .into_iter()
            .map(|m| String::from_utf8(m.body).unwrap())
            .collect()
    }

    /// Идентификаторы чата в порядке показа (§9.1) — для сравнения
    /// с [`Node::arrivals`].
    fn shown_ids(&self, peer_ik: &[u8; 32]) -> Vec<[u8; 16]> {
        let chat = Engine::<MemoryStore>::chat_id_for(peer_ik);
        self.engine
            .store()
            .messages(&chat, 1_000, None)
            .unwrap()
            .into_iter()
            .map(|m| m.msg_id)
            .collect()
    }

    fn received_count(&self) -> usize {
        self.events.iter().filter(|e| matches!(e, Event::MessageReceived { .. })).count()
    }
}

impl SimNode for Node {
    fn on_deliver(&mut self, ctx: &mut Ctx<'_>, _from: NodeId, kind: TransportKind, bytes: &[u8]) {
        let effects = self
            .engine
            .step(ctx.now_ms(), Input::Received { via: to_proto(kind), frame: bytes.to_vec() })
            .expect("приём кадра не должен отказывать");
        self.apply(ctx, effects);
    }

    fn on_timer(&mut self, ctx: &mut Ctx<'_>, token: u64) {
        let effects = self.engine.step(ctx.now_ms(), Input::Timer { token }).expect("таймер");
        self.apply(ctx, effects);
    }

    /// Прямой канал не доставил — ядро обязано перейти к следующему
    /// транспорту (§5.4). Без этой связки откат непроверяем.
    fn on_send_failed(&mut self, ctx: &mut Ctx<'_>, to: NodeId, kind: TransportKind) {
        let Some((&peer_ik, _)) = self.peers.iter().find(|(_, id)| **id == to) else {
            return;
        };
        let effects = self
            .engine
            .step(ctx.now_ms(), Input::ConnectionLost { peer_ik, via: to_proto(kind) })
            .expect("отказ транспорта не должен ронять ядро");
        self.apply(ctx, effects);
    }
}

/// Собирает прогон и знакомит всех со всеми (§4.2, QR при встрече).
fn network(seed: u64, count: u16) -> Sim<Node> {
    network_with(seed, count, false)
}

/// Сеть, где у контактов есть только почтовый адрес.
///
/// Нужна сценариям про почту: контакт с обоими адресами сначала пробует
/// onion и ждёт таймаут §5.4. Здесь этот путь не изучается, поэтому он
/// убран из условий, а не обойдён в утверждениях.
fn network_over_mail(seed: u64, count: u16) -> Sim<Node> {
    network_with(seed, count, true)
}

fn network_with(seed: u64, count: u16, mail_only: bool) -> Sim<Node> {
    let mut nodes: Vec<Node> = (0..count).map(|i| Node::new(i, seed, mail_only)).collect();

    let cards: Vec<(NodeId, [u8; 32], Vec<u8>)> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (NodeId(i as u16), n.ik(), n.engine.own_card().encode().unwrap()))
        .collect();

    for node in &mut nodes {
        for (id, ik, _) in &cards {
            node.peers.insert(*ik, *id);
        }
    }

    let mut sim = Sim::new(seed, nodes);

    // Потери на onion оставлены штатными: об отказе прямого канала сообщают,
    // и ядро обязано повторить попытку (§5.4), а повторное первое сообщение
    // получатель обязан обслужить идемпотентно (§8.3). Обе способности
    // появились — пусть проверяются на каждом прогоне.
    //
    // Почта — другое дело: она об отказе не сообщает и квитанций не шлёт
    // (§9.4), поэтому потерянное письмо обнаружить нечем. Моделировать это
    // потерями значило бы требовать от протокола того, чего v1 не обещает;
    // настоящий отказ почты — недоступность сервера, а она сообщается.
    sim.net_mut()
        .set_profile(TransportKind::Mail, LinkProfile { loss_permille: 0, ..LinkProfile::MAIL });

    // Дубликаты включены везде: их обязана съедать дедупликация (§9.2).

    sim.start();

    for i in 0..count {
        for (_, ik, card) in &cards {
            if *ik == sim.node(NodeId(i)).ik() {
                continue;
            }
            let card = card.clone();
            sim.act(NodeId(i), |node, ctx| {
                node.command(ctx, Command::AddContact { card_bytes: card, met_in_person: true });
            });
        }
    }
    sim
}

fn send(sim: &mut Sim<Node>, from: NodeId, to_ik: [u8; 32], text: &str) {
    let chat = Engine::<MemoryStore>::chat_id_for(&to_ik);
    let text = text.to_owned();
    sim.act(from, |node, ctx| {
        node.command(ctx, Command::SendText { chat, text });
    });
}

/// §16: перестановка сообщений почтовым транспортом.
#[test]
fn mail_reordering_is_repaired_by_hlc() {
    let mut sim = network_over_mail(0xB0B, 2);
    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    let texts: Vec<String> = (0..12).map(|i| format!("сообщение {i:02}")).collect();
    for text in &texts {
        send(&mut sim, a, b_ik, text);
        sim.run_for(1_000);
    }
    sim.run_to_idle(200_000).expect("прогон должен завершиться");

    let shown = sim.node(b).chat_with(&a_ik);
    assert_eq!(shown.len(), texts.len(), "по почте дошло не всё, сид {:#x}", sim.seed());

    // Порядок показа задаёт HLC, а не время прихода (§9.1).
    assert_eq!(shown, texts, "сид {:#x}", sim.seed());

    // И главное: перестановка действительно была. Без этой проверки тест
    // проходил бы и на транспорте, который ничего не переставляет, —
    // а именно так он и вёл себя, пока молча уходил в onion.
    assert_ne!(
        sim.node(b).arrivals,
        sim.node(b).shown_ids(&a_ik),
        "почта не переставила ни одного сообщения — сценарий ничего не проверил, сид {:#x}",
        sim.seed()
    );
}

/// §16: разделение сети на неделю с последующим слиянием.
#[test]
fn week_long_partition_then_merge_delivers_everything() {
    // Только почта: прямой канал во время разрыва не спулится, а теряется,
    // и до появления отката §5.4 сценарий про офлайн-доставку обязан гонять
    // тот транспорт, который для офлайна и предназначен (§5.3).
    let mut sim = network_over_mail(0xA1CE, 2);
    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    // Сначала обычная переписка, чтобы сессия успела установиться.
    send(&mut sim, a, b_ik, "до разрыва");
    sim.run_to_idle(200_000).unwrap();
    assert_eq!(sim.node(b).chat_with(&a_ik), vec!["до разрыва".to_string()]);

    // Неделя врозь: почта копится в спуле, прямой канал не работает.
    sim.partition(b, 1);
    send(&mut sim, a, b_ik, "во время разрыва");
    sim.run_for(WEEK_MS);

    assert!(sim.stats().spooled > 0, "почта во время разрыва должна копиться");
    assert_eq!(sim.node(b).chat_with(&a_ik).len(), 1, "во время разрыва ничего не доходит");

    sim.heal();
    sim.run_to_idle(200_000).expect("прогон должен завершиться");

    assert_eq!(
        sim.node(b).chat_with(&a_ik),
        vec!["до разрыва".to_string(), "во время разрыва".to_string()],
        "после слияния сообщение обязано дойти, сид {:#x}",
        sim.seed()
    );
}

/// §16: отправка обоими транспортами одновременно.
///
/// §5.4 такую отправку запрещает, но §9.2 обязан выдерживать её на приёме:
/// кадр, доставленный дважды, показывается один раз.
#[test]
fn the_same_frame_over_two_transports_is_shown_once() {
    let mut sim = network(0xC0DE, 2);
    sim.net_mut().set_enabled(TransportKind::Lan, true);
    sim.net_mut().set_profile(TransportKind::Lan, LinkProfile::INSTANT);

    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    send(&mut sim, a, b_ik, "однажды");
    sim.run_to_idle(200_000).unwrap();
    assert_eq!(sim.node(b).chat_with(&a_ik), vec!["однажды".to_string()]);
    let delivered = sim.node(b).received_count();

    // Тот же кадр, но другим транспортом. Берём его у отправителя: так же
    // поступил бы клиент, дославший сообщение из очереди при появлении
    // контакта в сети (§5.4).
    let frame = sim.act(a, |node, ctx| {
        let chat = Engine::<MemoryStore>::chat_id_for(&b_ik);
        let effects = node
            .engine
            .step(ctx.now_ms(), Input::Command(Command::SendText { chat, text: "дубль".into() }))
            .unwrap();
        effects
            .into_iter()
            .find_map(|e| match e {
                Effect::Send { frame, .. } => Some(frame),
                _ => None,
            })
            .expect("по установленной сессии должен уйти ровно один кадр")
    });

    sim.inject(a, b, TransportKind::Mail, frame.clone());
    sim.inject(a, b, TransportKind::Lan, frame);
    sim.run_to_idle(200_000).expect("прогон должен завершиться");

    assert_eq!(
        sim.node(b).received_count(),
        delivered + 1,
        "дубль обязан быть отброшен дедупликацией, сид {:#x}",
        sim.seed()
    );
    assert_eq!(sim.node(b).chat_with(&a_ik), vec!["однажды".to_string(), "дубль".to_string()]);
}

/// §16: расхождение воспроизводится по номеру сида.
///
/// Проверяется то, что от сида действительно зависит, — сетевое расписание.
/// Байты кадров сравнивать нельзя: эфемерные ключи Noise берутся из `OsRng`
/// (см. заголовок файла), и это ограничение, а не случайность теста.
#[test]
fn network_schedule_is_reproducible_by_seed() {
    fn run(seed: u64) -> (Vec<String>, u64) {
        let mut sim = network_over_mail(seed, 2);
        let (a, b) = (NodeId(0), NodeId(1));
        let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

        for i in 0..10 {
            send(&mut sim, a, b_ik, &format!("текст {i:02}"));
            sim.run_for(2_000);
        }
        sim.partition(b, 1);
        sim.run_for(WEEK_MS);
        sim.heal();
        sim.run_to_idle(200_000).unwrap();

        (sim.node(b).chat_with(&a_ik), sim.stats().delivered)
    }

    let first = run(11);
    let second = run(11);
    assert_eq!(first, second, "один сид — один прогон");

    // Итог не должен зависеть от сида: после слияния доходит всё.
    let other = run(99);
    assert_eq!(first.0, other.0, "после слияния состояние обязано сойтись");
}

/// §5.4: onion не ответил — сообщение уходит почтой.
///
/// Главный сценарий доставки в продукте: собеседник не в сети, прямой канал
/// молчит, и через 45 секунд клиент обязан перейти к почте. До появления
/// очереди повторов это место было дырой — кадр просто терялся.
#[test]
fn onion_failure_falls_back_to_mail() {
    let mut sim = network(0x5A4E, 2);
    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    // Получатель в другом сегменте: onion до него не доходит, почта копится.
    sim.partition(b, 1);
    send(&mut sim, a, b_ik, "через почту");

    // Меньше таймаута §5.4 — переход ещё не должен был случиться.
    sim.run_for(40_000);
    assert_eq!(
        sim.stats().send_failures,
        0,
        "переход раньше 45 секунд — это гонка, а не последовательность (§5.4)"
    );

    // После таймаута отправитель узнаёт об отказе и берёт следующий транспорт.
    sim.run_for(60_000);
    assert!(sim.stats().send_failures > 0, "об отказе onion должны были сообщить");
    assert!(sim.stats().spooled > 0, "после отказа сообщение обязано уйти почтой");

    sim.heal();
    sim.run_to_idle(500_000).expect("прогон должен завершиться");

    assert_eq!(
        sim.node(b).chat_with(&a_ik),
        vec!["через почту".to_string()],
        "сообщение не дошло вторым транспортом, сид {:#x}",
        sim.seed()
    );
}

/// §5.4: одно сообщение — один транспорт за раз.
///
/// «Одновременная отправка одним и тем же сообщением по нескольким
/// транспортам запрещена.» Проверяется тем, что до отказа первого транспорта
/// второй не задействуется вовсе.
#[test]
fn transports_are_tried_in_sequence_not_in_parallel() {
    let mut sim = network(0x5E00, 2);
    let (a, b) = (NodeId(0), NodeId(1));
    let b_ik = sim.node(b).ik();

    sim.partition(b, 1);
    send(&mut sim, a, b_ik, "по очереди");
    sim.run_for(1_000);

    // Сразу после отправки в спуле пусто: почта ещё не задействована,
    // потому что onion ещё не объявлен неудавшимся.
    assert_eq!(
        sim.stats().spooled,
        0,
        "почта задействована одновременно с onion — это запрещено §5.4"
    );
}

/// §5.4: ненадёжный прямой канал не мешает доставке — выручает откат.
///
/// Каждый второй кадр onion теряется. Повторов **тем же** транспортом
/// в протоколе нет сознательно (см. `transport_policy`), и именно поэтому
/// сценарий важен: он проверяет, что откат на почту сам по себе достаточен,
/// а не что мы дожали ненадёжный канал упорством.
#[test]
fn a_lossy_direct_channel_falls_back_and_delivers() {
    let mut sim = network(0x105_5, 2);
    sim.net_mut().set_profile(
        TransportKind::Onion,
        LinkProfile { loss_permille: 500, ..LinkProfile::ONION },
    );

    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    send(&mut sim, a, b_ik, "сквозь потери");
    sim.run_to_idle(500_000).expect("прогон должен завершиться");

    assert_eq!(
        sim.node(b).chat_with(&a_ik),
        vec!["сквозь потери".to_string()],
        "сообщение не выбралось из ненадёжного канала, сид {:#x}",
        sim.seed()
    );
    assert!(sim.stats().dropped > 0, "потерь не было — сценарий ничего не проверил");
}

/// §8.3: потеря ответа на рукопожатие не оставляет контакт без сессии.
///
/// Самый узкий случай найденной дыры: первое сообщение дошло, ответ пропал.
/// Инициатор перешлёт первое сообщение, и получатель обязан ответить тем же
/// сохранённым ответом вместо молчаливого отброса как повтора.
#[test]
fn a_lost_handshake_response_is_recovered() {
    let mut sim = network(0x8A3, 2);
    let (a, b) = (NodeId(0), NodeId(1));
    let (a_ik, b_ik) = (sim.node(a).ik(), sim.node(b).ik());

    send(&mut sim, a, b_ik, "после потери ответа");

    // Первое сообщение уходит и доходит; ответ теряем, включив потери
    // ровно на время его полёта.
    sim.run_for(1_000);
    sim.net_mut().set_profile(
        TransportKind::Onion,
        LinkProfile { loss_permille: 1000, ..LinkProfile::ONION },
    );
    sim.run_for(2_000);
    sim.net_mut()
        .set_profile(TransportKind::Onion, LinkProfile { loss_permille: 0, ..LinkProfile::ONION });

    sim.run_to_idle(500_000).expect("прогон должен завершиться");

    assert_eq!(
        sim.node(b).chat_with(&a_ik),
        vec!["после потери ответа".to_string()],
        "потерянный ответ на рукопожатие оставил контакт без сессии, сид {:#x}",
        sim.seed()
    );
}
