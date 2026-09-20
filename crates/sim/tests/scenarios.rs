//! Обязательные сценарии из §16.
//!
//! Каждый тест — это строка из списка спецификации:
//!
//! * разделение сети на неделю с последующим слиянием;
//! * перестановка сообщений почтовым транспортом;
//! * отправка обоими транспортами одновременно;
//! * одновременное исключение участника в двух сегментах.
//!
//! Узел здесь — минимальный: OR-Set состава, гибридные часы и окно
//! дедупликации, то есть ровно те подсистемы, сходимость которых сценарии
//! и проверяют. Когда появится `ratatosk-core`, его `Engine` встанет на это
//! же место, реализовав `SimNode`, и сценарии останутся дословно теми же.

use ratatosk_crdt::{DedupWindow, Hlc, HlcClock, MsgId, OrSet, OrSetOp, Tag};
use ratatosk_sim::{Ctx, LinkProfile, NodeId, Sim, SimNode, TransportKind};

// --- минимальный формат сообщения для сценариев -----------------------------

const KIND_ADD: u8 = 0x01;
const KIND_REMOVE: u8 = 0x02;
const KIND_TEXT: u8 = 0x03;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Msg {
    Membership { id: MsgId, op: OrSetOp<u16> },
    Text { id: MsgId, hlc: Hlc, body: Vec<u8> },
}

fn put_hlc(out: &mut Vec<u8>, h: Hlc) {
    out.extend_from_slice(&h.wall_ms.to_be_bytes());
    out.extend_from_slice(&h.logical.to_be_bytes());
}

fn get_hlc(b: &[u8], at: usize) -> Hlc {
    let wall = u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
    let logical = u32::from_be_bytes(b[at + 8..at + 12].try_into().unwrap());
    Hlc::new(wall, logical)
}

fn put_tag(out: &mut Vec<u8>, t: Tag) {
    put_hlc(out, t.hlc);
    out.extend_from_slice(&t.actor);
    out.extend_from_slice(&t.uniq);
}

const TAG_BYTES: usize = 12 + 32 + 8;

fn get_tag(b: &[u8], at: usize) -> Tag {
    Tag::new(
        get_hlc(b, at),
        b[at + 12..at + 44].try_into().unwrap(),
        b[at + 44..at + 52].try_into().unwrap(),
    )
}

fn encode(msg: &Msg) -> Vec<u8> {
    let mut out = Vec::new();
    match msg {
        Msg::Membership { id, op: OrSetOp::Add { elem, tag } } => {
            out.push(KIND_ADD);
            out.extend_from_slice(id);
            out.extend_from_slice(&elem.to_be_bytes());
            put_tag(&mut out, *tag);
        }
        Msg::Membership { id, op: OrSetOp::Remove { elem, observed } } => {
            out.push(KIND_REMOVE);
            out.extend_from_slice(id);
            out.extend_from_slice(&elem.to_be_bytes());
            out.extend_from_slice(&(observed.len() as u32).to_be_bytes());
            for t in observed {
                put_tag(&mut out, *t);
            }
        }
        Msg::Text { id, hlc, body } => {
            out.push(KIND_TEXT);
            out.extend_from_slice(id);
            put_hlc(&mut out, *hlc);
            out.extend_from_slice(body);
        }
    }
    out
}

fn decode(b: &[u8]) -> Msg {
    let id: MsgId = b[1..17].try_into().unwrap();
    match b[0] {
        KIND_ADD => {
            let elem = u16::from_be_bytes(b[17..19].try_into().unwrap());
            Msg::Membership { id, op: OrSetOp::Add { elem, tag: get_tag(b, 19) } }
        }
        KIND_REMOVE => {
            let elem = u16::from_be_bytes(b[17..19].try_into().unwrap());
            let count = u32::from_be_bytes(b[19..23].try_into().unwrap()) as usize;
            let observed = (0..count).map(|i| get_tag(b, 23 + i * TAG_BYTES)).collect();
            Msg::Membership { id, op: OrSetOp::Remove { elem, observed } }
        }
        KIND_TEXT => Msg::Text { id, hlc: get_hlc(b, 17), body: b[29..].to_vec() },
        other => panic!("неизвестный тип сообщения {other}"),
    }
}

// --- узел --------------------------------------------------------------------

struct Peer {
    me: NodeId,
    peers: Vec<NodeId>,
    transport: TransportKind,
    actor: [u8; 32],
    clock: HlcClock,
    members: OrSet<u16>,
    dedup: DedupWindow,
    /// Принятые тексты в порядке приёма — специально не отсортированы,
    /// чтобы тест видел настоящую перестановку.
    inbox: Vec<(Hlc, Vec<u8>)>,
    /// Байты, ушедшие в эфир. Нужны, чтобы тест мог повторить кадр другим
    /// транспортом — ровно так, как это сделал бы клиент, дославший сообщение
    /// из очереди при появлении контакта в сети (§5.4).
    sent: Vec<Vec<u8>>,
    duplicates_seen: usize,
}

impl Peer {
    fn new(me: NodeId, peers: Vec<NodeId>, transport: TransportKind) -> Peer {
        let mut actor = [0u8; 32];
        actor[0] = me.0 as u8;
        Peer {
            me,
            peers,
            transport,
            actor,
            clock: HlcClock::new(),
            members: OrSet::new(),
            dedup: DedupWindow::default(),
            inbox: Vec::new(),
            sent: Vec::new(),
            duplicates_seen: 0,
        }
    }

    fn fresh_id(ctx: &mut Ctx<'_>) -> MsgId {
        let mut id = [0u8; 16];
        ctx.rng().fill(&mut id);
        id
    }

    fn broadcast(&mut self, ctx: &mut Ctx<'_>, msg: &Msg) {
        let bytes = encode(msg);
        self.sent.push(bytes.clone());
        for p in self.peers.clone() {
            if p != self.me {
                ctx.send(p, self.transport, bytes.clone());
            }
        }
    }

    fn add_member(&mut self, ctx: &mut Ctx<'_>, elem: u16) {
        let hlc = self.clock.now(ctx.now_ms()).unwrap();
        let mut uniq = [0u8; 8];
        ctx.rng().fill(&mut uniq);
        let op = OrSet::prepare_add(elem, Tag::new(hlc, self.actor, uniq));
        self.members.apply(op.clone());
        let msg = Msg::Membership { id: Self::fresh_id(ctx), op };
        self.broadcast(ctx, &msg);
    }

    fn remove_member(&mut self, ctx: &mut Ctx<'_>, elem: u16) {
        let op = self.members.prepare_remove(elem);
        self.members.apply(op.clone());
        let msg = Msg::Membership { id: Self::fresh_id(ctx), op };
        self.broadcast(ctx, &msg);
    }

    fn send_text(&mut self, ctx: &mut Ctx<'_>, body: &[u8]) {
        let hlc = self.clock.now(ctx.now_ms()).unwrap();
        let msg = Msg::Text { id: Self::fresh_id(ctx), hlc, body: body.to_vec() };
        self.broadcast(ctx, &msg);
    }

    /// Порядок, в котором сообщения показываются пользователю: по HLC (§9.1).
    fn ordered_inbox(&self) -> Vec<Vec<u8>> {
        let mut v = self.inbox.clone();
        v.sort_by_key(|(h, _)| *h);
        v.into_iter().map(|(_, b)| b).collect()
    }
}

impl SimNode for Peer {
    fn on_deliver(&mut self, ctx: &mut Ctx<'_>, _from: NodeId, _k: TransportKind, bytes: &[u8]) {
        let msg = decode(bytes);
        let id = match &msg {
            Msg::Membership { id, .. } | Msg::Text { id, .. } => *id,
        };
        if !self.dedup.check(id, ctx.now_ms()).is_fresh() {
            self.duplicates_seen += 1;
            return;
        }
        match msg {
            Msg::Membership { op, .. } => self.members.apply(op),
            Msg::Text { hlc, body, .. } => {
                // Метка из далёкого будущего отбрасывается вместе с сообщением.
                if self.clock.observe(ctx.now_ms(), hlc).is_ok() {
                    self.inbox.push((hlc, body));
                }
            }
        }
    }
}

// --- сценарии ----------------------------------------------------------------

fn three_peers(seed: u64, transport: TransportKind) -> Sim<Peer> {
    let ids: Vec<NodeId> = (0..3).map(NodeId).collect();
    let nodes = ids.iter().map(|&id| Peer::new(id, ids.clone(), transport)).collect();
    let mut sim = Sim::new(seed, nodes);
    sim.start();
    sim
}

const WEEK_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// §16: разделение сети на неделю с последующим слиянием.
#[test]
fn week_long_partition_then_merge_converges() {
    let mut sim = three_peers(0xA1CE, TransportKind::Mail);

    // Общая история до разрыва.
    with(&mut sim, NodeId(0), |p, c| p.add_member(c, 100));
    with(&mut sim, NodeId(0), |p, c| p.add_member(c, 200));
    sim.run_for(600_000);

    // Узел 2 уходит в отдельный сегмент на неделю.
    sim.partition(NodeId(2), 1);
    with(&mut sim, NodeId(0), |p, c| p.add_member(c, 300));
    with(&mut sim, NodeId(2), |p, c| p.add_member(c, 400));
    sim.run_for(WEEK_MS);

    assert!(sim.stats().spooled > 0, "почта во время разрыва должна копиться");
    assert!(!sim.node(NodeId(0)).members.contains(&400), "сегменты не должны видеть друг друга");

    // Слияние.
    sim.heal();
    sim.run_to_idle(100_000).expect("прогон должен завершиться");

    let expected = vec![100u16, 200, 300, 400];
    for id in 0..3 {
        let got: Vec<u16> = sim.node(NodeId(id)).members.elements().copied().collect();
        assert_eq!(got, expected, "узел {id} не сошёлся, сид {:#x}", sim.seed());
    }
}

/// §16: перестановка сообщений почтовым транспортом.
#[test]
fn mail_reordering_is_repaired_by_hlc() {
    let mut sim = three_peers(0xB0B, TransportKind::Mail);

    let bodies: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i]).collect();
    for body in &bodies {
        with(&mut sim, NodeId(0), |p, c| p.send_text(c, body));
        sim.run_for(1_000);
    }
    sim.run_to_idle(100_000).expect("прогон должен завершиться");

    let receiver = sim.node(NodeId(1));
    let arrival: Vec<Vec<u8>> = receiver.inbox.iter().map(|(_, b)| b.clone()).collect();
    assert!(!arrival.is_empty(), "хоть что-то должно дойти");
    assert_ne!(arrival, bodies, "почта обязана была переставить сообщения");

    // Порядок показа восстанавливается по HLC, а не по времени прихода.
    let shown = receiver.ordered_inbox();
    let expected: Vec<Vec<u8>> = bodies.iter().filter(|b| shown.contains(b)).cloned().collect();
    assert_eq!(shown, expected, "сид {:#x}", sim.seed());
}

/// §16: отправка обоими транспортами одновременно.
///
/// §5.4 такую отправку запрещает, но §9.2 обязан выдерживать её на приёме:
/// сообщение, ушедшее почтой, а потом продублированное прямым каналом, должно
/// быть показано один раз.
#[test]
fn same_message_over_two_transports_is_shown_once() {
    let mut sim = three_peers(0xC0DE, TransportKind::Mail);
    sim.net_mut().set_enabled(TransportKind::Lan, true);
    sim.net_mut().set_profile(TransportKind::Lan, LinkProfile::INSTANT);

    with(&mut sim, NodeId(0), |p, c| p.send_text(c, b"once"));
    sim.run_to_idle(10_000).expect("прогон должен завершиться");
    assert_eq!(sim.node(NodeId(1)).inbox.len(), 1);

    // Ровно те же байты — вторым транспортом.
    let bytes = sim.node(NodeId(0)).sent[0].clone();
    sim.inject(NodeId(0), NodeId(1), TransportKind::Lan, bytes);
    sim.run_to_idle(10_000).expect("прогон должен завершиться");

    assert_eq!(sim.node(NodeId(1)).inbox.len(), 1, "дубль обязан быть отброшен");
    assert_eq!(sim.node(NodeId(1)).duplicates_seen, 1);
}

/// §16: одновременное исключение участника в двух сегментах.
#[test]
fn concurrent_eviction_in_two_segments_converges() {
    let mut sim = three_peers(0xDEAD, TransportKind::Mail);

    with(&mut sim, NodeId(0), |p, c| p.add_member(c, 777));
    sim.run_to_idle(100_000).expect("прогон должен завершиться");
    for id in 0..3 {
        assert!(sim.node(NodeId(id)).members.contains(&777));
    }

    // Разрыв: узлы 0 и 1 в одном сегменте, узел 2 — в другом.
    sim.partition(NodeId(2), 1);
    with(&mut sim, NodeId(0), |p, c| p.remove_member(c, 777));
    with(&mut sim, NodeId(2), |p, c| p.remove_member(c, 777));
    sim.run_for(WEEK_MS);

    sim.heal();
    sim.run_to_idle(100_000).expect("прогон должен завершиться");

    for id in 0..3 {
        assert!(
            !sim.node(NodeId(id)).members.contains(&777),
            "узел {id}: оба удаления видели одно и то же добавление, участник должен исчезнуть везде; сид {:#x}",
            sim.seed()
        );
    }
}

/// Волна ухода: расписание, а не десяток вызовов посреди прогона.
///
/// Рой ломается на **совпадениях** — ушедшая пятая часть, наложившаяся
/// на заживание, — и задавать их надо до прогона, чтобы падение
/// воспроизводилось по сиду.
#[test]
fn a_churn_wave_is_scheduled_once_and_heals_by_itself() {
    let mut sim = three_peers(0xF00D, TransportKind::Mail);

    // Уходят все трое вразнобой и возвращаются через минуту.
    let gone = sim.churn_wave(1_000, 10_000, 5_000, 60_000);
    assert_eq!(gone.len(), 3, "доля 1000‰ — это все");

    // Пишем, когда в отлучке **все трое**: уходят они вразнобой (5 с
    // между окнами), и на двенадцатой секунде ушёл только первый —
    // письмо ещё доехало бы. Окна здесь [10, 70), [15, 75), [20, 80) с;
    // двадцать пять — первый момент, когда нет никого.
    sim.run_for(25_000);
    with(&mut sim, NodeId(0), |p, c| p.send_text(c, "пока тебя нет".as_bytes()));
    sim.run_for(5_000);
    assert!(sim.stats().spooled > 0, "ушедшему письма кладутся в спул");

    // И разобраться спул обязан **сам**, по расписанию: никто не зовёт
    // `set_online`, часы двигает очередь. Без события возвращения
    // вернувшийся ждал бы постороннего повода — а на пустой очереди
    // не дождался бы никогда.
    sim.run_to_idle(100_000).expect("прогон должен завершиться");
    assert_eq!(sim.stats().spooled, 0, "вернувшиеся разобрали накопившееся; сид {:#x}", sim.seed());
    assert_eq!(
        sim.node(NodeId(1)).inbox.len(),
        1,
        "и слово, сказанное в отлучку, дошло; сид {:#x}",
        sim.seed()
    );
}

/// Волна воспроизводится по сиду: ушли те же и в те же моменты.
///
/// Без этого «ушла пятая часть» — не сценарий, а случайность, и падение
/// на ней не воспроизвести.
#[test]
fn the_same_seed_sends_the_same_nodes_away() {
    let wave = |seed: u64| {
        let mut sim = three_peers(seed, TransportKind::Mail);
        let gone = sim.churn_wave(500, 1_000, 100, 1_000);
        let windows: Vec<(NodeId, Vec<(u64, u64)>)> =
            gone.iter().map(|id| (*id, sim.net_mut().offline_windows(*id).to_vec())).collect();
        windows
    };
    assert_eq!(wave(0x5EED), wave(0x5EED));
}

/// §16: «Найденное расхождение воспроизводится по номеру сида.»
///
/// Проверяются две разные вещи, и их важно не путать:
///
/// * **порядок прихода** зависит от сида — иначе харнесс не исследует
///   пространство перестановок и ничего не найдёт;
/// * **итоговое состояние** от сида не зависит — это и есть сходимость,
///   ради которой всё построено.
#[test]
fn runs_are_reproducible_by_seed() {
    struct Fingerprint {
        arrival_order: Vec<Vec<Vec<u8>>>,
        members: Vec<Vec<u16>>,
    }

    fn run(seed: u64) -> Fingerprint {
        let mut sim = three_peers(seed, TransportKind::Mail);
        for i in 0..10u16 {
            with(&mut sim, NodeId(i % 3), |p, c| p.add_member(c, i));
            with(&mut sim, NodeId(0), |p, c| p.send_text(c, &i.to_be_bytes()));
            sim.run_for(5_000);
        }
        sim.partition(NodeId(1), 2);
        sim.run_for(WEEK_MS);
        sim.heal();
        sim.run_to_idle(200_000).unwrap();

        Fingerprint {
            arrival_order: (0..3)
                .map(|n| sim.node(NodeId(n)).inbox.iter().map(|(_, b)| b.clone()).collect())
                .collect(),
            members: (0..3)
                .map(|n| sim.node(NodeId(n)).members.elements().copied().collect())
                .collect(),
        }
    }

    let a1 = run(1);
    let a2 = run(1);
    let b = run(99);

    assert_eq!(a1.arrival_order, a2.arrival_order, "один сид — один прогон, байт в байт");
    assert_eq!(a1.members, a2.members);

    assert_ne!(
        a1.arrival_order, b.arrival_order,
        "разные сиды обязаны давать разные перестановки, иначе харнесс ничего не ищет"
    );
    assert_eq!(
        a1.members, b.members,
        "а вот итоговое состояние обязано совпасть: сходимость от сида не зависит"
    );
}

// --- вспомогательное ---------------------------------------------------------

/// Выполняет локальное действие узла так же, как это сделал бы UI.
fn with(sim: &mut Sim<Peer>, id: NodeId, f: impl FnOnce(&mut Peer, &mut Ctx<'_>)) {
    sim.act(id, f);
}
