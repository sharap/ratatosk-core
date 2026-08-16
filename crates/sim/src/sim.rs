//! Планировщик симуляции: виртуальное время, очередь событий, узлы.

use std::cmp::{Ordering, Reverse};
use std::collections::{BinaryHeap, HashMap};

use crate::net::{Delivery, Network, NodeId, TransportKind};
use crate::rng::Rng;

/// Действие, которое узел просит выполнить сеть.
#[derive(Debug, Clone)]
enum Action {
    Send { to: NodeId, kind: TransportKind, bytes: Vec<u8> },
    Timer { after_ms: u64, token: u64 },
}

/// Контекст, доступный узлу во время обработки события.
///
/// Узел не видит ни очереди, ни других узлов, ни реального времени — только
/// то, что видел бы настоящий клиент. Это то же ограничение, что и sans-io
/// в `ratatosk-core`, и оно здесь по той же причине.
pub struct Ctx<'a> {
    now_ms: u64,
    me: NodeId,
    actions: &'a mut Vec<Action>,
    rng: &'a mut Rng,
}

impl Ctx<'_> {
    /// Текущее виртуальное время, мс.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Собственный идентификатор узла.
    #[must_use]
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// Отправляет байты указанным транспортом.
    pub fn send(&mut self, to: NodeId, kind: TransportKind, bytes: Vec<u8>) {
        self.actions.push(Action::Send { to, kind, bytes });
    }

    /// Просит разбудить себя через `after_ms` виртуальных миллисекунд.
    pub fn set_timer(&mut self, after_ms: u64, token: u64) {
        self.actions.push(Action::Timer { after_ms, token });
    }

    /// Генератор, принадлежащий этому узлу.
    ///
    /// У каждого узла свой поток, выведенный из общего сида: благодаря этому
    /// правка сетевого профиля не сдвигает случайные решения узлов и падение
    /// остаётся воспроизводимым.
    pub fn rng(&mut self) -> &mut Rng {
        self.rng
    }
}

/// Узел, участвующий в симуляции.
pub trait SimNode {
    /// Вызывается один раз перед началом прогона.
    fn on_start(&mut self, _ctx: &mut Ctx<'_>) {}

    /// Прибыли байты от другого узла.
    fn on_deliver(&mut self, ctx: &mut Ctx<'_>, from: NodeId, kind: TransportKind, bytes: &[u8]);

    /// Сработал таймер, поставленный через [`Ctx::set_timer`].
    fn on_timer(&mut self, _ctx: &mut Ctx<'_>, _token: u64) {}

    /// Доставка прямым каналом не удалась.
    ///
    /// Без этого сигнала §5.4 непроверяем: отправитель не узнаёт, что onion
    /// не ответил, и не переходит к почте. Молча потерянный кадр выглядит
    /// в сценарии как «сообщение не дошло», хотя протокол обязан был
    /// доставить его следующим транспортом.
    ///
    /// Почта так не отказывает — она копится в спуле (§5.3), — поэтому
    /// уведомление приходит только для прямых каналов.
    fn on_send_failed(&mut self, _ctx: &mut Ctx<'_>, _to: NodeId, _kind: TransportKind) {}
}

#[derive(Debug, Clone)]
enum Event {
    Deliver { from: NodeId, to: NodeId, kind: TransportKind, bytes: Vec<u8> },
    Timer { node: NodeId, token: u64 },
    SendFailed { node: NodeId, to: NodeId, kind: TransportKind },
}

#[derive(Debug, Clone)]
struct Scheduled {
    at_ms: u64,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.at_ms == other.at_ms && self.seq == other.seq
    }
}
impl Eq for Scheduled {}
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        // Порядок строгий: одинаковое время разводится порядковым номером
        // постановки. Без этого прогон перестаёт быть воспроизводимым.
        self.at_ms.cmp(&other.at_ms).then(self.seq.cmp(&other.seq))
    }
}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Сводка прогона — то, что печатается в отчёте о падении вместе с сидом.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Сколько кадров доставлено.
    pub delivered: u64,
    /// Сколько потеряно сетью.
    pub dropped: u64,
    /// Сколько сейчас лежит в почтовом спуле.
    pub spooled: u64,
    /// Сколько сработало таймеров.
    pub timers_fired: u64,
    /// Сколько отказов доставки сообщено отправителям.
    pub send_failures: u64,
}

/// Прогон: узлы, сеть, виртуальные часы и очередь событий.
pub struct Sim<N: SimNode> {
    nodes: Vec<N>,
    rngs: Vec<Rng>,
    net: Network,
    net_rng: Rng,
    now_ms: u64,
    seq: u64,
    queue: BinaryHeap<Reverse<Scheduled>>,
    spool: HashMap<NodeId, Vec<(NodeId, Vec<u8>)>>,
    stats: Stats,
    seed: u64,
}

impl<N: SimNode> Sim<N> {
    /// Создаёт прогон с заданным сидом.
    ///
    /// Сид — единственный источник случайности во всей симуляции.
    pub fn new(seed: u64, nodes: Vec<N>) -> Sim<N> {
        let rngs = (0..nodes.len())
            .map(|i| {
                Rng::from_seed(seed ^ (0x51_7C_C1_B7_27_22_0A_95u64.wrapping_mul(i as u64 + 1)))
            })
            .collect();
        Sim {
            nodes,
            rngs,
            net: Network::new(),
            net_rng: Rng::from_seed(seed.wrapping_add(0xD1B5_4A32_D192_ED03)),
            now_ms: 0,
            seq: 0,
            queue: BinaryHeap::new(),
            spool: HashMap::new(),
            stats: Stats::default(),
            seed,
        }
    }

    /// Сид этого прогона — печатать в любом отчёте о расхождении.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Текущее виртуальное время.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Статистика прогона.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let spooled = self.spool.values().map(|v| v.len() as u64).sum();
        Stats { spooled, ..self.stats }
    }

    /// Модель сети — настраивается до и во время прогона.
    pub fn net_mut(&mut self) -> &mut Network {
        &mut self.net
    }

    /// Узел по идентификатору.
    #[must_use]
    pub fn node(&self, id: NodeId) -> &N {
        &self.nodes[id.index()]
    }

    /// Изменяемый доступ к узлу — для проверок в тестах.
    pub fn node_mut(&mut self, id: NodeId) -> &mut N {
        &mut self.nodes[id.index()]
    }

    /// Все узлы.
    #[must_use]
    pub fn nodes(&self) -> &[N] {
        &self.nodes
    }

    /// Число узлов.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Есть ли узлы.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Вызывает `on_start` у всех узлов.
    pub fn start(&mut self) {
        for i in 0..self.nodes.len() {
            let id = NodeId(i as u16);
            let mut actions = Vec::new();
            {
                let mut ctx = Ctx {
                    now_ms: self.now_ms,
                    me: id,
                    actions: &mut actions,
                    rng: &mut self.rngs[i],
                };
                self.nodes[i].on_start(&mut ctx);
            }
            self.apply(id, actions);
        }
    }

    /// Выполняет локальное действие узла — то, что в продукте инициирует UI.
    ///
    /// Замыкание получает узел и контекст, поэтому отправки и таймеры из
    /// локального действия проходят через сеть на общих основаниях.
    pub fn act<R>(&mut self, id: NodeId, f: impl FnOnce(&mut N, &mut Ctx<'_>) -> R) -> R {
        let i = id.index();
        let mut actions = Vec::new();
        let out = {
            let mut ctx =
                Ctx { now_ms: self.now_ms, me: id, actions: &mut actions, rng: &mut self.rngs[i] };
            f(&mut self.nodes[i], &mut ctx)
        };
        self.apply(id, actions);
        out
    }

    /// Доставляет байты узлу, минуя сеть, — как будто их принёс транспорт.
    pub fn inject(&mut self, from: NodeId, to: NodeId, kind: TransportKind, bytes: Vec<u8>) {
        self.push(self.now_ms, Event::Deliver { from, to, kind, bytes });
    }

    /// Переводит узел в онлайн или офлайн.
    ///
    /// При возвращении в сеть почтовый спул разбирается — это моделирует
    /// IMAP IDLE, забирающий накопившееся (§5.3).
    pub fn set_online(&mut self, node: NodeId, on: bool) {
        self.net.set_online(node, on);
        if on {
            self.flush_spool(node);
        }
    }

    /// Помещает узел в сегмент сети.
    pub fn partition(&mut self, node: NodeId, segment: u8) {
        self.net.set_segment(node, segment);
    }

    /// Слияние сегментов: все узлы снова видят друг друга, спулы разбираются.
    pub fn heal(&mut self) {
        self.net.heal();
        let nodes: Vec<NodeId> = self.spool.keys().copied().collect();
        for n in nodes {
            if self.net.is_online(n) {
                self.flush_spool(n);
            }
        }
    }

    /// Прогоняет симуляцию до момента `until_ms` включительно.
    ///
    /// Возвращает число обработанных событий.
    pub fn run_until(&mut self, until_ms: u64) -> usize {
        let mut handled = 0;
        while let Some(Reverse(next)) = self.queue.peek() {
            if next.at_ms > until_ms {
                break;
            }
            let Reverse(scheduled) = self.queue.pop().expect("очередь непуста: peek уже проверил");
            self.now_ms = scheduled.at_ms;
            self.dispatch(scheduled.event);
            handled += 1;
        }
        self.now_ms = self.now_ms.max(until_ms);
        handled
    }

    /// Прогоняет `duration_ms` виртуального времени вперёд.
    pub fn run_for(&mut self, duration_ms: u64) -> usize {
        self.run_until(self.now_ms + duration_ms)
    }

    /// Прогоняет, пока очередь не опустеет или не будет исчерпан лимит шагов.
    ///
    /// Лимит обязателен: зацикливание узлов должно давать понятный отказ,
    /// а не бесконечный тест в CI.
    pub fn run_to_idle(&mut self, max_steps: usize) -> Result<usize, usize> {
        let mut handled = 0;
        while let Some(Reverse(next)) = self.queue.peek() {
            if handled >= max_steps {
                return Err(handled);
            }
            let at = next.at_ms;
            let Reverse(scheduled) = self.queue.pop().expect("очередь непуста: peek уже проверил");
            self.now_ms = at;
            self.dispatch(scheduled.event);
            handled += 1;
        }
        Ok(handled)
    }

    fn dispatch(&mut self, event: Event) {
        match event {
            Event::Deliver { from, to, kind, bytes } => {
                if !self.net.is_online(to) {
                    // Узел успел уйти офлайн, пока кадр был в пути.
                    if kind.is_direct() {
                        self.stats.dropped += 1;
                    } else {
                        self.spool.entry(to).or_default().push((from, bytes));
                    }
                    return;
                }
                self.stats.delivered += 1;
                let i = to.index();
                let mut actions = Vec::new();
                {
                    let mut ctx = Ctx {
                        now_ms: self.now_ms,
                        me: to,
                        actions: &mut actions,
                        rng: &mut self.rngs[i],
                    };
                    self.nodes[i].on_deliver(&mut ctx, from, kind, &bytes);
                }
                self.apply(to, actions);
            }
            Event::SendFailed { node, to, kind } => {
                self.stats.send_failures += 1;
                let i = node.index();
                let mut actions = Vec::new();
                {
                    let mut ctx = Ctx {
                        now_ms: self.now_ms,
                        me: node,
                        actions: &mut actions,
                        rng: &mut self.rngs[i],
                    };
                    self.nodes[i].on_send_failed(&mut ctx, to, kind);
                }
                self.apply(node, actions);
            }
            Event::Timer { node, token } => {
                self.stats.timers_fired += 1;
                let i = node.index();
                let mut actions = Vec::new();
                {
                    let mut ctx = Ctx {
                        now_ms: self.now_ms,
                        me: node,
                        actions: &mut actions,
                        rng: &mut self.rngs[i],
                    };
                    self.nodes[i].on_timer(&mut ctx, token);
                }
                self.apply(node, actions);
            }
        }
    }

    fn apply(&mut self, from: NodeId, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send { to, kind, bytes } => {
                    match self.net.schedule(&mut self.net_rng, self.now_ms, from, to, kind) {
                        Delivery::At(at) => {
                            self.push(at, Event::Deliver { from, to, kind, bytes });
                        }
                        Delivery::Twice(a, b) => {
                            self.push(a, Event::Deliver { from, to, kind, bytes: bytes.clone() });
                            self.push(b, Event::Deliver { from, to, kind, bytes });
                        }
                        Delivery::Dropped => {
                            self.stats.dropped += 1;
                            // Прямой канал обязан сообщить отправителю о том,
                            // что не дошло, — иначе переход к следующему
                            // транспорту (§5.4) никогда не произойдёт.
                            if kind.is_direct() {
                                let at = self.now_ms + self.net.failure_notice_ms(kind);
                                self.push(at, Event::SendFailed { node: from, to, kind });
                            }
                        }
                        Delivery::Spool => self.spool.entry(to).or_default().push((from, bytes)),
                    }
                }
                Action::Timer { after_ms, token } => {
                    self.push(self.now_ms + after_ms, Event::Timer { node: from, token });
                }
            }
        }
    }

    fn flush_spool(&mut self, node: NodeId) {
        let Some(pending) = self.spool.remove(&node) else {
            return;
        };
        for (from, bytes) in pending {
            if !self.net.reachable(from, node) {
                // Всё ещё в разных сегментах — обратно в спул.
                self.spool.entry(node).or_default().push((from, bytes));
                continue;
            }
            match self.net.schedule(&mut self.net_rng, self.now_ms, from, node, TransportKind::Mail)
            {
                Delivery::At(at) => self
                    .push(at, Event::Deliver { from, to: node, kind: TransportKind::Mail, bytes }),
                Delivery::Twice(a, b) => {
                    self.push(
                        a,
                        Event::Deliver {
                            from,
                            to: node,
                            kind: TransportKind::Mail,
                            bytes: bytes.clone(),
                        },
                    );
                    self.push(
                        b,
                        Event::Deliver { from, to: node, kind: TransportKind::Mail, bytes },
                    );
                }
                Delivery::Dropped => self.stats.dropped += 1,
                Delivery::Spool => self.spool.entry(node).or_default().push((from, bytes)),
            }
        }
    }

    fn push(&mut self, at_ms: u64, event: Event) {
        self.seq += 1;
        self.queue.push(Reverse(Scheduled { at_ms, seq: self.seq, event }));
    }
}
