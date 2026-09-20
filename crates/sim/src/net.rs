//! Модель сети: транспорты, задержки, разделения, почтовый спул (§5, §16).

use std::collections::HashMap;

use crate::rng::Rng;

/// Номер узла в симуляции.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u16);

impl NodeId {
    /// Индекс для доступа к массиву узлов.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Транспорт, по которому идёт кадр (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportKind {
    /// Локальная сеть. По умолчанию выключена (§5.1).
    Lan,
    /// Канал L2CAP поверх Bluetooth LE (0.4). По умолчанию выключен.
    Bt,
    /// Меш Yggdrasil (0.2). По умолчанию выключен.
    Ygg,
    /// Tor onion-to-onion (§5.2).
    Onion,
    /// Событие на реле nostr поверх Tor (0.3). По умолчанию выключен.
    Nostr,
    /// Почта chatmail поверх Tor (§5.3).
    Mail,
}

impl TransportKind {
    /// Все транспорты.
    pub const ALL: [TransportKind; 6] = [
        TransportKind::Lan,
        TransportKind::Bt,
        TransportKind::Ygg,
        TransportKind::Onion,
        TransportKind::Nostr,
        TransportKind::Mail,
    ];

    /// Прямой ли это канал.
    ///
    /// Различие содержательное, а не косметическое: квитанции о доставке
    /// и прочтении отправляются только прямым каналом (§9.4), а файлы больше
    /// 20 МБ — только им же (§10.3).
    #[must_use]
    pub const fn is_direct(self) -> bool {
        matches!(
            self,
            TransportKind::Lan | TransportKind::Bt | TransportKind::Ygg | TransportKind::Onion
        )
    }
}

/// Характеристики транспорта.
#[derive(Debug, Clone, Copy)]
pub struct LinkProfile {
    /// Минимальная односторонняя задержка, мс.
    pub min_latency_ms: u64,
    /// Максимальная односторонняя задержка, мс. Разброс и создаёт перестановки.
    pub max_latency_ms: u64,
    /// Вероятность потери кадра, промилле.
    pub loss_permille: u32,
    /// Вероятность дублирования кадра, промилле.
    pub duplicate_permille: u32,
    /// Через сколько отправитель узнаёт, что доставка не удалась, мс.
    ///
    /// Для прямых каналов это таймаут соединения: §5.4 отводит onion 45 секунд,
    /// после чего клиент обязан перейти к следующему транспорту. Почта таким
    /// образом не отказывает — она копится в спуле, — поэтому значение для неё
    /// не используется.
    pub failure_notice_ms: u64,
}

impl LinkProfile {
    /// Локальная сеть: быстро и почти без потерь.
    pub const LAN: LinkProfile = LinkProfile {
        min_latency_ms: 1,
        max_latency_ms: 10,
        loss_permille: 0,
        duplicate_permille: 0,
        failure_notice_ms: 5_000,
    };

    /// Bluetooth: канал L2CAP в одной комнате (0.4).
    ///
    /// Задержка не миллисекундная, как в проводной сети, и упирается она
    /// не в расстояние, а в расписание: пакеты в BLE ходят интервалами
    /// соединения, и кадр ждёт ближайшего. Отсюда десятки миллисекунд
    /// снизу и сотни сверху — интервал выбирает не приложение, а стек
    /// на обеих сторонах.
    ///
    /// Потери редкие: канальный уровень переспрашивает сам. Дублей нет
    /// вовсе — поток, а не события на реле.
    ///
    /// **Задержки сверены с живым стендом** (`HANDOFF.md`, 6з): круг
    /// с квитанцией на кадрах от 4 до 64 КиБ занимает 370–540 мс в обе
    /// стороны, то есть односторонняя задержка того же порядка, что здесь.
    ///
    /// Чего профиль по-прежнему не знает — **пропускной способности**:
    /// модель сети считает задержки и потери, а не байты в секунду.
    /// На стенде мебибайт идёт около тридцати секунд (≈35 КБ/с), и это
    /// число сегодня живёт в другом месте — `floor_bytes_per_sec`
    /// в политике, откуда его берут сроки ожидания.
    pub const BT: LinkProfile = LinkProfile {
        min_latency_ms: 30,
        max_latency_ms: 400,
        loss_permille: 2,
        duplicate_permille: 0,
        // Столько же, сколько `BT_CONNECT_TIMEOUT_MS` в политике: встреча
        // расписаний объявления и сканирования занимает секунды.
        failure_notice_ms: 10_000,
    };

    /// Меш Yggdrasil: обычный интернет плюс путь через соседей.
    ///
    /// Двадцать–полтораста миллисекунд: пакет идёт напрямую, но не по
    /// кратчайшему маршруту, а по дереву меша, и число промежуточных узлов
    /// заранее неизвестно. Потери выше, чем у onion, и это не придирка
    /// к реализации: маршрут перестраивается на ходу, и кадр, ушедший
    /// по прежнему пути, теряется целиком.
    ///
    /// Срок отказа — пять секунд, как у локальной сети: соединение либо
    /// устанавливается, либо нет, и ждать сорок пять здесь нечего.
    pub const YGG: LinkProfile = LinkProfile {
        min_latency_ms: 20,
        max_latency_ms: 150,
        loss_permille: 10,
        duplicate_permille: 0,
        failure_notice_ms: 5_000,
    };

    /// Tor: 300–800 мс односторонней задержки по §5.2, редкие обрывы.
    pub const ONION: LinkProfile = LinkProfile {
        min_latency_ms: 300,
        max_latency_ms: 800,
        loss_permille: 5,
        // §5.4: таймаут попытки соединения с onion-сервисом.
        duplicate_permille: 0,
        failure_notice_ms: 45_000,
    };

    /// Nostr: между onion и почтой, и ближе к onion.
    ///
    /// Событие уходит на реле по живому веб-сокету и лежит там, пока
    /// собеседник не зайдёт, — но когда он в сети, доставка идёт секунды,
    /// а не минуты: реле раздаёт подписчикам сразу. Отсюда и разброс:
    /// нижняя граница как у onion плюс круг до реле, верхняя — минута
    /// на случай перегруженного реле, а не четыре, как у почтовой очереди.
    ///
    /// Дубли заметны: одно и то же событие приезжает с каждого реле,
    /// на которое мы его положили. Это не поломка реле, а устройство сети,
    /// и дедупликация §9.2 обязана это выдержать — здесь оно и проверяется.
    ///
    /// `failure_notice_ms` ноль, как у почты: отказ приходит не сроком
    /// ожидания, а ответом реле («блокировано», «не в списке»).
    pub const NOSTR: LinkProfile = LinkProfile {
        min_latency_ms: 1_000,
        max_latency_ms: 60_000,
        loss_permille: 3,
        duplicate_permille: 40,
        failure_notice_ms: 0,
    };

    /// Почта: секунды и минуты, сильные перестановки, изредка дубли от сервера.
    pub const MAIL: LinkProfile = LinkProfile {
        min_latency_ms: 2_000,
        max_latency_ms: 240_000,
        loss_permille: 1,
        duplicate_permille: 10,
        failure_notice_ms: 0,
    };

    /// Профиль без задержек и потерь — для тестов, где интересна только логика.
    pub const INSTANT: LinkProfile = LinkProfile {
        min_latency_ms: 0,
        max_latency_ms: 0,
        loss_permille: 0,
        duplicate_permille: 0,
        failure_notice_ms: 0,
    };
}

/// Что сеть решила сделать с кадром.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Доставить в указанный момент виртуального времени.
    At(u64),
    /// Доставить дважды — перестановки и дубли из §9.2 воспроизводятся здесь.
    Twice(u64, u64),
    /// Потерять.
    Dropped,
    /// Положить в почтовый спул: получатель офлайн или в другом сегменте.
    Spool,
}

/// Состояние моделируемой сети.
///
/// # Четыре слоя, и порядок между ними важен
///
/// Сеть отвечает на вопрос «что будет с кадром» по слоям, от частного
/// к общему:
///
/// 1. **связь** — профиль пары узлов на этой ступени
///    ([`Network::set_link_profile`]). Рою это нужно буквально: ребро
///    дерева раздачи через три хопа ведёт себя не так, как прямое,
///    и «средняя по сети задержка» такой разницы не показывает;
/// 2. **узел** — есть ли у него эта ступень вовсе
///    ([`Network::set_node_enabled`]). Популяция смешанная: у этих меш,
///    у тех реле, и §5.4 обязан выбирать разное для разных соседей;
/// 3. **топология** — связаны ли они на этой ступени и через сколько
///    хопов ([`Network::set_hop`]). Без неё меш — это «видим или нет»,
///    то есть не меш;
/// 4. **ступень** — общий профиль и общий выключатель.
#[derive(Debug, Clone)]
pub struct Network {
    profiles: HashMap<TransportKind, LinkProfile>,
    enabled: HashMap<TransportKind, bool>,
    segment: HashMap<NodeId, u8>,
    online: HashMap<NodeId, bool>,
    /// Профиль **связи**: перекрывает профиль ступени для этой пары.
    ///
    /// Ключ направленный: связь бывает несимметричной, и у роя это
    /// обычное дело — узел за NAT отвечает медленнее, чем слышит.
    link_profiles: HashMap<(NodeId, NodeId, TransportKind), LinkProfile>,
    /// Есть ли ступень **у этого узла**. Нет записи — берётся общий
    /// выключатель ступени.
    node_enabled: HashMap<(NodeId, TransportKind), bool>,
    /// Граф соседей на ступени: ребро и его задержка, мс.
    ///
    /// Пусто для ступени — она прямая (все со всеми, как было). Есть
    /// хоть одно ребро — ступень становится **графовой**: кадр идёт
    /// кратчайшим путём, и задержка пути складывается с задержкой
    /// профиля.
    hops: HashMap<TransportKind, HashMap<NodeId, Vec<(NodeId, u64)>>>,
    /// Окна, в которые узел выключен: `[от, до)` виртуального времени.
    ///
    /// Отдельно от [`Network::online`], потому что это **расписание**,
    /// а не состояние: волна ухода задаётся один раз, до прогона, и живёт
    /// по своим часам.
    offline_windows: HashMap<NodeId, Vec<(u64, u64)>>,
}

impl Default for Network {
    fn default() -> Self {
        Network::new()
    }
}

impl Network {
    /// Сеть с профилями по умолчанию.
    ///
    /// LAN выключен — как и в продукте (§5.1: «По умолчанию LAN выключен»).
    /// Тест, которому нужен LAN, включает его явно, и это правильная сторона
    /// умолчания: забытый вызов даёт более строгий сценарий, а не более мягкий.
    #[must_use]
    pub fn new() -> Network {
        let mut profiles = HashMap::new();
        profiles.insert(TransportKind::Lan, LinkProfile::LAN);
        profiles.insert(TransportKind::Bt, LinkProfile::BT);
        profiles.insert(TransportKind::Ygg, LinkProfile::YGG);
        profiles.insert(TransportKind::Onion, LinkProfile::ONION);
        profiles.insert(TransportKind::Nostr, LinkProfile::NOSTR);
        profiles.insert(TransportKind::Mail, LinkProfile::MAIL);

        let mut enabled = HashMap::new();
        enabled.insert(TransportKind::Lan, false);
        // И эфир выключен: он стоит батареи постоянно, а не в момент
        // отправки, и сценарий, которому он нужен, включает его явно.
        enabled.insert(TransportKind::Bt, false);
        // Выключен по той же причине, что и LAN: ступень не работает,
        // пока не названы пиры. Сценарий, которому она нужна, включает
        // её явно.
        enabled.insert(TransportKind::Ygg, false);
        enabled.insert(TransportKind::Onion, true);
        // И nostr по той же причине, что меш: ступень не работает, пока
        // не названы реле. Включённая по умолчанию, она молча уводила бы
        // отправку с почты на ступень, которой ни у кого нет.
        enabled.insert(TransportKind::Nostr, false);
        enabled.insert(TransportKind::Mail, true);

        Network {
            profiles,
            enabled,
            segment: HashMap::new(),
            online: HashMap::new(),
            link_profiles: HashMap::new(),
            node_enabled: HashMap::new(),
            hops: HashMap::new(),
            offline_windows: HashMap::new(),
        }
    }

    /// Заменяет профиль транспорта.
    pub fn set_profile(&mut self, kind: TransportKind, profile: LinkProfile) {
        self.profiles.insert(kind, profile);
    }

    /// Включает или выключает транспорт целиком.
    pub fn set_enabled(&mut self, kind: TransportKind, on: bool) {
        self.enabled.insert(kind, on);
    }

    /// Доступен ли транспорт.
    #[must_use]
    pub fn is_enabled(&self, kind: TransportKind) -> bool {
        self.enabled.get(&kind).copied().unwrap_or(false)
    }

    /// Задаёт профиль **связи** — пары узлов на этой ступени.
    ///
    /// Перекрывает профиль ступени только для этой пары и только в эту
    /// сторону. Всё, что не названо, продолжает жить общим профилем:
    /// сценарий, которому разница не нужна, не платит за неё ни строкой.
    pub fn set_link_profile(
        &mut self,
        from: NodeId,
        to: NodeId,
        kind: TransportKind,
        profile: LinkProfile,
    ) {
        self.link_profiles.insert((from, to, kind), profile);
    }

    /// То же в обе стороны — самый частый случай.
    pub fn set_link_profile_both(
        &mut self,
        a: NodeId,
        b: NodeId,
        kind: TransportKind,
        profile: LinkProfile,
    ) {
        self.set_link_profile(a, b, kind, profile);
        self.set_link_profile(b, a, kind, profile);
    }

    /// Какой профиль действует для этой связи: свой или ступенчатый.
    #[must_use]
    pub fn profile_for(
        &self,
        from: NodeId,
        to: NodeId,
        kind: TransportKind,
    ) -> Option<LinkProfile> {
        self.link_profiles.get(&(from, to, kind)).or_else(|| self.profiles.get(&kind)).copied()
    }

    /// Включает или выключает ступень **у одного узла**.
    ///
    /// Популяция роя смешанная: у одних меш, у других только реле.
    /// Общий выключатель такого сказать не умеет, а §5.4 обязан выбирать
    /// для разных соседей разное.
    pub fn set_node_enabled(&mut self, node: NodeId, kind: TransportKind, on: bool) {
        self.node_enabled.insert((node, kind), on);
    }

    /// Есть ли ступень у этого узла. Не названо — берётся общий
    /// выключатель ступени.
    #[must_use]
    pub fn is_enabled_for(&self, node: NodeId, kind: TransportKind) -> bool {
        self.node_enabled.get(&(node, kind)).copied().unwrap_or_else(|| self.is_enabled(kind))
    }

    /// Заводит ребро графа на ступени: соседи и задержка хопа, мс.
    ///
    /// Ребро **двустороннее**: сосед в меше — отношение взаимное.
    /// Несимметричную задержку задаёт [`Network::set_link_profile`],
    /// здесь же — топология.
    ///
    /// Первое же ребро делает ступень графовой: узлы, между которыми
    /// пути нет, перестают видеть друг друга **на этой ступени**.
    pub fn set_hop(&mut self, kind: TransportKind, a: NodeId, b: NodeId, hop_ms: u64) {
        let graph = self.hops.entry(kind).or_default();
        graph.entry(a).or_default().push((b, hop_ms));
        graph.entry(b).or_default().push((a, hop_ms));
    }

    /// Задержка кратчайшего пути, мс. `None` — пути нет.
    ///
    /// Ступень без единого ребра считается прямой: путь есть всегда
    /// и стоит ноль.
    #[must_use]
    pub fn path_ms(&self, kind: TransportKind, from: NodeId, to: NodeId) -> Option<u64> {
        let Some(graph) = self.hops.get(&kind) else { return Some(0) };
        if from == to {
            return Some(0);
        }
        // Дейкстра на карте: узлов в прогоне сотни, рёбер — единицы
        // на узел, и считать это на каждый кадр дешевле, чем держать
        // кэш, который придётся сбрасывать при каждой правке топологии.
        let mut best: HashMap<NodeId, u64> = HashMap::new();
        let mut frontier = vec![(0u64, from)];
        best.insert(from, 0);
        while let Some((at, node)) = frontier.pop() {
            if node == to {
                continue;
            }
            for (next, hop) in graph.get(&node).into_iter().flatten() {
                let cost = at + hop;
                if best.get(next).is_none_or(|known| cost < *known) {
                    best.insert(*next, cost);
                    frontier.push((cost, *next));
                }
            }
        }
        best.get(&to).copied()
    }

    /// Расписывает окно, в котором узел выключен: `[от, до)`.
    ///
    /// Волна ухода — это сценарий, а не десяток ручных вызовов посреди
    /// прогона: рой ломается на **совпадениях** ухода и возвращения,
    /// а их надо задавать до прогона и воспроизводить по сиду.
    pub fn set_offline_window(&mut self, node: NodeId, from_ms: u64, to_ms: u64) {
        self.offline_windows.entry(node).or_default().push((from_ms, to_ms));
    }

    /// Окна, в которые узел выключен.
    #[must_use]
    pub fn offline_windows(&self, node: NodeId) -> &[(u64, u64)] {
        self.offline_windows.get(&node).map_or(&[], Vec::as_slice)
    }

    /// Все моменты, когда какое-нибудь окно кончается.
    ///
    /// Нужно прогону: вернувшийся узел обязан разобрать почтовый спул,
    /// а разбирает его тот, у кого есть очередь событий (§5.3).
    #[must_use]
    pub fn window_ends(&self) -> Vec<(NodeId, u64)> {
        let mut ends: Vec<(NodeId, u64)> = self
            .offline_windows
            .iter()
            .flat_map(|(node, windows)| windows.iter().map(|(_, to)| (*node, *to)))
            .collect();
        ends.sort_unstable();
        ends
    }

    /// Включён ли узел **в этот момент**: и выключателем, и расписанием.
    #[must_use]
    pub fn is_online_at(&self, node: NodeId, now_ms: u64) -> bool {
        self.is_online(node)
            && !self.offline_windows(node).iter().any(|(from, to)| now_ms >= *from && now_ms < *to)
    }

    /// Помещает узел в сегмент сети. Узлы разных сегментов не видят друг друга.
    ///
    /// Сегмент 0 — «общая сеть» и значение по умолчанию.
    pub fn set_segment(&mut self, node: NodeId, segment: u8) {
        self.segment.insert(node, segment);
    }

    /// Возвращает все узлы в общий сегмент — слияние после разделения.
    pub fn heal(&mut self) {
        self.segment.clear();
    }

    /// Сегмент узла.
    #[must_use]
    pub fn segment_of(&self, node: NodeId) -> u8 {
        self.segment.get(&node).copied().unwrap_or(0)
    }

    /// Включён ли узел (телефон разряжен, приложение убито системой).
    #[must_use]
    pub fn is_online(&self, node: NodeId) -> bool {
        self.online.get(&node).copied().unwrap_or(true)
    }

    /// Меняет состояние узла.
    pub fn set_online(&mut self, node: NodeId, on: bool) {
        self.online.insert(node, on);
    }

    /// Через сколько отправитель узнаёт о неудаче на этом транспорте.
    #[must_use]
    pub fn failure_notice_ms(&self, kind: TransportKind) -> u64 {
        self.profiles.get(&kind).map_or(0, |p| p.failure_notice_ms)
    }

    /// Могут ли узлы обмениваться данными напрямую.
    ///
    /// Про сегменты, а не про ступень: разделение сети рвёт всё сразу.
    /// Связность **на ступени** спрашивают у [`Network::path_ms`].
    #[must_use]
    pub fn reachable(&self, from: NodeId, to: NodeId) -> bool {
        self.segment_of(from) == self.segment_of(to)
    }

    /// Решает судьбу кадра.
    ///
    /// Вся случайность берётся из переданного [`Rng`], поэтому решение
    /// воспроизводится по сиду.
    pub fn schedule(
        &self,
        rng: &mut Rng,
        now_ms: u64,
        from: NodeId,
        to: NodeId,
        kind: TransportKind,
    ) -> Delivery {
        // Ступень нужна **обоим**, и это не строгость ради строгости:
        // ни у одной из шести нет стороны, которая работала бы в одиночку.
        // Реле не отдаст событие тому, кто на него не ходит; в общей сети
        // не найдёт тот, кто не слушает.
        if !self.is_enabled_for(from, kind) || !self.is_enabled_for(to, kind) {
            return Delivery::Dropped;
        }
        if !self.reachable(from, to) {
            // Почта переживает разделение сети только если сегменты видят один
            // и тот же сервер; в модели разделение рвёт и её — это строгий,
            // то есть безопасный, вариант.
            return if kind == TransportKind::Mail { Delivery::Spool } else { Delivery::Dropped };
        }
        // Путь по графу ступени. Ступень без рёбер прямая, и путь стоит
        // ноль, — прежнее поведение целиком.
        let Some(path_ms) = self.path_ms(kind, from, to) else {
            // Связаны сегментом, но не соседством: в меше это обычное дело,
            // и означает оно ровно то же, что «не дозвонились».
            return if kind == TransportKind::Mail { Delivery::Spool } else { Delivery::Dropped };
        };
        if !self.is_online_at(to, now_ms) {
            // Прямой канал требует, чтобы получатель был в сети. Почта — нет:
            // ради этого она в протоколе и существует (§5.3).
            return if kind.is_direct() { Delivery::Dropped } else { Delivery::Spool };
        }

        let profile = match self.profile_for(from, to, kind) {
            Some(p) => p,
            None => return Delivery::Dropped,
        };

        if rng.chance_permille(profile.loss_permille) {
            return Delivery::Dropped;
        }

        // Задержка пути **складывается** с задержкой профиля, а не заменяет
        // её: профиль — про саму ступень (круг до реле, шифрование, стек),
        // путь — про то, сколько раз кадр перепрыгнул. Ребро дерева через
        // три хопа обязано вести себя не так, как прямое, — ради этого
        // граф и заведён.
        let first = now_ms + path_ms + rng.range(profile.min_latency_ms, profile.max_latency_ms);
        if rng.chance_permille(profile.duplicate_permille) {
            let second =
                now_ms + path_ms + rng.range(profile.min_latency_ms, profile.max_latency_ms);
            return Delivery::Twice(first, second);
        }
        Delivery::At(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: NodeId = NodeId(0);
    const B: NodeId = NodeId(1);

    #[test]
    fn lan_is_off_by_default() {
        let net = Network::new();
        assert!(!net.is_enabled(TransportKind::Lan));
        assert!(net.is_enabled(TransportKind::Onion));
        assert!(net.is_enabled(TransportKind::Mail));
    }

    #[test]
    fn disabled_transport_drops() {
        let net = Network::new();
        let mut rng = Rng::from_seed(1);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Lan), Delivery::Dropped);
    }

    #[test]
    fn partition_drops_direct_and_spools_mail() {
        let mut net = Network::new();
        net.set_segment(B, 1);
        let mut rng = Rng::from_seed(2);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Onion), Delivery::Dropped);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Mail), Delivery::Spool);
    }

    #[test]
    fn failure_notice_matches_the_spec_timeout() {
        let net = Network::new();
        // §5.4: onion — 45 секунд, после чего переход к следующему транспорту.
        assert_eq!(net.failure_notice_ms(TransportKind::Onion), 45_000);
        assert!(net.failure_notice_ms(TransportKind::Lan) < 45_000);
    }

    #[test]
    fn healing_restores_reachability() {
        let mut net = Network::new();
        net.set_segment(B, 1);
        assert!(!net.reachable(A, B));
        net.heal();
        assert!(net.reachable(A, B));
    }

    #[test]
    fn offline_peer_spools_mail_but_not_direct() {
        let mut net = Network::new();
        net.set_online(B, false);
        let mut rng = Rng::from_seed(3);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Onion), Delivery::Dropped);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Mail), Delivery::Spool);
    }

    #[test]
    fn onion_latency_matches_spec_range() {
        let net = Network::new();
        let mut rng = Rng::from_seed(4);
        for _ in 0..500 {
            if let Delivery::At(at) = net.schedule(&mut rng, 1_000, A, B, TransportKind::Onion) {
                assert!((1_300..=1_800).contains(&at), "{at}");
            }
        }
    }

    #[test]
    fn mail_reorders_because_of_latency_spread() {
        let net = Network::new();
        let mut rng = Rng::from_seed(5);
        let mut times = Vec::new();
        for i in 0..50u64 {
            if let Delivery::At(at) = net.schedule(&mut rng, i * 10, A, B, TransportKind::Mail) {
                times.push(at);
            }
        }
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_ne!(times, sorted, "почта обязана переставлять сообщения");
    }

    // --- Четыре слоя сети: связь, узел, топология, расписание -------------

    #[test]
    fn a_link_profile_beats_the_transport_profile() {
        // Ради роя: ребро дерева раздачи через три хопа ведёт себя не так,
        // как прямое, и «средняя по сети задержка» такой разницы
        // не показывает. Числа здесь свои, не из профиля ступени: возьми
        // проверка `LinkProfile::ONION`, правка профиля подняла бы и её,
        // и она смолчала бы о том, что связь перестала быть особой.
        let mut net = Network::new();
        net.set_link_profile(
            A,
            B,
            TransportKind::Onion,
            LinkProfile { min_latency_ms: 5_000, max_latency_ms: 5_000, ..LinkProfile::ONION },
        );
        let mut rng = Rng::from_seed(11);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Onion), Delivery::At(5_000));
        // Обратная сторона — своя: связь направленная, и узел за NAT
        // отвечает медленнее, чем слышит.
        let back = net.schedule(&mut rng, 0, B, A, TransportKind::Onion);
        assert!(matches!(back, Delivery::At(at) if (300..=800).contains(&at)), "{back:?}");
    }

    #[test]
    fn a_rung_missing_on_one_node_is_missing_for_the_pair() {
        // Популяция роя смешанная: у этих меш, у тех реле. Ступень нужна
        // **обоим** — ни у одной из шести нет стороны, работающей
        // в одиночку.
        let mut net = Network::new();
        net.set_enabled(TransportKind::Ygg, true);
        let mut rng = Rng::from_seed(12);
        assert!(matches!(net.schedule(&mut rng, 0, A, B, TransportKind::Ygg), Delivery::At(_)));

        net.set_node_enabled(B, TransportKind::Ygg, false);
        assert_eq!(net.schedule(&mut rng, 0, A, B, TransportKind::Ygg), Delivery::Dropped);
        assert_eq!(net.schedule(&mut rng, 0, B, A, TransportKind::Ygg), Delivery::Dropped);
        // А у остальных ступень по-прежнему общая: выключили одному.
        assert!(net.is_enabled_for(A, TransportKind::Ygg));
    }

    #[test]
    fn three_hops_cost_more_than_one() {
        // Топология — не «видим или нет»: у пути есть длина, и она
        // складывается с задержкой ступени. Числа здесь свои и круглые,
        // чтобы сложение было видно глазом.
        let mut net = Network::new();
        net.set_enabled(TransportKind::Ygg, true);
        net.set_profile(TransportKind::Ygg, LinkProfile::INSTANT);
        let (c, d) = (NodeId(2), NodeId(3));
        net.set_hop(TransportKind::Ygg, A, B, 10);
        net.set_hop(TransportKind::Ygg, B, c, 10);
        net.set_hop(TransportKind::Ygg, c, d, 10);

        assert_eq!(net.path_ms(TransportKind::Ygg, A, B), Some(10), "сосед — один хоп");
        assert_eq!(net.path_ms(TransportKind::Ygg, A, d), Some(30), "через троих — три");
        let mut rng = Rng::from_seed(13);
        assert_eq!(net.schedule(&mut rng, 0, A, d, TransportKind::Ygg), Delivery::At(30));

        // Узел, которого нет в графе, на этой ступени недостижим —
        // хотя сегмент у него общий.
        let stranger = NodeId(9);
        assert_eq!(net.path_ms(TransportKind::Ygg, A, stranger), None);
        assert_eq!(net.schedule(&mut rng, 0, A, stranger, TransportKind::Ygg), Delivery::Dropped);
        // А ступень без единого ребра осталась прямой.
        assert_eq!(net.path_ms(TransportKind::Onion, A, stranger), Some(0));
    }

    #[test]
    fn a_shorter_path_wins_even_when_it_is_found_later() {
        // Дейкстра, а не «первый найденный путь»: в меше обход соседей
        // задан порядком заведения рёбер, и длинный путь находится первым
        // сплошь и рядом.
        let mut net = Network::new();
        net.set_enabled(TransportKind::Ygg, true);
        let (c, d) = (NodeId(2), NodeId(3));
        net.set_hop(TransportKind::Ygg, A, c, 100);
        net.set_hop(TransportKind::Ygg, c, d, 100);
        net.set_hop(TransportKind::Ygg, d, B, 100);
        net.set_hop(TransportKind::Ygg, A, B, 50);
        assert_eq!(net.path_ms(TransportKind::Ygg, A, B), Some(50));
    }

    #[test]
    fn an_offline_window_is_a_schedule_and_not_a_switch() {
        // Волна ухода задаётся до прогона и живёт по своим часам:
        // «выключен сейчас» и «выключен с 10:00 до 10:05» — разные вещи,
        // и вторая воспроизводится по сиду.
        let mut net = Network::new();
        net.set_offline_window(B, 1_000, 2_000);
        assert!(net.is_online_at(B, 999), "до окна — в сети");
        assert!(!net.is_online_at(B, 1_000), "граница включительно");
        assert!(!net.is_online_at(B, 1_999));
        assert!(net.is_online_at(B, 2_000), "верхняя граница открыта: вернулся");

        let mut rng = Rng::from_seed(14);
        assert_eq!(net.schedule(&mut rng, 1_500, A, B, TransportKind::Onion), Delivery::Dropped);
        assert_eq!(net.schedule(&mut rng, 1_500, A, B, TransportKind::Mail), Delivery::Spool);
        assert!(matches!(
            net.schedule(&mut rng, 2_500, A, B, TransportKind::Onion),
            Delivery::At(_)
        ));
        assert_eq!(net.window_ends(), vec![(B, 2_000)]);
    }

    #[test]
    fn scheduling_is_reproducible_by_seed() {
        let net = Network::new();
        let run = || {
            let mut rng = Rng::from_seed(0xBEEF);
            (0..200)
                .map(|i| net.schedule(&mut rng, i, A, B, TransportKind::Mail))
                .collect::<Vec<_>>()
        };
        assert_eq!(run(), run());
    }
}
