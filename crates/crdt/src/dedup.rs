//! Окно дедупликации по `msg_id` (§9.2).
//!
//! Одно сообщение может законно прийти дважды разными транспортами — например,
//! ушло почтой, а потом контакт появился онлайн (§5.4). Это **нормальный
//! режим, а не ошибка**: дублирование на приёме разрешается здесь и нигде
//! больше.
//!
//! Структура в памяти — горячее окно; долговременное окно живёт в SQLite
//! (`ratatosk-store`) и чистится по тому же TTL при compaction (§12).

use std::collections::{HashMap, VecDeque};

/// TTL окна дедупликации — 30 суток (§9.2).
pub const DEDUP_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Предел на число записей в памяти.
///
/// Верхняя граница нужна, потому что TTL сам по себе от переполнения не
/// защищает: поток мусорных `msg_id` за минуту не устаревает.
pub const DEDUP_CAPACITY: usize = 200_000;

/// Идентификатор сообщения — 16 случайных байт (§9.1).
pub type MsgId = [u8; 16];

/// Что делать с сообщением.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupVerdict {
    /// Видим впервые — обрабатывать.
    Fresh,
    /// Уже видели — молча отбросить.
    Duplicate,
}

impl DedupVerdict {
    /// `true`, если сообщение надо обработать.
    #[must_use]
    pub const fn is_fresh(self) -> bool {
        matches!(self, DedupVerdict::Fresh)
    }
}

/// Скользящее окно виденных `msg_id`.
#[derive(Debug, Clone)]
pub struct DedupWindow {
    seen: HashMap<MsgId, u64>,
    order: VecDeque<(MsgId, u64)>,
    ttl_ms: u64,
    capacity: usize,
}

impl Default for DedupWindow {
    fn default() -> Self {
        DedupWindow::new(DEDUP_WINDOW_MS, DEDUP_CAPACITY)
    }
}

impl DedupWindow {
    /// Окно с заданными TTL и ёмкостью.
    #[must_use]
    pub fn new(ttl_ms: u64, capacity: usize) -> DedupWindow {
        DedupWindow {
            seen: HashMap::new(),
            order: VecDeque::new(),
            ttl_ms,
            capacity: capacity.max(1),
        }
    }

    /// Проверяет и, если сообщение новое, запоминает его.
    ///
    /// `now_ms` — физическое время приёма, не HLC: окно измеряется реальными
    /// сутками, а не логическим порядком.
    pub fn check(&mut self, id: MsgId, now_ms: u64) -> DedupVerdict {
        self.purge(now_ms);
        if self.seen.contains_key(&id) {
            return DedupVerdict::Duplicate;
        }
        self.seen.insert(id, now_ms);
        self.order.push_back((id, now_ms));
        self.evict_over_capacity();
        DedupVerdict::Fresh
    }

    /// Снимает отметку: кадр отложен, и приехать заново ему можно.
    ///
    /// Отметка ставится **до** разбора, а разбор вправе отложить кадр
    /// и потом вытеснить его из очереди отложенного. Без отмены
    /// вытесненный оставался бы «виденным» весь срок окна: анти-энтропия
    /// привозила бы его снова, а окно выбрасывало бы как повтор.
    /// Запись в порядке вытеснения остаётся — она безвредна: при
    /// вытеснении время сверяется, и чужую свежую отметку она не снимет.
    pub fn forget(&mut self, id: &MsgId) {
        self.seen.remove(id);
    }

    /// Видели ли идентификатор, не изменяя окно.
    #[must_use]
    pub fn contains(&self, id: &MsgId) -> bool {
        self.seen.contains_key(id)
    }

    /// Сколько записей сейчас в окне.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Пусто ли окно.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Выбрасывает записи старше TTL.
    pub fn purge(&mut self, now_ms: u64) {
        while let Some(&(id, at)) = self.order.front() {
            // Запись живёт ровно ttl: считаем от времени вставки вперёд, а не
            // от `now` назад, — иначе saturating_sub на малых `now` обнуляет
            // окно и первое же сообщение теряет свою запись.
            if at.saturating_add(self.ttl_ms) > now_ms {
                break;
            }
            self.order.pop_front();
            // Запись могла быть перезаписана более свежей — сверяем время.
            if self.seen.get(&id).copied() == Some(at) {
                self.seen.remove(&id);
            }
        }
    }

    fn evict_over_capacity(&mut self) {
        while self.order.len() > self.capacity {
            if let Some((id, at)) = self.order.pop_front() {
                if self.seen.get(&id).copied() == Some(at) {
                    self.seen.remove(&id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> MsgId {
        [n; 16]
    }

    #[test]
    fn a_forgotten_id_is_fresh_again_and_a_later_mark_survives_the_old_slot() {
        // Снятая отметка возвращает кадру право приехать; а запись
        // в порядке вытеснения, оставшаяся от старой отметки, не должна
        // снести новую при чистке по сроку.
        let mut w = DedupWindow::new(100, 8);
        assert!(w.check(id(1), 0).is_fresh());
        w.forget(&id(1));
        assert!(!w.contains(&id(1)));
        assert!(w.check(id(1), 50).is_fresh(), "после снятия — снова свежий");
        // Старая запись (время 0) выходит по сроку; новая (50) остаётся.
        w.purge(120);
        assert!(w.contains(&id(1)), "чистка по старому слоту не снесла новую отметку");
        assert!(!w.check(id(1), 121).is_fresh());
    }

    #[test]
    fn first_sighting_is_fresh_second_is_duplicate() {
        let mut w = DedupWindow::default();
        assert_eq!(w.check(id(1), 0), DedupVerdict::Fresh);
        assert_eq!(w.check(id(1), 1_000), DedupVerdict::Duplicate);
        assert_eq!(w.check(id(2), 1_000), DedupVerdict::Fresh);
    }

    #[test]
    fn different_transports_deliver_the_same_message_once() {
        // §5.4: почта ушла, потом контакт появился онлайн и прислал то же.
        let mut w = DedupWindow::default();
        let m = id(7);
        assert!(w.check(m, 0).is_fresh());
        assert!(!w.check(m, 45_000).is_fresh());
    }

    #[test]
    fn entries_expire_after_ttl() {
        let mut w = DedupWindow::new(1_000, 100);
        w.check(id(1), 0);
        assert!(w.contains(&id(1)));
        w.purge(1_001);
        assert!(!w.contains(&id(1)));
        assert_eq!(w.check(id(1), 1_001), DedupVerdict::Fresh);
    }

    #[test]
    fn capacity_bounds_memory_under_flood() {
        let mut w = DedupWindow::new(DEDUP_WINDOW_MS, 8);
        for n in 0..64u8 {
            w.check(id(n), u64::from(n));
        }
        assert!(w.len() <= 8, "окно должно быть ограничено, а не расти");
        assert!(w.contains(&id(63)), "самые свежие записи сохраняются");
        assert!(!w.contains(&id(0)), "самые старые вытесняются");
    }

    #[test]
    fn purge_is_idempotent() {
        let mut w = DedupWindow::new(1_000, 100);
        w.check(id(1), 0);
        w.purge(5_000);
        w.purge(5_000);
        assert!(w.is_empty());
    }
}
