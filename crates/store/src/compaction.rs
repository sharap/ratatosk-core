//! Compaction (§12).
//!
//! «Compaction — обязателен с первого дня. Иначе клиент перестанет
//! открываться на третий год.» Модуль задаёт, что и когда чистится; сами
//! запросы — в [`crate::sqlite`].
//!
//! Правила намеренно собраны в одном месте и покрыты тестами: забытая уборка
//! проявляется не багом, а медленной деградацией через год эксплуатации,
//! когда воспроизвести её на стенде уже нельзя.

/// Окно причинных ссылок — 1000 последних сообщений (§12).
///
/// Дальше — линейный порядок по HLC, ссылки отбрасываются.
pub const CAUSAL_REFS_WINDOW: u64 = 1_000;

/// Сколько живут надгробия удалённых сообщений — 90 суток (§12).
pub const TOMBSTONE_TTL_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// Раз во сколько сообщений группа фиксирует снапшот состава (§12).
pub const GROUP_SNAPSHOT_EVERY: u64 = 5_000;

/// TTL кэша пропущенных ключей — 30 суток (§8.4).
pub const SKIPPED_KEYS_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Предел кэша пропущенных ключей на устройство (§8.4).
pub const SKIPPED_KEYS_MAX_PER_DEVICE: u64 = 200_000;
/// Предел кэша пропущенных ключей на сессию (§8.4).
pub const SKIPPED_KEYS_MAX_PER_SESSION: u64 = 2_000;

/// TTL окна дедупликации — 30 суток (§9.2).
pub const DEDUP_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// TTL записей anti-replay рукопожатий — 30 суток (§8.3).
pub const HANDSHAKE_SEEN_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Ёмкость anti-replay кэша (§8.3).
pub const HANDSHAKE_SEEN_CAPACITY: u64 = 100_000;

/// Одна задача уборки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// Выбросить пропущенные ключи старше TTL и сверх пределов.
    SkippedKeys,
    /// Выбросить записи окна дедупликации старше TTL.
    Dedup,
    /// Выбросить записи anti-replay старше TTL и сверх ёмкости.
    HandshakeSeen,
    /// Схлопнуть надгробия старше 90 суток.
    Tombstones,
    /// Отбросить причинные ссылки за пределами окна.
    CausalRefs,
    /// Выбросить незавершённые сборки фрагментов с истёкшим TTL.
    Reassembly,
    /// Зафиксировать снапшот состава группы.
    GroupSnapshot,
}

impl Task {
    /// Все задачи. Порядок значим: сначала дешёвые, затем те, что переписывают
    /// строки, — так уборка отдаёт место раньше, чем начнёт нагружать диск.
    pub const ALL: [Task; 7] = [
        Task::Dedup,
        Task::HandshakeSeen,
        Task::SkippedKeys,
        Task::Reassembly,
        Task::CausalRefs,
        Task::Tombstones,
        Task::GroupSnapshot,
    ];
}

/// Расписание уборки.
///
/// Уборка запускается по событию, а не по таймеру: телефон значительную часть
/// времени спит (§13.1), и таймер там ничего не гарантирует.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// Каждые сколько обработанных сообщений запускать лёгкие задачи.
    pub every_messages: u64,
    /// Минимальный интервал между полными прогонами, мс.
    pub min_interval_ms: u64,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule { every_messages: 500, min_interval_ms: 6 * 60 * 60 * 1000 }
    }
}

impl Schedule {
    /// Пора ли запускать уборку.
    #[must_use]
    pub fn due(&self, messages_since: u64, last_run_ms: u64, now_ms: u64) -> bool {
        messages_since >= self.every_messages
            || now_ms.saturating_sub(last_run_ms) >= self.min_interval_ms
    }
}

/// Просрочена ли запись.
///
/// **Единственное определение границы во всём проекте.** До этой функции
/// правило было записано трижды — в `crdt::DedupWindow`, в in-memory
/// хранилище и в SQL, — и три записи разошлись ровно на один момент времени:
/// в возрасте, равном TTL, одни считали запись живой, другие мёртвой.
/// Для окна дедупликации (§9.2) это значит, что сообщение могло воскреснуть
/// на одном устройстве и не воскреснуть на другом.
///
/// Принято: запись живёт **ровно** `ttl_ms`; в момент, когда возраст
/// сравнялся с TTL, она уже просрочена.
#[must_use]
pub fn is_expired(created_ms: u64, now_ms: u64, ttl_ms: u64) -> bool {
    // Насыщение здесь — про часы, идущие назад: запись «из будущего»
    // не просрочена, а не просрочена бесконечно.
    now_ms.saturating_sub(created_ms) >= ttl_ms
}

/// Граница для SQL: записи с `created_ms <= cutoff` просрочены.
///
/// Возвращает «время рождения», а не «возраст», потому что запрос к БД
/// сравнивает хранимый столбец напрямую, без арифметики в SQL.
///
/// `None` означает, что просрочить ещё нечего: устройство работает меньше,
/// чем TTL. Прежняя версия возвращала здесь ноль через `saturating_sub`,
/// и это было не «безопасное умолчание», а ошибка — на свежей установке
/// под условие `created_ms <= 0` попадала любая запись с нулевой меткой.
#[must_use]
pub fn cutoff_ms(now_ms: u64, ttl_ms: u64) -> Option<u64> {
    now_ms.checked_sub(ttl_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tasks_are_listed() {
        assert_eq!(Task::ALL.len(), 7);
        // Дедупликация первая: она самая дешёвая и освобождает больше всего строк.
        assert_eq!(Task::ALL[0], Task::Dedup);
    }

    #[test]
    fn ttls_match_the_spec() {
        let day = 24 * 60 * 60 * 1000u64;
        assert_eq!(TOMBSTONE_TTL_MS, 90 * day);
        assert_eq!(SKIPPED_KEYS_TTL_MS, 30 * day);
        assert_eq!(DEDUP_TTL_MS, 30 * day);
        assert_eq!(HANDSHAKE_SEEN_TTL_MS, 30 * day);
    }

    #[test]
    fn limits_match_the_spec() {
        assert_eq!(CAUSAL_REFS_WINDOW, 1_000);
        assert_eq!(GROUP_SNAPSHOT_EVERY, 5_000);
        assert_eq!(SKIPPED_KEYS_MAX_PER_SESSION, 2_000);
        assert_eq!(SKIPPED_KEYS_MAX_PER_DEVICE, 200_000);
        assert_eq!(HANDSHAKE_SEEN_CAPACITY, 100_000);
    }

    #[test]
    fn schedule_fires_on_message_count() {
        let s = Schedule::default();
        assert!(!s.due(s.every_messages - 1, 0, 0));
        assert!(s.due(s.every_messages, 0, 0));
    }

    #[test]
    fn schedule_fires_on_elapsed_time() {
        let s = Schedule::default();
        assert!(!s.due(0, 0, s.min_interval_ms - 1));
        assert!(s.due(0, 0, s.min_interval_ms));
    }

    #[test]
    fn nothing_expires_before_the_ttl_has_elapsed() {
        // На свежей установке уборка не должна удалять ничего.
        assert_eq!(cutoff_ms(1_000, DEDUP_TTL_MS), None);
        assert!(!is_expired(0, 1_000, DEDUP_TTL_MS));
    }

    #[test]
    fn the_boundary_is_inclusive() {
        // Возраст, равный TTL, — уже просрочено. Это и есть то единственное
        // место, где три прежние реализации расходились.
        assert!(!is_expired(0, 999, 1_000));
        assert!(is_expired(0, 1_000, 1_000));
        assert!(is_expired(0, 1_001, 1_000));
    }

    #[test]
    fn records_from_the_future_are_not_expired() {
        // Часы могли уйти назад между запусками (§9.1 допускает это прямо).
        assert!(!is_expired(5_000, 1_000, 100));
    }

    #[test]
    fn sql_cutoff_agrees_with_is_expired() {
        // SQL не может вызвать Rust, поэтому граница там записана вторым
        // способом. Тест держит оба способа в согласии — иначе файловое
        // и in-memory хранилища снова разойдутся на границе.
        for ttl in [1u64, 2, 7, 1_000] {
            for now in 0..64u64 {
                for created in 0..64u64 {
                    let by_sql = match cutoff_ms(now, ttl) {
                        Some(cutoff) => created <= cutoff,
                        None => false,
                    };
                    assert_eq!(
                        by_sql,
                        is_expired(created, now, ttl),
                        "расхождение: создано {created}, сейчас {now}, ttl {ttl}"
                    );
                }
            }
        }
    }
}
