//! Режим компаньона: десктоп как терминал к телефону (§13.4).
//!
//! Телефон — единственный носитель идентичности и единственное хранилище
//! истории. Собственных `IK`/`SK`, собственного onion-адреса и собственного
//! chatmail-аккаунта у десктопа нет; для всех контактов существует **один**
//! пользователь.
//!
//! Это не функция протокола, а локальный RPC поверх уже построенных
//! механизмов — новых криптографических конструкций не вводится. Сопряжение
//! использует тот же Noise IK и тот же кадровый формат, что и контакты.
//!
//! Следствия, которые §13.4 требует принять и показать пользователю:
//!
//! * телефон офлайн или разряжен — десктоп не работает (§14, пункт 5);
//! * пока десктоп подключён, расход батареи телефона выше;
//! * компрометация десктопа даёт доступ к кэшу и возможность отправлять
//!   сообщения от имени пользователя до отзыва сопряжения. Ключи при этом
//!   не утекают.

/// Предел кэша на десктопе — 1000 последних сообщений на чат (§13.4).
pub const DESKTOP_CACHE_PER_CHAT: usize = 1_000;

/// Через сколько без подключения кэш десктопа стирается — 30 суток (§13.4).
pub const DESKTOP_CACHE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Что разрешено пересекать границу устройства (§13.4).
///
/// «Ключевой материал контактов, `IK`, `SK` и `db_key` границу устройства
/// не пересекают никогда.» Перечисление существует, чтобы это правило было
/// проверяемым в коде, а не только в тексте.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crossing {
    /// Список чатов.
    ChatList,
    /// Расшифрованные сообщения.
    DecryptedMessages,
    /// Статусы доставки.
    Statuses,
    /// Команды на отправку.
    SendCommands,
}

impl Crossing {
    /// Всё, что разрешено передавать десктопу.
    pub const ALLOWED: [Crossing; 4] = [
        Crossing::ChatList,
        Crossing::DecryptedMessages,
        Crossing::Statuses,
        Crossing::SendCommands,
    ];
}

/// Сопряжённое устройство.
#[derive(Debug, Clone)]
pub struct PairedDevice {
    /// Идентификатор записи.
    pub device_id: [u8; 16],
    /// Метка для списка на телефоне.
    pub label: String,
    /// Когда сопряжено, мс.
    pub paired_ms: u64,
    /// Когда последний раз подключалось, мс.
    pub last_seen_ms: u64,
}

impl PairedDevice {
    /// Пора ли стереть кэш на десктопе (§13.4).
    #[must_use]
    pub fn cache_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms) >= DESKTOP_CACHE_TTL_MS
    }
}

/// Отзыв сопряжения (§13.4).
///
/// «Отзыв — удаление записи и **немедленный** разрыв сессии.» Отложенный
/// разрыв означал бы окно, в котором отозванный десктоп продолжает отправлять
/// сообщения от имени пользователя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    /// Какое устройство.
    pub device_id: [u8; 16],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_application_level_data_crosses_the_boundary() {
        // §13.4: через канал идут только уже расшифрованные прикладные
        // события. Тест держит перечисление закрытым — добавить в него
        // ключевой материал нельзя, не сломав эту проверку сознательно.
        assert_eq!(Crossing::ALLOWED.len(), 4);
        for c in Crossing::ALLOWED {
            assert!(matches!(
                c,
                Crossing::ChatList
                    | Crossing::DecryptedMessages
                    | Crossing::Statuses
                    | Crossing::SendCommands
            ));
        }
    }

    #[test]
    fn cache_expires_after_thirty_days() {
        let d = PairedDevice {
            device_id: [0u8; 16],
            label: "ноутбук".into(),
            paired_ms: 0,
            last_seen_ms: 0,
        };
        assert!(!d.cache_expired(DESKTOP_CACHE_TTL_MS - 1));
        assert!(d.cache_expired(DESKTOP_CACHE_TTL_MS));
    }

    #[test]
    fn cache_limit_matches_spec() {
        assert_eq!(DESKTOP_CACHE_PER_CHAT, 1_000);
    }
}
