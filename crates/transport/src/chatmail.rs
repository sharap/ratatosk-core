//! Почта chatmail поверх Tor (§5.3).
//!
//! Почта используется как **тупая труба для наших же запечатанных кадров**.
//! OpenPGP, Autocrypt и любые почтовые схемы шифрования не применяются —
//! криптостек в системе один.
//!
//! Что видит сервер, и это надо сказать пользователю (§2.2, §14 пункт 2):
//! содержимого и IP он не видит, но видит, какие адреса переписываются между
//! собой, когда и какого размера. Это цена асинхронной доставки без своей
//! инфраструктуры.

/// Фиксированная тема письма (§5.3).
///
/// Одна и та же для всех: тема — открытый заголовок, и любая переменная часть
/// в ней стала бы метаданными для сервера.
pub const SUBJECT: &str = "Ratatosk";

/// MIME-тип тела (§5.3).
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Предел размера письма (§5.3).
pub const MAX_MESSAGE_BYTES: u64 = 20_000_000;

/// Длина случайной локальной части адреса (§5.3).
pub const LOCAL_PART_LEN: std::ops::RangeInclusive<usize> = 6..=8;

/// Учётная запись на chatmail-сервере.
///
/// Создаётся автоматически при первом запуске: эти серверы допускают
/// регистрацию без персональных данных. Адрес — случайные 6–8 символов,
/// никак не связанные с личностью (§5.3).
pub struct ChatmailAccount {
    /// Адрес вида `a7f3k9@nine.example`.
    pub address: String,
}

impl ChatmailAccount {
    /// Регистрирует новую учётную запись на выбранном сервере.
    ///
    /// Пользователь может указать любой сервер, включая собственный (§1).
    ///
    /// TODO(этап 3): регистрация через SMTP/IMAP поверх SOCKS arti.
    pub async fn register(
        _server: &str,
        _socks: std::net::SocketAddr,
    ) -> Result<ChatmailAccount, crate::TransportError> {
        todo!("этап 3: регистрация на chatmail-сервере (§5.3)")
    }
}

/// Отправка через SMTP поверх SOCKS-прокси arti.
///
/// TODO(этап 3): собрать письмо с фиксированной темой, телом в base64 и
/// минимальным набором заголовков. Никакой информации в заголовки не
/// выносится (§5.3).
pub async fn send(
    _account: &ChatmailAccount,
    _to: &str,
    _frames: &[Vec<u8>],
) -> Result<(), crate::TransportError> {
    todo!("этап 3: отправка SMTP через SOCKS (§5.3)")
}

/// Приём через IMAP IDLE.
///
/// При разрыве — переподключение с экспоненциальным backoff (§13.1).
///
/// TODO(этап 3): IDLE-цикл, разбор тела, выдача кадров в ядро.
pub async fn poll(_account: &ChatmailAccount) -> Result<Vec<Vec<u8>>, crate::TransportError> {
    todo!("этап 3: IMAP IDLE через SOCKS (§5.3)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_is_constant() {
        // Переменная тема была бы метаданными в открытом виде.
        assert_eq!(SUBJECT, "Ratatosk");
    }

    #[test]
    fn message_limit_matches_file_limit() {
        assert_eq!(MAX_MESSAGE_BYTES, ratatosk_proto::files::MAIL_FILE_LIMIT_BYTES);
    }
}
