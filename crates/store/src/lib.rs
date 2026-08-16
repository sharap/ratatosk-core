//! Локальное хранилище (§12).
//!
//! SQLite (`rusqlite`) + FTS5 для поиска. Чувствительные поля шифруются
//! на уровне приложения ключом `db_key`; метаданные схемы остаются открытыми.
//!
//! Хранилище синхронное и это осознанно: SQLite синхронен по природе, а ядро
//! (§13.3) построено как sans-io — недетерминизм в нём допускается только
//! от сети, но не от диска. Поэтому [`Store`] — обычный трейт с блокирующими
//! методами, а не async.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod compaction;
pub mod memory;
pub mod schema;
pub mod sql_types;
pub mod sqlite;

use ratatosk_crdt::{Hlc, MsgId};

/// Ключ в служебной таблице: зерно собственной идентичности, запечатанное
/// `db_key` (§3, §8.6).
pub const META_IDENTITY_SEED: &str = "identity_seed";

/// Ключ в служебной таблице: соль для вывода `db_key` из PIN (§8.6).
///
/// Хранится открыто — это штатный режим соли, её секретность не требуется.
pub const META_DB_SALT: &str = "db_salt";

pub use compaction::{Schedule, Task};
pub use memory::MemoryStore;
pub use schema::SCHEMA_VERSION;
pub use sqlite::SqliteStore;

/// Отказ хранилища.
///
/// Ошибка нарочно **не** упоминает SQLite. Трейт [`Store`] имеет две
/// реализации — файловую и in-memory для симуляции (§16), и тип ошибки,
/// содержащий `rusqlite::Error`, заставлял бы вторую тянуть первую вместе
/// со всем C-кодом. Конкретная причина приходит строкой от бэкенда.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Ошибка нижележащего хранилища.
    #[error("ошибка хранилища: {0}")]
    Backend(String),

    /// Операция не поддерживается этой реализацией.
    ///
    /// In-memory хранилище не умеет, например, экспорт архива (§12), и должно
    /// сказать об этом прямо, а не сделать вид, что всё получилось.
    #[error("операция не поддерживается этим хранилищем: {0}")]
    Unsupported(&'static str),
    /// Схема новее, чем понимает эта сборка.
    #[error("схема версии {found} новее поддерживаемой {supported}")]
    FutureSchema {
        /// Версия в файле.
        found: u32,
        /// Версия сборки.
        supported: u32,
    },
    /// БД зашифрована, а ключ не предоставлен (§8.6).
    #[error("база заблокирована")]
    Locked,
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

/// Результат операции хранилища.
pub type Result<T> = core::result::Result<T, StoreError>;

/// Сообщение в том виде, в каком оно лежит на диске.
#[derive(Debug, Clone)]
pub struct StoredMessage {
    /// Идентификатор.
    pub msg_id: MsgId,
    /// Чат.
    pub chat_id: [u8; 16],
    /// Отправитель.
    pub sender_ik: [u8; 32],
    /// Метка порядка (§9.1).
    pub hlc: Hlc,
    /// Расшифрованное тело.
    pub body: Vec<u8>,
    /// Момент приёма, мс.
    pub received_ms: u64,
}

/// Контакт в том виде, в каком он лежит на диске (§4).
///
/// Поля продублированы рядом с `card_bytes` не от лени: §6 требует считать
/// подпись над **принятыми** байтами, поэтому карточка обязана храниться
/// целиком и неизменной. Разобранные поля рядом — чтобы список контактов
/// открывался запросом, а не разбором CBOR у каждой строки.
#[derive(Debug, Clone)]
pub struct StoredContact {
    /// Статический ключ Noise.
    pub ik: [u8; 32],
    /// Ключ подписи.
    pub sk: [u8; 32],
    /// Onion-адрес (§5.2). Пустая строка — адреса нет.
    pub onion: String,
    /// Chatmail-адрес (§5.3). Пустая строка — адреса нет.
    pub chatmail: String,
    /// Отображаемое имя. Получателем не доверяется (§4.1).
    pub display_name: String,
    /// Версия карточки, монотонная (§4.3).
    pub card_version: u64,
    /// Принятые байты карточки — то, над чем считается подпись (§6).
    pub card_bytes: Vec<u8>,
    /// Отпечаток сверен голосом (§4.2).
    pub verified: bool,
    /// Момент добавления, мс.
    pub created_ms: u64,
}

/// Интерфейс хранилища.
///
/// Трейт, а не конкретный тип, — ради двух вещей: подмены на in-memory
/// реализацию в симуляции (§16) и возможности прогнать одни и те же
/// сценарии против обеих.
pub trait Store {
    /// Открывает или создаёт БД, применяя миграции.
    fn migrate(&mut self) -> Result<()>;

    /// Записывает сообщение.
    fn put_message(&mut self, message: &StoredMessage) -> Result<()>;

    /// Записывает контакт, заменяя прежнюю запись с тем же `ik`.
    fn put_contact(&mut self, contact: &StoredContact) -> Result<()>;

    /// Читает все контакты.
    fn contacts(&self) -> Result<Vec<StoredContact>>;

    /// Читает служебное значение.
    ///
    /// Здесь живёт то, что не является ни сообщением, ни контактом:
    /// зерно собственной идентичности (§3), соль для `db_key` (§8.6),
    /// состояние гибридных часов (§9.1).
    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Пишет служебное значение.
    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<()>;

    /// Читает окно сообщений чата в порядке HLC (§9.1).
    fn messages(
        &self,
        chat_id: &[u8; 16],
        limit: usize,
        before: Option<Hlc>,
    ) -> Result<Vec<StoredMessage>>;

    /// Отмечает `msg_id` как виденный. Возвращает `false`, если уже видели (§9.2).
    fn note_seen(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool>;

    /// Выполняет одну задачу уборки (§12).
    fn compact(&mut self, task: Task, now_ms: u64) -> Result<u64>;

    /// Выгружает переписку в зашифрованный архив (§12).
    ///
    /// Единственный путь переноса истории на другое устройство в v1.
    fn export(&self, destination: &std::path::Path) -> Result<()>;
}
