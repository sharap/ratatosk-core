//! Ядро Ratatosk v0.1 (§13.3).
//!
//! «Rust, биндинги через UniFFI для Android, прямые вызовы на десктопе.
//! В ядре: крипта, протокол, транспорты, хранилище, синхронизация.
//! В клиентах — только UI и системная интеграция. Правило без исключений:
//! никакой протокольной логики выше UniFFI-границы.»
//!
//! [`Engine`] реализует это правило буквально: он принимает [`Input`],
//! возвращает [`Effect`] и не делает ничего сам. Клиенту остаётся показать
//! события и передать команды.
//!
//! Тексты из §14 живут в [`honest`] — там же и по той же причине: обещание,
//! которого протокол не даёт, придумывается именно в клиенте.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accounts;
pub mod companion;
pub mod engine;
pub mod entropy;
pub mod frames;
pub mod honest;
pub mod io;
pub mod reader;
pub mod vault;

#[cfg(feature = "driver")]
pub mod driver;

/// Среда вокруг терминала компаньона (§13.4).
///
/// За тем же признаком, что и [`driver`]: ей нужны и tokio, и транспорт,
/// а симуляция (§16) собирается без обоих.
#[cfg(feature = "driver")]
pub mod companion_driver;

pub use accounts::{
    tor_path_beside, write_onion_keystore, Account, AccountError, AccountId, Registry, TorLayout,
};
pub use companion::{
    Cache, ClientEffect, ClientEvent, ClientInput, CompanionClient, OutgoingItem, PairedDevice,
    DESKTOP_CACHE_CHATS, DESKTOP_CACHE_PER_CHAT, DESKTOP_CACHE_TTL_MS,
};
#[cfg(feature = "driver")]
pub use companion_driver::{
    CompanionCommand, CompanionDriver, CompanionEvent, CompanionEvents, CompanionHandle,
};
pub use engine::{Contact, Engine, EngineError, ExportScope, SelfAddresses, MAX_LOCAL_NAME_CHARS};
pub use entropy::{Entropy, OsEntropy, SeededEntropy};
pub use io::{
    ArchiveKey, ChatId, Command, Effect, Event, Exported, Input, Merged, OutgoingFile, Swept,
};
pub use reader::FileReader;
