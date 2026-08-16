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

pub mod companion;
pub mod engine;
pub mod entropy;
pub mod honest;
pub mod io;
pub mod vault;

#[cfg(feature = "driver")]
pub mod driver;

pub use engine::{Contact, Engine, EngineError, SelfAddresses};
pub use entropy::{Entropy, OsEntropy, SeededEntropy};
pub use io::{ChatId, Command, Effect, Event, Input};
