//! Транспорты (§5).
//!
//! Здесь и только здесь живут сокеты, рантайм и всё, что зависит от реального
//! времени. Ядро (`ratatosk-core`) отдаёт сюда готовые кадры и получает
//! обратно события — оно не знает, что такое TCP.
//!
//! Три транспорта, ровно как в §5:
//!
//! * [`lan`] — mDNS с ротируемым маяком, по умолчанию **выключен** (§5.1);
//! * [`onion`] — встроенный arti, onion-сервис v3 (§5.2);
//! * [`chatmail`] — SMTP/IMAP поверх SOCKS-прокси arti (§5.3).
//!
//! Единственная внешняя инфраструктура — публичные chatmail-серверы (§1).
//! Своих мы не пишем и не держим.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chatmail;
pub mod lan;
pub mod onion;
pub mod runner;

pub use lan::{LanConfig, LanDirectory, LanRunner};
pub use runner::{PeerAddress, Runner, TransportCommand, TransportError, TransportEvent};
