//! Транспорты (§5).
//!
//! Здесь и только здесь живут сокеты, рантайм и всё, что зависит от реального
//! времени. Ядро (`ratatosk-core`) отдаёт сюда готовые кадры и получает
//! обратно события — оно не знает, что такое TCP.
//!
//! Три транспорта §5, четвёртый из 0.2 и шестой из 0.4:
//!
//! * [`lan`] — mDNS с ротируемым маяком, по умолчанию **выключен** (§5.1);
//! * [`bluetooth`] — объявление BLE и канал L2CAP, по умолчанию
//!   **выключен** (0.4);
//! * [`ygg`] — меш Yggdrasil поверх внешнего демона, по умолчанию
//!   **выключен** (0.2);
//! * [`onion`] — встроенный arti, onion-сервис v3 (§5.2);
//! * [`chatmail`] — SMTP/IMAP поверх SOCKS-прокси arti (§5.3).
//!
//! Работают они не по очереди, а вместе: [`multi::Transports`] сводит их
//! под одну ручку, потому что §5.4 — это лестница, а лестница из одной
//! ступени не лестница. Драйвер при этом по-прежнему держит один раннер.
//!
//! Транспорт под выключателем — [`switched::Switched`]. Он решает две
//! задачи сразу, и обе про время: bootstrap Tor идёт десятки секунд, а
//! открытие аккаунта обязано быть мгновенным (всё это время onion честно
//! отказывает); и человек вправе выключить Tor так, чтобы Tor выключился,
//! а не только выпал из лестницы §5.4.
//!
//! Кадрирование у прямых каналов общее и живёт в `link`: они отличаются
//! только тем, чем открыт поток, а две полосы записи (мелкие кадры вперёд
//! чанков) нужны всем — на onion даже сильнее, потому что мебибайт уходит
//! туда секундами, а не миллисекундами. Меш пользуется тем же `link`
//! и по той же причине: у него меняется лишь источник потока, и встроенный
//! узел (`ygg_stream`) заменит потом ровно его.
//!
//! Единственная внешняя инфраструктура — публичные chatmail-серверы (§1).
//! Своих мы не пишем и не держим.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bluetooth;
pub mod chatmail;
pub mod lan;
mod link;
pub mod multi;
#[cfg(feature = "nostr")]
pub mod nostr;
pub mod onion;
pub mod runner;
pub mod switched;
// TLS жил внутри `chatmail`, пока потребитель был один. Со ступенью nostr
// их стало двое, и общий модуль внутри одного из них означал бы, что реле
// тянет за собой почтовый признак сборки.
#[cfg(any(feature = "chatmail-net", feature = "nostr"))]
pub mod tls;
pub mod ygg;

pub use bluetooth::bridge::{BridgedAir, BtRadio};
#[cfg(all(feature = "bt", target_os = "linux"))]
pub use bluetooth::local::LocalAir;
pub use bluetooth::{Air, BtAddress, BtConfig, BtRunner};
pub use lan::{LanConfig, LanDirectory, LanRunner};
pub use multi::{Disabled, Transports};
pub use runner::{PeerAddress, Runner, TransportCommand, TransportError, TransportEvent};
pub use switched::Switched;
pub use ygg::{YggConfig, YggRunner, YGG_PORT};
