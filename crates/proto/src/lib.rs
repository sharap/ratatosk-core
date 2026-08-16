//! Протокольная логика Ratatosk v0.1 без ввода-вывода.
//!
//! Крейт не открывает сокетов, не трогает диск и не читает часы. Всё время
//! приходит параметром `now_ms`, все байты — на входе и выходе. Из-за этого
//! каждый модуль здесь можно прогнать в детерминированной симуляции (§16)
//! и получить воспроизводимое по сиду поведение.
//!
//! | Модуль | Раздел спецификации |
//! |---|---|
//! | [`transport_policy`] | §5.4 выбор транспорта, запрет смешивать LAN и Tor |
//! | [`session`] | §7.3 маршрутизация приёма, §8.3 реестр сессий |
//! | [`fragment`] | §9.3 фрагментация и сборка с пределами |
//! | [`receipts`] | §9.4 квитанции только прямым каналом |
//! | [`group`] | §11 sender keys, состав, исключение |
//! | [`files`] | §10 файлы, чанки, превью |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod files;
pub mod fragment;
pub mod group;
pub mod receipts;
pub mod session;
pub mod transport_policy;

pub use fragment::Reassembler;
pub use group::{Group, GroupError, MAX_GROUP_MEMBERS};
pub use receipts::{DeliveryStatus, Receipt};
pub use session::{Route, SessionRegistry};
pub use transport_policy::{Attempt, Decision, PeerAvailability, Transport};
