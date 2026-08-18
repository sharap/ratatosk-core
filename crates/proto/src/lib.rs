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
//! | [`avatar`] | аватарка профиля — **дополнение** к §4.2, в v0.1 не описано |
//! | [`retract`] | просьба удалить сообщение — **дополнение**, в v0.1 не описано |
//! | [`edit`] | правка отправленного — **дополнение**, в v0.1 не описано |
//! | [`reaction`] | реакция эмодзи — **дополнение**, в v0.1 не описано |
//! | [`forward`] | пересылка в другой чат — **дополнение**, в v0.1 не описано |
//! | [`reply`] | ответ на сообщение — **дополнение**, в v0.1 не описано |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod avatar;
pub mod edit;
pub mod files;
pub mod forward;
pub mod fragment;
pub mod group;
pub mod reaction;
pub mod receipts;
pub mod reply;
pub mod retract;
pub mod session;
pub mod transport_policy;

pub use avatar::{AvatarError, MAX_AVATAR_BYTES};
pub use edit::{EditError, MAX_EDIT_AGE_MS};
pub use forward::MAX_FORWARD_IDS;
pub use fragment::Reassembler;
pub use group::{Group, GroupError, MAX_GROUP_MEMBERS};
pub use reaction::{ReactionError, MAX_REACTION_BYTES};
pub use receipts::{DeliveryStatus, Receipt};
pub use reply::ReplyError;
pub use retract::MAX_RETRACT_IDS;
pub use session::{Route, SessionRegistry};
pub use transport_policy::{Attempt, Decision, PeerAvailability, Transport};
