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
//! | [`card_update`] | §4.3 обновление адресов, подписанное `SK` |
//! | [`session`] | §7.3 маршрутизация приёма, §8.3 реестр сессий |
//! | [`fragment`] | §9.3 фрагментация и сборка с пределами |
//! | [`receipts`] | §9.4 квитанции только прямым каналом |
//! | [`group`] | §11 sender keys, состав, исключение |
//! | [`files`] | §10 файлы, чанки, превью |
//! | [`mail`] | §5.3 настройки почтового ящика — и почта **без** Tor |
//! | [`avatar`] | аватарка профиля — **дополнение** к §4.2, в v0.1 не описано |
//! | [`retract`] | просьба удалить сообщение — **дополнение**, в v0.1 не описано |
//! | [`edit`] | правка отправленного — **дополнение**, в v0.1 не описано |
//! | [`reaction`] | реакция эмодзи — **дополнение**, в v0.1 не описано |
//! | [`forward`] | пересылка в другой чат — **дополнение**, в v0.1 не описано |
//! | [`reply`] | ответ на сообщение — **дополнение**, в v0.1 не описано |
//! | [`ygg`] | адрес в меше из открытого ключа — **0.2**, в v0.1 не описано |
//! | [`nostr`] | ступень поверх реле nostr — **0.3**, в v0.1 не описано |
//! | [`bluetooth`] | объявление BLE шестой ступени — **0.4**, в v0.1 не описано |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// Настройка уведомлений чата: чем ядро отвечает на «молчать ли здесь».
///
/// Живёт в протоколе, а не в клиенте, по правилу §13.3: срок молчания
/// **истекает**, и решение «молчим ли сейчас» — счёт, а не показ.
/// Сделай его клиент — у одного факта стало бы два источника, и часовые
/// пояса развели бы их в первый же вечер.
pub mod notify;

pub mod avatar;
pub mod bluetooth;
pub mod card_update;
pub mod channel;
pub mod companion;
pub mod contact_share;
pub mod edit;
pub mod files;
pub mod forward;
pub mod fragment;
pub mod group;
pub mod group_action;
pub mod mail;
pub mod nostr;
pub mod reaction;
pub mod receipts;
pub mod reply;
pub mod retract;
pub mod session;
pub mod swarm;
pub mod transport_policy;
pub mod ygg;

pub use avatar::{AvatarError, MAX_AVATAR_BYTES};
pub use card_update::UpdateError;
pub use edit::{EditError, MAX_EDIT_AGE_MS};
pub use forward::MAX_FORWARD_IDS;
pub use fragment::Reassembler;
pub use group::{
    Group, GroupError, GroupMessage, Intro, LeaveConsequences, Roster, JOIN_DISCLOSURE,
    MAX_GROUP_MEMBERS,
};
pub use group_action::{Action, ActionError};
pub use reaction::{ReactionError, MAX_REACTION_BYTES};
pub use receipts::{DeliveryStatus, Receipt};
pub use reply::ReplyError;
pub use retract::MAX_RETRACT_IDS;
pub use session::{Route, SessionRegistry};
// Классы размера живут в `wire` — там же, где кадр. Реэкспорт нужен тем, кто
// зависит от протокола, но не от провода: без него стенду пришлось бы либо
// тянуть лишний крейт, либо завести **вторую** арифметику размеров кадра,
// расходящуюся с настоящей молча.
pub use ratatosk_wire::SizeClass;
pub use transport_policy::{
    Attempt, Decision, PeerAvailability, Reachability, Rung, Transport, TransportSet,
};
