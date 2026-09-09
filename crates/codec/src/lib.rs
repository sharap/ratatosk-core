//! Сериализация Ratatosk v0.1 (§4, §6, §9.1).
//!
//! Детерминированный CBOR (RFC 8949 §4.2) для всего: ключи по возрастанию,
//! минимальная длина, никаких неопределённых длин.
//!
//! Крейт намеренно не зависит от `ratatosk-crypto`: подписи он не проверяет,
//! а только сохраняет байты, над которыми их надо считать ([`canonical::Raw`]).
//! Разнесение не косметическое — оно позволяет фаззить разбор структур
//! (§16) без криптостека в дереве зависимостей.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canonical;
pub mod card;
pub mod envelope;
pub mod error;

pub use canonical::{Raw, PROTOCOL_VERSION};
// Полезная нагрузка конверта — это `ciborium::Value`, поэтому собрать
// конверт, не имея этого типа, нельзя. Реэкспорт избавляет остальные крейты
// от прямой зависимости на ciborium и заодно фиксирует, что версия у всех
// одна.
pub use card::{CardUpdate, ContactCard, URI_PREFIX, YGG_KEY_LEN};
pub use ciborium::value::Value;
pub use envelope::{Envelope, Fragment, PayloadType};
pub use error::{CodecError, Result};
