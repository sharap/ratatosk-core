//! Конверт сообщения (§9.1).
//!
//! ```cbor
//! Envelope = {
//!   1: uint,        ; protocol_version
//!   2: bytes,       ; msg_id, 16 байт, случайные
//!   3: { 1: uint, 2: uint },  ; hlc
//!   4: uint,        ; тип полезной нагрузки
//!   5: any,         ; полезная нагрузка
//!   6: ? bytes,     ; group_id
//!   7: ? [bytes],   ; causal_refs
//!   8: ? {1: bytes, 2: uint, 3: uint},  ; фрагмент
//! }
//! ```

use ciborium::value::Value;
use ratatosk_crdt::{Hlc, MsgId};

use crate::canonical::{self, Raw, KEY_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::error::{CodecError, Result};

const KEY_MSG_ID: u64 = 2;
const KEY_HLC: u64 = 3;
const KEY_PAYLOAD_TYPE: u64 = 4;
const KEY_PAYLOAD: u64 = 5;
const KEY_GROUP_ID: u64 = 6;
const KEY_CAUSAL_REFS: u64 = 7;
const KEY_FRAGMENT: u64 = 8;

const KEY_HLC_WALL: u64 = 1;
const KEY_HLC_LOGICAL: u64 = 2;

const KEY_FRAG_UID: u64 = 1;
const KEY_FRAG_INDEX: u64 = 2;
const KEY_FRAG_TOTAL: u64 = 3;

/// Предел числа фрагментов на сообщение (§9.3).
pub const MAX_FRAGMENTS: u64 = 4096;

/// Тип полезной нагрузки.
/// Открытость этого перечисления выражена вариантом [`PayloadType::Unknown`],
/// а не атрибутом `#[non_exhaustive]`: тип нагрузки приходит по сети от
/// клиента другой версии, и неизвестный код обязан быть **значением**, которое
/// код обрабатывает явно. Атрибут вместо этого лишь заставил бы писать `_`
/// и потерять проверку полноты по известным типам.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    /// Текстовое сообщение.
    Text,
    /// Метаданные файла: имя, размер, `file_key` (§10.1).
    FileOffer,
    /// Чанк файла (§10.2).
    FileChunk,
    /// Превью изображения, до 32 КиБ (§10.3).
    Preview,
    /// Квитанция о доставке или прочтении. Только прямым каналом (§9.4).
    Receipt,
    /// Блок состава группы (§11.2).
    GroupMembership,
    /// Распространение sender key (§11.1).
    SenderKey,
    /// Обновление контакт-карточки (§4.3).
    CardUpdate,
    /// Тип, не известный этой сборке.
    ///
    /// Сохраняется, а не отбрасывается: неизвестное поле не повод терять
    /// сообщение целиком.
    Unknown(u64),
}

impl PayloadType {
    /// Числовой код.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            PayloadType::Text => 1,
            PayloadType::FileOffer => 2,
            PayloadType::FileChunk => 3,
            PayloadType::Preview => 4,
            PayloadType::Receipt => 5,
            PayloadType::GroupMembership => 6,
            PayloadType::SenderKey => 7,
            PayloadType::CardUpdate => 8,
            PayloadType::Unknown(code) => code,
        }
    }

    /// Разбор кода.
    #[must_use]
    pub const fn from_code(code: u64) -> PayloadType {
        match code {
            1 => PayloadType::Text,
            2 => PayloadType::FileOffer,
            3 => PayloadType::FileChunk,
            4 => PayloadType::Preview,
            5 => PayloadType::Receipt,
            6 => PayloadType::GroupMembership,
            7 => PayloadType::SenderKey,
            8 => PayloadType::CardUpdate,
            other => PayloadType::Unknown(other),
        }
    }
}

/// Заголовок фрагмента (§9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    /// Идентификатор сборки.
    pub uid: [u8; 16],
    /// Номер фрагмента, с нуля.
    pub index: u64,
    /// Всего фрагментов.
    pub total: u64,
}

impl Fragment {
    /// Проверяет согласованность полей.
    pub fn validate(&self) -> Result<()> {
        if self.total == 0 || self.total > MAX_FRAGMENTS || self.index >= self.total {
            return Err(CodecError::TypeMismatch);
        }
        Ok(())
    }
}

/// Конверт сообщения.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// Случайный идентификатор, 16 байт. Основа дедупликации (§9.2).
    pub msg_id: MsgId,
    /// Гибридные логические часы — источник порядка (§9.1).
    pub hlc: Hlc,
    /// Тип полезной нагрузки.
    pub payload_type: PayloadType,
    /// Полезная нагрузка.
    pub payload: Value,
    /// Идентификатор группы, если сообщение групповое.
    pub group_id: Option<Vec<u8>>,
    /// `msg_id` непосредственных предшественников.
    ///
    /// Хранятся только для окна в 1000 последних сообщений; дальше —
    /// линейный порядок по HLC, ссылки отбрасываются (§12).
    pub causal_refs: Vec<MsgId>,
    /// Заголовок фрагмента, если сообщение разрезано.
    pub fragment: Option<Fragment>,
}

impl Envelope {
    /// Минимальный конверт.
    #[must_use]
    pub fn new(msg_id: MsgId, hlc: Hlc, payload_type: PayloadType, payload: Value) -> Envelope {
        Envelope {
            msg_id,
            hlc,
            payload_type,
            payload,
            group_id: None,
            causal_refs: Vec::new(),
            fragment: None,
        }
    }

    /// Кодирует в детерминированный CBOR.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut entries = vec![
            (Value::Integer(KEY_PROTOCOL_VERSION.into()), Value::Integer(PROTOCOL_VERSION.into())),
            (Value::Integer(KEY_MSG_ID.into()), Value::Bytes(self.msg_id.to_vec())),
            (
                Value::Integer(KEY_HLC.into()),
                Value::Map(vec![
                    (Value::Integer(KEY_HLC_WALL.into()), Value::Integer(self.hlc.wall_ms.into())),
                    (
                        Value::Integer(KEY_HLC_LOGICAL.into()),
                        Value::Integer(self.hlc.logical.into()),
                    ),
                ]),
            ),
            (
                Value::Integer(KEY_PAYLOAD_TYPE.into()),
                Value::Integer(self.payload_type.code().into()),
            ),
            (Value::Integer(KEY_PAYLOAD.into()), self.payload.clone()),
        ];

        if let Some(group_id) = &self.group_id {
            entries.push((Value::Integer(KEY_GROUP_ID.into()), Value::Bytes(group_id.clone())));
        }
        if !self.causal_refs.is_empty() {
            entries.push((
                Value::Integer(KEY_CAUSAL_REFS.into()),
                Value::Array(self.causal_refs.iter().map(|r| Value::Bytes(r.to_vec())).collect()),
            ));
        }
        if let Some(f) = &self.fragment {
            f.validate()?;
            entries.push((
                Value::Integer(KEY_FRAGMENT.into()),
                Value::Map(vec![
                    (Value::Integer(KEY_FRAG_UID.into()), Value::Bytes(f.uid.to_vec())),
                    (Value::Integer(KEY_FRAG_INDEX.into()), Value::Integer(f.index.into())),
                    (Value::Integer(KEY_FRAG_TOTAL.into()), Value::Integer(f.total.into())),
                ]),
            ));
        }

        canonical::encode(&Value::Map(entries))
    }

    /// Разбирает конверт, сохраняя принятые байты (§6).
    pub fn decode(bytes: &[u8]) -> Result<Raw<Envelope>> {
        let value = canonical::decode(bytes)?;
        let map = canonical::as_map(&value)?;
        canonical::check_version(map)?;

        let hlc_map = canonical::as_map(canonical::require(map, KEY_HLC)?)?;
        let logical = canonical::as_u64(canonical::require(hlc_map, KEY_HLC_LOGICAL)?)?;
        let hlc = Hlc::new(
            canonical::as_u64(canonical::require(hlc_map, KEY_HLC_WALL)?)?,
            u32::try_from(logical).map_err(|_| CodecError::TypeMismatch)?,
        );

        let causal_refs = match canonical::get(map, KEY_CAUSAL_REFS) {
            Some(Value::Array(items)) => {
                items.iter().map(canonical::as_array::<16>).collect::<Result<Vec<MsgId>>>()?
            }
            Some(_) => return Err(CodecError::TypeMismatch),
            None => Vec::new(),
        };

        let fragment = match canonical::get(map, KEY_FRAGMENT) {
            Some(v) => {
                let fm = canonical::as_map(v)?;
                let f = Fragment {
                    uid: canonical::as_array(canonical::require(fm, KEY_FRAG_UID)?)?,
                    index: canonical::as_u64(canonical::require(fm, KEY_FRAG_INDEX)?)?,
                    total: canonical::as_u64(canonical::require(fm, KEY_FRAG_TOTAL)?)?,
                };
                f.validate()?;
                Some(f)
            }
            None => None,
        };

        let envelope = Envelope {
            msg_id: canonical::as_array(canonical::require(map, KEY_MSG_ID)?)?,
            hlc,
            payload_type: PayloadType::from_code(canonical::as_u64(canonical::require(
                map,
                KEY_PAYLOAD_TYPE,
            )?)?),
            payload: canonical::require(map, KEY_PAYLOAD)?.clone(),
            group_id: match canonical::get(map, KEY_GROUP_ID) {
                Some(v) => Some(canonical::as_bytes(v)?.to_vec()),
                None => None,
            },
            causal_refs,
            fragment,
        };
        Ok(Raw::new(bytes.to_vec(), envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> Envelope {
        Envelope::new(
            [7u8; 16],
            Hlc::new(1_700_000_000_000, 3),
            PayloadType::Text,
            Value::Text("привет".into()),
        )
    }

    #[test]
    fn round_trip_minimal() {
        let bytes = envelope().encode().unwrap();
        assert_eq!(*Envelope::decode(&bytes).unwrap().value(), envelope());
    }

    #[test]
    fn round_trip_full() {
        let mut e = envelope();
        e.group_id = Some(vec![1, 2, 3]);
        e.causal_refs = vec![[1u8; 16], [2u8; 16]];
        e.fragment = Some(Fragment { uid: [9u8; 16], index: 0, total: 4 });

        let bytes = e.encode().unwrap();
        assert_eq!(*Envelope::decode(&bytes).unwrap().value(), e);
    }

    #[test]
    fn optional_fields_are_omitted_not_nulled() {
        // Пустые ключи в кадре — это лишние байты в каждом сообщении и лишний
        // разнобой в канонической форме.
        let bytes = envelope().encode().unwrap();
        let map = canonical::as_map(&canonical::decode(&bytes).unwrap()).unwrap().to_vec();
        assert!(canonical::get(&map, KEY_GROUP_ID).is_none());
        assert!(canonical::get(&map, KEY_FRAGMENT).is_none());
    }

    #[test]
    fn unknown_payload_type_survives() {
        let mut e = envelope();
        e.payload_type = PayloadType::Unknown(999);
        let bytes = e.encode().unwrap();
        assert_eq!(
            Envelope::decode(&bytes).unwrap().value().payload_type,
            PayloadType::Unknown(999)
        );
    }

    #[test]
    fn fragment_bounds_are_enforced() {
        assert!(Fragment { uid: [0u8; 16], index: 0, total: 0 }.validate().is_err());
        assert!(Fragment { uid: [0u8; 16], index: 4, total: 4 }.validate().is_err());
        assert!(Fragment { uid: [0u8; 16], index: 0, total: MAX_FRAGMENTS + 1 }
            .validate()
            .is_err());
        assert!(Fragment { uid: [0u8; 16], index: 0, total: MAX_FRAGMENTS }.validate().is_ok());
    }

    #[test]
    fn hlc_is_carried_exactly() {
        let e = envelope();
        let bytes = e.encode().unwrap();
        assert_eq!(Envelope::decode(&bytes).unwrap().value().hlc, e.hlc);
    }

    #[test]
    fn bytes_are_preserved_for_signing() {
        let bytes = envelope().encode().unwrap();
        assert_eq!(Envelope::decode(&bytes).unwrap().bytes(), &bytes[..]);
    }
}
