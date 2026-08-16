//! Контакт-карточка и её обновление (§4).

use ciborium::value::Value;
use data_encoding::BASE32_NOPAD;

use crate::canonical::{self, Raw, KEY_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::error::{CodecError, Result};

/// Префикс URI контакт-карточки (§4.1).
pub const URI_PREFIX: &str = "ratatosk:v0:";

// Расхождение со спецификацией, разрешённое сознательно.
//
// §4.1 нумерует поля карточки с единицы, а §6 требует, чтобы `protocol_version`
// был первым ключом каждой структуры. Оба правила претендуют на ключ 1, и
// вместе они невыполнимы: карточка получала два ключа 1, а `require` находил
// первый попавшийся.
//
// Выбрана единообразная нумерация: `protocol_version` — ключ 1 везде без
// исключений, поля карточки сдвинуты на 2..8. Альтернатива (отдать
// `protocol_version` ключ 0 и сохранить нумерацию §4.1) формально тоже
// удовлетворяет «первому ключу», но заводит одну структуру, живущую по
// особому правилу, — а такие исключения потом стоят дороже.
//
// Решать это надо было сейчас: карточка едет в QR-кодах, и после первой
// выдачи ссылок нумерация становится вопросом совместимости.
const KEY_IK: u64 = 2;
const KEY_SK: u64 = 3;
const KEY_ONION: u64 = 4;
const KEY_CHATMAIL: u64 = 5;
const KEY_DISPLAY_NAME: u64 = 6;
const KEY_VERSION: u64 = 7;

/// Контакт-карточка (§4.1).
///
/// ```cbor
/// ContactCard = {
///   1: bytes,     ; IK, 32
///   2: bytes,     ; SK, 32
///   3: tstr,      ; onion-адрес
///   4: tstr,      ; chatmail-адрес
///   5: tstr,      ; отображаемое имя (не доверенное)
///   6: uint,      ; версия карточки
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCard {
    /// Статический ключ Noise.
    pub ik: [u8; 32],
    /// Ключ проверки подписи.
    pub sk: [u8; 32],
    /// Onion-адрес вида `xxxxx.onion`.
    pub onion: String,
    /// Chatmail-адрес.
    pub chatmail: String,
    /// Отображаемое имя.
    ///
    /// **Не доверенное** (§4.1): его выбирает владелец карточки, и UI обязан
    /// показывать рядом отпечаток или пометку «не проверен», а не одно имя.
    pub display_name: String,
    /// Монотонная версия карточки (§4.3).
    pub version: u64,
}

impl ContactCard {
    /// Кодирует в детерминированный CBOR.
    pub fn encode(&self) -> Result<Vec<u8>> {
        canonical::encode(&self.to_value())
    }

    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Integer(KEY_PROTOCOL_VERSION.into()), Value::Integer(PROTOCOL_VERSION.into())),
            (Value::Integer(KEY_IK.into()), Value::Bytes(self.ik.to_vec())),
            (Value::Integer(KEY_SK.into()), Value::Bytes(self.sk.to_vec())),
            (Value::Integer(KEY_ONION.into()), Value::Text(self.onion.clone())),
            (Value::Integer(KEY_CHATMAIL.into()), Value::Text(self.chatmail.clone())),
            (Value::Integer(KEY_DISPLAY_NAME.into()), Value::Text(self.display_name.clone())),
            (Value::Integer(KEY_VERSION.into()), Value::Integer(self.version.into())),
        ])
    }

    /// Разбирает из канонического CBOR, сохраняя принятые байты (§6).
    pub fn decode(bytes: &[u8]) -> Result<Raw<ContactCard>> {
        let value = canonical::decode(bytes)?;
        let map = canonical::as_map(&value)?;
        canonical::check_version(map)?;

        let card = ContactCard {
            ik: canonical::as_array(canonical::require(map, KEY_IK)?)?,
            sk: canonical::as_array(canonical::require(map, KEY_SK)?)?,
            onion: canonical::as_text(canonical::require(map, KEY_ONION)?)?.to_owned(),
            chatmail: canonical::as_text(canonical::require(map, KEY_CHATMAIL)?)?.to_owned(),
            display_name: canonical::as_text(canonical::require(map, KEY_DISPLAY_NAME)?)?
                .to_owned(),
            version: canonical::as_u64(canonical::require(map, KEY_VERSION)?)?,
        };
        Ok(Raw::new(bytes.to_vec(), card))
    }

    /// Кодирует в URI `ratatosk:v0:<base32(deterministic CBOR)>` (§4.1).
    ///
    /// Около 200 байт — в QR-код помещается свободно.
    pub fn to_uri(&self) -> Result<String> {
        Ok(format!("{URI_PREFIX}{}", BASE32_NOPAD.encode(&self.encode()?)))
    }

    /// Разбирает URI.
    pub fn from_uri(uri: &str) -> Result<Raw<ContactCard>> {
        let body = uri.strip_prefix(URI_PREFIX).ok_or(CodecError::BadContactUri)?;
        let bytes = BASE32_NOPAD.decode(body.as_bytes()).map_err(|_| CodecError::BadContactUri)?;
        ContactCard::decode(&bytes)
    }
}

/// Обновление адресов существующего контакта (§4.3).
///
/// Подписывается `SK`. Получатель принимает только строго большую версию.
/// Ключи `IK`/`SK` меняться не могут — это уже другая идентичность.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardUpdate {
    /// Новая карточка.
    pub card: ContactCard,
    /// Подпись `SK` над каноническими байтами карточки.
    pub signature: [u8; 64],
}

impl CardUpdate {
    /// Проверяет обновление против уже известной карточки.
    ///
    /// Проверка подписи здесь **не** выполняется: за неё отвечает
    /// `ratatosk-crypto`, и разнесение сделано специально, чтобы кодек не
    /// зависел от криптостека. Вызывающий обязан сделать оба шага.
    pub fn check_against(&self, known: &ContactCard) -> Result<()> {
        if self.card.ik != known.ik || self.card.sk != known.sk {
            return Err(CodecError::IdentityChanged);
        }
        if self.card.version <= known.version {
            return Err(CodecError::StaleCardVersion {
                got: self.card.version,
                known: known.version,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card() -> ContactCard {
        ContactCard {
            ik: [1u8; 32],
            sk: [2u8; 32],
            onion: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion".into(),
            chatmail: "a7f3k9@nine.example".into(),
            display_name: "Алиса".into(),
            version: 1,
        }
    }

    #[test]
    fn round_trip() {
        let bytes = card().encode().unwrap();
        assert_eq!(*ContactCard::decode(&bytes).unwrap().value(), card());
    }

    #[test]
    fn no_field_key_collides_with_protocol_version() {
        // Именно это столкновение и сломало разбор карточки: §4.1 и §6
        // оба претендовали на ключ 1. Проверка дешёвая и держит нумерацию
        // при добавлении новых полей.
        let keys = [KEY_IK, KEY_SK, KEY_ONION, KEY_CHATMAIL, KEY_DISPLAY_NAME, KEY_VERSION];
        for k in keys {
            assert_ne!(k, KEY_PROTOCOL_VERSION, "поле карточки заняло ключ protocol_version");
        }
        let mut sorted = keys;
        sorted.sort_unstable();
        sorted.windows(2).for_each(|w| assert_ne!(w[0], w[1], "два поля делят один ключ"));
    }

    #[test]
    fn uri_round_trip() {
        let uri = card().to_uri().unwrap();
        assert!(uri.starts_with(URI_PREFIX));
        assert_eq!(*ContactCard::from_uri(&uri).unwrap().value(), card());
    }

    #[test]
    fn card_fits_in_a_qr_code() {
        // §4.1: «Размер — около 200 байт, в QR помещается свободно.»
        // Проверяем не «около», а потолок, за которым QR становится плотным.
        assert!(card().encode().unwrap().len() < 400, "карточка разрослась");
    }

    #[test]
    fn decoded_bytes_are_preserved_for_signing() {
        let bytes = card().encode().unwrap();
        assert_eq!(ContactCard::decode(&bytes).unwrap().bytes(), &bytes[..]);
    }

    #[test]
    fn bad_uri_is_rejected() {
        assert!(matches!(
            ContactCard::from_uri("https://example.com"),
            Err(CodecError::BadContactUri)
        ));
        assert!(ContactCard::from_uri("ratatosk:v0:!!!!").is_err());
    }

    #[test]
    fn update_requires_strictly_greater_version() {
        let known = card();
        let mut newer = card();
        newer.version = 2;

        let ok = CardUpdate { card: newer, signature: [0u8; 64] };
        assert!(ok.check_against(&known).is_ok());

        let same = CardUpdate { card: card(), signature: [0u8; 64] };
        assert!(matches!(
            same.check_against(&known),
            Err(CodecError::StaleCardVersion { got: 1, known: 1 })
        ));
    }

    #[test]
    fn update_may_not_change_identity() {
        let known = card();
        let mut impostor = card();
        impostor.version = 2;
        impostor.ik = [9u8; 32];

        let update = CardUpdate { card: impostor, signature: [0u8; 64] };
        assert!(matches!(update.check_against(&known), Err(CodecError::IdentityChanged)));
    }

    #[test]
    fn update_may_change_addresses() {
        let known = card();
        let mut moved = card();
        moved.version = 2;
        moved.chatmail = "zz99@other.example".into();
        moved.onion = "newaddress.onion".into();

        assert!(CardUpdate { card: moved, signature: [0u8; 64] }.check_against(&known).is_ok());
    }
}
