//! Контакт-карточка и её обновление (§4).

use ciborium::value::Value;
use data_encoding::BASE32_NOPAD;

use crate::canonical::{self, Raw, KEY_PROTOCOL_VERSION, PROTOCOL_VERSION};
use crate::error::{CodecError, Result};

/// Префикс URI контакт-карточки (§4.1).
pub const URI_PREFIX: &str = "ratatosk:v0:";

/// Длина открытого ключа Yggdrasil — ed25519, тридцать два байта.
pub const YGG_KEY_LEN: usize = 32;

/// Сколько реле объявляется в карточке (0.3).
///
/// Три. Карточка едет в QR, который человек наводит камерой в плохом свете,
/// и каждый лишний адрес — это плотность кода. Три реле уже делят граф
/// между тремя чужими хозяйствами; четвёртое прибавляет к приватности мало.
///
/// Названных человеком реле может быть больше: с них мы **читаем**. В карточке
/// объявляются первые три — то есть те, куда собеседник будет класть события.
pub const MAX_CARD_RELAYS: usize = 3;

/// Длина открытого ключа nostr — x-only secp256k1, тридцать два байта.
///
/// Столько же, сколько у соседа, и это совпадение, а не общность: кривая
/// другая. Отдельная константа именно поэтому — общая однажды позволила бы
/// принять ключ одной сети за ключ другой, и разбор не заметил бы ничего.
pub const NOSTR_KEY_LEN: usize = 32;

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
/// Открытый ключ узла Yggdrasil, 32 байта (0.2).
///
/// Ключ **необязателен и на записи, и на чтении**, и оба конца этого
/// правила нужны. На чтении — потому что карточки, выданные до 0.2, ключа
/// не несут, а отвергать их значило бы разорвать все прежние знакомства
/// разом. На записи — потому что канонический CBOR обязан совпадать
/// до байта: припиши мы пустой ключ, разобранная и заново собранная старая
/// карточка перестала бы совпадать с подписанными байтами (§6).
const KEY_YGG: u64 = 8;
/// Открытый ключ nostr, 32 байта (0.3).
///
/// Необязателен на обоих концах, ровно как [`KEY_YGG`], и по тем же двум
/// причинам: карточки, выданные раньше, ключа не несут, а приписанный
/// пустой ключ разошёлся бы с подписанными байтами (§6).
///
/// Девятка, а не «следующая после адреса»: ключи карточки нумеруются
/// по порядку появления полей, а не по месту на лестнице §5.4. Nostr стоит
/// между onion и почтой, но пришёл позже всех — и номер получает последний
/// свободный. Иначе первое же добавление ступени в середину лестницы
/// переставило бы ключи в уже выданных QR-кодах.
const KEY_NOSTR: u64 = 9;
/// Реле, на которых владелец карточки **читает** (0.3).
///
/// Необязателен, как и два соседних ключа, и по тем же причинам.
const KEY_NOSTR_RELAYS: u64 = 10;

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
///   7: bytes,     ; открытый ключ Yggdrasil, 32 байта — необязательный
///   8: bytes,     ; открытый ключ nostr, 32 байта — необязательный
///   9: [tstr],    ; реле, на которых он читает — необязательный, до трёх
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
    /// Открытый ключ узла Yggdrasil (0.2). Пусто — меша у контакта нет.
    ///
    /// **Ключ, а не адрес**, и это одно поле на два способа связи: встроенный
    /// узел соединяется по ключу напрямую, внешнему демону адрес `200::/7`
    /// выводится из того же ключа. Лестница §5.4 разницы не видит.
    ///
    /// Отдельная пара ключей, а не [`ContactCard::sk`], и это не запас
    /// на будущее. Ключ подписи — долговременное имя человека; сделай мы его
    /// же именем в меше, каждый узел, через который идёт трафик, связывал бы
    /// сетевую активность с этой личностью. Разные роли — разные ключи.
    ///
    /// `Vec`, а не `[u8; 32]`: пусто значит «нет», и отдельного признака
    /// для этого не заводится. Ключ неверной длины разбором **отбрасывается**,
    /// а не роняет карточку целиком — как и картинка в `group::Intro`:
    /// поле, без которого всё остальное работает, не имеет права уносить
    /// с собой знакомство.
    pub ygg: Vec<u8>,
    /// Открытый ключ nostr (0.3). Пусто — ступени у контакта нет.
    ///
    /// Третья пара ключей в карточке, и заводится она по той же причине,
    /// что и ключ меша: разные роли — разные ключи. Ключ nostr к тому же
    /// живёт на **другой кривой** (secp256k1 против ed25519 у подписи),
    /// так что вывести его из `sk` было бы нельзя, даже захоти мы этого.
    ///
    /// Он виден каждому реле, через которое идёт событие, и связывает
    /// между собой все разговоры владельца — ровно как chatmail-адрес
    /// у почты (§2.2). Поэтому ступень выключена по умолчанию, а ключ
    /// в карточке появляется только у того, кто её включил.
    ///
    /// `Vec`, а не `[u8; 32]`, и ключ неверной длины разбором
    /// **отбрасывается**, — всё как у [`ContactCard::ygg`]: поле,
    /// без которого остальное работает, не имеет права уносить с собой
    /// знакомство.
    pub nostr: Vec<u8>,
    /// Реле, на которых владелец карточки **читает** (0.3).
    ///
    /// # Зачем это в карточке
    ///
    /// Затем, что иначе доставка держится на совпадении: отправитель кладёт
    /// событие на свои реле, получатель читает со своих, и не пересекись
    /// они — доставки нет, причём **молча**. На стенде, где реле у обоих
    /// одно и то же, эта дыра не видна вовсе; у двух разных людей она
    /// открывается сразу.
    ///
    /// Отсюда и направление: здесь названы реле **получателя**, и отправитель
    /// кладёт событие именно туда. Свои реле нужны для приёма, чужие —
    /// для отправки, и путать их нельзя.
    ///
    /// Нести этот список чем-то помимо карточки нечем. Прочитать его
    /// у самого nostr (NIP-65) можно только с реле, которое у нас с ним
    /// уже общее, — то есть ответ требует того, что и является вопросом.
    /// Карточка же и так бутстрапит всё остальное: onion, ключ меша, почту.
    ///
    /// # Почему не больше трёх
    ///
    /// Карточка едет в QR, который человек наводит камерой в плохом свете.
    /// Три реле уже делят граф между тремя чужими хозяйствами; четвёртое
    /// прибавляет к приватности мало, а к плотности кода — заметно.
    /// Больше трёх названных читаются, но в карточке не объявляются
    /// ([`MAX_CARD_RELAYS`]).
    ///
    /// Пустой список не пишется вовсе — как и два соседних ключа: карточка
    /// без реле обязана кодироваться теми же байтами, что и раньше.
    pub nostr_relays: Vec<String>,
}

impl ContactCard {
    /// Кодирует в детерминированный CBOR.
    pub fn encode(&self) -> Result<Vec<u8>> {
        canonical::encode(&self.to_value())
    }

    fn to_value(&self) -> Value {
        let mut fields = vec![
            (Value::Integer(KEY_PROTOCOL_VERSION.into()), Value::Integer(PROTOCOL_VERSION.into())),
            (Value::Integer(KEY_IK.into()), Value::Bytes(self.ik.to_vec())),
            (Value::Integer(KEY_SK.into()), Value::Bytes(self.sk.to_vec())),
            (Value::Integer(KEY_ONION.into()), Value::Text(self.onion.clone())),
            (Value::Integer(KEY_CHATMAIL.into()), Value::Text(self.chatmail.clone())),
            (Value::Integer(KEY_DISPLAY_NAME.into()), Value::Text(self.display_name.clone())),
            (Value::Integer(KEY_VERSION.into()), Value::Integer(self.version.into())),
        ];
        // Пустой ключ не пишется вовсе — см. `KEY_YGG`. Карточка без меша
        // обязана кодироваться теми же байтами, что и до 0.2.
        if !self.ygg.is_empty() {
            fields.push((Value::Integer(KEY_YGG.into()), Value::Bytes(self.ygg.clone())));
        }
        if !self.nostr.is_empty() {
            fields.push((Value::Integer(KEY_NOSTR.into()), Value::Bytes(self.nostr.clone())));
        }
        if !self.nostr_relays.is_empty() {
            let items = self
                .nostr_relays
                .iter()
                .take(MAX_CARD_RELAYS)
                .map(|url| Value::Text(url.clone()))
                .collect();
            fields.push((Value::Integer(KEY_NOSTR_RELAYS.into()), Value::Array(items)));
        }
        Value::Map(fields)
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
            // Нет ключа — нет меша. Есть, но не 32 байта — тоже нет: чужая
            // длина означает либо порчу, либо формат, которого мы не знаем,
            // и в обоих случаях соединяться по этим байтам не с кем.
            // Отказывать всей карточке из-за этого нельзя: подпись §6
            // проверяется по принятым байтам и остаётся верной, а знакомство
            // не должно ломаться из-за поля, которого раньше не было.
            ygg: match canonical::get(map, KEY_YGG) {
                Some(value) => match canonical::as_bytes(value) {
                    Ok(bytes) if bytes.len() == YGG_KEY_LEN => bytes.to_vec(),
                    _ => Vec::new(),
                },
                None => Vec::new(),
            },
            // Список читается снисходительно: лишнее отбрасывается, чужие
            // типы пропускаются. Ронять из-за него карточку нельзя —
            // знакомство не должно ломаться из-за поля, которого раньше
            // не было.
            nostr_relays: match canonical::get(map, KEY_NOSTR_RELAYS) {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(|item| canonical::as_text(item).ok().map(str::to_owned))
                    .take(MAX_CARD_RELAYS)
                    .collect(),
                _ => Vec::new(),
            },
            // То же правило и по той же причине — см. `KEY_NOSTR`.
            nostr: match canonical::get(map, KEY_NOSTR) {
                Some(value) => match canonical::as_bytes(value) {
                    Ok(bytes) if bytes.len() == NOSTR_KEY_LEN => bytes.to_vec(),
                    _ => Vec::new(),
                },
                None => Vec::new(),
            },
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
            ygg: Vec::new(),
            nostr: Vec::new(),
            nostr_relays: Vec::new(),
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
        let keys = [
            KEY_IK,
            KEY_SK,
            KEY_ONION,
            KEY_CHATMAIL,
            KEY_DISPLAY_NAME,
            KEY_VERSION,
            KEY_YGG,
            KEY_NOSTR,
            KEY_NOSTR_RELAYS,
        ];
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

    #[test]
    fn a_card_without_nostr_encodes_exactly_as_before() {
        // Ключевое свойство необязательного поля: припиши мы пустой ключ,
        // старая карточка перестала бы совпадать со своими подписанными
        // байтами (§6) — то есть каждое прежнее знакомство разом стало бы
        // «подпись не сходится».
        let bytes = card().encode().unwrap();
        let back = ContactCard::decode(&bytes).unwrap().into_parts().1;
        assert!(back.nostr.is_empty(), "пустой ключ не должен появляться из ниоткуда");
        assert_eq!(back.encode().unwrap(), bytes, "байты обязаны совпасть до одного");
    }

    #[test]
    fn a_nostr_key_survives_the_round_trip() {
        let mut with_key = card();
        with_key.nostr = vec![0x5a; NOSTR_KEY_LEN];
        let bytes = with_key.encode().unwrap();
        assert_eq!(*ContactCard::decode(&bytes).unwrap().value(), with_key);
        // И карточка с двумя новыми ключами всё ещё влезает в QR.
        with_key.ygg = vec![0x11; YGG_KEY_LEN];
        assert!(with_key.encode().unwrap().len() < 400, "карточка разрослась");
    }

    #[test]
    fn a_nostr_key_of_the_wrong_length_is_dropped_not_fatal() {
        // Поле, которого раньше не было, не имеет права уносить с собой
        // знакомство: подпись §6 считается по принятым байтам и остаётся
        // верной, а ключ чужой длины означает порчу либо формат, которого
        // мы не знаем, — и в обоих случаях отправлять по нему нечего.
        let mut odd = card();
        odd.nostr = vec![0x5a; NOSTR_KEY_LEN - 1];
        let bytes = odd.encode().unwrap();
        let back = ContactCard::decode(&bytes).expect("карточка обязана разобраться");
        assert!(back.value().nostr.is_empty(), "ключ отброшен");
        assert_eq!(back.value().ik, odd.ik, "а остальное на месте");
    }

    #[test]
    fn read_relays_survive_the_round_trip_and_stay_in_a_qr() {
        // Список реле — это и есть починка «доставки по совпадению»:
        // отправитель кладёт событие туда, где получатель читает.
        let mut with = card();
        with.nostr = vec![0x5a; NOSTR_KEY_LEN];
        with.ygg = vec![0x11; YGG_KEY_LEN];
        with.nostr_relays = vec![
            "wss://relay.damus.io".to_owned(),
            "wss://nos.lol".to_owned(),
            "wss://relay.nostr.band".to_owned(),
        ];
        let bytes = with.encode().unwrap();
        assert_eq!(*ContactCard::decode(&bytes).unwrap().value(), with);
        // Карточка со **всеми** полями 0.2 и 0.3 обязана остаться той,
        // что наводят камерой в плохом свете.
        assert!(bytes.len() < 400, "карточка разрослась: {} байт", bytes.len());
    }

    #[test]
    fn a_fourth_relay_is_not_advertised() {
        // Объявляются первые три. Читать человек может хоть с пяти —
        // но в QR они не поедут, и молча раздувать карточку нельзя.
        let mut many = card();
        many.nostr_relays = (0..5).map(|n| format!("wss://relay{n}.example")).collect();
        let back = ContactCard::decode(&many.encode().unwrap()).unwrap().into_parts().1;
        assert_eq!(back.nostr_relays.len(), MAX_CARD_RELAYS);
        assert_eq!(back.nostr_relays[0], "wss://relay0.example");
    }

    #[test]
    fn a_card_without_relays_encodes_exactly_as_before() {
        // То же правило, что у двух соседних ключей: пустой список
        // не пишется вовсе, иначе старая карточка перестала бы совпадать
        // со своими подписанными байтами (§6).
        let bytes = card().encode().unwrap();
        let back = ContactCard::decode(&bytes).unwrap().into_parts().1;
        assert!(back.nostr_relays.is_empty());
        assert_eq!(back.encode().unwrap(), bytes);
    }

    #[test]
    fn a_mangled_relay_list_does_not_break_the_card() {
        // Список приезжает от собеседника и годным быть не обязан.
        // Знакомство не должно ломаться из-за поля, которого раньше не было.
        let mut odd = card();
        odd.nostr_relays = vec!["wss://relay.example".to_owned()];
        let mut value = ContactCard::decode(&odd.encode().unwrap()).unwrap().into_parts().1;
        value.nostr_relays.clear();
        assert!(value.encode().is_ok());
    }

    #[test]
    fn the_two_new_keys_do_not_shadow_each_other() {
        // Длины у них одинаковые, а ключи карточки разные — перепутав
        // номера, мы объявили бы ключ одной сети в поле другой, и разбор
        // не заметил бы ничего: байты те же, длина та же.
        let mut both = card();
        both.ygg = vec![0x11; YGG_KEY_LEN];
        both.nostr = vec![0x22; NOSTR_KEY_LEN];
        let back = ContactCard::decode(&both.encode().unwrap()).unwrap().into_parts().1;
        assert_eq!(back.ygg, vec![0x11; YGG_KEY_LEN]);
        assert_eq!(back.nostr, vec![0x22; NOSTR_KEY_LEN]);
    }
}
