//! Обновление адресов своей карточки (§4.3).
//!
//! Адреса меняются, ключи — нет. Onion-адрес появляется, когда поднялся Tor;
//! почтовый — когда завели ящик. Человек, добавивший вас по QR в кафе, знает
//! карточку той минуты, и без обновления он останется с ней навсегда: связь
//! будет работать, пока вы в одной локальной сети, и оборвётся, как только
//! разойдётесь.
//!
//! # Здесь подпись есть — в отличие от «поделиться контактом»
//!
//! Разница принципиальная, и её стоит проговорить рядом, потому что модули
//! соседние. [`crate::contact_share`] везёт **чужую** карточку, и подписать её
//! владелец не может — он не знает, что ею делятся; поэтому присланный контакт
//! непроверен всегда и известный не обновляет никогда. Здесь владелец меняет
//! **свою** карточку, уже известную получателю, и обязан доказать, что это он.
//! Доказывает подписью `SK` — тем самым ключом, отпечаток которого получатель
//! однажды сверил голосом (§4.2).
//!
//! Отсюда же следует, что сверка **переживает** обновление. Меняются адреса,
//! `IK` и `SK` остаются, значит отпечаток тот же, значит сверять заново нечего.
//! Сбрасывать признак сверки при каждой смене адреса означало бы просить
//! человека звонить собеседнику всякий раз, когда у того поднялся Tor, — и
//! приучить его подтверждать не глядя.
//!
//! # Что проверяется и в каком порядке
//!
//! 1. **Владелец.** `IK` в обновлении обязан совпасть с тем, чья это сессия.
//!    Без этой проверки Алиса прислала бы обновление «карточки Кэрол» со своим
//!    onion-адресом и увела бы маршрут на себя — ровно то, от чего
//!    отказывается [`crate::contact_share`].
//! 2. **Версия строго больше.** Иначе повтор старого кадра откатывал бы адреса
//!    к прежним — атака без единого поддельного байта, на одних лишь
//!    сохранённых.
//! 3. **Ключи не менялись.** Другие `IK`/`SK` — это другой человек, а не
//!    новость о старом.
//! 4. **Подпись.** Проверяется **известным** `SK`, а не тем, что приехал:
//!    проверять подпись ключом из подписанного сообщения — это проверять,
//!    что отправитель умеет подписывать своим же ключом.
//! 5. **Onion-адрес похож на адрес.** Строка, которая не может быть адресом
//!    v3, — мусор, и принять её значит обречь §5.4 на 45 секунд молчания
//!    при каждой отправке.
//!
//! Порядок не косметический: сперва дешёвые проверки и та, что решает
//! «от того ли это человека», и только потом разбор полей, которыми управляет
//! отправитель.
//!
//! # Чего здесь нет
//!
//! Отзыва. Карточку нельзя объявить недействительной — §4.3 знает только
//! замену на более новую. Устройство, потерянное вместе с ключами, лечится
//! новой личностью и повторной сверкой, а не сообщением «прежнюю не
//! слушайте», которому всё равно нечем было бы верить.

use ratatosk_codec::{canonical, CardUpdate, CodecError, ContactCard, Value};
use ratatosk_crypto::{onion, Identity, PublicIdentity};

/// Ключ карточки в нагрузке.
const KEY_CARD: u64 = 1;
/// Ключ подписи в нагрузке.
const KEY_SIGNATURE: u64 = 2;

/// Почему обновление не принято.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// Нагрузка не разобралась.
    #[error("обновление карточки испорчено")]
    Malformed,
    /// Обновление приехало из чужой сессии.
    #[error("обновление пришло не от владельца карточки")]
    NotFromOwner,
    /// Версия не больше известной.
    ///
    /// **Не признак злого умысла.** Обновление уходит всем контактам разом,
    /// доставка идёт разными путями и с разной задержкой (§5.4), и повтор
    /// старого — обычное дело. Обрабатывается тишиной, а не счётчиком аномалий.
    #[error("обновление не новее известного")]
    Stale,
    /// В обновлении сменились `IK` или `SK`.
    #[error("в обновлении сменились ключи — это другая личность")]
    IdentityChanged,
    /// Подпись не сошлась с известным `SK`.
    #[error("подпись обновления не сошлась")]
    BadSignature,
    /// Onion-адрес не может быть onion-адресом.
    #[error("onion-адрес в обновлении не адрес")]
    BadOnion,
}

/// Собирает подписанную нагрузку из своей карточки.
///
/// Кодирование и подпись — в одном месте намеренно: подпись обязана быть
/// над **теми самыми** байтами, которые поедут. Разнеси эти два шага, и
/// однажды кто-нибудь подпишет одну кодировку, а отправит другую.
///
/// # Errors
///
/// Отказ кодирования карточки.
pub fn signed_payload(identity: &Identity, card: &ContactCard) -> Result<Value, CodecError> {
    let bytes = card.encode()?;
    let signature = identity.sign(&bytes);
    Ok(payload(&bytes, &signature))
}

/// Собирает нагрузку из готовых байтов и подписи.
#[must_use]
pub fn payload(card_bytes: &[u8], signature: &[u8; 64]) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_CARD.into()), Value::Bytes(card_bytes.to_vec())),
        (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
    ])
}

/// Принимает **первую** карточку от того, чья сессия уже установлена.
///
/// # Чем это отличается от [`accept`]
///
/// У [`accept`] есть якорь — карточка, известная до сих пор: ею
/// проверяется подпись, и новой верят ровно настолько, насколько верили
/// прежней. Здесь якоря нет, и взять его неоткуда: владелец канала,
/// узнанный из ссылки (§10.1), приходит одним лишь `IK`.
///
/// Якорем становится **сессия**. Рукопожатие (§8.2) доказало, что
/// собеседник владеет этим `IK`; карточка связывает `IK` с `SK` своей
/// подписью, и проверяется она приехавшим `SK` — то есть подтверждает
/// лишь внутреннюю связность. Столько же веры ей и есть: §10.2 говорит,
/// что адрес из ссылки ничем не подтверждён, а личность устанавливает
/// рукопожатие. Ровно на этих условиях заводится и незнакомец (§8.3).
///
/// # Errors
///
/// [`UpdateError::Malformed`] — карта не той формы, подпись не сошлась
/// с приехавшим `SK`; [`UpdateError::NotFromOwner`] — карточка не про
/// того, чья это сессия.
pub fn accept_first(value: &Value, peer_ik: &[u8; 32]) -> Result<ContactCard, UpdateError> {
    let map = canonical::as_map(value).map_err(|_| UpdateError::Malformed)?;
    let Ok(Value::Bytes(card_bytes)) = canonical::require(map, KEY_CARD) else {
        return Err(UpdateError::Malformed);
    };
    let Ok(Value::Bytes(signature)) = canonical::require(map, KEY_SIGNATURE) else {
        return Err(UpdateError::Malformed);
    };
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| UpdateError::Malformed)?;
    let card = ContactCard::decode(card_bytes).map_err(|_| UpdateError::Malformed)?.into_parts().1;
    if card.ik != *peer_ik {
        return Err(UpdateError::NotFromOwner);
    }
    let who = PublicIdentity::from_bytes(card.ik, card.sk).map_err(|_| UpdateError::Malformed)?;
    who.verify(card_bytes, &signature).map_err(|_| UpdateError::Malformed)?;
    Ok(card)
}

/// Разбирает и проверяет обновление, возвращая новую карточку.
///
/// `peer_ik` — чья это сессия, `known` — карточка, известная до сих пор.
/// Возвращённой карточке можно верить ровно в той мере, в какой верят
/// известной: это она, с новыми адресами.
///
/// # Errors
///
/// [`UpdateError`] — по одной причине на каждую проверку из описания модуля.
pub fn accept(
    value: &Value,
    peer_ik: &[u8; 32],
    known: &ContactCard,
) -> Result<ContactCard, UpdateError> {
    let map = canonical::as_map(value).map_err(|_| UpdateError::Malformed)?;
    let Ok(Value::Bytes(card_bytes)) = canonical::require(map, KEY_CARD) else {
        return Err(UpdateError::Malformed);
    };
    let Ok(Value::Bytes(signature)) = canonical::require(map, KEY_SIGNATURE) else {
        return Err(UpdateError::Malformed);
    };
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| UpdateError::Malformed)?;
    let card = ContactCard::decode(card_bytes).map_err(|_| UpdateError::Malformed)?.into_parts().1;

    // Первым делом — от того ли это человека. Всё остальное имеет смысл
    // только после этого ответа.
    if card.ik != *peer_ik {
        return Err(UpdateError::NotFromOwner);
    }

    let update = CardUpdate { card, signature };
    update.check_against(known).map_err(|e| match e {
        CodecError::StaleCardVersion { .. } => UpdateError::Stale,
        CodecError::IdentityChanged => UpdateError::IdentityChanged,
        _ => UpdateError::Malformed,
    })?;

    // Известным `SK`, а не приехавшим. Проверка подписи ключом из самого
    // подписанного сообщения подтверждает только то, что отправитель владеет
    // каким-то ключом.
    PublicIdentity::from_bytes(known.ik, known.sk)
        .and_then(|owner| owner.verify(card_bytes, &update.signature))
        .map_err(|_| UpdateError::BadSignature)?;

    // Пустой адрес законен: Tor может быть не поднят, и «адреса нет» —
    // это правда о собеседнике, а не порча. Непустой обязан быть адресом.
    if !update.card.onion.is_empty() && !onion::is_address(&update.card.onion) {
        return Err(UpdateError::BadOnion);
    }

    Ok(update.card)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Identity {
        Identity::from_seed([5u8; 32])
    }

    fn known_card(owner: &Identity) -> ContactCard {
        ContactCard {
            ik: owner.public().ik,
            sk: owner.public().sk,
            onion: String::new(),
            chatmail: String::new(),
            display_name: "Алиса".into(),
            version: 1,
            ygg: Vec::new(),
            nostr: Vec::new(),
            nostr_relays: Vec::new(),
        }
    }

    /// Настоящий адрес v3 — проверка формата в [`accept`] иначе не пройдена.
    const ADDRESS: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";

    fn moved(owner: &Identity) -> ContactCard {
        ContactCard { onion: ADDRESS.into(), version: 2, ..known_card(owner) }
    }

    #[test]
    fn an_update_from_the_owner_is_accepted() {
        let owner = owner();
        let payload = signed_payload(&owner, &moved(&owner)).unwrap();
        let accepted = accept(&payload, &owner.public().ik, &known_card(&owner)).unwrap();
        assert_eq!(accepted.onion, ADDRESS);
        assert_eq!(accepted.version, 2);
    }

    #[test]
    fn an_update_about_someone_else_is_refused() {
        // Главная проверка этого модуля: иначе «поделиться контактом»
        // превращается в способ увести маршрут на себя.
        let owner = owner();
        let stranger = Identity::from_seed([6u8; 32]);
        let payload = signed_payload(&owner, &moved(&owner)).unwrap();
        assert_eq!(
            accept(&payload, &stranger.public().ik, &known_card(&owner)),
            Err(UpdateError::NotFromOwner)
        );
    }

    #[test]
    fn a_replay_of_an_old_card_is_refused() {
        // Откат адресов повтором сохранённого кадра — атака, для которой
        // не нужно подделывать ни байта.
        let owner = owner();
        let old = ContactCard { version: 1, ..moved(&owner) };
        let payload = signed_payload(&owner, &old).unwrap();
        assert_eq!(
            accept(&payload, &owner.public().ik, &known_card(&owner)),
            Err(UpdateError::Stale)
        );
    }

    #[test]
    fn a_changed_key_is_not_an_update_but_another_person() {
        let owner = owner();
        let other = Identity::from_seed([7u8; 32]);
        let swapped = ContactCard { sk: other.public().sk, ..moved(&owner) };
        let payload = signed_payload(&owner, &swapped).unwrap();
        assert_eq!(
            accept(&payload, &owner.public().ik, &known_card(&owner)),
            Err(UpdateError::IdentityChanged)
        );
    }

    #[test]
    fn a_signature_by_the_wrong_key_is_refused() {
        // Подписал кто-то другой, а карточка чужая целиком — значит,
        // подпись проверяется известным ключом, а не приехавшим.
        let owner = owner();
        let forger = Identity::from_seed([8u8; 32]);
        let payload = signed_payload(&forger, &moved(&owner)).unwrap();
        assert_eq!(
            accept(&payload, &owner.public().ik, &known_card(&owner)),
            Err(UpdateError::BadSignature)
        );
    }

    #[test]
    fn a_tampered_card_is_refused() {
        // Подпись считается над принятыми байтами (§6), поэтому правка
        // одного поля после подписи обязана всплыть.
        let owner = owner();
        let honest = moved(&owner);
        let signature = owner.sign(&honest.encode().unwrap());
        let tampered = ContactCard { display_name: "Мэллори".into(), ..honest };
        let payload = payload(&tampered.encode().unwrap(), &signature);
        assert_eq!(
            accept(&payload, &owner.public().ik, &known_card(&owner)),
            Err(UpdateError::BadSignature)
        );
    }

    #[test]
    fn an_onion_that_cannot_be_an_onion_is_refused() {
        let owner = owner();
        let broken = ContactCard { onion: "почти.onion".into(), ..moved(&owner) };
        let payload = signed_payload(&owner, &broken).unwrap();
        assert_eq!(
            accept(&payload, &owner.public().ik, &known_card(&owner)),
            Err(UpdateError::BadOnion)
        );
    }

    #[test]
    fn an_empty_onion_is_a_fact_and_not_a_breakage() {
        // Tor может быть не поднят, и «адреса нет» — правда о собеседнике.
        let owner = owner();
        let mail_only = ContactCard {
            chatmail: "a7f3k9@nine.example".into(),
            version: 2,
            ..known_card(&owner)
        };
        let payload = signed_payload(&owner, &mail_only).unwrap();
        let accepted = accept(&payload, &owner.public().ik, &known_card(&owner)).unwrap();
        assert!(accepted.onion.is_empty());
        assert_eq!(accepted.chatmail, "a7f3k9@nine.example");
    }

    #[test]
    fn a_broken_payload_is_refused_without_panic() {
        let owner = owner();
        let known = known_card(&owner);
        let empty = Value::Map(Vec::new());
        assert_eq!(accept(&empty, &owner.public().ik, &known), Err(UpdateError::Malformed));

        let short = payload(&moved(&owner).encode().unwrap(), &[0u8; 64]);
        assert_eq!(accept(&short, &owner.public().ik, &known), Err(UpdateError::BadSignature));

        let garbage = payload(b"not a card at all", &[0u8; 64]);
        assert_eq!(accept(&garbage, &owner.public().ik, &known), Err(UpdateError::Malformed));
    }
}
