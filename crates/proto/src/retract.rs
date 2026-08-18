//! Просьба удалить сообщение у собеседника.
//!
//! **Спецификация v0.1 этого не описывает.** Дополнение, и §17 просит такие
//! вещи называть отдельно. В §12 надгробия уже есть («удалённые живут 90
//! суток»), но только как местная уборка; сюда добавляется способ попросить
//! о том же другую сторону.
//!
//! # Это просьба, а не удаление
//!
//! Разница не в формулировке, а в том, что протокол может обещать. Отправив
//! кадр, мы не знаем и не можем узнать: работает ли у собеседника наш клиент
//! или его переделка, не снят ли уже скриншот, не открыт ли чат на втором
//! устройстве. Поэтому команда называется «отозвать», а не «удалить у обоих»,
//! а §14 требует сказать это пользователю до нажатия, а не после.
//!
//! Отсюда же следует, что отзыв **не** идёт отдельным быстрым каналом, как
//! квитанция (§9.4). Квитанция, не дошедшая до собеседника, — мелочь: он
//! увидит «отправлено» вместо «доставлено». Отзыв, не дошедший из-за того,
//! что человек в тот момент был офлайн, — это ровно та неудача, ради которой
//! всё и затевалось. Поэтому он едет обычной очередью доставки §5.4, с теми
//! же откатами: LAN, onion, почта.
//!
//! # Кто что может отозвать
//!
//! Отозвать можно **только своё**. Правило проверяет получатель, а не
//! отправитель: иначе достаточно было бы прислать чужой идентификатор, чтобы
//! стереть слова из чужой переписки. Проверка живёт в ядре
//! (`Engine::on_retract`) и стоит одного сравнения `sender_ik`.

use ratatosk_codec::{canonical, CodecError, Value};
use ratatosk_crdt::MsgId;

/// Ключ списка идентификаторов в полезной нагрузке.
const KEY_IDS: u64 = 1;

/// Сколько сообщений можно отозвать одним кадром.
///
/// Предел нужен на приёме, как и у квитанций: список приходит от собеседника,
/// и без потолка одна просьба заставила бы перебрать столько записей, сколько
/// он пожелает. Сотня — это «убрать разговор, который зря начал», а не край.
pub const MAX_RETRACT_IDS: usize = 100;

/// Собирает полезную нагрузку просьбы.
#[must_use]
pub fn payload(msg_ids: &[MsgId]) -> Value {
    let ids = msg_ids.iter().map(|id| Value::Bytes(id.to_vec())).collect();
    Value::Map(vec![(Value::Integer(KEY_IDS.into()), Value::Array(ids))])
}

/// Разбирает полезную нагрузку просьбы.
///
/// Всё здесь приходит от собеседника, поэтому проверяется всё: и длина
/// каждого идентификатора, и их число.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`], если структура не та или список длиннее
/// [`MAX_RETRACT_IDS`].
pub fn from_payload(value: &Value) -> Result<Vec<MsgId>, CodecError> {
    let map = canonical::as_map(value)?;
    let Value::Array(items) = canonical::require(map, KEY_IDS)? else {
        return Err(CodecError::TypeMismatch);
    };
    if items.len() > MAX_RETRACT_IDS {
        return Err(CodecError::TypeMismatch);
    }

    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        ids.push(canonical::as_array::<16>(item)?);
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_round_trips() {
        let ids: Vec<MsgId> = vec![[1u8; 16], [2u8; 16]];
        assert_eq!(from_payload(&payload(&ids)).unwrap(), ids);
    }

    #[test]
    fn an_empty_list_is_allowed_and_means_nothing_to_do() {
        // Пустой список — не ошибка формата: он законно получается, если
        // все названные сообщения уже удалены. Отбрасывать за это сессию
        // было бы несоразмерно.
        assert_eq!(from_payload(&payload(&[])).unwrap(), Vec::<MsgId>::new());
    }

    #[test]
    fn an_overlong_list_is_refused() {
        let ids: Vec<MsgId> = vec![[3u8; 16]; MAX_RETRACT_IDS + 1];
        assert!(from_payload(&payload(&ids)).is_err());
    }

    #[test]
    fn a_wrong_sized_identifier_is_refused() {
        let bad = Value::Map(vec![(
            Value::Integer(KEY_IDS.into()),
            Value::Array(vec![Value::Bytes(vec![0u8; 8])]),
        )]);
        assert!(from_payload(&bad).is_err());
    }
}
