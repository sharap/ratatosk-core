//! Детерминированный CBOR (§6).
//!
//! RFC 8949 §4.2: ключи по возрастанию, минимальная длина, никаких
//! неопределённых длин.
//!
//! Причина отказа от protobuf (§6): мы считаем хэши и подписи от структур,
//! а protobuf не нормирует байтовое представление — порядок полей,
//! минимальность варинтов, порядок map. Два честных клиента получили бы
//! разные хэши одной структуры.
//!
//! Из этого следует правило, которое здесь выражено типом [`Raw`]:
//! **подпись и хэш вычисляются над принятыми байтами**, а не над результатом
//! повторной сериализации. Неизвестные ключи сохраняются и не
//! переупорядочиваются.

use ciborium::value::Value;

use crate::error::{CodecError, Result};

/// Ключ `protocol_version`, обязательный первым в каждой структуре (§6).
pub const KEY_PROTOCOL_VERSION: u64 = 1;

/// Текущая мажорная версия протокола.
pub const PROTOCOL_VERSION: u64 = 0;

/// Разобранная структура вместе с байтами, из которых она получена.
///
/// Существует ровно ради правила §6: подписывается и хэшируется `bytes`,
/// а не результат повторной сериализации `value`. Пересобрать байты из
/// разобранного значения нельзя — неизвестные будущим версиям ключи при
/// этом потерялись бы, а подпись перестала бы сходиться.
#[derive(Debug, Clone, PartialEq)]
pub struct Raw<T> {
    bytes: Vec<u8>,
    value: T,
}

impl<T> Raw<T> {
    /// Связывает значение с байтами, из которых оно разобрано.
    #[must_use]
    pub fn new(bytes: Vec<u8>, value: T) -> Raw<T> {
        Raw { bytes, value }
    }

    /// Принятые байты — то, над чем считаются подпись и хэш.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Разобранное значение.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Разбирает `Raw` на части.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, T) {
        (self.bytes, self.value)
    }
}

/// Кодирует значение в детерминированный CBOR.
///
/// Отвергает карты с повторяющимися ключами — см. [`canonicalize`].
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    let sorted = canonicalize(value.clone())?;
    let mut out = Vec::new();
    ciborium::into_writer(&sorted, &mut out).map_err(|_| CodecError::Encode)?;
    Ok(out)
}

/// Разбирает байты, требуя каноничности.
///
/// Проверка — повторное кодирование и сравнение с входом. Она строже любой
/// поштучной: ловит и несортированные ключи, и неминимальные длины,
/// и неопределённые длины, и хвостовой мусор, — одним правилом, которое
/// невозможно забыть расширить при добавлении нового типа.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| CodecError::Decode)?;
    let reencoded = encode(&value)?;
    if reencoded != bytes {
        return Err(CodecError::NotCanonical);
    }
    Ok(value)
}

/// Рекурсивно приводит значение к каноническому виду.
///
/// Сортировка ключей — по их закодированному представлению (RFC 8949 §4.2.1).
/// Для целочисленных ключей 0..=23, которыми пользуется весь протокол,
/// это совпадает с числовым порядком, но полагаться на совпадение нельзя:
/// одно поле с ключом больше 23 сломало бы такое допущение молча.
///
/// **Повторяющиеся ключи отвергаются.** RFC 8949 требует уникальности,
/// но дело не только в букве стандарта: карта с двумя одинаковыми ключами —
/// классический источник расхождения реализаций. Одна возьмёт первое
/// значение, другая последнее, и подпись сойдётся у обеих при разном
/// прочитанном содержимом. Проверка здесь закрывает это и на приёме
/// (через [`decode`]), и на отправке — второе поймало собственную ошибку
/// в нумерации полей контакт-карточки.
fn canonicalize(value: Value) -> Result<Value> {
    match value {
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let k = canonicalize(k)?;
                let v = canonicalize(v)?;
                keyed.push((encode_key_bytes(&k), k, v));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));

            if let Some(w) = keyed.windows(2).find(|w| w[0].0 == w[1].0) {
                return Err(CodecError::DuplicateKey { key: w[0].0.clone() });
            }

            Ok(Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect()))
        }
        Value::Array(items) => {
            items.into_iter().map(canonicalize).collect::<Result<Vec<_>>>().map(Value::Array)
        }
        Value::Tag(tag, inner) => Ok(Value::Tag(tag, Box::new(canonicalize(*inner)?))),
        other => Ok(other),
    }
}

fn encode_key_bytes(key: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // Ключ, который не кодируется, всё равно упадёт при кодировании всей
    // структуры; здесь достаточно устойчивого порядка.
    let _ = ciborium::into_writer(key, &mut out);
    out
}

/// Читает целочисленный ключ из карты.
pub fn get(map: &[(Value, Value)], key: u64) -> Option<&Value> {
    map.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if u64::try_from(*i) == Ok(key)))
        .map(|(_, v)| v)
}

/// Читает обязательный целочисленный ключ.
pub fn require(map: &[(Value, Value)], key: u64) -> Result<&Value> {
    get(map, key).ok_or(CodecError::MissingField { key })
}

/// Проверяет `protocol_version` (§6).
///
/// Клиент отвергает старшие мажорные версии с понятным сообщением — именно
/// сообщением, а не «битой структурой»: пользователю нужно сказать
/// «обновите приложение».
pub fn check_version(map: &[(Value, Value)]) -> Result<u64> {
    let raw = require(map, KEY_PROTOCOL_VERSION)?;
    let version = as_u64(raw)?;
    if version > PROTOCOL_VERSION {
        return Err(CodecError::FutureVersion { got: version, supported: PROTOCOL_VERSION });
    }
    Ok(version)
}

/// Извлекает беззнаковое целое.
pub fn as_u64(value: &Value) -> Result<u64> {
    match value {
        Value::Integer(i) => u64::try_from(*i).map_err(|_| CodecError::TypeMismatch),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Извлекает строку.
pub fn as_text(value: &Value) -> Result<&str> {
    match value {
        Value::Text(t) => Ok(t),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Извлекает байтовую строку.
pub fn as_bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Извлекает байтовый массив фиксированной длины.
pub fn as_array<const N: usize>(value: &Value) -> Result<[u8; N]> {
    as_bytes(value)?.try_into().map_err(|_| CodecError::TypeMismatch)
}

/// Извлекает карту.
pub fn as_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(m) => Ok(m),
        _ => Err(CodecError::TypeMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: Vec<(u64, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (Value::Integer(k.into()), v)).collect())
    }

    #[test]
    fn encoding_sorts_keys() {
        let unsorted = map(vec![(3, Value::Bool(true)), (1, Value::Bool(false))]);
        let sorted = map(vec![(1, Value::Bool(false)), (3, Value::Bool(true))]);
        assert_eq!(encode(&unsorted).unwrap(), encode(&sorted).unwrap());
    }

    #[test]
    fn encoding_is_stable() {
        let v = map(vec![(1, Value::Integer(0.into())), (2, Value::Text("x".into()))]);
        assert_eq!(encode(&v).unwrap(), encode(&v).unwrap());
    }

    #[test]
    fn nested_maps_are_sorted_too() {
        let inner_unsorted = map(vec![(9, Value::Null), (2, Value::Null)]);
        let inner_sorted = map(vec![(2, Value::Null), (9, Value::Null)]);
        assert_eq!(
            encode(&map(vec![(1, inner_unsorted)])).unwrap(),
            encode(&map(vec![(1, inner_sorted)])).unwrap()
        );
    }

    #[test]
    fn decode_rejects_unsorted_input() {
        let bytes = {
            let mut out = Vec::new();
            let unsorted = Value::Map(vec![
                (Value::Integer(3.into()), Value::Null),
                (Value::Integer(1.into()), Value::Null),
            ]);
            ciborium::into_writer(&unsorted, &mut out).unwrap();
            out
        };
        assert!(matches!(decode(&bytes), Err(CodecError::NotCanonical)));
    }

    #[test]
    fn round_trip_preserves_unknown_keys() {
        // §6: неизвестные ключи сохраняются как непрозрачный остаток.
        // Ключ 99 не знает ни одна структура v0 — он обязан пережить разбор.
        let v = map(vec![(1, Value::Integer(0.into())), (99, Value::Text("из будущего".into()))]);
        let bytes = encode(&v).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(encode(&back).unwrap(), bytes);
        assert!(get(as_map(&back).unwrap(), 99).is_some());
    }

    #[test]
    fn raw_keeps_received_bytes() {
        let v = map(vec![(1, Value::Integer(0.into()))]);
        let bytes = encode(&v).unwrap();
        let raw = Raw::new(bytes.clone(), v);
        assert_eq!(raw.bytes(), &bytes[..]);
    }

    #[test]
    fn future_major_version_is_refused_clearly() {
        let v = map(vec![(1, Value::Integer((PROTOCOL_VERSION + 1).into()))]);
        let m = as_map(&v).unwrap();
        assert!(matches!(check_version(m), Err(CodecError::FutureVersion { .. })));
    }

    #[test]
    fn missing_version_is_an_error() {
        let v = map(vec![(2, Value::Null)]);
        assert!(matches!(
            check_version(as_map(&v).unwrap()),
            Err(CodecError::MissingField { key: 1 })
        ));
    }

    #[test]
    fn duplicate_keys_are_rejected_on_encode() {
        // Ровно эта проверка ловит ошибку в нумерации полей структуры —
        // до того, как она уедет в QR-код.
        let v = map(vec![(1, Value::Integer(0.into())), (1, Value::Bytes(vec![9]))]);
        assert!(matches!(encode(&v), Err(CodecError::DuplicateKey { .. })));
    }

    #[test]
    fn duplicate_keys_are_rejected_on_decode() {
        // Собеседник прислал карту с дублем: одна реализация взяла бы первое
        // значение, другая последнее, подпись сошлась бы у обеих.
        let bytes = {
            let mut out = Vec::new();
            let dup = Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(0.into())),
                (Value::Integer(1.into()), Value::Integer(7.into())),
            ]);
            ciborium::into_writer(&dup, &mut out).unwrap();
            out
        };
        assert!(matches!(decode(&bytes), Err(CodecError::DuplicateKey { .. })));
    }

    #[test]
    fn duplicates_are_caught_in_nested_maps_too() {
        let inner = Value::Map(vec![
            (Value::Integer(5.into()), Value::Null),
            (Value::Integer(5.into()), Value::Null),
        ]);
        assert!(matches!(encode(&map(vec![(1, inner)])), Err(CodecError::DuplicateKey { .. })));
    }

    #[test]
    fn distinct_keys_of_different_types_are_not_duplicates() {
        // Целое 1 и строка "1" кодируются по-разному и дублем не являются.
        let v = Value::Map(vec![
            (Value::Integer(1.into()), Value::Null),
            (Value::Text("1".into()), Value::Null),
        ]);
        assert!(encode(&v).is_ok());
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut bytes = encode(&map(vec![(1, Value::Integer(0.into()))])).unwrap();
        bytes.push(0xFF);
        assert!(decode(&bytes).is_err());
    }
}
