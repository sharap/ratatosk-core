//! Инвариант §16: «каноническая сериализация делает round-trip».
//!
//! Свойство здесь сильнее, чем звучит в §16, и намеренно: §6 требует не просто
//! обратимости, а **нормальной формы**. Одна и та же структура у двух честных
//! клиентов обязана дать одни и те же байты — иначе подпись, посчитанная одним,
//! не сойдётся у другого. Поэтому проверяется четыре вещи:
//!
//! 1. кодирование — нормальная форма: перестановка ключей ничего не меняет;
//! 2. `decode` принимает байты **тогда и только тогда**, когда они канонические;
//! 3. всё, что `decode` принял, пересобирается байт в байт (правило §6 о том,
//!    что подпись считается над принятыми байтами);
//! 4. на произвольном мусоре из сети нет паник — только ошибки.
//!
//! Область значений — ровно те типы CBOR, которыми пользуется протокол (§6):
//! целые, байтовые строки, текст, `bool`, `null`, массивы, карты. Плавающих
//! чисел в протоколе нет, и генерировать их значило бы проверять ciborium,
//! а не себя.

use ciborium::value::Value;
use proptest::prelude::*;
use ratatosk_codec::canonical::{decode, encode};

/// Кодирует значение как есть, не приводя к каноническому виду.
///
/// Нужно, чтобы получить заведомо **неканонические** байты: `encode`
/// такие построить не даст, а собеседник — вполне может прислать.
fn encode_verbatim(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("значение из генератора кодируемо");
    out
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        // Диапазон i64: CBOR шире не кодирует, и выход за него — вопрос
        // к ciborium, а не к каноничности.
        any::<i64>().prop_map(|i| Value::Integer(i.into())),
        prop::collection::vec(any::<u8>(), 0..24).prop_map(Value::Bytes),
        ".{0,16}".prop_map(Value::Text),
    ]
}

/// Ключи берутся из узкого набора, чтобы дубли и соседние по кодированию
/// ключи встречались часто. Граница 23/24 — та, на которой у CBOR меняется
/// длина заголовка, а значит и порядок сортировки по байтам расходится
/// с числовым (RFC 8949 §4.2.1).
fn key() -> impl Strategy<Value = Value> {
    prop_oneof![
        (0i64..30).prop_map(|i| Value::Integer(i.into())),
        (-5i64..2).prop_map(|i| Value::Integer(i.into())),
        "[a-c]{1,2}".prop_map(Value::Text),
    ]
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::vec((key(), inner), 0..4).prop_map(Value::Map),
        ]
    })
}

/// Своя перестановка вместо генератора случайных чисел: контрпример
/// воспроизводится по одному значению `swaps`.
fn permute<T>(mut items: Vec<T>, swaps: &[u16]) -> Vec<T> {
    let n = items.len();
    if n < 2 {
        return items;
    }
    for (i, s) in swaps.iter().enumerate() {
        items.swap(i % n, usize::from(*s) % n);
    }
    items
}

proptest! {
    /// Кодирование — нормальная форма: порядок ключей на входе не влияет
    /// на байты на выходе.
    ///
    /// Это и есть причина, по которой в §6 выбран CBOR с правилами RFC 8949
    /// §4.2, а не protobuf: без нормальной формы два честных клиента считают
    /// подпись над разными байтами одной структуры.
    #[test]
    fn key_order_does_not_change_the_bytes(
        entries in prop::collection::vec((key(), value()), 0..6),
        swaps in prop::collection::vec(any::<u16>(), 0..12),
    ) {
        let straight = Value::Map(entries.clone());
        let shuffled = Value::Map(permute(entries, &swaps));

        match (encode(&straight), encode(&shuffled)) {
            (Ok(a), Ok(b)) => prop_assert_eq!(a, b, "перестановка ключей изменила байты"),
            // Отказ тоже обязан не зависеть от порядка: дубль остаётся дублем.
            (Err(_), Err(_)) => {}
            (a, b) => prop_assert!(false, "перестановка изменила исход: {a:?} против {b:?}"),
        }
    }

    /// `decode` принимает байты тогда и только тогда, когда они канонические.
    ///
    /// Односторонняя формулировка («канонические принимаются») пропустила бы
    /// главное: приём неканонических байтов означает, что одна и та же
    /// структура имеет два представления, и `BLAKE3` от них разный.
    #[test]
    fn decode_accepts_exactly_the_canonical_encoding(
        v in value(),
    ) {
        let verbatim = encode_verbatim(&v);
        match encode(&v) {
            Ok(canonical) => {
                prop_assert_eq!(
                    decode(&verbatim).is_ok(),
                    verbatim == canonical,
                    "приём разошёлся с каноничностью"
                );
                let back = decode(&canonical).expect("каноническое обязано читаться");
                prop_assert_eq!(encode(&back).unwrap(), canonical, "round-trip не байт в байт");
            }
            Err(_) => {
                prop_assert!(decode(&verbatim).is_err(), "структура с дублем ключа принята");
            }
        }
    }

    /// Повторное кодирование ничего не меняет: канонизация — проекция.
    #[test]
    fn canonicalization_is_a_fixed_point(v in value()) {
        let Ok(once) = encode(&v) else { return Ok(()) };
        let back = decode(&once).expect("каноническое обязано читаться");
        let twice = encode(&back).expect("уже каноническое обязано кодироваться");
        prop_assert_eq!(once, twice);
    }

    /// Всё, что принято из сети, пересобирается байт в байт.
    ///
    /// Правило §6 («подпись считается над принятыми байтами») выполнимо только
    /// при этом условии; заодно это проверка, что на произвольном мусоре
    /// разбор не паникует, а возвращает ошибку.
    #[test]
    fn anything_accepted_re_encodes_to_itself(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        if let Ok(v) = decode(&bytes) {
            prop_assert_eq!(encode(&v).unwrap(), bytes);
        }
    }

    /// Хвостовой мусор не проходит: длина структуры — часть её самой.
    ///
    /// Иначе к подписанной структуре можно дописать байты, подпись сойдётся
    /// (она считается над принятыми байтами до конца), а два клиента прочитают
    /// разное количество данных.
    #[test]
    fn trailing_bytes_are_never_accepted(
        v in value(),
        tail in prop::collection::vec(any::<u8>(), 1..8),
    ) {
        let Ok(mut bytes) = encode(&v) else { return Ok(()) };
        bytes.extend_from_slice(&tail);
        prop_assert!(decode(&bytes).is_err(), "хвост после структуры принят");
    }
}
