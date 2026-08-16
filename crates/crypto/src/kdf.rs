//! Тонкая обёртка над `BLAKE3::derive_key` (§8.1).
//!
//! Единственная точка, где в ядре выводятся ключи. Она существует, чтобы
//! контекст нельзя было передать «строкой по месту»: аргумент берётся
//! из [`crate::labels`], и это видно в каждом вызове.

use zeroize::Zeroizing;

/// Ключевой материал длиной 32 байта, затираемый при выходе из области видимости.
pub type Key32 = Zeroizing<[u8; 32]>;

/// Выводит 32 байта из контекста и входного материала.
#[must_use]
pub fn derive(context: &'static str, material: &[u8]) -> Key32 {
    Zeroizing::new(blake3::derive_key(context, material))
}

/// Выводит произвольное число байт из контекста и материала.
///
/// Нужно там, где длина не 32: например, `session_id` — первые 8 байт (§8.3).
pub fn derive_into(context: &'static str, material: &[u8], out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(material);
    hasher.finalize_xof().fill(out);
}

/// Выводит первые 8 байт как `u64` big-endian.
///
/// Так получается `session_id` (§8.3) и значение маяка LAN (§5.1).
#[must_use]
pub fn derive_u64(context: &'static str, material: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    derive_into(context, material, &mut out);
    u64::from_be_bytes(out)
}

/// Склейка нескольких кусков материала без промежуточных аллокаций.
///
/// Спецификация записывает вход как `a ‖ b ‖ c`; функция делает ровно это
/// и не даёт случайно поменять порядок, потеряв совместимость.
#[must_use]
pub fn derive_concat(context: &'static str, parts: &[&[u8]]) -> Key32 {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    for p in parts {
        hasher.update(p);
    }
    Zeroizing::new(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labels;

    #[test]
    fn different_contexts_give_different_keys() {
        let material = b"same input";
        assert_ne!(*derive(labels::CHAIN_A, material), *derive(labels::CHAIN_B, material));
        assert_ne!(*derive(labels::MSG, material), *derive(labels::CHAIN, material));
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(*derive(labels::ROOT, b"x"), *derive(labels::ROOT, b"x"));
    }

    #[test]
    fn concat_matches_manual_concatenation() {
        let joined = [b"aa".as_slice(), b"bb".as_slice()].concat();
        assert_eq!(*derive_concat(labels::ROOT, &[b"aa", b"bb"]), *derive(labels::ROOT, &joined));
    }

    #[test]
    fn prefix_related_contexts_are_independent() {
        // Спецификация даёт родственные по написанию контексты:
        // "ratatosk v0 chain" (§8.4) — префикс "ratatosk v0 chain-a" (§8.3).
        //
        // Для `derive_key` это безопасно: контекст хешируется целиком
        // в отдельном режиме и превращается в ключ, которым потом хешируется
        // материал. Ключи получаются независимыми.
        //
        // Для наивной схемы `BLAKE3(context ‖ material)` та же пара была бы
        // дырой: ("chain", "-a" ‖ X) и ("chain-a", X) склеиваются в одни
        // и те же байты. Тест фиксирует, почему §8.1 предписывает именно
        // `derive_key`, — чтобы при «упрощении» этого места кто-нибудь
        // заметил, что упрощает.
        let material = b"root";
        assert_ne!(*derive(labels::CHAIN, material), *derive(labels::CHAIN_A, material));
        assert_ne!(*derive(labels::CHAIN, material), *derive(labels::CHAIN_B, material));
        assert_ne!(*derive(labels::CHAIN_A, material), *derive(labels::CHAIN_B, material));

        // И то же самое в форме, где склейка была бы фатальной.
        assert_ne!(
            *derive_concat(labels::CHAIN, &[b"-a", material]),
            *derive_concat(labels::CHAIN_A, &[material])
        );
    }

    #[test]
    fn concat_is_order_sensitive() {
        assert_ne!(
            *derive_concat(labels::ROOT, &[b"aa", b"bb"]),
            *derive_concat(labels::ROOT, &[b"bb", b"aa"])
        );
    }

    #[test]
    fn xof_prefix_matches_fixed_output() {
        // Первые 32 байта XOF обязаны совпадать с обычным выводом, иначе
        // session_id и ключ разошлись бы при смене реализации.
        let mut long = [0u8; 64];
        derive_into(labels::SESSION_ID, b"h", &mut long);
        assert_eq!(&long[..32], &derive(labels::SESSION_ID, b"h")[..]);
    }
}
