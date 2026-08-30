//! Ключ локального хранилища (§8.6).
//!
//! `db_key` шифруется `Argon2id(PIN)`; результат хранится в Android Keystore /
//! OS-хранилище десктопа. Без PIN приложение не открывает БД.
//!
//! PIN опционален. При отказе UI обязан показать, что содержимое доступно
//! любому, кто получил устройство, — §2.2 прямо относит скомпрометированное
//! устройство к тому, от чего защиты нет и быть не может.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Параметры Argon2id.
///
/// Подобраны под слабый Android-телефон: вывод ключа не должен занимать
/// больше секунды на устройстве уровня Android 9 (§13.1), иначе разблокировка
/// станет заметно раздражающей и пользователь отключит PIN.
///
/// TODO(этап 0): измерить на реальном минимальном устройстве и зафиксировать
/// числа здесь вместе с моделью и временем.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    /// Память, КиБ.
    pub memory_kib: u32,
    /// Число проходов.
    pub iterations: u32,
    /// Степень параллелизма.
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

/// Длина соли.
pub const SALT_LEN: usize = 16;

/// Выводит ключ шифрования `db_key` из PIN.
///
/// Соль хранится рядом с зашифрованным `db_key` в открытом виде — это её
/// штатный режим; секретность соли не требуется.
pub fn derive_from_pin(
    pin: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
        .map_err(|_| CryptoError::BadKeyMaterial)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin.as_bytes(), salt, out.as_mut())
        .map_err(|_| CryptoError::BadKeyMaterial)?;
    Ok(out)
}

/// Генерирует новую соль.
#[must_use]
pub fn generate_salt() -> [u8; SALT_LEN] {
    use rand_core::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);
    salt
}

/// Генерирует `db_key` (§3).
#[must_use]
pub fn generate_db_key() -> Zeroizing<[u8; 32]> {
    use rand_core::RngCore;
    let mut key = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(key.as_mut());
    key
}

/// Длина nonce, которым начинается запечатанное поле.
pub const FIELD_NONCE_LEN: usize = 24;

/// Запечатывает поле базы ключом `db_key` (§12).
///
/// Живёт здесь, а не в `ratatosk-store`, из-за §8.1: комбинирование
/// примитивов должно быть **в одном модуле, покрытом тест-векторами**.
/// Хранилищу остаётся решать, что шифровать, а не как.
///
/// `aad` привязывает шифротекст к его месту: имя столбца вместе с ключом
/// строки. Без этого шифротекст можно переставить из строки в строку, и
/// расшифровка пройдёт успешно — подменив содержимое чужого сообщения на
/// содержимое своего.
///
/// Nonce случайный и едет впереди шифротекста: одно и то же поле
/// переписывается (правка статуса, повторная запись), а повтор nonce
/// на одном ключе разрушает XChaCha20 целиком.
pub fn seal_field(db_key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use rand_core::RngCore;
    let mut nonce = [0u8; FIELD_NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(db_key));
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buffer)
        .map_err(|_| CryptoError::BadKeyMaterial)?;

    let mut out = Vec::with_capacity(FIELD_NONCE_LEN + buffer.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Распечатывает поле базы.
///
/// Отказ означает либо неверный PIN, либо порчу файла, либо перестановку
/// шифротекста между строками. Различать их незачем: во всех трёх случаях
/// читать нечего.
pub fn open_field(db_key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    const TAG_LEN: usize = 16;
    if sealed.len() < FIELD_NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (nonce, rest) = sealed.split_at(FIELD_NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(db_key));
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            buffer.as_mut_slice(),
            tag.into(),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(buffer)
}

/// Сколько символов в группе показанного ключа.
const KEY_GROUP_LEN: usize = 4;

/// Показывает ключ базы человеку (§12).
///
/// **Ключ придётся переписать руками**, и от этого весь вид: base32 без
/// похожих знаков (тот же алфавит, что у отпечатка §3 — «0 или O» человек
/// не должен решать по-разному в разных местах приложения), группами
/// по четыре. Тридцать два байта дают 52 символа, то есть тринадцать групп.
///
/// Длинно, и короче не выйдет: это ключ, а не пароль. Сокращать его —
/// значит сокращать защиту архива, который уедет на флешке.
#[must_use]
pub fn key_text(key: &[u8; 32]) -> String {
    let text = crate::identity::crockford().encode(key);
    text.as_bytes()
        .chunks(KEY_GROUP_LEN)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Читает ключ, переписанный человеком.
///
/// Разделители и регистр не важны: человек перепишет как получится,
/// и отказывать ему из-за строчной буквы значит отказывать зря.
///
/// # Errors
///
/// [`CryptoError::BadKeyMaterial`], если строка не разбирается или в ней
/// не тридцать два байта.
pub fn key_from_text(text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let cleaned: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = crate::identity::crockford()
        .decode(cleaned.as_bytes())
        .map_err(|_| CryptoError::BadKeyMaterial)?;
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CryptoError::BadKeyMaterial)?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Быстрые параметры: боевые в тестах дают минуты на весь набор.
    fn fast() -> KdfParams {
        KdfParams { memory_kib: 8, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn field_round_trips() {
        let key = [7u8; 32];
        let sealed = seal_field(&key, b"messages.body:abc", "привет".as_bytes()).unwrap();
        assert_eq!(
            &open_field(&key, b"messages.body:abc", &sealed).unwrap()[..],
            "привет".as_bytes()
        );
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let sealed = seal_field(&[7u8; 32], b"aad", b"x").unwrap();
        assert!(open_field(&[8u8; 32], b"aad", &sealed).is_err());
    }

    #[test]
    fn ciphertext_cannot_be_moved_to_another_row() {
        // Главное, ради чего здесь AAD: без него шифротекст чужого сообщения
        // подставляется в свою строку, и расшифровка проходит успешно.
        let key = [7u8; 32];
        let sealed = seal_field(&key, b"messages.body:row-1", "чужое".as_bytes()).unwrap();
        assert!(open_field(&key, b"messages.body:row-2", &sealed).is_err());
    }

    #[test]
    fn the_same_plaintext_seals_differently_each_time() {
        // Повтор nonce на одном ключе разрушает XChaCha20, а поля
        // переписываются.
        let key = [7u8; 32];
        assert_ne!(
            seal_field(&key, b"aad", "одно и то же".as_bytes()).unwrap(),
            seal_field(&key, b"aad", "одно и то же".as_bytes()).unwrap()
        );
    }

    #[test]
    fn truncated_input_is_refused_without_panic() {
        let key = [7u8; 32];
        let sealed = seal_field(&key, b"aad", b"x").unwrap();
        for cut in 0..sealed.len() {
            assert!(open_field(&key, b"aad", &sealed[..cut]).is_err(), "обрез {cut}");
        }
    }

    #[test]
    fn an_empty_field_round_trips() {
        let key = [7u8; 32];
        let sealed = seal_field(&key, b"aad", b"").unwrap();
        assert!(open_field(&key, b"aad", &sealed).unwrap().is_empty());
    }

    #[test]
    fn derivation_is_deterministic() {
        let salt = [1u8; SALT_LEN];
        let a = derive_from_pin("1234", &salt, fast()).unwrap();
        let b = derive_from_pin("1234", &salt, fast()).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn different_pins_give_different_keys() {
        let salt = [1u8; SALT_LEN];
        assert_ne!(
            *derive_from_pin("1234", &salt, fast()).unwrap(),
            *derive_from_pin("1235", &salt, fast()).unwrap()
        );
    }

    #[test]
    fn different_salts_give_different_keys() {
        assert_ne!(
            *derive_from_pin("1234", &[1u8; SALT_LEN], fast()).unwrap(),
            *derive_from_pin("1234", &[2u8; SALT_LEN], fast()).unwrap()
        );
    }

    #[test]
    fn salts_are_not_repeated() {
        assert_ne!(generate_salt(), generate_salt());
    }

    #[test]
    fn db_keys_are_not_repeated() {
        assert_ne!(*generate_db_key(), *generate_db_key());
    }

    #[test]
    fn a_shown_key_reads_back() {
        let key = [7u8; 32];
        let text = key_text(&key);
        assert_eq!(text.len(), 52 + 12, "52 символа и двенадцать дефисов");
        assert_eq!(*key_from_text(&text).unwrap(), key);
    }

    #[test]
    fn a_key_written_down_by_a_human_still_reads() {
        // Человек перепишет как получится: строчными, с пробелами вместо
        // дефисов, с лишним пробелом в конце. Отказывать ему из-за этого
        // значит отказывать зря — а второй попытки у него может не быть.
        let key = [0xABu8; 32];
        let text = key_text(&key).to_lowercase().replace('-', " ");
        assert_eq!(*key_from_text(&format!("  {text} ")).unwrap(), key);
    }

    #[test]
    fn a_key_that_is_not_a_key_is_refused() {
        assert!(key_from_text("").is_err(), "пустая строка — не ключ");
        assert!(key_from_text("0123").is_err(), "коротко");
        assert!(key_from_text(&key_text(&[1u8; 32])[..20]).is_err(), "обрезано");
    }
}
