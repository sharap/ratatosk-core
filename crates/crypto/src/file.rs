//! Шифрование чанков файла (§10.1).
//!
//! Файл шифруется случайным `file_key` (32 байта), который едет в предложении.
//! Ключ **каждого чанка** выводится отдельно:
//!
//! ```text
//! chunk_key = BLAKE3_derive_key("ratatosk v0 file", file_key ‖ index_be)
//! ```
//!
//! Это ровно та деривация, которую §10.1 называет `chunk_id`. Отдельного
//! идентификатора чанка помимо неё нет: номер чанка и так едет в конверте
//! открытым текстом, а «идентификатор», который одновременно является ключом,
//! публиковать нельзя. Поэтому деривация одна и живёт здесь — в модуле, где
//! §8.1 велит держать комбинирование примитивов, — а `ratatosk_proto::files`
//! на неё ссылается.
//!
//! # Nonce нулевой, и вот почему это безопасно
//!
//! У каждого чанка свой ключ, и этим ключом шифруется **ровно один** блок
//! данных. Повтор пары «ключ, nonce» возможен только если один и тот же
//! `file_key` использован для двух разных содержимых одного и того же номера
//! чанка. Отсюда инвариант, который обязан держать вызывающий код:
//!
//! **`file_key` генерируется заново на каждое предложение файла и никогда
//! не переиспользуется.** Повторная отправка того же файла — это новое
//! предложение с новым ключом. Нарушив это, мы получим не потерю сообщения,
//! а раскрытие обоих чанков сразу.
//!
//! Альтернатива — случайный nonce рядом с шифротекстом — стоила бы 24 байта
//! на чанк и всё равно требовала бы генератора там, где его может не быть
//! (возобновление после перезапуска перечитывает чанк с диска). Вывод ключа
//! из номера, наоборот, воспроизводим: тот же чанк даёт тот же шифротекст,
//! и возобновление по индексу (§10.2) становится тривиальным.
//!
//! # AAD
//!
//! `file_id ‖ index_be`. Без него чанк можно переставить из одного файла
//! в другой (или на другую позицию), и расшифровка пройдёт — получатель
//! соберёт файл, в котором один кусок не оттуда. Хэш шифротекста поймал бы
//! это в конце, но платить за это целой передачей незачем.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::kdf::{self, Key32};
use crate::labels;

/// Идентификатор файла — он же привязка чанка к своему месту.
pub type FileId = [u8; 16];

/// Ключ файла (§10.1).
pub type FileKey = [u8; 32];

/// Сколько байт добавляет запечатывание чанка.
pub const CHUNK_TAG_LEN: usize = 16;

/// Ключ чанка — он же `chunk_id` из §10.1.
///
/// Значение покрыто тест-вектором `chunk_id`: две независимые реализации
/// обязаны сойтись, иначе файлы не соберутся между разными сборками.
#[must_use]
pub fn chunk_key(file_key: &FileKey, index: u64) -> Key32 {
    kdf::derive_concat(labels::FILE, &[file_key, &index.to_be_bytes()])
}

fn aad(file_id: &FileId, index: u64) -> [u8; 24] {
    let mut aad = [0u8; 24];
    aad[..16].copy_from_slice(file_id);
    aad[16..].copy_from_slice(&index.to_be_bytes());
    aad
}

/// Запечатывает чанк файла.
///
/// Возвращает `plaintext.len() + CHUNK_TAG_LEN` байт.
///
/// # Errors
///
/// [`CryptoError::Decrypt`] — только при отказе примитива; на корректном
/// входе не случается.
pub fn seal_chunk(
    file_key: &FileKey,
    file_id: &FileId,
    index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = chunk_key(file_key, index);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));

    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&[0u8; 24]),
            &aad(file_id, index),
            &mut buffer,
        )
        .map_err(|_| CryptoError::Decrypt)?;

    buffer.extend_from_slice(&tag);
    Ok(buffer)
}

/// Распечатывает чанк файла.
///
/// # Errors
///
/// [`CryptoError::Decrypt`], если тег не сошёлся: чанк испорчен, подменён
/// или переставлен с чужого места.
pub fn open_chunk(
    file_key: &FileKey,
    file_id: &FileId,
    index: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < CHUNK_TAG_LEN {
        return Err(CryptoError::Decrypt);
    }
    let split = sealed.len() - CHUNK_TAG_LEN;
    let key = chunk_key(file_key, index);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key[..]));

    let mut buffer = Zeroizing::new(sealed[..split].to_vec());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&[0u8; 24]),
            &aad(file_id, index),
            buffer.as_mut_slice(),
            sealed[split..].into(),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: FileKey = [7u8; 32];
    const FILE: FileId = [3u8; 16];

    #[test]
    fn a_chunk_round_trips() {
        let sealed = seal_chunk(&KEY, &FILE, 0, b"soderzhimoe").unwrap();
        assert_eq!(sealed.len(), b"soderzhimoe".len() + CHUNK_TAG_LEN);
        assert_eq!(&open_chunk(&KEY, &FILE, 0, &sealed).unwrap()[..], b"soderzhimoe");
    }

    #[test]
    fn a_chunk_cannot_be_moved() {
        // Главное свойство AAD: переставленный чанк не открывается. Хэш
        // шифротекста поймал бы подмену в конце передачи, но платить за это
        // целым файлом незачем.
        let sealed = seal_chunk(&KEY, &FILE, 5, b"pyatyj").unwrap();
        assert!(open_chunk(&KEY, &FILE, 6, &sealed).is_err(), "другой номер");
        assert!(open_chunk(&KEY, &[9u8; 16], 5, &sealed).is_err(), "другой файл");
        assert!(open_chunk(&[8u8; 32], &FILE, 5, &sealed).is_err(), "другой ключ");
    }

    #[test]
    fn a_damaged_chunk_is_refused() {
        let mut sealed = seal_chunk(&KEY, &FILE, 0, b"celyj").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open_chunk(&KEY, &FILE, 0, &sealed).is_err());
        assert!(open_chunk(&KEY, &FILE, 0, &[]).is_err(), "пустой вход — не паника");
    }

    #[test]
    fn sealing_is_reproducible() {
        // На этом стоит возобновление (§10.2): чанк, перечитанный с диска
        // после перезапуска, обязан запечататься теми же байтами — иначе
        // хэш шифротекста у получателя не сойдётся.
        assert_eq!(
            seal_chunk(&KEY, &FILE, 3, b"tot zhe").unwrap(),
            seal_chunk(&KEY, &FILE, 3, b"tot zhe").unwrap()
        );
    }

    #[test]
    fn chunk_keys_are_unique_per_index_and_file() {
        assert_ne!(chunk_key(&KEY, 0), chunk_key(&KEY, 1));
        assert_ne!(chunk_key(&KEY, 0), chunk_key(&[1u8; 32], 0));
        assert_eq!(chunk_key(&KEY, 42), chunk_key(&KEY, 42));
    }
}
