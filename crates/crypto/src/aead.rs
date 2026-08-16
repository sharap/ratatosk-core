//! Запечатывание и распечатывание кадра (§7.2).
//!
//! ```text
//! plaintext  = payload ‖ 0x80 ‖ 0x00 * k
//! ciphertext ‖ tag = XChaCha20-Poly1305(key, nonce, aad = header, plaintext)
//! ```
//!
//! **AAD равен всему заголовку.** Это не оптимизация, а требование §7.2: без
//! него `counter` не аутентифицирован, и подделанный заголовок заставляет
//! получателя выводить тысячи ключей до провала проверки.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ratatosk_wire::{assemble, pad_into, parse, unpad, Header, SizeClass, HEADER_LEN};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Запечатывает полезную нагрузку в готовый кадр.
///
/// Возвращает ровно `class.frame_len()` байт.
pub fn seal(key: &[u8; 32], header: &Header, class: SizeClass, payload: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = Zeroizing::new(Vec::with_capacity(class.plaintext_len()));
    pad_into(payload, class, &mut buffer)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let aad = header.encode();
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&header.nonce), &aad, buffer.as_mut_slice())
        .map_err(|_| CryptoError::Decrypt)?;

    let mut sealed = Vec::with_capacity(class.sealed_len());
    sealed.extend_from_slice(&buffer);
    sealed.extend_from_slice(&tag);
    Ok(assemble(header, &sealed)?)
}

/// Распечатывает кадр и снимает паддинг.
///
/// Ключ выводится вызывающим кодом **ровно для позиции `counter`** из
/// заголовка (§7.3, шаг 3): пропущенные ключи достраиваются только после
/// успешной проверки тега, иначе стоимость мусорного кадра зависела бы от
/// заявленного счётчика.
pub fn open(key: &[u8; 32], frame: &[u8]) -> Result<(Header, Zeroizing<Vec<u8>>)> {
    let view = parse(frame)?;
    let sealed_len = view.sealed.len();
    let ct_len = sealed_len - ratatosk_wire::TAG_LEN;

    let mut buffer = Zeroizing::new(view.sealed[..ct_len].to_vec());
    let tag = &view.sealed[ct_len..];

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let aad = &frame[..HEADER_LEN];
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&view.header.nonce),
            aad,
            buffer.as_mut_slice(),
            tag.into(),
        )
        .map_err(|_| CryptoError::Decrypt)?;

    let payload = unpad(&buffer)?.to_vec();
    Ok((view.header, Zeroizing::new(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatosk_wire::FrameType;

    fn header(counter: u64) -> Header {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        Header::new(FrameType::Data, 42, counter, nonce)
    }

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let frame = seal(&key, &header(1), SizeClass::S, b"hello").unwrap();
        assert_eq!(frame.len(), SizeClass::S.frame_len());
        let (h, payload) = open(&key, &frame).unwrap();
        assert_eq!(h, header(1));
        assert_eq!(&payload[..], b"hello");
    }

    #[test]
    fn empty_payload_round_trips() {
        let key = [7u8; 32];
        let frame = seal(&key, &header(0), SizeClass::S, b"").unwrap();
        let (_, payload) = open(&key, &frame).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn all_classes_round_trip() {
        let key = [7u8; 32];
        for class in SizeClass::ALL {
            let payload = vec![0xABu8; class.max_payload()];
            let frame = seal(&key, &header(2), class, &payload).unwrap();
            assert_eq!(frame.len(), class.frame_len());
            assert_eq!(&open(&key, &frame).unwrap().1[..], &payload[..]);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let frame = seal(&[7u8; 32], &header(1), SizeClass::S, b"x").unwrap();
        assert!(matches!(open(&[8u8; 32], &frame), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_counter_is_rejected() {
        // Главная причина, по которой AAD — весь заголовок (§7.2).
        let key = [7u8; 32];
        let mut frame = seal(&key, &header(1), SizeClass::S, b"x").unwrap();
        frame[10] ^= 0xFF; // старший байт counter
        assert!(matches!(open(&key, &frame), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_session_id_is_rejected() {
        let key = [7u8; 32];
        let mut frame = seal(&key, &header(1), SizeClass::S, b"x").unwrap();
        frame[2] ^= 0x01;
        assert!(matches!(open(&key, &frame), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn tampered_padding_is_rejected() {
        // Паддинг внутри AEAD, поэтому правка любого его байта ловится тегом,
        // а не проверкой формата, — скрытый канал закрыт.
        let key = [7u8; 32];
        let mut frame = seal(&key, &header(1), SizeClass::S, b"x").unwrap();
        let last = frame.len() - ratatosk_wire::TAG_LEN - 1;
        frame[last] ^= 0x01;
        assert!(matches!(open(&key, &frame), Err(CryptoError::Decrypt)));
    }

    #[test]
    fn ciphertext_hides_payload_length() {
        let key = [7u8; 32];
        let short = seal(&key, &header(1), SizeClass::S, b"a").unwrap();
        let long = seal(&key, &header(1), SizeClass::S, &[0u8; 2000]).unwrap();
        assert_eq!(short.len(), long.len());
    }
}
