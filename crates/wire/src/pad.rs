//! Паддинг открытого текста (§7.2).
//!
//! ```text
//! plaintext = payload ‖ 0x80 ‖ 0x00 * k
//! ```
//!
//! Паддинг находится **внутри** AEAD, поэтому он аутентифицирован и не может
//! служить скрытым каналом. Схема ISO/IEC 7816-4: маркер `0x80`, затем нули
//! до размера класса.

use crate::error::WireError;
use crate::size_class::SizeClass;

/// Байт-маркер конца полезной нагрузки.
pub const PAD_MARKER: u8 = 0x80;

/// Длина маркера. Присутствует всегда, поэтому вычитается из `max_payload`.
pub(crate) const PAD_MARKER_LEN: usize = 1;

/// Дополняет полезную нагрузку до открытого текста нужного класса.
///
/// Дописывает в `out` ровно `class.plaintext_len()` байт. Существующее
/// содержимое `out` не трогается — это позволяет собирать кадр в один буфер,
/// начиная с заголовка.
pub fn pad_into(payload: &[u8], class: SizeClass, out: &mut Vec<u8>) -> Result<(), WireError> {
    pad_to(payload, class.plaintext_len(), out)
}

/// Дополняет полезную нагрузку до произвольной длины.
///
/// Нужно кадру рукопожатия (§8.3): его содержимое шифрует сам Noise, нашего
/// тега AEAD там нет, и дополнять надо до всей запечатанной области кадра,
/// а не до `plaintext_len`. Схема паддинга при этом та же — иначе на приёме
/// понадобились бы две разные процедуры снятия.
pub fn pad_to(payload: &[u8], total_len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
    // `checked_sub`, а не `saturating_sub`: при `total_len == 0` насыщение
    // дало бы `max == 0`, пустая нагрузка прошла бы проверку, и функция
    // записала бы один байт маркера вместо нуля запрошенных. Край без места
    // даже под маркер — это ошибка, а не «ноль».
    let max = total_len
        .checked_sub(PAD_MARKER_LEN)
        .ok_or(WireError::PayloadTooLarge { got: payload.len(), max: 0 })?;
    if payload.len() > max {
        return Err(WireError::PayloadTooLarge { got: payload.len(), max });
    }
    out.reserve(total_len);
    out.extend_from_slice(payload);
    out.push(PAD_MARKER);
    out.resize(out.len() + (max - payload.len()), 0u8);
    Ok(())
}

/// Снимает паддинг с расшифрованного открытого текста.
///
/// Вызывается **только после** успешной проверки тега AEAD, поэтому содержимое
/// уже аутентифицировано: постоянное время здесь не требуется, атакующий не
/// может подобрать вход.
pub fn unpad(plaintext: &[u8]) -> Result<&[u8], WireError> {
    let end = plaintext.iter().rposition(|&b| b != 0).ok_or(WireError::MalformedPadding)?;
    if plaintext[end] != PAD_MARKER {
        return Err(WireError::MalformedPadding);
    }
    Ok(&plaintext[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_across_classes() {
        for class in SizeClass::ALL {
            for len in [0usize, 1, 2, 100, class.max_payload()] {
                let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut buf = Vec::new();
                pad_into(&payload, class, &mut buf).unwrap();
                assert_eq!(buf.len(), class.plaintext_len());
                assert_eq!(unpad(&buf).unwrap(), &payload[..]);
            }
        }
    }

    #[test]
    fn payload_ending_in_zeroes_survives() {
        // Главная ловушка схемы: нули в конце нагрузки не должны съедаться.
        let payload = vec![0u8; 64];
        let mut buf = Vec::new();
        pad_into(&payload, SizeClass::S, &mut buf).unwrap();
        assert_eq!(unpad(&buf).unwrap(), &payload[..]);
    }

    #[test]
    fn payload_ending_in_marker_survives() {
        let payload = vec![PAD_MARKER; 8];
        let mut buf = Vec::new();
        pad_into(&payload, SizeClass::S, &mut buf).unwrap();
        assert_eq!(unpad(&buf).unwrap(), &payload[..]);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let payload = vec![1u8; SizeClass::S.max_payload() + 1];
        let mut buf = Vec::new();
        assert!(matches!(
            pad_into(&payload, SizeClass::S, &mut buf),
            Err(WireError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn all_zero_plaintext_is_malformed() {
        assert_eq!(unpad(&[0u8; 32]), Err(WireError::MalformedPadding));
        assert_eq!(unpad(&[]), Err(WireError::MalformedPadding));
    }

    #[test]
    fn wrong_marker_is_malformed() {
        let mut buf = vec![1u8, 2, 3, 0x7f];
        buf.resize(64, 0);
        assert_eq!(unpad(&buf), Err(WireError::MalformedPadding));
    }

    #[test]
    fn pad_to_fills_exactly_the_requested_length() {
        for total in [1usize, 2, 64, 4096] {
            let mut buf = Vec::new();
            pad_to(b"", total, &mut buf).unwrap();
            assert_eq!(buf.len(), total);
            assert_eq!(unpad(&buf).unwrap(), b"");
        }
    }

    #[test]
    fn pad_to_round_trips_a_handshake_sized_message() {
        // Кадр рукопожатия: сообщение Noise дополняется до всей запечатанной
        // области класса S, без места под наш тег.
        let message = vec![0x5Au8; 300];
        let total = SizeClass::S.sealed_len();
        let mut buf = Vec::new();
        pad_to(&message, total, &mut buf).unwrap();
        assert_eq!(buf.len(), total);
        assert_eq!(unpad(&buf).unwrap(), &message[..]);
    }

    #[test]
    fn pad_to_rejects_payload_without_room_for_the_marker() {
        let mut buf = Vec::new();
        assert!(matches!(
            pad_to(&[1u8; 8], 8, &mut buf),
            Err(WireError::PayloadTooLarge { got: 8, max: 7 })
        ));
        assert!(pad_to(&[], 0, &mut buf).is_err());
    }

    #[test]
    fn pad_into_and_pad_to_agree() {
        for class in SizeClass::ALL {
            let payload = b"same payload";
            let mut a = Vec::new();
            let mut b = Vec::new();
            pad_into(payload, class, &mut a).unwrap();
            pad_to(payload, class.plaintext_len(), &mut b).unwrap();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn pad_appends_and_does_not_clobber() {
        let mut buf = vec![0xAAu8; 42];
        pad_into(b"hi", SizeClass::S, &mut buf).unwrap();
        assert_eq!(&buf[..42], &[0xAAu8; 42][..]);
        assert_eq!(buf.len(), 42 + SizeClass::S.plaintext_len());
    }
}
