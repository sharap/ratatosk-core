//! Сборка и разбор кадра целиком (§7).
//!
//! ```text
//! frame = header ‖ ciphertext ‖ tag
//! ```
//!
//! Крейт не шифрует: [`assemble`] принимает уже запечатанные байты, [`parse`]
//! возвращает их как срез. Ключи и AEAD — в `ratatosk-crypto`.

use crate::error::WireError;
use crate::header::{Header, HEADER_LEN};
use crate::size_class::SizeClass;

/// Разобранный кадр: заголовок и ссылка на запечатанную часть.
///
/// Заимствует исходный буфер, поэтому разбор не копирует мегабайтные кадры
/// класса L.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameView<'a> {
    /// Разобранный заголовок. Его же байты идут в AAD при расшифровании.
    pub header: Header,
    /// Шифротекст вместе с тегом Poly1305.
    pub sealed: &'a [u8],
    /// Класс размера, определённый по длине кадра.
    pub class: SizeClass,
}

impl<'a> FrameView<'a> {
    /// Байты заголовка, которые надо передать как AAD (§7.2).
    ///
    /// Пересобираются из разобранной структуры, а не берутся срезом исходного
    /// буфера, — но это безопасно: `decode`/`encode` биективны для всех
    /// заголовков, прошедших разбор (см. тест `aad_matches_original_bytes`).
    #[must_use]
    pub fn aad(&self) -> [u8; HEADER_LEN] {
        self.header.encode()
    }
}

/// Разбирает байты, полученные из транспорта.
///
/// Порядок проверок соответствует §7.3: сначала длина (самая дешёвая проверка,
/// отсекает основную массу мусора), затем версия и тип. Поиск сессии, вывод
/// ключа и проверка тега — уже за пределами этого крейта.
pub fn parse(bytes: &[u8]) -> Result<FrameView<'_>, WireError> {
    let class = SizeClass::from_frame_len(bytes.len())?;
    let header = Header::decode(&bytes[..HEADER_LEN])?;
    Ok(FrameView { header, sealed: &bytes[HEADER_LEN..], class })
}

/// Собирает кадр из заголовка и запечатанной части.
///
/// Класс определяется по длине `sealed`: она однозначно задаёт размер кадра.
pub fn assemble(header: &Header, sealed: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    assemble_into(header, sealed, &mut out)?;
    Ok(out)
}

/// То же, что [`assemble`], но дописывает в существующий буфер.
pub fn assemble_into(header: &Header, sealed: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    let class = SizeClass::ALL.into_iter().find(|c| c.sealed_len() == sealed.len()).ok_or(
        WireError::SealedLengthMismatch { got: sealed.len(), want: SizeClass::S.sealed_len() },
    )?;
    debug_assert_eq!(class.frame_len(), HEADER_LEN + sealed.len());
    out.reserve(class.frame_len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(sealed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{FrameType, NONCE_LEN};

    fn header() -> Header {
        Header::new(FrameType::Data, 77, 1234, [9u8; NONCE_LEN])
    }

    #[test]
    fn round_trip_all_classes() {
        for class in SizeClass::ALL {
            let sealed = vec![0x5Au8; class.sealed_len()];
            let frame = assemble(&header(), &sealed).unwrap();
            assert_eq!(frame.len(), class.frame_len());

            let view = parse(&frame).unwrap();
            assert_eq!(view.class, class);
            assert_eq!(view.header, header());
            assert_eq!(view.sealed, &sealed[..]);
        }
    }

    #[test]
    fn aad_matches_original_bytes() {
        let sealed = vec![0u8; SizeClass::S.sealed_len()];
        let frame = assemble(&header(), &sealed).unwrap();
        let view = parse(&frame).unwrap();
        assert_eq!(&view.aad()[..], &frame[..HEADER_LEN]);
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let sealed = vec![0u8; SizeClass::S.sealed_len()];
        let frame = assemble(&header(), &sealed).unwrap();
        assert!(parse(&frame[..frame.len() - 1]).is_err());
        assert!(parse(&frame[..HEADER_LEN]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn assemble_rejects_off_size_sealed() {
        assert!(assemble(&header(), &[0u8; 10]).is_err());
    }

    /// Мини-фаззер: разбор не должен паниковать ни на каком входе.
    /// Настоящий `cargo-fuzz` (§16) работает по тому же контракту.
    #[test]
    fn parse_never_panics() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for len in [0usize, 1, 41, 42, 4095, 4096, 4097, 65536] {
            for _ in 0..64 {
                let bytes: Vec<u8> = (0..len)
                    .map(|_| {
                        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                        (state >> 33) as u8
                    })
                    .collect();
                let _ = parse(&bytes);
            }
        }
    }
}
