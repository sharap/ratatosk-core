//! Заголовок кадра (§7.1).
//!
//! ```text
//! header = version(1) ‖ type(1) ‖ session_id(8) ‖ counter(8) ‖ nonce(24)
//! ```
//!
//! Заголовок целиком идёт в AAD (§7.2). Это не деталь реализации, а требование:
//! без него `counter` не аутентифицирован, и подделанный заголовок заставляет
//! получателя выводить тысячи ключей до провала проверки.

use crate::error::WireError;

/// Байт версии кадра. Мажорная версия v0.
pub const WIRE_VERSION: u8 = 0;

/// Длина nonce XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;

/// Длина тега Poly1305.
pub const TAG_LEN: usize = 16;

/// Длина заголовка: 1 + 1 + 8 + 8 + 24.
pub const HEADER_LEN: usize = 1 + 1 + 8 + 8 + NONCE_LEN;

/// Тип кадра (§7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// `0x01` — рукопожатие Noise IK. Идёт с `session_id == 0` (§8.3).
    Handshake,
    /// `0x02` — данные внутри установленной сессии.
    Data,
}

impl FrameType {
    /// Байтовое представление.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            FrameType::Handshake => 0x01,
            FrameType::Data => 0x02,
        }
    }

    /// Разбор байта типа.
    pub fn from_byte(b: u8) -> Result<FrameType, WireError> {
        match b {
            0x01 => Ok(FrameType::Handshake),
            0x02 => Ok(FrameType::Data),
            got => Err(WireError::UnknownFrameType { got }),
        }
    }
}

/// `session_id`, которым помечаются кадры рукопожатия (§8.3).
///
/// Вычислить настоящий `session_id` до завершения рукопожатия нельзя — он
/// выводится из транскрипта Noise. Поэтому handshake-кадры адресуются нулём
/// и обрабатываются отдельной веткой приёма.
pub const HANDSHAKE_SESSION_ID: u64 = 0;

/// Разобранный заголовок кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Версия кадра.
    pub version: u8,
    /// Тип кадра.
    pub frame_type: FrameType,
    /// Идентификатор сессии: первые 8 байт `BLAKE3_derive_key("ratatosk v0 sid", h)`.
    ///
    /// 64 бита, а не 32, — коллизии практически невозможны (§7.1).
    pub session_id: u64,
    /// Номер сообщения в отправляющей цепочке. Монотонный, не сбрасывается.
    pub counter: u64,
    /// Nonce XChaCha20-Poly1305.
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Заголовок кадра данных или рукопожатия текущей версии.
    #[must_use]
    pub const fn new(
        frame_type: FrameType,
        session_id: u64,
        counter: u64,
        nonce: [u8; NONCE_LEN],
    ) -> Header {
        Header { version: WIRE_VERSION, frame_type, session_id, counter, nonce }
    }

    /// Заголовок кадра рукопожатия (`session_id == 0`, §8.3).
    #[must_use]
    pub const fn handshake(nonce: [u8; NONCE_LEN]) -> Header {
        Header::new(FrameType::Handshake, HANDSHAKE_SESSION_ID, 0, nonce)
    }

    /// Сериализация. Порядок байтов — big-endian во всём протоколе.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1] = self.frame_type.to_byte();
        out[2..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..18].copy_from_slice(&self.counter.to_be_bytes());
        out[18..HEADER_LEN].copy_from_slice(&self.nonce);
        out
    }

    /// Разбор. Принимает ровно [`HEADER_LEN`] байт.
    pub fn decode(bytes: &[u8]) -> Result<Header, WireError> {
        if bytes.len() != HEADER_LEN {
            return Err(WireError::SealedLengthMismatch { got: bytes.len(), want: HEADER_LEN });
        }
        let version = bytes[0];
        if version != WIRE_VERSION {
            // Отвергаем с понятной ошибкой, а не «битый кадр»: клиент должен
            // уметь сказать пользователю «обновите приложение» (§6).
            return Err(WireError::UnsupportedVersion { got: version });
        }
        let frame_type = FrameType::from_byte(bytes[1])?;
        let mut eight = [0u8; 8];
        eight.copy_from_slice(&bytes[2..10]);
        let session_id = u64::from_be_bytes(eight);
        eight.copy_from_slice(&bytes[10..18]);
        let counter = u64::from_be_bytes(eight);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[18..HEADER_LEN]);
        Ok(Header { version, frame_type, session_id, counter, nonce })
    }

    /// `true`, если кадр адресован веткой рукопожатия.
    #[must_use]
    pub const fn is_handshake(&self) -> bool {
        matches!(self.frame_type, FrameType::Handshake)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        let mut nonce = [0u8; NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        Header::new(FrameType::Data, 0xdead_beef_cafe_f00d, 0x0102_0304_0506_0708, nonce)
    }

    #[test]
    fn header_len_matches_spec() {
        assert_eq!(HEADER_LEN, 42);
    }

    #[test]
    fn round_trip() {
        let h = sample();
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn big_endian_layout_is_stable() {
        // Раскладка входит в AAD, поэтому она — часть протокола, а не деталь.
        let h = sample();
        let bytes = h.encode();
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 0x02);
        assert_eq!(&bytes[2..10], &0xdead_beef_cafe_f00du64.to_be_bytes());
        assert_eq!(&bytes[10..18], &0x0102_0304_0506_0708u64.to_be_bytes());
    }

    #[test]
    fn rejects_future_version() {
        let mut bytes = sample().encode();
        bytes[0] = 1;
        assert_eq!(Header::decode(&bytes), Err(WireError::UnsupportedVersion { got: 1 }));
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = sample().encode();
        bytes[1] = 0x03;
        assert_eq!(Header::decode(&bytes), Err(WireError::UnknownFrameType { got: 0x03 }));
    }

    #[test]
    fn handshake_header_carries_zero_session() {
        let h = Header::handshake([0u8; NONCE_LEN]);
        assert!(h.is_handshake());
        assert_eq!(h.session_id, HANDSHAKE_SESSION_ID);
        assert_eq!(h.counter, 0);
    }
}
