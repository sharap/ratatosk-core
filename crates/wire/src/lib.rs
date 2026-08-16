//! Формат кадра Ratatosk v0.1.
//!
//! Крейт описывает **только байты на проводе**: раскладку заголовка, классы
//! размера и паддинг. Он ничего не шифрует и не знает про сессии — шифрование
//! живёт в `ratatosk-crypto`, которому этот крейт отдаёт готовый заголовок
//! в качестве AAD.
//!
//! Разделение сделано ради §16: разбор кадра фаззится с первого дня, и фаззер
//! не должен тянуть за собой криптостек, SQLite и arti.
//!
//! Соответствие спецификации: §5.5 (классы размера), §7 (кадр).
//!
//! ```
//! use ratatosk_wire::{Header, FrameType, SizeClass, assemble, parse};
//!
//! let header = Header::new(FrameType::Data, 0x0102_0304_0506_0708, 42, [7u8; 24]);
//! let sealed = vec![0u8; SizeClass::S.sealed_len()];
//! let frame = assemble(&header, &sealed).unwrap();
//!
//! let view = parse(&frame).unwrap();
//! assert_eq!(view.class, SizeClass::S);
//! assert_eq!(view.header.counter, 42);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod frame;
mod header;
mod pad;
mod size_class;

pub use error::WireError;
pub use frame::{assemble, assemble_into, parse, FrameView};
pub use header::{
    FrameType, Header, HANDSHAKE_SESSION_ID, HEADER_LEN, NONCE_LEN, TAG_LEN, WIRE_VERSION,
};
pub use pad::{pad_into, pad_to, unpad, PAD_MARKER};
pub use size_class::SizeClass;
