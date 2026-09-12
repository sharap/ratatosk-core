//! Криптостек Ratatosk v0.1 (§3, §8).
//!
//! §8.1 формулирует правило, которому подчинён весь крейт: «Собственных
//! реализаций примитивов нет. Собственный код — только их комбинирование,
//! в одном модуле, покрытом тест-векторами.» Этот крейт и есть тот модуль.
//! Примитивы берутся из `blake3`, `x25519-dalek`, `ed25519-dalek`,
//! `chacha20poly1305`, `argon2` и `snow`; здесь только их связывание.
//!
//! Что где лежит:
//!
//! | Модуль | Раздел спецификации |
//! |---|---|
//! | [`labels`] | контексты деривации, все сразу |
//! | [`kdf`] | §8.1, обёртка над `BLAKE3::derive_key` |
//! | [`identity`] | §3 идентичность, отпечаток, §5.1 маяк LAN |
//! | [`onion`] | §3 `onion_key`, §5.2 адрес сервиса |
//! | [`mesh`] | ключ своего узла в меше Yggdrasil (0.2) |
//! | [`aead`] | §7.2 запечатывание кадра |
//! | [`file`] | §10.1 ключи и запечатывание чанков файла |
//! | [`handshake`] | §8.2 Noise IK, §8.3 сессия, §8.5 перерукопожатие |
//! | [`ratchet`] | §8.4 симметричный ретчет, §11.1 sender keys |
//! | [`storage_key`] | §8.6 `db_key` из PIN |
//!
//! Чего здесь нет и не будет в v1: DH-шага в ретчете (§8.5), пула
//! одноразовых предключей (§8.2 — в `IK` он не нужен), PoW (§15 — в `IK`
//! получатель не перебирает контакты), криптографической эвикции из групп
//! (§15).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod companion;
pub mod error;
pub mod file;
pub mod group;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod labels;
pub mod mesh;
pub mod nostr;
pub mod onion;
pub mod ratchet;
pub mod storage_key;

pub use error::{CryptoError, Result};
pub use file::{FileId, FileKey};
pub use handshake::{
    Accepted, Admission, HandshakeOutcome, HandshakeReplayGuard, Initiator, PendingHandshake,
    RekeyPolicy, Responder, Role, Session,
};
pub use identity::{Identity, PublicIdentity};
pub use kdf::Key32;
pub use mesh::MeshKey;
pub use onion::OnionKey;
