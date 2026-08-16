//! Идентичность устройства (§3).
//!
//! Одна идентичность на установку. Мультиустройственность и персоны — вне v1;
//! десктоп идентичности не имеет вовсе и работает компаньоном к телефону
//! (§13.4).
//!
//! Весь ключевой материал выводится из 32 байт CSPRNG. Исключение —
//! `onion_key`: его формат задан спецификацией Tor, поэтому он генерируется
//! независимо и в seed не входит. Практическое следствие, которое обязано
//! быть в UI: резервная фраза возвращает `IK`/`SK`, но **не** onion-адрес.

use std::sync::OnceLock;

use data_encoding::Encoding;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};
use crate::kdf;
use crate::labels;

/// Длина seed и всех выводимых из него ключей.
pub const SEED_LEN: usize = 32;

/// Сколько групп показывается в отпечатке (§3).
pub const FINGERPRINT_GROUPS: usize = 6;
/// Символов в группе.
pub const FINGERPRINT_GROUP_LEN: usize = 4;
/// Сколько байт отпечатка реально доходит до пользователя.
///
/// 6 групп по 4 символа base32 — это 24 символа, то есть 120 бит.
/// Спецификация (§3) говорит «первые 32 байта», но в 24 символа помещается
/// 15 байт; больше показать нельзя, не меняя формат отображения.
/// 120 бит для сверки голосом более чем достаточно, но расхождение
/// с текстом §3 стоит зафиксировать явно, а не сгладить молча.
pub const FINGERPRINT_BYTES: usize = 15;

/// Алфавит base32 без похожих знаков (Crockford: без I, L, O, U).
fn fingerprint_encoding() -> &'static Encoding {
    static ENC: OnceLock<Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("0123456789ABCDEFGHJKMNPQRSTVWXYZ");
        spec.encoding().expect("алфавит из 32 различных символов корректен")
    })
}

/// Публичная часть идентичности — то, что уезжает в контакт-карточке (§4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicIdentity {
    /// Статический ключ Noise.
    pub ik: [u8; 32],
    /// Ключ проверки подписи.
    pub sk: [u8; 32],
}

impl PublicIdentity {
    /// Собирает из сырых байтов, проверяя, что `SK` — корректная точка Ed25519.
    pub fn from_bytes(ik: [u8; 32], sk: [u8; 32]) -> Result<PublicIdentity> {
        VerifyingKey::from_bytes(&sk).map_err(|_| CryptoError::BadKeyMaterial)?;
        Ok(PublicIdentity { ik, sk })
    }

    /// Отпечаток для сверки людьми (§3).
    ///
    /// `BLAKE3(IK ‖ SK)`, затем base32 без похожих знаков, 6 групп по 4.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.ik);
        hasher.update(&self.sk);
        let digest = hasher.finalize();

        let text = fingerprint_encoding().encode(&digest.as_bytes()[..FINGERPRINT_BYTES]);
        text.as_bytes()
            .chunks(FINGERPRINT_GROUP_LEN)
            .take(FINGERPRINT_GROUPS)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Проверяет подпись, сделанную `SK` этой идентичности.
    ///
    /// Используется для групповых блоков и `CardUpdate` (§4.3, §11.1).
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let key = VerifyingKey::from_bytes(&self.sk).map_err(|_| CryptoError::BadKeyMaterial)?;
        key.verify(message, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::BadKeyMaterial)
    }
}

/// Секретная часть идентичности.
///
/// `Drop` затирает материал. Копий быть не должно: тип намеренно не `Clone`.
pub struct Identity {
    seed: Zeroizing<[u8; SEED_LEN]>,
    ik_secret: StaticSecret,
    sk_secret: SigningKey,
    public: PublicIdentity,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Секреты не печатаются никогда: строка из Debug рано или поздно
        // окажется в логе.
        f.debug_struct("Identity").field("fingerprint", &self.public.fingerprint()).finish()
    }
}

impl Identity {
    /// Создаёт идентичность из 32 байт CSPRNG.
    ///
    /// Seed передаётся аргументом, а не читается изнутри: это позволяет
    /// прогонять тест-векторы и симуляцию на фиксированных значениях.
    /// Боевой вызов — [`Identity::generate`].
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Identity {
        let ik_bytes = kdf::derive(labels::IK, &seed);
        let sk_bytes = kdf::derive(labels::SK, &seed);

        let ik_secret = StaticSecret::from(*ik_bytes);
        let sk_secret = SigningKey::from_bytes(&sk_bytes);
        let public = PublicIdentity {
            ik: XPublicKey::from(&ik_secret).to_bytes(),
            sk: sk_secret.verifying_key().to_bytes(),
        };

        Identity { seed: Zeroizing::new(seed), ik_secret, sk_secret, public }
    }

    /// Создаёт идентичность из системного CSPRNG.
    #[must_use]
    pub fn generate() -> Identity {
        use rand_core::RngCore;
        let mut seed = [0u8; SEED_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        let id = Identity::from_seed(seed);
        seed.zeroize();
        id
    }

    /// Публичная часть.
    #[must_use]
    pub fn public(&self) -> PublicIdentity {
        self.public
    }

    /// Отпечаток для сверки (§3).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.public.fingerprint()
    }

    /// Секретный `IK` — только для Noise-рукопожатия (§8.2).
    #[must_use]
    pub fn ik_secret(&self) -> &StaticSecret {
        &self.ik_secret
    }

    /// Сырые байты секретного `IK` — их требует `snow` при сборке сессии.
    #[must_use]
    pub fn ik_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.ik_secret.to_bytes())
    }

    /// Подписывает сообщение ключом `SK`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.sk_secret.sign(message).to_bytes()
    }

    /// Seed для резервной копии.
    ///
    /// Показывается пользователю как 24 слова BIP39 и **не** должен попадать
    /// ни в логи, ни в экспорт переписки. Формулировка в UI по §3: «эта фраза
    /// вернёт вам ваш адрес, но не ваши сообщения».
    #[must_use]
    pub fn backup_seed(&self) -> &[u8; SEED_LEN] {
        &self.seed
    }
}

/// Маяк mDNS для LAN-обнаружения (§5.1).
///
/// ```text
/// beacon = nonce(8) ‖ BLAKE3_derive_key("ratatosk v0 beacon", IK ‖ floor(unix/900) ‖ nonce)[0..8]
/// ```
///
/// Статический идентификатор в эфир не транслируется никогда: посторонний
/// видит шум, меняющийся каждые 15 минут. Контакт пересчитывает значение для
/// каждого известного `IK` и слотов −1, 0, +1.
pub mod beacon {
    use super::labels;

    /// Длина слота ротации — 15 минут в секундах (§5.1).
    pub const SLOT_SECONDS: u64 = 900;

    /// Номер слота для момента времени.
    #[must_use]
    pub const fn slot(unix_seconds: u64) -> u64 {
        unix_seconds / SLOT_SECONDS
    }

    /// Вычисляет значение маяка.
    #[must_use]
    pub fn compute(ik: &[u8; 32], slot: u64, nonce: &[u8; 8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        let mut hasher = blake3::Hasher::new_derive_key(labels::BEACON);
        hasher.update(ik);
        hasher.update(&slot.to_be_bytes());
        hasher.update(nonce);
        hasher.finalize_xof().fill(&mut out);
        out
    }

    /// Полная TXT-запись: `nonce ‖ значение`.
    #[must_use]
    pub fn record(ik: &[u8; 32], slot: u64, nonce: [u8; 8]) -> [u8; 16] {
        let value = compute(ik, slot, &nonce);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&nonce);
        out[8..].copy_from_slice(&value);
        out
    }

    /// Проверяет запись против известного `IK` со слотами −1, 0, +1 (§5.1).
    ///
    /// Три слота нужны из-за расхождения часов: без соседних слотов контакт
    /// становится невидимым каждые 15 минут на границе.
    #[must_use]
    pub fn matches(record: &[u8; 16], ik: &[u8; 32], current_slot: u64) -> bool {
        let nonce: [u8; 8] = record[..8].try_into().expect("срез длины 8");
        let claimed: [u8; 8] = record[8..].try_into().expect("срез длины 8");
        [current_slot.wrapping_sub(1), current_slot, current_slot.wrapping_add(1)]
            .into_iter()
            .any(|s| compute(ik, s, &nonce) == claimed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> [u8; SEED_LEN] {
        [byte; SEED_LEN]
    }

    #[test]
    fn identity_is_deterministic_from_seed() {
        let a = Identity::from_seed(seed(1));
        let b = Identity::from_seed(seed(1));
        assert_eq!(a.public(), b.public());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn different_seeds_give_different_identities() {
        assert_ne!(Identity::from_seed(seed(1)).public(), Identity::from_seed(seed(2)).public());
    }

    #[test]
    fn ik_and_sk_are_independent() {
        // Оба выводятся из одного seed, но разными контекстами (§3).
        let id = Identity::from_seed(seed(3));
        assert_ne!(id.public().ik, id.public().sk);
    }

    #[test]
    fn fingerprint_shape_matches_spec() {
        let fp = Identity::from_seed(seed(4)).fingerprint();
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), FINGERPRINT_GROUPS);
        for g in groups {
            assert_eq!(g.len(), FINGERPRINT_GROUP_LEN);
            assert!(
                g.chars().all(|c| !matches!(c, 'I' | 'L' | 'O' | 'U')),
                "в отпечатке не должно быть похожих знаков: {g}"
            );
        }
    }

    #[test]
    fn signature_round_trip() {
        let id = Identity::from_seed(seed(5));
        let sig = id.sign(b"group block");
        assert!(id.public().verify(b"group block", &sig).is_ok());
        assert!(id.public().verify(b"group blocc", &sig).is_err());
    }

    #[test]
    fn foreign_key_does_not_verify() {
        let a = Identity::from_seed(seed(6));
        let b = Identity::from_seed(seed(7));
        let sig = a.sign(b"x");
        assert!(b.public().verify(b"x", &sig).is_err());
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let id = Identity::from_seed(seed(8));
        let text = format!("{id:?}");
        assert!(!text.contains("seed"));
        assert!(text.contains(&id.fingerprint()));
    }

    #[test]
    fn beacon_rotates_every_slot() {
        let ik = [9u8; 32];
        let nonce = [1u8; 8];
        assert_ne!(beacon::compute(&ik, 100, &nonce), beacon::compute(&ik, 101, &nonce));
    }

    #[test]
    fn beacon_matches_neighbouring_slots() {
        let ik = [9u8; 32];
        let rec = beacon::record(&ik, 100, [7u8; 8]);
        for s in [99, 100, 101] {
            assert!(beacon::matches(&rec, &ik, s), "слот {s} должен приниматься");
        }
        assert!(!beacon::matches(&rec, &ik, 102));
    }

    #[test]
    fn beacon_hides_identity_from_strangers() {
        let mine = [9u8; 32];
        let other = [8u8; 32];
        let rec = beacon::record(&mine, 100, [7u8; 8]);
        assert!(!beacon::matches(&rec, &other, 100), "посторонний не должен узнавать контакт");
    }

    #[test]
    fn beacon_slot_length_is_fifteen_minutes() {
        assert_eq!(beacon::SLOT_SECONDS, 15 * 60);
        assert_eq!(beacon::slot(899), 0);
        assert_eq!(beacon::slot(900), 1);
    }
}
