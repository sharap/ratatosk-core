//! Ключ onion-сервиса v3 и его адрес (§3, §5.2).
//!
//! §3 выносит `onion_key` из общего зерна: его формат задан спецификацией
//! Tor, а не нами, поэтому он генерируется независимо и в резервную фразу
//! не входит. Практическое следствие, которое обязано доходить до человека:
//! фраза возвращает `IK` и `SK`, то есть саму личность и все проверенные
//! отпечатки, но **не** onion-адрес. Адрес переживает только перенос базы.
//!
//! Ключ заводится здесь и хранится запечатанным в нашей базе — но с оговоркой,
//! которую надо назвать прямо, а не спрятать. **Работать arti умеет только
//! с ключом на диске.** Своё хранилище ключей он заполняет сам, снаружи в него
//! не положить, а чужое читает лишь в формате C Tor — то есть из открытого
//! файла. Поэтому запечатанное зерно здесь — источник и резервная копия,
//! а рядом с ним неизбежно живёт открытая рабочая копия
//! ([`OnionKey::ctor_secret_file`]). Шифрование базы её не покрывает,
//! и PIN (§8.6) её не защищает.
//!
//! Что это даёт взамен: адрес принадлежит базе. Он считается до всякого
//! bootstrap — а значит, карточку (§4.1) человек показывает сразу, не дожидаясь
//! десятков секунд подъёма сети, — и переживает восстановление базы на другом
//! устройстве. Отдай мы ключ arti целиком, адрес существовал бы только в его
//! каталоге и терялся вместе с ним.
//!
//! Расчёт адреса дословно повторяет rend-spec-v3:
//!
//! ```text
//! CHECKSUM = SHA3-256(".onion checksum" ‖ PUBKEY ‖ VERSION)[..2]
//! address  = base32(PUBKEY ‖ CHECKSUM ‖ VERSION) + ".onion"
//! ```
//!
//! Отсюда две зависимости, которых §8.1 требует объяснять поимённо: `sha3`
//! для контрольной суммы адреса и `sha2` для разложения ключа по RFC 8032.
//! Ни один из хэшей здесь не выбран нами: первый задан форматом адреса,
//! второй — форматом ключа Ed25519.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Sha512;
// `Digest` у `sha2` и `sha3` — один и тот же типаж из крейта `digest`,
// поэтому импортируется один раз. Разойдись поколения `digest`, сборка
// упала бы прямо здесь, и это лучше, чем два одинаковых имени в области
// видимости.
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Длина зерна ключа onion-сервиса.
pub const ONION_SEED_LEN: usize = 32;

/// Длина адреса без суффикса — 56 символов base32.
pub const ONION_ADDRESS_LEN: usize = 56;

/// Суффикс onion-адреса.
pub const ONION_SUFFIX: &str = ".onion";

/// Версия адреса (rend-spec-v3). Вторая версия отменена и не поддерживается.
const ADDRESS_VERSION: u8 = 3;

/// Контекст контрольной суммы, из rend-spec-v3 дословно.
const CHECKSUM_CONTEXT: &[u8] = b".onion checksum";

/// Сколько байт хэша попадает в адрес.
const CHECKSUM_LEN: usize = 2;

/// Что кодируется в адрес: открытый ключ, сумма, версия.
const ADDRESS_BYTES: usize = 32 + CHECKSUM_LEN + 1;

/// Длина расширенного секретного ключа Ed25519 (RFC 8032 §5.1.5).
pub const EXPANDED_SECRET_LEN: usize = 64;

/// Имя файла с секретным ключом сервиса в раскладке C Tor.
pub const CTOR_SECRET_FILE: &str = "hs_ed25519_secret_key";
/// Имя файла с открытым ключом сервиса в раскладке C Tor.
pub const CTOR_PUBLIC_FILE: &str = "hs_ed25519_public_key";
/// Имя файла с адресом сервиса в раскладке C Tor.
pub const CTOR_HOSTNAME_FILE: &str = "hostname";

/// Заголовок файла секретного ключа, дословно как у C Tor.
const CTOR_SECRET_TAG: &[u8] = b"== ed25519v1-secret: type0 ==";
/// Заголовок файла открытого ключа, дословно как у C Tor.
const CTOR_PUBLIC_TAG: &[u8] = b"== ed25519v1-public: type0 ==";
/// Длина поля заголовка: строка, дополненная нулями.
const CTOR_TAG_LEN: usize = 32;

/// Долговременный ключ onion-сервиса этого устройства.
///
/// Хранится зерном: 32 байта, из которых Ed25519 выводит пару по RFC 8032.
/// В базе лежит запечатанным `db_key` (§8.6), как и зерно личности.
pub struct OnionKey {
    seed: Zeroizing<[u8; ONION_SEED_LEN]>,
    public: [u8; 32],
}

impl OnionKey {
    /// Заводит новый ключ из CSPRNG.
    #[must_use]
    pub fn generate() -> OnionKey {
        use rand_core::RngCore;
        let mut seed = [0u8; ONION_SEED_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        OnionKey::from_seed(seed)
    }

    /// Восстанавливает ключ из зерна.
    #[must_use]
    pub fn from_seed(seed: [u8; ONION_SEED_LEN]) -> OnionKey {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        OnionKey { seed: Zeroizing::new(seed), public }
    }

    /// Зерно — то, что уезжает в базу запечатанным.
    #[must_use]
    pub fn seed(&self) -> &[u8; ONION_SEED_LEN] {
        &self.seed
    }

    /// Открытый ключ сервиса.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Адрес вида `<56 символов>.onion`.
    #[must_use]
    pub fn address(&self) -> String {
        address_of(&self.public)
    }

    /// Ключ подписи — то, что нужно отдать arti при публикации сервиса.
    ///
    /// Отдаётся копией и живёт ровно столько, сколько нужно вызывающему:
    /// [`SigningKey`] затирает себя при уничтожении.
    #[must_use]
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
}

impl OnionKey {
    /// Расширенный секретный ключ по RFC 8032 §5.1.5.
    ///
    /// `SHA-512(зерно)` с клампингом: младшие три бита первого байта в ноль,
    /// старший бит последнего в ноль, следующий за ним — в единицу. Первые
    /// 32 байта служат скаляром, вторые — префиксом подписи.
    ///
    /// Считается здесь, а не берётся у `ed25519-dalek`, по одной причине:
    /// dalek хранит скаляр как `Scalar`, а тот вправе привести значение
    /// по модулю порядка группы. Клампованный скаляр заведомо больше порядка,
    /// поэтому приведённые байты — **другие**, и Tor такой ключ не примет.
    /// Разница проявилась бы не ошибкой, а чужим onion-адресом.
    #[must_use]
    pub fn expanded_secret(&self) -> Zeroizing<[u8; EXPANDED_SECRET_LEN]> {
        let mut hasher = Sha512::new();
        hasher.update(&self.seed[..]);
        let digest = hasher.finalize();

        let mut expanded = Zeroizing::new([0u8; EXPANDED_SECRET_LEN]);
        expanded.copy_from_slice(&digest);
        expanded[0] &= 248;
        expanded[31] &= 127;
        expanded[31] |= 64;
        expanded
    }

    /// Содержимое файла `hs_ed25519_secret_key` (раскладка C Tor).
    ///
    /// Нужно потому, что arti читает **чужое** хранилище ключей только
    /// в формате C Tor: своё он заполняет сам и снаружи в него не положить.
    /// Формат простой и стабильный — 32 байта заголовка и 64 байта ключа, —
    /// в отличие от внутреннего формата arti, который меняется вместе с ним.
    #[must_use]
    pub fn ctor_secret_file(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0u8; CTOR_TAG_LEN + EXPANDED_SECRET_LEN]);
        out[..CTOR_SECRET_TAG.len()].copy_from_slice(CTOR_SECRET_TAG);
        out[CTOR_TAG_LEN..].copy_from_slice(&self.expanded_secret()[..]);
        out
    }

    /// Содержимое файла `hs_ed25519_public_key` (раскладка C Tor).
    #[must_use]
    pub fn ctor_public_file(&self) -> Vec<u8> {
        let mut out = vec![0u8; CTOR_TAG_LEN + 32];
        out[..CTOR_PUBLIC_TAG.len()].copy_from_slice(CTOR_PUBLIC_TAG);
        out[CTOR_TAG_LEN..].copy_from_slice(&self.public);
        out
    }

    /// Содержимое файла `hostname` (раскладка C Tor).
    ///
    /// С переводом строки на конце: так пишет C Tor, и разбирающий его код
    /// на этот перевод рассчитывает.
    #[must_use]
    pub fn ctor_hostname_file(&self) -> Vec<u8> {
        let mut out = self.address().into_bytes();
        out.push(b'\n');
        out
    }
}

/// Без зерна: сокрытие в `Debug` дешевле, чем разбор утёкшего лога.
impl core::fmt::Debug for OnionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OnionKey").field("address", &self.address()).finish_non_exhaustive()
    }
}

/// Адрес по открытому ключу сервиса.
#[must_use]
pub fn address_of(public: &[u8; 32]) -> String {
    let mut raw = [0u8; ADDRESS_BYTES];
    raw[..32].copy_from_slice(public);
    raw[32..34].copy_from_slice(&checksum(public));
    raw[34] = ADDRESS_VERSION;

    let mut text = BASE32_NOPAD.encode(&raw);
    text.make_ascii_lowercase();
    text.push_str(ONION_SUFFIX);
    text
}

/// Открытый ключ по адресу — с проверкой суммы, версии и самой точки.
///
/// Суффикс `.onion` необязателен, регистр не важен: адрес приходит из
/// карточки, набранной руками, вставленной из буфера или прочитанной с QR.
///
/// Проверяется всё, что можно проверить, — и в этом смысл функции. Адрес
/// приходит из карточки, а карточку §14 запрещает принимать на веру: одна
/// испорченная буква даёт адрес, который никогда не ответит, и без проверки
/// суммы это выяснилось бы через 45 секунд молчания вместо мгновенного
/// «карточка испорчена».
///
/// # Errors
///
/// [`CryptoError::BadKeyMaterial`] — не та длина, не тот алфавит, не сошлась
/// сумма, не та версия или ключ не является точкой Ed25519.
pub fn public_of(address: &str) -> Result<[u8; 32]> {
    // Разбор идёт по байтам, а не по символам, и на то две причины.
    //
    // Первая: суффикс отрезается **без учёта регистра**. Адрес, скопированный
    // целиком заглавными, оканчивается на `.ONION`, и `strip_suffix(".onion")`
    // его не узнаёт — обещание «регистр не важен» держалось бы только
    // до последней точки.
    //
    // Вторая: сюда приходит любая строка, включая не-ASCII. Резать `&str`
    // по вычисленному смещению значило бы падать на границе символа, а не
    // возвращать «не адрес».
    let bytes = address.as_bytes();
    let body = match bytes.len().checked_sub(ONION_SUFFIX.len()) {
        Some(cut) if bytes[cut..].eq_ignore_ascii_case(ONION_SUFFIX.as_bytes()) => &bytes[..cut],
        _ => bytes,
    };
    if body.len() != ONION_ADDRESS_LEN {
        return Err(CryptoError::BadKeyMaterial);
    }

    let mut upper = body.to_vec();
    upper.make_ascii_uppercase();
    let raw = BASE32_NOPAD.decode(&upper).map_err(|_| CryptoError::BadKeyMaterial)?;
    if raw.len() != ADDRESS_BYTES {
        return Err(CryptoError::BadKeyMaterial);
    }

    let public: [u8; 32] = raw[..32].try_into().map_err(|_| CryptoError::BadKeyMaterial)?;
    if raw[34] != ADDRESS_VERSION {
        return Err(CryptoError::BadKeyMaterial);
    }
    if raw[32..34] != checksum(&public)[..] {
        return Err(CryptoError::BadKeyMaterial);
    }
    VerifyingKey::from_bytes(&public).map_err(|_| CryptoError::BadKeyMaterial)?;

    Ok(public)
}

/// Похоже ли это на настоящий onion-адрес v3.
#[must_use]
pub fn is_address(text: &str) -> bool {
    public_of(text).is_ok()
}

fn checksum(public: &[u8; 32]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha3_256::new();
    hasher.update(CHECKSUM_CONTEXT);
    hasher.update(public);
    hasher.update([ADDRESS_VERSION]);
    let digest = hasher.finalize();

    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Настоящий адрес из сети Tor — DuckDuckGo. Тест-вектор здесь нужен
    /// именно чужой: собственный расчёт, сверенный сам с собой, подтвердил бы
    /// только то, что код не изменился, а не то, что он совместим.
    const KNOWN_ADDRESS: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    const KNOWN_PUBLIC: &str = "1d04a1d04a338c6e6ae970bfabee49049d6702250984ca950c01673f4ec034ad";

    fn known_public() -> [u8; 32] {
        let bytes = hex::decode(KNOWN_PUBLIC).unwrap();
        bytes.try_into().unwrap()
    }

    #[test]
    fn the_address_matches_a_real_one_from_the_network() {
        assert_eq!(address_of(&known_public()), KNOWN_ADDRESS);
        assert_eq!(public_of(KNOWN_ADDRESS).unwrap(), known_public());
    }

    #[test]
    fn the_seed_determines_the_address() {
        // Зерно — первый тест-вектор RFC 8032 (Ed25519, TEST 1). Адрес
        // посчитан по rend-spec-v3 и зафиксирован: если он поедет,
        // все выданные карточки станут недействительны молча.
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let key = OnionKey::from_seed(seed);
        assert_eq!(
            hex::encode(key.public()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(key.address(), "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion");
    }

    #[test]
    fn the_same_seed_gives_the_same_address() {
        let key = OnionKey::generate();
        let again = OnionKey::from_seed(*key.seed());
        assert_eq!(key.address(), again.address(), "перезапуск не вправе менять адрес");
        assert_eq!(public_of(&key.address()).unwrap(), key.public());
    }

    #[test]
    fn two_devices_get_two_addresses() {
        assert_ne!(OnionKey::generate().address(), OnionKey::generate().address());
    }

    #[test]
    fn one_wrong_letter_is_noticed_at_once() {
        // Ради этого свойства в адресе и живёт контрольная сумма: опечатка
        // обязана обнаружиться сразу, а не 45 секундами молчания позже (§5.4).
        let mut broken = KNOWN_ADDRESS.to_owned();
        broken.replace_range(0..1, "e");
        assert!(!is_address(&broken));
    }

    #[test]
    fn the_suffix_is_optional_and_the_case_is_not_important() {
        let body = KNOWN_ADDRESS.strip_suffix(ONION_SUFFIX).unwrap();
        assert_eq!(public_of(body).unwrap(), known_public());
        assert_eq!(public_of(&body.to_uppercase()).unwrap(), known_public());

        // Суффикс тоже приходит заглавными — целиком скопированный адрес
        // выглядит именно так. Первая редакция отрезала ровно `.onion`
        // и на этой строке отказывала.
        assert_eq!(public_of(&KNOWN_ADDRESS.to_uppercase()).unwrap(), known_public());
        let mixed = format!("{body}.OnIoN");
        assert_eq!(public_of(&mixed).unwrap(), known_public());
    }

    #[test]
    fn a_string_of_any_bytes_is_a_refusal_and_not_a_panic() {
        // Сюда приходит что угодно: набранное руками, вставленное из буфера,
        // разобранное с QR. Резать строку по вычисленному смещению значило бы
        // падать на границе символа вместо отказа.
        let long = "ф".repeat(56);
        for text in ["ю", "не адрес вовсе", "ы.onion", long.as_str()] {
            assert!(!is_address(text));
        }
    }

    #[test]
    fn a_second_version_address_is_refused() {
        // Адреса v2 отменены в самой сети Tor. Принять такой значит обещать
        // соединение, которого не будет.
        assert!(!is_address("expyuzz4wqqyqhjn.onion"));
        assert!(!is_address(""));
        assert!(!is_address(".onion"));
        assert!(!is_address("не адрес вовсе"));
    }

    #[test]
    fn a_wrong_version_byte_is_refused() {
        // Сумма считается по версии, поэтому подменить одну версию
        // на другую, не тронув сумму, нельзя — но проверить обе проверки
        // по отдельности стоит.
        let mut raw = [0u8; ADDRESS_BYTES];
        raw[..32].copy_from_slice(&known_public());
        raw[32..34].copy_from_slice(&checksum(&known_public()));
        raw[34] = 4;
        let mut text = BASE32_NOPAD.encode(&raw);
        text.make_ascii_lowercase();
        assert!(!is_address(&text));
    }

    /// Зерно из RFC 8032 (TEST 1) и его разложение, посчитанное **вне** этого
    /// кода: SHA-512 с клампингом, а затем проверка, что скаляр даёт ровно
    /// тот открытый ключ, который называет RFC. Без второй половины проверки
    /// вектор подтверждал бы только неизменность кода.
    const RFC_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_EXPANDED: &str = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f";

    fn rfc_key() -> OnionKey {
        let seed: [u8; 32] = hex::decode(RFC_SEED).unwrap().try_into().unwrap();
        OnionKey::from_seed(seed)
    }

    #[test]
    fn the_expanded_key_matches_rfc_8032() {
        assert_eq!(hex::encode(rfc_key().expanded_secret()), RFC_EXPANDED);
    }

    #[test]
    fn the_clamping_is_not_forgotten() {
        // Три бита, из-за которых ключ, посчитанный «почти правильно»,
        // даёт другой адрес — и обнаруживается это только тем, что никто
        // не может дозвониться.
        for seed in [[0u8; 32], [255u8; 32], [7u8; 32]] {
            let expanded = OnionKey::from_seed(seed).expanded_secret();
            assert_eq!(expanded[0] & 7, 0, "младшие три бита обязаны быть нулём");
            assert_eq!(expanded[31] & 128, 0, "старший бит обязан быть нулём");
            assert_eq!(expanded[31] & 64, 64, "предстарший бит обязан быть единицей");
        }
    }

    #[test]
    fn the_ctor_files_have_the_layout_c_tor_writes() {
        let key = rfc_key();

        let secret = key.ctor_secret_file();
        assert_eq!(secret.len(), 96, "32 байта заголовка и 64 ключа");
        assert!(secret.starts_with(b"== ed25519v1-secret: type0 =="));
        assert_eq!(&secret[29..32], &[0, 0, 0], "заголовок дополняется нулями");
        assert_eq!(&secret[32..], &key.expanded_secret()[..]);

        let public = key.ctor_public_file();
        assert_eq!(public.len(), 64, "32 байта заголовка и 32 ключа");
        assert!(public.starts_with(b"== ed25519v1-public: type0 =="));
        assert_eq!(&public[32..], &key.public()[..]);

        let hostname = key.ctor_hostname_file();
        assert_eq!(hostname, format!("{}\n", key.address()).into_bytes());
        assert!(hostname.ends_with(b".onion\n"), "C Tor пишет с переводом строки");
    }

    #[test]
    fn the_files_round_trip_through_the_address() {
        // Три файла обязаны описывать одну и ту же личность: разойдись они,
        // arti опубликовал бы сервис по одному адресу, а мы называли бы
        // контактам другой.
        let key = OnionKey::generate();
        let public = key.ctor_public_file();
        let from_file: [u8; 32] = public[32..].try_into().unwrap();
        assert_eq!(from_file, key.public());

        let hostname = String::from_utf8(key.ctor_hostname_file()).unwrap();
        assert_eq!(public_of(hostname.trim_end()).unwrap(), key.public());
    }

    #[test]
    fn the_debug_view_does_not_show_the_seed() {
        let key = OnionKey::generate();
        let shown = format!("{key:?}");
        assert!(shown.contains(".onion"), "адрес показать можно и нужно");
        assert!(!shown.contains(&hex::encode(key.seed())), "зерно — нет");
    }
}
