//! Ключ **своего** узла в меше Yggdrasil (0.2).
//!
//! Нужен ровно одному режиму — встроенному узлу. Внешнему демону свой ключ
//! мы не заводим: он его уже завёл, и наше дело — узнать открытую половину
//! и назвать её в карточке.
//!
//! # Чем отличается от [`onion`](crate::onion)
//!
//! Формой — ничем: то же зерно ed25519, тот же вывод открытой половины.
//! Разъезжаются они в том, **что этот ключ значит**.
//!
//! `onion_key` — долговременная идентичность устройства в сети Tor:
//! завладевший им выдаёт себя за это устройство, и §5.2 на этом стоит.
//! Ключ узла меша не удостоверяет никого. Он называет **место** —
//! адрес `200::/7`, по которому нас находят, — и не более того: личность
//! устанавливает рукопожатие §8.2, а адрес меша к тому же **сжимает** ключ
//! до четырнадцати байт и опознать по нему собеседника нельзя в принципе
//! ([`ratatosk_proto::ygg`](../../ratatosk_proto/ygg/index.html)).
//!
//! Отсюда и разная защита на диске, и разница названа здесь, чтобы её
//! не пришлось выводить заново: зерно onion **запечатывается** отдельно
//! (`storage_key::seal_field`), зерно меша лежит обычной служебной строкой.
//! Хранилище зашифровано ключом §8.6, то есть ровно тем же, чем переписка
//! и пароль от почты. Второй слой у onion — не общее правило, а надбавка
//! самому дорогому ключу в базе; платить её всем подряд значило бы
//! завести привычку, за которой перестанет быть видно, где она нужна.
//!
//! # Что бывает, если его украсть
//!
//! Вор занимает наш адрес в меше и принимает соединения, шедшие нам.
//! Дальше он упирается в §8.2: рукопожатие с ним не сходится ни у одного
//! нашего собеседника, потому что `IK` у него не наш. Он узнаёт, что нас
//! кто-то искал, и ничего сверх. Потеря настоящая, но ограниченная —
//! и ровно поэтому не стоит второго слоя.
//!
//! # Он переживает перезапуск, и это обязательно
//!
//! Адрес в меше едет в карточке (§4.1, поле 0.2). Новый ключ при каждом
//! запуске означал бы новый адрес, растущую версию карточки и рассылку
//! всем контактам — ни за чем, каждый старт. Поэтому «прочитать или
//! завести» стоит в одном месте, как и у личности с onion.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

/// Длина зерна и открытого ключа — ed25519, тридцать два байта.
pub const MESH_SEED_LEN: usize = 32;

/// Ключ узла меша: зерно на диске, открытая половина в карточке.
#[derive(Clone)]
pub struct MeshKey {
    seed: Zeroizing<[u8; MESH_SEED_LEN]>,
    public: [u8; 32],
}

impl MeshKey {
    /// Заводит новый ключ из CSPRNG.
    #[must_use]
    pub fn generate() -> MeshKey {
        use rand_core::RngCore;
        let mut seed = [0u8; MESH_SEED_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        MeshKey::from_seed(seed)
    }

    /// Восстанавливает ключ из зерна.
    #[must_use]
    pub fn from_seed(seed: [u8; MESH_SEED_LEN]) -> MeshKey {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        MeshKey { seed: Zeroizing::new(seed), public }
    }

    /// Зерно — то, что лежит в служебной строке базы.
    #[must_use]
    pub fn seed(&self) -> &[u8; MESH_SEED_LEN] {
        &self.seed
    }

    /// Открытый ключ узла — то, что уезжает в карточке.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
}

/// Печатается без зерна.
///
/// Производный `Debug` вывалил бы закрытый ключ в журнал при первой же
/// отладочной строке. Та же причина, по которой свой `Debug` написан
/// у почтовых настроек: секрет, попавший в отчёт, уже не секрет.
impl core::fmt::Debug for MeshKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeshKey").field("public", &hex_head(&self.public)).finish_non_exhaustive()
    }
}

fn hex_head(key: &[u8; 32]) -> String {
    key.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_public_key() {
        // Ради этого ключ и хранится: адрес в меше обязан пережить
        // перезапуск, иначе карточка растит версию каждый старт.
        let seed = [7u8; MESH_SEED_LEN];
        assert_eq!(MeshKey::from_seed(seed).public(), MeshKey::from_seed(seed).public());
    }

    #[test]
    fn a_generated_key_is_not_the_zero_key() {
        // Проверка дешёвая, а ловит она худший из отказов CSPRNG —
        // тот, при котором все устройства получают один адрес.
        let key = MeshKey::generate();
        assert_ne!(*key.seed(), [0u8; MESH_SEED_LEN]);
        assert_ne!(key.public(), [0u8; 32]);
    }

    #[test]
    fn two_generated_keys_differ() {
        assert_ne!(MeshKey::generate().public(), MeshKey::generate().public());
    }

    #[test]
    fn the_public_key_matches_ed25519() {
        // Сверка с примитивом напрямую: если бы мы однажды подставили сюда
        // x25519 (а обе половины стека их путают), адрес считался бы
        // от чужой кривой и не сошёлся бы ни с чьим.
        let seed = [3u8; MESH_SEED_LEN];
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(MeshKey::from_seed(seed).public(), expected);
    }

    #[test]
    fn debug_does_not_print_the_seed() {
        // Не украшение: эффекты и настройки попадают в журнал целиком.
        let key = MeshKey::from_seed([0xabu8; MESH_SEED_LEN]);
        let shown = format!("{key:?}");
        assert!(!shown.contains("ab, ab"), "зерно не должно печататься: {shown}");
        assert!(!shown.contains("seed"), "и даже упоминаться: {shown}");
    }
}
