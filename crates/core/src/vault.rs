//! Постоянная идентичность на диске (§3, §8.6).
//!
//! Личность — это `IK` и `SK`, выведенные из одного зерна. Пока зерно живёт
//! только в памяти, каждый запуск — новое устройство: меняется отпечаток,
//! меняется контакт-карточка, и все, кто её сохранил, теряют связь. Поэтому
//! зерно обязано пережить перезапуск, а раз оно секретное — лежать
//! запечатанным.
//!
//! Ключ запечатывания — `db_key` из §8.6; выводит его тот, кто знает PIN.
//! Здесь только «прочитать или завести», потому что порядок этих двух шагов
//! ошибиться не должен: сгенерировать поверх существующего зерна значит
//! молча выбросить идентичность вместе со всеми сессиями.

use std::path::Path;

use ratatosk_crypto::identity::SEED_LEN;
use ratatosk_crypto::{storage_key, Identity};
use ratatosk_store::{SqliteStore, Store, StoreError, META_DB_SALT, META_IDENTITY_SEED};
use zeroize::Zeroizing;

use crate::engine::EngineError;

/// Привязка запечатанного зерна к его месту в базе.
const SEED_AAD: &[u8] = b"meta.identity_seed";

/// Ключ в служебной таблице: `db_key`, лежащий **открыто**, когда PIN не задан.
const META_PLAIN_DB_KEY: &str = "db_key_plain";

/// Открывает базу и выводит ключ шифрования полей (§8.6).
///
/// Соль хранится открыто рядом с базой — это её штатный режим. Прочитать её
/// надо до вывода ключа, а завести — до первой записи, поэтому база сначала
/// открывается пустым ключом ради одной служебной таблицы. Открытым ключом
/// при этом не шифруется ничего: `meta` не запечатывается.
///
/// **`pin = None` означает, что содержимое доступно любому, кто получил
/// файл.** §8.6 разрешает отказаться от PIN, но обещает, что `db_key` уедет
/// в Android Keystore или хранилище ключей ОС; до его подключения ключ лежит
/// в самой базе открыто, и шифрование полей становится защитой только от
/// случайного чтения файла, но не от того, у кого он в руках. Клиент обязан
/// показать `no_pin_warning()`. Когда Keystore появится, ключ будет приходить
/// снаружи — для этого есть [`open_with_key`].
pub fn open_encrypted(
    path: &Path,
    pin: Option<&str>,
) -> Result<(SqliteStore, Zeroizing<[u8; 32]>), EngineError> {
    let mut probe = SqliteStore::open(path, Zeroizing::new([0u8; 32]))?;
    probe.migrate()?;

    let db_key = match pin {
        Some(pin) => {
            let salt =
                read_or_create(&mut probe, META_DB_SALT, || storage_key::generate_salt().to_vec())?;
            let salt: [u8; storage_key::SALT_LEN] = salt
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("соль в базе испорчена".into()))?;
            storage_key::derive_from_pin(pin, &salt, storage_key::KdfParams::default())?
        }
        None => {
            let key = read_or_create(&mut probe, META_PLAIN_DB_KEY, || {
                storage_key::generate_db_key().to_vec()
            })?;
            let key: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("ключ базы испорчен".into()))?;
            Zeroizing::new(key)
        }
    };
    drop(probe);

    Ok((open_with_key(path, Zeroizing::new(*db_key))?, db_key))
}

/// Открывает базу готовым ключом — тем, что пришёл из хранилища ключей ОС.
pub fn open_with_key(path: &Path, db_key: Zeroizing<[u8; 32]>) -> Result<SqliteStore, EngineError> {
    let mut store = SqliteStore::open(path, db_key)?;
    store.migrate()?;
    Ok(store)
}

fn read_or_create<S: Store>(
    store: &mut S,
    key: &str,
    make: impl FnOnce() -> Vec<u8>,
) -> Result<Vec<u8>, EngineError> {
    if let Some(found) = store.meta(key)? {
        return Ok(found);
    }
    let fresh = make();
    store.put_meta(key, &fresh)?;
    Ok(fresh)
}

/// Читает личность из хранилища, а если её там нет — заводит и сохраняет.
///
/// Второй запуск с тем же `db_key` обязан вернуть **ту же** личность: на
/// этом держится всё остальное, потому что контакты знают устройство по `IK`.
pub fn load_or_create<S: Store>(store: &mut S, db_key: &[u8; 32]) -> Result<Identity, EngineError> {
    if let Some(sealed) = store.meta(META_IDENTITY_SEED)? {
        let seed = storage_key::open_field(db_key, SEED_AAD, &sealed)?;
        let seed: [u8; SEED_LEN] =
            seed.as_slice().try_into().map_err(|_| ratatosk_crypto::CryptoError::BadKeyMaterial)?;
        return Ok(Identity::from_seed(seed));
    }

    let seed = generate_seed();
    let sealed = storage_key::seal_field(db_key, SEED_AAD, &seed[..])?;
    store.put_meta(META_IDENTITY_SEED, &sealed)?;
    Ok(Identity::from_seed(*seed))
}

fn generate_seed() -> Zeroizing<[u8; SEED_LEN]> {
    use rand_core::RngCore;
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    rand_core::OsRng.fill_bytes(seed.as_mut());
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatosk_store::MemoryStore;

    fn store() -> MemoryStore {
        let mut s = MemoryStore::new();
        s.migrate().unwrap();
        s
    }

    #[test]
    fn the_second_open_returns_the_same_identity() {
        let mut s = store();
        let key = [3u8; 32];
        let first = load_or_create(&mut s, &key).unwrap().fingerprint();
        let second = load_or_create(&mut s, &key).unwrap().fingerprint();
        assert_eq!(first, second, "перезапуск не должен менять отпечаток");
    }

    #[test]
    fn a_wrong_key_does_not_silently_create_a_new_identity() {
        // Молча завести новую личность при неверном PIN — худший исход:
        // пользователь увидит пустой клиент вместо сообщения «не тот PIN»
        // и решит, что переписка потеряна.
        let mut s = store();
        load_or_create(&mut s, &[3u8; 32]).unwrap();
        assert!(load_or_create(&mut s, &[4u8; 32]).is_err());
    }

    #[test]
    fn separate_stores_get_separate_identities() {
        let key = [3u8; 32];
        let a = load_or_create(&mut store(), &key).unwrap().fingerprint();
        let b = load_or_create(&mut store(), &key).unwrap().fingerprint();
        assert_ne!(a, b, "два устройства с одним PIN — всё равно два устройства");
    }
}
