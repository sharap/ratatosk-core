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

/// Открывает ли этот PIN эту базу — **ничего не меняя**.
///
/// Нужно скрытым аккаунтам (`crate::accounts`): у них не записано нигде
/// ничего, и найти нужный можно только попыткой открыть каждый файл,
/// не числящийся в реестре.
///
/// «Ничего не меняя» здесь не вежливость, а требование. Перебор идёт
/// по чужим файлам: в каталоге может лежать что угодно, и [`open_encrypted`]
/// для проверки не годится втройне — он накатывает миграции на чужую базу,
/// заводит соль там, где её не было, и, встретив базу без зерна, создаёт
/// в ней личность. Каждое из трёх — порча того, что нам не принадлежит.
/// Поэтому здесь только чтение, и даже миграции не накатываются: `meta`
/// заведена первой миграцией и есть в любой нашей базе.
///
/// `false` возвращается на все случаи неудачи сразу, и различать их незачем:
/// файла нет, это не база вовсе, это чужая база, у неё нет PIN, PIN не тот,
/// зерно испорчено — открыть нечем во всех шести.
///
/// **Нечитаемый файл — тоже `false`, а не отказ.** Перебор идёт по каталогу,
/// в котором лежит что попало, и прервать его из-за одного файла без прав
/// на чтение значило бы не открыть человеку его аккаунт из-за чужого мусора
/// по соседству.
///
/// Стоит одного вывода ключа Argon2id (§8.6) — около полусекунды. При
/// переборе это умножается на число файлов, и человеку об ожидании
/// стоит сказать.
///
/// # Errors
///
/// Только отказ вывода ключа. Всё, что относится к самому файлу, — `Ok(false)`.
pub fn accepts_pin(path: &Path, pin: &str) -> Result<bool, EngineError> {
    if !path.exists() {
        return Ok(false);
    }
    // Только на чтение — и это главное в этой функции.
    //
    // Обычное открытие применяет прагмы, среди которых `journal_mode = WAL`.
    // Она пишет в файл: чужая база по соседству необратимо переводится
    // в режим WAL и обрастает `-wal` и `-shm`, а пустой файл перестаёт быть
    // пустым — SQLite считает его новой базой и пишет заголовок. Перебор
    // идёт по каталогу, где лежит что попало, и портить соседей он не вправе.
    //
    // Нулевым ключом, потому что ничего запечатанного мы этим шагом
    // не читаем: соль лежит в `meta` открыто.
    let Ok(probe) = SqliteStore::open_readonly(path, Zeroizing::new([0u8; 32])) else {
        return Ok(false);
    };

    // Отказ чтения `meta` означает, что это наша база другой эпохи или
    // чужая база вовсе: таблицы нет. Тоже не ошибка.
    let Ok(Some(salt)) = probe.meta(META_DB_SALT) else { return Ok(false) };
    let Ok(salt) = <[u8; storage_key::SALT_LEN]>::try_from(salt.as_slice()) else {
        return Ok(false);
    };
    let Ok(Some(sealed)) = probe.meta(META_IDENTITY_SEED) else { return Ok(false) };

    let db_key = storage_key::derive_from_pin(pin, &salt, storage_key::KdfParams::default())?;
    Ok(storage_key::open_field(&db_key, SEED_AAD, &sealed).is_ok())
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

    /// Свой временный путь: база нужна настоящая, `in_memory` тут не годится.
    fn temp_db(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ratatosk-vault-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        for extra in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{extra}", path.display()));
        }
        path
    }

    fn forget(path: &Path) {
        for extra in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{extra}", path.display()));
        }
    }

    #[test]
    fn only_its_own_pin_opens_a_base() {
        // Ради этого свойства аккаунты и разведены по файлам: один PIN
        // не открывает вторую переписку. Если это когда-нибудь перестанет
        // выполняться, весь смысл разделения исчезнет.
        let path = temp_db("own-pin");
        {
            let (mut store, db_key) = open_encrypted(&path, Some("1111")).unwrap();
            load_or_create(&mut store, &db_key).unwrap();
        }

        assert!(accepts_pin(&path, "1111").unwrap(), "свой PIN открывает");
        assert!(!accepts_pin(&path, "2222").unwrap(), "чужой — нет");
        forget(&path);
    }

    #[test]
    fn probing_a_stranger_changes_nothing() {
        // Перебор идёт по чужим файлам: в каталоге может лежать что угодно.
        // Накатить на такой файл миграции, завести в нём соль или личность —
        // порча того, что нам не принадлежит.
        let path = temp_db("stranger");
        std::fs::write(&path, b"not a database at all").unwrap();
        let before = std::fs::read(&path).unwrap();

        assert!(!accepts_pin(&path, "1111").unwrap(), "чужой файл — не аккаунт");
        assert_eq!(std::fs::read(&path).unwrap(), before, "и он не тронут");

        // Пустой файл — случай тоньше и потому опаснее: для SQLite это
        // законная новая база, и обычное открытие записало бы в него
        // заголовок вместе с прагмами. Проверяем, что он остался пустым
        // и что рядом не завелись `-wal` с `-shm`.
        std::fs::write(&path, b"").unwrap();
        assert!(!accepts_pin(&path, "1111").unwrap());
        assert!(std::fs::read(&path).unwrap().is_empty(), "пустой файл обязан остаться пустым");
        for extra in ["-wal", "-shm"] {
            let neighbour = std::path::PathBuf::from(format!("{}{extra}", path.display()));
            assert!(!neighbour.exists(), "перебор завёл рядом {extra} — значит, писал");
        }
        forget(&path);
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        // Файл мог исчезнуть между чтением каталога и попыткой открыть.
        // Это не повод прерывать перебор.
        let path = temp_db("missing");
        assert!(!accepts_pin(&path, "1111").unwrap());
    }

    #[test]
    fn a_base_without_a_pin_cannot_be_found_by_probing() {
        // Отсюда правило: у скрытого аккаунта PIN обязателен. Без соли
        // перебирать не с чем, и файл становится мёртвым грузом.
        let path = temp_db("nopin");
        {
            let (mut store, db_key) = open_encrypted(&path, None).unwrap();
            load_or_create(&mut store, &db_key).unwrap();
        }

        assert!(!accepts_pin(&path, "1111").unwrap());
        assert!(!accepts_pin(&path, "").unwrap());
        forget(&path);
    }
}
