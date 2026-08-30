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
use ratatosk_crypto::onion::ONION_SEED_LEN;
use ratatosk_crypto::{kdf, labels, storage_key, Identity, OnionKey};
use ratatosk_store::{
    SqliteStore, Store, StoreError, META_DB_SALT, META_IDENTITY_SEED, META_ONION_KEY,
};
use zeroize::Zeroizing;

use crate::engine::EngineError;

/// Привязка запечатанного зерна к его месту в базе.
const SEED_AAD: &[u8] = b"meta.identity_seed";

/// Привязка запечатанного ключа onion-сервиса к его месту в базе.
///
/// Своя, отличная от [`SEED_AAD`]: два секрета одной длины в одной таблице
/// иначе становятся взаимозаменяемыми. Переставить их местами — значит
/// подменить и личность, и адрес разом, а AAD делает такую перестановку
/// отказом расшифровки, а не тихой подменой.
const ONION_AAD: &[u8] = b"meta.onion_key";

/// Ключ в служебной таблице: `db_key`, лежащий **открыто**, когда защиты нет.
const META_PLAIN_DB_KEY: &str = "db_key_plain";

/// Разделители назначений внутри одного контекста деривации.
///
/// Два способа открыть базу дают разный материал одной длины, и без пометки
/// их можно было бы перепутать местами: секрет устройства в роли вывода
/// из PIN и наоборот. Метка стоит первой, чтобы разделение не зависело
/// от длин того, что идёт следом.
const TAG_DEVICE: &[u8] = b"device";
/// Метка для случая «и PIN, и устройство».
const TAG_PIN_AND_DEVICE: &[u8] = b"pin+device";

/// Чем открывается база (§8.6).
///
/// Спецификация знает PIN и обещает, что при отказе от него `db_key` уедет
/// в хранилище ключей ОС. Здесь это обещание и выполнено — тремя способами
/// вместо двух, потому что они защищают от разного:
///
/// * **PIN** — от того, у кого файл базы. Устройство при этом не нужно:
///   базу можно перенести и открыть где угодно, зная PIN.
/// * **Устройство** — от того, у кого файл, но нет телефона. Секрет живёт
///   в Android Keystore и наружу не выходит; перенести базу на другой
///   телефон нельзя **вообще**, даже зная всё.
/// * **И то и другое** — от обоих сразу: файл бесполезен без устройства,
///   устройство — без PIN.
///
/// Цена третьего и второго названа прямо: **потеря телефона — потеря
/// переписки**. Секрет из Keystore не восстанавливается ни резервной фразой,
/// ни бэкапом; вернуть базу без него нельзя, и сказать об этом человеку
/// клиент обязан до, а не после.
#[derive(Debug, Clone, Copy)]
pub enum Unlock<'a> {
    /// PIN человека.
    Pin(&'a str),
    /// Секрет из хранилища ключей ОС — 32 байта, которых нет больше нигде.
    Device(&'a [u8; 32]),
    /// PIN и секрет устройства вместе.
    PinAndDevice {
        /// PIN человека.
        pin: &'a str,
        /// Секрет из хранилища ключей ОС.
        device: &'a [u8; 32],
    },
    /// Ничего: `db_key` лежит в базе открыто.
    ///
    /// §8.6 такое разрешает, но это означает, что содержимое доступно
    /// любому, кто получил файл. Клиент обязан показать предупреждение.
    Nothing,
}

/// Открывает базу и выводит ключ шифрования полей (§8.6).
///
/// Соль хранится открыто рядом с базой — это её штатный режим. Прочитать её
/// надо до вывода ключа, а завести — до первой записи, поэтому база сначала
/// открывается пустым ключом ради одной служебной таблицы. Открытым ключом
/// при этом не шифруется ничего: `meta` не запечатывается.
///
/// Чем именно открывается база — в [`Unlock`]; там же сказано, от чего
/// защищает каждый способ и чем за него платят.
///
/// **[`Unlock::Nothing`] означает, что содержимое доступно любому, кто получил
/// файл.** §8.6 такое разрешает, но ключ базы лежит тогда в ней самой
/// открыто, и шифрование полей защищает лишь от случайного чтения, а не
/// от того, у кого файл в руках. Клиент обязан показать `no_pin_warning()`.
/// На Android этот способ выбирать больше незачем: [`Unlock::Device`]
/// не требует от человека ничего и защищает по-настоящему.
pub fn open_encrypted(
    path: &Path,
    unlock: Unlock<'_>,
) -> Result<(SqliteStore, Zeroizing<[u8; 32]>), EngineError> {
    let mut probe = SqliteStore::open(path, Zeroizing::new([0u8; 32]))?;
    probe.migrate()?;

    // Соль одна на базу и общая для всех способов: заведи мы её по соли
    // на способ, смена способа означала бы другой `db_key` при том же PIN —
    // то есть нечитаемую переписку.
    let db_key = match unlock {
        Unlock::Pin(pin) => {
            let salt = salt_of(&mut probe)?;
            storage_key::derive_from_pin(pin, &salt, storage_key::KdfParams::default())?
        }
        // Argon2id здесь не нужен и был бы вредом: секрет устройства — это
        // 32 байта из CSPRNG, перебирать их бессмысленно, а полсекунды
        // задержки платил бы человек на каждом открытии.
        Unlock::Device(device) => {
            let salt = salt_of(&mut probe)?;
            kdf::derive_concat(labels::DEVICE_KEY, &[TAG_DEVICE, device, &salt])
        }
        Unlock::PinAndDevice { pin, device } => {
            let salt = salt_of(&mut probe)?;
            let from_pin =
                storage_key::derive_from_pin(pin, &salt, storage_key::KdfParams::default())?;
            kdf::derive_concat(
                labels::DEVICE_KEY,
                &[TAG_PIN_AND_DEVICE, &from_pin[..], device, &salt],
            )
        }
        Unlock::Nothing => {
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

/// Соль базы: читается или заводится при первом открытии.
fn salt_of<S: Store>(store: &mut S) -> Result<[u8; storage_key::SALT_LEN], EngineError> {
    let salt = read_or_create(store, META_DB_SALT, || storage_key::generate_salt().to_vec())?;
    salt.as_slice()
        .try_into()
        .map_err(|_| StoreError::Backend("соль в базе испорчена".into()).into())
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
    if let Some(identity) = identity_in(store, db_key)? {
        return Ok(identity);
    }

    let seed = generate_seed();
    let sealed = storage_key::seal_field(db_key, SEED_AAD, &seed[..])?;
    store.put_meta(META_IDENTITY_SEED, &sealed)?;
    Ok(Identity::from_seed(*seed))
}

/// Читает личность из хранилища, **ничего не заводя**.
///
/// `None` — зерна там нет. Отдельно от [`load_or_create`], потому что есть
/// случай, где заводить нельзя ни в коем случае: чужая база, открытая
/// на чтение (архив при слиянии знакомств, §12). Записать в неё свою
/// личность значило бы испортить то, что нам не принадлежит, — та же
/// причина, по которой `accepts_pin` не накатывает миграции.
///
/// # Errors
///
/// Отказ хранилища или расшифровки: не тот `db_key`, испорченное зерно.
pub fn identity_in<S: Store>(
    store: &S,
    db_key: &[u8; 32],
) -> Result<Option<Identity>, EngineError> {
    let Some(sealed) = store.meta(META_IDENTITY_SEED)? else { return Ok(None) };
    let seed = storage_key::open_field(db_key, SEED_AAD, &sealed)?;
    let seed: [u8; SEED_LEN] =
        seed.as_slice().try_into().map_err(|_| ratatosk_crypto::CryptoError::BadKeyMaterial)?;
    Ok(Some(Identity::from_seed(seed)))
}

/// Читает ключ onion-сервиса, а если его нет — заводит и сохраняет (§3, §5.2).
///
/// Отдельная функция, а не часть [`load_or_create`], по той же причине,
/// по которой ключ лежит отдельной строкой: §3 выводит его независимо
/// от зерна личности. Связать их значило бы пообещать, что резервная фраза
/// возвращает и адрес, — а она не возвращает.
///
/// Второй запуск обязан вернуть **тот же** адрес: onion-адрес уехал
/// в карточках (§4.1), которые люди сохранили у себя. Сменить его молча —
/// то же самое, что сменить отпечаток: связь рвётся у всех сразу и без
/// объяснения. Поэтому здесь, как и с личностью, «прочитать или завести»
/// в одном месте и в одном порядке.
///
/// # Errors
///
/// Отказ хранилища или расшифровки: не тот `db_key`, испорченная запись.
/// Молча завести новый ключ на месте нечитаемого нельзя — это и была бы
/// та самая тихая смена адреса.
pub fn load_or_create_onion<S: Store>(
    store: &mut S,
    db_key: &[u8; 32],
) -> Result<OnionKey, EngineError> {
    if let Some(sealed) = store.meta(META_ONION_KEY)? {
        let seed = storage_key::open_field(db_key, ONION_AAD, &sealed)?;
        let seed: [u8; ONION_SEED_LEN] =
            seed.as_slice().try_into().map_err(|_| ratatosk_crypto::CryptoError::BadKeyMaterial)?;
        return Ok(OnionKey::from_seed(seed));
    }

    let key = OnionKey::generate();
    let sealed = storage_key::seal_field(db_key, ONION_AAD, &key.seed()[..])?;
    store.put_meta(META_ONION_KEY, &sealed)?;
    Ok(key)
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

    #[test]
    fn the_second_open_returns_the_same_onion_address() {
        // Адрес уехал в карточках, которые люди сохранили у себя. Молчаливая
        // смена адреса рвёт связь со всеми сразу — ровно как смена отпечатка.
        let mut s = store();
        let key = [7u8; 32];
        let first = load_or_create_onion(&mut s, &key).unwrap().address();
        let second = load_or_create_onion(&mut s, &key).unwrap().address();
        assert_eq!(first, second);
        assert!(first.ends_with(".onion"));
    }

    #[test]
    fn a_wrong_key_does_not_silently_create_a_new_address() {
        let mut s = store();
        load_or_create_onion(&mut s, &[7u8; 32]).unwrap();
        assert!(load_or_create_onion(&mut s, &[8u8; 32]).is_err());
    }

    #[test]
    fn the_onion_key_is_independent_of_the_identity_seed() {
        // §3: `onion_key` в зерно не входит. Проверяется тем, что одна
        // запись не открывается контекстом другой: перепутать их местами
        // должно быть отказом расшифровки, а не тихой подменой.
        let mut s = store();
        let key = [7u8; 32];
        load_or_create(&mut s, &key).unwrap();
        load_or_create_onion(&mut s, &key).unwrap();

        let seed_record = s.meta(META_IDENTITY_SEED).unwrap().unwrap();
        let onion_record = s.meta(META_ONION_KEY).unwrap().unwrap();
        assert_ne!(seed_record, onion_record);
        assert!(storage_key::open_field(&key, ONION_AAD, &seed_record).is_err());
        assert!(storage_key::open_field(&key, SEED_AAD, &onion_record).is_err());
    }

    #[test]
    fn losing_the_onion_key_does_not_touch_the_identity() {
        // Обратная сторона независимости: перенос базы без строки onion_key
        // (или её порча) обязан оставить личность целой — иначе одна беда
        // превращается в две.
        let mut s = store();
        let key = [7u8; 32];
        let fingerprint = load_or_create(&mut s, &key).unwrap().fingerprint();
        load_or_create_onion(&mut s, &key).unwrap();

        s.put_meta(META_ONION_KEY, b"mangled").unwrap();
        assert!(load_or_create_onion(&mut s, &key).is_err(), "порча обязана быть отказом");
        s.put_meta(META_ONION_KEY, &[]).unwrap();
        assert!(load_or_create_onion(&mut s, &key).is_err(), "пустая строка — тоже порча");

        assert_eq!(
            load_or_create(&mut s, &key).unwrap().fingerprint(),
            fingerprint,
            "личность не зависит от целости onion-ключа"
        );
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
            let (mut store, db_key) = open_encrypted(&path, Unlock::Pin("1111")).unwrap();
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
    fn a_device_secret_opens_only_its_own_base() {
        // Ради этого свойства секрет и берётся из хранилища ключей ОС:
        // база, унесённая с телефона, не открывается ничем.
        let path = temp_db("device");
        let secret = [9u8; 32];
        {
            let (mut store, db_key) = open_encrypted(&path, Unlock::Device(&secret)).unwrap();
            load_or_create(&mut store, &db_key).unwrap();
        }

        let again = open_encrypted(&path, Unlock::Device(&secret)).unwrap();
        assert!(
            load_or_create(&mut { again.0 }, &again.1).is_ok(),
            "тот же секрет обязан открыть ту же базу"
        );

        let (mut store, db_key) = open_encrypted(&path, Unlock::Device(&[8u8; 32])).unwrap();
        assert!(
            load_or_create(&mut store, &db_key).is_err(),
            "чужой секрет не вправе открывать базу — и не вправе заводить в ней личность"
        );
        forget(&path);
    }

    #[test]
    fn the_three_ways_give_three_different_keys() {
        // Метки назначения внутри деривации нужны ровно за этим: без них
        // «секрет устройства» и «вывод из PIN» — два блока по 32 байта,
        // и перепутать их местами было бы нечем.
        let path = temp_db("ways");
        let secret = [9u8; 32];

        let pin_only = open_encrypted(&path, Unlock::Pin("1111")).unwrap().1;
        let device_only = open_encrypted(&path, Unlock::Device(&secret)).unwrap().1;
        let both =
            open_encrypted(&path, Unlock::PinAndDevice { pin: "1111", device: &secret }).unwrap().1;

        assert_ne!(*pin_only, *device_only);
        assert_ne!(*pin_only, *both);
        assert_ne!(*device_only, *both, "PIN в материале ничего не изменил");
        forget(&path);
    }

    #[test]
    fn a_base_without_a_pin_cannot_be_found_by_probing() {
        // Отсюда правило: у скрытого аккаунта PIN обязателен. Без соли
        // перебирать не с чем, и файл становится мёртвым грузом.
        let path = temp_db("nopin");
        {
            let (mut store, db_key) = open_encrypted(&path, Unlock::Nothing).unwrap();
            load_or_create(&mut store, &db_key).unwrap();
        }

        assert!(!accepts_pin(&path, "1111").unwrap());
        assert!(!accepts_pin(&path, "").unwrap());
        forget(&path);
    }
}
