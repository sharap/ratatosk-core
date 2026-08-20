//! Несколько личностей на одном устройстве (§3, дополнение).
//!
//! **Спецификация v0.1 этого не описывает.** Она говорит об одной идентичности
//! на устройство: зерно в базе, `IK` и `SK` из него, отпечаток для сверки.
//! Здесь таких устройств несколько внутри одного приложения.
//!
//! # Аккаунт — это отдельный файл базы, а не колонка в таблицах
//!
//! Второй вариант напрашивался: добавить `account_id` во все таблицы и жить
//! в одной базе. Он неверен, и не из-за объёма правок.
//!
//! База шифруется полями на `db_key`, который выводится из PIN (§8.6). Одна
//! база — один `db_key`, то есть **один PIN открывает всё**. Человек, который
//! завёл второй аккаунт затем, чтобы первый о нём ничего не говорил, получил
//! бы ровно обратное: назвал PIN под принуждением — отдал обе переписки.
//! Отдельные файлы дают отдельные ключи, и это единственное, ради чего
//! разделение вообще имеет смысл.
//!
//! Побочно оказалось, что ядру для этого не нужно ничего: `Engine` не знает
//! о путях, глобального состояния в дереве нет, каталог вложений выводится
//! из пути к базе, LAN берёт порт у системы, а имя в mDNS случайно на каждый
//! запуск. Два ядра в одном процессе не сталкиваются уже сегодня.
//!
//! # Что лежит в реестре и почему он открытый
//!
//! Список надо показать **до** ввода PIN — иначе выбирать не из чего.
//! Значит расшифровать его нечем, и всё, что в нём есть, доступно любому,
//! кто взял устройство: имена аккаунтов, их число и время создания.
//!
//! Поэтому в реестре нет ничего, кроме этого. Ни `IK`, ни отпечатка,
//! ни аватарки — они внутри зашифрованной базы. И **идентификатор аккаунта
//! случаен**, а не выведен из личности: выведи мы его, имя файла выдавало бы
//! то, что база прячет.
//!
//! # Скрытый аккаунт: что это значит и чего не значит
//!
//! Скрытый аккаунт — это аккаунт, которого нет в реестре. Приложение о нём
//! не знает и в списке не показывает; открывается он вводом своего PIN,
//! перебором файлов, не числящихся в реестре.
//!
//! **Он скрыт от списка, а не от осмотра файловой системы.** Файл базы лежит
//! рядом с остальными и виден любому, кто смотрит каталог: число файлов
//! больше числа записей в реестре — вот и весь секрет. Спрятать сам факт
//! существования можно было бы только внутри другой базы, как это делают
//! скрытые тома, и это отдельная работа с отдельными обещаниями.
//!
//! Сказать это в UI обязательно. «Скрытый» звучит как «его не найдут»,
//! а на деле означает «в списке его нет» — и человек, который положится
//! на первое прочтение, пострадает не от ошибки в коде.

use std::path::{Path, PathBuf};

use ratatosk_codec::{canonical, CodecError, Value};

use crate::entropy::Entropy;

/// Имя файла реестра в корне.
const REGISTRY_FILE: &str = "accounts.cbor";

/// Расширение файла базы аккаунта.
const DB_EXTENSION: &str = "db";

/// Расширение каталога вложений — то же правило, что и у одиночной базы.
const BLOBS_EXTENSION: &str = "files";

/// Сколько знаков в шестнадцатеричном имени файла.
const ID_HEX_LEN: usize = 32;

/// Ключ версии протокола в реестре.
const KEY_VERSION: u64 = 1;
/// Ключ списка аккаунтов.
const KEY_ACCOUNTS: u64 = 2;
/// Ключ идентификатора.
const KEY_ID: u64 = 3;
/// Ключ имени.
const KEY_LABEL: u64 = 4;
/// Ключ момента создания.
const KEY_CREATED: u64 = 5;

/// Наибольшая длина имени аккаунта в символах.
///
/// Имя пишется в открытый файл и показывается в списке. Предел здесь
/// не про место на диске, а про то, чтобы список оставался списком.
pub const MAX_LABEL_CHARS: usize = 64;

/// Идентификатор аккаунта.
///
/// Шестнадцать случайных байт. **Не выводится ни из чего**: имя файла лежит
/// открыто, и вывод из личности выдавал бы то, что база прячет.
pub type AccountId = [u8; 16];

/// Аккаунт в том виде, в каком он числится в реестре.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Идентификатор; он же имя файла базы.
    pub id: AccountId,
    /// Имя для списка. Задал человек; **лежит открыто**.
    pub label: String,
    /// Когда завели, мс.
    pub created_ms: u64,
}

/// Почему операция с реестром не удалась.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// Отказ файловой системы.
    #[error("реестр аккаунтов недоступен: {0}")]
    Io(String),
    /// Файл реестра испорчен.
    ///
    /// **Не то же самое, что «реестра нет».** Отсутствие файла — это первый
    /// запуск, и он означает пустой список. А испорченный файл означает, что
    /// аккаунты есть, но какие — неизвестно; ответить на это пустым списком
    /// значило бы предложить человеку завести всё заново поверх целых баз.
    #[error("файл реестра испорчен")]
    Corrupt,
    /// Имя пустое или длиннее [`MAX_LABEL_CHARS`].
    #[error("недопустимое имя аккаунта")]
    BadLabel,
    /// Реестр записан сборкой новее этой.
    ///
    /// Отдельно от [`AccountError::Corrupt`], потому что это разные советы
    /// человеку. Испорченный файл — беда; файл из будущего означает, что
    /// приложение откатили, и лечится это обратным обновлением. Прочитать
    /// его всё равно нельзя: в нём могут быть поля, которых мы не понимаем,
    /// а перезаписать реестр, потеряв их, значит потерять аккаунты.
    #[error("реестр записан версией {got}, эта сборка понимает {supported}")]
    FutureRegistry {
        /// Версия в файле.
        got: u64,
        /// Версия сборки.
        supported: u64,
    },
    /// Такого аккаунта в реестре нет.
    #[error("аккаунт неизвестен")]
    Unknown,
}

impl From<std::io::Error> for AccountError {
    fn from(error: std::io::Error) -> Self {
        AccountError::Io(error.to_string())
    }
}

impl From<CodecError> for AccountError {
    fn from(_: CodecError) -> Self {
        AccountError::Corrupt
    }
}

/// Результат операции с реестром.
pub type Result<T> = core::result::Result<T, AccountError>;

/// Реестр аккаунтов в каталоге.
#[derive(Debug, Clone)]
pub struct Registry {
    root: PathBuf,
    listed: Vec<Account>,
}

impl Registry {
    /// Открывает реестр в каталоге, заводя каталог при необходимости.
    ///
    /// Отсутствие файла — пустой список: так выглядит первый запуск.
    ///
    /// # Errors
    ///
    /// [`AccountError::Io`] при отказе файловой системы,
    /// [`AccountError::Corrupt`] на испорченном файле.
    pub fn open(root: impl Into<PathBuf>) -> Result<Registry> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;

        let path = root.join(REGISTRY_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Registry { root, listed: Vec::new() })
            }
            Err(error) => return Err(error.into()),
        };
        let listed = decode_registry(&bytes)?;
        Ok(Registry { root, listed })
    }

    /// Каталог, в котором лежат аккаунты.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Аккаунты из реестра, в порядке создания.
    ///
    /// Скрытых здесь нет по определению: скрытый — это тот, кого в реестре
    /// не числится.
    #[must_use]
    pub fn listed(&self) -> &[Account] {
        &self.listed
    }

    /// Путь к базе аккаунта.
    #[must_use]
    pub fn db_path(&self, id: &AccountId) -> PathBuf {
        self.root.join(hex(id)).with_extension(DB_EXTENSION)
    }

    /// Путь к каталогу вложений аккаунта.
    ///
    /// Выводится из пути к базе тем же правилом, что и у одиночной: каталог
    /// соседний, чтобы жить и удаляться вместе с ней.
    #[must_use]
    pub fn blobs_path(&self, id: &AccountId) -> PathBuf {
        self.root.join(hex(id)).with_extension(BLOBS_EXTENSION)
    }

    /// Заводит аккаунт и записывает его в реестр.
    ///
    /// Файла базы при этом не создаёт: её заводит первое открытие, и оно же
    /// знает про PIN. Реестр про ключи не знает ничего и знать не должен.
    ///
    /// # Errors
    ///
    /// [`AccountError::BadLabel`] на пустом или слишком длинном имени,
    /// [`AccountError::Io`] при отказе записи.
    pub fn create(
        &mut self,
        entropy: &mut dyn Entropy,
        label: &str,
        created_ms: u64,
    ) -> Result<Account> {
        let label = check_label(label)?;
        let account = Account { id: self.fresh_id(entropy), label, created_ms };
        self.listed.push(account.clone());
        self.save()?;
        Ok(account)
    }

    /// Заводит аккаунт **мимо реестра** — скрытый.
    ///
    /// Возвращает только идентификатор: записывать его некуда, а вернуть
    /// вызывающему надо, иначе он не найдёт путь к базе.
    ///
    /// Скрытым он остаётся до тех пор, пока его не открыли: открытие идёт
    /// перебором файлов, не числящихся в реестре ([`Registry::unlisted`]).
    /// Поэтому у скрытого аккаунта **обязан быть PIN** — без него открывать
    /// нечем, и файл станет мёртвым грузом. Проверить это здесь нельзя:
    /// реестр про ключи не знает; проверяет вызывающий.
    pub fn create_hidden(&mut self, entropy: &mut dyn Entropy) -> AccountId {
        self.fresh_id(entropy)
    }

    /// Меняет имя аккаунта.
    ///
    /// # Errors
    ///
    /// [`AccountError::Unknown`], [`AccountError::BadLabel`],
    /// [`AccountError::Io`].
    pub fn rename(&mut self, id: &AccountId, label: &str) -> Result<()> {
        let label = check_label(label)?;
        let account = self.listed.iter_mut().find(|a| a.id == *id).ok_or(AccountError::Unknown)?;
        account.label = label;
        self.save()
    }

    /// Убирает аккаунт из реестра, **не трогая его данные**.
    ///
    /// Это и есть «сделать скрытым»: файлы на месте, в списке его больше нет,
    /// открывается вводом PIN. Обратная операция — [`Registry::adopt`].
    ///
    /// # Errors
    ///
    /// [`AccountError::Unknown`], [`AccountError::Io`].
    pub fn hide(&mut self, id: &AccountId) -> Result<()> {
        let before = self.listed.len();
        self.listed.retain(|a| a.id != *id);
        if self.listed.len() == before {
            return Err(AccountError::Unknown);
        }
        self.save()
    }

    /// Вносит в реестр аккаунт, которого там не было, — снимает скрытость.
    ///
    /// # Errors
    ///
    /// [`AccountError::BadLabel`], [`AccountError::Io`].
    pub fn adopt(&mut self, id: &AccountId, label: &str, created_ms: u64) -> Result<Account> {
        let label = check_label(label)?;
        if let Some(known) = self.listed.iter_mut().find(|a| a.id == *id) {
            known.label = label;
            let account = known.clone();
            self.save()?;
            return Ok(account);
        }
        let account = Account { id: *id, label, created_ms };
        self.listed.push(account.clone());
        self.save()?;
        Ok(account)
    }

    /// Стирает аккаунт целиком: запись в реестре, базу и вложения.
    ///
    /// Работает и над скрытым — тем, кого в реестре нет.
    ///
    /// **Удаление файла не значит, что байты исчезли.** На флеш-памяти запись
    /// поверх не гарантирована ничем: контроллер пишет в другое место,
    /// а прежнее освобождает когда сочтёт нужным. Здесь делается то, что
    /// вообще возможно из приложения, — не больше; обещать человеку
    /// «стёрто безвозвратно» нельзя.
    ///
    /// # Errors
    ///
    /// [`AccountError::Io`], если файл есть, но не удаляется. Отсутствие
    /// файла ошибкой не считается: стирать нечего — значит уже стёрто.
    pub fn wipe(&mut self, id: &AccountId) -> Result<()> {
        // Сперва данные, потом запись в реестре. Обратный порядок оставил бы
        // базу без всякого следа о том, чья она, — и человек не смог бы
        // ни открыть её, ни убрать.
        remove_file_if_present(&self.db_path(id))?;
        // WAL и индекс журнала лежат рядом отдельными файлами и переживают
        // удаление основного: база, удалённая наполовину, при следующем
        // открытии воскресает частью переписки.
        for extra in ["db-wal", "db-shm"] {
            remove_file_if_present(&self.root.join(hex(id)).with_extension(extra))?;
        }
        match std::fs::remove_dir_all(self.blobs_path(id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let before = self.listed.len();
        self.listed.retain(|a| a.id != *id);
        if self.listed.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// Базы в каталоге, которых нет в реестре, — кандидаты на скрытый аккаунт.
    ///
    /// Именно перебором: у скрытого аккаунта не записано ничего, и найти его
    /// можно только попыткой открыть каждый нечислящийся файл введённым PIN.
    /// Стоит это одного вывода ключа Argon2id на файл (§8.6) — около
    /// полусекунды каждый, и человеку об этом ожидании стоит сказать.
    ///
    /// # Errors
    ///
    /// [`AccountError::Io`] при отказе чтения каталога.
    pub fn unlisted(&self) -> Result<Vec<AccountId>> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".db") else { continue };
            // Чужое имя пропускается молча: в каталоге может оказаться что
            // угодно, и считать это своим аккаунтом мы не вправе.
            let Some(id) = id_from_hex(stem) else { continue };
            if self.listed.iter().any(|a| a.id == id) {
                continue;
            }
            found.push(id);
        }
        found.sort_unstable();
        Ok(found)
    }

    /// Свободный идентификатор.
    ///
    /// Столкновение шестнадцати случайных байт невозможно на практике,
    /// но проверка стоит одного сравнения, а её отсутствие стоило бы чужой
    /// переписки поверх своей.
    fn fresh_id(&self, entropy: &mut dyn Entropy) -> AccountId {
        loop {
            let mut id = [0u8; 16];
            entropy.fill(&mut id);
            if self.listed.iter().all(|a| a.id != id) && !self.db_path(&id).exists() {
                return id;
            }
        }
    }

    /// Записывает реестр целиком.
    ///
    /// Через временный файл и переименование: реестр переписывается целиком,
    /// и обрыв записи посередине оставил бы обрезанный файл, то есть
    /// [`AccountError::Corrupt`] на все аккаунты сразу. Переименование внутри
    /// одного каталога атомарно на всех системах, которые нас интересуют.
    fn save(&self) -> Result<()> {
        let bytes = encode_registry(&self.listed)?;
        let target = self.root.join(REGISTRY_FILE);
        let temporary = self.root.join(format!("{REGISTRY_FILE}.new"));
        std::fs::write(&temporary, &bytes)?;
        std::fs::rename(&temporary, &target)?;
        Ok(())
    }
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Проверяет имя аккаунта и возвращает его без краевых пробелов.
fn check_label(label: &str) -> Result<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_LABEL_CHARS {
        return Err(AccountError::BadLabel);
    }
    // Управляющие символы в имени, которое поедет в список: перевод строки
    // разорвёт вывод, а невидимые знаки позволят двум аккаунтам выглядеть
    // одинаково.
    if trimmed.chars().any(char::is_control) {
        return Err(AccountError::BadLabel);
    }
    Ok(trimmed.to_owned())
}

fn hex(id: &AccountId) -> String {
    use std::fmt::Write as _;

    let mut name = String::with_capacity(ID_HEX_LEN);
    for byte in id {
        let _ = write!(name, "{byte:02x}");
    }
    name
}

/// Разбирает имя файла обратно в идентификатор.
///
/// Строго: ровно тридцать два строчных шестнадцатеричных знака. Разбор
/// «на глаз» принял бы и заглавные, и ведущий плюс, — а по такому имени
/// мы пошли бы открывать не тот файл.
fn id_from_hex(name: &str) -> Option<AccountId> {
    if name.len() != ID_HEX_LEN
        || !name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut id = [0u8; 16];
    for (at, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        id[at] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(id)
}

/// Кодирует реестр детерминированным CBOR — тем же кодеком, что и протокол.
///
/// Не JSON и не свой формат: у нас уже есть кодек, который отвергает
/// неканоничное и повторяющиеся ключи, и заводить рядом второй разбор
/// значило бы завести второе место для расхождений.
fn encode_registry(listed: &[Account]) -> Result<Vec<u8>> {
    let accounts = listed
        .iter()
        .map(|account| {
            Value::Map(vec![
                (Value::Integer(KEY_ID.into()), Value::Bytes(account.id.to_vec())),
                (Value::Integer(KEY_LABEL.into()), Value::Text(account.label.clone())),
                (Value::Integer(KEY_CREATED.into()), Value::Integer(account.created_ms.into())),
            ])
        })
        .collect();
    let value = Value::Map(vec![
        (
            Value::Integer(KEY_VERSION.into()),
            Value::Integer(ratatosk_codec::PROTOCOL_VERSION.into()),
        ),
        (Value::Integer(KEY_ACCOUNTS.into()), Value::Array(accounts)),
    ]);
    Ok(canonical::encode(&value)?)
}

fn decode_registry(bytes: &[u8]) -> Result<Vec<Account>> {
    let value = canonical::decode(bytes)?;
    let map = canonical::as_map(&value)?;
    // Версия разбирается раньше всего и отдельно: «файл из будущего» — это
    // не порча, а откат сборки, и человеку надо сказать разное.
    canonical::check_version(map).map_err(|error| match error {
        CodecError::FutureVersion { got, supported } => {
            AccountError::FutureRegistry { got, supported }
        }
        other => AccountError::from(other),
    })?;

    let Value::Array(items) = canonical::require(map, KEY_ACCOUNTS)? else {
        return Err(AccountError::Corrupt);
    };
    let mut listed = Vec::with_capacity(items.len());
    for item in items {
        let entry = canonical::as_map(item)?;
        let id = canonical::as_array::<16>(canonical::require(entry, KEY_ID)?)?;
        let Value::Text(label) = canonical::require(entry, KEY_LABEL)? else {
            return Err(AccountError::Corrupt);
        };
        let created_ms = canonical::as_u64(canonical::require(entry, KEY_CREATED)?)?;
        listed.push(Account { id, label: label.clone(), created_ms });
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeededEntropy;

    fn temp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "ratatosk-accounts-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    #[test]
    fn a_fresh_directory_has_no_accounts() {
        // Отсутствие файла — первый запуск, а не поломка.
        let root = temp_root("fresh");
        let registry = Registry::open(&root).unwrap();
        assert!(registry.listed().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn accounts_survive_reopening() {
        let root = temp_root("survive");
        let mut entropy = SeededEntropy::new(1);
        {
            let mut registry = Registry::open(&root).unwrap();
            registry.create(&mut entropy, "работа", 100).unwrap();
            registry.create(&mut entropy, "личное", 200).unwrap();
        }

        let registry = Registry::open(&root).unwrap();
        let names: Vec<&str> = registry.listed().iter().map(|a| a.label.as_str()).collect();
        assert_eq!(names, vec!["работа", "личное"], "порядок создания сохраняется");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn every_account_gets_its_own_files() {
        // Разные базы — разные ключи. На этом стоит вся затея: один PIN
        // не должен открывать вторую переписку.
        let root = temp_root("paths");
        let mut entropy = SeededEntropy::new(2);
        let mut registry = Registry::open(&root).unwrap();
        let first = registry.create(&mut entropy, "первый", 100).unwrap();
        let second = registry.create(&mut entropy, "второй", 100).unwrap();

        assert_ne!(registry.db_path(&first.id), registry.db_path(&second.id));
        assert_ne!(registry.blobs_path(&first.id), registry.blobs_path(&second.id));
        assert_ne!(registry.db_path(&first.id), registry.blobs_path(&first.id));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hidden_account_is_missing_from_the_list_but_not_from_the_disk() {
        // Ровно то, что обязан сказать UI: скрыт от списка, а не от осмотра
        // каталога. Файл виден, и число файлов больше числа записей.
        let root = temp_root("hidden");
        let mut entropy = SeededEntropy::new(3);
        let mut registry = Registry::open(&root).unwrap();
        let listed = registry.create(&mut entropy, "обычный", 100).unwrap();
        let hidden = registry.create_hidden(&mut entropy);

        // Базы заводит открытие; здесь достаточно самих файлов.
        std::fs::write(registry.db_path(&listed.id), b"x").unwrap();
        std::fs::write(registry.db_path(&hidden), b"x").unwrap();

        assert_eq!(registry.listed().len(), 1, "в списке только обычный");
        assert_eq!(registry.unlisted().unwrap(), vec![hidden], "а на диске — оба");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hiding_and_adopting_are_opposites() {
        let root = temp_root("hide");
        let mut entropy = SeededEntropy::new(4);
        let mut registry = Registry::open(&root).unwrap();
        let account = registry.create(&mut entropy, "работа", 100).unwrap();
        std::fs::write(registry.db_path(&account.id), b"x").unwrap();

        registry.hide(&account.id).unwrap();
        assert!(registry.listed().is_empty(), "скрытый уходит из списка");
        assert_eq!(registry.unlisted().unwrap(), vec![account.id], "но данные на месте");

        registry.adopt(&account.id, "работа", 100).unwrap();
        assert_eq!(registry.listed().len(), 1, "и возвращается");
        assert!(registry.unlisted().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wiping_takes_the_files_too() {
        let root = temp_root("wipe");
        let mut entropy = SeededEntropy::new(5);
        let mut registry = Registry::open(&root).unwrap();
        let account = registry.create(&mut entropy, "лишний", 100).unwrap();

        std::fs::write(registry.db_path(&account.id), b"x").unwrap();
        std::fs::write(root.join(hex(&account.id)).with_extension("db-wal"), b"x").unwrap();
        std::fs::create_dir_all(registry.blobs_path(&account.id)).unwrap();
        std::fs::write(registry.blobs_path(&account.id).join("chunk"), b"x").unwrap();

        registry.wipe(&account.id).unwrap();
        assert!(registry.listed().is_empty());
        assert!(!registry.db_path(&account.id).exists());
        assert!(
            !root.join(hex(&account.id)).with_extension("db-wal").exists(),
            "WAL переживает удаление основного файла и воскрешает часть переписки"
        );
        assert!(!registry.blobs_path(&account.id).exists(), "вложения тоже");

        // Повтор безвреден: стирать нечего — значит уже стёрто.
        registry.wipe(&account.id).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_broken_registry_is_not_an_empty_one() {
        // Разница существенная: на пустой список человек заведёт всё заново
        // поверх целых баз, а на отказ — позовёт на помощь.
        let root = temp_root("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(REGISTRY_FILE), b"\xff\xff\xff").unwrap();

        assert!(matches!(Registry::open(&root), Err(AccountError::Corrupt)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_label_that_would_break_the_list_is_refused() {
        let root = temp_root("labels");
        let mut entropy = SeededEntropy::new(6);
        let mut registry = Registry::open(&root).unwrap();

        assert!(registry.create(&mut entropy, "   ", 100).is_err(), "пустое имя");
        assert!(registry.create(&mut entropy, "работа\nличное", 100).is_err(), "перевод строки");
        assert!(
            registry.create(&mut entropy, &"я".repeat(MAX_LABEL_CHARS + 1), 100).is_err(),
            "длиннее предела"
        );
        assert_eq!(
            registry.create(&mut entropy, "  работа  ", 100).unwrap().label,
            "работа",
            "краевые пробелы снимаются"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_stranger_in_the_directory_is_not_an_account() {
        // Перебор нечислящихся файлов — это попытки открыть чужое. Принять
        // за аккаунт что попало значит тратить полсекунды Argon2id на каждый
        // посторонний файл.
        let root = temp_root("strangers");
        let registry = Registry::open(&root).unwrap();
        std::fs::write(root.join("notes.db"), b"x").unwrap();
        std::fs::write(root.join("00112233445566778899AABBCCDDEEFF.db"), b"x").unwrap();
        std::fs::write(root.join("0011223344556677.db"), b"x").unwrap();

        assert!(registry.unlisted().unwrap().is_empty(), "имя не наше — файл не наш");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_registry_round_trips_through_its_own_codec() {
        let listed = vec![
            Account { id: [1u8; 16], label: "работа".into(), created_ms: 100 },
            Account { id: [2u8; 16], label: "личное".into(), created_ms: 200 },
        ];
        let bytes = encode_registry(&listed).unwrap();
        assert_eq!(decode_registry(&bytes).unwrap(), listed);
    }
}
