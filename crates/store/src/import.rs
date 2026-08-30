//! Ввоз архива переписки (§12).
//!
//! # Обратная сторона [`crate::archive`], и она опаснее
//!
//! Вывоз читает своё и пишет свой файл. Ввоз читает **чужой** файл — тот,
//! что приехал на флешке, полежал в облаке, мог быть оборван на середине
//! копирования или подменён целиком. Отсюда весь вид этого модуля: сперва
//! всё собирается рядом и проверяется, и только потом занимает своё место.
//!
//! # Что такое ввоз, а что нет
//!
//! Здесь **восстановление**: архив становится аккаунтом. Идентичность,
//! контакты, история — из архива, и рядом с ними ничего не было.
//!
//! Слияния с уже живущим аккаунтом здесь нет и в v1 не будет. Причина не
//! в трудоёмкости: у слияния нет ответа на вопрос, чьей остаётся личность.
//! Две личности в одном аккаунте — не состояние, которое можно как-то
//! показать; человек не бывает двумя людьми. Поэтому база, лежащая на месте
//! назначения, — это отказ, а не повод что-то решать за человека.
//!
//! # Две личности в сети — это на совести человека
//!
//! Восстановленный аккаунт — **та же** личность, что осталась на прежнем
//! устройстве. Два устройства, отвечающие одним `IK`, разойдутся сессиями
//! (§8.4) и запутают собеседников: у каждого своя очередь, свои счётчики,
//! свои квитанции. Для второго экрана есть режим компаньона (§13.4), и он
//! устроен ровно затем, чтобы этого не случилось.
//!
//! Запретить это ввоз не может — старое устройство ему недоступно. Что он
//! может и обязан: сказать словами, что прежним пользоваться больше нельзя.

use std::path::Path;

use zeroize::Zeroizing;

use crate::archive::{ArchiveError, ArchiveReader, EntryKind, ExportScope, KeyWrap};
use crate::blobs::Blobs;
use crate::{schema, Result, SqliteStore, Store, StoreError};

impl From<ArchiveError> for StoreError {
    fn from(error: ArchiveError) -> StoreError {
        StoreError::Backend(error.to_string())
    }
}

/// Чем открывают архив (§12).
///
/// Два входа в один и тот же архив, и это не избыточность. Фразу человек
/// придумывает сам и держит в голове; сырой ключ он кладёт в менеджер
/// паролей и не смотрит на него никогда. Первое — для того, кто меняет
/// телефон; второе — для того, кто восстанавливает архив пятилетней
/// давности, фразу от которого давно забыл.
#[derive(Debug, Clone, Copy)]
pub enum ArchiveUnlock<'a> {
    /// Сырой ключ базы — тот, что показывался при вывозе.
    Key(&'a Zeroizing<[u8; 32]>),
    /// Фраза, которую человек придумал при вывозе.
    ///
    /// Работает только с архивом, в котором есть завёрнутый ключ. У архива
    /// постарше его нет, и отказ об этом скажет словами — иначе человек
    /// решит, что не помнит фразу, которой никогда не было.
    Passphrase(&'a str),
}

/// Что за архив лежит по этому пути — до того, как что-то спрашивать.
///
/// **Спрашивать надо то, что подойдёт.** Экран, требующий фразу от архива,
/// в котором её нет, — это тупик: человек будет вспоминать то, чего не было.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchivePeek {
    /// Что вывезено.
    pub scope: ExportScope,
    /// Открывается ли фразой. `false` — только сырым ключом.
    pub takes_passphrase: bool,
}

/// Заглядывает в архив, ничего не открывая (§12).
///
/// Читает заголовок и, если она есть, первую запись. Ни ключа, ни фразы
/// для этого не нужно: и область вывоза, и наличие завёрнутого ключа
/// лежат открыто — по ним ничего о переписке не узнать.
///
/// # Errors
///
/// Файла нет, это не архив, он новее этой сборки или оборван.
pub fn peek_archive(archive: &Path) -> Result<ArchivePeek> {
    let file = std::fs::File::open(archive)
        .map_err(|e| StoreError::Backend(format!("архив не открыть: {e}")))?;
    let mut reader = ArchiveReader::open(std::io::BufReader::new(file))?;
    let scope = reader.header().scope;
    let takes_passphrase = matches!(
        reader.next_entry()?,
        Some((entry, _)) if entry.kind == EntryKind::WrappedKey
    );
    Ok(ArchivePeek { scope, takes_passphrase })
}

/// Что приехало из архива — для показа человеку.
///
/// Числа здесь не украшение. Человек, вводящий чужой файл, вправе увидеть,
/// **что именно** он вставил, до того как начнёт этим пользоваться: сто
/// контактов и ноль сообщений — это граф, и если он ждал переписку,
/// то ошибся файлом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    /// Что было вывезено — из заголовка архива, а не из догадки.
    pub scope: ExportScope,
    /// Сколько знакомств приехало.
    pub contacts: u64,
    /// Сколько сообщений.
    pub messages: u64,
    /// Сколько записей о вложениях.
    pub files: u64,
    /// Сколько вложений доехало **целиком** — байтами, а не записью.
    pub whole_files: u64,
    /// Сколько байт вложений легло в хранилище.
    pub bytes: u64,
}

/// Восстанавливает аккаунт из архива (§12).
///
/// `destination` — куда лечь базе, `blobs` — куда лечь вложениям. Ключ —
/// тот, что человек переписал с экрана при вывозе
/// (`ratatosk_crypto::storage_key::key_from_text`).
///
/// **Существующая база — отказ.** Ввоз поверх живого аккаунта не имеет
/// смысла (см. заголовок модуля), а молча его затереть — это стереть
/// человеку переписку по нажатию кнопки «восстановить».
///
/// # Errors
///
/// Отказ, если файла нет, это не архив, он оборван, ключ не тот, схема
/// в нём новее этой сборки или база на месте назначения уже есть.
pub fn import_archive(
    archive: &Path,
    unlock: ArchiveUnlock<'_>,
    destination: &Path,
    blobs: &mut dyn Blobs,
) -> Result<Imported> {
    if destination.exists() {
        return Err(StoreError::Backend(
            "по этому пути уже есть база — ввоз поверх живого аккаунта не делается".into(),
        ));
    }

    // Собирается рядом, а не на месте: снимок, не прошедший проверку,
    // не должен ни секунды лежать под именем настоящей базы.
    let temp = destination.with_extension("import-tmp");
    let _ = std::fs::remove_file(&temp);

    let done = assemble(archive, unlock, &temp, Some(blobs));
    if done.is_err() {
        // Куски вложений, успевшие лечь, остаются сиротами: базы, которая
        // о них знает, не будет. Их уберёт сверка (§12) — она затем
        // и написана, чтобы байты без записи не жили вечно.
        let _ = std::fs::remove_file(&temp);
        return done;
    }
    std::fs::rename(&temp, destination)
        .map_err(|e| StoreError::Backend(format!("база не встала на место: {e}")))?;
    done
}

/// Собирает базу и вложения рядом с местом назначения.
fn assemble(
    archive: &Path,
    unlock: ArchiveUnlock<'_>,
    temp: &Path,
    mut blobs: Option<&mut dyn Blobs>,
) -> Result<Imported> {
    use std::io::Write;

    let file = std::fs::File::open(archive)
        .map_err(|e| StoreError::Backend(format!("архив не открыть: {e}")))?;
    let mut reader = ArchiveReader::open(std::io::BufReader::new(file))?;
    let header = reader.header();

    let mut snapshot = std::io::BufWriter::new(
        std::fs::File::create(temp)
            .map_err(|e| StoreError::Backend(format!("базу не создать: {e}")))?,
    );

    // Ключ базы: либо принесён человеком, либо лежит в архиве завёрнутым
    // во фразу. Второй случай **разворачивается первым делом** — куски базы
    // им и открываются, а читаем мы потоком.
    let mut key: Option<Zeroizing<[u8; 32]>> = match unlock {
        ArchiveUnlock::Key(key) => Some(Zeroizing::new(**key)),
        ArchiveUnlock::Passphrase(_) => None,
    };

    // Куски базы обязаны идти по порядку: снимок склеивается встык,
    // и кусок не на своём месте дал бы базу, которая открывается
    // и врёт. Проверяется счётчиком, а не доверием к писателю.
    let mut expect_db = 0u64;
    let mut arrived: Vec<(crate::FileId, u64)> = Vec::new();
    let mut bytes = 0u64;

    while let Some((entry, body)) = reader.next_entry()? {
        match entry.kind {
            EntryKind::WrappedKey => {
                let ArchiveUnlock::Passphrase(phrase) = unlock else {
                    // Пришли с сырым ключом — заворачивание нам ни к чему.
                    // Не ошибка: у архива два входа, и человек выбрал второй.
                    continue;
                };
                if key.is_some() || expect_db > 0 {
                    return Err(StoreError::Backend(
                        "завёрнутый ключ в архиве не первой записью — архив испорчен".into(),
                    ));
                }
                key = Some(unwrap_key(&header.archive_id, phrase, &body)?);
            }
            EntryKind::Database => {
                if entry.index != expect_db {
                    return Err(StoreError::Backend(format!(
                        "куски базы идут не по порядку: ждали {expect_db}, приехал {}",
                        entry.index
                    )));
                }
                let Some(key) = key.as_ref() else {
                    // Фразу спросили, а завернуть ключ было некому: архив
                    // старее фразы. Сказать это словами обязательно — иначе
                    // человек будет вспоминать то, чего никогда не было.
                    return Err(StoreError::Backend(
                        "этот архив фразой не открывается: в нём нет завёрнутого ключа. \
                         Нужен ключ, который показывался при вывозе"
                            .into(),
                    ));
                };
                let aad = crate::archive::db_chunk_aad(&header.archive_id, entry.index);
                let open = ratatosk_crypto::storage_key::open_field(key, &aad, &body)
                    .map_err(|_| StoreError::Backend("ключ не подходит к этому архиву".into()))?;
                snapshot
                    .write_all(&open)
                    .map_err(|e| StoreError::Backend(format!("база не записалась: {e}")))?;
                expect_db += 1;
            }
            EntryKind::Attachment => {
                // Хранилища байтов может не быть вовсе: слияние знакомств
                // (`open_snapshot`) читает из архива одну базу, и раскладывать
                // ради этого гигабайты вложений незачем.
                let Some(blobs) = blobs.as_deref_mut() else { continue };
                // Как есть: кусок уже запечатан своим ключом (§10.1),
                // и ключ этот лежит в базе, которую мы только что открыли
                // тем же ключом архива.
                blobs.put_chunk(&entry.id, entry.index, &body)?;
                arrived.push((entry.id, entry.index));
                bytes += body.len() as u64;
            }
        }
    }
    snapshot.flush().map_err(|e| StoreError::Backend(format!("база не дописалась: {e}")))?;
    drop(snapshot);

    if expect_db == 0 {
        return Err(StoreError::Backend("в архиве нет базы — это не архив переписки".into()));
    }
    let Some(key) = key else {
        return Err(StoreError::Backend("архив без базы и без ключа".into()));
    };

    finish(temp, &key, header.scope, &arrived, bytes)
}

/// Разворачивает ключ базы из фразы.
///
/// Настройки вывода берутся **из архива**, а не из этой сборки: подними мы
/// стоимость Argon2id — и архив, сделанный вчера, перестал бы открываться,
/// а человек прочёл бы это как «фраза не та».
fn unwrap_key(archive_id: &[u8; 16], phrase: &str, body: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let wrap = KeyWrap::from_bytes(body)?;
    let params = ratatosk_crypto::storage_key::KdfParams {
        memory_kib: wrap.memory_kib,
        iterations: wrap.iterations,
        parallelism: wrap.parallelism,
    };
    // Та же дверь, что у PIN (§8.6): фраза — это тот же секрет из головы,
    // и второй вывод ключа рядом с первым однажды разошёлся бы с ним.
    let from_phrase = ratatosk_crypto::storage_key::derive_from_pin(phrase, &wrap.salt, params)
        .map_err(|_| StoreError::Backend("ключ из фразы не вывелся".into()))?;
    let opened = ratatosk_crypto::storage_key::open_field(
        &from_phrase,
        &crate::archive::wrapped_key_aad(archive_id),
        &wrap.sealed,
    )
    .map_err(|_| StoreError::Backend("фраза не подходит к этому архиву".into()))?;
    let key: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Backend("в архиве не ключ базы".into()))?;
    Ok(Zeroizing::new(key))
}

/// Открывает собранную базу, проверяет её и приводит записи о вложениях
/// в согласие с тем, что доехало.
fn finish(
    temp: &Path,
    key: &Zeroizing<[u8; 32]>,
    scope: ExportScope,
    arrived: &[(crate::FileId, u64)],
    bytes: u64,
) -> Result<Imported> {
    let contacts = prepare(temp, key)?.contacts()?.len() as u64;

    let counts = reconcile_files(temp, scope, arrived)?;

    // **Журнал сводится и соединения закрываются до переименования.**
    // База открыта в режиме WAL: часть только что написанного лежит
    // в `<temp>-wal`, и переезд одного файла оставил бы её позади —
    // молча, потому что база и без неё откроется.
    {
        let conn = rusqlite::Connection::open(temp)?;
        // Через `query_row`, а не `pragma_update`: `journal_mode` возвращает
        // строку с новым режимом, а `pragma_update` на возвращённой строке
        // спотыкается.
        conn.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))?;
    }
    // Приписка **к имени целиком**, как её делает сам SQLite: `with_extension`
    // здесь заменил бы расширение и промахнулся бы по имени файла.
    for suffix in ["-wal", "-shm"] {
        let mut beside = temp.as_os_str().to_os_string();
        beside.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(beside));
    }

    Ok(Imported {
        scope,
        contacts,
        messages: counts.messages,
        files: counts.files,
        whole_files: counts.whole,
        bytes,
    })
}

/// Открывает собранный снимок: проверяет схему, мигрирует, читает поле.
///
/// **Схема новее этой сборки — отказ.** Мигрировать назад нечем, а читать
/// чужое будущее наугад — это показать человеку переписку, разобранную
/// неверно. Спрашивается до открытия хранилища: `migrate` откажет и сам,
/// но своими словами, про «более старую сборку поверх более новой БД», —
/// а человек вводит архив, и услышать он должен про архив.
fn prepare(temp: &Path, key: &Zeroizing<[u8; 32]>) -> Result<SqliteStore> {
    {
        let probe = rusqlite::Connection::open(temp)?;
        let version: u32 = probe.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > schema::SCHEMA_VERSION {
            return Err(StoreError::Backend(format!(
                "архив сделан сборкой новее: схема {version}, здесь {}",
                schema::SCHEMA_VERSION
            )));
        }
        if version == 0 {
            return Err(StoreError::Backend(
                "в архиве не база переписки: схемы в ней нет вовсе".into(),
            ));
        }
    }
    // Схема старее — обычное дело: архив мог пролежать год. Миграции те же,
    // что накатываются на живую базу.
    let mut store = SqliteStore::open(temp, Zeroizing::new(**key))?;
    store.migrate()?;
    // Первое настоящее чтение запечатанных полей: до него ключ подтверждён
    // только кусками архива. Отказ здесь означал бы, что поля внутри
    // шифровались не тем ключом, каким собран архив.
    store.contacts()?;
    Ok(store)
}

/// Архив, открытый **только на чтение** (§12).
///
/// Нужен слиянию знакомств: оно берёт из чужого архива контакты и не трогает
/// ни своей личности, ни своей переписки. Вложения при этом не раскладываются
/// вовсе — ради списка контактов гонять гигабайты незачем.
///
/// Черновик базы живёт, пока живёт эта запись, и убирается вместе с ней.
/// Порядок полей — порядок уборки: сперва закрывается хранилище, потом
/// стирается файл.
pub struct Snapshot {
    /// Открытая база из архива. Читать — можно, писать в неё незачем.
    pub store: SqliteStore,
    /// Что было вывезено.
    pub scope: ExportScope,
    /// Ключ базы: им же открывается зерно личности внутри (§3).
    pub key: Zeroizing<[u8; 32]>,
    path: std::path::PathBuf,
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        // Черновик — расшифрованная копия чужой базы. Оставлять его лежать
        // нельзя ни в каком исходе, включая панику выше по стеку.
        let _ = std::fs::remove_file(&self.path);
        for suffix in ["-wal", "-shm"] {
            let mut beside = self.path.as_os_str().to_os_string();
            beside.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(beside));
        }
    }
}

/// Открывает архив на чтение, ничего никуда не вставляя (§12).
///
/// `scratch` — каталог для черновика. **От вызывающего, а не общий
/// временный:** на телефоне общего временного каталога нет, а расшифрованная
/// копия чужой базы в общем месте — это утечка.
///
/// # Errors
///
/// Файла нет, это не архив, он оборван, ключ или фраза не те, схема новее
/// этой сборки.
pub fn open_snapshot(
    archive: &Path,
    unlock: ArchiveUnlock<'_>,
    scratch: &Path,
) -> Result<Snapshot> {
    std::fs::create_dir_all(scratch)
        .map_err(|e| StoreError::Backend(format!("каталог для черновика не создать: {e}")))?;
    let path = scratch.join(format!(
        "ratatosk-snapshot-{}-{:?}.db",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    let opened = assemble(archive, unlock, &path, None).and_then(|imported| {
        let key = match unlock {
            ArchiveUnlock::Key(key) => Zeroizing::new(**key),
            // Фразу разворачивал `assemble`; развернуть её второй раз дешевле,
            // чем протаскивать ключ сквозь отчёт о ввозе, который к слиянию
            // отношения не имеет.
            ArchiveUnlock::Passphrase(_) => key_from_archive(archive, unlock)?,
        };
        let store = prepare(&path, &key)?;
        Ok(Snapshot { store, scope: imported.scope, key, path: path.clone() })
    });
    if opened.is_err() {
        let _ = std::fs::remove_file(&path);
    }
    opened
}

/// Достаёт ключ базы из архива, запертого фразой.
fn key_from_archive(archive: &Path, unlock: ArchiveUnlock<'_>) -> Result<Zeroizing<[u8; 32]>> {
    let ArchiveUnlock::Passphrase(phrase) = unlock else {
        return Err(StoreError::Backend("ключ и так известен".into()));
    };
    let file = std::fs::File::open(archive)
        .map_err(|e| StoreError::Backend(format!("архив не открыть: {e}")))?;
    let mut reader = ArchiveReader::open(std::io::BufReader::new(file))?;
    let archive_id = reader.header().archive_id;
    match reader.next_entry()? {
        Some((entry, body)) if entry.kind == EntryKind::WrappedKey => {
            unwrap_key(&archive_id, phrase, &body)
        }
        _ => Err(StoreError::Backend(
            "этот архив фразой не открывается: в нём нет завёрнутого ключа".into(),
        )),
    }
}

/// Что насчитали в восстановленной базе.
struct Counts {
    messages: u64,
    files: u64,
    whole: u64,
}

/// Приводит записи о вложениях в согласие с тем, что доехало.
///
/// **Состояние вложения считается по приехавшим байтам, а не по тому, что
/// записано в снимке.** Причина не в подозрительности к архиву, а в том,
/// что байты и записи разъезжаются законно:
///
/// * в архиве без вложений (`WithoutAttachments`) записи есть, а байтов нет
///   вовсе — по решению человека;
/// * **и в полном архиве тоже**: у отправленных с телефона файлов байты
///   лежат по `source_path` — в галерее, в загрузках, где человек их
///   положил, — а в хранилище вложений их нет и не было. Вывозить чужие
///   файлы из галереи мессенджер не вправе.
///
/// Оставить `complete = 1` там, где байтов нет, значит показать человеку
/// вложение, которое не открывается, — ровно то, что §14 запрещает.
fn reconcile_files(
    temp: &Path,
    scope: ExportScope,
    arrived: &[(crate::FileId, u64)],
) -> Result<Counts> {
    let conn = rusqlite::Connection::open(temp)?;

    // Отметки о кусках переписываются целиком по тому, что легло: строки
    // из снимка говорят о хранилище прежнего устройства, а не этого.
    //
    // **Таблицы две, и раскладывать куски надо по обеим.** В хранилище
    // байтов лежат и вложения сообщений (`files`), и незаконченные выгрузки
    // с десктопа (`staged_files`, §13.4) — а `file_id` у них из одного
    // пространства. Свалив всё в одну таблицу, мы завели бы строки,
    // ссылающиеся в пустоту, и заодно потеряли бы выгрузку, которая
    // на прежнем устройстве шла и могла бы продолжиться на этом.
    //
    // Проверка `EXISTS` — она же и защита от третьего случая: кусок, чьего
    // файла нет ни в одной из таблиц, не попадает никуда. Внешние ключи
    // на этом соединении выключены, и молча принять такую строку было бы
    // легко.
    conn.execute("DELETE FROM file_chunks", [])?;
    conn.execute("DELETE FROM staged_chunks", [])?;
    {
        let mut into_files = conn.prepare(
            "INSERT OR IGNORE INTO file_chunks (file_id, chunk_index)
             SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM files WHERE files.file_id = ?1)",
        )?;
        let mut into_staged = conn.prepare(
            "INSERT OR IGNORE INTO staged_chunks (file_id, chunk_index)
             SELECT ?1, ?2
              WHERE EXISTS (SELECT 1 FROM staged_files WHERE staged_files.file_id = ?1)",
        )?;
        for (file_id, index) in arrived {
            let index = crate::sql_types::to_sql(*index);
            into_files.execute(rusqlite::params![&file_id[..], index])?;
            into_staged.execute(rusqlite::params![&file_id[..], index])?;
        }
    }

    // Целым считается тот, у кого кусков столько же, сколько обещает запись.
    conn.execute(
        "UPDATE files SET complete = (
             SELECT count(*) FROM file_chunks WHERE file_chunks.file_id = files.file_id
         ) >= chunk_total AND chunk_total > 0",
        [],
    )?;

    // В архиве без вложений согласие снимается со всех: иначе первое же
    // подключение начало бы тянуть с собеседников всё, от чего человек
    // только что отказался ради лёгкого архива. В полном архиве согласие
    // остаётся — там незаконченная передача продолжится сама, как после
    // обычного перезапуска (§10.2).
    if scope == ExportScope::WithoutAttachments {
        conn.execute("UPDATE files SET accepted = 0 WHERE complete = 0", [])?;
    }

    let messages: i64 =
        conn.query_row("SELECT count(*) FROM messages WHERE tombstone_ms IS NULL", [], |r| {
            r.get(0)
        })?;
    let files: i64 = conn.query_row("SELECT count(*) FROM files", [], |r| r.get(0))?;
    let whole: i64 =
        conn.query_row("SELECT count(*) FROM files WHERE complete = 1", [], |r| r.get(0))?;

    Ok(Counts { messages: messages as u64, files: files as u64, whole: whole as u64 })
}
