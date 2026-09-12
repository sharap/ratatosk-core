//! Реализация хранилища на SQLite.
//!
//! Шифрование — на уровне приложения (§12), а не SQLCipher: `db_key`
//! применяется к отдельным полям перед записью. Так криптостек остаётся один
//! (§5.3: «криптостек в системе один»), и не появляется второй, спрятанный
//! внутри драйвера БД.

use std::path::{Path, PathBuf};

use ratatosk_crdt::{Hlc, MsgId};
use ratatosk_crypto::storage_key;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::compaction::{self, Task};
use crate::schema;
use crate::sql_types;
use crate::tokens;
use crate::{
    FileId, Result, StagedUpload, Store, StoreError, StoredAvatar, StoredContact,
    StoredContactShare, StoredFile, StoredGroup, StoredGroupAvatar, StoredMembershipBlock,
    StoredMembershipOp, StoredMessage, StoredOutbox, StoredPairedDevice, StoredPendingGroup,
    StoredReaction, StoredSenderChain, StoredSession,
};

/// Хранилище на SQLite.
pub struct SqliteStore {
    conn: Connection,
    path: PathBuf,
    /// Ключ шифрования полей (§8.6). Хранилище им только пользуется — выводит
    /// его из PIN тот, кто знает PIN, а это не дело хранилища.
    db_key: Zeroizing<[u8; 32]>,
}

impl SqliteStore {
    /// Открывает базу по пути.
    pub fn open(path: impl AsRef<Path>, db_key: Zeroizing<[u8; 32]>) -> Result<SqliteStore> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        conn.execute_batch(schema::PRAGMAS)?;
        Ok(SqliteStore { conn, path, db_key })
    }

    /// Открывает базу **только на чтение**, не трогая файл.
    ///
    /// Нужно перебору скрытых аккаунтов (`core::vault::accepts_pin`): он идёт
    /// по каталогу, где рядом лежит что попало, и портить соседей не вправе.
    ///
    /// Отличие от [`SqliteStore::open`] не в намерении, а в последствиях,
    /// и они серьёзнее, чем кажется. Обычное открытие применяет прагмы,
    /// среди которых `journal_mode = WAL`, — а она **записывает** в файл
    /// и делает это необратимо: чужая база по соседству переводится в режим
    /// WAL, рядом с ней заводятся `-wal` и `-shm`. Пустой файл при этом
    /// перестаёт быть пустым: SQLite считает его новой базой и пишет
    /// заголовок.
    ///
    /// Поэтому здесь нет ни прагм, ни миграций. Читать это позволяет ровно
    /// то, что нужно перебору: `meta` заведена первой миграцией и есть
    /// в любой нашей базе, а прагмы на чтение не влияют.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`], если файла нет или он недоступен. «Файл есть,
    /// но это не база» здесь **не** ошибка: SQLite открывает лениво, и узнает
    /// об этом первый же запрос.
    pub fn open_readonly(
        path: impl AsRef<Path>,
        db_key: Zeroizing<[u8; 32]>,
    ) -> Result<SqliteStore> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        Ok(SqliteStore { conn, path, db_key })
    }

    /// Открывает базу в памяти — для тестов и симуляции.
    pub fn in_memory(db_key: Zeroizing<[u8; 32]>) -> Result<SqliteStore> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::PRAGMAS)?;
        Ok(SqliteStore { conn, path: PathBuf::new(), db_key })
    }

    /// Привязка шифротекста к его месту.
    ///
    /// Без неё запечатанное поле можно переставить из строки в строку —
    /// расшифровка пройдёт, и в чужом сообщении окажется своё содержимое.
    fn field_aad(column: &str, row_key: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(column.len() + 1 + row_key.len());
        aad.extend_from_slice(column.as_bytes());
        aad.push(b':');
        aad.extend_from_slice(row_key);
        aad
    }

    /// Ключ строки реакции: сообщение и автор вместе.
    ///
    /// Порознь их брать нельзя: по одному `msg_id` шифротекст переставлялся бы
    /// между авторами, и реакция одного человека читалась бы как реакция
    /// другого.
    fn reaction_row_key(msg_id: &MsgId, author_ik: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(msg_id.len() + author_ik.len());
        key.extend_from_slice(msg_id);
        key.extend_from_slice(author_ik);
        key
    }

    /// Ключ строки цепочки отправителя: чат, затем участник.
    ///
    /// Пары мало по той же причине, что и у реакций: одна половина ключа
    /// повторяется у многих строк, и AAD, собранный из неё одной, разрешил
    /// бы переставить шифротекст между ними прямым доступом к файлу.
    fn chain_row_key(chat_id: &[u8; 16], member_ik: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(chat_id.len() + member_ik.len());
        key.extend_from_slice(chat_id);
        key.extend_from_slice(member_ik);
        key
    }

    /// Собирает группу из прочитанной строки, расшифровывая название.
    fn group_row(
        &self,
        chat_id: [u8; 16],
        owner: &[u8],
        sealed: &[u8],
        created_ms: i64,
        title_wall: i64,
        title_logical: i64,
    ) -> Result<StoredGroup> {
        let owner_ik: [u8; 32] = owner
            .try_into()
            .map_err(|_| StoreError::Backend("ключ владельца не 32 байта".into()))?;
        let opened = self.open_sealed("chats.title_enc", &chat_id, sealed)?;
        let title = String::from_utf8(opened)
            .map_err(|_| StoreError::Backend("название группы не UTF-8".into()))?;
        Ok(StoredGroup {
            chat_id,
            owner_ik,
            title,
            title_wall: sql_types::from_sql(title_wall),
            // Логическая часть HLC — 32 бита; в базе она лежит целым
            // со знаком, и обрезка невозможна: больше `u32::MAX` туда
            // не кладётся.
            title_logical: u32::try_from(sql_types::from_sql(title_logical)).unwrap_or(u32::MAX),
            created_ms: sql_types::from_sql(created_ms),
        })
    }

    /// Собирает цепочку из прочитанной строки, расшифровывая состояние.
    fn chain_row(
        &self,
        chat_id: &[u8; 16],
        member_ik: [u8; 32],
        sealed: &[u8],
        counter: i64,
        // Метка поворота одним аргументом, а не двумя: врозь они
        // бессмысленны, а порознь переданные легко перепутать местами.
        mark: (i64, i64),
        skipped: Option<&[u8]>,
    ) -> Result<StoredSenderChain> {
        let row_key = Self::chain_row_key(chat_id, &member_ik);
        let opened = self.open_sealed("sender_chains.chain_enc", &row_key, sealed)?;
        let chain: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Backend("состояние цепочки не 32 байта".into()))?;
        let skipped = match skipped {
            Some(bytes) => self.open_sealed("sender_chains.skipped_enc", &row_key, bytes)?,
            None => Vec::new(),
        };
        Ok(StoredSenderChain {
            member_ik,
            chain,
            counter: sql_types::from_sql(counter),
            chain_wall: sql_types::from_sql(mark.0),
            // Логическая часть HLC — 32 бита; в базе она лежит целым
            // со знаком, и обрезка невозможна: больше `u32::MAX` туда
            // не кладётся.
            chain_logical: u32::try_from(sql_types::from_sql(mark.1)).unwrap_or(u32::MAX),
            skipped,
        })
    }

    fn seal(&self, column: &str, row_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        storage_key::seal_field(&self.db_key, &Self::field_aad(column, row_key), plaintext)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// Выбрасывает из снимка всё, кроме знакомств (§12).
    ///
    /// **Оставляется перечисленное, опустошается остальное**, а не наоборот.
    /// Список того, что выбрасывать, отстал бы от схемы молча: новая таблица
    /// уехала бы вместе с графом, а в ней могла оказаться переписка.
    /// Таблица, которой нет ни в одном списке, попадает в журнал — тем же
    /// приёмом, что и `warn_if_filling`.
    ///
    /// Соединение своё и **без наших прагм**: внешние ключи здесь выключены
    /// нарочно. Опустошаются целые таблицы, и порядок удаления при живых
    /// ключах пришлось бы выстраивать; то, что остаётся, не ссылается
    /// ни на что.
    fn prune_to_graph(snapshot: &Path) -> Result<()> {
        let conn = Connection::open(snapshot)?;

        let mut tables: Vec<String> = Vec::new();
        {
            let mut statement = conn.prepare(
                "SELECT name FROM sqlite_master \
                   WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                tables.push(row?);
            }
        }

        for table in &tables {
            if !schema::ALL_TABLES.contains(&table.as_str()) {
                tracing::warn!(
                    table = %table,
                    "таблица не описана в списках вывоза (§12) — уезжает пустой"
                );
            }
            if schema::GRAPH_TABLES.contains(&table.as_str()) {
                continue;
            }
            // Имя таблицы параметром быть не может, а взято оно из самой
            // базы и сверено со списком — подставить сюда чужое неоткуда.
            conn.execute(&format!("DELETE FROM \"{table}\""), [])?;
        }

        // `meta` уезжает не целиком: там и личность, и отметки прочтения
        // по каждому чату. Строки перечислены поимённо по той же причине.
        let holes = (1..=schema::GRAPH_META_KEYS.len())
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute(
            &format!("DELETE FROM meta WHERE key NOT IN ({holes})"),
            rusqlite::params_from_iter(schema::GRAPH_META_KEYS),
        )?;

        // Второй `VACUUM`: без него снимок остался бы размером с базу —
        // страницы освободились, но файл не сжался, и «только контакты»
        // весил бы как вся переписка.
        conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Читает снимок по куску, печатает `db_key` и кладёт в архив (§12).
    ///
    /// По куску, а не целиком: база бывает в сотни мегабайт, и держать
    /// её в памяти дважды — открытую и запечатанную — телефон не обязан.
    fn seal_snapshot_into(
        &self,
        snapshot: &Path,
        sink: &mut dyn crate::archive::ArchiveSink,
    ) -> Result<()> {
        use std::io::Read;

        let archive_id = sink.archive_id();
        let mut file = std::fs::File::open(snapshot)
            .map_err(|e| StoreError::Backend(format!("снимок базы не открыть: {e}")))?;
        let mut buffer = vec![0u8; crate::archive::SNAPSHOT_CHUNK_BYTES];
        let mut index = 0u64;
        loop {
            let mut filled = 0usize;
            // Читаем до полного куска: `read` вправе вернуть меньше, чем
            // просили, и в середине файла это не конец. Куски разной длины
            // архив бы принял, но снимок из них потом не собрался бы.
            while filled < buffer.len() {
                let got = file
                    .read(&mut buffer[filled..])
                    .map_err(|e| StoreError::Backend(format!("снимок базы не прочитать: {e}")))?;
                if got == 0 {
                    break;
                }
                filled += got;
            }
            if filled == 0 {
                break;
            }
            let aad = crate::archive::db_chunk_aad(&archive_id, index);
            let sealed = storage_key::seal_field(&self.db_key, &aad, &buffer[..filled])
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            sink.put(crate::archive::EntryKind::Database, &[0u8; 16], index, &sealed)
                .map_err(|e| StoreError::Backend(format!("архив не записался: {e}")))?;
            index += 1;
            if filled < buffer.len() {
                break;
            }
        }
        Ok(())
    }

    /// Переписывает поисковый индекс сообщения (§12).
    ///
    /// Сперва удаляет, потом вставляет: правка сообщения обязана убрать
    /// слова, которых в нём больше нет, — иначе поиск находил бы по тексту,
    /// который человек стёр.
    ///
    /// Ассоциированная функция, а не метод: зовётся изнутри транзакции,
    /// а `&self` там уже занят заимствованием соединения.
    fn index_words(
        tx: &rusqlite::Transaction<'_>,
        db_key: &[u8; 32],
        msg_id: &MsgId,
        body: &[u8],
    ) -> Result<()> {
        tx.execute("DELETE FROM message_tokens WHERE msg_id = ?1", [&msg_id[..]])?;

        // Тело не текст — индексировать нечего. Не ошибка: сообщением
        // с вложением может быть и пустая подпись.
        let Ok(text) = std::str::from_utf8(body) else { return Ok(()) };
        let mut insert =
            tx.prepare("INSERT OR IGNORE INTO message_tokens (msg_id, token) VALUES (?1, ?2)")?;
        for token in tokens::tokens_of(db_key, text) {
            insert.execute(rusqlite::params![&msg_id[..], &token[..]])?;
        }
        Ok(())
    }

    /// Убирает сообщение из поискового индекса.
    ///
    /// Зовётся там, где тело стирается, а строка остаётся, — то есть
    /// у надгробий (§12). Каскад внешнего ключа тут не поможет: строка
    /// никуда не делась, делось её содержимое, и индекс по нему обязан
    /// уйти вместе с ним. Иначе поиск находил бы удалённое.
    fn forget_words(tx: &rusqlite::Transaction<'_>, msg_id: &MsgId) -> Result<()> {
        tx.execute("DELETE FROM message_tokens WHERE msg_id = ?1", [&msg_id[..]])?;
        Ok(())
    }

    /// Строит поисковый индекс заново, если он построен не по тому формату.
    ///
    /// Формат хранится в служебной таблице ([`crate::META_SEARCH_INDEX`]).
    /// Нет записи — индекса нет вовсе: так выглядит и свежая база, и та,
    /// что дожила до появления поиска.
    fn index_if_stale(tx: &rusqlite::Transaction<'_>, db_key: &[u8; 32]) -> Result<()> {
        let stored: Option<Vec<u8>> = tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [crate::META_SEARCH_INDEX], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        let built = stored
            .and_then(|raw| <[u8; 4]>::try_from(raw.as_slice()).ok())
            .map_or(0, u32::from_be_bytes);
        if built == tokens::INDEX_FORMAT {
            return Ok(());
        }

        // Старые токены — в мусор целиком, а не поверх: посчитанные по другим
        // правилам, они не совпадут ни с одним запросом и останутся лежать
        // навсегда.
        tx.execute("DELETE FROM message_tokens", [])?;
        Self::index_everything(tx, db_key)?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![crate::META_SEARCH_INDEX, &tokens::INDEX_FORMAT.to_be_bytes()[..]],
        )?;
        Ok(())
    }

    /// Индексирует всю уже накопленную переписку — один раз, при обновлении.
    ///
    /// Дорого ровно настолько, насколько велика история, и делается ровно
    /// один раз: следующая запись пойдёт обычным путём. Тела приходится
    /// расшифровывать — иначе индексировать нечего.
    ///
    /// Надгробия пропускаются: тело у них пустое, и найтись они не должны.
    fn index_everything(tx: &rusqlite::Transaction<'_>, db_key: &[u8; 32]) -> Result<()> {
        let rows: Vec<(MsgId, Vec<u8>)> = {
            let mut statement =
                tx.prepare("SELECT msg_id, body_enc FROM messages WHERE tombstone_ms IS NULL")?;
            let mapped = statement
                .query_map([], |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
            let mut collected = Vec::new();
            for row in mapped {
                let (msg_id, body_enc) = row?;
                let Ok(msg_id) = MsgId::try_from(msg_id.as_slice()) else { continue };
                collected.push((msg_id, body_enc));
            }
            collected
        };

        for (msg_id, body_enc) in rows {
            // Расшифровать нечем — значит и индексировать нечего. Ронять
            // обновление из-за одной испорченной строки нельзя: человек
            // остался бы без приложения вовсе.
            let aad = Self::field_aad("messages.body_enc", &msg_id);
            let Ok(body) = storage_key::open_field(db_key, &aad, &body_enc) else { continue };
            Self::index_words(tx, db_key, &msg_id, &body)?;
        }
        Ok(())
    }

    fn open_sealed(&self, column: &str, row_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        storage_key::open_field(&self.db_key, &Self::field_aad(column, row_key), sealed)
            // Неверный PIN и порча файла здесь неотличимы, и различать их
            // незачем: читать в обоих случаях нечего.
            .map(|opened| opened.to_vec())
            .map_err(|_| StoreError::Locked)
    }

    /// Путь к файлу базы.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Удаляет записи старше TTL по индексу возраста.
    ///
    /// Граница берётся из [`compaction::cutoff_ms`], сравнение в SQL —
    /// **включающее** (`<=`), и это не мелочь: то же правило записано
    /// в [`compaction::is_expired`] для in-memory хранилища, а расхождение
    /// на один момент времени разводит два устройства. Согласие двух записей
    /// проверяется тестом `sql_cutoff_agrees_with_is_expired`.
    ///
    /// `None` от `cutoff_ms` означает, что устройство работает меньше TTL
    /// и удалять нечего, — запрос в этом случае не выполняется вовсе.
    fn purge_by_age(&self, sql: &str, ttl_ms: u64, now_ms: u64) -> Result<usize> {
        match compaction::cutoff_ms(now_ms, ttl_ms) {
            Some(cutoff) => Ok(self.conn.execute(sql, [sql_types::to_sql(cutoff)])?),
            None => Ok(0),
        }
    }

    /// Проверяет, что таблица, для которой уборка ещё не написана, пуста.
    ///
    /// Возвращает ноль всегда — убирать в ней нечего, пока в неё не пишут.
    /// Но если строки появились, молчать нельзя: значит, функцию завели,
    /// а уборку к ней забыли, и таблица будет расти, пока клиент не перестанет
    /// открываться. Тихая запись в журнал — не лучший сторож, зато она есть
    /// на устройстве пользователя, а тест на стенде — нет.
    fn warn_if_filling(&self, table: &str, whose: &str) -> Result<usize> {
        let rows: i64 =
            self.conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))?;
        if rows > 0 {
            tracing::error!(
                table,
                rows,
                "таблица заполняется, а уборка для неё не написана ({whose})"
            );
        }
        Ok(0)
    }

    /// Читает строки файлов из подготовленного запроса.
    ///
    /// Одно место на три чтения (`file`, `files_of`, `unfinished_files`):
    /// разведённые по веткам, они разошлись бы в том, что делать с испорченным
    /// полем, — а это решение про честность, а не про SQL.
    fn read_files(
        &self,
        statement: &mut rusqlite::Statement<'_>,
        params: impl rusqlite::Params,
    ) -> Result<Vec<StoredFile>> {
        let rows = statement.query_map(params, |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                sql_types::from_sql(row.get(3)?),
                sql_types::from_sql(row.get(4)?),
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, i64>(7)? != 0,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)? != 0,
                row.get::<_, i64>(10)? != 0,
                row.get::<_, i64>(11)?,
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (
                file_id,
                msg_id,
                name_enc,
                size_bytes,
                chunk_total,
                key_enc,
                preview_enc,
                incoming,
                source_path,
                accepted,
                complete,
                ordinal,
            ) = row?;
            let file_id: FileId =
                file_id.try_into().map_err(|_| StoreError::Backend("file_id не 16 байт".into()))?;
            // Имя и ключ обязательны: без ключа файл не собрать, а без имени
            // нечего показать. Испорченное здесь — это неверный PIN или порча
            // файла, и отвечать надо отказом, а не файлом без имени.
            let name =
                String::from_utf8(self.open_sealed("files.name_enc", &file_id, &name_enc)?)
                    .map_err(|_| StoreError::Backend("имя файла не UTF-8".into()))?;
            let key: [u8; 32] = self
                .open_sealed("files.file_key_enc", &file_id, &key_enc)?
                .try_into()
                .map_err(|_| StoreError::Backend("ключ файла не 32 байта".into()))?;
            let preview = match preview_enc {
                Some(sealed) => Some(self.open_sealed("files.preview_enc", &file_id, &sealed)?),
                None => None,
            };
            found.push(StoredFile {
                file_id,
                msg_id: msg_id
                    .try_into()
                    .map_err(|_| StoreError::Backend("msg_id не 16 байт".into()))?,
                name,
                size_bytes,
                chunk_total,
                key,
                preview,
                incoming,
                source_path,
                accepted,
                complete,
                // Отрицательного там взяться неоткуда — столбец пишем только
                // мы, — но читать чужое число как своё без проверки нельзя:
                // порченая база обязана давать отказ, а не тихий ноль.
                ordinal: u32::try_from(ordinal)
                    .map_err(|_| StoreError::Backend("порядок вложения вне диапазона".into()))?,
            });
        }
        Ok(found)
    }

    fn schema_version(&self) -> Result<u32> {
        let version: u32 = self.conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(version)
    }
}

impl Store for SqliteStore {
    fn migrate(&mut self) -> Result<()> {
        let current = self.schema_version()?;
        if current > schema::SCHEMA_VERSION {
            // Откат вниз по версии схемы невозможен: пользователь поставил
            // более старую сборку поверх более новой БД. Отказ с внятным
            // сообщением лучше, чем повреждение данных.
            return Err(StoreError::FutureSchema {
                found: current,
                supported: schema::SCHEMA_VERSION,
            });
        }

        let tx = self.conn.transaction()?;
        for (i, migration) in schema::MIGRATIONS.iter().enumerate() {
            let version = i as u32 + 1;
            if version > current {
                tx.execute_batch(migration)?;
            }
        }
        // Поисковый индекс заводится пустым, а переписка к этому моменту уже
        // есть. Наполнить его миграцией нельзя: токены считаются на `db_key`,
        // а SQL про ключи не знает, — поэтому наполнение идёт здесь, в той же
        // транзакции. Без него поиск на существующей базе молча не находил бы
        // ничего старше обновления, и списать это было бы не на что.
        //
        // Признак — **формат индекса**, а не версия схемы. Сперва стояло
        // «база младше девятой», и это работало ровно до следующей миграции:
        // версия схемы отвечает на вопрос «какие таблицы есть», а не
        // «заполнены ли они». Наполнение — операция над данными, и повод
        // у неё свой: сменилась токенизация, или индекс стёрли руками.
        Self::index_if_stale(&tx, &self.db_key)?;
        tx.pragma_update(None, "user_version", schema::SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(())
    }

    fn put_message(&mut self, message: &StoredMessage) -> Result<()> {
        // Тело шифруется до записи и привязывается к своей строке.
        let body_enc = self.seal("messages.body_enc", &message.msg_id, &message.body)?;

        let tx = self.conn.transaction()?;

        // Удалённое не воскрешаем. Ради этого надгробие и существует:
        // копия того же сообщения законно приходит вторым транспортом (§9.2),
        // и без этой проверки `INSERT OR REPLACE` ниже затёр бы надгробие
        // новой строкой — то есть вернул бы в чат то, что человек убрал.
        let tombstoned: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM messages WHERE msg_id = ?1 AND tombstone_ms IS NOT NULL",
                [&message.msg_id[..]],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        if tombstoned.is_some() {
            return Ok(());
        }

        // Внешний ключ `messages.chat_id → chats.chat_id` включён прагмой,
        // поэтому строка чата обязана существовать раньше сообщения.
        // `peer_ik` остаётся пустым: для 1:1 он выводится из `chat_id`,
        // а сообщение может прийти раньше, чем контакт станет известен.
        tx.execute(
            "INSERT OR IGNORE INTO chats (chat_id, kind, created_ms) VALUES (?1, 0, ?2)",
            rusqlite::params![&message.chat_id[..], sql_types::to_sql(message.received_ms)],
        )?;

        // `payload_type` пока всегда «текст»: `Engine::deliver` другого
        // и не кладёт. Файлы и групповые блоки (§10, §11) придут вместе
        // с расширением `StoredMessage`, а не отдельным полем здесь.
        //
        // `transport` не заполняется сознательно: у записи на диске живой
        // попытки доставки нет, а выдуманное значение §14 прямо запрещает.
        // `status` пишется как есть, включая `NULL` — «неизвестно» и «ждёт
        // отправки» это разные вещи.
        //
        // Про `OR REPLACE` и реакции. SQLite исполняет замену как удаление
        // строки, а `reactions.msg_id` объявлен `ON DELETE CASCADE` — значит
        // повторная запись **того же** `msg_id` унесла бы реакции. Сегодня
        // этого не происходит: до сюда доходит только новое сообщение, дубль
        // отсекается дедупликацией (§9.2) выше по стеку, а удалённое — проверкой
        // надгробия здесь же. Оговорка оставлена для того, кто когда-нибудь
        // решит писать через это место обновление существующей записи: править
        // текст надо `edit_message`, а не повторным `put_message`.
        tx.execute(
            "INSERT OR REPLACE INTO messages (
                 msg_id, chat_id, sender_ik, hlc_wall, hlc_logical,
                 payload_type, body_enc, received_ms, status, edited_ms, forwarded, reply_to
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &message.msg_id[..],
                &message.chat_id[..],
                &message.sender_ik[..],
                sql_types::to_sql(message.hlc.wall_ms),
                // Логическая компонента HLC — u32; величиной она от этого
                // быть не перестаёт, поэтому идёт через тот же `to_sql`.
                sql_types::to_sql(u64::from(message.hlc.logical)),
                body_enc,
                sql_types::to_sql(message.received_ms),
                message.status.map(i64::from),
                message.edited_ms.map(sql_types::to_sql),
                i64::from(message.forwarded),
                message.reply_to.map(|id| id.to_vec()),
            ],
        )?;
        // Индекс поиска — в той же транзакции, что и тело. Это не удобство:
        // разъехавшись, они дали бы сообщение, которое нельзя найти, либо
        // находку, которую нельзя показать.
        Self::index_words(&tx, &self.db_key, &message.msg_id, &message.body)?;
        tx.commit()?;
        Ok(())
    }

    fn messages(
        &self,
        chat_id: &[u8; 16],
        limit: usize,
        before: Option<Hlc>,
    ) -> Result<Vec<StoredMessage>> {
        // Порядок задаёт HLC, а не `received_ms` (§9.1) — ровно индекс
        // `messages_order`. Выбирается хвост окна: чат листается назад, поэтому
        // сортировка в запросе убывающая, а разворот делается после.
        let mut statement = self.conn.prepare(
            "SELECT msg_id, sender_ik, hlc_wall, hlc_logical, body_enc, received_ms, status,
                    edited_ms, forwarded, reply_to
               FROM messages
              WHERE chat_id = ?1
                AND tombstone_ms IS NULL
                AND (?2 IS NULL OR (hlc_wall, hlc_logical) < (?2, ?3))
              ORDER BY hlc_wall DESC, hlc_logical DESC, msg_id DESC
              LIMIT ?4",
        )?;

        let rows = statement.query_map(
            rusqlite::params![
                &chat_id[..],
                before.map(|b| sql_types::to_sql(b.wall_ms)),
                before.map_or(0, |b| sql_types::to_sql(u64::from(b.logical))),
                sql_types::to_sql(limit as u64),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    sql_types::from_sql(row.get(2)?),
                    sql_types::from_sql(row.get(3)?),
                    row.get::<_, Vec<u8>>(4)?,
                    sql_types::from_sql(row.get(5)?),
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, i64>(8)? != 0,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                ))
            },
        )?;

        let mut window = Vec::new();
        for row in rows {
            let (
                msg_id,
                sender_ik,
                wall_ms,
                logical,
                body_enc,
                received_ms,
                status,
                edited,
                fwd,
                reply_to,
            ) = row?;
            let msg_id: MsgId =
                msg_id.try_into().map_err(|_| StoreError::Backend("msg_id не 16 байт".into()))?;
            let sender_ik: [u8; 32] = sender_ik
                .try_into()
                .map_err(|_| StoreError::Backend("sender_ik не 32 байта".into()))?;
            // Значение вне u32 означает порчу файла, а не старую версию:
            // писали мы сами и только через `to_sql`.
            let logical = u32::try_from(logical)
                .map_err(|_| StoreError::Backend("логическая компонента HLC вне u32".into()))?;
            let hlc = Hlc::new(wall_ms, logical);
            let body = self.open_sealed("messages.body_enc", &msg_id, &body_enc)?;
            window.push(StoredMessage {
                msg_id,
                chat_id: *chat_id,
                sender_ik,
                hlc,
                body,
                received_ms,
                // Код вне диапазона `u8` означает порчу: писали мы сами.
                status: status.and_then(|code| u8::try_from(code).ok()),
                edited_ms: edited.map(sql_types::from_sql),
                forwarded: fwd,
                // Ссылка мягкая: сообщения с таким `msg_id` может уже не быть.
                // Порченую длину трактуем как её отсутствие — цитировать
                // нечего, а ронять чат из-за этого незачем.
                reply_to: reply_to.and_then(|raw| MsgId::try_from(raw.as_slice()).ok()),
            });
        }

        // Наружу — по возрастанию: так же, как отдаёт `MemoryStore`, и так же,
        // как читает чат человек.
        window.reverse();
        Ok(window)
    }

    fn status(&self, msg_id: &MsgId) -> Result<Option<u8>> {
        let found = self
            .conn
            .query_row("SELECT status FROM messages WHERE msg_id = ?1", [&msg_id[..]], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        // Код вне диапазона `u8` означает порчу: писали мы сами.
        Ok(found.flatten().and_then(|code| u8::try_from(code).ok()))
    }

    fn set_status(&mut self, msg_id: &MsgId, status: u8) -> Result<bool> {
        // Условия в SQL нет: допустимость перехода решена уровнем выше
        // (`receipts::advance`), а дублировать это правило здесь значит
        // однажды дать ему разойтись. Возвращается только факт «строка
        // нашлась»: по очереди §5.4 ездят и отзывы, которых в истории нет.
        let affected = self.conn.execute(
            "UPDATE messages SET status = ?2 WHERE msg_id = ?1 AND tombstone_ms IS NULL",
            rusqlite::params![&msg_id[..], i64::from(status)],
        )?;
        Ok(affected > 0)
    }

    fn message(&self, msg_id: &MsgId) -> Result<Option<StoredMessage>> {
        let found = self
            .conn
            .query_row(
                "SELECT chat_id, sender_ik, hlc_wall, hlc_logical, body_enc, received_ms,
                        status, edited_ms, forwarded, reply_to
                   FROM messages WHERE msg_id = ?1 AND tombstone_ms IS NULL",
                [&msg_id[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        sql_types::from_sql(row.get(2)?),
                        sql_types::from_sql(row.get(3)?),
                        row.get::<_, Vec<u8>>(4)?,
                        sql_types::from_sql(row.get(5)?),
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, i64>(8)? != 0,
                        row.get::<_, Option<Vec<u8>>>(9)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((
            chat_id,
            sender_ik,
            wall,
            logical,
            body_enc,
            received_ms,
            status,
            edited,
            fwd,
            reply_to,
        )) = found
        else {
            return Ok(None);
        };
        let body = self.open_sealed("messages.body_enc", msg_id, &body_enc)?;
        Ok(Some(StoredMessage {
            msg_id: *msg_id,
            chat_id: chat_id
                .try_into()
                .map_err(|_| StoreError::Backend("chat_id не 16 байт".into()))?,
            sender_ik: sender_ik
                .try_into()
                .map_err(|_| StoreError::Backend("sender_ik не 32 байта".into()))?,
            hlc: Hlc::new(wall, u32::try_from(logical).unwrap_or(u32::MAX)),
            body,
            received_ms,
            status: status.and_then(|code| u8::try_from(code).ok()),
            edited_ms: edited.map(sql_types::from_sql),
            forwarded: fwd,
            reply_to: reply_to.and_then(|raw| MsgId::try_from(raw.as_slice()).ok()),
        }))
    }

    fn tombstone_message(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        // Тело стирается прямо здесь, а не оставляется до уборки (§12):
        // надгробие хранит идентификатор, чтобы копия, пришедшая позже
        // другим транспортом (§9.2), не воскресила удалённое, — но текст
        // для этого не нужен, а держать его девяносто суток после «удалить»
        // значит не удалить.
        //
        // Отметка о правке уходит вместе с текстом: «изменено» у сообщения,
        // которого больше нет, — сведение ни о чём. Реакции — тоже: они
        // относились к словам, которых не осталось.
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "UPDATE messages
                SET tombstone_ms = ?2, body_enc = x'', status = NULL, edited_ms = NULL
              WHERE msg_id = ?1 AND tombstone_ms IS NULL",
            rusqlite::params![&msg_id[..], sql_types::to_sql(now_ms)],
        )?;
        if affected > 0 {
            tx.execute("DELETE FROM reactions WHERE msg_id = ?1", [&msg_id[..]])?;
            // Присланная карточка — тоже содержимое сообщения, и уходит
            // вместе с ним. Оставить её значит оставить в истории кнопку
            // «добавить контакт» у сообщения, которого больше нет.
            tx.execute("DELETE FROM contact_shares WHERE msg_id = ?1", [&msg_id[..]])?;
            // И поисковый индекс: стереть текст, оставив возможность найти
            // по нему сообщение, значит не стереть текст.
            Self::forget_words(&tx, msg_id)?;
        }
        tx.commit()?;
        Ok(affected > 0)
    }

    fn tombstone_chat(&mut self, chat_id: &[u8; 16], now_ms: u64) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "UPDATE messages
                SET tombstone_ms = ?2, body_enc = x'', status = NULL, edited_ms = NULL
              WHERE chat_id = ?1 AND tombstone_ms IS NULL",
            rusqlite::params![&chat_id[..], sql_types::to_sql(now_ms)],
        )?;
        tx.execute(
            "DELETE FROM reactions
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.execute(
            "DELETE FROM message_tokens
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.execute(
            "DELETE FROM contact_shares
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.commit()?;
        Ok(affected as u64)
    }

    fn edit_message(&mut self, msg_id: &MsgId, body: &[u8], edited_ms: u64) -> Result<bool> {
        // Тот же AAD, что и при записи: правка меняет содержимое строки,
        // а не её место.
        let body_enc = self.seal("messages.body_enc", msg_id, body)?;
        // Надгробие сильнее правки: сообщение, которое человек удалил,
        // не должно вернуться в чат из-за того, что автор его переписал.
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "UPDATE messages
                SET body_enc = ?2, edited_ms = ?3
              WHERE msg_id = ?1 AND tombstone_ms IS NULL",
            rusqlite::params![&msg_id[..], body_enc, sql_types::to_sql(edited_ms)],
        )?;
        // Индекс переписывается только если переписалось тело. Правка
        // надгробия не проходит — и его пустой индекс трогать не за что.
        if affected > 0 {
            Self::index_words(&tx, &self.db_key, msg_id, body)?;
        }
        tx.commit()?;
        Ok(affected > 0)
    }

    fn put_reaction(&mut self, reaction: &StoredReaction) -> Result<()> {
        // Реакция — содержимое, значит шифруется. AAD берёт и сообщение,
        // и автора: иначе строку можно переставить между авторами.
        let row_key = Self::reaction_row_key(&reaction.msg_id, &reaction.author_ik);
        let emoji_enc = self.seal("reactions.emoji_enc", &row_key, reaction.emoji.as_bytes())?;
        self.conn.execute(
            "INSERT OR REPLACE INTO reactions (msg_id, author_ik, emoji_enc, hlc_wall, hlc_logical)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                &reaction.msg_id[..],
                &reaction.author_ik[..],
                emoji_enc,
                sql_types::to_sql(reaction.hlc.wall_ms),
                sql_types::to_sql(u64::from(reaction.hlc.logical)),
            ],
        )?;
        Ok(())
    }

    fn reaction(&self, msg_id: &MsgId, author_ik: &[u8; 32]) -> Result<Option<StoredReaction>> {
        let found = self
            .conn
            .query_row(
                "SELECT emoji_enc, hlc_wall, hlc_logical
                   FROM reactions WHERE msg_id = ?1 AND author_ik = ?2",
                rusqlite::params![&msg_id[..], &author_ik[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        sql_types::from_sql(row.get(1)?),
                        sql_types::from_sql(row.get(2)?),
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((emoji_enc, wall, logical)) = found else { return Ok(None) };
        let row_key = Self::reaction_row_key(msg_id, author_ik);
        let bytes = self.open_sealed("reactions.emoji_enc", &row_key, &emoji_enc)?;
        let emoji =
            String::from_utf8(bytes).map_err(|_| StoreError::Backend("реакция не UTF-8".into()))?;
        Ok(Some(StoredReaction {
            msg_id: *msg_id,
            author_ik: *author_ik,
            emoji,
            hlc: Hlc::new(wall, u32::try_from(logical).unwrap_or(u32::MAX)),
        }))
    }

    fn reactions(&self, msg_id: &MsgId) -> Result<Vec<StoredReaction>> {
        let mut statement = self.conn.prepare(
            "SELECT author_ik, emoji_enc, hlc_wall, hlc_logical
               FROM reactions WHERE msg_id = ?1 ORDER BY author_ik",
        )?;
        let rows = statement.query_map([&msg_id[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                sql_types::from_sql(row.get(2)?),
                sql_types::from_sql(row.get(3)?),
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (author_ik, emoji_enc, wall, logical): (Vec<u8>, Vec<u8>, u64, u64) = row?;
            let author_ik: [u8; 32] = author_ik
                .try_into()
                .map_err(|_| StoreError::Backend("author_ik не 32 байта".into()))?;
            let row_key = Self::reaction_row_key(msg_id, &author_ik);
            let bytes = self.open_sealed("reactions.emoji_enc", &row_key, &emoji_enc)?;
            // Испорченная строка — не повод отказать в чтении чата: реакцию,
            // которую нечем показать, честнее пропустить. Снятая — тоже
            // не показывается: пустая строка здесь означает «реакции нет»,
            // а строка в базе существует только ради метки (см. `put_reaction`).
            let Ok(emoji) = String::from_utf8(bytes) else { continue };
            if emoji.is_empty() {
                continue;
            }
            found.push(StoredReaction {
                msg_id: *msg_id,
                author_ik,
                emoji,
                hlc: Hlc::new(wall, u32::try_from(logical).unwrap_or(u32::MAX)),
            });
        }
        Ok(found)
    }
    fn put_paired_device(&mut self, device: &StoredPairedDevice) -> Result<()> {
        // AAD привязывает ключ к строке: переставленный прямым доступом
        // к файлу он не откроется, и чужое устройство не станет своим.
        let sealed =
            self.seal("paired_devices.pairing_key_enc", &device.device_id, &device.pairing_public)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO paired_devices
             (device_id, label, pairing_key_enc, paired_ms, last_seen_ms, onion, ygg)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &device.device_id[..],
                &device.label,
                sealed,
                sql_types::to_sql(device.paired_ms),
                sql_types::to_sql(device.last_seen_ms),
                &device.onion,
                &device.ygg,
            ],
        )?;
        Ok(())
    }

    fn paired_devices(&self) -> Result<Vec<StoredPairedDevice>> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, label, pairing_key_enc, paired_ms, last_seen_ms, onion, ygg
             FROM paired_devices ORDER BY paired_ms",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?;

        let mut devices = Vec::new();
        for row in rows {
            let (id, label, sealed, paired_ms, last_seen_ms, onion, ygg) = row?;
            let device_id: [u8; 16] = id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("идентификатор устройства не 16 байт".into()))?;
            let opened = self.open_sealed("paired_devices.pairing_key_enc", &device_id, &sealed)?;
            let pairing_public: [u8; 32] = opened
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("ключ сопряжения не 32 байта".into()))?;
            devices.push(StoredPairedDevice {
                device_id,
                label,
                pairing_public,
                paired_ms: sql_types::from_sql(paired_ms),
                last_seen_ms: sql_types::from_sql(last_seen_ms),
                onion,
                ygg,
            });
        }
        Ok(devices)
    }

    fn delete_paired_device(&mut self, device_id: &[u8; 16]) -> Result<()> {
        self.conn.execute("DELETE FROM paired_devices WHERE device_id = ?1", [&device_id[..]])?;
        Ok(())
    }

    fn set_device_onion(&mut self, device_id: &[u8; 16], onion: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE paired_devices SET onion = ?2 WHERE device_id = ?1",
            rusqlite::params![&device_id[..], onion],
        )?;
        Ok(())
    }

    fn set_device_ygg(&mut self, device_id: &[u8; 16], ygg: &[u8]) -> Result<()> {
        self.conn.execute(
            "UPDATE paired_devices SET ygg = ?2 WHERE device_id = ?1",
            rusqlite::params![&device_id[..], ygg],
        )?;
        Ok(())
    }

    fn put_group(&mut self, group: &StoredGroup) -> Result<()> {
        let sealed = self.seal("chats.title_enc", &group.chat_id, group.title.as_bytes())?;
        self.conn.execute(
            // `kind = 1` ставится и при обновлении: строку чата мог завести
            // приход сообщения (`kind = 0`, владелец пуст), и группа тогда
            // приходит в уже существующую строку.
            //
            // Владелец — `coalesce`: пустое место заполняется, занятое
            // не трогается. Первое нужно ровно для того случая выше, второе
            // — правило §11.2: владелец у группы один и на всю жизнь.
            //
            // `created_ms` не обновляется по той же причине: если строка
            // завелась сообщением, чат для этого устройства начался тогда,
            // а не в тот момент, когда до него добралось сведение о группе.
            //
            // Название и его метка обновляются **вместе и только вперёд**:
            // условие сравнивает пару «часы, счётчик» с той, что уже лежит.
            // Два переименования одного человека законно приходят в обратном
            // порядке (§9.2), и без этого условия старое затёрло бы новое.
            // Сравнение стоит в SQL, а не в ядре, ровно затем, чтобы «читать
            // и писать» не разъезжались между чтением и записью.
            "INSERT INTO chats (chat_id, kind, owner_ik, title_enc, created_ms,
                                title_wall, title_logical)
             VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(chat_id) DO UPDATE SET
               kind = 1,
               owner_ik = coalesce(chats.owner_ik, excluded.owner_ik),
               title_enc = CASE
                 WHEN (excluded.title_wall, excluded.title_logical)
                      >= (chats.title_wall, chats.title_logical)
                 THEN excluded.title_enc ELSE chats.title_enc END,
               title_wall = max(chats.title_wall, excluded.title_wall),
               title_logical = CASE
                 WHEN excluded.title_wall > chats.title_wall THEN excluded.title_logical
                 WHEN excluded.title_wall = chats.title_wall
                      THEN max(chats.title_logical, excluded.title_logical)
                 ELSE chats.title_logical END",
            rusqlite::params![
                &group.chat_id[..],
                &group.owner_ik[..],
                sealed,
                sql_types::to_sql(group.created_ms),
                sql_types::to_sql(group.title_wall),
                sql_types::to_sql(u64::from(group.title_logical))
            ],
        )?;
        Ok(())
    }

    fn group(&self, chat_id: &[u8; 16]) -> Result<Option<StoredGroup>> {
        let found = self
            .conn
            .query_row(
                "SELECT owner_ik, title_enc, created_ms, title_wall, title_logical FROM chats
                  WHERE chat_id = ?1 AND kind = 1 AND owner_ik IS NOT NULL",
                [&chat_id[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((owner, sealed, created_ms, wall, logical)) = found else { return Ok(None) };
        Ok(Some(self.group_row(*chat_id, &owner, &sealed, created_ms, wall, logical)?))
    }

    fn groups(&self) -> Result<Vec<StoredGroup>> {
        let mut stmt = self.conn.prepare(
            // Порядок — по времени заведения, затем по идентификатору:
            // §16 требует воспроизводимости, а она держится на том, что
            // порядок чтения задан целиком, без опоры на порядок вставки.
            "SELECT chat_id, owner_ik, title_enc, created_ms, title_wall, title_logical
               FROM chats
              WHERE kind = 1 AND owner_ik IS NOT NULL
              ORDER BY created_ms, chat_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;

        let mut groups = Vec::new();
        for row in rows {
            let (id, owner, sealed, created_ms, wall, logical) = row?;
            let chat_id: [u8; 16] = id
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("идентификатор чата не 16 байт".into()))?;
            groups.push(self.group_row(chat_id, &owner, &sealed, created_ms, wall, logical)?);
        }
        Ok(groups)
    }

    fn put_membership(&mut self, chat_id: &[u8; 16], ops: &[StoredMembershipOp]) -> Result<()> {
        // Одной транзакцией: пачка операций приходит одним блоком состава
        // (§11.2), и половина пачки на диске — это состав, которого никто
        // не объявлял.
        let tx = self.conn.transaction()?;
        for op in ops {
            tx.execute(
                // Ключ строки — вся метка целиком, и повтор той же операции
                // безвреден. `max` на надгробии делает погашение
                // односторонним: удаление, дошедшее раньше добавления
                // (а в OR-Set это обычное дело), не отменяется тем, что
                // добавление доехало вторым.
                "INSERT INTO group_members
                   (chat_id, member_ik, tag_wall, tag_logical, tag_actor, tag_uniq, removed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(chat_id, member_ik, tag_wall, tag_logical, tag_actor, tag_uniq)
                 DO UPDATE SET removed = max(group_members.removed, excluded.removed)",
                rusqlite::params![
                    &chat_id[..],
                    &op.member_ik[..],
                    sql_types::to_sql(op.tag_wall),
                    i64::from(op.tag_logical),
                    &op.tag_actor[..],
                    &op.tag_uniq[..],
                    i64::from(op.removed)
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn membership(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredMembershipOp>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_ik, tag_wall, tag_logical, tag_actor, tag_uniq, removed
               FROM group_members WHERE chat_id = ?1
              ORDER BY tag_wall, tag_logical, tag_actor, tag_uniq, member_ik",
        )?;
        let rows = stmt.query_map([&chat_id[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;

        let mut ops = Vec::new();
        for row in rows {
            let (member, tag_wall, tag_logical, actor, uniq, removed) = row?;
            ops.push(StoredMembershipOp {
                member_ik: member
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Backend("ключ участника не 32 байта".into()))?,
                tag_wall: sql_types::from_sql(tag_wall),
                tag_logical: u32::try_from(tag_logical).unwrap_or(0),
                tag_actor: actor
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Backend("ключ автора метки не 32 байта".into()))?,
                tag_uniq: uniq
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Backend("разводящие байты не 8 байт".into()))?,
                removed: removed != 0,
            });
        }
        Ok(ops)
    }

    fn put_membership_block(
        &mut self,
        chat_id: &[u8; 16],
        block: &StoredMembershipBlock,
    ) -> Result<()> {
        self.conn.execute(
            // `DO NOTHING`, а не `DO UPDATE`: тот же блок законно приходит
            // вторым транспортом (§9.2). Перезапись означала бы, что байты,
            // над которыми стоит подпись, можно подменить, назвав прежний
            // идентификатор, — а идентификатор и есть их хэш.
            "INSERT INTO group_blocks (chat_id, block_id, author_ik, block_bytes, received_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(chat_id, block_id) DO NOTHING",
            rusqlite::params![
                &chat_id[..],
                &block.block_id[..],
                &block.author_ik[..],
                &block.bytes[..],
                sql_types::to_sql(block.received_ms)
            ],
        )?;
        Ok(())
    }

    fn membership_blocks(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredMembershipBlock>> {
        let mut stmt = self.conn.prepare(
            // Порядок приёма, затем идентификатор: он задан целиком,
            // без опоры на порядок вставки, — по той же причине, что
            // у состава (§16).
            "SELECT block_id, author_ik, block_bytes, received_ms FROM group_blocks
              WHERE chat_id = ?1 ORDER BY received_ms, block_id",
        )?;
        let rows = stmt.query_map([&chat_id[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;

        let mut blocks = Vec::new();
        for row in rows {
            let (id, author, bytes, received_ms) = row?;
            blocks.push(StoredMembershipBlock {
                block_id: id
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Backend("идентификатор блока не 16 байт".into()))?,
                author_ik: author
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Backend("ключ автора не 32 байта".into()))?,
                bytes,
                received_ms: sql_types::from_sql(received_ms),
            });
        }
        Ok(blocks)
    }

    fn put_sender_chain(&mut self, chat_id: &[u8; 16], chain: &StoredSenderChain) -> Result<()> {
        let row_key = Self::chain_row_key(chat_id, &chain.member_ik);
        let sealed = self.seal("sender_chains.chain_enc", &row_key, &chain.chain)?;
        // Пусто — значит NULL, а не пустой блоб: «пропусков нет» и «пропуски
        // записаны как ноль байт» это одно и то же, и хранить для этого
        // отдельное значение незачем.
        let skipped = if chain.skipped.is_empty() {
            None
        } else {
            Some(self.seal("sender_chains.skipped_enc", &row_key, &chain.skipped)?)
        };
        self.conn.execute(
            // Ключ, номер, метка поворота и кэш обновляются одним оператором
            // и порознь никогда не пишутся: разойдись ключ с номером —
            // сообщение расшифруется, а место в цепочке окажется не то;
            // переживи кэш смену ключа — он открывал бы номера от цепочки,
            // которой больше нет; отстань метка от ключа — получатель
            // принял бы опоздавшее объявление за свежее.
            //
            // Старшинство здесь не сравнивается, и это не забывчивость:
            // тем же оператором пишется продвижение цепочки вперёд, у
            // которого метка та же самая. Кто кого обгоняет, знает ядро
            // (`Engine::on_sender_key`) — только оно отличает объявление
            // новой цепочки от очередного шага по старой.
            "INSERT INTO sender_chains (chat_id, member_ik, chain_enc, counter,
                                        chain_wall, chain_logical, skipped_enc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(chat_id, member_ik) DO UPDATE SET
               chain_enc = excluded.chain_enc,
               counter = excluded.counter,
               chain_wall = excluded.chain_wall,
               chain_logical = excluded.chain_logical,
               skipped_enc = excluded.skipped_enc",
            rusqlite::params![
                &chat_id[..],
                &chain.member_ik[..],
                sealed,
                sql_types::to_sql(chain.counter),
                sql_types::to_sql(chain.chain_wall),
                sql_types::to_sql(chain.chain_logical.into()),
                skipped
            ],
        )?;
        Ok(())
    }

    fn sender_chain(
        &self,
        chat_id: &[u8; 16],
        member_ik: &[u8; 32],
    ) -> Result<Option<StoredSenderChain>> {
        let found = self
            .conn
            .query_row(
                "SELECT chain_enc, counter, chain_wall, chain_logical, skipped_enc
                   FROM sender_chains
                  WHERE chat_id = ?1 AND member_ik = ?2",
                rusqlite::params![&chat_id[..], &member_ik[..]],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((sealed, counter, wall, logical, skipped)) = found else { return Ok(None) };
        Ok(Some(self.chain_row(
            chat_id,
            *member_ik,
            &sealed,
            counter,
            (wall, logical),
            skipped.as_deref(),
        )?))
    }

    fn sender_chains(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredSenderChain>> {
        let mut stmt = self.conn.prepare(
            "SELECT member_ik, chain_enc, counter, chain_wall, chain_logical, skipped_enc
               FROM sender_chains
              WHERE chat_id = ?1 ORDER BY member_ik",
        )?;
        let rows = stmt.query_map([&chat_id[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })?;

        let mut chains = Vec::new();
        for row in rows {
            let (member, sealed, counter, wall, logical, skipped) = row?;
            let member_ik: [u8; 32] = member
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Backend("ключ участника не 32 байта".into()))?;
            chains.push(self.chain_row(
                chat_id,
                member_ik,
                &sealed,
                counter,
                (wall, logical),
                skipped.as_deref(),
            )?);
        }
        Ok(chains)
    }

    fn remember_revocation(&mut self, pairing_public: &[u8; 32], revoked_ms: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO revoked_devices (pairing_public, revoked_ms) VALUES (?1, ?2)
             ON CONFLICT(pairing_public) DO UPDATE SET revoked_ms = excluded.revoked_ms",
            rusqlite::params![&pairing_public[..], sql_types::to_sql(revoked_ms)],
        )?;
        Ok(())
    }

    fn revocation(&self, pairing_public: &[u8; 32]) -> Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT revoked_ms FROM revoked_devices WHERE pairing_public = ?1",
                [&pairing_public[..]],
                |row| row.get::<_, i64>(0),
            )
            .map(|ms| Some(u64::try_from(ms).unwrap_or(0)))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })
    }

    fn prune_revocations(&mut self, before_ms: u64) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM revoked_devices WHERE revoked_ms < ?1",
            [sql_types::to_sql(before_ms)],
        )?)
    }

    fn touch_paired_device(&mut self, device_id: &[u8; 16], now_ms: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE paired_devices SET last_seen_ms = ?2 WHERE device_id = ?1",
            rusqlite::params![&device_id[..], sql_types::to_sql(now_ms)],
        )?;
        Ok(())
    }

    fn put_avatar(&mut self, owner_ik: &[u8; 32], avatar: &StoredAvatar) -> Result<()> {
        // AAD привязывает шифротекст к строке: аватарка, переставленная
        // из одной строки в другую прямым доступом к файлу, не откроется.
        let sealed = self.seal("avatars.avatar_enc", owner_ik, &avatar.bytes)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO avatars (owner_ik, avatar_enc, updated_ms)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![&owner_ik[..], sealed, sql_types::to_sql(avatar.updated_ms)],
        )?;
        Ok(())
    }

    fn avatar(&self, owner_ik: &[u8; 32]) -> Result<Option<StoredAvatar>> {
        let found = self
            .conn
            .query_row(
                "SELECT avatar_enc, updated_ms FROM avatars WHERE owner_ik = ?1",
                [&owner_ik[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((sealed, updated_ms)) = found else { return Ok(None) };
        let bytes = self.open_sealed("avatars.avatar_enc", owner_ik, &sealed)?;
        Ok(Some(StoredAvatar { bytes, updated_ms: sql_types::from_sql(updated_ms) }))
    }

    fn has_avatar(&self, owner_ik: &[u8; 32]) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row("SELECT 1 FROM avatars WHERE owner_ik = ?1", [&owner_ik[..]], |row| {
                row.get(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        Ok(found.is_some())
    }

    fn avatar_stamp(&self, owner_ik: &[u8; 32]) -> Result<Option<u64>> {
        self.conn
            .query_row(
                "SELECT updated_ms FROM avatars WHERE owner_ik = ?1",
                [&owner_ik[..]],
                |row| row.get::<_, i64>(0),
            )
            // Столбец объявлен INTEGER, и SQLite это знаковое число: строка,
            // записанная сборкой с другими часами, вправе оказаться
            // отрицательной. Ноль здесь честнее отрицательной метки —
            // он значит «показывать нечего», а метка «до эпохи» разошлась бы
            // со сравнением на десктопе неизвестно как.
            .map(|ms| Some(u64::try_from(ms).unwrap_or(0)))
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })
    }

    fn delete_avatar(&mut self, owner_ik: &[u8; 32]) -> Result<()> {
        self.conn.execute("DELETE FROM avatars WHERE owner_ik = ?1", [&owner_ik[..]])?;
        Ok(())
    }

    fn put_group_avatar(&mut self, chat_id: &[u8; 16], avatar: &StoredGroupAvatar) -> Result<()> {
        // Пустые байты кладутся **пустым блобом**, а не шифротекстом
        // из нонса и тега: снятая картинка обязана быть отличима от лежащей
        // по одной длине столбца — иначе «есть ли что показывать»
        // не ответить, не расшифровав тридцать два килобайта.
        //
        // Утечки здесь нет сверх той, что уже есть: строка существует —
        // значит картинку когда-то ставили, и это того же рода сведение,
        // что и `kind = 1` рядом.
        //
        // AAD привязывает шифротекст к строке — как у лица контакта:
        // картинка, переставленная из одной группы в другую прямым доступом
        // к файлу, не откроется.
        let sealed = if avatar.bytes.is_empty() {
            Vec::new()
        } else {
            self.seal("group_avatars.avatar_enc", chat_id, &avatar.bytes)?
        };
        self.conn.execute(
            // Слово в слово то же сравнение, что у названия группы в `chats`,
            // и по той же причине: две смены картинки законно приходят
            // в обратном порядке (§9.2), а решать между ними должна метка,
            // а не порядок прихода. Байты и метка обновляются вместе —
            // разъедься они, у группы оказалась бы новая метка при старой
            // картинке, и настоящая новая была бы отвергнута навсегда.
            "INSERT INTO group_avatars (chat_id, avatar_enc, avatar_wall, avatar_logical)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(chat_id) DO UPDATE SET
               avatar_enc = CASE
                 WHEN (excluded.avatar_wall, excluded.avatar_logical)
                      >= (group_avatars.avatar_wall, group_avatars.avatar_logical)
                 THEN excluded.avatar_enc ELSE group_avatars.avatar_enc END,
               avatar_wall = max(group_avatars.avatar_wall, excluded.avatar_wall),
               avatar_logical = CASE
                 WHEN excluded.avatar_wall > group_avatars.avatar_wall
                      THEN excluded.avatar_logical
                 WHEN excluded.avatar_wall = group_avatars.avatar_wall
                      THEN max(group_avatars.avatar_logical, excluded.avatar_logical)
                 ELSE group_avatars.avatar_logical END",
            rusqlite::params![
                &chat_id[..],
                sealed,
                sql_types::to_sql(avatar.avatar_wall),
                sql_types::to_sql(u64::from(avatar.avatar_logical))
            ],
        )?;
        Ok(())
    }

    fn group_avatar(&self, chat_id: &[u8; 16]) -> Result<Option<StoredGroupAvatar>> {
        let found = self
            .conn
            .query_row(
                "SELECT avatar_enc, avatar_wall, avatar_logical
                 FROM group_avatars WHERE chat_id = ?1",
                [&chat_id[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;

        let Some((sealed, wall, logical)) = found else { return Ok(None) };
        // Пустой блоб — снятая картинка; расшифровывать в нём нечего.
        let bytes = if sealed.is_empty() {
            Vec::new()
        } else {
            self.open_sealed("group_avatars.avatar_enc", chat_id, &sealed)?
        };
        Ok(Some(StoredGroupAvatar {
            bytes,
            avatar_wall: sql_types::from_sql(wall),
            avatar_logical: u32::try_from(sql_types::from_sql(logical)).unwrap_or(u32::MAX),
        }))
    }

    fn has_group_avatar(&self, chat_id: &[u8; 16]) -> Result<bool> {
        // Длина столбца, а не расшифровка: пустой блоб означает снятую
        // картинку, и это единственное, что нужно знать списку чатов.
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT length(avatar_enc) FROM group_avatars WHERE chat_id = ?1",
                [&chat_id[..]],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        Ok(found.is_some_and(|len| len > 0))
    }

    fn group_avatar_stamp(&self, chat_id: &[u8; 16]) -> Result<Option<(u64, u32)>> {
        self.conn
            .query_row(
                "SELECT avatar_wall, avatar_logical FROM group_avatars WHERE chat_id = ?1",
                [&chat_id[..]],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map(|(wall, logical)| {
                Some((
                    sql_types::from_sql(wall),
                    u32::try_from(sql_types::from_sql(logical)).unwrap_or(u32::MAX),
                ))
            })
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })
    }

    fn replace_pending_group(&mut self, frames: &[StoredPendingGroup]) -> Result<()> {
        // Шифруется **до** сделки: `seal` берёт `&self`, а сделка занимает
        // соединение исключительно, и внутри неё до ключа уже не дотянуться.
        // Привязка шифра — к номеру сообщения, как у очереди отправки:
        // это единственное, что у строки есть своего и неизменного.
        let mut sealed = Vec::with_capacity(frames.len());
        for frame in frames {
            sealed.push(self.seal("pending_group.envelope_enc", &frame.msg_id, &frame.envelope)?);
        }

        // Одной сделкой: очередь, переписанная наполовину, — это потерянные
        // кадры, а падение между двумя запросами вещь обычная.
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM pending_group", [])?;
        for (frame, envelope_enc) in frames.iter().zip(sealed) {
            tx.execute(
                "INSERT INTO pending_group (place, chat_id, peer_ik, msg_id, envelope_enc)
                      VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    i64::from(frame.place),
                    &frame.chat_id[..],
                    &frame.peer_ik[..],
                    &frame.msg_id[..],
                    envelope_enc,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn pending_group(&self) -> Result<Vec<StoredPendingGroup>> {
        let mut statement = self.conn.prepare(
            "SELECT place, chat_id, peer_ik, msg_id, envelope_enc
               FROM pending_group ORDER BY place",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut found = Vec::new();
        for row in rows {
            let (place, chat_id, peer_ik, msg_id, envelope_enc) = row?;
            let chat_id: [u8; 16] =
                chat_id.try_into().map_err(|_| StoreError::Backend("chat_id не 16 байт".into()))?;
            let peer_ik: [u8; 32] = peer_ik
                .try_into()
                .map_err(|_| StoreError::Backend("peer_ik не 32 байта".into()))?;
            let msg_id: MsgId =
                msg_id.try_into().map_err(|_| StoreError::Backend("msg_id не 16 байт".into()))?;
            let envelope =
                self.open_sealed("pending_group.envelope_enc", &msg_id, &envelope_enc)?;
            found.push(StoredPendingGroup {
                place: u32::try_from(place).unwrap_or(u32::MAX),
                chat_id,
                peer_ik,
                msg_id,
                envelope,
            });
        }
        Ok(found)
    }

    fn put_outbox(&mut self, entry: &StoredOutbox) -> Result<()> {
        // Конверт незапечатан, то есть содержит текст: шифруется как тело
        // сообщения и привязывается к своей строке.
        let envelope_enc = self.seal("outbox.envelope_enc", &entry.msg_id, &entry.envelope)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO outbox (msg_id, recipient_ik, envelope_enc, queued_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                &entry.msg_id[..],
                &entry.recipient_ik[..],
                envelope_enc,
                sql_types::to_sql(entry.queued_ms),
            ],
        )?;
        Ok(())
    }

    fn outbox(&self) -> Result<Vec<StoredOutbox>> {
        // Порядок — по моменту постановки: человек писал в каком-то порядке,
        // и отправлять надо в том же.
        let mut statement = self.conn.prepare(
            "SELECT msg_id, recipient_ik, envelope_enc, queued_ms
               FROM outbox ORDER BY queued_ms, msg_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                sql_types::from_sql(row.get(3)?),
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (msg_id, recipient_ik, envelope_enc, queued_ms) = row?;
            let msg_id: MsgId =
                msg_id.try_into().map_err(|_| StoreError::Backend("msg_id не 16 байт".into()))?;
            let envelope = self.open_sealed("outbox.envelope_enc", &msg_id, &envelope_enc)?;
            found.push(StoredOutbox {
                msg_id,
                recipient_ik: recipient_ik
                    .try_into()
                    .map_err(|_| StoreError::Backend("recipient_ik не 32 байта".into()))?,
                envelope,
                queued_ms,
            });
        }
        Ok(found)
    }

    fn delete_outbox(&mut self, msg_id: &MsgId, recipient_ik: &[u8; 32]) -> Result<()> {
        // По паре, а не по номеру: первичный ключ таблицы всегда был
        // `(msg_id, recipient_ik)`, а удаление ходило по одному номеру —
        // и дошедшая копия группового сообщения уносила из очереди копии
        // всех остальных участников.
        self.conn.execute(
            "DELETE FROM outbox WHERE msg_id = ?1 AND recipient_ik = ?2",
            rusqlite::params![&msg_id[..], &recipient_ik[..]],
        )?;
        Ok(())
    }

    fn delete_outbox_all(&mut self, msg_id: &MsgId) -> Result<()> {
        self.conn.execute("DELETE FROM outbox WHERE msg_id = ?1", [&msg_id[..]])?;
        Ok(())
    }

    fn put_file(&mut self, file: &StoredFile) -> Result<()> {
        // Имя, ключ и превью — содержимое (§12). Имя не меньше остального:
        // «результаты анализов.pdf» в открытом столбце рассказывает о переписке
        // ровно то, от чего шифруется тело сообщения.
        let name_enc = self.seal("files.name_enc", &file.file_id, file.name.as_bytes())?;
        let key_enc = self.seal("files.file_key_enc", &file.file_id, &file.key)?;
        let preview_enc = match &file.preview {
            Some(bytes) => Some(self.seal("files.preview_enc", &file.file_id, bytes)?),
            None => None,
        };
        // **`IGNORE`, а не `REPLACE`.** Тот же файл может приехать вторым
        // сообщением — так и выглядит пересланное вложение, — а у нас он
        // к тому времени уже собран. `REPLACE` затёр бы `complete`
        // и `source_path` тем, что пришло по проводу, то есть отобрал бы
        // у человека скачанный файл ради строки, которая ничего нового
        // не несёт. Содержимое у одного `file_id` одно; сверяет это
        // вызывающий (`Engine::record_offers`) — ему есть что сделать
        // с расхождением, а хранилищу нечего.
        self.conn.execute(
            "INSERT OR IGNORE INTO files (
                 file_id, name_enc, size_bytes, chunk_total, file_key_enc,
                 preview_enc, incoming, source_path, accepted, complete
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                &file.file_id[..],
                name_enc,
                sql_types::to_sql(file.size_bytes),
                sql_types::to_sql(file.chunk_total),
                key_enc,
                preview_enc,
                i64::from(file.incoming),
                file.source_path.as_deref(),
                i64::from(file.accepted),
                i64::from(file.complete),
            ],
        )?;
        self.attach_file(&file.msg_id, &file.file_id, file.ordinal)
    }

    fn file(&self, file_id: &FileId) -> Result<Option<StoredFile>> {
        // Сообщение здесь — **самое раннее** из тех, к которым файл приложен,
        // и берётся оно левым присоединением: запись обязана читаться и тогда,
        // когда связки не осталось вовсе (сообщение стёрли, а байты ещё нет).
        // Решать по нему что-либо про права нельзя — для этого
        // `messages_of_file`, и почему, написано у `StoredFile::msg_id`.
        let mut statement = self.conn.prepare(
            "SELECT files.file_id, COALESCE(link.msg_id, zeroblob(16)), name_enc, size_bytes,
                    chunk_total, file_key_enc, preview_enc, incoming, source_path, accepted,
                    complete, COALESCE(link.ordinal, 0)
               FROM files
               LEFT JOIN (
                    SELECT file_id, msg_id, ordinal FROM message_files
                     GROUP BY file_id
                     HAVING ordinal = MIN(ordinal)
               ) AS link ON link.file_id = files.file_id
              WHERE files.file_id = ?1",
        )?;
        let mut found = self.read_files(&mut statement, rusqlite::params![&file_id[..]])?;
        Ok(found.pop())
    }

    fn files_of(&self, msg_id: &MsgId) -> Result<Vec<StoredFile>> {
        let mut statement = self.conn.prepare(
            "SELECT files.file_id, message_files.msg_id, name_enc, size_bytes, chunk_total,
                    file_key_enc, preview_enc, incoming, source_path, accepted, complete,
                    message_files.ordinal
               FROM message_files
               JOIN files ON files.file_id = message_files.file_id
              WHERE message_files.msg_id = ?1
              ORDER BY message_files.ordinal, files.file_id",
        )?;
        self.read_files(&mut statement, rusqlite::params![&msg_id[..]])
    }

    fn messages_of_file(&self, file_id: &FileId) -> Result<Vec<MsgId>> {
        let mut statement = self
            .conn
            .prepare("SELECT msg_id FROM message_files WHERE file_id = ?1 ORDER BY msg_id")?;
        let rows = statement.query_map([&file_id[..]], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = Vec::new();
        for row in rows {
            let bytes = row?;
            // Длина не та — строка испорчена. Пропускаем: в худшем случае
            // недосчитаемся одного права, то есть откажем на законной
            // просьбе. Обратная ошибка — разрешить лишнему.
            let Ok(msg_id) = MsgId::try_from(bytes.as_slice()) else { continue };
            found.push(msg_id);
        }
        Ok(found)
    }

    fn orphan_file_ids(&self) -> Result<Vec<FileId>> {
        let mut statement = self.conn.prepare(
            "SELECT file_id FROM files
              WHERE file_id NOT IN (SELECT file_id FROM message_files)
              ORDER BY file_id",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = Vec::new();
        for row in rows {
            let bytes = row?;
            // Длина не та — строка испорчена. Пропускаем: в худшем случае
            // на диске останется лишнее. Обратная ошибка — стереть нужное.
            let Ok(file_id) = FileId::try_from(bytes.as_slice()) else { continue };
            found.push(file_id);
        }
        Ok(found)
    }

    fn attach_file(&mut self, msg_id: &MsgId, file_id: &FileId, ordinal: u32) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO message_files (msg_id, file_id, ordinal)
                  VALUES (?1, ?2, ?3)",
            rusqlite::params![&msg_id[..], &file_id[..], i64::from(ordinal)],
        )?;
        Ok(())
    }

    fn detach_files_of(&mut self, msg_id: &MsgId) -> Result<Vec<FileId>> {
        // Сперва — что было приложено, потом отвязка, потом пересчёт ссылок.
        // Порядок и есть смысл: спроси мы про сирот до отвязки, их бы не было
        // ни одной.
        let attached: Vec<FileId> =
            self.files_of(msg_id)?.into_iter().map(|file| file.file_id).collect();
        self.conn.execute("DELETE FROM message_files WHERE msg_id = ?1", [&msg_id[..]])?;

        let mut orphans = Vec::new();
        for file_id in attached {
            let left: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM message_files WHERE file_id = ?1",
                [&file_id[..]],
                |row| row.get(0),
            )?;
            if left == 0 {
                orphans.push(file_id);
            }
        }
        Ok(orphans)
    }

    fn put_contact_share(&mut self, share: &StoredContactShare) -> Result<()> {
        let card_enc = self.seal("contact_shares.card_enc", &share.msg_id, &share.card_bytes)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO contact_shares (msg_id, ik, card_enc) VALUES (?1, ?2, ?3)",
            rusqlite::params![&share.msg_id[..], &share.ik[..], card_enc],
        )?;
        Ok(())
    }

    fn contact_share_of(&self, msg_id: &MsgId) -> Result<Option<StoredContactShare>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT ik, card_enc FROM contact_shares WHERE msg_id = ?1",
                [&msg_id[..]],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        let Some((ik, card_enc)) = row else { return Ok(None) };

        let ik: [u8; 32] =
            ik.try_into().map_err(|_| StoreError::Backend("ik не 32 байта".into()))?;
        let card_bytes = self.open_sealed("contact_shares.card_enc", msg_id, &card_enc)?;
        Ok(Some(StoredContactShare { msg_id: *msg_id, ik, card_bytes }))
    }

    fn set_accepted(&mut self, file_id: &FileId, accepted: bool) -> Result<bool> {
        let affected = self.conn.execute(
            "UPDATE files SET accepted = ?2 WHERE file_id = ?1",
            rusqlite::params![&file_id[..], i64::from(accepted)],
        )?;
        Ok(affected > 0)
    }

    fn complete_file(&mut self, file_id: &FileId) -> Result<bool> {
        let affected = self
            .conn
            .execute("UPDATE files SET complete = 1 WHERE file_id = ?1", [&file_id[..]])?;
        Ok(affected > 0)
    }

    fn note_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO file_chunks (file_id, chunk_index) VALUES (?1, ?2)",
            rusqlite::params![&file_id[..], sql_types::to_sql(index)],
        )?;
        Ok(())
    }

    fn has_chunk(&self, file_id: &FileId, index: u64) -> Result<bool> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file_chunks WHERE file_id = ?1 AND chunk_index = ?2",
                rusqlite::params![&file_id[..], sql_types::to_sql(index)],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        Ok(found.is_some())
    }

    fn received_chunks(&self, file_id: &FileId) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM file_chunks WHERE file_id = ?1",
            [&file_id[..]],
            |row| row.get(0),
        )?;
        Ok(sql_types::from_sql(count))
    }

    fn put_staged(&mut self, staged: &StagedUpload) -> Result<()> {
        // Имя, ключ и превью — содержимое (§12), как и у обычного файла.
        let name_enc =
            self.seal("staged_files.name_enc", &staged.file_id, staged.name.as_bytes())?;
        let key_enc = self.seal("staged_files.file_key_enc", &staged.file_id, &staged.key)?;
        let preview_enc = match &staged.preview {
            Some(bytes) => Some(self.seal("staged_files.preview_enc", &staged.file_id, bytes)?),
            None => None,
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO staged_files (
                 file_id, chat_id, name_enc, size_bytes, chunk_total,
                 file_key_enc, preview_enc, started_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &staged.file_id[..],
                &staged.chat_id[..],
                name_enc,
                sql_types::to_sql(staged.size_bytes),
                sql_types::to_sql(staged.chunk_total),
                key_enc,
                preview_enc,
                sql_types::to_sql(staged.started_ms),
            ],
        )?;
        Ok(())
    }

    fn staged_uploads(&self) -> Result<Vec<StagedUpload>> {
        let mut statement = self.conn.prepare(
            "SELECT file_id, chat_id, name_enc, size_bytes, chunk_total,
                    file_key_enc, preview_enc, started_ms
               FROM staged_files ORDER BY started_ms, file_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                sql_types::from_sql(row.get(3)?),
                sql_types::from_sql(row.get(4)?),
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                sql_types::from_sql(row.get(7)?),
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (
                file_id,
                chat_id,
                name_enc,
                size_bytes,
                chunk_total,
                key_enc,
                preview_enc,
                started_ms,
            ) = row?;
            let file_id: FileId =
                file_id.try_into().map_err(|_| StoreError::Backend("file_id не 16 байт".into()))?;
            let name = String::from_utf8(self.open_sealed(
                "staged_files.name_enc",
                &file_id,
                &name_enc,
            )?)
            .map_err(|_| StoreError::Backend("имя файла не UTF-8".into()))?;
            let key: [u8; 32] = self
                .open_sealed("staged_files.file_key_enc", &file_id, &key_enc)?
                .try_into()
                .map_err(|_| StoreError::Backend("ключ файла не 32 байта".into()))?;
            let preview = match preview_enc {
                Some(sealed) => {
                    Some(self.open_sealed("staged_files.preview_enc", &file_id, &sealed)?)
                }
                None => None,
            };
            found.push(StagedUpload {
                file_id,
                chat_id: chat_id
                    .try_into()
                    .map_err(|_| StoreError::Backend("chat_id не 16 байт".into()))?,
                name,
                size_bytes,
                chunk_total,
                key,
                preview,
                started_ms,
            });
        }
        Ok(found)
    }

    fn note_staged_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO staged_chunks (file_id, chunk_index) VALUES (?1, ?2)",
            rusqlite::params![&file_id[..], sql_types::to_sql(index)],
        )?;
        Ok(())
    }

    fn staged_chunks(&self, file_id: &FileId) -> Result<Vec<u64>> {
        let mut statement = self.conn.prepare(
            "SELECT chunk_index FROM staged_chunks WHERE file_id = ?1 ORDER BY chunk_index",
        )?;
        let rows = statement.query_map([&file_id[..]], |row| row.get::<_, i64>(0))?;
        let mut found = Vec::new();
        for row in rows {
            found.push(sql_types::from_sql(row?));
        }
        Ok(found)
    }

    fn delete_staged(&mut self, file_id: &FileId) -> Result<()> {
        // Куски уходят каскадом: внешний ключ объявлен `ON DELETE CASCADE`,
        // и полагаться на него дешевле, чем помнить про второй запрос.
        self.conn.execute("DELETE FROM staged_files WHERE file_id = ?1", [&file_id[..]])?;
        Ok(())
    }

    fn staged_older_than(&self, cutoff_ms: u64) -> Result<Vec<FileId>> {
        let mut statement =
            self.conn.prepare("SELECT file_id FROM staged_files WHERE started_ms < ?1")?;
        let rows =
            statement.query_map([sql_types::to_sql(cutoff_ms)], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = Vec::new();
        for row in rows {
            found.push(
                row?.try_into().map_err(|_| StoreError::Backend("file_id не 16 байт".into()))?,
            );
        }
        Ok(found)
    }

    fn next_missing_chunk(&self, file_id: &FileId, chunk_total: u64) -> Result<Option<u64>> {
        // Индексы читаются по порядку и обходятся в Rust, а не считаются в SQL.
        // Арифметики в запросах здесь нет намеренно (см. `compact`), а для
        // двух тысяч строк разницы всё равно никакой.
        let mut statement = self.conn.prepare(
            "SELECT chunk_index FROM file_chunks WHERE file_id = ?1 ORDER BY chunk_index",
        )?;
        let rows = statement
            .query_map([&file_id[..]], |row| Ok(sql_types::from_sql(row.get::<_, i64>(0)?)))?;

        let mut expected = 0u64;
        for row in rows {
            let index: u64 = row?;
            if index != expected {
                return Ok(Some(expected));
            }
            expected += 1;
        }
        Ok((expected < chunk_total).then_some(expected))
    }

    fn unfinished_files(&self) -> Result<Vec<StoredFile>> {
        let mut statement = self.conn.prepare(
            "SELECT files.file_id, COALESCE(link.msg_id, zeroblob(16)), name_enc, size_bytes,
                    chunk_total, file_key_enc, preview_enc, incoming, source_path, accepted,
                    complete, COALESCE(link.ordinal, 0)
               FROM files
               LEFT JOIN (
                    SELECT file_id, msg_id, ordinal FROM message_files
                     GROUP BY file_id
                     HAVING ordinal = MIN(ordinal)
               ) AS link ON link.file_id = files.file_id
              WHERE complete = 0
              ORDER BY files.file_id",
        )?;
        self.read_files(&mut statement, rusqlite::params![])
    }

    fn file_ids_of_chat(&self, chat_id: &[u8; 16]) -> Result<Vec<FileId>> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT message_files.file_id FROM message_files
               JOIN messages ON messages.msg_id = message_files.msg_id
              WHERE messages.chat_id = ?1
              ORDER BY message_files.file_id",
        )?;
        let rows = statement.query_map([&chat_id[..]], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = Vec::new();
        for row in rows {
            let bytes = row?;
            let Ok(file_id) = FileId::try_from(bytes.as_slice()) else { continue };
            found.push(file_id);
        }
        Ok(found)
    }

    fn all_file_ids(&self) -> Result<Vec<FileId>> {
        let mut statement = self.conn.prepare("SELECT file_id FROM files ORDER BY file_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = Vec::new();
        for row in rows {
            let bytes = row?;
            // Длина не та — строка испорчена. Пропускаем: сверка от этого
            // недосчитается одного файла, то есть в худшем случае оставит
            // на диске лишнее. Обратная ошибка — стереть нужное.
            let Ok(file_id) = FileId::try_from(bytes.as_slice()) else { continue };
            found.push(file_id);
        }
        Ok(found)
    }

    fn delete_file(&mut self, file_id: &FileId) -> Result<()> {
        // Чанки уйдут каскадом; байты с диска убирает вызывающий — они лежат
        // в `Blobs`, а не здесь.
        self.conn.execute("DELETE FROM files WHERE file_id = ?1", [&file_id[..]])?;
        Ok(())
    }

    fn search(&self, chat_id: Option<&[u8; 16]>, query: &str, limit: usize) -> Result<Vec<MsgId>> {
        let wanted = tokens::tokens_of(&self.db_key, query);
        if wanted.is_empty() {
            // Пустой запрос — пустой ответ. Вернуть всю историю значило бы
            // ответить не на тот вопрос.
            return Ok(Vec::new());
        }

        // Место под токены строится по их числу: списка переменной длины
        // в SQL нет, а склеивать значения в текст запроса нельзя даже когда
        // это байты, которые мы посчитали сами.
        let places =
            (0..wanted.len()).map(|i| format!("?{}", i + 4)).collect::<Vec<_>>().join(", ");
        let sql = format!(
            "SELECT m.msg_id
               FROM messages m
               JOIN message_tokens t ON t.msg_id = m.msg_id
              WHERE m.tombstone_ms IS NULL
                AND (?1 IS NULL OR m.chat_id = ?1)
                AND t.token IN ({places})
              GROUP BY m.msg_id
             HAVING COUNT(DISTINCT t.token) = ?2
              ORDER BY m.hlc_wall DESC, m.hlc_logical DESC, m.msg_id DESC
              LIMIT ?3"
        );

        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::with_capacity(wanted.len() + 3);
        params.push(Box::new(chat_id.map(|id| id.to_vec())));
        params.push(Box::new(sql_types::to_sql(wanted.len() as u64)));
        params.push(Box::new(sql_types::to_sql(limit as u64)));
        for token in &wanted {
            params.push(Box::new(token.to_vec()));
        }

        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            rusqlite::params_from_iter(params.iter().map(std::convert::AsRef::as_ref)),
            |row| row.get::<_, Vec<u8>>(0),
        )?;

        let mut found = Vec::new();
        for row in rows {
            let bytes = row?;
            let Ok(msg_id) = MsgId::try_from(bytes.as_slice()) else { continue };
            found.push(msg_id);
        }
        Ok(found)
    }

    fn note_seen(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO dedup (msg_id, seen_ms) VALUES (?1, ?2)",
            rusqlite::params![&msg_id[..], sql_types::to_sql(now_ms)],
        )?;
        Ok(inserted == 1)
    }

    fn put_contact(&mut self, contact: &StoredContact) -> Result<()> {
        // Локальное имя — заметка о человеке, поэтому шифруется, как и тело
        // сообщения, и привязывается к своей строке.
        let local_name_enc = match &contact.local_name {
            Some(name) => {
                Some(self.seal("contacts.local_name_enc", &contact.ik, name.as_bytes())?)
            }
            None => None,
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (
                 ik, sk, onion, chatmail, display_name,
                 card_version, card_bytes, verified, created_ms, local_name_enc, ygg
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &contact.ik[..],
                &contact.sk[..],
                contact.onion,
                contact.chatmail,
                contact.display_name,
                sql_types::to_sql(contact.card_version),
                contact.card_bytes,
                i64::from(contact.verified),
                sql_types::to_sql(contact.created_ms),
                local_name_enc,
                contact.ygg,
            ],
        )?;
        Ok(())
    }

    fn delete_contact(&mut self, ik: &[u8; 32]) -> Result<()> {
        // Сессии уйдут каскадом: внешний ключ объявлен ON DELETE CASCADE,
        // а прагма `foreign_keys = ON` выставляется при каждом открытии.
        self.conn.execute("DELETE FROM contacts WHERE ik = ?1", [&ik[..]])?;
        self.conn.execute("DELETE FROM avatars WHERE owner_ik = ?1", [&ik[..]])?;
        Ok(())
    }

    fn delete_chat(&mut self, chat_id: &[u8; 16]) -> Result<()> {
        let tx = self.conn.transaction()?;
        // Сообщения — явно, хотя внешний ключ и каскадный: порядок здесь
        // виден в диффе, а поведение не зависит от того, включена ли прагма.
        // Реакции — по той же причине и раньше сообщений: без них они
        // остались бы висеть на идентификаторах, которых уже нет.
        tx.execute(
            "DELETE FROM reactions
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.execute(
            "DELETE FROM message_tokens
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.execute(
            "DELETE FROM contact_shares
              WHERE msg_id IN (SELECT msg_id FROM messages WHERE chat_id = ?1)",
            [&chat_id[..]],
        )?;
        tx.execute("DELETE FROM messages WHERE chat_id = ?1", [&chat_id[..]])?;
        tx.execute("DELETE FROM chats WHERE chat_id = ?1", [&chat_id[..]])?;
        tx.commit()?;
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<StoredContact>> {
        let mut statement = self.conn.prepare(
            "SELECT ik, sk, onion, chatmail, display_name, card_version,
                    card_bytes, verified, created_ms, local_name_enc, ygg
               FROM contacts ORDER BY ik",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                sql_types::from_sql(row.get(5)?),
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, i64>(7)? != 0,
                sql_types::from_sql(row.get(8)?),
                row.get::<_, Option<Vec<u8>>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (
                ik,
                sk,
                onion,
                chatmail,
                display_name,
                card_version,
                card_bytes,
                verified,
                created_ms,
                local_name_enc,
                ygg,
            ) = row?;
            // Испорченное локальное имя не повод не отдать контакт: без имени
            // с человеком всё ещё можно переписываться, а без контакта — нет.
            let local_name = match local_name_enc {
                Some(sealed) => self
                    .open_sealed("contacts.local_name_enc", &ik, &sealed)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok()),
                None => None,
            };
            found.push(StoredContact {
                ik: ik.try_into().map_err(|_| StoreError::Backend("ik не 32 байта".into()))?,
                sk: sk.try_into().map_err(|_| StoreError::Backend("sk не 32 байта".into()))?,
                onion,
                chatmail,
                display_name,
                card_version,
                card_bytes,
                verified,
                created_ms,
                local_name,
                ygg,
            });
        }
        Ok(found)
    }

    fn put_session(&mut self, session: &StoredSession) -> Result<()> {
        // Снимок запечатывается и привязывается к своей строке: переставленный
        // между сессиями, он подсунул бы чужую цепочку под свой `session_id`.
        let state_enc =
            self.seal("sessions.state_enc", &session.session_id.to_be_bytes(), &session.snapshot)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (
                 session_id, peer_ik, binding, state_enc, established_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                // `session_id` выведен из хэша транскрипта и в половине случаев
                // больше `i64::MAX`; сохраняется побитово, сравнивается только
                // на равенство — см. `crate::sql_types`.
                sql_types::id_to_sql(session.session_id),
                &session.peer_ik[..],
                i64::from(session.binding),
                state_enc,
                sql_types::to_sql(session.established_ms),
            ],
        )?;
        Ok(())
    }

    fn sessions(&self) -> Result<Vec<StoredSession>> {
        let mut statement = self.conn.prepare(
            "SELECT session_id, peer_ik, binding, state_enc, established_ms FROM sessions",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                sql_types::id_from_sql(row.get(0)?),
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                sql_types::from_sql(row.get(4)?),
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (session_id, peer_ik, binding, state_enc, established_ms) = row?;
            let snapshot =
                self.open_sealed("sessions.state_enc", &session_id.to_be_bytes(), &state_enc)?;
            found.push(StoredSession {
                session_id,
                peer_ik: peer_ik
                    .try_into()
                    .map_err(|_| StoreError::Backend("peer_ik не 32 байта".into()))?,
                // Отрицательное или огромное число сюда попасть не может:
                // столбец пишем только мы, кодом семейства. А вот число
                // **незнакомое** — может, из более новой сборки, и его
                // разбирает уже ядро.
                binding: u8::try_from(binding).unwrap_or(u8::MAX),
                snapshot,
                established_ms,
            });
        }
        Ok(found)
    }

    fn delete_session(&mut self, session_id: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM sessions WHERE session_id = ?1",
            [sql_types::id_to_sql(session_id)],
        )?;
        Ok(())
    }

    fn put_handshake_seen(&mut self, digest: &[u8; 32], seen_ms: u64) -> Result<()> {
        // `OR IGNORE`, а не `OR REPLACE`: срок §8.3 считается от **первой**
        // встречи. Обновляй повтор время, настойчивый повторяющийся кадр
        // продлевал бы запись бесконечно — то есть кэш перестал бы стареть
        // ровно там, где стареть обязан.
        self.conn.execute(
            "INSERT OR IGNORE INTO handshake_seen (digest, created_ms) VALUES (?1, ?2)",
            rusqlite::params![&digest[..], sql_types::to_sql(seen_ms)],
        )?;
        Ok(())
    }

    fn handshake_seen(&self, newer_than_ms: u64) -> Result<Vec<([u8; 32], u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT digest, created_ms FROM handshake_seen
              WHERE created_ms > ?1
           ORDER BY created_ms ASC",
        )?;
        let mut rows = stmt.query([sql_types::to_sql(newer_than_ms)])?;
        let mut found = Vec::new();
        while let Some(row) = rows.next()? {
            let raw: Vec<u8> = row.get(0)?;
            // Строка не той длины — порча, а не запись: пропускаем молча.
            // Уронить здесь весь запуск из-за одной строки кэша значило бы
            // променять защиту от повтора на невозможность войти.
            let Ok(digest) = <[u8; 32]>::try_from(raw.as_slice()) else { continue };
            found.push((digest, sql_types::from_sql(row.get::<_, i64>(1)?)));
        }
        Ok(found)
    }

    fn prune_handshake_seen(&mut self, older_than_ms: u64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM handshake_seen WHERE created_ms <= ?1",
            [sql_types::to_sql(older_than_ms)],
        )?;
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let found = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(StoreError::from(other)),
            })?;
        Ok(found)
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    fn compact(&mut self, task: Task, now_ms: u64) -> Result<u64> {
        // Заготовка показывает форму: каждая задача — один DELETE по индексу
        // возраста, без арифметики в SQL (граница считается в Rust).
        //
        // Границы проходят через sql_types::to_sql, а не через `as i64`:
        // это метки времени, то есть величины, и сравнение `<` в SQL для них
        // осмысленно. Для session_id пришлось бы брать id_to_sql, и сравнивать
        // его на «меньше» было бы уже нельзя — см. crate::sql_types.
        let affected = match task {
            Task::Dedup => self.purge_by_age(
                "DELETE FROM dedup WHERE seen_ms <= ?1",
                compaction::DEDUP_TTL_MS,
                now_ms,
            )?,
            Task::HandshakeSeen => self.purge_by_age(
                "DELETE FROM handshake_seen WHERE created_ms <= ?1",
                compaction::HANDSHAKE_SEEN_TTL_MS,
                now_ms,
            )?,
            Task::SkippedKeys => self.purge_by_age(
                "DELETE FROM skipped_keys WHERE created_ms <= ?1",
                compaction::SKIPPED_KEYS_TTL_MS,
                now_ms,
            )?,
            // Остальные задачи перечислены поимённо, а не через `_`:
            // добавление новой задачи уборки обязано сломать компиляцию
            // именно здесь. Ради этого же с Task снят `#[non_exhaustive]`.
            //
            // Здесь стояло `todo!()`, и это было бы падением приложения
            // в тот день, когда уборку наконец начали запускать. Таблицы
            // заведены схемой, но писать в них некому: причинные ссылки
            // (§9.1) не сохраняются, фрагментация (§9.3) придёт с почтой,
            // снапшоты состава (§12) — с группами. Ноль здесь не заглушка,
            // а правда о том, сколько строк подлежит уборке.
            //
            // Правду эту стережёт `warn_if_filling`: в день, когда в таблицу
            // начнут писать, в журнале появится запись о том, что уборка
            // для неё не написана, — вместо тишины на несколько лет.
            Task::Reassembly => self.warn_if_filling("reassembly", "§9.3, фрагментация")?,
            Task::CausalRefs => self.warn_if_filling("causal_refs", "§12, окно ссылок")?,
            // §12: надгробие живёт 90 суток и уходит вместе со строкой.
            // Тело в ней и так уже пустое — стёрли в момент удаления.
            Task::Tombstones => self.purge_by_age(
                "DELETE FROM messages WHERE tombstone_ms IS NOT NULL AND tombstone_ms <= ?1",
                compaction::TOMBSTONE_TTL_MS,
                now_ms,
            )?,
            Task::GroupSnapshot => {
                self.warn_if_filling("group_baseline", "§12, снапшот состава")?
            }
        };
        Ok(affected as u64)
    }

    fn export_into(
        &self,
        scope: crate::archive::ExportScope,
        sink: &mut dyn crate::archive::ArchiveSink,
    ) -> Result<()> {
        // **`VACUUM INTO`, а не копия файла.** База открыта в режиме WAL:
        // часть свежих строк лежит в журнале рядом, и копия одного файла
        // дала бы архив без последних сообщений — молча, потому что такая
        // база прекрасно открывается. Заодно снимок выбрасывает дыры
        // от удалённых строк, и архив выходит меньше живой базы.
        let temp = self.path.with_extension("export-tmp");
        // Остаток прошлой неудачной попытки: `VACUUM INTO` отказывается
        // писать в существующий файл, и без этой строки вторая попытка
        // экспорта не состоялась бы никогда.
        let _ = std::fs::remove_file(&temp);
        let temp_text = temp.to_string_lossy().into_owned();
        self.conn.execute("VACUUM INTO ?1", [temp_text.as_str()])?;

        // Граф вывозится тем же снимком, из которого выброшено лишнее.
        // Собирать его отдельным запросом значило бы завести второй способ
        // читать контакты — и однажды они разошлись бы с первым.
        let sealed = if scope == crate::archive::ExportScope::SocialGraph {
            Self::prune_to_graph(&temp).and_then(|()| self.seal_snapshot_into(&temp, sink))
        } else {
            self.seal_snapshot_into(&temp, sink)
        };
        // Снимок убирается в любом исходе: он — незашифрованная копия базы
        // рядом с базой, и оставлять его лежать нельзя тем более после
        // неудачи, о которой человеку скажут словами.
        if let Err(error) = std::fs::remove_file(&temp) {
            tracing::warn!(?error, path = ?temp, "снимок базы убрать не вышло");
        }
        sealed
    }

    fn export_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(*self.db_key))
    }
}
