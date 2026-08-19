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
use crate::{
    FileId, Result, Store, StoreError, StoredAvatar, StoredContact, StoredFile, StoredMessage,
    StoredOutbox, StoredReaction, StoredSession,
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

    fn seal(&self, column: &str, row_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        storage_key::seal_field(&self.db_key, &Self::field_aad(column, row_key), plaintext)
            .map_err(|e| StoreError::Backend(e.to_string()))
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
        tx.commit()?;
        Ok(affected as u64)
    }

    fn edit_message(&mut self, msg_id: &MsgId, body: &[u8], edited_ms: u64) -> Result<bool> {
        // Тот же AAD, что и при записи: правка меняет содержимое строки,
        // а не её место.
        let body_enc = self.seal("messages.body_enc", msg_id, body)?;
        // Надгробие сильнее правки: сообщение, которое человек удалил,
        // не должно вернуться в чат из-за того, что автор его переписал.
        let affected = self.conn.execute(
            "UPDATE messages
                SET body_enc = ?2, edited_ms = ?3
              WHERE msg_id = ?1 AND tombstone_ms IS NULL",
            rusqlite::params![&msg_id[..], body_enc, sql_types::to_sql(edited_ms)],
        )?;
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

    fn delete_avatar(&mut self, owner_ik: &[u8; 32]) -> Result<()> {
        self.conn.execute("DELETE FROM avatars WHERE owner_ik = ?1", [&owner_ik[..]])?;
        Ok(())
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

    fn delete_outbox(&mut self, msg_id: &MsgId) -> Result<()> {
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
        self.conn.execute(
            "INSERT OR REPLACE INTO files (
                 file_id, msg_id, name_enc, size_bytes, chunk_total, file_key_enc,
                 preview_enc, incoming, source_path, accepted, complete
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &file.file_id[..],
                &file.msg_id[..],
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
        Ok(())
    }

    fn file(&self, file_id: &FileId) -> Result<Option<StoredFile>> {
        let mut statement = self.conn.prepare(
            "SELECT file_id, msg_id, name_enc, size_bytes, chunk_total, file_key_enc,
                    preview_enc, incoming, source_path, accepted, complete
               FROM files WHERE file_id = ?1",
        )?;
        let mut found = self.read_files(&mut statement, rusqlite::params![&file_id[..]])?;
        Ok(found.pop())
    }

    fn files_of(&self, msg_id: &MsgId) -> Result<Vec<StoredFile>> {
        let mut statement = self.conn.prepare(
            "SELECT file_id, msg_id, name_enc, size_bytes, chunk_total, file_key_enc,
                    preview_enc, incoming, source_path, accepted, complete
               FROM files WHERE msg_id = ?1 ORDER BY file_id",
        )?;
        self.read_files(&mut statement, rusqlite::params![&msg_id[..]])
    }

    fn accept_file(&mut self, file_id: &FileId) -> Result<bool> {
        let affected = self
            .conn
            .execute("UPDATE files SET accepted = 1 WHERE file_id = ?1", [&file_id[..]])?;
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
            "SELECT file_id, msg_id, name_enc, size_bytes, chunk_total, file_key_enc,
                    preview_enc, incoming, source_path, accepted, complete
               FROM files WHERE complete = 0 ORDER BY file_id",
        )?;
        self.read_files(&mut statement, rusqlite::params![])
    }

    fn file_ids_of_chat(&self, chat_id: &[u8; 16]) -> Result<Vec<FileId>> {
        let mut statement = self.conn.prepare(
            "SELECT files.file_id FROM files
               JOIN messages ON messages.msg_id = files.msg_id
              WHERE messages.chat_id = ?1
              ORDER BY files.file_id",
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
                 card_version, card_bytes, verified, created_ms, local_name_enc
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
        tx.execute("DELETE FROM messages WHERE chat_id = ?1", [&chat_id[..]])?;
        tx.execute("DELETE FROM chats WHERE chat_id = ?1", [&chat_id[..]])?;
        tx.commit()?;
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<StoredContact>> {
        let mut statement = self.conn.prepare(
            "SELECT ik, sk, onion, chatmail, display_name, card_version,
                    card_bytes, verified, created_ms, local_name_enc
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
                i64::from(!session.lan),
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
                row.get::<_, i64>(2)? == 0,
                row.get::<_, Vec<u8>>(3)?,
                sql_types::from_sql(row.get(4)?),
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (session_id, peer_ik, lan, state_enc, established_ms) = row?;
            let snapshot =
                self.open_sealed("sessions.state_enc", &session_id.to_be_bytes(), &state_enc)?;
            found.push(StoredSession {
                session_id,
                peer_ik: peer_ik
                    .try_into()
                    .map_err(|_| StoreError::Backend("peer_ik не 32 байта".into()))?,
                lan,
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
            Task::Reassembly => todo!("этап 0: сборки фрагментов с истёкшим TTL (§9.3)"),
            Task::CausalRefs => todo!("этап 0: причинные ссылки за окном в 1000 (§12)"),
            // §12: надгробие живёт 90 суток и уходит вместе со строкой.
            // Тело в ней и так уже пустое — стёрли в момент удаления.
            Task::Tombstones => self.purge_by_age(
                "DELETE FROM messages WHERE tombstone_ms IS NOT NULL AND tombstone_ms <= ?1",
                compaction::TOMBSTONE_TTL_MS,
                now_ms,
            )?,
            Task::GroupSnapshot => todo!("этап 0: снапшот состава группы (§12)"),
        };
        Ok(affected as u64)
    }

    fn export(&self, _destination: &Path) -> Result<()> {
        // TODO(этап 4): VACUUM INTO во временный файл, затем шифрование тем же
        // db_key; ключ показывается пользователю (§12).
        todo!("этап 4: экспорт переписки (§12)")
    }
}
