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
use crate::{Result, Store, StoreError, StoredContact, StoredMessage};

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
        // `transport` и `status` не заполняются сознательно: у записи на диске
        // живой попытки доставки нет, а выдуманный статус §14 прямо запрещает.
        tx.execute(
            "INSERT OR REPLACE INTO messages (
                 msg_id, chat_id, sender_ik, hlc_wall, hlc_logical,
                 payload_type, body_enc, received_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
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
            "SELECT msg_id, sender_ik, hlc_wall, hlc_logical, body_enc, received_ms
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
                ))
            },
        )?;

        let mut window = Vec::new();
        for row in rows {
            let (msg_id, sender_ik, wall_ms, logical, body_enc, received_ms) = row?;
            let msg_id: MsgId = msg_id
                .try_into()
                .map_err(|_| StoreError::Backend("msg_id не 16 байт".into()))?;
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
            });
        }

        // Наружу — по возрастанию: так же, как отдаёт `MemoryStore`, и так же,
        // как читает чат человек.
        window.reverse();
        Ok(window)
    }

    fn note_seen(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO dedup (msg_id, seen_ms) VALUES (?1, ?2)",
            rusqlite::params![&msg_id[..], sql_types::to_sql(now_ms)],
        )?;
        Ok(inserted == 1)
    }

    fn put_contact(&mut self, contact: &StoredContact) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (
                 ik, sk, onion, chatmail, display_name,
                 card_version, card_bytes, verified, created_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
            ],
        )?;
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<StoredContact>> {
        let mut statement = self.conn.prepare(
            "SELECT ik, sk, onion, chatmail, display_name, card_version,
                    card_bytes, verified, created_ms
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
            ))
        })?;

        let mut found = Vec::new();
        for row in rows {
            let (ik, sk, onion, chatmail, display_name, card_version, card_bytes, verified, created_ms) =
                row?;
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
            });
        }
        Ok(found)
    }

    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let found = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get::<_, Vec<u8>>(0))
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
            Task::Tombstones => todo!("этап 0: надгробия старше 90 суток (§12)"),
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
