//! Схема SQLite (§12).
//!
//! Чувствительные поля шифруются **на уровне приложения** ключом `db_key`;
//! метаданные схемы остаются открытыми. Столбцы, содержащие шифротекст,
//! названы с суффиксом `_enc` — чтобы отсутствие суффикса в новом столбце
//! бросалось в глаза на ревью.
//!
//! Compaction обязателен с первого дня (§12): иначе клиент перестанет
//! открываться на третий год. Правила вычистки — в [`crate::compaction`],
//! но места, которые они чистят, заданы уже здесь.

/// Версия схемы. Увеличивается на каждую миграцию.
pub const SCHEMA_VERSION: u32 = 1;

/// Прагмы, выставляемые при каждом открытии соединения.
pub const PRAGMAS: &str = "\
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA secure_delete = ON;
";

/// Начальная схема.
pub const MIGRATION_0001: &str = r#"
-- Контакты (§4).
CREATE TABLE contacts (
    ik              BLOB PRIMARY KEY NOT NULL,   -- 32 байта
    sk              BLOB NOT NULL,               -- 32 байта
    onion           TEXT NOT NULL,
    chatmail        TEXT NOT NULL,
    display_name    TEXT NOT NULL,               -- не доверенное (§4.1)
    card_version    INTEGER NOT NULL,            -- монотонная (§4.3)
    card_bytes      BLOB NOT NULL,               -- принятые байты для подписи (§6)
    verified        INTEGER NOT NULL DEFAULT 0,  -- отпечаток сверен голосом (§4.2)
    created_ms      INTEGER NOT NULL
) STRICT;

-- Сессии (§8.3). Ключевой материал шифруется db_key на уровне приложения.
--
-- session_id хранится ПОБИТОВО через sql_types::id_to_sql: он выведен из хэша
-- транскрипта и в половине случаев больше i64::MAX, то есть лежит здесь
-- отрицательным числом. Сравнивать этот столбец можно только на равенство;
-- ORDER BY и BETWEEN по нему бессмысленны.
-- Состояние ретчета хранится **одним** запечатанным снимком, а не полями.
-- Причина в том, что счётчик отправки и ключ цепочки обязаны меняться
-- атомарно: разойдясь на одну запись, они дают повтор пары «ключ, nonce»,
-- то есть разрушают шифрование кадра целиком. Одна строка — одна транзакция,
-- и разойтись им негде. Формат снимка — `Session::export` в `ratatosk-crypto`.
CREATE TABLE sessions (
    session_id      INTEGER PRIMARY KEY NOT NULL,
    peer_ik         BLOB NOT NULL REFERENCES contacts(ik) ON DELETE CASCADE,
    binding         INTEGER NOT NULL,            -- 0 = LAN, 1 = Tor (§5.4)
    state_enc       BLOB NOT NULL,               -- снимок ретчета целиком
    established_ms  INTEGER NOT NULL             -- вход в правило §8.5
) STRICT;
CREATE INDEX sessions_by_peer ON sessions(peer_ik);

-- Кэш пропущенных ключей (§8.4): 2000 на сессию, 200 000 на устройство, TTL 30 суток.
--
-- Пока **не заполняется**: пропущенные ключи входят в снимок сессии выше.
-- Для локальной сети этого достаточно — перестановки там редки, и снимок
-- невелик. Отдельная таблица понадобится с приходом почты (этап 3): там
-- перестановки — штатный режим, кэш дорастает до предела §8.4, и переписывать
-- его целиком на каждое сообщение станет заметно дорого.

CREATE TABLE skipped_keys (
    session_id      INTEGER NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    counter         INTEGER NOT NULL,
    key_enc         BLOB NOT NULL,
    created_ms      INTEGER NOT NULL,
    PRIMARY KEY (session_id, counter)
) STRICT;
CREATE INDEX skipped_keys_by_age ON skipped_keys(created_ms);

-- Anti-replay рукопожатий (§8.3): TTL 30 суток, ёмкость 100 000, вытеснение LRU.
CREATE TABLE handshake_seen (
    digest          BLOB PRIMARY KEY NOT NULL,
    created_ms      INTEGER NOT NULL
) STRICT;
CREATE INDEX handshake_seen_by_age ON handshake_seen(created_ms);

-- Чаты: 1:1 и группы.
-- Для 1:1 `chat_id` — первые 16 байт `IK` собеседника, поэтому `peer_ik`
-- здесь избыточен и заполняется, только когда собеседник уже известен;
-- сообщение может лечь в чат раньше, чем контакт (§8.2 везёт карточку
-- в рукопожатии, а не до него).
CREATE TABLE chats (
    chat_id         BLOB PRIMARY KEY NOT NULL,
    kind            INTEGER NOT NULL,            -- 0 = 1:1, 1 = группа
    peer_ik         BLOB,                        -- для 1:1
    owner_ik        BLOB,                        -- для группы (§11.2)
    title_enc       BLOB,
    created_ms      INTEGER NOT NULL
) STRICT;

-- Сообщения. Порядок — по HLC (§9.1), а не по времени приёма.
CREATE TABLE messages (
    msg_id          BLOB PRIMARY KEY NOT NULL,   -- 16 байт
    chat_id         BLOB NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    sender_ik       BLOB NOT NULL,
    hlc_wall        INTEGER NOT NULL,
    hlc_logical     INTEGER NOT NULL,
    payload_type    INTEGER NOT NULL,
    body_enc        BLOB NOT NULL,
    envelope_bytes  BLOB,                        -- принятые байты (§6), нужны для проверки подписи
    received_ms     INTEGER NOT NULL,
    -- Транспорт и статус допускают NULL, и это не послабление: сообщение,
    -- поднятое с диска после перезапуска, живой попытки доставки уже не имеет.
    -- NOT NULL здесь заставлял бы писать выдуманное значение — а «неизвестно»
    -- и «отправлено» это разные вещи, и §14 требует не путать их перед
    -- пользователем.
    transport       INTEGER,                     -- определяет потолок статуса (§9.4)
    status          INTEGER,
    tombstone_ms    INTEGER                      -- удалённые живут 90 суток (§12)
) STRICT;
CREATE INDEX messages_order ON messages(chat_id, hlc_wall, hlc_logical, msg_id);
CREATE INDEX messages_tombstones ON messages(tombstone_ms);

-- Причинные ссылки. Хранятся только для окна в 1000 последних сообщений (§12).
CREATE TABLE causal_refs (
    msg_id          BLOB NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    ref_msg_id      BLOB NOT NULL,
    PRIMARY KEY (msg_id, ref_msg_id)
) STRICT;

-- Полнотекстовый поиск. Содержимое открытое: FTS5 не умеет искать по шифротексту.
-- Это осознанный размен, и он относится к тому же классу риска, что §2.2
-- «скомпрометированное устройство»: сам файл БД лежит в защищённом хранилище.
CREATE VIRTUAL TABLE messages_fts USING fts5(
    body,
    content = '',
    tokenize = 'unicode61'
);

-- Окно дедупликации (§9.2): 30 суток.
CREATE TABLE dedup (
    msg_id          BLOB PRIMARY KEY NOT NULL,
    seen_ms         INTEGER NOT NULL
) STRICT;
CREATE INDEX dedup_by_age ON dedup(seen_ms);

-- Состав групп: OR-Set с метками HLC (§11.2).
CREATE TABLE group_members (
    chat_id         BLOB NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    member_ik       BLOB NOT NULL,
    tag_wall        INTEGER NOT NULL,
    tag_logical     INTEGER NOT NULL,
    tag_actor       BLOB NOT NULL,
    tag_uniq        BLOB NOT NULL,
    removed         INTEGER NOT NULL DEFAULT 0,  -- надгробие
    PRIMARY KEY (chat_id, member_ik, tag_wall, tag_logical, tag_actor, tag_uniq)
) STRICT;

-- Базовая линия после снапшота состава (§12): всё до неё свёрнуто.
CREATE TABLE group_baseline (
    chat_id         BLOB PRIMARY KEY NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    baseline_wall   INTEGER NOT NULL,
    baseline_logical INTEGER NOT NULL,
    messages_since  INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Sender keys участников (§11.1).
CREATE TABLE sender_chains (
    chat_id         BLOB NOT NULL REFERENCES chats(chat_id) ON DELETE CASCADE,
    member_ik       BLOB NOT NULL,
    chain_enc       BLOB NOT NULL,
    counter         INTEGER NOT NULL,
    PRIMARY KEY (chat_id, member_ik)
) STRICT;

-- Файлы (§10).
CREATE TABLE files (
    file_id         BLOB PRIMARY KEY NOT NULL,
    msg_id          BLOB REFERENCES messages(msg_id) ON DELETE SET NULL,
    file_key_enc    BLOB NOT NULL,
    size_bytes      INTEGER NOT NULL,
    chunk_total     INTEGER NOT NULL,
    ciphertext_hash BLOB NOT NULL,               -- хэш от шифротекста (§10.1)
    local_path      TEXT,
    complete        INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE file_chunks (
    file_id         BLOB NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    chunk_index     INTEGER NOT NULL,
    received        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id, chunk_index)
) STRICT;

-- Незавершённые сборки фрагментов (§9.3).
CREATE TABLE reassembly (
    uid             BLOB NOT NULL,
    frag_index      INTEGER NOT NULL,
    frag_total      INTEGER NOT NULL,
    data_enc        BLOB NOT NULL,
    first_seen_ms   INTEGER NOT NULL,
    ttl_ms          INTEGER NOT NULL,            -- 30 суток почта, 10 минут прямой (§9.3)
    PRIMARY KEY (uid, frag_index)
) STRICT;
CREATE INDEX reassembly_by_age ON reassembly(first_seen_ms);

-- Очередь исходящих: одно сообщение — один транспорт за раз (§5.4).
CREATE TABLE outbox (
    msg_id          BLOB NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    recipient_ik    BLOB NOT NULL,
    frame           BLOB NOT NULL,
    tried_mask      INTEGER NOT NULL DEFAULT 0,  -- битовая маска Transport
    next_attempt_ms INTEGER NOT NULL,
    PRIMARY KEY (msg_id, recipient_ik)
) STRICT;
CREATE INDEX outbox_schedule ON outbox(next_attempt_ms);

-- Сопряжённые десктопы (§13.4). Отзыв — удаление строки и разрыв сессии.
CREATE TABLE paired_devices (
    device_id       BLOB PRIMARY KEY NOT NULL,
    label           TEXT NOT NULL,
    pairing_key_enc BLOB NOT NULL,
    paired_ms       INTEGER NOT NULL,
    last_seen_ms    INTEGER NOT NULL
) STRICT;

-- Служебное: версия схемы, гибридные часы, счётчики.
CREATE TABLE meta (
    key             TEXT PRIMARY KEY NOT NULL,
    value           BLOB NOT NULL
) STRICT;
"#;

/// Все миграции по порядку.
pub const MIGRATIONS: [&str; 1] = [MIGRATION_0001];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_count_matches_version() {
        assert_eq!(MIGRATIONS.len() as u32, SCHEMA_VERSION);
    }

    #[test]
    fn encrypted_columns_are_marked() {
        // Правило именования: столбец с шифротекстом обязан кончаться на _enc.
        // Тест грубый, но он ловит забытый столбец на ревью, а не в проде.
        for sensitive in ["state", "key", "body", "file_key", "chain", "data"] {
            let marked = format!("{sensitive}_enc");
            assert!(MIGRATION_0001.contains(&marked), "нет зашифрованного столбца {marked}");
        }
    }

    #[test]
    fn schema_uses_strict_tables() {
        // STRICT не даёт SQLite молча принять текст в INTEGER-столбец.
        let table_count = MIGRATION_0001.matches("CREATE TABLE").count();
        let strict_count = MIGRATION_0001.matches(") STRICT;").count();
        assert_eq!(table_count, strict_count, "не все таблицы объявлены STRICT");
    }

    #[test]
    fn compaction_targets_have_age_indexes() {
        // §12: всё, что чистится по TTL, должно чиститься по индексу,
        // иначе compaction сам станет причиной подвисаний.
        for index in [
            "skipped_keys_by_age",
            "handshake_seen_by_age",
            "dedup_by_age",
            "reassembly_by_age",
            "messages_tombstones",
        ] {
            assert!(MIGRATION_0001.contains(index), "нет индекса {index}");
        }
    }
}
