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
pub const SCHEMA_VERSION: u32 = 8;

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

/// Аватарки профиля — дополнение к §4.2, в спецификации v0.1 не описано.
///
/// Отдельная таблица, а не столбец в `contacts`, по двум причинам. Своя
/// аватарка контактом не является, а класть её в `meta` рядом с солью и
/// зерном — смешивать служебные величины с содержимым. И размер: строка
/// контакта читается при каждом подъёме (`Store::contacts`), и таскать
/// вместе с ней тридцать килобайт картинки на каждый старт незачем.
///
/// `owner_ik` для своей аватарки — собственный `IK`. Внешнего ключа
/// на `contacts` нет намеренно: своя строка иначе не легла бы вовсе.
pub const MIGRATION_0002: &str = r#"
CREATE TABLE avatars (
    owner_ik        BLOB PRIMARY KEY NOT NULL,   -- 32 байта; своя — собственный IK
    avatar_enc      BLOB NOT NULL,
    updated_ms      INTEGER NOT NULL
) STRICT;
"#;

/// Локальное имя контакта — то, как его подписал у себя пользователь.
///
/// **По проводу не едет никогда.** Имя из карточки (§4.1) задаёт собеседник
/// и потому не доверено; это — своя пометка, и отправить её значило бы
/// сообщить человеку, как его записали, а заодно завести поле, которое
/// собеседник может подделать. Шифруется: это заметка о человеке.
pub const MIGRATION_0003: &str = r#"
ALTER TABLE contacts ADD COLUMN local_name_enc BLOB;
"#;

/// Очередь ожидающих отправки — заново.
///
/// Таблица `outbox` из первой миграции не заполнялась ни разу, и это к счастью:
/// она была рассчитана на другую механику. В ней лежал **запечатанный** кадр
/// и битовая маска испробованных транспортов с моментом следующей попытки, то
/// есть повторы по расписанию. Действующая доставка устроена иначе: кадр
/// запечатывается заново под текущую сессию в момент отправки (§8.4 — ключ
/// у каждого кадра свой), а к отложенным сообщениям ядро возвращается не по
/// таймеру, а на событиях, которые меняют шансы: сеть сменилась, собеседник
/// объявился, сессия установилась. Хранить запечатанный кадр было бы прямо
/// неверно: сессия к моменту отправки может быть уже другой.
///
/// Поэтому хранится **конверт** — незапечатанный, а значит с текстом внутри,
/// а значит зашифрованный `db_key`, с суффиксом `_enc` по правилу §12. Столбец
/// прежней таблицы назывался `frame` и суффикса не имел; для кадра, уже
/// закрытого сессионным ключом, это было допустимо, для конверта — нет.
pub const MIGRATION_0004: &str = r#"
DROP TABLE outbox;
CREATE TABLE outbox (
    msg_id          BLOB PRIMARY KEY NOT NULL,   -- 16 байт
    recipient_ik    BLOB NOT NULL,               -- 32 байта
    envelope_enc    BLOB NOT NULL,               -- конверт целиком (§9.1)
    queued_ms       INTEGER NOT NULL             -- когда человек нажал «отправить»
) STRICT;
CREATE INDEX outbox_by_peer ON outbox(recipient_ik);
"#;

/// Правка, пересылка и реакции — дополнения к v0.1 (§17).
///
/// Три столбца и одна таблица, и каждое решение здесь про честность показа,
/// а не про удобство хранения.
///
/// `edited_ms` — отметка «изменено». Прежний текст не хранится нигде (см.
/// `ratatosk_proto::edit`), поэтому столбца под него нет и не будет: правка,
/// оставляющая старые слова доступными, обещает обратное тому, что нажал
/// человек. А отметка обязательна — молча подменить слова в чужой истории
/// §14 запрещает.
///
/// `forwarded` — пометка «переслано». Автор при этом **не хранится**: подпись
/// §6 при пересылке не сохраняется, и столбец `forwarded_from` был бы местом
/// для утверждения, которое получатель проверить не может.
///
/// `reactions` — отдельная таблица, а не столбец в `messages`: реакций на одно
/// сообщение столько, сколько участников, и в 1:1 их две, а в группе (§11) —
/// по числу людей. Ключ — пара «сообщение, автор», потому что реакция от
/// человека одна: новая заменяет прежнюю. Метка HLC рядом нужна, чтобы
/// запоздавшая реакция не затирала свежую (§9.2).
///
/// Внешний ключ на `messages` каскадный: реакция без сообщения бессмысленна.
/// Но удаление сообщения — это надгробие, а не удаление строки (§12), поэтому
/// реакции при удалении убираются **явно**, а каскад остаётся страховкой для
/// уборки.
pub const MIGRATION_0005: &str = r#"
ALTER TABLE messages ADD COLUMN edited_ms INTEGER;
ALTER TABLE messages ADD COLUMN forwarded INTEGER NOT NULL DEFAULT 0;

CREATE TABLE reactions (
    msg_id          BLOB NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    author_ik       BLOB NOT NULL,               -- 32 байта; своя — собственный IK
    emoji_enc       BLOB NOT NULL,               -- содержимое, значит шифруется
    hlc_wall        INTEGER NOT NULL,
    hlc_logical     INTEGER NOT NULL,
    PRIMARY KEY (msg_id, author_ik)
) STRICT;
"#;

/// Ответы на сообщения — дополнение к v0.1 (§17).
///
/// Один столбец: `msg_id` того сообщения, на которое отвечают. Отрывка цитаты
/// рядом нет и не будет — цитату каждая сторона рисует из своей копии
/// (`ratatosk_proto::reply`), а столбец с присланным текстом был бы местом для
/// слов, которые собеседник не говорил.
///
/// **Почему не `causal_refs`.** Таблица для причинных ссылок в схеме уже есть,
/// и соблазн лечь в неё понятен. Но она про другое: §12 держит в ней окно
/// последних тысячи сообщений и чистит его уборкой — то есть ссылка оттуда
/// законно исчезает. Ответ так исчезать не должен: это не подсказка порядка,
/// а часть того, что человек написал. Смешав одно с другим, мы получили бы
/// ответы, у которых через тысячу сообщений пропадает адресат, — и списали бы
/// это на уборку.
///
/// Внешнего ключа нет намеренно. Сообщение, на которое отвечают, может у нас
/// вообще никогда не появиться: ответ приходит своим кадром и может опередить
/// исходное сообщение или пережить его удаление. Ссылка поэтому «мягкая»:
/// не разрешилась — UI говорит «сообщение недоступно», а сам ответ остаётся
/// на месте.
pub const MIGRATION_0006: &str = r#"
ALTER TABLE messages ADD COLUMN reply_to BLOB;
"#;

/// Файлы — заново (§10).
///
/// Таблицы `files` и `file_chunks` из первой миграции не заполнялись ни разу,
/// и это к счастью: они были рассчитаны на другую механику и не знали ни имени
/// файла, ни превью, ни того, входящий он или исходящий.
///
/// Что изменилось и почему.
///
/// `name_enc`, `preview_enc`, `file_key_enc` — содержимое, поэтому шифруются
/// (§12). Имя файла говорит о переписке не меньше, чем текст сообщения:
/// «результаты анализов.pdf» в открытом столбце — ровно то, от чего §12
/// защищает тело сообщения.
///
/// `incoming` и `source_path` разводят две половины одной таблицы. Исходящий
/// файл читается **с диска по пути**: копировать гигабайт в своё хранилище
/// ради отправки значит требовать вдвое больше места, чем у файла есть.
/// Входящий, наоборот, пути не имеет — его чанки лежат в `Blobs` под своим
/// `file_id`, и путь появляется только когда человек нажал «сохранить».
///
/// `accepted` — согласие на загрузку. Автоматическое по порогу или нажатием;
/// хранится, потому что переживает перезапуск: файл, принятый вчера, не должен
/// спрашивать снова.
///
/// `local_path` из прежней таблицы не вернулся: это было место для «куда мы
/// его положили», а кладём мы теперь в `Blobs` по `file_id`. Путь сохранения
/// принадлежит системе и живёт у клиента.
///
/// `file_chunks` осталась строкой на принятый чанк. Для файла предельного
/// размера это две тысячи строк — и точный ответ на вопрос «с какого чанка
/// продолжать» (§10.2) без единого допущения о порядке прихода.
pub const MIGRATION_0007: &str = r#"
DROP TABLE file_chunks;
DROP TABLE files;

CREATE TABLE files (
    file_id         BLOB PRIMARY KEY NOT NULL,   -- 16 байт
    msg_id          BLOB NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    name_enc        BLOB NOT NULL,               -- имя говорит о переписке (§12)
    size_bytes      INTEGER NOT NULL,
    chunk_total     INTEGER NOT NULL,
    file_key_enc    BLOB NOT NULL,               -- ключ файла (§10.1)
    -- Столбец, который убирает следующая миграция. Оставлен здесь нарочно:
    -- база, успевшая накатить эту миграцию, его уже завела, и переписывать
    -- прошлое значило бы получить две разные схемы под одним номером — на
    -- новом устройстве без столбца, на старом с ним, и `DROP COLUMN` в 0008
    -- отказал бы ровно на первом. История миграций не правится задним числом.
    ciphertext_hash BLOB NOT NULL,               -- см. MIGRATION_0008
    preview_enc     BLOB,                        -- до 32 КиБ, класс M (§10.3)
    incoming        INTEGER NOT NULL,            -- 1 = принимаем, 0 = отправляем
    source_path     TEXT,                        -- откуда читать исходящий
    accepted        INTEGER NOT NULL DEFAULT 0,  -- согласие на загрузку
    complete        INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX files_by_message ON files(msg_id);
CREATE INDEX files_unfinished ON files(complete, incoming);

CREATE TABLE file_chunks (
    file_id         BLOB NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    chunk_index     INTEGER NOT NULL,
    PRIMARY KEY (file_id, chunk_index)
) STRICT;
"#;

/// Хэш шифротекста уходит из таблицы файлов (§10.1) — и это **расхождение
/// со спецификацией, записанное осознанно**.
///
/// §10.1 говорит: «Хэш для проверки целостности считается от шифротекста».
/// Главное в этой фразе — запрет считать хэш от **открытого** содержимого:
/// он позволил бы проверять наличие у вас конкретного известного файла. Запрет
/// соблюдён: хэша от содержимого нет нигде.
///
/// А сам хэш от шифротекста в нашей схеме не нужен, и держать его — значит
/// держать поле, которое ничего не проверяет. Каждый чанк запечатан отдельным
/// ключом, выведенным из `file_key ‖ index`, с AAD `file_id ‖ index`
/// (`ratatosk_crypto::file`). Тег AEAD уже утверждает три вещи: содержимое
/// не изменено, чанк с этого места и из этого файла. Хэш от склейки
/// шифротекстов добавил бы к этому ровно одно — что файл не обрезан, — а это
/// и так известно из `chunk_total`, который приезжает в том же предложении
/// и по той же зашифрованной сессии.
///
/// Чего он при этом стоил бы: работы порядка размера файла **в одном шаге**
/// ядра — и у отправителя перед отправкой, и у получателя при сборке. Ядро
/// sans-io (§13.3) обязано отвечать за постоянное время; двухгигабайтный файл
/// означал бы замерший интерфейс на десятки секунд, дважды. Возобновление
/// (§10.2) после перезапуска потребовало бы ещё и сохранённого состояния
/// хэшера, которого у BLAKE3 в публичном API нет.
///
/// Поэтому столбец уходит. Проверка целостности осталась и стала строже —
/// она поштучная и не откладывается до конца передачи.
pub const MIGRATION_0008: &str = r#"
ALTER TABLE files DROP COLUMN ciphertext_hash;
"#;

// Про порядок: столбец заводится в 0007 и убирается здесь, хотя между двумя
// миграциями не было ни одного выпуска. Так и надо. Миграция — не запись
// о намерении, а описание того, что уже произошло с чьей-то базой; переписав
// 0007, мы получили бы две несовместимые схемы под одним номером и падение
// `DROP COLUMN` на устройстве, которое накатило прежнюю версию.

/// Все миграции по порядку.
pub const MIGRATIONS: [&str; 8] = [
    MIGRATION_0001,
    MIGRATION_0002,
    MIGRATION_0003,
    MIGRATION_0004,
    MIGRATION_0005,
    MIGRATION_0006,
    MIGRATION_0007,
    MIGRATION_0008,
];

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
        for sensitive in [
            "state",
            "key",
            "body",
            "file_key",
            "chain",
            "data",
            "avatar",
            "local_name",
            "envelope",
            "emoji",
            "name",
            "preview",
        ] {
            let marked = format!("{sensitive}_enc");
            assert!(
                MIGRATIONS.iter().any(|m| m.contains(&marked)),
                "нет зашифрованного столбца {marked}"
            );
        }
    }

    #[test]
    fn schema_uses_strict_tables() {
        // STRICT не даёт SQLite молча принять текст в INTEGER-столбец.
        let table_count: usize = MIGRATIONS.iter().map(|m| m.matches("CREATE TABLE").count()).sum();
        let strict_count: usize = MIGRATIONS.iter().map(|m| m.matches(") STRICT;").count()).sum();
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
