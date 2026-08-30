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
pub const SCHEMA_VERSION: u32 = 15;

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
--
-- Размен оказался неверным, и таблицу убирает MIGRATION_0009: §2.2 — про
-- устройство с малварью, а body_enc защищает от потерянного и изъятого,
-- где «защищённое хранилище» не значит ничего. Строки оставлены как были:
-- миграция описывает то, что уже произошло с чьей-то базой, и переписывать
-- её задним числом нельзя (см. про 0007 и 0008 ниже).
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

/// Поиск: индекс по хэшам слов вместо полнотекстового по открытому тексту.
///
/// **Отмена расхождения №5 из `ARCHITECTURE.md`.** Там было записано, что
/// `messages_fts` хранит тела открытым текстом, а оправдано это §2.2 —
/// «скомпрометированное устройство вне защиты». Оправдание неверное, и
/// увидеть это стоило начать заполнять индекс.
///
/// §2.2 говорит про устройство с малварью или рутом. А `body_enc` существует
/// ради другого случая: телефон **потеряли или изъяли**, файл базы у чужого,
/// PIN нет. База целиком не шифруется — это обычный SQLite, шифруются
/// отдельные поля (§12). Полнотекстовый индекс по открытым телам положил бы
/// рядом с зашифрованными сообщениями их же незашифрованную копию, то есть
/// свёл бы `body_enc` к декорации. Индекс, заполненный один раз, отдал бы
/// всю переписку.
///
/// Поэтому в индексе лежат не слова, а `BLAKE3_keyed(db_key, слово)`. Запрос
/// хэшируется тем же ключом и ищется по равенству. Без `db_key` эти хэши
/// не вычислить и не обратить: восстановить по ним текст нельзя.
///
/// Плата названа честно и следует из самой схемы: **ищутся только целые
/// слова.** Ни префиксов, ни подстрок, ни морфологии, ни ранжирования
/// по релевантности — хэш от «дом» и хэш от «дома» не связаны ничем.
/// И по индексу видно **структуру**: сколько в переписке разных слов,
/// сколько раз каждое повторяется и в каких сообщениях встречается вместе.
/// Содержимого это не выдаёт, а статистику выдаёт.
///
/// `PRIMARY KEY (msg_id, token)` заодно схлопывает повторы слова внутри
/// одного сообщения: «сколько раз» — сведение, без которого поиск обходится,
/// а частотный анализ обходится хуже.
pub const MIGRATION_0009: &str = r#"
DROP TABLE messages_fts;

CREATE TABLE message_tokens (
    msg_id          BLOB NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    token           BLOB NOT NULL,               -- BLAKE3_keyed(db_key, слово), 16 байт
    PRIMARY KEY (msg_id, token)
) STRICT;
CREATE INDEX message_tokens_by_token ON message_tokens(token);
"#;

/// Присланные карточки контактов (§4.1, дополнение).
///
/// Одна на сообщение — поэтому `msg_id` и первичный ключ. Поделиться тремя
/// людьми значит отправить три сообщения: у каждого своё решение «добавить
/// или нет» и свой статус доставки.
///
/// `card_enc` шифруется (§12), и это не перестраховка: карточка говорит,
/// с кем человек знаком, а список знакомств — ровно то же сведение о жизни,
/// что и текст сообщения. `ik` рядом открытым — по нему ищут, добавлен ли
/// уже этот человек, а сам `ik` контакта и так лежит открытым в `contacts`.
///
/// Признака «добавлен» в таблице нет намеренно. Он вычисляется: есть ли
/// строка в `contacts` с этим `ik`. Отдельный флаг разошёлся бы с правдой
/// в первый же раз, когда контакт добавят из QR или удалят.
pub const MIGRATION_0010: &str = r#"
CREATE TABLE contact_shares (
    msg_id          BLOB PRIMARY KEY NOT NULL REFERENCES messages(msg_id) ON DELETE CASCADE,
    ik              BLOB NOT NULL,               -- 32 байта, чей контакт
    card_enc        BLOB NOT NULL                -- карточка целиком, как приняли (§6)
) STRICT;
CREATE INDEX contact_shares_by_ik ON contact_shares(ik);
"#;

/// Сопряжённые десктопы (§13.4).
///
/// Отдельной миграцией, а не строкой в [`MIGRATION_0001`], и это исправление
/// настоящей ошибки, а не педантизм. Таблица была дописана в первую миграцию,
/// то есть в ту, которая на всех уже живущих устройствах давно выполнена.
/// Собралось бы это без единого предупреждения: SQL — строка, компилятор
/// в неё не смотрит. А на устройстве первое же сопряжение упало бы на
/// «no such table: paired_devices», и починить это можно было бы только
/// удалив базу, то есть переписку.
///
/// Отсюда правило: **выполненная миграция заморожена**. Новая таблица,
/// новый столбец, новый индекс — всегда следующим номером. За этим следит
/// `released_migrations_are_frozen`.
pub const MIGRATION_0011: &str = r#"
CREATE TABLE paired_devices (
    device_id       BLOB PRIMARY KEY NOT NULL,
    label           TEXT NOT NULL,
    pairing_key_enc BLOB NOT NULL,               -- ключ сопряжения под db_key
    paired_ms       INTEGER NOT NULL,
    last_seen_ms    INTEGER NOT NULL             -- 0 — ни разу не подключалось
) STRICT;
"#;

/// Порядок вложений внутри сообщения (§10).
///
/// **Появилась потому, что порядка не было вовсе, а он казался очевидным.**
/// `files_of` отдавала вложения `ORDER BY file_id`, то есть по случайным
/// шестнадцати байтам: три фотографии, выбранные человеком подряд, приходили
/// собеседнику в произвольном порядке. Заметить это на одном вложении нельзя,
/// а на трёх — сразу.
///
/// Столбец, а не сортировка по имени или размеру: порядок выбрал человек,
/// и вывести его из содержимого нельзя ничем.
///
/// Умолчание `0` у всех уже лежащих строк — и это правильно: у сообщений
/// с одним вложением порядок не значит ничего, а у прежних многофайловых
/// он и был произвольным. Чтение сортирует `ordinal, file_id`, так что старые
/// строки сохраняют ровно тот порядок, в каком показывались раньше.
pub const MIGRATION_0012: &str = r#"
ALTER TABLE files ADD COLUMN ordinal INTEGER NOT NULL DEFAULT 0;
"#;

/// Незаконченные выгрузки с десктопа (§13.4).
///
/// **Отдельные таблицы, а не строка в `files`.** У выгрузки нет сообщения:
/// оно заводится только третьим шагом, когда собраны все куски, — а
/// `files.msg_id` объявлен `NOT NULL REFERENCES messages`. Ослабить его
/// значило бы перестроить таблицу, в которой лежит настоящая переписка,
/// ради состояния, живущего минуты.
///
/// Здесь же и причина, по которой это вообще понадобилось: до сих пор
/// выгрузка жила в памяти ядра, и перезапуск телефона стирал её целиком.
/// С одним файлом это была досада, с пятью — потеря четырёх выгруженных
/// ради пятого.
///
/// `started_ms` нужен уборке: брошенная выгрузка занимает место в хранилище
/// байтов, и без срока это место не вернётся никогда.
pub const MIGRATION_0013: &str = r#"
CREATE TABLE staged_files (
    file_id         BLOB PRIMARY KEY NOT NULL,   -- 16 байт, назначил телефон
    chat_id         BLOB NOT NULL,               -- кому уедет, когда соберётся
    name_enc        BLOB NOT NULL,               -- имя говорит о переписке (§12)
    size_bytes      INTEGER NOT NULL,
    chunk_total     INTEGER NOT NULL,
    file_key_enc    BLOB NOT NULL,               -- ключ файла (§10.1)
    preview_enc     BLOB,                        -- до 32 КиБ, класс M (§10.3)
    started_ms      INTEGER NOT NULL             -- когда завели: для уборки
) STRICT;

CREATE TABLE staged_chunks (
    file_id         BLOB NOT NULL REFERENCES staged_files(file_id) ON DELETE CASCADE,
    chunk_index     INTEGER NOT NULL,
    PRIMARY KEY (file_id, chunk_index)
) STRICT;
"#;

/// Отозванные сопряжения — надгробия, ради ответа вернувшемуся десктопу (§13.4).
///
/// **Хранится ключ, а не устройство.** Записи о сопряжении больше нет —
/// её снёс отзыв, — и восстанавливать её нельзя: тогда отозванный десктоп
/// снова стал бы устройством. Остаётся ровно то, чем его узнать
/// в рукопожатии, и метка, по которой надгробие однажды уберут.
///
/// `revoked_ms` держит срок: тридцать суток, столько же, сколько живёт кэш
/// десктопа без подключения (§13.4). Дольше незачем — к тому времени десктоп
/// стирает кэш сам, и сказать ему уже нечего; меньше нельзя — до тех пор
/// он вправе вернуться и услышать причину вместо тишины.
///
/// Метки устройства здесь нет намеренно. Она нужна человеку в списке
/// сопряжений, а надгробию — незачем: показывать его человеку нечего,
/// и лишнее поле означало бы, что имя отозванного ноутбука переживает
/// сам отзыв.
pub const MIGRATION_0014: &str = r#"
CREATE TABLE revoked_devices (
    pairing_public  BLOB PRIMARY KEY NOT NULL,   -- 32 байта: чем узнать в рукопожатии
    revoked_ms      INTEGER NOT NULL             -- когда отозвали: для срока
) STRICT;
"#;

/// Адрес десктопа — чтобы телефон мог до него дозвониться вне общей сети.
///
/// **Почему столбец, а не поле в ключе сопряжения.** Ключ сопряжения — это
/// то, чем устройство узнаётся; адрес — то, где оно сейчас. Второе меняется
/// (сервис подняли, погасили, машину перенесли), первое не меняется никогда.
///
/// Открытым текстом, как и `contacts.onion`, и по той же причине: это адрес,
/// а не содержимое. Кто им владеет, видно и так — строка лежит в таблице
/// сопряжений.
///
/// Пустая строка — «только общая сеть», и это самое частое значение: дома
/// телефон находит десктоп маяком §5.1, и onion ему не нужен.
pub const MIGRATION_0015: &str = r#"
ALTER TABLE paired_devices ADD COLUMN onion TEXT NOT NULL DEFAULT '';
"#;

/// Все таблицы базы — поимённо.
///
/// Список нужен вывозу «социального графа» (§12): он оставляет
/// в [`GRAPH_TABLES`] и опустошает всё остальное. Перечислять то, что
/// **опустошается**, было бы опаснее: новая таблица уехала бы вместе
/// с графом молча, а в ней могла оказаться переписка.
///
/// Сверяется тестом с тем, что на самом деле создают миграции, — чтобы
/// «список отстал от схемы» было падением сборки, а не тихой утечкой.
pub const ALL_TABLES: [&str; 24] = [
    "avatars",
    "causal_refs",
    "chats",
    "contact_shares",
    "contacts",
    "dedup",
    "file_chunks",
    "files",
    "group_baseline",
    "group_members",
    "handshake_seen",
    "message_tokens",
    "messages",
    "meta",
    "outbox",
    "paired_devices",
    "reactions",
    "reassembly",
    "revoked_devices",
    "sender_chains",
    "sessions",
    "skipped_keys",
    "staged_chunks",
    "staged_files",
];

/// Таблицы, уезжающие в вывоз «социального графа» (§12).
///
/// Контакты с их адресами, аватарки к ним и служебная строка — всё.
///
/// **Чего здесь нет и почему.** `sessions` и `sender_chains` — состояние
/// ратчета (§8.4): два устройства, шагающие по одной сессии, ломают
/// переписку обоим, поэтому новое здоровается заново. `paired_devices` —
/// сопряжения с десктопом: устройство, сопряжённое сразу с двумя телефонами,
/// это способ тихо раздать доступ. `chats` — переписка, а не знакомство,
/// и заводятся они первым же сообщением сами.
pub const GRAPH_TABLES: [&str; 3] = ["avatars", "contacts", "meta"];

/// Строки `meta`, уезжающие вместе с графом (§12).
///
/// Своя личность целиком: зерно (§3), ключ onion-сервиса (§5.2), соль
/// для вывода ключа из PIN (§8.6), объявленная карточка (§4.3) и почтовый
/// ящик (§5.3).
///
/// **Ящик едет вместе с паролем**, и это стоит знать. Без него личность
/// переносится наполовину: адрес в карточке есть, а войти в него новое
/// устройство не может, и собеседник, у которого только почта, остаётся
/// с адресом в никуда. Пароль защищён тем же ключом, что и переписка,
/// и в архиве — тем же, что весь снимок.
pub const GRAPH_META_KEYS: [&str; 5] =
    ["identity_seed", "onion_key", "db_salt", "self_card", "mail_account"];

/// Все миграции по порядку.
pub const MIGRATIONS: [&str; 15] = [
    MIGRATION_0001,
    MIGRATION_0002,
    MIGRATION_0003,
    MIGRATION_0004,
    MIGRATION_0005,
    MIGRATION_0006,
    MIGRATION_0007,
    MIGRATION_0008,
    MIGRATION_0009,
    MIGRATION_0010,
    MIGRATION_0011,
    MIGRATION_0012,
    MIGRATION_0013,
    MIGRATION_0014,
    MIGRATION_0015,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_list_matches_what_the_migrations_create() {
        // **Список обязан отставать от схемы шумно.** Вывоз графа оставляет
        // перечисленное и опустошает остальное; таблица, не попавшая
        // в список, уехала бы вместе с графом молча — а в ней могла
        // оказаться переписка.
        let mut created: Vec<String> = Vec::new();
        for migration in MIGRATIONS {
            for line in migration.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("CREATE TABLE ") {
                    let name: String =
                        rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    created.push(name);
                }
            }
        }
        created.sort();
        // Пересозданную миграцией таблицу считаем **одной**: перестройка
        // таблицы — обычный приём SQLite, а имя от этого не двоится.
        created.dedup();
        let mut known: Vec<String> = ALL_TABLES.iter().map(|t| (*t).to_owned()).collect();
        known.sort();
        assert_eq!(created, known, "список таблиц разошёлся с миграциями");
    }

    #[test]
    fn the_graph_tables_are_real_tables() {
        for table in GRAPH_TABLES {
            assert!(ALL_TABLES.contains(&table), "таблицы {table} в схеме нет");
        }
    }

    #[test]
    fn migration_count_matches_version() {
        assert_eq!(MIGRATIONS.len() as u32, SCHEMA_VERSION);
    }

    /// Контрольные суммы выпущенных миграций.
    ///
    /// Каждая из них уже выполнена на живых устройствах. Правка любой из них
    /// не даёт **ничего** тому, у кого база уже есть: миграция с этим номером
    /// у него отмечена выполненной и второй раз не пойдёт. Новая таблица
    /// попадёт только на свежеустановленные устройства, и расхождение между
    /// двумя половинами пользователей вскроется не сборкой, а падением
    /// на «no such table» у одной из них.
    ///
    /// Так уже случилось: таблица `paired_devices` (§13.4) была дописана
    /// в [`MIGRATION_0001`] и переехала в [`MIGRATION_0011`] отдельным
    /// исправлением. Этот список существует затем, чтобы это не повторилось.
    ///
    /// **Что делать, если тест упал.** Почти наверняка вы правите выпущенную
    /// миграцию — верните её как было и заведите следующий номер. Число здесь
    /// меняют только вместе с добавлением новой миграции в конец списка.
    const FROZEN: [u64; 15] = [
        0xa3f5_d87f_eeaa_0e3c,
        0x7996_4d61_828d_b650,
        0x67d3_78d4_c2cc_c4f1,
        0xa17e_09c9_981f_39a6,
        0xd2f7_425e_015d_be60,
        0x6054_f58b_0da1_40be,
        0x1357_bf71_164f_d540,
        0xc24a_a2bb_94f8_9ae1,
        0xf06e_e041_8bdd_ac39,
        0xa26a_3e5f_41b0_c803,
        0xde25_353b_dd1a_d1da,
        0xdceb_7612_67d6_ce9a,
        0x8f1d_f010_038e_1883,
        0x7f6f_ac9e_fd48_0955,
        0x685e_f95e_a083_7bab,
    ];

    /// FNV-1a, 64 бита.
    ///
    /// Своя функция вместо зависимости: криптографической стойкости здесь
    /// не нужно — тест ловит **свою** невнимательность, а не подмену.
    fn checksum(text: &str) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in text.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    #[test]
    fn released_migrations_are_frozen() {
        assert_eq!(FROZEN.len(), MIGRATIONS.len(), "у новой миграции нет контрольной суммы");
        for (number, (migration, frozen)) in MIGRATIONS.iter().zip(FROZEN).enumerate() {
            assert_eq!(
                checksum(migration),
                frozen,
                "миграция {:04} изменена. Она уже выполнена на живых устройствах, \
                 и правка до них не доедет — заведите следующий номер",
                number + 1
            );
        }
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
            // Карточка присланного контакта: она говорит, с кем человек
            // знаком, а список знакомств — то же сведение о жизни, что
            // и текст сообщения.
            "card",
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
