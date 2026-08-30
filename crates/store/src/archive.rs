//! Формат вывезенного архива переписки (§12).
//!
//! # Что здесь и чего здесь нет
//!
//! Здесь — **раскладка байтов и ничего больше**: заголовок, рамка записи,
//! правила разбора. Ни файлов, ни базы, ни шифрования: их знают
//! [`crate::sqlite`] и ядро. Разделено это нарочно — раскладку можно
//! проверить тестами, не поднимая ни SQLite, ни диска, а именно она
//! обязана пережить смену версии клиента.
//!
//! # Почему архив вообще нужен
//!
//! §12: «переписка выгружается в зашифрованный архив (тот же `db_key`, ключ
//! показывается пользователю). Это единственный путь переноса истории
//! на другое устройство в v1». Ни синхронизации, ни облака в v1 нет —
//! значит без архива история человека привязана к одному телефону
//! до его поломки.
//!
//! # Что лежит внутри
//!
//! Две вещи, и обе кусками:
//!
//! * **база** — снимок файла SQLite, запечатанный `db_key` по куску;
//! * **вложения** — куски из хранилища байтов, взятые **как есть**.
//!
//! Вложения не перешифровываются, и это решение, а не экономия внимания.
//! Куски файлов уже запечатаны своим ключом (§10.1), а ключ файла лежит
//! в базе, которая запечатана `db_key`. Второй слой поверх первого не скрыл
//! бы ничего нового — длины записей в архиве открыты в любом случае, — зато
//! стоил бы прохода шифрованием по каждому гигабайту вложений.
//!
//! **Что архив открывает о себе тому, у кого нет ключа:** сколько в нём
//! вложений, сколько у каждого кусков и какой они длины, и насколько велика
//! база. Это цена за то, что вложения едут как есть; скрыть её можно было бы
//! только набивкой, то есть заметно раздув архив.
//!
//! # Идентификатор архива
//!
//! Шестнадцать случайных байт в заголовке, открытых, и они входят
//! в associated data каждого куска базы. Без них два архива **одного
//! аккаунта** были бы взаимозаменяемы по кускам: `db_key` тот же, номер
//! куска тот же, — и кусок вчерашнего архива подставился бы в сегодняшний
//! незаметно. Стоит это шестнадцати байт.

use core::fmt;

/// Первые байты файла: по ним видно, что это вообще.
///
/// Нужны не для красоты: без них чужой файл разбирался бы как архив
/// и падал бы где-то в середине, а человек читал бы «архив испорчен»
/// вместо «это не архив».
pub const MAGIC: [u8; 8] = *b"RTSKEXP1";

/// Версия раскладки. Растёт, когда старый читатель перестаёт понимать новый
/// файл; читатель обязан отказываться словами, а не разбирать наугад.
pub const VERSION: u32 = 1;

/// Длина заголовка архива.
pub const HEADER_LEN: usize = 32;

/// Длина рамки одной записи — без её содержимого.
pub const ENTRY_HEADER_LEN: usize = 29;

/// Каким куском режется снимок базы.
///
/// Мебибайт — обычная единица чтения с диска, и он же случайно совпадает
/// с чанком файла (§10.1). **Совпадение здесь только совпадение**: слой
/// хранения о протоколе не знает нарочно, и брать число оттуда значило бы
/// завести ему такую зависимость ради одной константы. Поменяется чанк
/// протокола — это число не обязано меняться следом.
pub const SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;

/// Наибольшая длина содержимого одной записи.
///
/// **Предел нужен на чтении, а не на записи.** Архив мог быть испорчен
/// или подменён, и четыре байта длины позволяют попросить четыре гигабайта
/// в память до всякой расшифровки.
///
/// Два мебибайта, а не «сколько пишем плюс тег»: записи бывают двух родов —
/// кусок базы (наш размер плюс печать) и кусок вложения (чанк протокола
/// плюс тег), — и второй задан не здесь. Запас вдвое покрывает оба, а сотни
/// мегабайт на одну запись не бывает ни при каком из них.
pub const MAX_ENTRY_BYTES: usize = 2 * 1024 * 1024;

/// Что именно вывозится (§12).
///
/// **Область записана в архиве**, а не подразумевается по содержимому:
/// тот, кто его ввозит, обязан знать, чего в нём нет, — иначе архив без
/// вложений он вставит как полный, и человек увидит переписку с файлами,
/// которых не существует.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportScope {
    /// Всё: переписка, вложения, знакомства.
    Everything,
    /// Переписка без вложений — на порядок легче и уезжает в мессенджер.
    ///
    /// Записи о вложениях в базе **остаются**: выковырять их из снимка
    /// значило бы переписать чужую переписку. Ввоз обязан прочесть область
    /// и показать такие вложения как оставшиеся на прежнем устройстве.
    WithoutAttachments,
    /// Только знакомства: контакты с их адресами и своя идентичность.
    ///
    /// Ни сообщений, ни вложений, ни сессий. Сессии — отдельной строкой:
    /// это состояние ратчета (§8.4), и два устройства, шагающие по одной
    /// сессии, ломают переписку обоим. Новое устройство здоровается заново.
    SocialGraph,
}

impl ExportScope {
    /// Код в заголовке архива.
    ///
    /// Ноль у полного вывоза не случайно: заголовок версии 1 держал на этом
    /// месте нулевой запас, и архивы, написанные до появления областей,
    /// читаются как полные — то есть верно.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ExportScope::Everything => 0,
            ExportScope::WithoutAttachments => 1,
            ExportScope::SocialGraph => 2,
        }
    }

    /// Область по коду. `None` — код неизвестен.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<ExportScope> {
        match code {
            0 => Some(ExportScope::Everything),
            1 => Some(ExportScope::WithoutAttachments),
            2 => Some(ExportScope::SocialGraph),
            _ => None,
        }
    }

    /// Едут ли в этой области вложения.
    #[must_use]
    pub const fn carries_attachments(self) -> bool {
        matches!(self, ExportScope::Everything)
    }

    /// Как назвать область человеку.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            ExportScope::Everything => "переписка со вложениями",
            ExportScope::WithoutAttachments => "переписка без вложений",
            ExportScope::SocialGraph => "контакты и своя идентичность",
        }
    }
}

/// Заголовок архива.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Шестнадцать случайных байт: они входят в associated data кусков базы.
    pub archive_id: [u8; 16],
    /// Что именно вывезено.
    pub scope: ExportScope,
}

/// Что за запись лежит в архиве.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Кусок снимка базы, запечатанный `db_key`.
    Database,
    /// Кусок вложения — ровно тот, что лежит в хранилище байтов (§10.1).
    Attachment,
    /// Ключ базы, завёрнутый в парольную фразу (§12).
    ///
    /// **Идёт первой записью и только первой.** Куски базы запечатаны
    /// `db_key`, а `db_key` лежит здесь: читатель разбирает архив потоком
    /// и обязан получить ключ раньше того, что им открывается.
    ///
    /// Запись **необязательна**. Её отсутствие означает архив, который
    /// открывается сырым ключом, — так делались все архивы до появления
    /// фразы, и они обязаны читаться дальше.
    WrappedKey,
}

impl EntryKind {
    /// Код в рамке записи. Ноль занят концом архива и видом быть не может.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            EntryKind::Database => 1,
            EntryKind::Attachment => 2,
            EntryKind::WrappedKey => 3,
        }
    }

    /// Вид по коду. `None` — код неизвестен.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<EntryKind> {
        match code {
            1 => Some(EntryKind::Database),
            2 => Some(EntryKind::Attachment),
            3 => Some(EntryKind::WrappedKey),
            _ => None,
        }
    }
}

/// Байт, которым архив кончается.
///
/// Конец назван явно, а не «файл кончился»: оборванная на середине запись
/// иначе выглядела бы законным концом, и половина переписки читалась бы
/// как целая.
pub const END: u8 = 0;

/// Рамка записи: всё, кроме содержимого.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Что это.
    pub kind: EntryKind,
    /// Чего кусок: `file_id` вложения или нули у базы.
    pub id: [u8; 16],
    /// Номер куска, с нуля.
    pub index: u64,
    /// Длина содержимого, идущего следом.
    pub len: usize,
}

/// Что могло пойти не так при разборе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// Это не архив: не совпала магия.
    NotAnArchive,
    /// Архив новее этой сборки.
    UnknownVersion(u32),
    /// Файл кончился там, где обязан был продолжаться.
    Truncated,
    /// Рамка записи не разобралась: неизвестный вид или запредельная длина.
    BadEntry,
    /// Область вывоза этой сборке неизвестна.
    UnknownScope(u8),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArchiveError::NotAnArchive => write!(f, "это не архив переписки"),
            ArchiveError::UnknownVersion(v) => {
                write!(f, "архив версии {v}, а эта сборка знает {VERSION}")
            }
            ArchiveError::Truncated => write!(f, "архив оборван"),
            ArchiveError::BadEntry => write!(f, "запись в архиве не разобралась"),
            ArchiveError::UnknownScope(code) => {
                write!(f, "архив вывезен областью {code}, а эта сборка её не знает")
            }
        }
    }
}

impl std::error::Error for ArchiveError {}

/// Собирает заголовок архива.
#[must_use]
pub fn header_bytes(header: &Header) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[..8].copy_from_slice(&MAGIC);
    out[8..12].copy_from_slice(&VERSION.to_be_bytes());
    out[12..28].copy_from_slice(&header.archive_id);
    out[28] = header.scope.code();
    // Хвост нулевой: запас под то, чего ещё нет. Область встала как раз
    // в него — версию поднимать не пришлось, потому что ноль на этом месте
    // означает «всё», то есть ровно то, что писала версия без областей.
    out
}

/// Разбирает заголовок и отдаёт идентификатор архива.
///
/// # Errors
///
/// [`ArchiveError::NotAnArchive`], [`ArchiveError::UnknownVersion`],
/// [`ArchiveError::Truncated`].
pub fn parse_header(bytes: &[u8]) -> Result<Header, ArchiveError> {
    if bytes.len() < HEADER_LEN {
        return Err(ArchiveError::Truncated);
    }
    if bytes[..8] != MAGIC {
        return Err(ArchiveError::NotAnArchive);
    }
    let version = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if version != VERSION {
        return Err(ArchiveError::UnknownVersion(version));
    }
    let mut archive_id = [0u8; 16];
    archive_id.copy_from_slice(&bytes[12..28]);
    // Неизвестная область — отказ, а не «наверное, всё». Ввоз, принявший
    // незнакомую область за полную, показал бы человеку переписку с тем,
    // чего в архиве нет.
    let Some(scope) = ExportScope::from_code(bytes[28]) else {
        return Err(ArchiveError::UnknownScope(bytes[28]));
    };
    Ok(Header { archive_id, scope })
}

/// Собирает рамку записи.
#[must_use]
pub fn entry_bytes(
    kind: EntryKind,
    id: &[u8; 16],
    index: u64,
    len: usize,
) -> [u8; ENTRY_HEADER_LEN] {
    let mut out = [0u8; ENTRY_HEADER_LEN];
    out[0] = kind.code();
    out[1..17].copy_from_slice(id);
    out[17..25].copy_from_slice(&index.to_be_bytes());
    // Обрезание здесь невозможно: длину задаёт запечатанный кусок, а он
    // ограничен `MAX_ENTRY_BYTES`. Приведение всё равно явное — молчаливое
    // `as` спрятало бы будущую ошибку.
    let len = u32::try_from(len).unwrap_or(u32::MAX);
    out[25..29].copy_from_slice(&len.to_be_bytes());
    out
}

/// Разбирает рамку записи. `Ok(None)` — архив кончился.
///
/// # Errors
///
/// [`ArchiveError::Truncated`] — рамка не поместилась целиком;
/// [`ArchiveError::BadEntry`] — неизвестный вид или запредельная длина.
pub fn parse_entry(bytes: &[u8]) -> Result<Option<Entry>, ArchiveError> {
    let Some(&first) = bytes.first() else { return Err(ArchiveError::Truncated) };
    if first == END {
        return Ok(None);
    }
    if bytes.len() < ENTRY_HEADER_LEN {
        return Err(ArchiveError::Truncated);
    }
    let Some(kind) = EntryKind::from_code(first) else {
        return Err(ArchiveError::BadEntry);
    };
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[1..17]);
    let mut index = [0u8; 8];
    index.copy_from_slice(&bytes[17..25]);
    let mut len = [0u8; 4];
    len.copy_from_slice(&bytes[25..29]);
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_ENTRY_BYTES {
        return Err(ArchiveError::BadEntry);
    }
    Ok(Some(Entry { kind, id, index: u64::from_be_bytes(index), len }))
}

/// Associated data куска базы.
///
/// Связывает шифротекст с **этим** архивом и **этим** номером куска. Без
/// первого куски двух архивов одного аккаунта переставлялись бы между собой,
/// без второго — куски внутри архива.
#[must_use]
pub fn db_chunk_aad(archive_id: &[u8; 16], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(11 + 16 + 8);
    aad.extend_from_slice(b"export:db:");
    aad.extend_from_slice(archive_id);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Длина соли в завёрнутом ключе — та же, что у соли базы (§8.6).
pub const WRAP_SALT_LEN: usize = 16;

/// Длина завёрнутого ключа целиком.
///
/// Соль, три числа настроек вывода и запечатанные тридцать два байта:
/// nonce (24) + шифротекст (32) + тег (16).
pub const WRAP_LEN: usize = WRAP_SALT_LEN + 12 + 72;

/// Ключ базы, завёрнутый в парольную фразу.
///
/// **Настройки вывода едут вместе с ключом**, а не берутся из сборки,
/// которая архив открывает. Иначе архив, сделанный сегодня, перестал бы
/// открываться в тот день, когда мы поднимем стоимость Argon2id, — и
/// человек прочёл бы это как «фраза не та».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrap {
    /// Соль вывода. Открыта — это её штатный режим.
    pub salt: [u8; WRAP_SALT_LEN],
    /// Память Argon2id, КиБ.
    pub memory_kib: u32,
    /// Число проходов.
    pub iterations: u32,
    /// Степень параллелизма.
    pub parallelism: u32,
    /// `db_key`, запечатанный ключом из фразы.
    pub sealed: Vec<u8>,
}

impl KeyWrap {
    /// Собирает тело записи.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WRAP_LEN);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.memory_kib.to_be_bytes());
        out.extend_from_slice(&self.iterations.to_be_bytes());
        out.extend_from_slice(&self.parallelism.to_be_bytes());
        out.extend_from_slice(&self.sealed);
        out
    }

    /// Разбирает тело записи.
    ///
    /// # Errors
    ///
    /// [`ArchiveError::BadEntry`], если длина не та. Точность здесь важнее
    /// снисходительности: завёрнутый ключ — это ровно столько байт, сколько
    /// их положил писатель, и «почти столько» означает испорченный архив.
    pub fn from_bytes(bytes: &[u8]) -> Result<KeyWrap, ArchiveError> {
        if bytes.len() != WRAP_LEN {
            return Err(ArchiveError::BadEntry);
        }
        let mut salt = [0u8; WRAP_SALT_LEN];
        salt.copy_from_slice(&bytes[..WRAP_SALT_LEN]);
        let number = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        Ok(KeyWrap {
            salt,
            memory_kib: number(WRAP_SALT_LEN),
            iterations: number(WRAP_SALT_LEN + 4),
            parallelism: number(WRAP_SALT_LEN + 8),
            sealed: bytes[WRAP_SALT_LEN + 12..].to_vec(),
        })
    }
}

/// Associated data завёрнутого ключа.
///
/// Привязка к архиву — той же рукой, что и у кусков базы. Подставить сюда
/// чужой завёрнутый ключ и так бесполезно: под чужой фразой лежит чужой
/// `db_key`, и куски базы им не откроются. Но связывать шифротекст с местом
/// дешевле, чем каждый раз доказывать, что подмена безвредна.
#[must_use]
pub fn wrapped_key_aad(archive_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(11 + 16);
    aad.extend_from_slice(b"export:key:");
    aad.extend_from_slice(archive_id);
    aad
}

/// Куда складываются записи архива.
///
/// Типаж, а не структура, ровно по одной причине: куски базы печатает
/// хранилище — ключ базы не выходит за его пределы, — а куски вложений
/// кладёт ядро, у которого есть хранилище байтов. Общий у них только этот
/// вход.
pub trait ArchiveSink {
    /// Кладёт одну запись.
    ///
    /// # Errors
    ///
    /// Ошибка записи в файл.
    fn put(
        &mut self,
        kind: EntryKind,
        id: &[u8; 16],
        index: u64,
        body: &[u8],
    ) -> std::io::Result<()>;

    /// Идентификатор архива — он нужен печатающему для associated data.
    fn archive_id(&self) -> [u8; 16];
}

/// Пишет архив в поток.
pub struct ArchiveWriter<W: std::io::Write> {
    out: W,
    header: Header,
    /// Сколько записей легло — для отчёта человеку.
    entries: u64,
    /// Сколько байт содержимого легло.
    bytes: u64,
}

impl<W: std::io::Write> ArchiveWriter<W> {
    /// Начинает архив: пишет заголовок.
    ///
    /// # Errors
    ///
    /// Ошибка записи.
    pub fn start(mut out: W, header: Header) -> std::io::Result<ArchiveWriter<W>> {
        out.write_all(&header_bytes(&header))?;
        Ok(ArchiveWriter { out, header, entries: 0, bytes: 0 })
    }

    /// Закрывает архив: пишет конец и отдаёт счётчики.
    ///
    /// # Errors
    ///
    /// Ошибка записи.
    pub fn finish(mut self) -> std::io::Result<(u64, u64)> {
        self.out.write_all(&[END])?;
        self.out.flush()?;
        Ok((self.entries, self.bytes))
    }
}

impl<W: std::io::Write> ArchiveSink for ArchiveWriter<W> {
    fn put(
        &mut self,
        kind: EntryKind,
        id: &[u8; 16],
        index: u64,
        body: &[u8],
    ) -> std::io::Result<()> {
        self.out.write_all(&entry_bytes(kind, id, index, body.len()))?;
        self.out.write_all(body)?;
        self.entries += 1;
        self.bytes += body.len() as u64;
        Ok(())
    }

    fn archive_id(&self) -> [u8; 16] {
        self.header.archive_id
    }
}

/// Читает архив из потока.
///
/// **Читатель здесь, рядом с писателем**, и по той же причине, по какой
/// весь этот модуль не знает ни базы, ни диска: разбор чужого файла —
/// самое опасное место всей затеи, и проверять его надо там, где для этого
/// не нужно ни SQLite, ни ключей.
///
/// Поток, а не буфер: архив бывает в гигабайты, и держать его в памяти
/// целиком ради разбора незачем.
pub struct ArchiveReader<R: std::io::Read> {
    input: R,
    header: Header,
}

impl<R: std::io::Read> ArchiveReader<R> {
    /// Читает заголовок и готовится отдавать записи.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] — это не архив, он новее или оборван; ошибка чтения
    /// приезжает [`ArchiveError::Truncated`], потому что для разбора обе
    /// беды одинаковы: продолжать нечем.
    pub fn open(mut input: R) -> Result<ArchiveReader<R>, ArchiveError> {
        let mut head = [0u8; HEADER_LEN];
        read_exact(&mut input, &mut head)?;
        let header = parse_header(&head)?;
        Ok(ArchiveReader { input, header })
    }

    /// Заголовок: идентификатор архива и область вывоза.
    #[must_use]
    pub fn header(&self) -> Header {
        self.header
    }

    /// Следующая запись вместе с содержимым. `None` — архив кончился.
    ///
    /// # Errors
    ///
    /// [`ArchiveError`] — рамка не разобралась или файл оборван.
    #[allow(clippy::type_complexity)]
    pub fn next_entry(&mut self) -> Result<Option<(Entry, Vec<u8>)>, ArchiveError> {
        let mut first = [0u8; 1];
        read_exact(&mut self.input, &mut first)?;
        if first[0] == END {
            return Ok(None);
        }
        let mut rest = [0u8; ENTRY_HEADER_LEN];
        rest[0] = first[0];
        read_exact(&mut self.input, &mut rest[1..])?;
        let Some(entry) = parse_entry(&rest)? else {
            // Ноль уже отсеян выше; сюда попасть нельзя, но выдумывать
            // за разбор «конец» тем более нельзя.
            return Err(ArchiveError::BadEntry);
        };
        // Длина уже проверена `parse_entry` против `MAX_ENTRY_BYTES` —
        // выделять по ней память можно.
        let mut body = vec![0u8; entry.len];
        read_exact(&mut self.input, &mut body)?;
        Ok(Some((entry, body)))
    }
}

/// Читает ровно столько байт, сколько просили.
///
/// Своя, а не `Read::read_exact`: та отдаёт `std::io::Error`, а здесь у всех
/// бед разбора один ответ — продолжать нечем. Заодно короткое чтение
/// в середине файла не путается с концом файла.
fn read_exact<R: std::io::Read>(input: &mut R, into: &mut [u8]) -> Result<(), ArchiveError> {
    let mut filled = 0;
    while filled < into.len() {
        match input.read(&mut into[filled..]) {
            Ok(0) => return Err(ArchiveError::Truncated),
            Ok(got) => filled += got,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ArchiveError::Truncated),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(scope: ExportScope) -> Header {
        Header { archive_id: [7u8; 16], scope }
    }

    #[test]
    fn a_header_round_trips() {
        for scope in
            [ExportScope::Everything, ExportScope::WithoutAttachments, ExportScope::SocialGraph]
        {
            let head = header(scope);
            assert_eq!(parse_header(&header_bytes(&head)), Ok(head), "{scope:?}");
        }
    }

    #[test]
    fn the_scope_is_written_down_and_not_guessed_from_the_contents() {
        // Архив без вложений и полный архив без единого вложения выглядят
        // одинаково. Ввоз, принявший первый за второй, покажет человеку
        // переписку с файлами, которых не существует.
        let head = header(ExportScope::WithoutAttachments);
        assert_eq!(
            parse_header(&header_bytes(&head)).unwrap().scope,
            ExportScope::WithoutAttachments
        );
    }

    #[test]
    fn an_archive_from_before_scopes_reads_as_everything() {
        // Запас в заголовке был нулевым, и область встала ровно в него.
        // Ноль обязан означать «всё» — иначе первый же архив, написанный
        // до этой правки, стал бы нечитаемым.
        let mut bytes = header_bytes(&header(ExportScope::Everything));
        bytes[28] = 0;
        assert_eq!(parse_header(&bytes).unwrap().scope, ExportScope::Everything);
    }

    #[test]
    fn an_unknown_scope_is_refused_rather_than_taken_for_everything() {
        let mut bytes = header_bytes(&header(ExportScope::Everything));
        bytes[28] = 9;
        assert_eq!(parse_header(&bytes), Err(ArchiveError::UnknownScope(9)));
    }

    #[test]
    fn only_the_full_scope_carries_attachments() {
        assert!(ExportScope::Everything.carries_attachments());
        assert!(!ExportScope::WithoutAttachments.carries_attachments());
        assert!(!ExportScope::SocialGraph.carries_attachments());
    }

    #[test]
    fn someone_elses_file_is_not_an_archive() {
        // Человек указал не тот файл — он вправе прочитать об этом словами,
        // а не «архив испорчен» после половины разбора.
        let mut bytes = header_bytes(&header(ExportScope::Everything));
        bytes[0] = b'X';
        assert_eq!(parse_header(&bytes), Err(ArchiveError::NotAnArchive));
    }

    #[test]
    fn an_archive_from_the_future_says_so_instead_of_guessing() {
        let mut bytes = header_bytes(&header(ExportScope::Everything));
        bytes[8..12].copy_from_slice(&(VERSION + 1).to_be_bytes());
        assert_eq!(parse_header(&bytes), Err(ArchiveError::UnknownVersion(VERSION + 1)));
    }

    #[test]
    fn a_header_cut_short_is_refused() {
        let bytes = header_bytes(&header(ExportScope::Everything));
        assert_eq!(parse_header(&bytes[..HEADER_LEN - 1]), Err(ArchiveError::Truncated));
    }

    #[test]
    fn an_entry_round_trips() {
        let framed = entry_bytes(EntryKind::Attachment, &[3u8; 16], 42, 1000);
        let entry = parse_entry(&framed).unwrap().expect("не конец");
        assert_eq!(
            entry,
            Entry { kind: EntryKind::Attachment, id: [3u8; 16], index: 42, len: 1000 }
        );
    }

    #[test]
    fn the_end_is_named_and_not_guessed() {
        // Оборванная запись иначе выглядела бы законным концом, и половина
        // переписки читалась бы как целая.
        assert_eq!(parse_entry(&[END]), Ok(None));
        assert_eq!(parse_entry(&[]), Err(ArchiveError::Truncated));
        let framed = entry_bytes(EntryKind::Database, &[0u8; 16], 0, 10);
        assert_eq!(parse_entry(&framed[..ENTRY_HEADER_LEN - 1]), Err(ArchiveError::Truncated));
    }

    #[test]
    fn a_wrapped_key_round_trips() {
        let wrap = KeyWrap {
            salt: [3u8; WRAP_SALT_LEN],
            memory_kib: 65536,
            iterations: 3,
            parallelism: 1,
            sealed: vec![7u8; 72],
        };
        let bytes = wrap.to_bytes();
        assert_eq!(bytes.len(), WRAP_LEN);
        assert_eq!(KeyWrap::from_bytes(&bytes), Ok(wrap));
    }

    #[test]
    fn the_kdf_cost_travels_with_the_key() {
        // Возьми читатель настройки из своей сборки — архив, сделанный
        // сегодня, перестал бы открываться в день, когда мы поднимем
        // стоимость Argon2id. И человек прочёл бы это как «фраза не та».
        let wrap = KeyWrap {
            salt: [1u8; WRAP_SALT_LEN],
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 4,
            sealed: vec![0u8; 72],
        };
        let back = KeyWrap::from_bytes(&wrap.to_bytes()).unwrap();
        assert_eq!((back.memory_kib, back.iterations, back.parallelism), (19_456, 2, 4));
    }

    #[test]
    fn a_wrapped_key_of_the_wrong_length_is_refused() {
        let bytes = KeyWrap {
            salt: [0u8; WRAP_SALT_LEN],
            memory_kib: 1,
            iterations: 1,
            parallelism: 1,
            sealed: vec![0u8; 72],
        }
        .to_bytes();
        assert_eq!(KeyWrap::from_bytes(&bytes[..WRAP_LEN - 1]), Err(ArchiveError::BadEntry));
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(KeyWrap::from_bytes(&longer), Err(ArchiveError::BadEntry));
    }

    #[test]
    fn an_unknown_kind_is_refused_rather_than_skipped() {
        // Пропустить незнакомую запись значило бы отдать человеку архив,
        // из которого молча выпала часть переписки.
        let mut framed = entry_bytes(EntryKind::Database, &[0u8; 16], 0, 10);
        framed[0] = 9;
        assert_eq!(parse_entry(&framed), Err(ArchiveError::BadEntry));
    }

    #[test]
    fn a_length_beyond_the_limit_is_refused_before_any_allocation() {
        // Четыре байта длины позволяют попросить четыре гигабайта в память
        // до всякой расшифровки. Архив мог быть подменён.
        let mut framed = entry_bytes(EntryKind::Database, &[0u8; 16], 0, 0);
        framed[25..29].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_entry(&framed), Err(ArchiveError::BadEntry));
    }

    #[test]
    fn the_aad_binds_the_chunk_to_its_archive_and_its_place() {
        // Два архива одного аккаунта шифруются одним ключом. Без обеих
        // привязок кусок вчерашнего архива подставился бы в сегодняшний.
        let first = db_chunk_aad(&[1u8; 16], 0);
        assert_ne!(first, db_chunk_aad(&[2u8; 16], 0), "разные архивы");
        assert_ne!(first, db_chunk_aad(&[1u8; 16], 1), "разные куски");
    }

    /// Небольшой архив из двух записей — для тестов чтения.
    fn two_entry_archive(scope: ExportScope) -> Vec<u8> {
        let mut out = Vec::new();
        let head = Header { archive_id: [5u8; 16], scope };
        let mut writer = ArchiveWriter::start(&mut out, head).unwrap();
        writer.put(EntryKind::Database, &[0u8; 16], 0, b"base").unwrap();
        writer.put(EntryKind::Attachment, &[9u8; 16], 3, b"kusok").unwrap();
        writer.finish().unwrap();
        out
    }

    #[test]
    fn the_reader_walks_the_archive_the_writer_wrote() {
        let bytes = two_entry_archive(ExportScope::SocialGraph);
        let mut reader = ArchiveReader::open(std::io::Cursor::new(bytes)).expect("заголовок");
        assert_eq!(reader.header().scope, ExportScope::SocialGraph);
        assert_eq!(reader.header().archive_id, [5u8; 16]);

        let (first, body) = reader.next_entry().unwrap().expect("первая");
        assert_eq!(first.kind, EntryKind::Database);
        assert_eq!(body, b"base");
        let (second, body) = reader.next_entry().unwrap().expect("вторая");
        assert_eq!((second.kind, second.id, second.index), (EntryKind::Attachment, [9u8; 16], 3));
        assert_eq!(body, b"kusok");
        assert_eq!(reader.next_entry().unwrap(), None, "и конец назван");
    }

    #[test]
    fn an_archive_cut_off_mid_entry_is_refused_not_taken_for_the_end() {
        // **Главная опасность чтения.** Оборванный архив, принятый
        // за законченный, даёт половину переписки, выглядящую целой.
        let whole = two_entry_archive(ExportScope::Everything);
        for cut in [HEADER_LEN + 1, HEADER_LEN + ENTRY_HEADER_LEN, whole.len() - 1] {
            let mut reader = ArchiveReader::open(std::io::Cursor::new(whole[..cut].to_vec()))
                .expect("заголовок");
            loop {
                match reader.next_entry() {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("обрыв на {cut} прочитан как законный конец"),
                    Err(error) => {
                        assert_eq!(error, ArchiveError::Truncated, "обрыв на {cut}");
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn a_header_that_never_arrived_is_refused() {
        let whole = two_entry_archive(ExportScope::Everything);
        let error = ArchiveReader::open(std::io::Cursor::new(whole[..HEADER_LEN - 1].to_vec()));
        assert_eq!(error.err(), Some(ArchiveError::Truncated));
        assert_eq!(
            ArchiveReader::open(std::io::Cursor::new(Vec::new())).err(),
            Some(ArchiveError::Truncated),
            "пустой файл — не пустой архив"
        );
    }

    #[test]
    fn a_reader_fed_a_hostile_length_gives_up_before_allocating() {
        // Четыре байта длины позволяют попросить четыре гигабайта. Отказ
        // обязан случиться **до** выделения памяти, то есть в разборе рамки.
        let mut bytes = two_entry_archive(ExportScope::Everything);
        let at = HEADER_LEN + 25;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let mut reader = ArchiveReader::open(std::io::Cursor::new(bytes)).expect("заголовок");
        assert_eq!(reader.next_entry().err(), Some(ArchiveError::BadEntry));
    }

    #[test]
    fn a_written_archive_reads_back_entry_by_entry() {
        let mut out = Vec::new();
        {
            let head = Header { archive_id: [5u8; 16], scope: ExportScope::Everything };
            let mut writer = ArchiveWriter::start(&mut out, head).expect("заголовок");
            writer.put(EntryKind::Database, &[0u8; 16], 0, b"base").expect("база");
            writer.put(EntryKind::Attachment, &[9u8; 16], 3, b"kusok").expect("вложение");
            let (entries, bytes) = writer.finish().expect("конец");
            assert_eq!((entries, bytes), (2, 9));
        }

        let head = parse_header(&out).expect("заголовок читается");
        assert_eq!(head.archive_id, [5u8; 16]);
        assert_eq!(head.scope, ExportScope::Everything);

        let mut at = HEADER_LEN;
        let mut seen = Vec::new();
        while let Some(entry) = parse_entry(&out[at..]).expect("рамка") {
            at += ENTRY_HEADER_LEN;
            seen.push((entry, out[at..at + entry.len].to_vec()));
            at += entry.len;
        }
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0.kind, EntryKind::Database);
        assert_eq!(seen[0].1, b"base");
        assert_eq!(seen[1].0.kind, EntryKind::Attachment);
        assert_eq!(seen[1].0.id, [9u8; 16]);
        assert_eq!(seen[1].0.index, 3);
        assert_eq!(seen[1].1, b"kusok");
        assert_eq!(at, out.len() - 1, "после последней записи — только байт конца");
    }
}
