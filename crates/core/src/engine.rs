//! Ядро протокола (§13.3).
//!
//! «В ядре: крипта, протокол, транспорты, хранилище, синхронизация.
//! В клиентах — только UI и системная интеграция. Правило без исключений:
//! никакой протокольной логики выше UniFFI-границы.»
//!
//! [`Engine`] — единственная точка входа. Он не создаёт потоков, не открывает
//! сокетов и не читает часы: время приходит параметром `now_ms`, внешний мир
//! общается с ним через [`Input`] и [`Effect`], случайность — через
//! [`Entropy`].
//!
//! **Область этого этапа — 1:1 текст.** Файлы (§10), группы (§11) и
//! перерукопожатие (§8.5) ещё не проходят через `step`; каждая такая ветка
//! помечена `todo!()` со ссылкой на раздел. Ветки перечислены поимённо,
//! без `_`, поэтому новый вариант `Command` сломает компиляцию здесь.

use std::collections::{BTreeMap, BTreeSet};

use ratatosk_codec::{ContactCard, Envelope, PayloadType, Value};
use ratatosk_crdt::{DedupWindow, Hlc, HlcClock, MsgId};
use ratatosk_crypto::aead;
use ratatosk_crypto::handshake::{
    Accepted, HandshakeOutcome, Initiator, PendingHandshake, Responder,
};
use ratatosk_crypto::{HandshakeReplayGuard, Identity, RekeyPolicy, Session};
use ratatosk_proto::fragment::Reassembler;
use ratatosk_proto::receipts::{Receipt, MAX_RECEIPT_IDS};
use ratatosk_proto::transport_policy::{Attempt, Decision, PeerAvailability, SessionBinding};
use ratatosk_proto::{DeliveryStatus, SessionRegistry, Transport};
use ratatosk_store::{
    Blobs, FileId, Schedule, Store, StoredContactShare, StoredFile, StoredMessage, Task,
};
use ratatosk_wire::{pad_to, unpad, FrameType, Header, SizeClass};

use crate::entropy::Entropy;
use crate::io::{ChatId, Command, Effect, Event, Input, OutgoingFile, Swept};
use crate::reader::FileReader;

/// Номер первого сообщения рукопожатия в поле `counter` заголовка.
///
/// **Уточнение к §8.3.** Спецификация говорит, что кадры рукопожатия идут
/// с `session_id = 0`, но не говорит, как получатель отличает первое
/// сообщение `-> e, es, s, ss` от ответа `<- e, ee, se`. Оба приходят с нулём.
///
/// Формат кадра менять не пришлось: `counter` в заголовке (§7.1) — это
/// «номер сообщения в отправляющей цепочке», и для рукопожатия он
/// естественно читается как номер шага. Ноль — первое, единица — ответ.
/// В §8.3 это стоит дописать одной фразой.
pub const HANDSHAKE_STEP_FIRST: u64 = 0;
/// Номер ответного сообщения рукопожатия.
pub const HANDSHAKE_STEP_RESPONSE: u64 = 1;

/// Класс кадра для рукопожатия (§5.5).
///
/// Первое сообщение — это `e` (32) + зашифрованный `s` (48) + карточка
/// (около 200 байт, §4.1) + тег. Всё укладывается в 4 КиБ с запасом.
const HANDSHAKE_CLASS: SizeClass = SizeClass::S;

/// Страховочный таймаут попытки, если транспорт своего не задаёт.
///
/// [`Attempt::timeout_ms`] возвращает `None` для почты — её ответа ждать
/// бессмысленно (§5.4). Но запись в очереди без таймера зависла бы навсегда,
/// поэтому у прямых каналов таймаут есть всегда, а это значение — то же,
/// что вернула бы политика. Своего числа здесь нет намеренно: два срока
/// ожидания ответа, живущие в разных файлах, однажды разойдутся.
const ONION_FALLBACK_TIMEOUT_MS: u64 = ratatosk_proto::transport_policy::ONION_REPLY_TIMEOUT_MS;

/// Сколько ждать, пока обнаружение (§5.1) ответит, есть ли собеседник в сети.
///
/// Нужно ровно на холодном старте и после смены сети: `seen_on_lan` не
/// переживает перезапуск намеренно — адрес в локальной сети живёт столько же,
/// сколько подключение, и поднимать его с диска значило бы врать. Но mDNS
/// отвечает не мгновенно, и без этой паузы первое же сообщение после запуска
/// объявлялось недоставленным раньше, чем собеседник вообще успевал найтись.
///
/// Три секунды: mDNS в локальной сети отвечает за сотни миллисекунд даже на
/// телефоне, а человек, нажавший «отправить», столько подождёт. Ожидание
/// выдаётся один раз на контакт за сеанс, поэтому собеседник, которого в этой
/// сети нет, стоит трёх секунд один раз, а не при каждой отправке.
const LAN_DISCOVERY_GRACE_MS: u64 = 3_000;

/// Наибольшая длина локального имени контакта, в символах Unicode.
///
/// Предел нужен не ради экрана, а ради базы: поле пишет клиент, и без потолка
/// одна опечатка в цикле кладёт в хранилище мегабайты. Шестидесяти четырёх
/// хватает на «Аня с курсов вязания» с запасом.
pub const MAX_LOCAL_NAME_CHARS: usize = 64;

/// Сколько неотправленных сообщений помнить до появления сети.
///
/// Список живёт в памяти и потому ограничен: очередь, растущая без предела,
/// на телефоне кончается убитым процессом. Двести — это «писал весь вечер
/// в самолёте», а не край. Про то, что список **не переживает перезапуск**,
/// сказано в `FFI.md` прямо: обещать больше, чем сделано, §14 запрещает.
const MAX_DEFERRED: usize = 200;

/// Отказ ядра.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Ошибка хранилища.
    #[error("хранилище: {0}")]
    Store(#[from] ratatosk_store::StoreError),
    /// Ошибка криптослоя.
    #[error("криптография: {0}")]
    Crypto(#[from] ratatosk_crypto::CryptoError),
    /// Ошибка разбора структуры.
    #[error("формат: {0}")]
    Codec(#[from] ratatosk_codec::CodecError),
    /// Ошибка формата кадра.
    #[error("кадр: {0}")]
    Wire(#[from] ratatosk_wire::WireError),
    /// Гибридные часы отказались выдать метку.
    #[error("часы: {0}")]
    Clock(#[from] ratatosk_crdt::HlcError),
    /// Обращение к неизвестному контакту или чату.
    #[error("контакт неизвестен")]
    UnknownPeer,
    /// Аватарка не прошла проверку размера или формата.
    #[error("аватарка: {0}")]
    Avatar(#[from] ratatosk_proto::avatar::AvatarError),
    /// Локальное имя длиннее [`MAX_LOCAL_NAME_CHARS`].
    #[error("локальное имя длиннее {MAX_LOCAL_NAME_CHARS} символов")]
    LocalNameTooLong,
    /// Правка не принята: пустая, поздняя или не своя.
    #[error("правка: {0}")]
    Edit(#[from] ratatosk_proto::edit::EditError),
    /// Реакция не принята: слишком длинная или не эмодзи.
    #[error("реакция: {0}")]
    Reaction(#[from] ratatosk_proto::reaction::ReactionError),
    /// Файл не принят: размер, имя, число вложений или превью.
    #[error("файл: {0}")]
    File(#[from] ratatosk_proto::files::FileError),
    /// Ответ не принят: без слов или на то, чего в этом чате нет.
    ///
    /// Отказ, а не тихая отправка обычным текстом: человек нажал «ответить»
    /// на что-то конкретное, и молча превратить это в отдельное сообщение
    /// значит сделать не то, что он просил.
    #[error("ответ: {0}")]
    Reply(#[from] ratatosk_proto::reply::ReplyError),
}

// Варианта «нет доступного транспорта» здесь нет сознательно. Раньше он был,
// и это была ошибка проектирования: сообщение, которому некуда ехать, — не
// отказ ядра, а исход доставки. Отказ вернулся бы вызывающему и сообщение
// исчезло бы, тогда как §14 требует показать пользователю, что оно не ушло.
// Теперь этот случай выражается статусом `DeliveryStatus::Undeliverable`,
// а сообщение остаётся в истории.

// Срок молчания по файлу живёт в `proto::files`, а не здесь: он зависит
// от транспорта (мебибайт по локальной сети и мебибайт через три реле Tor —
// разные величины), и держать его рядом с размером чанка и окном честнее,
// чем рядом с кодом, который его только заводит.

/// Идущая исходящая передача файла (§10.2).
///
/// Окно, а не «шлём всё подряд»: без него один шаг ядра выдал бы драйверу весь
/// файл эффектами, то есть два гигабайта в памяти процесса, который на Android
/// убивают за меньшее. Отправитель держит окно в [`CHUNK_WINDOW`] чанков
/// впереди подтверждённого получателем.
///
/// [`CHUNK_WINDOW`]: ratatosk_proto::files::CHUNK_WINDOW
#[derive(Debug, Clone, Copy)]
struct Sending {
    file_id: FileId,
    peer_ik: [u8; 32],
    /// Сколько всего чанков.
    chunk_total: u64,
    /// Получатель подтвердил всё **до** этого номера.
    acked_upto: u64,
    /// Сколько чанков уже отправлено.
    sent_upto: u64,
}

/// Чем сообщение является помимо текста.
///
/// Один тип на отправку и на приём, и это не экономия: тип конверта, пометка
/// в истории и ссылка на цитируемое сообщение обязаны выбираться **вместе**.
/// Разведи их по трём параметрам — и первый же вызов поставит
/// `PayloadType::Forward` без пометки в базе или ссылку без типа `Reply`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextKind {
    /// Обычное сообщение.
    Plain,
    /// Переслано из другого разговора (`ratatosk_proto::forward`).
    Forwarded,
    /// Ответ на сообщение (`ratatosk_proto::reply`).
    Reply(MsgId),
}

impl TextKind {
    /// Тип конверта (§9.1).
    const fn payload_type(self) -> PayloadType {
        match self {
            TextKind::Plain => PayloadType::Text,
            TextKind::Forwarded => PayloadType::Forward,
            TextKind::Reply(_) => PayloadType::Reply,
        }
    }

    /// Полезная нагрузка. У ответа она составная — ссылка и текст.
    fn payload(self, text: &str) -> Value {
        match self {
            TextKind::Plain | TextKind::Forwarded => Value::Text(text.to_owned()),
            TextKind::Reply(target) => ratatosk_proto::reply::payload(target, text),
        }
    }

    /// Пометка «переслано» для истории.
    const fn forwarded(self) -> bool {
        matches!(self, TextKind::Forwarded)
    }

    /// Ссылка на цитируемое сообщение для истории.
    const fn reply_to(self) -> Option<MsgId> {
        match self {
            TextKind::Reply(target) => Some(target),
            _ => None,
        }
    }
}

/// Собственные адреса — то, что уезжает в контакт-карточке (§4.1).
#[derive(Debug, Clone)]
pub struct SelfAddresses {
    /// Onion-адрес этого устройства (§5.2).
    pub onion: String,
    /// Chatmail-адрес (§5.3).
    pub chatmail: String,
    /// Отображаемое имя. Получателем не доверяется (§4.1).
    pub display_name: String,
}

/// Что ядро знает о контакте.
#[derive(Debug, Clone)]
pub struct Contact {
    /// Карточка с адресами.
    pub card: ContactCard,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Что известно о доступности прямо сейчас (§5.4).
    pub availability: PeerAvailability,
    /// Как его подписал у себя пользователь. По проводу не едет никогда.
    pub local_name: Option<String>,
    /// Лежит ли в хранилище его аватарка.
    ///
    /// Признак держится в памяти, а сами байты — нет: список контактов
    /// читается на каждый показ чатов, и расшифровывать по тридцать
    /// килобайт на контакт ради «есть ли картинка» незачем.
    ///
    /// **Это не «показывать ли её»:** аватарка несверенного контакта
    /// хранится, но наружу не отдаётся (§4.2). Решает это
    /// [`Engine::avatar_of`], и только оно.
    pub has_avatar: bool,
}

/// Почему попытка доставки не удалась.
///
/// Различие не косметическое: от него зависит, жива ли сессия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// Транспорт сказал прямо: соединиться не удалось или связь оборвалась.
    ///
    /// Про сессию это не говорит ничего. Собеседник мог уйти из сети на
    /// минуту; его состояние ретчета при этом никуда не делось, и наше тоже.
    Reported,
    /// Кадр ушёл, а квитанции в срок не пришло.
    ///
    /// Вот это уже подозрение на сессию. Запись в сокет удалась, то есть байты
    /// куда-то уехали, — а подтверждения нет. Одна из причин: у собеседника
    /// нашей сессии больше нет (переустановил клиент, потерял базу, закрыл её
    /// прежней сборкой), и наши кадры он отбрасывает как неизвестные (§7.3).
    /// Сам он об этом сказать не может: расшифровать нечем, а верить кадру
    /// «я тебя не знаю» без подписи нельзя.
    ///
    /// Поэтому сессия закрывается, и следующая попытка идёт через новое
    /// рукопожатие — оно аутентифицировано (§8.2), в отличие от любого намёка.
    Silent,
}

/// Что сейчас с сообщением на пути к получателю (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryState {
    /// Сессии ещё нет: рукопожатие в пути, сообщение ждёт его завершения.
    AwaitingSession,
    /// Ушло прямым каналом. Ждём квитанции, отказа или истечения срока.
    ///
    /// Прямой канал подтверждает доставку квитанцией за миллисекунды (§9.4),
    /// поэтому истёкший срок означает здесь **не** «отправлено», а «не вышло»:
    /// попытка переходит к следующему транспорту по §5.4. Запись уходит
    /// из очереди либо по подтверждению, либо когда транспорты кончились.
    InFlight { via: Transport, timer: u64 },
    /// LAN включён, но собеседника в эфире ещё не слышали — ждём обнаружение.
    ///
    /// Это **не** ступень §5.4: транспорт здесь не тратится. «Мы ещё не
    /// искали» и «мы искали и не нашли» — разные вещи, и путать их дорого.
    /// Сразу после запуска не слышали никого: `seen_on_lan` не поднимается
    /// с диска (адрес в локальной сети живёт ровно столько, сколько сеанс),
    /// а mDNS отвечает через сотни миллисекунд. Первое сообщение после
    /// перезапуска попадало ровно в эту щель и объявлялось недоставленным
    /// за долю секунды до того, как собеседник находился.
    AwaitingDiscovery { timer: u64 },
}

/// Незавершённое исходящее рукопожатие вместе с его попыткой доставки.
///
/// Первое сообщение — такой же кадр, как любой другой, и теряется так же.
/// Без собственной попытки по §5.4 получалась бы тупиковая связка: данные
/// переходят на почту, а рукопожатие, без которого они не поедут, осталось
/// в упавшем onion.
struct OutgoingHandshake {
    state: PendingHandshake,
    /// Готовый кадр первого сообщения — чтобы переслать его другим
    /// транспортом, не начиная рукопожатие заново.
    frame: Vec<u8>,
    attempt: Attempt,
    peer_ik: [u8; 32],
    /// Метка таймера текущей попытки, если транспорт прямой.
    ///
    /// Без неё молча проглоченное рукопожатие не переходит на следующий
    /// транспорт: об отказе никто не сообщает, а ждать больше нечего.
    timer: Option<u64>,
}

/// Сообщение в очереди доставки.
#[derive(Debug, Clone)]
struct Delivery {
    msg_id: MsgId,
    peer_ik: [u8; 32],
    /// Конверт хранится целиком: при переходе на другой транспорт кадр
    /// запечатывается заново, следующим ключом цепочки. Копия получится
    /// с тем же `msg_id`, и если обе дойдут, лишнюю съест дедупликация (§9.2).
    envelope: Vec<u8>,
    attempt: Attempt,
    state: DeliveryState,
    /// Когда человек нажал «отправить».
    ///
    /// Не то же, что метка порядка (§9.1): та задаёт место в чате, а это —
    /// место в очереди ожидающих. Порядок отправки после долгого офлайна
    /// обязан совпадать с порядком, в котором человек писал.
    queued_ms: u64,
    /// Пробовали ли уже переустановить сессию из-за молчания.
    ///
    /// Ровно один раз на сообщение. Без ограничения два узла с расходящимся
    /// состоянием гоняли бы рукопожатия по кругу вместо того, чтобы честно
    /// объявить неудачу.
    session_reset_used: bool,
}

/// Состояние ядра.
///
/// Обобщено по хранилищу, чтобы симуляция (§16) подставляла [`ratatosk_store::MemoryStore`],
/// а продукт — SQLite. Ни один сценарий не должен требовать правки
/// протокольного кода ради подмены хранилища.
pub struct Engine<S: Store> {
    identity: Identity,
    addresses: SelfAddresses,
    store: S,
    entropy: Box<dyn Entropy>,
    clock: HlcClock,
    sessions: SessionRegistry,
    dedup: DedupWindow,
    reassembler: Reassembler,
    handshake_guard: HandshakeReplayGuard,
    rekey: RekeyPolicy,
    contacts: BTreeMap<[u8; 32], Contact>,
    by_chat: BTreeMap<ChatId, [u8; 32]>,
    pending: Vec<OutgoingHandshake>,
    outbox: Vec<Delivery>,
    next_timer_token: u64,
    /// §5.1: по умолчанию выключен. Хранится отдельно от контактов, потому
    /// что состояние переключателя существует и когда контактов ещё нет.
    lan_enabled: bool,
    /// Кого заметили в LAN раньше, чем добавили в контакты.
    seen_on_lan: BTreeSet<[u8; 32]>,
    /// Сообщения, которым некуда было ехать. Ждут случая (§5.4).
    ///
    /// Не то же самое, что очередь: попытка по ним уже закончена и статус
    /// объявлен. Это память о том, что человек хотел отправить, а сети
    /// не было, — чтобы вернуться к этому, когда сеть появится.
    deferred: Vec<Delivery>,
    /// Кому уже давали срок на обнаружение в этом сеансе.
    ///
    /// Ожидание выдаётся **один раз на контакт**, а не на каждое сообщение:
    /// собеседнику, которого в этой сети нет, иначе платили бы задержкой
    /// перед каждой отправкой. Сбрасывается при смене сети и при включении
    /// LAN — то есть тогда, когда прежний ответ «не слышно» устарел.
    awaited_discovery: BTreeSet<[u8; 32]>,
    /// До какого места в каждом чате уже отправлена квитанция о прочтении.
    read_upto: BTreeMap<ChatId, Hlc>,
    /// Байты файлов — вне SQLite (§10, §12).
    blobs: Box<dyn Blobs>,
    /// Порог автоматического приёма файлов. `None` — спрашивать всегда.
    auto_accept: Option<u64>,
    /// Идущие **исходящие** передачи.
    ///
    /// Только в памяти, и это не упущение: всё, что нужно для возобновления,
    /// знает получатель (какие чанки у него есть) и хранит у себя. Отправителю
    /// достаточно исходного файла на диске и просьбы «продолжай с такого-то» —
    /// поэтому после перезапуска ему нечего восстанавливать, он ждёт вопроса.
    sending: Vec<Sending>,
    /// Взведённый срок молчания по каждому файлу: файл → метка.
    ///
    /// Ключ — **файл**, а не метка, и это исправление настоящей поломки.
    /// Раньше метки копились: каждый принятый чанк заводил свою, ни одна
    /// не снималась, и на длинном файле десяток сроков выходил вразнобой.
    /// Каждый выход — новая просьба, каждая просьба — новые чанки, и передача
    /// разгоняла сама себя, пока очередь кадров к собеседнику не забивалась
    /// мебибайтами. Теперь у файла ровно один живой срок; сработавшая метка,
    /// которой здесь больше нет, — опоздавшая, и её игнорируют.
    file_timers: BTreeMap<FileId, u64>,
    /// Сколько сообщений легло в историю с прошлой уборки (§12).
    ///
    /// В памяти, а не на диске, и это не забывчивость: счётчик — способ
    /// не запускать уборку слишком часто, а перезапуск и так повод пройтись.
    /// Момент прошлой уборки, наоборот, переживает перезапуск
    /// ([`META_LAST_COMPACTION`]) — иначе шестичасовой интервал не наступал бы
    /// никогда у того, кто перезапускает телефон чаще.
    ///
    /// [`META_LAST_COMPACTION`]: ratatosk_store::META_LAST_COMPACTION
    messages_since_compaction: u64,
    /// Правила уборки (§12).
    schedule: Schedule,
    /// Своя карточка в том виде, в каком её последний раз объявили (§4.3).
    ///
    /// `None` — не объявляли ни разу, и карточка остаётся первой версии.
    /// Хранится целиком, а не одной версией: без прежних адресов первое же
    /// объявление после перезапуска выглядело бы изменением, и §4.3 стал бы
    /// рассылкой на каждый старт процесса.
    announced: Option<ContactCard>,
    /// Кому текущая версия карточки уже досылалась в этом запуске (§4.3).
    ///
    /// В памяти, а не на диске, и это не забывчивость. На диске лежало бы
    /// «мы отправили», а нужно «он получил», — а этого мы не знаем: квитанции
    /// на `CardUpdate` протокол не предусматривает. Поэтому цена ошибки
    /// выбрана в сторону лишнего кадра: после перезапуска каждый контакт
    /// получит объявление ещё раз (двести байт при первом же рукопожатии),
    /// зато адрес не потеряется молча.
    ///
    /// Обнуляется при смене карточки: прежние отправки к новой версии
    /// отношения не имеют.
    card_pushed: BTreeSet<[u8; 32]>,
}

impl<S: Store> Engine<S> {
    /// Собирает ядро.
    pub fn new(
        identity: Identity,
        store: S,
        blobs: Box<dyn Blobs>,
        entropy: Box<dyn Entropy>,
        addresses: SelfAddresses,
    ) -> Engine<S> {
        Engine {
            identity,
            addresses,
            store,
            entropy,
            clock: HlcClock::new(),
            sessions: SessionRegistry::new(),
            dedup: DedupWindow::default(),
            reassembler: Reassembler::new(),
            handshake_guard: HandshakeReplayGuard::default(),
            rekey: RekeyPolicy::default(),
            contacts: BTreeMap::new(),
            by_chat: BTreeMap::new(),
            pending: Vec::new(),
            outbox: Vec::new(),
            next_timer_token: 1,
            lan_enabled: false,
            seen_on_lan: BTreeSet::new(),
            deferred: Vec::new(),
            awaited_discovery: BTreeSet::new(),
            read_upto: BTreeMap::new(),
            blobs,
            auto_accept: Some(ratatosk_proto::files::DEFAULT_AUTO_ACCEPT_BYTES),
            sending: Vec::new(),
            file_timers: BTreeMap::new(),
            messages_since_compaction: 0,
            schedule: Schedule::default(),
            announced: None,
            card_pushed: BTreeSet::new(),
        }
    }

    /// Идентификатор чата 1:1 с этим контактом.
    ///
    /// Первые 16 байт `IK` собеседника. Годится, потому что обе стороны
    /// вычисляют его из одного и того же значения без всякой договорённости,
    /// и потому что `IK` уникален по построению. Для групп идентификатор
    /// будет свой (§11), и это уже другая ветка.
    #[must_use]
    pub fn chat_id_for(peer_ik: &[u8; 32]) -> ChatId {
        peer_ik[..16].try_into().expect("срез длины 16")
    }

    /// Отпечаток собственной идентичности (§3).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Своя контакт-карточка — для QR и ссылок (§4.1).
    #[must_use]
    pub fn own_card(&self) -> ContactCard {
        ContactCard {
            ik: self.identity.public().ik,
            sk: self.identity.public().sk,
            onion: self.addresses.onion.clone(),
            chatmail: self.addresses.chatmail.clone(),
            display_name: self.addresses.display_name.clone(),
            version: self.announced.as_ref().map_or(1, |card| card.version),
        }
    }

    /// Известные контакты.
    #[must_use]
    pub fn contacts(&self) -> &BTreeMap<[u8; 32], Contact> {
        &self.contacts
    }

    /// Хранилище — для миграций, чтения и обслуживания.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Хранилище на чтение.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Сколько сообщений сейчас в очереди доставки (§5.4).
    #[must_use]
    pub fn queued(&self) -> usize {
        self.outbox.len()
    }

    /// Сколько сообщений ждёт установления сессии.
    #[must_use]
    pub fn awaiting_session(&self) -> usize {
        self.outbox.iter().filter(|d| d.state == DeliveryState::AwaitingSession).count()
    }

    /// Обрабатывает один вход и возвращает эффекты.
    ///
    /// Единственный метод, меняющий состояние. Одна и та же последовательность
    /// входов при одном и том же начальном состоянии даёт одну и ту же
    /// последовательность эффектов — на этом держится §16.
    pub fn step(&mut self, now_ms: u64, input: Input) -> Result<Vec<Effect>, EngineError> {
        match input {
            Input::Command(command) => self.on_command(now_ms, command),
            Input::Received { via, frame } => self.on_frame(now_ms, via, &frame),
            Input::SeenOnLan { peer_ik } => {
                // mDNS повторяет объявления, поэтому важен именно **переход**
                // «не видели → видим»: на каждом повторе перебирать очередь
                // незачем, а на первом — необходимо.
                let appeared = match self.contacts.get(&peer_ik) {
                    Some(contact) => !contact.availability.seen_on_lan,
                    None => false,
                };
                match self.contacts.get_mut(&peer_ik) {
                    Some(contact) => contact.availability.seen_on_lan = true,
                    // Контакт и его видимость приходят разными путями —
                    // командой от UI и событием транспорта, — и порядок между
                    // ними не гарантирован. Потерять отметку значило бы
                    // отправить почтой сообщение собеседнику за стенкой,
                    // и разбираться потом, почему.
                    None => {
                        self.seen_on_lan.insert(peer_ik);
                        return Ok(Vec::new());
                    }
                }
                // Собеседник нашёлся — всё, что ждало этого ответа, едет
                // немедленно, не досиживая свой срок.
                let mut effects = self.resume_discovery(peer_ik)?;
                if appeared {
                    // И то, что не уехало раньше: он снова в сети.
                    effects.extend(self.retry_deferred(Some(peer_ik))?);
                    // Недокачанные файлы спрашиваются здесь же — но только
                    // если сессия уже есть: просьба без прямого канала уйдёт
                    // в никуда, а рукопожатие позовёт нас ещё раз.
                    effects.extend(self.resume_files(now_ms, peer_ik)?);
                }
                Ok(effects)
            }
            Input::Connected { .. } => Ok(Vec::new()),
            // Разрыв соединения — это событие **сокета**, а не сессии, и
            // путать их оказалось дорого. Раньше здесь закрывалась LAN-сессия:
            // читалось это как §5.4 («сессия, начатая в LAN, через onion
            // не продолжается»), но §5.4 запрещает совсем другое — переносить
            // сессию в чужое семейство транспортов, и за этим следит
            // `SessionBinding`.
            //
            // Чем это обходилось: одна неудачная запись в сокет или смена
            // сети убивала сессию **у нас**, а у собеседника она оставалась.
            // Дальше он отправлял кадры в сессию, которой у нас больше нет,
            // мы их молча отбрасывали (§7.3), квитанции он не получал — и
            // видел «не доставлено» при живой связи и «онлайн» на экране.
            // Помогало только удалить и добавить контакт заново: тогда обе
            // стороны начинали с чистого рукопожатия.
            //
            // Сессия переживает разрыв TCP. Закрывает её теперь только
            // молчание в ответ на отправленный кадр — см. [`Failure`].
            Input::ConnectionLost { peer_ik, via } => {
                self.on_delivery_failed(peer_ik, via, Failure::Reported)
            }
            // TODO(этап 1): перерукопожатие (§8.5) и расписание уборки (§12)
            // тоже придут таймерами — пока их ставит только доставка.
            Input::Timer { token } => self.on_timer(now_ms, token),
        }
    }

    /// Ближайший момент, когда ядру нужно проснуться.
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<u64> {
        // TODO(этап 1): минимум из таймаутов доставки (§5.4), срока
        // перерукопожатия (§8.5) и расписания уборки (§12).
        None
    }

    // --- команды ------------------------------------------------------------

    fn on_command(&mut self, now_ms: u64, command: Command) -> Result<Vec<Effect>, EngineError> {
        match command {
            Command::AddContact { card_bytes, met_in_person } => {
                // Разбор дважды — здесь и внутри — нарочно: `add_contact`
                // зовут ещё из трёх мест, и возвращать оттуда ключ ради
                // одного вызывающего значит усложнить три ветки вместо одной.
                let peer_ik = ContactCard::decode(&card_bytes)?.value().ik;
                let mut effects = self.add_contact(now_ms, &card_bytes, met_in_person)?;
                // Ссылку могли скопировать до того, как поднялся onion:
                // тогда в ней пустой адрес, и без досылки собеседник узнает
                // наш только случайно (§4.3).
                effects.extend(self.push_own_card(now_ms, peer_ik)?);
                Ok(effects)
            }
            Command::MarkVerified { peer_ik } => {
                self.contacts.get_mut(&peer_ik).ok_or(EngineError::UnknownPeer)?.verified = true;
                // Сверка голосом (§4.2) — разовое действие пользователя.
                // Не пережив перезапуск, она обесценивается: просить сверять
                // отпечаток заново при каждом старте никто не станет.
                self.persist_contact(&peer_ik, now_ms)?;
                // До сверки аватарку ему не отправляли — теперь можно.
                // Два события у пользователя сливаются в одно: сверили —
                // и лица появились с обеих сторон.
                let mut effects = Vec::new();
                if let Some(via) = self.direct_channel(&peer_ik) {
                    effects.extend(self.offer_avatar(now_ms, peer_ik, via)?);
                }
                Ok(effects)
            }
            Command::SendText { chat, text } => self.send_text(now_ms, chat, &text),
            Command::RevokeVerification { peer_ik } => {
                let contact = self.contacts.get_mut(&peer_ik).ok_or(EngineError::UnknownPeer)?;
                contact.verified = false;
                self.persist_contact(&peer_ik, now_ms)?;
                // Собеседнику не уходит ничего. Отзыв — решение пользователя
                // о том, кому он доверяет, а не сообщение о человеке; уведомив
                // о нём, мы завели бы сигнал, которого он не просил подавать.
                //
                // Аватарка с этого момента ему не отправляется и его не
                // показывается — оба конца §4.2 читают тот же самый признак,
                // поэтому отдельно ничего делать не надо. Байты его аватарки
                // остаются лежать: сверят заново — покажется снова.
                Ok(vec![Effect::Notify(Event::ContactChanged { peer_ik })])
            }
            Command::SetLocalName { peer_ik, name } => {
                self.on_set_local_name(now_ms, peer_ik, name)
            }
            Command::DeleteContact { peer_ik, purge_history } => {
                self.on_delete_contact(peer_ik, purge_history)
            }
            Command::DeleteMessages { chat, msg_ids } => {
                Ok(self.forget_messages(now_ms, chat, &msg_ids))
            }
            Command::RetractMessages { chat, msg_ids } => {
                self.on_retract_messages(now_ms, chat, &msg_ids)
            }
            Command::SendReply { chat, reply_to, text } => {
                self.on_send_reply(now_ms, chat, reply_to, &text)
            }
            Command::EditMessage { chat, msg_id, text } => {
                self.on_edit_message(now_ms, chat, msg_id, &text)
            }
            Command::ForwardMessages { chat, msg_ids } => {
                self.on_forward_messages(now_ms, chat, &msg_ids)
            }
            Command::SetReaction { chat, msg_id, emoji } => {
                self.on_set_reaction(now_ms, chat, msg_id, &emoji)
            }
            Command::ClearChat { chat } => self.on_clear_chat(now_ms, chat),
            Command::SetAvatar(bytes) => self.on_set_avatar(now_ms, &bytes),
            Command::SetLanEnabled(on) => {
                self.lan_enabled = on;
                for contact in self.contacts.values_mut() {
                    contact.availability.lan_enabled = on;
                }
                // Прежние «не слышно» устарели: эфир только что открылся,
                // и каждому контакту снова полагается срок на обнаружение.
                self.awaited_discovery.clear();
                let mut effects = vec![Effect::SetLanEnabled(on)];
                if on {
                    effects.push(self.watch_lan_peers());
                    // Локальная сеть только что появилась как возможность —
                    // значит у отложенных сообщений появился шанс. Это же
                    // и путь после перезапуска: клиент включает LAN при
                    // старте, и очередь с диска приходит в движение.
                    effects.extend(self.retry_deferred(None)?);
                }
                Ok(effects)
            }
            Command::NetworkChanged => self.on_network_changed(),
            Command::SendFiles { chat, files, text } => {
                self.on_send_files(now_ms, chat, &files, &text)
            }
            Command::AcceptFile { file_id } => self.on_accept_file(now_ms, file_id),
            Command::DeclineFile { file_id } => self.on_decline_file(file_id),
            Command::AnnounceAddresses { onion, chatmail } => {
                self.on_announce_addresses(now_ms, onion, chatmail)
            }
            Command::ShareContact { chat, peer_ik } => self.on_share_contact(now_ms, chat, peer_ik),
            Command::AddSharedContact { msg_id } => self.on_add_shared_contact(now_ms, msg_id),
            Command::SetAutoAcceptBytes(limit) => {
                self.auto_accept = limit;
                // Настройка обязана пережить перезапуск: иначе назавтра
                // телефон снова начнёт принимать всё подряд.
                let value = limit.map_or_else(Vec::new, |bytes| bytes.to_be_bytes().to_vec());
                self.store.put_meta(ratatosk_store::META_AUTO_ACCEPT, &value)?;
                Ok(Vec::new())
            }
            Command::CreateGroup { .. }
            | Command::InviteToGroup { .. }
            | Command::EvictFromGroup { .. } => todo!("этап 5: группы (§11)"),
            Command::MarkRead { chat, up_to } => self.on_mark_read(now_ms, chat, up_to),
        }
    }

    /// Поднимает состояние с диска после перезапуска.
    ///
    /// Отдельно от [`Engine::new`], а не внутри неё, по двум причинам: `new`
    /// остаётся не могущей отказать, и симуляция (§16) продолжает собирать
    /// ядро без единого обращения к хранилищу.
    ///
    /// Сессии здесь **не** восстанавливаются. Ключевой материал ретчета пришлось
    /// бы сериализовать вместе с кэшем пропущенных ключей, а выигрыш невелик:
    /// без сессии первая же отправка проводит рукопожатие заново, и в локальной
    /// сети это миллисекунды. Плата за это записана в §8.5 — новая сессия
    /// означает и новый forward secrecy, а не потерю переписки.
    /// Возвращает число поднятых контактов.
    ///
    /// Эффектов здесь нет намеренно: `restore` вызывается до того, как
    /// появился драйвер, и вернуть их было бы некуда. Список маяков для
    /// транспорта (§5.1) выставит `Command::SetLanEnabled`, который клиент
    /// подаёт в любом случае — а при выключенном LAN он и не нужен.
    pub fn restore(&mut self) -> Result<usize, EngineError> {
        let stored = self.store.contacts()?;
        let restored = stored.len();
        for contact in stored {
            let card = ContactCard::decode(&contact.card_bytes)?.into_parts().1;
            let peer_ik = card.ik;
            let availability = PeerAvailability {
                has_onion: !card.onion.is_empty(),
                has_chatmail: !card.chatmail.is_empty(),
                lan_enabled: self.lan_enabled,
                // Видимость в LAN живёт ровно столько, сколько работает
                // устройство: адрес в локальной сети меняется при каждом
                // подключении, и поднимать его с диска значило бы врать.
                seen_on_lan: false,
            };
            let chat = Self::chat_id_for(&peer_ik);
            self.contacts.insert(
                peer_ik,
                Contact {
                    card,
                    verified: contact.verified,
                    availability,
                    local_name: contact.local_name,
                    has_avatar: self.store.has_avatar(&peer_ik)?,
                },
            );
            self.by_chat.insert(chat, peer_ik);

            // Водяной знак прочтения (§9.4). Без него первое же открытие чата
            // после перезапуска выпускало бы квитанцию о том, что собеседнику
            // уже сообщили, — то есть квитанция становилась следствием старта
            // приложения, а не действия человека.
            if let Some(edge) = self.load_read_upto(chat)? {
                self.read_upto.insert(chat, edge);
            }
        }

        // Очередь ожидающих — то, ради чего статус «отправим, когда появится»
        // вообще имеет право существовать. Без неё обещание жило бы только
        // до конца процесса, а на Android процесс убивают постоянно: человек
        // видел бы «ждём» у сообщения, к которому никто уже не вернётся.
        //
        // К отправке это состояние не приводит: ядро тронет очередь, когда
        // клиент включит LAN, сменится сеть или объявится собеседник.
        for waiting in self.store.outbox()? {
            // Контакт мог быть удалён между запусками — тогда ехать некому.
            if !self.contacts.contains_key(&waiting.recipient_ik) {
                self.store.delete_outbox(&waiting.msg_id)?;
                continue;
            }
            self.deferred.push(Delivery {
                msg_id: waiting.msg_id,
                peer_ik: waiting.recipient_ik,
                envelope: waiting.envelope,
                attempt: Attempt::new(),
                state: DeliveryState::AwaitingSession,
                queued_ms: waiting.queued_ms,
                session_reset_used: false,
            });
        }

        // Порог автоприёма файлов (§10). Настройка человека, и переживать
        // перезапуск она обязана: иначе назавтра телефон снова начнёт
        // принимать всё подряд. Пустое значение означает «спрашивать всегда»
        // — это выбор, а не отсутствие настройки, поэтому и хранится он
        // отдельно от «ключа нет вовсе».
        // Своя карточка в том виде, в каком её объявляли (§4.3). Отсюда
        // берутся и версия, и адреса: без адресов первое же объявление после
        // старта выглядело бы изменением, а на телефоне стартов много.
        //
        // Имя из записи **не** восстанавливается: его задаёт клиент при
        // открытии, и человек мог переименоваться между запусками. Разойдись
        // они — следующее объявление это заметит и разошлёт новую карточку.
        //
        // Испорченная запись читается как отсутствующая: отказ открыть базу
        // из-за одной служебной строки хуже, чем карточка первой версии,
        // которую вылечит следующее объявление.
        if let Some(card) = self
            .store
            .meta(ratatosk_store::META_SELF_CARD)?
            .and_then(|raw| ContactCard::decode(&raw).ok().map(|decoded| decoded.into_parts().1))
        {
            self.addresses.onion.clone_from(&card.onion);
            self.addresses.chatmail.clone_from(&card.chatmail);
            self.announced = Some(card);
        }

        self.auto_accept = match self.store.meta(ratatosk_store::META_AUTO_ACCEPT)? {
            Some(raw) if raw.is_empty() => None,
            Some(raw) => <[u8; 8]>::try_from(raw.as_slice())
                .map(u64::from_be_bytes)
                .ok()
                .or(Some(ratatosk_proto::files::DEFAULT_AUTO_ACCEPT_BYTES)),
            None => Some(ratatosk_proto::files::DEFAULT_AUTO_ACCEPT_BYTES),
        };

        // Сессии поднимаются после контактов: внешний ключ в схеме связывает
        // их с `contacts`, и порядок здесь тот же, что и на записи.
        for stored in self.store.sessions()? {
            let session = Session::restore(&stored.snapshot)?;
            let binding = if stored.lan { SessionBinding::Lan } else { SessionBinding::Tor };
            // Вытесненные с диска тоже уходят: база могла накопить их прежней
            // сборкой, до того как реестр начал держать по одной на семейство.
            for stale in self.sessions.insert(session, binding) {
                self.store.delete_session(stale)?;
            }
        }
        Ok(restored)
    }

    /// Регистрирует новую сессию и убирает ту, которую она заменила.
    ///
    /// Прежняя уходит и из реестра, и с диска. Оставленная, она вернулась бы
    /// после перезапуска и снова начала бы участвовать в выборе `for_peer` —
    /// то есть ровно та поломка, от которой вытеснение и заведено.
    fn supersede(&mut self, session: Session, binding: SessionBinding) -> Result<(), EngineError> {
        for stale in self.sessions.insert(session, binding) {
            self.store.delete_session(stale)?;
        }
        Ok(())
    }

    /// Закрывает сессию с контактом — в памяти и на диске.
    ///
    /// Возвращает `true`, если было что закрывать.
    fn drop_session(&mut self, peer_ik: &[u8; 32], via: Transport) -> Result<bool, EngineError> {
        let Some(session_id) = self.sessions.for_peer(peer_ik, via) else {
            return Ok(false);
        };
        self.sessions.remove(session_id);
        self.store.delete_session(session_id)?;
        Ok(true)
    }

    /// Складывает состояние сессии на диск (§8.3, §12).
    ///
    /// **Вызывается до того, как кадр уйдёт в сеть.** Порядок здесь — не
    /// аккуратность, а корректность: счётчик отправки, откатившийся после
    /// того как система убила процесс, означает второй кадр с той же парой
    /// «ключ, nonce». Для XChaCha20-Poly1305 это не потеря сообщения,
    /// а раскрытие обоих.
    ///
    /// На приёме порядок обратный и это безопасно: если процесс умрёт между
    /// расшифровкой и записью, кадр после перезапуска расшифруется тем же
    /// ключом ещё раз, а дубль съест дедупликация (§9.2).
    fn persist_session(&mut self, session_id: u64) -> Result<(), EngineError> {
        let Some(bound) = self.sessions.get(session_id) else {
            return Ok(());
        };
        let stored = ratatosk_store::StoredSession {
            session_id,
            peer_ik: bound.session.peer_ik,
            lan: bound.binding == SessionBinding::Lan,
            snapshot: bound.session.export().to_vec(),
            established_ms: bound.session.established_ms,
        };
        self.store.put_session(&stored)?;
        Ok(())
    }

    /// Складывает контакт на диск (§4, §12).
    fn persist_contact(&mut self, peer_ik: &[u8; 32], now_ms: u64) -> Result<(), EngineError> {
        let Some(contact) = self.contacts.get(peer_ik) else {
            return Ok(());
        };
        // §6: подпись считается над принятыми байтами, поэтому карточка
        // сохраняется целиком и неизменной, а не пересобирается из полей.
        let card_bytes = contact.card.encode()?;
        let stored = ratatosk_store::StoredContact {
            ik: contact.card.ik,
            sk: contact.card.sk,
            onion: contact.card.onion.clone(),
            chatmail: contact.card.chatmail.clone(),
            display_name: contact.card.display_name.clone(),
            card_version: contact.card.version,
            card_bytes,
            verified: contact.verified,
            created_ms: now_ms,
            local_name: contact.local_name.clone(),
        };
        self.store.put_contact(&stored)?;
        Ok(())
    }

    fn add_contact(
        &mut self,
        now_ms: u64,
        card_bytes: &[u8],
        met_in_person: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let card = ContactCard::decode(card_bytes)?.into_parts().1;
        let peer_ik = card.ik;
        let fingerprint =
            ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk)?.fingerprint();

        let availability = PeerAvailability {
            has_onion: !card.onion.is_empty(),
            has_chatmail: !card.chatmail.is_empty(),
            ..PeerAvailability::default()
        };

        // §4.2: QR при личной встрече — канал доверенный по построению,
        // ссылка — нет, и контакт остаётся непроверенным до сверки голосом.
        // Новый контакт наследует текущее состояние LAN: иначе контакт,
        // добавленный после включения, остался бы с `lan_enabled = false`,
        // и §5.4 отправил бы его сообщения мимо локальной сети — молча,
        // потому что onion и почта тоже «работают».
        let availability = PeerAvailability {
            lan_enabled: self.lan_enabled,
            seen_on_lan: self.seen_on_lan.remove(&peer_ik),
            ..availability
        };

        // Аватарка могла приехать раньше карточки: контакт добавляют после
        // того, как сессия уже установлена и что-то по ней приходило.
        let has_avatar = self.store.has_avatar(&peer_ik)?;
        // Локальное имя переживает всё, кроме удаления контакта: карточка
        // может приехать заново (§4.3), а подпись пользователя — его, и
        // затирать её обновлением с той стороны нельзя.
        let local_name = self.contacts.get(&peer_ik).and_then(|c| c.local_name.clone());
        self.contacts.insert(
            peer_ik,
            Contact { card, verified: met_in_person, availability, local_name, has_avatar },
        );
        self.by_chat.insert(Self::chat_id_for(&peer_ik), peer_ik);
        self.persist_contact(&peer_ik, now_ms)?;

        let mut effects = vec![Effect::Notify(Event::ContactAdded {
            peer_ik,
            fingerprint,
            verified: met_in_person,
        })];
        // Маяк нового контакта транспорт ещё не ищет — список изменился.
        if self.lan_enabled {
            effects.push(self.watch_lan_peers());
        }
        Ok(effects)
    }

    /// Сеть сменилась: всё, что известно о локальной, устарело (§5.1).
    ///
    /// Видимость сбрасывается **до** переоткрытия транспорта, и порядок
    /// важен: пока `seen_on_lan` держится, §5.4 продолжает выбирать LAN
    /// и отправлять по адресам прежней сети. Сообщения при этом не теряются
    /// — они честно упрутся в отказ и уйдут дальше по §5.4, — но каждое
    /// заплатит таймаутом за то, что и так уже известно.
    ///
    /// Сессии не трогаем. Ключевой материал к сети не привязан: если оба
    /// устройства оказались в новой сети вместе, переписка продолжится без
    /// нового рукопожатия. Сессию, чьё соединение оборвалось, закроет
    /// `Input::ConnectionLost` своим чередом (§5.4).
    fn on_network_changed(&mut self) -> Result<Vec<Effect>, EngineError> {
        for contact in self.contacts.values_mut() {
            contact.availability.seen_on_lan = false;
        }
        self.seen_on_lan.clear();
        // Сеть другая — значит и ответ «здесь его не слышно» относился
        // к прежней. Срок на обнаружение выдаётся заново.
        self.awaited_discovery.clear();

        if !self.lan_enabled {
            // Выключенный LAN переоткрывать нечего, и объявляться незачем.
            return Ok(Vec::new());
        }
        // Сессии живут дальше: смена сети — событие сокетов, а не ретчета.
        // Собеседник, оставшийся в прежней сети, о переезде не знает, и
        // выбрасывать общее состояние из-за него значит ломать связь ровно
        // тогда, когда она вот-вот восстановится.
        let mut effects = vec![Effect::RestartLan, self.watch_lan_peers()];
        // Сеть появилась — самое время попробовать то, что не уехало.
        // Именно здесь, а не по таймеру: смена сети — единственное событие,
        // которое действительно меняет шансы у **всех** сразу.
        effects.extend(self.retry_deferred(None)?);
        Ok(effects)
    }

    /// Клиент сообщил, что пользователь прочитал чат до этого места (§9.4).
    ///
    /// **Единственный источник квитанции о прочтении.** Ни приём сообщения,
    /// ни открытие чата, ни запуск приложения её не порождают: ядро не знает
    /// и не может знать, что человек прочитал. Знает клиент — и говорит
    /// об этом вызовом. Из этого следует и то, что клиент, который квитанций
    /// о прочтении не хочет (или у которого они выключены настройкой), просто
    /// не зовёт эту команду; отдельного выключателя в ядре для этого не надо.
    ///
    /// Водяной знак — до какого места уже отправляли — **лежит на диске**.
    /// Раньше он жил в памяти, и это была ошибка ровно того же рода: после
    /// перезапуска первое же открытие чата выпускало квитанцию заново, то есть
    /// квитанция получалась следствием запуска приложения, а не действия
    /// человека. Одному собеседнику это выглядит как «он перечитывает нашу
    /// переписку» на пустом месте.
    fn on_mark_read(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        up_to: MsgId,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        let window = self.store.messages(&chat, MAX_RECEIPT_IDS, None)?;
        // Граница задаётся сообщением, а не временем: клиент знает, до какого
        // места дочитал пользователь, но не знает меток HLC.
        let Some(edge) = window.iter().find(|m| m.msg_id == up_to).map(|m| m.hlc) else {
            // Сообщение вне окна или уже вычищено уборкой (§12) — не ошибка.
            return Ok(Vec::new());
        };

        let watermark = self.read_upto.get(&chat).copied();
        let ids: Vec<MsgId> = window
            .iter()
            // Квитанция о прочтении — про **чужие** сообщения: своим она
            // ничего не сообщает.
            .filter(|m| m.sender_ik == peer_ik)
            .filter(|m| m.hlc <= edge && watermark.is_none_or(|seen| m.hlc > seen))
            .map(|m| m.msg_id)
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // Прямой канал, а не очередь §5.4: квитанция не начинает рукопожатие
        // и не уходит почтой. Но и не мимо §5.4 — какой из прямых каналов
        // сейчас годен, решает та же лестница, см. `direct_channel`.
        let Some(via) = self.direct_channel(&peer_ik) else {
            return Ok(Vec::new());
        };

        // Знак двигается вместе с отправкой, а не до неё: не ушло — значит
        // и отмечать нечего, иначе следующий вызов промолчит о сообщениях,
        // про которые собеседник так и не узнал.
        let effects = self.send_receipt(now_ms, peer_ik, via, Receipt::Read, &ids)?;
        if !effects.is_empty() {
            self.read_upto.insert(chat, edge);
            self.persist_read_upto(chat, edge)?;
        }
        Ok(effects)
    }

    /// Кладёт водяной знак прочтения на диск (§9.4).
    fn persist_read_upto(&mut self, chat: ChatId, edge: Hlc) -> Result<(), EngineError> {
        let mut value = [0u8; 12];
        value[..8].copy_from_slice(&edge.wall_ms.to_be_bytes());
        value[8..].copy_from_slice(&edge.logical.to_be_bytes());
        self.store.put_meta(&ratatosk_store::read_upto_key(&chat), &value)?;
        Ok(())
    }

    /// Читает водяной знак прочтения с диска.
    ///
    /// Испорченное значение трактуется как его отсутствие: цена ошибки —
    /// одна лишняя квитанция, а отказ открыть базу из-за двенадцати байт
    /// служебной метки был бы несоразмерен.
    fn load_read_upto(&self, chat: ChatId) -> Result<Option<Hlc>, EngineError> {
        let Some(raw) = self.store.meta(&ratatosk_store::read_upto_key(&chat))? else {
            return Ok(None);
        };
        let Ok(bytes): Result<[u8; 12], _> = raw.as_slice().try_into() else {
            return Ok(None);
        };
        let wall_ms = u64::from_be_bytes(bytes[..8].try_into().expect("восемь байт"));
        let logical = u32::from_be_bytes(bytes[8..].try_into().expect("четыре байта"));
        Ok(Some(Hlc::new(wall_ms, logical)))
    }

    // --- удаление сообщений -------------------------------------------------

    /// Убирает сообщения из своей истории. Ничего никуда не отправляет.
    ///
    /// Возвращает событие только про те, что действительно были: список
    /// приходит от клиента, и половина названного могла быть удалена
    /// секунду назад с другого экрана.
    fn forget_messages(&mut self, now_ms: u64, chat: ChatId, msg_ids: &[MsgId]) -> Vec<Effect> {
        let mut gone = Vec::new();
        for msg_id in msg_ids {
            // Удалённое не должно уехать. Сообщение могло ждать сети со
            // статусом «отправим, когда появится»; отправить его после того,
            // как человек его удалил, — худшее из возможных поведений.
            self.deferred.retain(|d| d.msg_id != *msg_id);
            self.outbox.retain(|d| d.msg_id != *msg_id);
            let _ = self.store.delete_outbox(msg_id);

            // Вложения уходят вместе с сообщением — и записи, и байты.
            // Каскад внешнего ключа тут не поможет: надгробие не удаляет
            // строку сообщения, а гигабайт чанков на диске пережил бы «удалить»
            // и лежал бы там, где человек уверен, что уже ничего нет.
            self.forget_files(msg_id);

            // Отказ хранилища на одном сообщении не повод бросить остальные:
            // пользователь просил убрать список, а не «список или ничего».
            if self.store.tombstone_message(msg_id, now_ms).unwrap_or(false) {
                gone.push(*msg_id);
            }
        }
        if gone.is_empty() {
            return Vec::new();
        }
        vec![Effect::Notify(Event::MessagesDeleted { chat, msg_ids: gone })]
    }

    /// Убирает вложения сообщения: записи, байты и идущие передачи.
    ///
    /// Отказы проглатываются намеренно: удаление не должно останавливаться
    /// на первом же файле, который не удалось стереть. Оставшийся чанк —
    /// мусор на диске, а незавершённое удаление — сообщение, которое человек
    /// считает удалённым.
    fn forget_files(&mut self, msg_id: &MsgId) {
        let files = self.store.files_of(msg_id).unwrap_or_default();
        for file in files {
            self.forget_file(&file.file_id);
        }
    }

    /// Убирает одно вложение: идущую передачу, срок молчания, байты и запись.
    ///
    /// Порядок значим ровно в одном месте: байты уходят раньше записи. Иначе
    /// запись исчезает первой, и чанки на диске остаются без всякого следа
    /// о том, чьи они, — подобрать их сможет только сверка каталога с базой
    /// ([`Engine::sweep_orphan_files`]).
    fn forget_file(&mut self, file_id: &FileId) {
        self.sending.retain(|s| s.file_id != *file_id);
        self.file_timers.remove(file_id);
        let _ = self.blobs.remove(file_id);
        let _ = self.store.delete_file(file_id);
    }

    /// Удаляет у себя и просит собеседника удалить у себя.
    ///
    /// Просьба уходит только про **свои** сообщения. Чужие удаляются локально
    /// и молча: попросить человека забыть его собственные слова — не то, что
    /// протокол должен уметь выражать, и получатель такую просьбу всё равно
    /// отвергнет (см. [`Engine::on_retract`]).
    ///
    /// Отзыв едет **обычной очередью доставки** (§5.4), а не отдельным
    /// быстрым каналом, как квитанция (§9.4). Квитанция, не дошедшая до
    /// собеседника, — мелочь; отзыв, не дошедший потому, что человек был
    /// офлайн, — ровно та неудача, ради которой всё и затевалось.
    fn on_retract_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        let own_ik = self.identity.public().ik;

        // Чьё сообщение — знает хранилище, а не клиент: он мог прислать
        // и чужой идентификатор, и вовсе выдуманный.
        let mut ours = Vec::new();
        for msg_id in msg_ids.iter().take(ratatosk_proto::MAX_RETRACT_IDS) {
            if self.store.message(msg_id)?.is_some_and(|m| m.sender_ik == own_ik) {
                ours.push(*msg_id);
            }
        }

        let mut effects = self.forget_messages(now_ms, chat, msg_ids);
        if ours.is_empty() {
            return Ok(effects);
        }

        effects.extend(self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Retract,
            ratatosk_proto::retract::payload(&ours),
        )?);
        Ok(effects)
    }

    /// Очищает чат у себя.
    fn on_clear_chat(&mut self, now_ms: u64, chat: ChatId) -> Result<Vec<Effect>, EngineError> {
        // Идентификаторы собираются до уборки: событие обязано сказать UI,
        // что именно исчезло, а после надгробий история уже пуста.
        let doomed: Vec<MsgId> =
            self.store.messages(&chat, usize::MAX, None)?.into_iter().map(|m| m.msg_id).collect();
        if self.store.tombstone_chat(&chat, now_ms)? == 0 {
            return Ok(Vec::new());
        }
        // Ничего из очищенного не должно уехать позже — и ничего не должно
        // остаться на диске.
        for msg_id in &doomed {
            self.forget_files(msg_id);
            self.deferred.retain(|d| d.msg_id != *msg_id);
            self.outbox.retain(|d| d.msg_id != *msg_id);
            self.store.delete_outbox(msg_id)?;
        }
        // Водяной знак прочтения теряет смысл вместе с историей: сообщений,
        // про которые уже отправляли квитанцию, больше нет.
        self.read_upto.remove(&chat);
        Ok(vec![Effect::Notify(Event::MessagesDeleted { chat, msg_ids: doomed })])
    }

    /// Пришла просьба удалить сообщения.
    ///
    /// **Отозвать можно только своё.** Проверяет это получатель, а не
    /// отправитель: иначе достаточно прислать чужой идентификатор, чтобы
    /// стереть слова из чужой переписки. Стоит проверка одного сравнения
    /// `sender_ik`, а без неё «удалить у обоих» превращается в «удалить
    /// у кого угодно что угодно».
    ///
    /// Просьба про сообщение, которого нет, — не ошибка: копия могла быть
    /// удалена раньше или не дойти вовсе.
    fn on_retract(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let msg_ids = ratatosk_proto::retract::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let mut gone = Vec::new();
        for msg_id in &msg_ids {
            let Some(message) = self.store.message(msg_id)? else { continue };
            if message.sender_ik != peer_ik || message.chat_id != chat {
                // Просьба про чужое. Это не «формат не тот», а попытка
                // распорядиться не своим, поэтому она считается аномалией
                // сессии, а не молча пропускается.
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                continue;
            }
            if self.store.tombstone_message(msg_id, now_ms)? {
                gone.push(*msg_id);
            }
        }

        // Квитанция — как на текст (§9.4), и по той же причине: отзыв едет
        // очередью §5.4, а запись в очереди закрывается подтверждением.
        // Без него страховочный срок прямого канала объявил бы неудачу
        // и послал бы ту же просьбу ещё раз, уже почтой.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;
        if !gone.is_empty() {
            effects.push(Effect::Notify(Event::MessagesDeleted { chat, msg_ids: gone }));
        }
        Ok(effects)
    }

    // --- файлы (§10) --------------------------------------------------------

    /// Отправляет файлы одним сообщением.
    ///
    /// Что происходит сразу: сообщение ложится в историю (с подписью, если она
    /// есть), для каждого файла заводится запись и уезжает **предложение** —
    /// имя, размер, ключ и превью. Байты не читаются вовсе: чанки пойдут
    /// потом, и только если получатель их попросит.
    ///
    /// Ключ у каждого файла свой и генерируется здесь. Это не мелочь:
    /// `ratatosk_crypto::file` шифрует чанк ключом, выведенным из
    /// `file_key ‖ index`, с нулевым nonce — и это безопасно ровно до тех пор,
    /// пока один и тот же `file_key` не использован дважды для разного
    /// содержимого. Повторная отправка того же файла — это новое предложение
    /// с новым ключом.
    fn on_send_files(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        files: &[OutgoingFile],
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        if files.is_empty() || files.len() > files::MAX_FILES_PER_MESSAGE {
            return Err(files::FileError::TooMany.into());
        }

        let msg_id = self.entropy.msg_id();
        let hlc = self.clock.now(now_ms)?;
        let own_ik = self.identity.public().ik;

        // Сперва собираем предложение целиком — и только потом пишем в базу.
        // Отказ на третьем файле не должен оставлять в истории сообщение
        // с двумя вложениями, которых никто не просил.
        let mut offers = Vec::with_capacity(files.len());
        let mut records = Vec::with_capacity(files.len());
        for file in files {
            let size_bytes = self.blobs.size_of(&file.path)?;
            if size_bytes > files::MAX_FILE_BYTES {
                return Err(files::FileError::TooLarge.into());
            }
            let name = file
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(files::FileError::BadName)?
                .to_owned();
            files::check_name(&name)?;
            if let Some(preview) = &file.preview {
                if !files::preview_fits(preview.len()) {
                    return Err(files::FileError::PreviewTooLarge.into());
                }
            }

            let file_id = self.entropy.msg_id();
            let mut key = [0u8; 32];
            self.entropy.fill(&mut key);

            offers.push(files::FileOffer {
                file_id,
                name: name.clone(),
                size_bytes,
                key,
                preview: file.preview.clone(),
            });
            records.push(StoredFile {
                file_id,
                msg_id,
                name,
                size_bytes,
                chunk_total: files::chunk_count(size_bytes),
                key,
                preview: file.preview.clone(),
                incoming: false,
                // Путь, а не байты: копировать файл ради отправки значит
                // требовать вдвое больше места, чем у него есть.
                source_path: Some(file.path.to_string_lossy().into_owned()),
                // Своё отправляем, ничего не спрашивая.
                accepted: true,
                complete: true,
            });
        }
        files::check_offers(&offers).map_err(EngineError::File)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: own_ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        for record in &records {
            self.store.put_file(record)?;
        }

        let envelope =
            Envelope::new(msg_id, hlc, PayloadType::FileOffer, files::offer_payload(text, &offers));
        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
        })
    }

    /// Поделиться контактом: отправить в чат карточку известного человека.
    ///
    /// Своей карточкой — можно, и это та же операция: `peer_ik` совпадает
    /// с собственным `IK`, карточка берётся своя. Отдельного механизма
    /// «передать визитку» заводить незачем.
    ///
    /// Что **не** едет: локальное имя, которым пользователь подписал человека
    /// у себя (§4.1 — «по проводу не едет никогда»: это заметка о своём
    /// отношении, а не свойство контакта), и признак сверки — присланный
    /// контакт непроверен всегда.
    fn on_share_contact(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let own_ik = self.identity.public().ik;
        let card_bytes = if peer_ik == own_ik {
            self.own_card().encode()?
        } else {
            let contact = self.contacts.get(&peer_ik).ok_or(EngineError::UnknownPeer)?;
            contact.card.encode()?
        };

        let Some(&recipient) = self.by_chat.get(&chat) else {
            return Err(EngineError::UnknownPeer);
        };
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();

        // Тело пустое: карточка лежит записью рядом, как вложение. Класть
        // её байты в текст значило бы показать человеку CBOR, если клиент
        // забудет про отдельное поле, — а §14 просит не показывать того,
        // чего человек не поймёт.
        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: own_ik,
            hlc,
            body: Vec::new(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        self.store.put_contact_share(&StoredContactShare {
            msg_id,
            ik: peer_ik,
            card_bytes: card_bytes.clone(),
        })?;

        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::ContactShare,
            ratatosk_proto::contact_share::payload(&card_bytes),
        );
        self.enqueue(Delivery {
            msg_id,
            peer_ik: recipient,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
        })
    }

    /// Адреса устройства изменились — сказать об этом контактам (§4.3).
    ///
    /// **Всем сразу, а не тому, кто спросит.** Устройство не знает, какую
    /// версию карточки помнит каждый: карточка расходится по QR, ссылкам
    /// и пересылкам, и обратной связи в этом канале нет. Обновление уходит
    /// каждому контакту отдельной доставкой, дальше §5.4 разбирается сам,
    /// а тем, кого сейчас нет в сети, оно ждёт в очереди наравне с текстом.
    ///
    /// **Тот же адрес — ничего не происходит.** Иначе каждый подъём Tor
    /// поднимал бы версию и рассылал обновление всем, а на телефоне подъём
    /// случается при каждом возвращении сети.
    ///
    /// Записью в истории не становится: адрес — свойство устройства,
    /// а не сообщение человеку. В чате показывать нечего.
    fn on_announce_addresses(
        &mut self,
        now_ms: u64,
        onion: String,
        chatmail: String,
    ) -> Result<Vec<Effect>, EngineError> {
        // Сравнивается с **объявленным**, а не с текущим состоянием в памяти:
        // после перезапуска адреса подняты с диска именно оттуда, и повтор
        // того же объявления обязан остаться бесплатным.
        //
        // Имя тоже участвует: карточка везёт его целиком, и человек,
        // переименовавшийся между запусками, иначе остался бы для контактов
        // под прежним именем навсегда.
        let unchanged = self.announced.as_ref().is_some_and(|last| {
            last.onion == onion
                && last.chatmail == chatmail
                && last.display_name == self.addresses.display_name
        });
        if unchanged {
            return Ok(Vec::new());
        }

        self.addresses.onion = onion;
        self.addresses.chatmail = chatmail;

        let version = self.announced.as_ref().map_or(1, |last| last.version) + 1;
        let card = ContactCard { version, ..self.own_card() };

        // Байты считаются один раз и служат трижды: их подписывают, их
        // отправляют, их же кладут на диск. §6 требует, чтобы проверяемое
        // проверялось над принятым представлением, и три разных вычисления
        // «того же самого» — способ однажды получить три разных ответа.
        let bytes = card.encode()?;
        let signature = self.identity.sign(&bytes);

        // Запись — до рассылки. Разослать и не сохранить значит после
        // перезапуска выдать ту же версию второй раз: у получателей она
        // уже не «строго больше», и следующая смена адреса до них не доедет.
        self.store.put_meta(ratatosk_store::META_SELF_CARD, &bytes)?;
        self.announced = Some(card);

        let payload = ratatosk_proto::card_update::payload(&bytes, &signature);
        let recipients: Vec<[u8; 32]> = self.contacts.keys().copied().collect();
        // Версия сменилась — значит всё, что досылалось раньше, относилось
        // к прежней карточке и больше ничего не значит.
        self.card_pushed.clear();
        let mut effects = Vec::new();
        for peer_ik in recipients {
            self.card_pushed.insert(peer_ik);
            effects.extend(self.enqueue_request(
                now_ms,
                peer_ik,
                PayloadType::CardUpdate,
                payload.clone(),
            )?);
        }
        Ok(effects)
    }

    /// Досылает свою карточку одному контакту (§4.3).
    ///
    /// Дыра, которую это закрывает, видна только на двух устройствах, и она
    /// не в протоколе, а в том, **когда** мы им пользуемся.
    /// [`Engine::on_announce_addresses`] рассылает обновление тем контактам,
    /// которые есть на момент объявления, — и на этом останавливается. Дальше
    /// возможны три случая, и во всех трёх собеседник остаётся без адреса:
    ///
    /// * контакт добавлен **после** объявления — рассылка его не застала;
    /// * ссылка на карточку скопирована до объявления — в ней пустой `onion`,
    ///   а повторное объявление того же адреса бесплатно (и потому молчит);
    /// * контакт добавлен заново после перезапуска — `announced` поднят
    ///   с диска, объявлять нечего, рассылки нет.
    ///
    /// Карточка едет и в первом сообщении рукопожатия (§8.2), но там она
    /// применяется, только если контакт ещё не заведён: менять адреса уже
    /// известного человека кадром без подписи нельзя. Значит, единственный
    /// путь для нового адреса — подписанный `CardUpdate`, и досылать его надо
    /// самим.
    ///
    /// Момент выбран самый ранний из возможных — установление сессии
    /// и добавление контакта: раньше кадр всё равно некуда деть.
    fn push_own_card(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        // Не объявляли ничего — и досылать нечего: у собеседника карточка
        // первой версии, ровно та же, что у нас.
        let Some(card) = self.announced.as_ref() else { return Ok(Vec::new()) };
        if !self.contacts.contains_key(&peer_ik) {
            return Ok(Vec::new());
        }
        // Второй раз одному и тому же в одном запуске — впустую: `Stale`
        // на той стороне (§4.3) и лишний кадр на этой.
        if !self.card_pushed.insert(peer_ik) {
            return Ok(Vec::new());
        }

        // Байты пересобираются, а не берутся с диска, и это то же самое:
        // CBOR детерминированный (§6), подпись Ed25519 — тоже.
        let bytes = card.encode()?;
        let signature = self.identity.sign(&bytes);
        let payload = ratatosk_proto::card_update::payload(&bytes, &signature);
        self.enqueue_request(now_ms, peer_ik, PayloadType::CardUpdate, payload)
    }

    /// Собеседник сменил адреса (§4.3).
    ///
    /// Проверки — в `ratatosk_proto::card_update`, и там же объяснено, почему
    /// их пять и почему именно в таком порядке. Здесь остаётся то, что нельзя
    /// проверить без состояния: обновление о неизвестном человеке применять
    /// некуда, и это не ошибка — контакт могли удалить, пока кадр ехал.
    ///
    /// **Сверка (§4.2) переживает обновление.** `IK` и `SK` не изменились —
    /// значит, отпечаток тот же, значит, сверять заново нечего. Сбрасывать
    /// признак при каждой смене адреса значило бы просить человека звонить
    /// собеседнику всякий раз, когда у того поднялся Tor, — и приучить его
    /// подтверждать не глядя.
    ///
    /// **Локальное имя тоже остаётся.** Это подпись пользователя о своём
    /// отношении, и обновление с той стороны её не касается.
    fn on_card_update(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(known) = self.contacts.get(&peer_ik) else { return Ok(Vec::new()) };

        let card =
            match ratatosk_proto::card_update::accept(&envelope.payload, &peer_ik, &known.card) {
                Ok(card) => card,
                // Повтор старого — обычное дело: обновление ушло всем сразу,
                // а пути у §5.4 разной длины. Тишина, а не счётчик аномалий.
                Err(ratatosk_proto::card_update::UpdateError::Stale) => return Ok(Vec::new()),
                Err(_) => {
                    self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
            };

        let Some(contact) = self.contacts.get_mut(&peer_ik) else { return Ok(Vec::new()) };
        contact.availability.has_onion = !card.onion.is_empty();
        contact.availability.has_chatmail = !card.chatmail.is_empty();
        contact.card = card;
        self.persist_contact(&peer_ik, now_ms)?;

        // Появившийся адрес — это появившийся путь. Сообщения, которым
        // некуда было ехать, ждали именно этого (§5.4).
        let mut effects = vec![Effect::Notify(Event::ContactChanged { peer_ik })];
        effects.extend(self.retry_deferred(Some(peer_ik))?);
        Ok(effects)
    }

    /// Пришла карточка третьего человека.
    ///
    /// Ложится в историю записью и **ничего не меняет**: ни контактов,
    /// ни адресов уже известного человека. Решение принимает пользователь
    /// ([`Command::AddSharedContact`]).
    fn on_contact_share(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Разбор здесь, а не при показе: испорченная карточка не должна
        // добираться до истории и ждать там нажатия, которое всё равно
        // ничем не кончится.
        let (card_bytes, card) = ratatosk_proto::contact_share::from_payload(&envelope.payload)
            .map_err(|e| {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                e
            })?;
        // Ключи обязаны складываться в отпечаток: карточка с мусором вместо
        // `SK` не добавится никогда, и держать её в истории незачем.
        if ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        let shared_ik = card.ik;
        let mut effects =
            self.on_incoming_text(now_ms, via, peer_ik, envelope, "", TextKind::Plain)?;
        // Запись — после сообщения: внешний ключ ведёт на него, и обратный
        // порядок был бы карточкой, приложенной к тому, чего ещё нет.
        // Если сообщение не легло (дубль, надгробие), карточке тем более
        // незачем ложиться.
        if self.store.message(&envelope.msg_id)?.is_some() {
            self.store.put_contact_share(&StoredContactShare {
                msg_id: envelope.msg_id,
                ik: shared_ik,
                card_bytes,
            })?;
        } else {
            effects.clear();
        }
        Ok(effects)
    }

    /// Человек решил добавить присланный контакт.
    ///
    /// **Всегда непроверенным.** Даже если тот, кто поделился, у нас сверен:
    /// §4.2 — про сверку отпечатка голосом с самим человеком, а поручительство
    /// друга это не она. Подпись бы тут не помогла — её у карточки нет
    /// и не бывает (`ratatosk_proto::contact_share`).
    ///
    /// **Известный контакт не трогается.** Ни адреса, ни версия карточки,
    /// ни признак сверки. Иначе кто угодно пришлёт «Кэрол версии 99» со своим
    /// onion-адресом и уведёт маршрут на себя; адреса меняет только
    /// подписанный `CardUpdate` из сессии самой Кэрол (§4.3).
    fn on_add_shared_contact(
        &mut self,
        now_ms: u64,
        msg_id: MsgId,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(share) = self.store.contact_share_of(&msg_id)? else { return Ok(Vec::new()) };
        if share.ik == self.identity.public().ik {
            // Своя карточка, вернувшаяся к нам. Добавлять себя в контакты
            // нечего, и это не ошибка — просто нажатие ни к чему не ведёт.
            return Ok(Vec::new());
        }
        if self.contacts.contains_key(&share.ik) {
            // Уже знаем. Молча и без изменений — см. выше про подмену адресов.
            return Ok(Vec::new());
        }
        let peer_ik = share.ik;
        let mut effects = self.add_contact(now_ms, &share.card_bytes, false)?;
        // Присланная третьим человеком карточка тем более может быть старой:
        // она ехала через чужое устройство и чужую очередь.
        effects.extend(self.push_own_card(now_ms, peer_ik)?);
        Ok(effects)
    }

    /// Человек согласился принять файл.
    fn on_accept_file(&mut self, now_ms: u64, file_id: FileId) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming || file.complete {
            return Ok(Vec::new());
        }
        self.store.accept_file(&file_id)?;
        // Первая просьба про файл — «начните сначала», то есть тот же случай,
        // что и возобновление: у отправителя об этой передаче ещё ничего нет.
        self.ask_for_file(now_ms, &file, true)
    }

    /// Человек отказался от файла.
    ///
    /// Собеседнику не уходит ничего: отказ — решение о своей памяти, а не
    /// сообщение о себе. Он увидит, что чанки перестали запрашивать, и это
    /// всё, что ему полагается знать.
    fn on_decline_file(&mut self, file_id: FileId) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming {
            return Ok(Vec::new());
        }
        // Сперва байты, потом запись: обратный порядок оставил бы чанки
        // на диске без всякого следа о том, чьи они.
        self.blobs.remove(&file_id)?;
        self.store.delete_file(&file_id)?;
        Ok(vec![Effect::Notify(Event::FileProgress { file_id, received: 0, total: 0 })])
    }

    /// Просит собеседника продолжить (или начать) передачу файла.
    ///
    /// Просьба уходит **прямым каналом и только им**: файл — это тысячи кадров,
    /// и почтой (§5.3) они не поедут. Нет канала — нет и просьбы: собеседник
    /// появится, сессия установится, и мы спросим снова.
    fn ask_for_file(
        &mut self,
        now_ms: u64,
        file: &StoredFile,
        stalled: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let chat = self.store.message(&file.msg_id)?.map(|m| m.chat_id);
        let Some(peer_ik) = chat.and_then(|chat| self.by_chat.get(&chat).copied()) else {
            return Ok(Vec::new());
        };
        let next = self.store.next_missing_chunk(&file.file_id, file.chunk_total)?;
        let Some(next) = next else {
            // Просить нечего — всё на месте. Такое бывает у пустого файла
            // и у передачи, которая закончилась ровно перед перезапуском.
            return self.finish_file(file);
        };
        let Some(via) = self.direct_channel(&peer_ik) else { return Ok(Vec::new()) };

        let mut effects = self.send_file_frame(
            now_ms,
            peer_ik,
            via,
            PayloadType::FileRequest,
            ratatosk_proto::files::request_payload(file.file_id, next, stalled),
        )?;
        effects.extend(self.watch_for_stall(file.file_id, via));
        Ok(effects)
    }

    /// Ставит срок молчания по файлу.
    ///
    /// Без него оборванная передача не возобновится никогда: отправитель ждёт
    /// подтверждения, получатель ждёт чанков, и оба правы. Срок сторожит
    /// получатель — у него есть всё, чтобы спросить заново.
    fn watch_for_stall(&mut self, file_id: FileId, via: Transport) -> Vec<Effect> {
        let token = self.allocate_timer();
        // Прежняя метка забывается, а не снимается: отменить уже поставленный
        // таймер драйверу нечем, но сработавшая метка, которой здесь больше
        // нет, ничего не делает. Живой срок у файла всегда один.
        self.file_timers.insert(file_id, token);
        vec![Effect::SetTimer { after_ms: ratatosk_proto::files::stall_ms(via), token }]
    }

    /// Отправляет служебный кадр файла — просьбу или чанк.
    ///
    /// Мимо очереди §5.4, и это не нарушение, а её признание: очередь
    /// обслуживает **сообщения**, у которых есть статус, квитанция и место
    /// в истории. У чанка нет ничего из этого — его подтверждает следующая
    /// просьба, а не квитанция, и ставить тысячи чанков в очередь доставки
    /// значит забить её тем, чему там не место.
    fn send_file_frame(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        payload_type: PayloadType,
        payload: Value,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            return Ok(Vec::new());
        };
        let envelope =
            Envelope::new(self.entropy.msg_id(), self.clock.now(now_ms)?, payload_type, payload);
        let frame = self.seal_for(session_id, &envelope.encode()?)?;
        Ok(vec![Effect::Send { peer_ik, via, frame }])
    }

    /// Пришло предложение файлов.
    ///
    /// Сообщение с подписью ложится в историю обычным путём — с событием и
    /// квитанцией (§9.4). Файлы к нему прикладываются записями; те, что
    /// проходят по порогу, сразу запрашиваются, остальные ждут человека.
    fn on_file_offer(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (caption, offers) = ratatosk_proto::files::offer_from_payload(&envelope.payload)?;
        let mut effects =
            self.on_incoming_text(now_ms, via, peer_ik, envelope, &caption, TextKind::Plain)?;

        let mut records = Vec::with_capacity(offers.len());
        for offer in offers {
            let chunk_total = ratatosk_proto::files::chunk_count(offer.size_bytes);
            let record = StoredFile {
                file_id: offer.file_id,
                msg_id: envelope.msg_id,
                name: offer.name,
                size_bytes: offer.size_bytes,
                chunk_total,
                key: offer.key,
                preview: offer.preview,
                incoming: true,
                source_path: None,
                // Порог — настройка, а не правило: `None` означает «спрашивать
                // всегда», и это законный выбор человека.
                accepted: ratatosk_proto::files::auto_accept(offer.size_bytes, self.auto_accept),
                // Пустой файл собран в тот же миг: чанков у него нет.
                complete: chunk_total == 0,
            };
            self.store.put_file(&record)?;
            records.push(record);
        }

        for record in records {
            if record.complete {
                effects.extend(self.finish_file(&record)?);
            } else if record.accepted {
                effects.extend(self.ask_for_file(now_ms, &record, true)?);
            }
        }
        Ok(effects)
    }

    /// Пришла просьба продолжить передачу — она же подтверждение.
    fn on_file_request(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (file_id, next_index, stalled) =
            ratatosk_proto::files::request_from_payload(&envelope.payload)?;

        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        // Отдаём только своё и только тому, кому отправляли: просьба про чужой
        // файл — попытка вычитать переписку, которой у собеседника нет.
        if file.incoming
            || self.store.message(&file.msg_id)?.map(|m| m.chat_id)
                != Some(Self::chat_id_for(&peer_ik))
        {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        if next_index > file.chunk_total {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        let position = self.sending.iter().position(|s| s.file_id == file_id);
        let sending = match position {
            Some(at) => {
                let sending = &mut self.sending[at];
                // Получатель сам сказал, что имеет в виду, — гадать не о чем.
                // «Ничего не дошло» отматывает отправку назад; подтверждение
                // только двигает окно, потому что то, что уже в полёте,
                // слать второй раз незачем.
                if stalled {
                    sending.sent_upto = next_index;
                } else {
                    sending.sent_upto = sending.sent_upto.max(next_index);
                }
                sending.acked_upto = next_index;
                *sending
            }
            None => {
                // Первая просьба — или первая после нашего перезапуска.
                // Своего состояния передачи отправитель не хранит: всё, что
                // нужно, только что приехало в просьбе.
                let sending = Sending {
                    file_id,
                    peer_ik,
                    chunk_total: file.chunk_total,
                    acked_upto: next_index,
                    sent_upto: next_index,
                };
                self.sending.push(sending);
                sending
            }
        };

        if sending.acked_upto >= file.chunk_total {
            // Получатель сказал, что у него всё. Больше этой передаче ничего
            // не нужно.
            self.sending.retain(|s| s.file_id != file_id);
            return Ok(Vec::new());
        }
        self.pump_file(now_ms, &file)
    }

    /// Досылает чанки, пока окно не закрылось.
    fn pump_file(&mut self, now_ms: u64, file: &StoredFile) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let Some(index) = self.sending.iter().position(|s| s.file_id == file.file_id) else {
            return Ok(Vec::new());
        };
        let sending = self.sending[index];
        let Some(via) = self.direct_channel(&sending.peer_ik) else {
            // Прямого канала нет — чанкам ехать не на чем. Получатель спросит
            // снова, когда канал появится; своего расписания у отправителя нет.
            return Ok(Vec::new());
        };
        let Some(source) = file.source_path.clone() else { return Ok(Vec::new()) };
        let Some(session_id) = self.sessions.for_peer(&sending.peer_ik, via) else {
            return Ok(Vec::new());
        };

        let limit = sending.chunk_total.min(sending.acked_upto.saturating_add(files::CHUNK_WINDOW));
        let mut effects = Vec::new();
        let mut next = sending.sent_upto;
        while next < limit {
            let offset = next * files::CHUNK_BYTES as u64;
            // Отказ чтения и пустой ответ — один и тот же случай: файла там
            // больше нет или он стал короче. Отказ **не** поднимается выше:
            // это не поломка ядра, а исчезнувший исходник, и сказать о нём
            // надо человеку, а не вызывающему коду.
            let plain = self
                .blobs
                .read_at(std::path::Path::new(&source), offset, files::CHUNK_BYTES)
                .unwrap_or_default();
            if plain.is_empty() {
                // Молчать нельзя: передача встанет, и человек будет думать,
                // что она идёт.
                self.sending.retain(|s| s.file_id != file.file_id);
                effects.push(Effect::Notify(Event::HonestNotice {
                    text: crate::honest::FILE_SOURCE_GONE,
                }));
                break;
            }
            let sealed = ratatosk_crypto::file::seal_chunk(&file.key, &file.file_id, next, &plain)?;
            let envelope = Envelope::new(
                self.entropy.msg_id(),
                self.clock.now(now_ms)?,
                PayloadType::FileChunk,
                files::chunk_payload(file.file_id, next, &sealed),
            );
            let frame = self.seal_for(session_id, &envelope.encode()?)?;
            effects.push(Effect::Send { peer_ik: sending.peer_ik, via, frame });
            next += 1;
        }
        if let Some(slot) = self.sending.iter_mut().find(|s| s.file_id == file.file_id) {
            slot.sent_upto = next;
        }
        Ok(effects)
    }

    /// Пришёл чанк файла.
    ///
    /// Квитанции (§9.4) здесь нет и не должно быть: чанк — не сообщение,
    /// и подтверждает его следующая просьба, а не отметка в истории.
    fn on_file_chunk(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let (file_id, index, sealed) = files::chunk_from_payload(&envelope.payload)?;
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming
            || !file.accepted
            || self.store.message(&file.msg_id)?.map(|m| m.chat_id)
                != Some(Self::chat_id_for(&peer_ik))
        {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        if index >= file.chunk_total {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        // Проверка тега — здесь и сейчас, до записи на диск. Она утверждает
        // три вещи разом: содержимое не изменено, чанк с этого места и из
        // этого файла (§10.1, AAD).
        if ratatosk_crypto::file::open_chunk(&file.key, &file_id, index, &sealed).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
            return Ok(Vec::new());
        }

        // Повтор чанка законен (§9.2) и безвреден — но обрабатывать его как
        // новый нельзя: он потянул бы за собой и подтверждение, и новый срок
        // молчания, а значит и новые чанки в ответ. Ровно так передача
        // начинала разгонять сама себя.
        if self.store.has_chunk(&file_id, index)? {
            return Ok(Vec::new());
        }

        // Байты — раньше отметки. Наоборот было бы «файл собран из куска,
        // которого нет»: отметка переживает падение процесса, а незаписанный
        // чанк — нет.
        self.blobs.put_chunk(&file_id, index, &sealed)?;
        self.store.note_chunk(&file_id, index)?;

        let received = self.store.received_chunks(&file_id)?;
        let mut effects = vec![Effect::Notify(Event::FileProgress {
            file_id,
            received,
            total: file.chunk_total,
        })];

        if received >= file.chunk_total {
            effects.extend(self.finish_file(&file)?);
            return Ok(effects);
        }
        // Подтверждение — оно же просьба продолжать. Реже, чем каждый чанк:
        // окно не должно простаивать, но и кадр на каждый чанк ни к чему.
        // Подтверждение — «принял, шлите дальше», а не «начните заново»:
        // у отправителя в полёте ещё несколько чанков, и пересылать их
        // не нужно. Различие едет флагом, а не угадывается на той стороне.
        if received % files::ACK_EVERY == 0 {
            effects.extend(self.ask_for_file(now_ms, &file, false)?);
        } else {
            effects.extend(self.watch_for_stall(file_id, via));
        }
        Ok(effects)
    }

    /// Файл собран.
    fn finish_file(&mut self, file: &StoredFile) -> Result<Vec<Effect>, EngineError> {
        self.store.complete_file(&file.file_id)?;
        self.file_timers.remove(&file.file_id);
        Ok(vec![Effect::Notify(Event::FileProgress {
            file_id: file.file_id,
            received: file.chunk_total,
            total: file.chunk_total,
        })])
    }

    /// Срок молчания вышел — спрашиваем заново.
    fn on_file_stall(&mut self, now_ms: u64, file_id: FileId) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if file.complete || !file.incoming || !file.accepted {
            return Ok(Vec::new());
        }
        // Срок вышел — значит за всё это время не пришло ничего. Вот теперь
        // отправителю и правда надо начать с названного номера.
        self.ask_for_file(now_ms, &file, true)
    }

    /// Возобновляет незаконченные приёмы у этого собеседника.
    ///
    /// Зовётся, когда появляется прямой канал: после рукопожатия и когда
    /// собеседник объявился в эфире. Это и есть возобновление после
    /// перезапуска — своего состояния передачи у получателя нет, всё нужное
    /// лежит в базе.
    fn resume_files(&mut self, now_ms: u64, peer_ik: [u8; 32]) -> Result<Vec<Effect>, EngineError> {
        let chat = Self::chat_id_for(&peer_ik);
        let unfinished: Vec<StoredFile> = self
            .store
            .unfinished_files()?
            .into_iter()
            .filter(|f| f.incoming && f.accepted)
            .collect();

        let mut effects = Vec::new();
        for file in unfinished {
            if self.store.message(&file.msg_id)?.map(|m| m.chat_id) != Some(chat) {
                continue;
            }
            effects.extend(self.ask_for_file(now_ms, &file, true)?);
        }
        Ok(effects)
    }

    /// Кладёт сообщение в историю — единственная дверь, через которую оно
    /// туда попадает.
    ///
    /// Дверь одна затем, что за ней есть учёт: уборка (§12) запускается
    /// «каждые N сообщений», и считать их по трём разным местам значит
    /// однажды забыть четвёртое.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    fn remember(&mut self, message: &StoredMessage) -> Result<(), EngineError> {
        self.store.put_message(message)?;
        self.messages_since_compaction = self.messages_since_compaction.saturating_add(1);
        Ok(())
    }

    /// Прибирается, если пора (§12).
    ///
    /// «Compaction обязателен с первого дня. Иначе клиент перестанет
    /// открываться на третий год» — и до этой функции он был написан целиком,
    /// но не запускался ни разу: [`Store::compact`] звали только тесты. Ошибка
    /// ровно того рода, о котором предупреждает спецификация: она проявляется
    /// не падением, а медленной деградацией, и на стенде её не увидеть.
    ///
    /// **По событию, а не по таймеру.** Телефон значительную часть времени
    /// спит (§13.1), и таймер там не гарантирует ничего; поэтому проверка
    /// делается после каждого шага ядра, а условие берётся из [`Schedule`]:
    /// накопилось довольно сообщений **или** прошло довольно времени.
    ///
    /// Возвращает число убранных строк — ноль означает и «было нечего»,
    /// и «ещё не пора».
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn compact_if_due(&mut self, now_ms: u64) -> Result<u64, EngineError> {
        let last = self
            .store
            .meta(ratatosk_store::META_LAST_COMPACTION)?
            .and_then(|raw| <[u8; 8]>::try_from(raw.as_slice()).ok())
            .map_or(0, u64::from_be_bytes);
        if !self.schedule.due(self.messages_since_compaction, last, now_ms) {
            return Ok(0);
        }

        // Отметка ставится **до** работы, а не после. Уборка, падающая
        // на какой-то одной задаче, иначе повторялась бы на каждом шаге
        // ядра — то есть отказ хранилища превращался бы в бесконечный цикл
        // отказов. Пропустить один круг дешевле.
        self.store.put_meta(ratatosk_store::META_LAST_COMPACTION, &now_ms.to_be_bytes())?;
        self.messages_since_compaction = 0;

        let mut removed = 0;
        for task in Task::ALL {
            // Отказ одной задачи не отменяет остальные: они независимы,
            // и не убрать всё — лучше, чем не убрать ничего.
            match self.store.compact(task, now_ms) {
                Ok(rows) => removed += rows,
                Err(error) => tracing::warn!(?task, ?error, "задача уборки не выполнена"),
            }
        }
        Ok(removed)
    }

    /// Стирает с диска вложения, которых нет в базе (§12).
    ///
    /// Байты вложений живут не в базе, а рядом с ней ([`ratatosk_store::Blobs`]),
    /// и это правильно: двухгигабайтный BLOB в SQLite — переписанная страница
    /// на каждый чанк и WAL размером с файл. Но у раздельного хранения есть
    /// своя цена, и вот она: база и диск способны разойтись, а база о том,
    /// что осталось на диске, не знает ничего.
    ///
    /// Расходятся они двумя путями, и оба настоящие. Удаление контакта вместе
    /// с историей сносит сообщения, каскад внешних ключей уносит записи
    /// о файлах — а каталоги с чанками остаются лежать; переписка на гигабайт
    /// исчезала из базы, не освободив ни байта. И удаление сообщения намеренно
    /// проглатывает отказы удаления байтов: незавершённое удаление сообщения
    /// хуже, чем оставшийся на диске мусор, — но мусор остаётся.
    ///
    /// Поэтому сверка отдельной операцией, а не частью удаления: она чинит
    /// и то, что утекло вчера на устройстве, где эта функция ещё не работала.
    /// Направление у неё одно — **с диска убирается лишнее**, на диск ничего
    /// не добавляется. Запись в базе без байтов на диске мусором не является:
    /// это незаконченный приём, и продолжится он ровно с той дырки, которой
    /// не хватает (§10.2).
    ///
    /// Стирается два вида лишнего: целые каталоги вложений, о которых в базе
    /// нет ни строчки, и отдельные чанки, не отмеченные принятыми, — след
    /// процесса, убитого системой между записью байтов и отметкой о них
    /// (порядок этих двух шагов сознательный, см. [`ratatosk_store::Blobs`]).
    /// Такой чанк не читается никогда: его перепросят и перезапишут.
    ///
    /// Дорогая: обходит каталог целиком. Звать по кнопке «освободить место»
    /// или в редкой фоновой уборке, но не по событию.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или диска. Убранное до отказа остаётся убранным:
    /// уборка не транзакция, и делать её транзакцией незачем — повторный
    /// запуск просто доделает остальное.
    pub fn sweep_orphan_files(&mut self) -> Result<Swept, EngineError> {
        let known: BTreeSet<FileId> = self.store.all_file_ids()?.into_iter().collect();
        let mut swept = Swept::default();

        for file_id in self.blobs.stored_files()? {
            let chunks = self.blobs.stored_chunks(&file_id)?;
            if !known.contains(&file_id) {
                swept.bytes += chunks.iter().map(|(_, size)| *size).sum::<u64>();
                swept.files += 1;
                self.blobs.remove(&file_id)?;
                continue;
            }
            // Идущую передачу это не трогает: чанк отмечается в базе в том же
            // шаге, в котором ложится на диск, а уборка идёт между шагами.
            // Неотмеченный чанк здесь — всегда след прошлой жизни процесса.
            for (index, size) in chunks {
                if !self.store.has_chunk(&file_id, index)? {
                    self.blobs.remove_chunk(&file_id, index)?;
                    swept.chunks += 1;
                    swept.bytes += size;
                }
            }
        }
        Ok(swept)
    }

    /// Открывает вложение на чтение — **один раз на файл, а не на кусок**.
    ///
    /// Ядро отвечает на один вопрос и выдаёт [`FileReader`], в котором лежит
    /// всё нужное для расшифровки. Дальше клиент читает сам, из своего
    /// потока, и ядро в этом не участвует.
    ///
    /// Раньше он участвовал в каждом куске, и это был не выбор, а недосмотр:
    /// открытие вложения на полгигабайта означало пятьсот заходов в очередь
    /// драйвера, каждый на время чтения с диска и расшифровки мебибайта.
    /// Всё это время не уходили сообщения и не срабатывали таймеры. Чтение
    /// вложения ничего в состоянии не меняет — значит, ему незачем стоять
    /// в очереди за тем, что меняет.
    ///
    /// Работает и на **своё** отправленное вложение: у него нет запечатанных
    /// чанков (отправитель читает исходник с диска, ничего не копируя),
    /// поэтому читатель берёт его по пути и открытым текстом. До этой правки
    /// своё вложение через ядро не открывалось вовсе.
    ///
    /// `None` — такого файла нет: не приезжал, отклонён или удалён.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    ///
    /// [`FileReader`]: crate::reader::FileReader
    pub fn open_file(&self, file_id: &FileId) -> Result<Option<FileReader>, EngineError> {
        let Some(file) = self.store.file(file_id)? else { return Ok(None) };
        Ok(Some(FileReader::new(
            *file_id,
            file.key,
            file.chunk_total,
            file.size_bytes,
            file.source_path.map(std::path::PathBuf::from),
            self.blobs.reader(),
        )))
    }

    /// Порог автоматического приёма файлов.
    #[must_use]
    pub const fn auto_accept_bytes(&self) -> Option<u64> {
        self.auto_accept
    }

    // --- правка, пересылка, реакции -----------------------------------------

    /// Заменяет текст своего сообщения и просит собеседника сделать то же.
    ///
    /// Три отказа, и все три — до записи: пустая правка (это удаление, у него
    /// своя команда), чужое сообщение, истёкшее окно. Отказ возвращается
    /// вызывающему, потому что человек ждёт ответа **сейчас**: он смотрит
    /// на поле ввода, и «ничего не произошло» здесь — худший исход.
    ///
    /// Прежний текст не сохраняется, но появляется отметка о правке: молча
    /// подменить слова в чужой истории §14 запрещает.
    ///
    /// **Очередь при этом не переписывается.** Если сообщение ещё ждёт сети,
    /// собеседник получит сперва прежний текст, а сразу за ним — правку,
    /// и увидит исправленное с пометкой «изменено». Это верно и без хитростей:
    /// сообщение действительно правили. Подменять конверт в очереди значило бы
    /// решать, дошла ли уже копия, — а этого мы не знаем (§9.2).
    fn on_edit_message(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        ratatosk_proto::edit::check(text)?;

        // Чьё сообщение и когда оно появилось — знает хранилище, а не клиент.
        let own_ik = self.identity.public().ik;
        let message = self
            .store
            .message(&msg_id)?
            .filter(|m| m.sender_ik == own_ik && m.chat_id == chat)
            .ok_or(ratatosk_proto::EditError::NotYours)?;
        // Срок считается по **местным** часам: `received_ms` у своего
        // сообщения — момент, когда человек нажал «отправить». Физическая
        // компонента HLC для этого не годится, её вторая половина приходит
        // от собеседника (§9.1).
        if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
            return Err(ratatosk_proto::EditError::TooLate.into());
        }

        let trimmed = text.trim();
        let mut effects = Vec::new();
        if self.store.edit_message(&msg_id, trimmed.as_bytes(), now_ms)? {
            effects.push(Effect::Notify(Event::MessageEdited { chat, msg_id }));
        }
        effects.extend(self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Edit,
            ratatosk_proto::edit::payload(msg_id, trimmed),
        )?);
        Ok(effects)
    }

    /// Пересылает сообщения в другой чат.
    ///
    /// Каждое уезжает своим новым сообщением: новый `msg_id`, своя метка,
    /// своя запись в очереди. Автор не указывается — см.
    /// `ratatosk_proto::forward`: подпись §6 при пересылке не сохраняется,
    /// и имя рядом с чужими словами было бы утверждением, которое получатель
    /// проверить не может.
    ///
    /// Пропущенное молча — то, чего уже нет или что нельзя прочитать текстом:
    /// список приходит от клиента, а половина названного могла быть удалена
    /// секунду назад с другого экрана.
    fn on_forward_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        // Тексты собираются заранее: отправка занимает `self` целиком.
        let mut texts = Vec::new();
        for msg_id in msg_ids.iter().take(ratatosk_proto::MAX_FORWARD_IDS) {
            let Some(message) = self.store.message(msg_id)? else { continue };
            // Не-UTF-8 в теле означает не текст: вложений в v0.1 ещё нет (§10),
            // и пересылать нечего. Молча — потому что это не отказ ядра.
            let Ok(text) = String::from_utf8(message.body) else { continue };
            texts.push(text);
        }

        let mut effects = Vec::new();
        for text in texts {
            effects.extend(self.send_own_text(
                now_ms,
                chat,
                peer_ik,
                &text,
                TextKind::Forwarded,
            )?);
        }
        Ok(effects)
    }

    /// Ставит или снимает свою реакцию.
    ///
    /// Реагировать можно и на своё сообщение: запрещать это незачем, а правило
    /// «только чужое» пришлось бы объяснять.
    ///
    /// Метка HLC у реакции своя, и она существенна: реакция законно приезжает
    /// с опозданием (§9.2), и без метки запоздавшая копия возвращала бы то,
    /// что человек снял.
    fn on_set_reaction(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        emoji: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        // Проверка та же, что и на приёме: отправить то, что сами не приняли
        // бы, — верный способ развести две стороны.
        ratatosk_proto::reaction::check(emoji)?;

        // Реакция на то, чего нет, — не ошибка ядра, но и делать нечего.
        if self.store.message(&msg_id)?.is_none_or(|m| m.chat_id != chat) {
            return Ok(Vec::new());
        }

        let hlc = self.clock.now(now_ms)?;
        let own_ik = self.identity.public().ik;
        self.store.put_reaction(&ratatosk_store::StoredReaction {
            msg_id,
            author_ik: own_ik,
            emoji: emoji.to_owned(),
            hlc,
        })?;

        let mut effects =
            vec![Effect::Notify(Event::ReactionChanged { chat, msg_id, author_ik: own_ik })];
        effects.extend(self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Reaction,
            ratatosk_proto::reaction::payload(msg_id, emoji),
        )?);
        Ok(effects)
    }

    /// Пришла просьба заменить текст сообщения.
    ///
    /// **Править можно только своё**, и проверяет это получатель — ровно как
    /// с отзывом. Без проверки достаточно прислать чужой идентификатор, чтобы
    /// переписать слова в чужой переписке, а это хуже удаления: удаление
    /// видно, подмена — нет.
    ///
    /// Окно правки проверяется здесь **по своим часам**, и у этого есть цена:
    /// правка, пролежавшая в очереди дольше недели, не применится, а
    /// собеседник об этом не узнает — квитанция говорит «кадр пришёл», а не
    /// «правка принята». Отдельного отказа для этого случая нет намеренно:
    /// новый вид кадра ради события, которое требует недели офлайна, дороже
    /// пользы. Записано как известный пробел, а не как «работает».
    fn on_edit(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, text) = ratatosk_proto::edit::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        // Квитанция — как на текст и как на отзыв (§9.4): запись в очереди
        // §5.4 закрывается подтверждением, иначе страховочный срок объявит
        // неудачу и пошлёт ту же просьбу ещё раз.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        // Правка про сообщение, которого нет, — не ошибка: копия могла быть
        // удалена раньше или не дойти вовсе.
        let Some(message) = self.store.message(&target)? else { return Ok(effects) };
        if message.sender_ik != peer_ik || message.chat_id != chat {
            // Попытка распорядиться не своим — аномалия сессии, а не «формат
            // не тот».
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }
        if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
            return Ok(effects);
        }

        if self.store.edit_message(&target, text.as_bytes(), now_ms)? {
            effects.push(Effect::Notify(Event::MessageEdited { chat, msg_id: target }));
        }
        Ok(effects)
    }

    /// Пришла реакция собеседника.
    ///
    /// Реагировать он может и на своё сообщение, и на наше — но только в своём
    /// чате: реакция на сообщение из чужой переписки означала бы, что нам
    /// прислали идентификатор, которого знать не должны.
    fn on_reaction(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, emoji) = ratatosk_proto::reaction::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Some(message) = self.store.message(&target)? else { return Ok(effects) };
        if message.chat_id != chat {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }

        // §9.1: свежее не затирается старым. Сравнивается с записью **как
        // есть**, включая снятие: иначе опоздавшая реакция вернула бы то,
        // что собеседник убрал.
        if self.store.reaction(&target, &peer_ik)?.is_some_and(|known| known.hlc >= envelope.hlc) {
            return Ok(effects);
        }

        self.store.put_reaction(&ratatosk_store::StoredReaction {
            msg_id: target,
            author_ik: peer_ik,
            emoji,
            hlc: envelope.hlc,
        })?;
        effects.push(Effect::Notify(Event::ReactionChanged {
            chat,
            msg_id: target,
            author_ik: peer_ik,
        }));
        Ok(effects)
    }

    // --- редактирование и удаление контактов --------------------------------

    /// Подписывает контакт своим именем — или снимает подпись.
    ///
    /// Пустая строка после обрезки пробелов считается снятием: человек,
    /// стёрший имя в поле ввода, имел в виду именно это, а не «подписать
    /// пустотой». Возвращать его к имени из карточки — правильный исход,
    /// и заставлять клиент отличать `Some("")` от `None` незачем.
    fn on_set_local_name(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        name: Option<String>,
    ) -> Result<Vec<Effect>, EngineError> {
        let trimmed = name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
        if let Some(name) = &trimmed {
            if name.chars().count() > MAX_LOCAL_NAME_CHARS {
                return Err(EngineError::LocalNameTooLong);
            }
        }

        let contact = self.contacts.get_mut(&peer_ik).ok_or(EngineError::UnknownPeer)?;
        contact.local_name = trimmed;
        self.persist_contact(&peer_ik, now_ms)?;
        Ok(vec![Effect::Notify(Event::ContactChanged { peer_ik })])
    }

    /// Удаляет контакт — и всё, что было привязано к его личности.
    ///
    /// Что уходит всегда: карточка, отметка о сверке (§4.2), аватарка, сессия
    /// вместе с ключевым материалом (§8.3), незаконченное рукопожатие и всё,
    /// что стояло в очереди этому человеку. Оставить сессию значило бы держать
    /// ключи для собеседника, которого у пользователя больше нет, — а §12
    /// требует, чтобы удаление удаляло.
    ///
    /// Что уходит по решению человека: переписка. Ядро её не выбрасывает само
    /// и не оставляет само — за это отвечает `purge_history`.
    ///
    /// **Чего эта команда не делает: она не мешает собеседнику вернуться.**
    /// Его рукопожатие (§8.2) заведёт контакт заново — уже несверенным, но
    /// заведёт. Удаление — это «убрать у себя», а не «запретить писать»;
    /// обещать второе, умея только первое, §14 запрещает прямо. Текст для UI
    /// лежит в [`crate::honest::DELETION_NOTICE`].
    fn on_delete_contact(
        &mut self,
        peer_ik: [u8; 32],
        purge_history: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        if !self.contacts.contains_key(&peer_ik) {
            return Err(EngineError::UnknownPeer);
        }
        let chat = Self::chat_id_for(&peer_ik);

        // Сессии — первыми и из обоих мест сразу: из реестра в памяти и
        // с диска. Пережившая удаление запись в реестре продолжала бы
        // расшифровывать кадры от человека, которого больше нет в контактах.
        for transport in [Transport::Lan, Transport::Onion, Transport::Mail] {
            if let Some(session_id) = self.sessions.for_peer(&peer_ik, transport) {
                self.sessions.remove(session_id);
                self.store.delete_session(session_id)?;
            }
        }

        // Незаконченное рукопожатие и очередь: без контакта `advance` всё
        // равно упрётся в `UnknownPeer`, и записи остались бы навсегда.
        self.pending.retain(|p| p.peer_ik != peer_ik);
        self.outbox.retain(|d| d.peer_ik != peer_ik);
        for waiting in std::mem::take(&mut self.deferred) {
            if waiting.peer_ik == peer_ik {
                self.store.delete_outbox(&waiting.msg_id)?;
            } else {
                self.deferred.push(waiting);
            }
        }

        self.contacts.remove(&peer_ik);
        self.by_chat.remove(&chat);
        self.seen_on_lan.remove(&peer_ik);
        self.awaited_discovery.remove(&peer_ik);
        self.read_upto.remove(&chat);

        self.store.delete_contact(&peer_ik)?;
        self.store.delete_avatar(&peer_ik)?;
        if purge_history {
            // Байты вложений — **до** `delete_chat`, и только в этом порядке.
            // Он уносит сообщения, каскад внешних ключей уносит следом записи
            // о файлах, и после него спросить «какие вложения были в этом
            // чате» уже не у кого: каталоги с чанками остались бы на диске
            // навсегда, а переписка на гигабайт исчезла бы, не освободив
            // ни байта. Подобрать их потом умеет только
            // [`Engine::sweep_orphan_files`], и полагаться на неё здесь
            // значило бы оставлять мусор нарочно.
            for file_id in self.store.file_ids_of_chat(&chat).unwrap_or_default() {
                self.forget_file(&file_id);
            }
            self.store.delete_chat(&chat)?;
        }

        let mut effects = vec![Effect::Notify(Event::ContactRemoved { peer_ik })];
        // Список маяков изменился — транспорт больше не должен искать его
        // в эфире (§5.1). Без этого удалённый контакт продолжал бы
        // «находиться» в локальной сети, а ядро — заводить его заново.
        if self.lan_enabled {
            effects.push(self.watch_lan_peers());
        }
        Ok(effects)
    }

    // --- аватарки ----------------------------------------------------------
    //
    // Дополнение к спецификации: v0.1 аватарок не описывает. Правила и пределы
    // собраны в `ratatosk_proto::avatar`, здесь — только их применение.

    /// Прямой канал к контакту, если сессия по нему есть (§5.4).
    ///
    /// Аватарка, как и квитанция (§9.4), почтой не ходит: тридцать килобайт
    /// в письме — это удвоение трафика и метаданных у сервера ради картинки
    /// в профиле. И рукопожатия ради неё тоже не начинаем.
    fn direct_channel(&self, peer_ik: &[u8; 32]) -> Option<Transport> {
        // Спрашивается §5.4, а не перебирается список руками, и это
        // исправление ошибки, которая выглядела так: сообщения через onion
        // ходят, а файлы не идут — доезжает только само сообщение с превью.
        //
        // Прежний перебор `[Lan, Onion]` смотрел ровно на одно: есть ли
        // сессия. Сессия же переживает и выключение локальной сети, и уход
        // собеседника из неё, — она не про доступность, а про ключи. Поэтому
        // после `/lan` выключенного (или просто после ухода из общей сети)
        // у файлов оставался «прямой канал» LAN, которого нет: просьба
        // о чанках уезжала в мёртвый транспорт, срок молчания (§10.2)
        // спрашивал заново — и снова туда же, вечно.
        //
        // Сообщения при этом ходили, потому что они идут очередью §5.4,
        // а та про выключенный LAN знает. Разошлись два пути выбора
        // транспорта — разошлось и поведение.
        let availability = self.availability_of(peer_ik).ok()?;
        let mut attempt = Attempt::new();
        while let Some(Decision::Use(transport)) = attempt.next(availability) {
            // Почта сюда не годится по устройству: чанки идут мимо очереди
            // доставки, а §9.4 у почты не обещает даже «отправлено».
            if transport.is_direct() && self.sessions.for_peer(peer_ik, transport).is_some() {
                return Some(transport);
            }
        }
        None
    }

    /// Ставит или снимает свою аватарку и рассылает её сверенным контактам.
    fn on_set_avatar(&mut self, now_ms: u64, bytes: &[u8]) -> Result<Vec<Effect>, EngineError> {
        // Проверка до записи, а не после: отказать пользователю сразу честнее,
        // чем принять картинку, которую потом не сможет принять собеседник.
        ratatosk_proto::avatar::check(bytes)?;

        let own_ik = self.identity.public().ik;
        if bytes.is_empty() {
            self.store.delete_avatar(&own_ik)?;
        } else {
            self.store.put_avatar(
                &own_ik,
                &ratatosk_store::StoredAvatar { bytes: bytes.to_vec(), updated_ms: now_ms },
            )?;
        }

        // Кому отдавать, решает §4.2, и только он. Список собирается заранее:
        // отправка занимает `self` целиком.
        let recipients: Vec<[u8; 32]> = self
            .contacts
            .iter()
            .filter(|(_, contact)| contact.verified)
            .map(|(peer_ik, _)| *peer_ik)
            .collect();

        let mut effects = Vec::new();
        for peer_ik in recipients {
            let Some(via) = self.direct_channel(&peer_ik) else { continue };
            effects.extend(self.send_avatar(now_ms, peer_ik, via, bytes)?);
        }
        Ok(effects)
    }

    /// Отправляет свою аватарку контакту, если она есть и если он сверен.
    ///
    /// Зовётся при установлении сессии: собеседник мог переустановить клиент
    /// или впервые нас увидеть, и узнать, что у него уже есть, нам неоткуда —
    /// спрашивать пришлось бы лишним круговым обменом. Сессия устанавливается
    /// редко и переживает перезапуск (§8.3), так что цена ограничена.
    fn offer_avatar(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        let own_ik = self.identity.public().ik;
        let Some(avatar) = self.store.avatar(&own_ik)? else {
            // Своей аватарки нет — и сообщать об этом нечего: пустая
            // рассылка при каждом рукопожатии была бы трафиком ни о чём.
            return Ok(Vec::new());
        };
        self.send_avatar(now_ms, peer_ik, via, &avatar.bytes)
    }

    /// Кладёт аватарку в кадр — единственное место, где проверяется §4.2.
    ///
    /// Пустые байты законны: это «я снял аватарку», и сверенный контакт
    /// обязан об этом узнать, иначе у него навсегда останется прежнее лицо.
    fn send_avatar(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        if !via.is_direct() {
            return Ok(Vec::new());
        }
        // §4.2: несверенному контакту своё лицо не отдаётся. Он может быть
        // не тем, за кого себя выдаёт, — сверка ровно про эту возможность.
        if !self.contacts.get(&peer_ik).is_some_and(|c| c.verified) {
            return Ok(Vec::new());
        }
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            return Ok(Vec::new());
        };

        let hlc = self.clock.now(now_ms)?;
        let envelope = Envelope::new(
            self.entropy.msg_id(),
            hlc,
            PayloadType::Avatar,
            Value::Bytes(bytes.to_vec()),
        );
        let frame = self.seal_for(session_id, &envelope.encode()?)?;
        Ok(vec![Effect::Send { peer_ik, via, frame }])
    }

    /// Пришла аватарка контакта.
    ///
    /// Сохраняется **и от несверенного** — но не показывается (см.
    /// [`Engine::avatar_of`]). Разница неочевидная, поэтому вот рассуждение.
    ///
    /// Сверка односторонняя: собеседник мог сверить наш отпечаток при встрече,
    /// а мы его — ещё нет. Тогда он законно шлёт нам лицо, а мы законно его
    /// не показываем. Выбросив байты, мы получили бы чат, где после сверки
    /// аватарка не появляется до следующего рукопожатия — а рукопожатие
    /// переживает перезапуск (§8.3) и может не случиться неделями. Поэтому
    /// байты лежат, а решение о показе принимается каждый раз заново.
    ///
    /// Цена ограничена: одна запись на контакт, не больше
    /// [`MAX_AVATAR_BYTES`](ratatosk_proto::MAX_AVATAR_BYTES), с перезаписью.
    fn on_avatar(
        &mut self,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Value::Bytes(bytes) = &envelope.payload else {
            return Err(ratatosk_codec::CodecError::TypeMismatch.into());
        };
        // Проверка своя, а не доверие отправителю, — как и с квитанциями:
        // транспорт знаем мы, и подделать его он не может.
        if !via.is_direct() {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        // Кадр расшифрован, то есть сессия есть; но контакт мог не успеть
        // появиться, если карточка из §8.2 почему-то не разобралась.
        if !self.contacts.contains_key(&peer_ik) {
            return Ok(Vec::new());
        }
        // Негодная аватарка — не повод рвать сессию: сообщение отбрасывается
        // так же тихо, как мусорный кадр в §7.3, и записывается в аномалии.
        if ratatosk_proto::avatar::check(bytes).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        // Аватарка уходит заново при каждом установлении сессии, поэтому
        // две отправки легко обгоняют друг друга. Метка отправителя решает,
        // какая из них последняя; своим часам здесь верить нельзя — момент
        // приёма у более старой копии может оказаться более поздним.
        let arrived_ms = envelope.hlc.wall_ms;
        if let Some(stored) = self.store.avatar(&peer_ik)? {
            if stored.updated_ms > arrived_ms {
                return Ok(Vec::new());
            }
        }

        if bytes.is_empty() {
            self.store.delete_avatar(&peer_ik)?;
        } else {
            self.store.put_avatar(
                &peer_ik,
                &ratatosk_store::StoredAvatar { bytes: bytes.clone(), updated_ms: arrived_ms },
            )?;
        }
        if let Some(contact) = self.contacts.get_mut(&peer_ik) {
            contact.has_avatar = !bytes.is_empty();
        }
        Ok(vec![Effect::Notify(Event::AvatarChanged { peer_ik })])
    }

    /// Аватарка контакта — или `None`, если её нет **или он не сверен**.
    ///
    /// Правило показа живёт здесь, а не в клиенте: §13.3 не разрешает
    /// протокольной логике подниматься выше UniFFI-границы, а «показывать
    /// лицо только сверенному» — ровно она. Клиент, который решил бы иначе,
    /// не смог бы: байтов ему просто не отдадут.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn avatar_of(&self, peer_ik: &[u8; 32]) -> Result<Option<Vec<u8>>, EngineError> {
        let Some(contact) = self.contacts.get(peer_ik) else {
            return Ok(None);
        };
        if !contact.verified {
            return Ok(None);
        }
        Ok(self.store.avatar(peer_ik)?.map(|a| a.bytes))
    }

    /// Своя аватарка.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn own_avatar(&self) -> Result<Option<Vec<u8>>, EngineError> {
        Ok(self.store.avatar(&self.identity.public().ik)?.map(|a| a.bytes))
    }

    /// Отправляет квитанцию собеседнику (§9.4).
    ///
    /// Не через очередь доставки, и это важно. Квитанция — сведение о чужом
    /// сообщении, а не своё сообщение: у неё нет ни истории, ни статуса,
    /// и повторять её другим транспортом бессмысленно. Не дошла — собеседник
    /// увидит «отправлено» вместо «доставлено», что честно.
    ///
    /// Квитанция на квитанцию не отправляется по построению: сюда приходят
    /// только из ветки текста.
    fn send_receipt(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        receipt: Receipt,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        // §9.4: по почте квитанции не ходят — каждая была бы отдельным
        // письмом, то есть удвоением трафика и метаданных у сервера.
        if !ratatosk_proto::receipts::may_send_receipt(via) || msg_ids.is_empty() {
            return Ok(Vec::new());
        }
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            // Сессии нет — рукопожатие ради квитанции не начинаем: это
            // превратило бы сведение о доставке в повод для трафика.
            return Ok(Vec::new());
        };

        let hlc = self.clock.now(now_ms)?;
        let envelope = Envelope::new(
            self.entropy.msg_id(),
            hlc,
            PayloadType::Receipt,
            receipt.payload(msg_ids),
        );
        let frame = self.seal_for(session_id, &envelope.encode()?)?;
        Ok(vec![Effect::Send { peer_ik, via, frame }])
    }

    /// Выставляет статус доставки и сообщает о нём UI (§9.4).
    ///
    /// Одна точка на все переходы, и это не удобство: статус обязан только
    /// расти, а правило «только растёт», размазанное по пяти местам, рано
    /// или поздно разойдётся. Хранилище возвращает статус, **который
    /// получился**, — его и показываем, а не тот, что просили.
    ///
    /// Неизвестный `msg_id` — не ошибка: квитанция может прийти на сообщение,
    /// уже вычищенное уборкой (§12), и ронять из-за этого сессию незачем.
    fn note_status(
        &mut self,
        msg_id: MsgId,
        target: DeliveryStatus,
    ) -> Result<Vec<Effect>, EngineError> {
        let current = self.store.status(&msg_id)?.and_then(DeliveryStatus::from_code);
        // Допустимость перехода решает §9.4, а не хранилище и не это место:
        // правило неочевидное (`Undeliverable` перекрывает только `Pending`),
        // и записанное дважды оно однажды разойдётся.
        let Some(status) = ratatosk_proto::receipts::advance(current, target) else {
            // Ничего не изменилось — события об этом быть не должно.
            return Ok(Vec::new());
        };
        // Дошло — значит ждать больше нечего: запись уходит и из очереди
        // на диске. Иначе после перезапуска сообщение поехало бы вторым
        // экземпляром; дубль у получателя съела бы дедупликация (§9.2),
        // но лишний кадр всё равно ни к чему.
        if status >= DeliveryStatus::Sent {
            self.deferred.retain(|d| d.msg_id != msg_id);
            self.store.delete_outbox(&msg_id)?;
        }

        // Хранилище отвечает, нашлась ли строка. Не нашлась — сообщать UI
        // не о чем: по очереди §5.4 ездят и отзывы, которых в истории нет,
        // и события о статусе несуществующего сообщения только запутали бы
        // клиента. То же и с удалённым: у надгробия статуса нет.
        if !self.store.set_status(&msg_id, status.code())? {
            return Ok(Vec::new());
        }
        Ok(vec![Effect::Notify(Event::StatusChanged { msg_id, status })])
    }

    /// Список контактов, чьи маяки транспорт должен искать в эфире (§5.1).
    fn watch_lan_peers(&self) -> Effect {
        Effect::WatchLanPeers(self.contacts.keys().copied().collect())
    }

    fn send_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        self.send_own_text(now_ms, chat, peer_ik, text, TextKind::Plain)
    }

    /// Отвечает на сообщение этого чата.
    ///
    /// По проводу едет ссылка, а не цитата: цитату каждая сторона рисует
    /// из своей копии, и подделать её поэтому нельзя. Цель проверяется здесь —
    /// она обязана существовать и лежать **в этом** чате: ответ на сообщение
    /// из чужого разговора и цитировать нечем, и рассказал бы получателю
    /// об идентификаторе, которого он знать не должен.
    fn on_send_reply(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        reply_to: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        // Та же функция, что зовёт граница UniFFI, — правило одно и записано
        // в одном месте. Разница только в моменте: там раньше, здесь наверняка.
        ratatosk_proto::reply::check(text)?;
        if self.store.message(&reply_to)?.is_none_or(|m| m.chat_id != chat) {
            return Err(ratatosk_proto::ReplyError::TargetMissing.into());
        }
        self.send_own_text(now_ms, chat, peer_ik, text.trim(), TextKind::Reply(reply_to))
    }

    /// Кладёт своё текстовое сообщение в историю и в очередь §5.4.
    ///
    /// Одно место на обычную отправку, пересылку и ответ: различаются они ровно
    /// тем, что задаёт [`TextKind`] — типом конверта, нагрузкой и пометкой
    /// в истории. Разведи их по трём функциям, и первое же изменение в порядке
    /// «сначала записать, потом отправить» пришлось бы вносить трижды.
    fn send_own_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        text: &str,
        kind: TextKind,
    ) -> Result<Vec<Effect>, EngineError> {
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();
        let envelope = Envelope::new(msg_id, hlc, kind.payload_type(), kind.payload(text));
        let bytes = envelope.encode()?;

        // Своё сообщение кладётся в историю сразу: доставка может занять
        // сутки почтового круга (§5.3), а в чате оно должно быть видно уже.
        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Своё сообщение начинает с «ждёт отправки» и растёт оттуда.
            // У принятого статуса нет вовсе — там нечему расти.
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: kind.forwarded(),
            reply_to: kind.reply_to(),
        })?;

        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: bytes,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
        })
    }

    /// Ставит в очередь §5.4 служебную просьбу: отзыв, правку, реакцию.
    ///
    /// Отдельно от [`Engine::send_own_text`], и это не дублирование: у просьбы
    /// нет своей строки в истории — в чате видно её **следствие**, а не её
    /// саму. Поэтому у неё нет и статуса доставки: `note_status` для такого
    /// `msg_id` не найдёт строки и промолчит.
    fn enqueue_request(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        payload_type: PayloadType,
        payload: Value,
    ) -> Result<Vec<Effect>, EngineError> {
        let envelope =
            Envelope::new(self.entropy.msg_id(), self.clock.now(now_ms)?, payload_type, payload);
        self.enqueue(Delivery {
            msg_id: envelope.msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
        })
    }

    /// Ставит сообщение в очередь доставки и делает первую попытку.
    fn enqueue(&mut self, mut delivery: Delivery) -> Result<Vec<Effect>, EngineError> {
        let effects = self.advance(&mut delivery)?;
        // Запись хранится, пока попытка не закрыта. Закрывают её два исхода:
        // уход почтой (§9.4 — дальше «отправлено» статус не растёт) и
        // исчерпание транспортов. Всё остальное — ожидание.
        if !delivery.attempt.is_finished() {
            self.outbox.push(delivery);
        }
        Ok(effects)
    }

    /// Пробует следующий транспорт по §5.4.
    ///
    /// Строгая последовательность, а не гонка: [`Attempt`] выдаёт очередной
    /// транспорт только после того, как предыдущий объявлен неудавшимся,
    /// и поэтому одно сообщение физически не может уйти двумя каналами
    /// одновременно.
    fn advance(&mut self, delivery: &mut Delivery) -> Result<Vec<Effect>, EngineError> {
        let contact = self.contacts.get(&delivery.peer_ik).ok_or(EngineError::UnknownPeer)?;
        let availability = contact.availability;

        // Обнаружение ещё не отвечало — подождём его, прежде чем расходовать
        // транспорты. Иначе §5.4 получает на вход «в LAN не видно» там, где
        // правильный ответ — «пока не знаем».
        if let Some(effect) = self.park_for_discovery(delivery) {
            return Ok(vec![effect]);
        }

        let transport = match delivery.attempt.next(availability) {
            Some(Decision::Use(t)) => t,
            Some(Decision::Undeliverable) | None => {
                // Транспорты кончились — но это ещё не приговор. Пока работает
                // только локальная сеть, «собеседника нет в сети» — самый
                // частый исход отправки, а не поломка, и показывать его
                // ошибкой значит пугать человека тем, что в порядке вещей.
                //
                // Поэтому исходов два. Смогли запомнить сообщение и вернуться
                // к нему позже — «ждём, когда появится». Не смогли (очередь
                // полна, контакта больше нет) — «не доставлено», без обещаний.
                delivery.attempt.succeed();
                let (remembered, mut effects) = self.remember_undelivered(delivery)?;
                let status = if remembered {
                    DeliveryStatus::Waiting
                } else {
                    DeliveryStatus::Undeliverable
                };
                effects.extend(self.note_status(delivery.msg_id, status)?);
                return Ok(effects);
            }
        };

        let Some(session_id) = self.sessions.for_peer(&delivery.peer_ik, transport) else {
            // Сессии для этого семейства транспортов нет. §5.4 запрещает
            // продолжать LAN-сессию через onion, поэтому «нет сессии» здесь
            // означает именно новое рукопожатие, а не переиспользование.
            delivery.state = DeliveryState::AwaitingSession;
            return self.ensure_handshake(delivery.peer_ik, transport);
        };

        let frame = self.seal_for(session_id, &delivery.envelope)?;
        let mut effects = vec![Effect::Send { peer_ik: delivery.peer_ik, via: transport, frame }];

        if transport.is_direct() {
            // Срок ожидания квитанции (§9.4), а не страховка от молчания
            // транспорта. Успешная запись в сокет ничего не доказывает:
            // полуоткрытое соединение принимает байты молча. Не пришла
            // квитанция за отведённое время — попытка не удалась, и §5.4
            // ведёт дальше.
            let timer = self.allocate_timer();
            let after_ms = delivery.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            delivery.state = DeliveryState::InFlight { via: transport, timer };
            effects.push(Effect::SetTimer { after_ms, token: timer });
        } else {
            // §9.4: по почте статус дальше «отправлено» не растёт, ждать
            // нечего, и запись из очереди уходит.
            delivery.attempt.succeed();
            effects.extend(self.note_status(delivery.msg_id, DeliveryStatus::Sent)?);
        }
        Ok(effects)
    }

    /// Начинает рукопожатие, если оно ещё не в пути.
    fn ensure_handshake(
        &mut self,
        peer_ik: [u8; 32],
        transport: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        if self.pending.iter().any(|p| p.peer_ik == peer_ik) {
            // Второе рукопожатие только потратило бы ещё одну операцию
            // у получателя и породило вторую сессию.
            return Ok(Vec::new());
        }
        self.begin_handshake(peer_ik, transport)
    }

    fn allocate_timer(&mut self) -> u64 {
        let token = self.next_timer_token;
        self.next_timer_token += 1;
        token
    }

    fn begin_handshake(
        &mut self,
        peer_ik: [u8; 32],
        transport: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        // §8.2: в первом сообщении — только карточка и приветствие.
        let card = self.own_card().encode()?;
        let (message, state) = Initiator::start(&self.identity, &peer_ik, &card)?;
        let frame = self.handshake_frame(HANDSHAKE_STEP_FIRST, &message)?;

        // Попытка заводится на том же транспорте, который выбрала доставка:
        // рукопожатие и данные обязаны идти одним путём, иначе сессия
        // установится не в том семействе транспортов (§5.4).
        let mut attempt = Attempt::new();
        let availability = self.availability_of(&peer_ik)?;
        while let Some(Decision::Use(t)) = attempt.next(availability) {
            if t == transport {
                break;
            }
        }

        let mut effects = vec![Effect::Send { peer_ik, via: transport, frame: frame.clone() }];
        let mut timer = None;
        if transport.is_direct() {
            let token = self.allocate_timer();
            let after_ms = attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            effects.push(Effect::SetTimer { after_ms, token });
            timer = Some(token);
        }
        self.pending.push(OutgoingHandshake { state, frame, attempt, peer_ik, timer });
        Ok(effects)
    }

    /// Пересылает незавершённое рукопожатие следующим транспортом (§5.4).
    ///
    /// Второе возвращаемое значение — «транспорты для рукопожатия кончились».
    /// Оно нужно вызывающему: сессии не будет, а значит и сообщения, которые
    /// её ждут, никогда не уедут. Молча оставить их в очереди нельзя (§14).
    fn retry_handshake(
        &mut self,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<(Vec<Effect>, bool), EngineError> {
        let availability = match self.availability_of(&peer_ik) {
            Ok(a) => a,
            Err(_) => return Ok((Vec::new(), false)),
        };

        let mut effects = Vec::new();
        let mut exhausted = false;
        let mut pending = std::mem::take(&mut self.pending);
        for handshake in &mut pending {
            if handshake.peer_ik != peer_ik || handshake.attempt.tried().last() != Some(&via) {
                continue;
            }
            match handshake.attempt.next(availability) {
                Some(Decision::Use(next)) => {
                    effects.push(Effect::Send {
                        peer_ik,
                        via: next,
                        frame: handshake.frame.clone(),
                    });
                    // Новой попытке — новый срок. Без него молчание второго
                    // транспорта не приводит к третьему, и откат §5.4
                    // обрывается на середине.
                    handshake.timer = None;
                    if next.is_direct() {
                        let token = self.allocate_timer();
                        let after_ms =
                            handshake.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
                        effects.push(Effect::SetTimer { after_ms, token });
                        handshake.timer = Some(token);
                    }
                }
                Some(Decision::Undeliverable) | None => exhausted = true,
            }
        }
        // Исчерпанное рукопожатие выбрасывается. Оставшись, оно не только
        // текло бы памятью, но и блокировало `ensure_handshake`: тот считает
        // запись в `pending` признаком «рукопожатие уже в пути», и следующая
        // попытка связаться с этим контактом не началась бы никогда.
        if exhausted {
            pending.retain(|p| p.peer_ik != peer_ik || !p.attempt.is_finished());
        }
        self.pending = pending;
        Ok((effects, exhausted))
    }

    fn availability_of(&self, peer_ik: &[u8; 32]) -> Result<PeerAvailability, EngineError> {
        Ok(self.contacts.get(peer_ik).ok_or(EngineError::UnknownPeer)?.availability)
    }

    // --- кадры --------------------------------------------------------------

    fn handshake_frame(&mut self, step: u64, message: &[u8]) -> Result<Vec<u8>, EngineError> {
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let header =
            Header::new(FrameType::Handshake, ratatosk_wire::HANDSHAKE_SESSION_ID, step, nonce);

        // Кадр рукопожатия не запечатывается нашим AEAD: его содержимое уже
        // зашифровал Noise. Дополняется он до всей запечатанной области —
        // места под наш тег здесь нет.
        let mut sealed = Vec::new();
        pad_to(message, HANDSHAKE_CLASS.sealed_len(), &mut sealed)?;
        Ok(ratatosk_wire::assemble(&header, &sealed)?)
    }

    fn seal_for(&mut self, session_id: u64, envelope: &[u8]) -> Result<Vec<u8>, EngineError> {
        let class = SizeClass::smallest_for(envelope.len()).ok_or(
            ratatosk_wire::WireError::PayloadTooLarge {
                got: envelope.len(),
                max: SizeClass::L.max_payload(),
            },
        )?;

        let bound = self.sessions.get_mut(session_id).ok_or(EngineError::UnknownPeer)?;
        let (counter, key) = bound.session.send.next();

        // Nonce выводится из счётчика, а не из случайности. Ключ сообщения
        // и так свежий на каждый кадр (§8.4), так что повтора nonce быть
        // не может; зато кадр становится воспроизводимым, а §16 этого и хочет.
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());

        let header = Header::new(FrameType::Data, session_id, counter, nonce);
        let frame = aead::seal(&key, &header, class, envelope)?;

        // Запись до возврата кадра, а не после его отправки: см. пояснение
        // к `persist_session`. Между продвижением цепочки и записью не должно
        // быть ничего, что может не вернуться.
        self.persist_session(session_id)?;
        Ok(frame)
    }

    // --- приём --------------------------------------------------------------

    fn on_frame(
        &mut self,
        now_ms: u64,
        via: Transport,
        frame: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let view = ratatosk_wire::parse(frame)?;

        match self.sessions.route(view.header.session_id) {
            ratatosk_proto::Route::Handshake => {
                let message = unpad(view.sealed)?.to_vec();
                match view.header.counter {
                    HANDSHAKE_STEP_FIRST => self.on_handshake_first(now_ms, via, &message),
                    HANDSHAKE_STEP_RESPONSE => self.on_handshake_response(now_ms, via, &message),
                    _ => Ok(Vec::new()),
                }
            }
            ratatosk_proto::Route::Session(session_id) => {
                let counter = view.header.counter;
                self.on_data(now_ms, via, session_id, counter, frame)
            }
            ratatosk_proto::Route::Unknown => {
                // §7.3, шаг 4: отбросить и посчитать. Источник неизвестен —
                // кадр не расшифрован, — поэтому аномалия пишется на нули.
                self.sessions.note_anomaly([0u8; 32], |c| c.unknown_session += 1);
                Ok(Vec::new())
            }
        }
    }

    fn on_handshake_first(
        &mut self,
        now_ms: u64,
        via: Transport,
        message: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Отказ рукопожатия — не отказ ядра. Почтовый транспорт штатно
        // дублирует письма (§9.2), и повтор обязан быть отброшен так же тихо,
        // как мусорный кадр в §7.3.
        let outcome =
            match Responder::accept(&self.identity, message, &mut self.handshake_guard, now_ms) {
                Ok(outcome) => outcome,
                Err(ratatosk_crypto::CryptoError::HandshakeReplay) => {
                    self.sessions.note_anomaly([0u8; 32], |c| c.handshake_replay += 1);
                    return Ok(Vec::new());
                }
                Err(_) => {
                    self.sessions.note_anomaly([0u8; 32], |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
            };

        // Повтор: сессия уже есть, менять нечего — пересылаем прежний ответ.
        // Именно это спасает контакт, у которого потерялся первый ответ.
        let accepted = match outcome {
            HandshakeOutcome::Established(accepted) => accepted,
            HandshakeOutcome::Repeat { response, peer_ik } => {
                let frame = self.handshake_frame(HANDSHAKE_STEP_RESPONSE, &response)?;
                return Ok(vec![Effect::Send { peer_ik, via, frame }]);
            }
        };
        let Accepted { payload, response, session } = accepted;

        let peer_ik = session.peer_ik;
        let mut effects = Vec::new();

        // В первом сообщении приехала карточка отправителя (§8.2). Контакт
        // остаётся непроверенным: карточка пришла по сети, а не из QR (§4.2).
        if !self.contacts.contains_key(&peer_ik) {
            effects.extend(self.add_contact(now_ms, &payload, false)?);
        }

        let session_id = session.session_id;
        self.supersede(session, SessionBinding::of(via))?;
        self.persist_session(session_id)?;

        let frame = self.handshake_frame(HANDSHAKE_STEP_RESPONSE, &response)?;
        effects.push(Effect::Send { peer_ik, via, frame });
        // После ответа, а не до: пока сессия не подтверждена нашим кадром,
        // отправлять по ней нечего. Сверенному контакту уедет лицо, всем
        // остальным — ничего (§4.2).
        effects.extend(self.offer_avatar(now_ms, peer_ik, via)?);
        // Карточка из первого сообщения (§8.2) применяется только к новому
        // контакту, и у собеседника — то же правило. Значит, наш адрес
        // до него доедет только подписанным обновлением (§4.3).
        effects.extend(self.push_own_card(now_ms, peer_ik)?);
        effects.extend(self.resume_files(now_ms, peer_ik)?);
        Ok(effects)
    }

    fn on_handshake_response(
        &mut self,
        now_ms: u64,
        via: Transport,
        message: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Кто прислал ответ, из кадра не видно, поэтому перебираются
        // незавершённые рукопожатия. Это НЕ trial decryption из §8.3:
        // множество задано нашими собственными отправками и мало, а не
        // всеми контактами и не выбирается атакующим.
        let mut established: Option<Session> = None;
        for candidate in self.pending.iter_mut() {
            if let Ok(session) = candidate.state.finish(message, now_ms) {
                established = Some(session);
                break;
            }
        }

        let Some(session) = established else {
            self.sessions.note_anomaly([0u8; 32], |c| c.handshake_replay += 1);
            return Ok(Vec::new());
        };

        let peer_ik = session.peer_ik;
        let session_id = session.session_id;
        self.pending.retain(|p| p.peer_ik != peer_ik);
        self.supersede(session, SessionBinding::of(via))?;
        // До досылки очереди: `flush_outbox` двигает отправляющую цепочку,
        // и запись должна лечь раньше первого кадра.
        self.persist_session(session_id)?;

        let mut effects = self.flush_outbox(peer_ik)?;
        effects.extend(self.offer_avatar(now_ms, peer_ik, via)?);
        // Мы звали — значит карточка уехала в первом сообщении. Но если
        // собеседник уже знал нас, он её отбросил: см. `push_own_card`.
        effects.extend(self.push_own_card(now_ms, peer_ik)?);
        // Сессия есть — значит связь работает. То, что не уехало раньше,
        // получает свой шанс здесь.
        effects.extend(self.retry_deferred(Some(peer_ik))?);
        // И недокачанные файлы тоже: у получателя нет своего расписания,
        // он спрашивает, когда появляется канал (§10.2).
        effects.extend(self.resume_files(now_ms, peer_ik)?);
        Ok(effects)
    }

    /// Досылает всё, что ждало сессию с этим контактом.
    fn flush_outbox(&mut self, peer_ik: [u8; 32]) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik
                || !matches!(delivery.state, DeliveryState::AwaitingSession)
            {
                continue;
            }
            // Попытка та же самая: транспорт уже выбран, не хватало сессии.
            // Новый вызов `attempt.next` здесь съел бы транспорт зря.
            effects.extend(self.resend_current(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Отправляет сообщение тем транспортом, который уже выбран попыткой.
    fn resend_current(&mut self, delivery: &mut Delivery) -> Result<Vec<Effect>, EngineError> {
        let Some(&transport) = delivery.attempt.tried().last() else {
            return self.advance(delivery);
        };
        let Some(session_id) = self.sessions.for_peer(&delivery.peer_ik, transport) else {
            return Ok(Vec::new());
        };

        let frame = self.seal_for(session_id, &delivery.envelope)?;
        let mut effects = vec![Effect::Send { peer_ik: delivery.peer_ik, via: transport, frame }];

        if transport.is_direct() {
            let timer = self.allocate_timer();
            let after_ms = delivery.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            delivery.state = DeliveryState::InFlight { via: transport, timer };
            effects.push(Effect::SetTimer { after_ms, token: timer });
        } else {
            delivery.attempt.succeed();
            effects.extend(self.note_status(delivery.msg_id, DeliveryStatus::Sent)?);
        }
        Ok(effects)
    }

    /// Откладывает попытку до ответа обнаружения — или не откладывает.
    ///
    /// Возвращает `Some(таймер)`, если ждать есть чего. Условий три, и все
    /// обязательны: LAN включён (иначе ждать нечего), собеседника в эфире
    /// ещё не слышали, и срок ему в этом сеансе ещё не выдавался. Последнее
    /// важнее, чем кажется: без него каждое сообщение собеседнику из другой
    /// сети начиналось бы с трёхсекундной паузы.
    fn park_for_discovery(&mut self, delivery: &mut Delivery) -> Option<Effect> {
        if !self.lan_enabled || !delivery.attempt.tried().is_empty() {
            return None;
        }
        let contact = self.contacts.get(&delivery.peer_ik)?;
        if contact.availability.seen_on_lan {
            return None;
        }
        if !self.awaited_discovery.insert(delivery.peer_ik) {
            return None;
        }

        let timer = self.allocate_timer();
        delivery.state = DeliveryState::AwaitingDiscovery { timer };
        Some(Effect::SetTimer { after_ms: LAN_DISCOVERY_GRACE_MS, token: timer })
    }

    /// Обнаружение ответило (или кончился срок) — двигаем отложенное.
    ///
    /// Вызывается и по маяку, и по таймеру: разница только в том, окажется ли
    /// LAN доступен на следующем шаге. Решает это [`Attempt`], а не эта
    /// функция, — здесь только снимается пауза.
    fn resume_discovery(&mut self, peer_ik: [u8; 32]) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik
                || !matches!(delivery.state, DeliveryState::AwaitingDiscovery { .. })
            {
                continue;
            }
            // Состояние снимается до `advance`: иначе `park_for_discovery`
            // увидел бы нетронутую попытку и отложил её второй раз.
            delivery.state = DeliveryState::AwaitingSession;
            effects.extend(self.advance(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Запоминает сообщение, которому некуда было ехать.
    ///
    /// Попытка сбрасывается: когда сеть вернётся, §5.4 начнётся заново —
    /// с локальной сети, а не с того транспорта, на котором всё кончилось.
    /// Возвращает «запомнили ли» и события про вытесненное из очереди.
    fn remember_undelivered(
        &mut self,
        delivery: &Delivery,
    ) -> Result<(bool, Vec<Effect>), EngineError> {
        // Ждать имеет смысл только если что-то может измениться. Условий два,
        // и оба необходимы.
        //
        // Контакт должен существовать: удалённому отправлять некому.
        let Some(contact) = self.contacts.get(&delivery.peer_ik) else {
            return Ok((false, Vec::new()));
        };
        // И должен быть хоть один путь, который когда-нибудь может открыться:
        // включённая локальная сеть (собеседник появится в эфире) либо адрес
        // в карточке (§4.1). Если LAN выключен, а адресов в карточке нет,
        // ждать нечего в буквальном смысле — и обещать «отправим позже» было бы
        // выдумкой. Тогда это «не доставлено», без обещаний.
        let availability = contact.availability;
        if !availability.lan_enabled && !availability.has_onion && !availability.has_chatmail {
            return Ok((false, Vec::new()));
        }
        if self.deferred.iter().any(|d| d.msg_id == delivery.msg_id) {
            return Ok((true, Vec::new()));
        }

        let mut effects = Vec::new();
        if self.deferred.len() >= MAX_DEFERRED {
            // Вытесняется самое старое: у свежего больше шансов ещё быть
            // нужным человеку. И вытесненному честно меняется статус —
            // обещание «отправим позже» снимается вместе с очередью, и UI
            // об этом узнаёт. Молча оставить «ждём» у сообщения, к которому
            // никто больше не вернётся, значит соврать на экране.
            let evicted = self.deferred.remove(0);
            self.store.delete_outbox(&evicted.msg_id)?;
            effects.extend(self.note_status(evicted.msg_id, DeliveryStatus::Undeliverable)?);
        }

        // На диск — до того, как объявлен статус. Обещание, которого нет
        // в базе, не переживёт убитый процесс, а на экране останется.
        self.store.put_outbox(&ratatosk_store::StoredOutbox {
            msg_id: delivery.msg_id,
            recipient_ik: delivery.peer_ik,
            envelope: delivery.envelope.clone(),
            queued_ms: delivery.queued_ms,
        })?;

        let mut waiting = delivery.clone();
        waiting.attempt = Attempt::new();
        waiting.state = DeliveryState::AwaitingSession;
        waiting.session_reset_used = false;
        self.deferred.push(waiting);
        Ok((true, effects))
    }

    /// Пробует отправить заново то, что ждало случая.
    ///
    /// Зовётся на событиях, которые действительно меняют шансы: сеть
    /// сменилась, контакт объявился в эфире, сессия установилась. По таймеру
    /// — никогда: у ядра нет часов, а опрос на телефоне стоит батареи (§14).
    fn retry_deferred(&mut self, peer_ik: Option<[u8; 32]>) -> Result<Vec<Effect>, EngineError> {
        if self.deferred.is_empty() {
            return Ok(Vec::new());
        }
        let (ready, waiting): (Vec<Delivery>, Vec<Delivery>) = std::mem::take(&mut self.deferred)
            .into_iter()
            .partition(|d| peer_ik.is_none_or(|only| d.peer_ik == only));
        self.deferred = waiting;

        let mut effects = Vec::new();
        for delivery in ready {
            // Контакт мог быть удалён, пока сообщение ждало: тогда ехать
            // некому, и обещание надо снять — вместе с записью на диске.
            if !self.contacts.contains_key(&delivery.peer_ik) {
                self.store.delete_outbox(&delivery.msg_id)?;
                effects.extend(self.note_status(delivery.msg_id, DeliveryStatus::Undeliverable)?);
                continue;
            }
            // Запись на диске остаётся до подтверждения: попытка может опять
            // не удаться, и тогда сообщение снова ляжет в ожидание — без
            // повторной записи, потому что она уже там.
            effects.extend(self.enqueue(delivery)?);
        }
        Ok(effects)
    }

    /// Прямой канал отказал — переходим к следующему транспорту (§5.4).
    fn on_delivery_failed(
        &mut self,
        peer_ik: [u8; 32],
        via: Transport,
        why: Failure,
    ) -> Result<Vec<Effect>, EngineError> {
        // Молчание в ответ на ушедший кадр — единственная причина закрыть
        // сессию. Закрываем **до** переноса попытки: следующий шаг должен
        // увидеть, что сессии нет, и начать рукопожатие.
        let stale_session =
            why == Failure::Silent && via.is_direct() && self.drop_session(&peer_ik, via)?;

        // Адрес в локальной сети забывается только при **явном** отказе:
        // соединиться не удалось — значит устройства там больше нет.
        //
        // При молчании — наоборот, не забывается: запись в сокет удалась,
        // то есть по этому адресу кто-то слушает. Забыв его здесь, мы увели
        // бы следующую попытку с LAN на транспорты, которых может и не быть,
        // — и вместо переустановки сессии получили бы «не доставлено».
        if why == Failure::Reported && via == Transport::Lan {
            if let Some(contact) = self.contacts.get_mut(&peer_ik) {
                contact.availability.seen_on_lan = false;
            }
        }

        // Рукопожатие переносится первым: без сессии данные всё равно
        // упрутся в ожидание, и порядок эффектов станет непонятным.
        let (mut effects, handshake_exhausted) = self.retry_handshake(peer_ik, via)?;
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik {
                continue;
            }
            let failed_here = match delivery.state {
                DeliveryState::InFlight { via: v, .. } => v == via,
                // Сообщение ждало сессии, а рукопожатию идти больше некуда.
                // Ждать нечего: попытка обязана дойти до конца и объявить
                // исход, иначе сообщение зависает в очереди навсегда — ровно
                // то молчание, которое §14 запрещает.
                DeliveryState::AwaitingSession => handshake_exhausted,
                // Это сообщение ещё не выходило в сеть и потому здесь ничего
                // не теряло: у него свой срок, и снимет паузу он, а не чужой
                // отказ. Тронуть его тут значило бы сжечь LAN за компанию —
                // как раз тогда, когда собеседник вот-вот найдётся.
                DeliveryState::AwaitingDiscovery { .. } => false,
            };
            if !failed_here {
                continue;
            }

            // Сессия оказалась несогласованной — даём этому сообщению ещё
            // один заход по тому же транспорту, но через новое рукопожатие.
            // Это не повтор в смысле §5.4 (тот запрещает повторять транспорт
            // после отказа): отказал не транспорт, а сессия, и заменив её,
            // мы пробуем впервые. Ровно один раз на сообщение — иначе два
            // узла с расходящимся состоянием гоняли бы рукопожатия по кругу.
            if stale_session && !delivery.session_reset_used {
                delivery.session_reset_used = true;
                delivery.attempt = Attempt::new();
                delivery.state = DeliveryState::AwaitingSession;
            }
            effects.extend(self.advance(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Сработал таймер попытки: подтверждения нет — попытка не удалась.
    ///
    /// **Раньше здесь выставлялось «отправлено», и это была ошибка.** Прямой
    /// канал подтверждает доставку квитанцией за миллисекунды (§9.4); если
    /// за отведённое время её нет, значит кадр не дошёл. Объявлять при этом
    /// успех — не просто неточность в индикаторе: попытка закрывалась, и
    /// откат на следующий транспорт по §5.4 **не запускался вовсе**. Молча
    /// исчезнувший собеседник получался неотличим от ответившего, и запись
    /// в сокет это не ловит — ядро принимает её в буфер и для мёртвого узла.
    ///
    /// Поэтому таймер идёт тем же путём, что и явный отказ: это одно и то же
    /// событие для §5.4 — «здесь не вышло, пробуем дальше».
    ///
    /// Запоздавшая квитанция ничего не ломает: `receipts::advance` разрешает
    /// перейти от объявленного провала к подтверждённой доставке, а лишнюю
    /// копию у получателя съест дедупликация (§9.2).
    fn on_timer(&mut self, now_ms: u64, token: u64) -> Result<Vec<Effect>, EngineError> {
        // Срок обнаружения — не отказ транспорта, а конец паузы: §5.4 ещё
        // не начинался. Поэтому он разбирается отдельно и раньше.
        let awaiting_discovery = self.outbox.iter().find_map(|d| match d.state {
            DeliveryState::AwaitingDiscovery { timer } if timer == token => Some(d.peer_ik),
            _ => None,
        });
        if let Some(peer_ik) = awaiting_discovery {
            return self.resume_discovery(peer_ik);
        }

        // Срок молчания по файлу — не отказ транспорта и не конец паузы
        // доставки: чанки идут мимо очереди §5.4, и путать их сроки с её
        // сроками нельзя.
        let stalled_file =
            self.file_timers.iter().find(|(_, armed)| **armed == token).map(|(id, _)| *id);
        if let Some(file_id) = stalled_file {
            self.file_timers.remove(&file_id);
            return self.on_file_stall(now_ms, file_id);
        }

        // Один и тот же счётчик меток обслуживает и рукопожатия, и доставку,
        // поэтому владельца ищем в обоих местах.
        let waiting = self
            .pending
            .iter()
            .find(|p| p.timer == Some(token))
            .and_then(|p| p.attempt.tried().last().map(|via| (p.peer_ik, *via)))
            .or_else(|| {
                self.outbox.iter().find_map(|d| match d.state {
                    DeliveryState::InFlight { via, timer } if timer == token => {
                        Some((d.peer_ik, via))
                    }
                    _ => None,
                })
            });

        // Метка без владельца — обычное дело: доставка могла завершиться
        // квитанцией раньше срока, и таймер просто опоздал.
        let Some((peer_ik, via)) = waiting else {
            return Ok(Vec::new());
        };
        // Сюда приходят только по истечении срока, то есть кадр ушёл,
        // а подтверждения нет.
        self.on_delivery_failed(peer_ik, via, Failure::Silent)
    }

    fn on_data(
        &mut self,
        now_ms: u64,
        via: Transport,
        session_id: u64,
        counter: u64,
        frame: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let bound = self.sessions.get_mut(session_id).ok_or(EngineError::UnknownPeer)?;
        let peer_ik = bound.session.peer_ik;

        // §7.3, шаг 3: ключ выводится ровно для позиции `counter`, и только
        // после успешной проверки тега достраиваются пропущенные.
        let key = match bound.session.recv.peek(counter) {
            Ok(key) => key,
            // Ключ этой позиции уже израсходован — значит кадр в точности
            // повторяет уже принятый. Ретчет отказывает по построению, и это
            // главная защита от повтора: она не зависит ни от окна
            // дедупликации, ни от базы.
            //
            // Аномалией это не считается. Точный повтор кадра — штатный режим
            // §9.2: почта дублирует письма, и записывать за это исправного
            // собеседника в подозрительные значит однажды закрыть сессию
            // ни за что.
            //
            // Квитанцию отсюда отправить нельзя, и не по недосмотру: чтобы
            // узнать, о каком сообщении речь, кадр нужно расшифровать, а ключа
            // больше нет. Настоящую повторную отправку — новый кадр с тем же
            // `msg_id` — подтверждает дедупликация ниже, и именно она случается
            // на практике: отправитель, не получивший квитанцию, шлёт сообщение
            // заново и запечатывает его следующим ключом цепочки.
            Err(ratatosk_crypto::CryptoError::MessageKeyConsumed) => return Ok(Vec::new()),
            Err(_) => {
                self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
                return Ok(Vec::new());
            }
        };

        let opened = aead::open(&key, frame);
        let (_, plaintext) = match opened {
            Ok(v) => v,
            Err(_) => {
                self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
                return Ok(Vec::new());
            }
        };

        let bound = self.sessions.get_mut(session_id).expect("сессия только что была");
        bound.session.recv.commit(counter, now_ms)?;
        self.persist_session(session_id)?;

        let envelope = Envelope::decode(&plaintext)?.into_parts().1;

        // §9.2: одно сообщение может законно прийти дважды — разными
        // транспортами или повторной отправкой. Это нормальный режим, а не
        // ошибка. Здесь дубль — всегда **другой кадр с тем же `msg_id`**:
        // точный повтор кадра до этого места не доходит, его отвергает ретчет
        // (см. выше), а отправитель, посылающий сообщение заново, каждый раз
        // запечатывает его новым ключом цепочки.
        //
        // **И подтвердить дубль обязаны.** Раньше он отбрасывался молча, и это
        // была настоящая поломка, а не мелочь. §9.2 говорит о том, что дубль
        // не показывают пользователю **дважды**; квитанция — не показ, а факт:
        // «сообщение у меня». Для дубля этот факт верен тем более.
        //
        // Чем молчание обходилось: отправитель, не получивший первую квитанцию
        // (оборвалась связь, убили процесс, перезапустили приложение), считал
        // сообщение неотправленным и присылал его снова. Мы съедали копию
        // и не отвечали — и он снова считал, что не дошло. Сообщение навсегда
        // оставалось «ждёт» у отправителя и лежало прочитанным у получателя,
        // а каждое появление в сети приводило к очередной бесполезной отправке.
        // Чанк файла в окно дедупликации не кладётся, и это не исключение
        // из §9.2, а его прочтение. Окно защищает **показ**: одно сообщение —
        // один раз на экране. У чанка показа нет; повтор его безвреден (те же
        // байты лягут в то же место), а две тысячи идентификаторов на файл
        // забили бы и окно, и таблицу `dedup` тем, что никогда не понадобится.
        if envelope.payload_type == PayloadType::FileChunk {
            return self.deliver(now_ms, via, peer_ik, envelope);
        }

        let fresh = self.dedup.check(envelope.msg_id, now_ms).is_fresh()
            && self.store.note_seen(&envelope.msg_id, now_ms)?;
        if !fresh {
            // Отвечаем тем, что есть на самом деле. Если пользователь уже
            // дочитал до этого места (§9.4), то и говорить надо «прочитано»:
            // водяной знак прочтения не даст отправить эту квитанцию второй
            // раз, и без ответа здесь отправитель никогда бы о ней не узнал.
            let chat = Self::chat_id_for(&peer_ik);
            let receipt = if self.read_upto.get(&chat).is_some_and(|edge| *edge >= envelope.hlc) {
                Receipt::Read
            } else {
                Receipt::Delivered
            };
            return self.send_receipt(now_ms, peer_ik, via, receipt, &[envelope.msg_id]);
        }

        // §9.1: метка из далёкого будущего отбрасывается вместе с сообщением.
        let Ok(_) = self.clock.observe(now_ms, envelope.hlc) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };

        self.deliver(now_ms, via, peer_ik, envelope)
    }

    /// Кладёт принятый текст в историю и подтверждает приём.
    ///
    /// Одно место на обычное сообщение, пересланное и ответ: различаются они
    /// только пометками ([`TextKind`]), а разведённые по трём функциям однажды
    /// разошлись бы в чём-то большем — например, в том, отправлена ли
    /// квитанция.
    fn on_incoming_text(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
        text: &str,
        kind: TextKind,
    ) -> Result<Vec<Effect>, EngineError> {
        let chat = Self::chat_id_for(&peer_ik);
        self.remember(&StoredMessage {
            msg_id: envelope.msg_id,
            chat_id: chat,
            sender_ik: peer_ik,
            hlc: envelope.hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // У принятого сообщения статуса нет: статус — это судьба
            // отправки, а оно уже здесь.
            status: None,
            edited_ms: None,
            forwarded: kind.forwarded(),
            reply_to: kind.reply_to(),
        })?;

        let mut effects =
            vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })];
        // §9.4: квитанция о доставке — сразу и только прямым каналом.
        // «Доставлено» означает ровно то, что кадр принят и расшифрован,
        // и узнать это может только получатель.
        effects.extend(self.send_receipt(
            now_ms,
            peer_ik,
            via,
            Receipt::Delivered,
            &[envelope.msg_id],
        )?);
        Ok(effects)
    }

    /// Пришло пересланное сообщение.
    ///
    /// Отличается от обычного одной пометкой в истории — и тем, что пометка
    /// **обязательна**: без неё чужие слова выглядят словами собеседника.
    /// Автора здесь нет и быть не может: при пересылке подпись §6 не
    /// сохраняется, и указать его можно было бы только на словах.
    fn on_forwarded(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let text = Self::text_of(envelope)?;
        self.on_incoming_text(now_ms, via, peer_ik, envelope, &text, TextKind::Forwarded)
    }

    /// Пришёл ответ на сообщение.
    ///
    /// Ссылка **мягкая**, и это существенно. Цели может не быть вовсе: ответ
    /// мог опередить исходное сообщение (§9.2 — приход не равен порядку) или
    /// пережить его удаление. Терять из-за этого текст нельзя: ответ — это
    /// слова человека, а цитата — только контекст к ним. Ссылка сохраняется
    /// как есть, а «сообщение недоступно» скажет UI.
    ///
    /// Отвергается один случай: ссылка на сообщение, которое у нас есть,
    /// но **в другом чате**. Назвать такой `msg_id` собеседник не мог бы,
    /// не зная того, чего ему знать неоткуда, — поэтому это аномалия сессии.
    /// Текст и здесь сохраняется, теряется только ссылка.
    fn on_replied(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, text) = ratatosk_proto::reply::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let kind = match self.store.message(&target)? {
            Some(known) if known.chat_id != chat => {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                TextKind::Plain
            }
            _ => TextKind::Reply(target),
        };
        self.on_incoming_text(now_ms, via, peer_ik, envelope, &text, kind)
    }

    /// Достаёт текст из конверта обычного или пересланного сообщения.
    fn text_of(envelope: &Envelope) -> Result<String, EngineError> {
        let Value::Text(text) = &envelope.payload else {
            return Err(ratatosk_codec::CodecError::TypeMismatch.into());
        };
        Ok(text.clone())
    }

    fn deliver(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        match envelope.payload_type {
            PayloadType::Text => {
                let text = Self::text_of(&envelope)?;
                self.on_incoming_text(now_ms, via, peer_ik, &envelope, &text, TextKind::Plain)
            }
            PayloadType::Forward => self.on_forwarded(now_ms, via, peer_ik, &envelope),
            PayloadType::Reply => self.on_replied(now_ms, via, peer_ik, &envelope),
            PayloadType::Avatar => self.on_avatar(via, peer_ik, &envelope),
            PayloadType::Retract => self.on_retract(now_ms, via, peer_ik, &envelope),
            PayloadType::Edit => self.on_edit(now_ms, via, peer_ik, &envelope),
            PayloadType::Reaction => self.on_reaction(now_ms, via, peer_ik, &envelope),
            // Неизвестный тип не повод терять сообщение целиком, но и
            // показать его нечем: молча пропускаем (§9.1).
            PayloadType::Unknown(_) => Ok(Vec::new()),
            PayloadType::FileOffer => self.on_file_offer(now_ms, via, peer_ik, &envelope),
            PayloadType::FileChunk => self.on_file_chunk(now_ms, via, peer_ik, &envelope),
            PayloadType::FileRequest => self.on_file_request(now_ms, peer_ik, &envelope),
            PayloadType::ContactShare => self.on_contact_share(now_ms, via, peer_ik, &envelope),
            // §10.3 отдаёт превью вместе с предложением файла, отдельным кадром
            // оно не ездит. Тип остаётся в перечислении, потому что он есть
            // в спецификации, а молча принимать то, чего мы не отправляем,
            // незачем.
            PayloadType::Preview => Ok(Vec::new()),
            PayloadType::Receipt => {
                let (receipt, msg_ids) = Receipt::from_payload(&envelope.payload)?;
                let candidate = match receipt {
                    Receipt::Delivered => DeliveryStatus::Delivered,
                    Receipt::Read => DeliveryStatus::Read,
                };
                // §9.4: квитанция, пришедшая не прямым каналом, не применяется.
                // Своя проверка, а не доверие отправителю: транспорт знаем мы,
                // и подделать его он не может.
                if !ratatosk_proto::receipts::may_send_receipt(via) {
                    self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }

                let mut effects = Vec::new();
                for msg_id in &msg_ids {
                    effects.extend(self.note_status(*msg_id, candidate)?);
                }

                // Доставка подтверждена — запись из очереди уходит, и её
                // таймер остаётся без владельца. Оставить её значит дождаться
                // срока и объявить провал у сообщения, которое уже прочитано.
                self.outbox.retain(|d| !msg_ids.contains(&d.msg_id));
                Ok(effects)
            }
            PayloadType::GroupMembership | PayloadType::SenderKey => {
                todo!("этап 5: группы (§11)")
            }
            PayloadType::CardUpdate => self.on_card_update(now_ms, peer_ik, &envelope),
        }
    }
}

// Поля, к которым ядро обратится на следующих этапах.
impl<S: Store> Engine<S> {
    /// Политика перерукопожатия (§8.5) — понадобится на этапе 1.
    #[must_use]
    pub fn rekey_policy(&self) -> &RekeyPolicy {
        &self.rekey
    }

    /// Сборщик фрагментов (§9.3) — понадобится на этапе 4.
    #[must_use]
    pub fn reassembler(&self) -> &Reassembler {
        &self.reassembler
    }

    /// Последняя выданная метка часов — для отладки порядка (§9.1).
    #[must_use]
    pub fn clock_last(&self) -> Hlc {
        self.clock.last()
    }

    /// Видели ли идентификатор в окне дедупликации (§9.2).
    #[must_use]
    pub fn has_seen(&self, msg_id: &MsgId) -> bool {
        self.dedup.contains(msg_id)
    }

    /// Число установленных сессий.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
