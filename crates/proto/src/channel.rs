//! Представление канала — подписанный владельцем документ с версией
//! (фаза 2, §3.1, §6.1–§6.3).
//!
//! Всё, что о канале договорено, лежит здесь: порода, название, права,
//! сложность PoW, окно сидирования. Не «настройки у владельца», а документ,
//! который каждый подписчик проверяет сам и по которому судит о чужих
//! записях.
//!
//! # Почему документ, а не набор блоков
//!
//! Право снимают, а снятие — отрицательное утверждение: «этого больше
//! нет». Отдельными блоками его не выразить, потому что **неприход
//! надгробия неотличим от «не отзывали»** — а в рое неприход штатен.
//! Версионированный документ этого лишён: пришла версия новее — в ней
//! написано всё, что действует; не пришла — действует прежняя.
//!
//! # Что даёт версия
//!
//! Три вещи разом, и каждая требует именно монотонного номера: снятие
//! права, глубина истории и сложность PoW. Ссылка на канал называет
//! **минимальную** версию (§10.1), и подписка на версии ниже неё
//! отвергается — так старая ссылка перестаёт пускать, когда владелец
//! закрыл дверь.
//!
//! # Чего здесь нет
//!
//! **Правки представления не-владельцем.** §6.2 разрешает держателю права
//! «менять представление» править описательные поля, и это здесь
//! не выражено — нарочно. Проверить такую правку в одиночку нельзя:
//! права лежат внутри документа, и подписанный не-владельцем документ
//! доказывал бы своё право сам собой. Правило обязано опираться
//! на **прежнюю** принятую версию — то есть быть правилом о переходе,
//! а не о документе, — и в спеке его пока нет. Поэтому здесь подписывает
//! владелец, и только он.

use ratatosk_codec::{canonical, Value};
use ratatosk_crypto::{Identity, PublicIdentity};

use ratatosk_crdt::ActorId;

use crate::group::GroupId;

const KEY_GROUP: u64 = 1;
const KEY_OWNER: u64 = 2;
const KEY_VERSION: u64 = 3;
const KEY_KIND: u64 = 4;
const KEY_TITLE: u64 = 5;
const KEY_POW: u64 = 6;
const KEY_SEED_DAYS: u64 = 7;
const KEY_SEED_BYTES: u64 = 8;
const KEY_GRANTS: u64 = 9;
const KEY_WHO: u64 = 10;
const KEY_RIGHTS: u64 = 11;
const KEY_UNTIL: u64 = 12;
const KEY_BLOCK: u64 = 13;
const KEY_SIGNATURE: u64 = 14;

/// Наибольшая длина названия канала в байтах.
///
/// **Ровно [`crate::group::MAX_GROUP_TITLE_BYTES`], и не числом, а ссылкой.**
/// Название канала и название группы показываются в одном и том же списке
/// чатов и вводятся в одно и то же поле; разойдись пределы — человек
/// однажды получил бы два разных ответа на «почему не влезает».
///
/// Стояло здесь 128 с комментарием «то же число, что у группы», и это
/// было просто неверно: у группы 256. Разница не теоретическая — 256
/// это потолок шестидесяти четырёх символов по четыре байта
/// (`ratatosk_core::MAX_GROUP_TITLE_CHARS`), то есть предел, при котором
/// **любое** название, законное в поле ввода, влезает. При 128 канал
/// отвергал бы названия из эмодзи, законные для группы, и объяснить это
/// человеку было бы нечем.
pub const MAX_TITLE_BYTES: usize = crate::group::MAX_GROUP_TITLE_BYTES;

/// Сложность PoW у только что заведённого канала (§11).
///
/// **Ноль, и это не осторожность, а честность.** PoW не собран: поставь
/// мы здесь число, представление обещало бы фильтр, которого нет,
/// и подписчик, проверяющий документ, считал бы защищённым то, что
/// не защищено. Поднять сложность владелец сможет новой версией — §11
/// прямо на это и рассчитывает («можно поднять при наплыве»).
pub const DEFAULT_POW_BITS: u32 = 0;

/// Окно сидирования у нового канала — суток (§9.3).
///
/// **Умолчание, а не правило: спека числа не называет.** Месяц взят
/// не с потолка — это шаг, которым живут сроки §6.3 (поворот ключа раз
/// в месяц), и окно короче него означало бы, что новый читатель
/// не застаёт даже одного поколения архива целиком.
pub const DEFAULT_SEED_DAYS: u32 = 30;

/// Окно сидирования у нового канала — байт (§9.3).
///
/// **Умолчание, а не правило.** §9.3 требует сказать человеку прямо:
/// на его устройстве лежат байты, которых он не выбирал и не может
/// прочесть, и раздаёт он их своим трафиком. Четверть гигабайта —
/// то, что можно назвать вслух, не пряча в мелкий шрифт; владелец
/// вправе поднять, а участник — хранить дольше, но не меньше.
pub const DEFAULT_SEED_BYTES: u64 = 256 * 1024 * 1024;

/// Сколько выдач прав помещается в одно представление.
///
/// Предел проверяется **на приёме**: длину называет та сторона провода,
/// и «миллион выдач» — это запрос памяти, а не список прав. То же правило,
/// что у состава группы.
pub const MAX_GRANTS: usize = 64;

/// Порода канала — решается при создании и не меняется (§6.1).
///
/// Переход между породами не предусмотрен: это разные обещания. В открытом
/// ключ чтения лежит в ссылке, и отобрать его нельзя ни у кого; в канале
/// по приглашению впускает владелец поимённо. Сменить одно на другое
/// значит завести новый канал — так и надо говорить человеку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Ключ чтения лежит в ссылке. Подписка мгновенна, владелец не участвует.
    Open,
    /// Ключ выдаёт владелец. Заявка, впуск, поворот ключа при исключении.
    ByInvite,
}

impl Kind {
    /// Код для хранения и провода. Менять нельзя: он лежит в чужих базах.
    ///
    /// Нуля среди кодов нет нарочно: порода — не то, что бывает
    /// «не задано», а `0` в целочисленном столбце получается сам собой
    /// при всякой ошибке. Пусть такая ошибка отказывает, а не читается
    /// как открытый канал.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Kind::Open => 1,
            Kind::ByInvite => 2,
        }
    }

    /// Обратно из кода. `None` — незнакомая порода.
    ///
    /// Прочесть незнакомую как одну из известных значило бы пообещать
    /// не то: порода решает, отбирается ли доступ обратно (§6.1).
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Kind> {
        match code {
            1 => Some(Kind::Open),
            2 => Some(Kind::ByInvite),
            _ => None,
        }
    }
}

/// Права, которые владелец раздаёт (§6.2).
///
/// Набор битов, а не список строк: он едет в каждом представлении,
/// и неизвестное право сборка постарше обязана **сохранить**, а не
/// потерять. Биты это дают даром — незнакомый бит переживает разбор
/// и запись.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rights(u32);

impl Rights {
    /// Публиковать в канал.
    pub const WRITE: Rights = Rights(1);
    /// Выдавать ключ чтения (§6.5).
    pub const ADMIT: Rights = Rights(2);
    /// Поворачивать ключ чтения, отсекая невписанных (§6.4).
    pub const EVICT: Rights = Rights(4);
    /// Править описательные поля представления.
    pub const EDIT: Rights = Rights(8);

    /// Ничего.
    #[must_use]
    pub const fn none() -> Rights {
        Rights(0)
    }

    /// Все четыре — то, что есть у владельца и чего он не может лишиться.
    #[must_use]
    pub const fn all() -> Rights {
        Rights(1 | 2 | 4 | 8)
    }

    /// Входит ли право в набор — **целиком**.
    #[must_use]
    pub const fn has(self, right: Rights) -> bool {
        self.0 & right.0 == right.0
    }

    /// Есть ли хоть одно из перечисленных прав.
    ///
    /// Нужно там, где одно и то же действие законно по разным причинам.
    /// Так у выдачи ключа чтения: её делает и тот, кто впускает (§6.2 —
    /// «выдавать ключ чтения»), и тот, кто поворачивает («поворачивать
    /// ключ, отсекая невписанных»). Требуй мы обоих прав, поворот стал бы
    /// невозможен для того, кому дали только его.
    ///
    /// Пустой набор прав не проходит: `has_any(none())` — ложь, тогда как
    /// `has(none())` истина. Разница намеренная, и имена о ней говорят.
    #[must_use]
    pub const fn has_any(self, rights: Rights) -> bool {
        self.0 & rights.0 != 0
    }

    /// Объединение.
    #[must_use]
    pub const fn with(self, right: Rights) -> Rights {
        Rights(self.0 | right.0)
    }

    /// Сырые биты — для хранения и провода.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Из сырых битов. Незнакомые сохраняются (см. заголовок типа).
    #[must_use]
    pub const fn from_bits(bits: u32) -> Rights {
        Rights(bits)
    }
}

/// Выдача права одному человеку, со сроком (§6.2, §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// Кому.
    pub who: ActorId,
    /// Что может.
    pub rights: Rights,
    /// До какого момента, мс от эпохи.
    ///
    /// **Срок, а не отзыв** (§6.3). Не продлил — истекло само, и молчание
    /// владельца отказывает вниз, а не вверх: в рое неприход надгробия
    /// штатен, и отзыв, который не доехал, выглядел бы как право.
    pub until_ms: u64,
}

impl Grant {
    /// Действует ли выдача в этот момент.
    #[must_use]
    pub const fn live_at(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }
}

/// Представление канала — то, что подписывает владелец.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Representation {
    /// Идентификатор канала, 16 байт. Случайный и лежит **внутри** (§3.1).
    pub group: GroupId,
    /// Чья подпись действительна над этим документом.
    pub owner: ActorId,
    /// Монотонный номер. Ссылка называет минимальный (§10.1).
    pub version: u64,
    /// Порода — при создании и навсегда (§6.1).
    pub kind: Kind,
    /// Название, которое видит подписчик.
    pub title: String,
    /// Сложность PoW на запись (§11). Ноль — не требуется.
    pub pow_bits: u32,
    /// Окно сидирования: сколько суток хранить (§9.3).
    pub seed_days: u32,
    /// Окно сидирования: сколько байт хранить (§9.3).
    pub seed_bytes: u64,
    /// Кому что выдано. Владельца здесь нет: у него всё и всегда.
    pub grants: Vec<Grant>,
}

impl Representation {
    /// Что этот человек вправе делать в этот момент.
    ///
    /// Владельцу — всё, и лишить его нельзя (5вп): правило стоит здесь,
    /// а не у вызывающего, потому что мест, где спрашивают про права,
    /// будет много, а правило одно.
    #[must_use]
    pub fn rights_of(&self, who: &ActorId, now_ms: u64) -> Rights {
        rights_from(&self.owner, &self.grants, who, now_ms)
    }

    /// Вправе ли он писать в канал прямо сейчас.
    #[must_use]
    pub fn may_write(&self, who: &ActorId, now_ms: u64) -> bool {
        self.rights_of(who, now_ms).has(Rights::WRITE)
    }
}

/// Что этот человек вправе делать, по владельцу и списку выдач.
///
/// # Зачем свободной функцией, а не только методом
///
/// На диске выдачи лежат **разобранными**, отдельной таблицей: иначе
/// «вправе ли он писать» означало бы разбор CBOR на каждое входящее
/// сообщение. Спрашивать права оттуда придётся, и собирать ради этого
/// поддельное [`Representation`] значило бы либо сочинять недостающие
/// поля, либо завести второе место, где живёт правило «владельцу всё,
/// истёкшее не считается».
///
/// [`Representation::rights_of`] зовёт эту же функцию, так что мест
/// по-прежнему одно.
#[must_use]
pub fn rights_from(owner: &ActorId, grants: &[Grant], who: &ActorId, now_ms: u64) -> Rights {
    // Владельцу всё, и лишить его нельзя (5вп). Проверка стоит **до**
    // списка: окажись владелец в нём с урезанным набором, список не должен
    // мочь его урезать.
    if *who == *owner {
        return Rights::all();
    }
    grants
        .iter()
        .filter(|grant| grant.who == *who && grant.live_at(now_ms))
        .fold(Rights::none(), |acc, grant| acc.with(grant.rights))
}

/// Разобранное, но **непроверенное** представление.
///
/// Существует затем же, зачем `group::Unchecked`: проверку подписи нельзя
/// пропустить молча. [`Representation`] достаётся только через
/// [`UncheckedRepresentation::verify`], и та забирает значение целиком.
#[derive(Debug, Clone)]
pub struct UncheckedRepresentation {
    representation: Representation,
    signature: [u8; 64],
    signed: Vec<u8>,
}

impl UncheckedRepresentation {
    /// Какого канала — чтобы найти его до проверки.
    #[must_use]
    pub const fn claims_group(&self) -> &GroupId {
        &self.representation.group
    }

    /// Чьей подписи ждать, по словам самого документа.
    ///
    /// Значение **заявленное**: верить ему можно только сверив с тем
    /// `owner_ik`, что приехал из ссылки (§10.3, шаг 3). Документ,
    /// назвавший владельцем себя, проверку своей же подписью пройдёт.
    #[must_use]
    pub const fn claims_owner(&self) -> &ActorId {
        &self.representation.owner
    }

    /// Какая версия заявлена — для правила «не ниже, чем в ссылке» (§10.3).
    #[must_use]
    pub const fn claims_version(&self) -> u64 {
        self.representation.version
    }

    /// Байты, над которыми считана подпись, — **как приняли**.
    ///
    /// Нужны тому, кто кладёт документ на диск: хранить надо именно их
    /// (§6). Собери их заново из разобранного — и расхождение
    /// канонизации на один байт превратило бы законный документ
    /// в испорченный после первого же перезапуска.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }

    /// Подпись, как приехала.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Проверяет подпись **названным** ключом и отдаёт представление.
    ///
    /// # Errors
    ///
    /// [`ChannelError::BadSignature`] — подпись не сошлась.
    pub fn verify(self, owner: &PublicIdentity) -> Result<Representation, ChannelError> {
        owner.verify(&self.signed, &self.signature).map_err(|_| ChannelError::BadSignature)?;
        Ok(self.representation)
    }
}

/// Почему представление не принято.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// Форма не та: нет поля, не тот тип, превышен предел.
    #[error("представление канала не разобралось")]
    Malformed,
    /// Подпись не сошлась с названным ключом.
    #[error("подпись представления не сошлась")]
    BadSignature,
    /// Версия не новее той, что уже принята (§6.1).
    ///
    /// **Не порча и не нападение.** Отдельно от [`ChannelError::Malformed`]
    /// именно поэтому: на порче растёт счётчик аномалий (§7.3), а старая
    /// версия приезжает штатно — в рое копии обгоняют друг друга, и одна
    /// и та же версия приходит от десятка раздающих.
    #[error("версия представления не новее принятой")]
    StaleVersion,
    /// Версия ниже той, что назвала ссылка (§10.3, шаг 4).
    ///
    /// Так поднятая версия делает старые ссылки негодными, и отзыва
    /// ссылки заводить не приходится (§10.7). Отдельно от
    /// [`ChannelError::StaleVersion`]: там «у нас уже новее», здесь
    /// «дверь закрыли», и человеку от них нужно разное.
    #[error("версия представления ниже той, что назвала ссылка")]
    BelowLinkVersion,
    /// Документ говорит о другом канале, другой породе или другом владельце.
    ///
    /// Всё это при заведении задаётся навсегда (§6.1): порода — разные
    /// обещания, владелец — единственный, чья подпись действительна.
    /// Смена любого из них означает не новую версию, а другой канал.
    #[error("представление говорит не об этом канале")]
    NotTheSameChannel,
}

/// Можно ли принять `next` вместо `previous` (§6.1, §10.3).
///
/// Подпись здесь **не проверяется**: её проверяет
/// [`UncheckedRepresentation::verify`], и ключ для неё берётся по-разному
/// — из ссылки в первый раз, из принятого документа потом. Разделено
/// затем, чтобы правило перехода можно было проверить без криптографии,
/// а криптографию — без правила.
///
/// # Что проверяется и почему именно это
///
/// **Версия строго больше.** Равная — не обновление: в рое одна и та же
/// версия приезжает от десятка раздающих, и принимать её заново значило
/// бы переписывать выдачи на каждую копию. Меньшая — опоздавшая копия,
/// и применить её значило бы воскресить снятое право.
///
/// **Версия не ниже названной ссылкой** (§10.3, шаг 4). Так поднятая
/// версия делает старые ссылки негодными, и отзыва ссылки заводить
/// не приходится (§10.7). Порог проверяется **всегда**, а не только
/// в первый раз: ссылку могли переслать кому угодно, и приняв однажды
/// версию выше порога, мы не обязаны принимать следующую ниже него.
///
/// **Идентификатор, порода и владелец неизменны.** Всё трое задаются
/// при заведении навсегда: порода — это разные обещания (§6.1), владелец
/// — единственный, чья подпись действительна, идентификатор — тождество
/// канала. Смена любого означает не новую версию, а другой канал,
/// и молча подменить один другим — ровно то, от чего проверка стоит.
///
/// # Чего здесь нет
///
/// Правил о **содержимом** перехода: можно ли снять право, опустить
/// сложность PoW, укоротить окно сидирования. Их в спеке нет, и выдумать
/// их здесь значило бы отвергать документы, которые владелец вправе
/// подписать. Владелец распоряжается своим каналом; ограничивает его
/// не переход, а то, что каждый шаг публичен и версионирован.
///
/// # Errors
///
/// [`ChannelError::StaleVersion`], [`ChannelError::BelowLinkVersion`],
/// [`ChannelError::NotTheSameChannel`] — по написанному выше.
pub fn accepts(
    previous: Option<&Representation>,
    next: &Representation,
    min_version: u64,
) -> Result<(), ChannelError> {
    if next.version < min_version {
        return Err(ChannelError::BelowLinkVersion);
    }
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous.group != next.group || previous.owner != next.owner || previous.kind != next.kind {
        return Err(ChannelError::NotTheSameChannel);
    }
    if next.version <= previous.version {
        return Err(ChannelError::StaleVersion);
    }
    Ok(())
}

fn grant_value(grant: &Grant) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_WHO.into()), Value::Bytes(grant.who.to_vec())),
        (Value::Integer(KEY_RIGHTS.into()), Value::Integer(grant.rights.bits().into())),
        (Value::Integer(KEY_UNTIL.into()), Value::Integer(grant.until_ms.into())),
    ])
}

fn representation_value(representation: &Representation) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(representation.group.to_vec())),
        (Value::Integer(KEY_OWNER.into()), Value::Bytes(representation.owner.to_vec())),
        (Value::Integer(KEY_VERSION.into()), Value::Integer(representation.version.into())),
        (Value::Integer(KEY_KIND.into()), Value::Integer(representation.kind.code().into())),
        (Value::Integer(KEY_TITLE.into()), Value::Text(representation.title.clone())),
        (Value::Integer(KEY_POW.into()), Value::Integer(representation.pow_bits.into())),
        (Value::Integer(KEY_SEED_DAYS.into()), Value::Integer(representation.seed_days.into())),
        (Value::Integer(KEY_SEED_BYTES.into()), Value::Integer(representation.seed_bytes.into())),
        (
            Value::Integer(KEY_GRANTS.into()),
            // Без обрезки: длину стережёт `signed_representation`, и обрезка
            // здесь была бы вторым правилом, которое никогда не срабатывает.
            // Предел на приёме — против чужого документа, а не своего.
            Value::Array(representation.grants.iter().map(grant_value).collect()),
        ),
    ])
}

/// Собирает подписанное представление.
///
/// Кодирование и подпись стоят в одном месте по той же причине, что
/// у блока состава: разнеси их, и однажды кто-нибудь подпишет одну
/// кодировку, а отправит другую.
///
/// # Errors
///
/// Отказ кодирования; [`ChannelError::Malformed`] — название длиннее
/// предела или выдач больше [`MAX_GRANTS`]. Проверка стоит **и здесь**,
/// на отправке: собрать документ, который никто не примет, значит
/// потратить круг по сети на объяснение вместо отказа на месте.
pub fn signed_representation(
    owner: &Identity,
    representation: &Representation,
) -> Result<Value, ChannelError> {
    let (bytes, signature) = sign_representation(owner, representation)?;
    Ok(wire_value(bytes, &signature))
}

/// Собирает то, что едет по проводу, из уже подписанной пары.
///
/// Нужна тому, кто подписал документ раньше и держит его байты на диске:
/// уехать обязаны **они**, а не пересобранные из разобранного. Форма
/// карты задана здесь и только здесь — иначе у одного формата стало бы
/// два сборщика, и первая же правка развела бы их молча.
#[must_use]
pub fn wire_value(block_bytes: Vec<u8>, signature: &[u8; 64]) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_BLOCK.into()), Value::Bytes(block_bytes)),
        (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
    ])
}

/// Заявка на подписку: карта для провода (фаза 2, §10.4).
///
/// # Внутри только канал
///
/// §10.4 называет заявку «блоком с нашей карточкой», и карточка в ней
/// действительно едет — но **рукопожатием** (§8.2), первым кадром той же
/// сессии. Второй её экземпляр внутри заявки означал бы два источника
/// одного и того же, а расходятся такие пары молча.
///
/// # Подписи нет, и она была бы лишней
///
/// Заявка едет по установленной сессии: кто её прислал, уже доказано
/// рукопожатием. Подпись доказывала бы то же самое второй раз — и
/// вдобавок делала бы заявку **пересылаемой**, то есть позволяла бы
/// третьему предъявить владельцу чужую просьбу.
#[must_use]
pub fn request_value(group: &GroupId) -> Value {
    Value::Map(vec![(Value::Integer(KEY_GROUP.into()), Value::Bytes(group.to_vec()))])
}

/// Читает заявку с провода.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — карта не той формы или идентификатор
/// не шестнадцати байт.
pub fn request_from_value(value: &Value) -> Result<GroupId, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let group = canonical::require(map, KEY_GROUP).map_err(|_| ChannelError::Malformed)?;
    canonical::as_array::<16>(group).map_err(|_| ChannelError::Malformed)
}

/// Подписывает представление и отдаёт **пару** «байты и подпись».
///
/// Нужна там, где документ ложится на диск: хранить надо именно те
/// байты, над которыми считана подпись (§6). Собери их заново перед
/// проверкой — и любое расхождение канонизации превратило бы законный
/// документ в испорченный после первого же перезапуска.
///
/// [`signed_representation`] — та же работа, завёрнутая в карту для
/// провода; обе зовут одно и то же место, чтобы подпись считалась
/// над одним и тем же.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — название длиннее [`MAX_TITLE_BYTES`],
/// выдач больше [`MAX_GRANTS`] или отказало кодирование.
pub fn sign_representation(
    owner: &Identity,
    representation: &Representation,
) -> Result<(Vec<u8>, [u8; 64]), ChannelError> {
    if representation.title.len() > MAX_TITLE_BYTES || representation.grants.len() > MAX_GRANTS {
        return Err(ChannelError::Malformed);
    }
    let bytes = canonical::encode(&representation_value(representation))
        .map_err(|_| ChannelError::Malformed)?;
    let signature = owner.sign(&bytes);
    Ok((bytes, signature))
}

fn grant_from_value(value: &Value) -> Result<Grant, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let rights = canonical::as_u64(
        canonical::require(map, KEY_RIGHTS).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?;
    Ok(Grant {
        who: canonical::as_array::<32>(
            canonical::require(map, KEY_WHO).map_err(|_| ChannelError::Malformed)?,
        )
        .map_err(|_| ChannelError::Malformed)?,
        rights: Rights::from_bits(u32::try_from(rights).map_err(|_| ChannelError::Malformed)?),
        until_ms: canonical::as_u64(
            canonical::require(map, KEY_UNTIL).map_err(|_| ChannelError::Malformed)?,
        )
        .map_err(|_| ChannelError::Malformed)?,
    })
}

/// Разбирает представление, **не** проверяя подпись.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — форма не та или превышены пределы.
pub fn parse_representation(value: &Value) -> Result<UncheckedRepresentation, ChannelError> {
    let outer = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let Ok(Value::Bytes(signed)) = canonical::require(outer, KEY_BLOCK) else {
        return Err(ChannelError::Malformed);
    };
    let Ok(Value::Bytes(signature)) = canonical::require(outer, KEY_SIGNATURE) else {
        return Err(ChannelError::Malformed);
    };
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| ChannelError::Malformed)?;

    let inner = canonical::decode(signed).map_err(|_| ChannelError::Malformed)?;
    let map = canonical::as_map(&inner).map_err(|_| ChannelError::Malformed)?;
    let field = |key: u64| canonical::require(map, key).map_err(|_| ChannelError::Malformed);
    let number = |key: u64| -> Result<u64, ChannelError> {
        canonical::as_u64(field(key)?).map_err(|_| ChannelError::Malformed)
    };

    let title = canonical::as_text(field(KEY_TITLE)?).map_err(|_| ChannelError::Malformed)?;
    if title.len() > MAX_TITLE_BYTES {
        return Err(ChannelError::Malformed);
    }
    let Value::Array(grants) = field(KEY_GRANTS)? else {
        return Err(ChannelError::Malformed);
    };
    // Предел — **отказ**, а не обрезка, и здесь это не то же, что
    // у вложений. Лишнее вложение — неполный показ, и он виден; лишняя
    // выдача — это право, о котором мы промолчали, и разойдётся оно молча:
    // один подписчик обслужит того, кого другой отвергнет.
    if grants.len() > MAX_GRANTS {
        return Err(ChannelError::Malformed);
    }

    let kind = Kind::from_code(number(KEY_KIND)?).ok_or(ChannelError::Malformed)?;
    let representation = Representation {
        group: canonical::as_array::<16>(field(KEY_GROUP)?).map_err(|_| ChannelError::Malformed)?,
        owner: canonical::as_array::<32>(field(KEY_OWNER)?).map_err(|_| ChannelError::Malformed)?,
        version: number(KEY_VERSION)?,
        kind,
        title: title.to_owned(),
        pow_bits: u32::try_from(number(KEY_POW)?).map_err(|_| ChannelError::Malformed)?,
        seed_days: u32::try_from(number(KEY_SEED_DAYS)?).map_err(|_| ChannelError::Malformed)?,
        seed_bytes: number(KEY_SEED_BYTES)?,
        grants: grants.iter().map(grant_from_value).collect::<Result<Vec<_>, _>>()?,
    };
    Ok(UncheckedRepresentation { representation, signature, signed: signed.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Identity {
        Identity::from_seed([1u8; 32])
    }

    fn sample(version: u64) -> Representation {
        Representation {
            group: [7u8; 16],
            owner: owner().public().ik,
            version,
            kind: Kind::ByInvite,
            title: "костёр".to_owned(),
            pow_bits: 0,
            seed_days: 30,
            seed_bytes: 64 * 1024 * 1024,
            grants: vec![Grant {
                who: [9u8; 32],
                rights: Rights::WRITE.with(Rights::ADMIT),
                until_ms: 2_000,
            }],
        }
    }

    #[test]
    fn a_representation_survives_the_round_trip_and_the_signature() {
        let owner = owner();
        let value = signed_representation(&owner, &sample(3)).expect("подписалось");
        let back = parse_representation(&value)
            .expect("разобралось")
            .verify(&owner.public())
            .expect("подпись цела");
        assert_eq!(back, sample(3));
    }

    #[test]
    fn a_representation_checked_against_the_wrong_key_is_refused() {
        let value = signed_representation(&owner(), &sample(3)).expect("подписалось");
        let stranger = Identity::from_seed([2u8; 32]);
        assert!(matches!(
            parse_representation(&value).unwrap().verify(&stranger.public()),
            Err(ChannelError::BadSignature)
        ));
    }

    #[test]
    fn every_field_is_inside_the_signature() {
        // **По полю на строчку, и это не педантизм.** Каждое из них
        // что-то разрешает или запрещает: версия пускает по ссылке,
        // порода решает, отбирается ли доступ, сложность PoW — цену
        // слова, окно сидирования — что значит «вся история».
        let owner = owner();
        let original = sample(3);
        let value = signed_representation(&owner, &original).expect("подписалось");
        let Value::Map(pairs) = &value else { panic!("карта") };
        let signature = pairs
            .iter()
            .find(|(k, _)| *k == Value::Integer(KEY_SIGNATURE.into()))
            .map(|(_, v)| v.clone())
            .unwrap();

        let mut bumped = original.clone();
        bumped.version = 4;
        let mut opened = original.clone();
        opened.kind = Kind::Open;
        let mut cheap = original.clone();
        cheap.pow_bits = 0xFF;
        let mut wide = original.clone();
        wide.seed_days = 1;
        let mut granted = original.clone();
        granted.grants[0].rights = Rights::all();
        let mut prolonged = original.clone();
        prolonged.grants[0].until_ms = u64::MAX;

        for (what, tampered) in [
            ("версия", bumped),
            ("порода", opened),
            ("сложность", cheap),
            ("окно", wide),
            ("права", granted),
            ("срок", prolonged),
        ] {
            let forged = Value::Map(vec![
                (
                    Value::Integer(KEY_BLOCK.into()),
                    Value::Bytes(canonical::encode(&representation_value(&tampered)).unwrap()),
                ),
                (Value::Integer(KEY_SIGNATURE.into()), signature.clone()),
            ]);
            assert!(
                matches!(
                    parse_representation(&forged).unwrap().verify(&owner.public()),
                    Err(ChannelError::BadSignature)
                ),
                "подмена поля «{what}» обязана ломать подпись"
            );
        }
    }

    #[test]
    fn the_owner_has_everything_and_cannot_lose_it() {
        // 5вп: владелец не лишается прав. Правило живёт здесь, потому что
        // спрашивать про права будут из многих мест, а правило одно.
        let mut representation = sample(3);
        representation.grants.push(Grant {
            who: representation.owner,
            rights: Rights::none(),
            until_ms: 0,
        });
        let rights = representation.rights_of(&representation.owner, 1_000_000);
        assert!(rights.has(Rights::WRITE));
        assert!(rights.has(Rights::ADMIT));
        assert!(rights.has(Rights::EVICT));
        assert!(rights.has(Rights::EDIT));
    }

    #[test]
    fn a_grant_stops_working_when_its_time_is_up() {
        // §6.3: не продлил — истекло само, без отзыва. Отказ вниз, а не вверх.
        let representation = sample(3);
        let who = [9u8; 32];
        assert!(representation.may_write(&who, 1_999), "до срока пишет");
        assert!(!representation.may_write(&who, 2_000), "ровно в срок — уже нет");
        assert!(!representation.may_write(&who, 2_001), "и позже тоже");
    }

    #[test]
    fn a_stranger_may_do_nothing() {
        let representation = sample(3);
        assert_eq!(representation.rights_of(&[3u8; 32], 1_000), Rights::none());
    }

    #[test]
    fn unknown_rights_bits_survive_a_round_trip() {
        // Сборка постарше обязана **сохранить** право, которого не знает,
        // а не потерять его при чтении и записи: потеряв, она отдала бы
        // соседу документ, где права меньше, чем подписал владелец.
        let owner = owner();
        let mut representation = sample(3);
        representation.grants[0].rights = Rights::from_bits(0x8000_0001);
        let value = signed_representation(&owner, &representation).expect("подписалось");
        let back = parse_representation(&value).unwrap().verify(&owner.public()).unwrap();
        assert_eq!(back.grants[0].rights.bits(), 0x8000_0001);
    }

    #[test]
    fn a_title_past_the_limit_is_refused_on_both_sides() {
        let owner = owner();
        let mut representation = sample(3);
        representation.title = "я".repeat(MAX_TITLE_BYTES);
        assert!(
            matches!(signed_representation(&owner, &representation), Err(ChannelError::Malformed)),
            "«я» — два байта, значит предел превышен вдвое"
        );
    }

    #[test]
    fn too_many_grants_are_refused_rather_than_trimmed() {
        // Обрезка здесь была бы молчаливым расхождением: один подписчик
        // обслужил бы того, кого другой отверг.
        let owner = owner();
        let mut representation = sample(3);
        representation.grants = (0..=MAX_GRANTS)
            .map(|n| Grant {
                who: [u8::try_from(n % 251).unwrap(); 32],
                rights: Rights::WRITE,
                until_ms: 1,
            })
            .collect();
        assert!(matches!(
            signed_representation(&owner, &representation),
            Err(ChannelError::Malformed)
        ));
    }

    #[test]
    fn too_many_grants_from_a_stranger_are_refused_on_parse() {
        // **Предел на приёме — против чужого документа.** Свой не соберётся:
        // `signed_representation` откажет. А вот прислать нам список
        // на миллион выдач может кто угодно, и это запрос памяти,
        // а не список прав.
        let owner = owner();
        let mut representation = sample(3);
        representation.grants = (0..=MAX_GRANTS)
            .map(|n| Grant {
                who: [u8::try_from(n % 251).unwrap(); 32],
                rights: Rights::WRITE,
                until_ms: 1,
            })
            .collect();
        // Мимо `signed_representation` — руками, как это сделал бы чужой.
        let bytes = canonical::encode(&representation_value(&representation)).unwrap();
        let signature = owner.sign(&bytes);
        let forged = Value::Map(vec![
            (Value::Integer(KEY_BLOCK.into()), Value::Bytes(bytes)),
            (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
        ]);
        assert!(
            matches!(parse_representation(&forged), Err(ChannelError::Malformed)),
            "подпись тут цела — отказать обязан предел, а не она"
        );
    }

    #[test]
    fn the_title_limit_is_the_same_one_the_group_has() {
        // **Стояло 128 с комментарием «то же число, что у группы».**
        // У группы 256, и разница была не теоретической: 256 — это потолок
        // шестидесяти четырёх символов по четыре байта, то есть предел,
        // при котором любое название из поля ввода влезает. При 128 канал
        // отвергал бы названия из эмодзи, законные для группы.
        //
        // Проверка стоит затем, чтобы пределы нельзя было развести снова:
        // поле ввода одно, и два ответа на «почему не влезает» у него
        // быть не должно.
        assert_eq!(MAX_TITLE_BYTES, crate::group::MAX_GROUP_TITLE_BYTES);

        // Предел в символах живёт в ядре (`MAX_GROUP_TITLE_CHARS`), сюда
        // он не виден, и связь между ними стережёт проверка на той стороне
        // (`a_channel_title_obeys_the_same_two_limits_as_a_group`). Здесь
        // проверяется то, что видно отсюда: название из самых дорогих
        // символов, занявшее предел целиком, обязано подписаться.
        let longest = "\u{1f600}".repeat(MAX_TITLE_BYTES / 4);
        assert_eq!(longest.len(), MAX_TITLE_BYTES);

        let owner = owner();
        let mut representation = sample(3);
        representation.title = longest;
        assert!(
            signed_representation(&owner, &representation).is_ok(),
            "название, законное в поле ввода, обязано подписаться"
        );
    }

    // --- Тексты (§15) -----------------------------------------------------

    #[test]
    fn the_texts_say_what_the_protocol_actually_does() {
        // **§14 требует, чтобы обещания продукта не расходились
        // со свойствами протокола**, и держится это единственным
        // способом: свойство названо константой, текст его пересказывает,
        // проверка сверяет одно с другим. То же устройство, что
        // у `group::EvictionConsequences`.
        //
        // Сверяются не слова целиком, а **слова, несущие обещание**:
        // проверка на полный текст ломалась бы от запятой и ничего
        // не стерегла бы.
        assert!(OpenChannelConsequences::KEY_IS_IN_THE_LINK);
        assert!(OpenChannelConsequences::ANYONE_WITH_THE_LINK_READS);
        assert!(!OpenChannelConsequences::ACCESS_CAN_BE_TAKEN_BACK);
        let text = OpenChannelConsequences::ui_text();
        assert!(text.contains("в самой ссылке"), "про ключ в ссылке сказать обязаны");
        assert!(text.contains("нельзя"), "про невозвратность доступа — тоже");

        assert!(PrivateChannelConsequences::SOMEONE_MUST_ADMIT_YOU);
        assert!(!PrivateChannelConsequences::OPENS_BEFORE_ADMISSION);
        let text = PrivateChannelConsequences::ui_text();
        assert!(text.contains("не откроется"));

        assert!(AdmitterGrantConsequences::ADMITTED_STAY_AFTER_THE_RIGHT_IS_TAKEN);
        assert!(AdmitterGrantConsequences::OWNER_SEES_THE_TRACE);
        assert!(AdmitterGrantConsequences::CAN_PASS_THE_KEY_OUTSIDE);
        let text = AdmitterGrantConsequences::ui_text();
        assert!(text.contains("останутся"), "про то, что впущенные остаются");
        assert!(text.contains("в обход"), "и про то, что ключ можно передать мимо");

        assert!(KeyRotationConsequences::OUTSIDERS_LOSE_THE_FUTURE);
        assert!(KeyRotationConsequences::OUTSIDERS_KEEP_THE_PAST);
        assert!(!KeyRotationConsequences::INSIDERS_LOSE_THE_ARCHIVE);
        let text = KeyRotationConsequences::ui_text();
        assert!(text.contains("потеряют доступ"), "кнопка называется последствием (§6.4)");
        assert!(text.contains("останется"), "и тем, что прочитанное не забрать");

        assert!(SharingConsequences::THE_LINK_CARRIES_OUR_ADDRESS);
        assert!(SharingConsequences::IT_REVEALS_THAT_WE_READ_IT);
        assert!(SharingConsequences::ui_text().contains("ваш адрес"));
    }

    #[test]
    fn the_private_channel_text_promises_the_request_we_now_send() {
        // **Эта проверка была написана падающей, и она упала — как
        // и задумано.** Полтора года текст говорил «попросите его другим
        // способом», потому что заявки (§10.4) в ядре не было: дотянуться
        // до владельца было нечем. Прежняя редакция стерегла ровно это —
        // «не обещать того, чего не отправляем» — и падала в тот день,
        // когда заявку напишут.
        //
        // День настал: §8.3 дал сессию без контакта, заявка уезжает
        // владельцу, и фраза спеки вернулась. Стережёт проверка теперь
        // обратное: текст обязан обещать то, что мы **делаем**.
        assert!(PrivateChannelConsequences::OWNER_LEARNS_BY_ITSELF);
        let text = PrivateChannelConsequences::ui_text();
        assert!(
            text.contains("карточку"),
            "заявка есть — и человеку сказано, что владелец её увидит"
        );
        assert!(
            !text.contains("другим способом"),
            "а совет «попросите иначе» стал неправдой: ссылка сама и просит"
        );
    }

    #[test]
    fn no_text_is_empty_or_a_single_word() {
        // Заготовка вместо текста — то же, что текст неверный: человек
        // прочтёт её и решит, что это всё, что ему хотели сказать.
        for text in [
            OpenChannelConsequences::ui_text(),
            PrivateChannelConsequences::ui_text(),
            AdmitterGrantConsequences::ui_text(),
            KeyRotationConsequences::ui_text(),
            SharingConsequences::ui_text(),
        ] {
            assert!(text.len() > 80, "текст в {} байт ничего не объясняет", text.len());
            assert!(text.ends_with('.'), "текст обрывается на полуслове: {text}");
            assert!(!text.contains("  "), "двойной пробел — след склейки строк: {text}");
        }
    }

    // --- Учёт впусков (§6.5) ----------------------------------------------

    fn admission(generation: u64) -> Admission {
        Admission { group: [7u8; 16], who: [9u8; 32], admitted_by: owner().public().ik, generation }
    }

    /// Собирает то, что поедет по проводу.
    fn signed_admission(by: &Identity, admission: &Admission) -> Value {
        let (bytes, signature) = sign_admission(by, admission).expect("подписалось");
        admission_wire_value(bytes, &signature)
    }

    #[test]
    fn an_admission_survives_the_round_trip_and_the_signature() {
        let admitter = owner();
        let it = admission(3);
        let value = signed_admission(&admitter, &it);
        let back = parse_admission(&value).expect("разбирается");
        assert_eq!(back.claims(), &it, "до проверки видно то же самое");
        assert_eq!(back.verify(&admitter.public()).expect("подпись сходится"), it);
    }

    #[test]
    fn an_admission_checked_against_the_wrong_key_is_refused() {
        // **Главная проверка записи.** Она про то, кто кого впустил,
        // и подписью это и доказывается. Прими мы её чужим ключом —
        // «впустил» стало бы утверждением без доказательства.
        let admitter = owner();
        let stranger = Identity::from_seed([42u8; 32]);
        let value = signed_admission(&admitter, &admission(3));
        assert!(matches!(
            parse_admission(&value).unwrap().verify(&stranger.public()),
            Err(ChannelError::NotTheSameChannel)
        ));
    }

    #[test]
    fn an_admission_that_names_one_and_is_signed_by_another_is_refused() {
        // Запись **называет** впускающего внутри себя. Подпиши её другой,
        // и она утверждала бы одно, а доказывала другое. Отказ приходит
        // от подписи, а не от имени: имя чужое подставить легко.
        let stranger = Identity::from_seed([42u8; 32]);
        let mut it = admission(3);
        it.admitted_by = owner().public().ik;
        // Подписывает не тот, кто назван.
        let value = signed_admission(&stranger, &it);
        assert!(matches!(
            parse_admission(&value).unwrap().verify(&owner().public()),
            Err(ChannelError::BadSignature)
        ));
    }

    #[test]
    fn every_field_of_an_admission_is_inside_the_signature() {
        // Ни одно поле не должно поддаваться правке в пути. Проверяется
        // каждое поимённо: покрой подпись три поля из четырёх, и четвёртое
        // правилось бы молча.
        let admitter = owner();
        let it = admission(3);
        let (_, signature) = sign_admission(&admitter, &it).expect("подписалось");

        for other in [
            Admission { group: [1u8; 16], ..it },
            Admission { who: [1u8; 32], ..it },
            Admission { admitted_by: [1u8; 32], ..it },
            Admission { generation: 4, ..it },
        ] {
            let forged = admission_wire_value(
                canonical::encode(&admission_value(&other)).unwrap(),
                &signature,
            );
            let parsed = parse_admission(&forged).expect("форма цела");
            // Подменённый `admitted_by` отвергается именем, остальные —
            // подписью. Важно, что **ни одно** не проходит.
            assert!(parsed.verify(&admitter.public()).is_err(), "поле поправили, а подпись цела");
        }
    }

    // --- Правило перехода (§6.1, §10.3) -----------------------------------

    #[test]
    fn a_newer_version_is_accepted_and_the_same_one_is_not() {
        // Равная версия — **не обновление**. В рое одна и та же копия
        // приезжает от десятка раздающих, и принимай мы её заново,
        // выдачи переписывались бы на каждую.
        let old = sample(3);
        let mut new = sample(4);
        new.title = "иначе".to_owned();

        assert!(accepts(Some(&old), &new, 0).is_ok());
        assert!(matches!(accepts(Some(&old), &sample(3), 0), Err(ChannelError::StaleVersion)));
        assert!(matches!(accepts(Some(&old), &sample(2), 0), Err(ChannelError::StaleVersion)));
    }

    #[test]
    fn the_first_representation_is_accepted_without_a_previous_one() {
        // Пара ко всем отказам ниже: не будь этой проверки, «отвергнуто»
        // ничего не значило бы — могло бы отвергать всё подряд.
        assert!(accepts(None, &sample(1), 0).is_ok());
        assert!(accepts(None, &sample(7), 7).is_ok(), "ровно порог — уже не ниже");
    }

    #[test]
    fn a_version_below_what_the_link_named_is_refused_even_later() {
        // **Порог проверяется всегда, а не только в первый раз.** Ссылку
        // могли переслать кому угодно; приняв однажды версию выше порога,
        // мы не обязаны принимать следующую ниже него. На этом и держится
        // §10.7: отзыва ссылки не бывает, но поднятая версия делает старые
        // ссылки негодными.
        assert!(matches!(accepts(None, &sample(3), 5), Err(ChannelError::BelowLinkVersion)));
        let old = sample(1);
        assert!(matches!(accepts(Some(&old), &sample(3), 5), Err(ChannelError::BelowLinkVersion)));
    }

    #[test]
    fn the_link_threshold_is_checked_before_staleness() {
        // Порядок отказов значим: «дверь закрыли» и «у нас уже новее» —
        // разные вещи, и первое человеку важнее. Документ ниже порога
        // **и** не новее принятого обязан назваться закрытой дверью.
        let old = sample(9);
        assert!(matches!(accepts(Some(&old), &sample(3), 5), Err(ChannelError::BelowLinkVersion)));
    }

    #[test]
    fn a_change_of_kind_owner_or_id_is_not_a_new_version() {
        // Все трое задаются при заведении навсегда (§6.1). Смена любого
        // означает не новую версию, а **другой канал**, и подменить один
        // другим молча — ровно то, от чего проверка стоит.
        let old = sample(3);

        // `sample` даёт `ByInvite` — меняем на `Open`, иначе «смена»
        // была бы тем же значением, и проверка не проверяла бы ничего.
        let mut other_kind = sample(4);
        assert_eq!(old.kind, Kind::ByInvite, "заготовка сменилась — поправьте проверку");
        other_kind.kind = Kind::Open;
        assert!(matches!(
            accepts(Some(&old), &other_kind, 0),
            Err(ChannelError::NotTheSameChannel)
        ));

        let mut other_owner = sample(4);
        other_owner.owner = [42u8; 32];
        assert!(matches!(
            accepts(Some(&old), &other_owner, 0),
            Err(ChannelError::NotTheSameChannel)
        ));

        let mut other_group = sample(4);
        other_group.group = [42u8; 16];
        assert!(matches!(
            accepts(Some(&old), &other_group, 0),
            Err(ChannelError::NotTheSameChannel)
        ));
    }

    #[test]
    fn what_the_new_version_says_is_not_judged() {
        // **Чего правило не делает.** Снятие права, опущенная сложность
        // PoW, укороченное окно — всё это владелец вправе подписать,
        // и правил о содержимом перехода в спеке нет. Выдумай мы их
        // здесь, мы отвергали бы законные документы.
        let mut old = sample(3);
        old.grants = vec![Grant { who: [1u8; 32], rights: Rights::all(), until_ms: u64::MAX }];
        old.pow_bits = 20;
        old.seed_days = 365;

        let mut stripped = sample(4);
        stripped.grants = Vec::new();
        stripped.pow_bits = 0;
        stripped.seed_days = 1;
        assert!(accepts(Some(&old), &stripped, 0).is_ok(), "владелец распоряжается своим каналом");
    }

    // --- Ссылка (§10.1, §10.2) -------------------------------------------

    fn onion() -> String {
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion".to_owned()
    }

    fn open_link() -> Invitation {
        Invitation {
            group: [7u8; 16],
            owner: [1u8; 32],
            min_version: 3,
            key: Some([5u8; 32]),
            endpoints: vec![
                Endpoint::Onion(onion()),
                Endpoint::Ygg([6u8; 32]),
                Endpoint::Chatmail("kot@nine.example".to_owned()),
                Endpoint::NostrRelay("wss://relay.nine.example".to_owned()),
            ],
        }
    }

    #[test]
    fn a_link_survives_the_round_trip() {
        let link = open_link();
        let uri = link.to_uri().expect("ссылка собирается");
        assert!(uri.starts_with(CHANNEL_URI_PREFIX));
        assert_eq!(Invitation::from_uri(&uri).expect("разбирается"), link);
    }

    #[test]
    fn every_address_kind_of_a_card_rides_in_a_link() {
        // §10.1: «`addrs[]` — адреса всех доступных видов, **как в карточке
        // контакта**». Видов в карточке пять — onion, почта, меш, ключ
        // nostr и его реле, — и ссылка обязана везти каждый: узел, у которого
        // из путей один nostr, иначе раздаёт ссылку, по которой до него
        // не достучаться.
        //
        // Чего эта проверка не стережёт: **что ядро их туда положило**. Она
        // про формат ссылки; за наполнение отвечает `Engine::channel_link`
        // и проверка `a_channel_link_carries_every_kind_of_address_we_have`.
        let mut link = open_link();
        link.endpoints = vec![
            Endpoint::Onion(onion()),
            Endpoint::Chatmail("kot@nine.example".to_owned()),
            Endpoint::Ygg([6u8; 32]),
            Endpoint::Nostr([9u8; 32]),
            Endpoint::NostrRelay("wss://relay.nine.example".to_owned()),
        ];
        let uri = link.to_uri().expect("ссылка собирается");
        assert_eq!(Invitation::from_uri(&uri).expect("разбирается"), link);
    }

    #[test]
    fn a_nostr_key_does_not_come_back_as_a_relay() {
        // Ключ и реле — соседние виды, и едут они рядом. Перепутай их
        // разбор — и §5.4 получил бы «реле», по которому некому писать,
        // ровно в той поломке, из-за которой вид и заведён.
        let mut link = open_link();
        link.endpoints = vec![Endpoint::Nostr([9u8; 32])];
        let back = Invitation::from_uri(&link.to_uri().unwrap()).unwrap();
        assert_eq!(back.endpoints, vec![Endpoint::Nostr([9u8; 32])]);
    }

    #[test]
    fn the_key_in_the_link_is_what_makes_the_channel_open() {
        assert!(open_link().claims_open());
        let mut by_invite = open_link();
        by_invite.key = None;
        assert!(!by_invite.claims_open(), "у канала по приглашению ключ выдаёт владелец");
        let uri = by_invite.to_uri().unwrap();
        assert_eq!(Invitation::from_uri(&uri).unwrap().key, None, "и в ссылке его нет");
    }

    /// Ссылка по приглашению: без ключа и с одним адресом.
    fn lean_link() -> Invitation {
        let mut lean = open_link();
        lean.key = None;
        lean.endpoints = vec![Endpoint::Onion(onion())];
        lean
    }

    /// Во сколько бит обойдётся отрезок строки в QR-коде.
    ///
    /// Алфавитно-цифровой режим QR — цифры, ЗАГЛАВНЫЕ буквы и
    /// `` $%*+-./:`` — одиннадцать бит на пару знаков и шесть на нечётный
    /// остаток. Всё, что в него не влезает, идёт байтовым: восемь бит
    /// на знак. Заголовок отрезка (режим и счётчик) здесь не считается:
    /// он одинаков у сравниваемых вариантов и разницу не меняет.
    fn qr_bits(segment: &str) -> usize {
        const ALNUM: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        if segment.chars().all(|sign| ALNUM.contains(sign)) {
            let signs = segment.chars().count();
            signs / 2 * 11 + (signs % 2) * 6
        } else {
            segment.len() * 8
        }
    }

    #[test]
    fn the_size_is_measured_and_not_estimated() {
        // **Замер, а не оценка.** §10.1 обещает: открытый канал с четырьмя
        // адресами — около 210 байт и 280 знаков, по приглашению с одним —
        // около 114 и 152. Знаков у нас больше обещанного вдвойне: тело
        // вышло крупнее оценки, и кодировка взята base32, которая длиннее
        // base64url на четверть. Предел стоит там, где ссылка перестала бы
        // влезать в разумный QR, а не там, где её ждала спека.
        let open = open_link().to_uri().unwrap();
        let body = open.len() - CHANNEL_URI_PREFIX.len();
        assert!(body < 480, "открытая ссылка разрослась: {body} знаков");

        let lean = lean_link().to_uri().unwrap();
        let lean_body = lean.len() - CHANNEL_URI_PREFIX.len();
        assert!(lean_body < 240, "ссылка по приглашению разрослась: {lean_body} знаков");
        assert!(lean_body < body, "меньше адресов — короче ссылка");
        eprintln!("ссылка: открытая {body} знаков, по приглашению {lean_body}");
    }

    #[test]
    fn base32_costs_fewer_qr_bits_than_base64url_would() {
        // **Это и есть причина отступить от §10.1.** Утверждение «base64url
        // короче» верно в знаках и неверно в битах QR — а меряют ссылку
        // именно ими. Разойдись счёт с этим выводом, ломаться обязано
        // здесь, а не у человека, чей код не снялся с экрана.
        for (what, link) in [("открытая", open_link()), ("по приглашению", lean_link())]
        {
            let bytes = canonical::encode(&link.value()).unwrap();
            let ours = data_encoding::BASE32_NOPAD.encode(&bytes);
            let theirs = data_encoding::BASE64URL_NOPAD.encode(&bytes);

            assert!(
                ours.len() > theirs.len(),
                "{what}: base32 обязан быть длиннее в знаках — это и сбивало с толку"
            );
            let (ours_bits, theirs_bits) = (qr_bits(&ours), qr_bits(&theirs));
            assert!(
                ours_bits < theirs_bits,
                "{what}: base32 {ours_bits} бит против {theirs_bits} — выигрыш пропал"
            );
            eprintln!(
                "{what}: {} байт → base32 {} знаков / {ours_bits} бит, \
                 base64url {} знаков / {theirs_bits} бит",
                bytes.len(),
                ours.len(),
                theirs.len()
            );
        }
    }

    #[test]
    fn the_body_of_a_link_fits_the_alphanumeric_mode_of_qr() {
        // На этом держится весь выигрыш предыдущей проверки. Вернёт
        // кто-нибудь base64url — падать будет здесь, и словами про режим,
        // а не числом бит.
        let uri = open_link().to_uri().unwrap();
        let body = uri.strip_prefix(CHANNEL_URI_PREFIX).unwrap();
        assert_eq!(
            qr_bits(body),
            body.len() / 2 * 11 + (body.len() % 2) * 6,
            "тело ссылки выпало из алфавитно-цифрового режима QR"
        );
    }

    #[test]
    fn the_prefix_is_the_only_part_left_in_byte_mode() {
        // **Незакрытое, записанное проверкой.** Приставка строчная, значит
        // едет байтовым режимом: 160 бит вместо 110. Лечится заглавной
        // приставкой, но она общая у карточки (§4.1), сопряжения (§13.4)
        // и канала, и решать надо разом для всех. Пока — зафиксировано.
        assert_eq!(qr_bits(CHANNEL_URI_PREFIX), CHANNEL_URI_PREFIX.len() * 8, "160 бит");
        let upper = CHANNEL_URI_PREFIX.to_uppercase();
        assert!(qr_bits(&upper) < qr_bits(CHANNEL_URI_PREFIX), "заглавная дешевле");
    }

    #[test]
    fn two_links_to_one_channel_differ_as_strings() {
        // **Ловушка для кода.** Каждый, кто делится, кладёт свои адреса,
        // и сравнивать ссылки как строки нельзя нигде: тождество канала —
        // это `group`.
        let mine = open_link();
        let mut theirs = open_link();
        theirs.endpoints = vec![Endpoint::Onion(onion())];

        assert_ne!(mine.to_uri().unwrap(), theirs.to_uri().unwrap(), "строки разные");
        assert_eq!(mine.group, theirs.group, "а канал один");
    }

    #[test]
    fn a_link_with_the_wrong_prefix_is_refused() {
        let uri = open_link().to_uri().unwrap();
        let body = uri.strip_prefix(CHANNEL_URI_PREFIX).unwrap();
        // Приставка карточки на теле канала: похоже на вид, ведёт в другое
        // место. Человек, вставивший не ту, обязан получить отказ.
        assert!(matches!(
            Invitation::from_uri(&format!("ratatosk:v0:{body}")),
            Err(ChannelError::Malformed)
        ));
        assert!(matches!(Invitation::from_uri(body), Err(ChannelError::Malformed)));
        assert!(matches!(
            Invitation::from_uri("ratatosk:v0:channel:!!!"),
            Err(ChannelError::Malformed)
        ));
    }

    #[test]
    fn a_link_without_addresses_is_legal() {
        // Пусто — законно: остаются почта и реле, и §10.5 честно говорит,
        // что это часы, а не секунды.
        let mut bare = open_link();
        bare.endpoints = Vec::new();
        let uri = bare.to_uri().unwrap();
        assert_eq!(Invitation::from_uri(&uri).unwrap().endpoints, Vec::new());
    }

    #[test]
    fn an_endpoint_kind_we_do_not_know_refuses_the_whole_link() {
        // Ссылка ведёт в одно место. Пропустив непонятный адрес, мы открыли
        // бы канал не тем путём, каким собирался тот, кто делился, — и молча.
        let forged = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_OWNER.into()), Value::Bytes(vec![1u8; 32])),
            (Value::Integer(KEY_MIN_VERSION.into()), Value::Integer(3.into())),
            (
                Value::Integer(KEY_ENDPOINTS.into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Integer(KEY_ENDPOINT_KIND.into()), Value::Integer(99.into())),
                    (Value::Integer(KEY_ENDPOINT_VALUE.into()), Value::Text("что-то".to_owned())),
                ])]),
            ),
        ]);
        let uri = format!(
            "{CHANNEL_URI_PREFIX}{}",
            data_encoding::BASE32_NOPAD.encode(&canonical::encode(&forged).unwrap())
        );
        assert!(matches!(Invitation::from_uri(&uri), Err(ChannelError::Malformed)));
    }

    #[test]
    fn too_many_addresses_are_refused_on_both_sides() {
        let mut crowded = open_link();
        crowded.endpoints = (0..=MAX_ENDPOINTS).map(|_| Endpoint::Onion(onion())).collect();
        assert!(matches!(crowded.to_uri(), Err(ChannelError::Malformed)), "свою не собрать");
    }

    #[test]
    fn a_kind_we_do_not_know_is_refused() {
        // Порода решает, отбирается ли доступ обратно. Прочитать незнакомую
        // как одну из известных значило бы пообещать не то.
        let owner = owner();
        let value = signed_representation(&owner, &sample(3)).expect("подписалось");
        let Value::Map(pairs) = &value else { panic!("карта") };
        let signature = pairs
            .iter()
            .find(|(k, _)| *k == Value::Integer(KEY_SIGNATURE.into()))
            .map(|(_, v)| v.clone())
            .unwrap();
        let mut inner = match canonical::decode(&match pairs
            .iter()
            .find(|(k, _)| *k == Value::Integer(KEY_BLOCK.into()))
            .map(|(_, v)| v.clone())
            .unwrap()
        {
            Value::Bytes(bytes) => bytes,
            _ => panic!("байты"),
        })
        .unwrap()
        {
            Value::Map(pairs) => pairs,
            _ => panic!("карта"),
        };
        for (key, value) in &mut inner {
            if *key == Value::Integer(KEY_KIND.into()) {
                *value = Value::Integer(99.into());
            }
        }
        let forged = Value::Map(vec![
            (
                Value::Integer(KEY_BLOCK.into()),
                Value::Bytes(canonical::encode(&Value::Map(inner)).unwrap()),
            ),
            (Value::Integer(KEY_SIGNATURE.into()), signature),
        ]);
        assert!(matches!(parse_representation(&forged), Err(ChannelError::Malformed)));
    }
}

// --- Ссылка на канал (§10.1, §10.2) ---------------------------------------

/// Приставка ссылки на канал.
///
/// Отличается от контактной (`ratatosk:v0:`) и от сопряжения
/// (`ratatosk:v0:pair:`) третьим словом, и это то же правило, что завели
/// для сопряжения: ссылки похожи на вид, а ведут в разные места, и человек,
/// вставивший не ту, должен получить отказ словами, а не молчание.
pub const CHANNEL_URI_PREFIX: &str = "ratatosk:v0:channel:";

/// Сколько адресов помещается в ссылку.
///
/// По одному на вид плюс запас: ссылку собирает тот, кто делится (§10.2),
/// и класть в неё десяток сидов незачем — она провисит год, а живут они
/// недели.
pub const MAX_ENDPOINTS: usize = 8;

const KEY_MIN_VERSION: u64 = 15;
const KEY_KEY: u64 = 16;
const KEY_ENDPOINTS: u64 = 17;
const KEY_ENDPOINT_KIND: u64 = 18;
const KEY_ENDPOINT_VALUE: u64 = 19;
const KEY_ADMITTED_BY: u64 = 20;
const KEY_GENERATION: u64 = 21;

/// Куда стучаться за представлением канала.
///
/// Виды те же, что в карточке контакта: ссылка обязана открываться и там,
/// где быстрых путей нет вовсе, — почтой и через реле, пусть и часами
/// (§10.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Onion-адрес.
    Onion(String),
    /// Адрес chatmail.
    Chatmail(String),
    /// Ключ узла в меше, 32 байта.
    Ygg([u8; 32]),
    /// Адрес реле nostr.
    NostrRelay(String),
    /// Открытый ключ nostr, 32 байта (0.3).
    ///
    /// **Реле без ключа — не адрес.** Событие на реле адресуется ключом
    /// получателя, и список реле без него говорит лишь «туда он ходит
    /// читать». Пока в ссылке ехали одни реле, §5.4 у подписчика считал
    /// ступень годной, а раннер отвечал `NoAddress`: лестница кончалась,
    /// заявка (§10.4) вечно ждала. Вид заведён вместе с той починкой.
    Nostr([u8; 32]),
}

impl Endpoint {
    const fn code(&self) -> u64 {
        match self {
            Endpoint::Onion(_) => 1,
            Endpoint::Chatmail(_) => 2,
            Endpoint::Ygg(_) => 3,
            Endpoint::NostrRelay(_) => 4,
            Endpoint::Nostr(_) => 5,
        }
    }
}

/// Тело ссылки на канал (§10.1).
///
/// # Адреса здесь ничем не подтверждены, и это нарочно
///
/// Представление проверяется подписью `owner_ik`, поэтому подставленный
/// адрес в худшем случае не ответит. Раз поле недоверенное — заполнить
/// его вправе кто угодно, и собирает ссылку тот, кто делится (§10.2).
///
/// # Ловушка для кода
///
/// **Ссылки на один канал у двух людей — разные строки.** Каждый кладёт
/// свои адреса. Тождество канала — это `group`, и сравнивать ссылки
/// как строки нельзя нигде.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// Какой канал.
    pub group: GroupId,
    /// Чьей подписи ждать от представления (§10.3, шаг 3).
    pub owner: ActorId,
    /// Ниже какой версии представление не принимать (§10.3, шаг 4).
    ///
    /// Так поднятая версия делает старые ссылки негодными, и отзыва ссылки
    /// заводить не приходится (§10.7).
    pub min_version: u64,
    /// Ключ чтения — **только у открытого канала** (§6.1).
    ///
    /// Его наличие и есть порода: у канала по приглашению ключ выдаёт
    /// владелец, и в ссылке ему делать нечего.
    pub key: Option<[u8; 32]>,
    /// Куда стучаться. Пусто — законно: остаётся почта и реле.
    pub endpoints: Vec<Endpoint>,
}

impl Invitation {
    /// Открытый ли это канал, по словам ссылки.
    ///
    /// **По словам** — представление скажет то же самое подписью, и вот
    /// ему верить можно. Расхождение между ними — отказ: ссылка с ключом
    /// к каналу по приглашению обещает доступ, которого нет.
    #[must_use]
    pub const fn claims_open(&self) -> bool {
        self.key.is_some()
    }

    /// Собирает ссылку `ratatosk:v0:channel:<base32>`.
    ///
    /// # Почему не base64url, хотя §10.1 велит его
    ///
    /// §10.1 выбирает base64url за то, что он «короче base32 на четверть»,
    /// и в знаках это правда. Но ссылку меряют не знаками: вручную её
    /// не переписывают, её снимают с экрана, а значит считать надо биты
    /// QR-кода. Там правда обратная.
    ///
    /// Алфавит base32 — цифры и заглавные буквы — целиком лежит
    /// в алфавитно-цифровом режиме QR: одиннадцать бит на **два** знака,
    /// то есть пять с половиной на знак. base64url со строчными буквами
    /// и `-_` в этот режим не влезает и едет байтовым, по восемь бит
    /// на **каждый**. Пять с половиной против восьми с запасом перекрывают
    /// четверть лишних знаков.
    ///
    /// Замерено, а не прикинуто
    /// (`base32_costs_fewer_qr_bits_than_base64url_would`): открытая ссылка
    /// с четырьмя адресами — **2200 бит в base32 против 2672 в base64url**,
    /// то есть base32 дешевле на восемнадцать процентов. Поэтому §10.1
    /// здесь не исполнен: его обоснование посчитано в тех единицах,
    /// в которых оно ничего не решает.
    ///
    /// Заодно ушло расхождение с остальными ссылками: и карточка контакта
    /// (§4.1), и сопряжение (§13.4) давно на base32.
    ///
    /// Менять кодировку задним числом значило бы ломать розданные ссылки —
    /// потому и меняем **сейчас**, пока ни одной не роздано.
    ///
    /// # Что этим не выиграно
    ///
    /// Приставка `ratatosk:v0:channel:` строчная, и она одна остаётся
    /// в байтовом режиме (`the_prefix_is_the_only_part_left_in_byte_mode`):
    /// двадцать знаков — 160 бит вместо 110. Лечится только заглавной
    /// приставкой, а она общая у трёх видов ссылок, и решать про неё надо
    /// отдельно и разом для всех.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Malformed`] — адресов больше [`MAX_ENDPOINTS`]
    /// или отказало кодирование.
    pub fn to_uri(&self) -> Result<String, ChannelError> {
        if self.endpoints.len() > MAX_ENDPOINTS {
            return Err(ChannelError::Malformed);
        }
        let bytes = canonical::encode(&self.value()).map_err(|_| ChannelError::Malformed)?;
        Ok(format!("{CHANNEL_URI_PREFIX}{}", data_encoding::BASE32_NOPAD.encode(&bytes)))
    }

    /// Разбирает ссылку.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Malformed`] — не та приставка, не та кодировка,
    /// не та форма или превышены пределы.
    pub fn from_uri(uri: &str) -> Result<Invitation, ChannelError> {
        let body = uri.strip_prefix(CHANNEL_URI_PREFIX).ok_or(ChannelError::Malformed)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| ChannelError::Malformed)?;
        let value = canonical::decode(&bytes).map_err(|_| ChannelError::Malformed)?;
        Invitation::from_value(&value)
    }

    fn value(&self) -> Value {
        let mut fields = vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(self.group.to_vec())),
            (Value::Integer(KEY_OWNER.into()), Value::Bytes(self.owner.to_vec())),
            (Value::Integer(KEY_MIN_VERSION.into()), Value::Integer(self.min_version.into())),
        ];
        if let Some(key) = self.key {
            fields.push((Value::Integer(KEY_KEY.into()), Value::Bytes(key.to_vec())));
        }
        if !self.endpoints.is_empty() {
            fields.push((
                Value::Integer(KEY_ENDPOINTS.into()),
                Value::Array(
                    self.endpoints
                        .iter()
                        .map(|endpoint| {
                            let value = match endpoint {
                                Endpoint::Onion(text)
                                | Endpoint::Chatmail(text)
                                | Endpoint::NostrRelay(text) => Value::Text(text.clone()),
                                Endpoint::Ygg(key) | Endpoint::Nostr(key) => {
                                    Value::Bytes(key.to_vec())
                                }
                            };
                            Value::Map(vec![
                                (
                                    Value::Integer(KEY_ENDPOINT_KIND.into()),
                                    Value::Integer(endpoint.code().into()),
                                ),
                                (Value::Integer(KEY_ENDPOINT_VALUE.into()), value),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        Value::Map(fields)
    }

    fn from_value(value: &Value) -> Result<Invitation, ChannelError> {
        let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
        let field = |key: u64| canonical::require(map, key).map_err(|_| ChannelError::Malformed);

        let key = match canonical::get(map, KEY_KEY) {
            Some(value) => {
                Some(canonical::as_array::<32>(value).map_err(|_| ChannelError::Malformed)?)
            }
            None => None,
        };
        let endpoints = match canonical::get(map, KEY_ENDPOINTS) {
            Some(Value::Array(items)) => {
                // Отказ, а не обрезка: адрес — это «куда стучаться», и
                // тихо выбросив часть, мы отличались бы от отправителя
                // тем, чего он не может увидеть.
                if items.len() > MAX_ENDPOINTS {
                    return Err(ChannelError::Malformed);
                }
                items.iter().map(endpoint_from_value).collect::<Result<Vec<_>, _>>()?
            }
            Some(_) => return Err(ChannelError::Malformed),
            None => Vec::new(),
        };
        Ok(Invitation {
            group: canonical::as_array::<16>(field(KEY_GROUP)?)
                .map_err(|_| ChannelError::Malformed)?,
            owner: canonical::as_array::<32>(field(KEY_OWNER)?)
                .map_err(|_| ChannelError::Malformed)?,
            min_version: canonical::as_u64(field(KEY_MIN_VERSION)?)
                .map_err(|_| ChannelError::Malformed)?,
            key,
            endpoints,
        })
    }
}

fn endpoint_from_value(value: &Value) -> Result<Endpoint, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let kind = canonical::as_u64(
        canonical::require(map, KEY_ENDPOINT_KIND).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?;
    let raw = canonical::require(map, KEY_ENDPOINT_VALUE).map_err(|_| ChannelError::Malformed)?;
    let text = || canonical::as_text(raw).map(str::to_owned).map_err(|_| ChannelError::Malformed);
    match kind {
        1 => Ok(Endpoint::Onion(text()?)),
        2 => Ok(Endpoint::Chatmail(text()?)),
        3 => {
            Ok(Endpoint::Ygg(canonical::as_array::<32>(raw).map_err(|_| ChannelError::Malformed)?))
        }
        4 => Ok(Endpoint::NostrRelay(text()?)),
        5 => Ok(Endpoint::Nostr(
            canonical::as_array::<32>(raw).map_err(|_| ChannelError::Malformed)?,
        )),
        // Незнакомый вид адреса — **отказ ссылке целиком**, и это не строгость
        // ради строгости. Ссылка ведёт в одно место; пропустив непонятный
        // адрес, мы открыли бы канал не тем путём, каким собирался тот,
        // кто делился, и молча.
        _ => Err(ChannelError::Malformed),
    }
}

// --- Тексты (§15) ---------------------------------------------------------

// Ниже — обещания, которые ядро уже выполняет, сказанные словами.
//
// Устроены они так же, как `group::EvictionConsequences` (§11.4):
// сперва **именованные свойства** протокола, потом текст, который их
// пересказывает, и проверка, связывающая одно с другим. §14 требует,
// чтобы обещания продукта не расходились со свойствами протокола,
// и единственный способ это удержать — держать их рядом.
//
// # Чего здесь нет, и это не забывчивость
//
// §15 перечисляет двенадцать текстов. Семь из них описывают то, чего
// ядро **не делает**:
//
// * `channel_preview_notice` — предпросмотр соединяется с владельцем
//   или сидом (§10.3, шаг 2). Достать представление по адресам нечем;
//   показать этот текст сегодня значило бы предупредить о соединении,
//   которого не будет;
// * `channel_history_none_notice` — глубина истории (§5.4) не собрана:
//   `archive_wrap` не пишется, и «прежние записи не передаются» верно
//   для **всех** каналов, а не «так настроен этот»;
// * `channel_slow_path_notice` — расписания §10.5 нет;
// * `relay_policy_notice` — политики раздачи (§12) нет;
// * `account_second_notice`, `account_switch_notice` —
//   мультиаккаунтности (§12) нет.
//
// Текст, описывающий несуществующее поведение, хуже отсутствующего:
// отсутствующий человек не прочтёт, а ложный он прочтёт и поверит.
// Каждый появится вместе со своим поведением.

/// Что означает открытый канал (§6.1, §10.7).
///
/// Показывается **до** подписки, до того как ссылкой поделятся, и **до
/// заведения** такого канала: непоправимое здесь одно и то же для обеих
/// сторон — ключ чтения уедет в ссылку, и закрыть доступ обратно нельзя
/// никогда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenChannelConsequences;

impl OpenChannelConsequences {
    /// Лежит ли ключ чтения в самой ссылке.
    ///
    /// Да: `Invitation::key` у открытого канала заполнен, и наличие
    /// ключа **и есть** порода (§6.1).
    pub const KEY_IS_IN_THE_LINK: bool = true;
    /// Прочтёт ли канал всякий, кому ссылку переслали.
    ///
    /// Да, и это не утечка, а способ распространения.
    pub const ANYONE_WITH_THE_LINK_READS: bool = true;
    /// Можно ли закрыть доступ обратно.
    ///
    /// Нет. Поворот ключа у открытого канала отвергается
    /// (`OpenChannelHasNoRotation`): отбирать не у кого.
    pub const ACCESS_CAN_BE_TAKEN_BACK: bool = false;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Ключ чтения лежит в самой ссылке. Любой, кому её перешлют, будет \
         читать этот канал — так он и распространяется. Закрыть доступ \
         обратно нельзя: для этого владельцу пришлось бы завести новый канал."
    }
}

/// Что означает канал по приглашению (§6.1, §10.4).
///
/// # Кому это говорится
///
/// **Тому, кто подписывается, и до подписки.** Текст §15 обращён к нему
/// прямо: «Впустить вас должен владелец». Показать его **заводящему**
/// канал — значит сказать владельцу, что его самого кто-то должен
/// впустить; так и случилось на стенде, пока это не было записано здесь.
///
/// Текста для «завожу канал по приглашению» в §15 нет вовсе, и
/// выдумывать его нельзя: текст, не связанный со свойством протокола,
/// §14 запрещает ровно так же, как текст про несуществующее поведение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateChannelConsequences;

impl PrivateChannelConsequences {
    /// Нужен ли владелец (или его делегат), чтобы впустить.
    ///
    /// Да: `AdmitToChannel` спрашивает право «впускать» и отдаёт ключ
    /// сам — без этого читать нечем.
    pub const SOMEONE_MUST_ADMIT_YOU: bool = true;
    /// Откроется ли канал до впуска.
    ///
    /// Нет: ключа чтения в ссылке нет, и поколение приезжает впуском.
    pub const OPENS_BEFORE_ADMISSION: bool = false;
    /// Узнаёт ли владелец о переходе по ссылке **сам по себе**.
    ///
    /// **Да — с тех пор, как появилась заявка** (§10.4). Переход по ссылке
    /// отправляет владельцу заявку, и карточка едет с ней же —
    /// рукопожатием (§8.2), первым кадром сессии.
    ///
    /// Полтора года это было `false`, и текст честно говорил «попросите
    /// его другим способом»: дотянуться до владельца было нечем, потому
    /// что лестница §5.4 знала только контактов, а §10.4 запрещает
    /// заводить контакт при подписке. Сессия без контакта (§8.3) это
    /// и сняла.
    pub const OWNER_LEARNS_BY_ITSELF: bool = true;

    /// Точная формулировка для UI (§15).
    ///
    /// Дословно по спеке: заявка есть, и обещание «он увидит вашу
    /// карточку» стало правдой.
    ///
    /// «Или тот, кому он это доверил» — сверх спеки, и это не вольность:
    /// §6.2 раздаёт право «впускать», и человеку честнее знать, что
    /// впустить его может не только владелец.
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Впустить вас должен владелец канала или тот, кому он это доверил, \
         и он должен быть для этого на связи. Пока он не ответит, канал \
         не откроется. Он увидит вашу карточку."
    }
}

/// Что означает передача права «впускать» (§6.2, §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmitterGrantConsequences;

impl AdmitterGrantConsequences {
    /// Остаются ли впущенные им после снятия права.
    ///
    /// Да: снятие права — это новая версия представления, и на состав
    /// она не влияет. Отозвать впуск поимённо нечем, и §6.5 требует
    /// сказать это **при назначении**, а не при снятии.
    pub const ADMITTED_STAY_AFTER_THE_RIGHT_IS_TAKEN: bool = true;
    /// Виден ли владельцу след каждого впуска.
    ///
    /// Да, пока делегат следует правилам: запись подписана им и едет
    /// всем (`channel_admits`).
    pub const OWNER_SEES_THE_TRACE: bool = true;
    /// Может ли он передать ключ мимо протокола.
    ///
    /// Да, и следа не останется. Это учёт, а не принуждение (§6.5):
    /// ключ у него на руках, и запретить ему сказать его вслух нельзя
    /// никакой криптографией.
    pub const CAN_PASS_THE_KEY_OUTSIDE: bool = true;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Он сможет впускать читателей сам, и впущенные останутся в канале, \
         даже если вы снимете его потом. Вы будете видеть, кого он впустил, \
         — но только пока он следует правилам: ключ чтения у него на руках, \
         и передать его в обход он тоже может."
    }
}

/// Что означает поворот ключа чтения (§6.4).
///
/// §6.4 требует, чтобы кнопка называлась **последствием**, а не
/// действием: «повернуть ключ» человеку ничего не говорит, «потеряют
/// доступ» — говорит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRotationConsequences;

impl KeyRotationConsequences {
    /// Теряют ли доступ к новому те, кого нет в составе.
    ///
    /// Да: новое поколение уезжает только тем, кто есть сейчас.
    pub const OUTSIDERS_LOSE_THE_FUTURE: bool = true;
    /// Остаётся ли у них прочитанное.
    ///
    /// Да, и забрать его нельзя: прежние поколения у них на диске.
    pub const OUTSIDERS_KEEP_THE_PAST: bool = true;
    /// Теряется ли архив у тех, кто остался.
    ///
    /// Нет: поколения сосуществуют (§6.4), и прежние никуда не деваются.
    pub const INSIDERS_LOSE_THE_ARCHIVE: bool = false;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Все, кого нет в вашем списке читателей, потеряют доступ к новым \
         записям. Уже прочитанное у них останется — забрать его нельзя. \
         Те, кто в списке, ничего не заметят, а история канала никуда \
         не денется."
    }
}

/// Что означает поделиться ссылкой (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharingConsequences;

impl SharingConsequences {
    /// Попадает ли в ссылку наш собственный адрес.
    ///
    /// Да: `Engine::channel_link` кладёт свои onion и почту — по ним
    /// и стучатся за представлением (§10.2).
    pub const THE_LINK_CARRIES_OUR_ADDRESS: bool = true;
    /// Узнаёт ли получивший ссылку, что мы этот канал читаем.
    ///
    /// Да: адрес в ссылке стоит рядом с идентификатором канала, и одно
    /// связывается с другим без всякого соединения.
    pub const IT_REVEALS_THAT_WE_READ_IT: bool = true;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "В ссылку попадёт ваш адрес — вы раздаёте этот канал. Любой, \
         к кому она попадёт дальше, узнает его и то, что вы этот канал \
         читаете, даже если сам подписываться не станет."
    }
}

// --- Учёт впусков (§6.5) --------------------------------------------------

/// Запись о впуске — кто кого впустил и на каком поколении ключа (§6.5).
///
/// # Это учёт, а не принуждение
///
/// Впускающий держит ключ чтения и может передать его мимо протокола —
/// следа не останется. Запись показывает владельцу тех, кто действовал
/// **по правилам**, и ничего не говорит про остальных. Обещать здесь
/// больше значило бы обещать невыполнимое.
///
/// Чинится это не записью, а поворотом (§6.4): впущенный мимо учёта
/// отваливается на ближайшем повороте, если впустивший не кормит его
/// дальше. Разовая утечка конечна; бесконечная требует постоянного
/// соучастия, и вот оно уже видно.
///
/// # Подписывает впускающий, а не владелец
///
/// Право «впускать» владелец раздаёт (§6.2), и запись — след того, кто
/// им воспользовался. Подпиши её владелец, она перестала бы что-либо
/// говорить о делегате.
///
/// # Впущенные остаются впущенными
///
/// Снятие права «впускать» не отзывает прежние впуски: отзыв был бы
/// отрицательным утверждением, а в рое надгробие не работает. §6.5
/// требует сказать это **при назначении**, а не при снятии, — и текст
/// этого предупреждения живёт в §15, а не здесь.
///
/// # Поколение в записи — то, что выдали
///
/// Не «нынешнее», а именно выданное: поворот случится, номера разойдутся,
/// и запись обязана остаться утверждением о прошлом, а не о настоящем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    /// В какой канал.
    pub group: GroupId,
    /// Кого впустили.
    pub who: ActorId,
    /// Кто впустил. Его подписью запись и проверяется.
    pub admitted_by: ActorId,
    /// На каком поколении ключа чтения (§6.4).
    pub generation: u64,
}

fn admission_value(admission: &Admission) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(admission.group.to_vec())),
        (Value::Integer(KEY_WHO.into()), Value::Bytes(admission.who.to_vec())),
        (Value::Integer(KEY_ADMITTED_BY.into()), Value::Bytes(admission.admitted_by.to_vec())),
        (Value::Integer(KEY_GENERATION.into()), Value::Integer(admission.generation.into())),
    ])
}

/// Подписывает запись о впуске и отдаёт пару «байты и подпись».
///
/// Пара, а не готовая карта, по той же причине, что у представления:
/// на диск обязаны лечь именно те байты, над которыми считана подпись
/// (§6), а не пересобранные из разобранного.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — отказало кодирование.
pub fn sign_admission(
    admitter: &Identity,
    admission: &Admission,
) -> Result<(Vec<u8>, [u8; 64]), ChannelError> {
    // Подписывает **тот, кто впустил**, и своё же имя в записи он
    // подтверждает подписью. Разойдись они — запись утверждала бы одно,
    // а доказывала другое; проверка на приёме это и ловит.
    let bytes =
        canonical::encode(&admission_value(admission)).map_err(|_| ChannelError::Malformed)?;
    let signature = admitter.sign(&bytes);
    Ok((bytes, signature))
}

/// Собирает то, что едет по проводу, из подписанной пары.
///
/// Форма карты задана здесь и только здесь — та же, что у представления,
/// и по той же причине: два сборщика одного формата разойдутся первой же
/// правкой.
#[must_use]
pub fn admission_wire_value(block_bytes: Vec<u8>, signature: &[u8; 64]) -> Value {
    wire_value(block_bytes, signature)
}

/// Разобранная, но **непроверенная** запись о впуске.
///
/// Существует затем же, зачем [`UncheckedRepresentation`]: проверку
/// подписи нельзя пропустить молча.
#[derive(Debug, Clone)]
pub struct UncheckedAdmission {
    admission: Admission,
    signature: [u8; 64],
    signed: Vec<u8>,
}

impl UncheckedAdmission {
    /// Какого канала — чтобы найти его до проверки.
    #[must_use]
    pub const fn claims_group(&self) -> &GroupId {
        &self.admission.group
    }

    /// Что записано, до проверки подписи.
    ///
    /// **Заявленное**: поверить, кто кого впустил, можно только сверив
    /// подпись с карточкой названного впускающего.
    #[must_use]
    pub const fn claims(&self) -> &Admission {
        &self.admission
    }

    /// Байты под подписью — как приняли (§6).
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }

    /// Подпись, как приехала.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Проверяет подпись ключом того, кто в записи назван впускающим.
    ///
    /// **Ключ передаёт вызывающий**, а не берётся из записи: она сама
    /// про себя говорит, кто её подписал, и поверить этому можно только
    /// сверив с карточкой, добытой отдельно.
    ///
    /// # Errors
    ///
    /// [`ChannelError::BadSignature`] — подпись не сошлась;
    /// [`ChannelError::NotTheSameChannel`] — ключ не того человека,
    /// который назван впускающим.
    pub fn verify(self, admitter: &PublicIdentity) -> Result<Admission, ChannelError> {
        if admitter.ik != self.admission.admitted_by {
            return Err(ChannelError::NotTheSameChannel);
        }
        admitter.verify(&self.signed, &self.signature).map_err(|_| ChannelError::BadSignature)?;
        Ok(self.admission)
    }
}

/// Разбирает запись о впуске. Подпись **не проверяется** — см.
/// [`UncheckedAdmission::verify`].
///
/// # Errors
///
/// [`ChannelError::Malformed`] — не та форма или не та длина поля.
pub fn parse_admission(value: &Value) -> Result<UncheckedAdmission, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let Ok(Value::Bytes(signed)) = canonical::require(map, KEY_BLOCK) else {
        return Err(ChannelError::Malformed);
    };
    let signature = canonical::as_array::<64>(
        canonical::require(map, KEY_SIGNATURE).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?;

    let inner = canonical::decode(signed).map_err(|_| ChannelError::Malformed)?;
    let fields = canonical::as_map(&inner).map_err(|_| ChannelError::Malformed)?;
    let field = |key: u64| canonical::require(fields, key).map_err(|_| ChannelError::Malformed);
    let admission = Admission {
        group: canonical::as_array::<16>(field(KEY_GROUP)?).map_err(|_| ChannelError::Malformed)?,
        who: canonical::as_array::<32>(field(KEY_WHO)?).map_err(|_| ChannelError::Malformed)?,
        admitted_by: canonical::as_array::<32>(field(KEY_ADMITTED_BY)?)
            .map_err(|_| ChannelError::Malformed)?,
        generation: canonical::as_u64(field(KEY_GENERATION)?)
            .map_err(|_| ChannelError::Malformed)?,
    };
    Ok(UncheckedAdmission { admission, signature, signed: signed.clone() })
}
