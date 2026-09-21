//! Рой: каталог пиров и участие в раздаче (фаза 2, §7.5, §7.5.1).
//!
//! # Что здесь есть и чего нет
//!
//! Здесь — **запись каталога** (`PeerRecord`) и **три состояния участия**.
//! Самого дерева раздачи (§7.1), анти-энтропии (§7.2) и вытягивания
//! (§7.4) здесь нет: они придут следующими и будут стоять на этом.
//!
//! # Почему запись подписана, хотя едет по установленной сессии
//!
//! Потому что она **пересылаемая**, и в этом весь смысл каталога:
//! владелец получает запись читателя и развозит её остальным (§7.5,
//! «каталог — сам поток блоков роя»). Не будь подписи, развозящий мог бы
//! назвать чужим адресом что угодно — а по этому адресу его будут
//! набирать.
//!
//! Тем же отличается запись от заявки §10.4: заявка едет **одному**
//! и доказана рукопожатием, а запись едет дальше.
//!
//! # Срок годности вместо отзыва
//!
//! §7.5: «срок годности убирает ушедших: перестал продлевать — выпал».
//! Отзыва нет нарочно — иначе ушедшему пришлось бы дождаться связи,
//! чтобы перестать раздавать, а он мог просто выключить телефон.
//! Цена названа вслух: объявление гаснет **не сразу**, а к концу срока.

use ratatosk_codec::{canonical, Value};
use ratatosk_crypto::{Identity, PublicIdentity};

use ratatosk_crdt::ActorId;

use crate::channel::{ChannelError, Endpoint, MAX_ENDPOINTS};
use crate::group::GroupId;

/// Сколько живёт запись каталога, мс — семь суток.
///
/// Неделя, а не сутки и не месяц, и число выбрано между двумя бедами.
/// Короткий срок гонит продление по сети: телефон, который заходит
/// в сеть раз в день, выпадал бы из каталога чаще, чем появлялся
/// в нём. Длинный оставляет в каталоге мёртвые адреса: набирающий
/// платит за них таймаутом, и §7.7 называет это «ложное have».
pub const RECORD_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// За сколько до конца срока запись продлевается, мс — двое суток.
///
/// Запас на то, чтобы устройство успело оказаться в сети. Продлевать
/// впритык значит выпадать из каталога у каждого, кто спал дольше нас.
pub const RENEW_AHEAD_MS: u64 = 2 * 24 * 60 * 60 * 1000;

/// Участие в раздаче (§7.5.1). Три состояния, а не два.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Seeding {
    /// Не раздаём никому.
    Off,
    /// **Тихая раздача — умолчание.** Адрес не объявлен, набрать нас
    /// нельзя, но по своим исходящим соединениям мы несём трафик наравне
    /// со всеми.
    ///
    /// Та самая середина, которой не хватало: рой перестаёт зависеть
    /// от того, нажмёт ли кто-нибудь кнопку, а раскрытие адреса остаётся
    /// осознанным выбором.
    Quiet,
    /// Объявленный сид: адрес в каталоге, нас набирают, отдаём по политике.
    Announced,
}

impl Seeding {
    /// Числовой код — им состояние ложится на диск.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Seeding::Off => 0,
            Seeding::Quiet => 1,
            Seeding::Announced => 2,
        }
    }

    /// Разбор кода. Незнакомый — `None`: читать чужое состояние как своё
    /// умолчание значило бы включить раздачу тому, кто её выключал.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Seeding> {
        match code {
            0 => Some(Seeding::Off),
            1 => Some(Seeding::Quiet),
            2 => Some(Seeding::Announced),
            _ => None,
        }
    }

    /// Объявлен ли адрес — то есть попадём ли мы в каталог.
    #[must_use]
    pub const fn announces_address(self) -> bool {
        matches!(self, Seeding::Announced)
    }
}

/// Последствия объявленного сидирования — то, что говорится **до** нажатия.
///
/// §7.5.1 требует, чтобы объявленное сидирование оставалось осознанным
/// выбором «с текстом про раскрытие (§15)». Самого текста §15 не приводит;
/// он собран здесь из того, что §7.5 и §10.2 говорят про раскрытие,
/// и правило то же, что у прочих: сперва последствие, потом действие.
pub struct SeedingConsequences;

impl SeedingConsequences {
    /// Узнает ли адрес каждый читатель канала. Да: каталог едет всем.
    pub const ADDRESS_REACHES_EVERY_READER: bool = true;
    /// Станут ли нас набирать незнакомые. Да, и это и есть раздача.
    pub const STRANGERS_WILL_DIAL_US: bool = true;
    /// Гаснет ли объявление сразу после отказа. **Нет**: срок годности.
    pub const STOPS_AT_ONCE: bool = false;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Ваш адрес узнает каждый, кто читает этот канал, и по нему вас будут \
         набирать незнакомые. Отказаться можно в любой момент, но объявление \
         погаснет не сразу: оно живёт неделю и просто перестанет продлеваться. \
         Тихая раздача адреса не раскрывает — вы отдаёте только тем, к кому \
         подключились сами."
    }
}

/// Кому отдаём, когда раздаём (§12, «уровни отдачи»).
///
/// **Две ручки, а не одна.** §12 начинается с этого: принимать почти
/// бесплатно и безопасно — блок самопроверяем; отдавать — это трафик
/// и признание, что данные у нас. Поэтому участие в раздаче (§7.5.1)
/// и круг тех, кому раздаём, — разные вопросы, и ответы на них
/// хранятся врозь.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sharing {
    /// Всем, кто спросил. **Умолчание, и оно таким останется** (§12).
    Everyone,
    /// Только контактам.
    Contacts,
    /// Только сверенным.
    ///
    /// §12 велит называть этот уровень тем, что он есть: сверенных
    /// единицы, и это почти «не раздавать», а не середина.
    Verified,
}

impl Sharing {
    /// Числовой код — им уровень ложится на диск.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Sharing::Everyone => 0,
            Sharing::Contacts => 1,
            Sharing::Verified => 2,
        }
    }

    /// Разбор кода. Незнакомый — `None`.
    ///
    /// Спуститься к умолчанию здесь **нельзя**: умолчание — «всем»,
    /// и прочитать чужой код как него значило бы раздать тому, кому
    /// человек раздавать запретил. Зовущий обязан решить сам, и решает
    /// он в пользу более строгого.
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Sharing> {
        match code {
            0 => Some(Sharing::Everyone),
            1 => Some(Sharing::Contacts),
            2 => Some(Sharing::Verified),
            _ => None,
        }
    }

    /// Сужает ли уровень круг — то есть надо ли сказать про цену (§12).
    #[must_use]
    pub const fn narrows_the_swarm(self) -> bool {
        !matches!(self, Sharing::Everyone)
    }
}

/// Последствия сужения круга — то, что говорится **до** нажатия (§12, §15).
///
/// Имя длиннее соседского нарочно: `channel::SharingConsequences` — про
/// показ **ссылки** (§10.2), а это про то, кому мы отдаём блоки. Две
/// разные вещи с одинаковым коротким именем однажды перепутались бы
/// на границе, где обе видны рядом.
///
/// §12 требует этого прямо: «при затягивании UI говорит, что платят
/// не только за себя». Довод там же и назван: уровни «только контактам»
/// и «только сверенным» безобидны как личный выбор и разрушительны
/// как популярный — рой сворачивается в граф контактов, то есть
/// в модель, отвергнутую за плохую связность. Заметит это не тот,
/// кто настраивал, а новый подписчик, которому некому будет ответить.
pub struct SharingLevelConsequences;

impl SharingLevelConsequences {
    /// Платит ли за сужение кто-то, кроме настроившего. Да.
    pub const OTHERS_PAY_TOO: bool = true;
    /// Остаётся ли умолчание открытым. Да, и §12 велит ему таким остаться.
    pub const DEFAULT_STAYS_OPEN: bool = true;

    /// Точная формулировка для UI (§15).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Раздача — то, чем канал держится: блоки берут друг у друга сами \
         читатели. Сузив круг, вы платите не только за себя: у нового \
         подписчика останется меньше тех, у кого можно спросить, и заметит \
         это он, а не вы. «Только сверенным» — это почти «не раздавать»: \
         сверенных обычно единицы."
    }
}

/// Пределы отдачи — те самые «три числа» §9.2, которые наши (§9.2).
///
/// Третье число — окно сидирования — живёт не здесь: для канала оно
/// «не технический параметр», а часть подписанного представления
/// (§9.3), и ставит его владелец, а не мы. Наши — два: сколько блоков
/// отдаём **одному** пиру за минуту и сколько **всем вместе**.
///
/// Выключатель §9.2 тоже отдельно: это участие в раздаче ([`Seeding`]).
/// Ноль здесь означает то же самое для блоков, но не гасит объявление
/// и не отменяет привязок — выключать раздачу надо выключателем,
/// а не нулём.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GivingLimits {
    /// Сколько блоков отдаём одному пиру за окно.
    pub per_peer: u32,
    /// Сколько блоков отдаём всем вместе за окно.
    pub total: u32,
}

impl Default for GivingLimits {
    fn default() -> GivingLimits {
        GivingLimits { per_peer: BLOCKS_PER_WINDOW, total: BLOCKS_PER_WINDOW_TOTAL }
    }
}

impl GivingLimits {
    /// Восемь байт для диска: два `u32` старшим байтом вперёд.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.per_peer.to_be_bytes());
        out[4..].copy_from_slice(&self.total.to_be_bytes());
        out
    }

    /// Разбор записанного. Не те байты — `None`, и зовущий берёт
    /// умолчание: настройка из будущей сборки не должна выключать
    /// раздачу сегодняшней.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<GivingLimits> {
        let bytes: [u8; 8] = bytes.try_into().ok()?;
        let per_peer = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let total = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Some(GivingLimits { per_peer, total })
    }

    /// Сколько ещё можно отдать этому пиру, зная отданное за окно.
    #[must_use]
    pub const fn left_for_peer(self, served_to_peer: u32, served_total: u32) -> u32 {
        let by_peer = self.per_peer.saturating_sub(served_to_peer);
        let by_total = self.total.saturating_sub(served_total);
        if by_peer < by_total {
            by_peer
        } else {
            by_total
        }
    }
}

/// Запись каталога пиров (§7.5).
///
/// `PeerRecord{ group_id, ik, addresses[], valid_until, signature }`
/// из спеки: подпись живёт рядом, в [`sign_record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// Какого канала эта раздача. Запись **не общая на все каналы**:
    /// §7.5 ключует каталог группой, и сид, раздающий два канала,
    /// объявляется в обоих — иначе читатель одного узнал бы про второй.
    pub group: GroupId,
    /// Чей адрес. Подпись проверяется его `SK`.
    pub ik: ActorId,
    /// Куда набирать. Те же виды, что в ссылке (§10.1).
    pub endpoints: Vec<Endpoint>,
    /// До какого момента запись годна, мс.
    pub valid_until_ms: u64,
}

const KEY_GROUP: u8 = 1;
const KEY_IK: u8 = 2;
const KEY_ENDPOINTS: u8 = 3;
const KEY_VALID_UNTIL: u8 = 4;
const KEY_BLOCK: u8 = 5;
const KEY_SIGNATURE: u8 = 6;
const KEY_ENDPOINT_KIND: u8 = 7;
const KEY_ENDPOINT_VALUE: u8 = 8;

fn endpoint_value(endpoint: &Endpoint) -> Value {
    let value = match endpoint {
        Endpoint::Onion(text) | Endpoint::Chatmail(text) | Endpoint::NostrRelay(text) => {
            Value::Text(text.clone())
        }
        Endpoint::Ygg(key) | Endpoint::Nostr(key) => Value::Bytes(key.to_vec()),
    };
    Value::Map(vec![
        (Value::Integer(KEY_ENDPOINT_KIND.into()), Value::Integer(endpoint_code(endpoint).into())),
        (Value::Integer(KEY_ENDPOINT_VALUE.into()), value),
    ])
}

/// Код вида адреса — **тот же, что в ссылке** (§10.1).
///
/// Числа повторены здесь нарочно и сверены проверкой
/// `a_catalogue_speaks_the_same_address_codes_as_a_link`: разойдись они,
/// один и тот же onion означал бы в каталоге и в ссылке разное, и понять
/// это можно было бы только по тому, что до сида не дозвонились.
const fn endpoint_code(endpoint: &Endpoint) -> u64 {
    match endpoint {
        Endpoint::Onion(_) => 1,
        Endpoint::Chatmail(_) => 2,
        Endpoint::Ygg(_) => 3,
        Endpoint::NostrRelay(_) => 4,
        Endpoint::Nostr(_) => 5,
    }
}

fn endpoint_from_value(value: &Value) -> Result<Endpoint, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let kind = canonical::as_u64(
        canonical::require(map, KEY_ENDPOINT_KIND.into()).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?;
    let raw =
        canonical::require(map, KEY_ENDPOINT_VALUE.into()).map_err(|_| ChannelError::Malformed)?;
    let text = || canonical::as_text(raw).map(str::to_owned).map_err(|_| ChannelError::Malformed);
    let bytes = || canonical::as_array::<32>(raw).map_err(|_| ChannelError::Malformed);
    match kind {
        1 => Ok(Endpoint::Onion(text()?)),
        2 => Ok(Endpoint::Chatmail(text()?)),
        3 => Ok(Endpoint::Ygg(bytes()?)),
        4 => Ok(Endpoint::NostrRelay(text()?)),
        5 => Ok(Endpoint::Nostr(bytes()?)),
        // Незнакомый вид — отказ записи целиком, ровно как в ссылке:
        // пропустив его, мы держали бы в каталоге запись, которая
        // обещает путь, которого не понимаем.
        _ => Err(ChannelError::Malformed),
    }
}

fn record_value(record: &PeerRecord) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(record.group.to_vec())),
        (Value::Integer(KEY_IK.into()), Value::Bytes(record.ik.to_vec())),
        (
            Value::Integer(KEY_ENDPOINTS.into()),
            Value::Array(record.endpoints.iter().map(endpoint_value).collect()),
        ),
        (Value::Integer(KEY_VALID_UNTIL.into()), Value::Integer(record.valid_until_ms.into())),
    ])
}

fn record_from_value(value: &Value) -> Result<PeerRecord, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let field = |key: u8| canonical::require(map, key.into()).map_err(|_| ChannelError::Malformed);
    let endpoints = match canonical::get(map, KEY_ENDPOINTS.into()) {
        Some(Value::Array(items)) => {
            if items.len() > MAX_ENDPOINTS {
                return Err(ChannelError::Malformed);
            }
            items.iter().map(endpoint_from_value).collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => return Err(ChannelError::Malformed),
        None => Vec::new(),
    };
    Ok(PeerRecord {
        group: canonical::as_array::<16>(field(KEY_GROUP)?).map_err(|_| ChannelError::Malformed)?,
        ik: canonical::as_array::<32>(field(KEY_IK)?).map_err(|_| ChannelError::Malformed)?,
        endpoints,
        valid_until_ms: canonical::as_u64(field(KEY_VALID_UNTIL)?)
            .map_err(|_| ChannelError::Malformed)?,
    })
}

/// Подписывает запись и отдаёт пару «байты и подпись».
///
/// Пара, а не готовая карта, по той же причине, что у представления
/// (§6.1): на диск обязаны лечь именно те байты, над которыми считана
/// подпись, а не пересобранные из разобранного.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — адресов больше [`MAX_ENDPOINTS`] либо
/// подписывающий назвал чужой `ik`; отказ кодирования.
pub fn sign_record(
    seed: &Identity,
    record: &PeerRecord,
) -> Result<(Vec<u8>, [u8; 64]), ChannelError> {
    if record.endpoints.len() > MAX_ENDPOINTS {
        return Err(ChannelError::Malformed);
    }
    // Своё имя в записи подтверждается своей же подписью. Разойдись они —
    // запись утверждала бы одно, а проверялась другим, и адрес в каталоге
    // оказался бы чужим.
    if record.ik != seed.public().ik {
        return Err(ChannelError::Malformed);
    }
    let bytes = canonical::encode(&record_value(record)).map_err(|_| ChannelError::Malformed)?;
    let signature = seed.sign(&bytes);
    Ok((bytes, signature))
}

/// То, что едет по проводу: подписанные байты рядом с подписью.
#[must_use]
pub fn wire_value(block_bytes: Vec<u8>, signature: &[u8; 64]) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_BLOCK.into()), Value::Bytes(block_bytes)),
        (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
    ])
}

/// Разобранная, но **непроверенная** запись каталога.
///
/// Существует затем же, зачем `channel::UncheckedRepresentation`: забыть
/// проверку подписи можно только написав «не проверять» словами.
#[derive(Debug, Clone)]
pub struct UncheckedRecord {
    record: PeerRecord,
    signature: [u8; 64],
    signed: Vec<u8>,
}

impl UncheckedRecord {
    /// Какого канала запись — чтобы найти канал до проверки.
    #[must_use]
    pub const fn claims_group(&self) -> &GroupId {
        &self.record.group
    }

    /// Чей адрес, по словам самой записи.
    ///
    /// **Заявленное значение.** Проверять его надо тем, что известно
    /// иначе: запись, назвавшая своим `ik` кого угодно, свою же подпись
    /// пройдёт — она ею и подписана.
    #[must_use]
    pub const fn claims_ik(&self) -> &ActorId {
        &self.record.ik
    }

    /// Байты, над которыми считана подпись, — как приняли.
    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed
    }

    /// Сама подпись.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Отдаёт запись **без проверки подписи**, и название об этом говорит.
    ///
    /// # Когда это законно
    ///
    /// Ровно в одном случае: проверить нечем. Карточки сида у читателя
    /// может не быть вовсе — читатели канала друг друга не знают (§3.2), —
    /// а адрес и так ничем не подтверждён (§10.2): личность устанавливает
    /// рукопожатие (§8.2), и подделанный адрес в худшем случае не ответит.
    ///
    /// Выбросив такую запись, мы потеряли бы единственный путь к сиду,
    /// чьей карточки у нас нет, — то есть ровно то, ради чего каталог
    /// и заведён. Поэтому запись берут, но называют вещи своими именами:
    /// наружу она едет с признаком «подпись не проверена».
    #[must_use]
    pub fn untrusted(self) -> PeerRecord {
        self.record
    }

    /// Проверяет подпись и отдаёт запись.
    ///
    /// # Errors
    ///
    /// [`ChannelError::BadSignature`] — подпись не сошлась.
    pub fn verify(self, author: &PublicIdentity) -> Result<PeerRecord, ChannelError> {
        if author.ik != self.record.ik {
            return Err(ChannelError::BadSignature);
        }
        author.verify(&self.signed, &self.signature).map_err(|_| ChannelError::BadSignature)?;
        Ok(self.record)
    }
}

/// Кадр дерева раздачи: `IHAVE`, `GRAFT`, `PRUNE` (§7.1).
///
/// # Один тип на три вида, и это не экономия
///
/// Правило «отдельный тип, а не признак» защищает от одного: показать
/// незнакомое как знакомое. Здесь показывать нечего вовсе — эти кадры
/// человек не видит никогда. А вот механизм у них один: дерево, в котором
/// `IHAVE` зовёт, `GRAFT` чинит, `PRUNE` подрезает. Сборка, которая знает
/// один из трёх, обязана знать все три: понимающая `IHAVE`, но не
/// понимающая `GRAFT`, звала бы к себе блоки и не умела бы их попросить.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// «У меня есть такой блок» — зов ленивому пиру (§7.1).
    IHave {
        /// Какого канала.
        group: GroupId,
        /// Какой блок: номер конверта.
        block: [u8; 16],
    },
    /// «Пришли его и переведи меня в eager» — починка дерева (§7.1, шаг 4).
    Graft {
        /// Какого канала.
        group: GroupId,
        /// Какой блок.
        block: [u8; 16],
    },
    /// «Вот что у меня есть» — have-вектор анти-энтропии (§7.2).
    ///
    /// Дерево возит хвост, анти-энтропия — историю; рубеж тот же, что
    /// «живая лента / архив». Вектор ключуется **по автору**, а авторов
    /// в канале единицы: при одном публикаторе это одна строка, хоть
    /// при десяти тысячах читателей (§7.5.2).
    Have {
        /// Какого канала.
        group: GroupId,
        /// Что есть по каждому автору.
        ranges: Vec<Range>,
    },
    /// «Пришли мне вот это» — просьба анти-энтропии (§7.2).
    ///
    /// Спрашивается **диапазон**, а не отдельный номер, и это не удобство:
    /// у читателя в журнале законные дыры — позиции адресных блоков,
    /// которые до него не доезжали (`phase2-plan.md`, расхождение 13).
    /// Попроси он «дай 47», ответом было бы молчание, неотличимое
    /// от потери.
    Want {
        /// Какого канала.
        group: GroupId,
        /// Чья цепочка.
        author: ActorId,
        /// С какого номера, включительно.
        from_seq: u64,
        /// По какой, включительно. Ответ короче — законен.
        to_seq: u64,
    },
    /// «Не шли мне целиком, я уже получил это иначе» (§7.1, шаг 3).
    ///
    /// Блок не называется: подрезается **ребро**, а не доставка. Назови
    /// мы блок, пришлось бы решать, что делать со следующим, — а ответ
    /// один: лишние рёбра отмирают, дерево возникает само.
    Prune {
        /// Какого канала.
        group: GroupId,
    },
}

/// Строка have-вектора: что есть у пира по одному автору (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// Чья цепочка.
    pub author: ActorId,
    /// Самый ранний номер, который у него есть.
    ///
    /// «`first_seq` не равен нулю, если префикс обрезан окном
    /// сидирования» (§7.2).
    pub first_seq: u64,
    /// Самый поздний.
    pub last_seq: u64,
}

/// Окно, в котором считаются пределы на пира, мс (§7.7).
///
/// Минута: короче — и одна пачка блоков после долгого отсутствия
/// выглядела бы затоплением; длиннее — и затопивший успел бы навредить,
/// прежде чем счётчик его заметит.
pub const BUDGET_WINDOW_MS: u64 = 60_000;

/// Сколько **повторных** зовов принимаем от одного пира за окно (§7.7,
/// «затопление `IHAVE`»).
///
/// # Считаются не зовы, а повторы одного и того же
///
/// Повтор — это зов того же пира о том же блоке, которого мы от него
/// уже ждём. Всё остальное — работа: зов о блоке, который у нас уже
/// есть, значит, что копия обогнала зов; зов другого пира о том, чего
/// мы ждём, значит, что у блока в рое два источника, и второй зовёт
/// просто потому, что первым не был.
///
/// Первая редакция считала все зовы и остужала честного сида за занятую
/// ленту: семьдесят слов подряд — это семьдесят законных зовов. Вторая
/// считала любой зов о том, чего мы ждём, и остужала сида за то, что
/// владелец позвал раньше. Обе покраснели на
/// `an_honest_seed_is_not_cooled_by_a_busy_channel`.
pub const EMPTY_CALLS_PER_WINDOW: u32 = 32;

/// Сколько неотвеченных зовов от одного пира держим в памяти (§7.7).
///
/// **Предел памяти, а не признак вины.** Назвать тысячу выдуманных
/// блоков дешевле, чем их иметь, — поэтому ждущих зовов не бывает
/// больше этого числа. Но и честный сид накапливает их пачкой: канал,
/// в котором сказали семьдесят слов подряд, — это семьдесят законных
/// зовов разом. Поэтому сверх предела зов просто **не берётся в счёт**,
/// а остывание за это не ставится: молчуна отличает не всплеск,
/// а то, что блоки потом так и не приходят.
///
/// Ровно на этом покраснела проверка `an_honest_seed_is_not_cooled_by_a_busy_channel`.
pub const OUTSTANDING_CALLS: usize = 256;

/// Сколько блоков отдаём одному пиру за окно (§7.7, «бесконечное
/// вытягивание — предел на пира»).
///
/// Вдвое больше, чем влезает в один ответ: догоняющий после отлучки
/// вправе получить свой хвост, а тянущий бесконечно упрётся в предел.
pub const BLOCKS_PER_WINDOW: u32 = 2 * MAX_WANT_BLOCKS as u32;

/// Сколько блоков отдаём **всем вместе** за окно (§9.2, «общий предел»).
///
/// Четвёртое число §9.2 и единственное, которое считает не пира,
/// а нас самих: предел на пира (`BLOCKS_PER_WINDOW`) защищает
/// от одного жадного, общий — от десяти вежливых. Сервера нет,
/// значит ограничителя частоты нет ни у кого, кроме нас самих, —
/// и это тот случай, когда платит человек: его трафиком, его
/// батареей, его тарифом.
///
/// Восемь полных ответов в минуту: заметно больше, чем нужно каналу
/// с живой лентой, и заметно меньше, чем выест догоняющий рой
/// на телефоне. Число — умолчание, а не предел: §9.2 велит держать
/// его **на диске**, и человек вправе его подвинуть.
pub const BLOCKS_PER_WINDOW_TOTAL: u32 = 8 * MAX_WANT_BLOCKS as u32;

/// Сколько неответов подряд до остывания (§7.7, «ложное `have`»).
///
/// Два, а не один: первый неответ — обычное дело (собеседник ушёл
/// из сети ровно между зовом и просьбой), а второй подряд уже
/// говорит о том, что звали не того.
pub const MISSES_BEFORE_COOLING: u32 = 2;

/// Сколько длится остывание, мс (§7.7).
///
/// Четверть часа — та же ступенька, что у расписания §10.5: реже
/// спрашивать бессмысленно, чаще — значит не остывать вовсе.
pub const COOLING_MS: u64 = 15 * 60_000;

/// Сколько блоков отдают на одну просьбу (§7.2: «не более 128»).
pub const MAX_WANT_BLOCKS: usize = 128;

/// Сколько просьб шлём за один обмен векторами (§7.2, §7.7).
///
/// Дыр у читателя, пропавшего надолго, бывает много, а ответ на просьбу
/// ограничен ста двадцатью восемью блоками. Спроси мы обо всём разом,
/// один вернувшийся узел получил бы от соседа столько кадров, сколько
/// §7.7 отдавать не велит, — и остыл бы у него сам. Остальное
/// спрашивается следующим обменом: дыра никуда не денется, она видна
/// по номеру (§7.3).
pub const MAX_WANTS_PER_ROUND: usize = 8;

/// Чего у нас нет из того, что назвал сосед (§7.2, §7.3).
///
/// `wanted` — кусок соседа, `mine` — **наши** сплошные куски того же
/// автора, упорядоченные по возрастанию. Отдаются дыры: то, что есть
/// у него и нет у нас.
///
/// # Почему это считается, а не берётся из «последнего номера»
///
/// Первая редакция спрашивала «всё, что новее нашего последнего», и
/// пропуск в середине не чинился никогда: по нашему же вектору выходило,
/// что просить нечего. §7.3 говорит обратное — «узел, имеющий 46 и 48,
/// **знает**, что 47 существует», — и знание это обязано превращаться
/// в просьбу.
#[must_use]
pub fn gaps(wanted: (u64, u64), mine: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let (from, to) = wanted;
    if from > to {
        return Vec::new();
    }
    let mut holes = Vec::new();
    let mut edge = from;
    for &(first, last) in mine {
        if last < edge {
            continue;
        }
        if first > to {
            break;
        }
        if first > edge {
            holes.push((edge, first.saturating_sub(1)));
        }
        edge = last.saturating_add(1);
        if edge > to {
            return holes;
        }
    }
    if edge <= to {
        holes.push((edge, to));
    }
    holes
}

/// Сколько строк в have-векторе принимаем.
///
/// Авторов в канале единицы (§7.5.2), и вектор на тридцать две строки —
/// это уже канал с тремя десятками публикаторов. Предел здесь против
/// чужого кадра, а не против своего: §7.7 велит считать пределы на пира.
pub const MAX_HAVE_RANGES: usize = 32;

const KIND_IHAVE: u64 = 1;
const KIND_GRAFT: u64 = 2;
const KIND_PRUNE: u64 = 3;
const KIND_HAVE: u64 = 4;
const KIND_WANT: u64 = 5;
const KEY_KIND: u8 = 9;
const KEY_BLOCK_ID: u8 = 10;
const KEY_RANGES: u8 = 11;
const KEY_AUTHOR: u8 = 12;
const KEY_FIRST: u8 = 13;
const KEY_LAST: u8 = 14;

impl Control {
    /// Какого канала кадр — это есть у всех видов.
    #[must_use]
    pub const fn group(&self) -> &GroupId {
        match self {
            Control::IHave { group, .. }
            | Control::Graft { group, .. }
            | Control::Have { group, .. }
            | Control::Want { group, .. } => group,
            Control::Prune { group } => group,
        }
    }

    /// То, что едет по проводу.
    #[must_use]
    pub fn value(&self) -> Value {
        let mut fields = vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(self.kind().into())),
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(self.group().to_vec())),
        ];
        match self {
            Control::IHave { block, .. } | Control::Graft { block, .. } => {
                fields.push((Value::Integer(KEY_BLOCK_ID.into()), Value::Bytes(block.to_vec())));
            }
            Control::Prune { .. } => {}
            Control::Have { ranges, .. } => {
                fields.push((
                    Value::Integer(KEY_RANGES.into()),
                    Value::Array(
                        ranges
                            .iter()
                            .map(|range| {
                                Value::Map(vec![
                                    (
                                        Value::Integer(KEY_AUTHOR.into()),
                                        Value::Bytes(range.author.to_vec()),
                                    ),
                                    (
                                        Value::Integer(KEY_FIRST.into()),
                                        Value::Integer(range.first_seq.into()),
                                    ),
                                    (
                                        Value::Integer(KEY_LAST.into()),
                                        Value::Integer(range.last_seq.into()),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ));
            }
            Control::Want { author, from_seq, to_seq, .. } => {
                fields.push((Value::Integer(KEY_AUTHOR.into()), Value::Bytes(author.to_vec())));
                fields.push((Value::Integer(KEY_FIRST.into()), Value::Integer((*from_seq).into())));
                fields.push((Value::Integer(KEY_LAST.into()), Value::Integer((*to_seq).into())));
            }
        }
        Value::Map(fields)
    }

    const fn kind(&self) -> u64 {
        match self {
            Control::IHave { .. } => KIND_IHAVE,
            Control::Graft { .. } => KIND_GRAFT,
            Control::Prune { .. } => KIND_PRUNE,
            Control::Have { .. } => KIND_HAVE,
            Control::Want { .. } => KIND_WANT,
        }
    }

    /// Читает кадр дерева с провода.
    ///
    /// # Errors
    ///
    /// [`ChannelError::Malformed`] — не та форма, не та длина или
    /// незнакомый вид. Незнакомый вид — отказ, а не пропуск: кадр
    /// управления, которого мы не понимаем, менять дерево не должен.
    pub fn from_value(value: &Value) -> Result<Control, ChannelError> {
        let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
        let kind = canonical::require(map, KEY_KIND.into())
            .and_then(canonical::as_u64)
            .map_err(|_| ChannelError::Malformed)?;
        let group = canonical::require(map, KEY_GROUP.into())
            .and_then(canonical::as_array::<16>)
            .map_err(|_| ChannelError::Malformed)?;
        let block = || {
            canonical::require(map, KEY_BLOCK_ID.into())
                .and_then(canonical::as_array::<16>)
                .map_err(|_| ChannelError::Malformed)
        };
        let number = |key: u8| {
            canonical::require(map, key.into())
                .and_then(canonical::as_u64)
                .map_err(|_| ChannelError::Malformed)
        };
        match kind {
            KIND_IHAVE => Ok(Control::IHave { group, block: block()? }),
            KIND_GRAFT => Ok(Control::Graft { group, block: block()? }),
            KIND_PRUNE => Ok(Control::Prune { group }),
            KIND_HAVE => {
                let Some(Value::Array(items)) = canonical::get(map, KEY_RANGES.into()) else {
                    return Err(ChannelError::Malformed);
                };
                // Отказ, а не обрезка: приняв половину вектора, мы
                // попросили бы не то и не у того, а объяснить это
                // приславшему было бы нечем.
                if items.len() > MAX_HAVE_RANGES {
                    return Err(ChannelError::Malformed);
                }
                let mut ranges = Vec::with_capacity(items.len());
                for item in items {
                    let row = canonical::as_map(item).map_err(|_| ChannelError::Malformed)?;
                    let field = |key: u8| {
                        canonical::require(row, key.into()).map_err(|_| ChannelError::Malformed)
                    };
                    let author = canonical::as_array::<32>(field(KEY_AUTHOR)?)
                        .map_err(|_| ChannelError::Malformed)?;
                    let first = canonical::as_u64(field(KEY_FIRST)?)
                        .map_err(|_| ChannelError::Malformed)?;
                    let last =
                        canonical::as_u64(field(KEY_LAST)?).map_err(|_| ChannelError::Malformed)?;
                    // Перевёрнутый диапазон — испорченный кадр: «есть
                    // с сорок восьмого по сорок шестой» не значит ничего.
                    if last < first {
                        return Err(ChannelError::Malformed);
                    }
                    ranges.push(Range { author, first_seq: first, last_seq: last });
                }
                Ok(Control::Have { group, ranges })
            }
            KIND_WANT => {
                let author = canonical::require(map, KEY_AUTHOR.into())
                    .and_then(canonical::as_array::<32>)
                    .map_err(|_| ChannelError::Malformed)?;
                let (from_seq, to_seq) = (number(KEY_FIRST)?, number(KEY_LAST)?);
                if to_seq < from_seq {
                    return Err(ChannelError::Malformed);
                }
                Ok(Control::Want { group, author, from_seq, to_seq })
            }
            _ => Err(ChannelError::Malformed),
        }
    }
}

/// Бывает ли пир на этой ступени **ленивым** (§8.4).
///
/// §8.4 расписывает роли ступеней прямо:
///
/// | Ступень | Роль в gossip |
/// |---|---|
/// | LAN | eager, приоритетный |
/// | ygg / onion | eager и lazy — основная ткань дерева |
/// | bluetooth | **только eager, только хвост**; архив не возит |
/// | почта, nostr | **всегда eager, никогда lazy** |
///
/// Довод у почты и реле назван там же: «`IHAVE` с ответом через часы
/// бессмыслен». У эфира он другой и не про скорость: 9–12 КБ/с и класс
/// S — зов там дешевле блока, но разница съедается вторым кругом
/// «зов → срок → `GRAFT`», а сроки в комнате без сети некому пережить.
///
/// **Цена ошибки здесь — молчание.** Ленивый на почте получает зов,
/// заводить срок ему нечем (см. [`graft_wait_ms`]), и блок он попросит
/// только анти-энтропией — часы спустя. Снаружи это «слово не дошло»,
/// а не «дошло позже».
#[must_use]
pub const fn may_be_lazy(via: crate::transport_policy::Transport) -> bool {
    use crate::transport_policy::Transport;
    matches!(via, Transport::Lan | Transport::Ygg | Transport::Onion)
}

/// Возит ли ступень **архив** (§8.4): эфир — нет.
///
/// «Эфир не возит архив: 9–12 КБ/с, мебибайт — полторы минуты».
/// Спрашивается на обоих концах: просящий не просит того, что
/// не доедет, отдающий не отдаёт того, что не увезёт. Живая лента
/// по эфиру при этом ходит — §8.4 оставляет ему хвост.
#[must_use]
pub const fn carries_archive(via: crate::transport_policy::Transport) -> bool {
    use crate::transport_policy::Transport;
    !matches!(via, Transport::Bt)
}

/// Сколько ждать блок после `IHAVE`, прежде чем звать `GRAFT` (§7.1, §7.7).
///
/// # Число берётся у ступени, а не выдумывается здесь
///
/// §7.7 говорит «секунды в LAN, десятки секунд в onion» — то есть ровно
/// то, что у ступени уже посчитано сроком ответа. Заведи мы своё число,
/// оно разошлось бы с ним при первой же правке: у ступени срок меняют,
/// когда меняют её саму, а про срок дерева в тот день никто не вспомнит.
///
/// # У медленных ступеней `GRAFT` не зовут вовсе
///
/// Почта и реле ответа не обещают (§5.3, 0.3): блок едет минутами
/// и часами, и `GRAFT` там значил бы «попроси ещё раз то, что и так
/// в пути» — то есть удвоение трафика ради нетерпения. Потерянное
/// на медленной ступени чинит анти-энтропия (§7.2), а не дерево.
#[must_use]
pub fn graft_wait_ms(via: crate::transport_policy::Transport) -> Option<u64> {
    use crate::transport_policy::{
        Transport, BT_RECEIPT_TIMEOUT_MS, LAN_RECEIPT_TIMEOUT_MS, ONION_REPLY_TIMEOUT_MS,
        YGG_RECEIPT_TIMEOUT_MS,
    };
    // **Одно решение, а не два.** Кто бывает ленивым, сказано
    // в [`may_be_lazy`]; срок заводится ровно тем, кто им бывает.
    // Разойдись эти два места, зов приехал бы туда, где его некому
    // превратить в просьбу, — то есть в молчание.
    if !may_be_lazy(via) {
        return None;
    }
    match via {
        Transport::Lan => Some(LAN_RECEIPT_TIMEOUT_MS),
        Transport::Bt => Some(BT_RECEIPT_TIMEOUT_MS),
        Transport::Ygg => Some(YGG_RECEIPT_TIMEOUT_MS),
        Transport::Onion => Some(ONION_REPLY_TIMEOUT_MS),
        Transport::Nostr | Transport::Mail => None,
    }
}

/// Привязка к сиду: «я читаю этот канал» (§7.5.1).
///
/// # Подписи нет, и она была бы лишней
///
/// Привязка едет по установленной сессии: кто просит, доказано
/// рукопожатием. А **право** просить не проверяется вовсе — §7.6:
/// «любой, у кого есть идентификатор канала, вправе вытянуть
/// шифротекст; прочесть — нет». Сид не знает состава и проверить
/// всё равно не смог бы.
#[must_use]
pub fn attach_value(group: &GroupId) -> Value {
    Value::Map(vec![(Value::Integer(KEY_GROUP.into()), Value::Bytes(group.to_vec()))])
}

/// Читает привязку с провода.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — не та форма или не та длина.
pub fn attach_from_value(value: &Value) -> Result<GroupId, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    canonical::require(map, KEY_GROUP.into())
        .and_then(canonical::as_array::<16>)
        .map_err(|_| ChannelError::Malformed)
}

/// Читает запись с провода — **без** проверки подписи.
///
/// # Errors
///
/// [`ChannelError::Malformed`] — не та форма, не та длина, незнакомый
/// вид адреса.
pub fn record_from_wire(value: &Value) -> Result<UncheckedRecord, ChannelError> {
    let map = canonical::as_map(value).map_err(|_| ChannelError::Malformed)?;
    let block = canonical::as_bytes(
        canonical::require(map, KEY_BLOCK.into()).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?
    .to_vec();
    let signature = canonical::as_array::<64>(
        canonical::require(map, KEY_SIGNATURE.into()).map_err(|_| ChannelError::Malformed)?,
    )
    .map_err(|_| ChannelError::Malformed)?;
    let decoded = canonical::decode(&block).map_err(|_| ChannelError::Malformed)?;
    let record = record_from_value(&decoded)?;
    Ok(UncheckedRecord { record, signature, signed: block })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hole_in_the_middle_is_asked_for_and_the_covered_part_is_not() {
        // §7.3: «узел, имеющий 46 и 48, знает, что 47 существует».
        // Знание превращается в просьбу ровно здесь.
        assert_eq!(gaps((40, 50), &[(40, 46), (48, 50)]), vec![(47, 47)]);
        // Всё закрыто — просить нечего, и это не то же, что «спросить обо всём».
        assert_eq!(gaps((40, 50), &[(30, 60)]), Vec::new());
        // Нет ничего — просим целиком.
        assert_eq!(gaps((40, 50), &[]), vec![(40, 50)]);
    }

    #[test]
    fn the_edges_are_asked_for_too_and_the_order_is_from_old_to_new() {
        // Хвост (новее нашего последнего) и начало (старше нашего
        // первого) — такие же дыры, как середина: разница только в том,
        // что у краёв нет второй границы.
        assert_eq!(gaps((1, 100), &[(50, 60)]), vec![(1, 49), (61, 100)]);
        // Порядок — от старого к новому: он же порядок в векторе, и
        // на нём стоит выбор «что спросить первым» у зовущего.
        assert_eq!(gaps((1, 100), &[(10, 20), (30, 40)]), vec![(1, 9), (21, 29), (41, 100)]);
    }

    #[test]
    fn an_upside_down_want_asks_for_nothing() {
        // «С пятидесятого по сороковой» не значит ничего — и точно
        // не значит «весь журнал».
        assert_eq!(gaps((50, 40), &[]), Vec::new());
        // Один номер — законная просьба, и она не теряется.
        assert_eq!(gaps((7, 7), &[]), vec![(7, 7)]);
        assert_eq!(gaps((7, 7), &[(7, 7)]), Vec::new());
    }

    fn seed_identity(byte: u8) -> Identity {
        Identity::from_seed([byte; 32])
    }

    fn record(byte: u8, until: u64) -> PeerRecord {
        PeerRecord {
            group: [7u8; 16],
            ik: seed_identity(byte).public().ik,
            endpoints: vec![
                Endpoint::Onion(
                    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion".into(),
                ),
                Endpoint::Nostr([9u8; 32]),
            ],
            valid_until_ms: until,
        }
    }

    #[test]
    fn a_record_survives_the_round_trip() {
        let me = seed_identity(1);
        let record = record(1, 1_000);
        let (bytes, signature) = sign_record(&me, &record).expect("подписывается");
        let back = record_from_wire(&wire_value(bytes, &signature)).expect("разбирается");
        assert_eq!(back.claims_group(), &record.group);
        assert_eq!(back.verify(&me.public()).expect("подпись сходится"), record);
    }

    #[test]
    fn a_record_signed_by_someone_else_is_refused() {
        // Каталог **пересылаемый**: владелец развозит чужие записи.
        // Не проверь мы подпись, развозящий назвал бы чужим адресом
        // что угодно — а по этому адресу собеседника будут набирать.
        let (me, other) = (seed_identity(1), seed_identity(2));
        let (bytes, signature) = sign_record(&me, &record(1, 1_000)).expect("подписывается");
        let unchecked = record_from_wire(&wire_value(bytes, &signature)).expect("разбирается");
        assert!(matches!(unchecked.verify(&other.public()), Err(ChannelError::BadSignature)));
    }

    #[test]
    fn a_record_about_someone_else_does_not_get_signed() {
        // Своё имя в записи подтверждается своей же подписью, и подделать
        // это надо ловить **на отправке** тоже: собрать запись, которую
        // никто не примет, значит потратить круг по сети на объяснение.
        let me = seed_identity(1);
        let mut theirs = record(1, 1_000);
        theirs.ik = seed_identity(2).public().ik;
        assert!(matches!(sign_record(&me, &theirs), Err(ChannelError::Malformed)));
    }

    #[test]
    fn a_catalogue_speaks_the_same_address_codes_as_a_link() {
        // Числа видов адреса повторены в двух местах — в ссылке (§10.1)
        // и здесь, — и разойтись они не вправе: один и тот же onion
        // обязан означать в каталоге то же, что в ссылке. Проверяется
        // **через провод**, а не сравнением констант: сравнение констант
        // прошло бы и при перепутанном разборе.
        let me = seed_identity(1);
        let all = vec![
            Endpoint::Onion("aaaa.onion".into()),
            Endpoint::Chatmail("kot@nine.example".into()),
            Endpoint::Ygg([6u8; 32]),
            Endpoint::NostrRelay("wss://relay.nine.example".into()),
            Endpoint::Nostr([9u8; 32]),
        ];
        let mut mine = record(1, 1_000);
        mine.endpoints.clone_from(&all);
        let (bytes, signature) = sign_record(&me, &mine).expect("подписывается");
        let back = record_from_wire(&wire_value(bytes, &signature))
            .expect("разбирается")
            .verify(&me.public())
            .expect("подпись сходится");
        assert_eq!(back.endpoints, all);

        // И та же пятёрка, проехав ссылкой, читается теми же видами.
        let link = crate::channel::Invitation {
            group: [7u8; 16],
            owner: me.public().ik,
            min_version: 1,
            key: None,
            endpoints: all.clone(),
        };
        let parsed = crate::channel::Invitation::from_uri(&link.to_uri().expect("ссылка"))
            .expect("разбирается");
        assert_eq!(parsed.endpoints, all);
    }

    #[test]
    fn too_many_addresses_are_refused_on_both_sides() {
        let me = seed_identity(1);
        let mut crowded = record(1, 1_000);
        crowded.endpoints = (0..=MAX_ENDPOINTS).map(|_| Endpoint::Nostr([1u8; 32])).collect();
        assert!(matches!(sign_record(&me, &crowded), Err(ChannelError::Malformed)));
    }

    #[test]
    fn a_have_vector_survives_the_round_trip() {
        // §7.2: «`Have{ ranges: [ { author_ik, first_seq, last_seq } ] }`».
        let have = Control::Have {
            group: [7u8; 16],
            ranges: vec![
                Range { author: [1u8; 32], first_seq: 0, last_seq: 9 },
                Range { author: [2u8; 32], first_seq: 40, last_seq: 41 },
            ],
        };
        assert_eq!(Control::from_value(&have.value()).expect("разбирается"), have);
    }

    #[test]
    fn a_want_asks_for_a_range_and_not_for_a_number() {
        // Спрашивается диапазон: у читателя в журнале законные дыры —
        // позиции адресных блоков, которые до него не доезжали.
        let want = Control::Want { group: [7u8; 16], author: [1u8; 32], from_seq: 40, to_seq: 60 };
        assert_eq!(Control::from_value(&want.value()).expect("разбирается"), want);
    }

    #[test]
    fn an_upside_down_range_is_refused() {
        // «Есть с сорок восьмого по сорок шестой» не значит ничего,
        // а спрошенное задом наперёд заставило бы отвечающего гадать.
        let mut broken = Control::Have {
            group: [7u8; 16],
            ranges: vec![Range { author: [1u8; 32], first_seq: 9, last_seq: 0 }],
        }
        .value();
        assert!(matches!(Control::from_value(&broken), Err(ChannelError::Malformed)));
        broken =
            Control::Want { group: [7u8; 16], author: [1u8; 32], from_seq: 9, to_seq: 0 }.value();
        assert!(matches!(Control::from_value(&broken), Err(ChannelError::Malformed)));
    }

    #[test]
    fn a_have_vector_longer_than_the_limit_is_refused_whole() {
        // Обрезка здесь была бы хуже отказа: приняв половину вектора,
        // мы попросили бы не то и не у того, а сказать об этом
        // приславшему было бы нечем.
        let ranges = (0..=MAX_HAVE_RANGES)
            .map(|i| Range {
                author: [u8::try_from(i).unwrap_or(0); 32],
                first_seq: 0,
                last_seq: 1,
            })
            .collect();
        let crowded = Control::Have { group: [7u8; 16], ranges };
        assert!(matches!(Control::from_value(&crowded.value()), Err(ChannelError::Malformed)));
    }

    #[test]
    fn an_unknown_control_kind_is_refused() {
        // Кадр управления, которого мы не понимаем, менять дерево
        // не должен: незнакомое не читается как знакомое.
        let Value::Map(mut fields) = Control::Prune { group: [7u8; 16] }.value() else {
            panic!("карта")
        };
        fields[0] = (Value::Integer(KEY_KIND.into()), Value::Integer(99u64.into()));
        assert!(matches!(Control::from_value(&Value::Map(fields)), Err(ChannelError::Malformed)));
    }

    #[test]
    fn the_default_is_quiet_seeding_and_it_hides_the_address() {
        // §7.5.1: тихая раздача — умолчание, и в этом весь смысл трёх
        // состояний. Рой не должен зависеть от того, нажмёт ли кто-нибудь
        // кнопку, а раскрытие адреса обязано оставаться выбором.
        assert!(!Seeding::Quiet.announces_address());
        assert!(!Seeding::Off.announces_address());
        assert!(Seeding::Announced.announces_address());
        assert_eq!(Seeding::from_code(Seeding::Quiet.code()), Some(Seeding::Quiet));
        assert_eq!(Seeding::from_code(9), None, "незнакомое состояние не читается как умолчание");
    }

    #[test]
    fn the_text_says_what_it_costs_and_that_it_does_not_stop_at_once() {
        let text = SeedingConsequences::ui_text();
        assert!(text.contains("адрес"), "раскрытие адреса названо прямо");
        assert!(text.contains("не сразу"), "гаснет по сроку, и об этом сказано до нажатия");
        assert!(text.contains("Тихая раздача"), "названа середина, которая адрес не раскрывает");
        assert!(!SeedingConsequences::STOPS_AT_ONCE);
    }

    #[test]
    fn the_giving_limits_round_trip_and_the_smaller_one_wins() {
        // §9.2, «три числа и выключатель, все на диске». Два из них наши,
        // и на диск они едут восемью байтами: разбор обязан вернуть
        // ровно то, что записали.
        let limits = GivingLimits { per_peer: 7, total: 11 };
        assert_eq!(GivingLimits::from_bytes(&limits.to_bytes()), Some(limits));
        assert_eq!(GivingLimits::from_bytes(&[0u8; 7]), None, "не те байты — не настройка");
        assert_eq!(GivingLimits::from_bytes(&[]), None);

        // Предел на пира защищает от одного жадного, общий — от десяти
        // вежливых, и побеждает **меньший из двух остатков**.
        assert_eq!(limits.left_for_peer(0, 0), 7, "пока свободно — упираемся в предел на пира");
        assert_eq!(limits.left_for_peer(0, 9), 2, "общий кончается раньше — он и решает");
        assert_eq!(limits.left_for_peer(7, 0), 0, "свой предел исчерпан");
        assert_eq!(limits.left_for_peer(99, 99), 0, "переполнения не бывает");

        // Умолчание — не нули: база без строки не должна выключать
        // раздачу никому.
        let default = GivingLimits::default();
        assert_eq!(default.per_peer, BLOCKS_PER_WINDOW);
        assert_eq!(default.total, BLOCKS_PER_WINDOW_TOTAL);
        assert!(default.total > default.per_peer, "общий предел шире, иначе он лишний");
    }

    #[test]
    fn the_rungs_that_cannot_be_lazy_have_no_graft_deadline() {
        // §8.4 таблицей: LAN, ygg и onion — ткань дерева; эфир «только
        // eager»; почта и реле «всегда eager, никогда lazy».
        //
        // **Два места обязаны говорить одно.** Кто бывает ленивым —
        // `may_be_lazy`; кто заводит срок на зов — `graft_wait_ms`.
        // Разойдись они, зов приехал бы туда, где его некому превратить
        // в просьбу, а снаружи это выглядело бы как «слово не дошло».
        use crate::transport_policy::Transport;
        for via in [Transport::Lan, Transport::Ygg, Transport::Onion] {
            assert!(may_be_lazy(via), "{via:?} — ткань дерева");
            assert!(graft_wait_ms(via).is_some(), "{via:?} обязан заводить срок");
        }
        for via in [Transport::Bt, Transport::Nostr, Transport::Mail] {
            assert!(!may_be_lazy(via), "{via:?} ленивым не бывает");
            assert_eq!(graft_wait_ms(via), None, "{via:?} срока не заводит");
        }
        // Эфир возит хвост, но не архив; остальные — возят.
        assert!(!carries_archive(Transport::Bt), "9–12 КБ/с: мебибайт — полторы минуты");
        for via in [Transport::Lan, Transport::Ygg, Transport::Onion, Transport::Mail] {
            assert!(carries_archive(via), "{via:?} архив возит");
        }
    }

    #[test]
    fn the_open_level_is_the_default_and_an_unknown_code_is_not_read_as_one() {
        // §12: «умолчание остаётся открытым». Умолчание выражено
        // **отсутствием** настройки, а не кодом, и потому здесь
        // проверяется другое: что коды ходят туда и обратно и что чужой
        // код не читается как знакомый.
        assert_eq!(Sharing::from_code(Sharing::Everyone.code()), Some(Sharing::Everyone));
        assert_eq!(Sharing::from_code(Sharing::Contacts.code()), Some(Sharing::Contacts));
        assert_eq!(Sharing::from_code(Sharing::Verified.code()), Some(Sharing::Verified));
        assert_eq!(Sharing::from_code(9), None, "чужой код не читается как знакомый");
        assert!(!Sharing::Everyone.narrows_the_swarm(), "открытый уровень цены не имеет");
        assert!(Sharing::Contacts.narrows_the_swarm(), "о сужении надо сказать");
        assert!(Sharing::Verified.narrows_the_swarm());
    }

    #[test]
    fn the_narrowing_text_says_that_others_pay_too() {
        // §12 дословно: «при затягивании UI говорит, что платят не только
        // за себя». Текст обязан сказать и это, и то, что «только
        // сверенным» — почти «не раздавать»: §12 велит называть уровень
        // тем, что он есть.
        let text = SharingLevelConsequences::ui_text();
        assert!(text.contains("не только за себя"), "цена названа прямо");
        assert!(text.contains("подписчика"), "сказано, кто заметит: новый подписчик, а не вы");
        assert!(text.contains("почти «не раздавать»"), "третий уровень назван тем, что он есть");
        assert!(SharingLevelConsequences::OTHERS_PAY_TOO);
        assert!(SharingLevelConsequences::DEFAULT_STAYS_OPEN);
    }
}
