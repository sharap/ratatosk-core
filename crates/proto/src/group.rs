//! Группы на sender keys (§11).
//!
//! Ratchet Tree, MLS и криптографическая эвикция — вне v1 (§15): они требуют
//! общего порядка коммитов, которого в модели без сервера нет.
//!
//! Три следствия этой модели, каждое из которых обязано доходить до UI:
//!
//! * **Отрицаемости внутри группы нет.** Sender key одинаков у всех
//!   получателей, поэтому групповое сообщение подписывается `SK` отправителя —
//!   иначе любой участник подделал бы сообщение от имени любого другого (§11.1).
//! * **Исключение социальное, а не криптографическое** (§11.4): исключённый
//!   сохраняет доступ ко всей прошлой переписке.
//! * **Максимум 32 участника** (§11.3): групповое сообщение уходит отдельной
//!   копией каждому по его 1:1-каналу, потому что отправка через `To:` со
//!   списком раскрыла бы состав группы chatmail-серверу.

use std::collections::BTreeSet;

use ratatosk_codec::{canonical, CodecError, Value};
use ratatosk_crdt::{ActorId, Hlc, OrSet, OrSetOp, Tag};
use ratatosk_crypto::{Identity, PublicIdentity};

const KEY_GROUP: u64 = 1;
const KEY_AUTHOR: u64 = 2;
const KEY_OPS: u64 = 3;
const KEY_ELEM: u64 = 4;
const KEY_TAGS: u64 = 5;
const KEY_WALL_MS: u64 = 6;
const KEY_COUNTER: u64 = 7;
const KEY_LOGICAL: u64 = 14;
const KEY_ACTOR: u64 = 8;
const KEY_UNIQ: u64 = 9;
const KEY_KIND: u64 = 10;
const KEY_BLOCK: u64 = 11;
const KEY_SIGNATURE: u64 = 12;
const KEY_CHAIN: u64 = 13;
const KEY_CARDS: u64 = 15;
const KEY_TITLE: u64 = 16;
const KEY_SEALED: u64 = 17;
const KEY_AVATAR: u64 = 18;
const KEY_AVATAR_WALL: u64 = 19;
const KEY_AVATAR_LOGICAL: u64 = 20;

/// Код операции добавления в блоке состава. Едет по проводу — менять нельзя.
const OP_ADD: u64 = 1;
/// Код операции удаления.
const OP_REMOVE: u64 = 2;

/// Предел размера группы в v1 (§11.3).
///
/// Не «пока что» и не «для производительности»: сообщение в группе на 32
/// человека — это до 32 писем, и больше не потянет ни батарея, ни лимиты
/// chatmail-серверов.
pub const MAX_GROUP_MEMBERS: usize = 32;

/// Раз во сколько сообщений фиксируется снапшот состава (§12).
pub const MEMBERSHIP_SNAPSHOT_EVERY: u64 = 5_000;

/// Идентификатор группы.
pub type GroupId = [u8; 16];

/// Читает необязательную метку HLC из пары ключей.
///
/// Отсутствие метки — не ошибка формата: сборка, не знавшая этого поля,
/// его не шлёт. Нулевая метка означает «старшинство не названо», и первое
/// же названное её обгонит.
///
/// # Errors
///
/// Поле есть, но не целое или логическая компонента не влезает в 32 бита.
fn optional_hlc(
    map: &[(Value, Value)],
    wall_key: u64,
    logical_key: u64,
) -> Result<Hlc, CodecError> {
    let wall_ms = match canonical::get(map, wall_key) {
        Some(value) => canonical::as_u64(value)?,
        None => 0,
    };
    let logical = match canonical::get(map, logical_key) {
        Some(value) => {
            u32::try_from(canonical::as_u64(value)?).map_err(|_| CodecError::TypeMismatch)?
        }
        None => 0,
    };
    Ok(Hlc::new(wall_ms, logical))
}

/// Отказ в групповой операции.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    /// Группа уже содержит [`MAX_GROUP_MEMBERS`] участников.
    #[error("в группе не может быть больше {MAX_GROUP_MEMBERS} участников")]
    TooManyMembers,
    /// Исключать может только создатель (§11.2).
    #[error("исключать участников может только создатель группы")]
    NotOwner,
    /// Участника нет в группе.
    #[error("участник не состоит в группе")]
    NotAMember,
}

/// Состояние группы на одном устройстве.
#[derive(Debug, Clone)]
pub struct Group {
    /// Идентификатор.
    pub id: GroupId,
    /// Создатель. В v1 только он может исключать (§11.2).
    pub owner: ActorId,
    members: OrSet<ActorId>,
    messages_since_snapshot: u64,
}

impl Group {
    /// Создаёт группу с одним участником — создателем.
    #[must_use]
    pub fn create(id: GroupId, owner: ActorId, at: Tag) -> Group {
        let mut members = OrSet::new();
        members.apply(OrSet::prepare_add(owner, at));
        Group { id, owner, members, messages_since_snapshot: 0 }
    }

    /// Поднимает группу, состав которой будет применён операциями.
    ///
    /// **Не [`Group::create`], и разница здесь не косметическая.** `create`
    /// добавляет создателя **новой** меткой — той, что потом уедет в блоке
    /// состава и станет известна остальным. Позови её тот, кто поднимает
    /// группу с диска, и у создателя оказалось бы две метки добавления:
    /// настоящая, поднятая из истории, и выдуманная прямо сейчас. Вторую
    /// не гасит ни одно удаление — их писали, видя только первую, — и
    /// создатель стал бы неисключаемым после первого же перезапуска.
    ///
    /// Поэтому: `create` — когда группа заводится, `restore` — когда её
    /// состав приходит операциями, всё равно откуда: с диска или по сети.
    ///
    /// Счётчик сообщений до снапшота (§12) начинается с нуля: сколько их
    /// было до подъёма, здесь взять неоткуда.
    #[must_use]
    pub fn restore(id: GroupId, owner: ActorId) -> Group {
        Group { id, owner, members: OrSet::new(), messages_since_snapshot: 0 }
    }

    /// Текущий состав.
    pub fn members(&self) -> impl Iterator<Item = &ActorId> {
        self.members.elements()
    }

    /// Сколько участников.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Пуста ли группа.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Состоит ли участник в группе.
    #[must_use]
    pub fn contains(&self, who: &ActorId) -> bool {
        self.members.contains(who)
    }

    /// Готовит приглашение. Приглашать может любой участник (§11.2).
    pub fn invite(&self, who: ActorId, tag: Tag) -> Result<OrSetOp<ActorId>, GroupError> {
        if self.len() >= MAX_GROUP_MEMBERS && !self.contains(&who) {
            return Err(GroupError::TooManyMembers);
        }
        Ok(OrSet::prepare_add(who, tag))
    }

    /// Готовит исключение. Исключать может только создатель (§11.2).
    pub fn evict(&self, by: ActorId, who: ActorId) -> Result<OrSetOp<ActorId>, GroupError> {
        if by != self.owner {
            return Err(GroupError::NotOwner);
        }
        if !self.contains(&who) {
            return Err(GroupError::NotAMember);
        }
        Ok(self.members.prepare_remove(who))
    }

    /// Готовит выход — удаление себя из состава.
    ///
    /// **Дополнение к спецификации:** §11.2 знает только «создатель
    /// исключает» и выхода не описывает. Дополнение того же рода, что отзыв
    /// и реакции, и §17 просит называть такие вещи отдельно.
    ///
    /// # Почему это не частный случай исключения
    ///
    /// [`Group::evict`] требует, чтобы удаляющий был создателем, — и это
    /// правило про **власть над чужим членством**. Выход про своё, и власти
    /// не требует вовсе: человек, который не может уйти из разговора, — это
    /// не свойство протокола, а его недоработка.
    ///
    /// Отсюда и правило приёма, которое обязано стоять у получателя:
    /// удаление принимается, если его подписал создатель **либо** если
    /// удаляемый и есть автор блока. Второе условие не даёт выходу стать
    /// лазейкой: подписать «ушёл такой-то» за другого нельзя.
    ///
    /// # Создателю выход тоже разрешён
    ///
    /// Ценой, которую надо сказать вслух: передачи прав в v1 нет, и после
    /// ухода создателя исключать не сможет никто. Запретить ему выходить
    /// было бы хуже — это оставило бы человека в разговоре навсегда.
    /// Группа при этом остаётся живой: приглашать вправе любой участник,
    /// и вернуть создателя тоже.
    ///
    /// # Errors
    ///
    /// [`GroupError::NotAMember`] — выходить не из чего.
    pub fn leave(&self, me: ActorId) -> Result<OrSetOp<ActorId>, GroupError> {
        if !self.contains(&me) {
            return Err(GroupError::NotAMember);
        }
        Ok(self.members.prepare_remove(me))
    }

    /// Применяет операцию состава — свою или пришедшую в подписанном блоке.
    ///
    /// Подпись проверяется **до** вызова, в `ratatosk-core`: этот модуль
    /// оперирует уже доверенными операциями.
    pub fn apply(&mut self, op: OrSetOp<ActorId>) {
        self.members.apply(op);
    }

    /// Сливает состояние с другим устройством после разделения сети.
    pub fn merge(&mut self, other: &Group) {
        self.members.merge(&other.members);
    }

    /// Отмечает отправленное или принятое сообщение и говорит, пора ли снапшот.
    ///
    /// Триггер обязан быть одинаковым у всех участников (§12), иначе узлы
    /// свернут разные истории и разойдутся.
    pub fn note_message(&mut self) -> bool {
        self.messages_since_snapshot += 1;
        self.messages_since_snapshot >= MEMBERSHIP_SNAPSHOT_EVERY
    }

    /// Фиксирует снапшот состава, сворачивая историю OR-Set (§12).
    pub fn snapshot(&mut self, baseline: Hlc) {
        self.members.compact(baseline, self.owner);
        self.messages_since_snapshot = 0;
    }

    /// Кому рассылать групповое сообщение (§11.3).
    ///
    /// Отдельная копия каждому по его 1:1-каналу. Отправитель исключается
    /// из списка: себе копию слать незачем.
    pub fn recipients(&self, me: &ActorId) -> Vec<ActorId> {
        self.members.elements().filter(|m| *m != me).copied().collect()
    }
}

/// Наибольшее число операций в одном блоке состава.
///
/// Блок описывает изменение состава, а состав ограничен
/// [`MAX_GROUP_MEMBERS`]. Вдвое — с запасом на «добавили и убрали»
/// в одном блоке; больше — это не блок состава, а запрос памяти.
pub const MAX_MEMBERSHIP_OPS: usize = MAX_GROUP_MEMBERS * 2;

/// Наибольшее число наблюдённых меток у одного удаления.
///
/// Удаление гасит те метки добавления, которые автор видел, а добавлений
/// одного участника не бывает больше, чем раз его приглашали. Число
/// щедрое: повторные приглашения законны, но их не тысячи.
pub const MAX_OBSERVED_TAGS: usize = 256;

/// Ключ отправителя в том виде, в каком его отдают участнику (§11.1, §11.5).
///
/// **Номер едет вместе с ключом, и врозь они бессмысленны.** Отдающий
/// к этому моменту отправил `counter` сообщений; получатель, начавший
/// с нуля, сошёлся бы в ключах и разошёлся в номерах — а номер решает,
/// какое место в цепочке занимает пришедшее сообщение.
///
/// Подписи здесь нет, и это осознанно: блок едет **только** по установленной
/// 1:1-сессии, которая уже говорит, от кого он. Пересылать чужой ключ
/// отправителя незачем — при вступлении их отдаёт пригласивший, и отдаёт
/// как свои сведения, за которые ручается сессия с ним.
///
/// # Почему у блока есть метка поворота
///
/// Каждое вступление проворачивает цепочку каждого участника (§11.5), а §9.2
/// разрешает переставлять кадры. Два приглашения подряд — и до участника
/// едут **два** объявления одной и той же цепочки, с одинаковым `counter`
/// (после поворота он всегда нулевой). Без признака старшинства получатель
/// не отличает свежее от опоздавшего и примерно в половине случаев оставляет
/// себе мёртвую цепочку: номер верный, а ключ не тот. Дальше сообщения
/// отправителя не открываются — молча, потому что снаружи это неотличимо
/// от порчи.
///
/// Метку ставит **владелец** цепочки в момент поворота, и при пересылке
/// чужого ключа (§11.5) она едет как есть. Поэтому сравнивать её всегда
/// можно: две метки одной цепочки выданы одними часами, чьей бы рукой
/// ни были переданы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderKeyBlock {
    /// Какой группы.
    pub group: GroupId,
    /// Чей это ключ. Не выводится из сессии: пригласивший отдаёт и чужие.
    pub member: ActorId,
    /// Состояние цепочки.
    pub chain: [u8; 32],
    /// Номер, которому это состояние соответствует.
    pub counter: u64,
    /// Когда владелец эту цепочку завёл — метка его часов.
    ///
    /// Только для старшинства: получатель берёт цепочку, лишь если метка
    /// строго новее уже лежащей. Нулевая метка означает «старшинства не
    /// назвали» — так шлёт сборка, не знавшая этого поля.
    pub chain_hlc: Hlc,
}

/// Кодирует ключ отправителя.
#[must_use]
pub fn sender_key_value(block: &SenderKeyBlock) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(block.group.to_vec())),
        (Value::Integer(KEY_ACTOR.into()), Value::Bytes(block.member.to_vec())),
        (Value::Integer(KEY_CHAIN.into()), Value::Bytes(block.chain.to_vec())),
        (Value::Integer(KEY_COUNTER.into()), Value::Integer(block.counter.into())),
        (Value::Integer(KEY_WALL_MS.into()), Value::Integer(block.chain_hlc.wall_ms.into())),
        (Value::Integer(KEY_LOGICAL.into()), Value::Integer(block.chain_hlc.logical.into())),
    ])
}

/// Разбирает ключ отправителя.
///
/// # Errors
///
/// Значение не той формы.
pub fn sender_key_from_value(value: &Value) -> Result<SenderKeyBlock, CodecError> {
    let map = canonical::as_map(value)?;
    Ok(SenderKeyBlock {
        group: canonical::as_array::<16>(canonical::require(map, KEY_GROUP)?)?,
        member: canonical::as_array::<32>(canonical::require(map, KEY_ACTOR)?)?,
        chain: canonical::as_array::<32>(canonical::require(map, KEY_CHAIN)?)?,
        counter: canonical::as_u64(canonical::require(map, KEY_COUNTER)?)?,
        // Необязательное на чтении — по той же причине, что и метка
        // названия: сборка, не знавшая старшинства, её не шлёт.
        chain_hlc: optional_hlc(map, KEY_WALL_MS, KEY_LOGICAL)?,
    })
}

/// Изменение состава, подписанное его автором (§11.2).
///
/// **Один блок — один автор.** Так подпись остаётся проверяемой после
/// пересылки: при вступлении (§11.5) новый участник получает состав
/// от пригласившего, а операции в нём написаны разными людьми. Разложи мы
/// их в общий мешок с одной подписью — новичок узнал бы только то, что
/// пригласивший не соврал **себе**, а про исключение, сделанное создателем,
/// ему пришлось бы верить на слово.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipBlock {
    /// Какой группы.
    pub group: GroupId,
    /// Кто автор. Подпись проверяется его `SK`.
    pub author: ActorId,
    /// Что он сделал с составом.
    pub ops: Vec<OrSetOp<ActorId>>,
}

/// Разобранный, но **непроверенный** блок состава.
///
/// Существует затем, чтобы проверку подписи нельзя было пропустить молча:
/// [`MembershipBlock`] из него достаётся только через [`Unchecked::verify`],
/// и та забирает значение целиком. Забыть проверку можно лишь написав
/// «не проверять» словами.
#[derive(Debug, Clone)]
pub struct Unchecked {
    block: MembershipBlock,
    signature: [u8; 64],
    /// Те самые байты, над которыми стоит подпись.
    signed: Vec<u8>,
}

impl Unchecked {
    /// Кто, по словам блока, его написал.
    ///
    /// Нужно, чтобы найти его `SK` **до** проверки: ключ ищется по имени
    /// автора, а имя лежит внутри. Верить этому полю до `verify` нельзя
    /// ни в чём другом.
    #[must_use]
    pub fn claims_author(&self) -> &ActorId {
        &self.block.author
    }

    /// Какой группы блок — тоже до проверки, чтобы найти группу.
    #[must_use]
    pub fn claims_group(&self) -> &GroupId {
        &self.block.group
    }

    /// Проверяет подпись **известным** ключом и отдаёт блок.
    ///
    /// `known` — личность автора, какой её знает получатель, а не какой
    /// её объявляет блок. Проверка ключом из самого сообщения подтверждала
    /// бы только то, что отправитель владеет каким-то ключом (та же ошибка,
    /// от которой бережётся `card_update`).
    ///
    /// # Errors
    ///
    /// [`MembershipError::NotFromAuthor`] — известный ключ не тот, что назван
    /// в блоке; [`MembershipError::BadSignature`] — подпись не сошлась.
    pub fn verify(self, known: &PublicIdentity) -> Result<MembershipBlock, MembershipError> {
        if known.ik != self.block.author {
            return Err(MembershipError::NotFromAuthor);
        }
        known.verify(&self.signed, &self.signature).map_err(|_| MembershipError::BadSignature)?;
        Ok(self.block)
    }
}

/// Почему подписанный кусок не принят.
///
/// Один тип на блок состава (§11.2) и на групповое сообщение (§11.1):
/// исходов у проверки подписи ровно три, и они одни и те же. Имя осталось
/// от первого из двух — это долг, а не замысел; тексты при этом говорят
/// про подпись вообще, чтобы в журнале не значилось «блок состава» там,
/// где разбиралось сообщение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    /// Значение не той формы или превышает пределы.
    #[error("подписанный кусок не разобрался")]
    Malformed,
    /// Известный ключ не совпал с тем, кто назван внутри.
    #[error("подписано не тем, кто назван внутри")]
    NotFromAuthor,
    /// Подпись не сошлась.
    #[error("подпись не сошлась")]
    BadSignature,
}

/// Собирает подписанную нагрузку изменения состава.
///
/// Кодирование и подпись — в одном месте, как и у `card_update`: подпись
/// обязана стоять над **теми самыми** байтами, которые поедут. Разнеси
/// эти два шага — и однажды кто-нибудь подпишет одну кодировку, а отправит
/// другую.
///
/// # Errors
///
/// Отказ кодирования.
pub fn signed_membership(
    identity: &Identity,
    block: &MembershipBlock,
) -> Result<Value, CodecError> {
    let bytes = canonical::encode(&membership_value(block))?;
    let signature = identity.sign(&bytes);
    Ok(Value::Map(vec![
        (Value::Integer(KEY_BLOCK.into()), Value::Bytes(bytes)),
        (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
    ]))
}

/// Разбирает нагрузку изменения состава, **не** проверяя подпись.
///
/// # Errors
///
/// [`MembershipError::Malformed`] — форма или пределы.
pub fn parse_membership(value: &Value) -> Result<Unchecked, MembershipError> {
    let map = canonical::as_map(value).map_err(|_| MembershipError::Malformed)?;
    let Ok(Value::Bytes(signed)) = canonical::require(map, KEY_BLOCK) else {
        return Err(MembershipError::Malformed);
    };
    let Ok(Value::Bytes(signature)) = canonical::require(map, KEY_SIGNATURE) else {
        return Err(MembershipError::Malformed);
    };
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| MembershipError::Malformed)?;
    let inner = canonical::decode(signed).map_err(|_| MembershipError::Malformed)?;
    let block = membership_from_value(&inner).map_err(|_| MembershipError::Malformed)?;
    Ok(Unchecked { block, signature, signed: signed.clone() })
}

fn membership_value(block: &MembershipBlock) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(block.group.to_vec())),
        (Value::Integer(KEY_AUTHOR.into()), Value::Bytes(block.author.to_vec())),
        (
            Value::Integer(KEY_OPS.into()),
            Value::Array(block.ops.iter().take(MAX_MEMBERSHIP_OPS).map(op_value).collect()),
        ),
    ])
}

fn membership_from_value(value: &Value) -> Result<MembershipBlock, CodecError> {
    let map = canonical::as_map(value)?;
    let Value::Array(ops) = canonical::require(map, KEY_OPS)? else {
        return Err(CodecError::TypeMismatch);
    };
    // Предел на приёме, а не только на отправке: длину называет та сторона
    // провода, и «сто тысяч операций» — это запрос памяти, а не состав.
    if ops.len() > MAX_MEMBERSHIP_OPS {
        return Err(CodecError::TypeMismatch);
    }
    Ok(MembershipBlock {
        group: canonical::as_array::<16>(canonical::require(map, KEY_GROUP)?)?,
        author: canonical::as_array::<32>(canonical::require(map, KEY_AUTHOR)?)?,
        ops: ops.iter().map(op_from_value).collect::<Result<Vec<_>, _>>()?,
    })
}

fn tag_value(tag: &Tag) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_WALL_MS.into()), Value::Integer(tag.hlc.wall_ms.into())),
        (Value::Integer(KEY_LOGICAL.into()), Value::Integer(tag.hlc.logical.into())),
        (Value::Integer(KEY_ACTOR.into()), Value::Bytes(tag.actor.to_vec())),
        (Value::Integer(KEY_UNIQ.into()), Value::Bytes(tag.uniq.to_vec())),
    ])
}

fn tag_from_value(value: &Value) -> Result<Tag, CodecError> {
    let map = canonical::as_map(value)?;
    Ok(Tag {
        hlc: Hlc::new(
            canonical::as_u64(canonical::require(map, KEY_WALL_MS)?)?,
            // Логическая часть — `u32`: пришедшее больше не «большая метка»,
            // а чужая форма, и разбор её отвергает, а не режет.
            u32::try_from(canonical::as_u64(canonical::require(map, KEY_LOGICAL)?)?)
                .map_err(|_| CodecError::TypeMismatch)?,
        ),
        actor: canonical::as_array::<32>(canonical::require(map, KEY_ACTOR)?)?,
        uniq: canonical::as_array::<8>(canonical::require(map, KEY_UNIQ)?)?,
    })
}

fn op_value(op: &OrSetOp<ActorId>) -> Value {
    match op {
        OrSetOp::Add { elem, tag } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(OP_ADD.into())),
            (Value::Integer(KEY_ELEM.into()), Value::Bytes(elem.to_vec())),
            (Value::Integer(KEY_TAGS.into()), Value::Array(vec![tag_value(tag)])),
        ]),
        OrSetOp::Remove { elem, observed } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(OP_REMOVE.into())),
            (Value::Integer(KEY_ELEM.into()), Value::Bytes(elem.to_vec())),
            (
                Value::Integer(KEY_TAGS.into()),
                Value::Array(observed.iter().take(MAX_OBSERVED_TAGS).map(tag_value).collect()),
            ),
        ]),
    }
}

fn op_from_value(value: &Value) -> Result<OrSetOp<ActorId>, CodecError> {
    let map = canonical::as_map(value)?;
    let elem = canonical::as_array::<32>(canonical::require(map, KEY_ELEM)?)?;
    let Value::Array(tags) = canonical::require(map, KEY_TAGS)? else {
        return Err(CodecError::TypeMismatch);
    };
    if tags.len() > MAX_OBSERVED_TAGS {
        return Err(CodecError::TypeMismatch);
    }
    match canonical::as_u64(canonical::require(map, KEY_KIND)?)? {
        OP_ADD => {
            // Ровно одна метка: добавление помечается одной, и массив
            // из двух — это не «добавление с запасом», а чужая форма.
            let [tag] = tags.as_slice() else { return Err(CodecError::TypeMismatch) };
            Ok(OrSetOp::Add { elem, tag: tag_from_value(tag)? })
        }
        OP_REMOVE => {
            let mut observed = BTreeSet::new();
            for tag in tags {
                observed.insert(tag_from_value(tag)?);
            }
            Ok(OrSetOp::Remove { elem, observed })
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

/// Наибольшее число карточек в одном списке участников.
///
/// Столько же, сколько участников: список описывает состав, а состав
/// ограничен [`MAX_GROUP_MEMBERS`]. Больше — не список, а запрос памяти.
pub const MAX_ROSTER_CARDS: usize = MAX_GROUP_MEMBERS;

/// Наибольший размер одной карточки в списке, в байтах.
///
/// Настоящая карточка — два ключа по 32 байта, onion в 62 знака, почтовый
/// адрес и имя: две-три сотни байт. Килобайт — запас вчетверо, за которым
/// начинается не имя, а набивка.
///
/// Предел нужен здесь, а не только в `codec`: карточек в списке до тридцати
/// двух, и без потолка на каждую весь список становится тем самым запросом
/// памяти, от которого бережётся [`MAX_ROSTER_CARDS`]. Что весь список
/// при этих числах помещается в один кадр, проверяется тестом — замером,
/// а не рассуждением.
pub const MAX_ROSTER_CARD_BYTES: usize = 1024;

/// Карточки участников, как их отдают при вступлении (§11.5).
///
/// **Спецификация требует их прямо**: «новый участник получает
/// от пригласившего состав группы, контакт-карточки всех участников,
/// текущие sender keys всех участников». Без карточек первые два бесполезны:
/// по составу не с кем говорить — адресов нет, — а подписи блоков нечем
/// проверять, `SK` лежит в карточке.
///
/// Едет он и в обратную сторону: при вступлении карточка новичка нужна
/// всем прежним участникам, и это тот же список из одной строки.
///
/// # Чего этот список не даёт
///
/// **Карточка не подписана** (§4.1): её подлинность держится на канале,
/// по которому она приехала. Значит новичок верит пригласившему —
/// и §11.5 говорит ровно это, называя источник. Подписи на блоках состава
/// (5во) защищают его от **других** участников, а не от пригласившего:
/// подсунь тот вместо чужого `SK` свой, он подделал бы блоки от того
/// человека. Отсюда правило, которое обязано дойти до UI: участники,
/// узнанные из списка, — **несверенные контакты** (§4.2), и сверять их
/// человеку придётся голосом, как всех прочих.
///
/// Спецификация называет и второе следствие: «присоединение раскрывает
/// всем участникам onion- и chatmail-адреса друг друга. Так и сказать
/// при создании группы» — это [`JOIN_DISCLOSURE`].
///
/// # Байты, а не разобранные карточки
///
/// Здесь они непрозрачны нарочно. Что такое правильная карточка — вопрос
/// `codec`, а не групп; разбирает их ядро, тем же кодом, что и все прочие
/// карточки. Этот слой проверяет ровно две вещи, обе на приёме: сколько
/// карточек и какой длины каждая.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    /// Какой группы.
    pub group: GroupId,
    /// Канонические байты карточек — в том виде, в каком они приехали (§6).
    pub cards: Vec<Vec<u8>>,
}

/// Что сказать человеку при создании группы (§11.5).
///
/// Точная формулировка живёт рядом с кодом по той же причине, что
/// и [`EvictionConsequences::ui_text`]: §14 существует затем, чтобы
/// обещания продукта не расходились со свойствами протокола, а требование
/// «так и сказать при создании группы» стоит в спецификации дословно.
pub const JOIN_DISCLOSURE: &str =
    "Все участники группы увидят адреса друг друга. Обратно это не отменить: \
     вышедший из группы адреса уже знает.";

/// Кодирует список карточек.
#[must_use]
pub fn roster_value(roster: &Roster) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(roster.group.to_vec())),
        (
            Value::Integer(KEY_CARDS.into()),
            Value::Array(
                roster
                    .cards
                    .iter()
                    .take(MAX_ROSTER_CARDS)
                    .filter(|card| card.len() <= MAX_ROSTER_CARD_BYTES)
                    .map(|card| Value::Bytes(card.clone()))
                    .collect(),
            ),
        ),
    ])
}

/// Разбирает список карточек.
///
/// Оба предела проверяются **здесь**, на приёме: длину называет та сторона
/// провода, и «тысяча карточек по мегабайту» — это запрос памяти, а не
/// состав. То же правило, что у блока состава.
///
/// # Errors
///
/// Значение не той формы или превышает пределы.
pub fn roster_from_value(value: &Value) -> Result<Roster, CodecError> {
    let map = canonical::as_map(value)?;
    let Value::Array(cards) = canonical::require(map, KEY_CARDS)? else {
        return Err(CodecError::TypeMismatch);
    };
    if cards.len() > MAX_ROSTER_CARDS {
        return Err(CodecError::TypeMismatch);
    }
    let mut out = Vec::with_capacity(cards.len());
    for card in cards {
        let Value::Bytes(bytes) = card else { return Err(CodecError::TypeMismatch) };
        if bytes.len() > MAX_ROSTER_CARD_BYTES {
            return Err(CodecError::TypeMismatch);
        }
        out.push(bytes.clone());
    }
    Ok(Roster {
        group: canonical::as_array::<16>(canonical::require(map, KEY_GROUP)?)?,
        cards: out,
    })
}

/// Наибольшая длина названия группы по проводу, в байтах.
///
/// **Байты, а не символы**, и это не расхождение с продуктовым пределом
/// в 64 символа (`ratatosk_core::MAX_GROUP_TITLE_CHARS`), а его следствие:
/// символ UTF-8 занимает не больше четырёх байт, значит законное название
/// не длиннее 256. Считать здесь символы значило бы разбирать строку,
/// чтобы решить, стоит ли её разбирать.
///
/// Предел нужен на приёме: длину называет та сторона провода, и «название
/// в мегабайт» — это запрос памяти, а не название.
pub const MAX_GROUP_TITLE_BYTES: usize = 256;

/// Кто и как назвал группу — то, чего новичку неоткуда узнать (§11.5).
///
/// # Зачем отдельно от состава
///
/// Состав говорит, **кто** в группе. Он не говорит ни кто её создал, ни как
/// она называется, — а без первого не работает §11.2 (исключать может только
/// создатель), без второго чат не показать в списке.
///
/// Вывести создателя из истории блоков нельзя честно. Похоже, что это автор
/// самого раннего блока, добавившего сам себя, — но «похоже» здесь означает
/// «подделывается блоком, который кто угодно вправе подписать». Право
/// исключать не должно держаться на догадке о порядке.
///
/// # Кто за это ручается
///
/// Пригласивший, и никто больше: подписи здесь нет. Это то же поручительство,
/// на котором держатся карточки в [`Roster`], и §11.5 называет источник прямо.
/// Соврав про создателя, пригласивший подарил бы право исключать не тому —
/// но он же выбирает, во что приглашать, и человек, которому он соврал,
/// с тем же успехом мог быть приглашён в выдуманную группу.
///
/// Название и картинка приезжают здесь же, и ручается за них тот же
/// пригласивший. Оба общие: менять их вправе только создатель, а сюда они
/// попадают такими, какими лежат у пригласившего, — вместе со своими
/// метками, чтобы новичок не разошёлся с остальными на следующей смене.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intro {
    /// Какой группы.
    pub group: GroupId,
    /// Создатель. В v1 только он может исключать (§11.2).
    pub owner: ActorId,
    /// Как её назвал пригласивший.
    pub title: String,
    /// Метка названия — та, при которой его поставили (§9.1).
    ///
    /// **Едет вместе с названием, а не выдумывается новичком.** Иначе
    /// вышло бы так: новичок пометил бы услышанное название моментом
    /// своего вступления, а переименование, случившееся **раньше**
    /// вступления, но доехавшее позже, он отверг бы как устаревшее —
    /// и остался бы с названием, которого больше нет ни у кого.
    ///
    /// Нулевая метка законна и означает «названию метки не выдавали»:
    /// так у групп, заведённых сборкой без переименования. Её обгонит
    /// любое настоящее переименование, и это верный исход.
    pub title_hlc: Hlc,
    /// Аватарка группы; пустая — картинки нет или её сняли.
    ///
    /// **Едет здесь, а не отдельным действием, и это единственная дорога
    /// картинки к новичку.** Переслать ему чужое действие нельзя:
    /// пересылающий выдал бы старой картинке метку своего конверта,
    /// и настоящая новая была бы отвергнута как опоздавшая. Здесь метка
    /// едет отдельным полем и переживает пересылку в точности — ровно как
    /// у названия.
    ///
    /// Тридцать два килобайта (`avatar::MAX_AVATAR_BYTES`) укладываются
    /// в кадр класса M вместе со всем остальным: список карточек едет
    /// **своим** кадром, а не этим.
    pub avatar: Vec<u8>,
    /// Метка аватарки (§9.1). Нулевая означает «картинки не ставили».
    pub avatar_hlc: Hlc,
}

/// Влезает ли название в предел провода ([`MAX_GROUP_TITLE_BYTES`]).
///
/// **Про пустоту здесь не сказано ничего, и это намеренно.** Пустое
/// название отвергает ядро — при заведении, где человек нажал кнопку
/// и обязан узнать почему (§14). На приёме отвергать нечего: пустая
/// строка от чужой сборки это мусор, а не нападение, и чат с ней всё
/// равно надо как-то показать.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`] — длиннее предела.
pub fn check_title_fits(title: &str) -> Result<(), CodecError> {
    if title.len() > MAX_GROUP_TITLE_BYTES {
        return Err(CodecError::TypeMismatch);
    }
    Ok(())
}

/// Годится ли строка в **новое** название при переименовании.
///
/// Отличается от [`check_title_fits`] ровно пустотой, и различие
/// не косметическое. Представление группы приезжает один раз, при
/// вступлении, и пустое имя там — досадный мусор, с которым чат всё
/// равно надо показать. Переименование — **действие человека**: пустым
/// названием оно стёрло бы у всех то, что было, и притворилось бы
/// обычной сменой имени.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`] — пусто после обрезки краёв или длиннее
/// предела.
pub fn check_new_title(title: &str) -> Result<(), CodecError> {
    if title.trim().is_empty() {
        return Err(CodecError::TypeMismatch);
    }
    check_title_fits(title)
}

/// Кодирует представление группы.
#[must_use]
pub fn intro_value(intro: &Intro) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(intro.group.to_vec())),
        (Value::Integer(KEY_ACTOR.into()), Value::Bytes(intro.owner.to_vec())),
        (Value::Integer(KEY_TITLE.into()), Value::Text(intro.title.clone())),
        (Value::Integer(KEY_WALL_MS.into()), Value::Integer(intro.title_hlc.wall_ms.into())),
        (Value::Integer(KEY_LOGICAL.into()), Value::Integer(intro.title_hlc.logical.into())),
        (Value::Integer(KEY_AVATAR.into()), Value::Bytes(intro.avatar.clone())),
        (Value::Integer(KEY_AVATAR_WALL.into()), Value::Integer(intro.avatar_hlc.wall_ms.into())),
        (
            Value::Integer(KEY_AVATAR_LOGICAL.into()),
            Value::Integer(intro.avatar_hlc.logical.into()),
        ),
    ])
}

/// Разбирает представление группы.
///
/// # Errors
///
/// Значение не той формы или название длиннее [`MAX_GROUP_TITLE_BYTES`].
pub fn intro_from_value(value: &Value) -> Result<Intro, CodecError> {
    let map = canonical::as_map(value)?;
    let title = canonical::as_text(canonical::require(map, KEY_TITLE)?)?;
    check_title_fits(title)?;
    Ok(Intro {
        group: canonical::as_array::<16>(canonical::require(map, KEY_GROUP)?)?,
        owner: canonical::as_array::<32>(canonical::require(map, KEY_ACTOR)?)?,
        title: title.to_owned(),
        // Необязательное на чтении: сборка, не знавшая переименования,
        // метки не шлёт. Ноль означает «метки не выдавали», и первое же
        // переименование его обгонит.
        title_hlc: optional_hlc(map, KEY_WALL_MS, KEY_LOGICAL)?,
        // Тоже необязательное: сборка, не знавшая аватарок, картинки
        // не шлёт. Проверяется тем же правилом, что и присланная
        // действием, — предел и сигнатура; негодную не берём вовсе,
        // потому что вступление из-за картинки срываться не должно.
        avatar: match canonical::get(map, KEY_AVATAR) {
            Some(Value::Bytes(bytes)) if crate::avatar::check(bytes).is_ok() => bytes.clone(),
            Some(Value::Bytes(_)) => Vec::new(),
            Some(_) => return Err(CodecError::TypeMismatch),
            None => Vec::new(),
        },
        avatar_hlc: optional_hlc(map, KEY_AVATAR_WALL, KEY_AVATAR_LOGICAL)?,
    })
}

/// Групповое сообщение — шифротекст с подписью отправителя (§11.1).
///
/// # Почему подпись обязательна
///
/// Sender key одинаков у **всех** получателей. Без подписи любой участник
/// подделал бы сообщение от имени любого другого, просто взяв цепочку,
/// которую ему честно отдали (§11.5). Спецификация говорит это прямо
/// и называет следствие: отрицаемости внутри группы нет, и §14 требует
/// сказать об этом человеку.
///
/// Подпись же делает безвредной и вторую вольность модели — то, что чужой
/// ключ отправителя вправе назвать любой участник: подменивший его добьётся
/// только того, что сообщение не откроется.
///
/// # Что подписано
///
/// Каноническая запись группы, отправителя, номера и шифротекста — то есть
/// **те самые байты**, которые поедут. Кодирование и подпись стоят в одном
/// месте по той же причине, что у блока состава: разнеси их, и однажды
/// кто-нибудь подпишет одну кодировку, а отправит другую (§6).
///
/// Номер входит в подписанное нарочно: переставь его сосед по сети, и
/// сообщение попыталось бы открыться чужим ключом цепочки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessage {
    /// Какой группы.
    pub group: GroupId,
    /// Кто отправил. Из сессии не выводится: копию вправе переслать любой.
    pub sender: ActorId,
    /// Место в цепочке отправителя.
    pub counter: u64,
    /// Шифротекст вместе с тегом AEAD.
    pub sealed: Vec<u8>,
}

/// Разобранное, но **непроверенное** групповое сообщение.
///
/// Существует затем же, зачем [`Unchecked`] у блока состава: проверку
/// подписи нельзя пропустить молча. [`GroupMessage`] достаётся только через
/// [`UncheckedMessage::verify`], и та забирает значение целиком.
#[derive(Debug, Clone)]
pub struct UncheckedMessage {
    message: GroupMessage,
    signature: [u8; 64],
    signed: Vec<u8>,
}

impl UncheckedMessage {
    /// Какой группы, по словам сообщения, — чтобы найти её до проверки.
    #[must_use]
    pub fn claims_group(&self) -> &GroupId {
        &self.message.group
    }

    /// Кто, по словам сообщения, его отправил.
    ///
    /// Нужно, чтобы найти его `SK` и цепочку **до** проверки. Верить этому
    /// полю до `verify` нельзя ни в чём другом.
    #[must_use]
    pub fn claims_sender(&self) -> &ActorId {
        &self.message.sender
    }

    /// Место в цепочке, на которое сообщение претендует.
    ///
    /// Отдаётся до проверки нарочно: ключ считается по номеру, а стоимость
    /// мусорного кадра §7.3 требует ограничить **до** всякой криптографии.
    /// Само число при этом подписано — подменивший его получит отказ подписи.
    #[must_use]
    pub const fn claims_counter(&self) -> u64 {
        self.message.counter
    }

    /// Проверяет подпись **известным** ключом и отдаёт сообщение.
    ///
    /// # Errors
    ///
    /// [`MembershipError::NotFromAuthor`] — известный ключ не тот, что назван
    /// в сообщении; [`MembershipError::BadSignature`] — подпись не сошлась.
    pub fn verify(self, known: &PublicIdentity) -> Result<GroupMessage, MembershipError> {
        if known.ik != self.message.sender {
            return Err(MembershipError::NotFromAuthor);
        }
        known.verify(&self.signed, &self.signature).map_err(|_| MembershipError::BadSignature)?;
        Ok(self.message)
    }
}

/// Собирает подписанную нагрузку группового сообщения.
///
/// # Errors
///
/// Отказ кодирования.
pub fn signed_message(identity: &Identity, message: &GroupMessage) -> Result<Value, CodecError> {
    let bytes = canonical::encode(&message_value(message))?;
    let signature = identity.sign(&bytes);
    Ok(Value::Map(vec![
        (Value::Integer(KEY_BLOCK.into()), Value::Bytes(bytes)),
        (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(signature.to_vec())),
    ]))
}

/// Разбирает групповое сообщение, **не** проверяя подпись.
///
/// # Errors
///
/// [`MembershipError::Malformed`] — форма или пределы.
pub fn parse_message(value: &Value) -> Result<UncheckedMessage, MembershipError> {
    let map = canonical::as_map(value).map_err(|_| MembershipError::Malformed)?;
    let Ok(Value::Bytes(signed)) = canonical::require(map, KEY_BLOCK) else {
        return Err(MembershipError::Malformed);
    };
    let Ok(Value::Bytes(signature)) = canonical::require(map, KEY_SIGNATURE) else {
        return Err(MembershipError::Malformed);
    };
    let signature: [u8; 64] =
        signature.as_slice().try_into().map_err(|_| MembershipError::Malformed)?;
    let inner = canonical::decode(signed).map_err(|_| MembershipError::Malformed)?;
    let message = message_from_value(&inner).map_err(|_| MembershipError::Malformed)?;
    Ok(UncheckedMessage { message, signature, signed: signed.clone() })
}

fn message_value(message: &GroupMessage) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_GROUP.into()), Value::Bytes(message.group.to_vec())),
        (Value::Integer(KEY_ACTOR.into()), Value::Bytes(message.sender.to_vec())),
        (Value::Integer(KEY_COUNTER.into()), Value::Integer(message.counter.into())),
        (Value::Integer(KEY_SEALED.into()), Value::Bytes(message.sealed.clone())),
    ])
}

fn message_from_value(value: &Value) -> Result<GroupMessage, CodecError> {
    let map = canonical::as_map(value)?;
    let Value::Bytes(sealed) = canonical::require(map, KEY_SEALED)? else {
        return Err(CodecError::TypeMismatch);
    };
    Ok(GroupMessage {
        group: canonical::as_array::<16>(canonical::require(map, KEY_GROUP)?)?,
        sender: canonical::as_array::<32>(canonical::require(map, KEY_ACTOR)?)?,
        counter: canonical::as_u64(canonical::require(map, KEY_COUNTER)?)?,
        sealed: sealed.clone(),
    })
}

/// Что происходит с исключённым участником (§11.4).
///
/// Тип существует, чтобы формулировка для UI жила рядом с кодом, а не только
/// в спецификации: §14 требует, чтобы обещания продукта не расходились со
/// свойствами протокола.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictionConsequences;

impl EvictionConsequences {
    /// Получает ли исключённый новые сообщения от честных клиентов.
    pub const RECEIVES_NEW_MESSAGES: bool = false;
    /// Сохраняет ли доступ к прошлой переписке.
    pub const KEEPS_PAST_MESSAGES: bool = true;
    /// Может ли модифицированный клиент продолжать читать через пересылку.
    pub const MODIFIED_CLIENT_CAN_RELAY: bool = true;

    /// Точная формулировка для UI (§11.4).
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Участник удалён. Он больше не получит новых сообщений, но сохранит \
         доступ к прошлым. Для полной изоляции создайте новую группу."
    }
}

/// Вправе ли автор блока делать то, что в нём написано (§11.2).
///
/// Правило одно, и оно про удаление: **исключать может только создатель,
/// а выйти — каждый сам за себя.** Добавление разрешено всем участникам
/// и здесь не рассматривается вовсе.
///
/// # Почему это отдельная функция, а не три строки в ядре
///
/// Потому что это единственное место, где решается, кто над чьим членством
/// властен, — и до сих пор проверить его можно было только собрав два узла,
/// сессию между ними и подделанный блок. Такого теста не было написано ни
/// разу, и правило жило непроверенным. Здесь оно проверяется четырьмя
/// строками.
///
/// # Блок оценивается целиком
///
/// Смешанный блок от не-создателя — нарушение §11.2 его автором, и
/// разбирать такой по операциям значит завести правило, которого
/// в спецификации нет. Поэтому ответ один на весь блок.
#[must_use]
pub fn removal_allowed(author: ActorId, owner: ActorId, ops: &[OrSetOp<ActorId>]) -> bool {
    if author == owner {
        return true;
    }
    // Не-создатель вправе удалить ровно одного человека — себя. Подписать
    // это за другого нельзя: подпись под блоком и есть доказательство того,
    // что автор — он.
    !ops.iter().any(|op| match op {
        OrSetOp::Remove { elem, .. } => *elem != author,
        OrSetOp::Add { .. } => false,
    })
}

/// Что происходит с тем, кто вышел сам.
///
/// **Дополнение к спецификации**, и потому формулировка тем более обязана
/// жить рядом с кодом: §11.4 описывает исключение, а выход не описывает
/// никак — придумать за него слова больше некому.
///
/// Половина последствий совпадает с §11.4 дословно, и это не совпадение:
/// изнутри протокола выход и исключение — одна и та же операция состава,
/// разнятся они только тем, кто её подписал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaveConsequences;

impl LeaveConsequences {
    /// Получает ли вышедший новые сообщения от честных клиентов.
    pub const RECEIVES_NEW_MESSAGES: bool = false;
    /// Сохраняет ли доступ к прошлой переписке.
    pub const KEEPS_PAST_MESSAGES: bool = true;
    /// Может ли его вернуть любой участник, а не только создатель.
    pub const ANY_MEMBER_CAN_INVITE_BACK: bool = true;

    /// Точная формулировка для UI.
    #[must_use]
    pub const fn ui_text() -> &'static str {
        "Вы выйдете из группы. Переписка останется у вас, новых сообщений \
         вы получать не будете. Вернуть вас в группу может любой участник."
    }

    /// Что добавить, если выходит создатель.
    ///
    /// Отдельным текстом, а не припиской ко всем: остальным участникам это
    /// сказать нечего, а предупреждение, которое видят все, перестают
    /// читать.
    #[must_use]
    pub const fn owner_text() -> &'static str {
        "Вы создатель этой группы. После вашего выхода никто не сможет ни \
         исключать участников, ни менять название: передача прав в этой \
         версии не поддерживается."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: ActorId = [1u8; 32];
    const OTHER: ActorId = [2u8; 32];

    fn tag(ms: u64, actor: ActorId, n: u64) -> Tag {
        Tag::new(Hlc::new(ms, 0), actor, n.to_be_bytes())
    }

    fn group() -> Group {
        Group::create([0u8; 16], OWNER, tag(1, OWNER, 0))
    }

    #[test]
    fn creator_is_the_first_member() {
        let g = group();
        assert!(g.contains(&OWNER));
        assert_eq!(g.len(), 1);
    }

    #[test]
    fn a_restored_group_starts_empty_and_fills_from_operations() {
        // Пустая до первой операции: состав приходит историей, а не
        // предположением о том, что создатель в ней есть.
        let mut g = Group::restore([0u8; 16], OWNER);
        assert!(g.is_empty());

        g.apply(OrSet::prepare_add(OWNER, tag(1, OWNER, 0)));
        g.apply(OrSet::prepare_add(OTHER, tag(2, OWNER, 1)));
        assert_eq!(g.len(), 2);
        assert_eq!(g.owner, OWNER, "владелец приходит отдельно от состава");
    }

    #[test]
    fn a_restored_owner_can_still_be_evicted() {
        // Ради этого `restore` и заведён. Позови подъём `create`, у создателя
        // оказалось бы две метки: поднятая и выдуманная при подъёме. Вторую
        // не гасит ни одно удаление — их писали, видя только первую, —
        // и создатель стал бы неисключаемым после перезапуска.
        let added = tag(1, OWNER, 0);

        let mut fresh = Group::create([0u8; 16], OWNER, added);
        fresh.apply(fresh.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let eviction = fresh.evict(OWNER, OWNER).unwrap();

        let mut restored = Group::restore([0u8; 16], OWNER);
        restored.apply(OrSet::prepare_add(OWNER, added));
        restored.apply(eviction);
        assert!(!restored.contains(&OWNER), "удаление обязано погасить поднятую метку");
    }

    #[test]
    fn anyone_may_invite() {
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        assert!(g.contains(&OTHER));

        // Приглашает не создатель — тоже разрешено (§11.2).
        let third = [3u8; 32];
        g.apply(g.invite(third, tag(3, OTHER, 2)).unwrap());
        assert!(g.contains(&third));
    }

    #[test]
    fn only_owner_may_evict() {
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        assert!(matches!(g.evict(OTHER, OWNER), Err(GroupError::NotOwner)));
        assert!(g.evict(OWNER, OTHER).is_ok());
    }

    #[test]
    fn evicting_a_stranger_is_an_error() {
        let g = group();
        assert!(matches!(g.evict(OWNER, [9u8; 32]), Err(GroupError::NotAMember)));
    }

    #[test]
    fn an_intro_carries_the_title_tag() {
        // Метка едет вместе с названием, а не выдумывается новичком:
        // иначе переименование, случившееся раньше вступления и доехавшее
        // позже, было бы отвергнуто как устаревшее.
        let intro = Intro {
            group: [7u8; 16],
            owner: OWNER,
            title: "у костра".to_owned(),
            title_hlc: Hlc::new(9, 2),
            avatar: Vec::new(),
            avatar_hlc: Hlc::default(),
        };
        let back = intro_from_value(&intro_value(&intro)).unwrap();
        assert_eq!(back.title_hlc, Hlc::new(9, 2));
        assert_eq!(back.title, "у костра");
    }

    #[test]
    fn an_intro_from_an_older_build_has_no_tag_and_that_is_legal() {
        // Сборка, не знавшая переименования, метки не шлёт. Потребуй мы
        // ключ — вступление в группу с такого телефона не состоялось бы
        // вовсе, из-за поля, без которого всё остальное работает.
        let older = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("у костра".into())),
        ]);
        let back =
            intro_from_value(&older).expect("представление версии постарше обязано читаться");
        assert_eq!(back.title_hlc, Hlc::new(0, 0), "нет метки — значит её не выдавали");
    }

    #[test]
    fn anyone_may_leave_including_the_owner() {
        // Выход про своё членство, а не про чужое, и власти не требует.
        // Создателю тоже: человек, который не может уйти из разговора, —
        // это недоработка, а не свойство протокола.
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());

        g.apply(g.leave(OTHER).unwrap());
        assert!(!g.contains(&OTHER), "участник вышел");

        let mut g = group();
        g.apply(g.leave(OWNER).unwrap());
        assert!(!g.contains(&OWNER), "и создатель тоже");
    }

    #[test]
    fn leaving_a_group_you_are_not_in_is_an_error() {
        let g = group();
        assert!(matches!(g.leave([9u8; 32]), Err(GroupError::NotAMember)));
    }

    #[test]
    fn only_the_owner_may_remove_someone_else() {
        // Правило §11.2 на **приёме**: до сих пор проверить его можно было
        // только собрав два узла, сессию и подделанный блок — и потому
        // не проверял никто.
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let third = [3u8; 32];
        g.apply(g.invite(third, tag(3, OWNER, 2)).unwrap());

        let kick_third = g.evict(OWNER, third).unwrap();
        assert!(removal_allowed(OWNER, OWNER, &[kick_third.clone()]), "создателю можно");
        assert!(!removal_allowed(OTHER, OWNER, &[kick_third]), "участнику чужое — нельзя");
    }

    #[test]
    fn anyone_may_remove_themselves() {
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let own_exit = g.leave(OTHER).unwrap();
        assert!(removal_allowed(OTHER, OWNER, &[own_exit]), "выход подписан тем, кто уходит");
    }

    #[test]
    fn a_block_mixing_an_exit_with_a_foreign_removal_is_refused_whole() {
        // Блок оценивается целиком: разбирать смешанный по операциям значит
        // завести правило, которого в спецификации нет.
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let third = [3u8; 32];
        g.apply(g.invite(third, tag(3, OWNER, 2)).unwrap());

        let ops = vec![g.leave(OTHER).unwrap(), g.evict(OWNER, third).unwrap()];
        assert!(!removal_allowed(OTHER, OWNER, &ops), "свой выход чужого удаления не оправдывает");
    }

    #[test]
    fn adding_needs_no_permission_at_all() {
        // Приглашать вправе любой участник (§11.2), и правило про удаление
        // не должно случайно перекрыть это.
        let g = group();
        let invite = g.invite([9u8; 32], tag(4, OTHER, 3)).unwrap();
        assert!(removal_allowed(OTHER, OWNER, &[invite]));
    }

    #[test]
    fn a_departed_member_can_be_invited_back_by_anyone() {
        // OR-Set это и обеспечивает: удаление гасит метки, которые автор
        // видел, а новое приглашение ставит новую. Возвращает **любой**
        // участник — приглашение в §11.2 не привилегия создателя.
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        g.apply(g.leave(OTHER).unwrap());

        g.apply(g.invite(OTHER, tag(3, OWNER, 2)).unwrap());
        assert!(g.contains(&OTHER), "вернулся");
    }

    #[test]
    fn the_owner_stays_the_owner_after_leaving() {
        // Владение не снимается выходом: вернувшись, создатель снова сможет
        // исключать. Снимай мы его, у группы не осталось бы создателя
        // никогда — а это уже другая модель, и §11.2 её не описывает.
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        g.apply(g.leave(OWNER).unwrap());

        assert_eq!(g.owner, OWNER, "создатель прежний");
        assert!(matches!(g.evict(OTHER, OTHER), Err(GroupError::NotOwner)), "исключать некому");
    }

    #[test]
    fn group_size_is_capped_at_thirty_two() {
        let mut g = group();
        for i in 1..MAX_GROUP_MEMBERS {
            let mut who = [0u8; 32];
            who[0] = i as u8;
            who[1] = 0xEE;
            g.apply(g.invite(who, tag(i as u64, OWNER, i as u64)).unwrap());
        }
        assert_eq!(g.len(), MAX_GROUP_MEMBERS);
        assert!(matches!(
            g.invite([0xFF; 32], tag(99, OWNER, 99)),
            Err(GroupError::TooManyMembers)
        ));
    }

    #[test]
    fn recipients_exclude_the_sender() {
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        assert_eq!(g.recipients(&OWNER), vec![OTHER]);
    }

    #[test]
    fn eviction_survives_a_partition_merge() {
        // §16: одновременное исключение участника в двух сегментах.
        let mut a = group();
        a.apply(a.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let mut b = a.clone();

        let op = a.evict(OWNER, OTHER).unwrap();
        a.apply(op.clone());
        b.apply(op);

        a.merge(&b);
        b.merge(&a);
        assert!(!a.contains(&OTHER));
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn snapshot_trigger_is_deterministic() {
        let mut g = group();
        for _ in 0..MEMBERSHIP_SNAPSHOT_EVERY - 1 {
            assert!(!g.note_message());
        }
        assert!(g.note_message(), "снапшот раз в {MEMBERSHIP_SNAPSHOT_EVERY} сообщений");
    }

    #[test]
    fn snapshot_preserves_membership() {
        let mut g = group();
        g.apply(g.invite(OTHER, tag(2, OWNER, 1)).unwrap());
        let before: Vec<_> = g.members().copied().collect();
        g.snapshot(Hlc::new(100, 0));
        assert_eq!(g.members().copied().collect::<Vec<_>>(), before);
    }

    fn owner_identity() -> Identity {
        Identity::from_seed([1u8; 32])
    }

    fn block_of(identity: &Identity) -> MembershipBlock {
        let me = identity.public().ik;
        let mut observed = BTreeSet::new();
        observed.insert(tag(5, me, 1));
        observed.insert(tag(6, OTHER, 2));
        MembershipBlock {
            group: [7u8; 16],
            author: me,
            ops: vec![
                OrSetOp::Add { elem: OTHER, tag: tag(4, me, 3) },
                OrSetOp::Remove { elem: OTHER, observed },
            ],
        }
    }

    #[test]
    fn a_membership_block_survives_the_round_trip_and_the_signature() {
        let owner = owner_identity();
        let block = block_of(&owner);
        let payload = signed_membership(&owner, &block).expect("блок кодируется");

        let unchecked = parse_membership(&payload).expect("разбор");
        assert_eq!(unchecked.claims_author(), &owner.public().ik);
        assert_eq!(unchecked.claims_group(), &block.group);
        let back = unchecked.verify(&owner.public()).expect("подпись сходится");
        assert_eq!(back, block, "операции обязаны пережить круг целиком");
    }

    #[test]
    fn a_block_signed_by_someone_else_is_refused() {
        // Ради этого блок и подписан: при вступлении (§11.5) состав приезжает
        // от пригласившего, а операции в нём написаны разными людьми.
        // Без подписи новичок верил бы пригласившему на слово во всём.
        let owner = owner_identity();
        let forger = Identity::from_seed([9u8; 32]);
        let payload = signed_membership(&forger, &block_of(&owner)).expect("кодируется");

        let unchecked = parse_membership(&payload).expect("разбор");
        assert_eq!(
            unchecked.verify(&owner.public()),
            Err(MembershipError::BadSignature),
            "подпись чужим ключом обязана быть отвергнута"
        );
    }

    #[test]
    fn a_block_checked_against_the_wrong_identity_is_refused_before_the_signature() {
        // Проверять надо **известным** ключом, а не тем, что назван внутри:
        // иначе проверка подтверждала бы лишь то, что отправитель владеет
        // каким-то ключом. Здесь известный ключ — чужой, и блок отвергается
        // по имени автора, не доходя до криптографии.
        let owner = owner_identity();
        let other = Identity::from_seed([9u8; 32]);
        let payload = signed_membership(&owner, &block_of(&owner)).expect("кодируется");

        let unchecked = parse_membership(&payload).expect("разбор");
        assert_eq!(unchecked.verify(&other.public()), Err(MembershipError::NotFromAuthor));
    }

    #[test]
    fn a_tampered_block_does_not_pass() {
        // Подпись стоит над байтами блока, а не над разобранным значением:
        // подменённый состав обязан её сломать.
        let owner = owner_identity();
        let payload = signed_membership(&owner, &block_of(&owner)).expect("кодируется");
        let Value::Map(mut fields) = payload else { panic!("нагрузка — карта") };

        let honest = block_of(&owner);
        let mut tampered = honest.clone();
        tampered.ops = vec![OrSetOp::Add { elem: [42u8; 32], tag: tag(4, owner.public().ik, 3) }];
        let bytes = canonical::encode(&membership_value(&tampered)).expect("кодируется");
        for (key, value) in &mut fields {
            if *key == Value::Integer(KEY_BLOCK.into()) {
                *value = Value::Bytes(bytes.clone());
            }
        }

        let unchecked = parse_membership(&Value::Map(fields)).expect("разбор");
        assert_eq!(unchecked.verify(&owner.public()), Err(MembershipError::BadSignature));
    }

    #[test]
    fn a_block_longer_than_the_limit_is_refused_on_arrival() {
        // Длину называет та сторона провода: «сто тысяч операций» — это
        // запрос памяти, а не состав. Предел на приёме, а не только
        // на отправке.
        let owner = owner_identity();
        let me = owner.public().ik;
        let ops: Vec<Value> = (0..=MAX_MEMBERSHIP_OPS)
            .map(|n| {
                op_value(&OrSetOp::Add {
                    elem: [u8::try_from(n % 251).unwrap_or(0); 32],
                    tag: tag(4, me, 3),
                })
            })
            .collect();
        let huge = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_AUTHOR.into()), Value::Bytes(me.to_vec())),
            (Value::Integer(KEY_OPS.into()), Value::Array(ops)),
        ]);
        assert!(membership_from_value(&huge).is_err());
    }

    #[test]
    fn an_add_carries_exactly_one_tag() {
        // Добавление помечается одной меткой. Массив из двух — не «с запасом»,
        // а чужая форма, и принять её значило бы молча выбрать первую.
        let me = owner_identity().public().ik;
        let two = Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(OP_ADD.into())),
            (Value::Integer(KEY_ELEM.into()), Value::Bytes(OTHER.to_vec())),
            (
                Value::Integer(KEY_TAGS.into()),
                Value::Array(vec![tag_value(&tag(1, me, 1)), tag_value(&tag(2, me, 2))]),
            ),
        ]);
        assert!(op_from_value(&two).is_err());
    }

    #[test]
    fn a_sender_key_survives_the_round_trip() {
        let block = SenderKeyBlock {
            group: [7u8; 16],
            member: OTHER,
            chain: [3u8; 32],
            counter: 1_234,
            chain_hlc: Hlc::new(9_000, 2),
        };
        let back = sender_key_from_value(&sender_key_value(&block)).expect("разбор");
        assert_eq!(back, block, "номер и метка поворота обязаны ехать вместе с ключом");
    }

    #[test]
    fn a_sender_key_without_a_mark_reads_as_the_beginning_of_time() {
        // Так выглядит блок от сборки, не знавшей старшинства: разбор
        // обязан его принять, а метка — оказаться нулевой, чтобы первое
        // же названное старшинство её обогнало.
        let old = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OTHER.to_vec())),
            (Value::Integer(KEY_CHAIN.into()), Value::Bytes(vec![3u8; 32])),
            (Value::Integer(KEY_COUNTER.into()), Value::Integer(0.into())),
        ]);
        let back = sender_key_from_value(&old).expect("разбор старого блока");
        assert_eq!(back.chain_hlc, Hlc::default(), "без поля метка обязана быть нулевой");
    }

    fn card(n: u8, len: usize) -> Vec<u8> {
        vec![n; len]
    }

    /// Картинка нужной длины, начинающаяся с настоящей сигнатуры PNG.
    fn png_of(len: usize) -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.resize(len.max(bytes.len()), 0);
        bytes
    }

    fn png() -> Vec<u8> {
        png_of(64)
    }

    #[test]
    fn an_intro_survives_the_round_trip() {
        let intro = Intro {
            group: [7u8; 16],
            owner: OWNER,
            title: "у костра".to_owned(),
            title_hlc: Hlc::new(7, 1),
            avatar: png(),
            avatar_hlc: Hlc::new(8, 3),
        };
        assert_eq!(intro_from_value(&intro_value(&intro)).unwrap(), intro);
    }

    #[test]
    fn an_oversized_title_is_refused_on_receipt() {
        // Длину называет та сторона провода: «название в мегабайт» —
        // запрос памяти, а не название.
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("я".repeat(MAX_GROUP_TITLE_BYTES))),
        ]);
        assert!(intro_from_value(&value).is_err(), "кириллица идёт по два байта");

        // Ровно предел — законен, и в байтах, а не в символах.
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("я".repeat(MAX_GROUP_TITLE_BYTES / 2))),
        ]);
        assert!(intro_from_value(&value).is_ok());
    }

    #[test]
    fn an_empty_title_is_legal_on_the_wire() {
        // Отвергает пустое название ядро, при заведении, — там человек
        // нажал кнопку и обязан узнать почему (§14). На приёме отвергать
        // нечего: пустая строка от чужой сборки это не атака, а мусор,
        // и чат с ней всё равно надо как-то показать.
        let intro = Intro {
            group: [7u8; 16],
            owner: OWNER,
            title: String::new(),
            title_hlc: Hlc::new(0, 0),
            avatar: Vec::new(),
            avatar_hlc: Hlc::default(),
        };
        assert_eq!(intro_from_value(&intro_value(&intro)).unwrap(), intro);
    }

    #[test]
    fn an_intro_carries_the_avatar_and_its_tag() {
        // Единственная дорога картинки к новичку. Метка едет отдельным
        // полем и переживает пересылку: выдай пригласивший свою, настоящая
        // новая картинка создателя была бы у новичка отвергнута.
        let intro = Intro {
            group: [7u8; 16],
            owner: OWNER,
            title: "у костра".to_owned(),
            title_hlc: Hlc::new(9, 2),
            avatar: png(),
            avatar_hlc: Hlc::new(11, 5),
        };
        let back = intro_from_value(&intro_value(&intro)).unwrap();
        assert_eq!(back.avatar, png());
        assert_eq!(back.avatar_hlc, Hlc::new(11, 5), "метка та же, а не нулевая");
    }

    #[test]
    fn an_intro_from_a_build_without_avatars_still_joins() {
        // Потребуй мы ключ — вступление с телефона постарше не состоялось
        // бы вовсе, из-за поля, без которого всё остальное работает. То же
        // решение, что у метки названия.
        let older = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("у костра".into())),
        ]);
        let back = intro_from_value(&older).unwrap();
        assert!(back.avatar.is_empty(), "картинки нет");
        assert_eq!(back.avatar_hlc, Hlc::default(), "и метки тоже: её обгонит любая");
    }

    #[test]
    fn a_bad_avatar_does_not_break_joining() {
        // Картинка — украшение, а состав и создатель — нет. Сорви мы
        // вступление из-за негодных байтов, человек остался бы вовсе
        // без группы там, где довольно показать её без лица.
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("у костра".into())),
            (Value::Integer(KEY_AVATAR.into()), Value::Bytes(b"not an image".to_vec())),
        ]);
        let back = intro_from_value(&value).unwrap();
        assert!(back.avatar.is_empty(), "негодные байты не едут в системный декодер");
        assert_eq!(back.title, "у костра", "а всё остальное на месте");

        // И слишком большая — тем же путём: предел меряет `avatar::check`.
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (Value::Integer(KEY_ACTOR.into()), Value::Bytes(OWNER.to_vec())),
            (Value::Integer(KEY_TITLE.into()), Value::Text("у костра".into())),
            (
                Value::Integer(KEY_AVATAR.into()),
                Value::Bytes(png_of(crate::avatar::MAX_AVATAR_BYTES + 1)),
            ),
        ]);
        assert!(intro_from_value(&value).unwrap().avatar.is_empty());
    }

    #[test]
    fn an_intro_with_a_full_avatar_fits_one_frame() {
        // Худший законный случай, замером, а не рассуждением: предельная
        // картинка и предельное название. Не поместись — вступление
        // пришлось бы фрагментировать (§9.3), а это другой разговор.
        // Карточки участников едут **своим** кадром и здесь не при чём.
        let intro = Intro {
            group: [7u8; 16],
            owner: OWNER,
            title: "я".repeat(MAX_GROUP_TITLE_BYTES / 2),
            title_hlc: Hlc::new(u64::MAX, u32::MAX),
            avatar: png_of(crate::avatar::MAX_AVATAR_BYTES),
            avatar_hlc: Hlc::new(u64::MAX, u32::MAX),
        };
        let bytes = canonical::encode(&intro_value(&intro)).expect("представление кодируется");
        let class = ratatosk_wire::SizeClass::smallest_for(bytes.len());
        assert!(class.is_some(), "представление в {} байт не лезет ни в один кадр", bytes.len());
        assert_eq!(
            intro_from_value(&canonical::decode(&bytes).unwrap()).unwrap(),
            intro,
            "и разбирается обратно целиком"
        );
    }

    #[test]
    fn a_roster_survives_the_round_trip() {
        let roster = Roster { group: [7u8; 16], cards: vec![card(1, 200), card(2, 300)] };
        assert_eq!(roster_from_value(&roster_value(&roster)).unwrap(), roster);
    }

    #[test]
    fn an_empty_roster_is_legal() {
        // Список из нуля карточек законен: группа из одного создателя,
        // и рассказывать о ней ещё некому.
        let roster = Roster { group: [7u8; 16], cards: Vec::new() };
        assert_eq!(roster_from_value(&roster_value(&roster)).unwrap(), roster);
    }

    #[test]
    fn too_many_cards_are_refused_on_receipt() {
        // Длину называет та сторона провода: «тысяча карточек» — запрос
        // памяти, а не состав. Предел проверяется на приёме, а не только
        // на отправке.
        let cards = (0..=MAX_ROSTER_CARDS).map(|n| card(n as u8, 8)).collect::<Vec<_>>();
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (
                Value::Integer(KEY_CARDS.into()),
                Value::Array(cards.into_iter().map(Value::Bytes).collect()),
            ),
        ]);
        assert!(roster_from_value(&value).is_err());
    }

    #[test]
    fn an_oversized_card_is_refused_on_receipt() {
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (
                Value::Integer(KEY_CARDS.into()),
                Value::Array(vec![Value::Bytes(card(1, MAX_ROSTER_CARD_BYTES + 1))]),
            ),
        ]);
        assert!(roster_from_value(&value).is_err());
        // Ровно предел — законен.
        let value = Value::Map(vec![
            (Value::Integer(KEY_GROUP.into()), Value::Bytes(vec![7u8; 16])),
            (
                Value::Integer(KEY_CARDS.into()),
                Value::Array(vec![Value::Bytes(card(1, MAX_ROSTER_CARD_BYTES))]),
            ),
        ]);
        assert!(roster_from_value(&value).is_ok());
    }

    #[test]
    fn a_full_roster_fits_one_frame() {
        // Худший **законный** случай, замером, а не рассуждением: тридцать
        // две карточки по килобайту. Не поместись он — вступление в полную
        // группу пришлось бы фрагментировать (§9.3), а это уже другой
        // разговор про потери и сборку.
        let roster = Roster {
            group: [7u8; 16],
            cards: (0..MAX_ROSTER_CARDS)
                .map(|n| card(u8::try_from(n % 256).unwrap(), MAX_ROSTER_CARD_BYTES))
                .collect(),
        };
        let bytes = canonical::encode(&roster_value(&roster)).expect("список кодируется");
        let class = ratatosk_wire::SizeClass::smallest_for(bytes.len());
        assert!(class.is_some(), "полный список в {} байт не лезет ни в один кадр", bytes.len());
        assert_eq!(
            roster_from_value(&canonical::decode(&bytes).unwrap()).unwrap(),
            roster,
            "и разбирается обратно целиком"
        );
    }

    #[test]
    fn the_join_disclosure_says_what_it_costs() {
        // §11.5 требует сказать это при создании группы дословно.
        assert!(JOIN_DISCLOSURE.contains("адреса"));
        assert!(JOIN_DISCLOSURE.contains("не отменить"), "необратимость — половина смысла");
    }

    fn message(counter: u64) -> GroupMessage {
        GroupMessage { group: [7u8; 16], sender: OWNER, counter, sealed: b"sealed bytes".to_vec() }
    }

    #[test]
    fn a_signed_message_verifies_with_the_senders_key() {
        let sender = Identity::from_seed([1u8; 32]);
        let mut message = message(3);
        message.sender = sender.public().ik;

        let value = signed_message(&sender, &message).unwrap();
        let unchecked = parse_message(&value).unwrap();
        assert_eq!(*unchecked.claims_group(), message.group);
        assert_eq!(*unchecked.claims_sender(), message.sender);
        assert_eq!(unchecked.claims_counter(), 3, "номер виден до проверки — по нему ищут ключ");
        assert_eq!(unchecked.verify(&sender.public()).unwrap(), message);
    }

    #[test]
    fn a_message_signed_by_someone_else_is_refused() {
        // Ради этого подпись в §11.1 и стоит: sender key одинаков у всех
        // получателей, и без подписи любой участник подделал бы сообщение
        // от имени любого другого.
        let sender = Identity::from_seed([1u8; 32]);
        let impostor = Identity::from_seed([2u8; 32]);
        let mut message = message(0);
        message.sender = sender.public().ik;

        // Самозванец подписывает сообщение, назвавшись отправителем.
        let value = signed_message(&impostor, &message).unwrap();
        assert!(matches!(
            parse_message(&value).unwrap().verify(&sender.public()),
            Err(MembershipError::BadSignature)
        ));

        // И назвавшись собой — тоже не сойдётся с ключом, который ищут.
        let mut own = message.clone();
        own.sender = impostor.public().ik;
        let value = signed_message(&impostor, &own).unwrap();
        assert!(matches!(
            parse_message(&value).unwrap().verify(&sender.public()),
            Err(MembershipError::NotFromAuthor)
        ));
    }

    #[test]
    fn the_counter_is_inside_the_signature() {
        // Переставь его сосед по сети — и сообщение попыталось бы открыться
        // чужим ключом цепочки. Номер обязан быть подписан вместе с телом.
        let sender = Identity::from_seed([1u8; 32]);
        let mut message = message(5);
        message.sender = sender.public().ik;
        let value = signed_message(&sender, &message).unwrap();

        // Подменяем номер внутри подписанного куска.
        let Value::Map(pairs) = &value else { panic!("нагрузка — карта") };
        let signature = pairs
            .iter()
            .find(|(k, _)| *k == Value::Integer(KEY_SIGNATURE.into()))
            .map(|(_, v)| v.clone())
            .unwrap();
        let mut tampered = message.clone();
        tampered.counter = 6;
        let forged = Value::Map(vec![
            (
                Value::Integer(KEY_BLOCK.into()),
                Value::Bytes(canonical::encode(&message_value(&tampered)).unwrap()),
            ),
            (Value::Integer(KEY_SIGNATURE.into()), signature),
        ]);

        let unchecked = parse_message(&forged).unwrap();
        assert_eq!(unchecked.claims_counter(), 6, "подмена видна в заявке");
        assert!(matches!(unchecked.verify(&sender.public()), Err(MembershipError::BadSignature),));
    }

    #[test]
    fn a_message_of_the_wrong_shape_is_refused() {
        assert!(matches!(
            parse_message(&Value::Integer(1.into())),
            Err(MembershipError::Malformed)
        ));
        // Подпись не той длины — тоже форма, а не подделка.
        let broken = Value::Map(vec![
            (Value::Integer(KEY_BLOCK.into()), Value::Bytes(vec![1, 2, 3])),
            (Value::Integer(KEY_SIGNATURE.into()), Value::Bytes(vec![0u8; 63])),
        ]);
        assert!(matches!(parse_message(&broken), Err(MembershipError::Malformed)));
    }

    #[test]
    fn ui_text_matches_the_actual_guarantees() {
        assert!(!EvictionConsequences::RECEIVES_NEW_MESSAGES);
        assert!(EvictionConsequences::KEEPS_PAST_MESSAGES);
        assert!(EvictionConsequences::ui_text().contains("сохранит"));
    }

    #[test]
    fn the_owner_is_warned_about_everything_that_leaves_with_him() {
        // §14: сказать надо всё, чего после ухода не будет. Право
        // исключать было первым, название стало вторым, и текст обязан
        // расти вместе с правом — иначе он превращается в неполную правду,
        // а неполная правда здесь хуже молчания.
        let text = LeaveConsequences::owner_text();
        assert!(text.contains("исключать"), "про исключение: {text}");
        assert!(text.contains("название"), "и про название: {text}");
    }

    #[test]
    fn a_new_title_is_stricter_than_one_that_merely_arrives() {
        // Пустое имя в представлении группы — досадный мусор, с которым
        // чат всё равно надо показать. Пустое имя в переименовании —
        // действие человека, стирающее у всех то, что было.
        assert!(check_title_fits("").is_ok(), "на приёме пустое законно");
        assert!(check_new_title("").is_err(), "а переименованием — нет");
        assert!(check_new_title("   ").is_err(), "и пробелами тоже");
        assert!(check_new_title("у костра").is_ok());

        let long = "я".repeat(MAX_GROUP_TITLE_BYTES);
        assert!(check_new_title(&long).is_err(), "предел провода один на оба правила");
    }
}
