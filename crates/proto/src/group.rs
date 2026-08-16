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

use ratatosk_crdt::{ActorId, Hlc, OrSet, OrSetOp, Tag};

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

    #[test]
    fn ui_text_matches_the_actual_guarantees() {
        assert!(!EvictionConsequences::RECEIVES_NEW_MESSAGES);
        assert!(EvictionConsequences::KEEPS_PAST_MESSAGES);
        assert!(EvictionConsequences::ui_text().contains("сохранит"));
    }
}
