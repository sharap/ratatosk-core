//! OR-Set с метками HLC — состав группы (§11.2).
//!
//! Добавление и удаление — подписанные блоки, распространяемые по 1:1-сессиям
//! каждому участнику. Порядок разрешается семантикой OR-Set: удаление
//! действует на те добавления, которые удаляющий **видел**. Это корректно
//! обрабатывает случай «исключили, пока он в другом сегменте сети заново
//! вступал»: невиденное добавление переживает удаление, участник остаётся
//! в группе, и расхождения состояний между узлами не возникает.
//!
//! Крейт хранит только структуру данных. Подписи блоков (§11.2) и права
//! («любой приглашает, исключает только создатель») — уровнем выше,
//! в `ratatosk-proto`.

use std::collections::{BTreeMap, BTreeSet};

use crate::hlc::Hlc;

/// Идентификатор автора операции — `IK` участника (§3).
pub type ActorId = [u8; 32];

/// Уникальная метка одной операции добавления.
///
/// Уникальность обеспечивают все три поля вместе: `hlc` даёт порядок, `actor`
/// разводит одновременные операции разных участников, `uniq` — повторные
/// добавления одного участника внутри одной метки HLC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag {
    /// Момент операции по гибридным часам автора.
    pub hlc: Hlc,
    /// Кто выполнил операцию.
    pub actor: ActorId,
    /// Случайные байты, разводящие коллизии внутри одной метки.
    pub uniq: [u8; 8],
}

impl Tag {
    /// Собирает метку.
    #[must_use]
    pub const fn new(hlc: Hlc, actor: ActorId, uniq: [u8; 8]) -> Tag {
        Tag { hlc, actor, uniq }
    }
}

/// Операция над множеством — то, что кладётся в подписанный блок и рассылается.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrSetOp<T> {
    /// Добавление элемента с новой уникальной меткой.
    Add {
        /// Добавляемый элемент.
        elem: T,
        /// Метка операции.
        tag: Tag,
    },
    /// Удаление: гасятся ровно те метки добавления, которые автор видел.
    Remove {
        /// Удаляемый элемент.
        elem: T,
        /// Наблюдённые автором метки добавления.
        observed: BTreeSet<Tag>,
    },
}

/// Observed-Remove Set.
///
/// Слияние коммутативно, ассоциативно и идемпотентно — это проверяется
/// тестами здесь и `proptest`-инвариантами из §16.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrSet<T: Ord + Clone> {
    adds: BTreeMap<T, BTreeSet<Tag>>,
    /// Надгробия хранятся парой «элемент, метка», а не одной меткой.
    ///
    /// Метка уникальна лишь постольку, поскольку `uniq` — восемь случайных
    /// байт. Набор надгробий, общий на все элементы, превращает совпадение
    /// меток в тихое исчезновение чужого элемента: удаление `alice` погасило
    /// бы добавление `bob`. Пара делает это невозможным структурно, а не
    /// маловероятным, и обходится бесплатно — операция удаления и так знает
    /// свой элемент.
    tombstones: BTreeSet<(T, Tag)>,
    baseline: Hlc,
}

impl<T: Ord + Clone> Default for OrSet<T> {
    fn default() -> Self {
        OrSet::new()
    }
}

impl<T: Ord + Clone> OrSet<T> {
    /// Пустое множество.
    #[must_use]
    pub fn new() -> OrSet<T> {
        OrSet { adds: BTreeMap::new(), tombstones: BTreeSet::new(), baseline: Hlc::ZERO }
    }

    /// Граница, до которой история свёрнута в снапшот (§12).
    #[must_use]
    pub const fn baseline(&self) -> Hlc {
        self.baseline
    }

    /// Строит операцию добавления. Состояние не меняется — применяется
    /// через [`OrSet::apply`], чтобы локальный путь и путь приёма были одним
    /// и тем же кодом.
    #[must_use]
    pub fn prepare_add(elem: T, tag: Tag) -> OrSetOp<T> {
        OrSetOp::Add { elem, tag }
    }

    /// Строит операцию удаления, фиксируя метки, видимые прямо сейчас.
    ///
    /// Если элемента нет, операция получится с пустым набором меток — она
    /// корректна и просто ничего не гасит.
    #[must_use]
    pub fn prepare_remove(&self, elem: T) -> OrSetOp<T> {
        let observed = self.adds.get(&elem).cloned().unwrap_or_default();
        OrSetOp::Remove { elem, observed }
    }

    /// Применяет операцию — свою или пришедшую от участника.
    pub fn apply(&mut self, op: OrSetOp<T>) {
        match op {
            OrSetOp::Add { elem, tag } => {
                // Метка старше baseline уже учтена в снапшоте: повторное
                // применение воскресило бы удалённого участника.
                if tag.hlc < self.baseline {
                    return;
                }
                // Удаление могло обогнать добавление, которое оно гасит (§9.2):
                // почта переставляет сообщения. Без этой проверки два узла,
                // получившие одни и те же операции в разном порядке, разойдутся
                // по составу группы — `merge` надгробия учитывает, а `apply`
                // учитывать обязан ровно так же.
                if self.tombstones.contains(&(elem.clone(), tag)) {
                    return;
                }
                self.adds.entry(elem).or_default().insert(tag);
            }
            OrSetOp::Remove { elem, observed } => {
                if let Some(tags) = self.adds.get_mut(&elem) {
                    for t in &observed {
                        tags.remove(t);
                    }
                    if tags.is_empty() {
                        self.adds.remove(&elem);
                    }
                }
                // Надгробия хранятся отдельно: добавление с той же меткой
                // может прийти позже удаления (почта переставляет сообщения).
                self.tombstones.extend(observed.into_iter().map(|t| (elem.clone(), t)));
            }
        }
    }

    /// Есть ли элемент в множестве.
    #[must_use]
    pub fn contains(&self, elem: &T) -> bool {
        self.adds.get(elem).is_some_and(|tags| !tags.is_empty())
    }

    /// Текущий состав, в детерминированном порядке.
    pub fn elements(&self) -> impl Iterator<Item = &T> {
        self.adds.iter().filter(|(_, tags)| !tags.is_empty()).map(|(e, _)| e)
    }

    /// Число элементов. Для группы сравнивается с пределом в 32 участника (§11.3).
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements().count()
    }

    /// Пусто ли множество.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Слияние с состоянием другого узла.
    ///
    /// Порядок аргументов не важен и повторное слияние ничего не меняет —
    /// без этого сходимость после разделения сети (§16) недостижима.
    pub fn merge(&mut self, other: &OrSet<T>) {
        for (elem, tags) in &other.adds {
            self.adds.entry(elem.clone()).or_default().extend(tags.iter().copied());
        }
        self.baseline = self.baseline.max(other.baseline);

        let mut tombstones = std::mem::take(&mut self.tombstones);
        tombstones.extend(other.tombstones.iter().cloned());

        // Гасим всё, что помечено удалённым любой из сторон.
        self.adds.retain(|elem, tags| {
            tags.retain(|t| !tombstones.contains(&(elem.clone(), *t)));
            !tags.is_empty()
        });
        self.tombstones = tombstones;
    }

    /// Пустое множество с **уже поставленным** водяным знаком.
    ///
    /// Нужно при подъёме свёрнутого состава с диска: знак обязан стоять
    /// **до** того, как применят первую операцию, иначе свёрнутое
    /// добавление воскреснет, приехав от соседа. Знак — единственное,
    /// что переживает свёртку, кроме самого состава.
    #[must_use]
    pub fn restored_at(baseline: Hlc) -> OrSet<T> {
        OrSet { adds: BTreeMap::new(), tombstones: BTreeSet::new(), baseline }
    }

    /// Схлопывает историю в снапшот состава (§12).
    ///
    /// После вызова надгробия старше `baseline` выброшены, а каждый выживший
    /// элемент несёт единственную синтетическую метку. Операции с метками
    /// старше `baseline` после этого игнорируются.
    ///
    /// Вызывать можно только по детерминированному триггеру, одинаковому
    /// у всех участников (§12: снапшот раз в 5000 сообщений), иначе узлы
    /// свернут разные истории и разойдутся.
    pub fn compact(&mut self, baseline: Hlc, snapshot_actor: ActorId) {
        let survivors: Vec<T> = self.elements().cloned().collect();
        self.adds.clear();
        self.tombstones.retain(|(_, t)| t.hlc >= baseline);
        self.baseline = baseline;

        for (i, elem) in survivors.into_iter().enumerate() {
            let uniq = (i as u64).to_be_bytes();
            self.adds.entry(elem).or_default().insert(Tag::new(baseline, snapshot_actor, uniq));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ActorId = [0xAA; 32];
    const B: ActorId = [0xBB; 32];

    fn tag(ms: u64, actor: ActorId, n: u64) -> Tag {
        Tag::new(Hlc::new(ms, 0), actor, n.to_be_bytes())
    }

    fn set_with(items: &[(&'static str, Tag)]) -> OrSet<&'static str> {
        let mut s = OrSet::new();
        for (elem, t) in items {
            s.apply(OrSet::prepare_add(*elem, *t));
        }
        s
    }

    #[test]
    fn add_then_remove() {
        let mut s = set_with(&[("alice", tag(1, A, 1))]);
        assert!(s.contains(&"alice"));
        let op = s.prepare_remove("alice");
        s.apply(op);
        assert!(!s.contains(&"alice"));
        assert!(s.is_empty());
    }

    #[test]
    fn concurrent_add_wins_over_unseen_remove() {
        // Сценарий из §11.2: участника исключают в одном сегменте сети,
        // пока во втором его заново добавляют. Невиденное добавление выживает.
        let mut seg1 = set_with(&[("carol", tag(1, A, 1))]);
        let mut seg2 = seg1.clone();

        let remove = seg1.prepare_remove("carol"); // видит только метку 1
        seg1.apply(remove.clone());

        seg2.apply(OrSet::prepare_add("carol", tag(2, B, 2))); // новое добавление

        seg1.merge(&seg2);
        seg2.apply(remove);

        assert!(seg1.contains(&"carol"));
        assert!(seg2.contains(&"carol"));
        assert_eq!(seg1, seg2, "узлы должны сойтись к одному состоянию");
    }

    #[test]
    fn remove_wins_when_it_saw_the_add() {
        let mut seg1 = set_with(&[("dave", tag(1, A, 1))]);
        let mut seg2 = seg1.clone();

        seg2.apply(OrSet::prepare_add("dave", tag(2, B, 2)));
        let remove = seg2.prepare_remove("dave"); // видит обе метки
        seg2.apply(remove.clone());

        seg1.apply(remove);
        seg1.merge(&seg2);
        seg2.merge(&seg1);

        assert!(!seg1.contains(&"dave"));
        assert_eq!(seg1, seg2);
    }

    #[test]
    fn merge_is_commutative_associative_idempotent() {
        let s1 = set_with(&[("a", tag(1, A, 1)), ("b", tag(2, A, 2))]);
        let mut s2 = set_with(&[("b", tag(3, B, 3)), ("c", tag(4, B, 4))]);
        let rm = s2.prepare_remove("b");
        s2.apply(rm);
        let s3 = set_with(&[("d", tag(5, A, 5))]);

        let mut left = s1.clone();
        left.merge(&s2);
        left.merge(&s3);

        let mut right = s3.clone();
        right.merge(&s2);
        right.merge(&s1);

        assert_eq!(left, right, "слияние коммутативно");

        let mut again = left.clone();
        again.merge(&s2);
        again.merge(&s1);
        assert_eq!(left, again, "слияние идемпотентно");
    }

    #[test]
    fn remove_arriving_before_add_takes_effect_via_apply_too() {
        // Регрессия. Раньше надгробие учитывал только `merge`, а `apply` —
        // нет, и два узла, получившие одни и те же две операции в разном
        // порядке, расходились по составу группы навсегда. Порядок доставки
        // при этом не аномалия: §9.2 прямо говорит, что почта переставляет
        // сообщения.
        let mut donor = set_with(&[("erin", tag(1, A, 1))]);
        let remove = donor.prepare_remove("erin");
        donor.apply(remove.clone());

        let mut late: OrSet<&str> = OrSet::new();
        late.apply(remove);
        late.apply(OrSet::prepare_add("erin", tag(1, A, 1)));

        assert!(!late.contains(&"erin"));
        assert_eq!(donor, late, "порядок доставки не должен менять состояние");
    }

    #[test]
    fn a_tombstone_does_not_reach_across_elements() {
        // Регрессия. Надгробия хранились одной меткой без элемента, поэтому
        // удаление одного участника гасило добавление другого, если метки
        // совпали. В бою это опиралось на то, что `uniq` — восемь случайных
        // байт; здесь совпадение выставлено намеренно.
        let shared = tag(1, A, 7);

        let mut s = OrSet::new();
        s.apply(OrSet::prepare_add("alice", shared));
        let remove = s.prepare_remove("alice");
        s.apply(remove.clone());

        // Тот же контрпример в обоих порядках доставки.
        let mut after = s.clone();
        after.apply(OrSet::prepare_add("bob", shared));

        let mut before: OrSet<&str> = OrSet::new();
        before.apply(remove);
        before.apply(OrSet::prepare_add("bob", shared));

        assert!(after.contains(&"bob"), "удаление alice не должно касаться bob");
        assert!(before.contains(&"bob"));
        assert_eq!(after, before);
    }

    #[test]
    fn remove_arriving_before_add_still_takes_effect() {
        // Почта переставляет сообщения (§9.2): блок удаления может обогнать
        // блок добавления, который он гасит.
        let donor = set_with(&[("erin", tag(1, A, 1))]);
        let remove = donor.prepare_remove("erin");

        let mut receiver: OrSet<&str> = OrSet::new();
        receiver.apply(remove);
        receiver.merge(&donor);

        assert!(!receiver.contains(&"erin"), "надгробие должно пережить перестановку");
    }

    #[test]
    fn compaction_preserves_membership() {
        let mut s = set_with(&[("a", tag(1, A, 1)), ("b", tag(2, A, 2)), ("c", tag(3, B, 3))]);
        let rm = s.prepare_remove("b");
        s.apply(rm);

        let before: Vec<_> = s.elements().copied().collect();
        s.compact(Hlc::new(100, 0), A);
        let after: Vec<_> = s.elements().copied().collect();

        assert_eq!(before, after);
        assert_eq!(s.baseline(), Hlc::new(100, 0));
    }

    #[test]
    fn compacted_set_ignores_stale_ops() {
        let mut s = set_with(&[("a", tag(1, A, 1))]);
        let rm = s.prepare_remove("a");
        s.apply(rm);
        s.compact(Hlc::new(100, 0), A);

        // Запоздавшее добавление из свёрнутой эпохи не должно воскресить
        // исключённого участника.
        s.apply(OrSet::prepare_add("a", tag(2, B, 9)));
        assert!(!s.contains(&"a"));
    }

    #[test]
    fn compaction_result_is_merge_stable() {
        let mut a = set_with(&[("x", tag(1, A, 1)), ("y", tag(2, B, 2))]);
        let mut b = a.clone();
        a.compact(Hlc::new(50, 0), A);
        b.compact(Hlc::new(50, 0), A);
        assert_eq!(a, b, "одинаковый триггер даёт одинаковый снапшот");

        a.merge(&b);
        assert_eq!(a.elements().copied().collect::<Vec<_>>(), vec!["x", "y"]);
    }
}
