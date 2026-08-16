//! Инварианты §16: «слияние OR-Set коммутативно и идемпотентно».
//!
//! Примерные тесты в `src/orset.rs` проверяют те случаи, которые пришли в
//! голову автору. Здесь проверяется свойство: любая история операций, любой
//! порядок доставки. Разница не теоретическая — первый же прогон этого файла
//! нашёл расхождение, которое примерные тесты не ловили: удаление, обогнавшее
//! добавление, гасилось при `merge`, но не при `apply`.
//!
//! Область значений намеренно узкая (16 элементов, 4 автора, метки HLC в
//! диапазоне 0..8), чтобы коллизии и одновременные операции случались часто,
//! а не раз в тысячу прогонов.

use std::collections::BTreeSet;

use proptest::prelude::*;
use ratatosk_crdt::hlc::Hlc;
use ratatosk_crdt::orset::{ActorId, OrSet, OrSetOp, Tag};

/// Действие в истории. Из него получается операция — но `Remove` требует
/// состояния (§11.2: гасятся ровно виденные метки), поэтому история
/// разворачивается в операции узлом-автором, а не напрямую.
#[derive(Debug, Clone)]
enum Action {
    Add { elem: u8, actor: u8, ms: u8, uniq: u8 },
    Remove { elem: u8, by: u8 },
}

fn actor(n: u8) -> ActorId {
    [n; 32]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        3 => (0u8..16, 0u8..4, 0u8..8, 0u8..4)
            .prop_map(|(elem, actor, ms, uniq)| Action::Add { elem, actor, ms, uniq }),
        1 => (0u8..16, 0u8..4).prop_map(|(elem, by)| Action::Remove { elem, by }),
    ]
}

fn history() -> impl Strategy<Value = Vec<Action>> {
    prop::collection::vec(action(), 0..40)
}

/// Разворачивает историю в операции.
///
/// Удаления готовят несколько «авторов» с разной осведомлённостью: узел `by`
/// видел только те добавления, которые до него дошли. Именно так возникают
/// одновременные операции, ради которых OR-Set и взят.
fn unfold(actions: &[Action]) -> Vec<OrSetOp<u8>> {
    let mut authors: Vec<OrSet<u8>> = (0..4).map(|_| OrSet::new()).collect();
    let mut ops = Vec::new();

    for a in actions {
        let op = match *a {
            Action::Add { elem, actor: who, ms, uniq } => {
                let tag = Tag::new(Hlc::new(u64::from(ms), 0), actor(who), [uniq; 8]);
                OrSet::prepare_add(elem, tag)
            }
            Action::Remove { elem, by } => authors[usize::from(by)].prepare_remove(elem),
        };
        // Автор удаления видит операцию сразу; остальные — с задержкой,
        // которую моделирует уже сам порядок доставки в тестах ниже.
        match a {
            Action::Add { actor: who, .. } => authors[usize::from(*who)].apply(op.clone()),
            Action::Remove { by, .. } => authors[usize::from(*by)].apply(op.clone()),
        }
        ops.push(op);
    }
    ops
}

/// Перестановка, задаваемая сгенерированными индексами: свой шаффл вместо
/// зависимости от генератора случайных чисел, чтобы контрпример был
/// воспроизводим по одному только значению `swaps`.
fn permute<T>(mut items: Vec<T>, swaps: &[u16]) -> Vec<T> {
    let n = items.len();
    if n < 2 {
        return items;
    }
    for (i, s) in swaps.iter().enumerate() {
        let a = i % n;
        let b = usize::from(*s) % n;
        items.swap(a, b);
    }
    items
}

fn replay(ops: &[OrSetOp<u8>]) -> OrSet<u8> {
    let mut s = OrSet::new();
    for op in ops {
        s.apply(op.clone());
    }
    s
}

fn members(s: &OrSet<u8>) -> BTreeSet<u8> {
    s.elements().copied().collect()
}

proptest! {
    /// Порядок доставки не влияет на результат.
    ///
    /// Это и есть причина, по которой в §11.2 стоит OR-Set, а не «список
    /// с последней записью побеждает»: почта переставляет сообщения (§9.2),
    /// а сегменты сети сливаются в произвольном порядке (§16).
    #[test]
    fn delivery_order_does_not_matter(
        actions in history(),
        swaps in prop::collection::vec(any::<u16>(), 0..80),
    ) {
        let ops = unfold(&actions);
        let straight = replay(&ops);
        let shuffled = replay(&permute(ops, &swaps));
        prop_assert_eq!(&straight, &shuffled, "разный порядок доставки дал разное состояние");
    }

    /// Слияние коммутативно.
    #[test]
    fn merge_is_commutative(
        left in history(),
        right in history(),
    ) {
        let a = replay(&unfold(&left));
        let b = replay(&unfold(&right));

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b;
        ba.merge(&a);

        prop_assert_eq!(ab, ba);
    }

    /// Слияние ассоциативно.
    #[test]
    fn merge_is_associative(
        x in history(),
        y in history(),
        z in history(),
    ) {
        let a = replay(&unfold(&x));
        let b = replay(&unfold(&y));
        let c = replay(&unfold(&z));

        let mut left = a.clone();
        left.merge(&b);
        left.merge(&c);

        let mut bc = b;
        bc.merge(&c);
        let mut right = a;
        right.merge(&bc);

        prop_assert_eq!(left, right);
    }

    /// Слияние идемпотентно: повторное — и с самим собой — ничего не меняет.
    #[test]
    fn merge_is_idempotent(
        x in history(),
        y in history(),
    ) {
        let a = replay(&unfold(&x));
        let b = replay(&unfold(&y));

        let mut once = a.clone();
        once.merge(&b);

        let mut twice = once.clone();
        twice.merge(&b);
        prop_assert_eq!(&once, &twice, "повторное слияние изменило состояние");

        let mut with_self = once.clone();
        with_self.merge(&once.clone());
        prop_assert_eq!(&once, &with_self, "слияние с собой изменило состояние");
    }

    /// Слияние состояний равносильно проигрыванию обеих историй целиком.
    ///
    /// Без этого «догнать» отставший узел можно было бы только пересылкой всего
    /// журнала операций, а не состояния (§12, снапшот).
    #[test]
    fn merging_states_equals_replaying_both_logs(
        left in history(),
        right in history(),
    ) {
        let lops = unfold(&left);
        let rops = unfold(&right);

        let mut merged = replay(&lops);
        merged.merge(&replay(&rops));

        let mut all = lops;
        all.extend(rops);
        let replayed = replay(&all);

        prop_assert_eq!(members(&merged), members(&replayed));
    }

    /// Свёртка по общему триггеру не зависит от порядка доставки.
    ///
    /// §12 требует, чтобы снапшот делался по детерминированному условию,
    /// одинаковому у всех участников. Проверяется именно этот режим: свёртка
    /// у обоих узлов с одной границей и одним автором снапшота.
    #[test]
    fn compaction_commutes_with_delivery_order(
        actions in history(),
        swaps in prop::collection::vec(any::<u16>(), 0..80),
    ) {
        let ops = unfold(&actions);
        let mut straight = replay(&ops);
        let mut shuffled = replay(&permute(ops, &swaps));

        let baseline = Hlc::new(1_000, 0);
        straight.compact(baseline, actor(0));
        shuffled.compact(baseline, actor(0));

        prop_assert_eq!(&straight, &shuffled);

        // И снапшот остаётся неподвижной точкой слияния.
        let mut merged = straight.clone();
        merged.merge(&shuffled);
        prop_assert_eq!(&straight, &merged);
    }
}
