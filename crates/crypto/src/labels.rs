//! Контексты `BLAKE3_derive_key` — все в одном месте.
//!
//! Каждая строка встречается в спецификации ровно один раз и здесь ровно один
//! раз. Причина держать их вместе, а не по месту использования: совпадение
//! двух контекстов даёт совпадение независимых ключей, и такую ошибку не
//! ловит ни один тест, кроме теста на уникальность самих строк — он ниже.
//!
//! Менять строку задним числом нельзя: она входит в вывод ключей, то есть
//! в совместимость на проводе. Новое назначение — новая строка.

/// §3: долговременный X25519 из общего seed.
pub const IK: &str = "ratatosk v0 ik";
/// §3: долговременный Ed25519 из общего seed.
pub const SK: &str = "ratatosk v0 sk";

/// §5.1: ротируемый маяк mDNS.
pub const BEACON: &str = "ratatosk v0 beacon";

/// §8.3: идентификатор сессии из транскрипта Noise.
pub const SESSION_ID: &str = "ratatosk v0 sid";
/// §8.3: корневой ключ сессии.
pub const ROOT: &str = "ratatosk v0 root";
/// §8.3: цепочка инициатора.
pub const CHAIN_A: &str = "ratatosk v0 chain-a";
/// §8.3: цепочка получателя.
pub const CHAIN_B: &str = "ratatosk v0 chain-b";

/// §8.4: ключ сообщения из состояния цепочки.
pub const MSG: &str = "ratatosk v0 msg";
/// §8.4: шаг цепочки.
pub const CHAIN: &str = "ratatosk v0 chain";

/// §10.1: идентификатор чанка файла.
pub const FILE: &str = "ratatosk v0 file";

/// §11.1: шаг sender-цепочки в группе.
pub const SENDER_CHAIN: &str = "ratatosk v0 sender-chain";
/// §11.1: ключ группового сообщения.
pub const SENDER_MSG: &str = "ratatosk v0 sender-msg";

/// §12: токен поискового индекса из `db_key` и слова.
///
/// В индексе лежат не слова, а их хэши на ключе базы: полнотекстовый индекс
/// по открытым телам свёл бы `body_enc` к декорации — файл базы отдал бы
/// всю переписку тому, у кого нет PIN.
pub const SEARCH_TOKEN: &str = "ratatosk v0 search-token";

/// Все контексты — для теста уникальности и для тест-векторов.
pub const ALL: [&str; 13] = [
    IK,
    SK,
    BEACON,
    SESSION_ID,
    ROOT,
    CHAIN_A,
    CHAIN_B,
    MSG,
    CHAIN,
    FILE,
    SENDER_CHAIN,
    SENDER_MSG,
    SEARCH_TOKEN,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn contexts_are_unique() {
        let set: HashSet<&&str> = ALL.iter().collect();
        assert_eq!(set.len(), ALL.len(), "два назначения делят один контекст деривации");
    }

    #[test]
    fn contexts_are_namespaced_and_versioned() {
        // Префикс с версией нужен, чтобы v1 не смог случайно вывести те же
        // ключи, что v0, если строку скопируют в новый код.
        for c in ALL {
            assert!(c.starts_with("ratatosk v0 "), "контекст без версии: {c}");
        }
    }

    #[test]
    fn similar_names_denote_different_things() {
        // §8.3 и §8.4 дали похожие имена разным вещам: CHAIN_A/CHAIN_B — это
        // начальные состояния цепочек сессии, а CHAIN — шаг ретчета внутри
        // цепочки. Спутать их в коде легко, и `labels::CHAIN` вместо
        // `labels::CHAIN_A` даст рабочий, но несовместимый клиент.
        //
        // Криптографической опасности в префиксности нет: `derive_key`
        // хеширует контекст целиком (доказательство — тест
        // `kdf::tests::prefix_related_contexts_are_independent`). Поэтому
        // здесь фиксируется только то, что имена различны и что их сходство
        // осознано, а не случайно.
        assert_ne!(CHAIN, CHAIN_A);
        assert_ne!(CHAIN, CHAIN_B);
        assert!(CHAIN_A.starts_with(CHAIN), "имена из §8.3 и §8.4 родственны по построению");
    }
}
