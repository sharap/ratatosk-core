//! Источник случайности для ядра.
//!
//! Ядро sans-io, а случайность — такой же внешний мир, как часы и сокеты.
//! Если брать её из `OsRng` прямо в `step`, симуляция перестаёт быть
//! воспроизводимой по сиду, а §16 требует ровно обратного.
//!
//! Что это покрывает и чего не покрывает, стоит сказать прямо. `msg_id`
//! отсюда — и это важно: §9.1 упорядочивает сообщения по
//! `hlc → causal_refs → msg_id`, то есть идентификатор участвует в разрешении
//! одновременности, и случайный `msg_id` менял бы порядок показа от прогона
//! к прогону. А вот эфемерные ключи Noise берутся внутри `snow` из `OsRng`,
//! и сюда не приходят: полная воспроизводимость рукопожатий потребует
//! собственного резолвера `snow` (см. TESTING.md).

/// Откуда ядро берёт случайные байты.
pub trait Entropy: Send {
    /// Заполняет буфер.
    fn fill(&mut self, buf: &mut [u8]);

    /// Шестнадцать байт идентификатора сообщения (§9.1).
    fn msg_id(&mut self) -> [u8; 16] {
        let mut id = [0u8; 16];
        self.fill(&mut id);
        id
    }
}

/// Системный CSPRNG — то, что работает в продукте.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(buf);
    }
}

/// Детерминированный источник для симуляции и тестов.
///
/// Тот же xoshiro256\*\*, что в харнессе, но заведён отдельно: смешивать
/// поток узла с потоком сети значило бы, что правка сетевого профиля сдвигает
/// идентификаторы сообщений.
#[derive(Debug, Clone)]
pub struct SeededEntropy {
    state: [u64; 4],
}

impl SeededEntropy {
    /// Создаёт источник из сида.
    #[must_use]
    pub fn new(seed: u64) -> SeededEntropy {
        let mut z = seed;
        let mut next = || {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        SeededEntropy { state: [next(), next(), next(), next()] }
    }

    fn next_u64(&mut self) -> u64 {
        let s = &mut self.state;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }
}

impl Entropy for SeededEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_entropy_is_reproducible() {
        let mut a = SeededEntropy::new(42);
        let mut b = SeededEntropy::new(42);
        for _ in 0..100 {
            assert_eq!(a.msg_id(), b.msg_id());
        }
    }

    #[test]
    fn different_seeds_give_different_ids() {
        let mut a = SeededEntropy::new(1);
        let mut b = SeededEntropy::new(2);
        assert_ne!(a.msg_id(), b.msg_id());
    }

    #[test]
    fn ids_do_not_repeat_within_a_run() {
        let mut e = SeededEntropy::new(7);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(e.msg_id()), "msg_id повторился — дедупликация съест сообщение");
        }
    }

    #[test]
    fn os_entropy_produces_distinct_ids() {
        let mut e = OsEntropy;
        assert_ne!(e.msg_id(), e.msg_id());
    }
}
