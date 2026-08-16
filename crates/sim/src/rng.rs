//! Детерминированный генератор псевдослучайных чисел (xoshiro256**).
//!
//! Собственная реализация здесь оправдана ровно потому, почему §8.1 запрещает
//! собственные криптопримитивы: это **не** криптография. Генератор нужен, чтобы
//! расхождение воспроизводилось по номеру сида на любой машине и в любой
//! версии зависимостей. Для ключевого материала используется CSPRNG из
//! `ratatosk-crypto`, и никогда — этот код.

/// Генератор, полностью определяемый сидом.
#[derive(Debug, Clone)]
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    /// Создаёт генератор из 64-битного сида.
    ///
    /// Номер сида — единственное, что нужно записать в отчёт о падении, чтобы
    /// прогон повторился байт в байт (§16).
    #[must_use]
    pub fn from_seed(seed: u64) -> Rng {
        let mut z = seed;
        let mut next = || {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            x ^ (x >> 31)
        };
        Rng { s: [next(), next(), next(), next()] }
    }

    /// Следующее 64-битное значение.
    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;

        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);

        result
    }

    /// Равномерное значение в `[0, n)`. При `n == 0` возвращает 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Отбраковка по модулю: смещение исключено, а лишние итерации
        // детерминированы, то есть воспроизводимости не мешают.
        let zone = u64::MAX - (u64::MAX % n) - 1;
        loop {
            let v = self.next_u64();
            if v <= zone {
                return v % n;
            }
        }
    }

    /// Равномерное значение в `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// `true` с вероятностью `permille / 1000`.
    pub fn chance_permille(&mut self, permille: u32) -> bool {
        if permille == 0 {
            return false;
        }
        if permille >= 1000 {
            return true;
        }
        self.below(1000) < u64::from(permille)
    }

    /// Заполняет буфер псевдослучайными байтами.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    /// Перемешивание на месте (Фишер — Йетс).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below((i + 1) as u64) as usize;
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::from_seed(42);
        let mut b = Rng::from_seed(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::from_seed(1);
        let mut b = Rng::from_seed(2);
        let differs = (0..64).any(|_| a.next_u64() != b.next_u64());
        assert!(differs);
    }

    #[test]
    fn below_respects_bound() {
        let mut r = Rng::from_seed(7);
        for _ in 0..10_000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(1), 0);
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn range_is_inclusive_and_safe() {
        let mut r = Rng::from_seed(9);
        for _ in 0..10_000 {
            let v = r.range(5, 9);
            assert!((5..=9).contains(&v));
        }
        assert_eq!(r.range(3, 3), 3);
        assert_eq!(r.range(9, 3), 9);
    }

    #[test]
    fn chance_edges_are_absolute() {
        let mut r = Rng::from_seed(11);
        for _ in 0..100 {
            assert!(!r.chance_permille(0));
            assert!(r.chance_permille(1000));
            assert!(r.chance_permille(5000));
        }
    }

    #[test]
    fn chance_is_roughly_calibrated() {
        let mut r = Rng::from_seed(13);
        let hits = (0..100_000).filter(|_| r.chance_permille(250)).count();
        assert!((24_000..26_000).contains(&hits), "получено {hits}");
    }

    #[test]
    fn fill_handles_ragged_tail() {
        let mut r = Rng::from_seed(3);
        let mut buf = [0u8; 13];
        r.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut r = Rng::from_seed(5);
        let mut v: Vec<u32> = (0..64).collect();
        r.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..64).collect::<Vec<_>>());
        assert_ne!(v, sorted, "перемешивание должно что-то менять");
    }
}
