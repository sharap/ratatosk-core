//! Гибридные логические часы (§9.1).
//!
//! `hlc` — источник порядка. Системное время источником порядка не является
//! никогда: клиент отбрасывает `wall_ms`, опережающий локальное более чем
//! на [`MAX_FUTURE_SKEW_MS`], и упорядочивает по `hlc → causal_refs → msg_id`.
//!
//! Реализация — классический HLC (Kulkarni et al.): физическая компонента
//! никогда не идёт назад, логическая растёт при совпадении физических.

use core::fmt;

/// Допустимое опережение локальных часов удалённым `wall_ms` — 5 минут (§9.1).
pub const MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;

/// Метка гибридных логических часов.
///
/// Порядок полей задаёт лексикографическое сравнение: сначала `wall_ms`,
/// затем `logical`. На этом держится производный `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hlc {
    /// Физическая компонента, миллисекунды Unix.
    pub wall_ms: u64,
    /// Логическая компонента — счётчик событий внутри одной миллисекунды.
    pub logical: u32,
}

impl Hlc {
    /// Метка с нулевой логической компонентой.
    #[must_use]
    pub const fn new(wall_ms: u64, logical: u32) -> Hlc {
        Hlc { wall_ms, logical }
    }

    /// Начало времён. Используется как baseline при compaction (§12).
    pub const ZERO: Hlc = Hlc { wall_ms: 0, logical: 0 };
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.wall_ms, self.logical)
    }
}

/// Отказ обработать удалённую метку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HlcError {
    /// Удалённая метка опережает локальные часы больше чем на
    /// [`MAX_FUTURE_SKEW_MS`].
    ///
    /// Сообщение отбрасывается: иначе один клиент со сломанными часами
    /// (или злонамеренный) навсегда утащил бы часы всей группы в будущее.
    ClockSkew {
        /// `wall_ms` из удалённой метки.
        remote_wall_ms: u64,
        /// Локальное физическое время на момент проверки.
        local_wall_ms: u64,
    },
    /// Логическая компонента переполнилась внутри одной миллисекунды.
    ///
    /// Практически недостижимо (нужно 2^32 событий за миллисекунду), но
    /// молчаливое заворачивание сломало бы монотонность, поэтому — ошибка.
    LogicalOverflow,
}

impl fmt::Display for HlcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HlcError::ClockSkew { remote_wall_ms, local_wall_ms } => write!(
                f,
                "метка из будущего: удалённое время {remote_wall_ms} против локального {local_wall_ms}"
            ),
            HlcError::LogicalOverflow => write!(f, "переполнение логической компоненты HLC"),
        }
    }
}

impl std::error::Error for HlcError {}

/// Состояние гибридных часов узла.
///
/// Физическое время не читается внутри — оно передаётся аргументом. Благодаря
/// этому симуляция (§16) прогоняет неделю разделения сети за миллисекунды.
#[derive(Debug, Clone, Copy, Default)]
pub struct HlcClock {
    last: Hlc,
}

impl HlcClock {
    /// Часы, стартующие с нуля.
    #[must_use]
    pub const fn new() -> HlcClock {
        HlcClock { last: Hlc::ZERO }
    }

    /// Часы, восстановленные из хранилища после перезапуска.
    ///
    /// Последнюю выданную метку обязательно сохранять: без этого после
    /// перезапуска с отставшими системными часами узел выдаст метки, которые
    /// уже использовал.
    #[must_use]
    pub const fn resume(last: Hlc) -> HlcClock {
        HlcClock { last }
    }

    /// Последняя выданная или принятая метка.
    #[must_use]
    pub const fn last(&self) -> Hlc {
        self.last
    }

    /// Метка для локального события.
    pub fn now(&mut self, physical_ms: u64) -> Result<Hlc, HlcError> {
        let next = if physical_ms > self.last.wall_ms {
            Hlc::new(physical_ms, 0)
        } else {
            // Физические часы стоят или откатились назад — растим логическую
            // компоненту, физическую не трогаем.
            Hlc::new(
                self.last.wall_ms,
                self.last.logical.checked_add(1).ok_or(HlcError::LogicalOverflow)?,
            )
        };
        self.last = next;
        Ok(next)
    }

    /// Метка для приёма удалённого события.
    ///
    /// Возвращает ошибку, если удалённая метка слишком далеко в будущем —
    /// сообщение в этом случае отбрасывается, а состояние часов не меняется.
    pub fn observe(&mut self, physical_ms: u64, remote: Hlc) -> Result<Hlc, HlcError> {
        if remote.wall_ms > physical_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(HlcError::ClockSkew {
                remote_wall_ms: remote.wall_ms,
                local_wall_ms: physical_ms,
            });
        }

        let wall = physical_ms.max(self.last.wall_ms).max(remote.wall_ms);
        let logical = if wall == self.last.wall_ms && wall == remote.wall_ms {
            self.last.logical.max(remote.logical).checked_add(1).ok_or(HlcError::LogicalOverflow)?
        } else if wall == self.last.wall_ms {
            self.last.logical.checked_add(1).ok_or(HlcError::LogicalOverflow)?
        } else if wall == remote.wall_ms {
            remote.logical.checked_add(1).ok_or(HlcError::LogicalOverflow)?
        } else {
            0
        };

        let next = Hlc::new(wall, logical);
        self.last = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_events_are_strictly_increasing() {
        let mut c = HlcClock::new();
        let mut prev = Hlc::ZERO;
        // Физическое время то стоит, то откатывается — метки всё равно растут.
        for physical in [10u64, 10, 10, 9, 8, 11, 11, 100] {
            let now = c.now(physical).unwrap();
            assert!(now > prev, "{now} должно быть больше {prev}");
            prev = now;
        }
    }

    #[test]
    fn frozen_clock_grows_logical_only() {
        let mut c = HlcClock::new();
        assert_eq!(c.now(5).unwrap(), Hlc::new(5, 0));
        assert_eq!(c.now(5).unwrap(), Hlc::new(5, 1));
        assert_eq!(c.now(5).unwrap(), Hlc::new(5, 2));
    }

    #[test]
    fn backwards_physical_clock_does_not_move_hlc_back() {
        let mut c = HlcClock::new();
        c.now(1_000).unwrap();
        let after = c.now(500).unwrap();
        assert_eq!(after.wall_ms, 1_000);
        assert_eq!(after.logical, 1);
    }

    #[test]
    fn receive_adopts_remote_future_within_tolerance() {
        let mut c = HlcClock::new();
        let remote = Hlc::new(2_000, 7);
        let got = c.observe(1_000, remote).unwrap();
        assert_eq!(got, Hlc::new(2_000, 8));
        assert!(got > remote, "принятая метка должна доминировать над удалённой");
    }

    #[test]
    fn receive_rejects_far_future() {
        let mut c = HlcClock::new();
        let remote = Hlc::new(MAX_FUTURE_SKEW_MS + 1_001, 0);
        assert!(matches!(c.observe(1_000, remote), Err(HlcError::ClockSkew { .. })));
        // Состояние часов не должно испортиться отброшенным сообщением.
        assert_eq!(c.last(), Hlc::ZERO);
    }

    #[test]
    fn boundary_of_skew_window_is_accepted() {
        let mut c = HlcClock::new();
        let remote = Hlc::new(1_000 + MAX_FUTURE_SKEW_MS, 0);
        assert!(c.observe(1_000, remote).is_ok());
    }

    #[test]
    fn causality_survives_a_round_trip() {
        // a → b → a: каждое следующее событие больше всех предыдущих.
        let mut a = HlcClock::new();
        let mut b = HlcClock::new();

        let m1 = a.now(100).unwrap();
        let m2 = b.observe(50, m1).unwrap(); // у b часы отстают
        let m3 = b.now(50).unwrap();
        let m4 = a.observe(101, m3).unwrap();

        assert!(m1 < m2 && m2 < m3 && m3 < m4);
    }

    #[test]
    fn resume_preserves_monotonicity_across_restart() {
        let mut c = HlcClock::new();
        c.now(1_000).unwrap();
        let saved = c.last();

        // Перезапуск, системные часы отстали на минуту.
        let mut restarted = HlcClock::resume(saved);
        assert!(restarted.now(940).unwrap() > saved);
    }

    #[test]
    fn ordering_is_lexicographic() {
        assert!(Hlc::new(1, 5) < Hlc::new(2, 0));
        assert!(Hlc::new(1, 0) < Hlc::new(1, 1));
        assert_eq!(Hlc::new(3, 3), Hlc::new(3, 3));
    }
}
