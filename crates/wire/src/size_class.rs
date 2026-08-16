//! Классы размера кадра (§5.5).
//!
//! Каждый кадр дополняется до размера своего класса, поэтому наблюдатель видит
//! только один из трёх размеров. Три класса, а не один, — сознательный
//! компромисс спецификации: 4 КиБ на квитанцию о прочтении при почтовом
//! транспорте неприемлемы по трафику и батарее.

use crate::error::WireError;
use crate::header::{HEADER_LEN, TAG_LEN};
use crate::pad::PAD_MARKER_LEN;

/// Класс размера кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SizeClass {
    /// 4 КиБ — текст, служебные сообщения, квитанции.
    S,
    /// 64 КиБ — превью, мелкие файлы, групповые блоки.
    M,
    /// 1 МиБ — чанки файлов.
    L,
}

impl SizeClass {
    /// Все классы по возрастанию. Порядок важен: [`SizeClass::smallest_for`]
    /// полагается на него.
    pub const ALL: [SizeClass; 3] = [SizeClass::S, SizeClass::M, SizeClass::L];

    /// Полный размер кадра этого класса в байтах.
    #[must_use]
    pub const fn frame_len(self) -> usize {
        match self {
            SizeClass::S => 4 * 1024,
            SizeClass::M => 64 * 1024,
            SizeClass::L => 1024 * 1024,
        }
    }

    /// Длина запечатанной части — шифротекст вместе с тегом AEAD.
    #[must_use]
    pub const fn sealed_len(self) -> usize {
        self.frame_len() - HEADER_LEN
    }

    /// Длина открытого текста до шифрования: полезная нагрузка плюс паддинг.
    #[must_use]
    pub const fn plaintext_len(self) -> usize {
        self.sealed_len() - TAG_LEN
    }

    /// Наибольшая полезная нагрузка, помещающаяся в класс.
    ///
    /// На один байт меньше открытого текста: маркер паддинга `0x80`
    /// присутствует всегда, даже когда нулевых байтов после него нет (§7.2).
    #[must_use]
    pub const fn max_payload(self) -> usize {
        self.plaintext_len() - PAD_MARKER_LEN
    }

    /// Наименьший класс, вмещающий полезную нагрузку такой длины.
    ///
    /// `None` означает, что нагрузку надо фрагментировать (§9.3).
    #[must_use]
    pub fn smallest_for(payload_len: usize) -> Option<SizeClass> {
        SizeClass::ALL.into_iter().find(|c| payload_len <= c.max_payload())
    }

    /// Класс по фактической длине полученных байтов.
    ///
    /// Первая проверка на приёме (§7.3, шаг 1).
    pub fn from_frame_len(len: usize) -> Result<SizeClass, WireError> {
        SizeClass::ALL
            .into_iter()
            .find(|c| c.frame_len() == len)
            .ok_or(WireError::BadFrameLength { got: len })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_lengths_match_spec() {
        assert_eq!(SizeClass::S.frame_len(), 4096);
        assert_eq!(SizeClass::M.frame_len(), 65536);
        assert_eq!(SizeClass::L.frame_len(), 1048576);
    }

    #[test]
    fn classes_are_ordered_ascending() {
        // На этом порядке держится smallest_for.
        let mut prev = 0;
        for c in SizeClass::ALL {
            assert!(c.frame_len() > prev);
            prev = c.frame_len();
        }
    }

    #[test]
    fn layout_adds_up() {
        for c in SizeClass::ALL {
            assert_eq!(c.frame_len(), HEADER_LEN + c.plaintext_len() + TAG_LEN);
            assert_eq!(c.max_payload() + PAD_MARKER_LEN, c.plaintext_len());
        }
    }

    #[test]
    fn smallest_for_picks_the_smallest() {
        assert_eq!(SizeClass::smallest_for(0), Some(SizeClass::S));
        assert_eq!(SizeClass::smallest_for(SizeClass::S.max_payload()), Some(SizeClass::S));
        assert_eq!(SizeClass::smallest_for(SizeClass::S.max_payload() + 1), Some(SizeClass::M));
        assert_eq!(SizeClass::smallest_for(SizeClass::M.max_payload() + 1), Some(SizeClass::L));
        assert_eq!(SizeClass::smallest_for(SizeClass::L.max_payload() + 1), None);
    }

    #[test]
    fn from_frame_len_rejects_everything_else() {
        assert_eq!(SizeClass::from_frame_len(4096), Ok(SizeClass::S));
        assert!(SizeClass::from_frame_len(4095).is_err());
        assert!(SizeClass::from_frame_len(0).is_err());
        assert!(SizeClass::from_frame_len(usize::MAX).is_err());
    }
}
