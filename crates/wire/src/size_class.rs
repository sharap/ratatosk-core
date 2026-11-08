//! Классы размера кадра (§5.5).
//!
//! Каждый кадр дополняется до размера своего класса, поэтому наблюдатель видит
//! только один из четырёх размеров. Несколько классов, а не один, —
//! сознательный компромисс спецификации: 4 КиБ на квитанцию о прочтении при
//! почтовом транспорте неприемлемы по трафику и батарее.
//!
//! Четвёртый класс (`XS`) заведён по замеру на живом устройстве: контроллер
//! BT 4.2 (RTL8723CS) принимал кадр в килобайт девять раз из десяти,
//! а кадр класса `S` — один раз из четырёх, и ни одна нарезка этого
//! не меняла. Разбор — в `XS`.

use crate::error::WireError;
use crate::header::{HEADER_LEN, TAG_LEN};
use crate::pad::PAD_MARKER_LEN;

/// Класс размера кадра.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SizeClass {
    /// 1 КиБ — рукопожатие, квитанции, короткие сообщения.
    ///
    /// # Почему он появился
    ///
    /// Замер на живом устройстве. Контроллер BT 4.2 (RTL8723CS, PinePhone)
    /// принимал кадр в килобайт **девять раз из десяти**, а кадр класса `S`
    /// — **один раз из четырёх**, и ни одна нарезка этого не меняла: семь
    /// пакетов по 672 байта не доехали ни разу, в том числе с тридцатью
    /// секундами ожидания. Без этого класса эфир на контроллерах BT 4.x
    /// не работает вовсе — ни рукопожатие, ни переписка.
    ///
    /// # Почему именно килобайт
    ///
    /// Снизу подпирает рукопожатие: оно несёт свою карточку целиком, Noise IK
    /// добавляет 96 байт, и полная карточка (onion, почта, имя, nostr с реле,
    /// ygg) даёт 427 байт сообщения. Накладные расходы кадра — 59 байт,
    /// поэтому 128 байт не вмещают даже пустую карточку, 256 — только
    /// пустую, а 512 оставляют двадцать шесть байт запаса при карточке,
    /// которая растёт. Килобайт даёт 965 байт нагрузки и меньше шести
    /// процентов накладных против двадцати трёх у 256 байт.
    XS,
    /// 4 КиБ — длинный текст, служебные сообщения, групповые блоки.
    S,
    /// 64 КиБ — превью, мелкие файлы, групповые блоки.
    M,
    /// 1 МиБ — чанки файлов.
    L,
}

impl SizeClass {
    /// Все классы по возрастанию. Порядок важен: [`SizeClass::smallest_for`]
    /// полагается на него.
    pub const ALL: [SizeClass; 4] = [SizeClass::XS, SizeClass::S, SizeClass::M, SizeClass::L];

    /// Полный размер кадра этого класса в байтах.
    #[must_use]
    pub const fn frame_len(self) -> usize {
        match self {
            SizeClass::XS => 1024,
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
        // Числа повторены руками, а не выведены из класса: это обещание
        // провода, и менять его вправе только спецификация.
        assert_eq!(SizeClass::XS.frame_len(), 1024);
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
        assert_eq!(SizeClass::smallest_for(0), Some(SizeClass::XS));
        assert_eq!(SizeClass::smallest_for(SizeClass::XS.max_payload()), Some(SizeClass::XS));
        assert_eq!(SizeClass::smallest_for(SizeClass::XS.max_payload() + 1), Some(SizeClass::S));
        assert_eq!(SizeClass::smallest_for(SizeClass::S.max_payload() + 1), Some(SizeClass::M));
        assert_eq!(SizeClass::smallest_for(SizeClass::M.max_payload() + 1), Some(SizeClass::L));
        assert_eq!(SizeClass::smallest_for(SizeClass::L.max_payload() + 1), None);
    }

    #[test]
    fn the_smallest_class_holds_a_handshake_with_a_full_card() {
        // **Это и есть нижняя граница класса, и она не от радио.**
        // Рукопожатие несёт свою карточку целиком, Noise IK добавляет
        // к ней 96 байт (`e`, зашифрованный статик, тег нагрузки),
        // а полная карточка — onion, почта, имя, nostr с реле, ygg —
        // занимает 331 байт. Итого 427.
        //
        // Числа повторены руками: возьми проверка их из кодека, и
        // разросшаяся карточка молча перестала бы влезать, а узнали бы
        // мы об этом на устройстве — рукопожатием, которое не проходит.
        const HANDSHAKE_WITH_FULL_CARD: usize = 96 + 331;
        assert!(
            SizeClass::XS.max_payload() >= HANDSHAKE_WITH_FULL_CARD,
            "в младший класс обязано влезать рукопожатие с полной карточкой: \
             {} против {HANDSHAKE_WITH_FULL_CARD}",
            SizeClass::XS.max_payload()
        );
        // И запас сверх него — не роскошь: карточка растёт (до трёх реле,
        // длинные имена). Полкилобайта запаса — то, чего не даёт класс
        // на 512 байт (там его двадцать шесть).
        assert!(
            SizeClass::XS.max_payload() - HANDSHAKE_WITH_FULL_CARD >= 512,
            "запас под рост карточки обязан остаться"
        );
    }

    #[test]
    fn from_frame_len_rejects_everything_else() {
        assert_eq!(SizeClass::from_frame_len(4096), Ok(SizeClass::S));
        assert!(SizeClass::from_frame_len(4095).is_err());
        assert!(SizeClass::from_frame_len(0).is_err());
        assert!(SizeClass::from_frame_len(usize::MAX).is_err());
    }
}
