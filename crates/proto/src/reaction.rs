//! Реакция на сообщение — эмодзи вместо ответа.
//!
//! **Спецификация v0.1 этого не описывает.** Дополнение, и §17 просит такие
//! вещи называть отдельно.
//!
//! # Одна реакция от человека
//!
//! Новая заменяет прежнюю, пустая строка снимает. Так устроено не для
//! простоты кода, а потому что множество реакций от одного человека — это
//! множество кадров на пустяк: каждый со своим паддингом до класса размера
//! (§5.5), каждый со своей записью в очереди §5.4. Одна реакция — одно
//! состояние, и правило слияния тогда состоит из одной строки: кто позже
//! по HLC (§9.1), тот и прав.
//!
//! Порядок сравнивается по метке, а не по приходу: реакция законно приезжает
//! с опозданием (§9.2), и «последняя пришедшая» затирала бы свежую старой.
//!
//! # Почему не фиксированный набор
//!
//! Список из шести смайликов пришлось бы держать одинаковым в ядре, в Kotlin
//! и в спецификации, а первый же клиент с седьмым смайликом стал бы
//! несовместимым молча. Едет строка — и совместимость сводится к её длине.
//!
//! # Проверка — предел, а не вкус
//!
//! Настоящее ограничение здесь одно: [`MAX_REACTION_BYTES`]. Оно и мешает
//! превратить реакцию в канал для текста, то есть в способ прислать
//! сообщение, которое не выглядит сообщением.
//!
//! Проверка «похоже на эмодзи» — **эвристика, и называется так честно**:
//! таблиц свойств Unicode в ядре нет, тащить их сюда ради смайлика незачем,
//! а Unicode пополняется быстрее, чем обновляются приложения. Отвергается
//! то, что заведомо не реакция — латиница, цифры сами по себе, пробелы,
//! управляющие символы; всё остальное принимается. Ошибка эвристики в сторону
//! «принять» стоит одного странного символа на экране, в сторону «отвергнуть»
//! — работающей у собеседника функции, которая у нас молча отказала.

use ratatosk_codec::{canonical, CodecError, Value};
use ratatosk_crdt::MsgId;

/// Ключ идентификатора сообщения, к которому относится реакция.
const KEY_TARGET: u64 = 1;
/// Ключ строки реакции.
const KEY_EMOJI: u64 = 2;

/// Наибольшая длина реакции в байтах.
///
/// Тридцать два байта — это семейный эмодзи со всеми соединителями и
/// модификаторами тона кожи (самые длинные из ходовых — около двадцати пяти).
/// И это заведомо мало для сообщения: реакция не должна становиться способом
/// прислать текст в обход показа сообщения.
pub const MAX_REACTION_BYTES: usize = 32;

/// Наибольшая длина реакции в кодовых точках.
///
/// Предел в байтах сам по себе разрешил бы тридцать две буквы латиницы;
/// этот — не разрешает. Восемь точек хватает на составной эмодзи с двумя
/// модификаторами и соединителями.
pub const MAX_REACTION_CHARS: usize = 8;

/// Почему реакция не принята.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReactionError {
    /// Длиннее [`MAX_REACTION_BYTES`] или [`MAX_REACTION_CHARS`].
    #[error("реакция длиннее {MAX_REACTION_BYTES} байт")]
    TooLong,
    /// На эмодзи не похоже: латиница, пробелы, управляющие символы.
    #[error("реакция должна быть эмодзи")]
    NotAnEmoji,
}

/// Проверяет строку реакции.
///
/// Пустая строка законна и означает «снять свою реакцию»: отдельного
/// представления для снятия нет намеренно — по проводу это такое же
/// состояние, как и любое другое, а второе представление того же самого
/// однажды разошлось бы с первым.
///
/// # Errors
///
/// [`ReactionError::TooLong`] или [`ReactionError::NotAnEmoji`].
pub fn check(emoji: &str) -> Result<(), ReactionError> {
    if emoji.is_empty() {
        return Ok(());
    }
    if emoji.len() > MAX_REACTION_BYTES || emoji.chars().count() > MAX_REACTION_CHARS {
        return Err(ReactionError::TooLong);
    }
    if !looks_like_emoji(emoji) {
        return Err(ReactionError::NotAnEmoji);
    }
    Ok(())
}

/// Эвристика «это эмодзи, а не текст».
///
/// Два условия. Ни одного ASCII-символа, кроме цифр и `#`, `*` — эти три
/// встречаются в клавишных эмодзи вида `1️⃣`, но только вместе с
/// не-ASCII частью. И хотя бы одна не-ASCII кодовая точка — иначе цифры
/// прошли бы сами по себе.
///
/// Что это **не** проверяет: что перед нами один эмодзи, что он существует
/// в Unicode и что он вообще отобразится. Для этого нужны таблицы свойств,
/// которых в ядре нет, — см. заголовок модуля.
#[must_use]
pub fn looks_like_emoji(emoji: &str) -> bool {
    let mut has_wide = false;
    for ch in emoji.chars() {
        if ch.is_ascii() {
            if !ch.is_ascii_digit() && ch != '#' && ch != '*' {
                return false;
            }
        } else {
            has_wide = true;
        }
    }
    has_wide
}

/// Собирает полезную нагрузку реакции.
#[must_use]
pub fn payload(target: MsgId, emoji: &str) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_TARGET.into()), Value::Bytes(target.to_vec())),
        (Value::Integer(KEY_EMOJI.into()), Value::Text(emoji.to_owned())),
    ])
}

/// Разбирает полезную нагрузку реакции.
///
/// Строка приходит от собеседника, поэтому проверяется здесь же: принять
/// её без проверки значило бы записать в базу то, чего сами не отправили бы.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`], если структура не та или строка не прошла
/// [`check`].
pub fn from_payload(value: &Value) -> Result<(MsgId, String), CodecError> {
    let map = canonical::as_map(value)?;
    let target = canonical::as_array::<16>(canonical::require(map, KEY_TARGET)?)?;
    let Value::Text(emoji) = canonical::require(map, KEY_EMOJI)? else {
        return Err(CodecError::TypeMismatch);
    };
    if check(emoji).is_err() {
        return Err(CodecError::TypeMismatch);
    }
    Ok((target, emoji.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reaction_round_trips() {
        let (target, emoji) = from_payload(&payload([3u8; 16], "❤")).unwrap();
        assert_eq!(target, [3u8; 16]);
        assert_eq!(emoji, "❤");
    }

    #[test]
    fn an_empty_reaction_means_take_mine_back() {
        assert_eq!(check(""), Ok(()));
        let (_, emoji) = from_payload(&payload([1u8; 16], "")).unwrap();
        assert!(emoji.is_empty(), "снятие — такое же состояние, как и любое другое");
    }

    #[test]
    fn a_reaction_cannot_carry_text() {
        // Главное, ради чего здесь вообще есть проверка: реакция не должна
        // становиться способом прислать сообщение мимо показа сообщения.
        assert_eq!(check("привет, это я"), Err(ReactionError::TooLong));
        assert_eq!(check("ok"), Err(ReactionError::NotAnEmoji));
        assert_eq!(check(" "), Err(ReactionError::NotAnEmoji));
        assert_eq!(check("\u{7}"), Err(ReactionError::NotAnEmoji));
        // Восемь букв укладываются в предел байтов — и обязаны не пройти
        // по пределу кодовых точек и по эвристике.
        assert!(check("abcdefgh").is_err());
    }

    #[test]
    fn composite_emoji_fit() {
        // Самые длинные из ходовых: семья с соединителями и тон кожи.
        for emoji in ["👍", "👍🏽", "👨‍👩‍👧‍👦", "🇷🇺", "1️⃣"] {
            assert_eq!(check(emoji), Ok(()), "не прошло: {emoji}");
        }
    }

    #[test]
    fn a_digit_alone_is_not_a_reaction() {
        // Цифры разрешены только в компании не-ASCII части: без неё это текст.
        assert_eq!(check("1"), Err(ReactionError::NotAnEmoji));
    }
}
