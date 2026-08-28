//! Достать одно строковое поле из маленького JSON (§5.3).
//!
//! # Почему не `serde_json`
//!
//! Разбирать надо ровно один ответ: `{"email": "...", "password": "..."}`.
//! Полный разборщик JSON вместе с `serde` — это две заметные зависимости
//! в дереве, где каждая объяснена (§8.1), ради двух строк.
//!
//! # И почему это не «свой разборщик JSON»
//!
//! Его здесь нет и не будет. Это **поиск поля**, а не разбор документа:
//! функция находит ключ верхнего уровня и читает следующую за ним строку
//! по правилам JSON — с экранированием, потому что пароль имеет полное
//! право содержать кавычку или обратную косую.
//!
//! Отсюда честные ограничения, и они не мешают задаче:
//!
//! * вложенность не поддержана — ключ с тем же именем внутри объекта нашёлся
//!   бы наравне с верхним. Chatmail-серверы отвечают плоским объектом;
//! * числа, `true`, `null` в качестве значения не читаются: нам нужны
//!   строки, всё прочее означает, что ответ не тот;
//! * `\uXXXX` разворачивается, суррогатные пары — нет. В адресе и пароле
//!   им взяться неоткуда, а тихо склеить пару неверно — хуже, чем не понять.
//!
//! Если однажды понадобится разбирать что-то сложнее, правильный ход —
//! взять готовый разборщик, а не дописывать этот.

/// Значение строкового поля верхнего уровня.
///
/// Возвращает `None`, если ключа нет, значение не строка или строка
/// оборвана. Отличать эти случаи вызывающему незачем: во всех трёх ответ
/// сервера не тот, и сказать человеку надо одно и то же.
#[must_use]
pub fn field(json: &str, name: &str) -> Option<String> {
    let bytes = json.as_bytes();
    let quoted = format!("\"{name}\"");
    let mut from = 0;
    while let Some(at) = json[from..].find(&quoted) {
        let key_end = from + at + quoted.len();
        from = key_end;
        // За ключом обязано идти двоеточие: иначе это не ключ, а совпадение
        // внутри чужого значения — например, пароль, содержащий "email".
        let after_colon = match skip_spaces(bytes, key_end) {
            Some(pos) if bytes.get(pos) == Some(&b':') => pos + 1,
            _ => continue,
        };
        let Some(value_start) = skip_spaces(bytes, after_colon) else { continue };
        if bytes.get(value_start) != Some(&b'"') {
            // Значение не строка — читать нечего. Продолжать поиск незачем:
            // ключ найден, и он не тот, что нам нужен.
            return None;
        }
        return unescape(&json[value_start + 1..]);
    }
    None
}

/// Первая позиция не-пробела, начиная с `from`.
fn skip_spaces(bytes: &[u8], from: usize) -> Option<usize> {
    (from..bytes.len()).find(|at| !bytes[*at].is_ascii_whitespace())
}

/// Читает строку JSON от начала до закрывающей кавычки.
fn unescape(rest: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => {
                let escaped = chars.next()?;
                match escaped {
                    '"' | '\\' | '/' => out.push(escaped),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        let code = u32::from_str_radix(&hex, 16).ok()?;
                        // Суррогат в одиночку — не символ. Склеить пару мы
                        // не умеем и делать вид не станем.
                        out.push(char::from_u32(code)?);
                    }
                    // Неизвестное экранирование означает, что это не JSON.
                    _ => return None,
                }
            }
            c => out.push(c),
        }
    }
    // Строка кончилась, а кавычки не было: ответ оборван.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_field_is_found() {
        let json = "{\"email\":\"a@b.cd\",\"password\":\"sekret\"}";
        assert_eq!(field(json, "email").as_deref(), Some("a@b.cd"));
        assert_eq!(field(json, "password").as_deref(), Some("sekret"));
        assert_eq!(field(json, "token"), None);
    }

    #[test]
    fn spaces_around_the_colon_do_not_matter() {
        let json = "{\n  \"email\" :   \"a@b.cd\"\n}";
        assert_eq!(field(json, "email").as_deref(), Some("a@b.cd"));
    }

    #[test]
    fn a_password_may_contain_a_quote() {
        // Сервер вправе выдать что угодно, и экранированная кавычка в пароле
        // — не экзотика, а обычный случайный набор символов.
        let json = "{\"password\":\"a\\\"b\\\\c\"}";
        assert_eq!(field(json, "password").as_deref(), Some("a\"b\\c"));
    }

    #[test]
    fn an_escape_sequence_is_unfolded() {
        let json = "{\"password\":\"\\u0041\\n\\t\"}";
        assert_eq!(field(json, "password").as_deref(), Some("A\n\t"));
    }

    #[test]
    fn a_key_inside_a_value_is_not_a_key() {
        // Пароль, содержащий чужое имя поля, — ровно тот случай, ради
        // которого проверяется двоеточие после ключа.
        let json = "{\"password\":\"\\\"email\\\" is not here\",\"email\":\"a@b.cd\"}";
        assert_eq!(field(json, "email").as_deref(), Some("a@b.cd"));
    }

    #[test]
    fn a_value_that_is_not_a_string_is_not_guessed_at() {
        assert_eq!(field("{\"email\":42}", "email"), None);
        assert_eq!(field("{\"email\":null}", "email"), None);
    }

    #[test]
    fn a_truncated_answer_is_refused() {
        // Обрыв на середине пароля дал бы ящик, в который не войти.
        assert_eq!(field("{\"password\":\"половина", "password"), None);
        assert_eq!(field("{\"password\":\"конец\\", "password"), None);
    }

    #[test]
    fn a_lone_surrogate_is_refused_rather_than_glued() {
        assert_eq!(field("{\"password\":\"\\ud83d\"}", "password"), None);
    }
}
