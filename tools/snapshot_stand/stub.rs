// Заглушки кодека, сохраняющие ровно то свойство, ради которого нужен
// круговой тест: канонизацию — сортировку ключей и отказ на повторах (§6).
#![allow(dead_code)]

pub type MsgId = [u8; 16];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Bool(bool),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    TypeMismatch,
    MissingField,
    DuplicateKey,
    NotAMap,
}
impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CodecError {}

pub mod canonical {
    use super::{CodecError, Value};

    /// Кодирование: сортирует ключи и отвергает повторы — то же, что делает
    /// настоящий детерминированный CBOR (§6).
    pub fn encode(value: &Value) -> Result<Vec<u8>, CodecError> {
        let sorted = canonicalize(value)?;
        Ok(format!("{sorted:?}").into_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Value, CodecError> {
        let text = core::str::from_utf8(bytes).map_err(|_| CodecError::TypeMismatch)?;
        parse(&mut text.chars().peekable())
    }

    fn canonicalize(value: &Value) -> Result<Value, CodecError> {
        Ok(match value {
            Value::Map(entries) => {
                let mut keys: Vec<i128> = Vec::new();
                let mut out: Vec<(Value, Value)> = Vec::new();
                for (k, v) in entries {
                    let Value::Integer(n) = k else { return Err(CodecError::TypeMismatch) };
                    if keys.contains(n) {
                        return Err(CodecError::DuplicateKey);
                    }
                    keys.push(*n);
                    out.push((k.clone(), canonicalize(v)?));
                }
                out.sort_by_key(|(k, _)| match k {
                    Value::Integer(n) => *n,
                    _ => 0,
                });
                Value::Map(out)
            }
            Value::Array(items) => {
                Value::Array(items.iter().map(canonicalize).collect::<Result<_, _>>()?)
            }
            other => other.clone(),
        })
    }

    // Разбор отладочного представления — грубо, но достаточно: проверяется
    // не формат, а то, что собранное значение разбирается обратно в то же.
    fn parse(it: &mut core::iter::Peekable<core::str::Chars<'_>>) -> Result<Value, CodecError> {
        skip_ws(it);
        let head: String = take_ident(it);
        match head.as_str() {
            "Integer" => {
                expect(it, '(')?;
                let n = take_while(it, |c| c != ')');
                expect(it, ')')?;
                Ok(Value::Integer(n.trim().parse().map_err(|_| CodecError::TypeMismatch)?))
            }
            "Bool" => {
                expect(it, '(')?;
                let n = take_while(it, |c| c != ')');
                expect(it, ')')?;
                Ok(Value::Bool(n.trim() == "true"))
            }
            "Text" => {
                expect(it, '(')?;
                skip_ws(it);
                expect(it, '"')?;
                let s = take_while(it, |c| c != '"');
                expect(it, '"')?;
                skip_ws(it);
                expect(it, ')')?;
                Ok(Value::Text(s))
            }
            "Bytes" => {
                expect(it, '(')?;
                skip_ws(it);
                expect(it, '[')?;
                let body = take_while(it, |c| c != ']');
                expect(it, ']')?;
                skip_ws(it);
                expect(it, ')')?;
                let mut bytes = Vec::new();
                for part in body.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    bytes.push(part.parse().map_err(|_| CodecError::TypeMismatch)?);
                }
                Ok(Value::Bytes(bytes))
            }
            "Array" => {
                expect(it, '(')?;
                skip_ws(it);
                expect(it, '[')?;
                let mut items = Vec::new();
                loop {
                    skip_ws(it);
                    if it.peek() == Some(&']') {
                        it.next();
                        break;
                    }
                    items.push(parse(it)?);
                    skip_ws(it);
                    if it.peek() == Some(&',') {
                        it.next();
                    }
                }
                skip_ws(it);
                expect(it, ')')?;
                Ok(Value::Array(items))
            }
            "Map" => {
                expect(it, '(')?;
                skip_ws(it);
                expect(it, '[')?;
                let mut entries = Vec::new();
                loop {
                    skip_ws(it);
                    if it.peek() == Some(&']') {
                        it.next();
                        break;
                    }
                    expect(it, '(')?;
                    let k = parse(it)?;
                    skip_ws(it);
                    expect(it, ',')?;
                    let v = parse(it)?;
                    skip_ws(it);
                    expect(it, ')')?;
                    entries.push((k, v));
                    skip_ws(it);
                    if it.peek() == Some(&',') {
                        it.next();
                    }
                }
                skip_ws(it);
                expect(it, ')')?;
                Ok(Value::Map(entries))
            }
            _ => Err(CodecError::TypeMismatch),
        }
    }

    fn skip_ws(it: &mut core::iter::Peekable<core::str::Chars<'_>>) {
        while it.peek().is_some_and(|c| c.is_whitespace()) {
            it.next();
        }
    }
    fn take_ident(it: &mut core::iter::Peekable<core::str::Chars<'_>>) -> String {
        let mut s = String::new();
        while it.peek().is_some_and(|c| c.is_alphanumeric()) {
            s.push(it.next().unwrap());
        }
        s
    }
    fn take_while(
        it: &mut core::iter::Peekable<core::str::Chars<'_>>,
        f: impl Fn(char) -> bool,
    ) -> String {
        let mut s = String::new();
        while it.peek().is_some_and(|c| f(*c)) {
            s.push(it.next().unwrap());
        }
        s
    }
    fn expect(
        it: &mut core::iter::Peekable<core::str::Chars<'_>>,
        c: char,
    ) -> Result<(), CodecError> {
        skip_ws(it);
        if it.next() == Some(c) {
            Ok(())
        } else {
            Err(CodecError::TypeMismatch)
        }
    }

    pub fn as_map(value: &Value) -> Result<&[(Value, Value)], CodecError> {
        match value {
            Value::Map(m) => Ok(m),
            _ => Err(CodecError::NotAMap),
        }
    }
    pub fn get(map: &[(Value, Value)], key: u64) -> Option<&Value> {
        map.iter()
            .find(|(k, _)| matches!(k, Value::Integer(n) if *n == i128::from(key)))
            .map(|(_, v)| v)
    }
    pub fn require(map: &[(Value, Value)], key: u64) -> Result<&Value, CodecError> {
        get(map, key).ok_or(CodecError::MissingField)
    }
    pub fn as_u64(value: &Value) -> Result<u64, CodecError> {
        match value {
            Value::Integer(n) => u64::try_from(*n).map_err(|_| CodecError::TypeMismatch),
            _ => Err(CodecError::TypeMismatch),
        }
    }
    pub fn as_text(value: &Value) -> Result<&str, CodecError> {
        match value {
            Value::Text(t) => Ok(t),
            _ => Err(CodecError::TypeMismatch),
        }
    }
    pub fn as_array<const N: usize>(value: &Value) -> Result<[u8; N], CodecError> {
        match value {
            Value::Bytes(b) if b.len() == N => {
                let mut out = [0u8; N];
                out.copy_from_slice(b);
                Ok(out)
            }
            _ => Err(CodecError::TypeMismatch),
        }
    }
}
