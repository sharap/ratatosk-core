#![allow(dead_code)]
//! Стенд формата снимка: две функции подняты **дословно** из
//! crates/core/src/companion.rs, кодек настоящий по поведению (сортировка
//! ключей, отказ на повторах), печать снята — проверяется формат, не AEAD.
mod stub;
use stub::{canonical, CodecError, Value};

const YGG_KEY_LEN: usize = 32;
const MAX_PEER_LEN: usize = 256;
const MAX_YGG_PEERS: usize = 16;

const SNAP_VERSION: u64 = 2;
const SNAP_KEY_VERSION: u64 = 1;
const SNAP_KEY_CHATS: u64 = 2;
const SNAP_KEY_HISTORY: u64 = 3;
const SNAP_KEY_ONION: u64 = 10;
const SNAP_KEY_YGG: u64 = 11;
const SNAP_KEY_PEERS: u64 = 12;

#[derive(Debug, PartialEq, Eq)]
enum CacheError { Codec(CodecError), Version }
impl From<CodecError> for CacheError { fn from(e: CodecError) -> Self { CacheError::Codec(e) } }

/// Кэш здесь — только то, что нужно формату: версия и два списка.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Cache { chats: usize }
impl Cache {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::Integer(SNAP_KEY_VERSION.into()), Value::Integer(SNAP_VERSION.into())),
            (Value::Integer(SNAP_KEY_CHATS.into()), Value::Array(vec![Value::Bool(true); self.chats])),
            (Value::Integer(SNAP_KEY_HISTORY.into()), Value::Array(Vec::new())),
        ])
    }
    fn from_value(value: &Value) -> Result<Cache, CacheError> {
        let map = canonical::as_map(value)?;
        if canonical::as_u64(canonical::require(map, SNAP_KEY_VERSION)?)? != SNAP_VERSION {
            return Err(CacheError::Version);
        }
        let Value::Array(chats) = canonical::require(map, SNAP_KEY_CHATS)? else {
            return Err(CodecError::TypeMismatch.into());
        };
        Ok(Cache { chats: chats.len() })
    }
}

#[derive(Default)]
struct Client {
    cache: Cache,
    phone_onion: String,
    phone_ygg: Vec<u8>,
    phone_ygg_peers: Vec<String>,
    addr_dirty: bool,
}

impl Client {
    fn snapshot(&mut self) -> Result<Vec<u8>, CodecError> {
        let bytes = canonical::encode(&self.snapshot_value())?;
        self.addr_dirty = false;
        Ok(bytes)
    }

