//! Разбор контакт-карточек и URI (§4.1, §16).
//!
//! Отдельная цель, потому что карточка приходит из QR-кода — то есть из
//! источника, который пользователь наводит на что угодно.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ratatosk_codec::ContactCard::decode(data);
    if let Ok(text) = core::str::from_utf8(data) {
        let _ = ratatosk_codec::ContactCard::from_uri(text);
    }
});
