//! CBOR-десериализация не должна паниковать (§6, §16).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = ratatosk_codec::canonical::decode(data) {
        // Успешный разбор означает каноничность: повторное кодирование
        // обязано дать те же байты (§6).
        let reencoded = ratatosk_codec::canonical::encode(&value).expect("значение уже разобрано");
        assert_eq!(reencoded, data);
    }
    let _ = ratatosk_codec::Envelope::decode(data);
});
