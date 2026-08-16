//! Разбор кадра не должен паниковать ни на каком входе (§7.3, §16).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(view) = ratatosk_wire::parse(data) {
        // Инварианты успешного разбора: длина совпадает с классом, а AAD
        // побайтово равен заголовку в исходном буфере (§7.2).
        assert_eq!(view.class.frame_len(), data.len());
        assert_eq!(&view.aad()[..], &data[..ratatosk_wire::HEADER_LEN]);
    }
    // Снятие паддинга вызывается на уже аутентифицированных байтах, но
    // падать не должно и на мусоре.
    let _ = ratatosk_wire::unpad(data);
});
