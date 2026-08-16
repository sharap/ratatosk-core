//! Файлы (§10).
//!
//! Файл шифруется случайным `file_key` (32 байта), передаваемым в сообщении.
//! `chunk_id = BLAKE3_derive_key("ratatosk v0 file", file_key ‖ index)`.
//! Хэш для проверки целостности считается **от шифротекста**.
//!
//! Content-addressing по хэшу открытого содержимого не применяется (§10.1):
//! он позволил бы проверять наличие у вас конкретного известного файла.
//! Это не оптимизация, а решение модели угроз — менять его нельзя, не
//! переписав §2.

use ratatosk_crypto::{kdf, labels};
use ratatosk_wire::SizeClass;

use crate::transport_policy::Transport;

/// Запас под CBOR-конверт вокруг чанка (§9.1).
///
/// Чанк едет не голым: он лежит в поле `payload` конверта, рядом с `msg_id`,
/// меткой HLC, типом нагрузки и, для групп, `group_id`. Всё это тоже обязано
/// поместиться в кадр. Реальная накладка — около сотни байт; 256 взяты
/// с запасом, а достаточность запаса проверяется тестом
/// `a_full_chunk_fits_in_one_frame_with_its_envelope` на настоящем конверте,
/// а не на оценке.
pub const ENVELOPE_RESERVE_BYTES: usize = 256;

/// Размер чанка при передаче прямым каналом — класс L (§10.2).
///
/// **Расхождение со спецификацией, разрешённое в пользу арифметики.**
/// §10.2 говорит «чанками по 1 МиБ», §5.5 задаёт класс L равным 1 МиБ.
/// Вместе это невыполнимо: 1 МиБ — размер **кадра целиком**, включая
/// 42 байта заголовка, 16 байт тега и хотя бы один байт паддинга (§7).
/// Чанк ровно в 1 МиБ не помещается в кадр, который должен его нести.
///
/// Поэтому размер выводится из класса, а не задаётся числом: получается
/// чуть меньше мебибайта. Захардкоженная константа снова разошлась бы
/// с классом при первом же изменении формата заголовка.
pub const CHUNK_BYTES: usize = SizeClass::L.max_payload() - ENVELOPE_RESERVE_BYTES;

/// Предел размера файла для почты — 20 МБ (§5.3, §10.3).
///
/// Мегабайты десятичные: ограничение приходит от почтовых серверов, а они
/// считают именно так.
pub const MAIL_FILE_LIMIT_BYTES: u64 = 20_000_000;

/// Предел размера превью — 32 КиБ, класс M (§10.3).
pub const PREVIEW_LIMIT_BYTES: usize = 32 * 1024;

/// Ключ файла.
pub type FileKey = [u8; 32];

/// Идентификатор чанка (§10.1).
#[must_use]
pub fn chunk_id(file_key: &FileKey, index: u64) -> [u8; 32] {
    *kdf::derive_concat(labels::FILE, &[file_key, &index.to_be_bytes()])
}

/// Сколько чанков в файле такого размера.
#[must_use]
pub fn chunk_count(size_bytes: u64) -> u64 {
    if size_bytes == 0 {
        return 0;
    }
    size_bytes.div_ceil(CHUNK_BYTES as u64)
}

/// Класс кадра для чанка файла — всегда L (§5.5).
#[must_use]
pub const fn chunk_size_class() -> SizeClass {
    SizeClass::L
}

/// Можно ли отправить файл этим транспортом (§10.3).
#[must_use]
pub const fn may_send_over(size_bytes: u64, transport: Transport) -> bool {
    match transport {
        Transport::Lan | Transport::Onion => true,
        Transport::Mail => size_bytes <= MAIL_FILE_LIMIT_BYTES,
    }
}

/// Текст для UI, когда файл ждёт прямого канала (§10.3).
#[must_use]
pub const fn waiting_for_direct_channel_text() -> &'static str {
    "Файл будет отправлен, когда получатель появится в сети"
}

/// Правило для десктопа-компаньона (§13.4).
///
/// Передача файлов больше 20 МБ с десктопа разрешена **только когда оба
/// устройства в одной сети** — иначе выгрузка идёт через мобильный канал
/// телефона. UI обязан сообщать об этом явно.
#[must_use]
pub const fn companion_may_upload(size_bytes: u64, same_network: bool) -> bool {
    size_bytes <= MAIL_FILE_LIMIT_BYTES || same_network
}

/// Помещается ли превью в свой предел.
#[must_use]
pub const fn preview_fits(bytes: usize) -> bool {
    bytes <= PREVIEW_LIMIT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_ids_are_unique_per_index() {
        let key = [7u8; 32];
        assert_ne!(chunk_id(&key, 0), chunk_id(&key, 1));
        assert_eq!(chunk_id(&key, 5), chunk_id(&key, 5));
    }

    #[test]
    fn chunk_ids_differ_between_files() {
        assert_ne!(chunk_id(&[1u8; 32], 0), chunk_id(&[2u8; 32], 0));
    }

    #[test]
    fn chunk_count_rounds_up() {
        assert_eq!(chunk_count(0), 0);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64 + 1), 2);
    }

    #[test]
    fn chunks_use_the_large_frame_class() {
        assert_eq!(chunk_size_class(), SizeClass::L);
        assert!(
            CHUNK_BYTES <= SizeClass::L.max_payload(),
            "чанк {CHUNK_BYTES} не помещается в нагрузку кадра {}",
            SizeClass::L.max_payload()
        );
    }

    #[test]
    fn chunk_is_just_under_a_mebibyte() {
        // §10.2 обещает «по 1 МиБ». Получается чуть меньше — но именно
        // «чуть»: если запас вдруг съест заметную долю, это ошибка в расчёте,
        // а не компромисс.
        assert!(CHUNK_BYTES < 1024 * 1024);
        assert!(CHUNK_BYTES > 1024 * 1024 - 1024, "чанк ужался сильнее, чем на килобайт");
    }

    #[test]
    fn a_full_chunk_fits_in_one_frame_with_its_envelope() {
        // Главная проверка этого модуля. Чанк едет в конверте, конверт —
        // в кадре; провал здесь означал бы, что передача файлов ломается
        // на каждом чанке, а не в редком краю.
        //
        // Конверт собирается самый тяжёлый из возможных для чанка: с
        // `group_id` и с заголовком фрагмента. Фрагментации у чанка на самом
        // деле не бывает (он помещается в кадр по построению), но запас
        // должен покрывать и её.
        use ratatosk_codec::{Envelope, Fragment, PayloadType, Value};
        use ratatosk_crdt::Hlc;

        let mut envelope = Envelope::new(
            [0xAB; 16],
            Hlc::new(u64::MAX, u32::MAX),
            PayloadType::FileChunk,
            Value::Bytes(vec![0u8; CHUNK_BYTES]),
        );
        envelope.group_id = Some(vec![0xCD; 16]);
        envelope.fragment = Some(Fragment { uid: [0xEF; 16], index: 4095, total: 4096 });

        let encoded = envelope.encode().expect("конверт должен собираться");
        assert!(
            encoded.len() <= SizeClass::L.max_payload(),
            "конверт с чанком занял {} байт при пределе {}; увеличьте ENVELOPE_RESERVE_BYTES",
            encoded.len(),
            SizeClass::L.max_payload()
        );
    }

    #[test]
    fn reserve_is_not_wildly_oversized() {
        // Обратная сторона предыдущего теста: запас должен быть с полем,
        // но не вдвое больше нужного, иначе мы теряем полезную ёмкость
        // в каждом кадре файла.
        assert!(ENVELOPE_RESERVE_BYTES <= 1024);
    }

    #[test]
    fn mail_refuses_large_files() {
        assert!(may_send_over(MAIL_FILE_LIMIT_BYTES, Transport::Mail));
        assert!(!may_send_over(MAIL_FILE_LIMIT_BYTES + 1, Transport::Mail));
        assert!(may_send_over(u64::MAX, Transport::Onion));
    }

    #[test]
    fn companion_upload_rule_matches_spec() {
        // §13.4: большой файл с десктопа — только в одной сети с телефоном.
        assert!(companion_may_upload(1_000, false));
        assert!(!companion_may_upload(MAIL_FILE_LIMIT_BYTES + 1, false));
        assert!(companion_may_upload(MAIL_FILE_LIMIT_BYTES + 1, true));
    }

    #[test]
    fn preview_limit_matches_frame_class() {
        assert!(preview_fits(PREVIEW_LIMIT_BYTES));
        assert!(!preview_fits(PREVIEW_LIMIT_BYTES + 1));
        assert!(PREVIEW_LIMIT_BYTES <= SizeClass::M.max_payload());
    }
}
