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

use ratatosk_codec::{canonical, CodecError, Value};
use ratatosk_crypto::file::CHUNK_TAG_LEN;
use ratatosk_wire::SizeClass;

use crate::transport_policy::Transport;

/// Идентификатор файла.
pub type FileId = [u8; 16];

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
pub const CHUNK_BYTES: usize = SizeClass::L.max_payload() - ENVELOPE_RESERVE_BYTES - CHUNK_TAG_LEN;

/// Предел размера файла для почты — 20 МБ (§5.3, §10.3).
///
/// Мегабайты десятичные: ограничение приходит от почтовых серверов, а они
/// считают именно так.
pub const MAIL_FILE_LIMIT_BYTES: u64 = 20_000_000;

/// Предел размера превью — 32 КиБ, класс M (§10.3).
pub const PREVIEW_LIMIT_BYTES: usize = 32 * 1024;

/// Ключ файла.
pub type FileKey = [u8; 32];

/// Идентификатор чанка (§10.1) — он же ключ, которым чанк запечатан.
///
/// Деривация одна и живёт в `ratatosk_crypto::file`: §8.1 велит держать
/// комбинирование примитивов в одном модуле, покрытом тест-векторами.
/// Здесь — только имя, под которым её знает §10.1.
#[must_use]
pub fn chunk_id(file_key: &FileKey, index: u64) -> [u8; 32] {
    *ratatosk_crypto::file::chunk_key(file_key, index)
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

/// Наибольший размер файла в v1 — 2 ГиБ.
///
/// Предел нужен не арифметике (счётчик чанков `u64` и так не переполнится),
/// а трём вещам сразу. Учёт принятых чанков — строка на чанк, и без верхней
/// границы её нечем оценить. Очередь §5.4 обслуживает один файл целиком,
/// и без предела один файл занимает канал на неопределённый срок. И честность:
/// оставшееся время можно показать только там, где известен размер.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Сколько файлов можно прикрепить к одному сообщению.
///
/// Предел на приёме, как у квитанций и отзыва: список приходит от собеседника.
/// Десять — это «скинуть фотографии с прогулки», а не выгрузка галереи.
pub const MAX_FILES_PER_MESSAGE: usize = 10;

/// Наибольшая длина имени файла в символах.
pub const MAX_FILE_NAME_CHARS: usize = 255;

/// Порог автоматического приёма по умолчанию — 512 КиБ.
///
/// Значение по умолчанию, а не правило: порог настраивается, и «никогда»
/// (`None`) — законная настройка. Мелочь вроде фотографии приезжает сама,
/// как в любом мессенджере; всё, что крупнее, ждёт нажатия. Чужой клиент
/// не должен уметь занять память телефона, не спросив.
pub const DEFAULT_AUTO_ACCEPT_BYTES: u64 = 512 * 1024;

/// Сколько чанков отправитель шлёт вперёд подтверждённого получателем.
///
/// Окно, а не «шлём всё подряд», и это не оптимизация. Без окна ядро выдало бы
/// драйверу все чанки файла одним шагом — два гигабайта эффектов в памяти
/// у процесса, который на Android убивают за меньшее.
///
/// **Два, а не четыре**, и число это про отзывчивость, а не про пропускную
/// способность. Кадры к одному собеседнику идут одной очередью, и обычное
/// сообщение, отправленное посреди передачи файла, ждёт всего, что уже в
/// полёте. Четыре чанка — это четыре мебибайта ожидания на медленном Wi-Fi,
/// то есть «сообщения не отправляются, пока идёт файл». Два — вдвое меньше,
/// и при подтверждении на **каждый** чанк ([`ACK_EVERY`]) конвейер всё равно
/// не простаивает: подтверждение приходит, пока уходит следующий чанк.
pub const CHUNK_WINDOW: u64 = 2;

/// Через сколько принятых чанков получатель подтверждает приём.
///
/// Каждый. Подтверждение — крохотный кадр класса S (§5.5) рядом с мебибайтом
/// чанка, экономить на нём нечего, а редкие подтверждения при маленьком окне
/// останавливают передачу.
pub const ACK_EVERY: u64 = 1;

/// Сколько ждать чанк, прежде чем спросить заново (§10.2).
///
/// Сторожит получатель, и срок отсчитывается от **последнего пришедшего**
/// чанка: подтверждается каждый ([`ACK_EVERY`]), и каждый заводит срок
/// заново. То есть это ответ на вопрос «за это время не пришло ничего».
///
/// **Зависит от транспорта, и это не тонкость, а условие работоспособности.**
/// Чанк — мебибайт (класс L, §5.5). По локальной сети он уходит
/// за миллисекунды, через три реле Tor — за десятки секунд, а ждать
/// получателю приходится ещё и того, что уже в полёте: окно
/// [`CHUNK_WINDOW`] держит на линии до двух мебибайт.
///
/// Срок короче этого времени не «ускоряет возобновление», а ломает передачу
/// совсем. Получатель объявляет молчанием чанк, который в этот момент идёт
/// по проводу, и просит начать заново; отправитель отматывает окно и кладёт
/// в ту же линию **второй экземпляр** того же мебибайта. Линия становится
/// медленнее, следующий срок выходит ещё вернее, и передача разгоняет сама
/// себя в обратную сторону. Снаружи: «файл начинает загружаться и никогда
/// не догружается» — с настоящим прогрессом между срывами, потому что
/// что-то всё-таки доезжает.
///
/// Числа поэтому пессимистичные. Локальная сеть: десять секунд это запас
/// в тысячу раз, и он ни на что не влияет. Onion: два мебибайта окна
/// при скромных тридцати килобайтах в секунду это семьдесят секунд, отсюда
/// две минуты. Дорого ждать столько впустую — но обрыв канала ловится
/// не этим сроком, а разрывом сессии (§5.4), после которого передачу
/// возобновляет появление канала. Этот срок — последняя страховка,
/// и ей положено быть терпеливой.
#[must_use]
pub const fn stall_ms(via: Transport) -> u64 {
    match via {
        Transport::Lan => 10_000,
        Transport::Onion => 120_000,
        // Почтой чанки не ходят вовсе (§10.2 требует прямого канала), и это
        // значение существует только чтобы не было ветки без ответа.
        Transport::Mail => 120_000,
    }
}

/// Ключ идентификатора файла в нагрузке.
const KEY_FILE_ID: u64 = 1;
/// Ключ списка файлов в предложении.
const KEY_FILES: u64 = 2;
/// Ключ подписи к файлам.
const KEY_CAPTION: u64 = 1;
/// Ключ имени файла.
const KEY_NAME: u64 = 2;
/// Ключ размера.
const KEY_SIZE: u64 = 3;
/// Ключ файлового ключа (§10.1).
const KEY_FILE_KEY: u64 = 4;
/// Ключ превью.
const KEY_PREVIEW: u64 = 6;
/// Ключ номера чанка — он же номер, с которого просят продолжить.
const KEY_INDEX: u64 = 2;
/// Ключ байтов чанка.
const KEY_BYTES: u64 = 3;
/// Ключ признака «до меня ничего не доходит» в просьбе.
const KEY_STALLED: u64 = 3;

/// Почему файл не принят.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// Больше [`MAX_FILE_BYTES`].
    #[error("файл больше {MAX_FILE_BYTES} байт")]
    TooLarge,
    /// Файлов в сообщении больше [`MAX_FILES_PER_MESSAGE`].
    #[error("к одному сообщению можно приложить не больше {MAX_FILES_PER_MESSAGE} файлов")]
    TooMany,
    /// Имя пустое, слишком длинное или содержит путь.
    #[error("недопустимое имя файла")]
    BadName,
    /// Превью больше [`PREVIEW_LIMIT_BYTES`].
    #[error("превью больше {PREVIEW_LIMIT_BYTES} байт")]
    PreviewTooLarge,
}

/// Предложение одного файла — то, что едет в `PayloadType::FileOffer`.
///
/// Ключ файла едет здесь же, и иначе нельзя: §10.1 передаёт `file_key`
/// «в сообщении», то есть по уже установленной сессии. Отдельного обмена
/// ключами для файлов нет и не нужно — кадр с предложением уже зашифрован
/// сессионным ключом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    /// Идентификатор файла — по нему адресуются чанки.
    pub file_id: FileId,
    /// Имя для показа. **Не путь**: см. [`check_name`].
    pub name: String,
    /// Размер открытого содержимого.
    pub size_bytes: u64,
    /// Ключ файла (§10.1).
    pub key: FileKey,
    /// Превью изображения до [`PREVIEW_LIMIT_BYTES`] (§10.3).
    pub preview: Option<Vec<u8>>,
}

/// Проверяет имя файла.
///
/// Имя приходит от собеседника и попадает на экран, а при сохранении —
/// в имя файла на диске. Поэтому здесь отвергаются разделители пути,
/// управляющие символы и «точечные» имена: получатель хранит файл под своим
/// `file_id` и чужое имя путём не считает, но правило дешевле привычки —
/// первый же клиент, который склеит имя с каталогом, получит запись куда
/// угодно.
///
/// # Errors
///
/// [`FileError::BadName`].
pub fn check_name(name: &str) -> Result<(), FileError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_FILE_NAME_CHARS {
        return Err(FileError::BadName);
    }
    if trimmed == "." || trimmed == ".." {
        return Err(FileError::BadName);
    }
    if trimmed.chars().any(|c| c == '/' || c == '\\' || c.is_control()) {
        return Err(FileError::BadName);
    }
    Ok(())
}

/// Проверяет одно предложение файла — до отправки и на приёме.
///
/// # Errors
///
/// [`FileError`] по первому нарушению.
pub fn check_offer(offer: &FileOffer) -> Result<(), FileError> {
    check_name(&offer.name)?;
    if offer.size_bytes > MAX_FILE_BYTES {
        return Err(FileError::TooLarge);
    }
    if offer.preview.as_ref().is_some_and(|p| !preview_fits(p.len())) {
        return Err(FileError::PreviewTooLarge);
    }
    Ok(())
}

/// Проверяет весь список вложений сообщения.
///
/// # Errors
///
/// [`FileError::TooMany`] или ошибка любого из файлов.
pub fn check_offers(offers: &[FileOffer]) -> Result<(), FileError> {
    if offers.len() > MAX_FILES_PER_MESSAGE {
        return Err(FileError::TooMany);
    }
    for offer in offers {
        check_offer(offer)?;
    }
    Ok(())
}

/// Принимать ли файл такого размера автоматически.
///
/// `None` означает «никогда»: человек принимает каждый файл руками. Это
/// законная настройка, а не отключённая функция.
#[must_use]
pub const fn auto_accept(size_bytes: u64, threshold: Option<u64>) -> bool {
    match threshold {
        Some(limit) => size_bytes <= limit,
        None => false,
    }
}

/// Собирает нагрузку предложения: подпись и список файлов.
#[must_use]
pub fn offer_payload(caption: &str, offers: &[FileOffer]) -> Value {
    let files = offers
        .iter()
        .map(|offer| {
            let mut entry = vec![
                (Value::Integer(KEY_FILE_ID.into()), Value::Bytes(offer.file_id.to_vec())),
                (Value::Integer(KEY_NAME.into()), Value::Text(offer.name.clone())),
                (Value::Integer(KEY_SIZE.into()), Value::Integer(offer.size_bytes.into())),
                (Value::Integer(KEY_FILE_KEY.into()), Value::Bytes(offer.key.to_vec())),
            ];
            if let Some(preview) = &offer.preview {
                entry.push((Value::Integer(KEY_PREVIEW.into()), Value::Bytes(preview.clone())));
            }
            Value::Map(entry)
        })
        .collect();
    Value::Map(vec![
        (Value::Integer(KEY_CAPTION.into()), Value::Text(caption.to_owned())),
        (Value::Integer(KEY_FILES.into()), Value::Array(files)),
    ])
}

/// Разбирает нагрузку предложения.
///
/// Проверяется всё: число файлов, длина каждого поля, имя, размер, превью.
/// Список приходит от собеседника, и единственная защита от «предложения»
/// на тысячу файлов — вот эта проверка.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`], если структура не та или что-то не прошло
/// [`check_offers`].
pub fn offer_from_payload(value: &Value) -> Result<(String, Vec<FileOffer>), CodecError> {
    let map = canonical::as_map(value)?;
    let Value::Text(caption) = canonical::require(map, KEY_CAPTION)? else {
        return Err(CodecError::TypeMismatch);
    };
    let Value::Array(items) = canonical::require(map, KEY_FILES)? else {
        return Err(CodecError::TypeMismatch);
    };
    if items.len() > MAX_FILES_PER_MESSAGE {
        return Err(CodecError::TypeMismatch);
    }

    let mut offers = Vec::with_capacity(items.len());
    for item in items {
        let entry = canonical::as_map(item)?;
        // Превью необязательно: у документа его нет вовсе. Отсутствие ключа —
        // законный случай, а вот ключ не того типа — нет.
        let preview = match canonical::get(entry, KEY_PREVIEW) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CodecError::TypeMismatch),
            None => None,
        };
        offers.push(FileOffer {
            file_id: canonical::as_array::<16>(canonical::require(entry, KEY_FILE_ID)?)?,
            name: match canonical::require(entry, KEY_NAME)? {
                Value::Text(name) => name.clone(),
                _ => return Err(CodecError::TypeMismatch),
            },
            size_bytes: canonical::as_u64(canonical::require(entry, KEY_SIZE)?)?,
            key: canonical::as_array::<32>(canonical::require(entry, KEY_FILE_KEY)?)?,
            preview,
        });
    }
    if check_offers(&offers).is_err() {
        return Err(CodecError::TypeMismatch);
    }
    Ok((caption.clone(), offers))
}

/// Собирает нагрузку чанка.
#[must_use]
pub fn chunk_payload(file_id: FileId, index: u64, sealed: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_FILE_ID.into()), Value::Bytes(file_id.to_vec())),
        (Value::Integer(KEY_INDEX.into()), Value::Integer(index.into())),
        (Value::Integer(KEY_BYTES.into()), Value::Bytes(sealed.to_vec())),
    ])
}

/// Разбирает нагрузку чанка.
///
/// Длина проверяется здесь: чанк больше положенного означает либо чужую
/// сборку, либо попытку заставить нас держать в памяти больше, чем нужно.
///
/// # Errors
///
/// [`CodecError::TypeMismatch`].
pub fn chunk_from_payload(value: &Value) -> Result<(FileId, u64, Vec<u8>), CodecError> {
    let map = canonical::as_map(value)?;
    let file_id = canonical::as_array::<16>(canonical::require(map, KEY_FILE_ID)?)?;
    let index = canonical::as_u64(canonical::require(map, KEY_INDEX)?)?;
    let Value::Bytes(sealed) = canonical::require(map, KEY_BYTES)? else {
        return Err(CodecError::TypeMismatch);
    };
    if sealed.len() > CHUNK_BYTES + CHUNK_TAG_LEN || sealed.len() < CHUNK_TAG_LEN {
        return Err(CodecError::TypeMismatch);
    }
    Ok((file_id, index, sealed.clone()))
}

/// Собирает просьбу продолжить передачу с указанного чанка (§10.2).
///
/// Она же подтверждение: «всё до этого номера у меня есть». Кадр один, но
/// **говорит он две разные вещи**, и различает их флаг `stalled`.
///
/// # Почему флаг, а не догадка
///
/// Найдено на живом стенде, и стоило это зависшей передачи. Сначала кадр был
/// один и без флага: отправитель сам решал, подтверждение перед ним или
/// просьба начать заново, — по тому, продвинулся ли номер. Догадка неверна.
///
/// Получатель подтверждает **следующий недостающий** чанк, а у отправителя
/// в это время в полёте ещё несколько. Сроки молчания у получателя выходят
/// вразнобой, и в какой-то момент он честно просит номер, который уже просил.
/// Отправитель читает это как «ничего не дошло», отматывает отправку назад
/// и шлёт по второму разу то, что уже в пути. Каждый повтор у получателя —
/// новый срок молчания и новая просьба, и передача сама себя разгоняет:
/// файл «грузится вечно», а очередь кадров к этому собеседнику забита
/// мебибайтами, из-за чего не уходят и обычные сообщения.
///
/// Получатель прекрасно знает, что имеет в виду. Поэтому он это и говорит:
/// `stalled = false` — «принял, шлите дальше» (окно едет вперёд, ничего
/// не пересылается), `stalled = true` — «за целый срок ничего не пришло,
/// начните с этого номера» (отправка отматывается). Догадок больше нет.
#[must_use]
pub fn request_payload(file_id: FileId, next_index: u64, stalled: bool) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_FILE_ID.into()), Value::Bytes(file_id.to_vec())),
        (Value::Integer(KEY_INDEX.into()), Value::Integer(next_index.into())),
        (Value::Integer(KEY_STALLED.into()), Value::Bool(stalled)),
    ])
}

/// Разбирает просьбу продолжить передачу.
///
/// Возвращает номер и признак «до меня ничего не доходит».
///
/// # Errors
///
/// [`CodecError::TypeMismatch`].
pub fn request_from_payload(value: &Value) -> Result<(FileId, u64, bool), CodecError> {
    let map = canonical::as_map(value)?;
    let file_id = canonical::as_array::<16>(canonical::require(map, KEY_FILE_ID)?)?;
    let index = canonical::as_u64(canonical::require(map, KEY_INDEX)?)?;
    let Value::Bool(stalled) = canonical::require(map, KEY_STALLED)? else {
        return Err(CodecError::TypeMismatch);
    };
    Ok((file_id, index, *stalled))
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
        use ratatosk_codec::{Envelope, Fragment, PayloadType};
        use ratatosk_crdt::Hlc;

        // Чанк едет **запечатанным**: к нему прибавляется тег AEAD, и он
        // тоже обязан поместиться. Раньше здесь стоял открытый чанк, и запас
        // считался без тега — на шестнадцать байт оптимистичнее правды.
        let mut envelope = Envelope::new(
            [0xAB; 16],
            Hlc::new(u64::MAX, u32::MAX),
            PayloadType::FileChunk,
            chunk_payload([0xBC; 16], u64::MAX, &[0u8; CHUNK_BYTES + CHUNK_TAG_LEN]),
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
    fn an_offer_round_trips_with_several_files() {
        // К одному сообщению прикладывают несколько файлов — это обычный
        // случай («скинуть фотографии»), а не расширение.
        let offers = vec![
            FileOffer {
                file_id: [1u8; 16],
                name: "otchet.pdf".into(),
                size_bytes: 1_234,
                key: [2u8; 32],
                preview: None,
            },
            FileOffer {
                file_id: [4u8; 16],
                name: "foto.jpg".into(),
                size_bytes: 99_000,
                key: [5u8; 32],
                preview: Some(vec![0x89, b'P', b'N', b'G']),
            },
        ];
        let (caption, back) = offer_from_payload(&offer_payload("вот", &offers)).unwrap();
        assert_eq!(caption, "вот");
        assert_eq!(back, offers);
    }

    #[test]
    fn an_offer_without_a_caption_is_normal() {
        let offers = vec![FileOffer {
            file_id: [1u8; 16],
            name: "bez.txt".into(),
            size_bytes: 1,
            key: [0u8; 32],
            preview: None,
        }];
        let (caption, _) = offer_from_payload(&offer_payload("", &offers)).unwrap();
        assert!(caption.is_empty(), "файл без подписи — законное сообщение");
    }

    #[test]
    fn a_hostile_offer_is_refused() {
        let one = |name: &str, size: u64, preview: Option<Vec<u8>>| FileOffer {
            file_id: [1u8; 16],
            name: name.into(),
            size_bytes: size,
            key: [0u8; 32],
            preview,
        };

        // Список длиннее предела заставил бы перебрать сколько угодно записей.
        let many: Vec<_> = (0..=MAX_FILES_PER_MESSAGE).map(|_| one("a.txt", 1, None)).collect();
        assert!(offer_from_payload(&offer_payload("", &many)).is_err());

        // Имя с путём. Получатель хранит файл под своим `file_id` и чужое имя
        // путём не считает — но правило дешевле привычки.
        for name in ["../../etc/passwd", "a/b.txt", "", ".", "..", "плохо\u{7}"] {
            assert!(check_name(name).is_err(), "имя прошло: {name}");
        }
        assert!(offer_from_payload(&offer_payload("", &[one("a/b", 1, None)])).is_err());

        // Размер и превью — за пределом.
        assert!(
            offer_from_payload(&offer_payload("", &[one("a", MAX_FILE_BYTES + 1, None)])).is_err()
        );
        let big = vec![0u8; PREVIEW_LIMIT_BYTES + 1];
        assert!(offer_from_payload(&offer_payload("", &[one("a", 1, Some(big))])).is_err());
    }

    #[test]
    fn a_chunk_payload_round_trips_and_bounds_its_size() {
        let sealed = vec![9u8; 100];
        let (file_id, index, back) =
            chunk_from_payload(&chunk_payload([2u8; 16], 7, &sealed)).unwrap();
        assert_eq!((file_id, index, back), ([2u8; 16], 7, sealed));

        // Чанк больше положенного — либо чужая сборка, либо попытка занять
        // память; и то и другое отвергается до записи на диск.
        let huge = vec![0u8; CHUNK_BYTES + CHUNK_TAG_LEN + 1];
        assert!(chunk_from_payload(&chunk_payload([2u8; 16], 0, &huge)).is_err());
        // И короче тега быть не может: там нечего проверять.
        assert!(chunk_from_payload(&chunk_payload([2u8; 16], 0, &[1, 2, 3])).is_err());
    }

    #[test]
    fn a_request_says_why_it_asks() {
        // Регрессия. Без флага отправитель угадывал, подтверждение перед ним
        // или просьба начать заново, — и на длинном файле угадывал неверно,
        // отматывая отправку на каждом запоздавшем сроке. Передача при этом
        // не заканчивалась никогда.
        let (file_id, next, stalled) =
            request_from_payload(&request_payload([5u8; 16], 42, false)).unwrap();
        assert_eq!((file_id, next, stalled), ([5u8; 16], 42, false));

        let (_, _, stalled) = request_from_payload(&request_payload([5u8; 16], 42, true)).unwrap();
        assert!(stalled, "«ничего не дошло» обязано отличаться от «принял, шлите дальше»");
    }

    #[test]
    fn the_auto_accept_threshold_is_a_setting_not_a_rule() {
        // «Никогда» — законная настройка, а не отключённая функция.
        assert!(!auto_accept(1, None));
        assert!(auto_accept(DEFAULT_AUTO_ACCEPT_BYTES, Some(DEFAULT_AUTO_ACCEPT_BYTES)));
        assert!(!auto_accept(DEFAULT_AUTO_ACCEPT_BYTES + 1, Some(DEFAULT_AUTO_ACCEPT_BYTES)));
        // Порог по умолчанию пропускает фотографию и не пропускает видео.
        assert!(auto_accept(300 * 1024, Some(DEFAULT_AUTO_ACCEPT_BYTES)));
        assert!(!auto_accept(50 * 1024 * 1024, Some(DEFAULT_AUTO_ACCEPT_BYTES)));
    }

    #[test]
    fn the_window_leaves_room_to_breathe() {
        // Окно существует по двум причинам сразу, и проверяются обе.
        //
        // Ядро не должно выдавать драйверу весь файл одним шагом — отсюда
        // верхняя граница на то, что в полёте.
        assert!(
            CHUNK_WINDOW * CHUNK_BYTES as u64 <= 2 * 1024 * 1024,
            "в полёте не больше двух мебибайт: за ними ждёт обычное сообщение"
        );
        // И передача не должна вставать: подтверждают не реже, чем окно
        // успевает закрыться.
        assert!(ACK_EVERY <= CHUNK_WINDOW, "подтверждение реже окна остановит передачу");
        assert!(CHUNK_WINDOW >= 2, "окно в один чанк — это шаг за круг, а не конвейер");
    }

    #[test]
    fn the_stall_deadline_outlasts_a_window_on_the_slowest_transport() {
        // Ошибка, которую это стережёт: срок молчания короче времени передачи
        // не ускоряет возобновление, а ломает её совсем. Получатель объявляет
        // молчанием чанк, который прямо сейчас идёт по проводу, отправитель
        // отматывает окно и кладёт в ту же линию второй экземпляр того же
        // мебибайта — и передача разгоняет сама себя в обратную сторону.
        // Снаружи: «файл начинает загружаться и никогда не догружается».
        //
        // Скорость взята нарочно скромной: одна цепочка Tor через три реле
        // это не канал, а обещание канала.
        const SLOW_ONION_BYTES_PER_SEC: u64 = 30 * 1024;
        let window_bytes = CHUNK_WINDOW * CHUNK_BYTES as u64;
        let needed_ms = window_bytes * 1_000 / SLOW_ONION_BYTES_PER_SEC;
        assert!(
            stall_ms(Transport::Onion) >= needed_ms,
            "в срок молчания обязано помещаться целое окно: нужно {needed_ms} мс, \
             отведено {}",
            stall_ms(Transport::Onion)
        );
        // По локальной сети мебибайт уходит за миллисекунды, и срок там нужен
        // не для скорости, а чтобы оборванная передача вообще возобновилась.
        assert!(
            stall_ms(Transport::Lan) < stall_ms(Transport::Onion),
            "у транспортов разная цена мебибайта — значит и сроки разные"
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
