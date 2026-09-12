//! Почта chatmail (§5.3): сборка и разбор писем.
//!
//! Почта используется как **тупая труба для наших же запечатанных кадров**.
//! OpenPGP, Autocrypt и любые почтовые схемы шифрования не применяются —
//! криптостек в системе один.
//!
//! Снаружи письмо при этом выглядит как OpenPGP/MIME, и это не противоречие,
//! а требование чужого сервера: chatmail не пересылает незашифрованную почту
//! и проверяет форму конверта. Разбор — в [`build_message`]; внутри конверта
//! лежит наш кадр, и ни одного байта OpenPGP в нём нет.
//!
//! Что видит сервер, и это надо сказать пользователю (§2.2, §14 пункт 2):
//! содержимого он не видит, но видит, какие адреса переписываются между
//! собой, когда и какого размера. Это цена асинхронной доставки без своей
//! инфраструктуры, и от Tor она не зависит.
//!
//! А вот IP зависит: §5.3 говорит «поверх Tor», и по умолчанию так и есть,
//! но там, где Tor заблокирован, почта остаётся единственным путём до
//! собеседника — и тогда она идёт напрямую. Переключатель и его цена —
//! в [`ratatosk_proto::mail`].
//!
//! Здесь — чистая часть: письмо из кадров и кадры из письма, а рядом,
//! в [`http`] и [`json`], — разбор ответа сервера на просьбу завести новый
//! ящик. Всё это проверяется тестами без сети.
//!
//! Сокеты живут за признаком `chatmail-net`: [`tls`] открывает поток
//! (прямо или через Tor) и заворачивает его в TLS, [`smtp`] входит на сервер
//! и отправляет письмо, [`imap`] принимает и прибирает ящик, [`runner`]
//! отвечает на команды ядра и держит обе задачи.

pub mod http;
#[cfg(feature = "chatmail-net")]
pub mod imap;
pub mod json;
#[cfg(feature = "chatmail-net")]
pub mod runner;
#[cfg(feature = "chatmail-net")]
pub mod smtp;
// TLS переехал на уровень крейта: потребителей у него стало двое — почта
// и nostr, а держать общий модуль внутри одного из них значило бы, что
// ступень реле тянет за собой почтовый признак сборки.
//
// Имя `chatmail::tls` при этом осталось рабочим: переименовывать четыре
// места ради переезда незачем, а `pub use` стоит ровно ноль.
#[cfg(feature = "chatmail-net")]
pub use crate::tls;

/// Фиксированная тема письма (§5.3, с поправкой).
///
/// Одна и та же для всех: тема — открытый заголовок, и любая переменная часть
/// в ней стала бы метаданными для сервера.
///
/// §5.3 называет здесь строку `Ratatosk`, и постоянство — правильная половина
/// требования. Неправильная — содержание: постоянная строка тоже метаданные,
/// просто другие. Она сообщает каждому узлу по пути, каким мессенджером
/// пользуется отправитель, — ровно то, ради чего мы не пишем `User-Agent`
/// и `Chat-Version`. Между «тема ничего не говорит о переписке» и «тема
/// ничего не говорит вообще» спецификация имела в виду первое, а стоило
/// второе.
///
/// `[...]` — то же, что ставит Delta Chat. Заодно письмо перестаёт
/// отличаться от его писем по единственному оставшемуся признаку: для
/// наблюдателя, считающего адреса и размеры (§2.2), полезно быть одним
/// из многих, а не одним из немногих.
pub const SUBJECT: &str = "[...]";

/// MIME-тип зашифрованной части (§5.3, RFC 3156).
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// Граница частей письма.
///
/// Постоянная, а не случайная, и это не лень. Граница — открытый заголовок:
/// случайная строка в ней была бы ещё одним полем, по которому письма одного
/// отправителя отличаются от писем другого. Столкнуться ей не с чем: внутри
/// частей только base64 и строки брони OpenPGP, и ни одна из них так
/// не начинается.
const BOUNDARY: &str = "ratatosk-boundary";

/// Начало брони OpenPGP (RFC 4880, §6.2).
const ARMOR_BEGIN: &str = "-----BEGIN PGP MESSAGE-----";

/// Конец брони OpenPGP.
const ARMOR_END: &str = "-----END PGP MESSAGE-----";

/// Предел размера письма (§5.3).
///
/// Берётся из ядра, а не задаётся здесь числом: от этого же предела зависит
/// арифметика чанка (`files::letter_bytes`), и два независимых числа однажды
/// разошлись бы — с тем исходом, что файл почтой начал бы уезжать
/// и отвергаться сервером на первом же куске.
pub const MAX_MESSAGE_BYTES: u64 = ratatosk_proto::files::MAX_LETTER_BYTES;

/// Длина случайной локальной части адреса (§5.3).
pub const LOCAL_PART_LEN: std::ops::RangeInclusive<usize> = 6..=8;

/// Длина строки base64 в теле письма.
///
/// 76 — предел из RFC 2045. Он не косметика: почтовые узлы вправе рвать
/// длинные строки сами, и порванная не на границе четвёрки base64 строка
/// приезжает мусором.
const LINE_LEN: usize = 76;

/// Почему письмо не разобралось.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// В письме нет пустой строки, отделяющей заголовки от тела.
    #[error("письмо без тела")]
    NoBody,
    /// Тело не разобралось как base64.
    #[error("тело не base64")]
    NotBase64,
    /// Письмо длиннее [`MAX_MESSAGE_BYTES`].
    #[error("письмо длиннее предела")]
    TooLarge,
    /// Кадров в теле не нашлось.
    #[error("в письме нет кадров")]
    Empty,
    /// Под бронёй лежит не наш пакет.
    ///
    /// Чужое письмо в конверте OpenPGP — обычное дело: ящик открыт всему
    /// миру, и настоящая почта от настоящего Delta Chat приедет в него
    /// в точно таком же конверте. Отличать её надо здесь и молча.
    #[error("под бронёй не наш пакет")]
    NotOurPacket,
}

/// Собирает письмо из кадров.
///
/// Заголовков ровно столько, сколько нужно, чтобы письмо доехало. Всё
/// остальное — метаданные в открытом виде: `Subject` постоянный (§5.3),
/// даты нет (её проставит сервер, и наша была бы вторым источником
/// времени), `Message-ID` нет (он приезжает от сервера и ничего нам
/// не говорит), `User-Agent` нет — он сообщал бы всем узлам по пути,
/// каким мессенджером пользуется отправитель.
///
/// # Почему письмо выглядит как OpenPGP/MIME
///
/// §5.3 говорит прямо: OpenPGP не применяется, криптостек один. Так и есть
/// — расшифровывается это письмо только нашим ключом, и ни одного байта
/// настоящего OpenPGP внутри нет. Но chatmail-серверы отказываются
/// пересылать незашифрованную почту («523 Encryption Needed: Invalid
/// Unencrypted Mail»), и правило разумное: иначе сервер, открытый
/// для регистрации без документов, за день становится бесплатным
/// ретранслятором спама.
///
/// Правило прочитано в исходнике фильтра, а не угадано, и требует оно
/// ровно четырёх вещей:
///
/// 1. `multipart/encrypted` ровно из двух частей, ни одна не составная;
/// 2. первая — `application/pgp-encrypted` с телом `Version: 1`;
/// 3. вторая — `application/octet-stream` в броне OpenPGP **без** заголовков
///    брони (у исходящих писем комментарии запрещены);
/// 4. под бронёй — цепочка пакетов OpenPGP, у которой длины сходятся
///    до последнего байта, а последний пакет имеет тип 18 (SEIPD).
///
/// Четвёртое и есть настоящая проверка: конверта мало, содержимое
/// разбирается по-настоящему. Поэтому кадр становится телом настоящего
/// пакета SEIPD — см. [`armor`].
///
/// Мы этому правилу удовлетворяем **по существу**, а не в обход. Письмо
/// действительно зашифровано, просто не тем ключом, который сервер умеет
/// назвать по имени; отличить одно шифрование от другого он не может —
/// в этом весь смысл шифрования. Обещания, которого не выполняем, здесь
/// нет: OpenPGP не заявляется нигде, где это увидел бы человек, а всякий,
/// кто попробует расшифровать письмо как PGP, получит честное «не мой
/// ключ» — что и есть правда.
///
/// Контрольная сумма брони — настоящая CRC-24. Фильтр её отбрасывает,
/// не проверяя, но другие разборщики проверяют, и найдётся выдуманная
/// не у нас, а у собеседника.
///
/// Форма сверена с двумя настоящими письмами Delta Chat, снятыми с живых
/// ящиков, — и второе с того самого сервера, который нас отверг. Те же две
/// части в том же порядке, тот же `protocol=`, `7bit` на обеих.
///
/// `charset="utf-8"` на обеих частях — **подражание, а не смысл**:
/// у `application/octet-stream` кодировки нет и быть не может, и фильтр,
/// как теперь видно из его исходника, сравнивает только тип без параметров.
/// Оставлен потому, что так пишет Delta Chat, а по этому пути ходят ещё
/// и чужие узлы, чьих правил мы не читали.
///
/// Что отличается сознательно — `Date`, `Message-ID` и `Chat-Version`,
/// которые Delta Chat пишет, а мы нет: первые два проставит сервер,
/// а третий сообщал бы каждому узлу по пути, каким мессенджером
/// пользуется отправитель.
///
/// # Errors
///
/// [`MessageError::TooLarge`], если письмо не влезло в предел §5.3,
/// и [`MessageError::Empty`] на пустом списке кадров: пустое письмо —
/// это трафик и запись в журнале сервера без единого байта пользы.
pub fn build_message(from: &str, to: &str, frames: &[Vec<u8>]) -> Result<String, MessageError> {
    if frames.is_empty() {
        return Err(MessageError::Empty);
    }
    let armored = frames.iter().map(|frame| armor(frame)).collect::<Vec<_>>().join("\r\n");

    let message = format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: {SUBJECT}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; \
         boundary=\"{BOUNDARY}\"\r\n\
         \r\n\
         --{BOUNDARY}\r\n\
         Content-Type: application/pgp-encrypted; charset=\"utf-8\"\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         \r\n\
         Version: 1\r\n\
         --{BOUNDARY}\r\n\
         Content-Type: {CONTENT_TYPE}; charset=\"utf-8\"\r\n\
         Content-Transfer-Encoding: 7bit\r\n\
         \r\n\
         {armored}\r\n\
         --{BOUNDARY}--\r\n"
    );
    if too_large(message.len()) {
        return Err(MessageError::TooLarge);
    }
    Ok(message)
}

/// Не вышло ли письмо за предел §5.3.
fn too_large(len: usize) -> bool {
    u64::try_from(len).unwrap_or(u64::MAX) > MAX_MESSAGE_BYTES
}

/// Тип пакета OpenPGP: зашифрованные данные с проверкой целостности (SEIPD).
///
/// Байт целиком: биты 7–6 равны `11` (современный формат RFC 9580),
/// младшие шесть — номер типа, 18.
const PACKET_SEIPD: u8 = 0xD2;

/// Признак пятибайтовой длины тела пакета (RFC 9580, 4.2.1).
///
/// Одна форма на все размеры, а не самая короткая для каждого: кадры у нас
/// от сотни байт до чанка файла, и выбор формы по размеру — три ветки
/// и три повода ошибиться ради четырёх сэкономленных байт на письмо.
const PACKET_FIVE_OCTET_LENGTH: u8 = 0xFF;

/// Версия пакета SEIPD.
const PACKET_VERSION: u8 = 1;

/// Сколько байт занимает заголовок пакета вместе с версией.
const PACKET_HEADER_LEN: usize = 7;

/// Заворачивает кадр в пакет OpenPGP и броню.
///
/// # Зачем кадру заголовок пакета
///
/// Фильтр chatmail-сервера не верит конверту на слово: он снимает броню,
/// декодирует base64 и **проходит по цепочке пакетов OpenPGP**, требуя,
/// чтобы длины сошлись до последнего байта, а последний пакет оказался
/// SEIPD (тип 18). Голый кадр не проходит на первом же байте.
///
/// Поэтому кадр становится телом настоящего пакета SEIPD версии 1. Это
/// не притворство ради проверки: получается **синтаксически правильное
/// сообщение OpenPGP**, у которого шифротекст зашифрован не сеансовым
/// ключом PGP, а нашим AEAD. Всякий, кто попробует его расшифровать
/// как PGP, получит честный ответ «не мой ключ» — что и есть правда.
///
/// Цена — семь байт на письмо.
fn armor(frame: &[u8]) -> String {
    let packet = packet(frame);
    let body = wrap(&data_encoding::BASE64.encode(&packet));
    let checksum = data_encoding::BASE64.encode(&crc24(&packet));
    format!("{ARMOR_BEGIN}\r\n\r\n{body}\r\n={checksum}\r\n{ARMOR_END}")
}

/// Собирает пакет SEIPD с кадром внутри.
fn packet(frame: &[u8]) -> Vec<u8> {
    // Длина тела считается вместе с байтом версии — он часть тела пакета,
    // а не заголовка. Ошибка здесь стоила бы ровно одного байта
    // расхождения, и фильтр отверг бы письмо, не сказав чем именно.
    let body_len = u32::try_from(frame.len().saturating_add(1)).unwrap_or(u32::MAX);
    let mut packet = Vec::with_capacity(PACKET_HEADER_LEN + frame.len());
    packet.push(PACKET_SEIPD);
    packet.push(PACKET_FIVE_OCTET_LENGTH);
    packet.extend_from_slice(&body_len.to_be_bytes());
    packet.push(PACKET_VERSION);
    packet.extend_from_slice(frame);
    packet
}

/// Достаёт кадр из пакета — обратное к [`packet`].
///
/// # Errors
///
/// [`MessageError::NotOurPacket`], если это не наш пакет. Не ошибка
/// и не повод для тревоги: ящик открыт всему миру, и настоящее письмо
/// Delta Chat приедет в таком же конверте с настоящим OpenPGP внутри.
fn unpacket(packet: &[u8]) -> Result<Vec<u8>, MessageError> {
    if packet.len() < PACKET_HEADER_LEN
        || packet[0] != PACKET_SEIPD
        || packet[1] != PACKET_FIVE_OCTET_LENGTH
        || packet[6] != PACKET_VERSION
    {
        return Err(MessageError::NotOurPacket);
    }
    let declared = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
    // Заявленная длина сверяется с настоящей: разойдись они, кадр приехал
    // бы обрезанным или с хвостом, а тег AEAD сказал бы об этом невнятно —
    // «не расшифровалось», без указания на причину.
    if declared != packet.len() - PACKET_HEADER_LEN + 1 {
        return Err(MessageError::NotOurPacket);
    }
    Ok(packet[PACKET_HEADER_LEN..].to_vec())
}

/// Контрольная сумма брони (RFC 4880, §6.1).
///
/// Настоящая, а не заглушка: разборщик, который её проверяет, на выдуманной
/// отвергнет всё письмо, и найдётся это не у нас, а у собеседника.
fn crc24(data: &[u8]) -> [u8; 3] {
    let mut crc: u32 = 0x00B7_04CE;
    for byte in data {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    let crc = crc & 0x00FF_FFFF;
    [(crc >> 16) as u8, (crc >> 8) as u8, crc as u8]
}

/// Разбирает письмо обратно в кадры.
///
/// Заголовки не читаются вовсе, и это не лень. Верить в них нечему:
/// `From` подделывается, `Subject` мог поправить сервер, а кто прислал
/// кадр — устанавливает рукопожатие (§8.2), а не почтовый заголовок.
///
/// Разборщика MIME здесь тоже нет, и это не упрощение: границы частей
/// сервер вправе переписать, а броня OpenPGP размечает себя сама. Ищем
/// её — и только её.
///
/// Контрольная сумма брони **не проверяется**. Целостность утверждает тег
/// AEAD нашего кадра (§7.3), и он говорит строго больше: CRC-24 ловит
/// случайную порчу, тег — любую, включая подделанную. Отвергать кадр
/// по слабой проверке до сильной значило бы завести второй источник правды
/// о целостности, а он однажды разойдётся с первым.
///
/// # Errors
///
/// [`MessageError`] — что именно не так с письмом.
pub fn parse_message(message: &[u8]) -> Result<Vec<Vec<u8>>, MessageError> {
    if too_large(message.len()) {
        return Err(MessageError::TooLarge);
    }
    let text = core::str::from_utf8(message).map_err(|_| MessageError::NotBase64)?;
    // Переводы строк приводятся к одному виду до всякого разбора: письмо
    // могло пройти через узел, переписавший CRLF в LF.
    let normalized = text.replace("\r\n", "\n");

    let mut frames = Vec::new();
    let mut rest = normalized.as_str();
    while let Some(start) = rest.find(ARMOR_BEGIN) {
        let after = &rest[start + ARMOR_BEGIN.len()..];
        let Some(end) = after.find(ARMOR_END) else {
            return Err(MessageError::NoBody);
        };
        frames.push(unarmor(&after[..end])?);
        rest = &after[end + ARMOR_END.len()..];
    }

    if frames.is_empty() {
        return Err(MessageError::NoBody);
    }
    Ok(frames)
}

/// Достаёт кадр из тела брони — того, что лежит между `BEGIN` и `END`.
fn unarmor(inside: &str) -> Result<Vec<u8>, MessageError> {
    // Заголовки брони (если они есть) отделены от данных пустой строкой.
    // Своих мы не пишем, но чужие письма могут прийти и с ними.
    let data = match inside.trim_start_matches('\n').split_once("\n\n") {
        Some((_, data)) => data,
        None => inside,
    };
    let encoded: String = data
        .lines()
        // Строка контрольной суммы начинается с `=`; в самом base64 такой
        // строки быть не может — `=` там только в конце последней четвёрки.
        .filter(|line| !line.trim_start().starts_with('='))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    if encoded.is_empty() {
        return Err(MessageError::Empty);
    }
    let packet =
        data_encoding::BASE64.decode(encoded.as_bytes()).map_err(|_| MessageError::NotBase64)?;
    unpacket(&packet)
}

/// Разбивает строку base64 на строки по [`LINE_LEN`].
fn wrap(encoded: &str) -> String {
    encoded
        .as_bytes()
        .chunks(LINE_LEN)
        .map(|chunk| core::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_is_constant() {
        // Переменная тема была бы метаданными в открытом виде, а
        // постоянная и говорящая — метаданными о том, чем письмо написано.
        assert_eq!(SUBJECT, "[...]");
    }

    #[test]
    fn a_letter_with_a_chunk_fits_the_limit() {
        // Раньше здесь стояло `MAX_MESSAGE_BYTES == MAIL_FILE_LIMIT_BYTES`,
        // и равенство было верным по случайности: файл почтой **был** одним
        // письмом. Теперь файл — сотня писем, числа разошлись, и проверять
        // надо другое.
        //
        // А именно: письмо с чанком обязано помещаться в предел. Иначе файлы
        // почтой не пошли бы вовсе, и узналось бы это отказом сервера
        // на первом же куске — на стенде, а не здесь.
        //
        // Считается на настоящей сборке, а не по формуле: `letter_bytes`
        // и есть та формула, и сверять её с самой собой бессмысленно.
        let frame = vec![0u8; ratatosk_wire::SizeClass::L.frame_len()];
        let message = build_message("a@nine.example", "b@nine.example", &[frame]).unwrap();
        assert!(
            message.len() as u64 <= MAX_MESSAGE_BYTES,
            "письмо с чанком — {} байт при пределе {MAX_MESSAGE_BYTES}",
            message.len()
        );
        // И оценка ядра обязана быть оценкой сверху: по ней ядро считает,
        // сколько чужого ящика занимает окно. Оценка снизу означала бы,
        // что мы обещаем собеседнику меньше, чем занимаем.
        let estimate = ratatosk_proto::files::letter_bytes(ratatosk_wire::SizeClass::L.frame_len());
        assert!(
            estimate >= message.len(),
            "оценка {estimate} меньше настоящего письма {}",
            message.len()
        );
    }

    #[test]
    fn frames_survive_the_round_trip() {
        let frames = vec![vec![7u8; 4096], vec![9u8; 100], vec![0u8, 255u8, 128u8]];
        let message = build_message("a@nine.example", "b@nine.example", &frames).unwrap();
        assert_eq!(parse_message(message.as_bytes()).unwrap(), frames);
    }

    #[test]
    fn the_envelope_is_the_one_the_server_asks_for() {
        // Разбор настоящего отказа: chatmail-сервер не пересылает
        // незашифрованную почту и проверяет **форму** — конверт RFC 3156.
        // Письмо в виде голого `application/octet-stream` он отвергал
        // словами «523 Encryption Needed: Invalid Unencrypted Mail».
        let message = build_message("a@nine.example", "b@nine.example", &[vec![1u8; 64]]).unwrap();
        assert!(message.contains("Content-Type: multipart/encrypted;"));
        assert!(message.contains("protocol=\"application/pgp-encrypted\""));
        // Первая часть — опознание версии, ровно как в RFC 3156.
        assert!(message.contains("Content-Type: application/pgp-encrypted; charset=\"utf-8\""));
        // Тело первой части — ровно `Version: 1`, без лишней пустой строки.
        // Перевод строки перед границей принадлежит границе (RFC 2046),
        // и лишний давал бы разборщику тело `"Version: 1\r\n"` вместо
        // `"Version: 1"`. Проверяющий равенство на этом и споткнётся.
        assert!(message.contains(&format!("\r\n\r\nVersion: 1\r\n--{BOUNDARY}\r\n")));
        // Обе части объявлены `7bit`, как у Delta Chat: base64 и броня
        // семибитны, и сказать это прямо дешевле, чем полагаться
        // на умолчание у каждого узла по пути.
        assert_eq!(
            message.matches("Content-Transfer-Encoding: 7bit").count(),
            2,
            "обе части обязаны объявить кодировку"
        );
        // Вторая — «шифротекст», и внутри наша броня.
        assert!(message.contains(ARMOR_BEGIN));
        assert!(message.contains(ARMOR_END));
        assert!(message.trim_end().ends_with(&format!("--{BOUNDARY}--")));
    }

    #[test]
    fn the_headers_say_nothing_about_the_conversation() {
        // Всё, что попадает в заголовки, сервер видит открытым. Тема —
        // постоянная, и больше в шапке нет ничего, чего там быть не должно.
        let message = build_message("a@nine.example", "b@nine.example", &[vec![1u8; 8]]).unwrap();
        let head = message.split("\r\n\r\n").next().unwrap();
        assert!(head.contains(&format!("Subject: {SUBJECT}")));
        for forbidden in ["Date:", "Message-ID:", "User-Agent:", "X-"] {
            assert!(!head.contains(forbidden), "лишний заголовок {forbidden}: {head}");
        }
    }

    #[test]
    fn a_line_never_grows_past_the_rfc_limit() {
        // Длинные строки почтовые узлы вправе рвать сами, и порванная
        // не на границе четвёрки base64 строка приезжает мусором.
        // Проверяется тело брони: заголовок `Content-Type` длиннее,
        // и это законно — рвать заголовки по правилам умеют все.
        let message =
            build_message("a@nine.example", "b@nine.example", &[vec![3u8; 5000]]).unwrap();
        let inside = message.split_once(ARMOR_BEGIN).unwrap().1.split_once(ARMOR_END).unwrap().0;
        for line in inside.split("\r\n") {
            assert!(line.len() <= LINE_LEN, "строка длиннее предела RFC 2045: {}", line.len());
        }
    }

    #[test]
    fn a_message_that_lost_its_crlf_still_parses() {
        // Письмо могло пройти через узел, переписавший переводы строк.
        let message = build_message("a@nine.example", "b@nine.example", &[vec![5u8; 200]]).unwrap();
        let mangled = message.replace("\r\n", "\n");
        assert_eq!(parse_message(mangled.as_bytes()).unwrap(), vec![vec![5u8; 200]]);
    }

    #[test]
    fn armor_headers_from_someone_else_do_not_confuse_us() {
        // Своих заголовков брони мы не пишем, но чужое письмо вправе их
        // иметь: RFC 4880 отделяет их от данных пустой строкой.
        let frame = vec![42u8; 90];
        let encoded = wrap(&data_encoding::BASE64.encode(&packet(&frame)));
        let letter = format!(
            "Subject: x\r\n\r\n{ARMOR_BEGIN}\r\nVersion: OpenPrivacy 0.99\r\nComment: чужой\
             \r\n\r\n{encoded}\r\n=twTO\r\n{ARMOR_END}\r\n"
        );
        assert_eq!(parse_message(letter.as_bytes()).unwrap(), vec![frame]);
    }

    #[test]
    fn the_frame_travels_inside_a_real_openpgp_packet() {
        // Фильтр chatmail-сервера снимает броню, декодирует base64 и идёт
        // по цепочке пакетов OpenPGP: длины обязаны сойтись до последнего
        // байта, а последний пакет — оказаться SEIPD (тип 18). Голый кадр
        // не проходил на первом же байте, и отказ выглядел так же, как
        // отказ из-за конверта, — то есть ни на что не указывал.
        let frame = vec![9u8; 4096];
        let packet = packet(&frame);

        assert_eq!(packet[0] & 0xC0, 0xC0, "современный формат пакета");
        assert_eq!(packet[0] & 0x3F, 18, "SEIPD");
        assert_eq!(packet[1], 0xFF, "пятибайтовая длина");
        let declared = u32::from_be_bytes([packet[2], packet[3], packet[4], packet[5]]) as usize;
        assert_eq!(
            declared,
            packet.len() - 6,
            "длина тела обязана сойтись с настоящей до байта: расхождение фильтр отвергнет молча"
        );
        assert_eq!(packet[6], 1, "версия SEIPD");
        assert_eq!(unpacket(&packet).unwrap(), frame);
    }

    #[test]
    fn a_letter_from_a_real_pgp_client_is_not_ours() {
        // Ящик открыт всему миру, и настоящее письмо Delta Chat приедет
        // в точно таком же конверте — с настоящим OpenPGP внутри.
        // Спутать их нельзя: наши кадры расшифровываются нашим ключом,
        // а чужой пакет надо отличить здесь и молча.
        let foreign = data_encoding::BASE64.encode(b"\x85\x01\x0cRSA-...");
        let letter = format!("{ARMOR_BEGIN}\r\n\r\n{foreign}\r\n=twTO\r\n{ARMOR_END}\r\n");
        assert_eq!(parse_message(letter.as_bytes()), Err(MessageError::NotOurPacket));
    }

    #[test]
    fn a_packet_whose_length_does_not_match_is_refused() {
        // Обрезанный по дороге пакет тег AEAD отверг бы невнятно —
        // «не расшифровалось», без указания на причину. Здесь причина
        // ещё видна.
        let mut short = packet(&[7u8; 32]);
        short.truncate(short.len() - 4);
        assert_eq!(unpacket(&short), Err(MessageError::NotOurPacket));
    }

    #[test]
    fn the_checksum_line_is_not_taken_for_data() {
        // Строка контрольной суммы начинается с `=`, и попади она в base64
        // — кадр приехал бы длиннее на три байта и не расшифровался.
        let frame = vec![1u8, 2u8, 3u8];
        let letter = build_message("a@nine.example", "b@nine.example", &[frame.clone()]).unwrap();
        assert!(letter.contains("\r\n="), "броня обязана нести контрольную сумму");
        assert_eq!(parse_message(letter.as_bytes()).unwrap(), vec![frame]);
    }

    #[test]
    fn the_checksum_of_nothing_is_the_initial_value() {
        // CRC-24 из RFC 4880 начинается с 0xB704CE, и на пустом входе
        // остаётся им же. Отсюда всем известное `=twTO` у пустой брони —
        // единственная точка, по которой начальное значение сверяется
        // с чужим кодом, а не с самим собой.
        assert_eq!(crc24(&[]), [0xB7, 0x04, 0xCE]);
        assert_eq!(data_encoding::BASE64.encode(&crc24(&[])), "twTO");
    }

    #[test]
    fn rubbish_is_refused_rather_than_guessed_at() {
        // Письмо без брони — не наше: молча вернуть из него ноль кадров
        // значило бы принять чужую почту за свою испорченную.
        assert_eq!(parse_message(b"Subject: Ratatosk"), Err(MessageError::NoBody));
        assert_eq!(parse_message(b"Subject: x\r\n\r\nprivet"), Err(MessageError::NoBody));
        // Броня началась и не кончилась — письмо обрезано по дороге.
        let cut = format!("Subject: x\r\n\r\n{ARMOR_BEGIN}\r\n\r\nAAAA\r\n");
        assert_eq!(parse_message(cut.as_bytes()), Err(MessageError::NoBody));
        // Броня есть, а внутри не base64.
        let junk = format!("{ARMOR_BEGIN}\r\n\r\n!!!!\r\n{ARMOR_END}\r\n");
        assert_eq!(parse_message(junk.as_bytes()), Err(MessageError::NotBase64));
        // Броня есть, а внутри ничего.
        let hollow = format!("{ARMOR_BEGIN}\r\n\r\n{ARMOR_END}\r\n");
        assert_eq!(parse_message(hollow.as_bytes()), Err(MessageError::Empty));
    }

    #[test]
    fn an_empty_letter_is_not_sent_at_all() {
        // Пустое письмо — трафик и запись в журнале сервера без единого
        // байта пользы.
        assert_eq!(
            build_message("a@nine.example", "b@nine.example", &[]),
            Err(MessageError::Empty)
        );
    }
}
