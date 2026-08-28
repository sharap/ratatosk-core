//! Один HTTP-запрос: сходить на chatmail-сервер за новым ящиком (§5.3).
//!
//! # Почему свой, а не готовый клиент
//!
//! Запрос ровно один, без тела, без редиректов, без cookie и без keep-alive;
//! ответ — маленький JSON с двумя полями. Готовый HTTP-клиент принёс бы
//! в дерево пул соединений, разбор HTTP/2, свой TLS-стек и свою модель
//! рантайма — и всё это ради одной строки. §8.1 требует объяснять каждую
//! зависимость; объяснить эту было бы нечем.
//!
//! Вторая причина весомее первой: соединение к серверу мы открываем **сами**,
//! потому что оно может идти через Tor (поток arti, а не сокет ОС).
//! Клиенты, которые умеют произвольный транспорт, — это уже `hyper` с ручным
//! коннектором, и «готовое» в нём остаётся только название.
//!
//! # Что здесь есть и чего нет
//!
//! Здесь чистые функции: собрать запрос, разобрать ответ. Ни сокета, ни TLS,
//! ни времени — всё это уровнем выше, и потому весь разбор проверяем тестами
//! без сети.
//!
//! Из HTTP/1.1 поддержано ровно необходимое: код ответа, `Content-Length`,
//! `Transfer-Encoding: chunked` и «до конца потока». Ни сжатия, ни редиректов:
//! редирект на регистрации — это уже другой сервер, и молча ходить за паролем
//! туда, куда человек не просил, нельзя.

use crate::chatmail::json;

/// Предел размера ответа.
///
/// Ответ — две короткие строки. Мегабайт здесь означает, что мы пришли
/// не туда (страница с ошибкой, портал провайдера, чужой сервис), и читать
/// его до конца незачем: разбирать всё равно будет нечего.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Почему поход за ящиком не удался.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// Ответ не похож на HTTP.
    #[error("ответ сервера не похож на HTTP")]
    NotHttp,
    /// Сервер ответил кодом, отличным от 2xx.
    #[error("сервер ответил {code}")]
    Status {
        /// Код ответа.
        code: u16,
    },
    /// Редирект. Ходить за паролем на другой сервер молча нельзя.
    #[error("сервер перенаправляет на другой адрес — за паролем туда не ходим")]
    Redirect,
    /// Ответ длиннее [`MAX_RESPONSE_BYTES`] или заявленная длина не сходится.
    #[error("ответ сервера слишком велик или оборван")]
    BadLength,
    /// Тело есть, но в нём нет ни адреса, ни пароля.
    #[error("в ответе сервера нет адреса и пароля")]
    NoCredentials,
}

/// Собирает запрос за новым ящиком.
///
/// `POST`, потому что регистрация меняет состояние сервера, и `GET` для неё
/// был бы неправдой в протокольном смысле: такой запрос вправе повторить
/// кто угодно по дороге — прокси, кэш, сама библиотека. Chatmail-серверы
/// принимают оба, а нам дороже, чтобы повтор не завёл лишний ящик.
///
/// `Connection: close` — намеренно: соединение живёт ровно один запрос,
/// и это заодно делает «читать до конца потока» законным ответом на письмо
/// без `Content-Length`.
///
/// Заголовка `User-Agent` нет. Он сообщил бы серверу, каким мессенджером
/// пользуется человек, — а это ровно те метаданные, которых мы избегаем
/// в письмах (§5.3). Здесь то же самое и по той же причине.
#[must_use]
pub fn request(host: &str, path: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: application/json\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    )
}

/// Разбирает ответ и достаёт адрес с паролем.
///
/// # Errors
///
/// [`HttpError`] — что именно не так с ответом.
pub fn credentials(response: &[u8]) -> Result<(String, String), HttpError> {
    let body = body_of(response)?;
    // Тело разбирается как текст, а не как байты: JSON с адресом и паролем
    // — текст по определению, а битые байты здесь означают, что мы пришли
    // не туда.
    let text = core::str::from_utf8(&body).map_err(|_| HttpError::NoCredentials)?;
    let address = json::field(text, "email").or_else(|| json::field(text, "address"));
    let password = json::field(text, "password");
    match (address, password) {
        (Some(address), Some(password)) if !address.is_empty() && !password.is_empty() => {
            Ok((address, password))
        }
        _ => Err(HttpError::NoCredentials),
    }
}

/// Отделяет тело от заголовков, проверив код ответа.
fn body_of(response: &[u8]) -> Result<Vec<u8>, HttpError> {
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(HttpError::BadLength);
    }
    let split = find(response, b"\r\n\r\n").map(|at| (at, at + 4));
    let split = split.or_else(|| find(response, b"\n\n").map(|at| (at, at + 2)));
    let (head_end, body_start) = split.ok_or(HttpError::NotHttp)?;

    // Заголовки — текст; тело может быть чем угодно, поэтому режется байтами.
    let head = core::str::from_utf8(&response[..head_end]).map_err(|_| HttpError::NotHttp)?;
    let mut lines = head.split(|c| c == '\n').map(|line| line.trim_end_matches('\r'));

    let status = lines.next().ok_or(HttpError::NotHttp)?;
    let code = status_code(status)?;
    match code {
        200..=299 => {}
        // Редирект отдельной ошибкой: «сервер ответил 302» человеку ничего
        // не говорит, а «за паролем на другой адрес не ходим» — говорит.
        300..=399 => return Err(HttpError::Redirect),
        code => return Err(HttpError::Status { code }),
    }

    let body = &response[body_start..];
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        // Имена заголовков регистронезависимы (RFC 9110), и серверы этим
        // пользуются: `Content-Length`, `content-length`, `CONTENT-LENGTH`.
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => length = value.parse::<usize>().ok(),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }

    if chunked {
        return dechunk(body);
    }
    match length {
        Some(length) if length > body.len() => Err(HttpError::BadLength),
        Some(length) => Ok(body[..length].to_vec()),
        // Длины нет — читаем до конца потока. Это законно ровно потому,
        // что мы просили `Connection: close`.
        None => Ok(body.to_vec()),
    }
}

/// Склеивает тело, разбитое на куски (RFC 9112 §7.1).
///
/// Оно здесь не для полноты картины. Настоящий chatmail-сервер (nginx перед
/// приложением) отвечает на регистрацию **именно так**: `Transfer-Encoding:
/// chunked` и никакого `Content-Length`. Написанный вслепую разбор на этом
/// отказывал — и отказал бы на первом же живом запросе, потому что без длины
/// и без кусков тело взять неоткуда.
///
/// Формат прост: строка с шестнадцатеричной длиной, кусок, перевод строки,
/// и так до куска нулевой длины. Расширения после `;` в строке длины
/// отбрасываются, хвостовые заголовки после нулевого куска не читаются:
/// нам в них искать нечего.
fn dechunk(body: &[u8]) -> Result<Vec<u8>, HttpError> {
    let mut out = Vec::new();
    let mut rest = body;
    loop {
        let at = find(rest, b"\n").ok_or(HttpError::BadLength)?;
        let line = core::str::from_utf8(&rest[..at]).map_err(|_| HttpError::BadLength)?;
        // `trim` заодно снимает `\r`: разделитель по букве RFC — CRLF,
        // но узел по дороге мог переписать переводы строк.
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| HttpError::BadLength)?;
        rest = &rest[at + 1..];

        if size == 0 {
            return Ok(out);
        }
        if rest.len() < size {
            // Тело оборвано на середине куска. Дочитать нечего, а отдать
            // половину пароля хуже, чем не отдать ничего.
            return Err(HttpError::BadLength);
        }
        out.extend_from_slice(&rest[..size]);
        if out.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::BadLength);
        }
        rest = &rest[size..];

        let skip = if rest.starts_with(b"\r\n") {
            2
        } else if rest.starts_with(b"\n") {
            1
        } else {
            return Err(HttpError::BadLength);
        };
        rest = &rest[skip..];
    }
}

/// Код из строки состояния `HTTP/1.1 200 OK`.
fn status_code(status: &str) -> Result<u16, HttpError> {
    let mut parts = status.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(HttpError::NotHttp);
    }
    parts.next().and_then(|code| code.parse().ok()).ok_or(HttpError::NotHttp)
}

/// Первое вхождение подстроки в байтах.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(head: &str, body: &str) -> Vec<u8> {
        format!("{head}\r\n\r\n{body}").into_bytes()
    }

    /// Ответ с честной длиной: считать её руками в тесте — способ проверить
    /// арифметику вместо разбора.
    fn measured(status: &str, body: &str) -> Vec<u8> {
        response(&format!("{status}\r\nContent-Length: {}", body.len()), body)
    }

    #[test]
    fn the_request_says_nothing_about_who_is_asking() {
        // `User-Agent` сообщил бы каждому узлу по пути, каким мессенджером
        // пользуется человек. В письмах мы этого избегаем — здесь тоже.
        let request = request("chatmail.example", "/new");
        assert!(request.starts_with("POST /new HTTP/1.1\r\n"));
        assert!(request.contains("Host: chatmail.example\r\n"));
        for forbidden in ["User-Agent", "Cookie", "Referer"] {
            assert!(!request.contains(forbidden), "лишний заголовок {forbidden}: {request}");
        }
    }

    #[test]
    fn credentials_come_out_of_the_body() {
        let raw = measured(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json",
            "{\"email\": \"a7f3k9@chatmail.example\", \"password\": \"x\"}",
        );
        let (address, password) = credentials(&raw).unwrap();
        assert_eq!(address, "a7f3k9@chatmail.example");
        assert_eq!(password, "x");
    }

    #[test]
    fn a_server_that_calls_it_address_is_understood_too() {
        // Поля у разных сборок серверов называются по-разному, а разница
        // между `email` и `address` человеку ничего не объясняет.
        let raw = response(
            "HTTP/1.1 200 OK",
            "{\"address\":\"a@chatmail.example\",\"password\":\"sekret\"}",
        );
        assert_eq!(
            credentials(&raw).unwrap(),
            ("a@chatmail.example".to_owned(), "sekret".to_owned())
        );
    }

    #[test]
    fn the_answer_a_real_server_gives() {
        // Снято с настоящего сервера (nine.testrun.org, август 2026) и
        // переписано сюда буква в букву. Именно этот ответ поймал ошибку:
        // разбор, написанный вслепую, ждал `Content-Length`, а nginx перед
        // приложением отвечает кусками и длины не сообщает вовсе.
        //
        // Пароль тоже настоящей формы: `!72ft<T+:Gxg` — со знаками
        // препинания, потому что сервер выдаёт случайный набор символов.
        let body = "{\"email\": \"webx1x3q6@nine.testrun.org\", \
                    \"password\": \"!72ft<T+:Gxg\"}";
        let raw = format!(
            "HTTP/1.1 200 OK\r\n\
             Server: nginx\r\n\
             Date: Sun, 23 Aug 2026 06:26:41 GMT\r\n\
             Content-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\n\
             \r\n\
             {:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        let (address, password) = credentials(raw.as_bytes()).unwrap();
        assert_eq!(address, "webx1x3q6@nine.testrun.org");
        assert_eq!(password, "!72ft<T+:Gxg");
    }

    #[test]
    fn the_second_real_answer_with_a_trailing_newline() {
        // Второй ответ с того же сервера, и он поправил представление
        // о первом: кусок объявлен как `0x44` — 68 байт, — а самого JSON
        // ровно 67. Лишний байт это перевод строки, который приложение
        // дописывает в конец тела. Разбор его переживает: `json::field`
        // читает строку до закрывающей кавычки, а что идёт после тела,
        // ему безразлично.
        //
        // Пароль тоже стоит держать перед глазами: `@**1fdp@+_|;` —
        // вертикальная черта, точка с запятой, звёздочки. Никакой
        // обработки «как в оболочке» над этими байтами быть не должно.
        let body = "{\"email\": \"0i469f47n@nine.testrun.org\", \
                    \"password\": \"@**1fdp@+_|;\"}\n";
        assert_eq!(body.len(), 0x44, "длина куска с настоящего сервера");

        for terminator in ["\r\n", "\n"] {
            // Признак конца куска по букве RFC — CRLF, но в выводе стенда
            // между телом и нулевым куском пустой строки не было; значит
            // терпимость к голому LF здесь не «на всякий случай», а нужна.
            let raw = format!(
                "HTTP/1.1 200 OK\r\n\
                 Server: nginx\r\n\
                 Content-Type: application/json\r\n\
                 Transfer-Encoding: chunked\r\n\
                 Connection: close\r\n\
                 \r\n\
                 44\r\n{body}{terminator}0\r\n\r\n"
            );
            let (address, password) = credentials(raw.as_bytes()).unwrap();
            assert_eq!(address, "0i469f47n@nine.testrun.org");
            assert_eq!(password, "@**1fdp@+_|;");
        }
    }

    #[test]
    fn a_body_in_several_chunks_is_glued_back() {
        // Сервер вправе резать где угодно, в том числе посередине пароля.
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   12\r\n{\"email\":\"a@b.cd\",\r\n\
                   14\r\n\"password\":\"sekret\"}\r\n\
                   0\r\n\r\n";
        assert_eq!(
            credentials(raw.as_bytes()).unwrap(),
            ("a@b.cd".to_owned(), "sekret".to_owned())
        );
    }

    #[test]
    fn a_body_cut_off_mid_chunk_is_refused() {
        // Отдать половину пароля хуже, чем не отдать ничего: ящик,
        // в который не войти, человек будет чинить не с той стороны.
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   40\r\n{\"email\":\"a@b.cd\"";
        assert_eq!(credentials(raw.as_bytes()), Err(HttpError::BadLength));
    }

    #[test]
    fn a_refusal_keeps_its_code() {
        // «Сервер ответил 429» человек может понять и переждать; «не вышло»
        // не говорит ничего.
        let raw = response("HTTP/1.1 429 Too Many Requests", "поспите");
        assert_eq!(credentials(&raw), Err(HttpError::Status { code: 429 }));
    }

    #[test]
    fn a_redirect_is_not_followed() {
        // Ходить за паролем туда, куда человек не просил, нельзя — даже
        // если сервер вежливо предлагает.
        let raw = response("HTTP/1.1 302 Found\r\nLocation: https://evil.test/new", "");
        assert_eq!(credentials(&raw), Err(HttpError::Redirect));
    }

    #[test]
    fn a_truncated_body_is_refused_rather_than_half_read() {
        // Обрыв на середине пароля дал бы ящик, в который не войти,
        // и разбираться человек будет с почтой, а не с обрывом.
        let raw = response("HTTP/1.1 200 OK\r\nContent-Length: 500", "{\"email\":\"a@b.c\"}");
        assert_eq!(credentials(&raw), Err(HttpError::BadLength));
    }

    #[test]
    fn a_page_instead_of_json_is_not_guessed_at() {
        let cases: [(&[u8], HttpError); 3] = [
            (b"HTTP/1.1 200 OK\r\n\r\n<html>welcome</html>", HttpError::NoCredentials),
            (b"not http at all", HttpError::NotHttp),
            (b"MUMBLE 200 OK\r\n\r\n{}", HttpError::NotHttp),
        ];
        for (raw, expected) in cases {
            assert_eq!(credentials(raw), Err(expected), "ответ {:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn a_header_written_in_any_case_is_still_a_header() {
        // Имена заголовков регистронезависимы, и серверы этим пользуются.
        let body = "{\"email\":\"a@b.cd\",\"password\":\"sekret\"}";
        let raw = response(&format!("HTTP/1.1 200 OK\r\ncontent-length: {}", body.len()), body);
        assert!(credentials(&raw).is_ok(), "заголовок в нижнем регистре обязан считаться");
    }
}
