//! Поход за публичным перечнем chatmail-серверов.
//!
//! # Зачем это вообще
//!
//! Чтобы завести ящик, надо назвать сервер — а человеку, который не знает
//! слова «chatmail», назвать его нечем. Серверов в сборке нет и не будет:
//! сервер видит адрес ящика и то, с кем и когда он переписывается,
//! и выбирать его за человека нельзя. Здесь только **приносится перечень,
//! из которого он выбирает** — тем же путём, каким приносятся пиры меша
//! и реле nostr.
//!
//! # Tor
//!
//! Через Tor поход **идёт, когда тот поднят**, иначе прямо — как у списка
//! пиров. Условием Tor не сделан нарочно: вопрос «какие серверы бывают»
//! ящика ещё не касается, а требование лишило бы перечня тех, кто возит
//! почту напрямую. Что источник при прямом походе видит адрес устройства,
//! человеку сказано до нажатия (`MAIL_SERVER_SOURCE_NOTICE`, §14).
//!
//! Сама регистрация и ящик — другое дело: там путь выбирает человек
//! (`via_tor`), и к этому походу его выбор не относится.
//!
//! # Чего здесь нет
//!
//! Ни кэша, ни расписания, ни повторов, ни проверки серверов: перечень
//! спрашивается, когда человек нажал. Жив ли сервер и заведёт ли он ящик,
//! покажет регистрация — стучаться в два десятка чужих серверов от имени
//! человека, чтобы показать ему галочки, было бы хуже, чем не знать.

use super::http;
use ratatosk_proto::mail::{self, MailServer, MailServerListError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Сколько ждём ответа. Через Tor секунды здесь — норма; предел нужен,
/// чтобы окно не висело вечно.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

/// Приносит перечень серверов в порядке источника.
///
/// # Errors
///
/// [`MailServerListError::SourceSilent`] — источник не ответил, срок вышел
/// или ответил отказом. [`MailServerListError::FormatChanged`] — ответ
/// пришёл, а серверов в нём нет.
pub async fn fetch(tor: &crate::onion::TorHandle) -> Result<Vec<MailServer>, MailServerListError> {
    let page = match tokio::time::timeout(DEADLINE, ask(tor)).await {
        Ok(result) => result?,
        Err(_) => return Err(MailServerListError::SourceSilent),
    };
    let servers = mail::mail_servers_from_page(&String::from_utf8_lossy(&page));
    if servers.is_empty() {
        // Пустой перечень — не успех: пустой эту страницу не держат,
        // значит сменилась её разметка, а наш разбор отстал. Выданный
        // за успех, он читался бы как «серверов нет».
        return Err(MailServerListError::FormatChanged);
    }
    Ok(servers)
}

/// Один запрос: соединиться, спросить, дочитать.
async fn ask(tor: &crate::onion::TorHandle) -> Result<Vec<u8>, MailServerListError> {
    // Соединение, TLS, запись, чтение — до ответа дело не дошло.
    const SILENT: MailServerListError = MailServerListError::SourceSilent;
    // Спрашивается **поднятость**, а не признак сборки: собранный,
    // но ещё не поднявшийся Tor дал бы отказ там, где прямой запрос
    // прошёл бы.
    let via_tor = tor.is_up();
    let mut stream = crate::tls::connect(mail::MAIL_SERVER_LIST_HOST, 443, via_tor, tor)
        .await
        .map_err(|_| SILENT)?;
    let request = http::get(mail::MAIL_SERVER_LIST_HOST, mail::MAIL_SERVER_LIST_PATH, None, ACCEPT);
    stream.write_all(request.as_bytes()).await.map_err(|_| SILENT)?;
    stream.flush().await.map_err(|_| SILENT)?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|_| SILENT)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        // Предел проверяется по ходу: чужой сервер вправе отдать гигабайт,
        // и дочитывать его, чтобы потом отвергнуть, незачем.
        if response.len() > http::MAX_RESPONSE_BYTES {
            return Err(MailServerListError::FormatChanged);
        }
    }
    http::body(&response).map_err(|error| match error {
        // Код ответа — источник отказал; ждать или назвать сервер самому.
        http::HttpError::Status { .. } => MailServerListError::SourceSilent,
        // Не HTTP, оборван или больше предела — ответил не тем.
        _ => MailServerListError::FormatChanged,
    })
}

/// Что просим в ответ: страница — HTML, и ничего другого источник не отдаёт.
const ACCEPT: &str = "text/html";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_names_the_source_and_nothing_about_us() {
        let request =
            http::get(mail::MAIL_SERVER_LIST_HOST, mail::MAIL_SERVER_LIST_PATH, None, ACCEPT);
        assert!(request.starts_with("GET /relays HTTP/1.1\r\n"), "{request}");
        assert!(request.contains("Host: chatmail.at\r\n"), "{request}");
        assert!(request.contains("Accept: text/html\r\n"), "{request}");
        // Имени клиента в запросе нет: источнику незачем знать, каким
        // приложением его спрашивают.
        assert!(!request.contains("User-Agent"), "{request}");
        assert!(request.ends_with("\r\n\r\n"));
    }

    // **Чего эта проверка не стережёт.** Что страница и правда размечена
    // так, как её читает разбор, — это проверено живым походом, а не
    // прогоном: сеть здесь не зовётся. Сменит источник разметку — прогон
    // смолчит, а поход честно ответит `FormatChanged`.
}
