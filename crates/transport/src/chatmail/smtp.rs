//! Отправка письма: вход на сервер и `DATA` (§5.3).
//!
//! # Соединение живёт между письмами
//!
//! Вход на chatmail-сервер стоит одного TLS-рукопожатия и одного `AUTH`,
//! а через Tor — ещё и построения цепочки. Открывать всё это на каждое
//! сообщение значило бы платить десятками секунд за каждую реплику
//! в переписке. Поэтому [`Sender`] держит соединение открытым и переоткрывает
//! его только тогда, когда оно оборвалось.
//!
//! Оборвётся оно обязательно: почтовые серверы закрывают простаивающие
//! соединения через минуты, и это штатное поведение, а не отказ. Поэтому
//! [`Sender::send`] умеет ровно одну повторную попытку — переоткрыть
//! и отправить снова. Ровно одну: если не вышло и на свежем соединении,
//! дело не в простое, и §5.4 обязан узнать об этом сейчас, а не после
//! третьего круга.
//!
//! # Почему `auth`, а не `try_login`
//!
//! У `async-smtp` есть готовый `try_login`, и он делает почти то, что нужно.
//! Почти: не найдя среди предложенных сервером ни одного знакомого механизма,
//! он возвращает **успех** — «делать было нечего». Для нас это худший из
//! возможных ответов: «вошли» и «не пробовали входить» для §5.4 разные вещи,
//! и молчаливое второе означало бы почту, объявленную работающей, которая
//! отвергнет первое же письмо.
//!
//! Поэтому механизм называется прямо. Сначала `PLAIN` — его понимают все
//! chatmail-серверы, — а на отказ `LOGIN`, потому что отказать сервер может
//! и по причине «такого механизма не предлагаю». Не вышло оба раза — это
//! настоящий отказ входа, и он едет человеку словами.

use tokio::io::BufStream;

use ratatosk_proto::mail::MailAccount;

use crate::chatmail::tls::{self, Plain};
use crate::onion::TorHandle;
use crate::runner::TransportError;

/// Поток, каким его видит `async-smtp`.
///
/// `BufStream` не украшение: `SmtpTransport` требует от потока построчного
/// чтения (`AsyncBufRead`), а TLS-поток его не даёт.
type Stream = BufStream<tokio_rustls::client::TlsStream<Plain>>;

/// Открытое соединение с почтовым сервером на отправку.
pub struct Sender {
    transport: async_smtp::SmtpTransport<Stream>,
    /// Предел одного письма, объявленный сервером (`SIZE`, RFC 1870).
    ///
    /// `None` — не объявлен, и это законно: RFC разрешает голое `SIZE`
    /// без числа. Трактуется как «подойдёт», а не как «ноль».
    max_letter_bytes: Option<u64>,
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sender(соединение открыто)")
    }
}

impl Sender {
    /// Открывает соединение и входит на сервер.
    ///
    /// # Errors
    ///
    /// [`TransportError::Refused`] с внятной причиной: не установился TLS,
    /// сервер не поздоровался, вход отвергнут. Все три человек читает
    /// по-разному, и все три надо показать словами, а не одним «почта
    /// не работает».
    pub async fn login(account: &MailAccount, tor: &TorHandle) -> Result<Sender, TransportError> {
        let stream =
            tls::connect(&account.smtp_host, account.smtp_port, account.via_tor, tor).await?;

        // Имя в `EHLO` остаётся умолчанием библиотеки — `[127.0.0.1]`.
        // Настоящее имя машины здесь было бы метаданными в открытом виде:
        // его видит и сервер, и всякий, кто смотрит на соединение до TLS
        // у другой стороны. Совместимость от этого не страдает: адрес
        // проходит проверки Postfix.
        let mut transport =
            async_smtp::SmtpTransport::new(async_smtp::SmtpClient::new(), BufStream::new(stream))
                .await
                .map_err(|error| {
                    TransportError::Refused(format!("SMTP не поздоровался: {error}"))
                })?;

        // `SIZE` спрашивается **до** входа, и оба слова здесь по делу.
        //
        // «Спрашивается» — потому что `async-smtp` ответ на свой `EHLO`
        // разбирает в `ServerInfo`, а `SIZE` в него не кладёт вовсе, и само
        // поле приватно. Второй `EHLO` законен (RFC 5321, 4.1.4) и стоит
        // одного круга за вход, который и так случается редко.
        //
        // «До входа» — потому что `EHLO` сбрасывает состояние сеанса. После
        // `AUTH` часть серверов считает сброшенным и его.
        let max_letter_bytes = probe_size(&mut transport).await;

        let credentials = async_smtp::authentication::Credentials::new(
            account.address.clone(),
            account.password.as_str().to_owned(),
        );

        let plain =
            transport.auth(async_smtp::authentication::Mechanism::Plain, &credentials).await;
        if let Err(first) = plain {
            let login =
                transport.auth(async_smtp::authentication::Mechanism::Login, &credentials).await;
            if let Err(second) = login {
                // Обе причины, а не последняя: сервер мог отвергнуть первый
                // механизм словами «не предлагаю», а второй — «пароль
                // не подходит», и это разные беды с разным лечением.
                return Err(TransportError::Refused(format!(
                    "вход на сервер отвергнут: PLAIN — {first}; LOGIN — {second}"
                )));
            }
        }
        Ok(Sender { transport, max_letter_bytes })
    }

    /// Предел письма, объявленный сервером.
    ///
    /// `None` — не объявлен. Это **наш** сервер: предел сервера получателя
    /// невидим и останется таким, письмо уходит релеем.
    #[must_use]
    pub const fn max_letter_bytes(&self) -> Option<u64> {
        self.max_letter_bytes
    }

    /// Отправляет письмо.
    ///
    /// Возвращается **после** того, как сервер принял письмо в свою очередь,
    /// — и только это даёт право сказать человеку «отправлено» (§9.4, 5аа).
    ///
    /// # Errors
    ///
    /// [`TransportError::Refused`] — адрес не годится или сервер письма
    /// не принял.
    pub async fn send(&mut self, from: &str, to: &str, body: &str) -> Result<(), TransportError> {
        // Свой предел проверяется до отправки, а не выясняется отказом.
        // Разница не в круге по сети, а во внятности: сервер отвечает
        // на слишком большое письмо кодом 552 с текстом на своё усмотрение,
        // и в журнале это выглядит как «сервер не принял письмо» — беда,
        // неотличимая от полудюжины других.
        if let Some(limit) = self.max_letter_bytes {
            let size = body.len() as u64;
            if size > limit {
                return Err(TransportError::Refused(format!(
                    "письмо на {size} байт не влезает в предел сервера {limit}"
                )));
            }
        }

        let envelope = async_smtp::Envelope::new(Some(address(from)?), vec![address(to)?])
            .map_err(|error| TransportError::Refused(format!("конверт не собрался: {error}")))?;

        self.transport.send(async_smtp::SendableEmail::new(envelope, body)).await.map_err(
            |error| TransportError::Refused(format!("сервер не принял письмо: {error}")),
        )?;
        Ok(())
    }
}

/// Спрашивает сервер о пределе письма вторым `EHLO`.
///
/// Отказ здесь — не отказ входа: не ответил, ответил невнятно, не объявил
/// `SIZE` — во всех трёх случаях `None`, то есть «предел неизвестен».
/// Считать неизвестный предел нулём значило бы сломать почту на всяком
/// сервере, который о себе молчит.
async fn probe_size(transport: &mut async_smtp::SmtpTransport<Stream>) -> Option<u64> {
    // Имя то же, что подставляет библиотека своему `EHLO`, — `[127.0.0.1]`.
    // Назови мы себя иначе, сервер увидел бы два разных приветствия
    // от одного соединения, и это лишний повод для его правил.
    let hello = async_smtp::extension::ClientId::new(
        async_smtp::extension::ClientId::default().to_string(),
    );
    let response = transport.get_mut().ehlo(hello).await.ok()?;
    size_of(&response)
}

/// Достаёт число из строки `SIZE …` в ответе на `EHLO` (RFC 1870).
fn size_of(response: &async_smtp::response::Response) -> Option<u64> {
    for line in &response.message {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("SIZE") {
            continue;
        }
        // Голое `SIZE` без числа RFC разрешает, и означает оно «предела
        // не называю». Это `None`, а не ноль, и разница здесь ровно между
        // «файлы поедут» и «почта не возит ничего».
        return parts.next().and_then(|value| value.parse::<u64>().ok());
    }
    None
}

/// Разбирает адрес для конверта SMTP.
///
/// Проверка тут не наша, а библиотечная, и она про одно: чтобы в команду
/// сервера не попало управляющих символов. Годность самого ящика решает
/// сервер, и решать её за него мы не беремся.
fn address(value: &str) -> Result<async_smtp::EmailAddress, TransportError> {
    value
        .parse()
        .map_err(|_| TransportError::Refused(format!("адрес не годится для письма: {value}")))
}

#[cfg(test)]
mod tests {
    use super::size_of;
    use async_smtp::response::{Category, Code, Detail, Response, Severity};

    fn ehlo(lines: &[&str]) -> Response {
        Response::new(
            Code::new(Severity::PositiveCompletion, Category::Unspecified4, Detail::Zero),
            lines.iter().map(|line| (*line).to_owned()).collect(),
        )
    }

    #[test]
    fn the_answer_a_real_stingy_server_gave() {
        // Снято со стенда `tarpit.fun` — нарочно скупого chatmail-сервера.
        // Оказалось, что скуп он ящиком, а не письмом: 30 МБ на письмо
        // не ограничивают ничего. Ради этого числа и заводился второй `EHLO`.
        let response = ehlo(&[
            "tarpit.fun",
            "PIPELINING",
            "SIZE 31457280",
            "VRFY",
            "ETRN",
            "AUTH PLAIN",
            "ENHANCEDSTATUSCODES",
            "8BITMIME",
            "DSN",
            "SMTPUTF8",
            "CHUNKING",
        ]);
        assert_eq!(size_of(&response), Some(31_457_280));
    }

    #[test]
    fn a_bare_size_means_no_limit_named() {
        // RFC 1870 разрешает объявить `SIZE` без числа. Прочти мы это как
        // ноль — почта перестала бы отправлять что бы то ни было.
        assert_eq!(size_of(&ehlo(&["mail.example", "SIZE", "8BITMIME"])), None);
        assert_eq!(size_of(&ehlo(&["mail.example", "SIZE нет"])), None);
        assert_eq!(size_of(&ehlo(&["mail.example", "8BITMIME"])), None);
    }

    #[test]
    fn a_word_starting_with_size_is_not_size() {
        // `SIZEX 5` — не наш ключ, и разбор по префиксу подсунул бы сюда
        // чужое число. Ключи ESMTP сравниваются целиком.
        assert_eq!(size_of(&ehlo(&["mail.example", "SIZEX 5"])), None);
    }
}
