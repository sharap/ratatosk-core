//! TLS до почтового сервера — и путь к нему, прямой или через Tor (§5.3).
//!
//! # Один шифрованный слой, два пути под ним
//!
//! Выше TLS всё одинаково: SMTP, IMAP и поход за ящиком не знают, чем открыт
//! поток. Ниже — два случая: обычный сокет ОС и поток arti. Разделение
//! проходит ровно по одной функции ([`dial`]), и это не украшение —
//! так проверено на отдельном стенде, где оба пути отработали одним и тем же
//! кодом выше сокета.
//!
//! # Корневые сертификаты — свои, а не системные
//!
//! `webpki-roots` вместо хранилища ОС. Причин две. Первая: на Android
//! системное хранилище доступно через JNI, то есть транспорту пришлось бы
//! знать про платформу — ровно того, чего §13.1 избегает. Вторая: набор
//! корней у нас одинаков везде, и «на этом телефоне не работает, а на том
//! работает» перестаёт быть возможным исходом.
//!
//! Цена названа честно: корпоративный корень, добавленный человеком в систему,
//! мы не увидим. Для chatmail-серверов с обычными сертификатами это
//! безразлично, для сервера за корпоративным перехватом — нет.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::runner::TransportError;

/// Поток до сервера, чем бы он ни был открыт.
///
/// Тип-объект, а не обобщение: выше TLS путь безразличен, и таскать параметр
/// типа через SMTP, IMAP и HTTP значило бы объявить его значимым там,
/// где он не значим. Цена — одна виртуальная таблица на соединение, то есть
/// ничто на фоне трёх реле Tor.
pub type Plain = Box<dyn Stream>;

/// То, что умеет поток: читать, писать и печататься в журнал.
///
/// `Debug` здесь не роскошь: `async-imap` требует его от своего потока,
/// и без него `Client::new` не соберётся.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug + Send> Stream for T {}

/// Открывает поток до сервера — прямо или через Tor.
///
/// # Errors
///
/// [`TransportError::Unavailable`], если путь через Tor выбран, а Tor
/// не поднят или не собран: обещать соединение, которого не будет, нельзя.
/// [`TransportError::Io`] — отказ самого соединения.
#[allow(unused_variables)]
pub async fn dial(
    host: &str,
    port: u16,
    via_tor: bool,
    tor: &crate::onion::TorHandle,
) -> Result<Plain, TransportError> {
    if !via_tor {
        let tcp = TcpStream::connect((host, port)).await?;
        // Нагла: почтовые протоколы построчные, и склеивание мелких строк
        // в один пакет добавляет к каждой команде задержку подтверждения.
        let _ = tcp.set_nodelay(true);
        return Ok(Box::new(tcp));
    }

    #[cfg(feature = "onion-arti")]
    {
        use tokio_util::compat::FuturesAsyncReadCompatExt;

        let Some(client) = tor.client() else {
            return Err(TransportError::Unavailable);
        };
        let stream = client
            .connect((host, port))
            .await
            .map_err(|error| TransportError::Refused(format!("Tor не открыл поток: {error}")))?;
        // Полным путём намеренно: поток arti может реализовать и трейты
        // futures, и трейты tokio, — и тогда короткое `.compat()` стало бы
        // неоднозначным. Проверено на отдельном стенде.
        Ok(Box::new(FuturesAsyncReadCompatExt::compat(stream)))
    }
    #[cfg(not(feature = "onion-arti"))]
    {
        Err(TransportError::Unavailable)
    }
}

/// Заворачивает поток в TLS.
///
/// # Errors
///
/// [`TransportError::Refused`] на негодном имени сервера или неудавшемся
/// рукопожатии TLS.
pub async fn wrap(
    host: &str,
    stream: Plain,
) -> Result<tokio_rustls::client::TlsStream<Plain>, TransportError> {
    let connector = tokio_rustls::TlsConnector::from(config());
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| TransportError::Refused(format!("имя сервера не годится: {host}")))?;
    connector
        .connect(name, stream)
        .await
        .map_err(|error| TransportError::Refused(format!("TLS не установился: {error}")))
}

/// Настройки TLS — одни на всё приложение.
///
/// Собираются один раз: разбор трёх сотен корневых сертификатов на каждое
/// соединение — заметная работа, а меняться им между соединениями незачем.
fn config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth(),
        )
    }))
}

/// Открывает поток и сразу заворачивает его в TLS.
///
/// # Errors
///
/// То же, что у [`dial`] и [`wrap`].
pub async fn connect(
    host: &str,
    port: u16,
    via_tor: bool,
    tor: &crate::onion::TorHandle,
) -> Result<tokio_rustls::client::TlsStream<Plain>, TransportError> {
    let plain = dial(host, port, via_tor, tor).await?;
    wrap(host, plain).await
}
