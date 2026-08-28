//! Приём писем: вход, выборка, разбор и уборка ящика (§5.3).
//!
//! # Ждём, а не опрашиваем
//!
//! §5.3 называет `IMAP IDLE`, и причина не в изяществе: опрос раз в минуту
//! на телефоне — это минутные пробуждения радиомодуля круглые сутки (§13.1),
//! а письмо всё равно приходит в среднем на полминуты позже, чем могло бы.
//! `IDLE` держит одно соединение и молчит, пока сервер не скажет, что что-то
//! появилось.
//!
//! Соединение при этом надо пересоздавать не реже чем раз в 29 минут — иначе
//! сервер вправе счесть клиента уснувшим и разорвать связь. Это делает
//! библиотека (`Handle::wait`), и полагаться на нас тут нечему; но знать
//! стоит, потому что «раз в полчаса пересоединяется» — не поломка.
//!
//! Сервер может не уметь `IDLE`. Тогда остаётся опрос, и он честно медленнее:
//! письмо ждёт до [`POLL_INTERVAL`].
//!
//! # Ящик после нас пустеет
//!
//! Разобранные письма удаляются, и это не уборка ради порядка. Прочитанное
//! письмо, оставшееся на сервере, — это наш кадр, лежащий у чужой стороны
//! неограниченно долго: содержимое ей не прочесть, но сам факт переписки,
//! её время и объём остаются в её распоряжении (§2.2). Чем меньше времени
//! оно там лежит, тем меньше цена.
//!
//! **Чужое письмо не удаляется никогда.** Ящик открыт всему миру, и в него
//! может прийти настоящая почта — от Delta Chat, от человека, от службы
//! сервера. Стереть её потому, что мы не смогли её разобрать, значило бы
//! уничтожить чужое сообщение по своей неспособности его прочесть. Такие
//! письма получают отметку «прочитано», чтобы не приезжать снова, и остаются
//! лежать.
//!
//! # Порядок: сперва отдать, потом удалить
//!
//! Кадры уезжают в ядро **до** того, как письмо помечено к удалению. Обрыв
//! между этими шагами означает, что письмо приедет ещё раз, — а точный
//! повтор кадра штатен по §9.2 и §7.3: ретчет отвергает его по построению.
//! Обратный порядок означал бы потерянное сообщение при том же обрыве,
//! и потеря была бы тихой.

use futures::TryStreamExt;

use ratatosk_proto::mail::MailAccount;
use ratatosk_proto::Transport;

use crate::chatmail::parse_message;
use crate::chatmail::tls::{self, Plain};
use crate::onion::TorHandle;
use crate::runner::{TransportError, TransportEvent};

/// Как часто заглядывать в ящик, если сервер не умеет `IDLE`.
pub const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Ящик, в котором лежит входящая почта.
///
/// Имя задано RFC 3501 и одинаково у всех серверов; папок мы не заводим
/// и не читаем — письмо живёт в ящике секунды.
const INBOX: &str = "INBOX";

/// Поток до сервера, каким его видит `async-imap`.
type Stream = tokio_rustls::client::TlsStream<Plain>;

/// Открытая сессия IMAP.
pub struct Receiver {
    session: async_imap::Session<Stream>,
    /// Умеет ли сервер `IDLE`.
    ///
    /// Спрашивается один раз при входе, а не выясняется отказом. Отказ
    /// пришлось бы разбирать посреди ожидания, где сессия уже отдана
    /// во владение ручке `IDLE` и вернуть её оттуда нечем, — то есть
    /// платить полным переподключением за каждую проверку.
    idle: bool,
    /// Умеет ли сервер `QUOTA` (RFC 2087).
    ///
    /// Спрашивается тем же одним запросом способностей, что и `IDLE`.
    /// Не умеет — значит объём ящика нам неизвестен, и это законное
    /// состояние, а не отказ: `GETQUOTAROOT` у такого сервера ответил бы
    /// ошибкой, которую пришлось бы отличать от настоящих.
    quota: bool,
}

/// Сколько байт в единице квоты `STORAGE`.
///
/// RFC 2087 считает `STORAGE` в килобайтах — «units of 1024 octets».
/// Без этого множителя ящик `tarpit.fun` на 204800 выглядел бы
/// двухсоткилобайтным, то есть переполненным всегда.
const QUOTA_UNIT: u64 = 1024;

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Receiver(соединение открыто)")
    }
}

impl Receiver {
    /// Открывает соединение, входит на сервер и выбирает ящик.
    ///
    /// # Errors
    ///
    /// [`TransportError::Refused`] с внятной причиной: не установился TLS,
    /// сервер не поздоровался, вход отвергнут, ящика нет.
    pub async fn login(account: &MailAccount, tor: &TorHandle) -> Result<Receiver, TransportError> {
        let stream =
            tls::connect(&account.imap_host, account.imap_port, account.via_tor, tor).await?;

        let mut client = async_imap::Client::new(stream);
        // Приветствие читается обязательно и до всего остального: пока оно
        // не снято с потока, сервер считает, что разговор не начался,
        // и следующая команда встанет в очередь за ним.
        client
            .read_response()
            .await
            .map_err(|error| TransportError::Refused(format!("IMAP не ответил: {error}")))?
            .ok_or_else(|| TransportError::Refused("IMAP молчит вместо приветствия".to_owned()))?;

        let mut session = client
            .login(&account.address, account.password.as_str())
            // Отказ входа возвращает вместе с ошибкой и клиента, чтобы можно
            // было попробовать другой способ. Нам это не нужно: пароль один,
            // и второго способа нет.
            .await
            .map_err(|(error, _client)| {
                TransportError::Refused(format!("вход в почту отвергнут: {error}"))
            })?;

        // Способности спрашиваются до выбора ящика: список у сервера один
        // на сессию, и после `SELECT` он тот же самый. И спрашиваются
        // **одним** запросом на обе способности: второй `CAPABILITY` дал бы
        // тот же ответ за лишний круг, который через Tor не бесплатен.
        let (idle, quota) = match session.capabilities().await {
            Ok(caps) => (caps.has_str("IDLE"), caps.has_str("QUOTA")),
            Err(_) => (false, false),
        };
        if !idle {
            tracing::debug!("почта: сервер не умеет IDLE — переходим на опрос");
        }
        if !quota {
            tracing::debug!("почта: сервер не умеет QUOTA — объём ящика останется неизвестным");
        }

        session
            .select(INBOX)
            .await
            .map_err(|error| TransportError::Refused(format!("ящик не открылся: {error}")))?;

        Ok(Receiver { session, idle, quota })
    }

    /// Спрашивает, сколько в ящике занято и сколько всего (RFC 2087).
    ///
    /// Отвечает в **байтах**, а не в единицах протокола: множитель — часть
    /// разбора, и оставить его вызывающему значило бы однажды забыть.
    ///
    /// `None` во всех случаях, когда сказать нечего: сервер не умеет `QUOTA`,
    /// отказал, не назвал корень для `INBOX` или назвал ресурс без `STORAGE`.
    /// Отказ здесь не отказ приёма — ящик работает и без объявленной квоты,
    /// и валить из-за неё соединение было бы несоразмерно.
    ///
    /// Ноль в поле `limit` протокол трактует как «без предела»; здесь он
    /// становится `None` по той же причине, по какой `SIZE` без числа —
    /// «предела не называю», а не «предел нулевой».
    pub async fn mailbox_quota(&mut self) -> Option<(u64, u64)> {
        if !self.quota {
            return None;
        }
        let (_roots, quotas) = match self.session.get_quota_root(INBOX).await {
            Ok(answer) => answer,
            Err(error) => {
                tracing::debug!(%error, "почта: квота не спросилась");
                return None;
            }
        };
        for quota in &quotas {
            for resource in &quota.resources {
                if resource.name != async_imap::types::QuotaResourceName::Storage {
                    continue;
                }
                if resource.limit == 0 {
                    return None;
                }
                return Some((
                    resource.usage.saturating_mul(QUOTA_UNIT),
                    resource.limit.saturating_mul(QUOTA_UNIT),
                ));
            }
        }
        None
    }

    /// Забирает всё новое, отдаёт кадры и прибирает за собой.
    ///
    /// Кадры уходят событиями **до** уборки — разбор порядка см. в заголовке
    /// файла.
    ///
    /// # Errors
    ///
    /// [`TransportError::Refused`] на любом отказе сервера. Соединение после
    /// этого считается негодным: вызывающий заводит новое.
    pub async fn take(
        &mut self,
        events: &tokio::sync::mpsc::Sender<TransportEvent>,
    ) -> Result<(), TransportError> {
        let fresh =
            self.session.uid_search("UNSEEN").await.map_err(|error| {
                TransportError::Refused(format!("поиск в ящике не вышел: {error}"))
            })?;
        if fresh.is_empty() {
            return Ok(());
        }

        // Список номеров строкой — так требует протокол. Сортируется он ради
        // одного: письма приходят в порядке отправки, и разбирать их в другом
        // значило бы без нужды нагружать сборку кадров (§7.3) перестановками,
        // которых на самом деле не было.
        let mut uids: Vec<u32> = fresh.into_iter().collect();
        uids.sort_unstable();
        let list = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");

        // `BODY.PEEK[]`, а не `BODY[]`: выборка не должна сама расставлять
        // отметки. Что прочитано, а что нет, решаем мы ниже — и по-разному
        // для своих писем и чужих.
        let letters: Vec<async_imap::types::Fetch> = {
            let stream =
                self.session.uid_fetch(&list, "(UID BODY.PEEK[])").await.map_err(|error| {
                    TransportError::Refused(format!("выборка не вышла: {error}"))
                })?;
            stream.try_collect().await.map_err(|error| {
                TransportError::Refused(format!("письмо не дочиталось: {error}"))
            })?
        };

        let mut ours = Vec::new();
        let mut foreign = Vec::new();
        for letter in &letters {
            let Some(uid) = letter.uid else {
                // Без номера письмо не пометить — оставляем как есть.
                // Приедет снова, и это лучше, чем потерять его из виду.
                continue;
            };
            let Some(body) = letter.body() else {
                foreign.push(uid);
                continue;
            };
            match parse_message(body) {
                Ok(frames) => {
                    for frame in frames {
                        let event = TransportEvent::Received {
                            via: Transport::Mail,
                            // Отправителя не сообщаем: `From` подделывается,
                            // а кто прислал кадр — устанавливает рукопожатие
                            // (§8.2), и только оно.
                            peer_hint: None,
                            frame,
                        };
                        if events.send(event).await.is_err() {
                            // Некому отдавать — раннер снят. Письмо остаётся
                            // в ящике непрочитанным: следующий запуск заберёт
                            // его целиком.
                            return Ok(());
                        }
                    }
                    ours.push(uid);
                }
                Err(error) => {
                    tracing::debug!(%error, uid, "почта: письмо не наше — оставляем в ящике");
                    foreign.push(uid);
                }
            }
        }

        // Чужое — только отметка «прочитано», чтобы не приезжало снова.
        self.mark(&foreign, "+FLAGS (\\Seen)").await?;
        // Своё — к удалению, и сразу же вычистить.
        self.mark(&ours, "+FLAGS (\\Deleted)").await?;
        if !ours.is_empty() {
            let stream = self.session.expunge().await.map_err(|error| {
                TransportError::Refused(format!("уборка ящика не вышла: {error}"))
            })?;
            stream.try_collect::<Vec<_>>().await.map_err(|error| {
                TransportError::Refused(format!("уборка ящика не дочиталась: {error}"))
            })?;
        }
        Ok(())
    }

    /// Ставит письмам отметку.
    async fn mark(&mut self, uids: &[u32], flags: &str) -> Result<(), TransportError> {
        if uids.is_empty() {
            return Ok(());
        }
        let list = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let stream =
            self.session.uid_store(&list, flags).await.map_err(|error| {
                TransportError::Refused(format!("отметка не поставилась: {error}"))
            })?;
        // Ответ вычитывается целиком, даже если он нам не нужен: непрочитанный
        // ответ остаётся в потоке и приедет вместо ответа на следующую
        // команду — а разбираться в этом придётся уже по симптомам.
        stream
            .try_collect::<Vec<_>>()
            .await
            .map_err(|error| TransportError::Refused(format!("отметка не дочиталась: {error}")))?;
        Ok(())
    }

    /// Ждёт, пока в ящике что-нибудь появится.
    ///
    /// Забирает владение и возвращает: `IDLE` в `async-imap` устроен как
    /// отдельное состояние сессии, и вернуть её из него можно только
    /// закончив ожидание. Отказ по дороге означает негодное соединение —
    /// сессия при этом теряется намеренно, и вызывающий заводит новую.
    ///
    /// # Errors
    ///
    /// [`TransportError::Refused`], если сервер не умеет `IDLE` или разорвал
    /// связь. Первое лечится опросом, второе — новым соединением.
    pub async fn wait_for_news(self) -> Result<Receiver, TransportError> {
        if !self.idle {
            // Опрос. Честно медленнее: письмо ждёт до `POLL_INTERVAL`,
            // и сказать об этом больше некому — в UI такой разницы
            // не покажешь, а в журнале она уже названа при входе.
            tokio::time::sleep(POLL_INTERVAL).await;
            return Ok(self);
        }
        let (idle, quota) = (self.idle, self.quota);
        let mut handle = self.session.idle();
        handle
            .init()
            .await
            .map_err(|error| TransportError::Refused(format!("IDLE не начался: {error}")))?;

        // Ожидание живёт в своей области видимости: оно заимствует ручку,
        // а закончить `IDLE` можно только отдав ручку целиком. Сторож
        // прерывания держится живым до конца ожидания — уронив его раньше,
        // мы бы сами себя и прервали.
        let outcome = {
            let (waiting, _stop) = handle.wait();
            waiting.await
        };
        outcome.map_err(|error| TransportError::Refused(format!("IDLE оборвался: {error}")))?;

        let session = handle
            .done()
            .await
            .map_err(|error| TransportError::Refused(format!("IDLE не закончился: {error}")))?;
        Ok(Receiver { session, idle, quota })
    }
}
