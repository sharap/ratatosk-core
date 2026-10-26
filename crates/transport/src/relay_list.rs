//! Спросить, какие реле бывают, и выбрать поближе (0.3, дополнение).
//!
//! # Зачем это вообще
//!
//! Ступень nostr без реле не работает, а называть реле руками человеку
//! нечем: он не знает ни адресов, ни того, чем они отличаются. Зашитого
//! списка при этом нет и не будет — реле видит, кто с кем переписывается
//! (0.3.3), и выбирать его за человека нельзя (§14).
//!
//! Выход тот же, что у пиров меша (0.2.7): список **приносится** во время
//! работы, а человек смотрит и выбирает. Разница в источнике — у меша это
//! файл в репозитории сети, здесь наблюдатель, публикующий описания реле
//! событиями NIP-66.
//!
//! # Кого спрашиваем, и чем за это платят
//!
//! Адрес наблюдателя лежит в сборке (`nostr::RELAY_SOURCE`) — и это цена:
//! кого спрашивать, выбрали мы, а он видит, что с этого адреса ищут реле.
//! Сказать об этом человеку **до** похода обязан клиент
//! (`ratatosk_core::honest::RELAY_SOURCE_NOTICE`).
//!
//! Ходим через Tor, когда он поднят, — тем же правилом, что и сама
//! ступень. Условием это не является: без Tor поход идёт прямо, иначе
//! человек, у которого Tor не собран, остался бы без реле вовсе.
//!
//! # Чего здесь нет
//!
//! Ни кэша, ни расписания, ни повторов: спрашивают, когда человек открыл
//! экран и нажал. Реле закрываются и появляются чаще, чем выходят версии,
//! и хранить вчерашний ответ значило бы предлагать вчерашнюю сеть.

use crate::chatmail::http;
use futures::{SinkExt, StreamExt};
use ratatosk_proto::nostr::{self, RelayCandidate, RelayListError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Сколько ждём ответа наблюдателя.
///
/// Через Tor это цепочка из трёх узлов плюс чужой узел, и секунды здесь —
/// норма. Предел нужен затем, чтобы экран не висел вечно: человек,
/// нажавший «подобрать», обязан получить либо реле, либо отказ.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Сколько ждём ответа **самого реле** на вопрос о себе и на стук.
///
/// Короче, чем у наблюдателя: реле либо отвечает сразу, либо нам
/// не подходит. Проверка идёт у всех сразу, и общий срок — этот же.
const VET_DEADLINE: std::time::Duration = std::time::Duration::from_secs(12);

/// Сколько реле проверяем. Больше — дольше ждать, а человеку нужно три.
const VET_WIDTH: usize = 8;

/// Сколько реле отдаём наружу.
///
/// Человеку нужно два-три (0.3.3: несколько реле делят след), но выбирает
/// он сам, и выбор из восьми — это ещё обозримо глазами.
const KEEP: usize = 8;

/// Имя подписки: своё, короткое и одно на поход.
const SUBSCRIPTION: &str = "relays";

/// Приносит реле названной страны, ближние — первыми.
///
/// # Errors
///
/// [`RelayListError::NoCountry`] — код страны негоден;
/// [`RelayListError::SourceSilent`] — наблюдатель не ответил, оборвал
/// или не уложился в срок; [`RelayListError::FormatChanged`] — ответ
/// пришёл, а годных реле в нём нет.
pub async fn fetch(
    country: &str,
    tor: &crate::onion::TorHandle,
) -> Result<Vec<RelayCandidate>, RelayListError> {
    let request = nostr::relay_query_json(SUBSCRIPTION, country, nostr::RELAY_QUERY_LIMIT)
        .ok_or(RelayListError::NoCountry)?;
    match tokio::time::timeout(DEADLINE, ask(&request, tor)).await {
        Ok(Ok(candidates)) => {
            // Сперва ближние и разных владельцев, потом проверка: иначе
            // мы проверяли бы десятки реле, чтобы выбросить их по тому же
            // правилу, по которому не взяли бы и без проверки.
            let nearest = nostr::nearest_relays(&candidates, VET_WIDTH);
            let picked: Vec<_> = vet(nearest, tor).await.into_iter().take(KEEP).collect();
            if picked.is_empty() {
                // Пустота после удачного похода — не успех: наблюдатель
                // отвечает сотнями описаний, и ноль годных означает, что
                // разметка у него сменилась, а наш разбор отстал. Выданный
                // за успех, такой ответ человек прочёл бы как «реле нет».
                Err(RelayListError::FormatChanged)
            } else {
                Ok(picked)
            }
        }
        Ok(Err(why)) => Err(why),
        Err(_) => Err(RelayListError::SourceSilent),
    }
}

/// Один заход: соединиться, спросить, дочитать до конца сохранённых.
async fn ask(
    request: &str,
    tor: &crate::onion::TorHandle,
) -> Result<Vec<RelayCandidate>, RelayListError> {
    let target = nostr::relay_target(nostr::RELAY_SOURCE).ok_or(RelayListError::SourceSilent)?;
    // Спрашивается **поднятость**, а не признак сборки: собранный,
    // но ещё не поднявшийся Tor дал бы отказ там, где прямой запрос
    // прошёл бы.
    let via_tor = tor.is_up() && target.tls;
    let plain = crate::tls::dial(&target.host, target.port, via_tor, tor)
        .await
        .map_err(|_| RelayListError::SourceSilent)?;
    let stream: crate::tls::Plain = if target.tls {
        Box::new(
            crate::tls::wrap(&target.host, plain)
                .await
                .map_err(|_| RelayListError::SourceSilent)?,
        )
    } else {
        plain
    };
    let (mut socket, _response) = tokio_tungstenite::client_async(nostr::RELAY_SOURCE, stream)
        .await
        .map_err(|_| RelayListError::SourceSilent)?;

    socket
        .send(tokio_tungstenite::tungstenite::Message::text(request.to_owned()))
        .await
        .map_err(|_| RelayListError::SourceSilent)?;

    let mut candidates = Vec::new();
    while let Some(Ok(message)) = socket.next().await {
        let Ok(text) = message.to_text() else { continue };
        match read(text) {
            Some(Read::Candidate(candidate)) => candidates.push(candidate),
            // Конец сохранённого — всё, что у наблюдателя было; ждать
            // дальше означало бы ждать новых замеров, а их делают минутами.
            Some(Read::End) => break,
            None => {}
        }
    }
    // Прощаемся словами протокола: подписка на чужом узле, оставленная
    // открытой, живёт у него до разрыва.
    let _ = socket
        .send(tokio_tungstenite::tungstenite::Message::text(nostr::unsubscribe_json(SUBSCRIPTION)))
        .await;
    let _ = socket.close(None).await;
    Ok(candidates)
}

/// Спрашивает у самих реле, пускают ли они чужих.
///
/// # Почему наблюдателя мало
///
/// Его замер говорит «отвечает», а не «пустит вас», и разница эта
/// стоила подборки: человек получил восемь живых реле, из которых
/// ни одно не взяло его сообщений. Проверено после: два из них
/// встречают запросом входа, хотя у наблюдателя помечены «входа
/// не требует», ещё одно в своём NIP-11 пишет `restricted_writes`.
///
/// Поэтому спрашиваем дважды и у самого реле: что оно пишет о себе
/// (NIP-11) и чем встречает (стук). Обе проверки идут у всех сразу —
/// последовательно это были бы минуты.
///
/// # Чего и эта проверка не даёт
///
/// Обещания, что **запись** пройдёт. Проверить её можно только записью,
/// а писать в чужое реле ради пробы — сорить у чужого человека. Реле,
/// которое молчит о себе и пускает читать, остаётся догадкой; об этом
/// клиент говорит человеку словами.
async fn vet(
    candidates: Vec<RelayCandidate>,
    tor: &crate::onion::TorHandle,
) -> Vec<RelayCandidate> {
    let checks = candidates.into_iter().map(|candidate| async move {
        let open = tokio::time::timeout(VET_DEADLINE, open_to_strangers(&candidate.url, tor))
            .await
            .unwrap_or(false);
        open.then_some(candidate)
    });
    futures::future::join_all(checks).await.into_iter().flatten().collect()
}

/// Пускает ли это реле чужого: что говорит о себе и чем встречает.
async fn open_to_strangers(url: &str, tor: &crate::onion::TorHandle) -> bool {
    if says_it_is_closed(url, tor).await {
        return false;
    }
    knock_at(url, tor).await
}

/// Что реле пишет о себе (NIP-11).
///
/// `true` — само сказало, что не пустит: вход по ключу, деньги или
/// закрытая запись. Молчание — не отказ (см. `nostr::relay_refuses`).
async fn says_it_is_closed(url: &str, tor: &crate::onion::TorHandle) -> bool {
    let Some(target) = nostr::relay_target(url) else { return true };
    let via_tor = tor.is_up() && target.tls;
    // Тот же узел и тот же порт, что у веб-сокета: NIP-11 отдаётся
    // обычным запросом с особым `Accept`.
    let Ok(plain) = crate::tls::dial(&target.host, target.port, via_tor, tor).await else {
        return false;
    };
    let Ok(mut stream) = crate::tls::wrap(&target.host, plain).await else { return false };
    let request = http::get(&target.host, "/", None, "application/nostr+json");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
        }
        if response.len() > http::MAX_RESPONSE_BYTES {
            break;
        }
    }
    let Ok(body) = http::body(&response) else { return false };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else { return false };
    let limits = value.get("limitation");
    let flag = |name: &str| {
        limits.and_then(|limits| limits.get(name)).and_then(serde_json::Value::as_bool)
    };
    nostr::relay_refuses(flag("auth_required"), flag("payment_required"), flag("restricted_writes"))
}

/// Стук: соединиться и попросить показать что-нибудь.
///
/// Реле, которое требует входа, встречает `AUTH` — так отвечают оба
/// случая, на которых подборка и сломалась. Записи здесь нет: проверить
/// её можно только записью, а это мусор в чужом реле.
async fn knock_at(url: &str, tor: &crate::onion::TorHandle) -> bool {
    let Some(target) = nostr::relay_target(url) else { return false };
    let via_tor = tor.is_up() && target.tls;
    let Ok(plain) = crate::tls::dial(&target.host, target.port, via_tor, tor).await else {
        return false;
    };
    let stream: crate::tls::Plain = if target.tls {
        let Ok(wrapped) = crate::tls::wrap(&target.host, plain).await else { return false };
        Box::new(wrapped)
    } else {
        plain
    };
    let Ok((mut socket, _)) = tokio_tungstenite::client_async(url, stream).await else {
        return false;
    };
    let request = "[\"REQ\",\"knock\",{\"kinds\":[1],\"limit\":1}]".to_owned();
    if socket.send(tokio_tungstenite::tungstenite::Message::text(request)).await.is_err() {
        return false;
    }
    let mut open = false;
    while let Some(Ok(message)) = socket.next().await {
        let Ok(text) = message.to_text() else { continue };
        match nostr::knock(text) {
            nostr::Knock::Open => {
                open = true;
                break;
            }
            nostr::Knock::Closed => break,
            // Своё реле вправе сказать что-то своё: ждём внятного ответа,
            // а срок на всю проверку стоит снаружи.
            nostr::Knock::Unclear => {}
        }
    }
    let _ = socket.close(None).await;
    open
}

/// Что приехало от наблюдателя.
enum Read {
    /// Описание реле, годное в кандидаты.
    Candidate(RelayCandidate),
    /// Сохранённое кончилось (`EOSE`).
    End,
}

/// Разбирает одно сообщение реле; `None` — не про нас.
///
/// Разбор JSON здесь, а правила — в протоколе: что считать годным реле,
/// решает `nostr::relay_candidate`, и проверяется оно без сети.
fn read(text: &str) -> Option<Read> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let items = value.as_array()?;
    match items.first()?.as_str()? {
        "EVENT" => {
            let event = items.get(2)?;
            if event.get("kind").and_then(serde_json::Value::as_u64)?
                != u64::from(nostr::RELAY_INFO_KIND)
            {
                return None;
            }
            let tags = event.get("tags")?.as_array()?;
            let flat: Vec<Vec<String>> = tags
                .iter()
                .filter_map(|tag| {
                    let values = tag.as_array()?;
                    Some(
                        values
                            .iter()
                            .map(|value| value.as_str().unwrap_or_default().to_owned())
                            .collect(),
                    )
                })
                .collect();
            nostr::relay_candidate(&flat).map(Read::Candidate)
        }
        "EOSE" => Some(Read::End),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_watchers_event_is_read_into_a_candidate() {
        // Строка — настоящая, укороченная: так наблюдатель и отвечает.
        let text = r#"["EVENT","relays",{"kind":30166,"tags":[
            ["d","wss://relay.sigit.io/"],["rtt-open","109"],["n","clearnet"],
            ["l","v236","176.9.50.120","DE","Hetzner Online GmbH"]]}]"#;
        match read(text) {
            Some(Read::Candidate(candidate)) => {
                assert_eq!(candidate.url, "wss://relay.sigit.io/");
                assert_eq!(candidate.rtt_ms, Some(109));
            }
            _ => panic!("кандидат не разобрался"),
        }
    }

    #[test]
    fn the_end_of_stored_events_is_told_apart_from_a_relay() {
        assert!(matches!(read(r#"["EOSE","relays"]"#), Some(Read::End)));
        // Чужой вид события — не наше дело, и кандидатом он не станет.
        // Событие нарочно **годное во всём остальном**: иначе проверка
        // была бы зелена от недостающего тега, а не от проверки вида,
        // и снятие проверки она бы проспала.
        let other = r#"["EVENT","relays",{"kind":1,"tags":[
            ["d","wss://relay.example/"],["rtt-open","40"],["n","clearnet"]]}]"#;
        assert!(read(other).is_none(), "вид события проверяется, а не угадывается");
        assert!(read("не json").is_none());
        assert!(read(r#"["NOTICE","перегружены"]"#).is_none());
    }

    // **Чего эти проверки не стерегут.** Живого похода: сеть в прогоне
    // не зовётся, и что наблюдатель отвечает именно такими событиями —
    // проверено запросом руками, а не здесь.
}
