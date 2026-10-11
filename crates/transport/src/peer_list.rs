//! Поход за публичным списком пиров меша (0.2.7).
//!
//! # Зачем это вообще
//!
//! Встроенный узел без пиров не соединён ни с кем, и 0.2.5 требует, чтобы
//! пиров называл человек. Требование остаётся — здесь только **приносится
//! список, из которого он выбирает**. Разница существенная: зашитого
//! в сборку списка по-прежнему нет, и ни одного адреса, выбранного за
//! человека, в бинарнике не лежит.
//!
//! # Почему только через Tor
//!
//! Запрос говорит чужому серверу, что с этого адреса включают меш. Это
//! ровно та метка, которой мы избегаем у реле nostr, и правило то же:
//! ходим только через Tor. Записано оно **в манифесте** — признак
//! `peer-list` требует `onion-arti`, — потому что там его не обойти
//! забывчивостью. Сборка без Tor похода не содержит, и ядро отвечает
//! человеку отказом, а не тихим прямым запросом.
//!
//! # Кого спрашиваем, и почему это тоже цена
//!
//! Репозиторий, который ведут сами авторы сети
//! (`ratatosk_proto::ygg::PEER_LIST_HOST`). Адрес источника в сборке
//! есть — и это выбор, который сделали мы, а не человек. Поэтому
//! о нём сказано текстом (§14), а не умолчано: «список спрашивается
//! там-то» человек обязан прочитать до нажатия.
//!
//! # Чего здесь нет
//!
//! Ни кэша, ни расписания, ни повторов. Список спрашивается, когда человек
//! открыл экран и нажал; хранить его между запусками незачем — он протухает
//! быстрее, чем релиз, а экран всё равно открывают, чтобы посмотреть
//! свежий. Повтор при отказе — тоже решение человека: молча ходить
//! к чужому серверу по кругу значит стучаться от его имени без спроса.

use crate::chatmail::http;
use ratatosk_proto::ygg::{self, PeerListError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Сколько ждём ответа.
///
/// Через Tor это цепочка из трёх узлов плюс чужой сервер, и секунды здесь
/// — норма, а не сбой. Предел нужен затем, чтобы экран не висел вечно:
/// человек, нажавший «принести список», обязан получить либо список,
/// либо отказ.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

/// Приносит список пиров названной страны (0.2.7).
///
/// Возвращает адреса в том порядке, в каком они стоят в файле: он там
/// осмысленный — узлы сгруппированы по владельцам, и перемешав их, мы
/// лишили бы человека возможности выбрать двух **разных** операторов.
///
/// Перечня стран этот поход не требует: знающий страну берёт её напрямую,
/// и отказ необязательного [`countries`] ему не мешает.
///
/// # Errors
///
/// [`PeerListError::NoSuchList`] — области или страны с таким именем нет.
/// [`PeerListError::SourceSilent`] — источник не ответил, срок вышел или
/// Tor не поднят. [`PeerListError::FormatChanged`] — ответ пришёл,
/// а адресов в нём нет.
///
/// Причины различены затем, что действие у каждой своё: текст к ним —
/// в `ratatosk_core::honest::peer_list_refusal_text` (§13.3).
pub async fn fetch(
    region: &str,
    country: &str,
    tor: &crate::onion::TorHandle,
) -> Result<Vec<String>, PeerListError> {
    // Имена проверены **до** сети: подставленное в путь чужое значение
    // увело бы запрос куда угодно, в том числе вверх по каталогам.
    let path = ygg::peer_list_path(region, country).ok_or(PeerListError::NoSuchList)?;
    let body = read(ygg::PEER_LIST_HOST, &path, tor).await.map_err(list_why)?;
    let peers = ygg::peers_from_list(&String::from_utf8_lossy(&body));
    if peers.is_empty() {
        // Пустой список — не успех. Пустых файлов в репозитории не бывает,
        // значит их разметка могла измениться, а наш разбор отстать.
        // Выданный за успех, такой список человек прочёл бы как «пиров
        // нет» и пошёл искать их сам.
        return Err(PeerListError::FormatChanged);
    }
    Ok(peers)
}

/// Приносит перечень стран области — **необязательно** (0.2.7).
///
/// Удобство, а не основа: у API предел в шестьдесят запросов в час
/// на адрес, а через Tor адрес выхода общий на многих, и отказ здесь —
/// обычное дело. Поэтому [`fetch`] от этого похода не зависит, а отказ
/// говорит человеку, что страну можно назвать и самому.
///
/// # Errors
///
/// [`PeerListError::NoSuchList`] — области с таким именем нет.
/// [`PeerListError::IndexBusy`] — API отказал (чаще всего пределом),
/// не ответил или в ответе нет ни одного имени: ждать бесполезно,
/// страну надо назвать самому.
pub async fn countries(
    region: &str,
    tor: &crate::onion::TorHandle,
) -> Result<Vec<String>, PeerListError> {
    let path = ygg::peer_index_path(region).ok_or(PeerListError::NoSuchList)?;
    // Причина переводится по коду ответа, а не сводится к одной.
    // Прежде здесь стоял `IndexBusy` на всё, и 403 от нехватки
    // `User-Agent` человек читал как «предел запросов» — совет подождать
    // там, где виновата наша же недостающая строка.
    let body = read(ygg::PEER_INDEX_HOST, &path, tor).await.map_err(index_why)?;
    let names = ygg::countries_from_index(&String::from_utf8_lossy(&body));
    if names.is_empty() {
        // Ответ пришёл, а имён в нём нет — это **не** предел: предел
        // отвечает кодом, а не пустотой. Значит либо каталог опустел,
        // либо разметка ответа сменилась, и советовать «подождите»
        // здесь было бы ложью.
        return Err(PeerListError::FormatChanged);
    }
    Ok(names)
}

/// Почему не вышло со **списком** пиров.
///
/// 403 здесь не бывает пределом: `raw` ни имени, ни ключа не требует,
/// и отказ от него означает «ответил не тем».
const fn list_why(fail: Fail) -> ygg::PeerListError {
    match fail {
        Fail::Network | Fail::Status(_) => ygg::PeerListError::SourceSilent,
        Fail::Garbled => ygg::PeerListError::FormatChanged,
    }
}

/// Почему не вышло с **перечнем** стран.
///
/// 403 и 429 у чужого API означают предел: ждать бесполезно, адрес
/// выхода Tor общий на многих, и занят он скорее всего не нами.
/// Остальное — «ответил не тем», и совет человеку другой.
const fn index_why(fail: Fail) -> ygg::PeerListError {
    match fail {
        Fail::Status(403 | 429) => ygg::PeerListError::IndexBusy,
        Fail::Network | Fail::Status(_) => ygg::PeerListError::SourceSilent,
        Fail::Garbled => ygg::PeerListError::FormatChanged,
    }
}

/// Кому из двух источников нужно имя клиента (0.2.7).
///
/// Чистой функцией и отдельно от похода — ради проверки: сеть в прогоне
/// не зовётся, а правило здесь и было нарушено. `api.github.com` без
/// `User-Agent` отвечает 403, `raw.githubusercontent.com` — не требует,
/// и отсюда вышла поломка: пиры ехали, страны нет.
///
/// Решается **по хосту**, а не по месту вызова: два места вызова рано
/// или поздно разъехались бы, а хост — то самое, от чего требование
/// и зависит.
fn agent_for(host: &str) -> Option<&'static str> {
    if host == ygg::PEER_INDEX_AGENT_HOST {
        Some(ygg::PEER_INDEX_AGENT)
    } else {
        None
    }
}

/// Один поход со сроком: соединиться, спросить, дочитать тело.
async fn read(host: &str, path: &str, tor: &crate::onion::TorHandle) -> Result<Vec<u8>, Fail> {
    match tokio::time::timeout(DEADLINE, ask(host, path, tor)).await {
        Ok(result) => result,
        Err(_) => Err(Fail::Network),
    }
}

/// Что именно не получилось — настолько, насколько это видно здесь.
///
/// Код ответа различается нарочно. Прежде всё сводилось к одному отказу,
/// и 403 от нехватки `User-Agent` человек читал как «предел запросов»:
/// совет подождать там, где виновата наша же недостающая строка. Ложный
/// диагноз хуже отсутствующего — по нему перестают искать.
enum Fail {
    /// Соединение, срок, TLS — до ответа дело не дошло.
    Network,
    /// Сервер ответил кодом. 403 и 429 у чужого API означают предел;
    /// остальное — «ответил не тем».
    Status(u16),
    /// Ответ не похож на HTTP или оборван.
    Garbled,
}

/// Один запрос: соединиться, спросить, дочитать.
async fn ask(host: &str, path: &str, tor: &crate::onion::TorHandle) -> Result<Vec<u8>, Fail> {
    // **Через Tor, когда тот поднят; иначе прямо.** Условием Tor здесь
    // не является, и это исправление первой редакции: она требовала его
    // по образцу реле nostr, а образец не подошёл. У реле долговечный
    // ключ, связанный с адресом устройства хоть раз, связан с ним
    // навсегда; меш такой тайны не держит — адрес в нём выводится
    // из открытого ключа и виден каждому узлу на пути (0.2.6), и опции
    // «меш через Tor» в дереве нет вовсе.
    //
    // Спрашивается **поднятость**, а не признак сборки: собранный,
    // но ещё не поднявшийся Tor дал бы отказ там, где прямой запрос
    // прошёл бы. `is_up` отвечает в обеих сборках.
    let via_tor = tor.is_up();
    let mut stream =
        crate::tls::connect(host, 443, via_tor, tor).await.map_err(|_| Fail::Network)?;
    let request = match agent_for(host) {
        Some(agent) => http::get_as(host, path, agent),
        None => http::get(host, path),
    };
    stream.write_all(request.as_bytes()).await.map_err(|_| Fail::Network)?;
    stream.flush().await.map_err(|_| Fail::Network)?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.map_err(|_| Fail::Network)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        // Предел тот же, что у похода за ящиком, и проверяется **по ходу**,
        // а не после: чужой сервер вправе отдать гигабайт, и дочитывать
        // его до конца, чтобы потом отвергнуть, незачем.
        if response.len() > http::MAX_RESPONSE_BYTES {
            return Err(Fail::Garbled);
        }
    }
    http::body(&response).map_err(|error| match error {
        http::HttpError::Status { code } => Fail::Status(code),
        _ => Fail::Garbled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_index_names_a_client_because_only_it_demands_one() {
        // Это и была поломка: `api.github.com` без `User-Agent` отвечает
        // 403, а `raw` не требует — список пиров ехал, перечень стран нет.
        assert_eq!(agent_for(ygg::PEER_INDEX_HOST), Some(ygg::PEER_INDEX_AGENT));
        assert_eq!(agent_for(ygg::PEER_LIST_HOST), None, "raw имени не требует");
        assert_eq!(agent_for("example.test"), None);
    }

    #[test]
    fn the_index_request_carries_the_header_and_the_list_request_does_not() {
        // Сверяется **собранный запрос**, а не только решение: между
        // решением и заголовком лежит сборщик, и разойтись они могут
        // молча.
        let index = http::get_as(ygg::PEER_INDEX_HOST, "/p", ygg::PEER_INDEX_AGENT);
        assert!(index.contains("User-Agent: yggdrasil-peers\r\n"), "{index}");
        let list = http::get(ygg::PEER_LIST_HOST, "/p");
        assert!(!list.contains("User-Agent"), "{list}");
        // И оба обязаны остаться годным HTTP: пустая строка в конце одна.
        for request in [&index, &list] {
            assert!(request.ends_with("\r\n\r\n"), "{request}");
            assert!(request.starts_with("GET /p HTTP/1.1\r\n"));
        }
    }

    #[test]
    fn a_limit_and_a_refusal_are_told_apart() {
        // 403 от нехватки имени человек читал как «предел запросов» —
        // совет подождать там, где виновата наша строка. Теперь предел
        // это предел, а отказ — отказ.
        assert!(matches!(index_why(Fail::Status(429)), ygg::PeerListError::IndexBusy));
        assert!(matches!(index_why(Fail::Status(403)), ygg::PeerListError::IndexBusy));
        assert!(matches!(index_why(Fail::Status(500)), ygg::PeerListError::SourceSilent));
        assert!(matches!(index_why(Fail::Network), ygg::PeerListError::SourceSilent));
    }

    // **Чего эти проверки не стерегут.** Что чужой сервер и правда требует
    // имя — это проверено запросом руками, а не прогоном: сеть здесь
    // не зовётся. Сменит он требование — проверки смолчат, а поймает
    // живой поход.
}
