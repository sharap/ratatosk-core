//! Кадры поверх потока: две полосы записи и разбор на чтении (§5.5, §7).
//!
//! Вынесено из [`crate::lan`], и вынесено по конкретной причине, а не ради
//! аккуратности. Onion (§5.2) отличается от локальной сети ровно одним —
//! чем открыт поток. Кадры те же, классы размера те же, разделение полос
//! нужно там даже сильнее: на LAN мебибайт чанка уходит в сокет за
//! миллисекунды, а через три реле Tor — за секунды, и текст, оказавшийся
//! за ним в общей очереди, ждал бы всё это время.
//!
//! Логика этих ста строк стоила трёх ошибок подряд (буря сроков молчания,
//! самораскрутка окна, одна очередь записи на всё), и второй её экземпляр
//! означал бы, что следующую ошибку придётся чинить дважды.
//!
//! # Поток здесь односторонний
//!
//! И это не упрощение, а свойство протокола: соединение набирает каждая
//! сторона сама, потому что транспорт не знает, кто к нему подключился —
//! личность устанавливает рукопожатие (§8.2), а не адрес. Поэтому чтение
//! и запись параметризованы по разным типам: читающей задаче хватает
//! [`AsyncRead`], пишущей — [`AsyncWrite`].
//!
//! # Формат
//!
//! Перед кадром идёт один байт класса размера. Длина кадра из класса
//! известна (§5.5), поэтому больше в заголовке потока ничего не нужно:
//! длина, переданная явно, была бы вторым источником правды — и первым,
//! чем воспользовался бы тот, кто хочет заставить нас выделить память.
//!
//! # Кадр записан значит кадр отправлен
//!
//! После каждого кадра идёт сброс потока, и это не осторожность.
//! `DataStream` у arti буферизован: он копит байты и отдаёт их в цепочку
//! целыми ячейками, а хвост кадра остаётся в буфере до следующей записи.
//! Получатель в это время стоит на `read_exact` посреди кадра. Снаружи
//! это выглядит как «сообщения приходят через одно, а последнее
//! не приходит никогда» — и только на onion: на TCP буфера нет, и все
//! тесты этого файла зелены.
//!
//! # Связь заводится раньше соединения
//!
//! [`Link::dialing`] возвращает полосы **сразу**, а набор номера уезжает
//! в свою задачу. Кадры при этом не теряются: они ждут в тех же очередях,
//! в которых ждали бы при медленной сети, и уходят, как только поток
//! появится.
//!
//! Так сделано по следу настоящей поломки, и стоит назвать её целиком.
//! Раньше набор ждался внутри [`crate::Runner::execute`], то есть внутри
//! `Driver::apply`, то есть **в теле цикла драйвера** — того самого, который
//! отвечает на запросы UI. Один недозвон через onion (сорок пять секунд
//! по §5.4) останавливал ядро целиком: ни переписки на экране, ни таймеров,
//! ни приёма по локальной сети. А на старте это било сильнее всего:
//! `Engine::startup_effects` возвращает в том числе доставки, недоделанные
//! в прошлый раз, и приложение показывало пустой экран ровно столько,
//! сколько занимал набор до всех, кого нет в сети.
//!
//! Отказ от этого не пропадает: он приезжает ядру
//! [`TransportEvent::ConnectFailed`] — тем же событием, каким приехал бы
//! обрыв, случись он секундой позже. §5.4 от этого не меняется, меняется
//! только путь, которым отказ доходит.

use std::future::Future;

use ratatosk_proto::transport_policy::Transport;
use ratatosk_wire::SizeClass;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::runner::{TransportError, TransportEvent};

/// Сколько мелких кадров ждёт записи, прежде чем отправитель начнёт ждать.
///
/// Кадры классов S и M — от четырёх килобайт; тридцать две штуки это меньше
/// двух мебибайт в худшем случае и обычно десятки килобайт. Ждать на такой
/// очереди можно: она наполняется ровно тогда, когда сеть действительно
/// не успевает, и тогда ожидание — честный ответ, а не затор.
pub(crate) const URGENT_QUEUE: usize = 32;

/// Сколько чанков файла ждёт записи, прежде чем кадр будет отброшен.
///
/// Кадр класса L — мебибайт, поэтому очередь короткая намеренно: восемь
/// штук это восемь мебибайт памяти на одно соединение. Больше и не нужно —
/// окно передачи (§10.2) держит в полёте единицы чанков на файл, так что
/// заполнить эту очередь может только сеть, которая встала совсем.
pub(crate) const BULK_QUEUE: usize = 8;

/// Байт класса размера, идущий перед кадром.
pub(crate) const fn tag_of(class: SizeClass) -> u8 {
    match class {
        SizeClass::S => 0,
        SizeClass::M => 1,
        SizeClass::L => 2,
    }
}

/// Класс размера по байту из потока.
pub(crate) fn class_of_tag(tag: u8) -> Option<SizeClass> {
    match tag {
        0 => Some(SizeClass::S),
        1 => Some(SizeClass::M),
        2 => Some(SizeClass::L),
        _ => None,
    }
}

/// Две полосы записи в одно соединение.
///
/// Разделение появилось не от любви к приоритетам, а от простого наблюдения:
/// кадр класса L — мебибайт, кадр с текстом — четыре килобайта, и в общей
/// очереди текст ждёт, пока в сокет уползут мегабайты чужой передачи. На
/// быстром LAN это миллисекунды, на onion — минуты, и человек видит, что
/// «файл заблокировал переписку».
///
/// Поэтому полос две, и пишущая задача всегда сначала опустошает срочную.
/// Передача файла от этого не замедляется заметно: она и так упирается
/// в пропускную способность, а мелкие кадры отнимают у неё доли процента.
#[derive(Clone)]
pub(crate) struct Link {
    urgent: mpsc::Sender<Vec<u8>>,
    bulk: mpsc::Sender<Vec<u8>>,
}

impl Link {
    /// Заводит полосы **до** того, как поток появится: набор идёт в фоне.
    ///
    /// Возвращается мгновенно. Кадры, положенные в полосы до конца набора,
    /// ждут там же, где ждали бы при медленной сети, и уходят, как только
    /// соединение установится.
    ///
    /// # Чем это кончается для ядра
    ///
    /// Набор удался — [`TransportEvent::Connected`], как и прежде. Не удался
    /// — [`TransportEvent::ConnectFailed`], и полосы закрываются вместе
    /// с задачей: [`Link::is_closed`] отдаёт `true`, раннер забывает связь
    /// и следующая попытка набирает заново. Ждавшие кадры при этом
    /// пропадают — и это правильно, потому что ядро узнаёт об отказе тем же
    /// событием и уводит доставку на следующую ступень §5.4, а запись
    /// в очереди отправки остаётся на диске до подтверждения.
    ///
    /// Отказ **не** возвращается вызывающему: возвращать его некому — набор
    /// ещё идёт, когда `execute` уже вернулся. В этом вся суть перемены,
    /// см. заголовок файла.
    ///
    /// # Способ завести связь только один, и это нарочно
    ///
    /// Рядом стоял `Link::open` — «полосы поверх уже открытого потока», —
    /// и после этой поставки он остался без единого вызова: исходящие все
    /// набираются, а принятые соединения работают на чтение
    /// ([`spawn_read_loop`]) и полос записи не имеют вовсе. Держать его
    /// значило бы держать второй путь, по которому связь заводится **без**
    /// новости ядру, — то есть заготовку для следующего «сообщения
    /// не ходят, и непонятно почему». Готовому потоку здесь отвечает набор,
    /// который уже удался.
    pub(crate) fn dialing<F, W>(
        dial: F,
        peer_ik: [u8; 32],
        via: Transport,
        events: mpsc::Sender<TransportEvent>,
    ) -> Link
    where
        F: Future<Output = Result<W, TransportError>> + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (urgent_tx, urgent_rx) = mpsc::channel(URGENT_QUEUE);
        let (bulk_tx, bulk_rx) = mpsc::channel(BULK_QUEUE);
        tokio::spawn(async move {
            match dial.await {
                Ok(writer) => {
                    // Сперва новость, потом запись. Порядок важен: ядро
                    // считает ступень пригодной по этому событию, и кадр,
                    // ушедший раньше него, был бы отправлен по соединению,
                    // о котором ядро ещё не знает.
                    let _ = events.send(TransportEvent::Connected { peer_ik, via }).await;
                    write_loop(writer, urgent_rx, bulk_rx, peer_ik, via, events).await;
                }
                Err(error) => {
                    tracing::debug!(?via, ?error, "набор не удался");
                    let _ = events.send(TransportEvent::ConnectFailed { peer_ik, via }).await;
                    // Приёмники уходят вместе с задачей — полосы закрыты,
                    // и ждавшие кадры уезжают в мусор осознанно (см. выше).
                }
            }
        });
        Link { urgent: urgent_tx, bulk: bulk_tx }
    }

    /// Закрыта ли хоть одна полоса.
    ///
    /// Обе половины живут и умирают вместе — их держит одна пишущая задача,
    /// и её уход закрывает обе. Проверка по любой из них равносильна, но
    /// писать «любая» честнее, чем полагаться на это молча.
    pub(crate) fn is_closed(&self) -> bool {
        self.urgent.is_closed() || self.bulk.is_closed()
    }

    /// Кладёт кадр в свою полосу.
    ///
    /// Класс L едет через [`mpsc::Sender::try_send`] — то есть отправка чанка
    /// **никогда** не ждёт. Ждать здесь нельзя: `Driver::apply` дожидается
    /// каждой команды по очереди, и одно ожидание на забитой очереди чанков
    /// останавливает весь цикл ядра — вместе с сообщениями, квитанциями
    /// и таймерами. Именно так «зависший файл» и превращался в зависший
    /// мессенджер.
    ///
    /// Цена отказа известна и ограничена: потерянный чанк получатель
    /// перепросит по сроку молчания (§10.2), как перепросил бы потерянный
    /// сетью. Мелкие кадры, наоборот, ждут: терять квитанцию или сообщение
    /// ради полумиллисекунды нечестно.
    pub(crate) async fn send(&self, frame: Vec<u8>) -> Result<(), TransportError> {
        let bulky = SizeClass::from_frame_len(frame.len()).is_ok_and(|class| class == SizeClass::L);
        if bulky {
            self.bulk.try_send(frame).map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => TransportError::Busy,
                mpsc::error::TrySendError::Closed(_) => TransportError::Unavailable,
            })
        } else {
            self.urgent.send(frame).await.map_err(|_| TransportError::Unavailable)
        }
    }
}

/// Тип и сессия кадра — одной строкой для журнала.
///
/// Заголовок §7.1 открыт: первый байт — версия, второй — тип, дальше
/// восемь байт идентификатора сессии. Разбирать его целиком здесь нечем
/// и незачем — журналу довольно того, что видно без ключей.
///
/// Заведено по следу живой поломки: в журнале на один записанный кадр
/// приходилось три прочитанных, и понять, что это было, оказалось нечем.
fn frame_kind(frame: &[u8]) -> String {
    use std::fmt::Write as _;

    let Some(&kind) = frame.get(1) else { return "?".to_owned() };
    let name = match kind {
        0x01 => "рукопожатие",
        0x02 => "данные",
        _ => "неизвестно",
    };
    let mut out = name.to_owned();
    if let Some(bytes) = frame.get(2..10) {
        let mut session = [0u8; 8];
        session.copy_from_slice(bytes);
        // Сессия — то, чем различаются «две сессии на одну пару», а это
        // главный подозреваемый в односторонней переписке.
        let _ = write!(out, " sid={:04x}", u64::from_be_bytes(session) & 0xffff);
    }
    out
}

/// Читающая задача: разбирает поток на кадры и отдаёт их ядру.
///
/// `link` — номер принятой связи, если у ступени связи счётные и в них
/// можно **ответить**. Нужен он одному эфиру: телефон объявляется
/// приватным адресом, набрать его в ответ нельзя, а открытый им канал
/// двусторонний. У остальных ступеней `None` — см.
/// [`TransportEvent::Received::link`].
pub(crate) fn spawn_read_loop<R>(
    mut reader: R,
    via: Transport,
    link: Option<u64>,
    events: mpsc::Sender<TransportEvent>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let mut tag = [0u8; 1];
            if reader.read_exact(&mut tag).await.is_err() {
                return;
            }
            let Some(class) = class_of_tag(tag[0]) else {
                // Неизвестный класс — поток дальше не разобрать: где кончается
                // этот кадр, неизвестно. Единственный корректный ход — закрыть.
                tracing::debug!(tag = tag[0], "неизвестный класс кадра, закрываем поток");
                return;
            };
            let mut frame = vec![0u8; class.frame_len()];
            if reader.read_exact(&mut frame).await.is_err() {
                return;
            }
            // Пара к строке на записи: сколько ушло и сколько пришло —
            // и **чего именно**. Без типа «три кадра прочитано» не читается
            // никак: рукопожатие, данные и повтор выглядят одинаково,
            // а означают разное. Тип и номер сессии лежат открыто
            // в заголовке (§7.1) — тем они и хороши для журнала.
            tracing::debug!(?via, ?class, kind = %frame_kind(&frame), "кадр прочитан");
            let event = TransportEvent::Received {
                via,
                // Транспорт не знает, кто прислал: личность даёт рукопожатие
                // (§8.2), а не адрес. Номер связи — это «откуда», а не
                // «от кого», и одно другим не становится.
                peer_hint: None,
                link,
                frame,
            };
            if events.send(event).await.is_err() {
                return;
            }
        }
    });
}

/// Запись: сначала срочная полоса, потом чанки.
///
/// `biased` в [`tokio::select!`] здесь — это и есть весь приоритет: пока
/// в срочной полосе есть хоть один кадр, к чанкам очередь не доходит.
/// Голодания у чанков не возникает, потому что мелкие кадры кончаются:
/// их порождают сообщения и квитанции, а не бесконечный поток.
///
/// Не задача, а будущее: [`Link::dialing`] запускает её **после** набора,
/// внутри своей задачи, и второй `spawn` там был бы лишним.
/// Пишет один кадр: байт класса, тело, сброс.
///
/// Отдельной функцией ради одного — **сохранить ошибку**. Тремя
/// `.is_ok()` подряд она терялась, и связь закрывалась без объяснения;
/// разница видна только тогда, когда что-то пошло не так, то есть
/// ровно тогда, когда журнал и нужен.
///
/// Про обязательность сброса — см. разбор в теле цикла записи.
async fn write_frame<W>(writer: &mut W, class: SizeClass, frame: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[tag_of(class)]).await?;
    writer.write_all(frame).await?;
    writer.flush().await
}

async fn write_loop<W>(
    mut writer: W,
    mut urgent: mpsc::Receiver<Vec<u8>>,
    mut bulk: mpsc::Receiver<Vec<u8>>,
    peer_ik: [u8; 32],
    via: Transport,
    events: mpsc::Sender<TransportEvent>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    loop {
        // Обе полосы закрываются вместе — их отправители лежат в одной
        // записи `Link`, — поэтому `None` с любой из них означает, что
        // соединение больше никому не нужно.
        let frame = tokio::select! {
            biased;
            frame = urgent.recv() => match frame {
                Some(frame) => frame,
                None => break,
            },
            frame = bulk.recv() => match frame {
                Some(frame) => frame,
                None => break,
            },
        };
        let Ok(class) = SizeClass::from_frame_len(frame.len()) else {
            // Кадр не того размера сюда попасть не может: его собирает
            // `crypto::aead::seal`. Если попал — это ошибка выше, и
            // молча отправлять её в сеть нельзя.
            tracing::error!(len = frame.len(), "кадр вне классов размера, не отправлен");
            continue;
        };
        // Запись **и обязательный сброс**. Сброс здесь не осторожность,
        // а условие работоспособности, и вот почему.
        //
        // `DataStream` у arti буферизован: он копит байты и отдаёт их
        // в цепочку целыми ячейками (около 498 байт полезной нагрузки).
        // Кадр класса S — 4096 байт плюс байт класса, то есть восемь
        // полных ячеек и хвост в сотню с лишним байт. Без сброса этот
        // хвост остаётся в буфере, и у получателя `read_exact` стоит
        // на недочитанном кадре до тех пор, пока хвост не вытолкнет
        // **следующая** запись. Снаружи это выглядит как «сообщения
        // приходят через одно, а последнее не приходит никогда».
        //
        // На TCP сброс не стоит ничего: там его и так нет. Поэтому
        // условия «если поток буферизован» здесь нет — есть просто
        // правило: кадр записан значит кадр отправлен.
        //
        // Сброс на каждый кадр, а не на пачку. Пачка дала бы экономию
        // в одну неполную ячейку на кадр — а стоила бы правила, которое
        // держится в голове: «отправлено, если следом идёт ещё что-то».
        // Такие правила и порождают ошибки вроде этой.
        if let Err(error) = write_frame(&mut writer, class, &frame).await {
            // **Вслух, и это не украшение журнала.** Здесь стояло
            // `.is_ok() && .is_ok() && .is_ok()`, то есть сама ошибка
            // выбрасывалась, а связь закрывалась молча. Ядро при этом
            // узнавало «оборвалось» — и правильно, — но **почему**
            // оборвалось, не знал никто.
            //
            // На LAN и onion это почти не мешало: там запись не падает
            // на ровном месте. На радио падает, и первым же выходом
            // в эфир (0.4) стоило часа разбирательства: набор сообщал
            // «канал открыт», кадр уходил в очередь, а дальше стояла
            // тишина и семь сообщений разом объявлялись недоставимыми.
            // Ошибка системы, потерянная вот этой строкой, и была
            // ответом.
            tracing::warn!(
                ?via,
                ?class,
                ?error,
                kind = %frame_kind(&frame),
                "кадр не записан — связь закрыта"
            );
            let _ = events.send(TransportEvent::Disconnected { peer_ik, via }).await;
            break;
        }
        // По этой строке видно, сколько кадров ушло на самом деле.
        // Вместе с такой же на чтении она отвечает на вопрос, который
        // иначе неразрешим: кадр не дошёл — его не отправили, потеряли
        // по дороге или не сумели расшифровать?
        tracing::debug!(?via, ?class, kind = %frame_kind(&frame), "кадр записан");
    }

    // **Поток закрывается явно, а не роняется.** Для `TcpStream` разницы нет
    // — закрытие делает `Drop`, — а для потоков поверх чужих стеков есть,
    // и стоила она поставки.
    //
    // Наблюдалось это так: после сброса связей (смена сети) следующий набор
    // к тому же собеседнику по мешу упирался в срок ожидания, и лечился
    // только перезапуском приложения. Похоже на то, что сессия TCP/KEY
    // у собеседника оставалась жива — мы уронили свою половину, не сказав
    // об этом, — а порт у меша постоянный с обеих сторон, так что новый
    // набор приходил в ту же пару и оставался без ответа.
    //
    // Явное закрытие — единственное, чем мы вправе сказать «эта сессия
    // кончилась», и стоит оно одной строки. Отказ здесь глотается сознательно:
    // закрываем то, что уже сломано, и второй раз об этом говорить некому.
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Поток в памяти вместо сокета: проверяются полосы, а не сеть.
    ///
    /// Ёмкость мала намеренно — пишущая задача обязана упереться в поток
    /// на первом же чанке, иначе очередь не наполнится и проверять станет
    /// нечего. На настоящем сокете эту роль играют буферы системы, но их
    /// размер решаем не мы, и тест зависел бы от машины.
    ///
    /// Набор здесь удался сразу: способ завести связь один, и готовому
    /// потоку отвечает готовое будущее. Первым событием при этом приезжает
    /// [`TransportEvent::Connected`] — тому, кто читает поток событий,
    /// его надо пропустить.
    fn linked() -> (Link, tokio::io::DuplexStream, mpsc::Receiver<TransportEvent>) {
        let (writer, reader) = tokio::io::duplex(4096);
        let (events_tx, events_rx) = mpsc::channel(8);
        let link = Link::dialing(
            async move { Ok::<_, TransportError>(writer) },
            [7u8; 32],
            Transport::Lan,
            events_tx,
        );
        (link, reader, events_rx)
    }

    #[tokio::test]
    async fn a_full_chunk_queue_refuses_instead_of_waiting() {
        // Суть всей правки: отправка чанка не ждёт никогда. `Driver::apply`
        // дожидается каждой команды по очереди, и одно ожидание на забитой
        // очереди останавливает весь цикл ядра — вместе с сообщениями,
        // квитанциями и таймерами. Так «зависший файл» и превращался
        // в зависший мессенджер.
        let (urgent_tx, _urgent_rx) = mpsc::channel(URGENT_QUEUE);
        let (bulk_tx, _bulk_rx) = mpsc::channel(BULK_QUEUE);
        let link = Link { urgent: urgent_tx, bulk: bulk_tx };

        let chunk = || vec![0u8; SizeClass::L.frame_len()];
        for _ in 0..BULK_QUEUE {
            link.send(chunk()).await.expect("пока есть место — кадр принимается");
        }
        assert!(
            matches!(link.send(chunk()).await, Err(TransportError::Busy)),
            "переполнение обязано отличаться от обрыва: рвать живое соединение из-за затора нельзя"
        );

        // А мелкий кадр в это же время проходит: полосы независимы.
        link.send(vec![0u8; SizeClass::S.frame_len()])
            .await
            .expect("переписка не зависит от того, сколько чанков ждёт записи");
    }

    #[tokio::test]
    async fn a_message_overtakes_the_chunks_already_queued() {
        // Ради этого полосы и разделены: без приоритета текст ждал бы,
        // пока в поток уползут мегабайты чужой передачи.
        let (link, mut incoming, _events) = linked();

        // Забиваем полосу чанков до отказа — тогда задача записи заведомо
        // стоит на первом из них, а остальные ждут в очереди.
        let mut queued = 0usize;
        while link.send(vec![0u8; SizeClass::L.frame_len()]).await.is_ok() {
            queued += 1;
        }
        assert!(queued >= 2, "очередь чанков обязана вмещать хотя бы пару кадров");

        link.send(vec![0u8; SizeClass::S.frame_len()]).await.expect("мелкий кадр принят");

        let mut order = Vec::new();
        for _ in 0..=queued {
            let mut tag = [0u8; 1];
            incoming.read_exact(&mut tag).await.expect("тег класса");
            let class = class_of_tag(tag[0]).expect("известный класс");
            let mut frame = vec![0u8; class.frame_len()];
            incoming.read_exact(&mut frame).await.expect("кадр целиком");
            order.push(class);
        }

        let small = order.iter().position(|c| *c == SizeClass::S).expect("мелкий кадр дошёл");
        // Точное место назвать нельзя: сколько байт успеет уйти в буфер
        // потока, решает не отправитель. Проверяется то, ради чего полосы
        // и разделены, — мелкий кадр не ждёт всей очереди: после него чанков
        // остаётся больше половины.
        let after = order.len() - small - 1;
        assert!(after * 2 >= queued, "мелкий кадр пропустили вперёд не по-настоящему: {order:?}");
    }

    #[tokio::test]
    async fn a_frame_arrives_whole_and_says_which_transport_brought_it() {
        // Читающая задача — общая для LAN и onion, и `via` в событии берётся
        // из того, кто её завёл: ядро различает транспорты (§5.4), а поток
        // о себе ничего не сообщает.
        let (writer, reader) = tokio::io::duplex(SizeClass::S.frame_len() * 2);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        spawn_read_loop(reader, Transport::Onion, None, events_tx);

        // Новости самой связи уезжают в отдельный канал: этот тест смотрит
        // на приём, а не на набор.
        let link = Link::dialing(
            async move { Ok::<_, TransportError>(writer) },
            [7u8; 32],
            Transport::Onion,
            mpsc::channel(8).0,
        );
        let mut frame = vec![0u8; SizeClass::S.frame_len()];
        frame[0] = 42;
        link.send(frame.clone()).await.expect("кадр принят");

        match events_rx.recv().await.expect("событие о приёме") {
            TransportEvent::Received { via, peer_hint, link, frame: got } => {
                assert_eq!(via, Transport::Onion);
                assert!(peer_hint.is_none(), "адрес не говорит, кто это (§8.2)");
                assert!(link.is_none(), "у onion принятых связей нет: ответ едет своим набором");
                assert_eq!(got, frame, "кадр обязан доехать байт в байт");
            }
            other => panic!("ожидалось событие о приёме, пришло {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_frame_may_be_queued_before_the_dial_lands() {
        // Ради этого связь и заводится раньше соединения: набор уехал
        // в задачу, а кадр обязан подождать в полосе, а не пропасть
        // и не задержать вызывающего.
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let (writer, mut incoming) = tokio::io::duplex(SizeClass::S.frame_len() * 2);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let link = Link::dialing(
            async move {
                held.await.map_err(|_| TransportError::Unavailable)?;
                Ok(writer)
            },
            [7u8; 32],
            Transport::Onion,
            events_tx,
        );

        link.send(vec![0u8; SizeClass::S.frame_len()])
            .await
            .expect("кадр принимается, пока идёт набор");

        // И до конца набора в поток не уходит ничего: писать пока некуда.
        let mut tag = [0u8; 1];
        let early = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            incoming.read_exact(&mut tag),
        )
        .await;
        assert!(early.is_err(), "до соединения писать некуда");

        release.send(()).expect("набор ждёт разрешения");
        match events_rx.recv().await.expect("новость о соединении") {
            TransportEvent::Connected { peer_ik, via } => {
                assert_eq!(peer_ik, [7u8; 32]);
                assert_eq!(via, Transport::Onion);
            }
            other => panic!("ожидалось соединение, пришло {other:?}"),
        }
        incoming.read_exact(&mut tag).await.expect("кадр уходит вслед за соединением");
        assert_eq!(class_of_tag(tag[0]), Some(SizeClass::S));
    }

    /// Поток, который помнит, закрыли ли его явно.
    ///
    /// Настоящий `TcpStream` этого не различает — закрытие делает `Drop`, —
    /// а `DuplexStream` тем более: у него обрыв и закрытие на чтении
    /// выглядят одинаково. Поэтому проверять приходится не следствие,
    /// а сам вызов.
    struct Watched {
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl tokio::io::AsyncWrite for Watched {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_forgotten_link_closes_its_stream_instead_of_dropping_it() {
        // Для `TcpStream` разницы нет, для потока поверх чужого стека есть,
        // и стоила она поставки: после сброса связей следующий набор к тому
        // же собеседнику по мешу упирался в срок ожидания и лечился только
        // перезапуском приложения. Похоже на живую сессию у собеседника,
        // которой мы не сказали, что она кончилась.
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = Watched { closed: std::sync::Arc::clone(&closed) };
        let link = Link::dialing(
            async move { Ok::<_, TransportError>(writer) },
            [7u8; 32],
            Transport::Ygg,
            mpsc::channel(8).0,
        );

        // Раннер забыл связь — полосы закрылись, пишущая задача выходит.
        drop(link);

        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            while !closed.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("забытая связь обязана закрыть поток, а не уронить его молча");
    }

    #[tokio::test]
    async fn a_failed_dial_says_so_and_closes_the_link() {
        // Отказ обязан приехать событием: возвращать его некому — набор
        // ещё идёт, когда `execute` уже вернулся. А связь обязана закрыться,
        // иначе раннер держал бы её вечно и больше никогда не набрал бы
        // этот номер заново.
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let link = Link::dialing(
            async { Err::<tokio::io::DuplexStream, _>(TransportError::Timeout) },
            [7u8; 32],
            Transport::Ygg,
            events_tx,
        );

        match events_rx.recv().await.expect("новость об отказе") {
            TransportEvent::ConnectFailed { peer_ik, via } => {
                assert_eq!(peer_ik, [7u8; 32]);
                assert_eq!(via, Transport::Ygg);
            }
            other => panic!("ожидался отказ набора, пришло {other:?}"),
        }

        // Задача досыпает после отправки новости, поэтому не «сразу»,
        // а «в срок»: проверяется закрытие, а не расторопность планировщика.
        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            while !link.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("не набравшаяся связь обязана закрыться");
    }

    #[tokio::test]
    async fn a_broken_stream_is_reported_once() {
        // Обрыв обязан дойти до ядра событием, а не только отказом отправки:
        // §5.4 иначе узнает о нём лишь по сроку молчания.
        let (writer, reader) = tokio::io::duplex(64);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let link = Link::dialing(
            async move { Ok::<_, TransportError>(writer) },
            [7u8; 32],
            Transport::Lan,
            events_tx,
        );
        drop(reader);

        // Первый кадр может уйти в буфер и не заметить обрыва — второй
        // уже упрётся. Полоса срочная: она ждёт, и потому дойдёт до записи.
        for _ in 0..2 {
            let _ = link.send(vec![0u8; SizeClass::S.frame_len()]).await;
        }

        // Первым приезжает состоявшееся соединение — его пропускаем:
        // проверяется обрыв, а не то, что связь завелась.
        let broken = loop {
            match events_rx.recv().await.expect("событие об обрыве") {
                TransportEvent::Connected { .. } => continue,
                other => break other,
            }
        };
        match broken {
            TransportEvent::Disconnected { peer_ik, via } => {
                assert_eq!(peer_ik, [7u8; 32]);
                assert_eq!(via, Transport::Lan);
            }
            other => panic!("ожидался обрыв, пришло {other:?}"),
        }
    }
}
