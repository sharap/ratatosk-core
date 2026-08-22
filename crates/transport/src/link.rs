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
    /// Заводит полосы и пишущую задачу поверх открытого потока.
    pub(crate) fn open<W>(
        writer: W,
        peer_ik: [u8; 32],
        via: Transport,
        events: mpsc::Sender<TransportEvent>,
    ) -> Link
    where
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (urgent_tx, urgent_rx) = mpsc::channel(URGENT_QUEUE);
        let (bulk_tx, bulk_rx) = mpsc::channel(BULK_QUEUE);
        spawn_write_loop(writer, urgent_rx, bulk_rx, peer_ik, via, events);
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

/// Читающая задача: разбирает поток на кадры и отдаёт их ядру.
pub(crate) fn spawn_read_loop<R>(
    mut reader: R,
    via: Transport,
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
            // Пара к строке на записи: сколько ушло и сколько пришло.
            tracing::debug!(?via, ?class, "кадр прочитан");
            let event = TransportEvent::Received {
                via,
                // Транспорт не знает, кто прислал: личность даёт рукопожатие
                // (§8.2), а не адрес.
                peer_hint: None,
                frame,
            };
            if events.send(event).await.is_err() {
                return;
            }
        }
    });
}

/// Пишущая задача: сначала срочная полоса, потом чанки.
///
/// `biased` в [`tokio::select!`] здесь — это и есть весь приоритет: пока
/// в срочной полосе есть хоть один кадр, к чанкам очередь не доходит.
/// Голодания у чанков не возникает, потому что мелкие кадры кончаются:
/// их порождают сообщения и квитанции, а не бесконечный поток.
fn spawn_write_loop<W>(
    mut writer: W,
    mut urgent: mpsc::Receiver<Vec<u8>>,
    mut bulk: mpsc::Receiver<Vec<u8>>,
    peer_ik: [u8; 32],
    via: Transport,
    events: mpsc::Sender<TransportEvent>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Обе полосы закрываются вместе — их отправители лежат в одной
            // записи `Link`, — поэтому `None` с любой из них означает, что
            // соединение больше никому не нужно.
            let frame = tokio::select! {
                biased;
                frame = urgent.recv() => match frame {
                    Some(frame) => frame,
                    None => return,
                },
                frame = bulk.recv() => match frame {
                    Some(frame) => frame,
                    None => return,
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
            let written = writer.write_all(&[tag_of(class)]).await.is_ok()
                && writer.write_all(&frame).await.is_ok()
                && writer.flush().await.is_ok();
            if !written {
                let _ = events.send(TransportEvent::Disconnected { peer_ik, via }).await;
                return;
            }
            // По этой строке видно, сколько кадров ушло на самом деле.
            // Вместе с такой же на чтении она отвечает на вопрос, который
            // иначе неразрешим: кадр не дошёл — его не отправили, потеряли
            // по дороге или не сумели расшифровать?
            tracing::debug!(?via, ?class, "кадр записан");
        }
    });
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
    fn linked() -> (Link, tokio::io::DuplexStream, mpsc::Receiver<TransportEvent>) {
        let (writer, reader) = tokio::io::duplex(4096);
        let (events_tx, events_rx) = mpsc::channel(8);
        let link = Link::open(writer, [7u8; 32], Transport::Lan, events_tx);
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
        spawn_read_loop(reader, Transport::Onion, events_tx);

        let link = Link::open(writer, [7u8; 32], Transport::Onion, mpsc::channel(8).0);
        let mut frame = vec![0u8; SizeClass::S.frame_len()];
        frame[0] = 42;
        link.send(frame.clone()).await.expect("кадр принят");

        match events_rx.recv().await.expect("событие о приёме") {
            TransportEvent::Received { via, peer_hint, frame: got } => {
                assert_eq!(via, Transport::Onion);
                assert!(peer_hint.is_none(), "адрес не говорит, кто это (§8.2)");
                assert_eq!(got, frame, "кадр обязан доехать байт в байт");
            }
            other => panic!("ожидалось событие о приёме, пришло {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_broken_stream_is_reported_once() {
        // Обрыв обязан дойти до ядра событием, а не только отказом отправки:
        // §5.4 иначе узнает о нём лишь по сроку молчания.
        let (writer, reader) = tokio::io::duplex(64);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let link = Link::open(writer, [7u8; 32], Transport::Lan, events_tx);
        drop(reader);

        // Первый кадр может уйти в буфер и не заметить обрыва — второй
        // уже упрётся. Полоса срочная: она ждёт, и потому дойдёт до записи.
        for _ in 0..2 {
            let _ = link.send(vec![0u8; SizeClass::S.frame_len()]).await;
        }

        match events_rx.recv().await.expect("событие об обрыве") {
            TransportEvent::Disconnected { peer_ik, via } => {
                assert_eq!(peer_ik, [7u8; 32]);
                assert_eq!(via, Transport::Lan);
            }
            other => panic!("ожидался обрыв, пришло {other:?}"),
        }
    }
}
