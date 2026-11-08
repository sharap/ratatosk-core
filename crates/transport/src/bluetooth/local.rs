//! Эфир на Linux: объявление, сканирование и канал L2CAP поверх `bluer` (0.4).
//!
//! Отдельным модулем по той же причине, по какой mDNS вынесен из
//! локальной сети: чужой крейт живёт под признаком сборки, а раннер —
//! всегда.
//!
//! # Что прочитано по документации, а не предположено
//!
//! * `Advertisement::advertisement_type` по умолчанию `Broadcast`,
//!   а нам нужен `Peripheral`: широковещательное объявление
//!   не подключаемо, и канал по нему никто не откроет. Это самая
//!   дорогая мелочь во всём модуле — забыв её, получаешь объявление,
//!   которое видно и к которому нельзя подойти;
//! * `SocketAddr::any_le()` при `bind` означает «любой **публичный**
//!   адрес адаптера и динамически выданный PSM». Публичный — и потому
//!   мы им не пользуемся: адаптер с приватностью объявляется случайным
//!   адресом. Слушаем на своём, взятом у адаптера, с нулевым PSM —
//!   номер мы не выбираем, его выдают, и мы его объявляем;
//! * `Adapter::advertise` возвращает ручку, и объявление держится,
//!   пока она жива. Снятие — это `drop`, а не вызов;
//! * `Device::manufacturer_data` отдаёт то, что устройство объявило,
//!   **без подключения** к нему. На этом всё обнаружение и держится.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bluer::adv::{Advertisement, Type as AdvType};
use bluer::l2cap::{Socket as L2capSocket, SocketAddr as L2capAddr, Stream, StreamListener};
use bluer::{Adapter, AdapterEvent, Address, AddressType, DiscoveryFilter, DiscoveryTransport};
use futures::StreamExt;
use ratatosk_crypto::identity::beacon;
use ratatosk_proto::bluetooth as advert;
use ratatosk_proto::transport_policy::{Transport, BT_CONNECT_TIMEOUT_MS};
use tokio::io::WriteHalf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::AIR_RECV_MTU;
use super::{
    dial_attempt_limit, note_advert, short, short_record, unix_seconds, Air, AirSetup, BtAddress,
    DialFuture,
};
use crate::link::spawn_read_loop;
use crate::runner::{TransportError, TransportEvent};

/// Через сколько пробовать сканирование заново, если оно кончилось.
///
/// Кончиться оно может не по нашей вине: `bluetoothd` перезапустили,
/// адаптер моргнул. Выйти из цикла значило бы перестать находить
/// кого-либо до перезапуска приложения — и молча.
const RESCAN_PAUSE: Duration = Duration::from_secs(2);

/// После скольких неудач подряд жаловаться вслух.
///
/// Пять. Меньше — и разовый отказ `bluetoothd` (перезапустили, адаптер
/// моргнул) превращался бы в тревогу на ровном месте; больше — и человек
/// успеет решить, что ступень сломана молча.
const SCAN_COMPLAINT_AFTER: u32 = 5;

/// Как часто переспрашивать адаптер, пока кого-то не хватает.
///
/// Секунда — это заметно меньше того, что человек считает «сразу», и
/// заметно больше интервала объявления BLE. Дороже опрос делать незачем:
/// быстрее собеседник всё равно не объявится.
///
/// Опрос идёт **только пока мы кого-то ждём** (см. `waiting_for_someone`),
/// поэтому в покое он не стоит ничего.
const SWEEP_PAUSE: Duration = Duration::from_secs(1);

/// Сколько давать обзору на то, чтобы убрать антенну.
///
/// Остановка обзора идёт через D-Bus: мы возвращаемся из захода,
/// ручка сессии уходит, `bluetoothd` получает `StopDiscovery`
/// и только потом контроллер перестаёт слушать. Четверть секунды —
/// с запасом на этот круг и вчетверо меньше самой короткой задержки,
/// которую человек замечает.
///
/// Платится она **только когда связи ещё нет**: при поднятой связи
/// набор укладывается в шесть десятков миллисекунд и антенна ему
/// не нужна.
const RADIO_HANDOVER: Duration = Duration::from_millis(250);

/// «Операция уже идёт» — `EALREADY` в `errno` Linux.
///
/// Числом, а не через `libc`: модуль и так только для BlueZ, то есть
/// только для Linux, и тащить крейт ради одной константы дороже, чем
/// назвать её здесь.
const EALREADY: i32 = 114;

/// Сколько ждать, прежде чем пробовать набор снова после «уже идёт».
///
/// Четверть секунды — это порядок интервала соединения BLE, помноженный
/// на несколько попыток контроллера. Чаще спрашивать бессмысленно:
/// ответ не изменится, а каждый заход — это ещё один запрос к ядру.
const BUSY_PAUSE: Duration = Duration::from_millis(250);

/// Сколько раз терпеть «уже идёт», прежде чем считать адрес мёртвым.
///
/// Два. Настоящая гонка — когда собеседник тянет связь навстречу —
/// разрешается за один-два интервала соединения; а «уже идёт», которое
/// не кончается, означает другое: адреса больше нет. Ждать его дольше
/// нечем: приватный адрес проворачивается, и прежний не оживёт.
const BUSY_TRIES: u32 = 2;

/// Как часто спрашивать канал, готов ли он на самом деле.
///
/// Двадцать пять миллисекунд — заметно меньше интервала соединения
/// BLE (десятки миллисекунд), то есть мы не проспим готовность
/// и не устроим при этом опрос вхолостую.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Самый большой пакет, который мы пишем в эфир.
///
/// # Почему число наше, а не провода
///
/// Спросить сокет **необходимо и недостаточно**. Договорный предел
/// отдаёт `BT_SNDMTU`, и на живом замере он сказал 4097 с обеих сторон
/// — ровно то, что мы просили, — а на деле пакет такого размера
/// доезжал до PinePhone (RTL8723CS, ядро 6.17.5) **один раз
/// из четырёх**, тогда как пакеты до 672 байт доезжали все. То есть
/// число, которое называет стек, бывает ложью, и верить ему
/// без потолка нельзя.
///
/// # Почему 672
///
/// Стандарт тут не помощник: он гарантирует только 23 байта у LE
/// (MTU и MPS), 64 — у расширенного режима и 48 у BR/EDR. Кадрами
/// такого размера не живут.
///
/// А 672 — умолчание MTU базового режима L2CAP, и ровно оно зашито
/// в BlueZ (`L2CAP_DEFAULT_MTU`). Похоже, что стек, пообещавший
/// больше, тихо откатывается именно на него; на замере это и видно.
/// Значит 672 — наименьшее число, которое держат все, а не наша
/// догадка.
///
/// # Чего это стоит
///
/// Почти ничего. В эфире пакет всё равно режется контроллером
/// на куски по 27–251 байт, так что кадр в четыре килобайта и так
/// едет десятками посылок. Деление на 672 добавляет лишь заголовок
/// L2CAP на каждый кусок — меньше процента от объёма.
const AIR_SAFE_PACKET: usize = 672;

/// Как часто вещать объявление.
///
/// # Это число стоило замера, и до замера его тут не было вовсе
///
/// Интервал не задавался, то есть действовало умолчание BlueZ. Чем оно
/// обходится — снято на живых устройствах (PinePhone 1.2 и этот ПК,
/// L2CAP-сокеты **не нашим** кодом, чтобы мерить радио, а не себя):
///
/// | Кто объявляется | Сколько шло открытие канала |
/// |---|---|
/// | PinePhone, умолчание BlueZ | 4,3 с · 4,9 с · 8,3 с · дважды дольше 10 с |
/// | ПК, умолчание BlueZ | 1,6 с · 4,2 с · 5,2 с |
/// | ПК, интервал задан (100–150 мс) | 0,35 с · 0,41 с · 0,42 с · 0,48 с |
///
/// Разница в **десять раз**, и она объясняет поломку целиком. Предел
/// одной попытки по постоянному адресу — восемь секунд
/// (`DIAL_PUBLIC`), ступени отведено десять
/// (`BT_CONNECT_TIMEOUT_MS`): с умолчанием BlueZ набор к PinePhone
/// укладывался в срок примерно раз из трёх, а три неудачи подряд
/// уводили ступень в выдержку на сорок пять секунд. Снаружи это
/// выглядело как «эфир работает в одну сторону»: свои наборы телефон
/// делал (его-то срок начинался раньше), а до него не доезжал никто.
///
/// Четверть секунды — не выбор, а **равенство с Android**: там
/// `ADVERTISE_MODE_BALANCED` стоит с самого начала и означает те же
/// 250 мс. Одна и та же мысль дошла до одной половины из двух, и это
/// второй раз в этом файле — первым был «набор старше обзора».
///
/// Меньше брать нельзя без разговора про заряд: объявление — то
/// немногое, что радио делает **всегда** (0.4.3).
const ADVERT_INTERVAL: Duration = Duration::from_millis(250);

/// Запас к границе слота при переобъявлении.
///
/// Объявление меняется вместе с записью маяка, и менять его надо
/// **после** того, как слот сменился у нас, а не до: соседний слот
/// собеседник примет (§5.1 проверяет −1, 0, +1), а вот запись
/// из будущего при расхождении часов — не обязательно.
const SLOT_MARGIN: Duration = Duration::from_secs(2);

/// Перо, которое не пишет пакетов больше безопасного.
///
/// На L2CAP **запись и есть пакет**, и слишком большой пакет собеседник
/// может не принять вовсе — разбор у `AIR_SAFE_PACKET`. Резать надо здесь,
/// а не в `link`: предел — свойство этого звена, а `link` один на все
/// ступени и про радио не знает.
///
/// Короткая запись законна: `link` пишет кадры через `write_all`
/// и сам докладывает остаток.
pub struct Chunked<W> {
    inner: W,
    limit: usize,
}

impl<W> Chunked<W> {
    /// Сколько писать одним пакетом: меньшее из обещанного и безопасного.
    ///
    /// Отдельной функцией ради проверки — радио для неё не нужно.
    #[must_use]
    fn limit_from(announced: Option<usize>) -> usize {
        match announced {
            // Собеседник вправе назвать **меньше** нашего потолка —
            // тогда слушаем его: стандарт разрешает и 23 байта.
            Some(mtu) if mtu > 0 => mtu.min(AIR_SAFE_PACKET),
            // Не спросилось — берём потолок. Это не «на всякий случай»:
            // без ответа мы не знаем ничего, а безопасное известно.
            _ => AIR_SAFE_PACKET,
        }
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Chunked<W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let limit = self.limit;
        let me = self.get_mut();
        let cut = buf.len().min(limit);
        std::pin::Pin::new(&mut me.inner).poll_write(cx, &buf[..cut])
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// Делит поток надвое, обрезав пакеты пера по звену.
fn split_chunked(stream: Stream) -> (tokio::io::ReadHalf<Stream>, Chunked<WriteHalf<Stream>>) {
    // Предел спрашивается **у этого** сокета: он у каждого звена свой.
    let announced = stream.as_ref().send_mtu().ok().map(usize::from);
    let limit = Chunked::<WriteHalf<Stream>>::limit_from(announced);
    tracing::info!(обещано = ?announced, пишем_по = limit, "эфир: предел пакета");
    let (reader, writer) = tokio::io::split(stream);
    (reader, Chunked { inner: writer, limit })
}

/// Эфир этой машины: `bluer`, сокеты L2CAP, свои задачи.
///
/// Реализация [`Air`] для Linux. Вся её жизнь — в поле: эфир есть,
/// пока есть `Radio`, и гаснет он не вызовом, а `drop`.
#[derive(Default)]
pub struct LocalAir {
    radio: Option<Radio>,
    adapter: AdapterSlot,
    airtime: Arc<Airtime>,
    /// Куда отдавать кадры, прочитанные из **набранных** каналов.
    ///
    /// Понадобилось вместе с ответом в принятый канал: у одного канала
    /// L2CAP две стороны, и если собеседник отвечает в тот, который набрали
    /// мы, читать его обязаны тоже мы. Набор же идёт своей задачей, до
    /// которой `AirSetup` не доезжает, — отсюда и это поле.
    events: Arc<Mutex<Option<mpsc::Sender<TransportEvent>>>>,
}

/// Кто сейчас занимает радио: обзор или набор.
///
/// # Зачем это вообще понадобилось
///
/// **Обзор и соединение делят одну антенну.** Пока контроллер слушает
/// эфир, устанавливать связь ему некогда, и `Stream::connect` просто
/// висит — не отказывает, а висит, пока не кончится отведённый срок.
///
/// Разбор со стенда, и он однозначен. Набор при уже поднятой связи
/// («соединены=Some(true)» — её поднял собеседник) удавался за 60 мс.
/// Набор без неё («соединены=Some(false)») не удавался **ни разу**:
/// ровно десять секунд тишины и «набор не уложился в срок». И рядом
/// улика: объявления собеседника, которые сыпались раз в секунду,
/// на время набора пропадали и возвращались сразу после его конца.
/// То есть обзор и набор мешали друг другу, и видно это было прямо
/// в журнале.
///
/// Правило поэтому такое: **набор старше обзора**. Начался набор —
/// обзор уступает антенну и возвращается, когда набор кончился.
/// Для Android это было написано с самого начала (там обзор
/// останавливают руками перед `connect`), а для Linux — нет.
/// Одна и та же мысль, дошедшая до одной половины из двух.
#[derive(Debug)]
struct Airtime {
    /// Сколько наборов идёт прямо сейчас.
    ///
    /// Счётчик, а не флаг: наборов бывает два разом — срочный канал
    /// и объёмный, — и флаг, снятый первым закончившимся, вернул бы
    /// обзор в эфир посреди второго.
    ///
    /// `watch`, а не `Notify`: у него есть текущее значение, и ожидание
    /// не может проскочить мимо изменения, случившегося между проверкой
    /// и подпиской.
    dialing: tokio::sync::watch::Sender<usize>,
}

impl Default for Airtime {
    fn default() -> Airtime {
        Airtime { dialing: tokio::sync::watch::channel(0).0 }
    }
}

impl Airtime {
    /// Занимает радио на время набора.
    fn hold(self: &Arc<Self>) -> Held {
        self.dialing.send_modify(|busy| *busy += 1);
        Held(Arc::clone(self))
    }

    /// Ждёт, пока наборы кончатся.
    async fn wait_until_free(&self) {
        let mut changes = self.dialing.subscribe();
        loop {
            let busy = *changes.borrow_and_update() > 0;
            if !busy {
                return;
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
    }

    /// Ждёт, пока начнётся набор.
    async fn wait_until_busy(&self) {
        let mut changes = self.dialing.subscribe();
        loop {
            let busy = *changes.borrow_and_update() > 0;
            if busy {
                return;
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
    }
}

/// Занятое радио. Освобождается вместе с концом набора — любым.
struct Held(Arc<Airtime>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.dialing.send_modify(|busy| *busy = busy.saturating_sub(1));
    }
}

/// Показывает то единственное, что о нём стоит знать: поднят ли эфир.
///
/// Руками, а не выводом: внутри лежит `bluer::Adapter`, и обещать за чужой
/// тип, что он умеет печататься, мы не вправе. Вывод сломался бы не здесь,
/// а в чужой сборке и при обновлении чужого крейта.
impl std::fmt::Debug for LocalAir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAir").field("поднят", &self.radio.is_some()).finish()
    }
}

/// Адаптер, взятый при подъёме, — чтобы о нём можно было спросить снаружи.
///
/// Нужен **набору**, и не для самого набора: `Stream::connect` адаптера
/// не требует. Нужен он затем, чтобы спросить у системы, **соединены ли
/// мы с этим устройством уже**. Без этого вопроса отказ `EALREADY`
/// («операция уже идёт») нечем отличить от случайной неудачи, а это
/// разные беды с разным лечением.
type AdapterSlot = Arc<Mutex<Option<Adapter>>>;

impl LocalAir {
    /// Заводит эфир, не поднимая его.
    #[must_use]
    pub fn new() -> LocalAir {
        LocalAir::default()
    }
}

impl Air for LocalAir {
    type Stream = Chunked<WriteHalf<Stream>>;

    fn raise(&mut self, setup: AirSetup<Self::Stream>) {
        if let Ok(mut held) = self.events.lock() {
            *held = Some(setup.events.clone());
        }
        self.radio =
            Some(Radio::start(setup, Arc::clone(&self.adapter), Arc::clone(&self.airtime)));
    }

    fn lower(&mut self) {
        // Всё, что знает радио, уходит вместе с ним: объявление,
        // сокет, сканирование. См. `Drop for Radio`.
        self.radio = None;
        if let Ok(mut held) = self.adapter.lock() {
            *held = None;
        }
        if let Ok(mut held) = self.events.lock() {
            *held = None;
        }
    }

    fn dial(&self, target: BtAddress) -> DialFuture<Self::Stream> {
        // Набор не заимствует эфир: он уезжает в задачу связи, которая
        // переживает и выключение ступени, и сам раннер.
        let events = self.events.lock().ok().and_then(|held| held.clone());
        Box::pin(dial(target, Arc::clone(&self.adapter), Arc::clone(&self.airtime), events))
    }
}

/// Живой эфир. Всё, что он держит, уходит вместе с ним.
#[derive(Debug)]
struct Radio {
    task: JoinHandle<()>,
}

impl Drop for Radio {
    fn drop(&mut self) {
        // Снятие объявления и остановка сканирования — это `drop`
        // ручек, лежащих на стеке задачи. Отмена задачи роняет стек,
        // а с ним и ручки: человек, выключивший ступень, уходит
        // из эфира сразу.
        self.task.abort();
    }
}

impl Radio {
    /// Поднимает эфир в своей задаче.
    fn start(
        setup: AirSetup<Chunked<WriteHalf<Stream>>>,
        adapter: AdapterSlot,
        airtime: Arc<Airtime>,
    ) -> Radio {
        let events = setup.events.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run(setup, adapter, airtime).await {
                // Ступень объявляется потерянной, а не молчит: §5.4
                // иначе выбирал бы эфир, которого нет, и платил бы
                // за него полным сроком набора на каждом сообщении.
                tracing::warn!(%error, "эфир не поднялся");
                let _ = events.send(TransportEvent::Lost { transport: Transport::Bt }).await;
            }
        });
        Radio { task }
    }
}

/// Останавливает задачу вместе со своей жизнью.
struct Stopped(JoinHandle<()>);

impl Drop for Stopped {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Отказ чужого крейта — словами, которые можно показать человеку.
///
/// `bluer::Error` не наш тип, и превращать его в `Io` было бы неправдой:
/// «адаптер выключен» и «нет дескрипторов» — разные беды, а выглядели бы
/// одинаково.
fn refused(what: &str, error: impl std::fmt::Display) -> TransportError {
    TransportError::Refused(format!("{what}: {error}"))
}

/// Поднимает эфир и не возвращается, пока он жив.
async fn run(
    setup: AirSetup<Chunked<WriteHalf<Stream>>>,
    slot: AdapterSlot,
    airtime: Arc<Airtime>,
) -> Result<(), TransportError> {
    let events = setup.events.clone();
    let my_ik = setup.my_ik;
    let session = bluer::Session::new().await.map_err(|e| refused("сессия Bluetooth", e))?;
    let adapter = session.default_adapter().await.map_err(|e| refused("адаптер", e))?;
    if let Ok(mut held) = slot.lock() {
        *held = Some(adapter.clone());
    }

    // **Адаптер мы не включаем.** Выключенный Bluetooth — это выбор
    // человека, и щёлкать его переключатель за него нельзя. Ступень
    // честно не поднимается, и причина называется словами.
    if !adapter.is_powered().await.map_err(|e| refused("адаптер", e))? {
        return Err(TransportError::Refused(
            "адаптер Bluetooth выключен — включите его в системе".to_owned(),
        ));
    }

    // Сокет — первым: его номер едет в объявлении.
    //
    // Привязка идёт к **своему** адресу адаптера и его типу, а не
    // к `SocketAddr::any_le()`. Разница не косметическая: `any_le`
    // означает «любой **публичный** адрес», а адаптер с включённой
    // приватностью объявляется случайным — и входящее соединение
    // придёт не на тот адрес, на котором мы слушаем. Так сделано
    // и в примере `l2cap_server` у `bluer`, а пример, в отличие
    // от справочника, кто-то запускал на железе.
    //
    // Ноль в номере PSM — «выдайте свободный»: ниже `PSM_LE_DYN_START`
    // слушать всё равно не дадут без `CAP_NET_BIND_SERVICE`.
    let own = adapter.address().await.map_err(|e| refused("адрес адаптера", e))?;
    let own_type = adapter.address_type().await.map_err(|e| refused("тип адреса", e))?;
    let listener = StreamListener::bind(L2capAddr::new(own, own_type, 0))
        .await
        .map_err(|e| refused("сокет L2CAP", e))?;
    // **MTU приёма — до первого `accept`.** Принятые сокеты наследуют его
    // у слушающего, и выставленный позже он до них уже не доедет.
    //
    // Отказ здесь не смертелен: канал поднимется и с умолчанием BlueZ,
    // просто собеседник будет резать кадры на семь пакетов. Молчать
    // об этом нельзя — разбирать потом придётся по почерку.
    ask_recv_mtu(listener.as_ref(), "слушающий");
    let psm = listener.as_ref().local_addr().map_err(|e| refused("номер канала", e))?.psm;
    tracing::info!(
        psm,
        адрес = %own,
        тип = ?own_type,
        mtu = AIR_RECV_MTU,
        "эфир: канал L2CAP занят"
    );

    let _accepting = Stopped(spawn_accept_loop(listener, events.clone(), setup.accepted.clone()));
    let _scanning = Stopped(spawn_scan_loop(adapter.clone(), setup, airtime));

    advertise_loop(adapter, my_ik, psm, events).await
}

/// Объявляет себя и переобъявляет со сменой слота.
///
/// Не возвращается никогда, пока объявлять удаётся. Переобъявление
/// нужно потому, что запись маяка ротируется (§5.1): объявление,
/// не меняющееся со временем, — это долговременный опознаватель
/// устройства, то есть ровно то, чего маяк избегает.
async fn advertise_loop(
    adapter: Adapter,
    my_ik: [u8; 32],
    psm: u16,
    events: mpsc::Sender<TransportEvent>,
) -> Result<(), TransportError> {
    let mut announced = false;
    // Просить ли интервал — спрашивается **до** первой попытки.
    //
    // # Разбор, стоивший живого устройства
    //
    // Интервал ядро ставит командой расширенного объявления, а у
    // контроллеров старше BT 5.0 её нет: BlueZ отвечает «Failed to
    // register advertisement», и объявления не выходит **никакого**.
    // То есть правка, ускоряющая набор на новых устройствах, на старых
    // убивает ступень целиком. Проверено на PinePhone (RTL8723CS,
    // BT 4.2): эфир не поднялся вовсе.
    //
    // Хуже того, **каждая отказная попытка съедает место под
    // объявление**: на том же PinePhone `SupportedInstances` упал
    // с пяти до трёх ровно по числу моих попыток, и обратно их
    // возвращает только перезапуск `bluetoothd`. Значит «попробовать
    // и отступить» — плохой способ: он тратит невозвратное.
    //
    // Спрашивать надо платформу, и признак у неё есть: вторичные
    // каналы (`SupportedSecondaryChannels`) бывают только
    // у расширенного объявления. У ПК (BT 5.3) там 1M, 2M и Coded,
    // у PinePhone список пуст.
    let extended = adapter
        .supported_advertising_secondary_channels()
        .await
        .ok()
        .flatten()
        .is_some_and(|channels| !channels.is_empty());
    if !extended {
        // Вслух и один раз: набирать нас будут в разы дольше, и знать
        // это надо до разбора «почему до меня не доходят», а не после.
        tracing::warn!(
            "эфир: контроллер не умеет расширенного объявления — интервал назначить \
             нечем, объявляемся умолчанием платформы, и набирать нас будут дольше (0.4.3)"
        );
    }
    // Отступление остаётся сверх расспроса: платформа может ответить
    // «умею», а регистрация всё равно не пройдёт — тогда лучше медленное
    // объявление, чем никакое.
    let mut interval_taken = extended;
    loop {
        let now = unix_seconds();
        let slot = beacon::slot(now);
        let record = beacon::record(&my_ik, slot, fresh_nonce());
        let payload =
            advert::payload(&record, psm).map_err(|e| refused("нагрузка объявления", e))?;

        let handle = match adapter.advertise(announcement(&payload, interval_taken)).await {
            Ok(handle) => handle,
            Err(error) if interval_taken => {
                // Платформа сказала «умею», а не вышло. Отступаем — но
                // место под объявление эта попытка уже потратила, и
                // вернуть его может только перезапуск `bluetoothd`.
                tracing::warn!(
                    %error,
                    просили_мс = ADVERT_INTERVAL.as_millis(),
                    "эфир: интервал объявления не принят, хотя платформа обещала — \
                     объявляемся умолчанием, и набирать нас будут дольше (0.4.3)"
                );
                interval_taken = false;
                adapter
                    .advertise(announcement(&payload, false))
                    .await
                    .map_err(|e| refused("объявление", e))?
            }
            Err(error) => return Err(refused("объявление", error)),
        };

        if !announced {
            announced = true;
            // Готовность объявляется **после** того, как объявление
            // ушло в эфир, а не после занятия сокета: до этого
            // мгновения нас не найдёт никто, и §5.4, выбрав ступень,
            // сжёг бы попытку.
            let _ = events.send(TransportEvent::Ready { transport: Transport::Bt }).await;
        }

        // **Каждое объявление, а не только первое.** Запись маяка
        // проворачивается со слотом, и по журналу одной машины нельзя было
        // сказать, что именно она вещала в тот миг, когда другая её
        // не узнала. Слушающая сторона печатает начало записи той же
        // формой — два журнала сличаются напрямую.
        //
        // Строка одна на четверть часа, так что шумом она не станет.
        tracing::info!(
            slot,
            ключ = %short(&my_ik),
            маяк = %short_record(&record),
            "эфир: объявились"
        );

        // Спать до границы следующего слота — того же расписания
        // держится маяк локальной сети.
        let now = unix_seconds();
        let next = (beacon::slot(now) + 1) * beacon::SLOT_SECONDS;
        tokio::time::sleep(Duration::from_secs(next.saturating_sub(now)) + SLOT_MARGIN).await;

        // Прежнее снимается перед новым, а не после: два объявления
        // одного устройства в эфире — это два разных маяка от одного
        // радио, то есть подсказка тому, кто их сличает.
        drop(handle);
    }
}

/// Собирает объявление: нагрузка, тип, интервал.
///
/// Отдельной функцией затем, что её можно проверить **без радио**:
/// числа и тип здесь — обещания, а не настройки.
fn announcement(payload: &[u8], with_interval: bool) -> Advertisement {
    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(advert::COMPANY_ID, payload.to_vec());
    Advertisement {
        // **Именно `Peripheral`.** По умолчанию тип `Broadcast`,
        // а широковещательное объявление не подключаемо: видно нас
        // было бы, а подойти нельзя.
        advertisement_type: AdvType::Peripheral,
        manufacturer_data,
        discoverable: Some(true),
        // Имя устройства не объявляется никогда: оно и бюджет
        // объявления рвёт (0.4.3), и вещает в эфир имя телефона.
        local_name: None,
        // **Интервал называется, а не наследуется** — но только там, где
        // его принимают. Разбор — у `ADVERT_INTERVAL`; коротко: умолчание
        // платформы стоило секунд на открытие канала, а наш предел
        // попытки — восемь секунд.
        min_interval: with_interval.then_some(ADVERT_INTERVAL),
        max_interval: with_interval.then_some(ADVERT_INTERVAL),
        ..Default::default()
    }
}

/// Соль объявления — новая на каждое переобъявление.
///
/// Она и позволяет менять объявление чаще слота, не теряя
/// узнаваемости: собеседник проверяет запись целиком, а не её часть.
fn fresh_nonce() -> [u8; 8] {
    use rand_core::RngCore as _;

    let mut nonce = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Принимает входящие каналы и делит каждый надвое.
///
/// **Принятое работает не только на чтение — с этой поставки.** Канал
/// L2CAP двусторонний по устройству, и перо от него уезжает наверх:
/// набрать телефон в ответ нельзя (приватный адрес проворачивается,
/// а сопряжения у нас нет), зато ответить в открытый им канал — можно.
/// Чей это канал, здесь по-прежнему неизвестно: имя ему назовёт ядро.
fn spawn_accept_loop(
    listener: StreamListener,
    events: mpsc::Sender<TransportEvent>,
    accepted: mpsc::Sender<(u64, Chunked<WriteHalf<Stream>>)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Номера принятых каналов свои и растут подряд. Совпасть им
        // не с чем: номера этой ступени ходят только между раннером
        // и этим циклом.
        let mut next_link: u64 = 0;
        loop {
            match listener.accept().await {
                Ok((stream, from)) => {
                    let link = next_link;
                    next_link += 1;
                    // Отладочным видом, а не показом: `SocketAddr`
                    // из `bluer` — чужой тип, и обещать ему `Display`
                    // мы не вправе.
                    tracing::debug!(?from, link, "эфир: входящий канал");
                    let (reader, writer) = split_chunked(stream);
                    // Перо — первым: раннер обязан знать про канал раньше,
                    // чем ядро получит пришедший им кадр, иначе имя
                    // приедет каналу, о котором раннер ещё не слышал.
                    if accepted.send((link, writer)).await.is_err() {
                        // Раннера больше нет — читать некому и незачем.
                        return;
                    }
                    spawn_read_loop(reader, Transport::Bt, Some(link), events.clone());
                }
                // Выйти из цикла значило бы замолчать навсегда.
                Err(error) => {
                    tracing::debug!(?error, "эфир: канал не принят");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    })
}

/// Слушает эфир и опознаёт объявления маяком.
fn spawn_scan_loop(
    adapter: Adapter,
    setup: AirSetup<Chunked<WriteHalf<Stream>>>,
    airtime: Arc<Airtime>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Сколько заходов подряд не задались. Нужен счётчик, а не флаг:
        // разовый отказ — обычное дело (`bluetoothd` моргнул), а вот
        // непрекращающийся означает совсем другую беду и лечится иначе.
        let mut failures: u32 = 0;
        loop {
            // Пока идёт набор, обзора нет вовсе: антенна одна. Ждём
            // здесь, а не внутри захода, — так заход всегда начинается
            // со свободным радио.
            airtime.wait_until_free().await;
            match scan(&adapter, &setup, &airtime).await {
                // Уступили набору: возвращаемся немедленно, как только
                // он кончится. Пауза здесь была бы потерянными секундами
                // ровно там, где человек ждёт ответа.
                Ok(Yielded::ToDial) => {
                    failures = 0;
                    continue;
                }
                Ok(Yielded::StreamEnded) => failures = 0,
                Err(error) => {
                    failures += 1;
                    complain(&error, failures);
                }
            }
            // Сканирование могло кончиться не по нашей вине —
            // `bluetoothd` перезапустили, адаптер моргнул. Пробуем
            // снова: молча перестать находить кого-либо хуже.
            //
            // А вот **долбиться** в него каждые две секунды впустую —
            // тоже незачем: если обзор не пошёл десять раз подряд, он
            // не пойдёт и с одиннадцатого, пока не уберут причину.
            let pause =
                if failures > SCAN_COMPLAINT_AFTER { RESCAN_PAUSE * 8 } else { RESCAN_PAUSE };
            tokio::time::sleep(pause).await;
        }
    })
}

/// Жалуется на неудавшийся обзор — ровно один раз, зато по делу.
///
/// # Зачем понадобилось
///
/// Разбор со стенда, и беда была тихой. `bluetoothd` отвечал «обзор уже
/// идёт» — его держало **чужое** приложение, — и цикл честно пробовал
/// снова каждые две секунды. На уровне `debug`, то есть для человека
/// молча. Ступень при этом числилась рабочей: объявление-то ушло.
///
/// Снаружи это худший вид поломки: нас слышно, мы не слышим никого,
/// и причина не названа нигде. Половина ступени, притворяющаяся целой.
fn complain(error: &TransportError, failures: u32) {
    if failures < SCAN_COMPLAINT_AFTER {
        // Разовый отказ — обычное дело, и шуметь о нём не стоит.
        tracing::debug!(%error, "эфир: сканирование прервалось");
        return;
    }
    if failures > SCAN_COMPLAINT_AFTER {
        // Пожаловались один раз. Повторять — значит завалить журнал
        // той же строкой и спрятать в ней всё остальное.
        return;
    }
    tracing::warn!(
        %error,
        заходов = failures,
        "эфир: обзор не идёт — нас слышно, мы не слышим никого;          чаще всего его держит другое приложение: `bluetoothctl scan off`,          закройте настройки Bluetooth и менеджеры устройств"
    );
}

/// Чем кончился заход сканирования.
///
/// Различать обязательно: уступка набору — дело штатное и частое,
/// и платить за неё той же паузой, что за упавший `bluetoothd`,
/// значило бы добавлять секунды к каждой отправке.
enum Yielded {
    /// Начался набор, антенна отдана ему.
    ToDial,
    /// Поток событий кончился сам.
    StreamEnded,
}

/// Один заход сканирования — до конца потока событий.
async fn scan(
    adapter: &Adapter,
    setup: &AirSetup<Chunked<WriteHalf<Stream>>>,
    airtime: &Airtime,
) -> Result<Yielded, TransportError> {
    let filter = DiscoveryFilter {
        // Только LE: классического радио нам не нужно вовсе, а
        // чередующийся обзор тратил бы время на него.
        transport: DiscoveryTransport::Le,
        // Повторы объявлений нужны: собеседник переобъявляется
        // со сменой слота, и без повторов мы узнали бы об этом
        // только при следующем его появлении в эфире.
        duplicate_data: true,
        ..Default::default()
    };
    adapter.set_discovery_filter(filter).await.map_err(|e| refused("фильтр обзора", e))?;
    let mut stream =
        adapter.discover_devices_with_changes().await.map_err(|e| refused("обзор", e))?;
    // **Удавшийся обзор говорит об этом вслух, и это не шум.** Вся эта
    // ступень отлаживается по журналу, а тишина в нём означала два разных
    // состояния сразу: «обзор идёт, собеседник молчит» и «обзор не идёт».
    // Различить их было нечем, и разбор каждый раз начинался с догадки.
    // Строка одна на заход, а заход длится минутами.
    tracing::info!("эфир: обзор пошёл");

    // Опрос идёт **рядом** с потоком событий, а не вместо него, и первый
    // тик `interval` срабатывает сразу — то есть заход сканирования
    // начинается с того, что адаптер уже знает.
    let mut sweeps = tokio::time::interval(SWEEP_PAUSE);
    sweeps.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            // **Первым делом и с пометкой `biased`.** Набор ждать не может:
            // он уже идёт, а его время уходит в отведённый срок. Честная
            // жеребьёвка `select!` дала бы обзору шанс утащить ещё одно
            // событие — и вместе с ним антенну.
            () = airtime.wait_until_busy() => {
                tracing::debug!("эфир: уступаем антенну набору");
                // Поток обзора уходит вместе с возвратом, и вместе с ним
                // прекращается сам обзор: держит его ручка внутри потока.
                return Ok(Yielded::ToDial);
            }
            event = stream.next() => {
                // Конец потока — конец захода: наружу, там пересоберут.
                let Some(event) = event else { return Ok(Yielded::StreamEnded) };
                // Прочие события эфира не касаются. `DeviceChanged` среди
                // них нет вовсе: `discover_devices_with_changes` отдаёт
                // смену свойств тем же `DeviceAdded`.
                if let AdapterEvent::DeviceAdded(address) = event {
                    look_at(adapter, setup, address).await;
                }
            }
            _ = sweeps.tick() => {
                // Опрашивать всё подряд — дорого: под BLE вещает всякий
                // наушник, и в вагоне метро это сотни устройств. Поэтому
                // опрос идёт **только пока мы кого-то ждём** и смолкает
                // сам, едва все дождались.
                if waiting_for_someone(setup) {
                    resweep(adapter, setup).await;
                }
            }
        }
    }
}

/// Ждём ли мы кого-нибудь, кого ещё не слышали.
///
/// Ровно это и есть условие опроса: список контактов у нас есть всегда,
/// а вот «никого не хватает» — состояние обычное, и в нём радио трогать
/// незачем.
fn waiting_for_someone<S>(setup: &AirSetup<S>) -> bool {
    let watched: Vec<[u8; 32]> = setup.watched.lock().map(|w| w.clone()).unwrap_or_default();
    if watched.is_empty() {
        return false;
    }
    let Ok(directory) = setup.directory.lock() else { return false };
    watched.iter().any(|peer_ik| !directory.contains_key(peer_ik))
}

/// Спрашивает адаптер обо всём, что он уже знает.
///
/// # Зачем это нужно сверх потока событий
///
/// Поток событий отвечает на вопрос «что изменилось», а нам нужен другой:
/// «что известно **сейчас**». Разница видна в тот миг, когда человек
/// добавляет контакт: объявление собеседника могло прозвучать минуту
/// назад, `bluetoothd` его помнит — а нового события до следующего
/// объявления не будет, и мы ждём его секундами. На стенде это выглядело
/// как «добавил карточку, и десять секунд собеседника нет в сети», при
/// двух метрах между машинами.
///
/// Буфер услышанного (`Heard`) этого не закрывает: в нём лежит только то,
/// что поймало **наше** сканирование с момента включения ступени, а у
/// адаптера память шире и старше.
async fn resweep<S>(adapter: &Adapter, setup: &AirSetup<S>) {
    let Ok(addresses) = adapter.device_addresses().await else { return };
    for address in addresses {
        look_at(adapter, setup, address).await;
        // Обход обрывается, едва все дождались, и это не мелочь.
        // Каждое устройство — запрос к `bluetoothd`, а в вагоне метро
        // их сотни; дойдя до нужного пятым, платить за остальные триста
        // незачем. Заодно обход не держит поток событий: он идёт в том
        // же цикле, и пока мы спрашиваем чужие наушники, объявление
        // собеседника ждёт разбора.
        if !waiting_for_someone(setup) {
            return;
        }
    }
}

/// Читает объявление одного устройства и опознаёт его маяком.
///
/// Одна на событие и на опрос: два пути к одному и тому же вопросу —
/// «чьё это объявление» — разошлись бы на первой же правке.
async fn look_at<S>(adapter: &Adapter, setup: &AirSetup<S>, address: Address) {
    let Ok(device) = adapter.device(address) else { return };
    // Данные объявления читаются **без подключения**: это то,
    // что устройство сказало в эфир, и больше нам ничего не надо.
    let Ok(Some(data)) = device.manufacturer_data().await else { return };
    let Some(bytes) = data.get(&advert::COMPANY_ID) else { return };
    // Опознание — **общее** для обеих реализаций эфира и живёт
    // выше (`note_advert`): перебор известных `IK` по маяку —
    // протокольное правило (§5.1), а не дело радио. Радио здесь
    // отвечает ровно на два вопроса: чьи это байты и каким адресом
    // объявились.
    let random = matches!(device.address_type().await, Ok(AddressType::LeRandom) | Err(_));
    for peer_ik in note_advert(setup, bytes, *address, random) {
        // Событие шлётся на каждое объявление, а не только
        // на первое: переход «не слышали → слышим» считает ядро
        // (`Input::SeenOnBt`), и повтор оно отбрасывает само.
        // Решать это здесь значило бы завести вторую половину
        // одного правила.
        let _ = setup.events.send(TransportEvent::SeenOnBt { peer_ik }).await;
    }
}

/// Дожидается, пока канал станет настоящим.
///
/// # Зачем это вообще нужно
///
/// `Stream::connect` в `bluer` 0.17 возвращает успех **раньше**, чем
/// канал установлен, и первая запись после него падает с ENOTCONN
/// («Transport endpoint is not connected», код 107). Это не наша
/// ошибка и не догадка: она заведена у них под номером 163 и на день
/// поставки открыта. У нас она выглядела так — «канал открыт» за
/// двести микросекунд, ни одного записанного кадра и семь сообщений
/// разом в ожидании; работало только со второго захода, когда ACL уже
/// подняла встречная сторона.
///
/// # Почему опрос, а не задержка
///
/// В том же обсуждении обходной путь — поспать полторы секунды после
/// набора. Нам это не годится дважды: полторы секунды тратились бы
/// и там, где канал готов через сорок миллисекунд, а там, где радио
/// медленнее обычного, их всё равно не хватило бы.
///
/// Спрашиваем поэтому сам сокет, и спрашиваем тем, о чём документация
/// `bluer` говорит прямо: MTU отправки «может быть недоступен сразу
/// после установления соединения, и тогда функция вернёт ошибку;
/// в этом случае попробуйте спросить его снова после того, как что-то
/// отправлено или принято». То есть удавшийся запрос MTU и есть
/// признак живого канала — единственный, который чужой крейт отдаёт
/// **не** через запись.
///
/// Возвращает, сколько пришлось ждать: это первое измеренное число
/// ступени, и в журнале оно стоит рядом с набором не для красоты —
/// по нему видно, во что обходится открытие канала на самом деле.
async fn settle(stream: &Stream, budget: Duration) -> Result<Duration, TransportError> {
    let started = std::time::Instant::now();
    loop {
        if stream.as_ref().send_mtu().is_ok() {
            return Ok(started.elapsed());
        }
        if started.elapsed() >= budget {
            return Err(TransportError::Timeout);
        }
        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// Просит у сокета наш MTU приёма и говорит, если не дали.
///
/// Отдельной функцией, потому что мест два — слушающий сокет и набранный,
/// — и разойдись они, половина каналов возила бы кадры целиком, а половина
/// кусками. Такую разницу ловят не логикой, а неделей на стенде.
fn ask_recv_mtu(socket: &L2capSocket<Stream>, whose: &str) {
    if let Err(error) = socket.set_recv_mtu(AIR_RECV_MTU) {
        // Не отказ: канал поднимется и с умолчанием BlueZ. Но кадр тогда
        // приедет несколькими пакетами вместо одного, и знать об этом надо
        // заранее, а не выводить потом из почерка порчи.
        tracing::warn!(
            %error,
            сокет = whose,
            просили = AIR_RECV_MTU,
            "эфир: MTU приёма выставить не удалось — кадры поедут кусками"
        );
        return;
    }
    // **Читаем обратно, а не верим просьбе.** Ядро вправе дать меньше,
    // и разница между «попросили» и «дали» — это ровно то число, по
    // которому потом видно, одним пакетом едет кадр или семью. Гадать
    // о нём по чужому ядру нечего: пусть говорит само.
    match socket.recv_mtu() {
        Ok(given) => tracing::info!(
            сокет = whose,
            просили = AIR_RECV_MTU,
            дали = given,
            "эфир: MTU приёма выставлен"
        ),
        Err(error) => tracing::debug!(%error, сокет = whose, "эфир: MTU приёма не спросился"),
    }
}

/// Набирает канал, выставив MTU приёма **до** соединения.
///
/// `Stream::connect` завёл бы сокет сам, и вклиниться было бы некуда:
/// MTU обязан стоять до того, как стороны о нём договорятся. Поэтому
/// сокет собирается здесь по частям — ровно теми же тремя шагами, что
/// и внутри `bluer`, плюс наш четвёртый между вторым и третьим.
async fn connect_with_mtu(sa: L2capAddr) -> std::io::Result<Stream> {
    let socket = L2capSocket::<Stream>::new_stream()?;
    // Привязка к «любому своему» адресу того же вида, что у цели:
    // сокет обязан быть привязан до соединения, а какой именно адрес
    // адаптера возьмётся — решает система.
    let local = if sa.addr_type == AddressType::BrEdr {
        L2capAddr::any_br_edr()
    } else {
        L2capAddr::any_le()
    };
    socket.bind(local)?;
    ask_recv_mtu(&socket, "набранный");
    socket.connect(sa).await
}

/// Набирает канал к услышанному собеседнику.
///
/// Отказ здесь **называется целиком**, и это не избыточность журнала.
/// Ошибок у `connect` по сути три разных, и лечатся они по-разному:
/// «нет такого устройства» (объявление устарело, адрес BLE провернулся),
/// «отказано в доступе» (уровень безопасности сокета либо пара
/// не установлена) и «соединение отвергнуто» (этот PSM никто не слушает).
/// Различить их можно только увидев код, который вернуло ядро.
async fn dial(
    target: BtAddress,
    adapter: AdapterSlot,
    airtime: Arc<Airtime>,
    events: Option<mpsc::Sender<TransportEvent>>,
) -> Result<Chunked<WriteHalf<Stream>>, TransportError> {
    let address_type = if target.random { AddressType::LeRandom } else { AddressType::LePublic };
    let sa = L2capAddr::new(Address::new(target.addr), address_type, target.psm);
    let budget = Duration::from_millis(BT_CONNECT_TIMEOUT_MS);
    let started = std::time::Instant::now();

    // **Главный вопрос этого разбора — и задаётся он до набора.**
    //
    // Отказ `EALREADY` приходил ровно тогда, когда набор шёл сразу после
    // входящего кадра, то есть когда связь с этим устройством уже подняла
    // **встречная** сторона. Подозрение поэтому такое: контроллеру
    // предлагается быть ведущим к тому, к кому он уже ведомый, а этого
    // многие не умеют.
    //
    // Подозрение и остаётся подозрением, пока его не с чем сверить.
    // Строка ниже и есть то, с чем сверять: если перед каждым неудачным
    // набором стоит «соединены=Some(true)», объяснение найдено; если
    // «Some(false)» — неверно, и искать надо другое.
    let connected = peer_connected(&adapter, target.addr).await;
    tracing::info!(
        адрес = %super::radio_address(&target.addr),
        случайный = target.random,
        psm = target.psm,
        соединены = ?connected,
        "эфир: набираем канал L2CAP"
    );

    // **Антенна занимается на всё время набора.** Обзор увидит это
    // и отступит; вернётся он сам, когда ручка ниже уйдёт вместе
    // с этой функцией — удачно она кончится или нет.
    let _antenna = airtime.hold();

    // Отступает обзор не мгновенно: остановка идёт через D-Bus,
    // и контроллер узнаёт о ней не в тот же миг. Ждать эту передышку
    // стоит **только когда связи ещё нет** — а когда она есть, набор
    // укладывается в шесть десятков миллисекунд и антенна ему не нужна
    // вовсе. Вот для чего этот вопрос задавался до сих пор ради одного
    // журнала.
    if connected != Some(true) {
        tokio::time::sleep(RADIO_HANDOVER).await;
    }

    // Предел одной попытки зависит от того, каков адрес: постоянному
    // собеседнику дают дозвониться, приватный проверяют накоротке.
    // Само правило — не здесь: оно протокольное (`dial_attempt_limit`).
    let attempt = dial_attempt_limit(target.random);

    let mut busy_tries = 0u32;
    let stream = loop {
        let left = budget.saturating_sub(started.elapsed());
        if left.is_zero() {
            tracing::warn!(
                адрес = %super::radio_address(&target.addr),
                срок_мс = BT_CONNECT_TIMEOUT_MS,
                "эфир: набор не уложился в срок"
            );
            return Err(TransportError::Timeout);
        }
        // Каждой попытке — свой предел, а не весь остаток бюджета:
        // висящий дольше `connect` не «медленный», он мёртвый, и следующая
        // попытка упрётся в тот же адрес. Сколько именно ждать — решено
        // выше по адресу, а не здесь.
        match tokio::time::timeout(left.min(attempt), connect_with_mtu(sa)).await {
            Ok(Ok(stream)) => break stream,
            // «Операция уже идёт» — не отказ, а **занятость**: к этому
            // устройству уже тянут связь, и через мгновение она либо
            // будет, либо нет.
            //
            // Повторов при этом считанное число, и это поправка к самому
            // себе. Сперва здесь стояло «пробовать до конца бюджета», и
            // на стенде это вышло хуже прежнего: там, где адрес попросту
            // мёртв — собеседник провернул приватный адрес, — отказ
            // приходил за две секунды, а стал приходить за десять. Цена
            // ошибки несимметрична: лишний повтор стоит полсекунды,
            // а лишнее ожидание — всей попытки §5.4.
            Ok(Err(error)) if error.raw_os_error() == Some(EALREADY) => {
                busy_tries += 1;
                if busy_tries > BUSY_TRIES {
                    tracing::warn!(
                        адрес = %super::radio_address(&target.addr),
                        попыток = busy_tries,
                        "эфир: связь всё «устанавливается» — похоже, адреса больше нет"
                    );
                    return Err(refused("канал L2CAP", error));
                }
                tracing::info!(
                    адрес = %super::radio_address(&target.addr),
                    осталось_мс = left.as_millis(),
                    попытка = busy_tries,
                    "эфир: связь уже устанавливается — ждём и пробуем снова"
                );
                tokio::time::sleep(BUSY_PAUSE).await;
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    адрес = %super::radio_address(&target.addr),
                    случайный = target.random,
                    psm = target.psm,
                    // Отладочным видом, а не показом: у `io::Error`
                    // он печатает и код, и вид, и текст системы
                    // («Connection refused», «No route to host»), —
                    // то есть ровно то, по чему эти беды и различаются.
                    ?error,
                    "эфир: канал не открылся"
                );
                return Err(refused("канал L2CAP", error));
            }
            Err(_) => {
                // Висящая попытка кончает набор целиком, а не уступает
                // место следующей: следующая упрётся в тот же мёртвый
                // адрес и отнимет у §5.4 ещё три секунды. Быстрый отказ
                // здесь дороже упорства — ждать нам всё равно придётся
                // того, что собеседник наберёт нас сам.
                tracing::warn!(
                    адрес = %super::radio_address(&target.addr),
                    psm = target.psm,
                    случайный = target.random,
                    попытка_мс = attempt.as_millis(),
                    "эфир: набор повис — похоже, по этому адресу никого нет"
                );
                return Err(TransportError::Timeout);
            }
        }
    };

    // Набор занял сколько-то из бюджета; остаток — ожиданию. Общий срок
    // на «дозвониться» от этого не растёт: §5.4 отмерил его целиком,
    // и делить его между двумя половинами набора — дело этой функции,
    // а не лестницы.
    let dialed = started.elapsed();
    let left = budget.saturating_sub(dialed);
    match settle(&stream, left).await {
        Ok(waited) => {
            tracing::info!(
                адрес = %super::radio_address(&target.addr),
                psm = target.psm,
                набрали_мс = dialed.as_millis(),
                устоялся_мс = waited.as_millis(),
                "эфир: канал открыт"
            );
            // **Набранный канал тоже читается.** Здесь стояло «читать
            // незачем: ответы приедут встречным» — и это перестало быть
            // правдой в тот день, когда принятый канал стал двусторонним.
            // У одного канала L2CAP две стороны, и если одна в него
            // отвечает, другая обязана слушать; иначе ответ уходит
            // в тишину, а собеседник повторяет рукопожатие до бесконечности.
            //
            // Номера у этой половины нет: **мы сами набрали**, то есть
            // знаем собеседника без всякого имени. Номер нужен только
            // принятому каналу — его чей, решает ядро.
            let (reader, writer) = split_chunked(stream);
            match events {
                Some(events) => spawn_read_loop(reader, Transport::Bt, None, events),
                // **Канал без чтения — это звено в одну сторону, и молчать
                // о нём нельзя.** Писать в него будут как в исправный:
                // кадры уезжают, ответы собеседника уходят в брошенный
                // конец, а снаружи это выглядит как «у меня отправляется,
                // а обратно нет» — тот самый вид поломки, который в этом
                // дереве стоил недели.
                //
                // Случай редкий — ручку событий уносит гашение ступени
                // (`lower`), то есть нужна гонка с ним, — и редкостью
                // своей он и опасен: разбирать его стали бы по журналу,
                // а в журнале до этой строки не было ничего.
                //
                // Проверкой это не покрыто и покрыто быть не может:
                // ветка живёт только в настоящем радио.
                None => tracing::error!(
                    адрес = %super::radio_address(&target.addr),
                    "эфир: канал набран, а читать его некому — ответы собеседника пропадут"
                ),
            }
            Ok(writer)
        }
        Err(error) => {
            // Второй вопрос разбора: что было с устройством, пока канал
            // «открывался, но не работал». Если и здесь «соединены=true»,
            // то мы всё это время сидели на встречной связи и ждали
            // от неё того, чего она дать не может.
            let connected = peer_connected(&adapter, target.addr).await;
            tracing::warn!(
                адрес = %super::radio_address(&target.addr),
                psm = target.psm,
                набрали_мс = dialed.as_millis(),
                ждали_мс = left.as_millis(),
                соединены = ?connected,
                "эфир: канал открылся, но так и не заработал"
            );
            Err(error)
        }
    }
}

/// Соединены ли мы с этим устройством прямо сейчас — как считает система.
///
/// `None` означает «спросить не удалось», и это **не** то же самое, что
/// «нет»: адаптера может не быть вовсе (ступень гасят), устройство может
/// быть системе незнакомо. Три состояния вместо двух нужны именно здесь —
/// разбор, в котором «не знаю» выглядит как «нет», заводит не туда.
async fn peer_connected(slot: &AdapterSlot, addr: [u8; 6]) -> Option<bool> {
    // Замок берётся и отпускается **до** ожидания: держать `std::Mutex`
    // через `await` нельзя.
    let adapter = {
        let held = slot.lock().ok()?;
        held.clone()?
    };
    adapter.device(Address::new(addr)).ok()?.is_connected().await.ok()
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use tokio::io::AsyncWriteExt as _;

    use super::*;

    /// Перо, запоминающее **каждую** запись по отдельности.
    ///
    /// Ради этого и заведено: на L2CAP размер записи и есть размер
    /// пакета, а весь разбор упёрся именно в него. Сложить байты
    /// в один буфер значило бы стереть то единственное, что проверяется.
    #[derive(Clone, Default)]
    struct EachWrite(Arc<Mutex<Vec<Vec<u8>>>>);

    impl tokio::io::AsyncWrite for EachWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().expect("замок").push(buf.to_vec());
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_frame_leaves_the_air_in_packets_no_bigger_than_the_safe_one() {
        // **Замер с устройства, а не осторожность.** Пакет в 4097 байт
        // доезжал до PinePhone один раз из четырёх, пакеты до 672 —
        // все. Сокет при этом обещал 4097 с обеих сторон: договорный
        // предел бывает ложью.
        //
        // Число здесь повторено руками. Возьми проверка
        // `AIR_SAFE_PACKET` — поднятие потолка подняло бы и её, и она
        // смолчала бы о том, что пакеты снова стали непроходимыми.
        let seen = EachWrite::default();
        let mut pen =
            Chunked { inner: seen.clone(), limit: Chunked::<EachWrite>::limit_from(None) };

        let frame = vec![9u8; ratatosk_wire::SizeClass::S.frame_len()];
        pen.write_all(&[7u8]).await.expect("байт класса");
        pen.write_all(&frame).await.expect("кадр");

        let writes = seen.0.lock().expect("замок").clone();
        assert!(
            writes.iter().all(|packet| packet.len() <= 672),
            "пакетов больше 672 байт быть не должно: {:?}",
            writes.iter().map(Vec::len).collect::<Vec<_>>()
        );
        // И ни байта не потеряно: кадр собирается из пакетов целиком.
        let together: Vec<u8> = writes.concat();
        let mut whole = vec![7u8];
        whole.extend_from_slice(&frame);
        assert_eq!(together, whole, "кадр обязан доехать побайтно тем же");
    }

    #[test]
    fn the_packet_limit_listens_to_the_peer_when_the_peer_asks_for_less() {
        // Три случая, и все три настоящие: стандарт разрешает собеседнику
        // назвать и 23 байта (LE), стек может пообещать больше
        // безопасного — и может не ответить вовсе.
        assert_eq!(Chunked::<EachWrite>::limit_from(Some(23)), 23, "меньше нашего — слушаем его");
        assert_eq!(
            Chunked::<EachWrite>::limit_from(Some(4097)),
            672,
            "больше безопасного — режем по безопасному: 4097 доезжал раз из четырёх"
        );
        assert_eq!(Chunked::<EachWrite>::limit_from(None), 672, "не спросилось — берём безопасное");
        assert_eq!(Chunked::<EachWrite>::limit_from(Some(0)), 672, "ноль — это не ответ");
    }

    #[test]
    fn the_advert_names_an_interval_fast_enough_for_our_own_dial_budget() {
        // **Проверка обещания, а не настройки.** Интервал объявления
        // не задавался вовсе, и с умолчанием BlueZ открытие канала шло
        // секунды — до десяти и дольше к PinePhone, при пределе попытки
        // в восемь секунд. Снаружи это выглядело как «эфир работает
        // в одну сторону».
        //
        // Числа здесь повторены руками, а не взяты из крейта: возьми
        // проверка `ADVERT_INTERVAL` и `DIAL_PUBLIC` сама, и поднятие
        // интервала до секунды подняло бы заодно и проверку — та
        // смолчала бы о том, что набор снова перестал укладываться
        // в срок.
        let advert = announcement(&[0u8; 20], true);
        let min = advert.min_interval.expect("интервал обязан быть назван, а не унаследован");
        let max = advert.max_interval.expect("и верхняя граница тоже");
        assert!(
            min <= Duration::from_millis(250) && max <= Duration::from_millis(250),
            "четверть секунды — то же, что платит Android (`ADVERTISE_MODE_BALANCED`); \
             медленнее — и набор перестанет укладываться в срок, {min:?}..{max:?}"
        );
        assert!(min <= max, "BlueZ отвергает объявление, у которого нижняя граница выше верхней");
        // И то, без чего объявление бесполезно: по широковещательному
        // к нам не подойдёт никто.
        assert!(matches!(advert.advertisement_type, AdvType::Peripheral));
        assert!(advert.local_name.is_none(), "имя телефона в эфир не вещаем (0.4.3)");

        // **Вторая форма — та, которой объявляются, когда интервал
        // не приняли.** Она обязана остаться законным объявлением:
        // контроллеры старше BT 5.0 интервала не принимают вовсе, и без
        // этой формы ступень у них не поднимается ни разу. Проверено
        // на устройстве: PinePhone отвечал «Failed to register
        // advertisement», и эфира не было вовсе.
        let plain = announcement(&[0u8; 20], false);
        assert!(plain.min_interval.is_none() && plain.max_interval.is_none());
        assert!(matches!(plain.advertisement_type, AdvType::Peripheral), "подойти всё равно надо");
        assert!(plain.local_name.is_none(), "имя телефона в эфир не вещаем и здесь");
        assert_eq!(
            plain.manufacturer_data, advert.manufacturer_data,
            "отступление меняет только интервал: нагрузка маяка (§5.1) та же"
        );

        // Чего проверка не стережёт: того, что контроллер интервал
        // примет, и того, что отступление случится. И то и другое видно
        // только на радио — здесь проверено лишь, что обе формы законны.
    }
}
