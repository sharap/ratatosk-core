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
use bluer::l2cap::{SocketAddr as L2capAddr, Stream, StreamListener};
use bluer::{Adapter, AdapterEvent, Address, AddressType, DiscoveryFilter, DiscoveryTransport};
use futures::StreamExt;
use ratatosk_crypto::identity::beacon;
use ratatosk_proto::bluetooth as advert;
use ratatosk_proto::transport_policy::{Transport, BT_CONNECT_TIMEOUT_MS};
use tokio::io::WriteHalf;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{note_advert, unix_seconds, Air, AirSetup, BtAddress, DialFuture};
use crate::link::spawn_read_loop;
use crate::runner::{TransportError, TransportEvent};

/// Через сколько пробовать сканирование заново, если оно кончилось.
///
/// Кончиться оно может не по нашей вине: `bluetoothd` перезапустили,
/// адаптер моргнул. Выйти из цикла значило бы перестать находить
/// кого-либо до перезапуска приложения — и молча.
const RESCAN_PAUSE: Duration = Duration::from_secs(2);

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

/// Сколько ждать одну попытку набора, прежде чем считать адрес мёртвым.
///
/// Три секунды. Довод измеренный, а не выбранный: удавшиеся наборы
/// на стенде занимали 60, 338 и 438 миллисекунд — запас семикратный.
///
/// Нужен этот предел из-за телефона. Android **объявляется одним
/// приватным адресом, а подключается другим** (замечено на стенде:
/// объявление с `67:0C:…`, входящий канал с `72:A6:…`), и набор
/// по объявленному не удаётся никогда. Без предела каждое первое
/// сообщение стоило бы полного срока §5.4 — десяти секунд ожидания
/// там, где ответ известен заранее.
const ATTEMPT_LIMIT: Duration = Duration::from_secs(3);

/// Как часто спрашивать канал, готов ли он на самом деле.
///
/// Двадцать пять миллисекунд — заметно меньше интервала соединения
/// BLE (десятки миллисекунд), то есть мы не проспим готовность
/// и не устроим при этом опрос вхолостую.
const SETTLE_POLL: Duration = Duration::from_millis(25);

/// Запас к границе слота при переобъявлении.
///
/// Объявление меняется вместе с записью маяка, и менять его надо
/// **после** того, как слот сменился у нас, а не до: соседний слот
/// собеседник примет (§5.1 проверяет −1, 0, +1), а вот запись
/// из будущего при расхождении часов — не обязательно.
const SLOT_MARGIN: Duration = Duration::from_secs(2);

/// Эфир этой машины: `bluer`, сокеты L2CAP, свои задачи.
///
/// Реализация [`Air`] для Linux. Вся её жизнь — в поле: эфир есть,
/// пока есть [`Radio`], и гаснет он не вызовом, а `drop`.
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
    type Stream = WriteHalf<Stream>;

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
        setup: AirSetup<WriteHalf<Stream>>,
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
    setup: AirSetup<WriteHalf<Stream>>,
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
    let psm = listener.as_ref().local_addr().map_err(|e| refused("номер канала", e))?.psm;
    tracing::info!(psm, адрес = %own, тип = ?own_type, "эфир: канал L2CAP занят");

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
    loop {
        let now = unix_seconds();
        let slot = beacon::slot(now);
        let record = beacon::record(&my_ik, slot, fresh_nonce());
        let payload =
            advert::payload(&record, psm).map_err(|e| refused("нагрузка объявления", e))?;

        let mut manufacturer_data = BTreeMap::new();
        manufacturer_data.insert(advert::COMPANY_ID, payload.to_vec());
        let announcement = Advertisement {
            // **Именно `Peripheral`.** По умолчанию тип
            // `Broadcast`, а широковещательное объявление
            // не подключаемо: видно нас было бы, а подойти нельзя.
            advertisement_type: AdvType::Peripheral,
            manufacturer_data,
            discoverable: Some(true),
            // Имя устройства не объявляется никогда: оно и бюджет
            // объявления рвёт (0.4.3), и вещает в эфир имя телефона.
            local_name: None,
            ..Default::default()
        };

        let handle = adapter.advertise(announcement).await.map_err(|e| refused("объявление", e))?;

        if !announced {
            announced = true;
            // Готовность объявляется **после** того, как объявление
            // ушло в эфир, а не после занятия сокета: до этого
            // мгновения нас не найдёт никто, и §5.4, выбрав ступень,
            // сжёг бы попытку.
            let _ = events.send(TransportEvent::Ready { transport: Transport::Bt }).await;
            tracing::info!(slot, "эфир: объявились");
        }

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
    accepted: mpsc::Sender<(u64, WriteHalf<Stream>)>,
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
                    let (reader, writer) = tokio::io::split(stream);
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
    setup: AirSetup<WriteHalf<Stream>>,
    airtime: Arc<Airtime>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Пока идёт набор, обзора нет вовсе: антенна одна. Ждём
            // здесь, а не внутри захода, — так заход всегда начинается
            // со свободным радио.
            airtime.wait_until_free().await;
            match scan(&adapter, &setup, &airtime).await {
                // Уступили набору: возвращаемся немедленно, как только
                // он кончится. Пауза здесь была бы потерянными секундами
                // ровно там, где человек ждёт ответа.
                Ok(Yielded::ToDial) => continue,
                Ok(Yielded::StreamEnded) => {}
                Err(error) => tracing::debug!(%error, "эфир: сканирование прервалось"),
            }
            // Сканирование могло кончиться не по нашей вине —
            // `bluetoothd` перезапустили, адаптер моргнул. Пробуем
            // снова: молча перестать находить кого-либо хуже.
            tokio::time::sleep(RESCAN_PAUSE).await;
        }
    })
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
    setup: &AirSetup<WriteHalf<Stream>>,
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
) -> Result<WriteHalf<Stream>, TransportError> {
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
        // Каждой попытке — свой предел, а не весь остаток бюджета.
        // Довод измеренный: удавшиеся наборы занимали 60, 338 и 438 мс,
        // то есть три секунды — семикратный запас. Висящий дольше `connect`
        // не «медленный», он мёртвый: адрес, по которому нас ждут, у BLE
        // отвечает сразу или не отвечает вовсе.
        match tokio::time::timeout(left.min(ATTEMPT_LIMIT), Stream::connect(sa)).await {
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
                    попытка_мс = ATTEMPT_LIMIT.as_millis(),
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
            let (reader, writer) = tokio::io::split(stream);
            if let Some(events) = events {
                spawn_read_loop(reader, Transport::Bt, None, events);
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
