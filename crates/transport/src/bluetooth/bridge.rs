//! Эфир за границей §13.3: радио держит платформа (Android, 0.4).
//!
//! На Linux ступень работает своим радио ([`super::local`]): `bluer` даёт
//! и объявление, и обзор, и сокеты L2CAP. На Android ничего этого в Rust
//! нет и быть не может — объявляет `BluetoothLeAdvertiser`, сканирует
//! `BluetoothLeScanner`, а канал открывает `BluetoothSocket`, и все трое
//! живут в Java.
//!
//! Этот модуль — половина моста со стороны Rust. Вторая половина, класс
//! на Kotlin, реализует [`BtRadio`]; между ними UniFFI, и через границу
//! ходят **только байты и числа**.
//!
//! # Что осталось по эту сторону
//!
//! Всё, что не требует радио, и это не мелочь:
//!
//! * **формат объявления** — собирается здесь ([`ratatosk_proto::bluetooth`]),
//!   платформе отдаётся готовая нагрузка. Иначе формат существовал бы
//!   в двух видах: в Rust для десктопа и в Kotlin для телефона, — и
//!   разошлись бы они на первой же правке;
//! * **ротация** объявления по слотам §5.1 — здесь же, по тем же часам;
//! * **опознание** контакта маяком ([`super::note_advert`]) — здесь, потому
//!   что это протокольное правило, а не дело радио. Платформа сообщает
//!   «слышал такие байты с такого адреса» и не знает, чьи они;
//! * **кадрирование** (`crate::link`) и выбор канала по классу кадра.
//!
//! Платформе остаётся ровно то, чего Rust не умеет: вещать, слушать
//! и переносить байты.
//!
//! # Почему методы платформы ничего не возвращают
//!
//! Потому что все они долгие. `connect` у `BluetoothSocket` блокирует поток
//! на секунды, запись в `OutputStream` — на время передачи. Вызов через
//! UniFFI синхронный, и «вернуть результат» означало бы держать поток
//! ядра всё это время.
//!
//! Поэтому договор такой: **сказали — делай, об исходе сообщи событием**.
//! Rust называет каналу номер заранее и ждёт `opened`/`open_failed`;
//! запись Kotlin ставит в свою очередь; закрытие приезжает `closed`.
//! Ровно то же правило, по которому живёт `Runner::execute` (см. его
//! заголовок), только по другую сторону границы.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ratatosk_crypto::identity::beacon;
use ratatosk_proto::bluetooth as advert;
use ratatosk_proto::transport_policy::{Transport, BT_CONNECT_TIMEOUT_MS};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use super::{note_advert, short, short_record, unix_seconds, Air, AirSetup, BtAddress, DialFuture};
use crate::link::{fnv_update, spawn_read_loop, FNV_OFFSET};
use crate::runner::{TransportError, TransportEvent};

/// Сколько кусков, пришедших от платформы, ждут разбора.
///
/// Куски приходят по мере чтения сокета, то есть килобайтами; сотня — это
/// запас на время, пока сборщик кадров занят предыдущим.
const INCOMING_QUEUE: usize = 128;

/// Сколько ждать места в очереди разбора, прежде чем счесть разбор мёртвым.
///
/// # Разбор третьей поломки того же узла
///
/// Замер `/probe m` валился на тридцатом кадре, и валился одинаково:
/// у отправителя запись падала с `NotConnected`. Закрывал канал **сам
/// приёмник**, вот здесь, — очередь разбора переполнялась, и переполнение
/// считалось доказательством того, что разбор мёртв.
///
/// Доказательством оно не было. Считаем: очередь — сто двадцать восемь
/// кусков по восемь килобайт, то есть около мебибайта. Замер `s` на сотне
/// кадров — это четыреста килобайт, они в запас влезают целиком, и потому
/// проходил. Замер `m` на тридцати — почти два мебибайта, и он в запас
/// не влезает никак. Порог был не в кадрах и не в классе, а в **байтах,
/// которые ядро не успело разобрать**.
///
/// А отставать ядру положено: кадр класса M — это шестьдесят четыре
/// килобайта, которые надо расшифровать, сложить и показать. Пока оно
/// занято одним, радио приносит следующий. Это не поломка, это нормальная
/// разница скоростей — и на неё есть управление потоком L2CAP, придуманное
/// ровно для этого.
///
/// Мы его обходили. Платформа читала сокет всегда, что бы ни творилось
/// ниже, — а раз читала, то и возвращала кредиты, и отправителю никто
/// не говорил «погоди». Единственным способом сказать это оставался обрыв.
///
/// Правильный способ — **не читать**. Очередь полна значит платформенный
/// поток чтения стоит; сокет не вычитывается; кредиты не возвращаются;
/// `write_all` у отправителя ждёт. Никто ничего не теряет, передача просто
/// идёт со скоростью самого медленного участка — как и должна.
///
/// Срок нужен на случай, когда разбор действительно мёртв: ждать вечно
/// значило бы держать канал, из которого никогда ничего не выйдет.
/// Полминуты — это заведомо больше любой честной задержки (самый долгий
/// кадр в эфире идёт секунды) и заведомо меньше того, что человек готов
/// счесть работой.
const ROOM_LIMIT: Duration = Duration::from_secs(30);

/// Насколько часто спрашивать про место в очереди.
///
/// Две миллисекунды: на полосе эфира за это время не приезжает и десятка
/// байт, так что опоздание неощутимо, а холостых пробуждений за полминуты
/// набирается пятнадцать тысяч — для потока, который всё равно стоит,
/// это ничто.
///
/// Опросом, а не ожиданием на канале: [`mpsc::Sender::blocking_send`]
/// требует, чтобы поток не принадлежал рантайму, а звать нас могут
/// откуда угодно — граница §13.3 про потоки не договаривается.
const ROOM_POLL: Duration = Duration::from_millis(2);

/// Через сколько принятых байт говорить об этом в журнале.
///
/// Шестьдесят четыре кибибайта: на кадр класса L строк выходит
/// шестнадцать, на разговор из мелких кадров — ни одной.
const COUNT_STEP: u64 = 64 * 1024;

/// Счёт принятого по одному каналу.
///
/// Байты и **куски** вместе: размер куска — это то, чем платформа режет
/// поток, и он же главный подозреваемый, когда кадр доезжает нужной длины,
/// а содержимым не сходится.
struct Counted {
    /// Всего байт.
    bytes: u64,
    /// Всего кусков.
    chunks: u64,
    /// Номер последней названной в журнале ступеньки.
    said: u64,
    /// Отпечаток всего потока, пришедшего каналом.
    ///
    /// **Последняя развилка разбора.** Кадр доезжает нужной длины,
    /// кадрирование не сбивается, а тег не сходится — значит байты
    /// заменяются на месте. Заменить их может либо провод (платформа
    /// прочитала не то), либо дорога от платформы к ядру (копия, очередь,
    /// граница FFI). Ту же цифру считает у себя платформа: сошлись —
    /// виноват провод, разошлись — дорога.
    rolling: u64,
}

impl Default for Counted {
    fn default() -> Counted {
        Counted { bytes: 0, chunks: 0, said: 0, rolling: FNV_OFFSET }
    }
}

/// Радио, которого у нас нет: его держит платформа.
///
/// Реализуется на Kotlin; через UniFFI ходят только байты и числа.
/// Ни один метод не ждёт исхода — см. заголовок модуля.
pub trait BtRadio: Send + Sync + 'static {
    /// Поднять слушающий сокет L2CAP и начать сканировать эфир.
    ///
    /// Номер занятого канала приезжает событием `on_ready`, беда —
    /// `on_lost`. Отдельным вызовом, а не частью [`BtRadio::advertise`],
    /// потому что объявлять **нечего**, пока номера нет: он едет
    /// в объявлении (0.4.3). Сначала сокет, потом номер, потом
    /// объявление — тот же порядок, что и у местного радио.
    fn start(&self);

    /// Объявлять вот эту нагрузку (18 байт) до следующего вызова.
    ///
    /// Зовётся и при подъёме, и на каждой смене слота §5.1. Платформа
    /// обязана заменить прежнее объявление, а не добавить второе: два
    /// объявления одного радио — это подсказка тому, кто их сличает.
    fn advertise(&self, payload: Vec<u8>);

    /// Перестать объявляться и сканировать, закрыть все каналы.
    fn stop(&self);

    /// Открыть канал к устройству. Исход — событием `opened`/`open_failed`.
    ///
    /// Номер канала даёт **Rust**: платформе остаётся его запомнить.
    /// Иначе номера пришлось бы согласовывать в обе стороны, а это лишний
    /// повод им разойтись.
    fn open(&self, channel: u64, addr: Vec<u8>, random: bool, psm: u16);

    /// Записать байты в открытый канал.
    ///
    /// Платформа ставит их в свою очередь и пишет из своего потока: запись
    /// в `OutputStream` блокирует, а этот вызов — нет.
    fn write(&self, channel: u64, bytes: Vec<u8>);

    /// Закрыть канал.
    fn close(&self, channel: u64);
}

/// Эфир через мост.
///
/// Клонируется дёшево: всё состояние под `Arc`, и клиенту (FFI) нужна
/// та же ручка, что и раннеру, — он через неё приносит события снизу.
#[derive(Clone, Default)]
pub struct BridgedAir {
    inner: Arc<Bridge>,
}

impl BridgedAir {
    /// Заводит мост. Радио при этом ещё нет: его приносит клиент.
    #[must_use]
    pub fn new() -> BridgedAir {
        BridgedAir::default()
    }

    /// Вручает мосту радио платформы.
    ///
    /// До этого вызова ступень не поднимается **никак**: подниматься нечем,
    /// и молчаливое согласие здесь было бы обманом — §5.4 считал бы
    /// ступень живой и жёг бы на ней попытки.
    pub fn set_radio(&self, radio: Arc<dyn BtRadio>) {
        if let Ok(mut held) = self.inner.radio.lock() {
            *held = Some(radio);
        }
    }

    /// Есть ли радио у моста.
    #[must_use]
    pub fn has_radio(&self) -> bool {
        self.inner.radio.lock().is_ok_and(|held| held.is_some())
    }

    /// Платформа подняла сокет и готова объявляться.
    ///
    /// Номер PSM приходит отсюда и только отсюда: его выдаёт система тому,
    /// кто открыл серверный сокет, — то есть платформе.
    pub fn on_ready(&self, psm: u16) {
        self.inner.on_ready(psm);
    }

    /// Эфир не поднялся или отвалился, и вот почему.
    pub fn on_lost(&self, reason: &str) {
        self.inner.on_lost(reason);
    }

    /// Платформа услышала объявление под нашим кодом производителя.
    pub fn on_heard(&self, payload: &[u8], addr: [u8; 6], random: bool) {
        self.inner.on_heard(payload, addr, random);
    }

    /// Канал, который мы просили открыть, открылся.
    pub fn on_opened(&self, channel: u64) {
        self.inner.settle_dial(channel, Ok(()));
    }

    /// Канал открыть не удалось.
    pub fn on_open_failed(&self, channel: u64, reason: &str) {
        self.inner.settle_dial(channel, Err(reason.to_owned()));
    }

    /// К нам подключились.
    ///
    /// Такой канал читается — и, с этой поставки, **в него же отвечают**:
    /// набрать телефон по объявленному адресу нельзя, а открытый им канал
    /// двусторонний. Чей он, платформа по-прежнему не знает; имя каналу
    /// называет ядро.
    pub fn on_incoming(&self, channel: u64) {
        self.inner.on_incoming(channel);
    }

    /// Из канала пришли байты.
    pub fn on_bytes(&self, channel: u64, data: Vec<u8>) {
        self.inner.on_bytes(channel, data);
    }

    /// Канал закрылся — с той стороны или по ошибке записи.
    pub fn on_closed(&self, channel: u64) {
        self.inner.on_closed(channel);
    }
}

impl Air for BridgedAir {
    type Stream = Outgoing;

    fn raise(&mut self, setup: AirSetup<Self::Stream>) {
        self.inner.raise(setup);
    }

    fn lower(&mut self) {
        self.inner.lower();
    }

    fn dial(&self, target: BtAddress) -> DialFuture<Self::Stream> {
        let bridge = Arc::clone(&self.inner);
        Box::pin(async move { bridge.dial(target).await })
    }
}

/// Состояние моста. Одно на ступень, живёт под `Arc`.
#[derive(Default)]
struct Bridge {
    radio: Mutex<Option<Arc<dyn BtRadio>>>,
    /// Чем ступень поднята сейчас. `None` — выключена.
    setup: Mutex<Option<AirSetup<Outgoing>>>,
    /// Рантайм ядра — чтобы было куда заводить задачи с чужого потока.
    ///
    /// # Зачем он здесь, и почему без него всё рушится
    ///
    /// Мост зовут **с потоков платформы**: обзор BLE отвечает со своего
    /// потока Java, чтение сокета — со своего. Контекста tokio у них нет
    /// и быть не может, а `tokio::spawn` без контекста — не ошибка,
    /// а **паника**; паника через границу FFI кончается остановкой
    /// приложения.
    ///
    /// Ручка снимается в [`Bridge::raise`] — единственном месте, куда
    /// заведомо приходят изнутри рантайма (команду `SetEnabled` исполняет
    /// драйвер). Дальше задачи заводятся на неё явно, а не «туда, где
    /// мы сейчас».
    runtime: Mutex<Option<tokio::runtime::Handle>>,
    /// Задача ротации объявления. Уходит вместе с выключением.
    rotation: Mutex<Option<JoinHandle<()>>>,
    /// Номер для следующего канала.
    next_channel: AtomicU64,
    /// Кто ждёт, что его канал откроется.
    dialing: Mutex<HashMap<u64, oneshot::Sender<Result<(), String>>>>,
    /// Куда класть байты, пришедшие в канал.
    incoming: Mutex<HashMap<u64, mpsc::Sender<Vec<u8>>>>,
    /// Сколько байт и кусков пришло каналом и о скольких уже сказано.
    counted: Mutex<HashMap<u64, Counted>>,
    /// Жив ли набранный нами канал — по флажку на канал.
    ///
    /// Держится он не ради уборки, а ради **обрыва**. Когда платформа
    /// говорит `closed` о канале, который набрали мы, узнать об этом
    /// должна связь (`link`) — иначе она будет писать в закрытый канал
    /// и считать, что пишет, а §5.4 будет ждать квитанцию до полного
    /// срока. Флажок гасится, и ближайшая запись честно падает.
    alive: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

impl Bridge {
    fn radio(&self) -> Option<Arc<dyn BtRadio>> {
        self.radio.lock().ok()?.clone()
    }

    /// Исполняет `what` в контексте рантайма ядра.
    ///
    /// Нужно каждому вызову **с потока платформы**, внутри которого может
    /// завестись задача или таймер. Прямой `tokio::spawn` там паникует,
    /// и паника уходит через границу FFI — то есть роняет приложение,
    /// а не ступень.
    ///
    /// Возвращает `None`, если ступень не поднята: значит и делать нечего.
    fn in_runtime<T>(&self, what: impl FnOnce() -> T) -> Option<T> {
        let handle = self.runtime.lock().ok()?.clone()?;
        let _inside = handle.enter();
        Some(what())
    }

    fn raise(&self, setup: AirSetup<Outgoing>) {
        let events = setup.events.clone();
        if let Ok(mut held) = self.setup.lock() {
            *held = Some(setup);
        }
        // Ручка рантайма снимается здесь и только здесь: сюда приходят
        // изнутри цикла драйвера, а дальше мост живёт на чужих потоках.
        // Отсутствие ручки — не мелочь: без неё первая же задача с потока
        // платформы уронила бы приложение паникой.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                if let Ok(mut held) = self.runtime.lock() {
                    *held = Some(handle);
                }
            }
            Err(_) => {
                tracing::warn!("эфир: ступень поднимают вне рантайма — заводить задачи некуда");
                let _ = events.try_send(TransportEvent::Lost { transport: Transport::Bt });
                return;
            }
        }
        let Some(radio) = self.radio() else {
            // Честный отказ вместо молчания: ступень включена человеком,
            // а поднимать её нечем — платформа радио не вручила. Молча
            // это выглядело бы как «включено и не работает», то есть как
            // поломка без причины.
            tracing::warn!("эфир: радио платформы не вручено — ступень не поднимется");
            let _ = events.try_send(TransportEvent::Lost { transport: Transport::Bt });
            return;
        };
        // Объявиться нечем, пока платформа не сказала свой PSM: номер
        // канала едет в объявлении (0.4.3). Поэтому здесь только «подними
        // сокет», а объявление — в `on_ready`.
        radio.start();
        tracing::info!("эфир: радио поднимается, ждём номер канала от платформы");
    }

    fn lower(&self) {
        if let Ok(mut held) = self.setup.lock() {
            *held = None;
        }
        // Ручка рантайма уходит вместе со ступенью: «не поднята» обязано
        // быть одним состоянием, а не двумя похожими. Отмене задач она
        // не нужна — `abort` контекста не требует.
        if let Ok(mut held) = self.runtime.lock() {
            *held = None;
        }
        if let Ok(mut held) = self.rotation.lock() {
            if let Some(task) = held.take() {
                task.abort();
            }
        }
        if let Some(radio) = self.radio() {
            radio.stop();
        }
        // Каналы закрывает платформа по `stop`, но помнить о них больше
        // незачем: после включения они будут другими.
        if let Ok(mut held) = self.incoming.lock() {
            held.clear();
        }
        if let Ok(mut held) = self.dialing.lock() {
            held.clear();
        }
        if let Ok(mut held) = self.alive.lock() {
            for (_, alive) in held.drain() {
                alive.store(false, Ordering::Relaxed);
            }
        }
    }

    /// Собирает объявление для текущего слота и отдаёт его платформе.
    fn announce(&self, psm: u16) -> bool {
        let Some(radio) = self.radio() else { return false };
        let Ok(held) = self.setup.lock() else { return false };
        let Some(setup) = held.as_ref() else { return false };

        let slot = beacon::slot(unix_seconds());
        let record = beacon::record(&setup.my_ik, slot, fresh_nonce());
        match advert::payload(&record, psm) {
            Ok(payload) => {
                radio.advertise(payload.to_vec());
                // Ключ и начало записи маяка — затем же, зачем у местного
                // радио: чтобы журнал телефона сличался с журналом машины
                // напрямую, а не через догадку о том, что он вещал.
                tracing::info!(
                    slot,
                    psm,
                    ключ = %short(&setup.my_ik),
                    маяк = %short_record(&record),
                    "эфир: объявились через мост"
                );
                true
            }
            Err(error) => {
                // Номер вне динамического диапазона LE. Это ошибка
                // платформы, и молчать о ней нельзя: объявление с таким
                // номером позвало бы собеседника в никуда.
                tracing::warn!(%error, psm, "эфир: платформа дала негодный номер канала");
                false
            }
        }
    }

    fn on_ready(self: &Arc<Self>, psm: u16) {
        if !self.announce(psm) {
            self.on_lost("объявление не собралось");
            return;
        }
        let events = match self.setup.lock() {
            Ok(held) => held.as_ref().map(|setup| setup.events.clone()),
            Err(_) => None,
        };
        if let Some(events) = events {
            let _ = events.try_send(TransportEvent::Ready { transport: Transport::Bt });
        }

        // Ротация объявления — по тем же часам, что у локальной сети:
        // объявление, не меняющееся со временем, есть долговременный
        // опознаватель устройства (§5.1).
        //
        // **Задача заводится на ручку рантайма, а не «здесь».** Сюда
        // приходят с потока платформы, у которого контекста tokio нет:
        // голый `tokio::spawn` тут паникует, и паника через границу FFI
        // роняет приложение.
        let bridge = Arc::clone(self);
        let Some(task) = self.in_runtime(|| tokio::spawn(rotate(bridge, psm))) else {
            self.on_lost("ступень не поднята — ротацию завести некуда");
            return;
        };
        if let Ok(mut held) = self.rotation.lock() {
            if let Some(old) = held.replace(task) {
                old.abort();
            }
        }
    }

    fn on_lost(&self, reason: &str) {
        tracing::warn!(reason, "эфир: платформа сообщила о беде");
        let events = match self.setup.lock() {
            Ok(held) => held.as_ref().map(|setup| setup.events.clone()),
            Err(_) => None,
        };
        if let Some(events) = events {
            let _ = events.try_send(TransportEvent::Lost { transport: Transport::Bt });
        }
    }

    fn on_heard(&self, payload: &[u8], addr: [u8; 6], random: bool) {
        let Ok(held) = self.setup.lock() else { return };
        let Some(setup) = held.as_ref() else { return };
        for peer_ik in note_advert(setup, payload, addr, random) {
            // Как и у местного радио: событие на **каждое** объявление,
            // переход считает ядро.
            let _ = setup.events.try_send(TransportEvent::SeenOnBt { peer_ik });
        }
    }

    fn settle_dial(&self, channel: u64, outcome: Result<(), String>) {
        let waiting = self.dialing.lock().ok().and_then(|mut held| held.remove(&channel));
        if let Some(reply) = waiting {
            let _ = reply.send(outcome);
        }
    }

    fn on_incoming(self: &Arc<Self>, channel: u64) {
        let events = match self.setup.lock() {
            Ok(held) => held.as_ref().map(|setup| setup.events.clone()),
            Err(_) => None,
        };
        let Some(events) = events else {
            // Ступень выключена, а канал пришёл: закрываем, не читая.
            if let Some(radio) = self.radio() {
                radio.close(channel);
            }
            return;
        };
        let (tx, rx) = mpsc::channel(INCOMING_QUEUE);
        // Сборщик кадров — это задача, и заводится она **на ручку
        // рантайма**: сюда приходят с потока платформы, принявшего
        // соединение, а `tokio::spawn` без контекста паникует. Вторая
        // такая же точка — ротация объявления; обе они и есть весь
        // список мест, где мост трогает рантайм с чужого потока.
        let spawned = self.in_runtime(|| {
            // Кадры отсюда сразу едут сборщику, и вместе с ними — номер
            // канала: ответить в него можно, а набрать телефон в ответ
            // нельзя (см. `AirSetup::accepted`).
            spawn_read_loop(Incoming::new(rx), Transport::Bt, Some(channel), events);
        });
        if spawned.is_none() {
            // Ступень не поднята: читать этот канал некому и незачем.
            if let Some(radio) = self.radio() {
                radio.close(channel);
            }
            return;
        }
        if let Ok(mut held) = self.incoming.lock() {
            held.insert(channel, tx);
        }
        // Перо принятого канала — наверх. У моста это тот же `Outgoing`,
        // что и у набранного: номер один, а откуда он взялся — платформе
        // безразлично.
        let alive = Arc::new(AtomicBool::new(true));
        if let Ok(mut held) = self.alive.lock() {
            held.insert(channel, Arc::clone(&alive));
        }
        let writer = Outgoing { bridge: Arc::clone(self), channel, alive };
        let handed = match self.setup.lock() {
            Ok(held) => held.as_ref().map(|setup| setup.accepted.clone()),
            Err(_) => None,
        };
        if let Some(handed) = handed {
            // `try_send`, а не ожидание: сюда приходят с потока платформы,
            // и держать его нельзя ничем. Переполнение очереди означает,
            // что к нам ломятся быстрее, чем ядро разбирает, — и лишний
            // канал честнее не взять, чем запереть чужой поток.
            if handed.try_send((channel, writer)).is_err() {
                tracing::warn!(channel, "эфир: принятых каналов больше, чем разбирается");
            }
        }
        tracing::debug!(channel, "эфир: входящий канал через мост");
    }

    fn on_bytes(&self, channel: u64, data: Vec<u8>) {
        let sender = self.incoming.lock().ok().and_then(|held| held.get(&channel).cloned());
        let Some(sender) = sender else {
            // Канала мы не знаем. Закрывать его отсюда нельзя: под этим же
            // номером может жить **набранный нами** канал, у которого своя
            // задача и своя жизнь, — а байты в него приходить не должны
            // вовсе (соединения односторонние, см. заголовок ступени).
            // Значит либо канал уже закрыт, либо платформа читает то,
            // из чего читать не просили. И то и другое — строка в журнале.
            tracing::debug!(channel, "эфир: байты из канала, которого мы не ждём");
            return;
        };
        // **Счёт байт на канал, и он тут не для красоты.** Мебибайт идёт
        // сотнями кусков, и вопрос при разборе один: доехало ли его ровно
        // столько, сколько ушло. Недосчёт означает потерю в чтении
        // платформы, точное совпадение при негодном кадре — что куски
        // пришли не в том порядке. Различить это иначе нечем.
        //
        // Строка раз в 64 КиБ: на мебибайт их шестнадцать, на разговор
        // из мелких кадров — ни одной.
        let report = self.counted.lock().ok().and_then(|mut held| {
            let counted = held.entry(channel).or_default();
            counted.bytes = counted.bytes.saturating_add(data.len() as u64);
            counted.chunks = counted.chunks.saturating_add(1);
            counted.rolling = fnv_update(counted.rolling, &data);
            let step = counted.bytes / COUNT_STEP;
            let news = step != counted.said;
            counted.said = step;
            news.then_some((counted.bytes, counted.chunks, data.len(), counted.rolling))
        });
        if let Some((bytes, chunks, last, rolling)) = report {
            // **Куски, а не только байты.** Размер куска — это то, чем
            // платформа режет поток, и он же главный подозреваемый, когда
            // кадр доезжает нужной длины, а содержимым не сходится: буфер
            // чтения меньше пакета L2CAP теряет хвост пакета молча.
            // Средний размер куска, упёршийся ровно в размер буфера, —
            // это и есть та улика.
            tracing::debug!(
                channel,
                всего = bytes,
                кусков = chunks,
                последний = last,
                поток = %format!("{rolling:016x}"),
                "эфир: принято байт каналом"
            );
        }
        // **Ждём места, а не закрываем канал.** Здесь стоял `try_send`,
        // и переполнение очереди считалось доказательством того, что
        // разбор мёртв. Доказательством оно не было: ядро просто занято
        // предыдущим кадром, а платформа тем временем вычитывает сокет
        // и возвращает кредиты L2CAP — то есть отправителю никто
        // не говорит «погоди». Разбор целого разряда см. у [`ROOM_LIMIT`].
        //
        // Остановка здесь и есть то самое «погоди»: поток, принёсший
        // куски, стоит, сокет не вычитывается, кредиты не возвращаются,
        // запись у отправителя ждёт.
        if !send_waiting(&sender, data, ROOM_LIMIT) {
            // Полминуты без единого разобранного куска — это уже не
            // «занято», а «некому». Вот теперь закрывать честно.
            tracing::warn!(
                channel,
                ждали_с = ROOM_LIMIT.as_secs(),
                "эфир: разбор встал насовсем, канал закрывается"
            );
            self.on_closed(channel);
            if let Some(radio) = self.radio() {
                radio.close(channel);
            }
        }
    }

    fn on_closed(&self, channel: u64) {
        // Счёт уходит вместе с каналом: номера переиспользуются, и чужой
        // остаток превратил бы следующий разбор в загадку.
        if let Ok(mut held) = self.counted.lock() {
            held.remove(&channel);
        }
        if let Ok(mut held) = self.incoming.lock() {
            held.remove(&channel);
        }
        // Набор, ждущий этого канала, тоже надо закрыть: иначе он досидит
        // до срока и объявит «не уложились», хотя ответ уже есть.
        self.settle_dial(channel, Err("канал закрылся".to_owned()));
        // А если канал был набран и работал — погасить флажок. Связь
        // узнаёт об обрыве ближайшей записью: она вернёт ошибку вместо
        // тишины. Без этого §5.4 считал бы ступень годной и ждал бы
        // квитанцию до полного срока.
        let alive = self.alive.lock().ok().and_then(|mut held| held.remove(&channel));
        if let Some(alive) = alive {
            alive.store(false, Ordering::Relaxed);
        }
    }

    async fn dial(self: Arc<Self>, target: BtAddress) -> Result<Outgoing, TransportError> {
        let Some(radio) = self.radio() else {
            return Err(TransportError::Unavailable);
        };
        let channel = self.next_channel.fetch_add(1, Ordering::Relaxed);
        let (reply, answer) = oneshot::channel();
        if let Ok(mut held) = self.dialing.lock() {
            held.insert(channel, reply);
        }
        radio.open(channel, target.addr.to_vec(), target.random, target.psm);

        // Ждём платформу — но не дольше, чем §5.4 отвёл на набор.
        let settled =
            tokio::time::timeout(Duration::from_millis(BT_CONNECT_TIMEOUT_MS), answer).await;
        match settled {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(reason))) => {
                tracing::warn!(channel, reason, "эфир: канал не открылся");
                return Err(TransportError::Refused(reason));
            }
            // Отправитель ответа исчез — такого быть не должно, но
            // разбираться в этом на живом устройстве нечем: считаем
            // отказом.
            Ok(Err(_)) => return Err(TransportError::Unavailable),
            Err(_) => {
                self.settle_dial(channel, Err("срок вышел".to_owned()));
                radio.close(channel);
                tracing::warn!(channel, срок_мс = BT_CONNECT_TIMEOUT_MS, "эфир: набор не уложился");
                return Err(TransportError::Timeout);
            }
        }

        // Канал открыт — и читается тоже.
        //
        // Здесь стояло «нужен нам только на запись: ответы приедут
        // встречным каналом», и это перестало быть правдой в тот день,
        // когда принятый канал стал двусторонним. У одного канала L2CAP
        // две стороны: если собеседник отвечает в тот, который набрали мы,
        // слушать его обязаны мы. Без этого байты доходили до платформы,
        // платформа отдавала их `on_bytes`, а мост выбрасывал — канала
        // не было в списке читаемых. Снаружи это выглядело как
        // рукопожатие, повторяющееся без конца.
        let alive = Arc::new(AtomicBool::new(true));
        if let Ok(mut held) = self.alive.lock() {
            held.insert(channel, Arc::clone(&alive));
        }

        let events = match self.setup.lock() {
            Ok(held) => held.as_ref().map(|setup| setup.events.clone()),
            Err(_) => None,
        };
        if let Some(events) = events {
            let (tx, rx) = mpsc::channel(INCOMING_QUEUE);
            if let Ok(mut held) = self.incoming.lock() {
                held.insert(channel, tx);
            }
            // Номера у этой половины нет: **мы сами набрали**, то есть
            // знаем собеседника без всякого имени. Номер нужен только
            // принятому каналу — чей он, решает ядро.
            //
            // Заводить задачу здесь можно прямо: `dial` живёт внутри
            // задачи связи, а та — в рантайме ядра. Чужих потоков тут нет.
            spawn_read_loop(Incoming::new(rx), Transport::Bt, None, events);
        }
        Ok(Outgoing { bridge: self, channel, alive })
    }
}

/// Набранный канал как поток на запись.
///
/// # Почему здесь нет ни задачи, ни буфера
///
/// Потому что [`BtRadio::write`] по договору **не ждёт**: платформа кладёт
/// байты в свою очередь и пишет их своим потоком. Значит `poll_write`
/// может отдать их сразу и вернуть готовность — ни насоса, ни промежуточной
/// трубы между `link` и радио не нужно.
///
/// Первая редакция моста была устроена иначе: труба `simplex` и задача,
/// перекладывающая из неё в радио. Выглядело привычно, а стоило бы дорого —
/// обрыв канала не доходил бы до связи вовсе. Труба принимает запись, пока
/// в ней есть место, независимо от того, читает ли кто-то с другого конца;
/// `link` считал бы кадры записанными, §5.4 ждал бы квитанцию до полного
/// срока, и человек видел бы «отправляется» на мёртвом канале. Здесь же
/// обрыв — это флажок, и ближайшая запись честно падает.
///
/// # Чего это стоит
///
/// Встречного давления у нас нет: сколько `link` записал, столько и уехало
/// в очередь платформы. Потолок этому ставит не поток, а сам `link` —
/// полоса объёмных кадров пропускает их по одному, а окно чанков для эфира
/// равно двум ([`ratatosk_proto::files::chunk_window`]). То есть в очереди
/// Kotlin оказывается не больше пары мебибайт, и это осознанная цена
/// за честный обрыв.
pub struct Outgoing {
    bridge: Arc<Bridge>,
    channel: u64,
    /// Жив ли канал. Гасится из [`BridgedAir::on_closed`].
    alive: Arc<AtomicBool>,
}

impl Outgoing {
    /// Обрыв словами, которые дойдут до журнала связи.
    fn broken() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "канал Bluetooth закрыт платформой")
    }
}

impl AsyncWrite for Outgoing {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.alive.load(Ordering::Relaxed) {
            return Poll::Ready(Err(Outgoing::broken()));
        }
        let Some(radio) = self.bridge.radio() else {
            return Poll::Ready(Err(Outgoing::broken()));
        };
        radio.write(self.channel, buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    /// Сбрасывать нечего: своего буфера у потока нет.
    ///
    /// Сброс для `link` — условие работоспособности (см. его `write_loop`),
    /// и отвечать «сброшено» можно только потому, что копить здесь негде:
    /// байты уже у платформы.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Закрытие — это закрытие **канала**, а не только потока.
    ///
    /// `link` закрывает поток явно, и для радио разница не косметическая:
    /// брошенный канал L2CAP остаётся открытым у собеседника.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.alive.store(false, Ordering::Relaxed);
        if let Ok(mut held) = self.bridge.alive.lock() {
            held.remove(&self.channel);
        }
        if let Some(radio) = self.bridge.radio() {
            radio.close(self.channel);
        }
        Poll::Ready(Ok(()))
    }
}

/// Запас к границе слота при переобъявлении — тот же, что у местного радио.
const SLOT_MARGIN: Duration = Duration::from_secs(2);

/// Переобъявляется со сменой слота, пока это удаётся.
///
/// Объявление, не меняющееся со временем, есть долговременный
/// опознаватель устройства (§5.1), — поэтому задача бесконечная,
/// и уходит она только вместе со ступенью.
///
/// Свободной функцией, а не будущим по месту: заводится она через
/// [`Bridge::in_runtime`], и собранное отдельно читается там легче,
/// чем вложенное в замыкание внутри замыкания.
async fn rotate(bridge: Arc<Bridge>, psm: u16) {
    loop {
        let now = unix_seconds();
        let next = (beacon::slot(now) + 1) * beacon::SLOT_SECONDS;
        tokio::time::sleep(Duration::from_secs(next.saturating_sub(now)) + SLOT_MARGIN).await;
        if !bridge.announce(psm) {
            break;
        }
    }
}

/// Кладёт кусок в очередь разбора, дожидаясь места.
///
/// Возвращает, уехал ли кусок. `false` означает одно из двух: разбор
/// не взял ни куска за весь срок, либо очередь закрыта совсем, — и то
/// и другое повод закрыть канал.
///
/// **Останавливать зовущий поток — это и есть смысл функции**, а не её
/// побочный вред. Зовут её с потока платформы, который вычитывает сокет;
/// пока он стоит, сокет не вычитывается, кредиты L2CAP не возвращаются,
/// а запись у отправителя ждёт. Управление потоком, придуманное для этого
/// в самом L2CAP, начинает наконец работать. Разбор — у [`ROOM_LIMIT`].
///
/// Срок отдельным доводом, а не константой внутри: проверке нужен
/// короткий, а эфиру — длинный, и подменять время на часы ради одной
/// ветки дороже, чем передать число.
fn send_waiting(sender: &mpsc::Sender<Vec<u8>>, data: Vec<u8>, limit: Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    let mut data = data;
    loop {
        match sender.try_send(data) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
            Err(mpsc::error::TrySendError::Full(back)) => data = back,
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(ROOM_POLL);
    }
}

/// Соль объявления — новая на каждое переобъявление (§5.1).
fn fresh_nonce() -> [u8; 8] {
    use rand_core::RngCore as _;

    let mut nonce = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Входящий канал как поток на чтение.
///
/// Тридцать строк вместо чужого крейта, и причина простая: платформа
/// отдаёт байты **толчком** (синхронным вызовом), а сборщик кадров ждёт
/// их **тягой** (`AsyncRead`). Между ними очередь, и это единственное,
/// что здесь происходит.
struct Incoming {
    chunks: mpsc::Receiver<Vec<u8>>,
    /// Хвост куска, не поместившийся в буфер читателя.
    rest: Vec<u8>,
}

impl Incoming {
    fn new(chunks: mpsc::Receiver<Vec<u8>>) -> Incoming {
        Incoming { chunks, rest: Vec::new() }
    }
}

impl AsyncRead for Incoming {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Закрепление здесь ни при чём: очередь и хвост переносимы,
        // и `get_mut` честнее, чем проекция ради проекции.
        let me = self.get_mut();
        if me.rest.is_empty() {
            match me.chunks.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => me.rest = chunk,
                // Очередь закрыта — канала больше нет. Это конец потока,
                // а не ошибка: сборщик кадров закроет свою задачу сам.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let take = me.rest.len().min(buf.remaining());
        buf.put_slice(&me.rest[..take]);
        me.rest.drain(..take);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_full_queue_waits_instead_of_dropping_the_channel() {
        // **Разбор замера `m`.** Очередь полна не потому, что разбор мёртв,
        // а потому, что ядро занято предыдущим кадром: шестьдесят четыре
        // килобайта надо расшифровать, сложить и показать. Прежде это
        // считалось доказательством смерти и стоило канала — у отправителя
        // запись падала с `NotConnected` на тридцатом кадре.
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(vec![1u8; 8]).expect("первый кусок влезает");

        let done = Arc::new(AtomicBool::new(false));
        let handed = {
            let tx = tx.clone();
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let ok = send_waiting(&tx, vec![2u8; 8], Duration::from_secs(5));
                done.store(true, Ordering::SeqCst);
                ok
            })
        };

        // Поток стоит — и в этом вся польза: пока он стоит, платформа
        // не вычитывает сокет, кредиты L2CAP не возвращаются, а запись
        // у отправителя ждёт.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!done.load(Ordering::SeqCst), "места нет — значит ждём");

        // Разбор дошёл до первого куска, место освободилось.
        assert_eq!(rx.try_recv().expect("первый кусок"), vec![1u8; 8]);
        assert!(handed.join().expect("поток"), "кусок уехал, а не пропал");
        // **И уехал вторым.** Порядок тут не украшение: куски — это поток,
        // и переставленные местами они дают кадр нужной длины с испорченной
        // серединой, то есть поломку, которую видно только по тегу AEAD.
        assert_eq!(rx.try_recv().expect("второй кусок"), vec![2u8; 8]);
    }

    #[test]
    fn a_queue_that_never_moves_gives_up_in_the_end() {
        // Ждать вечно значило бы держать канал, из которого никогда ничего
        // не выйдет. Срок отличает «ядро занято» от «ядра нет».
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(vec![1u8; 8]).expect("первый кусок влезает");

        let started = Instant::now();
        assert!(
            !send_waiting(&tx, vec![2u8; 8], Duration::from_millis(100)),
            "разбор не взял ни куска — канал пора закрывать"
        );
        assert!(started.elapsed() >= Duration::from_millis(100), "и ждали мы весь срок");
    }

    #[test]
    fn a_queue_that_is_gone_does_not_cost_the_whole_wait() {
        // Разбор кончился — ждать нечего и незачем. Полминуты тишины
        // на закрытом канале задержали бы всё, что идёт следом.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        drop(rx);

        let started = Instant::now();
        assert!(!send_waiting(&tx, vec![2u8; 8], Duration::from_secs(30)), "очереди больше нет");
        assert!(started.elapsed() < Duration::from_secs(1), "и узнали мы это сразу");
    }
}
