//! UniFFI-граница (§13.3).
//!
//! Правило без исключений: **никакой протокольной логики выше этой границы.**
//! Всё, что здесь есть, — перевод типов ядра в то, что умеет UniFFI, и
//! обратно. Если появляется соблазн написать здесь `if`, зависящий от
//! содержимого сообщения, значит логика уходит в клиент и выпадает из
//! симуляции (§16).
//!
//! Типы наружу намеренно простые: без лайфтаймов, без generic'ов, без
//! заимствований. Kotlin и Tauri видят обычные структуры и колбэки.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ratatosk_codec::ContactCard;
use ratatosk_core::driver::{Driver, DriverHandle, EventStream};
use ratatosk_core::{vault, Command, Engine, Event, OsEntropy, SelfAddresses};
use ratatosk_proto::DeliveryStatus;
use ratatosk_store::SqliteStore;
use ratatosk_transport::{LanConfig, LanRunner};

uniffi::setup_scaffolding!();

impl RatatoskError {
    fn internal(reason: impl std::fmt::Display) -> RatatoskError {
        RatatoskError::Internal { reason: reason.to_string() }
    }
}

/// Отделяет «не тот PIN» от всего остального.
///
/// Различие содержательное, а не косметическое: заблокированную базу лечит
/// пользователь, введя правильный PIN, а внутреннюю ошибку — не лечит никак.
/// Показать первое как второе значит подтолкнуть человека переустановить
/// клиент и потерять переписку, которая на самом деле цела.
///
/// Определяется по типу ошибки, а не по тексту: формулировки правятся, и
/// сравнение подстрок развалилось бы молча.
fn engine_err(error: ratatosk_core::EngineError) -> RatatoskError {
    use ratatosk_core::EngineError;
    match error {
        EngineError::Store(ratatosk_store::StoreError::Locked)
        | EngineError::Crypto(ratatosk_crypto::CryptoError::Decrypt) => RatatoskError::Locked,
        other => RatatoskError::internal(other),
    }
}

/// Ошибка, которую видит клиент.
///
/// Формулировки скупые и не раскрывают, что именно не сошлось: подробная
/// ошибка на границе рано или поздно оказывается в логе, а оттуда — у того,
/// от кого §2.1 обещает защиту.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RatatoskError {
    /// База заблокирована: нужен PIN (§8.6).
    #[error("база заблокирована")]
    Locked,
    /// Внутренняя ошибка.
    #[error("внутренняя ошибка: {reason}")]
    Internal {
        /// Короткое описание для отчёта.
        reason: String,
    },
}

/// Статус доставки для UI (§9.4).
///
/// `Delivered` и `Read` недостижимы при почтовой доставке — это свойство
/// протокола, а не решение клиента (§14, пункт 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeliveryStatus {
    /// Отправить не удалось: ни один транспорт не сработал (§5.4).
    ///
    /// Отдельный вариант, а не «ждёт отправки». Сообщение, которое не ушло
    /// и не уйдёт, показанное как ожидающее, — обещание, которого протокол
    /// не даёт, то есть ровно то, что §14 запрещает.
    Undeliverable,
    /// Ждёт отправки.
    Pending,
    /// Отправлено.
    Sent,
    /// Доставлено. Только прямой канал.
    Delivered,
    /// Прочитано. Только прямой канал.
    Read,
}

/// Событие для UI.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiEvent {
    /// Пришло сообщение.
    MessageReceived {
        /// Чат.
        chat_id: Vec<u8>,
        /// Идентификатор сообщения.
        msg_id: Vec<u8>,
    },
    /// Изменился статус доставки.
    StatusChanged {
        /// Идентификатор сообщения.
        msg_id: Vec<u8>,
        /// Новый статус.
        status: FfiDeliveryStatus,
    },
    /// Добавлен контакт.
    ContactAdded {
        /// Отпечаток для показа (§3).
        fingerprint: String,
        /// Сверен ли отпечаток. Пока нет — UI обязан пометить контакт
        /// непроверенным (§4.2).
        verified: bool,
    },
    /// Изменился состав группы.
    GroupMembershipChanged {
        /// Чат.
        chat_id: Vec<u8>,
    },
    /// Текст из §14, который клиент обязан показать дословно.
    HonestNotice {
        /// Текст.
        text: String,
    },
}

/// Контакт в том виде, в каком его показывает UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContact {
    /// Статический ключ — им адресуются команды.
    pub peer_ik: Vec<u8>,
    /// Идентификатор чата 1:1 с этим контактом.
    pub chat_id: Vec<u8>,
    /// Отпечаток для сверки голосом (§3, §4.2).
    pub fingerprint: String,
    /// Имя из карточки. **Не доверенное** (§4.1): его задаёт собеседник,
    /// и UI обязан показывать его как подпись, а не как удостоверение.
    pub display_name: String,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Виден ли контакт в локальной сети прямо сейчас (§5.1).
    pub seen_on_lan: bool,
}

/// Сообщение в том виде, в каком его показывает UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessage {
    /// Идентификатор.
    pub msg_id: Vec<u8>,
    /// Текст.
    pub body: String,
    /// Своё ли сообщение.
    ///
    /// Считается здесь, а не в клиенте: сравнение с собственным `IK` —
    /// протокольное знание, и §13.3 не разрешает ему подниматься выше.
    pub mine: bool,
    /// Физическая компонента метки порядка (§9.1), миллисекунды.
    ///
    /// Показывать её как время получения можно, а сортировать по ней —
    /// нет: порядок задаёт HLC целиком, и он уже применён к списку.
    pub wall_ms: u64,
    /// Судьба отправки (§9.4).
    ///
    /// `None` у **принятых** сообщений, и это не пропуск: статус — это судьба
    /// отправки, а принятое уже здесь. Рисовать у чужого сообщения галочку
    /// значит показать пользователю то, чего протокол не утверждает.
    pub status: Option<FfiDeliveryStatus>,
}

/// Подписка UI на события ядра.
///
/// Колбэк, а не опрос: на Android опрос из foreground service — прямой расход
/// батареи, а §14 пункт 6 и так обещает пользователю больше, чем хотелось бы.
///
/// `foreign`, а не `rust, foreign`: трейт реализует только UI, и Rust-версии
/// через границу не ходят. Так не генерируется неиспользуемый скаффолдинг.
/// Устаревший `callback_interface` (с `Box<dyn _>`) не используется.
#[uniffi::export(foreign)]
pub trait EventObserver: Send + Sync {
    /// Вызывается на каждое событие.
    fn on_event(&self, event: FfiEvent);
}

/// Всё, что стало известно при открытии и дальше не меняется.
struct Opened {
    handle: DriverHandle,
    fingerprint: String,
    contact_uri: String,
    own_ik: [u8; 32],
}

/// Клиент ядра — то, что держит Kotlin или Tauri.
///
/// Ядро живёт на собственном потоке с рантаймом, и это не деталь реализации,
/// а следствие двух вещей сразу: методы через UniFFI синхронные, а состояние
/// рукопожатия из `snow` не обещает `Send`. Поэтому всё, что относится
/// к ядру, **создаётся внутри этого потока** — наружу уходит только ручка
/// из каналов, которую пересылать можно.
///
/// Уничтожение клиента закрывает каналы, драйвер выходит из цикла, поток
/// завершается. Отдельного `close` нет намеренно: два способа остановиться
/// разошлись бы при первой же ошибке в клиенте.
#[derive(uniffi::Object)]
pub struct RatatoskClient {
    opened: Opened,
    observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>>,
}

#[uniffi::export]
impl RatatoskClient {
    /// Открывает или создаёт хранилище по пути.
    ///
    /// `pin` — `None`, если пользователь отказался от PIN. В этом случае
    /// клиент **обязан** показать [`no_pin_warning`]: §8.6 разрешает отказ,
    /// но до подключения хранилища ключей ОС ключ базы лежит в самой базе
    /// открыто, и содержимое доступно любому, кто получил файл.
    ///
    /// Неверный PIN возвращает [`RatatoskError::Locked`] и **не** заводит
    /// новую личность: молчаливый старт с чистого листа выглядит как
    /// потерянная переписка.
    #[uniffi::constructor]
    pub fn open(
        db_path: String,
        pin: Option<String>,
        display_name: String,
    ) -> Result<Arc<Self>, RatatoskError> {
        let observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>> = Arc::new(Mutex::new(None));
        let pump_observer = Arc::clone(&observer);

        // Канал на одно сообщение: поток отчитывается об исходе запуска
        // ровно раз, а дальше живёт своей жизнью.
        let (ready_tx, ready_rx) =
            std::sync::mpsc::sync_channel::<Result<Opened, RatatoskError>>(1);

        std::thread::Builder::new()
            .name("ratatosk-core".to_owned())
            .spawn(move || {
                let runtime =
                    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = ready_tx.send(Err(RatatoskError::internal(error)));
                            return;
                        }
                    };
                runtime.block_on(async move {
                    let started = start(PathBuf::from(db_path), pin, display_name).await;
                    let (mut driver, opened, events) = match started {
                        Ok(parts) => parts,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(opened)).is_err() {
                        // Клиент не дождался — поднимать ядро незачем.
                        return;
                    }
                    tokio::spawn(pump_events(events, pump_observer));
                    if let Err(error) = driver.run().await {
                        tracing_stop(&error);
                    }
                });
            })
            .map_err(RatatoskError::internal)?;

        let opened = ready_rx
            .recv()
            .map_err(|_| RatatoskError::internal("поток ядра завершился при запуске"))??;

        Ok(Arc::new(RatatoskClient { opened, observer }))
    }

    /// Подписывает UI на события.
    pub fn set_observer(&self, observer: Arc<dyn EventObserver>) {
        if let Ok(mut slot) = self.observer.lock() {
            *slot = Some(observer);
        }
    }

    /// Отпечаток собственной идентичности (§3).
    pub fn fingerprint(&self) -> String {
        self.opened.fingerprint.clone()
    }

    /// Своя контакт-карточка как URI для QR (§4.1).
    pub fn my_contact_uri(&self) -> String {
        self.opened.contact_uri.clone()
    }

    /// Идентификатор чата 1:1 с контактом.
    pub fn chat_id_for(&self, peer_ik: Vec<u8>) -> Result<Vec<u8>, RatatoskError> {
        let ik = to_ik(&peer_ik)?;
        Ok(Engine::<SqliteStore>::chat_id_for(&ik).to_vec())
    }

    /// Добавляет контакт по URI из QR или ссылки (§4.2).
    ///
    /// `met_in_person` различает два способа обмена: при личной встрече канал
    /// доверенный по построению и отпечаток сверять не нужно; по ссылке —
    /// нужно, и до сверки контакт помечается непроверенным.
    pub fn add_contact(&self, uri: String, met_in_person: bool) -> Result<(), RatatoskError> {
        let card_bytes =
            ContactCard::from_uri(&uri).map_err(RatatoskError::internal)?.bytes().to_vec();
        self.command(Command::AddContact { card_bytes, met_in_person })
    }

    /// Подтверждает сверку отпечатка голосом (§4.2).
    pub fn mark_verified(&self, peer_ik: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::MarkVerified { peer_ik: to_ik(&peer_ik)? })
    }

    /// Отправляет текст.
    pub fn send_text(&self, chat_id: Vec<u8>, text: String) -> Result<(), RatatoskError> {
        self.command(Command::SendText { chat: to_chat(&chat_id)?, text })
    }

    /// Включает или выключает LAN (§5.1).
    ///
    /// Перед включением клиент обязан показать [`lan_warning`].
    pub fn set_lan_enabled(&self, enabled: bool) -> Result<(), RatatoskError> {
        self.command(Command::SetLanEnabled(enabled))
    }

    /// Сообщает, что пользователь дочитал чат до этого сообщения (§9.4).
    ///
    /// Отсюда уходит квитанция о прочтении — но только прямым каналом
    /// и только про сообщения собеседника. По почте квитанций нет вовсе:
    /// каждая была бы отдельным письмом.
    ///
    /// **Это единственный источник квитанции о прочтении.** Ни приём
    /// сообщения, ни открытие чата, ни запуск приложения её не порождают:
    /// ядро не знает и не может знать, что человек прочитал, — знает клиент.
    /// Когда именно звать, решает тоже клиент: открытие чата, докрутка до
    /// конца, задержка на экране. Ядро своей политики сюда не добавляет.
    ///
    /// Отсюда же и выключатель: клиенту, который квитанций о прочтении
    /// не хочет, достаточно не звать эту команду. Отдельной настройки
    /// в ядре нет и не нужно.
    ///
    /// Повторный вызов про то же место ничего не отправляет — и это
    /// переживает перезапуск: собеседнику сообщают один раз.
    pub fn mark_read(&self, chat_id: Vec<u8>, up_to: Vec<u8>) -> Result<(), RatatoskError> {
        let up_to: [u8; 16] = up_to
            .as_slice()
            .try_into()
            .map_err(|_| RatatoskError::internal("идентификатор сообщения не 16 байт"))?;
        self.command(Command::MarkRead { chat: to_chat(&chat_id)?, up_to })
    }

    /// Сообщает, что сеть сменилась.
    ///
    /// Заметить это может только система: на Android — `ConnectivityManager`,
    /// на десктопе — событие смены интерфейса. Ядро не имеет ни сокетов,
    /// ни часов и отличить смену сети от молчания собеседника не может.
    ///
    /// Без этого вызова после перехода с Wi-Fi на мобильный (и обратно, и
    /// между точками доступа) локальная сеть остаётся в прежнем состоянии:
    /// адреса указывают в старую сеть, объявление в эфир не звучит, и каждая
    /// отправка платит таймаутом за то, что уже известно.
    ///
    /// Вызывать можно свободно: лишний вызов стоит одного переобъявления.
    pub fn network_changed(&self) -> Result<(), RatatoskError> {
        self.command(Command::NetworkChanged)
    }

    /// Список контактов.
    pub fn contacts(&self) -> Result<Vec<FfiContact>, RatatoskError> {
        let found = self
            .opened
            .handle
            .contacts_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|c| FfiContact {
                chat_id: Engine::<SqliteStore>::chat_id_for(&c.peer_ik).to_vec(),
                peer_ik: c.peer_ik.to_vec(),
                fingerprint: c.fingerprint,
                display_name: c.display_name,
                verified: c.verified,
                seen_on_lan: c.availability.seen_on_lan,
            })
            .collect())
    }

    /// Последние сообщения чата в порядке HLC (§9.1).
    pub fn messages(&self, chat_id: Vec<u8>, limit: u32) -> Result<Vec<FfiMessage>, RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let found = self
            .opened
            .handle
            .messages_blocking(chat, limit as usize)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|m| FfiMessage {
                msg_id: m.msg_id.to_vec(),
                // Тела сегодня всегда текстовые (§9.1, `PayloadType::Text`);
                // порча кодировки не повод потерять сообщение целиком.
                body: String::from_utf8_lossy(&m.body).into_owned(),
                mine: m.sender_ik == self.opened.own_ik,
                wall_ms: m.hlc.wall_ms,
                status: m.status.and_then(DeliveryStatus::from_code).map(status_of),
            })
            .collect())
    }
}

impl RatatoskClient {
    fn command(&self, command: Command) -> Result<(), RatatoskError> {
        self.opened
            .handle
            .send_blocking(command)
            .map_err(|_| RatatoskError::internal("ядро остановлено"))
    }
}

/// Перевод лестницы статусов §9.4 в то, что видит UI.
///
/// Варианты перечислены поимённо: новый статус обязан сломать сборку здесь,
/// а не молча стать чем-то похожим.
const fn status_of(status: DeliveryStatus) -> FfiDeliveryStatus {
    match status {
        DeliveryStatus::Undeliverable => FfiDeliveryStatus::Undeliverable,
        DeliveryStatus::Pending => FfiDeliveryStatus::Pending,
        DeliveryStatus::Sent => FfiDeliveryStatus::Sent,
        DeliveryStatus::Delivered => FfiDeliveryStatus::Delivered,
        DeliveryStatus::Read => FfiDeliveryStatus::Read,
    }
}

fn to_ik(bytes: &[u8]) -> Result<[u8; 32], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("ключ контакта не 32 байта"))
}

fn to_chat(bytes: &[u8]) -> Result<[u8; 16], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор чата не 16 байт"))
}

/// Собирает ядро целиком — внутри потока, которому оно и принадлежит.
async fn start(
    db_path: PathBuf,
    pin: Option<String>,
    display_name: String,
) -> Result<(Driver<SqliteStore, LanRunner>, Opened, EventStream), RatatoskError> {
    let (mut store, db_key) =
        vault::open_encrypted(&db_path, pin.as_deref()).map_err(engine_err)?;
    let identity = vault::load_or_create(&mut store, &db_key).map_err(engine_err)?;

    // Onion и chatmail пока пусты: их адреса появятся вместе с транспортами
    // этапов 2 и 3. §5.4 с пустыми адресами честно скажет «отправлять некуда»,
    // а не сделает вид, что письмо ушло.
    let addresses = SelfAddresses { onion: String::new(), chatmail: String::new(), display_name };

    let mut engine = Engine::new(identity, store, Box::new(OsEntropy), addresses);
    engine.restore().map_err(engine_err)?;

    let card = engine.own_card();
    let opened_parts =
        (engine.fingerprint(), card.to_uri().map_err(RatatoskError::internal)?, card.ik);

    // §5.1: LAN выключен по умолчанию. Порт занимается сразу — он нужен
    // объявлению, а без объявления никого не раскрывает.
    let runner =
        LanRunner::start(LanConfig::default(), card.ik).await.map_err(RatatoskError::internal)?;

    let (driver, handle, events) = Driver::new(engine, runner);
    let opened = Opened {
        handle,
        fingerprint: opened_parts.0,
        contact_uri: opened_parts.1,
        own_ik: opened_parts.2,
    };
    Ok((driver, opened, events))
}

/// Единственный читатель потока событий: раздаёт их подписчику.
///
/// Пока подписчика нет, события **отбрасываются**, а не копятся. Очередь
/// событий, накопленная до подписки, выплеснулась бы на UI одним залпом
/// при первом же `set_observer` — и он показал бы как новые те сообщения,
/// которые уже лежат в истории.
async fn pump_events(
    mut events: EventStream,
    observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>>,
) {
    while let Some(event) = events.next().await {
        let Some(translated) = translate(event) else {
            continue;
        };
        let Some(subscriber) = observer.lock().ok().and_then(|slot| slot.clone()) else {
            continue;
        };
        subscriber.on_event(translated);
    }
}

/// Перевод событий ядра в то, что видит UI.
///
/// Варианты перечислены поимённо: новое событие ядра обязано сломать сборку
/// здесь, а не тихо не дойти до клиента.
fn translate(event: Event) -> Option<FfiEvent> {
    Some(match event {
        Event::MessageReceived { chat, msg_id } => {
            FfiEvent::MessageReceived { chat_id: chat.to_vec(), msg_id: msg_id.to_vec() }
        }
        Event::StatusChanged { msg_id, status } => {
            FfiEvent::StatusChanged { msg_id: msg_id.to_vec(), status: status_of(status) }
        }
        Event::ContactAdded { fingerprint, verified, .. } => {
            FfiEvent::ContactAdded { fingerprint, verified }
        }
        Event::GroupMembershipChanged { chat } => {
            FfiEvent::GroupMembershipChanged { chat_id: chat.to_vec() }
        }
        // §10 ещё не проходит через `step`, поэтому события и не будет.
        // Показывать вместо него пустое уведомление хуже, чем не показывать
        // ничего: клиент нарисовал бы пустую строку из §14.
        Event::FileProgress { .. } => return None,
        Event::HonestNotice { text } => FfiEvent::HonestNotice { text: text.to_owned() },
    })
}

fn tracing_stop(error: &ratatosk_core::EngineError) {
    // Отказ ядра наружу не выбрасывается: клиент уже держит объект, а
    // конструктор давно вернулся. Единственное, что честно, — записать.
    eprintln!("ratatosk: ядро остановилось: {error}");
}

/// Тексты из §14, которые клиент обязан показать дословно.
///
/// Функция на границе, а не константа в клиенте: §14 существует затем, чтобы
/// обещания продукта не разошлись со свойствами протокола, и держать эти
/// строки в Kotlin означало бы разрешить им разойтись.
#[uniffi::export]
#[must_use]
pub fn honest_notices() -> Vec<String> {
    ratatosk_core::honest::NOTICES.iter().map(|s| (*s).to_string()).collect()
}

/// Предупреждение при включении LAN (§5.1).
#[uniffi::export]
#[must_use]
pub fn lan_warning() -> String {
    ratatosk_core::honest::LAN_WARNING.to_string()
}

/// Предупреждение при отказе от PIN (§8.6).
#[uniffi::export]
#[must_use]
pub fn no_pin_warning() -> String {
    ratatosk_core::honest::NO_PIN_WARNING.to_string()
}

/// Формулировка последствий исключения из группы (§11.4).
#[uniffi::export]
#[must_use]
pub fn eviction_notice() -> String {
    ratatosk_proto::group::EvictionConsequences::ui_text().to_string()
}
