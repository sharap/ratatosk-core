//! Драйвер: единственное место, где ядро встречается с рантаймом.
//!
//! Цикл прост и обязан таким остаться: взять событие, отдать его [`Engine`],
//! исполнить возвращённые эффекты. Никакой протокольной логики здесь нет —
//! любая ветка «а если это групповое сообщение» в драйвере означает, что она
//! ушла из ядра и выпала из симуляции (§16).
//!
//! Три источника входов: транспорт, команды UI и таймеры. Таймеры держит
//! драйвер, а не ядро: [`Effect::SetTimer`] задаёт срок, драйвер спит до
//! ближайшего и возвращает [`Input::Timer`]. Спит, а не опрашивает — на
//! телефоне это прямо расход батареи (§13.1).

use std::collections::BTreeMap;
use std::time::Duration;

use ratatosk_proto::transport_policy::PeerAvailability;
use ratatosk_store::{StoredMessage, Store};
use ratatosk_transport::{Runner, TransportCommand, TransportEvent};
use tokio::sync::{mpsc, oneshot};

use crate::engine::{Engine, EngineError};
use crate::io::{ChatId, Command, Effect, Event, Input};
use ratatosk_transport::runner::PeerAddress;

/// Сколько команд и уведомлений помещается в очередь, прежде чем отправитель
/// начнёт ждать.
const CHANNEL_DEPTH: usize = 64;

/// Запрос на чтение состояния.
///
/// Отдельно от [`Command`] намеренно: команда меняет состояние и её исполнение
/// наблюдается событиями, а запрос ничего не меняет и обязан вернуть ответ.
/// Смешать их значило бы завести команду, у которой есть результат, — и первый
/// же клиент начал бы строить на нём логику, которой по §13.3 быть не должно.
enum Query {
    /// Окно сообщений чата в порядке HLC (§9.1).
    Messages {
        chat: ChatId,
        limit: usize,
        reply: oneshot::Sender<Vec<StoredMessage>>,
    },
    /// Что известно о контактах прямо сейчас.
    Contacts { reply: oneshot::Sender<Vec<ContactStatus>> },
}

/// Что клиент знает о контакте.
///
/// [`PeerAvailability`] здесь не украшение: это ровно те четыре признака,
/// по которым §5.4 выбирает транспорт. Без них «сообщение не ушло» —
/// сообщение без причины, а причина у него всегда одна из четырёх.
#[derive(Debug, Clone)]
pub struct ContactStatus {
    /// Статический ключ контакта.
    pub peer_ik: [u8; 32],
    /// Отпечаток для сверки голосом (§3, §4.2).
    ///
    /// Считается здесь, а не в клиенте: §13.3 запрещает протокольную логику
    /// выше границы, а вывод отпечатка из `IK ‖ SK` — ровно она.
    pub fingerprint: String,
    /// Имя из карточки. Получателем не доверяется (§4.1).
    pub display_name: String,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Чем до него можно достучаться (§5.4).
    pub availability: PeerAvailability,
}

/// Что разбудило цикл. Существует только затем, чтобы решение принималось
/// после `select!`, а не внутри его ветки.
enum Wake {
    Input(Input),
    Query(Query),
    Timers,
    Stop,
}

/// Ручка, через которую UI разговаривает с драйвером.
///
/// Единственный путь наружу: §13.3 запрещает протокольную логику выше UniFFI,
/// и структурно это выражено тем, что у клиента есть только команды, запросы
/// и события, а до [`Engine`] он не дотягивается.
///
/// Клонируется, а поток событий — нет, и это не асимметрия ради удобства.
/// Команды шлют откуда угодно: из UI-потока, из уведомления, из фоновой
/// задачи. События читает ровно один насос, который раздаёт их дальше;
/// два читателя поделили бы поток между собой, и половина событий не дошла
/// бы ни до кого.
#[derive(Clone)]
pub struct DriverHandle {
    commands: mpsc::Sender<Command>,
    queries: mpsc::Sender<Query>,
}

/// Поток событий для UI. Существует в единственном экземпляре.
pub struct EventStream {
    notices: mpsc::Receiver<Event>,
}

impl EventStream {
    /// Ждёт следующее событие. `None` — драйвер остановлен.
    pub async fn next(&mut self) -> Option<Event> {
        self.notices.recv().await
    }
}

impl DriverHandle {
    /// Отправляет команду ядру.
    ///
    /// Ошибка означает, что драйвер остановлен.
    pub async fn send(&self, command: Command) -> Result<(), Command> {
        self.commands.send(command).await.map_err(|e| e.0)
    }

    /// Читает последние сообщения чата. `None` — драйвер остановлен.
    pub async fn messages(&self, chat: ChatId, limit: usize) -> Option<Vec<StoredMessage>> {
        let (reply, answer) = oneshot::channel();
        self.queries.send(Query::Messages { chat, limit, reply }).await.ok()?;
        answer.await.ok()
    }

    /// Читает список контактов вместе с их доступностью. `None` — драйвер
    /// остановлен.
    pub async fn contacts(&self) -> Option<Vec<ContactStatus>> {
        let (reply, answer) = oneshot::channel();
        self.queries.send(Query::Contacts { reply }).await.ok()?;
        answer.await.ok()
    }

    // --- синхронные обёртки для UniFFI --------------------------------------
    //
    // Методы через UniFFI-границу синхронные, а драйвер живёт на своём потоке
    // с рантаймом. Эти три обёртки — единственный мост между ними.
    //
    // Вызывать их изнутри рантайма нельзя: `blocking_send` в асинхронном
    // контексте паникует. Для клиента это не ограничение — он звонит сюда
    // из UI-потока, который рантайма не знает вовсе.

    /// Отправляет команду, блокируя вызывающий поток.
    pub fn send_blocking(&self, command: Command) -> Result<(), Command> {
        self.commands.blocking_send(command).map_err(|e| e.0)
    }

    /// Читает сообщения, блокируя вызывающий поток.
    pub fn messages_blocking(&self, chat: ChatId, limit: usize) -> Option<Vec<StoredMessage>> {
        let (reply, answer) = oneshot::channel();
        self.queries.blocking_send(Query::Messages { chat, limit, reply }).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает контакты, блокируя вызывающий поток.
    pub fn contacts_blocking(&self) -> Option<Vec<ContactStatus>> {
        let (reply, answer) = oneshot::channel();
        self.queries.blocking_send(Query::Contacts { reply }).ok()?;
        answer.blocking_recv().ok()
    }
}

/// Гоняет ядро поверх настоящего ввода-вывода.
pub struct Driver<S: Store, R: Runner> {
    engine: Engine<S>,
    runner: R,
    commands: mpsc::Receiver<Command>,
    queries: mpsc::Receiver<Query>,
    notices: mpsc::Sender<Event>,
    /// Срок → метки таймеров, которые в этот срок сработают.
    ///
    /// `BTreeMap` ради одного свойства: ближайший срок — это `keys().next()`,
    /// то есть цикл всегда знает, до какого момента спать.
    timers: BTreeMap<u64, Vec<u64>>,
}

impl<S: Store, R: Runner> Driver<S, R> {
    /// Связывает ядро с раннером и выдаёт ручку и поток событий для UI.
    pub fn new(engine: Engine<S>, runner: R) -> (Driver<S, R>, DriverHandle, EventStream) {
        let (commands_tx, commands_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (queries_tx, queries_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (notices_tx, notices_rx) = mpsc::channel(CHANNEL_DEPTH);
        let driver = Driver {
            engine,
            runner,
            commands: commands_rx,
            queries: queries_rx,
            notices: notices_tx,
            timers: BTreeMap::new(),
        };
        let handle = DriverHandle { commands: commands_tx, queries: queries_tx };
        (driver, handle, EventStream { notices: notices_rx })
    }

    /// Ядро на чтение — для тестов и диагностики.
    pub fn engine(&self) -> &Engine<S> {
        &self.engine
    }

    /// Основной цикл. Возвращается, когда закрылся транспорт или ручка UI.
    pub async fn run(&mut self) -> Result<(), EngineError> {
        loop {
            let deadline = self.timers.keys().next().copied();

            // Ветки `select!` только называют, что случилось, и ничего не
            // делают: пока идёт разбор, остальные фьючерсы ещё живы и держат
            // заимствования полей, так что `&mut self` внутри ветки не взять.
            //
            // Все три ожидания — `recv` по каналу, то есть отменяемы без
            // потери сообщения. Иначе `select!` терял бы вход при каждом
            // срабатывании таймера.
            let wake = tokio::select! {
                event = self.runner.next_event() => match event {
                    Some(event) => Wake::Input(translate(event)),
                    None => Wake::Stop,
                },
                command = self.commands.recv() => match command {
                    Some(command) => Wake::Input(Input::Command(command)),
                    None => Wake::Stop,
                },
                query = self.queries.recv() => match query {
                    Some(query) => Wake::Query(query),
                    None => Wake::Stop,
                },
                () = sleep_until(deadline) => Wake::Timers,
            };

            match wake {
                Wake::Input(input) => self.feed(input).await?,
                Wake::Query(query) => self.answer(query),
                Wake::Timers => self.fire_due_timers().await?,
                Wake::Stop => return Ok(()),
            }
        }
    }

    /// Отвечает на запрос чтения. Состояние не меняется.
    fn answer(&self, query: Query) {
        match query {
            Query::Messages { chat, limit, reply } => {
                let found = self.engine.store().messages(&chat, limit, None).unwrap_or_default();
                // Отправитель мог уйти, не дождавшись: это не ошибка.
                let _ = reply.send(found);
            }
            Query::Contacts { reply } => {
                let found = self
                    .engine
                    .contacts()
                    .iter()
                    .map(|(peer_ik, contact)| ContactStatus {
                        peer_ik: *peer_ik,
                        // Ключи в карточке уже проверялись при добавлении;
                        // если разбор всё же откажет, показывать пустую строку
                        // честнее, чем ронять список контактов.
                        fingerprint: ratatosk_crypto::PublicIdentity::from_bytes(
                            contact.card.ik,
                            contact.card.sk,
                        )
                        .map(|id| id.fingerprint())
                        .unwrap_or_default(),
                        display_name: contact.card.display_name.clone(),
                        verified: contact.verified,
                        availability: contact.availability,
                    })
                    .collect();
                let _ = reply.send(found);
            }
        }
    }

    /// Подаёт вход ядру и исполняет всё, что оно вернуло.
    async fn feed(&mut self, input: Input) -> Result<(), EngineError> {
        let now_ms = now_ms();
        for effect in self.engine.step(now_ms, input)? {
            self.apply(now_ms, effect).await;
        }
        Ok(())
    }

    /// Отдаёт ядру все таймеры, чей срок наступил.
    ///
    /// Именно все: если процесс был усыплён, к пробуждению просрочено может
    /// быть несколько, и обработка по одному за круг растянула бы отказ
    /// доставки на лишние обороты цикла.
    async fn fire_due_timers(&mut self) -> Result<(), EngineError> {
        let now = now_ms();
        let due: Vec<u64> = {
            let rest = self.timers.split_off(&(now + 1));
            let fired = std::mem::replace(&mut self.timers, rest);
            fired.into_values().flatten().collect()
        };
        for token in due {
            self.feed(Input::Timer { token }).await?;
        }
        Ok(())
    }

    async fn apply(&mut self, now_ms: u64, effect: Effect) {
        let command = match effect {
            Effect::Send { peer_ik, via, frame } => Some(TransportCommand::Send {
                peer: self.address_of(peer_ik),
                via,
                frame,
            }),
            Effect::Connect { peer_ik, via } => {
                Some(TransportCommand::Connect { peer: self.address_of(peer_ik), via })
            }
            Effect::SetLanEnabled(on) => Some(TransportCommand::SetLanEnabled(on)),
            Effect::WatchLanPeers(peers) => Some(TransportCommand::WatchLanPeers(peers)),
            Effect::SetTimer { after_ms, token } => {
                self.timers.entry(now_ms.saturating_add(after_ms)).or_default().push(token);
                None
            }
            Effect::Notify(event) => {
                // Переполнение очереди UI не должно останавливать протокол:
                // клиент, который не читает события, — его беда, а сообщения
                // при этом обязаны продолжать ходить.
                if self.notices.try_send(event).is_err() {
                    tracing::debug!("очередь событий UI переполнена, событие отброшено");
                }
                None
            }
        };
        if let Some(command) = command {
            if let Err(error) = self.runner.execute(command).await {
                // Отказ транспорта — не отказ ядра: сообщение остаётся
                // в очереди и уйдёт следующим транспортом по §5.4.
                tracing::debug!(?error, "транспорт отказал, переходим к следующему");
            }
        }
    }

    /// Адреса контакта для транспорта.
    ///
    /// Берутся из карточки (§4.1). Адреса в локальной сети здесь нет и быть
    /// не может: он меняется при каждом подключении к другой сети, поэтому
    /// его знает только обнаружение (§5.1).
    fn address_of(&self, peer_ik: [u8; 32]) -> PeerAddress {
        match self.engine.contacts().get(&peer_ik) {
            Some(contact) => PeerAddress {
                ik: peer_ik,
                onion: non_empty(&contact.card.onion),
                chatmail: non_empty(&contact.card.chatmail),
            },
            None => PeerAddress { ik: peer_ik, onion: None, chatmail: None },
        }
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

/// Спит до указанного момента; без срока — не просыпается вовсе.
async fn sleep_until(deadline_ms: Option<u64>) {
    match deadline_ms {
        Some(at) => {
            let now = now_ms();
            tokio::time::sleep(Duration::from_millis(at.saturating_sub(now))).await;
        }
        // Ждать нечего — пусть просыпают транспорт или UI.
        None => std::future::pending().await,
    }
}

fn translate(event: TransportEvent) -> Input {
    match event {
        TransportEvent::Received { via, frame, .. } => Input::Received { via, frame },
        TransportEvent::Connected { peer_ik, via } => Input::Connected { peer_ik, via },
        TransportEvent::Disconnected { peer_ik, via }
        | TransportEvent::ConnectFailed { peer_ik, via } => Input::ConnectionLost { peer_ik, via },
        TransportEvent::SeenOnLan { peer_ik } => Input::SeenOnLan { peer_ik },
        TransportEvent::TorReady => Input::Timer { token: 0 },
    }
}

/// Системное время в миллисекундах.
///
/// Единственное место в ядре, где читаются часы, — и оно намеренно вынесено
/// в драйвер: §9.1 требует, чтобы системное время никогда не было источником
/// порядка. Порядок задаёт HLC, а это значение — только вход для него.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}
