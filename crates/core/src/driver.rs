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

use ratatosk_crdt::{Hlc, MsgId};
use ratatosk_proto::transport_policy::PeerAvailability;
use ratatosk_store::{Store, StoredMessage, StoredReaction};
use ratatosk_transport::{Runner, TransportCommand, TransportEvent};
use tokio::sync::{mpsc, oneshot};

use crate::engine::{Engine, EngineError};
use crate::io::{ChatId, Command, Effect, Event, Input};
use ratatosk_transport::runner::PeerAddress;

/// Сколько команд и уведомлений помещается в очередь, прежде чем отправитель
/// начнёт ждать.
const CHANNEL_DEPTH: usize = 64;

/// Что клиент прислал драйверу: команду или запрос.
///
/// **Одна очередь на оба, и это исправление настоящей ошибки.** Раньше
/// команды и запросы шли разными каналами, а `select!` выбирает готовую ветку
/// произвольно — поэтому чтение, отправленное **после** записи, могло быть
/// обслужено **до** неё. Клиент ставил аватарку и тут же перечитывал её,
/// получая прежнюю; то же самое ждало любого, кто отправит сообщение и сразу
/// перечитает чат. Объяснить такое пользователю нельзя, а воспроизвести —
/// через раз, что хуже всего.
///
/// Одна очередь даёт то, чего клиент и ожидает: **что позвал раньше, то
/// и выполнится раньше** (в пределах одной ручки — `tokio::mpsc` хранит
/// порядок для каждого отправителя).
///
/// Разделение [`Command`] и [`Query`] **типами** при этом остаётся, и оно
/// важнее общей очереди: команда меняет состояние и наблюдается событиями,
/// а запрос ничего не меняет и обязан вернуть ответ. Смешать их значило бы
/// завести команду, у которой есть результат, — и первый же клиент начал бы
/// строить на нём логику, которой по §13.3 быть не должно.
enum Request {
    /// Изменить состояние.
    Command(Command),
    /// Прочитать состояние.
    Query(Query),
}

/// Сообщение вместе с тем, что к нему прилипло.
///
/// Реакции читаются здесь, а не отдельным запросом на каждое сообщение:
/// клиент рисует их в том же списке, а сотня запросов на экран чата — сотня
/// проходов через границу §13.3 ради строки в тридцать байт.
#[derive(Debug, Clone)]
pub struct MessageView {
    /// Само сообщение.
    pub message: StoredMessage,
    /// Реакции — только те, что есть: снятые хранилище не отдаёт.
    pub reactions: Vec<StoredReaction>,
}

/// Запрос на чтение состояния.
enum Query {
    /// Окно сообщений чата в порядке HLC (§9.1).
    Messages { chat: ChatId, limit: usize, reply: oneshot::Sender<Vec<MessageView>> },
    /// Окно **перед** названным сообщением — листание назад.
    ///
    /// Якорем служит `msg_id`, а не метка HLC, и это не удобство: метка —
    /// протокольная величина (§9.1), и выдав её наружу, мы отдали бы клиенту
    /// возможность строить на ней порядок. Свой якорь он и так знает — это
    /// сообщение, которое он видит первым в списке.
    MessagesBefore {
        chat: ChatId,
        before: MsgId,
        limit: usize,
        reply: oneshot::Sender<Vec<MessageView>>,
    },
    /// Одно сообщение по идентификатору.
    ///
    /// Нужно ради цитат: ответ несёт ссылку, а не текст (`proto::reply`),
    /// и цитируемое сообщение может лежать далеко за пределами загруженного
    /// окна. `None` — его нет: удалено, не дошло или вычищено уборкой (§12).
    Message { msg_id: MsgId, reply: oneshot::Sender<Option<MessageView>> },
    /// Что известно о контактах прямо сейчас.
    Contacts { reply: oneshot::Sender<Vec<ContactStatus>> },
    /// Байты аватарки: свои (`None`) или контакта (`Some`).
    ///
    /// Отдельным запросом, а не полем в [`ContactStatus`]: до тридцати двух
    /// килобайт на контакт, и тащить их в каждый показ списка чатов незачем.
    /// Клиент берёт байты, когда дошёл до отрисовки, и обновляет по событию
    /// [`Event::AvatarChanged`].
    Avatar { owner: Option<[u8; 32]>, reply: oneshot::Sender<Option<Vec<u8>>> },
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
    /// Как контакт подписан у пользователя. По проводу не едет никогда.
    pub local_name: Option<String>,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Чем до него можно достучаться (§5.4).
    pub availability: PeerAvailability,
    /// Есть ли у него аватарка, которую **можно показать**.
    ///
    /// Учитывает §4.2: у несверенного контакта аватарка может лежать
    /// в хранилище, но здесь всё равно будет `false` — показывать её нельзя,
    /// а обещать клиенту картинку, которой он не получит, незачем.
    pub has_avatar: bool,
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
    requests: mpsc::Sender<Request>,
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
        self.requests.send(Request::Command(command)).await.map_err(|e| match e.0 {
            Request::Command(command) => command,
            Request::Query(_) => unreachable!("послали команду — вернулась не она"),
        })
    }

    /// Читает последние сообщения чата. `None` — драйвер остановлен.
    pub async fn messages(&self, chat: ChatId, limit: usize) -> Option<Vec<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Query(Query::Messages { chat, limit, reply })).await.ok()?;
        answer.await.ok()
    }

    /// Читает список контактов вместе с их доступностью. `None` — драйвер
    /// остановлен.
    pub async fn contacts(&self) -> Option<Vec<ContactStatus>> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Query(Query::Contacts { reply })).await.ok()?;
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
        self.requests.blocking_send(Request::Command(command)).map_err(|e| match e.0 {
            Request::Command(command) => command,
            Request::Query(_) => unreachable!("послали команду — вернулась не она"),
        })
    }

    /// Читает сообщения, блокируя вызывающий поток.
    pub fn messages_blocking(&self, chat: ChatId, limit: usize) -> Option<Vec<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::Messages { chat, limit, reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает окно перед названным сообщением — листание назад.
    pub fn messages_before_blocking(
        &self,
        chat: ChatId,
        before: MsgId,
        limit: usize,
    ) -> Option<Vec<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .blocking_send(Request::Query(Query::MessagesBefore { chat, before, limit, reply }))
            .ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает одно сообщение по идентификатору.
    ///
    /// Внешний `None` означает «драйвер остановлен», внутренний — «такого
    /// сообщения нет».
    pub fn message_blocking(&self, msg_id: MsgId) -> Option<Option<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::Message { msg_id, reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает контакты, блокируя вызывающий поток.
    pub fn contacts_blocking(&self) -> Option<Vec<ContactStatus>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::Contacts { reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает аватарку, блокируя вызывающий поток.
    ///
    /// `owner` — `None` для своей. Внешний `None` означает «драйвер
    /// остановлен», внутренний — «аватарки нет или показывать её нельзя».
    pub fn avatar_blocking(&self, owner: Option<[u8; 32]>) -> Option<Option<Vec<u8>>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::Avatar { owner, reply })).ok()?;
        answer.blocking_recv().ok()
    }
}

/// Гоняет ядро поверх настоящего ввода-вывода.
pub struct Driver<S: Store, R: Runner> {
    engine: Engine<S>,
    runner: R,
    requests: mpsc::Receiver<Request>,
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
        let (requests_tx, requests_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (notices_tx, notices_rx) = mpsc::channel(CHANNEL_DEPTH);
        let driver = Driver {
            engine,
            runner,
            requests: requests_rx,
            notices: notices_tx,
            timers: BTreeMap::new(),
        };
        let handle = DriverHandle { requests: requests_tx };
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
            // Оба ожидания — `recv` по каналу, то есть отменяемы без потери
            // сообщения. Иначе `select!` терял бы вход при каждом
            // срабатывании таймера.
            //
            // Команды и запросы идут одной очередью, поэтому порядок между
            // ними сохраняется: чтение, отправленное после записи, не может
            // обогнать её. Событиям транспорта такой гарантии не нужно и не
            // может быть — они приходят снаружи.
            let wake = tokio::select! {
                event = self.runner.next_event() => match event {
                    Some(event) => Wake::Input(translate(event)),
                    None => Wake::Stop,
                },
                request = self.requests.recv() => match request {
                    Some(Request::Command(command)) => Wake::Input(Input::Command(command)),
                    Some(Request::Query(query)) => Wake::Query(query),
                    None => Wake::Stop,
                },
                () = sleep_until(deadline) => Wake::Timers,
            };

            match wake {
                Wake::Input(input) => self.tolerate(input).await?,
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
                // Отправитель мог уйти, не дождавшись: это не ошибка.
                let _ = reply.send(self.window(&chat, limit, None));
            }
            Query::MessagesBefore { chat, before, limit, reply } => {
                // Якоря может уже не быть — например, его удалили. Тогда
                // листать не от чего, и честный ответ пустой: отдав вместо
                // него последние сообщения, мы показали бы человеку конец
                // переписки там, где он листал её начало.
                let anchor = self.engine.store().message(&before).ok().flatten();
                let found = match anchor {
                    Some(message) => self.window(&chat, limit, Some(message.hlc)),
                    None => Vec::new(),
                };
                let _ = reply.send(found);
            }
            Query::Message { msg_id, reply } => {
                let store = self.engine.store();
                let found = store.message(&msg_id).ok().flatten().map(|message| {
                    let reactions = store.reactions(&message.msg_id).unwrap_or_default();
                    MessageView { message, reactions }
                });
                let _ = reply.send(found);
            }
            Query::Avatar { owner, reply } => {
                let found = match owner {
                    Some(peer_ik) => self.engine.avatar_of(&peer_ik),
                    None => self.engine.own_avatar(),
                };
                // Ошибка хранилища здесь неотличима от «нет аватарки», и это
                // единственное честное поведение: показать нечего в обоих
                // случаях, а ронять список чатов из-за картинки нельзя.
                let _ = reply.send(found.unwrap_or_default());
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
                        local_name: contact.local_name.clone(),
                        verified: contact.verified,
                        availability: contact.availability,
                        // §4.2: у несверенного показывать нечего, даже если
                        // байты лежат. Правило одно и то же здесь и в
                        // `Engine::avatar_of` — разойдясь, они дали бы кружок
                        // с заглушкой вместо картинки, которая «вот-вот».
                        has_avatar: contact.has_avatar && contact.verified,
                    })
                    .collect();
                let _ = reply.send(found);
            }
        }
    }

    /// Окно сообщений вместе с реакциями.
    ///
    /// Одно место на все три чтения истории: разведённые по веткам, они однажды
    /// разошлись бы в том, отдаются ли реакции.
    fn window(&self, chat: &ChatId, limit: usize, before: Option<Hlc>) -> Vec<MessageView> {
        let store = self.engine.store();
        store
            .messages(chat, limit, before)
            .unwrap_or_default()
            .into_iter()
            .map(|message| {
                // Отказ на реакциях не должен стоить чата: сообщение без
                // реакций читается, реакции без сообщения — нет.
                let reactions = store.reactions(&message.msg_id).unwrap_or_default();
                MessageView { message, reactions }
            })
            .collect()
    }

    /// Подаёт вход ядру и исполняет всё, что оно вернуло.
    async fn feed(&mut self, input: Input) -> Result<(), EngineError> {
        let now_ms = now_ms();
        for effect in self.engine.step(now_ms, input)? {
            self.apply(now_ms, effect).await;
        }
        Ok(())
    }

    /// Подаёт вход и **переживает** его отказ.
    ///
    /// Раньше любой отказ `step` останавливал драйвер, и это была ошибка,
    /// которую видно только на живом клиенте. Отвергнутый вход — это, как
    /// правило, чужая или клиентская ошибка, а не поломка ядра: команда
    /// с устаревшим `chat_id`, картинка не того формата, кадр от собеседника
    /// со сломанной сборкой. Останавливаться на них значит дать любому
    /// контакту выключить мессенджер одним негодным сообщением, а клиенту —
    /// одной опечаткой в идентификаторе.
    ///
    /// Отказ хранилища остаётся смертельным, и это не исключение из правила,
    /// а его продолжение: без диска ядро не может ни принять сообщение, ни
    /// сохранить сессию, и продолжать работу означало бы делать вид, что всё
    /// в порядке, теряя всё, что придёт дальше (§14).
    async fn tolerate(&mut self, input: Input) -> Result<(), EngineError> {
        match self.feed(input).await {
            Ok(()) => Ok(()),
            Err(error @ EngineError::Store(_)) => Err(error),
            Err(error) => {
                tracing::warn!(%error, "вход отвергнут ядром");
                Ok(())
            }
        }
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
            self.tolerate(Input::Timer { token }).await?;
        }
        Ok(())
    }

    async fn apply(&mut self, now_ms: u64, effect: Effect) {
        let command = match effect {
            Effect::Send { peer_ik, via, frame } => {
                Some(TransportCommand::Send { peer: self.address_of(peer_ik), via, frame })
            }
            Effect::Connect { peer_ik, via } => {
                Some(TransportCommand::Connect { peer: self.address_of(peer_ik), via })
            }
            Effect::SetLanEnabled(on) => Some(TransportCommand::SetLanEnabled(on)),
            Effect::WatchLanPeers(peers) => Some(TransportCommand::WatchLanPeers(peers)),
            Effect::RestartLan => Some(TransportCommand::RestartLan),
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
