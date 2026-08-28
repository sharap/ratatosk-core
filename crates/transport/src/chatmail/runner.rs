//! Почтовый транспорт (§5.3): ящик, вход на сервер и отправка писем.
//!
//! # Что он уже умеет и чего ещё нет
//!
//! Умеет всё, что нужно ступени §5.4: держать настройки ящика, сходить
//! на chatmail-сервер за новым, войти по SMTP и отправить письмо, войти
//! по IMAP и принять.
//!
//! Задач при этом две, и это не симметрия ради симметрии. Отправка обязана
//! уходить сразу, а приём ждёт часами (`IDLE`); сведи их в одну очередь —
//! ожидание встало бы поперёк писем.
//!
//! # Почему всё живое уехало в задачу
//!
//! `execute` обязан вернуться быстро: он вызывается из цикла драйвера,
//! и всё, что в нём ждёт, останавливает заодно локальную сеть, которая
//! работает уже сейчас. А ждать в почте есть чего: заведение ящика — секунды
//! напрямую и десятки через Tor, вход на сервер — столько же, отправка
//! письма — ещё столько же.
//!
//! Поэтому команда только кладёт работу в очередь, а ответ приезжает
//! событием. Заодно это единственный способ сказать человеку правду
//! о долгом действии: «пошли» и «пришли» — два разных сообщения,
//! и между ними бывает минута.
//!
//! # Одна задача на всю почту, а не по задаче на письмо
//!
//! Соединение с сервером одно, и работать с ним из нескольких задач нельзя:
//! SMTP — диалог, а не набор независимых запросов. Поэтому письма
//! обслуживает **одна** задача, по одному за раз, в порядке очереди.
//!
//! Отсюда же берётся порядок подтверждений: письма уходят тем порядком,
//! каким пришли команды. Ядро на это не полагается — оно сверяет метку
//! (`handoff`), — но знать об этом полезно тому, кто будет читать журнал.
//!
//! Заведение ящика — третье исключение: оно идёт своей задачей, потому что
//! случается до того, как появился ящик, а значит и до того, как есть куда
//! входить.

use ratatosk_proto::mail::{MailAccount, Secret};
use ratatosk_proto::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::chatmail::imap::Receiver;
use crate::chatmail::smtp::Sender;
use crate::chatmail::{http, tls};
use crate::onion::TorHandle;
use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Сколько ждать ответа сервера на просьбу завести ящик.
///
/// Щедро: через Tor сюда входит подъём цепочки, а человек уже нажал и ждёт.
/// Но не бесконечно — молчащий сервер обязан однажды стать внятным отказом,
/// иначе на экране навсегда останется «просьба ушла» (§14).
const REGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Глубина очереди событий.
const EVENTS: usize = 32;

/// Глубина очереди исходящих писем.
///
/// Шестьдесят четыре письма в очереди означают, что задача стоит не минуту
/// и не две. Переполнение обрабатывается как затор, а не как отказ (см.
/// [`TransportError::Busy`]): ступень при заторе не сжигается, а срок
/// на передачу (5аа) всё равно доведёт дело до внятного исхода.
const OUTGOING: usize = 64;

/// Через сколько повторять неудавшийся вход на сервер.
///
/// Без повтора провалившийся вход означал бы почту, выключенную до тех пор,
/// пока человек сам чего-нибудь не нажмёт, — а он не обязан догадываться,
/// что именно. Сервер же чаще всего лежит минуту, а не навсегда.
///
/// Минута — не выбор из тонких соображений: чаще незачем (почта асинхронна
/// по устройству, лишняя минута в ней не видна), реже — значит человек
/// успеет решить, что сломано насовсем. Срок заводится **только** пока есть
/// что повторять; когда почта работает, задача просто спит на очереди.
const LOGIN_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// Через сколько поднимать приём заново после обрыва.
///
/// Тот же смысл и почти то же число, что у [`LOGIN_RETRY`], но константа
/// своя: сроки эти живут в разных задачах и однажды разойдутся по делу —
/// у приёма соединение долгоживущее, и слишком частые попытки его поднять
/// на телефоне заметнее.
const RECEIVE_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// Работа для почтовой задачи.
///
/// Три вида, и каждый меняет состояние соединения: настройки — заново
/// входить, выключатель — гасить, письмо — открыть, если погасло.
enum Job {
    /// Настройки ящика сменились (или ящик убрали).
    ///
    /// В коробке, потому что `MailAccount` заметно больше остальных
    /// вариантов, и без неё вся очередь состояла бы из ячеек его размера.
    Account(Box<Option<MailAccount>>),
    /// Человек включил или выключил почту (§5.4).
    Enabled(bool),
    /// Отправить письмо.
    Letter {
        /// Кому — для события о передаче; сам адрес в `to`.
        peer_ik: [u8; 32],
        /// Почтовый адрес получателя.
        to: String,
        /// Готовое письмо целиком.
        body: String,
        /// Метка, которую вернуть, когда сервер письмо примет.
        handoff: Option<u64>,
    },
}

/// Почтовый транспорт.
pub struct MailRunner {
    events_tx: mpsc::Sender<TransportEvent>,
    events_rx: mpsc::Receiver<TransportEvent>,
    /// Настройки ящика, если он заведён. Приходят из ядра командой.
    account: Option<MailAccount>,
    /// Общий Tor-клиент — не свой (см. [`TorHandle`]).
    tor: TorHandle,
    /// Задачи, которые надо снять вместе с раннером.
    ///
    /// Иначе поход за ящиком пережил бы выключение почты и объявил бы
    /// результат в мёртвый канал — либо, что хуже, завёл бы ящик, о котором
    /// человек уже передумал.
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Очередь к почтовой задаче. Заводится при первой команде.
    ///
    /// Не в конструкторе, и это не лень: `tokio::spawn` требует рантайма,
    /// а раннер собирают там, где его может ещё не быть. Команды же всегда
    /// приходят из цикла драйвера, то есть изнутри рантайма.
    jobs: Option<mpsc::Sender<Job>>,
}

impl Drop for MailRunner {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl std::fmt::Debug for MailRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Настройки не печатаются даже своим `Debug`: в журнале от них
        // пользы нет, а пароль лишний раз ходить по коду не должен.
        f.debug_struct("MailRunner")
            .field("ящик", &self.account.is_some())
            .field("tor", &self.tor)
            .finish()
    }
}

impl MailRunner {
    /// Заводит раннер. Сети при этом не касается.
    #[must_use]
    pub fn new(tor: TorHandle) -> MailRunner {
        let (events_tx, events_rx) = mpsc::channel(EVENTS);
        MailRunner { events_tx, events_rx, account: None, tor, tasks: Vec::new(), jobs: None }
    }

    /// Заведён ли ящик — для показа человеку.
    #[must_use]
    pub fn has_account(&self) -> bool {
        self.account.is_some()
    }

    /// Очередь к почтовой задаче, поднимая её при первой надобности.
    fn jobs(&mut self) -> mpsc::Sender<Job> {
        if self.jobs.is_none() {
            let (tx, rx) = mpsc::channel(OUTGOING);
            let events = self.events_tx.clone();
            let tor = self.tor.clone();
            self.tasks.retain(|task| !task.is_finished());
            self.tasks.push(tokio::spawn(serve(rx, events, tor)));
            self.jobs = Some(tx);
        }
        self.jobs.clone().expect("очередь только что заведена")
    }

    /// Запускает поход за новым ящиком.
    ///
    /// Отказы **не** возвращаются вызывающему: он давно ушёл. Всё, что
    /// случится дальше, уезжает событием — и успех, и любая беда.
    fn start_registration(&mut self, url: String, via_tor: bool) {
        let events = self.events_tx.clone();
        let tor = self.tor.clone();
        self.tasks.retain(|task| !task.is_finished());
        self.tasks.push(tokio::spawn(async move {
            let outcome = tokio::time::timeout(REGISTER_TIMEOUT, register(&url, via_tor, &tor));
            let event = match outcome.await {
                Ok(Ok((address, password))) => {
                    TransportEvent::MailAccountCreated { address, password: Secret::new(password) }
                }
                Ok(Err(reason)) => TransportEvent::MailAccountFailed { reason },
                Err(_) => TransportEvent::MailAccountFailed {
                    reason: "сервер не ответил за отведённое время".to_owned(),
                },
            };
            if events.send(event).await.is_err() {
                tracing::debug!("почта: некому сказать об исходе регистрации");
            }
        }));
    }
}

/// Почтовая задача: одна на весь транспорт, по одному делу за раз.
async fn serve(
    mut jobs: mpsc::Receiver<Job>,
    events: mpsc::Sender<TransportEvent>,
    tor: TorHandle,
) {
    let mut account: Option<MailAccount> = None;
    // Начинаем с «включена»: первым делом ядро объявляет положение всех
    // переключателей (`startup_effects`), и правда приедет раньше, чем
    // появится первое письмо.
    let mut enabled = true;
    let mut sender: Option<Sender> = None;
    // Пожаловались ли уже на неудавшийся вход.
    //
    // Без этого повторные попытки заваливали бы человека одной и той же
    // строкой раз в минуту, пока лежит сервер. Сказать надо один раз —
    // и ещё раз, если после успеха всё сломается снова.
    let mut complained = false;
    // Приём живёт своей задачей: `IDLE` ждёт часами, а отправка обязана
    // уходить сразу. Одной очередью их не свести — ожидание встало бы
    // поперёк писем.
    let mut receiving: Option<Task> = None;

    loop {
        // Срок заводится только тогда, когда есть что повторять: войти
        // не удалось, но ящик есть и почта включена. Во всех остальных
        // случаях задача просто спит на очереди и не будит ничего (§13.1).
        let retrying = sender.is_none() && enabled && account.is_some();
        let job = if retrying {
            match tokio::time::timeout(LOGIN_RETRY, jobs.recv()).await {
                Ok(Some(job)) => job,
                Ok(None) => return,
                Err(_) => {
                    // Сервер мог лежать минуту, а не навсегда. Пока никто
                    // не повторяет вход, почта остаётся выключенной до тех
                    // пор, пока человек сам чего-нибудь не нажмёт, — а он
                    // не обязан догадываться, что нажимать.
                    sender = open(&account, enabled, &tor, &events, &mut complained).await;
                    continue;
                }
            }
        } else {
            match jobs.recv().await {
                Some(job) => job,
                None => return,
            }
        };

        match job {
            Job::Account(next) => {
                // Прежнее соединение больше не наше: оно открыто под другим
                // ящиком, и отправить из него письмо от нового отправителя
                // сервер всё равно не даст.
                drop(sender.take());
                account = *next;
                complained = false;
                sender = open(&account, enabled, &tor, &events, &mut complained).await;
                restart_receiving(&mut receiving, &account, enabled, &tor, &events);
            }
            Job::Enabled(on) => {
                if on == enabled {
                    continue;
                }
                enabled = on;
                if enabled {
                    complained = false;
                    sender = open(&account, enabled, &tor, &events, &mut complained).await;
                } else {
                    // Выключить почту значит закрыть **оба** соединения,
                    // а не просто выпасть из лестницы §5.4. Иначе выключатель
                    // оставлял бы открытым канал до сервера — то самое
                    // «выключено, а всё ещё работает», которое §14 запрещает
                    // показывать. Для приёма это ещё заметнее: `IDLE` держит
                    // соединение сутками.
                    sender = None;
                }
                restart_receiving(&mut receiving, &account, enabled, &tor, &events);
            }
            Job::Letter { peer_ik, to, body, handoff } => {
                let sent = deliver(&mut sender, &account, enabled, &tor, &events, &to, &body).await;
                let event = match sent {
                    Ok(()) => match handoff {
                        Some(handoff) => {
                            TransportEvent::Handed { peer_ik, via: Transport::Mail, handoff }
                        }
                        // Подтверждения никто не ждёт — квитанции, карточки,
                        // ответы рукопожатия. Молчание здесь правильно.
                        None => continue,
                    },
                    Err(error) => {
                        // Отказ, а не молчание: §5.4 обязан узнать, что
                        // ступень не сработала. Причина уходит в журнал —
                        // человеку её показывать нечем: это сообщение,
                        // а не действие, которое он только что совершил.
                        tracing::debug!(%error, "почта: письмо не ушло");
                        TransportEvent::ConnectFailed { peer_ik, via: Transport::Mail }
                    }
                };
                if events.send(event).await.is_err() {
                    tracing::debug!("почта: некому сказать об исходе отправки");
                    return;
                }
            }
        }
    }
}

/// Задача, снимаемая вместе с тем, кто её держит.
///
/// Нужен потому, что снятие задачи **не** снимает её потомков: оборви
/// мы почтовую задачу, приём остался бы жить со своим соединением IMAP,
/// открытым к серверу навсегда. Сторож в переменной решает это тем, что
/// снятие задачи роняет её локальные переменные — включая этот сторож.
struct Task(tokio::task::JoinHandle<()>);

impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Поднимает задачу приёма заново — или снимает её.
///
/// Заново, а не «поправить на ходу»: у приёма своё соединение, свой ящик
/// и своё долгое ожидание, и менять под ним настройки посреди `IDLE` нечем.
/// Уронить и поднять дешевле и, главное, честнее — второго состояния,
/// в котором задача работает со старым ящиком, просто не бывает.
fn restart_receiving(
    receiving: &mut Option<Task>,
    account: &Option<MailAccount>,
    enabled: bool,
    tor: &TorHandle,
    events: &mpsc::Sender<TransportEvent>,
) {
    // Присваивание роняет прежний сторож, а тот снимает прежнюю задачу.
    *receiving = None;
    if !enabled {
        return;
    }
    let Some(account) = account.clone() else {
        return;
    };
    *receiving = Some(Task(tokio::spawn(receive(account, tor.clone(), events.clone()))));
}

/// Спрашивает квоту и уводит её событием, если сервер её назвал.
///
/// Молчание — законный ответ: сервер может не уметь `QUOTA` или объявить
/// ящик безлимитным. Событие тогда не уезжает вовсе, и ядро остаётся
/// с «объём неизвестен» — а это не то же, что «места нет».
async fn report_quota(receiver: &mut Receiver, events: &mpsc::Sender<TransportEvent>) {
    if let Some((used_bytes, limit_bytes)) = receiver.mailbox_quota().await {
        let _ = events.send(TransportEvent::MailQuota { used_bytes, limit_bytes }).await;
    }
}

/// Задача приёма: держит соединение и отдаёт кадры, пока её не снимут.
///
/// Ошибки лечит одним способом — новым соединением. Разбирать их по видам
/// смысла нет: и разорванная связь, и уснувший сервер, и отказ `IDLE`
/// означают ровно одно — прежнее соединение больше не годится.
async fn receive(account: MailAccount, tor: TorHandle, events: mpsc::Sender<TransportEvent>) {
    let mut complained = false;
    loop {
        let mut receiver = match Receiver::login(&account, &tor).await {
            Ok(receiver) => {
                complained = false;
                receiver
            }
            Err(error) => {
                // Отдельной строкой от отправки, и не для порядка: почта,
                // которая шлёт, но не принимает, снаружи выглядит как
                // молчащий собеседник. Такое человек читает как «он мне
                // не отвечает», а не как «у меня не работает приём».
                if !complained {
                    complained = true;
                    let reason = format!("письма отправляются, но не приходят: {error}");
                    let _ = events.send(TransportEvent::MailLoginFailed { reason }).await;
                }
                tokio::time::sleep(RECEIVE_RETRY).await;
                continue;
            }
        };

        // Квота — сразу после входа: числа нужны ядру до того, как оно
        // решит просить чанки файла почтой, а не после первого отказа.
        report_quota(&mut receiver, &events).await;

        loop {
            if let Err(error) = receiver.take(&events).await {
                tracing::debug!(%error, "почта: приём оборвался — переподключаемся");
                break;
            }
            // И после каждой разборки: числа меняются от того, что мы сами
            // из ящика вычищаем, и застывшая цифра врала бы ровно в ту
            // сторону, в какую хуже, — «места нет», когда оно есть.
            report_quota(&mut receiver, &events).await;
            match receiver.wait_for_news().await {
                Ok(next) => receiver = next,
                Err(error) => {
                    tracing::debug!(%error, "почта: ожидание оборвалось — переподключаемся");
                    break;
                }
            }
        }
        tokio::time::sleep(RECEIVE_RETRY).await;
    }
}

/// Входит на сервер, если есть куда и разрешено.
///
/// Событие о готовности уходит отсюда: §5.4 начинает выбирать почту ровно
/// с этого мгновения, и раньше входа объявлять её работающей нельзя.
///
/// `complained` не даёт повторным попыткам превратить одну неисправность
/// в поток одинаковых строк. Сказать надо один раз — и ещё раз, если после
/// удачного входа всё сломается снова.
async fn open(
    account: &Option<MailAccount>,
    enabled: bool,
    tor: &TorHandle,
    events: &mpsc::Sender<TransportEvent>,
    complained: &mut bool,
) -> Option<Sender> {
    let account = account.as_ref()?;
    if !enabled {
        return None;
    }
    match Sender::login(account, tor).await {
        Ok(open) => {
            *complained = false;
            let _ = events.send(TransportEvent::Ready { transport: Transport::Mail }).await;
            // Предел письма — сразу за готовностью: от него зависит, поедут
            // ли почтой файлы (§10.3), и узнать это ядро должно до первой
            // попытки, а не отказом на первом чанке.
            let _ = events
                .send(TransportEvent::MailLetterLimit { bytes: open.max_letter_bytes() })
                .await;
            Some(open)
        }
        Err(error) => {
            if !*complained {
                *complained = true;
                let _ = events
                    .send(TransportEvent::MailLoginFailed { reason: error.to_string() })
                    .await;
            }
            None
        }
    }
}

/// Отправляет письмо, переоткрывая соединение, если прежнее умерло.
///
/// Ровно одна повторная попытка. Почтовые серверы закрывают простаивающие
/// соединения через минуты — это штатное поведение, а не отказ, и платить
/// за него потерянным сообщением нельзя. Но если не вышло и на свежем
/// соединении, дело не в простое, и §5.4 обязан узнать об этом сейчас.
async fn deliver(
    sender: &mut Option<Sender>,
    account: &Option<MailAccount>,
    enabled: bool,
    tor: &TorHandle,
    events: &mpsc::Sender<TransportEvent>,
    to: &str,
    body: &str,
) -> Result<(), TransportError> {
    let Some(account) = account.as_ref() else {
        return Err(TransportError::Unavailable);
    };
    if !enabled {
        return Err(TransportError::Unavailable);
    }

    if let Some(open) = sender.as_mut() {
        match open.send(&account.address, to, body).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::debug!(%error, "почта: соединение не сработало — открываем заново");
                *sender = None;
            }
        }
    }

    let mut fresh = Sender::login(account, tor).await?;
    // Готовность объявляется и отсюда: соединение могло умереть после
    // выключения экрана, а ядро всё это время считало ступень рабочей.
    // Повтор для него бесплатен — уже готовый транспорт вход игнорирует.
    let _ = events.send(TransportEvent::Ready { transport: Transport::Mail }).await;
    let _ = events.send(TransportEvent::MailLetterLimit { bytes: fresh.max_letter_bytes() }).await;
    fresh.send(&account.address, to, body).await?;
    *sender = Some(fresh);
    Ok(())
}

/// Сходить на сервер и принести адрес с паролем.
///
/// Причина отказа — строкой, а не типом: она едет прямиком человеку,
/// и разбирать её по дороге некому и незачем.
async fn register(url: &str, via_tor: bool, tor: &TorHandle) -> Result<(String, String), String> {
    let target = ratatosk_proto::mail::AccountUrl::parse(url).map_err(|error| error.to_string())?;

    let mut stream = tls::connect(&target.host, target.port, via_tor, tor)
        .await
        .map_err(|error| error.to_string())?;

    let request = http::request(&target.host, &target.path);
    stream.write_all(request.as_bytes()).await.map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;

    // До конца потока: мы просили `Connection: close`, и это законный
    // признак конца ответа. Предел — чтобы страница на мегабайт вместо
    // JSON не съела память: разбирать в ней всё равно нечего.
    let mut answer = Vec::new();
    let mut limited = stream.take(http::MAX_RESPONSE_BYTES as u64);
    limited.read_to_end(&mut answer).await.map_err(|error| error.to_string())?;

    http::credentials(&answer).map_err(|error| error.to_string())
}

impl Runner for MailRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            TransportCommand::SetMailAccount(account) => {
                self.account = account.clone();
                let jobs = self.jobs();
                // `try_send`, а не `send`: ждать места в очереди значило бы
                // остановить цикл драйвера, а очередь пуста ровно тогда,
                // когда почта работает. Потерять настройки при переполнении
                // не страшно — они приедут снова при следующей смене
                // и при следующем запуске (`startup_effects`).
                let _ = jobs.try_send(Job::Account(Box::new(account)));
                Ok(())
            }
            TransportCommand::CreateMailAccount { url, via_tor } => {
                // Отказать сразу, если ясно, что не выйдет: человек ждёт
                // ответа, и минута тишины перед «Tor не поднялся» —
                // это минута, отнятая ни за что.
                if via_tor && !self.tor.is_up() {
                    return Err(TransportError::Refused(
                        "Tor ещё не поднялся — подождите или снимите галочку".to_owned(),
                    ));
                }
                self.start_registration(url, via_tor);
                Ok(())
            }
            // Разъединение приходит всем сразу. Соединение у почты есть,
            // но оно **до сервера**, а не до собеседника: закрывать его
            // потому, что один контакт стал недостижим, не за что.
            TransportCommand::Disconnect { .. } => Ok(()),
            TransportCommand::SetEnabled { transport: Transport::Mail, enabled } => {
                let jobs = self.jobs();
                let _ = jobs.try_send(Job::Enabled(enabled));
                Ok(())
            }
            TransportCommand::Send { peer, via: Transport::Mail, frame, handoff } => {
                let Some(account) = self.account.clone() else {
                    // Ящика нет — писать не от кого. Это не поломка,
                    // а состав: §5.4 узнает и пойдёт дальше.
                    return Err(TransportError::Unavailable);
                };
                let Some(to) = peer.chatmail.clone() else {
                    return Err(TransportError::NoAddress);
                };
                // Письмо собирается **здесь**, а не в задаче, и по делу:
                // здесь ещё можно отказать вызывающему сразу, а из задачи
                // отказ поехал бы событием и стоил бы лишнего круга.
                let body = crate::chatmail::build_message(&account.address, &to, &[frame])
                    .map_err(|error| {
                        TransportError::Refused(format!("письмо не собралось: {error}"))
                    })?;
                let jobs = self.jobs();
                jobs.try_send(Job::Letter { peer_ik: peer.ik, to, body, handoff })
                    // Затор, а не отказ: ступень при этом не сжигается
                    // (§5.4 не меняет транспорт на `Busy`), а срок
                    // на передачу доведёт дело до внятного исхода.
                    .map_err(|_| TransportError::Busy)?;
                Ok(())
            }
            // Всё прочее — не наше: чужие транспорты, настройки LAN.
            _ => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        self.events_rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(chatmail: Option<&str>) -> crate::runner::PeerAddress {
        crate::runner::PeerAddress {
            ik: [1u8; 32],
            onion: None,
            chatmail: chatmail.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn a_mailbox_over_tor_is_refused_before_the_wait_begins() {
        // Человек ждёт ответа. Минута тишины перед «Tor не поднялся» —
        // это минута, отнятая ни за что.
        let mut runner = MailRunner::new(TorHandle::default());
        let refusal = runner
            .execute(TransportCommand::CreateMailAccount {
                url: "https://chatmail.example/new".to_owned(),
                via_tor: true,
            })
            .await;
        assert!(matches!(refusal, Err(TransportError::Refused(_))), "ждали внятного отказа");
    }

    #[tokio::test]
    async fn settings_are_remembered_and_forgotten_on_command() {
        let mut runner = MailRunner::new(TorHandle::default());
        assert!(!runner.has_account(), "из коробки ящика нет");

        let account = MailAccount::from_address("a@nine.example", "sekret");
        runner.execute(TransportCommand::SetMailAccount(Some(account))).await.unwrap();
        assert!(runner.has_account());

        runner.execute(TransportCommand::SetMailAccount(None)).await.unwrap();
        assert!(!runner.has_account(), "убранный ящик обязан забыться");
    }

    #[tokio::test]
    async fn sending_without_a_mailbox_is_refused_rather_than_queued() {
        // Ящика нет — писать не от кого, и держать письмо в очереди значило
        // бы ждать срока передачи впустую. §5.4 узнаёт сразу.
        let mut runner = MailRunner::new(TorHandle::default());
        let verdict = runner
            .execute(TransportCommand::Send {
                peer: peer(Some("b@nine.example")),
                via: Transport::Mail,
                frame: vec![0u8; 16],
                handoff: Some(7),
            })
            .await;
        assert!(matches!(verdict, Err(TransportError::Unavailable)));
    }

    #[tokio::test]
    async fn a_peer_without_an_address_is_refused_by_name() {
        // Отдельно от «ящика нет»: чинится это не тем же самым. Свой ящик
        // заводит человек, чужой адрес приезжает обновлением карточки (§4.3).
        let mut runner = MailRunner::new(TorHandle::default());
        let account = MailAccount::from_address("a@nine.example", "sekret");
        runner.execute(TransportCommand::SetMailAccount(Some(account))).await.unwrap();

        let verdict = runner
            .execute(TransportCommand::Send {
                peer: peer(None),
                via: Transport::Mail,
                frame: vec![0u8; 16],
                handoff: Some(7),
            })
            .await;
        assert!(matches!(verdict, Err(TransportError::NoAddress)));
    }

    #[tokio::test]
    async fn foreign_commands_are_not_ours() {
        let mut runner = MailRunner::new(TorHandle::default());
        // Разъединение приходит всем сразу и почты не касается: её соединение
        // — до сервера, а не до собеседника, и закрывать его потому, что один
        // контакт стал недостижим, не за что.
        runner.execute(TransportCommand::Disconnect { peer: peer(None) }).await.unwrap();

        // А выключатель чужого транспорта — не наше дело вовсе.
        let verdict = runner
            .execute(TransportCommand::SetEnabled { transport: Transport::Lan, enabled: true })
            .await;
        assert!(matches!(verdict, Err(TransportError::Unavailable)));
    }
}
