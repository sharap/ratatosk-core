//! Ступень nostr: события на реле (0.3).
//!
//! Пятая ступень §5.4. Разбор того, зачем она и чего стоит, — в
//! `ratatosk_proto::nostr` и в `ARCHITECTURE.md`, 5ге; здесь только
//! ввод-вывод.
//!
//! # Как это устроено
//!
//! Три уровня, и разделены они по тому, что каждый умеет ждать.
//!
//! * [`NostrRunner`] отвечает ядру **мгновенно**: кладёт работу в очередь
//!   и возвращается. Ждать сети ему нельзя — `Driver::apply` дожидается
//!   каждой команды в теле своего цикла (см. заголовок [`Runner`]).
//! * `serve` — одна задача на всю ступень. Держит ключ, список реле,
//!   сборщик частей и учёт отправок. Сети тоже не касается.
//! * `serve_relay` — по задаче на реле. Вот она и ждёт: соединение через
//!   Tor, TLS, рукопожатие веб-сокета, подписка, и дальше насос в обе
//!   стороны до обрыва.
//!
//! Разделение не ради слоёв: реле у человека несколько, они отваливаются
//! и возвращаются поодиночке, и одна задача на всех означала бы, что
//! молчащее реле держит остальные.
//!
//! # Tor по умолчанию, но не всегда
//!
//! Ключ nostr долговечен, и связанный с адресом устройства однажды он связан
//! с ним навсегда. Поэтому путь до реле открывается через Tor — [`tls::dial`]
//! зовётся с `via_tor` из настройки, а настройка по умолчанию истинна.
//!
//! Выключается она там, где Tor недоступен физически: ступень, которая
//! в таком месте просто не работает, — это не забота о приватности, это
//! отсутствие связи. Ровно тот же размен и ровно та же формулировка уже
//! стоят у почты (`ratatosk_proto::mail`); заводить второе правило на тот
//! же вопрос незачем.
//!
//! Следствие названо прямо: с `via_tor` и **без** признака сборки
//! `onion-arti` ступень не работает вовсе и честно отказывает.
//!
//! Открытый `ws://` при этом не принимается никуда, кроме себя самого:
//! разбор адреса живёт в `ratatosk_proto::nostr::relay_target`, и там же
//! объяснено, почему.
//!
//! # Свои реле и чужие
//!
//! Реле — не адрес собеседника, а **место встречи**, и пока место выбирал
//! каждый сам, встречи могло не быть вовсе: двое с непересекающимися списками
//! кладут события каждый к себе и ждут друг друга вечно. Дыра была названа
//! с самого начала и закрыта так (NIP-65 в нашем виде): карточка везёт до трёх
//! реле, с которых её владелец **читает**, и отправитель кладёт событие
//! туда — а не к себе.
//!
//! Отсюда два вида связей, и различие между ними существенное:
//!
//! * **своё** реле — подписка и чтение. Их состав видит человек, и по ним же
//!   считается готовность ступени;
//! * **чужое** реле — только запись. Подписки там нет нарочно: подписаться
//!   значило бы сказать постороннему реле «этот ключ здесь читает», то есть
//!   дорисовать ребро графа на ровном месте. По той же причине чужие реле
//!   не попадают ни в состав на экране, ни в готовность: живое реле
//!   собеседника не означает, что до **нас** кто-то дозовётся.
//!
//! Чужих связей столько, сколько собеседников, поэтому их число ограничено
//! сверху и лишние вытесняются по давности (`MAX_PEER_LINKS`). Карточка
//! без реле — не отказ: событие кладётся на свои, и это в точности прежнее
//! поведение, то есть расчёт на общее реле.
//!
//! # Что здесь разбирается, а что собирается
//!
//! Собирается всё в `ratatosk_proto::nostr` — идентификатор события
//! считается от строки, собранной до знака, и второй сборки быть не должно.
//! Разбирается — здесь, через `serde_json`: чужой JSON, разобранный
//! по догадке, молча покажет не то, и этот урок уже оплачен составом пиров
//! меша.
//!
//! [`Runner`]: crate::runner::Runner
//! [`tls::dial`]: crate::tls::dial

use std::collections::HashMap;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;

use ratatosk_proto::fragment::{self, Accepted, Reassembler};
use ratatosk_proto::nostr::{
    self, Event, NostrKey, NostrRelay, NostrSecret, NostrSetup, PART_BYTES,
};
use ratatosk_proto::transport_policy::Transport;
use ratatosk_wire::SizeClass;

use crate::onion::TorHandle;
use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Глубина очереди событий наверх.
const EVENTS: usize = 64;

/// Глубина очереди работ к задаче ступени.
const JOBS: usize = 64;

/// Глубина очереди к одному реле.
///
/// Небольшая нарочно: реле, которое не принимает, обязано упереться
/// в переполнение и отвалиться, а не копить события в памяти телефона.
const TO_RELAY: usize = 32;

/// Сколько ждать соединения с реле.
///
/// Столько же, сколько onion (§5.4), и по той же причине: под нами цепочка
/// встречи Tor, и меряться надо ею, а не веб-сокетом.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

/// Через сколько пробовать реле заново после обрыва.
///
/// Минута: соединение долгоживущее, и частые попытки его поднять заметны
/// на телефоне батареей. То же число и по той же причине, что у приёма
/// почты.
const RELAY_RETRY: Duration = Duration::from_secs(60);

/// Сколько ждать недостающие части кадра.
///
/// Срок почты, а не прямого канала (§9.3), и это не описка: ступень
/// асинхронна по устройству. Части едут разными событиями, реле отдаёт их
/// когда отдаёт, а собеседник мог положить их и вчера. Десять минут
/// прямого канала выбрасывали бы здесь сборку, которой оставалось дождаться
/// одного события.
const PART_TTL_MS: u64 = fragment::REASSEMBLY_TTL_MAIL_MS;

/// Сколько своих реле поднимать, сколько бы их ни назвали.
///
/// Своё реле — это долгоживущее соединение через Tor, то есть цепочка
/// встречи и батарея телефона. Восемь — заведомо больше, чем нужно (с двух
/// уже нет одной точки отказа), и при этом потолок, а не пожелание: список
/// приезжает из настроек, а настройки заполняет человек.
const MAX_OWN_LINKS: usize = 8;

/// Сколько чужих реле держать одновременно.
///
/// Чужие реле приходят из карточек, и их число растёт с числом собеседников:
/// тридцать контактов по три реле — это девяносто веб-сокетов через Tor
/// на телефоне. Поэтому потолок и вытеснение по давности: переписка идёт
/// с несколькими людьми сразу, а не с тридцатью.
///
/// Вытеснение не теряет сообщений. Связь поднимается заново при первой же
/// отправке — платится она только временем соединения.
const MAX_PEER_LINKS: usize = 8;

/// Насколько отметка досмотренного должна сдвинуться, чтобы сказать ядру.
///
/// Минута. За отметкой стоит запись на диск, а события приходят пачками:
/// без шага обмен из сотни сообщений стоил бы сотни записей. Цена шага
/// известна и мала: перезапуск переспросит у реле последнюю минуту, и
/// дедупликация §9.2 снимет повторы сама.
const SINCE_REPORT_STEP: u64 = 60;

/// Имя подписки.
///
/// Одно на всё соединение и постоянное: подписка у нас ровно одна, а
/// случайное имя добавило бы реле ещё одну строку про нас, ничего не дав.
const SUBSCRIPTION: &str = "rk";

/// Работа для задачи ступени.
enum Job {
    /// Настройка сменилась: ключ, список реле — или ступень выключили.
    ///
    /// В коробке: вариант заметно больше остальных, и без неё вся очередь
    /// состояла бы из ячеек его размера.
    Setup(Box<NostrSetup>),
    /// Человек включил или выключил ступень (§5.4).
    Enabled(bool),
    /// Сеть сменилась.
    ///
    /// Соединения прежней сети мертвы, а сокеты об этом не знают: веб-сокет
    /// держится молча и узнает об обрыве на первой записи, то есть на первом
    /// же сообщении. Поэтому связи сбрасываются, и реле поднимаются заново.
    NetworkChanged,
    /// Отправить кадр.
    Send {
        /// Кому — для событий наверх.
        peer_ik: [u8; 32],
        /// Его ключ nostr: он стоит в событии открыто.
        to: NostrKey,
        /// Реле, объявленные **его** карточкой: где он читает (§4.3).
        ///
        /// Пусто — карточка их не называет (старая или ступень у него
        /// выключена); тогда кладём на свои и надеемся на общее реле.
        relays: Vec<String>,
        /// Готовый кадр целиком; резать его — наше дело.
        frame: Vec<u8>,
        /// Метка, которую вернуть, когда событие примут.
        handoff: Option<u64>,
    },
}

/// Что реле сказало задаче ступени.
#[derive(Debug)]
enum Note {
    /// Соединение установлено и подписка принята.
    Up {
        /// Какое реле.
        url: String,
        /// Своё ли оно. Чужие в состав на экране не идут — см. заголовок.
        own: bool,
    },
    /// Соединения нет — вот почему.
    Down {
        /// Какое реле.
        url: String,
        /// Словами, для показа человеку (§14).
        note: String,
        /// Своё ли оно.
        own: bool,
    },
    /// Пришло событие — вот его содержимое.
    Event {
        /// Содержимое как есть, в base64.
        content: String,
    },
    /// Событие из подписки оказалось вот насколько свежим.
    ///
    /// Отдельно от `Event`, потому что время события нужно **всегда**, даже
    /// когда его содержимое нам не подошло: отметка досмотренного не должна
    /// зависеть от того, собрался ли из части кадр.
    Seen {
        /// Секунды unix.
        created_at: u64,
    },
    /// Реле ответило на наше событие (`OK` в NIP-01).
    Accepted {
        /// Идентификатор события, шестнадцатеричным.
        id: String,
        /// Принято или отвергнуто.
        ok: bool,
    },
}

/// Транспорт поверх реле nostr.
pub struct NostrRunner {
    events_tx: mpsc::Sender<TransportEvent>,
    events_rx: mpsc::Receiver<TransportEvent>,
    /// Общий Tor-клиент — не свой (см. [`TorHandle`]).
    tor: TorHandle,
    /// Задачи, которые снимаются вместе с раннером.
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Очередь к задаче ступени. Заводится при первой команде.
    ///
    /// Не в конструкторе, и это не лень: `tokio::spawn` требует рантайма,
    /// а раннер собирают там, где его может ещё не быть.
    jobs: Option<mpsc::Sender<Job>>,
}

impl Drop for NostrRunner {
    fn drop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl std::fmt::Debug for NostrRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrRunner").field("tor", &self.tor).finish_non_exhaustive()
    }
}

impl NostrRunner {
    /// Заводит раннер. Сети при этом не касается.
    #[must_use]
    pub fn new(tor: TorHandle) -> NostrRunner {
        let (events_tx, events_rx) = mpsc::channel(EVENTS);
        NostrRunner { events_tx, events_rx, tor, tasks: Vec::new(), jobs: None }
    }

    /// Очередь к задаче ступени, поднимая её при первой надобности.
    fn jobs(&mut self) -> mpsc::Sender<Job> {
        if self.jobs.is_none() {
            let (tx, rx) = mpsc::channel(JOBS);
            let events = self.events_tx.clone();
            let tor = self.tor.clone();
            self.tasks.retain(|task| !task.is_finished());
            self.tasks.push(tokio::spawn(serve(rx, events, tor)));
            self.jobs = Some(tx);
        }
        self.jobs.clone().expect("очередь только что заведена")
    }

    /// Кладёт работу, не дожидаясь её исполнения.
    ///
    /// `try_send`, а не `send`: ожидание места в очереди — это ожидание
    /// в теле цикла драйвера, а он отвечает на запросы UI и ведёт таймеры
    /// всех остальных ступеней.
    fn put(&mut self, job: Job) -> Result<(), TransportError> {
        self.jobs().try_send(job).map_err(|_| TransportError::Busy)
    }
}

impl Runner for NostrRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            TransportCommand::Send { peer, via, frame, handoff } => {
                if via != Transport::Nostr {
                    return Err(TransportError::Unavailable);
                }
                // Класс L этой ступенью не ездит вовсе — и отказ обязан быть
                // здесь, до очереди и до подписи.
                //
                // Спецификация (0.3.5) говорит это про чанки файлов, но довод
                // у неё не про файлы, а про размер: мебибайт — это 128 событий
                // по одиннадцать килобайт подряд, и ни одно реле такого
                // не потерпит. Ровно тот же довод целиком относится к очень
                // длинному **тексту**: класс у кадра тот же.
                //
                // Найдено измерением на стенде: `/long 63` доезжает, `/long 64`
                // нет. Граница ровно там, где кончается класс M (65477 байт
                // полезной нагрузки), а не на пределе реле, как казалось.
                if SizeClass::from_frame_len(frame.len()).is_ok_and(|class| class == SizeClass::L) {
                    tracing::info!(
                        кадр = frame.len(),
                        "nostr: класс L этой ступенью не ездит — лестница пойдёт дальше"
                    );
                    return Err(TransportError::Unavailable);
                }
                // Ключа нет — ехать некуда, и сказать об этом надо сразу:
                // §5.4 обязан узнать об отказе и пойти дальше по лестнице.
                let Some(to) = peer.nostr else {
                    return Err(TransportError::NoAddress);
                };
                // Реле собеседника — из его карточки, а не из наших настроек:
                // класть надо туда, где он читает (см. заголовок). Пусто —
                // не отказ: положим на свои.
                self.put(Job::Send {
                    peer_ik: peer.ik,
                    to,
                    relays: peer.nostr_relays,
                    frame,
                    handoff,
                })
            }
            TransportCommand::SetEnabled { transport: Transport::Nostr, enabled } => {
                self.put(Job::Enabled(enabled))
            }
            TransportCommand::SetNostr(setup) => self.put(Job::Setup(Box::new(setup))),
            TransportCommand::NetworkChanged => self.put(Job::NetworkChanged),
            // Соединения с собеседником у этой ступени нет вовсе: событие
            // ложится на реле и живёт само. Рвать нечего, и отказом это
            // не является.
            TransportCommand::Connect { .. } | TransportCommand::Disconnect { .. } => Ok(()),
            TransportCommand::SetEnabled { .. }
            | TransportCommand::WatchPeers(_)
            | TransportCommand::SetYgg(_)
            | TransportCommand::SetMailAccount(_)
            | TransportCommand::CreateMailAccount { .. } => Err(TransportError::Unavailable),
            // Принятых связей у этой ступени нет: отвечать в них нечего.
            TransportCommand::BindLink { .. } => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        self.events_rx.recv().await
    }
}

/// Что мы знаем про отправку одного кадра.
struct Outgoing {
    peer_ik: [u8; 32],
    handoff: Option<u64>,
    /// Сколько частей ещё не принято ни одним реле.
    waiting: usize,
}

/// Что мы знаем про одну часть в полёте.
struct Flying {
    /// К какой отправке относится.
    token: u64,
    /// Сколько реле уже ответило.
    answers: usize,
    /// Сколько реле всего, то есть сколько ответов ждать.
    relays: usize,
}

/// Живая связь с одним реле.
struct Link {
    /// Очередь готовых строк `["EVENT",…]` к нему.
    tx: mpsc::Sender<String>,
    /// Задача, которую снимать вместе со связью.
    task: tokio::task::JoinHandle<()>,
    /// Своё ли это реле: со своего читаем и на своё пишем, на чужое —
    /// только пишем. Разбор различия — в заголовке.
    own: bool,
    /// Отметка последнего обращения — значение [`State::uses`] на тот миг.
    ///
    /// Счётчик, а не часы, и это не мелочь: вытеснение выбирает **самую
    /// давнюю** связь, а две отправки подряд укладываются в одну
    /// миллисекунду. По часам они оказались бы равны, и вытеснялась бы
    /// произвольная из них — то есть, может быть, та, которой только что
    /// пользовались.
    ///
    /// Нужна отметка только чужим: свои не вытесняются никогда.
    used: u64,
}

/// Состояние ступени: всё, что живёт между работами.
struct State {
    key: Option<(NostrKey, NostrSecret)>,
    relays: Vec<String>,
    /// Ходить ли до реле через Tor. Умолчание — да; разбор в заголовке.
    via_tor: bool,
    /// Живые связи по адресу реле.
    ///
    /// По адресу, а не списком, ради единственного свойства: одно реле —
    /// одна связь. Реле собеседника вполне может оказаться нашим же, и две
    /// задачи на один адрес означали бы два соединения, две подписки и два
    /// экземпляра каждого события.
    links: HashMap<String, Link>,
    /// Какие реле отвечают прямо сейчас.
    alive: HashMap<String, NostrRelay>,
    /// Была ли ступень объявлена готовой.
    ready: bool,
    enabled: bool,
    /// Сборка кадров из частей — одна на все реле.
    ///
    /// Одна нарочно: одно и то же событие приезжает с каждого реле,
    /// на которое мы его положили, и общий сборщик снимает эти дубли
    /// сам (`Accepted::Duplicate`). Сборщик на реле каждому собирал бы
    /// один и тот же кадр столько раз, сколько у человека реле.
    parts: Reassembler,
    /// Отправки, ждущие подтверждения.
    outgoing: HashMap<u64, Outgoing>,
    /// Части в полёте, по идентификатору события.
    flying: HashMap<String, Flying>,
    /// Счётчик меток отправок.
    next_token: u64,
    /// Счётчик обращений к связям — из него берутся отметки `Link::used`.
    uses: u64,
    /// До какого времени досмотрены события, секунды unix.
    ///
    /// Приезжает настройкой (то есть с диска) и растёт по мере приёма.
    /// Наверх уходит редко — см. [`SINCE_REPORT_STEP`].
    since: u64,
    /// Какое значение отметки уже сохранено на диске.
    ///
    /// Держится отдельно от `since` затем, что запись на диск стоит дороже
    /// приёма события: без этой пары ядро получало бы новость на **каждое**
    /// принятое событие.
    since_told: u64,
}

impl State {
    fn new() -> State {
        State {
            key: None,
            relays: Vec::new(),
            // Умолчание строгое: ступень без настройки не поднимется вовсе,
            // но если бы поднялась — пусть через Tor.
            via_tor: true,
            links: HashMap::new(),
            alive: HashMap::new(),
            ready: false,
            // Начинаем с «включена»: первым делом ядро объявляет положение
            // всех переключателей (`startup_effects`), и правда приедет
            // раньше первой отправки.
            enabled: true,
            parts: Reassembler::new(),
            outgoing: HashMap::new(),
            flying: HashMap::new(),
            next_token: 1,
            uses: 0,
            since: 0,
            since_told: 0,
        }
    }

    /// Роняет все соединения — и свои, и чужие. Задачи снимаются, очереди
    /// закрываются.
    fn drop_links(&mut self) {
        for (_, link) in self.links.drain() {
            link.task.abort();
        }
        self.alive.clear();
    }

    /// Поднимает задачу на каждое своё реле.
    ///
    /// Чужие связи при этом тоже роняются, и это не побочное действие:
    /// зовут эту работу при смене настройки, ключа или сети, а каждое
    /// из трёх делает прежние сокеты негодными одинаково.
    fn raise_links(&mut self, notes: &mpsc::Sender<Note>, tor: &TorHandle) {
        self.drop_links();
        // Задаче реле нужен только открытый ключ — подписью занимается
        // задача ступени, и закрытая половина по задачам не расходится.
        let Some(public) = self.key.as_ref().map(|(public, _)| *public) else { return };
        if !self.enabled {
            return;
        }
        if self.relays.len() > MAX_OWN_LINKS {
            tracing::warn!(
                названо = self.relays.len(),
                предел = MAX_OWN_LINKS,
                "nostr: своих реле названо больше, чем поднимаем — лишние не читаются"
            );
        }
        let urls: Vec<String> = self.relays.iter().take(MAX_OWN_LINKS).cloned().collect();
        for url in urls {
            let used = self.tick();
            self.spawn_link(&url, public, true, notes, tor, used);
        }
    }

    /// Следующая отметка обращения.
    fn tick(&mut self) -> u64 {
        self.uses += 1;
        self.uses
    }

    /// Заводит связь с реле и задачу к ней.
    ///
    /// Общее место для своих и чужих нарочно: различаются они одним полем,
    /// и две почти одинаковые сборки задачи — это два места, где потом
    /// поправят одно.
    fn spawn_link(
        &mut self,
        url: &str,
        public: NostrKey,
        own: bool,
        notes: &mpsc::Sender<Note>,
        tor: &TorHandle,
        used: u64,
    ) {
        let (tx, rx) = mpsc::channel(TO_RELAY);
        let task = tokio::spawn(serve_relay(Relay {
            url: url.to_owned(),
            ours: public,
            subscribe: own,
            since: self.since,
            via_tor: self.via_tor,
            tor: tor.clone(),
            outgoing: rx,
            notes: notes.clone(),
        }));
        if let Some(old) = self.links.insert(url.to_owned(), Link { tx, task, own, used }) {
            // Сюда не попадают: и `raise_links`, и `ensure_link` смотрят,
            // есть ли связь, до того как заводить новую. Но молча заменить
            // живую задачу значило бы оставить её висеть навсегда.
            old.task.abort();
        }
    }

    /// Добивается связи с названным реле, поднимая её при надобности.
    ///
    /// Ложь означает «связи нет и не будет»: адрес не разобрался, ключа нет,
    /// ступень выключена — или чужих связей уже столько, сколько мы согласны
    /// держать, и вытеснить нечего.
    fn ensure_link(&mut self, url: &str, notes: &mpsc::Sender<Note>, tor: &TorHandle) -> bool {
        let used = self.tick();
        if let Some(link) = self.links.get_mut(url) {
            link.used = used;
            return true;
        }
        if !self.enabled {
            return false;
        }
        let Some(public) = self.key.as_ref().map(|(public, _)| *public) else { return false };
        // Адрес приехал из чужой карточки, то есть снаружи. Негодный —
        // отбрасывается здесь, а не в задаче реле: задача на негодном адресе
        // отказала бы, подождала минуту и отказала снова, и так навсегда.
        if nostr::relay_target(url).is_none() {
            tracing::debug!(%url, "nostr: реле из карточки названо негодным адресом");
            return false;
        }
        if self.peer_links() >= MAX_PEER_LINKS && !self.evict_peer_link() {
            return false;
        }
        self.spawn_link(url, public, false, notes, tor, used);
        true
    }

    /// Сколько сейчас чужих связей.
    fn peer_links(&self) -> usize {
        self.links.values().filter(|link| !link.own).count()
    }

    /// Убирает самую давно не нужную чужую связь.
    ///
    /// Ложь — убирать нечего: все связи свои, а своих мы не трогаем. Своё
    /// реле — это приём, и разорвать его ради отправки значило бы перестать
    /// слышать, чтобы сказать.
    fn evict_peer_link(&mut self) -> bool {
        let Some(url) = self
            .links
            .iter()
            .filter(|(_, link)| !link.own)
            .min_by_key(|(_, link)| link.used)
            .map(|(url, _)| url.clone())
        else {
            return false;
        };
        if let Some(link) = self.links.remove(&url) {
            link.task.abort();
        }
        tracing::debug!(%url, предел = MAX_PEER_LINKS, "nostr: чужое реле вытеснено по давности");
        true
    }

    /// Очереди тех реле, куда класть события для этого собеседника.
    ///
    /// Реле из его карточки — это места, где он **читает**; туда и надо
    /// класть. Свои остаются запасным путём ровно на один случай: карточка
    /// реле **не называет** — тогда вся надежда на то, что читает он там же,
    /// где и мы, и это в точности прежнее поведение ступени.
    ///
    /// Список из негодных адресов запасным путём не считается, и различие
    /// здесь существенное. «Не сказал, где читает» и «сказал, а мы не поняли»
    /// — разные вещи: во втором случае положить на свои реле значило бы
    /// объявить доставку туда, куда он не смотрит, и получить «отдано»
    /// вместо честного отказа.
    fn targets(
        &mut self,
        peer_relays: &[String],
        notes: &mpsc::Sender<Note>,
        tor: &TorHandle,
    ) -> Vec<mpsc::Sender<String>> {
        let urls: Vec<String> = if peer_relays.is_empty() {
            self.links.iter().filter(|(_, link)| link.own).map(|(url, _)| url.clone()).collect()
        } else {
            let mut named: Vec<String> = Vec::new();
            for url in peer_relays {
                // Список приехал из чужой карточки, и повтор в нём ничем
                // не запрещён. Не отсеяв его, мы положили бы на одно реле два
                // одинаковых события и ждали бы по ним два ответа.
                if named.iter().any(|known| known == url) {
                    continue;
                }
                if self.ensure_link(url, notes, tor) {
                    named.push(url.clone());
                }
            }
            named
        };
        urls.iter().filter_map(|url| self.links.get(url)).map(|link| link.tx.clone()).collect()
    }
}

/// Задача ступени: одна на всю ступень, по одной работе за раз.
async fn serve(
    mut jobs: mpsc::Receiver<Job>,
    events: mpsc::Sender<TransportEvent>,
    tor: TorHandle,
) {
    let (notes_tx, mut notes_rx) = mpsc::channel(EVENTS);
    let mut state = State::new();

    loop {
        tokio::select! {
            job = jobs.recv() => match job {
                Some(job) => on_job(&mut state, job, &notes_tx, &tor, &events).await,
                // Очередь закрыта — раннера не осталось.
                None => {
                    state.drop_links();
                    return;
                }
            },
            note = notes_rx.recv() => match note {
                Some(note) => on_note(&mut state, note, &events).await,
                // Отправитель живёт в самой задаче, так что этого
                // не случается; но `None` в цикле — это вечная готовность
                // ветки, и обойти её надо явно.
                None => return,
            },
        }
    }
}

/// Работа от ядра.
async fn on_job(
    state: &mut State,
    job: Job,
    notes: &mpsc::Sender<Note>,
    tor: &TorHandle,
    events: &mpsc::Sender<TransportEvent>,
) {
    match job {
        Job::Setup(setup) => {
            match *setup {
                NostrSetup::Off => {
                    state.key = None;
                    state.relays.clear();
                }
                NostrSetup::On { secret, relays, via_tor, since } => {
                    // Открытая половина выводится из закрытой, а не приезжает
                    // рядом: два поля, которые можно рассогласовать, — это
                    // два поля, которые однажды рассогласуют.
                    match derive(&secret) {
                        Some(public) => {
                            state.key = Some((public, secret));
                            state.relays = relays;
                            state.via_tor = via_tor;
                            // Назад отметка не ходит: настройка приезжает
                            // и при каждой смене списка реле, а на диске
                            // может лежать значение постарше того, что мы
                            // уже досмотрели в этом сеансе.
                            state.since = state.since.max(since);
                            state.since_told = state.since;
                        }
                        None => {
                            tracing::warn!("nostr: закрытый ключ не разобрался, ступень выключена");
                            state.key = None;
                            state.relays.clear();
                        }
                    }
                }
            }
            state.raise_links(notes, tor);
            settle(state, events).await;
        }
        Job::Enabled(on) => {
            state.enabled = on;
            if on {
                state.raise_links(notes, tor);
            } else {
                // Выключение человеком — не потеря ступени: `Lost` означает
                // «перестала работать, хотя её не выключали». Ядро гасит
                // готовность само, по своей же команде.
                state.drop_links();
                state.ready = false;
            }
            settle(state, events).await;
        }
        Job::NetworkChanged => {
            state.raise_links(notes, tor);
            settle(state, events).await;
        }
        Job::Send { peer_ik, to, relays, frame, handoff } => {
            let sending = Sending { peer_ik, to, relays: &relays, frame: &frame, handoff };
            send_frame(state, sending, notes, tor, events).await;
        }
    }
}

/// Весть от реле.
async fn on_note(state: &mut State, note: Note, events: &mpsc::Sender<TransportEvent>) {
    match note {
        // Чужие реле в состав не идут и готовности не дают — разбор
        // в заголовке. В журнал, однако, идут: «событие не ушло» иначе
        // не отличить от «реле собеседника не отвечает».
        Note::Up { url, own } => {
            if !own {
                tracing::debug!(%url, "nostr: реле собеседника отвечает");
                return;
            }
            state.alive.insert(url.clone(), NostrRelay { url, up: true, note: String::new() });
            settle(state, events).await;
        }
        Note::Down { url, note, own } => {
            if !own {
                tracing::debug!(%url, %note, "nostr: реле собеседника не отвечает");
                return;
            }
            state.alive.insert(url.clone(), NostrRelay { url, up: false, note });
            settle(state, events).await;
        }
        Note::Event { content } => {
            if let Some(frame) = collect(state, &content) {
                let event = TransportEvent::Received {
                    via: Transport::Nostr,
                    // **Не** ключ из события, и это не забывчивость.
                    // Подпись говорит «положил владелец этого ключа»,
                    // а личность устанавливает рукопожатие §8.2. Ровно
                    // так же поступает почта с заголовком `From:`.
                    peer_hint: None,
                    // Связей у реле нет: ответ уедет своей публикацией.
                    link: None,
                    frame,
                };
                let _ = events.send(event).await;
            }
        }
        Note::Seen { created_at } => {
            if created_at <= state.since {
                return;
            }
            state.since = created_at;
            // Наверх — только заметными шагами: за новостью стоит запись
            // на диск, а события приходят пачками.
            if state.since >= state.since_told.saturating_add(SINCE_REPORT_STEP) {
                state.since_told = state.since;
                let event = TransportEvent::NostrSince { created_at: state.since };
                let _ = events.send(event).await;
            }
        }
        Note::Accepted { id, ok } => {
            answer(state, &id, ok, events).await;
        }
    }
}

/// Метка сборки для одной отправки — шестнадцать случайных байт.
///
/// # Почему случайные, а не счётчик
///
/// Здесь стоял счётчик отправок вместе с половиной `IK` получателя, и это
/// оказалось двумя ошибками разом. Обе нашлись на стенде, в журнале одного
/// прогона.
///
/// **Первая: счётчик начинается заново при каждом запуске.** Реле хранит
/// события и после перезапуска отдаёт их заново; метки нового запуска
/// совпадали с метками прежнего, и у получателя части **разных** сообщений
/// сходились в одну сборку. Собиралось из них что придётся, а при разном
/// числе частей сборщик честно отвечал `Inconsistent` — эта строка и стоит
/// в журнале. Уникальность метки обязана переживать перезапуск, а счётчик
/// в памяти её не переживает по устройству.
///
/// **Вторая: заголовок части не зашифрован.** Он лежит внутри содержимого
/// события (0.3.5) — то есть открыт для реле, — и восемь байт `IK`
/// получателя мы отдавали реле даром. `IK` живёт дольше ключа nostr
/// и общий для **всех** ступеней: по нему разговор на реле связывается
/// с тем же человеком в локальной сети, в меше и в почте. Ничего подобного
/// 0.3.3 реле не обещало.
///
/// Случайные байты решают обе: они уникальны без памяти о прошлых запусках
/// и не выводятся ни из чего.
fn fresh_uid() -> fragment::Uid {
    use rand_core::RngCore;

    let mut uid = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut uid);
    uid
}

/// Открытая половина закрытого ключа.
fn derive(secret: &NostrSecret) -> Option<NostrKey> {
    let key = ratatosk_crypto::nostr::NostrKey::from_seed(*secret.bytes()).ok()?;
    Some(NostrKey::new(key.public()))
}

/// Одна отправка: кому, куда и что.
///
/// Структурой, а не пятью доводами подряд: без неё у `send_frame` их было бы
/// девять — с двумя очередями и указателем на Tor вперемешку. Перепутать
/// местами `peer_ik` и содержимое кадра было бы делом одной строки, а
/// заметить это можно было бы только по тому, что сообщение не дошло.
struct Sending<'a> {
    /// Кому — для событий наверх.
    peer_ik: [u8; 32],
    /// Его ключ nostr: он стоит в событии открыто.
    to: NostrKey,
    /// Реле из **его** карточки: где он читает. Пусто — кладём на свои.
    relays: &'a [String],
    /// Готовый кадр целиком; резать его — наше дело.
    frame: &'a [u8],
    /// Метка, которую вернуть, когда событие примут.
    handoff: Option<u64>,
}

/// Режет кадр, подписывает части и раскладывает их по реле **получателя**.
///
/// Куда именно — решает `State::targets`; здесь важно лишь то, что выбор
/// делается один раз на отправку и все части едут одним и тем же составом
/// реле. Разойдись он между частями, у получателя оказалось бы полкадра
/// на одном реле и полкадра на другом — и ни одного собранного.
async fn send_frame(
    state: &mut State,
    sending: Sending<'_>,
    notes: &mpsc::Sender<Note>,
    tor: &TorHandle,
    events: &mpsc::Sender<TransportEvent>,
) {
    let Sending { peer_ik, to, relays, frame, handoff } = sending;
    let Some((public, secret)) = state.key.clone() else {
        return refuse(peer_ik, events).await;
    };
    let Ok(signer) = ratatosk_crypto::nostr::NostrKey::from_seed(*secret.bytes()) else {
        return refuse(peer_ik, events).await;
    };

    let uid = fresh_uid();

    let chunks = fragment::split(frame, PART_BYTES);
    let Ok(total) = u16::try_from(chunks.len()) else {
        return refuse(peer_ik, events).await;
    };
    if chunks.len() > 1 {
        // Только про многочастные кадры и только здесь: одночастных большинство,
        // и строка на каждый была бы шумом, а вот нарезку надо видеть — иначе
        // «доехало полсообщения» неотличимо от «доехало не то».
        tracing::info!(кадр = frame.len(), частей = chunks.len(), "nostr: кадр поехал частями");
    }
    let token = state.next_token;
    // Метка занимается **здесь**, а не после успешной раскладки, и это
    // не перестановка строк. Из неё выведен `uid` сборки; откажи отправка
    // после того, как часть событий уже ушла на реле, — следующая отправка
    // взяла бы тот же `uid`, и у получателя её части смешались бы
    // с застрявшими чужими. Собралось бы из этого не сообщение, а мусор.
    state.next_token += 1;
    let created_at = seconds_now();

    // **Сперва собрать всё, потом разослать.** Порядок здесь не вкусовой:
    // подпись может не построиться на любой части, и раскладывай мы события
    // по реле на ходу, отказ посередине оставил бы половину сообщения
    // на реле и записи о ней в учёте — навсегда, потому что ждать ответа
    // по несуществующей отправке будет некому.
    let mut ready = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let part = nostr::Part { uid, index: u16::try_from(index).expect("влезает"), total };
        let content = nostr::content_encode(&part.wrap(chunk));
        let mut event = Event {
            id: [0u8; 32],
            pubkey: public,
            created_at,
            recipient: to,
            // Срок истечения (NIP-40) — от времени события, а не от «сейчас»:
            // все части одного кадра обязаны исчезнуть вместе. Разойдись они,
            // у получателя осталась бы сборка, которой недостаёт куска,
            // и ждала бы она его до собственного срока.
            expires_at: created_at.saturating_add(nostr::EVENT_TTL_SECONDS),
            content,
            sig: [0u8; 64],
        };
        event.id = ratatosk_crypto::nostr::event_id(&event.preimage());
        let Ok(sig) = signer.sign(&event.id) else {
            // Подпись не построилась — редкость за гранью вероятного
            // (`ratatosk_crypto::nostr`), но молчать о ней нельзя.
            return refuse(peer_ik, events).await;
        };
        event.sig = sig;
        ready.push((data_encoding::HEXLOWER.encode(&event.id), nostr::publish_json(&event)));
    }

    // Состав реле выбирается **после** подписи и один раз: связь может
    // подняться (`ensure_link` заводит задачу), и делать это ради отправки,
    // которая тут же откажет на подписи, незачем.
    let senders = state.targets(relays, notes, tor);
    if senders.is_empty() {
        // Ни своих реле, ни годных чужих — класть некуда.
        return refuse(peer_ik, events).await;
    }

    // Не `relays` — так называется список из карточки, лежащий строкой выше,
    // а это число очередей, по которым часть разошлась.
    let across = senders.len();

    // **Все части или ни одной.** Здесь стоял подсчёт ушедших, и он лгал
    // в худшую сторону, какая бывает: части, не влезшие в очередь реле,
    // просто выпадали, а учёт заводился на ушедшие. Дальше всё шло «как
    // надо» — реле подтверждало каждую, `waiting` доходило до нуля,
    // и ядро получало `Handed`, то есть **«доставлено»** о сообщении,
    // которого собеседник не соберёт никогда: у него недостаёт частей.
    //
    // Нашлось это на границе класса L, где кадр режется на 128 частей
    // при очереди в 32 (`TO_RELAY`). Класс L сюда больше не приходит
    // (см. `execute`), но лечить надо не симптом: затор возможен и на
    // восьми частях, если реле медленное.
    //
    // Ушедшие события обратно не вернуть, и это не беда: у получателя они
    // полежат в сборщике и уйдут по сроку (§9.3). Беда была бы соврать
    // про доставку (§14).
    let mut queued: Vec<String> = Vec::with_capacity(ready.len());
    for (id_hex, line) in &ready {
        let mut taken = false;
        for tx in &senders {
            // `try_send`: реле, которое не успевает, обязано упереться
            // в переполнение, а не задержать остальные.
            if tx.try_send(line.clone()).is_ok() {
                taken = true;
            }
        }
        if !taken {
            tracing::info!(
                частей = ready.len(),
                ушло = queued.len(),
                "nostr: очередь реле переполнена — отправка отменена целиком"
            );
            return refuse(peer_ik, events).await;
        }
        queued.push(id_hex.clone());
    }

    for id_hex in queued {
        state.flying.insert(id_hex, Flying { token, answers: 0, relays: across });
    }
    state.outgoing.insert(token, Outgoing { peer_ik, handoff, waiting: ready.len() });
}

/// Объявляет отправку неудавшейся.
///
/// Именно событием, а не отказом из `execute`: к этому моменту ядро давно
/// ушло. `ConnectFailed` — то же, чем отвечает почта, и §5.4 на него ведёт
/// доставку дальше по лестнице.
async fn refuse(peer_ik: [u8; 32], events: &mpsc::Sender<TransportEvent>) {
    let _ = events.send(TransportEvent::ConnectFailed { peer_ik, via: Transport::Nostr }).await;
}

/// Ответ реле на нашу часть.
async fn answer(state: &mut State, id: &str, ok: bool, events: &mpsc::Sender<TransportEvent>) {
    // Всё нужное снимается сразу и заимствование отпускается: дальше мы
    // трогаем ту же карту на запись, и держать на ней ссылку значило бы
    // писать код, который живёт милостью проверки заимствований.
    let Some(flying) = state.flying.get(id) else { return };
    let token = flying.token;
    let answers = flying.answers + 1;
    let relays = flying.relays;

    if ok {
        // Довольно **одного** принявшего реле: событие легло, и собеседник
        // его заберёт. Остальные ответы по этой части нам уже безразличны.
        state.flying.remove(id);
        let Some(out) = state.outgoing.get_mut(&token) else { return };
        out.waiting -= 1;
        if out.waiting > 0 {
            return;
        }
        let out = state.outgoing.remove(&token).expect("запись только что была");
        // Метка есть не всегда: `None` означает «подтверждения никто
        // не ждёт», и молчание в ответ на такую отправку не потеря.
        if let Some(handoff) = out.handoff {
            let event =
                TransportEvent::Handed { peer_ik: out.peer_ik, via: Transport::Nostr, handoff };
            let _ = events.send(event).await;
        }
        return;
    }

    if answers < relays {
        // Отказало одно реле — остальные ещё могут принять.
        if let Some(flying) = state.flying.get_mut(id) {
            flying.answers = answers;
        }
        return;
    }

    // Отказали все: часть не легла никуда, значит не легло и сообщение.
    state.flying.remove(id);
    if let Some(out) = state.outgoing.remove(&token) {
        // Прочие части этой отправки больше никого не ждут.
        state.flying.retain(|_, other| other.token != token);
        let event = TransportEvent::ConnectFailed { peer_ik: out.peer_ik, via: Transport::Nostr };
        let _ = events.send(event).await;
    }
}

/// Складывает пришедшую часть; отдаёт кадр, когда он собрался.
fn collect(state: &mut State, content: &str) -> Option<Vec<u8>> {
    let bytes = nostr::content_decode(content)?;
    let (part, body) = nostr::Part::unwrap(&bytes)?;
    let verdict = state.parts.accept(
        part.uid,
        part.index.into(),
        part.total.into(),
        body,
        PART_TTL_MS,
        millis_now(),
    );
    match verdict {
        Ok(Accepted::Complete(frame)) => {
            if part.total > 1 {
                tracing::info!(частей = part.total, кадр = frame.len(), "nostr: кадр собран");
            }
            Some(frame)
        }
        // Недостача — не беда сама по себе, но именно она отличает
        // «сообщение идёт» от «сообщение не дойдёт никогда»: части едут
        // разными событиями, и застрявшая сборка видна только отсюда.
        Ok(Accepted::Pending { have, total }) => {
            tracing::info!(есть = have, всего = total, "nostr: кадр ещё не собран");
            None
        }
        // Дубль здесь — не беда, а устройство ступени: одно событие
        // приезжает с каждого реле, на которое мы его положили.
        Ok(_) => None,
        Err(error) => {
            tracing::debug!(?error, "nostr: часть не принята сборщиком");
            None
        }
    }
}

/// Приводит состав реле и готовность ступени в согласие с тем, что есть.
async fn settle(state: &mut State, events: &mpsc::Sender<TransportEvent>) {
    // Состав — человеку: реле держит кто-то посторонний, и оно может
    // исчезнуть навсегда. Без живого состава «nostr не работает» и «одно
    // из пяти реле умерло полгода назад» выглядят одинаково.
    let mut relays: Vec<NostrRelay> = state.alive.values().cloned().collect();
    relays.sort_by(|a, b| a.url.cmp(&b.url));
    let _ = events.send(TransportEvent::NostrRelays { relays }).await;

    // Готовность — на границе нуля, и только на ней. Повтор ядро отбросит
    // само, но слать его каждое соединение значило бы засыпать журнал.
    let up = state.alive.values().any(|relay| relay.up);
    if up && !state.ready {
        state.ready = true;
        let _ = events.send(TransportEvent::Ready { transport: Transport::Nostr }).await;
    } else if !up && state.ready {
        state.ready = false;
        let _ = events.send(TransportEvent::Lost { transport: Transport::Nostr }).await;
    }
}

/// Задача одного реле: соединиться, подписаться и качать в обе стороны.
///
/// Возвращается только вместе со снятием: обрыв — повод подождать и начать
/// заново, а не закончить.
async fn serve_relay(mut relay: Relay) {
    // Наибольшее `created_at`, которое мы видели. Переживает обрыв,
    // а перезапуск приложения — через диск: начальное значение приезжает
    // настройкой, дальнейшие уходят наверх вестью `Seen`.
    //
    // Здесь стоял ноль с припиской «цена названа в `HANDOFF.md`». Цену
    // заплатили: реле после каждого старта отдавало всю сохранённую историю,
    // включая давние кадры рукопожатия, а anti-replay кэш §8.3 живёт
    // в памяти и перезапуск не переживает — старое рукопожатие принималось
    // как новое и вытесняло живую сессию.
    let mut since = relay.since;

    loop {
        match pump(&mut relay, &mut since).await {
            Ok(()) => {}
            Err(note) => {
                let down = Note::Down { url: relay.url.clone(), note, own: relay.subscribe };
                if relay.notes.send(down).await.is_err() {
                    return;
                }
            }
        }
        tokio::time::sleep(RELAY_RETRY).await;
    }
}

/// Всё, что нужно задаче одного реле.
///
/// Структурой, а не восемью доводами: половина из них одного типа, и
/// перепутать местами `url` с тем, что рядом, было бы делом одной строки.
struct Relay {
    url: String,
    /// **Наш** открытый ключ — тот, по которому идёт подписка.
    ours: NostrKey,
    /// Подписываться ли на этом реле.
    ///
    /// Оно же «своё ли реле»: на чужое мы только кладём. Разбор — в
    /// заголовке; здесь довольно того, что подписка на чужом реле сообщила
    /// бы ему, где мы читаем.
    subscribe: bool,
    /// С какого времени просить события, секунды unix.
    ///
    /// Начальное значение; дальше задача ведёт его сама и переживает им
    /// обрывы. Перезапуск приложения им не переживается — для этого отметка
    /// и уходит на диск через ядро.
    since: u64,
    via_tor: bool,
    tor: TorHandle,
    outgoing: mpsc::Receiver<String>,
    notes: mpsc::Sender<Note>,
}

/// Один заход: соединение, подписка и насос до обрыва.
async fn pump(relay: &mut Relay, since: &mut u64) -> Result<(), String> {
    // Разбирается сразу и целиком: дальше в теле живёт `select!`, и брать
    // поля через `relay.` в двух его ветках значило бы делить заимствование
    // там, где макрос его не делит.
    //
    // `since` из записи здесь намеренно **не берётся**: это начальное
    // значение, и его уже прочитал `serve_relay`. Живое едет отдельным
    // доводом и переживает обрывы; свяжи мы поле тем же именем — оно
    // молча заслонило бы довод, и отметка сбрасывалась бы к начальной
    // на каждом заходе.
    let Relay { url, ours, subscribe, via_tor, tor, outgoing, notes, since: _ } = relay;
    let url: &str = url;
    let via_tor = *via_tor;
    let subscribe = *subscribe;

    let target = nostr::relay_target(url).ok_or_else(|| format!("адрес реле не годится: {url}"))?;

    // Строка на каждую попытку, и она не отладочный мусор. Без неё «реле
    // ещё не пробовали» на экране означает сразу две разные вещи: задача
    // реле не запускалась вовсе (ступени нет в сборке) — или запускалась
    // и висит на соединении. Различить их по экрану было нечем, и один
    // разбор это уже стоило. Попытка одна в минуту на реле, так что
    // в журнале это не шум.
    tracing::info!(%url, узел = %target.host, порт = target.port, tls = target.tls, "идём на реле");

    // До себя самого — никакого Tor: цепочка встречи до `127.0.0.1` никуда
    // не ведёт по построению. Это не поблажка настройке, а то же самое,
    // что она означает: через Tor мы ходим **наружу**.
    let through_tor = via_tor && target.tls;

    let plain = tokio::time::timeout(
        CONNECT_TIMEOUT,
        crate::tls::dial(&target.host, target.port, through_tor, tor),
    )
    .await
    .map_err(|_| "реле не ответило за отведённое время".to_owned())?
    .map_err(|error| format!("{error}"))?;

    // Оба случая — один и тот же тип: `Plain` это `Box<dyn Stream>`,
    // а завёрнутый в TLS поток в такую коробку кладётся так же. Иначе
    // пришлось бы заводить перечисление с пересылкой четырёх методов
    // ради одной ветки.
    let stream: crate::tls::Plain = if target.tls {
        Box::new(
            tokio::time::timeout(CONNECT_TIMEOUT, crate::tls::wrap(&target.host, plain))
                .await
                .map_err(|_| "TLS не установился за отведённое время".to_owned())?
                .map_err(|error| format!("{error}"))?,
        )
    } else {
        plain
    };

    let (mut socket, _response) =
        tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::client_async(url, stream))
            .await
            .map_err(|_| "рукопожатие веб-сокета не уложилось в срок".to_owned())?
            .map_err(|error| format!("веб-сокет не открылся: {error}"))?;

    // Подписка — только на своём реле. На чужом соединение нужно ровно
    // затем, чтобы положить событие и услышать `OK`; сказать ему сверх
    // этого, что наш ключ здесь читает, — значит отдать даром то, ради
    // чего вся ступень и ходит через Tor.
    if subscribe {
        // Запас назад: `created_at` ставит отправитель своими часами,
        // и отстающие часы иначе означали бы событие, которое не приедет
        // к нам никогда.
        let from = since.saturating_sub(nostr::SINCE_MARGIN_SECONDS);
        // Вслух, потому что разница между «просим последний час» и «просим
        // всё с начала времён» — это разница между тишиной и лавиной,
        // а снаружи они выглядят одинаково.
        tracing::info!(%url, начиная = from, "подписываемся");
        let request = nostr::subscribe_json(SUBSCRIPTION, ours, from);
        socket
            .send(tokio_tungstenite::tungstenite::Message::text(request))
            .await
            .map_err(|error| format!("подписка не ушла: {error}"))?;
    }

    if notes.send(Note::Up { url: url.to_owned(), own: subscribe }).await.is_err() {
        return Ok(());
    }

    loop {
        tokio::select! {
            line = outgoing.recv() => match line {
                Some(line) => {
                    socket
                        .send(tokio_tungstenite::tungstenite::Message::text(line))
                        .await
                        .map_err(|error| format!("событие не ушло: {error}"))?;
                }
                None => return Ok(()),
            },
            incoming = socket.next() => match incoming {
                Some(Ok(message)) => {
                    let Ok(text) = message.to_text() else { continue };
                    if text.is_empty() {
                        continue;
                    }
                    match parse(text) {
                        Some(Parsed::Event { content, created_at }) => {
                            *since = (*since).max(created_at);
                            // Время — вперёд содержимого и независимо от него:
                            // событие могло не подойти сборщику, но
                            // досмотренным оно от этого быть не перестаёт.
                            if notes.send(Note::Seen { created_at }).await.is_err() {
                                return Ok(());
                            }
                            if notes.send(Note::Event { content }).await.is_err() {
                                return Ok(());
                            }
                        }
                        Some(Parsed::Ok { id, ok, note }) => {
                            if !ok {
                                tracing::debug!(%url, %id, %note, "реле отвергло событие");
                            }
                            if notes.send(Note::Accepted { id, ok }).await.is_err() {
                                return Ok(());
                            }
                        }
                        Some(Parsed::Closed { note }) => {
                            return Err(format!("реле закрыло подписку: {note}"));
                        }
                        // `EOSE`, `NOTICE` и всё незнакомое — не наше дело.
                        // Незнакомое именно **пропускается**, а не считается
                        // поломкой: реле вправе говорить то, чего мы не знаем.
                        _ => {}
                    }
                    // Ответ на `Ping` библиотека складывает в очередь записи
                    // сама, но **отправляет** его только со следующей
                    // записью. Реле, которое проверяет нас пингом, а в ответ
                    // получает тишину, читает соединение как мёртвое — и мы
                    // теряли бы реле ровно тогда, когда говорить нечего.
                    // Проталкивание стоит одного системного вызова.
                    if let Err(error) = socket.flush().await {
                        return Err(format!("очередь записи не протолкнулась: {error}"));
                    }
                }
                Some(Err(error)) => return Err(format!("обрыв: {error}")),
                None => return Err("реле закрыло соединение".to_owned()),
            },
        }
    }
}

/// Что реле нам сказало.
#[derive(Debug, PartialEq)]
enum Parsed {
    /// Событие из подписки.
    Event {
        /// Содержимое как есть.
        content: String,
        /// Когда оно положено, секунды.
        created_at: u64,
    },
    /// Ответ на наше событие.
    Ok {
        /// Идентификатор, шестнадцатеричным.
        id: String,
        /// Принято или нет.
        ok: bool,
        /// Что сказало реле — словами.
        note: String,
    },
    /// Подписка закрыта реле.
    Closed {
        /// Причина словами.
        note: String,
    },
    /// Всё остальное: `EOSE`, `NOTICE`, незнакомое.
    Other,
}

/// Разбирает сообщение реле (NIP-01).
///
/// `None` — не JSON или не массив, то есть не сообщение протокола вовсе.
/// Всё, что разобралось, но нам незнакомо, возвращается как [`Parsed::Other`]
/// и молча пропускается: реле вправе говорить то, чего мы не знаем, и
/// считать это поломкой — верный способ отвалиться от живого реле.
fn parse(text: &str) -> Option<Parsed> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let items = value.as_array()?;
    match items.first()?.as_str()? {
        "EVENT" => {
            // ["EVENT", <подписка>, <событие>]
            let event = items.get(2)?;
            let content = event.get("content")?.as_str()?.to_owned();
            let created_at = event.get("created_at").and_then(serde_json::Value::as_u64)?;
            Some(Parsed::Event { content, created_at })
        }
        "OK" => {
            // ["OK", <идентификатор>, <принято>, <словами>]
            let id = items.get(1)?.as_str()?.to_owned();
            let ok = items.get(2)?.as_bool()?;
            let note =
                items.get(3).and_then(serde_json::Value::as_str).unwrap_or_default().to_owned();
            Some(Parsed::Ok { id, ok, note })
        }
        "CLOSED" => {
            // ["CLOSED", <подписка>, <словами>]
            let note =
                items.get(2).and_then(serde_json::Value::as_str).unwrap_or_default().to_owned();
            Some(Parsed::Closed { note })
        }
        _ => Some(Parsed::Other),
    }
}

/// Текущее время в секундах — то, что ждёт NIP-01.
fn seconds_now() -> u64 {
    millis_now() / 1000
}

/// Текущее время в миллисекундах.
fn millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_message_is_read_for_its_content_and_time() {
        let line = r#"["EVENT","rk",{"id":"aa","pubkey":"bb","created_at":1700000000,"kind":4242,"tags":[],"content":"ZGF0YQ","sig":"cc"}]"#;
        assert_eq!(
            parse(line),
            Some(Parsed::Event { content: "ZGF0YQ".to_owned(), created_at: 1_700_000_000 })
        );
    }

    #[test]
    fn an_ok_message_is_read_for_its_verdict() {
        assert_eq!(
            parse(r#"["OK","abc",true,""]"#),
            Some(Parsed::Ok { id: "abc".to_owned(), ok: true, note: String::new() })
        );
        assert_eq!(
            parse(r#"["OK","abc",false,"blocked: pubkey not allowed"]"#),
            Some(Parsed::Ok {
                id: "abc".to_owned(),
                ok: false,
                note: "blocked: pubkey not allowed".to_owned()
            })
        );
    }

    #[test]
    fn a_closed_subscription_is_a_reason_to_reconnect() {
        assert_eq!(
            parse(r#"["CLOSED","rk","error: too many concurrent REQs"]"#),
            Some(Parsed::Closed { note: "error: too many concurrent REQs".to_owned() })
        );
    }

    #[test]
    fn what_we_do_not_know_is_skipped_and_not_called_a_break() {
        // Реле вправе говорить то, чего мы не знаем. Считать это поломкой —
        // верный способ отвалиться от живого реле на ровном месте.
        for line in [
            r#"["EOSE","rk"]"#,
            r#"["NOTICE","restricted: we're closing"]"#,
            r#"["AUTH","challenge"]"#,
            r#"["СОВСЕМ","новое",1,2,3]"#,
        ] {
            assert_eq!(parse(line), Some(Parsed::Other), "{line}");
        }
    }

    #[test]
    fn nonsense_is_refused_rather_than_guessed() {
        // Не JSON, не массив, пустой массив, обрезанное событие — всё это
        // не сообщение протокола, и придумывать за реле нечего.
        assert_eq!(parse("не json"), None);
        assert_eq!(parse("{}"), None);
        assert_eq!(parse("[]"), None);
        assert_eq!(parse(r#"["EVENT","rk"]"#), None, "события нет");
        assert_eq!(parse(r#"["EVENT","rk",{"content":"x"}]"#), None, "времени нет");
        assert_eq!(parse(r#"["OK","abc"]"#), None, "вердикта нет");
    }

    // --- куда кладутся события ----------------------------------------------
    //
    // Всё ниже — про выбор реле, и проверяется он **без сети**. Задачи реле
    // при этом заводятся настоящие и уходят соединяться в никуда (порты
    // взяты заведомо пустые): их дело здесь — существовать, а не соединиться.
    // Проверяем состав связей и то, чьи очереди вернул выбор.

    /// Состояние с ключом и названными своими реле.
    fn stand(own: &[&str]) -> (State, mpsc::Sender<Note>, mpsc::Receiver<Note>, TorHandle) {
        let (notes_tx, notes_rx) = mpsc::channel(EVENTS);
        let mut state = State::new();
        // Ключ ставится прямо: выводить открытую половину из закрытой здесь
        // нечего, выбор реле её не касается.
        state.key = Some((NostrKey::new([9u8; 32]), NostrSecret::new([7u8; 32])));
        state.relays = own.iter().map(|url| (*url).to_owned()).collect();
        let tor = TorHandle::default();
        state.raise_links(&notes_tx, &tor);
        (state, notes_tx.clone(), notes_rx, tor)
    }

    /// Та же очередь, что у названной связи?
    fn is_link(state: &State, url: &str, tx: &mpsc::Sender<String>) -> bool {
        state.links.get(url).is_some_and(|link| link.tx.same_channel(tx))
    }

    #[tokio::test]
    async fn a_frame_goes_to_the_relays_the_card_names_and_not_to_ours() {
        // Ради этого вся работа. Реле собеседника — это место, где он
        // **читает**; положив событие к себе, мы кладём его туда, куда он
        // никогда не заглянет, и переписка двух людей с непересекающимися
        // списками не начинается вовсе.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let senders = state.targets(&["ws://127.0.0.1:7002".to_owned()], &notes, &tor);

        assert_eq!(senders.len(), 1);
        assert!(is_link(&state, "ws://127.0.0.1:7002", &senders[0]), "кладём на его реле");
        assert!(state.links.contains_key("ws://127.0.0.1:7001"), "своё реле осталось на приёме");
        assert!(!state.links["ws://127.0.0.1:7002"].own, "чужое реле — только для записи");
        assert!(state.links["ws://127.0.0.1:7001"].own);
    }

    #[tokio::test]
    async fn a_card_without_relays_falls_back_to_our_own() {
        // Старая карточка или выключенная у собеседника ступень — не отказ:
        // остаётся надежда, что читает он там же, где и мы. Это ровно то
        // поведение, что было до списков реле.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let senders = state.targets(&[], &notes, &tor);

        assert_eq!(senders.len(), 1);
        assert!(is_link(&state, "ws://127.0.0.1:7001", &senders[0]));
        assert_eq!(state.links.len(), 1, "лишних связей не заведено");
    }

    #[tokio::test]
    async fn a_relay_named_wrongly_is_skipped_and_the_good_one_still_works() {
        // Карточка приезжает снаружи, и негодный адрес в ней — обычное дело.
        // Отбрасывается он **до** задачи: задача на таком адресе отказывала бы
        // раз в минуту вечно.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        // Второй адрес негоден по-настоящему: открытый `ws://` наружу
        // не принимается никуда, кроме себя самого (`relay_target`).
        let named = ["ws://8.8.8.8:7003".to_owned(), "ws://127.0.0.1:7004".to_owned()];
        let senders = state.targets(&named, &notes, &tor);

        assert_eq!(senders.len(), 1, "годный адрес из списка сработал");
        assert!(is_link(&state, "ws://127.0.0.1:7004", &senders[0]));
        assert!(!state.links.contains_key("ws://8.8.8.8:7003"), "на негодный задачи нет");
    }

    #[tokio::test]
    async fn a_wholly_unusable_list_is_not_silently_replaced_by_ours() {
        // Разница с пустым списком существенная: пусто — «он не сказал, где
        // читает», и запасной путь честен. А вот список из негодных адресов
        // — это «сказал, но мы его не поняли», и подменять его своими реле
        // значило бы обещать доставку туда, куда он не смотрит.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        assert!(state.targets(&["не адрес".to_owned()], &notes, &tor).is_empty());
        assert_eq!(state.targets(&[], &notes, &tor).len(), 1, "а пустой список — запасной путь");
    }

    #[tokio::test]
    async fn our_own_relay_named_by_the_card_does_not_become_a_second_link() {
        // Общее реле — самый частый случай, и две задачи на один адрес
        // означали бы два соединения, две подписки и каждое событие дважды.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let senders = state.targets(&["ws://127.0.0.1:7001".to_owned()], &notes, &tor);

        assert_eq!(state.links.len(), 1, "связь одна");
        assert!(state.links["ws://127.0.0.1:7001"].own, "и она осталась своей, то есть читающей");
        assert!(is_link(&state, "ws://127.0.0.1:7001", &senders[0]));
    }

    #[tokio::test]
    async fn a_relay_named_twice_gets_one_copy() {
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let twice = ["ws://127.0.0.1:7002".to_owned(), "ws://127.0.0.1:7002".to_owned()];
        assert_eq!(state.targets(&twice, &notes, &tor).len(), 1);
    }

    #[tokio::test]
    async fn foreign_relays_are_capped_and_the_oldest_one_goes_first() {
        // Чужие реле приходят из карточек, и без потолка их число росло бы
        // с числом собеседников. Вытесняется **самое давнее**, а не
        // произвольное: иначе связь, которой только что пользовались,
        // поднималась бы заново на каждой отправке.
        let (mut state, notes, _rx, tor) = stand(&[]);
        let url = |n: usize| format!("ws://127.0.0.1:{}", 7100 + n);
        for n in 0..MAX_PEER_LINKS {
            assert!(!state.targets(&[url(n)], &notes, &tor).is_empty(), "{n}");
        }
        assert_eq!(state.peer_links(), MAX_PEER_LINKS);

        // Самой давней была нулевая — обращаемся к ней, и давней становится
        // первая.
        let _ = state.targets(&[url(0)], &notes, &tor);
        let _ = state.targets(&[url(MAX_PEER_LINKS)], &notes, &tor);

        assert_eq!(state.peer_links(), MAX_PEER_LINKS, "потолок держится");
        assert!(state.links.contains_key(&url(MAX_PEER_LINKS)), "новая связь заведена");
        assert!(state.links.contains_key(&url(0)), "та, которой только что пользовались, цела");
        assert!(!state.links.contains_key(&url(1)), "ушла самая давняя");
    }

    #[tokio::test]
    async fn our_own_relays_are_never_evicted_for_a_foreign_one() {
        // Своё реле — это приём. Разорвать его ради отправки значило бы
        // перестать слышать, чтобы сказать.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let url = |n: usize| format!("ws://127.0.0.1:{}", 7100 + n);
        for n in 0..=MAX_PEER_LINKS {
            let _ = state.targets(&[url(n)], &notes, &tor);
        }
        assert!(state.links["ws://127.0.0.1:7001"].own, "своё реле на месте");
        assert_eq!(state.peer_links(), MAX_PEER_LINKS);
    }

    #[tokio::test]
    async fn a_class_l_frame_is_refused_and_a_class_m_one_is_taken() {
        // Мебибайт — это 128 событий по одиннадцать килобайт подряд, и ни одно
        // реле такого не потерпит. Отказ обязан быть мгновенным: §5.4 ведёт
        // доставку дальше по лестнице, а почта класс L везёт.
        //
        // Вторая половина проверки не менее важна первой: отказывай ступень
        // и классу M, длинный текст не ездил бы по ней вовсе — и молча.
        let peer = || crate::runner::PeerAddress {
            ik: [1u8; 32],
            onion: None,
            chatmail: None,
            ygg: None,
            nostr: Some(NostrKey::new([5u8; 32])),
            nostr_relays: Vec::new(),
        };
        let mut runner = NostrRunner::new(TorHandle::default());
        let heavy = TransportCommand::Send {
            peer: peer(),
            via: Transport::Nostr,
            frame: vec![0u8; SizeClass::L.frame_len()],
            handoff: None,
        };
        assert!(matches!(runner.execute(heavy).await, Err(TransportError::Unavailable)));

        let fitting = TransportCommand::Send {
            peer: peer(),
            via: Transport::Nostr,
            frame: vec![0u8; SizeClass::M.frame_len()],
            handoff: None,
        };
        assert!(runner.execute(fitting).await.is_ok(), "класс M ступень везёт");
    }

    // --- отметка досмотренного -----------------------------------------------

    #[tokio::test]
    async fn the_watermark_grows_inside_but_reaches_the_core_in_steps() {
        // За новостью наверх стоит запись на диск, а события приходят
        // пачками: обмен из сотни сообщений не должен стоить сотни записей.
        let (mut state, _notes, _rx, _tor) = stand(&[]);
        let (events, mut got) = mpsc::channel(EVENTS);

        on_note(&mut state, Note::Seen { created_at: 1_000 }, &events).await;
        assert_eq!(state.since, 1_000);
        assert!(
            matches!(got.try_recv(), Ok(TransportEvent::NostrSince { created_at: 1_000 })),
            "первое же событие обязано лечь на диск: до него там ноль"
        );

        on_note(&mut state, Note::Seen { created_at: 1_030 }, &events).await;
        assert_eq!(state.since, 1_030, "внутри отметка растёт всегда");
        assert!(got.try_recv().is_err(), "а наверх мелкий шаг не уходит");

        on_note(&mut state, Note::Seen { created_at: 1_100 }, &events).await;
        assert!(
            matches!(got.try_recv(), Ok(TransportEvent::NostrSince { created_at: 1_100 })),
            "заметный шаг — уходит"
        );
    }

    #[tokio::test]
    async fn the_watermark_never_walks_backwards() {
        // `created_at` ставит **отправитель**, и часы у него свои. Событие
        // из прошлого — обычное дело, и отматывать по нему отметку значило бы
        // переспрашивать у реле всё заново при каждом таком событии.
        let (mut state, _notes, _rx, _tor) = stand(&[]);
        let (events, mut got) = mpsc::channel(EVENTS);
        on_note(&mut state, Note::Seen { created_at: 9_000 }, &events).await;
        let _ = got.try_recv();

        on_note(&mut state, Note::Seen { created_at: 5 }, &events).await;
        assert_eq!(state.since, 9_000, "назад отметка не ходит");
        assert!(got.try_recv().is_err(), "и на диск от этого ничего не пишется");
    }

    #[tokio::test]
    async fn a_setup_brings_the_watermark_from_disk_and_does_not_rewind_it() {
        // Настройка приезжает не только при включении ступени, но и при
        // каждой смене списка реле. На диске при этом может лежать значение
        // старее того, что мы уже досмотрели в этом сеансе.
        let (notes, _rx) = mpsc::channel(EVENTS);
        let (events, _got) = mpsc::channel(EVENTS);
        let tor = TorHandle::default();
        let mut state = State::new();
        let setup = |since| {
            Job::Setup(Box::new(NostrSetup::On {
                secret: NostrSecret::new([7u8; 32]),
                relays: Vec::new(),
                via_tor: true,
                since,
            }))
        };

        on_job(&mut state, setup(500), &notes, &tor, &events).await;
        assert_eq!(state.since, 500, "отметка приехала с диска");
        on_job(&mut state, setup(100), &notes, &tor, &events).await;
        assert_eq!(state.since, 500, "и не отмотана назад настройкой постарше");
    }

    // --- честность отправки --------------------------------------------------

    /// Отправка через `send_frame` с настоящей подписью.
    async fn send(
        state: &mut State,
        notes: &mpsc::Sender<Note>,
        tor: &TorHandle,
        events: &mpsc::Sender<TransportEvent>,
        frame_len: usize,
    ) {
        let frame = vec![0u8; frame_len];
        let sending = Sending {
            peer_ik: [3u8; 32],
            to: NostrKey::new([5u8; 32]),
            relays: &[],
            frame: &frame,
            handoff: Some(77),
        };
        send_frame(state, sending, notes, tor, events).await;
    }

    /// Состояние с одной связью, очередь которой **читаем мы**.
    ///
    /// Нужен затем, что проверять надо не состояние, а уехавшие байты:
    /// метка сборки лежит в содержимом события открыто, и увидеть её можно
    /// только там, где её увидит реле.
    fn tapped() -> (State, mpsc::Sender<Note>, TorHandle, mpsc::Receiver<String>) {
        let (notes, _) = mpsc::channel(EVENTS);
        let (tx, lines) = mpsc::channel(TO_RELAY);
        let mut state = State::new();
        state.key = Some((NostrKey::new([9u8; 32]), NostrSecret::new([7u8; 32])));
        state.links.insert(
            "ws://127.0.0.1:7001".to_owned(),
            Link { tx, task: tokio::spawn(std::future::ready(())), own: true, used: 1 },
        );
        (state, notes, TorHandle::default(), lines)
    }

    /// Метка сборки из уехавшего события — тем же путём, каким её читает реле.
    fn uid_of(line: &str) -> fragment::Uid {
        let value: serde_json::Value = serde_json::from_str(line).expect("событие — это JSON");
        let content = value[1]["content"].as_str().expect("у события есть содержимое");
        let bytes = nostr::content_decode(content).expect("содержимое — base64url");
        nostr::Part::unwrap(&bytes).expect("в начале — заголовок части").0.uid
    }

    #[tokio::test]
    async fn two_sends_never_share_an_assembly_mark() {
        // Ради этого свойства метка и сделана случайной. Счётчик в памяти
        // начинался заново при каждом запуске, реле отдавало сохранённые
        // события после перезапуска — и части **разных** сообщений сходились
        // у получателя в одну сборку. В журнале стенда это осталось строкой
        // `часть не принята сборщиком error=Inconsistent`.
        let (mut state, notes, tor, mut lines) = tapped();
        let (events, _got) = mpsc::channel(EVENTS);

        send(&mut state, &notes, &tor, &events, 64 * 1024).await;
        let first: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok()).collect();
        send(&mut state, &notes, &tor, &events, 64 * 1024).await;
        let second: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok()).collect();

        assert_eq!(first.len(), 8, "восемь частей");
        assert_eq!(second.len(), 8);

        let one = uid_of(&first[0]);
        let two = uid_of(&second[0]);
        assert_ne!(one, two, "две отправки обязаны получить разные метки");
        assert!(first.iter().all(|line| uid_of(line) == one), "части одной отправки — одна метка");
        assert!(second.iter().all(|line| uid_of(line) == two));
    }

    #[tokio::test]
    async fn the_assembly_mark_tells_the_relay_nothing_about_the_peer() {
        // Заголовок части не зашифрован: он лежит в содержимом события,
        // то есть открыт для реле. Прежняя метка везла в нём восемь байт
        // `IK` получателя — ключа, который живёт дольше ключа nostr и общий
        // для всех ступеней. По нему разговор на реле связался бы с тем же
        // человеком в локальной сети, в меше и в почте; ничего подобного
        // реле не обещано (0.3.3).
        let (mut state, notes, tor, mut lines) = tapped();
        let (events, _got) = mpsc::channel(EVENTS);
        send(&mut state, &notes, &tor, &events, 4 * 1024).await;

        let line = lines.try_recv().expect("событие уехало");
        let uid = uid_of(&line);
        // `send` шлёт собеседнику с `ik = [3u8; 32]`.
        assert!(
            !uid.windows(8).any(|window| window == [3u8; 8]),
            "в метке не должно быть ни куска ключа собеседника: {uid:?}"
        );
    }

    #[tokio::test]
    async fn a_frame_that_fits_the_queue_is_booked_whole() {
        // Опора для двух проверок ниже: без неё «отправка отменена» нельзя
        // отличить от «подпись не построилась», и обе они дали бы один и тот
        // же зелёный цвет по одному и тому же событию отказа.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let (events, mut got) = mpsc::channel(EVENTS);
        // Кадр класса M — восемь частей по `PART_BYTES`.
        send(&mut state, &notes, &tor, &events, 64 * 1024).await;

        assert_eq!(state.outgoing.len(), 1, "учёт отправки заведён");
        assert_eq!(state.flying.len(), 8, "все восемь частей в полёте");
        assert!(got.try_recv().is_err(), "отказа быть не должно");
    }

    #[tokio::test]
    async fn a_frame_that_only_half_fits_the_queue_is_refused_whole() {
        // Ради этого свойства всё и переписано. Не влезшие в очередь части
        // прежде просто выпадали, а учёт заводился на ушедшие — и когда реле
        // подтверждало их все, ядро получало `Handed`, то есть «доставлено»
        // о сообщении, которого собеседник не соберёт никогда.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let (events, mut got) = mpsc::channel(EVENTS);

        // Забиваем очередь реле, оставив место ровно одной части из восьми.
        // Задача реле её не разбирает: она стоит на соединении с пустым
        // портом и до насоса не доходит.
        let tx = state.links["ws://127.0.0.1:7001"].tx.clone();
        for _ in 0..TO_RELAY - 1 {
            tx.try_send("занято".to_owned()).expect("место есть");
        }

        send(&mut state, &notes, &tor, &events, 64 * 1024).await;

        assert!(state.outgoing.is_empty(), "учёта нет — обещать доставку нечем");
        assert!(state.flying.is_empty(), "и частей в полёте не числится");
        assert!(
            matches!(
                got.try_recv(),
                Ok(TransportEvent::ConnectFailed { via: Transport::Nostr, .. })
            ),
            "отказ обязан уехать событием: §5.4 иначе будет ждать вечно"
        );
    }

    #[tokio::test]
    async fn a_cancelled_send_does_not_reuse_the_assembly_mark() {
        // Часть событий при отказе уже ушла на реле. Возьми следующая
        // отправка ту же метку сборки, у получателя её части смешались бы
        // с застрявшими чужими — и собрался бы мусор, а не сообщение.
        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        let (events, _got) = mpsc::channel(EVENTS);
        let tx = state.links["ws://127.0.0.1:7001"].tx.clone();
        for _ in 0..TO_RELAY - 1 {
            tx.try_send("занято".to_owned()).expect("место есть");
        }

        let before = state.next_token;
        send(&mut state, &notes, &tor, &events, 64 * 1024).await;
        assert!(state.next_token > before, "метка сборки занята, а не возвращена");
    }

    #[tokio::test]
    async fn without_a_key_or_switched_off_nothing_is_dialled() {
        // Ключа нет — подписывать нечем, и соединяться незачем. Выключено
        // человеком — тем более: связь, поднятая после выключения, это
        // ступень, работающая вопреки переключателю.
        let (notes, _rx) = mpsc::channel(EVENTS);
        let tor = TorHandle::default();

        let mut bare = State::new();
        assert!(!bare.ensure_link("ws://127.0.0.1:7002", &notes, &tor), "без ключа");

        let (mut state, notes, _rx, tor) = stand(&["ws://127.0.0.1:7001"]);
        state.enabled = false;
        assert!(!state.ensure_link("ws://127.0.0.1:7002", &notes, &tor), "выключено человеком");
        assert_eq!(state.peer_links(), 0);
    }
}
