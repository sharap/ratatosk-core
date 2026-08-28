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
use ratatosk_proto::transport_policy::{PeerAvailability, Transport};
use ratatosk_store::{FileId, Store, StoredFile, StoredMessage, StoredReaction};
use ratatosk_transport::{Runner, TransportCommand, TransportError, TransportEvent};
use tokio::sync::{mpsc, oneshot};

use crate::engine::{Engine, EngineError};
use crate::io::{ChatId, Command, Effect, Event, Input, Swept};
use crate::reader::FileReader;
use ratatosk_transport::runner::PeerAddress;

/// Сколько команд и уведомлений помещается в очередь, прежде чем отправитель
/// начнёт ждать.
const CHANNEL_DEPTH: usize = 64;

/// Сколько раз один вход имеет право породить следующий, прежде чем это
/// перестанет быть лестницей §5.4 и станет кольцом.
///
/// Настоящая глубина мала: отказ транспорта переводит доставку на следующую
/// ступень, ступеней три, и на этом всё. Но отказать может и целая пачка
/// сообщений сразу, каждое своим кругом, поэтому запас взят с избытком —
/// он страховка от ошибки в ядре, а не рабочий предел.
const MAX_FEED_ROUNDS: usize = 256;

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
    /// Обслуживание: меняет состояние **и** отвечает.
    ///
    /// Третий вид появился не для симметрии. Команда ничего не возвращает,
    /// а запрос ничего не меняет — и на этом обещании держится [`Driver::answer`],
    /// который берёт `&self`. Уборке нужно и то, и другое: она стирает файлы
    /// и обязана сказать сколько. Сложить её в команду значило бы отправить
    /// ответ окольным путём через поток событий; сложить в запрос — молча
    /// отменить правило, по которому чтение безопасно.
    Chore(Chore),
}

/// Кому сказать, если транспорт откажет прямо здесь, синхронно.
///
/// Тип, а не пара опций: у отказа три разных адресата, и путать их нельзя.
/// Доставке отказ означает следующую ступень §5.4; человеку, попросившему
/// завести почту, — ответ на его просьбу; всему остальному — ничего.
#[derive(Debug, Clone, Copy)]
enum Refusal {
    /// Сообщение переходит на следующий транспорт (§5.4).
    Delivery {
        /// Кому не доехало.
        peer_ik: [u8; 32],
        /// Каким транспортом.
        via: Transport,
    },
    /// Человек ждёт ящика, и отказ — это ответ ему (§5.3, §14).
    Mailbox,
    /// Сказать некому: эффект ничьей просьбой не был.
    Silent,
}

/// Обслуживание хранилища — по кнопке, а не по расписанию.
enum Chore {
    /// Стереть с диска вложения, которых нет в базе (§12).
    SweepOrphanFiles { reply: oneshot::Sender<Swept> },
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
    /// Вложения. К одному сообщению их может быть несколько (§10).
    pub files: Vec<FileView>,
    /// Присланная карточка контакта, если это сообщение — она.
    pub shared_contact: Option<SharedContactView>,
}

/// Присланная карточка контакта вместе с тем, что о ней уже известно.
///
/// Отпечаток и признак «уже в контактах» считаются здесь, а не в клиенте:
/// вывод отпечатка из `IK ‖ SK` — протокольная логика, а §13.3 держит её
/// ниже границы. Заодно клиенту нечем ошибиться в главном — в том, что
/// показать рядом с именем.
#[derive(Debug, Clone)]
pub struct SharedContactView {
    /// Чей контакт.
    pub peer_ik: [u8; 32],
    /// Имя из карточки. Его выбрал сам владелец, и **доверять ему нельзя**
    /// (§4.1) — как и любому `display_name`.
    pub display_name: String,
    /// Отпечаток для сверки голосом (§3, §4.2).
    ///
    /// Показывать обязательно: это единственное, что человек может проверить
    /// сам, и единственное, что отличает настоящего собеседника от карточки,
    /// которую отправитель сочинил.
    pub fingerprint: String,
    /// Этот человек уже есть в контактах.
    ///
    /// Считается наличием контакта, а не флагом в базе: флаг разошёлся бы
    /// с правдой в первый же раз, когда контакт добавят из QR или удалят.
    pub already_known: bool,
}

/// Вложение вместе с тем, сколько его уже приехало.
///
/// Счётчик считается здесь, а не отдельным запросом на каждый файл: иначе
/// экран чата с десятком вложений стоил бы десяти проходов через границу
/// §13.3 ради одного числа.
#[derive(Debug, Clone)]
pub struct FileView {
    /// Что за файл.
    pub file: StoredFile,
    /// Сколько чанков уже принято. У исходящего и у собранного — все.
    pub received_chunks: u64,
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
    /// Открыть вложение на чтение (§10.2).
    ///
    /// Один заход на файл, а не на кусок. Дальше клиент читает через
    /// [`FileReader`] из своего потока, и очередь драйвера в этом
    /// не участвует — иначе открытие вложения на полгигабайта останавливало
    /// бы отправку сообщений на всё время расшифровки.
    OpenFile { file_id: FileId, reply: oneshot::Sender<Option<FileReader>> },
    /// Порог автоматического приёма файлов.
    AutoAccept { reply: oneshot::Sender<Option<u64>> },
    /// Какие транспорты сейчас включены (§5.4).
    ///
    /// Запросом, а не памятью клиента: выбор переживает перезапуск в `meta`,
    /// и второй его экземпляр в настройках приложения однажды разошёлся бы
    /// с тем, по которому ядро принимает решения.
    Transports { reply: oneshot::Sender<TransportStatus> },
    /// Настройки почтового ящика, если он заведён (§5.3).
    ///
    /// **Вместе с паролем**, и это не оплошность. Пароль мог выдать сервер
    /// при регистрации, и человек не видел его никогда; не показав, мы
    /// оставили бы его без единственного способа войти в свою же почту
    /// с другого устройства или после переустановки.
    MailAccount { reply: oneshot::Sender<Option<ratatosk_proto::mail::MailAccount>> },
    /// Своя карточка прямо сейчас — ссылка и её версия (§4.1, §4.3).
    ///
    /// Запросом, а не значением, полученным при открытии: адреса появляются
    /// позже старта (§5.2), версия карточки при этом растёт, и ссылка,
    /// показанная на экране, перестаёт быть той, что уедет к собеседнику.
    /// Показывать устаревший QR — обещать адрес, которого в нём нет.
    OwnCard { reply: oneshot::Sender<OwnCard> },
    /// Поиск по словам (§12).
    ///
    /// `chat` = `None` — по всей переписке. Возвращает сами сообщения, а не
    /// идентификаторы: клиент их и показывает, а второй заход через границу
    /// §13.3 за каждой находкой был бы ровно тем, чего [`MessageView`]
    /// и создан избежать.
    Search {
        chat: Option<ChatId>,
        query: String,
        limit: usize,
        reply: oneshot::Sender<Vec<MessageView>>,
    },
    /// Превью вложения (§10.3).
    FilePreview { file_id: FileId, reply: oneshot::Sender<Option<Vec<u8>>> },
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

/// Своя карточка в том виде, в каком её показывают человеку.
///
/// Отдельная структура, а не `ContactCard`: наружу отдаётся готовая ссылка
/// и то, по чему видно, изменилась ли она, — ключи в UI не нужны, а версия
/// нужна, потому что по ней клиент понимает, что показанный QR устарел.
#[derive(Debug, Clone)]
pub struct OwnCard {
    /// Ссылка `ratatosk:v0:…` — она же содержимое QR (§4.1).
    pub uri: String,
    /// Версия карточки (§4.3). Растёт при каждой смене адресов.
    pub version: u64,
    /// Onion-адрес. Пустая строка — «ещё нет».
    pub onion: String,
    /// Почтовый адрес. Пустая строка — «ещё нет».
    pub chatmail: String,
}

/// Состояние транспортов на этом устройстве (§5.4).
///
/// Два набора, а не один, и разница видна человеку: «включён» — выбор,
/// «работает» — состояние. Включённый Tor становится работающим через
/// десятки секунд, и всё это время §5.4 его не выбирает; клиенту это нужно,
/// чтобы сказать «поднимается» вместо «не работает».
/// `Copy` здесь больше нет, и это не потеря. Он стоял, пока в структуре
/// лежали два набора битов; с появлением строк — последней новости Tor
/// и причины отказа почты — копировать её молча стало нельзя, а нужды
/// в этом нет: её берут целиком, один раз, и разбирают на месте.
#[derive(Debug, Clone)]
pub struct TransportStatus {
    /// Что разрешил человек. Переживает перезапуск.
    pub enabled: ratatosk_proto::TransportSet,
    /// Что уже работает. Состояние сеанса, на диск не идёт.
    pub ready: ratatosk_proto::TransportSet,
    /// Последнее, что сказал о себе Tor.
    ///
    /// Запросом, а не только событием, и это не удобство. Событие
    /// существует один раз: клиент, открывший экран настроек через минуту
    /// после подъёма, не увидит ничего и покажет пустоту вместо «работает».
    /// А человек, зашедший туда, спрашивает ровно одно — «почему не идёт», —
    /// и ответ обязан быть на экране, а не в пропущенном уведомлении.
    pub tor: Option<TorNote>,
    /// Почему не работает почта, если она не работает.
    ///
    /// Та же причина, что и у `tor`, и та же беда без этого поля: «включена,
    /// ящик заведён, а сообщения не уходят» — состояние, которое человек
    /// не может ни объяснить, ни исправить, пока ему не сказали, что сервер
    /// не пустил и почему.
    ///
    /// `None` означает «жаловаться не на что»: либо работает, либо ещё
    /// не пробовали.
    pub mail_failure: Option<String>,
    /// Что почтовый сервер сказал о своих пределах.
    ///
    /// Запросом, а не только событием, и по той же причине, что у `tor`:
    /// событие приходит в момент входа, а на экран настроек человек
    /// заглядывает когда угодно.
    ///
    /// Пустые поля означают «не спрашивали или сервер не назвал». Показывать
    /// такое нечего — и не надо: «предел: неизвестно» человеку не говорит
    /// ничего, а место на экране занимает.
    pub mail_limits: ratatosk_proto::mail::MailLimits,
}

/// Последнее, что Tor сказал о себе (§5.2, §13.1).
///
/// То же самое, что уезжает событием `Event::TorStatus`, — но доступное
/// в любой момент. Оба нужны: событие двигает индикатор, запрос отвечает
/// тому, кто пришёл смотреть позже.
#[derive(Debug, Clone)]
pub struct TorNote {
    /// Доля готовности, от 0 до 1.
    pub fraction: f32,
    /// Что происходит сейчас — словами arti.
    pub note: String,
    /// Почему подъём стоит, если он стоит.
    pub blocked: Option<String>,
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
    /// Та же доступность, разложенная по ступеням, с готовым вердиктом.
    ///
    /// Считается **здесь**, а не у того, кто спрашивает, и это исправление
    /// настоящего расхождения: стенд печатал в `/who` свою копию лестницы
    /// §5.4, клиент завёл бы третью. Копии расходятся при первом же
    /// добавлении ступени, и расходятся молча — экран говорит одно,
    /// а уезжает другое.
    pub reachability: ratatosk_proto::transport_policy::Reachability,
    /// Есть ли у него аватарка, которую **можно показать**.
    ///
    /// Учитывает §4.2: у несверенного контакта аватарка может лежать
    /// в хранилище, но здесь всё равно будет `false` — показывать её нельзя,
    /// а обещать клиенту картинку, которой он не получит, незачем.
    pub has_avatar: bool,
    /// Onion-адрес из карточки (§5.2). `None` — адреса нет.
    ///
    /// Пустая строка в карточке означает «адреса нет», и превращать её
    /// в `None` здесь, а не оставлять клиенту, — то же правило §13.3:
    /// «пусто» и «нет» различает протокол, а не UI.
    pub onion: Option<String>,
    /// Chatmail-адрес из карточки (§5.3). `None` — адреса нет.
    ///
    /// Отвечает на вопрос, который иначе не задать: дойдёт ли до человека
    /// сообщение, пока он не в сети. Без почтового адреса — нет.
    pub chatmail: Option<String>,
    /// Версия карточки, монотонная (§4.3).
    ///
    /// Диагностическая величина: по ней видно, доехало ли до нас обновление
    /// адресов. Показывать её в списке контактов незачем; на экране
    /// «почему не доходит» — есть зачем.
    pub card_version: u64,
    /// Когда контакт добавили, мс.
    pub added_ms: u64,
    /// Живой прямой канал, если он есть (§5.4).
    ///
    /// **Не то же, что `seen_on_lan`.** Маяк говорит «устройство в эфире»,
    /// а это — «сессия установлена, кадры пойдут сейчас». Между ними
    /// рукопожатие, и на медленном канале это заметные секунды.
    ///
    /// `None` при живой почте — обычное дело и не беда: почта прямым
    /// каналом не бывает по устройству (§9.4).
    pub direct_channel: Option<Transport>,
    /// Сколько кадров от этого источника отброшено (§7.3, шаг 4).
    ///
    /// Считалось с самого начала и не показывалось никому. Это единственный
    /// признак того, что кто-то шлёт на устройство мусор от имени контакта:
    /// в переписке этого не видно — такие кадры отбрасываются до неё.
    /// В памяти, обнуляется перезапуском.
    pub anomalies: ratatosk_proto::session::AnomalyCounters,
}

/// Что разбудило цикл. Существует только затем, чтобы решение принималось
/// после `select!`, а не внутри его ветки.
enum Wake {
    Input(Input),
    Query(Query),
    Chore(Chore),
    Timers,
    Stop,
    /// Tor опубликовал сервис: ступень заработала, и у неё есть адрес.
    ///
    /// Отдельная ветка, а не готовый [`Input`], по двум причинам сразу.
    /// Во-первых, отсюда рождаются **два** входа, и порядок между ними
    /// важен: сперва §5.4 узнаёт, что ступень заработала, потом контакты
    /// узнают адрес. Во-вторых, команда объявления несёт карточку целиком —
    /// и onion, и почту; транспорт знает только свою половину, вторую надо
    /// взять у ядра, а до ядра в ветке `select!` не дотянуться.
    TorReady(String),
    /// Новость для UI, которой ядро не касается вовсе.
    ///
    /// Ход подъёма Tor — не состояние протокола: ни одно решение §5.4
    /// на него не опирается, и заводить ради него вход в ядро значило бы
    /// провести через `Engine::step` то, что там нечего делать.
    Notice(Event),
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
            Request::Query(_) | Request::Chore(_) => {
                unreachable!("послали команду — вернулась не она")
            }
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

    /// Какие транспорты включены и какие работают (§5.4).
    /// `None` — драйвер остановлен.
    pub async fn transports(&self) -> Option<TransportStatus> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Query(Query::Transports { reply })).await.ok()?;
        answer.await.ok()
    }

    /// То же, блокируя вызывающий поток.
    pub fn transports_blocking(&self) -> Option<TransportStatus> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::Transports { reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Настройки почтового ящика (§5.3). `None` — драйвер остановлен.
    ///
    /// Внешний `Option` означает «драйвер остановлен», внутренний — «ящика
    /// нет». Разница видна вызывающему, и путать их нельзя: первое —
    /// поломка, второе — обычное состояние из коробки.
    pub async fn mail_account(&self) -> Option<Option<ratatosk_proto::mail::MailAccount>> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Query(Query::MailAccount { reply })).await.ok()?;
        answer.await.ok()
    }

    /// То же, блокируя вызывающий поток.
    pub fn mail_account_blocking(&self) -> Option<Option<ratatosk_proto::mail::MailAccount>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::MailAccount { reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает свою карточку (§4.1). `None` — драйвер остановлен.
    ///
    /// Именно запросом, а не значением, взятым при открытии: адреса
    /// появляются позже старта (§5.2), и снимок, сделанный один раз,
    /// врёт ровно про то, ради чего карточку и показывают.
    pub async fn own_card(&self) -> Option<OwnCard> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Query(Query::OwnCard { reply })).await.ok()?;
        answer.await.ok()
    }

    /// Ищет сообщения по словам (§12). `None` — драйвер остановлен.
    pub async fn search(
        &self,
        chat: Option<ChatId>,
        query: String,
        limit: usize,
    ) -> Option<Vec<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(Request::Query(Query::Search { chat, query, limit, reply }))
            .await
            .ok()?;
        answer.await.ok()
    }

    /// Стирает с диска вложения, которых нет в базе (§12).
    ///
    /// `None` — драйвер остановлен.
    pub async fn sweep_orphan_files(&self) -> Option<Swept> {
        let (reply, answer) = oneshot::channel();
        self.requests.send(Request::Chore(Chore::SweepOrphanFiles { reply })).await.ok()?;
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
            Request::Query(_) | Request::Chore(_) => {
                unreachable!("послали команду — вернулась не она")
            }
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

    /// Открывает вложение на чтение — один заход на файл, а не на кусок.
    ///
    /// Внешний `None` — драйвер остановлен, внутренний — такого файла нет.
    /// Полученным [`FileReader`] можно пользоваться из любого потока и
    /// сколько угодно долго: ядро в чтении не участвует.
    pub fn open_file_blocking(&self, file_id: FileId) -> Option<Option<FileReader>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::OpenFile { file_id, reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает превью вложения.
    pub fn file_preview_blocking(&self, file_id: FileId) -> Option<Option<Vec<u8>>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::FilePreview { file_id, reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Стирает с диска вложения, которых нет в базе (§12).
    ///
    /// `None` — драйвер остановлен. Дорогая операция: обходит каталог
    /// вложений целиком, поэтому зовётся по кнопке «освободить место»,
    /// а не при каждом запуске.
    pub fn sweep_orphan_files_blocking(&self) -> Option<Swept> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Chore(Chore::SweepOrphanFiles { reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Ищет сообщения по словам (§12).
    ///
    /// `chat = None` — по всей переписке. Ищутся **целые слова**: индекс
    /// хранит их хэши на ключе базы, поэтому ни префиксов, ни подстрок тут
    /// нет и быть не может.
    pub fn search_blocking(
        &self,
        chat: Option<ChatId>,
        query: String,
        limit: usize,
    ) -> Option<Vec<MessageView>> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .blocking_send(Request::Query(Query::Search { chat, query, limit, reply }))
            .ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает свою карточку, блокируя вызывающий поток.
    pub fn own_card_blocking(&self) -> Option<OwnCard> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::OwnCard { reply })).ok()?;
        answer.blocking_recv().ok()
    }

    /// Читает порог автоматического приёма файлов.
    pub fn auto_accept_blocking(&self) -> Option<Option<u64>> {
        let (reply, answer) = oneshot::channel();
        self.requests.blocking_send(Request::Query(Query::AutoAccept { reply })).ok()?;
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
    /// Последняя новость от Tor — чтобы её мог спросить и опоздавший.
    ///
    /// Живёт в драйвере, а не в ядре, и намеренно: ни одно решение §5.4
    /// на неё не опирается. Это состояние показа, и место ему там же,
    /// где очередь уведомлений.
    tor_note: Option<TorNote>,
    /// Последнее, что почтовый сервер сказал о своих пределах.
    ///
    /// Кэш ровно того же назначения, что `tor_note`: событие двигает
    /// индикатор, запрос отвечает тому, кто пришёл смотреть позже.
    mail_limits: ratatosk_proto::mail::MailLimits,
    /// Последняя жалоба почты, если она не работает.
    mail_failure: Option<String>,
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
            tor_note: None,
            mail_limits: ratatosk_proto::mail::MailLimits::default(),
            mail_failure: None,
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
        // Первое, что делает драйвер, — доносит до транспортов то, что человек
        // решил в прошлый раз (§5.4). До этого момента сказать было некому:
        // `Engine::restore` зовётся раньше драйвера и эффектов не возвращает.
        //
        // Клиент, выставляющий переключатели при старте, ничего не портит:
        // повтор того же значения ядро отбрасывает молча.
        let now = now_ms();
        for effect in self.engine.startup_effects() {
            if let Some(failed) = self.apply(now, effect).await {
                // Ответить на это некому и нечем: соединений ещё нет,
                // доставок тоже. Но промолчать нельзя — это первый признак
                // того, что транспорт не собрался.
                let _ = failed;
                tracing::debug!("транспорт отказался включаться при старте");
            }
        }

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
                    Some(event) => translate(event),
                    None => Wake::Stop,
                },
                request = self.requests.recv() => match request {
                    Some(Request::Command(command)) => Wake::Input(Input::Command(command)),
                    Some(Request::Query(query)) => Wake::Query(query),
                    Some(Request::Chore(chore)) => Wake::Chore(chore),
                    None => Wake::Stop,
                },
                () = sleep_until(deadline) => Wake::Timers,
            };

            match wake {
                Wake::Input(input) => {
                    // Почта заработала — прежней жалобе конец. Оставленная,
                    // она пережила бы починку и объясняла бы человеку беду,
                    // которой уже нет.
                    if matches!(input, Input::TransportReady { transport: Transport::Mail }) {
                        self.mail_failure = None;
                    }
                    self.tolerate(input).await?;
                }
                Wake::Query(query) => self.answer(query),
                Wake::Chore(chore) => self.do_chore(chore),
                Wake::Timers => self.fire_due_timers().await?,
                Wake::Notice(event) => {
                    // Новость не только уезжает, но и запоминается: экран,
                    // открытый позже, спросит `Query::Transports` и получит
                    // то же самое. Без этого «почему не работает» отвечалось
                    // бы только тем, кто смотрел в нужную секунду.
                    match &event {
                        Event::TorStatus { fraction, note, blocked } => {
                            self.tor_note = Some(TorNote {
                                fraction: *fraction,
                                note: note.clone(),
                                blocked: blocked.clone(),
                            });
                        }
                        Event::MailLoginFailed { reason } => {
                            self.mail_failure = Some(reason.clone());
                        }
                        Event::MailLimits { letter_bytes, mailbox_used, mailbox_limit, .. } => {
                            // Выводы (`crowded`, `carries_files`) не хранятся:
                            // они считаются из этих же трёх чисел правилом
                            // из `proto::mail`, и вторая их копия однажды
                            // разошлась бы с первой.
                            self.mail_limits = ratatosk_proto::mail::MailLimits {
                                letter_bytes: *letter_bytes,
                                mailbox_used: *mailbox_used,
                                mailbox_limit: *mailbox_limit,
                            };
                        }
                        _ => {}
                    }
                    // Тот же путь, что и у уведомлений ядра: переполненная
                    // очередь UI не вправе останавливать протокол.
                    if self.notices.try_send(event).is_err() {
                        tracing::debug!("очередь событий UI переполнена, новость отброшена");
                    }
                }
                Wake::TorReady(onion) => {
                    // Два действия, и порядок между ними важен.
                    //
                    // Сперва §5.4 узнаёт, что ступень заработала: до этого
                    // момента onion в лестнице не участвовал, и всё, что
                    // ждало, ждало именно этого. Объяви мы сначала адрес,
                    // рассылка §4.3 пошла бы по ступени, которую ядро ещё
                    // считает неготовой, — и легла бы в ожидание.
                    self.tolerate(Input::TransportReady { transport: Transport::Onion }).await?;

                    // Почта здесь не называется вовсе. Раньше её приходилось
                    // доставать из текущей карточки, потому что команда
                    // требовала обе половины и пустая строка означала «нет»;
                    // теперь «не трогать» выразимо, и обход не нужен.
                    let command = Command::AnnounceAddresses { onion: Some(onion), chatmail: None };
                    self.tolerate(Input::Command(command)).await?;
                }
                Wake::Stop => return Ok(()),
            }

            // Уборка (§12) — по событию, а не по таймеру: телефон
            // значительную часть времени спит (§13.1), и таймер там
            // не гарантирует ничего, а этот цикл всё равно просыпается
            // на каждое сообщение. Само решение «пора или нет» принимает
            // ядро; здесь только повод спросить.
            //
            // Отказ хранилища тут не роняет драйвер: не прибраться —
            // не то же самое, что не доставить сообщение.
            match self.engine.compact_if_due(now_ms()) {
                Ok(0) => {}
                Ok(removed) => tracing::debug!(removed, "уборка прошла"),
                Err(error) => tracing::warn!(%error, "уборка не удалась"),
            }
        }
    }

    /// Выполняет обслуживание и отвечает, что вышло.
    ///
    /// Идёт той же очередью, что команды и запросы, — то есть **между**
    /// шагами ядра, а не посреди одного. Для уборки это не деталь: чанк
    /// ложится на диск и отмечается в базе внутри одного шага, и уборка,
    /// вклинившаяся между этими двумя операциями, сочла бы живой чанк мусором.
    fn do_chore(&mut self, chore: Chore) {
        match chore {
            Chore::SweepOrphanFiles { reply } => {
                // Отказ диска здесь — не повод ронять мессенджер: убранное
                // до отказа убрано, остальное подберёт следующий запуск.
                // Человек увидит нули и повторит.
                let swept = self.engine.sweep_orphan_files().unwrap_or_else(|error| {
                    tracing::warn!(?error, "уборка осиротевших вложений не доделана");
                    Swept::default()
                });
                let _ = reply.send(swept);
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
                    let files = Self::file_views(store, &message.msg_id);
                    let shared_contact = self.shared_contact_view(&message.msg_id);
                    MessageView { message, reactions, files, shared_contact }
                });
                let _ = reply.send(found);
            }
            Query::OpenFile { file_id, reply } => {
                // Отказ хранилища здесь неотличим от «такого файла нет», и это
                // единственное честное поведение: показать нечего в обоих
                // случаях, а ронять чат из-за вложения нельзя.
                let _ = reply.send(self.engine.open_file(&file_id).unwrap_or_default());
            }
            Query::AutoAccept { reply } => {
                let _ = reply.send(self.engine.auto_accept_bytes());
            }
            Query::Transports { reply } => {
                let _ = reply.send(TransportStatus {
                    enabled: self.engine.transports(),
                    ready: self.engine.transports_ready(),
                    tor: self.tor_note.clone(),
                    mail_failure: self.mail_failure.clone(),
                    mail_limits: self.mail_limits,
                });
            }
            Query::MailAccount { reply } => {
                let _ = reply.send(self.engine.mail_account().cloned());
            }
            Query::OwnCard { reply } => {
                let card = self.engine.own_card();
                // Кодирование карточки может отказать только на испорченной
                // памяти, но ронять из-за него ядро нечего: пустая ссылка
                // видна на экране сразу, а упавший драйвер уносит с собой
                // переписку.
                let _ = reply.send(OwnCard {
                    uri: card.to_uri().unwrap_or_default(),
                    version: card.version,
                    onion: card.onion,
                    chatmail: card.chatmail,
                });
            }
            Query::Search { chat, query, limit, reply } => {
                let store = self.engine.store();
                let found = store
                    .search(chat.as_ref(), &query, limit)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|msg_id| {
                        // Находка без сообщения — рассинхрон индекса
                        // с историей. Пропускаем молча: показать её нечем,
                        // а ронять поиск целиком из-за одной строки незачем.
                        let message = store.message(&msg_id).ok().flatten()?;
                        let reactions = store.reactions(&msg_id).unwrap_or_default();
                        let files = Self::file_views(store, &msg_id);
                        let shared_contact = self.shared_contact_view(&msg_id);
                        Some(MessageView { message, reactions, files, shared_contact })
                    })
                    .collect();
                let _ = reply.send(found);
            }
            Query::FilePreview { file_id, reply } => {
                let found =
                    self.engine.store().file(&file_id).ok().flatten().and_then(|f| f.preview);
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
                // Список собирается в два прохода, и не по прихоти: сессии
                // и аномалии спрашиваются у ядра, а `contacts()` держит
                // на нём заимствование. Копия ключей стоит тридцати двух
                // байт на контакт и снимает вопрос целиком.
                let peers: Vec<[u8; 32]> = self.engine.contacts().keys().copied().collect();
                let extras: BTreeMap<[u8; 32], (Option<Transport>, _)> = peers
                    .iter()
                    .map(|peer_ik| {
                        // Прямой канал — тот же вопрос, что задаёт §5.4,
                        // и заданный тем же способом: первая прямая ступень,
                        // на которой есть сессия.
                        let direct = [Transport::Lan, Transport::Onion]
                            .into_iter()
                            .find(|via| self.engine.session_for(peer_ik, *via).is_some());
                        (*peer_ik, (direct, self.engine.anomalies(peer_ik)))
                    })
                    .collect();
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
                        reachability: ratatosk_proto::transport_policy::Reachability::of(
                            contact.availability,
                        ),
                        // §4.2: у несверенного показывать нечего, даже если
                        // байты лежат. Правило одно и то же здесь и в
                        // `Engine::avatar_of` — разойдясь, они дали бы кружок
                        // с заглушкой вместо картинки, которая «вот-вот».
                        has_avatar: contact.has_avatar && contact.verified,
                        // Пустая строка в карточке означает «адреса нет».
                        onion: none_if_empty(&contact.card.onion),
                        chatmail: none_if_empty(&contact.card.chatmail),
                        card_version: contact.card.version,
                        added_ms: contact.added_ms,
                        direct_channel: extras.get(peer_ik).and_then(|(direct, _)| *direct),
                        anomalies: extras
                            .get(peer_ik)
                            .map(|(_, anomalies)| *anomalies)
                            .unwrap_or_default(),
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
                // реакций читается, реакции без сообщения — нет. То же и
                // с вложениями.
                let reactions = store.reactions(&message.msg_id).unwrap_or_default();
                let files = Self::file_views(store, &message.msg_id);
                let shared_contact = self.shared_contact_view(&message.msg_id);
                MessageView { message, reactions, files, shared_contact }
            })
            .collect()
    }

    /// Вложения сообщения вместе с ходом их передачи.
    fn file_views(store: &S, msg_id: &MsgId) -> Vec<FileView> {
        store
            .files_of(msg_id)
            .unwrap_or_default()
            .into_iter()
            .map(|file| {
                // Своё и собранное считаются полными без запроса: у первого
                // чанков «принято» не бывает вовсе, у второго они все на месте.
                let received_chunks = if !file.incoming || file.complete {
                    file.chunk_total
                } else {
                    store.received_chunks(&file.file_id).unwrap_or(0)
                };
                FileView { file, received_chunks }
            })
            .collect()
    }

    /// Присланная карточка контакта, если это сообщение — она.
    ///
    /// Берёт `&self`, а не `&S`, в отличие от [`Driver::file_views`]: признак
    /// «уже в контактах» знает ядро, а не хранилище, — контакты лежат в памяти
    /// движка.
    fn shared_contact_view(&self, msg_id: &MsgId) -> Option<SharedContactView> {
        let share = self.engine.store().contact_share_of(msg_id).ok().flatten()?;
        // Карточку разбираем каждый раз заново, а не храним разобранной:
        // §6 требует читать принятые байты, и второе представление рядом
        // однажды разошлось бы с первым.
        let card = ratatosk_codec::ContactCard::decode(&share.card_bytes).ok()?.into_parts().1;
        // Отпечаток не сложился — показывать нечего: такую карточку и добавить
        // нельзя. Прятать её целиком честнее, чем рисовать имя без отпечатка.
        let fingerprint =
            ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk).ok()?.fingerprint();
        Some(SharedContactView {
            peer_ik: card.ik,
            display_name: card.display_name,
            fingerprint,
            already_known: self.engine.contacts().contains_key(&card.ik),
        })
    }

    /// Подаёт вход ядру и исполняет всё, что оно вернуло.
    async fn feed(&mut self, input: Input) -> Result<(), EngineError> {
        // Очередь, а не рекурсия: отказ транспорта рождает новый вход, тот —
        // новые эффекты, и так пока лестница §5.4 не кончится. Рекурсивный
        // `async fn` пришлось бы боксировать на каждом обороте, а тут хватает
        // очереди из нескольких элементов.
        let mut inputs = std::collections::VecDeque::from([input]);
        let mut rounds = 0usize;
        while let Some(input) = inputs.pop_front() {
            rounds += 1;
            if rounds > MAX_FEED_ROUNDS {
                // Кольцо эффектов. Оборвать и сказать вслух: молча крутиться
                // тут значит съесть процессор телефона на ровном месте.
                tracing::error!(rounds, "кольцо эффектов в драйвере — обрываю круг");
                return Ok(());
            }
            let now_ms = now_ms();
            for effect in self.engine.step(now_ms, input)? {
                if let Some(failed) = self.apply(now_ms, effect).await {
                    inputs.push_back(failed);
                }
            }
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
    /// Отвергнутая **команда** вдобавок доезжает до человека словами
    /// ([`Event::CommandRefused`]).
    ///
    /// Раньше она оставалась строкой в журнале, и это была настоящая
    /// поломка честности, найденная на стенде: человек ошибся в ссылке
    /// на регистрацию почты, ядро внятно отказало — «в ссылке нет имени
    /// сервера», — а на экране не появилось ничего. Он видел «пошли
    /// за ящиком» и тишину.
    ///
    /// Кадры и таймеры так не сообщаются намеренно: их отказы — чужие
    /// ошибки и сетевой мусор (§7.3), а не действие человека, и вываливать
    /// их на экран значило бы приучить не читать.
    async fn tolerate(&mut self, input: Input) -> Result<(), EngineError> {
        let was_command = matches!(input, Input::Command(_));
        match self.feed(input).await {
            Ok(()) => Ok(()),
            Err(error @ EngineError::Store(_)) => Err(error),
            Err(error) => {
                tracing::warn!(%error, "вход отвергнут ядром");
                if was_command
                    && self
                        .notices
                        .try_send(Event::CommandRefused { reason: error.to_string() })
                        .is_err()
                {
                    tracing::debug!("очередь событий UI переполнена, отказ не показан");
                }
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

    /// Исполняет один эффект.
    ///
    /// Возвращает вход, который надо подать ядру следом: транспорт отказал
    /// прямо здесь, синхронно. Ядру про такой отказ надо сказать тем же
    /// входом, каким сказал бы сам транспорт, случись отказ позже.
    async fn apply(&mut self, now_ms: u64, effect: Effect) -> Option<Input> {
        // Как сообщать об отказе — решается до того, как эффект разберут
        // на части: `frame` уезжает в команду, а ключ и транспорт нужны после.
        let refusal = match &effect {
            Effect::Send { peer_ik, via, .. } | Effect::Connect { peer_ik, via } => {
                Refusal::Delivery { peer_ik: *peer_ik, via: *via }
            }
            // Человек нажал «завести почту» и ждёт ответа. Отказ транспорта
            // — это и есть ответ, и он обязан до него доехать: раньше здесь
            // была только строка в журнале, а на экране не появлялось
            // ничего. Найдено на стенде, где почтового раннера ещё нет
            // вовсе и отказ приходит на каждую попытку.
            Effect::CreateMailAccount { .. } => Refusal::Mailbox,
            Effect::SetTransportEnabled { .. }
            | Effect::SetMailAccount(_)
            | Effect::WatchLanPeers(_)
            | Effect::RestartLan
            | Effect::SetTimer { .. }
            | Effect::Notify(_) => Refusal::Silent,
        };

        let command = match effect {
            Effect::Send { peer_ik, via, frame, handoff } => {
                Some(TransportCommand::Send { peer: self.address_of(peer_ik), via, frame, handoff })
            }
            Effect::Connect { peer_ik, via } => {
                Some(TransportCommand::Connect { peer: self.address_of(peer_ik), via })
            }
            Effect::SetTransportEnabled { transport, enabled } => {
                Some(TransportCommand::SetEnabled { transport, enabled })
            }
            Effect::SetMailAccount(account) => Some(TransportCommand::SetMailAccount(account)),
            Effect::CreateMailAccount { url, via_tor } => {
                Some(TransportCommand::CreateMailAccount { url, via_tor })
            }
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
        let Some(command) = command else { return None };
        let Err(error) = self.runner.execute(command).await else { return None };

        // Отказ транспорта — не отказ ядра: сообщение остаётся в очереди
        // и уходит следующим транспортом по §5.4. Но узнать об этом ядро
        // обязано **сейчас**, а не по сроку ожидания ответа.
        //
        // Раньше здесь стояла только эта запись в журнал, и она была
        // неправдой: «переходим к следующему» никто не делал. Ядро ничего
        // не знало об отказе и честно ждало ответа — а ответить было некому,
        // потому что кадр никуда не уехал. Каждое сообщение платило полным
        // сроком (§5.4) за отказ, случившийся мгновенно, и на стенде это
        // выглядело как пачка «ждём, когда появится» через полторы минуты
        // после отправки.
        // «Занято» — не отказ. Очередь записи забита большой передачей,
        // соединение живо и пишет; увести доставку на следующую ступень
        // из-за затора значило бы лечить медлительность разрывом.
        if matches!(error, TransportError::Busy) {
            tracing::debug!("транспорт занят — ступень не меняем");
            return None;
        }

        tracing::debug!(?error, "транспорт отказал, переходим к следующему");
        match refusal {
            // Повтор безвреден: тот же отказ может приехать ещё раз событием
            // от самого транспорта (LAN так и делает), но ядро сверяет
            // транспорт с тем, на котором сообщение сейчас, — а оно к тому
            // моменту уже на следующей ступени, и второй отказ ничего
            // не сжигает.
            Refusal::Delivery { peer_ik, via } => Some(Input::ConnectionLost { peer_ik, via }),
            Refusal::Mailbox => Some(Input::MailAccountFailed { reason: error.to_string() }),
            Refusal::Silent => None,
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

/// Переводит событие транспорта в то, что с ним будет делать цикл.
///
/// Возвращает [`Wake`], а не [`Input`], из-за единственного случая: подъём
/// onion-сервиса приводит не к входу в ядро, а к команде, которую надо
/// собрать, заглянув в ядро. Раньше на его месте стоял `Input::Timer`
/// с нулевой меткой — то есть событие молча выбрасывалось.
fn translate(event: TransportEvent) -> Wake {
    let input = match event {
        TransportEvent::Received { via, frame, .. } => Input::Received { via, frame },
        TransportEvent::Connected { peer_ik, via } => Input::Connected { peer_ik, via },
        TransportEvent::Disconnected { peer_ik, via }
        | TransportEvent::ConnectFailed { peer_ik, via } => Input::ConnectionLost { peer_ik, via },
        TransportEvent::SeenOnLan { peer_ik } => Input::SeenOnLan { peer_ik },
        TransportEvent::TorReady { onion } => return Wake::TorReady(onion),
        TransportEvent::TorProgress { fraction, note, blocked } => {
            return Wake::Notice(Event::TorStatus { fraction, note, blocked })
        }
        TransportEvent::MailAccountCreated { address, password } => {
            Input::MailAccountCreated { address, password }
        }
        TransportEvent::MailAccountFailed { reason } => Input::MailAccountFailed { reason },
        TransportEvent::Handed { peer_ik, via, handoff } => Input::Handed { peer_ik, via, handoff },
        TransportEvent::Ready { transport } => Input::TransportReady { transport },
        // Через ядро, а не мимо: от этих чисел зависят два его решения —
        // пускать ли почту в выбор канала для файла и просить ли чанки
        // в свой кончающийся ящик. Показ — уже следствие, и приезжает
        // он одним сведённым событием (`Engine::tell_mail_limits`).
        TransportEvent::MailLetterLimit { bytes } => Input::MailLetterLimit { bytes },
        TransportEvent::MailQuota { used_bytes, limit_bytes } => {
            Input::MailQuota { used_bytes, limit_bytes }
        }
        // Мимо ядра: не сумевшая войти почта просто не становится ступенью,
        // и §5.4 ведёт себя ровно так же, как до заведения ящика. Сказать
        // об этом надо человеку, а не протоколу.
        TransportEvent::MailLoginFailed { reason } => {
            return Wake::Notice(Event::MailLoginFailed { reason })
        }
    };
    Wake::Input(input)
}

/// Пустая строка — это «нет», и различать их обязан не клиент.
///
/// В карточке (§6) отсутствие адреса выражено пустой строкой: у CBOR-карты
/// нет «поля, которого нет», и заводить его ради двух полей незачем.
/// Но выше границы §13.3 пустая строка — приглашение показать пустой адрес
/// вместо «адреса нет», и первый же клиент это приглашение примет.
fn none_if_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
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
