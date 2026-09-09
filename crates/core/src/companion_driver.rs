//! Среда вокруг терминала компаньона: транспорт, часы, диск (§13.4).
//!
//! # Зачем он появился
//!
//! [`CompanionClient`] — sans-io, как и [`Engine`](crate::Engine): вход,
//! состояние, эффекты. Это правильно и это неполно. Между ним и человеком
//! лежит всё то, чего у него нет: сокет, повтор рукопожатия по времени,
//! файл кэша, чтение и запись вложений. Написано это было **в стенде** —
//! и там бы и осталось, если бы десктоп был на Rust.
//!
//! Десктоп на Kotlin Compose, и планшет-компаньон на Android — тоже.
//! Значит между ядром и UI будет UniFFI, а через неё sans-io не пролезает:
//! отдавать наружу `ClientEffect::Send(Vec<u8>)` значит просить Kotlin
//! говорить в сокет протокольными кадрами — то есть ровно та протокольная
//! логика выше границы, которую §13.3 запрещает без исключений.
//!
//! Поэтому среда переезжает сюда, а UI получает то же, что получает UI
//! телефона: команды внутрь, события наружу, и никакого доступа к кадрам.
//!
//! # Что здесь живёт, а что нет
//!
//! Здесь: круг событий транспорта, повтор рукопожатия с отступлением, снимок
//! кэша на диск, чтение отправляемого файла и запись забираемого.
//!
//! Не здесь: решения. Какой кусок просить следующим, что делать с ответом
//! не на ту просьбу, когда выгрузка кончилась — всё это в
//! [`CompanionClient`], и подниматься сюда ему незачем.
//!
//! # Байты файлов границу не пересекают
//!
//! Наружу выходят **пути**, а не куски. Причина не в красоте: UniFFI копирует
//! каждый `Vec<u8>`, и мебибайт на кусок превратил бы гигабайтный файл
//! в два гигабайта копирований, а последовательность кусков — в заботу UI.
//! Та же форма, что у телефона: `send_files` берёт путь с самого начала.

use std::path::PathBuf;

use ratatosk_proto::companion::{Attachment, ChatSummary, Member, Message, Reaction, Request};
use ratatosk_proto::files::{FileId, CHUNK_BYTES};
use ratatosk_proto::Transport;
use ratatosk_transport::{PeerAddress, Runner, TransportCommand, TransportEvent};
use tokio::sync::mpsc;

use crate::companion::{ClientEffect, ClientEvent, ClientInput, CompanionClient, OutgoingItem};

/// Глубина очередей между UI и драйвером.
const CHANNEL_DEPTH: usize = 64;

/// Через сколько повторить рукопожатие в первый раз.
const RETRY_MIN_MS: u64 = 1_000;

/// Дальше какого предела не отступать.
///
/// Пятнадцать секунд, а не минуты: человек сидит перед окном и ждёт, пока
/// оно оживёт. Минутная пауза здесь неотличима от «не работает».
const RETRY_MAX_MS: u64 = 15_000;

/// Не чаще чем раз в столько кэш ложится на диск.
///
/// **Отложенная запись, а не запись на каждое изменение.** Стенд писал файл
/// всякий раз, когда кэш менялся, и это было записано пробелом: окно
/// с открытым чатом правит кэш на каждое сообщение, и файл на сотню
/// килобайт переписывался бы со скоростью разговора.
///
/// Две секунды — это «человек перестал печатать». Несохранённым при падении
/// остаётся окно в две секунды переписки, и восстанавливается оно первым же
/// ответом телефона.
const CACHE_WRITE_EVERY_MS: u64 = 2_000;

/// Что UI просит у компаньона.
///
/// **Список закрытый, и он у́же того, что умеет провод.** Просьбы вроде
/// «дай кусок файла» или «вот кусок» здесь отсутствуют намеренно: ими
/// распоряжается драйвер, и дать до них дотянуться UI значило бы вернуть
/// последовательность кусков туда, откуда её убирали.
#[derive(Debug, Clone)]
pub enum CompanionCommand {
    /// Перечитать список чатов.
    Chats,
    /// Страница истории. `before: None` — с конца ленты.
    History {
        /// Какой чат.
        chat: [u8; 16],
        /// Сколько сообщений.
        limit: u32,
        /// Перед каким сообщением.
        before: Option<[u8; 16]>,
    },
    /// Завести группу (§11).
    ///
    /// **Перед вызовом окно обязано показать `group_join_notice()`** —
    /// §11.5 требует сказать при создании, что участники увидят адреса
    /// друг друга. Текст лежит в биндингах окна, проводом не едет,
    /// и телефон не знает, показали ли его: проследить может только окно.
    CreateGroup {
        /// Как назвать.
        title: String,
    },
    /// Позвать в группу (§11.2). Вправе любой участник.
    InviteToGroup {
        /// Куда.
        chat: [u8; 16],
        /// Кого — идентификатором его **личного** чата.
        member: [u8; 16],
    },
    /// Исключить из группы (§11.2). Только создатель.
    ///
    /// **Перед вызовом окно обязано показать `eviction_notice()`** (§11.4):
    /// исключённый сохранит доступ к прошлой переписке, и отменить это
    /// нельзя ничем.
    EvictFromGroup {
        /// Откуда.
        chat: [u8; 16],
        /// Кого — идентификатором его **личного** чата.
        member: [u8; 16],
    },
    /// Переименовать группу. Только создатель.
    RenameGroup {
        /// Какую.
        chat: [u8; 16],
        /// Как назвать.
        title: String,
    },
    /// Сменить аватарку группы. Только создатель. Пусто — снять.
    SetGroupAvatar {
        /// Какой группе.
        chat: [u8; 16],
        /// Байты картинки; пусто — снять.
        bytes: Vec<u8>,
    },
    /// Выйти из группы.
    ///
    /// **Перед вызовом окно обязано показать `leave_notice()`**, а если
    /// выходит создатель — ещё и `owner_leave_notice()`: после его ухода
    /// группу нельзя ни переименовать, ни исключить из неё.
    LeaveGroup {
        /// Из какой.
        chat: [u8; 16],
    },
    /// Спросить состав группы (§11.2).
    ///
    /// У личного чата ответ пуст, и это не ошибка вызывающего: состав
    /// переписки двоих — её заголовок.
    Members {
        /// Какой группы.
        chat: [u8; 16],
    },
    /// Отправить текст.
    SendText {
        /// Куда.
        chat: [u8; 16],
        /// Что.
        text: String,
    },
    /// Ответить на сообщение.
    SendReply {
        /// Куда.
        chat: [u8; 16],
        /// На что.
        reply_to: [u8; 16],
        /// Что.
        text: String,
    },
    /// Заменить текст своего сообщения.
    EditMessage {
        /// В каком чате.
        chat: [u8; 16],
        /// Какое.
        msg_id: [u8; 16],
        /// Новый текст.
        text: String,
    },
    /// Поставить или снять реакцию. Пустая строка снимает.
    SetReaction {
        /// В каком чате.
        chat: [u8; 16],
        /// На каком сообщении.
        msg_id: [u8; 16],
        /// Эмодзи.
        emoji: String,
    },
    /// Удалить сообщения у себя.
    DeleteMessages {
        /// Из какого чата.
        chat: [u8; 16],
        /// Какие.
        msg_ids: Vec<[u8; 16]>,
    },
    /// Удалить у себя и попросить собеседника.
    RetractMessages {
        /// Из какого чата.
        chat: [u8; 16],
        /// Какие.
        msg_ids: Vec<[u8; 16]>,
    },
    /// Переслать сообщения в другой чат.
    ForwardMessages {
        /// Куда.
        chat: [u8; 16],
        /// Что.
        msg_ids: Vec<[u8; 16]>,
    },
    /// Поделиться в чате карточкой человека (§4.1).
    ///
    /// Человек назван **личным чатом** с ним — тем же именем, каким его
    /// называет состав группы. `None` означает «своей карточкой»: личного
    /// чата с самим собой не бывает.
    ShareContact {
        /// В какой чат — переписку или группу.
        chat: [u8; 16],
        /// Чьей карточкой; `None` — своей.
        who: Option<[u8; 16]>,
    },
    /// Добавить к себе того, чья карточка приехала этим сообщением.
    AddSharedContact {
        /// Какое сообщение принесло карточку.
        msg_id: [u8; 16],
    },
    /// Очистить чат у себя.
    ClearChat {
        /// Какой.
        chat: [u8; 16],
    },
    /// Отметить прочитанным до этого сообщения включительно.
    MarkRead {
        /// Какой чат.
        chat: [u8; 16],
        /// До какого.
        up_to: [u8; 16],
    },
    /// Принять входящее вложение к загрузке — на телефоне.
    AcceptFile {
        /// Какое.
        file_id: FileId,
    },
    /// Перестать качать, не отказываясь: приехавшее остаётся.
    PauseFile {
        /// Какое.
        file_id: FileId,
    },
    /// Отказаться от входящего вложения совсем.
    DeclineFile {
        /// Какое.
        file_id: FileId,
    },
    /// Дай превью вложения (§10.3).
    ///
    /// **Байты, а не путь** — единственное исключение из правила заголовка
    /// модуля, и мера у него своя: превью не больше 32 КиБ, тогда как кусок
    /// файла — мебибайт. Одна копия на показанную картинку против гигабайта
    /// копирований на гигабайтный файл; временный файл ради тридцати
    /// килобайт стоил бы дороже — его ещё пришлось бы кому-то убирать.
    ///
    /// Спрашивать имеет смысл там, где `has_preview` у вложения говорит
    /// «есть», и **только для показанного сейчас**: страница вперёд — это
    /// снова те самые мегабайты, только россыпью.
    Preview {
        /// Какое вложение.
        file_id: FileId,
    },
    /// Спросить аватарку — контакта или свою.
    ///
    /// **Байты, а не путь**, по той же мере, что и у [`CompanionCommand::Preview`]:
    /// лицо не больше 32 КиБ, и временный файл ради тридцати килобайт стоил
    /// бы дороже картинки.
    ///
    /// Спрашивать имеет смысл про те чаты, у которых `avatar_ms` в списке
    /// разошёлся с показанным, — их называет `Cache::stale_avatars`. Своё
    /// (`chat: None`) спрашивается раз за подключение: метки для сравнения
    /// у него нет, себя в списке чатов не бывает.
    Avatar {
        /// Чей чат, или `None` — своя.
        chat: Option<[u8; 16]>,
    },
    /// Поставить или снять **свою** аватарку (§4.2).
    ///
    /// **Байты, а не путь** — то же исключение, что у превью и у чтения
    /// лица: 32 КиБ, одна копия, и временный файл ради них стоил бы дороже
    /// картинки.
    ///
    /// Пусто — «снять». Разошлёт её сверенным контактам телефон: сессии
    /// с ними есть только у него (§13.4). Ответ — `Done` молчанием
    /// и `CompanionEvent::AvatarChanged` следом; негодная картинка вернётся
    /// `Refused` со словами.
    SetAvatar {
        /// Байты картинки; пусто — снять.
        bytes: Vec<u8>,
    },
    /// Забрать вложение с телефона в файл по этому пути.
    ///
    /// Байты пишет драйвер: путь, а не поток, — см. заголовок модуля.
    SaveFile {
        /// Какое вложение.
        file_id: FileId,
        /// Сколько в нём кусков — из [`Attachment::chunk_total`].
        chunk_total: u64,
        /// Куда положить.
        path: PathBuf,
    },
    /// Прекратить начатое сохранение и убрать недописанное.
    CancelSave,
    /// Отправить файлы одним сообщением. Читает их драйвер.
    SendFiles {
        /// В какой чат.
        chat: [u8; 16],
        /// Пути и превью — по паре на файл, в порядке выбора.
        ///
        /// Порядок несущий: в нём вложения лягут в сообщение и в нём же
        /// их увидит собеседник (`ARCHITECTURE.md`, 5бэ).
        files: Vec<(PathBuf, Option<Vec<u8>>)>,
        /// Подпись к сообщению. Пустая законна.
        text: String,
    },
    /// Передумать отправлять: выгруженное на телефоне выбросить.
    CancelSend,
    /// Куда класть снимок кэша. `None` — никуда, и уже лежащее стереть.
    ///
    /// Выключение **стирает** файл, а не перестаёт его обновлять: человек,
    /// снявший галочку, имел в виду «здесь этого не должно быть» (§13.4).
    KeepCache {
        /// Путь или `None`.
        path: Option<PathBuf>,
    },
}

/// Что компаньон говорит UI.
///
/// Отличается от [`ClientEvent`] тем, чего здесь **нет**: просьб дать кусок
/// и приехавших байтов. Их обслуживает драйвер, и наверх поднимается только
/// исход — файл сохранён, файл отправлен, не вышло и почему.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompanionEvent {
    /// Сессия с телефоном установлена.
    Linked,
    /// Канала больше нет. §14, пункт 5: телефона нет — десктоп не работает.
    Unlinked,
    /// Каким проводом говорит телефон. `theirs: None` — сборка старее.
    Wire {
        /// Что назвал телефон.
        theirs: Option<u32>,
        /// Что здесь.
        ours: u32,
    },
    /// Группа заведена — вот чем её открыть.
    GroupCreated {
        /// Идентификатор заведённой группы.
        chat: [u8; 16],
    },
    /// Состав группы (§11.2).
    ///
    /// Признака `fresh` здесь нет, и это не пропуск: состав не кэшируется
    /// вовсе, а значит приходит только от телефона и только сейчас.
    Members {
        /// Какой группы.
        chat: [u8; 16],
        /// Участники; пусто у личного чата.
        members: Vec<Member>,
    },
    /// Список чатов. `fresh` — подтверждён ли телефоном в этой связи.
    Chats {
        /// Чаты.
        chats: Vec<ChatSummary>,
        /// Подтверждено сейчас.
        fresh: bool,
    },
    /// Страница истории.
    History {
        /// Какого чата.
        chat: [u8; 16],
        /// Сообщения, от старых к новым.
        page: Vec<Message>,
        /// Подтверждено сейчас.
        fresh: bool,
    },
    /// Пришло сообщение.
    Arrived(Message),
    /// Сменился статус доставки.
    Status {
        /// Какого сообщения.
        msg_id: [u8; 16],
        /// Новый код.
        status: u8,
    },
    /// Список чатов изменился — перечитать.
    ChatsChanged,
    /// Сообщений больше нет.
    Gone {
        /// В каком чате.
        chat: [u8; 16],
        /// Каких.
        msg_ids: Vec<[u8; 16]>,
    },
    /// Сообщение поправили — вот оно целиком.
    Edited(Message),
    /// У сообщения сменился набор реакций.
    Reacted {
        /// В каком чате.
        chat: [u8; 16],
        /// На каком сообщении.
        msg_id: [u8; 16],
        /// Все реакции сейчас.
        reactions: Vec<Reaction>,
    },
    /// У вложения на телефоне сдвинулся приём.
    FileProgress {
        /// Какого.
        file_id: FileId,
        /// Сколько кусков у телефона.
        have_chunks: u64,
        /// Сколько всего.
        chunk_total: u64,
        /// Согласен ли телефон качать его сейчас.
        accepted: bool,
    },
    /// Вложения больше нет — убрать строку.
    FileGone {
        /// Какого.
        file_id: FileId,
    },
    /// Превью вложения (§10.3) — или его отсутствие.
    ///
    /// `bytes: None` — превью нет, и это ответ, а не отказ: вложение без
    /// картинки обычное дело, показывать по этому поводу строку незачем.
    FilePreview {
        /// Какого вложения.
        file_id: FileId,
        /// Байты, если они есть. Не больше 32 КиБ — проверено проводом.
        bytes: Option<Vec<u8>>,
    },
    /// Аватарка — или её отсутствие.
    ///
    /// `bytes: None` — показывать нечего, и это ответ, а не отказ: аватарки
    /// нет либо контакт не сверен (§4.2). Снаружи эти случаи неразличимы
    /// намеренно, и рисовать в обоих надо одно — заглушку.
    Avatar {
        /// Чей чат, или `None` — своя.
        chat: Option<[u8; 16]>,
        /// Байты, если они есть. Не больше 32 КиБ — проверено проводом.
        bytes: Option<Vec<u8>>,
        /// Подтверждено ли телефоном сейчас; `false` — показанное из кэша.
        fresh: bool,
    },
    /// Сопряжение отозвано — этот компьютер больше не второй экран (§13.4).
    ///
    /// К этому моменту кэш пуст и в памяти, и на диске: файл драйвер стёр
    /// сам. Ждать решения человека тут нечего — решение он уже принял,
    /// на телефоне.
    ///
    /// Показать **обязательно и словами**: до этой новости отзыв выглядел
    /// тишиной, неотличимой от «телефон не в сети». Дальше терминал
    /// не подключается и на просьбы отвечает отказом; новый второй экран
    /// заводится новым QR.
    Revoked,
    /// Лицо сменилось — прежнее с экрана убрать, новое спросить.
    ///
    /// Байтов не несёт: новость приезжает без спроса, и тридцать два
    /// килобайта без спроса — трафик, за который окно не просило.
    AvatarChanged {
        /// Чей чат, или `None` — своя.
        chat: Option<[u8; 16]>,
        /// Новая метка; `0` — показывать нечего, и спрашивать не о чем.
        avatar_ms: u64,
    },
    /// Вложение забрано и лежит по этому пути.
    FileSaved {
        /// Какое.
        file_id: FileId,
        /// Где.
        path: PathBuf,
    },
    /// Файлы выгружены и телефон отправил сообщение с ними.
    ///
    /// «Отправил» означает то же, что для текста: сообщение легло в историю
    /// и встало в очередь §5.4. Дошло ли — скажет статус (§14).
    FilesSent {
        /// Какие — все разом, в порядке выбора.
        file_ids: Vec<FileId>,
    },
    /// Связь пропала посреди приёма вложения — он ждёт, а не сорвался.
    ///
    /// Записанное лежит на диске под именем с припиской `.part`, и
    /// продолжение допишет его с того же места. Убирать ничего не надо.
    FetchPaused,
    /// Приём вложения продолжился с того места, где его оборвали.
    FetchResumed {
        /// Сколько кусков уже на диске.
        done: u64,
        /// Сколько их всего.
        total: u64,
    },
    /// Связь пропала посреди отправки — она ждёт, а не сорвалась.
    ///
    /// Выгруженные куски лежат у телефона (`ARCHITECTURE.md`, 5вб), пути
    /// драйвер держит открытыми, и продолжение начнётся само, как только
    /// телефон вернётся. Показывать это как ошибку нельзя: человек начал бы
    /// заново то, что и так доедет.
    SendPaused,
    /// Отправка продолжилась с того места, где её оборвали.
    SendResumed {
        /// Сколько файлов уже целиком у телефона.
        done: u32,
        /// Сколько их всего.
        total: u32,
    },
    /// Сделано, сказать нечего.
    Done,
    /// Не вышло, и вот почему — словами, для показа человеку (§14).
    Refused(String),
    /// Спросить не у кого: сессии нет.
    NotLinked,
}

/// Ручка, через которую UI разговаривает с компаньоном.
///
/// Клонируется; поток событий — нет, и по той же причине, что у телефона:
/// два читателя поделили бы события между собой.
#[derive(Clone)]
pub struct CompanionHandle {
    commands: mpsc::Sender<CompanionCommand>,
}

impl CompanionHandle {
    /// Отправляет команду. Ошибка означает, что драйвер остановлен.
    ///
    /// # Errors
    ///
    /// Возвращает команду обратно, если драйвера больше нет.
    pub async fn send(&self, command: CompanionCommand) -> Result<(), CompanionCommand> {
        self.commands.send(command).await.map_err(|e| e.0)
    }

    /// То же из потока без `async`.
    ///
    /// # Errors
    ///
    /// Возвращает команду обратно, если драйвера больше нет.
    pub fn send_blocking(&self, command: CompanionCommand) -> Result<(), CompanionCommand> {
        self.commands.blocking_send(command).map_err(|e| e.0)
    }
}

/// Поток событий для UI. Существует в единственном экземпляре.
pub struct CompanionEvents {
    notices: mpsc::Receiver<CompanionEvent>,
}

impl CompanionEvents {
    /// Ждёт следующее событие. `None` — драйвер остановлен.
    pub async fn next(&mut self) -> Option<CompanionEvent> {
        self.notices.recv().await
    }
}

/// Файл, который сейчас пишется на диск.
struct Saving {
    file_id: FileId,
    /// Куда файл ляжет, когда приедет целиком.
    path: PathBuf,
    /// Куда он пишется, пока едет: `path` с припиской `.part`.
    ///
    /// **Имя решает ту же задачу, что раньше решало стирание.** Недокачанный
    /// файл под настоящим именем неотличим от докачанного, и §14 этого
    /// не разрешает; но стирать его на разрыве значит терять мебибайты
    /// из-за секундной потери сети. Приписка говорит о том же честнее
    /// и вдобавок переживает разрыв: продолжение пишет в тот же файл.
    ///
    /// Рядом с целью, а не во временном каталоге: переименование обязано
    /// быть в пределах одной файловой системы, иначе это копирование
    /// гигабайта в конце приёма.
    partial: PathBuf,
    file: std::fs::File,
}

/// Имя, под которым файл пишется, пока не приехал целиком.
///
/// Приписка **к имени целиком**, а не замена расширения: `otchet.pdf`
/// становится `otchet.pdf.part`, и настоящее имя видно человеку сразу.
fn partial_name(path: &std::path::Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    path.with_file_name(name)
}

/// Сообщение, которое сейчас уезжает: файлы и открытый из них один.
///
/// **Пути держит драйвер, идентификаторы придумывает телефон**, и связать
/// одно с другим можно только по номеру в списке — его и везёт
/// [`ClientEvent::NeedChunk`]. По имени искать нельзя: два файла в одном
/// сообщении вправе называться одинаково.
///
/// Открыт при этом ровно один: терминал выгружает по очереди, и держать
/// десять дескрипторов ради этого незачем.
struct Sending {
    /// Пути в том порядке, в каком их дал UI.
    paths: Vec<PathBuf>,
    /// Который открыт сейчас, и он сам.
    at: usize,
    file: std::fs::File,
}

/// Среда вокруг [`CompanionClient`].
pub struct CompanionDriver<R: Runner> {
    client: CompanionClient,
    runner: R,
    phone_ik: [u8; 32],
    commands: mpsc::Receiver<CompanionCommand>,
    notices: mpsc::Sender<CompanionEvent>,
    /// Когда повторить рукопожатие и как долго ждать в следующий раз.
    retry_at_ms: u64,
    retry_wait_ms: u64,
    /// Куда класть снимок кэша. `None` — никуда, и это умолчание (§13.4).
    cache_path: Option<PathBuf>,
    /// Каким транспортом звонить телефону.
    ///
    /// **Не лестница §5.4, и это осознанно.** Там три ступени, сроки
    /// и откаты, потому что там сообщение обязано дойти хоть когда-нибудь.
    /// Здесь всё иначе: у второго экрана два транспорта, а «не дошло»
    /// означает «окно не обновилось» — беда, которая чинится следующим
    /// рукопожатием через секунду.
    ///
    /// Правило поэтому в одну строку: **пока телефон видно в общей сети —
    /// общая сеть**, иначе onion, если адрес известен. Локальная сеть
    /// быстрее, дешевле и не поднимает Tor ради соседней комнаты.
    ///
    /// Начинаем с локальной: маяк §5.1 приходит быстро, а onion до первого
    /// разочарования означал бы цепочку Tor у людей, сидящих в метре
    /// друг от друга.
    via: Transport,
    /// Когда кэш можно писать снова. Ноль — можно сейчас.
    cache_after_ms: u64,
    /// Собранный снимок, который не лёг на диск. Ждёт следующей попытки.
    cache_pending: Option<Vec<u8>>,
    saving: Option<Saving>,
    sending: Option<Sending>,
    /// Пиры, на которых поднят свой узел меша. Пусто — узла нет.
    ///
    /// Помнится ровно затем, чтобы не перезапускать узел на том же самом
    /// списке: объявление адреса приходит на каждом рукопожатии, а перезапуск
    /// узла — это разрыв всего, что через него шло.
    mesh_peers: Vec<String>,
    /// Часы. Отдельным полем ради тестов: у драйвера их иначе не подменить.
    now: fn() -> u64,
}

impl<R: Runner> CompanionDriver<R> {
    /// Связывает терминал с транспортом и выдаёт ручку и поток событий.
    pub fn new(
        client: CompanionClient,
        runner: R,
    ) -> (CompanionDriver<R>, CompanionHandle, CompanionEvents) {
        Self::with_clock(client, runner, now_ms)
    }

    /// То же с подменёнными часами — для тестов.
    pub fn with_clock(
        client: CompanionClient,
        runner: R,
        now: fn() -> u64,
    ) -> (CompanionDriver<R>, CompanionHandle, CompanionEvents) {
        let (commands_tx, commands_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (notices_tx, notices_rx) = mpsc::channel(CHANNEL_DEPTH);
        let phone_ik = client.phone_ik();
        let driver = CompanionDriver {
            client,
            runner,
            phone_ik,
            commands: commands_rx,
            notices: notices_tx,
            retry_at_ms: 0,
            retry_wait_ms: RETRY_MIN_MS,
            cache_path: None,
            via: Transport::Lan,
            cache_after_ms: 0,
            cache_pending: None,
            saving: None,
            sending: None,
            mesh_peers: Vec::new(),
            now,
        };
        (driver, CompanionHandle { commands: commands_tx }, CompanionEvents { notices: notices_rx })
    }

    /// Терминал на чтение — для диагностики и тестов.
    pub fn client(&self) -> &CompanionClient {
        &self.client
    }

    /// Основной цикл. Возвращается, когда закрылся транспорт или ручка UI.
    pub async fn run(&mut self) {
        // Свой узел меша — **до** первого рукопожатия, а не после. Пиры уже
        // есть, они приехали в приглашении, и поднимать узел позже значило бы
        // требовать живого канала ради ступени, которая этот канал и даёт.
        // Узел встаёт не мгновенно; ступень подхватит его `mesh_came_up`,
        // когда раннер скажет `YggReady`.
        let peers = self.client.phone_ygg_peers().to_vec();
        self.raise_own_node(peers).await;

        // Здороваемся сразу: адрес мог приехать настройкой, и ждать маяка,
        // которого на loopback может не быть вовсе, незачем.
        self.feed(ClientInput::Reach).await;

        loop {
            let now = (self.now)();
            let sleep_for = self.retry_at_ms.saturating_sub(now).max(1);

            let wake = tokio::select! {
                command = self.commands.recv() => match command {
                    Some(command) => Wake::Command(command),
                    None => return,
                },
                event = self.runner.next_event() => match event {
                    Some(event) => Wake::Transport(event),
                    None => return,
                },
                () = tokio::time::sleep(std::time::Duration::from_millis(sleep_for)) => Wake::Tick,
            };

            match wake {
                Wake::Command(command) => self.on_command(command).await,
                Wake::Transport(event) => self.on_transport(event).await,
                Wake::Tick => self.on_tick().await,
            }
            self.persist_cache();
        }
    }

    /// Пора ли повторить рукопожатие.
    ///
    /// **Повтор по времени, а не только по маяку**, и это исправление
    /// настоящей поломки со стенда: телефон не может ответить, пока не знает
    /// адреса десктопа, а маяк mDNS шлётся однократно. Полагаться было
    /// не на что.
    async fn on_tick(&mut self) {
        if self.client.linked() {
            // Связь есть — следующая проверка нескоро, и отступление
            // сбрасывается: следующий разрыв обязан чиниться быстро.
            self.retry_wait_ms = RETRY_MIN_MS;
            self.retry_at_ms = (self.now)() + RETRY_MAX_MS;
            return;
        }
        self.feed(ClientInput::Reach).await;
        self.retry_wait_ms = (self.retry_wait_ms * 2).min(RETRY_MAX_MS);
        self.retry_at_ms = (self.now)() + self.retry_wait_ms;
    }

    async fn on_transport(&mut self, event: TransportEvent) {
        // Любое движение в эфире — повод попробовать снова поскорее.
        self.retry_wait_ms = RETRY_MIN_MS;
        match event {
            TransportEvent::Received { frame, .. } => {
                self.feed(ClientInput::Received(frame)).await;
            }
            // Маяк телефона в эфире — повод поздороваться. Повторы
            // безвредны: пока связь жива, терминал их не замечает.
            TransportEvent::SeenOnLan { .. } | TransportEvent::Connected { .. } => {
                // Телефон в общей сети — возвращаемся к ней. Возврат нужен
                // не меньше отката: ушедший на onion терминал остался бы
                // там навсегда, гоняя переписку через три реле в соседнюю
                // комнату.
                self.via = Transport::Lan;
                self.feed(ClientInput::Reach).await;
            }
            // Разрыв транспорта не называет, и это не пробел: канал
            // у терминала один, и разорваться мог только он.
            TransportEvent::Disconnected { .. } => self.on_link_gone(None).await,
            TransportEvent::ConnectFailed { via, .. } => self.on_link_gone(Some(via)).await,
            // Свой onion поднялся — телефону будет чем перезвонить.
            // Уезжает адрес не сейчас, а следующим рукопожатием: живой
            // связи он не нужен, а нужен он ровно тогда, когда терминал
            // не в общей сети, — и такой разговор всегда начинается новым
            // рукопожатием (§13.4).
            TransportEvent::TorReady { onion } => {
                self.feed(ClientInput::OnionReady(onion)).await;
            }
            // Свой узел меша поднялся — телефону будет чем перезвонить.
            // Уезжает ключ тем же путём и в тот же миг, что и onion:
            // следующим рукопожатием.
            TransportEvent::YggReady { key } => {
                self.feed(ClientInput::YggReady(key.to_vec())).await;
                self.mesh_came_up().await;
            }
            // Остальное компаньона не касается: у него нет ни доставки,
            // ни почты.
            _ => {}
        }
    }

    /// Узел меша поднялся — и, может быть, пора вернуться на его ступень.
    ///
    /// **Возврат нужен не меньше отката, и это уже было записано** — про
    /// локальную сеть: ушедший на onion терминал остался бы там навсегда,
    /// гоняя переписку через три реле в соседнюю комнату. У меша ровно то же,
    /// только причина другая и куда более частая.
    ///
    /// Лестница выбирает ступень **один раз**, в миг отказа предыдущей,
    /// а отказ этот случается через миллисекунды после запуска. Узел меша
    /// к тому времени ещё не поднялся: включение уходит команде, привязка
    /// к адресу — это сеть, а свой узел вдобавок ждёт пиров, которые
    /// приезжают только по живому каналу. То есть в момент решения меша
    /// **никогда** нет — и лестница, честно его пропустив, уходила на onion
    /// и не возвращалась.
    ///
    /// Наружу это выглядело так: до правки терминал упирался в меш, которого
    /// у него не было; после — проходил мимо меша, который вот-вот будет.
    /// Оба раза — одна и та же ошибка: решение принято раньше, чем стало
    /// что решать.
    ///
    /// Кольца отсюда не выходит: событие приходит на подъём узла, а узел
    /// поднимается один раз.
    async fn mesh_came_up(&mut self) {
        if self.via != Transport::Onion || self.client.phone_ygg().is_empty() {
            return;
        }
        tracing::debug!("узел меша поднялся — возвращаемся на его ступень");
        self.via = Transport::Ygg;
        self.feed(ClientInput::Reach).await;
    }

    /// Канал пропал: связь потеряна, и, может быть, пора сменить транспорт.
    ///
    /// `failed` — каким транспортом не дозвонились, если транспорт назван.
    /// Сверяется он с тем, которым звоним **мы**: отказ чужого транспорта
    /// о нашем не говорит ничего.
    async fn on_link_gone(&mut self, failed: Option<Transport>) {
        // Локальная сеть не отозвалась — пробуем через Tor, если есть куда.
        // Без адреса переключаться некуда, и остаёмся при своём: «звоню туда,
        // где никого нет» честнее, чем «звоню в никуда».
        let ours = match failed {
            Some(via) => via == self.via,
            None => true,
        };
        // Лестница у канала та же, что у §5.4, и в том же порядке:
        // общая сеть → меш → onion. Меш выше onion по тем же доводам —
        // он прямой и быстрый, — и ниже общей сети по тем же: в ней сосед
        // за стеной, а в меше трафик уходит наружу и возвращается.
        //
        // Ступень пропускается, если ехать по ней некуда: адреса нет.
        // «Звоню туда, где никого нет» честнее, чем «звоню в никуда».
        // **Ступень нужна с обоих концов.** Ключ телефона отвечает только
        // на «куда ехать»; на «чем ехать» отвечает свой узел, и без него
        // ступень выдаёт `Unavailable` на каждый кадр — то есть лестница
        // встаёт на ней навсегда, потому что синхронный отказ отправки
        // событием не приходит и отката не заводит.
        //
        // Ровно это и случилось на живом стенде: терминал ушёл с общей сети
        // на меш, которого у него не было, и до onion не добрался никогда.
        let mesh_ready = !self.client.phone_ygg().is_empty() && !self.client.own_ygg().is_empty();
        // Вслух, потому что тишина здесь неотличима от «меша нет в сборке».
        // Пропуск ступени — решение, и в разборе оно обязано быть видно
        // вместе с причиной: чей именно конец не готов.
        if self.via == Transport::Lan && !mesh_ready {
            tracing::debug!(
                ключ_телефона = !self.client.phone_ygg().is_empty(),
                свой_узел = !self.client.own_ygg().is_empty(),
                "меш пропущен: ступень нужна с обоих концов"
            );
        }
        let next = match self.via {
            Transport::Lan if mesh_ready => Some(Transport::Ygg),
            Transport::Lan | Transport::Ygg if !self.client.phone_onion().is_empty() => {
                Some(Transport::Onion)
            }
            _ => None,
        };
        let switched = ours && next.is_some();
        if let (true, Some(next)) = (ours, next) {
            tracing::debug!(
                прежняя = self.via.label(),
                следующая = next.label(),
                "канал молчит — пробуем следующую ступень"
            );
            self.via = next;
        }
        self.feed(ClientInput::Lost).await;

        // **Сменив транспорт, пробуем сразу, не досиживая до тика.** Пауза
        // здесь бессмысленна: мы только что решили попробовать другую дорогу,
        // и ждать секунду, чтобы этой дорогой воспользоваться, — значит
        // держать окно пустым ровно столько же.
        //
        // Кольца из этого не выходит: смена бывает одна (общая сеть → onion),
        // а обратно возвращает только маяк, который и так здоровается сам.
        // Отказ **onion** сюда приходит уже при `via == Onion`, ничего
        // не меняет и нового круга не заводит.
        if switched {
            self.feed(ClientInput::Reach).await;
        }
    }

    async fn on_command(&mut self, command: CompanionCommand) {
        let request = match command {
            CompanionCommand::Chats => Request::Chats,
            CompanionCommand::History { chat, limit, before } => {
                Request::History { chat, limit, before }
            }
            CompanionCommand::Members { chat } => Request::Members { chat },
            CompanionCommand::CreateGroup { title } => Request::CreateGroup { title },
            CompanionCommand::InviteToGroup { chat, member } => {
                Request::InviteToGroup { chat, member }
            }
            CompanionCommand::EvictFromGroup { chat, member } => {
                Request::EvictFromGroup { chat, member }
            }
            CompanionCommand::RenameGroup { chat, title } => Request::RenameGroup { chat, title },
            CompanionCommand::SetGroupAvatar { chat, bytes } => {
                Request::SetGroupAvatar { chat, bytes }
            }
            CompanionCommand::LeaveGroup { chat } => Request::LeaveGroup { chat },
            CompanionCommand::SendText { chat, text } => Request::SendText { chat, text },
            CompanionCommand::SendReply { chat, reply_to, text } => {
                Request::SendReply { chat, reply_to, text }
            }
            CompanionCommand::EditMessage { chat, msg_id, text } => {
                Request::EditMessage { chat, msg_id, text }
            }
            CompanionCommand::SetReaction { chat, msg_id, emoji } => {
                Request::SetReaction { chat, msg_id, emoji }
            }
            CompanionCommand::DeleteMessages { chat, msg_ids } => {
                Request::DeleteMessages { chat, msg_ids }
            }
            CompanionCommand::RetractMessages { chat, msg_ids } => {
                Request::RetractMessages { chat, msg_ids }
            }
            CompanionCommand::ForwardMessages { chat, msg_ids } => {
                Request::ForwardMessages { chat, msg_ids }
            }
            CompanionCommand::ShareContact { chat, who } => Request::ShareContact { chat, who },
            CompanionCommand::AddSharedContact { msg_id } => Request::AddSharedContact { msg_id },
            CompanionCommand::ClearChat { chat } => Request::ClearChat { chat },
            CompanionCommand::MarkRead { chat, up_to } => Request::MarkRead { chat, up_to },
            CompanionCommand::AcceptFile { file_id } => Request::AcceptFile { file_id },
            CompanionCommand::PauseFile { file_id } => Request::PauseFile { file_id },
            CompanionCommand::DeclineFile { file_id } => Request::DeclineFile { file_id },
            CompanionCommand::Preview { file_id } => Request::FilePreview { file_id },
            CompanionCommand::Avatar { chat } => Request::Avatar { chat },
            CompanionCommand::SetAvatar { bytes } => Request::SetMyAvatar { bytes },

            CompanionCommand::SaveFile { file_id, chunk_total, path } => {
                self.start_save(file_id, chunk_total, path).await;
                return;
            }
            CompanionCommand::CancelSave => {
                self.feed(ClientInput::CancelFetch).await;
                self.abandon_save();
                return;
            }
            CompanionCommand::SendFiles { chat, files, text } => {
                self.start_send(chat, files, text).await;
                return;
            }
            CompanionCommand::CancelSend => {
                self.sending = None;
                self.feed(ClientInput::CancelSend).await;
                return;
            }
            CompanionCommand::KeepCache { path } => {
                self.keep_cache(path).await;
                return;
            }
        };
        self.feed(ClientInput::Ask(request)).await;
    }

    /// Готовит запись вложения и просит телефон отдавать куски.
    async fn start_save(&mut self, file_id: FileId, chunk_total: u64, path: PathBuf) {
        if self.saving.is_some() {
            self.tell(CompanionEvent::Refused(
                "одно вложение за раз — дождитесь конца или отмените".to_owned(),
            ))
            .await;
            return;
        }
        let partial = partial_name(&path);
        match std::fs::File::create(&partial) {
            Ok(file) => self.saving = Some(Saving { file_id, path, partial, file }),
            Err(error) => {
                self.tell(CompanionEvent::Refused(format!("файл не создать: {error}"))).await;
                return;
            }
        }
        self.feed(ClientInput::Fetch { file_id, chunk_total }).await;
    }

    /// Разбирает список файлов и просит телефон отвести место под первый.
    ///
    /// **Все открываются до первой просьбы.** Узнать, что пятый файл
    /// не читается, после того как четыре уже уехали, — худший из порядков:
    /// на телефоне осталось бы четыре занятых места, а человек увидел бы
    /// отказ вместо отправки. Дескриптор при этом остаётся один — открытие
    /// здесь только проверяет, что файл есть и читается.
    async fn start_send(
        &mut self,
        chat: [u8; 16],
        files: Vec<(PathBuf, Option<Vec<u8>>)>,
        text: String,
    ) {
        if self.sending.is_some() {
            self.tell(CompanionEvent::Refused(
                "одно сообщение за раз — дождитесь конца или отмените".to_owned(),
            ))
            .await;
            return;
        }
        let mut paths = Vec::with_capacity(files.len());
        let mut items = Vec::with_capacity(files.len());
        for (path, preview) in files {
            let opened =
                std::fs::File::open(&path).and_then(|file| file.metadata().map(|meta| meta.len()));
            let size_bytes = match opened {
                Ok(size) => size,
                Err(error) => {
                    self.tell(CompanionEvent::Refused(format!(
                        "файл {} не открыть: {error}",
                        path.display()
                    )))
                    .await;
                    return;
                }
            };
            // Имя, а не путь: по проводу едет то, что покажут человеку,
            // и каталоги отправителя к этому отношения не имеют.
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                self.tell(CompanionEvent::Refused(format!(
                    "у пути {} нет имени файла",
                    path.display()
                )))
                .await;
                return;
            };
            items.push(OutgoingItem { name, size_bytes, preview });
            paths.push(path);
        }
        let Some(first) = paths.first() else {
            self.tell(CompanionEvent::Refused("отправлять нечего: файлы не выбраны".to_owned()))
                .await;
            return;
        };
        let file = match std::fs::File::open(first) {
            Ok(file) => file,
            Err(error) => {
                self.tell(CompanionEvent::Refused(format!("файл не открыть: {error}"))).await;
                return;
            }
        };
        self.sending = Some(Sending { paths, at: 0, file });
        self.feed(ClientInput::Send { chat, items, text }).await;
    }

    /// Бросает незаконченную запись и убирает обрывок с диска.
    ///
    /// Недокачанный файл выглядит ровно как докачанный, и оставить его —
    /// значит отдать человеку битую картинку без единого признака того,
    /// что она битая (§14).
    fn abandon_save(&mut self) {
        let Some(saving) = self.saving.take() else { return };
        if let Err(error) = std::fs::remove_file(&saving.partial) {
            tracing::warn!(?error, path = ?saving.partial, "обрывок вложения убрать не вышло");
        }
    }

    /// Включает или выключает дисковый кэш (§13.4).
    async fn keep_cache(&mut self, path: Option<PathBuf>) {
        match path {
            Some(path) => {
                match std::fs::read(&path) {
                    Ok(sealed) => {
                        if let Err(error) = self.client.restore(&sealed) {
                            // Не беда: файл от другого сопряжения, испорчен
                            // или записан другой сборкой. Переписка живёт
                            // на телефоне, и перечитать её стоит круга по сети.
                            tracing::info!(?error, "кэш не поднят — начинаем с пустого");
                        } else {
                            // **Узел — сразу после подъёма файла.** Кэш
                            // включают командой, то есть уже после `run`,
                            // а свой узел поднимался только там и по новости.
                            // Без этой строки пиры с диска лежали бы мёртвым
                            // грузом до первой связи — ровно та поломка,
                            // ради которой их и стали записывать.
                            let peers = self.client.phone_ygg_peers().to_vec();
                            self.raise_own_node(peers).await;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => tracing::warn!(?error, "кэш не прочитан"),
                }
                self.cache_path = Some(path);
                // Уже накопленное ложится сразу: включив кэш, человек ждёт,
                // что он и правда начал храниться, а не начнёт с завтра.
                self.cache_after_ms = 0;
                self.persist_cache();
            }
            None => {
                // Выключение **стирает**, а не перестаёт обновлять: человек,
                // снявший галочку, имел в виду «здесь этого не должно быть».
                // Недописанный снимок выбрасывается вместе с файлом — иначе
                // он лёг бы на диск после того, как кэш выключили.
                self.cache_pending = None;
                if let Some(path) = self.cache_path.take() {
                    if let Err(error) = std::fs::remove_file(&path) {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(?error, "снимок кэша стереть не вышло");
                        }
                    }
                }
            }
        }
    }

    /// Кладёт снимок на диск, но не чаще, чем позволено.
    ///
    /// **Несостоявшаяся запись остаётся в руках.** `snapshot` снимает признак
    /// «изменилось» тем, что снимок собран, — про диск он ничего не знает.
    /// Выбросив собранные байты после отказа записи, драйвер потерял бы их
    /// навсегда: терминал уже считает, что файл и память сошлись, и следующий
    /// заход сюда просто вернётся ни с чем.
    fn persist_cache(&mut self) {
        let Some(path) = self.cache_path.clone() else { return };
        if self.cache_pending.is_none() && !self.client.snapshot_due() {
            return;
        }
        let now = (self.now)();
        if now < self.cache_after_ms {
            return;
        }
        let sealed = match self.cache_pending.take() {
            Some(sealed) => Some(sealed),
            None => match self.client.snapshot() {
                Ok(sealed) => Some(sealed),
                Err(error) => {
                    tracing::warn!(?error, "снимок кэша не собрался");
                    None
                }
            },
        };
        if let Some(sealed) = sealed {
            if let Err(error) = std::fs::write(&path, &sealed) {
                tracing::warn!(?error, "снимок кэша не записался — попробуем позже");
                self.cache_pending = Some(sealed);
            }
        }
        self.cache_after_ms = now + CACHE_WRITE_EVERY_MS;
    }

    /// Один вход терминала: кадры уезжают в сеть, события — наверх.
    ///
    /// Круг замыкается здесь же: `NeedChunk` и `FileBytes` до UI не доходят,
    /// драйвер отвечает на них сам. Ради этого он и заведён.
    async fn feed(&mut self, input: ClientInput) {
        let mut queue = vec![input];
        // Предел от кольца, а не от объёма: честный круг здесь — единицы
        // шагов, и только выгрузка файла делает их длиннее на один кусок.
        for _ in 0..8 {
            let Some(input) = (!queue.is_empty()).then(|| queue.remove(0)) else { break };
            for effect in self.client.step((self.now)(), input) {
                match effect {
                    ClientEffect::Send(frame) => self.push(frame).await,
                    ClientEffect::Show(event) => {
                        if let Some(answer) = self.show(event).await {
                            queue.push(answer);
                        }
                    }
                }
            }
        }
    }

    /// Говорит раннеру то, что не про отправку кадра.
    ///
    /// Отказ уходит в журнал и ничего не останавливает: ступень, которая
    /// не поднялась, лестница канала просто пропустит — она смотрит на то,
    /// поднялся ли **узел** (`ClientEvent`/`YggReady`), а не на то, что мы
    /// его попросили подняться.
    async fn tell_runner(&mut self, command: TransportCommand) {
        if let Err(error) = self.runner.execute(command).await {
            tracing::debug!(?error, "раннер не принял настройку");
        }
    }

    /// Отдаёт кадр в сеть.
    ///
    /// Адрес телефона берётся из приглашения — там он и лежит с самого
    /// сопряжения (`PairingInvite::onion`). До этой поставки сюда уезжал
    /// `None`, и вне общей сети терминал звонил в никуда, даже имея адрес
    /// в руках.
    async fn push(&mut self, frame: Vec<u8>) {
        let onion = self.client.phone_onion();
        let onion = (!onion.is_empty()).then(|| onion.to_owned());
        // Ключ меша — **каждый раз заново**, а не разобранный при запуске:
        // телефон вправе объявить новый по живому каналу
        // (`companion::Notice::LinkAddress`), и следующий кадр обязан идти
        // по объявленному.
        let ygg: Option<[u8; 32]> = self.client.phone_ygg().try_into().ok();
        let sent = self
            .runner
            .execute(TransportCommand::Send {
                peer: PeerAddress { ik: self.phone_ik, onion, chatmail: None, ygg },
                via: self.via,
                frame,
                handoff: None,
            })
            .await;
        if let Err(error) = sent {
            // В журнал, а не человеку: повтор рукопожатия идёт по таймеру,
            // и та же строка каждую секунду — не сообщение, а шум.
            tracing::debug!(?error, "кадр телефону не ушёл");
        }
    }

    /// Разбирает событие терминала: своё обслуживает, чужое отдаёт наверх.
    ///
    /// Возвращает вход, которым круг продолжается, — только для того, чем
    /// драйвер занимается сам.
    async fn show(&mut self, event: ClientEvent) -> Option<ClientInput> {
        match event {
            ClientEvent::FileBytes { index, bytes, .. } => {
                let Some(saving) = self.saving.as_mut() else {
                    tracing::debug!("кусок приехал, а писать некуда");
                    return None;
                };
                // Запись **по смещению**, а не в конец: дописывание работало
                // бы ровно до первого повтора куска и молча собрало бы файл
                // длиннее исходного.
                use std::io::{Seek, SeekFrom, Write};
                let written = saving
                    .file
                    .seek(SeekFrom::Start(index * CHUNK_BYTES as u64))
                    .and_then(|_| saving.file.write_all(&bytes));
                if let Err(error) = written {
                    self.abandon_save();
                    self.tell(CompanionEvent::Refused(format!("на диск не записалось: {error}")))
                        .await;
                    return Some(ClientInput::CancelFetch);
                }
                None
            }
            ClientEvent::FileDone { file_id } => {
                match self.saving.take() {
                    Some(saving) => {
                        // Настоящее имя файл получает **последним действием**,
                        // и до него под этим именем нет ничего: недокачанного
                        // файла, выглядящего готовым, не бывает вовсе.
                        drop(saving.file);
                        match std::fs::rename(&saving.partial, &saving.path) {
                            Ok(()) => {
                                self.tell(CompanionEvent::FileSaved { file_id, path: saving.path })
                                    .await;
                            }
                            Err(error) => {
                                // Байты все на диске, а имени у них нет.
                                // Молчать нельзя: человек ждёт файл там,
                                // где его не окажется.
                                let _ = std::fs::remove_file(&saving.partial);
                                self.tell(CompanionEvent::Refused(format!(
                                    "файл приехал, но переименовать его не вышло: {error}"
                                )))
                                .await;
                            }
                        }
                    }
                    None => tracing::debug!("вложение приехало, но писать было некуда"),
                }
                None
            }
            ClientEvent::NeedChunk { which, index, .. } => {
                let Some(sending) = self.sending.as_mut() else {
                    tracing::debug!("телефон просит кусок, а читать нечего");
                    return None;
                };
                // Очередь перешла к следующему файлу — открываем его.
                // Дескриптор один: терминал выгружает по очереди, и держать
                // десять открытых ради этого незачем.
                let which = which as usize;
                if which != sending.at {
                    let Some(path) = sending.paths.get(which).cloned() else {
                        tracing::debug!(which, "просят файл, которого в списке нет");
                        return None;
                    };
                    match std::fs::File::open(&path) {
                        Ok(file) => {
                            sending.at = which;
                            sending.file = file;
                        }
                        Err(error) => {
                            self.sending = None;
                            self.tell(CompanionEvent::Refused(format!(
                                "файл {} не прочитать: {error}",
                                path.display()
                            )))
                            .await;
                            return Some(ClientInput::CancelSend);
                        }
                    }
                }
                let Some(sending) = self.sending.as_mut() else { return None };
                use std::io::{Seek, SeekFrom};
                let mut buffer = vec![0u8; CHUNK_BYTES];
                let read = sending
                    .file
                    .seek(SeekFrom::Start(index * CHUNK_BYTES as u64))
                    .and_then(|_| read_full(&mut sending.file, &mut buffer));
                match read {
                    Ok(got) => {
                        buffer.truncate(got);
                        Some(ClientInput::PutChunk { index, bytes: buffer })
                    }
                    Err(error) => {
                        // Исходник исчез или не читается. Молчать нельзя:
                        // отправка встанет, а человек будет думать, что идёт.
                        let path = sending
                            .paths
                            .get(sending.at)
                            .cloned()
                            .unwrap_or_else(|| PathBuf::from("?"));
                        self.sending = None;
                        self.tell(CompanionEvent::Refused(format!(
                            "файл {} не прочитать: {error}",
                            path.display()
                        )))
                        .await;
                        Some(ClientInput::CancelSend)
                    }
                }
            }
            ClientEvent::Sent { file_ids } => {
                self.sending = None;
                self.tell(CompanionEvent::FilesSent { file_ids: file_ids.into_iter().collect() })
                    .await;
                None
            }
            ClientEvent::FetchCancelled { .. } => {
                self.abandon_save();
                None
            }
            ClientEvent::FilePreview { file_id, bytes } => {
                self.tell(CompanionEvent::FilePreview { file_id, bytes }).await;
                None
            }
            ClientEvent::Revoked => {
                // **Файл стирается здесь, а не оставляется до выключения
                // кэша человеком.** Терминал уже выбросил всё из памяти;
                // оставленный файл пережил бы перезапуск и поднялся бы
                // в окно, которому в этой переписке отказано.
                //
                // Путь тоже забывается: писать в него больше нечего,
                // а `persist_cache` без этого положил бы туда пустой снимок
                // сразу после стирания.
                self.cache_pending = None;
                if let Some(path) = self.cache_path.take() {
                    if let Err(error) = std::fs::remove_file(&path) {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            tracing::warn!(?error, "снимок кэша отозванного стереть не вышло");
                        }
                    }
                }
                self.tell(CompanionEvent::Revoked).await;
                None
            }
            ClientEvent::Avatar { chat, bytes, fresh } => {
                self.tell(CompanionEvent::Avatar { chat, bytes, fresh }).await;
                None
            }
            ClientEvent::Members { chat, members } => {
                self.tell(CompanionEvent::Members { chat, members }).await;
                None
            }
            ClientEvent::GroupCreated { chat } => {
                self.tell(CompanionEvent::GroupCreated { chat }).await;
                None
            }
            ClientEvent::AvatarChanged { chat, avatar_ms } => {
                self.tell(CompanionEvent::AvatarChanged { chat, avatar_ms }).await;
                None
            }
            ClientEvent::FileGone { file_id } => {
                // Качали его сюда — обрывок лишний.
                if self.saving.as_ref().is_some_and(|saving| saving.file_id == file_id) {
                    self.abandon_save();
                }
                self.tell(CompanionEvent::FileGone { file_id }).await;
                None
            }
            // **Отказ ничего не убирает**, и это исправление, а не небрежность.
            // Здесь стояло «убрать обрывок и отпустить пути» — по любому
            // отказу телефона, в том числе на правку чужого сообщения
            // посреди отправки. Живая выгрузка от этого вставала молча:
            // `NeedChunk` приходил, а читать было нечего. Теперь конец
            // отправки и конец сохранения приезжают своими событиями.
            ClientEvent::Refused(why) => {
                self.tell(CompanionEvent::Refused(why)).await;
                None
            }
            ClientEvent::SendStopped { why } => {
                self.sending = None;
                self.tell(CompanionEvent::Refused(why)).await;
                None
            }
            ClientEvent::FetchStopped { why } => {
                self.abandon_save();
                self.tell(CompanionEvent::Refused(why)).await;
                None
            }
            // Ни обрывок, ни дескриптор не трогаем: продолжение допишет
            // тот же файл с того же места.
            ClientEvent::FetchPaused => {
                self.tell(CompanionEvent::FetchPaused).await;
                None
            }
            ClientEvent::FetchResumed { done, total } => {
                self.tell(CompanionEvent::FetchResumed { done, total }).await;
                None
            }
            // Пути **не** отпускаются: выгрузка ждёт возвращения телефона
            // и продолжится с того же места. Сохранение продолжать нечем —
            // обрывок убираем, как убирали.
            ClientEvent::SendPaused => {
                self.tell(CompanionEvent::SendPaused).await;
                None
            }
            ClientEvent::SendResumed { done, total } => {
                self.tell(CompanionEvent::SendResumed { done, total }).await;
                None
            }
            // `abandon_save` здесь больше нет: и отправка, и приём переживают
            // разрыв. Убирает обрывок тот, кто знает, что продолжения
            // не будет, — отмена человеком, отказ телефона, исчезнувшее
            // вложение.
            ClientEvent::Unlinked => {
                self.tell(CompanionEvent::Unlinked).await;
                None
            }
            ClientEvent::Linked => {
                self.tell(CompanionEvent::Linked).await;
                None
            }
            ClientEvent::Wire { theirs, ours } => {
                self.tell(CompanionEvent::Wire { theirs, ours }).await;
                None
            }
            ClientEvent::Chats { chats, fresh } => {
                self.tell(CompanionEvent::Chats { chats, fresh }).await;
                None
            }
            ClientEvent::History { chat, page, fresh } => {
                self.tell(CompanionEvent::History { chat, page, fresh }).await;
                None
            }
            ClientEvent::Arrived(message) => {
                self.tell(CompanionEvent::Arrived(message)).await;
                None
            }
            ClientEvent::Status { msg_id, status } => {
                self.tell(CompanionEvent::Status { msg_id, status }).await;
                None
            }
            ClientEvent::ChatsChanged => {
                self.tell(CompanionEvent::ChatsChanged).await;
                None
            }
            ClientEvent::Gone { chat, msg_ids } => {
                self.tell(CompanionEvent::Gone { chat, msg_ids }).await;
                None
            }
            ClientEvent::Edited(message) => {
                self.tell(CompanionEvent::Edited(message)).await;
                None
            }
            ClientEvent::Reacted { chat, msg_id, reactions } => {
                self.tell(CompanionEvent::Reacted { chat, msg_id, reactions }).await;
                None
            }
            ClientEvent::FileProgress { file_id, have_chunks, chunk_total, accepted } => {
                self.tell(CompanionEvent::FileProgress {
                    file_id,
                    have_chunks,
                    chunk_total,
                    accepted,
                })
                .await;
                None
            }
            // **Адрес телефона сменился — и набирать надо по новому.**
            //
            // Наружу это не идёт: человеку сказать нечего, а вот раннеру
            // сказать надо. Он и набирает — ядро транспорта не видит (§13.3),
            // и без этой строки следующая попытка пошла бы по адресу из
            // приглашения, то есть по тому, которого у телефона может уже
            // не быть.
            ClientEvent::PhoneAddress { onion, ygg, ygg_peers } => {
                tracing::info!(
                    onion = !onion.is_empty(),
                    ygg = !ygg.is_empty(),
                    "телефон объявил, чем его набрать"
                );
                // Адрес ставить никуда не надо: он живёт у клиента, а `push`
                // читает его **перед каждым кадром**.
                //
                // А вот свой узел меша поднять надо, и поднять здесь: пиров
                // взять больше неоткуда. Зерно выводится из секрета
                // сопряжения, пиры только что приехали — оба числа наконец
                // есть, и раньше этой минуты их не было.
                //
                // Объявленный список полнее того, что уехал в QR, и заменяет
                // его целиком.
                self.raise_own_node(ygg_peers.clone()).await;
                None
            }
            ClientEvent::Done => {
                self.tell(CompanionEvent::Done).await;
                None
            }
            ClientEvent::NotLinked => {
                self.tell(CompanionEvent::NotLinked).await;
                None
            }
            // В журнал, а не на экран: «ничего не приходит» и «приходит
            // непонятное» обязаны различаться, но человека это не касается.
            ClientEvent::Ignored(why) => {
                tracing::debug!(why, "кадр не понят");
                None
            }
        }
    }

    /// Поднимает **свой** узел меша на названных пирах.
    ///
    /// Узел терминалу нужен свой: у ступени `Ygg` нет «клиентского» режима —
    /// адрес `200::/7` берётся из собственного ключа, и без работающего узла
    /// набирать нечем (см. `Transport::Ygg`).
    ///
    /// Пиров взять неоткуда, кроме телефона, и в этом была поломка: сперва
    /// они приезжали только объявлением по живому каналу, а живой канал
    /// требует поднятой ступени — узел не вставал никогда, если общей сети
    /// и Tor не было. Поэтому короткий список едет ещё и в приглашении,
    /// и первый вызов сюда случается на запуске, до всякой связи.
    ///
    /// Повторный вызов с тем же списком ничего не делает: раннер перенимает
    /// настройку перезапуском узла, а перезапускать работающий меш ради
    /// того же самого — рвать связь на ровном месте.
    ///
    /// Без ключа телефона узел не поднимается вовсе, и это то же условие,
    /// по которому лестница пропускает ступень (`mesh_ready`): меша нет
    /// у той стороны — ехать по нему некуда, а поднятый ни за чем узел
    /// это лишний демон и лишний открытый порт на чужой машине.
    ///
    /// Порядок тот же, что у ядра (`startup_effects`): настройка, потом
    /// выключатель. Раннер поднимается по той настройке, которая у него
    /// есть на момент включения.
    async fn raise_own_node(&mut self, peers: Vec<String>) {
        if peers.is_empty() || peers == self.mesh_peers || self.client.phone_ygg().is_empty() {
            return;
        }
        tracing::info!(пиров = peers.len(), "поднимаем свой узел меша");
        let setup = ratatosk_proto::ygg::YggSetup::Embedded {
            seed: ratatosk_proto::ygg::NodeSeed::new(self.client.mesh_seed().to_vec()),
            peers: peers.clone(),
        };
        self.mesh_peers = peers;
        self.tell_runner(TransportCommand::SetYgg(setup)).await;
        self.tell_runner(TransportCommand::SetEnabled { transport: Transport::Ygg, enabled: true })
            .await;
    }

    /// Отдаёт событие наверх. Некому — значит UI ушёл, и это не беда.
    async fn tell(&self, event: CompanionEvent) {
        let _ = self.notices.send(event).await;
    }
}

/// Что разбудило цикл.
enum Wake {
    Command(CompanionCommand),
    Transport(TransportEvent),
    Tick,
}

/// Читает столько, сколько поместится, — или до конца файла.
///
/// `Read::read` вправе вернуть меньше запрошенного и без всякой ошибки;
/// приняв это за конец файла, отправка резала бы куски произвольной длины,
/// а телефон отвергал бы их как «не той длины, какую обещал размер».
fn read_full(file: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read;
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            got => filled += got,
        }
    }
    Ok(filled)
}

/// Часы стенной эпохи в миллисекундах.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Вложение в том виде, в каком его показывают: реэкспорт для UI.
///
/// Чтобы клиенту не приходилось тянуть `ratatosk_proto` ради одного типа,
/// который он и так получает событиями.
pub type CompanionAttachment = Attachment;

/// Чат в списке — реэкспорт по той же причине.
pub type CompanionChat = ChatSummary;

/// Сообщение в том виде, в каком его видит десктоп, — реэкспорт.
pub type CompanionMessage = Message;
