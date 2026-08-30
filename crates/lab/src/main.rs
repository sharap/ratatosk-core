//! Стенд: два узла, локальная сеть, текст 1:1.
//!
//! Это не продукт и не пример архитектуры клиента. Это самый короткий способ
//! проверить, что ядро работает на живой сети, — до того, как появится UI,
//! и вместо того, чтобы проверять протокол через UI.
//!
//! Что он делает: поднимает ядро с хранилищем в памяти и LAN-транспортом,
//! печатает свою контакт-карточку, принимает чужую, и дальше каждая строка
//! со stdin уезжает собеседнику.
//!
//! ```text
//! # на первой машине
//! cargo run -p ratatosk-lab -- --name Алиса
//! # на второй
//! cargo run -p ratatosk-lab -- --name Боб
//! # обменяться напечатанными карточками через /add <карточка>
//! ```
//!
//! Порядок с onion такой: `/onion` на обеих машинах, потом `/card` — и уже
//! эту строку копировать. Карточка, скопированная до `/onion`, везёт пустой
//! адрес; ядро дошлёт настоящий при первой же связи (§4.3), но проверять
//! Tor на догоняющем обновлении вместо карточки — лишний повод запутаться.
//!
//! Обнаружение через mDNS работает не везде: мультикаст режут и гостевой
//! Wi-Fi, и часть корпоративных сетей. Поэтому есть `/addr` — вписать адрес
//! руками. Передача и обнаружение проверяются по отдельности намеренно:
//! иначе неудача не отличима от «сеть не пропускает mDNS».
//!
//! # Режим компаньона (§13.4)
//!
//! Ключ `--companion` полностью меняет роль стенда: вместо узла со своей
//! личностью он становится **терминалом** к телефону. Проверяется это двумя
//! процессами на одной машине:
//!
//! ```text
//! # первый — телефон
//! cargo run -p ratatosk-lab -- --name телефон --port 41234
//! > /pair ноутбук                   # печатает ссылку — скопировать целиком
//!
//! # второй — десктоп
//! cargo run -p ratatosk-lab -- --companion 'ratatosk:v0:pair:…' \
//!                              --peer 127.0.0.1:41234
//! > /devaddr …                      # строку печатает сам терминал —
//! >                                 # выполнить её надо на телефоне
//! ```
//!
//! Двух строк с адресами здесь не одна, а две, и это не избыточность:
//! соединения односторонние (`ARCHITECTURE.md`, 5ц), каждая сторона пишет
//! только в то, что набрала сама, — значит найти друг друга обязаны обе.
//! На loopback mDNS чаще всего нет, поэтому оба адреса вписываются руками.

// Предел глубины запросов компилятора поднят намеренно.
//
// `#[tokio::main]` заворачивает всё в одно будущее, и в нём вложены друг
// в друга `run_persistent` → `run` → `console` вместе с подъёмом Tor.
// Вычисление раскладки такого типа упирается в умолчание (128), и rustc
// сам предлагает поднять предел. На поведение это не влияет: речь про
// глубину анализа при сборке, а не про рекурсию в работе.
#![recursion_limit = "512"]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use ratatosk_codec::ContactCard;
use ratatosk_core::driver::{Driver, DriverHandle, EventStream};
use ratatosk_core::{
    vault, Command, CompanionClient, CompanionCommand, CompanionDriver, CompanionEvent,
    CompanionHandle, Engine, Event, OsEntropy, SelfAddresses,
};
use ratatosk_crypto::{Identity, OnionKey};
use ratatosk_proto::companion::{ChatSummary, Message, PairingInvite, Reaction};
use ratatosk_proto::mail::MailAccount;
use ratatosk_proto::DeliveryStatus;
use ratatosk_store::{FsBlobs, MemoryStore, Store};
#[cfg(feature = "tor")]
use ratatosk_transport::Switched;
// `Disabled` нужен только тем сборкам, где чего-то нет. С обоими признаками
// сразу все три ступени заняты настоящими раннерами, и безусловный импорт
// становится предупреждением — в сборке, которая как раз и есть рабочая.
#[cfg(any(not(feature = "tor"), not(feature = "mail")))]
use ratatosk_transport::Disabled;
use ratatosk_transport::{
    LanConfig, LanDirectory, LanRunner, Runner, TransportCommand, Transports,
};
use tokio::io::{AsyncBufReadExt, BufReader};

/// Есть ли в этом двоичном файле живой arti (§5.2).
///
/// Не «включён ли Tor», а «собран ли он вовсе», и разница стоила сеанса
/// разбора. Стенд без `--features tor` держит на месте onion
/// [`ratatosk_transport::Disabled`], а тот на переключатель отвечает
/// `Ok(())` — и правильно отвечает:
/// разрешение относится к §5.4, а не к сборке. Но снаружи это выглядело
/// так: `/tor on` принят, выбор записан в базу, строк подъёма нет ни одной.
/// Неотличимо от сломанного Tor — то есть ровно та «чужая неисправность
/// вместо своей», которую §14 запрещает показывать.
const TOR_BUILT_IN: bool = cfg!(feature = "tor");

/// Есть ли в этом двоичном файле сокеты почты (§5.3).
///
/// Та же история и та же цена: без `--features mail` просьба завести ящик
/// возвращается словами «транспорт недоступен», а они читаются как отказ
/// сервера, а не как отсутствие кода.
const MAIL_BUILT_IN: bool = cfg!(feature = "mail");

/// Чем собран этот стенд — одной строкой в шапку.
///
/// Печатается всегда, а не только когда чего-то нет: строка «почта: нет»
/// полезна ровно тем, что её ищут глазами после первой же непонятной тишины.
fn build_line() -> String {
    let tor = if TOR_BUILT_IN { "onion (arti)" } else { "onion НЕТ (--features tor)" };
    let mail = if MAIL_BUILT_IN { "почта" } else { "почта НЕТ (--features mail)" };
    format!("LAN, {tor}, {mail}")
}

struct Args {
    name: String,
    port: u16,
    discovery: bool,
    /// Работать ли по локальной сети (§5.1).
    ///
    /// Выключается ключом `--no-lan`, и это единственный способ проверить
    /// onion честно: LAN — первая ступень §5.4, и пока она работает,
    /// до второй дело не доходит.
    lan: bool,
    /// Не проверять права на каталоги Tor (`--trust-fs`).
    ///
    /// Нужно там, где `fs-mistrust` отвергает заведомо безопасный путь:
    /// каталог внутри контейнера, домашний каталог с необычными правами.
    /// На своей машине включать незачем.
    trust_fs: bool,
    data: Option<PathBuf>,
    pin: Option<String>,
    /// Каталог с несколькими аккаунтами (§3, дополнение).
    accounts: Option<PathBuf>,
    /// Имя аккаунта в этом каталоге; заводится, если его там ещё нет.
    account: Option<String>,
    /// Работать терминалом к телефону (§13.4): ссылка `ratatosk:v0:pair:…`.
    ///
    /// Полностью меняет режим стенда: своей личности, своей истории и своих
    /// контактов у терминала нет — он показывает чужие и просит чужой рукой.
    companion: Option<String>,
    /// Куда класть кэш терминала (§13.4). `None` — никуда.
    ///
    /// Это и есть та самая галочка «хранить кэш на диске»: по умолчанию
    /// её нет, и на диск не ложится ничего. В настоящем клиенте она стоит
    /// на экране сопряжения и переключается позже; здесь — ключ запуска
    /// и команда `/cache`.
    cache: Option<PathBuf>,
    /// Адрес телефона, если mDNS не работает: `127.0.0.1:41234`.
    ///
    /// Для проверки двумя процессами на одной машине это основной путь:
    /// mDNS на loopback работает не везде, а два процесса на 127.0.0.1 —
    /// самый короткий способ увидеть режим целиком.
    peer: Option<String>,
}

fn parse_args() -> Args {
    let mut args = Args {
        name: "узел".to_owned(),
        port: 0,
        discovery: true,
        lan: true,
        trust_fs: false,
        data: None,
        pin: None,
        accounts: None,
        account: None,
        companion: None,
        peer: None,
        cache: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--name" => args.name = argv.next().unwrap_or_default(),
            "--port" => args.port = argv.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            "--no-mdns" => args.discovery = false,
            "--no-lan" => args.lan = false,
            "--trust-fs" => args.trust_fs = true,
            "--data" => args.data = argv.next().map(PathBuf::from),
            "--pin" => args.pin = argv.next(),
            "--accounts" => args.accounts = argv.next().map(PathBuf::from),
            "--account" => args.account = argv.next(),
            "--companion" => args.companion = argv.next(),
            "--peer" => args.peer = argv.next(),
            "--cache" => args.cache = argv.next().map(PathBuf::from),
            other => eprintln!("неизвестный ключ: {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Фильтр берётся из `RUST_LOG`, а умолчание включает и arti.
    //
    // Прежнее умолчание («ratatosk=debug») скрывало журнал Tor целиком —
    // и вопрос «поднимается или уже нет» оставался без ответа при полном
    // молчании в консоли. Свой журнал у arti подробный и внятный; прятать
    // его от того, кто отлаживает сеть, незачем.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        "ratatosk=debug,arti_client=info,tor_dirmgr=info,tor_guardmgr=info,\
         tor_circmgr=info,tor_chanmgr=info,tor_hsservice=info"
            .to_owned()
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let mut args = parse_args();

    // Каталог аккаунтов сводится к пути базы: дальше всё работает как
    // с одиночной. Стенд проверяет ядро, а не список аккаунтов, — ему
    // достаточно уметь открыть нужный.
    if let Some(root) = args.accounts.clone() {
        match resolve_account(&root, args.account.as_deref()) {
            Ok(path) => args.data = Some(path),
            Err(error) => {
                eprintln!("аккаунт не открыть: {error}");
                return Ok(());
            }
        }
    }

    // Терминал — другой режим целиком, и разбирается он до всего остального:
    // ни хранилища, ни личности, ни аккаунтов ему не нужно.
    if let Some(uri) = args.companion.clone() {
        return run_companion(&args, &uri).await;
    }

    match (&args.data, &args.pin) {
        // §8.6: PIN необязателен, и его отсутствие — не ошибка. Но db_key
        // тогда надо класть в хранилище ключей ОС, которого у стенда нет,
        // а записать его рядом с базой значило бы сделать шифрование
        // декорацией. Поэтому здесь либо PIN, либо память.
        (Some(path), Some(pin)) => run_persistent(&args, path.clone(), pin.clone()).await,
        (Some(_), None) => {
            eprintln!("--data требует --pin: без него ключ базы негде хранить (§8.6)");
            Ok(())
        }
        (None, _) => run_ephemeral(&args).await,
    }
}

/// Стенд в роли десктопа-компаньона (§13.4).
///
/// Ничего своего у него нет: ни личности, ни истории, ни контактов. Есть
/// ссылка сопряжения, из зерна которой выводится статический ключ, и телефон
/// на другом конце. Всё, что показывается, приезжает оттуда.
///
/// **Проверять этим удобнее всего двумя процессами на одной машине:**
///
/// ```text
/// # первый — телефон
/// cargo run -p ratatosk-lab -- --name телефон --port 41234
/// > /pair ноутбук          # печатает ссылку — скопировать целиком
///
/// # второй — десктоп
/// cargo run -p ratatosk-lab -- --companion 'ratatosk:v0:pair:…' \
///                              --peer 127.0.0.1:41234
/// ```
///
/// `--peer` здесь не запасной путь, а основной: mDNS на loopback работает
/// не везде, и полагаться на него в проверке, которая должна быть быстрой,
/// незачем.
async fn run_companion(args: &Args, uri: &str) -> Result<(), Box<dyn std::error::Error>> {
    let invite = match PairingInvite::from_uri(uri.trim()) {
        Ok(invite) => invite,
        Err(error) => {
            eprintln!("ссылка сопряжения не годится: {error}");
            eprintln!("ждётся строка вида ratatosk:v0:pair:… — её печатает /pair на телефоне");
            return Ok(());
        }
    };

    let client = CompanionClient::from_invite(&invite, Box::new(OsEntropy));
    let phone_ik = client.phone_ik();

    // Маяк объявляется от **ключа сопряжения**, а не от какой-то своей
    // личности: телефон ищет в эфире именно его (§5.1), и другого способа
    // набрать десктоп у него нет — соединения односторонние.
    let config = LanConfig { enabled: true, port: args.port, discovery: args.discovery };
    let mut lan = LanRunner::start(config, client.ik()).await?;

    if let Some(peer) = args.peer.as_deref() {
        match peer.parse::<SocketAddr>() {
            Ok(addr) => lan.note_address(phone_ik, addr),
            Err(_) => eprintln!("--peer: нужен адрес вида 127.0.0.1:41234, а не «{peer}»"),
        }
    }
    lan.execute(TransportCommand::SetEnabled {
        transport: ratatosk_proto::Transport::Lan,
        enabled: true,
    })
    .await?;
    // Телефон объявляется от своего `IK`, и без этой строки его маяк
    // не с чем было бы сравнить.
    lan.execute(TransportCommand::WatchLanPeers(vec![phone_ik])).await?;

    println!("терминал : к «{}»", client.phone_name());
    println!("id       : {}", data_encoding::HEXLOWER.encode(&client.device_id()));
    println!("порт     : {}", lan.port());
    if invite.onion.is_empty() {
        println!("onion    : в приглашении пусто — только локальная сеть");
    } else {
        println!("onion    : {} (пока не используется: см. ARCHITECTURE, 5бб)", invite.onion);
    }
    println!();
    // Соединения односторонние (`ARCHITECTURE.md`, 5ц): телефон обязан
    // набрать десктоп сам, а на loopback mDNS работает не везде. Поэтому
    // строка печатается готовой к вставке — угадывать порт не придётся.
    if args.cache.is_none() {
        // §14: молчание об этом человек прочитает как «кэш есть».
        println!("кэш     : только в памяти — закроете окно, и он исчезнет");
        println!("           хранить на диске: --cache <путь> или /cache on <путь>");
        println!();
    }
    println!("если телефон не находит терминал сам, выполните на нём:");
    println!();
    println!("/devaddr {} 127.0.0.1:{}", data_encoding::HEXLOWER.encode(&client.ik()), lan.port());
    println!();
    println!("команды: /chats   /open <номер>   /more   /read   /cache [on <путь>|off]   /quit");
    println!("         /react <n> [эмодзи]   /reply <n> <текст>   /edit <n> <текст>");
    println!("         /del <n…>   /retract <n…>   /fwd <n…> <номер чата>   /clear");
    println!("         /accept <n> [k]   — качать вложение;  /pause — передумать");
    println!("         /decline <n> [k]  — отказаться совсем: приехавшее стирается");
    println!("         /preview <n> [k]  — превью вложения, если оно есть");
    println!("         /save <n> [k] <путь>   — забрать сюда;  /stop — прекратить");
    println!("         /send <путь…> [-- подпись] — отправить файлы одним сообщением");
    println!("         /sendpic <файл-превью> <путь> [подпись] — то же с превью");
    println!("         номер n — из строк, показанных /open и /more");
    println!("всё остальное уходит текстом в открытый чат");
    println!();

    // Среда — у драйвера, консоль — здесь. До этой поставки они были одним
    // куском, и переехали ради того, что этим же куском будет пользоваться
    // Kotlin: через UniFFI sans-io не пролезает (§13.3).
    let (mut driver, handle, events) = CompanionDriver::new(client, lan);
    let console = tokio::spawn(companion_console(handle, events, args.cache.clone()));
    tokio::select! {
        () = driver.run() => {}
        _ = console => {}
    }
    Ok(())
}

/// Всё, что помнит консоль терминала.
///
/// Помнит она мало и нарочно: история, список чатов и заголовки живут
/// на телефоне (§13.3), кэш и файлы — у [`CompanionDriver`], а здесь лежит
/// ровно то, без чего не составить следующую команду: какой чат открыт
/// и какие строки показаны последними.
struct Console {
    chats: Vec<ChatSummary>,
    /// Открытый чат. `None` — не выбран или связь пропала.
    current: Option<[u8; 16]>,
    /// Последняя показанная страница — то, на что ссылаются номера.
    page: Vec<Message>,
    /// Самое старое из показанного — курсор для `/more`.
    oldest: Option<[u8; 16]>,
    /// Самое новое из показанного — граница для `/read`.
    newest: Option<[u8; 16]>,
}

impl Console {
    fn new() -> Console {
        Console { chats: Vec::new(), current: None, page: Vec::new(), oldest: None, newest: None }
    }

    /// Печатает событие компаньона и обновляет то немногое, что помним.
    fn show(&mut self, event: CompanionEvent) {
        match event {
            CompanionEvent::Linked => println!("< телефон на связи"),
            CompanionEvent::Wire { theirs, ours } => match theirs {
                // Совпало — молчим: сообщать «всё в порядке» на каждом
                // подключении значит приучить не читать эту строку.
                Some(theirs) if theirs == ours => {}
                Some(theirs) => {
                    println!("< ВНИМАНИЕ: провод телефона версии {theirs}, здесь {ours}");
                    println!("    показ будет неполным — часть нового просто не приедет");
                }
                None => {
                    println!("< ВНИМАНИЕ: телефон не назвал версию провода вовсе");
                    println!("    значит его сборка старее этой — пересоберите ядро");
                }
            },
            CompanionEvent::Unlinked => {
                // §14, пункт 5: телефон офлайн — десктоп не работает.
                self.current = None;
                println!("< телефона нет в сети — отсюда сейчас не отправить ничего");
            }
            CompanionEvent::Chats { chats, fresh } => {
                self.chats = chats;
                if self.chats.is_empty() {
                    println!("< чатов нет");
                }
                if !fresh {
                    println!("< (из памяти — телефон ещё не подтверждал)");
                }
                for (n, chat) in self.chats.iter().enumerate() {
                    let mark = if chat.verified { "+" } else { " " };
                    println!("< {:>2}. {mark} {}: {}", n + 1, chat.title, chat.last_text);
                }
            }
            CompanionEvent::History { chat, page, fresh } => {
                // Чат в событии, а не по памяти: `/open` могли нажать, пока
                // эта страница ехала, и высыпать её в чужой разговор — худшее,
                // что можно сделать с историей.
                if self.current != Some(chat) {
                    println!("< страница не открытого сейчас чата — пропущена");
                    return;
                }
                if !fresh {
                    println!("< (из памяти — телефон ещё не подтверждал)");
                }
                if let Some(first) = page.first() {
                    self.oldest = Some(first.msg_id);
                }
                if let Some(last) = page.last() {
                    self.newest = Some(last.msg_id);
                }
                if page.is_empty() {
                    println!("< дальше ничего нет");
                }
                self.page = page;
                for (n, message) in self.page.iter().enumerate() {
                    println!("< {:>2}. {}", n + 1, line(message));
                }
            }
            CompanionEvent::Arrived(message) => {
                self.newest = Some(message.msg_id);
                self.page.push(message);
                let n = self.page.len();
                println!("< {n:>2}. {}", line(&self.page[n - 1]));
            }
            CompanionEvent::Status { msg_id, status } => match DeliveryStatus::from_code(status) {
                Some(status) => println!("< {} -> {status:?}", short(&msg_id)),
                None => println!("< {}: статус {status} неизвестен", short(&msg_id)),
            },
            CompanionEvent::ChatsChanged => println!("< список чатов изменился — /chats"),
            CompanionEvent::Gone { msg_ids, .. } => {
                for msg_id in &msg_ids {
                    println!("< {} стёрто", short(msg_id));
                }
                let before = self.page.len();
                self.page.retain(|message| !msg_ids.contains(&message.msg_id));
                if self.page.len() != before {
                    println!("< (нумерация сдвинулась — /open покажет заново)");
                }
                if self.oldest.is_some_and(|id| msg_ids.contains(&id)) {
                    self.oldest = None;
                }
                if self.newest.is_some_and(|id| msg_ids.contains(&id)) {
                    self.newest = None;
                }
            }
            CompanionEvent::Edited(message) => {
                println!("< {} исправлено: {}", short(&message.msg_id), line(&message));
            }
            CompanionEvent::Reacted { msg_id, reactions, .. } => {
                if reactions.is_empty() {
                    println!("< {}: реакций больше нет", short(&msg_id));
                } else {
                    println!("< {}: реакции{}", short(&msg_id), adorn(&reactions));
                }
            }
            CompanionEvent::FileProgress { file_id, have_chunks, chunk_total, accepted } => {
                for message in &mut self.page {
                    for file in message.files.iter_mut().filter(|f| f.file_id == file_id) {
                        file.have_chunks = have_chunks;
                        file.accepted = accepted;
                    }
                }
                // Три разных состояния при одних и тех же числах, и путать
                // их нельзя: остановлено человеком, идёт, готово.
                if !accepted {
                    println!(
                        "< {}: остановлено на {have_chunks}/{chunk_total} — /accept продолжит",
                        short(&file_id)
                    );
                } else if have_chunks >= chunk_total {
                    println!("< {} принят целиком — можно /save", short(&file_id));
                } else {
                    println!("< {}: {have_chunks}/{chunk_total}", short(&file_id));
                }
            }
            CompanionEvent::FilePreview { file_id, bytes } => match bytes {
                // Консоль картинку не нарисует, и притворяться незачем:
                // она говорит, что приехало и сколько. Настоящему клиенту
                // здесь место для самого изображения.
                Some(bytes) => println!(
                    "< превью {}: {} — консоль его не покажет, окно покажет",
                    short(&file_id),
                    bytes_text(bytes.len() as u64)
                ),
                None => println!("< превью {}: телефону нечего показать", short(&file_id)),
            },
            CompanionEvent::FileGone { file_id } => {
                for message in &mut self.page {
                    message.files.retain(|file| file.file_id != file_id);
                }
                println!("< вложение {} убрано — от него отказались", short(&file_id));
            }
            CompanionEvent::FileSaved { path, .. } => {
                println!("< вложение сохранено: {}", path.display());
            }
            CompanionEvent::FilesSent { file_ids } => {
                let files = if file_ids.len() == 1 {
                    "файл".to_owned()
                } else {
                    format!("{} файлов одним сообщением", file_ids.len())
                };
                println!("< {files} отправлен — «отправлено», а не «доставлено» (§9.4)");
            }
            CompanionEvent::FetchPaused => {
                println!("< связь пропала — приём ждёт, записанное лежит рядом с «.part»");
            }
            CompanionEvent::FetchResumed { done, total } => {
                println!("< продолжаю приём: {done} кусков из {total} уже на диске");
            }
            CompanionEvent::SendPaused => {
                println!("< связь пропала — отправка ждёт, выгруженное лежит у телефона");
            }
            CompanionEvent::SendResumed { done, total } => {
                println!("< продолжаю отправку: {done} из {total} файлов уже на телефоне");
            }
            CompanionEvent::Done => {}
            CompanionEvent::Refused(why) => println!("< телефон отказал: {why}"),
            CompanionEvent::NotLinked => println!("< телефона нет в сети"),
        }
    }

    /// Номер из последней показанной страницы — в идентификатор сообщения.
    fn pick(&self, picked: &str) -> Option<[u8; 16]> {
        if self.current.is_none() {
            println!("< сперва /open <номер>");
            return None;
        }
        match picked.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.page.len()) {
            Some(n) => Some(self.page[n - 1].msg_id),
            None => {
                println!("< нужен номер строки из показанного, от 1 до {}", self.page.len());
                None
            }
        }
    }

    /// То же для списка номеров через пробел.
    fn pick_many(&self, picked: &str) -> Option<Vec<[u8; 16]>> {
        let mut out = Vec::new();
        for word in picked.split_whitespace() {
            out.push(self.pick(word)?);
        }
        if out.is_empty() {
            println!("< нужен хотя бы один номер строки");
            return None;
        }
        Some(out)
    }

    /// «<номер строки> [номер вложения]» — во вложение.
    fn pick_file(&self, rest: &str) -> Option<&ratatosk_proto::companion::Attachment> {
        let words: Vec<&str> = rest.split_whitespace().collect();
        let (picked, which) = match words.as_slice() {
            [n] => (*n, 1usize),
            [n, k] => (*n, k.parse::<usize>().unwrap_or(0)),
            _ => {
                println!("< нужен номер строки, и через пробел — номер вложения, если их много");
                return None;
            }
        };
        let msg_id = self.pick(picked)?;
        let message = self.page.iter().find(|m| m.msg_id == msg_id)?;
        match which.checked_sub(1).and_then(|k| message.files.get(k)) {
            Some(file) => Some(file),
            None if message.files.is_empty() => {
                println!("< в этом сообщении вложений нет");
                None
            }
            None => {
                println!("< у этого сообщения вложений {}", message.files.len());
                None
            }
        }
    }

    /// Превращает строку человека в команду компаньону.
    ///
    /// `None` — просить нечего: команда обслужена на месте либо не понята.
    fn parse(&mut self, line: String) -> Option<CompanionCommand> {
        if line == "/chats" {
            return Some(CompanionCommand::Chats);
        }
        if let Some(rest) = line.strip_prefix("/open ") {
            let picked =
                rest.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
            let Some(n) = picked else {
                println!("< нужен номер из /chats, от 1 до {}", self.chats.len());
                return None;
            };
            let chat = self.chats[n - 1].chat;
            self.current = Some(chat);
            self.oldest = None;
            self.newest = None;
            println!("< открыт чат «{}»", self.chats[n - 1].title);
            return Some(CompanionCommand::History { chat, limit: 20, before: None });
        }
        if line == "/more" {
            let Some(chat) = self.current else {
                println!("< сперва /open <номер>");
                return None;
            };
            let Some(before) = self.oldest else {
                println!("< листать нечего: в этом чате ничего не показано");
                return None;
            };
            return Some(CompanionCommand::History { chat, limit: 20, before: Some(before) });
        }
        if let Some(rest) = line.strip_prefix("/react ") {
            let (picked, emoji) = split_first(rest);
            let msg_id = self.pick(picked)?;
            let chat = self.current?;
            return Some(CompanionCommand::SetReaction { chat, msg_id, emoji: emoji.to_owned() });
        }
        if let Some(rest) = line.strip_prefix("/reply ") {
            let (picked, text) = split_first(rest);
            let reply_to = self.pick(picked)?;
            let chat = self.current?;
            if text.is_empty() {
                println!("< ответ без слов — не ответ: /reply <номер> <текст>");
                return None;
            }
            return Some(CompanionCommand::SendReply { chat, reply_to, text: text.to_owned() });
        }
        if let Some(rest) = line.strip_prefix("/edit ") {
            let (picked, text) = split_first(rest);
            let msg_id = self.pick(picked)?;
            let chat = self.current?;
            if text.is_empty() {
                // Пустая правка — это не правка, а удаление, и для него
                // есть отдельная команда.
                println!("< пустая правка — это удаление: /del или /retract");
                return None;
            }
            return Some(CompanionCommand::EditMessage { chat, msg_id, text: text.to_owned() });
        }
        if let Some(rest) = line.strip_prefix("/del ") {
            let msg_ids = self.pick_many(rest)?;
            let chat = self.current?;
            return Some(CompanionCommand::DeleteMessages { chat, msg_ids });
        }
        if let Some(rest) = line.strip_prefix("/retract ") {
            let msg_ids = self.pick_many(rest)?;
            let chat = self.current?;
            println!("< это просьба, а не гарантия: чужой клиент вправе её не выполнить");
            return Some(CompanionCommand::RetractMessages { chat, msg_ids });
        }
        if let Some(rest) = line.strip_prefix("/fwd ") {
            let (picked, target) = split_first(rest);
            let msg_ids = self.pick_many(picked)?;
            let into =
                target.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
            let Some(n) = into else {
                println!("< куда пересылать: /fwd <номер сообщения> <номер чата из /chats>");
                return None;
            };
            return Some(CompanionCommand::ForwardMessages {
                chat: self.chats[n - 1].chat,
                msg_ids,
            });
        }
        if line == "/clear" {
            let Some(chat) = self.current else {
                println!("< сперва /open <номер>");
                return None;
            };
            println!("< чат очищается **у себя**: собеседник не узнает ничего");
            return Some(CompanionCommand::ClearChat { chat });
        }
        if let Some(rest) = line.strip_prefix("/accept ") {
            let file_id = self.pick_file(rest)?.file_id;
            return Some(CompanionCommand::AcceptFile { file_id });
        }
        if let Some(rest) = line.strip_prefix("/pause ") {
            let file_id = self.pick_file(rest)?.file_id;
            println!("< приехавшее остаётся: /accept продолжит с того же места");
            return Some(CompanionCommand::PauseFile { file_id });
        }
        if let Some(rest) = line.strip_prefix("/preview ") {
            let file = self.pick_file(rest)?;
            if !file.has_preview {
                println!("< у этого вложения превью нет — спрашивать нечего");
                return None;
            }
            return Some(CompanionCommand::Preview { file_id: file.file_id });
        }
        if let Some(rest) = line.strip_prefix("/decline ") {
            let file_id = self.pick_file(rest)?.file_id;
            println!("< собеседник об отказе не узнает — это решение о своей памяти");
            return Some(CompanionCommand::DeclineFile { file_id });
        }
        if let Some(rest) = line.strip_prefix("/save ") {
            let words: Vec<&str> = rest.split_whitespace().collect();
            let (picked, path) = match words.as_slice() {
                [n, path] => (format!("{n}"), *path),
                [n, k, path] => (format!("{n} {k}"), *path),
                _ => {
                    println!("< /save <номер строки> [номер вложения] <путь без пробелов>");
                    return None;
                }
            };
            let file = self.pick_file(&picked)?;
            if !file.accepted {
                println!("< телефон это вложение ещё не принял — сперва /accept");
                return None;
            }
            if file.have_chunks < file.chunk_total {
                println!(
                    "< телефон получил {} кусков из {} — вложение ещё едет к нему самому",
                    file.have_chunks, file.chunk_total
                );
                return None;
            }
            return Some(CompanionCommand::SaveFile {
                file_id: file.file_id,
                chunk_total: file.chunk_total,
                path: PathBuf::from(path),
            });
        }
        if line == "/stop" {
            return Some(CompanionCommand::CancelSave);
        }
        // Превью собирает клиент — стенд не клиент и картинок не рисует.
        // Поэтому он берёт **готовый файл** и отдаёт его байтами: проверить
        // дорогу можно, не заводя в стенде декодера изображений, которому
        // рядом с ключами и не место (§10.3).
        // Превью собирает клиент — стенд не клиент и картинок не рисует.
        // Поэтому он берёт **готовый файл** и отдаёт его байтами: проверить
        // дорогу можно, не заводя в стенде декодера изображений, которому
        // рядом с ключами и не место (§10.3).
        if let Some(rest) = line.strip_prefix("/sendpic ") {
            let (pic, rest) = split_first(rest);
            let (path, text) = split_first(rest);
            let Some(chat) = self.current else {
                println!("< сперва /open <номер>");
                return None;
            };
            if path.is_empty() {
                println!("< /sendpic <файл-превью> <путь> [подпись]");
                return None;
            }
            let preview = match std::fs::read(pic) {
                Ok(bytes) => bytes,
                Err(error) => {
                    println!("< превью {pic} не прочитать: {error}");
                    return None;
                }
            };
            println!("< превью: {}", bytes_text(preview.len() as u64));
            return Some(CompanionCommand::SendFiles {
                chat,
                files: vec![(PathBuf::from(path), Some(preview))],
                text: text.to_owned(),
            });
        }
        // Несколько файлов — одним сообщением. Разделитель `--`, а не пробел:
        // пути с пробелами стенд и так не берёт, но подпись отличить от пути
        // иначе нечем, а «последнее слово — подпись» ломается на первом же
        // однословном пути.
        if let Some(rest) = line.strip_prefix("/send ") {
            let Some(chat) = self.current else {
                println!("< сперва /open <номер>");
                return None;
            };
            let (paths, text) = match rest.split_once(" -- ") {
                Some((paths, text)) => (paths, text.trim()),
                None => (rest, ""),
            };
            let files: Vec<(PathBuf, Option<Vec<u8>>)> = paths
                .split_whitespace()
                // Без превью — законный и обычный случай: не картинка,
                // не смогли, не захотели.
                .map(|path| (PathBuf::from(path), None))
                .collect();
            if files.is_empty() {
                println!("< /send <путь…> [-- подпись]");
                return None;
            }
            if files.len() > 1 {
                println!("< {} файлов одним сообщением", files.len());
            }
            return Some(CompanionCommand::SendFiles { chat, files, text: text.to_owned() });
        }
        if line == "/unsend" {
            return Some(CompanionCommand::CancelSend);
        }
        if let Some(rest) = line.strip_prefix("/cache") {
            let rest = rest.trim();
            if rest == "off" {
                println!("< кэш выключен и файл стёрт");
                return Some(CompanionCommand::KeepCache { path: None });
            }
            if let Some(path) = rest.strip_prefix("on ") {
                // §14: сказать, чего это шифрование НЕ даёт, — обязательно.
                println!("    зашифрован ключом из зерна сопряжения, а зерно лежит рядом:");
                println!("    защищает от скопированного файла и от бэкапа, но не от");
                println!("    того, кто забрал эту машину целиком");
                return Some(CompanionCommand::KeepCache {
                    path: Some(PathBuf::from(path.trim())),
                });
            }
            println!("< /cache on <путь> | /cache off");
            return None;
        }
        if line == "/read" {
            return match (self.current, self.newest) {
                (Some(chat), Some(up_to)) => Some(CompanionCommand::MarkRead { chat, up_to }),
                _ => {
                    println!("< нечего отмечать: сперва /open <номер>");
                    None
                }
            };
        }
        if line.starts_with('/') {
            println!("< команды:");
            println!("<   /chats   /open <номер>   /more   /read");
            println!("<   /react <n> [эмодзи]   /reply <n> <текст>   /edit <n> <текст>");
            println!("<   /del <n…>   /retract <n…>   /fwd <n…> <номер чата>   /clear");
            println!("<   /accept <n> [k]   /pause <n> [k]   /decline <n> [k]");
            println!("<   /preview <n> [k]");
            println!("<   /save <n> [k] <путь>   /stop");
            println!("<   /send <путь…> [-- подпись]   /sendpic <превью> <путь> [подпись]");
            println!("<   /unsend");
            println!("<   /cache [on <путь>|off]   /quit");
            return None;
        }
        // Предел в **байтах**: кириллица в UTF-8 идёт по два, эмодзи по
        // четыре. Стенд говорит это до отправки — ровно то, что настоящее
        // окно обязано показывать счётчиком.
        if !ratatosk_proto::files::text_fits(line.len()) {
            println!(
                "< {} байт при пределе {} — столько в одно сообщение не влезает",
                line.len(),
                ratatosk_proto::files::MAX_TEXT_BYTES
            );
            return None;
        }
        match self.current {
            Some(chat) => Some(CompanionCommand::SendText { chat, text: line }),
            None => {
                println!("< сперва /open <номер> — /chats покажет список");
                None
            }
        }
    }
}

/// Консоль терминала: строки со stdin и события компаньона.
///
/// Транспорта, часов и диска здесь больше нет — всё это у
/// [`CompanionDriver`]. Осталось то, чем консоль и является: разбор строк
/// и печать.
async fn companion_console(
    handle: CompanionHandle,
    mut events: ratatosk_core::CompanionEvents,
    cache_path: Option<PathBuf>,
) {
    let mut console = Console::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    if let Some(path) = cache_path {
        println!("< кэш будет лежать в {}", path.display());
        handle.send(CompanionCommand::KeepCache { path: Some(path) }).await.ok();
    }

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { return };
                let line = line.trim().to_owned();
                if line.is_empty() {
                    continue;
                }
                if line == "/quit" {
                    return;
                }
                if let Some(command) = console.parse(line) {
                    if handle.send(command).await.is_err() {
                        return;
                    }
                }
            }
            event = events.next() => {
                let Some(event) = event else { return };
                console.show(event);
            }
        }
    }
}

/// Находит базу аккаунта по имени, заводя его при необходимости.
///
/// Реестр лежит открытым, и это видно прямо здесь: имя аккаунта читается
/// без всякого PIN. Так и задумано — список надо показать до разблокировки,
/// — но означает это, что взявший каталог видит, сколько аккаунтов и как
/// они названы.
fn resolve_account(
    root: &Path,
    label: Option<&str>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut registry = ratatosk_core::Registry::open(root)?;
    let label = label.unwrap_or("основной");

    if let Some(known) = registry.listed().iter().find(|a| a.label == label) {
        return Ok(registry.db_path(&known.id));
    }
    let created = registry.create(&mut OsEntropy, label, 0)?;
    println!("аккаунт  : {label} — заведён");
    Ok(registry.db_path(&created.id))
}

/// Хранилище в памяти: личность живёт до выхода.
async fn run_ephemeral(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.migrate()?;
    let identity = Identity::generate();
    // Ключ onion-сервиса тоже на один запуск: адрес нужен команде `/onion`,
    // а постоянство адреса проверяется на дисковом хранилище.
    let onion = OnionKey::generate();
    println!("хранилище: в памяти — перезапуск сотрёт личность и историю");
    // Без каталога: поднимать Tor на одноразовом ключе незачем — адрес
    // всё равно исчезнет вместе с процессом, а bootstrap стоит десятков
    // секунд. Команда `/onion` при этом работает: она проверяет §4.3,
    // а не сеть.
    run(args, identity, store, onion, None).await
}

/// Хранилище на диске: личность и переписка переживают перезапуск.
async fn run_persistent(
    args: &Args,
    path: PathBuf,
    pin: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Тот же путь, которым идёт клиент через UniFFI: политика ключей одна
    // на всех, иначе стенд проверял бы не то, что поедет пользователю.
    let (mut store, db_key) = vault::open_encrypted(&path, vault::Unlock::Pin(&pin))?;

    // Порядок важен: сначала личность, потом всё остальное. Сгенерировать
    // её поверх существующего зерна значит выбросить устройство целиком.
    let identity = vault::load_or_create(&mut store, &db_key)?;

    // Ключ onion-сервиса заводится здесь же и тем же `db_key`, но отдельной
    // записью: §3 выводит его независимо от зерна, и резервная фраза его
    // не возвращает. Адрес печатается ради проверки руками — перезапуск
    // обязан дать ту же строку. В карточку он при этом не попадает: сервиса
    // ещё нет, а обещать адрес, который никто не слушает, §14 запрещает.
    let onion = vault::load_or_create_onion(&mut store, &db_key)?;

    // Раскладка ключа в каталог, который читает arti (§5.2). Делается на
    // каждый запуск: файл могли удалить или перенести базу без него, а молча
    // поднявшийся сервис с другим адресом хуже, чем перезапись того же.
    //
    // Проверить руками стоит именно здесь: содержимое каталога видно `ls`,
    // и `hostname` обязан совпасть с напечатанным адресом.
    let layout = ratatosk_core::TorLayout::beside(&path);
    ratatosk_core::write_onion_keystore(&layout.keys, &onion)?;

    println!("хранилище: {}", path.display());
    // «Посчитан», а не «onion»: это предсказание из нашего ключа, а сервис
    // назовёт свой. Совпасть они обязаны, и пока это подписано как факт,
    // расхождение никто не заметит — см. `/tor`.
    println!("посчитан : {}", onion.address());
    println!("ключи    : {}", layout.keys.display());
    println!("состояние: {}", layout.state.display());
    run(args, identity, store, onion, Some(layout)).await
}

async fn run<S: Store + 'static>(
    args: &Args,
    identity: Identity,
    store: S,
    onion: OnionKey,
    layout: Option<ratatosk_core::TorLayout>,
) -> Result<(), Box<dyn std::error::Error>> {
    let onion_address = onion.address();
    // Адреса onion и chatmail намеренно пустые: этот стенд проверяет LAN,
    // а §5.4 с непустыми адресами увёл бы доставку на транспорты, которых
    // ещё нет, — и отказ выглядел бы как отказ локальной сети.
    let addresses = SelfAddresses {
        onion: String::new(),
        chatmail: String::new(),
        display_name: args.name.clone(),
    };

    // Вложения стенда лежат рядом с базой; без `--data` — во временном
    // каталоге, как и всё остальное состояние такого запуска.
    let blobs = FsBlobs::new(args.data.as_ref().map_or_else(
        || std::env::temp_dir().join("ratatosk-lab-files"),
        |p| p.with_extension("files"),
    ));
    let mut engine = Engine::new(identity, store, Box::new(blobs), Box::new(OsEntropy), addresses);
    let known = engine.restore()?;

    let own_ik = engine.own_card().ik;
    let card = BASE64URL_NOPAD.encode(&engine.own_card().encode()?);
    let fingerprint = engine.fingerprint();

    let config = LanConfig { enabled: args.lan, port: args.port, discovery: args.discovery };
    let lan = LanRunner::start(config, engine.own_card().ik).await?;
    let port = lan.port();
    let directory = lan.directory();

    // Ручка общего Tor-клиента — одна на обе ветки и на оба транспорта.
    // Onion-раннер кладёт в неё клиента, когда поднимется; почта берёт его
    // оттуда, а своего второго не заводит (§5.2: второй bootstrap — это
    // ещё десятки мегабайт памяти).
    let tor_handle = ratatosk_transport::onion::TorHandle::default();

    // Почтовый раннер живёт в обеих ветках: почта от Tor не зависит —
    // §5.3 по умолчанию идёт через него, но умеет и напрямую.
    #[cfg(feature = "mail")]
    let mail = ratatosk_transport::chatmail::runner::MailRunner::new(tor_handle.clone());
    #[cfg(not(feature = "mail"))]
    let mail = Disabled;

    // С признаком `tor` и дисковым хранилищем стенд поднимает настоящий
    // onion — в фоне, как это делает клиент: bootstrap идёт десятки секунд,
    // а команды со stdin обязаны работать сразу.
    #[cfg(feature = "tor")]
    let runner = {
        // Оба случая дают **один тип**: без каталога подъём сразу
        // объявляется неудавшимся. Так стенд с хранилищем в памяти
        // не поднимает Tor на одноразовом ключе — адрес всё равно исчез бы
        // вместе с процессом, — но составной раннер остаётся тем же.
        // Всё нужное для подъёма — под `Arc`, и это не украшение:
        // поднимать придётся столько раз, сколько человек передумает
        // (`/tor on`, `/tor off`), а замыкание-фабрика забирать в себя
        // ничего не вправе.
        let setup = std::sync::Arc::new((layout, onion, args.trust_fs));
        let handle = tor_handle.clone();
        let onion = Switched::new(move |progress| {
            let setup = std::sync::Arc::clone(&setup);
            let tor = handle.clone();
            async move {
                let (layout, key, trust_fs) = &*setup;
                let Some(layout) = layout.as_ref() else {
                    return Err(ratatosk_transport::TransportError::Unavailable);
                };
                ratatosk_transport::onion::arti::OnionRunner::start(
                    ratatosk_transport::onion::arti::OnionSetup {
                        state_dir: &layout.state,
                        cache_dir: &layout.cache,
                        keystore_dir: &layout.keys,
                        key,
                        dangerously_trust_filesystem: *trust_fs,
                        tor,
                    },
                    progress,
                )
                .await
            }
        });
        Transports::new(lan, onion, mail)
    };
    #[cfg(not(feature = "tor"))]
    let runner = {
        // Без признака onion и почта — `Disabled`: честный отказ, а не
        // молчаливый успех. Ровно это увидит §5.4 и перейдёт к следующей
        // ступени.
        let _ = (&layout, &onion, &tor_handle);
        Transports::new(lan, Disabled, mail)
    };

    println!("узел     : {}", args.name);
    println!("отпечаток: {fingerprint}");
    println!("порт     : {port}");
    // Раньше этой строки не было, и стенд без транспорта выглядел точно так
    // же, как стенд со сломанным транспортом. Разбирать вторую неисправность,
    // имея первую, можно долго.
    println!("сборка   : {}", build_line());
    println!(
        "сеть     : {}",
        if args.lan {
            "LAN включена — она первая ступень §5.4; выключить: /lan"
        } else {
            "LAN выключена (--no-lan) — доставка пойдёт через onion"
        }
    );
    if known > 0 {
        println!("контакты : {known} поднято с диска — /who");
    }
    println!();
    // Печатается готовая строка целиком, а не одна карточка: копировать кусок
    // из середины вывода — лишний повод ошибиться, а ошибка вылезет только
    // на разборе base64.
    println!("на второй машине выполните (строка копируется целиком):");
    println!();
    println!("/add {card}");
    println!();
    println!("если mDNS в вашей сети не работает, допишите через пробел адрес");
    println!("этой машины: /add <карточка> 192.168.1.5:{port}");
    println!();
    println!("строка выше — снимок на момент старта. После /onion карточка");
    println!("меняется, и свежую печатает /card — копировать нужно её.");
    println!();
    println!(
        "команды: /add <карточка> [ip:порт]   /card   /who   /lan   /tor [on|off]   /mail [set|new|tor|off]   /net   /onion   /pair <метка>   /devices   /devaddr <ключ> <ip:порт>   /unpair <id>   /find <слова>   /share   /take <msg_id>   /react [эмодзи]   /sweep   /quit"
    );
    println!("всё остальное уходит текстом первому добавленному контакту");
    println!();

    let (mut driver, handle, events) = Driver::new(engine, runner);

    // §5.1: LAN выключен по умолчанию. Стенд включает его явно — ровно так же,
    // как это должен будет сделать пользователь в UI. Команда идёт первой:
    // она проставляет разрешение уже поднятым с диска контактам.
    handle
        .send(Command::SetTransportEnabled {
            transport: ratatosk_proto::Transport::Lan,
            enabled: args.lan,
        })
        .await
        .ok();

    tokio::select! {
        result = driver.run() => {
            if let Err(error) = result {
                eprintln!("ядро остановилось: {error}");
            }
        }
        () = console(handle, events, directory, own_ik, onion_address, args.lan) => {}
    }
    Ok(())
}

/// Консоль: команды со stdin и события из ядра.
async fn console(
    handle: DriverHandle,
    mut events: EventStream,
    directory: LanDirectory,
    own_ik: [u8; 32],
    // Свой onion-адрес — для команды `/onion` (§4.3).
    onion_address: String,
    // Включена ли сейчас локальная сеть; переключается командой `/lan`.
    mut lan_on: bool,
) {
    // Последняя новость о Tor — для команды `/tor`. Именно последняя,
    // а не все: новости о подъёме это состояние, а не история.
    let mut tor: Option<String> = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut peer: Option<[u8; 32]> = None;

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Ok(Some(line)) = line else { return };
                let line = line.trim().to_owned();
                if line.is_empty() {
                    continue;
                }
                if line == "/quit" {
                    return;
                }
                if line == "/who" {
                    show_contacts(&handle, &directory).await;
                    continue;
                }
                if line == "/devices" {
                    show_devices(&handle, &directory).await;
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/devaddr ") {
                    // Адрес десктопа руками — по тем же двум причинам, что
                    // и `/addr` у контакта: mDNS в сети может не работать,
                    // а на loopback его чаще всего нет вовсе. Ключ здесь
                    // не `IK` человека, а публичная половина ключа
                    // сопряжения: именно от неё десктоп объявляется (§5.1).
                    let mut parts = rest.split_whitespace();
                    let key = parts.next().unwrap_or_default();
                    let addr = parts.next().unwrap_or_default();
                    match (
                        data_encoding::HEXLOWER.decode(key.as_bytes()),
                        addr.parse::<std::net::SocketAddr>(),
                    ) {
                        (Ok(raw), Ok(addr)) if raw.len() == 32 => {
                            let mut ik = [0u8; 32];
                            ik.copy_from_slice(&raw);
                            directory.note(ik, addr);
                            println!("< терминал {} по адресу {addr}", short(&ik));
                        }
                        _ => println!(
                            "< нужно: /devaddr <64 знака hex> <ip:порт> — строку печатает сам терминал"
                        ),
                    }
                    continue;
                }
                if let Some(label) = line.strip_prefix("/pair ") {
                    // Ссылка придёт событием `PairingReady` — и только им.
                    // Второго показа не будет: см. §13.4 и `on_pair_device`.
                    handle.send(Command::PairDevice { label: label.trim().to_owned() }).await.ok();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/unpair ") {
                    match data_encoding::HEXLOWER.decode(rest.trim().as_bytes()) {
                        Ok(raw) if raw.len() == 16 => {
                            let mut device_id = [0u8; 16];
                            device_id.copy_from_slice(&raw);
                            handle.send(Command::RevokePairing { device_id }).await.ok();
                        }
                        // Печатается полностью в `/devices` — короткой формы
                        // из журнала событий здесь не хватит.
                        _ => println!("< нужен полный id устройства в hex (32 знака) — /devices"),
                    }
                    continue;
                }
                if line == "/share" {
                    // Делимся с текущим собеседником **своей** карточкой:
                    // на стенде третьего обычно нет, а проверить путь этого
                    // достаточно — своя карточка идёт тем же кадром, что чужая.
                    if peer.is_none() {
                        peer = sole_contact(&handle).await;
                    }
                    let Some(ik) = peer else {
                        println!("< некому: сперва /add <карточка>");
                        continue;
                    };
                    let chat = Engine::<MemoryStore>::chat_id_for(&ik);
                    handle.send(Command::ShareContact { chat, peer_ik: own_ik }).await.ok();
                    println!("< своя карточка ушла в чат");
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/take ") {
                    // Добавить присланную карточку по идентификатору сообщения.
                    // Контакт появится **непроверенным** — иначе и быть
                    // не может: доверие не транзитивно (§4.2).
                    match data_encoding::HEXLOWER.decode(rest.trim().as_bytes()) {
                        Ok(raw) if raw.len() == 16 => {
                            let mut msg_id = [0u8; 16];
                            msg_id.copy_from_slice(&raw);
                            handle.send(Command::AddSharedContact { msg_id }).await.ok();
                            println!("< если карточка была — контакт добавлен непроверенным");
                        }
                        _ => println!("< нужен полный msg_id в hex (32 знака)"),
                    }
                    continue;
                }
                if line == "/react" || line.starts_with("/react ") {
                    // Реагируем на **последнее** сообщение чата, а не на
                    // названный идентификатор: набирать тридцать два знака
                    // hex ради смайлика человек не станет, а проверяется
                    // здесь дорога до второго экрана, а не разбор строки.
                    // Без аргумента — снятие: пустая строка и есть «снято»
                    // (`ratatosk_proto::reaction`).
                    let emoji = line.strip_prefix("/react ").unwrap_or("").trim().to_owned();
                    if peer.is_none() {
                        peer = sole_contact(&handle).await;
                    }
                    let Some(ik) = peer else {
                        println!("< некому: сперва /add <карточка>");
                        continue;
                    };
                    let chat = Engine::<MemoryStore>::chat_id_for(&ik);
                    match handle.messages(chat, 1).await.and_then(|found| found.into_iter().next()) {
                        Some(view) => {
                            let msg_id = view.message.msg_id;
                            handle.send(Command::SetReaction { chat, msg_id, emoji }).await.ok();
                            println!("< реакция на {}", short(&msg_id));
                        }
                        None => println!("< в чате пока нечего отмечать"),
                    }
                    continue;
                }
                if let Some(query) = line.strip_prefix("/find ") {
                    // Ищутся целые слова: в индексе лежат их хэши на ключе
                    // базы, а не сам текст. Проверяется здесь же — «прив»
                    // обязано не находить «привет».
                    match handle.search(None, query.trim().to_owned(), 20).await {
                        Some(found) if found.is_empty() => println!("< ничего не нашлось"),
                        Some(found) => {
                            for view in found {
                                println!(
                                    "< {}: {}",
                                    short(&view.message.msg_id),
                                    String::from_utf8_lossy(&view.message.body)
                                );
                            }
                        }
                        None => return,
                    }
                    continue;
                }
                if line == "/sweep" {
                    // Байты вложений лежат рядом с базой, а не в ней, и
                    // разойтись они способны. Проверяется руками так: принять
                    // файл, удалить контакт с историей, позвать `/sweep` —
                    // до правки он находил гигабайты, теперь обязан находить
                    // ноль.
                    match handle.sweep_orphan_files().await {
                        Some(swept) => println!(
                            "< убрано: вложений {}, обрывков {}, освободилось {} байт",
                            swept.files, swept.chunks, swept.bytes
                        ),
                        None => return,
                    }
                    continue;
                }
                if line == "/card" {
                    // Карточка спрашивается у ядра, а не берётся из снимка,
                    // сделанного при старте. Снимок был правдой ровно до
                    // первого `/onion`: после него в карточке адрес и версия
                    // на единицу больше, а на экране — прежняя строка. Именно
                    // это и приводило к тому, что вторая машина заводила
                    // контакт без onion-адреса.
                    print_card(&handle).await;
                    continue;
                }
                if line == "/onion" {
                    // Объявление адресов (§4.3) руками — тем же путём, каким
                    // его зовёт драйвер, когда сервис опубликован.
                    //
                    // Объявляется **то, что уже в карточке**, а посчитанный
                    // адрес идёт только если карточка пуста. Иначе эта команда
                    // затирала бы работающий адрес, который назвал сервис,
                    // посчитанным — а они, как выяснилось на стенде, совпадают
                    // не всегда.
                    //
                    // Почта здесь **не называется**, и раньше называлась —
                    // пустой строкой. Это и был баг со стенда: `/onion`
                    // бережно сохранял onion и молча стирал почтовый адрес.
                    // Там, где почта единственный транспорт, после этого
                    // до узла нельзя было достучаться вовсе — и следующее
                    // обновление карточки до собеседника уже не доезжало.
                    let current =
                        handle.own_card().await.map(|c| c.onion).unwrap_or_default();
                    let announce =
                        if current.is_empty() { onion_address.clone() } else { current };
                    handle
                        .send(Command::AnnounceAddresses {
                            onion: Some(announce.clone()),
                            chatmail: None,
                        })
                        .await
                        .ok();
                    println!("< адрес объявлен контактам: {announce}");
                    // Карточка изменилась — значит всё, что было напечатано
                    // раньше, устарело. Печатаем новую сразу: иначе человек
                    // скопирует прежнюю строку, и адреса в ней не окажется.
                    print_card(&handle).await;
                    continue;
                }
                if let Some(word) = line.strip_prefix("/tor ") {
                    // Переключатель, а не «остановить процесс»: ядро запомнит
                    // выбор и сообщит транспорту, а тот решит, что с собой
                    // делать. §5.4 перестаёт выбирать onion сразу — до того,
                    // как arti успеет что-либо предпринять.
                    let enabled = match word.trim() {
                        "on" | "вкл" => true,
                        "off" | "выкл" => false,
                        other => {
                            println!("< /tor on | /tor off (а не «{other}»)");
                            continue;
                        }
                    };
                    handle
                        .send(Command::SetTransportEnabled {
                            transport: ratatosk_proto::Transport::Onion,
                            enabled,
                        })
                        .await
                        .ok();
                    if enabled {
                        println!("< onion включён — §5.4 снова может его выбрать");
                        // Два разных «ничего не произошло», и различить их
                        // человек снаружи не может — значит, обязан сказать
                        // стенд.
                        if TOR_BUILT_IN {
                            // Ядро молчит на повтор того же выбора
                            // (`on_set_transport_enabled`), и это правильно:
                            // клиент выставляет все переключатели при старте.
                            // Но человеку, который ждёт строк подъёма, надо
                            // знать, что их не будет и почему.
                            println!("  если строк подъёма нет — Tor уже был включён");
                            println!("  и поднялся при старте; состояние покажет /tor");
                        } else {
                            println!("  НО этот стенд собран без arti: поднимать нечего.");
                            println!("  выбор записан в базу и подействует после сборки");
                            println!("  с --features tor");
                        }
                    } else {
                        println!("< onion выключен — §5.4 его больше не выбирает");
                        println!("  выбор запомнен и переживёт перезапуск");
                    }
                    continue;
                }
                if line == "/tor" {
                    // Вопрос, на который иначе отвечать нечем: «сообщения
                    // не ходят — это Tor ещё не готов или уже сломан?»
                    // Порядок строк — порядок причин: сперва наш сервис,
                    // потом адрес собеседника, потом сеть.
                    if !TOR_BUILT_IN {
                        // Первой строкой, до всего остального: пока это
                        // не сказано, любой разбор идёт не туда.
                        println!("< tor: этот стенд собран БЕЗ arti (--features tor)");
                        println!("  ключ и адрес ниже считаются и хранятся, но сервиса нет");
                    }
                    match &tor {
                        Some(note) => println!("< tor: {note}"),
                        None if TOR_BUILT_IN => {
                            println!("< tor: новостей не было — транспорт не поднимался");
                        }
                        None => {}
                    }
                    // Два адреса, а не один, и это не многословие. Первый
                    // посчитан из нашего ключа, второй — тот, что уехал
                    // контактам. Разошлись — arti обслуживает не наш ключ,
                    // и это объясняет тишину целиком.
                    println!("< посчитан из ключа : {onion_address}");
                    let in_card = handle.own_card().await.map(|c| c.onion).unwrap_or_default();
                    if in_card.is_empty() {
                        println!("  в карточке        : пусто — сервис ещё не назвал адрес");
                    } else if in_card == onion_address {
                        println!("  в карточке        : тот же — так и должно быть");
                    } else {
                        println!("  в карточке        : {in_card}");
                        println!("  ЭТО РАСХОЖДЕНИЕ: arti взял не наш ключ (см. строку «встало»)");
                    }
                    // Главный вопрос при «Tor запущен, а не идёт»: считает ли
                    // ядро ступень работающей. Включённая и работающая —
                    // разные вещи, и §5.4 выбирает только вторую.
                    if let Some(status) = handle.transports().await {
                        let onion = ratatosk_proto::Transport::Onion;
                        println!(
                            "  ступень onion: включена={}  работает={}",
                            yes(status.enabled.contains(onion)),
                            yes(status.ready.contains(onion))
                        );
                    }
                    println!("  адрес собеседника и видимость — /who");
                    println!("  свой адрес объявляется командой /onion; контактам,");
                    println!("  добавленным позже, он доедет сам при первой связи (§4.3)");
                    continue;
                }
                if line == "/lan" {
                    // Пока LAN работает, до onion дело не доходит: §5.4 —
                    // лестница, и локальная сеть на ней первая. Поэтому
                    // проверить второй транспорт можно только выключив
                    // первый, и это же делает человек в UI.
                    lan_on = !lan_on;
                    handle
                        .send(Command::SetTransportEnabled {
                            transport: ratatosk_proto::Transport::Lan,
                            enabled: lan_on,
                        })
                        .await
                        .ok();
                    if lan_on {
                        println!("< локальная сеть включена — она снова первая ступень");
                    } else {
                        println!("< локальная сеть выключена — доставка пойдёт через onion");
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/mail") {
                    mail_command(&handle, rest.trim()).await;
                    continue;
                }
                if line == "/net" {
                    // То же, что клиент вызовет из ConnectivityManager.
                    // Руками — чтобы проверить переоткрытие, не переключая
                    // Wi-Fi на самом деле.
                    handle.send(Command::NetworkChanged).await.ok();
                    println!("< сеть объявлена сменившейся: адреса забыты, объявление заново");
                    continue;
                }
                // Одна команда вместо двух: `/add` и `/addr` отличались одной
                // буквой и одним необязательным словом, и перепутать их было
                // проще, чем не перепутать, — а расплатой был отказ base64
                // в середине строки.
                if let Some(rest) =
                    line.strip_prefix("/add ").or_else(|| line.strip_prefix("/addr "))
                {
                    match add_contact(&handle, &directory, rest).await {
                        Ok(ik) => peer = Some(ik),
                        Err(error) => println!("< не принято: {error}"),
                    }
                    continue;
                }

                // Собеседник мог не приходить командой `/add` вовсе: §8.2
                // везёт карточку в первом сообщении рукопожатия, и ядро знает
                // контакт раньше консоли. Спрашиваем ядро, а не полагаемся
                // на то, что пользователь что-то набрал.
                if peer.is_none() {
                    peer = sole_contact(&handle).await;
                }
                let Some(ik) = peer else {
                    println!("< писать некому: /add <карточка> [ip:порт]");
                    continue;
                };
                // `chat_id_for` не зависит от хранилища, но живёт в `impl<S>`;
                // подставляем любой конкретный тип.
                let chat = Engine::<MemoryStore>::chat_id_for(&ik);
                if handle.send(Command::SendText { chat, text: line }).await.is_err() {
                    return;
                }
            }
            event = events.next() => {
                let Some(event) = event else { return };
                report(&event);
                match &event {
                    // Контакт, приехавший рукопожатием: отвечать ему можно
                    // сразу, ничего не набирая.
                    Event::ContactAdded { peer_ik, .. } => {
                        if peer.is_none() {
                            peer = Some(*peer_ik);
                        }
                    }
                    // Событие несёт только идентификатор (§9.1): тело читается
                    // из хранилища. Так же это будет делать и UI — список чата
                    // всё равно приходится перечитывать.
                    Event::MessageReceived { chat, msg_id } => {
                        if let Some(messages) = handle.messages(*chat, 20).await {
                            if let Some(view) =
                                messages.iter().find(|v| &v.message.msg_id == msg_id)
                            {
                                match &view.shared_contact {
                                    // Отпечаток рядом обязателен: карточку
                                    // прислал человек, а не её владелец,
                                    // и проверить её можно только голосом
                                    // с самим владельцем (§4.2).
                                    Some(shared) => {
                                        println!("< прислана карточка: {}", shared.display_name);
                                        println!("    отпечаток: {}", shared.fingerprint);
                                        if shared.already_known {
                                            println!("    этот контакт уже есть — ничего не меняем");
                                        } else {
                                            println!(
                                                "    добавить непроверенным: /take {}",
                                                data_encoding::HEXLOWER.encode(msg_id)
                                            );
                                        }
                                    }
                                    None => {
                                        println!(
                                            "< {}",
                                            String::from_utf8_lossy(&view.message.body)
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Event::StatusChanged { .. }
                    | Event::MessagesDeleted { .. }
                    | Event::MessageEdited { .. }
                    | Event::ReactionChanged { .. }
                    | Event::ContactChanged { .. }
                    | Event::ContactRemoved { .. }
                    | Event::AvatarChanged { .. }
                    | Event::GroupMembershipChanged { .. }
                    | Event::FileProgress { .. }
                    | Event::FileGone { .. }
                    // Печатается в `report`, а здесь делать нечего: ход
                    // подъёма Tor ничего не меняет в состоянии стенда.
                    | Event::HonestNotice { .. }
                    | Event::CommandRefused { .. }
                    // Тоже печатается в `report`. Ящик хранит ядро, стенду
                    // помнить его незачем — он спросит, когда понадобится.
                    | Event::MailAccountReady { .. }
                    | Event::MailAccountFailed { .. }
                    | Event::MailLoginFailed { .. }
                    | Event::MailLimits { .. }
                    // Тоже в `report`. Список устройств стенд не ведёт:
                    // спросит `/devices`, когда понадобится.
                    | Event::PairingReady { .. }
                    | Event::PairingRevoked { .. }
                    | Event::DeviceLink { .. }
                    | Event::FileWaitsForChannel { .. } => {}
                    // Печатается в `report`, а здесь запоминается: `/tor`
                    // обязан отвечать и тогда, когда строка уехала вверх.
                    Event::TorStatus { note, blocked, .. } => {
                        tor = Some(match blocked {
                            Some(reason) => format!("{note} (встало: {reason})"),
                            None => note.clone(),
                        });
                    }
                }
            }
        }
    }
}

/// Единственный контакт ядра, если он единственный.
///
/// Стенд ведёт один разговор, поэтому выбирать не из чего — но и угадывать
/// при нескольких контактах он не должен.
async fn sole_contact(handle: &DriverHandle) -> Option<[u8; 32]> {
    let contacts = handle.contacts().await?;
    match contacts.as_slice() {
        [only] => Some(only.peer_ik),
        [] => None,
        many => {
            println!("< контактов {}: стенд ведёт один разговор, /who", many.len());
            None
        }
    }
}

/// Показывает контакты вместе с причиной, по которой §5.4 выберет транспорт
/// или не выберет никакого.
///
/// Это главная диагностика стенда. `Undeliverable` сам по себе не говорит
/// ничего: он значит «ни один транспорт не подошёл», а какой именно признак
/// не сложился — видно только здесь.
/// Сопряжённые десктопы (§13.4).
async fn show_devices(handle: &DriverHandle, directory: &LanDirectory) {
    let Some(devices) = handle.devices().await else {
        println!("< драйвер остановлен");
        return;
    };
    if devices.is_empty() {
        println!("< сопряжений нет: /pair <метка>");
        return;
    }
    for device in devices {
        // Идентификатор целиком: им отзывают сопряжение, и обрезанный
        // пришлось бы искать глазами по журналу.
        println!(
            "< {} «{}»: {}",
            data_encoding::HEXLOWER.encode(&device.device_id),
            device.label,
            if device.connected { "на связи" } else { "не подключён" }
        );
        // Главный вопрос при разборе «почему не подключается»: знает ли
        // телефон, куда звонить. Ответить на него больше нечем — соединения
        // односторонние, и без адреса ответ на рукопожатие уходит в никуда.
        match directory.get(&device.pairing_public) {
            Some(addr) => println!("    адрес: {addr}"),
            None => {
                println!("    адреса нет — ответить ему телефон не сможет");
                println!("    ждём маяка mDNS либо вписываем руками: /devaddr");
            }
        }
        if device.last_seen_ms == 0 {
            println!("    ни разу не подключался");
        } else if device.cache_expired {
            println!("    больше тридцати суток без связи — кэш на десктопе стёрт (§13.4)");
        }
    }
}

async fn show_contacts(handle: &DriverHandle, directory: &LanDirectory) {
    let Some(contacts) = handle.contacts().await else {
        println!("< драйвер остановлен");
        return;
    };
    if contacts.is_empty() {
        println!("< контактов нет: /add <карточка> [ip:порт]");
        return;
    }

    for contact in contacts {
        let mark = if contact.verified { "сверен" } else { "НЕ сверен (§4.2)" };
        println!("< {} {} — {mark}", short(&contact.peer_ik), contact.display_name);
        // Отпечаток — то, что сверяют голосом (§4.2). Без него отметка
        // «не сверен» остаётся упрёком без способа его снять.
        println!("    отпечаток: {}", contact.fingerprint);

        println!("    добавлен: {} мс, карточка версии {}", contact.added_ms, contact.card_version);
        if let Some(onion) = &contact.onion {
            println!("    onion-адрес: {onion}");
        }
        if let Some(chatmail) = &contact.chatmail {
            println!("    почта: {chatmail}");
        }

        let addr = directory
            .get(&contact.peer_ik)
            .map_or_else(|| "неизвестен".to_owned(), |addr| addr.to_string());
        // Три признака у каждой ступени, и все три печатаются: «включён»
        // чинится переключателем, «работает» — временем (bootstrap идёт
        // десятки секунд), «адрес» — обменом карточками. Слив их в одно
        // слово, стенд отвечал бы на вопрос «почему не идёт» одинаково
        // для трёх разных бед.
        //
        // Раскладку и вердикт считает **ядро** (`Reachability`). Раньше
        // здесь стояла своя копия цепочки условий из `Attempt::next` —
        // две копии одной лестницы, расходящиеся при первом же изменении
        // правил, причём молча: стенд говорит «пойдёт почтой», а уезжает
        // через onion.
        for rung in &contact.reachability.rungs {
            let name = match rung.transport {
                ratatosk_proto::Transport::Lan => "LAN  ",
                ratatosk_proto::Transport::Onion => "onion",
                ratatosk_proto::Transport::Mail => "почта",
            };
            let tail = if rung.transport == ratatosk_proto::Transport::Lan {
                format!("  адрес: {addr}")
            } else {
                String::new()
            };
            println!(
                "    {name}: включён={}  работает={}  адрес/виден={}{tail}",
                yes(rung.enabled),
                yes(rung.ready),
                yes(rung.addressable)
            );
        }

        match (contact.reachability.route(), contact.reachability.rising()) {
            (Some(via), _) => println!("    → §5.4: пойдёт {}", via_name(via)),
            (None, Some(via)) => println!(
                "    → §5.4: {} ещё поднимается — уйдёт, как только заработает",
                via_name(via)
            ),
            (None, None) => {
                println!("    → §5.4: отправлять некуда");
                println!("      проверьте /tor, /mail и адреса в карточке;");
                println!("      для LAN: /add <карточка> <ip:порт> — на обеих машинах");
            }
        }

        // Отброшенные кадры (§7.3). Ноль — обычное дело и не печатается:
        // строка «аномалий: 0» у каждого контакта прячет ту единственную,
        // где не ноль.
        let anomalies = contact.anomalies;
        if anomalies.total() > 0 {
            println!(
                "    отброшено кадров: {} (чужая сессия {}, тег {}, формат {}, повтор {})",
                anomalies.total(),
                anomalies.unknown_session,
                anomalies.bad_tag,
                anomalies.malformed,
                anomalies.handshake_replay
            );
        }
    }
}

/// Имя транспорта для строки человеку.
fn via_name(via: ratatosk_proto::Transport) -> &'static str {
    match via {
        ratatosk_proto::Transport::Lan => "по LAN",
        ratatosk_proto::Transport::Onion => "через onion",
        ratatosk_proto::Transport::Mail => "почтой",
    }
}

fn yes(value: bool) -> &'static str {
    if value {
        "да"
    } else {
        "нет"
    }
}

/// Печатает свою карточку такой, какая она сейчас (§4.1).
///
/// Печатается ссылка `ratatosk:v0:…`, а не голый base64: ровно её показывает
/// клиент и кладёт в QR, и стенд не должен приучать к другому виду. `/add`
/// принимает оба.
async fn print_card(handle: &DriverHandle) {
    let Some(card) = handle.own_card().await else { return };
    println!();
    println!("< своя карточка, версия {}:", card.version);
    println!();
    println!("/add {}", card.uri);
    println!();
    if card.onion.is_empty() {
        println!("  onion в карточке нет — сперва /onion, потом копировать");
    } else {
        println!("  onion: {}", card.onion);
    }
}

/// `/add <карточка> [ip:порт]`.
async fn add_contact(
    handle: &DriverHandle,
    directory: &LanDirectory,
    rest: &str,
) -> Result<[u8; 32], String> {
    let mut words = rest.split_whitespace();
    let encoded = words.next().ok_or("нужна карточка")?;
    let addr = match words.next() {
        Some(text) => Some(
            text.parse::<SocketAddr>()
                .map_err(|_| format!("адрес вида 192.168.1.5:9001, а не «{text}»"))?,
        ),
        None => None,
    };
    if let Some(extra) = words.next() {
        return Err(format!("лишнее в конце строки: «{extra}»"));
    }

    let bytes = decode_card(encoded)?;
    let ik = ContactCard::decode(&bytes).map_err(|e| format!("разбор карточки: {e}"))?.value().ik;

    // `met_in_person: false` — карточка пришла текстом, а не с личной встречи,
    // и §4.2 требует держать контакт непроверенным до сверки голосом.
    handle
        .send(Command::AddContact { card_bytes: bytes, met_in_person: false })
        .await
        .map_err(|_| "драйвер остановлен".to_owned())?;

    match addr {
        Some(addr) => {
            directory.note(ik, addr);
            println!("< контакт {} по адресу {addr}", short(&ik));
        }
        None => println!("< контакт {}, адрес ждём от mDNS", short(&ik)),
    }
    Ok(ik)
}

/// Разбирает карточку, объясняя отказ так, чтобы по сообщению было понятно,
/// что чинить.
///
/// «invalid symbol at 122» само по себе не говорит ничего: строка длинная,
/// считать в ней символы никто не станет. Поэтому показываются и сам символ,
/// и длина — из них сразу видно, прилип ли хвост, потерялся ли кусок при
/// копировании или строка переносом разорвана надвое.
fn decode_card(encoded: &str) -> Result<Vec<u8>, String> {
    // Перенос строки при копировании — самая частая порча длинной строки,
    // и она безобидна: пробелы в base64 не значат ничего.
    let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();

    // Ссылка `ratatosk:v0:…` (§4.1) принимается наравне с голым base64:
    // именно её показывает клиент и кладёт в QR, и требовать от человека
    // отличать одно представление от другого не за что. Внутри неё base32,
    // и отдельная ветка нужна ровно поэтому.
    if let Some(body) = cleaned.strip_prefix(ratatosk_codec::URI_PREFIX) {
        return BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).map_err(|error| {
            format!(
                "{error}: после «{}» идёт base32, и здесь его {} символов — \
                 похоже, ссылка скопирована не целиком",
                ratatosk_codec::URI_PREFIX,
                body.chars().count()
            )
        });
    }

    BASE64URL_NOPAD.decode(cleaned.as_bytes()).map_err(|error| {
        let at = error.position;
        let symbol = cleaned
            .chars()
            .nth(at)
            .map_or_else(|| "строка кончилась".to_owned(), |c| format!("«{c}»"));
        format!(
            "{error}: символ {at} из {} — {symbol}. Карточка вставляется одной строкой; \
             адрес, если он нужен, пишется после неё через пробел",
            cleaned.chars().count()
        )
    })
}

/// Почтовый ящик: показать, завести руками, завести по ссылке, убрать (§5.3).
///
/// Одна команда с подкомандами, а не пять команд: у почты одно состояние,
/// и разводить его по нескольким именам значит заставить человека помнить,
/// какое из них что меняет.
async fn mail_command(handle: &DriverHandle, rest: &str) {
    let (word, tail) = match rest.split_once(char::is_whitespace) {
        Some((word, tail)) => (word, tail.trim()),
        None => (rest, ""),
    };

    match word {
        // Показать. Пароль печатается: его мог выдать сервер, и человек
        // не видел его никогда — без показа он не войдёт в свою же почту
        // с другого устройства. Стенд не телефон, чужих глаз у консоли нет.
        "" => match handle.mail_account().await {
            Some(Some(account)) => {
                println!("< почта: {}", account.address);
                println!("  пароль    : {}", account.password.as_str());
                println!("  imap      : {}:{}", account.imap_host, account.imap_port);
                println!("  smtp      : {}:{}", account.smtp_host, account.smtp_port);
                println!("  через tor : {}", yes(account.via_tor));
                if let Some(status) = handle.transports().await {
                    let mail = ratatosk_proto::Transport::Mail;
                    println!(
                        "  ступень   : включена={}  работает={}",
                        yes(status.enabled.contains(mail)),
                        yes(status.ready.contains(mail))
                    );
                    // Причина — рядом с состоянием, а не только в журнале:
                    // «включена, ящик есть, а не работает» без объяснения —
                    // состояние, из которого человек не знает выхода (§14).
                    if let Some(reason) = status.mail_failure {
                        println!("  не вышло  : {reason}");
                    }
                    // Пределы сервера — здесь же и целиком. Ради них
                    // и заводился второй `EHLO`: «файлы почтой не идут»
                    // без числа неотличимо от десятка других бед.
                    let limits = status.mail_limits;
                    println!(
                        "  письмо    : {}",
                        limits
                            .letter_bytes
                            .map_or_else(|| "предел не назван".to_owned(), bytes_text)
                    );
                    match (limits.mailbox_used, limits.mailbox_limit) {
                        (Some(used), Some(limit)) => println!(
                            "  ящик      : {} из {} (свободно {})",
                            bytes_text(used),
                            bytes_text(limit),
                            limits.free_bytes().map_or_else(String::new, bytes_text)
                        ),
                        _ => println!("  ящик      : объём не назван (сервер без QUOTA)"),
                    }
                    println!(
                        "  файлы     : {}",
                        if !limits.carries_file_chunks() {
                            "не поедут — письмо с куском файла не влезает в предел"
                        } else if limits.crowded() {
                            "не принимаются — в ящике меньше места, чем нужно передаче"
                        } else {
                            "поедут"
                        }
                    );
                }
                println!("  «работает» = вошли на сервер: отправка SMTP, приём IMAP");
            }
            Some(None) => {
                println!("< ящика нет — почта не ступень §5.4");
                println!("  /mail set <адрес> <пароль>          — существующая почта");
                println!("  /mail new <https://.../new> [on|off] — новый ящик на сервере");
                println!("  последнее слово у /mail new — идти ли через Tor (по умолчанию on)");
                println!("  у заведённого ящика путь меняется командой /mail tor on|off");
            }
            None => println!("< ядро остановлено"),
        },
        "set" => {
            let Some((address, password)) = tail.split_once(char::is_whitespace) else {
                println!("< /mail set <адрес> <пароль>");
                return;
            };
            let account = MailAccount::from_address(address, password.trim());
            match handle.send(Command::SetMailAccount(Some(account))).await {
                Ok(()) => println!("< ящик записан; адрес уедет контактам обновлением (§4.3)"),
                Err(_) => println!("< ядро остановлено"),
            }
        }
        "new" => {
            // Путь называется здесь же, необязательным словом в конце.
            // Отдельной командой его не задать: `/mail tor` меняет
            // **заведённый** ящик, а до регистрации ящика ещё нет —
            // и человек, желающий регистрироваться напрямую, оказывался
            // в тупике. Найдено на стенде.
            let (url, via_tor) = match tail.rsplit_once(char::is_whitespace) {
                Some((url, word)) if onoff(word).is_some() => {
                    (url.trim(), onoff(word).unwrap_or(true))
                }
                _ => (tail, true),
            };
            if url.is_empty() {
                println!("< /mail new https://chatmail.example/new [on|off]");
                println!("  последнее слово — идти ли через Tor; по умолчанию on");
                return;
            }
            let command = Command::CreateMailAccount { url: url.to_owned(), via_tor };
            match handle.send(command).await {
                // Не «пошли за ящиком»: `send` только кладёт команду
                // в очередь. Ушла просьба, а не ящик; об исходе скажет
                // событие, и оно может оказаться отказом.
                Ok(()) => {
                    println!("< просьба ушла: {url} (через tor: {})", yes(via_tor));
                    println!("  ответ придёт отдельной строкой");
                }
                Err(_) => println!("< ядро остановлено"),
            }
        }
        "tor" => {
            let Some(via_tor) = onoff(tail) else {
                println!("< /mail tor on | /mail tor off");
                return;
            };
            let Some(Some(mut account)) = handle.mail_account().await else {
                // Переключать нечего, и завести пустой ящик ради галочки
                // нельзя: выбор относится к ящику, а не к транспорту вообще.
                println!("< ящика нет — сперва /mail set или /mail new");
                return;
            };
            account.via_tor = via_tor;
            match handle.send(Command::SetMailAccount(Some(account))).await {
                Ok(()) if via_tor => println!("< почта пойдёт через Tor"),
                Ok(()) => {
                    println!("< почта пойдёт напрямую");
                    println!("  сервер увидит ваш IP и свяжет его с адресом ящика (§14)");
                }
                Err(_) => println!("< ядро остановлено"),
            }
        }
        "off" => match handle.send(Command::SetMailAccount(None)).await {
            Ok(()) => {
                println!("< ящик убран");
                println!("  адрес снят с карточки: обещать путь, которого нет, нельзя");
            }
            Err(_) => println!("< ядро остановлено"),
        },
        other => println!("< /mail | set | new | tor | off (а не «{other}»)"),
    }
}

/// `on`/`off` по-русски и по-английски.
fn onoff(word: &str) -> Option<bool> {
    match word.trim() {
        "on" | "вкл" => Some(true),
        "off" | "выкл" => Some(false),
        _ => None,
    }
}

/// Варианты перечислены поимённо, без `_`: новое событие должно ронять сборку
/// стенда, а не молча проваливаться в общую ветку.
fn report(event: &Event) {
    match event {
        Event::MessageReceived { .. } => {}
        Event::StatusChanged { msg_id, status } => {
            println!("< {} → {status:?}", short(msg_id));
            match status {
                // §14: сообщение осталось в истории и не ушло. Пользователю
                // нужно не «статус», а что с этим делать.
                DeliveryStatus::Undeliverable => {
                    println!("    ни один транспорт не подошёл — посмотрите /who");
                }
                DeliveryStatus::Waiting => {
                    println!("    собеседника нет в сети; уйдёт само, когда появится");
                }
                _ => {}
            }
        }
        Event::TorStatus { note, blocked, .. } => {
            // Ради этой строки событие и заведено: молчащая консоль
            // не отличает «поднимается долго» от «не поднимется никогда».
            //
            // Доля не печатается: arti уже начинает свою строку с процентов,
            // и получалось «tor 0%: 0%: …». Клиенту доля нужна — ему рисовать
            // полосу, — а здесь есть готовый текст.
            println!("< tor: {note}");
            if let Some(reason) = blocked {
                println!("    встало: {reason}");
            }
        }
        Event::ContactAdded { fingerprint, verified, .. } => {
            let mark = if *verified { "сверен" } else { "НЕ сверен (§4.2)" };
            println!("< контакт добавлен, отпечаток {fingerprint}, {mark} — можно писать");
        }
        Event::MessagesDeleted { msg_ids, .. } => {
            println!("< удалено сообщений: {}", msg_ids.len());
        }
        Event::MessageEdited { msg_id, .. } => {
            // Прежнего текста нет ни у кого, поэтому сказать о правке стенд
            // обязан: молчаливая подмена слов — ровно то, что §14 запрещает.
            println!("< {} изменено — перечитайте чат", short(msg_id));
        }
        Event::ReactionChanged { msg_id, author_ik, .. } => {
            // Саму реакцию событие не несёт: она читается вместе с сообщением.
            println!("< реакция от {} на {}", short(author_ik), short(msg_id));
        }
        Event::ContactChanged { peer_ik } => {
            println!("< контакт {} изменился — посмотрите /who", short(peer_ik));
        }
        Event::ContactRemoved { peer_ik } => {
            println!("< контакт {} удалён", short(peer_ik));
        }
        Event::AvatarChanged { peer_ik } => {
            // Стенд картинок не рисует — но показать, что кадр дошёл, обязан:
            // иначе «аватарка не появилась» неотличимо от «не отправилась».
            println!("< у {} сменилась аватарка", short(peer_ik));
        }
        Event::GroupMembershipChanged { chat } => {
            println!("< состав группы {} изменился", short(chat));
        }
        Event::FileProgress { file_id, received, total } => {
            println!("< файл {}: {received}/{total}", short(file_id));
        }
        Event::FileGone { file_id } => {
            println!("< вложение {} убрано — от него отказались", short(file_id));
        }
        Event::HonestNotice { text } => println!("< {text}"),
        Event::CommandRefused { reason } => {
            // §14: человек что-то сделал и обязан узнать, почему не вышло.
            // Раньше это была строка в журнале, а на экране — тишина.
            println!("< отказано: {reason}");
        }
        Event::MailAccountReady { address } => {
            // Адрес человек больше нигде не увидит, а писать ему будут
            // именно туда. Пароль не печатается: он в событие и не едет.
            println!("< почта заведена: {address}");
            println!("    адрес уехал контактам обновлением карточки (§4.3)");
        }
        Event::MailAccountFailed { reason } => {
            // §14: человек попросил завести почту. Молчание он прочтёт
            // как поломку стенда, а не как отказ сервера.
            println!("< почту завести не вышло: {reason}");
            // А «транспорт недоступен» он прочтёт как отказ сервера, хотя
            // это отсутствие кода. Причина не в тексте отказа: раннер,
            // которого нет, не может сказать о себе ничего умнее. Сказать
            // обязан стенд — он один знает, чем собран.
            if !MAIL_BUILT_IN {
                println!("    этот стенд собран БЕЗ сокетов почты: --features mail");
            } else if !TOR_BUILT_IN {
                println!("    напомню: через Tor нужен и --features tor — общий");
                println!("    Tor-клиент держит onion-раннер, а без него его нет");
            }
        }
        Event::FileWaitsForChannel { file_id } => {
            // §10.3 задаёт этот текст, и он показывается дословно: «загрузка»
            // и «ошибка» здесь одинаково неправда.
            println!(
                "< файл {}: {}",
                short(file_id),
                ratatosk_proto::files::waiting_for_channel_text()
            );
            println!("    канала нет вовсе — либо остался почтовый, а файл для почты велик");
        }
        Event::MailLoginFailed { reason } => {
            // Ящик есть, а войти не вышло. Молча переставшая работать почта
            // выглядит поломкой приложения; сообщения при этом продолжают
            // ходить остальными ступенями §5.4, и паниковать тут не о чем.
            println!("< на почтовый сервер не пустили: {reason}");
            println!("    почта не ступень §5.4, пока вход не удастся;");
            println!("    настройки покажет /mail, повторить вход — /mail set");
        }
        Event::MailLimits { letter_bytes, mailbox_used, mailbox_limit, crowded, carries_files } => {
            // Числа печатаются целиком: стенд для того и нужен, чтобы
            // увидеть, что именно сказал сервер, а не наш вывод из этого.
            println!(
                "< пределы почты: письмо {}, ящик {}",
                letter_bytes.map_or_else(|| "не назван".to_owned(), bytes_text),
                match (mailbox_used, mailbox_limit) {
                    (Some(used), Some(limit)) =>
                        format!("{} из {}", bytes_text(*used), bytes_text(*limit)),
                    _ => "не назван".to_owned(),
                }
            );
            if !*carries_files {
                println!("    файлы почтой не поедут: письмо с куском файла не влезает");
                println!("    сообщения при этом ходят как ходили");
            }
            if *crowded {
                println!("    места меньше, чем нужно одной передаче, — файлы не принимаются");
            }
        }
        Event::PairingReady { device_id, uri } => {
            // Ссылка целиком и один раз. Второго события не будет: секрет
            // живёт только здесь, телефон его не хранит (§13.4).
            println!("< сопряжение {} заведено", short(device_id));
            println!("    {uri}");
            println!("    это единственный показ — на телефоне секрета не остаётся");
            println!("    терминал: cargo run -p ratatosk-lab -- --companion '<ссылка>' \\");
            println!(
                "                                           --peer 127.0.0.1:<порт этого узла>"
            );
        }
        Event::PairingRevoked { device_id } => {
            println!("< сопряжение {} отозвано, сессия разорвана", short(device_id));
        }
        Event::DeviceLink { device_id, connected } => {
            let state = if *connected { "на связи" } else { "отключился" };
            println!("< десктоп {}: {state}", short(device_id));
        }
    }
}

/// Байты человеку: мегабайты при трёх и более разрядах, иначе как есть.
fn bytes_text(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} МБ", bytes as f64 / 1_000_000.0)
    } else {
        format!("{bytes} Б")
    }
}

/// Делит строку на первое слово и остаток.
///
/// Остаток отдаётся **как есть**, без повторного разбиения: это текст
/// сообщения, и пробелы в нём принадлежат человеку.
fn split_first(rest: &str) -> (&str, &str) {
    match rest.trim_start().split_once(char::is_whitespace) {
        Some((first, tail)) => (first, tail.trim_start()),
        None => (rest.trim(), ""),
    }
}

fn short(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&bytes[..bytes.len().min(6)])
}

/// Строка сообщения так, как её видит человек за десктопом.
///
/// Одна функция на все три места, где сообщение печатается, — страница,
/// новость о приходе, новость о правке. Три похожих `println!` разошлись бы
/// на первой же новой отметке, и разошлись бы молча: заметить, что «изменено»
/// рисуется в истории и не рисуется у только что пришедшего, можно только
/// глазами и только случайно.
///
/// Отметки обязательны, а не украшательны. «Изменено» — потому что прежнего
/// текста не остаётся ни у кого, и без него подменённые слова выглядят
/// исходными (§14). «Переслано» — потому что это утверждение о происхождении
/// слов. Ответ печатается ссылкой: цитату рисуют из своей копии, а её
/// у терминала может и не быть — тогда честно виден голый идентификатор,
/// а не выдуманный текст.
fn line(message: &Message) -> String {
    let mut out = String::new();
    if let Some(reply_to) = message.reply_to {
        out.push_str(&format!("в ответ на {}: ", short(&reply_to)));
    }
    out.push_str(if message.mine { "-> " } else { "<- " });
    if message.forwarded {
        out.push_str("(переслано) ");
    }
    out.push_str(&message.text);
    if message.edited_ms.is_some() {
        out.push_str(" (изменено)");
    }
    out.push_str(&adorn(&message.reactions));
    for (n, file) in message.files.iter().enumerate() {
        // Пара чисел, а не проценты: доля — это представление, и считать её
        // должен показ, а не провод. Зато по «2/9» сразу видно и то, что
        // приём идёт, и то, что забирать пока нечего.
        out.push_str(&format!(
            "\n<     [файл {}] {} — {}, кусков {}/{}{}",
            n + 1,
            file.name,
            bytes_text(file.size_bytes),
            file.have_chunks,
            file.chunk_total,
            // Без этой пометки «телефон не принял» и «телефон качает» —
            // оба ноль из N, и человек не знает, ждать ему или решать.
            if file.accepted { "" } else { "  ← ждёт решения: /accept" }
        ));
        // Картинку консоль не нарисует, но сказать, что она есть, обязана:
        // иначе `/preview` выглядит командой, которая никогда не работает.
        if file.has_preview {
            out.push_str("  (превью: /preview)");
        }
    }
    out
}

/// Приписка с реакциями к строке сообщения.
///
/// Пусто, когда реакций нет: в разговоре их не бывает у подавляющего
/// большинства сообщений, и пустые скобки после каждой строки сделали бы
/// ленту нечитаемой. Своя помечается звёздочкой — консоль не умеет показать
/// это иначе, а отличать своё от чужого надо: нажать «поставить» второй раз
/// человек не должен.
fn adorn(reactions: &[Reaction]) -> String {
    if reactions.is_empty() {
        return String::new();
    }
    let list: Vec<String> = reactions
        .iter()
        .map(|r| if r.mine { format!("{}*", r.emoji) } else { r.emoji.clone() })
        .collect();
    format!("  [{}]", list.join(" "))
}
