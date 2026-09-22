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
//! Ключ `--tordir` даёт терминалу свой onion-сервис: с ним телефон дотянется
//! до него из другого города, без него — только по общей сети. Нужен
//! и признак сборки `tor`, и постоянный каталог: адрес постоянен (выводится
//! из секрета сопряжения), но состояние сети arti держит на диске, и
//! одноразовый каталог означал бы полный bootstrap на каждый запуск.
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
use ratatosk_codec::{ContactCard, YGG_KEY_LEN};
use ratatosk_core::driver::{Driver, DriverHandle, EventStream, FileView};
use ratatosk_core::{
    vault, Command, CompanionClient, CompanionCommand, CompanionDriver, CompanionEvent,
    CompanionHandle, Engine, Event, OsEntropy, SelfAddresses,
};
use ratatosk_crypto::{Identity, OnionKey};
use ratatosk_proto::companion::{ChatSummary, Message, PairingInvite, Reaction};
use ratatosk_proto::mail::MailAccount;
use ratatosk_proto::ygg;
use ratatosk_proto::DeliveryStatus;
use ratatosk_store::{FsBlobs, MemoryStore, Store};
#[cfg(feature = "tor")]
use ratatosk_transport::Switched;
// Условным этот импорт был, пока `Disabled` требовался только сборкам,
// где чего-то нет. Теперь он нужен **всегда**: у терминала почты нет
// и не будет ни при каких признаках — почтовый круг это часы (§5.3),
// а второй экран про «здесь и сейчас».
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

/// Есть ли в этом двоичном файле **свой узел** меша (0.2).
///
/// Та же история в третий раз, и цена у неё та же. Без `--features ygg-node`
/// раннер на `/ygg node` отвечает отказом, а отказ читается как «узел
/// не поднялся» — то есть как чужая неисправность вместо отсутствия кода.
/// Строка в шапке снимает этот вопрос до того, как он возникнет.
const YGG_NODE_BUILT_IN: bool = cfg!(feature = "ygg-node");

/// Есть ли в этом двоичном файле ступень поверх реле nostr (0.3).
///
/// **Заведена по следу.** Без признака слот ступени занимает `Disabled`,
/// а он принимает настройку **молча** — и правильно делает: несобранному
/// раннеру ключ и реле не нужны, а отказ выглядел бы в журнале поломкой,
/// которой не случилось.
///
/// Цена этой правильности — тишина, неотличимая от неработающей ступени:
/// на стенде было видно «ступень включена, реле названо, ещё не пробовали»
/// — и так навсегда. То же самое дерево уже писало про onion и почту
/// («стенд без транспорта выглядел точно так же, как стенд со сломанным»),
/// и повторять этот урок третий раз незачем.
const NOSTR_BUILT_IN: bool = cfg!(feature = "nostr");

/// Собран ли живой эфир Bluetooth (0.4).
///
/// Тот же урок, третий раз подряд: без раннера ступень включается,
/// настройка ложится на диск, и всё это выглядит как работающая ступень,
/// которая почему-то молчит. Разница здесь только в том, что настраивать
/// в эфире нечего — значит и сказать про несобранную ступень надо прямее.
const BT_BUILT_IN: bool = cfg!(feature = "bt");

/// Чем собран этот стенд — одной строкой в шапку.
///
/// Печатается всегда, а не только когда чего-то нет: строка «почта: нет»
/// полезна ровно тем, что её ищут глазами после первой же непонятной тишины.
fn build_line() -> String {
    let tor = if TOR_BUILT_IN { "onion (arti)" } else { "onion НЕТ (--features tor)" };
    let mail = if MAIL_BUILT_IN { "почта" } else { "почта НЕТ (--features mail)" };
    let node = if YGG_NODE_BUILT_IN {
        "меш: демон и свой узел"
    } else {
        "меш: только демон (свой узел — --features ygg-node)"
    };
    let nostr = if NOSTR_BUILT_IN { "nostr" } else { "nostr НЕТ (--features nostr)" };
    let bt = if BT_BUILT_IN { "bluetooth" } else { "bluetooth НЕТ (--features bt)" };
    format!("LAN, {bt}, {tor}, {mail}, {nostr}, {node}")
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
    /// Назвал ли человек сеть **явно** ключом командной строки.
    ///
    /// Отдельно от самого выбора, и разница стоила поломки: стенд слал
    /// «включить LAN» на каждом запуске, потому что умолчание у флага —
    /// «включена». Тем самым он затирал на диске выбор, сделанный в прошлый
    /// раз командой `/lan`, — то есть настройки локальной сети не переживали
    /// перезапуск, и виноват был не движок, а этот флаг.
    ///
    /// Теперь без ключа стенд не говорит про сеть ничего и берёт то,
    /// что подняло ядро.
    lan_named: bool,
    /// Открытый ключ нашего узла Yggdrasil, шестнадцатеричный (`--ygg`).
    ///
    /// Стенду он нужен раньше самого раннера: ключ едет в карточке (§4.1),
    /// и без него ступень §5.4 у собеседника неадресуема. Пока раннера нет,
    /// ключ проверяет ровно одно — что карточка с мешем кодируется,
    /// подписывается и доезжает до второго узла целой.
    ygg: Option<String>,
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
    /// Каталог состояния Tor для терминала (`--tordir`).
    ///
    /// Без него терминал остаётся при локальной сети: свой onion-сервис
    /// поднимать негде, а поднятый на одноразовом каталоге исчез бы вместе
    /// с процессом вместе с адресом, который телефон уже запомнил.
    tordir: Option<PathBuf>,
    /// Куда класть кэш терминала (§13.4). `None` — никуда.
    ///
    /// Это и есть та самая галочка «хранить кэш на диске»: по умолчанию
    /// её нет, и на диск не ложится ничего. В настоящем клиенте она стоит
    /// на экране сопряжения и переключается позже; здесь — ключ запуска
    /// и команда `/cache`.
    cache: Option<PathBuf>,
    /// Ввезти архив переписки (§12) и выйти: `--import <файл> --key <ключ>`.
    ///
    /// Отдельным запуском, а не командой в диалоге, и это не лень: ввоз
    /// происходит **до** того, как появляется аккаунт, — базы, в которую
    /// можно было бы дать команду, ещё нет.
    import: Option<PathBuf>,
    /// Ключ архива — та строка, что печаталась при `/export`.
    import_key: Option<String>,
    /// Фраза, которой заперт архив (`--phrase`).
    import_phrase: Option<String>,
    /// Адрес телефона, если mDNS не работает: `127.0.0.1:41234`.
    ///
    /// Для проверки двумя процессами на одной машине это основной путь:
    /// mDNS на loopback работает не везде, а два процесса на 127.0.0.1 —
    /// самый короткий способ увидеть режим целиком.
    peer: Option<String>,
}

/// Разбирает `--ygg <64 шестнадцатеричных знака>` в тридцать два байта.
///
/// Отказ **вслух и с продолжением**: стенд без меша работает, стенд
/// с молча выброшенным ключом — обманывает.
fn ygg_from_args(raw: Option<&str>) -> Vec<u8> {
    let Some(raw) = raw else { return Vec::new() };
    // Нарезка **по байтам**, а не срезами строки, и это не вкусовщина:
    // `&raw[i..i + 2]` на строке из многобайтных знаков попадает в середину
    // символа и роняет стенд паникой. Строка нужной длины из таких знаков
    // набирается легко — хватит одного, вставленного при копировании.
    // Поймано стендом на `rustc`, а не на устройстве.
    let raw = raw.trim().as_bytes();
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let bytes: Option<Vec<u8>> = (raw.len() == YGG_KEY_LEN * 2)
        .then(|| {
            raw.chunks_exact(2)
                .map(|pair| Some(digit(pair[0])? * 16 + digit(pair[1])?))
                .collect::<Option<Vec<u8>>>()
        })
        .flatten();
    match bytes {
        Some(bytes) => bytes,
        None => {
            eprintln!("--ygg: нужен ключ из 64 шестнадцатеричных знаков, меш выключен");
            Vec::new()
        }
    }
}

fn parse_args() -> Args {
    let mut args = Args {
        name: "узел".to_owned(),
        port: 0,
        discovery: true,
        lan: true,
        lan_named: false,
        ygg: None,
        trust_fs: false,
        data: None,
        pin: None,
        accounts: None,
        account: None,
        companion: None,
        tordir: None,
        import: None,
        import_key: None,
        import_phrase: None,
        peer: None,
        cache: None,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--name" => args.name = argv.next().unwrap_or_default(),
            "--port" => args.port = argv.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            "--no-mdns" => args.discovery = false,
            "--no-lan" => {
                args.lan = false;
                args.lan_named = true;
            }
            "--ygg" => args.ygg = argv.next(),
            "--trust-fs" => args.trust_fs = true,
            "--data" => args.data = argv.next().map(PathBuf::from),
            "--pin" => args.pin = argv.next(),
            "--accounts" => args.accounts = argv.next().map(PathBuf::from),
            "--account" => args.account = argv.next(),
            "--companion" => args.companion = argv.next(),
            "--tordir" => args.tordir = argv.next().map(PathBuf::from),
            "--import" => args.import = argv.next().map(PathBuf::from),
            "--key" => args.import_key = argv.next(),
            "--phrase" => args.import_phrase = argv.next(),
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

    // Ввоз — тоже отдельный режим, и он раньше всего: аккаунта, в который
    // можно было бы войти, ещё нет, а после ввоза он открывается **прежним**
    // PIN — соль уехала в архиве вместе с базой.
    if let Some(archive) = args.import.clone() {
        return run_import(&args, &archive);
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
    lan.execute(TransportCommand::WatchPeers(vec![phone_ik])).await?;
    // Порт снимается **до** сборки составного раннера: `lan` уезжает в него
    // целиком, а число нужно ещё дважды — в шапке и в подсказке `/devaddr`.
    let lan_port = lan.port();

    // **Меш у терминала — своей рукой, как и onion.** Ядра у него нет,
    // а `startup_effects` есть только у телефона: там ступень поднимает
    // ядро, здесь сказать некому.
    //
    // Без этих строк второй слот составного раннера оставался `Disabled`,
    // и лестница канала, дойдя до меша, упиралась в `Unavailable` на каждый
    // кадр — то есть до onion не добиралась никогда.
    //
    // Ключ тот же `--ygg`, что и у обычного запуска: он означает «у меня
    // уже есть свой демон, ходи через него». Без него терминал поднимает
    // **встроенный** узел — сам, из зерна сопряжения и пиров телефона
    // (`CompanionDriver::raise_own_node`). Узел ему нужен обязательно:
    // клиентского режима у ступени нет, адрес `200::/7` выводится
    // из собственного ключа.
    let ygg_key = ygg_from_args(args.ygg.as_deref());
    let ygg = ratatosk_transport::YggRunner::start(
        ratatosk_transport::YggConfig { enabled: false, port: ratatosk_transport::YGG_PORT },
        &ygg_key,
    )
    .await?;

    // Свой onion-сервис. Оба случая дают **один тип** — как и у узла выше:
    // без каталога подъём сразу объявляется неудавшимся, и составной раннер
    // остаётся тем же. Каталог обязателен потому, что адрес обязан пережить
    // перезапуск: телефон запомнил его с прошлого рукопожатия, а сервис
    // на одноразовом каталоге поднялся бы под другим.
    let tor_handle = ratatosk_transport::onion::TorHandle::default();

    // Раннер nostr заводится одинаково в обеих сборках стенда: Tor ему нужен
    // не всегда. До локального реле (`ws://127.0.0.1:8080`) он ходит напрямую
    // — цепочка встречи до петлевого адреса никуда не вела бы, — и ступень
    // проверяется на своём `nostr-rs-relay` без признака `tor` вовсе.
    #[cfg(feature = "nostr")]
    let nostr = ratatosk_transport::nostr::NostrRunner::new(tor_handle.clone());
    #[cfg(not(feature = "nostr"))]
    let nostr = Disabled;

    #[cfg(feature = "tor")]
    let mut runner = {
        let layout = args.tordir.clone().map(ratatosk_core::TorLayout::under);
        if let Some(layout) = layout.as_ref() {
            // Ключ раскладывается до подъёма и на каждый запуск: arti читает
            // его из каталога, а файл могли удалить или перенести каталог.
            ratatosk_core::write_onion_keystore(&layout.keys, &client.onion_key())?;
        }
        let setup = std::sync::Arc::new((layout, client.onion_key(), args.trust_fs));
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
        Transports::new(lan, Disabled, ygg, onion, nostr, Disabled)
    };
    #[cfg(not(feature = "tor"))]
    let mut runner = {
        let _ = &tor_handle;
        Transports::new(lan, Disabled, ygg, Disabled, nostr, Disabled)
    };

    // **Включать приходится своей рукой.** У терминала нет ядра, а
    // `Switched` поднимается только по `SetEnabled` — у телефона это говорит
    // `Engine::startup_effects`, здесь сказать некому. Без этой строки
    // сервис остался бы выключенным навсегда, и адрес в рукопожатии
    // приезжал бы пустым при поднятом Tor.
    if args.tordir.is_some() {
        runner
            .execute(TransportCommand::SetEnabled {
                transport: ratatosk_proto::Transport::Onion,
                enabled: true,
            })
            .await?;
    }

    // То же и мешу: настройка, потом выключатель. Порядок тот, что у ядра
    // (`startup_effects`), и не случайный — раннер без настройки поднимать
    // нечего, а поднятый без неё честно отказывает.
    //
    // Без ключа ступень остаётся выключенной **здесь**, и это не полумера:
    // её поднимет драйвер встроенным узлом, когда узнает пиров.
    //
    // Отказ не роняет терминал, и это исправление настоящей поломки:
    // `?` здесь означал, что человек, у которого не запущен демон меша,
    // получал вместо окна сообщение об ошибке — при том, что локальная
    // сеть и onion у него работают. Ступень, которая не поднялась, —
    // это на одну ступень меньше, а не конец работы.
    if !ygg_key.is_empty() {
        let setup = TransportCommand::SetYgg(ygg::YggSetup::External { key: ygg_key.clone() });
        let mut outcome = runner.execute(setup).await;
        // Включатель — только по удавшейся настройке: поднимать ступень,
        // которой нечем ехать, значит завести `Unavailable` на каждый кадр.
        if outcome.is_ok() {
            let enable = TransportCommand::SetEnabled {
                transport: ratatosk_proto::Transport::Ygg,
                enabled: true,
            };
            outcome = runner.execute(enable).await;
        }
        if let Err(err) = outcome {
            eprintln!("меш не поднялся ({err}) — работаем без него");
        }
    }

    println!("терминал : к «{}»", client.phone_name());
    println!("id       : {}", data_encoding::HEXLOWER.encode(&client.device_id()));
    println!("порт     : {lan_port}");
    if invite.onion.is_empty() {
        println!("телефон  : onion в приглашении пуст — звонить только локальной сетью");
    } else {
        println!("телефон  : {}", invite.onion);
    }
    match (invite.ygg.is_empty(), ygg_key.is_empty(), YGG_NODE_BUILT_IN) {
        (true, true, _) => println!("меш      : ни у телефона, ни у нас — ступень не нужна"),
        (_, false, _) => println!("меш      : свой демон по --ygg, поднимаем сразу"),
        (_, true, true) if !invite.ygg_peers.is_empty() => {
            println!("меш      : свой узел, пиров в приглашении — {}", invite.ygg_peers.len());
        }
        (_, true, true) => {
            // Пиров в приглашении нет — телефон их не настроил или ссылка
            // из сборки, которая их ещё не возила. Узел встанет позже,
            // объявлением по живому каналу; сказать об этом надо вслух,
            // иначе «меш не работает» человек будет чинить наугад.
            println!("меш      : свой узел — пиров в приглашении нет, ждём объявления");
            println!("           (первое подключение идёт локальной сетью или onion)");
        }
        (_, true, false) => {
            println!("меш      : собрано без --features ygg-node — только демон по --ygg");
        }
    }
    match (&args.tordir, cfg!(feature = "tor")) {
        (Some(dir), true) => {
            // Адрес печатается сразу: он выведен из зерна сопряжения и
            // известен до всякого подъёма. Сам сервис поднимается десятки
            // секунд, и до `TorReady` телефону он не объявляется.
            println!("свой     : {}", client.onion_key().address());
            println!("           каталог {} — поднимаем в фоне", dir.display());
        }
        (Some(_), false) => {
            println!("свой     : собрано без --features tor — сервис не поднимется");
        }
        (None, _) => {
            println!("свой     : --tordir не задан — только локальная сеть");
        }
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
    println!("/devaddr {} 127.0.0.1:{lan_port}", data_encoding::HEXLOWER.encode(&client.ik()));
    println!();
    println!("команды: /chats   /open <номер>   /more   /read   /cache [on <путь>|off]   /quit");
    println!("         /react <n> [эмодзи]   /reply <n> <текст>   /edit <n> <текст>");
    println!("         /del <n…>   /retract <n…>   /fwd <n…> <номер чата>   /clear");
    println!("         /share [номер чата] — поделиться карточкой; без номера — своей");
    println!("         /add <n>          — добавить того, чья карточка в строке n");
    println!("         /accept <n> [k]   — качать вложение;  /pause — передумать");
    println!("         /decline <n> [k]  — отказаться совсем: приехавшее стирается");
    println!("         /preview <n> [k]  — превью вложения, если оно есть");
    println!("         /avatar [номер чата] — лицо контакта; без номера — своё");
    println!("         /members <номер чата> — состав группы");
    println!("         /newgroup <название>   /invite <группа> <контакт>");
    println!("         /evict <группа> <контакт>   /rename <группа> <название>");
    println!("         /gavatar <группа> [путь]   /leave <группа>");
    println!("         /setavatar [путь]    — поставить своё лицо; без пути — снять");
    println!("         /save <n> [k] <путь>   — забрать сюда;  /stop — прекратить");
    println!("         /send <путь…> [-- подпись] — отправить файлы одним сообщением");
    println!("         /sendpic <файл-превью> <путь> [подпись] — то же с превью");
    println!("         номер n — из строк, показанных /open и /more");
    println!("всё остальное уходит текстом в открытый чат");
    println!();

    // Среда — у драйвера, консоль — здесь. До этой поставки они были одним
    // куском, и переехали ради того, что этим же куском будет пользоваться
    // Kotlin: через UniFFI sans-io не пролезает (§13.3).
    let (mut driver, handle, events) = CompanionDriver::new(client, runner);
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
    /// Как назвать того, чьё это лицо, — для строки в консоли.
    ///
    /// По списку чатов, а не по идентификатору: шестнадцать байт человеку
    /// ничего не говорят, а имя чат везёт с собой. Чат, которого в списке
    /// уже нет, называется отпечатком — это честнее, чем «неизвестно».
    fn whose_face(chats: &[ChatSummary], chat: Option<[u8; 16]>) -> String {
        let Some(chat) = chat else { return "своё".to_owned() };
        chats
            .iter()
            .find(|known| known.chat == chat)
            .map_or_else(|| short(&chat), |known| format!("«{}»", known.title))
    }

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
                    // У группы сверки нет и быть не может: сверяют людей,
                    // а не круги знакомых. Показать ей пустое место рядом
                    // с несверенными контактами значило бы сказать «не
                    // сверена» — то, чего §4.2 про группу не говорит.
                    // Вышедшая группа помечается отдельно от обычной:
                    // писать в неё нельзя, и метка обязана это сказать
                    // раньше, чем человек наберёт строку и получит отказ.
                    let mark = if chat.is_group && !chat.joined {
                        "x"
                    } else if chat.is_group {
                        "*"
                    } else if chat.verified {
                        "+"
                    } else {
                        " "
                    };
                    // Лицо консоль не нарисует, но сказать о нём обязана:
                    // иначе `/avatar` выглядит командой, которая никогда
                    // не работает.
                    let face = if chat.avatar_ms == 0 { "" } else { "  (лицо: /avatar)" };
                    println!("< {:>2}. {mark} {}: {}{face}", n + 1, chat.title, chat.last_text);
                }
            }
            CompanionEvent::GroupCreated { chat } => {
                // Идентификатор пришёл ответом: искать новую группу
                // в перечитанном списке нечем — названия повторяются.
                println!("< группа заведена: {}", short(&chat));
                println!("    /chats покажет её строкой, /open по номеру — откроет");
            }
            CompanionEvent::Members { chat, members } => {
                // Ключа у участника нет (§13.4) — печатается идентификатор
                // его личного чата: им же ему и пишут. Пометка «вы» рядом
                // со своим: без неё хозяин телефона выглядел бы одним
                // из чужих, как это уже случилось у клиента телефона.
                if members.is_empty() {
                    println!("< участников нет: это личный чат, а не группа");
                } else {
                    println!("< участников {}:", members.len());
                    for member in &members {
                        // Признак создателя печатается отдельно от «вы»:
                        // это два разных факта, и у создателя, читающего
                        // свой состав, верны оба сразу.
                        println!(
                            "    {} {}{}{}",
                            data_encoding::HEXLOWER.encode(&member.chat),
                            member.name,
                            if member.mine { "  (вы)" } else { "" },
                            if member.owner { "  (создатель)" } else { "" }
                        );
                    }
                }
                let _ = chat;
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
            CompanionEvent::Revoked => {
                println!("< сопряжение отозвано с телефона: этот компьютер больше не второй");
                println!("<   экран. Кэш стёрт — и в памяти, и на диске. Чтобы связать заново,");
                println!("<   нужен новый QR: /pair на телефоне.");
            }
            CompanionEvent::Avatar { chat, bytes, fresh } => {
                let whose = Self::whose_face(&self.chats, chat);
                let from_cache = if fresh { "" } else { " (из памяти)" };
                match bytes {
                    // Как и с превью: консоль картинку не нарисует,
                    // и притворяться незачем.
                    Some(bytes) => println!(
                        "< лицо {whose}: {}{from_cache} — консоль его не покажет, окно покажет",
                        bytes_text(bytes.len() as u64)
                    ),
                    // Двух причин здесь намеренно не различить: аватарки нет
                    // и контакт не сверен (§4.2) выглядят одинаково.
                    None => println!("< лицо {whose}: показывать нечего{from_cache}"),
                }
            }
            CompanionEvent::AvatarChanged { chat, avatar_ms } => {
                let whose = Self::whose_face(&self.chats, chat);
                if avatar_ms == 0 {
                    println!("< лицо {whose} снято");
                } else {
                    println!("< лицо {whose} сменилось — /avatar покажет размер нового");
                }
            }
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

    /// Номер строки `/chats` — в идентификатор чата.
    ///
    /// Стенд адресует чаты номерами по той же причине, по какой действует
    /// на последнее сообщение: набирать тридцать два знака hex человек
    /// не станет, а проверяется здесь дорога до телефона, а не разбор
    /// строки. Настоящее окно берёт идентификаторы из списка.
    fn chat_by_number(&self, rest: &str, usage: &str) -> Option<[u8; 16]> {
        let n = rest.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
        match n {
            Some(n) => Some(self.chats[n - 1].chat),
            None => {
                println!("< нужно: {usage} — номера печатает /chats");
                None
            }
        }
    }

    /// «<номер группы> <номер контакта>» — в пару идентификаторов чатов.
    ///
    /// Участник и на этом проводе назван идентификатором своего личного
    /// чата (§13.4), поэтому оба номера берутся из одного списка.
    fn two_chats(&self, rest: &str, usage: &str) -> Option<([u8; 16], [u8; 16])> {
        let (first, second) = rest.split_once(' ')?;
        let chat = self.chat_by_number(first, usage)?;
        let member = self.chat_by_number(second, usage)?;
        Some((chat, member))
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
        if let Some(rest) = line.strip_prefix("/share") {
            let Some(chat) = self.current else {
                println!("< сперва /open <номер>");
                return None;
            };
            let rest = rest.trim();
            // Без довода — своя карточка: личного чата с самим собой нет,
            // а поделиться собой хотят чаще всего.
            let who = if rest.is_empty() {
                println!("< делимся своей карточкой");
                None
            } else {
                let picked =
                    rest.parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
                let Some(n) = picked else {
                    println!("< кем делиться: /share <номер чата из /chats>, без номера — собой");
                    return None;
                };
                Some(self.chats[n - 1].chat)
            };
            return Some(CompanionCommand::ShareContact { chat, who });
        }
        if let Some(rest) = line.strip_prefix("/add ") {
            let msg_id = self.pick(rest)?;
            println!("< сверки это не даёт: §4.2 — встреча голосом, а не нажатие");
            return Some(CompanionCommand::AddSharedContact { msg_id });
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
        if line.trim() == "/setavatar" {
            // Без пути — снять. Пустые байты здесь законное значение,
            // а не пустая команда.
            println!("< аватарка снимается — сверенные контакты узнают об этом");
            return Some(CompanionCommand::SetAvatar { bytes: Vec::new() });
        }
        if let Some(rest) = line.strip_prefix("/setavatar ") {
            let path = rest.trim();
            let bytes = match std::fs::read(path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    println!("< {path} не прочитать: {error}");
                    return None;
                }
            };
            // Предел проверит провод, а формат — телефон, и отказ приедет
            // словами. Размер печатается здесь, чтобы «не влезло» было видно
            // до того, как оно не влезет.
            println!("< отправляю своё лицо: {}", bytes_text(bytes.len() as u64));
            return Some(CompanionCommand::SetAvatar { bytes });
        }
        if let Some(rest) = line.strip_prefix("/newgroup ") {
            let title = rest.trim();
            if title.is_empty() {
                println!("< нужно: /newgroup <название>");
                return None;
            }
            // §11.5 требует сказать это **до** заведения. Текст берётся
            // той же функцией, что и на телефоне: проводом он не едет,
            // потому что это константа, а не сведение о телефоне.
            println!("< {}", ratatosk_proto::group::JOIN_DISCLOSURE);
            return Some(CompanionCommand::CreateGroup { title: title.to_owned() });
        }
        if let Some(rest) = line.strip_prefix("/invite ") {
            let (chat, member) = self.two_chats(rest, "/invite <номер группы> <номер контакта>")?;
            return Some(CompanionCommand::InviteToGroup { chat, member });
        }
        if let Some(rest) = line.strip_prefix("/evict ") {
            let (chat, member) = self.two_chats(rest, "/evict <номер группы> <номер контакта>")?;
            // §11.4 дословно, и тоже до действия: исключённый сохранит
            // доступ к прошлой переписке, и отменить это нельзя.
            println!("< {}", ratatosk_proto::group::EvictionConsequences::ui_text());
            return Some(CompanionCommand::EvictFromGroup { chat, member });
        }
        if let Some(rest) = line.strip_prefix("/rename ") {
            let (n, title) = rest.split_once(' ').unwrap_or((rest.trim(), ""));
            let chat = self.chat_by_number(n, "/rename <номер группы> <название>")?;
            if title.trim().is_empty() {
                println!("< без названия: /rename <номер группы> <новое название>");
                return None;
            }
            return Some(CompanionCommand::RenameGroup { chat, title: title.trim().to_owned() });
        }
        if let Some(rest) = line.strip_prefix("/gavatar ") {
            let (n, path) = rest.split_once(' ').unwrap_or((rest.trim(), ""));
            let chat = self.chat_by_number(n, "/gavatar <номер группы> [путь]")?;
            let path = path.trim();
            let bytes = if path.is_empty() {
                Vec::new()
            } else {
                match std::fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        println!("< не прочитать {path}: {error}");
                        return None;
                    }
                }
            };
            return Some(CompanionCommand::SetGroupAvatar { chat, bytes });
        }
        if let Some(rest) = line.strip_prefix("/leave ") {
            let chat = self.chat_by_number(rest, "/leave <номер группы>")?;
            // Оба текста §14: второй — только создателю, но окно стенда
            // не знает состава, пока его не спросили. Печатаются оба,
            // и это честнее умолчания: цена ухода создателя обязана быть
            // названа до, а не после.
            println!("< {}", ratatosk_proto::group::LeaveConsequences::ui_text());
            println!(
                "< если вы создатель: {}",
                ratatosk_proto::group::LeaveConsequences::owner_text()
            );
            return Some(CompanionCommand::LeaveGroup { chat });
        }
        if let Some(rest) = line.strip_prefix("/members ") {
            let n = rest.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
            let Some(n) = n else {
                println!("< нужен номер из /chats, от 1 до {}", self.chats.len());
                return None;
            };
            return Some(CompanionCommand::Members { chat: self.chats[n - 1].chat });
        }
        if line.trim() == "/avatar" {
            // Без номера — своё: себя в списке чатов нет, и спрашивается
            // оно без метки для сравнения.
            return Some(CompanionCommand::Avatar { chat: None });
        }
        if let Some(rest) = line.strip_prefix("/avatar ") {
            let n = rest.trim().parse::<usize>().ok().filter(|n| *n >= 1 && *n <= self.chats.len());
            let Some(n) = n else {
                println!("< нужен номер из /chats, от 1 до {}", self.chats.len());
                return None;
            };
            return Some(CompanionCommand::Avatar { chat: Some(self.chats[n - 1].chat) });
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
                // Нарезка — из той же записи: у каждого файла она своя.
                chunk_bytes: file.chunk_bytes,
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
            println!("<   /share [номер чата]   /add <n> — карточка человека (§4.1)");
            println!("<   /accept <n> [k]   /pause <n> [k]   /decline <n> [k]");
            println!("<   /preview <n> [k]   /avatar [номер чата]   /setavatar [путь]");
            println!("<   /members <номер чата> — состав группы");
            println!(
                "<   /newgroup <название>   /invite <группа> <контакт>   /evict <группа> <контакт>"
            );
            println!(
                "<   /rename <группа> <название>   /gavatar <группа> [путь]   /leave <группа>"
            );
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

/// Ввозит архив и выходит (§12).
///
/// Печатает, **что именно** приехало: сто контактов и ноль сообщений — это
/// граф, и человек, ждавший переписку, обязан увидеть это сразу, а не через
/// неделю.
fn run_import(args: &Args, archive: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = args.data.clone() else {
        eprintln!("ввозить некуда: укажите --data <файл базы>");
        return Ok(());
    };
    // Что спрашивать, говорит сам архив: экран, требующий фразу от архива,
    // в котором её нет, — тупик.
    let peek = ratatosk_store::peek_archive(archive)?;
    let key = match args.import_key.clone() {
        Some(text) => Some(
            ratatosk_crypto::storage_key::key_from_text(&text)
                .map_err(|_| "ключ не разобрался: перепишите его целиком")?,
        ),
        None => None,
    };
    let unlock = match (&args.import_phrase, &key) {
        (Some(phrase), _) => ratatosk_store::ArchiveUnlock::Passphrase(phrase),
        (None, Some(key)) => ratatosk_store::ArchiveUnlock::Key(key),
        (None, None) => {
            if peek.takes_passphrase {
                eprintln!("этот архив заперт фразой: --phrase <фраза>");
                eprintln!("(или сырым ключом, если вы его сохранили: --key <строка>)");
            } else {
                eprintln!("нужен ключ архива: --key <строка с экрана>");
            }
            return Ok(());
        }
    };

    // Вложения — туда же, куда их кладёт обычный запуск с `--data`.
    let mut blobs = FsBlobs::new(path.with_extension("files"));
    let done = ratatosk_store::import_archive(archive, unlock, &path, &mut blobs)?;

    println!("ввезено: {}", done.scope.title());
    println!("контактов: {}", done.contacts);
    println!("сообщений: {}", done.messages);
    println!("вложений : {} (целиком доехало {})", done.files, done.whole_files);
    println!("байт     : {}", done.bytes);
    println!("база     : {}", path.display());
    println!();
    println!("Открывать её надо **прежним** PIN: соль уехала вместе с базой.");
    println!("И прежним устройством пользоваться больше нельзя — личность одна");
    println!("на двоих не делится (§13.4: для второго экрана есть компаньон).");
    Ok(())
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
    // Ключ меша разбирается **один раз на запуск**: разбор говорит вслух
    // при неверном ключе, и два разбора подряд означали бы две одинаковые
    // жалобы на одну опечатку. Молча пустой ключ был бы худшим исходом:
    // человек передал `--ygg` и уверен, что меш в карточке, а собеседник
    // видит ступень без адреса и не понимает почему.
    let ygg_key = ygg_from_args(args.ygg.as_deref());
    let have_ygg = !ygg_key.is_empty();
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

    // Раннер заводится **выключенным** всегда, а включает его первый шаг
    // драйвера тем, что подняло ядро (`startup_effects`). Прежде сюда шёл
    // флаг командной строки, у которого умолчание «включена», — и стенд
    // зажигал маяк §5.1 до того, как ядро успевало сказать, что человек
    // его выключил.
    //
    // Порт занимается сразу и без флага: он нужен объявлению, а без
    // объявления никого не раскрывает.
    // Снимается до того, как ядро уедет в драйвер: дальше спросить его
    // можно только через ручку, а шапка печатается раньше.
    let engine_lan = if args.lan_named {
        args.lan
    } else {
        engine.transports().contains(ratatosk_proto::Transport::Lan)
    };

    let config = LanConfig { enabled: false, port: args.port, discovery: args.discovery };
    let lan = LanRunner::start(config, engine.own_card().ik).await?;
    let port = lan.port();
    let directory = lan.directory();

    // Меш заводится всегда, а включается только с ключом: раннер без ключа
    // честно отказывает, и это лучше, чем два разных состава раннеров.
    // Порт занимается при включении, а не здесь, — привязка к своему адресу
    // удаётся только при поднятом демоне.
    let ygg = ratatosk_transport::YggRunner::start(
        ratatosk_transport::YggConfig { enabled: false, port: ratatosk_transport::YGG_PORT },
        &ygg_key,
    )
    .await?;

    // Эфир Bluetooth (0.4). Заводится **выключенным**, как и локальная
    // сеть: включает его ядро первым шагом драйвера, если человек эту
    // ступень разрешил. Сокет и объявление при этом не трогаются вовсе —
    // радио поднимается только на `SetEnabled`.
    //
    // Радио у ступени два, и стенд выбирает своё признаком сборки. С `bt`
    // это `bluer` — настоящий эфир этой машины. Без него берётся мост,
    // тот же, каким пользуется Android, и берётся он **без радио**: мост
    // без радио честно объявляет ступень потерянной. Заглушки ради этого
    // заводить не пришлось — отказ и так получается настоящий, а не
    // написанный отдельно.
    #[cfg(feature = "bt")]
    let air = ratatosk_transport::LocalAir::new();
    #[cfg(not(feature = "bt"))]
    let air = ratatosk_transport::BridgedAir::new();
    let bt = ratatosk_transport::BtRunner::start(
        air,
        ratatosk_transport::BtConfig::default(),
        engine.own_card().ik,
    )
    .await?;

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

    // Раннер nostr заводится одинаково в обеих сборках стенда: Tor ему нужен
    // не всегда. До локального реле (`ws://127.0.0.1:8080`) он ходит напрямую
    // — цепочка встречи до петлевого адреса никуда не вела бы, — и ступень
    // проверяется на своём `nostr-rs-relay` без признака `tor` вовсе.
    #[cfg(feature = "nostr")]
    let nostr = ratatosk_transport::nostr::NostrRunner::new(tor_handle.clone());
    #[cfg(not(feature = "nostr"))]
    let nostr = Disabled;

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
        Transports::new(lan, bt, ygg, onion, nostr, mail)
    };
    #[cfg(not(feature = "tor"))]
    let runner = {
        // Без признака onion и почта — `Disabled`: честный отказ, а не
        // молчаливый успех. Ровно это увидит §5.4 и перейдёт к следующей
        // ступени.
        let _ = (&layout, &onion, &tor_handle);
        Transports::new(lan, bt, ygg, Disabled, nostr, mail)
    };

    println!("узел     : {}", args.name);
    println!("отпечаток: {fingerprint}");
    println!("порт     : {port}");
    // Раньше этой строки не было, и стенд без транспорта выглядел точно так
    // же, как стенд со сломанным транспортом. Разбирать вторую неисправность,
    // имея первую, можно долго.
    println!("сборка   : {}", build_line());
    // Печатается **поднятое с диска**, а не флаг: с этого запуска стенд
    // без ключа сеть не трогает, и печатать намерение вместо состояния
    // значило бы врать ровно в той строке, которую читают первой.
    let lan_now = engine_lan;
    println!(
        "сеть     : {}",
        match (lan_now, args.lan_named) {
            (true, true) => "LAN включена ключом — первая ступень §5.4; выключить: /lan",
            (true, false) => "LAN включена (с прошлого запуска) — первая ступень §5.4; /lan",
            (false, true) => "LAN выключена (--no-lan) — доставка пойдёт через onion",
            (false, false) => "LAN выключена (§5.1, умолчание) — включить: /lan",
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
        "команды: /add <карточка> [ip:порт]   /card   /who   /lan   /bt [on|off]   /ygg [on|off|mode|peer]   /tor [on|off]   /mail [set|new|tor|off]   /net   /onion   /pair <метка>   /devices   /devaddr <ключ> <ip:порт>   /peers   /unpair <id>   /newgroup <название>   /invite <id группы> [ключ]   /groups   /say <id группы> <текст>   /gedit <id группы> <текст>   /greply <id группы> <текст>   /greact <id группы> [эмодзи]   /gretract <id группы>   /rename <id группы> <название>   /gavatar <id группы> [путь]   /leave <id группы>   /evict <id группы> <ключ>   /newchannel <open|invite> <название>   /clink <id канала>   /sub <ссылка>   /unsub <id канала>   /admit <id канала> <ключ>   /right <id канала> <ключ> <waed|-> <дней>   /pow <id канала> <бит>   /rotate <id канала>   /grants <id канала>   /admits <id канала>   /requests <id канала>   /seed <id канала> <on|off|quiet>   /seeds <id канала>   /pull <id канала>   /sharing <id|-> <all|contacts|verified|default>   /limits [<на пира> <общий>]   /peeraddr <ключ> <ip:порт>   /find <слова>   /share   /take <msg_id>   /react [эмодзи]   /long [килобайт]   /probe <s|m|l> [сколько]   /file <путь>   /files   /accept <id>   /pause <id>   /decline <id>   /save <id> <путь>   /auto [байт|off]   /sweep   /export [nofiles|graph] <путь> [-- фраза]   /merge <архив> -- <фраза>   /quit\n\nввоз архива — отдельным запуском: --import <файл> --data <база> и --phrase <фраза> либо --key <ключ>"
    );
    println!("всё остальное уходит текстом первому добавленному контакту");
    println!();

    let (mut driver, handle, events) = Driver::new(engine, runner);

    // §5.1: LAN выключен по умолчанию. Стенд включает его явно — ровно так же,
    // как это должен будет сделать пользователь в UI. Команда идёт первой:
    // она проставляет разрешение уже поднятым с диска контактам.
    if args.lan_named {
        handle
            .send(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: args.lan,
            })
            .await
            .ok();
    }

    // Ключ из командной строки — это выбор режима «внешний демон», и едет
    // он **командами**, а не полем при сборке: настройки меша живут в базе,
    // и `--ygg` их меняет, а не подменяет на один запуск. Через ручку,
    // а не `engine.step` до драйвера: рассылка карточки §4.3 обязана уехать,
    // а не потеряться вместе с брошенными эффектами.
    //
    // Без ключа режим не трогается вовсе. Иначе запуск без флага выключал бы
    // меш тому, кто настроил его в прошлый раз и просто забыл флаг, — и
    // выглядело бы это как «стенд ломает настройки».
    if have_ygg {
        handle.send(Command::SetYggKey(ygg_key.clone())).await.ok();
        handle.send(Command::SetYggMode(ygg::YggMode::External)).await.ok();
    }

    tokio::select! {
        result = driver.run() => {
            if let Err(error) = result {
                eprintln!("ядро остановилось: {error}");
            }
        }
        () = console(handle, events, directory, own_ik, onion_address, lan_now) => {}
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
    //
    // Приходит **поднятой с диска**, а не флагом командной строки: иначе
    // первый же `/lan` после запуска, где сеть была выключена в прошлый раз,
    // сработал бы наоборот.
    mut lan_on: bool,
) {
    // Последняя новость о Tor — для команды `/tor`. Именно последняя,
    // а не все: новости о подъёме это состояние, а не история.
    let mut tor: Option<String> = None;
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut peer: Option<[u8; 32]> = None;
    // Замер эфира. Живёт в петле, а не в `report`: считать надо по ходу,
    // а `report` про состояние стенда ничего не знает и знать не должен.
    let mut probe: Option<Probe> = None;

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
                if line == "/peers" {
                    show_peers(&handle, &directory).await;
                    continue;
                }
                if line == "/devices" {
                    show_devices(&handle, &directory).await;
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/say ") {
                    // Отправка в группу — той же командой ядра, что и личное
                    // сообщение: ветку выбирает `chat_id`, а не клиент (§13.3).
                    // Стенду нужен отдельный ввод только потому, что он
                    // не держит «открытый чат».
                    let (chat, text) = rest.split_once(' ').unwrap_or((rest, ""));
                    match data_encoding::HEXLOWER.decode(chat.as_bytes()) {
                        Ok(raw) if raw.len() == 16 && !text.trim().is_empty() => {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&raw);
                            handle
                                .send(Command::SendText { chat: id, text: text.to_owned() })
                                .await
                                .ok();
                        }
                        _ => println!("< нужно: /say <id группы> <текст> — id печатает /groups"),
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/gedit ") {
                    let (chat, text) = split_group(rest, "/gedit <id группы> <текст>");
                    if let (Some(chat), false) = (chat, text.trim().is_empty()) {
                        match last_in_group(&handle, chat, Some(own_ik)).await {
                            Some(msg_id) => {
                                handle
                                    .send(Command::EditMessage {
                                        chat,
                                        msg_id,
                                        text: text.to_owned(),
                                    })
                                    .await
                                    .ok();
                                println!("< правка {}", short(&msg_id));
                            }
                            None => println!("< в группе нет вашего сообщения"),
                        }
                    } else if chat.is_some() {
                        // Пустая правка — это удаление, и у него своя команда.
                        println!("< пустая правка — это удаление: /gretract");
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/greply ") {
                    let (chat, text) = split_group(rest, "/greply <id группы> <текст>");
                    if let (Some(chat), false) = (chat, text.trim().is_empty()) {
                        match last_in_group(&handle, chat, None).await {
                            Some(reply_to) => {
                                handle
                                    .send(Command::SendReply {
                                        chat,
                                        reply_to,
                                        text: text.to_owned(),
                                    })
                                    .await
                                    .ok();
                                println!("< ответ на {}", short(&reply_to));
                            }
                            None => println!("< в группе пока нечего цитировать"),
                        }
                    } else if chat.is_some() {
                        println!("< ответ без слов — не ответ: /greply <id группы> <текст>");
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/greact ") {
                    // Без эмодзи — снятие: пустая строка и есть «снято»
                    // (`ratatosk_proto::reaction`).
                    let (chat, emoji) = split_group(rest, "/greact <id группы> [эмодзи]");
                    if let Some(chat) = chat {
                        match last_in_group(&handle, chat, None).await {
                            Some(msg_id) => {
                                handle
                                    .send(Command::SetReaction {
                                        chat,
                                        msg_id,
                                        emoji: emoji.trim().to_owned(),
                                    })
                                    .await
                                    .ok();
                                println!("< реакция на {}", short(&msg_id));
                            }
                            None => println!("< в группе пока нечего отмечать"),
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/gretract ") {
                    let (chat, _) = split_group(rest, "/gretract <id группы>");
                    if let Some(chat) = chat {
                        match last_in_group(&handle, chat, Some(own_ik)).await {
                            Some(msg_id) => {
                                println!(
                                    "< это просьба, а не гарантия: чужой клиент вправе её не выполнить"
                                );
                                handle
                                    .send(Command::RetractMessages {
                                        chat,
                                        msg_ids: vec![msg_id],
                                    })
                                    .await
                                    .ok();
                            }
                            None => println!("< в группе нет вашего сообщения"),
                        }
                    }
                    continue;
                }
                if line == "/groups" {
                    show_groups(&handle).await;
                    continue;
                }
                // **Команда без аргументов — подсказка, а не сообщение.**
                // Разборы ниже ищут приставку **с пробелом**, и `/clink`,
                // набранный без идентификатора, проваливался сквозь них
                // в общий путь «строка без команды» — то есть уезжал
                // собеседнику текстом. Поймано на стенде: в чужом чате
                // появились строки `/channels` и `/clink`.
                if let Some(usage) = channel_usage(&line) {
                    println!("< нужно: {usage}");
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/newchannel ") {
                    // Порода называется **словом и всегда**: она задаётся
                    // при заведении и не меняется никогда (§6.1), а умолчание
                    // здесь означало бы выбрать за человека то, что потом
                    // не исправить.
                    let (kind, title) = rest.trim().split_once(' ').unwrap_or((rest.trim(), ""));
                    let open = match kind {
                        "open" => Some(true),
                        "invite" => Some(false),
                        _ => {
                            println!("< нужно: /newchannel <open|invite> <название>");
                            None
                        }
                    };
                    if let Some(open) = open {
                        if title.trim().is_empty() {
                            println!("< без названия: /newchannel <open|invite> <название>");
                        } else {
                            // Последствие — до заведения, а не после (§15),
                            // и только то, которое сказано **заводящему**.
                            if let Some(notice) = creation_notice(open) {
                                println!("< {notice}");
                            }
                            handle
                                .send(Command::CreateChannel {
                                    title: title.trim().to_owned(),
                                    open,
                                })
                                .await
                                .ok();
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/clink ") {
                    let (chat, _) = split_group(rest, "/clink <id канала>");
                    if let Some(chat) = chat {
                        match handle.channel_link(chat).await {
                            None => println!("< драйвер остановлен"),
                            Some(Err(error)) => println!("< ссылку не собрать: {error}"),
                            Some(Ok(link)) => {
                                // Последствие — вместе со ссылкой, а не вместо
                                // неё (§15, §10.2): в ссылке едет наш адрес.
                                println!("< {}", ratatosk_proto::channel::SharingConsequences::ui_text());
                                println!("< {link}");
                            }
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/sub ") {
                    let uri = rest.trim().to_owned();
                    // **Вот здесь §15 и говорит про породу** — тому, кто
                    // подписывается, и до подписки. Порода читается
                    // из самой ссылки: наличие ключа чтения и есть она
                    // (§6.1). Разобрать её здесь — не вторая проверка:
                    // не разберись строка, команда всё равно уедет
                    // и ядро откажет словами, а источник правды один.
                    if let Ok(invitation) = ratatosk_proto::channel::Invitation::from_uri(&uri) {
                        println!("< {}", subscription_notice(invitation.claims_open()));
                        // **Ссылка без адресов — честное предупреждение.**
                        // §10.2 везёт в ссылке onion, почту, меш, ключ nostr
                        // и реле, но
                        // **не** адрес в локальной сети: он меняется при
                        // каждом подключении. Если адресов нет вовсе,
                        // заявка (§10.4) ляжет в очередь и будет ждать,
                        // пока владельца не станет слышно в эфире, — а
                        // на loopback маяка не бывает.
                        //
                        // Сказать это надо здесь: человек нажал «подписаться»
                        // и вправе знать, что пути пока нет. Иначе «ждём
                        // впуска» выглядит обещанием, которого никто
                        // не давал (§14).
                        if !invitation.claims_open() && invitation.endpoints.is_empty() {
                            println!(
                                "< в ссылке нет адресов: заявка полежит в очереди, пока \
                                 владельца не станет слышно. Не слышно — назовите адрес: \
                                 /peeraddr {} <ip:порт>",
                                data_encoding::HEXLOWER.encode(&invitation.owner)
                            );
                        }
                    }
                    handle.send(Command::SubscribeToChannel { uri }).await.ok();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/unsub ") {
                    let (chat, _) = split_group(rest, "/unsub <id канала>");
                    if let Some(chat) = chat {
                        // Стирает ключи чтения, а с ними архив (§10.6).
                        // Сказать это стенду надо ровно так же, как клиенту.
                        println!(
                            "< отписка сотрёт ключи чтения: прежние записи канала \
                             больше не откроются никогда"
                        );
                        handle.send(Command::UnsubscribeFromChannel { chat }).await.ok();
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/admit ") {
                    let (chat, who) = split_group(rest, "/admit <id канала> <ключ>");
                    if let Some(chat) = chat {
                        match decode_ik(who.trim()) {
                            Some(peer_ik) => {
                                handle.send(Command::AdmitToChannel { chat, peer_ik }).await.ok();
                            }
                            None => println!("< ключ — 64 знака hex; /who показывает его"),
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/right ") {
                    // `/right <id> <ключ> <набор|-> <дней>`: набор буквами
                    // (w a e d), прочерк снимает. Срок обязателен — §6.3
                    // не знает прав без срока, и умолчание здесь завело бы
                    // право, которое некому истечь.
                    let (chat, tail) = split_group(rest, "/right <id канала> <ключ> <waed|-> <дней>");
                    if let Some(chat) = chat {
                        let mut parts = tail.split_whitespace();
                        let who = parts.next().unwrap_or_default();
                        let set = parts.next().unwrap_or_default();
                        let days = parts.next().unwrap_or_default();
                        match (decode_ik(who), decode_rights(set), days.parse::<u64>()) {
                            (Some(who), Some(rights), Ok(days)) => {
                                if rights != 0 && set.contains('a') {
                                    // §6.5: сказать это надо при назначении,
                                    // а не при снятии.
                                    println!(
                                        "< {}",
                                        ratatosk_proto::channel::AdmitterGrantConsequences::ui_text()
                                    );
                                }
                                let until_ms = wall_ms() + days * 24 * 60 * 60 * 1000;
                                handle
                                    .send(Command::SetChannelRight {
                                        chat,
                                        who,
                                        rights,
                                        until_ms: if rights == 0 { 0 } else { until_ms },
                                    })
                                    .await
                                    .ok();
                            }
                            _ => println!(
                                "< нужно: /right <id канала> <ключ> <waed|-> <дней> — \
                                 w писать, a впускать, e исключать, d править"
                            ),
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/pow ") {
                    let (chat, bits) = split_group(rest, "/pow <id канала> <бит>");
                    if let Some(chat) = chat {
                        match bits.trim().parse::<u32>() {
                            Ok(bits) => {
                                handle.send(Command::SetChannelPow { chat, bits }).await.ok();
                            }
                            Err(_) => println!("< нужно: /pow <id канала> <бит>, ноль снимает цену"),
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/rotate ") {
                    let (chat, _) = split_group(rest, "/rotate <id канала>");
                    if let Some(chat) = chat {
                        // Кнопка называется последствием (§6.4, §15).
                        println!(
                            "< {}",
                            ratatosk_proto::channel::KeyRotationConsequences::ui_text()
                        );
                        handle.send(Command::RotateChannelKey { chat }).await.ok();
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/grants ") {
                    let (chat, _) = split_group(rest, "/grants <id канала>");
                    if let Some(chat) = chat {
                        show_grants(&handle, chat).await;
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/seed ") {
                    // **Раздача — согласие, а не право** (§7.5.1), и три
                    // состояния здесь не для полноты: тихая раздача
                    // умолчанием и есть то, на чём рой держится, а
                    // объявление адреса остаётся выбором с текстом §15.
                    let (chat, tail) = split_group(rest, "/seed <id канала> <on|off|quiet>");
                    if let Some(chat) = chat {
                        // Три состояния, и на стенде они теперь различимы:
                        // «off» перестал быть синонимом тихой раздачи
                        // с тех пор, как появилось право на обслуживание
                        // (§8.3) — выключивший не отдаёт никому.
                        let mode = match tail.trim() {
                            "on" | "да" => {
                                // Текст — **до** команды: после неё адрес
                                // уже уехал бы в каталог.
                                println!(
                                    "< {}",
                                    ratatosk_proto::swarm::SeedingConsequences::ui_text()
                                );
                                ratatosk_proto::swarm::Seeding::Announced
                            }
                            "off" | "нет" => ratatosk_proto::swarm::Seeding::Off,
                            _ => ratatosk_proto::swarm::Seeding::Quiet,
                        };
                        handle.send(Command::SetSeeding { chat, mode }).await.ok();
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/pull ") {
                    // §7.4, шаг 3: глубину тянет человек, а не обход.
                    // Одно движение — одна страница; конец истории
                    // приезжает событием, а не молчанием.
                    let (chat, _) = split_group(rest, "/pull <id канала>");
                    if let Some(chat) = chat {
                        handle.send(Command::PullOlderHistory { chat }).await.ok();
                        println!("< прошу страницу истории — дальше слушайте ленту");
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/sharing ") {
                    // §12: кому отдаём. Первое слово — канал или «-»
                    // (умолчание аккаунта), второе — уровень.
                    let (chat, tail) = if rest.trim_start().starts_with('-') {
                        (None, rest.trim_start().trim_start_matches('-').trim().to_owned())
                    } else {
                        let (chat, tail) = split_group(rest, "/sharing <id канала|-> <уровень>");
                        match chat {
                            Some(chat) => (Some(chat), tail.trim().to_owned()),
                            None => continue,
                        }
                    };
                    let level = match tail.as_str() {
                        "all" | "всем" => Some(ratatosk_proto::swarm::Sharing::Everyone),
                        "contacts" | "контактам" => {
                            Some(ratatosk_proto::swarm::Sharing::Contacts)
                        }
                        "verified" | "сверенным" => {
                            Some(ratatosk_proto::swarm::Sharing::Verified)
                        }
                        "default" | "умолчание" => None,
                        other => {
                            println!(
                                "< не знаю уровня «{other}»: all, contacts, verified, default"
                            );
                            continue;
                        }
                    };
                    // Текст §12 — **до** сужения: платит за него не только
                    // тот, кто настраивал.
                    if level.is_some_and(ratatosk_proto::swarm::Sharing::narrows_the_swarm) {
                        println!(
                            "< {}",
                            ratatosk_proto::swarm::SharingLevelConsequences::ui_text()
                        );
                    }
                    handle.send(Command::SetSharing { chat, level }).await.ok();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/limits") {
                    // §9.2: три числа и выключатель, все на диске. Здесь
                    // два наших — на пира и общий.
                    let words: Vec<&str> = rest.split_whitespace().collect();
                    match words.as_slice() {
                        [] => {
                            if let Some(limits) = handle.giving_limits().await {
                                println!(
                                    "< отдаём не больше {} блоков одному и {} всем за минуту",
                                    limits.per_peer, limits.total
                                );
                            }
                        }
                        [per_peer, total] => {
                            match (per_peer.parse::<u32>(), total.parse::<u32>()) {
                                (Ok(per_peer), Ok(total)) => {
                                    handle
                                        .send(Command::SetGivingLimits(
                                            ratatosk_proto::swarm::GivingLimits {
                                                per_peer,
                                                total,
                                            },
                                        ))
                                        .await
                                        .ok();
                                }
                                _ => println!("< числа: /limits <на пира> <общий>"),
                            }
                        }
                        _ => println!("< /limits [<на пира> <общий>]"),
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/seeds ") {
                    let (chat, _) = split_group(rest, "/seeds <id канала>");
                    if let Some(chat) = chat {
                        show_seeds(&handle, chat).await;
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/requests ") {
                    let (chat, _) = split_group(rest, "/requests <id канала>");
                    if let Some(chat) = chat {
                        show_requests(&handle, chat).await;
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/admits ") {
                    let (chat, _) = split_group(rest, "/admits <id канала>");
                    if let Some(chat) = chat {
                        show_admits(&handle, chat).await;
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/rename ") {
                    // Переименовать вправе только создатель; отказ придёт
                    // из ядра, и печатать его здесь нечем — команды уходят
                    // без ответа. Зато событие о смене имени придёт всем,
                    // включая нас.
                    let (chat, title) = split_group(rest, "/rename <id группы> <название>");
                    if let Some(chat) = chat {
                        if title.trim().is_empty() {
                            println!("< без названия: /rename <id группы> <новое название>");
                        } else {
                            handle
                                .send(Command::RenameGroup { chat, title: title.to_owned() })
                                .await
                                .ok();
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/gavatar ") {
                    // Картинка берётся с диска, а не выдумывается: проверяются
                    // и сигнатура формата, и предел, и оба — настоящие.
                    // Пустой путь снимает картинку: снятие такое же действие,
                    // как постановка, и проверять его надо ровно так же.
                    let (chat, path) = split_group(rest, "/gavatar <id группы> [путь]");
                    if let Some(chat) = chat {
                        let path = path.trim();
                        let bytes = if path.is_empty() {
                            Some(Vec::new())
                        } else {
                            match std::fs::read(path) {
                                Ok(bytes) => Some(bytes),
                                Err(error) => {
                                    println!("< не прочитать {path}: {error}");
                                    None
                                }
                            }
                        };
                        if let Some(bytes) = bytes {
                            // Проверка здесь, а не только в ядре: команда
                            // уходит без ответа, и отказ оттуда на стенде
                            // выглядел бы молчанием — ровно тем, что §14
                            // запрещает.
                            match ratatosk_proto::avatar::check(&bytes) {
                                Ok(()) => {
                                    handle
                                        .send(Command::SetGroupAvatar { chat, bytes })
                                        .await
                                        .ok();
                                }
                                Err(error) => println!("< {error}"),
                            }
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/leave ") {
                    // Перед выходом стенд печатает то же, что обязан показать
                    // клиент, — и предупреждение создателю, если выходит он.
                    // Увидеть формулировку глазами полезнее, чем прочитать
                    // её в тесте.
                    let (chat, _) = split_group(rest, "/leave <id группы>");
                    if let Some(chat) = chat {
                        println!("< {}", ratatosk_proto::group::LeaveConsequences::ui_text());
                        // `mine` у `GroupStatus` и означает «создатель ли мы»:
                        // ради этого поле и заведено — от него зависит,
                        // показывать ли «исключить» (§11.2).
                        if handle
                            .groups()
                            .await
                            .is_some_and(|all| all.iter().any(|g| g.chat == chat && g.mine))
                        {
                            println!(
                                "< {}",
                                ratatosk_proto::group::LeaveConsequences::owner_text()
                            );
                        }
                        handle.send(Command::LeaveGroup { chat }).await.ok();
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/evict ") {
                    // Перед исключением стенд печатает §11.4 дословно: это
                    // ровно та формулировка, которую обязан показать клиент,
                    // и увидеть её глазами полезнее, чем прочитать в тесте.
                    println!("< {}", ratatosk_proto::group::EvictionConsequences::ui_text());
                    let mut parts = rest.split_whitespace();
                    let chat = parts.next().unwrap_or_default();
                    let who = parts.next().unwrap_or_default();
                    match (
                        data_encoding::HEXLOWER.decode(chat.as_bytes()),
                        data_encoding::HEXLOWER.decode(who.as_bytes()),
                    ) {
                        (Ok(chat), Ok(ik)) if chat.len() == 16 && ik.len() == 32 => {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&chat);
                            let mut peer_ik = [0u8; 32];
                            peer_ik.copy_from_slice(&ik);
                            handle.send(Command::EvictFromGroup { chat: id, peer_ik }).await.ok();
                        }
                        _ => println!("< нужно: /evict <id группы> <ключ участника> — оба из /groups"),
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/invite ") {
                    // Два аргумента, второй необязателен: на стенде собеседник
                    // обычно один, и заставлять набирать его ключ руками
                    // значит мешать проверять то, ради чего команда написана.
                    let mut parts = rest.split_whitespace();
                    let chat = parts.next().unwrap_or_default();
                    let who = parts.next();
                    let chat = match data_encoding::HEXLOWER.decode(chat.as_bytes()) {
                        Ok(raw) if raw.len() == 16 => {
                            let mut id = [0u8; 16];
                            id.copy_from_slice(&raw);
                            id
                        }
                        // Печатается полностью в `/groups`: у группы
                        // идентификатор случаен, и короткой формы из журнала
                        // не хватит.
                        _ => {
                            println!("< нужен полный id группы в hex (32 знака) — /groups");
                            continue;
                        }
                    };
                    let peer_ik = match who {
                        Some(hex) => match data_encoding::HEXLOWER.decode(hex.as_bytes()) {
                            Ok(raw) if raw.len() == 32 => {
                                let mut ik = [0u8; 32];
                                ik.copy_from_slice(&raw);
                                Some(ik)
                            }
                            _ => {
                                println!("< ключ участника — 64 знака hex; /who показывает его");
                                continue;
                            }
                        },
                        None => sole_contact(&handle).await,
                    };
                    let Some(peer_ik) = peer_ik else {
                        println!("< некого приглашать: сперва /add <карточка>");
                        continue;
                    };
                    handle.send(Command::InviteToGroup { chat, peer_ik }).await.ok();
                    continue;
                }
                if let Some(title) = line.strip_prefix("/newgroup ") {
                    // Отправлять отсюда нечего: группа в момент заведения
                    // состоит из создателя (§11). Идентификатор придёт
                    // событием `GroupCreated` — вывести его человеку неоткуда
                    // больше, он случаен.
                    handle
                        .send(Command::CreateGroup { title: title.trim().to_owned() })
                        .await
                        .ok();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/peeraddr ") {
                    // **Адрес владельца канала руками.** По ссылке (§10.2)
                    // едут onion, почта, меш, ключ nostr и реле — но **не** адрес
                    // в локальной сети: он меняется при каждом подключении,
                    // и в карточке его тоже нет. В LAN адрес даёт маяк
                    // (§5.1), а мультикаст режут и корпоративные сети,
                    // и гостевой Wi-Fi, и loopback на одной машине.
                    //
                    // Тогда адрес называет человек — как `/devaddr` для
                    // терминала. Справочник у них один; команды две,
                    // потому что человек думает не «в какой справочник»,
                    // а «кому я называю адрес».
                    //
                    // Ключ владельца печатает `/groups` в строке канала.
                    let mut parts = rest.split_whitespace();
                    let key = parts.next().unwrap_or_default();
                    let addr = parts.next().unwrap_or_default();
                    match (decode_ik(key), addr.parse::<std::net::SocketAddr>()) {
                        (Some(ik), Ok(addr)) => {
                            directory.note(ik, addr);
                            println!("< {} по адресу {addr} — заявка поедет туда", short(&ik));
                        }
                        _ => println!(
                            "< нужно: /peeraddr <64 знака hex> <ip:порт> — ключ владельца \
                             печатает /groups"
                        ),
                    }
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
                // Имя команды целиком, а не по началу строки: `/find`
                // и `/file` различаются одной буквой, и «начинается на»
                // однажды увело бы поиск в отправку файла.
                if is_file_command(&line) {
                    if peer.is_none() {
                        peer = sole_contact(&handle).await;
                    }
                    file_command(&handle, &line, peer).await;
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
                if let Some(rest) = line.strip_prefix("/export ") {
                    // §12: единственный путь переноса истории. Ключ печатается
                    // **один раз** и больше не показывается — как ссылка
                    // сопряжения: второй раз этот же архив не спросишь.
                    // Фраза — после `--`, как подпись у `/send`: в ней бывают
                    // пробелы, и разбирать её по словам нельзя.
                    let (rest, phrase) = match rest.split_once(" -- ") {
                        Some((head, phrase)) => (head, Some(phrase.trim().to_owned())),
                        None => (rest, None),
                    };
                    let rest = rest.trim();
                    let (scope, path) = match rest.split_once(char::is_whitespace) {
                        Some(("nofiles", path)) => {
                            (ratatosk_core::ExportScope::WithoutAttachments, path)
                        }
                        Some(("graph", path)) => (ratatosk_core::ExportScope::SocialGraph, path),
                        _ => (ratatosk_core::ExportScope::Everything, rest),
                    };
                    let path = std::path::PathBuf::from(path.trim());
                    match handle.export_history(path, scope, phrase).await {
                        Some(Ok(done)) => {
                            println!(
                                "< архив: {} — {} ({} вложений, {} байт)",
                                done.path.display(),
                                done.scope.title(),
                                done.files,
                                done.bytes
                            );
                            if done.locked_by_phrase {
                                println!("< заперт фразой; ключ — запасной вход: {}", done.key_text);
                            } else {
                                println!(
                                    "< ключ (запишите, второй раз не покажу): {}",
                                    done.key_text
                                );
                            }
                        }
                        Some(Err(why)) => println!("< не вышло: {why}"),
                        None => return,
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("/merge ") {
                    // Слияние — **не** ввоз: личность и переписка остаются
                    // свои, из архива берутся только знакомства. Поэтому
                    // командой в живом аккаунте, а не отдельным запуском.
                    let (path, secret) = match rest.trim().split_once(" -- ") {
                        Some((path, secret)) => (path.trim(), Some(secret.trim())),
                        None => (rest.trim(), None),
                    };
                    let archive = std::path::PathBuf::from(path);
                    let unlock = match secret {
                        Some(secret) => ratatosk_core::ArchiveKey::Passphrase(secret.to_owned()),
                        None => {
                            println!("< нужна фраза: /merge <архив> -- <фраза>");
                            continue;
                        }
                    };
                    let scratch = std::env::temp_dir().join("ratatosk-lab-merge");
                    match handle.merge_contacts(archive, unlock, scratch).await {
                        Some(Ok(merged)) => {
                            println!(
                                "< добавлено {}, уже были {}, отвергнуто {}",
                                merged.added, merged.known, merged.refused
                            );
                            if merged.own_graph {
                                println!("< это ваш же граф: сверка и локальные имена перенесены");
                            } else {
                                println!(
                                    "< список чужой: никто не сверен (§4.2), имена не перенесены"
                                );
                            }
                        }
                        Some(Err(why)) => println!("< не вышло: {why}"),
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
                // Голое `/ygg` обязано попадать сюда же, а не мимо: первая
                // редакция разбирала только `/ygg ` с пробелом, и `/ygg`
                // уходило в переключатель — то есть команда, которую сама
                // же подсказка называет «что сейчас», печатала «ключа нет».
                if line == "/ygg" || line.starts_with("/ygg ") {
                    let rest = line.strip_prefix("/ygg").unwrap_or_default().trim();
                    ygg_command(&handle, rest).await;
                    continue;
                }
                if line == "/bt" || line.starts_with("/bt ") {
                    let rest = line.strip_prefix("/bt").unwrap_or_default().trim();
                    bt_command(&handle, rest).await;
                    continue;
                }
                if line == "/nostr" || line.starts_with("/nostr ") {
                    let rest = line.strip_prefix("/nostr").unwrap_or_default().trim();
                    nostr_command(&handle, rest).await;
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
                    println!(
                        "< сеть объявлена сменившейся: локальная объявляется заново, \
                         меш и onion сбрасывают связи"
                    );
                    // Заодно — состав пиров меша: он печатается той же
                    // дорогой, потому что «сеть сменилась» до этой ступени
                    // и так доходит. Строкой в журнале, а не ответом сюда:
                    // это сырой ответ библиотеки, который мы пока
                    // не разбираем, и место ему в журнале, а не в UI стенда.
                    println!("  состав пиров меша — строкой «меш: …» в журнале ниже");
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

                // Длинный текст **не набирается руками**, и это не лень,
                // а измеренное свойство терминала: в каноническом режиме
                // строка со stdin обрезается на 4095 байтах — молча, без
                // единого сообщения. Первая же попытка проверить многочастный
                // кадр с клавиатуры дала «текст режется примерно на 4000
                // символов», и выглядело это как наша поломка.
                if line == "/probe" || line.starts_with("/probe ") {
                    let rest = line.strip_prefix("/probe").unwrap_or_default().trim();
                    if rest.is_empty() {
                        match &probe {
                            Some(held) => held.tally(),
                            None => println!("{PROBE_USAGE}"),
                        }
                        continue;
                    }
                    let mut words = rest.split_whitespace();
                    let Some(class) = words.next().and_then(probe_class) else {
                        println!("{PROBE_USAGE}");
                        continue;
                    };
                    let count: usize = match words.next() {
                        Some(word) => word.parse().unwrap_or(0),
                        None => Probe::default_count(class),
                    };
                    if count == 0 || count > PROBE_MAX {
                        println!("{PROBE_USAGE}");
                        continue;
                    }
                    if peer.is_none() {
                        peer = sole_contact(&handle).await;
                    }
                    let Some(ik) = peer else {
                        println!("< писать некому: /add <карточка> [ip:порт]");
                        continue;
                    };
                    let Some(started) = Probe::start(class, count) else {
                        println!("< столько не влезает ни в один класс кадра");
                        continue;
                    };
                    started.announce();
                    let chat = Engine::<MemoryStore>::chat_id_for(&ik);
                    for _ in 0..count {
                        let text = long_text(started.text_bytes);
                        if handle.send(Command::SendText { chat, text }).await.is_err() {
                            return;
                        }
                    }
                    probe = Some(started);
                    continue;
                }

                if line == "/long" || line.starts_with("/long ") {
                    let rest = line.strip_prefix("/long").unwrap_or_default().trim();
                    let kib: usize = if rest.is_empty() { 8 } else { rest.parse().unwrap_or(0) };
                    if kib == 0 || kib > 512 {
                        println!("< нужно: /long [килобайт от 1 до 512] — по умолчанию 8");
                        continue;
                    }
                    let text = long_text(kib * 1024);
                    if peer.is_none() {
                        peer = sole_contact(&handle).await;
                    }
                    let Some(ik) = peer else {
                        println!("< писать некому: /add <карточка> [ip:порт]");
                        continue;
                    };
                    let chat = Engine::<MemoryStore>::chat_id_for(&ik);
                    println!("< шлём длинный текст: {} Б", text.len());
                    // Класс кадра называется **до** отправки, и не для красоты:
                    // граница между классами M и L — это граница между «ступень
                    // nostr это везёт» и «не везёт», и найдена она была дорого,
                    // как «ограничение примерно 63 килобайта».
                    //
                    // Считается настоящей арифметикой (`SizeClass::smallest_for`),
                    // а не своей копией: своя разошлась бы с ядром молча.
                    // Запас конверта берётся сверху — тем же числом, которым
                    // его резервирует протокол.
                    let with_envelope = text.len() + ratatosk_proto::files::ENVELOPE_RESERVE_BYTES;
                    match ratatosk_proto::SizeClass::smallest_for(with_envelope) {
                        Some(ratatosk_proto::SizeClass::L) => {
                            // Кто именно не везёт класс L, называется
                            // поимённо, и это не педантизм: строка
                            // «уйдёт почтой» была написана, когда ступень
                            // была одна, и после эфира (0.4) стала
                            // неправдой — он класс L везёт, своим каналом.
                            // Стенд, говорящий человеку неправду про
                            // маршрут, хуже стенда молчащего.
                            println!("    класс кадра L — его не везёт nostr (0.3.5),");
                            println!("    остальные ступени везут; эфир — отдельным каналом,");
                            println!("    и мебибайт по нему идёт около тридцати секунд (0.4.4)");
                        }
                        Some(class) => println!("    класс кадра {class:?}"),
                        None => println!("    столько не влезает ни в один класс кадра"),
                    }
                    println!("    нарезку и сборку ищите в журнале: «кадр поехал частями»");
                    if handle.send(Command::SendText { chat, text }).await.is_err() {
                        return;
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
                    // Каталог роя строку разговора не заводит: его
                    // печатает `report`, а здесь выбирают собеседника.
                    Event::SeedingChanged { .. }
                    | Event::SeedAnnounced { .. }
                    | Event::ChannelHistoryEnd { .. } => {}
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
                                        // Подпись автора — только там, где
                                        // её не вывести из «своё/чужое», то
                                        // есть в группе. В переписке двоих
                                        // она повторяла бы имя собеседника
                                        // у каждой строки.
                                        let body =
                                            String::from_utf8_lossy(&view.message.body);
                                        // Длинный текст **проверяется**, а не
                                        // печатается стеной: глазами в восьми
                                        // килобайтах обрыв не найти, а стенд
                                        // находит его по своей же разметке
                                        // (`/long`).
                                        let shown = long_verdict(&body)
                                            .unwrap_or_else(|| body.to_string());
                                        match &view.author {
                                            Some(author) => println!("< {author}: {shown}"),
                                            None => println!("< {shown}"),
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Замер считает **доставленные**: квитанция — это
                    // доказательство того, что кадр расшифровался на той
                    // стороне, то есть доехал целым. Ничего точнее у нас
                    // нет и быть не может.
                    Event::StatusChanged { msg_id, status } => {
                        if let Some(held) = probe.as_mut() {
                            if held.note(*msg_id, *status) {
                                held.tally();
                            }
                        }
                    }
                    Event::MessagesDeleted { .. }
                    | Event::MessageEdited { .. }
                    | Event::ReactionChanged { .. }
                    | Event::ContactChanged { .. }
                    | Event::ContactRemoved { .. }
                    | Event::AvatarChanged { .. }
                    | Event::OwnAvatarChanged
                    | Event::GroupCreated { .. }
                    | Event::ChannelCreated { .. }
                    | Event::ChannelChanged { .. }
                    | Event::ChannelSubscribed { .. }
                    | Event::ChannelRequested { .. }
                    | Event::ChannelUnsubscribed { .. }
                    | Event::ChannelKeyRotated { .. }
                    | Event::ChannelAdmitted { .. }
                    | Event::GroupMembershipChanged { .. }
                    | Event::GroupRenamed { .. }
                    | Event::GroupAvatarChanged { .. }
                    | Event::FileProgress { .. }
                    | Event::FileSending { .. }
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
/// Печатает группы и их состав (§11).
/// Разбирает «`<id группы>` и остаток строки».
///
/// Идентификатор печатает `/groups`; стенд не держит «открытого чата»,
/// поэтому его приходится называть каждый раз. Отказ печатается здесь же,
/// чтобы подсказка про формат стояла рядом с разбором, а не у четырёх
/// вызывающих.
fn split_group<'a>(rest: &'a str, usage: &str) -> (Option<[u8; 16]>, &'a str) {
    let (chat, tail) = rest.split_once(' ').unwrap_or((rest.trim(), ""));
    match data_encoding::HEXLOWER.decode(chat.trim().as_bytes()) {
        Ok(raw) if raw.len() == 16 => {
            let mut id = [0u8; 16];
            id.copy_from_slice(&raw);
            (Some(id), tail)
        }
        _ => {
            println!("< нужно: {usage} — id печатает /groups");
            (None, tail)
        }
    }
}

/// Последнее сообщение группы — или последнее **своё**.
///
/// Стенд действует на последнее, а не на названный идентификатор, и это
/// то же решение, что у `/react` в личном чате: набирать тридцать два знака
/// hex ради смайлика человек не станет, а проверяется здесь дорога до ядра,
/// а не разбор строки.
///
/// `mine` для правки и отзыва: распорядиться не своим ядро всё равно
/// не даст, но команды уходят **без ответа**, и отказ, случившийся там,
/// на экране не появится вовсе. Лучше сказать «нет вашего сообщения» здесь,
/// чем молча ничего не сделать.
///
/// Свой ключ приходит параметром, а не спрашивается у ручки: `OwnCard`
/// у драйвера — про адреса (§4.3), ключа в ней нет вовсе, а консоль своим
/// ключом уже располагает.
async fn last_in_group(
    handle: &DriverHandle,
    chat: [u8; 16],
    mine: Option<[u8; 32]>,
) -> Option<[u8; 16]> {
    let seen = handle.messages(chat, 50).await?;
    seen.into_iter()
        .rev()
        .find(|view| mine.is_none_or(|own| view.message.sender_ik == own))
        .map(|view| view.message.msg_id)
}

/// Подсказка по канальной команде, набранной без аргументов.
///
/// `None` — это не канальная команда без аргументов, и строку надо
/// разбирать дальше: она может быть и командой с аргументами,
/// и обычным сообщением.
///
/// Список здесь, а не по месту каждого разбора: забыть одну строку
/// из десяти — значит вернуть ровно ту поломку, ради которой список
/// и заведён.
fn channel_usage(line: &str) -> Option<&'static str> {
    Some(match line.trim() {
        "/newchannel" => "/newchannel <open|invite> <название>",
        "/clink" => "/clink <id канала> — id печатает /groups",
        "/sub" => "/sub <ссылка ratatosk:v0:channel:…>",
        "/unsub" => "/unsub <id канала> — стирает ключи чтения вместе с архивом",
        "/admit" => "/admit <id канала> <ключ> — ключ печатает /who",
        "/right" => "/right <id канала> <ключ> <waed|-> <дней>",
        "/pow" => "/pow <id канала> <бит>, ноль снимает цену",
        "/rotate" => "/rotate <id канала>",
        "/grants" => "/grants <id канала>",
        "/admits" => "/admits <id канала>",
        "/requests" => "/requests <id канала> — кто просится (§10.4)",
        "/peeraddr" => {
            "/peeraddr <ключ владельца> <ip:порт> — когда маяка нет; ключ печатает /groups"
        }
        // `/channels` не существует: каналы показывает `/groups` — они
        // и есть группы со вторым профилем (§3.2).
        "/channels" => "/groups — каналы показываются там же, где группы",
        _ => return None,
    })
}

/// Системное время в миллисекундах — для срока выдачи (§6.3).
///
/// Здесь, а не у ядра: срок в команде **абсолютный**, и считает его тот,
/// кто её отдаёт, — ровно как это сделает клиент на телефоне. Часы ядра
/// для этого не годятся: §9.1 держит их входом для HLC, а не источником
/// значений для протокола.
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// Текст §15, который надо показать **заводящему** канал. `None` —
/// показывать нечего.
///
/// # Почему у канала по приглашению текста нет
///
/// **Поломка, найденная на стенде.** Здесь печатался
/// `channel_private_notice`, а он обращён к тому, кто **подписывается**:
/// «Впустить вас должен владелец, и он должен быть для этого на связи».
/// Владелец, заводящий свой канал, читал про то, что его самого должен
/// кто-то впустить.
///
/// Текста для этого действия в §15 нет — и выдумывать его здесь нельзя:
/// тексты живут в `proto` и связаны проверками со свойствами протокола
/// (§14). Отдача `Option` — способ не соврать молча: «текста нет» здесь
/// выражено типом, а не пустой строкой.
///
/// У открытого канала текст есть и заводящему он нужен: ключ чтения
/// уедет в ссылку, и **закрыть доступ обратно нельзя никогда**.
fn creation_notice(open: bool) -> Option<&'static str> {
    open.then(ratatosk_proto::channel::OpenChannelConsequences::ui_text)
}

/// Текст §15 тому, кто **подписывается** по ссылке, — до подписки.
///
/// Оба здесь на месте: открытому каналу человек должен знать, что ключ
/// лежит в ссылке и раздаётся дальше вместе с ней; каналу по приглашению
/// — что его должен впустить владелец, и до тех пор канал не откроется.
fn subscription_notice(open: bool) -> &'static str {
    if open {
        ratatosk_proto::channel::OpenChannelConsequences::ui_text()
    } else {
        ratatosk_proto::channel::PrivateChannelConsequences::ui_text()
    }
}

/// Разбирает ключ участника из шестидесяти четырёх знаков hex.
fn decode_ik(text: &str) -> Option<[u8; 32]> {
    let raw = data_encoding::HEXLOWER.decode(text.trim().as_bytes()).ok()?;
    let mut ik = [0u8; 32];
    if raw.len() != 32 {
        return None;
    }
    ik.copy_from_slice(&raw);
    Some(ik)
}

/// Разбирает набор прав из букв: `w` писать, `a` впускать, `e` исключать,
/// `d` править. Прочерк — снять всё.
///
/// Незнакомая буква — отказ, а не пропуск: набрав `/right ... wx 30`,
/// человек имел в виду что-то, и молча выдать ему одно `w` значило бы
/// выдать не то, о чём он просил.
fn decode_rights(text: &str) -> Option<u32> {
    use ratatosk_proto::channel::Rights;

    if text == "-" {
        return Some(0);
    }
    if text.is_empty() {
        return None;
    }
    let mut rights = Rights::none();
    for letter in text.chars() {
        rights = match letter {
            'w' => rights.with(Rights::WRITE),
            'a' => rights.with(Rights::ADMIT),
            'e' => rights.with(Rights::EVICT),
            'd' => rights.with(Rights::EDIT),
            _ => return None,
        };
    }
    Some(rights.bits())
}

/// Выдачи прав канала (§6.2, §6.3).
async fn show_grants(handle: &DriverHandle, chat: [u8; 16]) {
    let Some(grants) = handle.channel_grants(chat).await else {
        println!("< драйвер остановлен");
        return;
    };
    if grants.is_empty() {
        println!("< выдач нет — или представление канала ещё не приехало");
        return;
    }
    for grant in grants {
        // «Истекла» печатается словом: строка остаётся в документе
        // до следующей версии (§6.2), и молчаливый пропуск истёкших
        // спрятал бы от хозяина стенда ровно то, что §6.3 велит показать.
        println!(
            "< {} {} [{}] до {}{}",
            data_encoding::HEXLOWER.encode(&grant.who),
            grant.name,
            rights_letters(grant.rights),
            grant.until_ms,
            if grant.live { "" } else { "  (истекла)" }
        );
    }
}

/// Заявки на подписку (§10.4).
async fn show_requests(handle: &DriverHandle, chat: [u8; 16]) {
    let Some(requests) = handle.channel_requests(chat).await else {
        println!("< драйвер остановлен");
        return;
    };
    if requests.is_empty() {
        println!("< заявок нет");
        return;
    }
    for request in requests {
        // Ключ целиком: им и впускают.
        println!(
            "< {} {} просится с {}\n    впустить: /admit {} {}",
            data_encoding::HEXLOWER.encode(&request.who),
            request.name,
            request.received_ms,
            data_encoding::HEXLOWER.encode(&chat),
            data_encoding::HEXLOWER.encode(&request.who),
        );
    }
}

/// Учёт впусков (§6.5).
async fn show_admits(handle: &DriverHandle, chat: [u8; 16]) {
    let Some(admits) = handle.channel_admits(chat).await else {
        println!("< драйвер остановлен");
        return;
    };
    if admits.is_empty() {
        println!("< впусков нет");
        return;
    }
    for admit in admits {
        println!(
            "< {} {} впущен {} на поколении {}",
            data_encoding::HEXLOWER.encode(&admit.who),
            admit.name,
            admit.admitted_by_name,
            admit.generation
        );
    }
}

/// Биты прав обратно в буквы — теми же, какими их набирают.
fn rights_letters(bits: u32) -> String {
    use ratatosk_proto::channel::Rights;

    let rights = Rights::from_bits(bits);
    let mut letters = String::new();
    for (right, letter) in
        [(Rights::WRITE, 'w'), (Rights::ADMIT, 'a'), (Rights::EVICT, 'e'), (Rights::EDIT, 'd')]
    {
        if rights.has(right) {
            letters.push(letter);
        }
    }
    if letters.is_empty() {
        letters.push('-');
    }
    letters
}

async fn show_groups(handle: &DriverHandle) {
    let Some(groups) = handle.groups().await else {
        println!("< драйвер остановлен");
        return;
    };
    if groups.is_empty() {
        println!("< ни групп, ни каналов: /newgroup <название> либо /newchannel <open|invite> <название>");
        return;
    }
    for group in groups {
        // Идентификатор целиком: им открывают чат, и обрезанный пришлось бы
        // искать глазами по журналу — тем же приёмом, что у устройств.
        // «Вышли» печатается отдельно от «создана здесь»: это два разных
        // факта, и после выхода создателя верны оба сразу.
        println!(
            "< {} «{}»{}{}",
            data_encoding::HEXLOWER.encode(&group.chat),
            group.title,
            if group.mine { ", создана здесь" } else { "" },
            if group.joined { "" } else { ", вы вышли" }
        );
        // Метка, а не «да/нет»: по ней на стенде видно, что смена картинки
        // доехала, — при одном и том же «есть» она обязана меняться.
        if group.avatar_ms != 0 {
            println!("    аватарка есть, метка {}", group.avatar_ms);
        }
        // Канальное — отдельной строкой и только у канала: у группы
        // этих вопросов нет вовсе (§3.2).
        if let Some(channel) = &group.channel {
            // **Ключ владельца — целиком.** Им адресуется `/peeraddr`,
            // когда маяка нет, и по нему человек отличает свой канал
            // от чужого. У читателя владельца в составе не будет вовсе
            // (§3.2), так что взять его больше неоткуда.
            println!("    владелец: {}", data_encoding::HEXLOWER.encode(&channel.owner_ik));
            println!(
                "    канал {}, версия {}, права [{}], цена {} бит, поколение {}{}{}{}",
                match channel.open {
                    Some(true) => "открытый",
                    Some(false) => "по приглашению",
                    // Документа ещё нет: порода известна только
                    // из ссылки, а ссылка ничем не подписана (§10.2).
                    None => "породы пока не знаем",
                },
                channel.version,
                rights_letters(channel.rights),
                channel.pow_bits,
                channel.generation,
                if channel.readable { "" } else { ", читать нечем" },
                if channel.awaiting { ", ждём впуска" } else { "" },
                if channel.may_rotate { ", ключ можно повернуть" } else { "" },
            );
            // **Признак §15 — первой строкой после шапки канала.**
            // Живой прогон сказал прямо: «вроде каналы работают,
            // но не всегда, и понимать в чём дело — полезно». Без этой
            // строки «ещё едет» и «брать не у кого» на стенде выглядят
            // одинаково — пустым каналом.
            let signal = channel.signal();
            if signal != ratatosk_proto::channel::Signal::Fine {
                println!("    почему тихо: {}", signal.ui_text());
                // Числа рядом со словами: слова объясняют, числа дают
                // разбирать. «Источников 0, в каталоге 2» — это уже
                // не жалоба, а то, с чем можно идти к `/seeds`.
                println!(
                    "    источников {}, в каталоге {}, ждём блоков {}",
                    match channel.sources_now {
                        Some(count) => count.to_string(),
                        // Свой канал: считать нечего, и ноль здесь
                        // соврал бы про «никто не отдаёт».
                        None => "— (канал наш)".to_owned(),
                    },
                    channel.seeds_known,
                    channel.awaiting_blocks,
                );
            }
            // §6.3: факт, а не вывод. «От владельца ничего не приходило»
            // — это про наш приём, а не про то, где владелец.
            if channel.owner_unseen {
                if let Some(quiet) = channel.owner_quiet_ms {
                    println!("    от владельца ничего не приходило {} суток", quiet / 86_400_000);
                }
            }
            if channel.grants_expiring != 0 {
                println!(
                    "    выдач истекает меньше чем через месяц: {} — продлите заранее",
                    channel.grants_expiring
                );
            }
        }
        for member in &group.members {
            // Ключ целиком: им исключают (`/evict`), и обрезанный пришлось бы
            // искать глазами по журналу — то же правило, что у устройств.
            // Рядом — имя и пометка «вы»: без неё хозяин стенда искал бы
            // себя в составе по ключу, как это делал клиент.
            println!(
                "    {} {}{}",
                data_encoding::HEXLOWER.encode(&member.ik),
                member.name,
                if member.mine { "  (вы)" } else { "" }
            );
        }
    }
}

/// Печатает каталог раздающих канал (§7.5).
///
/// Пока дерева раздачи (§7.1) нет, каталог ничего не доставляет — он
/// собирается. Показывать его всё равно надо: иначе «вызвался раздавать»
/// не отличить от «ничего не произошло», а разбирать потом нечем.
async fn show_seeds(handle: &DriverHandle, chat: [u8; 16]) {
    let Some(seeds) = handle.channel_seeds(chat).await else {
        println!("< драйвер остановлен");
        return;
    };
    if seeds.is_empty() {
        println!("< канал никто не раздаёт: /seed <id> on — объявить себя");
        return;
    }
    let now = wall_ms();
    for seed in seeds {
        let left = seed.valid_until_ms.saturating_sub(now) / (24 * 60 * 60 * 1000);
        // Ключ целиком: им называют адрес (`/peeraddr`), если до сида
        // не достучаться.
        println!(
            "< {} — раздаёт, годно ещё {left} сут{}",
            data_encoding::HEXLOWER.encode(&seed.ik),
            if seed.verified {
                ""
            } else {
                ", подпись не проверена (карточки нет)"
            }
        );
    }
}

/// Печатает пиров-не-контактов (§8.3) — третий вид записи за сессией.
///
/// **Без этой команды стенда их не видно вовсе.** Незнакомец, пожавший
/// руку, контактом больше не становится: он в `/who` не появится, а если
/// попросился в канал — виден только строкой заявки. Разбирать «почему
/// заявка не едет» тогда нечем: ни адресов, ни лестницы §5.4.
async fn show_peers(handle: &DriverHandle, directory: &LanDirectory) {
    let Some(peers) = handle.peers().await else {
        println!("< драйвер остановлен");
        return;
    };
    if peers.is_empty() {
        println!("< пиров нет: ими становятся владелец канала из ссылки и пожавший руку");
        return;
    }
    for peer in peers {
        let why = match peer.known_as {
            ratatosk_store::PEER_CHANNEL_OWNER => "владелец канала (из ссылки)",
            ratatosk_store::PEER_STRANGER => "пожал руку",
            _ => "неизвестно почему",
        };
        // Ключ целиком: им впускают (`/admit`) и им же называют адрес
        // (`/peeraddr`), а обрезанный пришлось бы искать глазами.
        println!("< {} — {why}", data_encoding::HEXLOWER.encode(&peer.ik));
        println!(
            "    карточка: {}, узнан: {} мс",
            if peer.has_card {
                "есть"
            } else {
                "нет — только адреса из ссылки"
            },
            peer.added_ms
        );
        let seen = match directory.get(&peer.ik) {
            Some(addr) => format!("{addr}"),
            None => "адреса нет — /peeraddr".to_owned(),
        };
        println!("    LAN: {seen}");
        // Вердикт лестницы — тот же, что у контакта, и считает его ядро:
        // разбор «почему не едет» у пира и у контакта обязан отвечать
        // одинаково, потому что путь у них один (§5.4).
        match (peer.reachability.route(), peer.reachability.rising()) {
            (Some(via), _) => println!("    → §5.4: пойдёт {}", via_name(via)),
            (None, Some(via)) => {
                println!("    → §5.4: {} ещё поднимается", via_name(via));
            }
            (None, None) => println!("    → §5.4: отправлять некуда — назовите адрес"),
        }
    }
}

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
        // Адрес в справочнике выше — это **локальная сеть**: маяк или
        // вписанное руками. А это — про другой город: назвал ли десктоп
        // свой onion в рукопожатии. Две разные достижимости, и путать
        // их при разборе «не подключается» — терять полдня.
        if device.reachable_anywhere {
            println!("    свой onion назвал — дозвонимся и вне общей сети");
        } else {
            println!("    onion не назвал — только общая сеть");
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
        // **Ключ целиком**, а не только начало в первой строке. Им
        // адресуются `/invite`, `/evict`, `/admit` и `/right`, и все
        // четыре требуют шестидесяти четырёх знаков — то же правило,
        // по которому `/groups` печатает ключи участников целиком.
        //
        // Пока его здесь не было, подсказки этих команд («ключ печатает
        // /who») говорили неправду: в списке стояло начало из двенадцати
        // знаков, и взять недостающее было негде. Поймано на стенде —
        // «ничего из /who не подходит».
        println!("    ключ: {}", data_encoding::HEXLOWER.encode(&contact.peer_ik));

        // **Рядом ли он прямо сейчас** — отдельной строкой и первой
        // из адресных, потому что это самый частый вопрос к списку.
        // Признак живёт сроком (`PRESENCE_TTL_MS`): полторы минуты тишины,
        // и он гаснет сам. Строки нет вовсе, когда никого рядом нет, —
        // «не рядом» у каждого второго контакта было бы шумом.
        let near: Vec<&str> = [
            contact.availability.seen_on_lan.then_some("локальная сеть"),
            contact.availability.seen_on_bt.then_some("эфир"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !near.is_empty() {
            println!("    рядом: {}", near.join(", "));
        }

        println!("    добавлен: {} мс, карточка версии {}", contact.added_ms, contact.card_version);
        if let Some(onion) = &contact.onion {
            println!("    onion-адрес: {onion}");
        }
        if let Some(chatmail) = &contact.chatmail {
            println!("    почта: {chatmail}");
        }
        // Ключ меша печатается **адресом**, а не байтами: байты человек
        // сверять не станет, а по адресу он и пингует, и смотрит
        // в `yggdrasilctl getPeers`. Пустой ключ не печатается вовсе —
        // это обычное состояние, а не беда, и строка «меша нет» у каждого
        // второго контакта была бы шумом.
        if let Some(key) = contact.ygg.as_ref().and_then(|k| <[u8; 32]>::try_from(&k[..]).ok()) {
            println!("    ygg-адрес: {}", ygg::address_text(&key));
        }
        // Куда уедет событие, когда §5.4 выберет nostr. Печатается только
        // когда реле названы: пустой список — обычное состояние (старая
        // карточка, выключенная у собеседника ступень), и строка о нём
        // у каждого второго контакта была бы шумом. А вот когда ступень
        // «годна», а сообщение не дошло, разбор начинается именно отсюда:
        // на своё реле мы бы положили ровно то же событие, и оно бы так же
        // легло — только читать его было бы некому.
        if !contact.nostr_relays.is_empty() {
            println!("    реле nostr (куда класть): {}", contact.nostr_relays.join(", "));
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
                ratatosk_proto::Transport::Bt => "bt   ",
                ratatosk_proto::Transport::Ygg => "ygg  ",
                ratatosk_proto::Transport::Onion => "onion",
                ratatosk_proto::Transport::Nostr => "nostr",
                ratatosk_proto::Transport::Mail => "почта",
            };
            let tail = if rung.transport == ratatosk_proto::Transport::Lan {
                format!("  адрес: {addr}")
            } else if rung.transport == ratatosk_proto::Transport::Ygg && !rung.addressable {
                // Самая частая беда ступени, и по одному «нет» её
                // не отличить от «мы забыли адрес»: у меша забывать нечего,
                // ключ либо приехал в карточке, либо нет.
                "  — ключа нет в его карточке".to_owned()
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
        ratatosk_proto::Transport::Bt => "по Bluetooth",
        ratatosk_proto::Transport::Ygg => "через меш",
        ratatosk_proto::Transport::Onion => "через onion",
        ratatosk_proto::Transport::Nostr => "через реле nostr",
        ratatosk_proto::Transport::Mail => "почтой",
    }
}

/// Метка длинного текста стенда.
///
/// Нужна затем, чтобы принятый текст **проверялся**, а не читался глазами:
/// в восьми килобайтах обрыв не виден, а по метке он находится сразу.
const LONG_MARK: &str = "RK-LONG";

/// Собирает текст ровно такой длины в байтах, по которому видно обрыв.
///
/// # Почему только ASCII
///
/// Потому что весь вопрос здесь — «сколько байт доехало». Возьми мы
/// кириллицу, длина в символах разошлась бы с длиной в байтах вдвое,
/// и диагностика сама вносила бы ту путаницу, которую призвана разрешить.
///
/// # Устройство
///
/// Голова и хвост несут **объявленную длину**, между ними — нумерованные
/// блоки по девять байт. Обрыв поэтому и виден, и локализуется: хвоста нет,
/// а последний целый блок называет своё место.
/// Как звать замер, если позвали неправильно.
const PROBE_USAGE: &str = "\
< нужно: /probe <s|m|l> [сколько] — класс кадра и сколько их послать
    s — 4 КиБ, m — 64 КиБ, l — мебибайт; без числа берётся разумное
    /probe без слов печатает итог начатого замера";

/// Больше этого за один замер не шлём: цифры от этого точнее не станут,
/// а эфир занят будет надолго.
const PROBE_MAX: usize = 100;

/// Замер эфира: сколько кадров такого класса доехало и за какое время.
///
/// # Зачем он вообще нужен
///
/// Про кадры в эфире у нас были **впечатления**, а не числа: «класс S
/// доходит всегда», «M иногда теряется», «L никогда». Решение же от них
/// зависит прямое — каким классом возить чанки файлов (§10.2) и стоит ли
/// заводить четвёртый класс между S и M. Впечатление «иногда» годится
/// для разговора и не годится для правки протокола.
///
/// Считает он **доставленные**, и это не выбор из удобства: квитанция
/// (§9.4) означает, что кадр расшифровался на той стороне, то есть доехал
/// целым. Ничего точнее у отправителя нет и быть не может — испорченный
/// кадр молча отбрасывается получателем, и сказать о нём некому.
struct Probe {
    /// Какой класс меряем.
    class: ratatosk_proto::SizeClass,
    /// Сколько послали.
    count: usize,
    /// Сколько полезных байт в каждом.
    text_bytes: usize,
    /// Когда начали.
    started: std::time::Instant,
    /// Что услышали про каждое сообщение.
    seen: std::collections::BTreeMap<[u8; 16], DeliveryStatus>,
}

impl Probe {
    /// Сколько кадров слать, если человек не назвал число.
    ///
    /// У класса L своё: двадцать мебибайт по эфиру — это полчаса, и такой
    /// замер человек прервёт раньше, чем он кончится.
    fn default_count(class: ratatosk_proto::SizeClass) -> usize {
        match class {
            ratatosk_proto::SizeClass::L => 3,
            _ => 20,
        }
    }

    /// Заводит замер, подобрав длину текста под класс.
    ///
    /// Текст берётся **под завязку** класса: меряем худший случай, ради
    /// которого всё и затевалось. Класс пересчитывается той же арифметикой,
    /// что у ядра (`smallest_for`), и если он вышел другим — замер
    /// не заводится вовсе: инструмент, врущий о том, что померил, хуже
    /// отсутствующего.
    fn start(class: ratatosk_proto::SizeClass, count: usize) -> Option<Probe> {
        let text_bytes =
            class.max_payload().checked_sub(ratatosk_proto::files::ENVELOPE_RESERVE_BYTES)?;
        let with_envelope = text_bytes + ratatosk_proto::files::ENVELOPE_RESERVE_BYTES;
        if ratatosk_proto::SizeClass::smallest_for(with_envelope) != Some(class) {
            return None;
        }
        Some(Probe {
            class,
            count,
            text_bytes,
            started: std::time::Instant::now(),
            seen: std::collections::BTreeMap::new(),
        })
    }

    /// Говорит, что и сколько сейчас поедет.
    fn announce(&self) {
        println!(
            "< замер: {} кадров класса {:?}, полезных {} Б в каждом",
            self.count, self.class, self.text_bytes
        );
        // Ожидаемое время называется заранее, чтобы человек не гадал,
        // повис замер или просто идёт. Скорость — скромная из политики,
        // то есть настоящее время выйдет не больше названного.
        if let Some(speed) =
            ratatosk_proto::transport_policy::floor_bytes_per_sec(ratatosk_proto::Transport::Bt)
        {
            let seconds = self.count as u64 * self.class.frame_len() as u64 / speed;
            println!("    по эфиру это не дольше {seconds} с; итог — /probe");
        }
    }

    /// Запоминает новость о сообщении. Отдаёт `true`, когда дождались всех.
    fn note(&mut self, msg_id: [u8; 16], status: DeliveryStatus) -> bool {
        // Сообщения замера не отличить от прочих по событию, и различать
        // их незачем: пока замер идёт, стенд ничего другого не шлёт.
        // Зато `Delivered` не перетирается более поздним `Read`: нам важен
        // первый признак того, что кадр доехал.
        let slot = self.seen.entry(msg_id).or_insert(status);
        if matches!(status, DeliveryStatus::Delivered | DeliveryStatus::Read) {
            *slot = status;
        }
        self.delivered() >= self.count
    }

    /// Сколько доехало.
    fn delivered(&self) -> usize {
        self.seen
            .values()
            .filter(|status| matches!(status, DeliveryStatus::Delivered | DeliveryStatus::Read))
            .count()
    }

    /// Печатает итог: доля дошедших и полезная скорость.
    fn tally(&self) {
        let done = self.delivered();
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        println!("< замер {:?}: доехало {done} из {}, за {:.1} с", self.class, self.count, elapsed);
        // **Полезная скорость, а не «сколько байт прошло».** Кадр добивается
        // до размера класса (§7), и у короткого сообщения по эфиру едет
        // добивка. Считать надо то, ради чего ехали.
        let useful = done as f64 * self.text_bytes as f64 / elapsed;
        let onwire = done as f64 * self.class.frame_len() as f64 / elapsed;
        println!("    полезных {:.1} Б/с, всего в эфир {:.1} Б/с", useful, onwire);
        if done < self.count {
            println!("    недоехавшие могли и не потеряться: квитанция ещё в пути");
        }
    }
}

/// Класс кадра по слову человека.
fn probe_class(word: &str) -> Option<ratatosk_proto::SizeClass> {
    match word {
        "s" | "S" => Some(ratatosk_proto::SizeClass::S),
        "m" | "M" => Some(ratatosk_proto::SizeClass::M),
        "l" | "L" => Some(ratatosk_proto::SizeClass::L),
        _ => None,
    }
}

fn long_text(bytes: usize) -> String {
    let head = format!("{LONG_MARK}-{bytes}-start|");
    let tail = format!("|end-{bytes}-{LONG_MARK}");
    if bytes <= head.len() + tail.len() {
        // Столько разметка не занимает — отдаём просто нужную длину.
        // Проверять на такой длине нечего, но и врать про неё нечем.
        return "x".repeat(bytes);
    }
    let mut out = String::with_capacity(bytes);
    out.push_str(&head);
    let mut block = 1u32;
    while out.len() + tail.len() + 9 <= bytes {
        out.push_str(&format!("{block:08}|"));
        block += 1;
    }
    while out.len() + tail.len() < bytes {
        out.push('.');
    }
    out.push_str(&tail);
    out
}

/// Вердикт о принятом длинном тексте — или `None`, если он не наш.
///
/// Отдельной функцией, а не строкой на месте: это **проверка**, и у неё
/// должны быть свои проверки. Печатать её обязан приём, потому что
/// отправитель и так знает, что послал.
fn long_verdict(text: &str) -> Option<String> {
    let rest = text.strip_prefix(&format!("{LONG_MARK}-"))?;
    let declared: usize = rest.split_once("-start|")?.0.parse().ok()?;
    let whole = text.len() == declared && text.ends_with(&format!("|end-{declared}-{LONG_MARK}"));
    if whole {
        return Some(format!("длинный текст ЦЕЛ: {declared} Б"));
    }
    // Последний целый блок называет место обрыва. Без него «обрезан»
    // отвечает только на «да или нет», а спрашивают всегда «где».
    let last = text
        .rsplit('|')
        .find(|block| block.len() == 8 && block.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or("—");
    Some(format!(
        "длинный текст ОБРЕЗАН: {} Б из объявленных {declared}, последний целый блок {last}",
        text.len()
    ))
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
///
/// **Без приставки `/add`, и это разбор живой путаницы.** Карточка
/// печаталась готовой строкой `/add ratatosk:v0:…` — удобно копировать,
/// но в терминале такая строка неотличима от набранной команды. В логе
/// стенда это читалось как «контакт добавлен», хотя не добавлялось ничего:
/// человек дважды нажал `/card`, а `/who` отвечал «контактов нет», и оба
/// мы полчаса искали поломку в эфире. Вывод, который можно спутать
/// с вводом, — это не мелочь оформления.
async fn print_card(handle: &DriverHandle) {
    let Some(card) = handle.own_card().await else { return };
    println!();
    println!("< своя карточка, версия {}:", card.version);
    println!();
    println!("  {}", card.uri);
    println!();
    println!("  скопируйте её на другую машину и вставьте там после /add");
    if card.onion.is_empty() {
        println!("  onion в карточке нет — сперва /onion, потом копировать");
    } else {
        println!("  onion: {}", card.onion);
    }
    // Ключ меша печатается тем же видом, каким принимается (`--ygg`):
    // человек копирует его со стенда на стенд, и два разных написания
    // одного ключа стоили бы ему разбирательства на ровном месте.
    if card.ygg.is_empty() {
        println!("  меша в карточке нет: /ygg daemon с --ygg <64 знака> либо /ygg node");
    } else {
        let hex: String = card.ygg.iter().map(|b| format!("{b:02x}")).collect();
        println!("  ygg:   {hex}");
        // Адрес печатается рядом с ключом, и это не украшение: ключ
        // переносится руками, а сверять шестьдесят четыре знака глазами
        // человек не станет. Адрес короткий, и `yggdrasilctl getSelf`
        // показывает его тем же видом — одного взгляда хватает, чтобы
        // понять, тот ли ключ перенесли.
        match <[u8; 32]>::try_from(card.ygg.as_slice()) {
            Ok(key) => println!("         адрес {} — сверьте с getSelf", ygg::address_text(&key)),
            // Сюда не попасть: разбор карточки чужую длину отбрасывает.
            // Но молчать на невозможном хуже, чем сказать о нём.
            Err(_) => println!("         ключ не тридцати двух байт — адреса нет"),
        }
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
/// `/ygg …` — состояние меша, ступень §5.4, режим и пиры (0.2).
///
/// Слова разведены по назначению, и это стоило одной путаницы: `on`/`off`
/// переключают **ступень** (как `/tor on|off`), `mode` меняет **откуда
/// берётся меш**. Первая редакция звала выключением и то и другое, и
/// «выключить меш» означало разом две разные вещи.
async fn ygg_command(handle: &DriverHandle, rest: &str) {
    use ratatosk_proto::ygg::YggMode;

    let (word, tail) = match rest.split_once(char::is_whitespace) {
        Some((word, tail)) => (word, tail.trim()),
        None => (rest, ""),
    };

    match word {
        "" | "?" => ygg_show(handle).await,

        // Ступень §5.4 — тот же переключатель, что `/lan` и `/tor`.
        "on" | "off" => {
            let on = word == "on";
            // Включать нечего, пока нет имени: раннер откажет, и отказ
            // прочтётся как поломка. Сказать причину здесь дешевле.
            if on {
                match handle.own_card().await {
                    Some(card) if card.ygg.is_empty() => {
                        println!("< имени в меше нет — включать нечего");
                        println!("  /ygg mode node   — свой узел, имя он даст сам");
                        println!("  /ygg mode daemon — внешний демон, ключ из --ygg");
                        return;
                    }
                    None => {
                        println!("< ядро остановлено");
                        return;
                    }
                    Some(_) => {}
                }
            }
            handle
                .send(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Ygg,
                    enabled: on,
                })
                .await
                .ok();
            if on {
                // Спрашивается **после** команды, и ответ будет уже про
                // неё: команды и запросы идут у драйвера одной очередью,
                // и чтение не может обогнать запись.
                //
                // Прежде здесь стояло безусловное «меш включён». Оно
                // и обмануло: ступень не поднималась, а стенд рапортовал
                // успех, и разбираться приходилось по журналу.
                // **Ждём, а не спрашиваем сразу.** Свой узел меша
                // поднимается секунду-полторы: слушающий сокет, набор
                // пиров, первый обмен. Спросив мгновенно, стенд печатал
                // «включён, но не поднялся» ровно там, где через секунду
                // всё работало, — и разбирать это приходилось по журналу.
                // Поймано на живом узле в первую же минуту.
                let mut up = false;
                for _ in 0..20 {
                    up = handle.transports().await.is_some_and(|status| {
                        status.ready.contains(ratatosk_proto::Transport::Ygg)
                    });
                    if up {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                if up {
                    println!("< меш включён и работает — ступень между локальной сетью и onion");
                } else {
                    println!("< меш включён, но **не поднялся**");
                    println!("  причина — в журнале строкой выше: у демона там адрес, который");
                    println!("  пробовали, у своего узла — причина словами (чаще всего пиры)");
                }
            } else {
                println!("< ступень меша выключена");
                if handle.ygg_settings().await.map(|(mode, _)| mode) == Some(YggMode::Embedded) {
                    println!("  {}", ratatosk_core::honest::YGG_NODE_STOP_NOTICE);
                }
            }
        }

        "mode" => ygg_mode(handle, tail).await,

        // Пиры **добавляются**, а не заменяют список. Команда ядра
        // (`SetYggPeers`) заменяет — так и надо для настройки, у которой
        // один источник правды. А человек за консолью пишет пиров по одному
        // и ждёт, что они копятся: первая редакция отдавала его строку
        // ядру как есть, и второй `/ygg peer` молча стирал первый.
        "peer" => {
            let Some((_, mut peers)) = handle.ygg_settings().await else {
                println!("< ядро остановлено");
                return;
            };
            if tail == "clear" {
                peers.clear();
            } else if tail.is_empty() {
                println!("< /ygg peer <ссылки>   — добавить; /ygg peer clear — очистить");
                println!(
                    "  сейчас: {}",
                    if peers.is_empty() { "пусто".to_owned() } else { peers.join(" ") }
                );
                return;
            } else {
                for named in tail.split_whitespace() {
                    if peers.iter().any(|known| known.as_str() == named) {
                        println!("  уже есть: {named}");
                    } else {
                        peers.push(named.to_owned());
                    }
                }
            }
            let shown = if peers.is_empty() { "пусто".to_owned() } else { peers.join(" ") };
            handle.send(Command::SetYggPeers(peers)).await.ok();
            // Печатается **весь** список, а не число добавленных: «названо: 1»
            // читается как «добавлен один» и ровно так и обмануло.
            println!("< пиры: {shown}");
        }

        other => {
            println!("< не понял «{other}»");
            println!("  /ygg                    — что сейчас");
            println!("  /ygg on | off           — ступень §5.4");
            println!("  /ygg mode daemon|node|off — откуда берётся меш");
            println!("  /ygg peer <ссылки>      — добавить пиров своему узлу");
            println!("  /ygg peer clear         — очистить список");
        }
    }
}

/// Вложения ли это — по имени команды целиком.
///
/// Отдельной функцией, чтобы список имён стоял один раз: разбор ниже
/// узнаёт их по первому слову, и второй такой список разошёлся бы
/// с первым на первой же новой команде.
fn is_file_command(line: &str) -> bool {
    let head = line.split_whitespace().next().unwrap_or_default();
    matches!(head, "/file" | "/files" | "/accept" | "/pause" | "/decline" | "/save" | "/auto")
}

/// Вложения (§10) на стенде: отправить, принять, сохранить, сверить.
///
/// # Зачем стенду файлы
///
/// Затем же, зачем `/long`: проверять не «дошло ли вообще», а **что
/// именно дошло**. Файл — единственное, что ездит чанками (§10.2),
/// то есть с окном, подтверждениями и возобновлением после обрыва;
/// ни текст, ни лицо этой дороги не проходят. До этих команд её нельзя
/// было пройти руками вовсе.
///
/// Команд шесть, и все короткие:
///
/// * `/file <путь>` — отправить файл;
/// * `/files` — что за вложения в этом чате и сколько уже приехало;
/// * `/accept <id>`, `/pause <id>`, `/decline <id>` — судьба входящего;
/// * `/save <id> <путь>` — собрать принятое на диск и назвать сумму;
/// * `/auto [байт|off]` — порог автоприёма.
///
/// Идентификатор — тот же короткий вид, что печатает стенд (`/files`):
/// хватает префикса, полные тридцать два знака набирать не надо.
async fn file_command(handle: &DriverHandle, line: &str, peer: Option<[u8; 32]>) {
    let mut words = line.split_whitespace();
    let command = words.next().unwrap_or_default();
    let rest: Vec<&str> = words.collect();

    // Порог автоприёма чата не требует: он один на все.
    if command == "/auto" {
        let limit = match rest.first().copied() {
            None => {
                // Без довода — показать, что стоит сейчас. Порог живёт
                // в ядре и переживает перезапуск, так что помнить его
                // стенду нечем и незачем.
                match handle.auto_accept().await {
                    Some(Some(bytes)) => println!("< автоприём до {bytes} Б; крупнее — спросим"),
                    Some(None) => println!("< автоприёма нет: каждый файл спрашиваем"),
                    None => println!("< ядро остановлено"),
                }
                println!("    поменять: /auto <байт> либо /auto off");
                return;
            }
            Some("off") => None,
            Some(number) => match number.parse::<u64>() {
                Ok(bytes) => Some(bytes),
                Err(_) => {
                    println!("< нужно число байт либо off");
                    return;
                }
            },
        };
        if handle.send(Command::SetAutoAcceptBytes(limit)).await.is_ok() {
            match limit {
                Some(bytes) => println!("< автоприём до {bytes} Б; крупнее — спросим"),
                None => println!("< автоприёма нет: каждый файл спрашиваем"),
            }
        }
        return;
    }

    let Some(ik) = peer else {
        println!("< некому: сперва /add <карточка>");
        return;
    };
    let chat = Engine::<MemoryStore>::chat_id_for(&ik);

    if command == "/file" {
        let Some(path) = rest.first() else {
            println!("< /file <путь к файлу>");
            return;
        };
        let path = std::path::PathBuf::from(path);
        // Сумма считается **до** отправки и печатается сразу: сверять
        // её потом не с чем, если не знать, что отправляли.
        match std::fs::read(&path) {
            Ok(bytes) => {
                println!("< шлём файл: {} Б, сумма {}", bytes.len(), sum_of(&bytes));
                println!("    ход передачи — строками «файл …: принято/всего»");
            }
            Err(error) => {
                println!("< файла не прочесть: {error}");
                return;
            }
        }
        // Превью стенд не готовит: §10.3 велит делать его клиенту,
        // а декодер изображений в процессе с ключами — большая
        // поверхность атаки. Без превью собеседник решает по имени
        // и размеру, и для стенда это честнее, чем картинка,
        // собранная лишь бы была.
        let files = vec![ratatosk_core::OutgoingFile { path, preview: None }];
        if handle.send(Command::SendFiles { chat, files, text: String::new() }).await.is_err() {
            println!("< ядро остановлено");
        }
        return;
    }

    // Всё остальное работает с уже известным вложением.
    let known = files_of(handle, chat).await;
    if command == "/files" {
        if known.is_empty() {
            println!("< вложений в этом чате нет");
            return;
        }
        for view in &known {
            let file = &view.file;
            let done = if view.received_chunks >= file.chunk_total {
                "целиком"
            } else {
                "качается"
            };
            println!(
                "< {} {} — {} Б, чанков {}/{} ({done})",
                short(&file.file_id),
                file.name,
                file.size_bytes,
                view.received_chunks,
                file.chunk_total
            );
        }
        println!("    принять: /accept <id>   сохранить: /save <id> <путь>");
        return;
    }

    let Some(prefix) = rest.first().copied() else {
        println!("< нужен идентификатор вложения — посмотрите /files");
        return;
    };
    let Some(view) = pick_file(&known, prefix) else {
        println!("< такого вложения в чате нет: /files покажет, какие есть");
        return;
    };
    let file_id = view.file.file_id;

    match command {
        "/accept" => {
            if handle.send(Command::AcceptFile { file_id }).await.is_ok() {
                println!("< принимаем {}", short(&file_id));
            }
        }
        // Пауза и отказ различаются тем, что остаётся, и стенд обязан
        // это проговаривать: у человека в руках две кнопки, и одна
        // из них необратима.
        "/pause" => {
            if handle.send(Command::PauseFile { file_id }).await.is_ok() {
                println!("< приостановлено; /accept продолжит с той же дырки");
            }
        }
        "/decline" => {
            if handle.send(Command::DeclineFile { file_id }).await.is_ok() {
                println!("< отказано; принятые куски удалены");
            }
        }
        "/save" => {
            let Some(target) = rest.get(1) else {
                println!("< /save <id> <путь>");
                return;
            };
            save_file(handle, file_id, std::path::PathBuf::from(target)).await;
        }
        other => println!("< не понял «{other}»"),
    }
}

/// Вложения чата — все, какие знает ядро.
///
/// Спрашиваются вместе с сообщениями: отдельного запроса «дай файлы чата»
/// у драйвера нет, и заводить его ради стенда незачем — окна в двадцать
/// сообщений хватает на любую проверку руками.
async fn files_of(handle: &DriverHandle, chat: ratatosk_core::ChatId) -> Vec<FileView> {
    let Some(messages) = handle.messages(chat, 20).await else {
        return Vec::new();
    };
    messages.into_iter().flat_map(|view| view.files).collect()
}

/// Находит вложение по началу идентификатора.
///
/// Совпадение обязано быть **единственным**: два файла с общим префиксом
/// — редкость, но «взяли первый попавшийся» в стенде для проверки файлов
/// было бы ошибкой ровно того рода, которую он ищет.
fn pick_file<'a>(known: &'a [FileView], prefix: &str) -> Option<&'a FileView> {
    let prefix = prefix.trim().to_lowercase();
    let mut found = known
        .iter()
        .filter(|view| data_encoding::HEXLOWER.encode(&view.file.file_id).starts_with(&prefix));
    let first = found.next()?;
    match found.next() {
        None => Some(first),
        Some(_) => {
            println!("< таких вложений несколько — назовите больше знаков");
            None
        }
    }
}

/// Собирает принятое вложение на диск и называет его сумму.
///
/// **Ради этой функции всё и затевалось.** «Файл принят» без сборки
/// проверяет только счётчик чанков; целость содержимого проверяет сумма,
/// сверенная с той, что напечатал отправитель.
///
/// Чтение уезжает в `spawn_blocking`: чанки читаются с диска и
/// расшифровываются, и делать это в цикле рантайма значило бы держать
/// стенд неотзывчивым всё время сборки.
async fn save_file(handle: &DriverHandle, file_id: [u8; 16], target: std::path::PathBuf) {
    let Some(reader) = handle.open_file(file_id).await else {
        println!("< ядро остановлено");
        return;
    };
    let Some(reader) = reader else {
        println!("< такого вложения ядро не знает");
        return;
    };

    let done = tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        for index in 0..reader.chunk_total() {
            match reader.chunk(index) {
                Ok(Some(chunk)) => bytes.extend_from_slice(&chunk),
                // Дырка в середине — обычное состояние недокачанного
                // файла, и говорить о ней надо номером: по нему видно,
                // докуда дошло.
                Ok(None) => return Err(format!("чанка {index} ещё нет — файл не целиком")),
                Err(error) => return Err(format!("чанк {index} не читается: {error}")),
            }
        }
        std::fs::write(&target, &bytes).map_err(|error| format!("не записать: {error}"))?;
        Ok((target, bytes.len(), sum_of(&bytes)))
    })
    .await;

    match done {
        Ok(Ok((path, len, sum))) => {
            println!("< сохранено: {} Б, сумма {sum}", len);
            println!("    {}", path.display());
            println!("    сверьте сумму с той, что напечатал отправитель");
        }
        Ok(Err(why)) => println!("< не собрали: {why}"),
        Err(_) => println!("< сборка упала"),
    }
}

/// Контрольная сумма для сверки глазами — начало BLAKE3.
///
/// Восьми байт хватает: сверяет их человек, а не протокол, и защищаться
/// ею не от кого — обе стороны свои. Полные тридцать два байта человек
/// сверять не станет, а не сверенная сумма не значит ничего.
fn sum_of(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&blake3::hash(bytes).as_bytes()[..8])
}

/// `/bt` — шестая ступень: эфир Bluetooth (0.4).
///
/// Настраивать здесь нечего, и это не упущение: ступень адресуется эфиром,
/// а не карточкой. Поэтому команд всего три — посмотреть, включить,
/// выключить.
///
/// `/bt on` включает ступень §5.4; радио при этом поднимается не сразу —
/// сессия D-Bus, адаптер, сокет и объявление занимают доли секунды,
/// и до конца этого ступень честно «не поднята». Смотреть исход надо
/// повторным `/bt`, а не по тому, что команда вернулась.
async fn bt_command(handle: &DriverHandle, rest: &str) {
    match rest.split_whitespace().next() {
        None => bt_show(handle).await,
        Some(word @ ("on" | "off")) => {
            let enabled = word == "on";
            let sent = handle
                .send(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Bt,
                    enabled,
                })
                .await;
            if sent.is_ok() {
                if enabled {
                    // Цена — **до** включения, как у меша и у nostr (§14).
                    // Здесь она не про приватность графа, а про заряд
                    // и про разрешения на телефоне.
                    println!(
                        "< эфир стоит заряда постоянно: объявлять себя и слушать надо всё                          время, а не в момент отправки"
                    );
                }
                bt_show(handle).await;
            }
        }
        Some(other) => println!("< не понял «{other}»: /bt [on|off]"),
    }
}

/// `/bt` без доводов — что со ступенью прямо сейчас.
async fn bt_show(handle: &DriverHandle) {
    if !BT_BUILT_IN {
        // Первой строкой и до всего остального: без раннера включать
        // нечего, а выглядит это как ступень, которая молчит.
        println!("< ВНИМАНИЕ: эфира нет в этой сборке — пересоберите с --features bt");
        println!("  ступень ниже включается, но радио поднимать некому");
    }
    let Some(status) = handle.transports().await else {
        println!("< ядро остановлено");
        return;
    };
    let transport = ratatosk_proto::Transport::Bt;
    println!(
        "< bluetooth: включена={} работает={}",
        yes(status.enabled.contains(transport)),
        yes(status.ready.contains(transport))
    );
    if status.enabled.contains(transport) && !status.ready.contains(transport) {
        // Три разные беды выглядят одинаково — «не поднята», — и
        // различить их можно только журналом: он называет причину
        // словами чужого крейта.
        println!("  радио ещё не поднялось или не поднялось вовсе:");
        println!("  адаптер выключен? `bluetoothctl show` и `rfkill list`");
        println!("  причина пишется в журнал строкой «эфир не поднялся»");
    }
    println!("  адрес в карточке ступени не нужен: собеседника слышно или нет — /who");
    println!("  файлы ездят: объёмный кадр идёт своим каналом (0.4.4)");
    println!("  слышно становится не сразу: объявление ловится секундами, а не мгновенно");
}

/// `/nostr` — состояние ступени и её настройка (0.3).
///
/// Без доводов печатает всё разом; с доводами настраивает:
///
/// * `/nostr on` и `/nostr off` — переключатель ступени §5.4;
/// * `/nostr relays <адрес> [<адрес>…]` — список реле целиком;
/// * `/nostr direct on|off` — ходить ли мимо Tor.
///
/// Список **заменяется целиком**, а не дополняется: так же устроен `/ygg
/// peers`, и так же он устроен в настройках у человека. Добавление по одному
/// потребовало бы удаления по одному, то есть второй команды и второго
/// способа ошибиться.
async fn nostr_command(handle: &DriverHandle, rest: &str) {
    let mut words = rest.split_whitespace();
    match words.next() {
        None => nostr_show(handle).await,
        Some("on") | Some("off") => {
            let enabled = rest.starts_with("on");
            let sent = handle
                .send(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Nostr,
                    enabled,
                })
                .await;
            if sent.is_ok() {
                // Цена называется **до** переключения, как велит §14
                // и как это сделано у меша. Стенд — тоже клиент.
                if enabled {
                    println!("< {}", ratatosk_core::honest::NOSTR_WARNING);
                }
                nostr_show(handle).await;
            }
        }
        Some("direct") => {
            let direct = words.next() == Some("on");
            if direct {
                println!("< {}", ratatosk_core::honest::NOSTR_DIRECT_WARNING);
            }
            if handle.send(Command::SetNostrDirect(direct)).await.is_ok() {
                nostr_show(handle).await;
            }
        }
        Some("relays") => {
            let relays: Vec<String> = words.map(str::to_owned).collect();
            if handle.send(Command::SetNostrRelays(relays)).await.is_ok() {
                // Негодные адреса ядро отбрасывает и говорит об этом
                // в журнал; печать состава ниже покажет, что уцелело.
                nostr_show(handle).await;
            }
        }
        Some(other) => {
            println!("< не понял «{other}»: /nostr [on|off|direct on|off|relays <адрес>…]");
        }
    }
}

/// `/nostr` без доводов — всё про ступень одним экраном.
///
/// Порознь эти строки не значат ничего: «ступень включена» без реле и «реле
/// названы» без ключа одинаково выглядят как работающая ступень.
async fn nostr_show(handle: &DriverHandle) {
    let Some((relays, direct)) = handle.nostr_settings().await else {
        println!("< ядро остановлено");
        return;
    };
    println!("< nostr: путь {}", if direct { "напрямую, мимо Tor" } else { "через Tor" });
    if !NOSTR_BUILT_IN {
        // Первой строкой и до всего остального: без раннера настройка
        // ложится на диск и не делает ничего, а выглядит это как рабочая
        // ступень, которая почему-то молчит.
        println!("  ВНИМАНИЕ: ступени нет в этой сборке — пересоберите с --features nostr");
        println!("  всё ниже — настройка на диске; соединяться с реле некому");
    }

    let card = handle.own_card().await;
    match &card {
        Some(card) if card.nostr.len() == ratatosk_proto::nostr::KEY_LEN => {
            match ratatosk_proto::nostr::NostrKey::from_slice(&card.nostr) {
                Some(key) => println!("  ключ:    {}", key.npub()),
                None => println!("  ключ:    в карточке лежит не ключ"),
            }
        }
        _ => println!("  ключа нет — ступень ни разу не включали"),
    }
    // Объявленное — это то, куда вам будут **класть**, а настроенное — то,
    // откуда вы **читаете**. Величины разные: в карточку уходят не все реле
    // (`MAX_CARD_RELAYS`), и расхождение между ними — ровно то, что стоит
    // видеть глазами, а не выяснять по молчанию.
    let advertised: Vec<String> = card.map(|card| card.nostr_relays).unwrap_or_default();

    let mut alive = None;
    if let Some(status) = handle.transports().await {
        let transport = ratatosk_proto::Transport::Nostr;
        alive = status.nostr_relays;
        println!(
            "  ступень: включена={} работает={}",
            yes(status.enabled.contains(transport)),
            yes(status.ready.contains(transport))
        );
    }

    if relays.is_empty() {
        println!("  реле не названы — ступень работать не может");
        println!("  назовите: /nostr relays ws://127.0.0.1:8080");
        return;
    }
    println!("  реле ({}):", relays.len());
    for url in &relays {
        // Живое состояние приезжает событием и может ещё не приехать —
        // это не то же, что «реле молчит», и путать их нельзя.
        let live = alive.as_ref().and_then(|list| list.iter().find(|r| r.url == *url));
        let mark =
            if advertised.iter().any(|named| named == url) { " [в карточке]" } else { "" };
        match live {
            Some(relay) if relay.up => println!("    {url} — отвечает{mark}"),
            Some(relay) if relay.note.is_empty() => println!("    {url} — не отвечает{mark}"),
            Some(relay) => println!("    {url} — не отвечает: {}{mark}", relay.note),
            None => println!("    {url} — ещё не пробовали{mark}"),
        }
    }
    if advertised.len() < relays.len() {
        println!(
            "  в карточке объявлены первые {} — только по ним до вас и дозвонятся (§4.3)",
            advertised.len()
        );
    }
}

/// `/ygg` — что сейчас с мешем, одним экраном.
///
/// Печатается всё разом: режим, имя, адрес, ступень и пиры. Порознь эти
/// строки не значат ничего — «ступень включена» без имени и «имя есть»
/// без пиров одинаково выглядят как работающий меш.
async fn ygg_show(handle: &DriverHandle) {
    use ratatosk_proto::ygg::YggMode;

    let Some((mode, peers)) = handle.ygg_settings().await else {
        println!("< ядро остановлено");
        return;
    };
    println!("< меш: {}", mode.title());
    match handle.own_card().await {
        Some(card) if card.ygg.len() == ygg::KEY_LEN => {
            let hex: String = card.ygg.iter().map(|b| format!("{b:02x}")).collect();
            println!("  ключ:  {hex}");
            if let Ok(key) = <[u8; ygg::KEY_LEN]>::try_from(&card.ygg[..]) {
                println!("  адрес: {}", ygg::address_text(&key));
            }
        }
        _ => println!("  имени в меше нет — ступень работать не может"),
    }
    let mut alive = None;
    if let Some(status) = handle.transports().await {
        let on = status.enabled.contains(ratatosk_proto::Transport::Ygg);
        let up = status.ready.contains(ratatosk_proto::Transport::Ygg);
        alive = status.ygg_peers;
        println!(
            "  ступень: включена={} работает={}",
            if on { "да" } else { "нет" },
            if up { "да" } else { "нет" }
        );
    }
    if mode == YggMode::Embedded {
        if peers.is_empty() {
            println!("  пиров нет: узел ни с кем не соединён");
            println!("  назвать: /ygg peer tcp://host:9001");
        } else {
            // Названо и живо — рядом, и это не украшение: порознь ни то,
            // ни другое не отвечает на «какой пир убрать». Мёртвый ищется
            // перебором, и число — единственный способ увидеть результат.
            match alive {
                // Живой состав называет всех — и мёртвых тоже, — поэтому
                // печатается он, а не названный список: там нет главного,
                // признака «работает».
                Some(live) if !live.is_empty() => {
                    println!("  пиры:");
                    for peer in live {
                        let mark =
                            if peer.up { "работает" } else { "не соединён" };
                        let side = if peer.inbound { " (входящий)" } else { "" };
                        println!("    {} — {mark}{side}, {:.0} мс", peer.uri, peer.latency_ms);
                    }
                }
                Some(_) => println!("  пиры: {} — узел ни с кем не соединён", peers.join(" ")),
                None => println!("  пиры: {} — узел ещё не поднят", peers.join(" ")),
            }
        }
        if !YGG_NODE_BUILT_IN {
            println!("  узла в этой сборке нет: пересоберите с --features ygg-node");
        }
    }
}

/// `/ygg mode …` — откуда берётся меш (0.2).
async fn ygg_mode(handle: &DriverHandle, tail: &str) {
    use ratatosk_proto::ygg::YggMode;

    let mode = match tail {
        "off" | "none" => YggMode::Off,
        "daemon" => YggMode::External,
        "node" => YggMode::Embedded,
        other => {
            println!("< не понял режим «{other}»: off | daemon | node");
            return;
        }
    };
    let was = handle.ygg_settings().await.map(|(mode, _)| mode);
    handle.send(Command::SetYggMode(mode)).await.ok();
    match mode {
        YggMode::Off => {
            println!("< меша нет — имя снято с карточки");
            if was == Some(YggMode::Embedded) {
                println!("  {}", ratatosk_core::honest::YGG_NODE_STOP_NOTICE);
            }
        }
        YggMode::External => {
            println!("< меш: внешний демон; имя — ключ, названный через --ygg");
            println!("  включить ступень: /ygg on");
        }
        YggMode::Embedded => {
            println!("< меш: свой узел; имя он назвал себе сам — смотрите /ygg");
            println!("  без пиров он ни с кем не соединён: /ygg peer tcp://host:9001");
            if !YGG_NODE_BUILT_IN {
                println!("  но в этой сборке узла нет: пересоберите с --features ygg-node");
            }
            println!("  включить ступень: /ygg on");
        }
    }
}

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
        Event::ContactAdded { peer_ik, fingerprint, verified, .. } => {
            let mark = if *verified { "сверен" } else { "НЕ сверен (§4.2)" };
            println!("< контакт добавлен, отпечаток {fingerprint}, {mark}");
            // **Ключ целиком и слово про адрес — здесь, а не «можно
            // писать».** Так приезжает незнакомец, пожавший руку: заявка
            // в канал (§10.4) приходит именно этим путём. Ответить ему
            // мы обязаны **своим** соединением (соединения односторонние,
            // `ARCHITECTURE.md` 5ц), а адреса его у нас может не быть
            // вовсе: в общей сети его даёт маяк §5.1, на одной машине
            // и в сети с зарезанным мультикастом — никто.
            //
            // Пойман на прогоне: у владельца появлялась эта строка,
            // и на том всё кончалось — заявка не приходила, потому что
            // рукопожатию нечем было ответить. Снаружи выглядело
            // как «дошло наполовину».
            println!("    ключ: {}", data_encoding::HEXLOWER.encode(peer_ik));
            println!(
                "    ответить можно, лишь зная его адрес: в общей сети его даёт маяк, \
                 иначе назовите сами — /peeraddr {} <ip:порт>",
                data_encoding::HEXLOWER.encode(peer_ik)
            );
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
        Event::OwnAvatarChanged => {
            // Сменить своё лицо может и сопряжённый десктоп: тогда эта
            // строка — единственный признак, что оно уже другое.
            println!("< своя аватарка сменилась");
        }
        Event::GroupCreated { chat, title } => {
            println!("< группа {} заведена: {title}", short(chat));
            // Полный идентификатор — по той же причине, что у канала ниже.
            println!("    пригласить: /invite {}", data_encoding::HEXLOWER.encode(chat));
        }
        Event::ChannelAdmitted { chat, who, admitted_by } => {
            println!(
                "< в канал {} впущен {}; впустил {}",
                short(chat),
                short(who),
                short(admitted_by)
            );
        }
        Event::ChannelKeyRotated { chat, generation } => {
            // **«Поколение», а не «повернулся».** Событие приходит и на
            // поворот, и на первую выдачу ключа впущенному — а у того
            // ничего не поворачивалось, он только что получил первое.
            // Читать «повернулся: поколение 0» человеку неоткуда.
            println!("< ключ чтения канала {}: поколение {generation}", short(chat));
        }
        Event::ChannelSubscribed { chat, awaiting } => {
            // Названия здесь нет: оно внутри представления, а его ещё
            // не привезли (§10.5).
            let what = if *awaiting { "ждём впуска" } else { "открытый" };
            println!("< подписались на канал {} ({what})", short(chat));
        }
        Event::ChannelRequested { chat, who } => {
            // Ключ целиком: им же и впускают (`/admit`), а обрезанный
            // пришлось бы искать глазами по журналу.
            println!(
                "< в канал {} просится {}\n    впустить: /admit {} {}",
                short(chat),
                short(who),
                data_encoding::HEXLOWER.encode(chat),
                data_encoding::HEXLOWER.encode(who),
            );
        }
        Event::SeedingChanged { chat, announced } => {
            if *announced {
                println!("< раздаём канал {} и объявили адрес — нас будут набирать", short(chat));
            } else {
                println!(
                    "< адрес в канале {} больше не объявляем; прежнее объявление \
                     погаснет к концу срока (§7.5)",
                    short(chat)
                );
            }
        }
        Event::ChannelHistoryEnd { chat } => {
            println!("< канал {}: глубже истории нет — спрошенные её не держат", short(chat));
        }
        Event::SeedAnnounced { chat, who } => {
            // Приходит владельцу: он и развозит каталог. Ключ целиком —
            // им же называют адрес (`/peeraddr`), если до сида не достучаться.
            println!(
                "< в канале {} вызвался раздавать {}\n    кто раздаёт: /seeds {}",
                short(chat),
                short(who),
                data_encoding::HEXLOWER.encode(chat),
            );
        }
        Event::ChannelUnsubscribed { chat } => {
            println!("< отписались от канала {}: ключи чтения стёрты", short(chat));
        }
        Event::ChannelChanged { chat, version, title } => {
            println!("< канал {} обновился до версии {version}: {title}", short(chat));
        }
        Event::ChannelCreated { chat, title, open } => {
            // Порода называется словом, а не флагом: §6.1 требует, чтобы
            // одно слово означало одну гарантию, и «open=true» ею не является.
            //
            // Породы может не быть вовсе: так приходит событие тому, кого
            // впустили, — вводный блок говорит «это канал», а порода живёт
            // в представлении и приедет следом.
            match open {
                Some(true) => println!("< канал {} заведён (открытый): {title}", short(chat)),
                Some(false) => {
                    println!("< канал {} заведён (по приглашению): {title}", short(chat));
                }
                None => println!("< канал {} появился: {title}", short(chat)),
            }
            // **Идентификатор целиком, готовой командой.** В первой строке
            // он обрезан — так его читают глазами, — а команды стенда
            // требуют все тридцать два знака и на обрезанный отвечают
            // «нужно: … — id печатает /groups». Пойман на собственном
            // прогоне: напечатанное только что нельзя скопировать
            // в следующую же команду.
            if open.is_some() {
                println!("    ссылка: /clink {}", data_encoding::HEXLOWER.encode(chat));
            }
        }
        Event::GroupMembershipChanged { chat } => {
            // **«Чат», а не «группа».** Событие общее: состав меняется
            // и у группы, и у канала (там — список читателей у владельца,
            // §3.2). Звать канал группой — тот же промах, что был
            // у «группа заведена» на вводном блоке.
            println!("< состав чата {} изменился", short(chat));
        }
        Event::GroupRenamed { chat, title } => {
            println!("< чат {} теперь называется: {title}", short(chat));
        }
        Event::GroupAvatarChanged { chat } => {
            // Байты в событии не едут — их спрашивают, когда рисуют.
            // Стенд не рисует ничего, поэтому печатает только факт;
            // «есть ли теперь картинка» видно по `/groups`.
            println!("< у чата {} сменилась аватарка", short(chat));
        }
        Event::FileProgress { file_id, received, total } => {
            println!("< файл {}: {received}/{total}", short(file_id));
        }
        // **Отдано, а не доставлено**, и слово выбрано нарочно. Знаем мы
        // ровно то, что кадр вручён транспорту; дошёл ли он — скажет
        // следующая просьба получателя, а не это число (§14).
        Event::FileSending { file_id, peer_ik, sent, total } => {
            println!("< файл {}: отдано {sent}/{total} → {}", short(file_id), short(peer_ik));
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
        Event::FileWaitsForChannel { file_id, reason } => {
            // Текст задан ядром и показывается дословно: «загрузка»
            // и «ошибка» здесь одинаково неправда.
            println!("< файл {}: {}", short(file_id), reason.text());
            // А рядом — короткое имя причины: его ищут глазами в выводе,
            // и ради него всё это и заведено. Один сеанс на устройствах
            // с такой строкой отвечает на вопрос, который два раза
            // пытались угадать.
            println!("    причина: {}", reason.label());
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
    // Подпись автора печатается там, где она пришла, — то есть в группе.
    // В переписке двоих её нет вовсе: имя собеседника и так стоит
    // в заголовке, и повторять его у каждой строки незачем.
    if let Some(author) = &message.author {
        out.push_str(&format!("{author}: "));
    }
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
    // Карточка человека — отдельной строкой, как вложение. Без неё
    // сообщение печаталось бы пустым: тело у него нарочно пустое.
    if let Some(shared) = &message.shared {
        out.push_str(&format!("\n<     [карточка] {}", shared.name));
        out.push_str(match shared.chat {
            // Знакомого добавлять незачем — и сказать об этом надо, иначе
            // `/add` выглядит командой, которая молча ничего не делает.
            Some(_) => "  (уже в контактах)",
            None => "  ← добавить: /add <номер строки>",
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kind_notice_goes_to_the_person_it_is_written_for() {
        // **Поломка, найденная на стенде.** Заведение канала печатало текст
        // §15 по породе — и у канала по приглашению это был
        // `channel_private_notice`, обращённый к тому, кто подписывается:
        // «Впустить вас должен владелец». Владелец, заводящий свой канал,
        // читал про то, что его самого должен кто-то впустить.
        assert_eq!(
            creation_notice(false),
            None,
            "заводящему канал по приглашению §15 не говорит ничего — и выдумывать нельзя"
        );
        assert_eq!(
            creation_notice(true),
            Some(ratatosk_proto::channel::OpenChannelConsequences::ui_text()),
            "а про открытый заводящему сказать надо: доступ обратно не закрыть"
        );

        // Подписывающемуся — оба, и каждый свой.
        assert_eq!(
            subscription_notice(false),
            ratatosk_proto::channel::PrivateChannelConsequences::ui_text()
        );
        assert_eq!(
            subscription_notice(true),
            ratatosk_proto::channel::OpenChannelConsequences::ui_text()
        );
        // И тексты эти **разные**: сойдись они, проверка выше зеленела бы
        // на пустом месте.
        assert_ne!(subscription_notice(false), subscription_notice(true));
    }

    #[test]
    fn a_channel_command_without_arguments_says_what_it_wants() {
        // Разборы ищут приставку **с пробелом**, и команда без аргументов
        // проваливалась в общий путь «строка без команды» — то есть уезжала
        // собеседнику текстом. Поймано на стенде: в чужом чате появились
        // строки `/channels` и `/clink`.
        for bare in [
            "/newchannel",
            "/clink",
            "/sub",
            "/unsub",
            "/admit",
            "/right",
            "/pow",
            "/rotate",
            "/grants",
            "/admits",
        ] {
            assert!(channel_usage(bare).is_some(), "{bare} без аргументов обязан подсказывать");
        }
        // `/channels` команды нет вовсе: каналы показывает `/groups`.
        assert!(channel_usage("/channels").is_some());
        // А команда **с** аргументами сюда не попадает: её разбирают ниже.
        assert!(channel_usage("/clink 76ee0a3d").is_none());
        assert!(channel_usage("обычное сообщение").is_none(), "текст человека — не команда");
    }

    #[test]
    fn rights_letters_survive_the_round_trip() {
        use ratatosk_proto::channel::Rights;

        assert_eq!(decode_rights("-"), Some(0), "прочерк снимает всё");
        assert_eq!(decode_rights("w"), Some(Rights::WRITE.bits()));
        assert_eq!(
            decode_rights("waed"),
            Some(Rights::all().bits()),
            "четыре буквы — четыре права §6.2"
        );
        // Незнакомая буква — отказ, а не пропуск: набрав `wx`, человек имел
        // в виду что-то, и выдать ему одно `w` значило бы выдать не то,
        // о чём он просил.
        assert_eq!(decode_rights("wx"), None);
        assert_eq!(decode_rights(""), None);

        for set in ["w", "a", "e", "d", "waed", "we"] {
            let bits = decode_rights(set).expect("набор разбирается");
            let shown = rights_letters(bits);
            assert_eq!(
                decode_rights(&shown),
                Some(bits),
                "показанное обязано читаться обратно: {set} → {shown}"
            );
        }
        assert_eq!(rights_letters(0), "-", "пустой набор печатается прочерком, а не пустотой");
    }

    #[test]
    fn a_long_text_is_exactly_as_long_as_asked() {
        // Ради этого свойства функция и существует: длина объявлена в самом
        // тексте, и разойдись она с настоящей — проверка на приёме врала бы
        // в обе стороны.
        for bytes in [1, 17, 64, 1024, 4095, 4096, 8 * 1024, 64 * 1024] {
            let text = long_text(bytes);
            assert_eq!(text.len(), bytes, "просили {bytes}");
            assert!(text.is_ascii(), "только ASCII: байты обязаны совпасть с символами");
        }
    }

    #[test]
    fn a_whole_long_text_is_called_whole() {
        let text = long_text(8 * 1024);
        let verdict = long_verdict(&text).expect("это наш текст");
        assert!(verdict.contains("ЦЕЛ"), "{verdict}");
        assert!(verdict.contains("8192"), "{verdict}");
    }

    #[test]
    fn a_text_cut_at_four_thousand_is_called_cut_and_placed() {
        // Ровно тот случай, ради которого всё написано: терминал в каноническом
        // режиме молча обрезает строку на 4095 байтах, и выглядит это как наша
        // поломка. Стенд обязан назвать обрыв обрывом.
        let text = long_text(8 * 1024);
        let cut = &text[..4095];
        let verdict = long_verdict(cut).expect("голова на месте, значит наш");
        assert!(verdict.contains("ОБРЕЗАН"), "{verdict}");
        assert!(verdict.contains("4095"), "{verdict}");
        assert!(verdict.contains("8192"), "объявленная длина обязана быть названа: {verdict}");
        // Место обрыва: до 4095-го байта укладывается четыре с лишним сотни
        // девятибайтовых блоков, и последний целый обязан быть назван.
        assert!(
            verdict.contains("последний целый блок 0000"),
            "место обрыва не названо: {verdict}"
        );
    }

    #[test]
    fn someone_elses_text_is_not_judged_at_all() {
        // Обычное сообщение обязано печататься как есть. Вердикт вместо текста
        // — это потеря переписки на ровном месте.
        assert_eq!(long_verdict("привет"), None);
        assert_eq!(long_verdict(""), None);
        assert_eq!(long_verdict("RK-LONG"), None, "метка без разметки — не наш текст");
        assert_eq!(long_verdict("RK-LONG-не число-start|"), None);
    }
}
