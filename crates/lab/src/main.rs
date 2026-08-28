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
use ratatosk_core::{vault, Command, Engine, Event, OsEntropy, SelfAddresses};
use ratatosk_crypto::{Identity, OnionKey};
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
use ratatosk_transport::{LanConfig, LanDirectory, LanRunner, Transports};
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
        "команды: /add <карточка> [ip:порт]   /card   /who   /lan   /tor [on|off]   /mail [set|new|tor|off]   /net   /onion   /find <слова>   /share   /take <msg_id>   /sweep   /quit"
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
                    let current =
                        handle.own_card().await.map(|c| c.onion).unwrap_or_default();
                    let announce =
                        if current.is_empty() { onion_address.clone() } else { current };
                    handle
                        .send(Command::AnnounceAddresses {
                            onion: announce.clone(),
                            chatmail: String::new(),
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

        let a = contact.availability;
        let addr = directory
            .get(&contact.peer_ik)
            .map_or_else(|| "неизвестен".to_owned(), |addr| addr.to_string());
        // Три признака у каждой ступени, и все три печатаются: «включён»
        // чинится переключателем, «работает» — временем (bootstrap идёт
        // десятки секунд), «адрес» — обменом карточками. Слив их в одно
        // слово, стенд отвечал бы на вопрос «почему не идёт» одинаково
        // для трёх разных бед.
        let step = |t| (a.enabled.contains(t), a.ready.contains(t));
        let (lan_on, lan_up) = step(ratatosk_proto::Transport::Lan);
        let (onion_on, onion_up) = step(ratatosk_proto::Transport::Onion);
        let (mail_on, mail_up) = step(ratatosk_proto::Transport::Mail);
        println!(
            "    LAN:   включён={}  работает={}  виден={}  адрес: {addr}",
            yes(lan_on),
            yes(lan_up),
            yes(a.seen_on_lan)
        );
        println!(
            "    onion: включён={}  работает={}  адрес={}",
            yes(onion_on),
            yes(onion_up),
            yes(a.has_onion)
        );
        println!(
            "    почта: включена={}  работает={}  адрес={}",
            yes(mail_on),
            yes(mail_up),
            yes(a.has_chatmail)
        );

        // Ровно та цепочка условий, что в `transport_policy::Attempt::next`.
        let verdict = if lan_on && lan_up && a.seen_on_lan {
            "пойдёт по LAN"
        } else if onion_on && onion_up && a.has_onion {
            "пойдёт через onion"
        } else if onion_on && a.has_onion {
            "onion ещё поднимается — уйдёт, как только сервис опубликуется"
        } else if mail_on && mail_up && a.has_chatmail {
            "пойдёт почтой"
        } else if !lan_on {
            "отправлять некуда: LAN выключен, других путей нет — \
             проверьте /tor и адреса в карточке"
        } else {
            "отправлять некуда: контакт не виден в LAN. \
             Допишите адрес: /add <карточка> <ip:порт> — на обеих машинах"
        };
        println!("    → §5.4: {verdict}");
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

fn short(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&bytes[..bytes.len().min(6)])
}
