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
//! Обнаружение через mDNS работает не везде: мультикаст режут и гостевой
//! Wi-Fi, и часть корпоративных сетей. Поэтому есть `/addr` — вписать адрес
//! руками. Передача и обнаружение проверяются по отдельности намеренно:
//! иначе неудача не отличима от «сеть не пропускает mDNS».

use std::net::SocketAddr;
use std::path::PathBuf;

use data_encoding::BASE64URL_NOPAD;
use ratatosk_codec::ContactCard;
use ratatosk_core::driver::{Driver, DriverHandle, EventStream};
use ratatosk_core::{vault, Command, Engine, Event, OsEntropy, SelfAddresses};
use ratatosk_crypto::Identity;
use ratatosk_proto::DeliveryStatus;
use ratatosk_store::{MemoryStore, Store};
use ratatosk_transport::{LanConfig, LanDirectory, LanRunner};
use tokio::io::{AsyncBufReadExt, BufReader};

struct Args {
    name: String,
    port: u16,
    discovery: bool,
    data: Option<PathBuf>,
    pin: Option<String>,
}

fn parse_args() -> Args {
    let mut args =
        Args { name: "узел".to_owned(), port: 0, discovery: true, data: None, pin: None };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--name" => args.name = argv.next().unwrap_or_default(),
            "--port" => args.port = argv.next().and_then(|p| p.parse().ok()).unwrap_or(0),
            "--no-mdns" => args.discovery = false,
            "--data" => args.data = argv.next().map(PathBuf::from),
            "--pin" => args.pin = argv.next(),
            other => eprintln!("неизвестный ключ: {other}"),
        }
    }
    args
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("ratatosk=debug").init();
    let args = parse_args();

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

/// Хранилище в памяти: личность живёт до выхода.
async fn run_ephemeral(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = MemoryStore::new();
    store.migrate()?;
    let identity = Identity::generate();
    println!("хранилище: в памяти — перезапуск сотрёт личность и историю");
    run(args, identity, store).await
}

/// Хранилище на диске: личность и переписка переживают перезапуск.
async fn run_persistent(
    args: &Args,
    path: PathBuf,
    pin: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Тот же путь, которым идёт клиент через UniFFI: политика ключей одна
    // на всех, иначе стенд проверял бы не то, что поедет пользователю.
    let (mut store, db_key) = vault::open_encrypted(&path, Some(&pin))?;

    // Порядок важен: сначала личность, потом всё остальное. Сгенерировать
    // её поверх существующего зерна значит выбросить устройство целиком.
    let identity = vault::load_or_create(&mut store, &db_key)?;
    println!("хранилище: {}", path.display());
    run(args, identity, store).await
}

async fn run<S: Store + 'static>(
    args: &Args,
    identity: Identity,
    store: S,
) -> Result<(), Box<dyn std::error::Error>> {
    // Адреса onion и chatmail намеренно пустые: этот стенд проверяет LAN,
    // а §5.4 с непустыми адресами увёл бы доставку на транспорты, которых
    // ещё нет, — и отказ выглядел бы как отказ локальной сети.
    let addresses = SelfAddresses {
        onion: String::new(),
        chatmail: String::new(),
        display_name: args.name.clone(),
    };

    let mut engine = Engine::new(identity, store, Box::new(OsEntropy), addresses);
    let known = engine.restore()?;

    let card = BASE64URL_NOPAD.encode(&engine.own_card().encode()?);
    let fingerprint = engine.fingerprint();

    let config = LanConfig { enabled: true, port: args.port, discovery: args.discovery };
    let runner = LanRunner::start(config, engine.own_card().ik).await?;
    let port = runner.port();
    let directory = runner.directory();

    println!("узел     : {}", args.name);
    println!("отпечаток: {fingerprint}");
    println!("порт     : {port}");
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
    println!("команды: /add <карточка> [ip:порт]   /who   /net   /quit");
    println!("всё остальное уходит текстом первому добавленному контакту");
    println!();

    let (mut driver, handle, events) = Driver::new(engine, runner);

    // §5.1: LAN выключен по умолчанию. Стенд включает его явно — ровно так же,
    // как это должен будет сделать пользователь в UI. Команда идёт первой:
    // она проставляет `lan_enabled` уже поднятым с диска контактам.
    handle.send(Command::SetLanEnabled(true)).await.ok();

    tokio::select! {
        result = driver.run() => {
            if let Err(error) = result {
                eprintln!("ядро остановилось: {error}");
            }
        }
        () = console(handle, events, directory) => {}
    }
    Ok(())
}

/// Консоль: команды со stdin и события из ядра.
async fn console(handle: DriverHandle, mut events: EventStream, directory: LanDirectory) {
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
                                println!("< {}", String::from_utf8_lossy(&view.message.body));
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
                    | Event::HonestNotice { .. } => {}
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
        println!(
            "    LAN: включён={}  виден={}  адрес: {addr}",
            yes(a.lan_enabled),
            yes(a.seen_on_lan)
        );
        println!("    onion={}  почта={}", yes(a.has_onion), yes(a.has_chatmail));

        // Ровно та цепочка условий, что в `transport_policy::Attempt::next`.
        let verdict = if a.lan_enabled && a.seen_on_lan {
            "пойдёт по LAN"
        } else if a.has_onion {
            "пойдёт через onion"
        } else if a.has_chatmail {
            "пойдёт почтой"
        } else if !a.lan_enabled {
            "отправлять некуда: LAN выключен, других адресов в карточке нет"
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
    }
}

fn short(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&bytes[..bytes.len().min(6)])
}
