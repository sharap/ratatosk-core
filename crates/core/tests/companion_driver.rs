//! Среда терминала компаньона — с настоящим телефоном на том конце (§13.4).
//!
//! # Почему этот файл появился поздно и почему всё-таки появился
//!
//! В `HANDOFF.md` было записано: драйвер не покрыт автотестами **и покрыт
//! быть не может**, потому что ему нужны tokio и живой транспорт. Первая
//! половина была правдой, вторая — нет, и это третий случай утверждения
//! о чужом слое, написанного по памяти.
//!
//! Живой транспорт ему не нужен: `Runner` — типаж, и поддельный раннер
//! пишется здесь же. Часы у драйвера подменяемы с рождения (`with_clock`).
//! А гонять его можно тем же `tokio::select!`, каким его гоняет стенд, —
//! без `spawn`, а значит и без требований `Send` к тому, что внутри.
//!
//! # Что здесь проверяется, чего не проверяет ничто другое
//!
//! Всё, что драйвер делает **сам**: файл на диске. `tests/terminal.rs`
//! доводит терминал до `NeedChunk` и `FileBytes` и на этом останавливается —
//! дальше начинается запись по смещению, стирание обрывка, открытие
//! следующего файла очереди. Ни один из этих путей до сегодня не исполнялся
//! в тестах ни разу.
//!
//! Телефон здесь настоящий: подделан только провод между ними.

#![cfg(feature = "driver")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{
    Command, CompanionClient, CompanionCommand, CompanionDriver, CompanionEvent, CompanionEvents,
    CompanionHandle, Effect, Engine, Event, Input, SeededEntropy,
};
use ratatosk_crypto::Identity;
use ratatosk_proto::companion::PairingInvite;
use ratatosk_proto::Transport;
use ratatosk_store::{MemoryBlobs, MemoryStore, Store};
use ratatosk_transport::{Runner, TransportCommand, TransportError, TransportEvent};

type Phone = Engine<MemoryStore>;

/// Провод между драйвером и телефоном — единственное, что здесь подделано.
///
/// Кадры, которые драйвер отправляет, складываются в `sent`; кадры, которые
/// он должен получить, приходят из `events`. Обе половины держит тест,
/// и он же играет роль сети.
struct FakeRunner {
    events: tokio::sync::mpsc::Receiver<TransportEvent>,
    sent: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Куда и чем звонили — для проверки выбора транспорта.
    ///
    /// Отдельным списком, а не третьим полем в канале кадров: кадры читают
    /// шесть тестов, а адресацию — один, и менять форму ради него значило бы
    /// править шесть мест из-за седьмого.
    addressed: Arc<Mutex<Vec<(Transport, Option<String>)>>>,
    /// Все команды подряд — для проверки настройки, а не отправки.
    ///
    /// Кадры сюда тоже попадают, и это нарочно: порядок «настроил меш,
    /// потом поздоровался» проверяется только тем, что обе записи лежат
    /// в одном списке.
    commands: Arc<Mutex<Vec<TransportCommand>>>,
}

impl Runner for FakeRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        if let Ok(mut seen) = self.commands.lock() {
            seen.push(command.clone());
        }
        if let TransportCommand::Send { peer, via, frame, .. } = command {
            if let Ok(mut seen) = self.addressed.lock() {
                seen.push((via, peer.onion.clone()));
            }
            // Некому принять — значит тест кончился, и это не ошибка сети.
            let _ = self.sent.send(frame).await;
        }
        Ok(())
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        self.events.recv().await
    }
}

/// Обе стороны и провод между ними.
struct Pair {
    phone: Phone,
    blobs: Arc<Mutex<MemoryBlobs>>,
    handle: CompanionHandle,
    events: CompanionEvents,
    /// Кадры от драйвера — их тест отдаёт телефону.
    from_desktop: tokio::sync::mpsc::Receiver<Vec<u8>>,
    /// Кадры телефону — их тест отдаёт драйверу.
    to_desktop: tokio::sync::mpsc::Sender<TransportEvent>,
    desktop_ik: [u8; 32],
    /// Ключ телефона: им адресованы события транспорта о разрыве и маяке.
    phone_ik: [u8; 32],
    /// Куда и чем драйвер звонил — общий список с поддельным раннером.
    addressed: Arc<Mutex<Vec<(Transport, Option<String>)>>>,
    /// Что драйвер просил у транспорта — общий список с поддельным раннером.
    commands: Arc<Mutex<Vec<TransportCommand>>>,
    /// Ссылка сопряжения целиком — из неё тест собирает снимок на диск.
    invite: PairingInvite,
    /// Сколько кадров доехало до телефона — то есть кругов по сети.
    ///
    /// Считается ради одной проверки: круг здесь стоит столько же,
    /// сколько в жизни, и «медленно по локальной сети» — это про их число,
    /// а не про байты.
    turns: u64,
}

impl Pair {
    /// Прогоняет один круг: кадр от драйвера — телефону, ответы — обратно.
    ///
    /// Возвращает `false`, когда драйвер ничего не отправил: значит обмен
    /// сошёлся и ждать больше нечего.
    async fn turn(&mut self, now_ms: u64) -> bool {
        let Ok(frame) = self.from_desktop.try_recv() else { return false };
        self.turns += 1;
        let effects = self
            .phone
            .step(now_ms, Input::Received { via: Transport::Lan, frame })
            .expect("шаг ядра");
        for effect in effects {
            let Effect::Send { peer_ik, frame, .. } = effect else { continue };
            if peer_ik != self.desktop_ik {
                continue;
            }
            let _ = self
                .to_desktop
                .send(TransportEvent::Received {
                    via: Transport::Lan,
                    peer_hint: None,
                    // Провод этого теста — локальная сеть, а у неё принятых
                    // связей нет: ответ едет своим набором.
                    link: None,
                    frame,
                })
                .await;
        }
        true
    }

    /// Гоняет круги, пока обмен не сойдётся.
    ///
    /// Тишина считается не одним пустым кругом, а несколькими подряд:
    /// драйвер и тест — две задачи одного рантайма, и «пусто» сразу после
    /// команды означает лишь то, что до драйвера ещё не дошла очередь.
    async fn settle(&mut self, now_ms: u64) {
        let mut quiet = 0;
        for _ in 0..256 {
            if self.turn(now_ms).await {
                quiet = 0;
            } else {
                quiet += 1;
                if quiet > 8 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        }
        panic!("обмен не сошёлся — вероятно, кольцо кадров");
    }

    /// Даёт драйверу дойти до своего следующего ожидания.
    ///
    /// Нужен там, где проверяется то, что драйвер делает **до** сети:
    /// создаёт файл, стирает обрывок, кладёт снимок кэша.
    async fn breathe(&mut self) {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Ждёт событие, которое подходит под образец.
    ///
    /// С таймаутом, а не бесконечно: не пришедшее событие обязано выглядеть
    /// как упавший тест, а не как повисший.
    async fn wait_for<T>(&mut self, mut pick: impl FnMut(&CompanionEvent) -> Option<T>) -> T {
        for _ in 0..64 {
            let next =
                tokio::time::timeout(std::time::Duration::from_millis(100), self.events.next())
                    .await;
            match next {
                Ok(Some(event)) => {
                    if let Some(found) = pick(&event) {
                        return found;
                    }
                }
                Ok(None) => panic!("поток событий закрылся"),
                Err(_) => tokio::task::yield_now().await,
            }
        }
        panic!("нужного события так и не пришло");
    }

    /// То же, но **не переставая гонять кадры**.
    ///
    /// `wait_for` только слушает, и это годится там, где обмен уже сошёлся.
    /// Там, где ожидаемое событие приходит в конце длинной цепочки кругов —
    /// рукопожатие, три просьбы, куски файла, отправка, — слушать мало:
    /// кадры остались бы лежать в канале, а тест ждал бы события, которому
    /// неоткуда взяться. `settle` перед ожиданием эту цепочку тоже не
    /// вытягивает: он считает обмен сошедшимся после нескольких пустых
    /// кругов подряд, а пауза на чтение мебибайта с диска выглядит именно
    /// так.
    ///
    /// `what` — чего ждём, словами: провалившееся ожидание обязано называть
    /// шаг, а не «нужного события так и не пришло».
    async fn wait_turning<T>(
        &mut self,
        now_ms: u64,
        what: &str,
        mut pick: impl FnMut(&CompanionEvent) -> Option<T>,
    ) -> T {
        for _ in 0..512 {
            let _ = self.turn(now_ms).await;
            let next =
                tokio::time::timeout(std::time::Duration::from_millis(20), self.events.next())
                    .await;
            match next {
                Ok(Some(event)) => {
                    if let Some(found) = pick(&event) {
                        return found;
                    }
                }
                Ok(None) => panic!("поток событий закрылся"),
                Err(_) => tokio::task::yield_now().await,
            }
        }
        panic!("так и не дождались: {what}");
    }
}

/// Телефон, драйвер и провод между ними — но драйвер ещё не запущен.
fn paired(now_ms: u64) -> (CompanionDriver<FakeRunner>, Pair) {
    paired_with_onion(now_ms, String::new())
}

/// То же, но у телефона есть onion-адрес — он уезжает в приглашение.
///
/// Отдельным входом, а не полем в `Pair`: адрес попадает в ссылку сопряжения
/// в момент её выдачи, и подставить его потом было бы враньём — терминал
/// берёт его именно оттуда.
fn paired_with_onion(now_ms: u64, phone_onion: String) -> (CompanionDriver<FakeRunner>, Pair) {
    paired_with(now_ms, phone_onion, Vec::new(), false)
}

/// То же, но у телефона ещё и настроены пиры меша.
///
/// Они уезжают в приглашение — и это единственный путь, которым терминал
/// узнаёт их **до** первой связи. Подставлять их драйверу прямо было бы
/// враньём ровно в том месте, где и была поломка.
///
/// `stale_invite` отдаёт терминалу ссылку **без** пиров — такую, какую
/// печатала сборка постарше, — оставляя полную в `Pair::invite`. Так
/// проверяется второй путь: пиры не из QR, а с диска.
fn paired_with(
    now_ms: u64,
    phone_onion: String,
    ygg_peers: Vec<String>,
    stale_invite: bool,
) -> (CompanionDriver<FakeRunner>, Pair) {
    let identity = Identity::from_seed([1u8; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция");
    let blobs = Arc::new(Mutex::new(MemoryBlobs::new()));
    let kept = Arc::clone(&blobs);
    let mut phone = Engine::new(
        identity,
        store,
        Box::new(blobs),
        Box::new(SeededEntropy::new(1)),
        SelfAddresses {
            onion: phone_onion,
            chatmail: "phone@nine.example".to_owned(),
            display_name: "телефон".to_owned(),
        },
    );
    phone
        .step(
            0,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Lan,
                enabled: true,
            }),
        )
        .expect("включение LAN");
    phone.step(0, Input::TransportReady { transport: Transport::Lan }).expect("готовность LAN");

    if !ygg_peers.is_empty() {
        // Режим — до ключа: в `Off` ключ запоминается, но имени не даёт,
        // и карточка уехала бы без меша. А без меша в карточке терминалу
        // и незачем поднимать узел.
        phone
            .step(0, Input::Command(Command::SetYggMode(ratatosk_proto::ygg::YggMode::External)))
            .expect("режим меша телефона");
        phone
            .step(0, Input::Command(Command::SetYggKey(vec![3u8; 32])))
            .expect("ключ меша телефона");
        phone.step(0, Input::Command(Command::SetYggPeers(ygg_peers))).expect("пиры меша телефона");
    }

    let effects = phone
        .step(now_ms, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");
    let uri = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Notify(Event::PairingReady { uri, .. }) => Some(uri),
            _ => None,
        })
        .expect("ссылка приходит событием");
    let invite = PairingInvite::from_uri(&uri).expect("разбор ссылки");

    let given = if stale_invite {
        PairingInvite { ygg_peers: Vec::new(), ..invite.clone() }
    } else {
        invite.clone()
    };
    let client = CompanionClient::from_invite(&given, Box::new(SeededEntropy::new(99)));
    let desktop_ik = client.ik();
    let phone_ik = invite.ik;

    let (to_desktop, events_rx) = tokio::sync::mpsc::channel(64);
    let (sent_tx, from_desktop) = tokio::sync::mpsc::channel(64);
    let addressed: Arc<Mutex<Vec<(Transport, Option<String>)>>> = Arc::default();
    let commands: Arc<Mutex<Vec<TransportCommand>>> = Arc::default();
    let runner = FakeRunner {
        events: events_rx,
        sent: sent_tx,
        addressed: Arc::clone(&addressed),
        commands: Arc::clone(&commands),
    };

    let (driver, handle, events) = CompanionDriver::new(client, runner);
    (
        driver,
        Pair {
            phone,
            blobs: kept,
            handle,
            events,
            from_desktop,
            to_desktop,
            desktop_ik,
            phone_ik,
            addressed,
            commands,
            invite,
            turns: 0,
        },
    )
}

/// Заводит контакт, чтобы терминалу было что показывать.
fn with_contact(phone: &mut Phone, now_ms: u64) -> [u8; 32] {
    let other = Identity::from_seed([9u8; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: other.public().ik,
        sk: other.public().sk,
        onion: String::new(),
        chatmail: "sosed@nine.example".to_owned(),
        display_name: "сосед".to_owned(),
        version: 1,
        ygg: Vec::new(),
        nostr: Vec::new(),
        nostr_relays: Vec::new(),
    };
    phone
        .step(
            now_ms,
            Input::Command(Command::AddContact {
                card_bytes: card.encode().expect("карточка"),
                met_in_person: true,
            }),
        )
        .expect("добавление контакта");
    card.ik
}

/// Свой временный каталог: зависимость ради одной функции не берём.
fn temp_dir(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ratatosk-driver-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("временный каталог");
    path
}

#[tokio::test]
async fn the_driver_links_up_and_hands_the_chat_list_to_the_window() {
    // Самый первый круг: драйвер здоровается сам, телефон отвечает, и окно
    // получает список чатов, ничего не спросив. Без этого человек после
    // подключения видел бы пустоту, которую пришлось бы разгонять таймером.
    let (mut driver, mut pair) = paired(1_000);
    with_contact(&mut pair.phone, 1_050);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            let chats = pair.wait_for(|event| match event {
                CompanionEvent::Chats { chats, .. } => Some(chats.clone()),
                _ => None,
            }).await;
            assert_eq!(chats.len(), 1, "контакт обязан приехать чатом");
            assert_eq!(chats[0].title, "сосед");
        } => {}
    }
}

#[tokio::test]
async fn the_terminal_falls_back_to_onion_and_comes_back_to_the_shared_network() {
    // Вне общей сети терминал до этой поставки звонил в никуда: адрес
    // телефона лежал у него в приглашении с самого сопряжения, а в команду
    // транспорта уезжал `None`.
    const PHONE: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    let (mut driver, mut pair) = paired_with_onion(1_000, PHONE.to_owned());
    let phone_ik = pair.phone_ik;

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            {
                let seen = pair.addressed.lock().expect("список адресов");
                assert!(!seen.is_empty(), "терминал обязан был позвонить");
                assert!(
                    seen.iter().all(|(via, _)| *via == Transport::Lan),
                    "начинаем с общей сети: onion до первого разочарования — \
                     цепочка Tor в соседнюю комнату"
                );
                assert!(
                    seen.iter().all(|(_, onion)| onion.as_deref() == Some(PHONE)),
                    "адрес телефона едет всегда: он известен с сопряжения, \
                     и решает по нему транспорт, а не мы"
                );
            }

            // Локальная сеть замолчала.
            pair.to_desktop
                .send(TransportEvent::ConnectFailed { peer_ik: phone_ik, via: Transport::Lan })
                .await
                .expect("событие транспорта");
            pair.settle(1_200).await;
            assert!(
                pair.addressed
                    .lock()
                    .expect("список адресов")
                    .iter()
                    .any(|(via, _)| *via == Transport::Onion),
                "не отозвалась общая сеть — пробуем через Tor"
            );

            // Телефон снова в эфире. Возврат нужен не меньше отката: иначе
            // терминал остался бы на onion навсегда — цепочка Tor в соседнюю
            // комнату.
            pair.to_desktop
                .send(TransportEvent::SeenOnLan { peer_ik: phone_ik })
                .await
                .expect("событие транспорта");
            pair.settle(1_300).await;

            // Спрашиваем что-нибудь: связь после onion-рукопожатия жива,
            // и само по себе `Reach` кадра не породит — а проверить надо,
            // каким транспортом уедет **следующий** разговор.
            pair.handle.send(CompanionCommand::Chats).await.expect("просьба принята");
            pair.settle(1_400).await;
            let seen = pair.addressed.lock().expect("список адресов");
            let (via, _) = seen.last().expect("после маяка звонок обязан быть");
            assert_eq!(*via, Transport::Lan, "маяк возвращает в общую сеть");
        } => {}
    }
}

#[tokio::test]
async fn a_terminal_without_the_phones_address_stays_where_it_is() {
    // Переключаться некуда: адреса нет. «Звоню туда, где никого нет»
    // честнее, чем «звоню в никуда», — и заодно это тот самый случай,
    // когда телефон просто выключили.
    let (mut driver, mut pair) = paired(1_000);
    let phone_ik = pair.phone_ik;

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.to_desktop
                .send(TransportEvent::ConnectFailed { peer_ik: phone_ik, via: Transport::Lan })
                .await
                .expect("событие транспорта");
            pair.settle(1_200).await;
            let seen = pair.addressed.lock().expect("список адресов");
            assert!(
                seen.iter().all(|(via, onion)| *via == Transport::Lan && onion.is_none()),
                "без адреса транспорт не меняется: {seen:?}"
            );
        } => {}
    }
}

#[tokio::test]
async fn a_saved_attachment_really_lands_on_disk() {
    // **Путь, который не исполнялся ни разу.** Запись по смещению, закрытие
    // файла, событие `FileSaved` с путём — всё это живёт только в драйвере,
    // и до сегодня проверялось чтением глазами.
    let dir = temp_dir("save");
    let target = dir.join("kot.jpg");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // Файл на телефоне: отправленный им самим, то есть готовый к чтению.
    let bytes: Vec<u8> = (0..1000u32).map(|n| (n % 251) as u8).collect();
    pair.blobs.lock().unwrap().seed_sparse("/tmp/kot.jpg", bytes.len() as u64);
    pair.phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/kot.jpg".into(),
                    preview: None,
                }],
                text: "вот кот".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = pair.phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file = pair.phone.store().files_of(&msg_id).expect("вложения")[0].clone();

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_200).await;
            pair.handle
                .send(CompanionCommand::SaveFile {
                    file_id: file.file_id,
                    chunk_total: file.chunk_total,
                    chunk_bytes: u64::from(file.chunk_bytes),
                    path: target.clone(),
                })
                .await
                .expect("команда принята");
            pair.settle(1_300).await;

            let path = pair.wait_for(|event| match event {
                CompanionEvent::FileSaved { path, .. } => Some(path.clone()),
                _ => None,
            }).await;
            assert_eq!(path, target, "путь в событии — тот, что просили");

            let written = std::fs::read(&target).expect("файл обязан лежать на диске");
            assert_eq!(written.len() as u64, file.size_bytes, "длина совпала");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_saved_attachment_keeps_its_bytes_when_the_narezka_is_not_the_default() {
    // **Разбор жалобы «файлы через компаньона приходят битыми».**
    //
    // Нарезка у файла своя с миграции 0026: в эфире чанк четыре килобайта,
    // на прочих ступенях мебибайт. Провод компаньона её **не везёт** —
    // `Response::FileOffer` называет только число кусков, — а десктоп
    // пишет кусок по смещению `index * CHUNK_BYTES`, то есть по своему
    // умолчанию. Совпадают они ровно тогда, когда файл ехал не эфиром.
    //
    // Проверка выше этого не видит по двум причинам сразу: файл в ней
    // однокусковый (смещение нулевое при любой нарезке) и сверяется у него
    // **длина**, а не содержимое. Здесь наоборот: несколько кусков
    // и побайтовое сравнение.
    let dir = temp_dir("narezka");
    let target = dir.join("kot.jpg");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // **Эфир включён** — и этого довольно: нарезку телефон выбирает
    // по включённым ступеням (`chunk_bytes_now`), а не по той, которой
    // файл поедет. У Никиты на телефоне он включён всегда.
    pair.phone
        .step(
            1_060,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Bt,
                enabled: true,
            }),
        )
        .expect("эфир включается");

    // Несколько кусков эфирной нарезки — и байты не нулевые, иначе
    // перепутанные смещения не отличить от правильных.
    let air = ratatosk_proto::files::AIR_CHUNK_BYTES;
    let bytes: Vec<u8> = (0..air as u32 * 3 + 17).map(|n| (n % 251) as u8).collect();
    pair.blobs.lock().unwrap().seed("/tmp/kot.jpg", bytes.clone());
    pair.phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/kot.jpg".into(),
                    preview: None,
                }],
                text: "вот кот".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = pair.phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file = pair.phone.store().files_of(&msg_id).expect("вложения")[0].clone();
    assert!(
        file.chunk_total > 1,
        "проверка бессмысленна на одном куске: смещение нулевое при любой нарезке"
    );

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_200).await;
            pair.handle
                .send(CompanionCommand::SaveFile {
                    file_id: file.file_id,
                    chunk_total: file.chunk_total,
                    chunk_bytes: u64::from(file.chunk_bytes),
                    path: target.clone(),
                })
                .await
                .expect("команда принята");
            pair.settle(1_300).await;

            pair.wait_for(|event| match event {
                CompanionEvent::FileSaved { path, .. } => Some(path.clone()),
                _ => None,
            }).await;

            let written = std::fs::read(&target).expect("файл обязан лежать на диске");
            assert_eq!(
                written.len(),
                bytes.len(),
                "длина обязана совпасть: по чужой нарезке куски ложатся врастопырку"
            );
            assert!(written == bytes, "и содержимое — до байта, иначе файл битый");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_finely_cut_attachment_does_not_cost_a_round_trip_per_piece() {
    // **Жалоба со стенда: «через компаньона файлы ползут даже по LAN».**
    //
    // Провод забирал вложение по куску за просьбу, а просьба — это круг
    // по сети. Пока кусок был мебибайтом, это ничего не стоило: сто
    // мегабайт — сотня кругов. С нарезкой эфира (четыре килобайта) те же
    // сто мегабайт стали двадцатью восемью тысячами кругов. Байты те же,
    // время — другое.
    //
    // Кадр ответа при этом рассчитан на целый мебибайт и вёз четыре
    // килобайта. Проверка про то, что теперь он везёт столько, сколько
    // влезает.
    let dir = temp_dir("packs");
    let target = dir.join("bolshoy.bin");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    pair.phone
        .step(
            1_060,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Bt,
                enabled: true,
            }),
        )
        .expect("эфир включается");

    let air = ratatosk_proto::files::AIR_CHUNK_BYTES as u64;
    let pieces = 600u64;
    let bytes: Vec<u8> = (0..(air * pieces) as u32).map(|n| (n % 251) as u8).collect();
    pair.blobs.lock().unwrap().seed("/tmp/bolshoy.bin", bytes.clone());
    pair.phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/bolshoy.bin".into(),
                    preview: None,
                }],
                text: String::new(),
            }),
        )
        .expect("отправка файла");
    let msg_id = pair.phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file = pair.phone.store().files_of(&msg_id).expect("вложения")[0].clone();
    assert_eq!(file.chunk_total, pieces, "нарезка обязана быть эфирной, иначе мерить нечего");

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_200).await;
            // Считаем **только выгрузку**: рукопожатие и список чатов
            // к делу не относятся.
            pair.turns = 0;
            pair.handle
                .send(CompanionCommand::SaveFile {
                    file_id: file.file_id,
                    chunk_total: file.chunk_total,
                    chunk_bytes: u64::from(file.chunk_bytes),
                    path: target.clone(),
                })
                .await
                .expect("команда принята");
            pair.settle(1_300).await;

            pair.wait_for(|event| match event {
                CompanionEvent::FileSaved { path, .. } => Some(path.clone()),
                _ => None,
            }).await;

            let written = std::fs::read(&target).expect("файл обязан лежать на диске");
            assert!(written == bytes, "быстрее — не значит кое-как: байты до одного");

            // **Число считается от правила, а не выписано.** Кусков шесть
            // сотен; кругов обязано быть примерно столько, сколько пачек,
            // — и уж точно не по кругу на кусок.
            let per_ask = ratatosk_proto::companion::chunks_per_ask(air);
            let packs = pieces.div_ceil(per_ask);
            assert!(
                pair.turns <= packs * 2 + 4,
                "кругов {} при {packs} пачках ({per_ask} кусков в каждой) — провод снова возит по куску",
                pair.turns
            );
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cancelling_a_save_removes_the_half_written_file() {
    // Недокачанный файл выглядит на диске ровно как докачанный. Оставить
    // его — значит отдать человеку битую картинку без единого признака
    // того, что она битая (§14).
    let dir = temp_dir("cancel");
    let target = dir.join("oborvysh.bin");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = ratatosk_proto::files::CHUNK_BYTES as u64 * 2 + 5;
    pair.blobs.lock().unwrap().seed_sparse("/tmp/big.bin", size);
    pair.phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/big.bin".into(),
                    preview: None,
                }],
                text: String::new(),
            }),
        )
        .expect("отправка файла");
    let msg_id = pair.phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file = pair.phone.store().files_of(&msg_id).expect("вложения")[0].clone();

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_200).await;
            pair.handle
                .send(CompanionCommand::SaveFile {
                    file_id: file.file_id,
                    chunk_total: file.chunk_total,
                    chunk_bytes: u64::from(file.chunk_bytes),
                    path: target.clone(),
                })
                .await
                .expect("команда принята");
            // Ни одного круга по проводу: телефону никто не отвечает,
            // и выгрузка остаётся открытой. Файл при этом уже создан —
            // `start_save` создаёт его до первой просьбы о куске, — но
            // **под именем с припиской**: под настоящим именем недокачанного
            // файла не бывает вовсе.
            pair.breathe().await;
            let partial = dir.join("oborvysh.bin.part");
            assert!(partial.exists(), "запись началась — иначе отменять нечего");
            assert!(!target.exists(), "настоящее имя файл получает последним действием");

            pair.handle.send(CompanionCommand::CancelSave).await.expect("отмена принята");
            pair.breathe().await;
            assert!(!partial.exists(), "передумавший человек не должен убирать обрывок сам");
            assert!(!target.exists());
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn sending_two_files_reads_both_from_disk_in_order() {
    // Очередь выгрузки целиком: драйвер открывает файлы по номеру из
    // `NeedChunk`, а не по имени. Имена здесь нарочно **одинаковые** — ровно
    // тот случай, в котором поиск по имени отдал бы байты не того файла.
    let first_dir = temp_dir("send-a");
    let second_dir = temp_dir("send-b");
    let first = first_dir.join("scan.pdf");
    let second = second_dir.join("scan.pdf");
    std::fs::write(&first, vec![0xAAu8; 300]).expect("первый файл");
    std::fs::write(&second, vec![0xBBu8; 500]).expect("второй файл");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.handle
                .send(CompanionCommand::SendFiles {
                    chat,
                    files: vec![(first.clone(), None), (second.clone(), None)],
                    text: "два скана".into(),
                })
                .await
                .expect("команда принята");
            pair.settle(1_200).await;

            let sent = pair.wait_for(|event| match event {
                CompanionEvent::FilesSent { file_ids } => Some(file_ids.clone()),
                _ => None,
            }).await;
            assert_eq!(sent.len(), 2, "оба файла одним сообщением");

            let history = pair.phone.store().messages(&chat, 10, None).expect("история");
            assert_eq!(history.len(), 1, "одно сообщение, а не два");
            let stored = pair.phone.store().files_of(&history[0].msg_id).expect("вложения");
            assert_eq!(stored.len(), 2);
            assert_eq!(stored[0].size_bytes, 300, "первый — тот, что назвали первым");
            assert_eq!(stored[1].size_bytes, 500, "и байты не перепутаны местами");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&first_dir);
    let _ = std::fs::remove_dir_all(&second_dir);
}

#[tokio::test]
async fn a_file_going_up_is_cut_the_way_the_phone_agreed_to_take_it() {
    // **Та же беда, что и на приёме, только с другой стороны провода.**
    // Телефон нарезает выгрузку своим числом (`chunk_bytes_now`) и сам же
    // сверяет длину каждого куска; десктоп читает исходник по своему
    // умолчанию. Разойдись они — телефон отвергает кусок за куском,
    // и выгрузка не едет вовсе.
    let dir = temp_dir("send-narezka");
    let path = dir.join("bolshoy.bin");
    let air = ratatosk_proto::files::AIR_CHUNK_BYTES;
    let bytes: Vec<u8> = (0..air as u32 * 2 + 9).map(|n| (n % 241) as u8).collect();
    std::fs::write(&path, &bytes).expect("исходник");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    pair.phone
        .step(
            1_060,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Bt,
                enabled: true,
            }),
        )
        .expect("эфир включается");

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.handle
                .send(CompanionCommand::SendFiles {
                    chat,
                    files: vec![(path.clone(), None)],
                    text: "большой".into(),
                })
                .await
                .expect("команда принята");
            pair.settle(1_200).await;

            let sent = pair.wait_for(|event| match event {
                CompanionEvent::FilesSent { file_ids } => Some(file_ids.clone()),
                _ => None,
            }).await;
            assert_eq!(sent.len(), 1, "файл обязан уехать, а не застрять на первом куске");

            let history = pair.phone.store().messages(&chat, 10, None).expect("история");
            let stored = pair.phone.store().files_of(&history[0].msg_id).expect("вложения");
            assert_eq!(stored[0].size_bytes, bytes.len() as u64, "и доехать целиком");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_file_that_cannot_be_read_is_refused_before_anything_goes_up() {
    // Узнать, что второй файл не читается, после того как первый уже уехал,
    // — худший из порядков: на телефоне осталось бы занятое место, а человек
    // увидел бы отказ вместо отправки.
    let dir = temp_dir("missing");
    let real = dir.join("est.bin");
    std::fs::write(&real, vec![1u8; 10]).expect("файл");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.handle
                .send(CompanionCommand::SendFiles {
                    chat,
                    files: vec![(real.clone(), None), (dir.join("net-takogo.bin"), None)],
                    text: String::new(),
                })
                .await
                .expect("команда принята");
            let why = pair.wait_for(|event| match event {
                CompanionEvent::Refused(why) => Some(why.clone()),
                _ => None,
            }).await;
            assert!(why.contains("не открыть"), "причина обязана быть внятной: {why}");

            assert!(
                pair.phone.store().messages(&chat, 10, None).expect("история").is_empty(),
                "ни одного сообщения и ни одной занятой выгрузки"
            );
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_broken_link_leaves_the_part_file_and_finishes_it_later() {
    // Приём через разрыв — вторая половина того же решения. Раньше обрывок
    // стирался, и человек качал мебибайты заново из-за секундной потери сети.
    //
    // Проверяется здесь, потому что весь спор про имя файла живёт только
    // в драйвере: `.part` пока едет, настоящее имя — последним действием.
    let dir = temp_dir("save-resume");
    let target = dir.join("video.mp4");
    let partial = dir.join("video.mp4.part");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = ratatosk_proto::files::CHUNK_BYTES as u64 * 2 + 9;
    pair.blobs.lock().unwrap().seed_sparse("/tmp/video.mp4", size);
    pair.phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/video.mp4".into(),
                    preview: None,
                }],
                text: "видео".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = pair.phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file = pair.phone.store().files_of(&msg_id).expect("вложения")[0].clone();

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_200).await;
            pair.handle
                .send(CompanionCommand::SaveFile {
                    file_id: file.file_id,
                    chunk_total: file.chunk_total,
                    chunk_bytes: u64::from(file.chunk_bytes),
                    path: target.clone(),
                })
                .await
                .expect("команда принята");

            // Крутим, пока на диск не ляжет кусок-другой, — и рвём посреди.
            let whole = ratatosk_proto::files::CHUNK_BYTES as u64 * file.chunk_total;
            for _ in 0..32 {
                pair.breathe().await;
                let _ = pair.turn(1_250).await;
                let written = std::fs::metadata(&partial).map(|meta| meta.len()).unwrap_or(0);
                if written > 0 && written < whole {
                    break;
                }
            }
            let written = std::fs::metadata(&partial).expect("обрывок на диске").len();
            assert!(written > 0 && written < size, "рвать надо посреди файла: {written} из {size}");
            assert!(!target.exists(), "под настоящим именем пока ничего нет");

            pair.to_desktop
                .send(TransportEvent::Disconnected { peer_ik: pair.phone_ik, via: Transport::Lan })
                .await
                .expect("разрыв принят");
            pair.wait_turning(1_260, "«связь пропала, приём ждёт»", |event| match event {
                CompanionEvent::FetchPaused => Some(()),
                CompanionEvent::Refused(why) => panic!("разрыв — не отказ: {why}"),
                _ => None,
            })
            .await;
            assert!(partial.exists(), "записанное обязано пережить разрыв");

            pair.to_desktop
                .send(TransportEvent::SeenOnLan { peer_ik: pair.phone_ik })
                .await
                .expect("маяк принят");
            let saved = pair
                .wait_turning(1_300, "конец приёма после продолжения", |event| match event {
                    CompanionEvent::FileSaved { path, .. } => Some(path.clone()),
                    CompanionEvent::Refused(why) => panic!("продолжение отказом не кончается: {why}"),
                    _ => None,
                })
                .await;

            assert_eq!(saved, target, "имя в событии — настоящее, а не с припиской");
            assert_eq!(
                std::fs::metadata(&target).expect("файл на диске").len(),
                size,
                "и собран целиком"
            );
            assert!(!partial.exists(), "приписки после конца не остаётся");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_broken_link_does_not_take_the_paths_with_it() {
    // Пути держит драйвер, и отпускать их на разрыве нельзя: продолжение
    // выгрузки просит кусок того же файла, а читать его будет неоткуда —
    // и отправка встанет молча.
    //
    // Проверяется здесь, потому что проверить это больше негде: пути живут
    // только в драйвере, и `tests/terminal.rs` о них не знает.
    let dir = temp_dir("send-resume");
    let path = dir.join("otchet.pdf");
    std::fs::write(&path, vec![0xCDu8; ratatosk_proto::files::CHUNK_BYTES * 2 + 7])
        .expect("файл на диске");

    let (mut driver, mut pair) = paired(1_000);
    let peer_ik = with_contact(&mut pair.phone, 1_050);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.handle
                .send(CompanionCommand::SendFiles {
                    chat,
                    files: vec![(path.clone(), None)],
                    text: "вот отчёт".into(),
                })
                .await
                .expect("команда принята");
            // Крутим ровно столько, чтобы у телефона лёг кусок-другой, —
            // и обрываемся **посреди** файла, а не между файлами.
            for _ in 0..32 {
                pair.breathe().await;
                let _ = pair.turn(1_150).await;
                let staged = pair.phone.store().staged_uploads().expect("выгрузки");
                let started = staged.first().is_some_and(|file| {
                    !pair.phone.store().staged_chunks(&file.file_id).expect("куски").is_empty()
                });
                if started {
                    break;
                }
            }
            let staged = pair.phone.store().staged_uploads().expect("выгрузки");
            assert_eq!(staged.len(), 1, "выгрузка обязана была начаться");
            let have = pair.phone.store().staged_chunks(&staged[0].file_id).expect("куски");
            assert!(
                !have.is_empty() && (have.len() as u64) < staged[0].chunk_total,
                "рвать связь надо посреди файла: {} кусков из {}",
                have.len(),
                staged[0].chunk_total
            );

            // Связь пропала.
            pair.to_desktop
                .send(TransportEvent::Disconnected { peer_ik: pair.phone_ik, via: Transport::Lan })
                .await
                .expect("разрыв принят");
            pair.wait_turning(1_200, "«связь пропала, отправка ждёт»", |event| match event {
                CompanionEvent::SendPaused => Some(()),
                CompanionEvent::Refused(why) => panic!("разрыв — не отказ: {why}"),
                _ => None,
            })
            .await;

            // И вернулась: маяк телефона в эфире. Дальше цепочка длинная —
            // рукопожатие, `Staged`, куски, отправка, — и гонять кадры надо
            // всё это время, а не ждать молча.
            pair.to_desktop
                .send(TransportEvent::SeenOnLan { peer_ik: pair.phone_ik })
                .await
                .expect("маяк принят");

            let sent = pair
                .wait_turning(1_300, "конец отправки после продолжения", |event| match event {
                    CompanionEvent::FilesSent { file_ids } => Some(file_ids.clone()),
                    CompanionEvent::Refused(why) => panic!("продолжение отказом не кончается: {why}"),
                    _ => None,
                })
                .await;
            assert_eq!(sent.len(), 1, "тот же файл, дочитанный с диска после разрыва");

            let history = pair.phone.store().messages(&chat, 10, None).expect("история");
            assert_eq!(history.len(), 1, "одно сообщение, а не два");
            let stored = pair.phone.store().files_of(&history[0].msg_id).expect("вложения");
            assert_eq!(
                stored[0].size_bytes,
                ratatosk_proto::files::CHUNK_BYTES as u64 * 2 + 7,
                "файл собран целиком"
            );
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn turning_the_cache_off_wipes_the_file() {
    // §13.4: выключение **стирает**, а не перестаёт обновлять. Человек,
    // снявший галочку, имел в виду «здесь этого не должно быть».
    let dir = temp_dir("cache");
    let cache = dir.join("snimok");

    let (mut driver, mut pair) = paired(1_000);
    with_contact(&mut pair.phone, 1_050);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.handle
                .send(CompanionCommand::KeepCache { path: Some(cache.clone()) })
                .await
                .expect("команда принята");
            pair.settle(1_100).await;
            pair.breathe().await;
            assert!(cache.exists(), "включённый кэш обязан лечь сразу, а не завтра");

            pair.handle.send(CompanionCommand::KeepCache { path: None }).await.expect("выключение");
            pair.breathe().await;
            assert!(!cache.exists(), "выключение стирает файл");
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_terminal_raises_its_own_mesh_node_from_the_invite() {
    // Поломка, ради которой это написано: встроенный узел терминала
    // не вставал **никогда** вне общей сети. Пиры приезжали только
    // объявлением по живому каналу, а живой канал требовал поднятой
    // ступени — узлу неоткуда было взяться, и в журнале стояло
    // «свой_узел=false» до конца запуска.
    //
    // Поэтому пиры едут ещё и в приглашении, а узел поднимается **до**
    // первого рукопожатия. Проверяется именно порядок: настройка, потом
    // включатель, и только потом кадр.
    let (mut driver, mut pair) =
        paired_with(1_000, String::new(), vec!["tls://пир.example:1337".to_owned()], false);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.breathe().await;
            let seen = pair.commands.lock().expect("список команд");
            let setup = seen
                .iter()
                .position(|command| matches!(command, TransportCommand::SetYgg(_)))
                .expect("узел обязан подниматься до первой связи");
            let enabled = seen
                .iter()
                .position(|command| matches!(
                    command,
                    TransportCommand::SetEnabled { transport: Transport::Ygg, enabled: true }
                ))
                .expect("поднятая настройка без включателя ступени не даёт");
            assert!(setup < enabled, "раннеру нечего поднимать до настройки");

            let first_frame = seen
                .iter()
                .position(|command| matches!(command, TransportCommand::Send { .. }));
            assert!(
                first_frame.is_none_or(|frame| enabled < frame),
                "узел обязан вставать раньше первого кадра: иначе ступень \
                 нужна для того, чтобы её поднять"
            );

            let TransportCommand::SetYgg(ratatosk_proto::ygg::YggSetup::Embedded {
                peers, ..
            }) = &seen[setup] else {
                panic!("без своего демона терминалу полагается встроенный узел");
            };
            assert_eq!(peers, &["tls://пир.example:1337".to_owned()], "пиры едут те, что дал телефон");
        } => {}
    }
}

#[tokio::test]
async fn a_terminal_without_peers_asks_the_transport_for_no_mesh_at_all() {
    // Обратная половина: пиров нет — и ступень не поднимается вовсе.
    // Поднятая без пиров, она стоила бы `Unavailable` на каждый кадр,
    // то есть съеденной попытки на пути к onion.
    let (mut driver, mut pair) = paired(1_000);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            let seen = pair.commands.lock().expect("список команд");
            assert!(
                !seen.iter().any(|command| matches!(command, TransportCommand::SetYgg(_))),
                "без пиров поднимать нечего"
            );
            assert!(
                !seen.iter().any(|command| matches!(
                    command,
                    TransportCommand::SetEnabled { transport: Transport::Ygg, .. }
                )),
                "ступень без узла обязана остаться выключенной"
            );
        } => {}
    }
}

#[tokio::test]
async fn the_same_peers_announced_again_do_not_restart_the_node() {
    // Объявление адреса приходит на **каждом** рукопожатии, а перезапуск
    // узла — это разрыв всего, что через него шло. Повтор с тем же списком
    // обязан быть тишиной.
    let (mut driver, mut pair) =
        paired_with(1_000, String::new(), vec!["tls://пир.example:1337".to_owned()], false);

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.settle(1_100).await;
            pair.breathe().await;
            let seen = pair.commands.lock().expect("список команд");
            let raised = seen
                .iter()
                .filter(|command| matches!(command, TransportCommand::SetYgg(_)))
                .count();
            assert_eq!(raised, 1, "узел поднят один раз, дальше объявления его не трогают");
        } => {}
    }
}

#[tokio::test]
async fn peers_kept_on_disk_raise_the_node_without_a_single_frame() {
    // Живой прогон сказал ровно это: «узел поднимается, только если есть
    // соединение по lan». Приглашение закрывает первый запуск, а дальше
    // всё, что терминал узнал по живому каналу, умирало вместе с процессом:
    // адрес и пиры в снимок не попадали.
    //
    // Здесь ссылка нарочно **без** пиров — такая, какую печатала сборка
    // постарше. Единственный путь, которым узел может встать, — снимок.
    let dir = temp_dir("mesh-cache");
    let cache = dir.join("snimok");

    let (mut driver, mut pair) = paired_with(
        1_000,
        String::new(),
        vec!["tls://пир.example:1337".to_owned()],
        true, // терминалу — ссылка без пиров
    );

    // Снимок кладёт на диск отдельный терминал того же сопряжения: файл
    // запечатан ключом из зерна, и чужой не открылся бы.
    let mut writer = CompanionClient::from_invite(&pair.invite, Box::new(SeededEntropy::new(7)));
    let sealed = writer.snapshot().expect("снимок");
    std::fs::write(&cache, &sealed).expect("файл кэша");

    tokio::select! {
        () = driver.run() => panic!("драйвер вышел раньше теста"),
        () = async {
            pair.breathe().await;
            {
                let seen = pair.commands.lock().expect("список команд");
                assert!(
                    !seen.iter().any(|command| matches!(command, TransportCommand::SetYgg(_))),
                    "до кэша поднимать нечего: в ссылке пиров нет"
                );
            }

            pair.handle
                .send(CompanionCommand::KeepCache { path: Some(cache.clone()) })
                .await
                .expect("команда принята");
            pair.breathe().await;

            let seen = pair.commands.lock().expect("список команд");
            let TransportCommand::SetYgg(ratatosk_proto::ygg::YggSetup::Embedded { peers, .. }) =
                seen.iter()
                    .find(|command| matches!(command, TransportCommand::SetYgg(_)))
                    .expect("узел обязан подняться с диска, без единого кадра")
            else {
                panic!("без своего демона терминалу полагается встроенный узел");
            };
            assert_eq!(peers, &["tls://пир.example:1337".to_owned()]);
        } => {}
    }
    let _ = std::fs::remove_dir_all(&dir);
}
