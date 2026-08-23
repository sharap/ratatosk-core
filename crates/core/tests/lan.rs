//! Два узла через настоящий TCP на loopback.
//!
//! Отличие от `pair.rs` и `scenarios.rs` в том, что здесь между ядрами нет
//! ни симуляции, ни прямой передачи `Vec<u8>` из рук в руки: кадры уходят
//! в сокет и приходят из сокета, время настоящее, а таймеры ставит драйвер.
//! Это последняя ступень перед двумя устройствами в одной комнате — всё,
//! что здесь зелёное, отличается от живой проверки только тем, что mDNS
//! заменён явной записью адреса.
//!
//! Обнаружение (mDNS) сознательно выключено: мультикаст в CI не работает,
//! и проверять через него передачу значило бы проверять сеть стенда.

#![cfg(feature = "driver")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use ratatosk_codec::ContactCard;
use ratatosk_core::driver::{Driver, DriverHandle, EventStream};
use ratatosk_core::{Command, Engine, Event, OsEntropy, SelfAddresses};
use ratatosk_crypto::Identity;
use ratatosk_store::{MemoryStore, Store};
use ratatosk_transport::{LanConfig, LanDirectory, LanRunner};

/// Потолок ожидания. Loopback отвечает за миллисекунды; секунды здесь —
/// чтобы тест падал с внятным «не дождались», а не висел.
const PATIENCE: Duration = Duration::from_secs(10);

struct Node {
    handle: DriverHandle,
    events: EventStream,
    directory: LanDirectory,
    card: Vec<u8>,
    ik: [u8; 32],
    port: u16,
}

type Wired = (Driver<MemoryStore, LanRunner>, Node);

/// Узел собирается, но не запускается: цикл драйвера гоняется вызывающим
/// через `select!`, а не `spawn`. Так тест не требует от ядра `Send` —
/// а состояние рукопожатия из `snow` его и не обещает.
/// Байты вложений в памяти: этот тест про сеть, а не про диск.
fn blobs() -> Box<ratatosk_store::MemoryBlobs> {
    Box::new(ratatosk_store::MemoryBlobs::new())
}

async fn spawn_node(name: &str) -> Wired {
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция хранилища в памяти");

    // Адреса onion и chatmail пустые: §5.4 иначе увёл бы доставку на
    // транспорты, которых в этом тесте нет, и отказ выглядел бы как отказ LAN.
    let addresses = SelfAddresses {
        onion: String::new(),
        chatmail: String::new(),
        display_name: name.to_owned(),
    };
    let engine = Engine::new(Identity::generate(), store, blobs(), Box::new(OsEntropy), addresses);
    let card = engine.own_card().encode().expect("своя карточка кодируется");
    let ik = engine.own_card().ik;

    let config = LanConfig { enabled: true, port: 0, discovery: false };
    let runner = LanRunner::start(config, ik).await.expect("LAN поднимается");
    let port = runner.port();
    let directory = runner.directory();

    let (driver, handle, events) = Driver::new(engine, runner);

    // §5.1: LAN выключен по умолчанию, включается сознательно. Команда
    // ложится в очередь и будет обработана, как только цикл начнёт крутиться.
    handle
        .send(Command::SetTransportEnabled {
            transport: ratatosk_proto::Transport::Lan,
            enabled: true,
        })
        .await
        .expect("драйвер жив");

    (driver, Node { handle, events, directory, card, ik, port })
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Добавляет контакт и дожидается подтверждения.
///
/// Ждать обязательно: адрес записывается следующим шагом, а «виден в LAN»
/// и «контакт добавлен» идут разными каналами.
async fn introduce(node: &mut Node, peer_card: &[u8], peer_ik: [u8; 32], peer_port: u16) {
    node.handle
        .send(Command::AddContact { card_bytes: peer_card.to_vec(), met_in_person: true })
        .await
        .expect("драйвер жив");

    let added = tokio::time::timeout(PATIENCE, async {
        while let Some(event) = node.events.next().await {
            if matches!(event, Event::ContactAdded { .. }) {
                return true;
            }
        }
        false
    })
    .await
    .expect("контакт добавлен в срок");
    assert!(added, "ядро не подтвердило добавление контакта");

    node.directory.note(peer_ik, loopback(peer_port));
}

/// Дожидается статуса доставки, пропуская всё остальное.
///
/// Отдельно от [`await_text`], и порядок вызовов важен: поток событий один,
/// читается он один раз, и всё пропущенное пропадает навсегда. Квитанция
/// о доставке приходит **раньше** ответного сообщения, поэтому ждать её
/// надо до него, а не после.
async fn await_status(node: &mut Node, wanted: ratatosk_proto::DeliveryStatus) {
    let seen = tokio::time::timeout(PATIENCE, async {
        while let Some(event) = node.events.next().await {
            if let Event::StatusChanged { status, .. } = event {
                if status == wanted {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or_else(|_| panic!("статус {wanted:?} не пришёл в срок"));
    assert!(seen, "драйвер остановился, не объявив статус {wanted:?}");
}

/// Дожидается сообщения и возвращает его текст.
async fn await_text(node: &mut Node) -> String {
    tokio::time::timeout(PATIENCE, async {
        while let Some(event) = node.events.next().await {
            let Event::MessageReceived { chat, msg_id } = event else {
                continue;
            };
            let messages = node.handle.messages(chat, 50).await.expect("драйвер жив");
            let found = messages
                .iter()
                .find(|v| v.message.msg_id == msg_id)
                .expect("событие ссылается на сообщение, которого нет в хранилище");
            return String::from_utf8(found.message.body.clone()).expect("текст в UTF-8");
        }
        panic!("драйвер остановился, не доставив сообщение");
    })
    .await
    .expect("сообщение пришло в срок")
}

#[tokio::test]
async fn two_engines_exchange_text_over_real_tcp() {
    let (mut alice_driver, mut alice) = spawn_node("Алиса").await;
    let (mut bob_driver, mut bob) = spawn_node("Боб").await;

    let (alice_card, alice_ik, alice_port) = (alice.card.clone(), alice.ik, alice.port);
    let (bob_card, bob_ik, bob_port) = (bob.card.clone(), bob.ik, bob.port);

    let exchange = async {
        introduce(&mut alice, &bob_card, bob_ik, bob_port).await;
        introduce(&mut bob, &alice_card, alice_ik, alice_port).await;

        let chat_with_bob = Engine::<MemoryStore>::chat_id_for(&bob_ik);
        alice
            .handle
            .send(Command::SendText {
                chat: chat_with_bob, text: "привет из LAN".to_owned()
            })
            .await
            .expect("драйвер жив");

        assert_eq!(await_text(&mut bob).await, "привет из LAN");

        // §9.4: доставку подтверждает получатель, а не таймер. Ждём **здесь**,
        // до ответного сообщения: квитанция уходит сразу после расшифровки,
        // то есть раньше, чем Боб успеет что-то написать.
        //
        // Заодно это проверка срока: страховочный таймер прямого канала —
        // пять секунд, а `PATIENCE` десять. Приди «доставлено» от таймера,
        // а не от квитанции, статус был бы `Sent`, и тест бы не прошёл.
        await_status(&mut alice, ratatosk_proto::DeliveryStatus::Delivered).await;

        // Обратное направление той же сессии: §8.3 устанавливает её один раз,
        // и ответ не должен требовать второго рукопожатия.
        let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice_ik);
        bob.handle
            .send(Command::SendText {
                chat: chat_with_alice, text: "и тебе привет".to_owned()
            })
            .await
            .expect("драйвер жив");

        assert_eq!(await_text(&mut alice).await, "и тебе привет");
    };

    tokio::select! {
        result = alice_driver.run() => panic!("драйвер Алисы остановился: {result:?}"),
        result = bob_driver.run() => panic!("драйвер Боба остановился: {result:?}"),
        () = exchange => {}
    }
}

/// Заводит «молчуна»: сокет, который соединение принимает и держит, но
/// не отвечает ни байтом. Возвращает порт.
///
/// Принятые соединения складываются в вектор и не закрываются: закрытие
/// дало бы ядру отправителя ошибку записи, то есть явный отказ — а проверить
/// надо ровно противоположное, тишину при живом сокете.
fn silent_listener() -> u16 {
    let listener = std::net::TcpListener::bind(loopback(0)).expect("сокет-молчун слушает");
    let port = listener.local_addr().expect("у сокета есть адрес").port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    port
}

#[tokio::test]
async fn a_peer_that_accepts_but_stays_silent_leaves_the_message_waiting() {
    // Тот самый случай, который выглядел как «ошибка не появляется»: узел
    // ушёл, но сокет на его адресе ещё жив (или это чужой процесс на том же
    // порту). Запись в такой сокет ядро операционной системы принимает
    // молча, поэтому транспорт об отказе не сообщает — и если считать
    // «отправили в сокет» успехом, откат §5.4 не запустится, а пользователь
    // увидит галочку вместо ошибки.
    //
    // Отличие от теста ниже принципиальное: там соединение отвергается,
    // здесь — устанавливается. Единственный, кто может объявить исход,
    // это срок ожидания квитанции (§9.4).
    let (mut alice_driver, mut alice) = spawn_node("Алиса").await;

    let ghost = Identity::generate();
    let ghost_card = ContactCard {
        ik: ghost.public().ik,
        sk: ghost.public().sk,
        onion: String::new(),
        chatmail: String::new(),
        display_name: "молчун".to_owned(),
        version: 1,
    };
    let ghost_ik = ghost_card.ik;
    let bytes = ghost_card.encode().expect("карточка кодируется");
    let port = silent_listener();

    let probe = async {
        introduce(&mut alice, &bytes, ghost_ik, port).await;

        let chat = Engine::<MemoryStore>::chat_id_for(&ghost_ik);
        alice
            .handle
            .send(Command::SendText { chat, text: "ты там?".to_owned() })
            .await
            .expect("драйвер жив");

        await_status(&mut alice, ratatosk_proto::DeliveryStatus::Waiting).await;
    };

    tokio::select! {
        result = alice_driver.run() => panic!("драйвер остановился: {result:?}"),
        () = probe => {}
    }
}

#[tokio::test]
async fn a_peer_that_never_answers_leaves_the_message_waiting() {
    // Собеседник, которого нет: §14 требует показать пользователю, что
    // сообщение не ушло, а не потерять его молча. Адрес указывает в порт,
    // который никто не слушает.
    let (mut alice_driver, mut alice) = spawn_node("Алиса").await;

    let ghost = Identity::generate();
    let ghost_card = ContactCard {
        ik: ghost.public().ik,
        sk: ghost.public().sk,
        onion: String::new(),
        chatmail: String::new(),
        display_name: "призрак".to_owned(),
        version: 1,
    };
    let ghost_ik = ghost_card.ik;
    let bytes = ghost_card.encode().expect("карточка кодируется");

    // Порт занимаем и тут же отпускаем: так адрес заведомо никем не слушается,
    // а выбран не наугад.
    let dead_port = {
        let socket = tokio::net::TcpListener::bind(loopback(0)).await.unwrap();
        socket.local_addr().unwrap().port()
    };

    let probe = async {
        introduce(&mut alice, &bytes, ghost_ik, dead_port).await;

        let chat = Engine::<MemoryStore>::chat_id_for(&ghost_ik);
        alice
            .handle
            .send(Command::SendText { chat, text: "есть кто?".to_owned() })
            .await
            .expect("драйвер жив");

        // §14: сообщение, которое не ушло, обязано быть помечено, а не
        // потеряно. Метка — `Waiting`: собеседника нет в сети, но локальная
        // сеть включена, и он может появиться; сообщение ждёт этого на диске.
        // Ждём именно этот статус, а не «первый попавшийся»: первым мог бы
        // прийти `Sent` от страховочного таймера, и тест бы прошёл, ничего
        // не проверив.
        await_status(&mut alice, ratatosk_proto::DeliveryStatus::Waiting).await;
    };

    tokio::select! {
        result = alice_driver.run() => panic!("драйвер остановился: {result:?}"),
        () = probe => {}
    }
}
