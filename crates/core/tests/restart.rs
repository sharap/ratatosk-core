//! Что переживает перезапуск клиента.
//!
//! До этого каждый запуск был новым устройством: менялся отпечаток, менялась
//! контакт-карточка, и все, кто её сохранил, теряли связь. Проверяется именно
//! это — по настоящему файлу, потому что база в памяти исчезает вместе
//! с процессом и проверить перезапуск не может в принципе.

use std::path::PathBuf;

use ratatosk_codec::ContactCard;
use ratatosk_core::io::{Command, Input};
use ratatosk_core::{vault, Engine, OsEntropy, SelfAddresses};
use ratatosk_crdt::Hlc;
use ratatosk_crypto::handshake::Role;
use ratatosk_crypto::{Identity, Session};
use ratatosk_proto::Transport;
use ratatosk_store::{SqliteStore, Store, StoredMessage, StoredSession};
use zeroize::Zeroizing;

/// Свой временный путь вместо зависимости ради одной функции.
struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ratatosk-restart-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        TempDb(path)
    }

    fn open(&self, key: &Zeroizing<[u8; 32]>) -> SqliteStore {
        let mut store = SqliteStore::open(&self.0, Zeroizing::new(**key)).expect("база открылась");
        store.migrate().expect("миграция прошла");
        store
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("db-shm"));
    }
}

/// Байты вложений в памяти: перезапуск проверяется по базе, а не по диску.
fn blobs() -> Box<ratatosk_store::MemoryBlobs> {
    Box::new(ratatosk_store::MemoryBlobs::new())
}

fn addresses() -> SelfAddresses {
    // Пустые адреса: доставке некуда идти, и сообщение получит `Undeliverable`.
    // Для этого теста так и надо — проверяется хранение, а не отправка.
    SelfAddresses { onion: String::new(), chatmail: String::new(), display_name: "я".to_owned() }
}

fn peer_card() -> (Vec<u8>, [u8; 32]) {
    let peer = Identity::generate();
    let card = ContactCard {
        ik: peer.public().ik,
        sk: peer.public().sk,
        onion: String::new(),
        chatmail: String::new(),
        display_name: "собеседник".to_owned(),
        version: 1,
    };
    (card.encode().expect("карточка кодируется"), card.ik)
}

#[test]
fn identity_contacts_and_history_survive_a_restart() {
    let db = TempDb::new("full");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    // --- первый запуск --------------------------------------------------
    let (fingerprint, chat) = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность заведена");
        let fingerprint = identity.fingerprint();

        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        assert_eq!(engine.restore().expect("подъём с чистой базы"), 0);

        engine
            .step(
                1_000,
                Input::Command(Command::AddContact {
                    card_bytes: card_bytes.clone(),
                    met_in_person: true,
                }),
            )
            .expect("контакт добавлен");

        let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);
        engine
            .step(
                2_000,
                Input::Command(Command::SendText {
                    chat, text: "до перезапуска".to_owned()
                }),
            )
            .expect("сообщение легло в историю");

        (fingerprint, chat)
    };

    // --- второй запуск --------------------------------------------------
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность поднята");
    assert_eq!(
        identity.fingerprint(),
        fingerprint,
        "отпечаток обязан совпасть: по нему контакты знают устройство (§3)"
    );

    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    assert_eq!(engine.restore().expect("контакты подняты"), 1);

    let contact = engine.contacts().get(&peer_ik).expect("тот же контакт");
    assert!(contact.verified, "§4.2: сверка голосом — разовое действие");
    assert_eq!(contact.card.display_name, "собеседник");

    let history = engine.store().messages(&chat, 10, None).expect("история читается");
    assert_eq!(history.len(), 1);
    assert_eq!(String::from_utf8_lossy(&history[0].body), "до перезапуска");
}

#[test]
fn a_read_receipt_is_not_re_sent_after_a_restart() {
    // §9.4: квитанцию о прочтении выпускает **вызов клиента**, и ничто иное.
    // Водяной знак жил в памяти, поэтому после перезапуска первое же открытие
    // чата отправляло её заново — то есть квитанция становилась следствием
    // старта приложения, а не действия человека. Собеседник видел, будто
    // переписку перечитывают, хотя её просто открыли.
    let db = TempDb::new("readmark");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);
    let msg_id = [7u8; 16];

    {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
            .unwrap();

        // Сессия и чужое сообщение заводятся напрямую: проверяется квитанция,
        // а не §8.2 и не приём кадра.
        let session = Session::derive(Role::Initiator, peer_ik, b"transcript", b"noise", 1_000);
        engine
            .store_mut()
            .put_session(&StoredSession {
                session_id: session.session_id,
                peer_ik,
                lan: true,
                snapshot: session.export().to_vec(),
                established_ms: 1_000,
            })
            .unwrap();
        engine
            .store_mut()
            .put_message(&StoredMessage {
                msg_id,
                chat_id: chat,
                sender_ik: peer_ik,
                hlc: Hlc::new(1_500, 0),
                body: b"chitay".to_vec(),
                received_ms: 1_500,
                status: None,
                edited_ms: None,
                forwarded: false,
                reply_to: None,
            })
            .unwrap();
        engine.restore().unwrap();

        let effects =
            engine.step(2_000, Input::Command(Command::MarkRead { chat, up_to: msg_id })).unwrap();
        assert!(
            effects.iter().any(|e| matches!(e, ratatosk_core::Effect::Send { .. })),
            "клиент позвал — квитанция обязана уйти: {effects:?}"
        );

        let again =
            engine.step(2_100, Input::Command(Command::MarkRead { chat, up_to: msg_id })).unwrap();
        assert!(again.is_empty(), "повторный вызов про то же место молчит: {again:?}");
    }

    // Перезапуск: знак поднимается с диска, и открытие чата само по себе
    // ничего не отправляет.
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();

    let effects =
        engine.step(3_000, Input::Command(Command::MarkRead { chat, up_to: msg_id })).unwrap();
    assert!(
        effects.is_empty(),
        "собеседнику уже сообщили; перезапуск — не повод сообщать снова: {effects:?}"
    );
}

#[test]
fn a_session_survives_and_its_send_counter_never_goes_back() {
    // Самое важное свойство всей персистентности. Откат отправляющего
    // счётчика после того, как система убила процесс, означает второй кадр
    // с той же парой «ключ, nonce»: для XChaCha20-Poly1305 это раскрытие
    // обоих сообщений, а не потеря одного.
    //
    // На Android это не редкий случай: процесс убивают постоянно, и «первая
    // отправка после запуска» — обычный режим, а не край.
    let db = TempDb::new("session");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    // Сессию неоткуда взять, не проведя рукопожатие, поэтому она заводится
    // напрямую: тест про хранение, а не про §8.2.
    let (session_id, counter_before) = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine
            .step(
                1_000,
                Input::Command(Command::AddContact {
                    card_bytes: card_bytes.clone(),
                    met_in_person: true,
                }),
            )
            .unwrap();

        let session = Session::derive(Role::Initiator, peer_ik, b"transcript", b"noise", 1_000);
        let session_id = session.session_id;
        engine
            .store_mut()
            .put_session(&StoredSession {
                session_id,
                peer_ik,
                lan: true,
                snapshot: session.export().to_vec(),
                established_ms: 1_000,
            })
            .unwrap();
        (session_id, 0u64)
    };

    // Перезапуск: сессия поднимается, и отправка продолжает ту же цепочку.
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    assert_eq!(engine.restore().unwrap(), 1, "контакт поднят");
    assert_eq!(engine.session_count(), 1, "сессия поднята");

    // LAN включён и контакт «виден» — иначе §5.4 отправлять не станет.
    engine.step(2_000, Input::Command(Command::SetLanEnabled(true))).unwrap();
    engine.step(2_000, Input::SeenOnLan { peer_ik }).unwrap();
    engine
        .step(2_100, Input::Command(Command::SendText { chat, text: "после смерти".to_owned() }))
        .unwrap();

    let snapshot = engine
        .store()
        .sessions()
        .unwrap()
        .into_iter()
        .find(|s| s.session_id == session_id)
        .expect("сессия на месте");
    let after = Session::restore(&snapshot.snapshot).expect("снимок читается");
    assert!(
        after.send.counter() > counter_before,
        "отправка обязана продвинуть цепочку и записать её"
    );
}

#[test]
fn a_lan_link_loss_keeps_the_session_but_silence_closes_it() {
    // Раньше здесь проверялось обратное: разрыв LAN закрывал сессию. Читалось
    // это как §5.4, но §5.4 запрещает **переносить** сессию в чужое семейство
    // транспортов, а не переживать разрыв сокета. Ошибка стоила дорого: сессия
    // умирала у одной стороны и оставалась у другой, та отправляла кадры
    // в никуда и видела «не доставлено» при живой связи. Лечилось только
    // удалением контакта.
    //
    // Закрывает сессию теперь одно: кадр ушёл, а квитанции в срок нет.
    let db = TempDb::new("lanloss");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine
        .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
        .unwrap();

    let session = Session::derive(Role::Initiator, peer_ik, b"transcript", b"noise", 1_000);
    let session_id = session.session_id;
    engine
        .store_mut()
        .put_session(&StoredSession {
            session_id,
            peer_ik,
            lan: true,
            snapshot: session.export().to_vec(),
            established_ms: 1_000,
        })
        .unwrap();
    engine.restore().unwrap();
    assert_eq!(engine.session_count(), 1);

    // Разрыв соединения — событие сокета. Сессия остаётся.
    engine.step(2_000, Input::ConnectionLost { peer_ik, via: Transport::Lan }).unwrap();
    assert_eq!(engine.session_count(), 1, "разрыв сокета не закрывает сессию");
    assert_eq!(engine.store().sessions().unwrap().len(), 1, "и с диска не убирает");

    // А вот молчание в ответ на ушедший кадр — закрывает.
    engine.step(3_000, Input::Command(Command::SetLanEnabled(true))).unwrap();
    engine.step(3_000, Input::SeenOnLan { peer_ik }).unwrap();
    let effects = engine
        .step(3_100, Input::Command(Command::SendText { chat, text: "есть кто?".to_owned() }))
        .unwrap();
    let token = effects
        .iter()
        .find_map(|e| match e {
            ratatosk_core::Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("прямой канал заводит срок ожидания квитанции");

    engine.step(9_000, Input::Timer { token }).unwrap();
    assert_eq!(engine.session_count(), 0, "несогласованная сессия закрыта в памяти");
    assert!(engine.store().sessions().unwrap().is_empty(), "и на диске тоже");
}

#[test]
fn a_network_change_forgets_what_it_knew_about_the_local_network() {
    // §5.1: адреса локальной сети принадлежат конкретной сети. Сохранив
    // видимость после перехода на другой Wi-Fi, §5.4 продолжал бы выбирать
    // LAN и платить таймаутом за каждое сообщение.
    let db = TempDb::new("netchange");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine
        .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
        .unwrap();
    engine.step(1_000, Input::Command(Command::SetLanEnabled(true))).unwrap();
    engine.step(1_000, Input::SeenOnLan { peer_ik }).unwrap();
    assert!(engine.contacts()[&peer_ik].availability.seen_on_lan);

    let effects = engine.step(2_000, Input::Command(Command::NetworkChanged)).unwrap();

    assert!(
        !engine.contacts()[&peer_ik].availability.seen_on_lan,
        "видимость в прежней сети недействительна"
    );
    assert!(
        effects.iter().any(|e| matches!(e, ratatosk_core::Effect::RestartLan)),
        "транспорт обязан подняться заново"
    );
}

#[test]
fn a_network_change_with_lan_off_does_not_turn_it_on() {
    // Смена сети — не решение пользователя. §5.1 держит LAN выключенным,
    // пока его не включили сознательно.
    let db = TempDb::new("netchange-off");
    let db_key = Zeroizing::new([5u8; 32]);

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());

    let effects = engine.step(1_000, Input::Command(Command::NetworkChanged)).unwrap();
    assert!(effects.is_empty(), "выключенный LAN переоткрывать нечего");
}

#[test]
fn a_wrong_pin_refuses_instead_of_starting_over() {
    // Худший исход — молча завести новую личность: пользователь увидит пустой
    // клиент и решит, что переписка потеряна, хотя он просто ошибся в PIN.
    let db = TempDb::new("wrongpin");
    {
        let mut store = db.open(&Zeroizing::new([5u8; 32]));
        vault::load_or_create(&mut store, &Zeroizing::new([5u8; 32])).expect("личность заведена");
    }

    let mut store = db.open(&Zeroizing::new([6u8; 32]));
    assert!(vault::load_or_create(&mut store, &Zeroizing::new([6u8; 32])).is_err());
}

#[test]
fn a_message_sent_with_nowhere_to_go_is_still_kept() {
    // §14: сообщение, которому некуда ехать, остаётся в истории и помечается,
    // а не исчезает. После перезапуска оно обязано быть на месте.
    let db = TempDb::new("undeliverable");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: false }))
            .unwrap();
        let effects = engine
            .step(2_000, Input::Command(Command::SendText { chat, text: "в пустоту".to_owned() }))
            .unwrap();
        assert!(
            effects.iter().any(|e| matches!(
                e,
                ratatosk_core::Effect::Notify(ratatosk_core::Event::StatusChanged {
                    status: ratatosk_proto::DeliveryStatus::Undeliverable,
                    ..
                })
            )),
            "пользователь обязан узнать, что сообщение не ушло"
        );
    }

    let store = db.open(&db_key);
    assert_eq!(store.messages(&chat, 10, None).unwrap().len(), 1);
}

#[test]
fn a_waiting_message_still_waits_after_a_restart() {
    // Статус «отправим, когда появится» — обещание, и оно чего-то стоит только
    // если переживает перезапуск. В памяти оно не переживало бы убитый процесс,
    // а на Android процесс убивают постоянно: человек видел бы «ждём»
    // у сообщения, к которому никто уже не вернётся. Ровно та нечестность,
    // которую запрещает §14.
    let db = TempDb::new("waiting");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    let msg_id = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
            .unwrap();
        // LAN включён, но собеседника никто не видел: отправлять некуда.
        engine.step(1_000, Input::Command(Command::SetLanEnabled(true))).unwrap();

        let effects = engine
            .step(2_000, Input::Command(Command::SendText { chat, text: "подожду".to_owned() }))
            .unwrap();
        let token = effects
            .iter()
            .find_map(|e| match e {
                ratatosk_core::Effect::SetTimer { token, .. } => Some(*token),
                _ => None,
            })
            .expect("срок обнаружения");
        engine.step(6_000, Input::Timer { token }).unwrap();

        let stored = engine.store().messages(&chat, 10, None).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].status.and_then(ratatosk_proto::DeliveryStatus::from_code),
            Some(ratatosk_proto::DeliveryStatus::Waiting),
            "сообщение ждёт, а не потеряно"
        );
        assert_eq!(engine.store().outbox().unwrap().len(), 1, "очередь легла на диск");
        stored[0].msg_id
    };

    // Перезапуск: очередь поднимается, и первое же включение LAN приводит её
    // в движение — сообщение уходит, как только собеседник находится.
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();
    assert_eq!(engine.store().outbox().unwrap().len(), 1, "очередь на месте");

    engine.step(10_000, Input::Command(Command::SetLanEnabled(true))).unwrap();
    let effects = engine.step(11_000, Input::SeenOnLan { peer_ik }).unwrap();
    assert!(
        effects.iter().any(|e| matches!(e, ratatosk_core::Effect::Send { .. })),
        "обещание, пережившее перезапуск, обязано исполниться: {effects:?}"
    );

    // И статус сообщения при этом тот же — ждало, не пропало.
    let stored = engine.store().messages(&chat, 10, None).unwrap();
    assert_eq!(stored[0].msg_id, msg_id);
}

#[test]
fn a_waiting_message_for_a_deleted_contact_stops_waiting() {
    // Обещание надо уметь снимать: контакта больше нет, ехать некому,
    // и «ждём, когда появится» превратилось бы в ожидание без конца.
    let db = TempDb::new("waiting-gone");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine
        .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
        .unwrap();
    engine.step(1_000, Input::Command(Command::SetLanEnabled(true))).unwrap();

    let effects = engine
        .step(2_000, Input::Command(Command::SendText { chat, text: "подожду".to_owned() }))
        .unwrap();
    let token = effects
        .iter()
        .find_map(|e| match e {
            ratatosk_core::Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("срок обнаружения");
    engine.step(6_000, Input::Timer { token }).unwrap();
    assert_eq!(engine.store().outbox().unwrap().len(), 1);

    engine
        .step(7_000, Input::Command(Command::DeleteContact { peer_ik, purge_history: false }))
        .unwrap();
    assert!(engine.store().outbox().unwrap().is_empty(), "ждать больше нечего и некого");
}
