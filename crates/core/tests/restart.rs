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
use ratatosk_crypto::Identity;
use ratatosk_store::{SqliteStore, Store};
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

fn addresses() -> SelfAddresses {
    // Пустые адреса: доставке некуда идти, и сообщение получит `Undeliverable`.
    // Для этого теста так и надо — проверяется хранение, а не отправка.
    SelfAddresses {
        onion: String::new(),
        chatmail: String::new(),
        display_name: "я".to_owned(),
    }
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

        let mut engine = Engine::new(identity, store, Box::new(OsEntropy), addresses());
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
                Input::Command(Command::SendText { chat, text: "до перезапуска".to_owned() }),
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

    let mut engine = Engine::new(identity, store, Box::new(OsEntropy), addresses());
    assert_eq!(engine.restore().expect("контакты подняты"), 1);

    let contact = engine.contacts().get(&peer_ik).expect("тот же контакт");
    assert!(contact.verified, "§4.2: сверка голосом — разовое действие");
    assert_eq!(contact.card.display_name, "собеседник");

    let history = engine.store().messages(&chat, 10, None).expect("история читается");
    assert_eq!(history.len(), 1);
    assert_eq!(String::from_utf8_lossy(&history[0].body), "до перезапуска");
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
        let mut engine = Engine::new(identity, store, Box::new(OsEntropy), addresses());
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
