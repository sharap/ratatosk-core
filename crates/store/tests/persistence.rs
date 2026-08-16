//! Что переживает перезапуск.
//!
//! Проверка идёт по настоящему файлу, а не по базе в памяти: `in_memory`
//! исчезает вместе с соединением и поэтому не может проверить ровно то,
//! ради чего всё это писалось.

use std::path::PathBuf;

use ratatosk_crdt::Hlc;
use ratatosk_store::{SqliteStore, Store, StoredContact, StoredMessage};
use zeroize::Zeroizing;

/// Свой временный путь вместо зависимости ради одной функции.
struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let mut path = std::env::temp_dir();
        // Имя должно быть уникальным между параллельными тестами: `cargo test`
        // гоняет их в потоках одного процесса, и общий файл дал бы гонку,
        // которая выглядит как плавающий отказ SQLite.
        path.push(format!("ratatosk-{tag}-{}-{:?}.db", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_file(&path);
        TempDb(path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        // WAL и индекс журнала лежат рядом отдельными файлами.
        let _ = std::fs::remove_file(self.0.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("db-shm"));
    }
}

fn key(byte: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([byte; 32])
}

fn message(n: u8, wall: u64) -> StoredMessage {
    StoredMessage {
        msg_id: [n; 16],
        chat_id: [9u8; 16],
        sender_ik: [n; 32],
        hlc: Hlc::new(wall, 0),
        body: format!("сообщение {n}").into_bytes(),
        received_ms: wall,
        status: None,
    }
}

fn contact(n: u8) -> StoredContact {
    StoredContact {
        ik: [n; 32],
        sk: [n.wrapping_add(1); 32],
        onion: String::new(),
        chatmail: String::new(),
        display_name: format!("контакт {n}"),
        card_version: 1,
        card_bytes: vec![n; 64],
        verified: n % 2 == 0,
        created_ms: 1000,
    }
}

#[test]
fn messages_survive_reopening() {
    let db = TempDb::new("messages");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        for n in 1..=3u8 {
            store.put_message(&message(n, u64::from(n) * 100)).unwrap();
        }
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.messages(&[9u8; 16], 10, None).unwrap();
    assert_eq!(
        found.iter().map(|m| String::from_utf8_lossy(&m.body).into_owned()).collect::<Vec<_>>(),
        vec!["сообщение 1", "сообщение 2", "сообщение 3"],
        "порядок задаёт HLC (§9.1), а не порядок вставки"
    );
}

#[test]
fn the_newest_window_comes_back() {
    let db = TempDb::new("window");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    for n in 1..=5u8 {
        store.put_message(&message(n, u64::from(n) * 100)).unwrap();
    }

    // Чат листается назад: нужны последние сообщения, а не первые.
    let found = store.messages(&[9u8; 16], 2, None).unwrap();
    assert_eq!(found.iter().map(|m| m.msg_id[0]).collect::<Vec<_>>(), vec![4, 5]);

    let older = store.messages(&[9u8; 16], 2, Some(Hlc::new(300, 0))).unwrap();
    assert_eq!(older.iter().map(|m| m.msg_id[0]).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn a_wrong_pin_cannot_read_bodies() {
    // Главное свойство §8.6: файл, попавший в чужие руки, без PIN не читается.
    let db = TempDb::new("wrongpin");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(
        store.messages(&[9u8; 16], 10, None).is_err(),
        "чужой ключ обязан получить отказ, а не мусор"
    );
}

#[test]
fn contacts_and_verification_survive_reopening() {
    let db = TempDb::new("contacts");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_contact(&contact(2)).unwrap();
        store.put_contact(&contact(3)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.contacts().unwrap();
    assert_eq!(found.len(), 2);
    // §4.2: сверка голосом — разовое действие, просить её заново нельзя.
    assert!(found.iter().find(|c| c.ik[0] == 2).unwrap().verified);
    assert!(!found.iter().find(|c| c.ik[0] == 3).unwrap().verified);
    // §6: карточка хранится принятыми байтами, а не пересобирается.
    assert_eq!(found.iter().find(|c| c.ik[0] == 2).unwrap().card_bytes, vec![2u8; 64]);
}

#[test]
fn a_repeated_contact_replaces_the_previous_one() {
    let db = TempDb::new("recontact");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_contact(&contact(3)).unwrap();
    let mut verified = contact(3);
    verified.verified = true;
    store.put_contact(&verified).unwrap();

    let found = store.contacts().unwrap();
    assert_eq!(found.len(), 1, "тот же ik — та же строка");
    assert!(found[0].verified);
}

#[test]
fn dedup_survives_reopening() {
    // §9.2: окно дедупликации обязано пережить перезапуск, иначе повтор
    // из почты покажется пользователю вторым сообщением.
    let db = TempDb::new("dedup");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        assert!(store.note_seen(&[7u8; 16], 100).unwrap(), "первый раз — свежий");
        assert!(!store.note_seen(&[7u8; 16], 100).unwrap(), "второй — уже видели");
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(!store.note_seen(&[7u8; 16], 200).unwrap(), "и после перезапуска — тоже");
}

#[test]
fn meta_round_trips() {
    let db = TempDb::new("meta");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        assert_eq!(store.meta("нет такого").unwrap(), None);
        store.put_meta("ключ", "значение".as_bytes()).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert_eq!(store.meta("ключ").unwrap().as_deref(), Some("значение".as_bytes()));
}

#[test]
fn migrating_twice_is_harmless() {
    // Обычный путь: клиент открывает базу при каждом запуске и мигрирует.
    let db = TempDb::new("migrate");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    assert_eq!(store.messages(&[9u8; 16], 10, None).unwrap().len(), 1);
}
