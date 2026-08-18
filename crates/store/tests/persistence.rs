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
        path.push(format!(
            "ratatosk-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
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
        edited_ms: None,
        forwarded: false,
        reply_to: None,
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
        local_name: None,
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

#[test]
fn an_avatar_round_trips_and_is_sealed() {
    let db = TempDb::new("avatar");
    let owner = [3u8; 32];
    let bytes = vec![0x89, b'P', b'N', b'G', 1, 2, 3, 4];

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        assert!(!store.has_avatar(&owner).unwrap());

        store
            .put_avatar(
                &owner,
                &ratatosk_store::StoredAvatar { bytes: bytes.clone(), updated_ms: 7 },
            )
            .unwrap();
        assert!(store.has_avatar(&owner).unwrap());
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.avatar(&owner).unwrap().expect("аватарка на месте");
    assert_eq!(found.bytes, bytes);
    assert_eq!(found.updated_ms, 7, "момент установки нужен, чтобы старая копия не затёрла новую");

    // Тот же файл чужим ключом: содержимое не открывается. Проверка того же
    // свойства, что и у тела сообщения, — картинка тоже содержимое (§12).
    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(wrong.avatar(&owner).is_err(), "чужой ключ не должен открывать аватарку");
    assert!(wrong.has_avatar(&owner).unwrap(), "но факт наличия строки виден — она не шифруется");
}

#[test]
fn deleting_an_avatar_leaves_nothing_behind() {
    let db = TempDb::new("avatar-del");
    let owner = [4u8; 32];
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store
        .put_avatar(
            &owner,
            &ratatosk_store::StoredAvatar { bytes: vec![0x89, b'P'], updated_ms: 1 },
        )
        .unwrap();
    store.delete_avatar(&owner).unwrap();

    assert!(!store.has_avatar(&owner).unwrap());
    assert_eq!(store.avatar(&owner).unwrap(), None);
}

#[test]
fn migrating_a_populated_database_keeps_it() {
    // Аватарки приехали второй миграцией, а у пользователя уже есть
    // переписка: появление новой таблицы не должно требовать начать
    // с чистого листа.
    //
    // Настоящую базу версии 1 этот тест подделать не может — сырого SQL
    // наружу нет, и `migrate` применяет всё сразу. Поэтому проверяется
    // ближайшее: повторная миграция поверх заполненной базы. Что именно
    // применяется поверх версии 1, стережёт `migration_count_matches_version`
    // в самой схеме.
    let db = TempDb::new("avatar-migrate");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store
        .put_avatar(&[5u8; 32], &ratatosk_store::StoredAvatar { bytes: vec![0x89], updated_ms: 2 })
        .unwrap();
    assert_eq!(store.messages(&[9u8; 16], 10, None).unwrap().len(), 1, "переписка на месте");
}

#[test]
fn a_local_name_round_trips_and_is_sealed() {
    // Локальное имя — заметка о человеке, поэтому шифруется наравне с телом
    // сообщения. По проводу оно не едет никогда: собеседник не должен знать,
    // как его записали, и не должен иметь возможности это подделать.
    let db = TempDb::new("localname");
    let mut with_name = contact(3);
    with_name.local_name = Some("Аня с курсов".to_owned());

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_contact(&with_name).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.contacts().unwrap().remove(0);
    assert_eq!(found.local_name.as_deref(), Some("Аня с курсов"));

    // Чужим ключом имя не открывается, но сам контакт читается: без имени
    // с человеком всё ещё можно переписываться, а без контакта — нет.
    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    let found = wrong.contacts().unwrap().remove(0);
    assert_eq!(found.local_name, None, "чужой ключ не открывает подпись");
    assert_eq!(found.ik, with_name.ik, "но контакт на месте");
}

#[test]
fn deleting_a_contact_takes_its_sessions_and_avatar() {
    // §12: удаление обязано удалять. Пережившая контакт сессия — это ключевой
    // материал для собеседника, которого у пользователя больше нет.
    let db = TempDb::new("delcontact");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    let victim = contact(4);
    store.put_contact(&victim).unwrap();
    store
        .put_avatar(
            &victim.ik,
            &ratatosk_store::StoredAvatar { bytes: vec![0x89, b'P'], updated_ms: 1 },
        )
        .unwrap();
    store
        .put_session(&ratatosk_store::StoredSession {
            session_id: 77,
            peer_ik: victim.ik,
            lan: true,
            snapshot: vec![1, 2, 3],
            established_ms: 1,
        })
        .unwrap();

    store.delete_contact(&victim.ik).unwrap();

    assert!(store.contacts().unwrap().is_empty());
    assert!(!store.has_avatar(&victim.ik).unwrap());
    assert!(store.sessions().unwrap().is_empty(), "сессия обязана уйти вместе с контактом");
}

#[test]
fn deleting_a_chat_takes_its_messages() {
    let db = TempDb::new("delchat");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();
    assert_eq!(store.messages(&[9u8; 16], 10, None).unwrap().len(), 2);

    store.delete_chat(&[9u8; 16]).unwrap();
    assert!(store.messages(&[9u8; 16], 10, None).unwrap().is_empty());
}

#[test]
fn a_tombstone_hides_the_message_and_wipes_its_body() {
    // Надгробие хранит идентификатор, а не текст. Держать тело девяносто
    // суток (§12) после того, как человек нажал «удалить», значит не удалить.
    let db = TempDb::new("tombstone");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();

    assert!(store.tombstone_message(&[1u8; 16], 1_000).unwrap());
    assert!(!store.tombstone_message(&[1u8; 16], 1_000).unwrap(), "второй раз удалять нечего");

    let left = store.messages(&[9u8; 16], 10, None).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].msg_id, [2u8; 16]);
    assert_eq!(store.message(&[1u8; 16]).unwrap().map(|m| m.msg_id), None, "удалённое не читается");
}

#[test]
fn a_late_copy_does_not_resurrect_a_deleted_message() {
    // §9.2: та же копия законно приходит вторым транспортом. Без этой
    // проверки `INSERT OR REPLACE` затёр бы надгробие новой строкой —
    // то есть вернул бы в чат то, что человек убрал.
    let db = TempDb::new("resurrect");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.tombstone_message(&[1u8; 16], 1_000).unwrap();

    store.put_message(&message(1, 100)).unwrap();
    assert!(store.messages(&[9u8; 16], 10, None).unwrap().is_empty(), "удалённое не воскресает");
}

#[test]
fn tombstones_expire_after_ninety_days_and_take_the_row() {
    let db = TempDb::new("tombstone-ttl");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.tombstone_message(&[1u8; 16], 1_000).unwrap();

    let ttl = ratatosk_store::compaction::TOMBSTONE_TTL_MS;
    assert_eq!(store.compact(ratatosk_store::Task::Tombstones, 1_000 + ttl - 1).unwrap(), 0);
    assert_eq!(store.compact(ratatosk_store::Task::Tombstones, 1_000 + ttl).unwrap(), 1);

    // Строки больше нет — значит, та же копия снова считается новой. Это
    // осознанная граница: §9.2 держит окно дедупликации тридцать суток,
    // надгробие — девяносто, и после них сообщение никто уже не пришлёт.
    store.put_message(&message(1, 100)).unwrap();
    assert_eq!(store.messages(&[9u8; 16], 10, None).unwrap().len(), 1);
}

#[test]
fn clearing_a_chat_leaves_tombstones_not_bodies() {
    let db = TempDb::new("tombstone-chat");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    for n in 1..=3u8 {
        store.put_message(&message(n, u64::from(n) * 100)).unwrap();
    }
    assert_eq!(store.tombstone_chat(&[9u8; 16], 5_000).unwrap(), 3);
    assert_eq!(store.tombstone_chat(&[9u8; 16], 6_000).unwrap(), 0, "чистить больше нечего");
    assert!(store.messages(&[9u8; 16], 10, None).unwrap().is_empty());
}

#[test]
fn an_outbox_entry_round_trips_and_is_sealed() {
    // Конверт незапечатан, то есть содержит текст: на диске он обязан лежать
    // зашифрованным наравне с телом сообщения (§12).
    let db = TempDb::new("outbox");
    let entry = ratatosk_store::StoredOutbox {
        msg_id: [8u8; 16],
        recipient_ik: [9u8; 32],
        envelope: "жду сети".as_bytes().to_vec(),
        queued_ms: 4_000,
    };

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        assert!(store.outbox().unwrap().is_empty());
        store.put_outbox(&entry).unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.outbox().unwrap();
    assert_eq!(found.len(), 1, "очередь обязана пережить перезапуск");
    assert_eq!(found[0].envelope, entry.envelope);
    assert_eq!(found[0].queued_ms, 4_000, "порядок отправки — по моменту нажатия");

    // Чужим ключом конверт не открывается.
    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(wrong.outbox().is_err(), "чужой ключ не должен читать очередь");

    store.delete_outbox(&entry.msg_id).unwrap();
    assert!(store.outbox().unwrap().is_empty());
}

#[test]
fn the_outbox_keeps_the_order_in_which_messages_were_written() {
    // Человек писал в каком-то порядке; после долгого офлайна сообщения
    // обязаны уехать в том же.
    let db = TempDb::new("outbox-order");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    for (n, at) in [(3u8, 300u64), (1, 100), (2, 200)] {
        store
            .put_outbox(&ratatosk_store::StoredOutbox {
                msg_id: [n; 16],
                recipient_ik: [9u8; 32],
                envelope: vec![n],
                queued_ms: at,
            })
            .unwrap();
    }

    let order: Vec<u8> = store.outbox().unwrap().into_iter().map(|e| e.envelope[0]).collect();
    assert_eq!(order, vec![1, 2, 3]);
}

#[test]
fn an_edit_replaces_the_body_and_leaves_a_mark() {
    let db = TempDb::new("edit");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
        assert!(store.edit_message(&[1u8; 16], "исправлено".as_bytes(), 500).unwrap());
        // Правка сообщения, которого нет, — не ошибка, но и не успех.
        assert!(!store.edit_message(&[9u8; 16], b"nope", 500).unwrap());
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.message(&[1u8; 16]).unwrap().expect("сообщение на месте");
    assert_eq!(found.body, "исправлено".as_bytes(), "прежний текст не хранится нигде");
    assert_eq!(
        found.edited_ms,
        Some(500),
        "отметка обязательна: §14 не разрешает молчаливую подмену"
    );
}

#[test]
fn a_tombstone_beats_an_edit() {
    // Собеседник поправил сообщение, которое человек у себя удалил. Правка
    // не должна вернуть его в чат: надгробие сильнее (§9.2).
    let db = TempDb::new("edit-tomb");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.tombstone_message(&[1u8; 16], 200).unwrap();

    assert!(!store.edit_message(&[1u8; 16], b"vernis", 300).unwrap());
    assert!(store.message(&[1u8; 16]).unwrap().is_none());
}

#[test]
fn a_reaction_round_trips_and_is_sealed() {
    let db = TempDb::new("reaction");
    let author = [4u8; 32];

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
        store
            .put_reaction(&ratatosk_store::StoredReaction {
                msg_id: [1u8; 16],
                author_ik: author,
                emoji: "👍".into(),
                hlc: Hlc::new(150, 0),
            })
            .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.reactions(&[1u8; 16]).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].emoji, "👍");
    assert_eq!(found[0].hlc, Hlc::new(150, 0), "метка нужна, чтобы старое не затёрло новое");

    // Реакция — содержимое, значит закрыта тем же ключом, что и тело (§12).
    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(wrong.reactions(&[1u8; 16]).is_err(), "чужой ключ не должен открывать реакцию");
}

#[test]
fn a_taken_back_reaction_is_kept_for_its_tag_but_not_shown() {
    // Снятие хранится строкой с пустой строкой внутри: без него запоздавшая
    // копия вернула бы реакцию, которую человек убрал (§9.2). Но показывать
    // такую запись нельзя — иначе в чате появится пустой пузырёк.
    let db = TempDb::new("reaction-back");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();

    let author = [4u8; 32];
    for (emoji, wall) in [("👍", 150u64), ("", 200)] {
        store
            .put_reaction(&ratatosk_store::StoredReaction {
                msg_id: [1u8; 16],
                author_ik: author,
                emoji: emoji.into(),
                hlc: Hlc::new(wall, 0),
            })
            .unwrap();
    }

    assert!(store.reactions(&[1u8; 16]).unwrap().is_empty(), "снятая реакция не показывается");
    let raw = store.reaction(&[1u8; 16], &author).unwrap().expect("запись осталась");
    assert!(raw.emoji.is_empty());
    assert_eq!(raw.hlc, Hlc::new(200, 0), "метка снятия — единственное, ради чего запись жива");
}

#[test]
fn deleting_a_message_takes_its_reactions() {
    let db = TempDb::new("reaction-del");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store
        .put_reaction(&ratatosk_store::StoredReaction {
            msg_id: [1u8; 16],
            author_ik: [4u8; 32],
            emoji: "👍".into(),
            hlc: Hlc::new(150, 0),
        })
        .unwrap();

    store.tombstone_message(&[1u8; 16], 200).unwrap();
    assert!(store.reactions(&[1u8; 16]).unwrap().is_empty());
    assert!(
        store.reaction(&[1u8; 16], &[4u8; 32]).unwrap().is_none(),
        "у надгробия нет реакций: они относились к словам, которых больше нет"
    );
}

#[test]
fn a_reaction_cannot_be_moved_between_authors() {
    // AAD привязывает шифротекст к паре «сообщение, автор». Без этого строку
    // можно переставить прямым доступом к файлу, и реакция одного человека
    // читалась бы как реакция другого.
    let db = TempDb::new("reaction-aad");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store
        .put_reaction(&ratatosk_store::StoredReaction {
            msg_id: [1u8; 16],
            author_ik: [4u8; 32],
            emoji: "👍".into(),
            hlc: Hlc::new(150, 0),
        })
        .unwrap();

    let moved = rusqlite::Connection::open(&db.0).unwrap();
    moved
        .execute(
            "UPDATE reactions SET author_ik = ?1 WHERE author_ik = ?2",
            rusqlite::params![&[5u8; 32][..], &[4u8; 32][..]],
        )
        .unwrap();
    drop(moved);

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(
        store.reaction(&[1u8; 16], &[5u8; 32]).is_err(),
        "переставленная реакция не должна открываться"
    );
}

#[test]
fn a_reply_link_survives_a_restart_and_may_dangle() {
    // Ссылка «на что это ответ» — мягкая: цели может не быть вовсе. Хранилище
    // обязано отдать её как есть, а не превратить в `None`, иначе UI не сможет
    // сказать «сообщение недоступно» — он вообще не узнает, что это ответ.
    let db = TempDb::new("reply");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();

        let mut answer = message(2, 200);
        answer.reply_to = Some([1u8; 16]);
        store.put_message(&answer).unwrap();

        let mut dangling = message(3, 300);
        dangling.reply_to = Some([99u8; 16]);
        store.put_message(&dangling).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let window = store.messages(&[9u8; 16], 10, None).unwrap();
    assert_eq!(window[0].reply_to, None, "обычное сообщение ответом не становится");
    assert_eq!(window[1].reply_to, Some([1u8; 16]));
    assert_eq!(
        window[2].reply_to,
        Some([99u8; 16]),
        "ссылка на то, чего нет, сохраняется — иначе ответ перестал бы быть ответом"
    );
    // И через чтение по одному идентификатору — тем же самым.
    assert_eq!(store.message(&[2u8; 16]).unwrap().unwrap().reply_to, Some([1u8; 16]));
}
