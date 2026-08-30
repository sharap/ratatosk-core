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
fn a_tombstone_satisfies_the_foreign_key_and_that_is_the_trap() {
    // Тест написан после того, как автор ошибся ровно здесь, — и этим же
    // тестом был пойман. Неверное рассуждение сохранено, чтобы не вернулось:
    //
    //     «`put_message` на надгробии молча ничего не пишет; значит вложение,
    //      приложенное следом, упрётся во внешний ключ, и ядро остановится».
    //
    // Неверно во второй половине. Надгробие — это `UPDATE`, а не `DELETE`:
    // строка сообщения **остаётся**, у неё лишь проставлен `tombstone_ms`.
    // Внешний ключ она удовлетворяет полностью.
    //
    // Отсюда настоящее правило, и оно неприятнее выдуманного: **база
    // в этом месте не защищает ничего**, а `store.message()` при этом
    // возвращает `None`, потому что надгробия он отсеивает. Вызывающий,
    // понадеявшийся на отказ базы, тихо приложит вложения к удалённому
    // сообщению — в чате их не видно, а чанки качаются.
    let db = TempDb::new("orphan-child");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.tombstone_message(&[1u8; 16], 1_000).unwrap();

    // Копия пришла вторым транспортом (§9.2) — и не легла.
    store.put_message(&message(1, 100)).unwrap();
    assert!(store.message(&[1u8; 16]).unwrap().is_none(), "читателю сообщения нет");

    let share = |n: u8| ratatosk_store::StoredContactShare {
        msg_id: [n; 16],
        ik: [7u8; 32],
        card_bytes: vec![1, 2, 3],
    };

    assert!(
        store.put_contact_share(&share(1)).is_ok(),
        "к надгробию содержимое прикладывается беспрепятственно: строка на месте"
    );
    assert!(
        store.put_contact_share(&share(2)).is_err(),
        "а вот к идентификатору, которого не было вовсе, — нет: вот где ключ и работает"
    );
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

fn file(n: u8, msg: u8, incoming: bool) -> ratatosk_store::StoredFile {
    ratatosk_store::StoredFile {
        file_id: [n; 16],
        msg_id: [msg; 16],
        name: format!("файл {n}.pdf"),
        size_bytes: 5_000,
        chunk_total: 3,
        key: [n.wrapping_add(1); 32],
        preview: None,
        ordinal: 0,
        incoming,
        source_path: (!incoming).then(|| "/tmp/ishodnyj".to_owned()),
        accepted: !incoming,
        complete: false,
    }
}

#[test]
fn attachments_come_back_in_the_order_they_were_put_in() {
    // **Проверяется запросом, а не памятью.** Здесь стояло `ORDER BY file_id`,
    // то есть по случайным шестнадцати байтам: три фотографии, выбранные
    // подряд, приходили в произвольном порядке. Заметить это на одном
    // вложении нельзя, и потому оно прожило до первого сообщения с тремя.
    //
    // Идентификаторы нарочно **против** порядка: если сортировка вернётся
    // к `file_id`, тест увидит это сразу.
    let db = TempDb::new("file-order");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();

    for (ordinal, id) in [30u8, 20, 10].into_iter().enumerate() {
        let mut record = file(id, 1, true);
        record.ordinal = u32::try_from(ordinal).unwrap();
        record.name = format!("файл {ordinal}");
        store.put_file(&record).unwrap();
    }

    let names: Vec<String> =
        store.files_of(&[1u8; 16]).unwrap().into_iter().map(|f| f.name).collect();
    assert_eq!(names, ["файл 0", "файл 1", "файл 2"], "порядок обещан `Store::files_of`");
}

#[test]
fn attachments_from_before_the_order_existed_keep_their_old_one() {
    // У строк, заведённых до столбца, `ordinal` равен нулю — у всех. Значит
    // порядок между ними решает `file_id`, то есть остаётся ровно тем, в каком
    // они показывались раньше. Прошлое не переписывается.
    let db = TempDb::new("file-order-old");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    for id in [30u8, 10, 20] {
        store.put_file(&file(id, 1, true)).unwrap();
    }
    let ids: Vec<u8> =
        store.files_of(&[1u8; 16]).unwrap().into_iter().map(|f| f.file_id[0]).collect();
    assert_eq!(ids, [10, 20, 30], "при равном порядке — по идентификатору, как было");
}

#[test]
fn a_file_round_trips_and_its_name_is_sealed() {
    // Имя файла говорит о переписке не меньше, чем текст: «результаты
    // анализов.pdf» в открытом столбце — ровно то, от чего §12 защищает тело.
    let db = TempDb::new("file");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
        let mut with_preview = file(2, 1, true);
        with_preview.preview = Some(vec![0x89, b'P', b'N', b'G']);
        store.put_file(&with_preview).unwrap();
        store.put_file(&file(3, 1, false)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.file(&[2u8; 16]).unwrap().expect("файл на месте");
    assert_eq!(found.name, "файл 2.pdf");
    assert_eq!(found.key, [3u8; 32], "без ключа файл не собрать");
    assert_eq!(found.preview.as_deref(), Some(&[0x89, b'P', b'N', b'G'][..]));
    assert!(found.incoming);
    assert!(!found.accepted, "входящий файл ждёт согласия");

    // К одному сообщению их несколько — это обычный случай.
    let attached = store.files_of(&[1u8; 16]).unwrap();
    assert_eq!(attached.len(), 2);
    assert_eq!(attached[1].source_path.as_deref(), Some("/tmp/ishodnyj"));

    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(wrong.file(&[2u8; 16]).is_err(), "чужой ключ не должен открывать имя и ключ файла");
}

#[test]
fn chunks_are_counted_and_the_first_gap_is_the_resume_point() {
    // §10.2: возобновление по индексу чанка. Точка возобновления — первый
    // недостающий, и считать её надо не по количеству принятых: чанки
    // законно приходят не по порядку.
    let db = TempDb::new("chunks");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.put_file(&file(2, 1, true)).unwrap();

    assert_eq!(store.next_missing_chunk(&[2u8; 16], 3).unwrap(), Some(0));

    store.note_chunk(&[2u8; 16], 0).unwrap();
    store.note_chunk(&[2u8; 16], 2).unwrap();
    assert_eq!(store.received_chunks(&[2u8; 16]).unwrap(), 2);
    assert_eq!(
        store.next_missing_chunk(&[2u8; 16], 3).unwrap(),
        Some(1),
        "принято два чанка из трёх, но продолжать надо с дырки"
    );

    store.note_chunk(&[2u8; 16], 1).unwrap();
    store.note_chunk(&[2u8; 16], 1).unwrap();
    assert_eq!(store.received_chunks(&[2u8; 16]).unwrap(), 3, "повтор не считается дважды");
    assert_eq!(store.next_missing_chunk(&[2u8; 16], 3).unwrap(), None, "файл собран");
}

#[test]
fn taking_the_consent_back_keeps_what_already_arrived() {
    // **На настоящей базе**, потому что проверяется SQL, которого компилятор
    // не читает: `UPDATE files SET accepted = ?2`. Память бы это пропустила —
    // там поле просто присваивается.
    //
    // Суть в том, что снятие согласия не трогает приехавшее. Иначе «передумал
    // на середине гигабайта» означало бы «начать заново», а на мобильном
    // канале это не пауза, а потеря.
    let db = TempDb::new("file-pause");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.put_file(&file(2, 1, true)).unwrap();

    assert!(store.set_accepted(&[2u8; 16], true).unwrap());
    store.note_chunk(&[2u8; 16], 0).unwrap();

    assert!(store.set_accepted(&[2u8; 16], false).unwrap(), "согласие снимается тем же путём");
    let paused = store.file(&[2u8; 16]).unwrap().expect("запись остаётся");
    assert!(!paused.accepted, "согласия больше нет");
    assert_eq!(store.received_chunks(&[2u8; 16]).unwrap(), 1, "а приехавшее — на месте");
    assert_eq!(
        store.next_missing_chunk(&[2u8; 16], 3).unwrap(),
        Some(1),
        "и продолжать надо с той же дырки, а не с нуля"
    );

    // Файла нет — и это не отказ базы, а `false`: решать про то, чего нет,
    // вызывающий волен, и падать тут не на чем.
    assert!(!store.set_accepted(&[9u8; 16], false).unwrap());
}

#[test]
fn an_unfinished_file_survives_a_restart() {
    // Ради этого учёт и лежит в базе: после перезапуска передача обязана
    // продолжиться с того же места, а не начаться заново.
    let db = TempDb::new("file-restart");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
        store.put_file(&file(2, 1, true)).unwrap();
        store.set_accepted(&[2u8; 16], true).unwrap();
        store.note_chunk(&[2u8; 16], 0).unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    let unfinished = store.unfinished_files().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert!(unfinished[0].accepted, "согласие переживает перезапуск: спрашивать заново незачем");
    assert_eq!(store.next_missing_chunk(&[2u8; 16], 3).unwrap(), Some(1));

    store.complete_file(&[2u8; 16]).unwrap();
    assert!(store.unfinished_files().unwrap().is_empty());
}

#[test]
fn deleting_a_message_takes_its_files_and_their_chunk_tally() {
    let db = TempDb::new("file-del");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.put_file(&file(2, 1, true)).unwrap();
    store.note_chunk(&[2u8; 16], 0).unwrap();

    store.delete_file(&[2u8; 16]).unwrap();
    assert!(store.file(&[2u8; 16]).unwrap().is_none());
    assert_eq!(store.received_chunks(&[2u8; 16]).unwrap(), 0, "учёт чанков не пережил файл");

    // И то же самое каскадом от чата: вложения не остаются от удалённой
    // переписки. Байты с диска убирает вызывающий — они лежат не здесь.
    store.put_file(&file(3, 1, true)).unwrap();
    store.delete_chat(&[9u8; 16]).unwrap();
    assert!(store.file(&[3u8; 16]).unwrap().is_none());
}

/// Выгрузка с десктопа — то, чего ещё нет ни в сообщении, ни в чате.
fn staged(n: u8, started_ms: u64) -> ratatosk_store::StagedUpload {
    ratatosk_store::StagedUpload {
        file_id: [n; 16],
        chat_id: [9u8; 16],
        name: format!("выгрузка {n}.pdf"),
        size_bytes: 5_000,
        chunk_total: 3,
        key: [n.wrapping_add(1); 32],
        preview: None,
        started_ms,
    }
}

#[test]
fn a_staged_upload_round_trips_and_is_sealed() {
    // Выгрузка живёт **до** сообщения: сообщения, к которому её приложить,
    // ещё нет, и чата в базе может не быть тоже. Значит внешним ключом её
    // не привязать ни к чему — и это нарочно, а не забывчивость.
    let db = TempDb::new("staged");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        let mut with_preview = staged(2, 1_000);
        with_preview.preview = Some(vec![0x89, b'P', b'N', b'G']);
        // Ни `put_message`, ни `put_contact` перед этим — и это должно пройти.
        store.put_staged(&with_preview).unwrap();
        store.put_staged(&staged(3, 2_000)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.staged_uploads().unwrap();
    assert_eq!(found.len(), 2, "обе выгрузки пережили перезапуск");
    assert_eq!(found[0].file_id, [2u8; 16], "порядок — по времени начала");
    assert_eq!(found[0].name, "выгрузка 2.pdf");
    assert_eq!(found[0].key, [3u8; 32], "без ключа куски не собрать");
    assert_eq!(found[0].preview.as_deref(), Some(&[0x89, b'P', b'N', b'G'][..]));
    assert_eq!(found[0].chat_id, [9u8; 16], "куда уедет, когда соберётся");
    assert_eq!(found[1].preview, None);

    // Имя выгрузки говорит о переписке ровно то же, что имя вложения (§12).
    let wrong = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(wrong.staged_uploads().is_err(), "чужой ключ не должен открывать имя и ключ файла");
}

#[test]
fn the_holes_in_a_staged_upload_are_named_and_not_counted() {
    // То же правило, что у приёма (§10.2), и по той же причине: куски вправе
    // приехать не по порядку, и «сколько принято» не отвечает на вопрос
    // «каких нет». Отсюда набор, а не счётчик.
    let db = TempDb::new("staged-chunks");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_staged(&staged(2, 1_000)).unwrap();

    assert!(store.staged_chunks(&[2u8; 16]).unwrap().is_empty());

    store.note_staged_chunk(&[2u8; 16], 2).unwrap();
    store.note_staged_chunk(&[2u8; 16], 0).unwrap();
    // Повтор — не ошибка: десктоп вправе прислать кусок ещё раз.
    store.note_staged_chunk(&[2u8; 16], 0).unwrap();
    assert_eq!(
        store.staged_chunks(&[2u8; 16]).unwrap(),
        vec![0, 2],
        "по возрастанию и без повторов"
    );

    store.note_staged_chunk(&[2u8; 16], 1).unwrap();
    assert_eq!(store.staged_chunks(&[2u8; 16]).unwrap(), vec![0, 1, 2]);
}

#[test]
fn deleting_a_staged_upload_takes_its_chunk_marks() {
    // Иначе отметки пережили бы саму выгрузку, и следующий файл с тем же
    // идентификатором (а он назначается заново) считался бы уже принятым.
    let db = TempDb::new("staged-del");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_staged(&staged(2, 1_000)).unwrap();
    store.note_staged_chunk(&[2u8; 16], 0).unwrap();

    store.delete_staged(&[2u8; 16]).unwrap();
    assert!(store.staged_uploads().unwrap().is_empty());
    assert!(store.staged_chunks(&[2u8; 16]).unwrap().is_empty(), "отметки ушли каскадом");
}

#[test]
fn an_old_staged_upload_is_found_by_the_time_it_was_started() {
    // Брошенную выгрузку никто не закрывает: у десктопа сдох процесс, и ни
    // отправки, ни отказа не придёт. Место в хранилище байтов вернёт только
    // срок — а срок считается от начала, потому что кусков может не быть
    // вовсе.
    let db = TempDb::new("staged-old");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_staged(&staged(2, 1_000)).unwrap();
    store.put_staged(&staged(3, 5_000)).unwrap();

    assert!(store.staged_older_than(1_000).unwrap().is_empty(), "ровно срок — ещё живая");
    assert_eq!(store.staged_older_than(1_001).unwrap(), vec![[2u8; 16]]);
    assert_eq!(store.staged_older_than(9_000).unwrap().len(), 2);
}

/// Сообщение с заданным текстом — для тестов поиска.
fn said(n: u8, wall: u64, text: &str) -> StoredMessage {
    StoredMessage { body: text.as_bytes().to_vec(), ..message(n, wall) }
}

#[test]
fn search_finds_whole_words_and_nothing_else() {
    let db = TempDb::new("search");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&said(1, 100, "Привет, как дела?")).unwrap();
    store.put_message(&said(2, 200, "дела идут хорошо")).unwrap();
    store.put_message(&said(3, 300, "совсем про другое")).unwrap();

    let found = |q: &str| {
        store.search(None, q, 10).unwrap().into_iter().map(|id| id[0]).collect::<Vec<_>>()
    };

    // Новые первыми: человек ищет то, о чём говорили недавно.
    assert_eq!(found("дела"), vec![2, 1]);
    // Регистр запроса значения не имеет.
    assert_eq!(found("ПРИВЕТ"), vec![1]);
    // Несколько слов — нужны все: уточняя запрос, человек ждёт меньше находок.
    assert_eq!(found("дела привет"), vec![1]);
    // И зафиксированное ограничение: по началу слова не ищется. Уметь это
    // значило бы уметь перебирать индекс по началу слова.
    assert!(found("прив").is_empty(), "префикс — не слово");
    // Пустой запрос отвечает пусто, а не всей историей.
    assert!(found("   ").is_empty());
    // Чужой чат не отдаётся.
    assert!(store.search(Some(&[7u8; 16]), "дела", 10).unwrap().is_empty());
}

#[test]
fn the_database_file_holds_no_plain_text() {
    // Ради этого индекс и устроен на хэшах. Полнотекстовый по открытым телам
    // положил бы рядом с зашифрованной перепиской её незашифрованную копию,
    // и потерянный телефон отдал бы всё, что человек написал.
    let db = TempDb::new("plaintext");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&said(1, 100, "секретное слово капибара")).unwrap();
    }

    // WAL сливается в основной файл при закрытии соединения; читаем оба
    // на случай, если что-то осталось.
    let mut bytes = std::fs::read(&db.0).unwrap_or_default();
    bytes.extend(std::fs::read(db.0.with_extension("db-wal")).unwrap_or_default());
    let haystack = String::from_utf8_lossy(&bytes);
    assert!(!haystack.contains("капибара"), "слово из переписки лежит в файле базы открытым");
    assert!(!haystack.contains("секретное"), "слово из переписки лежит в файле базы открытым");
}

#[test]
fn what_is_deleted_stops_being_found() {
    // Найти по тексту сообщение, текст которого стёрт, — значит не стереть его.
    let db = TempDb::new("search-delete");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&said(1, 100, "капибара")).unwrap();
    assert_eq!(store.search(None, "капибара", 10).unwrap().len(), 1);

    assert!(store.tombstone_message(&[1u8; 16], 500).unwrap());
    assert!(
        store.search(None, "капибара", 10).unwrap().is_empty(),
        "удалённое обязано перестать находиться"
    );
}

#[test]
fn an_edit_moves_the_index_with_the_text() {
    let db = TempDb::new("search-edit");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&said(1, 100, "первое слово")).unwrap();

    assert!(store.edit_message(&[1u8; 16], "второе слово".as_bytes(), 500).unwrap());
    assert!(
        store.search(None, "первое", 10).unwrap().is_empty(),
        "по стёртому слову находиться нечему"
    );
    assert_eq!(store.search(None, "второе", 10).unwrap().len(), 1, "а по новому — находится");
}

#[test]
fn the_history_that_predates_the_index_is_still_searchable() {
    // База, дожившая до обновления, обязана начать искать по всему, что в ней
    // уже лежит. Иначе поиск молча не находил бы ничего старше обновления,
    // и списать это было бы не на что.
    let db = TempDb::new("reindex");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&said(1, 100, "капибара")).unwrap();
    }

    // Возвращаем базу в состояние «индекс ещё не построен»: пустая таблица
    // токенов и стёртая отметка о формате. Схему при этом не трогаем вовсе.
    //
    // Две прежние попытки откатывали `user_version`, и обе разваливались:
    // сперва миграция 0009 падала на `DROP TABLE messages_fts` (таблицы уже
    // не было), потом 0010 — на `CREATE TABLE contact_shares` (таблица уже
    // была). Урок не про тест: признаком «индекс пора строить» не может быть
    // версия схемы. Схема отвечает, какие таблицы есть, а не заполнены ли
    // они, — и каждая новая миграция ломала бы это заново.
    //
    // Напрямую через rusqlite, а не через `Store`: трейт такого уметь
    // не должен, а тесту надо подделать прошлое.
    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute_batch(&format!(
            "DELETE FROM message_tokens;
             DELETE FROM meta WHERE key = '{}';",
            ratatosk_store::META_SEARCH_INDEX
        ))
        .unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    assert_eq!(
        store.search(None, "капибара", 10).unwrap().len(),
        1,
        "переиндексация обязана поднять то, что записано до неё"
    );
}

#[test]
fn compaction_runs_over_every_task_without_panicking() {
    // Три задачи уборки были заглушены `todo!()`, и это стало бы падением
    // приложения в тот день, когда уборку наконец начали запускать.
    let db = TempDb::new("compaction-all");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    for task in ratatosk_store::Task::ALL {
        store.compact(task, 90 * 24 * 60 * 60 * 1000).expect("задача уборки обязана отработать");
    }
}

#[test]
fn a_changed_index_format_rebuilds_everything() {
    // Смена токенизации — самая тихая поломка из возможных: приложение
    // работает, поиск не падает, просто перестаёт находить написанное до
    // обновления. Номер формата существует ровно затем, чтобы этого
    // не случилось молча.
    let db = TempDb::new("reindex-format");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&said(1, 100, "капибара")).unwrap();
    }

    // База, построенная по «формату 0», то есть по любому другому.
    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute(
            "UPDATE meta SET value = x'00000000' WHERE key = ?1",
            [ratatosk_store::META_SEARCH_INDEX],
        )
        .unwrap();
        raw.execute_batch("DELETE FROM message_tokens").unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    assert_eq!(
        store.search(None, "капибара", 10).unwrap().len(),
        1,
        "индекс чужого формата обязан быть построен заново"
    );
}
