//! Что переживает перезапуск.
//!
//! Проверка идёт по настоящему файлу, а не по базе в памяти: `in_memory`
//! исчезает вместе с соединением и поэтому не может проверить ровно то,
//! ради чего всё это писалось.

use std::path::PathBuf;

use ratatosk_crdt::Hlc;
use ratatosk_store::{
    MemoryStore, SqliteStore, Store, StoredArchiveKey, StoredChannel, StoredContact, StoredGrant,
    StoredGroup, StoredGroupAvatar, StoredMembershipBlock, StoredMembershipOp, StoredMessage,
    StoredSenderChain, StoredSubscription,
};
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
        // Нечётные — с ключом меша, чётные без: так одна и та же
        // вспомогалка проверяет и то, что тридцать два байта доезжают
        // до диска и обратно, и то, что пустой ключ остаётся пустым.
        ygg: if n % 2 == 0 { Vec::new() } else { vec![n; 32] },
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
    // Ключ меша (0.2) — свой столбец, и пустой он тоже переживает открытие:
    // «нет ключа» обязано остаться «нет ключа», а не стать чем-то ещё.
    assert_eq!(found.iter().find(|c| c.ik[0] == 3).unwrap().ygg, vec![3u8; 32]);
    assert!(found.iter().find(|c| c.ik[0] == 2).unwrap().ygg.is_empty());
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
            binding: 0,
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

    store.delete_outbox(&entry.msg_id, &entry.recipient_ik).unwrap();
    assert!(store.outbox().unwrap().is_empty());
}

#[test]
fn one_message_keeps_a_row_per_recipient() {
    // Сообщение в группу — это N доставок с **одним** номером (§11.3:
    // копию каждому шлёт сам отправитель). Первичный ключ таблицы всегда
    // был парой, а удаление ходило по одному номеру — и первая дошедшая
    // копия уносила из очереди копии всех прочих участников. Наружу это
    // выглядело как «в группах сообщения доходят не до всех, а недошедшие
    // не доходят никогда».
    let db = TempDb::new("outbox-per-recipient");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    // Строка сообщения здесь не нужна: внешний ключ на `messages` пропал
    // ещё в миграции 0004 вместе с половиной первичного ключа, и 0021
    // возвращает только вторую — у живых баз есть строки очереди без
    // сообщения (уборка §12 сносит историю, а очередь её переживает),
    // и ограничение уронило бы миграцию у них.
    let msg_id = [7u8; 16];
    let members: [[u8; 32]; 3] = [[0xa1; 32], [0xb2; 32], [0xc3; 32]];
    for member in &members {
        store
            .put_outbox(&ratatosk_store::StoredOutbox {
                msg_id,
                recipient_ik: *member,
                envelope: b"one message, three copies".to_vec(),
                queued_ms: 4_000,
            })
            .unwrap();
    }
    assert_eq!(store.outbox().unwrap().len(), 3, "по строке на участника");

    // Снятие **одной** доставки оставляет остальные.
    store.delete_outbox(&msg_id, &members[0]).unwrap();
    let left = store.outbox().unwrap();
    assert_eq!(left.len(), 2, "ушла ровно одна: {left:?}");
    assert!(left.iter().all(|e| e.recipient_ik != members[0]));

    // А «сообщения больше нет» уносит всё — и это отдельное имя нарочно,
    // чтобы «всех» нельзя было получить забывчивостью.
    store.delete_outbox_all(&msg_id).unwrap();
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
        chunk_bytes: 2_000,
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
fn a_foreign_narezka_survives_a_restart_and_is_not_guessed() {
    // **Ради чего столбец.** Размер чанка выбирает тот, кто отправляет
    // файл первым, по своей ступени. У пересланного он поэтому бывает
    // чужим — не равным ни одному из наших двух. Выводить его из пары
    // «размер, число кусков», как делалось до 0026, значило бы у такого
    // файла вывести **наш** размер: смещения поехали бы с первого куска,
    // и наружу это вышло бы не отказом, а испорченным файлом.
    //
    // Числа взяты нарочно чужие: 2500 не равно ни 3765, ни 1 048 245.
    let db = TempDb::new("file-narezka");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_message(&message(1, 100)).unwrap();
        let mut foreign = file(2, 1, true);
        foreign.size_bytes = 10_000;
        foreign.chunk_total = 4;
        foreign.chunk_bytes = 2_500;
        store.put_file(&foreign).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let back = store.file(&[2u8; 16]).unwrap().expect("запись на месте");
    assert_eq!(back.chunk_bytes, 2_500, "нарезка обязана вернуться той же, какой легла");
    assert_eq!(back.chunk_total, 4, "и число кусков вместе с ней");

    // И через список сообщения — тем же числом: два пути чтения записи
    // обязаны говорить одно, иначе передача пойдёт одной нарезкой,
    // а показ другой.
    let of_message = store.files_of(&[1u8; 16]).unwrap();
    assert_eq!(of_message.len(), 1);
    assert_eq!(of_message[0].chunk_bytes, 2_500, "оба пути чтения обязаны сходиться");
}

#[test]
fn a_staged_upload_keeps_the_narezka_it_agreed_on() {
    // Телефон назначил номера кусков, когда договаривался о выгрузке,
    // и мерить приходящие обязан тем же числом. Переживи перезапуск
    // только число кусков — и первый же кусок после него был бы отвергнут
    // как «не той длины», причём законный.
    let db = TempDb::new("staged-narezka");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        let mut air = staged(5, 1_000);
        air.size_bytes = 10_000;
        air.chunk_total = 3;
        air.chunk_bytes = 3_765;
        store.put_staged(&air).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let back = store.staged_uploads().unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].chunk_bytes, 3_765, "нарезка выгрузки обязана пережить перезапуск");
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
        chunk_bytes: 2_000,
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

/// Собирает архив в память и отдаёт его байтами.
fn archived(
    store: &SqliteStore,
    archive_id: [u8; 16],
    scope: ratatosk_store::archive::ExportScope,
) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let head = ratatosk_store::archive::Header { archive_id, scope };
        let mut writer = ratatosk_store::archive::ArchiveWriter::start(&mut out, head).unwrap();
        store.export_into(scope, &mut writer).expect("экспорт");
        writer.finish().expect("конец архива");
    }
    out
}

/// Достаёт из архива снимок базы, расшифровывая куски.
fn snapshot_from(archive: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use ratatosk_store::archive::{self, EntryKind};

    let archive_id = archive::parse_header(archive).expect("заголовок").archive_id;
    let mut at = archive::HEADER_LEN;
    let mut snapshot = Vec::new();
    while let Some(entry) = archive::parse_entry(&archive[at..]).expect("рамка") {
        at += archive::ENTRY_HEADER_LEN;
        let body = &archive[at..at + entry.len];
        at += entry.len;
        if entry.kind != EntryKind::Database {
            continue;
        }
        let aad = archive::db_chunk_aad(&archive_id, entry.index);
        let open = ratatosk_crypto::storage_key::open_field(key, &aad, body)
            .expect("кусок базы открывается своим ключом");
        snapshot.extend_from_slice(&open);
    }
    snapshot
}

#[test]
fn an_exported_archive_opens_back_into_a_working_database() {
    // §12: «единственный путь переноса истории на другое устройство».
    // Проверяется поэтому целиком, до открытой базы на том конце: архив,
    // который нельзя открыть обратно, — не архив, а иллюзия сохранности.
    let db = TempDb::new("export");
    let restored = TempDb::new("export-back");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    for n in 1..=3u8 {
        store.put_message(&message(n, u64::from(n) * 100)).unwrap();
    }
    store.put_contact(&contact(5)).unwrap();

    let archive = archived(&store, [3u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let db_key = store.export_key().expect("ключ архива");
    assert_eq!(*db_key, *key(1), "архив открывается ключом базы, а не новым (§12)");

    // Снимок обязан лежать в архиве **запечатанным**: файл уезжает
    // на флешке, и открытая копия базы в нём свела бы §12 к переносу
    // папки.
    assert!(
        !archive.windows(15).any(|w| w == b"SQLite format 3"),
        "заголовок SQLite виден в архиве открытым текстом"
    );

    std::fs::write(&restored.0, snapshot_from(&archive, &db_key)).expect("снимок на диск");
    let back = SqliteStore::open(&restored.0, key(1)).unwrap();
    let found = back.messages(&[9u8; 16], 10, None).expect("история из архива");
    assert_eq!(found.len(), 3, "переписка доехала целиком");
    assert_eq!(found[0].body, "сообщение 1".as_bytes(), "и читается тем же ключом");
    assert_eq!(back.contacts().expect("контакты").len(), 1, "контакты тоже");
}

#[test]
fn the_social_graph_carries_the_contacts_and_leaves_the_correspondence() {
    // Человек меняет телефон и готов расстаться с историей, но не со
    // **связями**: без контактов с их адресами он никому не может написать
    // первым, а собеседники не узнают его нового ключа.
    //
    // Проверяется обеими половинами: что доехало и — важнее — что не доехало.
    let db = TempDb::new("export-graph");
    let restored = TempDb::new("export-graph-back");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_contact(&contact(2)).unwrap();
    store.put_contact(&contact(3)).unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();
    store.put_meta(ratatosk_store::META_IDENTITY_SEED, b"zerno").unwrap();
    store.put_meta(ratatosk_store::META_SELF_CARD, b"kartochka").unwrap();
    store.put_meta(&ratatosk_store::read_upto_key(&[9u8; 16]), b"do-sjuda").unwrap();

    let archive = archived(&store, [8u8; 16], ratatosk_store::archive::ExportScope::SocialGraph);
    let head = ratatosk_store::archive::parse_header(&archive).unwrap();
    assert_eq!(
        head.scope,
        ratatosk_store::archive::ExportScope::SocialGraph,
        "область записана в архиве, а не выводится из содержимого"
    );

    let db_key = store.export_key().unwrap();
    std::fs::write(&restored.0, snapshot_from(&archive, &db_key)).expect("снимок на диск");
    let back = SqliteStore::open(&restored.0, key(1)).unwrap();

    // Доехало: контакты с адресами и своя личность.
    let contacts = back.contacts().expect("контакты");
    assert_eq!(contacts.len(), 2, "оба знакомства на месте");
    assert_eq!(contacts[0].card_bytes, vec![2u8; 64], "карточка — та же, байт в байт (§6)");
    assert_eq!(
        back.meta(ratatosk_store::META_IDENTITY_SEED).unwrap().as_deref(),
        Some(&b"zerno"[..]),
        "без своего зерна это чужой граф, а не свой"
    );
    assert_eq!(
        back.meta(ratatosk_store::META_SELF_CARD).unwrap().as_deref(),
        Some(&b"kartochka"[..])
    );

    // Не доехало: переписка и отметки о ней.
    assert!(
        back.messages(&[9u8; 16], 10, None).expect("история").is_empty(),
        "сообщений в графе быть не должно"
    );
    assert_eq!(
        back.meta(&ratatosk_store::read_upto_key(&[9u8; 16])).unwrap(),
        None,
        "`meta` уезжает не целиком: отметки прочтения — про переписку"
    );
}

#[test]
fn an_export_without_attachments_still_says_what_it_is() {
    // Архив без вложений и полный архив у человека без единого вложения
    // выглядят одинаково. Отличить их можно только по записанной области —
    // и ввоз обязан прочесть её, а не догадываться.
    let db = TempDb::new("export-nofiles");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();

    let archive =
        archived(&store, [6u8; 16], ratatosk_store::archive::ExportScope::WithoutAttachments);
    let head = ratatosk_store::archive::parse_header(&archive).unwrap();
    assert_eq!(head.scope, ratatosk_store::archive::ExportScope::WithoutAttachments);

    // Переписка при этом на месте: без вложений — не значит без слов.
    let restored = TempDb::new("export-nofiles-back");
    let db_key = store.export_key().unwrap();
    std::fs::write(&restored.0, snapshot_from(&archive, &db_key)).expect("снимок на диск");
    let back = SqliteStore::open(&restored.0, key(1)).unwrap();
    assert_eq!(back.messages(&[9u8; 16], 10, None).expect("история").len(), 1);
}

#[test]
fn an_archive_does_not_open_with_the_wrong_key() {
    // Иначе «зашифрованный архив» — слово, а не свойство.
    let db = TempDb::new("export-wrong");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();

    let archive = archived(&store, [4u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let archive_id = ratatosk_store::archive::parse_header(&archive).unwrap().archive_id;
    let first =
        ratatosk_store::archive::parse_entry(&archive[ratatosk_store::archive::HEADER_LEN..])
            .unwrap()
            .expect("первая запись");
    let at = ratatosk_store::archive::HEADER_LEN + ratatosk_store::archive::ENTRY_HEADER_LEN;
    let body = &archive[at..at + first.len];
    let aad = ratatosk_store::archive::db_chunk_aad(&archive_id, 0);
    assert!(
        ratatosk_crypto::storage_key::open_field(&[2u8; 32], &aad, body).is_err(),
        "чужой ключ не должен открывать архив"
    );
}

#[test]
fn a_chunk_cannot_be_moved_between_two_archives_of_one_account() {
    // Два архива одного аккаунта шифруются **одним** ключом, и без
    // идентификатора архива в associated data кусок вчерашнего архива
    // подставился бы в сегодняшний незаметно.
    let db = TempDb::new("export-splice");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_message(&message(1, 100)).unwrap();

    let first = archived(&store, [1u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let db_key = store.export_key().unwrap();
    let head = ratatosk_store::archive::HEADER_LEN + ratatosk_store::archive::ENTRY_HEADER_LEN;
    let entry = ratatosk_store::archive::parse_entry(&first[ratatosk_store::archive::HEADER_LEN..])
        .unwrap()
        .expect("запись");
    let body = &first[head..head + entry.len];

    // Тот же кусок, но выдаём его за кусок другого архива.
    let alien = ratatosk_store::archive::db_chunk_aad(&[2u8; 16], 0);
    assert!(
        ratatosk_crypto::storage_key::open_field(&db_key, &alien, body).is_err(),
        "кусок обязан быть привязан к своему архиву"
    );
    let own = ratatosk_store::archive::db_chunk_aad(&[1u8; 16], 0);
    assert!(ratatosk_crypto::storage_key::open_field(&db_key, &own, body).is_ok());
}

/// Кладёт байты архива в файл и отдаёт путь.
fn archive_file(tag: &str, bytes: &[u8]) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ratatosk-arch-{tag}-{}-{:?}.rtsk",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, bytes).expect("архив на диск");
    path
}

/// База с перепиской, контактом и одним вложением из трёх кусков.
fn account_with_everything(db: &TempDb) -> SqliteStore {
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_contact(&contact(5)).unwrap();
    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();
    store.put_file(&file(2, 1, true)).unwrap();
    store
}

#[test]
fn an_archive_goes_out_and_comes_back_as_a_working_account() {
    // Ради этого весь §12 и написан: переписка обязана пережить телефон.
    // Проверяется кругом целиком — вывоз, ключ, ввоз, открытая база, —
    // потому что вывоз, который нечем ввезти, ничего не сохраняет.
    let db = TempDb::new("round-out");
    let landing = TempDb::new("round-in");
    let store = account_with_everything(&db);
    let db_key = store.export_key().unwrap();

    // Архив: база от хранилища плюс куски вложения — как их кладёт ядро.
    let mut bytes = Vec::new();
    {
        let head = ratatosk_store::archive::Header {
            archive_id: [11u8; 16],
            scope: ratatosk_store::archive::ExportScope::Everything,
        };
        let mut writer = ratatosk_store::archive::ArchiveWriter::start(&mut bytes, head).unwrap();
        store.export_into(ratatosk_store::archive::ExportScope::Everything, &mut writer).unwrap();
        for index in 0..3u64 {
            ratatosk_store::archive::ArchiveSink::put(
                &mut writer,
                ratatosk_store::archive::EntryKind::Attachment,
                &[2u8; 16],
                index,
                &[index as u8; 64],
            )
            .unwrap();
        }
        writer.finish().unwrap();
    }
    let archive = archive_file("round", &bytes);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let done = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&db_key),
        &landing.0,
        &mut blobs,
    )
    .expect("ввоз");
    assert_eq!(done.scope, ratatosk_store::archive::ExportScope::Everything);
    assert_eq!(done.contacts, 1);
    assert_eq!(done.messages, 2);
    assert_eq!(done.files, 1);
    assert_eq!(done.whole_files, 1, "все три куска доехали — вложение целое");
    assert_eq!(done.bytes, 192);

    // И база на месте назначения — рабочая, тем же ключом.
    let back = SqliteStore::open(&landing.0, key(1)).unwrap();
    let history = back.messages(&[9u8; 16], 10, None).expect("история");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].body, "сообщение 1".as_bytes());
    assert_eq!(back.contacts().expect("контакты").len(), 1);
    let files = back.files_of(&[1u8; 16]).expect("вложения");
    assert_eq!(files.len(), 1);
    assert!(files[0].complete, "вложение, чьи байты доехали, — целое");
    assert_eq!(back.received_chunks(&[2u8; 16]).expect("куски"), 3);

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_file_whose_bytes_did_not_travel_stops_calling_itself_whole() {
    // Архив без вложений несёт **записи** о них и не несёт байтов. Оставить
    // такую запись «целой» значит показать человеку файл, который
    // не открывается, — ровно то, что §14 запрещает.
    let db = TempDb::new("nofiles-out");
    let landing = TempDb::new("nofiles-in");
    let mut store = account_with_everything(&db);
    store.note_chunk(&[2u8; 16], 0).unwrap();
    store.note_chunk(&[2u8; 16], 1).unwrap();
    store.note_chunk(&[2u8; 16], 2).unwrap();
    store.complete_file(&[2u8; 16]).unwrap();
    store.set_accepted(&[2u8; 16], true).unwrap();
    assert!(store.file(&[2u8; 16]).unwrap().unwrap().complete, "до вывоза — целое");

    let db_key = store.export_key().unwrap();
    let bytes =
        archived(&store, [12u8; 16], ratatosk_store::archive::ExportScope::WithoutAttachments);
    let archive = archive_file("nofiles", &bytes);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let done = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&db_key),
        &landing.0,
        &mut blobs,
    )
    .expect("ввоз");
    assert_eq!(done.files, 1, "запись о вложении доехала");
    assert_eq!(done.whole_files, 0, "а байты — нет, и запись это признаёт");

    let back = SqliteStore::open(&landing.0, key(1)).unwrap();
    let stored = back.file(&[2u8; 16]).expect("файл").expect("запись на месте");
    assert_eq!(stored.name, "файл 2.pdf", "имя вложения при этом никуда не делось");
    assert!(!stored.complete, "целым его называть больше нельзя");
    assert!(
        !stored.accepted,
        "и согласие снято: иначе первое подключение потянуло бы с собеседников всё, \
         от чего человек только что отказался"
    );
    assert_eq!(back.received_chunks(&[2u8; 16]).expect("куски"), 0, "отметки о кусках — чужие");

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn an_import_over_a_living_account_is_refused() {
    // Ввоз поверх живого аккаунта — это стереть человеку переписку
    // по нажатию кнопки «восстановить». И решить за него, чьей остаётся
    // личность, тоже нельзя: человек не бывает двумя людьми.
    let db = TempDb::new("over-out");
    let occupied = TempDb::new("over-in");
    let store = account_with_everything(&db);
    let db_key = store.export_key().unwrap();
    let bytes = archived(&store, [13u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let archive = archive_file("over", &bytes);

    // На месте назначения уже есть база — та, что завёл `TempDb`... точнее,
    // заведём её нарочно.
    {
        let mut living = SqliteStore::open(&occupied.0, key(2)).unwrap();
        living.migrate().unwrap();
        living.put_message(&message(7, 700)).unwrap();
    }

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let refused = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&db_key),
        &occupied.0,
        &mut blobs,
    );
    assert!(refused.is_err(), "поверх живого аккаунта ввоза нет");

    // И живое не тронуто.
    let living = SqliteStore::open(&occupied.0, key(2)).unwrap();
    assert_eq!(living.messages(&[9u8; 16], 10, None).unwrap().len(), 1, "чужая база цела");

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_wrong_key_leaves_no_half_made_account_behind() {
    // Человек ошибся ключом — самое обычное дело, ключ длинный. После
    // отказа не должно остаться ни базы, ни обрывка под её именем:
    // вторая попытка иначе упёрлась бы в «здесь уже есть база».
    let db = TempDb::new("badkey-out");
    let landing = TempDb::new("badkey-in");
    let store = account_with_everything(&db);
    let bytes = archived(&store, [14u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let archive = archive_file("badkey", &bytes);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let wrong = Zeroizing::new([2u8; 32]);
    let refused = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&wrong),
        &landing.0,
        &mut blobs,
    );
    assert!(refused.is_err(), "чужой ключ не должен открывать архив");
    assert!(!landing.0.exists(), "база не появилась");
    assert!(
        !landing.0.with_extension("import-tmp").exists(),
        "и обрывок не остался: вторая попытка обязана быть возможной"
    );

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_truncated_archive_creates_nothing_at_all() {
    // Оборванный архив, принятый за законченный, дал бы половину переписки,
    // выглядящую целой. Здесь — обрыв внутри записи.
    let db = TempDb::new("cut-out");
    let landing = TempDb::new("cut-in");
    let store = account_with_everything(&db);
    let db_key = store.export_key().unwrap();
    let bytes = archived(&store, [15u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let archive = archive_file("cut", &bytes[..bytes.len() - 10]);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let refused = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&db_key),
        &landing.0,
        &mut blobs,
    );
    assert!(refused.is_err(), "обрыв обязан быть отказом, а не половиной аккаунта");
    assert!(!landing.0.exists());

    let _ = std::fs::remove_file(&archive);
}

/// Заворачивает ключ базы во фразу — так, как это делает ядро при вывозе.
fn wrapped(db_key: &Zeroizing<[u8; 32]>, archive_id: [u8; 16], phrase: &str) -> Vec<u8> {
    let salt = [0x5Au8; ratatosk_store::archive::WRAP_SALT_LEN];
    let params = ratatosk_crypto::storage_key::KdfParams::default();
    let from_phrase = ratatosk_crypto::storage_key::derive_from_pin(phrase, &salt, params).unwrap();
    let sealed = ratatosk_crypto::storage_key::seal_field(
        &from_phrase,
        &ratatosk_store::archive::wrapped_key_aad(&archive_id),
        &db_key[..],
    )
    .unwrap();
    ratatosk_store::archive::KeyWrap {
        salt,
        memory_kib: params.memory_kib,
        iterations: params.iterations,
        parallelism: params.parallelism,
        sealed,
    }
    .to_bytes()
}

/// Архив, запертый фразой: завёрнутый ключ первой записью, дальше база.
fn phrase_locked_archive(store: &SqliteStore, archive_id: [u8; 16], phrase: &str) -> Vec<u8> {
    let db_key = store.export_key().unwrap();
    let mut out = Vec::new();
    let head = ratatosk_store::archive::Header {
        archive_id,
        scope: ratatosk_store::archive::ExportScope::Everything,
    };
    let mut writer = ratatosk_store::archive::ArchiveWriter::start(&mut out, head).unwrap();
    ratatosk_store::archive::ArchiveSink::put(
        &mut writer,
        ratatosk_store::archive::EntryKind::WrappedKey,
        &[0u8; 16],
        0,
        &wrapped(&db_key, archive_id, phrase),
    )
    .unwrap();
    store.export_into(ratatosk_store::archive::ExportScope::Everything, &mut writer).unwrap();
    writer.finish().unwrap();
    out
}

#[test]
fn an_archive_locked_with_a_phrase_opens_with_that_phrase() {
    // Ради этого заворачивание и делалось: пятьдесят два знака человек
    // не запомнит, а фразу, которую он придумал сам, — запомнит.
    let db = TempDb::new("phrase-out");
    let landing = TempDb::new("phrase-in");
    let store = account_with_everything(&db);
    let bytes = phrase_locked_archive(&store, [21u8; 16], "четыре весёлых кота");
    let archive = archive_file("phrase", &bytes);
    std::fs::remove_file(&landing.0).ok();

    // Сперва архив спрашивают, чего он хочет: экран, требующий фразу там,
    // где её нет, — тупик.
    let peek = ratatosk_store::peek_archive(&archive).expect("заглянуть");
    assert!(peek.takes_passphrase, "архив с завёрнутым ключом открывается фразой");
    assert_eq!(peek.scope, ratatosk_store::archive::ExportScope::Everything);

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let done = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Passphrase("четыре весёлых кота"),
        &landing.0,
        &mut blobs,
    )
    .expect("ввоз по фразе");
    assert_eq!(done.messages, 2);
    assert_eq!(done.contacts, 1);

    let back = SqliteStore::open(&landing.0, key(1)).unwrap();
    assert_eq!(back.messages(&[9u8; 16], 10, None).unwrap().len(), 2);

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn the_raw_key_still_opens_an_archive_locked_with_a_phrase() {
    // Второй вход, и он не запасной по важности: фразу пятилетней давности
    // человек забудет, а строка в менеджере паролей переживёт и его память,
    // и телефон.
    let db = TempDb::new("both-out");
    let landing = TempDb::new("both-in");
    let store = account_with_everything(&db);
    let db_key = store.export_key().unwrap();
    let bytes = phrase_locked_archive(&store, [22u8; 16], "фраза");
    let archive = archive_file("both", &bytes);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let done = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Key(&db_key),
        &landing.0,
        &mut blobs,
    )
    .expect("ввоз тем же ключом");
    assert_eq!(done.messages, 2, "завёрнутый ключ не мешает войти сырым");

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_wrong_phrase_is_refused_and_leaves_nothing() {
    let db = TempDb::new("badphrase-out");
    let landing = TempDb::new("badphrase-in");
    let store = account_with_everything(&db);
    let bytes = phrase_locked_archive(&store, [23u8; 16], "правильная");
    let archive = archive_file("badphrase", &bytes);
    std::fs::remove_file(&landing.0).ok();

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let refused = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Passphrase("неправильная"),
        &landing.0,
        &mut blobs,
    );
    assert!(refused.is_err(), "чужая фраза не открывает архив");
    assert!(!landing.0.exists(), "и ничего не остаётся");

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_phrase_offered_to_an_archive_without_one_says_so() {
    // Архив постарше фразой не запирался. Отказ обязан назвать причину:
    // иначе человек будет вспоминать фразу, которой никогда не было.
    let db = TempDb::new("nophrase-out");
    let landing = TempDb::new("nophrase-in");
    let store = account_with_everything(&db);
    let bytes = archived(&store, [24u8; 16], ratatosk_store::archive::ExportScope::Everything);
    let archive = archive_file("nophrase", &bytes);
    std::fs::remove_file(&landing.0).ok();

    assert!(
        !ratatosk_store::peek_archive(&archive).unwrap().takes_passphrase,
        "у старого архива фразы нет, и спрашивать её нельзя"
    );

    let mut blobs = ratatosk_store::MemoryBlobs::new();
    let refused = ratatosk_store::import_archive(
        &archive,
        ratatosk_store::ArchiveUnlock::Passphrase("любая"),
        &landing.0,
        &mut blobs,
    );
    let why = refused.expect_err("отказ").to_string();
    assert!(why.contains("фразой не открывается"), "причина обязана быть названа: {why}");

    let _ = std::fs::remove_file(&archive);
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

// --- Группы (§11) ---------------------------------------------------------

fn group(byte: u8, title: &str, created_ms: u64) -> StoredGroup {
    StoredGroup {
        chat_id: [byte; 16],
        owner_ik: [byte.wrapping_add(100); 32],
        title: title.to_owned(),
        // Метка нулевая: заготовка про хранение, а не про порядок,
        // а тесты порядка ставят её сами.
        title_wall: 0,
        title_logical: 0,
        created_ms,
        // Профиль `closed` — заготовка про хранение группы; про канал
        // спрашивают отдельные проверки ниже.
        profile: 0,
    }
}

fn op(member: u8, wall: u64, removed: bool) -> StoredMembershipOp {
    StoredMembershipOp {
        member_ik: [member; 32],
        tag_wall: wall,
        tag_logical: 0,
        tag_actor: [1u8; 32],
        tag_uniq: [member; 8],
        removed,
    }
}

#[test]
fn a_group_survives_reopening_with_its_title() {
    let db = TempDb::new("group");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.group(&[7u8; 16]).unwrap().unwrap();
    assert_eq!(found.title, "у костра");
    assert_eq!(found.owner_ik, [107u8; 32]);
    assert_eq!(found.created_ms, 1_000);
}

#[test]
fn the_group_title_is_not_in_the_file() {
    // Как человек назвал круг знакомых — сведение того же рода, что текст
    // сообщения (§12), и на диске его быть не должно.
    let db = TempDb::new("group-plain");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "капибары у костра", 1_000)).unwrap();
    }

    // WAL сливается в основной файл при закрытии соединения; читаем оба
    // на случай, если что-то осталось.
    let mut bytes = std::fs::read(&db.0).unwrap_or_default();
    bytes.extend(std::fs::read(db.0.with_extension("db-wal")).unwrap_or_default());
    let haystack = String::from_utf8_lossy(&bytes);
    assert!(!haystack.contains("капибары"), "название группы лежит в файле открытым текстом");
}

#[test]
fn a_wrong_key_does_not_open_the_group_title() {
    let db = TempDb::new("group-key");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(2)).unwrap();
    assert!(store.group(&[7u8; 16]).is_err(), "чужой ключ не должен открывать название");
}

#[test]
fn a_repeated_put_renames_the_group_but_keeps_its_owner() {
    // Владелец у группы один и на всю жизнь (§11.2): смена его здесь
    // означала бы, что право исключать переехало молча.
    let db = TempDb::new("group-owner");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    let mut renamed = group(7, "у большого костра", 5_000);
    renamed.owner_ik = [3u8; 32];
    store.put_group(&renamed).unwrap();

    let found = store.group(&[7u8; 16]).unwrap().unwrap();
    assert_eq!(found.title, "у большого костра", "название обязано обновиться");
    assert_eq!(found.owner_ik, [107u8; 32], "владелец обязан остаться прежним");
    assert_eq!(found.created_ms, 1_000, "время заведения обязано остаться прежним");
}

// --- Представление канала (фаза 2, §6.1–§6.3) ------------------------------

fn channel(version: u64, grants: Vec<StoredGrant>) -> StoredChannel {
    StoredChannel {
        chat_id: [7u8; 16],
        version,
        owner_ik: [107u8; 32],
        kind: 1,
        title: "лента".to_owned(),
        pow_bits: 20,
        seed_days: 30,
        seed_bytes: 1 << 20,
        // Байты и подпись здесь не настоящие: проверка про хранение,
        // а не про криптографию. Важно, что они доезжают **побайтово**.
        block_bytes: vec![version as u8; 64],
        signature: [9u8; 64],
        received_ms: 1_000,
        grants,
    }
}

fn grant(who: u8, rights: u32, until_ms: u64) -> StoredGrant {
    StoredGrant { who: [who; 32], rights, until_ms }
}

/// Чат заводится до представления: у `channel_representations` внешний
/// ключ на `chats`, и в файловой базе без строки чата вставка не пройдёт.
fn with_a_channel_chat(store: &mut dyn Store) {
    let mut row = group(7, "лента", 1_000);
    row.profile = 1;
    store.put_group(&row).unwrap();
}

#[test]
fn a_representation_survives_reopening_byte_for_byte() {
    let db = TempDb::new("channel");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        with_a_channel_chat(&mut store);
        store.put_channel(&channel(3, vec![grant(2, 1, 5_000), grant(1, 3, 9_000)])).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.channel(&[7u8; 16]).unwrap().expect("представление на месте");
    assert_eq!(found.version, 3);
    assert_eq!(found.title, "лента");
    assert_eq!(found.kind, 1);
    assert_eq!(found.pow_bits, 20);
    assert_eq!(found.seed_bytes, 1 << 20);
    // **Главное в этой проверке.** Подпись проверяется над принятыми
    // байтами (§6); измени их хранение на один байт — и документ,
    // проверившийся при приёме, перестал бы проверяться после перезапуска.
    assert_eq!(found.block_bytes, vec![3u8; 64], "байты под подписью обязаны дожить целыми");
    assert_eq!(found.signature, [9u8; 64]);
    assert_eq!(
        found.grants,
        vec![grant(1, 3, 9_000), grant(2, 1, 5_000)],
        "выдачи отдаются в порядке адресата, а не вставки"
    );
}

#[test]
fn the_channel_title_is_not_in_the_file() {
    // Как владелец назвал канал — сведение того же рода, что название
    // группы и текст сообщения (§12).
    let db = TempDb::new("channel-plain");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        with_a_channel_chat(&mut store);
        let mut it = channel(1, Vec::new());
        it.title = "капибары вещают".to_owned();
        store.put_channel(&it).unwrap();
    }

    let mut bytes = std::fs::read(&db.0).unwrap_or_default();
    bytes.extend(std::fs::read(db.0.with_extension("db-wal")).unwrap_or_default());
    let haystack = String::from_utf8_lossy(&bytes);
    assert!(!haystack.contains("капибары"), "название канала лежит в файле открытым текстом");
}

#[test]
fn a_new_version_replaces_the_grants_and_does_not_merge_them() {
    // **Снятие права выражается тем, что строки больше нет** (§6.2):
    // список в новой версии — это всё, что действует. Слейся он
    // с прежним, снятое право воскресло бы, и заметить это было бы
    // некому: документ подписан, а лишняя строка подписи не портит.
    for backend in 0..2 {
        let db = TempDb::new(&format!("channel-grants-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };
        with_a_channel_chat(store);

        store.put_channel(&channel(1, vec![grant(1, 1, 5_000), grant(2, 1, 5_000)])).unwrap();
        store.put_channel(&channel(2, vec![grant(1, 1, 9_000)])).unwrap();

        let found = store.channel(&[7u8; 16]).unwrap().unwrap();
        assert_eq!(found.version, 2);
        assert_eq!(found.grants, vec![grant(1, 1, 9_000)], "снятая выдача не должна воскреснуть");
    }
}

#[test]
fn unknown_rights_bits_reach_the_disk_and_come_back() {
    // Биты прав заведены ровно ради этого: сборка постарше обязана
    // **сохранить** право, которого не знает. Потеряй она бит при записи —
    // и отдала бы соседу документ, где прав меньше, чем подписал владелец.
    for backend in 0..2 {
        let db = TempDb::new(&format!("channel-bits-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };
        with_a_channel_chat(store);

        let odd = 1 | (1 << 17);
        store.put_channel(&channel(1, vec![grant(1, odd, 5_000)])).unwrap();
        assert_eq!(store.channel(&[7u8; 16]).unwrap().unwrap().grants[0].rights, odd);
    }
}

#[test]
fn both_backends_answer_the_same_about_a_channel() {
    // Трейт с одной честной реализацией не бывает абстракцией, а симуляция
    // §16 гоняет память. Разойдись они — стенд проверял бы не то, что
    // работает на устройстве.
    let db = TempDb::new("channel-both");
    let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
    sqlite.migrate().unwrap();
    let mut memory = MemoryStore::new();
    memory.migrate().unwrap();

    let it = channel(4, vec![grant(3, 8, 1_000), grant(1, 2, 7_000), grant(2, 4, 3_000)]);
    for store in [&mut sqlite as &mut dyn Store, &mut memory] {
        with_a_channel_chat(store);
        store.put_channel(&it).unwrap();
    }
    assert_eq!(sqlite.channel(&[7u8; 16]).unwrap(), memory.channel(&[7u8; 16]).unwrap());
    assert_eq!(sqlite.channel(&[8u8; 16]).unwrap(), None, "чужой чат — пусто у обоих");
    assert_eq!(memory.channel(&[8u8; 16]).unwrap(), None);
}

#[test]
fn deleting_a_chat_takes_everything_of_the_channel_with_it_in_both_backends() {
    // Отписка (§10.6) обещает: «чат удаляется, ключи стираются». Держится
    // это обещание на удалении чата, а каскад у двух хранилищ устроен
    // по-разному — внешним ключом в файловой базе и руками в памяти.
    //
    // **Паритет здесь и есть проверка.** Разойдись они, симуляция §16
    // проверяла бы отписку, которой на устройстве не бывает: в памяти
    // ключи чтения остались бы лежать, и «архив закрылся навсегда» было бы
    // ложью ровно там, где её никто не ищет. Тем же классом однажды
    // нашлись `group_avatars`.
    for backend in 0..2 {
        let db = TempDb::new(&format!("channel-delete-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };
        let who = if backend == 0 { "файловая база" } else { "память" };

        with_a_channel_chat(store);
        store.put_channel(&channel(2, vec![grant(1, 1, 9_000)])).unwrap();
        store.put_subscription(&subscription(3, 1, 2)).unwrap();
        store
            .put_archive_key(
                &[7u8; 16],
                &StoredArchiveKey { generation: 0, key: [42u8; 32], created_ms: 1_000 },
            )
            .unwrap();
        store
            .put_admit(
                &[7u8; 16],
                &ratatosk_store::StoredAdmit {
                    who: [1u8; 32],
                    admitted_by: [107u8; 32],
                    generation: 0,
                    block_bytes: vec![1, 2, 3],
                    signature: [4u8; 64],
                    created_ms: 1_000,
                },
            )
            .unwrap();
        // Заготовка обязана быть непустой — иначе проверка ниже была бы
        // истинной на пустом месте.
        assert!(!store.archive_keys(&[7u8; 16]).unwrap().is_empty(), "{who}: ключ не положился");

        store.delete_chat(&[7u8; 16]).unwrap();

        assert!(store.channel(&[7u8; 16]).unwrap().is_none(), "{who}: представление осталось");
        assert!(store.subscription(&[7u8; 16]).unwrap().is_none(), "{who}: подписка осталась");
        assert!(
            store.archive_keys(&[7u8; 16]).unwrap().is_empty(),
            "{who}: ключи чтения остались — архив остался бы открытым после отписки"
        );
        assert!(store.admits(&[7u8; 16]).unwrap().is_empty(), "{who}: учёт впусков остался");
    }
}

#[test]
fn asking_for_every_message_of_a_chat_does_not_bring_the_store_down() {
    // Поломка, найденная стендом отписки: «дай все сообщения» — это
    // `usize::MAX`, и он шёл в SQLite через перевод **величины протокола**,
    // где значение больше `i64::MAX` означает испорченные данные и роняет
    // отладочную сборку. Предел выборки — не величина протокола, а наша
    // собственная просьба.
    //
    // Тем же путём ходит очистка чата (`on_clear_chat`), то есть роняла
    // она не только отписку, и не в релизе: там перевод насыщался молча.
    let db = TempDb::new("limit-max");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "лента", 1_000)).unwrap();
    let mut row = message(1, 1_000);
    row.chat_id = [7u8; 16];
    store.put_message(&row).unwrap();

    let all = store.messages(&[7u8; 16], usize::MAX, None).unwrap();
    assert_eq!(all.len(), 1, "«дай всё» обязано отдавать всё, а не падать");
    assert_eq!(store.search(Some(&[7u8; 16]), "привет", usize::MAX).unwrap().len(), 0);
}

// --- Архив канала и окно сидирования (фаза 2, §7.2, §9.3) -----------------

fn arch_block(author: u8, seq: u64, size: usize) -> ratatosk_store::ArchivedBlock {
    ratatosk_store::ArchivedBlock {
        author_ik: [author; 32],
        seq,
        msg_id: [u8::try_from(seq).unwrap_or(0); 16],
        frame: vec![7u8; size],
        received_ms: 1_000 + seq * 1_000,
    }
}

#[test]
fn an_archived_block_comes_back_by_its_envelope_number() {
    // На `GRAFT` отвечают **по номеру конверта** (§7.1), а лежит блок
    // под «автор и позиция» (§7.3). Два ключа у одной строки — и оба
    // обязаны работать, иначе дерево не ответит на зов.
    let db = TempDb::new("archive-one");
    let chat = [3u8; 16];
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(3, "канал", 1_000)).unwrap();
        store.put_archived(&chat, &arch_block(9, 5, 10)).unwrap();
    }
    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.archived(&chat, &[5u8; 16]).unwrap().expect("кадр на месте");
    assert_eq!(found, arch_block(9, 5, 10), "архив переживает перезапуск целиком");
    assert!(store.archived(&chat, &[99u8; 16]).unwrap().is_none());
}

#[test]
fn a_have_vector_says_the_first_and_the_last() {
    // §7.2: «`Have{ ranges: [ { author_ik, first_seq, last_seq } ] }`»,
    // и §7.3 держится на том, что **между ними дыр нет**.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    let chat = [3u8; 16];
    for seq in [3u64, 4, 5, 6] {
        store.put_archived(&chat, &arch_block(9, seq, 10)).unwrap();
    }
    store.put_archived(&chat, &arch_block(1, 42, 10)).unwrap();

    let have = store.archive_have(&chat).unwrap();
    assert_eq!(have.len(), 2, "по строке на автора");
    let mine = have.iter().find(|r| r.author_ik == [9u8; 32]).expect("автор на месте");
    assert_eq!((mine.first_seq, mine.last_seq), (3, 6));
}

#[test]
fn a_gap_in_the_middle_breaks_the_have_vector_in_two() {
    // §7.3: «узел, имеющий 46 и 48, **знает**, что 47 существует».
    // Знает он это по вектору, и вектор обязан сказать правду: две
    // строки с провалом между ними, а не одна от первого до последнего.
    //
    // Первая редакция отдавала `MIN..MAX` на автора, и читатель,
    // пропустивший середину, объявлял, что она у него есть. Спросить
    // её он не мог — по собственному вектору выходило, что всё на месте,
    // — а сосед, попросивший у него пропущенное, получал молчание.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    let chat = [3u8; 16];
    // Читатель принял вступление (10), пропал на сорок номеров
    // и вернулся к пятьдесят первому.
    for seq in [10u64, 51, 52, 53] {
        store.put_archived(&chat, &arch_block(9, seq, 10)).unwrap();
    }

    let have = store.archive_have(&chat).unwrap();
    assert_eq!(have.len(), 2, "провал разрывает строку надвое; вектор: {have:?}");
    assert_eq!((have[0].first_seq, have[0].last_seq), (10, 10));
    assert_eq!((have[1].first_seq, have[1].last_seq), (51, 53));
    assert!(have.iter().all(|run| run.author_ik == [9u8; 32]), "автор у обеих строк один");
}

#[test]
fn two_authors_with_gaps_do_not_glue_into_one_run() {
    // Склейка идёт по **подряд идущим номерам одного автора**. Возьми
    // она только номер, хвост одного автора и начало другого слиплись бы
    // в одну строку — и вектор объявил бы чужие блоки своими.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    let chat = [3u8; 16];
    store.put_archived(&chat, &arch_block(1, 7, 10)).unwrap();
    store.put_archived(&chat, &arch_block(9, 8, 10)).unwrap();

    let have = store.archive_have(&chat).unwrap();
    assert_eq!(have.len(), 2, "разные авторы — разные строки; вектор: {have:?}");
    assert!(have.iter().all(|run| run.first_seq == run.last_seq));
}

#[test]
fn both_backends_see_the_same_gap() {
    // Трейт с одной честной реализацией не бывает абстракцией. Разойдись
    // хранилища здесь — один узел просил бы пропущенное, а другой считал
    // бы, что у него всё на месте.
    let db = TempDb::new("archive-gap-both");
    let chat = [3u8; 16];
    let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
    sqlite.migrate().unwrap();
    sqlite.put_group(&group(3, "канал", 1_000)).unwrap();
    let mut memory = MemoryStore::new();
    memory.migrate().unwrap();

    for store in [&mut sqlite as &mut dyn Store, &mut memory] {
        for seq in [1u64, 2, 5, 9, 10] {
            store.put_archived(&chat, &arch_block(9, seq, 10)).unwrap();
        }
        store.put_archived(&chat, &arch_block(1, 3, 10)).unwrap();
    }
    let have = sqlite.archive_have(&chat).unwrap();
    assert_eq!(have, memory.archive_have(&chat).unwrap(), "хранилища обязаны видеть одно");
    assert_eq!(have.len(), 4, "три куска у одного автора и один у другого; вектор: {have:?}");
}

#[test]
fn the_window_cuts_the_prefix_and_never_the_middle() {
    // §9.3 дословно: «удаляется **префикс** журнала, `first_seq`
    // в have-векторе поднимается; дыр в середине не бывает». Дыра
    // сделала бы have-вектор ложью, а §7.3 на нём стоит.
    //
    // Числа здесь свои, не из крейта: проверка стережёт обещание
    // «окно», а не сегодняшнее умолчание в тридцать суток.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    let chat = [3u8; 16];
    for seq in 1..=6u64 {
        store.put_archived(&chat, &arch_block(9, seq, 100)).unwrap();
    }
    // Шестьсот байт при окне в двести пятьдесят: влезают два кадра,
    // остальные четыре — префикс — уходят.
    let gone = store.prune_archive(&chat, 30, 250, 10_000).unwrap();
    assert_eq!(gone, 4, "снимается ровно столько, сколько не влезает");
    let have = store.archive_have(&chat).unwrap();
    assert_eq!((have[0].first_seq, have[0].last_seq), (5, 6), "снят префикс, хвост цел");
    let left = store.archived_range(&chat, &[9u8; 32], 0, 100).unwrap();
    let seqs: Vec<u64> = left.iter().map(|b| b.seq).collect();
    assert_eq!(seqs, vec![5, 6], "дыр в середине не бывает");
}

#[test]
fn the_window_also_cuts_by_age() {
    // Два предела, а не один: §9.3 называет `max_days` **и** `max_bytes`.
    // Канал, в котором говорят редко, обрезается временем, а не размером.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    let chat = [3u8; 16];
    for seq in 1..=4u64 {
        store.put_archived(&chat, &arch_block(9, seq, 10)).unwrap();
    }
    // Кадры лежат на 2, 3, 4 и 5 секунде; час спустя при окне в сутки
    // не уходит ничего, а при окне «ноль суток» уходит всё.
    assert_eq!(store.prune_archive(&chat, 1, u64::MAX, 3_600_000).unwrap(), 0);
    assert_eq!(store.prune_archive(&chat, 0, u64::MAX, 3_600_000).unwrap(), 4);
    assert!(store.archive_have(&chat).unwrap().is_empty());
}

#[test]
fn both_backends_cut_the_window_the_same_way() {
    // Трейт с одной честной реализацией не бывает абстракцией, а рой
    // на расхождении хранилищ дал бы have-векторы, которые не сходятся.
    let db = TempDb::new("archive-both");
    let chat = [3u8; 16];
    let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
    sqlite.migrate().unwrap();
    sqlite.put_group(&group(3, "канал", 1_000)).unwrap();
    let mut memory = MemoryStore::new();
    memory.migrate().unwrap();

    for store in [&mut sqlite as &mut dyn Store, &mut memory] {
        for seq in 1..=6u64 {
            store.put_archived(&chat, &arch_block(9, seq, 100)).unwrap();
        }
        store.prune_archive(&chat, 30, 250, 10_000).unwrap();
    }
    assert_eq!(sqlite.archive_have(&chat).unwrap(), memory.archive_have(&chat).unwrap());
    assert_eq!(
        sqlite.archived_range(&chat, &[9u8; 32], 0, 10).unwrap(),
        memory.archived_range(&chat, &[9u8; 32], 0, 10).unwrap()
    );
}

// --- Пир, который не контакт (§8.3) ----------------------------------------

fn peer(byte: u8) -> ratatosk_store::StoredPeer {
    ratatosk_store::StoredPeer {
        ik: [byte; 32],
        onion: "abcdefghij.onion".to_owned(),
        chatmail: "owner@nine.example".to_owned(),
        ygg: vec![7u8; 32],
        relays: vec!["wss://one.example".to_owned(), "wss://two.example".to_owned()],
        // Ключ рядом с реле, и в проверке он **обязателен**: доступность
        // ступени nostr считается по нему (миграция 0033). Потеряйся
        // столбец — `a_peer_survives_reopening_with_every_address`
        // краснеет, потому что сравнивает запись целиком.
        nostr: vec![5u8; 32],
        // Карточка — принятыми байтами (миграция 0034). Здесь она
        // не разбирается: хранилище возит байты, а разбирает их ядро.
        card: vec![0xa3, 0x01, 0x02],
        known_as: ratatosk_store::PEER_CHANNEL_OWNER,
        added_ms: 1_000,
    }
}

#[test]
fn a_peer_survives_reopening_with_every_address() {
    // Пир держит **адреса**, а не карточку: у владельца канала, узнанного
    // из ссылки (§10.1), карточки нет вовсе. Потеряйся здесь хоть один
    // адрес — лестница §5.4 после перезапуска спустилась бы ступенью ниже
    // и молча: «почты нет» она от «почта не отвечает» не отличает.
    let db = TempDb::new("peer");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_peer(&peer(9)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.peers().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0], peer(9), "пир доезжает до следующего запуска целиком");
}

#[test]
fn both_backends_answer_the_same_about_a_peer() {
    // Трейт с одной честной реализацией не бывает абстракцией, а симуляция
    // §16 гоняет память.
    let db = TempDb::new("peer-both");
    let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
    sqlite.migrate().unwrap();
    let mut memory = MemoryStore::new();
    memory.migrate().unwrap();

    for store in [&mut sqlite as &mut dyn Store, &mut memory] {
        store.put_peer(&peer(9)).unwrap();
        store.put_peer(&peer(3)).unwrap();
    }
    assert_eq!(sqlite.peers().unwrap(), memory.peers().unwrap());
    // Порядок — по ключу, и он одинаков у обоих: иначе симуляция §16
    // перестала бы быть воспроизводимой по сиду.
    assert_eq!(sqlite.peers().unwrap()[0].ik, [3u8; 32]);

    for store in [&mut sqlite as &mut dyn Store, &mut memory] {
        store.delete_peer(&[3u8; 32]).unwrap();
    }
    assert_eq!(sqlite.peers().unwrap().len(), 1);
    assert_eq!(memory.peers().unwrap().len(), 1);
}

#[test]
fn a_session_with_someone_who_is_not_a_contact_lies_down_on_disk() {
    // **То, ради чего снимался внешний ключ** (миграция 0031). Пока
    // `sessions.peer_ik` ссылался на `contacts(ik)`, сессия с пиром
    // физически не ложилась: вставка падала на ограничении, то есть
    // §8.3 был невозможен не по замыслу, а по схеме.
    let db = TempDb::new("session-peer");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_peer(&peer(9)).unwrap();
        store
            .put_session(&ratatosk_store::StoredSession {
                session_id: 42,
                peer_ik: [9u8; 32],
                binding: 0,
                snapshot: vec![1, 2, 3],
                established_ms: 1_000,
            })
            .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let sessions = store.sessions().unwrap();
    assert_eq!(sessions.len(), 1, "сессия с не-контактом обязана пережить перезапуск");
    assert_eq!(sessions[0].peer_ik, [9u8; 32]);
}

// --- Подписка и поколения ключа (фаза 2, §10.4, §6.4) ----------------------

fn subscription(min_version: u64, kind_claimed: u32, state: u32) -> StoredSubscription {
    StoredSubscription {
        chat_id: [7u8; 16],
        owner_ik: [107u8; 32],
        min_version,
        kind_claimed,
        state,
        joined_ms: 1_000,
    }
}

#[test]
fn a_subscription_survives_reopening() {
    // Порог версии обязан пережить перезапуск: без него §10.3 шаг 4
    // и §10.7 перестают действовать, и старая ссылка снова пускает.
    let db = TempDb::new("subscription");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        with_a_channel_chat(&mut store);
        store.put_subscription(&subscription(7, 2, 1)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.subscription(&[7u8; 16]).unwrap().expect("подписка на месте");
    assert_eq!(found.min_version, 7);
    assert_eq!(found.kind_claimed, 2);
    assert_eq!(found.state, 1);
    assert_eq!(found.owner_ik, [107u8; 32]);
    assert_eq!(store.subscription(&[8u8; 16]).unwrap(), None, "чужой чат — пусто");
}

#[test]
fn a_subscription_changes_state_but_a_key_generation_does_not_change_its_key() {
    // Два разных правила на соседних таблицах, и различие намеренное.
    // Подписка **меняется**: заявка становится участием. Поколение ключа
    // — нет: два разных ключа под одним номером это расхождение,
    // а не обновление, и затерев прежний, мы потеряли бы архив, который
    // он разворачивает (§6.4).
    for backend in 0..2 {
        let db = TempDb::new(&format!("subscription-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };
        with_a_channel_chat(store);

        store.put_subscription(&subscription(7, 2, 1)).unwrap();
        store.put_subscription(&subscription(7, 2, 2)).unwrap();
        assert_eq!(store.subscription(&[7u8; 16]).unwrap().unwrap().state, 2, "впустили");

        store
            .put_archive_key(
                &[7u8; 16],
                &StoredArchiveKey { generation: 0, key: [1u8; 32], created_ms: 1_000 },
            )
            .unwrap();
        store
            .put_archive_key(
                &[7u8; 16],
                &StoredArchiveKey { generation: 0, key: [2u8; 32], created_ms: 2_000 },
            )
            .unwrap();
        let keys = store.archive_keys(&[7u8; 16]).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key, [1u8; 32], "прежний ключ поколения затирать нельзя");
    }
}

#[test]
fn key_generations_live_side_by_side_and_come_back_in_order() {
    // §6.4: архив не теряется при повороте — читатель держит прежние
    // поколения для истории и получает новое для будущего.
    for backend in 0..2 {
        let db = TempDb::new(&format!("generations-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };
        with_a_channel_chat(store);

        // Кладём вразнобой: порядок обязан задаваться номером, а не
        // порядком вставки (§16).
        for generation in [2u64, 0, 1] {
            store
                .put_archive_key(
                    &[7u8; 16],
                    &StoredArchiveKey {
                        generation,
                        key: [u8::try_from(generation).unwrap(); 32],
                        created_ms: 1_000 + generation,
                    },
                )
                .unwrap();
        }
        let keys = store.archive_keys(&[7u8; 16]).unwrap();
        assert_eq!(keys.iter().map(|k| k.generation).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(keys[1].key, [1u8; 32]);
    }
}

#[test]
fn the_read_key_is_not_in_the_file() {
    // Ключ чтения канала — это доступ ко всему архиву (§5.4). На диске
    // открытым он лежать не должен, как и ключи сессий.
    let db = TempDb::new("generations-plain");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        with_a_channel_chat(&mut store);
        store
            .put_archive_key(
                &[7u8; 16],
                &StoredArchiveKey { generation: 0, key: [0xab; 32], created_ms: 1_000 },
            )
            .unwrap();
    }

    let mut bytes = std::fs::read(&db.0).unwrap_or_default();
    bytes.extend(std::fs::read(db.0.with_extension("db-wal")).unwrap_or_default());
    assert!(
        !bytes.windows(32).any(|w| w == [0xab; 32]),
        "ключ чтения канала лежит в файле открытым"
    );
}

// --- Профиль (фаза 2, §3.2) ------------------------------------------------

#[test]
fn a_profile_survives_reopening() {
    let db = TempDb::new("group-profile");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        let mut channel = group(7, "лента", 1_000);
        channel.profile = 1;
        store.put_group(&channel).unwrap();
        store.put_group(&group(8, "у костра", 1_000)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert_eq!(
        store.group(&[7u8; 16]).unwrap().unwrap().profile,
        1,
        "канал обязан остаться каналом"
    );
    assert_eq!(store.group(&[8u8; 16]).unwrap().unwrap().profile, 0, "группа — группой");
}

#[test]
fn a_group_written_before_the_column_existed_reads_as_closed() {
    // **Проверяется задним числом, а не на новых записях.** §14 обещает:
    // группы фазы 1 остаются `closed` навсегда. Живая база к моменту 0027
    // держит строки, написанные без этого столбца, и умолчание миграции —
    // единственное, что назначает им профиль.
    //
    // Проверка идёт **через настоящее чтение**, а не через `SELECT profile`:
    // столбец с умолчанием проверял бы SQLite, а нам надо знать, что
    // `group()` отдаёт такую строку и отдаёт её закрытой группой. Название
    // берётся зашифрованным из базы, накатанной до конца: ключ тот же
    // и чат тот же, значит и откроется оно тем же.
    let sealed = {
        let donor = TempDb::new("group-profile-donor");
        let mut store = SqliteStore::open(&donor.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(9, "у костра", 1_000)).unwrap();
        rusqlite::Connection::open(&donor.0)
            .unwrap()
            .query_row("SELECT title_enc FROM chats WHERE chat_id = ?1", [&[9u8; 16][..]], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .unwrap()
    };

    let up_to = ratatosk_store::schema::MIGRATIONS
        .iter()
        .position(|m| *m == ratatosk_store::schema::MIGRATION_0027)
        .expect("0027 в списке");
    let db = TempDb::new("group-profile-old");
    {
        let conn = rusqlite::Connection::open(&db.0).unwrap();
        for migration in &ratatosk_store::schema::MIGRATIONS[..up_to] {
            conn.execute_batch(migration).unwrap();
        }
        // Версия схемы ставится руками: без неё `migrate()` начал бы
        // с первой миграции и упал бы на «table contacts already exists».
        // Это и есть состояние живой базы накануне 0027.
        conn.pragma_update(None, "user_version", up_to as u32).unwrap();
        conn.execute(
            "INSERT INTO chats (chat_id, kind, owner_ik, title_enc, created_ms,
                                title_wall, title_logical)
             VALUES (?1, 1, ?2, ?3, 1000, 0, 0)",
            rusqlite::params![&[9u8; 16][..], &[109u8; 32][..], sealed],
        )
        .unwrap();
    }

    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    let found = store.group(&[9u8; 16]).unwrap().expect("строка на месте");
    assert_eq!(found.title, "у костра", "строка обязана дожить до нас целой");
    assert_eq!(found.profile, 0, "группа фазы 1 обязана остаться closed (§14)");
}

#[test]
fn a_profile_does_not_walk_back() {
    // Порода задаётся при заведении и не меняется (§6.1, §14).
    // `put_group` переписывает строку целиком — при переименовании тоже, —
    // и вызывающий, забывший привезти профиль, понизил бы канал до группы.
    // Здесь стоит `max`, чтобы забывчивость не была тихой порчей.
    for backend in 0..2 {
        let db = TempDb::new(&format!("group-profile-back-{backend}"));
        let mut sqlite = SqliteStore::open(&db.0, key(1)).unwrap();
        sqlite.migrate().unwrap();
        let mut memory = MemoryStore::new();
        memory.migrate().unwrap();
        let store: &mut dyn Store = if backend == 0 { &mut sqlite } else { &mut memory };

        let mut channel = group(7, "лента", 1_000);
        channel.profile = 1;
        store.put_group(&channel).unwrap();

        // Переименование, привёзшее умолчание вместо настоящего профиля.
        let mut renamed = group(7, "другая лента", 1_000);
        renamed.title_wall = 5_000;
        store.put_group(&renamed).unwrap();

        let found = store.group(&[7u8; 16]).unwrap().unwrap();
        assert_eq!(found.title, "другая лента", "название обязано обновиться");
        assert_eq!(found.profile, 1, "а канал — остаться каналом");
    }
}

#[test]
fn a_group_can_arrive_after_the_first_message_of_that_chat() {
    // Строку чата заводит приход сообщения — с `kind = 0` и пустым
    // владельцем. Сведение о группе может доехать вторым, и оно обязано
    // лечь в ту же строку.
    let db = TempDb::new("group-late");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    let mut said = message(1, 100);
    said.chat_id = [7u8; 16];
    store.put_message(&said).unwrap();
    assert!(store.group(&[7u8; 16]).unwrap().is_none(), "группы пока нет");

    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    let found = store.group(&[7u8; 16]).unwrap().unwrap();
    assert_eq!(found.owner_ik, [107u8; 32], "владелец обязан встать в пустое место");
    assert_eq!(store.messages(&[7u8; 16], 10, None).unwrap().len(), 1, "сообщение на месте");
}

#[test]
fn a_chat_that_is_not_a_group_is_not_listed_as_one() {
    let db = TempDb::new("group-only");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_message(&message(1, 100)).unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();

    let listed = store.groups().unwrap();
    assert_eq!(listed.len(), 1, "чат 1:1 не группа");
    assert_eq!(listed[0].chat_id, [7u8; 16]);
}

#[test]
fn groups_come_back_in_one_and_the_same_order() {
    // §16 требует воспроизводимости, а она держится на том, что порядок
    // чтения задан целиком, без опоры на порядок вставки.
    let db = TempDb::new("group-order");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_group(&group(9, "третья", 3_000)).unwrap();
    store.put_group(&group(2, "первая", 1_000)).unwrap();
    store.put_group(&group(5, "вторая", 2_000)).unwrap();

    let titles: Vec<String> = store.groups().unwrap().into_iter().map(|g| g.title).collect();
    assert_eq!(titles, vec!["первая", "вторая", "третья"]);
}

#[test]
fn membership_ops_survive_reopening_and_a_tombstone_never_lifts() {
    let db = TempDb::new("membership");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
        store.put_membership(&[7u8; 16], &[op(1, 10, false), op(2, 11, false)]).unwrap();
        // Удаление, а следом — то же добавление вторым заходом: в OR-Set
        // это обычное дело, и оно не должно снимать надгробие.
        store.put_membership(&[7u8; 16], &[op(2, 11, true)]).unwrap();
        store.put_membership(&[7u8; 16], &[op(2, 11, false)]).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let ops = store.membership(&[7u8; 16]).unwrap();
    assert_eq!(ops.len(), 2, "повтор той же метки не заводит новую строку");
    assert_eq!(ops[0], op(1, 10, false));
    assert_eq!(ops[1], op(2, 11, true), "надгробие обязано остаться стоять");
}

#[test]
fn membership_ops_come_back_in_one_and_the_same_order() {
    let db = TempDb::new("membership-order");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();

    store.put_membership(&[7u8; 16], &[op(3, 30, false), op(1, 10, false)]).unwrap();
    store.put_membership(&[7u8; 16], &[op(2, 20, false)]).unwrap();

    let walls: Vec<u64> =
        store.membership(&[7u8; 16]).unwrap().iter().map(|o| o.tag_wall).collect();
    assert_eq!(walls, vec![10, 20, 30]);
}

#[test]
fn a_sender_chain_survives_reopening_with_its_number() {
    // Ключ и номер врозь бессмысленны: ключ говорит, чем расшифровать,
    // номер — какое место в цепочке.
    let db = TempDb::new("chain");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
        store
            .put_sender_chain(
                &[7u8; 16],
                &StoredSenderChain {
                    member_ik: [1u8; 32],
                    chain: [42u8; 32],
                    counter: 0,
                    chain_wall: 0,
                    chain_logical: 0,
                    skipped: Vec::new(),
                },
            )
            .unwrap();
        store
            .put_sender_chain(
                &[7u8; 16],
                &StoredSenderChain {
                    member_ik: [1u8; 32],
                    chain: [43u8; 32],
                    counter: 7,
                    chain_wall: 0,
                    chain_logical: 0,
                    skipped: Vec::new(),
                },
            )
            .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
    assert_eq!(found.chain, [43u8; 32], "цепочка обязана обновиться");
    assert_eq!(found.counter, 7, "номер обязан приехать вместе с ключом");
    assert_eq!(store.sender_chains(&[7u8; 16]).unwrap().len(), 1, "обновление, а не вторая строка");
}

#[test]
fn a_sender_chain_belongs_to_one_group_and_one_member() {
    let db = TempDb::new("chain-scope");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store.put_group(&group(8, "у другого", 2_000)).unwrap();

    let mine = StoredSenderChain {
        member_ik: [1u8; 32],
        chain: [42u8; 32],
        counter: 3,
        chain_wall: 1_700_000_000_000,
        chain_logical: 4,
        skipped: Vec::new(),
    };
    store.put_sender_chain(&[7u8; 16], &mine).unwrap();

    // Метка поворота обязана пережить круг: по ней получатель отличает
    // свежее объявление цепочки от опоздавшего, и потеряйся она на диске —
    // после перезапуска он снова принимал бы любое.
    let found = store.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
    assert_eq!(found.chain_wall, 1_700_000_000_000, "метка поворота обязана лечь и подняться");
    assert_eq!(found.chain_logical, 4, "логическая часть метки — тоже");

    assert!(store.sender_chain(&[8u8; 16], &[1u8; 32]).unwrap().is_none(), "другая группа");
    assert!(store.sender_chain(&[7u8; 16], &[2u8; 32]).unwrap().is_none(), "другой участник");
    assert_eq!(store.sender_chains(&[7u8; 16]).unwrap(), vec![mine]);
    assert!(store.sender_chains(&[8u8; 16]).unwrap().is_empty());
}

#[test]
fn a_chain_moved_to_another_row_does_not_open() {
    // AAD привязывает шифротекст к паре «чат, участник»: переставленная
    // прямым доступом к файлу цепочка не открывается.
    let db = TempDb::new("chain-aad");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 3,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();
    drop(store);

    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute(
            "UPDATE sender_chains SET member_ik = ?1 WHERE member_ik = ?2",
            rusqlite::params![&[2u8; 32][..], &[1u8; 32][..]],
        )
        .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(
        store.sender_chain(&[7u8; 16], &[2u8; 32]).is_err(),
        "переставленная строка не открывается"
    );
}

#[test]
fn a_forgotten_group_takes_its_membership_and_chains_with_it() {
    // Каскад по внешнему ключу: состав и ключи отправителей — часть группы,
    // и переживать её они не должны.
    let db = TempDb::new("group-forget");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store.put_membership(&[7u8; 16], &[op(1, 10, false)]).unwrap();
    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 0,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();
    drop(store);

    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        raw.execute("DELETE FROM chats WHERE chat_id = ?1", [&[7u8; 16][..]]).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(store.group(&[7u8; 16]).unwrap().is_none());
    assert!(store.membership(&[7u8; 16]).unwrap().is_empty());
    assert!(store.sender_chains(&[7u8; 16]).unwrap().is_empty());
}

fn block(n: u8, author: u8, bytes: &str, received_ms: u64) -> StoredMembershipBlock {
    StoredMembershipBlock {
        block_id: [n; 16],
        author_ik: [author; 32],
        bytes: bytes.as_bytes().to_vec(),
        received_ms,
    }
}

#[test]
fn membership_blocks_survive_reopening_in_the_order_they_arrived() {
    let db = TempDb::new("blocks");

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
        store.put_membership_block(&[7u8; 16], &block(2, 20, "второй", 200)).unwrap();
        store.put_membership_block(&[7u8; 16], &block(1, 10, "первый", 100)).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.membership_blocks(&[7u8; 16]).unwrap();
    assert_eq!(found.len(), 2);
    assert_eq!(found[0], block(1, 10, "первый", 100), "порядок задан приёмом, а не вставкой");
    assert_eq!(found[1], block(2, 20, "второй", 200));
}

#[test]
fn the_same_block_arriving_twice_does_not_replace_its_bytes() {
    // Тот же блок законно приходит вторым транспортом (§9.2). Перезапись
    // означала бы, что байты, над которыми стоит подпись, можно подменить,
    // назвав прежний идентификатор, — а идентификатор и есть их хэш.
    let db = TempDb::new("blocks-twice");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();

    store.put_membership_block(&[7u8; 16], &block(1, 10, "настоящий", 100)).unwrap();
    let mut forged = block(1, 10, "подменённый", 900);
    forged.author_ik = [99u8; 32];
    store.put_membership_block(&[7u8; 16], &forged).unwrap();

    let found = store.membership_blocks(&[7u8; 16]).unwrap();
    assert_eq!(found.len(), 1, "повтор не заводит вторую строку");
    assert_eq!(found[0], block(1, 10, "настоящий", 100), "и не подменяет первую");
}

#[test]
fn membership_blocks_belong_to_one_group() {
    let db = TempDb::new("blocks-scope");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store.put_group(&group(8, "у другого", 2_000)).unwrap();

    store.put_membership_block(&[7u8; 16], &block(1, 10, "первый", 100)).unwrap();
    assert_eq!(store.membership_blocks(&[7u8; 16]).unwrap().len(), 1);
    assert!(store.membership_blocks(&[8u8; 16]).unwrap().is_empty());
}

#[test]
fn a_forgotten_group_takes_its_blocks_with_it() {
    let db = TempDb::new("blocks-forget");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store.put_membership_block(&[7u8; 16], &block(1, 10, "первый", 100)).unwrap();
    drop(store);

    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        raw.execute("DELETE FROM chats WHERE chat_id = ?1", [&[7u8; 16][..]]).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(store.membership_blocks(&[7u8; 16]).unwrap().is_empty());
}

#[test]
fn a_skipped_cache_survives_reopening_and_is_not_in_the_file() {
    // Кэш пропущенных ключей — ключевой материал: выброси его при
    // перезапуске, и всё, что уже в пути, не откроется (§11.1).
    let db = TempDb::new("skipped");
    let secret = b"skipped key material \xd0\xba\xd1\x8d\xd1\x88";

    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
        store
            .put_sender_chain(
                &[7u8; 16],
                &StoredSenderChain {
                    member_ik: [1u8; 32],
                    chain: [42u8; 32],
                    counter: 9,
                    chain_wall: 0,
                    chain_logical: 0,
                    skipped: secret.to_vec(),
                },
            )
            .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
    assert_eq!(found.skipped, secret, "кэш пережил перезапуск целиком");
    assert_eq!(found.counter, 9, "и номер вместе с ним");
    drop(store);

    let mut bytes = std::fs::read(&db.0).unwrap_or_default();
    bytes.extend(std::fs::read(db.0.with_extension("db-wal")).unwrap_or_default());
    assert!(!bytes.windows(secret.len()).any(|w| w == secret), "кэш ключей лежит в файле открытым");
}

#[test]
fn an_empty_skipped_cache_comes_back_empty() {
    // У своей цепочки пропусков не бывает по построению. Пустое значение
    // и NULL здесь одно и то же, и различать их незачем.
    let db = TempDb::new("skipped-none");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 0,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();

    let found = store.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
    assert!(found.skipped.is_empty());
    assert_eq!(store.sender_chains(&[7u8; 16]).unwrap()[0].skipped, Vec::<u8>::new());
}

#[test]
fn a_new_chain_wipes_the_cache_that_belonged_to_the_old_one() {
    // Пропуски относятся ровно к тому состоянию цепочки, из которого
    // выведены. Переживи они смену ключа — открывали бы номера цепочки,
    // которой больше нет.
    let db = TempDb::new("skipped-wipe");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();

    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 5,
                chain_wall: 0,
                chain_logical: 0,
                skipped: b"old".to_vec(),
            },
        )
        .unwrap();
    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [43u8; 32],
                counter: 0,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();

    let found = store.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
    assert_eq!(found.chain, [43u8; 32]);
    assert!(found.skipped.is_empty(), "кэш ушёл вместе с прежним ключом");
}

#[test]
fn a_cache_moved_to_another_row_does_not_open() {
    // AAD у кэша тот же, что у самой цепочки: пара «чат, участник».
    // Переставленный прямым доступом к файлу кэш не открывается.
    let db = TempDb::new("skipped-aad");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    store.put_group(&group(7, "у костра", 1_000)).unwrap();
    store
        .put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 3,
                chain_wall: 0,
                chain_logical: 0,
                skipped: b"cache".to_vec(),
            },
        )
        .unwrap();
    drop(store);

    {
        let raw = rusqlite::Connection::open(&db.0).unwrap();
        raw.execute(
            "UPDATE sender_chains SET member_ik = ?1 WHERE member_ik = ?2",
            rusqlite::params![&[2u8; 32][..], &[1u8; 32][..]],
        )
        .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    assert!(store.sender_chain(&[7u8; 16], &[2u8; 32]).is_err());
}

/// Гоняет проверку названия по **обеим** реализациям хранилища.
///
/// Расхождение здесь означало бы, что симуляция §16 проверяет не то, что
/// работает на устройстве: правило «только вперёд» записано двумя разными
/// способами — условием в SQL и сравнением в памяти, — и совпадать они
/// обязаны до последнего случая.
fn title_moves_forward_on<S: Store>(name: &str, store: &mut S) {
    let mut first = group(7, "у костра", 100);
    first.title_wall = 10;
    store.put_group(&first).expect("завели");

    let mut newer = first.clone();
    newer.title = "у большого костра".to_owned();
    newer.title_wall = 20;
    store.put_group(&newer).expect("новее");
    assert_eq!(
        store.group(&first.chat_id).expect("чтение").expect("есть").title,
        "у большого костра",
        "{name}: свежее применяется"
    );

    let mut older = first.clone();
    older.title = "устаревшее".to_owned();
    older.title_wall = 5;
    store.put_group(&older).expect("старее");
    let after = store.group(&first.chat_id).expect("чтение").expect("есть");
    assert_eq!(after.title, "у большого костра", "{name}: старое не затирает новое");
    assert_eq!(after.title_wall, 20, "{name}: и метка остаётся свежей");

    // Равные часы — спор решает логическая часть метки (§9.1).
    let mut same_wall = first.clone();
    same_wall.title = "тем же мигом, но позже".to_owned();
    same_wall.title_wall = 20;
    same_wall.title_logical = 3;
    store.put_group(&same_wall).expect("тот же миг");
    let after = store.group(&first.chat_id).expect("чтение").expect("есть");
    assert_eq!(after.title, "тем же мигом, но позже", "{name}: счётчик решает ничью");
    assert_eq!(after.title_logical, 3, "{name}");

    // И обратно: тот же миг, счётчик меньше — не применяется.
    let mut behind = first.clone();
    behind.title = "тем же мигом, но раньше".to_owned();
    behind.title_wall = 20;
    behind.title_logical = 1;
    store.put_group(&behind).expect("тот же миг, раньше");
    assert_eq!(
        store.group(&first.chat_id).expect("чтение").expect("есть").title,
        "тем же мигом, но позже",
        "{name}: меньший счётчик не побеждает"
    );
}

#[test]
fn a_group_title_only_moves_forward_in_the_file() {
    let db = TempDb::new("group-title-forward");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    title_moves_forward_on("файл", &mut store);
}

#[test]
fn a_group_title_only_moves_forward_in_memory() {
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    title_moves_forward_on("память", &mut store);
}

#[test]
fn a_group_title_tag_survives_reopening() {
    // Метка нужна после перезапуска не меньше, чем до: очередь §5.4
    // переживает процесс, и переименование, пролежавшее в ней ночь,
    // сравнивается уже с поднятой с диска меткой.
    let db = TempDb::new("group-title-tag");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        let mut with_tag = group(7, "у костра", 1_000);
        with_tag.title_wall = 42;
        with_tag.title_logical = 7;
        store.put_group(&with_tag).unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.group(&[7u8; 16]).unwrap().unwrap();
    assert_eq!((found.title_wall, found.title_logical), (42, 7));
    assert_eq!(found.title, "у костра", "и само название на месте");
}

fn png(byte: u8) -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.push(byte);
    bytes
}

/// Гоняет проверку аватарки группы по **обеим** реализациям хранилища.
///
/// Причина та же, что у названия: правило «только вперёд» записано двумя
/// разными способами — условием в SQL и сравнением в памяти, — и разойдись
/// они, симуляция §16 проверяла бы не то, что работает на устройстве.
fn group_avatar_moves_forward_on<S: Store>(name: &str, store: &mut S) {
    let chat = [7u8; 16];
    store.put_group(&group(7, "у костра", 100)).expect("группа");

    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(1), avatar_wall: 10, avatar_logical: 0 },
        )
        .expect("поставили");
    assert_eq!(
        store.group_avatar(&chat).expect("чтение").expect("есть").bytes,
        png(1),
        "{name}: картинка легла"
    );

    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(2), avatar_wall: 20, avatar_logical: 0 },
        )
        .expect("новее");
    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(3), avatar_wall: 5, avatar_logical: 0 },
        )
        .expect("старее");
    let after = store.group_avatar(&chat).expect("чтение").expect("есть");
    assert_eq!(after.bytes, png(2), "{name}: старое не затирает новое");
    assert_eq!(after.avatar_wall, 20, "{name}: и метка остаётся свежей");

    // Равные часы — спор решает логическая часть метки (§9.1).
    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(4), avatar_wall: 20, avatar_logical: 3 },
        )
        .expect("тот же миг");
    assert_eq!(
        store.group_avatar(&chat).expect("чтение").expect("есть").bytes,
        png(4),
        "{name}: счётчик решает ничью"
    );
    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(5), avatar_wall: 20, avatar_logical: 1 },
        )
        .expect("тот же миг, раньше");
    assert_eq!(
        store.group_avatar(&chat).expect("чтение").expect("есть").bytes,
        png(4),
        "{name}: меньший счётчик не побеждает"
    );

    // Снятие — такое же значение, как картинка, и метку оно двигает.
    // Строка при этом обязана остаться: без неё опоздавшая копия прежней
    // картинки легла бы обратно, потому что сравнивать было бы не с чем.
    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: Vec::new(), avatar_wall: 30, avatar_logical: 0 },
        )
        .expect("сняли");
    let after = store.group_avatar(&chat).expect("чтение").expect("строка осталась");
    assert!(after.bytes.is_empty(), "{name}: картинки нет");
    assert_eq!(after.avatar_wall, 30, "{name}: у снятия своя метка");

    store
        .put_group_avatar(
            &chat,
            &StoredGroupAvatar { bytes: png(6), avatar_wall: 25, avatar_logical: 0 },
        )
        .expect("опоздавшая");
    assert!(
        store.group_avatar(&chat).expect("чтение").expect("есть").bytes.is_empty(),
        "{name}: опоздавшая картинка не воскресает после снятия"
    );

    // Метка читается и без байтов — этим вопросом живёт список чатов.
    assert_eq!(store.group_avatar_stamp(&chat).expect("метка"), Some((30, 0)), "{name}");
    assert_eq!(
        store.group_avatar_stamp(&[9u8; 16]).expect("метка"),
        None,
        "{name}: у группы без картинки метки нет вовсе"
    );
}

#[test]
fn a_group_avatar_only_moves_forward_in_the_file() {
    let db = TempDb::new("group-avatar-forward");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    group_avatar_moves_forward_on("файл", &mut store);
}

#[test]
fn a_group_avatar_only_moves_forward_in_memory() {
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    group_avatar_moves_forward_on("память", &mut store);
}

#[test]
fn a_group_avatar_survives_reopening() {
    // Картинка шифруется, и ключ AAD привязан к строке: перепутай мы
    // ярлык или идентификатор чата при чтении, она не открылась бы —
    // а заметно это только после закрытия и открытия файла заново.
    let db = TempDb::new("group-avatar-reopen");
    {
        let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
        store.migrate().unwrap();
        store.put_group(&group(7, "у костра", 1_000)).unwrap();
        store
            .put_group_avatar(
                &[7u8; 16],
                &StoredGroupAvatar { bytes: png(9), avatar_wall: 42, avatar_logical: 7 },
            )
            .unwrap();
    }

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let found = store.group_avatar(&[7u8; 16]).unwrap().unwrap();
    assert_eq!(found.bytes, png(9));
    assert_eq!((found.avatar_wall, found.avatar_logical), (42, 7));
}

/// Гоняет каскад удаления чата по **обеим** реализациям хранилища.
fn a_deleted_chat_takes_the_group_with_it_on<S: Store>(name: &str, store: &mut S) {
    store.put_group(&group(7, "у костра", 100)).expect("группа");
    store
        .put_group_avatar(
            &[7u8; 16],
            &StoredGroupAvatar { bytes: png(1), avatar_wall: 10, avatar_logical: 0 },
        )
        .expect("картинка");
    store.delete_chat(&[7u8; 16]).expect("удаление чата");

    assert_eq!(store.group_avatar(&[7u8; 16]).expect("чтение"), None, "{name}: картинка ушла");
    assert_eq!(store.group(&[7u8; 16]).expect("чтение"), None, "{name}: и сама группа тоже");
    assert!(store.membership(&[7u8; 16]).expect("чтение").is_empty(), "{name}: и состав");
    assert!(store.sender_chains(&[7u8; 16]).expect("чтение").is_empty(), "{name}: и цепочки");
}

#[test]
fn a_deleted_chat_takes_the_group_with_it_in_the_file() {
    // Внешний ключ на `chats` с каскадом — в файловой базе, руками —
    // в памяти. Осиротевшая картинка это переписка, пережившая собственное
    // удаление, и она обязана уйти в обеих реализациях одинаково.
    let db = TempDb::new("group-avatar-cascade");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    a_deleted_chat_takes_the_group_with_it_on("файл", &mut store);
}

#[test]
fn a_deleted_chat_takes_the_group_with_it_in_memory() {
    // Найдено при заведении `group_avatars`: в памяти удаление чата
    // не сносило **ничего** группового, и подъём после удаления
    // в симуляции (§16) проверялся не тот, что на устройстве.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    a_deleted_chat_takes_the_group_with_it_on("память", &mut store);
}

/// Один файл на двух сообщениях — так выглядит пересланное вложение.
///
/// Проверяется на **обоих** хранилищах: расхождение здесь означало бы, что
/// тесты на памяти зелёные, а на устройстве вложение теряется.
fn a_file_may_belong_to_two_messages_on<S: Store>(what: &str, store: &mut S) {
    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();

    // Исходное сообщение с двумя вложениями.
    for (ordinal, id) in [10u8, 20].into_iter().enumerate() {
        let mut record = file(id, 1, true);
        record.ordinal = u32::try_from(ordinal).unwrap();
        record.complete = true;
        store.put_file(&record).unwrap();
    }
    // Пересылка: тот же `file_id`, второе сообщение. Перешифровывать байты
    // нельзя — чанк запечатан с `file_id` в AAD (§10.1), — поэтому файл
    // именно прикладывается.
    store.attach_file(&[2u8; 16], &[10u8; 16], 0).unwrap();

    let first: Vec<u8> = store.files_of(&[1u8; 16]).unwrap().iter().map(|f| f.file_id[0]).collect();
    let second: Vec<u8> =
        store.files_of(&[2u8; 16]).unwrap().iter().map(|f| f.file_id[0]).collect();
    assert_eq!(first, [10, 20], "{what}: у исходного сообщения оба вложения");
    assert_eq!(second, [10], "{what}: у пересланного — то, что переслали");

    let owners = store.messages_of_file(&[10u8; 16]).unwrap();
    assert_eq!(owners.len(), 2, "{what}: файл знает оба своих сообщения");

    // Удаление исходного не должно уносить байты у пересланной копии:
    // это и есть цена связки, ради которой она заведена.
    let orphans = store.detach_files_of(&[1u8; 16]).unwrap();
    assert_eq!(orphans, vec![[20u8; 16]], "{what}: осиротело только второе вложение");
    let left: Vec<u8> = store.files_of(&[2u8; 16]).unwrap().iter().map(|f| f.file_id[0]).collect();
    assert_eq!(left, [10], "{what}: пересланное вложение на месте");

    // А теперь и пересланное сообщение уходит — файл остаётся без ссылок.
    let orphans = store.detach_files_of(&[2u8; 16]).unwrap();
    assert_eq!(orphans, vec![[10u8; 16]], "{what}: последняя ссылка ушла — файл осиротел");
    // Строки осиротевших файлов уходят вместе со связкой — этот инвариант
    // держит триггер `files_drop_orphans`, а в памяти его зеркало. Список
    // возвращается всё равно: байты лежат не в хранилище, и убрать их
    // может только вызывающий.
    assert!(store.file(&[10u8; 16]).unwrap().is_none(), "{what}: файла без ссылок не бывает");
    assert!(store.file(&[20u8; 16]).unwrap().is_none(), "{what}: и второго тоже");
    assert!(
        store.orphan_file_ids().unwrap().is_empty(),
        "{what}: сироте неоткуда взяться — её уносит тот же шаг"
    );
}

#[test]
fn a_file_may_belong_to_two_messages() {
    let db = TempDb::new("file-shared");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    a_file_may_belong_to_two_messages_on("база", &mut store);
}

#[test]
fn a_file_may_belong_to_two_messages_in_memory() {
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    a_file_may_belong_to_two_messages_on("память", &mut store);
}

/// Повторная запись того же файла не отбирает у человека скачанное.
fn putting_a_known_file_again_keeps_what_we_have_on<S: Store>(what: &str, store: &mut S) {
    store.put_message(&message(1, 100)).unwrap();
    store.put_message(&message(2, 200)).unwrap();

    let mut mine = file(10, 1, true);
    mine.complete = true;
    store.put_file(&mine).unwrap();

    // Пересланная копия приезжает предложением: собран он у отправителя
    // или нет, в предложении не сказано, и `complete` там всегда ложь.
    let mut theirs = file(10, 2, true);
    theirs.complete = false;
    store.put_file(&theirs).unwrap();

    let read = store.file(&[10u8; 16]).unwrap().expect("файл на месте");
    assert!(read.complete, "{what}: собранный файл не отбирают ради строки о нём");
    assert_eq!(read.msg_id, [1u8; 16], "{what}: `file` называет самое раннее сообщение");
}

#[test]
fn putting_a_known_file_again_keeps_what_we_have() {
    let db = TempDb::new("file-keep");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();
    putting_a_known_file_again_keeps_what_we_have_on("база", &mut store);
}

#[test]
fn putting_a_known_file_again_keeps_what_we_have_in_memory() {
    let mut store = MemoryStore::new();
    store.migrate().unwrap();
    putting_a_known_file_again_keeps_what_we_have_on("память", &mut store);
}

#[test]
fn the_handshake_replay_cache_survives_a_restart() {
    // Ради этого всё и написано. §8.3 назначает записи кэша срок в тридцать
    // суток, а кэш жил в памяти — то есть срок не значил ничего. Ступень nostr
    // сделала это видимым: реле хранит события и отдаёт их снова после старта,
    // и забывчивый кэш принимал давнее рукопожатие как новое.
    //
    // Таблица под это лежала в схеме с самой первой миграции и не
    // использовалась ни разу.
    let db = TempDb::new("handshake-seen");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_handshake_seen(&[1u8; 32], 1_000).unwrap();
    store.put_handshake_seen(&[2u8; 32], 2_000).unwrap();
    // Повтор не заводит второй строки и **не** обновляет время: срок идёт
    // от первой встречи, иначе настойчивый повтор продлевал бы запись вечно.
    store.put_handshake_seen(&[1u8; 32], 9_000).unwrap();
    drop(store);

    let store = SqliteStore::open(&db.0, key(1)).unwrap();
    let seen = store.handshake_seen(0).unwrap();
    assert_eq!(seen.len(), 2, "обе записи пережили перезапуск");
    assert_eq!(seen[0], ([1u8; 32], 1_000), "и порядок — от старых к новым");
    assert_eq!(seen[1], ([2u8; 32], 2_000));
}

#[test]
fn the_handshake_replay_cache_is_cut_by_age_both_ways() {
    // Срок отсекается дважды — уборкой и при чтении. База могла пролежать
    // дольше срока, и просроченные записи не должны воскресать вместе с ней.
    let db = TempDb::new("handshake-age");
    let mut store = SqliteStore::open(&db.0, key(1)).unwrap();
    store.migrate().unwrap();

    store.put_handshake_seen(&[3u8; 32], 100).unwrap();
    store.put_handshake_seen(&[4u8; 32], 900).unwrap();

    assert_eq!(store.handshake_seen(500).unwrap().len(), 1, "чтение отсекает старое");

    store.prune_handshake_seen(500).unwrap();
    let left = store.handshake_seen(0).unwrap();
    assert_eq!(left, vec![([4u8; 32], 900)], "уборка убрала то же самое");
}

#[test]
fn the_memory_store_keeps_the_handshake_cache_the_same_way() {
    // Два хранилища обязаны вести себя одинаково: на `MemoryStore` живут
    // и стенд без `--data`, и симуляция §16, и почти все проверки ядра.
    // Разойдись они — поломка нашлась бы только на телефоне.
    let mut store = MemoryStore::new();
    store.migrate().unwrap();

    // Отпечатки нарочно взяты так, что порядок по хэшу и порядок по времени
    // **противоположны**: карта в памяти упорядочена ключом, и отдай она
    // записи этим порядком, уборка в кэше остановилась бы на первой же
    // «ещё свежей».
    store.put_handshake_seen(&[9u8; 32], 100).unwrap();
    store.put_handshake_seen(&[9u8; 32], 800).unwrap();
    store.put_handshake_seen(&[1u8; 32], 900).unwrap();

    assert_eq!(
        store.handshake_seen(0).unwrap(),
        vec![([9u8; 32], 100), ([1u8; 32], 900)],
        "от старых к новым, и повтор не обновил время"
    );
    assert_eq!(store.handshake_seen(500).unwrap(), vec![([1u8; 32], 900)]);

    store.prune_handshake_seen(500).unwrap();
    assert_eq!(store.handshake_seen(0).unwrap(), vec![([1u8; 32], 900)]);
}
