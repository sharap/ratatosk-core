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
use ratatosk_proto::mail::MailAccount;
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

/// Вывозит граф аккаунта в архив и отдаёт путь к нему.
fn graph_archive<S: Store>(engine: &mut Engine<S>, tag: &str, phrase: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "ratatosk-graph-{tag}-{}-{:?}.rtsk",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);
    engine
        .export_history(&path, ratatosk_core::ExportScope::SocialGraph, Some(phrase))
        .expect("граф вывезен");
    path
}

#[test]
fn a_foreign_graph_never_brings_the_verification_along() {
    // Половина ради которой слияние и делалось: человек уехал на новый
    // телефон с чистого листа и хочет вернуть **знакомства**, не возвращая
    // историю.
    //
    // И половина, ради которой оно так осторожно: личность у него новая,
    // значит прежний граф ей **чужой**, а из чужого списка сверка (§4.2)
    // не переносится никогда — поручительство не является сверкой голосом.
    let old = TempDb::new("graph-own-old");
    let new = TempDb::new("graph-own-new");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    // Старый телефон: контакт, сверенный голосом, и локальное имя к нему.
    let archive = {
        let mut store = old.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
        engine
            .step(
                1_000,
                Input::Command(Command::AddContact {
                    card_bytes: card_bytes.clone(),
                    met_in_person: true,
                }),
            )
            .expect("контакт");
        engine
            .step(
                1_100,
                Input::Command(Command::SetLocalName {
                    peer_ik,
                    name: Some("Оля с работы".to_owned()),
                }),
            )
            .expect("локальное имя");
        graph_archive(&mut engine, "own", "четыре весёлых кота")
    };

    // Новый телефон: **та же** личность (то же зерно), пустая переписка.
    let mut store = new.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
    // Зерно у новой базы своё, поэтому «свой граф» здесь не сойдётся —
    // и это правильный, самый частый случай: человек завёл новый аккаунт.
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().expect("подъём");
    assert!(engine.contacts().is_empty(), "начинали с чистого листа");

    let scratch = std::env::temp_dir().join("ratatosk-merge-scratch");
    let (merged, effects) = engine
        .merge_contacts_from(
            2_000,
            &archive,
            ratatosk_store::ArchiveUnlock::Passphrase("четыре весёлых кота"),
            &scratch,
        )
        .expect("слияние");

    assert_eq!(merged.added, 1, "знакомство доехало");
    assert_eq!(merged.known, 0);
    assert_eq!(merged.refused, 0);
    assert!(!merged.own_graph, "личность новая — граф для неё чужой");

    let contact = engine.contacts().get(&peer_ik).expect("контакт на месте");
    assert_eq!(contact.card.display_name, "собеседник");
    assert!(
        !contact.verified,
        "§4.2: сверка не переносится из чужого списка, а для новой личности \
         прежний граф — чужой"
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            ratatosk_core::Effect::Notify(ratatosk_core::Event::ContactAdded { .. })
        )),
        "о добавленном контакте обязано быть сказано событием"
    );

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn ones_own_graph_brings_the_verification_and_the_local_name() {
    // Другая половина того же правила. Архив, вывезенный **этой же**
    // личностью, — своя собственная запись: и сверка, и подпись к человеку
    // сделаны своей рукой. Терять их при переезде незачем.
    //
    // Личность здесь одна на две базы: так бывает после восстановления
    // из полного архива, когда граф вывозили отдельно и позже.
    let old = TempDb::new("graph-mine-old");
    let new = TempDb::new("graph-mine-new");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    let (archive, seed) = {
        let mut store = old.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let seed = store
            .meta(ratatosk_store::META_IDENTITY_SEED)
            .expect("зерно читается")
            .expect("зерно на месте");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
            .expect("контакт");
        engine
            .step(
                1_100,
                Input::Command(Command::SetLocalName {
                    peer_ik,
                    name: Some("Оля с работы".to_owned()),
                }),
            )
            .expect("локальное имя");
        (graph_archive(&mut engine, "mine", "фраза"), seed)
    };

    let mut store = new.open(&db_key);
    // Та же личность: зерно перенесено, как его переносит полный ввоз.
    store.put_meta(ratatosk_store::META_IDENTITY_SEED, &seed).expect("зерно на место");
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().expect("подъём");

    let scratch = std::env::temp_dir().join("ratatosk-merge-scratch");
    let (merged, _) = engine
        .merge_contacts_from(
            2_000,
            &archive,
            ratatosk_store::ArchiveUnlock::Passphrase("фраза"),
            &scratch,
        )
        .expect("слияние");

    assert!(merged.own_graph, "зерно то же — граф свой");
    assert_eq!(merged.added, 1);
    let contact = engine.contacts().get(&peer_ik).expect("контакт");
    assert!(contact.verified, "своя же сверка не теряется при переезде (§4.2)");
    assert_eq!(
        contact.local_name.as_deref(),
        Some("Оля с работы"),
        "и своя подпись к человеку — тоже"
    );

    let _ = std::fs::remove_file(&archive);
}

#[test]
fn a_known_contact_is_not_touched_by_a_merge() {
    // Правило то же, что у присланного контакта (§4.1): карточка в архиве
    // **не подписана**, и разреши мы обновление — граф, полученный от кого
    // угодно, переписал бы onion-адрес моего собеседника на чужой.
    let old = TempDb::new("graph-known-old");
    let new = TempDb::new("graph-known-new");
    let db_key = Zeroizing::new([5u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    let archive = {
        let mut store = old.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
        engine
            .step(
                1_000,
                Input::Command(Command::AddContact {
                    card_bytes: card_bytes.clone(),
                    met_in_person: false,
                }),
            )
            .expect("контакт");
        graph_archive(&mut engine, "known", "фраза")
    };

    let mut store = new.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().expect("подъём");
    // Тот же человек уже знаком, и **сверен голосом**.
    engine
        .step(1_500, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
        .expect("контакт");

    let scratch = std::env::temp_dir().join("ratatosk-merge-scratch");
    let (merged, _) = engine
        .merge_contacts_from(
            2_000,
            &archive,
            ratatosk_store::ArchiveUnlock::Passphrase("фраза"),
            &scratch,
        )
        .expect("слияние");

    assert_eq!(merged.added, 0);
    assert_eq!(merged.known, 1, "уже знаком — и об этом надо сказать числом");
    assert!(
        engine.contacts().get(&peer_ik).expect("контакт").verified,
        "сверка обязана уцелеть: архив её не знает, но трогать известного нельзя"
    );

    let _ = std::fs::remove_file(&archive);
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
fn added_when_survives_a_restart_and_means_added() {
    // Настоящий баг, найденный при выносе поля на границу §13.3, и увидеть
    // его можно **только** после перезапуска: в памяти момент добавления
    // лежал верный, а на диск при каждой записи контакта уезжало текущее
    // время. Записывается же контакт не только при добавлении — ещё при
    // сверке и при обновлении карточки (§4.3).
    //
    // Не замечал этого никто ровно потому, что поле никуда не отдавалось.
    // Первый же клиент, показавший «в контактах с …», показал бы «сегодня»
    // у человека, добавленного год назад.
    let db = TempDb::new("added");
    let db_key = Zeroizing::new([9u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность заведена");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём с чистой базы");

        engine
            .step(
                1_000,
                Input::Command(Command::AddContact {
                    card_bytes: card_bytes.clone(),
                    met_in_person: false,
                }),
            )
            .expect("контакт добавлен");
        assert_eq!(engine.contacts()[&peer_ik].added_ms, 1_000);

        // Сверка голосом — второе действие, и оно переписывает контакт
        // на диск. Ровно здесь «добавлен» и превращался в «сегодня».
        engine
            .step(500_000, Input::Command(Command::MarkVerified { peer_ik }))
            .expect("сверка принята");
        assert_eq!(engine.contacts()[&peer_ik].added_ms, 1_000, "в памяти было верно и раньше");
    }

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность поднята");
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    assert_eq!(engine.restore().expect("контакты подняты"), 1);

    let contact = &engine.contacts()[&peer_ik];
    assert!(contact.verified, "сверка пережила перезапуск");
    assert_eq!(
        contact.added_ms, 1_000,
        "«добавлен» — про первую встречу, а не про последнюю запись на диск"
    );
}

#[test]
fn a_switched_off_transport_stays_switched_off_after_a_restart() {
    // Выбор человека, а не состояние сети. Выключивший Tor обязан обнаружить
    // его выключенным и назавтра — иначе выключатель означает «до следующего
    // запуска», то есть не означает ничего.
    //
    // Хранит это ядро, а не клиент, и не из вкуса: §13.3 не пускает
    // протокольные решения выше границы, а «каким транспортом ехать» — оно
    // и есть. Второй экземпляр той же правды в настройках приложения однажды
    // разошёлся бы с тем, по которому ядро принимает решения, и разошёлся бы
    // молча.
    let db = TempDb::new("transports");
    let db_key = Zeroizing::new([5u8; 32]);

    {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().unwrap();

        // Умолчания заданы и разные: локальная сеть выключена (§5.1 — маяк
        // в эфире выдаёт присутствие устройства), onion включён.
        assert!(!engine.transports().contains(Transport::Lan), "§5.1: LAN по умолчанию выключен");
        assert!(engine.transports().contains(Transport::Onion), "onion по умолчанию включён");

        let effects = engine
            .step(
                1_000,
                Input::Command(Command::SetTransportEnabled {
                    transport: Transport::Onion,
                    enabled: false,
                }),
            )
            .unwrap();
        assert!(
            effects.iter().any(|e| matches!(
                e,
                ratatosk_core::Effect::SetTransportEnabled {
                    transport: Transport::Onion,
                    enabled: false
                }
            )),
            "транспорту обязаны сказать: гасить себя ему, а не ядру: {effects:?}"
        );

        // Повтор того же — бесплатно и молча: клиент выставляет переключатели
        // при каждом старте, и каждый такой старт не должен ничего значить.
        let again = engine
            .step(
                1_100,
                Input::Command(Command::SetTransportEnabled {
                    transport: Transport::Onion,
                    enabled: false,
                }),
            )
            .unwrap();
        assert!(again.is_empty(), "повтор того же значения ничего не делает: {again:?}");
    }

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();
    assert!(
        !engine.transports().contains(Transport::Onion),
        "выключенный транспорт обязан остаться выключенным"
    );

    // И транспортам об этом говорят при запуске — сами они не догадаются.
    let startup = engine.startup_effects();
    assert!(
        startup.iter().any(|e| matches!(
            e,
            ratatosk_core::Effect::SetTransportEnabled {
                transport: Transport::Onion,
                enabled: false
            }
        )),
        "при старте выбор обязан доехать до транспорта: {startup:?}"
    );
}

#[test]
fn a_mailbox_survives_the_restart_together_with_its_password() {
    // Ящик хранится там же, где переписка, и по той же причине, что и выбор
    // транспортов: §13.3 не пускает протокольные решения выше границы,
    // а «куда и чем входить» — часть выбора транспорта. Второй экземпляр
    // той же правды в настройках приложения однажды разошёлся бы с тем,
    // по которому ядро принимает решения, и разошёлся бы молча.
    //
    // Пароль лежит рядом с перепиской и защищён тем же ключом (§8.6).
    // Отдельное «более надёжное» место означало бы второй способ потерять
    // доступ, не убавив первого.
    let db = TempDb::new("mailbox");
    let db_key = Zeroizing::new([5u8; 32]);

    let mut account = MailAccount::from_address("a7f3k9@nine.example", "sekret");
    account.via_tor = false;
    account.smtp_port = 587;

    {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().unwrap();
        assert!(engine.mail_account().is_none(), "из коробки ящика нет");

        engine.step(1_000, Input::Command(Command::SetMailAccount(Some(account.clone())))).unwrap();
    }

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();
    assert_eq!(
        engine.mail_account(),
        Some(&account),
        "ящик обязан пережить перезапуск целиком — с портом и с выбором пути"
    );

    // И раннеру об этом говорят при запуске: сам он настройки взять негде.
    let startup = engine.startup_effects();
    assert!(
        startup.iter().any(|e| matches!(e, ratatosk_core::Effect::SetMailAccount(Some(_)))),
        "при старте ящик обязан доехать до транспорта: {startup:?}"
    );
}

#[test]
fn the_newest_session_of_a_family_is_the_one_that_sends_after_a_restart() {
    // Реестр держит в семействе одну отправляющую сессию — ту, что вставлена
    // последней. Прежняя при этом не исчезает, а остаётся принимать, и обе
    // лежат на диске.
    //
    // Порядок, в котором их отдаёт хранилище, ничем не задан. Без сортировки
    // по возрасту после перезапуска отправляющей могла бы стать та, что уже
    // ушла на покой, — и снаружи это выглядело бы как «после перезапуска
    // сообщения перестали доходить», без всякой видимой причины. По почте
    // такое не обнаруживается вовсе: квитанций там нет (§9.4).
    let db = TempDb::new("session-age");
    let db_key = Zeroizing::new([9u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    let newer_id = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).unwrap();
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
            .unwrap();

        // Две сессии одного семейства: так и бывает, когда прежняя ушла
        // на покой, а новая заняла её место.
        let older = Session::derive(Role::Initiator, peer_ik, b"older-transcript", b"noise", 1_000);
        let newer = Session::derive(Role::Initiator, peer_ik, b"newer-transcript", b"noise", 9_000);
        let newer_id = newer.session_id;
        assert_ne!(older.session_id, newer_id);

        // Кладём **новую первой**: если порядок чтения совпадёт с порядком
        // записи, тест поймает именно ту ошибку, ради которой написан.
        for (session, established_ms) in [(newer, 9_000u64), (older, 1_000u64)] {
            engine
                .store_mut()
                .put_session(&StoredSession {
                    session_id: session.session_id,
                    peer_ik,
                    lan: false,
                    snapshot: session.export().to_vec(),
                    established_ms,
                })
                .unwrap();
        }
        newer_id
    };

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();

    assert_eq!(
        engine.session_for(&peer_ik, Transport::Onion),
        Some(newer_id),
        "отправлять обязана самая свежая сессия семейства, а не та, \
         что первой попалась хранилищу"
    );
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

        // Сессия в базе локальная (`lan: true`) — значит и канал к ней
        // локальный, а локальная сеть по умолчанию выключена (§5.1) и после
        // перезапуска никем ещё не найдена. Без этих двух строк проверялась
        // бы отправка в сеть, которой нет: прямой канал спрашивает §5.4
        // наравне с очередью, и выключенный LAN он не выбирает.
        //
        // Это не подгонка под реализацию, а восстановление состояния, которое
        // на устройстве создают клиент и обнаружение: сессия переживает
        // перезапуск, видимость в сети — нет.
        engine
            .step(
                1_900,
                Input::Command(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Lan,
                    enabled: true,
                }),
            )
            .unwrap();
        engine.step(1_950, Input::SeenOnLan { peer_ik }).unwrap();

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
    // Канал поднимается заново — иначе тишина ниже ничего не доказывала бы:
    // она означала бы «некуда отправить», а проверяется «нечего отправлять».
    engine
        .step(
            2_900,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();
    engine.step(2_950, Input::SeenOnLan { peer_ik }).unwrap();

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
    engine
        .step(
            2_000,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();
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
fn a_lan_link_loss_keeps_the_session_and_silence_only_retires_it() {
    // Раньше здесь проверялось обратное: разрыв LAN закрывал сессию. Читалось
    // это как §5.4, но §5.4 запрещает **переносить** сессию в чужое семейство
    // транспортов, а не переживать разрыв сокета. Ошибка стоила дорого: сессия
    // умирала у одной стороны и оставалась у другой, та отправляла кадры
    // в никуда и видела «не доставлено» при живой связи. Лечилось только
    // удалением контакта.
    //
    // Второй заход по тем же граблям был мягче, но той же природы: молчание
    // в ответ на ушедший кадр сессию **закрывало**. А молчание —
    // свидетельство об одном направлении, сессия же двусторонняя (5ю).
    // Поэтому теперь она уходит на покой: принимать по ней можно, отправлять
    // нельзя, и отправка идёт через новое рукопожатие.
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

    // А вот молчание в ответ на ушедший кадр — отправляет её на покой.
    engine
        .step(
            3_000,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();
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

    let after = engine.step(9_000, Input::Timer { token }).unwrap();

    // Сессия остаётся — и это не недоделка, а разбор живой поломки (5ю).
    // Собеседник о нашем молчании не знает и продолжает слать по ней;
    // забыв её, мы отбрасывали бы каждый его кадр как «неизвестную сессию»,
    // а сказать ему об этом нечем — кадр не расшифрован, кто прислал,
    // неизвестно. Переписка умирала в одну сторону навсегда.
    assert_eq!(engine.session_count(), 1, "покойная сессия обязана остаться принимать");
    assert_eq!(engine.store().sessions().unwrap().len(), 1, "и с диска не убирается");

    // Но отправлять по ней больше нельзя: §5.4 идёт за новой сессией,
    // то есть за рукопожатием. Молчание обязано привести к нему, а не
    // к тишине — иначе сообщение просто исчезает (§14).
    assert!(
        after.iter().any(|e| matches!(e, ratatosk_core::Effect::Send { via: Transport::Lan, .. })),
        "покой без нового рукопожатия — это молчание, а не лечение: {after:?}"
    );
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
    engine
        .step(
            1_000,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();
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
fn a_message_in_flight_when_the_process_died_still_gets_sent() {
    // Самая старая дыра в доставке, и закрывается она здесь.
    //
    // Очередь ожидающих на диск ложилась давно: «отправим, когда появится» —
    // обещание, и без записи оно жило бы до конца процесса. А доставка
    // **в полёте** — та, для которой транспорт нашёлся и кадр ушёл, — жила
    // только в памяти. Убей процесс между «кадр отдан транспорту»
    // и подтверждением, и сообщение оставалось в `Pending` навсегда:
    // в очереди его нет, срок сработать неоткуда, вернуться некому.
    // На Android процесс убивают постоянно.
    //
    // Проверяется на **настоящей базе**: у `MemoryStore` нет ни файла,
    // ни перезапуска, и эту дыру он не показал бы никогда.
    let db = TempDb::new("in-flight");
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

        // Сессия заводится напрямую: проверяется переживание перезапуска,
        // а не §8.2. Порядок важен — `restore` перечитывает контакты с диска
        // и сбросил бы отметку «виден в эфире», поставь мы её раньше.
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
        engine.restore().unwrap();

        engine
            .step(
                1_100,
                Input::Command(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Lan,
                    enabled: true,
                }),
            )
            .unwrap();
        engine
            .step(1_100, Input::TransportReady { transport: ratatosk_proto::Transport::Lan })
            .unwrap();
        engine.step(1_100, Input::SeenOnLan { peer_ik }).unwrap();

        let effects = engine
            .step(2_000, Input::Command(Command::SendText { chat, text: "улетело".to_owned() }))
            .unwrap();
        assert!(
            effects.iter().any(|e| matches!(
                e,
                ratatosk_core::Effect::Send { via, .. }
                    if *via == ratatosk_proto::Transport::Lan
            )),
            "кадр обязан уйти — иначе это не полёт, а ожидание, и тест проверял бы не то"
        );
        assert_eq!(engine.queued(), 1, "доставка в полёте");
        assert_eq!(
            engine.store().outbox().unwrap().len(),
            1,
            "и лежит на диске: процесс могут убить прямо сейчас"
        );

        engine.store().messages(&chat, 10, None).unwrap()[0].msg_id
    };

    // Процесс убили между «кадр отдан транспорту» и подтверждением.
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).unwrap();
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().unwrap();

    assert_eq!(engine.queued(), 0, "в полёте после старта никого — и не должно быть");
    assert_eq!(
        engine.store().outbox().unwrap().len(),
        1,
        "а на диске доставка на месте и ждёт своего часа"
    );

    // И ядро возвращается к ней **само**, первым же действием запуска —
    // не дожидаясь, пока собеседник объявится в эфире.
    //
    // Проверяется именно `startup_effects`, а не `TransportReady`: у локальной
    // сети готовность выставлена с рождения (`IMMEDIATE_TRANSPORTS`), и такого
    // события для неё после старта не приходит вовсе. Полагаться на него
    // значило бы полагаться на то, чего нет.
    let startup = engine.startup_effects();
    assert!(!startup.is_empty());
    assert_eq!(engine.queued(), 1, "запуск сам взял недоделанную доставку в работу");
    assert!(engine.store().message(&msg_id).unwrap().is_some(), "сообщение никуда не делось");
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
        engine
            .step(
                1_000,
                Input::Command(Command::SetTransportEnabled {
                    transport: ratatosk_proto::Transport::Lan,
                    enabled: true,
                }),
            )
            .unwrap();

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

    engine
        .step(
            10_000,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();
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
    engine
        .step(
            1_000,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .unwrap();

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

#[test]
fn the_announced_card_survives_a_restart() {
    // Версия карточки (§4.3) обязана расти монотонно через перезапуски:
    // получатель принимает только строго большую, и сброс к единице
    // означал бы, что адреса у собеседников застыли навсегда и молча.
    //
    // Адреса — вместе с ней. Без них первое же объявление после старта
    // выглядит изменением, и на телефоне, где процесс убивают постоянно,
    // §4.3 превратился бы в рассылку на каждый запуск.
    let db = TempDb::new("card");
    let db_key = Zeroizing::new([5u8; 32]);
    let address = ratatosk_crypto::OnionKey::from_seed([9u8; 32]).address();

    // --- первый запуск: адрес появился ----------------------------------
    {
        let mut engine = Engine::new(
            Identity::from_seed([7u8; 32]),
            db.open(&db_key),
            blobs(),
            Box::new(OsEntropy),
            addresses(),
        );
        engine.restore().expect("подъём состояния");
        assert_eq!(engine.own_card().version, 1, "до объявления карточка первой версии");

        engine
            .step(
                1_000,
                Input::Command(Command::AnnounceAddresses {
                    onion: Some(address.clone()),
                    chatmail: Some(String::new()),
                }),
            )
            .expect("объявление адресов");
        assert_eq!(engine.own_card().version, 2);
        assert_eq!(engine.own_card().onion, address);
    }

    // --- второй запуск ---------------------------------------------------
    let mut engine = Engine::new(
        Identity::from_seed([7u8; 32]),
        db.open(&db_key),
        blobs(),
        Box::new(OsEntropy),
        addresses(),
    );
    engine.restore().expect("подъём состояния");

    assert_eq!(engine.own_card().version, 2, "версия поднялась с диска");
    assert_eq!(engine.own_card().onion, address, "и адрес вместе с ней");

    // Повтор того же объявления — ровно то, что клиент делает при каждом
    // старте, когда поднялся Tor. Он обязан быть бесплатным.
    let effects = engine
        .step(
            2_000,
            Input::Command(Command::AnnounceAddresses {
                onion: Some(address.clone()),
                chatmail: Some(String::new()),
            }),
        )
        .expect("повторное объявление");
    assert!(effects.is_empty(), "тот же адрес не рассылается заново");
    assert_eq!(engine.own_card().version, 2, "и версию не поднимает");

    // А смена — поднимает, и от двойки, а не от единицы.
    engine
        .step(
            3_000,
            Input::Command(Command::AnnounceAddresses {
                onion: Some(ratatosk_crypto::OnionKey::from_seed([10u8; 32]).address()),
                chatmail: Some(String::new()),
            }),
        )
        .expect("смена адреса");
    assert_eq!(engine.own_card().version, 3);
}

#[test]
fn a_group_survives_restart_with_its_title_owner_and_membership() {
    let db = TempDb::new("group");
    let db_key = Zeroizing::new([7u8; 32]);

    let (chat, mine) = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");

        let effects = engine
            .step(1_000, Input::Command(Command::CreateGroup { title: "у костра".to_owned() }))
            .expect("группа заведена");
        let chat = effects
            .iter()
            .find_map(|e| match e {
                ratatosk_core::Effect::Notify(ratatosk_core::Event::GroupCreated {
                    chat, ..
                }) => Some(*chat),
                _ => None,
            })
            .expect("событие о заведении");
        (chat, engine.own_card().ik)
    };

    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().expect("подъём");

    let state = engine.groups().get(&chat).expect("группа поднялась с диска");
    assert_eq!(state.title, "у костра");
    assert_eq!(state.created_ms, 1_000, "время заведения — то, а не время подъёма");
    assert_eq!(state.group.owner, mine);
    assert_eq!(state.group.members().copied().collect::<Vec<_>>(), vec![mine]);
}

#[test]
fn a_restored_owner_keeps_exactly_one_membership_tag() {
    // Ловушка, ради которой у `Group` есть `restore` отдельно от `create`.
    // Позови подъём `create`, у создателя оказалось бы две метки добавления:
    // поднятая из истории и выдуманная прямо сейчас. Вторую не гасит ни одно
    // удаление — их писали, видя только первую, — и создатель стал бы
    // неисключаемым после первого же перезапуска.
    //
    // Видно это только по истории: состав в обоих случаях один и тот же.
    let db = TempDb::new("group-tag");
    let db_key = Zeroizing::new([8u8; 32]);

    let chat = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
        engine
            .step(1_000, Input::Command(Command::CreateGroup { title: "у костра".to_owned() }))
            .expect("группа заведена")
            .iter()
            .find_map(|e| match e {
                ratatosk_core::Effect::Notify(ratatosk_core::Event::GroupCreated {
                    chat, ..
                }) => Some(*chat),
                _ => None,
            })
            .expect("событие о заведении")
    };

    let before = {
        let store = db.open(&db_key);
        store.membership(&chat).expect("история состава")
    };
    assert_eq!(before.len(), 1);

    // Три подъёма подряд: метка не размножается ни на одном.
    for _ in 0..3 {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
    }

    let store = db.open(&db_key);
    assert_eq!(
        store.membership(&chat).expect("история состава"),
        before,
        "подъём не имеет права дописывать историю состава"
    );
}

#[test]
fn a_group_copy_stays_silent_across_a_restart() {
    // Молчаливость групповой копии (§11.3, §14) жила только в памяти:
    // поднимая очередь с диска, ядро ставило `silent: false` всем подряд.
    // Значит перезапуск превращал копию в обычную доставку — со сроком
    // ответа, с ожиданием квитанции, которой не будет, и со статусом,
    // которого у группового сообщения быть не может.
    //
    // Теперь признак **выводится из кадра**, и второго экземпляра этого
    // факта нет вовсе. Проверяется по настоящему файлу: в памяти очередь
    // не переживает процесс и проверить тут нечего.
    let db = TempDb::new("group-silent");
    let db_key = Zeroizing::new([7u8; 32]);
    let (card_bytes, peer_ik) = peer_card();

    let (chat, msg_id) = {
        let mut store = db.open(&db_key);
        let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
        let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
        engine.restore().expect("подъём");
        engine
            .step(1_000, Input::Command(Command::AddContact { card_bytes, met_in_person: true }))
            .expect("контакт");
        let effects = engine
            .step(1_100, Input::Command(Command::CreateGroup { title: "у костра".to_owned() }))
            .expect("группа");
        let chat = effects
            .iter()
            .find_map(|e| match e {
                ratatosk_core::Effect::Notify(ratatosk_core::Event::GroupCreated {
                    chat, ..
                }) => Some(*chat),
                _ => None,
            })
            .expect("о заведении обязано прийти событие");
        engine
            .step(1_200, Input::Command(Command::InviteToGroup { chat, peer_ik }))
            .expect("приглашение");
        engine
            .step(1_300, Input::Command(Command::SendText { chat, text: "все тут?".to_owned() }))
            .expect("сказано");
        let msg_id = engine.store().messages(&chat, 10, None).expect("хранилище")[0].msg_id;
        assert_eq!(
            engine.store().message(&msg_id).expect("хранилище").expect("оно").status,
            None,
            "до перезапуска статуса нет"
        );
        (chat, msg_id)
    };

    // Новый процесс: та же база, то же сообщение, очередь поднимается с диска.
    let mut store = db.open(&db_key);
    let identity = vault::load_or_create(&mut store, &db_key).expect("личность");
    let mut engine = Engine::new(identity, store, blobs(), Box::new(OsEntropy), addresses());
    engine.restore().expect("подъём с диска");
    let _ = engine.startup_effects();
    engine.step(2_000, Input::Command(Command::NetworkChanged)).expect("сеть переключилась");

    assert!(engine.groups().contains_key(&chat), "группа поднялась");
    assert_eq!(
        engine.store().message(&msg_id).expect("хранилище").expect("оно").status,
        None,
        "и после перезапуска статуса у групповой копии нет"
    );
}
