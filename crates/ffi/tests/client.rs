//! Граница целиком, ровно так, как её увидит Kotlin или Tauri.
//!
//! Смысл этих тестов в том, что они ходят **только** через `RatatoskClient` —
//! ни `Engine`, ни `Driver` здесь не упоминаются. Всё, что нельзя сделать
//! отсюда, нельзя будет сделать и из UI, а `todo!()` за границей падает
//! паникой уже в первом же вызове.
//!
//! Двух узлов здесь нет намеренно: свести их через FFI можно было бы, только
//! вытащив наружу подстановку адреса LAN, а отладочная дырка в продуктовом
//! API переживает отладку. Обмен между узлами проверяет
//! `ratatosk-core --test lan`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ratatosk_ffi::{EventObserver, FfiDeliveryStatus, FfiEvent, RatatoskClient, RatatoskError};

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ratatosk-ffi-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_file(&path);
        TempDb(path)
    }

    fn path(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(self.0.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.0.with_extension("db-shm"));
    }
}

/// Наблюдатель, складывающий всё, что пришло, — это и делает UI.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<FfiEvent>>,
}

impl EventObserver for Recorder {
    fn on_event(&self, event: FfiEvent) {
        self.seen.lock().expect("замок цел").push(event);
    }
}

impl Recorder {
    /// Ждёт события, удовлетворяющего условию.
    ///
    /// Опрос, а не канал: наблюдатель — это то, что напишет клиент, и он
    /// тоже будет обычным объектом без всякой синхронизации с ядром.
    fn wait_for(&self, what: impl Fn(&FfiEvent) -> bool) -> bool {
        for _ in 0..200 {
            if self.seen.lock().expect("замок цел").iter().any(&what) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        false
    }
}

/// Чужая карточка: второй клиент нужен только ради его URI, поэтому он
/// открывается, отдаёт карточку и тут же закрывается.
fn someone_elses_uri(tag: &str) -> String {
    let db = TempDb::new(tag);
    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "Боб".to_owned())
        .expect("клиент открылся");
    assert!(client.contacts().expect("список читается").is_empty(), "у свежего клиента их нет");
    let uri = client.my_contact_uri();
    drop(client);
    settle();
    uri
}

/// Даёт потоку ядра свернуться, а файлу базы — освободиться.
///
/// Уничтожение клиента закрывает каналы, но поток разбирает себя не мгновенно.
/// В продукте это никого не касается, а тесту, который тут же открывает тот
/// же файл, — касается.
fn settle() {
    std::thread::sleep(std::time::Duration::from_millis(200));
}

#[test]
fn opening_twice_keeps_the_same_identity() {
    let db = TempDb::new("identity");

    let first = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("первый запуск");
    let fingerprint = first.fingerprint();
    let uri = first.my_contact_uri();
    assert!(uri.starts_with("ratatosk:v0:"), "карточка отдаётся как URI для QR (§4.1)");
    drop(first);
    settle();

    let second = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("второй запуск");
    assert_eq!(second.fingerprint(), fingerprint, "отпечаток обязан совпасть (§3)");
    assert_eq!(second.my_contact_uri(), uri, "и карточка тоже");
}

#[test]
fn a_wrong_pin_reports_locked_and_not_a_fresh_start() {
    let db = TempDb::new("pin");
    let first = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("первый запуск");
    drop(first);
    settle();

    let verdict = RatatoskClient::open(db.path(), Some("4321".to_owned()), "я".to_owned());
    assert!(
        matches!(verdict, Err(RatatoskError::Locked)),
        "неверный PIN обязан быть отличим от внутренней ошибки: его лечит \
         пользователь, а не переустановка"
    );
}

#[test]
fn a_contact_added_by_uri_shows_up_with_its_fingerprint() {
    let db = TempDb::new("contact");
    let uri = someone_elses_uri("peer-contact");

    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");
    let recorder = Arc::new(Recorder::default());
    client.set_observer(recorder.clone());

    client.add_contact(uri, false).expect("URI принят");
    assert!(
        recorder.wait_for(|e| matches!(e, FfiEvent::ContactAdded { .. })),
        "событие о добавлении обязано дойти до наблюдателя"
    );

    let contacts = client.contacts().expect("список читается");
    assert_eq!(contacts.len(), 1);
    assert!(!contacts[0].fingerprint.is_empty(), "отпечаток нужен для сверки голосом (§4.2)");
    assert!(!contacts[0].verified, "§4.2: по ссылке контакт непроверенный");
    assert_eq!(contacts[0].chat_id.len(), 16);

    // §4.2: сверка голосом переживает перезапуск.
    client.mark_verified(contacts[0].peer_ik.clone()).expect("отметка принята");
    // Отметка идёт через очередь команд; читаем, пока не увидим.
    let verified = (0..200).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(25));
        client.contacts().map(|c| c[0].verified).unwrap_or(false)
    });
    assert!(verified);
    drop(client);
    settle();

    let again = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("второй запуск");
    let contacts = again.contacts().expect("контакты поднялись с диска");
    assert_eq!(contacts.len(), 1);
    assert!(contacts[0].verified);
}

#[test]
fn a_sent_message_is_kept_and_reported_undeliverable() {
    // §14: сообщение, которому некуда ехать, остаётся в истории и помечается.
    // LAN выключен, onion и почты нет — значит, транспортов нет вовсе.
    let db = TempDb::new("send");
    let uri = someone_elses_uri("peer-send");

    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");
    let recorder = Arc::new(Recorder::default());
    client.set_observer(recorder.clone());

    client.add_contact(uri, true).expect("URI принят");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::ContactAdded { .. })));

    let chat = client.contacts().expect("список читается")[0].chat_id.clone();
    client.send_text(chat.clone(), "в пустоту".to_owned()).expect("команда принята");

    assert!(
        recorder.wait_for(|e| matches!(
            e,
            FfiEvent::StatusChanged { status: FfiDeliveryStatus::Undeliverable, .. }
        )),
        "UI обязан узнать, что сообщение не ушло, — и отличить это от «ждёт отправки»"
    );

    let history = client.messages(chat, 20).expect("история читается");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "в пустоту");
    assert!(history[0].mine, "своё сообщение помечается ядром, а не клиентом");
}

#[test]
fn lan_can_be_switched_on_and_off() {
    // §5.1: LAN выключен по умолчанию и включается сознательно. Проверяется
    // не поведение сети, а то, что команда доходит и не роняет ядро.
    let db = TempDb::new("lan");
    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");
    client.set_lan_enabled(true).expect("включение принято");
    client.set_lan_enabled(false).expect("выключение принято");
    assert!(!client.fingerprint().is_empty(), "ядро живо");
}

#[test]
fn a_network_change_is_survivable() {
    // На Android это происходит постоянно: Wi-Fi ↔ мобильный, переход между
    // точками, пробуждение. Ядро обязано пережить сообщение об этом в любом
    // состоянии — и при включённом LAN, и при выключенном.
    let db = TempDb::new("network");
    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");

    client.network_changed().expect("при выключенном LAN — тоже команда");
    client.set_lan_enabled(true).expect("включение принято");
    client.network_changed().expect("и при включённом");
    client.network_changed().expect("лишний вызов стоит одного переобъявления");

    assert!(!client.fingerprint().is_empty(), "ядро живо");
    assert!(client.contacts().is_ok(), "и отвечает на запросы");
}

#[test]
fn honest_texts_come_from_the_core() {
    // §14 существует, чтобы обещания продукта не расходились со свойствами
    // протокола. Строка, скопированная в Kotlin, разойдётся при первой правке.
    assert!(!ratatosk_ffi::honest_notices().is_empty());
    assert!(!ratatosk_ffi::lan_warning().is_empty());
    assert!(!ratatosk_ffi::no_pin_warning().is_empty());
}
