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
    // Тексты для правки и пересылки — из той же корзины: и то, и другое
    // обещает пользователю меньше, чем он думает, и сказать это обязан клиент.
    assert!(!ratatosk_ffi::edit_notice().is_empty());
    assert!(!ratatosk_ffi::forward_notice().is_empty());
    // И то, что показывают вместо цитаты, которой нет: придуманный текст
    // и пустая рамка — два способа соврать об одном.
    assert!(!ratatosk_ffi::quote_unavailable_notice().is_empty());
    // Пределы тоже приходят с этой стороны: число, записанное в Kotlin
    // отдельно, однажды разойдётся с ядром — и человек получит отказ уже
    // после нажатия.
    assert!(ratatosk_ffi::max_edit_age_ms() > 0);
    assert!(ratatosk_ffi::max_reaction_bytes() > 0);
    assert!(ratatosk_ffi::max_forward_ids() > 0);
}

#[test]
fn an_edit_and_a_reaction_are_visible_through_the_boundary() {
    // Что должен увидеть UI: новый текст, отметку «изменено» и свою реакцию.
    // Собеседника здесь нет (см. заголовок файла), поэтому проверяется своя
    // половина — та, которую человек видит сразу после нажатия.
    let db = TempDb::new("edit");
    let uri = someone_elses_uri("peer-edit");

    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");
    let recorder = Arc::new(Recorder::default());
    client.set_observer(recorder.clone());

    client.add_contact(uri, true).expect("URI принят");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::ContactAdded { .. })));

    let chat = client.contacts().expect("список читается")[0].chat_id.clone();
    client.send_text(chat.clone(), "прив".to_owned()).expect("команда принята");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::StatusChanged { .. })));

    let msg_id = client.messages(chat.clone(), 20).expect("история читается")[0].msg_id.clone();

    // Пустая правка — это удаление, и отказ приходит сразу, а не теряется
    // в очереди команд.
    assert!(client.edit_message(chat.clone(), msg_id.clone(), "  ".to_owned()).is_err());

    client
        .edit_message(chat.clone(), msg_id.clone(), "привет".to_owned())
        .expect("правка своего сообщения принята");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::MessageEdited { .. })));

    let history = client.messages(chat.clone(), 20).expect("история читается");
    assert_eq!(history[0].body, "привет");
    assert!(
        history[0].edited_at_ms.is_some(),
        "отметку «изменено» UI обязан показать: прежнего текста нет ни у кого"
    );
    assert!(!history[0].forwarded, "своё сообщение не переслано");

    // Реакция не должна быть способом прислать текст — отказ тоже сразу.
    assert!(client
        .set_reaction(chat.clone(), msg_id.clone(), Some("это целое сообщение".to_owned()))
        .is_err());

    client
        .set_reaction(chat.clone(), msg_id.clone(), Some("\u{1F44D}".to_owned()))
        .expect("реакция принята");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::ReactionChanged { .. })));

    let history = client.messages(chat.clone(), 20).expect("история читается");
    assert_eq!(history[0].reactions.len(), 1, "реакция читается вместе с сообщением");
    assert!(history[0].reactions[0].mine, "своя — считает ядро, а не клиент");

    // Снятие — такое же состояние, как и любое другое.
    client.set_reaction(chat.clone(), msg_id, None).expect("снятие принято");
    let cleared = (0..200).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(25));
        client.messages(chat.clone(), 20).map(|h| h[0].reactions.is_empty()).unwrap_or(false)
    });
    assert!(cleared, "снятая реакция не показывается");
}

#[test]
fn a_reply_can_be_found_and_the_history_pages_backwards() {
    // Ровно то, ради чего ответы и делались: цитата берётся по ссылке, а к
    // самому сообщению можно пролистать. Собеседника здесь нет (см. заголовок
    // файла) — проверяется своя половина, та, что видит человек сразу.
    let db = TempDb::new("reply");
    let uri = someone_elses_uri("peer-reply");

    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся");
    let recorder = Arc::new(Recorder::default());
    client.set_observer(recorder.clone());

    client.add_contact(uri, true).expect("URI принят");
    assert!(recorder.wait_for(|e| matches!(e, FfiEvent::ContactAdded { .. })));
    let chat = client.contacts().expect("список читается")[0].chat_id.clone();

    for text in ["раз", "два", "три"] {
        client.send_text(chat.clone(), text.to_owned()).expect("команда принята");
    }
    let history = (0..200)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(25));
            client.messages(chat.clone(), 20).ok().filter(|h| h.len() == 3)
        })
        .expect("три сообщения легли в историю");
    let first = history[0].msg_id.clone();

    // Ответ на первое сообщение.
    client.reply(chat.clone(), first.clone(), "это про «раз»".to_owned()).expect("ответ принят");
    let with_reply = (0..200)
        .find_map(|_| {
            std::thread::sleep(std::time::Duration::from_millis(25));
            client.messages(chat.clone(), 20).ok().filter(|h| h.len() == 4)
        })
        .expect("ответ лёг в историю");
    let answer = with_reply.last().expect("последний — ответ");
    assert_eq!(answer.reply_to, Some(first.clone()), "ссылка обязана быть видна клиенту");

    // Цитата берётся по ссылке — вот этим вызовом, если её нет в окне.
    let quoted = client
        .message(first.clone())
        .expect("чтение по идентификатору")
        .expect("цитируемое сообщение на месте");
    assert_eq!(quoted.body, "раз");

    // Пустой текст — отказ сразу, пока у человека открыто поле ввода.
    // Про «такого сообщения нет» граница ответить не может: команды уходят
    // без результата, и проверяет это ядро (см. `--test pair`).
    assert!(client.reply(chat.clone(), first.clone(), "  ".to_owned()).is_err());

    // Листание назад: окно перед первым сообщением пусто — это начало
    // переписки, а не ошибка.
    let before_first = client.messages_before(chat.clone(), first, 10).expect("листание работает");
    assert!(before_first.is_empty(), "перед первым сообщением ничего нет");

    // А перед последним — всё, что было до него, в том же порядке.
    let last = with_reply.last().unwrap().msg_id.clone();
    let earlier = client.messages_before(chat, last, 10).expect("листание работает");
    assert_eq!(
        earlier.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(),
        vec!["раз", "два", "три"]
    );
}

#[test]
fn an_avatar_round_trips_and_stays_hidden_until_verification() {
    // Граница целиком: поставить, прочитать, пережить перезапуск и не
    // показаться у несверенного. Двух узлов здесь нет (см. заголовок файла),
    // поэтому проверяется своя половина правила §4.2 — та, что про показ.
    let db = TempDb::new("avatar");
    let uri = someone_elses_uri("peer-avatar");
    let png = {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&[42u8; 128]);
        bytes
    };

    let peer_ik = {
        let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
            .expect("клиент открылся");

        assert_eq!(client.my_avatar().expect("читается"), None, "у свежего профиля её нет");
        client.set_avatar(Some(png.clone())).expect("аватарка принята");
        // Чтение **сразу** после записи, намеренно и без пауз: клиент так
        // и напишет, а раньше это работало через раз. Команды и запросы шли
        // разными каналами, и `select!` мог обслужить чтение до записи —
        // пользователь ставил аватарку и видел прежнюю.
        assert_eq!(client.my_avatar().expect("читается"), Some(png.clone()));

        // Не картинка и слишком большая — отказ, а не молчание: клиент обязан
        // узнать об этом до того, как покажет пользователю «готово».
        assert!(client.set_avatar(Some(b"<svg/>".to_vec())).is_err());
        let too_big = vec![0x89; ratatosk_ffi::max_avatar_bytes() as usize + 1];
        assert!(client.set_avatar(Some(too_big)).is_err());
        assert_eq!(client.my_avatar().expect("читается"), Some(png.clone()), "прежняя цела");

        // Контакт добавлен ссылкой, то есть несверенным (§4.2).
        client.add_contact(uri, false).expect("URI принят");
        let contact = client.contacts().expect("список читается").remove(0);
        assert!(!contact.verified);
        assert!(!contact.has_avatar, "у несверенного показывать нечего");
        assert_eq!(client.avatar_of(contact.peer_ik.clone()).expect("читается"), None);

        let peer_ik = contact.peer_ik;
        drop(client);
        settle();
        peer_ik
    };

    // Перезапуск: своя аватарка на месте, чужой по-прежнему нет.
    let client = RatatoskClient::open(db.path(), Some("1234".to_owned()), "я".to_owned())
        .expect("клиент открылся снова");
    assert_eq!(client.my_avatar().expect("читается"), Some(png));
    assert_eq!(client.avatar_of(peer_ik.clone()).expect("читается"), None);

    // Снять — тоже действие, и оно тоже переживает перезапуск.
    client.set_avatar(None).expect("снятие принято");
    assert_eq!(client.my_avatar().expect("читается"), None);
}
