//! Телефон и десктоп — обе стороны настоящие (§13.4).
//!
//! Отличие от `companion.rs` в том, кто на другом конце. Там десктоп собран
//! руками из `Initiator::start` и кадра §7.1 — нарочно, чтобы проверить ядро
//! **снаружи**, чужим кодом. Здесь на обоих концах наш код:
//! [`Engine`] и [`CompanionClient`], — и проверяется другое: что эти двое
//! договариваются между собой, а не каждый со своим представлением о проводе.
//!
//! Обе проверки нужны, и ни одна не заменяет другую. Согласованный с самим
//! собой код может быть согласованно неправ; независимая сторона это ловит.
//! Но независимая сторона не ловит того, что настоящий терминал делает сам —
//! спрашивает список чатов при подключении, отбрасывает ответ на просьбу,
//! которой не было, выбрасывает сессию вместе с каналом.

use std::sync::{Arc, Mutex};

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{
    ClientEffect, ClientEvent, ClientInput, Command, CompanionClient, Effect, Engine, Event, Input,
    OutgoingFile, OutgoingItem, SeededEntropy,
};
use ratatosk_crypto::Identity;
use ratatosk_proto::companion::{PairingInvite, Request};
use ratatosk_proto::{files, Transport};
use ratatosk_store::{MemoryBlobs, MemoryStore, Store};

type Phone = Engine<MemoryStore>;
type Blobs = Arc<Mutex<MemoryBlobs>>;

fn phone(seed: u8, name: &str) -> Phone {
    phone_with_blobs(seed, name).0
}

fn phone_with_blobs(seed: u8, name: &str) -> (Phone, Blobs) {
    let identity = Identity::from_seed([seed; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция in-memory хранилища");
    let blobs = Arc::new(Mutex::new(MemoryBlobs::new()));
    let handle = Arc::clone(&blobs);
    let mut engine = Engine::new(
        identity,
        store,
        Box::new(blobs),
        Box::new(SeededEntropy::new(u64::from(seed))),
        SelfAddresses {
            onion: format!("{name}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"),
            chatmail: format!("{name}@nine.example"),
            display_name: name.to_owned(),
        },
    );
    engine
        .step(
            0,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Lan,
                enabled: true,
            }),
        )
        .expect("включение локальной сети");
    engine
        .step(0, Input::TransportReady { transport: Transport::Lan })
        .expect("готовность локальной сети");
    (engine, handle)
}

/// Заводит контакт, чтобы терминалу было что показывать.
fn with_contact(phone: &mut Phone, now_ms: u64, name: &str, seed: u8) -> [u8; 32] {
    let other = Identity::from_seed([seed; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: other.public().ik,
        sk: other.public().sk,
        onion: String::new(),
        chatmail: format!("{name}@nine.example"),
        display_name: name.to_owned(),
        version: 1,
    };
    phone
        .step(
            now_ms,
            Input::Command(Command::AddContact {
                card_bytes: card.encode().expect("карточка"),
                met_in_person: true,
            }),
        )
        .expect("добавление контакта");
    card.ik
}

/// Провод: всё, что одна сторона отправила, отдаётся другой, пока не затихнет.
///
/// Возвращает то, что терминал показал бы человеку. Кадры телефона **чужим
/// адресатам** сюда не попадают: отправка текста заводит доставку по §5.4,
/// и её кадры к терминалу отношения не имеют.
fn pump(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    from_desktop: Vec<ClientEffect>,
) -> Vec<ClientEvent> {
    let mut shown = Vec::new();
    let mut to_phone: Vec<Vec<u8>> = Vec::new();
    let desktop_ik = desktop.ik();

    let collect =
        |effects: Vec<ClientEffect>, to_phone: &mut Vec<Vec<u8>>, shown: &mut Vec<ClientEvent>| {
            for effect in effects {
                match effect {
                    ClientEffect::Send(frame) => to_phone.push(frame),
                    ClientEffect::Show(event) => shown.push(event),
                }
            }
        };
    collect(from_desktop, &mut to_phone, &mut shown);

    // Предел от кольца, а не от объёма: честный обмен здесь — единицы кадров.
    for _ in 0..64 {
        let Some(frame) = to_phone.first().cloned() else { break };
        to_phone.remove(0);

        let effects =
            phone.step(now_ms, Input::Received { via: Transport::Lan, frame }).expect("шаг ядра");
        for effect in effects {
            let Effect::Send { peer_ik, frame, .. } = effect else { continue };
            if peer_ik != desktop_ik {
                continue;
            }
            let answered = desktop.step(now_ms, ClientInput::Received(frame));
            collect(answered, &mut to_phone, &mut shown);
        }
    }
    assert!(to_phone.is_empty(), "обмен не сошёлся — вероятно, кольцо кадров");
    shown
}

/// Отказ, как его видит человек, — любым из трёх событий.
///
/// Их три, потому что слой выше по ним делает разное: `SendStopped`
/// отпускает пути к файлам, `FetchStopped` убирает обрывок с диска,
/// `Refused` не трогает ничего. Для человека все три — «просьба
/// не выполнена, и вот почему», и тест, проверяющий «сказано словами»,
/// обязан видеть каждый из них.
///
/// Заведено после того, как разделение событий уронило пять тестов разом:
/// они искали `Refused` там, где теперь приезжает `SendStopped`.
fn refusal(event: &ClientEvent) -> Option<&str> {
    match event {
        ClientEvent::Refused(why)
        | ClientEvent::SendStopped { why }
        | ClientEvent::FetchStopped { why } => Some(why),
        _ => None,
    }
}

/// Отдаёт терминалу то, что телефон произвёл своим шагом.
///
/// Кадры **чужим адресатам** отсекаются: собственная доставка §5.4 к терминалу
/// отношения не имеет, а подсунутая ему падает на расшифровке — то есть
/// не там, где ошибка.
fn relay(desktop: &mut CompanionClient, now_ms: u64, from_phone: Vec<Effect>) -> Vec<ClientEvent> {
    let desktop_ik = desktop.ik();
    let mut shown = Vec::new();
    for effect in from_phone {
        let Effect::Send { peer_ik, frame, .. } = effect else { continue };
        if peer_ik != desktop_ik {
            continue;
        }
        for out in desktop.step(now_ms, ClientInput::Received(frame)) {
            if let ClientEffect::Show(event) = out {
                shown.push(event);
            }
        }
    }
    shown
}

/// Заводит сопряжение и отдаёт приглашение.
fn invited(phone: &mut Phone, now_ms: u64) -> PairingInvite {
    let effects = phone
        .step(now_ms, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");
    let uri = effects
        .into_iter()
        .find_map(|effect| match effect {
            Effect::Notify(Event::PairingReady { uri, .. }) => Some(uri),
            _ => None,
        })
        .expect("ссылка приходит событием");
    PairingInvite::from_uri(&uri).expect("разбор ссылки")
}

/// Сопрягает и доводит обе стороны до живой сессии.
fn linked(now_ms: u64) -> (Phone, CompanionClient, Vec<ClientEvent>) {
    let (phone, desktop, shown, _) = linked_with_invite(now_ms);
    (phone, desktop, shown)
}

/// То же, но отдаёт и приглашение: второй терминал из того же зерна нужен
/// там, где проверяется снимок кэша.
fn linked_with_invite(now_ms: u64) -> (Phone, CompanionClient, Vec<ClientEvent>, PairingInvite) {
    let mut phone = phone(1, "телефон");
    let invite = invited(&mut phone, now_ms);
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));

    let first = desktop.step(now_ms, ClientInput::Reach);
    let shown = pump(&mut phone, &mut desktop, now_ms, first);
    (phone, desktop, shown, invite)
}

#[test]
fn the_terminal_links_up_and_asks_for_the_chat_list_itself() {
    // Терминал спрашивает чаты сам, не дожидаясь окна. Иначе первое, что
    // видит человек после подключения, — пустота, которую пришлось бы
    // разгонять таймером в UI.
    let mut phone = phone(1, "телефон");
    let invite = invited(&mut phone, 1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);

    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));
    assert_eq!(desktop.phone_name(), "телефон", "имя из приглашения — заголовок окна");

    let first = desktop.step(1_100, ClientInput::Reach);
    let shown = pump(&mut phone, &mut desktop, 1_100, first);

    assert!(desktop.linked(), "после ответа рукопожатия связь есть");
    assert!(shown.contains(&ClientEvent::Linked));
    let chats = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Chats { chats, .. } => Some(chats),
            _ => None,
        })
        .expect("список чатов приходит сам, без просьбы окна");
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0].title, "сосед");
}

#[test]
fn the_phone_calls_the_terminal_its_own_device() {
    let (phone, desktop, _) = linked(1_000);
    let devices = phone.paired_devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        devices[0].device_id,
        desktop.device_id(),
        "идентификатор выводится, а не назначается"
    );
    assert!(phone.device_connected(&devices[0].device_id));
}

#[test]
fn a_second_reach_does_not_start_a_second_handshake() {
    // Маяк в локальной сети повторяется (§5.1). Каждый повтор, заводящий
    // новое рукопожатие, означал бы новую сессию на каждое объявление —
    // и вытеснение предыдущей у телефона.
    let (mut phone, mut desktop, _) = linked(1_000);
    let again = desktop.step(1_100, ClientInput::Reach);
    assert!(again.is_empty(), "связь жива — здороваться не с кем");

    let shown = pump(&mut phone, &mut desktop, 1_100, again);
    assert!(shown.is_empty());
    assert_eq!(phone.session_count(), 1, "сессия одна");
}

#[test]
fn text_typed_on_the_desktop_is_sent_by_the_phone() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let asked = desktop
        .step(1_200, ClientInput::Ask(Request::SendText { chat, text: "с ноутбука".into() }));
    let shown = pump(&mut phone, &mut desktop, 1_200, asked);

    assert!(shown.contains(&ClientEvent::Done), "телефон отвечает «сделано»");
    // И тем же обменом — новостью о самом сообщении: перечитывать историю
    // после каждой отправки терминал не обязан.
    let arrived = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => Some(message),
            _ => None,
        })
        .expect("о своём сообщении терминал узнаёт новостью");
    assert_eq!(arrived.text, "с ноутбука");
    assert!(arrived.mine);

    let page = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(page.len(), 1, "отправляет телефон, из своей истории");
}

#[test]
fn a_message_received_by_the_phone_reaches_the_desktop() {
    // Ради этого режим и нужен: человек смотрит в десктоп, а разговор идёт
    // через телефон. Сообщение сюда приезжает новостью, без всякой просьбы.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // Телефон кладёт принятое в историю тем же путём, каким это делает приём
    // из сети: `remember` — единственная воронка, и новость рождается в ней.
    let effects = phone
        .step(1_200, Input::Command(Command::SendText { chat, text: "ответ".into() }))
        .expect("отправка");
    let shown = relay(&mut desktop, 1_200, effects);

    let arrived = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => Some(message),
            _ => None,
        })
        .expect("новость о сообщении обязана доехать");
    assert_eq!(arrived.text, "ответ");
}

#[test]
fn an_ask_without_a_link_is_refused_out_loud() {
    // §14: обещать нечего. «Отправлено» у сообщения, которое некому передать,
    // было бы ложью, а молчание человек прочтёт как поломку окна.
    let invite = PairingInvite {
        ik: Identity::from_seed([1u8; 32]).public().ik,
        secret: ratatosk_proto::companion::PairingSecret::new([5u8; 32]),
        onion: String::new(),
        display_name: "телефон".into(),
    };
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));
    assert!(!desktop.linked());

    let effects = desktop.step(1_000, ClientInput::Ask(Request::Chats));
    assert!(matches!(effects.as_slice(), [ClientEffect::Show(ClientEvent::NotLinked)]));
}

#[test]
fn a_lost_channel_drops_the_session_and_says_so() {
    // Сессия у терминала одноразовая, и это осознанно иначе, чем у телефона
    // с контактом: там перерукопожатие может стоить суток почтового круга,
    // здесь — одного круга по локальной сети.
    let (mut phone, mut desktop, _) = linked(1_000);
    let lost = desktop.step(1_100, ClientInput::Lost);
    assert!(matches!(lost.as_slice(), [ClientEffect::Show(ClientEvent::Unlinked)]));
    assert!(!desktop.linked());

    // И связь поднимается заново, без участия человека.
    let again = desktop.step(1_200, ClientInput::Reach);
    let shown = pump(&mut phone, &mut desktop, 1_200, again);
    assert!(desktop.linked(), "второе рукопожатие сходится");
    assert!(shown.contains(&ClientEvent::Linked));
}

#[test]
fn a_revoked_terminal_stops_being_answered() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let device_id = phone.paired_devices()[0].device_id;

    phone
        .step(1_100, Input::Command(Command::RevokePairing { device_id }))
        .expect("отзыв сопряжения");

    let asked = desktop.step(1_200, ClientInput::Ask(Request::Chats));
    let shown = pump(&mut phone, &mut desktop, 1_200, asked);
    assert!(shown.is_empty(), "отозванному не отвечают, и придумывать ответ за телефон нельзя");
}

#[test]
fn an_answer_that_outlived_the_link_is_not_shown() {
    // Ответ, переживший разрыв, показывать нельзя: список чатов из прошлой
    // жизни затёр бы нынешний. Здесь его отсекает отсутствие сессии; внутри
    // терминала стоит и вторая проверка — набор неотвеченных номеров, —
    // и она ловит тот же случай, когда сессия успела встать заново.
    let (mut phone, mut desktop, _) = linked(1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);

    let asked = desktop.step(1_200, ClientInput::Ask(Request::Chats));
    let mut frames = Vec::new();
    for effect in asked {
        if let ClientEffect::Send(frame) = effect {
            frames.push(frame);
        }
    }
    let mut answers = Vec::new();
    for frame in frames {
        let effects =
            phone.step(1_200, Input::Received { via: Transport::Lan, frame }).expect("шаг");
        for effect in effects {
            if let Effect::Send { peer_ik, frame, .. } = effect {
                if peer_ik == desktop.ik() {
                    answers.push(frame);
                }
            }
        }
    }
    assert!(!answers.is_empty(), "ответ у телефона нашёлся");

    // Разрыв — и тот же ответ приезжает в пустоту.
    let _ = desktop.step(1_250, ClientInput::Lost);
    for frame in answers {
        let shown = desktop.step(1_300, ClientInput::Received(frame));
        assert!(
            matches!(shown.as_slice(), [ClientEffect::Show(ClientEvent::Ignored(_))] | []),
            "ответ без просьбы показывать нельзя"
        );
    }
}

/// Отправляет текст с телефона и возвращает его идентификатор.
fn say(phone: &mut Phone, now_ms: u64, chat: [u8; 16], text: &str) -> ([u8; 16], Vec<Effect>) {
    let effects = phone
        .step(now_ms, Input::Command(Command::SendText { chat, text: text.to_owned() }))
        .expect("отправка");
    let msg_id = phone
        .store()
        .messages(&chat, 1, None)
        .expect("история")
        .last()
        .expect("сообщение легло в историю")
        .msg_id;
    (msg_id, effects)
}

#[test]
fn a_message_deleted_on_the_phone_is_taken_off_the_desktop() {
    // Худший из отказов по §14: человек стёр сообщение, увидел, что оно
    // исчезло, — а на втором экране оно осталось лежать. До этой новости
    // оно так и лежало бы, пока десктоп не перечитает историю руками.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "лишнее");
    let _ = relay(&mut desktop, 1_100, effects);

    let effects = phone
        .step(1_200, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![msg_id] }))
        .expect("удаление");
    let shown = relay(&mut desktop, 1_200, effects);

    let told = shown.iter().any(
        |event| matches!(event, ClientEvent::Gone { msg_ids, .. } if msg_ids.contains(&msg_id)),
    );
    assert!(told, "об исчезновении сообщения десктоп обязан узнать");
}

#[test]
fn clearing_a_chat_takes_everything_off_the_desktop() {
    // Очистка чата — то же исчезновение, только списком. Проверяется отдельно
    // потому, что путь другой: не `forget_messages`, а `tombstone_chat`,
    // и собрать идентификаторы там надо **до** уборки.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (first, effects) = say(&mut phone, 1_100, chat, "раз");
    let _ = relay(&mut desktop, 1_100, effects);
    let (second, effects) = say(&mut phone, 1_150, chat, "два");
    let _ = relay(&mut desktop, 1_150, effects);

    let effects = phone.step(1_200, Input::Command(Command::ClearChat { chat })).expect("очистка");
    let shown = relay(&mut desktop, 1_200, effects);

    let gone: Vec<[u8; 16]> = shown
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Gone { msg_ids, .. } => Some(msg_ids.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(gone.contains(&first) && gone.contains(&second), "исчезло всё, и сказано про всё");
}

#[test]
fn an_edit_reaches_the_desktop_with_the_new_text() {
    // Текст едет целиком, а не одним идентификатором: у телефона за событием
    // стоит его база, у десктопа — нет, и голый идентификатор стоил бы ему
    // круга по сети за то, что телефон и так держал в руках.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "апечатка");
    let _ = relay(&mut desktop, 1_100, effects);

    let effects = phone
        .step(1_200, Input::Command(Command::EditMessage { chat, msg_id, text: "опечатка".into() }))
        .expect("правка");
    let shown = relay(&mut desktop, 1_200, effects);

    let edited = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Edited(message) => Some(message),
            _ => None,
        })
        .expect("о правке десктоп обязан узнать");
    assert_eq!(edited.msg_id, msg_id);
    assert_eq!(edited.text, "опечатка", "и узнать её текстом, а не поводом сходить ещё раз");
}

/// Просит телефон и возвращает то, что терминал показал бы человеку.
fn desktop_asks(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    request: Request,
) -> Vec<ClientEvent> {
    let asked = desktop.step(now_ms, ClientInput::Ask(request));
    pump(phone, desktop, now_ms, asked)
}

/// Последнее сообщение чата в истории телефона.
fn last_in(phone: &Phone, chat: [u8; 16]) -> [u8; 16] {
    phone.store().messages(&chat, 1, None).expect("история").last().expect("сообщение").msg_id
}

/// Сопрягает терминал с телефоном, у которого есть свой «диск».
fn linked_with_blobs(now_ms: u64) -> (Phone, Blobs, CompanionClient) {
    let (mut phone, blobs) = phone_with_blobs(1, "телефон");
    let invite = invited(&mut phone, now_ms);
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));
    let first = desktop.step(now_ms, ClientInput::Reach);
    let _ = pump(&mut phone, &mut desktop, now_ms, first);
    (phone, blobs, desktop)
}

#[test]
fn a_message_with_an_attachment_reaches_the_desktop_with_it_named() {
    // Ловушка, ради которой новость о сообщении собирается не сразу:
    // внешний ключ `files.msg_id → messages.msg_id` требует класть текст
    // раньше вложений, и новость, собранная в `remember`, уехала бы
    // **без файлов**. Человек видел бы «вот отчёт» без отчёта до тех пор,
    // пока не перечитает историю руками.
    let (mut phone, blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = files::CHUNK_BYTES as u64 * 2 + 5;
    blobs.lock().unwrap().seed_sparse("/tmp/otchet.pdf", size);
    let effects = phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![OutgoingFile { path: "/tmp/otchet.pdf".into(), preview: None }],
                text: "вот отчёт".into(),
            }),
        )
        .expect("отправка файла");
    let shown = relay(&mut desktop, 1_100, effects);

    let arrived = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => Some(message),
            _ => None,
        })
        .expect("сообщение доехало новостью");
    assert_eq!(arrived.files.len(), 1, "вложение обязано приехать вместе с сообщением");
    assert_eq!(arrived.files[0].name, "otchet.pdf");
    assert_eq!(arrived.files[0].size_bytes, size);
    assert_eq!(arrived.files[0].chunk_total, 3);
    assert_eq!(arrived.files[0].have_chunks, 3, "своё вложение лежит целиком");
}

#[test]
fn the_desktop_takes_an_attachment_chunk_by_chunk_and_gets_all_of_it() {
    // Ради этого весь путь и заведён. Проверяется не «что-то приехало»,
    // а длина и содержимое: кусок, легший не на своё место, собрал бы файл,
    // который выглядит целым и не является им.
    let (mut phone, blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = files::CHUNK_BYTES as u64 * 2 + 5;
    blobs.lock().unwrap().seed_sparse("/tmp/otchet.pdf", size);
    let effects = phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![OutgoingFile { path: "/tmp/otchet.pdf".into(), preview: None }],
                text: "вот отчёт".into(),
            }),
        )
        .expect("отправка файла");
    let shown = relay(&mut desktop, 1_100, effects);
    let attachment = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => message.files.first(),
            _ => None,
        })
        .expect("вложение названо")
        .clone();

    let started = desktop.step(
        1_200,
        ClientInput::Fetch { file_id: attachment.file_id, chunk_total: attachment.chunk_total },
    );
    let shown = pump(&mut phone, &mut desktop, 1_200, started);

    let mut whole = vec![0u8; size as usize];
    let mut seen = Vec::new();
    for event in &shown {
        if let ClientEvent::FileBytes { index, bytes, .. } = event {
            let at = *index as usize * files::CHUNK_BYTES;
            whole[at..at + bytes.len()].copy_from_slice(bytes);
            seen.push(*index);
        }
    }
    assert_eq!(seen, vec![0, 1, 2], "куски приходят по порядку и все");
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::FileDone { .. })),
        "конец выгрузки обязан быть назван: без него окно не знает, что файл готов"
    );
    assert_eq!(whole.len() as u64, size);
    assert!(whole.iter().all(|byte| *byte == 0), "исходник был из нулей — таким и обязан приехать");
}

#[test]
fn a_second_fetch_while_one_is_running_is_refused_in_words() {
    // Одно вложение за раз: кусок — целый кадр класса L, и две выгрузки
    // разом заняли бы и канал, и цикл телефона вдвое, не ускорив ничего.
    let (mut phone, blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = files::CHUNK_BYTES as u64 * 3;
    blobs.lock().unwrap().seed_sparse("/tmp/video.mp4", size);
    phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![OutgoingFile { path: "/tmp/video.mp4".into(), preview: None }],
                text: "видео".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file_id = phone.store().files_of(&msg_id).expect("вложения")[0].file_id;

    // Первая просьба уходит и **не** прокачивается: выгрузка остаётся идущей.
    let started = desktop.step(1_200, ClientInput::Fetch { file_id, chunk_total: 3 });
    assert!(started.iter().any(|effect| matches!(effect, ClientEffect::Send(_))));

    let second = desktop.step(1_300, ClientInput::Fetch { file_id, chunk_total: 3 });
    let refused =
        second.iter().any(|effect| matches!(effect, ClientEffect::Show(ClientEvent::Refused(_))));
    assert!(refused, "вторая выгрузка обязана быть отвергнута словами");
    assert!(
        !second.iter().any(|effect| matches!(effect, ClientEffect::Send(_))),
        "и не должна уехать просьбой"
    );
}

#[test]
fn a_download_that_lost_the_link_waits_instead_of_hanging_or_dying() {
    // Молчать здесь нельзя: «качается» навсегда, потому что следующего
    // куска не будет, пока связь не вернётся.
    //
    // **И убивать нельзя тоже.** Здесь стояло обратное правило — приём
    // умирал вместе с каналом, а обрывок стирался, — и оно решало верную
    // задачу неверной ценой: недокачанный файл под настоящим именем и правда
    // неотличим от докачанного, но платил за это человек мебибайтами заново
    // из-за секундной потери сети. Теперь имя говорит само (`.part`),
    // а приём ждёт и продолжается с того же куска.
    let (mut phone, blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = files::CHUNK_BYTES as u64 * 3;
    blobs.lock().unwrap().seed_sparse("/tmp/video.mp4", size);
    phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![OutgoingFile { path: "/tmp/video.mp4".into(), preview: None }],
                text: "видео".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file_id = phone.store().files_of(&msg_id).expect("вложения")[0].file_id;

    // Один круг руками, а не `pump`: тот довёл бы приём до конца, а нужен
    // разрыв **посреди**. Просьба о следующем куске при этом никуда
    // не уезжает — её эффект здесь просто не подхватывается, и выглядит это
    // для терминала ровно как потерянный кадр.
    let started = desktop.step(1_200, ClientInput::Fetch { file_id, chunk_total: 3 });
    let mut shown = Vec::new();
    for effect in started {
        let ClientEffect::Send(frame) = effect else { continue };
        let effects =
            phone.step(1_250, Input::Received { via: Transport::Lan, frame }).expect("шаг ядра");
        shown.extend(relay(&mut desktop, 1_250, effects));
    }
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::FileBytes { index: 0, .. })),
        "нулевой кусок обязан доехать до разрыва: {shown:?}"
    );

    let lost = desktop.step(1_300, ClientInput::Lost);
    assert!(
        lost.iter().any(|effect| matches!(effect, ClientEffect::Show(ClientEvent::FetchPaused))),
        "разрыв посреди приёма — «ждёт», а не «не вышло»"
    );

    // Место при этом **занято**, и это обратное прежнему правилу: приём
    // не закрыт, он ждёт. Освобождает его отмена человеком, а не разрыв.
    let again = desktop.step(1_400, ClientInput::Fetch { file_id, chunk_total: 3 });
    assert!(
        again.iter().any(|effect| matches!(
            effect,
            ClientEffect::Show(ClientEvent::Refused(why)) if why.contains("одно вложение")
        )),
        "второй приём поверх ждущего означал бы двух писателей в один файл"
    );

    // А связь вернулась — и приём продолжается с того куска, на котором встал.
    let back = desktop.step(1_500, ClientInput::Reach);
    let shown = pump(&mut phone, &mut desktop, 1_500, back);
    let resumed = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::FetchResumed { done, total } => Some((*done, *total)),
            _ => None,
        })
        .expect("продолжение обязано быть названо: до него на экране было «ждёт связи»");
    assert_eq!(resumed, (1, 3), "нулевой кусок уже на диске — просить надо первый");
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::FileBytes { index: 1, .. })),
        "и он приезжает, а не начинается всё заново"
    );
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::FileDone { .. })),
        "приём доходит до конца"
    );
}

/// Кладёт телефону входящее вложение, которого он ещё не принял.
///
/// Прямо в хранилище, а не через второй `Engine`: проверяется здесь дорога
/// от десктопа до решения, а не приём файла — он покрыт в `pair.rs`.
fn awaiting_decision(phone: &mut Phone, msg_id: [u8; 16], chunk_total: u64) -> [u8; 16] {
    awaiting_decision_with_preview(phone, msg_id, chunk_total, None)
}

/// То же, но с превью (§10.3) — или нарочно без него.
///
/// Отдельным входом, а не полем у всех вызовов: превью касается ровно двух
/// проверок, а остальным восьми оно шум.
fn awaiting_decision_with_preview(
    phone: &mut Phone,
    msg_id: [u8; 16],
    chunk_total: u64,
    preview: Option<Vec<u8>>,
) -> [u8; 16] {
    let file_id = [77u8; 16];
    phone
        .store_mut()
        .put_file(&ratatosk_store::StoredFile {
            file_id,
            msg_id,
            name: "видео.mp4".into(),
            size_bytes: files::CHUNK_BYTES as u64 * chunk_total,
            chunk_total,
            key: [3u8; 32],
            preview,
            ordinal: 0,
            incoming: true,
            source_path: None,
            // Порог автоприёма выключен — значит «спрашивать всегда» (§10.2),
            // и решение за человеком.
            accepted: false,
            complete: false,
        })
        .expect("вложение легло");
    file_id
}

#[test]
fn the_terminal_asks_which_wire_the_phone_speaks_before_anything_else() {
    // Порядок несущий: телефон постарше на `Hello` не ответит вовсе,
    // и узнать об этом можно только по тому, что ответ на следующую просьбу
    // пришёл раньше. Спроси мы чаты первыми — ловить было бы нечем.
    let (_, _, shown) = linked(1_000);
    let told = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Wire { theirs, ours } => Some((*theirs, *ours)),
            _ => None,
        })
        .expect("версию провода терминал спрашивает сам, при подключении");
    assert_eq!(
        told,
        (Some(ratatosk_proto::companion::WIRE_VERSION), ratatosk_proto::companion::WIRE_VERSION)
    );
}

#[test]
fn a_phone_that_does_not_know_hello_is_named_by_its_silence() {
    // Разбор живого расхождения: десктоп, поговорив с телефоном сборки
    // постарше, показывал сообщения без вложений и без реакций — и это
    // выглядело как поломка. Кодек прощающий, и это правильно; но молчаливая
    // деградация обязана быть **названа** (§14).
    let mut phone = phone(1, "телефон");
    let invite = invited(&mut phone, 1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));

    let first = desktop.step(1_100, ClientInput::Reach);
    // Телефон постарше отбрасывает непонятую просьбу молча
    // (`on_device_frame`), поэтому кадр с `Hello` просто не доходит.
    let mut shown = Vec::new();
    let mut to_phone: Vec<Vec<u8>> = Vec::new();
    let desktop_ik = desktop.ik();
    let mut hello_dropped = false;
    for effect in first {
        match effect {
            ClientEffect::Send(frame) => to_phone.push(frame),
            ClientEffect::Show(event) => shown.push(event),
        }
    }
    while let Some(frame) = (!to_phone.is_empty()).then(|| to_phone.remove(0)) {
        // Первый кадр после рукопожатия — `Hello`. Роняем его: ровно так
        // выглядит телефон, который этого вида просьбы не знает.
        if desktop.linked() && !hello_dropped {
            hello_dropped = true;
            continue;
        }
        let effects =
            phone.step(1_100, Input::Received { via: Transport::Lan, frame }).expect("шаг ядра");
        for effect in effects {
            let Effect::Send { peer_ik, frame, .. } = effect else { continue };
            if peer_ik != desktop_ik {
                continue;
            }
            for out in desktop.step(1_100, ClientInput::Received(frame)) {
                match out {
                    ClientEffect::Send(frame) => to_phone.push(frame),
                    ClientEffect::Show(event) => shown.push(event),
                }
            }
        }
    }

    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Wire { theirs: None, .. })),
        "молчание в ответ на `Hello` обязано быть названо, а не показано пустыми сообщениями"
    );
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Chats { .. })),
        "и при этом всё остальное обязано продолжать работать"
    );
}

#[test]
fn an_attachment_awaiting_a_decision_says_so_to_the_desktop() {
    // Ровно то, на чём споткнулся стенд: файл виден, забрать нечего,
    // и «телефон не принял» неотличимо от «телефон качает» — оба ноль из N.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот видео");
    awaiting_decision(&mut phone, msg_id, 4);

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::History { chat, limit: 10, before: None },
    );
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    let attachment = page[0].files.first().expect("вложение названо");
    assert!(!attachment.accepted, "решение ещё не принято, и это обязано быть видно");
    assert_eq!(attachment.have_chunks, 0);
}

#[test]
fn a_preview_is_named_in_the_page_and_fetched_separately() {
    // §10.3 на второй экран: в странице стоит признак, картинка едет отдельной
    // просьбой. Иначе сотня сообщений везла бы три мегабайта в одном кадре.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот кот");
    let picture = vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10];
    let file_id = awaiting_decision_with_preview(&mut phone, msg_id, 4, Some(picture.clone()));

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::History { chat, limit: 10, before: None },
    );
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    let attachment = page[0].files.first().expect("вложение названо");
    assert!(attachment.has_preview, "признак обязан доехать вместе со страницей");

    let shown = desktop_asks(&mut phone, &mut desktop, 1_300, Request::FilePreview { file_id });
    assert!(
        shown.contains(&ClientEvent::FilePreview { file_id, bytes: Some(picture) }),
        "а картинка — отдельной просьбой, и та самая: {shown:?}"
    );
}

#[test]
fn an_attachment_without_a_picture_says_so_and_answers_with_nothing() {
    // Две проверки в одной, потому что они про одну ошибку: показать
    // ожидание, которое никогда не кончится. Признак `false` — чтобы
    // не спрашивали; пустой ответ вместо отказа — чтобы спросивший
    // не получил строку, которую надо нести человеку (§14).
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот архив");
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::History { chat, limit: 10, before: None },
    );
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    assert!(!page[0].files[0].has_preview, "картинки нет — и спрашивать незачем");

    let shown = desktop_asks(&mut phone, &mut desktop, 1_300, Request::FilePreview { file_id });
    assert!(
        shown.contains(&ClientEvent::FilePreview { file_id, bytes: None }),
        "спросили всё равно — ответ пустой, но это ответ: {shown:?}"
    );
    assert!(
        !shown.iter().any(|event| matches!(event, ClientEvent::Refused(_))),
        "и не отказ: строка про каждую картинку без превью — шум, а не сообщение"
    );
}

#[test]
fn a_preview_asked_for_a_vanished_attachment_is_answered_empty() {
    // Вложение могли стереть, пока просьба ехала. Отказ здесь был бы
    // формально верен и практически вреден: человек увидел бы строку
    // об ошибке там, где просто нечего рисовать.
    let (mut phone, mut desktop, _) = linked(1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);
    let shown =
        desktop_asks(&mut phone, &mut desktop, 1_200, Request::FilePreview { file_id: [9u8; 16] });
    assert!(
        shown.contains(&ClientEvent::FilePreview { file_id: [9u8; 16], bytes: None }),
        "несуществующее вложение отвечается пустым превью: {shown:?}"
    );
}

#[test]
fn the_desktop_accepts_an_attachment_and_the_phone_starts_taking_it() {
    // Принять — это про телефон: начать качать у собеседника. Забрать
    // принятое себе — отдельная просьба, и порядок обязателен.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот видео");
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    let shown = desktop_asks(&mut phone, &mut desktop, 1_200, Request::AcceptFile { file_id });
    assert!(shown.contains(&ClientEvent::Done));
    assert!(
        phone.store().file(&file_id).expect("чтение").expect("вложение").accepted,
        "решение обязано лечь в базу телефона, а не остаться на десктопе"
    );
}

#[test]
fn declining_from_the_desktop_takes_the_attachment_off_the_phone() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот видео");
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    let shown = desktop_asks(&mut phone, &mut desktop, 1_200, Request::DeclineFile { file_id });
    assert!(shown.contains(&ClientEvent::Done));
    assert!(
        phone.store().file(&file_id).expect("чтение").is_none(),
        "отказ уносит и сведения о файле, и всё, что успело приехать"
    );
}

#[test]
fn the_phone_tells_the_desktop_how_the_receiving_goes() {
    // Без этой новости десктоп, попросивший принять, не узнаёт ничего:
    // `Attachment` приезжает страницей, а перечитывать её на всякий случай —
    // это опрос вместо новости. «Идёт приём» и «зависло» обязаны различаться.
    //
    // Раньше здесь стоял отказ — он был «самым коротким путём к событию
    // о ходе приёма», потому что честно говорил «ноль из нуля». Честно
    // это не было: отказ убирает вложение, а не двигает полоску, и нули
    // в ней десктоп читал как числа. Теперь у исчезновения своя новость,
    // а ход приёма проверяется тем, что его и двигает.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот видео");
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    let _ = desktop_asks(&mut phone, &mut desktop, 1_200, Request::AcceptFile { file_id });
    let shown = desktop_asks(&mut phone, &mut desktop, 1_300, Request::PauseFile { file_id });
    let told = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::FileProgress { file_id: id, have_chunks, chunk_total, accepted }
                if *id == file_id =>
            {
                Some((*have_chunks, *chunk_total, *accepted))
            }
            _ => None,
        })
        .expect("о движении приёма десктоп обязан узнать новостью");
    assert_eq!(told, (0, 4, false), "числа те же, что были, — а согласия больше нет");
}

/// Гонит выгрузку файла с десктопа целиком и отдаёт то, что показал терминал.
fn upload(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    chat: [u8; 16],
    bytes: &[u8],
) -> Vec<ClientEvent> {
    upload_with_preview(phone, desktop, now_ms, chat, bytes, None)
}

/// То же с превью (§10.3) — или нарочно без него.
fn upload_with_preview(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    chat: [u8; 16],
    bytes: &[u8],
    preview: Option<Vec<u8>>,
) -> Vec<ClientEvent> {
    upload_many(phone, desktop, now_ms, chat, &[("otchet.pdf", bytes, preview)], "вот отчёт")
}

/// Гонит выгрузку нескольких файлов одним сообщением.
///
/// Байты каждого файла свои: перепутанные местами куски здесь и есть та
/// ошибка, ради которой номер файла едет в `NeedChunk`.
fn upload_many(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    chat: [u8; 16],
    files: &[(&str, &[u8], Option<Vec<u8>>)],
    text: &str,
) -> Vec<ClientEvent> {
    let items = files
        .iter()
        .map(|(name, bytes, preview)| OutgoingItem {
            name: (*name).to_owned(),
            size_bytes: bytes.len() as u64,
            preview: preview.clone(),
        })
        .collect();
    let started = desktop.step(now_ms, ClientInput::Send { chat, items, text: text.to_owned() });
    let mut shown = pump(phone, desktop, now_ms, started);
    // Терминал просит куски по одному — отдаём, пока просит. Какого файла,
    // говорит он сам: угадывать по имени нельзя, имена вправе совпадать.
    loop {
        let Some((which, index)) = shown.iter().rev().find_map(|event| match event {
            ClientEvent::NeedChunk { which, index, .. } => Some((*which as usize, *index)),
            _ => None,
        }) else {
            break;
        };
        let bytes = files[which].1;
        let at = index as usize * files::CHUNK_BYTES;
        let end = (at + files::CHUNK_BYTES).min(bytes.len());
        let asked =
            desktop.step(now_ms, ClientInput::PutChunk { index, bytes: bytes[at..end].to_vec() });
        let more = pump(phone, desktop, now_ms, asked);
        let stop = !more.iter().any(|event| matches!(event, ClientEvent::NeedChunk { .. }));
        shown.extend(more);
        if stop {
            break;
        }
    }
    shown
}

#[test]
fn a_file_uploaded_from_the_desktop_becomes_a_message_the_phone_sends() {
    // Ради этого всё и затевалось: байты живут на ноутбуке, а отправляет
    // телефон — своим ключом, из своей истории, и собеседник не отличит
    // такой файл от отправленного с телефона.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let bytes: Vec<u8> = (0..files::CHUNK_BYTES * 2 + 17).map(|n| (n % 251) as u8).collect();
    let shown = upload(&mut phone, &mut desktop, 1_100, chat, &bytes);
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })),
        "конец отправки обязан быть назван: без него окно не знает, что можно закрывать"
    );

    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let stored = &phone.store().files_of(&msg_id).expect("вложения")[0];
    assert_eq!(stored.name, "otchet.pdf");
    assert_eq!(stored.size_bytes, bytes.len() as u64);
    assert!(!stored.incoming, "это исходящий файл — качать его не надо");
    assert!(
        stored.source_path.is_none(),
        "и на диске телефона его нет: байты легли в хранилище запечатанными"
    );

    // Читается он оттуда же, откуда читалось бы принятое, и совпадает
    // с исходником до байта.
    let reader = phone.open_file(&stored.file_id).expect("чтение").expect("вложение открывается");
    let mut whole = Vec::new();
    for index in 0..reader.chunk_total() {
        whole.extend_from_slice(&reader.chunk(index).expect("кусок").expect("кусок на месте"));
    }
    assert_eq!(whole, bytes, "выгруженное обязано совпасть с исходником до байта");
}

#[test]
fn a_file_bigger_than_the_rule_allows_is_refused_before_a_single_byte_moves() {
    // §13.4: файл больше 20 МБ мимо общей сети платит мобильным трафиком
    // телефона. Спрашивается это **до** передачи: сказать «слишком большой»
    // после гигабайта по проводу — издевательство.
    //
    // Здесь канал как раз LAN, значит правило пускает **любой** размер —
    // и это тоже проверка: предел не на общую сеть, а на её отсутствие.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let huge = ratatosk_proto::files::COMPANION_DIRECT_LIMIT_BYTES + 1;
    let started = desktop.step(
        1_100,
        ClientInput::Send {
            chat,
            items: vec![OutgoingItem { name: "video.mp4".into(), size_bytes: huge, preview: None }],
            text: String::new(),
        },
    );
    let shown = pump(&mut phone, &mut desktop, 1_100, started);
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::NeedChunk { .. })),
        "в общей сети размер не ограничен — правило про её отсутствие"
    );

    // А имя с путём не пускается никогда: по проводу едет то, что покажут.
    let bad = desktop.step(
        1_200,
        ClientInput::Send {
            chat,
            items: vec![OutgoingItem {
                name: "../etc/passwd".into(),
                size_bytes: 10,
                preview: None,
            }],
            text: String::new(),
        },
    );
    let shown = pump(&mut phone, &mut desktop, 1_200, bad);
    assert!(
        shown.iter().any(|event| refusal(event).is_some()),
        "отказывает телефон, и отправка на этом кончается: {shown:?}"
    );
}

#[test]
fn a_preview_made_by_the_desktop_reaches_both_the_record_and_the_offer() {
    // Собирает превью клиент — здесь его подменяют готовые байты. Проверяется
    // не картинка, а дорога: превью обязано лечь в запись файла (иначе
    // `has_preview` не станет правдой) **и** уехать собеседнику в предложении
    // §10.3 (иначе он решает по имени файла).
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let picture = vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10];
    let bytes: Vec<u8> = (0..64).map(|n| (n % 251) as u8).collect();
    let shown =
        upload_with_preview(&mut phone, &mut desktop, 1_100, chat, &bytes, Some(picture.clone()));
    assert!(shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })));

    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let stored = &phone.store().files_of(&msg_id).expect("вложения")[0];
    assert_eq!(
        stored.preview.as_ref(),
        Some(&picture),
        "превью обязано лечь в запись — иначе второй экран о нём не узнает"
    );

    // И оно же обязано вернуться на второй экран признаком.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::History { chat, limit: 10, before: None },
    );
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    assert!(page[0].files[0].has_preview, "своё превью видно так же, как чужое");
}

#[test]
fn an_upload_without_a_preview_stays_legal() {
    // Не картинка, декодер не справился, человек не захотел — всё это
    // обычные случаи, и отправка обязана работать ровно как раньше.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let bytes: Vec<u8> = (0..64).map(|n| (n % 251) as u8).collect();
    let shown = upload_with_preview(&mut phone, &mut desktop, 1_100, chat, &bytes, None);
    assert!(shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })));

    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let stored = &phone.store().files_of(&msg_id).expect("вложения")[0];
    assert!(stored.preview.is_none(), "пустота записана пустотой, а не нулевой картинкой");
}

#[test]
fn a_preview_over_the_limit_is_refused_by_the_phone_with_words() {
    // Длину называет десктоп, и проверять её обязан телефон: клиент мог
    // собрать что угодно. Отказ — словами, потому что человек нажал
    // «отправить», и молчание он прочтёт как «отправилось» (§14).
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let started = desktop.step(
        1_100,
        ClientInput::Send {
            chat,
            text: String::new(),
            items: vec![OutgoingItem {
                name: "кот.jpg".into(),
                size_bytes: 64,
                // На один байт больше предела. Телефон такую просьбу не разберёт
                // и, по своему правилу, **отбросит молча** — так устроено
                // узнавание старой сборки. Значит поймать это обязан терминал
                // у себя, до отправки; иначе человек ждал бы ответа, которого
                // не будет.
                preview: Some(vec![7u8; files::PREVIEW_LIMIT_BYTES + 1]),
            }],
        },
    );
    let shown = pump(&mut phone, &mut desktop, 1_100, started);
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Refused(_))),
        "молчание здесь человек прочтёт как «отправилось»: {shown:?}"
    );
    // И место свободно: следующая отправка принимается, а не упирается
    // в «один файл за раз».
    let bytes: Vec<u8> = (0..32).collect();
    let shown = upload_with_preview(&mut phone, &mut desktop, 1_200, chat, &bytes, None);
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })),
        "отвергнутая отправка обязана освободить место"
    );
}

#[test]
fn three_files_from_the_desktop_become_one_message_in_the_chosen_order() {
    // Обе стороны настоящие, и проверяется ровно то, ради чего затевалась
    // поставка: три файла одним сообщением, в том порядке, в каком их выбрали,
    // и каждый со своими байтами.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let first: Vec<u8> = (0..40u8).collect();
    let second: Vec<u8> = (0..40u8).map(|n| n.wrapping_add(100)).collect();
    let third: Vec<u8> = (0..40u8).map(|n| n.wrapping_mul(3)).collect();
    let shown = upload_many(
        &mut phone,
        &mut desktop,
        1_100,
        chat,
        &[
            ("один.bin", &first, None),
            ("два.bin", &second, Some(vec![0x89, b'P', b'N', b'G'])),
            ("три.bin", &third, None),
        ],
        "вот три",
    );
    let sent = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Sent { file_ids } => Some(file_ids.clone()),
            _ => None,
        })
        .expect("конец отправки обязан быть назван");
    assert_eq!(sent.len(), 3, "все три разом, а не по одному");

    let history = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(history.len(), 1, "три вложения — одно сообщение");
    assert_eq!(history[0].body, "вот три".as_bytes());

    let stored = phone.store().files_of(&history[0].msg_id).expect("вложения");
    let names: Vec<&str> = stored.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["один.bin", "два.bin", "три.bin"], "порядок — тот, в каком выбрали");
    assert_eq!(sent, stored.iter().map(|f| f.file_id).collect::<Vec<_>>(), "и он же в событии");
    assert!(stored[1].preview.is_some(), "превью досталось второму, а не первому");
    assert!(stored[0].preview.is_none());

    // И байты каждого — свои. Перепутанные местами куски здесь и есть та
    // ошибка, ради которой номер файла едет в `NeedChunk`.
    for (file, bytes) in stored.iter().zip([&first, &second, &third]) {
        let reader = phone.open_file(&file.file_id).expect("чтение").expect("вложение");
        let mut whole = Vec::new();
        for index in 0..file.chunk_total {
            whole.extend(reader.chunk(index).expect("кусок").expect("кусок на месте"));
        }
        assert_eq!(&whole, bytes, "у «{}» чужие байты", file.name);
    }
}

/// Гонит выгрузку, пока телефону не лягут `stop_after` кусков, и бросает.
///
/// Отдельно от `upload_many` затем, что прерваться надо **посреди**: конец
/// очереди проверяется другими тестами, а этот — про её середину.
fn upload_until(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    chat: [u8; 16],
    files: &[(&str, &[u8])],
    text: &str,
    stop_after: usize,
) -> Vec<ClientEvent> {
    let items = files
        .iter()
        .map(|(name, bytes)| OutgoingItem {
            name: (*name).to_owned(),
            size_bytes: bytes.len() as u64,
            preview: None,
        })
        .collect();
    let started = desktop.step(now_ms, ClientInput::Send { chat, items, text: text.to_owned() });
    let mut shown = pump(phone, desktop, now_ms, started);
    let mut given = 0usize;
    while given < stop_after {
        let Some((which, index)) = shown.iter().rev().find_map(|event| match event {
            ClientEvent::NeedChunk { which, index, .. } => Some((*which as usize, *index)),
            _ => None,
        }) else {
            break;
        };
        let bytes = files[which].1;
        let at = index as usize * files::CHUNK_BYTES;
        let end = (at + files::CHUNK_BYTES).min(bytes.len());
        let asked =
            desktop.step(now_ms, ClientInput::PutChunk { index, bytes: bytes[at..end].to_vec() });
        shown.extend(pump(phone, desktop, now_ms, asked));
        given += 1;
    }
    shown
}

/// Доводит уже начатую выгрузку до конца, отдавая куски, пока их просят.
fn finish_upload(
    phone: &mut Phone,
    desktop: &mut CompanionClient,
    now_ms: u64,
    files: &[(&str, &[u8])],
    mut shown: Vec<ClientEvent>,
) -> Vec<ClientEvent> {
    loop {
        let Some((which, index)) = shown.iter().rev().find_map(|event| match event {
            ClientEvent::NeedChunk { which, index, .. } => Some((*which as usize, *index)),
            _ => None,
        }) else {
            break;
        };
        let bytes = files[which].1;
        let at = index as usize * files::CHUNK_BYTES;
        let end = (at + files::CHUNK_BYTES).min(bytes.len());
        let asked =
            desktop.step(now_ms, ClientInput::PutChunk { index, bytes: bytes[at..end].to_vec() });
        let more = pump(phone, desktop, now_ms, asked);
        let stop = !more.iter().any(|event| matches!(event, ClientEvent::NeedChunk { .. }));
        shown.extend(more);
        if stop {
            break;
        }
    }
    shown
}

#[test]
fn an_upload_broken_in_the_middle_finishes_without_sending_anything_twice() {
    // Ради этого поставка и делалась, и проверяется она обеими настоящими
    // сторонами: телефон помнит выгрузку, терминал спрашивает, что у него
    // осталось, и продолжает с дырки.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // Три файла, у второго — три куска: рвём связь внутри него, а не между.
    let first: Vec<u8> = (0..32u8).collect();
    let second: Vec<u8> = (0..files::CHUNK_BYTES * 2 + 5).map(|n| (n % 251) as u8).collect();
    let third: Vec<u8> = (0..48u8).map(|n| n.wrapping_mul(3)).collect();
    let files: [(&str, &[u8]); 3] =
        [("один.bin", &first), ("два.bin", &second), ("три.bin", &third)];

    // Первый файл целиком (один кусок) и один кусок второго.
    let shown = upload_until(&mut phone, &mut desktop, 1_100, chat, &files, "вот три", 2);
    assert!(
        !shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })),
        "до конца очереди ещё далеко"
    );

    let lost = desktop.step(1_200, ClientInput::Lost);
    let shown_lost: Vec<ClientEvent> = lost
        .into_iter()
        .filter_map(|effect| match effect {
            ClientEffect::Show(event) => Some(event),
            ClientEffect::Send(_) => None,
        })
        .collect();
    assert!(
        shown_lost.contains(&ClientEvent::SendPaused),
        "разрыв посреди отправки — «ждёт», а не «не вышло»: куски лежат у телефона"
    );

    // Связь вернулась. Терминал сам спрашивает, что осталось, и продолжает.
    let back = desktop.step(1_300, ClientInput::Reach);
    let shown = pump(&mut phone, &mut desktop, 1_300, back);
    let resumed = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::SendResumed { done, total } => Some((*done, *total)),
            _ => None,
        })
        .expect("продолжение обязано быть названо: до него на экране было «ждёт связи»");
    assert_eq!(resumed, (1, 3), "первый файл у телефона целиком, второй — нет");
    assert!(
        shown
            .iter()
            .any(|event| matches!(event, ClientEvent::NeedChunk { which: 1, index: 1, .. })),
        "просится дырка второго файла, а не первый файл заново и не нулевой кусок"
    );

    let shown = finish_upload(&mut phone, &mut desktop, 1_300, &files, shown);
    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })),
        "конец отправки обязан быть назван"
    );

    // И сообщение — одно, со всеми тремя, в порядке выбора и с целыми байтами.
    let history = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(history.len(), 1, "разрыв не должен был родить второго сообщения");
    assert_eq!(history[0].body, "вот три".as_bytes());
    let stored = phone.store().files_of(&history[0].msg_id).expect("вложения");
    let names: Vec<&str> = stored.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["один.bin", "два.bin", "три.bin"]);
    for (file, bytes) in stored.iter().zip([&first, &second, &third]) {
        let reader = phone.open_file(&file.file_id).expect("чтение").expect("вложение");
        let mut whole = Vec::new();
        for index in 0..file.chunk_total {
            whole.extend(reader.chunk(index).expect("кусок").expect("кусок на месте"));
        }
        assert_eq!(&whole, bytes, "у «{}» чужие байты после продолжения", file.name);
    }
}

#[test]
fn a_desktop_message_with_one_attachment_still_works() {
    // Список из одного — обычный случай, и он обязан остаться самым простым.
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let bytes: Vec<u8> = (0..32u8).collect();
    let shown =
        upload_many(&mut phone, &mut desktop, 1_100, chat, &[("один.bin", &bytes, None)], "");
    assert!(shown.iter().any(|event| matches!(event, ClientEvent::Sent { .. })));
    let history = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(phone.store().files_of(&history[0].msg_id).expect("вложения").len(), 1);
}

#[test]
fn a_text_over_the_limit_is_refused_by_the_phone_too() {
    // Терминал ловит это у себя, но правило живёт **и** на телефоне: своя
    // отправка с самого телефона идёт мимо терминала, а сообщение, легшее
    // в базу и не собравшееся в кадр, человек видел бы вечно ждущим.
    let (mut phone, _blobs, _desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let huge = "т".repeat(files::MAX_TEXT_BYTES);
    let refused = phone.step(1_100, Input::Command(Command::SendText { chat, text: huge }));
    assert!(refused.is_err(), "слишком длинный текст обязан быть отвергнут");
    assert!(
        phone.store().messages(&chat, 10, None).expect("история").is_empty(),
        "и не лечь в историю: отказ до записи, а не после"
    );

    // Ровно предел — законен и доходит до истории.
    let edge = "т".repeat(files::MAX_TEXT_BYTES / 2);
    phone
        .step(1_200, Input::Command(Command::SendText { chat, text: edge }))
        .expect("ровно предел законен");
    assert_eq!(phone.store().messages(&chat, 10, None).expect("история").len(), 1);
}

#[test]
fn an_upload_with_a_hole_is_refused_rather_than_sent() {
    // Файл с дырой, уехавший собеседнику, тот соберёт и не заметит — хэш
    // считается от целого, а целого не будет. Человек при этом увидит
    // «отправлено».
    let (mut phone, _blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let started = desktop.step(
        1_100,
        ClientInput::Send {
            chat,
            items: vec![OutgoingItem {
                name: "otchet.pdf".into(),
                size_bytes: files::CHUNK_BYTES as u64 * 2,
                preview: None,
            }],
            text: String::new(),
        },
    );
    let shown = pump(&mut phone, &mut desktop, 1_100, started);
    let file_id = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::NeedChunk { file_id, .. } => Some(*file_id),
            _ => None,
        })
        .expect("место отведено");

    // Просим отправить, не выгрузив ни куска.
    let asked = desktop.step(
        1_200,
        ClientInput::Ask(Request::FileSend { file_ids: vec![file_id], text: String::new() }),
    );
    let shown = pump(&mut phone, &mut desktop, 1_200, asked);
    assert!(
        shown.iter().any(|event| refusal(event).is_some()),
        "отправлять неполное нельзя, и сказать об этом надо словами"
    );
    assert!(
        phone.store().messages(&chat, 10, None).expect("история").is_empty(),
        "и сообщения появиться не должно: недоехавший файл не имеет права быть в переписке"
    );
}

#[test]
fn declining_takes_the_attachment_off_the_desktop_and_leaves_the_message() {
    // Разбор живой поломки: отказ сообщался «нулём из нуля», десктоп верил
    // нулям как числам, и строка вложения оставалась на месте — показывая
    // «0/0» и предлагая принять то, чего на телефоне уже нет. Сообщение
    // превращалось во что-то непонятное.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, effects) = say(&mut phone, 1_100, chat, "вот видео");
    let _ = relay(&mut desktop, 1_100, effects);
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    // Кэш обязан держать сообщение — иначе проверять нечего.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::History { chat, limit: 10, before: None },
    );
    assert!(shown.iter().any(|event| matches!(
        event,
        ClientEvent::History { page, .. } if page[0].files.len() == 1
    )));

    let shown = desktop_asks(&mut phone, &mut desktop, 1_300, Request::DeclineFile { file_id });
    assert!(
        shown
            .iter()
            .any(|event| matches!(event, ClientEvent::FileGone { file_id: id } if *id == file_id)),
        "об исчезновении вложения обязана приходить своя новость, а не нули в полоске"
    );
    assert!(
        !shown.iter().any(|event| matches!(event, ClientEvent::FileProgress { .. })),
        "полоска того, чего больше нет, — это и есть призрак"
    );

    // И перечитывание показывает то же самое: сообщение на месте, вложения нет.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_400,
        Request::History { chat, limit: 10, before: None },
    );
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    assert_eq!(page.len(), 1, "сообщение осталось: текст к отвергнутой картинке никуда не делся");
    assert!(page[0].files.is_empty(), "а вложения у него больше нет");
    assert_eq!(page[0].text, "вот видео");
}

#[test]
fn pausing_from_the_desktop_keeps_the_offer_and_what_arrived() {
    // Разница с отказом — в том, что остаётся. На быстрой сети её незаметно,
    // и потому её легко не завести; на мобильном канале она и есть весь смысл.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "вот видео");
    let file_id = awaiting_decision(&mut phone, msg_id, 4);

    let _ = desktop_asks(&mut phone, &mut desktop, 1_200, Request::AcceptFile { file_id });
    let shown = desktop_asks(&mut phone, &mut desktop, 1_300, Request::PauseFile { file_id });
    assert!(shown.contains(&ClientEvent::Done));

    let file = phone.store().file(&file_id).expect("чтение").expect("запись остаётся");
    assert!(!file.accepted, "согласия больше нет");
    assert_eq!(file.chunk_total, 4, "а предложение живо: отказ унёс бы его целиком");

    // И десктоп узнаёт об этом новостью, а не перечитыванием.
    let told = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::FileProgress { file_id: id, accepted, .. } if *id == file_id => {
                Some(*accepted)
            }
            _ => None,
        })
        .expect("о снятом согласии десктоп обязан узнать");
    assert!(!told, "иначе пауза выглядит как зависший приём");

    // Принять заново можно, и это не начало сначала: запись та же.
    let again = desktop_asks(&mut phone, &mut desktop, 1_400, Request::AcceptFile { file_id });
    assert!(again.contains(&ClientEvent::Done));
    assert!(phone.store().file(&file_id).expect("чтение").expect("запись").accepted);
}

#[test]
fn stopping_a_fetch_needs_no_word_with_the_phone() {
    // У телефона состояния выгрузки нет: каждый кусок — отдельная просьба,
    // отвечаемая и забываемая. Значит прекратить — это перестать просить,
    // и никакого кадра для этого не нужно.
    let (mut phone, blobs, mut desktop) = linked_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = files::CHUNK_BYTES as u64 * 3;
    blobs.lock().unwrap().seed_sparse("/tmp/video.mp4", size);
    phone
        .step(
            1_100,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![OutgoingFile { path: "/tmp/video.mp4".into(), preview: None }],
                text: "видео".into(),
            }),
        )
        .expect("отправка файла");
    let msg_id = phone.store().messages(&chat, 1, None).expect("история")[0].msg_id;
    let file_id = phone.store().files_of(&msg_id).expect("вложения")[0].file_id;

    let started = desktop.step(1_200, ClientInput::Fetch { file_id, chunk_total: 3 });
    assert!(started.iter().any(|effect| matches!(effect, ClientEffect::Send(_))));

    let stopped = desktop.step(1_300, ClientInput::CancelFetch);
    assert!(
        !stopped.iter().any(|effect| matches!(effect, ClientEffect::Send(_))),
        "прекращение по проводу не ездит: телефону нечего об этом знать"
    );
    assert!(stopped
        .iter()
        .any(|effect| matches!(effect, ClientEffect::Show(ClientEvent::FetchCancelled { .. }))));

    // И место освобождено: следующая выгрузка принимается, а не отвергается
    // «одно вложение за раз».
    let again = desktop.step(1_400, ClientInput::Fetch { file_id, chunk_total: 3 });
    assert!(again.iter().any(|effect| matches!(effect, ClientEffect::Send(_))));
}

#[test]
fn the_desktop_sets_a_reaction_and_the_phone_tells_it_back() {
    // Круг целиком: просьба уходит с ноутбука, реакция ложится в базу
    // телефона, и оттуда же возвращается новостью — тем же путём, каким
    // возвращается реакция, поставленная руками на телефоне.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "слово");

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::SetReaction { chat, msg_id, emoji: "👍".into() },
    );
    assert!(shown.contains(&ClientEvent::Done), "телефон отвечает «сделано»");
    assert_eq!(phone.store().reactions(&msg_id).expect("реакции").len(), 1, "и правда сделал");

    let told = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Reacted { reactions, .. } => Some(reactions),
            _ => None,
        })
        .expect("свою же просьбу десктоп узнаёт новостью, а не догадкой");
    assert_eq!(told[0].emoji, "👍");
    assert!(told[0].mine);

    // И снятие тем же путём: пустая строка — состояние, а не отдельный вид.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_300,
        Request::SetReaction { chat, msg_id, emoji: String::new() },
    );
    assert!(shown.iter().any(
        |event| matches!(event, ClientEvent::Reacted { reactions, .. } if reactions.is_empty())
    ));
    assert!(phone.store().reactions(&msg_id).expect("реакции").is_empty());
}

#[test]
fn the_desktop_replies_and_edits_and_the_phone_keeps_the_rules() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (first, _) = say(&mut phone, 1_100, chat, "вопрос");

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::SendReply { chat, reply_to: first, text: "ответ".into() },
    );
    assert!(shown.contains(&ClientEvent::Done));
    let arrived = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) if message.text == "ответ" => Some(message),
            _ => None,
        })
        .expect("отправленное с ноутбука возвращается новостью");
    assert_eq!(arrived.reply_to, Some(first));

    let reply_id = last_in(&phone, chat);
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_300,
        Request::EditMessage {
            chat, msg_id: reply_id, text: "не ответ, а вопрос".into()
        },
    );
    let edited = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Edited(message) => Some(message),
            _ => None,
        })
        .expect("правка возвращается новостью");
    assert_eq!(edited.text, "не ответ, а вопрос");
    assert!(edited.edited_ms.is_some(), "и приезжает с отметкой — иначе это подмена слов");
}

#[test]
fn a_rule_the_phone_enforces_comes_back_to_the_desktop_in_words() {
    // Правила остались на телефоне — все до одного, — и десктоп узнаёт о них
    // не догадкой, а отказом со словами. «Правку старше недели не приняли»
    // и «телефон сломался» человек за ноутбуком обязан различать (§14).
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (msg_id, _) = say(&mut phone, 1_100, chat, "текст");

    // Пустая правка — не правка: для этого есть удаление, и телефон
    // отказывается, а не превращает одно в другое молча.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::EditMessage { chat, msg_id, text: "   ".into() },
    );
    let refused = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Refused(why) => Some(why),
            _ => None,
        })
        .expect("отказ обязан приехать словами");
    assert!(!refused.is_empty(), "и слова обязаны быть: пустой отказ нечего показать");
    assert!(!shown.contains(&ClientEvent::Done), "«сделано» на несделанное — ложь (§14)");

    // И реакция, которая не эмодзи: то же правило, тот же путь.
    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_300,
        Request::SetReaction { chat, msg_id, emoji: "hello".into() },
    );
    assert!(shown.iter().any(|event| matches!(event, ClientEvent::Refused(_))));
    assert!(phone.store().reactions(&msg_id).expect("реакции").is_empty());
}

#[test]
fn deleting_from_the_desktop_is_not_the_same_as_retracting() {
    // Поля у этих просьб одинаковы, а необратимость разная: одна про свою
    // копию, вторая — просьба к чужой. Спутав их, десктоп однажды стёр бы
    // переписку у собеседника, желая убрать её у себя.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (mine, _) = say(&mut phone, 1_100, chat, "своё");

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::DeleteMessages { chat, msg_ids: vec![mine] },
    );
    assert!(shown.iter().any(
        |event| matches!(event, ClientEvent::Gone { msg_ids, .. } if msg_ids.contains(&mine))
    ));
    assert!(phone.store().message(&mine).expect("чтение").is_none(), "у себя стёрлось");

    // Отзыв — то же у себя **плюс** просьба собеседнику. Кадр к нему
    // проверяется здесь только фактом: pump отдаёт терминалу лишь своё,
    // а чужое остаётся в эффектах шага.
    let (second, _) = say(&mut phone, 1_300, chat, "и это");
    let asked = desktop
        .step(1_400, ClientInput::Ask(Request::RetractMessages { chat, msg_ids: vec![second] }));
    let shown = pump(&mut phone, &mut desktop, 1_400, asked);
    assert!(shown.contains(&ClientEvent::Done));
    assert!(phone.store().message(&second).expect("чтение").is_none());
}

#[test]
fn clearing_a_chat_from_the_desktop_empties_it_on_the_phone() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let (first, _) = say(&mut phone, 1_100, chat, "раз");
    let (second, _) = say(&mut phone, 1_150, chat, "два");

    let shown = desktop_asks(&mut phone, &mut desktop, 1_200, Request::ClearChat { chat });
    assert!(shown.contains(&ClientEvent::Done));

    let gone: Vec<[u8; 16]> = shown
        .iter()
        .filter_map(|event| match event {
            ClientEvent::Gone { msg_ids, .. } => Some(msg_ids.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(gone.contains(&first) && gone.contains(&second), "исчезло всё, и сказано про всё");
    assert!(phone.store().messages(&chat, 10, None).expect("история").is_empty());
}

#[test]
fn forwarding_from_the_desktop_lands_in_the_other_chat_marked() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let first_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let second_ik = with_contact(&mut phone, 1_060, "коллега", 8);
    let from = Engine::<MemoryStore>::chat_id_for(&first_ik);
    let to = Engine::<MemoryStore>::chat_id_for(&second_ik);
    let (msg_id, _) = say(&mut phone, 1_100, from, "чужие слова");

    let shown = desktop_asks(
        &mut phone,
        &mut desktop,
        1_200,
        Request::ForwardMessages { chat: to, msg_ids: vec![msg_id] },
    );
    assert!(shown.contains(&ClientEvent::Done));
    let forwarded = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) if message.chat == to => Some(message),
            _ => None,
        })
        .expect("пересланное возвращается новостью");
    assert!(forwarded.forwarded, "и с пометкой: без неё это выглядит как свои слова");
}

#[test]
fn an_edited_message_reaches_the_desktop_marked_as_edited() {
    // §14 запрещает молча подменять слова в истории, и запрещает на **обоих**
    // экранах. У телефона отметка была с самого начала (`FfiMessage`),
    // у десктопа — нет: правка приезжала новостью и заменяла текст без следа.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "апечатка");
    let arrival = relay(&mut desktop, 1_100, effects);
    let arrived = arrival
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => Some(message),
            _ => None,
        })
        .expect("сообщение доехало");
    assert_eq!(arrived.edited_ms, None, "непоправленное отметки не несёт");

    let effects = phone
        .step(1_200, Input::Command(Command::EditMessage { chat, msg_id, text: "опечатка".into() }))
        .expect("правка");
    let shown = relay(&mut desktop, 1_200, effects);
    let edited = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Edited(message) => Some(message),
            _ => None,
        })
        .expect("о правке десктоп узнаёт");
    assert!(edited.edited_ms.is_some(), "и узнаёт вместе с отметкой, а не только текстом");

    // И в истории тоже: новость показывает один экран, страница — другой.
    let asked =
        desktop.step(1_300, ClientInput::Ask(Request::History { chat, limit: 10, before: None }));
    let shown = pump(&mut phone, &mut desktop, 1_300, asked);
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    assert!(page[0].edited_ms.is_some(), "страница несёт ту же отметку, что и новость");
}

#[test]
fn a_reply_reaches_the_desktop_as_a_link_and_not_as_a_quote() {
    // Цитату рисует та сторона, у которой есть своя копия. Присланный вместе
    // с ответом текст был бы местом для слов, которых собеседник не говорил, —
    // и через границу устройства это правило то же, что через провод.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (first, _) = say(&mut phone, 1_100, chat, "вопрос");
    let effects = phone
        .step(
            1_200,
            Input::Command(Command::SendReply { chat, reply_to: first, text: "ответ".into() }),
        )
        .expect("ответ");
    let shown = relay(&mut desktop, 1_200, effects);

    let arrived = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) if message.text == "ответ" => Some(message),
            _ => None,
        })
        .expect("ответ доехал новостью");
    assert_eq!(arrived.reply_to, Some(first), "ссылка на исходное — часть сообщения");
    assert!(!arrived.text.contains("вопрос"), "а вот отрывка цитаты в нём быть не должно");
}

#[test]
fn a_forwarded_message_reaches_the_desktop_marked_and_without_an_author() {
    // Пометка обязательна, а имени автора рядом нет намеренно: подпись §6
    // при пересылке не сохраняется, и «переслано от N» было бы утверждением,
    // которое никто не может проверить.
    let (mut phone, mut desktop, _) = linked(1_000);
    let first_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let second_ik = with_contact(&mut phone, 1_060, "коллега", 8);
    let from = Engine::<MemoryStore>::chat_id_for(&first_ik);
    let to = Engine::<MemoryStore>::chat_id_for(&second_ik);

    let (msg_id, _) = say(&mut phone, 1_100, from, "чужие слова");
    let effects = phone
        .step(1_200, Input::Command(Command::ForwardMessages { chat: to, msg_ids: vec![msg_id] }))
        .expect("пересылка");
    let shown = relay(&mut desktop, 1_200, effects);

    let forwarded = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) if message.chat == to => Some(message),
            _ => None,
        })
        .expect("пересланное доехало новостью");
    assert!(forwarded.forwarded, "без пометки это выглядело бы как свои слова");
}

#[test]
fn a_reaction_set_on_the_phone_reaches_the_desktop() {
    // До этой новости реакция была расхождением потише прочих, но того же
    // рода: поставленная на телефоне, на втором экране она не появлялась
    // вовсе — увидеть её можно было только перечитав чат.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "слово");
    let arrival = relay(&mut desktop, 1_100, effects);
    let arrived = arrival
        .iter()
        .find_map(|event| match event {
            ClientEvent::Arrived(message) => Some(message),
            _ => None,
        })
        .expect("сообщение доехало");
    assert!(arrived.reactions.is_empty(), "у только что появившегося реакций нет");

    let effects = phone
        .step(1_200, Input::Command(Command::SetReaction { chat, msg_id, emoji: "👍".into() }))
        .expect("реакция");
    let shown = relay(&mut desktop, 1_200, effects);

    let reacted = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Reacted { msg_id: id, reactions, .. } if *id == msg_id => Some(reactions),
            _ => None,
        })
        .expect("о реакции десктоп обязан узнать");
    assert_eq!(reacted.len(), 1);
    assert_eq!(reacted[0].emoji, "👍");
    assert!(reacted[0].mine, "своя реакция помечена своей: `IK` границу не пересекает");
}

#[test]
fn removing_a_reaction_is_told_as_an_empty_set_not_as_silence() {
    // Снятие по проводу контактов — пустая строка (это состояние с меткой
    // порядка). До десктопа оно обязано доехать как **пустой набор**: молчание
    // он прочтёт как «ничего не изменилось» и оставит снятое на экране.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "слово");
    let _ = relay(&mut desktop, 1_100, effects);
    let effects = phone
        .step(1_200, Input::Command(Command::SetReaction { chat, msg_id, emoji: "👍".into() }))
        .expect("реакция");
    let _ = relay(&mut desktop, 1_200, effects);

    let effects = phone
        .step(1_300, Input::Command(Command::SetReaction { chat, msg_id, emoji: String::new() }))
        .expect("снятие");
    let shown = relay(&mut desktop, 1_300, effects);

    let reacted = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::Reacted { reactions, .. } => Some(reactions),
            _ => None,
        })
        .expect("о снятии десктоп обязан узнать");
    assert!(reacted.is_empty(), "снятая реакция — пустой набор, а не запись с пустой строкой");
}

#[test]
fn a_history_page_carries_the_reactions_that_are_already_there() {
    // Новости приходят, пока десктоп подключён. Всё, что было до, он узнаёт
    // страницей истории — и без реакций в ней окно, открытое заново,
    // показывало бы переписку так, будто реакции сняли.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, _) = say(&mut phone, 1_100, chat, "слово");
    phone
        .step(1_150, Input::Command(Command::SetReaction { chat, msg_id, emoji: "🔥".into() }))
        .expect("реакция");

    let asked =
        desktop.step(1_200, ClientInput::Ask(Request::History { chat, limit: 10, before: None }));
    let shown = pump(&mut phone, &mut desktop, 1_200, asked);

    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("страница пришла");
    let message = page.iter().find(|m| m.msg_id == msg_id).expect("сообщение в странице");
    assert_eq!(message.reactions.len(), 1, "реакция приехала вместе с сообщением");
    assert_eq!(message.reactions[0].emoji, "🔥");
}

#[test]
fn paging_back_from_a_message_that_is_gone_says_so_instead_of_showing_an_edge() {
    // Мёртвый курсор и край истории — разные вещи, и раньше выглядели
    // одинаково: пустой страницей. Десктоп, услышав «край», переставал
    // листать назад, и переписка за курсором становилась недоступной,
    // хотя лежала на месте.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (older, _) = say(&mut phone, 1_100, chat, "раньше");
    let (anchor, _) = say(&mut phone, 1_150, chat, "якорь");
    phone
        .step(1_200, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![anchor] }))
        .expect("удаление якоря");

    let asked = desktop
        .step(1_300, ClientInput::Ask(Request::History { chat, limit: 10, before: Some(anchor) }));
    let shown = pump(&mut phone, &mut desktop, 1_300, asked);

    assert!(
        shown.iter().any(|event| matches!(event, ClientEvent::Refused(_))),
        "мёртвый курсор — отказ словами, а не молчаливый край истории"
    );
    assert!(
        !shown.iter().any(|event| matches!(event, ClientEvent::History { .. })),
        "и не страница: пустая прочлась бы как «дальше ничего нет»"
    );

    // А настоящий край — по-прежнему пустая страница, а не отказ: иначе
    // «долистали до начала» стало бы выглядеть как поломка.
    let asked = desktop
        .step(1_400, ClientInput::Ask(Request::History { chat, limit: 10, before: Some(older) }));
    let shown = pump(&mut phone, &mut desktop, 1_400, asked);
    let page = shown
        .iter()
        .find_map(|event| match event {
            ClientEvent::History { page, .. } => Some(page),
            _ => None,
        })
        .expect("край истории — это страница");
    assert!(page.is_empty(), "и она пустая");
}

#[test]
fn a_deletion_and_an_arrival_are_not_the_same_news() {
    // Оба ведут к перерисовке чата, но означают противоположное. Слитые
    // в одно «что-то изменилось», они заставили бы десктоп перечитывать
    // историю на каждое сообщение.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "слово");
    let arrival = relay(&mut desktop, 1_100, effects);
    assert!(arrival.iter().any(|event| matches!(event, ClientEvent::Arrived(_))));
    assert!(!arrival.iter().any(|event| matches!(event, ClientEvent::Gone { .. })));

    let effects = phone
        .step(1_200, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![msg_id] }))
        .expect("удаление");
    let removal = relay(&mut desktop, 1_200, effects);
    assert!(removal.iter().any(|event| matches!(event, ClientEvent::Gone { .. })));
    assert!(!removal.iter().any(|event| matches!(event, ClientEvent::Arrived(_))));
}

#[test]
fn the_terminal_shows_what_it_remembers_when_the_phone_is_away() {
    // Ради этого кэш и заведён: телефон в кармане уснул, а окно на ноутбуке
    // не гаснет. Но показанное обязано быть **помечено** — иначе это тот же
    // врущий экран, только теперь молчаливый.
    let (mut phone, mut desktop, _) = linked(1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);

    let asked = desktop.step(1_100, ClientInput::Ask(Request::Chats));
    let shown = pump(&mut phone, &mut desktop, 1_100, asked);
    assert!(
        shown.iter().any(|e| matches!(e, ClientEvent::Chats { fresh: true, .. })),
        "ответ телефона приходит подтверждённым"
    );

    let _ = desktop.step(1_200, ClientInput::Lost);
    let offline = desktop.step(1_300, ClientInput::Ask(Request::Chats));

    let mut events = Vec::new();
    for effect in offline {
        if let ClientEffect::Show(event) = effect {
            events.push(event);
        }
    }
    let remembered = events
        .iter()
        .find_map(|event| match event {
            ClientEvent::Chats { chats, fresh } => Some((chats, *fresh)),
            _ => None,
        })
        .expect("без связи показывается то, что помним");
    assert_eq!(remembered.0.len(), 1, "список тот же");
    assert!(!remembered.1, "и он помечен как неподтверждённый");
    assert!(
        events.iter().any(|e| matches!(e, ClientEvent::NotLinked)),
        "и сказано, что телефона нет: одно не заменяет другого"
    );
}

#[test]
fn a_deletion_reaches_the_cache_too() {
    // Иначе первое же перечитывание из памяти показало бы стёртое —
    // ровно та дыра, которую закрыли новости, только внутри терминала.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "лишнее");
    let _ = relay(&mut desktop, 1_100, effects);

    // Страницу надо сперва прочитать: новость о появлении ложится только
    // в тот чат, историю которого терминал и так держит.
    let asked =
        desktop.step(1_150, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut desktop, 1_150, asked);
    assert_eq!(desktop.cache().page(&chat).len(), 1, "сообщение легло в память");

    let effects = phone
        .step(1_200, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![msg_id] }))
        .expect("удаление");
    let _ = relay(&mut desktop, 1_200, effects);

    assert!(desktop.cache().page(&chat).is_empty(), "и ушло из памяти вместе с экраном");
}

#[test]
fn an_edit_replaces_the_remembered_text() {
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "апечатка");
    let _ = relay(&mut desktop, 1_100, effects);
    let asked =
        desktop.step(1_150, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut desktop, 1_150, asked);

    let effects = phone
        .step(1_200, Input::Command(Command::EditMessage { chat, msg_id, text: "опечатка".into() }))
        .expect("правка");
    let _ = relay(&mut desktop, 1_200, effects);

    let page = desktop.cache().page(&chat);
    assert_eq!(page.len(), 1, "правка не заводит второго сообщения");
    assert_eq!(page[0].text, "опечатка");
}

#[test]
fn a_chat_that_vanished_takes_its_history_out_of_memory() {
    // Список чатов заменяется ответом целиком, и вместе с исчезнувшим чатом
    // уходит его история: иначе удалённый на телефоне контакт жил бы
    // в памяти окна до перезапуска.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (_, effects) = say(&mut phone, 1_100, chat, "слово");
    let _ = relay(&mut desktop, 1_100, effects);
    let asked =
        desktop.step(1_150, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut desktop, 1_150, asked);
    assert!(!desktop.cache().page(&chat).is_empty());

    phone
        .step(1_200, Input::Command(Command::DeleteContact { peer_ik, purge_history: true }))
        .expect("удаление контакта");
    let asked = desktop.step(1_300, ClientInput::Ask(Request::Chats));
    let _ = pump(&mut phone, &mut desktop, 1_300, asked);

    assert!(desktop.cache().chats().is_empty(), "чата больше нет");
    assert!(desktop.cache().page(&chat).is_empty(), "и его истории тоже");
}

#[test]
fn an_answer_replaces_the_page_rather_than_piling_onto_it() {
    // Ответ телефона новее всего, что мы помним, и заменяет пересекающийся
    // кусок. Слияние потребовало бы на десктопе второй копии правил §9.1
    // о порядке — то есть ровно того, что §13.3 держит ниже границы.
    let (mut phone, mut desktop, _) = linked(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (_, effects) = say(&mut phone, 1_100, chat, "раз");
    let _ = relay(&mut desktop, 1_100, effects);

    for at in [1_150, 1_250] {
        let asked =
            desktop.step(at, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
        let _ = pump(&mut phone, &mut desktop, at, asked);
    }
    assert_eq!(desktop.cache().page(&chat).len(), 1, "дважды прочитанное — одно сообщение");
}

#[test]
fn a_snapshot_survives_a_closed_window() {
    // Ради этого дисковый кэш и заводят: окно закрыли, открыли — и переписка
    // на месте, не дожидаясь, пока телефон проснётся.
    let (mut phone, mut desktop, _, invite) = linked_with_invite(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (_, effects) = say(&mut phone, 1_100, chat, "было сказано");
    let _ = relay(&mut desktop, 1_100, effects);
    let asked =
        desktop.step(1_150, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut desktop, 1_150, asked);

    assert!(desktop.cache().dirty(), "кэш изменился — есть что писать");
    let sealed = desktop.snapshot().expect("снимок собирается");
    assert!(!desktop.cache().dirty(), "после снимка писать нечего");

    // Окно закрыли и открыли: тот же ключ сопряжения, новый терминал.
    let mut again = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(7)));
    assert!(again.cache().page(&chat).is_empty(), "пока не подняли — пусто");
    again.restore(&sealed).expect("снимок поднимается");

    assert_eq!(again.cache().page(&chat).len(), 1);
    assert_eq!(again.cache().page(&chat)[0].text, "было сказано");
    assert!(!again.cache().fresh(), "но это то, что было, а не то, что есть");
}

#[test]
fn a_snapshot_from_another_pairing_does_not_open() {
    // Иначе перепутанные каталоги дали бы чужую переписку в чужом окне —
    // а «файл не читается» человек хотя бы понимает.
    //
    // Хозяин назван `owner`, а не `phone`: имя `phone` носит и функция,
    // а второй телефон здесь заводится **после** первого — затенив её
    // переменной, вызвать её мы бы уже не смогли.
    let (mut owner, mut desktop, _, _) = linked_with_invite(1_000);
    let peer_ik = with_contact(&mut owner, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let asked =
        desktop.step(1_100, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut owner, &mut desktop, 1_100, asked);
    let sealed = desktop.snapshot().expect("снимок");

    let mut other_phone = phone(2, "другой");
    let other = invited(&mut other_phone, 2_000);
    let mut stranger = CompanionClient::from_invite(&other, Box::new(SeededEntropy::new(5)));

    assert!(stranger.restore(&sealed).is_err(), "чужой снимок не открывается");
    assert!(stranger.cache().chats().is_empty(), "и ничего от него не остаётся");
}

#[test]
fn a_damaged_snapshot_is_refused_rather_than_half_read() {
    let (mut phone, mut desktop, _, invite) = linked_with_invite(1_000);
    with_contact(&mut phone, 1_050, "сосед", 9);
    let asked = desktop.step(1_100, ClientInput::Ask(Request::Chats));
    let _ = pump(&mut phone, &mut desktop, 1_100, asked);

    let mut sealed = desktop.snapshot().expect("снимок");
    let last = sealed.len() - 1;
    sealed[last] ^= 0xff;

    let mut again = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(7)));
    assert!(again.restore(&sealed).is_err(), "испорченный снимок не читается");
}

#[test]
fn what_the_phone_says_replaces_what_came_off_the_disk() {
    // Пометка снимается первым же ответом, и снимается **целиком**: сообщение,
    // стёртое на телефоне, пока окно было закрыто, из кэша уходит вместе
    // с заменой страницы.
    let (mut phone, mut desktop, _, invite) = linked_with_invite(1_000);
    let peer_ik = with_contact(&mut phone, 1_050, "сосед", 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (msg_id, effects) = say(&mut phone, 1_100, chat, "исчезнет");
    let _ = relay(&mut desktop, 1_100, effects);
    let asked =
        desktop.step(1_150, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut desktop, 1_150, asked);
    let sealed = desktop.snapshot().expect("снимок");

    // Окно закрыто, а на телефоне сообщение стёрли — новость никуда не ушла.
    phone
        .step(1_200, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![msg_id] }))
        .expect("удаление");

    let mut again = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(7)));
    again.restore(&sealed).expect("снимок поднимается");
    assert_eq!(again.cache().page(&chat).len(), 1, "стёртое лежит в файле целым");
    assert!(!again.cache().fresh(), "и потому помечено");

    // Связь вернулась — и первый же ответ телефона это исправляет.
    let first = again.step(1_300, ClientInput::Reach);
    let _ = pump(&mut phone, &mut again, 1_300, first);
    let asked =
        again.step(1_400, ClientInput::Ask(Request::History { chat, limit: 20, before: None }));
    let _ = pump(&mut phone, &mut again, 1_400, asked);

    assert!(again.cache().page(&chat).is_empty(), "телефон сказал правду, и она заменила память");
    assert!(again.cache().fresh(), "и пометка снята");
}

#[test]
fn a_handshake_alone_does_not_mean_the_desktop_is_on_the_line() {
    // Отметка о деле, а не о намерении (ARCHITECTURE, 5аж и 5бз). Ответ
    // рукопожатия телефон кладёт в эффекты, но уедет ли он — неизвестно:
    // соединения односторонние, и без адреса десктопа ответ уходит в никуда.
    // Отметив связь на рукопожатии, телефон говорил «десктоп на связи»
    // ровно в тот момент, когда не смог ему ответить.
    let mut phone = phone(1, "телефон");
    let invite = invited(&mut phone, 1_000);
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));

    // Рукопожатие доезжает до телефона — и только оно.
    let hello = desktop.step(1_100, ClientInput::Reach);
    let mut frames = Vec::new();
    for effect in hello {
        if let ClientEffect::Send(frame) = effect {
            frames.push(frame);
        }
    }
    for frame in frames {
        phone.step(1_100, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    }

    let device_id = phone.paired_devices()[0].device_id;
    assert!(
        !phone.device_connected(&device_id),
        "рукопожатие не доказывает, что ответ дошёл — доказывает первая просьба"
    );
}

#[test]
fn the_first_request_is_what_puts_the_desktop_on_the_line() {
    // Обратная половина того же правила: просьба доказывает, что ответ дошёл
    // и обратный путь работает. Ничто другое этого не доказывает.
    let (phone, _desktop, _) = linked(1_000);
    let device_id = phone.paired_devices()[0].device_id;
    assert!(phone.device_connected(&device_id), "терминал спросил чаты сам — значит ответ дошёл");
}

#[test]
fn a_terminal_that_got_no_answer_says_hello_again() {
    // Ровно то, чего не хватало: телефон не смог ответить (адреса не знал),
    // и связь встаёт только со следующей попытки. Повторить обязан терминал —
    // у компаньона нет очереди §5.4, пересылать потерянный ответ некому.
    let mut phone = phone(1, "телефон");
    let invite = invited(&mut phone, 1_000);
    let mut desktop = CompanionClient::from_invite(&invite, Box::new(SeededEntropy::new(99)));

    // Первое рукопожатие: телефон его принял, а ответ до нас не доехал.
    let hello = desktop.step(1_100, ClientInput::Reach);
    assert!(hello.iter().any(|e| matches!(e, ClientEffect::Send(_))));
    for effect in hello {
        if let ClientEffect::Send(frame) = effect {
            phone.step(1_100, Input::Received { via: Transport::Lan, frame }).expect("шаг");
        }
    }
    assert!(!desktop.linked(), "ответа не было — связи нет");

    // Повтор обязан снова поздороваться, а не промолчать.
    let again = desktop.step(1_200, ClientInput::Reach);
    assert!(
        again.iter().any(|e| matches!(e, ClientEffect::Send(_))),
        "неотвеченное рукопожатие повторяется — иначе связь не встанет никогда"
    );

    // И на этот раз ответ доходит.
    let shown = pump(&mut phone, &mut desktop, 1_200, again);
    assert!(desktop.linked());
    assert!(shown.contains(&ClientEvent::Linked));
}
