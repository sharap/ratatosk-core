//! Два ядра, говорящие друг с другом напрямую.
//!
//! Тест соединяет два [`Engine`] проводом из десяти строк: всё, что одно
//! ядро вернуло как [`Effect::Send`], подаётся другому как
//! [`Input::Received`]. Ни сети, ни рантайма, ни симулятора — только
//! `step`.
//!
//! Это промежуточная ступень между модульными тестами и сценариями §16,
//! и она проверяет ровно то, что нельзя проверить по частям: что
//! рукопожатие, ретчет, кодек, кадрирование и хранилище **сходятся вместе**.
//! Если 1:1-текст не работает здесь, в симуляторе он не заработает тем более.

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, SeededEntropy};
use ratatosk_crypto::Identity;
use ratatosk_store::{MemoryStore, Store};

type Node = Engine<MemoryStore>;

fn node(seed: u8, name: &str) -> Node {
    let identity = Identity::from_seed([seed; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция in-memory хранилища");

    Engine::new(
        identity,
        store,
        Box::new(SeededEntropy::new(u64::from(seed))),
        SelfAddresses {
            onion: format!("{name}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"),
            chatmail: format!("{name}@nine.example"),
            display_name: name.to_owned(),
        },
    )
}

/// Провод между двумя ядрами.
///
/// Возвращает все события для UI, накопившиеся с обеих сторон, — по ним
/// и проверяется результат. Доставка мгновенная и без потерь: перестановки
/// и разрывы — забота симулятора, здесь проверяется сам протокол.
fn pump(a: &mut Node, b: &mut Node, now_ms: u64, from_a: Vec<Effect>) -> Vec<Event> {
    let mut events = Vec::new();
    let mut queue: Vec<(bool, Effect)> = from_a.into_iter().map(|e| (true, e)).collect();

    let mut steps = 0;
    while let Some((from_first, effect)) = queue.pop() {
        steps += 1;
        assert!(steps < 100, "обмен не сходится — вероятно, кольцо эффектов");

        match effect {
            Effect::Send { via, frame, .. } => {
                let target = if from_first { &mut *b } else { &mut *a };
                let produced = target
                    .step(now_ms, Input::Received { via, frame })
                    .expect("приём кадра не должен отказывать");
                queue.extend(produced.into_iter().map(|e| (!from_first, e)));
            }
            // Таймер попытки доставки (§5.4). Провод мгновенный и без потерь,
            // поэтому «об отказе не сообщили» здесь верно по построению:
            // срабатывание таймера означает «ушло». Без этой ветки запись
            // навсегда оставалась бы в очереди, и тест не проверял бы
            // жизненный цикл доставки целиком.
            Effect::SetTimer { token, .. } => {
                let owner = if from_first { &mut *a } else { &mut *b };
                let produced = owner.step(now_ms, Input::Timer { token }).expect("таймер доставки");
                queue.extend(produced.into_iter().map(|e| (from_first, e)));
            }
            Effect::Notify(event) => events.push(event),
            Effect::Connect { .. } | Effect::SetLanEnabled(_) | Effect::WatchLanPeers(_) => {}
        }
    }
    events
}

/// Знакомит два узла: каждый получает карточку другого как при встрече (§4.2).
fn introduce(a: &mut Node, b: &mut Node) {
    let a_card = a.own_card().encode().unwrap();
    let b_card = b.own_card().encode().unwrap();

    a.step(0, Input::Command(Command::AddContact { card_bytes: b_card, met_in_person: true }))
        .unwrap();
    b.step(0, Input::Command(Command::AddContact { card_bytes: a_card, met_in_person: true }))
        .unwrap();
}

fn send_text(node: &mut Node, peer: &Node, now_ms: u64, text: &str) -> Vec<Effect> {
    let chat = Engine::<MemoryStore>::chat_id_for(&peer.own_card().ik);
    node.step(now_ms, Input::Command(Command::SendText { chat, text: text.into() }))
        .expect("отправка текста")
}

fn inbox(node: &Node, peer: &Node) -> Vec<String> {
    let chat = Engine::<MemoryStore>::chat_id_for(&peer.own_card().ik);
    node.store()
        .messages(&chat, 100, None)
        .unwrap()
        .into_iter()
        .map(|m| String::from_utf8(m.body).unwrap())
        .collect()
}

#[test]
fn one_to_one_text_reaches_the_other_side() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "привет");
    let events = pump(&mut alice, &mut bob, 1_000, effects);

    assert!(
        events.iter().any(|e| matches!(e, Event::MessageReceived { .. })),
        "получатель не сообщил о приходе сообщения: {events:?}"
    );
    assert_eq!(inbox(&bob, &alice), vec!["привет".to_string()]);
}

#[test]
fn handshake_happens_once_and_carries_the_first_message() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    let events = pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(alice.session_count(), 1);
    assert_eq!(bob.session_count(), 1);
    assert_eq!(alice.awaiting_session(), 0, "сессия установлена — ждать больше нечего");
    assert_eq!(alice.queued(), 0, "очередь доставки должна опустеть");

    // §9.4: по прямому каналу отправитель узнаёт хотя бы «отправлено».
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::StatusChanged { status: ratatosk_proto::DeliveryStatus::Sent, .. }
        )),
        "статус доставки не дошёл до UI: {events:?}"
    );

    // Второе сообщение идёт по уже установленной сессии.
    let effects = send_text(&mut alice, &bob, 2_000, "второе");
    pump(&mut alice, &mut bob, 2_000, effects);
    assert_eq!(alice.session_count(), 1, "второй сессии быть не должно");
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "второе".to_string()]);
}

#[test]
fn both_directions_work_after_one_handshake() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "туда");
    pump(&mut alice, &mut bob, 1_000, effects);

    // Отвечает получатель — по той же сессии, встречной цепочкой (§8.3).
    let effects = send_text(&mut bob, &alice, 2_000, "обратно");
    let events = pump(&mut bob, &mut alice, 2_000, effects);

    assert!(events.iter().any(|e| matches!(e, Event::MessageReceived { .. })));
    assert_eq!(bob.session_count(), 1, "ответ не должен заводить вторую сессию");

    // Чат 1:1 держит обе стороны разговора: своё отправленное и чужое
    // принятое лежат в одном чате и упорядочены по HLC (§9.1).
    assert_eq!(inbox(&alice, &bob), vec!["туда".to_string(), "обратно".to_string()]);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let senders: Vec<[u8; 32]> = alice
        .store()
        .messages(&chat, 100, None)
        .unwrap()
        .into_iter()
        .map(|m| m.sender_ik)
        .collect();
    assert_eq!(
        senders,
        vec![alice.own_card().ik, bob.own_card().ik],
        "отправитель каждого сообщения должен сохраняться"
    );
}

#[test]
fn several_messages_keep_their_order() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    for (i, text) in ["раз", "два", "три", "четыре"].into_iter().enumerate() {
        let now = 1_000 + i as u64 * 100;
        let effects = send_text(&mut alice, &bob, now, text);
        pump(&mut alice, &mut bob, now, effects);
    }

    assert_eq!(inbox(&bob, &alice), vec!["раз", "два", "три", "четыре"]);
}

#[test]
fn the_sender_sees_its_own_message_immediately() {
    // §5.3: доставка может занять сутки почтового круга. В чате сообщение
    // обязано появиться сразу, а не после подтверждения.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    send_text(&mut alice, &bob, 1_000, "в очередь");
    assert_eq!(inbox(&alice, &bob), vec!["в очередь".to_string()]);
}

#[test]
fn the_responder_learns_the_contact_from_the_handshake() {
    // §8.2: в первом сообщении едет карточка. Получатель, не знавший
    // отправителя, узнаёт его — но контакт остаётся непроверенным (§4.2).
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));

    // Знает только Алиса: Боб карточку не получал.
    let b_card = bob.own_card().encode().unwrap();
    alice
        .step(0, Input::Command(Command::AddContact { card_bytes: b_card, met_in_person: true }))
        .unwrap();

    let effects = send_text(&mut alice, &bob, 1_000, "здравствуйте");
    let events = pump(&mut alice, &mut bob, 1_000, effects);

    let added = events
        .iter()
        .find_map(|e| match e {
            Event::ContactAdded { peer_ik, verified, .. } => Some((*peer_ik, *verified)),
            _ => None,
        })
        .expect("получатель должен был узнать контакт из рукопожатия");

    assert_eq!(added.0, alice.own_card().ik);
    assert!(!added.1, "карточка пришла по сети, а не из QR — контакт непроверен");
    assert_eq!(inbox(&bob, &alice), vec!["здравствуйте".to_string()]);
}

#[test]
fn a_duplicate_frame_is_delivered_once() {
    // §9.2: одно сообщение может законно прийти дважды разными транспортами.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Сначала рукопожатие — после него отправка даёт ровно один кадр,
    // и его легко предъявить дважды.
    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = send_text(&mut alice, &bob, 2_000, "однажды");
    let Some(Effect::Send { via, frame, .. }) = effects.into_iter().next() else {
        panic!("по установленной сессии ожидается ровно один кадр с данными");
    };

    bob.step(2_000, Input::Received { via, frame: frame.clone() }).unwrap();
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "однажды".to_string()]);

    // Тот же кадр повторно — дедупликация обязана его съесть.
    let repeated = bob.step(3_000, Input::Received { via, frame }).unwrap();
    assert!(
        !repeated.iter().any(|e| matches!(e, Effect::Notify(Event::MessageReceived { .. }))),
        "дубль не должен доходить до UI"
    );
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "однажды".to_string()]);
}

#[test]
fn a_corrupted_frame_is_dropped_without_effects() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "цел");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = send_text(&mut alice, &bob, 2_000, "битый");
    let Some(Effect::Send { via, mut frame, .. }) = effects.into_iter().next() else {
        panic!("ожидался кадр с данными");
    };
    let last = frame.len() - 1;
    frame[last] ^= 0xFF;

    let produced = bob.step(2_000, Input::Received { via, frame }).unwrap();
    assert!(produced.is_empty(), "битый кадр не должен порождать эффектов");
    assert_eq!(inbox(&bob, &alice), vec!["цел".to_string()]);
}

#[test]
fn sending_to_an_unknown_chat_is_an_error_not_a_panic() {
    let (mut alice, bob) = (node(1, "alice"), node(2, "bob"));
    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let result =
        alice.step(1_000, Input::Command(Command::SendText { chat, text: "кому?".into() }));
    assert!(result.is_err());
}
