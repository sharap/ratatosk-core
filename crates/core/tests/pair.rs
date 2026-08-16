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

use std::collections::VecDeque;

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
    let mut queue: VecDeque<(bool, Effect)> = from_a.into_iter().map(|e| (true, e)).collect();
    // Сроки ожидания копятся отдельно и срабатывают только тогда, когда
    // провод затих. Порядок здесь не косметика: срок прямого канала означает
    // «квитанции нет, попытка не удалась» (§5.4, §9.4), а на мгновенном
    // проводе квитанция обязана приходить раньше срока. Сработай таймер
    // посреди обмена — тест проверял бы откат на следующий транспорт вместо
    // доставки. Оставшийся при затихшем проводе владелец у метки — это уже
    // настоящий провал, и его тест обязан увидеть.
    let mut timers: Vec<(bool, u64)> = Vec::new();

    let mut steps = 0;
    loop {
        while let Some((from_first, effect)) = queue.pop_front() {
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
                Effect::SetTimer { token, .. } => timers.push((from_first, token)),
                Effect::Notify(event) => events.push(event),
                Effect::Connect { .. }
                | Effect::SetLanEnabled(_)
                | Effect::WatchLanPeers(_)
                | Effect::RestartLan => {}
            }
        }

        let Some((owner_first, token)) = timers.pop() else { break };
        let owner = if owner_first { &mut *a } else { &mut *b };
        let produced = owner.step(now_ms, Input::Timer { token }).expect("таймер доставки");
        queue.extend(produced.into_iter().map(|e| (owner_first, e)));
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

    // §9.4: по прямому каналу «доставлено» объявляет получатель квитанцией,
    // а не отправитель по таймеру. Поэтому ждём именно `Delivered`: `Sent`
    // здесь означал бы, что статус выставил срок ожидания, то есть обещание
    // без подтверждения — ровно то, что запрещает §14.
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::StatusChanged { status: ratatosk_proto::DeliveryStatus::Delivered, .. }
        )),
        "квитанция о доставке не дошла до UI: {events:?}"
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
fn a_deadline_without_a_receipt_is_a_failure_not_a_success() {
    // Раньше срок ожидания прямого канала объявлял «отправлено». Это выглядело
    // безобидной неточностью индикатора, а было дырой в §5.4: попытка
    // закрывалась успехом, и откат на следующий транспорт не начинался.
    // Проверяем на контакте с одним только onion: откатываться некуда,
    // поэтому исход попытки виден сразу и не смешивается с почтой.
    let mut alice = node(1, "alice");

    let ghost = Identity::from_seed([9u8; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: ghost.public().ik,
        sk: ghost.public().sk,
        onion: "ghostwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww.onion".to_owned(),
        chatmail: String::new(),
        display_name: "призрак".to_owned(),
        version: 1,
    };
    let ghost_ik = card.ik;
    alice
        .step(
            0,
            Input::Command(Command::AddContact {
                card_bytes: card.encode().unwrap(),
                met_in_person: true,
            }),
        )
        .unwrap();

    let chat = Engine::<MemoryStore>::chat_id_for(&ghost_ik);
    let effects = alice
        .step(1_000, Input::Command(Command::SendText { chat, text: "в пустоту".into() }))
        .expect("отправка текста");

    let token = effects
        .iter()
        .find_map(|e| match e {
            Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("прямой канал обязан завести срок ожидания квитанции");
    assert!(
        !effects.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::StatusChanged {
                status: ratatosk_proto::DeliveryStatus::Sent,
                ..
            })
        )),
        "запись в сокет — не доставка: обещать «отправлено» до квитанции нельзя (§14)"
    );

    // Квитанции нет — срок вышел.
    let produced = alice.step(46_000, Input::Timer { token }).expect("таймер");
    let statuses: Vec<_> = produced
        .iter()
        .filter_map(|e| match e {
            Effect::Notify(Event::StatusChanged { status, .. }) => Some(*status),
            _ => None,
        })
        .collect();

    assert!(
        statuses.contains(&ratatosk_proto::DeliveryStatus::Undeliverable),
        "молчание на единственном транспорте обязано стать ошибкой: {statuses:?}"
    );
    assert!(
        !statuses.contains(&ratatosk_proto::DeliveryStatus::Sent),
        "срок ожидания не выдаёт успеха: {statuses:?}"
    );
}

/// Контакт, до которого можно добраться **только** по локальной сети.
///
/// Ни onion, ни почты: §5.4 тогда не на что откатываться, и видно ровно
/// поведение LAN, а не смешанный результат трёх транспортов.
fn lan_only_contact(node: &mut Node, seed: u8) -> [u8; 32] {
    let peer = Identity::from_seed([seed; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: peer.public().ik,
        sk: peer.public().sk,
        onion: String::new(),
        chatmail: String::new(),
        display_name: "сосед".to_owned(),
        version: 1,
    };
    let peer_ik = card.ik;
    node.step(0, Input::Command(Command::SetLanEnabled(true))).unwrap();
    node.step(
        0,
        Input::Command(Command::AddContact {
            card_bytes: card.encode().unwrap(),
            met_in_person: true,
        }),
    )
    .unwrap();
    peer_ik
}

#[test]
fn a_message_waits_for_discovery_instead_of_failing_instantly() {
    // Холодный старт: LAN включён, контакт есть, но маяка его устройства
    // мы ещё не слышали — обнаружение занимает сотни миллисекунд, а нажатие
    // «отправить» ждать не обязано. «Мы ещё не искали» — не то же самое,
    // что «мы искали и не нашли», и объявлять недоставленным здесь нельзя.
    let mut alice = node(1, "alice");
    let peer_ik = lan_only_contact(&mut alice, 9);

    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);
    let effects = alice
        .step(1_000, Input::Command(Command::SendText { chat, text: "ты тут?".into() }))
        .expect("отправка текста");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "адреса ещё нет — отправлять некуда: {effects:?}"
    );
    assert!(
        !effects.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::StatusChanged {
                status: ratatosk_proto::DeliveryStatus::Undeliverable,
                ..
            })
        )),
        "обнаружение ещё не отвечало — объявлять провал рано: {effects:?}"
    );
    assert!(
        effects.iter().any(|e| matches!(e, Effect::SetTimer { .. })),
        "ожидание обязано быть ограниченным по времени, иначе это зависание: {effects:?}"
    );

    // Маяк услышан — сообщение едет, не досиживая свой срок.
    let produced = alice.step(1_100, Input::SeenOnLan { peer_ik }).expect("маяк");
    assert!(
        produced
            .iter()
            .any(|e| matches!(e, Effect::Send { via: ratatosk_proto::Transport::Lan, .. })),
        "собеседник нашёлся, а сообщение не поехало: {produced:?}"
    );
}

#[test]
fn the_discovery_grace_is_spent_once_per_contact() {
    // Обратная сторона ожидания: собеседнику, которого в этой сети нет,
    // нельзя платить паузой перед каждым сообщением. Срок выдаётся один раз
    // за сеанс — дальше ответ «не слышно» уже получен.
    let mut alice = node(1, "alice");
    let peer_ik = lan_only_contact(&mut alice, 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let effects = alice
        .step(1_000, Input::Command(Command::SendText { chat, text: "первое".into() }))
        .expect("отправка текста");
    let token = effects
        .iter()
        .find_map(|e| match e {
            Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("первому сообщению полагается срок на обнаружение");

    // Срок вышел, никто не отозвался.
    let produced = alice.step(4_000, Input::Timer { token }).expect("таймер");
    assert!(
        produced.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::StatusChanged {
                status: ratatosk_proto::DeliveryStatus::Undeliverable,
                ..
            })
        )),
        "после срока исход обязан быть объявлен: {produced:?}"
    );

    // Второе сообщение ждать уже нечего.
    let effects = alice
        .step(5_000, Input::Command(Command::SendText { chat, text: "второе".into() }))
        .expect("отправка текста");
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::SetTimer { .. })),
        "второй раз ждать того же собеседника незачем: {effects:?}"
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::StatusChanged {
                status: ratatosk_proto::DeliveryStatus::Undeliverable,
                ..
            })
        )),
        "исход второго сообщения известен сразу: {effects:?}"
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
