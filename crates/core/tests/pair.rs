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

    // Исход обязан быть объявлен — и он «ждём»: у контакта есть адрес в
    // карточке, значит путь когда-нибудь может открыться. Ошибкой (`Undeliverable`)
    // это становится только когда ждать буквально нечего — ни включённой
    // локальной сети, ни адресов.
    assert!(
        statuses.contains(&ratatosk_proto::DeliveryStatus::Waiting),
        "молчание на единственном транспорте обязано быть объявлено: {statuses:?}"
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

    // Срок вышел, никто не отозвался: сообщение переходит в ожидание.
    let produced = alice.step(4_000, Input::Timer { token }).expect("таймер");
    assert!(
        produced.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::StatusChanged {
                status: ratatosk_proto::DeliveryStatus::Waiting,
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
                status: ratatosk_proto::DeliveryStatus::Waiting,
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

/// Годная аватарка минимального размера: сигнатура PNG и немного нулей.
fn avatar(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(&[tag; 32]);
    bytes
}

#[test]
fn an_avatar_reaches_a_verified_contact() {
    // §4.2, симметричное правило: аватарка уходит только сверенному контакту
    // и показывается только у сверенного. Проверяются оба конца сразу —
    // отправка и показ, — потому что порознь каждый выглядит работающим.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Сессия ставится обычным обменом: аватарка едет по ней, а не отдельно.
    let effects = send_text(&mut alice, &bob, 1_000, "привет");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects =
        alice.step(2_000, Input::Command(Command::SetAvatar(avatar(7)))).expect("аватарка принята");
    let events = pump(&mut alice, &mut bob, 2_000, effects);

    assert!(
        events.iter().any(|e| matches!(e, Event::AvatarChanged { .. })),
        "получатель не узнал о новой аватарке: {events:?}"
    );
    assert_eq!(
        bob.avatar_of(&alice.own_card().ik).unwrap(),
        Some(avatar(7)),
        "Боб сверил Алису при встрече — лицо обязано показаться"
    );

    // Снятие — такое же событие: иначе у собеседника навсегда осталось бы
    // прежнее лицо.
    let effects =
        alice.step(3_000, Input::Command(Command::SetAvatar(Vec::new()))).expect("снятие принято");
    let events = pump(&mut alice, &mut bob, 3_000, effects);
    assert!(events.iter().any(|e| matches!(e, Event::AvatarChanged { .. })));
    assert_eq!(bob.avatar_of(&alice.own_card().ik).unwrap(), None, "аватарку сняли");
}

#[test]
fn an_avatar_from_an_unverified_contact_is_kept_but_hidden() {
    // Сверка односторонняя: Алиса сверила Боба при встрече, Боб её — нет.
    // Она законно шлёт лицо, он законно его не показывает. Байты при этом
    // сохраняются: выбросив их, чат после сверки остался бы без картинки
    // до следующего рукопожатия, а оно переживает перезапуск (§8.3) и может
    // не случиться неделями.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));

    let b_card = bob.own_card().encode().unwrap();
    alice
        .step(0, Input::Command(Command::AddContact { card_bytes: b_card, met_in_person: true }))
        .unwrap();
    alice.step(500, Input::Command(Command::SetAvatar(avatar(4)))).unwrap();

    // Боб узнаёт Алису из рукопожатия (§8.2), то есть несверенной.
    let effects = send_text(&mut alice, &bob, 1_000, "привет");
    pump(&mut alice, &mut bob, 1_000, effects);

    let alice_ik = alice.own_card().ik;
    assert_eq!(bob.avatar_of(&alice_ik).unwrap(), None, "до сверки показывать нечего (§4.2)");

    // Сверили голосом — лицо появляется само, без единого нового кадра.
    bob.step(2_000, Input::Command(Command::MarkVerified { peer_ik: alice_ik })).unwrap();
    assert_eq!(
        bob.avatar_of(&alice_ik).unwrap(),
        Some(avatar(4)),
        "после сверки аватарка обязана найтись без нового рукопожатия"
    );
}

#[test]
fn an_unverified_contact_gets_no_avatar() {
    // Боб узнал Алису из рукопожатия (§8.2), то есть по сети, а не из QR, —
    // значит несверен. Своё лицо ему не отдают, и §4.2 здесь единственная
    // причина: до сверки он может быть не тем, за кого себя выдаёт.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));

    // Знает только Алиса, и Боба она **не** сверяла.
    let b_card = bob.own_card().encode().unwrap();
    alice
        .step(0, Input::Command(Command::AddContact { card_bytes: b_card, met_in_person: false }))
        .unwrap();

    let effects =
        alice.step(1_000, Input::Command(Command::SetAvatar(avatar(9)))).expect("аватарка принята");
    assert!(effects.is_empty(), "отправлять некому и незачем: {effects:?}");

    // Даже когда сессия появится, аватарка не поедет.
    let effects = send_text(&mut alice, &bob, 2_000, "здравствуйте");
    let events = pump(&mut alice, &mut bob, 2_000, effects);
    assert!(
        !events.iter().any(|e| matches!(e, Event::AvatarChanged { .. })),
        "несверенный контакт не должен был получить лицо: {events:?}"
    );
    assert_eq!(bob.avatar_of(&alice.own_card().ik).unwrap(), None);

    // А после сверки — поедет, и без нового рукопожатия.
    let effects = alice
        .step(3_000, Input::Command(Command::MarkVerified { peer_ik: bob.own_card().ik }))
        .expect("сверка принята");
    let events = pump(&mut alice, &mut bob, 3_000, effects);
    assert!(
        events.iter().any(|e| matches!(e, Event::AvatarChanged { .. })),
        "сверка обязана открыть контакту лицо: {events:?}"
    );
}

#[test]
fn a_bad_avatar_is_refused_before_it_is_stored() {
    let mut alice = node(1, "alice");
    // Не картинка: клиент обязан узнать об этом сразу, а не после того,
    // как собеседник молча ничего не покажет.
    assert!(alice.step(1_000, Input::Command(Command::SetAvatar(b"<svg/>".to_vec()))).is_err());
    assert_eq!(alice.own_avatar().unwrap(), None, "негодное не должно было лечь в хранилище");

    let mut huge = avatar(1);
    huge.resize(ratatosk_proto::MAX_AVATAR_BYTES + 1, 0);
    assert!(alice.step(1_000, Input::Command(Command::SetAvatar(huge))).is_err());

    // Пустые байты — законное значение: это «снять аватарку».
    assert!(alice.step(1_000, Input::Command(Command::SetAvatar(Vec::new()))).is_ok());
}

#[test]
fn revoking_verification_closes_both_ends_of_the_avatar_rule() {
    // §4.2 симметричен, поэтому и отзыв обязан быть симметричным: с этого
    // момента лицо ему не отправляется и его не показывается. Оба конца
    // читают один и тот же признак — тест держит их вместе.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "привет");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = alice.step(2_000, Input::Command(Command::SetAvatar(avatar(1)))).unwrap();
    pump(&mut alice, &mut bob, 2_000, effects);
    let alice_ik = alice.own_card().ik;
    assert_eq!(bob.avatar_of(&alice_ik).unwrap(), Some(avatar(1)));

    // Боб передумал доверять.
    let events = bob
        .step(3_000, Input::Command(Command::RevokeVerification { peer_ik: alice_ik }))
        .expect("отзыв принят");
    assert!(
        events.iter().any(|e| matches!(e, Effect::Notify(Event::ContactChanged { .. }))),
        "UI обязан узнать: контакт снова непроверенный"
    );
    assert!(!bob.contacts()[&alice_ik].verified);
    assert_eq!(bob.avatar_of(&alice_ik).unwrap(), None, "показ прекращается сразу");

    // И в другую сторону: Боб больше не отдаёт своё лицо Алисе.
    let effects = bob.step(4_000, Input::Command(Command::SetAvatar(avatar(2)))).unwrap();
    let events = pump(&mut bob, &mut alice, 4_000, effects);
    assert!(
        !events.iter().any(|e| matches!(e, Event::AvatarChanged { .. })),
        "несверенному лицо не отправляют: {events:?}"
    );

    // Сверили заново — прежняя аватарка находится, пересылать её не надо.
    bob.step(5_000, Input::Command(Command::MarkVerified { peer_ik: alice_ik })).unwrap();
    assert_eq!(
        bob.avatar_of(&alice_ik).unwrap(),
        Some(avatar(1)),
        "байты лежали всё это время — сверка их открывает"
    );
}

#[test]
fn a_local_name_is_mine_and_never_travels() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let bob_ik = bob.own_card().ik;

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SetLocalName {
                peer_ik: bob_ik,
                name: Some("  Боб с работы  ".to_owned()),
            }),
        )
        .expect("имя принято");

    // Ни одного кадра: подпись — своя пометка, а не сообщение собеседнику.
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "локальное имя не должно порождать трафика: {effects:?}"
    );
    assert_eq!(
        alice.contacts()[&bob_ik].local_name.as_deref(),
        Some("Боб с работы"),
        "пробелы по краям обрезаются"
    );

    // Пустая строка равносильна снятию.
    alice
        .step(
            2_000,
            Input::Command(Command::SetLocalName { peer_ik: bob_ik, name: Some("   ".to_owned()) }),
        )
        .unwrap();
    assert_eq!(alice.contacts()[&bob_ik].local_name, None);

    // Слишком длинное — отказ, а не молчаливое обрезание: человек написал
    // не то, что увидит, и лучше сказать ему об этом.
    let long = "я".repeat(ratatosk_core::MAX_LOCAL_NAME_CHARS + 1);
    assert!(alice
        .step(3_000, Input::Command(Command::SetLocalName { peer_ik: bob_ik, name: Some(long) }))
        .is_err());
}

#[test]
fn deleting_a_contact_takes_the_session_but_spares_history_when_asked() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let bob_ik = bob.own_card().ik;

    let effects = send_text(&mut alice, &bob, 1_000, "было дело");
    pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(alice.session_count(), 1);

    let effects = alice
        .step(
            2_000,
            Input::Command(Command::DeleteContact { peer_ik: bob_ik, purge_history: false }),
        )
        .expect("удаление принято");

    assert!(
        effects.iter().any(|e| matches!(e, Effect::Notify(Event::ContactRemoved { .. }))),
        "UI обязан узнать об удалении: {effects:?}"
    );
    assert!(alice.contacts().get(&bob_ik).is_none());
    assert_eq!(alice.session_count(), 0, "ключевой материал не переживает контакт");
    assert_eq!(inbox(&alice, &bob), vec!["было дело".to_string()], "переписку просили оставить");

    // Писать удалённому нельзя: чата больше нет, и это отказ, а не паника.
    let chat = Engine::<MemoryStore>::chat_id_for(&bob_ik);
    assert!(alice
        .step(3_000, Input::Command(Command::SendText { chat, text: "эй".into() }))
        .is_err());
}

#[test]
fn deleting_a_contact_with_history_leaves_nothing() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let bob_ik = bob.own_card().ik;

    let effects = send_text(&mut alice, &bob, 1_000, "и этого не было");
    pump(&mut alice, &mut bob, 1_000, effects);

    alice
        .step(
            2_000,
            Input::Command(Command::DeleteContact { peer_ik: bob_ik, purge_history: true }),
        )
        .expect("удаление принято");

    assert!(inbox(&alice, &bob).is_empty(), "просили удалить переписку — её нет");
}

#[test]
fn a_deleted_contact_can_come_back_unverified() {
    // §14: удаление — это «убрать у себя», а не «запретить писать». Тест
    // фиксирует ровно то, что клиент обязан сказать пользователю вслух.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let alice_ik = alice.own_card().ik;
    bob.step(
        1_000,
        Input::Command(Command::DeleteContact { peer_ik: alice_ik, purge_history: true }),
    )
    .unwrap();
    assert!(bob.contacts().get(&alice_ik).is_none());

    // Алиса пишет: карточка у неё осталась, и рукопожатие (§8.2) везёт
    // в себе её собственную — Боб узнаёт отправителя заново.
    let effects = send_text(&mut alice, &bob, 2_000, "я снова тут");
    let events = pump(&mut alice, &mut bob, 2_000, effects);

    let added = events
        .iter()
        .find_map(|e| match e {
            Event::ContactAdded { peer_ik, verified, .. } => Some((*peer_ik, *verified)),
            _ => None,
        })
        .expect("контакт обязан завестись заново");
    assert_eq!(added.0, alice_ik);
    assert!(!added.1, "и он непроверенный: прежняя сверка удалена вместе с контактом");
    assert_eq!(inbox(&bob, &alice), vec!["я снова тут".to_string()]);
}

/// Идентификаторы сообщений чата в порядке показа.
fn ids_in(node: &Node, peer: &Node) -> Vec<[u8; 16]> {
    let chat = Engine::<MemoryStore>::chat_id_for(&peer.own_card().ik);
    node.store().messages(&chat, 100, None).unwrap().into_iter().map(|m| m.msg_id).collect()
}

#[test]
fn deleting_a_message_is_local_and_silent() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);
    let effects = send_text(&mut alice, &bob, 2_000, "второе");
    pump(&mut alice, &mut bob, 2_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let first = ids_in(&alice, &bob)[0];

    let effects = alice
        .step(3_000, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![first] }))
        .expect("удаление принято");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "удаление у себя не должно порождать трафика: {effects:?}"
    );
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Notify(Event::MessagesDeleted { .. }))),
        "UI обязан узнать: {effects:?}"
    );
    assert_eq!(inbox(&alice, &bob), vec!["второе".to_string()]);
    assert_eq!(
        inbox(&bob, &alice),
        vec!["первое".to_string(), "второе".to_string()],
        "у него всё на месте"
    );
}

#[test]
fn a_retraction_removes_the_message_on_both_sides() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "зря я это написал");
    pump(&mut alice, &mut bob, 1_000, effects);
    let effects = send_text(&mut alice, &bob, 2_000, "а это нет");
    pump(&mut alice, &mut bob, 2_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let regret = ids_in(&alice, &bob)[0];

    let effects = alice
        .step(3_000, Input::Command(Command::RetractMessages { chat, msg_ids: vec![regret] }))
        .expect("отзыв принят");
    let events = pump(&mut alice, &mut bob, 3_000, effects);

    assert_eq!(inbox(&alice, &bob), vec!["а это нет".to_string()], "у себя исчезло сразу");
    assert_eq!(inbox(&bob, &alice), vec!["а это нет".to_string()], "и у собеседника тоже");
    assert!(
        events.iter().any(|e| matches!(e, Event::MessagesDeleted { .. })),
        "получатель обязан сказать своему UI, что сообщение исчезло: {events:?}"
    );
    assert_eq!(alice.queued(), 0, "квитанция закрыла запись в очереди — второй отправки не будет");
}

#[test]
fn a_retraction_carries_only_your_own_words() {
    // Главное свойство всего механизма: отозвать можно только своё. Проверка
    // стоит дважды — отправитель не кладёт чужое в просьбу, получатель не
    // принимает чужое в ней, — и здесь видно первую: список смешанный,
    // а исчезает у собеседника ровно одно сообщение.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "моё слово");
    pump(&mut alice, &mut bob, 1_000, effects);
    let effects = send_text(&mut bob, &alice, 2_000, "и моё");
    pump(&mut bob, &mut alice, 2_000, effects);

    // У Боба в чате оба сообщения; берём оба идентификатора и просим отозвать
    // их разом — то есть в том числе чужое.
    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let both: Vec<[u8; 16]> = bob
        .store()
        .messages(&chat_with_alice, 100, None)
        .unwrap()
        .iter()
        .map(|m| m.msg_id)
        .collect();
    assert_eq!(both.len(), 2);

    let effects = bob
        .step(
            3_000,
            Input::Command(Command::RetractMessages { chat: chat_with_alice, msg_ids: both }),
        )
        .expect("команда принимается");
    pump(&mut bob, &mut alice, 3_000, effects);

    assert_eq!(
        inbox(&alice, &bob),
        vec!["моё слово".to_string()],
        "у Алисы обязано исчезнуть только сообщение Боба, а её собственное — остаться"
    );
    // У себя Боб убрал оба: это его история, и распоряжается ей он.
    assert!(inbox(&bob, &alice).is_empty());
}

#[test]
fn clearing_a_chat_empties_it_locally() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    for (i, text) in ["раз", "два", "три"].into_iter().enumerate() {
        let now = 1_000 + i as u64 * 100;
        let effects = send_text(&mut alice, &bob, now, text);
        pump(&mut alice, &mut bob, now, effects);
    }

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let effects = alice.step(5_000, Input::Command(Command::ClearChat { chat })).expect("очистка");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "очистка — местное дело: {effects:?}"
    );
    assert!(inbox(&alice, &bob).is_empty());
    assert_eq!(inbox(&bob, &alice).len(), 3, "у собеседника переписка цела");

    // Повторная очистка пустого чата ничего не сообщает.
    assert!(alice.step(6_000, Input::Command(Command::ClearChat { chat })).unwrap().is_empty());
}

#[test]
fn a_deleted_message_does_not_come_back_with_a_late_copy() {
    // §9.2: одно сообщение законно приходит дважды разными транспортами.
    // Надгробие существует ровно затем, чтобы вторая копия не воскресила то,
    // что человек убрал.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Сначала рукопожатие — после него отправка даёт ровно один кадр данных.
    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = send_text(&mut alice, &bob, 2_000, "однажды");
    let Some(Effect::Send { via, frame, .. }) = effects.into_iter().next() else {
        panic!("по установленной сессии ожидается ровно один кадр с данными");
    };
    bob.step(2_000, Input::Received { via, frame: frame.clone() }).unwrap();

    let chat = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let victim = bob
        .store()
        .messages(&chat, 10, None)
        .unwrap()
        .into_iter()
        .find(|m| m.body == "однажды".as_bytes())
        .expect("сообщение пришло")
        .msg_id;

    bob.step(3_000, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![victim] }))
        .unwrap();
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string()]);

    // Тот же кадр приходит ещё раз — например, вторым транспортом.
    bob.step(4_000, Input::Received { via, frame }).unwrap();
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string()], "удалённое не должно воскресать");
}

#[test]
fn a_socket_drop_does_not_destroy_the_session() {
    // Разрыв соединения — событие сокета, а не сессии. Раньше здесь
    // закрывалась LAN-сессия, и это была та самая поломка: у нас её нет,
    // у собеседника есть, его кадры мы отбрасываем как неизвестные, он видит
    // «не доставлено» при живой связи. Лечилось только удалением контакта.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(alice.session_count(), 1);

    alice
        .step(
            2_000,
            Input::ConnectionLost {
                peer_ik: bob.own_card().ik,
                via: ratatosk_proto::Transport::Lan,
            },
        )
        .expect("разрыв не должен ронять ядро");
    assert_eq!(alice.session_count(), 1, "сессия обязана пережить разрыв сокета");

    // И разговор продолжается той же сессией, без нового рукопожатия.
    let effects = send_text(&mut alice, &bob, 3_000, "второе");
    pump(&mut alice, &mut bob, 3_000, effects);
    assert_eq!(alice.session_count(), 1, "второй сессии быть не должно");
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "второе".to_string()]);
}

#[test]
fn a_peer_that_forgot_our_session_gets_a_new_one() {
    // Воспроизведение той самой жалобы: «то ходят, то не ходят, а после
    // удаления и добавления контакта снова ходят». Состояния расходятся —
    // у собеседника сессии больше нет, у нас есть, — и без переустановки
    // сессии сообщения уходят в пустоту, сколько бы их ни было.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string()]);

    // Боб потерял состояние: переустановил клиент, потерял базу, открыл её
    // прежней сборкой. Личность та же, сессии нет.
    let mut bob = node(2, "bob");
    assert_eq!(bob.session_count(), 0);

    let effects = send_text(&mut alice, &bob, 2_000, "второе");
    pump(&mut alice, &mut bob, 2_000, effects);

    assert_eq!(
        inbox(&bob, &alice),
        vec!["второе".to_string()],
        "молчание в ответ на кадр обязано привести к новому рукопожатию, а не к тишине"
    );
    assert_eq!(alice.session_count(), 1, "прежняя сессия закрыта, новая одна");
}

#[test]
fn a_message_with_nobody_to_send_it_to_waits_instead_of_failing() {
    // Пока работает только локальная сеть, «собеседника нет в сети» — самый
    // частый исход отправки, а не поломка. Раньше он выглядел ошибкой
    // и сообщение выбрасывалось; теперь это пауза с обещанием, и обещание
    // исполняется, как только собеседник появляется.
    let mut alice = node(1, "alice");
    let peer_ik = lan_only_contact(&mut alice, 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let effects = alice
        .step(1_000, Input::Command(Command::SendText { chat, text: "в никуда".into() }))
        .expect("отправка принята");
    let token = effects
        .iter()
        .find_map(|e| match e {
            Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("сначала ждём обнаружение");

    // Срок вышел, никого нет.
    let produced = alice.step(4_000, Input::Timer { token }).expect("таймер");
    let statuses: Vec<_> = produced
        .iter()
        .filter_map(|e| match e {
            Effect::Notify(Event::StatusChanged { status, .. }) => Some(*status),
            _ => None,
        })
        .collect();
    assert!(
        statuses.contains(&ratatosk_proto::DeliveryStatus::Waiting),
        "«собеседник офлайн» — это ожидание, а не ошибка: {statuses:?}"
    );
    assert!(
        !statuses.contains(&ratatosk_proto::DeliveryStatus::Undeliverable),
        "пугать ошибкой там, где сообщение никуда не потерялось, нельзя: {statuses:?}"
    );

    // Собеседник объявился в эфире — сообщение обязано поехать само.
    let effects = alice.step(5_000, Input::SeenOnLan { peer_ik }).expect("маяк");
    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::Send { via: ratatosk_proto::Transport::Lan, .. })),
        "то, что ждало сети, должно уехать при её появлении: {effects:?}"
    );
}

#[test]
fn deleting_a_waiting_message_stops_it_from_ever_going_out() {
    // Худшее из возможных поведений: человек удалил сообщение, пока оно ждало
    // сети, а оно всё равно уехало, когда сеть появилась.
    let mut alice = node(1, "alice");
    let peer_ik = lan_only_contact(&mut alice, 9);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let effects = alice
        .step(1_000, Input::Command(Command::SendText { chat, text: "зря".into() }))
        .expect("отправка принята");
    let token = effects
        .iter()
        .find_map(|e| match e {
            Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .expect("срок обнаружения");
    alice.step(4_000, Input::Timer { token }).unwrap();

    let waiting = alice.store().messages(&chat, 10, None).unwrap()[0].msg_id;
    alice
        .step(5_000, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![waiting] }))
        .expect("удаление принято");

    let effects = alice.step(6_000, Input::SeenOnLan { peer_ik }).expect("маяк");
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "удалённое не должно уехать, даже если ждало сети: {effects:?}"
    );
}

#[test]
fn a_replayed_frame_is_refused_by_the_ratchet() {
    // Точный повтор кадра отбивается не окном дедупликации, а ретчетом: ключ
    // позиции израсходован и стёрт (§8.4), расшифровать нечем. Защита от
    // повтора поэтому не зависит ни от размера окна, ни от базы.
    //
    // Тест существует, чтобы не путать этот случай с дублем из §9.2. Дубль —
    // это **другой кадр с тем же `msg_id`**, и обращаются с ним иначе:
    // см. `a_duplicate_is_acknowledged_so_the_sender_stops_guessing`.
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

    let repeated = bob.step(3_000, Input::Received { via, frame }).unwrap();
    assert!(
        repeated.is_empty(),
        "израсходованный ключ означает, что кадр уже принят: {repeated:?}"
    );
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "однажды".to_string()]);
}

/// Отправка, у которой потерялась квитанция.
///
/// Получатель принимает сообщение и отвечает — но ответ до отправителя
/// не доносится, ровно как при обрыве связи или убитом процессе. Дальше
/// отправитель доходит до срока ожидания и берётся за дело сам.
///
/// Возвращает то, что он при этом выпустил: там и новое рукопожатие (молчание
/// закрывает сессию, §8.5), и та же самая посылка вторым заходом. Копия придёт
/// **новым кадром с тем же `msg_id`** — точный повтор кадра ретчет не принял бы
/// вовсе, и никакого дубля получатель бы не увидел.
fn send_and_lose_the_receipt(
    alice: &mut Node,
    bob: &mut Node,
    now_ms: u64,
    text: &str,
) -> Vec<Effect> {
    let (mut sent, mut deadline) = (None, None);
    for effect in send_text(alice, bob, now_ms, text) {
        match effect {
            Effect::Send { via, frame, .. } => sent = Some((via, frame)),
            Effect::SetTimer { token, .. } => deadline = Some(token),
            _ => {}
        }
    }
    let (via, frame) = sent.expect("по установленной сессии уходит один кадр с данными");

    let acked = bob.step(now_ms, Input::Received { via, frame }).expect("приём кадра");
    assert!(
        acked.iter().any(|e| matches!(e, Effect::Send { .. })),
        "получатель обязан подтвердить приём: {acked:?}"
    );

    // Квитанцию Алисе не отдаём — и она доходит до срока ожидания.
    alice
        .step(now_ms + 60_000, Input::Timer { token: deadline.expect("срок ожидания квитанции") })
        .expect("срок вышел")
}

#[test]
fn a_duplicate_is_acknowledged_so_the_sender_stops_guessing() {
    // Ровно тот случай, из-за которого у ожидавшего сообщения не появлялись
    // отчёты. Первая квитанция потерялась — отправитель считает, что не дошло,
    // и посылает заново. Раньше копия съедалась молча: получатель ничего
    // не отвечал, отправитель ничего не узнавал, и сообщение навсегда
    // оставалось «ждёт» у одного и прочитанным у другого.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Ставим сессию, чтобы дальше отправка давала ровно один кадр данных.
    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = send_and_lose_the_receipt(&mut alice, &mut bob, 2_000, "дважды");
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "дважды".to_string()]);

    // Провод снова целый: Алиса заново договаривается о сессии и посылает
    // то же сообщение. Боб обязан не показать его второй раз (§9.2) — и обязан
    // подтвердить.
    let events = pump(&mut alice, &mut bob, 62_000, effects);
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::StatusChanged { status: ratatosk_proto::DeliveryStatus::Delivered, .. }
        )),
        "квитанция на дубль обязана продвинуть статус — иначе отправитель \
         не узнает никогда: {events:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(e, Event::MessageReceived { .. })),
        "дубль не должен доходить до UI второй раз: {events:?}"
    );
    assert_eq!(inbox(&bob, &alice), vec!["первое".to_string(), "дважды".to_string()]);
}

#[test]
fn a_duplicate_of_something_already_read_is_acknowledged_as_read() {
    // Водяной знак прочтения (§9.4) не даёт отправить одну и ту же квитанцию
    // о прочтении дважды — значит, если первая потерялась, узнать о прочтении
    // отправитель может только из ответа на дубль. Отвечать «доставлено» там,
    // где человек уже прочитал, — занижать то, что мы знаем.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    let effects = send_and_lose_the_receipt(&mut alice, &mut bob, 2_000, "прочти");

    // Боб дочитал чат до конца. Эта квитанция тоже никуда не уходит: провода
    // между узлами сейчас нет.
    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let last = bob.store().messages(&chat_with_alice, 10, None).unwrap().pop().unwrap().msg_id;
    bob.step(2_500, Input::Command(Command::MarkRead { chat: chat_with_alice, up_to: last }))
        .expect("отметка о прочтении");

    // Копия приезжает уже после прочтения.
    let events = pump(&mut alice, &mut bob, 62_000, effects);
    let statuses: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::StatusChanged { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    assert!(
        statuses.contains(&ratatosk_proto::DeliveryStatus::Read),
        "получатель прочитал — так и надо отвечать: {statuses:?}"
    );
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

// --- правка, пересылка, реакции ------------------------------------------

/// Отметки «изменено» у всех сообщений чата, в порядке §9.1.
fn edit_marks(node: &Node, peer: &Node) -> Vec<Option<u64>> {
    let chat = Engine::<MemoryStore>::chat_id_for(&peer.own_card().ik);
    node.store().messages(&chat, 100, None).unwrap().into_iter().map(|m| m.edited_ms).collect()
}

/// Все кадры, которые узел просил отправить.
fn frames(effects: Vec<Effect>) -> Vec<(ratatosk_proto::Transport, Vec<u8>)> {
    effects
        .into_iter()
        .filter_map(|e| match e {
            Effect::Send { via, frame, .. } => Some((via, frame)),
            _ => None,
        })
        .collect()
}

#[test]
fn an_edit_replaces_the_text_on_both_sides_and_leaves_a_mark() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "прив");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let typo = ids_in(&alice, &bob)[0];
    let effects = alice
        .step(
            2_000,
            Input::Command(Command::EditMessage {
                chat, msg_id: typo, text: "привет".into()
            }),
        )
        .expect("правка своего сообщения принимается");
    let events = pump(&mut alice, &mut bob, 2_000, effects);

    assert_eq!(inbox(&alice, &bob), vec!["привет".to_string()], "у себя — сразу");
    assert_eq!(inbox(&bob, &alice), vec!["привет".to_string()], "и у собеседника");
    assert!(
        events.iter().any(|e| matches!(e, Event::MessageEdited { .. })),
        "UI обязан узнать о правке: {events:?}"
    );
    // Отметка — не украшение: прежнего текста нет ни у кого, и без неё
    // подмена слов в истории была бы молчаливой (§14).
    assert_eq!(edit_marks(&alice, &bob), vec![Some(2_000)], "у себя отметка обязательна");
    assert_eq!(edit_marks(&bob, &alice), vec![Some(2_000)], "и у собеседника тоже");
    assert_eq!(alice.queued(), 0, "квитанция закрыла запись: второй отправки не будет");
}

#[test]
fn only_your_own_words_can_be_edited() {
    // Первая из двух проверок: отправитель не выпускает просьбу править чужое.
    // Вторая живёт в `Engine::on_edit` — получатель отвергает такую просьбу,
    // даже если её всё-таки прислали.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "моё слово");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let hers = ids_in(&bob, &alice)[0];
    let refused = bob.step(
        2_000,
        Input::Command(Command::EditMessage {
            chat: chat_with_alice,
            msg_id: hers,
            text: "я этого не говорил".into(),
        }),
    );
    assert!(refused.is_err(), "переписать чужие слова нельзя даже у себя");
    assert_eq!(inbox(&bob, &alice), vec!["моё слово".to_string()]);
    assert_eq!(edit_marks(&bob, &alice), vec![None], "отметки о правке взяться неоткуда");
}

#[test]
fn an_empty_edit_is_not_a_quiet_deletion() {
    // «Заменить на ничего» — это удаление, и выглядеть оно должно удалением.
    // Приняв пустую правку, мы стёрли бы текст без всякой отметки.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "слово");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let msg_id = ids_in(&alice, &bob)[0];
    let refused = alice
        .step(2_000, Input::Command(Command::EditMessage { chat, msg_id, text: "   ".into() }));
    assert!(refused.is_err());
    assert_eq!(inbox(&alice, &bob), vec!["слово".to_string()]);
}

#[test]
fn the_edit_window_closes_after_a_week() {
    // Предел существует, чтобы правка не стала способом переписать давний
    // разговор. Граница включающая: ровно неделя — ещё можно.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "давнее");
    pump(&mut alice, &mut bob, 1_000, effects);
    let effects = send_text(&mut alice, &bob, 2_000, "второе давнее");
    pump(&mut alice, &mut bob, 2_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let ids = ids_in(&alice, &bob);
    let week = ratatosk_proto::MAX_EDIT_AGE_MS;

    let on_the_edge = alice.step(
        1_000 + week,
        Input::Command(Command::EditMessage { chat, msg_id: ids[0], text: "успел".into() }),
    );
    assert!(on_the_edge.is_ok(), "ровно на границе правка ещё принимается");

    let too_late = alice.step(
        2_001 + week,
        Input::Command(Command::EditMessage {
            chat, msg_id: ids[1], text: "не успел".into()
        }),
    );
    assert!(too_late.is_err(), "через неделю переписывать разговор уже нельзя");
}

#[test]
fn a_forwarded_message_arrives_marked_and_without_an_author() {
    // Пересылка — это своё новое сообщение с чужими словами. Пометка
    // обязательна, автора нет: подпись §6 при пересылке не сохраняется,
    // и имя рядом с текстом было бы утверждением, которое получатель
    // проверить не может.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);

    let effects = send_text(&mut bob, &alice, 1_000, "секрет");
    pump(&mut bob, &mut alice, 1_000, effects);

    let from_bob = ids_in(&alice, &bob)[0];
    let chat_with_carol = Engine::<MemoryStore>::chat_id_for(&carol.own_card().ik);
    let effects = alice
        .step(
            2_000,
            Input::Command(Command::ForwardMessages {
                chat: chat_with_carol,
                msg_ids: vec![from_bob],
            }),
        )
        .expect("пересылка принята");
    pump(&mut alice, &mut carol, 2_000, effects);

    assert_eq!(inbox(&carol, &alice), vec!["секрет".to_string()], "текст доехал");

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let received = carol.store().messages(&chat_with_alice, 10, None).unwrap();
    assert!(received[0].forwarded, "пометка «переслано» обязательна");
    assert_eq!(
        received[0].sender_ik,
        alice.own_card().ik,
        "отправитель — тот, кто переслал; про Боба у Кэрол нет ничего"
    );

    // И у себя: своя копия тоже помечена — иначе через месяц человек решит,
    // что это его слова.
    let mine = alice.store().messages(&chat_with_carol, 10, None).unwrap();
    assert!(mine[0].forwarded);
}

#[test]
fn a_reaction_reaches_the_other_side_and_can_be_taken_back() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "смешно");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let msg_id = ids_in(&bob, &alice)[0];

    let effects = bob
        .step(
            2_000,
            Input::Command(Command::SetReaction {
                chat: chat_with_alice,
                msg_id,
                emoji: "👍".into(),
            }),
        )
        .expect("реакция принята");
    let events = pump(&mut bob, &mut alice, 2_000, effects);
    assert!(
        events.iter().any(|e| matches!(e, Event::ReactionChanged { .. })),
        "UI обязан узнать о реакции: {events:?}"
    );

    let seen = alice.store().reactions(&msg_id).unwrap();
    assert_eq!(seen.len(), 1, "реакция обязана доехать");
    assert_eq!(seen[0].emoji, "👍");
    assert_eq!(seen[0].author_ik, bob.own_card().ik);

    // Снятие — такое же состояние, как и любое другое.
    let effects = bob
        .step(
            3_000,
            Input::Command(Command::SetReaction {
                chat: chat_with_alice,
                msg_id,
                emoji: String::new(),
            }),
        )
        .expect("снятие принято");
    pump(&mut bob, &mut alice, 3_000, effects);
    assert!(alice.store().reactions(&msg_id).unwrap().is_empty(), "снятое не показывается");
    assert!(bob.store().reactions(&msg_id).unwrap().is_empty(), "и у себя тоже");
}

#[test]
fn a_late_reaction_does_not_undo_a_newer_one() {
    // §9.2: порядок прихода не равен порядку событий. Боб поставил реакцию
    // и снял её, а кадры доехали наоборот. Победить обязано снятие — иначе
    // у собеседника висит то, что человек убрал.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "смешно");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let msg_id = ids_in(&bob, &alice)[0];

    let put = frames(
        bob.step(
            2_000,
            Input::Command(Command::SetReaction {
                chat: chat_with_alice,
                msg_id,
                emoji: "👍".into(),
            }),
        )
        .unwrap(),
    );
    let taken_back = frames(
        bob.step(
            3_000,
            Input::Command(Command::SetReaction {
                chat: chat_with_alice,
                msg_id,
                emoji: String::new(),
            }),
        )
        .unwrap(),
    );

    // Сначала снятие, потом постановка: кэш пропущенных ключей (§8.4)
    // позволяет принять кадры в обратном порядке.
    for (via, frame) in taken_back.into_iter().chain(put) {
        alice.step(4_000, Input::Received { via, frame }).expect("приём");
    }
    assert!(
        alice.store().reactions(&msg_id).unwrap().is_empty(),
        "запоздавшая реакция не должна воскресать: решает метка, а не порядок прихода"
    );
}

#[test]
fn a_reaction_cannot_smuggle_text() {
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "смешно");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let msg_id = ids_in(&bob, &alice)[0];
    let refused = bob.step(
        2_000,
        Input::Command(Command::SetReaction {
            chat: chat_with_alice,
            msg_id,
            emoji: "это не реакция, а сообщение".into(),
        }),
    );
    assert!(refused.is_err(), "реакция не должна быть способом прислать текст");
}

#[test]
fn deleting_a_message_takes_its_reactions_with_it() {
    // Реакция относилась к словам, которых больше нет. Оставить её значит
    // держать на экране пузырёк, привязанный к пустоте.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "смешно");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let msg_id = ids_in(&bob, &alice)[0];
    let effects = bob
        .step(
            2_000,
            Input::Command(Command::SetReaction {
                chat: chat_with_alice,
                msg_id,
                emoji: "👍".into(),
            }),
        )
        .unwrap();
    pump(&mut bob, &mut alice, 2_000, effects);
    assert_eq!(bob.store().reactions(&msg_id).unwrap().len(), 1);

    bob.step(
        3_000,
        Input::Command(Command::DeleteMessages { chat: chat_with_alice, msg_ids: vec![msg_id] }),
    )
    .unwrap();
    assert!(bob.store().reactions(&msg_id).unwrap().is_empty());
}

// --- ответы --------------------------------------------------------------

/// Ссылки «на что это ответ» у всех сообщений чата, в порядке §9.1.
fn reply_links(node: &Node, peer: &Node) -> Vec<Option<[u8; 16]>> {
    let chat = Engine::<MemoryStore>::chat_id_for(&peer.own_card().ik);
    node.store().messages(&chat, 100, None).unwrap().into_iter().map(|m| m.reply_to).collect()
}

#[test]
fn a_reply_carries_a_link_and_the_quote_stays_home() {
    // Главное свойство: по проводу едет ссылка, а не отрывок цитаты. Значит
    // в теле ответа — только слова отвечающего, а цитату каждая сторона берёт
    // из своей копии и подделать её не может.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "выходим в семь?");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let question = ids_in(&bob, &alice)[0];
    let effects = bob
        .step(
            2_000,
            Input::Command(Command::SendReply {
                chat: chat_with_alice,
                reply_to: question,
                text: "да, в семь".into(),
            }),
        )
        .expect("ответ принят");
    pump(&mut bob, &mut alice, 2_000, effects);

    assert_eq!(
        inbox(&alice, &bob),
        vec!["выходим в семь?".to_string(), "да, в семь".to_string()],
        "в теле ответа только его слова — цитаты в нём нет"
    );
    assert_eq!(
        reply_links(&alice, &bob),
        vec![None, Some(question)],
        "ссылка обязана доехать: по ней UI и рисует цитату, и прокручивает к ней"
    );
    // И у себя тоже: свой ответ помечен так же, как принятый.
    assert_eq!(reply_links(&bob, &alice), vec![None, Some(question)]);
}

#[test]
fn a_reply_outlives_the_message_it_answers() {
    // Ссылка мягкая: сообщение, на которое отвечали, может исчезнуть. Ответ
    // при этом остаётся — это слова человека, а цитата только контекст.
    // Показать «сообщение недоступно» — работа UI, и вот на чём она стоит.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "выходим в семь?");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat_with_alice = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    let question = ids_in(&bob, &alice)[0];
    let effects = bob
        .step(
            2_000,
            Input::Command(Command::SendReply {
                chat: chat_with_alice,
                reply_to: question,
                text: "да".into(),
            }),
        )
        .unwrap();
    pump(&mut bob, &mut alice, 2_000, effects);

    // Боб убирает у себя то, на что отвечал.
    bob.step(
        3_000,
        Input::Command(Command::DeleteMessages { chat: chat_with_alice, msg_ids: vec![question] }),
    )
    .unwrap();

    assert_eq!(inbox(&bob, &alice), vec!["да".to_string()], "ответ остался");
    assert_eq!(
        reply_links(&bob, &alice),
        vec![Some(question)],
        "ссылка осталась — и не разрешается: цитировать нечего, и это надо сказать"
    );
    assert!(
        bob.store().message(&question).unwrap().is_none(),
        "цель ссылки удалена — UI обязан показать «сообщение недоступно»"
    );
}

#[test]
fn a_reply_that_arrives_first_keeps_its_words() {
    // Перестановка (§9.2): ответ обогнал сообщение, на которое отвечает.
    // Терять из-за этого текст нельзя — ссылка сохраняется как есть и
    // разрешится сама, когда исходное сообщение доедет.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Сессию ставим первым сообщением, чтобы дальше кадры были одиночными.
    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    // Второе сообщение Бобу не доносим — придержим его кадр.
    let held = frames(send_text(&mut alice, &bob, 2_000, "важное"));
    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let important = *ids_in(&alice, &bob).last().unwrap();

    // Алиса отвечает на своё же сообщение — так и получается ссылка, которой
    // у получателя ещё нет.
    let effects = alice
        .step(
            3_000,
            Input::Command(Command::SendReply {
                chat,
                reply_to: important,
                text: "и вот почему".into(),
            }),
        )
        .expect("ответ на своё сообщение принимается");
    pump(&mut alice, &mut bob, 3_000, effects);

    assert_eq!(
        inbox(&bob, &alice),
        vec!["первое".to_string(), "и вот почему".to_string()],
        "ответ показан, хотя цитировать пока нечего"
    );
    assert_eq!(reply_links(&bob, &alice), vec![None, Some(important)]);
    assert!(bob.store().message(&important).unwrap().is_none(), "цели пока нет");

    // Придержанный кадр доезжает — и ссылка разрешается сама.
    for (via, frame) in held {
        bob.step(4_000, Input::Received { via, frame }).expect("приём");
    }
    assert!(
        bob.store().message(&important).unwrap().is_some(),
        "ссылка обязана разрешиться, как только сообщение доехало"
    );
}

#[test]
fn a_reply_cannot_point_into_another_chat() {
    // Ответ на сообщение чужого разговора и цитировать нечем, и рассказал бы
    // получателю об идентификаторе, которого он знать не должен. Проверка
    // стоит дважды; здесь видно первую — отправитель такого не выпускает.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);

    let effects = send_text(&mut alice, &bob, 1_000, "боб, привет");
    pump(&mut alice, &mut bob, 1_000, effects);
    let from_bobs_chat = ids_in(&alice, &bob)[0];

    let chat_with_carol = Engine::<MemoryStore>::chat_id_for(&carol.own_card().ik);
    let refused = alice.step(
        2_000,
        Input::Command(Command::SendReply {
            chat: chat_with_carol,
            reply_to: from_bobs_chat,
            text: "смотри что пишут".into(),
        }),
    );
    assert!(refused.is_err(), "цитата из другого разговора наружу не уходит");
}

#[test]
fn a_reply_without_words_is_refused() {
    // Ответ без текста — это ссылка, показать которую человеку нечем.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let effects = send_text(&mut alice, &bob, 1_000, "вопрос");
    pump(&mut alice, &mut bob, 1_000, effects);

    let chat = Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik);
    let question = ids_in(&alice, &bob)[0];
    let refused = alice.step(
        2_000,
        Input::Command(Command::SendReply { chat, reply_to: question, text: "   ".into() }),
    );
    assert!(refused.is_err());

    // И ссылка на то, чего в этом чате нет, — тоже отказ, а не тихая отправка
    // обычным сообщением: человек нажал «ответить» на что-то конкретное.
    let nowhere = alice.step(
        3_000,
        Input::Command(Command::SendReply {
            chat, reply_to: [42u8; 16], text: "куда-то".into()
        }),
    );
    assert!(nowhere.is_err());
}
