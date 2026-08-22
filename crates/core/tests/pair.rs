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
use std::sync::{Arc, Mutex};

use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, SeededEntropy};
use ratatosk_crypto::Identity;
use ratatosk_store::{MemoryBlobs, MemoryStore, Store};

type Node = Engine<MemoryStore>;
/// Хранилище байтов, к которому есть доступ и у ядра, и у теста.
type Blobs = Arc<Mutex<MemoryBlobs>>;

fn node(seed: u8, name: &str) -> Node {
    node_with_blobs(seed, name).0
}

/// Узел вместе со ссылкой на его хранилище байтов.
///
/// Нужно там, где проверяются файлы: тесту приходится и положить исходный
/// файл «на диск» отправителю, и заглянуть в принятое у получателя.
fn node_with_blobs(seed: u8, name: &str) -> (Node, Blobs) {
    let identity = Identity::from_seed([seed; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция in-memory хранилища");

    let blobs: Blobs = Arc::new(Mutex::new(MemoryBlobs::new()));
    let engine = Engine::new(
        identity,
        store,
        Box::new(Arc::clone(&blobs)),
        Box::new(SeededEntropy::new(u64::from(seed))),
        SelfAddresses {
            onion: format!("{name}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"),
            chatmail: format!("{name}@nine.example"),
            display_name: name.to_owned(),
        },
    );
    (engine, blobs)
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

/// Все метки таймеров, которые узел просил поставить.
fn timers(effects: &[Effect]) -> Vec<u64> {
    effects
        .iter()
        .filter_map(|e| match e {
            Effect::SetTimer { token, .. } => Some(*token),
            _ => None,
        })
        .collect()
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

// --- файлы (§10) ---------------------------------------------------------

use ratatosk_core::OutgoingFile;
use ratatosk_proto::files;
// Здесь оно нужно поимённо: проверяется, **каким** транспортом уходит кадр,
// и `ratatosk_proto::Transport::Lan` внутри `matches!` читается уже плохо.
use ratatosk_proto::Transport;
// Под псевдонимом: имя `Blobs` в этом файле уже занято псевдонимом типа
// разделяемого хранилища, а трейт нужен ради `put_chunk` — тесты уборки
// кладут на «диск» то, чего ядро туда не клало.
use ratatosk_store::Blobs as BlobBytes;

/// Содержимое, которое узнаётся: каждый байт зависит от своего места.
fn payload_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Собирает файл из расшифрованных кусков — так же, как это делает клиент.
fn assembled(node: &Node, file_id: &[u8; 16]) -> Vec<u8> {
    let reader = node.open_file(file_id).unwrap().expect("файл известен");
    let mut whole = Vec::with_capacity(reader.size_bytes() as usize);
    for index in 0..reader.chunk_total() {
        let chunk = reader.chunk(index).unwrap().expect("кусок на месте");
        whole.extend_from_slice(&chunk);
    }
    whole
}

fn only_file(node: &Node, peer: &Node) -> [u8; 16] {
    let msg_id = *ids_in(node, peer).last().expect("сообщение с вложением");
    node.store().files_of(&msg_id).unwrap()[0].file_id
}

#[test]
fn a_file_travels_in_chunks_and_arrives_whole() {
    // Передача целиком: предложение, согласие по порогу, окно чанков,
    // подтверждения, сборка. Файл нарочно длиннее окна — иначе окно
    // не проверяется вовсе.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let mut bob = node(2, "bob");
    introduce(&mut alice, &mut bob);

    let content = payload_of(files::CHUNK_BYTES * 5 + 17);
    alice_blobs.lock().unwrap().seed("/tmp/otchet.pdf", content.clone());

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile {
                    path: "/tmp/otchet.pdf".into(),
                    preview: Some(vec![0x89, b'P', b'N', b'G']),
                }],
                text: "вот отчёт".into(),
            }),
        )
        .expect("отправка файла принята");

    // Порог автоприёма по умолчанию мал, поэтому Боб файл руками не принимает:
    // ставим ему порог заведомо больше файла.
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(Some(files::MAX_FILE_BYTES))))
        .unwrap();

    pump(&mut alice, &mut bob, 1_000, effects);

    assert_eq!(inbox(&bob, &alice), vec!["вот отчёт".to_string()], "подпись — обычное сообщение");
    let file_id = only_file(&bob, &alice);
    let received = bob.store().file(&file_id).unwrap().unwrap();
    assert_eq!(received.name, "otchet.pdf");
    assert_eq!(received.size_bytes, content.len() as u64);
    assert!(received.complete, "файл обязан собраться до конца");
    assert_eq!(received.preview.as_deref(), Some(&[0x89, b'P', b'N', b'G'][..]));
    assert_eq!(assembled(&bob, &file_id), content, "и совпасть с исходным до байта");
}

#[test]
fn a_direct_channel_is_never_a_switched_off_lan() {
    // Ошибка, из-за которой «сообщения через onion ходят, а файлы нет —
    // доезжает только сообщение с превью».
    //
    // Прямой канал (квитанции §9.4, аватарки §4.2, просьбы и чанки §10)
    // выбирается не очередью §5.4, а отдельно — и выбирался он раньше
    // перебором «есть ли сессия». Сессия же переживает выключение локальной
    // сети: она про ключи, а не про доступность. Поэтому после выключения
    // LAN у файлов оставался «прямой канал», которого нет, и просьба
    // о чанках уезжала в мёртвый транспорт — снова и снова, по сроку
    // молчания. Сообщения при этом ходили: очередь §5.4 про выключенный
    // LAN знает.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let (alice_ik, bob_ik) = (alice.own_card().ik, bob.own_card().ik);

    // Оба в общей сети: сессия установится по LAN — она первая ступень.
    alice.step(400, Input::Command(Command::SetLanEnabled(true))).unwrap();
    bob.step(400, Input::Command(Command::SetLanEnabled(true))).unwrap();
    alice.step(500, Input::SeenOnLan { peer_ik: bob_ik }).unwrap();
    bob.step(500, Input::SeenOnLan { peer_ik: alice_ik }).unwrap();

    let effects = send_text(&mut alice, &bob, 1_000, "по локальной сети");
    pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(inbox(&bob, &alice), vec!["по локальной сети".to_string()]);

    // Сеть выключили с обеих сторон. Сессия LAN осталась — и это правильно,
    // ключи никуда не делись. Но канала больше нет.
    alice.step(2_000, Input::Command(Command::SetLanEnabled(false))).unwrap();
    bob.step(2_000, Input::Command(Command::SetLanEnabled(false))).unwrap();

    let chat = Engine::<MemoryStore>::chat_id_for(&alice_ik);
    let last = bob.store().messages(&chat, 10, None).unwrap().pop().unwrap().msg_id;
    let effects = bob.step(2_100, Input::Command(Command::MarkRead { chat, up_to: last })).unwrap();
    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { via: Transport::Lan, .. })),
        "в выключенную сеть не отправляют ничего: {effects:?}"
    );

    // Onion-сессии ещё нет, поэтому квитанции сейчас ехать не на чем, и это
    // честный исход: она уедет, когда появится канал. Появляется он от первой
    // же переписки — §5.4 ведёт её на вторую ступень.
    let effects = send_text(&mut alice, &bob, 3_000, "теперь через onion");
    pump(&mut alice, &mut bob, 3_000, effects);
    assert_eq!(inbox(&bob, &alice).len(), 2, "второе сообщение приехало уже другим путём");

    // А вот теперь прямой канал есть — и он обязан быть тем самым, который
    // работает.
    let last = bob.store().messages(&chat, 10, None).unwrap().pop().unwrap().msg_id;
    let effects = bob.step(4_000, Input::Command(Command::MarkRead { chat, up_to: last })).unwrap();
    assert!(
        effects.iter().any(|e| matches!(e, Effect::Send { via: Transport::Onion, .. })),
        "прямой канал обязан найтись там, где он есть: {effects:?}"
    );
}

#[test]
fn a_file_over_the_threshold_waits_for_the_button() {
    // Чужой клиент не должен уметь занять память телефона, не спросив.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let mut bob = node(2, "bob");
    introduce(&mut alice, &mut bob);

    let content = payload_of(files::CHUNK_BYTES + 1);
    alice_blobs.lock().unwrap().seed("/tmp/video.mp4", content.clone());

    // «Спрашивать всегда» — законная настройка, а не отключённая функция.
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(None))).unwrap();

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: "/tmp/video.mp4".into(), preview: None }],
                text: String::new(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 1_000, effects);

    let file_id = only_file(&bob, &alice);
    let waiting = bob.store().file(&file_id).unwrap().unwrap();
    assert!(!waiting.accepted, "большой файл ждёт человека");
    assert!(!waiting.complete);
    assert_eq!(
        bob.store().received_chunks(&file_id).unwrap(),
        0,
        "пока не приняли — ни одного байта на диск"
    );

    // Человек нажал «принять» — и файл поехал.
    let effects = bob.step(2_000, Input::Command(Command::AcceptFile { file_id })).unwrap();
    pump(&mut bob, &mut alice, 2_000, effects);

    assert!(bob.store().file(&file_id).unwrap().unwrap().complete);
    assert_eq!(assembled(&bob, &file_id), content);
}

#[test]
fn a_declined_file_leaves_nothing_behind() {
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);

    alice_blobs.lock().unwrap().seed("/tmp/nenuzhno.bin", payload_of(files::CHUNK_BYTES / 2));
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(None))).unwrap();

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: "/tmp/nenuzhno.bin".into(), preview: None }],
                text: String::new(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 1_000, effects);

    let file_id = only_file(&bob, &alice);
    bob.step(2_000, Input::Command(Command::DeclineFile { file_id })).unwrap();

    assert!(bob.store().file(&file_id).unwrap().is_none(), "запись ушла");
    assert_eq!(bob_blobs.lock().unwrap().chunk_count(), 0, "и байты тоже");
    // Сообщение с подписью при этом остаётся: отказ — про вложение, а не про
    // слова собеседника.
    assert_eq!(ids_in(&bob, &alice).len(), 1);
}

#[test]
fn several_files_ride_on_one_message() {
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let mut bob = node(2, "bob");
    introduce(&mut alice, &mut bob);

    let first = payload_of(1_000);
    let second = payload_of(2_000);
    {
        let mut seeded = alice_blobs.lock().unwrap();
        seeded.seed("/tmp/a.jpg", first.clone());
        seeded.seed("/tmp/b.jpg", second.clone());
    }

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![
                    OutgoingFile { path: "/tmp/a.jpg".into(), preview: None },
                    OutgoingFile { path: "/tmp/b.jpg".into(), preview: None },
                ],
                text: "с прогулки".into(),
            }),
        )
        .expect("несколько вложений — обычный случай");
    pump(&mut alice, &mut bob, 1_000, effects);

    let msg_id = *ids_in(&bob, &alice).last().unwrap();
    let files = bob.store().files_of(&msg_id).unwrap();
    assert_eq!(files.len(), 2, "оба вложения на месте");
    for file in files {
        assert!(file.complete);
        let content = assembled(&bob, &file.file_id);
        assert!(content == first || content == second);
    }
}

#[test]
fn a_broken_transfer_resumes_where_it_stopped() {
    // §10.2: возобновление по индексу чанка. Связь рвётся посреди передачи;
    // возобновляет её **получатель** — у него есть всё, чтобы спросить заново,
    // а у отправителя своего состояния передачи нет вовсе.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let mut bob = node(2, "bob");
    introduce(&mut alice, &mut bob);
    // Сессию ставим заранее: иначе первые кадры будут рукопожатием, и тест
    // проверял бы §8.2 вместо §10.
    let hello = send_text(&mut alice, &bob, 800, "сейчас пришлю");
    pump(&mut alice, &mut bob, 800, hello);

    let content = payload_of(files::CHUNK_BYTES * 3 + 7);
    alice_blobs.lock().unwrap().seed("/tmp/dolgij.bin", content.clone());
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(Some(files::MAX_FILE_BYTES))))
        .unwrap();

    // Предложение доносим до Боба и забираем то, что он ответил: квитанцию
    // и просьбу о первом чанке.
    let offer = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: "/tmp/dolgij.bin".into(), preview: None }],
                text: String::new(),
            }),
        )
        .unwrap();
    let mut answer = Vec::new();
    for (via, frame) in frames(offer) {
        answer.extend(frames(bob.step(1_000, Input::Received { via, frame }).unwrap()));
    }
    assert!(!answer.is_empty(), "получатель обязан попросить первый чанк");

    // Ответ доезжает, чанки идут — но до Боба добирается только первый.
    let mut chunks = Vec::new();
    for (via, frame) in answer {
        chunks.extend(frames(alice.step(1_100, Input::Received { via, frame }).unwrap()));
    }
    assert!(chunks.len() > 1, "окно шлёт несколько чанков вперёд: {}", chunks.len());
    let first = chunks.remove(0);
    let after_chunk = bob.step(1_200, Input::Received { via: first.0, frame: first.1 }).unwrap();
    assert_eq!(bob.store().received_chunks(&only_file(&bob, &alice)).unwrap(), 1);

    // Дальше тишина — и её сторожит срок.
    let token = timers(&after_chunk).first().copied().expect("после чанка ставится срок молчания");
    let retry = bob.step(20_000, Input::Timer { token }).expect("срок молчания вышел");
    assert!(!frames(retry.clone()).is_empty(), "по сроку уходит новая просьба");

    // Провод снова цел: остаток доезжает сам.
    let events = pump(&mut bob, &mut alice, 20_000, retry);
    assert!(
        events.iter().any(|e| matches!(e, Event::FileProgress { .. })),
        "ход передачи обязан быть виден: {events:?}"
    );

    let file_id = only_file(&bob, &alice);
    assert!(bob.store().file(&file_id).unwrap().unwrap().complete, "файл дособрался");
    assert_eq!(assembled(&bob, &file_id), content, "и совпал с исходным до байта");
}

#[test]
fn a_file_that_vanished_stops_the_transfer_out_loud() {
    // Ядро не копирует файл при отправке — читает его с диска. Значит,
    // исчезнувший исходник останавливает передачу, и молчать об этом нельзя.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let mut bob = node(2, "bob");
    introduce(&mut alice, &mut bob);
    let hello = send_text(&mut alice, &bob, 800, "сейчас пришлю");
    pump(&mut alice, &mut bob, 800, hello);

    alice_blobs.lock().unwrap().seed("/tmp/propal.bin", payload_of(files::CHUNK_BYTES + 5));
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(Some(files::MAX_FILE_BYTES))))
        .unwrap();

    let offer = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: "/tmp/propal.bin".into(), preview: None }],
                text: String::new(),
            }),
        )
        .unwrap();
    let mut answer = Vec::new();
    for (via, frame) in frames(offer) {
        answer.extend(frames(bob.step(1_000, Input::Received { via, frame }).unwrap()));
    }

    // Файл исчез между предложением и первым чанком.
    alice_blobs.lock().unwrap().forget("/tmp/propal.bin");

    let mut said = Vec::new();
    for (via, frame) in answer {
        said.extend(alice.step(1_100, Input::Received { via, frame }).unwrap());
    }
    assert!(
        said.iter().any(|e| matches!(e, Effect::Notify(Event::HonestNotice { .. }))),
        "человек обязан узнать, что передача встала: {said:?}"
    );
    assert!(
        !said.iter().any(|e| matches!(e, Effect::Send { .. })),
        "и ни одного чанка не уходит: читать нечего"
    );
}

/// Принимает файл целиком и возвращает его идентификатор.
///
/// Ровно то же, что делают тесты передачи, — вынесено, чтобы тесты уборки
/// говорили про уборку, а не про §10.2 в третий раз.
fn receive_a_file(
    alice: &mut Node,
    alice_blobs: &Blobs,
    bob: &mut Node,
    path: &str,
    bytes: usize,
) -> [u8; 16] {
    let content = payload_of(bytes);
    alice_blobs.lock().unwrap().seed(path, content);
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(Some(files::MAX_FILE_BYTES))))
        .unwrap();

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: path.into(), preview: None }],
                text: String::new(),
            }),
        )
        .expect("отправка принята");
    pump(alice, bob, 1_000, effects);

    let file_id = only_file(bob, alice);
    assert!(bob.store().file(&file_id).unwrap().unwrap().complete, "файл обязан собраться");
    file_id
}

#[test]
fn deleting_a_contact_with_the_history_frees_the_disk_too() {
    // Байты вложений лежат не в базе, а рядом с ней, и каскад внешних ключей
    // до них не достаёт. Пока эти строки не появились, удаление контакта
    // с перепиской на гигабайт освобождало ноль байт: записи исчезали,
    // каталоги с чанками оставались навсегда.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);

    let file_id = receive_a_file(&mut alice, &alice_blobs, &mut bob, "/tmp/arhiv.zip", 5_000);
    assert!(bob_blobs.lock().unwrap().chunk_count() > 0, "чанки лежат на диске");

    let alice_ik = alice.own_card().ik;
    bob.step(
        2_000,
        Input::Command(Command::DeleteContact { peer_ik: alice_ik, purge_history: true }),
    )
    .expect("удаление принято");

    assert!(bob.store().file(&file_id).unwrap().is_none(), "запись о файле ушла с перепиской");
    assert_eq!(
        bob_blobs.lock().unwrap().chunk_count(),
        0,
        "и байты тоже: иначе место не освободится никогда"
    );
}

#[test]
fn the_sweep_takes_the_orphans_and_leaves_the_living() {
    // Уборка сверяет диск с базой и стирает лишнее. Проверяется вместе
    // с обратным: живое вложение и незаконченный приём она трогать не вправе.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);

    let file_id = receive_a_file(&mut alice, &alice_blobs, &mut bob, "/tmp/foto.jpg", 4_000);
    let alive = bob_blobs.lock().unwrap().chunk_count();
    assert!(alive > 0);

    // Сирота — каталог, о котором в базе нет ни строчки. Так выглядит
    // вложение, пережившее удаление переписки на прежней версии.
    bob_blobs.lock().unwrap().put_chunk(&[0xEEu8; 16], 0, b"sirota").unwrap();
    // Обрывок — чанк живого файла, не отмеченный принятым. Так выглядит
    // след процесса, убитого системой между записью байтов и отметкой.
    bob_blobs.lock().unwrap().put_chunk(&file_id, 999, b"obryvok").unwrap();

    let swept = bob.sweep_orphan_files().expect("уборка прошла");
    assert_eq!(swept.files, 1, "сирота обязан уйти целиком");
    assert_eq!(swept.chunks, 1, "и обрывок тоже");
    assert_eq!(swept.bytes, (b"sirota".len() + b"obryvok".len()) as u64);

    assert_eq!(
        bob_blobs.lock().unwrap().chunk_count(),
        alive,
        "а живое вложение обязано остаться нетронутым"
    );
    assert!(bob.store().file(&file_id).unwrap().unwrap().complete);

    // Второй прогон ничего не находит: уборка идемпотентна, иначе на неё
    // нельзя повесить кнопку.
    assert_eq!(bob.sweep_orphan_files().unwrap(), ratatosk_core::Swept::default());
}

#[test]
fn the_sweep_does_not_touch_a_transfer_in_progress() {
    // Незаконченный приём — не мусор: запись о нём в базе есть, и продолжится
    // он с той дырки, которой не хватает (§10.2). Уборка, принявшая его
    // за мусор, стёрла бы половину принятого и заставила качать заново.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);
    let hello = send_text(&mut alice, &bob, 800, "сейчас пришлю");
    pump(&mut alice, &mut bob, 800, hello);

    alice_blobs.lock().unwrap().seed("/tmp/kino.mkv", payload_of(files::CHUNK_BYTES * 3 + 7));
    bob.step(900, Input::Command(Command::SetAutoAcceptBytes(Some(files::MAX_FILE_BYTES))))
        .unwrap();

    let offer = alice
        .step(
            1_000,
            Input::Command(Command::SendFiles {
                chat: Engine::<MemoryStore>::chat_id_for(&bob.own_card().ik),
                files: vec![OutgoingFile { path: "/tmp/kino.mkv".into(), preview: None }],
                text: String::new(),
            }),
        )
        .unwrap();

    // Доводим передачу до середины и останавливаем.
    let mut answer = Vec::new();
    for (via, frame) in frames(offer) {
        answer.extend(frames(bob.step(1_000, Input::Received { via, frame }).unwrap()));
    }
    let mut chunks = Vec::new();
    for (via, frame) in answer {
        chunks.extend(frames(alice.step(1_100, Input::Received { via, frame }).unwrap()));
    }
    let first = chunks.remove(0);
    bob.step(1_200, Input::Received { via: first.0, frame: first.1 }).unwrap();

    let half = bob_blobs.lock().unwrap().chunk_count();
    assert!(half > 0, "часть файла уже на диске");

    let swept = bob.sweep_orphan_files().expect("уборка прошла");
    assert_eq!(swept, ratatosk_core::Swept::default(), "у незаконченного приёма убирать нечего");
    assert_eq!(bob_blobs.lock().unwrap().chunk_count(), half, "принятое осталось на месте");
}

#[test]
fn a_reader_outlives_the_core_and_reads_beside_it() {
    // Ради этого читатель и заведён. Раньше каждый кусок был заходом в очередь
    // драйвера, и открытие вложения на полгигабайта занимало ядро на всё время
    // расшифровки: сообщения в это время не уходили. Проверяется двумя
    // утверждениями. Первое: читателю ядро больше не нужно — он читает,
    // не касаясь `Engine`. Второе: пока он открыт, ядро продолжает работать.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, _bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);

    let content = payload_of(files::CHUNK_BYTES * 2 + 11);
    let file_id =
        receive_a_file(&mut alice, &alice_blobs, &mut bob, "/tmp/albom.zip", content.len());

    let reader = bob.open_file(&file_id).unwrap().expect("вложение открылось");
    assert_eq!(reader.chunk_total(), files::chunk_count(content.len() as u64));
    assert!(!reader.own(), "принятое вложение — не своё");

    // Читаем первый кусок, потом даём ядру поработать, потом дочитываем.
    // Если бы чтение шло через ядро, так переставить их было бы нельзя вовсе.
    let mut whole = reader.chunk(0).unwrap().expect("первый кусок");

    let while_reading = send_text(&mut bob, &alice, 3_000, "смотрю альбом");
    assert!(
        !frames(while_reading.clone()).is_empty(),
        "ядро обязано отправлять сообщения, пока открыто вложение"
    );
    pump(&mut bob, &mut alice, 3_000, while_reading);
    assert!(
        inbox(&alice, &bob).contains(&"смотрю альбом".to_owned()),
        "и они обязаны доходить, а не ждать конца чтения"
    );

    for index in 1..reader.chunk_total() {
        whole.extend_from_slice(&reader.chunk(index).unwrap().expect("кусок на месте"));
    }
    assert_eq!(whole, payload_of(content.len()), "и файл собрался до байта");

    // За концом файла показывать нечего, и это не отказ.
    assert!(reader.chunk(reader.chunk_total()).unwrap().is_none());
}

#[test]
fn a_sent_attachment_opens_from_its_source() {
    // Своё вложение через ядро не открывалось вовсе: запечатанных чанков
    // у отправителя нет — он читает исходник с диска, ничего не копируя.
    // Читатель обязан уметь и это, иначе человек не может открыть то,
    // что сам же и отправил.
    let (mut alice, alice_blobs) = node_with_blobs(1, "alice");
    let (mut bob, _bob_blobs) = node_with_blobs(2, "bob");
    introduce(&mut alice, &mut bob);

    let content = payload_of(files::CHUNK_BYTES + 5);
    let file_id = receive_a_file(&mut alice, &alice_blobs, &mut bob, "/tmp/moe.bin", content.len());

    // У Алисы файл тот же, но запись своя: идентификатор общий, источник — путь.
    let reader = alice.open_file(&file_id).unwrap().expect("своё вложение открылось");
    assert!(reader.own(), "это отправленный нами файл");
    assert_eq!(assembled(&alice, &file_id), content, "и читается до байта");

    // Исходник — не копия: удалили его, и открывать стало нечего. Молчать
    // об этом нельзя, поэтому здесь честный отказ, а не пустой кусок.
    alice_blobs.lock().unwrap().forget("/tmp/moe.bin");
    assert!(
        reader.chunk(0).is_err(),
        "исчезнувший исходник обязан отличаться от «показать нечего»"
    );
}

#[test]
fn the_cleanup_runs_by_itself_and_not_on_every_step() {
    // §12: «Compaction обязателен с первого дня. Иначе клиент перестанет
    // открываться на третий год.» Написан он был целиком, а запускался
    // только тестами — то есть не запускался. Проверяется и то, что теперь
    // запускается, и то, что не на каждом шаге: уборка на каждое сообщение
    // была бы своей поломкой.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let effects = send_text(&mut alice, &bob, 1_000, "первое");
    pump(&mut alice, &mut bob, 1_000, effects);

    // Пары сообщений мало, шести часов ещё не прошло — прибираться не время.
    assert_eq!(bob.compact_if_due(1_000).unwrap(), 0, "уборка не бежит на каждом шаге");

    // А через интервал — время. Убрать может быть и нечего; проверяется, что
    // отметка поставлена, то есть проход состоялся.
    let interval = ratatosk_store::Schedule::default().min_interval_ms;
    bob.compact_if_due(interval).expect("уборка прошла");
    assert!(
        bob.store().meta(ratatosk_store::META_LAST_COMPACTION).unwrap().is_some(),
        "проход обязан оставить отметку — иначе интервал не с чем сравнивать"
    );

    // И сразу второй раз не бежит: интервал считается от прошлого прохода.
    assert_eq!(bob.compact_if_due(interval).unwrap(), 0, "дважды подряд прибираться незачем");
}

#[test]
fn search_finds_whole_words_across_the_history() {
    // Правила поиска у обеих реализаций хранилища обязаны совпасть: в файловой
    // базе ищет индекс по хэшам слов, здесь — обход, а отвечать они должны
    // одинаково. Разойдись они — симуляция (§16) проверяла бы не тот поиск,
    // который поедет на телефон.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    for (at, text) in [(1_000, "привет, как дела"), (2_000, "дела идут"), (3_000, "про другое")]
    {
        let effects = send_text(&mut alice, &bob, at, text);
        pump(&mut alice, &mut bob, at, effects);
    }

    let found = |query: &str| {
        bob.store()
            .search(None, query, 10)
            .unwrap()
            .into_iter()
            .filter_map(|id| bob.store().message(&id).unwrap())
            .map(|m| String::from_utf8(m.body).unwrap())
            .collect::<Vec<_>>()
    };

    assert_eq!(found("дела"), vec!["дела идут".to_owned(), "привет, как дела".to_owned()]);
    assert_eq!(found("ДЕЛА").len(), 2, "регистр запроса значения не имеет");
    assert_eq!(found("дела привет"), vec!["привет, как дела".to_owned()], "нужны все слова");
    assert!(found("прив").is_empty(), "по началу слова не ищется, и это не недоделка");
    assert!(found("").is_empty(), "пустой запрос — пустой ответ, а не вся история");
}

// --- поделиться контактом (§4.1, дополнение) ------------------------------

/// Отправляет карточку и доводит её до собеседника. Возвращает `msg_id`
/// сообщения у получателя.
fn share(from: &mut Node, to: &mut Node, now_ms: u64, whose: [u8; 32]) -> [u8; 16] {
    let chat = Engine::<MemoryStore>::chat_id_for(&to.own_card().ik);
    let effects = from
        .step(now_ms, Input::Command(Command::ShareContact { chat, peer_ik: whose }))
        .expect("карточка принята к отправке");
    pump(from, to, now_ms, effects);

    let mine = Engine::<MemoryStore>::chat_id_for(&from.own_card().ik);
    let received = to.store().messages(&mine, 20, None).unwrap();
    received
        .iter()
        .rev()
        .find(|m| to.store().contact_share_of(&m.msg_id).unwrap().is_some())
        .expect("карточка легла в историю")
        .msg_id
}

#[test]
fn a_shared_contact_arrives_unverified_even_from_a_verified_friend() {
    // Главное свойство всей функции. Алиса сверила Кэрол голосом, но Бобу
    // от этого не легче: он не слышал Кэрол и проверить карточку не может.
    // Доверие не транзитивно (§4.2), и подпись бы не помогла — у карточки
    // её нет и не бывает.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);

    let carol_ik = carol.own_card().ik;
    assert!(alice.contacts().get(&carol_ik).unwrap().verified, "у Алисы Кэрол сверена");

    let msg_id = share(&mut alice, &mut bob, 1_000, carol_ik);

    // Само по себе сообщение ничего не добавило.
    assert!(bob.contacts().get(&carol_ik).is_none(), "приход карточки не добавляет контакт");

    bob.step(2_000, Input::Command(Command::AddSharedContact { msg_id })).expect("добавление");
    let added = bob.contacts().get(&carol_ik).expect("после нажатия контакт есть");
    assert!(!added.verified, "присланный контакт непроверен всегда — даже от сверенного друга");
    assert_eq!(added.card.display_name, "carol", "имя берётся из карточки");
}

#[test]
fn a_shared_card_never_touches_a_contact_we_already_have() {
    // Иначе кто угодно пришлёт «карточку версии 99» со своим адресом
    // и уведёт маршрут на себя. Адреса меняет только подписанное обновление
    // от самого владельца (§4.3).
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);
    introduce(&mut bob, &mut carol);

    let carol_ik = carol.own_card().ik;
    let before = bob.contacts().get(&carol_ik).expect("Боб уже знает Кэрол").clone();
    assert!(before.verified, "и знает сверенной");

    // Алиса делится настоящей Кэрол — даже честная карточка ничего не меняет.
    //
    // Подсунуть Бобу «Кэрол» с чужими ключами этим тестом не получится:
    // ядро отправляет то, что лежит в его собственном хранилище, а лгущего
    // собеседника через `--test pair` не собрать. Та же оговорка, что
    // у отзыва и правки.
    let msg_id = share(&mut alice, &mut bob, 2_000, carol_ik);
    bob.step(3_000, Input::Command(Command::AddSharedContact { msg_id })).unwrap();

    let after = bob.contacts().get(&carol_ik).expect("Кэрол на месте");
    assert!(after.verified, "сверка не сброшена");
    assert_eq!(after.card, before.card, "карточка известного контакта не тронута");
}

#[test]
fn sharing_your_own_card_is_the_same_operation() {
    // «Перешли мою визитку другу» — частый случай, и отдельного механизма
    // ему не нужно.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    let alice_ik = alice.own_card().ik;
    let msg_id = share(&mut alice, &mut bob, 1_000, alice_ik);
    let share_record = bob.store().contact_share_of(&msg_id).unwrap().expect("карточка на месте");
    assert_eq!(share_record.ik, alice_ik);

    // Боб уже знает Алису — нажатие ничего не меняет и не ломает.
    bob.step(2_000, Input::Command(Command::AddSharedContact { msg_id })).unwrap();
    assert!(bob.contacts().get(&alice_ik).unwrap().verified, "сверка Алисы не сброшена");
}

#[test]
fn the_local_name_stays_home() {
    // Локальное имя — заметка о своём отношении, а не свойство контакта,
    // и «по проводу не едет никогда» (§4.1). Проверяется именно здесь:
    // поделиться контактом — единственное место, где чужая карточка
    // покидает устройство.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);

    let carol_ik = carol.own_card().ik;
    alice
        .step(
            500,
            Input::Command(Command::SetLocalName {
                peer_ik: carol_ik,
                name: Some("Кэрол с работы".into()),
            }),
        )
        .unwrap();

    let msg_id = share(&mut alice, &mut bob, 1_000, carol_ik);
    let share_record = bob.store().contact_share_of(&msg_id).unwrap().unwrap();
    let text = String::from_utf8_lossy(&share_record.card_bytes).into_owned();
    assert!(!text.contains("работы"), "локальное имя уехало вместе с карточкой");

    bob.step(2_000, Input::Command(Command::AddSharedContact { msg_id })).unwrap();
    assert_eq!(
        bob.contacts().get(&carol_ik).unwrap().card.display_name,
        "carol",
        "у Боба имя из карточки, а не подпись Алисы"
    );
}

#[test]
fn a_shared_contact_disappears_with_its_message() {
    // Карточка — содержимое сообщения. Оставить её значит оставить в истории
    // кнопку «добавить» у сообщения, которого больше нет.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut alice, &mut carol);

    let msg_id = share(&mut alice, &mut bob, 1_000, carol.own_card().ik);
    let chat = Engine::<MemoryStore>::chat_id_for(&alice.own_card().ik);
    bob.step(2_000, Input::Command(Command::DeleteMessages { chat, msg_ids: vec![msg_id] }))
        .unwrap();

    assert!(
        bob.store().contact_share_of(&msg_id).unwrap().is_none(),
        "карточка обязана уйти вместе с сообщением"
    );
}

/// Настоящий адрес v3 — иначе обновление не пройдёт проверку формата.
///
/// Собственный, посчитанный из ключа: адрес в §4.3 обязан быть адресом,
/// и пара строк вида «aaaa.onion» здесь не годится, хотя в карточках
/// остальных тестов их достаточно.
fn some_onion(seed: u8) -> String {
    ratatosk_crypto::OnionKey::from_seed([seed; 32]).address()
}

#[test]
fn an_address_update_reaches_the_contact() {
    // Ради этого §4.3 и существует: человек, добавивший вас по QR в кафе,
    // знает карточку той минуты. Поднялся Tor — он обязан узнать адрес,
    // иначе знакомство годно ровно до выхода из общей сети.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let alice_ik = alice.own_card().ik;

    let before = bob.contacts()[&alice_ik].card.clone();
    let address = some_onion(9);

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: address.clone(),
                chatmail: String::new(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 1_000, effects);

    let after = &bob.contacts()[&alice_ik].card;
    assert_eq!(after.onion, address, "адрес обязан доехать");
    assert!(after.version > before.version, "версия карточки обязана вырасти");
    assert!(bob.contacts()[&alice_ik].availability.has_onion, "§5.4 обязан узнать про путь");
}

#[test]
fn an_address_update_does_not_undo_the_fingerprint_check() {
    // Меняются адреса, ключи остаются — значит, отпечаток тот же, значит,
    // сверять заново нечего. Сброс признака заставлял бы человека звонить
    // собеседнику при каждом подъёме Tor и приучил бы подтверждать не глядя.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let alice_ik = alice.own_card().ik;
    assert!(bob.contacts()[&alice_ik].verified, "знакомство при встрече — сверено");

    bob.step(
        500,
        Input::Command(Command::SetLocalName {
            peer_ik: alice_ik,
            name: Some("Аля с курсов".into()),
        }),
    )
    .unwrap();

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: some_onion(9),
                chatmail: "a7f3k9@nine.example".into(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 1_000, effects);

    let contact = &bob.contacts()[&alice_ik];
    assert!(contact.verified, "сверка обязана пережить смену адресов");
    assert_eq!(
        contact.local_name.as_deref(),
        Some("Аля с курсов"),
        "подпись пользователя — его, и обновление с той стороны её не касается"
    );
}

#[test]
fn announcing_the_same_addresses_costs_nothing() {
    // Подъём Tor случается при каждом возвращении сети. Поднимай версию
    // карточки каждый раз — и рассылка обновлений станет фоновым шумом.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);
    let address = some_onion(9);

    let first = alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: address.clone(),
                chatmail: String::new(),
            }),
        )
        .unwrap();
    assert!(!first.is_empty(), "первое объявление обязано уйти");
    pump(&mut alice, &mut bob, 1_000, first);
    let version = alice.own_card().version;

    let again = alice
        .step(
            2_000,
            Input::Command(Command::AnnounceAddresses { onion: address, chatmail: String::new() }),
        )
        .unwrap();
    assert!(again.is_empty(), "повтор с теми же адресами не рассылается");
    assert_eq!(alice.own_card().version, version, "и версию не поднимает");
}

#[test]
fn an_update_about_a_third_person_changes_nothing() {
    // Обновление меняет ровно одну карточку — того, кто его прислал.
    // Проверка «от владельца» живёт в `proto::card_update` и покрыта там;
    // здесь — что рассылка не задевает соседей по списку контактов.
    let (mut alice, mut bob, mut carol) = (node(1, "alice"), node(2, "bob"), node(3, "carol"));
    introduce(&mut alice, &mut bob);
    introduce(&mut bob, &mut carol);
    let carol_ik = carol.own_card().ik;
    let before = bob.contacts()[&carol_ik].card.clone();

    let effects = alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: some_onion(9),
                chatmail: String::new(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 1_000, effects);

    assert_eq!(bob.contacts()[&carol_ik].card, before, "чужая карточка не тронута");
}

/// Есть ли в пачке эффектов попытка что-то отправить.
///
/// Нужно там, где проверяется **отсутствие** досылки: «эффектов ровно один»
/// сломается от любой будущей мелочи, а «никуда не полез» — это ровно то,
/// что проверяется.
fn tries_to_reach_out(effects: &[Effect]) -> bool {
    effects.iter().any(|e| matches!(e, Effect::Send { .. } | Effect::Connect { .. }))
}

#[test]
fn a_contact_added_after_the_announcement_still_learns_the_address() {
    // Дыра, из-за которой на стенде «карточки не всегда обмениваются
    // tor-адресом». Рассылка §4.3 уходит тем контактам, которые есть
    // на момент объявления, — а ссылку копируют когда придётся, и добавляют
    // по ней тоже когда придётся. Достаточно один раз сделать /onion раньше,
    // чем собеседник добавлен, — и адрес не узнает никто и никогда:
    // повторное объявление того же адреса бесплатно и потому молчит.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    let alice_ik = alice.own_card().ik;
    let address = some_onion(9);

    // Ссылка снята до объявления — в ней прежний адрес и первая версия.
    let stale = alice.own_card().encode().unwrap();

    // Объявление в пустоту: контактов ещё нет, рассылать некому.
    let alone = alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: address.clone(),
                chatmail: String::new(),
            }),
        )
        .unwrap();
    assert!(alone.is_empty(), "объявлять некому — и нечего отправлять");

    // Знакомство после объявления. Боб заводит Алису по устаревшей ссылке.
    bob.step(2_000, Input::Command(Command::AddContact { card_bytes: stale, met_in_person: true }))
        .unwrap();
    let bob_card = bob.own_card().encode().unwrap();
    let effects = alice
        .step(
            2_000,
            Input::Command(Command::AddContact { card_bytes: bob_card, met_in_person: true }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 2_000, effects);

    let known = &bob.contacts()[&alice_ik];
    assert_eq!(known.card.onion, address, "адрес обязан доехать досылкой");
    assert!(known.availability.has_onion, "§5.4 обязан узнать про путь");
}

#[test]
fn establishing_a_session_delivers_the_address_to_whoever_missed_it() {
    // Тот же случай с другой стороны: добавил один, а первым написал другой.
    // Карточка едет и в первом сообщении рукопожатия (§8.2), но применяется
    // она только к незнакомому контакту — иначе адреса известного человека
    // менял бы кадр без подписи. Значит, знакомому наш адрес обязан приехать
    // подписанным обновлением, и повод для него — сама установленная связь.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    let alice_ik = alice.own_card().ik;
    let address = some_onion(9);

    let stale = alice.own_card().encode().unwrap();
    alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: address.clone(),
                chatmail: String::new(),
            }),
        )
        .unwrap();

    // Боб знает Алису по старой ссылке; Алиса о Бобе не знает вовсе.
    bob.step(2_000, Input::Command(Command::AddContact { card_bytes: stale, met_in_person: true }))
        .unwrap();

    let effects = send_text(&mut bob, &alice, 3_000, "привет");
    pump(&mut bob, &mut alice, 3_000, effects);

    assert_eq!(inbox(&alice, &bob), vec!["привет".to_string()], "сообщение обязано дойти");
    assert_eq!(
        bob.contacts()[&alice_ik].card.onion,
        address,
        "адрес обязан приехать вслед за установленной сессией"
    );
}

#[test]
fn the_same_card_is_not_pushed_to_the_same_contact_twice() {
    // Досылка — страховка, а не фон. Второй раз ту же версию тому же
    // человеку отправлять незачем: на той стороне это `Stale` (§4.3),
    // а на этой — лишний кадр при каждом рукопожатии.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    let stale = alice.own_card().encode().unwrap();
    alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: some_onion(9),
                chatmail: String::new(),
            }),
        )
        .unwrap();

    bob.step(2_000, Input::Command(Command::AddContact { card_bytes: stale, met_in_person: true }))
        .unwrap();
    let bob_card = bob.own_card().encode().unwrap();
    let first = alice
        .step(
            2_000,
            Input::Command(Command::AddContact {
                card_bytes: bob_card.clone(),
                met_in_person: true,
            }),
        )
        .unwrap();
    assert!(tries_to_reach_out(&first), "первая досылка обязана уйти");
    pump(&mut alice, &mut bob, 2_000, first);

    // Повторное добавление того же человека — обычное дело: пересняли QR,
    // прислали ссылку заново. Второй карточки за этим следовать не должно.
    let again = alice
        .step(
            4_000,
            Input::Command(Command::AddContact { card_bytes: bob_card, met_in_person: true }),
        )
        .unwrap();
    assert!(!tries_to_reach_out(&again), "та же версия тому же человеку не повторяется: {again:?}");
}

#[test]
fn a_new_announcement_is_pushed_again() {
    // Обратная сторона предыдущего: запрет на повтор относится к версии,
    // а не к человеку. Сменился адрес — досылка обязана ожить, иначе
    // страховка сработает ровно один раз за запуск.
    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    let alice_ik = alice.own_card().ik;
    let stale = alice.own_card().encode().unwrap();
    alice
        .step(
            1_000,
            Input::Command(Command::AnnounceAddresses {
                onion: some_onion(9),
                chatmail: String::new(),
            }),
        )
        .unwrap();

    bob.step(2_000, Input::Command(Command::AddContact { card_bytes: stale, met_in_person: true }))
        .unwrap();
    let bob_card = bob.own_card().encode().unwrap();
    let first = alice
        .step(
            2_000,
            Input::Command(Command::AddContact { card_bytes: bob_card, met_in_person: true }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 2_000, first);

    let second = some_onion(11);
    let effects = alice
        .step(
            5_000,
            Input::Command(Command::AnnounceAddresses {
                onion: second.clone(),
                chatmail: String::new(),
            }),
        )
        .unwrap();
    pump(&mut alice, &mut bob, 5_000, effects);

    assert_eq!(bob.contacts()[&alice_ik].card.onion, second, "новый адрес обязан доехать");
}

/// §16: переполнение кэша пропущенных ключей.
///
/// Сценарий из спецификации, которого до сих пор не было. Он проверяет
/// не арифметику предела (её проверяют модульные тесты в `ratchet`), а то,
/// что переполнение **не ломает сессию**: вытесненный ключ означает потерю
/// одного сообщения, а не разрыв переписки.
///
/// Почему это важно и почему это не редкость. Кэш наполняется, когда кадры
/// приходят не по порядку (§8.4), — а почта именно так их и доставляет.
/// Достаточно долгого офлайна: собеседник пишет, письма копятся на сервере
/// и приезжают вперемешку. Реализация, которая на переполнении роняет сессию,
/// прошла бы все остальные тесты и сломалась бы ровно у того, кто вернулся
/// из отпуска.
#[test]
fn an_overflowing_skipped_key_cache_does_not_break_the_session() {
    use ratatosk_crypto::ratchet::MAX_SKIPPED_PER_SESSION;

    // Кадр, снятый с провода: транспорт и байты.
    type Held = (ratatosk_proto::Transport, Vec<u8>);

    // Доставляет один придержанный кадр. Отдельной функцией, а не замыканием:
    // так у ссылок обычные времена жизни, а не выведенные.
    fn deliver(bob: &mut Node, at: u64, held: &[Held], i: usize) {
        let (via, frame) = held[i].clone();
        bob.step(at, Input::Received { via, frame }).expect("приём кадра не должен отказывать");
    }

    let (mut alice, mut bob) = (node(1, "alice"), node(2, "bob"));
    introduce(&mut alice, &mut bob);

    // Первое сообщение доходит целиком: дальше есть установленная сессия,
    // и всё последующее — уже ретчет, а не рукопожатие.
    let effects = send_text(&mut alice, &bob, 1_000, "здравствуй");
    pump(&mut alice, &mut bob, 1_000, effects);
    assert_eq!(inbox(&bob, &alice), vec!["здравствуй".to_string()]);

    // Алиса пишет много, а провод молчит: кадры собираются, но не доставляются.
    // Ровно так выглядит долгий офлайн получателя.
    let total = MAX_SKIPPED_PER_SESSION + 60;
    let mut held: Vec<Held> = Vec::with_capacity(total);
    for i in 0..total {
        let at = 2_000 + i as u64;
        for effect in send_text(&mut alice, &bob, at, &format!("письмо {i}")) {
            if let Effect::Send { via, frame, .. } = effect {
                held.push((via, frame));
            }
        }
    }
    assert_eq!(held.len(), total, "по установленной сессии на сообщение один кадр");

    // Доставка не по порядку. Числа выбраны так, чтобы каждый прыжок
    // укладывался в предел §7.3, а суммарный кэш — вышел за предел §8.4.
    let far = MAX_SKIPPED_PER_SESSION - 100;

    deliver(&mut bob, 100_000, &held, far);
    deliver(&mut bob, 100_001, &held, total - 5);

    // Самые старые ключи вытеснены — это и есть переполнение. Их сообщения
    // потеряны, и притвориться, что они дойдут, нельзя.
    deliver(&mut bob, 100_002, &held, 0);
    assert!(
        !inbox(&bob, &alice).contains(&"письмо 0".to_string()),
        "сообщение с вытесненным ключом не может быть прочитано — обещать обратное нечестно"
    );

    // А всё, что кэш ещё помнит, читается как ни в чём не бывало.
    deliver(&mut bob, 100_003, &held, far - 10);
    // И следующее по порядку — тоже: сессия жива, ретчет на месте.
    deliver(&mut bob, 100_004, &held, total - 4);

    let chat = inbox(&bob, &alice);
    assert!(chat.contains(&format!("письмо {}", far - 10)), "кэш перестал отдавать то, что помнит");
    assert!(chat.contains(&format!("письмо {}", total - 4)), "сессия не пережила переполнение");
    assert!(chat.contains(&"здравствуй".to_string()), "история до переполнения обязана остаться");
}
