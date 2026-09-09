//! Заведение группы (§11).
//!
//! Кадров отсюда не уезжает ни одного, и тесты об этом тоже: группа в момент
//! заведения состоит из создателя, рассказывать о ней некому. Проверяется
//! то, что ложится на диск и поднимается обратно, — потому что именно здесь
//! легко ошибиться молча: состав группы это CRDT, и лишняя метка,
//! выдуманная при подъёме, не видна ничем, кроме теста.

use ratatosk_codec::ContactCard;
use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{
    Command, Effect, Engine, EngineError, Event, Input, SeededEntropy, MAX_GROUP_TITLE_CHARS,
};
use ratatosk_crypto::{Identity, PublicIdentity};
use ratatosk_proto::group;
use ratatosk_store::{MemoryBlobs, MemoryStore, Store};

type Node = Engine<MemoryStore>;

fn node(seed: u8) -> Node {
    let identity = Identity::from_seed([seed; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция in-memory хранилища");
    let mut engine = Engine::new(
        identity,
        store,
        Box::new(MemoryBlobs::new()),
        Box::new(SeededEntropy::new(u64::from(seed))),
        SelfAddresses {
            onion: String::new(),
            chatmail: String::new(),
            display_name: "я".to_owned(),
        },
    );
    engine.restore().expect("подъём");
    engine
}

/// Заводит группу и отдаёт её идентификатор.
fn create(engine: &mut Node, now_ms: u64, title: &str) -> [u8; 16] {
    let effects = engine
        .step(now_ms, Input::Command(Command::CreateGroup { title: title.to_owned() }))
        .expect("группа заведена");
    let mut found = None;
    for effect in &effects {
        if let Effect::Notify(Event::GroupCreated { chat, .. }) = effect {
            found = Some(*chat);
        }
    }
    found.expect("о заведении обязано прийти событие")
}

#[test]
fn creating_a_group_sends_nothing_and_names_the_chat() {
    // Ни одного кадра: в группе один человек, и рассказывать о ней некому.
    // Событие при этом обязательно — идентификатор случаен, и узнать его
    // клиенту больше неоткуда.
    let mut me = node(1);
    let effects = me
        .step(100, Input::Command(Command::CreateGroup { title: "  у костра  ".to_owned() }))
        .expect("группа заведена");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "заведение группы не разговаривает с сетью"
    );
    let Some(Effect::Notify(Event::GroupCreated { chat, title })) =
        effects.iter().find(|e| matches!(e, Effect::Notify(Event::GroupCreated { .. })))
    else {
        panic!("событие о заведении не пришло");
    };
    assert_eq!(title, "у костра", "название подрезается по краям здесь, а не у клиента");

    let state = me.groups().get(chat).expect("группа известна ядру");
    assert_eq!(state.title, "у костра");
    assert_eq!(state.created_ms, 100);
}

#[test]
fn the_creator_is_the_only_member_and_the_owner() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;

    let state = me.groups().get(&chat).expect("группа известна ядру");
    assert_eq!(state.group.members().copied().collect::<Vec<_>>(), vec![mine]);
    assert_eq!(state.group.owner, mine, "исключать в v1 может только создатель (§11.2)");
}

#[test]
fn a_group_chat_id_is_not_a_contact_chat_id() {
    // У 1:1 идентификатор выводится из `IK` (`chat_id_for`), у группы он
    // случаен. Совпади они по устройству, а не по случайности — сообщения
    // двух разговоров легли бы в один чат.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert_ne!(chat, Engine::<MemoryStore>::chat_id_for(&me.own_card().ik));

    let second = create(&mut me, 200, "у другого костра");
    assert_ne!(chat, second, "две группы — два идентификатора");
}

#[test]
fn a_group_needs_a_name() {
    // У контакта имя бывает пустым законно — его задаёт собеседник.
    // Название группы задаёт этот человек, и запасного имени у группы нет.
    let mut me = node(1);
    assert!(matches!(
        me.step(100, Input::Command(Command::CreateGroup { title: "   ".to_owned() })),
        Err(EngineError::GroupTitleEmpty)
    ));
    assert!(me.groups().is_empty(), "отказ не должен оставлять полугруппу");

    let long = "я".repeat(ratatosk_core::MAX_GROUP_TITLE_CHARS + 1);
    assert!(matches!(
        me.step(200, Input::Command(Command::CreateGroup { title: long })),
        Err(EngineError::GroupTitleTooLong)
    ));
    assert!(me.groups().is_empty());
}

#[test]
fn the_sender_chain_is_written_at_creation() {
    // Ключ отправителя случаен (§11.1), то есть невыводим. Не запиши мы его
    // сразу — перезапуск между заведением и первым сообщением завёл бы
    // новый, и участники, успевшие получить прежний, читали бы пустоту.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;

    let chain = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("цепочка есть");
    assert_eq!(chain.counter, 0, "ни одного сообщения ещё не отправлено");
    assert_ne!(chain.chain, [0u8; 32], "цепочка обязана начинаться с секрета");

    // И она одна: чужие ключи отправителей приезжают при вступлении (§11.5),
    // а вступать пока некому.
    assert_eq!(me.store().sender_chains(&chat).expect("хранилище").len(), 1);
}

#[test]
fn two_groups_get_two_sender_chains() {
    // Цепочка принадлежит паре «группа, участник»: общая на все группы
    // означала бы, что ключ, отданный одному кругу знакомых, открывает
    // сообщения в другом.
    let mut me = node(1);
    let first = create(&mut me, 100, "первая");
    let second = create(&mut me, 200, "вторая");
    let mine = me.own_card().ik;

    let a = me.store().sender_chain(&first, &mine).expect("хранилище").expect("есть");
    let b = me.store().sender_chain(&second, &mine).expect("хранилище").expect("есть");
    assert_ne!(a.chain, b.chain);
}

#[test]
fn the_membership_history_holds_exactly_one_operation() {
    // На диске лежат **операции**, а не свёрнутый состав: OR-Set разрешает
    // порядок сам, и свёрнутый состав выбросил бы то, чем он разрешается.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;

    let ops = me.store().membership(&chat).expect("хранилище");
    assert_eq!(ops.len(), 1, "добавление себя — вся история новорождённой группы");
    assert_eq!(ops[0].member_ik, mine);
    assert!(!ops[0].removed);
    assert_eq!(ops[0].tag_actor, mine, "метку поставил создатель");
    assert_eq!(ops[0].tag_wall, 100, "метка взята у часов шага, а не выдумана");
}

/// Карточка постороннего — того, кого приглашают.
fn stranger(seed: u8) -> ContactCard {
    let who = Identity::from_seed([seed; 32]);
    ContactCard {
        ik: who.public().ik,
        sk: who.public().sk,
        // Адресов нет, и это законное состояние карточки: приглашение
        // проверяется здесь по составу и хранилищу, а не по доставке.
        onion: String::new(),
        chatmail: String::new(),
        display_name: format!("гость {seed}"),
        version: 1,
        ygg: Vec::new(),
    }
}

/// Заводит контакт, не устанавливая сессии.
fn befriend(engine: &mut Node, card: &ContactCard) -> [u8; 32] {
    engine
        .step(
            10,
            Input::Command(Command::AddContact {
                card_bytes: card.encode().expect("карточка кодируется"),
                met_in_person: true,
            }),
        )
        .expect("контакт заведён");
    card.ik
}

fn invite(engine: &mut Node, now_ms: u64, chat: [u8; 16], peer_ik: [u8; 32]) -> Vec<Effect> {
    engine
        .step(now_ms, Input::Command(Command::InviteToGroup { chat, peer_ik }))
        .expect("приглашение принято")
}

#[test]
fn the_creation_block_is_signed_and_stored() {
    // История состава обязана быть полной с первой операции: при первом же
    // приглашении её отдают новичку целиком (§11.5), и блок без подписи
    // он принять не сможет — да и не должен.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");

    let blocks = me.store().membership_blocks(&chat).expect("хранилище");
    assert_eq!(blocks.len(), 1, "заведение группы — тоже изменение состава");

    let card = me.own_card();
    let known = PublicIdentity::from_bytes(card.ik, card.sk).expect("своя личность");
    let value = ratatosk_codec::canonical::decode(&blocks[0].bytes).expect("блок разбирается");
    let block = group::parse_membership(&value)
        .expect("форма блока")
        .verify(&known)
        .expect("подпись сходится");
    assert_eq!(block.group, chat);
    assert_eq!(block.author, card.ik);
    assert_eq!(block.ops.len(), 1, "одна операция — добавление себя");
}

#[test]
fn an_invitation_needs_a_group() {
    let mut me = node(1);
    let guest = befriend(&mut me, &stranger(9));
    assert!(matches!(
        me.step(100, Input::Command(Command::InviteToGroup { chat: [0u8; 16], peer_ik: guest })),
        Err(EngineError::UnknownGroup)
    ));
}

#[test]
fn an_invitation_needs_a_known_contact() {
    // Приглашение незнакомцу было бы командой, которая заведомо ничего
    // не делает: без карточки ему нечем отправить даже рукопожатие.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert!(matches!(
        me.step(200, Input::Command(Command::InviteToGroup { chat, peer_ik: [77u8; 32] })),
        Err(EngineError::UnknownPeer)
    ));
    assert_eq!(me.store().membership(&chat).expect("хранилище").len(), 1, "отказ ничего не пишет");
}

#[test]
fn inviting_someone_already_in_is_refused() {
    // Отказ, а не тихий повтор: OR-Set принял бы вторую метку молча,
    // и двойное нажатие рассылало бы блок всем заново.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    assert!(matches!(
        me.step(300, Input::Command(Command::InviteToGroup { chat, peer_ik: guest })),
        Err(EngineError::AlreadyInGroup)
    ));
    assert_eq!(me.store().membership(&chat).expect("хранилище").len(), 2);

    // И себя тоже: создатель в составе с первой секунды.
    let mine = me.own_card().ik;
    assert!(matches!(
        me.step(400, Input::Command(Command::InviteToGroup { chat, peer_ik: mine })),
        Err(EngineError::AlreadyInGroup)
    ));
}

#[test]
fn an_invitation_adds_the_member_and_records_a_second_block() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    let state = me.groups().get(&chat).expect("группа известна");
    assert!(state.group.contains(&guest), "новичок в составе");
    assert_eq!(state.group.len(), 2);

    let ops = me.store().membership(&chat).expect("хранилище");
    assert_eq!(ops.len(), 2, "добавление себя и добавление новичка");
    assert_eq!(ops[1].member_ik, guest);
    assert_eq!(ops[1].tag_wall, 200, "метка взята у часов шага");

    let blocks = me.store().membership_blocks(&chat).expect("хранилище");
    assert_eq!(blocks.len(), 2, "один блок на одно изменение состава");
    assert_ne!(blocks[0].block_id, blocks[1].block_id, "разные блоки — разные строки");
}

#[test]
fn an_invitation_starts_a_new_sender_chain() {
    // §11.5: «при вступлении каждый участник обязан начать новую
    // sender-цепочку». Именно новую, а не продвинутую: продвижение
    // выводится из прежнего состояния и знающему его ничего не закрывает.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;
    let before = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    let after = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");
    assert_ne!(after.chain, before.chain, "цепочка обязана смениться");
    assert_eq!(after.counter, 0, "новая цепочка начинается с нуля");
    assert_eq!(me.store().sender_chains(&chat).expect("хранилище").len(), 1, "не вторая строка");
}

#[test]
fn a_second_invitation_rotates_the_chain_again() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;

    let first = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, first);
    let after_first = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    let second = befriend(&mut me, &stranger(8));
    invite(&mut me, 300, chat, second);
    let after_second = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    assert_ne!(after_second.chain, after_first.chain, "каждое вступление — новая цепочка");
    assert_eq!(me.groups()[&chat].group.len(), 3);

    // Метка поворота обязана расти, и это не украшение. Оба объявления
    // едут одновременно и с одинаковым (нулевым) номером; §9.2 разрешает
    // их переставить, и отличить свежее от опоздавшего получателю больше
    // нечем. Совпади метки — он взял бы пришедшее последним, то есть
    // в половине случаев мёртвую цепочку.
    assert!(
        (after_second.chain_wall, after_second.chain_logical)
            > (after_first.chain_wall, after_first.chain_logical),
        "второй поворот обязан быть старше первого: {:?} против {:?}",
        (after_second.chain_wall, after_second.chain_logical),
        (after_first.chain_wall, after_first.chain_logical),
    );
}

#[test]
fn an_invitation_says_the_membership_changed() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    let effects = invite(&mut me, 200, chat, guest);

    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::GroupMembershipChanged { chat: c }) if *c == chat
        )),
        "без события клиент не перерисует шапку"
    );
}

#[test]
fn evicting_yourself_is_refused() {
    // Отказ сохранился и после того, как выход появился, и это не
    // педантизм: у исключения правило §11.2 «только создатель», у выхода
    // правила нет вовсе. Отказ называет нужную команду, а не запрещает
    // намерение.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;
    assert!(matches!(
        me.step(200, Input::Command(Command::EvictFromGroup { chat, peer_ik: mine })),
        Err(EngineError::CannotEvictSelf)
    ));
    assert_eq!(me.groups()[&chat].group.len(), 1, "отказ ничего не тронул");
}

#[test]
fn evicting_someone_who_is_not_in_the_group_is_refused() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    assert!(matches!(
        me.step(200, Input::Command(Command::EvictFromGroup { chat, peer_ik: guest })),
        Err(EngineError::Group(ratatosk_proto::GroupError::NotAMember))
    ));
}

#[test]
fn an_eviction_records_a_block_of_its_own() {
    // Удаление — такая же операция состава, как добавление: подписанный блок
    // и строки-надгробия. Без блока новичку нечем было бы доказать, что
    // человека убрали (§11.5).
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    me.step(300, Input::Command(Command::EvictFromGroup { chat, peer_ik: guest }))
        .expect("исключение");

    assert!(!me.groups()[&chat].group.contains(&guest), "убран из состава");
    assert_eq!(me.store().membership_blocks(&chat).expect("хранилище").len(), 3);

    let ops = me.store().membership(&chat).expect("хранилище");
    assert_eq!(ops.len(), 2, "надгробие ложится на ту же метку, а не новой строкой");
    let tomb = ops.iter().find(|o| o.member_ik == guest).expect("строка гостя");
    assert!(tomb.removed, "метка добавления погашена");
}

#[test]
fn an_evicted_member_can_be_invited_back() {
    // Ради этого OR-Set и взят: удаление гасит те метки, которые автор видел,
    // а новое приглашение ставит новую.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);
    me.step(300, Input::Command(Command::EvictFromGroup { chat, peer_ik: guest }))
        .expect("исключение");
    invite(&mut me, 400, chat, guest);

    assert!(me.groups()[&chat].group.contains(&guest), "вернулся");
    assert_eq!(me.groups()[&chat].group.len(), 2);
}

// --- Действия в группе: правка, отзыв, реакция, ответ ---------------------
//
// Отправка проверяется здесь, на одном узле, и проверяется по двум следам:
// что легло у себя и **на сколько продвинулась цепочка**. Второе тут важнее
// первого: номер цепочки — единственное, что видно снаружи у кадра, который
// никуда не уехал, и именно он отличает «действие собралось» от «действие
// молча ничего не сделало».
//
// Приёма ещё нет: кадры уезжают, но принять их некому. Тестов на «дошло»
// поэтому здесь нет — они приедут вместе с обработчиком.

/// Заводит группу с одним гостем и говорит в ней; отдаёт всё сразу.
fn group_with_a_word(now_ms: u64) -> (Node, [u8; 16], [u8; 32], [u8; 16]) {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);
    me.step(now_ms, Input::Command(Command::SendText { chat, text: "все тут?".to_owned() }))
        .expect("сказано");
    let msg_id = me.store().messages(&chat, 10, None).expect("хранилище")[0].msg_id;
    (me, chat, guest, msg_id)
}

/// Где сейчас цепочка отправителя — единственный видимый след ушедшего кадра.
fn counter(engine: &Node, chat: [u8; 16]) -> u64 {
    let me = engine.own_card().ik;
    engine.store().sender_chain(&chat, &me).expect("хранилище").expect("цепочка").counter
}

#[test]
fn an_edit_in_a_group_changes_the_text_and_costs_one_number() {
    let (mut me, chat, _, msg_id) = group_with_a_word(300);
    let before = counter(&me, chat);

    me.step(
        400,
        Input::Command(Command::EditMessage {
            chat, msg_id, text: "все у костра?".to_owned()
        }),
    )
    .expect("правка");

    let stored = me.store().message(&msg_id).expect("хранилище").expect("сообщение на месте");
    assert_eq!(stored.body, "все у костра?".as_bytes(), "текст заменён у себя");
    assert!(stored.edited_ms.is_some(), "отметка «изменено» обязательна (§14)");
    assert_eq!(counter(&me, chat), before + 1, "правка стоит одного номера цепочки");
}

#[test]
fn a_reaction_in_a_group_costs_a_number_like_a_word() {
    // Цепочка — это порядок, в котором участник что-то делал. Не трать
    // реакция номера, получатель не отличил бы «не довезли» от «не было».
    let (mut me, chat, _, msg_id) = group_with_a_word(300);
    let before = counter(&me, chat);
    let own = me.own_card().ik;

    me.step(400, Input::Command(Command::SetReaction { chat, msg_id, emoji: "👍".to_owned() }))
        .expect("реакция");

    let stored = me.store().reaction(&msg_id, &own).expect("хранилище").expect("реакция легла");
    assert_eq!(stored.emoji, "👍");
    assert_eq!(counter(&me, chat), before + 1);
}

#[test]
fn a_reply_in_a_group_lands_under_the_number_of_its_own_frame() {
    // Ответ — новое сообщение, и у всех участников это одна и та же строка:
    // номер берётся из конверта, который уехал (§11.3).
    let (mut me, chat, _, msg_id) = group_with_a_word(300);

    me.step(
        400,
        Input::Command(Command::SendReply { chat, reply_to: msg_id, text: "тут".to_owned() }),
    )
    .expect("ответ");

    let all = me.store().messages(&chat, 10, None).expect("хранилище");
    assert_eq!(all.len(), 2, "ответ лёг в историю");
    let reply = all.iter().find(|m| m.msg_id != msg_id).expect("ответ");
    assert_eq!(reply.reply_to, Some(msg_id), "ссылка, а не цитата");
    assert_eq!(reply.body, "тут".as_bytes());
    // Один значок на тридцать двух получателей — обещание, которого §14
    // не даёт. У ответа в группе его нет ровно так же, как у сообщения.
    assert_eq!(reply.status, None, "статуса доставки у группового ответа нет");
}

#[test]
fn a_retraction_about_nothing_of_ours_sends_nothing() {
    // Отозвать можно только своё. У себя при этом убирается всё названное —
    // но кадр собирать не из чего, и номер цепочки тратить не на что.
    let (mut me, chat, _, _) = group_with_a_word(300);
    let before = counter(&me, chat);

    me.step(400, Input::Command(Command::RetractMessages { chat, msg_ids: vec![[42u8; 16]] }))
        .expect("отзыв принят");

    assert_eq!(counter(&me, chat), before, "цепочка не двинулась: просить не о чем");
}

#[test]
fn a_retraction_of_our_own_costs_one_number_for_the_whole_list() {
    // Список едет одним кадром — как и один на один.
    let (mut me, chat, _, msg_id) = group_with_a_word(300);
    let before = counter(&me, chat);

    me.step(400, Input::Command(Command::RetractMessages { chat, msg_ids: vec![msg_id] }))
        .expect("отзыв");

    assert_eq!(counter(&me, chat), before + 1);
    assert!(
        me.store().message(&msg_id).expect("хранилище").is_none(),
        "у себя сообщение убрано сразу"
    );
}

#[test]
fn editing_what_is_not_ours_is_refused_before_anything_moves() {
    let (mut me, chat, _, _) = group_with_a_word(300);
    let before = counter(&me, chat);

    let refused = me.step(
        400,
        Input::Command(Command::EditMessage {
            chat, msg_id: [42u8; 16], text: "чужое".to_owned()
        }),
    );

    assert!(matches!(refused, Err(EngineError::Edit(_))), "правка чужого отклонена: {refused:?}");
    assert_eq!(counter(&me, chat), before, "отказ до цепочки: номер не потрачен");
}

#[test]
fn an_empty_edit_in_a_group_is_refused_like_one_to_one() {
    // Правило берётся у 1:1, а не пишется заново: пустая правка — это
    // удаление, и подменять одно другим нельзя ни там, ни здесь.
    let (mut me, chat, _, msg_id) = group_with_a_word(300);
    let before = counter(&me, chat);

    let refused =
        me.step(400, Input::Command(Command::EditMessage { chat, msg_id, text: "  ".to_owned() }));

    assert!(refused.is_err());
    assert_eq!(counter(&me, chat), before);
}

#[test]
fn a_reply_to_a_message_from_another_chat_is_refused() {
    // Ответ на чужой разговор и цитировать нечем, и он рассказал бы
    // участникам об идентификаторе, которого они знать не должны.
    let (mut me, chat, _, _) = group_with_a_word(300);
    let other = create(&mut me, 350, "другая");
    me.step(360, Input::Command(Command::SendText { chat: other, text: "тут".to_owned() }))
        .expect("сказано");
    let elsewhere = me.store().messages(&other, 10, None).expect("хранилище")[0].msg_id;
    let before = counter(&me, chat);

    let refused = me.step(
        400,
        Input::Command(Command::SendReply { chat, reply_to: elsewhere, text: "?".to_owned() }),
    );

    assert!(refused.is_err());
    assert_eq!(counter(&me, chat), before);
}

#[test]
fn a_retraction_does_not_carry_a_number_from_another_chat() {
    // Отзыв — единственное из четырёх действий, которое чат не проверяло.
    // Назвав номер из другого разговора, клиент попросил бы удалить его
    // у всех участников — и тем самым рассказал бы тридцати двум людям,
    // что такой номер вообще есть. Правило теперь одно на 1:1 и на группу
    // (`own_of`), и здесь видно, что оно работает.
    let (mut me, chat, _, _) = group_with_a_word(300);
    let other = create(&mut me, 350, "другая");
    me.step(360, Input::Command(Command::SendText { chat: other, text: "не отсюда".to_owned() }))
        .expect("сказано");
    let elsewhere = me.store().messages(&other, 10, None).expect("хранилище")[0].msg_id;
    let before = counter(&me, chat);

    me.step(400, Input::Command(Command::RetractMessages { chat, msg_ids: vec![elsewhere] }))
        .expect("отзыв принят");

    assert_eq!(counter(&me, chat), before, "чужой чат в просьбу не попал");
}

#[test]
fn a_group_message_to_an_unreachable_member_still_has_no_status() {
    // Дыра, которую открыл групповой ответ, а болела она и у сообщения.
    // `silent` учитывался только после того, как транспорт нашёлся; когда
    // канала нет вовсе, статус объявлялся раньше этой проверки. У гостя
    // здесь нет ни адресов, ни сессии — то есть ровно этот случай.
    //
    // Один значок на тридцать двух получателей §14 не разрешает, и «ждём
    // отправки» — такое же обещание, как «доставлено».
    let (me, _chat, _, msg_id) = group_with_a_word(300);

    assert_eq!(
        me.store().message(&msg_id).expect("хранилище").expect("сообщение").status,
        None,
        "у группового сообщения статуса нет, даже когда до участника нет канала"
    );
}

// --- Выход из группы ------------------------------------------------------

#[test]
fn leaving_takes_you_out_and_records_a_block() {
    // Изнутри протокола выход — та же операция состава, что исключение,
    // и след у него такой же: подписанный блок плюс погашенная метка.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    me.step(300, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    let mine = me.own_card().ik;
    assert!(!me.groups()[&chat].group.contains(&mine), "вышли из состава");
    assert!(me.groups()[&chat].group.contains(&guest), "остальные на месте");
    assert_eq!(me.store().membership_blocks(&chat).expect("хранилище").len(), 3);
}

#[test]
fn after_leaving_you_cannot_speak_in_the_group() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);
    me.step(250, Input::Command(Command::SendText { chat, text: "пока".into() })).expect("сказано");
    let msg_id = me.store().messages(&chat, 10, None).expect("хранилище")[0].msg_id;
    me.step(300, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    assert!(matches!(
        me.step(400, Input::Command(Command::SendText { chat, text: "эй".into() })),
        Err(EngineError::NotInGroup)
    ));
    // И действия — той же проверкой: они собирают кадр той же функцией.
    // Цель берётся настоящая: реакция на несуществующее сообщение
    // отказывается **раньше** проверки состава и про выход не сказала бы
    // ничего.
    assert!(matches!(
        me.step(500, Input::Command(Command::SetReaction { chat, msg_id, emoji: "👍".into() })),
        Err(EngineError::NotInGroup)
    ));
}

#[test]
fn the_chat_stays_after_leaving() {
    // Переписка остаётся: это своя история, и уход из разговора не стирает
    // сказанное. Ровно то же обещает §11.4 исключённому.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);
    me.step(250, Input::Command(Command::SendText { chat, text: "пока".into() })).expect("сказано");

    me.step(300, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    assert_eq!(me.store().messages(&chat, 10, None).expect("хранилище").len(), 1);
    assert!(me.groups().contains_key(&chat), "группа остаётся в списке чатов");
}

#[test]
fn the_owner_may_leave_and_then_no_one_can_evict() {
    // Цена названа вслух в `LeaveConsequences::owner_text`: передачи прав
    // в v1 нет. Запретить создателю уходить было бы хуже — это оставило бы
    // человека в разговоре навсегда.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    me.step(300, Input::Command(Command::LeaveGroup { chat })).expect("создатель выходит");

    let mine = me.own_card().ik;
    assert_eq!(me.groups()[&chat].group.owner, mine, "владение выходом не снимается");
    assert!(matches!(
        me.step(400, Input::Command(Command::EvictFromGroup { chat, peer_ik: guest })),
        Err(EngineError::NotInGroup)
    ));
}

#[test]
fn leaving_twice_is_refused() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    assert!(me.step(300, Input::Command(Command::LeaveGroup { chat })).is_err());
}

// --- Подпись автора -------------------------------------------------------

#[test]
fn an_author_is_named_only_where_it_cannot_be_derived() {
    // `None` здесь означает «выводится из `mine`», а не «неизвестно».
    // В переписке двоих имя собеседника стоит заголовком чата, и подпись
    // у каждой строки повторяла бы его на весь экран; в группе «не своё»
    // означает одного из тридцати двух, и без имени сообщение не читается.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    assert_eq!(me.message_author(&chat, &guest).as_deref(), Some("гость 9"));
    let one_to_one = Engine::<MemoryStore>::chat_id_for(&guest);
    assert_eq!(me.message_author(&one_to_one, &guest), None, "в переписке двоих выводится");
}

#[test]
fn an_author_without_a_card_is_named_by_the_start_of_the_fingerprint() {
    // Участник, чья карточка ещё не доехала (§11.5), обязан быть подписан
    // хоть как-то: пустая подпись в группе неотличима от чужого сообщения
    // без автора вовсе.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let unknown = [0xabu8; 32];

    assert_eq!(
        me.message_author(&chat, &unknown).as_deref(),
        Some("abababab"),
        "начало отпечатка — то же, чем подписан безымянный контакт"
    );
}

#[test]
fn a_local_name_signs_the_message_too() {
    // Правило §4.1 одно на список контактов и на подпись под сообщением.
    // Разойдись они, человек, переименованный в списке, остался бы
    // подписан прежним именем в переписке.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    me.step(
        300,
        Input::Command(Command::SetLocalName {
            peer_ik: guest,
            name: Some("Оля с работы".to_owned()),
        }),
    )
    .expect("местное имя");

    assert_eq!(me.message_author(&chat, &guest).as_deref(), Some("Оля с работы"));
}

#[test]
fn your_own_group_message_is_signed_with_your_own_name() {
    // Себя в списке контактов нет, и без отдельной ветки собственное
    // сообщение подписывалось бы отпечатком. Показать вместо имени «вы» —
    // дело клиента: для этого у него `mine`.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;

    assert_eq!(me.message_author(&chat, &mine).as_deref(), Some("я"));
}

#[test]
fn the_member_list_names_everyone_and_marks_you() {
    // Поломка со стенда: клиент искал имя участника по ключу перебором
    // контактов — и **себя** там не находил, потому что своей карточки
    // в контактах нет. Хозяин телефона показывался «неизвестным
    // участником» в собственной группе.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    let members = me.group_members(&chat);
    assert_eq!(members.len(), 2);

    let mine = members.iter().find(|m| m.mine).expect("себя обязано быть видно");
    assert_eq!(mine.ik, me.own_card().ik);
    assert_eq!(mine.name, "я", "своё имя — из своей карточки, а не отпечатком");

    let other = members.iter().find(|m| !m.mine).expect("и гостя тоже");
    assert_eq!(other.ik, guest);
    assert_eq!(other.name, "гость 9");
}

#[test]
fn a_member_whose_card_has_not_arrived_is_still_named() {
    // Состав приезжает блоками, карточки — списком, и они законно
    // расходятся во времени (§9.2). Участник без карточки обязан быть
    // назван хоть как-то: пустое имя клиент показал бы пустотой.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");

    // Правило именования одно на подпись автора и на состав — проверяем
    // его тем же ключом, которого в контактах нет.
    assert_eq!(me.message_author(&chat, &[0xabu8; 32]).as_deref(), Some("abababab"));
}

#[test]
fn the_member_list_of_an_unknown_group_is_empty() {
    let me = node(1);
    assert!(me.group_members(&[9u8; 16]).is_empty(), "группы нет — и состава нет");
}

// --- Переименование -------------------------------------------------------

#[test]
fn renaming_a_group_stores_the_name_and_moves_the_tag_forward() {
    // Метка обязана уйти вперёд, и это не украшение: по ней и только по ней
    // решается, чьё название победит. Останься она на месте — второе
    // переименование того же человека остальные отвергли бы как опоздавшее.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let before = me.groups().get(&chat).expect("группа известна ядру").title_hlc;

    let effects = me
        .step(200, Input::Command(Command::RenameGroup { chat, title: "  у ручья  ".to_owned() }))
        .expect("переименование");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "в группе один человек — рассказывать некому"
    );
    assert!(
        effects.iter().any(|e| matches!(
            e,
            Effect::Notify(Event::GroupRenamed { chat: c, title }) if *c == chat && title == "у ручья"
        )),
        "название едет внутри события: запроси клиент его отдельно — следующее переименование обогнало бы ответ"
    );

    let state = me.groups().get(&chat).expect("группа на месте");
    assert_eq!(state.title, "у ручья", "подрезается здесь, а не у клиента");
    assert!(state.title_hlc > before, "метка обязана уйти вперёд");
    let stored = me.store().group(&chat).expect("хранилище").expect("группа на диске");
    assert_eq!(stored.title, "у ручья", "в памяти и на диске одно и то же");
    assert_eq!(
        (stored.title_wall, stored.title_logical),
        (state.title_hlc.wall_ms, state.title_hlc.logical),
        "метка легла на диск целиком: без неё перезапуск начал бы отсчёт заново"
    );
}

#[test]
fn a_new_name_and_its_tag_come_back_after_a_restart() {
    // Тот же путь, которым идёт настоящий перезапуск: `restore` собирает
    // группу из хранилища. Потеряйся здесь метка — после перезапуска
    // название менялось бы само: любое старое переименование выглядело
    // бы новее нулевой.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::RenameGroup { chat, title: "у ручья".to_owned() }))
        .expect("переименование");
    let tag = me.groups().get(&chat).expect("группа").title_hlc;

    me.restore().expect("подъём");

    let state = me.groups().get(&chat).expect("группа поднялась");
    assert_eq!(state.title, "у ручья");
    assert_eq!(state.title_hlc, tag, "метка поднялась той же, а не нулевой");
}

#[test]
fn a_rename_obeys_the_same_two_limits_as_creation() {
    // Пределы у заведения и у переименования обязаны совпадать: разойдись
    // они, название, законное при заведении, нельзя было бы вернуть.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");

    assert!(matches!(
        me.step(200, Input::Command(Command::RenameGroup { chat, title: "   ".to_owned() })),
        Err(EngineError::GroupTitleEmpty)
    ));
    let too_long = "я".repeat(MAX_GROUP_TITLE_CHARS + 1);
    assert!(matches!(
        me.step(300, Input::Command(Command::RenameGroup { chat, title: too_long })),
        Err(EngineError::GroupTitleTooLong)
    ));
    assert_eq!(
        me.groups().get(&chat).expect("группа").title,
        "у костра",
        "отказ не трогает ни названия, ни метки"
    );
}

#[test]
fn renaming_a_group_we_do_not_know_is_refused() {
    let mut me = node(1);
    assert!(matches!(
        me.step(
            100,
            Input::Command(Command::RenameGroup {
                chat: [9u8; 16], title: "у ручья".to_owned()
            })
        ),
        Err(EngineError::UnknownGroup)
    ));
}

#[test]
fn after_leaving_the_owner_cannot_rename_either() {
    // Создателем он остался, участником — нет. Отказ приходит от сборки
    // кадра, и он точнее «не создатель»: человек ушёл сам.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    assert!(matches!(
        me.step(300, Input::Command(Command::RenameGroup { chat, title: "у ручья".to_owned() })),
        Err(EngineError::NotInGroup)
    ));
}

// --- Аватарка -------------------------------------------------------------

/// Картинка нужной длины с настоящей сигнатурой PNG.
fn png_of(len: usize) -> Vec<u8> {
    let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.resize(len.max(bytes.len()), 7);
    bytes
}

fn png() -> Vec<u8> {
    png_of(64)
}

#[test]
fn setting_a_group_avatar_stores_it_and_moves_the_tag_forward() {
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert_eq!(me.group_avatar_stamp(&chat).expect("метка"), 0, "у новой группы картинки нет");

    let effects = me
        .step(200, Input::Command(Command::SetGroupAvatar { chat, bytes: png() }))
        .expect("аватарка");

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Send { .. })),
        "в группе один человек — рассказывать некому"
    );
    assert!(
        effects.iter().any(
            |e| matches!(e, Effect::Notify(Event::GroupAvatarChanged { chat: c }) if *c == chat)
        ),
        "без события окно не перерисуется — байты при этом в событии не едут"
    );

    assert_eq!(me.group_avatar_of(&chat).expect("чтение"), Some(png()));
    assert_ne!(me.group_avatar_stamp(&chat).expect("метка"), 0, "метка обязана уйти вперёд");
    let stored = me.store().group_avatar(&chat).expect("хранилище").expect("на диске");
    assert_eq!(stored.bytes, png(), "в памяти и на диске одно и то же");
}

#[test]
fn removing_a_group_avatar_keeps_the_tag_it_moved() {
    // Снятие — такое же действие, как постановка: у него своя метка,
    // и без неё опоздавшая копия прежней картинки вернула бы её на место.
    // Наружу при этом «сняли» и «не ставили» неразличимы — рисуют по ним
    // одно и то же.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::SetGroupAvatar { chat, bytes: png() })).expect("картинка");
    let after_set = me.groups().get(&chat).expect("группа").avatar_hlc;

    me.step(300, Input::Command(Command::SetGroupAvatar { chat, bytes: Vec::new() }))
        .expect("снятие");

    assert_eq!(me.group_avatar_of(&chat).expect("чтение"), None, "показывать нечего");
    assert_eq!(me.group_avatar_stamp(&chat).expect("метка"), 0, "и метка наружу — ноль");
    assert!(
        me.groups().get(&chat).expect("группа").avatar_hlc > after_set,
        "а внутри метка ушла вперёд: ею отбивается опоздавшая копия"
    );
    let stored = me.store().group_avatar(&chat).expect("хранилище").expect("строка осталась");
    assert!(stored.bytes.is_empty(), "строка держит метку, а байтов в ней нет");
}

#[test]
fn a_group_avatar_obeys_the_same_limits_as_a_face() {
    // Правило берётся у `avatar::check`, а не пишется заново: разойдись
    // они, в группу можно было бы положить то, чего нельзя себе.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");

    let too_big = png_of(ratatosk_proto::avatar::MAX_AVATAR_BYTES + 1);
    assert!(matches!(
        me.step(200, Input::Command(Command::SetGroupAvatar { chat, bytes: too_big })),
        Err(EngineError::Avatar(_))
    ));
    assert!(matches!(
        me.step(
            300,
            Input::Command(Command::SetGroupAvatar {
                chat,
                bytes: "это не картинка".as_bytes().to_vec()
            })
        ),
        Err(EngineError::Avatar(_))
    ));
    assert_eq!(me.group_avatar_of(&chat).expect("чтение"), None, "отказ ничего не положил");
}

#[test]
fn setting_an_avatar_for_a_group_we_do_not_know_is_refused() {
    let mut me = node(1);
    assert!(matches!(
        me.step(100, Input::Command(Command::SetGroupAvatar { chat: [9u8; 16], bytes: png() })),
        Err(EngineError::UnknownGroup)
    ));
}

#[test]
fn after_leaving_the_owner_cannot_change_the_avatar_either() {
    // Создателем он остался, участником — нет. Отказ приходит от сборки
    // кадра, и он точнее «не создатель»: человек ушёл сам.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::LeaveGroup { chat })).expect("выход");

    assert!(matches!(
        me.step(300, Input::Command(Command::SetGroupAvatar { chat, bytes: png() })),
        Err(EngineError::NotInGroup)
    ));
}

#[test]
fn a_group_avatar_and_its_tag_come_back_after_a_restart() {
    // Тот же путь, которым идёт настоящий перезапуск. Потеряйся метка —
    // картинка менялась бы сама: любая старая выглядела бы новее нулевой.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::SetGroupAvatar { chat, bytes: png() })).expect("картинка");
    let tag = me.groups().get(&chat).expect("группа").avatar_hlc;

    me.restore().expect("подъём");

    assert_eq!(me.group_avatar_of(&chat).expect("чтение"), Some(png()));
    assert_eq!(
        me.groups().get(&chat).expect("группа поднялась").avatar_hlc,
        tag,
        "метка поднялась той же, а не нулевой"
    );
}

#[test]
fn a_removed_avatar_stays_removed_after_a_restart() {
    // Пустые байты — значение, а не отсутствие строки. Пропади строка,
    // после перезапуска метка стала бы нулевой, и прежняя картинка,
    // доехавшая вторым транспортом (§9.2), легла бы обратно.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::SetGroupAvatar { chat, bytes: png() })).expect("картинка");
    me.step(300, Input::Command(Command::SetGroupAvatar { chat, bytes: Vec::new() }))
        .expect("снятие");
    let tag = me.groups().get(&chat).expect("группа").avatar_hlc;

    me.restore().expect("подъём");

    assert_eq!(me.group_avatar_of(&chat).expect("чтение"), None);
    assert_eq!(me.groups().get(&chat).expect("группа").avatar_hlc, tag, "метка снятия пережила");
}

/// Собеседник, до которого **есть чем** достучаться.
///
/// Отличается от [`stranger`] одним — непустым onion-адресом, — и разница
/// здесь вся: с пустой карточкой §5.4 честно отвечает «ехать некуда»,
/// доставка не откладывается и в очередь не попадает. А проверять надо
/// именно очередь.
fn reachable_stranger(seed: u8) -> ContactCard {
    ContactCard {
        onion: ratatosk_crypto::OnionKey::from_seed([seed; 32]).address(),
        ..stranger(seed)
    }
}

/// Начало отпечатка — чтобы жалоба теста называла, о ком речь.
fn who(peer_ik: &[u8; 32]) -> String {
    peer_ik[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Номер сообщения, только что сказанного в этот чат.
///
/// Нужен затем, что в очереди лежат **не только** копии сообщения:
/// приглашение кладёт туда же вводный блок, состав и карточки — каждому
/// участнику своим кадром и со своим номером. Первая редакция обоих тестов
/// ниже брала из очереди «первую строку этого участника» и получала кадр
/// приглашения, а потом искала его номер у остальных — где его нет и быть
/// не может. Тест падал на исправном коде, и падал справедливо: он
/// проверял не то, что называл.
fn said(alice: &Node, chat: [u8; 16], text: &str) -> [u8; 16] {
    // По тексту, а не по «первой записи»: порядок истории задаёт §9.1,
    // и опираться на него там, где нужен конкретный номер, — лишний повод
    // однажды взять чужой.
    alice
        .store()
        .messages(&chat, 50, None)
        .expect("история")
        .into_iter()
        .find(|stored| stored.body == text.as_bytes())
        .expect("сказанное обязано лечь в историю")
        .msg_id
}

/// Заводит группу с тремя достижимыми участниками.
fn trio(alice: &mut Node) -> ([u8; 16], Vec<[u8; 32]>) {
    let chat = create(alice, 1_000, "трое");
    let members = (2..=4)
        .map(|seed| {
            let card = reachable_stranger(seed);
            let ik = befriend(alice, &card);
            invite(alice, 1_100 + u64::from(seed), chat, ik);
            ik
        })
        .collect();
    (chat, members)
}

#[test]
fn every_member_gets_its_own_row_in_the_queue() {
    // Разбор поломки со стенда: «в группах сообщения доходят не всегда
    // и не до всех, через некоторое время чинится, а недошедшие так
    // и не доходят».
    //
    // Сообщение в группу — это N доставок с **одним** номером (§11.3:
    // копию каждому шлёт сам отправитель). Очередь же обходилась с ними
    // по одному номеру: «уже отложено» отвечало второму и всем следующим,
    // и в ожидании оставался ровно один недостижимый участник из скольких
    // угодно. Остальные теряли сообщение молча.
    //
    // Проверяется поэтому **число строк в очереди**, а не факт отправки:
    // отправки здесь нет вовсе — onion у всех в карточке есть, но не поднят,
    // и §5.4 честно откладывает.
    let mut alice = node(1);
    let (chat, members) = trio(&mut alice);

    alice
        .step(2_000, Input::Command(Command::SendText { chat, text: "всем".to_owned() }))
        .expect("сообщение в группу");

    // Номер **этого** сообщения, а не первой попавшейся строки в очереди:
    // там лежат и кадры приглашения, у каждого свой номер.
    let msg_id = said(&alice, chat, "всем");
    let queued = alice.store().outbox().expect("очередь");
    let copies: Vec<[u8; 32]> =
        queued.iter().filter(|e| e.msg_id == msg_id).map(|e| e.recipient_ik).collect();
    for member in &members {
        assert!(
            copies.contains(member),
            "у участника {} нет копии в очереди: {:?}",
            who(member),
            copies.iter().map(who).collect::<Vec<_>>()
        );
    }
    assert_eq!(copies.len(), members.len(), "по копии на участника и ни одной лишней");
}

#[test]
fn a_retired_copy_does_not_take_the_others_with_it() {
    // Вторая половина той же поломки, и она объясняет «недошедшие так
    // и не доходят». Уборка очереди ехала побочным действием статуса
    // и по одному номеру: первая дошедшая копия уносила — из памяти
    // и с диска — копии всех участников, до которых в тот момент было
    // не достучаться.
    //
    // Проверяется на хранилище напрямую: снятие одной доставки обязано
    // оставить остальные. Ровно этого не делал ни `delete_outbox` (ходил
    // по номеру), ни `MemoryStore` (держал карту по номеру) — и потому
    // поломку не мог увидеть ни один тест на памяти.
    let mut alice = node(1);
    let (chat, members) = trio(&mut alice);
    alice
        .step(2_000, Input::Command(Command::SendText { chat, text: "всем".to_owned() }))
        .expect("сообщение в группу");

    let msg_id = said(&alice, chat, "всем");
    alice.store_mut().delete_outbox(&msg_id, &members[0]).expect("снятие одной доставки");

    let left = alice.store().outbox().expect("очередь");
    assert!(
        !left.iter().any(|e| e.msg_id == msg_id && e.recipient_ik == members[0]),
        "снятая доставка обязана уйти"
    );
    for member in &members[1..] {
        assert!(
            left.iter().any(|e| e.msg_id == msg_id && e.recipient_ik == *member),
            "а доставка участнику {} обязана остаться",
            who(member)
        );
    }
}

#[test]
fn a_member_without_a_card_is_waited_for_not_dropped() {
    // Третья половина, и она объясняет «при добавлении участника до него
    // не сразу начинают доходить». Участник появляется в составе раньше,
    // чем его карточка (§11.5, она едет своим кадром), и копия ему
    // **выбрасывалась** молча: приезд карточки чинил следующие сообщения,
    // а сказанное в это окно не доезжало никогда.
    //
    // **Дверь здесь другая, и это надо знать.** Настоящий случай — блок
    // состава от третьего узла, обогнавший карточку, — требует группы
    // между двумя живыми ядрами, а такой оснастки в наборе нет вовсе
    // (см. `scenarios.rs`: сценарий §16 про исключение по этой же причине
    // остался на учебном узле). Ветка кода при этом ровно та же: участник
    // в составе есть, контакта нет.
    let mut alice = node(1);
    let (chat, members) = trio(&mut alice);
    let orphan = members[0];

    // Контакт убран, участник в составе остался: §11.4 — это разные
    // действия, и удаление контакта из группы никого не выводит.
    alice
        .step(
            1_500,
            Input::Command(Command::DeleteContact { peer_ik: orphan, purge_history: false }),
        )
        .expect("контакт удалён");
    assert!(
        alice.groups()[&chat].group.contains(&orphan),
        "удаление контакта не выводит из группы"
    );

    alice
        .step(2_000, Input::Command(Command::SendText { chat, text: "всем".to_owned() }))
        .expect("сообщение в группу");

    let msg_id = said(&alice, chat, "всем");
    let queued = alice.store().outbox().expect("очередь");
    let copies: Vec<[u8; 32]> =
        queued.iter().filter(|e| e.msg_id == msg_id).map(|e| e.recipient_ik).collect();
    assert!(
        copies.contains(&orphan),
        "копия участнику без карточки обязана ждать её, а не пропасть: {:?}",
        copies.iter().map(who).collect::<Vec<_>>()
    );
    // И остальным она при этом не помешала: прежде `?` в рассылке обрывал
    // цикл на первом же спотыкнувшемся участнике.
    for member in &members[1..] {
        assert!(copies.contains(member), "участник {} обязан получить копию", who(member));
    }
}
