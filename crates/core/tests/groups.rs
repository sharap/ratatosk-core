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
use ratatosk_proto::{channel, group};
use ratatosk_store::{MemoryBlobs, MemoryStore, Store, StoredGroup, StoredMembershipOp};

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
        nostr: Vec::new(),
        nostr_relays: Vec::new(),
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
fn an_invitation_leaves_the_sender_chain_alone() {
    // **Было наоборот, и менялось это зря.**
    //
    // §11.5 требует, чтобы новичок не вывел ключи прошлых сообщений, и
    // до фазы 2 это делалось поворотом: каждое вступление заводило всем
    // писателям новую цепочку. Цель верная, средство избыточное — новичку
    // отдаётся состояние на **текущей** позиции, а ретчет назад
    // не разворачивается. Прошлое закрывает он, а не политика.
    //
    // Цена поворота была не нулевой: он обнулял `counter` при каждом
    // вступлении, и номер переставал быть непрерывным. Фазе 2 он нужен
    // непрерывным.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;
    let before = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);

    let after = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");
    assert_eq!(after.chain, before.chain, "вступление цепочку не трогает");
    assert_eq!(after.counter, before.counter, "и номер не обнуляет");
    assert_eq!(
        (after.chain_wall, after.chain_logical),
        (before.chain_wall, before.chain_logical),
        "метка старшинства тоже на месте: цепочка не менялась, и говорить о смене нечего"
    );
}

#[test]
fn a_number_stays_continuous_across_invitations() {
    // **Предусловие фазы 2, а не украшение.** На непрерывном номере автора
    // стоят have-вектор (§7.2) и обнаружение пропуска (§7.3): узел, имеющий
    // 46 и 48, обязан **знать**, что 47 существует. Обнулись номер на каждом
    // вступлении — и знать было бы нечего.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;
    let chat_of =
        |e: &Node| e.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    let first = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, first);
    me.step(250, Input::Command(Command::SendText { chat, text: "слово".into() })).expect("текст");
    let after_word = chat_of(&me).counter;
    assert!(after_word > 0, "сказанное продвинуло номер");

    let second = befriend(&mut me, &stranger(8));
    invite(&mut me, 300, chat, second);

    assert_eq!(chat_of(&me).counter, after_word, "второе вступление номер не сбрасывает");
    assert_eq!(me.groups()[&chat].group.len(), 3);
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
fn an_eviction_starts_a_new_sender_chain() {
    // **Ради чего исключение перестало быть социальным (§11.4, фаза 2).**
    //
    // Раньше здесь не поворачивалось ничего, и обоснование стояло в коде:
    // «менять поздно, прошлое он уже прочёл». Про прошлое верно — забрать
    // прочитанное нельзя. Про будущее было неверно: sender-цепочка идёт
    // вперёд от состояния, которое у исключённого на руках, и всё, что
    // группа напишет дальше, он прочёл бы, просто перехватывая кадры.
    //
    // Теперь состав уменьшился — цепочка новая, и перехваченное
    // не открывается.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let mine = me.own_card().ik;
    let guest = befriend(&mut me, &stranger(9));
    invite(&mut me, 200, chat, guest);
    let before = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");

    me.step(300, Input::Command(Command::EvictFromGroup { chat, peer_ik: guest }))
        .expect("исключение");

    let after = me.store().sender_chain(&chat, &mine).expect("хранилище").expect("есть");
    assert_ne!(after.chain, before.chain, "убыль состава обязана поворачивать цепочку");
    assert_eq!(after.counter, 0, "новая цепочка начинается с нуля");
    // Именно **новая**, а не продвинутая: продвижение выводится из прежнего
    // состояния, которое у исключённого осталось.
    assert!(
        (after.chain_wall, after.chain_logical) > (before.chain_wall, before.chain_logical),
        "метка поворота обязана расти — по ней получатель отличает свежую цепочку от опоздавшей"
    );
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

// --- Профиль (фаза 2, §3.2) -----------------------------------------------

/// Поднимает узел над хранилищем, в котором уже лежит группа с этим
/// профилем. Так выглядит база, записанная другой сборкой.
fn node_over_a_group_with_profile(seed: u8, profile: u32) -> Node {
    let identity = Identity::from_seed([seed; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция");
    store
        .put_group(&StoredGroup {
            chat_id: [9u8; 16],
            // **Владелец — чужой, и это важно.** Себе владельцем правила
            // канала не отказывают ни в чём (5вп), и заготовка с нами
            // в роли владельца проверяла бы не то: «представления нет»
            // перестало бы значить «прав нет».
            owner_ik: [200u8; 32],
            title: "лента".to_owned(),
            title_wall: 0,
            title_logical: 0,
            created_ms: 100,
            profile,
        })
        .expect("группа легла");
    // Себя в состав — иначе это не «чат, в котором мы состоим», а чужой,
    // и всякая проверка упиралась бы в состав раньше, чем во что-либо
    // ещё. Метка своя: OR-Set разрешает порядок сам, а подъём читает
    // именно операции.
    store
        .put_membership(
            &[9u8; 16],
            &[StoredMembershipOp {
                member_ik: identity.public().ik,
                tag_wall: 100,
                tag_logical: 0,
                tag_actor: identity.public().ik,
                tag_uniq: [1u8; 8],
                removed: false,
            }],
        )
        .expect("состав лёг");
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

#[test]
fn a_group_created_here_is_closed_and_stays_closed_across_a_restart() {
    // §14: группы фазы 1 остаются `closed` навсегда. Проверяется и после
    // подъёма: профиль едет с диска, и потеряйся он там — канал после
    // перезапуска стал бы группой, где писать вправе все.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert_eq!(me.groups().get(&chat).expect("группа").profile, group::Profile::Closed);

    me.restore().expect("подъём");
    assert_eq!(me.groups().get(&chat).expect("группа поднялась").profile, group::Profile::Closed);
}

#[test]
fn a_channel_rises_as_a_channel() {
    // Пара к следующей проверке: знакомый профиль обязан подниматься,
    // иначе «не поднялся» ничего не значило бы.
    let me = node_over_a_group_with_profile(1, group::Profile::Channel.code());
    assert_eq!(
        me.groups().get(&[9u8; 16]).expect("канал поднялся").profile,
        group::Profile::Channel
    );
}

#[test]
fn a_chat_with_an_unknown_profile_does_not_rise() {
    // **Главная проверка профиля.** Строку написала сборка новее нашей.
    // Прочти мы её как `closed` — и получили бы чат, где, по нашему
    // мнению, писать вправе все, хотя владелец этого не разрешал.
    // Молчание здесь — то же поведение, что у сторожа версии провода
    // (5вм): чужую версию встречают отказом, а не догадкой.
    let me = node_over_a_group_with_profile(1, 7);
    assert!(me.groups().get(&[9u8; 16]).is_none(), "незнакомую породу поднимать нельзя");
    assert!(me.groups().is_empty(), "и ничего вместо неё тоже");
}

// --- Заведение канала (фаза 2, §6.1) --------------------------------------

/// Заводит канал и отдаёт его идентификатор.
fn create_channel(engine: &mut Node, now_ms: u64, title: &str, open: bool) -> [u8; 16] {
    let effects = engine
        .step(
            now_ms,
            Input::Command(Command::CreateChannel {
                title: title.to_owned(),
                open,
                history_all: true,
            }),
        )
        .expect("канал заводится");
    let mut found = None;
    for effect in effects {
        if let Effect::Notify(Event::ChannelCreated { chat, title: said, open: said_open }) = effect
        {
            assert_eq!(said, title, "название в событии — то же, что легло");
            assert_eq!(said_open, Some(open), "порода в событии — та же, что просили");
            found = Some(chat);
        }
    }
    found.expect("событие о заведении канала")
}

#[test]
fn a_channel_is_a_group_with_a_channel_profile() {
    // **Главное про канал в ядре.** Он лежит там же, где группы, — оттого
    // сорок развилок «группа или 1:1» остались верными без единой новой
    // ветки. Владелец в составе: он пишет, а пишущий обязан состоять.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);

    let state = me.groups().get(&chat).expect("канал лежит среди групп");
    assert_eq!(state.profile, group::Profile::Channel);
    assert_eq!(state.title, "лента");
    assert_eq!(state.group.owner, Identity::from_seed([1u8; 32]).public().ik, "владелец — мы");
    assert!(
        state.group.contains(&Identity::from_seed([1u8; 32]).public().ik),
        "владелец состоит в своём канале"
    );
}

#[test]
fn a_fresh_channel_has_a_signed_representation_of_version_one() {
    // Версия начинается с единицы, а не с нуля: ссылка называет
    // **минимальную** версию (§10.1), и нулевая не отличалась бы
    // от «версии не назвали».
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);

    let stored = me.store().channel(&chat).expect("чтение").expect("представление легло");
    assert_eq!(stored.version, 1);
    assert_eq!(stored.owner_ik, Identity::from_seed([1u8; 32]).public().ik);
    assert_eq!(stored.kind, u32::try_from(channel::Kind::Open.code()).unwrap());
    assert_eq!(stored.title, "лента");
    assert!(stored.grants.is_empty(), "владельца среди выдач нет: у него всё и всегда (5вп)");

    // **Подпись проверяется над принятыми байтами, а не над пересобранными.**
    // Разойдись канонизация на байт — документ, проверившийся при заведении,
    // перестал бы проверяться после перезапуска, и наружу это вышло бы
    // каналом, который вдруг перестал быть своим.
    let value = ratatosk_codec::Value::Map(vec![
        (
            ratatosk_codec::Value::Integer(13.into()),
            ratatosk_codec::Value::Bytes(stored.block_bytes.clone()),
        ),
        (
            ratatosk_codec::Value::Integer(14.into()),
            ratatosk_codec::Value::Bytes(stored.signature.to_vec()),
        ),
    ]);
    let unchecked = channel::parse_representation(&value).expect("разбирается");
    let checked = unchecked
        .verify(&Identity::from_seed([1u8; 32]).public())
        .expect("подпись владельца сходится");
    assert_eq!(checked.version, 1);
    assert_eq!(checked.kind, channel::Kind::Open);
    assert_eq!(checked.pow_bits, channel::DEFAULT_POW_BITS);
    assert_eq!(checked.seed_days, channel::DEFAULT_SEED_DAYS);
    assert_eq!(checked.seed_bytes, channel::DEFAULT_SEED_BYTES);
}

#[test]
fn the_kind_of_a_channel_is_what_the_command_said() {
    // Порода задаётся при заведении и не меняется (§6.1): это разные
    // обещания, и перехода между ними нет. Проверяется обе стороны —
    // иначе `open` мог бы не доезжать вовсе и тест этого не заметил бы.
    let mut me = node(1);
    let open = create_channel(&mut me, 100, "открытый", true);
    let closed = create_channel(&mut me, 200, "по приглашению", false);

    let kind = |chat: &[u8; 16]| me.store().channel(chat).unwrap().unwrap().kind;
    assert_eq!(kind(&open), u32::try_from(channel::Kind::Open.code()).unwrap());
    assert_eq!(kind(&closed), u32::try_from(channel::Kind::ByInvite.code()).unwrap());
}

#[test]
fn a_channel_comes_back_a_channel_after_a_restart() {
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    me.restore().expect("подъём");

    let state = me.groups().get(&chat).expect("канал поднялся");
    assert_eq!(state.profile, group::Profile::Channel, "профиль обязан пережить перезапуск");
    assert_eq!(state.title, "лента");
    assert_eq!(me.store().channel(&chat).unwrap().unwrap().version, 1);
}

#[test]
fn a_channel_title_obeys_the_same_two_limits_as_a_group() {
    // **Пределов два, и они обязаны сходиться.** В символах — тот же,
    // что у группы: поле ввода одно, и два ответа на «почему не влезает»
    // у него быть не должно. В байтах — предел представления.
    //
    // Проверка стоит здесь, а не в `proto`: предел в символах живёт
    // в ядре, предел в байтах — в протоколе, и связать их можно только
    // отсюда. Разведи их кто-нибудь — название из эмодзи, законное
    // для группы, канал отверг бы, и объяснить это было бы нечем.
    let mut me = node(1);

    assert!(matches!(
        me.step(
            100,
            Input::Command(Command::CreateChannel {
                title: "  ".to_owned(),
                open: true,
                history_all: true
            })
        ),
        Err(EngineError::GroupTitleEmpty)
    ));
    assert!(matches!(
        me.step(
            200,
            Input::Command(Command::CreateChannel {
                history_all: true,
                title: "я".repeat(MAX_GROUP_TITLE_CHARS + 1),
                open: true,
            })
        ),
        Err(EngineError::GroupTitleTooLong)
    ));

    // Самое дорогое законное название: предел в символах, по четыре байта
    // на символ. Оно обязано пройти — иначе байтовый предел уже тесен.
    let longest = "\u{1f600}".repeat(MAX_GROUP_TITLE_CHARS);
    assert_eq!(longest.chars().count(), MAX_GROUP_TITLE_CHARS);
    assert!(longest.len() <= channel::MAX_TITLE_BYTES, "байтовый предел уже символьного");
    let chat = create_channel(&mut me, 300, &longest, true);
    assert_eq!(me.store().channel(&chat).unwrap().unwrap().title, longest);
}

// --- Право писать (фаза 2, §6.2) -------------------------------------------

/// Переписывает представление канала, выдав этому человеку эти права.
///
/// Мимо ядра, руками: команды выдачи прав ещё нет, а проверка нужна уже
/// сейчас. Подпись здесь не настоящая — `check_may_put` читает
/// разобранную таблицу выдач, а не проверяет документ заново.
fn grant_in_channel(engine: &mut Node, chat: &[u8; 16], who: [u8; 32], rights: u32, until_ms: u64) {
    let mut stored = engine.store().channel(chat).unwrap().expect("представление");
    stored.version += 1;
    // Ключ проверки кладётся тем же, что у настоящей выдачи (§6.2):
    // читателям канала брать его больше неоткуда (§3.2).
    let sk = Identity::from_seed([1u8; 32]).public().sk;
    stored.grants = vec![ratatosk_store::StoredGrant { who, sk, rights, until_ms }];
    engine.store_mut().put_channel(&stored).expect("новая версия легла");
}

#[test]
fn the_owner_may_always_speak_in_his_own_channel() {
    // Пара ко всему, что ниже: у владельца все права и отнять их нельзя
    // (5вп). Не будь этой проверки, «отказано» ничего не значило бы —
    // могло бы отказывать всем подряд.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);
    me.step(200, Input::Command(Command::SendText { chat, text: "слово".to_owned() }))
        .expect("владелец пишет в свой канал");
}

#[test]
fn a_subscriber_without_the_write_right_is_refused_by_name() {
    // **Первое место, где профили расходятся.** В группе пишут все, кто
    // состоит; в канале — по праву. Отказ отдельный от `NotInGroup`:
    // «вас тут нет» и «вы тут есть, но это вам не разрешено» требуют
    // от человека разного.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);

    // Владелец меняется на чужого: так выглядит канал, на который мы
    // подписаны, а не наш.
    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();

    assert!(matches!(
        me.step(200, Input::Command(Command::SendText { chat, text: "слово".to_owned() })),
        Err(EngineError::NotAllowedInChannel)
    ));
}

#[test]
fn a_granted_right_lets_the_words_through_and_an_expired_one_does_not() {
    // **Срок, а не отзыв** (§6.3). Не продлил — истекло само; молчание
    // владельца отказывает вниз, а не вверх. Проверяется обеими
    // сторонами одного мгновения, иначе «истекло» могло бы значить
    // «не работало никогда».
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);
    let mine = Identity::from_seed([1u8; 32]).public().ik;

    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();
    grant_in_channel(&mut me, &chat, mine, channel::Rights::WRITE.bits(), 5_000);

    // **Пока срок идёт — слово уходит.** Раньше здесь стоял отказ
    // «в канале публикует владелец»: у держателя права не было дороги —
    // состава он не знает (§3.2). Дорога появилась (слово едет владельцу
    // и своим сидам), и проверка сказала об этом первой: имя её обещало
    // «право пускает слова», а стерегла она обратное.
    assert!(
        me.step(4_999, Input::Command(Command::SendText { chat, text: "успел".to_owned() }))
            .is_ok(),
        "пока срок идёт, право пускает слово"
    );
    assert!(
        matches!(
            me.step(5_000, Input::Command(Command::SendText { chat, text: "опоздал".to_owned() })),
            Err(EngineError::NotAllowedInChannel)
        ),
        "ровно в назначенный миг право уже не действует"
    );

    // Чего эта проверка **не** стережёт: что истёкшее право отвергается
    // на **приёме**. Сегодня своей сборкой такой кадр не собрать вовсе,
    // и стережёт это `a_word_from_someone_whose_right_expired_is_not_taken`
    // в `pair.rs` — там кадр собирает чужая сборка.
}

#[test]
fn the_write_right_does_not_let_you_rename_the_channel() {
    // §6.2 раздаёт разные права разным действиям: слова — «писать»,
    // название и картинка — «менять представление». Одно право,
    // дающее оба, означало бы, что список прав короче, чем написано.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);
    let mine = Identity::from_seed([1u8; 32]).public().ik;

    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();
    grant_in_channel(&mut me, &chat, mine, channel::Rights::WRITE.bits(), u64::MAX);

    // Право писать у нас есть — и слово уходит: §6.2 даёт право,
    // а дорогу даёт рой (слово едет владельцу и своим сидам).
    assert!(
        me.step(200, Input::Command(Command::SendText { chat, text: "слово".to_owned() })).is_ok(),
        "право писать пускает слово"
    );
    // **Владельцем группы мы остались** — сменился владелец представления,
    // и правило §11.2 «только создатель» сюда не вмешивается. Значит
    // отказывает ровно то, ради чего проверка написана: у нас есть
    // «писать» и нет «менять представление».
    //
    // Сперва здесь стояло `is_err()` с объяснением «упрётся в §11.2»,
    // и объяснение было неверным. Показала это поломка: сделай
    // `Rename` требующим `WRITE` — и переименование **проходит**,
    // чего при упоре в §11.2 случиться бы не могло.
    assert!(
        matches!(
            me.step(300, Input::Command(Command::RenameGroup { chat, title: "не я".to_owned() })),
            Err(EngineError::NotAllowedInChannel)
        ),
        "право писать не даёт менять представление"
    );
}

#[test]
fn with_the_edit_right_a_delegate_renames_the_channel_by_an_action() {
    // **Право «менять представление» было мёртвым.** Команда отказывала
    // «не владелец» ещё до вопроса о праве: выдать `EDIT` было можно,
    // а воспользоваться — нет. Теперь держатель правит название
    // действием (§6.2), оно едет владельцу и сидам той же дорогой, что
    // слово, а владелец подписывает названное новой версией документа
    // (`a_rename_by_the_edit_holder_reaches_everyone_and_survives_the_next_document`
    // на стенде).
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    let mine = Identity::from_seed([1u8; 32]).public().ik;

    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();
    grant_in_channel(&mut me, &chat, mine, channel::Rights::EDIT.bits(), u64::MAX);

    me.step(200, Input::Command(Command::RenameGroup { chat, title: "моё".to_owned() }))
        .expect("держатель права «менять представление» переименовывает");
    assert_eq!(me.groups().get(&chat).expect("канал").title, "моё", "название сменилось у себя");
    // Документ при этом не тронут: подписать его может только владелец.
    assert_eq!(me.store().channel(&chat).unwrap().unwrap().title, "лента");
}

#[test]
fn a_channel_without_a_representation_refuses_rather_than_guesses() {
    // Документ не приехал — прав мы не знаем. «Не знаю» обязано
    // отказывать вниз: пиши мы вслепую, кадры уезжали бы в канал,
    // где нас, возможно, и не звали писать, — и вернуть их было бы
    // нечем.
    //
    // Так выглядит канал сразу после перехода по ссылке: строка чата
    // уже есть, представление ещё едет (§10.3).
    let mut me = node_over_a_group_with_profile(1, group::Profile::Channel.code());
    let chat = [9u8; 16];
    assert!(me.store().channel(&chat).unwrap().is_none(), "представления ещё нет");

    assert!(matches!(
        me.step(200, Input::Command(Command::SendText { chat, text: "слово".to_owned() })),
        Err(EngineError::NotAllowedInChannel)
    ));
}

#[test]
fn in_a_group_nobody_is_asked_about_rights() {
    // §3.2: `closed` — буквально фаза 1. Проверка прав туда не должна
    // добраться вовсе: там пишут все, кто состоит, и вопроса
    // не существует.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    me.step(200, Input::Command(Command::SendText { chat, text: "слово".to_owned() }))
        .expect("в группе пишут все, кто состоит");
    assert!(
        me.store().channel(&chat).unwrap().is_none(),
        "у группы представления нет — и спрашивать его незачем"
    );
}

// --- Свёртка состава (фаза 2, §6.7, §12) ----------------------------------

/// Горизонт свёртки: раньше него сворачивать нечего.
const FOLD_AFTER: u64 = group::MEMBERSHIP_FOLD_AFTER_MS;

#[test]
fn nothing_is_folded_before_the_horizon() {
    // Пара ко всему остальному: свёртка не должна срабатывать раньше
    // времени, иначе она теряла бы операции, которые ещё в пути.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let before = me.store().membership(&chat).unwrap().len();
    assert!(before > 0, "своё добавление обязано лежать операцией");

    assert_eq!(me.compact_if_due(1_000).unwrap(), 0, "уборке ещё не пора");
    assert_eq!(me.store().membership(&chat).unwrap().len(), before);
    assert_eq!(me.store().group_baseline(&chat).unwrap(), None, "знака ещё нет");
}

#[test]
fn old_membership_is_folded_and_the_watermark_is_written() {
    // **Ради чего свёртка существует**: история состава не растёт вечно.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    for (seed, at) in [(2u8, 200u64), (3, 300), (4, 400)] {
        add_and_remove(&mut me, chat, seed, at);
    }
    let before = me.store().membership(&chat).unwrap().len();
    // **Четыре строки, а не шесть.** Ключ строки — метка целиком,
    // и удаление гасит **ту же** метку, которую поставило добавление:
    // обе ложатся в одну ячейку, и остаётся строка с надгробием.
    // То есть история состава и так вдвое короче, чем кажется по числу
    // действий, — но всё равно растёт, и вот это свёртка и убирает.
    assert_eq!(before, 4, "своё добавление и три погашенных");

    let later = FOLD_AFTER + 10_000;
    me.compact_if_due(later).expect("уборка");

    let after = me.store().membership(&chat).unwrap();
    assert!(after.len() < before, "свёрнутая история обязана стать короче: было {before}");
    assert_eq!(after.len(), 1, "остался один участник — мы сами");
    let (wall, _) = me.store().group_baseline(&chat).unwrap().expect("знак поставлен");
    assert_eq!(wall, 10_000, "знак отстаёт от «сейчас» ровно на горизонт");

    // Состав при этом не изменился — ни в памяти, ни после подъёма.
    let mine = Identity::from_seed([1u8; 32]).public().ik;
    assert_eq!(
        me.groups().get(&chat).unwrap().group.members().copied().collect::<Vec<_>>(),
        vec![mine]
    );
    me.restore().expect("подъём");
    assert_eq!(
        me.groups().get(&chat).unwrap().group.members().copied().collect::<Vec<_>>(),
        vec![mine]
    );
}

#[test]
fn a_folded_add_does_not_come_back_after_a_restart() {
    // **Главная проверка свёртки.** §6.7: операция старше знака
    // отвергается — «иначе выброшенное добавление воскреснет, приехав
    // от третьего участника». Работает это только если знак пережил
    // подъём; не переживи он, воскрешение случилось бы при первом же
    // перезапуске, и свёртка не значила бы ничего.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    let evicted = add_and_remove(&mut me, chat, 2, 200);

    me.compact_if_due(FOLD_AFTER + 10_000).expect("уборка");
    assert!(!me.groups().get(&chat).unwrap().group.contains(&evicted));

    me.restore().expect("подъём");
    assert_eq!(
        me.store().group_baseline(&chat).unwrap().map(|(w, _)| w),
        Some(10_000),
        "знак обязан пережить подъём"
    );
    assert!(
        !me.groups().get(&chat).unwrap().group.contains(&evicted),
        "свёрнутое добавление не должно воскресать при подъёме"
    );

    // И то же самое, когда свёрнутое добавление приезжает заново.
    let raised = me.groups().get(&chat).unwrap().group.clone();
    let mut raised = raised;
    raised.apply(ratatosk_crdt::OrSet::prepare_add(
        evicted,
        ratatosk_crdt::Tag::new(
            ratatosk_crdt::Hlc::new(200, 0),
            Identity::from_seed([1u8; 32]).public().ik,
            [7u8; 8],
        ),
    ));
    assert!(!raised.contains(&evicted), "и приехав от третьего — тоже не должно");
}

#[test]
fn the_watermark_does_not_creep_forward_when_there_is_nothing_to_fold() {
    // **Проверка сперва была слабой, и поломка это показала.** Она
    // сверяла, что вторая свёртка «ничего не выбросила», — а выбросить
    // там нечего в любом случае, и снятие сторожа её не роняло.
    //
    // Сторож стережёт другое, и это не про экономию диска. Горизонт
    // сдвигается **всегда**, вместе с часами. Двинь мы знак вперёд,
    // ничего при этом не свернув, — и операция, которая ещё в пути
    // и старше нового знака, будет отвергнута, хотя прежний знак её
    // принял бы. Свёртка сужает то, что мы готовы принять; сужать
    // задаром нельзя.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    add_and_remove(&mut me, chat, 2, 200);

    let first = me.compact_if_due(FOLD_AFTER + 10_000).expect("первая уборка");
    assert!(first > 0, "первая свёртка обязана что-то выбросить");
    let (wall, _) = me.store().group_baseline(&chat).unwrap().expect("знак");
    assert_eq!(wall, 10_000);
    let after = me.store().membership(&chat).unwrap();

    // Уборка **сильно позже**: горизонт ушёл вперёд, а сворачивать
    // по-прежнему нечего.
    me.store_mut().put_meta(ratatosk_store::META_LAST_COMPACTION, &0u64.to_be_bytes()).unwrap();
    let second = me.compact_if_due(FOLD_AFTER + 900_000).expect("вторая уборка");
    assert_eq!(second, 0, "сворачивать нечего");
    assert_eq!(
        me.store().group_baseline(&chat).unwrap().map(|(w, _)| w),
        Some(10_000),
        "знак обязан остаться на месте: двигать его задаром — сужать приём"
    );
    assert_eq!(me.store().membership(&chat).unwrap(), after, "и состав не переписан");
}

#[test]
fn the_blocks_are_not_touched_by_the_fold() {
    // §6.7: знак «не утверждение о составе, а граница применимости»,
    // и подписи у него нет. Блоки возят историю новичку (§11.5),
    // и он проверяет их подписями — выброси мы блоки, отдать ему стало
    // бы нечего, кроме нашего слова. Фаза 2 именно от веры пригласившему
    // и уходит (§3.1).
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    add_and_remove(&mut me, chat, 2, 200);
    let blocks = me.store().membership_blocks(&chat).unwrap().len();
    assert!(blocks > 0, "блоки обязаны лежать");

    me.compact_if_due(FOLD_AFTER + 10_000).expect("уборка");
    assert_eq!(
        me.store().membership_blocks(&chat).unwrap().len(),
        blocks,
        "свёртка блоки не трогает: новичку историю отдавать нечем будет"
    );
}

/// Добавляет участника и тут же исключает — две операции в истории.
fn add_and_remove(engine: &mut Node, chat: [u8; 16], seed: u8, at: u64) -> [u8; 32] {
    let card = stranger(seed);
    let who = befriend(engine, &card);
    engine
        .step(at, Input::Command(Command::InviteToGroup { chat, peer_ik: who }))
        .expect("приглашение");
    engine
        .step(at + 1, Input::Command(Command::EvictFromGroup { chat, peer_ik: who }))
        .expect("исключение");
    who
}

// --- Отписка (фаза 2, §10.6) ----------------------------------------------

#[test]
fn a_group_is_left_and_a_channel_is_unsubscribed_from() {
    // Два разных действия с разными обещаниями: из группы **выходят**,
    // и переписка остаётся; от канала **отписываются**, и вместе с ним
    // уходят ключи чтения. Сведи их в одну команду — и одно обещание
    // молча подменило бы другое.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert!(matches!(
        me.step(200, Input::Command(Command::UnsubscribeFromChannel { chat })),
        Err(EngineError::NotAChannel)
    ));
}

#[test]
fn the_owner_does_not_unsubscribe_from_his_own_channel() {
    // Отписка местная: владелец открытого канала о подписчиках не знает
    // (§10.4) и объявить им ничего не может. Удали он чат у себя —
    // исчез бы ключ подписи представления, и канал остался бы жить
    // у подписчиков без единой возможности им управлять.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", true);
    assert!(matches!(
        me.step(200, Input::Command(Command::UnsubscribeFromChannel { chat })),
        Err(EngineError::CannotUnsubscribeOwnChannel)
    ));
}

#[test]
fn unsubscribing_wipes_the_read_keys_and_lets_the_same_link_be_taken_again() {
    // Две половины одного обещания §10.6, и порознь они ничего не значат:
    // ключи обязаны исчезнуть (иначе «архив закрылся» — ложь), а чат
    // обязан перестать существовать настолько, чтобы та же ссылка снова
    // считалась новой (иначе человек, передумавший дважды, упирается
    // в «вы уже подписаны» навсегда).
    let mut me = node(1);
    let uri = open_channel_link();
    me.step(100, Input::Command(Command::SubscribeToChannel { uri: uri.clone() }))
        .expect("подписка по ссылке");
    let chat = *me.groups().keys().next().expect("канал завёлся");
    assert!(
        !me.store().archive_keys(&chat).unwrap().is_empty(),
        "у открытого канала ключ чтения приезжает ссылкой — иначе проверка ниже пуста"
    );

    me.step(200, Input::Command(Command::UnsubscribeFromChannel { chat })).expect("отписка");
    assert!(me.groups().get(&chat).is_none(), "чата больше нет");
    assert!(me.store().archive_keys(&chat).unwrap().is_empty(), "ключи чтения стёрты");
    assert!(me.store().subscription(&chat).unwrap().is_none(), "подписка стёрта");

    me.step(300, Input::Command(Command::SubscribeToChannel { uri }))
        .expect("та же ссылка снова считается новой");
}

/// Ссылка на открытый канал чужого владельца — как её присылает человек.
///
/// Собирается здесь, а не берётся у ядра: своя ссылка вела бы на свой же
/// канал, а отписка от своего запрещена. Ключ в ссылке и есть порода
/// (§6.1).
fn open_channel_link() -> String {
    channel::Invitation {
        group: [77u8; 16],
        owner: Identity::from_seed([200u8; 32]).public().ik,
        min_version: 1,
        key: Some([5u8; 32]),
        endpoints: Vec::new(),
    }
    .to_uri()
    .expect("ссылка собирается")
}

#[test]
fn granting_a_right_to_the_owner_is_refused_by_its_own_name() {
    // **Поломка, найденная на стенде.** Владелец набрал свой ключ вместо
    // чужого и услышал «в этом канале у вас нет права на это действие» —
    // то есть неправду: право у него как раз есть, и отнять его нельзя
    // (5вп). Выдача ему бессмысленна по другой причине, и сказать надо
    // именно её, иначе человек идёт искать, кто отнял у него права.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    let mine = Identity::from_seed([1u8; 32]).public().ik;

    assert!(matches!(
        me.step(
            200,
            Input::Command(Command::SetChannelRight {
                chat,
                who: mine,
                rights: channel::Rights::WRITE.bits(),
                until_ms: u64::MAX,
            })
        ),
        Err(EngineError::OwnerNeedsNoGrant)
    ));

    // **Пара к ней, и без неё первая половина ничего не значит:** тот же
    // отказ у не-владельца обязан остаться прежним — «нет права». Два
    // разных отказа на два разных положения.
    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();
    assert!(matches!(
        me.step(
            300,
            Input::Command(Command::SetChannelRight {
                chat,
                who: [7u8; 32],
                rights: channel::Rights::WRITE.bits(),
                until_ms: u64::MAX,
            })
        ),
        Err(EngineError::NotAllowedInChannel)
    ));
}

// --- Факты канала для клиента (фаза 2, §6.2, §6.3, §6.4) -------------------

#[test]
fn a_group_has_no_channel_facts_at_all() {
    // Признак «это канал» выражен **наличием записи**: у группы канального
    // экрана нет, и отдельного булева поля для этого не заводится.
    let mut me = node(1);
    let chat = create(&mut me, 100, "у костра");
    assert!(me.channel_facts(&chat, 200).is_none(), "у группы канальных фактов не бывает");
}

#[test]
fn the_facts_of_a_fresh_channel_say_what_the_owner_may_do() {
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    let facts = me.channel_facts(&chat, 200).expect("факты канала");

    assert_eq!(facts.version, 1, "версия начинается с единицы: ссылка называет минимальную");
    assert_eq!(facts.open, Some(false), "порода доказана подписанным документом");
    assert_eq!(facts.rights, channel::Rights::all().bits(), "у владельца все права (5вп)");
    assert_eq!(facts.rights_until_ms, 0, "у владельца срока нет и быть не может");
    assert!(facts.readable, "ключ чтения родится вместе с каналом");
    assert!(!facts.awaiting, "свой канал не ждёт ничьего впуска");
    assert!(
        facts.may_rotate,
        "нулевое поколение никому не рассылалось: предел недели не считается"
    );
    assert_eq!(facts.grants_expiring, 0, "выдач нет — и продлевать нечего");
}

#[test]
fn the_facts_do_not_promise_a_kind_the_link_only_claimed() {
    // §10.2: адреса и обещания ссылки ничем не подписаны. Покажи мы
    // обещанную породу установленной, человек прочёл бы «открытый канал»
    // там, где владелец обещал другое, — и решил бы, что читать можно
    // уже сейчас.
    let mut me = node(1);
    me.step(100, Input::Command(Command::SubscribeToChannel { uri: open_channel_link() }))
        .expect("подписка по ссылке");
    let chat = *me.groups().keys().next().expect("канал завёлся");

    let facts = me.channel_facts(&chat, 200).expect("факты канала");
    assert_eq!(facts.open, None, "породу называет документ, а не ссылка");
    assert_eq!(facts.version, 0, "документа ещё нет");
    assert_eq!(facts.rights, 0, "«не знаю» отказывает вниз (§6.2)");
    assert!(!facts.may_rotate, "не зная породы, поворот обещать нельзя");
}

#[test]
fn an_expiring_grant_is_counted_for_the_owner_and_not_for_anyone_else() {
    // §6.3 велит продлевать заранее: «владелец зашёл, у выдачи осталось
    // меньше месяца — продлить». Число повторено руками, а не взято
    // из ядра: оно стережёт обещание, и подними кто-нибудь порог
    // до квартала, проверка обязана это заметить.
    const MONTH_MS: u64 = 30 * 24 * 60 * 60 * 1000;
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    let stranger = Identity::from_seed([200u8; 32]).public().ik;

    grant_in_channel(&mut me, &chat, stranger, channel::Rights::WRITE.bits(), MONTH_MS * 3);
    let facts = me.channel_facts(&chat, MONTH_MS).expect("факты канала");
    assert_eq!(facts.grants_expiring, 0, "до конца ещё два месяца — продлевать рано");

    let facts = me.channel_facts(&chat, MONTH_MS * 2 + 1).expect("факты канала");
    assert_eq!(facts.grants_expiring, 1, "осталось меньше месяца — сказать надо заранее");

    let facts = me.channel_facts(&chat, MONTH_MS * 3 + 1).expect("факты канала");
    assert_eq!(facts.grants_expiring, 0, "истёкшую продлевать уже поздно: она не действует");
}

#[test]
fn our_own_grant_is_shown_with_its_deadline() {
    // Вторая половина §6.3 — та, что видит подписчик: право кончается
    // само, и «отказ наступает не внезапно» верно только если срок
    // показан заранее.
    let mut me = node(1);
    let chat = create_channel(&mut me, 100, "лента", false);
    let mine = Identity::from_seed([1u8; 32]).public().ik;

    // Владелец — чужой: себе владелец прав не выдаёт (5вп).
    let mut stored = me.store().channel(&chat).unwrap().unwrap();
    stored.owner_ik = [200u8; 32];
    me.store_mut().put_channel(&stored).unwrap();
    grant_in_channel(&mut me, &chat, mine, channel::Rights::WRITE.bits(), 9_000);

    let facts = me.channel_facts(&chat, 5_000).expect("факты канала");
    assert_eq!(facts.rights, channel::Rights::WRITE.bits());
    assert_eq!(facts.rights_until_ms, 9_000, "срок показывается, пока выдача действует");

    let facts = me.channel_facts(&chat, 9_000).expect("факты канала");
    assert_eq!(facts.rights, 0, "истекло — значит нет");
    assert_eq!(facts.rights_until_ms, 0, "и срока показывать больше нечего");
}

// --- Пир, который не контакт (§8.3; фаза 2, §10.4) -------------------------

/// Ссылка с адресами: по ней и узнаётся пир.
fn link_with_addresses() -> (String, [u8; 32]) {
    let owner = Identity::from_seed([200u8; 32]).public().ik;
    let uri = channel::Invitation {
        group: [88u8; 16],
        owner,
        min_version: 1,
        key: None,
        endpoints: vec![
            channel::Endpoint::Onion(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            channel::Endpoint::Chatmail("owner@nine.example".into()),
        ],
    }
    .to_uri()
    .expect("ссылка собирается");
    (uri, owner)
}

#[test]
fn a_channel_link_carries_every_kind_of_address_we_have() {
    // **§10.1 дословно: «`addrs[]` — адреса всех доступных видов, как
    // в карточке контакта».** Ядро клало туда два вида из пяти — onion
    // и почту, — и это нашлось на стенде: у владельца был поднят один
    // nostr, ссылка уехала **без единого адреса**, а подписчику стенд
    // честно сказал «адреса нет». §10.2 обещает ровно обратное: «ссылка
    // провисит год… откроется она через почту и nostr».
    //
    // Числа здесь свои, а не из крейта: проверка стережёт обещание §10.1
    // («все виды»), и возьми она список видов у того же кода, что его
    // собирает, — забытый вид она бы и не заметила.
    let identity = Identity::from_seed([42u8; 32]);
    let mut store = MemoryStore::new();
    store.migrate().expect("миграция");
    let mut me = Engine::new(
        identity,
        store,
        Box::new(MemoryBlobs::new()),
        Box::new(SeededEntropy::new(42)),
        SelfAddresses {
            onion: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            chatmail: "owner@nine.example".to_owned(),
            display_name: "я".to_owned(),
        },
    );
    me.restore().expect("подъём");
    me.step(10, Input::Command(Command::SetYggMode(ratatosk_proto::ygg::YggMode::External)))
        .expect("меш внешним демоном");
    me.step(20, Input::Command(Command::SetYggKey(vec![4u8; 32]))).expect("ключ меша назван");
    me.step(
        30,
        Input::Command(Command::SetTransportEnabled {
            transport: ratatosk_proto::Transport::Nostr,
            enabled: true,
        }),
    )
    .expect("ступень nostr включена");
    me.step(
        40,
        Input::Command(Command::SetNostrRelays(vec!["wss://relay.nine.example".to_owned()])),
    )
    .expect("реле названы");

    let chat = create_channel(&mut me, 100, "вестник", false);
    let link = me.channel_link(chat).expect("ссылка");
    let parsed = channel::Invitation::from_uri(&link).expect("ссылка разбирается");

    let kinds: Vec<&str> = parsed
        .endpoints
        .iter()
        .map(|endpoint| match endpoint {
            channel::Endpoint::Onion(_) => "onion",
            channel::Endpoint::Chatmail(_) => "почта",
            channel::Endpoint::Ygg(_) => "меш",
            channel::Endpoint::Nostr(_) => "ключ nostr",
            channel::Endpoint::NostrRelay(_) => "реле",
        })
        .collect();
    for kind in ["onion", "почта", "меш", "ключ nostr", "реле"] {
        assert!(kinds.contains(&kind), "в ссылке нет вида «{kind}»: {kinds:?}");
    }
    // И ключ — именно наш, а не чужой: перепутанный ключ увёл бы заявку
    // к постороннему, и обнаружилось бы это одной тишиной.
    assert!(
        parsed
            .endpoints
            .iter()
            .any(|e| matches!(e, channel::Endpoint::Nostr(key) if key == me.nostr_key())),
        "ключ nostr в ссылке обязан быть нашим"
    );
}

/// Ссылка, в которой из адресов — одни реле nostr.
///
/// Ровно то, что ядро собирало до починки: реле есть, ключа нет.
fn link_with_relays_only() -> (String, [u8; 32]) {
    let owner = Identity::from_seed([201u8; 32]).public().ik;
    let uri = channel::Invitation {
        group: [89u8; 16],
        owner,
        min_version: 1,
        key: None,
        endpoints: vec![channel::Endpoint::NostrRelay("wss://relay.nine.example".into())],
    }
    .to_uri()
    .expect("ссылка собирается");
    (uri, owner)
}

#[test]
fn someone_who_is_both_a_peer_and_a_contact_is_watched_once() {
    // Список наблюдаемых уезжает в эфир целиком, и повтор в нём стоит
    // двойной сверки каждого чужого объявления — а заодно врёт о числе:
    // на стенде это выглядело как «известных=2 ключи=afabc241,afabc241»
    // про одного собеседника.
    //
    // Состояние законное и сегодня обычное: владелец канала лежит пиром
    // (§10.4), а первым же рукопожатием становится ещё и несверенным
    // контактом — приёмной стороны §8.3 пока нет.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");
    befriend(&mut me, &stranger(200));
    assert!(me.contacts().contains_key(&owner), "он и контакт, и пир — иначе проверка пуста");
    assert!(me.peers().contains_key(&owner));

    let effects = me
        .step(
            200,
            Input::Command(Command::SetTransportEnabled {
                transport: ratatosk_proto::Transport::Lan,
                enabled: true,
            }),
        )
        .expect("локальная сеть включена");
    let watched = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::WatchPeers(peers) => Some(peers.clone()),
            _ => None,
        })
        .expect("список наблюдаемых уезжает транспорту");
    let mut unique = watched.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(watched.len(), unique.len(), "один собеседник — одна строка в списке: {watched:?}");
}

#[test]
fn relays_without_a_key_do_not_make_the_owner_reachable_by_nostr() {
    // **Поломка, найденная на стенде у владельца с одним только nostr.**
    // Доступность пира считалась по списку реле, а раннеру получателем
    // называть нечего: событие на реле адресуется открытым ключом.
    // §5.4 выбирал ступень, раннер отвечал `NoAddress`, лестница
    // кончалась — и заявка (§10.4) не уезжала никуда.
    //
    // У контакта то же самое всегда считалось по ключу (`card.nostr`);
    // это проверка того, что пир решается **тем же** правилом.
    let (mut me, (uri, owner)) = (node(1), link_with_relays_only());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");

    let peer = me.peers().get(&owner).expect("владелец лёг пиром");
    assert_eq!(peer.relays.len(), 1, "реле из ссылки запоминаются — они пригодятся с ключом");
    assert!(peer.nostr.is_empty(), "а ключа в этой ссылке не было");
    assert!(
        !me.availability_for(&owner).expect("доступность").has_nostr,
        "реле без ключа — не адрес: §5.4 не должен выбирать эту ступень"
    );
}

#[test]
fn a_nostr_key_in_the_link_is_what_opens_that_rung() {
    // Вторая половина: с ключом ступень обязана стать годной — иначе
    // проверка выше зелена оттого, что nostr не бывает годен никогда.
    let owner = Identity::from_seed([202u8; 32]).public().ik;
    let uri = channel::Invitation {
        group: [90u8; 16],
        owner,
        min_version: 1,
        key: None,
        endpoints: vec![
            channel::Endpoint::Nostr([3u8; 32]),
            channel::Endpoint::NostrRelay("wss://relay.nine.example".into()),
        ],
    }
    .to_uri()
    .expect("ссылка собирается");

    let mut me = node(1);
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");
    assert_eq!(me.peers().get(&owner).expect("пир").nostr, vec![3u8; 32]);
    assert!(
        me.availability_for(&owner).expect("доступность").has_nostr,
        "ключ приехал — ступень адресуема"
    );

    // И переживает перезапуск: заявка ждёт впуска сутками (§10.4), а
    // процесс на телефоне убивают постоянно.
    me.restore().expect("подъём");
    assert_eq!(me.peers().get(&owner).expect("пир").nostr, vec![3u8; 32]);
    assert!(me.availability_for(&owner).expect("доступность").has_nostr);
}

#[test]
fn a_link_leaves_the_owner_as_a_peer_and_not_as_a_contact() {
    // **§10.4 дословно: «контакт не заводится».** До владельца надо
    // дотянуться заявкой, а заводить его в знакомые — значит показать
    // человеку в списке чатов того, с кем он не разговаривал.
    //
    // Раньше адреса из ссылки выбрасывались вовсе, и дотянуться было
    // нечем. Теперь они ложатся пиром (§8.3) — отдельным списком,
    // который наружу не едет.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");

    assert!(!me.contacts().contains_key(&owner), "владелец не становится контактом (§10.4)");
    let peer = me.peers().get(&owner).expect("а пиром — становится");
    assert_eq!(peer.chatmail, "owner@nine.example", "адреса взяты из ссылки");
    assert!(peer.availability.has_onion && peer.availability.has_chatmail);
    assert!(!peer.availability.has_ygg, "чего в ссылке не было, то и не выдумано");
}

#[test]
fn a_peer_survives_a_restart_with_its_addresses() {
    // Пир лежит на диске (миграция 0031): заявка может ждать владельца
    // сутками, а процесс на телефоне убивают постоянно. Забудь мы пира
    // при подъёме — очередь осталась бы с получателем, которого некуда
    // слать, и её бы вычистили как мусор.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");

    // Сперва — что он **на диске**: карта в памяти о перезапуске ничего
    // не говорит.
    let stored = me.store().peers().expect("пиры с диска");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].chatmail, "owner@nine.example");

    me.restore().expect("подъём");
    let peer = me.peers().get(&owner).expect("пир поднялся с диска");
    assert_eq!(peer.chatmail, "owner@nine.example");
    assert!(peer.availability.has_onion, "и доступность посчитана заново из адресов");
}

#[test]
fn the_ladder_takes_a_peer_just_like_a_contact() {
    // **Главная проверка §8.3.** До пира-не-контакта лестница §5.4 обязана
    // доходить: раньше `advance` требовал контакта и отвечал `UnknownPeer`
    // ещё до первой ступени — то есть заявка не уехала бы никуда.
    //
    // Проверяется тем, что видно снаружи: отправка **не отказывает**,
    // и в эфире мы начинаем искать в том числе пира.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");

    // **Список ищемых спрашивается у подъёма**, а не у случайной команды:
    // `startup_effects` объявляет его всегда, и проверка не может пройти
    // оттого, что искать никого не звали.
    let watched = me
        .startup_effects()
        .iter()
        .find_map(|effect| match effect {
            Effect::WatchPeers(list) => Some(list.clone()),
            _ => None,
        })
        .expect("подъём обязан сказать транспорту, кого искать");
    assert!(
        watched.contains(&owner),
        "пира ищут в эфире наравне с контактами: он может быть за стенкой"
    );

    // Доступность у него есть, и она посчитана из адресов ссылки.
    let availability = me.availability_for(&owner).expect("доступность пира");
    assert!(availability.has_chatmail, "почта из ссылки — путь до владельца");
}

#[test]
fn unsubscribing_forgets_the_peer_it_was_needed_for() {
    // Пир держится причиной, по которой заведён (§10.6): канала нет —
    // и звонить владельцу больше незачем. Оставь мы его, список пиров
    // рос бы с каждой попробованной ссылкой и не убывал никогда.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");
    let chat = *me.groups().keys().next().expect("канал завёлся");

    me.step(200, Input::Command(Command::UnsubscribeFromChannel { chat })).expect("отписка");
    assert!(me.peers().get(&owner).is_none(), "пир забыт вместе с каналом");

    me.restore().expect("подъём");
    assert!(me.peers().get(&owner).is_none(), "и не возвращается с диска");
}

#[test]
fn a_request_that_had_nowhere_to_go_waits_instead_of_vanishing() {
    // **Поломка, найденная на стенде, и найденная по симптому «ничего
    // не произошло».** Человек подписался по ссылке в тот миг, когда
    // ни одной ступени не было: локальная сеть выключена, onion не поднят,
    // почты нет. Заявка (§10.4) собралась, лестница §5.4 честно сказала
    // «отправлять некуда» — и её **выбросили**: очередь ожидания
    // соглашалась ждать только ради контакта, а владелец канала контактом
    // не становится (§10.4) и не станет.
    //
    // Снаружи это выглядело так: у подписчика вечное «ждём впуска»,
    // у владельца — ни одной заявки, и включённая через минуту сеть
    // ничего не меняла. Ждать было уже нечему.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");

    // Ни одна ступень не годится: адреса из ссылки есть, а транспорты
    // у свежего узла выключены — ровно как на стенде.
    let waiting = me.store().outbox().expect("очередь");
    assert_eq!(waiting.len(), 1, "заявка обязана лечь в очередь, а не пропасть");
    assert_eq!(waiting[0].recipient_ik, owner, "и ждать именно владельца");

    // И пережить перезапуск: подписка ждёт впуска сутками (§10.4), а
    // процесс на телефоне убивают постоянно.
    me.restore().expect("подъём");
    assert_eq!(
        me.store().outbox().expect("очередь").len(),
        1,
        "подъём не должен вычищать заявку как мусор: пир на месте"
    );
}

#[test]
fn hearing_the_owner_in_the_air_gets_the_waiting_request_moving() {
    // Вторая половина той же поломки: отметку «слышно в эфире» ядро
    // применяло только к контактам. Пир оставался неслышимым навсегда,
    // и даже долежавшая заявка не трогалась с места.
    let (mut me, (uri, owner)) = (node(1), link_with_addresses());
    // **Порядок как на стенде, и он и есть проверка.** Сперва подписка,
    // когда ни одной ступени нет (§5.1 держит локальную сеть выключенной
    // по умолчанию), и только потом человек её включает. Разрешения —
    // состояние нашего устройства, и разнести их надо **всем**, кого мы
    // умеем достигать; пока они разносились одним контактам, пир застывал
    // с тем, что было в миг его появления, и включённая через минуту сеть
    // до него не доходила.
    me.step(100, Input::Command(Command::SubscribeToChannel { uri })).expect("подписка");
    me.step(
        150,
        Input::Command(Command::SetTransportEnabled {
            transport: ratatosk_proto::Transport::Lan,
            enabled: true,
        }),
    )
    .expect("локальная сеть включена");
    assert!(
        !me.availability_for(&owner).expect("доступность").seen_on_lan,
        "до маяка его не слышно — иначе проверка ниже пуста"
    );

    // Маяк владельца: транспорт услышал его и назвал ядру.
    let effects = me.step(200, Input::SeenOnLan { peer_ik: owner }).expect("маяк");
    assert!(
        me.availability_for(&owner).expect("доступность").seen_on_lan,
        "пира слышно так же, как контакта (§8.3)"
    );
    // И отложенное трогается с места: §5.4 больше не говорит «адреса нет».
    assert!(
        effects
            .iter()
            .any(|effect| matches!(effect, Effect::Send { peer_ik, .. } if *peer_ik == owner)),
        "услышали владельца — заявка обязана поехать, не досиживая срока"
    );
}
