//! Телефон и десктоп-компаньон (§13.4).
//!
//! Провод здесь не такой, как в `pair.rs`, и не мог бы им быть. Там два
//! равных [`Engine`], здесь — ядро и **терминал**: у десктопа нет своего
//! ядра, своей истории и своей идентичности. Поэтому вторую сторону
//! приходится собрать руками из тех же кирпичей, из которых её собирает
//! ядро: Noise IK, кадр §7.1, конверт §9.1.
//!
//! Это не дублирование логики ядра, а её проверка снаружи. Десктоп в этом
//! файле знает ровно то, что знает настоящий десктоп: зерно из ссылки
//! сопряжения, `IK` телефона и формат провода. Разойдись ядро с проводом
//! хоть в одном поле — рукопожатие не сойдётся или кадр не расшифруется,
//! и тест скажет об этом раньше стенда.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ratatosk_codec::{Envelope, PayloadType};
use ratatosk_core::engine::SelfAddresses;
use ratatosk_core::{Command, Effect, Engine, Event, Input, SeededEntropy};
use ratatosk_crypto::aead;
use ratatosk_crypto::handshake::{Initiator, PendingHandshake, Session};
use ratatosk_crypto::Identity;
use ratatosk_proto::companion::{self, PairingInvite, Request, Response};
use ratatosk_proto::Transport;
use ratatosk_store::{MemoryBlobs, MemoryStore, SqliteStore, Store};
use ratatosk_wire::{pad_to, unpad, FrameType, Header, SizeClass};
use zeroize::Zeroizing;

type Phone = Engine<MemoryStore>;

/// Кадры рукопожатия ходят наименьшим классом — так же, как в ядре.
const HANDSHAKE_CLASS: SizeClass = SizeClass::S;

fn phone(seed: u8, name: &str) -> Phone {
    phone_with_blobs(seed, name).0
}

fn phone_with_blobs(seed: u8, name: &str) -> (Phone, Arc<Mutex<MemoryBlobs>>) {
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
    lan_up(&mut engine);
    (engine, handle)
}

/// Поднимает локальную сеть — единственную ступень, доступную компаньону
/// на этом этапе (см. раздел «компаньон» в `engine.rs`).
fn lan_up<S: Store>(engine: &mut Engine<S>) {
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
}

/// Десктоп: ровно столько протокола, сколько его знает настоящий десктоп.
struct Desktop {
    identity: Identity,
    pending: Option<PendingHandshake>,
    session: Option<Session>,
    /// Номер следующей просьбы. Ответ узнаётся по нему — на проводе может
    /// быть больше одной просьбы сразу.
    next_id: u64,
}

impl Desktop {
    /// Собирается из зерна, которое приехало в ссылке сопряжения.
    ///
    /// Вот ради чего секрет — зерно, а не готовый ключ: десктопу нужен
    /// статический ключ **в том же виде**, в каком его строит телефон,
    /// и `Identity::from_seed` — единственное место, где этот вид задан.
    fn from_invite(invite: &PairingInvite) -> Desktop {
        Desktop {
            identity: Identity::from_seed(*invite.secret.as_bytes()),
            pending: None,
            session: None,
            next_id: 1,
        }
    }

    /// Сторона провода с произвольным ключом — то есть **не** наш десктоп.
    ///
    /// Нужна одному вопросу: что телефон делает с кадром компаньона,
    /// пришедшим от того, с кем сопряжения нет.
    fn with_identity(identity: Identity) -> Desktop {
        Desktop { identity, pending: None, session: None, next_id: 1 }
    }

    /// Публичная половина своего ключа — адрес на проводе.
    fn ik(&self) -> [u8; 32] {
        self.identity.public().ik
    }

    /// Первое сообщение рукопожатия.
    ///
    /// `payload` — то, что §8.2 возит в первом сообщении: карточка
    /// отправителя. У десктопа карточки нет и быть не может — он не человек
    /// в чьём-то списке контактов, — и он шлёт пустоту. Телефон её и не
    /// читает: узнав своё устройство по статическому ключу, он идёт другой
    /// веткой, до разбора карточки не доходя.
    ///
    /// **Тот, кто приходит контактом, обязан карточку прислать.** Пустая
    /// нагрузка от незнакомца — не «контакт без имени», а отказ разбора,
    /// и весь шаг ядра вернёт ошибку. Это ровно то, на чём споткнулся сам
    /// этот тест, когда звал `hello` с пустотой от чужого ключа.
    fn hello(&mut self, phone_ik: &[u8; 32], payload: &[u8]) -> Vec<u8> {
        let (message, pending) =
            Initiator::start(&self.identity, phone_ik, payload).expect("первое сообщение");
        self.pending = Some(pending);
        handshake_frame(ratatosk_core::engine::HANDSHAKE_STEP_FIRST, &message)
    }

    /// Кадр от телефона: либо ответ рукопожатия, либо данные сессии.
    fn take(&mut self, frame: &[u8], now_ms: u64) -> Option<Envelope> {
        let view = ratatosk_wire::parse(frame).expect("разбор кадра");
        if view.header.frame_type == FrameType::Handshake {
            let message = unpad(view.sealed).expect("снятие набивки").to_vec();
            let mut pending = self.pending.take().expect("рукопожатие не начиналось");
            self.session = Some(pending.finish(&message, now_ms).expect("ответ рукопожатия"));
            return None;
        }

        let session = self.session.as_mut().expect("сессии ещё нет");
        let counter = view.header.counter;
        let key = session.recv.peek(counter).expect("ключ позиции");
        let (_, plaintext) = aead::open(&key, frame).expect("расшифровка кадра");
        session.recv.commit(counter, now_ms).expect("отметка позиции");
        Some(Envelope::decode(&plaintext).expect("разбор конверта").into_parts().1)
    }

    /// Просьба к телефону. Возвращает её номер и готовый кадр.
    fn ask(&mut self, request: &Request) -> (u64, Vec<u8>) {
        let id = self.next_id;
        self.next_id += 1;
        let payload = companion::request_payload(id, request);
        // Метка часов у просьбы своя и телефоном не наблюдается (§9.1
        // к разговору с терминалом не относится) — ноль здесь честнее
        // выдуманного времени.
        let envelope = Envelope::new(
            [id as u8; 16],
            ratatosk_crdt::Hlc::new(0, 0),
            PayloadType::CompanionRequest,
            payload,
        );
        (id, self.seal(&envelope.encode().expect("кодирование конверта")))
    }

    fn seal(&mut self, envelope: &[u8]) -> Vec<u8> {
        let session = self.session.as_mut().expect("сессии ещё нет");
        let class = SizeClass::smallest_for(envelope.len()).expect("конверт влезает в класс");
        let (counter, key) = session.send.next();
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());
        let header = Header::new(FrameType::Data, session.session_id, counter, nonce);
        aead::seal(&key, &header, class, envelope).expect("запечатывание кадра")
    }
}

fn handshake_frame(step: u64, message: &[u8]) -> Vec<u8> {
    // Nonce нулевой, и это не небрежность: кадр рукопожатия нашим AEAD
    // не запечатывается — его содержимое уже зашифровал Noise, — и заголовок
    // здесь только адресует шаг.
    let header = Header::new(
        FrameType::Handshake,
        ratatosk_wire::HANDSHAKE_SESSION_ID,
        step,
        [0u8; ratatosk_wire::NONCE_LEN],
    );
    let mut sealed = Vec::new();
    pad_to(message, HANDSHAKE_CLASS.sealed_len(), &mut sealed).expect("набивка");
    ratatosk_wire::assemble(&header, &sealed).expect("сборка кадра")
}

/// Кадр рукопожатия с содержимым **как есть**, без набивки.
///
/// Нужен ровно для одного: показать телефону то, что набивкой не является.
/// Так выглядит и мусор соседа по сети, и наш собственный кадр отзыва,
/// попади он не туда.
fn handshake_frame_raw(step: u64, sealed: &[u8]) -> Vec<u8> {
    let header = Header::new(
        FrameType::Handshake,
        ratatosk_wire::HANDSHAKE_SESSION_ID,
        step,
        [0u8; ratatosk_wire::NONCE_LEN],
    );
    ratatosk_wire::assemble(&header, sealed).expect("сборка кадра")
}

/// Свой временный путь вместо зависимости ради одной функции.
///
/// То же, что в `restart.rs`, и по той же причине: перезапуск проверяется
/// по настоящему файлу — база в памяти исчезает вместе с процессом.
struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> TempDb {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "ratatosk-companion-{tag}-{}-{:?}.db",
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

fn addresses() -> SelfAddresses {
    SelfAddresses {
        onion: String::new(),
        chatmail: String::new(),
        display_name: "телефон".to_owned(),
    }
}

/// Отдаёт кадры из эффектов и события отдельно.
///
/// Кадры — **вместе с адресатом**, и это не педантизм. На том же шаге, где
/// телефон отвечает десктопу, он может слать рукопожатие собеседнику:
/// отправка текста заводит доставку по §5.4. Сунув такой кадр десктопу,
/// тест упал бы на расшифровке — и упал бы не там, где ошибка.
fn split(effects: Vec<Effect>) -> (Vec<([u8; 32], Vec<u8>)>, Vec<Event>) {
    let mut frames = Vec::new();
    let mut events = Vec::new();
    for effect in effects {
        match effect {
            Effect::Send { peer_ik, frame, .. } => frames.push((peer_ik, frame)),
            Effect::Notify(event) => events.push(event),
            _ => {}
        }
    }
    (frames, events)
}

/// Кадры, адресованные этой стороне провода.
fn addressed_to(frames: Vec<([u8; 32], Vec<u8>)>, who: [u8; 32]) -> Vec<Vec<u8>> {
    frames.into_iter().filter(|(to, _)| *to == who).map(|(_, frame)| frame).collect()
}

/// Заводит сопряжение и доводит десктоп до живой сессии.
fn paired(now_ms: u64) -> (Phone, Desktop, [u8; 16]) {
    let (phone, desktop, device_id, _) = paired_with_blobs(now_ms);
    (phone, desktop, device_id)
}

/// То же, но с «диском» телефона: без него вложению неоткуда взяться.
fn paired_with_blobs(now_ms: u64) -> (Phone, Desktop, [u8; 16], Arc<Mutex<MemoryBlobs>>) {
    let (mut phone, blobs) = phone_with_blobs(1, "телефон");
    let phone_ik = phone.own_card().ik;

    let effects = phone
        .step(now_ms, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");
    let (_, events) = split(effects);
    let (device_id, uri) = events
        .into_iter()
        .find_map(|event| match event {
            Event::PairingReady { device_id, uri } => Some((device_id, uri)),
            _ => None,
        })
        .expect("ссылка сопряжения приходит событием и только им");

    let invite = PairingInvite::from_uri(&uri).expect("разбор ссылки");
    assert_eq!(invite.ik, phone_ik, "в ссылке — IK телефона: по нему десктоп его и зовёт");

    let mut desktop = Desktop::from_invite(&invite);
    handshake(&mut phone, &mut desktop, now_ms);

    (phone, desktop, device_id, blobs)
}

/// Доводит десктоп до живой сессии с уже готовым телефоном.
///
/// Отдельно от `paired_with_blobs` затем, что здороваться приходится
/// дважды: сессия терминала на диск не ложится, и после перезапуска
/// телефона десктоп начинает разговор заново (см.
/// `a_device_session_does_not_outlive_a_restart`).
fn handshake<S: Store>(phone: &mut Engine<S>, desktop: &mut Desktop, now_ms: u64) {
    let phone_ik = phone.own_card().ik;
    let hello = desktop.hello(&phone_ik, &[]);
    let effects = phone
        .step(now_ms, Input::Received { via: Transport::Lan, frame: hello })
        .expect("рукопожатие от десктопа");
    let (frames, _) = split(effects);
    for frame in addressed_to(frames, desktop.ik()) {
        desktop.take(&frame, now_ms);
    }
    assert!(desktop.session.is_some(), "сессия с десктопом обязана установиться");
}

/// Спрашивает телефон и разбирает ответ.
fn ask<S: Store>(
    phone: &mut Engine<S>,
    desktop: &mut Desktop,
    now_ms: u64,
    request: &Request,
) -> Response {
    let (id, frame) = desktop.ask(request);
    let effects = phone.step(now_ms, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    let (frames, _) = split(effects);

    let mut answer = None;
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, now_ms) else { continue };
        if envelope.payload_type != PayloadType::CompanionResponse {
            continue;
        }
        let (got, response) =
            companion::response_from_payload(&envelope.payload).expect("разбор ответа");
        assert_eq!(got, id, "ответ обязан нести номер той просьбы, на которую он отвечает");
        answer = Some(response);
    }
    answer.expect("на просьбу обязан прийти ответ")
}

/// Байты, которые `avatar::check` признаёт картинкой.
///
/// Восемь байт сигнатуры PNG и ничего больше: ядро изображение не разбирает
/// (см. `ratatosk_proto::avatar`), и рисовать настоящий файл ради теста
/// значило бы проверять чужой кодек вместо своего провода.
fn png() -> Vec<u8> {
    vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
}

/// Кладёт контакту лицо прямо в хранилище.
///
/// **Мимо провода контактов, и это осознанно.** Настоящая дорога — сессия
/// с собеседником и `PayloadType::Avatar`; она проверена в `tests/pair.rs`
/// и здесь проверялась бы второй раз, зато потребовала бы второго телефона
/// с рукопожатием. Проверяется тут провод **компаньона**, и ему всё равно,
/// как строка в `avatars` появилась.
fn put_avatar<S: Store>(phone: &mut Engine<S>, peer_ik: &[u8; 32], at_ms: u64) {
    phone
        .store_mut()
        .put_avatar(peer_ik, &ratatosk_store::StoredAvatar { bytes: png(), updated_ms: at_ms })
        .expect("аватарка ложится в хранилище");
}

/// Единственная новость, уехавшая десктопу за этот шаг.
///
/// Именно единственная: «пришла нужная» и «пришла только нужная» — разные
/// утверждения, и второе ловит лишнюю рассылку, которую первое пропустит.
fn only_notice(desktop: &mut Desktop, effects: Vec<Effect>, now_ms: u64) -> companion::Notice {
    let (frames, _) = split(effects);
    let mut notices = Vec::new();
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, now_ms) else { continue };
        if envelope.payload_type != PayloadType::CompanionNotice {
            continue;
        }
        notices.push(companion::notice_from_payload(&envelope.payload).expect("разбор новости"));
    }
    assert_eq!(notices.len(), 1, "ожидалась ровно одна новость, приехало: {notices:?}");
    notices.remove(0)
}

/// Заводит телефону собеседника, чтобы десктопу было что показывать.
fn with_contact<S: Store>(phone: &mut Engine<S>, now_ms: u64) -> [u8; 32] {
    let other = Identity::from_seed([9u8; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: other.public().ik,
        sk: other.public().sk,
        onion: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion".into(),
        chatmail: "сосед@nine.example".into(),
        display_name: "сосед".into(),
        version: 1,
    };
    let bytes = card.encode().expect("кодирование карточки");
    phone
        .step(
            now_ms,
            Input::Command(Command::AddContact { card_bytes: bytes, met_in_person: true }),
        )
        .expect("добавление контакта");
    card.ik
}

#[test]
fn a_desktop_built_from_the_invite_seed_is_recognised_as_our_own() {
    // Главное свойство сопряжения: телефон узнаёт своё устройство
    // по статическому ключу в рукопожатии, ничего сверх кадра не спросив.
    let (mut phone, mut desktop, device_id) = paired(1_000);

    let devices = phone.paired_devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_id, device_id);
    assert_eq!(devices[0].label, "ноутбук");

    // А вот «на связи» рукопожатие ещё не значит: ответ телефон отправил,
    // но дошёл ли он — не знает. Доказывает это первая просьба, и только
    // она (`ARCHITECTURE.md`, 5бз).
    assert!(!phone.device_connected(&device_id), "рукопожатие не доказывает, что наш ответ дошёл");

    let (_, frame) = desktop.ask(&Request::Chats);
    phone.step(1_100, Input::Received { via: Transport::Lan, frame }).expect("просьба");
    assert!(phone.device_connected(&device_id), "а просьба — доказывает");
}

#[test]
fn a_paired_desktop_does_not_become_a_contact() {
    // §13.4: десктоп — терминал, а не собеседник. Появившись в контактах,
    // он завёл бы себе чат, попал бы в список маяков как контакт и получал
    // бы карточки — то есть выглядел бы человеком, которого нет.
    let (phone, _desktop, _) = paired(1_000);
    assert!(phone.contacts().is_empty(), "устройство не заводит контакта");
}

#[test]
fn the_desktop_sees_the_chat_list_the_phone_would_show() {
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);

    let Response::Chats(chats) = ask(&mut phone, &mut desktop, 1_200, &Request::Chats) else {
        panic!("на просьбу о чатах обязан прийти список чатов");
    };
    assert_eq!(chats.len(), 1);
    // `IK` собеседника по проводу компаньона не едет (§13.4): чат называет
    // себя идентификатором, а он выводится из ключа телефоном.
    assert_eq!(
        chats[0].chat,
        Engine::<MemoryStore>::chat_id_for(&peer_ik),
        "чат обязан быть тем самым, а узнаётся он по идентификатору"
    );
    assert_eq!(chats[0].title, "сосед", "заголовок считает телефон (§13.3)");
    assert!(chats[0].verified, "контакт добавлен из QR — сверен (§4.2)");
}

#[test]
fn the_desktop_gets_a_face_only_for_a_verified_contact() {
    // §4.2 симметричен, и провод компаньона обязан его держать так же,
    // как провод контактов: несверенному лицо не показывается. Если бы
    // правило жило только в UI телефона, второй экран открывал бы обход
    // в одну строку — а §13.3 ровно это и запрещает.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // Лицо приехало от контакта, но сверку с него сняли.
    phone
        .step(1_150, Input::Command(Command::RevokeVerification { peer_ik }))
        .expect("отзыв сверки");
    put_avatar(&mut phone, &peer_ik, 1_160);

    let Response::Chats(chats) = ask(&mut phone, &mut desktop, 1_200, &Request::Chats) else {
        panic!("список чатов");
    };
    assert_eq!(chats[0].avatar_ms, 0, "несверенному метка не едет — иначе десктоп бы спрашивал");

    let answer = ask(&mut phone, &mut desktop, 1_250, &Request::Avatar { chat: Some(chat) });
    assert_eq!(
        answer,
        Response::Avatar { bytes: None, avatar_ms: 0 },
        "и байты тоже: правило одно на оба экрана"
    );

    // Сверили — и лицо появилось, без нового рукопожатия.
    phone.step(1_300, Input::Command(Command::MarkVerified { peer_ik })).expect("сверка");
    let Response::Chats(chats) = ask(&mut phone, &mut desktop, 1_350, &Request::Chats) else {
        panic!("список чатов");
    };
    assert_eq!(chats[0].avatar_ms, 1_160, "метка — та же, что у строки в хранилище");

    let answer = ask(&mut phone, &mut desktop, 1_400, &Request::Avatar { chat: Some(chat) });
    let Response::Avatar { bytes, avatar_ms } = answer else {
        panic!("на просьбу об аватарке обязан прийти ответ об аватарке");
    };
    assert!(bytes.is_some(), "сверенному лицо показывается");
    assert_eq!(avatar_ms, chats[0].avatar_ms, "метка в ответе и в списке — одна и та же строка");
}

#[test]
fn ones_own_face_is_asked_for_without_a_chat() {
    // Себя в списке чатов нет, и метки для сравнения у своего лица нет тоже:
    // `None` здесь значит «про себя», а не «поля нет».
    let (mut phone, mut desktop, _) = paired(1_000);
    phone
        .step(1_100, Input::Command(Command::SetAvatar(png())))
        .expect("своя аватарка принимается");

    let answer = ask(&mut phone, &mut desktop, 1_200, &Request::Avatar { chat: None });
    let Response::Avatar { bytes, avatar_ms } = answer else {
        panic!("ответ об аватарке");
    };
    assert_eq!(bytes, Some(png()), "своё лицо десктопу отдаётся целиком");
    assert_eq!(avatar_ms, 1_100, "метка — часы того шага, на котором её поставили");
}

#[test]
fn changing_ones_own_face_reaches_the_desktop_without_being_asked() {
    // Иначе второй экран показывал бы прежнее лицо до перезапуска: свою
    // аватарку меняют на телефоне, а десктоп об этом узнать неоткуда —
    // в списке чатов себя нет.
    let (mut phone, mut desktop, _) = paired(1_000);
    let effects =
        phone.step(1_100, Input::Command(Command::SetAvatar(png()))).expect("своя аватарка");

    let notice = only_notice(&mut desktop, effects, 1_100);
    assert_eq!(
        notice,
        companion::Notice::AvatarChanged { chat: None, avatar_ms: 1_100 },
        "новость о своём лице обязана приехать без спроса"
    );

    // Снятие — такая же новость с нулевой меткой: иначе лицо осталось бы
    // на втором экране навсегда.
    let effects =
        phone.step(1_200, Input::Command(Command::SetAvatar(Vec::new()))).expect("снятие");
    let notice = only_notice(&mut desktop, effects, 1_200);
    assert_eq!(notice, companion::Notice::AvatarChanged { chat: None, avatar_ms: 0 });
}

#[test]
fn a_face_set_from_the_desktop_lands_on_the_phone_and_goes_to_contacts() {
    // Ради этого вторая половина и существует: человек кладёт картинку
    // на десктопе, а рассылает её телефон — своим ключом, по своим сессиям.
    // Десктоп в рассылке не участвует и не может: сессий с контактами
    // у него нет (§13.4).
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);

    let answer = ask(&mut phone, &mut desktop, 1_200, &Request::SetMyAvatar { bytes: png() });
    assert_eq!(answer, Response::Done, "картинка законная — телефон обязан её принять");
    assert_eq!(phone.own_avatar().unwrap(), Some(png()), "и положить у себя");

    // И отдать её обратно тому же десктопу — с меткой того шага, на котором
    // она легла.
    let answer = ask(&mut phone, &mut desktop, 1_300, &Request::Avatar { chat: None });
    assert_eq!(answer, Response::Avatar { bytes: Some(png()), avatar_ms: 1_200 });

    // Снятие — та же просьба с пустыми байтами.
    let answer = ask(&mut phone, &mut desktop, 1_400, &Request::SetMyAvatar { bytes: Vec::new() });
    assert_eq!(answer, Response::Done);
    assert_eq!(phone.own_avatar().unwrap(), None, "пусто — это «снять», а не «не трогать»");

    // Контакт при этом остался сверенным и никуда не делся: рассылка —
    // дело телефона, и она не роняет ничего, даже когда сессии нет.
    assert!(phone.contacts()[&peer_ik].verified);
}

#[test]
fn a_bad_face_from_the_desktop_comes_back_in_words() {
    // Просьба с другого устройства не вправе ронять шаг ядра, а человек
    // за ноутбуком обязан узнать, **почему** не вышло: «не картинка»
    // и «телефон сломался» чинятся по-разному (§14).
    let (mut phone, mut desktop, _) = paired(1_000);

    let answer =
        ask(&mut phone, &mut desktop, 1_200, &Request::SetMyAvatar { bytes: b"<svg/>".to_vec() });
    let Response::Refused(why) = answer else {
        panic!("негодная картинка обязана вернуться отказом, а не `Done`");
    };
    assert!(!why.trim().is_empty(), "отказ без слов человеку показать нечего");
    assert_eq!(phone.own_avatar().unwrap(), None, "негодное не должно было лечь в хранилище");
}

#[test]
fn the_phones_own_screen_learns_about_a_face_the_desktop_set() {
    // Без этого события телефон показывал бы прежнюю картинку до
    // перезапуска — то самое «экран врёт», ради которого §14 и написан.
    // Пока смена шла только с телефона, экран знал о ней от себя же;
    // теперь он вправе узнать последним.
    let (mut phone, mut desktop, _) = paired(1_000);

    let (_, frame) = desktop.ask(&Request::SetMyAvatar { bytes: png() });
    let effects = phone.step(1_200, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    let (_, events) = split(effects);
    assert!(
        events.iter().any(|e| matches!(e, Event::OwnAvatarChanged)),
        "экран телефона обязан узнать о смене своего лица: {events:?}"
    );
}

#[test]
fn a_local_name_wins_over_the_name_from_the_card() {
    // §4.1: имя из карточки задаёт собеседник и оно не доверяется. Решает
    // это протокол, а не десктоп, — иначе на двух экранах было бы два имени.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    phone
        .step(1_150, Input::Command(Command::SetLocalName { peer_ik, name: Some("Петя".into()) }))
        .expect("подпись контакта");

    let Response::Chats(chats) = ask(&mut phone, &mut desktop, 1_200, &Request::Chats) else {
        panic!("список чатов");
    };
    assert_eq!(chats[0].title, "Петя");
}

#[test]
fn a_text_sent_from_the_desktop_lands_in_the_phones_history() {
    // Ради этого весь режим и существует: человек печатает на десктопе,
    // а отправляет телефон — своим ключом, из своей истории.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let request = Request::SendText { chat, text: "привет с ноутбука".into() };
    let response = ask(&mut phone, &mut desktop, 1_200, &request);
    assert_eq!(response, Response::Done);

    let Response::History(page) =
        ask(&mut phone, &mut desktop, 1_300, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].text, "привет с ноутбука");
    assert!(page[0].mine, "отправлено от имени пользователя — своё");
}

#[test]
fn a_message_the_desktop_sent_comes_back_as_a_notice() {
    // Десктоп не обязан перечитывать историю после каждой отправки: то,
    // что легло в неё, приезжает новостью — тем же путём, каким приедет
    // и принятое от собеседника.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let (_, frame) = desktop.ask(&Request::SendText { chat, text: "эй".into() });
    let effects = phone.step(1_200, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    let (frames, _) = split(effects);

    let mut told = false;
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, 1_200) else { continue };
        if envelope.payload_type != PayloadType::CompanionNotice {
            continue;
        }
        let notice = companion::notice_from_payload(&envelope.payload).expect("разбор новости");
        if let companion::Notice::Message(message) = notice {
            assert_eq!(message.text, "эй");
            assert!(message.mine);
            told = true;
        }
    }
    assert!(told, "о своём же сообщении десктоп обязан узнать новостью");
}

/// Гонит одну выгрузку целиком и отдаёт `file_id`, который назвал телефон.
///
/// Чужим кодом, тремя просьбами подряд: терминал сегодня умеет один файл
/// за раз, а провод и телефон — несколько, и проверяется здесь именно это.
fn stage<S: Store>(
    phone: &mut Engine<S>,
    desktop: &mut Desktop,
    now_ms: u64,
    chat: [u8; 16],
    name: &str,
    bytes: &[u8],
) -> [u8; 16] {
    let answer = ask(
        phone,
        desktop,
        now_ms,
        &Request::FileOffer {
            chat,
            name: name.to_owned(),
            size_bytes: bytes.len() as u64,
            preview: None,
        },
    );
    let Response::FileOffer { file_id, chunk_total } = answer else {
        panic!("телефон обязан отвести место, а не {answer:?}");
    };
    for index in 0..chunk_total {
        let from = index as usize * ratatosk_proto::files::CHUNK_BYTES;
        let to = (from + ratatosk_proto::files::CHUNK_BYTES).min(bytes.len());
        let answer = ask(
            phone,
            desktop,
            now_ms + index + 1,
            &Request::FilePut { file_id, index, bytes: bytes[from..to].to_vec() },
        );
        assert!(matches!(answer, Response::Done), "кусок обязан лечь: {answer:?}");
    }
    file_id
}

#[test]
fn several_uploads_become_one_message_with_several_attachments() {
    // Ради этого версия провода и росла: три картинки, выбранные разом,
    // обязаны приехать одним сообщением, а не тремя.
    let (mut phone, mut desktop, _, _blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let names = ["один.jpg", "два.jpg", "три.jpg"];
    let mut ids = Vec::new();
    for (n, name) in names.iter().enumerate() {
        let bytes: Vec<u8> = (0..32u8).map(|b| b.wrapping_add(n as u8)).collect();
        ids.push(stage(&mut phone, &mut desktop, 1_200 + n as u64 * 100, chat, name, &bytes));
    }

    let answer = ask(
        &mut phone,
        &mut desktop,
        1_600,
        &Request::FileSend { file_ids: ids.clone(), text: "вот три".into() },
    );
    assert!(matches!(answer, Response::Done), "отправка обязана состояться: {answer:?}");

    // Одно сообщение, а не три.
    let history = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(history.len(), 1, "три вложения — одно сообщение");
    assert_eq!(history[0].body, "вот три".as_bytes(), "подпись едет с третьим шагом");

    let files = phone.store().files_of(&history[0].msg_id).expect("вложения");
    assert_eq!(files.len(), 3);
    let got: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(got, names, "порядок — тот, в каком их назвал десктоп");
}

#[test]
fn an_upload_survives_a_restart_of_the_phone() {
    // Ради этого поставка и делалась. Раньше выгрузка жила в памяти ядра,
    // и перезапуск телефона стирал её целиком: с пятью файлами — потеря
    // четырёх выгруженных ради пятого.
    //
    // По настоящей базе, и не только потому, что перезапуск иначе не
    // проверить: `staged_files` — новый способ трогать хранилище, а такое
    // проверяется на SQLite (см. `a_device_talks_to_a_phone_on_a_real_database`).
    // Байты вложений — в памяти: их сохранность здесь не проверяется, но
    // ручка у обоих запусков обязана быть одна.
    let db = TempDb::new("staged");
    let db_key = Zeroizing::new([11u8; 32]);
    let blobs: Arc<Mutex<MemoryBlobs>> = Arc::new(Mutex::new(MemoryBlobs::new()));
    let boot = |store: SqliteStore, blobs: Arc<Mutex<MemoryBlobs>>| {
        Engine::new(
            Identity::from_seed([1u8; 32]),
            store,
            Box::new(blobs),
            Box::new(SeededEntropy::new(1)),
            addresses(),
        )
    };

    let mut phone = boot(db.open(&db_key), Arc::clone(&blobs));
    lan_up(&mut phone);
    let effects = phone
        .step(1_000, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");
    let (_, events) = split(effects);
    let uri = events
        .into_iter()
        .find_map(|event| match event {
            Event::PairingReady { uri, .. } => Some(uri),
            _ => None,
        })
        .expect("ссылка сопряжения");
    let mut desktop = Desktop::from_invite(&PairingInvite::from_uri(&uri).expect("разбор ссылки"));
    handshake(&mut phone, &mut desktop, 1_050);

    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<SqliteStore>::chat_id_for(&peer_ik);

    let bytes: Vec<u8> = (0..64u8).collect();
    let file_id = stage(&mut phone, &mut desktop, 1_200, chat, "otchet.pdf", &bytes);

    // Телефон перезапустился: новое ядро на той же базе и на тех же байтах.
    drop(phone);
    let mut phone = boot(db.open(&db_key), Arc::clone(&blobs));
    phone.restore().expect("подъём");
    lan_up(&mut phone);
    // Сессия терминала перезапуск не переживает — десктоп здоровается заново.
    handshake(&mut phone, &mut desktop, 1_300);

    let answer = ask(&mut phone, &mut desktop, 1_400, &Request::Staged);
    let Response::Staged { files } = answer else {
        panic!("телефон обязан помнить выгрузку: {answer:?}");
    };
    assert_eq!(files.len(), 1, "одна незаконченная выгрузка");
    assert_eq!(files[0].file_id, file_id);
    assert_eq!(files[0].name, "otchet.pdf", "имя — по нему десктоп узнаёт своё");
    assert_eq!(files[0].size_bytes, 64);
    assert!(files[0].missing.is_empty(), "все куски на месте — дырок нет");

    // И её можно отправить, ничего не выгружая заново.
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_500,
        &Request::FileSend {
            file_ids: vec![file_id], text: "после перезапуска".into()
        },
    );
    assert!(matches!(answer, Response::Done), "отправка обязана состояться: {answer:?}");
    let history = phone.store().messages(&chat, 10, None).expect("история");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].body, "после перезапуска".as_bytes());
}

#[test]
fn the_staged_answer_names_the_holes_and_not_the_count() {
    // Продолжать надо с дырки, а не с числа принятых: куски вправе приехать
    // не по порядку. То же правило, что у приёма файлов (§10.2).
    let (mut phone, mut desktop, _, _blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = ratatosk_proto::files::CHUNK_BYTES as u64 * 3;
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_200,
        &Request::FileOffer { chat, name: "big.bin".into(), size_bytes: size, preview: None },
    );
    let Response::FileOffer { file_id, chunk_total } = answer else {
        panic!("место отведено");
    };
    assert_eq!(chunk_total, 3);

    // Кладём **средний** кусок: дырки останутся по краям.
    let chunk = vec![7u8; ratatosk_proto::files::CHUNK_BYTES];
    let answer =
        ask(&mut phone, &mut desktop, 1_300, &Request::FilePut { file_id, index: 1, bytes: chunk });
    assert!(matches!(answer, Response::Done));

    let answer = ask(&mut phone, &mut desktop, 1_400, &Request::Staged);
    let Response::Staged { files } = answer else {
        panic!("список выгрузок");
    };
    assert_eq!(files[0].missing, vec![0, 2], "нулевой и второй — именно их и просить");
}

#[test]
fn an_abandoned_upload_is_swept_after_its_time() {
    // Брошенную выгрузку никто не закрывает: у десктопа сдох процесс,
    // и ни `FileSend`, ни `FileAbort` не придут. Сверка сирот её нарочно
    // пропускает — значит без срока место не вернулось бы никогда.
    let (mut phone, mut desktop, _, _blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let bytes: Vec<u8> = (0..64u8).collect();
    let file_id = stage(&mut phone, &mut desktop, 1_200, chat, "zabytyj.bin", &bytes);

    // Срок ещё не вышел: трогать нельзя.
    let swept = phone
        .sweep_abandoned_uploads(1_200 + ratatosk_proto::companion::STAGED_TTL_MS)
        .expect("сверка");
    assert_eq!(swept.files, 0, "ровно срок — ещё живая");
    let answer = ask(&mut phone, &mut desktop, 1_300, &Request::Staged);
    assert!(matches!(answer, Response::Staged { ref files } if files.len() == 1));

    // А теперь вышел.
    let swept = phone
        .sweep_abandoned_uploads(1_201 + ratatosk_proto::companion::STAGED_TTL_MS)
        .expect("сверка");
    assert_eq!(swept.files, 1, "брошенная выгрузка убрана");
    let answer = ask(&mut phone, &mut desktop, 1_400, &Request::Staged);
    assert!(matches!(answer, Response::Staged { ref files } if files.is_empty()));
    assert!(
        phone.open_file(&file_id).expect("чтение").is_none(),
        "и байты её тоже ушли, а не остались сиротами"
    );
}

#[test]
fn a_send_with_one_file_missing_its_chunks_sends_nothing_at_all() {
    // Половина сообщения — худший исход: человек увидит «отправлено»
    // и не узнает, что уехало не то, что он выбрал. Поэтому сперва
    // проверяется всё, потом делается всё.
    let (mut phone, mut desktop, _, _blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let whole = stage(&mut phone, &mut desktop, 1_200, chat, "целый.bin", &[7u8; 32]);

    // Второй файл заведён, но ни куска не выгружено.
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_300,
        &Request::FileOffer {
            chat, name: "дырявый.bin".into(), size_bytes: 32, preview: None
        },
    );
    let Response::FileOffer { file_id: holed, .. } = answer else {
        panic!("место отведено");
    };

    let answer = ask(
        &mut phone,
        &mut desktop,
        1_400,
        &Request::FileSend { file_ids: vec![whole, holed], text: String::new() },
    );
    assert!(matches!(answer, Response::Refused(_)), "отказ словами: {answer:?}");
    assert!(
        phone.store().messages(&chat, 10, None).expect("история").is_empty(),
        "ни одного сообщения: целый файл тоже остался невыгруженным"
    );

    // И обе выгрузки на месте: докачав вторую, можно отправить обе.
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_500,
        &Request::FilePut { file_id: holed, index: 0, bytes: vec![9u8; 32] },
    );
    assert!(matches!(answer, Response::Done));
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_600,
        &Request::FileSend { file_ids: vec![whole, holed], text: String::new() },
    );
    assert!(matches!(answer, Response::Done), "отказ не должен был ничего сломать: {answer:?}");
    assert_eq!(phone.store().messages(&chat, 10, None).expect("история").len(), 1);
}

#[test]
fn the_same_file_named_twice_is_refused() {
    // Иначе вторая позиция указывала бы на уже вынутую выгрузку, и человек
    // получил бы сообщение с одним вложением вместо двух — или того хуже.
    let (mut phone, mut desktop, _, _blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let file_id = stage(&mut phone, &mut desktop, 1_200, chat, "один.bin", &[7u8; 32]);
    let answer = ask(
        &mut phone,
        &mut desktop,
        1_300,
        &Request::FileSend { file_ids: vec![file_id, file_id], text: String::new() },
    );
    assert!(matches!(answer, Response::Refused(_)), "отказ словами: {answer:?}");
}

#[test]
fn a_preview_rides_as_a_flag_and_arrives_by_its_own_request() {
    // Форма провода, а не поведение терминала: в странице стоит бит,
    // байты приезжают отдельным ответом. Сотня сообщений с превью внутри —
    // три мегабайта в одном кадре, то есть страница, которая не влезет.
    let (mut phone, mut desktop, _, blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let picture = vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10];
    blobs.lock().unwrap().seed_sparse("/tmp/kot.jpg", 128);
    phone
        .step(
            1_200,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/kot.jpg".into(),
                    preview: Some(picture.clone()),
                }],
                text: "вот кот".into(),
            }),
        )
        .expect("отправка файла с превью");

    let Response::History(page) =
        ask(&mut phone, &mut desktop, 1_300, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    let attachment = page[0].files.first().expect("вложение названо").clone();
    assert!(attachment.has_preview, "признак обязан ехать со страницей");

    let answer =
        ask(&mut phone, &mut desktop, 1_400, &Request::FilePreview { file_id: attachment.file_id });
    let Response::FilePreview { bytes } = answer else {
        panic!("превью, а не {answer:?}");
    };
    assert_eq!(bytes, Some(picture), "та самая картинка, что клали при отправке");
}

#[test]
fn an_attachment_is_named_in_the_page_and_handed_over_chunk_by_chunk() {
    // Чужим кодом — то же, что `terminal.rs` проверяет своим, и здесь важна
    // именно **форма провода**: вложение названо, ключа файла в кадре нет,
    // а байты приезжают отдельным ответом и по одному куску.
    let (mut phone, mut desktop, _, blobs) = paired_with_blobs(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let size = ratatosk_proto::files::CHUNK_BYTES as u64 + 7;
    blobs.lock().unwrap().seed_sparse("/tmp/otchet.pdf", size);
    phone
        .step(
            1_200,
            Input::Command(Command::SendFiles {
                chat,
                files: vec![ratatosk_core::OutgoingFile {
                    path: "/tmp/otchet.pdf".into(),
                    preview: None,
                }],
                text: "вот отчёт".into(),
            }),
        )
        .expect("отправка файла");

    let Response::History(page) =
        ask(&mut phone, &mut desktop, 1_300, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    let attachment = page[0].files.first().expect("вложение названо в странице").clone();
    assert_eq!(attachment.name, "otchet.pdf");
    assert_eq!(attachment.chunk_total, 2);

    // Ключа файла в кадре нет и быть не может (§13.4): десктоп называет
    // `file_id`, а расшифровывает телефон.
    let mut whole = vec![0u8; size as usize];
    for index in 0..attachment.chunk_total {
        let answer = ask(
            &mut phone,
            &mut desktop,
            1_400 + index,
            &Request::FileChunk { file_id: attachment.file_id, index },
        );
        let Response::FileChunk { index: got, bytes } = answer else {
            panic!("кусок вложения, а не {answer:?}");
        };
        assert_eq!(got, index, "номер обязан ехать вместе с байтами");
        let at = index as usize * ratatosk_proto::files::CHUNK_BYTES;
        whole[at..at + bytes.len()].copy_from_slice(&bytes);
    }
    assert!(whole.iter().all(|byte| *byte == 0), "исходник был из нулей");

    // Кусок за концом файла — отказ словами, а не пустые байты: пустой
    // массив выглядел бы как кусок из нулей, а он законный.
    let past = ask(
        &mut phone,
        &mut desktop,
        1_500,
        &Request::FileChunk { file_id: attachment.file_id, index: attachment.chunk_total },
    );
    assert!(matches!(past, Response::Refused(_)), "за концом файла — отказ, а не пустота");
}

#[test]
fn a_request_from_the_desktop_reaches_the_same_handler_as_a_command() {
    // Проверка чужим кодом того, что просьба с ноутбука не идёт своей
    // дорогой. Ветка провода зовёт **тот же** обработчик, что и команда
    // с телефона: правила о том, что можно править только своё, что отзыв
    // и удаление — разные вещи, а очистка чата отзыва не имеет, живут
    // в одном месте. Заведись у десктопа вторая дорога — она однажды
    // разрешила бы то, чего не разрешает первая.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    for text in ["раз", "два"] {
        assert_eq!(
            ask(
                &mut phone,
                &mut desktop,
                1_200,
                &Request::SendText { chat, text: text.to_owned() }
            ),
            Response::Done
        );
    }
    let msg_id = phone
        .store()
        .messages(&chat, 1, None)
        .expect("история")
        .last()
        .expect("сообщение легло")
        .msg_id;

    // Правило телефона возвращается словами, а не молчанием и не «сделано».
    let refused = ask(
        &mut phone,
        &mut desktop,
        1_300,
        &Request::EditMessage { chat, msg_id, text: "   ".into() },
    );
    assert!(matches!(refused, Response::Refused(_)), "пустая правка — не правка");

    assert_eq!(ask(&mut phone, &mut desktop, 1_400, &Request::ClearChat { chat }), Response::Done);
    assert!(
        phone.store().messages(&chat, 10, None).expect("история").is_empty(),
        "очистка с ноутбука — настоящая очистка на телефоне"
    );
}

#[test]
fn the_page_carries_the_marks_the_phone_shows_at_home() {
    // Проверка чужим кодом того же, что `terminal.rs` проверяет своим:
    // отметки не теряются **в проводе**. «Изменено» здесь главное — §14
    // запрещает молча подменять слова в истории, и запрещает на обоих экранах.
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    assert_eq!(
        ask(&mut phone, &mut desktop, 1_200, &Request::SendText { chat, text: "апечатка".into() }),
        Response::Done
    );
    let msg_id = phone
        .store()
        .messages(&chat, 1, None)
        .expect("история")
        .last()
        .expect("сообщение легло")
        .msg_id;

    let Response::History(before) =
        ask(&mut phone, &mut desktop, 1_250, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    assert_eq!(before[0].edited_ms, None, "непоправленное отметки не несёт");

    phone
        .step(1_300, Input::Command(Command::EditMessage { chat, msg_id, text: "опечатка".into() }))
        .expect("правка");

    let Response::History(after) =
        ask(&mut phone, &mut desktop, 1_400, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    assert_eq!(after[0].text, "опечатка");
    assert!(after[0].edited_ms.is_some(), "подменённые слова обязаны приехать с отметкой");
}

#[test]
fn a_reaction_is_told_as_the_whole_set_and_the_page_carries_it_too() {
    // Независимая проверка того же, что в `terminal.rs`, но чужим кодом:
    // новость разбирается тем же кодеком, каким её собирал телефон, и на ней
    // видно **форму** — набор целиком, а не «кто-то что-то поставил».
    let (mut phone, mut desktop, _) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    let request = Request::SendText { chat, text: "слово".into() };
    assert_eq!(ask(&mut phone, &mut desktop, 1_200, &request), Response::Done);
    let msg_id = phone
        .store()
        .messages(&chat, 1, None)
        .expect("история")
        .last()
        .expect("сообщение легло")
        .msg_id;

    let effects = phone
        .step(1_300, Input::Command(Command::SetReaction { chat, msg_id, emoji: "👍".into() }))
        .expect("реакция");
    let (frames, _) = split(effects);

    let mut told = None;
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, 1_300) else { continue };
        if envelope.payload_type != PayloadType::CompanionNotice {
            continue;
        }
        if let companion::Notice::Reacted { msg_id: id, reactions, .. } =
            companion::notice_from_payload(&envelope.payload).expect("разбор новости")
        {
            assert_eq!(id, msg_id);
            told = Some(reactions);
        }
    }
    let told = told.expect("о реакции десктоп обязан узнать");
    assert_eq!(told.len(), 1);
    assert_eq!(told[0].emoji, "👍");
    assert!(told[0].mine);

    // И то же самое — в истории: новости приходят, пока десктоп подключён,
    // а всё, что было до, он узнаёт страницей.
    let Response::History(page) =
        ask(&mut phone, &mut desktop, 1_400, &Request::History { chat, limit: 10, before: None })
    else {
        panic!("страница истории");
    };
    assert_eq!(page[0].reactions.len(), 1, "страница везёт реакции вместе с сообщением");
    assert_eq!(page[0].reactions[0].emoji, "👍");
}

#[test]
fn a_new_contact_tells_the_desktop_the_chat_list_changed() {
    // Список чатов у десктопа обновляется по этой новости, и без неё
    // добавленный на телефоне человек не появился бы там до перезапуска.
    let (mut phone, mut desktop, _) = paired(1_000);

    let other = Identity::from_seed([9u8; 32]);
    let card = ratatosk_codec::ContactCard {
        ik: other.public().ik,
        sk: other.public().sk,
        onion: String::new(),
        chatmail: "сосед@nine.example".into(),
        display_name: "сосед".into(),
        version: 1,
    };
    let effects = phone
        .step(
            1_100,
            Input::Command(Command::AddContact {
                card_bytes: card.encode().expect("карточка"),
                met_in_person: true,
            }),
        )
        .expect("добавление контакта");
    let (frames, _) = split(effects);

    let mut told = false;
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, 1_100) else { continue };
        if envelope.payload_type != PayloadType::CompanionNotice {
            continue;
        }
        if matches!(
            companion::notice_from_payload(&envelope.payload).expect("разбор новости"),
            companion::Notice::ChatsChanged
        ) {
            told = true;
        }
    }
    assert!(told, "о смене списка чатов десктоп обязан узнать");
}

#[test]
fn a_revoked_desktop_is_not_recognised_any_more() {
    // §13.4: «отзыв — удаление записи и немедленный разрыв сессии».
    // Проверяется именно немедленность: кадр, запечатанный до отзыва,
    // после него не должен быть понят.
    let (mut phone, mut desktop, device_id) = paired(1_000);
    let peer_ik = with_contact(&mut phone, 1_100);
    let chat = Engine::<MemoryStore>::chat_id_for(&peer_ik);

    // Кадр готов заранее — так выглядит десктоп, который уже набрал текст
    // и жмёт «отправить» в ту же секунду, когда с телефона его отзывают.
    let (_, frame) = desktop.ask(&Request::SendText { chat, text: "успею".into() });

    let effects = phone
        .step(1_200, Input::Command(Command::RevokePairing { device_id }))
        .expect("отзыв сопряжения");
    let (_, events) = split(effects);
    assert!(events
        .iter()
        .any(|event| matches!(event, Event::PairingRevoked { device_id: id } if *id == device_id)));
    assert!(phone.paired_devices().is_empty());

    let effects = phone.step(1_300, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    let (frames, _) = split(effects);
    assert!(
        addressed_to(frames, desktop.ik()).is_empty(),
        "отозванному устройству отвечать нечем: сессии больше нет"
    );

    let page = phone.store().messages(&chat, 10, None).expect("история");
    assert!(page.is_empty(), "отозванный десктоп не отправляет от имени пользователя");
}

#[test]
fn a_handshake_frame_of_noise_does_not_fell_the_core() {
    // Разбор дефекта, который старше режима компаньона. Кадр класса S с типом
    // «рукопожатие» и случайным содержимым проходил `unpad(view.sealed)?`
    // и ронял **весь шаг ядра** — своего рукопожатия для этого не требовалось,
    // хватало любого соседа по локальной сети. §7.3 про такие кадры говорит
    // прямо: они отбрасываются.
    let mut phone = phone(1, "телефон");
    let noise: Vec<u8> = (0..SizeClass::S.sealed_len()).map(|n| (n % 251) as u8 + 1).collect();
    let frame = handshake_frame_raw(0, &noise);

    let effects = phone
        .step(1_000, Input::Received { via: Transport::Lan, frame })
        .expect("мусорный кадр рукопожатия роняться не должен");
    assert!(effects.is_empty(), "и отвечать на него нечем: {effects:?}");
}

#[test]
fn a_stranger_whose_handshake_does_not_parse_gets_silence() {
    // Отозванному телефон отвечает надгробием (5вл) — но **только ему**.
    // Отвечать всем, чьё рукопожатие не разобралось, значило бы сообщать
    // любому, кто постучится, что мы здесь и что-то про него знаем.
    //
    // И заодно: такое рукопожатие не роняет шаг ядра и не заводит ни
    // контакта, ни сессии. До разбора 5вл роняло — `ContactCard::decode`
    // спотыкался о пустые байты.
    let mut phone = phone(1, "телефон");
    let phone_ik = phone.own_card().ik;

    let mut stranger = Desktop::with_identity(Identity::from_seed([42u8; 32]));
    let hello = stranger.hello(&phone_ik, &[]);

    let effects = phone
        .step(1_000, Input::Received { via: Transport::Lan, frame: hello })
        .expect("рукопожатие без карточки роняться не должно");
    assert!(effects.is_empty(), "незнакомцу не отвечают ничем: {effects:?}");
    assert!(phone.contacts().is_empty(), "и контактом он не становится");
}

#[test]
fn a_contact_may_not_speak_the_companion_wire() {
    // Кадры компаньона, пришедшие от **контакта**, — не наш разговор.
    // Ответив на них, телефон отдал бы собеседнику список чатов и право
    // отправлять сообщения от имени пользователя.
    //
    // Различаются контакт и устройство ровно одним: есть ли запись
    // о сопряжении. Значит проверять надо человека, который прошёл
    // рукопожатие честно, как контакт, — и заговорил не своим проводом.
    let mut phone = phone(1, "телефон");
    let phone_ik = phone.own_card().ik;

    let stranger = Identity::from_seed([9u8; 32]);
    let stranger_ik = stranger.public().ik;
    let card = ratatosk_codec::ContactCard {
        ik: stranger.public().ik,
        sk: stranger.public().sk,
        onion: String::new(),
        chatmail: "чужой@nine.example".into(),
        display_name: "чужой".into(),
        version: 1,
    };
    let card_bytes = card.encode().expect("карточка");
    let mut wire = Desktop::with_identity(stranger);

    let hello = wire.hello(&phone_ik, &card_bytes);
    let effects =
        phone.step(1_000, Input::Received { via: Transport::Lan, frame: hello }).expect("шаг");
    let (frames, _) = split(effects);
    for frame in addressed_to(frames, wire.ik()) {
        wire.take(&frame, 1_000);
    }
    assert!(wire.session.is_some(), "как контакт он рукопожатие проходит");
    assert!(phone.contacts().contains_key(&stranger_ik), "и контактом становится (§8.2)");

    let before = phone.anomalies(&stranger_ik).malformed;
    let (_, frame) = wire.ask(&Request::Chats);
    let effects = phone.step(1_100, Input::Received { via: Transport::Lan, frame }).expect("шаг");
    let (frames, _) = split(effects);

    assert!(
        addressed_to(frames, stranger_ik).is_empty(),
        "контакту на просьбу компаньона не отвечают"
    );
    assert_eq!(
        phone.anomalies(&stranger_ik).malformed,
        before + 1,
        "и считают это за кадр не по адресу (§7.3, шаг 4)"
    );
}

#[test]
fn pairing_survives_a_restart() {
    // Запись о сопряжении обязана лежать на диске: иначе десктоп после
    // перезапуска телефона превращается в незнакомца, и человеку пришлось бы
    // сопрягать его заново — а секрет ему уже отдан и отозвать его нечем.
    //
    // По настоящему файлу, а не по памяти: база в памяти исчезает вместе
    // с процессом и перезапуск проверить не может в принципе.
    let db = TempDb::new("pairing");
    let db_key = Zeroizing::new([7u8; 32]);

    let device_id = {
        let mut engine = Engine::new(
            Identity::from_seed([1u8; 32]),
            db.open(&db_key),
            Box::new(MemoryBlobs::new()),
            Box::new(SeededEntropy::new(1)),
            addresses(),
        );
        let effects = engine
            .step(1_000, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
            .expect("сопряжение");
        let (_, events) = split(effects);
        events
            .into_iter()
            .find_map(|event| match event {
                Event::PairingReady { device_id, .. } => Some(device_id),
                _ => None,
            })
            .expect("событие сопряжения")
    };

    let mut engine = Engine::new(
        Identity::from_seed([1u8; 32]),
        db.open(&db_key),
        Box::new(MemoryBlobs::new()),
        Box::new(SeededEntropy::new(1)),
        addresses(),
    );
    engine.restore().expect("подъём с диска");

    let devices = engine.paired_devices();
    assert_eq!(devices.len(), 1, "сопряжение обязано пережить перезапуск");
    assert_eq!(devices[0].device_id, device_id);
    assert_eq!(devices[0].label, "ноутбук");
    assert!(!engine.device_connected(&device_id), "канала после перезапуска нет");
}

#[test]
fn the_watched_beacons_include_the_paired_desktop() {
    // Соединения односторонние: не услышав маяк десктопа, телефон принял бы
    // рукопожатие и не смог бы ответить.
    let mut phone = phone(1, "телефон");
    let effects = phone
        .step(1_000, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");

    let watched = effects
        .iter()
        .find_map(|effect| match effect {
            Effect::WatchLanPeers(peers) => Some(peers.clone()),
            _ => None,
        })
        .expect("список маяков обязан обновиться");
    assert_eq!(watched.len(), 1, "устройство ищется в эфире наравне с контактами");
}

/// Полный обмен с устройством на **настоящей** базе.
///
/// Отдельно от всех тестов выше, и это не педантизм. Они живут на
/// `MemoryStore`, у которого нет ни внешних ключей, ни `STRICT`, ни
/// ограничений вообще, — и потому пропустили настоящую поломку: столбец
/// `sessions.peer_ik` объявлен `REFERENCES contacts(ik)`, а сопряжённое
/// устройство контактом не является нарочно. Первая же сессия с десктопом
/// упиралась во внешний ключ, шаг ядра возвращал отказ хранилища, и драйвер
/// останавливал ядро. На стенде без `--data` этого тоже не было видно —
/// он на памяти.
///
/// Правило отсюда: **всё, что трогает хранилище новым способом, проверяется
/// на SQLite.** Память проверяет логику, база проверяет схему.
#[test]
fn a_device_talks_to_a_phone_on_a_real_database() {
    let db = TempDb::new("device-sql");
    let db_key = Zeroizing::new([9u8; 32]);
    let identity = Identity::from_seed([1u8; 32]);
    let phone_ik = identity.public().ik;

    let mut phone = Engine::new(
        identity,
        db.open(&db_key),
        Box::new(MemoryBlobs::new()),
        Box::new(SeededEntropy::new(1)),
        addresses(),
    );
    phone
        .step(
            0,
            Input::Command(Command::SetTransportEnabled {
                transport: Transport::Lan,
                enabled: true,
            }),
        )
        .expect("включение локальной сети");

    let effects = phone
        .step(1_000, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
        .expect("сопряжение");
    let (_, events) = split(effects);
    let uri = events
        .into_iter()
        .find_map(|event| match event {
            Event::PairingReady { uri, .. } => Some(uri),
            _ => None,
        })
        .expect("ссылка");
    let invite = PairingInvite::from_uri(&uri).expect("разбор ссылки");

    let mut desktop = Desktop::from_invite(&invite);
    let hello = desktop.hello(&phone_ik, &[]);

    // Вот этот шаг и падал: `persist_session` писал сессию, чей `peer_ik`
    // не значится в `contacts`.
    let effects = phone
        .step(1_100, Input::Received { via: Transport::Lan, frame: hello })
        .expect("рукопожатие с устройством не должно ронять ядро");
    let (frames, _) = split(effects);
    for frame in addressed_to(frames, desktop.ik()) {
        desktop.take(&frame, 1_100);
    }
    assert!(desktop.session.is_some(), "сессия установилась");

    // И дальше по ней ходят настоящие просьбы — тоже через запись на диск.
    let (id, frame) = desktop.ask(&Request::Chats);
    let effects = phone
        .step(1_200, Input::Received { via: Transport::Lan, frame })
        .expect("просьба тоже не должна ронять ядро");
    let (frames, _) = split(effects);

    let mut answered = false;
    for frame in addressed_to(frames, desktop.ik()) {
        let Some(envelope) = desktop.take(&frame, 1_200) else { continue };
        if envelope.payload_type != PayloadType::CompanionResponse {
            continue;
        }
        let (got, _) = companion::response_from_payload(&envelope.payload).expect("ответ");
        assert_eq!(got, id);
        answered = true;
    }
    assert!(answered, "телефон ответил на просьбу");
    assert!(phone.device_connected(&phone.paired_devices()[0].device_id), "и отметил связь");
}

#[test]
fn a_device_session_does_not_outlive_a_restart() {
    // Следствие того же решения, и его стоит закрепить: сессия терминала
    // одноразовая, на диск не ложится — а значит после перезапуска телефона
    // её там нет. Десктоп поздоровается заново, это стоит круга по локальной
    // сети; пережившая перезапуск запись только разошлась бы с той, которой
    // у десктопа уже нет.
    let db = TempDb::new("device-session");
    let db_key = Zeroizing::new([9u8; 32]);
    let phone_ik = Identity::from_seed([1u8; 32]).public().ik;

    let mut desktop = {
        let mut phone = Engine::new(
            Identity::from_seed([1u8; 32]),
            db.open(&db_key),
            Box::new(MemoryBlobs::new()),
            Box::new(SeededEntropy::new(1)),
            addresses(),
        );
        let effects = phone
            .step(1_000, Input::Command(Command::PairDevice { label: "ноутбук".into() }))
            .expect("сопряжение");
        let (_, events) = split(effects);
        let uri = events
            .into_iter()
            .find_map(|event| match event {
                Event::PairingReady { uri, .. } => Some(uri),
                _ => None,
            })
            .expect("ссылка");
        let invite = PairingInvite::from_uri(&uri).expect("разбор ссылки");
        let mut desktop = Desktop::from_invite(&invite);
        let hello = desktop.hello(&phone_ik, &[]);
        let effects =
            phone.step(1_100, Input::Received { via: Transport::Lan, frame: hello }).expect("шаг");
        let (frames, _) = split(effects);
        for frame in addressed_to(frames, desktop.ik()) {
            desktop.take(&frame, 1_100);
        }
        desktop
    };
    assert!(desktop.session.is_some());

    let mut phone = Engine::new(
        Identity::from_seed([1u8; 32]),
        db.open(&db_key),
        Box::new(MemoryBlobs::new()),
        Box::new(SeededEntropy::new(1)),
        addresses(),
    );
    phone.restore().expect("подъём с диска");

    assert_eq!(phone.paired_devices().len(), 1, "само сопряжение перезапуск переживает");
    assert_eq!(phone.session_count(), 0, "а сессия с ним — нет");

    // Кадр в сессию, которой у телефона больше нет, отбрасывается молча
    // (§7.3) — и ядро при этом стоит на ногах.
    let (_, frame) = desktop.ask(&Request::Chats);
    let effects = phone
        .step(2_000, Input::Received { via: Transport::Lan, frame })
        .expect("кадр в мёртвую сессию не роняет ядро");
    let (frames, _) = split(effects);
    assert!(addressed_to(frames, desktop.ik()).is_empty(), "отвечать нечем");
}
