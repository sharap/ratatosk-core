//! Ядро протокола (§13.3).
//!
//! «В ядре: крипта, протокол, транспорты, хранилище, синхронизация.
//! В клиентах — только UI и системная интеграция. Правило без исключений:
//! никакой протокольной логики выше UniFFI-границы.»
//!
//! [`Engine`] — единственная точка входа. Он не создаёт потоков, не открывает
//! сокетов и не читает часы: время приходит параметром `now_ms`, внешний мир
//! общается с ним через [`Input`] и [`Effect`], случайность — через
//! [`Entropy`].
//!
//! **Область этого этапа — 1:1 текст.** Файлы (§10), группы (§11) и
//! перерукопожатие (§8.5) ещё не проходят через `step`; каждая такая ветка
//! помечена `todo!()` со ссылкой на раздел. Ветки перечислены поимённо,
//! без `_`, поэтому новый вариант `Command` сломает компиляцию здесь.

use std::collections::{BTreeMap, BTreeSet};

use ratatosk_codec::{ContactCard, Envelope, PayloadType, Value};
use ratatosk_crdt::{DedupWindow, Hlc, HlcClock, MsgId};
use ratatosk_crypto::aead;
use ratatosk_crypto::handshake::{
    Accepted, HandshakeOutcome, Initiator, PendingHandshake, Responder,
};
use ratatosk_crypto::{HandshakeReplayGuard, Identity, RekeyPolicy, Session};
use ratatosk_proto::fragment::Reassembler;
use ratatosk_proto::receipts::{Receipt, MAX_RECEIPT_IDS};
use ratatosk_proto::transport_policy::{Attempt, Decision, PeerAvailability, SessionBinding};
use ratatosk_proto::{DeliveryStatus, SessionRegistry, Transport};
use ratatosk_store::{Store, StoredMessage};
use ratatosk_wire::{pad_to, unpad, FrameType, Header, SizeClass};

use crate::entropy::Entropy;
use crate::io::{ChatId, Command, Effect, Event, Input};

/// Номер первого сообщения рукопожатия в поле `counter` заголовка.
///
/// **Уточнение к §8.3.** Спецификация говорит, что кадры рукопожатия идут
/// с `session_id = 0`, но не говорит, как получатель отличает первое
/// сообщение `-> e, es, s, ss` от ответа `<- e, ee, se`. Оба приходят с нулём.
///
/// Формат кадра менять не пришлось: `counter` в заголовке (§7.1) — это
/// «номер сообщения в отправляющей цепочке», и для рукопожатия он
/// естественно читается как номер шага. Ноль — первое, единица — ответ.
/// В §8.3 это стоит дописать одной фразой.
pub const HANDSHAKE_STEP_FIRST: u64 = 0;
/// Номер ответного сообщения рукопожатия.
pub const HANDSHAKE_STEP_RESPONSE: u64 = 1;

/// Класс кадра для рукопожатия (§5.5).
///
/// Первое сообщение — это `e` (32) + зашифрованный `s` (48) + карточка
/// (около 200 байт, §4.1) + тег. Всё укладывается в 4 КиБ с запасом.
const HANDSHAKE_CLASS: SizeClass = SizeClass::S;

/// Страховочный таймаут попытки, если транспорт своего не задаёт.
///
/// [`Attempt::timeout_ms`] возвращает `None` для почты — её ответа ждать
/// бессмысленно (§5.4). Но запись в очереди без таймера зависла бы навсегда,
/// поэтому у прямых каналов таймаут есть всегда, а это значение — потолок
/// из §5.4 на случай, если политика промолчит.
const ONION_FALLBACK_TIMEOUT_MS: u64 = 45_000;

/// Сколько ждать, пока обнаружение (§5.1) ответит, есть ли собеседник в сети.
///
/// Нужно ровно на холодном старте и после смены сети: `seen_on_lan` не
/// переживает перезапуск намеренно — адрес в локальной сети живёт столько же,
/// сколько подключение, и поднимать его с диска значило бы врать. Но mDNS
/// отвечает не мгновенно, и без этой паузы первое же сообщение после запуска
/// объявлялось недоставленным раньше, чем собеседник вообще успевал найтись.
///
/// Три секунды: mDNS в локальной сети отвечает за сотни миллисекунд даже на
/// телефоне, а человек, нажавший «отправить», столько подождёт. Ожидание
/// выдаётся один раз на контакт за сеанс, поэтому собеседник, которого в этой
/// сети нет, стоит трёх секунд один раз, а не при каждой отправке.
const LAN_DISCOVERY_GRACE_MS: u64 = 3_000;

/// Отказ ядра.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// Ошибка хранилища.
    #[error("хранилище: {0}")]
    Store(#[from] ratatosk_store::StoreError),
    /// Ошибка криптослоя.
    #[error("криптография: {0}")]
    Crypto(#[from] ratatosk_crypto::CryptoError),
    /// Ошибка разбора структуры.
    #[error("формат: {0}")]
    Codec(#[from] ratatosk_codec::CodecError),
    /// Ошибка формата кадра.
    #[error("кадр: {0}")]
    Wire(#[from] ratatosk_wire::WireError),
    /// Гибридные часы отказались выдать метку.
    #[error("часы: {0}")]
    Clock(#[from] ratatosk_crdt::HlcError),
    /// Обращение к неизвестному контакту или чату.
    #[error("контакт неизвестен")]
    UnknownPeer,
}

// Варианта «нет доступного транспорта» здесь нет сознательно. Раньше он был,
// и это была ошибка проектирования: сообщение, которому некуда ехать, — не
// отказ ядра, а исход доставки. Отказ вернулся бы вызывающему и сообщение
// исчезло бы, тогда как §14 требует показать пользователю, что оно не ушло.
// Теперь этот случай выражается статусом `DeliveryStatus::Undeliverable`,
// а сообщение остаётся в истории.

/// Собственные адреса — то, что уезжает в контакт-карточке (§4.1).
#[derive(Debug, Clone)]
pub struct SelfAddresses {
    /// Onion-адрес этого устройства (§5.2).
    pub onion: String,
    /// Chatmail-адрес (§5.3).
    pub chatmail: String,
    /// Отображаемое имя. Получателем не доверяется (§4.1).
    pub display_name: String,
}

/// Что ядро знает о контакте.
#[derive(Debug, Clone)]
pub struct Contact {
    /// Карточка с адресами.
    pub card: ContactCard,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Что известно о доступности прямо сейчас (§5.4).
    pub availability: PeerAvailability,
}

/// Что сейчас с сообщением на пути к получателю (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryState {
    /// Сессии ещё нет: рукопожатие в пути, сообщение ждёт его завершения.
    AwaitingSession,
    /// Ушло прямым каналом. Ждём квитанции, отказа или истечения срока.
    ///
    /// Прямой канал подтверждает доставку квитанцией за миллисекунды (§9.4),
    /// поэтому истёкший срок означает здесь **не** «отправлено», а «не вышло»:
    /// попытка переходит к следующему транспорту по §5.4. Запись уходит
    /// из очереди либо по подтверждению, либо когда транспорты кончились.
    InFlight { via: Transport, timer: u64 },
    /// LAN включён, но собеседника в эфире ещё не слышали — ждём обнаружение.
    ///
    /// Это **не** ступень §5.4: транспорт здесь не тратится. «Мы ещё не
    /// искали» и «мы искали и не нашли» — разные вещи, и путать их дорого.
    /// Сразу после запуска не слышали никого: `seen_on_lan` не поднимается
    /// с диска (адрес в локальной сети живёт ровно столько, сколько сеанс),
    /// а mDNS отвечает через сотни миллисекунд. Первое сообщение после
    /// перезапуска попадало ровно в эту щель и объявлялось недоставленным
    /// за долю секунды до того, как собеседник находился.
    AwaitingDiscovery { timer: u64 },
}

/// Незавершённое исходящее рукопожатие вместе с его попыткой доставки.
///
/// Первое сообщение — такой же кадр, как любой другой, и теряется так же.
/// Без собственной попытки по §5.4 получалась бы тупиковая связка: данные
/// переходят на почту, а рукопожатие, без которого они не поедут, осталось
/// в упавшем onion.
struct OutgoingHandshake {
    state: PendingHandshake,
    /// Готовый кадр первого сообщения — чтобы переслать его другим
    /// транспортом, не начиная рукопожатие заново.
    frame: Vec<u8>,
    attempt: Attempt,
    peer_ik: [u8; 32],
    /// Метка таймера текущей попытки, если транспорт прямой.
    ///
    /// Без неё молча проглоченное рукопожатие не переходит на следующий
    /// транспорт: об отказе никто не сообщает, а ждать больше нечего.
    timer: Option<u64>,
}

/// Сообщение в очереди доставки.
#[derive(Debug, Clone)]
struct Delivery {
    msg_id: MsgId,
    peer_ik: [u8; 32],
    /// Конверт хранится целиком: при переходе на другой транспорт кадр
    /// запечатывается заново, следующим ключом цепочки. Копия получится
    /// с тем же `msg_id`, и если обе дойдут, лишнюю съест дедупликация (§9.2).
    envelope: Vec<u8>,
    attempt: Attempt,
    state: DeliveryState,
}

/// Состояние ядра.
///
/// Обобщено по хранилищу, чтобы симуляция (§16) подставляла [`ratatosk_store::MemoryStore`],
/// а продукт — SQLite. Ни один сценарий не должен требовать правки
/// протокольного кода ради подмены хранилища.
pub struct Engine<S: Store> {
    identity: Identity,
    addresses: SelfAddresses,
    store: S,
    entropy: Box<dyn Entropy>,
    clock: HlcClock,
    sessions: SessionRegistry,
    dedup: DedupWindow,
    reassembler: Reassembler,
    handshake_guard: HandshakeReplayGuard,
    rekey: RekeyPolicy,
    contacts: BTreeMap<[u8; 32], Contact>,
    by_chat: BTreeMap<ChatId, [u8; 32]>,
    pending: Vec<OutgoingHandshake>,
    outbox: Vec<Delivery>,
    next_timer_token: u64,
    /// §5.1: по умолчанию выключен. Хранится отдельно от контактов, потому
    /// что состояние переключателя существует и когда контактов ещё нет.
    lan_enabled: bool,
    /// Кого заметили в LAN раньше, чем добавили в контакты.
    seen_on_lan: BTreeSet<[u8; 32]>,
    /// Кому уже давали срок на обнаружение в этом сеансе.
    ///
    /// Ожидание выдаётся **один раз на контакт**, а не на каждое сообщение:
    /// собеседнику, которого в этой сети нет, иначе платили бы задержкой
    /// перед каждой отправкой. Сбрасывается при смене сети и при включении
    /// LAN — то есть тогда, когда прежний ответ «не слышно» устарел.
    awaited_discovery: BTreeSet<[u8; 32]>,
    /// До какого места в каждом чате уже отправлена квитанция о прочтении.
    read_upto: BTreeMap<ChatId, Hlc>,
}

impl<S: Store> Engine<S> {
    /// Собирает ядро.
    pub fn new(
        identity: Identity,
        store: S,
        entropy: Box<dyn Entropy>,
        addresses: SelfAddresses,
    ) -> Engine<S> {
        Engine {
            identity,
            addresses,
            store,
            entropy,
            clock: HlcClock::new(),
            sessions: SessionRegistry::new(),
            dedup: DedupWindow::default(),
            reassembler: Reassembler::new(),
            handshake_guard: HandshakeReplayGuard::default(),
            rekey: RekeyPolicy::default(),
            contacts: BTreeMap::new(),
            by_chat: BTreeMap::new(),
            pending: Vec::new(),
            outbox: Vec::new(),
            next_timer_token: 1,
            lan_enabled: false,
            seen_on_lan: BTreeSet::new(),
            awaited_discovery: BTreeSet::new(),
            read_upto: BTreeMap::new(),
        }
    }

    /// Идентификатор чата 1:1 с этим контактом.
    ///
    /// Первые 16 байт `IK` собеседника. Годится, потому что обе стороны
    /// вычисляют его из одного и того же значения без всякой договорённости,
    /// и потому что `IK` уникален по построению. Для групп идентификатор
    /// будет свой (§11), и это уже другая ветка.
    #[must_use]
    pub fn chat_id_for(peer_ik: &[u8; 32]) -> ChatId {
        peer_ik[..16].try_into().expect("срез длины 16")
    }

    /// Отпечаток собственной идентичности (§3).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Своя контакт-карточка — для QR и ссылок (§4.1).
    #[must_use]
    pub fn own_card(&self) -> ContactCard {
        ContactCard {
            ik: self.identity.public().ik,
            sk: self.identity.public().sk,
            onion: self.addresses.onion.clone(),
            chatmail: self.addresses.chatmail.clone(),
            display_name: self.addresses.display_name.clone(),
            version: 1,
        }
    }

    /// Известные контакты.
    #[must_use]
    pub fn contacts(&self) -> &BTreeMap<[u8; 32], Contact> {
        &self.contacts
    }

    /// Хранилище — для миграций, чтения и обслуживания.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Хранилище на чтение.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Сколько сообщений сейчас в очереди доставки (§5.4).
    #[must_use]
    pub fn queued(&self) -> usize {
        self.outbox.len()
    }

    /// Сколько сообщений ждёт установления сессии.
    #[must_use]
    pub fn awaiting_session(&self) -> usize {
        self.outbox.iter().filter(|d| d.state == DeliveryState::AwaitingSession).count()
    }

    /// Обрабатывает один вход и возвращает эффекты.
    ///
    /// Единственный метод, меняющий состояние. Одна и та же последовательность
    /// входов при одном и том же начальном состоянии даёт одну и ту же
    /// последовательность эффектов — на этом держится §16.
    pub fn step(&mut self, now_ms: u64, input: Input) -> Result<Vec<Effect>, EngineError> {
        match input {
            Input::Command(command) => self.on_command(now_ms, command),
            Input::Received { via, frame } => self.on_frame(now_ms, via, &frame),
            Input::SeenOnLan { peer_ik } => {
                match self.contacts.get_mut(&peer_ik) {
                    Some(contact) => contact.availability.seen_on_lan = true,
                    // Контакт и его видимость приходят разными путями —
                    // командой от UI и событием транспорта, — и порядок между
                    // ними не гарантирован. Потерять отметку значило бы
                    // отправить почтой сообщение собеседнику за стенкой,
                    // и разбираться потом, почему.
                    None => {
                        self.seen_on_lan.insert(peer_ik);
                        return Ok(Vec::new());
                    }
                }
                // Собеседник нашёлся — всё, что ждало этого ответа, едет
                // немедленно, не досиживая свой срок.
                self.resume_discovery(peer_ik)
            }
            Input::Connected { .. } => Ok(Vec::new()),
            Input::ConnectionLost { peer_ik, via } => {
                // Сессия, начатая в LAN, через onion не продолжается (§5.4);
                // разрыв LAN закрывает её, а не переводит. Сессию поверх Tor
                // разрыв onion не трогает: почта живёт в том же семействе
                // и продолжит ту же сессию.
                if via == Transport::Lan {
                    if let Some(id) = self.sessions.for_peer(&peer_ik, via) {
                        self.sessions.remove(id);
                        // И с диска: восстановленная после перезапуска сессия
                        // указывала бы на собеседника, с которым связь уже
                        // разорвана, а §5.4 требует установить новую.
                        self.store.delete_session(id)?;
                    }
                }
                self.on_delivery_failed(peer_ik, via)
            }
            // TODO(этап 1): перерукопожатие (§8.5) и расписание уборки (§12)
            // тоже придут таймерами — пока их ставит только доставка.
            Input::Timer { token } => self.on_timer(token),
        }
    }

    /// Ближайший момент, когда ядру нужно проснуться.
    #[must_use]
    pub fn next_deadline_ms(&self) -> Option<u64> {
        // TODO(этап 1): минимум из таймаутов доставки (§5.4), срока
        // перерукопожатия (§8.5) и расписания уборки (§12).
        None
    }

    // --- команды ------------------------------------------------------------

    fn on_command(&mut self, now_ms: u64, command: Command) -> Result<Vec<Effect>, EngineError> {
        match command {
            Command::AddContact { card_bytes, met_in_person } => {
                self.add_contact(now_ms, &card_bytes, met_in_person)
            }
            Command::MarkVerified { peer_ik } => {
                self.contacts.get_mut(&peer_ik).ok_or(EngineError::UnknownPeer)?.verified = true;
                // Сверка голосом (§4.2) — разовое действие пользователя.
                // Не пережив перезапуск, она обесценивается: просить сверять
                // отпечаток заново при каждом старте никто не станет.
                self.persist_contact(&peer_ik, now_ms)?;
                Ok(Vec::new())
            }
            Command::SendText { chat, text } => self.send_text(now_ms, chat, &text),
            Command::SetLanEnabled(on) => {
                self.lan_enabled = on;
                for contact in self.contacts.values_mut() {
                    contact.availability.lan_enabled = on;
                }
                // Прежние «не слышно» устарели: эфир только что открылся,
                // и каждому контакту снова полагается срок на обнаружение.
                self.awaited_discovery.clear();
                let mut effects = vec![Effect::SetLanEnabled(on)];
                if on {
                    effects.push(self.watch_lan_peers());
                }
                Ok(effects)
            }
            Command::NetworkChanged => Ok(self.on_network_changed()),
            Command::SendFile { .. } => todo!("этап 4: передача файлов (§10)"),
            Command::CreateGroup { .. }
            | Command::InviteToGroup { .. }
            | Command::EvictFromGroup { .. } => todo!("этап 5: группы (§11)"),
            Command::MarkRead { chat, up_to } => self.on_mark_read(now_ms, chat, up_to),
        }
    }

    /// Поднимает состояние с диска после перезапуска.
    ///
    /// Отдельно от [`Engine::new`], а не внутри неё, по двум причинам: `new`
    /// остаётся не могущей отказать, и симуляция (§16) продолжает собирать
    /// ядро без единого обращения к хранилищу.
    ///
    /// Сессии здесь **не** восстанавливаются. Ключевой материал ретчета пришлось
    /// бы сериализовать вместе с кэшем пропущенных ключей, а выигрыш невелик:
    /// без сессии первая же отправка проводит рукопожатие заново, и в локальной
    /// сети это миллисекунды. Плата за это записана в §8.5 — новая сессия
    /// означает и новый forward secrecy, а не потерю переписки.
    /// Возвращает число поднятых контактов.
    ///
    /// Эффектов здесь нет намеренно: `restore` вызывается до того, как
    /// появился драйвер, и вернуть их было бы некуда. Список маяков для
    /// транспорта (§5.1) выставит `Command::SetLanEnabled`, который клиент
    /// подаёт в любом случае — а при выключенном LAN он и не нужен.
    pub fn restore(&mut self) -> Result<usize, EngineError> {
        let stored = self.store.contacts()?;
        let restored = stored.len();
        for contact in stored {
            let card = ContactCard::decode(&contact.card_bytes)?.into_parts().1;
            let peer_ik = card.ik;
            let availability = PeerAvailability {
                has_onion: !card.onion.is_empty(),
                has_chatmail: !card.chatmail.is_empty(),
                lan_enabled: self.lan_enabled,
                // Видимость в LAN живёт ровно столько, сколько работает
                // устройство: адрес в локальной сети меняется при каждом
                // подключении, и поднимать его с диска значило бы врать.
                seen_on_lan: false,
            };
            let chat = Self::chat_id_for(&peer_ik);
            self.contacts
                .insert(peer_ik, Contact { card, verified: contact.verified, availability });
            self.by_chat.insert(chat, peer_ik);

            // Водяной знак прочтения (§9.4). Без него первое же открытие чата
            // после перезапуска выпускало бы квитанцию о том, что собеседнику
            // уже сообщили, — то есть квитанция становилась следствием старта
            // приложения, а не действия человека.
            if let Some(edge) = self.load_read_upto(chat)? {
                self.read_upto.insert(chat, edge);
            }
        }

        // Сессии поднимаются после контактов: внешний ключ в схеме связывает
        // их с `contacts`, и порядок здесь тот же, что и на записи.
        for stored in self.store.sessions()? {
            let session = Session::restore(&stored.snapshot)?;
            let binding = if stored.lan { SessionBinding::Lan } else { SessionBinding::Tor };
            self.sessions.insert(session, binding);
        }
        Ok(restored)
    }

    /// Складывает состояние сессии на диск (§8.3, §12).
    ///
    /// **Вызывается до того, как кадр уйдёт в сеть.** Порядок здесь — не
    /// аккуратность, а корректность: счётчик отправки, откатившийся после
    /// того как система убила процесс, означает второй кадр с той же парой
    /// «ключ, nonce». Для XChaCha20-Poly1305 это не потеря сообщения,
    /// а раскрытие обоих.
    ///
    /// На приёме порядок обратный и это безопасно: если процесс умрёт между
    /// расшифровкой и записью, кадр после перезапуска расшифруется тем же
    /// ключом ещё раз, а дубль съест дедупликация (§9.2).
    fn persist_session(&mut self, session_id: u64) -> Result<(), EngineError> {
        let Some(bound) = self.sessions.get(session_id) else {
            return Ok(());
        };
        let stored = ratatosk_store::StoredSession {
            session_id,
            peer_ik: bound.session.peer_ik,
            lan: bound.binding == SessionBinding::Lan,
            snapshot: bound.session.export().to_vec(),
            established_ms: bound.session.established_ms,
        };
        self.store.put_session(&stored)?;
        Ok(())
    }

    /// Складывает контакт на диск (§4, §12).
    fn persist_contact(&mut self, peer_ik: &[u8; 32], now_ms: u64) -> Result<(), EngineError> {
        let Some(contact) = self.contacts.get(peer_ik) else {
            return Ok(());
        };
        // §6: подпись считается над принятыми байтами, поэтому карточка
        // сохраняется целиком и неизменной, а не пересобирается из полей.
        let card_bytes = contact.card.encode()?;
        let stored = ratatosk_store::StoredContact {
            ik: contact.card.ik,
            sk: contact.card.sk,
            onion: contact.card.onion.clone(),
            chatmail: contact.card.chatmail.clone(),
            display_name: contact.card.display_name.clone(),
            card_version: contact.card.version,
            card_bytes,
            verified: contact.verified,
            created_ms: now_ms,
        };
        self.store.put_contact(&stored)?;
        Ok(())
    }

    fn add_contact(
        &mut self,
        now_ms: u64,
        card_bytes: &[u8],
        met_in_person: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let card = ContactCard::decode(card_bytes)?.into_parts().1;
        let peer_ik = card.ik;
        let fingerprint =
            ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk)?.fingerprint();

        let availability = PeerAvailability {
            has_onion: !card.onion.is_empty(),
            has_chatmail: !card.chatmail.is_empty(),
            ..PeerAvailability::default()
        };

        // §4.2: QR при личной встрече — канал доверенный по построению,
        // ссылка — нет, и контакт остаётся непроверенным до сверки голосом.
        // Новый контакт наследует текущее состояние LAN: иначе контакт,
        // добавленный после включения, остался бы с `lan_enabled = false`,
        // и §5.4 отправил бы его сообщения мимо локальной сети — молча,
        // потому что onion и почта тоже «работают».
        let availability = PeerAvailability {
            lan_enabled: self.lan_enabled,
            seen_on_lan: self.seen_on_lan.remove(&peer_ik),
            ..availability
        };

        self.contacts.insert(peer_ik, Contact { card, verified: met_in_person, availability });
        self.by_chat.insert(Self::chat_id_for(&peer_ik), peer_ik);
        self.persist_contact(&peer_ik, now_ms)?;

        let mut effects = vec![Effect::Notify(Event::ContactAdded {
            peer_ik,
            fingerprint,
            verified: met_in_person,
        })];
        // Маяк нового контакта транспорт ещё не ищет — список изменился.
        if self.lan_enabled {
            effects.push(self.watch_lan_peers());
        }
        Ok(effects)
    }

    /// Сеть сменилась: всё, что известно о локальной, устарело (§5.1).
    ///
    /// Видимость сбрасывается **до** переоткрытия транспорта, и порядок
    /// важен: пока `seen_on_lan` держится, §5.4 продолжает выбирать LAN
    /// и отправлять по адресам прежней сети. Сообщения при этом не теряются
    /// — они честно упрутся в отказ и уйдут дальше по §5.4, — но каждое
    /// заплатит таймаутом за то, что и так уже известно.
    ///
    /// Сессии не трогаем. Ключевой материал к сети не привязан: если оба
    /// устройства оказались в новой сети вместе, переписка продолжится без
    /// нового рукопожатия. Сессию, чьё соединение оборвалось, закроет
    /// `Input::ConnectionLost` своим чередом (§5.4).
    fn on_network_changed(&mut self) -> Vec<Effect> {
        for contact in self.contacts.values_mut() {
            contact.availability.seen_on_lan = false;
        }
        self.seen_on_lan.clear();
        // Сеть другая — значит и ответ «здесь его не слышно» относился
        // к прежней. Срок на обнаружение выдаётся заново.
        self.awaited_discovery.clear();

        if !self.lan_enabled {
            // Выключенный LAN переоткрывать нечего, и объявляться незачем.
            return Vec::new();
        }
        vec![Effect::RestartLan, self.watch_lan_peers()]
    }

    /// Клиент сообщил, что пользователь прочитал чат до этого места (§9.4).
    ///
    /// **Единственный источник квитанции о прочтении.** Ни приём сообщения,
    /// ни открытие чата, ни запуск приложения её не порождают: ядро не знает
    /// и не может знать, что человек прочитал. Знает клиент — и говорит
    /// об этом вызовом. Из этого следует и то, что клиент, который квитанций
    /// о прочтении не хочет (или у которого они выключены настройкой), просто
    /// не зовёт эту команду; отдельного выключателя в ядре для этого не надо.
    ///
    /// Водяной знак — до какого места уже отправляли — **лежит на диске**.
    /// Раньше он жил в памяти, и это была ошибка ровно того же рода: после
    /// перезапуска первое же открытие чата выпускало квитанцию заново, то есть
    /// квитанция получалась следствием запуска приложения, а не действия
    /// человека. Одному собеседнику это выглядит как «он перечитывает нашу
    /// переписку» на пустом месте.
    fn on_mark_read(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        up_to: MsgId,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        let window = self.store.messages(&chat, MAX_RECEIPT_IDS, None)?;
        // Граница задаётся сообщением, а не временем: клиент знает, до какого
        // места дочитал пользователь, но не знает меток HLC.
        let Some(edge) = window.iter().find(|m| m.msg_id == up_to).map(|m| m.hlc) else {
            // Сообщение вне окна или уже вычищено уборкой (§12) — не ошибка.
            return Ok(Vec::new());
        };

        let watermark = self.read_upto.get(&chat).copied();
        let ids: Vec<MsgId> = window
            .iter()
            // Квитанция о прочтении — про **чужие** сообщения: своим она
            // ничего не сообщает.
            .filter(|m| m.sender_ik == peer_ik)
            .filter(|m| m.hlc <= edge && watermark.is_none_or(|seen| m.hlc > seen))
            .map(|m| m.msg_id)
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // Транспорт выбирается не политикой §5.4, а наличием прямой сессии:
        // квитанция не начинает рукопожатие и не уходит почтой.
        let Some(via) = [Transport::Lan, Transport::Onion]
            .into_iter()
            .find(|t| self.sessions.for_peer(&peer_ik, *t).is_some())
        else {
            return Ok(Vec::new());
        };

        // Знак двигается вместе с отправкой, а не до неё: не ушло — значит
        // и отмечать нечего, иначе следующий вызов промолчит о сообщениях,
        // про которые собеседник так и не узнал.
        let effects = self.send_receipt(now_ms, peer_ik, via, Receipt::Read, &ids)?;
        if !effects.is_empty() {
            self.read_upto.insert(chat, edge);
            self.persist_read_upto(chat, edge)?;
        }
        Ok(effects)
    }

    /// Кладёт водяной знак прочтения на диск (§9.4).
    fn persist_read_upto(&mut self, chat: ChatId, edge: Hlc) -> Result<(), EngineError> {
        let mut value = [0u8; 12];
        value[..8].copy_from_slice(&edge.wall_ms.to_be_bytes());
        value[8..].copy_from_slice(&edge.logical.to_be_bytes());
        self.store.put_meta(&ratatosk_store::read_upto_key(&chat), &value)?;
        Ok(())
    }

    /// Читает водяной знак прочтения с диска.
    ///
    /// Испорченное значение трактуется как его отсутствие: цена ошибки —
    /// одна лишняя квитанция, а отказ открыть базу из-за двенадцати байт
    /// служебной метки был бы несоразмерен.
    fn load_read_upto(&self, chat: ChatId) -> Result<Option<Hlc>, EngineError> {
        let Some(raw) = self.store.meta(&ratatosk_store::read_upto_key(&chat))? else {
            return Ok(None);
        };
        let Ok(bytes): Result<[u8; 12], _> = raw.as_slice().try_into() else {
            return Ok(None);
        };
        let wall_ms = u64::from_be_bytes(bytes[..8].try_into().expect("восемь байт"));
        let logical = u32::from_be_bytes(bytes[8..].try_into().expect("четыре байта"));
        Ok(Some(Hlc::new(wall_ms, logical)))
    }

    /// Отправляет квитанцию собеседнику (§9.4).
    ///
    /// Не через очередь доставки, и это важно. Квитанция — сведение о чужом
    /// сообщении, а не своё сообщение: у неё нет ни истории, ни статуса,
    /// и повторять её другим транспортом бессмысленно. Не дошла — собеседник
    /// увидит «отправлено» вместо «доставлено», что честно.
    ///
    /// Квитанция на квитанцию не отправляется по построению: сюда приходят
    /// только из ветки текста.
    fn send_receipt(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        receipt: Receipt,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        // §9.4: по почте квитанции не ходят — каждая была бы отдельным
        // письмом, то есть удвоением трафика и метаданных у сервера.
        if !ratatosk_proto::receipts::may_send_receipt(via) || msg_ids.is_empty() {
            return Ok(Vec::new());
        }
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            // Сессии нет — рукопожатие ради квитанции не начинаем: это
            // превратило бы сведение о доставке в повод для трафика.
            return Ok(Vec::new());
        };

        let hlc = self.clock.now(now_ms)?;
        let envelope = Envelope::new(
            self.entropy.msg_id(),
            hlc,
            PayloadType::Receipt,
            receipt.payload(msg_ids),
        );
        let frame = self.seal_for(session_id, &envelope.encode()?)?;
        Ok(vec![Effect::Send { peer_ik, via, frame }])
    }

    /// Выставляет статус доставки и сообщает о нём UI (§9.4).
    ///
    /// Одна точка на все переходы, и это не удобство: статус обязан только
    /// расти, а правило «только растёт», размазанное по пяти местам, рано
    /// или поздно разойдётся. Хранилище возвращает статус, **который
    /// получился**, — его и показываем, а не тот, что просили.
    ///
    /// Неизвестный `msg_id` — не ошибка: квитанция может прийти на сообщение,
    /// уже вычищенное уборкой (§12), и ронять из-за этого сессию незачем.
    fn note_status(
        &mut self,
        msg_id: MsgId,
        target: DeliveryStatus,
    ) -> Result<Vec<Effect>, EngineError> {
        let current = self.store.status(&msg_id)?.and_then(DeliveryStatus::from_code);
        // Допустимость перехода решает §9.4, а не хранилище и не это место:
        // правило неочевидное (`Undeliverable` перекрывает только `Pending`),
        // и записанное дважды оно однажды разойдётся.
        let Some(status) = ratatosk_proto::receipts::advance(current, target) else {
            // Ничего не изменилось — события об этом быть не должно.
            return Ok(Vec::new());
        };
        self.store.set_status(&msg_id, status.code())?;
        Ok(vec![Effect::Notify(Event::StatusChanged { msg_id, status })])
    }

    /// Список контактов, чьи маяки транспорт должен искать в эфире (§5.1).
    fn watch_lan_peers(&self) -> Effect {
        Effect::WatchLanPeers(self.contacts.keys().copied().collect())
    }

    fn send_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();
        let envelope = Envelope::new(msg_id, hlc, PayloadType::Text, Value::Text(text.to_owned()));
        let bytes = envelope.encode()?;

        // Своё сообщение кладётся в историю сразу: доставка может занять
        // сутки почтового круга (§5.3), а в чате оно должно быть видно уже.
        self.store.put_message(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Своё сообщение начинает с «ждёт отправки» и растёт оттуда.
            // У принятого статуса нет вовсе — там нечему расти.
            status: Some(DeliveryStatus::Pending.code()),
        })?;

        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: bytes,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
        })
    }

    /// Ставит сообщение в очередь доставки и делает первую попытку.
    fn enqueue(&mut self, mut delivery: Delivery) -> Result<Vec<Effect>, EngineError> {
        let effects = self.advance(&mut delivery)?;
        // Запись хранится, пока попытка не закрыта. Закрывают её два исхода:
        // уход почтой (§9.4 — дальше «отправлено» статус не растёт) и
        // исчерпание транспортов. Всё остальное — ожидание.
        if !delivery.attempt.is_finished() {
            self.outbox.push(delivery);
        }
        Ok(effects)
    }

    /// Пробует следующий транспорт по §5.4.
    ///
    /// Строгая последовательность, а не гонка: [`Attempt`] выдаёт очередной
    /// транспорт только после того, как предыдущий объявлен неудавшимся,
    /// и поэтому одно сообщение физически не может уйти двумя каналами
    /// одновременно.
    fn advance(&mut self, delivery: &mut Delivery) -> Result<Vec<Effect>, EngineError> {
        let contact = self.contacts.get(&delivery.peer_ik).ok_or(EngineError::UnknownPeer)?;
        let availability = contact.availability;

        // Обнаружение ещё не отвечало — подождём его, прежде чем расходовать
        // транспорты. Иначе §5.4 получает на вход «в LAN не видно» там, где
        // правильный ответ — «пока не знаем».
        if let Some(effect) = self.park_for_discovery(delivery) {
            return Ok(vec![effect]);
        }

        let transport = match delivery.attempt.next(availability) {
            Some(Decision::Use(t)) => t,
            Some(Decision::Undeliverable) | None => {
                // Транспорты кончились. Сообщение не исчезает молча —
                // пользователь обязан увидеть, что оно не ушло (§14).
                delivery.attempt.succeed();
                return self.note_status(delivery.msg_id, DeliveryStatus::Undeliverable);
            }
        };

        let Some(session_id) = self.sessions.for_peer(&delivery.peer_ik, transport) else {
            // Сессии для этого семейства транспортов нет. §5.4 запрещает
            // продолжать LAN-сессию через onion, поэтому «нет сессии» здесь
            // означает именно новое рукопожатие, а не переиспользование.
            delivery.state = DeliveryState::AwaitingSession;
            return self.ensure_handshake(delivery.peer_ik, transport);
        };

        let frame = self.seal_for(session_id, &delivery.envelope)?;
        let mut effects = vec![Effect::Send { peer_ik: delivery.peer_ik, via: transport, frame }];

        if transport.is_direct() {
            // Срок ожидания квитанции (§9.4), а не страховка от молчания
            // транспорта. Успешная запись в сокет ничего не доказывает:
            // полуоткрытое соединение принимает байты молча. Не пришла
            // квитанция за отведённое время — попытка не удалась, и §5.4
            // ведёт дальше.
            let timer = self.allocate_timer();
            let after_ms = delivery.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            delivery.state = DeliveryState::InFlight { via: transport, timer };
            effects.push(Effect::SetTimer { after_ms, token: timer });
        } else {
            // §9.4: по почте статус дальше «отправлено» не растёт, ждать
            // нечего, и запись из очереди уходит.
            delivery.attempt.succeed();
            effects.extend(self.note_status(delivery.msg_id, DeliveryStatus::Sent)?);
        }
        Ok(effects)
    }

    /// Начинает рукопожатие, если оно ещё не в пути.
    fn ensure_handshake(
        &mut self,
        peer_ik: [u8; 32],
        transport: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        if self.pending.iter().any(|p| p.peer_ik == peer_ik) {
            // Второе рукопожатие только потратило бы ещё одну операцию
            // у получателя и породило вторую сессию.
            return Ok(Vec::new());
        }
        self.begin_handshake(peer_ik, transport)
    }

    fn allocate_timer(&mut self) -> u64 {
        let token = self.next_timer_token;
        self.next_timer_token += 1;
        token
    }

    fn begin_handshake(
        &mut self,
        peer_ik: [u8; 32],
        transport: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        // §8.2: в первом сообщении — только карточка и приветствие.
        let card = self.own_card().encode()?;
        let (message, state) = Initiator::start(&self.identity, &peer_ik, &card)?;
        let frame = self.handshake_frame(HANDSHAKE_STEP_FIRST, &message)?;

        // Попытка заводится на том же транспорте, который выбрала доставка:
        // рукопожатие и данные обязаны идти одним путём, иначе сессия
        // установится не в том семействе транспортов (§5.4).
        let mut attempt = Attempt::new();
        let availability = self.availability_of(&peer_ik)?;
        while let Some(Decision::Use(t)) = attempt.next(availability) {
            if t == transport {
                break;
            }
        }

        let mut effects = vec![Effect::Send { peer_ik, via: transport, frame: frame.clone() }];
        let mut timer = None;
        if transport.is_direct() {
            let token = self.allocate_timer();
            let after_ms = attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            effects.push(Effect::SetTimer { after_ms, token });
            timer = Some(token);
        }
        self.pending.push(OutgoingHandshake { state, frame, attempt, peer_ik, timer });
        Ok(effects)
    }

    /// Пересылает незавершённое рукопожатие следующим транспортом (§5.4).
    ///
    /// Второе возвращаемое значение — «транспорты для рукопожатия кончились».
    /// Оно нужно вызывающему: сессии не будет, а значит и сообщения, которые
    /// её ждут, никогда не уедут. Молча оставить их в очереди нельзя (§14).
    fn retry_handshake(
        &mut self,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<(Vec<Effect>, bool), EngineError> {
        let availability = match self.availability_of(&peer_ik) {
            Ok(a) => a,
            Err(_) => return Ok((Vec::new(), false)),
        };

        let mut effects = Vec::new();
        let mut exhausted = false;
        let mut pending = std::mem::take(&mut self.pending);
        for handshake in &mut pending {
            if handshake.peer_ik != peer_ik || handshake.attempt.tried().last() != Some(&via) {
                continue;
            }
            match handshake.attempt.next(availability) {
                Some(Decision::Use(next)) => {
                    effects.push(Effect::Send {
                        peer_ik,
                        via: next,
                        frame: handshake.frame.clone(),
                    });
                    // Новой попытке — новый срок. Без него молчание второго
                    // транспорта не приводит к третьему, и откат §5.4
                    // обрывается на середине.
                    handshake.timer = None;
                    if next.is_direct() {
                        let token = self.allocate_timer();
                        let after_ms =
                            handshake.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
                        effects.push(Effect::SetTimer { after_ms, token });
                        handshake.timer = Some(token);
                    }
                }
                Some(Decision::Undeliverable) | None => exhausted = true,
            }
        }
        // Исчерпанное рукопожатие выбрасывается. Оставшись, оно не только
        // текло бы памятью, но и блокировало `ensure_handshake`: тот считает
        // запись в `pending` признаком «рукопожатие уже в пути», и следующая
        // попытка связаться с этим контактом не началась бы никогда.
        if exhausted {
            pending.retain(|p| p.peer_ik != peer_ik || !p.attempt.is_finished());
        }
        self.pending = pending;
        Ok((effects, exhausted))
    }

    fn availability_of(&self, peer_ik: &[u8; 32]) -> Result<PeerAvailability, EngineError> {
        Ok(self.contacts.get(peer_ik).ok_or(EngineError::UnknownPeer)?.availability)
    }

    // --- кадры --------------------------------------------------------------

    fn handshake_frame(&mut self, step: u64, message: &[u8]) -> Result<Vec<u8>, EngineError> {
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        self.entropy.fill(&mut nonce);
        let header =
            Header::new(FrameType::Handshake, ratatosk_wire::HANDSHAKE_SESSION_ID, step, nonce);

        // Кадр рукопожатия не запечатывается нашим AEAD: его содержимое уже
        // зашифровал Noise. Дополняется он до всей запечатанной области —
        // места под наш тег здесь нет.
        let mut sealed = Vec::new();
        pad_to(message, HANDSHAKE_CLASS.sealed_len(), &mut sealed)?;
        Ok(ratatosk_wire::assemble(&header, &sealed)?)
    }

    fn seal_for(&mut self, session_id: u64, envelope: &[u8]) -> Result<Vec<u8>, EngineError> {
        let class = SizeClass::smallest_for(envelope.len()).ok_or(
            ratatosk_wire::WireError::PayloadTooLarge {
                got: envelope.len(),
                max: SizeClass::L.max_payload(),
            },
        )?;

        let bound = self.sessions.get_mut(session_id).ok_or(EngineError::UnknownPeer)?;
        let (counter, key) = bound.session.send.next();

        // Nonce выводится из счётчика, а не из случайности. Ключ сообщения
        // и так свежий на каждый кадр (§8.4), так что повтора nonce быть
        // не может; зато кадр становится воспроизводимым, а §16 этого и хочет.
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        nonce[..8].copy_from_slice(&counter.to_be_bytes());

        let header = Header::new(FrameType::Data, session_id, counter, nonce);
        let frame = aead::seal(&key, &header, class, envelope)?;

        // Запись до возврата кадра, а не после его отправки: см. пояснение
        // к `persist_session`. Между продвижением цепочки и записью не должно
        // быть ничего, что может не вернуться.
        self.persist_session(session_id)?;
        Ok(frame)
    }

    // --- приём --------------------------------------------------------------

    fn on_frame(
        &mut self,
        now_ms: u64,
        via: Transport,
        frame: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let view = ratatosk_wire::parse(frame)?;

        match self.sessions.route(view.header.session_id) {
            ratatosk_proto::Route::Handshake => {
                let message = unpad(view.sealed)?.to_vec();
                match view.header.counter {
                    HANDSHAKE_STEP_FIRST => self.on_handshake_first(now_ms, via, &message),
                    HANDSHAKE_STEP_RESPONSE => self.on_handshake_response(now_ms, via, &message),
                    _ => Ok(Vec::new()),
                }
            }
            ratatosk_proto::Route::Session(session_id) => {
                let counter = view.header.counter;
                self.on_data(now_ms, via, session_id, counter, frame)
            }
            ratatosk_proto::Route::Unknown => {
                // §7.3, шаг 4: отбросить и посчитать. Источник неизвестен —
                // кадр не расшифрован, — поэтому аномалия пишется на нули.
                self.sessions.note_anomaly([0u8; 32], |c| c.unknown_session += 1);
                Ok(Vec::new())
            }
        }
    }

    fn on_handshake_first(
        &mut self,
        now_ms: u64,
        via: Transport,
        message: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Отказ рукопожатия — не отказ ядра. Почтовый транспорт штатно
        // дублирует письма (§9.2), и повтор обязан быть отброшен так же тихо,
        // как мусорный кадр в §7.3.
        let outcome =
            match Responder::accept(&self.identity, message, &mut self.handshake_guard, now_ms) {
                Ok(outcome) => outcome,
                Err(ratatosk_crypto::CryptoError::HandshakeReplay) => {
                    self.sessions.note_anomaly([0u8; 32], |c| c.handshake_replay += 1);
                    return Ok(Vec::new());
                }
                Err(_) => {
                    self.sessions.note_anomaly([0u8; 32], |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
            };

        // Повтор: сессия уже есть, менять нечего — пересылаем прежний ответ.
        // Именно это спасает контакт, у которого потерялся первый ответ.
        let accepted = match outcome {
            HandshakeOutcome::Established(accepted) => accepted,
            HandshakeOutcome::Repeat { response, peer_ik } => {
                let frame = self.handshake_frame(HANDSHAKE_STEP_RESPONSE, &response)?;
                return Ok(vec![Effect::Send { peer_ik, via, frame }]);
            }
        };
        let Accepted { payload, response, session } = accepted;

        let peer_ik = session.peer_ik;
        let mut effects = Vec::new();

        // В первом сообщении приехала карточка отправителя (§8.2). Контакт
        // остаётся непроверенным: карточка пришла по сети, а не из QR (§4.2).
        if !self.contacts.contains_key(&peer_ik) {
            effects.extend(self.add_contact(now_ms, &payload, false)?);
        }

        let session_id = session.session_id;
        self.sessions.insert(session, SessionBinding::of(via));
        self.persist_session(session_id)?;

        let frame = self.handshake_frame(HANDSHAKE_STEP_RESPONSE, &response)?;
        effects.push(Effect::Send { peer_ik, via, frame });
        Ok(effects)
    }

    fn on_handshake_response(
        &mut self,
        now_ms: u64,
        via: Transport,
        message: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Кто прислал ответ, из кадра не видно, поэтому перебираются
        // незавершённые рукопожатия. Это НЕ trial decryption из §8.3:
        // множество задано нашими собственными отправками и мало, а не
        // всеми контактами и не выбирается атакующим.
        let mut established: Option<Session> = None;
        for candidate in self.pending.iter_mut() {
            if let Ok(session) = candidate.state.finish(message, now_ms) {
                established = Some(session);
                break;
            }
        }

        let Some(session) = established else {
            self.sessions.note_anomaly([0u8; 32], |c| c.handshake_replay += 1);
            return Ok(Vec::new());
        };

        let peer_ik = session.peer_ik;
        let session_id = session.session_id;
        self.pending.retain(|p| p.peer_ik != peer_ik);
        self.sessions.insert(session, SessionBinding::of(via));
        // До досылки очереди: `flush_outbox` двигает отправляющую цепочку,
        // и запись должна лечь раньше первого кадра.
        self.persist_session(session_id)?;
        self.flush_outbox(peer_ik)
    }

    /// Досылает всё, что ждало сессию с этим контактом.
    fn flush_outbox(&mut self, peer_ik: [u8; 32]) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik
                || !matches!(delivery.state, DeliveryState::AwaitingSession)
            {
                continue;
            }
            // Попытка та же самая: транспорт уже выбран, не хватало сессии.
            // Новый вызов `attempt.next` здесь съел бы транспорт зря.
            effects.extend(self.resend_current(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Отправляет сообщение тем транспортом, который уже выбран попыткой.
    fn resend_current(&mut self, delivery: &mut Delivery) -> Result<Vec<Effect>, EngineError> {
        let Some(&transport) = delivery.attempt.tried().last() else {
            return self.advance(delivery);
        };
        let Some(session_id) = self.sessions.for_peer(&delivery.peer_ik, transport) else {
            return Ok(Vec::new());
        };

        let frame = self.seal_for(session_id, &delivery.envelope)?;
        let mut effects = vec![Effect::Send { peer_ik: delivery.peer_ik, via: transport, frame }];

        if transport.is_direct() {
            let timer = self.allocate_timer();
            let after_ms = delivery.attempt.timeout_ms().unwrap_or(ONION_FALLBACK_TIMEOUT_MS);
            delivery.state = DeliveryState::InFlight { via: transport, timer };
            effects.push(Effect::SetTimer { after_ms, token: timer });
        } else {
            delivery.attempt.succeed();
            effects.extend(self.note_status(delivery.msg_id, DeliveryStatus::Sent)?);
        }
        Ok(effects)
    }

    /// Откладывает попытку до ответа обнаружения — или не откладывает.
    ///
    /// Возвращает `Some(таймер)`, если ждать есть чего. Условий три, и все
    /// обязательны: LAN включён (иначе ждать нечего), собеседника в эфире
    /// ещё не слышали, и срок ему в этом сеансе ещё не выдавался. Последнее
    /// важнее, чем кажется: без него каждое сообщение собеседнику из другой
    /// сети начиналось бы с трёхсекундной паузы.
    fn park_for_discovery(&mut self, delivery: &mut Delivery) -> Option<Effect> {
        if !self.lan_enabled || !delivery.attempt.tried().is_empty() {
            return None;
        }
        let contact = self.contacts.get(&delivery.peer_ik)?;
        if contact.availability.seen_on_lan {
            return None;
        }
        if !self.awaited_discovery.insert(delivery.peer_ik) {
            return None;
        }

        let timer = self.allocate_timer();
        delivery.state = DeliveryState::AwaitingDiscovery { timer };
        Some(Effect::SetTimer { after_ms: LAN_DISCOVERY_GRACE_MS, token: timer })
    }

    /// Обнаружение ответило (или кончился срок) — двигаем отложенное.
    ///
    /// Вызывается и по маяку, и по таймеру: разница только в том, окажется ли
    /// LAN доступен на следующем шаге. Решает это [`Attempt`], а не эта
    /// функция, — здесь только снимается пауза.
    fn resume_discovery(&mut self, peer_ik: [u8; 32]) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik
                || !matches!(delivery.state, DeliveryState::AwaitingDiscovery { .. })
            {
                continue;
            }
            // Состояние снимается до `advance`: иначе `park_for_discovery`
            // увидел бы нетронутую попытку и отложил её второй раз.
            delivery.state = DeliveryState::AwaitingSession;
            effects.extend(self.advance(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Прямой канал отказал — переходим к следующему транспорту (§5.4).
    fn on_delivery_failed(
        &mut self,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        // Собеседник не ответил по локальной сети — значит его там больше
        // нет. Оставить признак видимости значит выбирать LAN и для следующего
        // сообщения, платя таймаутом за уже известное. Вернёт его mDNS,
        // когда устройство снова объявится (§5.1).
        if via == Transport::Lan {
            if let Some(contact) = self.contacts.get_mut(&peer_ik) {
                contact.availability.seen_on_lan = false;
            }
        }

        // Рукопожатие переносится первым: без сессии данные всё равно
        // упрутся в ожидание, и порядок эффектов станет непонятным.
        let (mut effects, handshake_exhausted) = self.retry_handshake(peer_ik, via)?;
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik {
                continue;
            }
            let failed_here = match delivery.state {
                DeliveryState::InFlight { via: v, .. } => v == via,
                // Сообщение ждало сессии, а рукопожатию идти больше некуда.
                // Ждать нечего: попытка обязана дойти до конца и объявить
                // исход, иначе сообщение зависает в очереди навсегда — ровно
                // то молчание, которое §14 запрещает.
                DeliveryState::AwaitingSession => handshake_exhausted,
                // Это сообщение ещё не выходило в сеть и потому здесь ничего
                // не теряло: у него свой срок, и снимет паузу он, а не чужой
                // отказ. Тронуть его тут значило бы сжечь LAN за компанию —
                // как раз тогда, когда собеседник вот-вот найдётся.
                DeliveryState::AwaitingDiscovery { .. } => false,
            };
            if !failed_here {
                continue;
            }
            effects.extend(self.advance(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }

    /// Сработал таймер попытки: подтверждения нет — попытка не удалась.
    ///
    /// **Раньше здесь выставлялось «отправлено», и это была ошибка.** Прямой
    /// канал подтверждает доставку квитанцией за миллисекунды (§9.4); если
    /// за отведённое время её нет, значит кадр не дошёл. Объявлять при этом
    /// успех — не просто неточность в индикаторе: попытка закрывалась, и
    /// откат на следующий транспорт по §5.4 **не запускался вовсе**. Молча
    /// исчезнувший собеседник получался неотличим от ответившего, и запись
    /// в сокет это не ловит — ядро принимает её в буфер и для мёртвого узла.
    ///
    /// Поэтому таймер идёт тем же путём, что и явный отказ: это одно и то же
    /// событие для §5.4 — «здесь не вышло, пробуем дальше».
    ///
    /// Запоздавшая квитанция ничего не ломает: `receipts::advance` разрешает
    /// перейти от объявленного провала к подтверждённой доставке, а лишнюю
    /// копию у получателя съест дедупликация (§9.2).
    fn on_timer(&mut self, token: u64) -> Result<Vec<Effect>, EngineError> {
        // Срок обнаружения — не отказ транспорта, а конец паузы: §5.4 ещё
        // не начинался. Поэтому он разбирается отдельно и раньше.
        let awaiting_discovery = self.outbox.iter().find_map(|d| match d.state {
            DeliveryState::AwaitingDiscovery { timer } if timer == token => Some(d.peer_ik),
            _ => None,
        });
        if let Some(peer_ik) = awaiting_discovery {
            return self.resume_discovery(peer_ik);
        }

        // Один и тот же счётчик меток обслуживает и рукопожатия, и доставку,
        // поэтому владельца ищем в обоих местах.
        let waiting = self
            .pending
            .iter()
            .find(|p| p.timer == Some(token))
            .and_then(|p| p.attempt.tried().last().map(|via| (p.peer_ik, *via)))
            .or_else(|| {
                self.outbox.iter().find_map(|d| match d.state {
                    DeliveryState::InFlight { via, timer } if timer == token => {
                        Some((d.peer_ik, via))
                    }
                    _ => None,
                })
            });

        // Метка без владельца — обычное дело: доставка могла завершиться
        // квитанцией раньше срока, и таймер просто опоздал.
        let Some((peer_ik, via)) = waiting else {
            return Ok(Vec::new());
        };
        self.on_delivery_failed(peer_ik, via)
    }

    fn on_data(
        &mut self,
        now_ms: u64,
        via: Transport,
        session_id: u64,
        counter: u64,
        frame: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let bound = self.sessions.get_mut(session_id).ok_or(EngineError::UnknownPeer)?;
        let peer_ik = bound.session.peer_ik;

        // §7.3, шаг 3: ключ выводится ровно для позиции `counter`, и только
        // после успешной проверки тега достраиваются пропущенные.
        let key = match bound.session.recv.peek(counter) {
            Ok(key) => key,
            Err(_) => {
                self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
                return Ok(Vec::new());
            }
        };

        let opened = aead::open(&key, frame);
        let (_, plaintext) = match opened {
            Ok(v) => v,
            Err(_) => {
                self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
                return Ok(Vec::new());
            }
        };

        let bound = self.sessions.get_mut(session_id).expect("сессия только что была");
        bound.session.recv.commit(counter, now_ms)?;
        self.persist_session(session_id)?;

        let envelope = Envelope::decode(&plaintext)?.into_parts().1;

        // §9.2: одно сообщение может законно прийти дважды разными
        // транспортами. Это нормальный режим, а не ошибка.
        if !self.dedup.check(envelope.msg_id, now_ms).is_fresh() {
            return Ok(Vec::new());
        }
        if !self.store.note_seen(&envelope.msg_id, now_ms)? {
            return Ok(Vec::new());
        }

        // §9.1: метка из далёкого будущего отбрасывается вместе с сообщением.
        let Ok(_) = self.clock.observe(now_ms, envelope.hlc) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };

        self.deliver(now_ms, via, peer_ik, envelope)
    }

    fn deliver(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        match envelope.payload_type {
            PayloadType::Text => {
                let Value::Text(text) = &envelope.payload else {
                    return Err(ratatosk_codec::CodecError::TypeMismatch.into());
                };
                let chat = Self::chat_id_for(&peer_ik);
                self.store.put_message(&StoredMessage {
                    msg_id: envelope.msg_id,
                    chat_id: chat,
                    sender_ik: peer_ik,
                    hlc: envelope.hlc,
                    body: text.as_bytes().to_vec(),
                    received_ms: now_ms,
                    // У принятого сообщения статуса нет: статус — это судьба
                    // отправки, а оно уже здесь.
                    status: None,
                })?;

                let mut effects =
                    vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })];
                // §9.4: квитанция о доставке — сразу и только прямым каналом.
                // «Доставлено» означает ровно то, что кадр принят и расшифрован,
                // и узнать это может только получатель.
                effects.extend(self.send_receipt(
                    now_ms,
                    peer_ik,
                    via,
                    Receipt::Delivered,
                    &[envelope.msg_id],
                )?);
                Ok(effects)
            }
            // Неизвестный тип не повод терять сообщение целиком, но и
            // показать его нечем: молча пропускаем (§9.1).
            PayloadType::Unknown(_) => Ok(Vec::new()),
            PayloadType::FileOffer | PayloadType::FileChunk | PayloadType::Preview => {
                todo!("этап 4: файлы (§10)")
            }
            PayloadType::Receipt => {
                let (receipt, msg_ids) = Receipt::from_payload(&envelope.payload)?;
                let candidate = match receipt {
                    Receipt::Delivered => DeliveryStatus::Delivered,
                    Receipt::Read => DeliveryStatus::Read,
                };
                // §9.4: квитанция, пришедшая не прямым каналом, не применяется.
                // Своя проверка, а не доверие отправителю: транспорт знаем мы,
                // и подделать его он не может.
                if !ratatosk_proto::receipts::may_send_receipt(via) {
                    self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }

                let mut effects = Vec::new();
                for msg_id in &msg_ids {
                    effects.extend(self.note_status(*msg_id, candidate)?);
                }

                // Доставка подтверждена — запись из очереди уходит, и её
                // таймер остаётся без владельца. Оставить её значит дождаться
                // срока и объявить провал у сообщения, которое уже прочитано.
                self.outbox.retain(|d| !msg_ids.contains(&d.msg_id));
                Ok(effects)
            }
            PayloadType::GroupMembership | PayloadType::SenderKey => {
                todo!("этап 5: группы (§11)")
            }
            PayloadType::CardUpdate => todo!("этап 2: обновление карточки (§4.3)"),
        }
    }
}

// Поля, к которым ядро обратится на следующих этапах.
impl<S: Store> Engine<S> {
    /// Политика перерукопожатия (§8.5) — понадобится на этапе 1.
    #[must_use]
    pub fn rekey_policy(&self) -> &RekeyPolicy {
        &self.rekey
    }

    /// Сборщик фрагментов (§9.3) — понадобится на этапе 4.
    #[must_use]
    pub fn reassembler(&self) -> &Reassembler {
        &self.reassembler
    }

    /// Последняя выданная метка часов — для отладки порядка (§9.1).
    #[must_use]
    pub fn clock_last(&self) -> Hlc {
        self.clock.last()
    }

    /// Видели ли идентификатор в окне дедупликации (§9.2).
    #[must_use]
    pub fn has_seen(&self, msg_id: &MsgId) -> bool {
        self.dedup.contains(msg_id)
    }

    /// Число установленных сессий.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}
