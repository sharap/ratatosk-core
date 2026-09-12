//! Рукопожатие Noise IK и установление сессии (§8.2, §8.3).
//!
//! Паттерн `Noise_IK_25519_ChaChaPoly_BLAKE2s`. BLAKE2s взят как штатный для
//! Noise; BLAKE3 используется вне Noise.
//!
//! `IK` означает «инициатор знает статический ключ получателя», и у нас он
//! всегда известен — он в контакт-карточке (§4.1). Отсюда три следствия,
//! ради которых паттерн и выбран:
//!
//! * пул одноразовых предключей не нужен — вся механика X3DH с бандлами, их
//!   пополнением, исчерпанием и гонками исчезает целиком;
//! * транскрипт входит в вывод ключей по построению Noise, поэтому понижение
//!   версии и подмена идентичности невозможны без дополнительных мер;
//! * первое сообщение асинхронно: получатель может быть офлайн.
//!
//! **Честное ограничение (§8.2).** В `IK` полезная нагрузка первого сообщения
//! защищена только статическим ключом получателя: компрометация его `IK`
//! в будущем раскрывает записанное первое сообщение. Поэтому в первом
//! сообщении не отправляется ничего, кроме приветствия и своей карточки;
//! предел [`MAX_FIRST_PAYLOAD`] делает это ограничением, а не пожеланием.
//!
//! **Рукопожатие двухшаговое, и это не деталь.** Паттерн `IK` — это
//! `-> e, es, s, ss` и `<- e, ee, se`. Асинхронно только **первое**
//! сообщение: получатель может быть офлайн, прочитать его и ответить позже.
//! Сессия появляется у обеих сторон лишь после второго сообщения, и §8.2
//! говорит об этом прямо: «содержательная переписка начинается после
//! ответа». Поэтому [`Initiator::start`] возвращает не сессию,
//! а [`PendingHandshake`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use snow::Builder;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::identity::Identity;
use crate::kdf::{self, Key32};
use crate::labels;
use crate::ratchet::{RecvChain, SendChain, MAX_SKIPPED_PER_SESSION};

/// Имя паттерна Noise (§8.2).
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// TTL записи в anti-replay кэше рукопожатий — 30 суток (§8.3).
pub const HANDSHAKE_REPLAY_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Ёмкость anti-replay кэша (§8.3).
pub const HANDSHAKE_REPLAY_CAPACITY: usize = 100_000;

/// Предел полезной нагрузки первого сообщения (§8.2).
///
/// Первое сообщение защищено слабее последующих, поэтому в нём едут только
/// приветствие и контакт-карточка — около 200 байт (§4.1). Килобайт даёт
/// запас на будущие поля и при этом не оставляет места для переписки:
/// ограничение §8.2 должно упираться в проверку, а не в добрую волю.
pub const MAX_FIRST_PAYLOAD: usize = 1024;

/// Длина эфемерного открытого ключа X25519 в первом сообщении.
const EPHEMERAL_LEN: usize = 32;

/// Рабочий буфер под сообщение Noise.
///
/// Первое сообщение — это `e` (32) + зашифрованный `s` (32 + 16) + нагрузка
/// с тегом. С учётом [`MAX_FIRST_PAYLOAD`] всё укладывается заведомо.
const NOISE_BUFFER: usize = 4096;

/// Роль в рукопожатии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Инициатор: шлёт `-> e, es, s, ss`.
    Initiator,
    /// Получатель.
    Responder,
}

/// Установленная сессия (§8.3).
///
/// ```text
/// транскрипт h — как определено Noise
/// session_id = BLAKE3_derive_key("ratatosk v0 sid", h)[0..8]
/// root_key   = BLAKE3_derive_key("ratatosk v0 root", h ‖ noise_output)
/// ck_send / ck_recv = BLAKE3_derive_key("ratatosk v0 chain-a" / "chain-b", root_key)
/// ```
///
/// Инициатор берёт `chain-a` как отправляющую, получатель — наоборот.
#[derive(Debug)]
pub struct Session {
    /// Идентификатор сессии в заголовке кадра.
    pub session_id: u64,
    /// `IK` собеседника — по нему сессия связывается с контактом.
    pub peer_ik: [u8; 32],
    /// Отправляющая цепочка.
    pub send: SendChain,
    /// Принимающая цепочка.
    pub recv: RecvChain,
    /// Момент установления, мс. Нужен для правила перерукопожатия (§8.5).
    pub established_ms: u64,
}

impl Session {
    /// Собирает сессию из транскрипта Noise и его выходного ключа.
    ///
    /// Вынесено отдельной функцией, чтобы деривация была одна на обе роли:
    /// расхождение здесь дало бы несовпадающие цепочки, и его не поймал бы
    /// ни один односторонний тест.
    #[must_use]
    pub fn derive(
        role: Role,
        peer_ik: [u8; 32],
        transcript: &[u8],
        noise_output: &[u8],
        now_ms: u64,
    ) -> Session {
        let session_id = kdf::derive_u64(labels::SESSION_ID, transcript);
        let root_key = kdf::derive_concat(labels::ROOT, &[transcript, noise_output]);

        let chain_a: Key32 = kdf::derive(labels::CHAIN_A, &root_key[..]);
        let chain_b: Key32 = kdf::derive(labels::CHAIN_B, &root_key[..]);

        let (send, recv) = match role {
            Role::Initiator => (chain_a, chain_b),
            Role::Responder => (chain_b, chain_a),
        };

        Session {
            session_id,
            peer_ik,
            send: SendChain::new(send),
            recv: RecvChain::new(recv),
            established_ms: now_ms,
        }
    }

    /// Снимок состояния для записи на диск (§12).
    ///
    /// Формат свой, а не CBOR: это внутреннее состояние одного устройства,
    /// оно никогда не уходит в сеть, и канонизация (§6) ему не нужна. Зато
    /// нужна ровно одна вещь — чтобы разбор не принял мусор молча.
    ///
    /// ```text
    /// version(1) ‖ session_id(8) ‖ peer_ik(32) ‖ established_ms(8)
    ///   ‖ send_chain(32) ‖ send_counter(8)
    ///   ‖ recv_chain(32) ‖ recv_next(8) ‖ skipped_count(4)
    ///   ‖ { counter(8) ‖ key(32) ‖ created_ms(8) } * skipped_count
    /// ```
    ///
    /// Результат содержит ключевой материал в открытом виде и обязан быть
    /// запечатан перед записью — этим занимается `ratatosk-store`.
    #[must_use]
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let (send_key, send_counter) = self.send.snapshot();
        let (recv_key, recv_next, skipped) = self.recv.snapshot();

        let mut out = Zeroizing::new(Vec::with_capacity(SNAPSHOT_HEAD + skipped.len() * 48));
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.peer_ik);
        out.extend_from_slice(&self.established_ms.to_be_bytes());
        out.extend_from_slice(&send_key[..]);
        out.extend_from_slice(&send_counter.to_be_bytes());
        out.extend_from_slice(&recv_key[..]);
        out.extend_from_slice(&recv_next.to_be_bytes());
        // Число пропущенных ограничено §8.4 (2000 на сессию), так что
        // в u32 оно помещается с огромным запасом.
        out.extend_from_slice(&(skipped.len() as u32).to_be_bytes());
        for (counter, (key, created_ms)) in skipped {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&key[..]);
            out.extend_from_slice(&created_ms.to_be_bytes());
        }
        out
    }

    /// Восстанавливает сессию из снимка.
    ///
    /// Отказ означает порчу файла или снимок от несовместимой версии. Тихо
    /// подставить пустую сессию нельзя: отправляющая цепочка начала бы
    /// с нуля, и **тот же ключ с тем же nonce ушёл бы в сеть второй раз**.
    pub fn restore(bytes: &[u8]) -> Result<Session> {
        let mut cursor = Cursor::new(bytes);
        if cursor.byte()? != SNAPSHOT_VERSION {
            return Err(CryptoError::BadKeyMaterial);
        }
        let session_id = u64::from_be_bytes(cursor.take()?);
        let peer_ik: [u8; 32] = cursor.take()?;
        let established_ms = u64::from_be_bytes(cursor.take()?);

        let send_key = Zeroizing::new(cursor.take::<32>()?);
        let send_counter = u64::from_be_bytes(cursor.take()?);
        let recv_key = Zeroizing::new(cursor.take::<32>()?);
        let recv_next = u64::from_be_bytes(cursor.take()?);

        let count = u32::from_be_bytes(cursor.take()?) as usize;
        // Заявленное число проверяется пределом §8.4 до всякого выделения
        // памяти: иначе испорченный файл просит гигабайт и получает его.
        if count > MAX_SKIPPED_PER_SESSION {
            return Err(CryptoError::BadKeyMaterial);
        }
        let mut skipped = BTreeMap::new();
        for _ in 0..count {
            let counter = u64::from_be_bytes(cursor.take()?);
            let key = Zeroizing::new(cursor.take::<32>()?);
            let created_ms = u64::from_be_bytes(cursor.take()?);
            skipped.insert(counter, (key, created_ms));
        }
        if !cursor.is_empty() {
            // Хвост означает, что разбор разошёлся с записью: молча
            // проглотить его — значит однажды восстановить не ту сессию.
            return Err(CryptoError::BadKeyMaterial);
        }

        Ok(Session {
            session_id,
            peer_ik,
            send: SendChain::restore(send_key, send_counter),
            recv: RecvChain::restore(recv_key, recv_next, skipped),
            established_ms,
        })
    }
}

/// Версия формата снимка. Меняется при любой правке раскладки.
const SNAPSHOT_VERSION: u8 = 1;
/// Длина неизменной части снимка.
const SNAPSHOT_HEAD: usize = 1 + 8 + 32 + 8 + 32 + 8 + 32 + 8 + 4;

/// Чтение снимка без паник на обрезанном входе.
///
/// `pub(crate)`, потому что снимков в крейте два: сессия здесь и приёмная
/// sender-цепочка в [`crate::ratchet`]. Правило «хвост означает расхождение
/// разбора с записью» обязано быть у них одно, а два одинаковых курсора
/// однажды разъехались бы на этом правиле.
pub(crate) struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    /// Курсор по началу среза.
    pub(crate) const fn new(bytes: &'a [u8]) -> Cursor<'a> {
        Cursor { rest: bytes }
    }

    /// Не осталось ли непрочитанного.
    ///
    /// Хвост в снимке означает, что разбор разошёлся с записью, и оба
    /// вызывающих обязаны этим кончать.
    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Один байт — версия формата.
    pub(crate) fn byte(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }

    /// Ровно `N` байт. Обрезанный вход даёт отказ, а не панику.
    pub(crate) fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.rest.len() < N {
            return Err(CryptoError::BadKeyMaterial);
        }
        let (head, tail) = self.rest.split_at(N);
        self.rest = tail;
        Ok(head.try_into().expect("срез длины N"))
    }
}

/// Условия полного повторного рукопожатия (§8.5).
///
/// Полноценный Double Ratchet с DH-шагом в v1 не реализуется: он плохо
/// сочетается с почтовым транспортом и заметно усложняет код. Вместо него —
/// полное перерукопожатие по любому из условий ниже.
///
/// Следствие, которое обязано быть в §14 и не должно рекламироваться иначе:
/// восстановление после компрометации занимает **до 7 суток**, а не одно
/// сообщение.
#[derive(Debug, Clone, Copy)]
pub struct RekeyPolicy {
    /// Максимальный возраст сессии — 7 суток.
    pub max_age_ms: u64,
    /// Максимум отправленных сообщений — 1000.
    pub max_messages: u64,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        RekeyPolicy { max_age_ms: 7 * 24 * 60 * 60 * 1000, max_messages: 1_000 }
    }
}

impl RekeyPolicy {
    /// Пора ли переустанавливать сессию.
    ///
    /// `both_online_direct` — третье условие §8.5: обе стороны одновременно
    /// доступны прямым каналом. Оно самое дешёвое и потому проверяется первым.
    #[must_use]
    pub fn should_rekey(&self, session: &Session, now_ms: u64, both_online_direct: bool) -> bool {
        both_online_direct
            || now_ms.saturating_sub(session.established_ms) >= self.max_age_ms
            || session.send.counter() >= self.max_messages
    }
}

/// Сколько ответов на рукопожатия хранится для повторной отправки.
///
/// Отдельный, куда меньший предел, чем у множества отпечатков: отпечаток —
/// это 32 байта, а ответ — сотня с лишним, и держать 100 000 ответов значило
/// бы отдать под них десяток мегабайт на телефоне. Повторы приходят в течение
/// минут или часов, а не недель, поэтому небольшого окна достаточно.
pub const HANDSHAKE_RESPONSE_CACHE: usize = 256;

/// Что делать с предъявленным рукопожатием (§8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// Видим впервые — выполнять рукопожатие.
    Fresh,
    /// Повтор, ответ на который сохранён: переслать его и ничего не менять.
    ///
    /// **Это исправление дыры, которой §8.3 не замечает.** Если ответ
    /// `<- e, ee, se` потерялся, инициатор перешлёт первое сообщение —
    /// и получатель, отвергнув его как повтор, оставил бы контакт без сессии
    /// навсегда. Повтор рукопожатия обязан быть идемпотентным, а не
    /// отвергаемым: тот же вход даёт тот же выход, новой сессии не возникает.
    Repeat {
        /// Сохранённый ответ.
        response: Vec<u8>,
        /// Кому его слать.
        ///
        /// Хранится рядом с ответом потому, что повтор **не расшифровывается**:
        /// заново прогонять Noise нельзя — это дало бы вторую сессию на тот же
        /// эфемерный ключ. А без разбора сообщения получатель не узнал бы,
        /// кому адресован ответ.
        peer_ik: [u8; 32],
    },
    /// Повтор, ответ на который уже вытеснен из кэша.
    ///
    /// Здесь остаётся только отбросить: заново провести рукопожатие нельзя —
    /// это создало бы вторую сессию на тот же эфемерный ключ.
    Stale,
}

/// Anti-replay кэш рукопожатий (§8.3).
///
/// Хранит `BLAKE3(e ‖ ciphertext)` обработанных рукопожатий: TTL 30 суток,
/// ёмкость 100 000, вытеснение LRU. Плюс небольшой кэш самих ответов —
/// см. [`Admission::Repeat`].
#[derive(Debug)]
pub struct HandshakeReplayGuard {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<([u8; 32], u64)>,
    responses: HashMap<[u8; 32], (Vec<u8>, [u8; 32])>,
    response_order: VecDeque<[u8; 32]>,
    ttl_ms: u64,
    capacity: usize,
}

impl Default for HandshakeReplayGuard {
    fn default() -> Self {
        HandshakeReplayGuard::new(HANDSHAKE_REPLAY_TTL_MS, HANDSHAKE_REPLAY_CAPACITY)
    }
}

impl HandshakeReplayGuard {
    /// Кэш с заданными TTL и ёмкостью.
    #[must_use]
    pub fn new(ttl_ms: u64, capacity: usize) -> HandshakeReplayGuard {
        HandshakeReplayGuard {
            seen: HashSet::new(),
            order: VecDeque::new(),
            responses: HashMap::new(),
            response_order: VecDeque::new(),
            ttl_ms,
            capacity: capacity.max(1),
        }
    }

    /// Отпечаток рукопожатия: `BLAKE3(e ‖ ciphertext)` (§8.3).
    ///
    /// `e` берётся строго как массив из 32 байт, а не как срез. Спецификация
    /// пишет склейку без разделителя, и на срезах она была бы неоднозначной:
    /// `("ab", "c")` и `("a", "bc")` дали бы один отпечаток. Фиксированная
    /// длина эфемерного ключа X25519 снимает вопрос — но снимает его тип,
    /// а не договорённость.
    #[must_use]
    pub fn digest(ephemeral: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ephemeral);
        hasher.update(ciphertext);
        *hasher.finalize().as_bytes()
    }

    /// Решает, что делать с предъявленным рукопожатием.
    ///
    /// Прежняя версия возвращала ошибку на любой повтор. Это выглядело
    /// строго и было неверно: повтор — штатное следствие потери ответа
    /// и дублирования писем (§9.2), а не атака. Атакующий повтором ничего
    /// не добивается: он получит те же байты, которые уже летели по сети.
    pub fn admit(&mut self, digest: [u8; 32], now_ms: u64) -> Admission {
        self.purge(now_ms);
        if self.seen.insert(digest) {
            self.order.push_back((digest, now_ms));
            while self.order.len() > self.capacity {
                if let Some((old, _)) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
            return Admission::Fresh;
        }
        match self.responses.get(&digest) {
            Some((response, peer_ik)) => {
                Admission::Repeat { response: response.clone(), peer_ik: *peer_ik }
            }
            None => Admission::Stale,
        }
    }

    /// Отпечаток целого сообщения рукопожатия.
    ///
    /// Та же величина, что считает [`Responder::accept`] внутри, — и именно
    /// поэтому она вынесена сюда, а не повторена на месте. Считать её надо
    /// снаружи ровно затем, чтобы **записать на диск**: кэш §8.3 обязан
    /// пережить перезапуск, а положить в него запись может только тот,
    /// у кого есть хранилище.
    ///
    /// `None` — сообщение короче эфемерного ключа, то есть не рукопожатие.
    #[must_use]
    pub fn digest_of(message: &[u8]) -> Option<[u8; 32]> {
        if message.len() < EPHEMERAL_LEN {
            return None;
        }
        let ephemeral: [u8; EPHEMERAL_LEN] =
            message[..EPHEMERAL_LEN].try_into().expect("длина проверена выше");
        Some(HandshakeReplayGuard::digest(&ephemeral, &message[EPHEMERAL_LEN..]))
    }

    /// Возвращает в кэш отпечаток, прочитанный с диска.
    ///
    /// Не `admit`: тот **решает**, что делать с предъявленным рукопожатием,
    /// и вернул бы `Fresh` на каждую восстановленную запись — то есть
    /// объявил бы всё виденное невиданным ровно в тот момент, ради которого
    /// кэш и восстанавливают.
    ///
    /// Ответа при этом не восстанавливается: он живёт в памяти и стоит
    /// сотню с лишним байт на запись. Следствие названо прямо — повтор,
    /// заставший перезапуск, будет отброшен (`Admission::Stale`), а не
    /// пересказан. Это верно по существу: раз отпечаток виден, сессия уже
    /// заведена, и второй её заводить нельзя.
    /// Записи обязаны приходить **от старых к новым**: очередь `order`
    /// упорядочена по времени, и [`HandshakeReplayGuard::purge`] снимает
    /// просроченное с её начала. Придя вразнобой, записи остановили бы
    /// уборку на первой же «ещё свежей».
    pub fn remember_seen(&mut self, digest: [u8; 32], when_ms: u64) {
        if self.seen.insert(digest) {
            self.order.push_back((digest, when_ms));
            while self.order.len() > self.capacity {
                if let Some((old, _)) = self.order.pop_front() {
                    self.seen.remove(&old);
                }
            }
        }
    }

    /// Сохраняет ответ вместе с адресатом, чтобы переслать его при повторе.
    pub fn remember_response(&mut self, digest: [u8; 32], response: &[u8], peer_ik: [u8; 32]) {
        if self.responses.insert(digest, (response.to_vec(), peer_ik)).is_none() {
            self.response_order.push_back(digest);
        }
        while self.response_order.len() > HANDSHAKE_RESPONSE_CACHE {
            if let Some(old) = self.response_order.pop_front() {
                self.responses.remove(&old);
            }
        }
    }

    /// Выбрасывает записи старше TTL.
    pub fn purge(&mut self, now_ms: u64) {
        while let Some(&(digest, at)) = self.order.front() {
            if at.saturating_add(self.ttl_ms) > now_ms {
                break;
            }
            self.order.pop_front();
            self.seen.remove(&digest);
            if self.responses.remove(&digest).is_some() {
                self.response_order.retain(|d| d != &digest);
            }
        }
    }

    /// Сколько записей в кэше.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Пуст ли кэш.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Секретный материал, выданный Noise после Split (§8.3).
///
/// Порядок двух ключей приводится к каноническому — по возрастанию байтов.
/// Причина не в эстетике: из сигнатуры `dangerously_get_raw_split` не следует,
/// меняет ли библиотека их местами в зависимости от роли. Если меняет,
/// стороны вывели бы разные `root_key` и молча перестали слышать друг друга;
/// если не меняет, сортировка ничего не портит. Это защита от свойства,
/// которое мы не можем проверить типом, — а сходимость ролей проверяется
/// тестом `both_roles_agree_on_the_session`.
fn canonical_noise_output(a: [u8; 32], b: [u8; 32]) -> Zeroizing<Vec<u8>> {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(&first);
    out.extend_from_slice(&second);
    out
}

fn noise_params() -> Result<snow::params::NoiseParams> {
    NOISE_PATTERN.parse().map_err(|_| CryptoError::Handshake)
}

/// Начатое, но не завершённое рукопожатие инициатора.
///
/// Живёт между отправкой первого сообщения и приходом ответа — при почтовом
/// транспорте это могут быть сутки. Поэтому состояние обязано переживать
/// ожидание, а не жить внутри одного вызова.
pub struct PendingHandshake {
    state: snow::HandshakeState,
    peer_ik: [u8; 32],
}

impl core::fmt::Debug for PendingHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingHandshake").field("peer_ik", &hex_prefix(&self.peer_ik)).finish()
    }
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

impl PendingHandshake {
    /// `IK` собеседника, которому адресовано рукопожатие.
    #[must_use]
    pub const fn peer_ik(&self) -> &[u8; 32] {
        &self.peer_ik
    }

    /// Принимает ответ `<- e, ee, se` и завершает установление сессии (§8.3).
    ///
    /// Берёт `&mut self`, а не `self`, сознательно. Получатель ответа не знает
    /// заранее, какому из своих незавершённых рукопожатий тот принадлежит,
    /// и вынужден пробовать их по очереди. Если бы неудачная попытка
    /// съедала состояние, первая же проверка уничтожала бы живое рукопожатие
    /// с другим контактом.
    pub fn finish(&mut self, response: &[u8], now_ms: u64) -> Result<Session> {
        let mut payload = Zeroizing::new(vec![0u8; NOISE_BUFFER]);
        self.state.read_message(response, &mut payload).map_err(|_| CryptoError::Handshake)?;

        if !self.state.is_handshake_finished() {
            return Err(CryptoError::Handshake);
        }

        let transcript = self.state.get_handshake_hash().to_vec();
        let (k1, k2) = self.state.dangerously_get_raw_split();
        let noise_output = canonical_noise_output(k1, k2);

        Ok(Session::derive(Role::Initiator, self.peer_ik, &transcript, &noise_output, now_ms))
    }
}

/// Инициатор рукопожатия.
///
/// Обёртка над `snow`: собственных криптографических конструкций здесь нет
/// (§8.1), только связывание транскрипта с деривацией §8.3.
pub struct Initiator;

impl Initiator {
    /// Строит первое сообщение `-> e, es, s, ss` с полезной нагрузкой.
    ///
    /// `payload` кодируется вызывающим кодом — детерминированным CBOR по §6.
    /// Крипта его не разбирает: она отвечает за секретность, а не за формат.
    /// Ограничение §8.2 выражено пределом [`MAX_FIRST_PAYLOAD`].
    ///
    /// Кадр отправляется с `session_id = 0` (§8.3): вычислить настоящий
    /// идентификатор до завершения рукопожатия нельзя.
    ///
    /// Сессии здесь ещё нет — она появится в [`PendingHandshake::finish`].
    pub fn start(
        me: &Identity,
        peer_ik: &[u8; 32],
        payload: &[u8],
    ) -> Result<(Vec<u8>, PendingHandshake)> {
        if payload.len() > MAX_FIRST_PAYLOAD {
            return Err(CryptoError::Handshake);
        }

        let secret = me.ik_secret_bytes();
        let mut state = Builder::new(noise_params()?)
            .local_private_key(&secret[..])
            .map_err(|_| CryptoError::BadKeyMaterial)?
            .remote_public_key(&peer_ik[..])
            .map_err(|_| CryptoError::BadKeyMaterial)?
            .build_initiator()
            .map_err(|_| CryptoError::Handshake)?;

        let mut buffer = vec![0u8; NOISE_BUFFER];
        let len = state.write_message(payload, &mut buffer).map_err(|_| CryptoError::Handshake)?;
        buffer.truncate(len);

        Ok((buffer, PendingHandshake { state, peer_ik: *peer_ik }))
    }
}

/// Чем закончилась обработка первого сообщения.
pub enum HandshakeOutcome {
    /// Рукопожатие выполнено, сессия установлена.
    Established(Accepted),
    /// Это был повтор: сессия уже есть, надо лишь переслать прежний ответ.
    ///
    /// Отдельный вариант, а не `Accepted` с флагом: у повтора нет ни новой
    /// сессии, ни новой полезной нагрузки, и попытка выразить его теми же
    /// полями заставила бы вызывающего гадать, какие из них настоящие.
    Repeat {
        /// Ответ, который надо отправить ещё раз.
        response: Vec<u8>,
        /// Кому его слать.
        peer_ik: [u8; 32],
    },
}

/// Первое сообщение, разобранное получателем.
pub struct Accepted {
    /// Полезная нагрузка первого сообщения — приветствие и карточка (§8.2).
    pub payload: Zeroizing<Vec<u8>>,
    /// Ответ `<- e, ee, se`, который надо отправить инициатору.
    pub response: Vec<u8>,
    /// Установленная сессия.
    pub session: Session,
}

/// Получатель рукопожатия.
pub struct Responder;

impl Responder {
    /// Обрабатывает первое сообщение и готовит ответ.
    ///
    /// Получатель пробует расшифровать **своим статическим ключом — одной
    /// операцией**: в `IK` он не перебирает контакты (§8.3). Именно это
    /// устраняет дорогое trial decryption, ради которого в старой
    /// спецификации существовал PoW (§15).
    ///
    /// Anti-replay проверяется **до** ответа: иначе повтор записанного
    /// рукопожатия заставлял бы нас каждый раз выполнять полную операцию
    /// и отвечать.
    pub fn accept(
        me: &Identity,
        message: &[u8],
        guard: &mut HandshakeReplayGuard,
        now_ms: u64,
    ) -> Result<HandshakeOutcome> {
        if message.len() < EPHEMERAL_LEN {
            return Err(CryptoError::Handshake);
        }
        let ephemeral: [u8; EPHEMERAL_LEN] =
            message[..EPHEMERAL_LEN].try_into().expect("длина проверена выше");
        let digest = HandshakeReplayGuard::digest(&ephemeral, &message[EPHEMERAL_LEN..]);
        match guard.admit(digest, now_ms) {
            Admission::Fresh => {}
            Admission::Repeat { response, peer_ik } => {
                return Ok(HandshakeOutcome::Repeat { response, peer_ik })
            }
            Admission::Stale => return Err(CryptoError::HandshakeReplay),
        }

        let secret = me.ik_secret_bytes();
        let mut state = Builder::new(noise_params()?)
            .local_private_key(&secret[..])
            .map_err(|_| CryptoError::BadKeyMaterial)?
            .build_responder()
            .map_err(|_| CryptoError::Handshake)?;

        let mut payload = Zeroizing::new(vec![0u8; NOISE_BUFFER]);
        let len = state.read_message(message, &mut payload).map_err(|_| CryptoError::Handshake)?;
        payload.truncate(len);

        // `IK` инициатора приходит внутри рукопожатия и уже аутентифицирован
        // им же: подставить чужой ключ, не зная соответствующего секрета,
        // нельзя. Брать отправителя из заголовка кадра было бы ошибкой.
        let peer_ik: [u8; 32] = state
            .get_remote_static()
            .ok_or(CryptoError::Handshake)?
            .try_into()
            .map_err(|_| CryptoError::BadKeyMaterial)?;

        let mut response = vec![0u8; NOISE_BUFFER];
        let len = state.write_message(&[], &mut response).map_err(|_| CryptoError::Handshake)?;
        response.truncate(len);

        if !state.is_handshake_finished() {
            return Err(CryptoError::Handshake);
        }

        let transcript = state.get_handshake_hash().to_vec();
        let (k1, k2) = state.dangerously_get_raw_split();
        let noise_output = canonical_noise_output(k1, k2);

        // Ответ сохраняется вместе с адресатом до возврата: если он потеряется
        // в сети, повторное первое сообщение получит ровно эти байты (§8.3).
        // Порядок важен — сохранить надо до того, как значение уедет наружу.
        guard.remember_response(digest, &response, peer_ik);

        let session = Session::derive(Role::Responder, peer_ik, &transcript, &noise_output, now_ms);
        Ok(HandshakeOutcome::Established(Accepted { payload, response, session }))
    }
}

/// Ключ сопряжения десктопа с телефоном (§13.4).
///
/// Отдельный X25519, генерируемый на сопряжение. Десктоп устанавливает
/// Noise IK-сессию к телефону — **тот же паттерн и тот же кадровый формат**,
/// что и для контактов: новых криптографических конструкций режим компаньона
/// не вводит.
#[must_use]
pub fn pairing_secret() -> Zeroizing<[u8; 32]> {
    use rand_core::RngCore;
    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    Zeroizing::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(role: Role, now_ms: u64) -> Session {
        Session::derive(role, [1u8; 32], b"transcript", b"noise-output", now_ms)
    }

    #[test]
    fn both_sides_derive_the_same_session_id() {
        assert_eq!(session(Role::Initiator, 0).session_id, session(Role::Responder, 0).session_id);
    }

    #[test]
    fn chains_are_crossed_between_roles() {
        // Отправляющая цепочка инициатора обязана совпасть с принимающей
        // цепочкой получателя, иначе стороны не услышат друг друга.
        let mut initiator = session(Role::Initiator, 0);
        let responder = session(Role::Responder, 0);

        let (n, key) = initiator.send.next();
        assert_eq!(*responder.recv.peek(n).unwrap(), *key);
    }

    #[test]
    fn a_snapshot_does_not_roll_the_send_counter_back() {
        // Самое важное свойство снимка. Откат отправляющего счётчика означает
        // повтор пары «ключ, nonce» — то есть полное разрушение шифрования
        // кадра, а не просто дубль сообщения.
        let mut before = session(Role::Initiator, 7);
        for _ in 0..5 {
            before.send.next();
        }
        let expected = before.send.counter();

        let after = Session::restore(&before.export()).expect("снимок читается");
        assert_eq!(after.send.counter(), expected, "счётчик отправки обязан пережить перезапуск");

        // И следующий ключ — тот, который был бы без перезапуска.
        let mut continued = before;
        let mut restored = after;
        assert_eq!(continued.send.next(), restored.send.next());
    }

    #[test]
    fn a_digest_restored_from_disk_is_not_admitted_as_fresh() {
        // Ровно то свойство, ради которого кэш кладётся на диск: рукопожатие,
        // принятое до перезапуска, после него обязано быть повтором,
        // а не новостью. Иначе оно выполняется заново, заводит вторую сессию
        // и вытесняет живую — §5.4 держит одну сессию на семейство.
        let mut guard = HandshakeReplayGuard::default();
        let digest = HandshakeReplayGuard::digest(&[3u8; 32], "шифротекст".as_bytes());
        guard.remember_seen(digest, 1_000);
        assert_eq!(guard.len(), 1);
        assert!(matches!(guard.admit(digest, 2_000), Admission::Stale));
    }

    #[test]
    fn a_restored_digest_still_ages_from_its_own_time() {
        // Срок идёт от первой встречи, а не от восстановления. Иначе каждый
        // перезапуск продлевал бы записи, и кэш перестал бы стареть вовсе.
        let mut guard = HandshakeReplayGuard::default();
        let digest = HandshakeReplayGuard::digest(&[4u8; 32], "х".as_bytes());
        guard.remember_seen(digest, 1_000);
        guard.purge(1_000 + HANDSHAKE_REPLAY_TTL_MS);
        assert_eq!(guard.len(), 0, "запись обязана состариться по своему времени");
    }

    #[test]
    fn the_digest_of_a_message_matches_the_one_admission_uses() {
        // `digest_of` существует затем, чтобы ядро записало на диск ровно ту
        // величину, которую сверяет `accept`. Разойдись они — кэш на диске
        // оказался бы бесполезен, и молча: каждое рукопожатие после
        // перезапуска снова считалось бы новым.
        let mut message = vec![7u8; EPHEMERAL_LEN];
        message.extend_from_slice("шифротекст".as_bytes());
        let want = HandshakeReplayGuard::digest(&[7u8; 32], "шифротекст".as_bytes());
        assert_eq!(HandshakeReplayGuard::digest_of(&message), Some(want));
        assert_eq!(
            HandshakeReplayGuard::digest_of(&[1u8; EPHEMERAL_LEN - 1]),
            None,
            "короче эфемерного ключа — не рукопожатие"
        );
    }

    #[test]
    fn a_snapshot_keeps_the_skipped_key_cache() {
        // §8.4: пропущенные ключи — не оптимизация, а условие работоспособности
        // при доставке с перестановками. Потерять их при перезапуске значит
        // потерять все сообщения, которые уже в пути.
        let mut sender = session(Role::Initiator, 0);
        let keys: Vec<_> = (0..5).map(|_| sender.send.next()).collect();

        let mut receiver = session(Role::Responder, 0);
        receiver.recv.commit(keys[4].0, 0).expect("прыжок вперёд");
        assert_eq!(receiver.recv.skipped_len(), 4);

        let restored = Session::restore(&receiver.export()).expect("снимок читается");
        assert_eq!(restored.recv.skipped_len(), 4);
        for (n, key) in keys.iter().take(4) {
            assert_eq!(*restored.recv.peek(*n).unwrap(), **key, "позиция {n}");
        }
    }

    #[test]
    fn a_snapshot_round_trips_completely() {
        let original = session(Role::Responder, 12_345);
        let restored = Session::restore(&original.export()).expect("снимок читается");
        assert_eq!(restored.session_id, original.session_id);
        assert_eq!(restored.peer_ik, original.peer_ik);
        assert_eq!(restored.established_ms, original.established_ms);
        assert_eq!(restored.recv.next_counter(), original.recv.next_counter());
    }

    #[test]
    fn a_damaged_snapshot_is_refused_without_panic() {
        // Подставить вместо испорченного снимка пустую сессию нельзя: цепочка
        // начнёт с нуля, и тот же ключ уйдёт в сеть второй раз. Поэтому здесь
        // только отказ — на любом входе.
        let snapshot = session(Role::Initiator, 1).export();

        for cut in 0..snapshot.len() {
            assert!(Session::restore(&snapshot[..cut]).is_err(), "обрез {cut}");
        }

        let mut with_tail = snapshot.to_vec();
        with_tail.push(0);
        assert!(Session::restore(&with_tail).is_err(), "хвост после снимка");

        let mut wrong_version = snapshot.to_vec();
        wrong_version[0] = SNAPSHOT_VERSION.wrapping_add(1);
        assert!(Session::restore(&wrong_version).is_err(), "чужая версия формата");
    }

    #[test]
    fn an_absurd_skipped_count_is_refused_before_allocating() {
        // Испорченный файл не должен просить гигабайт памяти и получать его.
        let mut snapshot = session(Role::Initiator, 1).export().to_vec();
        let at = SNAPSHOT_HEAD - 4;
        snapshot[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Session::restore(&snapshot).is_err());
    }

    #[test]
    fn different_transcripts_give_different_sessions() {
        let a = Session::derive(Role::Initiator, [1u8; 32], b"h1", b"out", 0);
        let b = Session::derive(Role::Initiator, [1u8; 32], b"h2", b"out", 0);
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn session_id_is_never_the_handshake_sentinel() {
        // §8.3: handshake-кадры адресуются нулём. Совпадение сломало бы
        // маршрутизацию приёма; вероятность 2^-64, но проверить дёшево.
        for i in 0..64u8 {
            let s = Session::derive(Role::Initiator, [i; 32], &[i], b"out", 0);
            assert_ne!(s.session_id, ratatosk_wire::HANDSHAKE_SESSION_ID);
        }
    }

    #[test]
    fn rekey_triggers_on_age() {
        let policy = RekeyPolicy::default();
        let s = session(Role::Initiator, 0);
        assert!(!policy.should_rekey(&s, policy.max_age_ms - 1, false));
        assert!(policy.should_rekey(&s, policy.max_age_ms, false));
    }

    #[test]
    fn rekey_triggers_on_message_count() {
        let policy = RekeyPolicy::default();
        let mut s = session(Role::Initiator, 0);
        for _ in 0..policy.max_messages {
            s.send.next();
        }
        assert!(policy.should_rekey(&s, 0, false));
    }

    #[test]
    fn rekey_prefers_the_cheap_opportunity() {
        // Третье условие §8.5: обе стороны онлайн прямым каналом.
        let policy = RekeyPolicy::default();
        let s = session(Role::Initiator, 0);
        assert!(policy.should_rekey(&s, 0, true));
    }

    #[test]
    fn replay_guard_rejects_repeats() {
        let mut guard = HandshakeReplayGuard::default();
        let d = HandshakeReplayGuard::digest(&[1u8; 32], b"ct");
        assert_eq!(guard.admit(d, 0), Admission::Fresh);
        // Ответ не сохранён — повтору нечего переслать.
        assert_eq!(guard.admit(d, 1_000), Admission::Stale);
    }

    #[test]
    fn replay_guard_forgets_after_ttl() {
        let mut guard = HandshakeReplayGuard::default();
        let d = HandshakeReplayGuard::digest(&[1u8; 32], b"ct");
        guard.admit(d, 0);
        guard.purge(HANDSHAKE_REPLAY_TTL_MS);
        assert!(guard.is_empty());
        assert_eq!(guard.admit(d, HANDSHAKE_REPLAY_TTL_MS), Admission::Fresh);
    }

    #[test]
    fn replay_guard_is_bounded() {
        let mut guard = HandshakeReplayGuard::new(HANDSHAKE_REPLAY_TTL_MS, 16);
        for i in 0..256u32 {
            let d = HandshakeReplayGuard::digest(&[1u8; 32], &i.to_be_bytes());
            guard.admit(d, u64::from(i));
        }
        assert!(guard.len() <= 16);
    }

    // --- рукопожатие целиком ------------------------------------------------

    /// Разворачивает исход, ожидая установленную сессию.
    fn established(outcome: HandshakeOutcome) -> Accepted {
        match outcome {
            HandshakeOutcome::Established(accepted) => accepted,
            HandshakeOutcome::Repeat { .. } => panic!("ожидалось новое рукопожатие, пришёл повтор"),
        }
    }

    fn alice() -> Identity {
        Identity::from_seed([1u8; 32])
    }

    fn bob() -> Identity {
        Identity::from_seed([2u8; 32])
    }

    /// Прогоняет оба сообщения `IK` и возвращает сессии обеих сторон.
    fn handshake(payload: &[u8]) -> (Session, Session) {
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();

        let (msg1, mut pending) = Initiator::start(&a, &b.public().ik, payload).unwrap();
        let accepted = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());
        let initiator_session = pending.finish(&accepted.response, 0).unwrap();
        (initiator_session, accepted.session)
    }

    #[test]
    fn both_roles_agree_on_the_session() {
        let (initiator, responder) = handshake(b"hello");
        assert_eq!(
            initiator.session_id, responder.session_id,
            "стороны вывели разные session_id — рукопожатие бесполезно"
        );
    }

    #[test]
    fn chains_are_crossed_after_a_real_handshake() {
        // Отправляющая цепочка инициатора обязана совпасть с принимающей
        // цепочкой получателя. Если библиотека меняет ключи Split местами
        // по роли, ломается именно это — и канонический порядок в
        // `canonical_noise_output` существует ровно ради данного теста.
        let (mut initiator, responder) = handshake(b"hello");
        let (n, key) = initiator.send.next();
        assert_eq!(*responder.recv.peek(n).unwrap(), *key);

        let (mut responder, initiator) = {
            let (i, r) = handshake(b"hello");
            (r, i)
        };
        let (n, key) = responder.send.next();
        assert_eq!(*initiator.recv.peek(n).unwrap(), *key);
    }

    #[test]
    fn each_handshake_gives_a_fresh_session() {
        // Эфемерный ключ новый каждый раз, значит и транскрипт другой.
        let (first, _) = handshake(b"hello");
        let (second, _) = handshake(b"hello");
        assert_ne!(first.session_id, second.session_id);
    }

    #[test]
    fn first_message_payload_reaches_the_responder() {
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let payload = b"card bytes and a greeting";

        let (msg1, _pending) = Initiator::start(&a, &b.public().ik, payload).unwrap();
        let accepted = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());
        assert_eq!(&accepted.payload[..], payload);
    }

    #[test]
    fn responder_learns_the_initiator_identity_from_the_handshake() {
        // §8.3: отправитель определяется рукопожатием, а не заголовком кадра.
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let (msg1, _) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();
        let accepted = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());
        assert_eq!(accepted.session.peer_ik, a.public().ik);
    }

    #[test]
    fn oversized_first_payload_is_refused() {
        // §8.2: первое сообщение — приветствие и карточка, не переписка.
        let (a, b) = (alice(), bob());
        let too_big = vec![0u8; MAX_FIRST_PAYLOAD + 1];
        assert!(Initiator::start(&a, &b.public().ik, &too_big).is_err());
    }

    #[test]
    fn a_stranger_cannot_read_the_first_message() {
        // `IK` шифрует первое сообщение статическим ключом получателя.
        let (a, b) = (alice(), bob());
        let carol = Identity::from_seed([3u8; 32]);
        let mut guard = HandshakeReplayGuard::default();

        let (msg1, _) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();
        assert!(matches!(
            Responder::accept(&carol, &msg1, &mut guard, 0),
            Err(CryptoError::Handshake)
        ));
    }

    #[test]
    fn replayed_first_message_gets_the_same_response_again() {
        // §8.3 в исходном виде велел бы отбросить повтор. Это оставляло бы
        // контакт без сессии навсегда, если потерялся ответ: инициатор шлёт
        // первое сообщение снова, получатель молчит.
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let (msg1, mut pending) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();

        let first = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());
        let repeat = Responder::accept(&b, &msg1, &mut guard, 1_000).unwrap();

        let HandshakeOutcome::Repeat { response, peer_ik } = repeat else {
            panic!("повтор обязан вернуть сохранённый ответ, а не новую сессию");
        };
        assert_eq!(response, first.response, "ответ обязан быть тем же самым");
        assert_eq!(peer_ik, a.public().ik, "адресат повтора обязан сохраниться");

        // И этого ответа достаточно, чтобы инициатор всё-таки установил
        // сессию — то есть потеря первого ответа больше не фатальна.
        let session = pending.finish(&response, 1_000).unwrap();
        assert_eq!(session.session_id, first.session.session_id);
    }

    #[test]
    fn a_repeat_creates_no_second_session() {
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let (msg1, _) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();

        let first = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());
        for at in [1_000, 2_000, 3_000] {
            match Responder::accept(&b, &msg1, &mut guard, at).unwrap() {
                HandshakeOutcome::Repeat { response, .. } => {
                    assert_eq!(response, first.response)
                }
                HandshakeOutcome::Established(_) => {
                    panic!("повтор породил вторую сессию на тот же эфемерный ключ")
                }
            }
        }
    }

    #[test]
    fn a_repeat_without_a_cached_response_is_refused() {
        // Кэш ответов мал по сравнению с множеством отпечатков: очень старый
        // повтор ответа уже не получит. Провести рукопожатие заново нельзя —
        // это дало бы вторую сессию, — поэтому остаётся отказ.
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::new(HANDSHAKE_REPLAY_TTL_MS, 100_000);
        let (msg1, _) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();
        established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());

        // Вытесняем ответ из кэша чужими рукопожатиями.
        for i in 0..(HANDSHAKE_RESPONSE_CACHE as u32 + 2) {
            let digest = HandshakeReplayGuard::digest(&[9u8; 32], &i.to_be_bytes());
            guard.admit(digest, 0);
            guard.remember_response(digest, b"other", [9u8; 32]);
        }

        assert!(matches!(
            Responder::accept(&b, &msg1, &mut guard, 2_000),
            Err(CryptoError::HandshakeReplay)
        ));
    }

    #[test]
    fn truncated_and_corrupt_messages_are_refused() {
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let (msg1, _) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();

        assert!(Responder::accept(&b, &msg1[..16], &mut guard, 0).is_err());

        let mut corrupt = msg1.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert!(Responder::accept(&b, &corrupt, &mut guard, 0).is_err());
    }

    #[test]
    fn initiator_rejects_a_forged_response() {
        let (a, b) = (alice(), bob());
        let mut guard = HandshakeReplayGuard::default();
        let (msg1, mut pending) = Initiator::start(&a, &b.public().ik, b"hi").unwrap();
        let accepted = established(Responder::accept(&b, &msg1, &mut guard, 0).unwrap());

        let mut forged = accepted.response.clone();
        forged[0] ^= 0x01;
        assert!(pending.finish(&forged, 0).is_err());
    }

    #[test]
    fn canonical_noise_output_is_order_independent() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(*canonical_noise_output(a, b), *canonical_noise_output(b, a));
        assert_eq!(canonical_noise_output(a, b).len(), 64);
        assert_ne!(*canonical_noise_output(a, a), *canonical_noise_output(a, b));
    }

    #[test]
    fn digest_separates_ephemeral_from_ciphertext() {
        // Склейка без разделителя однозначна только потому, что `e` — ровно
        // 32 байта. Тест фиксирует, что разные разбиения одних и тех же байт
        // невозможно предъявить по типам, а разное содержимое различается.
        let a = HandshakeReplayGuard::digest(&[1u8; 32], b"xy");
        let b = HandshakeReplayGuard::digest(&[2u8; 32], b"xy");
        let c = HandshakeReplayGuard::digest(&[1u8; 32], b"yx");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
