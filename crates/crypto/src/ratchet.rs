//! Симметричный ретчет и кэш пропущенных ключей (§8.4).
//!
//! ```text
//! message_key_n = BLAKE3_derive_key("ratatosk v0 msg", ck_n)
//! ck_{n+1}      = BLAKE3_derive_key("ratatosk v0 chain", ck_n)
//! ```
//!
//! DH-шага нет сознательно (§8.5): он требует ответа противоположной стороны,
//! а почтовый транспорт может доставлять сутки. Плата за это — post-compromise
//! security до 7 суток вместо одного сообщения, и об этом сказано в §14.
//!
//! Ключ сообщения стирается сразу после использования — в этом и состоит
//! forward secrecy.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::kdf::{self, Key32};
use crate::labels;

/// Предел кэша пропущенных ключей на сессию (§8.4).
pub const MAX_SKIPPED_PER_SESSION: usize = 2_000;
/// Предел кэша пропущенных ключей на устройство (§8.4).
pub const MAX_SKIPPED_PER_DEVICE: usize = 200_000;
/// TTL пропущенного ключа — 30 суток (§8.4).
pub const SKIPPED_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Насколько далеко вперёд разрешено прыгать счётчику за один кадр.
///
/// Ограничение вытекает из §7.3: стоимость мусорного кадра не должна зависеть
/// от заявленного счётчика. Значение совпадает с пределом кэша на сессию —
/// больше ключей всё равно не сохранить.
pub const MAX_COUNTER_JUMP: u64 = MAX_SKIPPED_PER_SESSION as u64;

/// Отправляющая цепочка.
#[derive(Debug)]
pub struct SendChain {
    chain_key: Key32,
    counter: u64,
}

impl SendChain {
    /// Начинает цепочку с заданного корневого состояния (§8.3).
    #[must_use]
    pub fn new(chain_key: Key32) -> SendChain {
        SendChain { chain_key, counter: 0 }
    }

    /// Номер следующего сообщения.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Состояние для записи на диск (§12).
    ///
    /// `pub(crate)`, а не `pub`: наружу ключевой материал уходит только
    /// запечатанным, через [`crate::handshake::Session::export`]. Публичный
    /// доступ к ключу цепочки означал бы, что положить его в лог можно,
    /// не заметив.
    pub(crate) fn snapshot(&self) -> (&Key32, u64) {
        (&self.chain_key, self.counter)
    }

    /// Восстанавливает цепочку из записанного состояния.
    pub(crate) fn restore(chain_key: Key32, counter: u64) -> SendChain {
        SendChain { chain_key, counter }
    }

    /// Выдаёт ключ следующего сообщения и продвигает цепочку.
    ///
    /// Состояние цепочки после вызова не позволяет получить выданный ключ
    /// обратно.
    pub fn next(&mut self) -> (u64, Key32) {
        let message_key = kdf::derive(labels::MSG, &self.chain_key[..]);
        self.chain_key = kdf::derive(labels::CHAIN, &self.chain_key[..]);
        let n = self.counter;
        self.counter += 1;
        (n, message_key)
    }
}

/// Принимающая цепочка вместе с кэшем пропущенных ключей.
///
/// Почтовый транспорт доставляет с перестановками и задержками (§8.4),
/// поэтому кэш — не оптимизация, а условие работоспособности.
#[derive(Debug)]
pub struct RecvChain {
    chain_key: Key32,
    next_counter: u64,
    skipped: BTreeMap<u64, (Key32, u64)>,
}

impl RecvChain {
    /// Начинает цепочку с заданного корневого состояния.
    #[must_use]
    pub fn new(chain_key: Key32) -> RecvChain {
        RecvChain { chain_key, next_counter: 0, skipped: BTreeMap::new() }
    }

    /// Номер, которого цепочка ждёт следующим.
    #[must_use]
    pub const fn next_counter(&self) -> u64 {
        self.next_counter
    }

    /// Сколько пропущенных ключей сейчас хранится.
    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Состояние для записи на диск (§12).
    ///
    /// Кэш пропущенных ключей входит в снимок целиком, и иначе нельзя:
    /// выбросить его при перезапуске значит потерять все сообщения, которые
    /// уже в пути и придут не по порядку (§8.4).
    pub(crate) fn snapshot(&self) -> (&Key32, u64, &BTreeMap<u64, (Key32, u64)>) {
        (&self.chain_key, self.next_counter, &self.skipped)
    }

    /// Восстанавливает цепочку из записанного состояния.
    pub(crate) fn restore(
        chain_key: Key32,
        next_counter: u64,
        skipped: BTreeMap<u64, (Key32, u64)>,
    ) -> RecvChain {
        RecvChain { chain_key, next_counter, skipped }
    }

    /// Ключ **ровно для позиции `counter`**, без продвижения цепочки (§7.3, шаг 3).
    ///
    /// Вызывается до проверки тега AEAD: стоимость мусорного кадра
    /// ограничивается одной операцией независимо от заявленного счётчика.
    /// Пропущенные ключи достраиваются отдельно, через [`RecvChain::commit`],
    /// и только после успешной проверки.
    pub fn peek(&self, counter: u64) -> Result<Key32> {
        if let Some((key, _)) = self.skipped.get(&counter) {
            return Ok(key.clone());
        }
        if counter < self.next_counter {
            return Err(CryptoError::MessageKeyConsumed);
        }
        let ahead = counter - self.next_counter;
        if ahead > MAX_COUNTER_JUMP {
            return Err(CryptoError::CounterTooFarAhead);
        }

        // Прокручиваем копию состояния: сама цепочка не двигается, пока тег
        // не проверен.
        let mut ck = self.chain_key.clone();
        for _ in 0..ahead {
            ck = kdf::derive(labels::CHAIN, &ck[..]);
        }
        Ok(kdf::derive(labels::MSG, &ck[..]))
    }

    /// Фиксирует успешно расшифрованный кадр.
    ///
    /// Достраивает и кэширует ключи пропущенных позиций, продвигает цепочку
    /// и стирает использованный ключ.
    pub fn commit(&mut self, counter: u64, now_ms: u64) -> Result<()> {
        if self.skipped.remove(&counter).is_some() {
            return Ok(());
        }
        if counter < self.next_counter {
            return Err(CryptoError::MessageKeyConsumed);
        }

        while self.next_counter < counter {
            let key = kdf::derive(labels::MSG, &self.chain_key[..]);
            self.skipped.insert(self.next_counter, (key, now_ms));
            self.chain_key = kdf::derive(labels::CHAIN, &self.chain_key[..]);
            self.next_counter += 1;
        }

        self.chain_key = kdf::derive(labels::CHAIN, &self.chain_key[..]);
        self.next_counter = counter + 1;
        self.enforce_limits(now_ms);
        Ok(())
    }

    /// Выбрасывает просроченные и лишние пропущенные ключи (§8.4).
    pub fn enforce_limits(&mut self, now_ms: u64) {
        self.skipped.retain(|_, (_, at)| now_ms.saturating_sub(*at) < SKIPPED_TTL_MS);
        while self.skipped.len() > MAX_SKIPPED_PER_SESSION {
            // Вытесняются самые старые — то есть с наименьшим счётчиком.
            let Some(&oldest) = self.skipped.keys().next() else { break };
            self.skipped.remove(&oldest);
        }
    }
}

/// Sender key группы (§11.1).
///
/// Отдельная цепочка на каждого участника, распространяемая всем остальным
/// по 1:1-сессиям. Ключ сообщения одинаков у всех получателей — поэтому
/// групповое сообщение обязано быть подписано `SK` отправителя, иначе любой
/// участник мог бы подделать сообщение от имени любого другого.
#[derive(Debug)]
pub struct SenderChain {
    key: Key32,
    counter: u64,
}

impl SenderChain {
    /// Начинает цепочку.
    #[must_use]
    pub fn new(key: Key32) -> SenderChain {
        SenderChain { key, counter: 0 }
    }

    /// Текущий номер.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Выдаёт ключ группового сообщения и продвигает цепочку.
    pub fn next(&mut self) -> (u64, Key32) {
        let message_key = kdf::derive(labels::SENDER_MSG, &self.key[..]);
        self.key = kdf::derive(labels::SENDER_CHAIN, &self.key[..]);
        let n = self.counter;
        self.counter += 1;
        (n, message_key)
    }

    /// Экспортирует состояние для передачи новому участнику (§11.5).
    ///
    /// Передаётся **текущее** состояние: новый участник не может расшифровать
    /// сообщения, отправленные до вступления.
    ///
    /// Одного этого мало: номер отсюда не виден, а получателю он нужен —
    /// см. [`SenderChain::resume`]. Отдавать их врозь пришлось бы всё равно,
    /// потому что по проводу они едут разными полями.
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key)
    }

    /// Поднимает чужую цепочку с того места, где её отдали (§11.5).
    ///
    /// **Номер обязателен, и это не мелочь.** [`SenderChain::new`] начинает
    /// с нуля, а отдающий к этому времени отправил уже `counter` сообщений:
    /// ключи у них сойдутся, а номера разойдутся — и получатель отверг бы
    /// первое же сообщение как «из будущего» либо принял бы чужой номер
    /// за свой. Оба конца обязаны знать одно число.
    #[must_use]
    pub fn resume(key: Key32, counter: u64) -> SenderChain {
        SenderChain { key, counter }
    }
}

/// Версия формата снимка приёмной цепочки. Меняется при любой правке раскладки.
const INBOX_SNAPSHOT_VERSION: u8 = 1;
/// Длина неизменной части снимка.
const INBOX_SNAPSHOT_HEAD: usize = 1 + 32 + 8 + 4;

/// Приём чужой sender-цепочки вместе с кэшем пропущенных ключей (§11.1).
///
/// # Почему это не [`RecvChain`]
///
/// Логика у них одна, и соблазн переиспользовать велик. Разводит их **ярлык**:
/// 1:1-цепочка крутится на `labels::MSG` и `labels::CHAIN`, групповая —
/// на `labels::SENDER_MSG` и `labels::SENDER_CHAIN` (§11.1). Ярлык здесь
/// не украшение: он единственное, что разделяет два ключевых материала,
/// и сложи мы обе цепочки в один тип с полем «каким ярлыком крутить», ошибка
/// в этом поле дала бы не отказ, а тихо неверные ключи. Разные типы делают
/// такую ошибку ненаписуемой.
///
/// # Зачем кэш
///
/// Ровно затем же, зачем он у 1:1 (§8.4): почта доставляет с перестановками,
/// а в группе перестановок больше — одно сообщение уезжает **тридцатью двумя
/// письмами** (§11.3), и порядок между разными отправителями не обещан вовсе.
/// Без кэша первое же переставленное сообщение отравляло бы цепочку
/// до следующей смены ключа.
///
/// # Чего он не лечит
///
/// Замену цепочки. При вступлении каждый участник заводит **новую** цепочку
/// (§11.5), и пришедший ключ вытесняет прежний вместе с кэшем: сообщения,
/// уехавшие по старой цепочке и не дошедшие, после этого не открыть. Это
/// свойство модели, а не кэша, и записано оно в `ARCHITECTURE.md`.
#[derive(Debug)]
pub struct SenderInbox {
    chain_key: Key32,
    next_counter: u64,
    skipped: BTreeMap<u64, (Key32, u64)>,
}

impl SenderInbox {
    /// Поднимает цепочку с того места, где её отдали (§11.5).
    ///
    /// Номер обязателен по той же причине, что у [`SenderChain::resume`]:
    /// отдающий к этому времени отправил уже `counter` сообщений, и начатая
    /// с нуля цепочка сошлась бы в ключах, но разошлась в номерах.
    #[must_use]
    pub fn resume(chain_key: Key32, counter: u64) -> SenderInbox {
        SenderInbox { chain_key, next_counter: counter, skipped: BTreeMap::new() }
    }

    /// Номер, которого цепочка ждёт следующим.
    #[must_use]
    pub const fn next_counter(&self) -> u64 {
        self.next_counter
    }

    /// Сколько пропущенных ключей сейчас хранится.
    #[must_use]
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Где цепочка стоит сейчас: ключ и номер, которого она ждёт.
    ///
    /// Нужно затем, что состояние чужой цепочки хранится **двумя** записями:
    /// позицией и кэшем пропусков. Позиция — то, что отдают новичку при
    /// вступлении (§11.5), и она обязана быть **текущей**: отдай мы ту,
    /// с которой начали, новичок открыл бы всё сказанное до него — ровно
    /// то, чего §11.5 обещает не допускать.
    ///
    /// Кэш при этом новичку не отдаётся никогда: пропуски — это наши
    /// нерасшифрованные хвосты, и к нему они отношения не имеют.
    #[must_use]
    pub fn position(&self) -> (Key32, u64) {
        (self.chain_key.clone(), self.next_counter)
    }

    /// Снимок состояния для записи на диск (§12).
    ///
    /// **Кэш входит целиком, и иначе нельзя**: выбросить его при перезапуске
    /// значит потерять все групповые сообщения, которые уже в пути и придут
    /// не по порядку, — а в группе их до тридцати двух копий на одно
    /// сообщение (§11.3).
    ///
    /// Формат свой, а не CBOR, и по той же причине, что у снимка сессии:
    /// это внутреннее состояние одного устройства, в сеть оно не уходит,
    /// и канонизация (§6) ему не нужна. Нужна ровно одна вещь — чтобы
    /// разбор не принял мусор молча.
    ///
    /// ```text
    /// version(1) ‖ chain(32) ‖ next_counter(8) ‖ skipped_count(4)
    ///   ‖ { counter(8) ‖ key(32) ‖ created_ms(8) } * skipped_count
    /// ```
    ///
    /// Результат содержит ключевой материал в открытом виде и обязан быть
    /// запечатан перед записью — этим занимается `ratatosk-store`.
    #[must_use]
    pub fn export(&self) -> Zeroizing<Vec<u8>> {
        let mut out =
            Zeroizing::new(Vec::with_capacity(INBOX_SNAPSHOT_HEAD + self.skipped.len() * 48));
        out.push(INBOX_SNAPSHOT_VERSION);
        out.extend_from_slice(&self.chain_key[..]);
        out.extend_from_slice(&self.next_counter.to_be_bytes());
        // Число пропущенных ограничено `MAX_SKIPPED_PER_SESSION`, так что
        // в u32 оно помещается с огромным запасом.
        out.extend_from_slice(&u32::try_from(self.skipped.len()).unwrap_or(u32::MAX).to_be_bytes());
        for (counter, (key, created_ms)) in &self.skipped {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(&key[..]);
            out.extend_from_slice(&created_ms.to_be_bytes());
        }
        out
    }

    /// Восстанавливает цепочку из снимка.
    ///
    /// Отказ означает порчу файла или снимок от несовместимой версии.
    /// Тихо подставить пустую цепочку нельзя: `next_counter` начался бы
    /// с нуля, и **уже принятые номера открылись бы заново** — то есть
    /// одно и то же сообщение легло бы в историю дважды.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadKeyMaterial`] — чужая версия, обрезанный вход,
    /// заявленное число пропусков больше предела или лишний хвост.
    pub fn restore(bytes: &[u8]) -> Result<SenderInbox> {
        let mut cursor = crate::handshake::Cursor::new(bytes);
        if cursor.byte()? != INBOX_SNAPSHOT_VERSION {
            return Err(CryptoError::BadKeyMaterial);
        }
        let chain_key = Zeroizing::new(cursor.take::<32>()?);
        let next_counter = u64::from_be_bytes(cursor.take()?);

        let count = u32::from_be_bytes(cursor.take()?) as usize;
        // Заявленное число проверяется пределом до всякого выделения памяти:
        // иначе испорченный файл просит гигабайт и получает его.
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
            // проглотить его — значит однажды восстановить не ту цепочку.
            return Err(CryptoError::BadKeyMaterial);
        }
        Ok(SenderInbox { chain_key, next_counter, skipped })
    }

    /// Ключ **ровно для позиции `counter`**, без продвижения цепочки.
    ///
    /// Тот же порядок, что у 1:1 (§7.3, шаг 3): ключ считается до проверки
    /// подписи и тега, поэтому стоимость мусорного кадра ограничена
    /// независимо от заявленного счётчика.
    ///
    /// # Errors
    ///
    /// [`CryptoError::MessageKeyConsumed`] — номер уже пройден и ключа больше
    /// нет; [`CryptoError::CounterTooFarAhead`] — прыжок дальше, чем можно
    /// сохранить.
    pub fn peek(&self, counter: u64) -> Result<Key32> {
        if let Some((key, _)) = self.skipped.get(&counter) {
            return Ok(key.clone());
        }
        if counter < self.next_counter {
            return Err(CryptoError::MessageKeyConsumed);
        }
        let ahead = counter - self.next_counter;
        if ahead > MAX_COUNTER_JUMP {
            return Err(CryptoError::CounterTooFarAhead);
        }

        let mut ck = self.chain_key.clone();
        for _ in 0..ahead {
            ck = kdf::derive(labels::SENDER_CHAIN, &ck[..]);
        }
        Ok(kdf::derive(labels::SENDER_MSG, &ck[..]))
    }

    /// Фиксирует успешно принятое сообщение.
    ///
    /// Достраивает и кэширует ключи пропущенных позиций, продвигает цепочку
    /// и стирает использованный ключ.
    ///
    /// # Errors
    ///
    /// [`CryptoError::MessageKeyConsumed`] — этот номер уже принимали.
    pub fn commit(&mut self, counter: u64, now_ms: u64) -> Result<()> {
        if self.skipped.remove(&counter).is_some() {
            return Ok(());
        }
        if counter < self.next_counter {
            return Err(CryptoError::MessageKeyConsumed);
        }

        while self.next_counter < counter {
            let key = kdf::derive(labels::SENDER_MSG, &self.chain_key[..]);
            self.skipped.insert(self.next_counter, (key, now_ms));
            self.chain_key = kdf::derive(labels::SENDER_CHAIN, &self.chain_key[..]);
            self.next_counter += 1;
        }

        self.chain_key = kdf::derive(labels::SENDER_CHAIN, &self.chain_key[..]);
        self.next_counter = counter + 1;
        self.enforce_limits(now_ms);
        Ok(())
    }

    /// Выбрасывает просроченные и лишние пропущенные ключи.
    ///
    /// Те же пределы, что у 1:1: тридцать суток и две тысячи ключей. Число
    /// здесь общее нарочно — «сколько ждать переставленное письмо» вопрос
    /// транспорта, а не того, кому оно адресовано.
    pub fn enforce_limits(&mut self, now_ms: u64) {
        self.skipped.retain(|_, (_, at)| now_ms.saturating_sub(*at) < SKIPPED_TTL_MS);
        while self.skipped.len() > MAX_SKIPPED_PER_SESSION {
            let Some(&oldest) = self.skipped.keys().next() else { break };
            self.skipped.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> Key32 {
        kdf::derive(labels::ROOT, b"test")
    }

    #[test]
    fn send_and_recv_agree_in_order() {
        let mut send = SendChain::new(root());
        let mut recv = RecvChain::new(root());
        for expected in 0..10u64 {
            let (n, key) = send.next();
            assert_eq!(n, expected);
            assert_eq!(*recv.peek(n).unwrap(), *key);
            recv.commit(n, 0).unwrap();
        }
    }

    #[test]
    fn out_of_order_delivery_works() {
        // Почта переставляет сообщения (§8.4) — это основной режим, не край.
        let mut send = SendChain::new(root());
        let keys: Vec<_> = (0..5).map(|_| send.next()).collect();

        let mut recv = RecvChain::new(root());
        for &(n, ref key) in [&keys[3], &keys[0], &keys[4], &keys[1], &keys[2]] {
            assert_eq!(*recv.peek(n).unwrap(), **key, "позиция {n}");
            recv.commit(n, 0).unwrap();
        }
        assert_eq!(recv.skipped_len(), 0, "все пропуски должны быть разобраны");
    }

    #[test]
    fn replayed_counter_is_refused() {
        let mut send = SendChain::new(root());
        let mut recv = RecvChain::new(root());
        let (n, _) = send.next();
        recv.commit(n, 0).unwrap();
        assert!(matches!(recv.peek(n), Err(CryptoError::MessageKeyConsumed)));
        assert!(matches!(recv.commit(n, 0), Err(CryptoError::MessageKeyConsumed)));
    }

    #[test]
    fn absurd_counter_is_refused_cheaply() {
        // §7.3: стоимость мусорного кадра не должна зависеть от счётчика.
        let recv = RecvChain::new(root());
        assert!(matches!(recv.peek(u64::MAX), Err(CryptoError::CounterTooFarAhead)));
    }

    #[test]
    fn peek_does_not_advance_state() {
        let recv = RecvChain::new(root());
        let a = recv.peek(5).unwrap();
        let b = recv.peek(5).unwrap();
        assert_eq!(*a, *b);
        assert_eq!(recv.next_counter(), 0, "peek не двигает цепочку");
    }

    #[test]
    fn a_sender_inbox_agrees_with_the_chain_it_mirrors() {
        // Обе стороны обязаны сойтись в ключах: отправитель крутит
        // `SenderChain`, получатель — `SenderInbox`, и разойдись они
        // хоть на ярлык, групповое сообщение не открылось бы ни разу.
        let mut send = SenderChain::new(root());
        let mut inbox = SenderInbox::resume(root(), 0);
        for expected in 0..10u64 {
            let (n, key) = send.next();
            assert_eq!(n, expected);
            assert_eq!(*inbox.peek(n).unwrap(), *key, "номер {n}");
            inbox.commit(n, 0).unwrap();
        }
        assert_eq!(inbox.skipped_len(), 0, "по порядку пропусков не бывает");
    }

    #[test]
    fn a_sender_inbox_survives_reordering() {
        // Одно групповое сообщение уезжает тридцатью двумя письмами (§11.3),
        // и порядок между ними не обещан. Без кэша первое переставленное
        // отравляло бы цепочку до следующей смены ключа.
        let mut send = SenderChain::new(root());
        let keys: Vec<(u64, Key32)> = (0..5).map(|_| send.next()).collect();

        let mut inbox = SenderInbox::resume(root(), 0);
        // Приходит последнее, затем всё остальное задом наперёд.
        for (n, key) in keys.iter().rev() {
            assert_eq!(*inbox.peek(*n).unwrap(), **key, "номер {n} в обратном порядке");
            inbox.commit(*n, 0).unwrap();
        }
        assert_eq!(inbox.skipped_len(), 0, "все пропуски разобраны");
    }

    #[test]
    fn a_sender_inbox_never_serves_a_number_twice() {
        // Forward secrecy: ключ стирается сразу после использования.
        let mut send = SenderChain::new(root());
        let (n, _) = send.next();
        let mut inbox = SenderInbox::resume(root(), 0);
        inbox.peek(n).unwrap();
        inbox.commit(n, 0).unwrap();
        assert!(matches!(inbox.peek(n), Err(CryptoError::MessageKeyConsumed)));
        assert!(matches!(inbox.commit(n, 0), Err(CryptoError::MessageKeyConsumed)));
    }

    #[test]
    fn a_sender_inbox_refuses_an_absurd_counter() {
        // §7.3: стоимость мусорного кадра не должна зависеть от заявленного
        // счётчика. Иначе один кадр с `u64::MAX` заставил бы выводить ключи
        // до конца времён.
        let inbox = SenderInbox::resume(root(), 0);
        assert!(inbox.peek(MAX_COUNTER_JUMP).is_ok(), "ровно предел законен");
        assert!(matches!(inbox.peek(MAX_COUNTER_JUMP + 1), Err(CryptoError::CounterTooFarAhead)));
        assert!(matches!(inbox.peek(u64::MAX), Err(CryptoError::CounterTooFarAhead)));
    }

    #[test]
    fn a_resumed_inbox_starts_where_the_key_was_handed_over() {
        // §11.5: цепочку отдают вместе с номером. Начни получатель с нуля —
        // он ждал бы номера, которых уже не будет.
        let mut send = SenderChain::new(root());
        for _ in 0..3 {
            send.next();
        }
        let handed = SenderInbox::resume(Key32::new(*send.export()), send.counter());
        assert_eq!(handed.next_counter(), 3);
        assert!(matches!(handed.peek(0), Err(CryptoError::MessageKeyConsumed)));

        let mut handed = handed;
        let (n, key) = send.next();
        assert_eq!(n, 3);
        assert_eq!(*handed.peek(n).unwrap(), *key, "первое после передачи открывается");
        handed.commit(n, 0).unwrap();
    }

    #[test]
    fn the_position_moves_with_the_chain() {
        // Позицию отдают новичку при вступлении (§11.5), и она обязана быть
        // текущей: отдай мы начальную, он открыл бы всё сказанное до него.
        let mut send = SenderChain::new(root());
        let mut inbox = SenderInbox::resume(root(), 0);
        let started = inbox.position();

        for _ in 0..3 {
            let (n, _) = send.next();
            inbox.peek(n).unwrap();
            inbox.commit(n, 0).unwrap();
        }
        let (key, next) = inbox.position();
        assert_eq!(next, 3, "номер продвинулся");
        assert_ne!(*key, *started.0, "и ключ вместе с ним");

        // Поднятая с этой позиции цепочка открывает следующее, но не прошлое.
        let mut handed = SenderInbox::resume(key, next);
        let (n, expected) = send.next();
        assert_eq!(*handed.peek(n).unwrap(), *expected);
        handed.commit(n, 0).unwrap();
        assert!(matches!(handed.peek(0), Err(CryptoError::MessageKeyConsumed)));
    }

    #[test]
    fn a_sender_inbox_snapshot_round_trips() {
        // Кэш входит в снимок целиком: выбросив его при перезапуске, мы
        // потеряли бы всё, что уже в пути.
        let mut send = SenderChain::new(root());
        let keys: Vec<(u64, Key32)> = (0..4).map(|_| send.next()).collect();

        let mut inbox = SenderInbox::resume(root(), 0);
        inbox.peek(3).unwrap();
        inbox.commit(3, 0).unwrap();
        assert_eq!(inbox.skipped_len(), 3);

        let bytes = inbox.export();
        let restored = SenderInbox::restore(&bytes).expect("снимок разбирается");
        assert_eq!(restored.next_counter(), 4);
        assert_eq!(restored.skipped_len(), 3, "кэш пережил снимок целиком");
        assert_eq!(*restored.peek(1).unwrap(), *keys[1].1, "пропущенный ключ пережил снимок");

        // Мусор не принимается молча: подставленная пустая цепочка открыла бы
        // уже принятые номера заново, и сообщение легло бы в историю дважды.
        assert!(SenderInbox::restore(&[]).is_err(), "пустой вход");
        assert!(SenderInbox::restore(&bytes[..bytes.len() - 1]).is_err(), "обрезанный");
        let mut tail = bytes.to_vec();
        tail.push(0);
        assert!(SenderInbox::restore(&tail).is_err(), "лишний хвост");
        let mut other = bytes.to_vec();
        other[0] = 2;
        assert!(SenderInbox::restore(&other).is_err(), "чужая версия");
    }

    #[test]
    fn skipped_keys_expire_by_ttl() {
        let mut send = SendChain::new(root());
        let keys: Vec<_> = (0..5).map(|_| send.next()).collect();

        let mut recv = RecvChain::new(root());
        recv.commit(keys[4].0, 0).unwrap();
        assert_eq!(recv.skipped_len(), 4);

        recv.enforce_limits(SKIPPED_TTL_MS + 1);
        assert_eq!(recv.skipped_len(), 0, "пропущенные ключи живут 30 суток");
    }

    #[test]
    fn chain_keys_differ_from_message_keys() {
        let mut send = SendChain::new(root());
        let (_, first) = send.next();
        let (_, second) = send.next();
        assert_ne!(*first, *second);
        assert_ne!(*first, *root());
    }

    #[test]
    fn a_resumed_chain_agrees_on_both_key_and_number() {
        // Ключи сходились и до `resume` — расходились номера, и это хуже
        // расхождения ключей: сообщение расшифровалось бы, а место в цепочке
        // оказалось не то.
        let mut sender = SenderChain::new(root());
        for _ in 0..7 {
            let _ = sender.next();
        }
        let mut joined = SenderChain::resume(sender.export(), sender.counter());
        assert_eq!(joined.counter(), sender.counter(), "номер обязан приехать вместе с ключом");

        let (mine, key_here) = sender.next();
        let (theirs, key_there) = joined.next();
        assert_eq!(mine, theirs, "номера сошлись");
        assert_eq!(key_here.as_ref(), key_there.as_ref(), "и ключи тоже");
    }

    #[test]
    fn sender_chain_export_matches_fresh_receiver() {
        let mut chain = SenderChain::new(root());
        let (_, before_join) = chain.next();
        chain.next();

        // Новый участник получает текущее состояние (§11.5) и с этого момента
        // читает то же, что и остальные.
        let mut joined = SenderChain::new(chain.export());
        let (_, sender_key) = chain.next();
        let (_, joined_key) = joined.next();

        assert_eq!(*sender_key, *joined_key, "после вступления ключи совпадают");
        assert_ne!(
            *before_join, *joined_key,
            "сообщения до вступления новому участнику недоступны"
        );
    }
}
