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
    #[must_use]
    pub fn export(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.key)
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
