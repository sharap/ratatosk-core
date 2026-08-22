//! Инварианты §16: «`decrypt(encrypt(x)) == x` при любых перестановках»
//! и «ключ сообщения не выдаётся дважды».
//!
//! Оба свойства до сих пор были покрыты примерами — то есть теми случаями,
//! которые пришли в голову автору. Разница существенна именно здесь: §8.4
//! построен вокруг того, что почта переставляет и задерживает сообщения,
//! а придуманные вручную перестановки всегда оказываются вежливыми.
//!
//! Область значений узкая намеренно: до двадцати сообщений в цепочке
//! и перестановки в тех же пределах. Кэш пропущенных ключей от этого
//! наполняется часто, а не раз в тысячу прогонов.
//!
//! Класс размера здесь всегда `S`: свойства не зависят от него, а кадр
//! класса `L` — мебибайт на каждое сообщение, и прогон на тысяче случаев
//! стал бы измерением скорости памяти.

use proptest::prelude::*;
use ratatosk_crypto::aead::{open, seal};
use ratatosk_crypto::kdf::{self, Key32};
use ratatosk_crypto::ratchet::{RecvChain, SendChain};
use ratatosk_wire::{FrameType, Header, SizeClass, NONCE_LEN};

/// Класс кадра для всех проверок ниже.
const CLASS: SizeClass = SizeClass::S;

/// Идентификатор сессии — величина из §7.1; для этих свойств любой.
const SESSION: u64 = 0x0123_4567_89ab_cdef;

/// Одно сообщение, готовое к отправке.
#[derive(Debug, Clone)]
struct Message {
    counter: u64,
    payload: Vec<u8>,
    frame: Vec<u8>,
}

/// Корневой ключ цепочки: свой для каждого прогона, чтобы прогоны
/// не зависели друг от друга.
fn chain_key(seed: u8) -> Key32 {
    kdf::derive("ratatosk v0 test chain", &[seed])
}

/// Нонс, однозначно определяемый номером: §7.2 требует уникальности нонса
/// в пределах ключа, а ключ здесь свой у каждого сообщения.
fn nonce_of(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Запечатывает подряд `payloads.len()` сообщений одной отправляющей цепочкой.
fn send_all(seed: u8, payloads: &[Vec<u8>]) -> Vec<Message> {
    let mut chain = SendChain::new(chain_key(seed));
    payloads
        .iter()
        .map(|payload| {
            let (counter, key) = chain.next();
            let header = Header::new(FrameType::Data, SESSION, counter, nonce_of(counter));
            let frame = seal(&key, &header, CLASS, payload).expect("нагрузка помещается в класс");
            Message { counter, payload: payload.clone(), frame }
        })
        .collect()
}

/// Своя перестановка вместо генератора случайных чисел: контрпример
/// воспроизводится по одному значению `swaps`.
fn permute<T>(mut items: Vec<T>, swaps: &[u16]) -> Vec<T> {
    let n = items.len();
    if n < 2 {
        return items;
    }
    for (i, s) in swaps.iter().enumerate() {
        items.swap(i % n, usize::from(*s) % n);
    }
    items
}

/// Нагрузки: короткие, потому что проверяется ретчет, а не паддинг.
fn payloads() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 1..20)
}

fn swaps() -> impl Strategy<Value = Vec<u16>> {
    prop::collection::vec(any::<u16>(), 0..40)
}

proptest! {
    /// `decrypt(encrypt(x)) == x` при любом порядке доставки.
    ///
    /// Ради этого свойства §8.4 и держит кэш пропущенных ключей: почта
    /// переставляет сообщения, и без кэша всё, что обогнало соседа,
    /// расшифровать было бы нечем — не «позже», а никогда.
    #[test]
    fn every_message_opens_no_matter_the_delivery_order(
        seed in any::<u8>(),
        payloads in payloads(),
        swaps in swaps(),
    ) {
        let sent = send_all(seed, &payloads);
        let delivered = permute(sent, &swaps);

        let mut recv = RecvChain::new(chain_key(seed));
        for message in &delivered {
            let key = recv.peek(message.counter).expect("ключ для позиции обязан выводиться");
            let (header, opened) = open(&key, &message.frame).expect("кадр обязан открыться");
            prop_assert_eq!(header.counter, message.counter);
            prop_assert_eq!(&opened[..], &message.payload[..], "открылось не то, что запечатали");
            recv.commit(message.counter, 0).expect("успешный кадр фиксируется");
        }
    }

    /// Ключ сообщения не выдаётся дважды.
    ///
    /// Это и есть forward secrecy в §8.4: ключ стирается сразу после
    /// использования. Повторное предъявление того же номера — либо дубль,
    /// который обязана была отсеять дедупликация (§9.2), либо повтор,
    /// и в обоих случаях ответ один — отказ.
    #[test]
    fn a_message_key_is_never_issued_twice(
        seed in any::<u8>(),
        payloads in payloads(),
        swaps in swaps(),
    ) {
        let sent = send_all(seed, &payloads);
        let delivered = permute(sent, &swaps);

        let mut recv = RecvChain::new(chain_key(seed));
        for message in &delivered {
            recv.peek(message.counter).expect("ключ для позиции");
            recv.commit(message.counter, 0).expect("фиксация");

            // Тот же номер второй раз — отказ. Не «другой ключ», не «тот же
            // ключ», а именно отказ: выдать ключ повторно значит отдать
            // возможность расшифровать перехваченный кадр тому, кто его
            // сохранил.
            prop_assert!(
                recv.peek(message.counter).is_err(),
                "ключ выдан повторно для номера {}", message.counter
            );
            prop_assert!(recv.commit(message.counter, 0).is_err(), "повторная фиксация принята");
        }
    }

    /// Разным номерам — разные ключи.
    ///
    /// Обратная сторона того же свойства, и проверять её надо отдельно:
    /// цепочка, выдающая один ключ на всё, «не выдаёт ключ дважды» формально
    /// не нарушает, потому что каждый номер она обслуживает по разу.
    #[test]
    fn different_positions_get_different_keys(
        seed in any::<u8>(),
        count in 1usize..20,
    ) {
        let mut chain = SendChain::new(chain_key(seed));
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for _ in 0..count {
            let (_, key) = chain.next();
            let key = *key;
            prop_assert!(!seen.contains(&key), "цепочка выдала один ключ дважды");
            seen.push(key);
        }
    }

    /// Отправляющая и принимающая цепочки идут в ногу.
    ///
    /// Проверяется на **упорядоченной** доставке, потому что здесь важно
    /// именно совпадение выводов: ключ, которым запечатали, обязан совпасть
    /// с тем, который вывели на приёме, байт в байт.
    #[test]
    fn the_two_chains_derive_the_same_keys(
        seed in any::<u8>(),
        count in 1usize..20,
    ) {
        let mut send = SendChain::new(chain_key(seed));
        let mut recv = RecvChain::new(chain_key(seed));

        for _ in 0..count {
            let (counter, sent) = send.next();
            let got = recv.peek(counter).expect("ключ для позиции");
            prop_assert_eq!(&sent[..], &got[..], "цепочки разошлись на позиции {}", counter);
            recv.commit(counter, 0).expect("фиксация");
        }
    }

    /// Испорченный кадр не открывается — и не роняет разбор.
    ///
    /// Один бит, а не случайные байты: подмена, которую AEAD обязан поймать,
    /// выглядит именно так. Ошибка при этом одна на все случаи (§7.3):
    /// различать «не тот ключ» и «испорченные байты» — значит завести оракул.
    #[test]
    fn a_single_flipped_bit_never_opens(
        seed in any::<u8>(),
        payload in prop::collection::vec(any::<u8>(), 0..64),
        position in any::<usize>(),
        bit in 0u8..8,
    ) {
        let sent = send_all(seed, &[payload]);
        let message = &sent[0];

        let mut broken = message.frame.clone();
        let at = position % broken.len();
        broken[at] ^= 1 << bit;

        let recv = RecvChain::new(chain_key(seed));
        let key = recv.peek(message.counter).expect("ключ для позиции");
        prop_assert!(open(&key, &broken).is_err(), "кадр с испорченным байтом {at} открылся");
    }

    /// Счётчик, ушедший слишком далеко вперёд, отвергается без работы.
    ///
    /// §7.3 (шаг 3): иначе кадр с `counter = u64::MAX` заставлял бы вывести
    /// невообразимое число ключей — отказ в обслуживании ценой одного кадра.
    #[test]
    fn an_absurd_counter_is_refused(
        counter in (ratatosk_crypto::ratchet::MAX_COUNTER_JUMP + 1)..u64::MAX,
    ) {
        let recv = RecvChain::new(chain_key(0));
        prop_assert!(recv.peek(counter).is_err(), "цепочка взялась догонять {counter}");
    }
}
