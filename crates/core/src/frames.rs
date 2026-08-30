//! Сборка и разборка кадров сессии (§7.1, §8.3).
//!
//! Отдельный модуль, потому что сторон стало две. Ядро телефона
//! ([`crate::engine::Engine`]) и терминал десктопа
//! ([`crate::companion::CompanionClient`], §13.4) говорят одним и тем же
//! проводом, и правила сборки кадра у них обязаны совпадать до байта.
//! Написанные дважды, они совпадали бы ровно до первой правки в одном
//! из мест — а разошедшись, дали бы «кадр не расшифровался» без единого
//! указания, где искать.
//!
//! Здесь только то, что не зависит от состояния сторон: заголовок, набивка,
//! запечатывание и распечатывание одной позиции цепочки. Всё, что вокруг, —
//! реестр сессий, запись на диск, счётчики аномалий, политика §5.4 —
//! остаётся у той стороны, у которой оно есть.

use ratatosk_crypto::{aead, CryptoError, Session};
use ratatosk_wire::{pad_to, unpad, FrameType, Header, SizeClass, WireError};

/// Класс размера, которым ходят кадры рукопожатия.
///
/// Наименьший: первое сообщение Noise IK с карточкой в нагрузке в него
/// укладывается, а больший класс означал бы лишние байты в эфире на каждое
/// знакомство.
pub const HANDSHAKE_CLASS: SizeClass = SizeClass::S;

/// Собирает кадр рукопожатия (§8.3).
///
/// `nonce` даёт вызывающий: у ядра он из [`crate::entropy::Entropy`],
/// у симуляции (§16) — воспроизводимый. Заголовок здесь только адресует
/// шаг: кадр рукопожатия **не запечатывается нашим AEAD**, его содержимое
/// уже зашифровал Noise, — и набивается он до всей запечатанной области,
/// потому что места под наш тег в нём нет.
///
/// # Errors
///
/// Сообщение не влезает в класс размера.
pub fn handshake(
    step: u64,
    message: &[u8],
    nonce: [u8; ratatosk_wire::NONCE_LEN],
) -> Result<Vec<u8>, WireError> {
    let header =
        Header::new(FrameType::Handshake, ratatosk_wire::HANDSHAKE_SESSION_ID, step, nonce);
    let mut sealed = Vec::new();
    pad_to(message, HANDSHAKE_CLASS.sealed_len(), &mut sealed)?;
    ratatosk_wire::assemble(&header, &sealed)
}

/// Достаёт сообщение Noise из кадра рукопожатия.
///
/// # Errors
///
/// Кадр не разбирается или набивка испорчена.
pub fn handshake_message(frame: &[u8]) -> Result<Vec<u8>, WireError> {
    let view = ratatosk_wire::parse(frame)?;
    Ok(unpad(view.sealed)?.to_vec())
}

/// Запечатывает конверт в следующую позицию отправляющей цепочки (§7.3).
///
/// **Двигает цепочку.** Позиция расходуется независимо от того, уедет ли
/// кадр: вернуть её назад нельзя, и вызывающий, решивший кадр не отправлять,
/// платит одной пропущенной позицией у получателя (тот достроит её как
/// пропущенный ключ, §8.4). Поэтому запечатывать надо тогда, когда решение
/// об отправке уже принято.
///
/// Nonce выводится из счётчика, а не из случайности. Ключ сообщения и так
/// свеж на каждый кадр (§8.4), так что повтора nonce быть не может; зато
/// кадр становится воспроизводимым, а §16 этого и хочет.
///
/// # Errors
///
/// Конверт не влезает в наибольший класс размера, или отказал AEAD.
pub fn seal(session: &mut Session, envelope: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let class = SizeClass::smallest_for(envelope.len()).ok_or(WireError::PayloadTooLarge {
        got: envelope.len(),
        max: SizeClass::L.max_payload(),
    })?;
    let (counter, key) = session.send.next();

    let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
    nonce[..8].copy_from_slice(&counter.to_be_bytes());

    let header = Header::new(FrameType::Data, session.session_id, counter, nonce);
    aead::seal(&key, &header, class, envelope)
}

/// Распечатывает кадр и продвигает принимающую цепочку.
///
/// Порядок здесь — §7.3, шаг 3, и переставлять его нельзя: ключ выводится
/// **ровно для позиции** из заголовка и только потом проверяется тег.
/// Стоимость мусорного кадра ограничена одной операцией, каким бы счётчик
/// в нём ни был объявлен, а цепочка не двигается, пока тег не сошёлся.
///
/// # Errors
///
/// [`CryptoError::MessageKeyConsumed`] — позиция уже израсходована, то есть
/// кадр в точности повторяет принятый. Это **не ошибка**: почта штатно
/// дублирует письма (§9.2), и вызывающий обязан отличать этот случай от
/// испорченного кадра. Всё остальное — испорченный кадр.
pub fn open(
    session: &mut Session,
    frame: &[u8],
    now_ms: u64,
) -> Result<Vec<u8>, ratatosk_crypto::CryptoError> {
    let view = ratatosk_wire::parse(frame)?;
    let counter = view.header.counter;
    let key = session.recv.peek(counter)?;
    let (_, plaintext) = aead::open(&key, frame)?;
    session.recv.commit(counter, now_ms)?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use ratatosk_crypto::handshake::{Accepted, HandshakeOutcome, Initiator, Responder};
    use ratatosk_crypto::{HandshakeReplayGuard, Identity};

    use super::*;
    use crate::engine::{HANDSHAKE_STEP_FIRST, HANDSHAKE_STEP_RESPONSE};

    /// Две стороны, доведённые до живых сессий этим же модулем.
    fn pair() -> (Session, Session) {
        let alice = Identity::from_seed([1u8; 32]);
        let bob = Identity::from_seed([2u8; 32]);
        let mut guard = HandshakeReplayGuard::default();

        let (first, mut pending) =
            Initiator::start(&alice, &bob.public().ik, b"card").expect("первое сообщение");
        let frame = handshake(HANDSHAKE_STEP_FIRST, &first, [7u8; ratatosk_wire::NONCE_LEN])
            .expect("кадр рукопожатия");

        let message = handshake_message(&frame).expect("сообщение из кадра");
        let outcome = Responder::accept(&bob, &message, &mut guard, 0).expect("приём");
        let HandshakeOutcome::Established(Accepted { payload, response, session: bobs }) = outcome
        else {
            panic!("повтор там, где повторять нечего");
        };
        assert_eq!(&payload[..], b"card", "нагрузка §8.2 доезжает целой");

        let back = handshake(HANDSHAKE_STEP_RESPONSE, &response, [8u8; ratatosk_wire::NONCE_LEN])
            .expect("кадр ответа");
        let message = handshake_message(&back).expect("сообщение из кадра");
        let alices = pending.finish(&message, 0).expect("ответ рукопожатия");
        (alices, bobs)
    }

    #[test]
    fn a_sealed_envelope_opens_on_the_other_side() {
        let (mut alice, mut bob) = pair();
        let frame = seal(&mut alice, "привет".as_bytes()).expect("запечатывание");
        assert_eq!(open(&mut bob, &frame, 0).expect("распечатывание"), "привет".as_bytes());
    }

    #[test]
    fn an_exact_repeat_is_told_apart_from_a_broken_frame() {
        // Различать эти два случая обязан вызывающий, и потому ошибка у них
        // разная: повтор письма — штатный режим §9.2, а испорченный кадр —
        // повод для счётчика аномалий (§7.3).
        let (mut alice, mut bob) = pair();
        let frame = seal(&mut alice, "раз".as_bytes()).expect("запечатывание");
        open(&mut bob, &frame, 0).expect("первый раз");

        assert!(matches!(
            open(&mut bob, &frame, 0),
            Err(ratatosk_crypto::CryptoError::MessageKeyConsumed)
        ));

        let mut broken = seal(&mut alice, "два".as_bytes()).expect("запечатывание");
        let last = broken.len() - 1;
        broken[last] ^= 0xff;
        assert!(matches!(open(&mut bob, &broken, 0), Err(ratatosk_crypto::CryptoError::Decrypt)));
    }

    #[test]
    fn a_gap_in_the_chain_is_filled_in_afterwards() {
        // §8.4: пропущенная позиция достраивается и ждёт своего кадра.
        // Терминалу это нужно буквально: он пропускает кадры, пока человек
        // не смотрит, и должен уметь разобрать пришедшее после.
        let (mut alice, mut bob) = pair();
        let first = seal(&mut alice, "раз".as_bytes()).expect("запечатывание");
        let second = seal(&mut alice, "два".as_bytes()).expect("запечатывание");

        assert_eq!(open(&mut bob, &second, 0).expect("второй"), "два".as_bytes());
        assert_eq!(open(&mut bob, &first, 0).expect("первый — из пропущенных"), "раз".as_bytes());
    }

    #[test]
    fn a_handshake_frame_survives_the_round_trip() {
        let message = vec![9u8; 200];
        let frame = handshake(HANDSHAKE_STEP_FIRST, &message, [0u8; ratatosk_wire::NONCE_LEN])
            .expect("кадр");
        assert_eq!(frame.len(), HANDSHAKE_CLASS.frame_len(), "класс размера тот же для всех");
        assert_eq!(handshake_message(&frame).expect("разбор"), message);
    }
}
