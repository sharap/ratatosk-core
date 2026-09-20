//! Запечатывание на долговременный `IK` получателя (фаза 2, §5.3).
//!
//! Шаблон `Noise_N_25519_ChaChaPoly_BLAKE2s` — односторонний, к статическому
//! ключу. Тот же набор примитивов, что у рукопожатия ([`crate::handshake`],
//! `Noise_IK_…`): ни одного нового примитива в дереве, и §8.1 соблюдён —
//! своего здесь только связывание.
//!
//! # Зачем он понадобился
//!
//! Ключ отправителя (`SenderKeyBlock`) ехал по **установленной 1:1-сессии**,
//! и она же говорила, от кого он. Фазе 2 этого мало: блок обязан доезжать
//! до того, с кем сессии нет и может не быть вовсе — через рой, третьими
//! руками. Открыто ключ отправителя не ретранслируется ни с какой подписью:
//! он секрет. Значит его надо запечатать так, чтобы распечатал ровно один
//! адресат, а везти мог кто угодно.
//!
//! # Почему `N`, а не `K` или `X`
//!
//! `N` не аутентифицирует отправителя — и не должен. Блок подписан `SK`
//! автора на уровне конверта (§4.1), и подпись покрывает **запечатанные
//! байты**. Печать отвечает за одно: прочтёт только тот, кому адресовано.
//! Взяв `K` или `X`, мы получили бы вторую, независимую аутентификацию
//! того же самого — и обязанность держать две в согласии.
//!
//! # Чем платим, и это надо знать до применения
//!
//! **Прямой секретности здесь нет.** Запечатано на долговременный `IK`:
//! утечка `IK` раскрывает всё, что ему когда-либо запечатывали. Раздача
//! по 1:1-сессии этим свойством обладала — сессия ретчетится.
//!
//! Отсюда правило, которое обязан держать вызывающий: **есть живая сессия —
//! отдавать по ней; печать только там, где сессии нет.** Свойство группы
//! формулируется по худшему случаю, и худший случай здесь — печать.
//!
//! # Накладная плата
//!
//! [`SEAL_OVERHEAD`] байт: эфемерный открытый ключ (32) и тег AEAD (16).
//! Состояние цепочки — 32 байта, значит запечатанный блок 80.

use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Шаблон Noise для печати на статический ключ.
///
/// Разбор выбора — в заголовке модуля. Менять строку задним числом нельзя:
/// она входит в вывод ключей, то есть в совместимость на проводе.
pub const SEAL_PATTERN: &str = "Noise_N_25519_ChaChaPoly_BLAKE2s";

/// Сколько байт добавляет печать: эфемерный ключ и тег.
///
/// Число не выведено из спецификации Noise по памяти, а **замерено**
/// прогоном (`the_overhead_is_what_the_callers_budget_on`): утверждение
/// о чужой библиотеке — это утверждение, а не наблюдение.
pub const SEAL_OVERHEAD: usize = 48;

fn params() -> Result<snow::params::NoiseParams> {
    SEAL_PATTERN.parse().map_err(|_| CryptoError::Handshake)
}

/// Запечатывает байты на `IK` получателя.
///
/// Отправитель анонимен для самой печати: подлинность приходит подписью
/// над результатом (§4.1). Каждый вызов берёт свежий эфемерный ключ,
/// поэтому две печати одного и того же разным адресатам — и даже одному
/// дважды — не совпадают побайтово.
///
/// # Errors
///
/// [`CryptoError::Handshake`] — `recipient_ik` не годится как точка X25519
/// либо отказал примитив.
pub fn seal_to_static(recipient_ik: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut state = snow::Builder::new(params()?)
        .remote_public_key(recipient_ik)
        .map_err(|_| CryptoError::Handshake)?
        .build_initiator()
        .map_err(|_| CryptoError::Handshake)?;

    let mut out = vec![0u8; plaintext.len() + SEAL_OVERHEAD];
    let written = state.write_message(plaintext, &mut out).map_err(|_| CryptoError::Handshake)?;
    out.truncate(written);
    Ok(out)
}

/// Распечатывает то, что запечатали нам.
///
/// Возвращает [`Zeroizing`]: внутри — ключевой материал, и он обязан
/// стираться, когда вызывающий его отпустит. То же правило, что
/// у [`crate::file::open_chunk`].
///
/// # Errors
///
/// [`CryptoError::Decrypt`] — печать адресована не нам, испорчена или
/// подменена. Различать эти случаи нельзя: это и есть оракул.
pub fn open_from_static(own_ik_secret: &[u8; 32], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // **Своей проверки длины здесь нет, и это выяснилось поломкой.**
    // Она стояла — «короткое отсечём до примитива», — а сломать её
    // не удалось: `snow` отвергает обрезок сам, и тем же отказом.
    // Проверка, которую нельзя провалить, это не защита, а строка,
    // которую следующий будет поддерживать. Поведение стережёт
    // `a_seal_shorter_than_its_own_overhead_is_refused` — ему всё равно,
    // кто именно отказал.
    let mut state = snow::Builder::new(params()?)
        .local_private_key(own_ik_secret)
        .map_err(|_| CryptoError::Handshake)?
        .build_responder()
        .map_err(|_| CryptoError::Handshake)?;

    let mut out = Zeroizing::new(vec![0u8; sealed.len()]);
    let read = state.read_message(sealed, &mut out).map_err(|_| CryptoError::Decrypt)?;
    out.truncate(read);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// Личность по зерну — как во всех тестах крейта.
    fn who(seed: u8) -> Identity {
        Identity::from_seed([seed; 32])
    }

    #[test]
    fn what_was_sealed_to_us_opens() {
        let bob = who(2);
        let chain = [7u8; 32];
        let sealed = seal_to_static(&bob.public().ik, &chain).expect("печать");
        let back = open_from_static(&bob.ik_secret_bytes(), &sealed).expect("распечатка");
        assert_eq!(&back[..], &chain[..], "распечатанное обязано совпасть до байта");
    }

    #[test]
    fn what_was_sealed_to_someone_else_does_not_open() {
        // **Главная проверка модуля.** Всё остальное здесь — про форму;
        // это — про то, ради чего он написан.
        let (bob, eve) = (who(2), who(3));
        let sealed = seal_to_static(&bob.public().ik, b"chain").expect("печать");
        let opened = open_from_static(&eve.ik_secret_bytes(), &sealed);
        assert!(opened.is_err(), "чужую печать открывать нельзя");
    }

    #[test]
    fn a_tampered_seal_does_not_open() {
        let bob = who(2);
        let mut sealed = seal_to_static(&bob.public().ik, b"chain").expect("печать");
        // Портится **последний** байт: он в теге. Порча эфемерного ключа
        // в начале дала бы отказ раньше AEAD, и проверка говорила бы
        // о разборе, а не о подлинности.
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(
            open_from_static(&bob.ik_secret_bytes(), &sealed).is_err(),
            "испорченная печать открываться не должна"
        );
    }

    #[test]
    fn two_seals_of_the_same_bytes_differ() {
        // Эфемерный ключ свежий на каждую печать. Совпади две печати —
        // ретранслятор видел бы, что одному и тому же адресату уехало
        // то же самое, и поворот цепочки читался бы по проводу.
        let bob = who(2);
        let first = seal_to_static(&bob.public().ik, b"chain").expect("первая");
        let second = seal_to_static(&bob.public().ik, b"chain").expect("вторая");
        assert_ne!(first, second, "две печати одного и того же обязаны различаться");
    }

    #[test]
    fn a_seal_shorter_than_its_own_overhead_is_refused() {
        let bob = who(2);
        assert!(open_from_static(&bob.ik_secret_bytes(), &[0u8; SEAL_OVERHEAD - 1]).is_err());
        assert!(open_from_static(&bob.ik_secret_bytes(), &[]).is_err());
    }

    #[test]
    fn the_overhead_is_what_the_callers_budget_on() {
        // **Замер, а не оценка.** На `SEAL_OVERHEAD` считают размер блока
        // и арифметику поворота (§6.6: 31 адресат с человека). Разойдись
        // константа с библиотекой — падать обязано здесь, а не у человека,
        // чей блок не влез в кадр.
        let bob = who(2);
        for len in [0usize, 1, 32, 1000] {
            let sealed = seal_to_static(&bob.public().ik, &vec![0xa5; len]).expect("печать");
            assert_eq!(
                sealed.len(),
                len + SEAL_OVERHEAD,
                "печать {len} байт заняла {}, а звали её на {}",
                sealed.len(),
                len + SEAL_OVERHEAD
            );
        }
    }

    #[test]
    fn an_empty_payload_still_round_trips() {
        // Пустая нагрузка законна: печать — общий примитив, и отказывать
        // ей здесь значило бы завести правило, которого нет у AEAD.
        let bob = who(2);
        let sealed = seal_to_static(&bob.public().ik, b"").expect("печать");
        let back = open_from_static(&bob.ik_secret_bytes(), &sealed).expect("распечатка");
        assert!(back.is_empty());
    }
}
