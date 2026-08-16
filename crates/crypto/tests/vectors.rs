//! Тест-векторы на деривацию ключей (§16).
//!
//! «Тест-векторы на всю деривацию ключей, зафиксированные в репозитории.»
//!
//! Ключевое свойство этого набора — **независимость происхождения**. Файлы
//! в `tests/vectors/` посчитаны `tools/gen_vectors.py`: BLAKE3 там своей
//! реализацией, сверенной с официальными контрольными векторами, X25519
//! и Ed25519 — библиотекой `cryptography`, base32 отпечатка — вручную по
//! алфавиту §3. Ни одна цифра не пришла из кода, который здесь проверяется.
//!
//! Поэтому падение такого теста означает не «кто-то поменял реализацию»,
//! а «две независимые реализации разошлись» — то есть ровно то, что делает
//! клиенты несовместимыми.
//!
//! Тест намеренно живёт в `tests/`, а не в `src/`: ему доступен только
//! публичный API крейта. Вектор, который нельзя проверить снаружи, проверяет
//! деталь реализации, а не протокол.

use ratatosk_crypto::handshake::{Role, Session};
use ratatosk_crypto::identity::Identity;
use ratatosk_crypto::{kdf, labels};

/// Разбирает строку файла векторов: поля через `|`, `#` — комментарий.
fn rows(text: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split('|').map(str::trim).collect())
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("некорректный hex {s:?}: {e}"))
}

fn array32(s: &str) -> [u8; 32] {
    unhex(s)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("ожидалось 32 байта, получено {}", v.len()))
}

/// Контекст по имени из файла — иначе опечатка в строке контекста осталась бы
/// незамеченной: тест сверял бы вектор сам с собой.
fn context_by_name(name: &str) -> &'static str {
    labels::ALL
        .into_iter()
        .find(|c| *c == name)
        .unwrap_or_else(|| panic!("в labels.rs нет контекста {name:?} — вектор или код устарел"))
}

#[test]
fn derive_key_vectors() {
    let text = include_str!("vectors/derive_key.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 4, "строка вектора: {row:?}");
        let context = context_by_name(row[0]);
        let material = unhex(row[1]);
        let out_len: usize = row[2].parse().expect("длина вывода");
        let expected = unhex(row[3]);

        assert_eq!(expected.len(), out_len, "длина ожидаемого значения не совпадает с полем");

        let mut got = vec![0u8; out_len];
        kdf::derive_into(context, &material, &mut got);

        assert_eq!(
            hex::encode(&got),
            hex::encode(&expected),
            "деривация разошлась: контекст {context:?}, материал {} байт, длина {out_len}",
            material.len()
        );

        // Для 32 байт заодно проверяется, что `derive` и `derive_into`
        // не разъехались между собой.
        if out_len == 32 {
            assert_eq!(&kdf::derive(context, &material)[..], &got[..]);
        }
        checked += 1;
    }

    assert!(checked >= 30, "векторов подозрительно мало: {checked}");
}

#[test]
fn every_label_is_covered_by_a_vector() {
    // Без этой проверки новый контекст в labels.rs остался бы без вектора,
    // и §16 «на всю деривацию» тихо перестал бы выполняться.
    let text = include_str!("vectors/derive_key.txt");
    let used: Vec<&str> = rows(text).map(|r| r[0]).collect();
    for context in labels::ALL {
        assert!(used.contains(&context), "нет ни одного вектора для контекста {context:?}");
    }
}

#[test]
fn identity_vectors() {
    let text = include_str!("vectors/identity.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 6, "строка вектора: {row:?}");
        let seed = array32(row[0]);
        let expected_ik_secret = row[1];
        let expected_ik_public = row[3];
        let expected_sk_public = row[4];
        let expected_fingerprint = row[5];

        let identity = Identity::from_seed(seed);

        assert_eq!(
            hex::encode(&identity.ik_secret_bytes()[..]),
            expected_ik_secret,
            "секретный IK разошёлся для seed {}",
            row[0]
        );

        // Публичные ключи считались независимой библиотекой: совпадение
        // означает, что dalek и `cryptography` согласны в кодировании точек
        // и в обработке скаляра.
        assert_eq!(hex::encode(identity.public().ik), expected_ik_public, "публичный IK");
        assert_eq!(hex::encode(identity.public().sk), expected_sk_public, "публичный SK");

        // Отпечаток — единственное, что сверяют люди голосом (§3). Здесь
        // проверяется вся цепочка целиком: хэш, срез, алфавит без похожих
        // знаков и разбиение на группы.
        assert_eq!(identity.fingerprint(), expected_fingerprint, "отпечаток");
        checked += 1;
    }

    assert!(checked >= 3, "векторов идентичности подозрительно мало: {checked}");
}

#[test]
fn session_vectors() {
    let text = include_str!("vectors/session.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 6, "строка вектора: {row:?}");
        let transcript = unhex(row[0]);
        let noise_output = unhex(row[1]);
        let expected_session_id = unhex(row[2]);
        let expected_root = unhex(row[3]);
        let expected_chain_a = array32(row[4]);
        let expected_chain_b = array32(row[5]);

        // §8.3: session_id — первые 8 байт, прочитанные как big-endian.
        // Вектор ловит и срез, и порядок байтов: перепутанный порядок дал бы
        // рабочий, но несовместимый клиент.
        let session_id = kdf::derive_u64(labels::SESSION_ID, &transcript);
        assert_eq!(
            session_id.to_be_bytes().to_vec(),
            expected_session_id,
            "session_id разошёлся для транскрипта {}",
            row[0]
        );

        let mut root_material = transcript.clone();
        root_material.extend_from_slice(&noise_output);
        let root = kdf::derive(labels::ROOT, &root_material);
        assert_eq!(hex::encode(&root[..]), hex::encode(&expected_root), "корневой ключ");

        assert_eq!(*kdf::derive(labels::CHAIN_A, &root[..]), expected_chain_a, "цепочка A");
        assert_eq!(*kdf::derive(labels::CHAIN_B, &root[..]), expected_chain_b, "цепочка B");

        // А теперь то же самое через настоящий Session::derive — иначе
        // проверялась бы формула, но не её применение.
        let mut initiator =
            Session::derive(Role::Initiator, [0u8; 32], &transcript, &noise_output, 0);
        let mut responder =
            Session::derive(Role::Responder, [0u8; 32], &transcript, &noise_output, 0);

        assert_eq!(initiator.session_id, session_id, "Session::derive и kdf разошлись");

        // §8.3: инициатор берёт chain-a как отправляющую, получатель — chain-b.
        let (n, initiator_key) = initiator.send.next();
        assert_eq!(n, 0);
        assert_eq!(
            *initiator_key,
            *kdf::derive(labels::MSG, &expected_chain_a),
            "цепочка инициатора"
        );

        let (n, responder_key) = responder.send.next();
        assert_eq!(n, 0);
        assert_eq!(
            *responder_key,
            *kdf::derive(labels::MSG, &expected_chain_b),
            "цепочка получателя"
        );

        checked += 1;
    }

    assert!(checked >= 4, "векторов сессии подозрительно мало: {checked}");
}

#[test]
fn vector_files_carry_their_warning() {
    // Файлы генерируются; правка руками ломает независимость всего набора.
    for text in [
        include_str!("vectors/derive_key.txt"),
        include_str!("vectors/identity.txt"),
        include_str!("vectors/session.txt"),
    ] {
        assert!(
            text.contains("СГЕНЕРИРОВАНО tools/gen_vectors.py"),
            "файл векторов потерял предупреждение о происхождении"
        );
    }
}
