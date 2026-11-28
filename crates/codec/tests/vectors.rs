//! Тест-векторы на каноническую сериализацию (§6, §4.1, §9.1).
//!
//! Каноническая сериализация — такая же точка расхождения реализаций, как
//! деривация ключей: подпись и хэш считаются **над байтами** (§6), и два
//! честных клиента, разошедшиеся на порядке ключей или на длине одного
//! целого, получают «подпись не сходится» на каждом сообщении. §4.1 это
//! уже подтвердил столкновением ключей: карточка получала два ключа 1,
//! и разбор брал первый попавшийся.
//!
//! Как и у `ratatosk-crypto`, ключевое свойство набора — **независимость
//! происхождения**. Файлы в `tests/vectors/` посчитаны
//! `tools/gen_codec_vectors.py`: CBOR там свой, по RFC 8949 §4.2, и перед
//! каждой генерацией сверяется с официальными примерами из приложения A
//! того же RFC; base32 карточки — вручную по алфавиту RFC 4648, а не
//! `data-encoding`. Ни одна цифра не пришла из кода, который здесь
//! проверяется. Поэтому падение означает не «кто-то поменял реализацию»,
//! а «две независимые реализации разошлись».
//!
//! # Что здесь проверяется в каждую сторону
//!
//! 1. **смысл → байты**: структура, собранная из полей, названных в строке
//!    вектора, обязана закодироваться ровно в указанные байты;
//! 2. **байты → смысл**: те же байты обязаны разобраться ровно в эти поля —
//!    без этой половины перенумерованный ключ прошёл бы незамеченным, если
//!    разбор и кодирование перепутали номера одинаково;
//! 3. **принятые байты сохраняются** (§6) и пересобираются байт в байт;
//! 4. **неканоническое отвергается** — отдельный файл; принявший такие
//!    байты клиент считал бы подпись не над тем, что подписывал отправитель.
//!
//! # Чего эти векторы не стерегут
//!
//! Внутреннюю форму нагрузки конверта (§9.1, ключ 5): для кодека она `any`,
//! а схему ей задаёт `ratatosk-proto`. В векторе она лежит готовыми
//! байтами — но не свободно: конверт целиком обязан совпасть до байта,
//! так что разойдись кодировщики на нагрузке, не совпал бы и конверт.
//!
//! Снисходительность разбора (ключ меша чужой длины отбрасывается, а не
//! роняет карточку) — это правила приёма, и живут они в тестах `card.rs`.
//! Здесь только байты.
//!
//! Тест намеренно живёт в `tests/`, а не в `src/`: ему доступен только
//! публичный API крейта. Вектор, который нельзя проверить снаружи,
//! проверяет деталь реализации, а не протокол.

use ratatosk_codec::canonical::{decode, encode};
use ratatosk_codec::{ContactCard, Envelope, Fragment, PayloadType, Value};
use ratatosk_crdt::{Hlc, MsgId};

/// Сколько реле карточка **объявляет** (0.3).
///
/// Число повторено здесь, а не взято из крейта: вектор стережёт обещание
/// «в QR едут первые три», и возьми он `MAX_CARD_RELAYS` — поднятие предела
/// подняло бы и проверку, а та смолчала бы о том, что в QR поехало больше.
const ADVERTISED_RELAYS: usize = 3;

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

fn array<const N: usize>(s: &str) -> [u8; N] {
    unhex(s)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("ожидалось {N} байт, получено {}", v.len()))
}

/// Пусто или отсутствует — так записано в файле.
fn blank(field: &str) -> bool {
    field == "-"
}

fn text_field(field: &str) -> String {
    if blank(field) {
        String::new()
    } else {
        field.to_owned()
    }
}

fn bytes_field(field: &str) -> Vec<u8> {
    if blank(field) {
        Vec::new()
    } else {
        unhex(field)
    }
}

#[test]
fn contact_card_vectors() {
    let text = include_str!("vectors/contact_card.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 12, "строка вектора: {row:?}");
        let name = row[0];
        let named_relays: Vec<String> =
            if blank(row[9]) { Vec::new() } else { row[9].split(',').map(str::to_owned).collect() };
        let expected = unhex(row[10]);
        let expected_uri = row[11];

        let card = ContactCard {
            ik: array(row[1]),
            sk: array(row[2]),
            onion: text_field(row[3]),
            chatmail: text_field(row[4]),
            display_name: text_field(row[5]),
            version: row[6].parse().expect("версия карточки"),
            ygg: bytes_field(row[7]),
            nostr: bytes_field(row[8]),
            nostr_relays: named_relays.clone(),
        };

        // Смысл → байты.
        assert_eq!(
            hex::encode(card.encode().expect("карточка кодируема")),
            hex::encode(&expected),
            "кодирование карточки разошлось: {name}"
        );

        // Байты → смысл. Поля сверяются по одному: скажи `assert_eq!` на
        // целой структуре «не равны», и не было бы видно, какой ключ уехал.
        let raw = ContactCard::decode(&expected).expect("вектор обязан разобраться");
        let back = raw.value();
        assert_eq!(back.ik, card.ik, "IK: {name}");
        assert_eq!(back.sk, card.sk, "SK: {name}");
        assert_eq!(back.onion, card.onion, "onion: {name}");
        assert_eq!(back.chatmail, card.chatmail, "почта: {name}");
        assert_eq!(back.display_name, card.display_name, "имя: {name}");
        assert_eq!(back.version, card.version, "версия: {name}");
        assert_eq!(back.ygg, card.ygg, "ключ меша: {name}");
        assert_eq!(back.nostr, card.nostr, "ключ nostr: {name}");
        // Названных реле может быть больше, чем объявленных: в колонке
        // вектора стоит то, что назвал человек, а в байтах — первые три.
        let advertised: Vec<String> =
            named_relays.iter().take(ADVERTISED_RELAYS).cloned().collect();
        assert_eq!(back.nostr_relays, advertised, "реле: {name}");

        // §6: подпись считается над принятыми байтами, а не над результатом
        // повторной сериализации.
        assert_eq!(raw.bytes(), &expected[..], "принятые байты не сохранены: {name}");
        assert_eq!(
            hex::encode(back.encode().expect("разобранная карточка кодируема")),
            hex::encode(&expected),
            "пересборка разошлась с принятыми байтами: {name}"
        );

        // §4.1: в QR едет URI, и именно он — настоящая точка стыка
        // с чужим клиентом. base32 посчитан независимо.
        assert_eq!(card.to_uri().expect("URI строится"), expected_uri, "URI: {name}");
        assert_eq!(
            ContactCard::from_uri(expected_uri).expect("URI разбирается").bytes(),
            &expected[..],
            "URI разобрался в другие байты: {name}"
        );

        checked += 1;
    }

    assert!(checked >= 15, "векторов карточки подозрительно мало: {checked}");
}

#[test]
fn envelope_vectors() {
    let text = include_str!("vectors/envelope.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 10, "строка вектора: {row:?}");
        let name = row[0];
        let payload_bytes = unhex(row[5]);
        let expected = unhex(row[9]);

        // Нагрузка дана байтами; чтобы положить её в конверт, её надо
        // разобрать — и она обязана быть канонической сама.
        let payload: Value =
            decode(&payload_bytes).expect("нагрузка вектора обязана быть канонической");

        let refs: Vec<MsgId> =
            if blank(row[7]) { Vec::new() } else { row[7].split(',').map(array::<16>).collect() };
        let fragment = if blank(row[8]) {
            None
        } else {
            let mut parts = row[8].split(':');
            Some(Fragment {
                uid: array(parts.next().expect("uid фрагмента")),
                index: parts.next().expect("номер фрагмента").parse().expect("номер"),
                total: parts.next().expect("всего фрагментов").parse().expect("всего"),
            })
        };

        let code: u64 = row[4].parse().expect("код типа нагрузки");
        let envelope = Envelope {
            msg_id: array(row[1]),
            hlc: Hlc::new(
                row[2].parse().expect("часы: стенные"),
                row[3].parse().expect("часы: логические"),
            ),
            payload_type: PayloadType::from_code(code),
            payload: payload.clone(),
            group_id: if blank(row[6]) { None } else { Some(unhex(row[6])) },
            causal_refs: refs.clone(),
            fragment,
        };

        // Смысл → байты.
        assert_eq!(
            hex::encode(envelope.encode().expect("конверт кодируем")),
            hex::encode(&expected),
            "кодирование конверта разошлось: {name}"
        );

        // Байты → смысл, по полю за раз.
        let raw = Envelope::decode(&expected).expect("вектор обязан разобраться");
        let back = raw.value();
        assert_eq!(back.msg_id, envelope.msg_id, "msg_id: {name}");
        assert_eq!(back.hlc, envelope.hlc, "часы: {name}");
        assert_eq!(back.payload_type.code(), code, "код типа нагрузки: {name}");
        assert_eq!(back.group_id, envelope.group_id, "group_id: {name}");
        assert_eq!(back.causal_refs, refs, "причинные ссылки: {name}");
        assert_eq!(back.fragment, envelope.fragment, "фрагмент: {name}");
        // Нагрузка сверяется байтами, а не значением: `Value` сравнить можно,
        // но разошедшееся кодирование нагрузки видно только в байтах.
        assert_eq!(
            hex::encode(encode(&back.payload).expect("нагрузка кодируема")),
            hex::encode(&payload_bytes),
            "нагрузка: {name}"
        );

        assert_eq!(raw.bytes(), &expected[..], "принятые байты не сохранены: {name}");
        assert_eq!(
            hex::encode(back.encode().expect("разобранный конверт кодируем")),
            hex::encode(&expected),
            "пересборка разошлась с принятыми байтами: {name}"
        );

        checked += 1;
    }

    assert!(checked >= 20, "векторов конверта подозрительно мало: {checked}");
}

#[test]
fn non_canonical_vectors_are_rejected() {
    // Вторая половина §6, без которой набор неполон: «принимает
    // канонические» и «отвергает прочие» — два разных обещания. Клиент,
    // принявший неканоническое, посчитал бы подпись не над теми байтами,
    // что подписывал отправитель.
    //
    // Чего эта проверка не стережёт: **какой именно** отказ вернулся.
    // Часть таких байтов отвергает ещё ciborium (чужая реализация),
    // часть — наша сверка повторным кодированием, и требовать здесь
    // определённого варианта ошибки значило бы стеречь чужое поведение.
    let text = include_str!("vectors/not_canonical.txt");
    let mut checked = 0;

    for row in rows(text) {
        assert_eq!(row.len(), 3, "строка вектора: {row:?}");
        let name = row[0];
        let bytes = unhex(row[1]);
        let why = row[2];

        assert!(decode(&bytes).is_err(), "приняты неканонические байты: {name} ({why})");
        // И через настоящие структуры: сверка каноничности обязана стоять
        // на пути разбора, а не только в `canonical::decode`.
        assert!(ContactCard::decode(&bytes).is_err(), "карточка принята: {name} ({why})");
        assert!(Envelope::decode(&bytes).is_err(), "конверт принят: {name} ({why})");

        checked += 1;
    }

    assert!(checked >= 12, "векторов на отказ подозрительно мало: {checked}");
}

#[test]
fn every_optional_field_appears_in_some_vector() {
    // Без этой проверки перегенерация, потерявшая случаи, прошла бы молча:
    // файл остался бы непустым, тесты зелёными, а необязательные ключи —
    // непроверенными. Именно так полгода зеленела метёлка `unused_params`,
    // осматривая ноль файлов.
    let cards: Vec<Vec<&str>> = rows(include_str!("vectors/contact_card.txt")).collect();
    for (column, field) in [(7, "ключ меша"), (8, "ключ nostr"), (9, "реле")] {
        assert!(
            cards.iter().any(|r| !blank(r[column])),
            "ни одного вектора карточки с полем «{field}»"
        );
        assert!(
            cards.iter().any(|r| blank(r[column])),
            "ни одного вектора карточки **без** поля «{field}» — \
             а пустое поле не пишется вовсе, и это тоже обещание (§6)"
        );
    }

    let envelopes: Vec<Vec<&str>> = rows(include_str!("vectors/envelope.txt")).collect();
    for (column, field) in [(6, "group_id"), (7, "причинные ссылки"), (8, "фрагмент")]
    {
        assert!(
            envelopes.iter().any(|r| !blank(r[column])),
            "ни одного вектора конверта с полем «{field}»"
        );
        assert!(
            envelopes.iter().any(|r| blank(r[column])),
            "ни одного вектора конверта **без** поля «{field}»"
        );
    }

    // Код типа нагрузки из будущей версии — отдельное обещание §9.1:
    // неизвестный тип сохраняется, а не отбрасывается.
    assert!(
        envelopes.iter().any(|r| r[4].parse::<u64>().expect("код") > 32),
        "ни одного вектора с кодом типа нагрузки из будущей версии"
    );
}

#[test]
fn vector_files_carry_their_warning() {
    // Файлы генерируются; правка руками ломает независимость всего набора.
    for text in [
        include_str!("vectors/contact_card.txt"),
        include_str!("vectors/envelope.txt"),
        include_str!("vectors/not_canonical.txt"),
    ] {
        assert!(
            text.contains("СГЕНЕРИРОВАНО tools/gen_codec_vectors.py"),
            "файл векторов потерял предупреждение о происхождении"
        );
    }
}
