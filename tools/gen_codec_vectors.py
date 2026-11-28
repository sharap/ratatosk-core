#!/usr/bin/env python3
"""Генератор тест-векторов на каноническую сериализацию (§6, §4.1, §9.1).

Смысл тот же, что у `gen_vectors.py`: **независимость происхождения**.
Векторы, посчитанные тем же кодом, который они проверяют, доказывают
только его неизменность — перепишешь кодек с ошибкой, перегенерируешь
векторы, и тесты зелёные при разъехавшихся клиентах. Поэтому здесь
не используется ничего из дерева:

* CBOR кодируется своим кодировщиком по RFC 8949 §4.2, а не ciborium;
  перед каждой генерацией он сверяется с **официальными** примерами
  из RFC 8949, приложение A, и отказывается работать при расхождении;
* base32 карточки (§4.1) считается вручную по алфавиту RFC 4648,
  а не `data-encoding`.

Почему именно эти две структуры. Каноническая сериализация — такая же
точка расхождения реализаций, как деривация: подпись и хэш считаются
над байтами (§6), и два честных клиента, разошедшиеся на одном
порядке ключей или на одной длине, получают «подпись не сходится»
на каждом сообщении. §4.1 это уже подтвердил столкновением ключей:
карточка получала два ключа 1, и разбор брал первый попавшийся.

Чего в наборе нет. Нагрузка конверта (§9.1, ключ 5) для кодека
прозрачна — `any`, — и её внутренняя форма задаётся `ratatosk-proto`.
В векторе она лежит готовыми байтами, а проверяется тем, что конверт
целиком обязан совпасть до байта: разойдись кодировщики на нагрузке,
не совпал бы и конверт.

Запуск:

    python3 tools/gen_codec_vectors.py

Перезаписывает файлы в `crates/codec/tests/vectors/`. Изменение любого
из них в диффе означает, что изменилась сериализация, — а это изменение
протокола, а не рефакторинг.
"""

import sys
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "crates" / "codec" / "tests" / "vectors"

# --- кодировщик CBOR (RFC 8949 §4.2) ---------------------------------------
#
# Представление значений — обычные типы Python: int → uint, bytes → байтовая
# строка, str → текст, list → массив, dict → карта. Отрицательных чисел
# и плавающих в протоколе нет вовсе (§6), поэтому их здесь нет и в
# кодировщике: уметь кодировать то, чего протокол не возит, значило бы
# проверять не себя.


def head(major: int, value: int) -> bytes:
    """Голова элемента **минимальной** длины — §4.2.1 требует именно её."""
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    if value < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")
    raise ValueError(f"не влезает в uint64: {value}")


def enc(value) -> bytes:
    """Кодирует значение в детерминированный CBOR."""
    if isinstance(value, bool):
        # Раньше int: в Python bool — подвид int, и порядок веток важен.
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return bytes([0xF6])
    if isinstance(value, int):
        if value < 0:
            raise ValueError("отрицательных чисел протокол не возит (§6)")
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(enc(item) for item in value)
    if isinstance(value, dict):
        # §4.2.1: ключи сортируются по своему **закодированному**
        # представлению, а не по числовому значению. Для ключей 0..=23 это
        # одно и то же, и полагаться на совпадение нельзя — ровно то же
        # сказано в `canonical.rs`.
        pairs = sorted((enc(k), enc(v)) for k, v in value.items())
        for a, b in zip(pairs, pairs[1:]):
            if a[0] == b[0]:
                raise ValueError("повторяющийся ключ карты")
        return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise TypeError(f"нечем кодировать {type(value)!r}")


# --- официальные примеры RFC 8949, приложение A ----------------------------
#
# Набор нарочно разнородный: границы минимальной длины (23/24/255/256…),
# UTF-8 вне ASCII и вне BMP, вложенные массивы, карты с ключами-числами
# и ключами-строками. Расхождение хоть в одном — отказ генерировать.

RFC_8949_APPENDIX_A = [
    (0, "00"),
    (1, "01"),
    (10, "0a"),
    (23, "17"),
    (24, "1818"),
    (25, "1819"),
    (100, "1864"),
    (1000, "1903e8"),
    (1000000, "1a000f4240"),
    (1000000000000, "1b000000e8d4a51000"),
    (18446744073709551615, "1bffffffffffffffff"),
    (False, "f4"),
    (True, "f5"),
    (None, "f6"),
    (b"", "40"),
    (bytes([1, 2, 3, 4]), "4401020304"),
    ("", "60"),
    ("a", "6161"),
    ("IETF", "6449455446"),
    ('"\\', "62225c"),
    ("ü", "62c3bc"),
    ("水", "63e6b0b4"),
    ("\U00010151", "64f0908591"),
    ([], "80"),
    ([1, 2, 3], "83010203"),
    ([1, [2, 3], [4, 5]], "8301820203820405"),
    ({}, "a0"),
    ({1: 2, 3: 4}, "a201020304"),
    ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
    (["a", {"b": "c"}], "826161a161626163"),
    (
        {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
        "a56161614161626142616361436164614461656145",
    ),
]


def self_check() -> None:
    bad = []
    for value, expected in RFC_8949_APPENDIX_A:
        got = enc(value).hex()
        if got != expected:
            bad.append(f"  {value!r}: RFC {expected}, у нас {got}")
    if bad:
        print("кодировщик CBOR разошёлся с RFC 8949:", *bad, sep="\n", file=sys.stderr)
        sys.exit(1)
    print(f"  кодировщик сверен с RFC 8949: {len(RFC_8949_APPENDIX_A)} примеров")


# --- base32 по RFC 4648 без выравнивания -----------------------------------
#
# Алфавит здесь **не** тот, что у отпечатка (§3): у отпечатка свой,
# без похожих знаков. Общая реализация однажды позволила бы принять
# один за другой.

B32_RFC4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def base32_nopad(data: bytes) -> str:
    out = []
    acc = 0
    bits = 0
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(B32_RFC4648[(acc >> bits) & 0x1F])
    if bits:
        out.append(B32_RFC4648[(acc << (5 - bits)) & 0x1F])
    return "".join(out)


# --- номера ключей, дословно из crates/codec/src ---------------------------
#
# Переписаны руками, а не прочитаны из кода: вектор обязан знать номера
# **сам**, иначе перенумеруй поля — и вектор перенумеруется вместе с ними,
# смолчав о сломанной совместимости.

# Имена повторяют имена из Rust с приставкой по структуре: по этой паре
# «имя — число» метелка `codec_keys_covered` и сличает два списка.
KEY_PROTOCOL_VERSION = 1
PROTOCOL_VERSION_VALUE = 0

# ContactCard (§4.1 со сдвигом на 2..10 — см. card.rs)
CARD_IK = 2
CARD_SK = 3
CARD_ONION = 4
CARD_CHATMAIL = 5
CARD_DISPLAY_NAME = 6
CARD_VERSION = 7
CARD_YGG = 8
CARD_NOSTR = 9
CARD_NOSTR_RELAYS = 10

# Envelope (§9.1)
ENV_MSG_ID = 2
ENV_HLC = 3
ENV_PAYLOAD_TYPE = 4
ENV_PAYLOAD = 5
ENV_GROUP_ID = 6
ENV_CAUSAL_REFS = 7
ENV_FRAGMENT = 8
HLC_WALL = 1
HLC_LOGICAL = 2
FRAG_UID = 1
FRAG_INDEX = 2
FRAG_TOTAL = 3

MAX_CARD_RELAYS = 3

NONE = "-"


def card_bytes(ik, sk, onion, chatmail, display_name, version, ygg, nostr, relays) -> bytes:
    fields = {
        KEY_PROTOCOL_VERSION: PROTOCOL_VERSION_VALUE,
        CARD_IK: ik,
        CARD_SK: sk,
        CARD_ONION: onion,
        CARD_CHATMAIL: chatmail,
        CARD_DISPLAY_NAME: display_name,
        CARD_VERSION: version,
    }
    # Пустое поле не пишется вовсе: карточка без меша, без nostr и без реле
    # обязана кодироваться теми же байтами, что и до 0.2.
    if ygg:
        fields[CARD_YGG] = ygg
    if nostr:
        fields[CARD_NOSTR] = nostr
    if relays:
        fields[CARD_NOSTR_RELAYS] = list(relays[:MAX_CARD_RELAYS])
    return enc(fields)


def envelope_bytes(msg_id, wall, logical, payload_type, payload_raw, group_id, refs, fragment):
    """Собирает конверт. Нагрузка подставляется **готовыми байтами**.

    Нагрузка для конверта — `any` (§9.1), её форму задаёт не кодек;
    подставляя байты, мы не кодируем её второй раз и не делаем вид,
    что знаем её схему.
    """
    fields = {
        KEY_PROTOCOL_VERSION: PROTOCOL_VERSION_VALUE,
        ENV_MSG_ID: msg_id,
        ENV_HLC: {HLC_WALL: wall, HLC_LOGICAL: logical},
        ENV_PAYLOAD_TYPE: payload_type,
    }
    if group_id is not None:
        fields[ENV_GROUP_ID] = group_id
    if refs:
        fields[ENV_CAUSAL_REFS] = list(refs)
    if fragment is not None:
        uid, index, total = fragment
        fields[ENV_FRAGMENT] = {FRAG_UID: uid, FRAG_INDEX: index, FRAG_TOTAL: total}

    # Нагрузка вставляется в уже отсортированную карту руками: её байты
    # даны готовыми, а кодировщик умеет только значения.
    pairs = sorted((enc(k), enc(v)) for k, v in fields.items())
    pairs.append((enc(ENV_PAYLOAD), payload_raw))
    pairs.sort()
    return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


HEADER = """\
# Тест-векторы Ratatosk v0.1 — {title} ({spec})
#
# СГЕНЕРИРОВАНО tools/gen_codec_vectors.py НЕЗАВИСИМОЙ РЕАЛИЗАЦИЕЙ.
# Править руками нельзя. Изменение строки в диффе = изменение протокола.
#
# Формат: поля разделены ' | ', строки с '#' — комментарии,
# '{none}' — пусто или отсутствует.
# {columns}
"""


def write(name: str, title: str, spec: str, columns: str, rows) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    with path.open("w", encoding="utf-8") as f:
        f.write(HEADER.format(title=title, spec=spec, columns=columns, none=NONE))
        for row in rows:
            if isinstance(row, str):
                f.write(f"\n# {row}\n")
                continue
            f.write(" | ".join(row) + "\n")
    count = sum(1 for r in rows if not isinstance(r, str))
    print(f"  {path.relative_to(OUT_DIR.parents[3])}: {count} векторов")


# --- входные данные --------------------------------------------------------
#
# Нарочито синтетические и узнаваемые: увидев 0101…01 в отладке, сразу
# понятно, что это вектор, а не боевой ключ.

IK = bytes([0x01] * 32)
SK = bytes([0x02] * 32)
YGG = bytes([0x11] * 32)
NOSTR = bytes([0x5A] * 32)
ONION = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
MAIL = "a7f3k9@nine.example"
RELAYS = ["wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band"]


def gen_contact_card():
    rows = []

    def row(name, *, onion=ONION, chatmail=MAIL, display="Алиса", version=1,
            ygg=b"", nostr=b"", relays=()):
        raw = card_bytes(IK, SK, onion, chatmail, display, version, ygg, nostr, relays)
        rows.append(
            (
                name,
                IK.hex(),
                SK.hex(),
                onion or NONE,
                chatmail or NONE,
                display or NONE,
                str(version),
                ygg.hex() if ygg else NONE,
                nostr.hex() if nostr else NONE,
                ",".join(relays) if relays else NONE,
                raw.hex(),
                "ratatosk:v0:" + base32_nopad(raw),
            )
        )

    rows.append("карточка v0.1: ни меша, ни nostr, ни реле")
    row("минимальная")
    row("имя вне ASCII", display="Алиса Иванова")
    row("имя вне BMP", display="Алиса 🙂")
    row("имя пустое", display="")

    rows.append("необязательные ключи — по одному и все вместе")
    row("только меш", ygg=YGG)
    row("только nostr", nostr=NOSTR)
    row("меш и nostr: ключи одной длины в разных полях", ygg=YGG, nostr=NOSTR)
    row("всё и три реле", ygg=YGG, nostr=NOSTR, relays=RELAYS)
    row("четвёртое реле не объявляется", relays=RELAYS + ["wss://relay4.example"])

    rows.append("края адресов: ступени у человека может не быть вовсе")
    row("без onion", onion="")
    row("без почты", chatmail="")

    rows.append("границы минимальной длины у версии карточки (§4.3)")
    row("версия 0", version=0)
    row("версия 23 — последняя в голове", version=23)
    row("версия 24 — первая с байтом длины", version=24)
    row("версия 255", version=255)
    row("версия 256", version=256)
    row("версия 65535", version=65535)
    row("версия 65536", version=65536)
    row("версия u64::MAX", version=18446744073709551615)

    write(
        "contact_card.txt",
        "контакт-карточка",
        "§4.1, §6",
        "имя | ik | sk | onion | почта | имя_показа | версия | ygg | nostr "
        "| реле | байты | uri",
        rows,
    )


def gen_envelope():
    rows = []

    def row(name, *, msg_id=bytes([0x07] * 16), wall=1_700_000_000_000, logical=3,
            payload_type=1, payload=b"", group_id=None, refs=(), fragment=None):
        raw = envelope_bytes(
            msg_id, wall, logical, payload_type, payload, group_id, refs, fragment
        )
        rows.append(
            (
                name,
                msg_id.hex(),
                str(wall),
                str(logical),
                str(payload_type),
                payload.hex(),
                group_id.hex() if group_id is not None else NONE,
                ",".join(r.hex() for r in refs) if refs else NONE,
                (
                    f"{fragment[0].hex()}:{fragment[1]}:{fragment[2]}"
                    if fragment is not None
                    else NONE
                ),
                raw.hex(),
            )
        )

    text = enc("привет")

    rows.append("минимальный конверт: только обязательные ключи")
    row("текст", payload=text)
    row("нагрузка — пусто", payload=enc(b""))
    row("нагрузка — null", payload=enc(None))
    row("нагрузка — пустая карта", payload=enc({}))
    row("нагрузка — пустой массив", payload=enc([]))

    rows.append("нагрузка, которой нужна сортировка ключей и длины")
    row("карта с ключами 1, 2, 10", payload=enc({1: "а", 10: "б", 2: "в"}), payload_type=2)
    row("байты длиной 24", payload=enc(bytes(range(24))), payload_type=3)
    row("байты длиной 300", payload=enc(bytes([0xAB] * 300)), payload_type=3)
    row("вложенные массивы", payload=enc([1, [2, 3], {"a": b"\x01"}]), payload_type=22)

    rows.append("часы §9.1: границы минимальной длины у обеих половин")
    row("часы в нуле", wall=0, logical=0, payload=text)
    row("logical 23", logical=23, payload=text)
    row("logical 24", logical=24, payload=text)
    row("logical u32::MAX", logical=4294967295, payload=text)
    row("wall u64::MAX", wall=18446744073709551615, payload=text)

    rows.append("необязательные ключи: группа, ссылки, фрагмент")
    row("группа", group_id=bytes([0xAA] * 16), payload_type=22, payload=enc(b"\x01\x02"))
    row("одна причинная ссылка", refs=[bytes([0x01] * 16)], payload=text)
    row(
        "две ссылки и группа",
        group_id=bytes([0xAA] * 16),
        refs=[bytes([0x01] * 16), bytes([0x02] * 16)],
        payload=text,
    )
    row(
        "фрагмент: первый из четырёх",
        payload_type=24,
        payload=enc(bytes([0xCD] * 8)),
        fragment=(bytes([0x09] * 16), 0, 4),
    )
    row(
        "фрагмент: последний из 4096 (§9.3, предел)",
        payload_type=24,
        payload=enc(bytes([0xCD] * 8)),
        fragment=(bytes([0x09] * 16), 4095, 4096),
    )
    row(
        "всё сразу",
        group_id=bytes([0xAA] * 16),
        refs=[bytes([0x01] * 16), bytes([0x02] * 16)],
        fragment=(bytes([0x09] * 16), 1, 2),
        payload_type=22,
        payload=enc({1: b"\xff", 2: 1}),
    )

    rows.append("тип нагрузки: края нумерации и чужая версия")
    row("наибольший известный код (32)", payload_type=32, payload=text)
    row("код из будущей версии", payload_type=999, payload=text)

    write(
        "envelope.txt",
        "конверт сообщения",
        "§9.1, §6",
        "имя | msg_id | часы_wall | часы_logical | тип | нагрузка_байты "
        "| group_id | ссылки | фрагмент | байты",
        rows,
    )


def gen_not_canonical():
    """Байты, которые разбор обязан **отвергнуть** (§6).

    Половина набора, без которой он неполон: «принимает канонические»
    и «отвергает прочие» — два разных обещания, и клиент, который
    принял неканоническое, посчитал бы подпись не над теми байтами,
    что подписывал отправитель.
    """
    rows = []

    def ok_card():
        return card_bytes(IK, SK, ONION, MAIL, "Алиса", 1, b"", b"", ())

    def row(name, raw: bytes, why: str):
        rows.append((name, raw.hex(), why))

    # Карта с ключами не по возрастанию — собирается вручную, потому что
    # кодировщик выше такого не построит.
    def map_verbatim(pairs):
        return head(5, len(pairs)) + b"".join(enc(k) + enc(v) for k, v in pairs)

    rows.append("порядок и единственность ключей (RFC 8949 §4.2.1)")
    row(
        "ключи не по возрастанию",
        map_verbatim([(2, 0), (1, 0)]),
        "ключ 2 раньше ключа 1",
    )
    row(
        "повторяющийся ключ",
        map_verbatim([(1, 0), (1, 1)]),
        "одна реализация взяла бы первое значение, другая второе",
    )
    row(
        "карточка с переставленными ключами",
        # Та же карточка, что в `contact_card.txt`, только ключ версии
        # протокола уехал в конец.
        head(5, 7)
        + enc(CARD_IK)
        + enc(IK)
        + enc(CARD_SK)
        + enc(SK)
        + enc(CARD_ONION)
        + enc(ONION)
        + enc(CARD_CHATMAIL)
        + enc(MAIL)
        + enc(CARD_DISPLAY_NAME)
        + enc("Алиса")
        + enc(CARD_VERSION)
        + enc(1)
        + enc(KEY_PROTOCOL_VERSION)
        + enc(PROTOCOL_VERSION_VALUE),
        "поля на месте, порядок чужой — подпись считалась бы не над теми байтами",
    )

    rows.append("неопределённая длина (§6 запрещает)")
    row("карта неопределённой длины", bytes([0xBF, 0x01, 0x00, 0xFF]), "0xbf вместо 0xa1")
    row("массив неопределённой длины", bytes([0x9F, 0x01, 0xFF]), "0x9f вместо 0x81")
    row(
        "текст по кускам",
        bytes([0x7F, 0x62]) + "пр".encode("utf-8")[:2] + bytes([0xFF]),
        "0x7f: текст, собранный из отрывков",
    )
    row(
        "байтовая строка по кускам",
        bytes([0x5F, 0x42, 0x01, 0x02, 0xFF]),
        "0x5f: строка, собранная из отрывков",
    )

    rows.append("неминимальная длина (RFC 8949 §4.2.1)")
    row("целое 0 в двух байтах", bytes([0x18, 0x00]), "0x1800 вместо 0x00")
    row("целое 23 в двух байтах", bytes([0x18, 0x17]), "0x1817 вместо 0x17")
    row("целое 24 в трёх байтах", bytes([0x19, 0x00, 0x18]), "0x190018 вместо 0x1818")
    row("пустая байтовая строка с байтом длины", bytes([0x58, 0x00]), "0x5800 вместо 0x40")
    row(
        "ключ карты с неминимальной головой",
        bytes([0xA1, 0x18, 0x01, 0x00]),
        "ключ 1 закодирован как 0x1801",
    )

    rows.append("хвост после структуры")
    row("карточка и лишний байт", ok_card() + bytes([0x00]), "за концом структуры ещё байт")
    row(
        "карточка и целая вторая карточка",
        ok_card() + ok_card(),
        "склеенные кадры — классический способ подсунуть второе содержимое",
    )

    write(
        "not_canonical.txt",
        "байты, которые разбор обязан отвергнуть",
        "§6",
        "имя | байты | почему",
        rows,
    )


def main():
    print("сверка кодировщика:")
    self_check()
    print("генерация:")
    gen_contact_card()
    gen_envelope()
    gen_not_canonical()


if __name__ == "__main__":
    main()
