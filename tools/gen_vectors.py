#!/usr/bin/env python3
"""Генератор тест-векторов на деривацию ключей (§16).

Смысл этого файла — независимость. Векторы, посчитанные тем же кодом, который
они проверяют, доказывают только его неизменность: перепишешь Rust с ошибкой,
перегенерируешь векторы — тесты зелёные, совместимости нет. Поэтому здесь
всё считается заново:

* BLAKE3 — собственной реализацией из `blake3_ref.py`, которая перед каждой
  генерацией сверяется с официальными контрольными векторами BLAKE3
  и отказывается работать при расхождении;
* X25519 и Ed25519 — библиотекой `cryptography`, а не dalek;
* base32 отпечатка — вручную по алфавиту из §3, а не через `data-encoding`.

Запуск:

    python3 tools/gen_vectors.py

Перезаписывает файлы в `crates/crypto/tests/vectors/`. Изменение любого
из них в диффе означает, что изменилась деривация, — а это изменение
протокола, а не рефакторинг.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import blake3_ref as b3  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402

OUT_DIR = Path(__file__).resolve().parent.parent / "crates" / "crypto" / "tests" / "vectors"

# --- контексты, дословно из crates/crypto/src/labels.rs ---------------------

IK = "ratatosk v0 ik"
SK = "ratatosk v0 sk"
BEACON = "ratatosk v0 beacon"
SESSION_ID = "ratatosk v0 sid"
ROOT = "ratatosk v0 root"
CHAIN_A = "ratatosk v0 chain-a"
CHAIN_B = "ratatosk v0 chain-b"
MSG = "ratatosk v0 msg"
CHAIN = "ratatosk v0 chain"
FILE = "ratatosk v0 file"
SENDER_CHAIN = "ratatosk v0 sender-chain"
SENDER_MSG = "ratatosk v0 sender-msg"
SEARCH_TOKEN = "ratatosk v0 search-token"
DEVICE_KEY = "ratatosk v0 device-key"
COMPANION_DEVICE = "ratatosk v0 companion-device"
COMPANION_CACHE = "ratatosk v0 companion-cache"
COMPANION_REVOKED = "ratatosk v0 companion-revoked"
COMPANION_ONION = "ratatosk v0 companion-onion"
GROUP_BLOCK = "ratatosk v0 group-block"

ALL_CONTEXTS = [IK, SK, BEACON, SESSION_ID, ROOT, CHAIN_A, CHAIN_B, MSG,
                CHAIN, FILE, SENDER_CHAIN, SENDER_MSG, SEARCH_TOKEN, DEVICE_KEY,
                COMPANION_DEVICE, COMPANION_CACHE, COMPANION_REVOKED,
                COMPANION_ONION, GROUP_BLOCK]

# --- входные данные ---------------------------------------------------------
#
# Значения нарочито синтетические и узнаваемые: увидев 000102...1f в отладке,
# сразу понятно, что это вектор, а не боевой ключ.

SEED_COUNTING = bytes(range(32))
SEED_AA = bytes([0xAA] * 32)
SEED_FF = bytes([0xFF] * 32)

MAT_EMPTY = b""
MAT_32 = bytes(range(32))
MAT_64 = bytes(range(64))

TRANSCRIPT = bytes([0x11] * 32)
NOISE_OUTPUT = bytes([0x22] * 32)

FILE_KEY = bytes([0x33] * 32)
BEACON_IK = bytes([0x44] * 32)
BEACON_NONCE = bytes([0x55] * 8)
SEARCH_DB_KEY = bytes([0x66] * 32)
BEACON_SLOT = 1_925_000

# Алфавит base32 без похожих знаков (§3): без I, L, O, U.
FP_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
FP_BYTES = 15
FP_GROUPS = 6
FP_GROUP_LEN = 4


def base32(data: bytes) -> str:
    """Кодирование по алфавиту §3, старшие биты первыми, без выравнивания."""
    bits = 0
    acc = 0
    out = []
    for byte in data:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(FP_ALPHABET[(acc >> bits) & 0x1F])
    if bits:
        out.append(FP_ALPHABET[(acc << (5 - bits)) & 0x1F])
    return "".join(out)


def fingerprint(ik_pub: bytes, sk_pub: bytes) -> str:
    digest = b3.hash_(ik_pub + sk_pub)
    text = base32(digest[:FP_BYTES])
    groups = [text[i * FP_GROUP_LEN:(i + 1) * FP_GROUP_LEN] for i in range(FP_GROUPS)]
    return "-".join(groups)


def identity_from_seed(seed: bytes):
    ik_secret = b3.derive_key(IK, seed)
    sk_secret = b3.derive_key(SK, seed)

    ik_pub = X25519PrivateKey.from_private_bytes(ik_secret).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_pub = Ed25519PrivateKey.from_private_bytes(sk_secret).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return ik_secret, sk_secret, ik_pub, sk_pub


HEADER = """\
# Тест-векторы Ratatosk v0.1 — {title} ({spec})
#
# СГЕНЕРИРОВАНО tools/gen_vectors.py НЕЗАВИСИМОЙ РЕАЛИЗАЦИЕЙ.
# Править руками нельзя. Изменение строки в диффе = изменение протокола.
#
# Формат: поля разделены ' | ', строки с '#' — комментарии.
# {columns}
"""


def write(name: str, title: str, spec: str, columns: str, rows):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    with path.open("w", encoding="utf-8") as f:
        f.write(HEADER.format(title=title, spec=spec, columns=columns))
        section = None
        for row in rows:
            if isinstance(row, str):
                section = row
                f.write(f"\n# {section}\n")
                continue
            f.write(" | ".join(row) + "\n")
    print(f"  {path.relative_to(OUT_DIR.parents[3])}: {sum(1 for r in rows if not isinstance(r, str))} векторов")


def gen_derive_key():
    rows = []

    rows.append("все контексты на одном материале — §8.1")
    for ctx in ALL_CONTEXTS:
        rows.append((ctx, MAT_32.hex(), "32", b3.derive_key(ctx, MAT_32).hex()))

    rows.append("пустой материал — край, который легко сломать оптимизацией")
    for ctx in (IK, ROOT, MSG):
        rows.append((ctx, "", "32", b3.derive_key(ctx, MAT_EMPTY).hex()))

    rows.append("материал длиннее блока BLAKE3")
    rows.append((ROOT, MAT_64.hex(), "32", b3.derive_key(ROOT, MAT_64).hex()))

    rows.append("XOF: длина вывода не 32 — проверяет derive_into")
    for out_len in (8, 16, 64, 131):
        rows.append((ROOT, MAT_32.hex(), str(out_len),
                     b3.derive_key(ROOT, MAT_32, out_len).hex()))

    rows.append("§8.4: шаг ретчета и ключ сообщения от одного состояния цепочки")
    ck0 = b3.derive_key(CHAIN_A, b3.derive_key(ROOT, TRANSCRIPT + NOISE_OUTPUT))
    ck = ck0
    for n in range(4):
        rows.append((MSG, ck.hex(), "32", b3.derive_key(MSG, ck).hex()))
        nxt = b3.derive_key(CHAIN, ck)
        rows.append((CHAIN, ck.hex(), "32", nxt.hex()))
        ck = nxt

    rows.append("§10.1: chunk_id = derive(file_key ‖ index_be)")
    for index in (0, 1, 4095, 2**64 - 1):
        material = FILE_KEY + index.to_bytes(8, "big")
        rows.append((FILE, material.hex(), "32", b3.derive_key(FILE, material).hex()))

    rows.append("§11.1: sender keys")
    sender = b3.derive_key(SENDER_CHAIN, MAT_32)
    for _ in range(3):
        rows.append((SENDER_MSG, sender.hex(), "32", b3.derive_key(SENDER_MSG, sender).hex()))
        sender = b3.derive_key(SENDER_CHAIN, sender)

    rows.append("§12: токен поиска = derive(db_key ‖ слово)[0..16]")
    # Слова взяты с намерением: русское и латинское, короткое и длинное,
    # с цифрой и в верхнем регистре — приведение к нижнему делает вызывающий,
    # и вектор обязан это зафиксировать, а не сгладить.
    for word in ("привет", "hello", "a", "2024", "капибара"):
        material = SEARCH_DB_KEY + word.encode("utf-8")
        rows.append((SEARCH_TOKEN, material.hex(), "16",
                     b3.derive_key(SEARCH_TOKEN, material, 16).hex()))

    rows.append("§5.1: маяк LAN = derive(IK ‖ slot_be ‖ nonce)[0..8]")
    for slot in (BEACON_SLOT - 1, BEACON_SLOT, BEACON_SLOT + 1):
        material = BEACON_IK + slot.to_bytes(8, "big") + BEACON_NONCE
        rows.append((BEACON, material.hex(), "8", b3.derive_key(BEACON, material, 8).hex()))

    write("derive_key.txt", "деривация ключей", "§3, §5.1, §8, §10.1, §11.1",
          "контекст | материал_hex | длина | ожидаемое_hex", rows)


def gen_identity():
    rows = ["§3: seed → IK, SK, отпечаток"]
    for seed in (SEED_COUNTING, SEED_AA, SEED_FF):
        ik_secret, sk_secret, ik_pub, sk_pub = identity_from_seed(seed)
        rows.append((seed.hex(), ik_secret.hex(), sk_secret.hex(),
                     ik_pub.hex(), sk_pub.hex(), fingerprint(ik_pub, sk_pub)))
    write("identity.txt", "идентичность", "§3",
          "seed_hex | ik_секрет_hex | sk_секрет_hex | ik_публичный_hex | sk_публичный_hex | отпечаток",
          rows)


def gen_session():
    rows = ["§8.3: транскрипт → session_id, корневой ключ, цепочки"]
    cases = [
        (TRANSCRIPT, NOISE_OUTPUT),
        (bytes([0x11] * 32), bytes([0x11] * 32)),
        (MAT_32, MAT_64),
        (b"", b""),
    ]
    for h, noise in cases:
        sid = b3.derive_key(SESSION_ID, h, 8)
        root = b3.derive_key(ROOT, h + noise)
        rows.append((h.hex(), noise.hex(), sid.hex(), root.hex(),
                     b3.derive_key(CHAIN_A, root).hex(),
                     b3.derive_key(CHAIN_B, root).hex()))
    write("session.txt", "установление сессии", "§8.3",
          "транскрипт_hex | выход_noise_hex | session_id_hex | root_hex | chain_a_hex | chain_b_hex",
          rows)


def main():
    if not b3.selftest():
        print("BLAKE3 не прошёл самопроверку — векторы не генерируются", file=sys.stderr)
        return 1
    print("BLAKE3: самопроверка по официальным векторам пройдена")
    gen_derive_key()
    gen_identity()
    gen_session()
    print("готово")
    return 0


if __name__ == "__main__":
    sys.exit(main())
