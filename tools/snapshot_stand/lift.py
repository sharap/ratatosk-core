"""Стенд дискового формата снимка терминала — собирается из дерева.

`cargo` в этом дереве не запускается, а дисковый формат ошибается молча
и навсегда: испорченный снимок не падает, он просто отдаёт не то. Поэтому
две функции, которые этот формат и составляют, прогоняются под `rustc`
отдельно — с настоящим по поведению кодеком (сортировка ключей, отказ
на повторах) и без печати: проверяется формат, а не AEAD.

**Функции поднимаются дословно из дерева, а не переписываются здесь.**
Переписанные, они проверяли бы переписанное — и разошлись бы с деревом
на первой же правке, оставшись зелёными.

    python3 tools/snapshot_stand/lift.py && rustc --edition 2021 \\
        /tmp/snapshot_stand/main.rs -o /tmp/snapshot_stand/stand \\
        && /tmp/snapshot_stand/stand

Стенд обязан ловить выдуманную поломку: снимите в `restore` старшинство
живого канала (`if self.addr_dirty { return Ok(()) }`) — он даст две
находки. Метелка, которая не бьётся на подсунутой поломке, зелена
вхолостую, и проверять это стоит трёх минут.
"""

import pathlib
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / "crates" / "core" / "src" / "companion.rs"
OUT = pathlib.Path("/tmp/snapshot_stand")

# Что поднимаем и по каким границам. Начало — сигнатура целиком, конец —
# закрывающая скобка метода на своём отступе: тела здесь не вложенные,
# и счёта скобок для них не нужно.
LIFTED = [
    "    fn snapshot_value(&self) -> Value {",
    "    pub fn restore(&mut self, sealed: &[u8]) -> Result<(), CacheError> {",
]
END = "\n    }\n"

# Чем заменяется то, чего в стенде нет. Печать снимается целиком: ключ
# и AAD выводятся из личности, которой здесь не заведено, а проверяется
# не они.
REPLACEMENTS = [
    (
        """        let key = self.cache_key();
        let bytes = ratatosk_crypto::storage_key::open_field(&key, &self.cache_aad(), sealed)
            .map_err(|_| CacheError::Sealed)?;
        let value = canonical::decode(&bytes)?;""",
        """        let value = canonical::decode(sealed)?;""",
    ),
    ("ratatosk_proto::ygg::KEY_LEN", "YGG_KEY_LEN"),
    ("companion::MAX_PEER_LEN", "MAX_PEER_LEN"),
    ("companion::MAX_YGG_PEERS", "MAX_YGG_PEERS"),
]


def lift(source: str, start: str) -> str:
    """Достаёт одну функцию от сигнатуры до закрывающей скобки метода."""
    if start not in source:
        raise SystemExit(
            f"в {SOURCE.name} не нашлось начала:\n  {start}\n"
            "Сигнатура изменилась — поправьте LIFTED, а не стенд."
        )
    begin = source.index(start)
    end = source.index(END, begin)
    return source[begin : end + len(END)]


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    body = "\n".join(lift(source, start) for start in LIFTED)
    for was, now in REPLACEMENTS:
        if was not in body:
            raise SystemExit(
                f"в поднятом нет того, что подменяется:\n  {was[:60]}…\n"
                "Дерево изменилось — поправьте REPLACEMENTS."
            )
        body = body.replace(was, now)

    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copy(HERE / "stub.rs", OUT / "stub.rs")
    main_rs = (
        (HERE / "head.rs").read_text(encoding="utf-8")
        + body
        + "}\n"
        + (HERE / "checks.rs").read_text(encoding="utf-8")
    )
    (OUT / "main.rs").write_text(main_rs, encoding="utf-8")
    print(f"собрано: {OUT / 'main.rs'}")
    print(f"дальше:  rustc --edition 2021 {OUT / 'main.rs'} -o {OUT / 'stand'} && {OUT / 'stand'}")


if __name__ == "__main__":
    sys.exit(main())
