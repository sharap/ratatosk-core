#!/usr/bin/env python3
"""Метелка: приватный помощник, забредший в экспортируемый блок UniFFI.

`#[uniffi::export]` берёт из блока **все** методы, не разбирая, какие из них
`pub`. Приватный помощник, возвращающий тип ядра или что-нибудь вроде
`(Vec<String>, bool)`, требует от моста `LowerReturn` — и весь блок
перестаёт собираться, причём сообщением про типаж, а не про место.

Правило поэтому простое и без исключений: **в блоке `#[uniffi::export] impl`
каждый метод обязан быть `pub`.** Помощникам место в обычном блоке рядом.

Компилятор это ловит и сам. Метелка существует затем, что ловит он это
ценой полной сборки чужого дерева — минуты против секунды, — а правило
уже стоило одного такого круга.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ROOT = ROOT_DIR / "crates"

# `pub`, `pub(crate)`, а также `async` между ними и `fn`.
PUBLIC = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?(?:async\s+)?(?:unsafe\s+)?$")


def block_body(src: str, start: int) -> tuple[str, int]:
    """Тело блока от его первой `{` и смещение этой скобки."""
    depth, j = 0, start
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j], start
        j += 1
    return src[start:], start


bad = []
blocks = 0
methods = 0
for path in sorted(ROOT.glob("*/src/**/*.rs")):
    src = path.read_text(encoding="utf-8")
    for m in re.finditer(r"#\[uniffi::export[^\]]*\]\s*\nimpl[^{]*\{", src):
        blocks += 1
        body, at = block_body(src, m.end() - 1)
        depth = 0
        for k, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            # Метод блока — это `fn` ровно на первом уровне вложенности.
            # Глубже лежат тела, и тамошние замыкания нас не касаются.
            elif depth == 1 and body.startswith("fn ", k):
                methods += 1
                if not PUBLIC.search(body[max(0, k - 40) : k]):
                    name = body[k + 3 :].split("(")[0].strip()
                    line = src[: at + k].count("\n") + 1
                    bad.append((path, line, name))

for path, line, name in bad:
    rel = path.relative_to(ROOT.parent)
    print(
        f"{rel}:{line}: метод `{name}` в блоке `#[uniffi::export]` не публичный. "
        "Мост возьмёт и его — перенесите помощника в обычный блок `impl`"
    )

print(f"экспортируемых блоков: {blocks}; методов в них: {methods}")
print("чисто" if not bad else f"НАХОДОК: {len(bad)}")
sys.exit(1 if bad else 0)
