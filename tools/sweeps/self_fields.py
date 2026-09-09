#!/usr/bin/env python3
"""Метелка: `self.имя` обязано быть полем этой записи или её методом.

Заведена по `no field 'handle' on type '&RatatoskClient'`: у клиента FFI
ручка драйвера лежит на этаж ниже (`self.opened.handle`), и написанное
по памяти `self.handle` компилятор отверг — но отверг у Никиты, кругом
сборки позже. Ошибка ровно того рода, ради которого метелки и заводятся:
её видно в одном файле, глазами, без всякого выведения типов.

Правило: внутри `impl Имя` (и `impl Трейт for Имя`) каждое `self.поле`
обязано быть либо объявленным полем `struct Имя`, либо её методом —
из любого `impl` этого же имени, включая реализации трейтов.

Смотрит только на записи, объявленные в самом дереве, и только на
`self.` с обычным именем следом. Пропускается вслух:

* `self.0`, `self.1` — кортежные записи здесь не разбираются;
* записи с одинаковыми именами в разных ящиках — какая из них тут, без
  разбора путей не сказать, а гадать хуже, чем промолчать;
* всё, что зовётся со скобками, — это метод, и метод может прийти
  из трейта, объявленного не здесь.
"""
import re
import sys
import pathlib
from collections import defaultdict

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"

SOURCES = sorted(ROOT.glob("*/src/**/*.rs")) + sorted(ROOT.glob("*/tests/**/*.rs"))
TEXT = {p: p.read_text(encoding="utf-8") for p in SOURCES}


def braced(text, at):
    depth, i = 0, at
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[at: i + 1]
        i += 1
    return text[at:]


# --- Что объявлено ------------------------------------------------------

fields = defaultdict(set)      # имя записи -> её поля
declared = defaultdict(int)    # имя записи -> сколько раз объявлена
methods = defaultdict(set)     # имя записи -> методы из всех её `impl`

STRUCT = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Z]\w*)(?:<[^>]*>)?\s*\{", re.M)
for path, src in TEXT.items():
    for m in STRUCT.finditer(src):
        name = m.group(1)
        declared[name] += 1
        body = braced(src, src.index("{", m.end() - 1))
        for f in re.finditer(r"^\s{4}(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:", body, re.M):
            fields[name].add(f.group(1))

# `impl … Имя …{` — берётся **последнее** заглавное слово до фигурной скобки:
# у `impl<S: Store> Engine<S>` это `Engine`, у `impl Runner for LanRunner` —
# `LanRunner`. Заодно так отсеиваются `impl` для чужих типов с путём.
IMPL = re.compile(r"^impl\b([^{]*)\{", re.M)


def impl_target(head):
    head = re.sub(r"<[^<>]*>", " ", head)
    head = re.sub(r"<[^<>]*>", " ", head)
    parts = re.findall(r"[A-Za-z_]\w*", head)
    return parts[-1] if parts else None


impls = []  # (path, target, тело)
for path, src in TEXT.items():
    for m in IMPL.finditer(src):
        target = impl_target(m.group(1))
        if not target:
            continue
        body = braced(src, m.end() - 1)
        impls.append((path, target, body, src[: m.start()].count("\n") + 1))
        for f in re.finditer(r"\bfn\s+(\w+)", body):
            methods[target].add(f.group(1))

# --- Проверка -----------------------------------------------------------

bad = []
checked = 0
skipped_dup = set()
USE = re.compile(r"\bself\s*\.\s*(\w+)\s*(\(?)")
for path, target, body, line_no in impls:
    if declared.get(target, 0) != 1:
        if target in declared:
            skipped_dup.add(target)
        continue
    known = fields[target] | methods[target]
    for m in USE.finditer(body):
        name, call = m.group(1), m.group(2)
        if call == "(":
            continue  # метод: мог прийти из трейта, объявленного не здесь
        if name.isdigit():
            continue
        checked += 1
        if name not in known:
            at = line_no + body[: m.start()].count("\n")
            bad.append((path, at, target, name))

for path, at, target, name in sorted(set(bad)):
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}:{at}: у `{target}` нет поля `{name}` — а `self.{name}` написано")

if skipped_dup:
    print("пропущено (одноимённых записей несколько): " + ", ".join(sorted(skipped_dup)))
print(f"обращений проверено: {checked}")
print("чисто" if not bad else f"находок: {len(set(bad))}")
sys.exit(1 if bad else 0)
