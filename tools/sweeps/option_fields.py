#!/usr/bin/env python3
"""Метелка: полю `Option<…>` не кладут голое значение.

Заведена по `expected Option<Vec<u8>>, found Vec<_>` — в стенде симуляции
осталось `ygg: Vec::new()` с тех пор, когда поле было голым вектором.
Ошибка глупая и ловится компилятором мгновенно — но компилятор здесь
не запускается, и ловил её человек за другим экраном кругом сборки позже.

Разница между `None` и `Some(vec![])` в этом поле не косметическая:
первое значит «про меш ничего не говорю» (телефон, где ключ живёт
настройкой), второе — «меша нет» (стенд, запущенный без ключа). Голый
вектор смешивал бы их в одно, и телефон стирал бы себе ключ при каждом
запуске. Оттого поле и стало `Option`, оттого и метелка.

Правило узкое **нарочно**: полю, объявленному `Option<…>`, кладётся либо
`None`, либо `Some(…)`, либо выражение — то есть что угодно, кроме
короткого списка заведомо голых значений (`Vec::new()`, `vec![]`,
`String::new()`, `0`, `false`, `true`, строка в кавычках). Шире брать
нельзя: `foo()` и `x` — законные значения, и отличить их от голого
`bar()` без разбора типов не выйдет. Узкое правило ловит ровно то,
что случается на деле — переживший смену типа старый литерал.
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

BARE = re.compile(
    r"""^(?:
        Vec::new\(\) | vec!\[\s*\] | String::new\(\) | String::from\(.*\)
        | \d+ | false | true | "[^"]*"(?:\.to_owned\(\)|\.to_string\(\))?
    )$""",
    re.X,
)


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


# --- Какие поля объявлены `Option` --------------------------------------

optional = defaultdict(set)
declared = defaultdict(int)
STRUCT = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Z]\w*)(?:<[^>]*>)?\s*\{", re.M)
for path, src in TEXT.items():
    for m in STRUCT.finditer(src):
        name = m.group(1)
        declared[name] += 1
        body = braced(src, src.index("{", m.end() - 1))
        for f in re.finditer(
            r"^\s{4}(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*Option\s*<", body, re.M
        ):
            optional[name].add(f.group(1))

watched = {n for n, f in optional.items() if f and declared[n] == 1}

# --- Что кладут ---------------------------------------------------------


def top_pairs(body):
    """Пары `поле: значение` на верхнем уровне тела записи."""
    # Комментарии снимаются **до** разреза по запятой, а не после: в русском
    # комментарии запятых больше, чем в коде, и разрез уводил начало поля
    # в середину фразы. Ошибка не теоретическая — на ней сломалась
    # родственная метелка `family_fields`, объявив неполной запись,
    # где было названо всё.
    inner = re.sub(r"//[^\n]*", "", body[1:-1])
    depth, start, out = 0, 0, []
    for i, c in enumerate(inner):
        if c in "{([<":
            depth += 1
        elif c in "})]>":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(inner[start:i])
            start = i + 1
    out.append(inner[start:])
    for chunk in out:
        text = " ".join(l.strip() for l in chunk.splitlines()).strip()
        m = re.match(r"^(\w+)\s*:\s*(.+)$", text, re.S)
        if m:
            yield m.group(1), m.group(2).strip()


bad = []
checked = 0
for path, src in TEXT.items():
    for name in watched:
        for m in re.finditer(r"\b" + name + r"\s*\{", src):
            # Объявление, а не сборка.
            head = src[max(0, m.start() - 40): m.start()]
            if re.search(r"\b(?:struct|enum|trait|impl|union)\s+$", head):
                continue
            body = braced(src, m.end() - 1)
            for field, value in top_pairs(body):
                if field not in optional[name]:
                    continue
                checked += 1
                if BARE.match(value):
                    at = src[: m.start()].count("\n") + 1 + body[: body.index(field)].count("\n")
                    bad.append((path, at, name, field, value))

for path, at, name, field, value in sorted(set(bad)):
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}:{at}: `{name}.{field}` объявлено `Option`, а положено `{value}`")

print(f"записей с полями-`Option`: {len(watched)}; таких полей заполнено: {checked}")
print("чисто" if not bad else f"находок: {len(set(bad))}")
sys.exit(1 if bad else 0)
