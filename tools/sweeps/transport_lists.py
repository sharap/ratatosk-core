#!/usr/bin/env python3
"""Метелка: список транспортов, выписанный руками, обязан быть полным.

За один день эта ошибка встретилась трижды, и все три раза одинаково:
где-то в коде стоял литерал `[Transport::Lan, Transport::Onion, ...]`,
написанный, когда ступеней было три. Появилась четвёртая (меш, 0.2) —
и в список не попала. Компилятор молчит: список синтаксически безупречен.

Что из этого вышло:

* `startup_effects` не говорил раннеру меша ничего — и настройки меша
  «не переживали перезапуск», хотя лежали на диске в целости;
* драйвер считал прямым каналом только `[Lan, Onion]` — и контакт с живой
  сессией по мешу показывался как «прямого канала нет»;
* стенд объявлял «троим» там, где транспортов стало четверо (это поймал
  Никита сборкой, и только потому, что там был `assert`).

Правило: в неиспытательном коде литерал-массив вариантов `Transport`
обязан называть **все** варианты. Нужен неполный — берите его из лестницы
(`Reachability::of(...).rungs`) и фильтруйте по признаку: тогда список
растёт сам, а признак говорит вслух, чем эти ступени отличаются.

Тесты не смотрятся: там неполный список — обычное дело и часто весь смысл
проверки («до него только по локальной сети»).
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"
DECL = ROOT / "proto/src/transport_policy.rs"

SOURCES = sorted(ROOT.glob("*/src/**/*.rs"))


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


def without_tests(src):
    """Тело `#[cfg(test)] mod …` вырезается, номера строк сохраняются."""
    m = re.search(r"#\[cfg\(test\)\]\s*\nmod\s+\w+\s*\{", src)
    if not m:
        return src
    start = src.index("{", m.end() - 1)
    body = braced(src, start)
    return src[:start] + "\n" * body.count("\n") + src[start + len(body):]


decl = DECL.read_text(encoding="utf-8")
m = re.search(r"\benum\s+Transport\s*\{", decl)
if not m:
    print("перечисление Transport не разобралось — метелка бесполезна")
    sys.exit(2)
ALL = set(re.findall(r"^    ([A-Z]\w*)\s*(?:,|\(|\{|$)", braced(decl, m.end() - 1), re.M))
if len(ALL) < 2:
    print("вариантов Transport меньше двух — метелка бесполезна")
    sys.exit(2)

# Литерал-массив, целиком состоящий из вариантов транспорта.
ITEM = r"(?:\w+::)*Transport::[A-Z]\w*"
ARRAY = re.compile(r"\[\s*(" + ITEM + r"(?:\s*,\s*" + ITEM + r")*)\s*,?\s*\]")

bad = []
checked = 0
for path in SOURCES:
    src = without_tests(path.read_text(encoding="utf-8"))
    for m in ARRAY.finditer(src):
        named = set(re.findall(r"Transport::([A-Z]\w*)", m.group(1)))
        if not named <= ALL:
            continue  # чужое перечисление с тем же хвостом имени
        checked += 1
        if named != ALL:
            line = src[: m.start()].count("\n") + 1
            bad.append((path, line, sorted(ALL - named)))

for path, line, missing in bad:
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}:{line}: список транспортов неполон — нет: {', '.join(missing)}")
    print("    нужен неполный — берите из лестницы и фильтруйте признаком")

print(f"списков проверено: {checked}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
