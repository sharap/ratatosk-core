#!/usr/bin/env python3
"""Метелка: одно имя — одно объявление внутри одного блока.

Заведена по случаю, который стоил бы Никите сборки целиком. В рабочее
дерево вклинилось 372 строки — старая копия одиннадцати методов работы
с группами — и попала она **внутрь** того же `impl<S: Store> Engine<S>`,
где эти методы уже жили. Такое rustc отвергает сразу (`E0592`), до
проверки заимствований, то есть Никита не увидел бы даже той ошибки,
ради которой посылка собиралась.

Заметила это тогда не эта метелка, а `record_fields`: у старой копии
не было полей, заведённых позже. То есть находка была **случайной** —
повторись беда в куске без записей, «чисто» сказали бы все метелки разом.
Отсюда и эта: она смотрит ровно на то, что произошло, а не на след,
который беда оставила по дороге.

Правило: в пределах одного блока верхнего уровня (`impl`, `trait`, `mod`,
тело функции сюда не считается — вложенное имя своё) имя `fn` встречается
один раз. Разные блоки — разные пространства, и одноимённые методы
в двух `impl` законны.

Смотрит на объявления с отступом ровно в четыре пробела: так пишутся
члены `impl` верхнего уровня, а вложенные помощники внутри тел — с восемью
и больше. Правило грубое, зато не требует разбора языка; цена ошибки
в другую сторону (пропустить дубль во вложенном модуле) невелика —
такие модули короткие и видны глазом.
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

# Начало блока верхнего уровня: `impl …`, `trait …`, `mod …` без отступа.
OPENER = re.compile(r"^(impl\b.*|pub\s+trait\b.*|trait\b.*|(?:pub\s+)?mod\s+\w+.*)\{\s*$")
MEMBER = re.compile(r"^    (?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)")

bad = []
blocks = 0
for path in SOURCES:
    lines = path.read_text(encoding="utf-8").splitlines()
    opener_line = None
    seen = defaultdict(list)
    for i, line in enumerate(lines, 1):
        if line and not line[0].isspace():
            # Новая вещь верхнего уровня — прежний блок закончился.
            if opener_line is not None:
                blocks += 1
                for name, at in seen.items():
                    if len(at) > 1:
                        bad.append((path, opener_line, name, at))
                seen = defaultdict(list)
                opener_line = None
            if OPENER.match(line):
                opener_line = i
            continue
        if opener_line is None:
            continue
        m = MEMBER.match(line)
        if m:
            seen[m.group(1)].append(i)
    if opener_line is not None:
        blocks += 1
        for name, at in seen.items():
            if len(at) > 1:
                bad.append((path, opener_line, name, at))

for path, opener_line, name, at in bad:
    rel = path.relative_to(ROOT.parent)
    места = ", ".join(str(a) for a in at)
    print(f"{rel}:{opener_line}: в одном блоке дважды объявлено `fn {name}` — строки {места}")

print(f"блоков проверено: {blocks}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
