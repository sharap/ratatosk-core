#!/usr/bin/env python3
"""Метелка: платформенный отказ не превращается в разрешение молча.

Правило словами: **условие про платформу остаётся в том месте, где оно
решает, бывает ли ступень, и рядом остаётся текст, объясняющий человеку
отсутствие.**

Заведена по настоящей поломке — точнее, по двум, которые не покраснели.
На Android мультикаст меша не работает (наблюдение с устройства, 0.2.7),
и `ygg::multicast_supported` отвечает `!cfg!(target_os = "android")`.
Возврат поломки показал, что проверить это прогоном **нельзя**: он идёт
на Linux, где условие ложно по построению. Замени `!cfg!(…)` на `true` —
значение на Linux то же, и все 490 проверок остаются зелёными. Собрать
под Android здесь тоже нечем: нужен NDK.

То есть половина правила держалась ни на чём — ровно тот случай, ради
которого метелки и существуют.

Чего эта метелка **не** стережёт: что на Android мультикаст и правда
не работает. Это наблюдение, а не измерение. Стережётся то, что
наблюдение не выкинут из кода незаметно.

Находок должно быть ноль. Поломка проверяется так: заменить условие
на `true` — метелка краснеет; убрать текст — тоже.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Одна пара — одно платформенное исключение: где решается и чем объясняется.
#
# Список короткий нарочно. Начни он расти — правило перестанет что-либо
# значить, а каждая строка здесь обязана стоять по настоящей поломке.
GATES = [
    {
        "где": "crates/proto/src/ygg.rs",
        "функция": "multicast_supported",
        "платформа": 'target_os = "android"',
        "текст": ("crates/core/src/honest.rs", "YGG_MULTICAST_UNSUPPORTED"),
        "почему": "на Android соседи мультикастом не находятся (0.2.7)",
    },
]


def body_of(source: str, name: str) -> str | None:
    """Тело функции по имени — грубо, до первой закрывающей скобки уровня."""
    start = re.search(rf"\n(pub )?const fn {re.escape(name)}\b[^{{]*{{", source)
    if not start:
        return None
    rest = source[start.end() :]
    depth = 1
    for index, char in enumerate(rest):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return rest[:index]
    return None


bad = []
for gate in GATES:
    path = ROOT / gate["где"]
    if not path.exists():
        bad.append(f"{gate['где']}: файла нет — метёлке нечего смотреть")
        continue
    body = body_of(path.read_text(encoding="utf-8"), gate["функция"])
    if body is None:
        bad.append(f"{gate['где']}: функции `{gate['функция']}` нет — метёлка отстала от кода")
        continue
    if gate["платформа"] not in body:
        bad.append(
            f"{gate['где']}: в `{gate['функция']}` нет условия `{gate['платформа']}` — "
            f"а оно там потому, что {gate['почему']}"
        )
    text_path, text_name = gate["текст"]
    text_file = ROOT / text_path
    if not text_file.exists() or text_name not in text_file.read_text(encoding="utf-8"):
        bad.append(
            f"{text_path}: нет `{text_name}` — отсутствие ступени человеку "
            f"объяснить нечем, а §14 это требует"
        )

print("\n".join(bad) if bad else f"чисто (платформенных исключений: {len(GATES)})")
sys.exit(1 if bad else 0)
