#!/usr/bin/env python3
"""Метелка: о ступенях §5.4 решает `transport_policy`, а не тот, кому надо.

Заведена по поломке, которая на живых устройствах выглядела как «оффлайн
участники пропускают все сообщения, и до них не доходит даже когда они сами
пишут в группу».

Причина: `remember_undelivered` решала «есть ли смысл ждать», перечисляя
ступени **руками** — «LAN выключен, onion нет, почты нет, значит ждать
нечего». Меш в этом списке забыли. Собеседник, доступный только через него,
попадал под условие целиком: сообщение объявлялось недоставимым и
выбрасывалось, ни разу не попав в очередь ожидания. Будить потом было
нечего — отсюда и «даже когда они сами пишут».

Ступеней четыре, и станет больше. Каждое место, где их перечисляют руками,
— это список, который однажды разойдётся с лестницей; разойдётся молча,
потому что компилятор про полноту такого списка ничего не знает.

Правило: **признаки адресуемости (`has_ygg`, `has_onion`, `has_chatmail`)
читает только `transport_policy`.** Остальным полагается спрашивать
`Reachability` — `route`, `rising`, `may_open`, `refusal`.

Заполнять их можно где угодно: карточка приезжает в ядро, и разложить её
по полям больше некому. Отличие простое и проверяемое: `has_x: …` и
`has_x = …` — это заполнение, всё прочее — решение.
"""
import re
import sys
import pathlib

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]

# Где правило живёт и потому не нарушается по определению.
HOME = "proto/src/transport_policy.rs"

FLAGS = ("has_ygg", "has_onion", "has_chatmail")

# Заполнение поля: `has_x: значение` в литерале записи либо `has_x = значение`
# присваиванием. `==` и `!=` сюда не попадают — это уже решение.
FILLING = re.compile(r"\b(?:" + "|".join(FLAGS) + r")\s*(?::|=(?!=))")

sources = sorted(ROOT_DIR.glob("crates/*/src/**/*.rs"))

bad = []
looked = 0
for path in sources:
    rel = str(path.relative_to(ROOT_DIR / "crates"))
    if rel.replace("\\", "/") == HOME:
        continue
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        stripped = line.strip()
        # Комментарии и документация про эти поля рассказывать вправе.
        if stripped.startswith("//"):
            continue
        if not any(flag in line for flag in FLAGS):
            continue
        looked += 1
        if FILLING.search(line):
            continue
        bad.append((rel, number, stripped[:78]))

for rel, number, text in bad:
    print(f"crates/{rel}:{number}: {text}")
    print("    решение по ступеням мимо `transport_policy`: спросите `Reachability`")

print(f"обращений к признакам адресуемости вне политики: {looked}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
