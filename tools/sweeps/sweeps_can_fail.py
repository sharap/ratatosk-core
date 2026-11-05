#!/usr/bin/env python3
"""Метелка обязана уметь краснеть: у каждой есть ненулевой возврат.

Развёртка — настоящая и дорогая. Шесть метелок из тридцати четырёх
печатали находки и возвращали ноль. `run_all` считает метелки
**по коду возврата**, поэтому отчёт говорил «все 34 метелки чисты»,
а на экране в это время лежало тридцать восемь находок:
`unused_params` — пять, `double_wrap` — семь, `orphan_writes` —
двадцать шесть. Лестница была зелена, пока метелки кричали.

Три остальные (`labels_covered`, `missing_docs`, `moved_runner`)
находок не имели — и не смогли бы сообщить о первой же.

Правило: в файле метелки должен стоять `sys.exit` с чем-то, кроме нуля.

**Чего эта метелка не стережёт.** Что возврат **достижим** — она
проверяет, что он написан, а не что до него доходит исполнение. Это
по силам только прогону самой метелки против заведомо ломаной заготовки,
а такой заготовки у метелок нет. Не стережёт она и смысл возврата:
`sys.exit(1)` при пустом списке находок она одобрит.
"""
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent

# `run_all` сам возвращает число упавших метелок — ему правило не нужно.
SKIP = {"run_all.py"}

EXIT = re.compile(r'\bsys\.exit\(\s*([^)]*)\)')

sweeps = sorted(p for p in HERE.glob("*.py") if p.name not in SKIP)
mute = []
for sweep in sweeps:
    args = [a.strip() for a in EXIT.findall(sweep.read_text(encoding="utf-8"))]
    if not any(a and a != "0" for a in args):
        mute.append(sweep.name)
        print(f"{sweep.name}: нет ненулевого sys.exit — краснеть не умеет")

print(f"метелок осмотрено: {len(sweeps)}")
print("чисто" if not mute else f"-- немых {len(mute)}")
sys.exit(1 if mute else 0)
