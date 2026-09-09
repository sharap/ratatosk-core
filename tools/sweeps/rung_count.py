#!/usr/bin/env python3
"""Двенадцатая проверка: ступеней всюду поровну.

Число транспортов записано в дереве не однажды, а в семи местах, и все семь
обязаны совпадать. Разойдясь, они не дают ошибки сборки: `stopped: [bool; 3]`
при четырёх раннерах — это выход за границу массива **во время работы**,
а лишняя ветка `select!` без своего индекса — молча неопрашиваемый транспорт.

Написана после того, как четвёртая ступень (0.2) прошла через все семь мест
руками. В тот раз сошлось; проверять это глазами второй раз незачем.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


bad = []
policy = text("proto/src/transport_policy.rs")
multi = text("transport/src/multi.rs")
sim = text("sim/src/net.rs")

# Источник истины — само перечисление.
enum_body = re.search(r"pub enum Transport \{(.*?)\n\}", policy, re.S).group(1)
variants = re.findall(r"^    ([A-Z]\w*),", enum_body, re.M)
n = len(variants)
if n < 3:
    print("перечисление Transport не разобралось — метелка бесполезна")
    sys.exit(2)

checks = [
    ("proto: ступеней у Reachability", policy, r"pub rungs: \[Rung; (\d+)\]"),
    ("proto: битов в маске KNOWN", policy, r"const KNOWN: u8 = ([\d |]+);"),
    ("multi: параметров у Transports", multi, r"pub struct Transports<([\w, ]+)> \{"),
    ("multi: длина stopped", multi, r"stopped: \[bool; (\d+)\]"),
    ("multi: обход to_all", multi, r"for via in \[([^\]]+)\]"),
    ("multi: веток select", multi, r"(?s)let \(which, event\) = tokio::select! \{(.*?)\n            \};"),
    ("sim: длина TransportKind::ALL", sim, r"pub const ALL: \[TransportKind; (\d+)\]"),
]

for label, src, pattern in checks:
    m = re.search(pattern, src)
    if not m:
        bad.append(f"{label}: место не найдено — метелка отстала от кода")
        continue
    body = m.group(1)
    if label.endswith("маске KNOWN"):
        got = len([p for p in body.split("|") if p.strip()])
    elif label.endswith("у Transports"):
        got = len([p for p in body.split(",") if p.strip()])
    elif label.endswith("to_all"):
        got = len(re.findall(r"Transport::\w+", body))
    elif label.endswith("веток select"):
        got = len(re.findall(r"next_event\(\)", body))
        # Индексы веток обязаны идти подряд от нуля: перепутанный индекс
        # помечает остановившимся **чужой** транспорт, и опрашиваться
        # перестанет живой.
        indexes = [int(x) for x in re.findall(r"stopped\[(\d+)\]", body)]
        if indexes != list(range(len(indexes))):
            bad.append(f"multi: индексы веток select идут не подряд: {indexes}")
    else:
        got = int(body)
    if got != n:
        bad.append(f"{label}: {got}, а транспортов {n}")

# Раскладка ступеней перечисляет каждый транспорт ровно один раз.
of_body = re.search(r"pub const fn of\(peer: PeerAvailability\) -> Reachability \{(.*?)\n    \}", policy, re.S)
if of_body:
    named = re.findall(r"transport: (Transport::\w+)", of_body.group(1))
    want = [f"Transport::{v}" for v in variants]
    if sorted(named) != sorted(want):
        bad.append(f"proto: Reachability::of раскладывает {named}, а транспортов {want}")

print("\n".join(bad) if bad else f"чисто (ступеней: {n})")
sys.exit(1 if bad else 0)
