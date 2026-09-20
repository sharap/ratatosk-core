#!/usr/bin/env python3
"""Одиннадцатая проверка: обрыв и отказ соединения не должны снова слиться.

Разница между ними стоила стенду переписки в одну сторону (HANDOFF, 6б):
обрыв сокета читался как «устройства в сети нет». Проверяется вся цепочка —
событие транспорта, вход ядра, причина отказа, единственное место, где
забывается адрес в локальной сети.
"""
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = str(ROOT_DIR / "crates/core/src") + "/"
bad = []


def text(name):
    with open(ROOT + name, encoding="utf-8") as f:
        return f.read()


def engine_source():
    """Ядро целиком: `engine.rs` плюс его подмодули.

    После разделения (0.5) ядро — не один файл, а каталог. Метелка,
    читающая только `engine.rs`, нашла бы пустоту и отчиталась
    «чисто» — то есть соврала бы ровно в тот день, когда её стоило
    послушать. Читается всё разом: метелке безразлично, в каком
    модуле лежит проводка, ей важно, что проводка есть.
    """
    root = ROOT_DIR / "crates/core/src"
    parts = [(root / "engine.rs").read_text(encoding="utf-8")]
    parts += [p.read_text(encoding="utf-8") for p in sorted((root / "engine").glob("*.rs"))]
    return "\n".join(parts)


def strip_comments(s):
    return "\n".join(line.split("//")[0] for line in s.split("\n"))


io = strip_comments(text("io.rs"))
driver = strip_comments(text("driver.rs"))
engine = strip_comments(engine_source())

# 1. Оба входа существуют и различны.
for want in ("ConnectionLost {", "ConnectFailed {"):
    if io.count("    " + want) != 1:
        bad.append(f"io.rs: вход {want.split()[0]} объявлен не ровно один раз")

# 2. Драйвер разводит события транспорта по разным входам.
pairs = {
    "TransportEvent::Disconnected": "Input::ConnectionLost",
    "TransportEvent::ConnectFailed": "Input::ConnectFailed",
}
for event, want in pairs.items():
    m = re.search(re.escape(event) + r"\s*\{[^}]*\}\s*=>\s*(Input::\w+)", driver)
    if not m:
        bad.append(f"driver.rs: {event} больше не переводится во вход")
    elif m.group(1) != want:
        bad.append(f"driver.rs: {event} едет в {m.group(1)}, а должен в {want}")

# 3. Ядро связывает входы с причинами.
wiring = {
    "Input::ConnectionLost": "Failure::Dropped",
    "Input::ConnectFailed": "Failure::Unreachable",
}
for inp, want in wiring.items():
    m = re.search(re.escape(inp) + r"\s*\{[^}]*\}\s*=>\s*\{\s*([^}]*?)\}", engine, re.S)
    if not m:
        bad.append(f"engine.rs: вход {inp} больше не разбирается")
    elif want not in m.group(1):
        bad.append(f"engine.rs: {inp} перестал означать {want}")

# 4. Адрес в локальной сети забывается ровно в одном месте и только по отказу.
forgets = [
    line
    for line in engine.split("\n")
    if "seen_on_lan = false" in line
]
# Три законных: отказ соединения, смена сети, выключенный транспорт.
if len(forgets) != 3:
    bad.append(
        "engine.rs: мест, где гасится seen_on_lan, стало "
        f"{len(forgets)} вместо трёх (отказ соединения, смена сети, LAN выключён)"
    )
guard = re.search(r"if why == (Failure::\w+) && via == Transport::Lan", engine)
if not guard:
    bad.append("engine.rs: условие забывания адреса не найдено")
elif guard.group(1) != "Failure::Unreachable":
    bad.append(f"engine.rs: адрес забывается по {guard.group(1)} — обрыв снова всё ломает")

# 5. Пришедший кадр возвращает адрес — **обоим** эфирам.
#
# Правило было про локальную сеть (`note_lan_presence`) и оттого наполовину
# неверное: в Bluetooth адресуемость давало только услышанное объявление,
# и собеседник, дозвонившийся до нас сам, числился «не слышен» при живом
# канале. §5.4 такую ступень не пробовал вовсе — `tried=[]`.
if "fn note_presence" not in engine:
    bad.append("engine.rs: note_presence исчезла — маяк снова единственное свидетельство")
else:
    # Четыре двери, через которые кадр попадает в ядро прямой ступенью:
    # входящее рукопожатие, **его повтор**, ответ на наше, данные в живой
    # сессии. Повтор добавлен последним и не зря: собеседник, повторяющий
    # первый шаг, иначе не давал ни отметки достижимости, ни имени связи —
    # и контакт по эфиру «не добавлялся».
    calls = engine.count("self.note_presence(")
    if calls != 4:
        bad.append(f"engine.rs: note_presence зовётся из {calls} мест, ожидалось четыре")
    # И обе ступени обязаны в ней разбираться: отметки разные
    # (`seen_on_lan`, `seen_on_bt`), и потерять вторую — вернуть поломку.
    for flag in ("seen_on_lan, true", "seen_on_bt, true"):
        if flag not in engine:
            bad.append(f"engine.rs: note_presence больше не ставит {flag.split(',')[0]}")

print("\n".join(bad) if bad else "чисто")
sys.exit(1 if bad else 0)
