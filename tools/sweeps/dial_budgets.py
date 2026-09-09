#!/usr/bin/env python3
"""Метелка: срок ожидания ступени обязан вмещать её набор — и свой, и чужой.

Заведена по поломке, которая выглядела так: «личные сообщения после офлайна
доходят, групповые — чаще всего нет».

Соединения односторонние (`ARCHITECTURE.md`, 5ц): ответ собеседника приезжает
не по нашему соединению, а по тому, которое он должен сперва набрать сам.
Значит срок ожидания ответа обязан вмещать **два** набора. У onion это было
записано и проверено с самого начала; у меша — нет. Меш мерялся локальной
сетью (пять секунд), а набирает восемь.

Следствие для обычного сообщения — лишняя ступень: срок вышел раньше, чем
транспорт успел сказать «не соединился». Следствие для **копии в группу** —
само сообщение: квитанции у неё нет (§11.3), её попытку закрывает молчание
транспорта, и молчание короче набора означало «отдано» ровно тогда, когда
шёл набор. Копия снималась с очереди, а через три секунды приезжал отказ,
которому уже некого было вести дальше.

Метелка стережёт две вещи разом:

* **числа живут в одном месте.** Таймаут набора объявляется в
  `transport_policy` и берётся раннером оттуда. Раньше он стоял литералом
  в раннере, а срок ожидания — в политике, в другом крейте: разойтись им
  было нечему помешать, и они разошлись;
* **срок вмещает два набора.** `ожидание >= 2 * набор` для каждой прямой
  ступени.

Почта сюда не входит: она асинхронна по устройству, набора у неё нет
и ждать ответа бессмысленно (§9.4).
"""
import re
import sys
import pathlib

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]

POLICY = ROOT_DIR / "crates/proto/src/transport_policy.rs"

# Прямые ступени: как зовётся набор, как зовётся ожидание, и чей раннер.
RUNGS = [
    ("lan", "LAN_CONNECT_TIMEOUT_MS", "LAN_RECEIPT_TIMEOUT_MS", "transport/src/lan.rs"),
    ("ygg", "YGG_CONNECT_TIMEOUT_MS", "YGG_RECEIPT_TIMEOUT_MS", "transport/src/ygg.rs"),
    ("onion", "ONION_CONNECT_TIMEOUT_MS", "ONION_REPLY_TIMEOUT_MS", "transport/src/onion/arti.rs"),
]


def constant(src, name):
    """Значение `pub const ИМЯ: u64 = …;` — с раскрытием `N * ДРУГАЯ`."""
    m = re.search(r"pub const " + re.escape(name) + r": u64 = ([^;]+);", src)
    if m is None:
        return None
    body = m.group(1).strip()
    # Подчёркивания снимаются **только с числа**. Первая редакция снимала их
    # со всего выражения — и `2 * ONION_CONNECT_TIMEOUT_MS` превращалось
    # в `2 * ONIONCONNECTTIMEOUTMS`, то есть в неизвестное имя. Метелка
    # объявляла, что константы нет, на исправном дереве.
    digits = body.replace("_", "")
    if digits.isdigit():
        return int(digits)
    mul = re.fullmatch(r"(\d+)\s*\*\s*(\w+)", body)
    if mul:
        inner = constant(src, mul.group(2))
        return None if inner is None else int(mul.group(1)) * inner
    return None


policy = POLICY.read_text(encoding="utf-8")

bad = []
checked = 0
for label, dial_name, wait_name, runner_rel in RUNGS:
    dial = constant(policy, dial_name)
    wait = constant(policy, wait_name)
    if dial is None or wait is None:
        bad.append(f"{label}: в `transport_policy` не нашлось {dial_name} или {wait_name}")
        continue
    checked += 1
    if wait < 2 * dial:
        bad.append(
            f"{label}: ждём {wait} мс, а набираем {dial} мс — "
            f"ступень бросается раньше, чем успевает отказать"
        )

    runner = ROOT_DIR / "crates" / runner_rel
    if not runner.exists():
        bad.append(f"{label}: раннер {runner_rel} не найден — метелка ослепла")
        continue
    text = runner.read_text(encoding="utf-8")
    # Литерал секунд/миллисекунд в объявлении таймаута — это второе место,
    # где живёт то же число.
    for m in re.finditer(r"const \w*CONNECT_TIMEOUT\w*[^=]*=\s*([^;]+);", text):
        value = m.group(1)
        if re.search(r"from_(?:secs|millis)\(\s*\d", value):
            bad.append(
                f"{label}: раннер задаёт таймаут набора числом ({value.strip()}) — "
                f"он обязан браться из `transport_policy::{dial_name}`"
            )

for line in bad:
    print(line)

print(f"прямых ступеней проверено: {checked}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
