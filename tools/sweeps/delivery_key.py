#!/usr/bin/env python3
"""Метелка: доставка опознаётся парой, а не номером сообщения.

Заведена по поломке, из-за которой в группах терялись сообщения: «не всегда
и не до всех, через некоторое время чинится, а недошедшие так и не доходят».

Причина одна и в трёх местах сразу. Сообщение в группу — это N доставок
с **одним** `msg_id` (§11.3: копию каждому шлёт сам отправитель). А код
обходился с очередью по одному номеру:

* `note_status` снимала с очереди всё с этим номером — и первая дошедшая
  копия уносила копии всех участников, до которых в тот момент было
  не достучаться;
* `remember_undelivered` считала «уже отложено» по номеру — то есть ждать
  оставался ровно один недостижимый участник из скольких угодно;
* `MemoryStore` держал очередь в карте по `MsgId`, поэтому ни симулятор,
  ни один тест на памяти этого увидеть не мог в принципе.

Правило: обращение к `self.deferred` или `self.outbox`, упоминающее
`msg_id`, обязано упоминать и `peer_ik`. Исключение — места, где исчезает
**само сообщение**: там «все получатели» и есть смысл.

Исключения названы поимённо и с причиной. Список короткий нарочно: как
только он начнёт расти, правило перестанет что-либо значить.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


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


# Функции, где «все копии» — и есть смысл: сообщение исчезает целиком.
WHOLE_MESSAGE = {
    # Человек удалил сообщение. Удалённое не должно уехать никому.
    "forget_messages",
    # Человек очистил чат. То же самое, только оптом.
    "on_clear_chat",
}

QUEUES = ("self.deferred", "self.outbox")


def enclosing(src, at):
    """Имя функции, внутри которой стоит позиция `at`."""
    name = None
    for m in re.finditer(r"\n    (?:pub )?(?:pub\(super\) )?(?:pub\(crate\) )?(?:const )?fn (\w+)", src[:at]):
        name = m.group(1)
    return name


src = engine_source()

bad = []
checked = 0
for queue in QUEUES:
    for m in re.finditer(re.escape(queue) + r"\s*\.\s*(\w+)\(", src):
        # Кусок до конца строки со скобками — этого хватает: обращения
        # к очереди пишутся одним выражением, а не абзацем.
        tail = src[m.end(): src.index("\n", m.end()) + 1]
        # Многострочные замыкания дочитываются до закрывающей скобки блока.
        if tail.count("(") > tail.count(")"):
            end = src.index(";", m.end())
            tail = src[m.end(): end]
        if "msg_id" not in tail:
            continue
        checked += 1
        if "peer_ik" in tail or "recipient" in tail:
            continue
        where = enclosing(src, m.start())
        if where in WHOLE_MESSAGE:
            continue
        line = src[: m.start()].count("\n") + 1
        bad.append((line, where, queue, m.group(1), " ".join(tail.split())[:70]))

for line, where, queue, method, tail in bad:
    print(f"crates/core/src/engine.rs:{line}: {where}: {queue}.{method}({tail}")
    print("    доставка опознана номером без получателя — в группе это все копии сразу")

print(f"обращений к очередям по номеру: {checked}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
