#!/usr/bin/env python3
"""Метелка: немолчаливый кадр обязан получать квитанцию.

Заведена по поломке, которая стоила трёх кругов разбора и выглядела как
«в группах сообщения доходят не всегда и не до всех».

Правило доставки §5.4 такое. Кадр, поставленный в очередь **не** молчаливым,
получает срок; вышедший срок читается как «прямой канал не удался»
(`Failure::Silent`). Неудача отправляет сессию на покой и начинает новое
рукопожатие. В семействе транспортов живут ровно две сессии — одна
отправляет, одна дослушивает, — и третья сносит первую насовсем. Кадры,
запечатанные снесённой, приезжают к собеседнику как «сессия неизвестна»
и молча пропадают (§7.3).

Значит забытая квитанция — это не «индикатор не тот». Это цепочка,
на конце которой **пропадают чужие слова**, и обнаруживается она только
на живой сети или на стенде с тремя узлами. Так и вышло: `on_edit`
и `on_reaction` квитанцию слали и знали зачем, а четыре групповых кадра
и обновление карточки §4.3 — забыли.

Что проверяется: **тип, который где-то ставится в очередь** (через
`enqueue_request` или `tell_member`), обязан при приёме отвечать
квитанцией — сам или через того, кого зовёт первым уровнем.

Кадры, уходящие прямым `Effect::Send` мимо очереди (аватарка, чанк файла,
просьба о чанке, сама квитанция), сюда не попадают вовсе: у них нет срока,
и подтверждать нечего.
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


# Молчаливые по построению: копия каждому участнику группы (§11.3).
# Квитанции у них нет и быть не может — один значок на тридцать двух
# получателей §14 не разрешает, и отправитель её не ждёт.
SILENT = {"GroupMessage", "GroupAction"}


def body_of(src, name):
    """Тело функции `name` — от заголовка до следующего объявления."""
    m = re.search(r"\n    (?:pub )?(?:pub\(super\) )?(?:pub\(crate\) )?(?:const )?fn " + re.escape(name) + r"\b", src)
    if m is None:
        return None
    rest = src[m.end():]
    nxt = re.search(r"\n    (?:pub )?(?:pub\(super\) )?(?:pub\(crate\) )?(?:const )?fn \w+", rest)
    return rest[: nxt.start()] if nxt else rest


src = engine_source()

# 1. Типы, которые ставятся в очередь.
queued = set()
for m in re.finditer(r"enqueue_request\(\s*[^;]*?PayloadType::(\w+)", src):
    queued.add(m.group(1))
# `tell_member` — обёртка над `enqueue_request` для групповых кадров:
# тип у неё аргументом, поэтому берётся с места зова.
for m in re.finditer(r"tell_member\(\s*[^;]*?PayloadType::(\w+)", src):
    queued.add(m.group(1))
# Прямые `enqueue(Delivery { … silent: false … })` — тип берётся
# из конверта, собранного тут же.
for m in re.finditer(r"PayloadType::(\w+)[^;]*?\n\s*(?:let mut effects = )?self\.enqueue\(", src):
    queued.add(m.group(1))

queued -= SILENT
if not queued:
    print("ни одного типа в очереди — метелка ослепла")
    sys.exit(1)

# 2. Куда ведёт приём каждого типа.
deliver = body_of(src, "deliver")
if deliver is None:
    print("не нашлась `fn deliver` — метелка ослепла")
    sys.exit(1)


# Разбор построчный, а не одним выражением: плечо `match` бывает
# многострочным (`A | B | C => …`), и жадная склейка через `\s*` съедала
# бы соседние плечи вместе с их разделителями. Первая редакция метелки
# так и делала — и теряла два типа из восьми, то есть ровно ту находку,
# ради которой заводилась.
handler_of = {}
pending = []
lines = deliver.split("\n")
for i, line in enumerate(lines):
    kinds = re.findall(r"PayloadType::(\w+)", line)
    if "=>" not in line:
        pending.extend(kinds)
        continue
    head, tail = line.split("=>", 1)
    kinds = pending + re.findall(r"PayloadType::(\w+)", head)
    pending = []
    if not kinds:
        continue
    # Тело плеча — до трёх строк: этого хватает и однострочному зову,
    # и блоку, начинающемуся с квитанции.
    window = "\n".join([tail] + lines[i + 1 : i + 4])
    call = re.search(r"self\.(\w+)\(", window)
    for kind in kinds:
        handler_of.setdefault(kind, call.group(1) if call else None)


def acknowledges(fn, depth=1):
    """Отвечает ли `fn` квитанцией — сам или через того, кого зовёт."""
    body = body_of(src, fn)
    if body is None:
        return False
    if "send_receipt" in body:
        return True
    if depth == 0:
        return False
    return any(
        acknowledges(inner, depth - 1)
        for inner in set(re.findall(r"self\.(on_\w+)\(", body))
    )


bad = []
for kind in sorted(queued):
    handler = handler_of.get(kind)
    if handler is None:
        bad.append((kind, "приём этого типа никуда не ведёт"))
    elif not acknowledges(handler):
        bad.append((kind, f"`{handler}` не отправляет квитанции"))

for kind, why in bad:
    print(f"PayloadType::{kind}: {why}")
    print("    немолчаливый кадр без квитанции: срок объявит неудачу, §5.4")
    print("    отправит сессию на покой, и кадры собеседника начнут пропадать")

print(f"типов в очереди: {len(queued)} ({', '.join(sorted(queued))})")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
