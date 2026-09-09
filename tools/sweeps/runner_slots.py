#!/usr/bin/env python3
"""Метелка: пустой слот составного транспорта обязан быть объяснён.

Заведена по поломке, встретившейся **дважды одинаково**. `Transports::new`
берёт четыре раннера — по одному на ступень §5.4, — и слот, в который
положили `Disabled`, выглядит совершенно нормально. Компилятор доволен:
`Disabled` — законный раннер, он честно отвечает `Unavailable`.

Что из этого вышло:

* стенд-терминал собирал `Transports::new(lan, Disabled, onion, Disabled)` —
  и лестница канала, дойдя до меша, упиралась в `Unavailable` на каждый
  кадр. Синхронный отказ события не рождает, отката не заводит: терминал
  до onion не добирался никогда;
* через поставку то же самое нашлось в `ffi` — там слот меша остался
  `Disabled`, и §5яи работала где угодно, только не в приложении.

Оба раза причина одна: список из четырёх ступеней собирается в нескольких
местах, и пустой слот молчит. Правило поэтому такое: **каждый `Disabled`
в неиспытательном коде обязан быть назван здесь вместе с причиной**.
Молчание превращается в написанное утверждение, и ложное утверждение
видно глазами — как и всё остальное в этом дереве.

Новый `Disabled` без записи — находка. Это нарочно: править метелку,
добавляя ступень, значит один раз вслух сказать, почему её нет.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ROOT = ROOT_DIR / "crates"

# Порядок слотов — тот же, что у ступеней §5.4, и это не совпадение:
# `Transports::new` принимает их лестницей.
SLOTS = ["Lan", "Ygg", "Onion", "Mail"]

# Чему позволено быть пустым и почему. Ключ — файл и ступень; причина
# читается человеком и больше нигде не используется.
ALLOWED = {
    ("crates/ffi/src/lib.rs", "Onion"): "собрано без признака `tor` — arti в граф не идёт",
    ("crates/ffi/src/companion.rs", "Onion"): "то же: без признака `tor`",
    (
        "crates/ffi/src/companion.rs",
        "Mail",
    ): "почтового круга у второго экрана нет и не будет (§5.3 — это часы, §13.4 — «здесь и сейчас»)",
    ("crates/lab/src/main.rs", "Onion"): "собрано без признака `tor`",
    ("crates/lab/src/main.rs", "Mail"): "у терминала почты нет — та же причина, что в `ffi`",
}


def test_spans(src: str) -> list[tuple[int, int]]:
    """Границы `mod tests` — там неполный набор ступеней и есть весь смысл."""
    spans = []
    for m in re.finditer(r"\bmod tests \{", src):
        i = m.end() - 1
        depth = 0
        for j in range(i, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
        spans.append((i, j))
    return spans


def args_of(src: str, start: int) -> list[str]:
    """Четыре довода вызова, поделённые по глубине скобок."""
    depth = 0
    current = ""
    parts = []
    for ch in src[start:]:
        if ch in "([{":
            depth += 1
            if depth == 1:
                continue
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                parts.append(current)
                return [p.strip() for p in parts]
        if depth == 1 and ch == ",":
            parts.append(current)
            current = ""
        else:
            current += ch
    return []


def main() -> int:
    bad = 0
    seen = 0
    for path in sorted(ROOT.glob("*/src/**/*.rs")):
        src = path.read_text(encoding="utf-8")
        spans = test_spans(src)
        rel = path.relative_to(ROOT_DIR).as_posix()
        for m in re.finditer(r"Transports::new\(", src):
            if any(start <= m.start() <= end for start, end in spans):
                continue
            seen += 1
            args = args_of(src, m.end() - 1)
            if len(args) != len(SLOTS):
                line = src[: m.start()].count("\n") + 1
                print(f"{rel}:{line}: у `Transports::new` не четыре довода — разбор не удался")
                bad += 1
                continue
            for slot, arg in zip(SLOTS, args):
                if arg != "Disabled":
                    continue
                if (rel, slot) in ALLOWED:
                    continue
                line = src[: m.start()].count("\n") + 1
                print(
                    f"{rel}:{line}: ступень {slot} пуста, а причины не записано. "
                    "Либо поднимите раннер, либо впишите её в ALLOWED этой метелки"
                )
                bad += 1

    print(f"сборок составного транспорта под присмотром: {seen}")
    print("чисто" if not bad else f"НАХОДОК: {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
