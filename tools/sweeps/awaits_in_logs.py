#!/usr/bin/env python3
"""Метелка: внутри `tracing!` не ждут.

Заведена по отказу сборки, который стоил круга через человека — а в этом
дереве круг через человека это и есть цена ошибки: `cargo` здесь
не запускается, собирает Никита на своей машине.

Написано было так:

```rust
tracing::info!(пиров = node.count_active_peers().await, "меш: набор не удался");
```

Выглядит безобидно и читается лучше, чем в два действия. Но `tracing!`
разворачивается во временные `Arguments<'_>` и `Option<&dyn Value>`, и
ожидание **между** ними оставляет их живыми через точку ожидания. Ни то,
ни другое не `Send`, а значит всё будущее перестаёт быть `Send` — и падает
не эта строка, а `tokio::spawn` где-то выше, с сообщением про
«future created by async block is not Send» и стрелкой в макрос.

Лечится одним действием: посчитать в переменную до макроса. Правило
поэтому такое — **в аргументах `tracing!` не бывает `.await`**, и это
правило текстовое, то есть его видно без компилятора.

Проверена возвратом поломки: `.await` обратно в аргумент — одна находка,
ровно та строка.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла: метелку зовут и из корня,
# и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ROOT = ROOT_DIR / "crates"

# Все уровни: правило про раскрытие макроса, а не про важность строки.
LEVELS = ("trace", "debug", "info", "warn", "error")

CALL = re.compile(r"\btracing::(" + "|".join(LEVELS) + r")!\s*\(")


def args_of(src: str, open_paren: int) -> tuple[str, int]:
    """Аргументы вызова целиком и позиция закрывающей скобки."""
    depth = 0
    for j in range(open_paren, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1 : j], j
    return src[open_paren + 1 :], len(src) - 1


def main() -> int:
    bad = 0
    seen = 0
    for path in sorted(ROOT.glob("*/src/**/*.rs")):
        src = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT_DIR).as_posix()
        for m in CALL.finditer(src):
            seen += 1
            args, _ = args_of(src, m.end() - 1)
            if ".await" not in args:
                continue
            line = src[: m.start()].count("\n") + 1
            print(
                f"{rel}:{line}: `.await` в аргументах `tracing!`. Временные "
                "макроса не `Send`, и ожидание между ними лишает `Send` всё "
                "будущее — посчитайте в переменную до макроса"
            )
            bad += 1

    print(f"записей в журнал под присмотром: {seen}")
    print("чисто" if not bad else f"НАХОДОК: {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
