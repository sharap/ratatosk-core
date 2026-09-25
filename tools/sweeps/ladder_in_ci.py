#!/usr/bin/env python3
"""Тридцать четвёртая проверка: лестница README и CI зовут одно и то же.

Правило словами: **каждая команда из блока «Проверки» в README имеет шаг
в `ci.yml`, и доводы у них совпадают.**

Заведена по настоящей поломке — точнее, по трём подряд в один день,
и все три одного вида: команда написана в лестнице, читатель считает
её работающей, а она либо не проходит, либо смотрит не туда.

Дороже всех обошлась третья. `cargo deny check` в README стоял без
признаков, а действие `cargo-deny-action` передаёт `--all-features`
по умолчанию. Локально зелено, в CI красно; и хуже того — из-под
признаков выпадала половина транспорта, то есть проверка была зелена
оттого, что смотрела не туда. Разница в один довод, и увидеть её
глазами нельзя: доводы лежат в разных файлах и разным синтаксисом.

**Чего эта метёлка НЕ стережёт, и это надо знать.** Она сверяет
**текст** команд, а не то, что они делают. Из трёх поломок того дня
она вернула бы одну — расхождение доводов. Ни «clippy не проходит»,
ни «`cargo deny` не начинается из-за непригодного конфига» ею
не ловятся: для этого команду надо запустить, а метёлки не запускают
`cargo`. Их ловит сам CI, и в этом разделение труда: метёлка стережёт
**согласие двух документов**, прогон — работу.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Команды, которые в лестнице есть, а шага в CI им не положено.
# Поимённо и с причиной: начни список расти — правило перестанет
# что-либо значить.
EXCEPTIONS = {
    # (пока пусто)
}


def ladder_commands():
    """Команды из блока «Проверки» в README — по одной на строку."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = re.search(r"\n## Проверки\n(.*?)\n## ", text, re.S)
    if not section:
        return None
    block = re.search(r"```sh\n(.*?)```", section.group(1), re.S)
    if not block:
        return None
    out = []
    for line in block.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def ci_steps():
    """Шаги `ci.yml` — куском текста каждый, без разбора YAML.

    Разбирать YAML незачем: цена пропущенной находки невелика, а ложная
    тревога стоит доверия ко всему набору.
    """
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    parts = re.split(r"\n      - ", text)
    return ["      - " + p for p in parts[1:]]


def ci_command_words(step):
    """Что шаг на самом деле зовёт: `run:` плюс доводы из `with:`.

    Действие вместо голой команды — тот же зов, только другим
    синтаксисом, и сверять надо его же. Доводы, приезжающие умолчанием
    действия, сюда не попадут — и не должны: невидимое умолчание
    и есть та поломка, ради которой метёлка написана.
    """
    words = []
    lines = [l.split("#", 1)[0] for l in step.splitlines()]
    for i, line in enumerate(lines):
        got = re.match(r" *run: *(.*)", line)
        if not got:
            continue
        if got.group(1).strip() in ("|", ">"):
            # Многострочный `run:` — берём строки, пока они отступлены
            # глубже самого ключа.
            depth = len(line) - len(line.lstrip())
            for tail in lines[i + 1:]:
                if tail.strip() and len(tail) - len(tail.lstrip()) <= depth:
                    break
                words += tail.split()
        else:
            words += got.group(1).split()
    if "uses:" in step:
        uses = re.search(r"uses: ([\w./-]+)", step).group(1)
        words.append(uses)
        for key in ("command", "arguments", "command-arguments"):
            for line in lines:
                got = re.match(rf" *{key}: *(.+)", line)
                if got:
                    words += got.group(1).split()
    return words


def tool_of(command):
    """Чем команда зовётся — одним словом, для поиска её шага в CI."""
    words = command.split()
    if words[0] == "cargo":
        return words[1]
    return pathlib.Path(words[-1]).name


bad = []

# Пропавший документ — не «чисто». Без этой проверки метёлка падала
# бы следом, и в отчёте вместо правила стоял бы разбор питона.
for needed in ("README.md", ".github/workflows/ci.yml"):
    if not (ROOT / needed).exists():
        print(f"{needed} не найден — метёлке нечего сверять")
        sys.exit(2)

commands = ladder_commands()
if commands is None:
    print("блок «Проверки» в README не разобрался — метёлка бесполезна")
    sys.exit(2)
if len(commands) < 3:
    print(f"в лестнице README {len(commands)} команд — метёлка отстала от кода")
    sys.exit(2)

steps = ci_steps()
if len(steps) < 3:
    print(f"в ci.yml разобралось {len(steps)} шагов — метёлка отстала от кода")
    sys.exit(2)

for command in commands:
    if command in EXCEPTIONS:
        continue
    tool = tool_of(command)
    # Шаг ищется по имени средства: `cargo deny` живёт в CI действием
    # `cargo-deny-action`, а не голой командой, и искать надо обоими.
    found = [s for s in steps if tool in ci_command_words(s) or any(tool in w for w in ci_command_words(s))]
    if not found:
        bad.append(f"{command!r}: в лестнице README есть, шага в ci.yml нет")
        continue
    if len(found) > 1:
        bad.append(f"{command!r}: шагов в ci.yml несколько — какой из них лестница, непонятно")
        continue

    # Доводы сверяются множествами: порядок значения не имеет, а лишний
    # и недостающий — имеют оба. Наша поломка была именно «в CI довод
    # есть, в README нет».
    want = set(command.split()) - {"cargo", tool}
    got = set(ci_command_words(found[0])) - {"cargo", tool}
    # Имя действия и путь к скрипту доводами не считаются.
    got = {w for w in got if not w.endswith("-action@v2") and "/" not in w}
    want = {w for w in want if "/" not in w}
    if want != got:
        only_readme = sorted(want - got)
        only_ci = sorted(got - want)
        detail = []
        if only_readme:
            detail.append(f"только в README: {' '.join(only_readme)}")
        if only_ci:
            detail.append(f"только в ci.yml: {' '.join(only_ci)}")
        bad.append(f"{command!r}: доводы разошлись — {'; '.join(detail)}")

print("\n".join(bad) if bad else f"чисто (команд в лестнице: {len(commands)}, шагов в ci.yml: {len(steps)})")
sys.exit(1 if bad else 0)
