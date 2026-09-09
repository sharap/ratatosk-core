#!/usr/bin/env python3
"""Метелка: новый вариант перечисления против каждого разбора по нему.

Написана она была под `PayloadType` — и не помогла, когда я завёл пятый
вид `Action`: смотрела на одно перечисление, а ошибка случилась в другом,
той же формы. Поэтому список теперь таблица, и добавить в неё третье
перечисление стоит одной строки.

Правило: у каждого `match`, в ветках которого назван хоть один вариант
перечисления, либо есть голое `_` **на уровне веток**, либо перечислены
все варианты.

Две ошибки в ней самой стоит помнить, потому что обе давали «чисто»
на дыре — то есть худший из возможных исходов:

* `PayloadType::Unknown(_)` принималось за ветку по умолчанию. Это один
  названный вариант, а не «все прочие».
* Ветка по умолчанию искалась во **всём** теле разбора, включая вложенные.
  Один `_ => Some(*target)` внутри чужой ветки отключал проверку целиком.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"

# (имя перечисления, файл объявления, вариант-«всё остальное» или None)
WATCHED = [
    ("PayloadType", ROOT / "codec/src/envelope.rs", "Unknown"),
    ("Action", ROOT / "proto/src/group_action.rs", None),
    ("Transport", ROOT / "proto/src/transport_policy.rs", None),
    # Добавлены после того, как в оба разом приехало по варианту (ключ меша,
    # 0.2): разборы по ним живут и в ядре, и в стендах тестов, и пропущенная
    # ветка там — ошибка сборки у Никиты, а не находка здесь.
    ("Effect", ROOT / "core/src/io.rs", None),
    ("Command", ROOT / "core/src/io.rs", None),
    ("TransportCommand", ROOT / "transport/src/runner.rs", None),
    # Запросы к драйверу: разбор один, но забытая ветка там — не ошибка
    # сборки, а `unreachable`-рука или молчащий запрос, смотря как написано.
    ("Query", ROOT / "core/src/driver.rs", None),
    # Режим меша и его настройка (0.2). Оба разбираются в ядре, в FFI и
    # в стенде, и оба обязаны разбираться целиком: пропущенная ветка —
    # это молча неработающий режим, а не отказ.
    ("YggMode", ROOT / "proto/src/ygg.rs", None),
    ("YggSetup", ROOT / "proto/src/ygg.rs", None),
    ("FfiYggMode", ROOT / "ffi/src/lib.rs", None),
]

SOURCES = sorted(ROOT.glob("*/src/**/*.rs")) + sorted(ROOT.glob("*/tests/**/*.rs"))
TEXT = {p: p.read_text(encoding="utf-8") for p in SOURCES}


def braced(text, at):
    """Кусок от `{` в позиции `at` до парной ей `}`."""
    depth, i = 0, at
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[at: i + 1]
        i += 1
    return text[at:]


def variants_of(name, path, catch_all):
    src = path.read_text(encoding="utf-8")
    m = re.search(r"\benum\s+" + re.escape(name) + r"\s*\{", src)
    if not m:
        return None
    body = braced(src, m.end() - 1)
    found = set(re.findall(r"^    ([A-Z][A-Za-z0-9]*)\s*(?:,|\(|\{|$)", body, re.M))
    if catch_all:
        found.discard(catch_all)
    return found


def arm_lines(arms):
    """Строки на уровне самих веток, без содержимого их тел."""
    out = []
    depth = 0
    for line in arms.splitlines():
        if depth == 1:
            out.append(line.strip())
        depth += line.count("{") + line.count("(") + line.count("[")
        depth -= line.count("}") + line.count(")") + line.count("]")
    return out


def pattern_texts(lines, name):
    """Куски строк веток, в которых стоят образцы.

    Отличать приходится от аргумента функции, вынесенного на свою строку
    (`PayloadType::CompanionResponse,`): он выглядит как начало ветки
    до последнего знака. Разница в нём и есть — у образца строка либо
    несёт `=>`, либо продолжается следующей (кончается самим вариантом
    или вертикальной чертой), а у аргумента она кончается запятой.

    Берётся **весь** образец, а не его начало. Первая редакция смотрела
    только на первый вариант в строке, и `Lan | Onion => true` читался
    как «Onion не назван» — то есть метелка ругалась на исправный разбор.
    Хуже: пропусти она так настоящую дыру, «чисто» ничего бы не значило.
    """
    out = []
    for line in lines:
        if "=>" in line:
            out.append(line.split("=>", 1)[0])
        # Продолжение образца с **начала** строки — так rustfmt и переносит
        # длинные перечисления вариантов. Без этой ветки метелка не видела
        # ни одной строки такого разбора, кроме первой и последней, — и
        # ругалась на исправный код шестью находками подряд.
        elif line.startswith("|"):
            out.append(line)
        # Хвост образца допускается: `Effect::Connect { .. }` — это **первая**
        # строка перенесённого перечисления, за ней идёт `| Effect::…`. Ни
        # `=>`, ни черты по краям у неё нет, и голым именем варианта она тоже
        # не является. Отличается от вынесенного аргумента по-прежнему одним:
        # у аргумента строка кончается запятой, у образца — нет.
        elif line.endswith("|") or re.fullmatch(
            rf"(?:\|\s*)?(?:&\s*)?(?:\w+\s*@\s*)?{name}::[A-Za-z0-9_]+"
            rf"(?:\s*\{{.*\}}|\s*\(.*\))?",
            line,
        ):
            out.append(line)
    return out


def is_pattern(patterns, name, variant):
    """Назван ли вариант **своим** образцом этого разбора.

    Образец делится по вертикальной черте, и каждая доля обязана
    начинаться с самого варианта. Так `Lan | Onion => …` засчитывает оба,
    а `Command::SetEnabled { transport: Transport::Lan, .. }` — ни одного:
    там разбирается другое перечисление, а `Transport::Lan` стоит вложенным
    образцом внутри. Вторая половина правила не украшение: без неё метелка
    требовала бы полноты по `Transport` от разбора команд.
    """
    # `Some(` и `Ok(` снимаются, и только они. Разбор `Option<Transport>`
    # обязан быть полным по `Transport` так же, как разбор самого транспорта,
    # — а вот произвольная обёртка `ЧужойВариант(Transport::Ygg)` означает
    # разбор **чужого** перечисления, и требовать полноты там нельзя.
    # Путь перед именем снимается: `ratatosk_proto::Transport::Lan` — тот же
    # образец, что и `Transport::Lan`. Без этого метелка молча пропускала
    # разборы, писавшие полный путь, — и «чисто» ничего не значило.
    head = re.compile(
        rf"^(?:Some\(|Ok\()?(?:&\s*)?(?:\w+\s*@\s*)?(?:\w+::)*{name}::{variant}\b"
    )
    for text in patterns:
        if any(head.match(part.strip()) for part in text.split("|")):
            return True
    return False


bad = []
checked = 0
for name, decl, catch_all in WATCHED:
    variants = variants_of(name, decl, catch_all)
    if not variants:
        print(f"перечисление {name} не разобралось — метелка бесполезна")
        sys.exit(2)
    for path, src in TEXT.items():
        for m in re.finditer(r"\bmatch\s+[^{;]{0,80}?\{", src):
            lines = arm_lines(braced(src, m.end() - 1))
            patterns = pattern_texts(lines, name)
            named = {v for v in variants if is_pattern(patterns, name, v)}
            if not named:
                continue
            checked += 1
            if any(re.match(r"^_\s*(?:=>|\|)", line) for line in lines):
                continue
            missing = sorted(variants - named)
            if missing:
                line_no = src[: m.start()].count("\n") + 1
                bad.append((path, line_no, name, missing))

for path, line_no, name, missing in bad:
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}:{line_no}: разбор {name} без ветки по умолчанию, не назван: {', '.join(missing)}")

print(f"перечислений под присмотром: {len(WATCHED)}; разборов проверено: {checked}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
