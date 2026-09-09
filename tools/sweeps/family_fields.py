#!/usr/bin/env python3
"""Метелка: семью полей заполняют целиком или не трогают вовсе.

Заведена по находке, которая выглядела как «ключ меша не доезжает до
собеседника». Доезжал он прекрасно — не поднималась **ступень**: из трёх
путей контакта (`has_ygg`, `has_onion`, `has_chatmail`) обновление карточки
пересчитывало два. Третий оставался таким, каким был при знакомстве, то есть
ложным навсегда — до перезапуска, где `restore` считает всё с диска заново
и всё сходится. Хуже места для расхождения не придумать: на стенде беда
чинится перезапуском и потому не воспроизводится.

Тот же пропуск нашёлся и при добавлении контакта, и там он прикрыт
`..PeerAvailability::default()` — то есть компилятор молчит по построению.
Ровно поэтому правило смотрит **не** на полноту записи (её стережёт
`record_fields`), а на полноту семьи:

    названо хоть одно поле семьи — обязаны быть названы все.

Не названо ни одного — сборка не про эту семью, и требовать нечего:
`PeerAvailability { enabled, ready, seen_on_lan, ..availability }` законно
достраивает соседнюю половину и путей не касается.

Проверяются два вида мест: сборка записи `Имя { … }` и подряд идущие
присваивания `что-то.поле = …`. Тесты — и файлы `tests/`, и модули
`#[cfg(test)]` — не смотрятся вовсе, и это не послабление: заготовка теста
**обязана** быть неполной. «Контакт, до которого только по локальной сети»
— половина смысла набора проверок лестницы, и требовать от неё всех трёх
путей значило бы запретить проверять §5.4.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"

# (запись, файл объявления, приставка семьи)
WATCHED = [
    ("PeerAvailability", ROOT / "proto/src/transport_policy.rs", "has_"),
]

SOURCES = sorted(ROOT.glob("*/src/**/*.rs"))


def without_tests(src):
    """Тело `#[cfg(test)] mod tests` вырезается, строки — сохраняются."""
    m = re.search(r"#\[cfg\(test\)\]\s*\nmod\s+\w+\s*\{", src)
    if not m:
        return src
    depth, i = 0, src.index("{", m.end() - 1)
    start = i
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    cut = src[start: i + 1]
    return src[:start] + "\n" * cut.count("\n") + src[i + 1:]


def uncomment(text):
    """Строчные комментарии снимаются, переводы строк — остаются.

    Снимать их надо **до** разбора на поля, а не после: в русском
    комментарии запятых больше, чем в коде, и разрез по запятой уводил
    начало поля в середину фразы. Первая редакция снимала их после —
    и объявляла неполной запись, где всё было названо.
    """
    return re.sub(r"//[^\n]*", "", text)


TEXT = {p: without_tests(p.read_text(encoding="utf-8")) for p in SOURCES}


def braced(text, at):
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


def family_of(name, path, prefix):
    src = path.read_text(encoding="utf-8")
    m = re.search(r"\bstruct\s+" + re.escape(name) + r"(?:<[^>]*>)?\s*\{", src)
    if not m:
        return None
    body = braced(src, m.end() - 1)
    return {
        f.group(1)
        for f in re.finditer(
            r"^\s{4}(?:pub(?:\([^)]*\))?\s+)?(" + prefix + r"\w+)\s*:", body, re.M
        )
    }


def top_names(body):
    """Имена полей, названные на верхнем уровне тела записи."""
    inner = uncomment(body[1:-1])
    depth, start, chunks = 0, 0, []
    for i, c in enumerate(inner):
        if c in "{([":
            depth += 1
        elif c in "})]":
            depth -= 1
        elif c == "," and depth == 0:
            chunks.append(inner[start:i])
            start = i + 1
    chunks.append(inner[start:])
    out = set()
    for chunk in chunks:
        text = " ".join(l.strip() for l in chunk.splitlines()).strip()
        m = re.match(r"^(\w+)\s*(?::|,|$)", text)
        if m:
            out.add(m.group(1))
    return out


bad = []
places = 0
for name, decl, prefix in WATCHED:
    family = family_of(name, decl, prefix)
    if not family:
        print(f"семья {prefix}* записи {name} не разобралась — метелка бесполезна")
        sys.exit(2)
    for path, src in TEXT.items():
        # --- сборки записи ---
        for m in re.finditer(r"\b" + name + r"\s*\{", src):
            head = src[max(0, m.start() - 40): m.start()]
            if re.search(r"\b(?:struct|enum|trait|impl|union)\s+$", head):
                continue
            named = top_names(braced(src, m.end() - 1)) & family
            if not named:
                continue
            places += 1
            if named != family:
                at = src[: m.start()].count("\n") + 1
                bad.append((path, at, name, "сборка", sorted(family - named)))

        # --- подряд идущие присваивания ---
        lines = src.splitlines()
        i = 0
        assign = re.compile(r"^\s*[\w.\[\]()]+\.(" + prefix + r"\w+)\s*=")
        while i < len(lines):
            m = assign.match(lines[i])
            if not m:
                i += 1
                continue
            start, named = i, set()
            while i < len(lines):
                m2 = assign.match(lines[i])
                if m2:
                    named.add(m2.group(1))
                    i += 1
                elif lines[i].strip().startswith("//") or not lines[i].strip():
                    i += 1
                else:
                    break
            named &= family
            if named:
                places += 1
                if named != family:
                    bad.append((path, start + 1, name, "присваивания", sorted(family - named)))

for path, at, name, kind, missing in sorted(set(map(lambda t: (t[0], t[1], t[2], t[3], tuple(t[4])), bad))):
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}:{at}: {kind} {name} трогает семью не целиком — забыто: {', '.join(missing)}")

print(f"мест проверено: {places}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
