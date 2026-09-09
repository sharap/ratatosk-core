"""Свёртка: конструкции записи собраны со **всеми** полями.

Заведена после того, как поле `author` у `companion::Message` было
добавлено в трёх файлах из четырёх. Компилятор поймал бы это — но только
там, куда я дал ему посмотреть: `cargo` в этом дереве не запускается,
и «поймает сборка» на деле означает «поймает человек за другим экраном».

Проверяется буквально: у каждого `Имя { ... }` в дереве — те же имена
полей, что объявлены у `pub struct Имя`. Записи со «..остальное» и
одноимённые типы из разных крейтов пропускаются вслух: молча пропущенная
проверка хуже отсутствующей.
"""
import re, pathlib, sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"
FILES = sorted(ROOT.rglob('*.rs'))

# --- объявления записей
declared: dict[str, set[str]] = {}
dupes: set[str] = set()
for path in FILES:
    src = path.read_text(encoding='utf-8')
    for m in re.finditer(r'\bpub struct (\w+) \{', src):
        name = m.group(1)
        i = m.end() - 1
        depth = 0
        for j in range(i, len(src)):
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    break
        body = src[i:j]
        fields = set(re.findall(r'^\s*pub (\w+):', body, re.M))
        if not fields:
            continue
        if name in declared and declared[name] != fields:
            dupes.add(name)
        declared[name] = fields

for name in sorted(dupes):
    print(f'пропущено (одноимённых объявлений несколько): {name}')
    declared.pop(name, None)

def strip_comments(body: str) -> str:
    """Убирает `//`-комментарии, **не трогая строковые значения**.

    Наивное `re.sub(r'//[^\\n]*', '', body)` резало по первому `//`,
    где бы оно ни стояло, — в том числе внутри строки. Одного адреса
    вида `"tls://пир.example:1337"` хватало, чтобы срезать хвост строки
    вместе с закрывающей кавычкой: дальше тело читалось как одна
    незакрытая строка, и все поля за ней пропадали из вида. Свёртка
    объявляла неполной сборку, где не хватало ровно ничего.

    Отсюда правило: состояние строки считается **один раз** и для
    комментариев, и для деления по запятым.
    """
    out = []
    in_string = False
    prev = ''
    skip_line = False
    for n, ch in enumerate(body):
        if skip_line:
            if ch == '\n':
                skip_line = False
                out.append(ch)
            prev = ch
            continue
        if in_string:
            out.append(ch)
            if ch == '"' and prev != '\\':
                in_string = False
            # Экранированная обратная косая закрывает сама себя: без этого
            # `"путь\\"` читался бы как продолжающаяся строка.
            prev = '' if (ch == '\\' and prev == '\\') else ch
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
        elif ch == '/' and body[n + 1 : n + 2] == '/':
            skip_line = True
        else:
            out.append(ch)
        prev = ch
    return ''.join(out)


def top_level_fields(body: str) -> set[str]:
    """Имена полей на верхнем уровне тела записи.

    Делить регулярным выражением нельзя: значение поля бывает вложенной
    записью, вызовом в несколько строк, массивом с запятыми. Поэтому
    запятые считаются с глубиной, а из каждой части берётся `имя:`
    либо сокращённое `имя`.
    """
    # Комментарии убираются **до** деления, а не после: запятая внутри
    # комментария иначе делит тело не там, и поле, стоящее за ней,
    # перестаёт быть началом части. Ровно на этом свёртка и промолчала
    # в первой версии — поймав `author` не везде.
    body = strip_comments(body)

    parts: list[str] = []
    depth = 0
    current = ''
    in_string = False
    prev = ''
    for ch in body[1:]:  # тело приходит вместе с открывающей скобкой
        if in_string:
            current += ch
            if ch == '"' and prev != '\\':
                in_string = False
            prev = ch
            continue
        if ch == '"':
            in_string = True
            current += ch
        elif ch in '{[(':
            depth += 1
            current += ch
        elif ch in '}])':
            if depth == 0:
                break
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += ch
        prev = ch
    parts.append(current)

    names: set[str] = set()
    for part in parts:
        cleaned = part.strip()
        if not cleaned:
            continue
        m = re.match(r'^(\w+)\s*(?::|$)', cleaned)
        if m:
            names.add(m.group(1))
    return names


def enum_spans(src: str) -> list[tuple[int, int]]:
    """Границы тел `enum` — внутри них записи не собирают, а объявляют.

    Вариант перечисления с полями выглядит в точности как сборка записи,
    и одноимённый вариант (`Query::Message` против `companion::Message`)
    свёртка иначе объявляет неполной сборкой.
    """
    spans = []
    for m in re.finditer(r'\benum \w+ \{', src):
        i = m.end() - 1
        depth = 0
        for j in range(i, len(src)):
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    break
        spans.append((i, j))
    return spans


bad = 0
skipped_rest = 0
for path in FILES:
    src = path.read_text(encoding='utf-8')
    spans = enum_spans(src)
    # Путь перед именем берётся вместе с именем, а само имя — последний
    # сегмент. Первая редакция запрещала двоеточие перед именем целиком,
    # и `crate::runner::PeerAddress { … }` не проверялся вовсе. Стоило это
    # трёх ошибок сборки у Никиты на ровном месте: метелка сказала «чисто»,
    # а полей не хватало в трёх местах одного файла.
    for m in re.finditer(r'(?<![\w:])((?:\w+::)*)(\w+) \{', src):
        if any(start <= m.start() <= end for start, end in spans):
            continue
        # Путь из **модулей** — это та же запись, просто названная полностью
        # (`crate::runner::PeerAddress`). Путь, где последний сегмент с
        # большой буквы, — это вариант перечисления (`Request::FileOffer`),
        # и к одноимённой записи он отношения не имеет. Различаются они
        # соглашением языка: модули со строчной, типы с прописной.
        if m.group(1) and not re.fullmatch(r'(?:[a-z_]\w*::)+', m.group(1)):
            continue
        name = m.group(2)
        if name not in declared:
            continue
        # Отсеиваем объявление самой записи и разбор в `match`.
        before = src[max(0, m.start() - 40):m.start()]
        if before.rstrip().endswith('struct') or 'pub struct' in before:
            continue
        i = m.end() - 1
        depth = 0
        for j in range(i, len(src)):
            if src[j] == '{':
                depth += 1
            elif src[j] == '}':
                depth -= 1
                if depth == 0:
                    break
        body = src[i:j]
        if '..' in body:
            skipped_rest += 1
            continue
        used = top_level_fields(body)
        missing = declared[name] - used
        # Разбор в образце (`Имя { поле, .. }`) отсеян выше; здесь остаётся
        # либо сборка, либо разбор без остатка — у обоих поля обязаны быть все.
        if missing and used & declared[name]:
            line = src[:m.start()].count('\n') + 1
            rel = path.relative_to(ROOT.parent)
            print(f'{rel}:{line}: {name} — нет полей: {", ".join(sorted(missing))}')
            bad += 1

print(f'записей под присмотром: {len(declared)}; со «..остальное» пропущено: {skipped_rest}')
print('чисто' if not bad else f'НАХОДОК: {bad}')
sys.exit(0 if not bad else 1)
