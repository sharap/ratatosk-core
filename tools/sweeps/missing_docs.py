# Развёртка: публичные вещи без документации в крейтах с #![warn(missing_docs)].
# Ловит в том числе случай, когда новый элемент вставлен ВНУТРЬ чужого
# доккомментария: пострадавший остаётся без документации и всплывает здесь.
#
# **Варианты перечисления и публичные поля — тоже.** Заголовок обещал это
# с самого начала, а проверялись только `pub`-элементы: вариант `pub` не
# бывает, и вставка между чужим описанием и его вариантом проходила молча.
# Ровно так и случилось: новый вариант команды уехал между `/// Переслать
# сообщения…` и `ForwardMessages`, и та осталась без описания.
# Компилятор это ловит (`missing_docs` срабатывает и на вариантах,
# и на публичных полях), а метелка — не ловила: обещала больше, чем
# проверяла. Хуже, чем не обещать вовсе, — на неё полагались.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


root = ROOT_DIR / "crates"
ITEM = re.compile(
    # `pub(crate)` и `pub(super)` наружу крейта не видны, и `missing_docs`
    # на них не срабатывает. Свёртка обязана повторять компилятор,
    # а не быть строже: лишние находки учат не читать её вывод.
    r'^(?P<ind>[ ]*)pub(?!\s*\()\s+'
    r'((async|const|unsafe|extern|default)\s+)*'
    r'(?P<kind>fn|struct|enum|trait|type|mod|const|static|union)\s+(?P<name>\w+)')
MOD_OPEN = re.compile(r'^(?P<ind>[ ]*)(?P<vis>pub(\s*\([^)]*\))?\s+)?mod\s+(?P<name>\w+)\s*\{')
ATTR_END = re.compile(r'^\s*(#!?\[|///|//!|//)')

def module_documented(path, name, lines, idx):
    """`pub mod X;` документирован, если в файле модуля есть //!."""
    # модуль лежит либо рядом, либо в каталоге, названном родительским файлом
    homes = (path.parent, path.parent / path.stem)
    cands = [h / f'{name}.rs' for h in homes] + [h / name / 'mod.rs' for h in homes]
    for cand in cands:
        if cand.exists():
            return '//!' in cand.read_text()
    return False

def docs_above(lines, i):
    """Идём вверх через атрибуты (в т.ч. многострочные) к доккомментарию."""
    j, depth = i - 1, 0
    while j >= 0:
        s = lines[j].strip()
        if not s:
            return False
        depth += s.count(']') - s.count('[')
        if s.startswith('///') or s.startswith('/**'):
            return True
        if s.startswith('#[') or s.startswith('#!['):
            depth = 0
            j -= 1
            continue
        if depth > 0 or s.startswith('//'):
            j -= 1
            continue
        return False
    return False

def members_without_docs(lines):
    """Номера строк вариантов и публичных полей без описания.

    Тело `pub enum`/`pub struct` разбирается по отступу: члены стоят на
    четырёх пробелах, вложенное — глубже, и путать их нельзя.
    """
    out = []
    depth = 0
    kind = None
    for i, ln in enumerate(lines):
        if depth == 0:
            m = OUTER.match(ln)
            if m and ln.rstrip().endswith('{'):
                kind = m.group('kind')
                depth = 1
                continue
        else:
            # Глубина **на входе в строку**, а не после неё. Первая
            # редакция считала наоборот, и строка `Вариант {` уходила
            # на глубину два раньше, чем её успевали проверить: метелка
            # видела только варианты без полей, то есть почти ничего.
            # Поймано возвратом поломки — тем самым, ради которого она
            # и заводилась.
            entry = depth
            depth += ln.count('{') - ln.count('}')
            if depth <= 0:
                kind = None
                depth = 0
                continue
            if entry != 1:
                continue
            m = VARIANT.match(ln) if kind == 'enum' else FIELD.match(ln)
            if m and not docs_above(lines, i):
                out.append((i, ln.strip()[:90]))
    return out


OUTER = re.compile(r'^pub (?P<kind>enum|struct) \w+')
# Вариант перечисления: с большой буквы, на четырёх пробелах.
VARIANT = re.compile(r'^ {4}[A-Z]\w*\s*[({,]|^ {4}[A-Z]\w*\s*$')
# Публичное поле записи. Непубличное `missing_docs` не требует.
FIELD = re.compile(r'^ {4}pub \w+\s*:')

crates = [p.parent.parent for p in root.glob('*/src/lib.rs')
          if '#![warn(missing_docs)]' in p.read_text()]

bad = 0
for crate in sorted(crates):
    for f in sorted(crate.rglob('src/**/*.rs')):
        lines = f.read_text().splitlines()
        # отрезки строк внутри непубличных или тестовых модулей
        hidden = [False] * len(lines)
        stack = []  # (отступ, скрыт?)
        for i, ln in enumerate(lines):
            if stack and len(ln) - len(ln.lstrip()) <= stack[-1][0] and ln.strip().startswith('}'):
                stack.pop()
            m = MOD_OPEN.match(ln)
            if m:
                test = i > 0 and 'cfg(test)' in lines[i - 1]
                stack.append((len(m.group('ind')), (not m.group('vis')) or test))
            hidden[i] = any(h for _, h in stack)
        for i, ln in enumerate(lines):
            m = ITEM.match(ln)
            if not m or hidden[i]:
                continue
            if m.group('kind') == 'mod' and ln.rstrip().endswith(';'):
                if module_documented(f, m.group('name'), lines, i):
                    continue
            if docs_above(lines, i):
                continue
            bad += 1
            print(f'{f.relative_to(root.parent)}:{i + 1}: {ln.strip()[:90]}')
        for i, text in members_without_docs(lines):
            if hidden[i]:
                continue
            bad += 1
            print(f'{f.relative_to(root.parent)}:{i + 1}: {text}')
print('чисто' if not bad else f'-- всего {bad}')
