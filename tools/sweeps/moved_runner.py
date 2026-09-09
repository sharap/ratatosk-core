# Развёртка: значение, уехавшее в конструктор, использованное после.
# Только те конструкторы, что **забирают** раннеры целиком, — там я эту
# ошибку и делаю.
#
# Конец функции считается по скобкам, а не по виду строки: вложенный блок
# закрывается такой же скобкой, и первая же попытка «ловить `}`» обрывала
# просмотр до настоящей ошибки. Строковые литералы и поля чужих структур
# (`invite.onion`) отсеиваются отдельно — на них развёртка кричала впустую.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


root = ROOT_DIR / "crates"
EATS = re.compile(r'\b(?:Transports::new|CompanionDriver::new|Driver::new|Switched::new)\s*\(([^)]*)\)')

def bare_use(line, name):
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '', line)
    stripped = re.sub(r'//.*$', '', stripped)
    return re.search(rf'(?<![.\w]){name}\b\s*[.\[]', stripped) is not None

bad = 0
for f in sorted(root.rglob('**/*.rs')):
    lines = f.read_text().splitlines()
    for i, line in enumerate(lines):
        m = EATS.search(line)
        if not m:
            continue
        names = [a.strip() for a in m.group(1).split(',')
                 if re.fullmatch(r'[a-z_][a-z0-9_]*', a.strip())]
        if not names:
            continue
        for j in range(i + 1, len(lines)):
            # Конец просмотра — следующее определение функции, а не скобка:
            # конструктор часто стоит внутри блока (`#[cfg] let runner = {…}`),
            # и по скобкам просмотр обрывался, не дойдя до ошибки.
            if re.match(r'^\s{0,4}(?:pub\s+)?(?:async\s+)?fn\s', lines[j]):
                break
            for name in list(names):
                if bare_use(lines[j], name):
                    print(f'{f.relative_to(root.parent)}:{j+1}: `{name}` уехал в конструктор '
                          f'на строке {i+1}, а здесь снова нужен')
                    bad += 1
                    names.remove(name)
            if not names:
                break
print('чисто' if not bad else f'-- всего {bad}')
