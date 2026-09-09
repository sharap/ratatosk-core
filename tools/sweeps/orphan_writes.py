# Развёртка: поле, которое пишут, но нигде не объявляют, — след скрипта,
# упавшего на середине. Ищет `self.<имя> =` и сверяет с объявлениями
# полей в структурах того же файла.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]

root = ROOT_DIR / "crates"
FIELD = re.compile(r'^\s+(?:pub(?:\s*\([^)]*\))?\s+)?(\w+):\s', re.M)
WRITE = re.compile(r'self\.(\w+)\s*=[^=]')
bad = 0
for f in sorted(root.rglob('src/**/*.rs')):
    text = f.read_text()
    declared = set(FIELD.findall(text))
    for name in sorted(set(WRITE.findall(text))):
        if name not in declared:
            print(f'{f.relative_to(root.parent)}: self.{name} = … — поля нет')
            bad += 1
print('чисто' if not bad else f'-- всего {bad}')
