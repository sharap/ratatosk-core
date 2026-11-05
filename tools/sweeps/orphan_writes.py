# Развёртка: поле, которое пишут, но нигде не объявляют, — след скрипта,
# упавшего на середине. Ищет `self.<имя> =` и сверяет с объявлениями
# полей в структурах этого файла **и всех его родительских модулей**.
#
# Родители обязательны, и без них метелка была бесполезна: `impl Engine`
# разнесён по `engine/*.rs`, а поля объявлены в `engine.rs`, то есть
# в другом файле. Двадцать шесть ложных находок — все до одной из этих
# файлов, и настоящую поломку среди них было бы не разглядеть.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]

root = ROOT_DIR / "crates"
FIELD = re.compile(r'^\s+(?:pub(?:\s*\([^)]*\))?\s+)?(\w+):\s', re.M)
WRITE = re.compile(r'self\.(\w+)\s*=[^=]')
def parents_of(path):
    """Файлы родительских модулей — вверх до корня крейта.

    `crates/core/src/engine/setup.rs` -> `crates/core/src/engine.rs`
    (и `engine/mod.rs`, если дерево собрано так), дальше `src/lib.rs`.
    """
    out = []
    cur = path
    while True:
        folder = cur.parent
        if folder.name == 'src' or folder == root or folder.parent == folder:
            break
        for cand in (folder.with_suffix('.rs'), folder / 'mod.rs'):
            if cand.exists() and cand != cur:
                out.append(cand)
        cur = folder
    src = path
    while src.parent.name != 'src' and src.parent != src:
        src = src.parent
    for cand in (src.parent / 'lib.rs', src.parent / 'main.rs'):
        if cand.exists() and cand != path:
            out.append(cand)
    return out


bad = 0
seen = 0
for f in sorted(root.rglob('src/**/*.rs')):
    text = f.read_text()
    declared = set(FIELD.findall(text))
    for parent in parents_of(f):
        declared |= set(FIELD.findall(parent.read_text()))
    for name in sorted(set(WRITE.findall(text))):
        seen += 1
        if name not in declared:
            print(f'{f.relative_to(root.parent)}: self.{name} = … — поля нет')
            bad += 1
print(f'записей в поля осмотрено: {seen}')
print('чисто' if not bad else f'-- всего {bad}')

# Находок должно быть **ноль**. Возврат обязателен: метелка печатала
# двадцать шесть находок и возвращала ноль, поэтому `run_all` считал
# её чистой.
import sys
sys.exit(1 if bad else 0)
