# Развёртка: новый ярлык обязан попасть в три места сразу — `labels::ALL`,
# список контекстов генератора и файл векторов. Пропусти одно — падает
# `every_label_is_covered_by_a_vector`, и падает у Никиты.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]

root = ROOT_DIR

src = (root / 'crates/crypto/src/labels.rs').read_text()
declared = dict(re.findall(r'pub const (\w+): &str = "([^"]+)";', src))
in_all = set(re.findall(r'\b(\w+),', re.search(r'pub const ALL: \[&str; \d+\] = \[(.*?)\];', src, re.S).group(1)))
gen = (root / 'tools/gen_vectors.py').read_text()
in_gen = set(re.findall(r'\b(\w+),?\s*\]?', re.search(r'ALL_CONTEXTS = \[(.*?)\]', gen, re.S).group(1)))
vectors = (root / 'crates/crypto/tests/vectors/derive_key.txt').read_text()

bad = 0
for name, text in declared.items():
    if name not in in_all:
        print(f'{name} ({text!r}) — нет в labels::ALL'); bad += 1
    if name not in in_gen:
        print(f'{name} ({text!r}) — нет в ALL_CONTEXTS генератора'); bad += 1
    if text not in vectors:
        print(f'{name} ({text!r}) — нет ни одного вектора'); bad += 1
n = int(re.search(r'pub const ALL: \[&str; (\d+)\]', src).group(1))
if n != len(declared):
    print(f'длина ALL — {n}, а ярлыков объявлено {len(declared)}'); bad += 1
print('чисто' if not bad else f'-- пробелов {bad}')
