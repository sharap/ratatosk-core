# Развёртка: обёртка вокруг того, что уже обёрнуто. Ловит `Zeroizing::new(f(…))`
# и `Some(f(…))`, где `f` в этом же дереве объявлена возвращающей
# `Zeroizing<…>`/`Key32` или `Option<…>`. Это ровно та ошибка, которую
# компилятор ловит секундой, а я — только у Никиты.
import re, pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


root = ROOT_DIR / "crates"
SIG = re.compile(r'\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^;{]*?\)\s*->\s*([^{;]+)', re.S)

zeroizing, optional = set(), set()
for f in root.rglob('src/**/*.rs'):
    for name, ret in SIG.findall(f.read_text()):
        ret = ' '.join(ret.split())
        if ret.startswith('Key32') or ret.startswith('Zeroizing<'):
            zeroizing.add(name)
        if ret.startswith('Option<'):
            optional.add(name)

bad = 0
for f in sorted(root.rglob('**/*.rs')):
    for n, line in enumerate(f.read_text().splitlines(), 1):
        for name in re.findall(r'Zeroizing::new\(\s*(?:\w+::)*(\w+)\s*\(', line):
            if name in zeroizing:
                print(f'{f.relative_to(root.parent)}:{n}: Zeroizing::new({name}(…)) — {name} уже отдаёт Zeroizing')
                bad += 1
        for name in re.findall(r'(?<![\w:])Some\(\s*(?:\w+::)*(\w+)\s*\(', line):
            if name in optional:
                print(f'{f.relative_to(root.parent)}:{n}: Some({name}(…)) — {name} уже отдаёт Option')
                bad += 1
print('чисто' if not bad else f'-- всего {bad}')
