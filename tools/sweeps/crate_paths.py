"""Сверяет пути `крейт::Имя`, которыми пользуются другие крейты, с тем,
что этот крейт на самом деле отдаёт из корня.

Заведён после `open_snapshot`: функция была объявлена `pub` в модуле,
но забыта в `pub use`, и сборка сказала об этом только у Никиты.
Компилятор ловит это всегда — но только когда доходит до сборки, а здесь
её нет. Сверка текстом дешевле круга через человека.
"""
import re, glob, os, sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


roots = {}          # имя крейта -> что отдаёт корень
for lib in glob.glob(str(ROOT_DIR / 'crates/*/src/lib.rs')):
    crate = 'ratatosk_' + lib.split('/')[1].replace('ratatosk-', '').replace('-', '_')
    s = open(lib, encoding='utf-8').read()
    names = set()
    for m in re.finditer(r'^pub use ([\w:]+)::\{(.*?)\};', s, re.M | re.S):
        names |= {n.strip().split(' as ')[-1] for n in m.group(2).split(',') if n.strip()}
    for m in re.finditer(r'^pub use [\w:]+::(\w+);', s, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^pub (?:mod|const|static) (\w+)', s, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^pub (?:fn|struct|enum|trait|type) (\w+)', s, re.M):
        names.add(m.group(1))
    for m in re.finditer(r'^pub async fn (\w+)', s, re.M):
        names.add(m.group(1))
    roots[crate] = names

bad = 0
sources = glob.glob(str(ROOT_DIR / 'crates/*/src/**/*.rs'), recursive=True) + glob.glob(
    str(ROOT_DIR / 'crates/*/tests/*.rs')
)
for path in sources:
    text = open(path, encoding='utf-8').read()
    # Имя своего крейта — по сегменту **после** `crates`, а не по второму
    # сегменту пути: пути теперь абсолютные, и второй сегмент это `home`.
    parts = path.split('/')
    own = 'ratatosk_' + parts[parts.index('crates') + 1].replace('ratatosk-', '').replace('-', '_')
    for crate, names in roots.items():
        if crate == own:
            continue
        for m in re.finditer(re.escape(crate) + r'::(\w+)', text):
            name = m.group(1)
            if name in names or name[0].islower() and name in names:
                continue
            if name not in names:
                line = text[:m.start()].count('\n') + 1
                print(f"{path}:{line}: {crate}::{name} — корень крейта этого не отдаёт")
                bad += 1
print("чисто" if not bad else f"расхождений: {bad}")
sys.exit(0)
