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
DECL = re.compile(r'\bfn\s+(\w+)')

# Имя считается обёрнутым, только если **все** его объявления в дереве
# отдают обёртку. Иначе однофамильцы ловятся вместо ошибки: `fn start`
# в дереве два десятка, и один из них (`lab`, проба ступени) отдаёт
# `Option<Probe>` — после чего всякий `Some(start(…))` где угодно считался
# находкой. Так пришли семь ложных: `start`, `address`, `from_bytes`,
# `decode` — имена слишком частые, чтобы различать их по имени.
#
# Цена правила названа прямо: **неоднозначное имя метелка пропускает.**
# Обёртка вокруг обёрнутого в функции, у которой есть однофамилец
# с другим возвратом, здесь не ловится — ловит компилятор.
decls, zeroizing_ret, optional_ret = {}, {}, {}
for f in root.rglob('src/**/*.rs'):
    text = f.read_text()
    for name in DECL.findall(text):
        decls[name] = decls.get(name, 0) + 1
    for name, ret in SIG.findall(text):
        ret = ' '.join(ret.split())
        if ret.startswith('Key32') or ret.startswith('Zeroizing<'):
            zeroizing_ret[name] = zeroizing_ret.get(name, 0) + 1
        if ret.startswith('Option<'):
            optional_ret[name] = optional_ret.get(name, 0) + 1

zeroizing = {n for n, k in zeroizing_ret.items() if decls.get(n, 0) == k}
optional = {n for n, k in optional_ret.items() if decls.get(n, 0) == k}

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
print(f'имён однозначных: {len(zeroizing) + len(optional)}, объявлений осмотрено: {sum(decls.values())}')
print('чисто' if not bad else f'-- всего {bad}')

# Находок должно быть **ноль**. Возврат обязателен: метелка печатала
# находки и возвращала ноль, поэтому `run_all` считал её чистой.
import sys
sys.exit(1 if bad else 0)
