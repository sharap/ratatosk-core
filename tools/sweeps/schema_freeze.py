import re, sqlite3, sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]

src = open(ROOT_DIR / "crates/store/src/schema.rs", encoding='utf-8').read()

def fnv(s: str) -> int:
    h = 0xcbf29ce484222325
    for b in s.encode('utf-8'):
        h ^= b
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

# Тексты миграций
migs = dict(re.findall(r'pub const (MIGRATION_\d+): &str = r#"(.*?)"#;', src, re.S))
version = int(re.search(r'pub const SCHEMA_VERSION: u32 = (\d+);', src).group(1))

def arr(name):
    m = re.search(r'const %s: \[([^;\]]+); (\d+)\] = \[(.*?)\n\s*\];' % name, src, re.S)
    body = m.group(3)
    return int(m.group(2)), body

n_m, body_m = arr('MIGRATIONS')
order = re.findall(r'MIGRATION_\d+', body_m)
n_f, body_f = arr('FROZEN')
frozen = [int(x.replace('_',''), 16) for x in re.findall(r'0x[0-9a-fA-F_]+', body_f)]

ok = True
if not (n_m == len(order) == version):
    print(f'ДЛИНА MIGRATIONS: объявлено {n_m}, элементов {len(order)}, версия {version}'); ok = False
if not (n_f == len(frozen) == version):
    print(f'ДЛИНА FROZEN: объявлено {n_f}, элементов {len(frozen)}, версия {version}'); ok = False

for i, name in enumerate(order):
    got = fnv(migs[name])
    if got != frozen[i]:
        print(f'{name}: контрольная сумма {got:#018x} != замороженной {frozen[i]:#018x}'); ok = False

n_t, body_t = arr('ALL_TABLES')
tables = re.findall(r'"([a-z_]+)"', body_t)
if n_t != len(tables):
    print(f'ДЛИНА ALL_TABLES: объявлено {n_t}, элементов {len(tables)}'); ok = False

db = sqlite3.connect(':memory:')
for name in order:
    db.executescript(migs[name])
have = {r[0] for r in db.execute("select name from sqlite_master where type='table'")}
missing = [t for t in tables if t not in have]
if missing:
    print('нет таблиц после миграций:', missing); ok = False
cols = {r[1] for r in db.execute('pragma table_info(chats)')}
for c in ('title_wall', 'title_logical'):
    if c not in cols:
        print(f'chats.{c} не появилась'); ok = False

print('чисто' if ok else 'ЕСТЬ РАСХОЖДЕНИЯ')
sys.exit(0 if ok else 1)
