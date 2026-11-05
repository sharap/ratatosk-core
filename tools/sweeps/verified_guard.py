"""Свёртка: `add_contact(..., false)` без проверки «уже знаем».

Зачем. `add_contact` ставит `verified` **по своему аргументу**, а не
сохраняет прежнее значение. Значит вызов с `false` для человека, которого
мы сверяли голосом, молча снимает сверку §4.2 — а сверка это единственное,
что отличает знакомого от того, кто прислал ссылку.

Все законные вызовы с `false` устроены одинаково: сперва `contains_key`,
и только для незнакомца — добавление. Свёртка требует того же от новых.
"""
import re, pathlib, sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


# Только внутренний помощник ядра: у границы UniFFI `add_contact` —
# другая функция и другое действие (человек нажал кнопку).
ROOT = ROOT_DIR / "crates/core/src"
WINDOW = 30
found = []
seen = 0

for path in ROOT.rglob("*.rs"):
    lines = path.read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines):
        if "self.add_contact(" not in line:
            continue
        # третий аргумент может стоять на этой же строке или ниже
        tail = "\n".join(lines[n:n + 6])
        if not re.search(r"add_contact\([^)]*\bfalse\b", tail, re.S):
            continue
        seen += 1
        window = "\n".join(lines[max(0, n - WINDOW):n])
        if "contains_key" not in window:
            found.append(f"{path}:{n+1}: {line.strip()}")

for f in found:
    print(f)
print(f"вызовов add_contact осмотрено: {seen}")
print("-- всего", len(found) if found else "чисто")

# Находок должно быть **ноль**.
#
# Возврат обязателен, и цену этого свёртка показала сама: её единственная
# находка была **настоящей** — ветка десктопа повторяла добавление своими
# руками, без проверки «уже знаем», и присланная карточка уводила маршрут
# знакомого к пришельцу. Печаталась она при этом в зелёный прогон:
# `sys.exit(0)` стоял в конце жёстко.
sys.exit(1 if found else 0)
