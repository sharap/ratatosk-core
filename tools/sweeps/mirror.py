#!/usr/bin/env python3
"""Метелка: поле, заведённое по эту сторону границы и потерянное по ту.

Компилятор ловит это только наполовину. Забудь я поле в записи FFI, но
напиши строку отображения — будет ошибка. Забудь я и то и другое — сборка
зелёная, а признак просто молча не переходит границу. Вот это и ищется.

Правило: у каждой функции `fn X_of(src: &Src) -> Dst` каждое поле `Src`
обязано быть прочитано в теле как `.поле`.

Поле, которому границу переходить **не положено**, называется в `SKIP`
вместе с причиной. Молчание превращается в написанное утверждение —
и ложное утверждение видно глазами, как и всё остальное в этом дереве.
Пустой `SKIP` был бы удобнее, но он же означал бы, что вид, нарочно
показывающий половину записи, метёлку не переживёт и её отключат целиком.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"
SRC = sorted(ROOT.glob("*/src/**/*.rs"))
TEXT = {p: p.read_text(encoding="utf-8") for p in SRC}


def fields_of(name):
    """Имена полей структуры `name`, где бы она ни лежала."""
    for path, text in TEXT.items():
        m = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{", text)
        if not m:
            continue
        depth, i = 0, m.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = text[m.end(): i]
        return set(re.findall(r"^\s*(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:", body, re.M))
    return None


def body_after(text, start):
    """Тело функции, начиная с её первой `{`."""
    i = text.index("{", start)
    depth, j = 0, i
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i: j + 1]
        j += 1
    return text[i:]


# Чему не положено переходить границу и почему. Ключ — имя функции и поле.
SKIP = {
    # Ссылка `ratatosk:v0:…` везёт карточку целиком, вместе с ключами
    # и именем; отдавать их вторым путём значило бы завести второе место,
    # где то же самое можно рассогласовать. Наружу они и не нужны: `ik`
    # и `sk` показывать человеку нечем, а имя он и так своё.
    ("own_card_of", "ik"): "уезжает ссылкой; показывать наружу нечем",
    ("own_card_of", "sk"): "то же самое",
    ("own_card_of", "display_name"): "своё имя клиент знает и без карточки",
    # Адрес для раннеров — это «куда ехать», и ничего сверх. Подпись,
    # имя и версия карточки к выбору дороги отношения не имеют, а всякое
    # лишнее поле здесь пришлось бы тащить через границу §13.3 в каждую
    # команду отправки.
    ("peer_address_of", "sk"): "подпись к выбору дороги отношения не имеет",
    ("peer_address_of", "display_name"): "имя не адрес",
    ("peer_address_of", "version"): "версия карточки — дело §4.3, не §5.4",
}

bad = []
pairs = 0
for path, text in TEXT.items():
    for m in re.finditer(
        # Тип может приехать по пути (`&ratatosk_core::GroupStatus`) —
        # берётся последний сегмент. Без этого свёртка молча пропускала
        # такие пары, то есть врала «чисто» ровно там, где смотреть надо.
        r"\bfn\s+([a-z_0-9]+)_of\s*\(\s*[a-z_0-9]+\s*:\s*&(?:[A-Za-z0-9_]+::)*([A-Za-z0-9_]+)\s*\)"
        r"\s*->\s*(?:[A-Za-z0-9_]+::)*([A-Za-z0-9_]+)",
        text,
    ):
        fn, src, dst = m.group(1) + "_of", m.group(2), m.group(3)
        src_fields = fields_of(src)
        dst_fields = fields_of(dst)
        if src_fields is None or dst_fields is None:
            continue
        # Зеркальная пара, а не любой помощник с именем на `_of`: у двух
        # сторон границы обязаны совпасть хотя бы два имени. Иначе это
        # просто функция, берущая что-то одно и делающая что-то другое.
        if len(src_fields & dst_fields) < 2:
            continue
        pairs += 1
        body = body_after(text, m.end())
        read = set(re.findall(r"\.([a-z_][a-z0-9_]*)\b", body))
        missed = sorted(f for f in src_fields - read if (fn, f) not in SKIP)
        if missed:
            bad.append((path, fn, src, dst, missed))

for path, fn, src, dst, missed in bad:
    rel = path.relative_to(ROOT.parent)
    print(f"{rel}: {fn}: {src} -> {dst}: не переходит границу: {', '.join(missed)}")

print(f"пар проверено: {pairs}; полей объявлено непереходящими: {len(SKIP)}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
