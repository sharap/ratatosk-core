#!/usr/bin/env python3
"""Метелка: настройку, поднятую с диска, обязан получить и раннер.

Заведена по находке со стенда, которая звучала так: «настройки yggdrasil
не сохраняются при перезапуске». Сохранялись они прекрасно — `restore`
поднимал их с диска и клал в ядро. Не доезжали они **вниз**:
`startup_effects` перечислял транспорты руками, тремя строками, и
появившийся четвёртым меш в этот список не попал; `Effect::SetYgg`
не отправлялся оттуда вовсе.

Наружу это выглядит как потеря настроек, а на деле — ядро знает, раннер
нет. Хуже всего то, что каждая половина по отдельности исправна: и запись
на диск, и подъём, и команда. Ошибка живёт **между** ними, и ни один тест
одной половины её не видит.

Правило первое: если эффект отправляется из обработчика настройки
(`on_set_*`), он обязан отправляться и из `startup_effects`. Иначе настройка
действует только до перезапуска — то есть работает ровно в том сеансе,
в котором её потрогали, и молча перестаёт после.

Правило второе, из той же поломки, но найденное отдельно и позже: внутри
`startup_effects` настройки обязаны идти **до** выключателей. Раннер
поднимается по той настройке, которая у него есть на момент включения;
приди «включить» раньше — он поднимет прежнюю, откажет, и приехавшая
следом настройка застанет ступень уже выключенной.

Наружу второе выглядело так: после перезапуска меш не работает, и чинится
выключением и включением руками. Настройка была на диске, была в ядре,
доехала до раннера — и всё равно не действовала, потому что доехала
второй. Первое правило при этом говорило «чисто».

Не считаются настройками и пропускаются вслух:

* `SetTimer` — это часы, а не настройка: срок, взведённый в прошлом
  запуске, восстанавливать бессмысленно;
* `Notify` — событие для UI, у которого нет прошлого;
* всё, что не начинается с `Set` и не названо в `EXTRA` ниже.
"""
import re
import sys
import pathlib

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]


ROOT = ROOT_DIR / "crates"
def engine_source():
    """Ядро целиком: `engine.rs` плюс его подмодули.

    После разделения (0.5) ядро — не один файл, а каталог. Метелка,
    читающая только `engine.rs`, нашла бы пустоту и отчиталась
    «чисто» — то есть соврала бы ровно в тот день, когда её стоило
    послушать. Читается всё разом: метелке безразлично, в каком
    модуле лежит проводка, ей важно, что проводка есть.
    """
    root = ROOT_DIR / "crates/core/src"
    parts = [(root / "engine.rs").read_text(encoding="utf-8")]
    parts += [p.read_text(encoding="utf-8") for p in sorted((root / "engine").glob("*.rs"))]
    return "\n".join(parts)


# Настройки, чьё имя не начинается с `Set`, но которые ими являются.
# Имя сменилось в 0.4 (`WatchLanPeers` → `WatchPeers`: эфиров стало два,
# а список контактов у них один). Старое имя здесь не оставлено нарочно:
# набор, в котором есть и то и другое, «чисто» говорил бы и про дерево,
# где эффект вовсе исчез.
EXTRA = {"WatchPeers"}

# Не настройки, хотя имя начинается с `Set`.
NOT_A_SETTING = {"SetTimer"}


def braced(text, at):
    depth, i = 0, at
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[at: i + 1]
        i += 1
    return text[at:]


def own_body_of(src, name):
    """Тело функции — **только своё**, без тел тех, кого она зовёт.

    Нужно ровно порядку: склеенное тело ставит эффекты помощника в конец
    независимо от того, где его позвали, и проверка порядка на нём врёт.
    Первая редакция так и врала — ругалась на исправный подъём.
    """
    m = re.search(r"\n    (?:pub )?(?:pub\(super\) )?(?:const )?fn " + re.escape(name) + r"\b", src)
    if not m:
        return None
    return braced(src, src.index("{", m.end()))


def body_of(src, name):
    """Тело функции с этим именем, вместе с телами тех, кого она зовёт.

    Один уровень вглубь, и этого хватает: обработчик настройки либо
    отправляет эффект сам, либо делегирует одному помощнику
    (`apply_transport`, `apply_ygg`). Два уровня уже утащили бы половину
    ядра и превратили бы правило в «эффект встречается где-нибудь».
    """
    m = re.search(r"\n    (?:pub )?(?:pub\(super\) )?(?:const )?fn " + re.escape(name) + r"\b", src)
    if not m:
        return None
    start = src.index("{", m.end())
    body = braced(src, start)
    for callee in set(re.findall(r"self\.(\w+)\(", body)):
        m2 = re.search(r"\n    (?:pub )?(?:pub\(super\) )?(?:const )?fn " + re.escape(callee) + r"\b", src)
        if m2:
            body += braced(src, src.index("{", m2.end()))
    return body


def settings_in(body):
    found = set(re.findall(r"Effect::([A-Z]\w*)", body))
    return {v for v in found if (v.startswith("Set") or v in EXTRA) and v not in NOT_A_SETTING}


src = engine_source()

startup = body_of(src, "startup_effects")
if startup is None:
    print("`startup_effects` не найдена — метелка бесполезна")
    sys.exit(2)
pushed = settings_in(startup)

handlers = sorted(set(re.findall(r"\n    (?:pub )?(?:pub\(super\) )?fn (on_set_\w+)\b", src)))
if not handlers:
    print("обработчиков настроек не найдено — метелка бесполезна")
    sys.exit(2)

bad = []
for name in handlers:
    body = body_of(src, name)
    if body is None:
        continue
    for variant in sorted(settings_in(body) - pushed):
        bad.append((name, variant))

# --- порядок внутри самого подъёма ---
#
# Выключателем считается `SetTransportEnabled`: он и есть та команда,
# по которой раннер поднимается. Всё прочее из семьи настроек обязано
# стоять раньше него.
SWITCH = "SetTransportEnabled"

# Порядок читается по **своему** телу, а зов помощника считается за те
# эффекты, которые помощник отдаёт, — в той точке, где его позвали.
# Иначе `effects.push(self.watch_peers())` не виден вовсе: своего
# литерала `Effect::` у него нет.
own = own_body_of(src, "startup_effects") or ""
order = []
for m in re.finditer(r"Effect::([A-Z]\w*)|self\.(\w+)\(", own):
    if m.group(1):
        order.append(m.group(1))
        continue
    helper = own_body_of(src, m.group(2))
    if helper:
        order.extend(sorted(settings_in(helper)))
if SWITCH in order:
    first_switch = order.index(SWITCH)
    for i, variant in enumerate(order):
        if i <= first_switch:
            continue
        if variant in pushed and variant != SWITCH:
            bad.append(("startup_effects", f"{variant}-после-{SWITCH}"))

for name, variant in bad:
    if variant.endswith(f"-после-{SWITCH}"):
        late = variant.split("-после-")[0]
        print(f"startup_effects отправляет Effect::{late} после Effect::{SWITCH}:")
        print("    раннер включится по прежней настройке и откажет, а новая")
        print("    застанет ступень уже выключенной — настройки поедут вторыми")
        continue
    print(f"{name} отправляет Effect::{variant}, а startup_effects — нет:")
    print("    настройка подействует только до перезапуска")

print(f"обработчиков настроек: {len(handlers)}; эффектов в подъёме: {len(pushed)}")
print("чисто" if not bad else f"находок: {len(bad)}")
sys.exit(1 if bad else 0)
