"""Свёртка: подъём обзора на Android считается окном квоты, а не сроком.

Зачем. Android считает `startScan`: пять за тридцать секунд на приложение.
Шестой **не отвергается ошибкой** — он принимается и не приносит ни одного
объявления. Снаружи это «блютуз устал»: связь есть, собеседников не видно,
и вернуть их можно только перезапуском приложения.

Поломка, по которой свёртка заведена, прожила до живого прогона 8 ноября.
В мосте стоял один срок между подъёмами — шесть секунд, — и в том же
комментарии было признано: «пять штук на тридцать секунд ровно, с запасом
в ноль». Запас в ноль и кончился: телефон перестал видеть и второй телефон,
и PinePhone, а перезапуск приложения вернул обоих.

Правило: окно (`SCAN_WINDOW_MS`) не короче тридцати секунд, а бюджет
(`SCAN_BUDGET`) — строго меньше платформенных пяти, потому что окно
у системы своё и с нашим не совпадает.

Чего свёртка **не** стережёт: что окно считается верно. Это Kotlin, и
проверок у него в этом дереве нет вовсе — держит его только прогон
на устройстве.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]

RADIO = ROOT_DIR / "android/BtRadio.kt"
# Платформенный предел: пять запусков за тридцать секунд. Числа названы
# здесь, а не взяты из моста, — иначе правка моста подняла бы и правило.
PLATFORM_STARTS = 5
PLATFORM_WINDOW_MS = 30_000

found = []
seen = 0

if not RADIO.exists():
    found.append("android/BtRadio.kt: радио пропало — свёртка смотрит не туда")
else:
    seen += 1
    text = RADIO.read_text(encoding="utf-8")

    window = re.search(r"const val SCAN_WINDOW_MS\s*=\s*([\d_]+)", text)
    budget = re.search(r"const val SCAN_BUDGET\s*=\s*([\d_]+)", text)
    if not window:
        found.append("android/BtRadio.kt: окно квоты не названо (SCAN_WINDOW_MS)")
    elif int(window.group(1).replace("_", "")) < PLATFORM_WINDOW_MS:
        found.append(
            f"android/BtRadio.kt: окно {window.group(1)} короче платформенных "
            f"{PLATFORM_WINDOW_MS} мс — подъёмы будут считаться не те"
        )
    if not budget:
        found.append("android/BtRadio.kt: бюджет подъёмов не назван (SCAN_BUDGET)")
    elif int(budget.group(1).replace("_", "")) >= PLATFORM_STARTS:
        found.append(
            f"android/BtRadio.kt: бюджет {budget.group(1)} не меньше платформенных "
            f"{PLATFORM_STARTS} — запаса нет, а он и кончился в прошлый раз"
        )
    # Один срок вместо окна — это та самая прежняя редакция.
    if "SCAN_COOLDOWN_MS" in text:
        found.append("android/BtRadio.kt: вернулся один срок между подъёмами вместо окна")

for line in found:
    print(line)
print(f"радио осмотрено: {seen}")
print("-- всего", len(found) if found else "чисто")

# Находок должно быть **ноль**.
sys.exit(1 if found else 0)
