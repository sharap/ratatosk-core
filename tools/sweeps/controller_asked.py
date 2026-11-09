"""Свёртка: оба радио спрашивают свой контроллер и печатают вывод.

Зачем. Радио у ступени два — `bluetooth/local.rs` (BlueZ) и
`android/BtRadio.kt` (мост), — и за один день трижды повторилась одна
и та же поломка: мысль доходила до **одной половины из двух**.

* интервал объявления задавал Android и не задавал Linux — набор к нам
  стоил секунд, и эфир выглядел односторонним;
* читать целыми пакетами умел Android и не умел Linux — кадр терялся
  молча, и это искали трижды;
* спрашивать контроллер о себе не умел никто, и оба предела ступени
  нашлись тыком, хотя были объявлены заранее.

Отсюда правило: что одна половина спрашивает у платформы, спрашивает
и другая, и обе печатают **вывод**, а не только факты — журналы двух
устройств сличаются глазами.

Чего свёртка **не** стережёт: что вывод верен и что слова совпадают
дословно. Первое держат проверки
(`the_verdict_about_the_controller_names_what_follows_from_it`),
второе — человек, который читает оба журнала рядом.
"""
import pathlib
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]

# У каждой половины свой способ спросить: у BlueZ это свойство адаптера,
# у Android — запрос к `BluetoothAdapter`. Общего слова нет и быть
# не может, поэтому для каждой названо своё.
# Слово «legacy» ищется **внутри самого вывода**, а не по файлу:
# по файлу оно есть и в комментариях, и в проверках, и свёртка смолчала
# бы, когда вывод перестал называть следствие. Это поправка к себе же —
# ровно та ложная зелень, что уже случалась у `advert_interval`.
RADIOS = {
    "crates/transport/src/bluetooth/local.rs": {
        "спрашивает": "supported_advertising_secondary_channels",
        "печатает": "что контроллер о себе говорит",
        "вывод от": "fn controller_verdict",
        "в выводе": "legacy",
    },
    "android/BtRadio.kt": {
        "спрашивает": "isLeExtendedAdvertisingSupported",
        "печатает": "контроллер о себе",
        "вывод от": "fun controllerVerdict",
        "в выводе": "legacy",
    },
}

# Сколько знаков после начала вывода считать его телом. Грубо и нарочно:
# точный разбор двух языков здесь дороже правила.
VERDICT_SPAN = 1200

found = []
seen = 0

for where, needles in RADIOS.items():
    path = ROOT_DIR / where
    if not path.exists():
        found.append(f"{where}: радио пропало — свёртка смотрит не туда")
        continue
    seen += 1
    text = path.read_text(encoding="utf-8")
    for what in ("спрашивает", "печатает", "вывод от"):
        if needles[what] not in text:
            found.append(f"{where}: не {what} — «{needles[what]}» в файле нет")
    start = text.find(needles["вывод от"])
    if start >= 0 and needles["в выводе"] not in text[start : start + VERDICT_SPAN]:
        found.append(
            f"{where}: вывод не называет следствия — «{needles['в выводе']}» "
            f"в его теле нет"
        )

for line in found:
    print(line)
print(f"радио осмотрено: {seen}")
print("-- всего", len(found) if found else "чисто")

# Находок должно быть **ноль**.
sys.exit(1 if found else 0)
