#!/usr/bin/env python3
"""Номер ключа объявлен в двух местах, и они обязаны совпадать (§6).

Развёртка — та же, что у `labels_covered`, только для сериализации.
Номера полей карточки и конверта живут в `crates/codec/src`, а тест-векторы
считает `tools/gen_codec_vectors.py` — и номера в нём **повторены руками**
нарочно: возьми генератор числа из кода, перенумеруй поле — и векторы
перенумеровались бы вместе с ним, смолчав о сломанной совместимости.

Цена этой нарочитости — два списка, которые расходятся молча. Добавь поле
в карточку, и векторы останутся зелёными: новое поле у них пустое, а пустое
не пишется вовсе (§6). То есть набор перестанет покрывать структуру целиком,
и узнать об этом будет негде.

Правило: для каждого `const KEY_X: u64 = N;` в кодеке в генераторе обязано
найтись имя, кончающееся на `X`, с тем же `N`.

**Чего эта метелка не стережёт.** Что у нового поля есть вектор
со **заполненным** значением: это проверяет
`every_optional_field_appears_in_some_vector` в самих векторах, и ему
для этого нужны колонки файла, а не номера ключей. Не стережёт она
и лишние имена в генераторе: имя без пары в коде безвредно.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Где объявлены номера ключей. `canonical.rs` держит общий ключ версии
# протокола, остальные два — свои структуры.
SOURCES = [
    "crates/codec/src/canonical.rs",
    "crates/codec/src/card.rs",
    "crates/codec/src/envelope.rs",
]
GENERATOR = "tools/gen_codec_vectors.py"

KEY = re.compile(r"^(?:pub )?const (KEY_\w+): u64 = (\d+);", re.M)
PY_CONST = re.compile(r"^([A-Z][A-Z0-9_]*) = (\d+)$", re.M)

generator = (ROOT / GENERATOR).read_text(encoding="utf-8")
in_generator = [(name, int(value)) for name, value in PY_CONST.findall(generator)]

bad = 0
looked = 0
for source in SOURCES:
    text = (ROOT / source).read_text(encoding="utf-8")
    for name, value in KEY.findall(text):
        looked += 1
        suffix = name.removeprefix("KEY_")
        same_name = [(n, v) for n, v in in_generator if n.endswith(suffix)]
        if not any(v == int(value) for _, v in same_name):
            if same_name:
                names = ", ".join(f"{n} = {v}" for n, v in same_name)
                print(f"{source}: {name} = {value}, а в генераторе {names}")
            else:
                print(f"{source}: {name} = {value} — в генераторе такого имени нет вовсе")
            bad += 1

print(f"ключей осмотрено: {looked} в {len(SOURCES)} файлах")
print("чисто" if not bad else f"-- расхождений {bad}")

# Находок должно быть **ноль**: каждый номер ключа обязан совпадать
# с повторённым в генераторе.
sys.exit(1 if bad else 0)
