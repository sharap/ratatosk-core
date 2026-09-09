#!/usr/bin/env python3
"""Прогоняет все метелки и говорит, какие нашли что-то.

Метелка — это проверка **текстом** того, что в этом дереве некому проверить
сборкой: `cargo` здесь не запускается, и «поле забыто в одном файле
из четырёх» ловил компилятор на чужой машине, то есть человек за другим
экраном. Каждая метелка заведена по настоящей поломке и проверена
её возвратом — сколько находок должно быть, написано в самой метелке.

Метелки не заменяют тесты и ничего не знают про поведение. Они стерегут
правила, которые живут **между** двумя исправными половинами: список
и его пользователей, запись и подъём, отправку и приём. Ошибка там
не видна ни одному тесту одной половины.

Зовётся из любого каталога: корень дерева каждая считает от себя.
Код возврата — число метелок с находками, ноль если чисто.
"""
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent

# Порядок — по имени: отчёт читается глазами, и стабильный порядок важнее
# любого другого.
SWEEPS = sorted(p for p in HERE.glob("*.py") if p.name != "run_all.py")


def main() -> int:
    failed = []
    for sweep in SWEEPS:
        done = subprocess.run(
            [sys.executable, str(sweep)], capture_output=True, text=True, check=False
        )
        out = (done.stdout or "").strip().split("\n")
        last = out[-1] if out else "(молчит)"
        mark = "  " if done.returncode == 0 else "!!"
        print(f"{mark} {sweep.stem:22} {last}")
        if done.returncode != 0:
            failed.append((sweep.stem, done.stdout, done.stderr))

    if not failed:
        print(f"\nвсе {len(SWEEPS)} метелки чисты")
        return 0

    print(f"\nнаходки у {len(failed)} из {len(SWEEPS)}:")
    for name, out, err in failed:
        print(f"\n--- {name} ---")
        print((out or "").rstrip())
        if err.strip():
            print((err or "").rstrip())
    return len(failed)


if __name__ == "__main__":
    sys.exit(main())
