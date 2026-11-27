#!/usr/bin/env python3
"""Метелка: форматирование не разъехалось **нигде**, а не только там, где правили.

Правило словами: **любой файл с кодом в этом дереве уложен `rustfmt`-ом
по `rustfmt.toml`, а не только тот, который кто-то недавно трогал.**

Заведена по настоящему долгу, и долг этот нашёлся сам: расхождение
лежало в `crates/proto/src/mail.rs` и
`crates/transport/src/chatmail/server_list.rs` несколько недель, его
дважды переносили из одного разбора в другой как «мелкий», и никто
не заметил третьего — `tools/snapshot_stand/checks.rs`. Нашлось всё
трое только тогда, когда `rustfmt --check` позвали по всему дереву
разом.

**Почему не ловила лестница.** В `CLAUDE.md` стоит
`rustfmt --edition 2021 <изменённые файлы>`: правило про **изменённые**.
Оно верное — переформатировать чужой файл в своей поставке значит
утопить правку в шуме, — но у него есть цена: тому, что разъехалось
однажды, покраснеть больше нечем никогда. Ни `cargo test`,
ни `clippy -D warnings`, ни `cargo doc`, ни перебор признаков
не смотрят на раскладку строк: она компилятору безразлична.

Чего эта метелка **не** стережёт: что `rustfmt.toml` настроен разумно,
что стиль читаем, что длинная строка не лучше перенесённой. Только
то, что дерево и `rustfmt` согласны между собой.

Находок должно быть ноль. Поломка проверяется так: склеить любой
перенос в одну строку длиннее `max_width` — метелка краснеет и
называет файл; убрать `rustfmt` из `PATH` — тоже краснеет, и это
нарочно: «проверить нечем» — не «чисто».
"""
import pathlib
import subprocess
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT = pathlib.Path(__file__).resolve().parents[2]

# Исключение **поимённо и с причиной**, одно.
#
# В `tools/snapshot_stand/` лежат не файлы, а куски: `lift.py` склеивает
# из них один `main.rs` и зовёт `rustc` напрямую (`cargo` в том стенде
# не участвует). По отдельности они не разбираются вовсе — `head.rs`
# обрывается внутри `impl Client`, и `rustfmt` на нём говорит
# «unclosed delimiter». Уложить такой кусок отдельно нельзя: раскладка
# у него своя только в склейке.
LIFTED = ROOT / "tools" / "snapshot_stand"

# Каталоги, которых в дереве нет, а на диске они есть.
SKIP_PARTS = {"target", ".git"}


def sources() -> list[pathlib.Path]:
    """Все файлы с кодом, кроме склеиваемых кусков."""
    found = []
    for path in sorted(ROOT.rglob("*.rs")):
        if SKIP_PARTS & set(path.parts):
            continue
        if LIFTED in path.parents:
            continue
        found.append(path)
    return found


files = sources()
bad = []

# Молчание — не «чисто», и «проверить нечем» тоже не «чисто».
if not files:
    bad.append("ни одного файла с кодом не нашлось — метелка смотрит не туда")
else:
    try:
        done = subprocess.run(
            ["rustfmt", "--edition", "2021", "--check", *[str(p) for p in files]],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        done = None
        bad.append("`rustfmt` не найден — проверить раскладку нечем, а это не «чисто»")

    if done is not None:
        # `rustfmt --check` печатает «Diff in <путь>:<строка>:» на каждое
        # расхождение. Файл называется один раз: мест в нём бывает много,
        # а править его всё равно целиком.
        drifted = []
        for line in done.stdout.splitlines():
            if line.startswith("Diff in "):
                where = line[len("Diff in ") :].rsplit(":", 2)[0]
                if where not in drifted:
                    drifted.append(where)
        for where in drifted:
            short = where[len(str(ROOT)) + 1 :] if where.startswith(str(ROOT)) else where
            bad.append(f"{short}: раскладка разъехалась — `rustfmt --edition 2021 {short}`")

        # Разбор, не прошедший у `rustfmt`, — тоже находка: значит в дереве
        # появился кусок, который не проверяет никто, а список исключений
        # про него не знает.
        #
        # Путь лежит **следующей** строкой, после `-->`, и без него находка
        # ничего не стоит: искать неразбираемый файл по дереву руками —
        # это та же работа, которую метелка и должна снять.
        notes = done.stderr.splitlines()
        for number, line in enumerate(notes):
            if not line.startswith("error"):
                continue
            where = "файл не назван"
            for tail in notes[number + 1 : number + 4]:
                if "-->" in tail:
                    spot = tail.split("-->", 1)[1].strip()
                    if spot.startswith(str(ROOT)):
                        spot = spot[len(str(ROOT)) + 1 :]
                    where = spot
                    break
            bad.append(f"{where}: `rustfmt` не смог разобрать — {line.strip()}")

print("\n".join(bad) if bad else f"чисто (файлов с кодом осмотрено: {len(files)})")
sys.exit(1 if bad else 0)
