#!/usr/bin/env python3
"""Метелка: состояния, общего на процесс, у ядра и транспорта не бывает.

§12 ставит жёсткое правило: **пул сессий — на аккаунт**, переиспользование
между аккаунтами запрещено. Там же назван и соблазн: «сессии ключуются
по `IK` пира», то есть кэш, общий на процесс, напрашивается сам. Цена
ему — не экономия, а связывание аккаунтов на проводе: два аккаунта
одного человека, ходящие в одну сессию, для наблюдателя один узел.

Держится правило сегодня построением: у каждого аккаунта своя база, своё
ядро и свой драйвер, и делить им нечего. Сломать это построение можно
одной строкой — `static` с внутренней изменяемостью, — и компилятор
о ней ничего не скажет: типы сойдутся, тесты пройдут, а разъедутся
не состояния, а **люди**.

Правило: **ни одного `static`, `lazy_static!` или `thread_local!`
с изменяемым содержимым в `crates/*/src`.** Исключения — поимённо
и с причиной: разрешено то, в чём нет ни байта о собеседнике.

Заведена не по пережитой поломке, а по прямому запрету спеки и названному
там же соблазну; сказано это прямо, чтобы завтра её не прочли как «здесь
что-то ломалось». Проверена возвратом поломки: добавленный `static
SESSIONS: Mutex<BTreeMap<...>>` в ядре находится.

Находок при заведении: **ноль** (три исключения — ниже).
"""
import pathlib
import re
import sys

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
CRATES = ROOT_DIR / "crates"

# Что считается изменяемым содержимым. `OnceLock` сюда входит нарочно:
# он пишется один раз, но написанное живёт до конца процесса и видно
# всем аккаунтам разом.
MUTABLE = re.compile(
    r"\b(Mutex|RwLock|OnceLock|OnceCell|RefCell|Cell|Atomic\w+|lazy_static|thread_local)\b"
)

STATIC = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?static\s+(\w+)\s*:\s*(.+?)(?:=|;)", re.M)
MACRO = re.compile(r"^\s*(lazy_static!|thread_local!)", re.M)

# Исключения — поимённо, с причиной. Разрешено то, в чём нет ни байта
# о собеседнике: общая таблица кодировки и настройки TLS-клиента,
# одинаковые для всех и ни на кого не указывающие.
EXCUSED = {
    ("crates/crypto/src/identity.rs", "ENC"): "таблица base32: одна на всех и ни о ком",
    ("crates/transport/src/tls.rs", "CONFIG"): "настройки TLS-клиента: ни байта о собеседнике",
    (
        "crates/transport/src/chatmail/tls.rs",
        "CONFIG",
    ): "то же для почты: корни доверия, а не состояние",
}


def main() -> int:
    bad = 0
    files = 0
    statics = 0
    for path in sorted(CRATES.glob("*/src/**/*.rs")):
        # Проверки живут своей жизнью: стенду и симуляции общее состояние
        # ничем не грозит, там один аккаунт по построению.
        if "/tests/" in str(path) or path.name == "main.rs":
            continue
        text = path.read_text(encoding="utf-8")
        files += 1
        relative = str(path.relative_to(ROOT_DIR))
        # `#[cfg(test)] mod tests` отрезается: статика проверки — её дело.
        cut = text.find("\nmod tests {")
        if cut == -1:
            cut = len(text)
        body = text[:cut]
        for name, kind in STATIC.findall(body):
            statics += 1
            if not MUTABLE.search(kind):
                continue
            if (relative, name) in EXCUSED:
                continue
            print(f"{relative}: `static {name}` общий на процесс — §12 запрещает (пул на аккаунт)")
            bad += 1
        for macro in MACRO.findall(body):
            statics += 1
            print(f"{relative}: `{macro}` общий на процесс — §12 запрещает (пул на аккаунт)")
            bad += 1

    # Обратная половина: исключение, под которым больше нет строки, —
    # это разрешение, выданное неизвестно кому.
    for (relative, name), why in sorted(EXCUSED.items()):
        path = ROOT_DIR / relative
        if not path.exists() or f"static {name}" not in path.read_text(encoding="utf-8"):
            print(f"{relative}: исключение `{name}` ({why}) больше не на что вешать")
            bad += 1

    print(f"файлов осмотрено: {files}, объявлений static: {statics}")
    print("чисто" if not bad else f"-- всего {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
