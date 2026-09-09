#!/usr/bin/env python3
"""Метелка: набор номера не ждётся в цикле драйвера.

Заведена по поломке, которая выглядела как «ядро стартует очень медленно
при включённом yggdrasil или tor: приложение долгое время не показывает
сообщения из локальной базы».

Причина была не там, где её искали. `RatatoskClient::open` отчитывается
наверх быстро, база открыта и прочитана, — но **отвечает** на запросы UI
только цикл `Driver::run`, а `Driver::apply` дожидается каждой команды
транспорта в теле этого цикла. Набор номера ждался внутри
`Runner::execute`, и значит ядро стояло:

* на старте — потому что `Engine::startup_effects` возвращает в том числе
  доставки, недоделанные в прошлый раз, и каждая из них платила полным
  набором ко всем, кого нет в сети (меш — восемь секунд, onion — сорок
  пять);
* и после старта — потому что один недозвон морозил всё сразу: запросы
  переписки, таймеры, приём по остальным ступеням.

Лечится это одним правилом: **долгое уезжает в задачу, а исход приезжает
событием** (`TransportEvent::Connected` / `ConnectFailed`). Правило записано
в `Runner`, а стережёт его эта метелка — двумя следствиями, которые видно
текстом:

1. `ensure_link` не бывает `async`. Именно эта функция набирала номер
   во всех трёх прямых транспортах, и именно её `async` возвращал бы
   ожидание обратно в `execute`.
2. в теле `async fn execute` не бывает `tokio::time::timeout`. Срок
   ожидания в команде — это и есть «ждём сеть здесь»; у команды сроков
   быть не может, потому что она обязана возвращаться мгновенно.

Проверена возвратом поломки: `async fn ensure_link` даёт находку, `timeout`
внутри `execute` — вторую.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла: метелку зовут и из корня,
# и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
ROOT = ROOT_DIR / "crates" / "transport" / "src"


def body_of(src: str, brace: int) -> str:
    """Тело блока, начинающегося с `{` в позиции `brace`."""
    depth = 0
    for j in range(brace, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[brace : j + 1]
    return src[brace:]


def line_of(src: str, at: int) -> int:
    return src[:at].count("\n") + 1


def main() -> int:
    bad = 0
    dialers = 0
    commands = 0
    for path in sorted(ROOT.glob("**/*.rs")):
        src = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT_DIR).as_posix()

        for m in re.finditer(r"\b(async\s+)?fn\s+ensure_link\b", src):
            dialers += 1
            if m.group(1):
                print(
                    f"{rel}:{line_of(src, m.start())}: `ensure_link` снова `async`. "
                    "Набор обязан уезжать в задачу (`Link::dialing`), иначе его "
                    "ждёт цикл драйвера — вместе с запросами UI и таймерами"
                )
                bad += 1

        for m in re.finditer(r"\basync\s+fn\s+execute\b", src):
            brace = src.find("{", m.end())
            if brace < 0:
                continue
            body = body_of(src, brace)
            commands += 1
            for hit in re.finditer(r"tokio::time::timeout\b", body):
                print(
                    f"{rel}:{line_of(src, brace + hit.start())}: срок ожидания "
                    "внутри `execute`. Команда транспорта обязана возвращаться "
                    "мгновенно: долгое уезжает в задачу, исход приезжает событием"
                )
                bad += 1

    print(f"наборов и команд под присмотром: {dialers} + {commands}")
    print("чисто" if not bad else f"НАХОДОК: {bad}")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
