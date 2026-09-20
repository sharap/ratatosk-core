#!/usr/bin/env python3
"""Метелка: удаление чата обязано сносить одно и то же в обоих хранилищах.

В файловой базе чат уносит за собой всё своё внешним ключом
(`REFERENCES chats(chat_id) ON DELETE CASCADE`), а `MemoryStore` делает
то же самое руками, строкой на карту. Компилятору здесь стеречь нечего:
забытая карта — это не ошибка типов, а расхождение двух исправных
половин.

**Заведена по настоящей поломке, и уже по второй.** Первой были
`group_avatars`: в памяти не сносилось ничего группового, и удалённый
чат исчезал на устройстве, а в симуляции (§16) оставался. Второй —
каналы фазы 2: отписка (§10.6) обещает «ключи стираются», и в памяти
они оставались лежать, то есть обещание было ложью ровно там, где его
никто не проверяет.

Правило: **у каждой таблицы, которую в схеме уносит каскадом от `chats`,
есть своя строка в `MemoryStore::delete_chat`.** Соответствие имён
не механическое (`channel_representations` — это `channels`, а
`group_members` — `membership`), поэтому оно лежит здесь таблицей,
и новая таблица без строки в ней — находка: её надо либо занести, либо
объяснить исключением.

Находок при заведении: **ноль**. Проверена возвратом поломки — со снятой
строкой `archive_keys` в `memory.rs` краснеет и она, и
`deleting_a_chat_takes_everything_of_the_channel_with_it_in_both_backends`.
"""
import pathlib
import re
import sys

# Корень дерева считается от самого файла, а не от текущего каталога:
# метелку зовут и из корня, и из CI, и по одной из редактора.
ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]

SCHEMA = ROOT_DIR / "crates/store/src/schema.rs"
MEMORY = ROOT_DIR / "crates/store/src/memory.rs"

# Таблица → что обязано упоминаться в `MemoryStore::delete_chat`.
#
# Имя поля, а не строка кода: как именно поле чистится — `remove` по ключу
# или `retain` по первому полю ключа — дело реализации, а вот упомянуто
# оно быть обязано.
FIELDS = {
    "messages": "messages",
    "group_members": "membership",
    "group_baseline": "baselines",
    "sender_chains": "chains",
    "group_blocks": "blocks",
    "group_avatars": "group_avatars",
    "channel_representations": "channels",
    "channel_subscriptions": "subscriptions",
    "channel_archive_keys": "archive_keys",
    "channel_admits": "admits",
    "channel_requests": "requests",
    "swarm_peers": "seeds",
    "swarm_seeding": "seeding",
    "channel_sharing": "sharing",
    "channel_archive": "archive",
}

# Исключения — поимённо и с причиной.
EXCUSED = {
    # Выдачи прав лежат **внутри** `StoredChannel`, а не отдельной картой:
    # в файловой базе они кладутся одной транзакцией с документом, и
    # отдельная карта в памяти завела бы возможность им разъехаться.
    # Уходят вместе с `channels`.
    "channel_grants": "лежат внутри StoredChannel",
    # Причинные ссылки и дедупликация каскадят от `messages`, а не от
    # `chats`: в памяти их уносит тот же проход по удаляемым сообщениям.
    "causal_refs": "каскад от messages",
    "message_tokens": "каскад от messages",
    "contact_shares": "каскад от messages",
    "message_files": "каскад от messages",
    "reactions": "каскад от messages",
}

CREATE = re.compile(
    r"CREATE TABLE (\w+)\s*\((.*?)\n\)", re.S
)


def main() -> int:
    schema = SCHEMA.read_text()
    memory = MEMORY.read_text()

    body = re.search(
        r"fn delete_chat\(&mut self, chat_id: &\[u8; 16\]\) -> Result<\(\)> \{(.*?)\n    \}",
        memory,
        re.S,
    )
    if body is None:
        print("-- в memory.rs не нашлось delete_chat: метелка смотрит не туда")
        return 1
    body = body.group(1)

    seen = set()
    bad = 0
    for name, columns in CREATE.findall(schema):
        # Таблица могла быть заведена, снесена и заведена заново другой
        # миграцией — считается **последнее** объявление.
        if "REFERENCES chats(chat_id)" not in columns:
            continue
        if "ON DELETE CASCADE" not in columns:
            continue
        seen.add(name)

    for name in sorted(seen):
        if name in EXCUSED:
            continue
        field = FIELDS.get(name)
        if field is None:
            print(f"{name}: каскад от chats есть, а строки в MemoryStore::delete_chat нет")
            bad += 1
            continue
        if field not in body:
            print(f"{name}: поле `{field}` не чистится в MemoryStore::delete_chat")
            bad += 1

    # Обратная половина: запись в таблице соответствий, под которой больше
    # нет таблицы, — это забытая уборка, и она молча ослабляет проверку.
    for name in sorted(FIELDS):
        if name not in seen:
            print(f"{name}: в таблице соответствий есть, а каскада от chats в схеме нет")
            bad += 1

    print(f"таблиц с каскадом от chats осмотрено: {len(seen)}")
    print("чисто" if not bad else f"-- всего {bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
