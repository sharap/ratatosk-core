//! Хранилище в памяти — для симуляции и тестов (§16).
//!
//! §16 требует «всю сеть в одном процессе с виртуальным временем». Файловая
//! база этому мешает дважды: она заводит настоящий диск там, где вся суть
//! в отсутствии внешнего мира, и она медленная, когда узлов десятки.
//!
//! Реализация не пытается быть SQLite: у неё нет ни поискового индекса,
//! ни экспорта — искать она умеет обходом.
//! Зато она даёт трейту [`Store`] вторую реализацию — а трейт с одной
//! реализацией никогда не бывает честной абстракцией.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ratatosk_crdt::{Hlc, MsgId};

use crate::compaction::{self, Task};
use crate::{
    ArchivedBlock, FileId, HaveRange, Result, StagedUpload, Store, StoreError, StoredAdmit,
    StoredArchiveKey, StoredAvatar, StoredChannel, StoredContact, StoredContactShare, StoredFile,
    StoredGroup, StoredGroupAvatar, StoredMembershipBlock, StoredMembershipOp, StoredMessage,
    StoredOutbox, StoredPairedDevice, StoredPeer, StoredPendingGroup, StoredReaction, StoredSeed,
    StoredSenderChain, StoredSession, StoredSubscription,
};

/// Хранилище в оперативной памяти.
#[derive(Debug, Default)]
pub struct MemoryStore {
    migrated: bool,
    /// Ключ упорядочен так же, как индекс `messages_order` в SQLite:
    /// чат, затем HLC, затем `msg_id` — то есть порядок §9.1.
    messages: BTreeMap<([u8; 16], Hlc, MsgId), StoredMessage>,
    seen: HashMap<MsgId, u64>,
    /// Когда сообщение удалили. Надгробие держит идентификатор, а не текст:
    /// тело стирается в тот же момент (§12).
    tombstones: HashMap<MsgId, u64>,
    /// `BTreeMap`, а не `HashMap`: порядок чтения контактов должен быть
    /// одинаков от запуска к запуску, иначе симуляция (§16) перестаёт быть
    /// воспроизводимой по сиду.
    contacts: BTreeMap<[u8; 32], StoredContact>,
    sessions: BTreeMap<u64, StoredSession>,
    /// Отпечатки принятых рукопожатий (§8.3) со временем первой встречи.
    ///
    /// `BTreeMap`, а не `HashMap`, по той же причине, что у контактов:
    /// порядок чтения обязан быть одинаков от запуска к запуску, иначе
    /// симуляция §16 перестаёт быть воспроизводимой по сиду.
    handshake_seen: BTreeMap<[u8; 32], u64>,
    avatars: BTreeMap<[u8; 32], StoredAvatar>,
    /// Аватарки групп (§11 + дополнение). Отдельно от `avatars`: ключ там
    /// — `IK` человека, здесь — идентификатор чата, и складывать их в одну
    /// карту значило бы объявить шестнадцать байт группы началом чьего-то
    /// ключа.
    group_avatars: BTreeMap<[u8; 16], StoredGroupAvatar>,
    devices: BTreeMap<[u8; 16], StoredPairedDevice>,
    /// Группы (§11). Строка чата здесь отдельной таблицей не нужна:
    /// в файловой базе группа и чат — одна строка, а тут чат ничем, кроме
    /// сообщений, не представлен.
    groups: BTreeMap<[u8; 16], StoredGroup>,
    /// Заявки на подписку (фаза 2, §10.4): чат, затем проситель.
    /// Порядок обхода задан ключом и совпадает с `ORDER BY` файловой базы.
    requests: BTreeMap<([u8; 16], [u8; 32]), u64>,
    /// Архив кадров канала (§7.2, §9.3): чат, автор, номер в цепочке.
    /// Ключ упорядочен так же, как `ORDER BY seq` в файловой базе.
    archive: BTreeMap<([u8; 16], [u8; 32], u64), ArchivedBlock>,
    /// Каталог роя (§7.5): чат, затем чей адрес. Порядок обхода задан
    /// ключом и совпадает с `ORDER BY` файловой базы.
    seeds: BTreeMap<([u8; 16], [u8; 32]), StoredSeed>,
    /// Наше участие в раздаче (§7.5.1): код состояния и когда выбран.
    seeding: BTreeMap<[u8; 16], (u32, u64)>,
    /// Переопределение уровня отдачи на канал (§12). Пусто — «как
    /// у аккаунта», и это не то же, что уровень «всем».
    sharing: BTreeMap<[u8; 16], u32>,
    /// Пиры-не-контакты (§8.3): владелец канала, до которого надо
    /// дотянуться заявкой. `BTreeMap` — по той же причине, что у контактов:
    /// порядок обхода обязан быть одинаков от запуска к запуску.
    peers: BTreeMap<[u8; 32], StoredPeer>,
    /// Представления каналов (фаза 2, §6.1). Выдачи лежат **внутри**
    /// `StoredChannel`, а не отдельной картой: в файловой базе они кладутся
    /// одной транзакцией с документом, и разъехаться им негде. Отдельная
    /// карта здесь завела бы такую возможность на ровном месте.
    channels: BTreeMap<[u8; 16], StoredChannel>,
    /// Подписки на каналы (фаза 2, §10.4) — наша сторона.
    subscriptions: BTreeMap<[u8; 16], StoredSubscription>,
    /// Поколения ключа чтения: чат, затем номер поколения. Порядок обхода
    /// задан ключом и совпадает с `ORDER BY` файловой базы.
    archive_keys: BTreeMap<([u8; 16], u64), StoredArchiveKey>,
    /// Впуски в канал (фаза 2, §6.5): чат, затем впущенный. Порядок
    /// обхода задан ключом и совпадает с `ORDER BY` файловой базы.
    admits: BTreeMap<([u8; 16], [u8; 32]), StoredAdmit>,
    /// Операции состава. Ключ — метка целиком, ровно как первичный ключ
    /// `group_members`: повтор той же операции обязан лечь в ту же ячейку.
    /// Порядок обхода задан ключом и совпадает с `ORDER BY` файловой базы.
    membership: BTreeMap<([u8; 16], u64, u32, [u8; 32], [u8; 8], [u8; 32]), bool>,
    /// Водяные знаки свёртки состава (§6.7) — зеркало `group_baseline`.
    baselines: BTreeMap<[u8; 16], (u64, u32)>,
    /// Подписанные блоки состава (§11.5). Ключ — чат и идентификатор блока,
    /// ровно как первичный ключ `group_blocks`: тот же блок, пришедший
    /// вторым транспортом, обязан лечь в ту же ячейку.
    blocks: BTreeMap<([u8; 16], [u8; 16]), StoredMembershipBlock>,
    /// Ключи отправителей: чат, затем участник.
    chains: BTreeMap<([u8; 16], [u8; 32]), StoredSenderChain>,
    /// Надгробия отозванных сопряжений (§13.4): ключ сопряжения и когда.
    /// Записи об устройстве уже нет — есть только то, чем узнать его
    /// в рукопожатии, чтобы ответить причиной вместо тишины.
    revocations: BTreeMap<[u8; 32], u64>,
    /// Ключ — пара «сообщение, автор»: реакция от человека одна, новая
    /// заменяет прежнюю.
    reactions: BTreeMap<(MsgId, [u8; 32]), StoredReaction>,
    /// Очередь доставки, по паре «сообщение и получатель».
    ///
    /// Пара, а не один `msg_id`, и разница не теоретическая: сообщение
    /// в группу — это N доставок с одним номером (§11.3). Ключ из номера
    /// держал бы одну из них, и остальные пропадали бы при постановке.
    /// Именно поэтому потерю копий в группе не ловил ни симулятор, ни один
    /// тест на `MemoryStore`: до диска они не доезжали вовсе.
    outbox: BTreeMap<(MsgId, [u8; 32]), StoredOutbox>,
    files: BTreeMap<FileId, StoredFile>,
    /// Отложенные групповые кадры — зеркало таблицы `pending_group`.
    ///
    /// Порядок вектора и есть очередь: место в ней — это и возраст.
    parked: Vec<StoredPendingGroup>,
    /// Связка «сообщение → файл → место», зеркало таблицы `message_files`.
    ///
    /// Отдельной картой, а не полем в `StoredFile`, по той же причине,
    /// по какой она отдельная таблица: один файл принадлежит нескольким
    /// сообщениям с тех пор, как появилась пересылка вложений.
    links: BTreeMap<(MsgId, FileId), u32>,
    /// Присланные карточки контактов: одна на сообщение.
    contact_shares: BTreeMap<MsgId, StoredContactShare>,
    /// Какие чанки приняты. `BTreeSet` по паре, чтобы «первый недостающий»
    /// считался обходом по порядку, как и в файловой базе.
    chunks: std::collections::BTreeSet<(FileId, u64)>,
    /// Незаконченные выгрузки с десктопа (§13.4) и их куски — тем же
    /// разделением, что у файлов: сведения отдельно, отметки о кусках
    /// отдельно.
    staged: BTreeMap<FileId, StagedUpload>,
    staged_chunks: std::collections::BTreeSet<(FileId, u64)>,
    meta: BTreeMap<String, Vec<u8>>,
}

impl MemoryStore {
    /// Пустое хранилище.
    #[must_use]
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }

    /// Сколько сообщений лежит во всех чатах.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Пусто ли хранилище.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Сколько идентификаторов в окне дедупликации.
    #[must_use]
    pub fn seen_len(&self) -> usize {
        self.seen.len()
    }

    /// Идентификаторы сообщений чата.
    ///
    /// Ключ карты — тройка, а не `msg_id`, поэтому «сообщения этого чата»
    /// каждый раз приходится собирать обходом. Место сборки одно, чтобы
    /// удаление чата и поиск его вложений не разошлись.
    fn message_ids_of_chat(&self, chat_id: &[u8; 16]) -> BTreeSet<MsgId> {
        self.messages
            .iter()
            .filter(|((chat, _, _), _)| chat == chat_id)
            .map(|(_, message)| message.msg_id)
            .collect()
    }

    /// Убирает файлы, на которые не осталось ни одной связки.
    ///
    /// Зеркало триггера `files_drop_orphans`: инвариант «файл без ссылок
    /// не существует» обязан держаться одинаково в обоих хранилищах,
    /// иначе симуляция (§16) проверяла бы не то состояние, что на
    /// устройстве.
    fn drop_orphan_files(&mut self) {
        let orphans: Vec<FileId> = self
            .files
            .keys()
            .filter(|file_id| !self.links.keys().any(|(_, id)| id == *file_id))
            .copied()
            .collect();
        for file_id in orphans {
            self.files.remove(&file_id);
            self.chunks.retain(|(id, _)| *id != file_id);
        }
    }
}

impl Store for MemoryStore {
    fn migrate(&mut self) -> Result<()> {
        self.migrated = true;
        Ok(())
    }

    fn put_message(&mut self, message: &StoredMessage) -> Result<()> {
        if !self.migrated {
            // Тот же контракт, что у файловой базы: писать в непроинициали-
            // зированное хранилище нельзя. Иначе симуляция прощала бы
            // пропущенную миграцию, а продукт — нет.
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Удалённое не воскрешаем — ровно то же правило, что и в файловой
        // базе: копия законно приходит вторым транспортом (§9.2), а надгробие
        // затем и стоит, чтобы она не вернула убранное человеком.
        if self.tombstones.contains_key(&message.msg_id) {
            return Ok(());
        }
        self.messages.insert((message.chat_id, message.hlc, message.msg_id), message.clone());
        Ok(())
    }

    fn put_contact(&mut self, contact: &StoredContact) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.contacts.insert(contact.ik, contact.clone());
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<StoredContact>> {
        Ok(self.contacts.values().cloned().collect())
    }

    fn delete_contact(&mut self, ik: &[u8; 32]) -> Result<()> {
        self.contacts.remove(ik);
        self.avatars.remove(ik);
        // Каскада внешних ключей здесь нет — он делается руками, иначе
        // симуляция расходилась бы с продуктом ровно там, где это опаснее
        // всего: ключевой материал пережил бы контакт.
        self.sessions.retain(|_, session| session.peer_ik != *ik);
        Ok(())
    }

    fn delete_chat(&mut self, chat_id: &[u8; 16]) -> Result<()> {
        let removed = self.message_ids_of_chat(chat_id);
        self.messages.retain(|(chat, _, _), _| chat != chat_id);
        for msg_id in removed {
            self.tombstones.remove(&msg_id);
            self.reactions.retain(|(id, _), _| *id != msg_id);
            // Файлы — тем же каскадом, что и в базе. Записи, пережившие
            // свои сообщения, разошлись бы с продуктом ровно в том месте,
            // которое ищет уборка: она считает лишним на диске то, чего нет
            // в базе, и лишняя запись прятала бы от неё настоящий мусор.
            //
            // Со связкой каскад двухступенчатый, как и триггер
            // `files_drop_orphans` в схеме: уходит связка, а файл — только
            // если это была последняя ссылка на него. Пересланная копия
            // читает тот же файл, и унеси мы его вместе с исходным
            // сообщением, у неё пропали бы байты.
            self.links.retain(|(m, _), _| *m != msg_id);
            self.contact_shares.remove(&msg_id);
        }
        self.drop_orphan_files();
        // Всё групповое — тем же каскадом, каким его уносит внешний ключ
        // на `chats` в файловой базе. Найдено при заведении `group_avatars`:
        // здесь не сносилось **ничего** группового, и удалённый чат группы
        // на устройстве исчезал, а в симуляции (§16) оставался — то есть
        // подъём после удаления проверялся не тот.
        self.groups.remove(chat_id);
        self.group_avatars.remove(chat_id);
        self.membership.retain(|(chat, ..), _| chat != chat_id);
        self.blocks.retain(|(chat, _), _| chat != chat_id);
        self.chains.retain(|(chat, _), _| chat != chat_id);
        // Знак свёртки и всё канальное — тем же каскадом. Пять строк
        // ниже появились не из полноты списка: без них отписка (§10.6)
        // означала бы здесь «чата нет, а ключи чтения есть», то есть
        // ровно то, чего она обещает не оставлять. В файловой базе их
        // уносит `ON DELETE CASCADE`, и разойдись два хранилища —
        // симуляция §16 проверяла бы отписку, которой на устройстве
        // не бывает. Тот же класс, что нашли `group_avatars` абзацем выше.
        self.baselines.remove(chat_id);
        self.channels.remove(chat_id);
        self.subscriptions.remove(chat_id);
        self.archive_keys.retain(|(chat, _), _| chat != chat_id);
        self.admits.retain(|(chat, _), _| chat != chat_id);
        self.requests.retain(|(chat, _), _| chat != chat_id);
        // Каталог роя и своё участие (§7.5): удалённый чат уносит и их.
        // §12 говорит про удаление канала прямо: «сидирование
        // прекращается», а сидировать чат, которого нет, — это держать
        // адрес в чужих каталогах ради байтов, которых у нас уже нет.
        self.seeds.retain(|(chat, _), _| chat != chat_id);
        self.archive.retain(|(chat, _, _), _| chat != chat_id);
        self.seeding.remove(chat_id);
        // И уровень отдачи (§12): переопределение на канал, которого
        // больше нет, — это настройка, которую человеку уже не показать
        // и не снять. Нашла эту строку метёлка `chat_cascade` в ту же
        // минуту, как таблица появилась.
        self.sharing.remove(chat_id);
        Ok(())
    }

    fn put_session(&mut self, session: &StoredSession) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.sessions.insert(session.session_id, session.clone());
        Ok(())
    }

    fn sessions(&self) -> Result<Vec<StoredSession>> {
        Ok(self.sessions.values().cloned().collect())
    }

    fn delete_session(&mut self, session_id: u64) -> Result<()> {
        self.sessions.remove(&session_id);
        Ok(())
    }

    fn put_handshake_seen(&mut self, digest: &[u8; 32], seen_ms: u64) -> Result<()> {
        // Повтор ложится в ту же ячейку и **не** обновляет время: срок
        // считается от первой встречи, иначе настойчивый повтор продлевал
        // бы запись вечно.
        self.handshake_seen.entry(*digest).or_insert(seen_ms);
        Ok(())
    }

    fn handshake_seen(&self, newer_than_ms: u64) -> Result<Vec<([u8; 32], u64)>> {
        let mut found: Vec<([u8; 32], u64)> = self
            .handshake_seen
            .iter()
            .filter(|(_, seen)| **seen > newer_than_ms)
            .map(|(digest, seen)| (*digest, *seen))
            .collect();
        // По времени, а не по отпечатку. Карта упорядочена ключом, то есть
        // хэшем, — а кэш складывает записи в очередь по времени и снимает
        // просроченное с её начала. Отдай мы их в порядке хэша, уборка
        // остановилась бы на первой же «ещё свежей».
        found.sort_by_key(|(_, seen)| *seen);
        Ok(found)
    }

    fn prune_handshake_seen(&mut self, older_than_ms: u64) -> Result<()> {
        self.handshake_seen.retain(|_, seen| *seen > older_than_ms);
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.meta.get(key).cloned())
    }

    fn put_meta(&mut self, key: &str, value: &[u8]) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.meta.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn messages(
        &self,
        chat_id: &[u8; 16],
        limit: usize,
        before: Option<Hlc>,
    ) -> Result<Vec<StoredMessage>> {
        let mut window: Vec<StoredMessage> = self
            .messages
            .iter()
            .filter(|((chat, hlc, _), m)| {
                chat == chat_id
                    && before.is_none_or(|b| *hlc < b)
                    && !self.tombstones.contains_key(&m.msg_id)
            })
            .map(|(_, m)| m.clone())
            .collect();

        // Отдаётся хвост окна: чат листается назад, и нужны последние `limit`
        // сообщений перед границей, а не первые с начала времён.
        if window.len() > limit {
            window.drain(..window.len() - limit);
        }
        Ok(window)
    }

    fn message(&self, msg_id: &MsgId) -> Result<Option<StoredMessage>> {
        if self.tombstones.contains_key(msg_id) {
            return Ok(None);
        }
        Ok(self.messages.values().find(|m| m.msg_id == *msg_id).cloned())
    }

    fn tombstone_message(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        if self.tombstones.contains_key(msg_id) {
            return Ok(false);
        }
        let Some(message) = self.messages.values_mut().find(|m| m.msg_id == *msg_id) else {
            return Ok(false);
        };
        // Тело стирается сразу, как и в файловой базе: держать текст после
        // «удалить» значит не удалить, а расхождение двух реализаций здесь
        // было бы расхождением в том, что значит удаление.
        message.body.clear();
        message.status = None;
        // И то же, что в файловой базе: отметка о правке и реакции относились
        // к словам, которых больше нет.
        message.edited_ms = None;
        self.reactions.retain(|(id, _), _| id != msg_id);
        // Присланная карточка — тоже содержимое сообщения, и уходит вместе
        // с ним: иначе в истории осталась бы кнопка «добавить контакт»
        // у сообщения, которого больше нет.
        self.contact_shares.remove(msg_id);
        self.tombstones.insert(*msg_id, now_ms);
        Ok(true)
    }

    fn tombstone_chat(&mut self, chat_id: &[u8; 16], now_ms: u64) -> Result<u64> {
        let victims: Vec<MsgId> = self
            .messages
            .iter()
            .filter(|((chat, _, _), _)| chat == chat_id)
            .map(|(_, m)| m.msg_id)
            .filter(|id| !self.tombstones.contains_key(id))
            .collect();
        let count = victims.len() as u64;
        for msg_id in victims {
            self.tombstone_message(&msg_id, now_ms)?;
        }
        Ok(count)
    }

    fn status(&self, msg_id: &MsgId) -> Result<Option<u8>> {
        Ok(self.messages.values().find(|m| m.msg_id == *msg_id).and_then(|m| m.status))
    }

    fn set_status(&mut self, msg_id: &MsgId, status: u8) -> Result<bool> {
        // Ключ карты — (чат, HLC, msg_id), поэтому запись ищется перебором.
        // Для памяти это допустимо: она существует ради симуляции, где
        // сообщений десятки, а не миллионы.
        if self.tombstones.contains_key(msg_id) {
            return Ok(false);
        }
        let Some(message) = self.messages.values_mut().find(|m| m.msg_id == *msg_id) else {
            return Ok(false);
        };
        message.status = Some(status);
        Ok(true)
    }

    fn edit_message(&mut self, msg_id: &MsgId, body: &[u8], edited_ms: u64) -> Result<bool> {
        // Надгробие сильнее правки — то же правило, что в файловой базе:
        // удалённое не возвращается в чат из-за того, что автор его переписал.
        if self.tombstones.contains_key(msg_id) {
            return Ok(false);
        }
        let Some(message) = self.messages.values_mut().find(|m| m.msg_id == *msg_id) else {
            return Ok(false);
        };
        message.body = body.to_vec();
        message.edited_ms = Some(edited_ms);
        Ok(true)
    }

    fn put_reaction(&mut self, reaction: &StoredReaction) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.reactions.insert((reaction.msg_id, reaction.author_ik), reaction.clone());
        Ok(())
    }

    fn reaction(&self, msg_id: &MsgId, author_ik: &[u8; 32]) -> Result<Option<StoredReaction>> {
        Ok(self.reactions.get(&(*msg_id, *author_ik)).cloned())
    }

    fn reactions(&self, msg_id: &MsgId) -> Result<Vec<StoredReaction>> {
        // Порядок — по автору, как и в SQLite: список реакций не должен
        // зависеть от того, какая реализация под ним. Снятые не отдаются:
        // их записи существуют только ради метки (см. `Store::put_reaction`).
        Ok(self
            .reactions
            .iter()
            .filter(|((id, _), reaction)| id == msg_id && !reaction.emoji.is_empty())
            .map(|(_, reaction)| reaction.clone())
            .collect())
    }

    fn put_paired_device(&mut self, device: &StoredPairedDevice) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.devices.insert(device.device_id, device.clone());
        Ok(())
    }

    fn paired_devices(&self) -> Result<Vec<StoredPairedDevice>> {
        // По времени сопряжения, как и в SQLite: порядок списка на экране
        // не должен зависеть от того, какое хранилище под ним.
        let mut found: Vec<StoredPairedDevice> = self.devices.values().cloned().collect();
        found.sort_by_key(|d| d.paired_ms);
        Ok(found)
    }

    fn delete_paired_device(&mut self, device_id: &[u8; 16]) -> Result<()> {
        self.devices.remove(device_id);
        Ok(())
    }

    fn set_device_onion(&mut self, device_id: &[u8; 16], onion: &str) -> Result<()> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.onion = onion.to_owned();
        }
        Ok(())
    }

    fn set_device_ygg(&mut self, device_id: &[u8; 16], ygg: &[u8]) -> Result<()> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.ygg = ygg.to_vec();
        }
        Ok(())
    }

    fn put_group(&mut self, group: &StoredGroup) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Тем же правилом, что и в файловой базе: владелец и время
        // заведения не обновляются (§11.2), а название — **только вперёд**.
        //
        // Сравнение пары «часы, счётчик» повторено здесь дословно, и это
        // не дублирование ради дублирования: две реализации одного
        // хранилища обязаны отвечать одинаково, иначе симуляция §16
        // проверяла бы не то, что работает на устройстве. Расхождение
        // здесь ловит `persistence.rs` — он гоняет оба.
        match self.groups.get_mut(&group.chat_id) {
            Some(known) => {
                if (group.title_wall, group.title_logical)
                    >= (known.title_wall, known.title_logical)
                {
                    known.title.clone_from(&group.title);
                    known.title_wall = group.title_wall;
                    known.title_logical = group.title_logical;
                }
                // Профиль — тем же `max`, что и в SQL: порода задаётся
                // при заведении и обратно не ходит (§6.1, §14).
                known.profile = known.profile.max(group.profile);
            }
            None => {
                self.groups.insert(group.chat_id, group.clone());
            }
        }
        Ok(())
    }

    fn group(&self, chat_id: &[u8; 16]) -> Result<Option<StoredGroup>> {
        Ok(self.groups.get(chat_id).cloned())
    }

    fn groups(&self) -> Result<Vec<StoredGroup>> {
        let mut found: Vec<StoredGroup> = self.groups.values().cloned().collect();
        // Тот же порядок, что и в файловой базе: время заведения, затем
        // идентификатор. Ключ карты — только идентификатор, поэтому
        // пересортировать приходится явно.
        found.sort_by_key(|group| (group.created_ms, group.chat_id));
        Ok(found)
    }

    fn put_channel(&mut self, channel: &StoredChannel) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Замена целиком, не слияние: список выдач в новой версии — это
        // всё, что действует (§6.2). Тот же смысл, что у `DELETE` перед
        // вставкой в файловой базе.
        let mut fresh = channel.clone();
        // Порядок выдач тот же, что отдаёт `ORDER BY who`: обе реализации
        // обязаны отвечать одинаково, иначе симуляция §16 проверяла бы
        // не то, что работает на устройстве.
        fresh.grants.sort_by_key(|grant| grant.who);
        self.channels.insert(channel.chat_id, fresh);
        Ok(())
    }

    fn channel(&self, chat_id: &[u8; 16]) -> Result<Option<StoredChannel>> {
        Ok(self.channels.get(chat_id).cloned())
    }

    fn put_subscription(&mut self, subscription: &StoredSubscription) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.subscriptions.insert(subscription.chat_id, *subscription);
        Ok(())
    }

    fn subscription(&self, chat_id: &[u8; 16]) -> Result<Option<StoredSubscription>> {
        Ok(self.subscriptions.get(chat_id).copied())
    }

    fn put_archive_key(&mut self, chat_id: &[u8; 16], key: &StoredArchiveKey) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Тем же правилом, что `OR IGNORE` в файловой базе: повтор того же
        // поколения безвреден, а **замена** ключа потеряла бы архив,
        // который прежний разворачивает.
        self.archive_keys.entry((*chat_id, key.generation)).or_insert_with(|| key.clone());
        Ok(())
    }

    fn archive_keys(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredArchiveKey>> {
        Ok(self
            .archive_keys
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|(_, key)| key.clone())
            .collect())
    }

    fn put_admit(&mut self, chat_id: &[u8; 16], admit: &StoredAdmit) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Тем же правилом, что `OR IGNORE` в файловой базе.
        self.admits.entry((*chat_id, admit.who)).or_insert_with(|| admit.clone());
        Ok(())
    }

    fn admits(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredAdmit>> {
        Ok(self
            .admits
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|(_, admit)| admit.clone())
            .collect())
    }

    fn put_membership(&mut self, chat_id: &[u8; 16], ops: &[StoredMembershipOp]) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        for op in ops {
            let key =
                (*chat_id, op.tag_wall, op.tag_logical, op.tag_actor, op.tag_uniq, op.member_ik);
            let known = self.membership.entry(key).or_insert(false);
            // `max`, а не присваивание: надгробие односторонне. См. тот же
            // оператор в файловой базе.
            *known = *known || op.removed;
        }
        Ok(())
    }

    fn fold_membership(
        &mut self,
        chat_id: &[u8; 16],
        baseline_wall: u64,
        baseline_logical: u32,
        folded: &[StoredMembershipOp],
    ) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.membership.retain(|(chat, ..), _| chat != chat_id);
        for op in folded {
            self.membership.insert(
                (*chat_id, op.tag_wall, op.tag_logical, op.tag_actor, op.tag_uniq, op.member_ik),
                false,
            );
        }
        self.baselines.insert(*chat_id, (baseline_wall, baseline_logical));
        Ok(())
    }

    fn group_baseline(&self, chat_id: &[u8; 16]) -> Result<Option<(u64, u32)>> {
        Ok(self.baselines.get(chat_id).copied())
    }

    fn membership(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredMembershipOp>> {
        let ops = self
            .membership
            .iter()
            .filter(|((chat, ..), _)| chat == chat_id)
            .map(|((_, tag_wall, tag_logical, tag_actor, tag_uniq, member_ik), removed)| {
                StoredMembershipOp {
                    member_ik: *member_ik,
                    tag_wall: *tag_wall,
                    tag_logical: *tag_logical,
                    tag_actor: *tag_actor,
                    tag_uniq: *tag_uniq,
                    removed: *removed,
                }
            })
            .collect();
        Ok(ops)
    }

    fn put_membership_block(
        &mut self,
        chat_id: &[u8; 16],
        block: &StoredMembershipBlock,
    ) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // `or_insert`, а не `insert`: повтор не подменяет байты, над которыми
        // стоит подпись. То же правило, что `DO NOTHING` в файловой базе.
        self.blocks.entry((*chat_id, block.block_id)).or_insert_with(|| block.clone());
        Ok(())
    }

    fn membership_blocks(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredMembershipBlock>> {
        let mut found: Vec<StoredMembershipBlock> = self
            .blocks
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|(_, block)| block.clone())
            .collect();
        // Тот же порядок, что в файловой базе: время приёма, затем
        // идентификатор. Ключ карты — только идентификатор, поэтому
        // пересортировать приходится явно.
        found.sort_by_key(|block| (block.received_ms, block.block_id));
        Ok(found)
    }

    fn put_sender_chain(&mut self, chat_id: &[u8; 16], chain: &StoredSenderChain) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.chains.insert((*chat_id, chain.member_ik), chain.clone());
        Ok(())
    }

    fn sender_chain(
        &self,
        chat_id: &[u8; 16],
        member_ik: &[u8; 32],
    ) -> Result<Option<StoredSenderChain>> {
        Ok(self.chains.get(&(*chat_id, *member_ik)).cloned())
    }

    fn sender_chains(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredSenderChain>> {
        Ok(self
            .chains
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|(_, chain)| chain.clone())
            .collect())
    }

    fn remember_revocation(&mut self, pairing_public: &[u8; 32], revoked_ms: u64) -> Result<()> {
        self.revocations.insert(*pairing_public, revoked_ms);
        Ok(())
    }

    fn revocation(&self, pairing_public: &[u8; 32]) -> Result<Option<u64>> {
        Ok(self.revocations.get(pairing_public).copied())
    }

    fn prune_revocations(&mut self, before_ms: u64) -> Result<usize> {
        let before = self.revocations.len();
        self.revocations.retain(|_, at| *at >= before_ms);
        Ok(before - self.revocations.len())
    }

    fn touch_paired_device(&mut self, device_id: &[u8; 16], now_ms: u64) -> Result<()> {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.last_seen_ms = now_ms;
        }
        Ok(())
    }

    fn put_avatar(&mut self, owner_ik: &[u8; 32], avatar: &StoredAvatar) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.avatars.insert(*owner_ik, avatar.clone());
        Ok(())
    }

    fn avatar(&self, owner_ik: &[u8; 32]) -> Result<Option<StoredAvatar>> {
        Ok(self.avatars.get(owner_ik).cloned())
    }

    fn has_avatar(&self, owner_ik: &[u8; 32]) -> Result<bool> {
        Ok(self.avatars.contains_key(owner_ik))
    }

    fn avatar_stamp(&self, owner_ik: &[u8; 32]) -> Result<Option<u64>> {
        Ok(self.avatars.get(owner_ik).map(|avatar| avatar.updated_ms))
    }

    fn put_group_avatar(&mut self, chat_id: &[u8; 16], avatar: &StoredGroupAvatar) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // То же сравнение, что в `INSERT` файловой базы, и повторено оно
        // здесь по той же причине, что у названия: разойдись две реализации
        // одного хранилища, симуляция §16 проверяла бы не то, что работает
        // на устройстве. Расхождение ловит `persistence.rs` — он гоняет обе
        // одним тестом.
        match self.group_avatars.get_mut(chat_id) {
            Some(known) => {
                if (avatar.avatar_wall, avatar.avatar_logical)
                    >= (known.avatar_wall, known.avatar_logical)
                {
                    known.clone_from(avatar);
                }
            }
            None => {
                self.group_avatars.insert(*chat_id, avatar.clone());
            }
        }
        Ok(())
    }

    fn group_avatar(&self, chat_id: &[u8; 16]) -> Result<Option<StoredGroupAvatar>> {
        Ok(self.group_avatars.get(chat_id).cloned())
    }

    fn has_group_avatar(&self, chat_id: &[u8; 16]) -> Result<bool> {
        Ok(self.group_avatars.get(chat_id).is_some_and(|a| !a.bytes.is_empty()))
    }

    fn group_avatar_stamp(&self, chat_id: &[u8; 16]) -> Result<Option<(u64, u32)>> {
        Ok(self.group_avatars.get(chat_id).map(|a| (a.avatar_wall, a.avatar_logical)))
    }

    fn delete_avatar(&mut self, owner_ik: &[u8; 32]) -> Result<()> {
        self.avatars.remove(owner_ik);
        Ok(())
    }

    fn put_archived(&mut self, chat_id: &[u8; 16], block: &ArchivedBlock) -> Result<()> {
        // `or_insert`, как `OR IGNORE` в файловой базе: позиция одна,
        // и второй кадр под тем же номером — ретрансляция того же самого.
        self.archive.entry((*chat_id, block.author_ik, block.seq)).or_insert_with(|| block.clone());
        Ok(())
    }

    fn archived(&self, chat_id: &[u8; 16], msg_id: &[u8; 16]) -> Result<Option<ArchivedBlock>> {
        Ok(self
            .archive
            .iter()
            .find(|((chat, _, _), block)| chat == chat_id && block.msg_id == *msg_id)
            .map(|(_, block)| block.clone()))
    }

    fn archived_range(
        &self,
        chat_id: &[u8; 16],
        author_ik: &[u8; 32],
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<ArchivedBlock>> {
        // Ключ карты — «чат, автор, номер», и обход по нему уже
        // отсортирован: то же, что `ORDER BY seq` в файловой базе.
        Ok(self
            .archive
            .iter()
            .filter(|((chat, author, seq), _)| {
                chat == chat_id && author == author_ik && *seq >= from_seq
            })
            .take(limit)
            .map(|(_, block)| block.clone())
            .collect())
    }

    fn archive_have(&self, chat_id: &[u8; 16]) -> Result<Vec<HaveRange>> {
        // Склейка подряд идущих, а не `MIN..MAX` по автору: провал
        // в журнале — не порча, а то, что §7.3 велит видеть по номеру.
        // Ключ карты уже упорядочен (чат, автор, номер), и обход идёт
        // в том же порядке, в каком строки едут на провод.
        let mut found: Vec<HaveRange> = Vec::new();
        for ((chat, author, seq), _) in &self.archive {
            if chat != chat_id {
                continue;
            }
            match found.last_mut() {
                Some(run) if run.author_ik == *author && run.last_seq.saturating_add(1) == *seq => {
                    run.last_seq = *seq;
                }
                _ => found.push(HaveRange { author_ik: *author, first_seq: *seq, last_seq: *seq }),
            }
        }
        Ok(found)
    }

    fn archive_recent(&self, chat_id: &[u8; 16], limit: usize) -> Result<Vec<ArchivedBlock>> {
        let mut found: Vec<ArchivedBlock> = self
            .archive
            .iter()
            .filter(|((chat, _, _), _)| chat == chat_id)
            .map(|(_, block)| block.clone())
            .collect();
        // Свежие первыми — тем же правилом, что в файловой базе:
        // по времени приёма, а при равном — по номеру.
        found.sort_by_key(|block| {
            (std::cmp::Reverse(block.received_ms), std::cmp::Reverse(block.seq))
        });
        found.truncate(limit);
        Ok(found)
    }

    fn prune_archive(
        &mut self,
        chat_id: &[u8; 16],
        max_days: u32,
        max_bytes: u64,
        now_ms: u64,
    ) -> Result<usize> {
        let day_ms = 24 * 60 * 60 * 1000u64;
        let edge = now_ms.saturating_sub(u64::from(max_days).saturating_mul(day_ms));
        let before = self.archive.len();
        self.archive.retain(|(chat, _, _), block| chat != chat_id || block.received_ms >= edge);

        // Снимается **префикс**: самое раннее по времени и номеру, пока
        // канал не влезет в окно. Так же, как в файловой базе, — иначе
        // have-вектор разошёлся бы у двух хранилищ.
        loop {
            let total: u64 = self
                .archive
                .iter()
                .filter(|((chat, _, _), _)| chat == chat_id)
                .map(|(_, block)| block.frame.len() as u64)
                .sum();
            if total <= max_bytes {
                break;
            }
            let Some(oldest) = self
                .archive
                .iter()
                .filter(|((chat, _, _), _)| chat == chat_id)
                .min_by_key(|(&(_, _, seq), block)| (block.received_ms, seq))
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.archive.remove(&oldest);
        }
        Ok(before - self.archive.len())
    }

    fn put_seed(&mut self, chat_id: &[u8; 16], seed: &StoredSeed) -> Result<()> {
        self.seeds.insert((*chat_id, seed.ik), seed.clone());
        Ok(())
    }

    fn seeds(&self, chat_id: &[u8; 16]) -> Result<Vec<StoredSeed>> {
        Ok(self
            .seeds
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|(_, seed)| seed.clone())
            .collect())
    }

    fn delete_seed(&mut self, chat_id: &[u8; 16], ik: &[u8; 32]) -> Result<()> {
        self.seeds.remove(&(*chat_id, *ik));
        Ok(())
    }

    fn prune_seeds(&mut self, now_ms: u64) -> Result<usize> {
        let before = self.seeds.len();
        self.seeds.retain(|_, seed| seed.valid_until_ms > now_ms);
        Ok(before - self.seeds.len())
    }

    fn seeding(&self, chat_id: &[u8; 16]) -> Result<Option<u32>> {
        Ok(self.seeding.get(chat_id).map(|(mode, _)| *mode))
    }

    fn set_seeding(&mut self, chat_id: &[u8; 16], mode: u32, now_ms: u64) -> Result<()> {
        self.seeding.insert(*chat_id, (mode, now_ms));
        Ok(())
    }

    fn sharing(&self, chat_id: &[u8; 16]) -> Result<Option<u32>> {
        Ok(self.sharing.get(chat_id).copied())
    }

    fn set_sharing(&mut self, chat_id: &[u8; 16], level: Option<u32>, _now_ms: u64) -> Result<()> {
        // `None` — запись уходит: пустота значит «как у аккаунта», и это
        // не то же, что уровень «всем» (§12).
        match level {
            Some(level) => {
                self.sharing.insert(*chat_id, level);
            }
            None => {
                self.sharing.remove(chat_id);
            }
        }
        Ok(())
    }
    fn put_channel_request(
        &mut self,
        chat_id: &[u8; 16],
        who: &[u8; 32],
        now_ms: u64,
    ) -> Result<()> {
        // `or_insert`, а не `insert`: время — момент первой просьбы,
        // и повтор его не двигает. То же правило, что в файловой базе.
        self.requests.entry((*chat_id, *who)).or_insert(now_ms);
        Ok(())
    }

    fn channel_requests(&self, chat_id: &[u8; 16]) -> Result<Vec<([u8; 32], u64)>> {
        Ok(self
            .requests
            .iter()
            .filter(|((chat, _), _)| chat == chat_id)
            .map(|((_, who), at)| (*who, *at))
            .collect())
    }

    fn delete_channel_request(&mut self, chat_id: &[u8; 16], who: &[u8; 32]) -> Result<()> {
        self.requests.remove(&(*chat_id, *who));
        Ok(())
    }

    fn put_peer(&mut self, peer: &StoredPeer) -> Result<()> {
        self.peers.insert(peer.ik, peer.clone());
        Ok(())
    }

    fn peers(&self) -> Result<Vec<StoredPeer>> {
        Ok(self.peers.values().cloned().collect())
    }

    fn delete_peer(&mut self, ik: &[u8; 32]) -> Result<()> {
        self.peers.remove(ik);
        Ok(())
    }

    fn last_heard_in_chat(&self, chat_id: &[u8; 16], sender_ik: &[u8; 32]) -> Result<Option<u64>> {
        // Надгробия здесь **не** отсеиваются, как и в файловой базе:
        // удалённое сообщение — всё равно свидетельство того, что человек
        // тогда был. Отсеивай мы их, уборка §12 через три месяца молча
        // превращала бы живого собеседника в пропавшего.
        Ok(self
            .messages
            .iter()
            .filter(|((chat, _, _), m)| chat == chat_id && m.sender_ik == *sender_ik)
            .map(|(_, m)| m.received_ms)
            .max())
    }

    fn replace_pending_group(&mut self, frames: &[StoredPendingGroup]) -> Result<()> {
        self.parked = frames.to_vec();
        Ok(())
    }

    fn pending_group(&self) -> Result<Vec<StoredPendingGroup>> {
        Ok(self.parked.clone())
    }

    fn put_outbox(&mut self, entry: &StoredOutbox) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.outbox.insert((entry.msg_id, entry.recipient_ik), entry.clone());
        Ok(())
    }

    fn outbox(&self) -> Result<Vec<StoredOutbox>> {
        let mut found: Vec<StoredOutbox> = self.outbox.values().cloned().collect();
        found.sort_by_key(|e| (e.queued_ms, e.msg_id));
        Ok(found)
    }

    fn delete_outbox(&mut self, msg_id: &MsgId, recipient_ik: &[u8; 32]) -> Result<()> {
        self.outbox.remove(&(*msg_id, *recipient_ik));
        Ok(())
    }

    fn delete_outbox_all(&mut self, msg_id: &MsgId) -> Result<()> {
        self.outbox.retain(|(id, _), _| id != msg_id);
        Ok(())
    }

    fn put_file(&mut self, file: &StoredFile) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        // Не затирать существующее — то же правило и тот же довод, что
        // у `INSERT OR IGNORE` в файловой базе: тот же файл приезжает
        // вторым сообщением после пересылки, а у нас он к тому времени
        // может быть уже собран.
        self.files.entry(file.file_id).or_insert_with(|| file.clone());
        self.links.insert((file.msg_id, file.file_id), file.ordinal);
        Ok(())
    }

    fn file(&self, file_id: &FileId) -> Result<Option<StoredFile>> {
        let Some(file) = self.files.get(file_id) else { return Ok(None) };
        // Самое раннее вложение — тот же выбор, что делает файловая база.
        // Связки не осталось вовсе — отдаём запись как есть: сообщение
        // могли стереть раньше байтов.
        let earliest = self
            .links
            .iter()
            .filter(|((_, id), _)| id == file_id)
            .min_by_key(|((msg_id, _), ordinal)| (**ordinal, *msg_id));
        let mut file = file.clone();
        if let Some(((msg_id, _), ordinal)) = earliest {
            file.msg_id = *msg_id;
            file.ordinal = *ordinal;
        }
        Ok(Some(file))
    }

    fn messages_of_file(&self, file_id: &FileId) -> Result<Vec<MsgId>> {
        Ok(self.links.keys().filter(|(_, id)| id == file_id).map(|(msg_id, _)| *msg_id).collect())
    }

    fn attach_file(&mut self, msg_id: &MsgId, file_id: &FileId, ordinal: u32) -> Result<()> {
        self.links.insert((*msg_id, *file_id), ordinal);
        Ok(())
    }

    fn detach_files_of(&mut self, msg_id: &MsgId) -> Result<Vec<FileId>> {
        let attached: Vec<FileId> =
            self.links.keys().filter(|(m, _)| m == msg_id).map(|(_, f)| *f).collect();
        self.links.retain(|(m, _), _| m != msg_id);
        let orphans: Vec<FileId> = attached
            .into_iter()
            .filter(|file_id| !self.links.keys().any(|(_, id)| id == file_id))
            .collect();
        // Строки уходят здесь же — как их уносит триггер в файловой базе.
        // Список всё равно возвращается: байты лежат не в хранилище,
        // и убрать их может только вызывающий.
        self.drop_orphan_files();
        Ok(orphans)
    }

    fn orphan_file_ids(&self) -> Result<Vec<FileId>> {
        Ok(self
            .files
            .keys()
            .filter(|file_id| !self.links.keys().any(|(_, id)| id == *file_id))
            .copied()
            .collect())
    }

    fn files_of(&self, msg_id: &MsgId) -> Result<Vec<StoredFile>> {
        let mut found: Vec<StoredFile> = self
            .links
            .iter()
            .filter(|((m, _), _)| m == msg_id)
            .filter_map(|((_, file_id), ordinal)| {
                self.files.get(file_id).map(|file| StoredFile {
                    msg_id: *msg_id,
                    ordinal: *ordinal,
                    ..file.clone()
                })
            })
            .collect();
        // Тот же порядок, что обещает `Store::files_of` и выдаёт SQLite:
        // сперва по месту в сообщении, а при равенстве — по идентификатору.
        // Расхождение двух хранилищ здесь было бы худшим сортом ошибки:
        // тесты на памяти зелёные, на устройстве вложения переставлены.
        found.sort_by_key(|file| (file.ordinal, file.file_id));
        Ok(found)
    }

    fn put_contact_share(&mut self, share: &StoredContactShare) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.contact_shares.insert(share.msg_id, share.clone());
        Ok(())
    }

    fn contact_share_of(&self, msg_id: &MsgId) -> Result<Option<StoredContactShare>> {
        Ok(self.contact_shares.get(msg_id).cloned())
    }

    fn set_accepted(&mut self, file_id: &FileId, accepted: bool) -> Result<bool> {
        let Some(file) = self.files.get_mut(file_id) else { return Ok(false) };
        file.accepted = accepted;
        Ok(true)
    }

    fn complete_file(&mut self, file_id: &FileId) -> Result<bool> {
        let Some(file) = self.files.get_mut(file_id) else { return Ok(false) };
        file.complete = true;
        Ok(true)
    }

    fn note_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        self.chunks.insert((*file_id, index));
        Ok(())
    }

    fn has_chunk(&self, file_id: &FileId, index: u64) -> Result<bool> {
        Ok(self.chunks.contains(&(*file_id, index)))
    }

    fn received_chunks(&self, file_id: &FileId) -> Result<u64> {
        Ok(self.chunks.range((*file_id, 0)..=(*file_id, u64::MAX)).count() as u64)
    }

    fn put_staged(&mut self, staged: &StagedUpload) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.staged.insert(staged.file_id, staged.clone());
        Ok(())
    }

    fn staged_uploads(&self) -> Result<Vec<StagedUpload>> {
        let mut found: Vec<StagedUpload> = self.staged.values().cloned().collect();
        // Тот же порядок, что обещан трейтом и что даёт SQLite: ключ карты —
        // `file_id`, и без этой строки две реализации разошлись бы молча.
        found.sort_by_key(|staged| (staged.started_ms, staged.file_id));
        Ok(found)
    }

    fn note_staged_chunk(&mut self, file_id: &FileId, index: u64) -> Result<()> {
        self.staged_chunks.insert((*file_id, index));
        Ok(())
    }

    fn staged_chunks(&self, file_id: &FileId) -> Result<Vec<u64>> {
        Ok(self
            .staged_chunks
            .range((*file_id, 0)..=(*file_id, u64::MAX))
            .map(|(_, index)| *index)
            .collect())
    }

    fn delete_staged(&mut self, file_id: &FileId) -> Result<()> {
        self.staged.remove(file_id);
        self.staged_chunks.retain(|(id, _)| id != file_id);
        Ok(())
    }

    fn staged_older_than(&self, cutoff_ms: u64) -> Result<Vec<FileId>> {
        Ok(self
            .staged
            .values()
            .filter(|staged| staged.started_ms < cutoff_ms)
            .map(|staged| staged.file_id)
            .collect())
    }

    fn next_missing_chunk(&self, file_id: &FileId, chunk_total: u64) -> Result<Option<u64>> {
        let mut expected = 0u64;
        for (_, index) in self.chunks.range((*file_id, 0)..=(*file_id, u64::MAX)) {
            if *index != expected {
                return Ok(Some(expected));
            }
            expected += 1;
        }
        Ok((expected < chunk_total).then_some(expected))
    }

    fn unfinished_files(&self) -> Result<Vec<StoredFile>> {
        Ok(self.files.values().filter(|f| !f.complete).cloned().collect())
    }

    fn file_ids_of_chat(&self, chat_id: &[u8; 16]) -> Result<Vec<FileId>> {
        let of_chat = self.message_ids_of_chat(chat_id);
        let mut found: Vec<FileId> = self
            .links
            .keys()
            .filter(|(msg_id, _)| of_chat.contains(msg_id))
            .map(|(_, file_id)| *file_id)
            .collect();
        // Один файл может висеть на двух сообщениях одного чата — после
        // пересылки внутри него. Список — про файлы, а не про вложения.
        found.sort_unstable();
        found.dedup();
        Ok(found)
    }

    fn all_file_ids(&self) -> Result<Vec<FileId>> {
        Ok(self.files.keys().copied().collect())
    }

    /// Ищет обходом, а не по индексу — и это не упрощение.
    ///
    /// Индекс в файловой базе нужен затем, чтобы не хранить открытый текст
    /// рядом с зашифрованным. Здесь всё и так в памяти процесса, прятать
    /// не от кого, а вот **правила** обязаны совпасть до буквы: те же слова,
    /// то же приведение к нижнему регистру, то же «нужны все слова
    /// запроса». Разойдись они — симуляция (§16) проверяла бы не тот поиск,
    /// который поедет на телефон.
    fn search(&self, chat_id: Option<&[u8; 16]>, query: &str, limit: usize) -> Result<Vec<MsgId>> {
        let wanted = crate::tokens::words(query);
        if wanted.is_empty() {
            return Ok(Vec::new());
        }

        let mut found: Vec<(Hlc, MsgId)> = self
            .messages
            .iter()
            .filter(|((chat, _, _), _)| chat_id.is_none_or(|want| chat == want))
            .filter(|(_, message)| !self.tombstones.contains_key(&message.msg_id))
            .filter(|(_, message)| {
                let Ok(text) = std::str::from_utf8(&message.body) else { return false };
                let present = crate::tokens::words(text);
                wanted.iter().all(|word| present.contains(word))
            })
            .map(|(_, message)| (message.hlc, message.msg_id))
            .collect();

        // Новые первыми — как и в файловой базе.
        found.sort_unstable_by(|a, b| b.cmp(a));
        found.truncate(limit);
        Ok(found.into_iter().map(|(_, msg_id)| msg_id).collect())
    }

    fn delete_file(&mut self, file_id: &FileId) -> Result<()> {
        self.files.remove(file_id);
        self.links.retain(|(_, id), _| id != file_id);
        // Каскада внешних ключей здесь нет — он делается руками, иначе
        // симуляция разошлась бы с продуктом там, где это заметно: учёт
        // чанков пережил бы файл.
        self.chunks.retain(|(id, _)| id != file_id);
        Ok(())
    }

    fn note_seen(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        Ok(self.seen.insert(*msg_id, now_ms).is_none())
    }

    fn seen(&self, msg_id: &MsgId) -> Result<bool> {
        Ok(self.seen.contains_key(msg_id))
    }

    fn compact(&mut self, task: Task, now_ms: u64) -> Result<u64> {
        // Ветки перечислены поимённо: новая задача уборки обязана сломать
        // компиляцию здесь, а не тихо остаться невыполненной.
        let removed = match task {
            Task::Dedup => {
                let before = self.seen.len();
                self.seen
                    .retain(|_, at| !compaction::is_expired(*at, now_ms, compaction::DEDUP_TTL_MS));
                (before - self.seen.len()) as u64
            }
            Task::Tombstones => {
                // По возрасту **надгробия**, а не сообщения. Раньше здесь
                // стояло `received_ms`, и уборка выносила всю переписку
                // старше девяноста суток — не удалённую, а просто старую.
                // В симуляции с длинным горизонтом (§16) это выглядело бы
                // как потеря истории на ровном месте.
                let expired: Vec<MsgId> = self
                    .tombstones
                    .iter()
                    .filter(|(_, at)| {
                        compaction::is_expired(**at, now_ms, compaction::TOMBSTONE_TTL_MS)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                let count = expired.len() as u64;
                for msg_id in expired {
                    self.tombstones.remove(&msg_id);
                    self.messages.retain(|_, m| m.msg_id != msg_id);
                    // В файловой базе это делает каскад внешнего ключа;
                    // здесь — руками, иначе симуляция разошлась бы с продуктом.
                    self.reactions.retain(|(id, _), _| *id != msg_id);
                }
                count
            }
            // Этим задачам в памяти соответствовать нечему: кэши ключей,
            // сборки фрагментов и снапшоты групп живут в самом движке,
            // а не в хранилище. Ноль здесь — честный ответ, а не заглушка.
            Task::SkippedKeys
            | Task::HandshakeSeen
            | Task::Reassembly
            | Task::CausalRefs
            | Task::GroupSnapshot => 0,
        };
        Ok(removed)
    }

    fn export_into(
        &self,
        _scope: crate::archive::ExportScope,
        _sink: &mut dyn crate::archive::ArchiveSink,
    ) -> Result<()> {
        Err(StoreError::Unsupported("экспорт архива требует файловой базы (§12)"))
    }

    fn export_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        // Ключа тут нет вовсе: хранилище в памяти ничего не шифрует.
        Err(StoreError::Unsupported("у хранилища в памяти нет ключа базы"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: [u8; 16] = [7u8; 16];

    fn store() -> MemoryStore {
        let mut s = MemoryStore::new();
        s.migrate().unwrap();
        s
    }

    fn message(n: u8, wall_ms: u64) -> StoredMessage {
        StoredMessage {
            msg_id: [n; 16],
            chat_id: CHAT,
            sender_ik: [1u8; 32],
            hlc: Hlc::new(wall_ms, 0),
            body: vec![n],
            received_ms: wall_ms,
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        }
    }

    #[test]
    fn writing_before_migration_is_refused() {
        let mut s = MemoryStore::new();
        assert!(s.put_message(&message(1, 100)).is_err());
    }

    #[test]
    fn messages_come_back_in_hlc_order() {
        let mut s = store();
        // Кладём вперемешку — порядок задаёт HLC, а не порядок вставки (§9.1).
        for (n, wall) in [(3u8, 300u64), (1, 100), (2, 200)] {
            s.put_message(&message(n, wall)).unwrap();
        }
        let got = s.messages(&CHAT, 10, None).unwrap();
        assert_eq!(got.iter().map(|m| m.body[0]).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[test]
    fn limit_returns_the_newest_window() {
        let mut s = store();
        for n in 1..=5u8 {
            s.put_message(&message(n, u64::from(n) * 100)).unwrap();
        }
        let got = s.messages(&CHAT, 2, None).unwrap();
        assert_eq!(got.iter().map(|m| m.body[0]).collect::<Vec<_>>(), vec![4, 5]);
    }

    #[test]
    fn before_pages_backwards() {
        let mut s = store();
        for n in 1..=5u8 {
            s.put_message(&message(n, u64::from(n) * 100)).unwrap();
        }
        let got = s.messages(&CHAT, 2, Some(Hlc::new(400, 0))).unwrap();
        assert_eq!(got.iter().map(|m| m.body[0]).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn other_chats_are_not_mixed_in() {
        let mut s = store();
        s.put_message(&message(1, 100)).unwrap();
        let mut other = message(2, 200);
        other.chat_id = [9u8; 16];
        s.put_message(&other).unwrap();

        assert_eq!(s.messages(&CHAT, 10, None).unwrap().len(), 1);
        assert_eq!(s.messages(&[9u8; 16], 10, None).unwrap().len(), 1);
    }

    #[test]
    fn dedup_reports_first_sighting_only() {
        let mut s = store();
        assert!(s.note_seen(&[1u8; 16], 0).unwrap());
        assert!(!s.note_seen(&[1u8; 16], 1_000).unwrap());
    }

    #[test]
    fn compaction_expires_the_dedup_window() {
        let mut s = store();
        s.note_seen(&[1u8; 16], 0).unwrap();
        assert_eq!(s.compact(Task::Dedup, compaction::DEDUP_TTL_MS).unwrap(), 1);
        assert_eq!(s.seen_len(), 0);
        // После истечения тот же идентификатор снова считается новым.
        assert!(s.note_seen(&[1u8; 16], compaction::DEDUP_TTL_MS).unwrap());
    }

    #[test]
    fn dedup_boundary_matches_the_in_memory_window() {
        // Окно дедупликации §9.2 существует в двух экземплярах: горячее
        // в движке (`crdt::DedupWindow`) и долговременное здесь. Разойдясь
        // на границе, они дали бы сообщение, воскресшее на одном устройстве
        // и не воскресшее на другом. Тест держит их вместе.
        use ratatosk_crdt::DedupWindow;

        let ttl = compaction::DEDUP_TTL_MS;
        for now in [ttl - 1, ttl, ttl + 1] {
            let mut store = store();
            store.note_seen(&[1u8; 16], 0).unwrap();
            store.compact(Task::Dedup, now).unwrap();

            let mut window = DedupWindow::new(ttl, 1_000);
            window.check([1u8; 16], 0);
            window.purge(now);

            assert_eq!(
                store.seen_len() == 0,
                window.is_empty(),
                "в момент {now} хранилище и окно движка разошлись"
            );
        }
    }

    #[test]
    fn an_edit_replaces_the_body_and_marks_it() {
        let mut s = store();
        s.put_message(&message(1, 100)).unwrap();
        assert!(s.edit_message(&[1u8; 16], b"novoe", 500).unwrap());

        let found = s.message(&[1u8; 16]).unwrap().unwrap();
        assert_eq!(found.body, b"novoe");
        assert_eq!(found.edited_ms, Some(500));

        // Надгробие сильнее правки — то же правило, что в файловой базе.
        s.tombstone_message(&[1u8; 16], 600).unwrap();
        assert!(!s.edit_message(&[1u8; 16], b"vernis", 700).unwrap());
    }

    #[test]
    fn a_taken_back_reaction_is_kept_for_its_tag_but_not_shown() {
        // Обе реализации обязаны понимать снятие одинаково: пустая строка —
        // это запись с меткой, а не то, что рисуют. Разойдись они здесь,
        // и симуляция (§16) перестала бы говорить о продукте.
        let mut s = store();
        s.put_message(&message(1, 100)).unwrap();
        let author = [4u8; 32];
        for (emoji, wall) in [("+", 150u64), ("", 200)] {
            s.put_reaction(&StoredReaction {
                msg_id: [1u8; 16],
                author_ik: author,
                emoji: emoji.into(),
                hlc: Hlc::new(wall, 0),
            })
            .unwrap();
        }

        assert!(s.reactions(&[1u8; 16]).unwrap().is_empty());
        let raw = s.reaction(&[1u8; 16], &author).unwrap().unwrap();
        assert_eq!(raw.hlc, Hlc::new(200, 0));

        // И уходит вместе с сообщением.
        s.tombstone_message(&[1u8; 16], 300).unwrap();
        assert!(s.reaction(&[1u8; 16], &author).unwrap().is_none());
    }

    #[test]
    fn attachments_come_back_in_the_same_order_as_from_sqlite() {
        // **Два хранилища обязаны отвечать одинаково.** Расхождение здесь —
        // худший сорт ошибки: тесты на памяти зелёные, а на устройстве
        // вложения переставлены. Правило одно: сперва `ordinal`, при равенстве
        // — `file_id`; тот же порядок закреплён в `tests/persistence.rs`.
        let mut s = store();
        s.put_message(&message(1, 100)).unwrap();
        for (ordinal, id) in [30u8, 20, 10].into_iter().enumerate() {
            s.put_file(&StoredFile {
                file_id: [id; 16],
                msg_id: [1u8; 16],
                name: format!("файл {ordinal}"),
                size_bytes: 10,
                chunk_total: 1,
                chunk_bytes: 10,
                key: [0u8; 32],
                preview: None,
                ordinal: u32::try_from(ordinal).unwrap(),
                incoming: true,
                source_path: None,
                accepted: true,
                complete: true,
            })
            .unwrap();
        }
        let names: Vec<String> =
            s.files_of(&[1u8; 16]).unwrap().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["файл 0", "файл 1", "файл 2"]);
    }

    #[test]
    fn the_resume_point_is_the_first_gap() {
        // То же правило, что в файловой базе: продолжать надо с дырки,
        // а не с числа принятых. Разойдясь здесь, симуляция (§16) перестала бы
        // говорить о продукте — а именно её мы гоняем на перестановках.
        let mut s = store();
        s.put_message(&message(1, 100)).unwrap();
        s.put_file(&StoredFile {
            file_id: [2u8; 16],
            msg_id: [1u8; 16],
            name: "a.bin".into(),
            size_bytes: 10,
            chunk_total: 3,
            chunk_bytes: 4,
            key: [0u8; 32],
            preview: None,
            ordinal: 0,
            incoming: true,
            source_path: None,
            accepted: false,
            complete: false,
        })
        .unwrap();

        assert_eq!(s.next_missing_chunk(&[2u8; 16], 3).unwrap(), Some(0));
        s.note_chunk(&[2u8; 16], 0).unwrap();
        s.note_chunk(&[2u8; 16], 2).unwrap();
        assert_eq!(s.received_chunks(&[2u8; 16]).unwrap(), 2);
        assert_eq!(s.next_missing_chunk(&[2u8; 16], 3).unwrap(), Some(1));
        s.note_chunk(&[2u8; 16], 1).unwrap();
        assert_eq!(s.next_missing_chunk(&[2u8; 16], 3).unwrap(), None);

        s.delete_file(&[2u8; 16]).unwrap();
        assert_eq!(s.received_chunks(&[2u8; 16]).unwrap(), 0);
    }

    #[test]
    fn export_says_it_cannot() {
        // Отказ словами, а не паника: вывезти переписку из симуляции (§16)
        // нельзя, и узнать об этом вызывающий обязан внятно.
        let s = store();
        let mut nowhere = Vec::new();
        let head = crate::archive::Header {
            archive_id: [0u8; 16],
            scope: crate::archive::ExportScope::Everything,
        };
        let mut sink = crate::archive::ArchiveWriter::start(&mut nowhere, head).unwrap();
        assert!(matches!(
            s.export_into(crate::archive::ExportScope::Everything, &mut sink),
            Err(StoreError::Unsupported(_))
        ));
        assert!(matches!(s.export_key(), Err(StoreError::Unsupported(_))));
    }

    fn group(byte: u8, title: &str, created_ms: u64) -> StoredGroup {
        StoredGroup {
            chat_id: [byte; 16],
            owner_ik: [byte.wrapping_add(100); 32],
            title: title.to_owned(),
            // Метка нулевая: заготовка про хранение, а не про порядок,
            // а тесты порядка ставят её сами.
            title_wall: 0,
            title_logical: 0,
            created_ms,
            profile: 0,
        }
    }

    fn op(member: u8, wall: u64, removed: bool) -> StoredMembershipOp {
        StoredMembershipOp {
            member_ik: [member; 32],
            tag_wall: wall,
            tag_logical: 0,
            tag_actor: [1u8; 32],
            tag_uniq: [member; 8],
            removed,
        }
    }

    #[test]
    fn a_repeated_put_renames_the_group_but_keeps_its_owner() {
        // То же правило, что в файловой базе: владелец у группы один
        // и на всю жизнь (§11.2).
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        let mut renamed = group(7, "у большого костра", 5_000);
        renamed.owner_ik = [3u8; 32];
        s.put_group(&renamed).unwrap();

        let found = s.group(&[7u8; 16]).unwrap().unwrap();
        assert_eq!(found.title, "у большого костра");
        assert_eq!(found.owner_ik, [107u8; 32], "владелец обязан остаться прежним");
        assert_eq!(found.created_ms, 1_000, "время заведения обязано остаться прежним");
    }

    #[test]
    fn groups_come_back_in_one_and_the_same_order() {
        let mut s = store();
        s.put_group(&group(9, "третья", 3_000)).unwrap();
        s.put_group(&group(2, "первая", 1_000)).unwrap();
        s.put_group(&group(5, "вторая", 2_000)).unwrap();

        let titles: Vec<String> = s.groups().unwrap().into_iter().map(|g| g.title).collect();
        assert_eq!(titles, vec!["первая", "вторая", "третья"]);
    }

    #[test]
    fn a_membership_tombstone_never_lifts() {
        // Удаление, дошедшее раньше повторного добавления, — не редкость,
        // а случай, ради которого OR-Set и взят.
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_membership(&[7u8; 16], &[op(1, 10, false), op(2, 11, false)]).unwrap();
        s.put_membership(&[7u8; 16], &[op(2, 11, true)]).unwrap();
        s.put_membership(&[7u8; 16], &[op(2, 11, false)]).unwrap();

        let ops = s.membership(&[7u8; 16]).unwrap();
        assert_eq!(ops.len(), 2, "повтор той же метки не заводит новую строку");
        assert_eq!(ops[1], op(2, 11, true), "надгробие обязано остаться стоять");
    }

    #[test]
    fn membership_ops_come_back_in_the_order_the_file_database_gives() {
        // Порядок задан меткой, а не порядком записи: разойдись два
        // хранилища здесь, симуляция §16 перестала бы быть воспроизводимой.
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_membership(&[7u8; 16], &[op(3, 30, false), op(1, 10, false)]).unwrap();
        s.put_membership(&[7u8; 16], &[op(2, 20, false)]).unwrap();

        let walls: Vec<u64> =
            s.membership(&[7u8; 16]).unwrap().iter().map(|o| o.tag_wall).collect();
        assert_eq!(walls, vec![10, 20, 30]);
    }

    fn block(n: u8, author: u8, bytes: &str, received_ms: u64) -> StoredMembershipBlock {
        StoredMembershipBlock {
            block_id: [n; 16],
            author_ik: [author; 32],
            bytes: bytes.as_bytes().to_vec(),
            received_ms,
        }
    }

    #[test]
    fn the_same_block_arriving_twice_does_not_replace_its_bytes() {
        // То же правило, что `DO NOTHING` в файловой базе: идентификатор
        // блока — хэш его байт, и подменить их, назвав прежний, нельзя.
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_membership_block(&[7u8; 16], &block(1, 10, "настоящий", 100)).unwrap();
        s.put_membership_block(&[7u8; 16], &block(1, 10, "подменённый", 900)).unwrap();

        let found = s.membership_blocks(&[7u8; 16]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], block(1, 10, "настоящий", 100));
    }

    #[test]
    fn membership_blocks_come_back_in_the_order_the_file_database_gives() {
        // Порядок задан приёмом, а не порядком записи: по нему блоки
        // пересылаются новичку (§11.5), и разойдись две реализации —
        // симуляция §16 перестала бы что-либо доказывать про продукт.
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_membership_block(&[7u8; 16], &block(3, 30, "третий", 300)).unwrap();
        s.put_membership_block(&[7u8; 16], &block(1, 10, "первый", 100)).unwrap();
        s.put_membership_block(&[7u8; 16], &block(2, 20, "второй", 200)).unwrap();

        let times: Vec<u64> =
            s.membership_blocks(&[7u8; 16]).unwrap().iter().map(|b| b.received_ms).collect();
        assert_eq!(times, vec![100, 200, 300]);
    }

    #[test]
    fn a_sender_chain_belongs_to_one_group_and_one_member() {
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_group(&group(8, "у другого", 2_000)).unwrap();

        let mine = StoredSenderChain {
            member_ik: [1u8; 32],
            chain: [42u8; 32],
            counter: 3,
            chain_wall: 0,
            chain_logical: 0,
            skipped: Vec::new(),
        };
        s.put_sender_chain(&[7u8; 16], &mine).unwrap();

        assert!(s.sender_chain(&[8u8; 16], &[1u8; 32]).unwrap().is_none(), "другая группа");
        assert!(s.sender_chain(&[7u8; 16], &[2u8; 32]).unwrap().is_none(), "другой участник");
        assert_eq!(s.sender_chains(&[7u8; 16]).unwrap(), vec![mine]);
        assert!(s.sender_chains(&[8u8; 16]).unwrap().is_empty());
    }

    #[test]
    fn a_sender_chain_is_replaced_whole() {
        // Ключ и номер врозь бессмысленны: разойдись они — сообщение
        // расшифруется, а место в цепочке окажется не то.
        let mut s = store();
        s.put_group(&group(7, "у костра", 1_000)).unwrap();
        s.put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [42u8; 32],
                counter: 0,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();
        s.put_sender_chain(
            &[7u8; 16],
            &StoredSenderChain {
                member_ik: [1u8; 32],
                chain: [43u8; 32],
                counter: 7,
                chain_wall: 0,
                chain_logical: 0,
                skipped: Vec::new(),
            },
        )
        .unwrap();

        let found = s.sender_chain(&[7u8; 16], &[1u8; 32]).unwrap().unwrap();
        assert_eq!((found.chain, found.counter), ([43u8; 32], 7));
        assert_eq!(s.sender_chains(&[7u8; 16]).unwrap().len(), 1);
    }
}
