//! Хранилище в памяти — для симуляции и тестов (§16).
//!
//! §16 требует «всю сеть в одном процессе с виртуальным временем». Файловая
//! база этому мешает дважды: она заводит настоящий диск там, где вся суть
//! в отсутствии внешнего мира, и она медленная, когда узлов десятки.
//!
//! Реализация не пытается быть SQLite: у неё нет ни FTS5, ни экспорта.
//! Зато она даёт трейту [`Store`] вторую реализацию — а трейт с одной
//! реализацией никогда не бывает честной абстракцией.

use std::collections::{BTreeMap, HashMap};

use ratatosk_crdt::{Hlc, MsgId};

use crate::compaction::{self, Task};
use crate::{
    Result, Store, StoreError, StoredAvatar, StoredContact, StoredMessage, StoredOutbox,
    StoredReaction, StoredSession,
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
    avatars: BTreeMap<[u8; 32], StoredAvatar>,
    /// Ключ — пара «сообщение, автор»: реакция от человека одна, новая
    /// заменяет прежнюю.
    reactions: BTreeMap<(MsgId, [u8; 32]), StoredReaction>,
    outbox: BTreeMap<MsgId, StoredOutbox>,
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
        let removed: Vec<MsgId> = self
            .messages
            .iter()
            .filter(|((chat, _, _), _)| chat == chat_id)
            .map(|(_, m)| m.msg_id)
            .collect();
        self.messages.retain(|(chat, _, _), _| chat != chat_id);
        for msg_id in removed {
            self.tombstones.remove(&msg_id);
            self.reactions.retain(|(id, _), _| *id != msg_id);
        }
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

    fn delete_avatar(&mut self, owner_ik: &[u8; 32]) -> Result<()> {
        self.avatars.remove(owner_ik);
        Ok(())
    }

    fn put_outbox(&mut self, entry: &StoredOutbox) -> Result<()> {
        if !self.migrated {
            return Err(StoreError::Backend("хранилище не проинициализировано".into()));
        }
        self.outbox.insert(entry.msg_id, entry.clone());
        Ok(())
    }

    fn outbox(&self) -> Result<Vec<StoredOutbox>> {
        let mut found: Vec<StoredOutbox> = self.outbox.values().cloned().collect();
        found.sort_by_key(|e| (e.queued_ms, e.msg_id));
        Ok(found)
    }

    fn delete_outbox(&mut self, msg_id: &MsgId) -> Result<()> {
        self.outbox.remove(msg_id);
        Ok(())
    }

    fn note_seen(&mut self, msg_id: &MsgId, now_ms: u64) -> Result<bool> {
        Ok(self.seen.insert(*msg_id, now_ms).is_none())
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

    fn export(&self, _destination: &std::path::Path) -> Result<()> {
        Err(StoreError::Unsupported("экспорт архива требует файловой базы (§12)"))
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
    fn export_says_it_cannot() {
        let s = store();
        assert!(matches!(
            s.export(std::path::Path::new("/tmp/x")),
            Err(StoreError::Unsupported(_))
        ));
    }
}
