//! Реестр сессий и маршрутизация приёма (§7.3, §8.3).
//!
//! Порядок приёма из §7.3 воспроизведён здесь дословно, потому что от него
//! зависит стоимость обработки мусорного кадра:
//!
//! 1. проверка размера и `version`/`type` — в `ratatosk-wire`;
//! 2. поиск сессии по `session_id`;
//! 3. вывод ключа **ровно для позиции `counter`**, проверка тега; только после
//!    успеха достраиваются и кэшируются пропущенные ключи;
//! 4. не нашли сессию / не прошёл тег → отбросить, инкрементировать счётчик
//!    аномалий по источнику.
//!
//! Trial decryption по всем контактам не выполняется. Для рукопожатия есть
//! отдельный путь (§8.3): кадр приходит с `session_id = 0`, и получатель
//! пробует расшифровать своим статическим ключом — одной операцией.

use std::collections::HashMap;

use ratatosk_crypto::handshake::Session;
use ratatosk_wire::HANDSHAKE_SESSION_ID;

use crate::transport_policy::{SessionBinding, Transport};

/// Куда направить принятый кадр.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// В ветку рукопожатия (§8.3).
    Handshake,
    /// В существующую сессию.
    Session(u64),
    /// Сессия неизвестна — отбросить и увеличить счётчик аномалий.
    Unknown,
}

/// Счётчик аномалий по источнику (§7.3, шаг 4).
///
/// Нужен не для наказания, а для наблюдаемости: всплеск отброшенных кадров
/// от одного источника — единственный сигнал о том, что кто-то пытается
/// нагружать устройство мусором.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnomalyCounters {
    /// Кадры с неизвестным `session_id`.
    pub unknown_session: u64,
    /// Кадры, не прошедшие проверку тега.
    pub bad_tag: u64,
    /// Кадры с некорректным форматом.
    pub malformed: u64,
    /// Повторно предъявленные рукопожатия.
    pub handshake_replay: u64,
}

impl AnomalyCounters {
    /// Всего аномалий.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.unknown_session + self.bad_tag + self.malformed + self.handshake_replay
    }
}

/// Сессия вместе с её привязкой к семейству транспортов.
#[derive(Debug)]
pub struct BoundSession {
    /// Криптографическое состояние.
    pub session: Session,
    /// LAN или Tor. Смешивать нельзя никогда (§5.4).
    pub binding: SessionBinding,
}

/// Реестр активных сессий.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    by_id: HashMap<u64, BoundSession>,
    by_peer: HashMap<[u8; 32], Vec<u64>>,
    anomalies: HashMap<[u8; 32], AnomalyCounters>,
}

impl SessionRegistry {
    /// Пустой реестр.
    #[must_use]
    pub fn new() -> SessionRegistry {
        SessionRegistry::default()
    }

    /// Куда направить кадр с таким `session_id`.
    #[must_use]
    pub fn route(&self, session_id: u64) -> Route {
        if session_id == HANDSHAKE_SESSION_ID {
            return Route::Handshake;
        }
        if self.by_id.contains_key(&session_id) {
            Route::Session(session_id)
        } else {
            Route::Unknown
        }
    }

    /// Регистрирует установленную сессию, **вытесняя прежнюю** с тем же
    /// контактом в том же семействе транспортов.
    ///
    /// Возвращает идентификаторы вытесненных: вызывающий обязан убрать их
    /// и с диска, иначе они вернутся после перезапуска.
    ///
    /// Вытеснение — не уборка мусора, а исправление настоящей поломки.
    /// Разговор 1:1 в одном семействе транспортов — это ровно одна сессия;
    /// накапливая их, реестр отдаёт по `for_peer` самую свежую **у себя**,
    /// а собеседник — самую свежую **у него**, и после любого расхождения
    /// (перерукопожатие, потеря сессии одной стороной) выборы перестают
    /// совпадать. Кадры при этом уходят в сессию, которой у другой стороны
    /// нет: она их молча отбрасывает (§7.3), квитанции не приходит, и
    /// отправитель до конца дней объявляет «не доставлено» — при живой связи
    /// и «онлайн» в интерфейсе.
    ///
    /// Второй, менее заметный итог накопления: ключевой материал старых
    /// сессий продолжал лежать в памяти и на диске без всякой пользы.
    pub fn insert(&mut self, session: Session, binding: SessionBinding) -> Vec<u64> {
        let id = session.session_id;
        let peer = session.peer_ik;

        let superseded: Vec<u64> = self
            .by_peer
            .get(&peer)
            .map(|ids| {
                ids.iter()
                    .filter(|old| **old != id)
                    .filter(|old| self.by_id.get(old).is_some_and(|bound| bound.binding == binding))
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        for old in &superseded {
            self.remove(*old);
        }

        self.by_id.insert(id, BoundSession { session, binding });
        let ids = self.by_peer.entry(peer).or_default();
        if !ids.contains(&id) {
            ids.push(id);
        }
        superseded
    }

    /// Сессия по идентификатору.
    #[must_use]
    pub fn get(&self, session_id: u64) -> Option<&BoundSession> {
        self.by_id.get(&session_id)
    }

    /// Изменяемая сессия по идентификатору.
    pub fn get_mut(&mut self, session_id: u64) -> Option<&mut BoundSession> {
        self.by_id.get_mut(&session_id)
    }

    /// Действующая сессия с контактом для указанного транспорта.
    ///
    /// Возвращает только сессию совместимой привязки: сессия, начатая в LAN,
    /// не будет предложена для onion (§5.4).
    #[must_use]
    pub fn for_peer(&self, peer_ik: &[u8; 32], transport: Transport) -> Option<u64> {
        self.by_peer
            .get(peer_ik)?
            .iter()
            .rev()
            .find(|id| self.by_id.get(id).is_some_and(|bound| bound.binding.allows(transport)))
            .copied()
    }

    /// Закрывает сессию — при перерукопожатии (§8.5) или отзыве сопряжения (§13.4).
    pub fn remove(&mut self, session_id: u64) -> Option<BoundSession> {
        let bound = self.by_id.remove(&session_id)?;
        if let Some(ids) = self.by_peer.get_mut(&bound.session.peer_ik) {
            ids.retain(|id| *id != session_id);
        }
        Some(bound)
    }

    /// Сколько активных сессий.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Пуст ли реестр.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Отмечает аномалию по источнику (§7.3, шаг 4).
    pub fn note_anomaly(&mut self, peer_ik: [u8; 32], f: impl FnOnce(&mut AnomalyCounters)) {
        f(self.anomalies.entry(peer_ik).or_default());
    }

    /// Счётчики аномалий по источнику.
    #[must_use]
    pub fn anomalies(&self, peer_ik: &[u8; 32]) -> AnomalyCounters {
        self.anomalies.get(peer_ik).copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatosk_crypto::handshake::Role;

    fn session(peer: u8, transcript: &[u8]) -> Session {
        Session::derive(Role::Initiator, [peer; 32], transcript, b"out", 0)
    }

    #[test]
    fn a_new_session_supersedes_the_old_one_with_the_same_peer() {
        // Разговор 1:1 в одном семействе транспортов — ровно одна сессия.
        // Накапливая их, реестр отдавал бы по `for_peer` самую свежую у себя,
        // а собеседник — самую свежую у него, и после любого расхождения
        // выборы перестали бы совпадать: кадры уходят в сессию, которой
        // у другой стороны нет.
        let mut r = SessionRegistry::new();
        let first = session(1, "первое рукопожатие".as_bytes());
        let second = session(1, "второе рукопожатие".as_bytes());
        let (old_id, new_id) = (first.session_id, second.session_id);
        assert_ne!(old_id, new_id);

        assert!(r.insert(first, SessionBinding::Lan).is_empty(), "вытеснять пока нечего");
        let superseded = r.insert(second, SessionBinding::Lan);

        assert_eq!(superseded, vec![old_id], "прежнюю надо не только забыть, но и назвать");
        assert_eq!(r.len(), 1);
        assert_eq!(r.route(old_id), Route::Unknown);
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Lan), Some(new_id));
    }

    #[test]
    fn sessions_of_different_families_coexist() {
        // Вытесняется только своё семейство: §5.4 держит LAN и Tor раздельно,
        // и сессия в локальной сети не имеет отношения к сессии поверх onion.
        let mut r = SessionRegistry::new();
        let lan = session(1, b"lan");
        let tor = session(1, b"tor");
        let (lan_id, tor_id) = (lan.session_id, tor.session_id);

        r.insert(lan, SessionBinding::Lan);
        assert!(r.insert(tor, SessionBinding::Tor).is_empty(), "чужое семейство не трогаем");

        assert_eq!(r.len(), 2);
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Lan), Some(lan_id));
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Onion), Some(tor_id));
    }

    #[test]
    fn zero_session_id_routes_to_handshake() {
        let r = SessionRegistry::new();
        assert_eq!(r.route(HANDSHAKE_SESSION_ID), Route::Handshake);
    }

    #[test]
    fn unknown_session_is_not_trial_decrypted() {
        // §7.3: перебора по контактам нет. Неизвестный id — сразу Unknown.
        let r = SessionRegistry::new();
        assert_eq!(r.route(12345), Route::Unknown);
    }

    #[test]
    fn known_session_routes_to_itself() {
        let mut r = SessionRegistry::new();
        let s = session(1, b"h");
        let id = s.session_id;
        r.insert(s, SessionBinding::Tor);
        assert_eq!(r.route(id), Route::Session(id));
    }

    #[test]
    fn lan_session_is_not_offered_for_onion() {
        let mut r = SessionRegistry::new();
        let s = session(1, b"h");
        r.insert(s, SessionBinding::Lan);
        assert!(r.for_peer(&[1u8; 32], Transport::Lan).is_some());
        assert!(
            r.for_peer(&[1u8; 32], Transport::Onion).is_none(),
            "§5.4: сессия из LAN не продолжается через onion"
        );
    }

    #[test]
    fn tor_session_serves_onion_and_mail() {
        let mut r = SessionRegistry::new();
        r.insert(session(1, b"h"), SessionBinding::Tor);
        assert!(r.for_peer(&[1u8; 32], Transport::Onion).is_some());
        assert!(r.for_peer(&[1u8; 32], Transport::Mail).is_some());
        assert!(r.for_peer(&[1u8; 32], Transport::Lan).is_none());
    }

    #[test]
    fn removal_cleans_both_indexes() {
        let mut r = SessionRegistry::new();
        let s = session(1, b"h");
        let id = s.session_id;
        r.insert(s, SessionBinding::Tor);
        r.remove(id);
        assert!(r.is_empty());
        assert!(r.for_peer(&[1u8; 32], Transport::Onion).is_none());
    }

    #[test]
    fn anomalies_are_counted_per_source() {
        let mut r = SessionRegistry::new();
        r.note_anomaly([1u8; 32], |c| c.bad_tag += 1);
        r.note_anomaly([1u8; 32], |c| c.unknown_session += 1);
        r.note_anomaly([2u8; 32], |c| c.malformed += 1);

        assert_eq!(r.anomalies(&[1u8; 32]).total(), 2);
        assert_eq!(r.anomalies(&[2u8; 32]).total(), 1);
        assert_eq!(r.anomalies(&[3u8; 32]).total(), 0);
    }
}
