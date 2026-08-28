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
    /// Сессия отправлена на покой: принимать по ней можно, отправлять — нет.
    ///
    /// Различие появилось из разбора живой поломки, и оно того стоит.
    /// Молчание в ответ на ушедший кадр — свидетельство об **одном
    /// направлении**: наши кадры до собеседника не доходят или его квитанции
    /// не доходят до нас. О том, доходят ли **его** сообщения до нас, оно
    /// не говорит ничего.
    ///
    /// Раньше такая сессия просто удалялась. Итог на стенде: мы её забыли,
    /// собеседник — нет, он продолжает слать по ней, а мы каждый его кадр
    /// молча отбрасываем как «неизвестная сессия». Сказать ему об этом
    /// нечем: кадр не расшифрован, кто прислал — неизвестно. Переписка
    /// умирает в одну сторону навсегда, при живой связи с обеих.
    ///
    /// Поэтому теперь такая сессия остаётся принимать. Отправка идёт через
    /// новое рукопожатие, а когда оно закончится, покойную вытеснит
    /// [`SessionRegistry::insert`] обычным порядком.
    pub retired: bool,
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
    ///
    /// # Вытеснение — на покой, а не в небытие
    ///
    /// Прежняя сессия семейства **не удаляется**, а отправляется на покой:
    /// отправлять по ней больше нельзя, принимать — можно. Разница стоила
    /// разбора живой поломки, и она вот в чём.
    ///
    /// Две стороны заводят сессии независимо, и в одном семействе они могут
    /// разойтись без всякой ошибки — например, если обе одновременно начали
    /// рукопожатие (каждая ответила на чужое и установила своё). Тогда у нас
    /// побеждает одна, у собеседника другая, и при удалении прежней каждая
    /// сторона молча отбрасывает всё, что шлёт вторая: «кадр для неизвестной
    /// сессии». Переписка умирает при живой связи с обеих сторон, и вылечить
    /// это нечем — по почте квитанций нет (§9.4), то есть отправитель даже
    /// не узнает, что его не слышат.
    ///
    /// Оставшись принимающей, прежняя сессия закрывает этот случай целиком:
    /// кто бы какую ни выбрал для отправки, у другой стороны она есть.
    ///
    /// Копиться при этом нечему: следующая сессия убирает покойную насовсем.
    /// В семействе живут самое большее две — одна отправляет, одна дослушивает.
    ///
    /// Возвращаются **только удалённые** идентификаторы: ушедшая на покой
    /// с диска не убирается, иначе после перезапуска она не смогла бы
    /// дослушать то, ради чего оставлена.
    pub fn insert(&mut self, session: Session, binding: SessionBinding) -> Vec<u64> {
        let id = session.session_id;
        let peer = session.peer_ik;

        let same_family: Vec<u64> = self
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

        // Действующая уходит на покой, уже покойная — насовсем. Одно
        // поколение отсрочки, не больше: в семействе живёт одна отправляющая
        // сессия и одна принимающая, и обе кончаются вместе со следующей.
        let mut removed = Vec::new();
        for old in same_family {
            match self.by_id.get_mut(&old) {
                Some(bound) if !bound.retired => bound.retired = true,
                _ => {
                    self.remove(old);
                    removed.push(old);
                }
            }
        }

        self.by_id.insert(id, BoundSession { session, binding, retired: false });
        let ids = self.by_peer.entry(peer).or_default();
        if !ids.contains(&id) {
            ids.push(id);
        }
        removed
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
            .find(|id| {
                self.by_id
                    .get(id)
                    .is_some_and(|bound| !bound.retired && bound.binding.allows(transport))
            })
            .copied()
    }

    /// Все сессии с этим контактом — включая отправленные на покой.
    ///
    /// Отдельно от [`SessionRegistry::for_peer`], и разница существенная:
    /// тот отвечает на вопрос «по чему отправлять», а этот — «что вообще
    /// связано с этим человеком». Удаление контакта спрашивает второе:
    /// пережившая удаление сессия продолжала бы расшифровывать кадры
    /// от того, кого в контактах больше нет.
    #[must_use]
    pub fn all_for_peer(&self, peer_ik: &[u8; 32]) -> Vec<u64> {
        self.by_peer.get(peer_ik).cloned().unwrap_or_default()
    }

    /// Отправляет сессию на покой: принимать по ней можно, отправлять — нет.
    ///
    /// Возвращает `true`, если было что отправлять. Зовётся, когда кадр ушёл,
    /// а ответа в срок не пришло: это свидетельство об одном направлении,
    /// и рвать из-за него второе — та самая поломка, ради которой признак
    /// и заведён (см. [`BoundSession::retired`]).
    pub fn retire(&mut self, peer_ik: &[u8; 32], transport: Transport) -> bool {
        let Some(session_id) = self.for_peer(peer_ik, transport) else {
            return false;
        };
        match self.by_id.get_mut(&session_id) {
            Some(bound) => {
                bound.retired = true;
                true
            }
            None => false,
        }
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
    fn a_retired_session_still_receives_but_no_longer_sends() {
        // Разбор живой поломки. Молчание в ответ на ушедший кадр — это
        // свидетельство об **одном** направлении. Закрывая из-за него сессию
        // целиком, мы её забывали, а собеседник нет: он продолжал слать
        // по ней, мы каждый его кадр отбрасывали как «неизвестная сессия»,
        // и сказать ему об этом было нечем — кадр не расшифрован, кто
        // прислал, неизвестно. Переписка умирала в одну сторону навсегда.
        let mut r = SessionRegistry::new();
        let live = session(1, b"handshake");
        let id = live.session_id;
        r.insert(live, SessionBinding::of(Transport::Onion));

        assert!(r.retire(&[1u8; 32], Transport::Onion), "было что отправлять на покой");
        assert_eq!(
            r.route(id),
            Route::Session(id),
            "принимать по ней обязаны: собеседник о нашем молчании не знает"
        );
        assert_eq!(
            r.for_peer(&[1u8; 32], Transport::Onion),
            None,
            "а отправлять по ней больше нельзя — на то она и на покое"
        );
        assert!(!r.retire(&[1u8; 32], Transport::Onion), "второй раз отправлять на покой нечего");
    }

    #[test]
    fn a_retired_session_is_superseded_like_any_other() {
        // Покой — не бессмертие: сессия остаётся принимать ровно до тех пор,
        // пока не появится новая. Иначе ключевой материал копился бы
        // в памяти и на диске без всякой пользы.
        let mut r = SessionRegistry::new();
        let old = session(1, b"first");
        let old_id = old.session_id;
        r.insert(old, SessionBinding::of(Transport::Onion));
        r.retire(&[1u8; 32], Transport::Onion);

        let fresh = session(1, b"second");
        let new_id = fresh.session_id;
        let removed = r.insert(fresh, SessionBinding::of(Transport::Onion));

        assert_eq!(removed, vec![old_id], "покойную обязаны убрать и назвать");
        assert_eq!(r.route(old_id), Route::Unknown);
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Onion), Some(new_id));
    }

    #[test]
    fn the_superseded_session_keeps_listening_for_one_more_generation() {
        // Две стороны заводят сессии независимо, и в одном семействе они
        // расходятся без всякой ошибки — хватит одновременного рукопожатия
        // с обеих сторон. Удали мы прежнюю сразу, каждая сторона молча
        // отбрасывала бы всё, что шлёт вторая, и по почте об этом никто
        // бы не узнал: квитанций там нет (§9.4).
        let mut r = SessionRegistry::new();
        let old = session(1, b"first");
        let old_id = old.session_id;
        r.insert(old, SessionBinding::of(Transport::Onion));

        let fresh = session(1, b"second");
        let new_id = fresh.session_id;
        let removed = r.insert(fresh, SessionBinding::of(Transport::Onion));

        assert!(removed.is_empty(), "прежняя уходит на покой, а не с диска");
        assert_eq!(r.route(old_id), Route::Session(old_id), "по ней обязаны принимать");
        assert_eq!(
            r.for_peer(&[1u8; 32], Transport::Onion),
            Some(new_id),
            "а отправлять — только по новой"
        );

        // И копиться нечему: третья убирает первую насовсем.
        let third = session(1, b"third");
        let third_id = third.session_id;
        let removed = r.insert(third, SessionBinding::of(Transport::Onion));
        assert_eq!(removed, vec![old_id], "поколение отсрочки ровно одно");
        assert_eq!(r.route(old_id), Route::Unknown);
        assert_eq!(r.route(new_id), Route::Session(new_id), "теперь дослушивает вторая");
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Onion), Some(third_id));
    }

    #[test]
    fn removing_a_contact_finds_retired_sessions_too() {
        // `for_peer` отвечает на вопрос «по чему отправлять», а удаление
        // контакта спрашивает другое: «что вообще связано с этим человеком».
        // Спроси оно первое — покойная сессия пережила бы удаление и
        // продолжала расшифровывать кадры от того, кого в контактах нет.
        let mut r = SessionRegistry::new();
        let live = session(1, b"handshake");
        let id = live.session_id;
        r.insert(live, SessionBinding::of(Transport::Onion));
        r.retire(&[1u8; 32], Transport::Onion);

        assert_eq!(r.all_for_peer(&[1u8; 32]), vec![id], "покойная обязана найтись");
        for session_id in r.all_for_peer(&[1u8; 32]) {
            r.remove(session_id);
        }
        assert_eq!(
            r.route(id),
            Route::Unknown,
            "после удаления контакта не расшифровывается ничто"
        );
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
        assert!(r.insert(second, SessionBinding::Lan).is_empty(), "прежняя уходит на покой");

        // Отправка — только по новой; в этом и был смысл вытеснения.
        assert_eq!(r.for_peer(&[1u8; 32], Transport::Lan), Some(new_id));
        // А приём по прежней остаётся: разбор — в `insert`.
        assert_eq!(r.route(old_id), Route::Session(old_id));
        assert_eq!(r.len(), 2);
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
