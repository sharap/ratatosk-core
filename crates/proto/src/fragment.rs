//! Фрагментация и сборка (§9.3).
//!
//! Полезная нагрузка, не помещающаяся в класс кадра, режется на фрагменты.
//! Ограничения спецификации, все до одного обязательные: до 4096 фрагментов
//! на сообщение, TTL незавершённой сборки 30 суток (почта) и 10 минут
//! (прямой канал), суммарно не более 64 МиБ буферов, при переполнении
//! вытесняются самые старые.
//!
//! Пределы здесь — не гигиена, а защита: сборщик без потолка позволяет любому,
//! кто может отправить кадр, занять всю память устройства первым фрагментом
//! из 4096.

use std::collections::HashMap;

/// Максимум фрагментов на сообщение (§9.3).
pub const MAX_FRAGMENTS: u64 = 4096;
/// TTL незавершённой сборки для почты — 30 суток (§9.3).
pub const REASSEMBLY_TTL_MAIL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// TTL незавершённой сборки для прямого канала — 10 минут (§9.3).
pub const REASSEMBLY_TTL_DIRECT_MS: u64 = 10 * 60 * 1000;
/// Суммарный предел буферов сборки — 64 МиБ (§9.3).
pub const REASSEMBLY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Идентификатор сборки.
pub type Uid = [u8; 16];

/// Отказ принять фрагмент.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    /// `total` вне допустимого диапазона или `index >= total`.
    OutOfRange,
    /// Фрагменты одной сборки объявляют разное `total`.
    Inconsistent,
    /// Сборка не помещается в бюджет буферов.
    BudgetExceeded,
}

/// Результат приёма фрагмента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Сборка ещё не полна.
    Pending {
        /// Сколько фрагментов уже есть.
        have: u64,
        /// Сколько всего ожидается.
        total: u64,
    },
    /// Сборка завершена, вот собранная нагрузка.
    Complete(Vec<u8>),
    /// Такой фрагмент уже принимали.
    Duplicate,
}

/// Режет нагрузку на фрагменты по `chunk` байт.
#[must_use]
pub fn split(payload: &[u8], chunk: usize) -> Vec<&[u8]> {
    if payload.is_empty() {
        return vec![&payload[..0]];
    }
    payload.chunks(chunk.max(1)).collect()
}

/// Сколько фрагментов потребуется.
#[must_use]
pub fn fragment_count(payload_len: usize, chunk: usize) -> u64 {
    if payload_len == 0 {
        return 1;
    }
    payload_len.div_ceil(chunk.max(1)) as u64
}

#[derive(Debug)]
struct Partial {
    total: u64,
    parts: HashMap<u64, Vec<u8>>,
    bytes: usize,
    first_seen_ms: u64,
    ttl_ms: u64,
}

/// Сборщик фрагментов с учётом всех пределов §9.3.
#[derive(Debug, Default)]
pub struct Reassembler {
    partials: HashMap<Uid, Partial>,
    bytes: usize,
}

impl Reassembler {
    /// Пустой сборщик.
    #[must_use]
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Сколько байт занято буферами.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Сколько незавершённых сборок.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    /// Принимает фрагмент.
    ///
    /// `ttl_ms` различается для почты и прямого канала (§9.3): по прямому
    /// каналу недостающий фрагмент за 10 минут уже не придёт, а по почте
    /// вполне может прийти через неделю.
    pub fn accept(
        &mut self,
        uid: Uid,
        index: u64,
        total: u64,
        data: &[u8],
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<Accepted, FragmentError> {
        if total == 0 || total > MAX_FRAGMENTS || index >= total {
            return Err(FragmentError::OutOfRange);
        }
        self.purge(now_ms);

        if data.len() > REASSEMBLY_BUDGET_BYTES {
            return Err(FragmentError::BudgetExceeded);
        }
        self.make_room(data.len(), now_ms);

        if let Some(existing) = self.partials.get(&uid) {
            if existing.total != total {
                // Разное `total` для одной сборки — либо баг отправителя, либо
                // попытка запутать сборщик. В обоих случаях сборка бесполезна.
                self.drop_uid(&uid);
                return Err(FragmentError::Inconsistent);
            }
            if existing.parts.contains_key(&index) {
                return Ok(Accepted::Duplicate);
            }
        }

        let have = {
            let entry = self.partials.entry(uid).or_insert_with(|| Partial {
                total,
                parts: HashMap::new(),
                bytes: 0,
                first_seen_ms: now_ms,
                ttl_ms,
            });
            entry.parts.insert(index, data.to_vec());
            entry.bytes += data.len();
            entry.parts.len() as u64
        };
        self.bytes += data.len();

        if have < total {
            return Ok(Accepted::Pending { have, total });
        }

        let mut partial = self.partials.remove(&uid).expect("запись только что была");
        self.bytes -= partial.bytes;
        let mut out = Vec::with_capacity(partial.bytes);
        for i in 0..total {
            out.extend_from_slice(&partial.parts.remove(&i).expect("все части на месте"));
        }
        Ok(Accepted::Complete(out))
    }

    /// Выбрасывает сборки, у которых истёк TTL.
    pub fn purge(&mut self, now_ms: u64) {
        let expired: Vec<Uid> = self
            .partials
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.first_seen_ms) >= p.ttl_ms)
            .map(|(uid, _)| *uid)
            .collect();
        for uid in expired {
            self.drop_uid(&uid);
        }
    }

    /// Освобождает место под новые байты, вытесняя самые старые сборки (§9.3).
    fn make_room(&mut self, incoming: usize, _now_ms: u64) {
        while self.bytes + incoming > REASSEMBLY_BUDGET_BYTES && !self.partials.is_empty() {
            let Some(oldest) = self
                .partials
                .iter()
                .min_by_key(|(uid, p)| (p.first_seen_ms, **uid))
                .map(|(uid, _)| *uid)
            else {
                break;
            };
            self.drop_uid(&oldest);
        }
    }

    fn drop_uid(&mut self, uid: &Uid) {
        if let Some(p) = self.partials.remove(uid) {
            self.bytes -= p.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: Uid = [1u8; 16];

    #[test]
    fn split_and_reassemble_in_order() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let parts = split(&payload, 256);
        let total = parts.len() as u64;
        assert_eq!(total, fragment_count(payload.len(), 256));

        let mut r = Reassembler::new();
        let mut result = None;
        for (i, part) in parts.iter().enumerate() {
            let got = r.accept(UID, i as u64, total, part, REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
            if let Accepted::Complete(bytes) = got {
                result = Some(bytes);
            }
        }
        assert_eq!(result.unwrap(), payload);
        assert_eq!(r.bytes(), 0, "после сборки буферы освобождаются");
    }

    #[test]
    fn reassembles_out_of_order() {
        // Почта переставляет фрагменты так же, как сообщения (§9.2).
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let parts = split(&payload, 100);
        let total = parts.len() as u64;

        let mut r = Reassembler::new();
        let mut order: Vec<usize> = (0..parts.len()).collect();
        order.reverse();

        let mut result = None;
        for i in order {
            if let Accepted::Complete(bytes) =
                r.accept(UID, i as u64, total, parts[i], REASSEMBLY_TTL_MAIL_MS, 0).unwrap()
            {
                result = Some(bytes);
            }
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn empty_payload_is_one_fragment() {
        assert_eq!(fragment_count(0, 100), 1);
        assert_eq!(split(b"", 100).len(), 1);
    }

    #[test]
    fn duplicate_fragment_is_reported() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        assert_eq!(
            r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap(),
            Accepted::Duplicate
        );
    }

    #[test]
    fn out_of_range_is_refused() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.accept(UID, 0, 0, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
        assert_eq!(
            r.accept(UID, 5, 5, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
        assert_eq!(
            r.accept(UID, 0, MAX_FRAGMENTS + 1, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
    }

    #[test]
    fn inconsistent_total_drops_the_assembly() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 4, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        assert_eq!(
            r.accept(UID, 1, 5, b"b", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::Inconsistent)
        );
        assert_eq!(r.pending(), 0);
        assert_eq!(r.bytes(), 0);
    }

    #[test]
    fn direct_channel_assembly_expires_in_ten_minutes() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        r.purge(REASSEMBLY_TTL_DIRECT_MS - 1);
        assert_eq!(r.pending(), 1);
        r.purge(REASSEMBLY_TTL_DIRECT_MS);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn mail_assembly_survives_a_week() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_MAIL_MS, 0).unwrap();
        r.purge(7 * 24 * 60 * 60 * 1000);
        assert_eq!(r.pending(), 1, "по почте фрагмент может прийти через неделю");
    }

    #[test]
    fn budget_evicts_oldest_assemblies() {
        // Один отправитель не должен занять всю память первым фрагментом
        // из 4096 в каждой из тысячи сборок.
        let mut r = Reassembler::new();
        let chunk = vec![0u8; 1024 * 1024];
        for i in 0..80u8 {
            let mut uid = [0u8; 16];
            uid[0] = i;
            r.accept(uid, 0, 2, &chunk, REASSEMBLY_TTL_MAIL_MS, u64::from(i)).unwrap();
        }
        assert!(r.bytes() <= REASSEMBLY_BUDGET_BYTES, "бюджет буферов превышен");
        assert!(r.pending() < 80, "самые старые сборки должны вытесняться");
    }
}
