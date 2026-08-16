//! Квитанции о доставке и прочтении (§9.4).
//!
//! Доставка и прочтение — **только прямым каналом**. По почте квитанции не
//! отправляются: каждая была бы отдельным письмом, что удваивает трафик,
//! расход батареи и объём метаданных у сервера.
//!
//! В UI при почтовой доставке показывается «отправлено», без «доставлено»
//! и «прочитано» (§14, пункт 1). Модуль существует, чтобы это правило было
//! одним местом в коде, а не привычкой.

use ratatosk_codec::{canonical, CodecError, Value};
use ratatosk_crdt::MsgId;

use crate::transport_policy::Transport;

/// Ключ вида квитанции в полезной нагрузке.
const KEY_KIND: u64 = 1;
/// Ключ списка идентификаторов.
const KEY_IDS: u64 = 2;

/// Сколько идентификаторов помещается в одну квитанцию.
///
/// Предел нужен на приёме: список приходит от собеседника, и без потолка
/// одна квитанция заставила бы перебрать столько записей, сколько он
/// пожелает. Сто сообщений — это открытый чат с непрочитанным за неделю,
/// а не край.
pub const MAX_RECEIPT_IDS: usize = 100;

/// Вид квитанции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    /// Кадр принят и расшифрован.
    Delivered,
    /// Пользователь открыл чат с этим сообщением.
    Read,
}

impl Receipt {
    /// Числовой код вида квитанции.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Receipt::Delivered => 1,
            Receipt::Read => 2,
        }
    }

    /// Собирает полезную нагрузку квитанции (§9.1, тип `Receipt`).
    ///
    /// Одна квитанция на список сообщений, а не по одной на каждое: открытый
    /// чат с двадцатью непрочитанными иначе выпустил бы двадцать кадров,
    /// и каждый со своим паддингом до класса размера (§5.5).
    #[must_use]
    pub fn payload(self, msg_ids: &[MsgId]) -> Value {
        let ids = msg_ids.iter().map(|id| Value::Bytes(id.to_vec())).collect();
        Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(self.code().into())),
            (Value::Integer(KEY_IDS.into()), Value::Array(ids)),
        ])
    }

    /// Разбирает полезную нагрузку квитанции.
    ///
    /// Всё здесь приходит от собеседника, поэтому проверяется всё: и вид,
    /// и длина каждого идентификатора, и число идентификаторов.
    pub fn from_payload(value: &Value) -> Result<(Receipt, Vec<MsgId>), CodecError> {
        let map = canonical::as_map(value)?;
        let kind = match canonical::as_u64(canonical::require(map, KEY_KIND)?)? {
            1 => Receipt::Delivered,
            2 => Receipt::Read,
            // Неизвестный вид — от клиента новее нашего. Терять сообщение
            // целиком незачем, но и применять непонятно что нельзя.
            _ => return Err(CodecError::TypeMismatch),
        };

        let Value::Array(items) = canonical::require(map, KEY_IDS)? else {
            return Err(CodecError::TypeMismatch);
        };
        if items.len() > MAX_RECEIPT_IDS {
            return Err(CodecError::TypeMismatch);
        }

        let mut ids = Vec::with_capacity(items.len());
        for item in items {
            ids.push(canonical::as_array::<16>(item)?);
        }
        Ok((kind, ids))
    }
}

/// Что показывать пользователю о судьбе сообщения.
///
/// Порядок вариантов значим: статус только растёт (см. [`apply`]).
/// [`DeliveryStatus::Undeliverable`] стоит **ниже** всех остальных именно
/// поэтому — он выставляется явно, когда транспорты §5.4 исчерпаны, и не
/// должен затирать уже достигнутый успех, если запоздавшая квитанция
/// всё-таки придёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeliveryStatus {
    /// Отправить не удалось: ни один транспорт из §5.4 не сработал.
    ///
    /// Вариант существует, потому что сообщение, которое не ушло, обязано
    /// быть видно пользователю. Молчаливое исчезновение — ровно та
    /// нечестность, которую запрещает §14.
    Undeliverable,
    /// Ждёт отправки.
    Pending,
    /// Отправлено. Дальше этого статуса почтовая доставка не уходит.
    Sent,
    /// Доставлено. Возможно только для прямого канала.
    Delivered,
    /// Прочитано. Возможно только для прямого канала.
    Read,
}

impl DeliveryStatus {
    /// Числовой код для хранения (§12).
    ///
    /// Хранилище держит статус числом и не знает, что оно значит: лестница
    /// статусов — это §9.4, то есть протокол, и жить она должна здесь.
    /// Числа выбраны с запасом снизу, чтобы новый статус можно было вставить,
    /// не переписывая базу.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            DeliveryStatus::Undeliverable => 0,
            DeliveryStatus::Pending => 10,
            DeliveryStatus::Sent => 20,
            DeliveryStatus::Delivered => 30,
            DeliveryStatus::Read => 40,
        }
    }

    /// Читает статус из кода. Неизвестный код — не повод потерять сообщение.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<DeliveryStatus> {
        match code {
            0 => Some(DeliveryStatus::Undeliverable),
            10 => Some(DeliveryStatus::Pending),
            20 => Some(DeliveryStatus::Sent),
            30 => Some(DeliveryStatus::Delivered),
            40 => Some(DeliveryStatus::Read),
            _ => None,
        }
    }
}

/// Можно ли отправлять квитанцию этим транспортом (§9.4).
#[must_use]
pub const fn may_send_receipt(transport: Transport) -> bool {
    transport.is_direct()
}

/// Максимальный статус, достижимый при доставке этим транспортом.
///
/// Функция существует, чтобы UI не мог показать «доставлено» после почтовой
/// отправки: обещание, которого протокол не даёт, — это ровно то, что §14
/// запрещает.
#[must_use]
pub const fn max_status(transport: Transport) -> DeliveryStatus {
    if transport.is_direct() {
        DeliveryStatus::Read
    } else {
        DeliveryStatus::Sent
    }
}

/// Разрешён ли переход статуса, и в какой (§9.4).
///
/// `None` означает «ничего не менять» — в том числе когда целевой статус
/// совпадает с текущим: событие об этом посылать незачем.
///
/// **`Undeliverable` — не ступень лестницы, а отдельная отметка**, и правило
/// для него своё. В порядке вариантов он стоит ниже всех, чтобы запоздавшая
/// квитанция могла его перекрыть; но именно поэтому проверка «только растёт»
/// к нему неприменима — под неё переход `Pending → Undeliverable` не проходит
/// вовсе, и сообщение, которому некуда ехать, навсегда остаётся «ждёт
/// отправки». Это ровно то молчание, которое запрещает §14.
///
/// Поэтому:
///
/// * `Undeliverable` перекрывает **только** `Pending` — подтверждённый успех
///   он не отменяет: сообщение могло дойти копией по другому транспорту (§9.2);
/// * всё остальное — только вверх.
#[must_use]
pub fn advance(current: Option<DeliveryStatus>, target: DeliveryStatus) -> Option<DeliveryStatus> {
    let Some(current) = current else {
        return Some(target);
    };
    if current == target {
        return None;
    }
    match target {
        DeliveryStatus::Undeliverable => {
            (current == DeliveryStatus::Pending).then_some(target)
        }
        _ => (target > current).then_some(target),
    }
}

/// Применяет квитанцию к текущему статусу.
///
/// Статус только растёт: квитанция о доставке, пришедшая после квитанции
/// о прочтении (перестановка — обычное дело), не откатывает индикатор.
#[must_use]
pub fn apply(current: DeliveryStatus, receipt: Receipt, via: Transport) -> DeliveryStatus {
    if !may_send_receipt(via) {
        return current;
    }
    let candidate = match receipt {
        Receipt::Delivered => DeliveryStatus::Delivered,
        Receipt::Read => DeliveryStatus::Read,
    };
    if candidate > current {
        candidate
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_payload_round_trips() {
        let ids = vec![[1u8; 16], [2u8; 16]];
        let (kind, back) = Receipt::from_payload(&Receipt::Read.payload(&ids)).unwrap();
        assert_eq!(kind, Receipt::Read);
        assert_eq!(back, ids);
    }

    #[test]
    fn an_empty_receipt_is_valid_and_means_nothing() {
        let (kind, ids) = Receipt::from_payload(&Receipt::Delivered.payload(&[])).unwrap();
        assert_eq!(kind, Receipt::Delivered);
        assert!(ids.is_empty(), "пустой список — не ошибка, просто нечего применять");
    }

    #[test]
    fn a_hostile_receipt_is_refused() {
        // Всё это приходит от собеседника, и проверяется поэтому всё.
        let too_many: Vec<_> = (0..=MAX_RECEIPT_IDS).map(|n| [n as u8; 16]).collect();
        assert!(
            Receipt::from_payload(&Receipt::Read.payload(&too_many)).is_err(),
            "список длиннее предела заставил бы перебрать сколько угодно записей"
        );

        let wrong_length = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(2.into()), Value::Array(vec![Value::Bytes(vec![0u8; 15])])),
        ]);
        assert!(Receipt::from_payload(&wrong_length).is_err(), "msg_id обязан быть 16 байт");

        let unknown_kind = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(99.into())),
            (Value::Integer(2.into()), Value::Array(vec![])),
        ]);
        assert!(Receipt::from_payload(&unknown_kind).is_err(), "неизвестный вид не применяется");

        assert!(Receipt::from_payload(&Value::Text("не карта".into())).is_err());
    }

    #[test]
    fn a_message_with_nowhere_to_go_becomes_undeliverable() {
        // Регрессия. `Undeliverable` стоит ниже всех в порядке вариантов,
        // и правило «только растёт», применённое к нему буквально, запрещало
        // переход `Pending → Undeliverable`: сообщение, которому некуда ехать,
        // навсегда оставалось «ждёт отправки». §14 это прямо запрещает.
        assert_eq!(
            advance(Some(DeliveryStatus::Pending), DeliveryStatus::Undeliverable),
            Some(DeliveryStatus::Undeliverable)
        );
    }

    #[test]
    fn a_failure_never_cancels_a_confirmed_success() {
        // Копия могла дойти другим транспортом (§9.2), и её подтверждение
        // сильнее нашего вывода об исчерпании транспортов.
        for reached in
            [DeliveryStatus::Sent, DeliveryStatus::Delivered, DeliveryStatus::Read]
        {
            assert_eq!(advance(Some(reached), DeliveryStatus::Undeliverable), None, "{reached:?}");
        }
    }

    #[test]
    fn a_late_receipt_overrides_a_declared_failure() {
        // Обратное направление: транспорты исчерпались, но копия всё-таки
        // дошла и собеседник это подтвердил.
        assert_eq!(
            advance(Some(DeliveryStatus::Undeliverable), DeliveryStatus::Delivered),
            Some(DeliveryStatus::Delivered)
        );
    }

    #[test]
    fn a_status_never_goes_backwards_and_never_repeats() {
        assert_eq!(advance(Some(DeliveryStatus::Delivered), DeliveryStatus::Sent), None);
        assert_eq!(advance(Some(DeliveryStatus::Read), DeliveryStatus::Delivered), None);
        // Повтор того же статуса — не изменение, и события о нём быть не должно.
        assert_eq!(advance(Some(DeliveryStatus::Sent), DeliveryStatus::Sent), None);
        // У сообщения без статуса приживается любой.
        assert_eq!(advance(None, DeliveryStatus::Pending), Some(DeliveryStatus::Pending));
    }

    #[test]
    fn status_codes_round_trip_and_keep_their_order() {
        for status in [
            DeliveryStatus::Undeliverable,
            DeliveryStatus::Pending,
            DeliveryStatus::Sent,
            DeliveryStatus::Delivered,
            DeliveryStatus::Read,
        ] {
            assert_eq!(DeliveryStatus::from_code(status.code()), Some(status));
        }
        // Порядок кодов обязан совпадать с порядком статусов: иначе сравнение
        // «статус только растёт» в базе и в памяти разойдётся.
        assert!(DeliveryStatus::Undeliverable.code() < DeliveryStatus::Pending.code());
        assert!(DeliveryStatus::Sent.code() < DeliveryStatus::Delivered.code());
        assert!(DeliveryStatus::Delivered.code() < DeliveryStatus::Read.code());
        assert_eq!(DeliveryStatus::from_code(7), None);
    }

    #[test]
    fn mail_never_produces_receipts() {
        assert!(!may_send_receipt(Transport::Mail));
        assert!(may_send_receipt(Transport::Lan));
        assert!(may_send_receipt(Transport::Onion));
    }

    #[test]
    fn mail_delivery_stops_at_sent() {
        assert_eq!(max_status(Transport::Mail), DeliveryStatus::Sent);
        assert_eq!(max_status(Transport::Onion), DeliveryStatus::Read);
    }

    #[test]
    fn status_only_grows() {
        let read = apply(DeliveryStatus::Sent, Receipt::Read, Transport::Onion);
        assert_eq!(read, DeliveryStatus::Read);
        // Квитанция о доставке пришла позже квитанции о прочтении.
        assert_eq!(apply(read, Receipt::Delivered, Transport::Onion), DeliveryStatus::Read);
    }

    #[test]
    fn undeliverable_is_the_floor_and_never_overwrites_success() {
        // Запоздавшая квитанция не должна воскрешать статус, но и провал
        // не должен затирать уже подтверждённую доставку.
        assert!(DeliveryStatus::Undeliverable < DeliveryStatus::Pending);
        assert_eq!(
            apply(DeliveryStatus::Delivered, Receipt::Delivered, Transport::Onion),
            DeliveryStatus::Delivered
        );
        assert!(DeliveryStatus::Undeliverable < max_status(Transport::Mail));
    }

    #[test]
    fn receipt_over_mail_is_ignored() {
        assert_eq!(
            apply(DeliveryStatus::Sent, Receipt::Read, Transport::Mail),
            DeliveryStatus::Sent,
            "§9.4: по почте квитанций не бывает, значит и статуса они не меняют"
        );
    }
}
