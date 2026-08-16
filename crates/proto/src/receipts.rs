//! Квитанции о доставке и прочтении (§9.4).
//!
//! Доставка и прочтение — **только прямым каналом**. По почте квитанции не
//! отправляются: каждая была бы отдельным письмом, что удваивает трафик,
//! расход батареи и объём метаданных у сервера.
//!
//! В UI при почтовой доставке показывается «отправлено», без «доставлено»
//! и «прочитано» (§14, пункт 1). Модуль существует, чтобы это правило было
//! одним местом в коде, а не привычкой.

use crate::transport_policy::Transport;

/// Вид квитанции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    /// Кадр принят и расшифрован.
    Delivered,
    /// Пользователь открыл чат с этим сообщением.
    Read,
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
