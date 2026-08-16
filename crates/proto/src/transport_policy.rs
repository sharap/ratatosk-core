//! Выбор транспорта (§5.4).
//!
//! **Не гонка.** Строгая последовательность с таймаутами:
//!
//! 1. Если контакт виден в LAN и LAN включён → LAN.
//! 2. Иначе попытка соединения с onion-адресом, таймаут 45 с.
//! 3. Если не удалось → отправка почтой.
//!
//! Одновременная отправка одним и тем же сообщением по нескольким транспортам
//! запрещена. Дублирование на приёме допускается и разрешается дедупликацией
//! (§9.2).
//!
//! **Единственное исключение:** LAN и Tor не смешиваются в одной сессии
//! никогда. Сессия, начатая в LAN, при потере связи не продолжается через
//! onion — устанавливается новая. Иначе локальный наблюдатель связывает
//! LAN-присутствие с onion-активностью. Это правило действует и для канала
//! десктоп—телефон (§13.4).

/// Таймаут попытки соединения с onion-сервисом (§5.4).
pub const ONION_CONNECT_TIMEOUT_MS: u64 = 45_000;

// Повторов **тем же** транспортом здесь нет, и это решение стоит объяснить,
// потому что соблазн их добавить возникает сразу.
//
// Я их добавлял и убрал. Рассуждение было такое: обрыв onion-цепочки — дело
// обычное, и уходить из-за него сразу на почту значит менять сотни
// миллисекунд на минуты задержки и на лишнюю запись в социальном графе
// chatmail-сервера (§2.2).
//
// Ошибка в том, что «onion не ответил» в подавляющем большинстве случаев
// означает «собеседник не в сети», а не «пакет потерялся». Тогда каждая
// лишняя попытка — это ещё 45 секунд ожидания там, где ответа не будет
// вовсе: три попытки отодвигают первое письмо со 135 секунд. Выигрыш
// достаётся редкому случаю, плата — частому.
//
// И главное: §5.4 предписывает ровно одну попытку на транспорт. Откат
// на следующий транспорт **и есть** механизм повтора, второй здесь не нужен.
//
// Осмысленный вариант, если он когда-нибудь понадобится: повторять только
// при свидетельстве, что собеседник в сети, — например, после недавнего
// удачного обмена прямым каналом. Без такого свидетельства повтор — гадание.

/// Транспорт (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// Локальная сеть. По умолчанию выключена (§5.1).
    Lan,
    /// Tor onion-to-onion (§5.2).
    Onion,
    /// Почта chatmail поверх Tor (§5.3).
    Mail,
}

impl Transport {
    /// Прямой ли это канал.
    ///
    /// Различие содержательное: квитанции идут только прямым каналом (§9.4),
    /// файлы больше 20 МБ — тоже (§10.3).
    #[must_use]
    pub const fn is_direct(self) -> bool {
        matches!(self, Transport::Lan | Transport::Onion)
    }
}

/// Что известно о контакте прямо сейчас.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerAvailability {
    /// Контакт виден в LAN по маяку mDNS (§5.1).
    pub seen_on_lan: bool,
    /// Пользователь включил LAN. По умолчанию выключен (§5.1).
    pub lan_enabled: bool,
    /// Известен onion-адрес.
    pub has_onion: bool,
    /// Известен chatmail-адрес.
    pub has_chatmail: bool,
}

/// Решение о том, куда отправлять.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Отправлять этим транспортом.
    Use(Transport),
    /// Отправить некуда: адресов нет.
    Undeliverable,
}

/// Состояние попытки доставки одного сообщения.
///
/// Тип нужен, чтобы запрет из §5.4 («одновременная отправка одним и тем же
/// сообщением по нескольким транспортам запрещена») был структурным, а не
/// дисциплинарным: следующий транспорт можно получить только после того,
/// как предыдущий явно объявлен неудавшимся.
#[derive(Debug, Clone)]
pub struct Attempt {
    tried: Vec<Transport>,
    finished: bool,
}

impl Default for Attempt {
    fn default() -> Self {
        Attempt::new()
    }
}

impl Attempt {
    /// Начинает новую попытку доставки.
    #[must_use]
    pub fn new() -> Attempt {
        Attempt { tried: Vec::new(), finished: false }
    }

    /// Транспорты, которые уже пробовали.
    #[must_use]
    pub fn tried(&self) -> &[Transport] {
        &self.tried
    }

    /// Завершена ли доставка.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Отмечает успешную отправку. Дальнейших попыток не будет.
    pub fn succeed(&mut self) {
        self.finished = true;
    }

    /// Следующий транспорт по правилам §5.4.
    ///
    /// Возвращает `None`, если доставка уже завершена.
    pub fn next(&mut self, peer: PeerAvailability) -> Option<Decision> {
        if self.finished {
            return None;
        }

        let candidate =
            if peer.lan_enabled && peer.seen_on_lan && !self.tried.contains(&Transport::Lan) {
                Some(Transport::Lan)
            } else if peer.has_onion && !self.tried.contains(&Transport::Onion) {
                Some(Transport::Onion)
            } else if peer.has_chatmail && !self.tried.contains(&Transport::Mail) {
                Some(Transport::Mail)
            } else {
                None
            };

        match candidate {
            Some(t) => {
                self.tried.push(t);
                Some(Decision::Use(t))
            }
            None => {
                self.finished = true;
                Some(Decision::Undeliverable)
            }
        }
    }

    /// Таймаут текущей попытки, мс.
    #[must_use]
    pub fn timeout_ms(&self) -> Option<u64> {
        match self.tried.last() {
            Some(Transport::Onion) => Some(ONION_CONNECT_TIMEOUT_MS),
            // LAN отвечает за миллисекунды: отдельный длинный таймаут ему
            // не нужен, обрыв виден сразу по сокету.
            Some(Transport::Lan) => Some(5_000),
            // Почта асинхронна по устройству: ждать её «ответа» бессмысленно.
            Some(Transport::Mail) | None => None,
        }
    }
}

/// Привязка сессии к семейству транспортов (§5.4, исключение).
///
/// LAN и Tor не смешиваются в одной сессии **никогда**. Тип делает это
/// проверяемым: сессия, начатая в LAN, отказывается продолжаться через onion,
/// и вызывающий обязан установить новую.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBinding {
    /// Сессия живёт в локальной сети.
    Lan,
    /// Сессия живёт поверх Tor — onion или почта.
    Tor,
}

impl SessionBinding {
    /// Привязка, к которой относится транспорт.
    #[must_use]
    pub const fn of(transport: Transport) -> SessionBinding {
        match transport {
            Transport::Lan => SessionBinding::Lan,
            // Почта тоже идёт поверх Tor (§5.3), поэтому она в том же
            // семействе, что и onion, и смешивать её с LAN так же нельзя.
            Transport::Onion | Transport::Mail => SessionBinding::Tor,
        }
    }

    /// Можно ли продолжать эту сессию указанным транспортом.
    #[must_use]
    pub fn allows(self, transport: Transport) -> bool {
        self == SessionBinding::of(transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> PeerAvailability {
        PeerAvailability {
            seen_on_lan: true,
            lan_enabled: true,
            has_onion: true,
            has_chatmail: true,
        }
    }

    #[test]
    fn lan_first_when_enabled_and_visible() {
        let mut a = Attempt::new();
        assert_eq!(a.next(full()), Some(Decision::Use(Transport::Lan)));
    }

    #[test]
    fn lan_is_skipped_when_disabled() {
        // §5.1: по умолчанию LAN выключен, даже если контакт виден.
        let peer = PeerAvailability { lan_enabled: false, ..full() };
        let mut a = Attempt::new();
        assert_eq!(a.next(peer), Some(Decision::Use(Transport::Onion)));
    }

    #[test]
    fn strict_sequence_not_a_race() {
        // Каждый прямой транспорт получает свои повторы, но порядок семейств
        // не нарушается: LAN исчерпывается раньше, чем начнётся onion.
        let mut a = Attempt::new();
        let mut order = Vec::new();
        while let Some(Decision::Use(t)) = a.next(full()) {
            order.push(t);
        }

        // Ровно по одной попытке на транспорт (§5.4).
        let expected = vec![Transport::Lan, Transport::Onion, Transport::Mail];
        assert_eq!(order, expected);

        // Цикл выше остановился на `Undeliverable`, и этот же вызов закрыл
        // попытку. Повторное обращение возвращает `None`: исчерпание
        // транспортов сообщается ровно один раз, иначе UI получил бы
        // «не доставлено» столько раз, сколько его спросят.
        assert!(a.is_finished());
        assert_eq!(a.next(full()), None);
    }

    #[test]
    fn success_stops_further_attempts() {
        let mut a = Attempt::new();
        a.next(full());
        a.succeed();
        assert_eq!(a.next(full()), None, "после успеха второй транспорт не выбирается");
    }

    #[test]
    fn no_addresses_means_undeliverable() {
        let mut a = Attempt::new();
        assert_eq!(a.next(PeerAvailability::default()), Some(Decision::Undeliverable));
    }

    #[test]
    fn onion_timeout_matches_spec() {
        let mut a = Attempt::new();
        a.next(PeerAvailability { lan_enabled: false, ..full() });
        assert_eq!(a.timeout_ms(), Some(ONION_CONNECT_TIMEOUT_MS));
        assert_eq!(ONION_CONNECT_TIMEOUT_MS, 45_000);
    }

    #[test]
    fn mail_has_no_timeout() {
        let peer = PeerAvailability { has_chatmail: true, ..PeerAvailability::default() };
        let mut a = Attempt::new();
        a.next(peer);
        assert_eq!(a.timeout_ms(), None, "почта асинхронна, ждать ответа бессмысленно");
    }

    #[test]
    fn lan_session_never_continues_over_onion() {
        let lan = SessionBinding::Lan;
        assert!(lan.allows(Transport::Lan));
        assert!(!lan.allows(Transport::Onion));
        assert!(!lan.allows(Transport::Mail));
    }

    #[test]
    fn tor_session_covers_onion_and_mail() {
        let tor = SessionBinding::Tor;
        assert!(tor.allows(Transport::Onion));
        assert!(tor.allows(Transport::Mail));
        assert!(!tor.allows(Transport::Lan));
    }

    #[test]
    fn direct_and_indirect_are_classified() {
        assert!(Transport::Lan.is_direct());
        assert!(Transport::Onion.is_direct());
        assert!(!Transport::Mail.is_direct());
    }
}
