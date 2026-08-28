//! Выбор транспорта (§5.4).
//!
//! **Не гонка.** Строгая последовательность с таймаутами:
//!
//! 1. Если LAN включён и контакт в нём виден → LAN.
//! 2. Иначе попытка соединения с onion-адресом, таймаут 45 с.
//! 3. Если не удалось → отправка почтой.
//!
//! Одновременная отправка одним и тем же сообщением по нескольким транспортам
//! запрещена. Дублирование на приёме допускается и разрешается дедупликацией
//! (§9.2).
//!
//! **Выключенный транспорт из лестницы выпадает целиком.** Разрешение
//! ([`TransportSet`]) и достижимость (адрес в карточке, маяк в эфире) —
//! разные вещи, и проверяются они по отдельности: первое чинится
//! переключателем в UI, второе — обменом карточками. Ступень, которую
//! человек выключил, не «пробуется и отказывает», а не пробуется вовсе:
//! иначе каждое сообщение платило бы за неё сроком ожидания.
//!
//! **Единственное исключение:** LAN и Tor не смешиваются в одной сессии
//! никогда. Сессия, начатая в LAN, при потере связи не продолжается через
//! onion — устанавливается новая. Иначе локальный наблюдатель связывает
//! LAN-присутствие с onion-активностью. Это правило действует и для канала
//! десктоп—телефон (§13.4).

/// Таймаут попытки соединения с onion-сервисом (§5.4).
pub const ONION_CONNECT_TIMEOUT_MS: u64 = 45_000;

/// Сколько ждать ответа собеседника после того, как кадр ушёл через onion.
///
/// **Не то же самое, что таймаут соединения, и вот почему.** Соединения
/// односторонние: каждая сторона набирает своё и пишет только в него
/// (`ARCHITECTURE.md`, 5ц). Значит, ответ собеседника — и квитанция (§9.4),
/// и второе сообщение рукопожатия (§8.2) — приезжает **не по нашему
/// соединению**, а по тому, которое собеседник должен сперва набрать сам.
/// А набор через Tor это построение цепочки встречи: те же секунды,
/// на которые мы отвели [`ONION_CONNECT_TIMEOUT_MS`] себе.
///
/// Отсюда и значение: наш срок ожидания обязан вмещать целый чужой набор,
/// иначе первое же сообщение объявляется недоставленным ровно тогда, когда
/// оно доставлено, — собеседник его уже читает, а отправителю показано
/// «не ушло». Ровно это и было видно на стенде.
///
/// Долгое ожидание здесь ничего не стоит, и это не оптимизм. Срок начинает
/// идти **после успешного соединения**, то есть когда сервис собеседника
/// заведомо в сети: недоступный ловится таймаутом набора, а не этим. Ждать
/// в такой ситуации разумно — ответ почти наверняка в пути.
pub const ONION_REPLY_TIMEOUT_MS: u64 = 2 * ONION_CONNECT_TIMEOUT_MS;

/// Сколько ждать квитанции по локальной сети, прежде чем считать попытку
/// неудавшейся (§5.4, §9.4).
///
/// Это **не** таймаут соединения: соединиться в локальной сети либо получается
/// сразу, либо не получается вовсе. Это срок ответа. Он нужен потому, что
/// успешная запись в сокет ничего не доказывает: узел мог уйти из сети,
/// оставив соединение полуоткрытым, или на его адресе и порту мог оказаться
/// чужой процесс — ядро операционной системы примет байты в буфер и в том,
/// и в другом случае. Единственное настоящее свидетельство доставки —
/// квитанция от собеседника.
///
/// Пять секунд: в локальной сети рукопожатие с квитанцией укладывается в
/// десятки миллисекунд даже на телефоне, так что запас стократный, а верхняя
/// граница определяется терпением человека, глядящего на экран.
pub const LAN_RECEIPT_TIMEOUT_MS: u64 = 5_000;

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
    /// Какие транспорты включены на этом устройстве.
    ///
    /// Не «есть ли адрес», а «разрешено ли им пользоваться»: это выбор
    /// человека, и он одинаков для всех контактов. Лежит здесь, а не рядом,
    /// потому что §5.4 принимает решение по одной структуре — иначе часть
    /// правила оказалась бы в другом месте и однажды разошлась бы.
    pub enabled: TransportSet,
    /// Какие транспорты **уже работают**.
    ///
    /// Отдельно от [`PeerAvailability::enabled`], и это не тонкость.
    /// «Человек включил Tor» и «Tor работает» разделяют десятки секунд:
    /// bootstrap, а за ним публикация сервиса. Считай мы включение
    /// готовностью, первое же сообщение после включения ушло бы в ступень,
    /// которой ещё нет, получило бы отказ — и **сожгло бы её**: §5.4
    /// не повторяет транспорт после отказа, и сообщение уехало бы дальше
    /// по лестнице или встало бы в ожидание, хотя Tor поднимется через
    /// полминуты.
    ///
    /// У LAN и почты этого разрыва нет: порт занят при старте, а почта
    /// асинхронна по устройству — ждать там нечего, и они готовы вместе
    /// с включением.
    pub ready: TransportSet,
    /// Известен onion-адрес.
    pub has_onion: bool,
    /// Известен chatmail-адрес.
    pub has_chatmail: bool,
}

/// Набор включённых транспортов.
///
/// Множество, а не поле на каждый транспорт, и это не украшение. Транспортов
/// станет больше (§5.3 ещё не написан, и он не последний), а каждый новый
/// выключатель отдельным `bool` означает новое поле в [`PeerAvailability`],
/// новую ветку в §5.4 и новый повод забыть одно из трёх мест.
///
/// Хранится одним байтом: набор целиком помещается в `meta` (§8.6) и
/// переживает перезапуск, не заводя себе ни таблицы, ни формата.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransportSet(u8);

impl TransportSet {
    /// Бит транспорта. Значения фиксированы: они уезжают на диск.
    const fn bit(transport: Transport) -> u8 {
        match transport {
            Transport::Lan => 1,
            Transport::Onion => 2,
            Transport::Mail => 4,
        }
    }

    /// Все известные биты — маска для чтения с диска.
    const KNOWN: u8 = 1 | 2 | 4;

    /// Пустой набор: не разрешён ни один транспорт.
    #[must_use]
    pub const fn none() -> TransportSet {
        TransportSet(0)
    }

    /// Разрешено ли пользоваться этим транспортом.
    #[must_use]
    pub const fn contains(self, transport: Transport) -> bool {
        self.0 & Self::bit(transport) != 0
    }

    /// Тот же набор плюс один транспорт.
    ///
    /// Отдельно от [`TransportSet::set`], потому что умеет то, чего тот
    /// не умеет: собирать набор в константе.
    #[must_use]
    pub const fn with(self, transport: Transport) -> TransportSet {
        TransportSet(self.0 | Self::bit(transport))
    }

    /// Включает или выключает транспорт.
    pub fn set(&mut self, transport: Transport, enabled: bool) {
        if enabled {
            self.0 |= Self::bit(transport);
        } else {
            self.0 &= !Self::bit(transport);
        }
    }

    /// Байт для записи на диск.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Набор из байта с диска.
    ///
    /// Незнакомые биты отбрасываются: запись могла лечь более новой версией,
    /// и включать по ней транспорт, которого в этой сборке нет, нечем.
    #[must_use]
    pub const fn from_bits(bits: u8) -> TransportSet {
        TransportSet(bits & Self::KNOWN)
    }
}

/// Одна ступень лестницы §5.4 глазами конкретного контакта.
///
/// Три признака, а не один «доступен», и они разного рода — потому что
/// и лечатся по-разному: [`Rung::enabled`] чинится переключателем в UI,
/// [`Rung::ready`] — временем (bootstrap Tor идёт десятки секунд),
/// [`Rung::addressable`] — обменом карточками (§4.3) или появлением в эфире
/// (§5.1). Слитые в одно слово, они отвечали бы на вопрос «почему не идёт»
/// одинаково для трёх разных бед.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rung {
    /// Какая ступень.
    pub transport: Transport,
    /// Разрешена человеком.
    pub enabled: bool,
    /// Уже работает.
    pub ready: bool,
    /// Есть куда ехать: адрес в карточке или маяк в эфире.
    pub addressable: bool,
}

impl Rung {
    /// Годится ли ступень прямо сейчас.
    #[must_use]
    pub const fn usable(self) -> bool {
        self.enabled && self.ready && self.addressable
    }

    /// Заберёт ли эта ступень отправку, когда поднимется.
    ///
    /// Разрешена и адресуема, но ещё не работает — то есть ждать её имеет
    /// смысл. Ровно этот случай отличает «Tor поднимается, сообщение уйдёт
    /// через полминуты» от «отправлять некуда»; смешав их, UI пугает
    /// человека тем, что вот-вот пройдёт само.
    #[must_use]
    pub const fn rising(self) -> bool {
        self.enabled && self.addressable && !self.ready
    }
}

/// Куда поедет следующее сообщение этому контакту — и почему не дальше.
///
/// **Существует затем, чтобы вердикт был один.** Раньше его считал каждый,
/// кому он нужен: `Attempt::next` — для отправки, стенд — для `/who`,
/// и клиент завёл бы третью копию. Три копии одной лестницы расходятся
/// не «когда-нибудь», а при первом же добавлении ступени, и расхождение
/// это молчаливое: UI показывает «пойдёт почтой», а уходит оно через onion.
///
/// Поэтому лестница живёт здесь одним списком, а [`Attempt::next`] ходит
/// по нему же. Правило, которое можно забыть, заменено кодом, который
/// забыть нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reachability {
    /// Ступени по порядку §5.4: LAN, onion, почта.
    pub rungs: [Rung; 3],
}

impl Reachability {
    /// Раскладывает доступность контакта по ступеням.
    #[must_use]
    pub const fn of(peer: PeerAvailability) -> Reachability {
        // Порядок здесь **и есть** §5.4, и читаться он должен сверху вниз
        // одним взглядом. Добавить транспорт значит дописать строку.
        Reachability {
            rungs: [
                Rung {
                    transport: Transport::Lan,
                    enabled: peer.enabled.contains(Transport::Lan),
                    ready: peer.ready.contains(Transport::Lan),
                    addressable: peer.seen_on_lan,
                },
                Rung {
                    transport: Transport::Onion,
                    enabled: peer.enabled.contains(Transport::Onion),
                    ready: peer.ready.contains(Transport::Onion),
                    addressable: peer.has_onion,
                },
                Rung {
                    transport: Transport::Mail,
                    enabled: peer.enabled.contains(Transport::Mail),
                    ready: peer.ready.contains(Transport::Mail),
                    addressable: peer.has_chatmail,
                },
            ],
        }
    }

    /// Состояние одной ступени.
    #[must_use]
    pub fn rung(&self, transport: Transport) -> Rung {
        self.rungs.into_iter().find(|rung| rung.transport == transport).unwrap_or(Rung {
            transport,
            enabled: false,
            ready: false,
            addressable: false,
        })
    }

    /// Ступень, которой уйдёт следующее сообщение.
    ///
    /// `None` — отправлять некуда прямо сейчас. Это **не** «не уйдёт
    /// никогда»: см. [`Reachability::rising`].
    #[must_use]
    pub fn route(&self) -> Option<Transport> {
        self.rungs.into_iter().find(|rung| rung.usable()).map(|rung| rung.transport)
    }

    /// Ступень, которая заберёт отправку, когда поднимется.
    ///
    /// Отвечает на «сообщение висит — оно уйдёт или нет». Непустой ответ
    /// означает «уйдёт, надо подождать»; пустой вместе с пустым
    /// [`Reachability::route`] — «ждать нечего, нужен адрес или переключатель».
    #[must_use]
    pub fn rising(&self) -> Option<Transport> {
        self.rungs.into_iter().find(|rung| rung.rising()).map(|rung| rung.transport)
    }
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

        // Лестница берётся у [`Reachability`], а не выписывается здесь.
        // Раньше она была списком в этой функции, и копия её жила в стенде
        // (`/who` печатал свой вердикт). Две копии одной лестницы расходятся
        // при первом же добавлении ступени, и расхождение молчаливое: экран
        // говорит «пойдёт почтой», а уходит через onion. Теперь список один,
        // а вопросов к нему два — «куда отправлять» и «что показать».
        let candidate = Reachability::of(peer)
            .rungs
            .into_iter()
            .find(|rung| rung.usable() && !self.tried.contains(&rung.transport))
            .map(|rung| rung.transport);

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

    /// Сколько ждать ответа собеседника по текущей попытке, мс.
    ///
    /// Именно ответа, а не соединения: соединение к этому моменту уже
    /// установлено, и его срок отмерил транспорт. Разница существенна
    /// для onion — см. [`ONION_REPLY_TIMEOUT_MS`].
    #[must_use]
    pub fn timeout_ms(&self) -> Option<u64> {
        match self.tried.last() {
            Some(Transport::Onion) => Some(ONION_REPLY_TIMEOUT_MS),
            Some(Transport::Lan) => Some(LAN_RECEIPT_TIMEOUT_MS),
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

    /// Всё разрешено, всё работает и всё достижимо — от этого отталкиваются
    /// проверки.
    fn full() -> PeerAvailability {
        PeerAvailability {
            seen_on_lan: true,
            enabled: everything(),
            ready: everything(),
            has_onion: true,
            has_chatmail: true,
        }
    }

    /// Набор со всеми транспортами.
    fn everything() -> TransportSet {
        let mut set = TransportSet::none();
        for transport in [Transport::Lan, Transport::Onion, Transport::Mail] {
            set.set(transport, true);
        }
        set
    }

    /// То же, но без одного.
    fn without(transport: Transport) -> PeerAvailability {
        let mut enabled = everything();
        enabled.set(transport, false);
        PeerAvailability { enabled, ..full() }
    }

    #[test]
    fn lan_first_when_enabled_and_visible() {
        let mut a = Attempt::new();
        assert_eq!(a.next(full()), Some(Decision::Use(Transport::Lan)));
    }

    #[test]
    fn lan_is_skipped_when_disabled() {
        // §5.1: по умолчанию LAN выключен, даже если контакт виден.
        let peer = without(Transport::Lan);
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
    fn a_transport_that_is_still_coming_up_is_not_a_step_either() {
        // Ошибка, ради которой это поле и заведено: «включён» и «работает»
        // разделяют десятки секунд bootstrap и публикации сервиса. Считай
        // включение готовностью — первое же сообщение после включения ушло
        // бы в ступень, которой ещё нет, получило бы отказ и **сожгло бы
        // её**: §5.4 транспорт после отказа не повторяет.
        let mut rising = everything();
        rising.set(Transport::Onion, false);
        let peer = PeerAvailability { ready: rising, ..without(Transport::Lan) };

        let mut a = Attempt::new();
        assert_eq!(
            a.next(peer),
            Some(Decision::Use(Transport::Mail)),
            "поднимающийся onion пропускается, а не тратится"
        );

        // А когда поднялся — он снова ступень, и притом первая из оставшихся.
        let mut a = Attempt::new();
        assert_eq!(a.next(without(Transport::Lan)), Some(Decision::Use(Transport::Onion)));
    }

    #[test]
    fn a_switched_off_transport_is_not_a_step() {
        // Разрешение и достижимость — разные вещи. Выключенный транспорт
        // не «пробуется и отказывает», а выпадает из лестницы целиком:
        // иначе каждое сообщение платило бы за него сроком ожидания,
        // а человек видел бы «не доставлено» вместо «выключено».
        let mut a = Attempt::new();
        assert_eq!(
            a.next(without(Transport::Onion)),
            Some(Decision::Use(Transport::Lan)),
            "первая ступень на месте"
        );
        assert_eq!(
            a.next(without(Transport::Onion)),
            Some(Decision::Use(Transport::Mail)),
            "выключенный onion пропускается целиком, а не пробуется"
        );
    }

    #[test]
    fn everything_switched_off_is_undeliverable_not_silence() {
        // §14: некуда — значит некуда, и сказать об этом надо сразу.
        // Молчание здесь превратилось бы в сообщение, которое «отправляется»
        // вечно.
        let peer = PeerAvailability { enabled: TransportSet::none(), ..full() };
        let mut a = Attempt::new();
        assert_eq!(a.next(peer), Some(Decision::Undeliverable));
    }

    #[test]
    fn a_set_survives_a_round_trip_through_a_byte() {
        // Набор уезжает в `meta` одним байтом и возвращается оттуда.
        let mut set = TransportSet::none();
        set.set(Transport::Onion, true);
        set.set(Transport::Mail, true);
        assert_eq!(TransportSet::from_bits(set.bits()), set);

        // Незнакомые биты отбрасываются: запись могла лечь более новой
        // версией, и включать по ней транспорт, которого в этой сборке нет,
        // нечем.
        assert_eq!(TransportSet::from_bits(0b1111_1111), TransportSet::from_bits(0b0000_0111));

        // Выключение действительно выключает, а не «почти».
        set.set(Transport::Onion, false);
        assert!(!set.contains(Transport::Onion));
        assert!(set.contains(Transport::Mail), "соседа выключение не задело");
    }

    #[test]
    fn onion_connect_timeout_matches_spec() {
        assert_eq!(ONION_CONNECT_TIMEOUT_MS, 45_000, "§5.4 задаёт срок соединения прямо");
    }

    #[test]
    fn waiting_for_a_reply_budgets_the_other_sides_dial() {
        // Соединения односторонние: ответ приезжает по соединению, которое
        // собеседник сперва набирает сам, а набор через Tor стоит столько же,
        // сколько наш. Срок ожидания короче чужого набора означал бы, что
        // первое же сообщение объявляется недоставленным ровно тогда, когда
        // оно доставлено.
        let mut a = Attempt::new();
        a.next(without(Transport::Lan));
        assert_eq!(a.timeout_ms(), Some(ONION_REPLY_TIMEOUT_MS));
        assert!(
            ONION_REPLY_TIMEOUT_MS >= 2 * ONION_CONNECT_TIMEOUT_MS,
            "в срок ответа обязан помещаться целый чужой набор, и наш тоже"
        );
    }

    #[test]
    fn mail_has_no_timeout() {
        let peer = PeerAvailability {
            has_chatmail: true,
            enabled: everything(),
            ready: everything(),
            ..Default::default()
        };
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

    #[test]
    fn the_verdict_agrees_with_the_ladder_on_every_combination() {
        // Главная проверка этой пары типов. `Reachability::route` существует
        // ради показа, `Attempt::next` — ради отправки, и разойдись они,
        // человек читал бы на экране одно, а уезжало бы другое. Молча.
        //
        // Проверяется полным перебором: пять независимых признаков — это
        // 2^5 = 32 сочетания, и перебрать их дешевле, чем выбирать
        // интересные и однажды выбрать не то.
        for bits in 0u8..32 {
            let mut enabled = TransportSet::none();
            let mut ready = TransportSet::none();
            let lan = bits & 1 != 0;
            let onion_on = bits & 2 != 0;
            let mail_on = bits & 4 != 0;
            if lan {
                enabled.set(Transport::Lan, true);
                ready.set(Transport::Lan, true);
            }
            if onion_on {
                enabled.set(Transport::Onion, true);
                ready.set(Transport::Onion, true);
            }
            if mail_on {
                enabled.set(Transport::Mail, true);
                ready.set(Transport::Mail, true);
            }
            let peer = PeerAvailability {
                seen_on_lan: bits & 8 != 0,
                enabled,
                ready,
                has_onion: bits & 16 != 0,
                has_chatmail: true,
            };

            let mut attempt = Attempt::new();
            let taken = match attempt.next(peer) {
                Some(Decision::Use(transport)) => Some(transport),
                _ => None,
            };
            assert_eq!(
                Reachability::of(peer).route(),
                taken,
                "вердикт разошёлся с отправкой на сочетании {bits}"
            );
        }
    }

    #[test]
    fn a_rising_rung_is_not_the_same_as_no_way_out() {
        // «Tor поднимается, сообщение уйдёт через полминуты» и «отправлять
        // некуда» — разные вещи, и UI обязан их различать: первое проходит
        // само, второе требует адреса или переключателя.
        let mut enabled = TransportSet::none();
        enabled.set(Transport::Onion, true);
        let rising = PeerAvailability {
            seen_on_lan: false,
            enabled,
            ready: TransportSet::none(),
            has_onion: true,
            has_chatmail: false,
        };
        let view = Reachability::of(rising);
        assert_eq!(view.route(), None, "ступень ещё не работает — ехать сейчас некуда");
        assert_eq!(view.rising(), Some(Transport::Onion), "но она поднимется и заберёт отправку");

        // А вот здесь ждать действительно нечего: транспорт разрешён
        // и работает, но адреса нет.
        let mut ready = TransportSet::none();
        ready.set(Transport::Onion, true);
        let hopeless = PeerAvailability { ready, has_onion: false, ..rising };
        let view = Reachability::of(hopeless);
        assert_eq!(view.route(), None);
        assert_eq!(view.rising(), None, "без адреса ждать нечего — это не «вот-вот»");
    }

    #[test]
    fn a_rung_says_which_of_the_three_troubles_it_is() {
        // Три признака ступени лечатся тремя разными действиями, и слить
        // их в одно «недоступен» значит ответить одинаково на три вопроса.
        let view = Reachability::of(without(Transport::Lan));
        let lan = view.rung(Transport::Lan);
        assert!(!lan.enabled, "выключен человеком — чинится переключателем");
        assert!(lan.addressable, "и при этом виден: беда не в адресе");
        assert!(!lan.usable());

        let onion = view.rung(Transport::Onion);
        assert!(onion.usable(), "остальные ступени выключение LAN не трогает");
    }
}
