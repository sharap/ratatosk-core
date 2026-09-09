//! Локальная сеть (§5.1).
//!
//! **По умолчанию LAN выключен.** Он раскрывает факт использования Ratatosk
//! в локальной сети; включается сознательно, с объяснением в UI. Умолчание
//! в коде должно совпадать с умолчанием в продукте — поэтому
//! [`LanConfig::default`] возвращает выключенное состояние.
//!
//! Обнаружение: mDNS, сервис `_ratatosk._tcp`, в TXT-записи — ротируемый маяк
//! из [`ratatosk_crypto::identity::beacon`]. Статический идентификатор
//! в эфир не транслируется никогда.
//!
//! # Кадрирование потока
//!
//! Длина кадра из заголовка **не выводится**: §7.1 длины не несёт, а классов
//! размера три (§5.5). Поэтому в поток перед каждым кадром идёт один байт
//! класса. Наблюдателю он ничего не добавляет — размер кадра тот и так считает
//! по байтам в сокете; §5.5 скрывает длину нагрузки, а не класс.
//!
//! Само кадрирование живёт в `crate::link` и здесь только используется:
//! onion (§5.2) отличается от локальной сети лишь тем, чем открыт поток,
//! а разделение полос записи нужно ему даже сильнее.
//!
//! # Соединения односторонние
//!
//! Каждая сторона набирает соединение сама и пишет только в него; принятые
//! соединения работают на чтение. Причина в том, что транспорт не знает, кто
//! к нему подключился: личность устанавливает рукопожатие (§8.2), а не TCP,
//! и до его завершения принятое соединение не с чем связать. Обратный ход
//! «угадать отправителя по адресу» — ровно та протокольная логика, которой
//! §13.3 в транспорте быть не должно.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatosk_crypto::identity::beacon;
use ratatosk_proto::transport_policy::{Transport, LAN_CONNECT_TIMEOUT_MS};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::link::{spawn_read_loop, Link};
use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Имя mDNS-сервиса (§5.1).
pub const SERVICE_TYPE: &str = "_ratatosk._tcp";

/// Полное имя сервиса в домене mDNS.
pub const SERVICE_DOMAIN: &str = "_ratatosk._tcp.local.";

/// Ключ TXT-записи, в которой едет маяк.
pub const BEACON_TXT_KEY: &str = "b";

/// Таймаут TCP-соединения внутри локальной сети.
///
/// Число берётся из §5.4 (`transport_policy`), а не задаётся здесь, и это
/// не педантизм: срок ожидания ответа у той же ступени обязан вмещать
/// **целый** такой набор — и наш, и чужой (соединения односторонние, 5ц).
/// Живя в разных крейтах, эти два числа однажды разошлись бы молча. С мешем
/// ровно это и случилось.
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(LAN_CONNECT_TIMEOUT_MS);

/// Настройки LAN-транспорта.
#[derive(Debug, Clone)]
pub struct LanConfig {
    /// Объявлять ли себя и слушать ли эфир.
    pub enabled: bool,
    /// Порт TCP. `0` — пусть выберет система.
    pub port: u16,
    /// Пользоваться ли mDNS.
    ///
    /// Выключается в тестах: обнаружение и передача — разные механизмы,
    /// и проверять передачу через мультикаст значит проверять сеть стенда.
    pub discovery: bool,
}

impl Default for LanConfig {
    fn default() -> Self {
        // §5.1: «По умолчанию LAN выключен.»
        LanConfig { enabled: false, port: 0, discovery: true }
    }
}

/// Известные адреса контактов в локальной сети.
///
/// Заполняется обнаружением, читается отправкой. Адрес здесь не приходит
/// в контакт-карточке (§4.1) и не может: он меняется при каждом подключении
/// к другой сети.
type Directory = Arc<Mutex<BTreeMap<[u8; 32], SocketAddr>>>;

/// Чьи маяки сопоставлять. Приходит из ядра командой
/// [`TransportCommand::WatchLanPeers`].
type Watched = Arc<Mutex<Vec<[u8; 32]>>>;

/// Полная TXT-запись маяка: `nonce ‖ значение` (§5.1).
type BeaconRecord = [u8; 16];

/// Что слышно в эфире прямо сейчас — независимо от того, ждём мы этого
/// собеседника или нет.
///
/// Нужен, потому что объявление могло прозвучать **раньше**, чем ядро сказало,
/// чьи маяки искать: контакт добавляют уже после запуска, а mDNS повторяет
/// анонс не сразу. Без этого буфера контакт «появлялся бы в сети» через
/// минуты после добавления — или не появлялся вовсе, если анонс уже прошёл.
///
/// Это кэш эфира, а не состояние: живёт только в памяти и ограничен по длине.
type Heard = Arc<Mutex<Vec<(BeaconRecord, SocketAddr)>>>;

/// Сколько объявлений помнить. В домашней сети устройств единицы, в офисной
/// — десятки; больше держать незачем, а безграничный список — способ занять
/// память чужим мультикастом.
const HEARD_CAPACITY: usize = 64;

/// Справочник адресов локальной сети, живущий отдельно от раннера.
///
/// Раннер уезжает внутрь драйвера, а адреса иногда нужно подставить снаружи —
/// в тестах и при ручной проверке, когда mDNS недоступен (мультикаст режут
/// и корпоративные сети, и гостевой Wi-Fi).
#[derive(Clone)]
pub struct LanDirectory {
    addresses: Directory,
    events: mpsc::Sender<TransportEvent>,
}

impl LanDirectory {
    /// Записывает адрес контакта и сообщает ядру, что тот виден в LAN.
    ///
    /// Одно и то же событие: знать адрес в локальной сети — и значит видеть
    /// контакт. Развести их значило бы завести состояние, в котором адрес
    /// известен, а §5.4 всё равно не выбирает LAN, — и разбираться, почему
    /// сообщение ушло почтой при живом собеседнике за стенкой.
    pub fn note(&self, peer_ik: [u8; 32], addr: SocketAddr) {
        if let Ok(mut dir) = self.addresses.lock() {
            dir.insert(peer_ik, addr);
        }
        if self.events.try_send(TransportEvent::SeenOnLan { peer_ik }).is_err() {
            tracing::debug!("очередь событий переполнена, отметка о видимости в LAN потеряна");
        }
    }

    /// Адрес контакта, если он известен.
    #[must_use]
    pub fn get(&self, peer_ik: &[u8; 32]) -> Option<SocketAddr> {
        self.addresses.lock().ok()?.get(peer_ik).copied()
    }
}

/// LAN-транспорт целиком: слушающий сокет, исходящие соединения, обнаружение.
pub struct LanRunner {
    events_tx: mpsc::Sender<TransportEvent>,
    events_rx: mpsc::Receiver<TransportEvent>,
    /// Куда писать каждому контакту.
    links: BTreeMap<[u8; 32], Link>,
    directory: Directory,
    watched: Watched,
    heard: Heard,
    /// Нужен только объявлению; без признака `lan` не используется.
    #[cfg_attr(not(feature = "lan"), allow(dead_code))]
    my_ik: [u8; 32],
    port: u16,
    enabled: bool,
    #[cfg_attr(not(feature = "lan"), allow(dead_code))]
    discovery_wanted: bool,
    #[cfg(feature = "lan")]
    discovery: Option<discovery::Discovery>,
}

impl LanRunner {
    /// Поднимает транспорт: занимает порт и, если LAN включён, объявляет себя.
    ///
    /// Слушающий сокет открывается независимо от `enabled`. Раскрывает
    /// присутствие именно объявление в эфир, а порт, о котором никто не знает,
    /// не раскрывает ничего; зато его номер нужен, чтобы объявление вообще
    /// было чем наполнить.
    pub async fn start(config: LanConfig, my_ik: [u8; 32]) -> Result<LanRunner, TransportError> {
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), config.port)).await?;
        let port = listener.local_addr()?.port();

        let (events_tx, events_rx) = mpsc::channel(64);
        spawn_accept_loop(listener, events_tx.clone());

        let mut runner = LanRunner {
            events_tx,
            events_rx,
            links: BTreeMap::new(),
            directory: Arc::new(Mutex::new(BTreeMap::new())),
            watched: Arc::new(Mutex::new(Vec::new())),
            heard: Arc::new(Mutex::new(Vec::new())),
            my_ik,
            port,
            enabled: false,
            discovery_wanted: config.discovery,
            #[cfg(feature = "lan")]
            discovery: None,
        };
        if config.enabled {
            runner.set_enabled(true)?;
        }
        Ok(runner)
    }

    /// Порт, который занял слушающий сокет.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Справочник адресов — его можно оставить себе, отдав раннер драйверу.
    #[must_use]
    pub fn directory(&self) -> LanDirectory {
        LanDirectory { addresses: Arc::clone(&self.directory), events: self.events_tx.clone() }
    }

    /// Записывает адрес контакта, минуя mDNS.
    ///
    /// Нужно тестам и ручной проверке: обнаружение и передача — разные
    /// механизмы, и первый не должен быть условием проверки второго.
    pub fn note_address(&self, peer_ik: [u8; 32], addr: SocketAddr) {
        self.directory().note(peer_ik, addr);
    }

    /// Адрес контакта, если он известен.
    #[must_use]
    pub fn address_of(&self, peer_ik: &[u8; 32]) -> Option<SocketAddr> {
        self.directory.lock().ok()?.get(peer_ik).copied()
    }

    fn set_enabled(&mut self, on: bool) -> Result<(), TransportError> {
        if on == self.enabled {
            return Ok(());
        }
        self.enabled = on;

        #[cfg(feature = "lan")]
        if self.discovery_wanted {
            if on {
                self.discovery = Some(discovery::Discovery::start(
                    self.my_ik,
                    self.port,
                    Arc::clone(&self.watched),
                    Arc::clone(&self.heard),
                    self.directory(),
                )?);
            } else {
                // Уход из эфира обязан быть немедленным: пользователь выключил
                // LAN именно затем, чтобы перестать быть видимым.
                self.discovery = None;
            }
        }
        Ok(())
    }

    /// Поднимает LAN заново после смены сети (§5.1).
    ///
    /// **Слушающий сокет переоткрывать не нужно, и это стоит объяснить.**
    /// Он привязан к `0.0.0.0`, то есть ко всем интерфейсам сразу, и смену
    /// сети переживает сам — адреса меняются под ним, а сокет остаётся.
    /// Переоткрытие сменило бы порт на ровном месте и оставило бы старую
    /// задачу приёма висеть на прежнем сокете.
    ///
    /// Заново заводится то, что действительно устарело: соединения,
    /// известные адреса и объявление в эфире.
    async fn restart(&mut self) -> Result<(), TransportError> {
        // Об оборванных соединениях ядро узнаёт сразу, а не по таймауту
        // первой отправки: §5.4 иначе заплатит ожиданием за то, что уже
        // известно. Сами сокеты об обрыве ещё не знают — узнают на первой
        // записи, и это как раз те секунды, которых хочется избежать.
        let peers: Vec<[u8; 32]> = self.links.keys().copied().collect();
        self.links.clear();
        for peer_ik in peers {
            let _ = self
                .events_tx
                .send(TransportEvent::Disconnected { peer_ik, via: Transport::Lan })
                .await;
        }

        // Адреса прежней сети хуже, чем их отсутствие: по ним отправка
        // упирается в таймаут вместо честного «адрес неизвестен». Кэш эфира
        // тоже: услышанное в прежней сети там больше не звучит.
        if let Ok(mut dir) = self.directory.lock() {
            dir.clear();
        }
        if let Ok(mut heard) = self.heard.lock() {
            heard.clear();
        }

        // Объявление перевыпускается — но только если LAN включён. Смена
        // сети не решает за пользователя (§5.1).
        #[cfg(feature = "lan")]
        if self.enabled && self.discovery_wanted {
            // Прежнее снимается первым: `Drop` шлёт прощальный пакет и
            // останавливает обзор, и делать это надо до нового объявления,
            // а не после.
            self.discovery = None;
            self.discovery = Some(discovery::Discovery::start(
                self.my_ik,
                self.port,
                Arc::clone(&self.watched),
                Arc::clone(&self.heard),
                self.directory(),
            )?);
        }
        Ok(())
    }

    /// Связь с контактом — существующая или набираемая.
    ///
    /// **Не ждёт соединения.** Набор уезжает в свою задачу
    /// ([`Link::dialing`]), а кадры до его конца ждут в полосах записи.
    /// Ждать здесь нельзя: `Driver::apply` дожидается каждой команды
    /// в теле своего цикла, и две секунды набора до устройства, которого
    /// уже нет в сети, — это две секунды, в которые ядро не отвечает
    /// ни на что.
    ///
    /// Отказ от этого не пропадает: он приезжает
    /// [`TransportEvent::ConnectFailed`], и адрес забывается там же, в задаче
    /// набора, — по той же причине, по какой забывался здесь.
    fn ensure_link(&mut self, peer_ik: [u8; 32]) -> Result<Link, TransportError> {
        if let Some(link) = self.links.get(&peer_ik) {
            if !link.is_closed() {
                return Ok(link.clone());
            }
            self.links.remove(&peer_ik);
        }

        let addr = self.address_of(&peer_ik).ok_or(TransportError::NoAddress)?;
        let directory = Arc::clone(&self.directory);
        let heard = Arc::clone(&self.heard);
        let link = Link::dialing(
            async move {
                let dialed = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .map_err(|_| TransportError::Timeout)
                    .and_then(|opened| opened.map_err(TransportError::from));
                let stream = match dialed {
                    Ok(stream) => stream,
                    Err(error) => {
                        forget_address(&directory, &heard, peer_ik);
                        return Err(error);
                    }
                };
                // Кадры уже дополнены до класса размера (§5.5); склейка
                // Нейгла только добавила бы задержку, ничего не экономя.
                stream.set_nodelay(true)?;
                // Тип ошибки назван прямо: он определяется только договором
                // `Link::dialing`, а `?` выше просят его знать раньше.
                Ok::<_, TransportError>(stream)
            },
            peer_ik,
            Transport::Lan,
            self.events_tx.clone(),
        );
        self.links.insert(peer_ik, link.clone());
        Ok(link)
    }

    /// Сверяет уже услышанные объявления с обновлённым списком контактов.
    ///
    /// Ровно то, чего не хватало без буфера [`Heard`]: контакт, добавленный
    /// после того как его устройство уже объявилось, иначе ждал бы следующего
    /// анонса.
    fn rematch_heard(&self, peers: &[[u8; 32]]) {
        if peers.is_empty() {
            return;
        }
        let heard: Vec<(BeaconRecord, SocketAddr)> =
            self.heard.lock().map(|h| h.clone()).unwrap_or_default();
        if heard.is_empty() {
            return;
        }

        let slot = beacon::slot(unix_seconds());
        let directory = self.directory();
        for (record, addr) in heard {
            for ik in peers {
                if beacon::matches(&record, ik, slot) {
                    directory.note(*ik, addr);
                }
            }
        }
    }

    /// Сообщает ядру о неудаче, а не только возвращает ошибку.
    ///
    /// Без события §5.4 узнал бы об отказе лишь по таймауту, то есть через
    /// пять секунд там, где ответ уже есть.
    ///
    /// Осталось для отказов, которые видны **сразу**: адреса нет вовсе,
    /// соединение оборвалось на записи. Неудача набора сюда больше не
    /// приходит — она случается в чужой задаче и рассказывает о себе сама.
    async fn report_failure(&self, peer_ik: [u8; 32]) {
        forget_address(&self.directory, &self.heard, peer_ik);
        let _ = self
            .events_tx
            .send(TransportEvent::ConnectFailed { peer_ik, via: Transport::Lan })
            .await;
    }
}

/// Забывает адрес, по которому не удалось соединиться.
///
/// Адрес в справочнике — это не свойство контакта, а последнее, что мы
/// о нём слышали. Не дозвонившись, держать его дальше нельзя: устройство
/// могло уйти из сети или перезапуститься с другим портом, и тогда каждая
/// следующая попытка упирается в ту же дыру, платя за неё таймаутом.
/// Забыть — значит вернуться к честному «адрес неизвестен»; живой сосед
/// объявится следующим анонсом mDNS через секунды.
///
/// Кэш эфира чистится заодно: иначе [`LanRunner::rematch_heard`] вернул бы
/// тот же мёртвый адрес при первом же обновлении списка контактов.
///
/// Свободной функцией, а не методом: звать её приходится и из задачи набора,
/// у которой раннера нет и быть не может, — а два экземпляра этого правила
/// однажды разошлись бы.
fn forget_address(directory: &Directory, heard: &Heard, peer_ik: [u8; 32]) {
    let stale = match directory.lock() {
        Ok(mut directory) => directory.remove(&peer_ik),
        Err(_) => None,
    };
    let Some(stale) = stale else { return };
    if let Ok(mut heard) = heard.lock() {
        heard.retain(|(_, addr)| *addr != stale);
    }
}

impl Runner for LanRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            TransportCommand::Send { peer, via, frame, .. } => {
                if via != Transport::Lan {
                    return Err(TransportError::Unavailable);
                }
                if !self.enabled {
                    return Err(TransportError::Unavailable);
                }
                match self.ensure_link(peer.ik) {
                    Ok(link) => match link.send(frame).await {
                        Ok(()) => Ok(()),
                        // Забитая очередь чанков — не обрыв: соединение живо,
                        // просто пишет медленнее, чем в него кладут. Рвать его
                        // здесь значило бы лечить затор разрывом, а заодно
                        // ронять переписку из-за одной передачи файла.
                        Err(TransportError::Busy) => Err(TransportError::Busy),
                        Err(error) => {
                            self.links.remove(&peer.ik);
                            self.report_failure(peer.ik).await;
                            Err(error)
                        }
                    },
                    Err(error) => {
                        self.report_failure(peer.ik).await;
                        Err(error)
                    }
                }
            }
            TransportCommand::Connect { peer, via } => {
                if via != Transport::Lan || !self.enabled {
                    return Err(TransportError::Unavailable);
                }
                match self.ensure_link(peer.ik) {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        self.report_failure(peer.ik).await;
                        Err(error)
                    }
                }
            }
            TransportCommand::Disconnect { peer } => {
                self.links.remove(&peer.ik);
                Ok(())
            }
            // Чужой транспорт сюда попасть не может — составной раннер
            // разводит по адресату, — но проверка стоит: молча включиться
            // по чужой команде хуже, чем отказать.
            TransportCommand::SetEnabled { transport: Transport::Lan, enabled } => {
                self.set_enabled(enabled)
            }
            TransportCommand::SetEnabled { .. } => Err(TransportError::Unavailable),
            TransportCommand::RestartLan => self.restart().await,
            TransportCommand::WatchLanPeers(peers) => {
                // Сначала пересматриваем уже услышанное, потом запоминаем
                // список. Порядок неважен для результата, но так очевидно,
                // что новый контакт находится сразу, а не со следующим анонсом.
                self.rematch_heard(&peers);
                if let Ok(mut watched) = self.watched.lock() {
                    *watched = peers;
                }
                Ok(())
            }
            // Почтовые настройки локальной сети не касаются. Сюда они
            // не доходят — составной раннер разводит по адресату, — но
            // молчаливое согласие с чужой командой хуже отказа.
            TransportCommand::SetMailAccount(_)
            | TransportCommand::CreateMailAccount { .. }
            | TransportCommand::SetYgg(_) => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        self.events_rx.recv().await
    }
}

fn spawn_accept_loop(listener: TcpListener, events: mpsc::Sender<TransportEvent>) {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    spawn_read_loop(stream, Transport::Lan, events.clone());
                }
                // Исчерпание дескрипторов лечится ожиданием, а не выходом
                // из цикла: выйдя, транспорт замолчал бы навсегда.
                Err(error) => {
                    tracing::debug!(?error, "не удалось принять соединение");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
}

/// Текущее время в секундах Unix — вход для номера слота маяка.
#[cfg_attr(not(feature = "lan"), allow(dead_code))]
fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(feature = "lan")]
mod discovery {
    //! mDNS: объявление себя и поиск контактов по маяку (§5.1).

    use super::{
        unix_seconds, BeaconRecord, Heard, LanDirectory, Watched, BEACON_TXT_KEY, HEARD_CAPACITY,
        SERVICE_DOMAIN,
    };
    use crate::runner::TransportError;

    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use data_encoding::HEXLOWER;
    use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
    use ratatosk_crypto::identity::beacon;

    /// Живое объявление и поиск. Уничтожение снимает объявление и
    /// останавливает задачи.
    pub struct Discovery {
        daemon: ServiceDaemon,
        fullname: String,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    /// Сколько ждать, пока демон действительно выпустит прощальный пакет.
    ///
    /// Ноль здесь означал бы отсутствие прощания вовсе, а не «быстро».
    const GOODBYE_WAIT: Duration = Duration::from_millis(500);

    impl Drop for Discovery {
        fn drop(&mut self) {
            for task in self.tasks.drain(..) {
                task.abort();
            }

            // Прощальный пакет: контакты должны узнать об уходе сразу, а не
            // по истечении TTL записи — иначе они держат наш прежний адрес
            // и порт до семидесяти пяти минут и всё это время звонят в пустоту.
            //
            // **Дождаться обязательно.** `unregister` только ставит задачу
            // демону и возвращает канал; `shutdown` следом останавливал поток
            // раньше, чем пакет уходил в сеть. Прощание было написано, но
            // не отправлялось ни разу — а по коду выглядело сделанным.
            match self.daemon.unregister(&self.fullname) {
                Ok(done) => {
                    let _ = done.recv_timeout(GOODBYE_WAIT);
                }
                Err(error) => tracing::debug!(?error, "не удалось снять объявление LAN"),
            }
            let _ = self.daemon.shutdown();
        }
    }

    impl Discovery {
        pub fn start(
            my_ik: [u8; 32],
            port: u16,
            watched: Watched,
            heard: Heard,
            directory: LanDirectory,
        ) -> Result<Discovery, TransportError> {
            let daemon = ServiceDaemon::new().map_err(mdns_error)?;

            let instance = instance_name();
            let info = service_info(&instance, &my_ik, port)?;
            let fullname = info.get_fullname().to_owned();
            daemon.register(info).map_err(mdns_error)?;

            let browse = daemon.browse(SERVICE_DOMAIN).map_err(mdns_error)?;
            let browse_task = tokio::spawn(browse_loop(browse, watched, heard, directory));
            let rotate_task = tokio::spawn(rotate_loop(daemon.clone(), instance, my_ik, port));

            Ok(Discovery { daemon, fullname, tasks: vec![browse_task, rotate_task] })
        }
    }

    fn mdns_error(error: mdns_sd::Error) -> TransportError {
        TransportError::Discovery(format!("{error:?}"))
    }

    /// Имя экземпляра mDNS — случайное и новое у каждого запуска.
    ///
    /// **Раньше оно выводилось из маяка текущего слота, и это была ошибка,
    /// которая ломала обнаружение после перезапуска.** Маяк детерминирован:
    /// он выводится из `IK` и номера пятнадцатиминутного слота. Значит
    /// приложение, перезапущенное внутри того же слота, объявлялось под
    /// **тем же самым** именем экземпляра и с тем же именем хоста — но со
    /// свежим эфемерным TCP-портом. Для собеседника это выглядело не как
    /// «сосед вернулся», а как «запись, которая у меня уже есть»: в его
    /// кэше mDNS лежал прежний порт, соединение уходило в пустоту, §5.4
    /// объявлял LAN недоступным, и связь не восстанавливалась до смены
    /// слота — до пятнадцати минут. Симметрично с обеих сторон, поэтому
    /// «устройства перестали видеть друг друга».
    ///
    /// Имя экземпляра — это идентификатор **объявления**, а не устройства,
    /// и всё, что в объявлении, у каждого запуска своё: порт, адрес, сокет.
    /// Поэтому и имя обязано быть своим.
    ///
    /// Приватности это не стоит ничего, наоборот: случайные восемь байт
    /// не выводятся из `IK` вовсе, тогда как прежнее имя было буквально
    /// первой половиной маяка, продублированной в открытом виде. Узнавание
    /// своих делает маяк в TXT (§5.1), и только он.
    fn instance_name() -> String {
        use rand_core::RngCore;

        let mut bytes = [0u8; 8];
        rand_core::OsRng.fill_bytes(&mut bytes);
        HEXLOWER.encode(&bytes)
    }

    /// Nonce маяка выводится из `IK` и слота, а не случаен.
    ///
    /// Случайный nonce пришлось бы хранить между перезапусками — иначе после
    /// рестарта устройство выглядит новым, и объявление теряет смысл для
    /// контактов, которые как раз его ждут. Вывод даёт то же свойство
    /// «меняется каждые 15 минут» без состояния на диске.
    ///
    /// Постороннему это ничего не даёт: и nonce, и значение маяка выводятся
    /// из `IK`, которого у него нет. Вся запись и так детерминирована слотом.
    fn nonce_for_slot(my_ik: &[u8; 32], slot: u64) -> [u8; 8] {
        beacon::compute(my_ik, slot, &[0u8; 8])
    }

    fn service_info(
        instance: &str,
        my_ik: &[u8; 32],
        port: u16,
    ) -> Result<ServiceInfo, TransportError> {
        let slot = beacon::slot(unix_seconds());
        let record = beacon::record(my_ik, slot, nonce_for_slot(my_ik, slot));
        let txt = HEXLOWER.encode(&record);
        let host = format!("{instance}.local.");
        ServiceInfo::new(
            SERVICE_DOMAIN,
            instance,
            &host,
            "",
            port,
            &[(BEACON_TXT_KEY, txt.as_str())][..],
        )
        .map(ServiceInfo::enable_addr_auto)
        .map_err(mdns_error)
    }

    /// Кладёт объявление в кэш эфира, вытесняя самое старое.
    fn remember(heard: &Heard, record: BeaconRecord, addr: SocketAddr) {
        let Ok(mut heard) = heard.lock() else { return };
        // Повторный анонс того же маяка — обычное дело: mDNS их и повторяет.
        heard.retain(|(seen, _)| *seen != record);
        heard.push((record, addr));
        if heard.len() > HEARD_CAPACITY {
            heard.remove(0);
        }
    }

    async fn browse_loop(
        browse: mdns_sd::Receiver<ServiceEvent>,
        watched: Watched,
        heard: Heard,
        directory: LanDirectory,
    ) {
        while let Ok(event) = browse.recv_async().await {
            let ServiceEvent::ServiceResolved(service) = event else {
                continue;
            };
            let Some(txt) = service.get_property_val_str(BEACON_TXT_KEY) else {
                continue;
            };
            let Ok(bytes) = HEXLOWER.decode(txt.as_bytes()) else {
                continue;
            };
            let Ok(record): Result<[u8; 16], _> = bytes.try_into() else {
                continue;
            };
            // У хоста может быть несколько адресов; берём наименьший, чтобы
            // выбор не зависел от порядка обхода `HashSet` и был одинаков
            // от запуска к запуску.
            let Some(ip) = service.get_addresses_v4().into_iter().min() else {
                continue;
            };
            let addr = SocketAddr::new(IpAddr::V4(ip), service.get_port());

            // Запоминается всё услышанное, а не только совпавшее: контакт
            // могут добавить через минуту после того, как его устройство
            // объявилось, и следующего анонса ждать незачем.
            remember(&heard, record, addr);

            // Список копируется, чтобы не держать блокировку через `.await`.
            let peers: Vec<[u8; 32]> = watched.lock().map(|w| w.clone()).unwrap_or_default();
            let slot = beacon::slot(unix_seconds());

            peers
                .into_iter()
                // `matches` сам принимает слоты −1, 0, +1 (§5.1): часы
                // устройств расходятся, и запись из соседнего слота — норма.
                .filter(|ik| beacon::matches(&record, ik, slot))
                .for_each(|ik| directory.note(ik, addr));
        }
    }

    /// Перевыпускает объявление на каждой границе слота (§5.1).
    ///
    /// Без этого маяк застыл бы на значении момента запуска, и наблюдатель
    /// получил бы ровно то, чего ротация избегает, — постоянный идентификатор.
    ///
    /// Меняется только TXT-запись; имя экземпляра остаётся прежним, и так
    /// и надо. В mDNS смена имени — это не обновление, а **новый** сервис:
    /// прежний остался бы в чужих кэшах призраком до истечения TTL, то есть
    /// до семидесяти пяти минут. Обновление записи под тем же именем доходит
    /// до соседей сразу, а идентифицирует нас для контактов маяк, а не имя.
    async fn rotate_loop(daemon: ServiceDaemon, instance: String, my_ik: [u8; 32], port: u16) {
        loop {
            let now = unix_seconds();
            let next = (beacon::slot(now) + 1) * beacon::SLOT_SECONDS;
            tokio::time::sleep(Duration::from_secs(next.saturating_sub(now).max(1))).await;

            match service_info(&instance, &my_ik, port) {
                Ok(info) => {
                    if let Err(error) = daemon.register(info) {
                        tracing::debug!(?error, "не удалось обновить объявление LAN");
                    }
                }
                Err(error) => tracing::debug!(?error, "не удалось собрать объявление LAN"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn every_launch_announces_under_its_own_name() {
            // Прежняя реализация выводила имя из маяка, то есть из `IK`
            // и номера слота. Перезапуск внутри тех же пятнадцати минут давал
            // **то же самое** имя при новом порте — и соседи продолжали звонить
            // по старому адресу, пока слот не сменится. Этот тест ловит именно
            // ту детерминированность.
            assert_ne!(
                super::instance_name(),
                super::instance_name(),
                "имя объявления обязано быть своим у каждого запуска"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatosk_wire::SizeClass;

    use super::*;

    #[test]
    fn lan_is_off_by_default() {
        assert!(!LanConfig::default().enabled, "§5.1: умолчание в коде и в продукте совпадают");
    }

    #[tokio::test]
    async fn disabled_lan_refuses_to_send() {
        // §5.1: пока пользователь не включил LAN, транспорт не отправляет
        // ничего — даже если адрес собеседника откуда-то известен.
        let mut runner = LanRunner::start(LanConfig::default(), [1u8; 32]).await.unwrap();
        assert!(runner.port() != 0, "порт занимается независимо от объявления");

        runner.note_address([2u8; 32], SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 9));
        let verdict = runner
            .execute(TransportCommand::Send {
                peer: crate::runner::PeerAddress {
                    ik: [2u8; 32],
                    onion: None,
                    chatmail: None,
                    ygg: None,
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
                handoff: None,
            })
            .await;
        assert!(matches!(verdict, Err(TransportError::Unavailable)));
    }

    #[tokio::test]
    async fn an_unknown_address_fails_fast_and_says_so() {
        // Отказ обязан приехать событием, а не только возвратом: §5.4 иначе
        // узнал бы о нём лишь по таймауту — через пять секунд там, где ответ
        // уже есть.
        let config = LanConfig { enabled: true, port: 0, discovery: false };
        let mut runner = LanRunner::start(config, [1u8; 32]).await.unwrap();

        let verdict = runner
            .execute(TransportCommand::Send {
                peer: crate::runner::PeerAddress {
                    ik: [2u8; 32],
                    onion: None,
                    chatmail: None,
                    ygg: None,
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
                handoff: None,
            })
            .await;
        assert!(matches!(verdict, Err(TransportError::NoAddress)));
        assert!(matches!(
            runner.next_event().await,
            Some(TransportEvent::ConnectFailed { via: Transport::Lan, .. })
        ));
    }

    #[tokio::test]
    async fn an_address_that_did_not_answer_is_forgotten() {
        // Адрес в справочнике — последнее, что мы слышали, а не свойство
        // контакта. Устройство могло перезапуститься и занять другой порт;
        // сохранив прежний, транспорт упирался бы в него при каждой отправке,
        // платя таймаутом, — и живой сосед оставался бы недостижимым.
        let config = LanConfig { enabled: true, port: 0, discovery: false };
        let mut runner = LanRunner::start(config, [1u8; 32]).await.unwrap();

        // Порт 9 (discard) на loopback никем не слушается — соединение
        // отвергается сразу, без ожидания.
        let dead = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 9);
        runner.note_address([2u8; 32], dead);
        assert_eq!(runner.address_of(&[2u8; 32]), Some(dead));

        let _ = runner
            .execute(TransportCommand::Send {
                peer: crate::runner::PeerAddress {
                    ik: [2u8; 32],
                    onion: None,
                    chatmail: None,
                    ygg: None,
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
                handoff: None,
            })
            .await;

        // Ждём **события**, а не возврата: набор уехал в свою задачу,
        // и к возврату `execute` он ещё идёт. Адрес забывается там же,
        // в задаче, и обязательно **до** новости об отказе — иначе эта
        // проверка гонялась бы с ней.
        await_connect_failed(&mut runner).await;
        assert_eq!(
            runner.address_of(&[2u8; 32]),
            None,
            "мёртвый адрес обязан уйти из справочника, а не пережить собеседника"
        );
    }

    #[tokio::test]
    async fn sending_does_not_wait_for_the_dial() {
        // Ради этого всё и переделано. `Driver::apply` дожидается каждой
        // команды **в теле своего цикла**, и набор, ждавшийся внутри
        // `execute`, останавливал ядро целиком: ни переписки на экране,
        // ни таймеров, ни приёма по другим ступеням. На старте это било
        // сильнее всего — `Engine::startup_effects` возвращает недоделанные
        // доставки, и приложение молчало ровно столько, сколько занимал
        // набор ко всем, кого нет в сети.
        //
        // Наблюдаемое следствие: команда возвращается `Ok`, хотя соединения
        // ещё нет и не будет. Отказ приезжает следом — событием.
        let config = LanConfig { enabled: true, port: 0, discovery: false };
        let mut runner = LanRunner::start(config, [1u8; 32]).await.unwrap();
        runner.note_address([2u8; 32], SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 9));

        let verdict = runner
            .execute(TransportCommand::Send {
                peer: crate::runner::PeerAddress {
                    ik: [2u8; 32],
                    onion: None,
                    chatmail: None,
                    ygg: None,
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
                handoff: None,
            })
            .await;
        assert!(
            verdict.is_ok(),
            "команда обязана вернуться, не дожидаясь исхода набора: {verdict:?}"
        );

        // Неудача набора обязана приехать событием — иначе §5.4 узнает
        // о ней только по сроку ожидания.
        await_connect_failed(&mut runner).await;
    }

    /// Ждёт отказ соединения, пропуская всё остальное.
    ///
    /// Пропускать приходится: запись адреса в справочник сама по себе
    /// событие ([`TransportEvent::SeenOnLan`]), и оно приезжает раньше.
    async fn await_connect_failed(runner: &mut LanRunner) {
        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(event) = runner.next_event().await {
                if matches!(event, TransportEvent::ConnectFailed { via: Transport::Lan, .. }) {
                    return true;
                }
            }
            false
        })
        .await
        .expect("отказ набора обязан приехать в срок");
        assert!(waited, "поток событий кончился раньше отказа");
    }
}
