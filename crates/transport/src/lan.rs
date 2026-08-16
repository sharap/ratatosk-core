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
use ratatosk_proto::transport_policy::Transport;
use ratatosk_wire::SizeClass;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Имя mDNS-сервиса (§5.1).
pub const SERVICE_TYPE: &str = "_ratatosk._tcp";

/// Полное имя сервиса в домене mDNS.
pub const SERVICE_DOMAIN: &str = "_ratatosk._tcp.local.";

/// Ключ TXT-записи, в которой едет маяк.
pub const BEACON_TXT_KEY: &str = "b";

/// Таймаут TCP-соединения внутри локальной сети.
///
/// LAN отвечает за миллисекунды; секунды здесь — запас на спящий Wi-Fi,
/// а не на маршрутизацию. Дальше ждать нечего: §5.4 переводит доставку
/// на следующий транспорт.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Сколько кадров помещается в очередь на запись, прежде чем отправка начнёт
/// ждать. Кадр класса L — мебибайт, поэтому очередь короткая намеренно.
const WRITE_QUEUE: usize = 16;

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

/// Байт класса размера, идущий перед кадром.
const fn tag_of(class: SizeClass) -> u8 {
    match class {
        SizeClass::S => 0,
        SizeClass::M => 1,
        SizeClass::L => 2,
    }
}

fn class_of_tag(tag: u8) -> Option<SizeClass> {
    match tag {
        0 => Some(SizeClass::S),
        1 => Some(SizeClass::M),
        2 => Some(SizeClass::L),
        _ => None,
    }
}

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
    links: BTreeMap<[u8; 32], mpsc::Sender<Vec<u8>>>,
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
        let listener = TcpListener::bind(SocketAddr::new(
            IpAddr::from([0, 0, 0, 0]),
            config.port,
        ))
        .await?;
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
        LanDirectory {
            addresses: Arc::clone(&self.directory),
            events: self.events_tx.clone(),
        }
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

    async fn ensure_link(
        &mut self,
        peer_ik: [u8; 32],
    ) -> Result<mpsc::Sender<Vec<u8>>, TransportError> {
        if let Some(link) = self.links.get(&peer_ik) {
            if !link.is_closed() {
                return Ok(link.clone());
            }
            self.links.remove(&peer_ik);
        }

        let addr = self.address_of(&peer_ik).ok_or(TransportError::NoAddress)?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout)??;
        // Кадры уже дополнены до класса размера (§5.5); склейка Нейгла только
        // добавила бы задержку, ничего не экономя.
        stream.set_nodelay(true)?;

        let (tx, rx) = mpsc::channel(WRITE_QUEUE);
        spawn_write_loop(stream, rx, peer_ik, self.events_tx.clone());
        self.links.insert(peer_ik, tx.clone());

        let _ = self
            .events_tx
            .send(TransportEvent::Connected { peer_ik, via: Transport::Lan })
            .await;
        Ok(tx)
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
    async fn report_failure(&self, peer_ik: [u8; 32]) {
        let _ = self
            .events_tx
            .send(TransportEvent::ConnectFailed { peer_ik, via: Transport::Lan })
            .await;
    }
}

impl Runner for LanRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            TransportCommand::Send { peer, via, frame } => {
                if via != Transport::Lan {
                    return Err(TransportError::Unavailable);
                }
                if !self.enabled {
                    return Err(TransportError::Unavailable);
                }
                match self.ensure_link(peer.ik).await {
                    Ok(link) => {
                        if link.send(frame).await.is_err() {
                            self.links.remove(&peer.ik);
                            self.report_failure(peer.ik).await;
                            return Err(TransportError::Unavailable);
                        }
                        Ok(())
                    }
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
                match self.ensure_link(peer.ik).await {
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
            TransportCommand::SetLanEnabled(on) => self.set_enabled(on),
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
                    spawn_read_loop(stream, events.clone());
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

fn spawn_read_loop(mut stream: TcpStream, events: mpsc::Sender<TransportEvent>) {
    tokio::spawn(async move {
        loop {
            let mut tag = [0u8; 1];
            if stream.read_exact(&mut tag).await.is_err() {
                return;
            }
            let Some(class) = class_of_tag(tag[0]) else {
                // Неизвестный класс — поток дальше не разобрать: где кончается
                // этот кадр, неизвестно. Единственный корректный ход — закрыть.
                tracing::debug!(tag = tag[0], "неизвестный класс кадра, закрываем поток");
                return;
            };
            let mut frame = vec![0u8; class.frame_len()];
            if stream.read_exact(&mut frame).await.is_err() {
                return;
            }
            let event = TransportEvent::Received {
                via: Transport::Lan,
                // Транспорт не знает, кто прислал: личность даёт рукопожатие
                // (§8.2), а не адрес.
                peer_hint: None,
                frame,
            };
            if events.send(event).await.is_err() {
                return;
            }
        }
    });
}

fn spawn_write_loop(
    mut stream: TcpStream,
    mut frames: mpsc::Receiver<Vec<u8>>,
    peer_ik: [u8; 32],
    events: mpsc::Sender<TransportEvent>,
) {
    tokio::spawn(async move {
        while let Some(frame) = frames.recv().await {
            let Ok(class) = SizeClass::from_frame_len(frame.len()) else {
                // Кадр не того размера сюда попасть не может: его собирает
                // `crypto::aead::seal`. Если попал — это ошибка выше, и
                // молча отправлять её в сеть нельзя.
                tracing::error!(len = frame.len(), "кадр вне классов размера, не отправлен");
                continue;
            };
            if stream.write_all(&[tag_of(class)]).await.is_err()
                || stream.write_all(&frame).await.is_err()
            {
                let _ = events
                    .send(TransportEvent::Disconnected { peer_ik, via: Transport::Lan })
                    .await;
                return;
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

    impl Drop for Discovery {
        fn drop(&mut self) {
            for task in self.tasks.drain(..) {
                task.abort();
            }
            // Прощальный пакет: контакты должны узнать об уходе сразу, а не
            // по истечении TTL записи.
            let _ = self.daemon.unregister(&self.fullname);
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

            // Имя экземпляра не должно нести идентичность: оно видно
            // постороннему так же, как всё остальное в эфире. Берём его
            // из маяка текущего слота — оно ротируется вместе с ним.
            let instance = instance_name(&my_ik);
            let info = service_info(&instance, &my_ik, port)?;
            let fullname = info.get_fullname().to_owned();
            daemon.register(info).map_err(mdns_error)?;

            let browse = daemon.browse(SERVICE_DOMAIN).map_err(mdns_error)?;
            let browse_task = tokio::spawn(browse_loop(browse, watched, heard, directory));
            let rotate_task =
                tokio::spawn(rotate_loop(daemon.clone(), instance, my_ik, port));

            Ok(Discovery { daemon, fullname, tasks: vec![browse_task, rotate_task] })
        }
    }

    fn mdns_error(error: mdns_sd::Error) -> TransportError {
        TransportError::Discovery(format!("{error:?}"))
    }

    fn instance_name(my_ik: &[u8; 32]) -> String {
        let slot = beacon::slot(unix_seconds());
        HEXLOWER.encode(&beacon::record(my_ik, slot, nonce_for_slot(my_ik, slot))[..8])
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
        ServiceInfo::new(SERVICE_DOMAIN, instance, &host, "", port, &[(BEACON_TXT_KEY, txt.as_str())][..])
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
            let peers: Vec<[u8; 32]> =
                watched.lock().map(|w| w.clone()).unwrap_or_default();
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
    async fn rotate_loop(daemon: ServiceDaemon, instance: String, my_ik: [u8; 32], port: u16) {
        loop {
            let now = unix_seconds();
            let next = (beacon::slot(now) + 1) * beacon::SLOT_SECONDS;
            tokio::time::sleep(Duration::from_secs(next.saturating_sub(now).max(1))).await;

            // Имя экземпляра тоже ротируется, поэтому объявление выпускается
            // заново целиком.
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_is_off_by_default() {
        assert!(!LanConfig::default().enabled, "§5.1: умолчание в коде и в продукте совпадают");
    }

    #[test]
    fn size_class_tags_round_trip() {
        for class in SizeClass::ALL {
            assert_eq!(class_of_tag(tag_of(class)), Some(class));
        }
        assert_eq!(class_of_tag(3), None, "неизвестный класс обязан отвергаться");
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
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
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
                },
                via: Transport::Lan,
                frame: vec![0u8; SizeClass::S.frame_len()],
            })
            .await;
        assert!(matches!(verdict, Err(TransportError::NoAddress)));
        assert!(matches!(
            runner.next_event().await,
            Some(TransportEvent::ConnectFailed { via: Transport::Lan, .. })
        ));
    }
}
