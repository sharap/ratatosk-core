//! Собственно arti: Tor-клиент, onion-сервис и кадры поверх `DataStream`.
//!
//! Отдельный файл и отдельный признак сборки (`onion-arti`) намеренно. Это
//! единственное место в дереве, которое трогает API arti, а проверить его
//! я могу только чужой сборкой: у arti нумерация 0.x, сигнатуры меняются,
//! и ошибка здесь стоит сорока зависимостей пересборки. Пока файл собирается
//! не всегда, остальное дерево остаётся зелёным.
//!
//! # Что здесь происходит
//!
//! ```text
//! start()  → TorClient::create_bootstrapped   (десятки секунд)
//!          → launch_onion_service              (наш ключ из ctor-хранилища)
//!          → handle_rend_requests → StreamRequest::accept → DataStream
//!          → TransportEvent::TorReady { onion }
//!
//! Send     → TorClient::connect((адрес, порт)) → DataStream → link::Link
//! ```
//!
//! Кадрирование берётся готовым из [`crate::link`] — тем же, что работает
//! на LAN: `DataStream` реализует `AsyncRead` и `AsyncWrite`, а больше
//! от потока ничего и не требуется.
//!
//! # Адрес считаем сами — и сверяем с тем, что поднял сервис
//!
//! Адрес выводится из нашего ключа арифметикой (`ratatosk_crypto::onion`),
//! и это позволяет знать его до всякого Tor: карточку (§4.1) человек
//! показывает сразу, а bootstrap идёт десятки секунд.
//!
//! Но посчитанный адрес — предсказание, а не факт. Если arti взял для сервиса
//! **не наш** ключ (нашёл свой в каталоге состояния и до ctor-хранилища
//! не дошёл), то посчитанный адрес не обслуживает никто, а обе половины при
//! этом выглядят исправными: Tor на 100 %, сервис опубликован, сообщения
//! не ходят, причины не видно. Ровно так это и выглядело на стенде.
//!
//! Поэтому адрес сверяется с тем, который поднял сервис, и **расхождение —
//! отказ**. Соблазн объявить рабочий чужой адрес велик — связь поехала бы
//! сразу, — но адрес сервиса это наша личность в сети (§3, §5.2), она обязана
//! выводиться из запечатанного зерна, а чужая живёт в каталоге состояния
//! и исчезает вместе с ним. Человек узнал бы об этом в день первой чистки.
//!
//! # Изоляция потоков не включается, и это выбор
//!
//! `TorClient::isolated_client` развёл бы соединения с разными контактами
//! по разным цепочкам. Для onion-сервисов выигрыш невелик: выходного узла
//! нет, а наблюдатель у сторожевого видит только шифрованный трафик
//! до реле. Плата же реальна — своя цепочка на контакт означает секунды
//! на установление и лишнюю память на телефоне (§13.1). Если когда-нибудь
//! окажется, что общая цепочка связывает контакты между собой, это место
//! меняется одной строкой.
//!
//! # Оговорка про сигнатуры
//!
//! Всё, что помечено `СВЕРИТЬ`, написано по документации, а не по сборке:
//! пути импорта и точные имена методов у arti я подтвердить не мог. Каждая
//! такая строка — отдельная, чтобы ошибка компилятора указывала ровно на неё.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::onion_service::OnionServiceConfig;
use arti_client::config::TorClientConfigBuilder;
use arti_client::{TorClient, TorClientConfig};
use futures::StreamExt;
use ratatosk_crypto::OnionKey;
use ratatosk_proto::transport_policy::{Transport, ONION_CONNECT_TIMEOUT_MS};
use tokio::sync::mpsc;
// СВЕРИТЬ: `handle_rend_requests` и `HsNickname` берутся из `tor-hsservice`
// напрямую, а не из переэкспорта `arti-client`, — так путь не зависит
// от того, что именно arti решил переэкспортировать в этой версии.
use tor_hsservice::{handle_rend_requests, HsNickname, RunningOnionService};
// СВЕРИТЬ: идентификатор хранилища ключей.
use tor_keymgr::KeystoreId;

use crate::link::{spawn_read_loop, Link};
use crate::onion::SERVICE_PORT;
use crate::runner::{PeerAddress, Runner, TransportCommand, TransportError, TransportEvent};

/// Имя сервиса: по нему arti ищет ключ, состояние и конфиг.
///
/// Одно на все аккаунты и это безопасно: у каждого аккаунта свой каталог
/// состояния и свой Tor-клиент, так что совпадение имён их не смешивает.
const NICKNAME: &str = "ratatosk";

/// Идентификатор нашего ctor-хранилища ключей.
const KEYSTORE_ID: &str = "ratatosk-service";

/// Сколько событий помещается в очередь до ядра.
const EVENT_QUEUE: usize = 64;

/// Что нужно транспорту, чтобы подняться.
///
/// Структурой, а не пятью аргументами: три из них — пути, и перепутать
/// их местами легко, а последствие («сервис поднялся с пустым хранилищем»)
/// выглядит как новый адрес без всякой ошибки.
pub struct OnionSetup<'a> {
    /// Состояние Tor-клиента: сторожевые узлы и ключи самого arti.
    pub state_dir: &'a Path,
    /// Кэш директории сети. Терять не жалко.
    pub cache_dir: &'a Path,
    /// Наше хранилище ключей в формате C Tor.
    pub keystore_dir: &'a Path,
    /// Ключ сервиса — для расчёта адреса, а не для передачи arti.
    pub key: &'a OnionKey,
    /// Не проверять права на каталоги.
    ///
    /// **Название нарочно неприятное.** arti через `fs-mistrust` проверяет
    /// не только сам каталог, но и всех его предков: доступный посторонним
    /// путь означает, что ключ сервиса можно подменить. На обычной системе
    /// проверка полезна и выключать её нельзя.
    ///
    /// Android — другой случай: приложение живёт в своём каталоге, чужих
    /// пользователей на устройстве нет, а предки пути принадлежат системе
    /// и устроены не так, как ждёт `fs-mistrust`. Там проверка отвергает
    /// заведомо безопасный путь, и её приходится снимать.
    pub dangerously_trust_filesystem: bool,
}

/// Onion-транспорт: свой Tor-клиент, свой сервис, свои соединения.
pub struct OnionRunner {
    client: Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    /// Пока жив — сервис опубликован. Уронишь — исчезнет из сети.
    _service: Arc<RunningOnionService>,
    links: BTreeMap<[u8; 32], Link>,
    events_tx: mpsc::Sender<TransportEvent>,
    events_rx: mpsc::Receiver<TransportEvent>,
    /// Свой адрес — посчитанный из ключа, а не спрошенный у сети.
    address: String,
}

impl OnionRunner {
    /// Поднимает Tor и публикует сервис.
    ///
    /// **Возвращается только после bootstrap** — это десятки секунд, и звать
    /// её надо из foreground service на Android (§13.1), а не из UI-потока.
    ///
    /// `state_dir` — каталог аккаунта: в нём же лежит ctor-хранилище с нашим
    /// ключом, разложенное `core::accounts::write_onion_keystore`. Ключ сюда
    /// передаётся не для того, чтобы его отдать arti (тот берёт его из
    /// каталога), а чтобы посчитать адрес и не спрашивать его у сети.
    ///
    /// # Errors
    ///
    /// Отказ конфигурации, bootstrap или публикации сервиса.
    pub async fn start(
        setup: OnionSetup<'_>,
        progress: mpsc::Sender<TransportEvent>,
    ) -> Result<OnionRunner, TransportError> {
        install_crypto_provider();

        let nickname = nickname()?;
        let config = client_config(&setup, &nickname)?;

        // Клиент заводится **не** поднятым, и это единственный способ узнать,
        // как идёт подъём: подписаться на новости можно только у готового
        // объекта, а `create_bootstrapped` возвращает его уже после
        // bootstrap — то есть после всего, о чём стоило рассказать.
        //
        // `Arc` здесь не наш, а arti: он заворачивает клиента сам — и в этом
        // конструкторе тоже, не только в `create_bootstrapped`. Приписать
        // свой значило бы завернуть дважды.
        let client: Arc<TorClient<tor_rtcompat::PreferredRuntime>> = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .map_err(|error| failed("клиент не собрался", &error))?;

        // Копия — для одной новости, которую надо суметь сказать после
        // подъёма: подъём мог кончиться и успехом, и обнаружением того,
        // что сервис поднялся не с нашим ключом.
        let progress_note = progress.clone();

        // Подписка — до подъёма, иначе первые новости пройдут мимо.
        // СВЕРИТЬ: имя метода подписки.
        spawn_status_loop(client.bootstrap_events(), progress);

        client.bootstrap().await.map_err(|error| failed("bootstrap не прошёл", &error))?;

        let service_config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|error| failed("конфиг сервиса не собрался", &error))?;

        // `Ok(None)` — «сервис выключен в конфиге». Мы его не выключали,
        // так что это не штатный случай, а рассогласование с arti.
        let (service, rend_requests) = client
            .launch_onion_service(service_config)
            .map_err(|error| failed("сервис не запустился", &error))?
            .ok_or(TransportError::Unavailable)?;

        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        spawn_accept_loop(rend_requests, events_tx.clone());

        // Что мы посчитали из ключа — и что сервис на самом деле обслуживает.
        // Расхождение здесь объясняет всё сразу: карточка везёт один адрес,
        // а в сети живёт другой, и дозвониться нельзя ни в одну сторону.
        let address = setup.key.address();
        if let Some(served) = foreign_address(&service, setup.key) {
            // Отказ, а не работа с чужим адресом. Соблазн объявить рабочий
            // велик — связь бы поехала прямо сейчас, — но адрес сервиса это
            // наша личность в сети (§3, §5.2), и она обязана выводиться
            // из запечатанного зерна. Приняв чужую, мы получили бы адрес,
            // который живёт в каталоге состояния Tor и исчезает вместе с ним,
            // а человек об этом узнал бы в тот день, когда каталог почистит.
            tracing::error!(
                ours = %address,
                %served,
                "arti поднял сервис с чужим ключом: ctor-хранилище не прочитано"
            );
            let _ = progress_note.try_send(TransportEvent::TorProgress {
                fraction: 1.0,
                note: format!("сервис поднялся с чужим ключом: обслуживает {served}"),
                blocked: Some(format!(
                    "ждали {address} — адрес из нашего ключа. Свой ключ arti держит \
                     в каталоге состояния и, найдя его там, до ctor-хранилища \
                     не доходит. Остановите узел, удалите каталог state внутри .tor \
                     и запустите заново"
                )),
            });
            return Err(TransportError::Unavailable);
        }
        // Адрес объявляется **не здесь**, и это исправление ошибки, которая
        // выглядела как «Tor поднялся, а сообщения не ходят».
        //
        // `launch_onion_service` возвращается, когда сервис запущен, — но
        // не когда он **опубликован**: дескриптор ещё надо разослать по
        // HSDir, и это отдельные десятки секунд после конца bootstrap.
        // Объяви мы адрес сразу, контакты получили бы его раньше, чем по нему
        // можно дозвониться, и первые попытки упёрлись бы в пустоту —
        // ровно то, чего §14 не разрешает: обещание, которого нет.
        //
        // Поэтому `TorReady` уходит из наблюдателя за состоянием сервиса,
        // когда тот скажет о себе «работаю».
        spawn_service_status_loop(Arc::clone(&service), address.clone(), events_tx.clone());

        Ok(OnionRunner {
            client,
            _service: service,
            links: BTreeMap::new(),
            events_tx,
            events_rx,
            address,
        })
    }

    /// Onion-адрес этого устройства.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Рассказывает наружу о том, что происходит с onion (§14).
    ///
    /// [`mpsc::Sender::try_send`], а не `send`, и это не мелочь: очередь
    /// вычитывает драйвер, а он в этот момент ждёт нас же внутри
    /// [`Runner::execute`]. Ожидание на полной очереди было бы взаимной
    /// блокировкой на все сорок пять секунд набора.
    ///
    /// Доля 1.0 — потому что bootstrap к этому моменту позади: новость
    /// не о подъёме, а о звонке.
    fn note(&self, note: String, blocked: Option<String>) {
        // И в журнал тоже — потому что в очередь новость ложится сейчас,
        // а вычитают её после того, как `execute` вернётся, то есть в худшем
        // случае через сорок пять секунд. Журнал печатается сразу, и «набираем
        // …» видно в тот момент, когда набор идёт, а не когда он кончился.
        tracing::info!(blocked = ?blocked, "onion: {note}");
        let _ =
            self.events_tx.try_send(TransportEvent::TorProgress { fraction: 1.0, note, blocked });
    }

    /// Соединение с контактом — существующее или новое.
    async fn ensure_link(&mut self, peer: &PeerAddress) -> Result<Link, TransportError> {
        if let Some(link) = self.links.get(&peer.ik) {
            if !link.is_closed() {
                return Ok(link.clone());
            }
            self.links.remove(&peer.ik);
        }

        let Some(address) = peer.onion.as_deref() else {
            // Не молча. «Сообщения не ходят» и «мы даже не набирали, потому
            // что номера нет» — разные неисправности, и чинят их в разных
            // местах: вторую — обменом карточками (§4.3), а не Tor.
            self.note(format!("{}: onion-адреса в карточке нет", short(&peer.ik)), None);
            return Err(TransportError::NoAddress);
        };

        // Про каждый набор — вслух. Без этой строки снаружи не отличить
        // «§5.4 до onion не дошёл» от «дошёл и не дозвонился», а это первый
        // вопрос при разборе любого «не ходит».
        self.note(format!("набираем {address}"), None);

        // §5.4 отводит onion 45 секунд и после этого переходит к почте.
        // Ждать дольше нельзя не из нетерпения: пока мы ждём, человек видит
        // «отправляется», а сообщение могло бы уже уехать следующей ступенью.
        let deadline = Duration::from_millis(ONION_CONNECT_TIMEOUT_MS);
        let stream = match tokio::time::timeout(
            deadline,
            self.client.connect((address, SERVICE_PORT)),
        )
        .await
        {
            Err(_) => {
                self.note(
                    format!("{address}: молчит {} с", ONION_CONNECT_TIMEOUT_MS / 1_000),
                    Some("дескриптор не найден или сервис недоступен".to_owned()),
                );
                return Err(TransportError::Timeout);
            }
            Ok(Err(error)) => {
                // Текст ошибки — наружу, а не только в журнал. У arti он
                // внятный («onion service descriptor not found», «stream
                // refused»), и по нему сразу видно, чья это беда.
                self.note(format!("{address}: не дозвонились"), Some(format!("{error}")));
                return Err(failed("соединение не установилось", &error));
            }
            Ok(Ok(stream)) => stream,
        };
        self.note(format!("{address}: соединение установлено"), None);

        let link = Link::open(stream, peer.ik, Transport::Onion, self.events_tx.clone());
        self.links.insert(peer.ik, link.clone());
        let _ = self
            .events_tx
            .send(TransportEvent::Connected { peer_ik: peer.ik, via: Transport::Onion })
            .await;
        Ok(link)
    }
}

impl Runner for OnionRunner {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            TransportCommand::Send { peer, via: Transport::Onion, frame } => {
                let link = self.ensure_link(&peer).await?;
                link.send(frame).await
            }
            TransportCommand::Connect { peer, via: Transport::Onion } => {
                self.ensure_link(&peer).await.map(|_| ())
            }
            // Разъединение приходит без `via` — всем транспортам сразу.
            // Забыть соединение здесь достаточно: пишущая задача уходит
            // вместе с последней полосой, а `DataStream` закрывается сам.
            TransportCommand::Disconnect { peer } => {
                self.links.remove(&peer.ik);
                Ok(())
            }
            // Всё остальное — не наше: LAN-настройки, чужие транспорты.
            _ => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        self.events_rx.recv().await
    }
}

/// Ждёт, пока сервис объявит себя работающим, и только тогда — [`TransportEvent::TorReady`].
///
/// Разница между «запущен» и «опубликован» — та самая, из-за которой
/// сообщения не ходят при поднятом на 100 % Tor: дескриптор сервиса
/// расходится по HSDir уже после конца bootstrap, и до этого момента
/// дозвониться по адресу нельзя.
///
/// Состояния пересказываются наружу как новости подъёма — человеку полезно
/// видеть, что после «100 %» дело ещё идёт.
///
/// СВЕРИТЬ: `status_events`, `state()` и имя состояния `Running`.
fn spawn_service_status_loop(
    service: Arc<RunningOnionService>,
    address: String,
    events: mpsc::Sender<TransportEvent>,
) {
    tokio::spawn(async move {
        let mut announced = false;
        // Прошлая строка — чтобы не повторять одну и ту же новость.
        //
        // Поток состояний отдаёт **текущее** состояние первым, а потом
        // каждое изменение отчёта — а меняться в нём может и то, о чём мы
        // не рассказываем (число точек встречи, например). Отсюда и брались
        // два «сервис опубликован» подряд: сервис один, событий два.
        // Сравнивается готовая строка, а не состояние: строка — ровно то,
        // что увидит человек, и повтор определяется по ней честнее.
        let mut said: Option<String> = None;
        let mut stream = service.status_events();
        while let Some(status) = stream.next().await {
            let state = status.state();
            let running = matches!(state, tor_hsservice::status::State::Running);

            let note = if running {
                format!("сервис опубликован: {address}")
            } else {
                format!("сервис: {state:?}")
            };
            if said.as_deref() != Some(note.as_str()) {
                said = Some(note.clone());
                let _ = events.try_send(TransportEvent::TorProgress {
                    fraction: 1.0,
                    note,
                    blocked: None,
                });
            }

            // Один раз: повторное объявление того же адреса ядро отбросит
            // само (§4.3), но гонять его по кругу незачем.
            if running && !announced {
                announced = true;
                if events.send(TransportEvent::TorReady { onion: address.clone() }).await.is_err() {
                    return;
                }
            }
        }
    });
}

/// Пересказывает новости о подъёме Tor в события транспорта.
///
/// Смысл ровно один: снаружи «поднимается долго» и «не поднимется никогда»
/// неотличимы, а разница между ними для человека — вся. arti сам знает,
/// на чём стоит (`blocked`), и молчать об этом §14 не разрешает.
///
/// Отправка — [`mpsc::Sender::try_send`], и переполнение очереди отбрасывает
/// новость молча. Так и надо: новости — это состояние, а не история.
/// Отстал читатель — важна последняя строка, а не все пропущенные, и уж точно
/// не стоит задерживать из-за них bootstrap.
fn spawn_status_loop<S>(mut events: S, progress: mpsc::Sender<TransportEvent>)
where
    S: futures::Stream<Item = arti_client::status::BootstrapStatus> + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        while let Some(status) = events.next().await {
            // СВЕРИТЬ: `as_frac`, `blocked` и `Display` у статуса.
            let event = TransportEvent::TorProgress {
                fraction: status.as_frac(),
                note: status.to_string(),
                blocked: status.blocked().map(|reason| reason.to_string()),
            };
            if progress.try_send(event).is_err() {
                tracing::debug!("очередь новостей о Tor переполнена, новость отброшена");
            }
        }
    });
}

/// Называет криптопровайдера rustls — один раз на процесс.
///
/// rustls 0.23 отказывается выбирать сам, если в дереве оказались оба
/// провайдера (`ring` и `aws-lc-rs`), а у arti в зависимостях именно так.
/// «Отказывается» здесь означает панику в момент первого TLS-рукопожатия,
/// то есть посреди bootstrap, — поэтому провайдер называется до всего
/// остального, а не когда-нибудь потом.
///
/// Выбран `ring`: `aws-lc-rs` тянет сборку C и cmake, а это ровно та возня
/// с кросс-компиляцией под Android (§13.1), от которой мы отказались ещё
/// на выборе rustls вместо native-tls.
///
/// Отказ установки игнорируется намеренно: он означает, что провайдера уже
/// назвало само приложение. Спорить с ним — не наше дело; наше дело —
/// чтобы провайдер был.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Конфиг клиента: пути состояния и наше хранилище ключей.
fn client_config(
    setup: &OnionSetup<'_>,
    nickname: &HsNickname,
) -> Result<TorClientConfig, TransportError> {
    // Пути состояния и кэша задаёт этот конструктор целиком; он же выводит
    // из `state_dir` путь к собственному хранилищу ключей arti. Нам оно
    // не нужно, но пусть лежит внутри каталога аккаунта, а не там, где arti
    // выберет сам.
    let mut builder = TorClientConfigBuilder::from_directories(setup.state_dir, setup.cache_dir);

    // Проверка прав снимается только там, где она отвергает заведомо
    // безопасный путь, — и это всегда Android (см. `OnionSetup`).
    // СВЕРИТЬ: путь до настроек проверки прав.
    if setup.dangerously_trust_filesystem {
        builder.storage().permissions().dangerously_trust_everyone();
    }

    // Смысл этих строк: arti читает **чужое** хранилище только в формате
    // C Tor и только по объявленному пути. Своё он заполняет сам, и снаружи
    // в него ключ не положить — поэтому наш ключ живёт здесь.
    //
    // Признак `arti-client/ctor-keystore` обязателен: без него arti собран
    // без поддержки таких хранилищ и отвергает конфиг на этапе сборки
    // настроек — `NoCompileTimeSupport`. Ошибка при этом внятная, но
    // приходит в работе, а не при компиляции, поэтому связь признака
    // с этими строками записана здесь.
    let mut service = tor_keymgr::config::CTorServiceKeystoreConfig::builder();
    service.id(keystore_id()?).path(setup.keystore_dir.to_path_buf()).nickname(nickname.clone());
    builder.storage().keystore().ctor_service(service);

    builder.build().map_err(|error| failed("конфиг клиента не собрался", &error))
}

/// Имя сервиса.
fn nickname() -> Result<HsNickname, TransportError> {
    // СВЕРИТЬ: конструктор имени.
    HsNickname::new(NICKNAME.to_owned()).map_err(|error| failed("имя сервиса не принято", &error))
}

/// Идентификатор хранилища.
fn keystore_id() -> Result<KeystoreId, TransportError> {
    // Разбором строки, а не `TryFrom`: у `KeystoreId` есть правила на состав
    // имени, и проверяет их он сам.
    KEYSTORE_ID
        .parse::<KeystoreId>()
        .map_err(|error| failed("идентификатор хранилища не принят", &error))
}

/// Принимает входящие потоки и отдаёт их кадры ядру.
///
/// Два правила приёма — не наша осторожность, а требование совместимости:
/// документация arti прямо предупреждает, что сервис, принимающий не только
/// `BEGIN` и не только на один порт, **отличим** от прочих onion-сервисов.
/// Это ровно §14 чужими словами: не выделяться там, где выделяться нечем.
fn spawn_accept_loop<S>(rend_requests: S, events: mpsc::Sender<TransportEvent>)
where
    S: futures::Stream<Item = tor_hsservice::RendRequest> + Send + 'static,
{
    tokio::spawn(async move {
        let mut streams = Box::pin(handle_rend_requests(rend_requests));
        while let Some(request) = streams.next().await {
            if !wants_our_port(&request) {
                // Отказ, а не разрыв цепочки: разрыв — заметное поведение,
                // а `END` с обычной причиной выглядит как у всех.
                //
                // СВЕРИТЬ: конструктор `End`.
                let end = tor_cell::relaycell::msg::End::new_with_reason(
                    tor_cell::relaycell::msg::EndReason::DONE,
                );
                let _ = request.reject(end).await;
                continue;
            }

            // СВЕРИТЬ: конструктор `Connected`.
            let connected = tor_cell::relaycell::msg::Connected::new_empty();
            match request.accept(connected).await {
                Ok(stream) => spawn_read_loop(stream, Transport::Onion, events.clone()),
                Err(error) => {
                    tracing::debug!(?error, "входящий поток не принят");
                }
            }
        }
    });
}

/// На наш ли порт этот поток.
///
/// СВЕРИТЬ: форма запроса. Ошибка здесь означает, что мы либо принимаем
/// лишнее, либо не принимаем ничего, и второе заметно сразу.
fn wants_our_port(request: &tor_hsservice::StreamRequest) -> bool {
    // Тип запроса живёт в `tor-proto`, а не в `tor-cell`: это уже разобранное
    // сообщение потока, а не сырая ячейка релейного уровня.
    use tor_proto::stream::IncomingStreamRequest;

    match request.request() {
        IncomingStreamRequest::Begin(begin) => begin.port() == SERVICE_PORT,
        // Всё остальное (`RESOLVE`, `CONNECT_UDP`) сервису мессенджера
        // не адресовано ни при каких обстоятельствах.
        _ => false,
    }
}

/// Тот ли ключ взял arti.
///
/// `None` — наш (или сервис адреса не назвал, и остаётся верить арифметике).
/// `Some(адрес)` — сервис обслуживает **чужой** адрес, и вот какой.
///
/// Строка считается нами, а не берётся у arti: у `HsId` нет `Display`, и это
/// не упущение — адрес сервиса штука чувствительная, и в журнал он попадает
/// только осознанно. Но `HsId` — это те же тридцать два байта ed25519-ключа,
/// из которых адрес выводится арифметикой rend-spec-v3, а она у нас есть
/// и покрыта настоящим адресом из сети.
///
/// СВЕРИТЬ (две строки ниже): `RunningOnionService::onion_address` и то, как
/// из `HsId` достаются байты. Если `From<HsId> for [u8; 32]` не окажется —
/// у макроса `define_bytes!` есть и `AsRef<[u8; 32]>`, тогда `*published.as_ref()`.
fn foreign_address(service: &RunningOnionService, key: &OnionKey) -> Option<String> {
    let published = service.onion_address()?;
    let bytes: [u8; 32] = published.into();
    if bytes == key.public() {
        return None;
    }
    Some(ratatosk_crypto::onion::address_of(&bytes))
}

/// Короткий вид ключа — для строк, которые читает человек.
fn short(ik: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(&ik[..6])
}

/// Превращает ошибку arti в нашу, оставляя подробность в журнале.
///
/// Наружу уходит `Unavailable` и только он: §5.4 интересует один вопрос —
/// сработала ступень или нет, — а подробности отказа Tor человеку показать
/// всё равно нечем. В `debug` они при этом остаются целиком.
fn failed(what: &str, error: &dyn std::fmt::Debug) -> TransportError {
    tracing::debug!(?error, "{what}");
    TransportError::Unavailable
}
