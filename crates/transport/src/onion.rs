//! Tor onion-to-onion (§5.2).
//!
//! Каждое устройство поднимает onion-сервис v3 через встроенный arti. Это
//! одновременно решает три задачи:
//!
//! * NAT-traversal — у onion-адреса нет NAT, hole punching не нужен,
//!   STUN/TURN не нужны (и потому вынесены в §15 как «не нужны», а не
//!   «отложены»);
//! * стабильную адресацию при смене сети — адрес не зависит от IP;
//! * сокрытие IP обеих сторон.
//!
//! Цена, которую §5.2 называет прямо: 300–800 мс односторонней задержки,
//! единицы секунд на установление, десятки мегабайт памяти на Tor-клиент.

/// Ожидаемая односторонняя задержка, нижняя граница (§5.2).
pub const EXPECTED_LATENCY_MIN_MS: u64 = 300;
/// Ожидаемая односторонняя задержка, верхняя граница (§5.2).
pub const EXPECTED_LATENCY_MAX_MS: u64 = 800;

/// Onion-сервис устройства.
///
/// TODO(этап 2): поднять `arti_client::TorClient`, опубликовать onion-сервис
/// v3 на `onion_key` из §3, принимать входящие потоки и отдавать кадры
/// в ядро событием [`crate::TransportEvent::Received`].
pub struct OnionService {
    _private: (),
}

impl OnionService {
    /// Запускает arti и публикует сервис.
    ///
    /// Bootstrap выполняется при старте foreground service на Android (§13.1);
    /// до его завершения исходящие кадры остаются в очереди, а не теряются.
    pub async fn start(_onion_key: &[u8; 32]) -> Result<OnionService, crate::TransportError> {
        todo!("этап 2: arti + onion-сервис v3 (§5.2)")
    }

    /// Onion-адрес этого устройства.
    pub fn address(&self) -> &str {
        todo!("этап 2: адрес опубликованного сервиса")
    }

    /// SOCKS-прокси arti — через него ходит и почтовый транспорт (§5.3).
    pub fn socks_addr(&self) -> std::net::SocketAddr {
        todo!("этап 2: адрес SOCKS-прокси для chatmail")
    }
}
