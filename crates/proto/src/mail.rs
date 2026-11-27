//! Настройки почтового ящика chatmail (§5.3) — и одно отступление от неё.
//!
//! Почта в §5.3 названа «chatmail **поверх Tor**», и по умолчанию так и есть.
//! Но у транспорта есть работа, которой у onion не бывает: там, где Tor
//! заблокирован, а обычная сеть работает, почта остаётся единственным путём
//! до собеседника. Поэтому у ящика есть переключатель [`MailAccount::via_tor`],
//! и цена его выключения названа прямо — см. ниже.
//!
//! # Что видит сервер
//!
//! Содержимого он не видит никогда: тело письма — наши же запечатанные кадры
//! (§5.3), и второго криптостека в системе нет. Но он видит, **какие адреса
//! переписываются между собой, когда и какого размера** письма. Это цена
//! асинхронной доставки без своей инфраструктуры, и она не зависит от Tor.
//!
//! Tor убирает из этого списка ровно одно: **IP отправителя**. Выключив его,
//! человек говорит серверу, откуда он выходит в сеть, — а вместе с адресом
//! ящика это уже привязка переписки к линии связи. Сказать об этом надо
//! до того, как он нажмёт переключатель, а не после (§14).
//!
//! # Чего здесь нет
//!
//! Пароль не затирается в памяти. Защищает его зашифрованная база (§8.6),
//! а не тип: `Zeroizing` над `String` дал бы затирание одного буфера, но
//! не тех копий, которые `String` оставляет за собой при каждом росте.
//! Обещать больше, чем сделано, — не по §14.
//!
//! Зато он не попадает в журнал: см. [`Secret`].

use core::fmt;

use ratatosk_codec::{canonical, CodecError, Value};

/// Порт IMAP поверх TLS.
///
/// Именно implicit TLS, а не STARTTLS: соединение шифруется с первого байта,
/// и понижения до открытого канала в нём не бывает.
pub const DEFAULT_IMAP_PORT: u16 = 993;

/// Порт SMTP поверх TLS (submission over implicit TLS).
pub const DEFAULT_SMTP_PORT: u16 = 465;

/// Предел длины любого поля настроек.
///
/// Не про безопасность, а про то, что настройки лежат в служебной таблице
/// и приезжают эффектом: строка на мегабайт здесь — ошибка ввода, а не
/// экзотический сервер.
pub const MAX_FIELD_LEN: usize = 255;

const KEY_ADDRESS: u64 = 1;
const KEY_PASSWORD: u64 = 2;
const KEY_IMAP_HOST: u64 = 3;
const KEY_IMAP_PORT: u64 = 4;
const KEY_SMTP_HOST: u64 = 5;
const KEY_SMTP_PORT: u64 = 6;
const KEY_VIA_TOR: u64 = 7;

/// Почему настройки нельзя принять.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailAccountError {
    /// Адрес не похож на почтовый: нет `@`, пустая часть, лишний `@`.
    #[error("адрес ящика не похож на почтовый")]
    BadAddress,
    /// Пустое имя сервера.
    #[error("имя сервера пустое")]
    BadHost,
    /// Порт ноль — соединяться некуда.
    #[error("порт не может быть нулём")]
    BadPort,
    /// Пустой пароль.
    ///
    /// Отдельной ошибкой, а не «пусть сервер откажет»: молчаливый отказ входа
    /// человек читает как «почта не работает», и чинить будет не то.
    #[error("пароль пустой")]
    BadPassword,
    /// Поле длиннее [`MAX_FIELD_LEN`].
    #[error("поле слишком длинное")]
    TooLong,
}

/// Строка, которую нельзя печатать.
///
/// Тип, а не соглашение, и разница существенная. Пароль едет до транспорта
/// эффектом и приезжает от него входом, а эффекты и входы драйвер пишет
/// в журнал целиком — производный `Debug` где-нибудь по дороге вынес бы
/// его в открытый лог на устройстве. Уследить за этим глазами нельзя:
/// достаточно одного нового места, где структуру напечатали.
///
/// Затирания памяти тип не обещает и обещать не может: `String` при каждом
/// росте оставляет за собой копию, а `Zeroizing` затёр бы только последнюю.
/// Защищает пароль зашифрованная база (§8.6), а не этот тип; здесь только
/// про журнал.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(String);

impl Secret {
    /// Заворачивает строку.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }

    /// Отдаёт содержимое тому, кому оно действительно нужно.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Пуст ли секрет.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Длина в байтах — для проверки пределов, не для показа.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<скрыт>")
    }
}

/// Настройки почтового ящика.
///
/// Заводит их человек — либо вводя данные существующей почты, либо давая
/// ссылку на chatmail-сервер, который заведёт новый ящик (§5.3). Структура
/// от этого не меняется: она отвечает на вопрос «куда и чем входить»,
/// а не «откуда взялся ящик».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccount {
    /// Адрес вида `a7f3k9@nine.example`. Он же логин: chatmail-серверы
    /// других логинов не знают.
    pub address: String,
    /// Пароль. В журнал не попадает — см. [`Secret`].
    pub password: Secret,
    /// Имя IMAP-сервера.
    pub imap_host: String,
    /// Порт IMAP.
    pub imap_port: u16,
    /// Имя SMTP-сервера.
    pub smtp_host: String,
    /// Порт SMTP.
    pub smtp_port: u16,
    /// Ходить ли до сервера через Tor.
    ///
    /// По умолчанию да (§5.3). Выключается там, где Tor недоступен, — и это
    /// осознанный размен, а не настройка производительности: сервер начинает
    /// видеть IP. Цена описана в шапке модуля, и клиент обязан назвать её
    /// человеку до переключения.
    pub via_tor: bool,
}

impl MailAccount {
    /// Настройки по адресу и паролю, с именами серверов из домена.
    ///
    /// Chatmail-серверы обслуживают IMAP и SMTP на самом домене адреса
    /// и на стандартных портах — из этого и исходим. Человеку, у которого
    /// сервер устроен иначе, остаются поля: угадывание здесь избавляет
    /// от ввода четырёх строк, а не заменяет их.
    ///
    /// Проверок не делает — их делает [`MailAccount::check`], и делает их
    /// тот, кто настройки принимает.
    #[must_use]
    pub fn from_address(address: &str, password: &str) -> MailAccount {
        let domain = address.rsplit('@').next().unwrap_or_default().to_owned();
        MailAccount {
            address: address.to_owned(),
            password: Secret::new(password),
            imap_host: domain.clone(),
            imap_port: DEFAULT_IMAP_PORT,
            smtp_host: domain,
            smtp_port: DEFAULT_SMTP_PORT,
            via_tor: true,
        }
    }

    /// Проверяет настройки на то, что видно без сети.
    ///
    /// Сеть скажет остальное, но скажет не сразу и невнятно: неверный адрес
    /// на chatmail-сервере выглядит как отказ входа, а отказ входа человек
    /// читает как «почта не работает». Что можно поймать здесь — ловим здесь.
    ///
    /// # Errors
    ///
    /// [`MailAccountError`] — какое именно поле не годится.
    pub fn check(&self) -> Result<(), MailAccountError> {
        let fields =
            [self.address.len(), self.password.len(), self.imap_host.len(), self.smtp_host.len()];
        if fields.iter().any(|len| *len > MAX_FIELD_LEN) {
            return Err(MailAccountError::TooLong);
        }
        // Адрес — первым, и порядок здесь не вкусовщина. Имена серверов
        // по умолчанию выводятся **из адреса** ([`MailAccount::from_address`]),
        // поэтому «a7f3k9@» без домена даёт пустой сервер, и проверь мы
        // сервер раньше, человек получил бы «имя сервера пустое» на поле,
        // которого он не трогал. Ошибка должна показывать на то, что он ввёл.
        check_address(&self.address)?;
        if self.password.is_empty() {
            return Err(MailAccountError::BadPassword);
        }
        if self.imap_host.is_empty() || self.smtp_host.is_empty() {
            return Err(MailAccountError::BadHost);
        }
        if self.imap_port == 0 || self.smtp_port == 0 {
            return Err(MailAccountError::BadPort);
        }
        Ok(())
    }

    /// Кодирует настройки для служебной таблицы.
    ///
    /// # Errors
    ///
    /// [`CodecError`] при отказе кодирования.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let map = vec![
            (Value::Integer(KEY_ADDRESS.into()), Value::Text(self.address.clone())),
            (Value::Integer(KEY_PASSWORD.into()), Value::Text(self.password.as_str().to_owned())),
            (Value::Integer(KEY_IMAP_HOST.into()), Value::Text(self.imap_host.clone())),
            (
                Value::Integer(KEY_IMAP_PORT.into()),
                Value::Integer(u64::from(self.imap_port).into()),
            ),
            (Value::Integer(KEY_SMTP_HOST.into()), Value::Text(self.smtp_host.clone())),
            (
                Value::Integer(KEY_SMTP_PORT.into()),
                Value::Integer(u64::from(self.smtp_port).into()),
            ),
            (Value::Integer(KEY_VIA_TOR.into()), Value::Bool(self.via_tor)),
        ];
        canonical::encode(&Value::Map(map))
    }

    /// Разбирает настройки из служебной таблицы.
    ///
    /// # Errors
    ///
    /// [`CodecError`] на испорченной или неполной записи.
    pub fn decode(bytes: &[u8]) -> Result<MailAccount, CodecError> {
        let value = canonical::decode(bytes)?;
        let map = canonical::as_map(&value)?;
        let port = |key: u64| -> Result<u16, CodecError> {
            u16::try_from(canonical::as_u64(canonical::require(map, key)?)?)
                .map_err(|_| CodecError::TypeMismatch)
        };
        let Value::Bool(via_tor) = canonical::require(map, KEY_VIA_TOR)? else {
            return Err(CodecError::TypeMismatch);
        };
        Ok(MailAccount {
            address: canonical::as_text(canonical::require(map, KEY_ADDRESS)?)?.to_owned(),
            password: Secret::new(canonical::as_text(canonical::require(map, KEY_PASSWORD)?)?),
            imap_host: canonical::as_text(canonical::require(map, KEY_IMAP_HOST)?)?.to_owned(),
            imap_port: port(KEY_IMAP_PORT)?,
            smtp_host: canonical::as_text(canonical::require(map, KEY_SMTP_HOST)?)?.to_owned(),
            smtp_port: port(KEY_SMTP_PORT)?,
            via_tor: *via_tor,
        })
    }
}

/// Разобранная ссылка на регистрацию нового ящика (§5.3).
///
/// Ссылка вида `https://chatmail.example/new`: сервер отвечает готовыми
/// адресом и паролем, персональных данных не спрашивая. Такие же ссылки
/// в ходу у Delta Chat, и это не совпадение — chatmail-серверы общие.
///
/// Разбирается здесь, а не в транспорте, по двум причинам. Отказать надо
/// **до** того, как человек нажал и стал ждать сети. И «только `https`» —
/// решение протокольного уровня, а не сетевого: по `http` пароль приехал бы
/// открытым текстом любому на пути, а этот пароль открывает переписку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountUrl {
    /// Имя сервера.
    pub host: String,
    /// Порт. `443`, если в ссылке не указан.
    pub port: u16,
    /// Путь вместе с ведущей косой чертой, например `/new`.
    pub path: String,
}

/// Почему ссылка на регистрацию не годится.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AccountUrlError {
    /// Ссылка не начинается с `https://`.
    #[error("ссылка обязана быть https")]
    NotHttps,
    /// Имя сервера пустое или с пробелами.
    #[error("в ссылке нет имени сервера")]
    BadHost,
    /// Порт не число или ноль.
    #[error("порт в ссылке не годится")]
    BadPort,
    /// Ссылка длиннее [`MAX_FIELD_LEN`].
    #[error("ссылка слишком длинная")]
    TooLong,
}

impl AccountUrl {
    /// Разбирает ссылку.
    ///
    /// Разбор нарочно свой и грубый: полный URL нам не нужен, а тянуть
    /// разборщик ссылок ради трёх полей — лишняя зависимость в дереве,
    /// где каждая объяснена (§8.1). Ни пользователя, ни пароля, ни запроса
    /// в такой ссылке не бывает, и принимать их мы не станем: `https://`,
    /// имя, необязательный порт, путь.
    ///
    /// # Errors
    ///
    /// [`AccountUrlError`] — что именно не так со ссылкой.
    pub fn parse(url: &str) -> Result<AccountUrl, AccountUrlError> {
        if url.len() > MAX_FIELD_LEN {
            return Err(AccountUrlError::TooLong);
        }
        let rest = url.strip_prefix("https://").ok_or(AccountUrlError::NotHttps)?;
        let (authority, path) = match rest.find('/') {
            Some(cut) => (&rest[..cut], rest[cut..].to_owned()),
            // Пути нет — значит корень. Отказывать не за что: сервер вправе
            // обслуживать регистрацию где угодно, включая `/`.
            None => (rest, "/".to_owned()),
        };
        // Ни `@`, ни `?`, ни `#`: имя с пользователем внутри — известный
        // способ показать человеку одно имя, а сходить на другое.
        let suspicious = authority.is_empty()
            || authority.contains('@')
            || url.contains('?')
            || url.contains('#')
            || url.chars().any(char::is_whitespace);
        if suspicious {
            return Err(AccountUrlError::BadHost);
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port.parse().map_err(|_| AccountUrlError::BadPort)?;
                if port == 0 {
                    return Err(AccountUrlError::BadPort);
                }
                (host, port)
            }
            None => (authority, 443),
        };
        if host.is_empty() || !host.contains('.') {
            return Err(AccountUrlError::BadHost);
        }
        Ok(AccountUrl { host: host.to_owned(), port, path })
    }
}

/// Что почтовый сервер сказал о своих пределах (§5.3).
///
/// Два числа из двух разных разговоров, и оба — **про свой сервер**, а не про
/// сервер собеседника. Его пределы невидимы, и это не недоработка: письмо
/// уходит нашему серверу, а дальше идёт релеем, о котором мы не знаем ничего.
///
/// # Зачем это ядру
///
/// Не для показа — для двух решений.
///
/// Первое: **поедет ли файл почтой**. Чанк едет кадром класса L, кадр
/// становится письмом на полтора мебибайта ([`files::letter_bytes`]). Сервер,
/// объявивший `SIZE` меньше этого, отвергнет каждый чанк, и передача будет
/// вечно начинаться заново. Честнее не начинать (§14).
///
/// Второе: **просить ли чанки почтой, когда свой ящик кончается**. Открытое
/// окно занимает [`files::mail_window_bytes`] чужого ящика — и столько же
/// нашего, когда принимаем мы. Ящика меньше, чем на окно, означает, что часть
/// писем сервер не примет, а отправитель узнает об этом отказом, которого
/// не поймёт.
///
/// [`files::letter_bytes`]: crate::files::letter_bytes
/// [`files::mail_window_bytes`]: crate::files::mail_window_bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MailLimits {
    /// Предел одного письма из `SIZE` в ответе на `EHLO` (RFC 1870).
    ///
    /// `None` — сервер не объявил, и это законно: RFC разрешает и голое
    /// `SIZE` без числа, что означает «предела не называю». Неизвестный
    /// предел трактуется как «подойдёт», а не как «ноль»: иначе почта
    /// перестала бы возить файлы на всяком сервере, который о себе молчит.
    pub letter_bytes: Option<u64>,
    /// Сколько байт занято в ящике (IMAP `QUOTA`, RFC 2087).
    pub mailbox_used: Option<u64>,
    /// Весь объём ящика в байтах.
    ///
    /// `None` — сервер не умеет `QUOTA` или не объявил её для `INBOX`.
    /// Ноль в самом протоколе означает «без предела», и до этого поля
    /// он не доходит: превращается в `None` при разборе.
    pub mailbox_limit: Option<u64>,
}

impl MailLimits {
    /// Поместится ли письмо такой длины в предел сервера.
    ///
    /// Неизвестный предел — «поместится». Обратное решение сделало бы
    /// молчаливый сервер хуже скупого.
    #[must_use]
    pub const fn letter_fits(&self, bytes: u64) -> bool {
        match self.letter_bytes {
            Some(limit) => bytes <= limit,
            None => true,
        }
    }

    /// Сколько в ящике осталось места.
    ///
    /// `None`, если объём неизвестен, — и это **не** «ноль»: у ящика без
    /// объявленной квоты места столько, сколько даст сервер.
    #[must_use]
    pub const fn free_bytes(&self) -> Option<u64> {
        match (self.mailbox_limit, self.mailbox_used) {
            (Some(limit), Some(used)) => Some(limit.saturating_sub(used)),
            _ => None,
        }
    }

    /// Осталось ли места меньше, чем на одно окно почтовой передачи.
    ///
    /// Порог именно такой, а не «девяносто процентов»: важно не то, сколько
    /// процентов занято, а поместится ли то, что мы собираемся попросить.
    /// Ящик на гигабайт, занятый на 95 %, для окна просторен; ящик на
    /// двадцать мегабайт, занятый наполовину, — нет.
    #[must_use]
    pub fn crowded(&self) -> bool {
        self.free_bytes().is_some_and(|free| free < crate::files::mail_window_bytes())
    }

    /// Влезет ли в предел сервера письмо с чанком файла.
    ///
    /// Отдельным методом, а не сравнением на месте: спрашивают об этом
    /// ядро (пускать ли почту в выбор канала) и стенд (что показать
    /// человеку), и ответ обязан совпасть.
    #[must_use]
    pub const fn carries_file_chunks(&self) -> bool {
        self.letter_fits(crate::files::letter_bytes(ratatosk_wire::SizeClass::L.frame_len()) as u64)
    }
}

/// Похож ли адрес на почтовый.
///
/// Проверка нарочно грубая: ровно один `@`, обе части непусты, пробелов нет.
/// Разбирать RFC 5322 здесь не нужно и вредно — отвергнутый по букве стандарта
/// рабочий адрес хуже, чем принятый и не подошедший: второе скажет сервер,
/// первое человек будет чинить вслепую.
fn check_address(address: &str) -> Result<(), MailAccountError> {
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(MailAccountError::BadAddress);
    };
    let bad = local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || address.chars().any(char::is_whitespace);
    if bad {
        return Err(MailAccountError::BadAddress);
    }
    Ok(())
}

// --- Публичный перечень chatmail-серверов ------------------------------------

/// Кого спрашиваем, какие chatmail-серверы бывают.
///
/// Страница, которую ведут авторы chatmail. Адрес источника в сборке есть —
/// и это выбор, который сделали мы, а не человек; поэтому о нём сказано
/// текстом (`ratatosk_core::honest::MAIL_SERVER_SOURCE_NOTICE`, §14).
/// **Серверов в сборке нет**: сервер видит адрес ящика и то, с кем и когда
/// он переписывается, и выбирать его за человека нельзя — как пира меша
/// и реле nostr.
pub const MAIL_SERVER_LIST_HOST: &str = "chatmail.at";

/// Путь перечня у источника.
pub const MAIL_SERVER_LIST_PATH: &str = "/relays";

/// Сколько серверов берём из ответа, не больше.
///
/// Перечень короткий (десятки), и предел здесь не про него: страница чужая,
/// и разбирать из неё тысячу ссылок, окажись они там, незачем.
pub const MAX_LIST_SERVERS: usize = 64;

/// Предел пояснения к серверу, символов.
pub const MAX_SERVER_NOTE: usize = 200;

/// Сервер из публичного перечня.
///
/// **Это ещё не настройка.** Ящик заводится отдельным вызовом, по ссылке
/// [`MailServer::account_url`], и только когда человек выбрал сервер сам.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailServer {
    /// Имя сервера: `nine.testrun.org`.
    pub host: String,
    /// Что о сервере сказано в перечне — словами его составителей, как есть:
    /// где стоит, на кого рассчитан. Бывает пустым. Не проверено никем.
    pub note: String,
}

impl MailServer {
    /// Ссылка, по которой этот сервер заводит новый ящик (§5.3).
    ///
    /// `/new` — общее место chatmail-серверов; этой же ссылкой заводит
    /// ящик Delta Chat. Сервер, который по ней не отвечает, скажет об этом
    /// отказом регистрации, а не тишиной.
    #[must_use]
    pub fn account_url(&self) -> String {
        format!("https://{}/new", self.host)
    }
}

/// Почему не приехал перечень chatmail-серверов.
///
/// Перечислением, как у списка пиров меша и у реле: каждая причина —
/// **своё действие человека**. Текст к причине живёт в ядре
/// (`ratatosk_core::honest::mail_server_list_refusal_text`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MailServerListError {
    /// Почтовой ступени в этой сборке нет, и сервер ей не нужен.
    #[error("в этой сборке нет почтовой ступени")]
    NotInThisBuild,
    /// Источник не ответил или ответил не тем. Делать: повторить позже
    /// или назвать сервер самому.
    #[error("источник перечня не ответил")]
    SourceSilent,
    /// Ответ пришёл, а серверов в нём нет: разметка страницы могла
    /// измениться. Делать: назвать сервер самому и сообщить нам.
    #[error("в ответе нет ни одного сервера")]
    FormatChanged,
}

/// Достаёт серверы из страницы перечня.
///
/// Страница — обычный HTML: пункт списка, в нём ссылка на сервер и строка
/// пояснения. Разбор нарочно свой и грубый, как у ссылки на регистрацию:
/// разборщик HTML ради двух десятков ссылок — лишняя зависимость в дереве,
/// где каждая объяснена (§8.1).
///
/// # Что считается сервером
///
/// Ссылка `https://имя/` **внутри пункта списка**, ведущая в корень сайта.
/// Этого хватает, чтобы не принять за сервер ссылку на документацию
/// (`https://chatmail.at/doc/relay` — и не в пункте, и с путём) и меню
/// сайта (там ссылки без имени сервера). Сам источник сервером не считается.
///
/// Имя проверяется строго — строчные латинские буквы, цифры, точка, дефис,
/// хотя бы одна точка: оно уедет в ссылку регистрации, и чужая строка в ней
/// означала бы запрос, которого мы не писали.
///
/// В пункте бывает два сервера сразу (два имени одного оператора) — оба
/// берутся, пояснение у них общее. Порядок страницы сохраняется: первым
/// там стоит сервер, с которого начинают другие приложения, и переставлять
/// чужой порядок незачем. Повторы отбрасываются.
#[must_use]
pub fn mail_servers_from_page(html: &str) -> Vec<MailServer> {
    let mut out: Vec<MailServer> = Vec::new();
    let mut rest = html;
    while let Some(start) = item_start(rest) {
        let item = &rest[start..];
        let end = item.find("</li>").unwrap_or(item.len());
        let (item, after) = item.split_at(end);
        rest = after.strip_prefix("</li>").unwrap_or(after);

        let hosts = hosts_in_item(item);
        if hosts.is_empty() {
            continue;
        }
        let note = plain_text(item);
        for host in hosts {
            if out.len() == MAX_LIST_SERVERS {
                return out;
            }
            if out.iter().all(|known| known.host != host) {
                out.push(MailServer { host, note: note.clone() });
            }
        }
    }
    out
}

/// Где начинается ближайший пункт списка.
///
/// Именно тег `li`, а не всё, что начинается с этих букв: в шапке страницы
/// стоит `<link …>`, и принятый за пункт, он утащил в пояснение к первому
/// серверу всю шапку с меню. Поймано живым походом.
fn item_start(html: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(found) = html[from..].find("<li") {
        let at = from + found;
        match html[at + 3..].chars().next() {
            Some(next) if next == '>' || next.is_ascii_whitespace() => return Some(at),
            _ => from = at + 3,
        }
    }
    None
}

/// Имена серверов, на которые ссылается пункт списка.
fn hosts_in_item(item: &str) -> Vec<String> {
    const LINK: &str = "href=\"https://";
    let mut hosts = Vec::new();
    let mut rest = item;
    while let Some(start) = rest.find(LINK) {
        rest = &rest[start + LINK.len()..];
        let Some(end) = rest.find('"') else { break };
        let address = &rest[..end];
        let (host, path) = address.split_once('/').unwrap_or((address, ""));
        // Только корень сайта: ссылка глубже ведёт на страницу, а не на сервер.
        if path.is_empty() && server_host_ok(host) && host != MAIL_SERVER_LIST_HOST {
            hosts.push(host.to_owned());
        }
    }
    hosts
}

/// Годится ли имя, чтобы поставить его в ссылку регистрации.
#[must_use]
pub fn server_host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_FIELD_LEN
        && host.contains('.')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// Текст пункта без разметки: теги сняты, пробелы и переводы строк сведены
/// к одному пробелу, четыре обычные сущности раскрыты, длина ограничена.
///
/// Текст чужой и уходит на экран как есть — поэтому из него убирается
/// всё, что могло бы оказаться разметкой, а клиент обязан показывать его
/// **простым текстом**.
fn plain_text(item: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for symbol in item.chars() {
        match symbol {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                text.push(' ');
            }
            _ if in_tag => {}
            _ => text.push(symbol),
        }
    }
    let text = text
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.chars().take(MAX_SERVER_NOTE).collect()
}

#[cfg(test)]
mod server_list_tests {
    use super::*;

    /// Кусок настоящей страницы — с её меню, пунктом на два сервера
    /// и ссылкой на документацию в конце.
    const PAGE: &str = r#"<head><link rel="stylesheet" href="/assets/main.css">
<link type="application/atom+xml" rel="alternate" href="https://chatmail.at/feed.xml" title="Chatmail" /></head>
<header><nav><ul>
  <li><a class="page-link" href="/relays">Relays</a></li>
  <li><a class="page-link" href="https://chatmail.at/doc/relay">Docs</a></li>
</ul></nav></header>
<ul>
  <li>
    <p><a href="https://nine.testrun.org" class="hilite">nine.testrun.org</a>
is the default onboarding relay for many chatmail apps</p>
  </li>
  <li>
    <p><a href="https://chat.adminforge.de/" class="hilite">chat.adminforge.de</a>
is hosted in Falkenstein, Germany and is geared towards German speaking users</p>
  </li>
  <li>
    <p><a href="https://woodpeckersnest.space/">woodpeckersnest.space</a> and
<a href="https://culturanerd.it/">culturanerd.it</a> are hosted in Italy &amp; run by one operator</p>
  </li>
  <li><p><a href="https://nine.testrun.org/">nine.testrun.org</a> again</p></li>
</ul>
<p>please refer to the <a href="https://chatmail.at/doc/relay">documentation</a>.</p>"#;

    #[test]
    fn servers_come_out_in_page_order_with_their_notes() {
        let servers = mail_servers_from_page(PAGE);
        let hosts: Vec<&str> = servers.iter().map(|server| server.host.as_str()).collect();
        assert_eq!(
            hosts,
            ["nine.testrun.org", "chat.adminforge.de", "woodpeckersnest.space", "culturanerd.it"]
        );
        assert_eq!(
            servers[1].note,
            "chat.adminforge.de is hosted in Falkenstein, Germany and is geared towards German speaking users"
        );
        // Два сервера одного пункта делят пояснение; сущность раскрыта.
        assert_eq!(servers[2].note, servers[3].note);
        assert!(
            servers[2].note.ends_with("are hosted in Italy & run by one operator"),
            "{}",
            servers[2].note
        );
        assert_eq!(servers[0].account_url(), "https://nine.testrun.org/new");
        // `<link>` в шапке — не пункт списка: пояснение к первому серверу
        // начинается с него самого, а не с шапки страницы.
        assert_eq!(
            servers[0].note,
            "nine.testrun.org is the default onboarding relay for many chatmail apps"
        );
    }

    #[test]
    fn neither_the_menu_nor_the_docs_link_is_a_server() {
        // Меню — пункты списка, но ссылки в них без имени сервера либо
        // с путём; ссылка на документацию — с именем, но вне пункта.
        let servers = mail_servers_from_page(PAGE);
        assert!(servers.iter().all(|server| server.host != MAIL_SERVER_LIST_HOST));
        assert_eq!(servers.len(), 4);
    }

    #[test]
    fn a_page_without_servers_gives_nothing() {
        assert!(mail_servers_from_page("").is_empty());
        assert!(mail_servers_from_page("<html><body><p>503</p></body></html>").is_empty());
        assert!(mail_servers_from_page(
            "<li>без ссылки</li><li><a href=\"http://plain.example/\">x</a></li>"
        )
        .is_empty());
        // Оборванная страница не роняет разбор.
        assert_eq!(mail_servers_from_page("<li><a href=\"https://a.example/\">a").len(), 1);
        assert!(mail_servers_from_page("<li><a href=\"https://a.example").is_empty());
    }

    #[test]
    fn only_a_plain_host_name_reaches_the_account_url() {
        for bad in [
            "",
            "localhost",
            "a.example:8443",
            "user@a.example",
            "A.Example",
            "a..example",
            ".a.example",
            "a.example.",
            "-a.example",
            "a.example/new",
            "a.example?x",
            "a b.example",
            "пример.рф",
        ] {
            assert!(!server_host_ok(bad), "{bad:?} не должно годиться");
        }
        assert!(server_host_ok("nine.testrun.org"));
        assert!(server_host_ok("chika.aangat.lahat.computer"));
        assert!(server_host_ok("e2ee.wang"));
        // И в разборе: негодное имя сервером не становится.
        let page =
            "<li><a href=\"https://Evil.Example/\">x</a><a href=\"https://a.example:444/\">y</a>\
                    <a href=\"https://good.example/\">z</a></li>";
        let hosts: Vec<String> =
            mail_servers_from_page(page).into_iter().map(|server| server.host).collect();
        assert_eq!(hosts, ["good.example"]);
    }

    #[test]
    fn foreign_text_is_flattened_and_bounded() {
        let long = "x".repeat(MAX_SERVER_NOTE * 2);
        let page = format!("<li><a href=\"https://a.example/\">a</a> <b>жирно</b>\n  {long}</li>");
        let note = &mail_servers_from_page(&page)[0].note;
        assert!(note.starts_with("a жирно x"), "{note}");
        assert!(!note.contains('<') && !note.contains('\n'));
        assert_eq!(note.chars().count(), MAX_SERVER_NOTE);
    }

    #[test]
    fn the_list_is_bounded() {
        let page: String = (0..MAX_LIST_SERVERS + 10)
            .map(|n| format!("<li><a href=\"https://s{n}.example/\">s</a></li>"))
            .collect();
        assert_eq!(mail_servers_from_page(&page).len(), MAX_LIST_SERVERS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> MailAccount {
        MailAccount::from_address("a7f3k9@nine.example", "sekret")
    }

    #[test]
    fn the_domain_becomes_both_servers() {
        let a = account();
        assert_eq!(a.imap_host, "nine.example");
        assert_eq!(a.smtp_host, "nine.example");
        assert_eq!(a.imap_port, DEFAULT_IMAP_PORT);
        assert_eq!(a.smtp_port, DEFAULT_SMTP_PORT);
        assert!(a.via_tor, "§5.3: по умолчанию почта идёт поверх Tor");
    }

    #[test]
    fn settings_survive_the_round_trip() {
        let mut a = account();
        a.via_tor = false;
        a.smtp_port = 587;
        let back = MailAccount::decode(&a.encode().unwrap()).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn a_password_never_reaches_the_log() {
        // Настройки едут до транспорта эффектом, а эффекты пишутся в журнал
        // целиком. Производный `Debug` вынес бы пароль в открытый лог.
        let printed = format!("{:?}", account());
        assert!(!printed.contains("sekret"), "пароль в отладочной печати: {printed}");
        assert!(printed.contains("a7f3k9@nine.example"), "а адрес нужен: {printed}");
    }

    #[test]
    fn what_can_be_caught_without_the_network_is_caught_here() {
        let cases = [
            ("nine.example", MailAccountError::BadAddress),
            ("@nine.example", MailAccountError::BadAddress),
            ("a7f3k9@", MailAccountError::BadAddress),
            ("a@b@nine.example", MailAccountError::BadAddress),
            ("a7f3k9@nine", MailAccountError::BadAddress),
            ("a7f3 k9@nine.example", MailAccountError::BadAddress),
        ];
        for (address, expected) in cases {
            let account = MailAccount::from_address(address, "sekret");
            assert_eq!(account.check(), Err(expected), "адрес {address}");
        }
    }

    #[test]
    fn an_empty_password_is_refused_before_the_server_refuses_it() {
        // Отказ входа человек читает как «почта не работает» и чинит не то.
        let account = MailAccount::from_address("a7f3k9@nine.example", "");
        assert_eq!(account.check(), Err(MailAccountError::BadPassword));
    }

    #[test]
    fn a_zero_port_has_nowhere_to_connect() {
        let mut account = account();
        account.smtp_port = 0;
        assert_eq!(account.check(), Err(MailAccountError::BadPort));
    }

    #[test]
    fn a_field_longer_than_the_limit_is_an_input_error() {
        let mut account = account();
        account.imap_host = "a".repeat(MAX_FIELD_LEN + 1);
        assert_eq!(account.check(), Err(MailAccountError::TooLong));
    }

    #[test]
    fn a_good_account_passes() {
        assert_eq!(account().check(), Ok(()));
    }

    #[test]
    fn a_registration_link_is_taken_apart() {
        let url = AccountUrl::parse("https://chatmail.example/new").unwrap();
        assert_eq!(url.host, "chatmail.example");
        assert_eq!(url.port, 443, "порт по умолчанию — https");
        assert_eq!(url.path, "/new");

        let with_port = AccountUrl::parse("https://chatmail.example:8443/cgi/new").unwrap();
        assert_eq!(with_port.port, 8443);
        assert_eq!(with_port.path, "/cgi/new");

        // Пути нет — значит корень: где сервер обслуживает регистрацию,
        // его дело.
        assert_eq!(AccountUrl::parse("https://chatmail.example").unwrap().path, "/");
    }

    #[test]
    fn a_link_without_tls_is_refused() {
        // По http пароль приехал бы открытым текстом любому на пути,
        // а этот пароль открывает переписку.
        assert_eq!(
            AccountUrl::parse("http://chatmail.example/new"),
            Err(AccountUrlError::NotHttps)
        );
        assert_eq!(AccountUrl::parse("chatmail.example/new"), Err(AccountUrlError::NotHttps));
    }

    #[test]
    fn a_link_that_shows_one_host_and_visits_another_is_refused() {
        // `https://chatmail.example@evil.test/new` человек читает как
        // «chatmail.example», а сходит оно на `evil.test`.
        assert_eq!(
            AccountUrl::parse("https://chatmail.example@evil.test/new"),
            Err(AccountUrlError::BadHost)
        );
    }

    #[test]
    fn a_link_with_rubbish_instead_of_a_host_is_refused() {
        let cases = [
            ("https:///new", AccountUrlError::BadHost),
            ("https://localhost/new", AccountUrlError::BadHost),
            ("https://chat mail.example/new", AccountUrlError::BadHost),
            ("https://chatmail.example:0/new", AccountUrlError::BadPort),
            ("https://chatmail.example:нет/new", AccountUrlError::BadPort),
        ];
        for (url, expected) in cases {
            assert_eq!(AccountUrl::parse(url), Err(expected), "ссылка {url}");
        }
    }

    #[test]
    fn an_unknown_limit_is_not_a_zero_limit() {
        // Сервер вправе объявить голое `SIZE` без числа (RFC 1870) или
        // не знать `QUOTA` вовсе. Прочти мы молчание как «ноль» — почта
        // перестала бы возить файлы на всяком сервере, который о себе
        // не рассказывает, и починить это человек не смог бы ничем.
        let unknown = MailLimits::default();
        assert!(unknown.letter_fits(u64::MAX));
        assert!(unknown.carries_file_chunks());
        assert_eq!(unknown.free_bytes(), None);
        assert!(!unknown.crowded(), "неизвестный объём — не «переполнен»");
    }

    #[test]
    fn a_stingy_letter_limit_stops_file_chunks() {
        // Настоящее письмо с чанком — около полутора мебибайт. Сервер
        // с мегабайтным пределом отвергнет каждый чанк, и передача будет
        // вечно начинаться заново; честнее не начинать (§14).
        let stingy = MailLimits { letter_bytes: Some(1_000_000), ..MailLimits::default() };
        assert!(!stingy.carries_file_chunks());
        // А тот, что назвал нам живой chatmail-сервер, — возит.
        let real = MailLimits { letter_bytes: Some(31_457_280), ..MailLimits::default() };
        assert!(real.carries_file_chunks());
    }

    #[test]
    fn crowded_asks_about_the_window_not_about_percents() {
        use crate::files::mail_window_bytes;
        let window = mail_window_bytes();

        // Ящик на гигабайт, занятый на 95 %, для окна просторен.
        let big = MailLimits {
            letter_bytes: None,
            mailbox_used: Some(950 * 1024 * 1024),
            mailbox_limit: Some(1024 * 1024 * 1024),
        };
        assert!(!big.crowded(), "проценты здесь ни при чём: места хватает на окно");

        // Ящик, занятый наполовину, но маленький, — тесен.
        let small = MailLimits {
            letter_bytes: None,
            mailbox_used: Some(window),
            mailbox_limit: Some(window + window / 2),
        };
        assert!(small.crowded());
        assert_eq!(small.free_bytes(), Some(window / 2));

        // Ровно окно — ещё не тесно: границу проверяем, потому что от неё
        // зависит, попросим мы чанки или скажем человеку, что не можем.
        let exact =
            MailLimits { letter_bytes: None, mailbox_used: Some(0), mailbox_limit: Some(window) };
        assert!(!exact.crowded());
    }

    #[test]
    fn the_numbers_a_real_stingy_server_gave() {
        // Сняты со стенда `tarpit.fun` — нарочно скупого chatmail-сервера.
        // `SIZE 31457280` и квота 204800 КиБ; RFC 2087 считает килобайтами,
        // и умножение на 1024 — не косметика: без него ящик выглядел бы
        // двухсоткилобайтным, то есть тесным всегда.
        let limits = MailLimits {
            letter_bytes: Some(31_457_280),
            mailbox_used: Some(0),
            mailbox_limit: Some(204_800 * 1024),
        };
        assert!(limits.carries_file_chunks(), "30 МБ на письмо — файлы поедут");
        assert!(!limits.crowded(), "200 МиБ ящика — окно помещается многократно");
        assert_eq!(limits.free_bytes(), Some(209_715_200));
    }
}
