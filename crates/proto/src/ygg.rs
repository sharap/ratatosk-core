//! Адрес в меше Yggdrasil — из открытого ключа (0.2).
//!
//! Карточка везёт **ключ**, а не адрес (`ratatosk-v0_2-spec.md`, 0.2.3), и
//! это одно поле на два способа связи: встроенный узел соединяется по ключу
//! напрямую, внешнему демону нужен адрес `200::/7`. Вывод адреса из ключа
//! однозначен, и живёт он здесь — в протоколе, а не в транспорте: правило
//! задано сетью, а не нашей реализацией, и понадобится оно ещё и тому,
//! кто захочет показать адрес человеку рядом с `yggdrasilctl`.
//!
//! # Почему своя реализация, а не чужая функция
//!
//! Тридцать строк на чистом `std` против зависимости от `yggdrasil`,
//! которая тянет за собой ironwood, tokio и ещё десяток крейтов. Ради
//! **вывода адреса** это несоразмерно: раннеру поверх внешнего демона
//! из всего меша нужна ровно эта функция и больше ничего.
//!
//! Сверено с их реализацией, а не написано по описанию: стенд на `rustc`
//! гоняет обе на десятках тысяч ключей — случайных и вырожденных — и
//! сравнивает побайтно (`TESTING.md`).
//!
//! # Что здесь считается
//!
//! Точный порядок (перенос `AddrForKey` из Go, как и у них):
//!
//! 1. Ключ инвертируется побитно.
//! 2. Считаются ведущие единицы инвертированного — их число ложится
//!    во второй байт адреса.
//! 3. Первый ноль **пропускается**: он и есть граница, и хранить его
//!    незачем — он выводится из счётчика.
//! 4. Остаток кладётся в байты 2..16, и кладётся **только целыми
//!    байтами**: хвост короче восьми бит отбрасывается.
//!
//! Четвёртый пункт выглядит произволом и им является — но это произвол
//! **чужой** сети, и повторить его надо в точности. Разойдись мы здесь,
//! адреса совпадали бы у всех обычных ключей и разошлись бы у ключа
//! с сотней нулевых битов в начале: находка на одном устройстве из
//! многих миллионов, и искать её было бы негде.

use ratatosk_codec::{CodecError, Value};

/// Первый байт адреса Yggdrasil. Им же адрес и опознаётся.
pub const ADDRESS_PREFIX: u8 = 0x02;

/// Длина открытого ключа узла — ed25519, тридцать два байта.
pub const KEY_LEN: usize = 32;

/// Сколько байт адреса занимает остаток ключа: шестнадцать минус префикс
/// и счётчик единиц.
const TAIL_BYTES: usize = 14;

/// Бит с номером `index`, считая от старшего бита нулевого байта.
const fn bit(bytes: &[u8; KEY_LEN], index: usize) -> bool {
    bytes[index / 8] & (0x80 >> (index % 8)) != 0
}

/// Адрес `200::/7` этого узла (0.2).
///
/// Всегда получается: вырожденных ключей, для которых адреса нет, не бывает.
/// Ключ из одних единиц даёт ноль ведущих единиц после инверсии, ключ
/// из одних нулей — двести пятьдесят шесть, и оба укладываются в тот же
/// шестнадцатибайтный вид.
#[must_use]
pub fn address_of(key: &[u8; KEY_LEN]) -> [u8; 16] {
    let mut inverted = [0u8; KEY_LEN];
    let mut i = 0;
    while i < KEY_LEN {
        inverted[i] = !key[i];
        i += 1;
    }

    let mut ones = 0;
    while ones < KEY_LEN * 8 && bit(&inverted, ones) {
        ones += 1;
    }

    let mut addr = [0u8; 16];
    addr[0] = ADDRESS_PREFIX;
    // Счётчик не влезает в байт только у ключа из одних нулей — там
    // двести пятьдесят шесть. Обрезка повторяет их реализацию; адрес
    // такого ключа всё равно ни у кого не встретится, а расходиться
    // на нём нельзя.
    addr[1] = if ones > 255 { 255 } else { ones as u8 };

    // Целыми байтами, и только ими: после счётчика и пропущенного нуля
    // остаётся `255 - ones` бит, и хвост короче восьми у них отбрасывается.
    let available = (KEY_LEN * 8).saturating_sub(ones + 1);
    let whole_bytes = (available / 8).min(TAIL_BYTES);
    let start = ones + 1;
    let mut n = 0;
    while n < whole_bytes * 8 {
        if bit(&inverted, start + n) {
            addr[2 + n / 8] |= 0x80 >> (n % 8);
        }
        n += 1;
    }
    addr
}

/// Наш ли это адрес по виду.
///
/// Проверка на один байт, и большего здесь не проверить: остальные
/// пятнадцать — сжатый ключ, и «правильность» у них та же, что у ключа.
#[must_use]
pub const fn is_address(addr: &[u8; 16]) -> bool {
    addr[0] == ADDRESS_PREFIX
}

/// Адрес строкой — тем видом, каким его показывает система.
///
/// Нужен там, где адрес читает человек: сверить с выводом `yggdrasilctl`
/// глазами по шестнадцати байтам невозможно.
#[must_use]
pub fn address_text(key: &[u8; KEY_LEN]) -> String {
    std::net::Ipv6Addr::from(address_of(key)).to_string()
}

/// Откуда у нас берётся меш (0.2).
///
/// Три состояния, а не два признака, и это выбор по существу: два признака
/// («меш включён» + «узел встроенный») допускают четыре сочетания, из
/// которых осмысленны три, а четвёртое — «узел встроенный, но выключен» —
/// пришлось бы каждый раз объяснять. Перечисление такого вопроса не задаёт.
///
/// Режимы **взаимоисключающи**, и это не ограничение реализации. У внешнего
/// демона ключ чужой: его завёл он, мы знаем открытую половину и называем
/// её в карточке. У встроенного узла ключ наш: закрытая половина лежит
/// у нас, открытая выводится. Работай оба разом — в карточке стояло бы
/// одно имя, а слушали бы мы два, и §5.4 выбирал бы вслепую.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum YggMode {
    /// Меша нет. Ключ в карточке не объявляется, ступень §5.4 не работает.
    #[default]
    Off,
    /// Внешний демон: `yggdrasil` на устройстве, ключ называет человек.
    ///
    /// Так работает стенд и телефон с официальным приложением. Наше дело —
    /// вывести адрес из названного ключа и соединиться по нему.
    External,
    /// Встроенный узел: меш живёт в нашем процессе, ключ наш.
    ///
    /// Ставить и настраивать человеку нечего, кроме списка пиров — без них
    /// узел ни с кем не соединён (см. [`peers_encode`]).
    Embedded,
}

impl YggMode {
    /// Код в служебной строке базы.
    ///
    /// Ноль у выключенного не случайно: базы, заведённые до 0.2, строки
    /// не имеют вовсе, и отсутствие читается как «меша нет» — то есть верно.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            YggMode::Off => 0,
            YggMode::External => 1,
            YggMode::Embedded => 2,
        }
    }

    /// Режим по коду. `None` — код неизвестен.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<YggMode> {
        match code {
            0 => Some(YggMode::Off),
            1 => Some(YggMode::External),
            2 => Some(YggMode::Embedded),
            _ => None,
        }
    }

    /// Как назвать режим человеку.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            YggMode::Off => "выключен",
            YggMode::External => "внешний демон",
            YggMode::Embedded => "встроенный узел",
        }
    }
}

/// Зерно встроенного узла — закрытый ключ, не печатающийся в отладке.
///
/// Обёртка, а не голый вектор, ровно ради `Debug`. Настройка меша едет
/// вниз эффектом, а эффекты попадают в журнал целиком: производный `Debug`
/// вывалил бы туда закрытый ключ при первой же отладочной строке.
/// Та же причина и то же решение, что у почтовых настроек с паролем.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeSeed(Vec<u8>);

impl NodeSeed {
    /// Заворачивает зерно.
    #[must_use]
    pub fn new(seed: Vec<u8>) -> NodeSeed {
        NodeSeed(seed)
    }

    /// Отдаёт зерно тому, кто поднимает узел.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for NodeSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "‹зерно узла меша, {} б›", self.0.len())
    }
}

/// Настройка меша целиком — то, что ядро говорит транспорту (0.2).
///
/// Один тип на все три режима, а не признак рядом с ключом. Причина
/// та же, что у [`YggMode`], но здесь она весомее: раннер обязан уметь
/// **выключать** прежний режим, и разъехавшиеся «поставь ключ» и «подними
/// узел» рано или поздно оставили бы работать оба.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YggSetup {
    /// Ничего не поднимать, поднятое — остановить.
    Off,
    /// Соединяться через внешний демон, слушая свой адрес.
    External {
        /// Открытый ключ **нашего** узла: из него выводится наш адрес.
        /// Пусто — человек режим выбрал, а ключ ещё не назвал.
        key: Vec<u8>,
    },
    /// Поднять узел у себя.
    Embedded {
        /// Закрытый ключ узла. Открытая половина уже стоит в карточке.
        seed: NodeSeed,
        /// Кому звонить, чтобы попасть в сеть. Пусто — узел одинок.
        peers: Vec<String>,
    },
}

impl YggSetup {
    /// Режим этой настройки.
    #[must_use]
    pub const fn mode(&self) -> YggMode {
        match self {
            YggSetup::Off => YggMode::Off,
            YggSetup::External { .. } => YggMode::External,
            YggSetup::Embedded { .. } => YggMode::Embedded,
        }
    }
}

/// Кодирует список пиров для служебной строки базы.
///
/// # Зачем список вообще
///
/// Встроенный узел без пиров не соединён ни с кем: `yggdrasil` не знает,
/// куда идти, и молчит. Это не поломка, а устройство сети — и потому
/// ступень в таком состоянии обязана честно отвечать «не работает»,
/// а не «работает, но никого нет».
///
/// # Почему список пуст по умолчанию
///
/// Зашитый список публичных пиров сделал бы меш работающим «из коробки»
/// ценой того, что **мы** выбираем, кто видит трафик человека. Плата
/// несоразмерна: пир видит источник и адресата пакетов в меше, а список
/// в сборке протухает вместе с релизом. Поэтому пиров называет человек,
/// а пока не назвал — ступень не работает и так и написано.
///
/// # Errors
///
/// Отказ кодирования: список не укладывается в детерминированный CBOR.
pub fn peers_encode(peers: &[String]) -> Result<Vec<u8>, CodecError> {
    let items = peers.iter().map(|p| Value::Text(p.clone())).collect();
    ratatosk_codec::canonical::encode(&Value::Array(items))
}

/// Разбирает список пиров из служебной строки.
///
/// # Errors
///
/// Не CBOR, не массив, не строки — то есть испорченная запись.
pub fn peers_decode(bytes: &[u8]) -> Result<Vec<String>, CodecError> {
    let value = ratatosk_codec::canonical::decode(bytes)?;
    let Value::Array(items) = value else {
        return Err(CodecError::TypeMismatch);
    };
    items
        .iter()
        .map(|item| match item {
            Value::Text(text) => Ok(text.clone()),
            _ => Err(CodecError::TypeMismatch),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ключ, у которого первые `zeros` бит нулевые, а дальше единицы.
    ///
    /// После инверсии нули становятся единицами — то есть это ключ
    /// с заданным числом ведущих единиц у инвертированного.
    fn key_with_leading_zeros(zeros: usize) -> [u8; KEY_LEN] {
        let mut key = [0xffu8; KEY_LEN];
        for index in 0..zeros {
            key[index / 8] &= !(0x80 >> (index % 8));
        }
        key
    }

    #[test]
    fn every_address_carries_the_prefix() {
        for zeros in [0, 1, 7, 8, 9, 100, 143, 200, 255, 256] {
            let addr = address_of(&key_with_leading_zeros(zeros));
            assert!(is_address(&addr), "{zeros}: адрес обязан начинаться с 0x02");
            assert_eq!(addr[0], ADDRESS_PREFIX);
        }
    }

    #[test]
    fn the_second_byte_counts_the_leading_ones() {
        for zeros in [0, 1, 7, 8, 9, 100] {
            let addr = address_of(&key_with_leading_zeros(zeros));
            assert_eq!(usize::from(addr[1]), zeros, "второй байт — счётчик единиц");
        }
    }

    #[test]
    fn a_key_of_all_ones_has_no_leading_ones_at_all() {
        // Инверсия даёт одни нули: ведущих единиц ноль, граница — первый же
        // бит. Случай крайний, и разойтись на нём легче всего.
        let addr = address_of(&[0xff; KEY_LEN]);
        assert_eq!(addr[1], 0);
        assert_eq!(&addr[2..], &[0u8; TAIL_BYTES], "остаток из одних нулей");
    }

    #[test]
    fn a_key_of_all_zeros_saturates_the_counter() {
        // Инверсия даёт одни единицы: двести пятьдесят шесть ведущих,
        // а байт вмещает двести пятьдесят пять. Обрезка — не наша выдумка,
        // а повторение их поведения.
        let addr = address_of(&[0x00; KEY_LEN]);
        assert_eq!(addr[1], 255);
        assert_eq!(&addr[2..], &[0u8; TAIL_BYTES], "целых байт остатка не осталось");
    }

    #[test]
    fn the_tail_is_written_by_whole_bytes_only() {
        // Ключ со ста сорока четырьмя нулевыми битами: после счётчика
        // и пропущенного нуля остаётся сто одиннадцать бит — тринадцать
        // целых байт и семь бит хвоста. Хвост обязан пропасть.
        let addr = address_of(&key_with_leading_zeros(144));
        assert_eq!(addr[1], 144);
        assert_eq!(addr[15], 0, "четырнадцатый байт остатка неполон — значит нулевой");
    }

    #[test]
    fn a_changed_bit_inside_the_prefix_changes_the_address() {
        // Вменяемость: адрес зависит от ключа не одним счётчиком.
        let mut a = [0x5au8; KEY_LEN];
        let b = a;
        a[3] ^= 0x01;
        assert_ne!(address_of(&a), address_of(&b));
    }

    #[test]
    fn the_address_is_a_lossy_squeeze_of_the_key() {
        // **Адрес собеседника не опознаёт.** В него влезает четырнадцать
        // байт остатка, то есть чуть больше половины ключа; два ключа,
        // расходящиеся только в хвосте, дают один адрес. Проверка стоит
        // здесь не ради полноты, а ради вывода: личность устанавливает
        // рукопожатие §8.2, а не адрес и не то, кто к нам подключился
        // (`ARCHITECTURE.md`, 5ц). Раннеру меша это правило нужно так же,
        // как локальной сети.
        let mut a = [0x5au8; KEY_LEN];
        let b = a;
        a[31] ^= 0x01;
        assert_eq!(address_of(&a), address_of(&b), "хвост ключа в адрес не попадает");
        assert_ne!(a, b, "а ключи при этом разные");
    }

    #[test]
    fn an_address_reads_the_way_the_system_shows_it() {
        let text = address_text(&[0xff; KEY_LEN]);
        assert!(text.starts_with("200:"), "{text}");
    }

    #[test]
    fn every_mode_survives_the_round_trip_through_its_code() {
        // Коды уезжают в базу и живут дольше сборки. Разойдись `code`
        // и `from_code` — человек нашёл бы у себя другой режим меша
        // после обновления, и молча.
        for mode in [YggMode::Off, YggMode::External, YggMode::Embedded] {
            assert_eq!(YggMode::from_code(mode.code()), Some(mode), "{mode:?}");
        }
    }

    #[test]
    fn an_unknown_mode_code_is_refused_not_guessed() {
        // Строка из будущей сборки — не повод угадывать. Отказ поднимет
        // умолчание «меша нет», а угаданный режим поднял бы узел,
        // которого человек не просил.
        assert_eq!(YggMode::from_code(3), None);
        assert_eq!(YggMode::from_code(255), None);
    }

    #[test]
    fn a_missing_row_reads_as_no_mesh() {
        // Базы, заведённые до 0.2, строки не имеют вовсе. Ноль обязан
        // означать «выключен» — иначе обновление приложения включило бы
        // меш всем разом.
        assert_eq!(YggMode::from_code(0), Some(YggMode::Off));
        assert_eq!(YggMode::default(), YggMode::Off);
    }

    #[test]
    fn a_setup_knows_its_own_mode() {
        // Настройка и режим обязаны сходиться: раннер выбирает по первой,
        // а человеку показывают второй, и разъехавшись они дали бы
        // «в настройках узел, в работе демон».
        assert_eq!(YggSetup::Off.mode(), YggMode::Off);
        assert_eq!(YggSetup::External { key: Vec::new() }.mode(), YggMode::External);
        assert_eq!(
            YggSetup::Embedded { seed: NodeSeed::new(vec![1; 32]), peers: Vec::new() }.mode(),
            YggMode::Embedded
        );
    }

    #[test]
    fn a_seed_is_not_printed() {
        // Настройка едет вниз эффектом, эффекты попадают в журнал целиком.
        let seed = NodeSeed::new(vec![0xab; 32]);
        let shown = format!("{:?}", YggSetup::Embedded { seed, peers: Vec::new() });
        assert!(!shown.contains("171"), "зерно не должно печататься: {shown}");
        assert!(!shown.contains("ab"), "ни в каком виде: {shown}");
        assert!(shown.contains("32"), "а длина — можно, она не секрет: {shown}");
    }

    #[test]
    fn peers_survive_the_round_trip() {
        let peers =
            vec!["tcp://ygg.example:9001".to_owned(), "quic://[2001:db8::1]:9002".to_owned()];
        let bytes = peers_encode(&peers).expect("список кодируется");
        assert_eq!(peers_decode(&bytes).expect("и разбирается"), peers);
    }

    #[test]
    fn an_empty_list_is_a_list_and_not_an_absence() {
        // Разница видна человеку: «пиров не назвали» и «строки нет» —
        // одно и то же состояние, и обходиться с ними надо одинаково,
        // а не падать на пустом списке.
        let bytes = peers_encode(&[]).expect("пустой список кодируется");
        assert_eq!(peers_decode(&bytes).expect("и разбирается"), Vec::<String>::new());
    }

    #[test]
    fn a_mangled_list_is_refused() {
        // Порча в служебной строке не должна становиться списком из одного
        // мусорного пира: узел пошёл бы звонить неизвестно куда.
        assert!(peers_decode(b"\xff\xff\xff").is_err());
        let not_an_array = ratatosk_codec::canonical::encode(&Value::Text("tcp://x".into()))
            .expect("строка кодируется");
        assert!(peers_decode(&not_an_array).is_err(), "массив — не строка");
    }
}
