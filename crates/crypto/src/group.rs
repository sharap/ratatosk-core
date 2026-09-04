//! Тело группового сообщения (§11.1).
//!
//! Ключ — тот, что выдала цепочка отправителя
//! ([`crate::ratchet::SenderChain::next`]). Он одноразовый: следующий номер
//! выводит следующий ключ, а этот стирается. Отсюда и всё остальное здесь.
//!
//! # Почему шифруется дважды
//!
//! Копия едет каждому участнику по его 1:1-каналу (§11.3), и каждая копия
//! уже запечатана сессией. Sender key поверх неё нужен не ради второго слоя
//! секретности, а чтобы все копии были **одним и тем же сообщением**: один
//! шифротекст, один номер, одна подпись на всех. Без него у тридцати двух
//! копий было бы тридцать два разных шифротекста, и «одно сообщение»
//! пришлось бы склеивать из совпадения текста — то есть никак.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::kdf::Key32;
use crate::storage_key;

/// Запечатывает тело группового сообщения.
///
/// # Примитив здесь не собирается заново
///
/// Внутри — [`storage_key::seal_field`], то есть ровно то же
/// XChaCha20-Poly1305 со случайным nonce впереди шифротекста. §8.1 требует,
/// чтобы комбинирование примитивов жило **в одном модуле, покрытом
/// тест-векторами**; переписать те же пятнадцать строк здесь значило бы
/// завести второе такое место. Отсюда и делегирование: этот модуль отвечает
/// за правильный AAD и за честное имя, а не за криптографию.
///
/// # Что связывает AAD
///
/// Группа, отправитель и номер. Подпись (§11.1) и так покрывает эти три
/// поля, и главная защита — она; AAD добавляет к ней то, что стоит
/// бесплатно: шифротекст, переставленный в другую группу, к другому
/// отправителю или на другой номер, не откроется **до** проверки подписи.
///
/// Это не паранойя. Ключ отправителя знают все участники (§11.5) — значит
/// любой из них умеет и открыть наше сообщение, и запечатать своё нашим
/// ключом. Подделать наше имя ему мешает подпись, а переставить наш же
/// шифротекст — вот это.
///
/// # Errors
///
/// Отказ примитива.
pub fn seal_message(
    key: &Key32,
    group: &[u8; 16],
    sender: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    storage_key::seal_field(key, &aad(group, sender, counter), plaintext)
}

/// Распечатывает тело группового сообщения.
///
/// Отказ означает либо не тот ключ — то есть не то место в цепочке, — либо
/// порчу, либо перестановку. Различать их незачем: во всех трёх случаях
/// читать нечего.
///
/// # Errors
///
/// [`crate::CryptoError::Decrypt`] — тег не сошёлся.
pub fn open_message(
    key: &Key32,
    group: &[u8; 16],
    sender: &[u8; 32],
    counter: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    storage_key::open_field(key, &aad(group, sender, counter), sealed)
}

/// Запечатывает тело группового действия — правки, отзыва, реакции, ответа.
///
/// # Зачем отдельная функция, если ключ и примитив те же
///
/// Ради **разделителя в AAD**. Обвязка у действия и у сообщения одна:
/// та же цепочка, тот же номер, та же подпись над теми же четырьмя полями.
/// Вид действия при этом лежит в конверте, а конверт не подписан — значит
/// участник, получивший нашу копию, вправе переслать её соседу, поменяв
/// тип нагрузки, и подпись сойдётся.
///
/// Одного этого мало для беды: правка, названная сообщением, не разберётся
/// как текст, а текст, названный правкой, не разберётся как карта. Но
/// «не разберётся» — свойство разбора, и держаться за него значит обещать,
/// что разбор никогда не станет мягче. Разделитель делает подмену
/// невозможной раньше: с чужим AAD тег не сойдётся, и до разбора дело
/// не дойдёт.
///
/// # Errors
///
/// Отказ примитива.
pub fn seal_action(
    key: &Key32,
    group: &[u8; 16],
    sender: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    storage_key::seal_field(key, &aad_action(group, sender, counter), plaintext)
}

/// Распечатывает тело группового действия.
///
/// # Errors
///
/// [`crate::CryptoError::Decrypt`] — тег не сошёлся; в том числе когда
/// действие выдали за сообщение.
pub fn open_action(
    key: &Key32,
    group: &[u8; 16],
    sender: &[u8; 32],
    counter: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    storage_key::open_field(key, &aad_action(group, sender, counter), sealed)
}

/// AAD действия: то же самое плюс хвост.
///
/// Хвост постоянной длины и непустой, поэтому AAD действия длиннее AAD
/// сообщения **всегда** — совпасть они не могут ни при каких значениях
/// полей, и второе свойство здесь не нужно доказывать отдельно.
fn aad_action(group: &[u8; 16], sender: &[u8; 32], counter: u64) -> Vec<u8> {
    let mut out = aad(group, sender, counter);
    out.extend_from_slice(b"action");
    out
}

/// Группа, отправитель и номер — склейкой, в этом порядке.
///
/// Длины полей постоянны, поэтому разделителя не нужно: разобрать склейку
/// иначе, чем она собрана, нельзя. Была бы хоть одна часть переменной длины,
/// разделитель понадобился бы — иначе «группа `ab`, отправитель `c`» и
/// «группа `a`, отправитель `bc`» дали бы один AAD.
fn aad(group: &[u8; 16], sender: &[u8; 32], counter: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 32 + 8);
    out.extend_from_slice(group);
    out.extend_from_slice(sender);
    out.extend_from_slice(&counter.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf;
    use crate::labels;

    fn key() -> Key32 {
        kdf::derive(labels::SENDER_MSG, b"test")
    }

    const GROUP: [u8; 16] = [7u8; 16];
    const SENDER: [u8; 32] = [1u8; 32];

    #[test]
    fn a_message_opens_with_the_same_key_and_place() {
        let sealed = seal_message(&key(), &GROUP, &SENDER, 3, "привет".as_bytes()).unwrap();
        let opened = open_message(&key(), &GROUP, &SENDER, 3, &sealed).unwrap();
        assert_eq!(&opened[..], "привет".as_bytes());
    }

    #[test]
    fn a_message_moved_to_another_place_does_not_open() {
        // Ключ отправителя знают все участники: любой из них умеет открыть
        // наше сообщение и запечатать своё нашим ключом. Подделать имя ему
        // мешает подпись (§11.1), переставить наш шифротекст — этот AAD.
        let sealed = seal_message(&key(), &GROUP, &SENDER, 3, "привет".as_bytes()).unwrap();
        assert!(open_message(&key(), &GROUP, &SENDER, 4, &sealed).is_err(), "другой номер");
        assert!(open_message(&key(), &[8u8; 16], &SENDER, 3, &sealed).is_err(), "другая группа");
        assert!(
            open_message(&key(), &GROUP, &[2u8; 32], 3, &sealed).is_err(),
            "другой отправитель"
        );
    }

    #[test]
    fn a_message_does_not_open_with_a_neighbouring_key() {
        // Ключ одноразовый: следующий номер выводит следующий ключ.
        let other = kdf::derive(labels::SENDER_MSG, b"other");
        let sealed = seal_message(&key(), &GROUP, &SENDER, 0, "привет".as_bytes()).unwrap();
        assert!(open_message(&other, &GROUP, &SENDER, 0, &sealed).is_err());
    }

    #[test]
    fn the_same_text_seals_differently_every_time() {
        // Nonce случайный: одинаковые шифротексты выдавали бы, что человек
        // повторил сам себя, — и это было бы видно всем, кто смотрит провод.
        let first = seal_message(&key(), &GROUP, &SENDER, 0, "да".as_bytes()).unwrap();
        let second = seal_message(&key(), &GROUP, &SENDER, 0, "да".as_bytes()).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn an_action_does_not_open_as_a_message() {
        // Вид действия лежит в конверте, а конверт не подписан: участник
        // вправе переслать нашу копию, поменяв тип нагрузки. Разделитель
        // в AAD делает подмену бесполезной до всякого разбора.
        let sealed = seal_action(&key(), &GROUP, &SENDER, 3, "правка".as_bytes()).unwrap();
        assert!(open_message(&key(), &GROUP, &SENDER, 3, &sealed).is_err());
        let sealed = seal_message(&key(), &GROUP, &SENDER, 3, "привет".as_bytes()).unwrap();
        assert!(open_action(&key(), &GROUP, &SENDER, 3, &sealed).is_err());
    }

    #[test]
    fn an_action_opens_with_the_same_key_and_place() {
        let sealed = seal_action(&key(), &GROUP, &SENDER, 9, "правка".as_bytes()).unwrap();
        let opened = open_action(&key(), &GROUP, &SENDER, 9, &sealed).unwrap();
        assert_eq!(&opened[..], "правка".as_bytes());
        assert!(open_action(&key(), &GROUP, &SENDER, 10, &sealed).is_err(), "другой номер");
    }

    #[test]
    fn the_two_aads_can_never_coincide() {
        // Хвост непустой и постоянной длины: AAD действия длиннее всегда.
        assert!(aad_action(&GROUP, &SENDER, 0).len() > aad(&GROUP, &SENDER, u64::MAX).len());
    }

    #[test]
    fn the_aad_cannot_be_reparsed_another_way() {
        // Длины постоянны, поэтому разделителя не нужно. Тест держит это
        // свойство: стань хоть одна часть переменной, склейка «поехала» бы.
        assert_eq!(aad(&GROUP, &SENDER, 0).len(), 16 + 32 + 8);
        assert_ne!(aad(&GROUP, &SENDER, 0), aad(&GROUP, &SENDER, 1));
    }
}
