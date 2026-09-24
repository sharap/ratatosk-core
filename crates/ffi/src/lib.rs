//! UniFFI-граница (§13.3).
//!
//! Правило без исключений: **никакой протокольной логики выше этой границы.**
//! Всё, что здесь есть, — перевод типов ядра в то, что умеет UniFFI, и
//! обратно. Если появляется соблазн написать здесь `if`, зависящий от
//! содержимого сообщения, значит логика уходит в клиент и выпадает из
//! симуляции (§16).
//!
//! Типы наружу намеренно простые: без лайфтаймов, без generic'ов, без
//! заимствований. Kotlin видит обычные структуры и колбэки — и на телефоне,
//! и на десктопе: он там на Compose, то есть на той же JVM.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// По той же причине, что и в стенде: ядро вместе с подъёмом Tor собирается
// в одно глубоко вложенное будущее, и вычисление его раскладки упирается
// в умолчание компилятора. Предел про сборку, а не про работу.
#![recursion_limit = "512"]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ratatosk_codec::ContactCard;
use ratatosk_core::driver::{
    ContactStatus, Driver, DriverHandle, EventStream, MessageView, OwnCard,
};
use ratatosk_core::{
    vault, Account, AccountId, Command, Engine, Event, OsEntropy, OutgoingFile, Registry,
    SelfAddresses,
};
use ratatosk_proto::DeliveryStatus;
use ratatosk_store::{FsBlobs, SqliteStore};
#[cfg(feature = "tor")]
use ratatosk_transport::{onion::arti::OnionRunner, Switched};
// `Disabled` нужен там, где ступени в сборке нет: она честно отказывает,
// и это правда о сборке, а не заглушка. Потребителей у него ровно два —
// `MailSide` и `NostrSide`, — и оба живут под `not(feature)`.
//
// **Условие здесь обязано быть их отрицанием, а не отсутствовать.**
// Стояло без условия, с объяснением «сборка с обоими признаками всё равно
// бывает», — и в такой сборке импорт становился неиспользуемым. Поймалось
// не сразу: `cargo build --workspace --all-features` в проверке не звался,
// а без признаков предупреждения нет.
#[cfg(not(all(feature = "mail", feature = "nostr")))]
use ratatosk_transport::Disabled;
use ratatosk_transport::{
    BridgedAir, BtConfig, BtRunner, LanConfig, LanRunner, Transports, YggConfig, YggRunner,
    YGG_PORT,
};

use crate::bluetooth::FfiBluetooth;

/// Эфир Bluetooth (0.4): радио приходит от платформы, правила остаются
/// здесь.
///
/// Модуль, а не место в этом файле: граница с радио — свой договор
/// из шести вызовов и восьми событий, и держать его посреди переписки
/// значило бы прятать.
pub mod bluetooth;

/// Второй экран телефона (§13.4) — отдельным объектом.
///
/// Модуль, а не второй крейт: планшет на Android бывает и аккаунтом,
/// и компаньоном, и двумя нативными библиотеками в одном приложении
/// это обошлось бы дороже, чем неиспользуемым SQLite на десктопе.
pub mod companion;

uniffi::setup_scaffolding!();

impl RatatoskError {
    fn internal(reason: impl std::fmt::Display) -> RatatoskError {
        RatatoskError::Internal { reason: reason.to_string() }
    }
}

/// Проверяет длину секрета устройства.
///
/// Ровно 32 байта, и отказ на всё остальное — не педантизм: секрет короче
/// означает, что клиент положил туда что-то не то (строку, хэш пароля,
/// идентификатор устройства), и молча вывести из этого ключ базы значило бы
/// сделать вид, что защита есть.
fn to_device_key(bytes: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, RatatoskError> {
    match bytes {
        None => Ok(None),
        Some(raw) => <[u8; 32]>::try_from(raw.as_slice()).map(Some).map_err(|_| {
            RatatoskError::internal("секрет устройства обязан быть длиной ровно 32 байта")
        }),
    }
}

/// Складывает PIN и секрет устройства в способ открытия базы (§8.6).
///
/// Все четыре сочетания законны, и выбирает их человек вместе с клиентом:
/// PIN — защита от того, у кого файл; секрет устройства — от того, у кого
/// файл, но нет телефона; вместе — от обоих; ничего — открытая база,
/// про которую клиент обязан предупредить.
fn unlock_of<'a>(pin: Option<&'a str>, device: Option<&'a [u8; 32]>) -> vault::Unlock<'a> {
    match (pin, device) {
        (Some(pin), Some(device)) => vault::Unlock::PinAndDevice { pin, device },
        (Some(pin), None) => vault::Unlock::Pin(pin),
        (None, Some(device)) => vault::Unlock::Device(device),
        (None, None) => vault::Unlock::Nothing,
    }
}

/// Отделяет «не тот PIN» от всего остального.
///
/// Различие содержательное, а не косметическое: заблокированную базу лечит
/// пользователь, введя правильный PIN, а внутреннюю ошибку — не лечит никак.
/// Показать первое как второе значит подтолкнуть человека переустановить
/// клиент и потерять переписку, которая на самом деле цела.
///
/// Определяется по типу ошибки, а не по тексту: формулировки правятся, и
/// сравнение подстрок развалилось бы молча.
fn engine_err(error: ratatosk_core::EngineError) -> RatatoskError {
    use ratatosk_core::EngineError;
    match error {
        EngineError::Store(ratatosk_store::StoreError::Locked)
        | EngineError::Crypto(ratatosk_crypto::CryptoError::Decrypt) => RatatoskError::Locked,
        // Группа полна — ответ, а не поломка (§18.4).
        EngineError::Group(ratatosk_proto::GroupError::TooManyMembers) => {
            RatatoskError::GroupFull {
                limit: u32::try_from(ratatosk_proto::MAX_GROUP_MEMBERS).unwrap_or(u32::MAX),
            }
        }
        // Отказы канала — по той же причине, по какой отделена полная
        // группа: это обычные ответы, и человеку есть что с каждым
        // сделать (фаза 2, §6, §10).
        EngineError::NotAllowedInChannel => {
            RatatoskError::Channel { reason: FfiChannelRefusal::NoRight }
        }
        EngineError::OwnerNeedsNoGrant => {
            RatatoskError::Channel { reason: FfiChannelRefusal::OwnerNeedsNoGrant }
        }
        EngineError::OnlyOwnerPublishesYet => {
            RatatoskError::Channel { reason: FfiChannelRefusal::OnlyOwnerPublishesYet }
        }
        EngineError::OnlyOwnerRotates => {
            RatatoskError::Channel { reason: FfiChannelRefusal::OnlyOwnerRotates }
        }
        EngineError::NotAChannel | EngineError::NotAGroup => {
            RatatoskError::Channel { reason: FfiChannelRefusal::WrongProfile }
        }
        EngineError::OpenChannelHasNoRotation => {
            RatatoskError::Channel { reason: FfiChannelRefusal::OpenHasNoRotation }
        }
        EngineError::RotatedTooRecently => {
            RatatoskError::Channel { reason: FfiChannelRefusal::RotatedTooRecently }
        }
        EngineError::NoReadKeyYet => {
            RatatoskError::Channel { reason: FfiChannelRefusal::NoReadKeyYet }
        }
        EngineError::PowTooHard => RatatoskError::Channel { reason: FfiChannelRefusal::PowTooHard },
        EngineError::BadChannelLink => {
            RatatoskError::Channel { reason: FfiChannelRefusal::BadLink }
        }
        EngineError::AlreadySubscribed => {
            RatatoskError::Channel { reason: FfiChannelRefusal::AlreadySubscribed }
        }
        EngineError::CannotUnsubscribeOwnChannel => {
            RatatoskError::Channel { reason: FfiChannelRefusal::OwnChannel }
        }
        EngineError::TooManyGrants => {
            RatatoskError::Channel { reason: FfiChannelRefusal::TooManyGrants }
        }
        other => RatatoskError::internal(other),
    }
}

/// Ошибка, которую видит клиент.
///
/// Формулировки скупые и не раскрывают, что именно не сошлось: подробная
/// ошибка на границе рано или поздно оказывается в логе, а оттуда — у того,
/// от кого §2.1 обещает защиту.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RatatoskError {
    /// База заблокирована: нужен PIN (§8.6).
    #[error("база заблокирована")]
    Locked,
    /// В группе больше нет мест (§18.4).
    ///
    /// **Отдельно от [`RatatoskError::Internal`] по той же причине, по какой
    /// отдельно «не тот PIN»:** это не сбой, а обычный ответ, и человеку
    /// есть что с ним сделать — завести вторую группу или кого-то убрать.
    /// Показанный как внутренняя ошибка, он толкает переустанавливать
    /// клиент ради того, что работает правильно.
    #[error("в группе уже {limit} участников — больше не поместится")]
    GroupFull {
        /// Предел, в который упёрлись, — чтобы клиенту не хранить его у себя.
        limit: u32,
    },
    /// Канал отказал, и человеку есть что с этим сделать (фаза 2).
    ///
    /// **Одним вариантом с причиной, а не десятью вариантами.** Все они
    /// про один экран и все требуют от человека действия — попросить
    /// право, подождать, вставить другую ссылку. Развернув их в десять
    /// вариантов, мы заставили бы клиент разбирать десять веток там,
    /// где ему нужен один текст; свалив в [`RatatoskError::Internal`] —
    /// посоветовали бы переустановить работающее.
    ///
    /// Текст к причине — [`channel_refusal_text`]; писать свой не надо.
    #[error("{}", channel_refusal_text(*reason))]
    Channel {
        /// Что именно не дало команде пройти.
        reason: FfiChannelRefusal,
    },
    /// Внутренняя ошибка.
    #[error("внутренняя ошибка: {reason}")]
    Internal {
        /// Короткое описание для отчёта.
        reason: String,
    },
}

/// Почему канал отказал (фаза 2, §6, §10).
///
/// Каждая причина — отдельное действие человека, и в этом весь смысл
/// их различать. Причина, по которой делать нечего, сюда не попадает:
/// она остаётся [`RatatoskError::Internal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiChannelRefusal {
    /// В канале нет такого права (§6.2), либо выдача истекла (§6.3).
    ///
    /// Отличить «не давали» от «истекло» можно по представлению, и это
    /// дело показывающего экрана, а не отказа: делать человеку в обоих
    /// случаях одно — просить владельца.
    NoRight,
    /// В звезде публикует только владелец (§3.2, §7.5.2).
    ///
    /// **Право «писать» при этом есть, и отказ не про него.** Слово
    /// развозит сказавший, по своему составу, а состав канала §3.2
    /// оставляет владельцу: читатели друг друга не знают, и держателю
    /// права развозить некому. Доставку делегату вернёт рой (§7).
    ///
    /// Клиенту: поле ввода в канале стоит гасить всем, кроме владельца
    /// (`FfiChannel::owner_ik` против своего ключа), а не по
    /// `rights.write` — право может быть, а доставка нет.
    OnlyOwnerPublishesYet,
    /// Ключ чтения поворачивает только владелец (§6.4, §3.2).
    ///
    /// Право «исключать» у делегата остаётся правом выдать ключ при
    /// впуске; развезти новое поколение ему некому — состав канала знает
    /// владелец. Клиенту: кнопку поворота показывать по
    /// `FfiChannel::may_rotate`, а не по `rights.evict`.
    OnlyOwnerRotates,
    /// Права выдают кому угодно, кроме владельца (§6.2).
    ///
    /// **Отдельно от [`FfiChannelRefusal::NoRight`], и разница
    /// содержательная:** там права нет, здесь оно есть и потому выдача
    /// бессмысленна. Свалив их в один ответ, клиент сказал бы владельцу,
    /// что ему самому в своём канале ничего не разрешено.
    OwnerNeedsNoGrant,
    /// Команда про канал пришла в обычную группу — или наоборот (§3.2).
    WrongProfile,
    /// В открытом канале ключ чтения не поворачивается (§6.1, §10.7).
    OpenHasNoRotation,
    /// Ключ чтения поворачивали меньше недели назад (§6.4).
    RotatedTooRecently,
    /// У канала ещё нет ни одного поколения ключа чтения (§6.4).
    NoReadKeyYet,
    /// Работа, которую требует канал, этому устройству не по силам (§11).
    PowTooHard,
    /// Это не ссылка на канал (§10.3, шаг 1).
    BadLink,
    /// На этот канал мы уже подписаны.
    AlreadySubscribed,
    /// Канал наш собственный: от своего не отписываются (§10.6).
    OwnChannel,
    /// Выдач больше, чем помещается в одно представление (§6.2).
    TooManyGrants,
}

/// Точные слова к отказу канала (§15).
///
/// На границе, а не в клиенте, по той же причине, что [`honest_notices`]:
/// отказ обязан говорить то, что протокол на самом деле делает, и строка
/// в Kotlin разошлась бы с поведением на первой же правке.
#[uniffi::export]
#[must_use]
pub fn channel_refusal_text(reason: FfiChannelRefusal) -> String {
    match reason {
        FfiChannelRefusal::NoRight => {
            "В этом канале у вас нет права на это действие. Права выдаёт \
             владелец, и у выдачи есть срок: она может и закончиться сама."
        }
        FfiChannelRefusal::OnlyOwnerPublishesYet => {
            "В этом канале публикует только владелец. Право писать \
             у вас есть, но разослать написанное пока некому: состав \
             канала знает он один."
        }
        FfiChannelRefusal::OwnerNeedsNoGrant => {
            "Это владелец канала: у него и так все права, и отнять их \
             нельзя. Выдавать их нужно другим."
        }
        FfiChannelRefusal::OnlyOwnerRotates => {
            "Ключ чтения поворачивает только владелец канала: новое \
             поколение развозится по составу, а состав знает он один."
        }
        FfiChannelRefusal::WrongProfile => {
            "Это действие не для этого чата: у канала и у группы разные \
             правила, и то, что можно в одном, не значит ничего в другом."
        }
        FfiChannelRefusal::OpenHasNoRotation => {
            "В открытом канале ключ чтения лежит в самой ссылке — у всех, \
             кому её переслали. Отбирать его не у кого: закрыть такой \
             канал можно только заведя новый."
        }
        FfiChannelRefusal::RotatedTooRecently => {
            "Ключ чтения поворачивали меньше недели назад. Каждый поворот \
             — это отдельная посылка каждому читателю, поэтому чаще нельзя."
        }
        FfiChannelRefusal::NoReadKeyYet => {
            "У канала ещё нет ключа чтения: впускать в него пока некуда. \
             Поверните ключ — и впускайте."
        }
        FfiChannelRefusal::PowTooHard => {
            "Этот канал требует работы, которую ваше устройство не смогло \
             посчитать. Цену назначает владелец канала."
        }
        FfiChannelRefusal::BadLink => {
            "Это не ссылка на канал. Ссылка начинается с ratatosk:v0:channel:"
        }
        FfiChannelRefusal::AlreadySubscribed => {
            "Вы уже подписаны на этот канал — он есть в списке чатов."
        }
        FfiChannelRefusal::OwnChannel => {
            "Это ваш канал. От своего канала не отписываются: подписчики \
             останутся с ним, а управлять им стало бы нечем."
        }
        FfiChannelRefusal::TooManyGrants => {
            "В представлении канала больше не помещается выдач. Снимите \
             право у кого-нибудь, чтобы выдать новое."
        }
    }
    .to_owned()
}

/// Почему передача файла стоит (§10.3).
///
/// **Из шести причин действия требует ровно одна.** Остальные пять
/// означают «файл не потерян, поедет сам»; [`FfiFileWaitReason::
/// MailboxFull`] означает «освободите место, иначе не поедет». Показать
/// их одинаково — соврать человеку в единственном случае, когда он может
/// что-то сделать (§14).
///
/// Текст к каждой — [`file_waiting_text`]; писать свой не надо.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiFileWaitReason {
    /// Канала нет ни одного: собеседника не достать ничем.
    Nowhere,
    /// Остался только почтовый канал, а файл ему не по размеру.
    TooBig,
    /// Дорога есть, связь устанавливается.
    Handshaking,
    /// Свой почтовый ящик переполнен — единственная причина, требующая
    /// действия человека.
    MailboxFull,
    /// Спросили — собеседник молчит.
    Silent,
    /// Ступень занята другими передачами, этот файл ждёт своей очереди.
    ///
    /// Очередь заведена нарочно: параллель на узком канале ничего
    /// не ускоряет. Показывать такой файл зависшим нельзя — он движется,
    /// просто не сейчас.
    Queued,
}

/// Переводит причину наружу.
const fn wait_reason_of(reason: ratatosk_proto::files::FileWait) -> FfiFileWaitReason {
    use ratatosk_proto::files::FileWait;

    match reason {
        FileWait::Nowhere => FfiFileWaitReason::Nowhere,
        FileWait::TooBig => FfiFileWaitReason::TooBig,
        FileWait::Handshaking => FfiFileWaitReason::Handshaking,
        FileWait::MailboxFull => FfiFileWaitReason::MailboxFull,
        FileWait::Silent => FfiFileWaitReason::Silent,
        FileWait::Queued => FfiFileWaitReason::Queued,
    }
}

/// И обратно — чтобы текст брался у ядра, а не переписывался здесь.
const fn wait_reason_back(reason: FfiFileWaitReason) -> ratatosk_proto::files::FileWait {
    use ratatosk_proto::files::FileWait;

    match reason {
        FfiFileWaitReason::Nowhere => FileWait::Nowhere,
        FfiFileWaitReason::TooBig => FileWait::TooBig,
        FfiFileWaitReason::Handshaking => FileWait::Handshaking,
        FfiFileWaitReason::MailboxFull => FileWait::MailboxFull,
        FfiFileWaitReason::Silent => FileWait::Silent,
        FfiFileWaitReason::Queued => FileWait::Queued,
    }
}

/// Статус доставки для UI (§9.4).
///
/// `Delivered` и `Read` недостижимы при почтовой доставке — это свойство
/// протокола, а не решение клиента (§14, пункт 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeliveryStatus {
    /// Отправить не удалось: ни один транспорт не сработал (§5.4).
    ///
    /// Отдельный вариант, а не «ждёт отправки». Сообщение, которое не ушло
    /// и не уйдёт, показанное как ожидающее, — обещание, которого протокол
    /// не даёт, то есть ровно то, что §14 запрещает.
    Undeliverable,
    /// Ждёт отправки: попытка идёт прямо сейчас.
    Pending,
    /// Собеседника нет в сети. Отправится само, когда он появится.
    ///
    /// **Не ошибка.** Пока работает только локальная сеть (§5.1), а onion
    /// и почты ещё нет, «собеседник офлайн» — самый частый исход отправки,
    /// и рисовать его восклицательным знаком значит пугать человека тем,
    /// что вообще-то в порядке вещей. Показывать стоит спокойно: часы,
    /// «ждёт сети», бледная отметка.
    ///
    /// Обещание за этим статусом настоящее: очередь лежит на диске и
    /// переживает перезапуск. Ядро вернётся к сообщению, когда включится
    /// локальная сеть, сменится сеть или собеседник объявится в эфире.
    ///
    /// Чего он **не** обещает: что это случится, пока приложение не работает.
    /// Отправляет ядро, а не система; убитый процесс ничего не отправляет,
    /// пока его не запустят. Текст для человека — [`waiting_notice`].
    Waiting,
    /// Отправлено.
    Sent,
    /// Доставлено. Только прямой канал.
    Delivered,
    /// Прочитано. Только прямой канал.
    Read,
}

/// Транспорт на границе §13.3.
///
/// Своё перечисление, а не `ratatosk_proto::Transport`: типы протокола
/// наружу не отдаются (§13.3), и превращение одного в другой — единственное
/// место, где о них знают обе стороны.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiTransport {
    /// Локальная сеть (§5.1). По умолчанию **выключена**: маяк в эфире
    /// выдаёт присутствие устройства всем, кто слушает.
    Lan,
    /// Канал L2CAP поверх Bluetooth LE (0.4). По умолчанию **выключен**:
    /// объявлять себя и слушать эфир стоит батареи постоянно, а на Android
    /// сканирование вдобавок спрашивает отдельное разрешение. UI обязан
    /// сказать об этом рядом с переключателем.
    ///
    /// **В этой сборке ступень не поднимается ни при каких настройках.**
    /// Она заведена в лестнице §5.4 и честно отвечает «не поднята»:
    /// раннера ещё нет, написан только протокольный слой. Показывать её
    /// человеку как рабочую нельзя (§14).
    Bt,
    /// Меш Yggdrasil (0.2). По умолчанию **выключен**: узел меша переносит
    /// чужой трафик, то есть тратит батарею и трафик человека на чужие
    /// пакеты. UI обязан сказать об этом рядом с переключателем.
    Ygg,
    /// Tor onion-to-onion (§5.2). По умолчанию включён.
    Onion,
    /// Реле nostr поверх Tor (0.3). По умолчанию **выключен**: ступень
    /// не работает, пока человек не назвал реле, а реле видит, кто кому
    /// пишет. UI обязан сказать об этом рядом с переключателем — ровно
    /// так же, как про меш.
    ///
    /// **В этой сборке ступень не поднимается ни при каких настройках.**
    /// Она заведена в лестнице §5.4 и честно отвечает «не поднята»:
    /// раннера ещё нет. Показывать её человеку как рабочую нельзя (§14).
    Nostr,
    /// Почта chatmail поверх Tor (§5.3). По умолчанию включена.
    Mail,
}

impl From<FfiTransport> for ratatosk_proto::Transport {
    fn from(value: FfiTransport) -> ratatosk_proto::Transport {
        match value {
            FfiTransport::Lan => ratatosk_proto::Transport::Lan,
            FfiTransport::Bt => ratatosk_proto::Transport::Bt,
            FfiTransport::Ygg => ratatosk_proto::Transport::Ygg,
            FfiTransport::Onion => ratatosk_proto::Transport::Onion,
            FfiTransport::Nostr => ratatosk_proto::Transport::Nostr,
            FfiTransport::Mail => ratatosk_proto::Transport::Mail,
        }
    }
}

impl From<ratatosk_proto::Transport> for FfiTransport {
    fn from(value: ratatosk_proto::Transport) -> FfiTransport {
        match value {
            ratatosk_proto::Transport::Lan => FfiTransport::Lan,
            ratatosk_proto::Transport::Bt => FfiTransport::Bt,
            ratatosk_proto::Transport::Ygg => FfiTransport::Ygg,
            ratatosk_proto::Transport::Onion => FfiTransport::Onion,
            ratatosk_proto::Transport::Nostr => FfiTransport::Nostr,
            ratatosk_proto::Transport::Mail => FfiTransport::Mail,
        }
    }
}

/// Откуда берётся меш, на границе §13.3 (0.2).
///
/// Своё перечисление по той же причине, что и у транспорта: типы протокола
/// наружу не отдаются.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiYggMode {
    /// Меша нет. Умолчание, и остаётся им после обновления приложения.
    Off,
    /// Внешний демон `yggdrasil` на устройстве; ключ называет человек.
    External,
    /// Свой узел в нашем процессе; имя выводится из своего зерна.
    Embedded,
}

impl From<FfiYggMode> for ratatosk_proto::ygg::YggMode {
    fn from(value: FfiYggMode) -> ratatosk_proto::ygg::YggMode {
        match value {
            FfiYggMode::Off => ratatosk_proto::ygg::YggMode::Off,
            FfiYggMode::External => ratatosk_proto::ygg::YggMode::External,
            FfiYggMode::Embedded => ratatosk_proto::ygg::YggMode::Embedded,
        }
    }
}

impl From<ratatosk_proto::ygg::YggMode> for FfiYggMode {
    fn from(value: ratatosk_proto::ygg::YggMode) -> FfiYggMode {
        match value {
            ratatosk_proto::ygg::YggMode::Off => FfiYggMode::Off,
            ratatosk_proto::ygg::YggMode::External => FfiYggMode::External,
            ratatosk_proto::ygg::YggMode::Embedded => FfiYggMode::Embedded,
        }
    }
}

/// Наше участие в раздаче канала — три состояния (§7.5.1).
///
/// Своё перечисление по той же причине, что у меша: типы протокола
/// наружу не отдаются.
///
/// Наружу едут **все три**, и это изменение против прежней границы.
/// Раньше ехали два (`announced: bool`): «тихо» и «не раздаём»
/// различались только тем, отдаём ли мы по своим исходящим соединениям,
/// а отдавать было нечего — дерева раздачи не существовало. Теперь оно
/// есть, и выключатель §9.2 стал кнопкой, у которой есть последствие.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSeeding {
    /// Не раздаём: никому и ничего.
    ///
    /// Канал при этом читается по-прежнему: выключается раздача,
    /// а не подписка.
    Off,
    /// Тихо — **умолчание**. Адрес не объявлен, набрать нас нельзя,
    /// но тем сидам, к кому мы подключились сами, мы отдаём наравне
    /// со всеми.
    Quiet,
    /// Объявленный сид: адрес в каталоге, набирают незнакомые,
    /// отдаём всякому, кто спросил (§7.6).
    ///
    /// Перед включением клиент обязан показать `seeding_notice`.
    Announced,
}

impl From<FfiSeeding> for ratatosk_proto::swarm::Seeding {
    fn from(value: FfiSeeding) -> ratatosk_proto::swarm::Seeding {
        match value {
            FfiSeeding::Off => ratatosk_proto::swarm::Seeding::Off,
            FfiSeeding::Quiet => ratatosk_proto::swarm::Seeding::Quiet,
            FfiSeeding::Announced => ratatosk_proto::swarm::Seeding::Announced,
        }
    }
}

impl From<ratatosk_proto::swarm::Seeding> for FfiSeeding {
    fn from(value: ratatosk_proto::swarm::Seeding) -> FfiSeeding {
        match value {
            ratatosk_proto::swarm::Seeding::Off => FfiSeeding::Off,
            ratatosk_proto::swarm::Seeding::Quiet => FfiSeeding::Quiet,
            ratatosk_proto::swarm::Seeding::Announced => FfiSeeding::Announced,
        }
    }
}

/// Кому отдаём, когда раздаём канал (фаза 2, §12).
///
/// **Вторая ручка, а не та же, что [`FfiSeeding`].** Участие в раздаче
/// отвечает на вопрос «раздаём ли вообще», уровень — «кому». Сложи их
/// в одну настройку, и «раздаю только контактам» стало бы неотличимо
/// от «не раздаю».
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSharingLevel {
    /// Всем, кто спросил. **Умолчание, и §12 велит ему таким остаться.**
    Everyone,
    /// Только контактам.
    Contacts,
    /// Только сверенным.
    ///
    /// Клиенту стоит называть это тем, что оно есть: сверенных обычно
    /// единицы, и это ближе к «не раздавать», чем к середине.
    Verified,
}

impl From<FfiSharingLevel> for ratatosk_proto::swarm::Sharing {
    fn from(value: FfiSharingLevel) -> ratatosk_proto::swarm::Sharing {
        match value {
            FfiSharingLevel::Everyone => ratatosk_proto::swarm::Sharing::Everyone,
            FfiSharingLevel::Contacts => ratatosk_proto::swarm::Sharing::Contacts,
            FfiSharingLevel::Verified => ratatosk_proto::swarm::Sharing::Verified,
        }
    }
}

impl From<ratatosk_proto::swarm::Sharing> for FfiSharingLevel {
    fn from(value: ratatosk_proto::swarm::Sharing) -> FfiSharingLevel {
        match value {
            ratatosk_proto::swarm::Sharing::Everyone => FfiSharingLevel::Everyone,
            ratatosk_proto::swarm::Sharing::Contacts => FfiSharingLevel::Contacts,
            ratatosk_proto::swarm::Sharing::Verified => FfiSharingLevel::Verified,
        }
    }
}

/// Пределы отдачи: сколько блоков отдаём за минуту (фаза 2, §9.2).
///
/// Два числа из четырёх, которые §9.2 называет «наши»: предел на пира
/// и общий. Третье — окно сидирования — ставит владелец канала
/// в подписанном представлении (§9.3), четвёртый пункт — выключатель
/// раздачи ([`FfiSeeding`]).
///
/// **Ноль законен и означает «блоков не отдаём».** Но выключать
/// раздачу нулём не стоит: выключатель гасит ещё и объявление адреса,
/// и привязки читателей, а ноль останавливает только отдачу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiGivingLimits {
    /// Сколько блоков отдаём **одному** пиру за минуту.
    pub per_peer: u32,
    /// Сколько блоков отдаём **всем вместе** за минуту.
    pub total: u32,
}

impl From<FfiGivingLimits> for ratatosk_proto::swarm::GivingLimits {
    fn from(value: FfiGivingLimits) -> ratatosk_proto::swarm::GivingLimits {
        ratatosk_proto::swarm::GivingLimits { per_peer: value.per_peer, total: value.total }
    }
}

impl From<ratatosk_proto::swarm::GivingLimits> for FfiGivingLimits {
    fn from(value: ratatosk_proto::swarm::GivingLimits) -> FfiGivingLimits {
        FfiGivingLimits { per_peer: value.per_peer, total: value.total }
    }
}

/// Событие для UI.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiEvent {
    /// Пришло сообщение.
    MessageReceived {
        /// Чат.
        chat_id: Vec<u8>,
        /// Идентификатор сообщения.
        msg_id: Vec<u8>,
    },
    /// Изменился статус доставки.
    StatusChanged {
        /// Идентификатор сообщения.
        msg_id: Vec<u8>,
        /// Новый статус.
        status: FfiDeliveryStatus,
    },
    /// Добавлен контакт.
    ContactAdded {
        /// Чей — им адресуются команды.
        peer_ik: Vec<u8>,
        /// Отпечаток для показа (§3).
        fingerprint: String,
        /// Сверен ли отпечаток. Пока нет — UI обязан пометить контакт
        /// непроверенным (§4.2).
        verified: bool,
    },
    /// Сообщения исчезли: удалены у себя или отозваны собеседником.
    MessagesDeleted {
        /// Чат.
        chat_id: Vec<u8>,
        /// Какие сообщения.
        msg_ids: Vec<Vec<u8>>,
    },
    /// Сообщение изменилось: автор его поправил.
    ///
    /// Прежнего текста нет ни у кого. Клиент перечитывает сообщение и обязан
    /// показать отметку [`FfiMessage::edited_at_ms`]: подмена текста без
    /// отметки — молчаливая подмена, а §14 это запрещает.
    MessageEdited {
        /// Чат.
        chat_id: Vec<u8>,
        /// Какое сообщение.
        msg_id: Vec<u8>,
    },
    /// Реакция появилась, сменилась или исчезла.
    ///
    /// Сама реакция событием не едет: она читается вместе с сообщением
    /// ([`FfiMessage::reactions`]), и второй источник того же сведения
    /// однажды разошёлся бы с первым.
    ReactionChanged {
        /// Чат.
        chat_id: Vec<u8>,
        /// На каком сообщении.
        msg_id: Vec<u8>,
        /// Чья реакция. Своя — собственный `IK`.
        author_ik: Vec<u8>,
    },
    /// Контакт изменился: сверка, локальное имя.
    ContactChanged {
        /// Чей.
        peer_ik: Vec<u8>,
    },
    /// Контакт удалён.
    ContactRemoved {
        /// Чей.
        peer_ik: Vec<u8>,
    },
    /// У контакта появилась, сменилась или исчезла аватарка.
    ///
    /// Байты событием не едут: они большие, а событие может ждать в очереди.
    /// Клиент забирает их через [`RatatoskClient::avatar_of`], когда дойдёт
    /// до отрисовки, и обновляет свой кэш по этому событию.
    AvatarChanged {
        /// Чья.
        peer_ik: Vec<u8>,
    },
    /// **Своя** аватарка поставлена или снята.
    ///
    /// Отдельное событие, а не [`FfiEvent::AvatarChanged`] с собственным
    /// `IK`: по тому клиент идёт за контактом и со своим ключом не нашёл бы
    /// там ничего, а перерисовать ему надо профиль.
    ///
    /// **Приходит и тогда, когда сменил не этот экран.** Своё лицо теперь
    /// вправе поменять сопряжённый десктоп (§13.4); без этого события
    /// телефон показывал бы прежнюю картинку до перезапуска. Байты —
    /// через [`RatatoskClient::my_avatar`], как и у чужой.
    OwnAvatarChanged,
    /// Как идёт подъём Tor (§5.2).
    ///
    /// Показывать это человеку **надо**, и не из любви к прогресс-барам:
    /// bootstrap занимает десятки секунд в хорошем случае и не кончается
    /// никогда в плохом — когда сеть Tor недоступна. Снаружи эти два случая
    /// неотличимы, и молчание о них выглядит как сломанное приложение.
    ///
    /// Пока `fraction < 1` — «поднимается». Непустое `blocked` — не ошибка,
    /// а причина остановки; она может смениться на пустую сама, когда сеть
    /// появится. Строки приходят от arti и предназначены для показа как есть.
    TorStatus {
        /// Доля готовности, от 0 до 1.
        fraction: f32,
        /// Что происходит сейчас.
        note: String,
        /// Почему стоит, если стоит.
        blocked: Option<String>,
    },
    /// Группа заведена (§11).
    ///
    /// Отдельно от [`FfiEvent::GroupMembershipChanged`]: то событие говорит
    /// «в известном чате стало иначе», а это — «в списке появилась строка,
    /// которой не было». Идентификатор здесь единственный способ узнать,
    /// какой чат открывать: у группы он случаен и человеку неизвестен.
    GroupCreated {
        /// Чат.
        chat_id: Vec<u8>,
        /// Название.
        title: String,
    },
    /// Кого-то впустили в канал (фаза 2, §6.5).
    ///
    /// Приходит и на свой впуск, и на чужой: учёт видит владелец, и он же
    /// видит, кто именно воспользовался правом «впускать».
    ChannelAdmitted {
        /// Чат.
        chat_id: Vec<u8>,
        /// Кого впустили.
        who: Vec<u8>,
        /// Кто впустил.
        admitted_by: Vec<u8>,
    },
    /// Ключ чтения канала повернулся (фаза 2, §6.4).
    ///
    /// Приходит и на свой поворот, и на чужой: у клиента один путь
    /// перерисовки. Архив при этом не теряется — прежние поколения
    /// остаются, новое приходит для будущего.
    ChannelKeyRotated {
        /// Чат.
        chat_id: Vec<u8>,
        /// Номер нового поколения.
        generation: u64,
    },
    /// Подписались на канал по ссылке (фаза 2, §10.4).
    ///
    /// **Названия в событии нет**: оно внутри представления, а его ещё
    /// не привезли. Класть название в ссылку для показа нельзя — оно
    /// ничем не подписано (§10.5). Строку в списке чатов рисует клиент:
    /// «канал, ссылку прислал X».
    ChannelSubscribed {
        /// Чат.
        chat_id: Vec<u8>,
        /// Ждём ли впуска владельцем. `false` — открытый канал.
        awaiting: bool,
    },
    /// Настройка уведомлений чата изменилась (§14).
    ///
    /// Приходит в ответ на [`RatatoskClient::set_chat_notify`] и ни
    /// от чего другого: по сети настройка не ездит — молчание дело
    /// **этого** устройства, и ни собеседник, ни свой же десктоп
    /// о нём не узнают.
    ChatNotifyChanged {
        /// Чат.
        chat_id: Vec<u8>,
    },
    /// Канал показан по ссылке — **до** подписки (фаза 2, §10.3, шаг 5).
    ///
    /// Приходит в ответ на [`RatatoskClient::preview_channel`]: документ
    /// приехал, подпись сошлась ключом из ссылки, версия не ниже
    /// обещанной. В базе при этом не завелось ничего — человек ещё
    /// не согласился, и согласие это [`RatatoskClient::subscribe_to_channel`]
    /// с той же ссылкой.
    ///
    /// **Неудача события не имеет.** Не достучались — §10.5 обещает
    /// ждать и не считать это тупиком; подделанная подпись и версия
    /// ниже обещанной выглядят на экране так же, и объяснить разницу
    /// человеку нечем. Клиенту рисовать ожидание, а не ошибку.
    ChannelPreviewed {
        /// Чат.
        chat_id: Vec<u8>,
        /// Как канал называется.
        title: String,
        /// Порода (§6.1): `true` — открытый.
        open: bool,
        /// Версия документа.
        version: u64,
        /// Цена слова в битах работы (§11). Ноль — не требуется.
        pow_bits: u32,
    },
    /// У канала новая версия представления (фаза 2, §6.1).
    ///
    /// Отдельно от [`FfiEvent::GroupRenamed`]: у группы переименование —
    /// это всё, что произошло, а здесь вместе с названием могли смениться
    /// права, сложность PoW и окно сидирования.
    ChannelChanged {
        /// Чат.
        chat_id: Vec<u8>,
        /// Номер принятой версии.
        version: u64,
        /// Название из новой версии.
        title: String,
    },
    /// Кто-то просится в канал (фаза 2, §10.4).
    ///
    /// Приходит **владельцу**. Ответ на заявку один — впуск
    /// ([`RatatoskClient::admit_to_channel`]); отказа как сообщения
    /// не бывает, и молчание и есть отказ. Показывать это надо так же:
    /// список просящих и кнопка «впустить», а не «принять/отклонить».
    ///
    /// Карточка просящего уже приехала: заявка везёт только канал.
    ChannelRequested {
        /// Чат.
        chat_id: Vec<u8>,
        /// Кто просится.
        who: Vec<u8>,
    },
    /// Наше участие в раздаче канала изменилось (фаза 2, §7.5.1).
    ///
    /// Признак «объявлено», а не всё состояние: человеку важно одно —
    /// раскрыт ли его адрес. Тихая раздача и отказ снаружи отличаются
    /// не событием, а экраном настроек.
    SeedingChanged {
        /// Чат.
        chat_id: Vec<u8>,
        /// Объявлен ли наш адрес в каталоге.
        announced: bool,
    },
    /// Глубже у спрошенных истории нет (фаза 2, §7.4, шаг 3).
    ///
    /// Ответ на [`RatatoskClient::pull_older_history`]: полоску загрузки
    /// пора убрать. Окончателен он ровно настолько, насколько полон
    /// каталог: появится сид с более длинным архивом — прокрутка снова
    /// даст страницу.
    ChannelHistoryEnd {
        /// Какой канал.
        chat_id: Vec<u8>,
    },
    /// Кто-то вызвался раздавать наш канал (фаза 2, §7.5).
    ///
    /// Приходит **владельцу**: каталог развозит он. Клиенту это повод
    /// перечитать список раздающих
    /// ([`RatatoskClient::channel_seeds`]), а не строка в чате.
    SeedAnnounced {
        /// Чат.
        chat_id: Vec<u8>,
        /// Кто вызвался.
        who: Vec<u8>,
    },
    /// Отписались от канала (фаза 2, §10.6).
    ///
    /// Чата больше нет: ни истории, ни ключей чтения, ни представления.
    /// Клиенту по нему делать ровно одно — убрать строку из списка чатов.
    ChannelUnsubscribed {
        /// Чат.
        chat_id: Vec<u8>,
    },
    /// Канал заведён (фаза 2, §6.1).
    ///
    /// Отдельно от [`FfiEvent::GroupCreated`]: у канала нет списка
    /// участников, зато есть ссылка и экран прав, и рисовать их
    /// по одному событию значило бы решать породу догадкой.
    ChannelCreated {
        /// Чат.
        chat_id: Vec<u8>,
        /// Название. У впущенного — из вводного блока; подписанным оно
        /// доедет в представлении.
        title: String,
        /// Открытый ли канал (§6.1). Порода задана при заведении
        /// и не меняется: «Открытый канал» и «Канал по приглашению» —
        /// два разных обещания, и слово для каждого одно.
        ///
        /// `null` — **породу ещё не знаем**: так приходит событие тому,
        /// кого впустили. Вводный блок говорит «это канал», а порода
        /// живёт в подписанном представлении и приедет следом
        /// ([`FfiEvent::ChannelChanged`]). До тех пор слова для неё нет,
        /// и выдумывать его нельзя: порода решает, у кого ключ чтения.
        open: Option<bool>,
    },
    /// Группу переименовали.
    ///
    /// Отдельно от [`FfiEvent::GroupMembershipChanged`] по той же причине,
    /// по какой заведение отделено от состава: клиент делает по ним разное
    /// — там перерисовать список участников, здесь заголовок и строку
    /// в списке чатов.
    ///
    /// Название приезжает **в событии**, а не спрашивается следом: между
    /// событием и запросом успело бы приехать следующее переименование,
    /// и клиент показал бы не то, о чём его известили.
    ///
    /// Приходит и на своё переименование тоже — у клиента один путь
    /// к перерисовке, а не два.
    GroupRenamed {
        /// Чат.
        chat_id: Vec<u8>,
        /// Новое название — уже подрезанное по краям.
        title: String,
    },
    /// Изменился состав группы.
    GroupMembershipChanged {
        /// Чат.
        chat_id: Vec<u8>,
    },
    /// У группы сменилась аватарка.
    ///
    /// Байты **не** едут в событии — в отличие от названия, и разница
    /// не в аккуратности, а в весе: до тридцати двух килобайт на каждое
    /// событие, а нужны они только тому окну, где эту группу видно.
    /// Читать их надо [`RatatoskClient::group_avatar`].
    ///
    /// Гонки, из-за которой название едет внутри события, здесь нет:
    /// клиент получит ту картинку, что лежит **сейчас**. Показать более
    /// свежую, чем обещали, не ошибка; более старую — была бы ею.
    ///
    /// Приходит и на своё изменение тоже — у клиента один путь
    /// к перерисовке, а не два.
    GroupAvatarChanged {
        /// Чат.
        chat_id: Vec<u8>,
    },
    /// Передача файла стоит, и вот почему (§10.3).
    ///
    /// **Состояние, а не происшествие.** Показывать надо на самом файле —
    /// строкой из [`file_waiting_text`], — а не всплывающей подсказкой:
    /// подсказка исчезнет, а ждать файл будет столько, сколько собеседник
    /// вне сети.
    ///
    /// **Причина приезжает вместе с событием, и её надо показывать.**
    /// Раньше текст был один на все случаи, и это врало: «ждёт канала»
    /// вместо «ваш почтовый ящик переполнен» — правда хуже той, которая
    /// есть, потому что во втором случае человек может что-то сделать.
    /// Из пяти причин действия требует ровно одна
    /// ([`FfiFileWaitReason::MailboxFull`]), и отличить её от остальных
    /// без этого поля нельзя.
    ///
    /// Снимает это состояние следующий [`FfiEvent::FileProgress`]: он
    /// и означает, что передача пошла.
    ///
    /// Прежнее имя — `FileWaitsForDirectChannel`; переименовано, когда
    /// чанки поехали почтой.
    FileWaitsForChannel {
        /// Какой файл.
        file_id: Vec<u8>,
        /// Почему стоит — текст берётся [`file_waiting_text`].
        reason: FfiFileWaitReason,
    },
    /// Ход передачи файла (§10.2).
    ///
    /// Приходит на каждый принятый чанк и на завершение.
    ///
    /// Прежде здесь стояло, что `total` равен нулю только у отклонённого
    /// файла и клиенту тогда надо перечитать сообщение. **Это было неверно
    /// дважды.** Пустой файл — ноль байт, законный файл — даёт ровно те же
    /// нули при завершении сборки, и клиенту говорилось «вложения нет»
    /// о вложении, которое есть. А отклонённый файл теперь называет себя
    /// сам: [`FfiEvent::FileGone`].
    FileProgress {
        /// Какой файл.
        file_id: Vec<u8>,
        /// Принято чанков.
        received: u64,
        /// Всего чанков.
        total: u64,
    },
    /// Ход передачи файла **у отправителя**.
    ///
    /// Числа тут значат другое, чем в [`FfiEvent::FileProgress`], и
    /// показывать их надо другими словами. «Принято» — это то, что
    /// собралось у получателя и сошлось суммой; «отдано» — то, что мы
    /// вручили транспорту. Второе доказывает отправку, а не доставку,
    /// и обещать по нему доставку значило бы врать (§14).
    FileSending {
        /// Какой файл.
        file_id: Vec<u8>,
        /// Кому.
        peer_ik: Vec<u8>,
        /// Отдано транспорту чанков.
        sent: u64,
        /// Всего чанков.
        total: u64,
    },
    /// Вложения больше нет: от него отказались, и всё убрано.
    ///
    /// Строку вложения надо **убрать**, а не обнулить в ней числа. Само
    /// сообщение при этом остаётся: текст к отвергнутой картинке никуда
    /// не делся.
    FileGone {
        /// Какого вложения.
        file_id: Vec<u8>,
    },
    /// Текст из §14, который клиент обязан показать дословно.
    HonestNotice {
        /// Текст.
        text: String,
    },
    /// Ядро отвергло команду (§14).
    ///
    /// Отдельно от [`FfiEvent::HonestNotice`]: там выверенный текст §14,
    /// здесь — отчёт о конкретном действии человека (опечатка в ссылке,
    /// файл не того формата). Показать обязательно: молчание после
    /// нажатия он прочтёт как поломку приложения.
    CommandRefused {
        /// Что именно не так — словами, для показа.
        reason: String,
    },
    /// Chatmail-сервер завёл ящик (§5.3).
    ///
    /// Показать адрес обязательно, и не из вежливости: это новая почта
    /// человека, он её больше нигде не увидит, а собеседники будут писать
    /// именно туда. Пароль в событие не едет — он не нужен ни для показа,
    /// ни для чего-либо ещё выше границы §13.3.
    MailAccountReady {
        /// Адрес, который выдал сервер.
        address: String,
    },
    /// Завести ящик не вышло (§5.3, §14).
    ///
    /// Человек нажал «завести почту» и обязан узнать, почему её нет.
    /// Молчаливый отказ он прочтёт как поломку приложения — и будет прав.
    MailAccountFailed {
        /// Что именно не вышло — словами, для показа.
        reason: String,
    },
    /// Вход на почтовый сервер не удался (§5.3, §14).
    ///
    /// Отдельно от [`FfiEvent::MailAccountFailed`], потому что беды разные
    /// и лечатся по-разному: там ящик не завёлся, здесь ящик есть, а войти
    /// в него не вышло — сменили пароль, лежит сервер, не пускает Tor.
    ///
    /// Показывать надо там же, где состояние почты: молча переставшая
    /// работать почта выглядит поломкой приложения. Ни ошибкой, ни модальным
    /// окном это не является — сообщения при этом продолжают ходить
    /// остальными ступенями §5.4.
    MailLoginFailed {
        /// Что именно не вышло — словами, для показа.
        reason: String,
    },
    /// Почтовый сервер назвал свои пределы (§5.3).
    ///
    /// Приходит при входе на сервер и после каждой разборки ящика. То же
    /// самое отдаёт [`RatatoskClient::mail_status`] — событие двигает
    /// показанное, запрос отвечает пришедшему позже.
    ///
    /// Само по себе оно не новость и всплывающей подсказки не заслуживает:
    /// это состояние экрана настроек почты. Новостью становятся два вывода
    /// внутри — `crowded` и `carries_files`, — и оба означают, что вложения
    /// сейчас почтой не пойдут, а сообщения пойдут.
    MailLimits {
        /// Предел одного письма, байт. `None` — сервер не назвал.
        letter_bytes: Option<u64>,
        /// Занято в ящике, байт.
        mailbox_used: Option<u64>,
        /// Весь объём ящика, байт.
        mailbox_limit: Option<u64>,
        /// Места меньше, чем нужно одной передаче файла.
        crowded: bool,
        /// Поедут ли почтой файлы.
        carries_files: bool,
    },
    /// Сопряжение заведено — вот ссылка для QR (§13.4).
    ///
    /// **Показать обязательно и сразу.** Секретная половина ключа живёт
    /// только в этой ссылке: телефон её не хранит, повторить событие нечем.
    /// Не показали — сопряжение придётся заводить заново, а прежняя запись
    /// останется в списке мёртвой.
    PairingReady {
        /// Какое устройство.
        device_id: Vec<u8>,
        /// Ссылка `ratatosk:v0:pair:…` — прямо в QR.
        uri: String,
    },
    /// Сопряжение отозвано (§13.4).
    PairingRevoked {
        /// Какое устройство.
        device_id: Vec<u8>,
    },
    /// Десктоп подключился или отключился (§13.4).
    DeviceLink {
        /// Какое устройство.
        device_id: Vec<u8>,
        /// Есть ли сейчас канал.
        connected: bool,
    },
}

/// Что происходит с почтой прямо сейчас (§5.3, §5.4).
///
/// Пять состояний, и это ровно те пять ответов, которые человек может
/// получить на вопрос «почему не отправляется». Каждый лечится по-своему,
/// и слить их в «работает / не работает» значило бы оставить его наедине
/// с состоянием, из которого он не знает выхода.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMailState {
    /// Выключена человеком. Лечится переключателем.
    Off,
    /// Включена, но ящика нет. Лечится вводом настроек или регистрацией.
    NoAccount,
    /// Ящик есть, входим на сервер. Лечится ожиданием — секунды, через Tor
    /// десятки секунд.
    Connecting,
    /// Вошли: §5.4 выбирает почту для отправки.
    Ready,
    /// Сервер не пустил. Причина — в `detail`, и показать её обязательно.
    Failed,
}

/// Состояние почты целиком — то, что рисуется на экране настроек.
///
/// Запросом, а не только событиями, и это не удобство. События существуют
/// один раз: клиент, открывший экран через минуту после входа, не увидит
/// ничего и покажет пустоту вместо правды. А человек, пришедший туда,
/// спрашивает ровно одно — «почему не идёт», — и ответ обязан быть
/// на экране, а не в пропущенном уведомлении.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMailStatus {
    /// Что происходит.
    pub state: FfiMailState,
    /// Словами, если есть что сказать: причина отказа сервера.
    pub detail: Option<String>,
    /// Адрес ящика, если он заведён, — его показывают рядом с состоянием.
    pub address: Option<String>,
    /// Идёт ли почта через Tor.
    ///
    /// Здесь же, а не отдельным запросом, потому что показывается рядом:
    /// «работает» и «работает напрямую» — разные утверждения, и второе
    /// человек обязан видеть, не открывая настройки ящика (§2.2).
    pub via_tor: bool,
    /// Предел одного письма у **своего** сервера, байт.
    ///
    /// `None` — сервер не назвал, и это законно. Показывать в этом случае
    /// нечего: строка «предел: неизвестно» человеку не говорит ничего.
    pub letter_limit_bytes: Option<u64>,
    /// Занято в ящике, байт. `None` — сервер не умеет `QUOTA`.
    pub mailbox_used_bytes: Option<u64>,
    /// Весь объём ящика, байт. `None` — сервер не умеет `QUOTA`.
    pub mailbox_limit_bytes: Option<u64>,
    /// Места в ящике меньше, чем нужно одной передаче файла.
    ///
    /// Готовый вывод, а не проценты: считать порог в клиенте значило бы
    /// вынести протокольное правило выше границы §13.3. Пока это `true`,
    /// файлы почтой **не принимаются** — и человеку стоит сказать почему,
    /// иначе он увидит только застывшую полосу.
    pub mailbox_crowded: bool,
    /// Поедут ли почтой файлы.
    ///
    /// `false` означает, что сервер объявил предел письма меньше, чем
    /// весит письмо с куском файла. Сообщения при этом ходят как ходили —
    /// это ограничение только для вложений, и сказать надо именно так.
    pub carries_files: bool,
}

/// Что Tor сказал о себе последним (§5.2, §13.1).
///
/// Тот же смысл и та же причина, что у [`FfiMailStatus`]: событие двигает
/// индикатор, запрос отвечает тому, кто пришёл смотреть позже.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiTorStatus {
    /// Доля готовности, от 0 до 1.
    pub fraction: f32,
    /// Что происходит сейчас — словами arti.
    pub note: String,
    /// Почему подъём стоит, если он стоит.
    ///
    /// Пусто — «идёт, просто долго». Непусто — «встал, и вот причина».
    /// Снаружи эти два случая неотличимы, и §14 не разрешает о них молчать.
    pub blocked: Option<String>,
}

/// Настройки почтового ящика в том виде, в каком их показывает UI (§5.3).
///
/// Пароль здесь открытой строкой, и по-другому нельзя: его либо ввёл сам
/// человек, либо выдал сервер — и во втором случае это единственное место,
/// где он может его увидеть. Прятать его от владельца значило бы запереть
/// его в собственной почте.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMailAccount {
    /// Адрес вида `a7f3k9@chatmail.example`. Он же логин.
    pub address: String,
    /// Пароль.
    pub password: String,
    /// Имя IMAP-сервера.
    pub imap_host: String,
    /// Порт IMAP.
    pub imap_port: u16,
    /// Имя SMTP-сервера.
    pub smtp_host: String,
    /// Порт SMTP.
    pub smtp_port: u16,
    /// Идёт ли почта через Tor.
    pub via_tor: bool,
}

/// Одна ступень лестницы §5.4 глазами конкретного контакта.
///
/// Три признака, а не один «доступен», и это не подробность ради
/// подробности: они лечатся тремя разными действиями. `enabled` чинится
/// переключателем в приложении, `ready` — временем (Tor поднимается
/// десятки секунд), `addressable` — обменом карточками (§4.3) или тем,
/// что собеседник появится в общей сети (§5.1).
///
/// Слив их в одно слово, экран отвечал бы одинаково на три разных вопроса,
/// и человек чинил бы не то. Именно так и выглядит «сообщение не уходит,
/// а почему — непонятно».
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiRung {
    /// Какая ступень.
    pub transport: FfiTransport,
    /// Разрешена человеком.
    pub enabled: bool,
    /// Уже работает.
    pub ready: bool,
    /// Есть куда ехать: адрес в карточке или маяк в эфире.
    pub addressable: bool,
    /// Годится прямо сейчас — все три признака сразу.
    pub usable: bool,
}

/// Куда поедет следующее сообщение этому контакту — и почему не дальше.
///
/// **Вердикт считает ядро, и пересчитывать его в клиенте нельзя** (§13.3).
/// Лестница §5.4 живёт одним списком в `proto::transport_policy`, и по нему
/// же ходит настоящая отправка. Копия в Kotlin разойдётся с ней при первом
/// же изменении правил — молча: экран скажет «пойдёт почтой», а уедет
/// через onion.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiReachability {
    /// Ступени по порядку §5.4: LAN, onion, почта.
    pub rungs: Vec<FfiRung>,
    /// Ступень, которой уйдёт следующее сообщение. `None` — сейчас некуда.
    pub route: Option<FfiTransport>,
    /// Ступень, которая заберёт отправку, когда поднимется.
    ///
    /// Отвечает на «сообщение висит — оно уйдёт или нет». Непустое значение
    /// вместе с пустым `route` означает «уйдёт, надо подождать» — и показывать
    /// это надо спокойно. Оба пустые — ждать нечего: нужен адрес или
    /// переключатель, и человек может это сделать сам.
    pub rising: Option<FfiTransport>,
}

/// Сколько кадров от этого источника отброшено (§7.3).
///
/// Не показатель для списка контактов, а строка на экране «почему
/// не доходит». Считалось это с самого начала и не показывалось никому,
/// а между тем это **единственный** признак того, что кто-то шлёт
/// на устройство мусор от имени контакта: в переписке такие кадры
/// не появляются — они отбрасываются до неё.
///
/// Счётчики живут в памяти и обнуляются перезапуском: это наблюдение
/// за происходящим сейчас, а не улика. Ноль — обычное состояние; всплеск
/// стоит показать, но не как ошибку приложения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiAnomalies {
    /// Кадры с неизвестным `session_id`.
    ///
    /// Самая безобидная строка: так выглядит собеседник, переустановивший
    /// клиент, — его кадры зашифрованы сессией, которой у нас больше нет.
    pub unknown_session: u64,
    /// Кадры, не прошедшие проверку тега.
    pub bad_tag: u64,
    /// Кадры с непонятным содержимым.
    pub malformed: u64,
    /// Повторно предъявленные рукопожатия.
    pub handshake_replay: u64,
    /// Всего.
    pub total: u64,
}

/// Сопряжённый десктоп в том виде, в каком его показывает UI (§13.4).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPairedDevice {
    /// Идентификатор записи — им же отзывают сопряжение.
    pub device_id: Vec<u8>,
    /// Метка, которую человек дал устройству при сопряжении.
    pub label: String,
    /// Когда сопряжено, мс.
    pub paired_ms: u64,
    /// Когда последний раз подключалось, мс. Ноль — ни разу.
    pub last_seen_ms: u64,
    /// Есть ли канал прямо сейчас.
    pub connected: bool,
    /// Пора ли десктопу стереть кэш — тридцать суток без связи (§13.4).
    pub cache_expired: bool,
    /// Дотянется ли до этого устройства телефон вне общей сети (§13.4).
    ///
    /// **Признак, а не адрес.** Ложь значит «только дома» — законное
    /// и самое частое состояние, и показывать его надо как состояние,
    /// а не как поломку: «работает, когда телефон и ноутбук в одной сети».
    ///
    /// Иначе человек, открывший ноутбук в другом городе, видит вечное
    /// «подключаемся» и не знает, ждать ему или нет (§14).
    pub reachable_anywhere: bool,
}

/// Контакт в том виде, в каком его показывает UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContact {
    /// Статический ключ — им адресуются команды.
    pub peer_ik: Vec<u8>,
    /// Идентификатор чата 1:1 с этим контактом.
    pub chat_id: Vec<u8>,
    /// Отпечаток для сверки голосом (§3, §4.2).
    pub fingerprint: String,
    /// Имя из карточки. **Не доверенное** (§4.1): его задаёт собеседник,
    /// и UI обязан показывать его как подпись, а не как удостоверение.
    pub display_name: String,
    /// Как контакт подписал у себя пользователь, если подписал.
    ///
    /// Показывать надо его, когда оно есть: это единственное имя, которому
    /// в списке контактов можно верить, потому что его написал сам человек.
    /// По проводу оно не едет никогда, и собеседник о нём не знает.
    pub local_name: Option<String>,
    /// Сверен ли отпечаток голосом (§4.2).
    pub verified: bool,
    /// Виден ли контакт в локальной сети прямо сейчас (§5.1).
    ///
    /// То же самое, что `addressable` у ступени LAN в `reachability`, —
    /// и оставлено намеренно: это самый частый вопрос списка контактов
    /// («кто рядом»), и заставлять его искать нужную ступень в массиве
    /// значило бы менять удобство на стройность.
    ///
    /// **Не то же, что «есть связь».** Маяк говорит «устройство в эфире»;
    /// установлена ли сессия, отвечает `direct_channel`.
    pub seen_on_lan: bool,
    /// Слышен ли контакт в эфире Bluetooth прямо сейчас (0.4).
    ///
    /// Пара к [`FfiContact::seen_on_lan`], и заведена отдельным полем,
    /// а не слита с ним в «рядом где-нибудь», по той же причине, по какой
    /// они раздельны в ядре: это **два разных эфира**. Устройство бывает
    /// слышно в Bluetooth и невидимо в локальной сети — разные Wi-Fi,
    /// гостевая сеть с изоляцией клиентов — и наоборот.
    ///
    /// Показывать их человеку одним значком при этом можно и правильно:
    /// ему важно «рядом», а не «каким радио». Сливать их стоит **в UI**,
    /// где эту мысль видно, а не на границе, где потерялась бы разница,
    /// нужная §5.4.
    ///
    /// # У этого признака есть срок
    ///
    /// «Рядом» — знание о сейчас, и держится оно полторы минуты с
    /// последнего свидетельства (объявления или пришедшего кадра). Ушедший
    /// собеседник гаснет сам, и ядро сообщает об этом
    /// `ContactChanged` — перечитайте список.
    pub seen_on_bt: bool,
    /// Есть ли аватарка, которую **можно показать**.
    ///
    /// Учитывает §4.2: у несверенного контакта картинка может лежать
    /// в хранилище, но здесь всё равно `false`. Само изображение —
    /// [`RatatoskClient::avatar_of`]; здесь только признак, чтобы список
    /// чатов не тянул по тридцать килобайт на строку.
    pub has_avatar: bool,
    /// Onion-адрес из карточки (§5.2). `None` — адреса нет.
    ///
    /// Показывать его в списке контактов незачем — это пятьдесят шесть
    /// знаков, — а на карточке человека есть зачем: по нему видно, чем
    /// до него вообще можно достучаться.
    pub onion: Option<String>,
    /// Chatmail-адрес из карточки (§5.3). `None` — адреса нет.
    ///
    /// Отвечает на вопрос, который иначе не задать: дойдёт ли до человека
    /// сообщение, пока он не в сети. Без почтового адреса — **нет**, и это
    /// стоит сказать до того, как человек напишет и станет ждать.
    pub chatmail: Option<String>,
    /// Открытый ключ узла Yggdrasil из карточки (0.2). `None` — меша нет.
    ///
    /// Тридцать два байта, а не строка: адрес `200::/7` выводится из них
    /// однозначно, и хранить обе записи одного и того же значило бы
    /// однажды показать человеку одну, а соединиться по другой. Показывать
    /// его стоит так же, как onion, — на карточке человека, а не в списке.
    pub ygg: Option<Vec<u8>>,
    /// Реле nostr, которые объявляет **его** карточка (0.3).
    ///
    /// Туда уйдёт событие, когда §5.4 выберет ступень nostr: реле в карточке
    /// — это места, где владелец читает. Показывать стоит там же, где onion
    /// и ключ меша: на карточке человека, а не в списке. Пусто — карточка
    /// реле не называет, и мы положим на свои, надеясь на общее.
    pub nostr_relays: Vec<String>,
    /// Версия карточки, монотонная (§4.3).
    ///
    /// Диагностика: по ней видно, доехало ли до нас обновление адресов.
    /// В списке контактов ей делать нечего.
    pub card_version: u64,
    /// Когда контакт добавили, мс от эпохи.
    pub added_ms: u64,
    /// Куда сейчас уйдёт сообщение этому человеку и почему не дальше.
    pub reachability: FfiReachability,
    /// Живой прямой канал, если он есть (§5.4).
    ///
    /// **Не то же, что `seen_on_lan`.** Маяк говорит «устройство в эфире»,
    /// а это — «сессия установлена, кадры пойдут сейчас». Между ними
    /// рукопожатие, и на медленном канале это заметные секунды.
    ///
    /// Пусто при работающей почте — обычное дело, а не беда: почта прямым
    /// каналом не бывает по устройству, и квитанций (§9.4) по ней нет.
    pub direct_channel: Option<FfiTransport>,
    /// Отброшенные кадры от этого источника (§7.3).
    pub anomalies: FfiAnomalies,
}

/// Участник группы в том виде, в каком его рисуют (§11).
///
/// Три поля, и по отдельности ни одного не хватает: по ключу берётся лицо
/// ([`RatatoskClient::avatar_of`]) и открывается карточка, имя считает ядро
/// по §4.1, а «это я» из ключа выводится сравнением с собственным — то
/// самое протокольное знание, которое §13.3 держит ниже границы.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroupMember {
    /// Публичный `IK`.
    pub ik: Vec<u8>,
    /// Как его назвать. Пустым не бывает: у безымянного — начало отпечатка.
    pub name: String,
    /// Это мы сами.
    ///
    /// Показать вместо имени «вы» — дело клиента; ядро отвечает только
    /// на вопрос, кто это.
    pub mine: bool,
}

/// Права в канале, как их рисуют (фаза 2, §6.2).
///
/// Четыре булевых вместо битовой маски: маска на границе §13.3 означала бы,
/// что клиент знает номера битов, то есть кусок протокола. Порядок полей —
/// порядок §6.2.
///
/// **Незнакомое право сюда не попадает.** Биты, выданные сборкой новее
/// нашей, переживают чтение и запись документа (`channel::Rights`), но
/// показать их нечем: слова для них у нас нет. Выдавая права этой
/// записью, клиент выданное незнакомое **снимет** — и это честно:
/// он и правда не знает, что выдаёт.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannelRights {
    /// Публиковать в канал.
    pub write: bool,
    /// Впускать: выдавать ключ чтения (§6.5).
    pub admit: bool,
    /// Поворачивать ключ чтения, отсекая невписанных (§6.4).
    ///
    /// Это и есть исключение читателя; другого в канале нет.
    pub evict: bool,
    /// Править описательные поля представления.
    pub edit: bool,
}

/// Что клиент знает о канале сверх того, что знает о группе (фаза 2).
///
/// Плоская, как и всё здесь: правила §6 посчитаны ядром, наружу едет
/// то, что рисуют.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannel {
    /// Принятая версия представления. `0` — документа ещё нет.
    ///
    /// Ноль обычен и законен: по ссылке чат заводится сразу, а документ
    /// едет отдельно и вправе опоздать (§10.3). Рисовать тогда нечего,
    /// кроме ожидания, — названия у канала в этот момент тоже нет.
    pub version: u64,
    /// Порода (§6.1): `true` — открытый, `false` — по приглашению.
    ///
    /// `null` — документа нет, и **обещание ссылки сюда не едет
    /// нарочно**: ссылка ничем не подписана (§10.2). Показать обещанное
    /// установленным значило бы сказать «открытый канал» там, где
    /// владелец обещал другое.
    pub open: Option<bool>,
    /// Владелец: чья подпись здесь действительна (§10.3, шаг 3).
    pub owner_ik: Vec<u8>,
    /// Что вправе делать **мы** прямо сейчас (§6.2, §6.3).
    ///
    /// Считается с учётом срока и правила «владельцу всё» — тем же
    /// местом, каким права спрашивает отправка. Поле ввода стоит гасить
    /// по `rights.write`, а не по составу: в канале состоять и мочь
    /// говорить — разные вещи.
    pub rights: FfiChannelRights,
    /// До какого момента действует наша выдача, мс. `0` — срока нет:
    /// мы владелец либо прав нам не давали.
    ///
    /// Показывать стоит заранее: §6.3 обещает, что отказ не наступает
    /// внезапно.
    pub rights_until_ms: u64,
    /// Сколько бит работы стоит слово (§11). `0` — работа не требуется.
    ///
    /// Цену назначает владелец, и отказ [`FfiChannelRefusal::PowTooHard`]
    /// приходит **до** отправки, а не после.
    pub pow_bits: u32,
    /// Ждём впуска владельцем (§10.4, §10.5).
    ///
    /// Показывать надо именно ожидание, а не пустой чат: §10.5 требует
    /// различать «заявка отправлена» и «впустили» — и после перезапуска
    /// тоже.
    pub awaiting: bool,
    /// Есть ли чем читать: хоть одно поколение ключа чтения (§6.4).
    ///
    /// `false` означает, что сообщения приедут и не откроются. Рисовать
    /// тогда надо ожидание, а не пустую ленту.
    pub readable: bool,
    /// Номер новейшего известного нам поколения ключа (§6.4).
    pub generation: u64,
    /// Показывать ли кнопку «повернуть ключ» (§6.4).
    ///
    /// Считает ядро по трём правилам разом: порода, право «исключать»
    /// и нижний предел в неделю. Отдаётся затем же, зачем
    /// [`FfiGroup::free_slots`], — чтобы отказ не понадобился.
    pub may_rotate: bool,
    /// Сколько миллисекунд от владельца ничего не приходило (§6.3).
    ///
    /// `null` — не приходило ни разу; это не «давно», а «считать ещё
    /// нечего»: у свежей подписки владелец просто не успел ничего
    /// сказать. У своего канала тоже `null`.
    ///
    /// **Утверждение — «от владельца ничего не приходило», а не
    /// «владелец не выходил на связь».** §6.3 выводит метку из записи
    /// пира со сроком годности, а каталога пиров в ядре нет; здесь
    /// считается наш приём. Текст обязан говорить именно это.
    pub owner_quiet_ms: Option<u64>,
    /// Молчание перешло порог §6.3 (два месяца).
    ///
    /// Порог задан спекой и живёт в ядре: вычитание дат на этой стороне
    /// границы означало бы второе место, где он записан.
    pub owner_unseen: bool,
    /// Сколько наших выдач истекает меньше чем через месяц (§6.3).
    ///
    /// **Только у владельца**, у остальных `0`: продлевать чужое нечем,
    /// и число, которое не к чему применить, на экране только пугает.
    /// §6.3 велит продлевать заранее — иначе требование превращается
    /// в «зайти строго на третий месяц».
    pub grants_expiring: u32,
    /// Сколько у нас **сейчас** живых источников этого канала (§7.5.1).
    ///
    /// Ноль — это §15: «никто из достижимых не отдаёт этот канал».
    /// Не «канал пуст» и не «мы без сети»: связь может быть, а брать
    /// блоки не у кого.
    ///
    /// **Владелец считается источником в канале по приглашению**: там
    /// он развозит по составу (§3.2), привязки к нему не заводится.
    /// Поэтому у впущенного читателя здесь всегда хотя бы единица,
    /// а о том, жив ли владелец, отвечает [`FfiChannel::owner_quiet_ms`].
    /// В открытом канале состава нет, и ноль здесь — настоящий ноль.
    ///
    /// `null` — канал наш: себе не раздают.
    pub sources_now: Option<u32>,
    /// Сколько годных записей каталога мы знаем (§7.5).
    ///
    /// Рядом с [`FfiChannel::sources_now`] нарочно: «раздавать некому»
    /// и «есть кому, а мы не дозвонились» — разные беды, и снаружи
    /// они неотличимы.
    pub seeds_known: u32,
    /// Сколько объявленных блоков мы ждём прямо сейчас (§7.1, шаг 4).
    ///
    /// «Видимая дыра» из §15: сосед позвал, значит блок есть, а у нас
    /// его нет. Число живое — приедет, и оно уменьшится само.
    ///
    /// Пропуск, видимый по номерам в чужом have-векторе, сюда **не**
    /// попадает: у читателя такие дыры есть всегда (адресные блоки
    /// чужих), и счётчик не обнулялся бы никогда.
    pub awaiting_blocks: u32,
    /// Владельцу: ключу чтения больше месяца (§6.4).
    ///
    /// У остальных `false`: чужой ключ повернуть нечем.
    pub rotation_overdue: bool,

    /// Что показывать, пока канал не открылся (§10.5).
    ///
    /// `null` — ждать нечего: канал открыт, либо это не канал.
    /// Отсчёт идёт от **первой** просьбы и повтором не двигается.
    ///
    /// Слова — [`channel_waiting_text`], кнопка «сообщить, когда
    /// откроется» — [`channel_waiting_offers_a_notification`].
    pub waiting: Option<FfiWaiting>,
    /// Чем объяснить тишину — один признак на экран (§15).
    ///
    /// Складывается из полей выше и ничего к ним не добавляет: клиенту
    /// нужен **один** ответ на вопрос «почему пусто», а выбор главного
    /// из шести — то самое правило, которое в каждом клиенте написали бы
    /// по-своему.
    pub signal: FfiChannelSignal,
}

/// Настройка уведомлений чата (§14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotify {
    /// Молчать ли по выбору человека.
    pub silent: bool,
    /// До какого момента, мс. `0` — бессрочно.
    ///
    /// Показывать стоит: «молчу» и «молчу до утра» — разные вещи,
    /// и вторая сама кончится.
    pub until_ms: u64,
    /// Говорить ли об этом чате **сейчас**.
    ///
    /// Считает ядро, а не клиент: срок истекает сам, и вычитание дат
    /// на этой стороне границы означало бы второе место, где живёт
    /// одно правило (§13.3).
    ///
    /// Отличается от `!silent` ровно истёкшим сроком — и это самый
    /// частый случай: «замолчать до утра» человек ставит чаще всего,
    /// а снять забывает.
    pub speaks_now: bool,
}

/// Что показывать, пока канал не открылся (§10.5).
///
/// Зеркало `channel::Waiting`. **Экран переключается раньше механизма**:
/// §10.5 говорит это прямым текстом — «отметка 0:30 меняет только
/// надпись». Расписание повторов живёт своей жизнью, и связывать их
/// клиенту не нужно.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiWaiting {
    /// До полуминуты: «открываем канал».
    Opening,
    /// От полуминуты до пяти минут: «дольше обычного».
    Longer,
    /// От пяти минут до суток: «медленный путь, это часы».
    SlowPath,
    /// Сутки прошли: «не отвечает», и ядро перестало стучать.
    NoAnswer,
}

/// Слова к состоянию ожидания (§15, §10.5).
#[uniffi::export]
#[must_use]
pub fn channel_waiting_text(waiting: FfiWaiting) -> String {
    core_waiting(waiting).ui_text().to_owned()
}

/// Показывать ли кнопку «сообщить, когда откроется» (§10.5).
///
/// Появляется вместе с медленным путём: ждать часами, глядя в экран,
/// никто не станет.
#[uniffi::export]
#[must_use]
pub fn channel_waiting_offers_a_notification(waiting: FfiWaiting) -> bool {
    core_waiting(waiting).offer_a_notification()
}

/// Текст §15 про медленный путь — он же [`FfiWaiting::SlowPath`].
///
/// Отдельным именем, потому что §15 называет его отдельно; строка
/// берётся оттуда же, где живёт состояние, и второй её копии нет.
#[uniffi::export]
#[must_use]
pub fn channel_slow_path_notice() -> String {
    ratatosk_proto::channel::Waiting::SlowPath.ui_text().to_owned()
}

/// Ожидание наружу.
fn waiting_of(waiting: ratatosk_proto::channel::Waiting) -> FfiWaiting {
    use ratatosk_proto::channel::Waiting;

    match waiting {
        Waiting::Opening => FfiWaiting::Opening,
        Waiting::Longer => FfiWaiting::Longer,
        Waiting::SlowPath => FfiWaiting::SlowPath,
        Waiting::NoAnswer => FfiWaiting::NoAnswer,
    }
}

/// Ожидание обратно — ради слов к нему.
fn core_waiting(waiting: FfiWaiting) -> ratatosk_proto::channel::Waiting {
    use ratatosk_proto::channel::Waiting;

    match waiting {
        FfiWaiting::Opening => Waiting::Opening,
        FfiWaiting::Longer => Waiting::Longer,
        FfiWaiting::SlowPath => Waiting::SlowPath,
        FfiWaiting::NoAnswer => Waiting::NoAnswer,
    }
}

/// Почему канал молчит — признак интерфейса (§15).
///
/// Зеркало `channel::Signal`: правило, по которому из фактов выбирается
/// главный признак, живёт в ядре (`ChannelFacts::signal`), а здесь
/// только перевод наружу. Повтори мы выбор тут, он зажил бы в двух
/// местах и разошёлся бы на первой правке.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiChannelSignal {
    /// Объяснять нечего: канал живёт обычной жизнью.
    ///
    /// Это не «всё доехало»: пустой канал, в котором просто ничего
    /// не говорили, выглядит так же, и обещать обратное ядру нечем.
    Fine,
    /// Ждём впуска владельцем (§10.4, §10.5).
    Awaiting,
    /// Читать нечем: ключа чтения нет (§6.4).
    NotReadable,
    /// Никто из достижимых не отдаёт этот канал (§7.5, §15).
    NobodyServes,
    /// Раздающие известны, но ни один сейчас не отвечает (§7.5.1).
    ///
    /// Отдельно от [`FfiChannelSignal::NobodyServes`], и разница
    /// не косметическая: там раздавать некому и помочь может только
    /// новый сид, здесь дело в связи — и человеку стоит проверить её,
    /// а не искать ссылку заново.
    SeedsUnreachable,
    /// От владельца ничего не приходило дольше порога §6.3.
    OwnerUnseen,
    /// Блоки объявлены и ещё едут (§7.1, шаг 4).
    Waiting,
    /// Владельцу: поворот ключа просрочен (§6.4).
    RotationOverdue,
}

/// Что стоит предпросмотр канала (§15, §10.3).
///
/// Показывается **до** [`RatatoskClient::preview_channel`] — это
/// единственный момент, когда человек ещё может отказаться бесплатно.
#[uniffi::export]
#[must_use]
pub fn channel_preview_notice() -> String {
    ratatosk_proto::channel::PreviewConsequences::ui_text().to_owned()
}

/// Слова к сообщению, которого нет у владельца канала (§14, §7.3).
///
/// На границе, а не в клиенте, по той же причине, что остальные тексты:
/// строка обязана говорить то, что ядро на самом деле знает. А знает
/// оно ровно одно — «до владельца это не доехало», — и всякая более
/// сильная формулировка («удалено», «подделка») была бы выдумкой.
#[uniffi::export]
#[must_use]
pub fn message_not_in_the_channel_text() -> String {
    "Этого сообщения нет у владельца канала: до него оно не доехало. \
     Вы его видите, а пришедший в канал завтра — нет."
        .to_owned()
}

/// Точные слова к признаку канала (§15).
///
/// На границе, а не в клиенте, по той же причине, что [`honest_notices`]
/// и [`channel_refusal_text`]: признак обязан говорить то, что протокол
/// на самом деле знает, а строка в Kotlin разошлась бы с поведением
/// на первой же правке.
#[uniffi::export]
#[must_use]
pub fn channel_signal_text(signal: FfiChannelSignal) -> String {
    core_signal(signal).ui_text().to_owned()
}

/// Выдача права, как её рисуют владельцу (фаза 2, §6.2, §6.3).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannelGrant {
    /// Кому выдано.
    pub who: Vec<u8>,
    /// Как его назвать. Пустым не бывает: у безымянного — начало отпечатка.
    pub name: String,
    /// Что выдано.
    pub rights: FfiChannelRights,
    /// До какого момента, мс.
    pub until_ms: u64,
    /// Действует ли прямо сейчас (§6.3).
    ///
    /// Истёкшая выдача остаётся в документе до следующей версии — снятие
    /// выражается отсутствием строки, а не надгробием, — и показывать её
    /// действующей нельзя.
    pub live: bool,
}

/// Кто раздаёт канал — строка каталога (фаза 2, §7.5).
///
/// Адреса наружу **не едут**: набирает ядро (§13.3), а на экране это
/// строка «такой-то раздаёт».
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannelSeed {
    /// Чей адрес объявлен.
    pub who: Vec<u8>,
    /// До какого момента запись годна, мс (§7.5).
    ///
    /// Показывать стоит: «раздаёт» с истекающим сроком означает
    /// «раздавал», и разница видна только по нему.
    pub valid_until_ms: u64,
    /// Сошлась ли подпись записи.
    ///
    /// Ложь означает «проверить было нечем» — карточки сида у читателя
    /// может не быть вовсе (§3.2), — а не «подделка». Поддельную отсеет
    /// владелец, который карточки знает.
    pub verified: bool,
}

/// Заявка на подписку — то, что видит владелец (фаза 2, §10.4).
///
/// Ответ на неё один — впуск ([`RatatoskClient::admit_to_channel`]).
/// Отказа как сообщения не бывает: §10.4 знает только впуск, а молчание
/// владельца и есть отказ. Рисовать поэтому надо список и кнопку
/// «впустить», а не пару «принять/отклонить»: вторая обещала бы
/// просящему ответ, которого он не получит.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannelRequest {
    /// Кто просится.
    pub who: Vec<u8>,
    /// Как его назвать. Карточка приехала рукопожатием (§8.2), и он
    /// **непроверенный контакт**, как всякий, кто написал первым.
    pub name: String,
    /// Когда попросил впервые, мс. Повтор заявки время не двигает:
    /// §10.5 меряет ожидание от первой просьбы.
    pub received_ms: u64,
}

/// Запись о впуске — учёт владельца (фаза 2, §6.5).
///
/// **Учёт, а не состав.** «Кто кого впустил» и «кто в канале» — разные
/// вопросы с разными источниками. Впущенный мимо учёта здесь не виден
/// вовсе: впускающий держит ключ и может передать его мимо протокола,
/// и обещать обратное значило бы обещать невыполнимое (§6.5).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiChannelAdmit {
    /// Кого впустили.
    pub who: Vec<u8>,
    /// Как его назвать.
    pub name: String,
    /// Кто впустил.
    pub admitted_by: Vec<u8>,
    /// Как назвать впустившего.
    pub admitted_by_name: String,
    /// Какое поколение ключа чтения ему тогда отдали.
    ///
    /// Именно выданное, а не нынешнее: поворот случится, номера
    /// разойдутся, и запись останется утверждением о прошлом.
    pub generation: u64,
    /// Когда запись легла к нам, мс.
    pub created_ms: u64,
}

/// Что клиент знает о группе (§11).
///
/// Плоская, как и всё на этой границе: `Group` — тип протокольного слоя,
/// и отдавать его наружу значило бы пустить решения о составе выше
/// границы §13.3. Наружу едет то, что рисуют.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroup {
    /// Идентификатор чата — им адресуются команды.
    pub chat_id: Vec<u8>,
    /// Название.
    ///
    /// **Общее**: его задаёт создатель, оно приезжает новичку при
    /// вступлении и расходится переименованием. Менять вправе только
    /// создатель — кнопку стоит показывать при `mine && joined`.
    pub title: String,
    /// Когда заведена, мс.
    pub created_ms: u64,
    /// Состав — записями, а не голыми ключами.
    ///
    /// **Ключей было мало.** Клиент искал имя по ключу перебором контактов
    /// — и не находил там **себя**: своей карточки в списке контактов нет,
    /// и хозяин телефона показывался «неизвестным участником». Поэтому имя
    /// и признак «это я» считает ядро, а не клиент (§13.3).
    ///
    /// Карточки к чужим по-прежнему ищутся в списке контактов: участники,
    /// узнанные при вступлении, заводятся **несверенными** (§4.2), и UI
    /// обязан показывать их так же, как всякий несверенный контакт.
    pub members: Vec<FfiGroupMember>,
    /// Создатель ли мы.
    ///
    /// **Выходом не снимается**: создатель, ушедший из группы, остаётся
    /// её создателем и, вернувшись, снова сможет исключать. Поэтому
    /// «показывать ли исключить» — это `mine && joined`, а не `mine`.
    /// Считается ядром, а не клиентом по сравнению ключей: правило одно
    /// и живёт в одном месте (§13.3).
    pub mine: bool,
    /// Состоим ли мы в группе сейчас.
    ///
    /// **Единственный честный признак того, что чат ещё наш.** Вывести
    /// его из [`FfiGroup::members`] поиском своего ключа клиент, конечно,
    /// может — но это ровно то знание о протоколе, которое §13.3 держит
    /// ниже границы, и первая же сборка, забывшая про выход, показала бы
    /// поле ввода там, где писать нельзя.
    ///
    /// `false` покрывает два случая, и различать их клиенту незачем:
    /// мы вышли сами и нас исключили. Показывать надо одно и то же —
    /// переписку без поля ввода. Что делать дальше, тоже одно: позвать
    /// обратно вправе любой участник, и попросить об этом можно только
    /// вне протокола.
    ///
    /// Переписка при этом остаётся, и группа остаётся в списке чатов:
    /// уход из разговора не стирает сказанное.
    pub joined: bool,
    /// Метка аватарки группы; `0` — показывать нечего.
    ///
    /// **Метка, а не признак «есть картинка»**: булево на смену картинки
    /// не реагирует, и клиент показывал бы прежнее лицо до перезапуска.
    /// Изменилась метка — перечитать [`RatatoskClient::group_avatar`].
    ///
    /// Ноль покрывает два случая — картинку не ставили и картинку сняли,
    /// — и различать их клиенту незачем: рисовать по ним одно и то же.
    ///
    /// **Правила §4.2 у группы нет.** В отличие от лица контакта, картинка
    /// группы показывается всем участникам, сверенным и нет: она отвечает
    /// не на вопрос «кто этот человек», а на вопрос «какой это разговор».
    /// Участников же ядро заводит несверенными (§11.5), и правило §4.2
    /// означало бы «картинки почти никогда нет».
    pub avatar_ms: u64,
    /// Сколько **новых** человек ещё поместится (§18.4).
    ///
    /// Отдаётся затем, чтобы отказ не понадобился: с этим числом клиент
    /// гасит «добавить» заранее и говорит, сколько мест осталось, вместо
    /// того чтобы объясняться после неудачной попытки. Упёршемуся всё
    /// равно ответит [`RatatoskError::GroupFull`] — но это ответ на гонку,
    /// а не обычный путь: состав меняется и у соседа.
    ///
    /// `0` у полной группы и у той, из которой мы вышли: звать оттуда
    /// мы всё равно не вправе.
    pub free_slots: u32,
    /// Всё, чем канал отличается от группы (фаза 2, §6, §10).
    ///
    /// `null` у обычной группы. Признак «это канал» выражен **наличием
    /// записи**, а не отдельным булевым полем: рисовать канальный экран
    /// не по чему, если записи нет, и два источника одного ответа
    /// однажды разошлись бы.
    ///
    /// Всё групповое при этом остаётся верным: у канала есть состав,
    /// название и создатель, потому что канал **и есть** группа со вторым
    /// профилем (§3.2). Разница не в том, что это, а в том, что с этим
    /// можно.
    pub channel: Option<FfiChannel>,
}

/// Сообщение в том виде, в каком его показывает UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessage {
    /// Идентификатор.
    pub msg_id: Vec<u8>,
    /// Текст.
    pub body: String,
    /// Своё ли сообщение.
    ///
    /// Считается здесь, а не в клиенте: сравнение с собственным `IK` —
    /// протокольное знание, и §13.3 не разрешает ему подниматься выше.
    pub mine: bool,
    /// Как подписать автора — или `None`, если подпись выводится из `mine`.
    ///
    /// **`None` означает «выводится», а не «неизвестно».** В переписке
    /// двоих автор исчерпывается признаком «своё ли»: не своё — значит
    /// собеседника, а его имя уже стоит заголовком чата. В группе так
    /// нельзя — «не своё» там означает одного из тридцати двух, — и потому
    /// `Some` приходит ровно у групповых сообщений.
    ///
    /// Имя считает ядро: местное имя (§4.1) вытесняет имя из карточки,
    /// а участник, чья карточка ещё не доехала (§11.5), подписывается
    /// началом отпечатка. Пустой строки здесь не бывает никогда.
    ///
    /// Своё сообщение в группе тоже подписано — своим именем из карточки.
    /// Показать вместо него «вы» клиент вправе: для этого у него `mine`.
    pub author: Option<String>,
    /// Есть ли это сообщение у владельца канала (§7.2, §7.3).
    ///
    /// `null` — судить не по чему: это не канал, канал наш собственный,
    /// вектор от владельца ещё не приезжал, либо номер лежит **вне**
    /// того, что владелец о себе сказал (архив обрезается окном §9.3,
    /// и о старом он молчит не потому, что его нет).
    ///
    /// `false` означает ровно одно: **до владельца это не доехало**,
    /// и пришедший в канал завтра этого не увидит. Не «удалили» —
    /// удаления §11.4 у канала нет вовсе — и не «подделка»: подпись
    /// проверена, иначе сообщение не показалось бы.
    ///
    /// Слова к метке — [`message_not_in_the_channel_text`]; писать свои
    /// не надо, они разойдутся с поведением на первой же правке.
    pub in_the_channel: Option<bool>,
    /// Ключ автора — рядом с именем и по тому же правилу.
    ///
    /// Нужен не для подписи, а для всего, что к автору привязано:
    /// лицо ([`RatatoskClient::avatar_of`] спрашивает по ключу), переход
    /// к карточке, склейка подряд идущих сообщений одного человека.
    /// Без него клиент умел бы только напечатать имя.
    ///
    /// `None` там же, где и [`FfiMessage::author`]: в переписке двоих
    /// автор и так известен.
    pub author_ik: Option<Vec<u8>>,
    /// Физическая компонента метки порядка (§9.1), миллисекунды.
    ///
    /// Показывать её как время получения можно, а сортировать по ней —
    /// нет: порядок задаёт HLC целиком, и он уже применён к списку.
    pub wall_ms: u64,
    /// Судьба отправки (§9.4).
    ///
    /// `None` у **принятых** сообщений, и это не пропуск: статус — это судьба
    /// отправки, а принятое уже здесь. Рисовать у чужого сообщения галочку
    /// значит показать пользователю то, чего протокол не утверждает.
    pub status: Option<FfiDeliveryStatus>,
    /// Когда сообщение правили. `None` — не правили.
    ///
    /// Показывать отметку **обязательно**: прежнего текста нет ни у кого,
    /// и без отметки подмена слов в истории выглядела бы так, будто их такими
    /// и написали. §14 это запрещает.
    pub edited_at_ms: Option<u64>,
    /// Переслано из другого разговора.
    ///
    /// Пометку показывать обязательно, а имени автора здесь нет намеренно:
    /// при пересылке подпись не сохраняется, и «переслано от N» было бы
    /// утверждением, которое никто не может проверить.
    pub forwarded: bool,
    /// Реакции на сообщение — по одной от человека.
    pub reactions: Vec<FfiReaction>,
    /// Вложения. К одному сообщению их может быть несколько (§10).
    pub files: Vec<FfiFile>,
    /// Сообщение, на которое это отвечает. `None` — ответом не является.
    ///
    /// Едет **ссылка**, а не отрывок цитаты: цитату клиент берёт из своей
    /// копии — [`RatatoskClient::message`], если её нет в загруженном окне.
    /// Подделать её поэтому нельзя.
    ///
    /// Ссылка **мягкая**: сообщения с таким `msg_id` может не быть — удалено,
    /// не дошло, вычищено уборкой. Тогда клиент обязан сказать «сообщение
    /// недоступно», а не придумывать текст и не прятать сам ответ.
    pub reply_to: Option<Vec<u8>>,
    /// Присланная карточка контакта, если это сообщение — она.
    pub shared_contact: Option<FfiSharedContact>,
}

/// Карточка контакта, присланная в чат (§4.1, дополнение).
///
/// **Проверить её нечем, и подпись бы не помогла.** Голая карточка не
/// подписана — ни здесь, ни в QR-коде: она *есть* заявление «вот мои ключи»,
/// а доверие к нему берётся из канала. Отправитель мог завести пару ключей
/// сам и назвать её чужим именем; тот, чьей карточкой делятся, ничего
/// не подписывал и не мог — он не знает, что ею делятся.
///
/// Что из этого обязан сделать клиент:
///
/// * показать [`FfiSharedContact::fingerprint`] рядом с именем — это
///   единственное, что человек может проверить сам, голосом (§4.2);
/// * сказать, **кто** прислал карточку (это видно по чату, и это единственное
///   знание, на котором можно принимать решение);
/// * не изображать проверенность: добавленный отсюда контакт непроверен
///   всегда, даже если приславший у вас сверен. Доверие не транзитивно.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSharedContact {
    /// Чей контакт.
    pub peer_ik: Vec<u8>,
    /// Имя из карточки. Выбрал его сам владелец — **не доверенное** (§4.1).
    pub display_name: String,
    /// Отпечаток для сверки голосом (§3, §4.2). Показывать обязательно.
    pub fingerprint: String,
    /// Этот человек уже есть в контактах.
    ///
    /// Тогда добавлять нечего, и кнопки быть не должно: присланная карточка
    /// **не обновляет** известный контакт — ни адреса, ни имя. Иначе кто
    /// угодно прислал бы «карточку версии 99» со своим адресом и увёл
    /// маршрут на себя.
    pub already_known: bool,
    /// Это наша собственная карточка, вернувшаяся к нам.
    ///
    /// Добавлять себя в контакты нечего; показать «это вы» честнее, чем
    /// нарисовать кнопку, которая ничего не делает.
    pub mine: bool,
}

/// Своя карточка в том виде, в каком её показывают человеку (§4.1, §4.3).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiOwnCard {
    /// Ссылка `ratatosk:v0:…` — она же содержимое QR.
    pub uri: String,
    /// Версия карточки. Растёт при каждой смене адресов (§4.3).
    ///
    /// Клиенту нужна ровно для одного: заметить, что показанный QR устарел.
    pub version: u64,
    /// Onion-адрес (§5.2). Пустая строка — Tor ещё не поднят.
    ///
    /// Пустоту стоит показать словами, а не пропуском: «пока только локальная
    /// сеть» — правда о том, где вас найдут, и человеку она важнее, чем
    /// аккуратный экран.
    pub onion: String,
    /// Почтовый адрес (§5.3). Пустая строка — ящика нет.
    pub chatmail: String,
    /// Открытый ключ узла Yggdrasil (0.2). Пусто — меша нет.
    ///
    /// В ссылке он уже есть — карточка везёт его сама, — а здесь лежит
    /// отдельно затем же, зачем onion: показать человеку, чем до него
    /// вообще можно достучаться, не разбирая ссылку глазами.
    pub ygg: Vec<u8>,
    /// Открытый ключ nostr (0.3). Пусто — ступень ни разу не включали.
    ///
    /// Байтами, а не строкой `npub1…`: строку отдаёт
    /// [`RatatoskClient::nostr_npub`], и держать два представления одного
    /// ключа значило бы однажды показать одно, а подписывать другим.
    pub nostr: Vec<u8>,
    /// Реле nostr, которые объявляет эта карточка (0.3).
    ///
    /// Именно объявленные, а не названные: сюда собеседник будет класть
    /// события. Разбор различия — у [`RatatoskClient::nostr_advertised_relays`].
    pub nostr_relays: Vec<String>,
}

/// Открытое на чтение вложение (§10.2).
///
/// Живёт отдельно от клиента и не занимает ядро: читать можно из фонового
/// потока сколько угодно долго, и переписка при этом идёт своим ходом.
/// Ключ файла остаётся внутри — наружу выходят только расшифрованные байты.
///
/// Это **снимок**: число кусков и ключ берутся в момент открытия. Файл,
/// который дозагружается прямо сейчас, читается ровно настолько, насколько
/// успел приехать; чтобы увидеть остальное, надо открыть заново.
#[derive(uniffi::Object)]
pub struct FfiFileReader {
    reader: ratatosk_core::FileReader,
}

#[uniffi::export]
impl FfiFileReader {
    /// Сколько всего кусков.
    pub fn chunk_total(&self) -> u64 {
        self.reader.chunk_total()
    }

    /// Размер файла целиком.
    pub fn size_bytes(&self) -> u64 {
        self.reader.size_bytes()
    }

    /// Своё ли это вложение — то, которое отправляли мы.
    ///
    /// У своего вложения байты берутся из исходника по пути, а не из
    /// принятого: отправитель ничего у себя не запечатывал. Отсюда разница
    /// в поведении, о которой стоит знать: свой файл перестаёт открываться,
    /// если человек удалил или перенёс исходник, — ядро его не копировало.
    pub fn own(&self) -> bool {
        self.reader.own()
    }

    /// Расшифрованный кусок. `None` — показать нечего.
    ///
    /// Куски идут подряд, от нуля до `chunk_total() - 1`; размер каждого,
    /// кроме последнего, — [`FfiFileReader::chunk_bytes`].
    ///
    /// Вызывать **не из UI-потока**: расшифровка мебибайта — это работа.
    /// Ядру она больше не мешает, а вот отрисовке помешает.
    pub fn chunk(&self, index: u64) -> Result<Option<Vec<u8>>, RatatoskError> {
        self.reader.chunk(index).map_err(|error| RatatoskError::internal(error.to_string()))
    }

    /// Каким куском нарезан **этот** файл.
    ///
    /// Своё число у каждого файла, а не общее: по эфиру кусок вчетверо
    /// меньше килобайта (класс L туда не доходит вовсе), а у пересланного
    /// нарезку выбрал чужой аппарат. Свободная функция [`chunk_bytes`]
    /// отвечает на другой вопрос — «каким куском режем **мы** прямо
    /// сейчас», — и для показа принятого файла не годится.
    #[must_use]
    pub fn chunk_bytes(&self) -> u32 {
        self.reader.chunk_bytes()
    }
}

/// Что убрала уборка осиротевших вложений (§12).
///
/// Три числа, а не одно: целые вложения без записи в базе — след удалённой
/// переписки, обрывки — след процесса, убитого системой между записью чанка
/// и отметкой о нём. Человеку показывают обычно только `bytes`, но остальные
/// два стоит писать в журнал: по ним видно, что именно течёт.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSwept {
    /// Сколько вложений убрано целиком.
    pub files: u64,
    /// Сколько отдельных чанков убрано.
    pub chunks: u64,
    /// Сколько байт освободилось.
    pub bytes: u64,
}

/// Что именно вывозить (§12).
///
/// Три области, и выбор между ними — не настройка «поменьше», а разные
/// задачи. Полный архив переносит переписку целиком и весит как она.
/// Без вложений — то же, но на порядок легче: уезжает почтой, а файлы
/// остаются на прежнем устройстве. Граф — только знакомства: с ним человек,
/// сменивший телефон, не теряет **связей**, даже если готов расстаться
/// с историей.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FfiExportScope {
    /// Переписка со вложениями.
    Everything,
    /// Переписка без вложений.
    WithoutAttachments,
    /// Только контакты с их адресами и своя идентичность.
    SocialGraph,
}

impl From<FfiExportScope> for ratatosk_core::ExportScope {
    fn from(scope: FfiExportScope) -> ratatosk_core::ExportScope {
        match scope {
            FfiExportScope::Everything => ratatosk_core::ExportScope::Everything,
            FfiExportScope::WithoutAttachments => ratatosk_core::ExportScope::WithoutAttachments,
            FfiExportScope::SocialGraph => ratatosk_core::ExportScope::SocialGraph,
        }
    }
}

/// Что уехало в вывезенный архив переписки (§12).
///
/// **Ключ показать обязательно и обязательно сразу.** Он здесь не для
/// журнала: без него архив не открывается нигде, а второй раз этот же
/// архив не спросишь. Клиент, который положит его в лог и не покажет
/// человеку, отдаст ему файл, который никогда не откроется.
///
/// Строкой, а не байтами: ключ выходит наружу ровно затем, чтобы его
/// переписали с экрана, и вид этой строки — часть решения §12.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiExported {
    /// Куда лёг архив.
    pub path: String,
    /// Ключ для показа человеку: base32 группами по четыре.
    ///
    /// Отдаётся **всегда**, в том числе когда архив заперт фразой: это
    /// второй вход, и место ему — в менеджере паролей.
    pub key_text: String,
    /// Заперт ли архив фразой.
    ///
    /// От этого зависит, **что** показывать. С фразой ключ — запасной вход
    /// «на всякий случай», и человек вправе его не записывать. Без фразы
    /// ключ единственный: потерять его значит потерять архив, и строка
    /// на экране обязана звучать иначе.
    pub locked_by_phrase: bool,
    /// Сколько вложений уехало вместе с базой.
    pub files: u64,
    /// Сколько байт в архиве.
    pub bytes: u64,
}

/// Вложение в том виде, в каком его показывает UI.
///
/// Байтов здесь нет: файл может весить гигабайты, а список чата рисуется
/// целиком. Содержимое берётся у [`RatatoskClient::open_file`] по куску,
/// превью — [`RatatoskClient::preview_of`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiFile {
    /// Идентификатор — им адресуются команды и чтение содержимого.
    pub file_id: Vec<u8>,
    /// Имя для показа. Задал его собеседник, поэтому **путём его считать
    /// нельзя**: ядро проверяет, что в нём нет разделителей, но сохранять
    /// файл под этим именем клиент обязан через системный выбор места.
    pub name: String,
    /// Размер открытого содержимого.
    pub size_bytes: u64,
    /// Входящий файл. У исходящего показывать «принять» нечего.
    pub incoming: bool,
    /// Принят к загрузке — автоматически по порогу или человеком.
    pub accepted: bool,
    /// Собран целиком.
    pub complete: bool,
    /// Сколько чанков уже принято — и сколько всего. Это и есть ход передачи;
    /// в байтах он получается умножением на [`FfiFile::chunk_bytes`].
    ///
    /// **Умножать на свободную функцию [`chunk_bytes`] нельзя**, и это
    /// не придирка: нарезка у файла своя (§10.2), у принятого по эфиру она
    /// в двести с лишним раз мельче, а у пересланного вообще выбрана чужим
    /// аппаратом. Общим числом ход такой передачи показался бы завершённым
    /// задолго до конца.
    pub received_chunks: u64,
    /// Сколько чанков всего.
    pub chunk_total: u64,
    /// Каким куском нарезан **этот** файл — размер всех, кроме последнего.
    ///
    /// Нужен ровно затем, чтобы показать ход передачи в байтах, и берётся
    /// из записи файла, а не из настроек: резал его тот, кто отправлял,
    /// и своей ступенью.
    pub chunk_bytes: u32,
    /// Есть ли превью, которое можно показать (§10.3).
    pub has_preview: bool,
}

/// Файл, который клиент просит отправить.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiOutgoingFile {
    /// Путь на диске. Файл **не копируется** — ядро читает его лениво,
    /// по чанку за раз, пока идёт передача. Значит, до её конца файл должен
    /// оставаться на месте; на Android это означает «сперва скопируйте
    /// из `content://` в своё хранилище, потом отправляйте».
    pub path: String,
    /// Превью изображения до [`max_preview_bytes`] (§10.3).
    ///
    /// Готовит клиент, как и аватарку: декодер изображений — большая
    /// поверхность атаки, и в процессе, который держит ключи, ему делать
    /// нечего. Без превью человек на той стороне решает «принимать или нет»
    /// по имени файла, то есть вслепую.
    pub preview: Option<Vec<u8>>,
}

/// Реакция на сообщение в том виде, в каком её показывает UI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiReaction {
    /// Эмодзи.
    pub emoji: String,
    /// Чья — им адресуется команда снятия.
    pub author_ik: Vec<u8>,
    /// Своя ли.
    ///
    /// Считается здесь, а не в клиенте: сравнение с собственным `IK` —
    /// протокольное знание, и §13.3 не разрешает ему подниматься выше.
    pub mine: bool,
}

/// Подписка UI на события ядра.
///
/// Колбэк, а не опрос: на Android опрос из foreground service — прямой расход
/// батареи, а §14 пункт 6 и так обещает пользователю больше, чем хотелось бы.
///
/// `foreign`, а не `rust, foreign`: трейт реализует только UI, и Rust-версии
/// через границу не ходят. Так не генерируется неиспользуемый скаффолдинг.
/// Устаревший `callback_interface` (с `Box<dyn _>`) не используется.
#[uniffi::export(foreign)]
pub trait EventObserver: Send + Sync {
    /// Вызывается на каждое событие.
    fn on_event(&self, event: FfiEvent);
}

/// Всё, что стало известно при открытии и дальше не меняется.
struct Opened {
    handle: DriverHandle,
    fingerprint: String,
    contact_uri: String,
    own_ik: [u8; 32],
}

/// Клиент ядра — то, что держит Kotlin.
///
/// Ядро живёт на собственном потоке с рантаймом, и это не деталь реализации,
/// а следствие двух вещей сразу: методы через UniFFI синхронные, а состояние
/// рукопожатия из `snow` не обещает `Send`. Поэтому всё, что относится
/// к ядру, **создаётся внутри этого потока** — наружу уходит только ручка
/// из каналов, которую пересылать можно.
///
/// Уничтожение клиента закрывает каналы, драйвер выходит из цикла, поток
/// завершается. Отдельного `close` нет намеренно: два способа остановиться
/// разошлись бы при первой же ошибке в клиенте.
#[derive(uniffi::Object)]
pub struct RatatoskClient {
    opened: Opened,
    observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>>,
    /// Ручка эфира: через неё платформа вручает радио и сообщает о нём.
    ///
    /// Заводится **до** потока ядра и живёт рядом с ним, а не внутри:
    /// радио приходит от службы, которая поднимается своим чередом, и
    /// ждать её открытием базы нельзя. Мост от этого не страдает — он
    /// и рассчитан на то, что радио появится позже.
    bluetooth: Arc<FfiBluetooth>,
}

#[uniffi::export]
impl RatatoskClient {
    /// Открывает или создаёт хранилище по пути.
    ///
    /// `pin` — `None`, если пользователь отказался от PIN. В этом случае
    /// клиент **обязан** показать [`no_pin_warning`]: §8.6 разрешает отказ,
    /// но ключ базы лежит тогда в самой базе открыто, и содержимое доступно
    /// любому, кто получил файл.
    ///
    /// `device_key` — 32 байта из хранилища ключей ОС (Android Keystore).
    /// Их генерирует и хранит клиент; ядро их не запоминает, а только
    /// выводит из них ключ базы вместе с солью. Что это даёт и чем за это
    /// платят:
    ///
    /// * с секретом устройства база **не открывается на другом телефоне** —
    ///   ни с PIN, ни без. Это защита от того, у кого файл, но нет аппарата;
    /// * и это же означает, что **потеря телефона — потеря переписки**.
    ///   Секрет из Keystore не восстанавливается ни резервной фразой,
    ///   ни бэкапом. Сказать об этом человеку надо до, а не после;
    /// * вместе с PIN — защита от обоих сразу: файл бесполезен без аппарата,
    ///   аппарат — без PIN.
    ///
    /// Секрет обязан быть ровно 32 байта. Всё остальное — отказ: короткий
    /// секрет означает, что клиент положил туда не то, и молча вывести
    /// из этого ключ базы значило бы изобразить защиту.
    ///
    /// Неверный PIN возвращает [`RatatoskError::Locked`] и **не** заводит
    /// новую личность: молчаливый старт с чистого листа выглядит как
    /// потерянная переписка.
    #[uniffi::constructor]
    pub fn open(
        db_path: String,
        pin: Option<String>,
        device_key: Option<Vec<u8>>,
        display_name: String,
    ) -> Result<Arc<Self>, RatatoskError> {
        let device_key = to_device_key(device_key)?;
        let observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>> = Arc::new(Mutex::new(None));
        let pump_observer = Arc::clone(&observer);
        // Мост эфира заводится здесь, а не в потоке ядра: клиенту он нужен
        // сразу после открытия, а поток к тому времени только начнёт
        // поднимать базу. Один и тот же мост уезжает в ступень и остаётся
        // у клиента — второй был бы мостом в никуда.
        let bt_air = BridgedAir::new();
        let core_air = bt_air.clone();

        // Канал на одно сообщение: поток отчитывается об исходе запуска
        // ровно раз, а дальше живёт своей жизнью.
        let (ready_tx, ready_rx) =
            std::sync::mpsc::sync_channel::<Result<Opened, RatatoskError>>(1);

        std::thread::Builder::new()
            .name("ratatosk-core".to_owned())
            .spawn(move || {
                // **Многопоточный, а не однопоточный**, и это исправление
                // настоящей медлительности, а не запас на будущее.
                //
                // Цикл драйвера живёт в `block_on`, то есть на этом самом
                // потоке. Всё, что порождает `tokio::spawn`, на однопоточном
                // рантайме делит поток с ним — а порождает много кто, и
                // не только мы: bootstrap Tor у arti это десятки задач,
                // разбирающих консенсус сети, и работа там не ожидание,
                // а счёт. Пока такая задача считает, цикл драйвера не
                // отвечает ни на запрос переписки, ни на таймер, и человек
                // видит приложение, которое «думает» ровно столько, сколько
                // поднимается Tor.
                //
                // Два рабочих потока, а не по числу ядер: считающих задач
                // у нас единицы, а каждый лишний поток на телефоне — это
                // память и расход батареи (§13.1). Ядру от этого `Send`
                // не требуется: `block_on` исполняет будущее на вызывающем
                // потоке, а `Send` обязателен только тому, что уезжает
                // в `tokio::spawn`, — и уезжало оно туда и раньше.
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(RatatoskError::internal(error)));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let started =
                        start(PathBuf::from(db_path), pin, device_key, display_name, core_air)
                            .await;
                    let (mut driver, opened, events) = match started {
                        Ok(parts) => parts,
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                            return;
                        }
                    };
                    if ready_tx.send(Ok(opened)).is_err() {
                        // Клиент не дождался — поднимать ядро незачем.
                        return;
                    }
                    tokio::spawn(pump_events(events, pump_observer));
                    if let Err(error) = driver.run().await {
                        tracing_stop(&error);
                    }
                });
            })
            .map_err(RatatoskError::internal)?;

        let opened = ready_rx
            .recv()
            .map_err(|_| RatatoskError::internal("поток ядра завершился при запуске"))??;

        Ok(Arc::new(RatatoskClient {
            opened,
            observer,
            bluetooth: Arc::new(FfiBluetooth::new(bt_air)),
        }))
    }

    /// Подписывает UI на события.
    pub fn set_observer(&self, observer: Arc<dyn EventObserver>) {
        if let Ok(mut slot) = self.observer.lock() {
            *slot = Some(observer);
        }
    }

    /// Ручка эфира Bluetooth (0.4.7).
    ///
    /// Через неё платформа вручает своё радио и сообщает о нём. Отдельным
    /// объектом намеренно: эфиром занимается служба переднего плана
    /// с разрешениями, и давать ей весь клиент значило бы давать ей
    /// переписку.
    ///
    /// Ступень при этом включается **не здесь**, а настройками транспортов,
    /// как и все прочие: радио — это про «чем», а не про «включено ли».
    pub fn bluetooth(&self) -> Arc<FfiBluetooth> {
        Arc::clone(&self.bluetooth)
    }

    /// Отпечаток собственной идентичности (§3).
    pub fn fingerprint(&self) -> String {
        self.opened.fingerprint.clone()
    }

    /// Своя контакт-карточка как URI для QR (§4.1).
    ///
    /// Спрашивается у ядра каждый раз, а не берётся из того, что было при
    /// открытии: адреса появляются позже старта (§5.2), и после
    /// [`RatatoskClient::announce_addresses`] прежняя ссылка уже не та, что
    /// уедет собеседнику. Показать устаревший QR — пообещать адрес, которого
    /// в нём нет.
    ///
    /// Если ядро остановлено, возвращается ссылка, снятая при открытии:
    /// она хотя бы верна для той минуты, а пустой экран вместо QR не помог бы
    /// никому.
    pub fn my_contact_uri(&self) -> String {
        self.opened
            .handle
            .own_card_blocking()
            .map_or_else(|| self.opened.contact_uri.clone(), |card| card.uri)
    }

    /// Свои адреса и версия карточки (§4.1, §4.3).
    ///
    /// Нужно экрану «мой профиль»: пустой onion означает, что Tor ещё
    /// не поднят, и сказать об этом честнее, чем показать QR без адреса
    /// и промолчать.
    pub fn my_addresses(&self) -> Result<FfiOwnCard, RatatoskError> {
        Ok(ffi_own_card_of(&self.own_card()?))
    }

    /// Идентификатор чата 1:1 с контактом.
    pub fn chat_id_for(&self, peer_ik: Vec<u8>) -> Result<Vec<u8>, RatatoskError> {
        let ik = to_ik(&peer_ik)?;
        Ok(Engine::<SqliteStore>::chat_id_for(&ik).to_vec())
    }

    /// Добавляет контакт по URI из QR или ссылки (§4.2).
    ///
    /// `met_in_person` различает два способа обмена: при личной встрече канал
    /// доверенный по построению и отпечаток сверять не нужно; по ссылке —
    /// нужно, и до сверки контакт помечается непроверенным.
    pub fn add_contact(&self, uri: String, met_in_person: bool) -> Result<(), RatatoskError> {
        let card_bytes =
            ContactCard::from_uri(&uri).map_err(RatatoskError::internal)?.bytes().to_vec();
        self.command(Command::AddContact { card_bytes, met_in_person })
    }

    /// Подтверждает сверку отпечатка голосом (§4.2).
    pub fn mark_verified(&self, peer_ik: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::MarkVerified { peer_ik: to_ik(&peer_ik)? })
    }

    /// Отзывает сверку отпечатка (§4.2).
    ///
    /// Контакт снова считается непроверенным: UI обязан пометить его так же,
    /// как контакт, добавленный по ссылке. Аватарка с этого момента ему
    /// не отправляется и его не показывается — оба конца правила читают
    /// один и тот же признак.
    ///
    /// **Собеседник об этом не узнает.** Отзыв — решение пользователя о том,
    /// кому он доверяет, а не сообщение о человеке. Перед вызовом клиент
    /// обязан показать [`revocation_notice`].
    pub fn revoke_verification(&self, peer_ik: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::RevokeVerification { peer_ik: to_ik(&peer_ik)? })
    }

    /// Подписывает контакт своим именем — или снимает подпись (`None`).
    ///
    /// Имя **локальное**: по проводу не едет никогда и собеседнику неизвестно.
    /// Имя из карточки задаёт он сам, и §4.1 прямо называет его не доверенным;
    /// это — своя пометка. Отправить её значило бы и сообщить человеку, как
    /// его записали, и завести поле, которое он может подделать.
    ///
    /// Пустая строка равносильна `None`: человек, стёрший имя в поле ввода,
    /// имел в виду именно это. Предел длины — [`max_local_name_chars`].
    pub fn set_local_name(
        &self,
        peer_ik: Vec<u8>,
        name: Option<String>,
    ) -> Result<(), RatatoskError> {
        let peer_ik = to_ik(&peer_ik)?;
        // Как и с аватаркой: проверка здесь, чтобы отказ пришёл сейчас,
        // а не потерялся в очереди команд. Правило одно, вызывается дважды.
        if let Some(name) = &name {
            let trimmed = name.trim();
            if trimmed.chars().count() > ratatosk_core::MAX_LOCAL_NAME_CHARS {
                return Err(RatatoskError::internal("локальное имя слишком длинное"));
            }
        }
        self.command(Command::SetLocalName { peer_ik, name })
    }

    /// Удаляет контакт.
    ///
    /// Личность уходит всегда: карточка, отметка о сверке (§4.2), аватарка,
    /// сессия вместе с ключевым материалом (§8.3) и всё, что стояло в очереди
    /// этому человеку. `purge_history` решает судьбу переписки — ядро не
    /// выбрасывает её само и не оставляет само.
    ///
    /// **Это не блокировка, и обещать её нельзя.** Собеседник может написать
    /// снова: его рукопожатие (§8.2) заведёт контакт заново — уже
    /// непроверенным, но заведёт. Перед вызовом клиент обязан показать
    /// [`deletion_notice`].
    pub fn delete_contact(
        &self,
        peer_ik: Vec<u8>,
        purge_history: bool,
    ) -> Result<(), RatatoskError> {
        self.command(Command::DeleteContact { peer_ik: to_ik(&peer_ik)?, purge_history })
    }

    /// Отправляет текст.
    pub fn send_text(&self, chat_id: Vec<u8>, text: String) -> Result<(), RatatoskError> {
        self.command(Command::SendText { chat: to_chat(&chat_id)?, text })
    }

    /// Ставит или снимает свою аватарку.
    ///
    /// `None` — снять. Байты — готовое изображение: PNG, JPEG или WebP,
    /// не больше [`max_avatar_bytes`]. Масштабирует и перекодирует **клиент**:
    /// декодер изображений — большая поверхность атаки, и в процессе,
    /// который держит ключи, ему делать нечего. Ядро проверяет ровно две
    /// вещи — длину и сигнатуру формата.
    ///
    /// Аватарка уходит **только сверенным контактам** (§4.2) и только прямым
    /// каналом: почта её не повезёт. Несверенные не получат ничего и не
    /// узнают, что она есть.
    ///
    /// Отдать её тому, чей отпечаток не сверен, значило бы отдать своё лицо
    /// тому, кто, может быть, не тот, за кого себя выдаёт, — а §4.2 ровно
    /// про эту возможность.
    pub fn set_avatar(&self, bytes: Option<Vec<u8>>) -> Result<(), RatatoskError> {
        let bytes = bytes.unwrap_or_default();
        // Проверка **здесь**, а не только в ядре, и это не нарушение §13.3:
        // решения на границе не принимается, зовётся та же самая функция,
        // что и внутри. Разница в моменте. Команды уходят в ядро без ответа,
        // поэтому отказ, случившийся там, вернулся бы клиенту никогда — а он
        // нужен сейчас, пока у пользователя ещё открыт выбор файла и слова
        // «слишком большая» ему что-то говорят.
        ratatosk_proto::avatar::check(&bytes)
            .map_err(|e| RatatoskError::Internal { reason: e.to_string() })?;
        self.command(Command::SetAvatar(bytes))
    }

    /// Своя аватарка, если она поставлена.
    pub fn my_avatar(&self) -> Result<Option<Vec<u8>>, RatatoskError> {
        self.opened
            .handle
            .avatar_blocking(None)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Аватарка контакта.
    ///
    /// `None` означает «показывать нечего»: её нет **или контакт не сверен**.
    /// Различать эти два случая клиенту не нужно, а §4.2 в обоих требует
    /// одного и того же — заглушку.
    ///
    /// Правило показа живёт в ядре, а не здесь: §13.3 не разрешает
    /// протокольной логике подниматься выше этой границы. Клиент, который
    /// решил бы показать лицо несверенного, не смог бы — байтов не отдадут.
    pub fn avatar_of(&self, peer_ik: Vec<u8>) -> Result<Option<Vec<u8>>, RatatoskError> {
        let peer_ik = to_ik(&peer_ik)?;
        self.opened
            .handle
            .avatar_blocking(Some(peer_ik))
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Включает или выключает транспорт (§5.4).
    ///
    /// Одна ручка на все транспорты: их станет больше, и по ручке на каждый
    /// означало бы новую функцию на границе §13.3 при каждом добавлении.
    ///
    /// Перед включением LAN клиент обязан показать [`lan_warning`].
    ///
    /// Выбор **хранит ядро** и переживает перезапуск. Клиенту дублировать его
    /// в своих настройках не нужно и не следует: два экземпляра одной правды
    /// однажды разойдутся, и разойдутся молча. Прочитать текущее состояние —
    /// [`RatatoskClient::transport_enabled`].
    pub fn set_transport_enabled(
        &self,
        transport: FfiTransport,
        enabled: bool,
    ) -> Result<(), RatatoskError> {
        self.command(Command::SetTransportEnabled { transport: transport.into(), enabled })
    }

    /// Включён ли транспорт прямо сейчас (§5.4).
    pub fn transport_enabled(&self, transport: FfiTransport) -> Result<bool, RatatoskError> {
        Ok(self.transport_status()?.enabled.contains(transport.into()))
    }

    /// Записывает настройки существующего почтового ящика (§5.3).
    ///
    /// Первый из двух способов обзавестись почтой; второй —
    /// [`RatatoskClient::create_mail_account`]. Спросить, какой из них,
    /// клиент обязан при включении почты: у человека либо уже есть ящик,
    /// либо нет ничего.
    ///
    /// `imap_host` и `smtp_host` пустые означают «взять из домена адреса»,
    /// порты `0` — «стандартные». Chatmail-серверы устроены именно так,
    /// и заставлять человека вводить четыре строки ради этого незачем.
    ///
    /// `via_tor` — выбор пути, и клиент обязан назвать его цену **до**
    /// переключения: выключив Tor, человек показывает серверу свой IP,
    /// а вместе с адресом ящика это привязка переписки к линии связи.
    /// Содержимого писем сервер не видит в любом случае (§5.3).
    ///
    /// Настройки **хранит ядро** и переживают перезапуск вместе с паролем:
    /// база зашифрована ключом §8.6. Клиенту дублировать их у себя не нужно
    /// и не следует.
    pub fn set_mail_account(
        &self,
        address: String,
        password: String,
        imap_host: String,
        imap_port: u16,
        smtp_host: String,
        smtp_port: u16,
        via_tor: bool,
    ) -> Result<(), RatatoskError> {
        let mut account = ratatosk_proto::mail::MailAccount::from_address(&address, &password);
        if !imap_host.is_empty() {
            account.imap_host = imap_host;
        }
        if !smtp_host.is_empty() {
            account.smtp_host = smtp_host;
        }
        if imap_port != 0 {
            account.imap_port = imap_port;
        }
        if smtp_port != 0 {
            account.smtp_port = smtp_port;
        }
        account.via_tor = via_tor;
        self.command(Command::SetMailAccount(Some(account)))
    }

    /// Убирает почтовый ящик (§5.3).
    ///
    /// Почта перестаёт быть ступенью §5.4, а chatmail-адрес снимается
    /// с карточки (§4.3): обещать путь, которого нет, нельзя.
    pub fn clear_mail_account(&self) -> Result<(), RatatoskError> {
        self.command(Command::SetMailAccount(None))
    }

    /// Называет открытый ключ **своего** узла в меше Yggdrasil (0.2).
    ///
    /// Тридцать два байта ставят ключ, пустой массив снимает меш; любая
    /// другая длина — отказ. Отказ, а не молчаливое стирание: ключ человек
    /// переносит руками из чужого приложения, и опечатку надо назвать —
    /// иначе он останется с выключенным мешем и без объяснения.
    ///
    /// **Где его взять.** На десктопе — у демона: `yggdrasilctl getSelf`,
    /// поле `key`. На телефоне с официальным приложением Yggdrasil —
    /// из его окна, руками: узел живёт в чужой песочнице, и спросить его
    /// программно неоткуда. Вывести ключ из адреса `200::/7` **нельзя**:
    /// адрес сжимает ключ до четырнадцати байт.
    ///
    /// **Настройка, а не адрес.** Переживает перезапуск, ставится один раз.
    /// Смена растит версию карточки и рассылает её контактам (§4.3): имя
    /// в меше — часть карточки, и собеседники обязаны узнать новое.
    ///
    /// **Ступень от этого не становится работающей.** Работает она с того
    /// момента, как раннер привязался к нашему адресу в меше, — то есть
    /// когда демон поднят и адрес назначен. До тех пор §5.4 её не выбирает,
    /// а `transport_ready(Ygg)` честно отвечает «нет».
    ///
    /// Перед включением ступени клиент обязан показать [`ygg_warning`].
    ///
    /// Относится к режиму внешнего демона. В режиме своего узла имя
    /// выводится из нашего зерна, и вызов отвечает отказом, а не тишиной.
    pub fn set_ygg_key(&self, key: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::SetYggKey(key))
    }

    /// Этот аккаунт вышел на экран или ушёл с него (§5.1).
    ///
    /// **Не переключатель локальной сети.** Гасит и зажигает маяк §5.1,
    /// не трогая выбор человека и ничего не записывая: одно устройство
    /// с тремя аккаунтами не должно объявлять в эфир три присутствия
    /// сразу — но и включать локальную сеть тому, кто её не включал,
    /// оно не вправе.
    ///
    /// Приложению с одним аккаунтом звать это не нужно вовсе: умолчание —
    /// «на экране».
    ///
    /// Onion и почты не касается: они не объявляют присутствия, а ждут
    /// входящих по адресу из карточки.
    ///
    /// **Это не «приложение свернули».** Признак говорит ровно одно:
    /// «этот аккаунт сейчас активный» — и приложению с одним аккаунтом
    /// звать его не нужно **никогда**. Передайте сюда состояние окна —
    /// и получите канал, который работает, только пока человек смотрит
    /// в экран; свёрнутое приложение продолжает принимать и отправлять
    /// своё, а вот **раздавать чужое** перестаёт.
    ///
    /// **Раздачу чужого канала (§7) это гасит** — §12: «активен ровно
    /// один аккаунт… его сидирование прекращается, `PeerRecord` выпадает
    /// по сроку». Ушедший с экрана перестаёт отдавать блоки чужих
    /// каналов и продлевать свою запись в каталоге; принимать
    /// он продолжает.
    ///
    /// **Свой канал отдаётся всегда.** Владелец — источник, а не сид
    /// (§7.5.2: «ноль сидов — это звезда, и она обязана работать как
    /// состояние»); погаси его признак экрана, канал перестал бы
    /// существовать для всех разом.
    /// Довод не про батарею: два аккаунта, раздающие с одного
    /// устройства, связываются на проводе объёмом и временем.
    ///
    /// Запись гаснет **не сразу** — отзыва §7.5 не знает, и до конца
    /// недели читатели будут набирать погасший адрес. Вернувшийся
    /// на экран раздаёт снова.
    pub fn set_foreground(&self, front: bool) -> Result<(), RatatoskError> {
        self.command(Command::SetForeground(front))
    }

    /// Выбирает, откуда берётся меш: никак, внешним демоном, своим узлом.
    ///
    /// Три состояния, и человек выбирает сам. Экрану настроек это один
    /// переключатель на три положения, а не два независимых флажка:
    /// режимы взаимоисключающи, и «узел встроенный, но выключен»
    /// пришлось бы объяснять.
    ///
    /// **Свой узел называет себя сам.** При первом включении заводится
    /// зерно, из него выводится имя в меше, оно уезжает в карточке.
    /// Возврат в этот режим даёт **то же** имя, а не новое.
    ///
    /// **Без пиров свой узел ни с кем не соединён** — назовите их
    /// через [`RatatoskClient::set_ygg_peers`], иначе ступень честно
    /// останется неработающей.
    ///
    /// Перед включением любого режима клиент обязан показать
    /// [`ygg_warning`].
    pub fn set_ygg_mode(&self, mode: FfiYggMode) -> Result<(), RatatoskError> {
        self.command(Command::SetYggMode(mode.into()))
    }

    /// Текущий режим меша.
    pub fn ygg_mode(&self) -> Result<FfiYggMode, RatatoskError> {
        let mode = self
            .opened
            .handle
            .ygg_mode_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(FfiYggMode::from(mode))
    }

    /// Называет пиров встроенного узла: `tcp://host:port` и подобные.
    ///
    /// Список заменяется целиком. Зашитого списка нет сознательно: пир
    /// видит источник и адресата пакетов в меше, и выбирать за человека,
    /// кто это будет, приложение не вправе.
    ///
    /// В карточке список не отражается: собеседнику важно наше имя в меше,
    /// а не то, через кого мы в него вошли.
    pub fn set_ygg_peers(&self, peers: Vec<String>) -> Result<(), RatatoskError> {
        self.command(Command::SetYggPeers(peers))
    }

    /// Пиры встроенного узла, как их назвал человек.
    pub fn ygg_peers(&self) -> Result<Vec<String>, RatatoskError> {
        self.opened
            .handle
            .ygg_peers_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Пиры встроенного узла и их состояние **прямо сейчас** (0.2).
    ///
    /// Пара к [`RatatoskClient::ygg_peers`], и пара неразлучная: тот
    /// отдаёт список, который назвал человек, этот — сколько из него
    /// работает. Порознь ни то, ни другое вопроса не закрывает.
    ///
    /// # Зачем это человеку
    ///
    /// Пир — чужой узел, который кто-то держит по доброй воле. Он может
    /// исчезнуть навсегда: владелец выключил ноду, кончился хостинг,
    /// сменился адрес. Без этого числа «меш не работает» и «один из трёх
    /// пиров умер полгода назад» выглядят на экране одинаково, а чинятся
    /// по-разному: в первом случае смотреть на сеть, во втором — убрать
    /// мёртвую строку из списка.
    ///
    /// Мёртвый пир из списка **не исчезает**: он остаётся с `up = false`
    /// и своим адресом. Поэтому сшивать этот список с настроенным не надо —
    /// живой состав называет всех, и «которую строку убрать» видно прямо
    /// здесь.
    ///
    /// # Что означает `None`
    ///
    /// **Своего узла нет**: ступень выключена, выбран внешний демон или узел
    /// ещё поднимается. Это не то же, что пустой список: пустой означает
    /// «узел есть, а соединён он ни с кем», и это другая неисправность.
    pub fn ygg_peers_alive(&self) -> Result<Option<Vec<FfiYggPeer>>, RatatoskError> {
        Ok(self.transport_status()?.ygg_peers.map(|peers| peers.iter().map(ygg_peer_of).collect()))
    }

    /// Ключ нашего узла в меше, если он назван (0.2). Пусто — меша нет.
    ///
    /// Читается из своей карточки: там он и живёт. Нужен экрану настроек,
    /// чтобы показать человеку **действующее** имя — не то, что он ввёл,
    /// а то, что уехало собеседникам, — и рядом выведенный адрес для сверки
    /// с `yggdrasilctl getSelf`. В режиме своего узла это имя мы назвали
    /// себе сами, и вводить его человеку было негде.
    pub fn ygg_key(&self) -> Result<Vec<u8>, RatatoskError> {
        let card = self
            .opened
            .handle
            .own_card_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(card.ygg)
    }

    /// Называет реле nostr (0.3): `wss://relay.example`.
    ///
    /// Список заменяется целиком. Зашитого списка нет и не будет: реле
    /// видит, какие ключи переписываются между собой и когда (0.3.3), —
    /// и выбирать за человека, кто это будет, приложение не вправе.
    ///
    /// Негодные адреса **отбрасываются, а не сохраняются**: ядро называет
    /// их в журнале и оставляет прежний список. Открытый `ws://` годится
    /// только до самого устройства (`127.0.0.1`, `localhost`) — наружу он
    /// отдал бы наблюдателю по дороге тот самый граф, ради сокрытия
    /// которого всё и городится.
    ///
    /// **Первые три уезжают в карточку** и становятся тем местом, куда
    /// собеседник будет класть события. Читаем мы со всех названных;
    /// объявляем три — карточка едет в QR, и каждый лишний адрес это
    /// плотность кода. Что именно объявлено, видно в
    /// [`RatatoskClient::nostr_advertised_relays`].
    ///
    /// Перед включением ступени клиент обязан показать [`nostr_warning`].
    pub fn set_nostr_relays(&self, relays: Vec<String>) -> Result<(), RatatoskError> {
        self.command(Command::SetNostrRelays(relays))
    }

    /// Реле nostr, как их назвал человек (0.3).
    pub fn nostr_relays(&self) -> Result<Vec<String>, RatatoskError> {
        Ok(self.nostr_settings()?.0)
    }

    /// Ходить ли на реле мимо Tor (0.3).
    ///
    /// **Размен, а не настройка скорости**, и цену клиент обязан назвать
    /// человеку **до** переключения — [`nostr_direct_warning`]. Умолчание
    /// — через Tor.
    ///
    /// Включается это там, где Tor недоступен физически: ступень, которая
    /// в таком месте просто не работает, — не забота о приватности, а
    /// отсутствие связи. Тот же размен и у почты.
    pub fn set_nostr_direct(&self, direct: bool) -> Result<(), RatatoskError> {
        self.command(Command::SetNostrDirect(direct))
    }

    /// Ходит ли ступень nostr мимо Tor (0.3). Ложь — через Tor.
    pub fn nostr_direct(&self) -> Result<bool, RatatoskError> {
        Ok(self.nostr_settings()?.1)
    }

    /// Реле и их состояние **прямо сейчас** (0.3).
    ///
    /// Пара к [`RatatoskClient::nostr_relays`], и пара неразлучная — ровно
    /// как у пиров меша: тот отдаёт список, который назвал человек, этот —
    /// сколько из него работает. Порознь ни то, ни другое вопроса
    /// не закрывает.
    ///
    /// Здесь только **свои** реле, те, с которых мы читаем. Реле
    /// собеседников, куда мы кладём события, сюда не попадают нарочно:
    /// живое чужое реле не означает, что до нас кто-то дозовётся, и
    /// показывать его как признак работоспособности было бы обманом.
    ///
    /// # Что означает `None`
    ///
    /// Ступень ничего ещё не сказала о себе: она выключена, либо раннера
    /// нет в сборке, либо он только поднимается. Это не то же, что пустой
    /// список: пустой означает «ступень работает, а реле не названы».
    pub fn nostr_relays_alive(&self) -> Result<Option<Vec<FfiNostrRelay>>, RatatoskError> {
        Ok(self
            .transport_status()?
            .nostr_relays
            .map(|relays| relays.iter().map(nostr_relay_of).collect()))
    }

    /// Свой ключ nostr в виде `npub1…` (NIP-19). Пусто — ступень не включали.
    ///
    /// Читается из своей карточки: там он и живёт. Человеку он нужен ровно
    /// для одного — сверить, что в другом клиенте nostr стоит тот же ключ.
    /// Байтами это не сверяется, на то bech32 и придуман.
    pub fn nostr_npub(&self) -> Result<String, RatatoskError> {
        let card = self.own_card()?;
        Ok(ratatosk_proto::nostr::NostrKey::from_slice(&card.nostr)
            .map(|key| key.npub())
            .unwrap_or_default())
    }

    /// Реле, которые **объявляет наша карточка** (0.3).
    ///
    /// Не то же, что [`RatatoskClient::nostr_relays`], и разница видна
    /// человеку: названные — места, откуда мы **читаем**; объявленные —
    /// места, куда собеседник будет **класть**. В карточку уходят не все,
    /// а первые три, и расхождение «названо пять, объявлено три» стоит
    /// показать глазами, а не оставлять выяснять по молчанию.
    pub fn nostr_advertised_relays(&self) -> Result<Vec<String>, RatatoskError> {
        Ok(self.own_card()?.nostr_relays)
    }

    /// Просит chatmail-сервер завести **новый** ящик (§5.3).
    ///
    /// `url` — ссылка вида `https://chatmail.example/new`; такие же в ходу
    /// у Delta Chat. Сервер отвечает готовыми адресом и паролем,
    /// персональных данных не спрашивая.
    ///
    /// Ссылка обязана быть `https` — иначе отказ, и отказ немедленный:
    /// по `http` пароль приехал бы открытым текстом любому на пути.
    ///
    /// `via_tor` относится **и к самой регистрации, и к заведённому ящику**.
    /// Разделять их нельзя: сходить за паролем напрямую, а письма возить
    /// через Tor значит один раз показать серверу IP и связать его
    /// с адресом навсегда.
    ///
    /// Функция возвращается сразу — поход в сеть идёт своим чередом. Исход
    /// приходит событием: [`FfiEvent::MailAccountReady`] с новым адресом
    /// либо [`FfiEvent::MailAccountFailed`] с причиной. Второе показать
    /// обязательно: человек нажал «завести почту» и молчание прочтёт
    /// как поломку приложения.
    pub fn create_mail_account(&self, url: String, via_tor: bool) -> Result<(), RatatoskError> {
        self.command(Command::CreateMailAccount { url, via_tor })
    }

    /// Настройки почтового ящика, если он заведён (§5.3).
    ///
    /// **Вместе с паролем**, и это не оплошность. Пароль мог выдать сервер
    /// при регистрации, и человек не видел его никогда; не показав, мы
    /// оставили бы его без единственного способа войти в свою же почту
    /// с другого устройства или после переустановки. Показывать его в UI
    /// стоит по нажатию, а не постоянно, — но иметь возможность обязан.
    pub fn mail_account(&self) -> Result<Option<FfiMailAccount>, RatatoskError> {
        let account = self
            .opened
            .handle
            .mail_account_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(account.map(|account| FfiMailAccount {
            address: account.address,
            password: account.password.as_str().to_owned(),
            imap_host: account.imap_host,
            imap_port: account.imap_port,
            smtp_host: account.smtp_host,
            smtp_port: account.smtp_port,
            via_tor: account.via_tor,
        }))
    }

    /// **Работает** ли транспорт прямо сейчас (§5.4).
    ///
    /// Не то же, что включён, и разницу надо показывать человеку: между
    /// «включил Tor» и «Tor работает» лежат десятки секунд bootstrap
    /// и публикации сервиса, и всё это время §5.4 его не выбирает.
    /// «Поднимается» — правда, «не работает» — нет.
    pub fn transport_ready(&self, transport: FfiTransport) -> Result<bool, RatatoskError> {
        Ok(self.transport_status()?.ready.contains(transport.into()))
    }

    /// Что происходит с почтой прямо сейчас (§5.3).
    ///
    /// Один запрос вместо четырёх: включена ли, есть ли ящик, вошли ли,
    /// а если нет — почему. Собирать это из отдельных ответов клиенту
    /// пришлось бы самому, и первая же сборка разошлась бы с правдой
    /// в состоянии «включена, ящик есть, но сервер не пустил» — самом
    /// непонятном из всех.
    pub fn mail_status(&self) -> Result<FfiMailStatus, RatatoskError> {
        let status = self.transport_status()?;
        let account = self.opened.handle.mail_account_blocking().flatten();
        let via_tor = account.as_ref().is_some_and(|account| account.via_tor);
        let address = account.as_ref().map(|account| account.address.clone());

        let state = if !status.enabled.contains(ratatosk_proto::Transport::Mail) {
            FfiMailState::Off
        } else if account.is_none() {
            FfiMailState::NoAccount
        } else if status.ready.contains(ratatosk_proto::Transport::Mail) {
            FfiMailState::Ready
        } else if status.mail_failure.is_some() {
            FfiMailState::Failed
        } else {
            FfiMailState::Connecting
        };
        let limits = status.mail_limits;
        Ok(FfiMailStatus {
            state,
            detail: status.mail_failure,
            address,
            via_tor,
            letter_limit_bytes: limits.letter_bytes,
            mailbox_used_bytes: limits.mailbox_used,
            mailbox_limit_bytes: limits.mailbox_limit,
            mailbox_crowded: limits.crowded(),
            carries_files: limits.carries_file_chunks(),
        })
    }

    /// Что Tor сказал о себе последним (§5.2).
    ///
    /// `None` означает «новостей не было»: транспорт не поднимался — либо
    /// выключен, либо ещё не начинал. Отличить это от «поднимается» можно
    /// по [`RatatoskClient::transport_enabled`], и различие стоит показывать:
    /// выключенный Tor — выбор человека, а молчащий — повод для тревоги.
    pub fn tor_status(&self) -> Result<Option<FfiTorStatus>, RatatoskError> {
        Ok(self.transport_status()?.tor.map(|tor| FfiTorStatus {
            fraction: tor.fraction,
            note: tor.note,
            blocked: tor.blocked,
        }))
    }

    /// Объявляет свои адреса контактам (§4.3).
    ///
    /// Зовётся, когда поднялся onion-сервис (§5.2) или завёлся почтовый ящик
    /// (§5.3): до этого адресов у устройства нет, и карточка, показанная
    /// в кафе по QR, знает только локальную сеть.
    ///
    /// **`None` — «не трогать», пустая строка — «адреса нет».** Различие
    /// не косметическое, и стоило оно поломки на стенде.
    ///
    /// Раньше оба аргумента были строками, то есть вызов всегда заявлял
    /// **обе** половины карточки. А знает обычно одну: экран Tor знает
    /// onion-адрес, экран почты — почтовый. Подставив во вторую пустую
    /// строку, вызывающий молча стирал работающий адрес — и там, где почта
    /// единственный транспорт, это означало «до меня больше не достучаться»:
    /// собеседник терял адрес, а сказать ему новый было уже не по чему.
    ///
    /// Поэтому правило простое: **называйте только то, что меняете.**
    /// Пустая строка — это осознанное «адреса больше нет», и она законна:
    /// Tor может быть выключен человеком.
    ///
    /// Повтор с теми же адресами не делает ничего и ничего не стоит — звать
    /// при каждом старте не только можно, но и нужно.
    ///
    /// **Версия карточки при этом растёт**, поэтому своя ссылка и QR
    /// меняются: клиенту стоит перечитать [`RatatoskClient::my_contact_uri`],
    /// если он показывает их на экране.
    pub fn announce_addresses(
        &self,
        onion: Option<String>,
        chatmail: Option<String>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::AnnounceAddresses { onion, chatmail })
    }

    /// Удаляет сообщения **у себя**.
    ///
    /// Тихо и без трафика: собеседник не узнает. Работает и над своими,
    /// и над чужими сообщениями — это своя история.
    ///
    /// Тело стирается сразу; в базе остаётся только идентификатор, чтобы
    /// копия, пришедшая позже другим транспортом, не воскресила удалённое.
    /// Через девяносто суток уходит и он (§12).
    pub fn delete_messages(
        &self,
        chat_id: Vec<u8>,
        msg_ids: Vec<Vec<u8>>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::DeleteMessages {
            chat: to_chat(&chat_id)?,
            msg_ids: to_msg_ids(&msg_ids)?,
        })
    }

    /// Удаляет у себя и **просит** собеседника удалить у себя.
    ///
    /// Именно просит. Мы не знаем и не можем узнать, работает ли у него наш
    /// клиент или его переделка, не снят ли уже скриншот, не открыт ли чат
    /// на втором устройстве. Перед вызовом клиент **обязан** показать
    /// [`retraction_notice`], и формулировка «удалить у обоих» на кнопке
    /// была бы обещанием, которого протокол не даёт (§14).
    ///
    /// Просьба уходит только про **свои** сообщения; чужие из списка просто
    /// удаляются у себя. Отзыв едет обычной очередью доставки (§5.4), а не
    /// отдельным быстрым каналом: собеседник, который был офлайн, получит
    /// его позже — иначе всё это не имело бы смысла.
    pub fn retract_messages(
        &self,
        chat_id: Vec<u8>,
        msg_ids: Vec<Vec<u8>>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::RetractMessages {
            chat: to_chat(&chat_id)?,
            msg_ids: to_msg_ids(&msg_ids)?,
        })
    }

    /// Отправляет файлы одним сообщением — с подписью или без (§10).
    ///
    /// Файл **не копируется**: ядро читает его с диска по пути, пока идёт
    /// передача. Значит, до её конца файл должен оставаться на месте — на
    /// Android это означает «сперва скопируйте из `content://` в своё
    /// хранилище, потом отправляйте». Исчезнувший исходник останавливает
    /// передачу, и клиент получит [`honest_notices`]-текст
    /// [`file_source_gone_notice`].
    ///
    /// Отказ приходит сразу: файлов больше [`max_files_per_message`], файл
    /// больше [`max_file_bytes`], негодное имя или слишком большое превью.
    ///
    /// Чанки идут **только прямым каналом** (§10.2): почтой тысячи кадров
    /// не поедут. Пока собеседника нет в сети, сообщение с вложением стоит
    /// в очереди как любое другое, а байты начнут ездить, когда он появится.
    pub fn send_files(
        &self,
        chat_id: Vec<u8>,
        files: Vec<FfiOutgoingFile>,
        text: String,
    ) -> Result<(), RatatoskError> {
        let chat = to_chat(&chat_id)?;
        if files.is_empty() || files.len() > ratatosk_proto::files::MAX_FILES_PER_MESSAGE {
            return Err(RatatoskError::internal("не тот набор файлов"));
        }
        for file in &files {
            if let Some(preview) = &file.preview {
                if !ratatosk_proto::files::preview_fits(preview.len()) {
                    return Err(RatatoskError::internal("превью слишком большое"));
                }
            }
        }
        let files = files
            .into_iter()
            .map(|f| OutgoingFile { path: PathBuf::from(f.path), preview: f.preview })
            .collect();
        self.command(Command::SendFiles { chat, files, text })
    }

    /// Принимает входящий файл к загрузке.
    ///
    /// Нужно только тем файлам, которые не прошли по порогу автоприёма
    /// ([`RatatoskClient::set_auto_accept_bytes`]). Согласие переживает
    /// перезапуск: спрашивать дважды об одном файле незачем.
    pub fn accept_file(&self, file_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::AcceptFile { file_id: to_file_id(&file_id)? })
    }

    /// Перестаёт качать входящий файл, не отказываясь от него.
    ///
    /// Приехавшее остаётся, предложение живёт, и `accept_file` продолжит
    /// с того же места (§10.2). Показывать это надо именно так — «остановлено,
    /// продолжить», — а не «отменено»: человек, прочитавший «отменено»,
    /// не станет продолжать то, что считает потерянным.
    pub fn pause_file(&self, file_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::PauseFile { file_id: to_file_id(&file_id)? })
    }

    /// Отказывается от входящего файла.
    ///
    /// Сведения о файле и всё, что успело приехать, удаляются. Собеседнику
    /// не уходит ничего: отказ — решение о своей памяти, а не сообщение о себе.
    /// Он увидит только, что чанки перестали запрашивать.
    pub fn decline_file(&self, file_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::DeclineFile { file_id: to_file_id(&file_id)? })
    }

    /// Отправляет в чат карточку контакта (§4.1, дополнение).
    ///
    /// Один контакт на сообщение. Своей карточкой поделиться можно — передайте
    /// собственный `IK`; это та же операция, отдельного механизма «визитка»
    /// нет.
    ///
    /// Не едет ничего лишнего: локальное имя, которым пользователь подписал
    /// человека у себя, остаётся у него (§4.1), признак сверки — тоже, потому
    /// что у получателя контакт будет непроверенным в любом случае.
    ///
    /// **Скажите это человеку до отправки.** Поделиться контактом — значит
    /// рассказать получателю, что вы знакомы с третьим, и отдать его адреса;
    /// согласия у третьего никто не спрашивал и спросить негде. Это цена
    /// любой визитки, переданной из рук в руки, но в мессенджере про
    /// приватность о ней стоит говорить вслух.
    pub fn share_contact(&self, chat_id: Vec<u8>, peer_ik: Vec<u8>) -> Result<(), RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let peer_ik = to_ik(&peer_ik)?;
        self.command(Command::ShareContact { chat, peer_ik })
    }

    /// Добавляет контакт, присланный в чат.
    ///
    /// **Всегда непроверенным** — даже если приславший у вас сверен. Отдельный
    /// метод, а не [`RatatoskClient::add_contact`] с готовыми байтами, именно
    /// поэтому: у `add_contact` есть `met_in_person`, а здесь его быть
    /// не может (§4.2).
    ///
    /// Ничего не делает, если контакт уже есть или если карточка — ваша
    /// собственная. Присланная карточка **не обновляет** известный контакт:
    /// адреса меняет только подписанное обновление от самого владельца (§4.3).
    ///
    /// Результат приходит событием `ContactAdded`, как и у `add_contact`.
    pub fn add_shared_contact(&self, msg_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::AddSharedContact { msg_id: to_msg_id(&msg_id)? })
    }

    /// Задаёт порог автоматического приёма файлов, в байтах.
    ///
    /// `None` — принимать только вручную; это законный выбор, а не отключённая
    /// функция. Настройка переживает перезапуск. По умолчанию —
    /// [`default_auto_accept_bytes`].
    pub fn set_auto_accept_bytes(&self, limit: Option<u64>) -> Result<(), RatatoskError> {
        self.command(Command::SetAutoAcceptBytes(limit))
    }

    /// Текущий порог автоматического приёма файлов.
    pub fn auto_accept_bytes(&self) -> Result<Option<u64>, RatatoskError> {
        self.opened
            .handle
            .auto_accept_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Стирает с диска вложения, которых нет в базе (§12).
    ///
    /// Байты вложений лежат не в базе, а в каталоге рядом с ней, и разойтись
    /// они способны: удаление переписки уносит записи, а каталоги с чанками
    /// остаются. Эта сверка их подбирает — и ту, что накопилась раньше, тоже.
    ///
    /// Направление одно: **с диска убирается лишнее**. Незаконченный приём
    /// не трогается — запись о нём в базе есть, и продолжится он с той же
    /// дырки (§10.2).
    ///
    /// Дорогая: обходит каталог вложений целиком, поэтому место ей —
    /// кнопка «освободить место», а не запуск приложения. Вызывать не
    /// из UI-потока.
    pub fn sweep_orphan_files(&self) -> Result<FfiSwept, RatatoskError> {
        let swept = self
            .opened
            .handle
            .sweep_orphan_files_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(FfiSwept { files: swept.files, chunks: swept.chunks, bytes: swept.bytes })
    }

    /// Добавляет к своим знакомствам те, что лежат в архиве (§12).
    ///
    /// **Не восстановление, и путать их нельзя.** `import_archive` делает
    /// архив аккаунтом целиком и требует чистого места; здесь личность
    /// остаётся своя, переписка своя, а из архива берутся только контакты.
    /// Поэтому это метод открытого клиента, а не свободная функция.
    ///
    /// Что человеку стоит сказать про исход:
    ///
    /// * `own_graph = false` — список чужой, и **никто в нём не сверен**
    ///   (§4.2: поручительство друга сверкой голосом не является).
    ///   Локальные имена из чужого списка тоже не переносятся.
    /// * `known` — сколько уже было. Эти не тронуты ни в одном поле:
    ///   ни адреса, ни версия карточки, ни сверка. Без этой строки слияние
    ///   ста контактов, из которых девяносто известны, выглядит поломкой.
    /// * `refused` — сколько записей оказались негодными. Ноль — обычное
    ///   дело; не ноль — повод посмотреть, откуда взялся архив.
    ///
    /// `scratch_dir` — каталог для черновика, приватный каталог приложения.
    /// Общий временный не годится: черновик — расшифрованная копия чужой базы.
    ///
    /// # Errors
    ///
    /// Файла нет, это не архив, он оборван, ключ или фраза не те.
    pub fn merge_contacts(
        &self,
        archive: String,
        unlock: FfiArchiveUnlock,
        scratch_dir: String,
    ) -> Result<FfiMerged, RatatoskError> {
        let unlock = match unlock {
            FfiArchiveUnlock::Passphrase { phrase } => {
                ratatosk_core::ArchiveKey::Passphrase(phrase)
            }
            FfiArchiveUnlock::Key { key_text } => ratatosk_core::ArchiveKey::Key(
                ratatosk_crypto::storage_key::key_from_text(&key_text).map_err(|_| {
                    RatatoskError::internal("ключ не разобрался: перепишите его целиком")
                })?,
            ),
        };
        let merged = self
            .opened
            .handle
            .merge_contacts_blocking(
                std::path::PathBuf::from(archive),
                unlock,
                std::path::PathBuf::from(scratch_dir),
            )
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?
            .map_err(RatatoskError::internal)?;
        Ok(FfiMerged {
            own_graph: merged.own_graph,
            added: merged.added,
            known: merged.known,
            refused: merged.refused,
        })
    }

    /// Вывозит переписку в зашифрованный архив (§12).
    ///
    /// **Единственный путь переноса истории на другое устройство в v1.**
    /// Ни синхронизации, ни облака нет; без архива переписка человека живёт
    /// ровно столько, сколько его телефон.
    ///
    /// `path` — куда положить файл. Существующий файл **не** перезаписывается:
    /// под ним может лежать единственная копия чьей-то переписки, и молчаливая
    /// перезапись стоила бы её.
    ///
    /// Ключ возвращается в [`FfiExported::key_text`], и показать его надо
    /// сразу: без него архив не открыть, а спросить его второй раз нельзя.
    ///
    /// Дорогая: переписывает базу и все вложения. Вызывать не из UI-потока
    /// и показывать человеку ожидание.
    pub fn export_history(
        &self,
        path: String,
        scope: FfiExportScope,
        phrase: Option<String>,
    ) -> Result<FfiExported, RatatoskError> {
        let done = self
            .opened
            .handle
            .export_history_blocking(std::path::PathBuf::from(path), scope.into(), phrase)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?
            .map_err(RatatoskError::internal)?;
        Ok(FfiExported {
            path: done.path.to_string_lossy().into_owned(),
            key_text: done.key_text,
            locked_by_phrase: done.locked_by_phrase,
            files: done.files,
            bytes: done.bytes,
        })
    }

    /// Открывает вложение на чтение (§10.2).
    ///
    /// **Один вызов на файл, а не на кусок.** Дальше куски берутся
    /// у [`FfiFileReader`], и ядро в этом не участвует: читать можно
    /// в фоновом потоке, пока переписка идёт своим ходом.
    ///
    /// Так было не всегда. Раньше каждый кусок ходил через ядро, и открытие
    /// вложения на полгигабайта занимало его на всё время чтения с диска
    /// и расшифровки — сообщения в это время не уходили. Расшифровка
    /// не стала быстрее; она перестала стоять в общей очереди.
    ///
    /// Собирает файл всё равно **клиент**: куда его положить — в галерею,
    /// в загрузки, в другое приложение — знает только он, и только он умеет
    /// писать туда системными средствами.
    ///
    /// `None` — такого вложения нет: не приезжало, отклонено или удалено.
    pub fn open_file(&self, file_id: Vec<u8>) -> Result<Option<Arc<FfiFileReader>>, RatatoskError> {
        let file_id = to_file_id(&file_id)?;
        let found = self
            .opened
            .handle
            .open_file_blocking(file_id)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.map(|reader| Arc::new(FfiFileReader { reader })))
    }

    /// Превью вложения, если оно есть (§10.3).
    ///
    /// Отдельным вызовом, как и аватарка: до 32 КиБ на файл, и тащить их
    /// в каждый показ списка чата незачем.
    pub fn preview_of(&self, file_id: Vec<u8>) -> Result<Option<Vec<u8>>, RatatoskError> {
        let file_id = to_file_id(&file_id)?;
        let found = self
            .opened
            .handle
            .file_preview_blocking(file_id)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found)
    }

    /// Отвечает на сообщение — с цитатой, которую нельзя подделать.
    ///
    /// По проводу едет **ссылка** (`msg_id`), а не отрывок текста: цитату
    /// каждая сторона рисует из своей копии. Поэтому в цитате не может
    /// оказаться слов, которых собеседник не говорил, — и поэтому же, если
    /// исходного сообщения у него нет, показать цитату будет нечем.
    ///
    /// Отвечать можно на любое сообщение этого чата, и на своё тоже.
    ///
    /// **Что проверяется здесь, а что в ядре.** Пустой текст отвергается
    /// сразу — это чистая проверка аргумента, и человеку она нужна сейчас,
    /// пока у него открыто поле ввода. А вот «такого сообщения в этом чате
    /// нет» знает только ядро, и ответ на этот отказ вернуться не может:
    /// команды уходят без результата. Наружу это выглядит как ответ, который
    /// не появился в чате, — редкий случай (клиент отвечает на то, что сам же
    /// и показал), но обещать здесь ошибку было бы неправдой.
    ///
    /// Как показать цитату: `reply_to` у ответа — идентификатор; сообщение
    /// по нему берётся из уже загруженного окна, а если его там нет —
    /// [`RatatoskClient::message`]. Чтобы **пролистать** к нему, нужен
    /// [`RatatoskClient::messages_before`].
    pub fn reply(
        &self,
        chat_id: Vec<u8>,
        reply_to: Vec<u8>,
        text: String,
    ) -> Result<(), RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let reply_to = to_msg_id(&reply_to)?;
        ratatosk_proto::reply::check(&text)
            .map_err(|e| RatatoskError::Internal { reason: e.to_string() })?;
        self.command(Command::SendReply { chat, reply_to, text })
    }

    /// Заменяет текст своего сообщения и **просит** собеседника сделать то же.
    ///
    /// Устройство то же, что у [`RatatoskClient::retract_messages`], и та же
    /// оговорка: это просьба. Перед вызовом клиент обязан показать
    /// [`edit_notice`] — прежний текст собеседник мог уже прочитать, и
    /// «изменить у обоих» на кнопке было бы обещанием, которого протокол
    /// не даёт (§14).
    ///
    /// Прежний текст не сохраняется ни у кого, но отметка о правке
    /// ([`FfiMessage::edited_at_ms`]) появляется у обоих, и показывать её
    /// обязательно.
    ///
    /// Отказ приходит сразу, до очереди: править можно только своё, только
    /// непустым текстом и только в течение [`max_edit_age_ms`].
    pub fn edit_message(
        &self,
        chat_id: Vec<u8>,
        msg_id: Vec<u8>,
        text: String,
    ) -> Result<(), RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let msg_id = to_msg_id(&msg_id)?;
        // Та же функция, что и в ядре, вызванная раньше: команды уходят без
        // ответа, и отказ, случившийся там, вернулся бы клиенту никогда — а он
        // нужен сейчас, пока у человека открыто поле ввода.
        ratatosk_proto::edit::check(&text)
            .map_err(|e| RatatoskError::Internal { reason: e.to_string() })?;
        self.command(Command::EditMessage { chat, msg_id, text })
    }

    /// Пересылает сообщения в другой чат.
    ///
    /// Каждое уезжает своим новым сообщением с пометкой «переслано»
    /// и **без имени автора**. Перед вызовом клиент обязан показать
    /// [`forward_notice`]: пользователь, знакомый с другими мессенджерами,
    /// уверен, что пересылает сообщение вместе с автором, а подтвердить
    /// авторство пересланного текста невозможно.
    ///
    /// Источник может быть любым чатом. Сообщений за раз — не больше
    /// [`max_forward_ids`]; лишние молча не отправляются, потому что каждое
    /// пересланное — отдельный кадр.
    pub fn forward_messages(
        &self,
        chat_id: Vec<u8>,
        msg_ids: Vec<Vec<u8>>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::ForwardMessages {
            chat: to_chat(&chat_id)?,
            msg_ids: to_msg_ids(&msg_ids)?,
        })
    }

    /// Ставит или снимает свою реакцию на сообщение.
    ///
    /// `None` или пустая строка — снять. Реакция от человека одна: новая
    /// заменяет прежнюю. Реагировать можно и на своё сообщение.
    ///
    /// Пределы — [`max_reaction_bytes`] и «это должно быть эмодзи». Второе
    /// проверяется эвристикой, а не таблицами Unicode, и настоящее
    /// ограничение здесь — длина: она и мешает превратить реакцию в способ
    /// прислать текст, который не выглядит сообщением.
    pub fn set_reaction(
        &self,
        chat_id: Vec<u8>,
        msg_id: Vec<u8>,
        emoji: Option<String>,
    ) -> Result<(), RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let msg_id = to_msg_id(&msg_id)?;
        let emoji = emoji.unwrap_or_default();
        ratatosk_proto::reaction::check(&emoji)
            .map_err(|e| RatatoskError::Internal { reason: e.to_string() })?;
        self.command(Command::SetReaction { chat, msg_id, emoji })
    }

    /// Очищает чат целиком — **у себя**.
    ///
    /// Отзыва здесь нет: просьба удалить всю переписку — это решение
    /// за собеседника о его истории. Убрать разговор у себя и стереть его
    /// у другого — разные намерения; второе выражается явным отзывом.
    pub fn clear_chat(&self, chat_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::ClearChat { chat: to_chat(&chat_id)? })
    }

    /// Сообщает, что пользователь дочитал чат до этого сообщения (§9.4).
    ///
    /// Отсюда уходит квитанция о прочтении — но только прямым каналом
    /// и только про сообщения собеседника. По почте квитанций нет вовсе:
    /// каждая была бы отдельным письмом.
    ///
    /// **Это единственный источник квитанции о прочтении.** Ни приём
    /// сообщения, ни открытие чата, ни запуск приложения её не порождают:
    /// ядро не знает и не может знать, что человек прочитал, — знает клиент.
    /// Когда именно звать, решает тоже клиент: открытие чата, докрутка до
    /// конца, задержка на экране. Ядро своей политики сюда не добавляет.
    ///
    /// Отсюда же и выключатель: клиенту, который квитанций о прочтении
    /// не хочет, достаточно не звать эту команду. Отдельной настройки
    /// в ядре нет и не нужно.
    ///
    /// Повторный вызов про то же место ничего не отправляет — и это
    /// переживает перезапуск: собеседнику сообщают один раз.
    pub fn mark_read(&self, chat_id: Vec<u8>, up_to: Vec<u8>) -> Result<(), RatatoskError> {
        let up_to = to_msg_id(&up_to)?;
        self.command(Command::MarkRead { chat: to_chat(&chat_id)?, up_to })
    }

    /// Сообщает, что сеть сменилась.
    ///
    /// Заметить это может только система: на Android — `ConnectivityManager`,
    /// на десктопе — событие смены интерфейса. Ядро не имеет ни сокетов,
    /// ни часов и отличить смену сети от молчания собеседника не может.
    ///
    /// Без этого вызова после перехода с Wi-Fi на мобильный (и обратно, и
    /// между точками доступа) локальная сеть остаётся в прежнем состоянии:
    /// адреса указывают в старую сеть, объявление в эфир не звучит, и каждая
    /// отправка платит таймаутом за то, что уже известно.
    ///
    /// Вызывать можно свободно: лишний вызов стоит одного переобъявления.
    pub fn network_changed(&self) -> Result<(), RatatoskError> {
        self.command(Command::NetworkChanged)
    }

    /// Группы, в которых мы состоим (§11).
    ///
    /// Отдельным списком, а не вперемешку с контактами: у группы нет ни
    /// отпечатка, ни сверки, ни адресов, и половина полей `FfiContact`
    /// у неё была бы пустой. Список чатов клиент собирает из двух списков —
    /// это честнее, чем один список с необязательными полями.
    pub fn groups(&self) -> Result<Vec<FfiGroup>, RatatoskError> {
        let found = self
            .opened
            .handle
            .groups_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.iter().map(group_of).collect())
    }

    /// Список контактов.
    pub fn contacts(&self) -> Result<Vec<FfiContact>, RatatoskError> {
        let found = self
            .opened
            .handle
            .contacts_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.iter().map(ffi_contact_of).collect())
    }

    /// Список сопряжённых десктопов (§13.4).
    pub fn devices(&self) -> Result<Vec<FfiPairedDevice>, RatatoskError> {
        let found = self
            .opened
            .handle
            .devices_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|d| FfiPairedDevice {
                device_id: d.device_id.to_vec(),
                label: d.label,
                paired_ms: d.paired_ms,
                last_seen_ms: d.last_seen_ms,
                connected: d.connected,
                cache_expired: d.cache_expired,
                reachable_anywhere: d.reachable_anywhere,
            })
            .collect())
    }

    /// Заводит сопряжение с десктопом и отдаёт ссылку для QR (§13.4).
    ///
    /// Ссылка приходит **событием** [`FfiEvent::PairingReady`], а не отсюда,
    /// и это не неудобство ради стройности. Команда пересекает границу
    /// в одну сторону (§13.3): ядро исполняет её в своём потоке, и ответ
    /// у него один на все команды. Клиенту всё равно надо слушать события —
    /// подключение десктопа придёт тем же путём.
    ///
    /// **Показать ссылку обязательно и сразу.** Секрет живёт только в ней:
    /// телефон его не хранит, и повторить событие нечем.
    pub fn pair_device(&self, label: String) -> Result<(), RatatoskError> {
        self.command(Command::PairDevice { label })
    }

    /// Заводит группу (§11).
    ///
    /// Идентификатор придёт событием `GroupCreated` — и только им: у группы
    /// он случаен, из названия не выводится и человеку неизвестен.
    ///
    /// **Перед вызовом обязателен [`group_join_notice`]**: §11.5 требует
    /// сказать, что участники увидят адреса друг друга, именно при создании
    /// группы. Сказанное после — уже не предупреждение, и отменить это
    /// нельзя ничем.
    ///
    /// Название непустое и не длиннее [`max_group_title_chars`] символов.
    /// Оба отказа приходят как `CommandRefused` со словами.
    pub fn create_group(&self, title: String) -> Result<(), RatatoskError> {
        self.command(Command::CreateGroup { title })
    }

    /// Заводит канал (фаза 2, §6.1).
    ///
    /// Отдельной командой от [`RatatoskClient::create_group`], а не флагом
    /// у неё: порода задаётся при заведении и **не меняется** (§6.1),
    /// а флаг у общей команды допускал бы умолчание там, где умолчания
    /// быть не должно.
    ///
    /// **Перед заведением открытого канала обязателен
    /// [`open_channel_notice`]** (§15): ключ чтения уедет в ссылку,
    /// и закрыть доступ обратно нельзя никогда.
    ///
    /// **А [`private_channel_notice`] здесь показывать нечего** — он
    /// обращён к тому, кто **подписывается** («впустить вас должен
    /// владелец»), и место ему перед
    /// [`RatatoskClient::subscribe_to_channel`]. Текста «завожу канал
    /// по приглашению» в §15 нет, и придумывать его клиенту нельзя: §14
    /// держит тексты связанными со свойствами протокола.
    ///
    /// Идентификатор придёт событием [`FfiEvent::ChannelCreated`] —
    /// и только им: он случаен.
    pub fn create_channel(&self, title: String, open: bool) -> Result<(), RatatoskError> {
        self.command(Command::CreateChannel { title, open })
    }

    /// Ссылка на канал — для QR и пересылки (фаза 2, §10.1, §10.2).
    ///
    /// **Собирает её тот, кто делится**, поэтому ссылки на один канал
    /// у двух людей — разные строки, и сравнивать их как строки нельзя
    /// нигде: тождество канала — это `chat_id`.
    ///
    /// **Перед показом обязателен [`sharing_notice`]** (§15): в ссылку
    /// попадает наш адрес, и всякий, к кому она попадёт дальше, узнает,
    /// что мы этот канал читаем.
    ///
    /// У открытого канала ссылка несёт **ключ чтения**. Сокращать её
    /// сторонним сервисом нельзя — ключ уедет сокращателю (§10.1).
    pub fn channel_link(&self, chat_id: Vec<u8>) -> Result<String, RatatoskError> {
        self.opened
            .handle
            .channel_link_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?
            .map_err(engine_err)
    }

    /// Подписывается на канал по ссылке (фаза 2, §10.3, §10.4).
    ///
    /// **Перед вызовом обязателен текст породы** — [`open_channel_notice`]
    /// либо [`private_channel_notice`] (§15), по тому, что обещает ссылка:
    /// ключ в ней есть у открытого канала и нет у канала по приглашению.
    /// Оба обращены к подписывающемуся и говорят ему разное: там — что
    /// ключ раздаётся дальше вместе со ссылкой, здесь — что до впуска
    /// владельцем канал не откроется.
    ///
    /// **Предпросмотр не бесплатен, и сказать это надо до вызова**
    /// (§10.3): чтобы достать представление, мы соединимся с владельцем
    /// или сидом, и он узнает, что кто-то интересуется каналом, даже
    /// если человек потом откажется.
    ///
    /// Достать представление ядро пока не умеет — это работа транспорта,
    /// — поэтому сразу после подписки у канала **нет названия**: оно
    /// внутри документа. Честная строка в списке чатов — «канал, ссылку
    /// прислал X», и рисует её клиент.
    ///
    /// У канала по приглашению событие придёт с `awaiting = true`:
    /// впустить должен владелец, и до впуска читать будет нечего.
    ///
    /// **Заявка едет обычной очередью §5.4 и вправе ждать.** Ссылка везёт
    /// onion, почту, меш, ключ nostr и реле (§10.2), но не адрес
    /// в локальной сети —
    /// он меняется при каждом подключении. Если в ссылке адресов нет
    /// вовсе, до владельца дотянутся только через эфир, и заявка полежит
    /// в очереди, пока его не станет слышно. Клиенту стоит сказать это
    /// словами: «ждём впуска» без объяснения выглядит обещанием, которого
    /// никто не давал (§14).
    pub fn subscribe_to_channel(&self, uri: String) -> Result<(), RatatoskError> {
        self.command(Command::SubscribeToChannel { uri })
    }

    /// Настраивает уведомления чата (§14).
    ///
    /// # Что решает ядро, а что клиент
    ///
    /// Ядро держит выбор человека и отвечает на один вопрос: говорить
    /// об этом чате или молчать **сейчас**. Звук, вибрация и вид
    /// шторки — показ, и решает их клиент (§13.3).
    ///
    /// # Срок
    ///
    /// `until_ms` — момент, когда молчание кончается само; ноль значит
    /// «пока не передумаю». У `silent = false` срок не читается: снятое
    /// молчание не должно включаться обратно.
    ///
    /// # Чат годится любой
    ///
    /// В том числе тот, в котором ещё нет ни сообщения: замолчать
    /// вправе и до первого слова.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn set_chat_notify(
        &self,
        chat_id: Vec<u8>,
        silent: bool,
        until_ms: u64,
    ) -> Result<(), RatatoskError> {
        self.command(Command::SetChatNotify { chat: to_chat(&chat_id)?, silent, until_ms })
    }

    /// Что человек выбрал для этого чата (§14).
    ///
    /// **Выбор, а не «молчим ли сейчас»**: на экране настроек нужен
    /// именно он — с выключателем и сроком, каким его поставили.
    /// Ответ на «молчать ли сейчас» даёт [`FfiNotify::speaks_now`]
    /// в этой же записи, и считает его ядро.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn chat_notify(&self, chat_id: Vec<u8>) -> Result<FfiNotify, RatatoskError> {
        let (notify, speaks_now) = self
            .opened
            .handle
            .chat_notify_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(FfiNotify {
            silent: notify.mode == ratatosk_proto::notify::Mode::Silent,
            until_ms: notify.until_ms,
            speaks_now,
        })
    }

    /// Показывает канал по ссылке **до** подписки (фаза 2, §10.3, шаг 5).
    ///
    /// # Что она делает
    ///
    /// Спрашивает документ у владельца по адресам из ссылки и, проверив
    /// подпись его ключом **из ссылки** и версию, отдаёт название,
    /// породу и цену слова событием [`FfiEvent::ChannelPreviewed`].
    /// В базе не заводится ничего, кроме пути к владельцу: согласие —
    /// это [`RatatoskClient::subscribe_to_channel`] с той же ссылкой.
    ///
    /// # Цену надо показать **до** вызова
    ///
    /// [`channel_preview_notice`] (§15): владелец узнает, что кто-то
    /// интересуется каналом, — даже если человек потом откажется.
    /// Отменить это задним числом нечем.
    ///
    /// # Ответа может и не быть
    ///
    /// И это не ошибка: §10.5 велит ждать и не считать молчание тупиком.
    /// Рисовать надо ожидание, а не отказ.
    ///
    /// # Errors
    ///
    /// [`FfiChannelRefusal::BadLink`] — ссылка не разобралась;
    /// [`FfiChannelRefusal::AlreadySubscribed`] — канал уже наш,
    /// и показывать нечего: документ у нас свежее обещанного ссылкой.
    pub fn preview_channel(&self, uri: String) -> Result<(), RatatoskError> {
        self.command(Command::PreviewChannel { uri })
    }

    /// Отписывается от канала (фаза 2, §10.6).
    ///
    /// **Отписка стирает ключи чтения, а с ними и архив.** Вернувшись
    /// по той же ссылке, человек прочтёт только то, что приедет заново:
    /// прежние поколения ключа хранятся у читателя и больше нигде.
    /// Сказать это надо **до** вызова — после будет поздно.
    ///
    /// В открытом канале владелец ничего не узнает: он и о подписке
    /// не знал. У канала по приглашению уедет блок ухода.
    ///
    /// От своего канала отписаться нельзя — придёт
    /// [`FfiChannelRefusal::OwnChannel`].
    pub fn unsubscribe_from_channel(&self, chat_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::UnsubscribeFromChannel { chat: to_chat(&chat_id)? })
    }

    /// Впускает человека в канал (фаза 2, §6.5, §10.4).
    ///
    /// Не то же, что пригласить в группу: впуск спрашивает право
    /// «впускать», отдаёт впущенному **поколение ключа чтения** и
    /// оставляет подписанную запись о себе. Поэтому
    /// [`RatatoskClient::invite_to_group`] в канале отказывает.
    ///
    /// Впускаемый обязан быть контактом: без карточки ему нечем
    /// запечатать ключ.
    ///
    /// **Впущенные остаются впущенными** после снятия права у того, кто
    /// впускал (§6.5). Сказать это надо при **назначении** права —
    /// [`admitter_grant_notice`], — а не при снятии.
    pub fn admit_to_channel(
        &self,
        chat_id: Vec<u8>,
        peer_ik: Vec<u8>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::AdmitToChannel {
            chat: to_chat(&chat_id)?,
            peer_ik: to_ik(&peer_ik)?,
        })
    }

    /// Выдаёт или снимает право в канале (фаза 2, §6.2, §6.3).
    ///
    /// Одна команда на то и другое: снятие — это выдача с пустым набором,
    /// потому что список в новой версии представления **и есть** всё, что
    /// действует. Подписывает документ владелец, и только он: «раздача
    /// прав не делегируется никогда, иначе это совладение» (§6.2).
    ///
    /// **Срок обязателен.** Не продлил — истекло само (§6.3); право без
    /// срока означало бы отзыв, а отзыв в рое не работает. Продлевать
    /// стоит заранее: [`FfiChannel::grants_expiring`] считает выдачи,
    /// которым осталось меньше месяца.
    ///
    /// Перед выдачей права «впускать» обязателен [`admitter_grant_notice`].
    pub fn set_channel_right(
        &self,
        chat_id: Vec<u8>,
        who: Vec<u8>,
        rights: FfiChannelRights,
        until_ms: u64,
    ) -> Result<(), RatatoskError> {
        self.command(Command::SetChannelRight {
            chat: to_chat(&chat_id)?,
            who: to_ik(&who)?,
            rights: rights_back(rights),
            until_ms,
        })
    }

    /// Назначает цену слова в канале (фаза 2, §11).
    ///
    /// Уезжает новой версией представления: подписчик обязан знать цену
    /// **до** того, как заплатит.
    ///
    /// PoW «поднимает пол против тривиального флуда; против видеокарты
    /// не работает, телефон наказывает всерьёз» (§11) — это фильтр
    /// первого уровня, а не защита, и обещать им больше нельзя.
    /// Слишком большое число отвергается сразу
    /// ([`FfiChannelRefusal::PowTooHard`]), а не превращает канал
    /// в непишущий для всех, у кого телефон.
    pub fn set_channel_pow(&self, chat_id: Vec<u8>, bits: u32) -> Result<(), RatatoskError> {
        self.command(Command::SetChannelPow { chat: to_chat(&chat_id)?, bits })
    }

    /// Поворачивает ключ чтения канала (фаза 2, §6.4).
    ///
    /// **Перед вызовом обязателен [`key_rotation_notice`]** (§15): кнопка
    /// называется последствием — все, кого нет в составе, теряют доступ
    /// к будущему. Прочитанное они сохранят: поколения сосуществуют,
    /// и архив не теряется.
    ///
    /// Показывать кнопку стоит по [`FfiChannel::may_rotate`]: там уже
    /// учтены порода, право и нижний предел в неделю.
    ///
    /// Раз в месяц ядро поворачивает ключ **само** (§6.4); эта команда —
    /// «повернуть сейчас», то есть исключение читателя.
    pub fn rotate_channel_key(&self, chat_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::RotateChannelKey { chat: to_chat(&chat_id)? })
    }

    /// Раздавать ли этот канал и объявлять ли адрес (фаза 2, §7.5.1).
    ///
    /// Три состояния, а не переключатель: [`FfiSeeding::Off`],
    /// [`FfiSeeding::Quiet`] (умолчание) и [`FfiSeeding::Announced`].
    /// Тихая раздача — середина, ради которой §7.5.1 и написан: рой
    /// не зависит от того, нажмёт ли кто-нибудь кнопку, а адрес при этом
    /// не раскрывается.
    ///
    /// **Перед `Announced` клиент обязан показать [`seeding_notice`]**:
    /// объявленный адрес узнаёт каждый читатель канала, и отказ гасит
    /// объявление не сразу.
    ///
    /// **`Off` — это выключатель раздачи (§9.2), а не отписка.** Канал
    /// продолжает читаться; перестаём мы только отдавать — и отдавать
    /// сразу, включая тех, кто привязался раньше.
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Channel`] — это не канал, или объявлять нечего:
    /// своих адресов нет вовсе.
    pub fn set_seeding(&self, chat_id: Vec<u8>, mode: FfiSeeding) -> Result<(), RatatoskError> {
        self.command(Command::SetSeeding { chat: to_chat(&chat_id)?, mode: mode.into() })
    }

    /// Дотянуть историю канала глубже — «прокрутка вверх» (§7.4, шаг 3).
    ///
    /// Зовётся, когда человек долистал до начала того, что у него есть.
    /// Одно движение — одна страница; дальше зовите снова.
    ///
    /// **Ответа у команды нет.** Блоки приедут обычной дорогой и лягут
    /// в историю, а клиент узнает о них по [`FfiEvent::MessageReceived`].
    /// Если у тех, кого спросили, глубже ничего нет, приедет
    /// [`FfiEvent::ChannelHistoryEnd`] — по нему полоску загрузки пора
    /// убрать. Ответ этот окончателен ровно настолько, насколько полон
    /// каталог: появится сид с более длинным архивом — прокрутка снова
    /// даст страницу.
    ///
    /// **Вступление историю не тянет** (§7.4), и это решение: иначе
    /// подписавшийся оплачивал бы год чужой переписки, которого
    /// не просил. Лента начинается с первого живого слова.
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Channel`] — это не канал или он неизвестен.
    pub fn pull_older_history(&self, chat_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::PullOlderHistory { chat: to_chat(&chat_id)? })
    }

    /// Пределы отдачи: сколько блоков за минуту одному и всем (§9.2).
    ///
    /// Числа лежат **на диске** и переживают перезапуск: §9.2 требует
    /// именно этого — «сервера нет, значит ограничителя частоты нет
    /// ни у кого, кроме нас самих».
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn set_giving_limits(&self, limits: FfiGivingLimits) -> Result<(), RatatoskError> {
        self.command(Command::SetGivingLimits(limits.into()))
    }

    /// Нынешние пределы отдачи (§9.2).
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn giving_limits(&self) -> Result<FfiGivingLimits, RatatoskError> {
        let limits = self
            .opened
            .handle
            .giving_limits_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(limits.into())
    }

    /// Кому отдавать блоки этого канала — или всех каналов (§12).
    ///
    /// `chat_id: None` ставит умолчание **аккаунта**; с каналом —
    /// переопределение на него одного. `level: None` при названном
    /// канале снимает переопределение, и канал возвращается
    /// к умолчанию аккаунта.
    ///
    /// **Перед сужением клиент обязан показать [`sharing_level_notice`]**
    /// (§12): платит за него не только тот, кто настраивал.
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Channel`] — названный чат не канал или неизвестен.
    pub fn set_sharing_level(
        &self,
        chat_id: Option<Vec<u8>>,
        level: Option<FfiSharingLevel>,
    ) -> Result<(), RatatoskError> {
        let chat = match chat_id {
            Some(bytes) => Some(to_chat(&bytes)?),
            None => None,
        };
        self.command(Command::SetSharing { chat, level: level.map(Into::into) })
    }

    /// Кому мы отдаём блоки этого канала (§12) — с учётом умолчания.
    ///
    /// Отдаётся **действующий** уровень, а не сырая настройка: у канала
    /// без переопределения это уровень аккаунта. Клиенту нужен ответ
    /// на вопрос «кому сейчас отдаём», а не на вопрос «нажимали ли тут
    /// кнопку».
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn sharing_level(&self, chat_id: Vec<u8>) -> Result<FfiSharingLevel, RatatoskError> {
        let level = self
            .opened
            .handle
            .sharing_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(level.into())
    }

    /// Наше участие в раздаче этого канала (фаза 2, §7.5.1).
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn seeding_mode(&self, chat_id: Vec<u8>) -> Result<FfiSeeding, RatatoskError> {
        let mode = self
            .opened
            .handle
            .seeding_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(mode.into())
    }

    /// Объявлен ли наш адрес в каталоге этого канала (фаза 2, §7.5.1).
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn seeding(&self, chat_id: Vec<u8>) -> Result<bool, RatatoskError> {
        let mode = self
            .opened
            .handle
            .seeding_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(mode.announces_address())
    }

    /// Кто раздаёт этот канал (фаза 2, §7.5).
    ///
    /// Протухшие записи не показываются: «перестал продлевать — выпал».
    ///
    /// # Errors
    ///
    /// [`RatatoskError::Internal`] — ядро остановлено.
    pub fn channel_seeds(&self, chat_id: Vec<u8>) -> Result<Vec<FfiChannelSeed>, RatatoskError> {
        let found = self
            .opened
            .handle
            .channel_seeds_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|seed| FfiChannelSeed {
                who: seed.ik.to_vec(),
                valid_until_ms: seed.valid_until_ms,
                verified: seed.verified,
            })
            .collect())
    }

    /// Кому что выдано в канале (фаза 2, §6.2).
    ///
    /// Отдельным чтением, а не полем в [`FfiGroup`]: до шестидесяти
    /// четырёх строк с именами на канал, а список чатов читается
    /// на каждый показ экрана.
    ///
    /// Истёкшие выдачи остаются в списке до следующей версии документа
    /// и помечены `live = false`: снятие выражается отсутствием строки,
    /// а не надгробием (§6.2).
    pub fn channel_grants(&self, chat_id: Vec<u8>) -> Result<Vec<FfiChannelGrant>, RatatoskError> {
        let found = self
            .opened
            .handle
            .channel_grants_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|grant| FfiChannelGrant {
                who: grant.who.to_vec(),
                name: grant.name,
                rights: rights_of(grant.rights),
                until_ms: grant.until_ms,
                live: grant.live,
            })
            .collect())
    }

    /// Кто просится в канал (фаза 2, §10.4).
    ///
    /// Приходит владельцу и только ему. Заявка ложится на диск и ждёт:
    /// §10.4 прямо говорит «владелец офлайн — заявка ждёт», и ждать она
    /// может сутками.
    ///
    /// Отвеченная заявка исчезает сама: впуск и есть ответ.
    pub fn channel_requests(
        &self,
        chat_id: Vec<u8>,
    ) -> Result<Vec<FfiChannelRequest>, RatatoskError> {
        let found = self
            .opened
            .handle
            .channel_requests_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|request| FfiChannelRequest {
                who: request.who.to_vec(),
                name: request.name,
                received_ms: request.received_ms,
            })
            .collect())
    }

    /// Кто кого впустил в канал — учёт владельца (фаза 2, §6.5).
    ///
    /// Показывает тех, кто действовал **по правилам**, и ничего не говорит
    /// про остальных: впускающий держит ключ и может передать его мимо
    /// протокола — следа не останется. Чинится это не записью, а поворотом
    /// ключа.
    pub fn channel_admits(&self, chat_id: Vec<u8>) -> Result<Vec<FfiChannelAdmit>, RatatoskError> {
        let found = self
            .opened
            .handle
            .channel_admits_blocking(to_chat(&chat_id)?)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found
            .into_iter()
            .map(|admit| FfiChannelAdmit {
                who: admit.who.to_vec(),
                name: admit.name,
                admitted_by: admit.admitted_by.to_vec(),
                admitted_by_name: admit.admitted_by_name,
                generation: admit.generation,
                created_ms: admit.created_ms,
            })
            .collect())
    }

    /// Приглашает в группу (§11.2, §11.5).
    ///
    /// Приглашать может любой участник. Приглашаемый обязан быть **контактом**:
    /// без карточки ему нечем отправить даже рукопожатие.
    ///
    /// Отсюда уезжает больше кадров, чем от любой другой команды: новичку
    /// отдают состав, карточки всех участников и их ключи отправителей.
    /// Ждать этого не нужно — состав у него соберётся сам, и о нём придёт
    /// `GroupMembershipChanged`.
    pub fn invite_to_group(&self, chat_id: Vec<u8>, peer_ik: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::InviteToGroup { chat: to_chat(&chat_id)?, peer_ik: to_ik(&peer_ik)? })
    }

    /// Исключает из группы. Только создатель (§11.2).
    ///
    /// **Перед вызовом обязателен [`eviction_notice`]**: §11.4 требует сказать
    /// дословно, что исключённый сохранит доступ к прошлой переписке.
    /// Исключение социальное, а не криптографическое, и обещать обратное
    /// нельзя.
    ///
    /// Себя исключить нельзя: для этого есть [`RatatoskClient::leave_group`].
    /// Отказ приходит словами и называет нужную команду.
    pub fn evict_from_group(
        &self,
        chat_id: Vec<u8>,
        peer_ik: Vec<u8>,
    ) -> Result<(), RatatoskError> {
        self.command(Command::EvictFromGroup {
            chat: to_chat(&chat_id)?,
            peer_ik: to_ik(&peer_ik)?,
        })
    }

    /// Переименовывает группу.
    ///
    /// **Дополнение к спецификации:** §11 рассылки названия не описывает.
    /// Вправе **только создатель** — то же правило, что у исключения
    /// (§11.2), расширенное по смыслу: он распоряжается тем, что
    /// относится ко всей группе.
    ///
    /// Пределы те же, что при заведении: непустое после обрезки краёв
    /// и не длиннее [`max_group_title_chars`]. Отказ приходит словами
    /// и сразу — здесь, а не молчанием в чате.
    ///
    /// Новое название приедет событием `GroupRenamed` — и на своё
    /// переименование тоже, чтобы у клиента был один путь к перерисовке,
    /// а не два.
    pub fn rename_group(&self, chat_id: Vec<u8>, title: String) -> Result<(), RatatoskError> {
        self.command(Command::RenameGroup { chat: to_chat(&chat_id)?, title })
    }

    /// Меняет аватарку группы.
    ///
    /// **Дополнение к спецификации:** §11 аватарок не описывает.
    /// Вправе **только создатель** — то же правило, что у переименования
    /// и у исключения (§11.2). Кнопку стоит показывать при
    /// `mine && joined`.
    ///
    /// `None` (или пустые байты) снимает картинку: это законное действие,
    /// и участники о нём узнают, иначе у них навсегда осталась бы прежняя.
    ///
    /// Пределы те же, что у своего лица: не больше [`max_avatar_bytes`],
    /// PNG, JPEG или WebP. Масштабирует и перекодирует **клиент** —
    /// декодер изображений в процессе, который держит ключи, не нужен.
    ///
    /// **Правила §4.2 здесь нет.** Картинка уходит всем участникам
    /// и показывается всем, сверенным и нет: она отвечает не на вопрос
    /// «кто этот человек», а на вопрос «какой это разговор», а участников
    /// группы ядро заводит несверенными (§11.5). Цена названа вслух:
    /// создатель вправе поставить группе чужую фотографию, и её увидят.
    ///
    /// Новая картинка приедет событием [`FfiEvent::GroupAvatarChanged`] —
    /// и на своё изменение тоже.
    pub fn set_group_avatar(
        &self,
        chat_id: Vec<u8>,
        bytes: Option<Vec<u8>>,
    ) -> Result<(), RatatoskError> {
        let bytes = bytes.unwrap_or_default();
        // Проверка здесь, а не только в ядре, — по той же причине, что
        // у своего лица: команды уходят в ядро без ответа, и отказ,
        // случившийся там, вернулся бы клиенту никогда. А нужен он сейчас,
        // пока у человека ещё открыт выбор файла.
        ratatosk_proto::avatar::check(&bytes)
            .map_err(|e| RatatoskError::Internal { reason: e.to_string() })?;
        self.command(Command::SetGroupAvatar { chat: to_chat(&chat_id)?, bytes })
    }

    /// Аватарка группы.
    ///
    /// `None` означает «показывать нечего»: её не ставили или сняли.
    /// Различать эти два случая клиенту незачем — рисовать по ним одно
    /// и то же.
    ///
    /// Отдельным вызовом, а не полем [`FfiGroup`]: до тридцати двух
    /// килобайт на группу, а список чатов читается на каждый показ экрана.
    /// Когда перечитывать — говорит [`FfiGroup::avatar_ms`] и событие
    /// [`FfiEvent::GroupAvatarChanged`].
    pub fn group_avatar(&self, chat_id: Vec<u8>) -> Result<Option<Vec<u8>>, RatatoskError> {
        let chat = to_chat(&chat_id)?;
        self.opened
            .handle
            .group_avatar_blocking(chat)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Выходит из группы.
    ///
    /// **Дополнение к спецификации:** §11.2 знает только «создатель
    /// исключает». Отдельная команда, а не исключение себя: у исключения
    /// правило «только создатель», у выхода правила нет вовсе.
    ///
    /// **Перед вызовом обязателен [`leave_notice`]** — а если выходит
    /// создатель, то и [`owner_leave_notice`]. Причина та же, что
    /// у исключения: §14 требует сказать вслух то, чего протокол
    /// не отменяет. Переписка останется, новых сообщений не будет,
    /// а после ухода создателя исключать не сможет никто.
    ///
    /// Вернуть вышедшего может **любой** участник: приглашение в §11.2
    /// не привилегия создателя.
    pub fn leave_group(&self, chat_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::LeaveGroup { chat: to_chat(&chat_id)? })
    }

    /// Отзывает сопряжение (§13.4).
    ///
    /// Сессия рвётся немедленно: отозванный десктоп перестаёт быть узнаваемым
    /// в тот же шаг ядра, а не после того, как допишет начатое.
    pub fn revoke_pairing(&self, device_id: Vec<u8>) -> Result<(), RatatoskError> {
        self.command(Command::RevokePairing { device_id: to_device_id(&device_id)? })
    }

    /// Последние сообщения чата в порядке HLC (§9.1).
    pub fn messages(&self, chat_id: Vec<u8>, limit: u32) -> Result<Vec<FfiMessage>, RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let found = self
            .opened
            .handle
            .messages_blocking(chat, limit as usize)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.into_iter().map(|view| self.view(view)).collect())
    }

    /// Ищет сообщения по словам (§12). Новые первыми.
    ///
    /// `chat_id = None` — по всей переписке.
    ///
    /// **Ищутся целые слова, и только они.** Ни префиксов, ни подстрок,
    /// ни морфологии: «дом» не найдёт «дома», а «прив» не найдёт «привет».
    /// Несколько слов в запросе означают «нужны все».
    ///
    /// Так вышло не от лени. База целиком не шифруется — это обычный SQLite,
    /// шифруются отдельные поля, тела сообщений в их числе. Полнотекстовый
    /// индекс по открытым телам положил бы рядом с зашифрованной перепиской
    /// её незашифрованную копию, и потерянный телефон отдал бы всё. Поэтому
    /// в индексе лежат хэши слов на ключе базы, а по хэшу нельзя искать
    /// по началу слова — как нельзя и перебирать индекс по началу слова.
    ///
    /// Клиенту стоит сказать это человеку прямо в поле поиска, иначе пустой
    /// ответ на «прив» он прочтёт как «ничего не нашлось».
    pub fn search(
        &self,
        chat_id: Option<Vec<u8>>,
        query: String,
        limit: u32,
    ) -> Result<Vec<FfiMessage>, RatatoskError> {
        let chat = match chat_id {
            Some(raw) => Some(to_chat(&raw)?),
            None => None,
        };
        let found = self
            .opened
            .handle
            .search_blocking(chat, query, limit as usize)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.into_iter().map(|view| self.view(view)).collect())
    }

    /// Окно сообщений **перед** названным — листание назад.
    ///
    /// Якорь — `msg_id` того сообщения, которое сейчас первое в списке:
    /// клиент его уже знает, а метку HLC (§9.1) наружу отдавать незачем —
    /// порядок задаёт она, и строить на ней логику выше границы §13.3 нельзя.
    ///
    /// Так же выглядит и «прокрутить до цитаты»: клиент листает назад, пока
    /// в окне не появится нужный `msg_id`. Пустой список означает либо начало
    /// переписки, либо что якоря больше нет (его удалили) — во втором случае
    /// листать не от чего, и отдавать вместо этого последние сообщения было бы
    /// обманом: человек увидел бы конец переписки там, где листал её начало.
    pub fn messages_before(
        &self,
        chat_id: Vec<u8>,
        before: Vec<u8>,
        limit: u32,
    ) -> Result<Vec<FfiMessage>, RatatoskError> {
        let chat = to_chat(&chat_id)?;
        let before = to_msg_id(&before)?;
        let found = self
            .opened
            .handle
            .messages_before_blocking(chat, before, limit as usize)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.into_iter().map(|view| self.view(view)).collect())
    }

    /// Одно сообщение по идентификатору.
    ///
    /// Нужно ради цитат: ответ несёт ссылку, а не текст, и цитируемое
    /// сообщение может лежать далеко за пределами загруженного окна.
    ///
    /// `None` означает «показать нечего»: сообщение удалено, не дошло или
    /// вычищено уборкой (§12). Клиент обязан сказать это прямо — «сообщение
    /// недоступно», — а не показать пустую рамку.
    pub fn message(&self, msg_id: Vec<u8>) -> Result<Option<FfiMessage>, RatatoskError> {
        let msg_id = to_msg_id(&msg_id)?;
        let found = self
            .opened
            .handle
            .message_blocking(msg_id)
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))?;
        Ok(found.map(|view| self.view(view)))
    }
}

impl RatatoskClient {
    /// Перевод сообщения ядра в то, что видит UI.
    ///
    /// Одно место на все три чтения истории: `messages`, `messages_before`
    /// и `message`. Разведённые по трём веткам, они однажды разошлись бы
    /// в том, чем считается «своё» — а это протокольное сравнение, и §13.3
    /// не разрешает ему подниматься в клиент.
    fn view(&self, view: MessageView) -> FfiMessage {
        let m = view.message;
        FfiMessage {
            msg_id: m.msg_id.to_vec(),
            // Тела сегодня всегда текстовые (§9.1: `Text`, `Forward`, `Reply`);
            // порча кодировки не повод потерять сообщение целиком.
            body: String::from_utf8_lossy(&m.body).into_owned(),
            mine: m.sender_ik == self.opened.own_ik,
            in_the_channel: view.in_the_channel,
            // Ключ едет ровно тогда, когда едет имя: два поля про одного
            // человека, и клиент, получивший одно без другого, показал бы
            // подпись без лица или лицо без подписи.
            author_ik: view.author.as_ref().map(|_| m.sender_ik.to_vec()),
            author: view.author,
            wall_ms: m.hlc.wall_ms,
            status: m.status.and_then(DeliveryStatus::from_code).map(status_of),
            edited_at_ms: m.edited_ms,
            forwarded: m.forwarded,
            reply_to: m.reply_to.map(|id| id.to_vec()),
            reactions: view
                .reactions
                .into_iter()
                .map(|r| FfiReaction {
                    emoji: r.emoji,
                    mine: r.author_ik == self.opened.own_ik,
                    author_ik: r.author_ik.to_vec(),
                })
                .collect(),
            files: view
                .files
                .into_iter()
                .map(|view| FfiFile {
                    // Ход передачи считает ядро: клиенту незачем знать,
                    // что чанки бывают неполными и приходят не по порядку.
                    received_chunks: view.received_chunks,
                    file_id: view.file.file_id.to_vec(),
                    name: view.file.name,
                    size_bytes: view.file.size_bytes,
                    incoming: view.file.incoming,
                    accepted: view.file.accepted,
                    complete: view.file.complete,
                    chunk_total: view.file.chunk_total,
                    chunk_bytes: view.file.chunk_bytes,
                    has_preview: view.file.preview.is_some(),
                })
                .collect(),
            shared_contact: view.shared_contact.map(|shared| FfiSharedContact {
                peer_ik: shared.peer_ik.to_vec(),
                display_name: shared.display_name,
                fingerprint: shared.fingerprint,
                already_known: shared.already_known,
                mine: shared.peer_ik == self.opened.own_ik,
            }),
        }
    }

    fn command(&self, command: Command) -> Result<(), RatatoskError> {
        self.opened
            .handle
            .send_blocking(command)
            .map_err(|_| RatatoskError::internal("ядро остановлено"))
    }

    /// Настройка ступени nostr одним запросом (0.3).
    ///
    /// Здесь, а не в экспортируемом блоке, — ровно по причине, записанной
    /// у `transport_status` ниже. Пару `(Vec<String>, bool)` мост не умеет
    /// и уметь не должен: наружу она выходит двумя чтениями по отдельности,
    /// а здесь склеена затем, чтобы не гонять два запроса к ядру ради
    /// одного экрана.
    fn nostr_settings(&self) -> Result<(Vec<String>, bool), RatatoskError> {
        self.opened
            .handle
            .nostr_settings_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Своя карточка одним запросом — для читателей полей ступеней.
    ///
    /// Тоже здесь, и по той же причине: `OwnCard` — тип ядра, а не моста.
    /// Наружу он выходит только переведённым (`ffi_own_card_of`).
    fn own_card(&self) -> Result<OwnCard, RatatoskError> {
        self.opened
            .handle
            .own_card_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }

    /// Состояние транспортов одним запросом — «включён» и «работает» сразу.
    ///
    /// Живёт **в этом** блоке, а не в экспортируемом, и это не вкусовщина:
    /// `#[uniffi::export]` берёт из блока все методы, не разбирая, какие
    /// из них `pub`. Приватный помощник, возвращающий `TransportStatus`
    /// (тип ядра, а не тип моста), требовал бы от него `LowerReturn` —
    /// и весь блок переставал собираться. Помощники ядра — сюда,
    /// в экспорт — только то, что переводит на язык клиента.
    fn transport_status(&self) -> Result<ratatosk_core::driver::TransportStatus, RatatoskError> {
        self.opened
            .handle
            .transports_blocking()
            .ok_or_else(|| RatatoskError::internal("ядро остановлено"))
    }
}

/// Пир встроенного узла меша, как его видит экран настроек (0.2).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiYggPeer {
    /// Адрес, которым соединились: `tcp://host:port`, `tls://host:port`.
    ///
    /// Та же строка, что человек ввёл в настройках, — по ней он и узнаёт,
    /// какую убирать.
    pub uri: String,
    /// Соединение работает.
    pub up: bool,
    /// Соединение начал он, а не мы.
    ///
    /// Такого пира в настройках нет, и кнопка «убрать» рядом с ним была бы
    /// обманом: мы его не добавляли и убрать не можем.
    pub inbound: bool,
    /// Задержка, мс. У неживого — ноль: она не измерялась.
    pub latency_ms: f64,
}

/// Переводит контакт через границу.
///
/// Именованной функцией, а не замыканием, и это долг, закрытый по следу:
/// зеркал карточки четыре, и два из них уже расходились молча — каждый раз
/// это стоило разбора на стенде. Здесь сборка стояла замыканием внутри
/// `contacts`, то есть вне всякого присмотра, и список реле nostr в неё
/// дописывался руками.
///
/// Названная так функция попадает под метёлку `mirror`: каждое поле
/// источника обязано быть прочитано в теле, а то, чему границу переходить
/// не положено, названо в её списке исключений вместе с причиной.
fn ffi_contact_of(contact: &ContactStatus) -> FfiContact {
    FfiContact {
        chat_id: Engine::<SqliteStore>::chat_id_for(&contact.peer_ik).to_vec(),
        peer_ik: contact.peer_ik.to_vec(),
        fingerprint: contact.fingerprint.clone(),
        display_name: contact.display_name.clone(),
        local_name: contact.local_name.clone(),
        verified: contact.verified,
        seen_on_lan: contact.availability.seen_on_lan,
        seen_on_bt: contact.availability.seen_on_bt,
        has_avatar: contact.has_avatar,
        onion: contact.onion.clone(),
        chatmail: contact.chatmail.clone(),
        ygg: contact.ygg.clone(),
        nostr_relays: contact.nostr_relays.clone(),
        card_version: contact.card_version,
        added_ms: contact.added_ms,
        reachability: reachability(contact.reachability),
        direct_channel: contact.direct_channel.map(FfiTransport::from),
        anomalies: FfiAnomalies {
            unknown_session: contact.anomalies.unknown_session,
            bad_tag: contact.anomalies.bad_tag,
            malformed: contact.anomalies.malformed,
            handshake_replay: contact.anomalies.handshake_replay,
            // Считается ядром, а не клиентом: сумма из четырёх слагаемых
            // выглядит безобидно ровно до появления пятого.
            total: contact.anomalies.total(),
        },
    }
}

/// Переводит свою карточку через границу.
///
/// Именованной функцией, а не замыканием, и это починка по следу: сборка
/// стояла прямо в `my_addresses`, и появившиеся в карточке ключ меша, ключ
/// nostr и список реле в неё не попали — компилятор смолчал, потому что
/// забыть можно было и поле, и строку. Ровно так же и ровно дважды это уже
/// случалось по ту сторону границы (`ARCHITECTURE.md`, `own_card_of`).
///
/// Названная так функция попадает под метёлку `mirror`: каждое поле
/// источника обязано быть прочитано в теле.
fn ffi_own_card_of(card: &OwnCard) -> FfiOwnCard {
    FfiOwnCard {
        uri: card.uri.clone(),
        version: card.version,
        onion: card.onion.clone(),
        chatmail: card.chatmail.clone(),
        ygg: card.ygg.clone(),
        nostr: card.nostr.clone(),
        nostr_relays: card.nostr_relays.clone(),
    }
}

/// Реле nostr и его состояние **прямо сейчас** (0.3).
///
/// Пара к `FfiYggPeer`, и по той же причине: реле держит кто-то посторонний,
/// и оно может исчезнуть навсегда. Без живого состава «nostr не работает»
/// и «одно из трёх реле умерло полгода назад» выглядят на экране одинаково,
/// а чинятся по-разному.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiNostrRelay {
    /// Адрес, которым соединялись: та же строка, что человек ввёл.
    pub url: String,
    /// Соединение работает и подписка принята.
    pub up: bool,
    /// Почему не работает — словами, для показа человеку (§14).
    ///
    /// Пусто у живого, а у неживого пусто означает «ещё не пробовали»:
    /// задача реле до соединения не дошла. Различать это стоит — первое
    /// чинится ожиданием, второе временем.
    pub note: String,
}

/// Переводит реле через границу.
///
/// Именованной функцией, а не замыканием, по той же причине, что и пир меша:
/// метёлка `mirror` требует, чтобы **каждое** поле источника было прочитано,
/// а замыкание она не видит.
fn nostr_relay_of(relay: &ratatosk_proto::nostr::NostrRelay) -> FfiNostrRelay {
    FfiNostrRelay { url: relay.url.clone(), up: relay.up, note: relay.note.clone() }
}

/// Переводит пира меша через границу.
///
/// Именованной функцией, а не замыканием, и это не вкусовщина: метелка
/// `mirror` ищет пары `fn X_of(src: &Src) -> Dst` и требует, чтобы **каждое**
/// поле источника было прочитано. Замыкание она не видит — а забытое
/// на границе поле уже случалось, и компилятор его не ловит.
fn ygg_peer_of(peer: &ratatosk_proto::ygg::YggPeer) -> FfiYggPeer {
    FfiYggPeer {
        uri: peer.uri.clone(),
        up: peer.up,
        inbound: peer.inbound,
        latency_ms: peer.latency_ms,
    }
}

/// Перевод лестницы статусов §9.4 в то, что видит UI.
///
/// Варианты перечислены поимённо: новый статус обязан сломать сборку здесь,
/// а не молча стать чем-то похожим.
const fn status_of(status: DeliveryStatus) -> FfiDeliveryStatus {
    match status {
        DeliveryStatus::Undeliverable => FfiDeliveryStatus::Undeliverable,
        DeliveryStatus::Pending => FfiDeliveryStatus::Pending,
        DeliveryStatus::Waiting => FfiDeliveryStatus::Waiting,
        DeliveryStatus::Sent => FfiDeliveryStatus::Sent,
        DeliveryStatus::Delivered => FfiDeliveryStatus::Delivered,
        DeliveryStatus::Read => FfiDeliveryStatus::Read,
    }
}

/// Переводит группу через границу.
///
/// Именованной функцией, а не замыканием внутри `groups`, и это не вкусовщина:
/// свёртка `/tmp/mirror.py` ищет пары `fn X_of(src: &Src) -> Dst` и требует,
/// чтобы **каждое** поле источника было прочитано. Замыкание она не видит —
/// а забытое на границе поле уже случалось, и компилятор его не ловит:
/// пропущенное поле в записи UniFFI собирается молча.
fn group_of(status: &ratatosk_core::driver::GroupStatus) -> FfiGroup {
    FfiGroup {
        chat_id: status.chat.to_vec(),
        title: status.title.clone(),
        created_ms: status.created_ms,
        channel: status.channel.as_ref().map(channel_of),
        members: status
            .members
            .iter()
            .map(|m| FfiGroupMember { ik: m.ik.to_vec(), name: m.name.clone(), mine: m.mine })
            .collect(),
        mine: status.mine,
        joined: status.joined,
        avatar_ms: status.avatar_ms,
        free_slots: status.free_slots,
    }
}

/// Переводит канальные факты наружу (фаза 2).
///
/// Ни одного решения здесь нет нарочно: всё посчитано ядром
/// (`Engine::channel_facts`), и повтори мы тут хоть одно правило §6,
/// оно зажило бы в двух местах.
fn channel_of(facts: &ratatosk_core::engine::ChannelFacts) -> FfiChannel {
    FfiChannel {
        version: facts.version,
        open: facts.open,
        owner_ik: facts.owner_ik.to_vec(),
        rights: rights_of(facts.rights),
        rights_until_ms: facts.rights_until_ms,
        pow_bits: facts.pow_bits,
        awaiting: facts.awaiting,
        readable: facts.readable,
        generation: facts.generation,
        may_rotate: facts.may_rotate,
        owner_quiet_ms: facts.owner_quiet_ms,
        owner_unseen: facts.owner_unseen,
        grants_expiring: facts.grants_expiring,
        sources_now: facts.sources_now,
        seeds_known: facts.seeds_known,
        awaiting_blocks: facts.awaiting_blocks,
        rotation_overdue: facts.rotation_overdue,
        waiting: facts.waiting.map(waiting_of),
        signal: signal_of(facts.signal()),
    }
}

/// Признак канала — наружу (§15).
///
/// Выбор главного признака сделан ядром (`ChannelFacts::signal`);
/// здесь только перевод.
fn signal_of(signal: ratatosk_proto::channel::Signal) -> FfiChannelSignal {
    use ratatosk_proto::channel::Signal;

    match signal {
        Signal::Fine => FfiChannelSignal::Fine,
        Signal::Awaiting => FfiChannelSignal::Awaiting,
        Signal::NotReadable => FfiChannelSignal::NotReadable,
        Signal::NobodyServes => FfiChannelSignal::NobodyServes,
        Signal::SeedsUnreachable => FfiChannelSignal::SeedsUnreachable,
        Signal::OwnerUnseen => FfiChannelSignal::OwnerUnseen,
        Signal::Waiting => FfiChannelSignal::Waiting,
        Signal::RotationOverdue => FfiChannelSignal::RotationOverdue,
    }
}

/// Признак обратно — ради слов к нему.
///
/// Пара к [`signal_of`], и нужна она затем, чтобы слова брались оттуда
/// же, где живёт признак. Без обратного перевода тексты §15 пришлось бы
/// переписать здесь во второй раз.
fn core_signal(signal: FfiChannelSignal) -> ratatosk_proto::channel::Signal {
    use ratatosk_proto::channel::Signal;

    match signal {
        FfiChannelSignal::Fine => Signal::Fine,
        FfiChannelSignal::Awaiting => Signal::Awaiting,
        FfiChannelSignal::NotReadable => Signal::NotReadable,
        FfiChannelSignal::NobodyServes => Signal::NobodyServes,
        FfiChannelSignal::SeedsUnreachable => Signal::SeedsUnreachable,
        FfiChannelSignal::OwnerUnseen => Signal::OwnerUnseen,
        FfiChannelSignal::Waiting => Signal::Waiting,
        FfiChannelSignal::RotationOverdue => Signal::RotationOverdue,
    }
}

/// Биты прав — в четыре вопроса (§6.2).
fn rights_of(bits: u32) -> FfiChannelRights {
    use ratatosk_proto::channel::Rights;

    let rights = Rights::from_bits(bits);
    FfiChannelRights {
        write: rights.has(Rights::WRITE),
        admit: rights.has(Rights::ADMIT),
        evict: rights.has(Rights::EVICT),
        edit: rights.has(Rights::EDIT),
    }
}

/// И обратно — то, что человек отметил на экране, в биты (§6.2).
///
/// Незнакомых битов тут взяться неоткуда, и в этом названная цена
/// записи: выдавая права отсюда, клиент снимает то, чего не знает.
fn rights_back(rights: FfiChannelRights) -> u32 {
    use ratatosk_proto::channel::Rights;

    let mut bits = Rights::none();
    if rights.write {
        bits = bits.with(Rights::WRITE);
    }
    if rights.admit {
        bits = bits.with(Rights::ADMIT);
    }
    if rights.evict {
        bits = bits.with(Rights::EVICT);
    }
    if rights.edit {
        bits = bits.with(Rights::EDIT);
    }
    bits.bits()
}

fn to_ik(bytes: &[u8]) -> Result<[u8; 32], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("ключ контакта не 32 байта"))
}

fn to_msg_id(bytes: &[u8]) -> Result<[u8; 16], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор сообщения не 16 байт"))
}

/// Разбирает идентификатор сопряжённого устройства (§13.4).
///
/// Отдельно от `to_msg_id`, хотя длина та же: слова в отказе читает человек,
/// и «идентификатор сообщения не 16 байт» на экране списка устройств
/// отправляет искать поломку не туда.
fn to_device_id(bytes: &[u8]) -> Result<[u8; 16], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор устройства не 16 байт"))
}

/// Разбирает идентификатор вложения (§10).
///
/// По той же причине, что и `to_device_id`: длина та же, а слова разные.
/// До этой поставки здесь звался `to_msg_id`, и человек, приложивший
/// не тот идентификатор к `accept_file`, читал про сообщение.
fn to_file_id(bytes: &[u8]) -> Result<[u8; 16], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор вложения не 16 байт"))
}

/// Переводит вердикт §5.4 через границу.
///
/// Ни одного решения здесь не принимается — и это главное свойство функции.
/// `usable`, `route` и `rising` считает `proto::transport_policy` тем же
/// кодом, по которому идёт настоящая отправка; здесь только перекладывание
/// полей. Появись тут хоть одно `&&`, правило §5.4 оказалось бы записано
/// в двух местах (§13.3).
fn reachability(view: ratatosk_proto::transport_policy::Reachability) -> FfiReachability {
    FfiReachability {
        rungs: view
            .rungs
            .into_iter()
            .map(|rung| FfiRung {
                transport: rung.transport.into(),
                enabled: rung.enabled,
                ready: rung.ready,
                addressable: rung.addressable,
                usable: rung.usable(),
            })
            .collect(),
        route: view.route().map(FfiTransport::from),
        rising: view.rising().map(FfiTransport::from),
    }
}

fn to_chat(bytes: &[u8]) -> Result<[u8; 16], RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор чата не 16 байт"))
}

/// Разбирает список идентификаторов сообщений.
///
/// Отказ на первом же негодном, а не пропуск: список пришёл от клиента,
/// и «удалили не то, что просили» — худший исход, чем «не удалили ничего».
fn to_msg_ids(ids: &[Vec<u8>]) -> Result<Vec<[u8; 16]>, RatatoskError> {
    ids.iter()
        .map(|id| {
            id.as_slice()
                .try_into()
                .map_err(|_| RatatoskError::internal("идентификатор сообщения не 16 байт"))
        })
        .collect()
}

/// Почтовый раннер — или его отсутствие.
///
/// Отдельным псевдонимом, чтобы состав транспортов не разветвлялся
/// на четыре сочетания признаков: `tor` и `mail` независимы друг от друга,
/// и перечислять их пары значило бы четыре раза написать одно и то же.
#[cfg(feature = "mail")]
type MailSide = ratatosk_transport::chatmail::runner::MailRunner;

/// Почты в этой сборке нет: [`ratatosk_transport::Disabled`] честно отказывает.
#[cfg(not(feature = "mail"))]
type MailSide = Disabled;

/// Раннер ступени nostr — или его отсутствие.
///
/// Отдельным псевдонимом по той же причине, что и почтовый: признаки
/// `tor`, `mail` и `nostr` независимы, и перечислять их сочетания значило
/// бы писать одно и то же восемь раз.
#[cfg(feature = "nostr")]
type NostrSide = ratatosk_transport::nostr::NostrRunner;

/// Ступени nostr в этой сборке нет: [`ratatosk_transport::Disabled`] честно
/// отказывает, а настройка при этом живёт и ждёт сборки с раннером.
#[cfg(not(feature = "nostr"))]
type NostrSide = Disabled;

/// Раннер эфира Bluetooth — один на все сборки.
///
/// Признака у него нет и не нужно: раннер собирается везде, а различается
/// **радио** под ним. На телефоне это мост в платформу ([`BridgedAir`]),
/// и приходит он снаружи; `bluer` сюда не входит и войти не может —
/// он обвязка BlueZ.
#[cfg(not(all(feature = "bt", target_os = "linux")))]
type BtSide = BtRunner<BridgedAir>;

/// Раннер эфира в сборке со **своим** радио.
///
/// На Linux с признаком `bt` радио есть у нас самих — `bluer` поверх
/// BlueZ, — и мост тогда не нужен: приходить ему неоткуда, клиент
/// на десктопе никакого `FfiBtRadio` не реализует. Тот же приём, что
/// у `tor`, `nostr` и почты: тип раннера выбирает сборка.
///
/// Без этой ветки биндинги на Linux собирались на мост **всегда**, и эфира
/// у десктопного приложения не было вовсе: ступень честно объявлялась
/// потерянной, потому что радио ей никто не вручал, а вручить его было
/// некому — `bluer` жил только у стенда.
#[cfg(all(feature = "bt", target_os = "linux"))]
type BtSide = BtRunner<ratatosk_transport::LocalAir>;

/// Чем поднимается эфир — проверяется **сборкой**, а не прогоном.
///
/// Тип раннера выбирает признак, и ошибка здесь не падает тестом: она
/// выглядит как работающая сборка, у которой просто нет эфира. Ровно так
/// оно и было до этой правки — биндинги на Linux собирались на мост
/// всегда, ступень честно объявлялась потерянной, и понять по прогону,
/// что радио не то, было нечем.
///
/// Поэтому проверка тут не утверждение о значении, а **приведение типа**:
/// съедет тип раннера обратно на мост — перестанет компилироваться.
#[cfg(test)]
mod air_choice {
    #[cfg(all(feature = "bt", target_os = "linux"))]
    #[allow(dead_code, reason = "проверка типа, звать её незачем")]
    fn the_rung_takes_the_local_radio(
        side: super::BtSide,
    ) -> super::BtRunner<ratatosk_transport::LocalAir> {
        side
    }

    #[cfg(not(all(feature = "bt", target_os = "linux")))]
    #[allow(dead_code, reason = "проверка типа, звать её незачем")]
    fn the_rung_takes_the_bridge(
        side: super::BtSide,
    ) -> super::BtRunner<ratatosk_transport::BridgedAir> {
        side
    }
}

/// Набор транспортов этой сборки.
///
/// Псевдоним, а не тип по месту: состав транспортов виден в сигнатурах,
/// и меняется он здесь, а не в каждой из них.
///
/// С признаком `tor` в середине стоит настоящий onion — обёрнутый
/// в [`Switched`], потому что bootstrap идёт десятки секунд, а открытие
/// аккаунта обязано быть мгновенным. Без признака там
/// [`ratatosk_transport::Disabled`], и это не заглушка, а правда о сборке:
/// §5.4 обязан узнать, что ступень не сработала, и перейти к следующей.
///
/// Bluetooth стоит настоящий — поверх моста в платформу (0.4.7).
/// `Disabled` здесь был бы не «правдой о сборке», а ошибкой: раннер
/// у ступени есть, и отсутствует не он, а радио. Радио же приходит
/// от клиента вызовом [`bluetooth::FfiBluetooth::set_radio`], и пока
/// его не вручили, ступень честно объявляется потерянной — то есть
/// §5.4 узнаёт правду, а не тишину.
#[cfg(feature = "tor")]
type Runners = Transports<LanRunner, BtSide, YggRunner, Switched<OnionRunner>, NostrSide, MailSide>;

/// Набор транспортов сборки без Tor: локальная сеть, эфир, меш и, если
/// собраны, реле nostr и почта.
#[cfg(not(feature = "tor"))]
type Runners = Transports<LanRunner, BtSide, YggRunner, Disabled, NostrSide, MailSide>;

/// Собирает ядро целиком — внутри потока, которому оно и принадлежит.
async fn start(
    db_path: PathBuf,
    pin: Option<String>,
    device_key: Option<[u8; 32]>,
    display_name: String,
    bt_air: BridgedAir,
) -> Result<(Driver<SqliteStore, Runners>, Opened, EventStream), RatatoskError> {
    let (mut store, db_key) =
        vault::open_encrypted(&db_path, unlock_of(pin.as_deref(), device_key.as_ref()))
            .map_err(engine_err)?;
    let identity = vault::load_or_create(&mut store, &db_key).map_err(engine_err)?;
    // Ключ onion-сервиса — отдельной записью (§3): из зерна он не выводится
    // и резервной фразой не восстанавливается.
    #[cfg(feature = "tor")]
    let onion_key = vault::load_or_create_onion(&mut store, &db_key).map_err(engine_err)?;

    // Байты вложений — рядом с базой, но не в ней (§10, §12). Каталог
    // соседний, чтобы жить и удаляться вместе с ней: база без чанков — это
    // сообщения с вложениями, которых нет, а чанки без базы — мусор,
    // который никто не подберёт.
    let blobs = FsBlobs::new(db_path.with_extension("files"));

    // Onion и chatmail пока пусты: их адреса появятся вместе с транспортами
    // этапов 2 и 3. §5.4 с пустыми адресами честно скажет «отправлять некуда»,
    // а не сделает вид, что письмо ушло.
    //
    // Меша здесь нет вовсе, и это не забывчивость: его настройки живут
    // в базе и поднимаются `restore` (`META_YGG_MODE` и соседи). Второй
    // двери у них нет — была, и первый же заход дал поломку.
    let addresses = SelfAddresses { onion: String::new(), chatmail: String::new(), display_name };

    let mut engine = Engine::new(identity, store, Box::new(blobs), Box::new(OsEntropy), addresses);
    engine.restore().map_err(engine_err)?;

    let card = engine.own_card();
    let opened_parts =
        (engine.fingerprint(), card.to_uri().map_err(RatatoskError::internal)?, card.ik);

    // §5.1: LAN выключен по умолчанию. Порт занимается сразу — он нужен
    // объявлению, а без объявления никого не раскрывает.
    let lan =
        LanRunner::start(LanConfig::default(), card.ik).await.map_err(RatatoskError::internal)?;

    // Меш заводится **с действующим именем из карточки**: `restore` уже
    // посчитал его из настроек и положил туда. Порт при этом не занимается —
    // привязка идёт при включении, и удаётся она только при поднятом демоне.
    // Имени нет — раннер честно откажет, а настройки назовут его на ходу.
    let ygg = YggRunner::start(YggConfig { enabled: false, port: YGG_PORT }, &card.ygg)
        .await
        .map_err(RatatoskError::internal)?;

    // Эфир Bluetooth (0.4). Заводится **выключенным**, как и локальная
    // сеть: включает его ядро первым шагом драйвера, если человек ступень
    // разрешил. Радио при этом может быть ещё не вручено — служба
    // с разрешениями поднимается своим чередом, — и это нормальное
    // состояние: ступень тогда честно объявляется потерянной.
    //
    // **Чем поднимается, решает сборка.** На Linux с признаком `bt` это
    // своё радио (`bluer`), и мост в этой ветке не участвует вовсе —
    // объект `FfiBluetooth` у клиента остаётся, но радио ему вручать
    // незачем (см. `bluetooth::FfiBluetooth::set_radio`).
    #[cfg(all(feature = "bt", target_os = "linux"))]
    let air = {
        // Мост заводится у клиента в любой сборке; здесь он не нужен,
        // и притворяться, что нужен, незачем.
        let _ = &bt_air;
        ratatosk_transport::LocalAir::new()
    };
    #[cfg(not(all(feature = "bt", target_os = "linux")))]
    let air = bt_air;
    let bt = BtRunner::start(air, BtConfig::default(), card.ik)
        .await
        .map_err(RatatoskError::internal)?;

    // Onion поднимается **в фоне опросов драйвера**: bootstrap идёт десятки
    // секунд, и ждать его здесь значило бы держать человека перед пустым
    // экраном минуту — вместе с локальной сетью, которая работает сразу.
    // До подъёма ступень честно отказывает (§5.4).
    //
    // И поднимается он не сразу, а когда ядро скажет, что человек его
    // включил: `Engine::startup_effects` объявляет включённые транспорты
    // первым делом в `Driver::run`. Выключенный в прошлый раз Tor
    // не поднимается вовсе — ни bootstrap, ни каталога сети, ни цепочек.
    // Ручка общего Tor-клиента — одна на оба транспорта: второй `TorClient`
    // означал бы второй bootstrap и ещё десятки мегабайт памяти (§5.2),
    // что на телефоне заметно.
    let tor_handle = ratatosk_transport::onion::TorHandle::default();

    #[cfg(feature = "mail")]
    let mail = ratatosk_transport::chatmail::runner::MailRunner::new(tor_handle.clone());
    #[cfg(not(feature = "mail"))]
    let mail = Disabled;

    // Ступень nostr (0.3). Ручка Tor у неё общая с onion и почтой — по той же
    // причине: второй `TorClient` означал бы второй bootstrap.
    //
    // Без признака ступень честно отказывает, а **настройка живёт**: реле
    // и путь ложатся на диск и ждут сборки, в которой найдётся раннер.
    // Клиенту это надо показывать словами, иначе экран настроек выглядит
    // рабочим, а ступень молчит — на стенде этот разбор уже был.
    #[cfg(feature = "nostr")]
    let nostr = ratatosk_transport::nostr::NostrRunner::new(tor_handle.clone());
    #[cfg(not(feature = "nostr"))]
    let nostr = Disabled;

    #[cfg(feature = "tor")]
    let runner = {
        let layout = ratatosk_core::TorLayout::beside(&db_path);
        // Ключ раскладывается до подъёма и на каждый запуск: arti читает
        // его из каталога, а файл могли удалить или перенести базу без него.
        ratatosk_core::write_onion_keystore(&layout.keys, &onion_key)
            .map_err(RatatoskError::internal)?;
        // Под `Arc`, потому что поднимать придётся столько раз, сколько
        // человек передумает: замыкание-фабрика зовётся на каждое включение
        // и забирать в себя ничего не вправе.
        let setup = std::sync::Arc::new((layout, onion_key));
        let handle = tor_handle.clone();
        let onion = Switched::new(move |progress| {
            let setup = std::sync::Arc::clone(&setup);
            let tor = handle.clone();
            async move {
                let (layout, onion_key) = &*setup;
                OnionRunner::start(
                    ratatosk_transport::onion::arti::OnionSetup {
                        state_dir: &layout.state,
                        cache_dir: &layout.cache,
                        keystore_dir: &layout.keys,
                        key: onion_key,
                        // На Android — и только там. Приложение живёт в своём
                        // каталоге, чужих пользователей на устройстве нет,
                        // а предки пути принадлежат системе и устроены не так,
                        // как ждёт `fs-mistrust`: проверка отвергает заведомо
                        // безопасный путь. На десктопе она остаётся включённой,
                        // потому что там она осмысленна.
                        dangerously_trust_filesystem: cfg!(target_os = "android"),
                        tor,
                    },
                    progress,
                )
                .await
            }
        });
        Transports::new(lan, bt, ygg, onion, nostr, mail)
    };
    // Без признака `tor` onion честно отказывает, а почта работает: §5.3
    // по умолчанию идёт через Tor, но умеет и напрямую.
    #[cfg(not(feature = "tor"))]
    let runner = {
        let _ = &tor_handle;
        Transports::new(lan, bt, ygg, Disabled, nostr, mail)
    };

    let (driver, handle, events) = Driver::new(engine, runner);
    let opened = Opened {
        handle,
        fingerprint: opened_parts.0,
        contact_uri: opened_parts.1,
        own_ik: opened_parts.2,
    };
    Ok((driver, opened, events))
}

/// Аккаунт в том виде, в каком он числится в реестре (§3, дополнение).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAccount {
    /// Идентификатор — им адресуются все операции с аккаунтом.
    pub id: Vec<u8>,
    /// Имя для списка. Задал человек.
    ///
    /// **Лежит открыто**, вне зашифрованной базы: список надо показать
    /// до ввода PIN, а расшифровать его в этот момент нечем.
    pub label: String,
    /// Когда завели, мс.
    pub created_ms: u64,
}

/// Несколько личностей на одном устройстве (§3, дополнение).
///
/// Аккаунт — это **отдельный файл базы со своим `db_key`**, а не запись
/// в общей. Одна база означала бы один ключ на всё, то есть один PIN,
/// открывающий обе переписки; человек, заведший второй аккаунт ровно затем,
/// чтобы первый о нём не говорил, получил бы обратное.
///
/// # Что реестр показывает всем
///
/// Взявший устройство видит **число аккаунтов, их имена и время создания** —
/// без всякого PIN. Иначе нельзя: список рисуется до разблокировки.
/// Внутри базы остаётся всё остальное: личность, отпечаток, переписка.
/// Сказать это человеку в UI обязательно.
///
/// # Скрытые аккаунты
///
/// [`AccountRegistry::create_hidden`] заводит аккаунт **мимо реестра**:
/// в списке его нет, открывается он через [`AccountRegistry::find_hidden`]
/// вводом своего PIN.
///
/// **Скрыт он от списка, а не от осмотра файловой системы.** Файл базы лежит
/// в том же каталоге, и файлов там больше, чем записей в реестре, — вот
/// и весь секрет. Слово «скрытый» читается как «его не найдут»; человек,
/// положившийся на это прочтение, пострадает не от ошибки в коде, поэтому
/// формулировка в UI важнее самой функции.
///
/// У скрытого аккаунта **обязан быть PIN**. Без него открывать нечем:
/// поиск идёт перебором, а перебирать без ключа не с чем.
#[derive(uniffi::Object)]
pub struct AccountRegistry {
    registry: Mutex<Registry>,
    /// Кто сейчас открыт — ради одного инварианта, см. `set_foreground`.
    ///
    /// Слабые ссылки: закрыть аккаунт — значит отпустить его клиента,
    /// и держать его здесь живым означало бы, что закрыть нельзя никогда.
    opened: Mutex<Vec<(AccountId, std::sync::Weak<RatatoskClient>)>>,
}

#[uniffi::export]
impl AccountRegistry {
    /// Открывает реестр в каталоге, заводя каталог при необходимости.
    ///
    /// Отсутствие файла реестра — первый запуск, то есть пустой список.
    /// А вот испорченный файл — отказ, и путать эти два случая нельзя:
    /// на пустой список человек заведёт всё заново поверх целых баз.
    #[uniffi::constructor]
    pub fn open(root: String) -> Result<Arc<AccountRegistry>, RatatoskError> {
        let registry = Registry::open(root).map_err(RatatoskError::internal)?;
        Ok(Arc::new(AccountRegistry {
            registry: Mutex::new(registry),
            opened: Mutex::new(Vec::new()),
        }))
    }

    /// Аккаунты из реестра, в порядке создания. Скрытых здесь нет.
    pub fn list(&self) -> Result<Vec<FfiAccount>, RatatoskError> {
        Ok(self.locked()?.listed().iter().map(account_of).collect())
    }

    /// Заводит аккаунт и вносит его в реестр.
    ///
    /// Файла базы при этом не создаёт: её заводит первое
    /// [`AccountRegistry::open_account`], и оно же знает про PIN.
    pub fn create(&self, label: String) -> Result<FfiAccount, RatatoskError> {
        let account = self
            .locked()?
            .create(&mut OsEntropy, &label, now_ms())
            .map_err(RatatoskError::internal)?;
        Ok(account_of(&account))
    }

    /// Заводит аккаунт **мимо реестра** — скрытый.
    ///
    /// Возвращает идентификатор: записать его некуда, и потеряв его,
    /// вы потеряете доступ до тех пор, пока не переберёте файлы по PIN.
    ///
    /// Открывать его **обязательно с PIN**: без него перебор ничего
    /// не найдёт, и файл станет мёртвым грузом.
    pub fn create_hidden(&self) -> Result<Vec<u8>, RatatoskError> {
        Ok(self.locked()?.create_hidden(&mut OsEntropy).to_vec())
    }

    /// Меняет имя аккаунта в реестре.
    pub fn rename(&self, id: Vec<u8>, label: String) -> Result<(), RatatoskError> {
        self.locked()?.rename(&to_account_id(&id)?, &label).map_err(RatatoskError::internal)
    }

    /// Убирает аккаунт из реестра, **не трогая его данные**.
    ///
    /// Это и есть «сделать скрытым»: файлы на месте, в списке его больше нет.
    /// Обратная операция — [`AccountRegistry::adopt`].
    pub fn hide(&self, id: Vec<u8>) -> Result<(), RatatoskError> {
        self.locked()?.hide(&to_account_id(&id)?).map_err(RatatoskError::internal)
    }

    /// Вносит в реестр аккаунт, которого там не было, — снимает скрытость.
    pub fn adopt(&self, id: Vec<u8>, label: String) -> Result<FfiAccount, RatatoskError> {
        let account = self
            .locked()?
            .adopt(&to_account_id(&id)?, &label, now_ms())
            .map_err(RatatoskError::internal)?;
        Ok(account_of(&account))
    }

    /// Стирает аккаунт целиком: запись, базу, журнал и вложения.
    ///
    /// **Удаление файла не значит, что байты исчезли.** На флеш-памяти запись
    /// поверх не гарантирована ничем: контроллер пишет в другое место,
    /// а прежнее освобождает когда сочтёт нужным. Делается то, что возможно
    /// из приложения; «стёрто безвозвратно» обещать нельзя.
    ///
    /// Открытый аккаунт стереть нельзя: файл из-под живого ядра — верный
    /// способ получить половину базы. Проверяется здесь, а не оставляется
    /// на совесть клиента.
    pub fn wipe(&self, id: Vec<u8>) -> Result<(), RatatoskError> {
        let id = to_account_id(&id)?;
        if self.live(&id)?.is_some() {
            return Err(RatatoskError::internal("аккаунт открыт: сперва закройте его"));
        }
        self.locked()?.wipe(&id).map_err(RatatoskError::internal)
    }

    /// Открывает аккаунт и поднимает для него ядро.
    ///
    /// Каждый аккаунт получает своё ядро, свою базу и свой каталог вложений.
    /// Открыть один аккаунт **дважды нельзя**: две сессии поверх одной базы
    /// разъедутся в состоянии ретчета, а это не рассинхрон показа, а потеря
    /// переписки. Повторный вызов на уже открытом аккаунте — отказ.
    pub fn open_account(
        &self,
        id: Vec<u8>,
        pin: Option<String>,
        device_key: Option<Vec<u8>>,
        display_name: String,
    ) -> Result<Arc<RatatoskClient>, RatatoskError> {
        let id = to_account_id(&id)?;
        if self.live(&id)?.is_some() {
            return Err(RatatoskError::internal("аккаунт уже открыт"));
        }
        let path = self.locked()?.db_path(&id);
        let path = path
            .to_str()
            .ok_or_else(|| RatatoskError::internal("путь к базе не в UTF-8"))?
            .to_owned();

        let client = RatatoskClient::open(path, pin, device_key, display_name)?;
        let mut opened = self.opened.lock().map_err(|_| poisoned())?;
        opened.retain(|(_, weak)| weak.strong_count() > 0);
        opened.push((id, Arc::downgrade(&client)));
        Ok(client)
    }

    /// Ищет скрытый аккаунт, который открывается этим PIN.
    ///
    /// Перебирает файлы, не числящиеся в реестре, и возвращает
    /// идентификатор первого подошедшего — или `None`, если не подошёл
    /// ни один. Открыть его дальше — [`AccountRegistry::open_account`]
    /// с тем же PIN.
    ///
    /// **Долго.** Каждая попытка стоит одного вывода ключа Argon2id (§8.6) —
    /// около полусекунды; всего их столько, сколько нечислящихся файлов.
    /// Показать человеку ожидание обязательно, иначе он решит, что
    /// приложение зависло. Звать не из UI-потока.
    ///
    /// Ничего при этом не меняется: перебор идёт по чужим файлам, и писать
    /// в них мы не вправе.
    pub fn find_hidden(&self, pin: String) -> Result<Option<Vec<u8>>, RatatoskError> {
        let candidates = {
            let registry = self.locked()?;
            let unlisted = registry.unlisted().map_err(RatatoskError::internal)?;
            unlisted.into_iter().map(|id| (id, registry.db_path(&id))).collect::<Vec<_>>()
        };
        for (id, path) in candidates {
            if vault::accepts_pin(&path, &pin).map_err(engine_err)? {
                return Ok(Some(id.to_vec()));
            }
        }
        Ok(None)
    }

    /// Объявляет в локальной сети **только** названный аккаунт (§5.1).
    ///
    /// Два одновременно объявленных аккаунта — это два сервиса, появляющихся
    /// и исчезающих вместе с одного адреса. §5.1 старательно делает имя
    /// экземпляра случайным, чтобы устройство нельзя было отследить между
    /// запусками, — а тут аккаунты выдавали бы друг друга наблюдателю в той
    /// же сети. Поэтому в эфире всегда один: тот, что сейчас на экране.
    ///
    /// Плата названа честно: остальным аккаунтам по локальной сети в фоне
    /// не приходит ничего.
    ///
    /// Инвариант держится **здесь**, а не в клиенте, и это не придирка:
    /// то, что клиент может забыть, он забудет — а забытый второй маяк
    /// в эфире не виден никому, кроме наблюдателя.
    ///
    /// `id = None` снимает объявление со всех.
    pub fn set_foreground(&self, id: Option<Vec<u8>>) -> Result<(), RatatoskError> {
        let front = match id {
            Some(raw) => Some(to_account_id(&raw)?),
            None => None,
        };
        let mut opened = self.opened.lock().map_err(|_| poisoned())?;
        opened.retain(|(_, weak)| weak.strong_count() > 0);

        // Обход не прерывается на первом отказе, и запоминается только он.
        // Прервавшись, мы оставили бы часть аккаунтов объявленными — то есть
        // ровно то состояние, которого вся эта функция и избегает. Отказ
        // здесь означает остановленное ядро, и он не повод бросить остальных
        // в эфире.
        //
        // `set_foreground`, а не `set_transport_enabled`, и это исправление
        // настоящей поломки. Прежде фоновым уходило «выключить LAN»,
        // а переднему — «включить LAN»: то есть локальная сеть включалась
        // человеку, который её не включал, и записывалась на диск как его
        // выбор. Маяк §5.1 уходил в эфир без спроса, `lan_warning()` перед
        // этим никто не показывал, и обнаруживалось это как «LAN включён
        // по умолчанию».
        //
        // Теперь фактов два и они не смешиваются: выбор человека остаётся
        // на диске нетронутым, а «на экране» живёт только в памяти ядра.
        let mut failure = None;
        for (account, weak) in opened.iter() {
            let Some(client) = weak.upgrade() else { continue };
            if let Err(error) = client.set_foreground(front == Some(*account)) {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl AccountRegistry {
    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Registry>, RatatoskError> {
        self.registry.lock().map_err(|_| poisoned())
    }

    /// Живой клиент этого аккаунта, если он открыт.
    fn live(&self, id: &AccountId) -> Result<Option<Arc<RatatoskClient>>, RatatoskError> {
        let opened = self.opened.lock().map_err(|_| poisoned())?;
        Ok(opened.iter().find(|(a, _)| a == id).and_then(|(_, weak)| weak.upgrade()))
    }
}

fn poisoned() -> RatatoskError {
    RatatoskError::internal("реестр аккаунтов отравлен чужой паникой")
}

fn account_of(account: &Account) -> FfiAccount {
    FfiAccount {
        id: account.id.to_vec(),
        label: account.label.clone(),
        created_ms: account.created_ms,
    }
}

fn to_account_id(bytes: &[u8]) -> Result<AccountId, RatatoskError> {
    bytes.try_into().map_err(|_| RatatoskError::internal("идентификатор аккаунта не 16 байт"))
}

/// Часы для реестра.
///
/// Своя копия, а не общая с драйвером: тот живёт на потоке ядра, а реестр
/// работает до того, как хоть одно ядро поднято.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Единственный читатель потока событий: раздаёт их подписчику.
///
/// Пока подписчика нет, события **отбрасываются**, а не копятся. Очередь
/// событий, накопленная до подписки, выплеснулась бы на UI одним залпом
/// при первом же `set_observer` — и он показал бы как новые те сообщения,
/// которые уже лежат в истории.
async fn pump_events(
    mut events: EventStream,
    observer: Arc<Mutex<Option<Arc<dyn EventObserver>>>>,
) {
    while let Some(event) = events.next().await {
        let Some(translated) = translate(event) else {
            continue;
        };
        let Some(subscriber) = observer.lock().ok().and_then(|slot| slot.clone()) else {
            continue;
        };
        subscriber.on_event(translated);
    }
}

/// Перевод событий ядра в то, что видит UI.
///
/// Варианты перечислены поимённо: новое событие ядра обязано сломать сборку
/// здесь, а не тихо не дойти до клиента.
fn translate(event: Event) -> Option<FfiEvent> {
    Some(match event {
        Event::MessageReceived { chat, msg_id } => {
            FfiEvent::MessageReceived { chat_id: chat.to_vec(), msg_id: msg_id.to_vec() }
        }
        Event::StatusChanged { msg_id, status } => {
            FfiEvent::StatusChanged { msg_id: msg_id.to_vec(), status: status_of(status) }
        }
        Event::ContactAdded { peer_ik, fingerprint, verified } => {
            FfiEvent::ContactAdded { peer_ik: peer_ik.to_vec(), fingerprint, verified }
        }
        Event::MessagesDeleted { chat, msg_ids } => FfiEvent::MessagesDeleted {
            chat_id: chat.to_vec(),
            msg_ids: msg_ids.iter().map(|id| id.to_vec()).collect(),
        },
        Event::MessageEdited { chat, msg_id } => {
            FfiEvent::MessageEdited { chat_id: chat.to_vec(), msg_id: msg_id.to_vec() }
        }
        Event::ChannelCreated { chat, title, open } => {
            FfiEvent::ChannelCreated { chat_id: chat.to_vec(), title, open }
        }
        Event::ChannelChanged { chat, version, title } => {
            FfiEvent::ChannelChanged { chat_id: chat.to_vec(), version, title }
        }
        Event::ChatNotifyChanged { chat } => FfiEvent::ChatNotifyChanged { chat_id: chat.to_vec() },
        Event::ChannelPreviewed { chat, title, open, version, pow_bits } => {
            FfiEvent::ChannelPreviewed { chat_id: chat.to_vec(), title, open, version, pow_bits }
        }
        Event::ChannelSubscribed { chat, awaiting } => {
            FfiEvent::ChannelSubscribed { chat_id: chat.to_vec(), awaiting }
        }
        Event::ChannelUnsubscribed { chat } => {
            FfiEvent::ChannelUnsubscribed { chat_id: chat.to_vec() }
        }
        Event::ChannelRequested { chat, who } => {
            FfiEvent::ChannelRequested { chat_id: chat.to_vec(), who: who.to_vec() }
        }
        Event::SeedingChanged { chat, announced } => {
            FfiEvent::SeedingChanged { chat_id: chat.to_vec(), announced }
        }
        Event::ChannelHistoryEnd { chat } => FfiEvent::ChannelHistoryEnd { chat_id: chat.to_vec() },
        Event::SeedAnnounced { chat, who } => {
            FfiEvent::SeedAnnounced { chat_id: chat.to_vec(), who: who.to_vec() }
        }
        Event::ChannelKeyRotated { chat, generation } => {
            FfiEvent::ChannelKeyRotated { chat_id: chat.to_vec(), generation }
        }
        Event::ChannelAdmitted { chat, who, admitted_by } => FfiEvent::ChannelAdmitted {
            chat_id: chat.to_vec(),
            who: who.to_vec(),
            admitted_by: admitted_by.to_vec(),
        },
        Event::ReactionChanged { chat, msg_id, author_ik } => FfiEvent::ReactionChanged {
            chat_id: chat.to_vec(),
            msg_id: msg_id.to_vec(),
            author_ik: author_ik.to_vec(),
        },
        Event::ContactChanged { peer_ik } => FfiEvent::ContactChanged { peer_ik: peer_ik.to_vec() },
        Event::ContactRemoved { peer_ik } => FfiEvent::ContactRemoved { peer_ik: peer_ik.to_vec() },
        Event::AvatarChanged { peer_ik } => FfiEvent::AvatarChanged { peer_ik: peer_ik.to_vec() },
        Event::OwnAvatarChanged => FfiEvent::OwnAvatarChanged,
        Event::TorStatus { fraction, note, blocked } => {
            FfiEvent::TorStatus { fraction, note, blocked }
        }
        Event::GroupCreated { chat, title } => {
            FfiEvent::GroupCreated { chat_id: chat.to_vec(), title }
        }
        Event::GroupMembershipChanged { chat } => {
            FfiEvent::GroupMembershipChanged { chat_id: chat.to_vec() }
        }
        Event::GroupRenamed { chat, title } => {
            FfiEvent::GroupRenamed { chat_id: chat.to_vec(), title }
        }
        Event::GroupAvatarChanged { chat } => {
            FfiEvent::GroupAvatarChanged { chat_id: chat.to_vec() }
        }
        Event::FileWaitsForChannel { file_id, reason } => FfiEvent::FileWaitsForChannel {
            file_id: file_id.to_vec(),
            reason: wait_reason_of(reason),
        },
        Event::FileProgress { file_id, received, total } => {
            FfiEvent::FileProgress { file_id: file_id.to_vec(), received, total }
        }
        Event::FileSending { file_id, peer_ik, sent, total } => FfiEvent::FileSending {
            file_id: file_id.to_vec(),
            peer_ik: peer_ik.to_vec(),
            sent,
            total,
        },
        Event::FileGone { file_id } => FfiEvent::FileGone { file_id: file_id.to_vec() },
        Event::HonestNotice { text } => FfiEvent::HonestNotice { text: text.to_owned() },
        Event::CommandRefused { reason } => FfiEvent::CommandRefused { reason },
        Event::MailAccountReady { address } => FfiEvent::MailAccountReady { address },
        Event::MailAccountFailed { reason } => FfiEvent::MailAccountFailed { reason },
        Event::MailLoginFailed { reason } => FfiEvent::MailLoginFailed { reason },
        Event::MailLimits { letter_bytes, mailbox_used, mailbox_limit, crowded, carries_files } => {
            FfiEvent::MailLimits {
                letter_bytes,
                mailbox_used,
                mailbox_limit,
                crowded,
                carries_files,
            }
        }
        Event::PairingReady { device_id, uri } => {
            FfiEvent::PairingReady { device_id: device_id.to_vec(), uri }
        }
        Event::PairingRevoked { device_id } => {
            FfiEvent::PairingRevoked { device_id: device_id.to_vec() }
        }
        Event::DeviceLink { device_id, connected } => {
            FfiEvent::DeviceLink { device_id: device_id.to_vec(), connected }
        }
    })
}

fn tracing_stop(error: &ratatosk_core::EngineError) {
    // Отказ ядра наружу не выбрасывается: клиент уже держит объект, а
    // конструктор давно вернулся. Единственное, что честно, — записать.
    //
    // **И записать туда, где прочтут.** Стоял здесь `eprintln!`, то есть
    // на Android — в никуда: остановка ядра, самая громкая беда из всех,
    // не оставляла следа вовсе. Теперь она идёт общим журналом
    // (`enable_logging`).
    tracing::error!(%error, "ядро остановилось");
}

/// Умолчание отбора строк журнала.
///
/// Наше — подробно, чужое — по делу. Без второй половины журнал тонет
/// в arti и tokio, а нужны там наши шесть ступеней.
const LOG_DEFAULT: &str = "ratatosk_transport=debug,ratatosk_core=debug,ratatosk_ffi=debug,info";

/// Разбирает отбор, присланный клиентом, — или берёт обычный.
///
/// Возвращает вместе с отбором признак «просили не то»: сказать об этом
/// надо, но уже в самом журнале. Отказывать за опечатку в отборе нечем
/// и незачем — «не включается, и непонятно почему» тут хуже всего.
fn log_filter(asked: &str) -> (tracing_subscriber::EnvFilter, bool) {
    match tracing_subscriber::EnvFilter::try_new(asked) {
        Ok(env) if !asked.is_empty() => (env, false),
        // `new`, а не `try_new`: строка наша собственная, и ошибка
        // в ней — не событие времени выполнения, а опечатка, которая
        // обязана быть заметной сразу.
        _ => (tracing_subscriber::EnvFilter::new(LOG_DEFAULT), !asked.is_empty()),
    }
}

/// Говорит в журнал о том, как он завёлся. Зовётся уже после подписчика.
fn log_started(where_to: &str, asked: &str, bad: bool) {
    if bad {
        tracing::warn!(отбор = %asked, куда = where_to, "журнал: отбор не разобрался, взят обычный");
    } else {
        tracing::info!(куда = where_to, "журнал: пишем");
    }
}

/// Заводит журнал ядра. Зовётся клиентом **до** открытия хранилища.
///
/// # Почему это вообще нужна отдельная просьба
///
/// Журнал ядра идёт через `tracing`, а `tracing` без подписчика — тишина
/// по построению: макросы никуда не пишут, и стоит это ноль. Поставить
/// его молча при открытии хранилища нельзя: подписчик — вещь процесса,
/// а не сессии, и ставится он один раз на всю жизнь процесса. Решать
/// за приложение, писать ли его внутренности в системный журнал, —
/// не наше дело.
///
/// # Куда попадут строки
///
/// На Android — в `logcat` под тегом `ratatosk` (`adb logcat -s ratatosk`).
/// На десктопе — в **поток ошибок** процесса: там это обычное место
/// журнала, и клиент, запущенный из терминала, видит его сразу.
///
/// **Десктоп сюда добавлен, и это не мелочь.** Прежде вне Android функция
/// не делала ничего вовсе: полагались на то, что подписчика ставит стенд.
/// Но стенд — не единственный десктопный клиент: компаньон на Compose
/// грузит библиотеку через JNA и своего подписчика не имеет ниоткуда.
/// Для него ядро молчало так же, как молчало на телефоне до 0.4, —
/// и разбирать что-либо на десктопе приходилось по одному Kotlin.
///
/// Клиенту без видимого потока ошибок (упакованное приложение) нужен
/// [`enable_file_logging`].
///
/// # Отбор
///
/// `filter` в синтаксисе `RUST_LOG` (`ratatosk_transport=debug,info`);
/// пустая строка означает умолчание — наши крейты подробно, остальное
/// по делу. Непонятный отбор не отказ: журнал заведётся обычным, а о
/// подмене будет сказано в нём же.
///
/// # Второй вызов ничего не делает
///
/// И не считается ошибкой: подписчик в процессе один, а клиент,
/// открывающий второй аккаунт, позовёт эту функцию снова — отказывать
/// ему не за что. По той же причине ничего не ломает вызов из стенда,
/// у которого подписчик свой: чей встал первым, тот и остаётся.
#[uniffi::export]
pub fn enable_logging(filter: String) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let asked = filter.trim().to_owned();
    let (env, bad) = log_filter(&asked);

    #[cfg(target_os = "android")]
    {
        let layer = match tracing_android::layer("ratatosk") {
            Ok(layer) => layer,
            Err(error) => {
                // Сказать некуда — журнала-то и нет. Остаётся системный
                // поток ошибок: на Android он уходит в никуда, но на
                // эмуляторе и в тестах виден.
                eprintln!("ratatosk: журнал не завёлся: {error}");
                return;
            }
        };
        // `try_init`, а не `init`: второй вызов — обычное дело
        // (клиент открыл второй аккаунт), а не повод ронять приложение.
        let _ = tracing_subscriber::registry().with(env).with(layer).try_init();
        log_started("logcat:ratatosk", &asked, bad);
    }

    #[cfg(not(target_os = "android"))]
    {
        // Без цвета: журнал десктопа читают и глазами в терминале,
        // и `grep`-ом из файла, куда его перенаправили. Управляющие
        // последовательности мешают второму и не нужны первому.
        let layer = tracing_subscriber::fmt::layer().with_ansi(false).with_writer(std::io::stderr);
        let _ = tracing_subscriber::registry().with(env).with(layer).try_init();
        log_started("поток ошибок", &asked, bad);
    }
}

/// Заводит журнал ядра **в файл**. Зовётся вместо [`enable_logging`].
///
/// # Зачем отдельно от потока ошибок
///
/// Потому что у упакованного приложения его нет. Компаньон на десктопе
/// запускают ярлыком, а не из терминала; на Android поток ошибок уходит
/// в никуда всегда. В обоих случаях файл — единственное место, откуда
/// журнал можно **достать и прислать**, а именно это и нужно, когда
/// разбирают поломку на чужом устройстве.
///
/// # Файл переписывается на каждом запуске
///
/// Не дописывается, и это осознанный выбор. Дописывание требует уборки:
/// журнал ступеней растёт мегабайтами в час, и без присмотра он однажды
/// займёт весь диск телефона. Один запуск — один файл: разбирают всегда
/// последний прогон, а сохранить предыдущий человек успеет сам.
///
/// Путь клиент выбирает свой — каталог приложения, кэш, что угодно, куда
/// ему разрешено писать. Ядро его не проверяет и не создаёт: не открылся
/// — сказано в поток ошибок, и журнала просто нет.
///
/// Остальное — как у [`enable_logging`]: тот же отбор, то же умолчание,
/// второй вызов так же ничего не делает.
#[uniffi::export]
pub fn enable_file_logging(filter: String, path: String) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let asked = filter.trim().to_owned();
    let (env, bad) = log_filter(&asked);

    // `create`, а не `append`: см. разбор выше про уборку.
    let file = match std::fs::File::create(&path) {
        Ok(file) => file,
        Err(error) => {
            // Единственное место, куда можно сказать: журнала ещё нет.
            eprintln!("ratatosk: журнал в {path} не завёлся: {error}");
            return;
        }
    };
    // Замок вокруг файла — требование `MakeWriter`: строки пишут все
    // потоки ядра сразу, и без него они перемешались бы посередине.
    let layer =
        tracing_subscriber::fmt::layer().with_ansi(false).with_writer(std::sync::Mutex::new(file));
    let _ = tracing_subscriber::registry().with(env).with(layer).try_init();
    log_started(&path, &asked, bad);
}

/// Тексты из §14, которые клиент обязан показать дословно.
///
/// Функция на границе, а не константа в клиенте: §14 существует затем, чтобы
/// обещания продукта не разошлись со свойствами протокола, и держать эти
/// строки в Kotlin означало бы разрешить им разойтись.
#[uniffi::export]
#[must_use]
pub fn honest_notices() -> Vec<String> {
    ratatosk_core::honest::NOTICES.iter().map(|s| (*s).to_string()).collect()
}

/// Что означает открытый канал (фаза 2, §15, §6.1, §10.7).
///
/// Показывается **до** заведения открытого канала, до подписки на него
/// и до того, как ссылкой поделятся: непоправимое здесь одно и то же
/// для обеих сторон. Говорит непоправимое: ключ чтения лежит в самой ссылке,
/// прочтёт её всякий, кому её перешлют, и закрыть доступ обратно нельзя.
///
/// Текст на границе, а не в клиенте, по той же причине, что
/// [`honest_notices`]: §15 существует затем, чтобы обещания продукта
/// не разошлись со свойствами протокола.
#[uniffi::export]
#[must_use]
pub fn open_channel_notice() -> String {
    ratatosk_proto::channel::OpenChannelConsequences::ui_text().to_owned()
}

/// Что означает канал по приглашению (фаза 2, §15, §6.1, §10.4).
///
/// Показывается **подписывающемуся** — при переходе по ссылке на такой
/// канал, до подписки. Заводящему его показывать нечего: текст обращён
/// к тому, кого впускают («впустить вас должен владелец»), и владелец
/// прочёл бы в нём, что его самого кто-то должен впустить.
///
/// **Говорит правду о сегодняшнем дне, а не о спеке.** §15 обещает
/// «он увидит вашу карточку», но заявки подписчика в ядре нет: переход
/// по ссылке не отправляет владельцу ничего, и сказать ему о себе надо
/// другим способом. Появится заявка — изменится и текст, и проверка
/// при нём падает ровно затем, чтобы это не забылось.
#[uniffi::export]
#[must_use]
pub fn private_channel_notice() -> String {
    ratatosk_proto::channel::PrivateChannelConsequences::ui_text().to_owned()
}

/// Что означает передача права «впускать» (фаза 2, §15, §6.5).
///
/// Показывается при **назначении** права, а не при снятии, и это
/// требование §6.5: впущенные остаются впущенными после того, как право
/// у впускавшего снято. Сказанное при снятии уже ничего не меняет.
#[uniffi::export]
#[must_use]
pub fn admitter_grant_notice() -> String {
    ratatosk_proto::channel::AdmitterGrantConsequences::ui_text().to_owned()
}

/// Что означает поворот ключа чтения (фаза 2, §15, §6.4).
///
/// Показывается до кнопки «повернуть сейчас»: §6.4 требует, чтобы она
/// называлась последствием. Все, кого нет в составе, теряют будущее;
/// прочитанное остаётся у них, и обещать обратное нельзя.
#[uniffi::export]
#[must_use]
pub fn key_rotation_notice() -> String {
    ratatosk_proto::channel::KeyRotationConsequences::ui_text().to_owned()
}

/// Что означает «поделиться ссылкой» (фаза 2, §15, §10.2).
///
/// Показывается до показа ссылки: в неё попадает наш адрес, и всякий,
/// к кому она попадёт дальше, узнает его — и то, что мы этот канал
/// читаем, — даже если сам подписываться не станет.
#[uniffi::export]
#[must_use]
pub fn sharing_notice() -> String {
    ratatosk_proto::channel::SharingConsequences::ui_text().to_owned()
}

/// Чем платит сужение круга отдачи (фаза 2, §15, §12).
///
/// Показывается **до** затягивания: §12 требует, чтобы UI сказал, что
/// платят не только за себя. Уровни «только контактам» и «только
/// сверенным» безобидны как личный выбор и разрушительны как
/// популярный — рой сворачивается в граф контактов, а заметит это
/// не тот, кто настраивал, а новый подписчик.
///
/// Сосед [`sharing_notice`] — про другое: там показ **ссылки** (§10.2).
#[uniffi::export]
#[must_use]
pub fn sharing_level_notice() -> String {
    ratatosk_proto::swarm::SharingLevelConsequences::ui_text().to_owned()
}

/// Что означает «объявить себя раздающим» (фаза 2, §15, §7.5.1).
///
/// Показывается **до** включения: адрес узнаёт каждый читатель канала,
/// набирать по нему будут незнакомые, а отказ гасит объявление не сразу —
/// оно живёт сроком годности (§7.5).
#[uniffi::export]
#[must_use]
pub fn seeding_notice() -> String {
    ratatosk_proto::swarm::SeedingConsequences::ui_text().to_owned()
}

/// Наибольший размер аватарки в байтах.
///
/// Функция на границе, а не число в клиенте: масштабирует изображение клиент,
/// и предел, записанный у него отдельно, однажды разойдётся с ядром — тогда
/// пользователь получит отказ уже после того, как выбрал фотографию.
#[uniffi::export]
#[must_use]
pub fn max_avatar_bytes() -> u32 {
    // `try_from`, а не `as`: предел заведомо мал, но молчаливое усечение
    // в этом месте однажды дало бы клиенту разрешение на кадр, который ядро
    // не примет.
    u32::try_from(ratatosk_proto::MAX_AVATAR_BYTES).unwrap_or(u32::MAX)
}

/// Наибольшая длина локального имени контакта, в символах.
#[uniffi::export]
#[must_use]
pub fn max_local_name_chars() -> u32 {
    u32::try_from(ratatosk_core::MAX_LOCAL_NAME_CHARS).unwrap_or(u32::MAX)
}

/// Что сказать про сообщение, ждущее появления собеседника.
#[uniffi::export]
#[must_use]
pub fn waiting_notice() -> String {
    ratatosk_core::honest::WAITING_NOTICE.to_string()
}

/// Что сказать перед отзывом сообщения (§14).
#[uniffi::export]
#[must_use]
pub fn retraction_notice() -> String {
    ratatosk_core::honest::RETRACTION_NOTICE.to_string()
}

/// Что сказать перед удалением контакта (§14).
#[uniffi::export]
#[must_use]
pub fn deletion_notice() -> String {
    ratatosk_core::honest::DELETION_NOTICE.to_string()
}

/// Что сказать перед отзывом сверки (§4.2).
#[uniffi::export]
#[must_use]
pub fn revocation_notice() -> String {
    ratatosk_core::honest::REVOCATION_NOTICE.to_string()
}

/// Что показать на файле, передача которого стоит (§10.3).
///
/// Текст задан ядром и переписыванию не подлежит: он обещает ровно то,
/// что протокол делает. «Ошибка отправки» и «загрузка…» здесь одинаково
/// неправда — файл не потерян и поедет сам, кроме одного случая, когда
/// от человека что-то нужно.
///
/// Причину берут из [`FfiEvent::FileWaitsForChannel`]: одного текста
/// на все пять не бывает, и попытка обойтись одним стоила двух
/// потраченных гипотез на живой поломке.
#[uniffi::export]
#[must_use]
pub fn file_waiting_text(reason: FfiFileWaitReason) -> String {
    wait_reason_back(reason).text().to_string()
}

/// Предупреждение при включении LAN (§5.1).
#[uniffi::export]
#[must_use]
pub fn lan_warning() -> String {
    ratatosk_core::honest::LAN_WARNING.to_string()
}

/// Адрес `200::/7`, выведенный из ключа узла в меше (0.2).
///
/// Считает **ядро**, а не клиент, и это §13.3: вывод адреса — правило чужой
/// сети, а не рисование. Две реализации одного правила разошлись бы молча,
/// и человек сверял бы с `yggdrasilctl getSelf` не тот адрес, по которому
/// мы на самом деле слушаем.
///
/// `None` — ключ не тридцати двух байт, в том числе пустой.
#[uniffi::export]
#[must_use]
pub fn ygg_address(key: Vec<u8>) -> Option<String> {
    <[u8; 32]>::try_from(key.as_slice()).ok().map(|key| ratatosk_proto::ygg::address_text(&key))
}

/// Предупреждение при включении меша Yggdrasil (0.2).
///
/// Показывается **до** `set_transport_enabled(Ygg, true)`, как и у LAN.
/// Разница в цене: LAN раскрывает присутствие, меш вдобавок тратит
/// батарею и трафик человека на чужие пакеты.
#[uniffi::export]
#[must_use]
pub fn ygg_warning() -> String {
    ratatosk_core::honest::YGG_WARNING.to_string()
}

/// Что ещё сказать перед выбором встроенного узла меша (0.2).
///
/// Показывается **вдобавок** к [`ygg_warning`], а не вместо: цена та же,
/// а нового здесь две вещи. Пиров человек называет сам, и без них узел
/// молчит — это самая частая причина «меш не работает». И имя в меше
/// приложение выдаёт себе само, вместе с базой.
#[uniffi::export]
#[must_use]
pub fn ygg_node_notice() -> String {
    ratatosk_core::honest::YGG_NODE_NOTICE.to_string()
}

/// Что показать при **выключении** встроенного узла меша (0.2).
///
/// Обязательно, а не по желанию. Человек выключает меш затем, чтобы
/// перестать переносить чужой трафик, — а библиотека узла остановки
/// не умеет, и трафик пойдёт до перезапуска приложения. Промолчать здесь
/// значило бы пообещать больше, чем делается.
#[uniffi::export]
#[must_use]
pub fn ygg_node_stop_notice() -> String {
    ratatosk_core::honest::YGG_NODE_STOP_NOTICE.to_string()
}

/// Предупреждение при включении ступени nostr (0.3).
///
/// Показывается **до** `set_transport_enabled(Nostr, true)`, как у LAN
/// и у меша. Цена своя: реле видит, какие ключи переписываются между собой
/// и когда, — то же, что почтовый сервер видит по `From:` и `To:`.
///
/// Средство у человека одно, и оно настоящее: реле он называет сам и может
/// назвать несколько, поделив след между ними. У почты такого выбора нет —
/// сервер один.
#[uniffi::export]
#[must_use]
pub fn nostr_warning() -> String {
    ratatosk_core::honest::NOSTR_WARNING.to_string()
}

/// Что сказать **до** переключения ступени nostr на путь мимо Tor (0.3).
///
/// Обязательно, а не по желанию: ключ nostr долговечен и общий для всех
/// собеседников, и реле, увидевшее адрес устройства рядом с ним, связывает
/// их навсегда. Решение при этом остаётся за человеком — есть места, где
/// Tor недоступен физически, и там ступень без этого не работает вовсе.
#[uniffi::export]
#[must_use]
pub fn nostr_direct_warning() -> String {
    ratatosk_core::honest::NOSTR_DIRECT_WARNING.to_string()
}

/// Что сказать про файлы на ступени nostr (0.3).
///
/// Файлы этой ступенью не ходят и ходить не будут: кусок файла — кадр
/// класса L, мебибайт, а реле меряют событие десятками килобайт. Передача
/// ждёт прямой связи или уходит почтой, и сказать об этом надо словами —
/// молчащая передача выглядит как поломка.
#[uniffi::export]
#[must_use]
pub fn nostr_no_files_notice() -> String {
    ratatosk_core::honest::NOSTR_NO_FILES_NOTICE.to_string()
}

/// Предупреждение при отказе от PIN (§8.6).
#[uniffi::export]
#[must_use]
pub fn no_pin_warning() -> String {
    ratatosk_core::honest::NO_PIN_WARNING.to_string()
}

/// Сколько времени сообщение можно править, в миллисекундах.
///
/// Функция на границе, а не число в клиенте: кнопку «изменить» рисует он,
/// и предел, записанный у него отдельно, однажды разойдётся с ядром — тогда
/// человек увидит кнопку, которая отказывает.
#[uniffi::export]
#[must_use]
pub fn max_edit_age_ms() -> u64 {
    ratatosk_proto::MAX_EDIT_AGE_MS
}

/// Наибольшая длина реакции в байтах.
#[uniffi::export]
#[must_use]
pub fn max_reaction_bytes() -> u32 {
    u32::try_from(ratatosk_proto::MAX_REACTION_BYTES).unwrap_or(u32::MAX)
}

/// Сколько сообщений можно переслать одной командой.
#[uniffi::export]
#[must_use]
pub fn max_forward_ids() -> u32 {
    u32::try_from(ratatosk_proto::MAX_FORWARD_IDS).unwrap_or(u32::MAX)
}

/// Размер куска файла в байтах — **умолчание провода**, а не правда
/// о конкретном файле.
///
/// Годится, чтобы прикинуть, на сколько кусков разойдётся файл, который
/// мы собираемся отправить по обычной сети. Для показа хода **принятого**
/// файла брать его нельзя: нарезку выбирает отправитель по своей ступени
/// (§10.2), и у приехавшего по эфиру она мельче в двести с лишним раз.
/// Своё число у файла отдают [`FfiFile::chunk_bytes`]
/// и [`FfiFileReader::chunk_bytes`].
#[uniffi::export]
#[must_use]
pub fn chunk_bytes() -> u32 {
    u32::try_from(ratatosk_proto::files::CHUNK_BYTES).unwrap_or(u32::MAX)
}

/// Наибольший размер файла в байтах.
#[uniffi::export]
#[must_use]
pub fn max_file_bytes() -> u64 {
    ratatosk_proto::files::MAX_FILE_BYTES
}

/// Наибольший размер файла, который поедет почтой (§10.3).
///
/// Файл крупнее ждёт прямого канала: почтой он поехал бы сутками, и §14
/// велит сказать это до начала, а не показывать полосу, которая
/// не сдвинется. Ограничение это про **время**, а не про место — место
/// защищает окно передачи.
///
/// Клиенту нужно, чтобы сказать заранее. Без этого числа он узнаёт
/// о запрете только событием [`FfiEvent::FileWaitsForChannel`], то есть
/// уже после того, как человек выбрал файл и нажал «отправить».
///
/// Заведомо меньше [`max_file_bytes`]: прямым каналом ходит всё.
/// Чем открывают архив (§12).
///
/// Два входа в один и тот же архив. Фразу человек придумал сам и держит
/// в голове; сырой ключ он положил в менеджер паролей и не смотрит на него
/// никогда. Спрашивать надо **тот, который подойдёт**, — что подойдёт,
/// говорит [`peek_archive`].
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiArchiveUnlock {
    /// Фраза, придуманная при вывозе.
    Passphrase {
        /// Она самая.
        phrase: String,
    },
    /// Сырой ключ — та строка, что показывалась при вывозе.
    Key {
        /// Разделители и регистр не важны.
        key_text: String,
    },
}

/// Что за архив лежит по этому пути (§12).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiArchivePeek {
    /// Что вывезено.
    pub scope: FfiExportScope,
    /// Открывается ли фразой. `false` — спрашивать надо ключ.
    pub takes_passphrase: bool,
}

/// Заглядывает в архив, ничего не открывая (§12).
///
/// **Звать до того, как что-то спрашивать у человека.** Экран, требующий
/// фразу от архива, в котором её нет, — тупик: человек будет вспоминать
/// то, чего никогда не было. Ни ключа, ни фразы для этого не нужно: область
/// вывоза и наличие завёрнутого ключа лежат в архиве открыто и о переписке
/// ничего не говорят.
///
/// # Errors
///
/// Файла нет, это не архив, он новее этой сборки или оборван.
#[uniffi::export]
pub fn peek_archive(archive: String) -> Result<FfiArchivePeek, RatatoskError> {
    let peek = ratatosk_store::peek_archive(std::path::Path::new(&archive))
        .map_err(RatatoskError::internal)?;
    Ok(FfiArchivePeek {
        scope: match peek.scope {
            ratatosk_core::ExportScope::Everything => FfiExportScope::Everything,
            ratatosk_core::ExportScope::WithoutAttachments => FfiExportScope::WithoutAttachments,
            ratatosk_core::ExportScope::SocialGraph => FfiExportScope::SocialGraph,
        },
        takes_passphrase: peek.takes_passphrase,
    })
}

/// Что дало слияние знакомств (§12).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMerged {
    /// Вывезен ли архив этой же личностью.
    ///
    /// `false` — список чужой, и никто в нём не сверен.
    pub own_graph: bool,
    /// Сколько знакомств добавлено.
    pub added: u64,
    /// Сколько уже было — **не тронуты** ни в одном поле.
    pub known: u64,
    /// Сколько записей отвергнуто как негодные.
    pub refused: u64,
}

/// Что приехало из архива — для показа человеку (§12).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiImported {
    /// Что было вывезено: `Everything`, `WithoutAttachments`, `SocialGraph`.
    pub scope: FfiExportScope,
    /// Сколько знакомств приехало.
    pub contacts: u64,
    /// Сколько сообщений.
    pub messages: u64,
    /// Сколько записей о вложениях.
    pub files: u64,
    /// Сколько вложений доехало **целиком** — байтами, а не записью.
    ///
    /// Разница с `files` — это то, о чём человеку стоит сказать: вложения,
    /// чьи байты остались на прежнем устройстве, показываются неполученными.
    pub whole_files: u64,
    /// Сколько байт вложений легло на диск.
    pub bytes: u64,
}

/// Восстанавливает аккаунт из архива (§12).
///
/// **Это восстановление, а не слияние.** Архив становится аккаунтом целиком;
/// база по пути `destination` не должна существовать — иначе отказ. Слияния
/// с живущим аккаунтом в v1 нет и не будет: у него нет ответа на вопрос,
/// чьей остаётся личность.
///
/// `key_text` — та строка, которую человек переписал с экрана при вывозе.
/// Разделители и регистр не важны.
///
/// Три вещи, которые UI обязан сказать человеку **после** успеха:
///
/// 1. **Прежним устройством пользоваться больше нельзя.** Восстановленный
///    аккаунт — та же личность; два устройства с одним `IK` разойдутся
///    сессиями и запутают собеседников. Для второго экрана есть режим
///    компаньона (§13.4).
/// 2. **База открывается прежним PIN.** Соль уехала в архиве вместе
///    с базой, поэтому `open` после ввоза ждёт тот PIN, что был на старом
///    телефоне, а не новый.
/// 3. Если `whole_files` меньше `files` — часть вложений осталась дома.
///
/// # Errors
///
/// Файла нет, это не архив, он оборван, ключ не тот, архив сделан сборкой
/// новее или база на месте назначения уже есть.
#[uniffi::export]
pub fn import_archive(
    archive: String,
    unlock: FfiArchiveUnlock,
    destination: String,
    files_dir: String,
) -> Result<FfiImported, RatatoskError> {
    // Ключ разбирается **до** всего остального: строка длинная, ошибиться
    // в ней легко, и «ключ не разобрался» человек обязан услышать раньше,
    // чем что-либо начнёт создаваться.
    let key = match &unlock {
        FfiArchiveUnlock::Key { key_text } => {
            Some(ratatosk_crypto::storage_key::key_from_text(key_text).map_err(|_| {
                RatatoskError::internal("ключ не разобрался: перепишите его целиком")
            })?)
        }
        FfiArchiveUnlock::Passphrase { .. } => None,
    };
    let unlock = match (&unlock, &key) {
        (FfiArchiveUnlock::Passphrase { phrase }, _) => {
            ratatosk_store::ArchiveUnlock::Passphrase(phrase)
        }
        (_, Some(key)) => ratatosk_store::ArchiveUnlock::Key(key),
        (FfiArchiveUnlock::Key { .. }, None) => unreachable!("ключ разобран выше"),
    };
    let mut blobs = ratatosk_store::FsBlobs::new(std::path::PathBuf::from(files_dir));
    let done = ratatosk_store::import_archive(
        std::path::Path::new(&archive),
        unlock,
        std::path::Path::new(&destination),
        &mut blobs,
    )
    .map_err(RatatoskError::internal)?;
    Ok(FfiImported {
        scope: match done.scope {
            ratatosk_core::ExportScope::Everything => FfiExportScope::Everything,
            ratatosk_core::ExportScope::WithoutAttachments => FfiExportScope::WithoutAttachments,
            ratatosk_core::ExportScope::SocialGraph => FfiExportScope::SocialGraph,
        },
        contacts: done.contacts,
        messages: done.messages,
        files: done.files,
        whole_files: done.whole_files,
        bytes: done.bytes,
    })
}

/// Насколько большой файл ещё уедет почтой.
///
/// Через сеть предел другой и выше: почта — самый узкий из транспортов,
/// и UI показывает именно этот предел, когда сети нет.
#[uniffi::export]
#[must_use]
pub fn mail_file_limit_bytes() -> u64 {
    ratatosk_proto::files::MAIL_FILE_LIMIT_BYTES
}

/// Сколько файлов можно приложить к одному сообщению.
#[uniffi::export]
#[must_use]
pub fn max_files_per_message() -> u32 {
    u32::try_from(ratatosk_proto::files::MAX_FILES_PER_MESSAGE).unwrap_or(u32::MAX)
}

/// Наибольший размер превью в байтах (§10.3).
#[uniffi::export]
#[must_use]
pub fn max_preview_bytes() -> u32 {
    u32::try_from(ratatosk_proto::files::PREVIEW_LIMIT_BYTES).unwrap_or(u32::MAX)
}

/// Наибольшая длина текста сообщения в **байтах**.
///
/// Одно число на всё: и на сообщение без вложений, и на подпись к десяти
/// файлам с превью. Выведено из худшего случая, поэтому у простого текста
/// остаётся неиспользованный запас, — но правило одно, и применить его
/// не то нельзя.
///
/// **Считать надо байты, а не символы.** Кириллица в UTF-8 идёт по два байта
/// на букву, эмодзи по четыре: счётчик символов в поле ввода обманул бы
/// человека вдвое или вчетверо. В Kotlin это `text.toByteArray().size`,
/// а не `text.length`.
#[uniffi::export]
#[must_use]
pub fn max_text_bytes() -> u32 {
    u32::try_from(ratatosk_proto::files::MAX_TEXT_BYTES).unwrap_or(u32::MAX)
}

/// Порог автоматического приёма файлов по умолчанию.
#[uniffi::export]
#[must_use]
pub fn default_auto_accept_bytes() -> u64 {
    ratatosk_proto::files::DEFAULT_AUTO_ACCEPT_BYTES
}

/// Что сказать, когда исходный файл исчез (§14).
#[uniffi::export]
#[must_use]
pub fn file_source_gone_notice() -> String {
    ratatosk_core::honest::FILE_SOURCE_GONE.to_string()
}

/// Что сказать перед правкой сообщения (§14).
#[uniffi::export]
#[must_use]
pub fn edit_notice() -> String {
    ratatosk_core::honest::EDIT_NOTICE.to_string()
}

/// Что показать вместо цитаты, которой нет.
///
/// Ответ несёт ссылку, а не текст: цитата берётся из своей копии сообщения,
/// и если её нет — удалили, не дошло, вычистила уборка — показывать нечего.
/// Строка отсюда, а не из клиента: придуманная цитата и пустая рамка — два
/// способа соврать об одном и том же.
#[uniffi::export]
#[must_use]
pub fn quote_unavailable_notice() -> String {
    ratatosk_core::honest::QUOTE_UNAVAILABLE.to_string()
}

/// Что сказать при пересылке (§14).
#[uniffi::export]
#[must_use]
pub fn forward_notice() -> String {
    ratatosk_core::honest::FORWARD_NOTICE.to_string()
}

/// Наибольшая длина названия группы, в символах (§11).
///
/// Считать клиенту приходится самому: поле ввода обязано останавливать
/// человека до нажатия, а не после отказа. **Символы, а не байты** —
/// предел здесь продуктовый, и кириллица в нём считается так же, как латиница.
#[uniffi::export]
#[must_use]
pub fn max_group_title_chars() -> u32 {
    u32::try_from(ratatosk_core::MAX_GROUP_TITLE_CHARS).unwrap_or(u32::MAX)
}

/// Формулировка последствий исключения из группы (§11.4).
#[uniffi::export]
#[must_use]
pub fn eviction_notice() -> String {
    ratatosk_proto::group::EvictionConsequences::ui_text().to_string()
}

/// Что сказать перед выходом из группы.
///
/// Половина сказанного совпадает с [`eviction_notice`] дословно, и это
/// не небрежность: изнутри протокола выход и исключение — одна и та же
/// операция состава, и последствия у них одни.
#[uniffi::export]
#[must_use]
pub fn leave_notice() -> String {
    ratatosk_proto::group::LeaveConsequences::ui_text().to_string()
}

/// Что добавить, если из группы выходит её создатель.
///
/// Отдельным текстом, а не припиской ко всем: остальным участникам это
/// сказать нечего, а предупреждение, которое видят все, перестают читать.
/// Показывать вместе с [`leave_notice`], когда `owner_ik` группы совпадает
/// с собственным ключом.
#[uniffi::export]
#[must_use]
pub fn owner_leave_notice() -> String {
    ratatosk_proto::group::LeaveConsequences::owner_text().to_string()
}

/// Что сказать при создании группы (§11.5).
///
/// Спецификация требует этого дословно: «присоединение раскрывает всем
/// участникам onion- и chatmail-адреса друг друга. Так и сказать
/// при создании группы».
///
/// Показывать **до** создания, как [`lan_warning`], а не после: сказанное
/// после — уже не предупреждение. Отменить это нельзя ничем: вышедший
/// из группы адреса уже знает.
#[uniffi::export]
#[must_use]
pub fn group_join_notice() -> String {
    ratatosk_proto::group::JOIN_DISCLOSURE.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(mine: bool, joined: bool) -> ratatosk_core::driver::GroupStatus {
        status_with_avatar(mine, joined, 0)
    }

    fn status_with_avatar(
        mine: bool,
        joined: bool,
        avatar_ms: u64,
    ) -> ratatosk_core::driver::GroupStatus {
        ratatosk_core::driver::GroupStatus {
            chat: [7u8; 16],
            title: "у костра".to_owned(),
            created_ms: 100,
            members: vec![
                ratatosk_core::GroupMember { ik: [1u8; 32], name: "я".to_owned(), mine: true },
                ratatosk_core::GroupMember {
                    ik: [2u8; 32], name: "гость".to_owned(), mine: false
                },
            ],
            mine,
            joined,
            avatar_ms,
            free_slots: 30,
            // Заготовка — про **группу**: канальные поля у неё пусты,
            // и этим же отличием проверяется, что «это канал» выражено
            // наличием записи, а не полем.
            channel: None,
        }
    }

    /// Та же заготовка, но канал — с фактами §6.
    fn channel_status(
        facts: ratatosk_core::engine::ChannelFacts,
    ) -> ratatosk_core::driver::GroupStatus {
        ratatosk_core::driver::GroupStatus { channel: Some(facts), ..status(false, true) }
    }

    /// Факты канала, в котором нам ничего не разрешено.
    fn plain_facts() -> ratatosk_core::engine::ChannelFacts {
        ratatosk_core::engine::ChannelFacts {
            version: 3,
            open: Some(false),
            owner_ik: [9u8; 32],
            rights: 0,
            rights_until_ms: 0,
            pow_bits: 0,
            awaiting: false,
            readable: true,
            generation: 2,
            may_rotate: false,
            owner_quiet_ms: None,
            owner_unseen: false,
            grants_expiring: 0,
            waiting: None,
            sources_now: Some(1),
            seeds_known: 1,
            awaiting_blocks: 0,
            rotation_overdue: false,
        }
    }

    #[test]
    fn every_channel_signal_crosses_the_boundary_and_comes_back_itself() {
        // Признак едет наружу переводом, а слова к нему берутся
        // обратным переводом — значит пара обязана быть тождеством.
        // Разойдись она хоть на одном варианте, человек прочёл бы
        // объяснение не того, что видит.
        //
        // **Чего проверка не стережёт:** список набран руками, и новый
        // вариант, забытый в переводе, ею не ловится. Ловит его
        // компилятор: оба `match` исчерпывающие.
        use ratatosk_proto::channel::Signal;

        for signal in [
            Signal::Fine,
            Signal::Awaiting,
            Signal::NotReadable,
            Signal::NobodyServes,
            Signal::SeedsUnreachable,
            Signal::OwnerUnseen,
            Signal::Waiting,
            Signal::RotationOverdue,
        ] {
            let outside = signal_of(signal);
            assert_eq!(core_signal(outside), signal, "перевод потерял признак: {signal:?}");
            assert_eq!(
                channel_signal_text(outside),
                signal.ui_text(),
                "слова разошлись с признаком: {signal:?}"
            );
        }
    }

    #[test]
    fn every_channel_signal_but_fine_has_words() {
        // Признак без слов — точка на экране, о которой в каждом
        // клиенте напишут своё. §15 держит тексты в ядре ровно за этим.
        for signal in [
            FfiChannelSignal::Awaiting,
            FfiChannelSignal::NotReadable,
            FfiChannelSignal::NobodyServes,
            FfiChannelSignal::SeedsUnreachable,
            FfiChannelSignal::OwnerUnseen,
            FfiChannelSignal::Waiting,
            FfiChannelSignal::RotationOverdue,
        ] {
            assert!(!channel_signal_text(signal).is_empty(), "признак без слов: {signal:?}");
        }
        // А «всё как надо» слов не имеет и иметь не должно: показывать
        // нечего, и строка «всё хорошо» на экране — шум, который
        // человек через неделю перестанет читать вместе с остальными.
        assert!(channel_signal_text(FfiChannelSignal::Fine).is_empty());
    }

    #[test]
    fn a_group_crosses_the_boundary_whole() {
        let it = group_of(&status(true, true));
        assert_eq!(it.chat_id, vec![7u8; 16]);
        assert_eq!(it.title, "у костра");
        assert_eq!(it.created_ms, 100);
        assert_eq!(it.members.len(), 2, "состав едет целиком: по нему рисуют участников");
        // Все три поля участника — и `mine` тут главное: без него клиент
        // искал бы себя перебором контактов и не нашёл бы.
        let me = it.members.iter().find(|m| m.mine).expect("себя обязано быть видно");
        assert_eq!(me.ik, vec![1u8; 32]);
        assert_eq!(me.name, "я", "имя считает ядро, а не клиент");
        assert!(it.members.iter().any(|m| !m.mine && m.name == "гость"));
        assert!(it.mine);
        assert!(it.joined);
        assert_eq!(it.avatar_ms, 0, "картинки нет — и метка нулевая");
        assert_eq!(it.free_slots, 30, "остаток мест едет наружу: по нему гасят «добавить»");
    }

    #[test]
    fn the_avatar_stamp_crosses_the_boundary() {
        // Метка, а не признак «есть картинка»: булево на смену картинки
        // не реагирует, и клиент показывал бы прежнее лицо до перезапуска.
        // Потеряйся поле здесь — картинка обновлялась бы только по событию,
        // а окно, открытое позже события, показывало бы старую.
        let it = group_of(&status_with_avatar(true, true, 1_700_000_000_001));
        assert_eq!(it.avatar_ms, 1_700_000_000_001);
    }

    #[test]
    fn leaving_does_not_take_away_being_the_creator() {
        // Два разных факта, и путать их нельзя: создатель, ушедший
        // из группы, остаётся создателем и, вернувшись, снова сможет
        // исключать. Поэтому «показывать ли исключить» — это `mine
        // && joined`, а не `mine`.
        let it = group_of(&status(true, false));
        assert!(it.mine, "владение выходом не снимается");
        assert!(!it.joined, "а состоять мы перестали");
    }

    #[test]
    fn a_group_we_never_owned_and_already_left_says_so_plainly() {
        // `joined = false` покрывает и «вышли сами», и «исключили»:
        // различать их клиенту незачем, показывать надо одно и то же.
        let it = group_of(&status(false, false));
        assert!(!it.mine);
        assert!(!it.joined);
    }

    /// Полная группа — ответ, а не сбой.
    ///
    /// **Различие содержательное, а не косметическое**, ровно как
    /// у «не того PIN» выше: с полной группой человек что-то делает —
    /// заводит вторую или кого-то убирает, — а с внутренней ошибкой
    /// не делает ничего, кроме переустановки клиента. Показать первое
    /// как второе значит посоветовать выбросить работающее.
    #[test]
    fn a_full_group_is_an_answer_and_not_a_fault() {
        let refusal = engine_err(ratatosk_core::EngineError::Group(
            ratatosk_proto::GroupError::TooManyMembers,
        ));
        let RatatoskError::GroupFull { limit } = refusal else {
            panic!("полная группа обязана отличаться от внутренней ошибки");
        };
        assert_eq!(
            usize::try_from(limit).unwrap_or(0),
            ratatosk_proto::MAX_GROUP_MEMBERS,
            "предел едет с отказом, чтобы клиенту не держать его у себя"
        );
    }

    /// Остальные отказы группы остаются внутренней ошибкой.
    ///
    /// Пара к предыдущей: выведи мы наружу всё подряд — и клиенту пришлось бы
    /// разбирать виды, о которых ему сказать человеку нечего.
    #[test]
    fn the_other_group_refusals_stay_internal() {
        for other in [ratatosk_proto::GroupError::NotOwner, ratatosk_proto::GroupError::NotAMember]
        {
            assert!(
                matches!(
                    engine_err(ratatosk_core::EngineError::Group(other)),
                    RatatoskError::Internal { .. }
                ),
                "наружу выведен ровно тот отказ, с которым человеку есть что делать"
            );
        }
    }

    // --- Каналы на границе (фаза 2, §6, §10, §13.3) ------------------------

    /// Канал отличается от группы **наличием записи**, а не полем.
    #[test]
    fn a_group_carries_no_channel_facts_and_a_channel_carries_them_all() {
        assert!(
            group_of(&status(true, true)).channel.is_none(),
            "у группы канального экрана нет: рисовать по нему нечего"
        );

        let it = group_of(&channel_status(plain_facts()));
        let channel = it.channel.expect("у канала факты обязаны доехать");
        assert_eq!(channel.version, 3);
        assert_eq!(channel.open, Some(false));
        assert_eq!(channel.owner_ik, vec![9u8; 32], "по владельцу проверяется подпись (§10.3)");
        assert_eq!(channel.generation, 2);
        assert!(channel.readable);
        assert!(!channel.rights.write, "право писать считает ядро, а не клиент по составу");
    }

    /// Права едут четырьмя вопросами и возвращаются теми же битами.
    #[test]
    fn rights_cross_the_boundary_in_both_directions() {
        use ratatosk_proto::channel::Rights;

        let bits = Rights::WRITE.with(Rights::EVICT).bits();
        let shown = rights_of(bits);
        assert!(shown.write && shown.evict, "выданное обязано быть видно");
        assert!(!shown.admit && !shown.edit, "невыданное — не выдумано");
        assert_eq!(rights_back(shown), bits, "обратный перевод обязан сойтись");

        // **Названная цена этой записи.** Незнакомый бит переживает
        // документ, но слова для него у нас нет: выдавая права отсюда,
        // клиент его снимет. Проверка стоит затем, чтобы это осталось
        // решением, а не неожиданностью.
        let odd = bits | (1 << 17);
        assert_eq!(
            rights_back(rights_of(odd)),
            bits,
            "незнакомое право через экран не проходит — и об этом сказано в доке"
        );
    }

    /// Отказ канала — ответ, а не сбой, и у каждого есть слова.
    #[test]
    fn every_channel_refusal_is_an_answer_with_words() {
        use ratatosk_core::EngineError;

        let named = [
            (EngineError::NotAllowedInChannel, FfiChannelRefusal::NoRight),
            (EngineError::OwnerNeedsNoGrant, FfiChannelRefusal::OwnerNeedsNoGrant),
            (EngineError::OnlyOwnerPublishesYet, FfiChannelRefusal::OnlyOwnerPublishesYet),
            (EngineError::OnlyOwnerRotates, FfiChannelRefusal::OnlyOwnerRotates),
            (EngineError::NotAChannel, FfiChannelRefusal::WrongProfile),
            (EngineError::NotAGroup, FfiChannelRefusal::WrongProfile),
            (EngineError::OpenChannelHasNoRotation, FfiChannelRefusal::OpenHasNoRotation),
            (EngineError::RotatedTooRecently, FfiChannelRefusal::RotatedTooRecently),
            (EngineError::NoReadKeyYet, FfiChannelRefusal::NoReadKeyYet),
            (EngineError::PowTooHard, FfiChannelRefusal::PowTooHard),
            (EngineError::BadChannelLink, FfiChannelRefusal::BadLink),
            (EngineError::AlreadySubscribed, FfiChannelRefusal::AlreadySubscribed),
            (EngineError::CannotUnsubscribeOwnChannel, FfiChannelRefusal::OwnChannel),
            (EngineError::TooManyGrants, FfiChannelRefusal::TooManyGrants),
        ];
        for (error, expected) in named {
            let RatatoskError::Channel { reason } = engine_err(error) else {
                panic!(
                    "отказ канала, показанный внутренней ошибкой, советует переустановить \
                        работающее"
                );
            };
            assert_eq!(reason, expected, "каждая причина требует от человека своего действия");
            // Текст не проверяется дословно — он правится, — но пустым
            // он не бывает: молчащий отказ и есть та самая внутренняя
            // ошибка, от которой причины и отделены.
            assert!(!channel_refusal_text(reason).is_empty(), "у отказа обязаны быть слова");
        }
    }

    /// А то, с чем человеку делать нечего, наружу не выводится.
    #[test]
    fn a_channel_refusal_that_says_nothing_to_a_human_stays_internal() {
        assert!(
            matches!(
                engine_err(ratatosk_core::EngineError::UnknownGroup),
                RatatoskError::Internal { .. }
            ),
            "«такой группы нет» — это сбой клиента, а не выбор человека"
        );
    }

    /// Тексты §15 доезжают целиком и берутся у ядра.
    #[test]
    fn the_channel_notices_come_from_the_protocol_and_not_from_the_client() {
        use ratatosk_proto::channel;

        assert_eq!(open_channel_notice(), channel::OpenChannelConsequences::ui_text());
        assert_eq!(private_channel_notice(), channel::PrivateChannelConsequences::ui_text());
        assert_eq!(admitter_grant_notice(), channel::AdmitterGrantConsequences::ui_text());
        assert_eq!(key_rotation_notice(), channel::KeyRotationConsequences::ui_text());
        assert_eq!(sharing_notice(), channel::SharingConsequences::ui_text());
        assert_eq!(seeding_notice(), ratatosk_proto::swarm::SeedingConsequences::ui_text());
        assert_eq!(
            sharing_level_notice(),
            ratatosk_proto::swarm::SharingLevelConsequences::ui_text()
        );
        // **Два соседних текста про разное, и перепутать их легко.**
        // `sharing_notice` — про показ ссылки (§10.2), `sharing_level_notice`
        // — про то, кому мы отдаём блоки (§12). Совпади они, клиент
        // показал бы человеку не то последствие, о котором спрашивает.
        assert_ne!(sharing_notice(), sharing_level_notice(), "тексты про разное");
    }

    #[test]
    fn the_giving_limits_cross_the_boundary_in_both_directions() {
        // Числа §9.2 человек правит экраном настроек, и на границе они
        // обязаны ходить туда и обратно: перевод «в одну сторону»
        // однажды показал бы не тот предел, который стоит у ядра.
        let limits = FfiGivingLimits { per_peer: 7, total: 11 };
        let inner: ratatosk_proto::swarm::GivingLimits = limits.into();
        assert_eq!(FfiGivingLimits::from(inner), limits);
        assert_eq!((inner.per_peer, inner.total), (7, 11), "числа не переставлены местами");
    }

    #[test]
    fn the_sharing_level_crosses_the_boundary_in_both_directions() {
        // Уровень отдачи — настройка, и на границе она обязана ходить
        // туда и обратно без потери: перевод «в одну сторону» однажды
        // показал бы человеку не тот уровень, который стоит у ядра.
        for level in
            [FfiSharingLevel::Everyone, FfiSharingLevel::Contacts, FfiSharingLevel::Verified]
        {
            let inner: ratatosk_proto::swarm::Sharing = level.into();
            assert_eq!(FfiSharingLevel::from(inner), level, "уровень {level:?} вернулся другим");
        }
        // И три состояния участия — тем же порядком: это разные ручки
        // (§12, «две ручки, а не одна»), и путать их на границе нельзя.
        for mode in [FfiSeeding::Off, FfiSeeding::Quiet, FfiSeeding::Announced] {
            let inner: ratatosk_proto::swarm::Seeding = mode.into();
            assert_eq!(FfiSeeding::from(inner), mode, "состояние {mode:?} вернулось другим");
        }
    }
}
