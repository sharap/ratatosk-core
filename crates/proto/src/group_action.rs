//! Правка, отзыв, реакция, ответ, файлы, переименование и аватарка —
//! в группе.
//!
//! **Спецификация v0.1 в группе не описывает ничего, кроме сообщения.**
//! Дополнение, и §17 просит такие вещи называть отдельно.
//!
//! # Что здесь нового, а что взято целиком
//!
//! Нового — ровно одно: как эти действия едут по группе. Правила
//! самих действий не переписываются, а берутся: пустая правка отказывается
//! [`crate::edit::check`], реакция проверяется [`crate::reaction::check`],
//! ответ — [`crate::reply::check`], длина списка отзыва меряется
//! [`crate::retract::MAX_RETRACT_IDS`], предложение файлов **целиком**
//! собирает и разбирает [`crate::files`] — тем же кодеком, что и один
//! на один, а байты картинки меряет [`crate::avatar::check`]. Заведи
//! здесь свои проверки — и
//! однажды в группе стало бы можно то, чего нельзя один на один, причём
//! молча.
//!
//! # Обвязка — та же, что у группового сообщения
//!
//! Действие уезжает так же, как сообщение (§11.3): запечатывается ключом
//! из цепочки отправителя, подписывается его `SK` и едет отдельной копией
//! каждому участнику по 1:1-каналу. Внешняя оболочка общая на оба типа
//! нагрузки — это [`crate::group::GroupMessage`], — и собирают её те же
//! [`crate::group::signed_message`] и [`crate::group::parse_message`].
//!
//! Различают их два признака, и оба обязательны. Тип нагрузки в конверте
//! говорит разбору, что внутри; разделитель в AAD
//! ([`ratatosk_crypto::group::seal_action`]) не даёт выдать одно за другое,
//! потому что конверт не подписан и тип в нём переписывается по дороге.
//!
//! # Номер цепочки тратится и на действие
//!
//! Реакция стоит того же номера, что слово. Это не расточительство:
//! цепочка — это порядок, в котором отправитель что-то делал, и пропуск
//! в ней у получателя означает «кадр потерялся». Не трать действия номер,
//! и получатель не отличил бы «реакцию не довезли» от «реакции не было».
//!
//! # Вид действия — внутри шифротекста
//!
//! И потому разбор обязан **молча пропускать вид, которого не знает**:
//! сборка постарше встретит [`ActionError::UnknownKind`] на том, что
//! новая сборка считает обычным делом. Это та же дисциплина, что у
//! незнакомого типа нагрузки в конверте, только этажом ниже.

use ratatosk_codec::{canonical, Value};
use ratatosk_crdt::MsgId;

use crate::{edit, files, reaction, reply, retract};

/// Ключ вида действия.
const KEY_KIND: u64 = 1;
/// Ключ цели — сообщения, о котором речь.
const KEY_TARGET: u64 = 2;
/// Ключ текста: новый текст правки, эмодзи реакции, слова ответа.
const KEY_TEXT: u64 = 3;
/// Ключ списка целей — только у отзыва.
const KEY_IDS: u64 = 4;
/// Ключ вложенного предложения файлов — только у файлов.
const KEY_OFFER: u64 = 5;
/// Ключ байтов картинки — только у аватарки. Он же везёт байты карточки
/// у `ContactShare`: оба — «непрозрачные байты этого действия», и второй
/// ключ под то же самое значил бы два имени у одной вещи.
const KEY_BYTES: u64 = 6;

const KIND_EDIT: u64 = 1;
const KIND_RETRACT: u64 = 2;
const KIND_REACTION: u64 = 3;
const KIND_REPLY: u64 = 4;
const KIND_FILES: u64 = 5;
const KIND_RENAME: u64 = 6;
const KIND_AVATAR: u64 = 7;
/// Пересланный текст. Заведён затем же, зачем `PayloadType::Forward`
/// один на один: «переслано» — это утверждение о происхождении слов,
/// и получатель обязан его видеть.
const KIND_FORWARD: u64 = 8;
/// Карточка контакта, которой поделились в группе.
const KIND_CONTACT: u64 = 9;

/// Почему действие не разобралось.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    /// Форма не та, или содержимое не прошло правила своего действия.
    #[error("действие не разобралось")]
    Malformed,
    /// Вид действия, которого эта сборка не знает.
    ///
    /// **Не порча и не нападение.** Отдельно от [`ActionError::Malformed`]
    /// именно поэтому: на порче счётчик аномалий собеседника растёт (§7.3),
    /// а на незнакомом виде расти не должен — иначе сборка поновее выглядела
    /// бы для нас источником мусора и в конце концов была бы отключена.
    #[error("вид действия неизвестен этой сборке")]
    UnknownKind,
}

/// Что участник сделал с уже сказанным.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Заменить текст своего сообщения (`crate::edit`).
    Edit {
        /// Какое сообщение.
        target: MsgId,
        /// Новый текст; пустым не бывает.
        text: String,
    },
    /// Попросить убрать свои сообщения (`crate::retract`).
    Retract {
        /// Какие именно; не длиннее [`retract::MAX_RETRACT_IDS`].
        targets: Vec<MsgId>,
    },
    /// Поставить или снять реакцию (`crate::reaction`).
    Reaction {
        /// На какое сообщение.
        target: MsgId,
        /// Эмодзи; пустая строка снимает прежнюю.
        emoji: String,
    },
    /// Ответить на сообщение (`crate::reply`).
    Reply {
        /// На какое отвечают.
        target: MsgId,
        /// Слова ответа; пустыми не бывают.
        text: String,
    },
    /// Предложить файлы (§10.1).
    ///
    /// # Вид, который не про уже сказанное
    ///
    /// Правка, отзыв, реакция и ответ ссылаются на существующее сообщение;
    /// этот заводит новое — как и ответ, но без цели. Здесь он потому, что нужна ему
    /// **та же обвязка**: цепочка отправителя, номер в ней, подпись, копия
    /// каждому по 1:1-каналу (§11.3), откладывание кадра, пришедшего
    /// раньше группы. Свой тип нагрузки означал бы вторую копию всего
    /// этого ради одного отличия.
    ///
    /// # Ключ файла едет здесь, и это безопасно ровно потому же, что и в 1:1
    ///
    /// §10.1 передаёт `file_key` «в сообщении», то есть по уже
    /// установленной сессии. Здесь он вдобавок лежит **под ключом
    /// отправителя** (§11.1), а тот знают только участники — то же
    /// свойство, что у любого группового сообщения.
    ///
    /// # А чанки в группе не отличаются от чанков один на один вовсе
    ///
    /// Чанк шифруется ключом, выведенным из `file_key ‖ index` (§10.1), —
    /// **не сессионным**. Значит байты чанка у всех участников одни и те же,
    /// и никакой групповой обёртки им не нужно: каждый получатель просит
    /// их сам и получает по своему 1:1-каналу, как и в переписке двоих.
    Files {
        /// Подпись к вложениям; пустая — законное дело.
        caption: String,
        /// Сами файлы; не длиннее [`files::MAX_FILES_PER_MESSAGE`].
        offers: Vec<files::FileOffer>,
        /// Переслано ли это вложение.
        ///
        /// Признаком, а не отдельным видом действия: `Action::Forward`
        /// везёт слова, а здесь к словам приложены файлы, и второй вид
        /// означал бы вторую копию всего разбора вложений. Едет он внутри
        /// вложенного предложения — тем же кодеком, что и один на один,
        /// так что расходиться этим двум местам нечем.
        forwarded: bool,
    },
    /// Переименовать группу.
    ///
    /// # Метки здесь нет, и это не пропуск
    ///
    /// Спор двух переименований разрешает метка HLC — но она уже едет
    /// **в конверте** (§9.1), тем же полем, каким разрешается спор реакций.
    /// Положи мы её ещё и внутрь, у одного факта стало бы два источника,
    /// и разошлись бы они молча: подписан конверт, а не вложенное число.
    ///
    /// # Кто вправе — проверяет получатель
    ///
    /// Только создатель (§11.2, расширенное по смыслу: он распоряжается
    /// тем, что относится ко всей группе). Проверка стоит на приёме,
    /// а не только у отправителя, по той же причине, что у удаления:
    /// иначе достаточно собрать кадр чужой сборкой.
    Rename {
        /// Новое название; пустым не бывает и длиннее предела — тоже.
        title: String,
    },
    /// Сменить аватарку группы.
    ///
    /// # Метки здесь нет — по той же причине, что у переименования
    ///
    /// Спор двух картинок разрешает метка HLC, и она уже едет **в конверте**
    /// (§9.1). Второй источник у одного факта разошёлся бы с первым молча:
    /// подписан конверт, а не вложенное число.
    ///
    /// Пересылки этого действия не бывает — оттого метка из конверта и
    /// годится. Новичку картинка достаётся не пересылкой, а вводным блоком
    /// (`crate::group::Intro`), и метка едет там отдельным полем, ровно
    /// как у названия.
    ///
    /// # Кто вправе — проверяет получатель
    ///
    /// Только создатель, как и у названия, и по той же причине проверка
    /// стоит на приёме: собрать кадр чужой сборкой ничто не мешает.
    ///
    /// # Правила §4.2 у группы нет
    ///
    /// Картинка уходит всем участникам, сверенным и нет. Рассуждение
    /// целиком — в [`crate::avatar`].
    Avatar {
        /// Байты картинки; пустые — создатель снял её.
        ///
        /// Проверяются [`crate::avatar::check`]: предел и сигнатура
        /// формата, то же самое, что у лица контакта.
        bytes: Vec<u8>,
    },
    /// Переслать в группу чужие слова (`crate::forward`).
    ///
    /// # Отдельный вид, а не признак у обычного сообщения
    ///
    /// Один на один «переслано» — это отдельный тип нагрузки
    /// (`PayloadType::Forward`), и здесь та же причина: пометка меняет
    /// смысл слов. Признаком внутри группового сообщения его положить
    /// было **некуда**: под ключом отправителя едет голый текст, а не
    /// карта полей, и завести там поле значило бы сменить формат
    /// зашифрованного тела — то есть сборка постарше показала бы человеку
    /// CBOR вместо слов.
    ///
    /// Ценой стало то, что сборка, не знающая этого вида, пересланного
    /// сообщения не увидит вовсе. Это designed-поведение
    /// ([`ActionError::UnknownKind`] — «не порча и не нападение»),
    /// и оно честнее показанного без пометки: имя рядом с чужими словами
    /// хуже отсутствия слов.
    ///
    /// # Автора здесь нет — как и в 1:1
    ///
    /// `crate::forward`: подпись §6 при пересылке не сохраняется, и имя
    /// рядом с чужими словами было бы утверждением, которое получатель
    /// проверить не может.
    Forward {
        /// Пересланные слова; пустыми не бывают.
        text: String,
    },
    /// Поделиться в группе карточкой известного человека (§4.1).
    ///
    /// Байтами карточки, а не разобранными полями: разбирает их
    /// `contact_share::from_payload` — тот же кодек, что и один на один.
    /// Разложи мы поля здесь, у одного формата стало бы два сборщика.
    ///
    /// Что **не** едет — то же, что и в 1:1: локальное имя, которым
    /// пользователь подписал человека у себя, и признак сверки.
    ContactShare {
        /// Закодированная `ContactCard`.
        card_bytes: Vec<u8>,
        /// Переслана ли эта карточка.
        ///
        /// Признаком, а не отдельным видом действия, и по той же причине,
        /// что у файлов: разбор карточки у этого вида уже есть, второй
        /// означал бы вторую его копию. Едет он внутри вложенной нагрузки
        /// — тем же кодеком, что и один на один.
        forwarded: bool,
    },
}

/// Собирает открытый текст действия — то, что ляжет под sender key.
#[must_use]
pub fn payload(action: &Action) -> Value {
    match action {
        Action::Edit { target, text } => triple(KIND_EDIT, *target, text),
        Action::Reaction { target, emoji } => triple(KIND_REACTION, *target, emoji),
        Action::Reply { target, text } => triple(KIND_REPLY, *target, text),
        Action::Rename { title } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_RENAME.into())),
            (Value::Integer(KEY_TEXT.into()), Value::Text(title.clone())),
        ]),
        Action::Files { caption, offers, forwarded } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_FILES.into())),
            // Вложенным значением, а не разложенным по ключам: собирает
            // его `files::offer_payload` — тот же кодек, что и в 1:1.
            // Разложи мы поля здесь, у одного формата стало бы два
            // сборщика, и первая же правка разошлась бы.
            (Value::Integer(KEY_OFFER.into()), files::offer_payload(caption, offers, *forwarded)),
        ]),
        Action::Avatar { bytes } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_AVATAR.into())),
            (Value::Integer(KEY_BYTES.into()), Value::Bytes(bytes.clone())),
        ]),
        Action::Forward { text } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_FORWARD.into())),
            (Value::Integer(KEY_TEXT.into()), Value::Text(text.clone())),
        ]),
        Action::ContactShare { card_bytes, forwarded } => Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_CONTACT.into())),
            // Вложенным значением, а не голыми байтами: собирает его
            // `contact_share::payload` — тот же кодек, что и в 1:1,
            // и признак «переслано» приезжает оттуда же.
            (
                Value::Integer(KEY_BYTES.into()),
                crate::contact_share::payload(card_bytes, *forwarded),
            ),
        ]),
        Action::Retract { targets } => {
            let ids = targets.iter().map(|id| Value::Bytes(id.to_vec())).collect();
            Value::Map(vec![
                (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_RETRACT.into())),
                (Value::Integer(KEY_IDS.into()), Value::Array(ids)),
            ])
        }
    }
}

fn triple(kind: u64, target: MsgId, text: &str) -> Value {
    Value::Map(vec![
        (Value::Integer(KEY_KIND.into()), Value::Integer(kind.into())),
        (Value::Integer(KEY_TARGET.into()), Value::Bytes(target.to_vec())),
        (Value::Integer(KEY_TEXT.into()), Value::Text(text.to_owned())),
    ])
}

/// Разбирает открытый текст действия.
///
/// Всё здесь приходит от участника группы, поэтому проверяется всё: и вид,
/// и длина идентификаторов, и правила самого действия — те же, что один
/// на один.
///
/// # Errors
///
/// [`ActionError::UnknownKind`] — вид неизвестен этой сборке;
/// [`ActionError::Malformed`] — всё остальное.
pub fn from_payload(value: &Value) -> Result<Action, ActionError> {
    let map = canonical::as_map(value).map_err(|_| ActionError::Malformed)?;
    let kind = canonical::require(map, KEY_KIND)
        .and_then(canonical::as_u64)
        .map_err(|_| ActionError::Malformed)?;
    // Вид проверяется первым: у незнакомого разбирать остальное нечем,
    // и отказать по форме значило бы назвать порчей чужую новизну.
    match kind {
        KIND_EDIT | KIND_REACTION | KIND_REPLY => {}
        KIND_RETRACT => return retract_from(map),
        KIND_FILES => return files_from(map),
        KIND_RENAME => return rename_from(map),
        KIND_AVATAR => return avatar_from(map),
        KIND_FORWARD => return forward_from(map),
        KIND_CONTACT => return contact_from(map),
        _ => return Err(ActionError::UnknownKind),
    }

    let target = canonical::require(map, KEY_TARGET)
        .and_then(canonical::as_array::<16>)
        .map_err(|_| ActionError::Malformed)?;
    let text = canonical::require(map, KEY_TEXT)
        .and_then(canonical::as_text)
        .map_err(|_| ActionError::Malformed)?;

    match kind {
        KIND_EDIT => {
            // Пустая правка — это удаление, и приехать правкой она не должна:
            // приняв её, мы стёрли бы текст, не сказав, что его удалили.
            edit::check(text).map_err(|_| ActionError::Malformed)?;
            Ok(Action::Edit { target, text: text.to_owned() })
        }
        KIND_REACTION => {
            reaction::check(text).map_err(|_| ActionError::Malformed)?;
            Ok(Action::Reaction { target, emoji: text.to_owned() })
        }
        _ => {
            reply::check(text).map_err(|_| ActionError::Malformed)?;
            Ok(Action::Reply { target, text: text.to_owned() })
        }
    }
}

fn rename_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let title = canonical::require(map, KEY_TEXT)
        .and_then(canonical::as_text)
        .map_err(|_| ActionError::Malformed)?;
    // Пустое имя здесь отвергается, а в представлении группы — нет,
    // и различие намеренное: там пустая строка досадный мусор, с которым
    // чат всё равно надо показать, а здесь это **действие человека**,
    // стирающее у всех то, что было.
    crate::group::check_new_title(title).map_err(|_| ActionError::Malformed)?;
    Ok(Action::Rename { title: title.trim().to_owned() })
}

fn avatar_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let Ok(Value::Bytes(bytes)) = canonical::require(map, KEY_BYTES) else {
        return Err(ActionError::Malformed);
    };
    // Предел и сигнатура — те же, что у лица контакта, и берутся они там же.
    // Заведи мы здесь свою проверку, в группу можно было бы прислать то,
    // чего нельзя человеку, причём молча.
    crate::avatar::check(bytes).map_err(|_| ActionError::Malformed)?;
    Ok(Action::Avatar { bytes: bytes.clone() })
}

fn forward_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let text = canonical::require(map, KEY_TEXT)
        .and_then(canonical::as_text)
        .map_err(|_| ActionError::Malformed)?;
    // Предел тот же, что у любого текста в кадре, и берётся он там же:
    // разойдись проверки, в группу можно было бы переслать то, чего нельзя
    // сказать. Пустая пересылка отвергается по той же причине, что пустая
    // правка, — это не слова, а дырка в истории.
    if text.is_empty() || !files::text_fits(text.len()) {
        return Err(ActionError::Malformed);
    }
    Ok(Action::Forward { text: text.to_owned() })
}

fn contact_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let nested = canonical::require(map, KEY_BYTES).map_err(|_| ActionError::Malformed)?;
    // Карточка обязана разбираться **здесь**, а не у получателя потом:
    // байты приехали от участника, и «положили в историю то, что не
    // читается» — это запись, которую человек будет видеть вечно.
    //
    // Разбирает её тот же кодек, что и один на один, и признак «переслано»
    // приезжает оттуда же. Дальше едут **принятые байты**, а не
    // пересобранные из полей: §6 требует, чтобы проверяемое проверялось
    // над принятым представлением.
    let (card_bytes, _, forwarded) =
        crate::contact_share::from_payload(nested).map_err(|_| ActionError::Malformed)?;
    Ok(Action::ContactShare { card_bytes, forwarded })
}

fn files_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let nested = canonical::require(map, KEY_OFFER).map_err(|_| ActionError::Malformed)?;
    // Правила предложения — числа файлов, длины имени, размера превью —
    // проверяет `offer_from_payload`, и здесь не повторяются. Разойдись
    // они, в группе стало бы можно послать то, чего нельзя один на один.
    let (caption, offers, forwarded) =
        files::offer_from_payload(nested).map_err(|_| ActionError::Malformed)?;
    Ok(Action::Files { caption, offers, forwarded })
}

fn retract_from(map: &[(Value, Value)]) -> Result<Action, ActionError> {
    let Ok(Value::Array(items)) = canonical::require(map, KEY_IDS) else {
        return Err(ActionError::Malformed);
    };
    if items.len() > retract::MAX_RETRACT_IDS {
        return Err(ActionError::Malformed);
    }
    let mut targets = Vec::with_capacity(items.len());
    for item in items {
        targets.push(canonical::as_array::<16>(item).map_err(|_| ActionError::Malformed)?);
    }
    Ok(Action::Retract { targets })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(action: &Action) -> Action {
        let bytes = canonical::encode(&payload(action)).unwrap();
        from_payload(&canonical::decode(&bytes).unwrap()).unwrap()
    }

    fn offer() -> files::FileOffer {
        files::FileOffer {
            file_id: [6u8; 16],
            name: "кот.jpg".into(),
            size_bytes: 1024,
            key: [7u8; 32],
            preview: None,
        }
    }

    #[test]
    fn every_kind_round_trips() {
        for action in [
            Action::Edit { target: [1u8; 16], text: "исправил".into() },
            Action::Retract { targets: vec![[2u8; 16], [3u8; 16]] },
            Action::Reaction { target: [4u8; 16], emoji: "👍".into() },
            Action::Reply { target: [5u8; 16], text: "согласен".into() },
            Action::Files { caption: "вот".into(), offers: vec![offer()], forwarded: false },
            Action::Rename { title: "у большого костра".into() },
            Action::Avatar { bytes: png() },
        ] {
            assert_eq!(round_trip(&action), action, "{action:?}");
        }
    }

    #[test]
    fn a_rename_round_trips_and_is_trimmed() {
        let action = Action::Rename { title: "  у большого костра  ".into() };
        assert_eq!(
            round_trip(&action),
            Action::Rename { title: "у большого костра".into() },
            "края подрезаются на приёме, как и при заведении"
        );
    }

    #[test]
    fn an_empty_rename_is_refused() {
        // В представлении группы пустое имя законно — там это досадный
        // мусор, с которым чат всё равно надо показать. Здесь это
        // **действие человека**, и пустым названием оно стёрло бы у всех
        // то, что было, притворившись обычной сменой имени.
        let bytes = canonical::encode(&payload(&Action::Rename { title: "   ".into() })).unwrap();
        let value = canonical::decode(&bytes).unwrap();
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn a_rename_carries_no_tag_of_its_own() {
        // Спор разрешает метка конверта (§9.1). Положи мы её ещё и внутрь,
        // у одного факта стало бы два источника — а подписан конверт,
        // не вложенное число.
        let value = payload(&Action::Rename { title: "у костра".into() });
        let Value::Map(pairs) = &value else { panic!("не карта") };
        assert_eq!(pairs.len(), 2, "вид и название — и ничего больше: {pairs:?}");
    }

    #[test]
    fn a_file_key_survives_the_trip_unchanged() {
        // Ключ файла (§10.1) едет внутри предложения, и без него чанки
        // не открываются вовсе. Потеряйся он молча — участники получили бы
        // вложение, которое невозможно прочесть.
        let action =
            Action::Files { caption: String::new(), offers: vec![offer()], forwarded: false };
        let Action::Files { offers, caption, .. } = round_trip(&action) else {
            panic!("вид не тот");
        };
        assert_eq!(offers[0].key, [7u8; 32]);
        assert_eq!(offers[0].file_id, [6u8; 16]);
        assert!(caption.is_empty(), "подпись без слов — законное дело");
    }

    #[test]
    fn the_file_rules_are_the_same_as_one_to_one() {
        // Проверки предложения берутся у `files`, а не пишутся заново:
        // разойдись они, в группе стало бы можно послать то, чего нельзя
        // в переписке двоих.
        let too_many = Action::Files {
            caption: String::new(),
            offers: vec![offer(); files::MAX_FILES_PER_MESSAGE + 1],
            forwarded: false,
        };
        let bytes = canonical::encode(&payload(&too_many)).unwrap();
        let value = canonical::decode(&bytes).unwrap();
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn an_empty_reaction_survives_because_it_means_removal() {
        // Пустая строка у реакции — не пустое поле, а команда «сними мою».
        let action = Action::Reaction { target: [4u8; 16], emoji: String::new() };
        assert_eq!(round_trip(&action), action);
    }

    #[test]
    fn an_unknown_kind_is_not_called_corruption() {
        // Сборка поновее вправе завести восьмой вид. Назови мы это порчей,
        // счётчик аномалий (§7.3) рос бы на честном соседе, и кончилось бы
        // это отключением того, кто ничего не нарушал.
        let value = Value::Map(vec![(Value::Integer(KEY_KIND.into()), Value::Integer(99.into()))]);
        assert_eq!(from_payload(&value), Err(ActionError::UnknownKind));
    }

    #[test]
    fn the_rules_are_the_same_as_one_to_one() {
        // Не «похожие», а те же самые: проверки берутся из edit, reaction
        // и reply. Разойдись они — в группе стало бы можно то, чего нельзя
        // в личной переписке, и никто бы этого не заметил.
        let empty_edit = triple(KIND_EDIT, [1u8; 16], "   ");
        assert_eq!(from_payload(&empty_edit), Err(ActionError::Malformed));
        let empty_reply = triple(KIND_REPLY, [1u8; 16], "");
        assert_eq!(from_payload(&empty_reply), Err(ActionError::Malformed));
        let long_reaction = triple(KIND_REACTION, [1u8; 16], "это не эмодзи, а фраза");
        assert_eq!(from_payload(&long_reaction), Err(ActionError::Malformed));
    }

    #[test]
    fn a_retract_longer_than_the_limit_is_refused() {
        // Предел меряется тем же числом, что и один на один: список приходит
        // от участника, и без потолка одна просьба заставила бы перебрать
        // столько записей, сколько он пожелает.
        let targets = vec![[1u8; 16]; retract::MAX_RETRACT_IDS + 1];
        let value = payload(&Action::Retract { targets });
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn a_wrong_sized_identifier_is_refused() {
        let value = Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_EDIT.into())),
            (Value::Integer(KEY_TARGET.into()), Value::Bytes(vec![0u8; 8])),
            (Value::Integer(KEY_TEXT.into()), Value::Text("а".into())),
        ]);
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    fn png() -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.extend_from_slice(&[7u8; 32]);
        bytes
    }

    #[test]
    fn a_removed_avatar_is_empty_bytes_and_not_an_absent_field() {
        // Снятие — такое же действие, как постановка: у него своя метка
        // в конверте, и без неё опоздавшая копия прежней картинки вернула
        // бы её на место. Отсутствующее поле означало бы порчу, а не снятие.
        let action = Action::Avatar { bytes: Vec::new() };
        assert_eq!(round_trip(&action), action);

        let no_field =
            Value::Map(vec![(Value::Integer(KEY_KIND.into()), Value::Integer(KIND_AVATAR.into()))]);
        assert_eq!(from_payload(&no_field), Err(ActionError::Malformed));
    }

    #[test]
    fn an_avatar_carries_no_tag_of_its_own() {
        // Метка одна и лежит в конверте (§9.1). Заведись вторая внутри,
        // у одного факта стало бы два источника: подписан конверт,
        // а вложенное число — нет.
        let value = payload(&Action::Avatar { bytes: png() });
        let Value::Map(entries) = &value else { panic!("действие — карта") };
        assert_eq!(entries.len(), 2, "вид и байты, и больше ничего: {entries:?}");
    }

    #[test]
    fn an_avatar_obeys_the_same_limits_as_a_face() {
        // Правило берётся у `avatar::check`, а не пишется заново: разойдись
        // они, в группу можно было бы прислать то, чего нельзя человеку.
        let too_big = Action::Avatar { bytes: vec![0u8; crate::avatar::MAX_AVATAR_BYTES + 1] };
        assert_eq!(from_payload(&payload(&too_big)), Err(ActionError::Malformed));

        let not_an_image =
            Action::Avatar { bytes: "это не картинка".as_bytes().to_vec() };
        assert_eq!(from_payload(&payload(&not_an_image)), Err(ActionError::Malformed));
    }

    #[test]
    fn an_avatar_that_is_not_bytes_is_refused() {
        // Текстом картинка не приезжает. Прими мы её так, в системный
        // декодер уехало бы то, что даже не притворяется файлом.
        let value = Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_AVATAR.into())),
            (Value::Integer(KEY_BYTES.into()), Value::Text("картинка".into())),
        ]);
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn a_kind_without_its_fields_is_malformed_not_unknown() {
        // Вид знаком, полей нет — это порча, и вот её считать аномалией
        // как раз надо.
        let value =
            Value::Map(vec![(Value::Integer(KEY_KIND.into()), Value::Integer(KIND_EDIT.into()))]);
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    fn card_bytes() -> Vec<u8> {
        ratatosk_codec::ContactCard {
            ik: [1u8; 32],
            sk: [2u8; 32],
            onion: String::new(),
            chatmail: "sosed@nine.example".to_owned(),
            display_name: "сосед".to_owned(),
            version: 1,
            ygg: Vec::new(),
            nostr: Vec::new(),
            nostr_relays: Vec::new(),
        }
        .encode()
        .expect("карточка")
    }

    #[test]
    fn forwarded_files_keep_their_mark_across_the_group() {
        // Пометка едет **внутри предложения**, а не отдельным видом: разбор
        // вложений у `Files` уже есть, и второй вид означал бы вторую его
        // копию. Проверяется именно то, что признак переживает круг, —
        // потерянный, он превратил бы чужие файлы в свои.
        let action =
            Action::Files { caption: "вот".into(), offers: vec![offer()], forwarded: true };
        assert_eq!(round_trip(&action), action);
    }

    #[test]
    fn a_build_without_the_mark_reads_files_as_not_forwarded() {
        // Ключа нет — «не переслано». Сборка постарше признака не везла,
        // и её предложение обязано разбираться по-прежнему.
        let plain =
            Action::Files { caption: "вот".into(), offers: vec![offer()], forwarded: false };
        let value = payload(&plain);
        let Value::Map(fields) = &value else { panic!("действие — карта") };
        assert!(
            !fields.iter().any(|(key, _)| *key == Value::Integer(KEY_OFFER.into())
                && format!("{:?}", value).contains("Bool(true)")),
            "у непересланного признака в проводе быть не должно"
        );
        assert_eq!(round_trip(&plain), plain);
    }

    #[test]
    fn a_forward_crosses_the_group_as_its_own_kind() {
        // «Переслано» — утверждение о происхождении слов, и получатель
        // обязан его видеть. Признаком внутри группового сообщения его
        // положить некуда: под ключом отправителя едет голый текст.
        let action = Action::Forward { text: "чужие слова".into() };
        assert_eq!(round_trip(&action), action);
    }

    #[test]
    fn an_empty_forward_is_refused() {
        // Пустая пересылка — не слова, а дырка в истории. То же правило,
        // что у пустой правки.
        let value = Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_FORWARD.into())),
            (Value::Integer(KEY_TEXT.into()), Value::Text(String::new())),
        ]);
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn a_shared_card_crosses_the_group_byte_for_byte() {
        // Байты едут **принятые**, а не пересобранные из полей: §6 требует,
        // чтобы проверяемое проверялось над принятым представлением.
        let action = Action::ContactShare { card_bytes: card_bytes(), forwarded: false };
        assert_eq!(round_trip(&action), action);
    }

    #[test]
    fn a_forwarded_card_keeps_its_mark_across_the_group() {
        // Пересылка сообщения с карточкой давала пустое сообщение: тело
        // у него пустое по построению, а карточка лежит записью рядом
        // и в пересылку не попадала. Признак — то, чем пересланная
        // карточка отличается от своей, и он обязан пережить круг.
        let action = Action::ContactShare { card_bytes: card_bytes(), forwarded: true };
        assert_eq!(round_trip(&action), action);
    }

    #[test]
    fn a_shared_card_that_does_not_parse_is_refused_on_arrival() {
        // Проверка стоит на разборе действия, а не у получателя потом:
        // «положили в историю то, что не читается» — это запись, которую
        // человек будет видеть вечно.
        let value = Value::Map(vec![
            (Value::Integer(KEY_KIND.into()), Value::Integer(KIND_CONTACT.into())),
            (Value::Integer(KEY_BYTES.into()), Value::Bytes(vec![0xff; 8])),
        ]);
        assert_eq!(from_payload(&value), Err(ActionError::Malformed));
    }

    #[test]
    fn the_new_kinds_read_as_unknown_to_an_older_build() {
        // Цена нового вида названа вслух: сборка постарше пересланного
        // сообщения не увидит вовсе. Важно, что это `UnknownKind`, а не
        // `Malformed`, — иначе на ней рос бы счётчик аномалий, и сборка
        // поновее выглядела бы источником мусора (§7.3).
        for kind in [KIND_FORWARD, KIND_CONTACT] {
            let value = Value::Map(vec![
                (Value::Integer(KEY_KIND.into()), Value::Integer((kind + 100).into())),
                (Value::Integer(KEY_TEXT.into()), Value::Text("что-то".into())),
            ]);
            assert_eq!(from_payload(&value), Err(ActionError::UnknownKind));
        }
    }
}
