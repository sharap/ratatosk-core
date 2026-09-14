//! Фрагментация и сборка (§9.3).
//!
//! Полезная нагрузка, не помещающаяся в класс кадра, режется на фрагменты.
//! Ограничения спецификации, все до одного обязательные: до 4096 фрагментов
//! на сообщение, TTL незавершённой сборки 30 суток (почта) и 10 минут
//! (прямой канал), суммарно не более 64 МиБ буферов, при переполнении
//! вытесняются самые старые.
//!
//! Пределы здесь — не гигиена, а защита: сборщик без потолка позволяет любому,
//! кто может отправить кадр, занять всю память устройства первым фрагментом
//! из 4096.

use std::collections::HashMap;

use ratatosk_wire::SizeClass;

use crate::transport_policy::Transport;

/// Максимум фрагментов на сообщение (§9.3).
pub const MAX_FRAGMENTS: u64 = 4096;
/// TTL незавершённой сборки для почты — 30 суток (§9.3).
pub const REASSEMBLY_TTL_MAIL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// TTL незавершённой сборки для прямого канала — 10 минут (§9.3).
pub const REASSEMBLY_TTL_DIRECT_MS: u64 = 10 * 60 * 1000;
/// Суммарный предел буферов сборки — 64 МиБ (§9.3).
pub const REASSEMBLY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

/// Идентификатор сборки.
pub type Uid = [u8; 16];

/// Отказ принять фрагмент.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    /// `total` вне допустимого диапазона или `index >= total`.
    OutOfRange,
    /// Фрагменты одной сборки объявляют разное `total`.
    Inconsistent,
    /// Сборка не помещается в бюджет буферов.
    BudgetExceeded,
}

/// Результат приёма фрагмента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Сборка ещё не полна.
    Pending {
        /// Сколько фрагментов уже есть.
        have: u64,
        /// Сколько всего ожидается.
        total: u64,
    },
    /// Сборка завершена, вот собранная нагрузка.
    Complete(Vec<u8>),
    /// Такой фрагмент уже принимали.
    Duplicate,
}

/// Режет нагрузку на фрагменты по `chunk` байт.
#[must_use]
pub fn split(payload: &[u8], chunk: usize) -> Vec<&[u8]> {
    if payload.is_empty() {
        return vec![&payload[..0]];
    }
    payload.chunks(chunk.max(1)).collect()
}

/// Сколько фрагментов потребуется.
#[must_use]
pub fn fragment_count(payload_len: usize, chunk: usize) -> u64 {
    if payload_len == 0 {
        return 1;
    }
    payload_len.div_ceil(chunk.max(1)) as u64
}

#[derive(Debug)]
struct Partial {
    total: u64,
    parts: HashMap<u64, Vec<u8>>,
    bytes: usize,
    first_seen_ms: u64,
    ttl_ms: u64,
}

/// Сборщик фрагментов с учётом всех пределов §9.3.
#[derive(Debug, Default)]
pub struct Reassembler {
    partials: HashMap<Uid, Partial>,
    bytes: usize,
}

impl Reassembler {
    /// Пустой сборщик.
    #[must_use]
    pub fn new() -> Reassembler {
        Reassembler::default()
    }

    /// Сколько байт занято буферами.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Сколько незавершённых сборок.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    /// Принимает фрагмент.
    ///
    /// `ttl_ms` различается для почты и прямого канала (§9.3): по прямому
    /// каналу недостающий фрагмент за 10 минут уже не придёт, а по почте
    /// вполне может прийти через неделю.
    pub fn accept(
        &mut self,
        uid: Uid,
        index: u64,
        total: u64,
        data: &[u8],
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<Accepted, FragmentError> {
        if total == 0 || total > MAX_FRAGMENTS || index >= total {
            return Err(FragmentError::OutOfRange);
        }
        self.purge(now_ms);

        if data.len() > REASSEMBLY_BUDGET_BYTES {
            return Err(FragmentError::BudgetExceeded);
        }
        self.make_room(data.len(), now_ms);

        if let Some(existing) = self.partials.get(&uid) {
            if existing.total != total {
                // Разное `total` для одной сборки — либо баг отправителя, либо
                // попытка запутать сборщик. В обоих случаях сборка бесполезна.
                self.drop_uid(&uid);
                return Err(FragmentError::Inconsistent);
            }
            if existing.parts.contains_key(&index) {
                return Ok(Accepted::Duplicate);
            }
        }

        let have = {
            let entry = self.partials.entry(uid).or_insert_with(|| Partial {
                total,
                parts: HashMap::new(),
                bytes: 0,
                first_seen_ms: now_ms,
                ttl_ms,
            });
            entry.parts.insert(index, data.to_vec());
            entry.bytes += data.len();
            entry.parts.len() as u64
        };
        self.bytes += data.len();

        if have < total {
            return Ok(Accepted::Pending { have, total });
        }

        let mut partial = self.partials.remove(&uid).expect("запись только что была");
        self.bytes -= partial.bytes;
        let mut out = Vec::with_capacity(partial.bytes);
        for i in 0..total {
            out.extend_from_slice(&partial.parts.remove(&i).expect("все части на месте"));
        }
        Ok(Accepted::Complete(out))
    }

    /// Выбрасывает сборки, у которых истёк TTL.
    pub fn purge(&mut self, now_ms: u64) {
        let expired: Vec<Uid> = self
            .partials
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.first_seen_ms) >= p.ttl_ms)
            .map(|(uid, _)| *uid)
            .collect();
        for uid in expired {
            self.drop_uid(&uid);
        }
    }

    /// Освобождает место под новые байты, вытесняя самые старые сборки (§9.3).
    fn make_room(&mut self, incoming: usize, _now_ms: u64) {
        while self.bytes + incoming > REASSEMBLY_BUDGET_BYTES && !self.partials.is_empty() {
            let Some(oldest) = self
                .partials
                .iter()
                .min_by_key(|(uid, p)| (p.first_seen_ms, **uid))
                .map(|(uid, _)| *uid)
            else {
                break;
            };
            self.drop_uid(&oldest);
        }
    }

    fn drop_uid(&mut self, uid: &Uid) {
        if let Some(p) = self.partials.remove(uid) {
            self.bytes -= p.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: Uid = [1u8; 16];

    #[test]
    fn split_and_reassemble_in_order() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let parts = split(&payload, 256);
        let total = parts.len() as u64;
        assert_eq!(total, fragment_count(payload.len(), 256));

        let mut r = Reassembler::new();
        let mut result = None;
        for (i, part) in parts.iter().enumerate() {
            let got = r.accept(UID, i as u64, total, part, REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
            if let Accepted::Complete(bytes) = got {
                result = Some(bytes);
            }
        }
        assert_eq!(result.unwrap(), payload);
        assert_eq!(r.bytes(), 0, "после сборки буферы освобождаются");
    }

    #[test]
    fn reassembles_out_of_order() {
        // Почта переставляет фрагменты так же, как сообщения (§9.2).
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let parts = split(&payload, 100);
        let total = parts.len() as u64;

        let mut r = Reassembler::new();
        let mut order: Vec<usize> = (0..parts.len()).collect();
        order.reverse();

        let mut result = None;
        for i in order {
            if let Accepted::Complete(bytes) =
                r.accept(UID, i as u64, total, parts[i], REASSEMBLY_TTL_MAIL_MS, 0).unwrap()
            {
                result = Some(bytes);
            }
        }
        assert_eq!(result.unwrap(), payload);
    }

    #[test]
    fn empty_payload_is_one_fragment() {
        assert_eq!(fragment_count(0, 100), 1);
        assert_eq!(split(b"", 100).len(), 1);
    }

    #[test]
    fn duplicate_fragment_is_reported() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        assert_eq!(
            r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap(),
            Accepted::Duplicate
        );
    }

    #[test]
    fn out_of_range_is_refused() {
        let mut r = Reassembler::new();
        assert_eq!(
            r.accept(UID, 0, 0, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
        assert_eq!(
            r.accept(UID, 5, 5, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
        assert_eq!(
            r.accept(UID, 0, MAX_FRAGMENTS + 1, b"a", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::OutOfRange)
        );
    }

    #[test]
    fn inconsistent_total_drops_the_assembly() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 4, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        assert_eq!(
            r.accept(UID, 1, 5, b"b", REASSEMBLY_TTL_DIRECT_MS, 0),
            Err(FragmentError::Inconsistent)
        );
        assert_eq!(r.pending(), 0);
        assert_eq!(r.bytes(), 0);
    }

    #[test]
    fn direct_channel_assembly_expires_in_ten_minutes() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_DIRECT_MS, 0).unwrap();
        r.purge(REASSEMBLY_TTL_DIRECT_MS - 1);
        assert_eq!(r.pending(), 1);
        r.purge(REASSEMBLY_TTL_DIRECT_MS);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn mail_assembly_survives_a_week() {
        let mut r = Reassembler::new();
        r.accept(UID, 0, 2, b"a", REASSEMBLY_TTL_MAIL_MS, 0).unwrap();
        r.purge(7 * 24 * 60 * 60 * 1000);
        assert_eq!(r.pending(), 1, "по почте фрагмент может прийти через неделю");
    }

    #[test]
    fn budget_evicts_oldest_assemblies() {
        // Один отправитель не должен занять всю память первым фрагментом
        // из 4096 в каждой из тысячи сборок.
        let mut r = Reassembler::new();
        let chunk = vec![0u8; 1024 * 1024];
        for i in 0..80u8 {
            let mut uid = [0u8; 16];
            uid[0] = i;
            r.accept(uid, 0, 2, &chunk, REASSEMBLY_TTL_MAIL_MS, u64::from(i)).unwrap();
        }
        assert!(r.bytes() <= REASSEMBLY_BUDGET_BYTES, "бюджет буферов превышен");
        assert!(r.pending() < 80, "самые старые сборки должны вытесняться");
    }
}

/// Наибольший класс кадра, который эта ступень действительно возит.
///
/// # Класс кадра — потолок содержимого, и потолок у ступеней разный
///
/// До 0.4.8 потолок считался одинаковым: кадр любого класса либо доезжает,
/// либо ступень отказывает. Замеры показали третье — кадр класса L
/// до Android **не доходит вовсе**, молча, а класс M теряется
/// на пятнадцати-двадцати пяти процентах. То есть у эфира потолок ниже,
/// и знать об этом обязана та сторона, которая собирает кадр.
///
/// Возвращается не «сколько байт», а класс: длину из класса выводит
/// [`ratatosk_wire::SizeClass::max_payload`], и второе правило рядом
/// с первым однажды разошлось бы с ним.
#[must_use]
pub const fn ceiling(via: Transport) -> SizeClass {
    match via {
        // Эфир возит класс S без единой потери и класс M с потерями;
        // класс L не возит вовсе. Потолок — S: это единственный класс,
        // на котором передача не платит повторами.
        Transport::Bt => SizeClass::S,
        // Остальным ступеням мебибайт по силам, и резать там нечего.
        Transport::Lan | Transport::Ygg | Transport::Onion => SizeClass::L,
        // Почта и nostr возят кадр письмом и событием соответственно;
        // предел там свой и считается не классом (§5.3, §5.6).
        Transport::Mail | Transport::Nostr => SizeClass::L,
    }
}

/// Сколько байт несущего конверта остаётся под кусок.
///
/// Несущий конверт — это `msg_id`, метка часов, тип, заголовок
/// [`ratatosk_codec::Fragment`] и сама нагрузка. Всё, кроме нагрузки,
/// занимает около сотни байт; запас взят вчетверо, а достаточность его
/// проверяется тестом на **настоящем** конверте, а не на оценке.
pub const CARRIER_RESERVE_BYTES: usize = 400;

/// Режет конверт на несущие, если он не влезает в потолок ступени.
///
/// Возвращает **закодированные** конверты, готовые к запечатыванию: один,
/// если резать нечего, иначе — по одному на кусок. Вызывающему остаётся
/// запечатать каждый своим кадром; собирает их получатель
/// [`Reassembler`]-ом, и после сборки исходный конверт неотличим
/// от приехавшего целым.
///
/// # Почему режется **закодированный** конверт, а не нагрузка
///
/// Резать нагрузку значило бы знать её устройство: у одного типа это
/// текст, у другого список предложений, у третьего байты чанка. Порезать
/// их по-разному — три разных сборщика и три разных способа ошибиться.
/// Закодированный конверт — это просто байты, и нож для них один.
///
/// # Метка часов у кусков та же, что у исходного конверта
///
/// Своей ей быть незачем: куски не показываются и в порядок разговора
/// не встают — встаёт собранный конверт, и метка у него своя, та самая.
/// Читается она отсюда же, из исходного конверта, и только когда резать
/// действительно приходится.
///
/// # Метка сборки берётся из того же источника, что и номера кусков
///
/// И **только когда резать приходится**. Взять её заранее — значит тратить
/// случайность на каждый уходящий кадр, а случайность у ядра одна на всё,
/// и в тестах она засеяна: лишний зачерпнутый номер сдвинул бы все
/// последующие. Поломка от такого выглядит как «тест на совсем другое
/// вдруг перестал сходиться».
///
/// # Errors
///
/// Отказ разбора исходного конверта или сборки несущего.
pub fn carriers(
    encoded: &[u8],
    via: Transport,
    mut next_msg_id: impl FnMut() -> [u8; 16],
) -> Result<Vec<Vec<u8>>, ratatosk_codec::CodecError> {
    let ceiling = ceiling(via).max_payload();
    if encoded.len() <= ceiling {
        // Влезает целиком — резать нечего, и трогать байты тоже: они уже
        // канонические, и второй проход через кодек мог бы только всё
        // испортить. И случайность не тратится: ни номера, ни метки сборки.
        return Ok(vec![encoded.to_vec()]);
    }

    let uid: Uid = next_msg_id();
    let hlc = ratatosk_codec::Envelope::decode(encoded)?.into_parts().1.hlc;
    let piece = ceiling.saturating_sub(CARRIER_RESERVE_BYTES).max(1);
    let parts = split(encoded, piece);
    let total = parts.len() as u64;
    let mut out = Vec::with_capacity(parts.len());
    for (index, part) in parts.into_iter().enumerate() {
        // **Свой `msg_id` у каждого куска, а не общий.** Окно дедупликации
        // (§9.1) отсеивает повторы по этому номеру, и общий номер означал
        // бы, что второй кусок и все следующие отброшены как повтор.
        let mut envelope = ratatosk_codec::Envelope::new(
            next_msg_id(),
            hlc,
            ratatosk_codec::PayloadType::Fragment,
            ratatosk_codec::Value::Bytes(part.to_vec()),
        );
        envelope.fragment = Some(ratatosk_codec::Fragment { uid, index: index as u64, total });
        out.push(envelope.encode()?);
    }
    Ok(out)
}

#[cfg(test)]
mod carrier_tests {
    use ratatosk_codec::{Envelope, PayloadType, Value};
    use ratatosk_crdt::Hlc;

    use super::*;

    fn ids() -> impl FnMut() -> [u8; 16] {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(1);
            [n; 16]
        }
    }

    fn big(payload_len: usize) -> Vec<u8> {
        Envelope::new(
            [0xAA; 16],
            Hlc::new(7, 1),
            PayloadType::Text,
            Value::Bytes(vec![9; payload_len]),
        )
        .encode()
        .expect("конверт собирается")
    }

    /// Несущие возвращаются байтами — разбираем их, чтобы посмотреть внутрь.
    fn opened(carrier: &[u8]) -> Envelope {
        Envelope::decode(carrier).expect("несущий разбирается").into_parts().1
    }

    #[test]
    fn what_fits_is_not_cut() {
        // Резать то, что и так доезжает, значило бы платить лишними кадрами
        // за ничто. И байты возвращаются те же самые, без второго прохода
        // через кодек.
        let encoded = big(100);
        let out = carriers(&encoded, Transport::Lan, ids()).expect("несущие собираются");
        assert_eq!(out.len(), 1, "целый конверт остаётся одним");
        assert_eq!(out[0], encoded, "и байты те же");
        assert!(opened(&out[0]).fragment.is_none(), "и заголовка фрагмента у него нет");
    }

    #[test]
    fn the_air_cuts_what_the_wire_does_not() {
        // **Ради чего всё.** Один и тот же конверт: по локальной сети едет
        // целым, по эфиру — кусками, потому что потолок класса там ниже
        // (0.4.8: класс L до Android не доходит вовсе).
        let encoded = big(50_000);
        let whole = carriers(&encoded, Transport::Lan, ids()).unwrap();
        assert_eq!(whole.len(), 1, "по проводу — целым");

        let cut = carriers(&encoded, Transport::Bt, ids()).unwrap();
        assert!(cut.len() > 1, "по эфиру — кусками: {}", cut.len());

        // Метку сборки чеканит сам резак — сверяем остальные с первой.
        let uid = opened(&cut[0]).fragment.expect("у куска обязан быть заголовок").uid;

        for (at, bytes) in cut.iter().enumerate() {
            let carrier = opened(bytes);
            let header = carrier.fragment.expect("у куска обязан быть заголовок");
            assert_eq!(header.uid, uid, "сборка одна на все куски");
            assert_eq!(header.index, at as u64, "номера идут подряд");
            assert_eq!(header.total, cut.len() as u64, "и число кусков у всех одно");
            header.validate().expect("заголовок обязан быть согласованным");
            assert_eq!(carrier.payload_type, PayloadType::Fragment, "тип несущий");
            // **Главное число этой проверки.** Несущий конверт обязан
            // помещаться в кадр, который ступень действительно возит;
            // иначе фрагментация чинила бы одно и ломала то же самое.
            assert!(
                bytes.len() <= ceiling(Transport::Bt).max_payload(),
                "несущий занял {} при потолке {}",
                bytes.len(),
                ceiling(Transport::Bt).max_payload()
            );
        }

        // **И номера сообщений у кусков разные.** Общий номер означал бы,
        // что окно дедупликации (§9.1) отбросит второй кусок и все
        // следующие как повтор — то есть сборка не завершится никогда.
        let mut seen: Vec<[u8; 16]> = cut.iter().map(|bytes| opened(bytes).msg_id).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), cut.len(), "у каждого куска свой номер сообщения");
    }

    #[test]
    fn a_chunk_sized_for_the_air_is_not_cut() {
        // **Условие, а не совпадение.** Кусок файла §10.2 в эфире подобран
        // ровно под класс S (`AIR_CHUNK_BYTES`), и резать его ещё раз
        // означало бы платить вторым конвертом за то, что уже посчитано, —
        // а заодно сделать окно передачи вдвое шире, чем ему разрешено
        // очередью. Разойдись эти два числа — и увидели бы мы это не здесь,
        // а на стенде, падением скорости вдвое.
        let sealed =
            vec![7u8; crate::files::AIR_CHUNK_BYTES + ratatosk_crypto::file::CHUNK_TAG_LEN];
        let encoded = Envelope::new(
            [0xCC; 16],
            Hlc::new(7, 1),
            PayloadType::FileChunk,
            crate::files::chunk_payload([0xBC; 16], u64::MAX, &sealed),
        )
        .encode()
        .expect("конверт с чанком собирается");

        let out = carriers(&encoded, Transport::Bt, ids()).expect("несущие собираются");
        assert_eq!(out.len(), 1, "эфирный чанк обязан ехать одним кадром");
    }

    #[test]
    fn the_pieces_put_back_together_are_the_envelope_that_went_in() {
        // Круг целиком: порезали, собрали сборщиком, разобрали — и получили
        // ровно тот конверт, который отправляли.
        let encoded = big(50_000);
        let cut = carriers(&encoded, Transport::Bt, ids()).unwrap();

        let mut reassembler = Reassembler::new();
        let mut assembled = None;
        for bytes in &cut {
            let carrier = opened(bytes);
            let header = carrier.fragment.expect("заголовок на месте");
            let Value::Bytes(part) = &carrier.payload else {
                panic!("нагрузка несущего — байты");
            };
            let got = reassembler
                .accept(header.uid, header.index, header.total, part, REASSEMBLY_TTL_DIRECT_MS, 0)
                .expect("кусок обязан приниматься");
            if let Accepted::Complete(bytes) = got {
                assembled = Some(bytes);
            }
        }

        let assembled = assembled.expect("сборка обязана завершиться последним куском");
        assert_eq!(assembled, encoded, "собранное обязано совпасть с отправленным");
        let back =
            Envelope::decode(&assembled).expect("исходный конверт разбирается").into_parts().1;
        assert_eq!(back.payload_type, PayloadType::Text, "и он тот же самый");
        assert_eq!(back.hlc, Hlc::new(7, 1), "и метка часов у него своя, та самая");
    }
}
