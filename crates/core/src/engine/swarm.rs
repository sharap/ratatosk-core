//! Рой: каталог пиров и участие в раздаче (фаза 2, §7.5, §7.5.1).
//!
//! # Что здесь есть и чего нет
//!
//! Есть каталог: кто вызвался раздавать канал и куда ему звонить.
//! Дерева раздачи (§7.1), анти-энтропии (§7.2) и вытягивания (§7.4)
//! здесь нет — они встанут на этот каталог, а не наоборот: §7.1 велит
//! держать 3–5 eager-пиров, и выбирать их не из чего, пока неизвестно,
//! кто вообще раздаёт.
//!
//! # Почему запись едет владельцу, а не всем
//!
//! Потому что состав канала знает владелец (§3.2). Сид шлёт свою запись
//! **ему одному**, а развозит её он — той же звездой, какой возит слова
//! (§7.5.2). Читатель, попытавшийся развезти сам, упёрся бы в пустой
//! список получателей: он не знает других читателей.
//!
//! Это и есть «ноль сидов — это звезда» в обратную сторону: пока роя
//! нет, каталог тоже возит звезда, и переход к рою её не отменит.

use ratatosk_proto::swarm::{self, PeerRecord, Seeding};

use super::*;

impl<S: Store> Engine<S> {
    /// Наше участие в раздаче этого чата (§7.5.1).
    ///
    /// Умолчание — **тихая раздача**: адрес не объявлен, но по своим
    /// исходящим соединениям мы несём трафик наравне со всеми. Так §7.5.1
    /// и велит: рой не должен зависеть от того, нажмёт ли кто-нибудь
    /// кнопку, а раскрытие адреса обязано остаться выбором.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn seeding(&self, chat: ChatId) -> Result<Seeding, EngineError> {
        Ok(self
            .store
            .seeding(&chat)?
            .and_then(Seeding::from_code)
            // Незнакомый код — тоже умолчание, и это не «читаем чужое
            // как своё»: код кладём мы сами, и незнакомым он окажется
            // только у базы из будущей сборки. Спуститься к тихой
            // раздаче безопаснее, чем к объявленной.
            .unwrap_or(Seeding::Quiet))
    }

    /// Кто раздаёт этот канал — каталог без протухших (§7.5).
    ///
    /// Протухшие не показываются и не отдаются наружу: «перестал
    /// продлевать — выпал», и запись с вышедшим сроком — это адрес,
    /// по которому больше не ждут.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn seeds(&self, chat: ChatId, now_ms: u64) -> Result<Vec<SeedView>, EngineError> {
        let mut found = Vec::new();
        for stored in self.store.seeds(&chat)? {
            if stored.valid_until_ms <= now_ms {
                continue;
            }
            let Ok(record) = swarm::record_from_wire(&swarm::wire_value(
                stored.record_bytes.clone(),
                &stored.signature,
            )) else {
                continue;
            };
            // Подпись проверяется **тем, чем можем**: карточка сида
            // у нас есть не всегда — читатели друг друга не знают (§3.2).
            // Непроверенную запись мы всё равно держим, и вот почему:
            // адрес и так ничем не подтверждён (§10.2), а личность
            // устанавливает рукопожатие (§8.2). Подделанный адрес в худшем
            // случае не ответит; зато выбросив запись, мы потеряли бы
            // единственный путь к сиду, чьей карточки у нас нет.
            let verified = self
                .public_identity_of(record.claims_ik())?
                .is_some_and(|who| record.clone().verify(&who).is_ok());
            // Подпись уже спрошена выше; здесь нужны поля, и берутся они
            // **не проверяя** — словами, как того требует имя метода.
            let record = record.untrusted();
            found.push(SeedView {
                ik: stored.ik,
                endpoints: record.endpoints,
                valid_until_ms: record.valid_until_ms,
                verified,
            });
        }
        Ok(found)
    }

    /// Меняет наше участие в раздаче (§7.5.1).
    ///
    /// # Только канал
    ///
    /// В группе каталог не нужен: §11.5 и так везёт каждому участнику
    /// карточки всех остальных — с адресами. Заводить рядом второй
    /// источник адресов значило бы завести пару, которая однажды
    /// разойдётся молча. §7.5 упоминает группу («публикует каждый
    /// участник»), но выигрыш там появится вместе с деревом, а не сейчас.
    ///
    /// # Объявиться без адреса нельзя
    ///
    /// Запись без единого адреса — это обещание пути, которого нет:
    /// читатель положит её в каталог и будет считать, что сид есть.
    /// Отказ вслух лучше: человеку надо поднять Tor, завести почту
    /// или назвать ключ меша.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownGroup`] — чата нет; [`EngineError::NotAChannel`]
    /// — это группа; [`EngineError::NothingToAnnounce`] — своих адресов
    /// нет вовсе; отказ хранилища.
    pub(super) fn on_set_seeding(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        mode: Seeding,
    ) -> Result<Vec<Effect>, EngineError> {
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        if mode.announces_address() && self.own_endpoints().is_empty() {
            return Err(EngineError::NothingToAnnounce);
        }
        self.store.set_seeding(&chat, mode.code(), now_ms)?;

        // **Отказ не отзывается по сети, и это решение §7.5.** Запись
        // просто перестаёт продлеваться и гаснет к концу срока; отзыв
        // потребовал бы связи ровно в тот момент, когда человек, скорее
        // всего, выключает телефон. Цена названа вслух в тексте §15.
        //
        // Свою запись при этом убираем **у себя** сразу: держать в своём
        // же каталоге обещание, от которого только что отказались, —
        // значит врать самому себе.
        if !mode.announces_address() {
            let me = self.identity.public().ik;
            self.store.delete_seed(&chat, &me)?;
            return Ok(vec![Effect::Notify(Event::SeedingChanged { chat, announced: false })]);
        }

        let mut effects = self.publish_own_record(now_ms, chat)?;
        effects.push(Effect::Notify(Event::SeedingChanged { chat, announced: true }));
        Ok(effects)
    }

    /// Подписывает свою запись каталога и отправляет её (§7.5).
    ///
    /// Одно место на первое объявление и на продление: разойдись они,
    /// продлённая запись однажды поехала бы другим набором адресов,
    /// чем объявленная.
    pub(super) fn publish_own_record(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let record = PeerRecord {
            group: chat,
            ik: me,
            endpoints: self.own_endpoints(),
            valid_until_ms: now_ms.saturating_add(swarm::RECORD_TTL_MS),
        };
        let (bytes, signature) =
            swarm::sign_record(&self.identity, &record).map_err(|_| EngineError::TooManyGrants)?;
        self.store.put_seed(
            &chat,
            &ratatosk_store::StoredSeed {
                ik: me,
                record_bytes: bytes.clone(),
                signature,
                valid_until_ms: record.valid_until_ms,
                received_ms: now_ms,
            },
        )?;

        let wire = ratatosk_codec::canonical::encode(&swarm::wire_value(bytes, &signature))
            .map_err(|_| EngineError::TooManyGrants)?;

        // Владелец развозит сам — он и есть звезда (§7.5.2). Остальные
        // шлют ему одному: состава у них нет (§3.2), и веер им собрать
        // не из чего.
        let owner = self.channel_owner(chat).unwrap_or(me);
        if owner == me {
            let action = ratatosk_proto::group_action::Action::SeedRecord { bytes: wire };
            let (msg_id, _, sealed) = self.seal_group_action(now_ms, chat, &action)?;
            return self.fan_out_group(now_ms, chat, msg_id, &sealed);
        }
        let (_, effects) = self.enqueue_request(
            now_ms,
            owner,
            PayloadType::SwarmPeer,
            ratatosk_codec::Value::Map(vec![
                (
                    ratatosk_codec::Value::Integer(SWARM_KEY_GROUP.into()),
                    ratatosk_codec::Value::Bytes(chat.to_vec()),
                ),
                (
                    ratatosk_codec::Value::Integer(SWARM_KEY_RECORD.into()),
                    ratatosk_codec::Value::Bytes(wire),
                ),
            ]),
        )?;
        Ok(effects)
    }

    /// Пришла запись каталога **один на один** — от сида владельцу (§7.5).
    ///
    /// # Почему её развозит владелец, а не принимает молча
    ///
    /// Каталог нужен не ему: он и так знает состав. Нужен он читателям —
    /// чтобы было у кого спрашивать блоки, когда появится дерево (§7.1).
    /// Значит принятая запись обязана поехать дальше, и везёт её тот,
    /// у кого есть список получателей.
    pub(super) fn on_seed_record(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — до всякого разбора, как у заявки и обновления
        // карточки: кадр едет очередью §5.4, у него заведён срок, и без
        // подтверждения §5.4 объявит неудачу и начнёт новое рукопожатие.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Ok(map) = ratatosk_codec::canonical::as_map(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };
        let (Ok(chat), Ok(wire)) = (
            ratatosk_codec::canonical::require(map, SWARM_KEY_GROUP.into())
                .and_then(ratatosk_codec::canonical::as_array::<16>),
            ratatosk_codec::canonical::require(map, SWARM_KEY_RECORD.into())
                .and_then(ratatosk_codec::canonical::as_bytes),
        ) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };
        let wire = wire.to_vec();

        // Канал обязан быть нашим: чужую раздачу нам развозить нечем —
        // состава у нас нет. Молча, как у заявки: кадр не по адресу.
        let me = self.identity.public().ik;
        let Some(state) = self.groups.get(&chat) else { return Ok(effects) };
        if state.profile.everyone_writes() || state.group.owner != me {
            return Ok(effects);
        }
        // **Раздавать вправе только тот, кто в составе.** Иначе любой,
        // узнавший идентификатор канала, вписал бы себя в каталог
        // и стал бы для читателей адресом, у которого те спрашивают
        // блоки. §7.6 разрешает **читать** всякому с идентификатором —
        // но каталог не про чтение, а про то, кому доверить раздачу.
        if !state.group.contains(&peer_ik) {
            return Ok(effects);
        }
        if !self.take_seed_record(now_ms, chat, peer_ik, &wire)? {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }
        effects.push(Effect::Notify(Event::SeedAnnounced { chat, who: peer_ik }));

        // И дальше — всем: тем же действием, каким каталог поедет в рое.
        let action = ratatosk_proto::group_action::Action::SeedRecord { bytes: wire };
        let (msg_id, _, sealed) = self.seal_group_action(now_ms, chat, &action)?;
        effects.extend(self.fan_out_group(now_ms, chat, msg_id, &sealed)?);
        Ok(effects)
    }

    /// Кладёт принятую запись каталога. Отдаёт `false`, если не годится.
    ///
    /// # Что проверяется
    ///
    /// * запись **про этот канал** — иначе одна раздача попала бы
    ///   в каталог другой;
    /// * `ik` записи — тот, о ком речь: подписать чужой адрес нельзя;
    /// * подпись — **если есть чем**. Карточки сида у нас может не быть
    ///   вовсе: читатели друг друга не знают (§3.2). Непроверенную запись
    ///   держим — адрес и так ничем не подтверждён (§10.2), а личность
    ///   устанавливает рукопожатие;
    /// * срок: протухшую не берём вовсе, а слишком долгую **подрезаем**.
    ///   Запись «годна до три тысячи двадцатого года» иначе осталась бы
    ///   в каталоге навсегда: уборка ходит по сроку.
    pub(super) fn take_seed_record(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        claimed: [u8; 32],
        wire: &[u8],
    ) -> Result<bool, EngineError> {
        let Ok(value) = ratatosk_codec::canonical::decode(wire) else { return Ok(false) };
        let Ok(unchecked) = swarm::record_from_wire(&value) else { return Ok(false) };
        if unchecked.claims_group() != &chat || unchecked.claims_ik() != &claimed {
            return Ok(false);
        }
        let signature = *unchecked.signature();
        let bytes = unchecked.signed_bytes().to_vec();
        if let Some(who) = self.public_identity_of(&claimed)? {
            if unchecked.clone().verify(&who).is_err() {
                return Ok(false);
            }
        }

        let record = unchecked.untrusted();
        if record.valid_until_ms <= now_ms {
            return Ok(false);
        }
        let ceiling = now_ms.saturating_add(swarm::RECORD_TTL_MS).saturating_add(DAY_MS);
        self.store.put_seed(
            &chat,
            &ratatosk_store::StoredSeed {
                ik: claimed,
                record_bytes: bytes,
                signature,
                valid_until_ms: record.valid_until_ms.min(ceiling),
                received_ms: now_ms,
            },
        )?;
        Ok(true)
    }

    /// Продлевает свою запись и убирает чужие протухшие (§7.5).
    ///
    /// Зовётся обслуживанием, а не таймером: своих часов у ядра нет,
    /// и «раз в сутки» здесь означает «на первом шаге после того, как
    /// сутки прошли».
    pub(super) fn keep_catalogue_fresh(&mut self, now_ms: u64) -> Result<Vec<Effect>, EngineError> {
        self.store.prune_seeds(now_ms)?;
        let me = self.identity.public().ik;
        let chats: Vec<ChatId> = self
            .groups
            .iter()
            .filter(|(_, state)| !state.profile.everyone_writes())
            .map(|(chat, _)| *chat)
            .collect();
        let mut effects = Vec::new();
        for chat in chats {
            if !self.seeding(chat)?.announces_address() {
                continue;
            }
            // Продлевается **своя** запись, и срок её берётся из каталога:
            // второго места, где он живёт, нет. Нет записи вовсе — значит
            // её унесла уборка, и объявиться надо заново.
            let mine = self.store.seeds(&chat)?.into_iter().find(|seed| seed.ik == me);
            let due = mine.map_or(true, |seed| {
                seed.valid_until_ms <= now_ms.saturating_add(swarm::RENEW_AHEAD_MS)
            });
            if due {
                effects.extend(self.publish_own_record(now_ms, chat)?);
            }
        }
        Ok(effects)
    }
}

/// Сутки в миллисекундах — запас на расхождение часов.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Ключ поля «канал» в кадре записи каталога.
const SWARM_KEY_GROUP: u8 = 1;
/// Ключ поля «подписанная запись».
const SWARM_KEY_RECORD: u8 = 2;

/// Что клиент показывает про сида (§7.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedView {
    /// Чей адрес.
    pub ik: [u8; 32],
    /// Куда набирать.
    pub endpoints: Vec<ratatosk_proto::channel::Endpoint>,
    /// До какого момента запись годна, мс.
    pub valid_until_ms: u64,
    /// Сошлась ли подпись.
    ///
    /// **Ложь здесь означает «проверить было нечем», а не «подделка»:**
    /// карточки сида у читателя может не быть вовсе (§3.2). Подделанная
    /// запись отсеивается там, где её видно, — у владельца, который
    /// карточки знает.
    pub verified: bool,
}
