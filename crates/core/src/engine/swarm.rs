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

use ratatosk_proto::swarm::{self, PeerRecord, Seeding, Sharing};

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

    /// Ставит уровень отдачи — на аккаунт или на один канал (§12).
    ///
    /// # Ничего не уезжает
    ///
    /// Уровень локален: он про то, кому **мы** отдаём, и в чужой записи
    /// ему делать нечего. Тем он и отличается от объявления адреса
    /// (§7.5), которое по сети едет.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownGroup`] — канала нет;
    /// [`EngineError::NotAChannel`] — это группа: уровни отдачи живут
    /// у каналов, а в группе раздачи нет вовсе (§7.5).
    pub(super) fn on_set_sharing(
        &mut self,
        now_ms: u64,
        chat: Option<ChatId>,
        level: Option<Sharing>,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(chat) = chat else {
            // Умолчание аккаунта. `None` здесь — возврат к «всем»:
            // строки просто не будет, и это то же самое, что её
            // отсутствие у новой базы.
            match level {
                Some(level) => self.store.put_meta(
                    ratatosk_store::META_SHARING,
                    &[u8::try_from(level.code()).unwrap_or(0)],
                )?,
                None => self.store.put_meta(ratatosk_store::META_SHARING, &[])?,
            }
            return Ok(Vec::new());
        };
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        self.store.set_sharing(&chat, level.map(Sharing::code), now_ms)?;
        Ok(Vec::new())
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
            // Дорогой документа (`push_document`): веером по составу
            // каталог открытого канала не узнал бы никто, а каталог —
            // это то, чем открытый канал только и держится.
            return self.push_document(now_ms, chat, msg_id, &sealed);
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
        // **Раздавать вправе тот, кто в составе, — но состав есть
        // не у всякого канала.** У открытого его нет вовсе (§10.4),
        // и требование состава означало там «в каталог не попадёт
        // никто»: рой открытого канала навсегда оставался звездой
        // на владельце, а читатели не узнавали друг о друге. Живой
        // прогон описал это как «часть получает всё быстро, часть
        // немного, часть вообще ничего».
        //
        // §7.6 отвечает, чем заменить состав: «вытянуть шифротекст
        // вправе любой, у кого есть идентификатор канала». Раздача
        // открытого канала и есть способ его существования (§10.7),
        // и спрашивать у неё состав не у кого. Вместо состава её держит
        // предел (`MAX_SEEDS`) и остывание §7.7.
        //
        // У канала по приглашению всё как было: состав есть, и он —
        // точный ответ на вопрос «кому доверить раздачу».
        if !self.is_open_channel(chat)? && !state.group.contains(&peer_ik) {
            return Ok(effects);
        }
        // Полный каталог — не аномалия кадра, а наш предел, и считать
        // за него чужую вину нельзя: пир прислал честную запись, места
        // не нашлось у нас.
        if !self.catalogue_has_room(chat, &peer_ik, now_ms)? {
            return Ok(effects);
        }
        if !self.take_seed_record(now_ms, chat, peer_ik, &wire)? {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }
        effects.push(Effect::Notify(Event::SeedAnnounced { chat, who: peer_ik }));

        // И дальше — всем: тем же действием и той же дорогой, какой
        // в этом канале едет всё остальное.
        let action = ratatosk_proto::group_action::Action::SeedRecord { bytes: wire };
        let (msg_id, _, sealed) = self.seal_group_action(now_ms, chat, &action)?;
        effects.extend(self.push_document(now_ms, chat, msg_id, &sealed)?);
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
    /// Есть ли в каталоге этого канала место под ещё одну запись (§7.5).
    ///
    /// Уже известному раздающему место есть всегда: продление записи
    /// новой не заводит, а запрети мы его на полном каталоге — список
    /// застыл бы навсегда, протухая целиком и разом.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    fn catalogue_has_room(
        &self,
        chat: ChatId,
        claimed: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool, EngineError> {
        let me = self.identity.public().ik;
        let known = self.store.seeds(&chat)?;
        if known.iter().any(|seed| seed.ik == *claimed) {
            return Ok(true);
        }
        // Считаются **годные и чужие**. Протухшие уберёт обход
        // (`prune_seeds`), и держать из-за них место занятым значило бы
        // запирать каталог теми, кого в нём давно нет. А своя запись
        // места у роя не отнимает: предел заведён против чужого потока,
        // и отдавать ему одно из мест за то, что мы сами раздаём, —
        // значит наказывать себя за раздачу.
        let taken =
            known.iter().filter(|seed| seed.valid_until_ms > now_ms && seed.ik != me).count();
        Ok(taken < swarm::MAX_SEEDS)
    }

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
        // **Адреса из записи — это путь к сиду** (§8.3). Без них каталог
        // остался бы списком ключей: привязаться (§7.5.1) не к чему,
        // §5.4 честно ответил бы «отправлять некуда». Кладутся они тем же
        // способом, что адреса владельца из ссылки, и с тем же доверием:
        // недоверенные (§10.2), проверяются рукопожатием.
        //
        // Своя запись сюда не попадает — она кладётся при подписании.
        if claimed != self.identity.public().ik {
            self.remember_peer(
                now_ms,
                claimed,
                &record.endpoints,
                ratatosk_store::PEER_CHANNEL_SEED,
            )?;
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
        // Архив обрезается тем же обходом: окно §9.3 меряется сутками,
        // и повод у него тот же, что у продления записи и поворота
        // ключа — единственный, который случается на спящем телефоне.
        self.prune_archives(now_ms)?;
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
            // **Фоновый аккаунт запись не продлевает** (§12: «его
            // сидирование прекращается, `PeerRecord` выпадает по сроку»).
            //
            // Выпадает, а не отзывается, — отзыва §7.5 не знает вовсе.
            // Значит цена переключения названа заранее: читатели будут
            // набирать погасший адрес до конца недели, а остывание §7.7
            // уведёт их к другим сидам раньше.
            if !self.foreground {
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
        // **Против эклипса — периодическое повышение** (§7.7): «лечится
        // минимальной степенью и периодическим повышением случайного
        // пира». Минимальная степень уже есть (`split_tree` поднимает
        // при опустевшем eager); здесь вторая половина. Без неё
        // запруненный со всех сторон узел так и остался бы ленивым
        // у всех — то есть отрезанным от живой ленты, хотя связи
        // у него есть.
        let trees: Vec<ChatId> = self.tree.keys().copied().collect();
        for chat in trees {
            let lazy: Vec<[u8; 32]> = self
                .tree
                .get(&chat)
                .map(|tree| tree.lazy.iter().copied().collect())
                .unwrap_or_default();
            if lazy.is_empty() {
                continue;
            }
            // Случайный, а не первый: первый по ключу поднимался бы
            // каждый обход, и «периодическое повышение случайного»
            // выродилось бы в «вечный eager у одного и того же».
            let mut raw = [0u8; 4];
            self.entropy.fill(&mut raw);
            let pick = usize::try_from(u32::from_le_bytes(raw)).unwrap_or(0) % lazy.len();
            let lucky = lazy[pick];
            if let Some(tree) = self.tree.get_mut(&chat) {
                tree.lazy.remove(&lucky);
                tree.eager.insert(lucky);
            }
        }

        // **Привязка повторяется обходом, и это не расточительство.**
        // У сида она живёт только в памяти: соединение — не запись
        // на диске, и после его перезапуска читателя надо назвать заново.
        // Молчание читателя от молчания сети не отличается, поэтому
        // единственный честный способ — повторять.
        let channels: Vec<ChatId> = self
            .groups
            .iter()
            .filter(|(_, state)| !state.profile.everyone_writes())
            .map(|(chat, _)| *chat)
            .collect();
        for chat in channels {
            effects.extend(self.attach_to_seeds(now_ms, chat)?);
        }
        Ok(effects)
    }
}

impl<S: Store> Engine<S> {
    /// Привязывается к сидам канала: «я читаю его, шлите блоки» (§7.5.1).
    ///
    /// # Соединение открывает читатель, и это не деталь
    ///
    /// Сид не знает, кто его читает: состава канала у него нет (§3.2),
    /// а каталог ведёт в обратную сторону — читатели узнают сидов.
    /// Значит первый шаг за читателем: он набирает сида и говорит, что
    /// ему нужно. Дальше сид шлёт блоки в это соединение — ровно то,
    /// что §7.5.1 называет тихой раздачей.
    ///
    /// # Сколько сидов держим
    ///
    /// Не больше [`MAX_ATTACHED_SEEDS`]: §7.1 держит 3–5 eager-пиров,
    /// и здесь то же число по той же причине — каждый лишний сид стоит
    /// лишней копии каждого блока. Выбор **по порядку ключа**, а не
    /// случайный: прогон обязан воспроизводиться по сиду (§16).
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn attach_to_seeds(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let seeds = self.attach_targets(now_ms, chat)?;
        let mut effects = Vec::new();
        for seed in seeds {
            // Отказ по одному не обрывает остальных, и обход тем более:
            // он идёт по **всем** каналам, и один потерянный адрес унёс
            // бы с собой и поворот ключа, и каталог, и привязки
            // ко всему прочему.
            match self.attach_one(now_ms, chat, seed) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::debug!(?error, "до сида не дотянуться"),
            }
        }
        Ok(effects)
    }

    /// Кому говорить «шли мне блоки» по этому каналу (§7.5.1, §7.5.2).
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    fn attach_targets(&mut self, now_ms: u64, chat: ChatId) -> Result<Vec<[u8; 32]>, EngineError> {
        let me = self.identity.public().ik;
        // Владельцу привязываться не к кому: он источник, и блоки
        // начинаются с него.
        if self.channel_owner(chat).is_some_and(|owner| owner == me) {
            return Ok(Vec::new());
        }
        // **Предпочтение отвечавшим недавно** (§7.7): сперва те, кто
        // что-то нам отдавал, потом остальные; остывающие — в конец,
        // а не вон: других может не быть вовсе, и тогда лучше попробовать
        // остывшего, чем не пробовать никого.
        // **Сид, до которого нам нечем дозвониться, — не кандидат.**
        // Каталог общий на канал, а ступени у читателей **разные**:
        // один в меше, другой на реле, и записи друг друга они видят,
        // а дозвониться не могут. Привяжись такой читатель к такому
        // сиду — он замолчал бы навсегда: владелец о нём больше не
        // знает (привязка живёт в памяти, §7.5.1), а сид недостижим.
        //
        // Живой прогон описал это так: «на двух устройствах всё отлично
        // работает, поломки начинаются, когда появляется ещё одно».
        // Пока их двое, выбирать не из чего; третий — первый раз, когда
        // выбор есть и его можно сделать неверно.
        //
        // Спрашивается `Rung::usable` — «разрешена, поднята, адресуема», —
        // а не `may_open`. Разница здесь решающая: `may_open` отвечает
        // «адрес известен, ступень когда-нибудь заработает», и для
        // **отправки** это верный вопрос — кадр полежит в очереди
        // и уедет. Привязка так не умеет: «шли мне блоки» не лежит
        // в очереди месяцами, а сид, выбранный вместо владельца,
        // отнимает единственную дорогу, которая работала.
        //
        // Ступень, которая сейчас поднимается, сид не теряет: обход
        // ходит раз в час и назовёт его снова, как только она встанет.
        let mut candidates: Vec<[u8; 32]> = self
            .seeds(chat, now_ms)?
            .into_iter()
            .map(|seed| seed.ik)
            .filter(|ik| *ik != me)
            .filter(|ik| {
                self.availability_of(ik).is_ok_and(|availability| {
                    ratatosk_proto::transport_policy::Reachability::of(availability)
                        .rungs
                        .iter()
                        .any(|rung| rung.usable())
                })
            })
            .collect();
        // **Открытый канал без сидов — привязываемся к владельцу.** §7.5.2:
        // «ноль сидов — это звезда, и она обязана работать как состояние,
        // а не как деградация». У канала по приглашению звезда работает
        // и без привязки — владелец знает состав; у открытого состава
        // не существует (§6.1), и пока мы не сказали «шли мне блоки»,
        // слать ему некому. Отсюда и была тишина: подписка по открытой
        // ссылке не приносила ни одного слова.
        //
        // **А у канала по приглашению — не привязываемся вовсе.** Там
        // владелец знает состав (§3.2) и шлёт по нему без всякой
        // привязки; скажи мы ему «шли мне блоки», он слал бы дважды,
        // дубль подрезал бы ребро сида (§7.1, шаг 3) — и рой свернулся
        // бы обратно в звезду. Замер поймал это сразу: дерево
        // у владельца переставало сжиматься вовсе.
        if candidates.is_empty() && self.is_open_channel(chat)? {
            if let Some(owner) = self.channel_owner(chat).filter(|owner| *owner != me) {
                candidates.push(owner);
            }
        }
        let owner = self.channel_owner(chat);
        candidates.sort_by_key(|ik| {
            let budget = self.swarm_budget.get(ik);
            let cooling = u8::from(self.cooling(now_ms, ik));
            // Владелец — последний из годных: сиды затем и есть, чтобы
            // снять с него нагрузку (§7.5.2).
            let is_owner = u8::from(owner == Some(*ik));
            // По убыванию «недавности»: чем позже ответил, тем раньше
            // в списке. Ключ добавлен третьим, чтобы порядок оставался
            // воспроизводимым по сиду (§16).
            (cooling, is_owner, std::cmp::Reverse(budget.map_or(0, |b| b.answered_ms)), *ik)
        });
        Ok(candidates.into_iter().take(MAX_ATTACHED_SEEDS).collect())
    }

    /// Открытый ли это канал (§6.1) — по **подписанному** документу.
    ///
    /// Порода из ссылки здесь не годится: она недоверена до первой
    /// подписи (§10.3, шаг 3), а решение по ней — кому говорить «шли мне
    /// блоки».
    fn is_open_channel(&self, chat: ChatId) -> Result<bool, EngineError> {
        if let Some(kind) = self
            .store
            .channel(&chat)?
            .and_then(|it| ratatosk_proto::channel::Kind::from_code(u64::from(it.kind)))
        {
            return Ok(kind == ratatosk_proto::channel::Kind::Open);
        }
        // **Документа ещё нет — верим ссылке, и здесь это законно.**
        // §10.3 не велит верить её породе в том, что касается
        // содержимого; здесь же решается, у кого спрашивать блоки,
        // и худшее, чем может обернуться ложь ссылки, — просьба
        // к владельцу, который просто не ответит. А без этого читатель
        // молчал бы до приезда представления — то есть ровно в тот
        // промежуток, когда представление и надо привезти.
        Ok(self.store.subscription(&chat)?.is_some_and(|it| it.kind_claimed == 1))
    }

    /// Говорит одному пиру «шли мне блоки этого канала» (§7.5.1).
    ///
    /// # Errors
    ///
    /// Отказ хранилища на постановке в очередь.
    pub(super) fn attach_one(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        seed: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        // **Кого набрали — помним**: тихая раздача (§7.5.1) отдаёт
        // именно им, и без этого списка «те, с кем соединились сами»
        // неотличимы от «кто угодно».
        self.dialed.entry(chat).or_default().insert(seed);
        // Молчаливой доставкой: квитанции у привязки нет и не нужно.
        // Не доехала — доедет следующим обходом, а пока слово придёт
        // от владельца звездой (§7.5.2).
        let (_, mut effects) = self.enqueue_request(
            now_ms,
            seed,
            PayloadType::SwarmAttach,
            swarm::attach_value(&chat),
        )?;
        // **Следом — свой have-вектор** (§7.2: «при установлении
        // соединения — обмен have-векторами»). Дерево возит хвост,
        // анти-энтропия — историю, и связь с сидом это единственный
        // момент, когда мы знаем, что он нас слышит.
        effects.extend(self.send_have(now_ms, chat, seed)?);
        Ok(effects)
    }

    /// Обслуживаем ли мы этого спрашивающего по этому каналу (§8.3, §7.5.1).
    ///
    /// # Что здесь сказано и чего здесь нет
    ///
    /// §8.3 называет это «правом на обслуживание» и предлагает
    /// проверять, «есть ли `IK` инициатора в `PeerRecord` какой-нибудь
    /// нашей группы». Здесь проверяется **не то**, и это решение,
    /// а не недосмотр:
    ///
    /// * спрашивающий — обычно **не сид**, а читатель, и в каталоге
    ///   его нет и не будет: §7.5.1 умолчанием ставит тихую раздачу,
    ///   при которой адрес не объявляется. Требуй мы записи от него,
    ///   рой обслуживал бы только сидов, то есть не работал бы вовсе;
    /// * §7.6 прямо запрещает спрашивать право **на чтение**: «любой,
    ///   у кого есть идентификатор канала, вправе вытянуть шифротекст».
    ///   Проверка состава здесь была бы ровно тем, что §7.6 отменяет;
    /// * закрывать сессию незнакомцу нельзя и по третьей причине:
    ///   заявка §10.4 — это рукопожатие именно от незнакомца, и владелец
    ///   обязан его принять.
    ///
    /// Спрашивается поэтому **наше** состояние, а не чужое, — ровно
    /// табличка §7.5.1: «нас набирают» и «кому отдаём».
    ///
    /// | Наше участие | Кому отдаём |
    /// |---|---|
    /// | не раздаём | никому |
    /// | тихо (умолчание) | тем, к кому подключились сами |
    /// | объявлено | всякому, кто спросил (§7.6) |
    ///
    /// **Владелец отдаёт всегда.** Он источник, и звезда §7.5.2 обязана
    /// работать как состояние: запрети мы ему отдавать, канал без сидов
    /// перестал бы существовать.
    ///
    /// # Errors
    ///
    /// Отказ хранилища на чтении состояния раздачи.
    pub(super) fn may_serve(&self, chat: ChatId, peer_ik: &[u8; 32]) -> Result<bool, EngineError> {
        // **Фоновый аккаунт не раздаёт** (§12). «Активен ровно один
        // аккаунт… его сидирование прекращается»: второй аккаунт,
        // открытый на том же устройстве, отдаёт блоки тем же радио
        // и тем же каналом, что и первый, — и связывает их на проводе
        // временем и объёмом. §12 называет это прямо: «не экономия,
        // а связывание аккаунтов».
        //
        // Принимать при этом можно: §12 начинается с того, что
        // принимать почти бесплатно, а платит — отдающий.
        if !self.foreground {
            return Ok(false);
        }
        let me = self.identity.public().ik;
        if self.channel_owner(chat).is_some_and(|owner| owner == me) {
            return Ok(true);
        }
        let participates = match self.seeding(chat)? {
            Seeding::Off => false,
            Seeding::Quiet => self.dialed.get(&chat).is_some_and(|dialed| dialed.contains(peer_ik)),
            Seeding::Announced => true,
        };
        // **Две ручки, а не одна** (§12). Участие в раздаче отвечает
        // на вопрос «раздаём ли вообще», уровень — «кому». Сложи их
        // в одну настройку, и «раздаю только контактам» стало бы
        // неотличимо от «не раздаю», а это разные вещи и для человека,
        // и для роя.
        Ok(participates && self.sharing_allows(chat, peer_ik)?)
    }

    /// Проходит ли этот пир по уровню отдачи (§12, «уровни отдачи»).
    ///
    /// Уровень берётся у канала, а нет своего — у аккаунта: §12 держит
    /// его «на аккаунт, с переопределением на группу».
    fn sharing_allows(&self, chat: ChatId, peer_ik: &[u8; 32]) -> Result<bool, EngineError> {
        Ok(match self.sharing(chat)? {
            Sharing::Everyone => true,
            Sharing::Contacts => self.contacts.contains_key(peer_ik),
            // **Сверенность спрашивается у контакта, и только у него.**
            // Пир роя (§8.3) сверенным не бывает: сверка — это сличение
            // отпечатков двумя людьми, а за пиром человека мы не знаем.
            Sharing::Verified => self.contacts.get(peer_ik).is_some_and(|who| who.verified),
        })
    }

    /// Уровень отдачи этого канала (§12): свой, а нет — аккаунта.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn sharing(&self, chat: ChatId) -> Result<Sharing, EngineError> {
        if let Some(level) = self.store.sharing(&chat)?.and_then(Sharing::from_code) {
            return Ok(level);
        }
        self.account_sharing()
    }

    /// Уровень отдачи аккаунта (§12). Умолчание — «всем».
    ///
    /// **Незнакомый код читается как «всем», и это осознанно.** У кодов
    /// из будущей сборки смысл может быть любым, но строку кладём мы
    /// сами, а не сеть; выбирая между «раздать лишнему» и «перестать
    /// раздавать вовсе», §12 выбирает первое: «умолчание остаётся
    /// открытым», потому что закрытый рой ломается тихо и не у того,
    /// кто настраивал.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn account_sharing(&self) -> Result<Sharing, EngineError> {
        let Some(bytes) = self.store.meta(ratatosk_store::META_SHARING)? else {
            return Ok(Sharing::Everyone);
        };
        let Some(&code) = bytes.first() else { return Ok(Sharing::Everyone) };
        Ok(Sharing::from_code(u32::from(code)).unwrap_or(Sharing::Everyone))
    }

    /// Сессия с этим пиром поднялась — назваться ему заново (§7.5.1).
    ///
    /// # Привязка живёт ровно столько, сколько живёт связь
    ///
    /// Она и объявлена свойством живого соединения: у принимающей
    /// стороны это строка в памяти. Значит всякий раз, когда соединение
    /// заводится заново — после перезапуска любого из двоих, после
    /// смены сети, после часов сна, — назваться надо снова. Ждать
    /// обхода нельзя: обход ходит раз в час **и только когда ядро
    /// просыпается**, а просыпается телефон от входящего — которого
    /// как раз и нет.
    ///
    /// Живой прогон описал это так: «через некоторое время сообщения
    /// в канале перестают приходить». Перестают навсегда: привязку
    /// потеряли, а повторить её нечем — тишина сама себя держит.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn reattach_to(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let channels: Vec<ChatId> = self
            .groups
            .iter()
            .filter(|(_, state)| !state.profile.everyone_writes())
            // Владелец никому не привязывается: он источник, и «шли мне
            // блоки» от него означало бы, что читатель начнёт слать ему
            // его же слова, а дубль подрежет ребро (§7.1, шаг 3).
            .filter(|(_, state)| state.group.owner != me)
            .map(|(chat, _)| *chat)
            .collect();
        let mut effects = Vec::new();
        for chat in channels {
            // Привязываемся не ко всякому, а ровно к тем, у кого
            // спрашиваем блоки, — и список этот один на оба места
            // (`attach_targets`): разойдись они, связь поднималась бы
            // с одним, а привязка уезжала бы к другому.
            if !self.attach_targets(now_ms, chat)?.contains(&peer_ik) {
                continue;
            }
            effects.extend(self.attach_one(now_ms, chat, peer_ik)?);
        }
        Ok(effects)
    }

    /// Пришла привязка: кто-то читает наш канал и просит блоки (§7.5.1).
    ///
    /// # Права не спрашиваем, и это §7.6
    ///
    /// «Любой, у кого есть идентификатор канала, вправе вытянуть
    /// шифротекст; прочесть — нет». Сид состава не знает и проверить
    /// право не может в принципе; защищаться надо не от чужих,
    /// а от избыточных — отсюда предел [`MAX_ATTACHED_READERS`].
    pub(super) fn on_swarm_attach(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — до разбора, и метёлка `receipt_wiring` нашла здесь
        // её отсутствие в ту же минуту, как привязка попала в очередь.
        // Цепочка та же, что у заявки: кадр едет очередью §5.4, у него
        // заведён срок, и без подтверждения §5.4 объявит неудачу,
        // отправит сессию на покой и начнёт новое рукопожатие — на каждой
        // привязке, то есть на каждом обходе.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Ok(chat) = swarm::attach_from_value(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };
        // Канала не знаем — отдавать нечего. Молча: это кадр не по адресу,
        // и рассказывать о нём нечего ни человеку, ни счётчику.
        let Some(state) = self.groups.get(&chat) else { return Ok(effects) };
        if state.profile.everyone_writes() {
            return Ok(effects);
        }
        // **Право на обслуживание** (§8.3, вторая половина). Молча:
        // сказать «я вам не раздаю» — значит сказать, что канал у нас
        // есть, а §7.5.1 обещает обратное тому, кто раздачу выключил.
        if !self.may_serve(chat, &peer_ik)? {
            tracing::debug!(peer = ?&peer_ik[..4], "привязка отклонена: не раздаём (§8.3)");
            return Ok(effects);
        }
        let attached = self.attached.entry(chat).or_default();
        // Предел — против избыточных (§7.7, §9.2), а не против чужих.
        // Переполнение **не вытесняет** прежних: вытеснение отдало бы
        // любому желающему возможность выбить чужого читателя из раздачи
        // одним кадром.
        if attached.len() >= MAX_ATTACHED_READERS && !attached.contains(&peer_ik) {
            return Ok(effects);
        }
        attached.insert(peer_ik);
        // **И свой вектор в ответ** — вторая половина обмена §7.2.
        // Без неё привязавшийся узнал бы только то, что появится
        // **после** привязки, а пропущенное так и осталось бы
        // пропущенным: дерево историю не возит.
        effects.extend(self.send_have(now_ms, chat, peer_ik)?);
        // **И документ с каталогом — если канал наш** (§7.4, шаг 1).
        //
        // Привязка — единственный повод, на котором мы знаем, что
        // читатель снова здесь; а сам он не знает, что отстал: версию
        // документа видно только у нас. Вектор §7.2 рядом вернёт
        // пропущенные **слова**, но документ по номерам не догнать —
        // он выпадает из архива по окну §9.3, а у каналов, разъехавшихся
        // до появления `push_document`, его там не было никогда.
        //
        // Читатель без свежего документа не знает выдач прав (§6.2)
        // и потому не может проверить ни одного слова второго автора:
        // блоки доезжают и откладываются навсегда.
        let me = self.identity.public().ik;
        if self.channel_owner(chat).is_some_and(|owner| owner == me) {
            effects.extend(self.send_channel_intro(now_ms, chat, peer_ik)?);
        }
        // Наружу — ничего, кроме квитанции: привязка не разговор.
        // Что блоки пошли, читатель увидит по самим блокам.
        Ok(effects)
    }
}

impl<S: Store> Engine<S> {
    /// Кому мы **можем** слать блоки этого канала.
    ///
    /// У владельца это состав (§3.2 оставляет его ему), у остальных —
    /// те, кто привязался к нам сам (§7.5.1). Третьего источника нет:
    /// читатель, к которому мы не подключены и который не подключился
    /// к нам, для нас не существует.
    pub(super) fn push_candidates(
        &self,
        chat: ChatId,
        own: bool,
    ) -> Result<Vec<[u8; 32]>, EngineError> {
        let me = self.identity.public().ik;
        if self.channel_owner(chat).is_some_and(|owner| owner == me) {
            // **Состав и привязавшиеся, а не одно только состав.**
            // У открытого канала состава не существует (§6.1), и пока
            // здесь был один `recipients`, слово владельца не уходило
            // никуда: подписчик по ссылке владельцу неизвестен. Привязка
            // (§7.5.1) — то, чем он о себе говорит, и для открытого
            // канала она единственный список получателей.
            let mut targets =
                self.groups.get(&chat).map(|state| state.group.recipients(&me)).unwrap_or_default();
            for peer in self.attached.get(&chat).into_iter().flatten() {
                if !targets.contains(peer) {
                    targets.push(*peer);
                }
            }
            return Ok(targets);
        }
        // **Право спрашивается здесь, а не только при привязке** (§8.3).
        // Привязка живёт в памяти, а раздачу человек выключает когда
        // захочет; проверь мы право один раз на входе, «не раздаю»
        // означало бы «не беру новых», и прежние читатели получали бы
        // блоки дальше — то есть кнопка врала бы.
        let mut candidates = Vec::new();
        for peer in self.attached.get(&chat).into_iter().flatten() {
            if self.may_serve(chat, peer)? {
                candidates.push(*peer);
            }
        }
        // **Своё слово едет ещё и вверх по течению** — владельцу и нашим
        // сидам (§7.5.1, §7.5.2). Состав канала знает владелец (§3.2),
        // и у того, кому дали право писать (§6.2), списка читателей нет
        // и быть не может: единственная его дорога — отдать слово тому,
        // у кого список есть.
        //
        // **Только своё.** Чужой блок пришёл к нам **от** кого-то
        // из них, и возвращать его туда же значит слать дубль, который
        // подрежет ребро (§7.1, шаг 3) и развалит дерево. Замер поймал
        // это сразу: у владельца переставала работать экономия.
        if !own {
            return Ok(candidates);
        }
        if let Some(owner) = self.channel_owner(chat).filter(|owner| *owner != me) {
            if !candidates.contains(&owner) {
                candidates.push(owner);
            }
        }
        for seed in self.dialed.get(&chat).into_iter().flatten() {
            if !candidates.contains(seed) {
                candidates.push(*seed);
            }
        }
        Ok(candidates)
    }

    /// Какой ступенью блок поедет к этому пиру **сейчас** (§5.4).
    ///
    /// Первая годная по лестнице — та же, которую выберет доставка.
    /// Ни одной годной нет — `None`: кадр ляжет в очередь и поедет,
    /// когда путь появится, а форму дерева на «пока некуда» строить
    /// нельзя.
    fn rung_to(&self, peer_ik: &[u8; 32]) -> Option<Transport> {
        let availability = self.availability_of(peer_ik).ok()?;
        ratatosk_proto::transport_policy::Reachability::of(availability)
            .rungs
            .into_iter()
            .find(|rung| rung.usable())
            .map(|rung| rung.transport)
    }

    /// Делит тех, кому можем слать, на eager и lazy (§7.1).
    ///
    /// # Почему по порядку ключа, а не случайно
    ///
    /// Прогон обязан воспроизводиться по сиду (§16). Случайный выбор
    /// eager дал бы дерево, которое у двух прогонов разное, и падение
    /// на нём не повторить. Случайность §7.1 нужна в другом месте —
    /// в повышении при опустевшем eager, и там она берётся из того же
    /// сида.
    ///
    /// # Минимальная степень
    ///
    /// «Опустело eager — повысить случайного из lazy, не дожидаясь
    /// `IHAVE`» (§7.1). Иначе запруненный узел оглохнет: ему некому
    /// слать целиком, а `IHAVE` он рассылает в пустоту.
    fn split_tree(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        own: bool,
    ) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>), EngineError> {
        let candidates = self.push_candidates(chat, own)?;
        // **Вопрос здесь один: есть ли у ленивого второй путь.** Ленивый
        // получает зов вместо блока и ждёт, что блок придёт иначе; нет
        // второго пути — нет и ленивых, иначе `IHAVE` означал бы «подожди
        // `T_graft` и попроси ещё раз», то есть задержку и лишний круг
        // вместо экономии (§7.5.2: «ноль сидов — это звезда, и она обязана
        // работать как состояние, а не как деградация»).
        //
        // **Ответ у владельца и у остальных разный, и это стоило живого
        // прогона.** У владельца второй путь для его читателя — это сид,
        // и если сидов нет, ленивых быть не должно. У всех остальных
        // второй путь есть **всегда**: первый — сам владелец, который
        // шлёт своим читателям и без нас, а мы и есть второй.
        //
        // Сид же смотрел в каталог, видел там только себя, решал «роя нет»
        // и возвращал в eager всех, кого только что подрезали `PRUNE`.
        // Снаружи: каждое слово стоило восьми блоков вместо пяти, читатели
        // слали подрезку при каждом слове, а дерево отрастало заново.
        // Поймано шестью узлами поверх живого меша; проверка —
        // `a_prune_at_a_seed_holds_and_the_second_word_costs_less`.
        let me = self.identity.public().ik;
        let i_am_the_source = self.channel_owner(chat).is_some_and(|owner| owner == me);
        let swarm_alive = if i_am_the_source {
            self.seeds(chat, now_ms)?.iter().any(|seed| seed.ik != me)
        } else {
            true
        };
        let tree = self.tree.entry(chat).or_default();
        // Ушедшие забываются: состав меняется, привязки истекают вместе
        // с сессией, и дерево не вправе помнить того, кому слать нечем.
        tree.eager.retain(|ik| candidates.contains(ik));
        tree.lazy.retain(|ik| candidates.contains(ik));
        for peer in &candidates {
            if tree.eager.contains(peer) || tree.lazy.contains(peer) {
                continue;
            }
            if !swarm_alive || tree.eager.len() < K_EAGER {
                tree.eager.insert(*peer);
            } else {
                tree.lazy.insert(*peer);
            }
        }
        // **Появился рой — лишние eager уходят в ленивые.** Без этой
        // строки дерево, выросшее звездой, звездой бы и осталось: новые
        // кандидаты делились бы по `k_eager`, а прежние сидели бы
        // в eager навсегда. Переход «звезда → рой» §7.5.2 обещает без
        // отдельного режима — вот он.
        //
        // Кого именно понизить, решает порядок ключа: прогон обязан
        // воспроизводиться по сиду (§16).
        if swarm_alive && tree.eager.len() > K_EAGER {
            let extra: Vec<[u8; 32]> = tree.eager.iter().skip(K_EAGER).copied().collect();
            for peer in extra {
                tree.eager.remove(&peer);
                tree.lazy.insert(peer);
            }
        }
        // Роя не стало — все обратно в eager: переход «рой → звезда»
        // проходит без отдельного режима (§7.5.2), и ленивый, оставшийся
        // ленивым после ухода последнего сида, замолчал бы навсегда.
        if !swarm_alive && !tree.lazy.is_empty() {
            let waiting: Vec<[u8; 32]> = tree.lazy.iter().copied().collect();
            for peer in waiting {
                tree.lazy.remove(&peer);
                tree.eager.insert(peer);
            }
        }
        if tree.eager.is_empty() {
            if let Some(first) = tree.lazy.iter().next().copied() {
                tree.lazy.remove(&first);
                tree.eager.insert(first);
            }
        }
        // **Ступень решает форму раздачи** (§8.4): почта и реле «всегда
        // eager, никогда lazy», эфир — «только eager, только хвост».
        // Ленивый на такой ступени получает зов, а завести по нему срок
        // ему нечем (`graft_wait_ms` — `None`), и блока он попросит
        // только анти-энтропией, часы спустя. Снаружи это не «позже»,
        // а «не дошло».
        //
        // Считается **последним**: до этого дерево делится по §7.1,
        // и вмешиваться в ту арифметику незачем — здесь только перенос
        // тех, кому ленивым быть нечем.
        let lazy_now: Vec<[u8; 32]> = tree.lazy.iter().copied().collect();
        let mut forced = Vec::new();
        for peer in lazy_now {
            let lazy_works = self.rung_to(&peer).is_some_and(swarm::may_be_lazy);
            if !lazy_works {
                forced.push(peer);
            }
        }
        let tree = self.tree.entry(chat).or_default();
        for peer in forced {
            tree.lazy.remove(&peer);
            tree.eager.insert(peer);
        }
        Ok((tree.eager.iter().copied().collect(), tree.lazy.iter().copied().collect()))
    }

    /// Кладёт блок в пакет, если ступень до пира асинхронная (§8.4).
    ///
    /// Отдаёт `true`, если блок уехал пакетом: вызывающему остаётся
    /// не слать его ещё и по одному.
    ///
    /// # Почему пакет, а не отдельные кадры
    ///
    /// §8.4: «Асинхронные ступени не бывают lazy… Им шлётся пакет
    /// блоков за окно с избыточностью». На почте и реле ответа
    /// не обещают, `GRAFT` там не зовут вовсе, и потерянный блок ждал бы
    /// анти-энтропии — то есть следующего обхода. Пакет везёт новый блок
    /// вместе с парой предыдущих из архива: одно письмо вместо трёх
    /// и втрое больший шанс, что пропущенное приедет само.
    ///
    /// Повторы съедает дедупликация §9.2 — та же, что у всякого кадра,
    /// и ничего нового для них заводить не пришлось.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки кадра.
    fn send_bundled(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        peer: [u8; 32],
        bytes: &[u8],
    ) -> Result<Option<Vec<Effect>>, EngineError> {
        // Пакет — только там, где нет обратной связи. У быстрых ступеней
        // потерянное чинит `GRAFT` за секунды, и возить втрое больше
        // ради этого незачем.
        if self.rung_to(&peer).is_some_and(swarm::may_be_lazy) {
            return Ok(None);
        }
        if !matches!(self.rung_to(&peer), Some(Transport::Mail | Transport::Nostr)) {
            // Эфиру пакет противопоказан отдельно: §8.4 оставляет ему
            // «только хвост», а класс S там мал.
            return Ok(None);
        }
        let mut blocks = vec![bytes.to_vec()];
        let mut total = bytes.len();
        // Избыточность — **предыдущие** блоки этого же канала, самые
        // свежие. Берутся из архива: он и есть окно (§9.3).
        for older in self.store.archive_recent(&chat, swarm::BUNDLE_BLOCKS)? {
            if blocks.len() >= swarm::BUNDLE_BLOCKS {
                break;
            }
            if older.msg_id == msg_id {
                continue;
            }
            if total.saturating_add(older.frame.len()) > swarm::BUNDLE_BYTES {
                break;
            }
            total += older.frame.len();
            blocks.push(older.frame);
        }
        if blocks.len() == 1 {
            // Везти нечего, кроме самого блока: пакет из одного кадра —
            // это тот же кадр, только в обёртке.
            return Ok(None);
        }
        let (_, sent) = self.enqueue_request(
            now_ms,
            peer,
            PayloadType::SwarmBundle,
            swarm::bundle_value(&blocks),
        )?;
        Ok(Some(sent))
    }

    /// Раздаёт блок по дереву: целиком eager, зовом — lazy (§7.1).
    ///
    /// `from` — тот, кто блок принёс; ему не возвращают ничего, иначе
    /// получилось бы кольцо из двух узлов.
    ///
    /// # Errors
    ///
    /// Отказ хранилища на постановке в очередь.
    /// Развозит **документ** канала: каждому, а не деревом (§7.1).
    ///
    /// # Почему не деревом
    ///
    /// Дерево §7.1 бережёт полосу тем, что ленивому уходит зов, а блок
    /// он берёт у соседа. С документом так не выходит: сосед его
    /// **не пересылает** — документы канала развозит владелец, и курьера
    /// у них нет (`on_group_action`). Ленивый дожидался бы `T_graft`,
    /// звал `GRAFT`, владелец возвращал бы его в eager — и дерево,
    /// сжатое роем, разворачивалось бы обратно в звезду на каждом
    /// документе. Поймано проверкой
    /// `when_the_last_seed_leaves_the_tree_becomes_a_star_again`.
    ///
    /// # Но и не веером по составу
    ///
    /// Веер стоял здесь с очереди 2, когда роя ещё не было, и пережил
    /// его появление вместе с дырой: **у открытого канала состава нет
    /// вовсе** (§10.4), и веер означал там «никому». Живой прогон
    /// описал это так: «в открытом канале трое, двое были друг у друга
    /// в контактах — между ними ходило, третий не получал ничего;
    /// удалил контакты — перестало ходить вовсе». Держалось всё
    /// на личном знакомстве: без выдачи из документа слово проверить
    /// нечем, и единственным ключом оставалась карточка контакта.
    ///
    /// Получатели поэтому — `push_candidates`: состав **и** привязанные.
    /// У канала по приглашению это не меньше прежнего, у открытого —
    /// впервые хоть кто-то.
    ///
    /// # И в архив
    ///
    /// Документ ложится в архив, как всякий блок канала: подписчик,
    /// спавший в этот час, возьмёт его анти-энтропией (§7.2) вместо
    /// того, чтобы не узнать о выдаче никогда. Это и есть первый шаг
    /// порядка §7.4 — «представление и `PeerRecord`».
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn push_document(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // В группе документов канала не бывает, но этим же путём едут
        // название и картинка: там состав и есть список получателей.
        if self.groups.get(&chat).is_none_or(|state| state.profile.everyone_writes()) {
            return self.fan_out_group(now_ms, chat, msg_id, bytes);
        }
        self.archive_channel_frame(now_ms, chat, msg_id, bytes)?;
        let mut effects = Vec::new();
        for peer in self.push_candidates(chat, true)? {
            // Отказ по одному не обрывает раздачу остальным — тот же
            // довод, что у веера и у дерева.
            match self.send_group_copy(now_ms, msg_id, peer, bytes) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::warn!(?error, "копия документа не поставилась"),
            }
        }
        Ok(effects)
    }

    pub(super) fn push_block(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        from: Option<[u8; 32]>,
        msg_id: MsgId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Блок кладётся в архив **до** раздачи: на `GRAFT` и на просьбу
        // §7.2 отвечает он, и ответить надо будет тому, кто сейчас
        // получит зов.
        self.archive_channel_frame(now_ms, chat, msg_id, bytes)?;
        // Принёсший ответил делом: счёт неудач ему обнуляется, и он
        // становится «отвечавшим недавно» (§7.7).
        if let Some(from) = from {
            self.note_swarm_answer(now_ms, from);
        }

        let (eager, lazy) = self.split_tree(now_ms, chat, from.is_none())?;
        let mut effects = Vec::new();
        for peer in eager {
            if from == Some(peer) {
                continue;
            }
            // **Асинхронной ступени — пакетом** (§8.4). Не вышло — едем
            // как ехали, по одному.
            match self.send_bundled(now_ms, chat, msg_id, peer, bytes) {
                Ok(Some(sent)) => {
                    effects.extend(sent);
                    continue;
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(?error, "пакет блоков не собрался"),
            }
            match self.send_group_copy(now_ms, msg_id, peer, bytes) {
                Ok(produced) => effects.extend(produced),
                // Отказ по одному не обрывает раздачу остальным — тот же
                // довод, что у веера: получателей много, и неудача с одним
                // ничего не говорит про других.
                Err(error) => tracing::warn!(?error, "копия eager-пиру не поставилась"),
            }
        }
        for peer in lazy {
            if from == Some(peer) {
                continue;
            }
            let call = swarm::Control::IHave { group: chat, block: msg_id };
            match self.send_swarm_control(now_ms, peer, &call) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::warn!(?error, "зов lazy-пиру не поставился"),
            }
        }
        Ok(effects)
    }

    /// Ставит в очередь §5.4 один кадр дерева (§7.1).
    ///
    /// Молчаливый: квитанции у него нет. Подтверждение `IHAVE` — это
    /// `GRAFT`, подтверждение `GRAFT` — сам блок; лишняя квитанция
    /// удваивала бы трафик механизма, заведённого ради его сокращения.
    pub(super) fn send_swarm_control(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        control: &swarm::Control,
    ) -> Result<Vec<Effect>, EngineError> {
        let (_, effects) =
            self.enqueue_request(now_ms, peer_ik, PayloadType::SwarmControl, control.value())?;
        Ok(effects)
    }

    /// Кладёт кадр канала в архив — то, чем отвечают на просьбу (§7.2, §9.3).
    ///
    /// # Почему на диск, а не в память
    ///
    /// Здесь сперва стоял хвост в памяти: продержать блок на время
    /// `T_graft` — секунды. Этого хватало дереву и не хватает
    /// анти-энтропии: она чинит **долгое** отсутствие, а «долгое»
    /// переживает перезапуск по определению. Окно у архива есть
    /// (§9.3, `seed_days` и `seed_bytes` из подписанного представления),
    /// и обрезает его обход.
    ///
    /// # Номер берётся из подписанного блока
    ///
    /// §7.3 держится на непрерывности номера у автора, и брать его
    /// из конверта нельзя: конверт подписью не покрыт. Позиция цепочки
    /// лежит **внутри** блока, там же, где подпись.
    ///
    /// # В архив идут **все** кадры канала, а не только слова
    ///
    /// §7.3 обещает, что «`seq` непрерывен у автора: узел, имеющий 46
    /// и 48, **знает**, что 47 существует». Цепочка отправителя (§11.1)
    /// одна на слова и на действия — представление, ключ чтения, запись
    /// о впуске тоже занимают позиции. Клади мы в архив одни слова,
    /// каждая правка документа выглядела бы дырой, и §7.3 врал бы
    /// при каждом впуске. Поймано первой же проверкой архива: номер
    /// первого слова оказался шестым, а не нулевым.
    ///
    /// Не разобрался блок — не кладём: в архив идёт то, что мы приняли
    /// и проверили, а не всё, что приехало.
    pub(super) fn archive_channel_frame(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        bytes: &[u8],
    ) -> Result<(), EngineError> {
        let Ok(envelope) = Envelope::decode(bytes) else { return Ok(()) };
        let envelope = envelope.into_parts().1;
        let Ok(unchecked) = ratatosk_proto::group::parse_message(&envelope.payload) else {
            return Ok(());
        };
        self.store.put_archived(
            &chat,
            &ratatosk_store::ArchivedBlock {
                author_ik: *unchecked.claims_sender(),
                seq: unchecked.claims_counter(),
                msg_id,
                frame: bytes.to_vec(),
                received_ms: now_ms,
            },
        )?;
        Ok(())
    }

    /// Обрезает архивы каналов по их окнам (§9.3).
    ///
    /// Окно берётся из **подписанного представления**: §9.3 говорит прямо
    /// — «для канала окно не технический параметр, оно определяет, что
    /// означает „всё“ в глубине истории, значит лежит в подписанном
    /// представлении». Документа нет — окно неизвестно, и обрезать нечем:
    /// выдуманное значение стёрло бы то, что владелец обещал хранить.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn prune_archives(&mut self, now_ms: u64) -> Result<(), EngineError> {
        let channels: Vec<ChatId> = self
            .groups
            .iter()
            .filter(|(_, state)| !state.profile.everyone_writes())
            .map(|(chat, _)| *chat)
            .collect();
        for chat in channels {
            let Some(stored) = self.store.channel(&chat)? else { continue };
            let gone =
                self.store.prune_archive(&chat, stored.seed_days, stored.seed_bytes, now_ms)?;
            if gone > 0 {
                tracing::debug!(канал = ?chat, убрано = gone, "архив канала обрезан окном");
            }
        }
        Ok(())
    }

    /// Пришёл кадр дерева: `IHAVE`, `GRAFT` или `PRUNE` (§7.1).
    pub(super) fn on_swarm_control(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Ok(control) = swarm::Control::from_value(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        let chat = *control.group();
        // Канала не знаем — дерева по нему у нас нет. Молча: кадр
        // не по адресу, и рассказывать о нём нечего.
        let Some(state) = self.groups.get(&chat) else { return Ok(Vec::new()) };
        if state.profile.everyone_writes() {
            return Ok(Vec::new());
        }

        match control {
            swarm::Control::IHave { block, .. } => {
                // **Затопление зовами** (§7.7): счётчик на пира, перевод
                // в lazy и остывание. Зов стоит метки времени и строки
                // в памяти, а блоков в минуту в канале единицы — сотня
                // зовов от одного пира это не лента, а попытка занять нас
                // собой.
                if self.cooling(now_ms, &peer_ik) {
                    return Ok(Vec::new());
                }
                // **Пустой зов** — о блоке, который у нас уже есть, либо
                // о том, которого мы и так ждём. Честному сиду такое
                // случается, а затопление из них и состоит.
                // **Зов о том, что у нас уже есть, — не затопление.**
                // Так выглядит обычная работа дерева: блок пришёл
                // от владельца раньше, чем зов от сида. Лишнее ребро
                // подрезает `PRUNE` — по лишнему **блоку**, а не по зову.
                // Первая редакция считала и такие, и остужала честного
                // сида за занятую ленту: проверка покраснела на семидесяти
                // словах подряд.
                let known = self.store.seen(&block)?;
                // **Повтор — это его же зов о том же блоке.** Зов другого
                // пира о блоке, которого мы уже ждём, — не затопление,
                // а обычная работа дерева: у блока в рое два источника,
                // владелец и сид, и второй зовёт просто потому, что первым
                // не был. Считай мы и такие, честный сид остывал бы на
                // ленте из семидесяти слов подряд — ровно на этом
                // проверка про него и покраснела.
                let repeat = self
                    .awaited_blocks
                    .get(&(chat, block))
                    .is_some_and(|awaited| awaited.who == peer_ik);
                let already = self.awaited_blocks.contains_key(&(chat, block));
                let outstanding =
                    self.awaited_blocks.values().filter(|awaited| awaited.who == peer_ik).count();
                if known {
                    return Ok(Vec::new());
                }
                // Сверх предела памяти зов просто не берётся: остывание
                // за всплеск не ставится, потому что всплеск бывает
                // и у честного (см. `OUTSTANDING_CALLS`).
                if outstanding >= swarm::OUTSTANDING_CALLS {
                    return Ok(Vec::new());
                }
                if already {
                    if !repeat {
                        return Ok(Vec::new());
                    }
                    let budget = self.budget_of(now_ms, peer_ik);
                    budget.ihave = budget.ihave.saturating_add(1);
                    if budget.ihave > swarm::EMPTY_CALLS_PER_WINDOW {
                        // Сперва в ленивые — чтобы мы сами перестали слать
                        // ему целиком, — и только потом остывание: §7.7
                        // называет оба, и порядок здесь тот же.
                        let tree = self.tree.entry(chat).or_default();
                        tree.eager.remove(&peer_ik);
                        tree.lazy.insert(peer_ik);
                        self.cool_down(now_ms, peer_ik, "затопил пустыми зовами");
                    }
                    return Ok(Vec::new());
                }
                // Ни `PRUNE`, ни отметки: `PRUNE` подрезает ребро,
                // по которому приходит **лишний блок**, а не лишний зов, —
                // иначе мы отрезали бы ленивых за то, ради чего они
                // и существуют.
                // Срок берётся у ступени, которой приехал зов (§7.7).
                // У почты и реле его нет вовсе — там `GRAFT` значил бы
                // «попроси ещё раз то, что и так в пути».
                let Some(wait) = swarm::graft_wait_ms(via) else { return Ok(Vec::new()) };
                let token = self.allocate_timer();
                let awaited = Awaited { who: peer_ik, wait_ms: wait, asked: false };
                self.awaited_blocks.insert((chat, block), awaited);
                self.graft_timers.insert(token, (chat, block));
                Ok(vec![Effect::SetTimer { after_ms: wait, token }])
            }
            swarm::Control::Graft { block, .. } => {
                // **Право на обслуживание** (§8.3) — до починки дерева:
                // не отдавая блоков, объявлять кого-то своим eager-пиром
                // значит завести ребро, по которому ничего не поедет.
                if !self.may_serve(chat, &peer_ik)? {
                    return Ok(Vec::new());
                }
                // Просят блок — значит просят и стать eager: §7.1 велит
                // чинить дерево там, где оно порвалось.
                let tree = self.tree.entry(chat).or_default();
                tree.lazy.remove(&peer_ik);
                tree.eager.insert(peer_ik);
                let Some(block) = self.store.archived(&chat, &block)? else {
                    // Блока в архиве нет: он старше окна сидирования
                    // (§9.3) либо мы его никогда не видели. Молчим —
                    // чинить это дерево не умеет, и §7.2 не зря отдаёт
                    // историю анти-энтропии.
                    return Ok(Vec::new());
                };
                let (block, bytes) = (block.msg_id, block.frame);
                self.send_group_copy(now_ms, block, peer_ik, &bytes)
            }
            swarm::Control::Have { ranges, .. } => self.on_have(now_ms, chat, peer_ik, &ranges),
            swarm::Control::Want { author, from_seq, to_seq, .. } => {
                self.on_want(now_ms, chat, peer_ik, &author, from_seq, to_seq)
            }
            swarm::Control::Prune { .. } => {
                // Ребро подрезано: лишние отмирают, дерево возникает само
                // (§7.1, шаг 3).
                let tree = self.tree.entry(chat).or_default();
                tree.eager.remove(&peer_ik);
                tree.lazy.insert(peer_ik);
                Ok(Vec::new())
            }
        }
    }

    /// Говорит пиру, что у нас есть, — have-вектор (§7.2).
    ///
    /// Шлётся при установлении связи: §7.2 так и велит — «при
    /// установлении соединения — обмен have-векторами». У нас связь
    /// с роевым пиром начинается привязкой (§7.5.1), и вектор едет
    /// следом за ней.
    ///
    /// Вектор ключуется **по автору**, а авторов в канале единицы
    /// (§7.5.2): при одном публикаторе это одна строка, хоть при десяти
    /// тысячах читателей. Поэтому его не жалко слать на каждую связь.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn send_have(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let ranges: Vec<swarm::Range> = self
            .store
            .archive_have(&chat)?
            .into_iter()
            .take(swarm::MAX_HAVE_RANGES)
            .map(|range| swarm::Range {
                author: range.author_ik,
                first_seq: range.first_seq,
                last_seq: range.last_seq,
            })
            .collect();
        // Пустой вектор — не повод молчать: «у меня нет ничего» это
        // ответ, по которому собеседник поймёт, что спрашивать у нас
        // нечего, а сам он нам нужен.
        let tell = swarm::Control::Have { group: chat, ranges };
        self.send_swarm_control(now_ms, peer_ik, &tell)
    }

    /// Пришёл чужой have-вектор: просим то, чего нет у нас (§7.2).
    ///
    /// # Спрашивается диапазон, а не номер
    ///
    /// У читателя в журнале законные дыры: позиции адресных блоков —
    /// ключ чтения впущенному, запись о впуске владельцу, — которые
    /// до него не доезжали (`phase2-plan.md`, расхождение 13). Попроси
    /// он «дай сорок седьмой», ответом было бы молчание, неотличимое
    /// от потери.
    ///
    /// # Спрашивается пропуск, а не только хвост
    ///
    /// §7.3: «узел, имеющий 46 и 48, **знает**, что 47 существует».
    /// Первая редакция просила лишь то, что новее нашего последнего, —
    /// и провал посередине не чинился никогда: читатель, пропавший
    /// на сорок номеров, объявлял их своими (`MIN..MAX` в векторе)
    /// и потому не просил. Теперь вектор честен, а разница считается
    /// [`swarm::gaps`].
    ///
    /// **Пропуск спрашивается раньше хвоста** — §7.3, «настойчивее
    /// хвоста». Хвост придёт и деревом: он живой, и за ним идёт
    /// раздача. За пропуском не идёт ничего.
    ///
    /// # Ниже границы открываемого не спрашиваем
    ///
    /// §7.4: «вступление не оплачивает историю, которую никто не
    /// открыл». У нас эта граница не выбор, а факт: сказанное до выдачи
    /// цепочки (§11.5) не откроется никогда, сколько его ни вези.
    /// Спрашивать такое — тратить полосу на кадры, которые молча
    /// исчезнут, и обещать человеку историю, которой он не увидит.
    fn on_have(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        ranges: &[swarm::Range],
    ) -> Result<Vec<Effect>, EngineError> {
        let mine = self.store.archive_have(&chat)?;
        // Дыры, а не просьбы: сперва собираются все, потом отбираются
        // самые нужные. Иначе порядок просьб зависел бы от порядка строк
        // в чужом векторе, то есть от чужой прихоти.
        let mut holes: Vec<(ActorId, u64, u64)> = Vec::new();
        // **Есть ли куда листать дальше.** Считается по границе, а не
        // по дырам: дыры у читателя есть всегда — адресные блоки чужих
        // (ключ чтения впущенному, запись о впуске) до него не доезжают
        // и не доедут. Считай мы «дальше некуда» по пустому списку дыр,
        // этого «некуда» не наступило бы никогда.
        let mut deeper_left = false;
        for range in ranges.iter().take(swarm::MAX_HAVE_RANGES) {
            let floor = self.openable_from(chat, &range.author, range)?;
            if floor > range.first_seq {
                deeper_left = true;
            }
            let from = range.first_seq.max(floor);
            let ours: Vec<(u64, u64)> = mine
                .iter()
                .filter(|row| row.author_ik == range.author)
                .map(|row| (row.first_seq, row.last_seq))
                .collect();
            for (first, last) in swarm::gaps((from, range.last_seq), &ours) {
                holes.push((range.author, first, last));
            }
        }
        // Порядок просьб: сперва то, за чем не идёт раздача. Хвост —
        // это то, что новее последнего нашего у этого автора; всё
        // остальное пропуск, и §7.3 велит спрашивать его настойчивее.
        holes.sort_by_key(|(author, first, _)| {
            let tail = mine
                .iter()
                .filter(|row| row.author_ik == *author)
                .map(|row| row.last_seq)
                .max()
                .is_some_and(|last| *first > last);
            (tail, *first)
        });
        // **Просьба обязана знать, по какой ступени уедет** (§8.4) —
        // и не просить архив там, где он не доедет. Эфир его не возит:
        // 9–12 КБ/с, и мебибайт — полторы минуты. Живая лента при этом
        // по нему ходит: §8.4 оставляет эфиру хвост, а не историю.
        if !self.rung_to(&peer_ik).is_some_and(swarm::carries_archive) {
            return Ok(Vec::new());
        }
        let mut effects = Vec::new();
        // **Прокрутка вверх — одно движение, одна страница** (§7.4,
        // шаг 3). Метка гаснет здесь: вектор пришёл, глубина посчитана,
        // и держать её дальше значило бы тянуть прошлое каждым обменом.
        //
        // Нечего просить — говорим «дальше некуда». Молчание на этом
        // месте клиенту неотличимо от «ещё едет», и полоска загрузки
        // висела бы вечно (§14).
        if self.history_pull.remove(&chat) && !deeper_left {
            effects.push(Effect::Notify(Event::ChannelHistoryEnd { chat }));
        }
        for (author, from_seq, to_seq) in holes.into_iter().take(swarm::MAX_WANTS_PER_ROUND) {
            let ask = swarm::Control::Want { group: chat, author, from_seq, to_seq };
            effects.extend(self.send_swarm_control(now_ms, peer_ik, &ask)?);
        }
        Ok(effects)
    }

    /// С какого номера этого автора нам вообще есть смысл просить (§7.3).
    ///
    /// Граница — самый старый ключ, который у нас ещё есть: кэш пропусков
    /// или позиция, с которой цепочку выдали (§11.5). Ниже неё блок
    /// приедет и молча исчезнет — открыть его нечем и не будет чем.
    ///
    /// Цепочки нет вовсе — просим с нуля: она едет отдельным кадром
    /// (§11.5) и может приехать позже, а до тех пор блок ложится
    /// в отложенные, а не пропадает.
    fn openable_from(
        &self,
        chat: ChatId,
        author: &ActorId,
        theirs: &swarm::Range,
    ) -> Result<u64, EngineError> {
        // **В канале граница не крипто, а политика** (§7.4): содержимое
        // открывается ключом чтения (§6.1, §10.4), и прочесть мы можем
        // всё, что нам отдадут. Значит вопрос не «что откроем», а «что
        // просим», и §7.4 отвечает: «вступление не оплачивает историю,
        // которую никто не открыл».
        //
        // Ниже нашего начала не просим; нет ничего вовсе — не просим
        // ничего, кроме живого хвоста, который приедет сам. Прокрутка
        // вверх (§7.4, шаг 3) сдвинет эту границу, когда появится, —
        // и это единственное, чего ей будет не хватать.
        if self.groups.get(&chat).is_some_and(|state| !state.profile.everyone_writes()) {
            let ours = self
                .store
                .archive_have(&chat)?
                .into_iter()
                .filter(|row| row.author_ik == *author)
                .map(|row| row.first_seq)
                .min();
            // **Ниже нашего начала не просим** — §7.4: «вступление
            // не оплачивает историю, которую никто не открыл». Нет
            // ничего вовсе — не просим ничего: лента начинается
            // с первого живого слова.
            //
            // Страницу «последних N блоков» (§7.4, шаг 2) я пробовал
            // тянуть обходом — и снял: новичок тянет её у всех сразу,
            // дубли подрезают рёбра, дерево перестаёт сходиться, а цена
            // вступления растёт вдвое.
            //
            // **Просит её человек** (§7.4, шаг 3): пока метка прокрутки
            // стоит, граница опускается на страницу — и ровно на одну.
            let floor = ours.unwrap_or_else(|| theirs.last_seq.saturating_add(1));
            if self.history_pull.contains(&chat) {
                return Ok(floor.saturating_sub(swarm::HISTORY_PAGE).max(theirs.first_seq));
            }
            return Ok(floor);
        }
        // В группе граница — крипто: ниже самого старого ключа не открыть
        // ничего и никогда (§11.5).
        let Some(stored) = self.store.sender_chain(&chat, author)? else { return Ok(0) };
        Ok(Self::inbox_of(&stored).oldest_openable())
    }

    /// Пришла просьба: отдаём кадры из архива (§7.2).
    ///
    /// # Право не спрашивается, и это §7.6
    ///
    /// «Любой, у кого есть идентификатор канала, вправе вытянуть
    /// шифротекст; прочесть — нет». Сид состава не знает и проверить
    /// право не может в принципе; защищаться надо не от чужих,
    /// а от избыточных — отсюда предел в [`swarm::MAX_WANT_BLOCKS`]
    /// блоков на просьбу (§7.2, §7.7).
    ///
    /// Ответ короче запрошенного законен: у нас могло не быть середины
    /// (адресные блоки чужих) или начала (окно сидирования, §9.3).
    fn on_want(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        author: &[u8; 32],
        from_seq: u64,
        to_seq: u64,
    ) -> Result<Vec<Effect>, EngineError> {
        // **Право на обслуживание** (§8.3): спрашивается наше участие
        // в раздаче, а не чужой состав — см. `may_serve`.
        if !self.may_serve(chat, &peer_ik)? {
            return Ok(Vec::new());
        }
        // **Эфир не возит архив** (§8.4) — и спрашивается это на обоих
        // концах. Просящий не просит того, что не доедет, отдающий
        // не отдаёт того, что не увезёт: у двоих в комнате без сети
        // ответ на просьбу об истории занял бы канал на минуты,
        // а живая лента встала бы за ним в очередь.
        if !self.rung_to(&peer_ik).is_some_and(swarm::carries_archive) {
            tracing::debug!(peer = ?&peer_ik[..4], "архив не отдаётся эфиром (§8.4)");
            return Ok(Vec::new());
        }
        // **Два предела, а не один** (§7.7 и §9.2). На пира — «бесконечное
        // вытягивание»: защищает от одного жадного. Общий — от десяти
        // вежливых: сервера нет, ограничителя частоты нет ни у кого,
        // кроме нас самих, и платит за отдачу человек — трафиком,
        // батареей, тарифом.
        //
        // Оба считаются **за окно**, а не на просьбу: предел на просьбу
        // обходится десятью просьбами подряд.
        let limits = self.giving_limits()?;
        let served_total = self.given_this_window(now_ms);
        let budget = self.budget_of(now_ms, peer_ik);
        let left = limits.left_for_peer(budget.served, served_total);
        if left == 0 {
            tracing::debug!(peer = ?&peer_ik[..4], "предел отдачи за окно исчерпан (§7.7, §9.2)");
            return Ok(Vec::new());
        }
        let width = usize::try_from(to_seq.saturating_sub(from_seq).saturating_add(1))
            .unwrap_or(swarm::MAX_WANT_BLOCKS);
        let limit = width.min(swarm::MAX_WANT_BLOCKS).min(left as usize);
        let blocks = self.store.archived_range(&chat, author, from_seq, limit)?;
        let mut effects = Vec::new();
        let mut given = 0u32;
        for block in blocks {
            if block.seq > to_seq {
                break;
            }
            effects.extend(self.send_group_copy(now_ms, block.msg_id, peer_ik, &block.frame)?);
            given = given.saturating_add(1);
        }
        let budget = self.budget_of(now_ms, peer_ik);
        budget.served = budget.served.saturating_add(given);
        self.swarm_given.1 = self.swarm_given.1.saturating_add(given);
        Ok(effects)
    }

    /// Сколько отдано **всем вместе** за нынешнее окно (§9.2).
    ///
    /// Окно то же, что у счёта на пира: разойдись они, «за минуту»
    /// означало бы две разные минуты, и читать счёт вместе с пределом
    /// стало бы нельзя.
    fn given_this_window(&mut self, now_ms: u64) -> u32 {
        if now_ms.saturating_sub(self.swarm_given.0) >= swarm::BUDGET_WINDOW_MS {
            self.swarm_given = (now_ms, 0);
        }
        self.swarm_given.1
    }

    /// Пределы отдачи — с диска, а нет строки — умолчания крейта (§9.2).
    ///
    /// §9.2 велит держать числа **на диске**: «сервера нет, значит
    /// ограничителя частоты нет ни у кого, кроме нас самих». Настройка,
    /// не пережившая перезапуск, ограничивает ровно до первого
    /// перезапуска.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub fn giving_limits(&self) -> Result<swarm::GivingLimits, EngineError> {
        let Some(bytes) = self.store.meta(ratatosk_store::META_GIVING_LIMITS)? else {
            return Ok(swarm::GivingLimits::default());
        };
        // Не те байты — умолчание, а не ноль: запись из будущей сборки
        // не должна выключать раздачу сегодняшней.
        Ok(swarm::GivingLimits::from_bytes(&bytes).unwrap_or_default())
    }

    /// Тянет историю канала глубже — «прокрутка вверх» (§7.4, шаг 3).
    ///
    /// # Как это устроено
    ///
    /// Просьба помечает канал и заново называется тем, у кого мы
    /// спрашиваем блоки (§7.5.1): в ответ приедет их have-вектор,
    /// а по нему — уже с опущенной границей — посчитается, чего нам
    /// не хватает. Своей дороги у прокрутки нет и не нужно: она
    /// пользуется тем же обменом §7.2, только просит глубже.
    ///
    /// # Одна просьба — одна страница
    ///
    /// Метка гаснет на ближайшем обмене. Человек листает дальше —
    /// зовёт снова; это и есть «по требованию» из §7.4.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownGroup`] — канала нет;
    /// [`EngineError::NotAChannel`] — это группа: глубины у неё нет,
    /// история группы едет вступлением (§11.5).
    pub(super) fn on_pull_older_history(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        self.history_pull.insert(chat);
        let targets = self.attach_targets(now_ms, chat)?;
        let mut effects = Vec::new();
        for peer in targets {
            // **Отказ по одному адресату не обрывает остальных** — то же
            // правило, что у веера и у дерева. И не выходит наружу
            // отказом команды: «до этого не дотянуться» — состояние,
            // а не ошибка человека.
            //
            // Живой прогон описал цену этой разницы: «удалил все контакты,
            // связанные с каналом, — и запрос истории отвечает „контакт
            // неизвестен“». Записи пира к тому времени не было (её съело
            // повышение до контакта), дороги в канал не осталось вовсе —
            // и прокрутка вверх падала отказом вместо честного «дальше
            // некуда».
            match self.attach_one(now_ms, chat, peer) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::debug!(?error, "до сида не дотянуться"),
            }
        }
        // Спросить некого — говорим об этом сразу, а не молчим: у канала
        // без сидов и без владельца под рукой прокрутка просто не даст
        // ничего, и полоску загрузки надо убрать (§14).
        if effects.is_empty() {
            self.history_pull.remove(&chat);
            effects.push(Effect::Notify(Event::ChannelHistoryEnd { chat }));
        }
        Ok(effects)
    }

    /// Ставит пределы отдачи (§9.2). Ничего не уезжает по сети.
    ///
    /// # Ноль законен и означает «блоков не отдаём»
    ///
    /// Но выключать раздачу нулём не стоит, и это разные вещи:
    /// выключатель §7.5.1 гасит ещё и объявление, и привязки, а ноль
    /// останавливает только отдачу блоков. Клиенту сказано то же самое
    /// на границе.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn on_set_giving_limits(
        &mut self,
        limits: swarm::GivingLimits,
    ) -> Result<Vec<Effect>, EngineError> {
        self.store.put_meta(ratatosk_store::META_GIVING_LIMITS, &limits.to_bytes())?;
        Ok(Vec::new())
    }

    /// Сработал срок `T_graft`: блок так и не приехал (§7.1, шаг 4).
    ///
    /// Отдаёт `None`, если метка не наша, — у ядра один счётчик меток
    /// на всё, и чужую трогать нельзя.
    pub(super) fn on_graft_timer(
        &mut self,
        now_ms: u64,
        token: u64,
    ) -> Result<Option<Vec<Effect>>, EngineError> {
        let Some((chat, block)) = self.graft_timers.remove(&token) else { return Ok(None) };
        let Some(awaited) = self.awaited_blocks.remove(&(chat, block)) else {
            return Ok(Some(Vec::new()));
        };
        let who = awaited.who;
        // Приехал, пока ждали, — чинить нечего. **Но и в заслугу
        // звавшему это не идёт**: блок мог прийти любым путём, и чей
        // он был на самом деле, мы не знаем. Заслуга считается там, где
        // она видна, — по блоку, принятому из его рук (`push_block`).
        if self.store.seen(&block)? {
            return Ok(Some(Vec::new()));
        }
        if awaited.asked {
            // **Спросили и не получили** — счёт неудач растёт, и на втором
            // подряд он остывает (§7.7, «ложное have»). Звать его снова
            // значит тратить `T_graft` на заведомое молчание; блок придёт
            // анти-энтропией §7.2, когда он вернётся.
            self.note_swarm_miss(now_ms, who);
            return Ok(Some(Vec::new()));
        }
        if self.cooling(now_ms, &who) {
            return Ok(Some(Vec::new()));
        }
        // Зовущий становится eager: мы просим у него блок и хотим, чтобы
        // следующий он прислал целиком, не спрашивая.
        let tree = self.tree.entry(chat).or_default();
        tree.lazy.remove(&who);
        tree.eager.insert(who);
        // Второй срок — на ответ: по его исходу и считается вина.
        let token = self.allocate_timer();
        let wait = awaited.wait_ms;
        self.awaited_blocks.insert((chat, block), Awaited { asked: true, ..awaited });
        self.graft_timers.insert(token, (chat, block));
        let ask = swarm::Control::Graft { group: chat, block };
        let mut effects = self.send_swarm_control(now_ms, who, &ask)?;
        effects.push(Effect::SetTimer { after_ms: wait, token });
        Ok(Some(effects))
    }

    /// Блок приехал вторым путём: подрезать ребро (§7.1, шаг 3).
    ///
    /// Зовётся на **дубле** — том, что съела дедупликация §9.2. Дубль
    /// в дереве значит ровно одно: у нас два eager-родителя там, где
    /// хватит одного.
    pub(super) fn prune_duplicate_sender(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(Vec::new()) };
        if state.profile.everyone_writes() {
            return Ok(Vec::new());
        }
        // Владелец **не подрезается**: он источник, и отрезав его,
        // читатель остался бы со вторым путём вместо первого — то есть
        // зависел бы от сида, которого завтра может не быть.
        if self.channel_owner(chat) == Some(peer_ik) {
            return Ok(Vec::new());
        }
        // **Своё дерево здесь не трогается, и это не забывчивость.**
        // Дерево у нас **направленное**: в нём те, кому шлём мы. От кого
        // приходит нам — решает их дерево, и подрезать его может только
        // сам приславший. Поэтому единственное, что тут делается, —
        // говорится `PRUNE`.
        //
        // Здесь сперва стояло `if !tree.eager.remove(&peer_ik) { … }`,
        // и оно молча отменяло подрезку у всякого, кто сам никому
        // не раздаёт, — то есть у обычного читателя, ради которого дубль
        // и случается. Поймано проверкой, а не рассуждением.
        let cut = swarm::Control::Prune { group: chat };
        self.send_swarm_control(now_ms, peer_ik, &cut)
    }
}

/// Сколько eager-пиров держит узел. §7.1: 3–5.
///
/// Четыре — середина названного спекой промежутка. Больше значит
/// больше копий каждого блока, меньше — дольше чинить дерево после
/// обрыва: ленивому придётся дождаться срока и позвать `GRAFT`.
pub(super) const K_EAGER: usize = 4;

/// Что мы считаем за одним роевым пиром (§7.7).
///
/// **Пределы считаются на пира, а не на канал**, и так велит §7.7:
/// затопить нас можно зовами по одному каналу, а вредит это всем.
/// Окно скользит по времени; в памяти, а не на диске: после
/// перезапуска у всех чистый лист, и это честнее — состояние сети
/// за время сна всё равно поменялось.
#[derive(Debug, Default, Clone)]
pub(super) struct Budget {
    /// Когда началось нынешнее окно.
    pub(super) window_started_ms: u64,
    /// Сколько зовов `IHAVE` он прислал за окно.
    pub(super) ihave: u32,
    /// Сколько блоков мы ему отдали за окно.
    pub(super) served: u32,
    /// Сколько раз подряд он не ответил на просьбу.
    pub(super) misses: u32,
    /// До какого момента он остывает, мс. Ноль — не остывает.
    pub(super) cooled_until_ms: u64,
    /// Когда он в последний раз что-то нам отдал, мс.
    ///
    /// §7.7 велит «предпочитать отвечавшим недавно», и это то самое
    /// «недавно».
    pub(super) answered_ms: u64,
}

/// Ожидание блока, о котором позвали `IHAVE` (§7.1, шаг 4).
///
/// Двухступенчатое нарочно. Первый срок — «не приехало ли другим
/// путём»: в дереве блок обычно приходит от eager-родителя раньше,
/// чем зов от ленивого, и зов оказывается просто опоздавшим. По его
/// исходу мы **просим** (`GRAFT`), но вины ещё не считаем: звавшего
/// никто не спрашивал. Второй срок — уже про вину: спросили и не
/// получили, это и есть «ложное have» из §7.7.
///
/// Первая редакция считала вину на первом сроке и остужала честного
/// сида за то, что владелец быстрее.
#[derive(Debug, Clone)]
pub(super) struct Awaited {
    /// Кто позвал.
    pub(super) who: [u8; 32],
    /// Срок ступени, которой приехал зов, мс, — по нему заводится второй.
    pub(super) wait_ms: u64,
    /// Спросили ли уже: на первом сроке — нет, на втором — да.
    pub(super) asked: bool,
}

/// Дерево раздачи одного канала (§7.1).
#[derive(Debug, Default, Clone)]
pub(super) struct Tree {
    /// Кому блоки уходят целиком.
    pub(super) eager: BTreeSet<[u8; 32]>,
    /// Кому уходит только зов `IHAVE`.
    pub(super) lazy: BTreeSet<[u8; 32]>,
}

/// Сколько сидов держит читатель. §7.1: eager-пиров 3–5.
pub(super) const MAX_ATTACHED_SEEDS: usize = 4;

/// Сколько читателей держит сид.
///
/// Предел против избыточных (§9.2), а не против чужих: сид не знает
/// состава и отличить «лишнего» от «своего» не может. Число взято
/// с запасом — канал на сотню читателей и один сид упрутся не в него,
/// а в полосу.
pub(super) const MAX_ATTACHED_READERS: usize = 256;

/// Сутки в миллисекундах — запас на расхождение часов.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Ключ поля «канал» в кадре записи каталога.
const SWARM_KEY_GROUP: u8 = 1;
/// Ключ поля «подписанная запись».
const SWARM_KEY_RECORD: u8 = 2;

impl<S: Store> Engine<S> {
    /// Открывает окно пределов, если прежнее вышло (§7.7).
    fn budget_of(&mut self, now_ms: u64, peer_ik: [u8; 32]) -> &mut Budget {
        let budget = self.swarm_budget.entry(peer_ik).or_default();
        if now_ms.saturating_sub(budget.window_started_ms) >= swarm::BUDGET_WINDOW_MS {
            budget.window_started_ms = now_ms;
            budget.ihave = 0;
            budget.served = 0;
        }
        budget
    }

    /// Остывает ли этот пир сейчас (§7.7).
    ///
    /// Остывание — не наказание, а правило приоритета: у нас есть другие
    /// пиры, и звать того, кто дважды подряд не ответил, — значит
    /// тратить `T_graft` на заведомое молчание.
    pub(super) fn cooling(&self, now_ms: u64, peer_ik: &[u8; 32]) -> bool {
        self.swarm_budget.get(peer_ik).is_some_and(|b| b.cooled_until_ms > now_ms)
    }

    /// Ставит пира на остывание (§7.7).
    ///
    /// **Владельца канала не остужают никогда**, и это не поблажка:
    /// он источник. Остывший владелец означает читателя, отрезанного
    /// от живой ленты на четверть часа — при том что другого пути
    /// у канала может не быть вовсе (§7.5.2, «ноль сидов — это звезда»).
    /// Защищаться от него бессмысленно и по второй причине: канал —
    /// его, и «затопить» нас он может просто словами.
    fn cool_down(&mut self, now_ms: u64, peer_ik: [u8; 32], why: &'static str) {
        if self.groups.keys().copied().collect::<Vec<_>>().into_iter().any(|chat| {
            !self.groups[&chat].profile.everyone_writes()
                && self.channel_owner(chat) == Some(peer_ik)
        }) {
            return;
        }
        let budget = self.swarm_budget.entry(peer_ik).or_default();
        budget.cooled_until_ms = now_ms.saturating_add(swarm::COOLING_MS);
        budget.misses = 0;
        tracing::debug!(peer = ?&peer_ik[..4], why, "роевой пир остывает (§7.7)");
    }

    /// Он ответил: счёт неудач обнуляется, «недавно» сдвигается (§7.7).
    pub(super) fn note_swarm_answer(&mut self, now_ms: u64, peer_ik: [u8; 32]) {
        let budget = self.swarm_budget.entry(peer_ik).or_default();
        budget.misses = 0;
        budget.answered_ms = now_ms;
        // Ответивший перестаёт остывать досрочно: остывание говорит
        // «он молчит», а он только что ответил.
        budget.cooled_until_ms = 0;
    }

    /// Он не ответил на просьбу: счёт неудач растёт (§7.7, «ложное have»).
    ///
    /// **Послабления «он отвечал недавно» здесь нет, и это решение,
    /// а не упущение.** Сперва оно стояло: пир, только что отдавший нам
    /// блок, вины не получал. Но вина теперь считается на **втором**
    /// сроке, а два срока `T_graft` длиннее окна `BUDGET_WINDOW_MS`
    /// на всякой ступени, кроме локальной сети, — «ответил недавно»
    /// и «промолчал дважды» вместе не встречаются, и снятие послабления
    /// не роняло ни одной проверки. Оставлять правило, которого нечем
    /// прогнать, значит завтра считать его работающим.
    ///
    /// «Предпочитать отвечавшим недавно» из §7.7 держится другим местом
    /// и живо: ответ делом обнуляет счёт (`note_swarm_answer`), а порядок
    /// привязки сортируется по `answered_ms`.
    fn note_swarm_miss(&mut self, now_ms: u64, peer_ik: [u8; 32]) {
        let budget = self.swarm_budget.entry(peer_ik).or_default();
        budget.misses = budget.misses.saturating_add(1);
        if budget.misses >= swarm::MISSES_BEFORE_COOLING {
            self.cool_down(now_ms, peer_ik, "звал, а блока нет");
        }
    }

    /// Форма дерева раздачи: кому целиком, кому зовом (§7.1).
    ///
    /// Наружу — ради разбора. «Слово не дошло» в рое означает одно
    /// из трёх: не тот, кого считали eager; ленивый, которому некому
    /// прислать; подрезанное ребро. Различить их по журналу нельзя,
    /// а по форме дерева — можно.
    ///
    /// Границу UniFFI это не пересекает (§13.3): клиенту показывать
    /// дерево нечего.
    #[must_use]
    pub fn swarm_tree(&self, chat: ChatId) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
        self.tree.get(&chat).map_or_else(
            || (Vec::new(), Vec::new()),
            |tree| (tree.eager.iter().copied().collect(), tree.lazy.iter().copied().collect()),
        )
    }

    /// Остывает ли роевой пир сейчас (§7.7) — наружу, ради разбора.
    ///
    /// «Он молчит» и «мы его не спрашиваем» выглядят снаружи одинаково,
    /// и различить их иначе нечем. Границу UniFFI не пересекает (§13.3).
    #[must_use]
    pub fn swarm_cooling(&self, peer_ik: &[u8; 32], now_ms: u64) -> bool {
        self.cooling(now_ms, peer_ik)
    }
}

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
