//! Сообщения и действия внутри группы (§11.1, §11.3).
//!
//! Рассылка по кадру на участника, ключи отправителя, откладывание
//! кадра, пришедшего раньше состава, и групповые правки, отзывы,
//! реакции, ответы.
//!
//! Состав группы здесь не меняется — это `groups`; здесь только
//! то, что по составу рассылается.

use super::*;

/// Что осталось от группового кадра, когда его открыли: чат, автор
/// и содержимое. `Zeroizing` здесь не украшение — открытый текст обязан
/// стереться, когда его положили в базу.
type OpenedGroupFrame = (ChatId, ActorId, zeroize::Zeroizing<Vec<u8>>);

impl<S: Store> Engine<S> {
    /// Едет ли кадр такого типа копией каждому участнику группы (§11.3).
    ///
    /// Одно место на два следствия, и оба про одно и то же обещание.
    /// Такая копия не растит статус доставки и не получает квитанции:
    /// один значок на тридцать двух получателей §14 не разрешает.
    ///
    /// Список типов здесь **один**. Держи его в двух местах — и новый
    /// групповой тип завёлся бы в одном, а во втором про него забыли:
    /// отправитель получил бы квитанцию, которой не ждёт, а она нашла бы
    /// строку в истории и выставила ей статус, которого у неё быть
    /// не может. Ровно это и случилось бы с ответом в группе.
    pub(super) const fn is_group_copy(payload_type: PayloadType) -> bool {
        matches!(payload_type, PayloadType::GroupMessage | PayloadType::GroupAction)
    }

    /// Разбирает групповой кадр от контакта (§11.5).
    ///
    /// Четыре вида, и объединяет их одно: все они относятся к группе,
    /// которой у нас может ещё не быть. Кадр про неизвестную группу
    /// не отбрасывается, а откладывается — почта переставляет письма (§9.2),
    /// и порядок четырёх кадров вступления не обещан никем.
    ///
    /// # Квитанция обязательна, и её отсутствие стоило дороже всего
    ///
    /// Эти четыре кадра едут через `enqueue_request`, то есть **не**
    /// молчаливыми: молчаливы ровно копии группового сообщения (§11.3),
    /// и только они. А раз доставка не молчалива, у неё заведён срок,
    /// и §5.4 читает вышедший срок как «прямой канал не удался»
    /// (`Failure::Silent`).
    ///
    /// Квитанции же на них никто не слал — и вот что из этого выходило.
    /// Каждый кадр вступления доживал до срока, срок объявлял неудачу,
    /// неудача отправляла сессию на покой и начинала новое рукопожатие.
    /// Одно приглашение — дюжина таких кадров, дюжина покойных сессий;
    /// а в семействе живут ровно две (`SessionRegistry::insert`), и третья
    /// сносит первую **насовсем**. Кадры, запечатанные снесённой, приезжали
    /// к собеседнику как «сессия неизвестна» и молча пропадали (§7.3).
    /// Отсюда и потерянные объявления цепочек, и потерянные слова: снаружи
    /// это выглядело как «в группах доходит не всегда и не до всех».
    ///
    /// Правило здесь ровно то же, что у правки и реакции (`on_edit`,
    /// `on_reaction`), и записано там теми же словами: **запись в очереди
    /// §5.4 закрывается подтверждением, иначе страховочный срок объявит
    /// неудачу и пошлёт ту же просьбу ещё раз.** Четыре групповых кадра
    /// просто забыли, когда заводили.
    ///
    /// Квитанция отправляется и на кадр, который мы **отложили**: «доставлено»
    /// значит «принят и расшифрован», а что делать с ним дальше — наша
    /// забота, не отправителя. Ложью это станет только если отложенное
    /// вытеснится переполнением, и это названная цена очереди в 64 кадра.
    pub(super) fn on_group_frame(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — до разбора. Она про то, что кадр приехал и открылся,
        // а не про то, что он оказался применим: неразобранный кадр
        // отправитель обязан перестать слать точно так же, как разобранный.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Some(chat) = Self::group_of_payload(envelope.payload_type, &envelope.payload) else {
            // Нагрузка не той формы — обычный сетевой мусор (§7.3).
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };

        effects.extend(self.dispatch_group_frame(now_ms, peer_ik, chat, envelope.clone())?);
        // Отложенное разбирается после **любого** группового кадра, а не
        // только после представления: карточка участника может доехать
        // позже блока, который ею проверяется, и тогда блок становится
        // применимым не от появления группы, а от появления контакта.
        effects.extend(self.drain_pending_group(now_ms)?);
        Ok(effects)
    }

    /// Какой группы этот кадр — до всякой проверки.
    ///
    /// Нужно, чтобы отложить кадр, ещё не зная, что с ним делать. Для блока
    /// состава это `claims_group`: имя группы лежит внутри подписанного
    /// куска, и верить ему до проверки нельзя ни в чём, кроме поиска.
    pub(super) fn group_of_payload(kind: PayloadType, payload: &Value) -> Option<ChatId> {
        match kind {
            PayloadType::GroupIntro => group::intro_from_value(payload).ok().map(|i| i.group),
            PayloadType::GroupMessage => {
                group::parse_message(payload).ok().map(|m| *m.claims_group())
            }
            PayloadType::GroupRoster => group::roster_from_value(payload).ok().map(|r| r.group),
            PayloadType::SenderKey => group::sender_key_from_value(payload).ok().map(|k| k.group),
            PayloadType::GroupMembership => {
                group::parse_membership(payload).ok().map(|u| *u.claims_group())
            }
            _ => None,
        }
    }

    /// Раскладывает кадр по обработчикам либо откладывает его.
    pub(super) fn dispatch_group_frame(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        chat: ChatId,
        envelope: Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Представление заводит группу и потому обслуживается до проверки
        // «знаем ли мы её»: оно и есть ответ на этот вопрос.
        if envelope.payload_type == PayloadType::GroupIntro {
            return self.on_group_intro(now_ms, peer_ik, &envelope.payload);
        }
        if !self.groups.contains_key(&chat) {
            // **Канал, от которого отписались, не ждёт.** Владелец и сиды
            // слать блоки не перестанут (привязка у них в памяти, §7.5.1),
            // и каждый такой кадр занимал бы место в очереди отложенного
            // — у чата, которого не будет. Стенд показал два таких кадра
            // у ушедшего читателя после трёх слов владельца.
            if self.left_channels.contains(&chat) {
                return Ok(Vec::new());
            }
            self.park_group_frame(PendingGroup { chat, envelope, peer_ik });
            return Ok(Vec::new());
        }
        match envelope.payload_type {
            PayloadType::GroupMembership => {
                self.on_membership_block(now_ms, peer_ik, chat, &envelope)
            }
            PayloadType::GroupRoster => self.on_group_roster(now_ms, peer_ik, chat, &envelope),
            PayloadType::SenderKey => self.on_sender_key(peer_ik, chat, &envelope),
            // Сообщение и действие разбираются целиком: `msg_id` и метка
            // HLC лежат в конверте, и без них их некуда положить.
            PayloadType::GroupMessage => self.on_group_message(now_ms, peer_ik, &envelope),
            PayloadType::GroupAction => self.on_group_action(now_ms, peer_ik, &envelope),
            _ => Ok(Vec::new()),
        }
    }

    /// Откладывает кадр до появления группы.
    ///
    /// Переполнение выбрасывает **самый старый**: свежий кадр относится
    /// к тому, что происходит сейчас, а пролежавший дольше всех, скорее
    /// всего, относится к группе, в которую нас так и не позвали.
    ///
    /// Возраст здесь — это **место в очереди**, и времени прихода кадр
    /// не носит. Носил бы — у одного и того же возраста стало бы два
    /// представления, читаемых порознь, и разошлись бы они молча.
    ///
    /// # Отметка «видено» снимается, и это разбор живой поломки
    ///
    /// Окно §9.2 отмечает номер кадра **до** разбора (`on_data`), а разбор
    /// вправе отложить кадр сюда и потом вытеснить его переполнением.
    /// Вытесненный оставался «виденным» тридцать суток: анти-энтропия §7.2
    /// честно привозила его снова, окно выбрасывало как повтор — и слово
    /// пропадало навсегда, а курьеру за него уходил ещё и `PRUNE`.
    /// Стенд показал это числом: читатель, пропустивший поворот ключа,
    /// из семидесяти слов получал шестьдесят четыре — ровно длину очереди.
    ///
    /// Отметка возвращается при разборе (`drain_pending_group`): кадр,
    /// который применился, снова считается виденным, а тот, что снова
    /// отложился, снова забывается. Один и тот же кадр, приехавший
    /// вторым путём, пока лежит здесь, заменяет свою запись, а не встаёт
    /// рядом с ней.
    pub(super) fn park_group_frame(&mut self, frame: PendingGroup) {
        // Канал, от которого отписались, не ждёт (см. `dispatch_group_frame`):
        // сюда попадают и слова, открытые не там, а в `open_group_frame`.
        if self.left_channels.contains(&frame.chat) {
            return;
        }
        let msg_id = frame.envelope.msg_id;
        self.dedup.forget(&msg_id);
        if let Err(error) = self.store.forget_seen(&msg_id) {
            tracing::warn!(?error, "отметка «видено» у отложенного кадра не снялась");
        }
        self.pending_group.retain(|parked| parked.envelope.msg_id != msg_id);
        if self.pending_group.len() >= MAX_PENDING_GROUP {
            self.pending_group.remove(0);
        }
        self.pending_group.push(frame);
        self.persist_pending_group();
    }

    /// Кладёт очередь отложенного на диск — целиком.
    ///
    /// **Целиком, а не по одной записи.** Очередь короткая
    /// ([`MAX_PENDING_GROUP`]) и меняется редко, зато «добавить сюда,
    /// забыть удалить там» — ровно та ошибка, которой очередь на диске
    /// обрастает первой. Переписанная целиком, она не может разойтись
    /// с памятью в принципе.
    ///
    /// **Отказ хранилища сюда не поднимается.** Не записанная очередь —
    /// это потерянный при следующем перезапуске кадр, то есть ровно то,
    /// что было всегда; уронить из-за неё **шаг приёма** значило бы
    /// променять один отложенный кадр на все идущие. В журнал, впрочем,
    /// сказать надо: молча это выглядело бы как «починка не работает».
    pub(super) fn persist_pending_group(&mut self) {
        let rows: Vec<ratatosk_store::StoredPendingGroup> = self
            .pending_group
            .iter()
            .enumerate()
            .filter_map(|(place, frame)| {
                let envelope = frame.envelope.encode().ok()?;
                Some(ratatosk_store::StoredPendingGroup {
                    place: u32::try_from(place).unwrap_or(u32::MAX),
                    chat_id: frame.chat,
                    peer_ik: frame.peer_ik,
                    msg_id: frame.envelope.msg_id,
                    envelope,
                })
            })
            .collect();
        if let Err(error) = self.store.replace_pending_group(&rows) {
            tracing::warn!(?error, "очередь отложенных кадров не легла на диск");
        }
    }

    /// Разбирает отложенное, что стало применимым.
    ///
    /// **Условие продолжения — укоротившаяся очередь, а не непустой заход**,
    /// и это не оптимизация. Разбор вправе положить кадр обратно: блок,
    /// автора которого мы всё ещё не знаем, откладывается снова. Повторяй
    /// мы обход по признаку «нашлось, что разбирать» — тот же блок брался
    /// бы и возвращался вечно, и шаг ядра не кончился бы никогда.
    ///
    /// Повтор при этом нужен: в одной очереди могут лежать блок и карточка,
    /// которой он проверяется, и разобранные в неудачном порядке они
    /// разошлись бы на один заход. Второй круг это чинит, а свойство
    /// «очередь укоротилась» его завершает — расти она не может, кадры
    /// в неё возвращаются только те, что из неё же и взяты.
    pub(super) fn drain_pending_group(&mut self, now_ms: u64) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        loop {
            let before = self.pending_group.len();
            let ready: Vec<PendingGroup> = self
                .pending_group
                .iter()
                .filter(|frame| self.groups.contains_key(&frame.chat))
                .cloned()
                .collect();
            if ready.is_empty() {
                return Ok(effects);
            }
            self.pending_group.retain(|frame| !self.groups.contains_key(&frame.chat));
            // Диск — сразу за памятью: разбор ниже вправе положить кадр
            // обратно (`park_group_frame` запишет снова), а вот разобранный
            // обязан исчезнуть с диска здесь, иначе перезапуск разобрал бы
            // его во второй раз. Дважды разобранное сообщение — это дубль
            // в истории, и §9.2 ловит его дедупликацией, но полагаться
            // на неё там, где можно просто не порождать дубль, незачем.
            self.persist_pending_group();
            for frame in ready {
                // Отметка «видено» возвращается перед разбором: пока кадр
                // лежал, её не было (см. `park_group_frame`). Отложится
                // снова — снова снимется.
                let msg_id = frame.envelope.msg_id;
                self.dedup.check(msg_id, now_ms);
                self.store.note_seen(&msg_id, now_ms)?;
                effects.extend(self.dispatch_group_frame(
                    now_ms,
                    frame.peer_ik,
                    frame.chat,
                    frame.envelope,
                )?);
            }
            if self.pending_group.len() >= before {
                return Ok(effects);
            }
        }
    }

    /// Принимает ключ отправителя участника (§11.1, §11.5).
    ///
    /// **Кто вправе его называть.** Любой участник группы: при вступлении
    /// ключи всех отдаёт пригласивший (§11.5), и требовать, чтобы каждый
    /// назвал свой сам, значило бы сделать вступление невозможным, пока
    /// не соберутся все.
    ///
    /// Подменить чужой ключ участник при этом может — и ничего этим
    /// не добивается, кроме порчи: групповое сообщение **подписано** `SK`
    /// отправителя (§11.1), и с подменённой цепочкой оно просто не откроется.
    /// Выдать себя за другого подменой ключа нельзя; ради этого подпись
    /// в §11.1 и стоит.
    ///
    /// Времени не принимает, и это не упущение: цепочка ложится на диск
    /// без отметки о моменте, а откладывание кадра меряет возраст местом
    /// в очереди (см. [`Engine::park_group_frame`]). Взять `now_ms` «на
    /// всякий случай» значило бы завести довод в пользу того, чтобы
    /// однажды им что-нибудь отметить.
    pub(super) fn on_sender_key(
        &mut self,
        peer_ik: [u8; 32],
        chat: ChatId,
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Ok(block) = group::sender_key_from_value(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        // Про **свою** цепочку чужого мнения не бывает: она наша, и принять
        // его значило бы забыть, чем мы подписываем.
        if block.member == self.identity.public().ik {
            return Ok(Vec::new());
        }
        // Та же причина, что у списка карточек: ключи законно обгоняют
        // состав. Кадр откладывается до появления обоих в составе —
        // а в канале владелец состоит по определению (`counts_as_member`):
        // блоков про него у читателя нет и не будет (§3.2), и требуй мы
        // их, цепочка владельца откладывалась бы навсегда.
        //
        // **В канале свою цепочку вправе назвать всякий сам.** Впускающий
        // делегат отдаёт впущенному свою цепочку до того, как впущенный
        // узнает о его праве (документ едет под ключом чтения, а ключ —
        // под этой же цепочкой); блок запечатан нам и говорит только
        // «вот чем проверять мои блоки». Чужая цепочка без права ничего
        // не открывает: слово судится правом (§6.2), а не цепочкой.
        let self_named = self.groups.get(&chat).is_some_and(|s| !s.profile.everyone_writes())
            && peer_ik == block.member;
        if !self_named
            && (!self.counts_as_member(chat, &peer_ik)
                || !self.counts_as_member(chat, &block.member))
        {
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(Vec::new());
        }
        // Опоздавшее объявление не берём. Каждое вступление проворачивает
        // цепочку каждого участника (§11.5), а §9.2 разрешает переставлять
        // кадры: два приглашения подряд — и до нас едут два объявления одной
        // цепочки с одинаковым (нулевым после поворота) номером. Отличить
        // их можно только меткой владельца, и берём мы строго новейшую.
        //
        // Цена ошибки здесь несимметрична. Отвергнув свежую, мы дождались бы
        // следующего поворота; взяв опоздавшую, мы получаем верный номер при
        // мёртвом ключе — и сообщения владельца молча перестают открываться,
        // потому что снаружи неудачный тег неотличим от порчи.
        if let Some(held) = self.store.sender_chain(&chat, &block.member)? {
            let held_hlc = Hlc::new(held.chain_wall, held.chain_logical);
            // Обе метки нулевые — старшинства не назвал никто: так шлёт
            // сборка, не знавшая этого поля. Ведём себя как прежде, иначе
            // у такого собеседника цепочка не сменилась бы уже никогда.
            let unmarked = block.chain_hlc == Hlc::default() && held_hlc == Hlc::default();
            if !unmarked && block.chain_hlc <= held_hlc {
                return Ok(Vec::new());
            }
        }
        // Распечатываем только теперь. Старшинство сравнивается по метке,
        // а она снаружи печати: блок, который мы и так отвергнем, незачем
        // открывать — и незачем давать повод отвечать на него временем.
        let Some((chain, counter)) =
            group::open_chain(&block, &self.identity.public().ik, &self.identity.ik_secret_bytes())
        else {
            // Адресовано не нам, не открылось или переклеено по дороге —
            // снаружи это одно и то же, и ответ на все три одинаков.
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: block.member,
                chain,
                counter,
                // Метка владельца ложится как приехала: сравнивать её
                // предстоит со следующим его же поворотом.
                chain_wall: block.chain_hlc.wall_ms,
                chain_logical: block.chain_hlc.logical,
                // Новая цепочка приходит **без** кэша, и это не потеря,
                // а смысл: пропуски относились к прежнему состоянию,
                // и пережив его смену, они открывали бы номера цепочки,
                // которой больше нет.
                skipped: Vec::new(),
            },
        )?;
        Ok(Vec::new())
    }

    /// Рассылает свою цепочку отправителя всем известным участникам.
    /// Своя цепочка как есть — для объявления без поворота.
    ///
    /// **Появилась вместе со снятием поворота при вступлении.** Раньше
    /// объявление ехало прицепом к повороту, и других поводов сказать
    /// «вот моя цепочка» не было. Теперь повод есть, а поворота нет:
    /// состав вырос, и новые участники нашей цепочки не знают.
    ///
    /// Метка едет та же, что лежит: цепочка не менялась. Получатель,
    /// у которого она уже есть, такое объявление отбросит — он берёт
    /// только строго более новое, — а тот, у кого её нет, возьмёт.
    /// Поэтому объявлять лишний раз безвредно.
    pub(super) fn current_sender_key(
        &self,
        chat: ChatId,
    ) -> Result<group::SenderKeyBlock, EngineError> {
        let me = self.identity.public().ik;
        let stored = self.store.sender_chain(&chat, &me)?.ok_or(EngineError::UnknownGroup)?;
        Ok(group::SenderKeyBlock {
            group: chat,
            member: me,
            // Открытым — печать накладывается на отправке, у каждого
            // адресата своя: она к нему и привязана.
            secret: group::ChainSecret::Open { chain: stored.chain, counter: stored.counter },
            chain_hlc: Hlc::new(stored.chain_wall, stored.chain_logical),
        })
    }

    /// Готовит объявление ключа **для одного адресата** — печатать или нет.
    ///
    /// Само правило §5.3 живёт в [`group::chain_secret_for`] — там его
    /// видно проверке. Движку остаётся то, чего нет больше нигде: взгляд
    /// на список сессий с этим адресатом.
    pub(super) fn sender_key_for(
        &self,
        block: &group::SenderKeyBlock,
        recipient: [u8; 32],
    ) -> Result<Value, EngineError> {
        let has_live_session = !self.sessions.all_for_peer(&recipient).is_empty();
        let secret = group::chain_secret_for(block, &recipient, has_live_session)?;
        Ok(group::sender_key_value(&group::SenderKeyBlock { secret, ..block.clone() }))
    }

    pub(super) fn announce_sender_key(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        mine: &group::SenderKeyBlock,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let members: Vec<[u8; 32]> =
            self.groups[&chat].group.members().copied().filter(|m| *m != me).collect();
        let mut effects = Vec::new();
        for member in members {
            let value = self.sender_key_for(mine, member)?;
            effects.extend(self.tell_member(now_ms, member, PayloadType::SenderKey, value)?);
        }
        Ok(effects)
    }

    /// Личность участника, какой мы её знаем, — для проверки подписи.
    ///
    /// `None` означает «его карточки у нас нет», а не «подпись не сошлась»:
    /// карточка едет отдельным кадром и вправе опоздать.
    /// Чем проверять слова этого автора в **этом канале** (§6.2).
    ///
    /// Сперва то, что знаем сами (карточка контакта или пира), потом —
    /// ключ из выдачи права. Второй источник заведён потому, что первого
    /// у читателя не бывает: §3.2 оставляет состав владельцу, и читатели
    /// друг друга не знают. Ключ приезжает подписанным — в том же
    /// документе, что и само право, — и гаснет вместе с ним.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn channel_identity_of(
        &self,
        chat: ChatId,
        who: &[u8; 32],
    ) -> Result<Option<ratatosk_crypto::PublicIdentity>, EngineError> {
        if let Some(known) = self.public_identity_of(who)? {
            return Ok(Some(known));
        }
        let Some(stored) = self.store.channel(&chat)? else { return Ok(None) };
        let Some(grant) = stored.grants.iter().find(|grant| grant.who == *who) else {
            return Ok(None);
        };
        // Пустой ключ — «проверить нечем»: так лежат выдачи из баз
        // постарше, где ключ вместе с правом ещё не ездил.
        if grant.sk == [0u8; 32] {
            return Ok(None);
        }
        Ok(ratatosk_crypto::PublicIdentity::from_bytes(*who, grant.sk).ok())
    }

    pub(super) fn public_identity_of(
        &self,
        who: &[u8; 32],
    ) -> Result<Option<ratatosk_crypto::PublicIdentity>, EngineError> {
        if *who == self.identity.public().ik {
            return Ok(Some(self.identity.public()));
        }
        if let Some(contact) = self.contacts.get(who) {
            return Ok(Some(ratatosk_crypto::PublicIdentity::from_bytes(
                contact.card.ik,
                contact.card.sk,
            )?));
        }
        // **И пир** (§8.3): читатель канала владельцу не контакт, а блоки
        // подписывает — тем же, чем все, — и уходит из канала подписанным
        // блоком (§10.6). Проверять их нечем было бы, не храни запись пира
        // карточку.
        //
        // Пир без карточки (владелец из ссылки, §10.1) отвечает `None`:
        // «проверять нечем» — не «подпись не сошлась», и разбирается это
        // там же, где раньше разбирался неизвестный ключ.
        let Some(peer) = self.peers.get(who).filter(|peer| !peer.card.is_empty()) else {
            return Ok(None);
        };
        Ok(Some(ratatosk_crypto::PublicIdentity::from_bytes(*who, peer.sk)?))
    }

    pub(super) fn send_group_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        // Отказ до записи в историю: сообщение, легшее в базу и не
        // собравшееся в кадр, человек видел бы у себя вечно ждущим отправки.
        if !ratatosk_proto::files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }
        let me = self.identity.public().ik;
        // Слова — это `WRITE`: то же право, что у правки и ответа
        // (`Action::needs_right`). Отдельного вида у текста нет, оттого
        // и право названо здесь прямо.
        self.check_may_put(now_ms, chat, channel::Rights::WRITE)?;
        // **А «публикует только владелец» здесь больше не спрашивается.**
        // Отказ этот был про доставку, а не про право: состава канала
        // держатель `WRITE` не знает (§3.2), и развозить ему было некому.
        // Теперь его слово уезжает владельцу и своим сидам
        // (`push_candidates`), а дальше идёт обычной раздачей — так же,
        // как чужое слово идёт от сида.

        // Цепочка продвигается **до** отправки и тут же ложится на диск.
        // Уроните процесс между продвижением и записью — и следующий запуск
        // выдаст тот же номер второй раз, то есть тот же ключ на другой
        // текст. Это худшее, что может случиться с потоковым шифром.
        let stored = self.store.sender_chain(&chat, &me)?.ok_or(EngineError::UnknownGroup)?;
        let mut chain = SenderChain::resume(zeroize::Zeroizing::new(stored.chain), stored.counter);
        let (counter, message_key) = chain.next();
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: me,
                chain: *chain.export(),
                counter: chain.counter(),
                // Метка та же: цепочка не сменилась, она **продвинулась**.
                // Новую метку выдаёт только поворот (`rotate_sender_chain`),
                // иначе получатель принял бы шаг вперёд за смену ключа.
                chain_wall: stored.chain_wall,
                chain_logical: stored.chain_logical,
                skipped: Vec::new(),
            },
        )?;

        let sealed = ratatosk_crypto::group::seal_message(
            &self.content_key(chat, &message_key, false)?,
            &chat,
            &me,
            counter,
            text.as_bytes(),
        )?;
        // **Номер и метка рождаются до блока**, а не после: с фазы 2 они
        // входят в подпись (§4.1), и подписать их можно только зная.
        // Раньше они брались следующими тремя строками, и порядок был
        // безразличен — пока копию возил сам отправитель.
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();
        // **Работа считается по шифротексту** (§11): он и есть тело блока.
        // Считать её по открытому тексту значило бы дать проверяющему
        // повод его знать, а весь смысл §7.3 в том, чтобы отсеять кадр
        // **до** расшифровки.
        let pow_nonce = self.solve_pow(now_ms, chat, &me, &sealed)?;
        let payload = group::signed_message(
            &self.identity,
            &group::GroupMessage {
                group: chat,
                sender: me,
                counter,
                sealed,
                stamp: Some(group::MessageStamp { msg_id, hlc }),
                pow_nonce,
            },
        )?;

        let envelope = Envelope::new(msg_id, hlc, PayloadType::GroupMessage, payload);
        let bytes = envelope.encode()?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: me,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Статуса нет, и это не «ещё не проставили»: см. выше.
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;

        // **Своё слово в канале раздаётся деревом** (§7.1): целиком —
        // eager-пирам, зовом `IHAVE` — ленивым. В группе веер остаётся
        // как был: §11.3 велит каждому рассылать свои копии самому,
        // и дерева там нет вовсе.
        //
        // Деревом раздаются **слова**, а не документы: представление,
        // ключи чтения и записи каталога едут веером. Документ редок
        // и важен, и лишний круг `IHAVE` → `GRAFT` стоил бы читателю
        // отложенного впуска ради экономии одного кадра.
        self.spread_in_chat(now_ms, chat, msg_id, &bytes)
    }

    /// Молчалива ли доставка такого кадра (см. [`Delivery::silent`]).
    ///
    /// Признак — **тип нагрузки**, и только он: молчаливы ровно те кадры,
    /// что едут копией каждому участнику группы (§11.3). Нечитаемый кадр
    /// считается обычным: это состояние «мы не знаем», а обычная доставка
    /// из двух — та, что ничего не ломает.
    pub(super) fn silent_frame(bytes: &[u8]) -> bool {
        let Ok(raw) = Envelope::decode(bytes) else { return false };
        Self::rides_silently(raw.into_parts().1.payload_type)
    }

    /// Едет ли кадр такого типа **без квитанции и без срока**.
    ///
    /// Шире, чем [`Engine::is_group_copy`], ровно на кадры дерева (§7.1),
    /// и вторая причина у них своя: подтверждение `IHAVE` — это `GRAFT`,
    /// подтверждение `GRAFT` — сам блок. Квитанция удваивала бы трафик
    /// механизма, заведённого ради его сокращения.
    ///
    /// Два предиката, а не один список: вопросы разные. «Копия группового»
    /// отвечает ещё и на «слать ли статус в историю», а кадру дерева
    /// в истории места нет вовсе.
    pub(super) const fn rides_silently(payload_type: PayloadType) -> bool {
        // Пакет блоков (§8.4) — те же копии, только пачкой: молчит он
        // по той же причине, что и они. Метёлка `receipt_wiring`
        // напомнила об этом в ту же минуту, как пакет появился:
        // немолчаливый кадр без квитанции уводит сессию на покой,
        // и кадры собеседника начинают пропадать.
        Self::is_group_copy(payload_type)
            || matches!(payload_type, PayloadType::SwarmControl | PayloadType::SwarmBundle)
    }

    /// Ставит в очередь §5.4 одну копию группового сообщения.
    ///
    /// Копия **молчаливая**: квитанции ей не будет и статуса у неё нет.
    /// Ступени §5.4 она при этом проходит все, как любая другая доставка, —
    /// почему именно так и что было раньше, в [`Delivery::silent`].
    pub(super) fn send_group_copy(
        &mut self,
        now_ms: u64,
        msg_id: MsgId,
        member: [u8; 32],
        envelope: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        if !self.contacts.contains_key(&member) && !self.peers.contains_key(&member) {
            // Участник, чьей карточки у нас нет: его добавил кто-то другой,
            // а карточка едет отдельным кадром (§11.5) и вправе опоздать.
            //
            // Слать сейчас нечем — но **выбрасывать нельзя**, и это была
            // поломка: новичок стоял у всех в списке участников, а сообщений
            // не получал, пока его карточка не доедет. Сказанное в это окно
            // не доходило до него никогда, и «через некоторое время чинится»
            // означало ровно приезд карточки.
            //
            // Кладётся в отложенные напрямую, минуя `remember_undelivered`:
            // тот честно отказывается ждать неизвестного контакта («удалённому
            // отправлять некому»), а здесь контакт не удалён, а ещё не приехал.
            // Разбудит `retry_deferred` — его зовёт `add_contact`.
            self.park_for_card(now_ms, msg_id, member, envelope)?;
            return Ok(Vec::new());
        }
        self.enqueue(Delivery {
            // Номер конверта, а не свой: сообщение одно, и в истории у всех
            // участников оно лежит под этим номером. Спутать записи очереди
            // между собой это не даст — ключ очереди пара «номер и
            // получатель», и с тех пор как копии в ней живут по-настоящему,
            // это важно уже не на словах (`delete_outbox`, `MIGRATION_0021`).
            msg_id,
            peer_ik: member,
            envelope: envelope.to_vec(),
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            // Выводится из кадра, а не проставляется здесь словом `true`.
            // Проставь мы его руками, у одного факта стало бы два источника:
            // этот и `silent_frame`, которым та же копия поднимается после
            // перезапуска. Совпадать они обязаны всегда — значит источник
            // должен быть один.
            silent: Self::silent_frame(envelope),
        })
    }

    /// Откладывает копию участнику, чья карточка ещё не доехала (§11.5).
    ///
    /// Отдельно от [`Engine::remember_undelivered`] по одной причине: тот
    /// отказывается ждать неизвестного контакта, и отказывается правильно —
    /// удалённому отправлять некому. Здесь случай другой: человек в составе
    /// группы, его карточка едет своим кадром и вправе опоздать.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn park_for_card(
        &mut self,
        now_ms: u64,
        msg_id: MsgId,
        member: [u8; 32],
        envelope: &[u8],
    ) -> Result<(), EngineError> {
        if self.deferred.iter().any(|d| d.msg_id == msg_id && d.peer_ik == member) {
            return Ok(());
        }
        if self.deferred.len() >= MAX_DEFERRED {
            // Тот же предел и то же правило, что у `remember_undelivered`:
            // вытесняется самое старое. Статус здесь не меняется — групповая
            // копия молчалива (§11.3), и объявлять по ней нечего.
            let evicted = self.deferred.remove(0);
            self.store.delete_outbox(&evicted.msg_id, &evicted.peer_ik)?;
        }
        let delivery = Delivery {
            msg_id,
            peer_ik: member,
            envelope: envelope.to_vec(),
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: Self::silent_frame(envelope),
        };
        self.persist_delivery(&delivery)?;
        self.deferred.push(delivery);
        tracing::info!(
            участник = %Self::short_label(&member),
            "копия отложена до карточки участника"
        );
        Ok(())
    }

    /// Ключ, которым запечатывается содержимое этого чата.
    ///
    /// # В канале это ключ чтения, а не ключ позиции цепочки
    ///
    /// §10.4 про открытый канал говорит прямо: «`AK` совпадает с ключом
    /// из ссылки и не поворачивается никогда», а §6.1 кладёт этот ключ
    /// **в саму ссылку**. Значит открыть слово канала обязан всякий,
    /// у кого ключ чтения есть, — и никто другой (§7.6: «вытянуть
    /// шифротекст вправе любой, прочесть — нет»).
    ///
    /// Цепочка отправителя (§11.1) для этого не годится и не годилась
    /// никогда: её ключ одноразовый и выдаётся участникам поимённо.
    /// Пока слова канала запечатывались ею, открытый канал не работал
    /// вовсе — подписчик по ссылке не мог прочесть ни слова, — а архив
    /// (§7.2) было бессмысленно хранить: пришедший позже не открыл бы
    /// его ничем. Поймано живым прогоном: «подписка проходит,
    /// а представление не приходит».
    ///
    /// # Что остаётся от цепочки
    ///
    /// **Номер.** §7.3 держится на непрерывности `seq` у автора, и его
    /// по-прежнему выдаёт цепочка — просто ключ её больше не нужен.
    /// Заводить второй счётчик значило бы завести второе место, где
    /// нумерация однажды разойдётся.
    ///
    /// # Чем защищено авторство, раз ключ общий
    ///
    /// Подписью автора над блоком (§11.1) и правом на запись (§6.2).
    /// Ключом чтения запечатать чужое слово может всякий читатель —
    /// но подписать его чужим именем не может никто, а неподписанное
    /// ядро не принимает.
    ///
    /// # Errors
    ///
    /// [`EngineError::NoReadKeyYet`] — канал есть, а ключа чтения нет:
    /// так выглядит подписка по приглашению до впуска.
    fn content_key(
        &self,
        chat: ChatId,
        from_chain: &ratatosk_crypto::kdf::Key32,
        carries_the_key: bool,
    ) -> Result<ratatosk_crypto::kdf::Key32, EngineError> {
        if self.groups.get(&chat).is_none_or(|state| state.profile.everyone_writes()) {
            return Ok(from_chain.clone());
        }
        // **Выдача ключа чтения едет цепочкой, а не ключом чтения.**
        // Иначе ключ был бы заперт сам в себе: впущенный не открыл бы
        // блок, которым ему этот ключ и выдают. Цепочка у него к этому
        // времени есть — её отдаёт вступление (§11.5).
        if carries_the_key {
            return Ok(from_chain.clone());
        }
        // Поколение берётся **новейшее**: §6.4 велит писать новым,
        // а прежние держать ради архива.
        let key = self.store.archive_keys(&chat)?.pop().ok_or(EngineError::NoReadKeyYet)?;
        Ok(ratatosk_crypto::kdf::Key32::new(key.key))
    }

    /// Собирает кадр группового действия.
    ///
    /// Продвигает цепочку отправителя, запечатывает действие её ключом,
    /// подписывает и складывает конверт. Наружу отдаёт номер конверта,
    /// метку и байты — всё, что вызывающему нужно, чтобы записать своё
    /// у себя и разослать копии.
    ///
    /// # Почему это отдельно от рассылки
    ///
    /// Из-за ответа. Ответ — новое сообщение, и в историю оно ложится
    /// **под номером конверта**: так у всех участников это одна и та же
    /// строка (§11.3). Значит номер обязан быть известен до рассылки,
    /// а порядок «сначала записать, потом отправить» — тот же, что
    /// у обычного сообщения: упавший между двумя шагами процесс оставит
    /// сказанное в истории, а не только в проводе.
    ///
    /// # Номер цепочки тратится и на реакцию
    ///
    /// Цепочка — это порядок, в котором участник что-то делал. Пропуск
    /// в ней у получателя означает «кадр потерялся»; не трать действия
    /// номер, и он не отличил бы «реакцию не довезли» от «реакции
    /// не было».
    pub(super) fn seal_group_action(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        action: &ratatosk_proto::group_action::Action,
    ) -> Result<(MsgId, Hlc, Vec<u8>), EngineError> {
        let me = self.identity.public().ik;
        // Чем судится действие — говорит оно само, и список там один
        // (`Action::gate`). Спрашивать здесь, а не у каждого вызывающего,
        // значит не иметь места, где о нём забудут.
        //
        // У представления судья — подпись владельца, и проверяет её
        // получатель. Своё состояние в чате всё равно спрашивается: кадр
        // собирается цепочкой отправителя, а её нет у того, кто не состоит.
        match action.gate() {
            ratatosk_proto::group_action::Gate::Right(right) => {
                self.check_may_put(now_ms, chat, right)?;
            }
            ratatosk_proto::group_action::Gate::AnyOf(rights) => {
                self.check_may_put_any(now_ms, chat, rights)?;
            }
            ratatosk_proto::group_action::Gate::OwnSignature => {
                self.check_may_put(now_ms, chat, channel::Rights::none())?;
            }
        }
        // **Право — раньше доставки, и порядок тут значим.** Веерное
        // в канале возит владелец (§3.2, §7.5.2); спроси мы это первым,
        // «у вас нет такого права» стало бы неотличимо от «доставлять
        // некому», и человек, которому права и правда не дали, пошёл бы
        // ждать роя вместо того, чтобы попросить владельца.
        //
        // Спрашивается у **действия**: право и направление доставки —
        // разные вопросы. Делегат не публикует, но впускает и выдаёт
        // ключ чтения, а эти блоки едут адресатами.
        // **Слово и всё, что о слове, публикует держатель права** —
        // дорога у него есть: владелец и свои сиды (`push_candidates`).
        // А документ канала по-прежнему возит владелец, и дело тут
        // не в доставке: представление судится **его подписью** (§10.3,
        // шаг 3), и подписанного делегатом не примет никто.
        // Название и картинка держателя `EDIT` — тоже «о слове» в этом
        // смысле: у них та же дорога, что у слова, а не веер владельца.
        let word = matches!(
            action.gate(),
            ratatosk_proto::group_action::Gate::Right(right)
                if right == channel::Rights::WRITE || right == channel::Rights::EDIT
        );
        if action.fans_out() && !word {
            self.check_may_publish(chat)?;
        }

        // Цепочка продвигается **до** отправки и тут же ложится на диск —
        // ровно по той же причине, что у сообщения: уроните процесс между
        // продвижением и записью, и следующий запуск выдаст тот же номер
        // второй раз, то есть тот же ключ на другое содержимое.
        let stored = self.store.sender_chain(&chat, &me)?.ok_or(EngineError::UnknownGroup)?;
        let mut chain = SenderChain::resume(zeroize::Zeroizing::new(stored.chain), stored.counter);
        let (counter, message_key) = chain.next();
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: me,
                chain: *chain.export(),
                counter: chain.counter(),
                // Метка та же: цепочка не сменилась, она **продвинулась**.
                // Новую метку выдаёт только поворот (`rotate_sender_chain`),
                // иначе получатель принял бы шаг вперёд за смену ключа.
                chain_wall: stored.chain_wall,
                chain_logical: stored.chain_logical,
                skipped: Vec::new(),
            },
        )?;

        let plain =
            ratatosk_codec::canonical::encode(&ratatosk_proto::group_action::payload(action))?;
        // `seal_action`, а не `seal_message`: тип нагрузки лежит в конверте,
        // а конверт подписью не покрыт, и разделитель в AAD не даёт выдать
        // действие за сообщение подменой одного числа по дороге.
        let carries_the_key =
            matches!(action, ratatosk_proto::group_action::Action::ArchiveKey { .. });
        let sealed = ratatosk_crypto::group::seal_action(
            &self.content_key(chat, &message_key, carries_the_key)?,
            &chat,
            &me,
            counter,
            &plain,
        )?;
        // Номер и метка — до блока, как и у сообщения: с фазы 2 они входят
        // в подпись (§4.1). Действие в группе подписывается тем же блоком,
        // что и текст, и правило у них одно.
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();
        // **Работа считается по шифротексту** (§11): он и есть тело блока.
        // Считать её по открытому тексту значило бы дать проверяющему
        // повод его знать, а весь смысл §7.3 в том, чтобы отсеять кадр
        // **до** расшифровки.
        let pow_nonce = self.solve_pow(now_ms, chat, &me, &sealed)?;
        let payload = group::signed_message(
            &self.identity,
            &group::GroupMessage {
                group: chat,
                sender: me,
                counter,
                sealed,
                stamp: Some(group::MessageStamp { msg_id, hlc }),
                pow_nonce,
            },
        )?;

        let envelope = Envelope::new(msg_id, hlc, PayloadType::GroupAction, payload);
        let bytes = envelope.encode()?;
        // **Свой кадр ложится в архив здесь, а не при рассылке** (§7.2).
        // Цепочка отправителя одна на всё, и позиции в ней занимают
        // и веерные действия, и адресные — ключ чтения впущенному,
        // запись о впуске владельцу. Архивируй мы при рассылке веером,
        // у автора получился бы журнал с дырами там, где он сам ничего
        // не терял: адресный блок веером не едет.
        //
        // Отдавать адресный блок спросившему не страшно и даже нужно:
        // §7.6 разрешает вытянуть шифротекст всякому, а открыть его
        // сможет только тот, кому он запечатан.
        if self.groups.get(&chat).is_some_and(|state| !state.profile.everyone_writes()) {
            let addressee = self.addressee_of(chat, action);
            self.archive_channel_frame(now_ms, chat, msg_id, &bytes, addressee)?;
        }
        Ok((msg_id, hlc, bytes))
    }

    /// Рассылает готовый групповой кадр — по копии каждому участнику (§11.3).
    ///
    /// Одно место на сообщение и на действие. Разведи их по двум циклам,
    /// и однажды одно из них стало бы обходить состав иначе.
    /// Разносит **слово или действие о слове** — в группе веером,
    /// в канале деревом (§11.3, §7.1).
    ///
    /// # Зачем одно место на оба вида чата
    ///
    /// В группе состав знает каждый, и копию шлёт каждый сам (§11.3).
    /// В канале состав знает **владелец** (§3.2), а держатель права
    /// писать (§6.2) не знает никого: его веер пуст, и всё, что он
    /// скажет, останется у него.
    ///
    /// Пока слова расходились одной дорогой (деревом), а действия
    /// о словах — другой (веером), выходило ровно то, что описал живой
    /// прогон: «обычные сообщения ходят нормально, а файлы и реакции
    /// от подписчиков не доходят». И в открытом канале — то же самое
    /// с другого конца: веер владельца пуст, потому что состава
    /// не существует (§6.1), и до подписчиков не доходили **его** файлы
    /// и реакции.
    ///
    /// # Документы каналов сюда не идут
    ///
    /// Представление, ключ чтения, запись о впуске и запись каталога
    /// едут веером владельца и адресатами: они его и ничьи больше,
    /// и дерево им не нужно (§7.1: «пересылаются слова, а не
    /// документы»).
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки копии.
    pub(super) fn spread_in_chat(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        if self.groups.get(&chat).is_some_and(|state| !state.profile.everyone_writes()) {
            return self.push_block(now_ms, chat, None, msg_id, bytes);
        }
        self.fan_out_group(now_ms, chat, msg_id, bytes)
    }

    pub(super) fn fan_out_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let recipients = match self.groups.get(&chat) {
            Some(state) => state.group.recipients(&me),
            None => return Err(EngineError::UnknownGroup),
        };
        let mut effects = Vec::new();
        for member in recipients {
            // Отказ по одному участнику **не обрывает** рассылку остальным.
            // Прежде здесь стоял `?`, и первый же спотыкнувшийся участник
            // уносил с собой всех, кто шёл в списке после него, — молча
            // и с сохранением порядка, то есть каждый раз одних и тех же.
            //
            // Сообщение одно, получателей много, и неудача с одним из них
            // ничего не говорит про других. Отказ уходит в журнал: бросить
            // его совсем значило бы завести тишину там, где мы её только
            // что чинили.
            match self.send_group_copy(now_ms, msg_id, member, bytes) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::warn!(
                    ?error,
                    участник = %Self::short_label(&member),
                    "копия участнику не поставилась в очередь"
                ),
            }
        }
        Ok(effects)
    }

    /// Правит своё сообщение в группе.
    ///
    /// Правила — те же, что один на один, и берутся оттуда же: пустая правка
    /// это удаление, править можно только своё, окно — неделя по местным
    /// часам. Разница ровно одна: кадр уезжает копией каждому участнику,
    /// а не одному собеседнику.
    pub(super) fn edit_group_message(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        ratatosk_proto::edit::check(text)?;
        if !ratatosk_proto::files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }
        let own_ik = self.identity.public().ik;
        let message = self
            .store
            .message(&msg_id)?
            .filter(|m| m.sender_ik == own_ik && m.chat_id == chat)
            .ok_or(ratatosk_proto::EditError::NotYours)?;
        if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
            return Err(ratatosk_proto::EditError::TooLate.into());
        }

        let trimmed = text.trim();
        let action =
            ratatosk_proto::group_action::Action::Edit { target: msg_id, text: trimmed.to_owned() };
        // Кадр собирается **до** правки у себя: сборка вправе отказать —
        // цепочки может не быть, — и правка, применённая у себя и никуда
        // не уехавшая, разошлась бы с тем, что видят остальные.
        let (frame_id, _, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        let mut effects = Vec::new();
        if self.store.edit_message(&msg_id, trimmed.as_bytes(), now_ms)? {
            effects.push(Effect::Notify(Event::MessageEdited { chat, msg_id }));
        }
        effects.extend(self.spread_in_chat(now_ms, chat, frame_id, &bytes)?);
        Ok(effects)
    }

    /// Отзывает свои сообщения в группе.
    ///
    /// Чьё сообщение — знает хранилище, а не клиент: он мог прислать и чужой
    /// идентификатор, и вовсе выдуманный. У себя при этом убирается **всё
    /// названное**, включая чужое: у себя человек вправе стереть что угодно,
    /// и просьба к другим — отдельное действие с отдельным правилом.
    pub(super) fn retract_group_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        let ours = self.own_of(chat, msg_ids)?;

        let mut effects = self.forget_messages(now_ms, chat, msg_ids);
        if ours.is_empty() {
            return Ok(effects);
        }
        let action = ratatosk_proto::group_action::Action::Retract { targets: ours };
        let (frame_id, _, bytes) = self.seal_group_action(now_ms, chat, &action)?;
        effects.extend(self.spread_in_chat(now_ms, chat, frame_id, &bytes)?);
        Ok(effects)
    }

    /// Ставит или снимает свою реакцию в группе.
    pub(super) fn react_in_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        emoji: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        ratatosk_proto::reaction::check(emoji)?;
        if self.store.message(&msg_id)?.is_none_or(|m| m.chat_id != chat) {
            return Ok(Vec::new());
        }

        let action = ratatosk_proto::group_action::Action::Reaction {
            target: msg_id,
            emoji: emoji.to_owned(),
        };
        let (frame_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        // Метка берётся **из кадра**, а не считается второй раз: у всех
        // участников реакция обязана лечь на ту же метку, иначе опоздавшая
        // копия у одного пересилит, а у другого нет (§9.2).
        let own_ik = self.identity.public().ik;
        self.store.put_reaction(&ratatosk_store::StoredReaction {
            msg_id,
            author_ik: own_ik,
            emoji: emoji.to_owned(),
            hlc,
        })?;
        let mut effects =
            vec![Effect::Notify(Event::ReactionChanged { chat, msg_id, author_ik: own_ik })];
        effects.extend(self.spread_in_chat(now_ms, chat, frame_id, &bytes)?);
        Ok(effects)
    }

    /// Отвечает на сообщение в группе.
    ///
    /// Ответ — новое сообщение, и в историю он ложится под номером конверта:
    /// у всех участников это одна и та же строка. По проводу едет ссылка,
    /// а не цитата — цитату каждый рисует из своей копии.
    pub(super) fn reply_in_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        reply_to: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        ratatosk_proto::reply::check(text)?;
        if !ratatosk_proto::files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }
        if self.store.message(&reply_to)?.is_none_or(|m| m.chat_id != chat) {
            return Err(ratatosk_proto::ReplyError::TargetMissing.into());
        }

        let trimmed = text.trim();
        let action = ratatosk_proto::group_action::Action::Reply {
            target: reply_to,
            text: trimmed.to_owned(),
        };
        let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: trimmed.as_bytes().to_vec(),
            received_ms: now_ms,
            // Статуса нет, и это не «ещё не проставили»: один значок
            // на тридцать двух получателей — обещание, которого протокол
            // не даёт (§14). То же самое, что у группового сообщения.
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: Some(reply_to),
        })?;
        self.spread_in_chat(now_ms, chat, msg_id, &bytes)
    }

    /// Открывает групповой кадр: подпись, ключ отправителя, тело.
    ///
    /// Одно место на сообщение и на действие. Всё, что до открытого текста,
    /// у них совпадает дословно: кто принёс, кто в составе, чем проверить
    /// подпись, откуда взять ключ, что делать с пропущенным номером. Разводить
    /// это по двум функциям значило бы завести две копии §11.5 — и одна
    /// из них однажды стала бы проверять на одно меньше.
    ///
    /// Опасение не отвлечённое: в этой самой функции уже был **лишний**
    /// экземпляр проверки — дедупликация, продублированная поверх той, что
    /// делает вызывающий, — и стоил он четырёх упавших тестов на два узла.
    ///
    /// `None` означает «дальше делать нечего», и причин у него четыре:
    /// кадр отложен до появления группы, ключа или карточки; кадр отброшен
    /// как порча; номер уже пройден; тип нагрузки не групповой. Различать
    /// их вызывающему незачем — во всех четырёх случаях читать нечего.
    ///
    /// # Что здесь происходит с цепочкой
    ///
    /// Номер расходуется **до** того, как содержимое разобрано, и это
    /// правильно: номер потратил отправитель, а не мы. Кадр, который
    /// не разобрался, не возвращает цепочку назад — иначе следующий номер
    /// выдал бы тот же ключ на другое содержимое.
    pub(super) fn open_group_frame(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Option<OpenedGroupFrame>, EngineError> {
        let Ok(unchecked) = group::parse_message(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(None);
        };
        let chat = *unchecked.claims_group();
        let sender = *unchecked.claims_sender();

        // Группы нет — откладываем: кадр вправе обогнать вступление (§9.2),
        // и выбросив его, мы потеряли бы первое сказанное слово.
        if !self.groups.contains_key(&chat) {
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(None);
        }
        // **Кто принёс — и вправе ли он.** Здесь стояло «принёсший обязан
        // быть отправителем», и для группы это по-прежнему верно: §11.3
        // велит каждому рассылать свои копии самому, и кадр за чужой
        // подписью из третьих рук там взяться неоткуда.
        //
        // **В канале это правило снято, и на нём стоял весь §7.** Рой —
        // это ретрансляция: блок едет от того, у кого он есть, тому, кому
        // нужен (§3.1, §7.1). Проверять при этом надо не курьера,
        // а содержимое, и всё нужное проверяется ниже: подпись автора,
        // номер из **подписанного** блока, цена работы над запечатанным,
        // ключ цепочки ровно этой позиции. Подменить в блоке нечего —
        // курьер несёт байты, которых не понимает.
        //
        // Что курьер **может**: прислать блок, который мы уже видели,
        // и прислать его много раз. Первое съедает дедупликация §9.2,
        // второе — ретчет: ключ позиции израсходован, и второй раз кадр
        // не откроется вовсе. Счётчик аномалий остаётся у мусора, а этот
        // случай мусором не является.
        //
        // **Групповая ветка проверкой не покрыта, и покрыть её нечем.**
        // Чтобы кадр группы приехал из третьих рук, курьер обязан
        // перепечатать чужой блок в **свою** сессию с получателем —
        // а такого пути в ядре нет вовсе: пересылка живёт только
        // в канале (`relay_to_attached`). Снаружи эта ветка недостижима,
        // и стоит она против чужой сборки и против собственной завтрашней
        // ошибки, а не против сегодняшнего пути. Написано здесь, чтобы
        // «непокрыто» не прочли завтра как «покрыто».
        if self.groups[&chat].profile.everyone_writes() && peer_ik != sender {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(None);
        }
        // А вот «его ещё нет в составе» — не аномалия, а очередь кадров.
        //
        // Слово, сказанное сразу после приглашения, законно обгоняет блок
        // состава, которым приглашённый в этот состав и попадает (§9.2).
        // Здесь стояла общая проверка с предыдущей: кадр считался испорченным
        // и **выбрасывался**, а сказанное в это окно не доходило никогда.
        // Ровно то, что человек описывал как «участника уже все видят
        // в списке, а сообщения до него не идут».
        //
        // Откладывается — как кадр про неизвестную группу и как кадр
        // от участника без карточки: недостающее едет и приедет.
        //
        // **В канале это правило другое, и разница не косметическая.**
        // У открытого канала состава не существует вовсе (§6.1): ключ
        // чтения лежит в ссылке, подписчики владельцу неизвестны,
        // и никто из них не делает ни одной операции состава. Требуй мы
        // здесь членства, подписчик, пришедший по ссылке, не принял бы
        // от владельца ни слова — он про владельца в своём составе
        // ничего не знает.
        //
        // Кто вправе говорить в канале, решает не состав, а **право**
        // (§6.2) — и его проверяют выше по течению `on_group_message`
        // и `apply_group_action`. Здесь остаётся владелец: его подпись
        // и есть канал.
        let sender_may_speak = if self.groups[&chat].profile.everyone_writes() {
            self.groups[&chat].group.contains(&sender)
        } else {
            // **В канале говорит тот, у кого право** (§6.2), а не тот,
            // кто в составе: состава у читателя нет и не будет (§3.2).
            // Пока здесь стоял только состав, слово второго автора
            // откладывалось у всех, кроме владельца, — а он один и видел,
            // что оно вообще было.
            //
            // **Любое право, а не только «писать», и ещё впустивший нас.**
            // Делегат с правом «впускать» отдаёт впущенному ключ чтения
            // и документ своими кадрами, и слово тут ни при чём;
            // а документ, по которому его право видно, лежит в одном
            // из этих кадров. Впустивший узнаётся по своему блоку
            // (`counts_as_member`), и без этого впуск делегатом стоял
            // на месте.
            self.counts_as_member(chat, &sender)
                || self.any_right_holds(now_ms, chat, &sender, channel::Rights::all())?
        };
        if !sender_may_speak {
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(None);
        }

        // **Работа — раньше подписи и раньше вывода ключа** (§7.3:
        // «дешёвое раньше дорогого»). Один хэш против проверки подписи
        // и шага цепочки: если фильтр стоит после них, он не фильтрует
        // ничего — дорогое уже потрачено.
        //
        // Сложность берётся из **принятого** представления. Не приняли —
        // ноль, и работа не требуется: выдумывать сложность нельзя ни
        // в какую сторону, а «не назвали» честнее, чем догадка.
        let bits = self.pow_bits(chat)?;
        if bits > 0 {
            let enough = unchecked.claims_pow_nonce().is_some_and(|nonce| {
                ratatosk_crypto::pow::holds(&chat, &sender, unchecked.claims_sealed(), nonce, bits)
            });
            if !enough {
                // Аномалия: канал объявил цену, и блок без неё честно
                // приехать не мог. Ровно затем фильтр и стоит.
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                return Ok(None);
            }
        }

        let Some(known) = self.channel_identity_of(chat, &sender)? else {
            // Карточка отправителя ещё не доехала — проверить подпись нечем.
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(None);
        };
        let counter = unchecked.claims_counter();
        let Ok(message) = unchecked.verify(&known) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(None);
        };

        // **Подписанное старше конверта.** Номер и метка едут в обоих
        // местах, но подписью покрыты только внутри блока: переставь их
        // ретранслятор в конверте — порядок показа поехал бы у всех, кто
        // принял кадр из его рук, а подменённый номер увёл бы чужую правку
        // не в то сообщение.
        //
        // Расхождение — аномалия, а не повод предпочесть подписанное:
        // конверт тут не «менее точный источник», а испорченный кадр.
        // Блок без метки — другое дело: так шлёт сборка фазы 1, и сверять
        // нечего.
        if let Some(stamp) = message.stamp {
            if stamp.msg_id != envelope.msg_id || stamp.hlc != envelope.hlc {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                return Ok(None);
            }
        }

        // **В канале ключ содержимого — ключ чтения, а не цепочка**
        // (§6.1, §10.4; см. `content_key`). Поэтому и цепочка отправителя
        // здесь не спрашивается: у подписчика по ссылке её нет и быть
        // не может — владелец о нём не знает (§10.4).
        if self.groups.get(&chat).is_some_and(|state| !state.profile.everyone_writes()) {
            return self.open_channel_frame(now_ms, peer_ik, envelope, chat, sender, counter);
        }
        let Some(stored) = self.store.sender_chain(&chat, &sender)? else {
            // Ключа отправителя ещё нет: он едет отдельным кадром (§11.5).
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(None);
        };
        let mut inbox = Self::inbox_of(&stored);
        let Ok(key) = inbox.peek(counter) else {
            // Номер уже пройден либо ушёл слишком далеко вперёд. Первое —
            // повтор вторым транспортом (§9.2), и дедупликация съела бы его
            // всё равно; второе — §7.3.
            return Ok(None);
        };
        // AAD выбирается **типом нагрузки**, и в этом весь смысл разделителя:
        // тип лежит в конверте, конверт подписью не покрыт, и участник вправе
        // переслать нашу копию соседу, поменяв тип. С чужим AAD тег
        // не сойдётся, и до разбора дело не дойдёт.
        let opened = match envelope.payload_type {
            PayloadType::GroupMessage => {
                ratatosk_crypto::group::open_message(&key, &chat, &sender, counter, &message.sealed)
            }
            PayloadType::GroupAction => {
                ratatosk_crypto::group::open_action(&key, &chat, &sender, counter, &message.sealed)
            }
            // Сюда зовут только эти два типа. Третий — ошибка ядра, а не
            // собеседника, и аномалию за неё считать не на кого.
            _ => return Ok(None),
        };
        let Ok(body) = opened else {
            // **Откладываем, а не выбрасываем, и аномалию не считаем.**
            //
            // Подпись уже сошлась — кадр писал именно этот участник, своим
            // `SK` (§11.1). Значит несошедшийся тег означает не подделку,
            // а то, что цепочка у нас **не та**: §11.5 велит проворачивать
            // её при каждом вступлении, §9.2 разрешает переставлять кадры,
            // и слово, сказанное сразу после приглашения, законно обгоняет
            // объявление новой цепочки.
            //
            // Прежде такой кадр считался испорченным и выбрасывался —
            // навсегда. Отправитель квитанцию получал, из очереди копию
            // снимал, и сказанное пропадало у одного участника из трёх.
            // Это вторая половина той же поломки, что и метка старшинства:
            // метка чинит **состояние** (цепочка сходится), а это —
            // **сказанное** (кадр дожидается ключа и открывается).
            //
            // Счётчик аномалий здесь молчит нарочно. Кадр вернётся сюда
            // при каждом разборе отложенного, и считай мы каждую попытку,
            // один неоткрываемый кадр надувал бы счёт §7.3 без предела —
            // наказывая участника за перестановку, которую протокол
            // разрешает сам.
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(None);
        };
        inbox.commit(counter, now_ms)?;
        // **Позиция пишется вместе с кэшем**, и это не аккуратность.
        // Позицию отдают новичку при вступлении (§11.5); оставь мы здесь ту,
        // с которой начали, новичок получил бы ключ, открывающий всё
        // сказанное до него, — ровно то, чего §11.5 обещает не допускать.
        let (chain, next) = inbox.position();
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: sender,
                chain: *chain,
                counter: next,
                // Метка та же: цепочка не сменилась, она **продвинулась**.
                // Выдай мы здесь свою — опоздавшее объявление отправителя
                // сравнивалось бы с нашими часами вместо его.
                chain_wall: stored.chain_wall,
                chain_logical: stored.chain_logical,
                skipped: inbox.export().to_vec(),
            },
        )?;
        Ok(Some((chat, sender, body)))
    }

    /// Распечатывает кадр **канала** ключом чтения (§6.1, §10.4, §7.6).
    ///
    /// # Поколения перебираются, а не называются в кадре
    ///
    /// §6.4: «поколения сосуществуют: прежние нужны для архива, новое —
    /// для будущего». Их единицы, и перебор от новейшего к старому стоит
    /// нескольких проверок тега — дешевле, чем поле в подписанном блоке,
    /// которому пришлось бы верить до расшифровки.
    ///
    /// # Не открылось — откладываем, а не считаем аномалией
    ///
    /// Слово вправе обогнать выдачу ключа: впуск (§10.4) и поворот
    /// (§6.4) едут отдельными блоками, и порядок §9.2 не обещан. Тот же
    /// довод, что у группы с неприехавшей цепочкой, и та же цена
    /// ошибки: посчитай мы это порчей, сказанное пропало бы навсегда.
    ///
    /// Счётчик аномалий здесь молчит нарочно: кадр вернётся сюда при
    /// каждом разборе отложенного, и считай мы каждую попытку, один
    /// неоткрываемый кадр надул бы счёт §7.3 без предела.
    fn open_channel_frame(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
        chat: ChatId,
        sender: ActorId,
        counter: u64,
    ) -> Result<Option<OpenedGroupFrame>, EngineError> {
        let Ok(unchecked) = group::parse_message(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(None);
        };
        let sealed = unchecked.claims_sealed().to_vec();
        let open_with = |key: &ratatosk_crypto::kdf::Key32| match envelope.payload_type {
            PayloadType::GroupMessage => {
                ratatosk_crypto::group::open_message(key, &chat, &sender, counter, &sealed).ok()
            }
            PayloadType::GroupAction => {
                ratatosk_crypto::group::open_action(key, &chat, &sender, counter, &sealed).ok()
            }
            // Сюда зовут только эти два типа. Третий — ошибка ядра.
            _ => None,
        };
        for key in self.store.archive_keys(&chat)?.into_iter().rev() {
            if let Some(body) = open_with(&ratatosk_crypto::kdf::Key32::new(key.key)) {
                return Ok(Some((chat, sender, body)));
            }
        }
        // **Не открылось ключом чтения — пробуем цепочку.** Ею едет ровно
        // один вид блока: выдача самого ключа чтения (§6.4), которую
        // ключом чтения запечатать нельзя — она оказалась бы заперта
        // сама в себе. Разбирать вид до расшифровки нечем, поэтому
        // пробуется ключ, а не читается признак: видов два, и перебор
        // стоит одной проверки тега.
        if let Some(stored) = self.store.sender_chain(&chat, &sender)? {
            let mut inbox = Self::inbox_of(&stored);
            if let Ok(key) = inbox.peek(counter) {
                if let Some(body) = open_with(&key) {
                    inbox.commit(counter, now_ms)?;
                    let (chain, next) = inbox.position();
                    self.store.put_sender_chain(
                        &chat,
                        &StoredSenderChain {
                            member_ik: sender,
                            chain: *chain,
                            counter: next,
                            chain_wall: stored.chain_wall,
                            chain_logical: stored.chain_logical,
                            skipped: inbox.export().to_vec(),
                        },
                    )?;
                    return Ok(Some((chat, sender, body)));
                }
            }
        }
        self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
        Ok(None)
    }

    /// Принимает сообщение в группе (§11.1).
    pub(super) fn on_group_message(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some((chat, sender, body)) = self.open_group_frame(now_ms, peer_ik, envelope)? else {
            return Ok(Vec::new());
        };

        // **Судейство при первом приёме** (§6.2), по представлению,
        // действующему сейчас. Проверка у отправителя не заменяет эту:
        // кадр можно собрать чужой сборкой, а слова в канале видит каждый
        // подписчик.
        //
        // Отвергается **молча, без отметки аномалии**. §6.2 говорит прямо:
        // получивший старый блок уже после снятия права его отвергнет,
        // и архивы разойдутся — «это свойство, а не поломка». Считать
        // аномалией чужой блок, который в момент отправки был законным,
        // значило бы наказывать за исправную работу.
        if !self.right_holds(now_ms, chat, &sender, channel::Rights::WRITE)? {
            return Ok(Vec::new());
        }

        // **Дедупликации здесь нет, и это не забывчивость.** Окно §9.2
        // проверяет вызывающий — `on_frame`, до всякого разбора нагрузки,
        // и одинаково для всех типов. Проверить второй раз значило бы
        // объявить повтором **своё же** сообщение: первый заход уже отметил
        // его номер, и второй нашёл бы его отмеченным.
        //
        // Так и было написано сперва, и стоило это четырёх упавших тестов
        // на два узла: сообщение не доходило вовсе, а отправитель получал
        // на него «доставлено» — квитанцию, которую вызывающий шлёт как раз
        // на повтор.
        self.remember(&StoredMessage {
            msg_id: envelope.msg_id,
            chat_id: chat,
            sender_ik: sender,
            hlc: envelope.hlc,
            body: body.to_vec(),
            received_ms: now_ms,
            // У принятого статуса нет вовсе — там нечему расти.
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        // **Чужой блок, принятый впервые, едет дальше** (§7.1, шаг 2) —
        // тем, кто привязался к нам за блоками этого канала (§7.5.1).
        // Байты те же, что приехали: подпись автора и цепочка его,
        // курьер в них ничего не меняет.
        //
        // Повторов эта строка не плодит: до неё доходит только первый
        // приём — второй съедает окно дедупликации §9.2 ещё в `on_frame`,
        // а третий не откроется вовсе, потому что ключ позиции цепочки
        // израсходован.
        //
        // Пересылаются **слова**, а не действия: живая лента — то, чего
        // читателю не хватает, когда путь от владельца плох. Представление
        // и ключи чтения едут от владельца адресно, и курьер им не нужен.
        let mut effects =
            vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })];
        if !self.groups[&chat].profile.everyone_writes() {
            let bytes = envelope.encode()?;
            effects.extend(self.push_block(
                now_ms,
                chat,
                Some(peer_ik),
                envelope.msg_id,
                &bytes,
            )?);
        }
        Ok(effects)
    }

    /// Принимает действие в группе: правку, отзыв, реакцию, ответ.
    ///
    /// # Незнакомый вид — не аномалия
    ///
    /// Вид действия лежит внутри шифротекста, и сборка поновее вправе
    /// завести пятый. Посчитай мы это порчей, счётчик аномалий (§7.3) рос бы
    /// на честном соседе, и кончилось бы это отключением того, кто ничего
    /// не нарушал. Порча — это когда вид **знаком**, а полей нет; вот она
    /// аномалия и есть.
    pub(super) fn on_group_action(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some((chat, sender, plain)) = self.open_group_frame(now_ms, peer_ik, envelope)? else {
            return Ok(Vec::new());
        };
        let Ok(value) = ratatosk_codec::canonical::decode(&plain) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        match ratatosk_proto::group_action::from_payload(&value) {
            Ok(action) => {
                let mut effects = match self
                    .apply_group_action(now_ms, chat, sender, envelope, &action)?
                {
                    ActionOutcome::Applied(effects) => effects,
                    // **Цель ещё не приехала — ждём её, а не забываем.**
                    // Отзыв, правка и реакция законно обгоняют своё слово
                    // (§9.2), а в канале это ещё и обычный путь: слово
                    // приедет анти-энтропией §7.2 часы спустя. Выбросив
                    // действие, мы получили бы у одного читателя слово,
                    // которое все остальные уже удалили, — стенд показал
                    // ровно это.
                    //
                    // Откладывается **кадр**, и это возможно только
                    // в канале: там содержимое открывается ключом чтения,
                    // и второй заход откроет его снова. В группе ключ
                    // позиции цепочки уже израсходован, и отложенный кадр
                    // не открылся бы никогда — там действие без цели
                    // по-прежнему пропадает, и это названо в `TESTING.md`.
                    ActionOutcome::TargetUnknown => {
                        if self.groups.get(&chat).is_some_and(|s| !s.profile.everyone_writes()) {
                            self.park_group_frame(PendingGroup {
                                chat,
                                envelope: envelope.clone(),
                                peer_ik,
                            });
                        }
                        return Ok(Vec::new());
                    }
                };
                // **Принятое действие — тоже позиция цепочки** (§7.3),
                // и в архиве ей место наравне со словом: спросивший
                // историю обязан получить подряд всё, что было.
                //
                // **И едет оно дальше — как слово** (§7.1, шаг 2), если
                // это действие **о слове**: реакция, правка, отзыв,
                // ответ, файл. Пока этого не было, действие доходило
                // ровно до одного соседа: сказавший не знает состава
                // (§3.2), а тот, кто знает, дальше его не нёс. Снаружи —
                // «сообщения ходят, а реакции и файлы от подписчиков
                // не доходят».
                //
                // Документы канала — представление, ключ чтения, запись
                // о впуске, запись каталога — так не ездят: их развозит
                // владелец сам, и курьер им не нужен.
                if self.groups.get(&chat).is_some_and(|s| !s.profile.everyone_writes()) {
                    let bytes = envelope.encode()?;
                    // Название и картинка от держателя права «менять
                    // представление» едут той же дорогой: у него, как
                    // у всякого делегата, состава нет (§3.2).
                    let about_a_word = matches!(
                        action.gate(),
                        ratatosk_proto::group_action::Gate::Right(right)
                            if right == channel::Rights::WRITE || right == channel::Rights::EDIT
                    );
                    if about_a_word {
                        effects.extend(self.push_block(
                            now_ms,
                            chat,
                            Some(peer_ik),
                            envelope.msg_id,
                            &bytes,
                        )?);
                    } else {
                        let addressee = self.addressee_of(chat, &action);
                        self.archive_channel_frame(
                            now_ms,
                            chat,
                            envelope.msg_id,
                            &bytes,
                            addressee,
                        )?;
                    }
                }
                Ok(effects)
            }
            Err(ratatosk_proto::ActionError::UnknownKind) => Ok(Vec::new()),
            Err(ratatosk_proto::ActionError::Malformed) => {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                Ok(Vec::new())
            }
        }
    }

    /// Применяет разобранное действие к истории.
    ///
    /// Правила те же, что один на один, и по той же причине: распорядиться
    /// не своим нельзя. Проверяет их **получатель**, а не отправитель —
    /// иначе достаточно прислать чужой идентификатор. В группе цена ошибки
    /// выше: правку принял бы каждый участник, и слова в чужой истории
    /// переписались бы у всех сразу.
    ///
    /// `sender` здесь совпадает с тем, кто кадр принёс: [`Engine::
    /// open_group_frame`] это уже проверил, и аномалия ложится на него.
    pub(super) fn apply_group_action(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        sender: ActorId,
        envelope: &Envelope,
        action: &ratatosk_proto::group_action::Action,
    ) -> Result<ActionOutcome, EngineError> {
        let mut waiting = false;
        let effects =
            self.apply_group_action_inner(now_ms, chat, sender, envelope, action, &mut waiting)?;
        Ok(if waiting { ActionOutcome::TargetUnknown } else { ActionOutcome::Applied(effects) })
    }

    /// Тело [`Engine::apply_group_action`]. `waiting` поднимается там,
    /// где действие ссылается на сообщение, которого у нас ещё нет:
    /// это ответ, а не ошибка, и наружу он выходит исходом.
    fn apply_group_action_inner(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        sender: ActorId,
        envelope: &Envelope,
        action: &ratatosk_proto::group_action::Action,
        waiting: &mut bool,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::group_action::Action;

        // Судейство при первом приёме (§6.2) — то же и там же, что
        // у слов. Молча: см. `on_group_message`.
        //
        // Представление сюда не попадает: его судит подпись владельца
        // (`Gate::OwnSignature`), и суди мы его правом, вышел бы круг —
        // первая же выданная выдача отбрасывалась бы, потому что
        // у получателя ещё нет представления, где она записана.
        match action.gate() {
            ratatosk_proto::group_action::Gate::Right(right) => {
                if !self.right_holds(now_ms, chat, &sender, right)? {
                    return Ok(Vec::new());
                }
            }
            ratatosk_proto::group_action::Gate::AnyOf(rights) => {
                // Ключ чтения от **впустившего нас** принимается и без
                // документа: документ приедет под этим же ключом (§10.4),
                // и требуй мы права раньше ключа — впуск делегатом
                // не открывался бы никогда. Кто нас впустил, доказывает
                // его подписанный блок, а не слова.
                if !self.any_right_holds(now_ms, chat, &sender, rights)?
                    && !self.admitted_me(chat, &sender)
                {
                    return Ok(Vec::new());
                }
            }
            ratatosk_proto::group_action::Gate::OwnSignature => {}
        }

        match action {
            Action::SeedRecord { bytes } => {
                // **Кто вписан в записи, тот её и подписал**, и берётся
                // это из самой записи, а не из отправителя: развозит
                // каталог владелец (§7.5.2), и запись в его кадре —
                // чужая по построению.
                let Ok(value) = ratatosk_codec::canonical::decode(bytes) else {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                };
                let Ok(unchecked) = ratatosk_proto::swarm::record_from_wire(&value) else {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                };
                let claimed = *unchecked.claims_ik();
                // **Своя же запись, вернувшаяся веером, — не новость.**
                // Владелец развозит её всем, включая нас; принять её
                // обратно не вредно, но и класть поверх своей незачем.
                if claimed == self.identity.public().ik {
                    return Ok(Vec::new());
                }
                if !self.take_seed_record(now_ms, chat, claimed, bytes)? {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                // **Узнали сида — сразу к нему и привязываемся** (§7.5.1):
                // ждать обхода значило бы ждать час ради кадра в сорок
                // байт. Наружу при этом ничего: каталог — не разговор,
                // и строки в чате ему не полагается.
                self.attach_to_seeds(now_ms, chat)
            }
            Action::Rename { title } => {
                // **В группе — только создатель** (§11.2, расширенное
                // по смыслу). Проверка на приёме, а не только
                // у отправителя: иначе достаточно собрать кадр чужой
                // сборкой — ровно тот же довод, что у `group::removal_allowed`.
                //
                // **В канале — держатель права «менять представление»**
                // (§6.2): право уже спрошено гейтом выше, а владельцу
                // оно принадлежит всегда.
                let in_a_group =
                    self.groups.get(&chat).is_some_and(|s| s.profile.everyone_writes());
                if in_a_group
                    && sender != self.groups.get(&chat).map_or(sender, |state| state.group.owner)
                {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                // Метка — из конверта: она же разрешает спор у реакций,
                // и второго источника у неё нет.
                if !self.apply_rename(chat, title, envelope.hlc)? {
                    return Ok(Vec::new());
                }
                let mut effects =
                    vec![Effect::Notify(Event::GroupRenamed { chat, title: title.clone() })];
                // **Владелец подписывает названное делегатом.** У канала
                // имя живёт в документе (§6.1), и всякая следующая версия
                // везёт его читателям; не впиши владелец новое имя —
                // первая же правка прав откатила бы название у всех.
                let me = self.identity.public().ik;
                if !in_a_group && sender != me && self.channel_owner(chat) == Some(me) {
                    let named = title.clone();
                    match self.publish_representation(now_ms, chat, move |next| next.title = named)
                    {
                        Ok(produced) => effects.extend(produced),
                        Err(error) => {
                            tracing::warn!(?error, "название делегата не легло в документ")
                        }
                    }
                }
                Ok(effects)
            }
            Action::Avatar { bytes } => {
                // **В группе — только создатель**, и проверка та же и там
                // же, что у переименования: собрать кадр чужой сборкой
                // ничто не мешает, а картинка в группе видна всем.
                // В канале — держатель права «менять представление»,
                // и его спросил гейт выше.
                let in_a_group =
                    self.groups.get(&chat).is_some_and(|s| s.profile.everyone_writes());
                if in_a_group
                    && sender != self.groups.get(&chat).map_or(sender, |state| state.group.owner)
                {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                // Байты проверены разбором действия (`avatar::check`) —
                // здесь второй проверки нет нарочно: разойдись они, в группе
                // стало бы можно то, чего нельзя один на один.
                //
                // Метка — из конверта, как у переименования: пересылки
                // этого действия не бывает, новичку картинка достаётся
                // вводным блоком.
                if !self.apply_group_avatar(chat, bytes, envelope.hlc)? {
                    return Ok(Vec::new());
                }
                Ok(vec![Effect::Notify(Event::GroupAvatarChanged { chat })])
            }
            Action::ArchiveKey { generation, recipient_ik, sealed } => {
                // **Не нам — молчим и ничего не отмечаем.** Блок
                // непрозрачен и адресован поимённо (§5.3); чужой в наших
                // руках — это штатная работа ретранслятора, а не мусор.
                // Сегодня владелец шлёт каждому его собственный, но
                // отбрасывать чужой по аномалии значило бы запретить
                // ретрансляцию до её появления.
                if *recipient_ik != self.identity.public().ik {
                    return Ok(Vec::new());
                }
                let Ok(opened) = ratatosk_crypto::seal::open_from_static(
                    &self.identity.ik_secret_bytes(),
                    sealed,
                ) else {
                    // Печать адресована нам, но не открывается: испорчена
                    // либо запечатана не на наш ключ. Вот это уже аномалия
                    // — честно доехать такое не могло.
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                };
                let Ok(key) = <[u8; 32]>::try_from(&opened[..]) else {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                };
                // **Прежние поколения не трогаются** (§6.4): архив
                // не теряется при повороте, и читатель держит их для
                // истории. Повтор того же номера безвреден — хранилище
                // не заменяет уже лежащий ключ.
                self.store.put_archive_key(
                    &chat,
                    &ratatosk_store::StoredArchiveKey {
                        generation: *generation,
                        key,
                        created_ms: now_ms,
                    },
                )?;
                // **Ключ пришёл — значит впустили** (§10.4). Пока
                // подписка числится заявкой, человек видит «ждём впуска»
                // (§10.5), и отметку эту снимать больше нечем: заявки мы
                // не шлём, и ответа на неё не бывает. Выданный ключ
                // чтения — единственное, что владелец делает впуском
                // и что до нас доезжает.
                //
                // Своей же рассылки это не касается: у владельца записи
                // подписки нет вовсе — ссылки не было.
                if let Some(mut subscription) = self.store.subscription(&chat)? {
                    if subscription.state == SUBSCRIPTION_REQUESTED {
                        subscription.state = SUBSCRIPTION_JOINED;
                        self.store.put_subscription(&subscription)?;
                    }
                }
                Ok(vec![Effect::Notify(Event::ChannelKeyRotated { chat, generation: *generation })])
            }
            Action::Admission { bytes } => {
                // Право впускающего уже спрошено выше (`Gate::Right(ADMIT)`).
                // Здесь остаётся подпись: она доказывает, **кто** составил
                // запись, и без неё учёт превратился бы в утверждение
                // любого, кто громче сказал.
                let Ok(value) = ratatosk_codec::canonical::decode(bytes) else {
                    return Ok(Vec::new());
                };
                let Ok(unchecked) = channel::parse_admission(&value) else {
                    return Ok(Vec::new());
                };
                if *unchecked.claims_group() != chat {
                    return Ok(Vec::new());
                }
                let claimed = *unchecked.claims();
                // **Ключом названного впускающего, а не принёсшего.** Блок
                // ретранслируем (§4.3), и путать «кто привёз» с «кто
                // подписал» здесь означало бы отменить это свойство.
                let Some(admitter) = self.public_identity_of(&claimed.admitted_by)? else {
                    // Карточки нет — проверить нечем. Молчим: «нечем
                    // проверить» не то же самое, что «подпись не сошлась».
                    return Ok(Vec::new());
                };
                let block_bytes = unchecked.signed_bytes().to_vec();
                let signature = *unchecked.signature();
                let Ok(admission) = unchecked.verify(&admitter) else {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                };
                // Впущенного в состав здесь **не вводим**: состав едет
                // блоками состава, своей дорогой и со своими метками
                // (§11.2). Запись — учёт, а не источник состава, и сделай
                // она вторым источником, два ответа на «кто в канале»
                // разошлись бы молча.
                self.store.put_admit(
                    &chat,
                    &ratatosk_store::StoredAdmit {
                        who: admission.who,
                        admitted_by: admission.admitted_by,
                        generation: admission.generation,
                        block_bytes,
                        signature,
                        created_ms: now_ms,
                    },
                )?;
                Ok(vec![Effect::Notify(Event::ChannelAdmitted {
                    chat,
                    who: admission.who,
                    admitted_by: admission.admitted_by,
                })])
            }
            Action::Representation { bytes } => {
                // **Документ едет в кадре владельца, и только в нём.**
                // Судится он подписью (`Gate::OwnSignature`), и без этой
                // строки любой участник мог бы слать кадр с чужим
                // документом — а несошедшаяся подпись записывалась бы
                // в аномалии **владельцу**, чьим ключом её проверяли.
                if self.channel_owner(chat).is_some_and(|owner| owner != sender) {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                self.apply_representation(now_ms, chat, sender, bytes)
            }
            Action::Files { caption, offers, forwarded } => {
                // Сообщение с вложениями — и оно же строка в истории,
                // под номером конверта: у всех участников это одна и та же
                // строка (§11.3). Подпись к вложениям — её текст.
                self.remember(&StoredMessage {
                    msg_id: envelope.msg_id,
                    chat_id: chat,
                    sender_ik: sender,
                    hlc: envelope.hlc,
                    body: caption.as_bytes().to_vec(),
                    received_ms: now_ms,
                    status: None,
                    edited_ms: None,
                    // Пометка приехала признаком внутри предложения — тем же
                    // путём, каким она едет один на один.
                    forwarded: *forwarded,
                    reply_to: None,
                })?;
                // Записи о файлах — только если сообщение действительно
                // легло. `put_message` молча ничего не пишет, если
                // на идентификатор стоит надгробие (§9.2), и вложения
                // легли бы тогда к удалённому сообщению: в чате их
                // не видно, а чанки качались бы, занимая ящик и трафик
                // ради того, что человек уже стёр. Та же проверка и та же
                // причина, что у 1:1 (`on_file_offer`).
                if self.store.message(&envelope.msg_id)?.is_none() {
                    return Ok(Vec::new());
                }
                let records = self.record_offers(envelope.msg_id, offers.clone())?;

                let mut effects =
                    vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })];
                for record in records {
                    if record.complete {
                        effects.extend(self.finish_file(now_ms, &record)?);
                    } else if record.accepted {
                        // Просьба уедет **отправителю предложения**, а не
                        // «собеседнику чата»: чанки есть только у него.
                        effects.extend(self.ask_for_file(now_ms, &record, true)?);
                    }
                }
                Ok(effects)
            }
            Action::Forward { text } => {
                // Пересланное — обычная строка истории с одним отличием:
                // признаком `forwarded`. Он и есть весь смысл отдельного
                // вида: «переслано» меняет смысл слов, и получатель обязан
                // это видеть (то же, что `PayloadType::Forward` в 1:1).
                //
                // Автора у пересланного нет и здесь: `sender_ik` — тот, кто
                // переслал, а не тот, чьи слова. Подпись §6 при пересылке
                // не сохраняется, и второго имени взяться неоткуда.
                self.remember(&StoredMessage {
                    msg_id: envelope.msg_id,
                    chat_id: chat,
                    sender_ik: sender,
                    hlc: envelope.hlc,
                    body: text.as_bytes().to_vec(),
                    received_ms: now_ms,
                    // Статуса нет — как у всякой групповой копии (§11.3).
                    status: None,
                    edited_ms: None,
                    forwarded: true,
                    reply_to: None,
                })?;
                Ok(vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })])
            }
            Action::ContactShare { card_bytes, forwarded } => {
                // Тело пустое, карточка лежит записью рядом — ровно так же,
                // как один на один: класть её байты в текст значило бы
                // показать человеку CBOR, забудь клиент про отдельное поле.
                self.remember(&StoredMessage {
                    msg_id: envelope.msg_id,
                    chat_id: chat,
                    sender_ik: sender,
                    hlc: envelope.hlc,
                    body: Vec::new(),
                    received_ms: now_ms,
                    status: None,
                    edited_ms: None,
                    // Пометка приехала признаком внутри нагрузки карточки —
                    // тем же путём, каким она едет один на один.
                    forwarded: *forwarded,
                    reply_to: None,
                })?;
                // Запись — только если сообщение действительно легло: та же
                // проверка и та же причина, что у вложений выше (надгробие
                // §9.2 оставило бы карточку висеть при удалённом сообщении).
                if self.store.message(&envelope.msg_id)?.is_none() {
                    return Ok(Vec::new());
                }
                // Годность карточки проверил разбор действия; здесь из неё
                // берётся только `ik` — под каким именем запись искать.
                //
                // Хранятся **принятые** байты, а не пересобранные из полей:
                // §6 требует, чтобы проверяемое проверялось над принятым
                // представлением, и пересборка разошлась бы с присланным
                // на любом расхождении версий. То же правило, что у 1:1.
                let ik = ContactCard::decode(card_bytes)?.value().ik;
                self.store.put_contact_share(&StoredContactShare {
                    msg_id: envelope.msg_id,
                    ik,
                    card_bytes: card_bytes.clone(),
                })?;
                Ok(vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })])
            }
            Action::Edit { target, text } => {
                // Правка про сообщение, которого нет, — не ошибка: копия
                // могла быть удалена раньше или не дойти вовсе. В канале
                // такой кадр ждёт своё слово (см. `on_group_action`).
                let Some(message) = self.store.message(target)? else {
                    *waiting = true;
                    return Ok(Vec::new());
                };
                if message.sender_ik != sender || message.chat_id != chat {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                // Срок — по **своим** часам: физическая компонента метки
                // приходит от отправителя (§9.1), и доверять ей в проверке,
                // которая его же и ограничивает, нельзя.
                if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
                    return Ok(Vec::new());
                }
                if self.store.edit_message(target, text.as_bytes(), now_ms)? {
                    return Ok(vec![Effect::Notify(Event::MessageEdited {
                        chat,
                        msg_id: *target,
                    })]);
                }
                Ok(Vec::new())
            }
            Action::Retract { targets } => {
                let mut gone = Vec::new();
                for target in targets {
                    let Some(message) = self.store.message(target)? else {
                        // Цели ещё нет — в канале кадр подождёт её.
                        // Надгробие §9.2 здесь не помогает: оно ставится
                        // на **известное** сообщение, а неизвестное
                        // приедет анти-энтропией позже и легло бы как
                        // живое.
                        *waiting = true;
                        continue;
                    };
                    if message.sender_ik != sender || message.chat_id != chat {
                        // Попытка распорядиться не своим — аномалия сессии,
                        // а не «формат не тот».
                        self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                        continue;
                    }
                    if self.store.tombstone_message(target, now_ms)? {
                        gone.push(*target);
                    }
                }
                if gone.is_empty() {
                    return Ok(Vec::new());
                }
                Ok(vec![Effect::Notify(Event::MessagesDeleted { chat, msg_ids: gone })])
            }
            Action::Reaction { target, emoji } => {
                // Реагировать участник вправе на что угодно **в этой группе** —
                // и на своё, и на чужое. Реакция на сообщение из другого чата
                // означала бы, что нам прислали идентификатор, которого знать
                // не должны.
                let Some(message) = self.store.message(target)? else {
                    *waiting = true;
                    return Ok(Vec::new());
                };
                if message.chat_id != chat {
                    self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                    return Ok(Vec::new());
                }
                // §9.1: свежее не затирается старым. Сравнивается с записью
                // **как есть**, включая снятие: иначе опоздавшая реакция
                // вернула бы то, что участник убрал.
                if self
                    .store
                    .reaction(target, &sender)?
                    .is_some_and(|known| known.hlc >= envelope.hlc)
                {
                    return Ok(Vec::new());
                }
                self.store.put_reaction(&ratatosk_store::StoredReaction {
                    msg_id: *target,
                    author_ik: sender,
                    emoji: emoji.clone(),
                    hlc: envelope.hlc,
                })?;
                Ok(vec![Effect::Notify(Event::ReactionChanged {
                    chat,
                    msg_id: *target,
                    author_ik: sender,
                })])
            }
            Action::Reply { target, text } => {
                // Цель **из другого чата** — ссылку снимаем: показать её
                // значило бы нарисовать цитату из разговора, к которому
                // эта группа отношения не имеет. Цель, которой нет вовсе, —
                // дело обычное: ответ законно обгоняет то, на что отвечает
                // (§9.2), и ссылка обязана дождаться.
                //
                // Само сообщение при этом остаётся в обоих случаях: выбросив
                // его, мы потеряли бы сказанное из-за неудачной ссылки.
                let reply_to = match self.store.message(target)? {
                    Some(known) if known.chat_id != chat => {
                        self.sessions.note_anomaly(sender, |c| c.malformed += 1);
                        None
                    }
                    _ => Some(*target),
                };
                self.remember(&StoredMessage {
                    msg_id: envelope.msg_id,
                    chat_id: chat,
                    sender_ik: sender,
                    hlc: envelope.hlc,
                    body: text.as_bytes().to_vec(),
                    received_ms: now_ms,
                    status: None,
                    edited_ms: None,
                    forwarded: false,
                    reply_to,
                })?;
                Ok(vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })])
            }
        }
    }
}
