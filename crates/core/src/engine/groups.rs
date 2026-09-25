//! Состав группы (§11.2, §11.5, §6.7): кто в ней и по какому праву.
//!
//! Заведение, приглашение, исключение, передача владения, свёртка
//! истории состава и права на запись. Общее с каналами — здесь;
//! то, чем канал от группы отличается, — в `channels`.
//!
//! Состав — это OR-Set поверх подписанных блоков, и подпись проверяется
//! **до** того, как операция сюда попадёт: этот модуль оперирует уже
//! доверенными операциями.

use super::*;

impl<S: Store> Engine<S> {
    /// Сворачивает историю состава там, где она переросла горизонт (§6.7).
    ///
    /// # Почему по возрасту, а не по числу сообщений
    ///
    /// Свёртка заставляет отвергать операции старше знака, и законная
    /// операция, опоздавшая сильнее, будет потеряна. Значит знак обязан
    /// отставать дольше самой длинной дороги — почты
    /// (`group::MEMBERSHIP_FOLD_AFTER_MS`). Счётчик сообщений, стоявший
    /// здесь раньше, этого условия не выражал вовсе.
    ///
    /// # Отказ одной группы не отменяет остальные
    ///
    /// То же правило, что у задач уборки выше: не свернуть всё лучше,
    /// чем не свернуть ничего.
    ///
    /// Возвращает, сколько операций выброшено, — тем же числом, каким
    /// отчитываются задачи уборки.
    pub(super) fn fold_old_membership(&mut self, now_ms: u64) -> u64 {
        let chats: Vec<ChatId> = self.groups.keys().copied().collect();
        let mut removed = 0;
        for chat in chats {
            match self.fold_one_membership(now_ms, chat) {
                Ok(rows) => removed += rows,
                Err(error) => {
                    tracing::warn!(?error, "состав чата не свернулся");
                }
            }
        }
        removed
    }

    /// Сворачивает состав одного чата, если есть что сворачивать.
    pub(super) fn fold_one_membership(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<u64, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(0) };
        let Some(horizon) = state.group.fold_horizon(now_ms) else { return Ok(0) };

        let baseline = state.group.baseline();
        let before = self.store.membership(&chat)?;
        // **Считается то, что свернётся впервые**, а не всё, что ниже
        // горизонта. Свёрнутый состав лежит синтетическими метками
        // **на самом знаке**, и они ниже любого будущего горизонта —
        // считай мы их, свёртка срабатывала бы на каждой уборке, двигая
        // знак вперёд и ничего не убирая.
        //
        // А двигать знак задаром нельзя, и это не про диск: знак — это
        // граница приёма. Уйдя вперёд без причины, он отверг бы операцию,
        // которая ещё в пути и которую прежний знак принял бы.
        //
        // Сперва здесь стояло «всё, что ниже горизонта», и проверка
        // на это не ловилась, пока не спросила про **сам знак**.
        let fresh = before
            .iter()
            .map(|op| Hlc::new(op.tag_wall, op.tag_logical))
            .filter(|at| *at > baseline && *at < horizon)
            .count();
        if fresh == 0 {
            return Ok(0);
        }

        let Some(state) = self.groups.get_mut(&chat) else { return Ok(0) };
        state.group.snapshot(horizon);
        let owner = state.group.owner;
        // Синтетические метки — те же, что кладёт `OrSet::compact`:
        // знак, владелец, порядковый номер. Разойдись они, поднятый
        // состав отличался бы от того, что в памяти.
        let folded: Vec<ratatosk_store::StoredMembershipOp> = state
            .group
            .members()
            .enumerate()
            .map(|(i, member)| ratatosk_store::StoredMembershipOp {
                member_ik: *member,
                tag_wall: horizon.wall_ms,
                tag_logical: horizon.logical,
                tag_actor: owner,
                tag_uniq: (i as u64).to_be_bytes(),
                removed: false,
            })
            .collect();

        self.store.fold_membership(&chat, horizon.wall_ms, horizon.logical, &folded)?;
        Ok(u64::try_from(before.len().saturating_sub(folded.len())).unwrap_or(0))
    }

    /// Заводит группу с одним участником — собой (§11).
    ///
    /// Кадров отсюда не уезжает ни одного, и это не недоделка. Группа
    /// в момент заведения состоит из создателя: рассказывать о ней некому,
    /// пока в неё не позвали. Состав и ключи отправителей поедут
    /// приглашением (§11.5) — там же, где появится первый получатель.
    ///
    /// Что ложится на диск сразу и почему все три вещи вместе:
    ///
    /// * **сама группа** — иначе перезапуск между заведением и первым
    ///   приглашением стёр бы её молча;
    /// * **операция добавления себя** — это первая запись истории состава,
    ///   и та самая метка, которую увидят приглашённые. Выведи её заново
    ///   при подъёме — она разошлась бы с их копией;
    /// * **свой ключ отправителя** — он случаен (§11.1), то есть невыводим.
    ///   Потеряв его до первого сообщения, мы завели бы новый, а участники,
    ///   успевшие получить прежний, читали бы пустоту.
    pub(super) fn on_create_group(
        &mut self,
        now_ms: u64,
        title: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(EngineError::GroupTitleEmpty);
        }
        if title.chars().count() > MAX_GROUP_TITLE_CHARS {
            return Err(EngineError::GroupTitleTooLong);
        }

        // Идентификатор случаен — тем же источником и с тем же допущением,
        // что `msg_id` (§9.1): шестнадцать байт из `entropy` не совпадут
        // с чужими. Для 1:1 идентификатор выводится из `IK` (`chat_id_for`),
        // и совпадение группы с будущим контактом здесь тоже исключается
        // только этим допущением, не проверкой: проверить нечего — контакта
        // ещё нет.
        let chat: GroupId = self.entropy.msg_id();
        let me = self.identity.public().ik;
        let at = self.fresh_tag(now_ms, me)?;

        let group = Group::create(chat, me, at);
        // Свой ключ отправителя — тоже случайный, и по той же причине,
        // по какой он вообще существует: цепочка §11.1 обязана начинаться
        // с секрета, которого не знает никто, кроме владельца.
        let mut chain = [0u8; 32];
        self.entropy.fill(&mut chain);
        let chain = SenderChain::new(zeroize::Zeroizing::new(chain));

        // Название получает метку сразу: без неё первое же переименование
        // сравнивалось бы с пустотой, а второе — с меткой первого, и
        // «только вперёд» держалось бы на случайности.
        let title_hlc = self.clock.now(now_ms)?;
        self.store.put_group(&StoredGroup {
            chat_id: chat,
            owner_ik: me,
            title: title.to_owned(),
            title_wall: title_hlc.wall_ms,
            title_logical: title_hlc.logical,
            created_ms: now_ms,
            // `CreateGroup` заводит **группу**, и профиль здесь не выбор,
            // а имя команды. Канал заводится своей командой (§10) —
            // и до неё этой строке нечего решать.
            profile: Profile::Closed.code(),
        })?;
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: me,
                chain: *chain.export(),
                counter: chain.counter(),
                // Метка та же, что у названия: обе выданы одними часами
                // в один миг, и заводить для цепочки вторую незачем.
                chain_wall: title_hlc.wall_ms,
                chain_logical: title_hlc.logical,
                // У своей цепочки пропусков не бывает: каждый номер
                // мы выдаём сами и по порядку.
                skipped: Vec::new(),
            },
        )?;
        // Своё добавление ложится **подписанным блоком**, а не только
        // разложенными операциями. Отправлять его сейчас некому, а хранить
        // надо: при первом же приглашении новичку отдают историю целиком
        // (§11.5), и блок без подписи он принять не сможет — да и не должен.
        self.record_own_ops(now_ms, chat, &[OrSet::prepare_add(me, at)])?;

        self.groups.insert(
            chat,
            GroupState {
                group,
                title: title.to_owned(),
                title_hlc,
                // Картинки у новорождённой группы нет, и метки у неё тоже:
                // ноль означает «не ставили», и первая же поставленная
                // его обгонит.
                avatar_hlc: Hlc::default(),
                created_ms: now_ms,
                profile: Profile::Closed,
            },
        );

        Ok(vec![Effect::Notify(Event::GroupCreated { chat, title: title.to_owned() })])
    }

    /// Приглашает человека в группу (§11.2, §11.5).
    ///
    /// Отсюда уезжает больше кадров, чем от любой другой команды, и делятся
    /// они на две несимметричные половины.
    ///
    /// **Прежним участникам** — то, что изменилось: подписанный блок
    /// с добавлением, карточка новичка и наша новая цепочка отправителя.
    ///
    /// **Новичку** — всё, чего у него нет: история состава целиком, карточки
    /// участников и все известные нам ключи отправителей. Спецификация
    /// перечисляет ровно эти три вещи (§11.5), и порознь они бесполезны:
    /// по составу не с кем говорить без карточек, а подписи блоков нечем
    /// проверять без `SK`, который в карточке и лежит.
    ///
    /// # Почему цепочка меняется
    ///
    /// §11.5: «при вступлении каждый участник обязан начать новую
    /// sender-цепочку». Полноценной backward secrecy это не даёт —
    /// новичок получит и **текущие** цепочки остальных, — но ограничивает
    /// окно: всё, что мы отправим после этой строки, выведено из секрета,
    /// которого до приглашения не существовало.
    ///
    /// Цена названа честно и в `ARCHITECTURE.md` (5ву): наши сообщения,
    /// уехавшие по старой цепочке и ещё не дошедшие, у прежних участников
    /// не откроются — новая цепочка заменяет старую в одной строке. Пока
    /// групповых сообщений нет, платить нечем; когда появятся, это придётся
    /// решать в них.
    pub(super) fn on_invite_to_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        // **В канал не приглашают, в него впускают** (§10.4).
        //
        // Отказ, а не молчаливое «сработает и так», и это ровно тот
        // случай, ради которого профиль спрашивают словами. Приглашение
        // делает три вещи меньше впуска: не спрашивает права «впускать»,
        // не отдаёт поколение ключа чтения и не оставляет подписанной
        // записи (§6.5). Сработай оно в канале — человек оказался бы
        // в чате, который ничего ему не покажет, а владелец не увидел бы
        // следа.
        if !state.profile.everyone_writes() {
            return Err(EngineError::NotAGroup);
        }
        if !state.group.contains(&me) {
            return Err(EngineError::NotInGroup);
        }
        if state.group.contains(&peer_ik) {
            return Err(EngineError::AlreadyInGroup);
        }
        // Контакт нужен не ради вежливости: без карточки ему нечем отправить
        // даже первое рукопожатие, а без сессии — ничего из перечисленного
        // выше. Приглашение незнакомцу было бы командой, которая заведомо
        // ничего не делает.
        if !self.contacts.contains_key(&peer_ik) {
            return Err(EngineError::UnknownPeer);
        }

        self.join_member(now_ms, chat, peer_ik)
    }

    /// Вводит человека в состав группового чата и отдаёт ему всё нужное.
    ///
    /// **Общая часть приглашения в группу и впуска в канал**, и общая она
    /// не ради экономии строк: состав, вводный блок, карточки и передача
    /// цепочки — это одно и то же действие, и разойдись две копии, одна
    /// из дорог однажды перестала бы отдавать что-нибудь из этого списка.
    ///
    /// Чего здесь **нет** и быть не должно: проверок права. Кто вправе
    /// звать — решает вызывающий, и решения эти разные: в группе зовёт
    /// любой участник (§11.2), в канале — держатель права «впускать»
    /// (§6.2).
    pub(super) fn join_member(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let at = self.fresh_tag(now_ms, me)?;
        // `invite` держит предел §11.3 — тридцать два участника. Проверять
        // его здесь во второй раз значило бы завести второе место, где
        // это число знают.
        let op = self.groups[&chat].group.invite(peer_ik, at)?;
        let block = self.record_own_ops(now_ms, chat, std::slice::from_ref(&op))?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.group.apply(op);
        }

        // **Цепочка при вступлении не трогается, и раньше трогалась зря.**
        //
        // Здесь стоял поворот, а обоснованием служило §11.5: «новичок
        // не должен вывести ключи прошлых сообщений». Цель верная, средство
        // избыточное. Новичку отдаётся `export()` на **текущей** позиции
        // (`hand_over_group`), а ретчет назад не разворачивается: из
        // состояния на номере N ключи номеров меньше N не выводятся никак.
        // Прошлое закрывает сам ретчет, а не политика.
        //
        // Что поворот при этом стоил: у каждого вступления он обнулял
        // `counter` всем писателям сразу, и номер переставал быть
        // непрерывным. Фазе 2 непрерывность нужна — на ней стоят have-вектор
        // и обнаружение пропуска, — так что снятие поворота это не только
        // упрощение, но и предусловие.
        //
        // Поворот остался там, где он **действительно** что-то закрывает:
        // при убыли состава (§11.4). Ушедший держит состояние цепочки
        // и идёт по ней вперёд сам — вот его новый секрет и отсекает.
        let mut effects = Vec::new();
        let cards = self.cards_by_ik()?;
        let newcomer_card = cards.get(&peer_ik).cloned();
        let members: Vec<[u8; 32]> =
            self.groups[&chat].group.members().copied().filter(|m| *m != me).collect();

        for member in &members {
            if *member == peer_ik {
                continue;
            }
            effects.extend(self.tell_member(
                now_ms,
                *member,
                PayloadType::GroupMembership,
                block.clone(),
            )?);
            if let Some(card) = newcomer_card.clone() {
                let roster = group::Roster { group: chat, cards: vec![card] };
                effects.extend(self.tell_member(
                    now_ms,
                    *member,
                    PayloadType::GroupRoster,
                    group::roster_value(&roster),
                )?);
            }
        }

        // Прежним участникам объявлять нечего: цепочка та же, что была,
        // и она у них есть. Новичку всё нужное — состав, карточки, ключи
        // отправителей на их нынешних позициях — отдаёт `hand_over_group`.
        effects.extend(self.hand_over_group(now_ms, chat, peer_ik, &cards)?);
        effects.push(Effect::Notify(Event::GroupMembershipChanged { chat }));
        Ok(effects)
    }

    /// Исключает участника (§11.2, §11.4).
    ///
    /// # Кто вправе
    ///
    /// Только создатель, и проверяет это `Group::evict` — второго места,
    /// где знают это правило, здесь нет. Приём проверяет его отдельно
    /// и своими руками: блок с удалением от не-создателя отвергается целиком,
    /// потому что верить чужой проверке нечему.
    ///
    /// # Исключённому говорят
    ///
    /// Блок уезжает **и ему тоже**, хотя из состава он уже вышел. Молчание
    /// здесь было бы худшим из решений: его клиент показывал бы живую группу,
    /// в которой никто не отвечает, — то самое молчание, которое §14
    /// запрещает. Узнать причину он вправе.
    ///
    /// # Цепочка не меняется
    ///
    /// При **вступлении** каждый заводит новую (§11.5); при уходе — нет,
    /// и менять её поздно: прошлое исключённый уже прочёл. §11.4 говорит
    /// это прямо, и `EvictionConsequences::ui_text` повторяет это человеку
    /// дословно — исключение социальное, а не криптографическое.
    pub(super) fn on_evict_from_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        if peer_ik == me {
            return Err(EngineError::CannotEvictSelf);
        }
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if !state.group.contains(&me) {
            return Err(EngineError::NotInGroup);
        }
        // `evict` держит оба правила §11.2 — «только создатель» и «только
        // того, кто состоит», — и отказывает своими словами.
        let op = state.group.evict(me, peer_ik)?;

        let block = self.record_own_ops(now_ms, chat, std::slice::from_ref(&op))?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.group.apply(op);
        }

        // Список получателей берётся **после** применения, и в него руками
        // добавляется исключённый: из состава он уже вышел, а сказать ему
        // надо.
        let mut targets: Vec<[u8; 32]> =
            self.groups[&chat].group.members().copied().filter(|m| *m != me).collect();
        targets.push(peer_ik);

        let mut effects = Vec::new();
        for member in targets {
            effects.extend(self.tell_member(
                now_ms,
                member,
                PayloadType::GroupMembership,
                block.clone(),
            )?);
        }
        // **Цепочка поворачивается здесь же, и список объявления берётся
        // из состава.** Исключённого в нём уже нет — он вышел строкой выше,
        // — поэтому новый ключ ему не уедет, а старый, что у него на руках,
        // с этой минуты ничего не открывает. Без поворота исключение
        // осталось бы социальным: копии перестали бы приходить, а всё,
        // что мы напишем дальше, он прочёл бы, перехватив.
        let mine = self.rotate_sender_chain(now_ms, chat)?;
        effects.extend(self.announce_sender_key(now_ms, chat, &mine)?);

        effects.push(Effect::Notify(Event::GroupMembershipChanged { chat }));
        Ok(effects)
    }

    /// Отдаёт новичку всё, чем группа держится (§11.5).
    ///
    /// Три вещи, и ни одна без остальных не работает: история состава,
    /// карточки участников, ключи отправителей.
    ///
    /// **История — блоками, по кадру на блок**, а не одним свёртком. Свёрток
    /// пришлось бы подписать нам, и новичок узнал бы ровно то, что мы
    /// не соврали себе (5во). Плата — кадр на каждое изменение состава
    /// за всю жизнь группы; свернёт эту историю снапшот §12, которого пока
    /// нет, и это записано в `ARCHITECTURE.md`.
    pub(super) fn hand_over_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        newcomer: [u8; 32],
        cards: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();

        for stored in self.store.membership_blocks(&chat)? {
            let value = ratatosk_codec::canonical::decode(&stored.bytes)?;
            effects.extend(self.tell_member(
                now_ms,
                newcomer,
                PayloadType::GroupMembership,
                value,
            )?);
        }

        // Первым — кто создал группу, как она называется и как выглядит:
        // без создателя не работает §11.2, без названия чат нечем показать.
        // Вывести это из блоков честно нельзя (см. `group::Intro`).
        //
        // Картинка едет здесь и только здесь: переслать новичку чужое
        // действие нельзя — мы выдали бы старой картинке метку своего
        // конверта, и настоящая новая была бы у него отвергнута как
        // опоздавшая (`group_action::Action::Avatar`).
        let stored_avatar = self.store.group_avatar(&chat)?;
        if let Some(state) = self.groups.get(&chat) {
            let (avatar, avatar_hlc) = stored_avatar.map_or_else(
                || (Vec::new(), Hlc::default()),
                |a| (a.bytes, Hlc::new(a.avatar_wall, a.avatar_logical)),
            );
            let intro = group::Intro {
                group: chat,
                owner: state.group.owner,
                title: state.title.clone(),
                title_hlc: state.title_hlc,
                avatar,
                avatar_hlc,
                // Порода едет вместе с представлением: не скажи мы её,
                // новичок завёл бы у себя обычную группу, где писать
                // вправе все, и первое же его слово уехало бы туда,
                // куда его не звали.
                profile: state.profile,
            };
            let value = group::intro_value(&intro);
            effects.extend(self.tell_member(now_ms, newcomer, PayloadType::GroupIntro, value)?);
        }

        let roster = self.roster_for(chat, newcomer, cards);
        if !roster.cards.is_empty() {
            effects.extend(self.tell_member(
                now_ms,
                newcomer,
                PayloadType::GroupRoster,
                group::roster_value(&roster),
            )?);
        }

        for chain in self.store.sender_chains(&chat)? {
            let block = group::SenderKeyBlock {
                group: chat,
                member: chain.member_ik,
                // Открытым — печать накладывается ниже, для этого новичка.
                secret: group::ChainSecret::Open { chain: chain.chain, counter: chain.counter },
                // Метка едет **чужая**, как лежит. Выдай мы здесь свою,
                // новичок сравнивал бы часы владельца цепочки с нашими,
                // и наша пересылка могла бы обогнать поворот владельца —
                // то есть надолго закрепить у новичка мёртвый ключ.
                chain_hlc: Hlc::new(chain.chain_wall, chain.chain_logical),
            };
            let value = self.sender_key_for(&block, newcomer)?;
            effects.extend(self.tell_member(now_ms, newcomer, PayloadType::SenderKey, value)?);
        }
        Ok(effects)
    }

    /// Ставит один групповой кадр в очередь §5.4.
    ///
    /// Через `enqueue_request`, то есть **без строки в истории**: состав,
    /// карточки и ключи — не сообщения, и в чате им делать нечего. Зато
    /// им достаётся вся лестница транспортов: группа, собравшаяся почтой,
    /// обязана собраться и через неё.
    pub(super) fn tell_member(
        &mut self,
        now_ms: u64,
        member: [u8; 32],
        payload_type: PayloadType,
        payload: Value,
    ) -> Result<Vec<Effect>, EngineError> {
        // Участник, которого мы не знаем как контакт, встречается законно:
        // его добавил кто-то другой, а карточка до нас ещё не доехала.
        // Слать ему нечем и незачем — тот, кто его пригласил, расскажет ему
        // всё сам.
        //
        // **Пир — знаем** (§8.3): у впущенного в канал читателя карточка
        // приехала рукопожатием, а контактом он не стал и не станет,
        // пока не заговорит лично. Не будь этой строки, впуск §10.4 отдавал
        // бы новичку пустоту — и починка приёмной стороны сломала бы
        // каналы целиком.
        if !self.contacts.contains_key(&member) && !self.peers.contains_key(&member) {
            return Ok(Vec::new());
        }
        let (_, effects) = self.enqueue_request(now_ms, member, payload_type, payload)?;
        Ok(effects)
    }

    /// Подписывает свои операции состава, кладёт их на диск и отдаёт нагрузку.
    ///
    /// Три записи одним движением, и порознь их делать нельзя: разложенные
    /// операции — то, из чего состав собирается, подписанный блок — то, чем
    /// его доказывают новичку (§11.5), а нагрузка — то, что уедет. Разойдись
    /// они, состав у нас и у остальных разошёлся бы молча.
    pub(super) fn record_own_ops(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        ops: &[OrSetOp<ActorId>],
    ) -> Result<Value, EngineError> {
        let me = self.identity.public().ik;
        let block = group::MembershipBlock { group: chat, author: me, ops: ops.to_vec() };
        let payload = group::signed_membership(&self.identity, &block)?;
        let bytes = ratatosk_codec::canonical::encode(&payload)?;

        self.store.put_membership(&chat, &Self::stored_from_ops(ops))?;
        self.store.put_membership_block(
            &chat,
            &StoredMembershipBlock {
                block_id: Self::block_id(&bytes),
                author_ik: me,
                bytes,
                received_ms: now_ms,
            },
        )?;
        Ok(payload)
    }

    /// Идентификатор подписанного блока — хэш его байт.
    ///
    /// По проводу не едет ни разу: это ключ строки в хранилище, и нужен он
    /// одному — чтобы тот же блок, пришедший вторым транспортом (§9.2),
    /// лёг в ту же строку.
    pub(super) fn block_id(bytes: &[u8]) -> [u8; 16] {
        let full = ratatosk_crypto::kdf::derive(ratatosk_crypto::labels::GROUP_BLOCK, bytes);
        full[..16].try_into().expect("срез длины 16")
    }

    /// Заводит новую цепочку отправителя для этой группы (§11.5).
    ///
    /// Не продвигает старую, а **заменяет** её случайным секретом: продвижение
    /// вперёд знающему прежнее состояние ничего не закрывает — оно из него
    /// и выводится. Смысл требования §11.5 в том, чтобы новичок не мог
    /// вывести ключи прошлых сообщений, а этого достигает только новый
    /// секрет.
    ///
    /// # Метка поворота
    ///
    /// Каждый поворот получает метку наших часов, и она уезжает вместе
    /// с ключом. Без неё два приглашения подряд пускают в провод два
    /// объявления одной цепочки с одинаковым номером — после поворота он
    /// всегда нулевой, — а §9.2 разрешает их переставить. Получатель тогда
    /// оставляет себе пришедшее последним, и в половине случаев это
    /// опоздавшее: номер верный, ключ мёртвый, дальше наши сообщения у него
    /// молча не открываются.
    pub(super) fn rotate_sender_chain(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<group::SenderKeyBlock, EngineError> {
        let me = self.identity.public().ik;
        let mut fresh = [0u8; 32];
        self.entropy.fill(&mut fresh);
        let chain = SenderChain::new(zeroize::Zeroizing::new(fresh));
        let hlc = self.clock.now(now_ms)?;
        let stored = StoredSenderChain {
            member_ik: me,
            chain: *chain.export(),
            counter: chain.counter(),
            chain_wall: hlc.wall_ms,
            chain_logical: hlc.logical,
            skipped: Vec::new(),
        };
        self.store.put_sender_chain(&chat, &stored)?;
        Ok(group::SenderKeyBlock {
            group: chat,
            member: me,
            secret: group::ChainSecret::Open { chain: stored.chain, counter: stored.counter },
            chain_hlc: hlc,
        })
    }

    /// Карточки участников группы, кроме одного (§11.5).
    ///
    /// Исключается получатель: свою карточку он знает лучше нас, а прислать
    /// её обратно значило бы дать ему повод обновить себя же нашей копией.
    ///
    /// Участник, чьей карточки у нас нет, просто не попадает в список.
    /// Так бывает законно: его добавил кто-то другой, и до нас карточка
    /// ещё не доехала. Врать про него нечем, а молчание здесь честнее
    /// пустой записи.
    pub(super) fn roster_for(
        &self,
        chat: ChatId,
        except: [u8; 32],
        cards: &BTreeMap<[u8; 32], Vec<u8>>,
    ) -> group::Roster {
        let Some(state) = self.groups.get(&chat) else {
            return group::Roster { group: chat, cards: Vec::new() };
        };
        let cards = state
            .group
            .members()
            .filter(|member| **member != except)
            .filter_map(|member| cards.get(member).cloned())
            .collect();
        group::Roster { group: chat, cards }
    }

    /// Байты карточек: свои и всех известных контактов, по `IK`.
    ///
    /// **С диска, а не пересобранные из полей.** Карточка контакта хранится
    /// теми байтами, которыми приехала (§6). Каноническое кодирование
    /// однозначно, и пересборка почти наверняка дала бы те же байты —
    /// «почти» тут лишнее слово: карточка чужой версии может нести поля,
    /// которых наш разбор не знает, и пересобранная она их потеряет.
    ///
    /// Своя собирается здесь же: её каноническое кодирование и есть то,
    /// что мы объявляем (§4.3), — принятых байт у неё не бывает.
    ///
    /// Один заход в хранилище на всё приглашение, а не по заходу
    /// на участника: тридцать два участника — это тридцать два обхода
    /// списка контактов.
    pub(super) fn cards_by_ik(&self) -> Result<BTreeMap<[u8; 32], Vec<u8>>, EngineError> {
        let mut cards: BTreeMap<[u8; 32], Vec<u8>> =
            self.store.contacts()?.into_iter().map(|c| (c.ik, c.card_bytes)).collect();
        cards.insert(self.identity.public().ik, self.own_card().encode()?);
        Ok(cards)
    }

    /// Принимает представление группы — и заводит её у себя (§11.5).
    ///
    /// **Только если группы ещё нет.** Владелец не меняется никогда (§11.2):
    /// принять второе представление значило бы позволить любому участнику
    /// переписать право исключать. Название тоже своё — рассылки
    /// переименований v1 не описывает, и второе представление затёрло бы
    /// то, что человек уже видит в списке.
    ///
    /// Своей цепочки отправителя у нас в новой группе нет — её здесь
    /// и заводим, и тут же рассылаем: без неё наши сообщения никому
    /// не откроются. Это та самая «новая цепочка при вступлении» (§11.5),
    /// вид со стороны вступающего.
    pub(super) fn on_group_intro(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        payload: &Value,
    ) -> Result<Vec<Effect>, EngineError> {
        let Ok(intro) = group::intro_from_value(payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        if self.groups.contains_key(&intro.group) {
            // **Группу знаем — но картинку из блока всё равно берём.**
            //
            // Подписчик канала знает его **всегда**: чат заводится
            // подпиской по ссылке, задолго до впуска. Пока здесь стоял
            // один ранний выход, вводный блок у него пропадал целиком —
            // а картинки у канала другой дороги нет: название едет
            // представлением (§6.1), а картинка только этим блоком.
            // Снаружи это выглядело так, как описал живой прогон:
            // «аватарку канала поставить можно, а у подписчиков она
            // не показывается — при том что имя и его смену они видят».
            //
            // Берём **только у владельца**: у знакомой группы нам уже
            // есть с чем сверить, и принимать картинку от любого
            // участника значило бы разрешить каждому её подменить. Тот
            // же довод, что у `Action::Avatar`, где проверка стоит
            // с самого начала.
            //
            // Метка — приехавшая, и спор решает она же
            // (`apply_group_avatar`): опоздавшая копия не затирает
            // новую.
            //
            // **Проверка «только владелец» проверкой не покрыта, и
            // покрыть её нечем.** Своей сборкой вводный блок шлёт лишь
            // тот, кто впускает, и картинку он берёт из своей же базы —
            // то есть ту же самую. Чтобы подменить её, нужен кадр чужой
            // сборки, а такого пути в стенде нет. Строка стоит против
            // неё и против собственной завтрашней ошибки; написано
            // здесь, чтобы «непокрыто» завтра не прочли как «покрыто».
            //
            // Цена этой строгости названа: если впускает **делегат**
            // с правом `ADMIT` (§6.2), картинка канала до впущенного
            // не доедет — делегат владельцем не является. Дождётся
            // следующей смены картинки, которую владелец развезёт сам.
            let owner_speaks =
                self.groups.get(&intro.group).is_some_and(|state| state.group.owner == peer_ik);
            if owner_speaks
                && intro.avatar_hlc != Hlc::default()
                && self.apply_group_avatar(intro.group, &intro.avatar, intro.avatar_hlc)?
            {
                return Ok(vec![Effect::Notify(Event::GroupAvatarChanged { chat: intro.group })]);
            }
            return Ok(Vec::new());
        }

        self.store.put_group(&StoredGroup {
            chat_id: intro.group,
            owner_ik: intro.owner,
            title: intro.title.clone(),
            // Метка приехала вместе с названием. Поставь мы здесь свою —
            // переименование, случившееся до нашего вступления и доехавшее
            // после, было бы отвергнуто как устаревшее.
            title_wall: intro.title_hlc.wall_ms,
            title_logical: intro.title_hlc.logical,
            created_ms: now_ms,
            // Порода — из вводного блока. Он её несёт с фазы 2; сборка
            // фазы 1 поля не шлёт, и тогда здесь `closed`, что для неё
            // и верно. Верить приглашающему тут приходится ровно в той
            // же мере, что и названию, — а подписанное представление
            // скажет то же самое и подписью (§10.3).
            profile: intro.profile.code(),
        })?;
        self.groups.insert(
            intro.group,
            GroupState {
                // `restore`, а не `create`: состав придёт операциями,
                // и выдуманная здесь метка владельца сделала бы его
                // неисключаемым (см. `Group::restore`).
                group: Group::restore(intro.group, intro.owner),
                title: intro.title.clone(),
                title_hlc: intro.title_hlc,
                // Картинка кладётся ниже, своим правилом: здесь метка
                // нулевая, чтобы это правило было **одно** на все три
                // дороги — свою смену, чужую и вводный блок.
                avatar_hlc: Hlc::default(),
                created_ms: now_ms,
                // Порода — из вводного блока, та же, что легла строкой
                // чата выше. Поставь здесь умолчание, и в памяти был бы
                // один ответ, а на диске другой: до перезапуска канал
                // вёл бы себя группой.
                profile: intro.profile,
            },
        );
        // Картинка приехала вместе с меткой, и метка ложится та, что
        // приехала: поставь мы свою, настоящая новая была бы отвергнута
        // как опоздавшая. Негодные байты сюда не доходят — их отбросил
        // разбор представления, не сорвав вступления.
        if intro.avatar_hlc != Hlc::default() {
            self.apply_group_avatar(intro.group, &intro.avatar, intro.avatar_hlc)?;
        }

        // **Чат объявляется тем, что он есть.** Вводный блок несёт породу
        // (§3.2), и канал, приехавший `GroupCreated`, заставил бы клиента
        // нарисовать групповой экран со списком участников — которого
        // в канале не существует, — а потом править его задним числом.
        //
        // Порода (открытый или по приглашению) здесь неизвестна: вводный
        // блок несёт профиль, а порода живёт в подписанном представлении
        // (§6.1) и приедет следом. `None` это и означает.
        let appeared = if intro.profile.everyone_writes() {
            Event::GroupCreated { chat: intro.group, title: intro.title }
        } else {
            Event::ChannelCreated { chat: intro.group, title: intro.title, open: None }
        };
        let mut effects = vec![Effect::Notify(appeared)];
        // Ключ заводится сразу, а рассылается тем, кого мы уже знаем.
        // Состав в этот миг обычно пуст — блоки ещё не разобраны, — и
        // остальным он уедет из разбора отложенного, когда они появятся.
        let mine = self.rotate_sender_chain(now_ms, intro.group)?;
        effects.extend(self.announce_sender_key(now_ms, intro.group, &mine)?);
        Ok(effects)
    }

    /// Переименовывает группу.
    ///
    /// **Дополнение к спецификации:** §11 рассылки названия не описывает.
    ///
    /// # Вправе только создатель
    ///
    /// Правило §11.2 расширено по смыслу, а не сломано: создатель
    /// распоряжается тем, что относится ко всей группе — удалением
    /// из состава и её именем, — а участники только ростом состава.
    ///
    /// Цена названа вслух в `LeaveConsequences::owner_text`: создатель,
    /// вышедший из группы, уносит с собой и это.
    ///
    /// # Порядок: сперва кадр, потом своё
    ///
    /// Метка названия берётся **из собранного конверта**, а не считается
    /// отдельно. Посчитай мы её здесь заново — у нас название легло бы
    /// на одну метку, у остальных на другую, и следующее переименование
    /// одни приняли бы, а другие отвергли. Ровно то же решение, что
    /// у реакции.
    pub(super) fn on_rename_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        title: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let title = title.trim();
        // Те же два предела, что при заведении, и в том же порядке:
        // человек нажал кнопку и обязан узнать почему (§14).
        if title.is_empty() {
            return Err(EngineError::GroupTitleEmpty);
        }
        if title.chars().count() > MAX_GROUP_TITLE_CHARS {
            return Err(EngineError::GroupTitleTooLong);
        }

        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        // «Только создатель» (§11.2) — правило группы. В канале название
        // правит и держатель права «менять представление» (§6.2), поэтому
        // владелец спрашивается ниже, внутри канальной ветки.
        if state.profile.everyone_writes() && state.group.owner != me {
            return Err(group::GroupError::NotOwner.into());
        }
        // **У канала имя живёт в подписанном представлении (§6.1), а не
        // в действии переименования.** Иначе у названия два хозяина:
        // строка чата у владельца меняется действием, а читателю приезжает
        // документ со **старым** именем и молча возвращает его обратно.
        // Ровно так это и выглядело бы после починки пустого имени
        // у читателя: один переименовал, у всех осталось прежнее.
        //
        // Предел в байтах здесь свой: документ подписывается и едет
        // ссылкой, и §6.1 меряет название байтами, а не знаками.
        if !state.profile.everyone_writes() {
            if title.len() > channel::MAX_TITLE_BYTES {
                return Err(EngineError::GroupTitleTooLong);
            }
            // **Право — первым.** У держателя `EDIT` оно есть, и отказ
            // «нет права» посоветовал бы просить то, что уже дали.
            self.check_may_put(now_ms, chat, channel::Rights::EDIT)?;
            // Владелец — по документу (`channel_owner`): им подписывается
            // новая версия, и строка чата тут не судья.
            if self.channel_owner(chat) == Some(me) {
                let named = title.to_owned();
                let mut effects =
                    self.publish_representation(now_ms, chat, move |next| next.title = named)?;
                // Своя строка чата — тем же шагом: `publish_representation`
                // трогает документ, а список чатов живёт в `chats`.
                let at = self.clock.now(now_ms)?;
                if self.apply_rename(chat, title, at)? {
                    effects.push(Effect::Notify(Event::GroupRenamed {
                        chat,
                        title: title.to_owned(),
                    }));
                }
                return Ok(effects);
            }
            // **Держатель права «менять представление» правит название
            // действием** (§6.2): подписать документ он не может — подпись
            // одна, владельца, — и потому действие едет той же дорогой,
            // что слово: владельцу и своим сидам (`push_candidates`).
            // Владелец, приняв его, подписывает новую версию документа
            // с этим названием (`apply_group_action`), и у читателей
            // название сходится к подписанному, а не к тому, чей кадр
            // приехал последним.
            //
            // До этой поставки право `EDIT` было мёртвым: команда отказывала
            // «не владелец» ещё до вопроса о праве, и выдать его было
            // можно, а воспользоваться — нет.
            let action = ratatosk_proto::group_action::Action::Rename { title: title.to_owned() };
            let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;
            self.apply_rename(chat, title, hlc)?;
            let mut effects = self.spread_in_chat(now_ms, chat, msg_id, &bytes)?;
            effects.push(Effect::Notify(Event::GroupRenamed { chat, title: title.to_owned() }));
            return Ok(effects);
        }
        // Состоим ли — не спрашиваем: спросит сборка кадра, и её отказ
        // (`NotInGroup`) точнее. Вышедший создатель попадёт именно сюда.
        let action = ratatosk_proto::group_action::Action::Rename { title: title.to_owned() };
        let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        self.apply_rename(chat, title, hlc)?;
        let mut effects = self.fan_out_group(now_ms, chat, msg_id, &bytes)?;
        effects.push(Effect::Notify(Event::GroupRenamed { chat, title: title.to_owned() }));
        Ok(effects)
    }

    /// Кладёт новое название — если оно новее того, что лежит.
    ///
    /// **Одно место на своё переименование и на чужое.** Сравнение стоит
    /// и здесь, и в `INSERT` хранилища, и это не лишнее: в память оно
    /// кладёт то же, что на диск, а хранилище отвечает за то, что переживёт
    /// перезапуск. Разъедься они — после перезапуска название менялось бы
    /// само.
    ///
    /// Отдаёт `true`, если название действительно сменилось: по этому
    /// признаку решается, говорить ли о нём наружу.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn apply_rename(
        &mut self,
        chat: ChatId,
        title: &str,
        at: Hlc,
    ) -> Result<bool, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(false) };
        if at < state.title_hlc {
            // Опоздавшее переименование (§9.2). Молча: это не порча
            // и не нападение, а обогнавшая его копия того же человека.
            return Ok(false);
        }
        let owner = state.group.owner;
        let created_ms = state.created_ms;
        // Профиль везётся **из состояния**, а не ставится умолчанием.
        // `put_group` здесь переписывает строку целиком ради названия,
        // и поставь мы тут `Closed` — переименование канала понижало бы
        // его до группы. В SQL от этого стоит `max`, но полагаться
        // на сторож вместо того, чтобы не портить, значит заводить
        // поломку и надеяться, что её поймают.
        let profile = state.profile.code();
        self.store.put_group(&StoredGroup {
            chat_id: chat,
            owner_ik: owner,
            title: title.to_owned(),
            title_wall: at.wall_ms,
            title_logical: at.logical,
            created_ms,
            profile,
        })?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.title = title.to_owned();
            state.title_hlc = at;
        }
        Ok(true)
    }

    /// Меняет аватарку группы (§11 + дополнение).
    ///
    /// # Вправе только создатель
    ///
    /// То же правило, что у названия, и та же причина: он распоряжается
    /// тем, что относится ко всей группе. Цена названа вслух в
    /// `LeaveConsequences::owner_text` — вышедший создатель уносит с собой
    /// и это.
    ///
    /// # Порядок: сперва кадр, потом своё
    ///
    /// Метка берётся **из собранного конверта**, ровно как у
    /// переименования. Посчитай мы её здесь заново — картинка легла бы
    /// у нас на одну метку, у остальных на другую, и следующую смену
    /// одни приняли бы, а другие отвергли.
    ///
    /// # Правила §4.2 здесь нет
    ///
    /// Картинка уходит **всем** участникам, сверенным и нет. Полное
    /// рассуждение — в `ratatosk_proto::avatar`; коротко: она отвечает
    /// не на вопрос «кто этот человек», а на вопрос «какой это разговор»,
    /// и участников группы ядро заводит несверенными (§11.5).
    pub(super) fn on_set_group_avatar(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Предел и сигнатура — те же, что у своего лица, и проверяются
        // до всего остального: человек нажал кнопку и обязан узнать
        // почему (§14).
        ratatosk_proto::avatar::check(bytes)?;

        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        // В группе — только создатель (§11.2). В канале картинку правит
        // и держатель права «менять представление» (§6.2): право спросит
        // сборка кадра (`Gate::Right(EDIT)`), а дорогу ему даёт рой —
        // тем же путём, что и переименование.
        let (in_a_group, i_own) = (state.profile.everyone_writes(), state.group.owner == me);
        if in_a_group && !i_own {
            return Err(group::GroupError::NotOwner.into());
        }
        // Состоим ли — спросит сборка кадра, и её отказ (`NotInGroup`)
        // точнее: вышедший создатель ушёл сам.
        let action = ratatosk_proto::group_action::Action::Avatar { bytes: bytes.to_vec() };
        let (msg_id, hlc, frame) = self.seal_group_action(now_ms, chat, &action)?;

        self.apply_group_avatar(chat, bytes, hlc)?;
        if !in_a_group && !i_own {
            let mut effects = self.spread_in_chat(now_ms, chat, msg_id, &frame)?;
            effects.push(Effect::Notify(Event::GroupAvatarChanged { chat }));
            return Ok(effects);
        }
        // **Дорогой документа** (`push_document`), а не веером: у канала
        // получателей знает рой, и у открытого канала веер означал
        // «никому» — состава у него нет вовсе (§10.4). В группе эта же
        // строка остаётся веером: там состав и есть список получателей.
        let mut effects = self.push_document(now_ms, chat, msg_id, &frame)?;
        effects.push(Effect::Notify(Event::GroupAvatarChanged { chat }));
        Ok(effects)
    }

    /// Кладёт аватарку группы — если она новее той, что лежит.
    ///
    /// **Одно место на свою смену, на чужую и на ту, что приехала
    /// с вводным блоком**, ровно как у названия. Сравнение стоит и здесь,
    /// и в `INSERT` хранилища: в память оно кладёт то же, что на диск,
    /// а разъедься они — после перезапуска картинка менялась бы сама.
    ///
    /// Отдаёт `true`, если картинка действительно сменилась: по этому
    /// признаку решается, говорить ли о ней наружу.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn apply_group_avatar(
        &mut self,
        chat: ChatId,
        bytes: &[u8],
        at: Hlc,
    ) -> Result<bool, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(false) };
        if at < state.avatar_hlc {
            // Опоздавшая копия (§9.2) — своя же, обогнанная по дороге.
            // Молча: это не порча и не нападение.
            return Ok(false);
        }
        self.store.put_group_avatar(
            &chat,
            &ratatosk_store::StoredGroupAvatar {
                bytes: bytes.to_vec(),
                avatar_wall: at.wall_ms,
                avatar_logical: at.logical,
            },
        )?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.avatar_hlc = at;
        }
        Ok(true)
    }

    /// Выходит из группы.
    ///
    /// **Дополнение к спецификации:** §11.2 выхода не описывает. Изнутри
    /// протокола это та же операция состава, что исключение, — разнятся они
    /// только тем, кто её подписал, и потому правило приёма проверяет
    /// именно это (см. [`Engine::on_membership_block`]).
    ///
    /// # Блок уезжает всем, включая тех, кого мы уже не увидим
    ///
    /// Получателей берём **до** применения: после него нас в составе нет,
    /// а сказать надо всем, кто был. Не скажи мы — остальные продолжали бы
    /// слать нам копии каждого слова, а мы бы их выбрасывали. Тихий выход
    /// стоил бы им трафика, а нам — молчаливого расхождения составов.
    ///
    /// # Цепочка не меняется, и это то же решение, что у §11.4
    ///
    /// Ротация нужна при **вступлении** (§11.5) — она закрывает окно перед
    /// новичком. Уход окна не открывает: прошлое ушедший уже прочёл, и
    /// менять ключи поздно. Ровно то же сказано про исключение.
    pub(super) fn on_leave_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        let op = state.group.leave(me)?;
        let targets: Vec<[u8; 32]> = state.group.members().copied().filter(|m| *m != me).collect();

        let block = self.record_own_ops(now_ms, chat, std::slice::from_ref(&op))?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.group.apply(op);
        }

        let mut effects = Vec::new();
        for member in targets {
            effects.extend(self.tell_member(
                now_ms,
                member,
                PayloadType::GroupMembership,
                block.clone(),
            )?);
        }
        effects.push(Effect::Notify(Event::GroupMembershipChanged { chat }));
        Ok(effects)
    }

    /// Принимает подписанное изменение состава (§11.2).
    ///
    /// Подпись проверяется **известным** ключом — тем, что лежит в карточке
    /// автора, а не тем, что назван в блоке. Ключ из самого сообщения
    /// подтверждал бы только владение каким-то ключом; ровно от этой ошибки
    /// бережётся и `card_update`.
    ///
    /// Автор, которого мы не знаем, — законный случай: его карточка едет
    /// отдельным кадром и может опоздать. Блок откладывается, а не
    /// отбрасывается.
    pub(super) fn on_membership_block(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        chat: ChatId,
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let payload = &envelope.payload;
        let Ok(unchecked) = group::parse_membership(payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        let author = *unchecked.claims_author();
        let Some(known) = self.public_identity_of(&author)? else {
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(Vec::new());
        };
        let Ok(block) = unchecked.verify(&known) else {
            // Подпись не сошлась — это уже не опоздание, а подделка либо
            // порча. Аномалия считается тому, кто принёс.
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };

        // §11.2: **исключать может только создатель.** Приглашать — любой
        // участник, и потому одной подписи для добавления довольно; для
        // удаления — нет.
        //
        // Проверка стоит **до записи на диск**, и это не мелочь. Ляг такой
        // блок в историю — он применился бы на следующем же подъёме, минуя
        // всякую проверку, и участник, исключённый кем попало, исчез бы
        // после перезапуска.
        //
        // Блок отвергается целиком, а не по операции: смешанный блок
        // от не-создателя это нарушение §11.2 его автором, а разбирать
        // такой по частям значит завести правило, которого в спецификации
        // нет.
        //
        // **И одно исключение — выход.** Дополнение к спецификации: удалить
        // себя вправе кто угодно, и подписать это за другого нельзя, потому
        // что удаляемый обязан совпасть с автором блока. Ослаблением
        // правила §11.2 это не является: власть над **чужим** членством
        // осталась там же, где была.
        //
        // Само правило живёт в `group::removal_allowed`, а не здесь.
        // Здесь его нельзя было проверить иначе как двумя узлами, сессией
        // и подделанным блоком — то есть не проверял никто.
        let owner = self.groups[&chat].group.owner;
        if !group::removal_allowed(author, owner, &block.ops) {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        let bytes = ratatosk_codec::canonical::encode(payload)?;
        self.store.put_membership_block(
            &chat,
            &StoredMembershipBlock {
                block_id: Self::block_id(&bytes),
                author_ik: author,
                bytes,
                received_ms: now_ms,
            },
        )?;
        self.store.put_membership(&chat, &Self::stored_from_ops(&block.ops))?;

        let me = self.identity.public().ik;
        let before: BTreeSet<[u8; 32]> = self.groups[&chat].group.members().copied().collect();
        if let Some(state) = self.groups.get_mut(&chat) {
            for op in block.ops {
                state.group.apply(op);
            }
        }
        let after: BTreeSet<[u8; 32]> = self.groups[&chat].group.members().copied().collect();
        if before == after {
            // Блок применился, но состав тот же: повтор вторым транспортом
            // (§9.2) либо добавление, уже погашенное известным нам
            // удалением. Рассказывать об этом нечего.
            return Ok(Vec::new());
        }

        // **Ушедший выпадает и из каталога** (§7.5).
        //
        // Запись раздающего живёт сроком, а не отзывом: «перестал
        // продлевать — выпал», и до конца срока это неделя. Всё это
        // время читатели привязываются к тому, кто из канала ушёл
        // и обслуживать их больше не станет — `may_serve` у него
        // отвечает «нет», потому что канала у него нет вовсе. Снаружи
        // это выглядит как «часть подписчиков замолчала», и чинит
        // само остывание §7.7 — четверть часа спустя.
        //
        // Владелец узнаёт об уходе первым (§10.6, блок ухода едет ему),
        // и у себя он запись убирает сразу: дальше её никто не получит
        // ни впуском, ни ответом на просьбу. Чужие копии остаются
        // до срока — отзыва §7.5 не знает, — но новых не появляется.
        for gone in before.difference(&after) {
            if let Err(error) = self.store.delete_seed(&chat, gone) {
                tracing::warn!(?error, "запись ушедшего не убралась из каталога");
            }
        }

        let mut effects = vec![Effect::Notify(Event::GroupMembershipChanged { chat })];
        // §11.5: «при вступлении каждый участник обязан начать новую
        // sender-цепочку». Обязан **каждый**, а не только пригласивший, —
        // иначе окно, которое требование ограничивает, не закрывается
        // ни у кого, кроме него.
        //
        // **И при убыли состава — тоже, а раньше не поворачивалось.**
        // Здесь стояло «менять поздно, прошлое он уже прочёл», и про
        // прошлое это верно: оно у ушедшего останется, забрать нельзя.
        // Про **будущее** было неверно. Цепочка идёт вперёд от состояния,
        // которое у него на руках, — значит не повернув её, мы оставляем
        // ему всё, что напишем дальше. Исключение было социальным ровно
        // поэтому (§11.4), и вот это и чинится.
        //
        // Уход по своей воле считается так же: правило смотрит на состав,
        // а не на причину. Прочитать будущее ушедший сам может ничуть
        // не хуже исключённого.
        // Прибыль состава цепочку больше не трогает — разбор у приглашения
        // (`on_invite_to_group`). Но **объявить** её прибывшим надо: нашей
        // цепочки они не знают, а раньше она уезжала прицепом к повороту.
        // Без этого сообщения новых участников до нас доходят, а наши
        // до них — нет: у них нашего ключа попросту нет.
        let joined = after.difference(&before).any(|who| *who != me);
        let left = before.difference(&after).any(|who| *who != me);
        // **Вывели нас самих — поворачивать нечего и некому:** объявление
        // ушло бы тем, кто нас участником больше не считает.
        //
        // Условие именно «были и не стало», а не «нет в составе». Второе
        // выглядит тем же самым и ломает законный случай: блоки состава
        // приезжают в любом порядке (§9.2), и «А добавил Б» вправе прийти
        // раньше, чем «А добавил нас». В тот миг нас нет ни в `before`,
        // ни в `after` — но мы не уходили, и цепочку завести обязаны,
        // иначе наши сообщения не откроются ни у кого. На этом и
        // споткнулся стенд: у двоих из троих сообщение третьего осталось
        // лежать отложенным.
        let we_left = before.contains(&me) && !after.contains(&me);
        if !we_left {
            // Убыль — новый секрет (§11.4): ушедший идёт по старой цепочке
            // вперёд сам. Прибыль — та же цепочка, просто сказанная вслух.
            let mine = if left {
                self.rotate_sender_chain(now_ms, chat)?
            } else if joined {
                self.current_sender_key(chat)?
            } else {
                return Ok(effects);
            };
            effects.extend(self.announce_sender_key(now_ms, chat, &mine)?);
        }
        Ok(effects)
    }

    /// Принимает карточки участников (§11.5).
    ///
    /// Заводит их **несверенными контактами** (§4.2), и это ровно то, о чём
    /// предупреждает `group::JOIN_DISCLOSURE`: вступление раскрывает адреса
    /// друг друга. Иначе с ними не поговорить — контакт здесь не только
    /// знакомство, но и то, куда слать.
    ///
    /// Список принимается только от участника: иначе любой контакт пополнял
    /// бы наш список знакомых, не спросив.
    pub(super) fn on_group_roster(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        chat: ChatId,
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let Ok(roster) = group::roster_from_value(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };
        let me = self.identity.public().ik;
        // **В канале список карточек заводит пиров, а не контактов**
        // (§8.3, приёмная сторона). Читателю при впуске приезжают двое —
        // владелец и впустивший (§10.4), — и разговаривал он ни с тем,
        // ни с другим: у него нет к ним ни чата, ни повода. Карточки
        // нужны обе (подпись представления и подпись впуска), а место им
        // в записи пира.
        //
        // У группы правило обратное и остаётся: §11.5 прямо обещает, что
        // участники увидят адреса друг друга.
        let as_peers = self.groups.get(&chat).is_some_and(|state| !state.profile.everyone_writes());
        // Отправитель ещё не значится участником — и это, скорее всего,
        // не самозванец, а порядок: блоки состава могли отстать от списка
        // (§9.2). Кадр откладывается, а не отбрасывается; чужой так и
        // пролежит до вытеснения, потому что участником не станет.
        //
        // **В канале список берётся от любого**, и это разбор впуска
        // делегатом. Список от впустившего приезжает **раньше** блока,
        // которым он нас впустил, а тот блок проверяется карточкой из этого
        // же списка: требуй мы здесь участия — список ждал бы блока, блок
        // ждал бы списка, и впущенный делегатом не читал бы ничего.
        // Цена малая: в канале список заводит пиров, а не контактов,
        // и карточка в нём подписана своим же ключом.
        if !as_peers && !self.counts_as_member(chat, &peer_ik) {
            self.park_group_frame(PendingGroup { chat, envelope: envelope.clone(), peer_ik });
            return Ok(Vec::new());
        }
        let mut effects = Vec::new();
        for card_bytes in roster.cards {
            // Карточка чужой сборки может не разобраться — это не повод
            // выбросить остальные: список собирал не тот, кто её написал.
            let Ok(card) = ContactCard::decode(&card_bytes) else { continue };
            let who = card.value().ik;
            if who == me {
                continue;
            }
            // **Знакомый пропускается целиком, и это не экономия.**
            // `add_contact` ставит `verified` по своему аргументу, а не
            // сохраняет прежнее значение, — значит список карточек снял бы
            // сверку §4.2 с человека, которого мы сверяли голосом. Обновлять
            // карточку знакомого есть кому: §4.3 везёт её **подписанной**,
            // и неподписанный список не вправе её вытеснять.
            //
            // Тем же приёмом бережётся приём рукопожатия: там `add_contact`
            // зовут только для незнакомца.
            if self.contacts.contains_key(&who) {
                continue;
            }
            if as_peers {
                effects.extend(self.remember_card_from_channel(now_ms, &card_bytes)?);
                continue;
            }
            // `met_in_person: false` — сверки здесь нет и быть не может.
            // За карточку ручается пригласивший, а поручительство сверкой
            // голосом не является (§4.2).
            effects.extend(self.add_contact(now_ms, &card_bytes, false)?);
        }
        Ok(effects)
    }

    /// Отправляет сообщение в группу.
    ///
    /// # Одно сообщение, тридцать две копии
    ///
    /// Конверт собирается **один** — с одним `msg_id` и одной меткой HLC, —
    /// и его байты уезжают каждому участнику по его 1:1-каналу (§11.3).
    /// Отсюда то, ради чего sender key вообще нужен: у всех получателей
    /// это буквально одно и то же сообщение, а не тридцать два похожих.
    ///
    /// # Почему у него нет статуса доставки
    ///
    /// Один значок на тридцать двух получателей — обещание, которого
    /// протокол не даёт. «Доставлено» после того, как дошло одному, — ложь;
    /// «не доставлено» после того, как не дошло одному, — тоже. §14 запрещает
    /// и то и другое, а «доставлено пятерым из семи» это уже другая работа,
    /// и она не сделана.
    ///
    /// Держится это на одном поле — [`Delivery::silent`]: такая копия
    /// не ждёт квитанции, её попытка закрывается записью в сокет, и в очередь
    /// §5.4 она не попадает. Статуса, стало быть, взяться неоткуда.
    ///
    /// Первая написанная версия обходилась без поля — разводила номер записи
    /// в очереди и номер конверта, — и это была ошибка: квитанцию адресуют
    /// **номеру конверта**, и разведя их, попытка по прямому каналу
    /// не закрывалась бы никогда.
    /// Проверяет, что мы вправе положить это в чат (фаза 2, §6.2).
    ///
    /// # Первое место, где профили расходятся
    ///
    /// До сих пор канал был группой во всём. Здесь появляется различие,
    /// и оно спрашивается **словами**: `profile.everyone_writes()`,
    /// а не сравнение с `Closed`. В `closed` пишут все, кто состоит, —
    /// вопроса о праве там не существует (§3.2).
    ///
    /// # Почему два чокпоинта, а не двенадцать
    ///
    /// Всё, что участник кладёт в чат, проходит ровно через два места:
    /// [`Engine::send_group_text`] (слова) и [`Engine::seal_group_action`]
    /// (всё остальное — правка, отзыв, реакция, ответ, файлы, пересылка,
    /// карточка, название, картинка). Оба зовут эту проверку, и потому
    /// забыть её негде: новый вид того, что можно сказать, обязан пройти
    /// через один из них, иначе у него не будет ни номера в цепочке,
    /// ни ключа сообщения.
    ///
    /// Какое право требует какое действие — говорит
    /// [`ratatosk_proto::group_action::Action::needs_right`], и список
    /// там один.
    ///
    /// # Состав спрашивается первым, и порядок значим
    ///
    /// Не состоишь — `NotInGroup`; состоишь без права —
    /// `NotAllowedInChannel`. Поменяй порядок, и посторонний узнавал бы
    /// из отказа, что у него нет **права** в канале, о котором ему знать
    /// неоткуда.
    ///
    /// # Чтение представления на каждую отправку
    ///
    /// Один запрос к разобранной таблице выдач по индексу. Держать
    /// представление в памяти рядом с `GroupState` было бы быстрее,
    /// но завело бы второе место, где живут права, и обязанность
    /// согласовывать его с диском при каждом приёме новой версии.
    /// Если это когда-нибудь станет дорого — мерить надо это, а не гадать.
    pub(super) fn check_may_put(
        &self,
        now_ms: u64,
        chat: ChatId,
        right: channel::Rights,
    ) -> Result<(), EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if !state.group.contains(&me) {
            return Err(EngineError::NotInGroup);
        }
        if self.right_holds(now_ms, chat, &me, right)? {
            Ok(())
        } else {
            Err(EngineError::NotAllowedInChannel)
        }
    }

    /// Есть ли кому развезти то, что расходится **веером** (§3.2, §7.5.2).
    ///
    /// # Право есть — а доставлять некому
    ///
    /// Веером в чате возит сказавший, по своему составу. Состав канала
    /// §3.2 оставляет владельцу: читатели друг друга не знают, и у
    /// держателя права «писать» список получателей пуст. «Сказал»
    /// означало бы «сказал в стол», а §14 запрещает обещать доставку,
    /// которой не будет.
    ///
    /// Раньше делегат доставлял — но лишь потому, что впуск раскрывал
    /// состав всем подряд, то есть ценой самого свойства, ради которого
    /// заведена фаза 2. Раскрытие снято; доставку делегату вернёт рой
    /// (§7), и тогда этот отказ исчезнет сам.
    ///
    /// # Спрашивается у действия, а не у права
    ///
    /// Адресованный блок — ключ чтения впущенному, запись о впуске
    /// владельцу — ничьего состава не требует, и делегат отправляет его
    /// как прежде. Что поедет веером, а что адресату, говорит
    /// `Action::fans_out` исчерпывающим перебором.
    ///
    /// # Errors
    ///
    /// [`EngineError::OnlyOwnerPublishesYet`] — это канал, и мы не его
    /// владелец.
    pub(super) fn check_may_publish(&self, chat: ChatId) -> Result<(), EngineError> {
        let me = self.identity.public().ik;
        if self.channel_owner(chat).is_some_and(|owner| owner != me) {
            return Err(EngineError::OnlyOwnerPublishesYet);
        }
        Ok(())
    }

    /// То же, что [`Engine::check_may_put`], но годится **любое**
    /// из перечисленных прав.
    ///
    /// Заведено ради выдачи ключа чтения: её делает и тот, кто впускает,
    /// и тот, кто поворачивает (§6.2). Отдельным методом, а не флагом,
    /// чтобы «нужны все» и «нужно любое» нельзя было спутать на месте
    /// вызова — вопрос тут разный, и ошибка в нём тихая.
    pub(super) fn check_may_put_any(
        &self,
        now_ms: u64,
        chat: ChatId,
        rights: channel::Rights,
    ) -> Result<(), EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if !state.group.contains(&me) {
            return Err(EngineError::NotInGroup);
        }
        if self.any_right_holds(now_ms, chat, &me, rights)? {
            Ok(())
        } else {
            Err(EngineError::NotAllowedInChannel)
        }
    }

    /// Есть ли у этого человека **хоть одно** из этих прав сейчас.
    pub(super) fn any_right_holds(
        &self,
        now_ms: u64,
        chat: ChatId,
        who: &[u8; 32],
        rights: channel::Rights,
    ) -> Result<bool, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(false) };
        if state.profile.everyone_writes() {
            return Ok(true);
        }
        let stored = self.store.channel(&chat)?;
        let owner = stored.as_ref().map_or(state.group.owner, |it| it.owner_ik);
        let grants: Vec<channel::Grant> = stored
            .as_ref()
            .map(|it| {
                it.grants
                    .iter()
                    .map(|grant| channel::Grant {
                        who: grant.who,
                        sk: grant.sk,
                        rights: channel::Rights::from_bits(grant.rights),
                        until_ms: grant.until_ms,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(channel::rights_from(&owner, &grants, who, now_ms).has_any(rights))
    }

    /// Сколько бит работы требует этот чат сейчас (фаза 2, §11).
    ///
    /// Ноль у всякой группы и у канала, представления которого мы ещё
    /// не приняли: сложность живёт в подписанном документе, и выдумывать
    /// её нельзя ни в какую сторону. Ноль здесь — не послабление,
    /// а честное «нам её не называли».
    pub(super) fn pow_bits(&self, chat: ChatId) -> Result<u32, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(0) };
        if state.profile.everyone_writes() {
            return Ok(0);
        }
        Ok(self.store.channel(&chat)?.map_or(0, |it| it.pow_bits))
    }

    /// Считает работу для блока, если канал её требует (§11).
    ///
    /// # Отказ, а не бесконечный счёт
    ///
    /// `pow::solve` ограничен числом попыток и потолком сложности.
    /// Владелец канала вправе поставить число, которого наше устройство
    /// не потянет, — и человеку надо сказать об этом словами, а не
    /// замереть на отправке одного сообщения.
    pub(super) fn solve_pow(
        &self,
        _now_ms: u64,
        chat: ChatId,
        me: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Option<u64>, EngineError> {
        let bits = self.pow_bits(chat)?;
        if bits == 0 {
            // Нонса нет вовсе, а не ноль: «работы не требовалось»
            // и «работа равна нулю» — разные утверждения, и поле
            // необязательное умеет сказать первое.
            return Ok(None);
        }
        let nonce = ratatosk_crypto::pow::solve(&chat, me, sealed, bits)
            .map_err(|_| EngineError::PowTooHard)?;
        Ok(Some(nonce))
    }

    /// Кто владелец этого канала — тем же источником, что и права.
    ///
    /// Истина — **подписанный документ** (§6.1): в нём владелец назван
    /// и им же проверяется подпись. Пока документа нет, годится строка
    /// чата: туда владелец лёг из ссылки (§10.3 шаг 3) либо из вводного
    /// блока, и правило перехода (`channel::accepts`) менять его потом
    /// не даёт — значит два источника расходиться не могут.
    ///
    /// Одним местом, а не тремя: права, судейство на приёме и правило
    /// «в звезде публикует владелец» обязаны отвечать про одного и того
    /// же человека. Разойдись они, кадр уезжал бы по одному владельцу,
    /// а судился по другому.
    ///
    /// `None` — чата нет либо это обычная группа: у неё владелец есть,
    /// но канальных правил к нему не применяют.
    pub(super) fn channel_owner(&self, chat: ChatId) -> Option<[u8; 32]> {
        let state = self.groups.get(&chat)?;
        if state.profile.everyone_writes() {
            return None;
        }
        let from_document = self.store.channel(&chat).ok().flatten().map(|it| it.owner_ik);
        Some(from_document.unwrap_or(state.group.owner))
    }

    /// Считается ли этот человек участником **для приёма кадров**.
    ///
    /// # Владелец канала состоит по определению
    ///
    /// В группе состав — общий факт, и вопрос решает список. В канале
    /// §3.2 оставляет состав владельцу: читатель знает **себя и его**,
    /// и блоков про остальных у него нет и не будет. Значит требовать
    /// от владельца записи в составе читателя — требовать того, чего
    /// в канале не бывает: его ключ отправителя и список карточек
    /// откладывались бы навсегда, а канал молчал бы при живой доставке.
    ///
    /// Правило то же, по которому владельца пропускает
    /// [`Engine::open_group_frame`]: его подпись и есть канал. Здесь оно
    /// названо вслух и лежит в одном месте на оба приёма — ключа
    /// отправителя и списка карточек.
    ///
    /// # И тот, кто нас впустил, — тоже
    ///
    /// Впустить в канал вправе делегат с правом «впускать» (§6.2), а состав
    /// у читателя — он сам да владелец: блока «владелец добавил делегата»
    /// у него нет и не будет (§3.2). Пока здесь спрашивался один состав,
    /// всё, что делегат присылал впущенному — карточки, цепочку, ключ
    /// чтения, документ, — откладывалось навсегда, и впущенный делегатом
    /// не читал ничего. Стенд показал это дословно: ноль ключей, состав
    /// из себя одного, пять кадров в отложенном.
    ///
    /// Впустивший узнаётся по **его подписанному блоку**, которым он нас
    /// и добавил: он лежит у нас, потому что мы его приняли. Держатель
    /// права по принятому документу считается участником по той же
    /// причине, что владелец: его слова канал и есть.
    pub(super) fn counts_as_member(&self, chat: ChatId, who: &[u8; 32]) -> bool {
        let Some(state) = self.groups.get(&chat) else { return false };
        if state.group.contains(who) {
            return true;
        }
        if state.profile.everyone_writes() {
            return false;
        }
        state.group.owner == *who
            || self.holds_any_right_now(chat, who)
            || self.admitted_me(chat, who)
    }

    /// Есть ли у него хоть одно живое право по принятому документу.
    ///
    /// Без времени — по последней метке часов: сюда спрашивают из мест,
    /// где времени нет (`counts_as_member`), а выдача живёт месяцами,
    /// и минута ошибки часов здесь ничего не решает.
    fn holds_any_right_now(&self, chat: ChatId, who: &[u8; 32]) -> bool {
        let now_ms = self.clock.last().wall_ms;
        self.any_right_holds(now_ms, chat, who, channel::Rights::all()).unwrap_or(false)
    }

    /// Впустил ли нас в этот канал именно он — по его подписанному блоку.
    ///
    /// Читается с диска и проверяется подписью каждый раз: блоков у читателя
    /// единицы, а держать второй ответ на «кто меня впустил» в памяти
    /// значило бы завести ещё одно место, которое после перезапуска
    /// поднимать. Отказ хранилища здесь — «нет»: это вопрос, а не действие.
    pub(super) fn admitted_me(&self, chat: ChatId, who: &[u8; 32]) -> bool {
        let me = self.identity.public().ik;
        let Ok(blocks) = self.store.membership_blocks(&chat) else { return false };
        let Ok(Some(known)) = self.public_identity_of(who) else { return false };
        for stored in blocks.iter().filter(|block| block.author_ik == *who) {
            let Ok(value) = ratatosk_codec::canonical::decode(&stored.bytes) else { continue };
            let Ok(unchecked) = group::parse_membership(&value) else { continue };
            let Ok(block) = unchecked.verify(&known) else { continue };
            if block.ops.iter().any(|op| matches!(op, OrSetOp::Add { elem, .. } if *elem == me)) {
                return true;
            }
        }
        false
    }

    /// Есть ли у этого человека это право в этом чате **сейчас**.
    ///
    /// # Одно место на обе стороны
    ///
    /// Спрашивают отсюда и отправитель, и получатель, и это не экономия
    /// строк. §6.2 требует судейства **при первом приёме**, по версии,
    /// действовавшей тогда; разойдись правила у двух сторон — отправитель
    /// выпускал бы кадры, которые получатель отвергает, и человек видел
    /// бы «ушло», а собеседник не видел бы ничего.
    ///
    /// # В группе ответ всегда «да»
    ///
    /// `closed` — буквально фаза 1: пишут все, кто состоит (§3.2).
    /// Состоит ли — не вопрос этой функции: на отправке это спрашивает
    /// [`Engine::check_may_put`], на приёме — [`Engine::open_group_frame`],
    /// и оба до неё.
    ///
    /// # «Не знаю» — это «нет»
    ///
    /// Нет чата, нет представления, порода из будущего — всё это `false`.
    /// Документ едет отдельно и вправе опоздать (§10.3), но пока его нет,
    /// прав мы не знаем, и молчание обязано отказывать вниз — тем же
    /// правилом, каким истекает срок (§6.3).
    pub(super) fn right_holds(
        &self,
        now_ms: u64,
        chat: ChatId,
        who: &[u8; 32],
        right: channel::Rights,
    ) -> Result<bool, EngineError> {
        let Some(state) = self.groups.get(&chat) else { return Ok(false) };
        if state.profile.everyone_writes() {
            return Ok(true);
        }
        // **Владельца мы знаем и без документа.** Он приехал ссылкой
        // (§10.3, шаг 3) или вводным блоком и лёг владельцем чата; на нём
        // же держится правило «владельцу всё и лишить нельзя» (5вп).
        // Требуй мы здесь представления, владелец не смог бы повернуть
        // ключ у читателя, к которому документ ещё не доехал, — а поворот
        // и есть первое, что владелец делает в новом канале.
        //
        // Без документа у **всех остальных** прав нет: выдачи живут в нём,
        // и «не знаю» обязано отказывать вниз (§6.3).
        let stored = self.store.channel(&chat)?;
        let owner = stored.as_ref().map_or(state.group.owner, |it| it.owner_ik);
        let grants: Vec<channel::Grant> = stored
            .as_ref()
            .map(|it| {
                it.grants
                    .iter()
                    .map(|grant| channel::Grant {
                        who: grant.who,
                        sk: grant.sk,
                        rights: channel::Rights::from_bits(grant.rights),
                        until_ms: grant.until_ms,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(channel::rights_from(&owner, &grants, who, now_ms).has(right))
    }

    /// Свежая метка для операции состава (§11.2).
    ///
    /// `uniq` берётся из `entropy`, а не из счётчика: метка обязана быть
    /// уникальной **между устройствами**, а счётчик у каждого свой и начался
    /// бы с нуля. Восемь случайных байт разводят и повторное приглашение
    /// одного человека внутри одной метки HLC — ровно то, ради чего поле
    /// в `Tag` и заведено.
    pub(super) fn fresh_tag(&mut self, now_ms: u64, actor: ActorId) -> Result<Tag, EngineError> {
        let hlc = self.clock.now(now_ms)?;
        let mut uniq = [0u8; 8];
        self.entropy.fill(&mut uniq);
        Ok(Tag::new(hlc, actor, uniq))
    }

    /// Раскладывает операции состава в строки хранилища.
    ///
    /// Одно добавление — одна строка. Одно **удаление** — по строке
    /// на каждую погашенную им метку, и это не потеря: удаление и есть набор
    /// надгробий над теми метками, которые автор видел (§11.2). Строка,
    /// помеченная `removed`, значит «эта метка добавления погашена», и все
    /// вместе они восстанавливают ту же операцию обратно.
    pub(super) fn stored_from_ops(ops: &[OrSetOp<ActorId>]) -> Vec<StoredMembershipOp> {
        let mut rows = Vec::new();
        for op in ops {
            match op {
                OrSetOp::Add { elem, tag } => rows.push(Self::stored_op(*elem, tag, false)),
                OrSetOp::Remove { elem, observed } => {
                    rows.extend(observed.iter().map(|tag| Self::stored_op(*elem, tag, true)));
                }
            }
        }
        rows
    }

    pub(super) fn stored_op(member_ik: ActorId, tag: &Tag, removed: bool) -> StoredMembershipOp {
        StoredMembershipOp {
            member_ik,
            tag_wall: tag.hlc.wall_ms,
            tag_logical: tag.hlc.logical,
            tag_actor: tag.actor,
            tag_uniq: tag.uniq,
            removed,
        }
    }

    /// Собирает строки хранилища обратно в операции.
    ///
    /// **Добавления идут первыми, удаления следом**, и порядок здесь не
    /// вкусовщина. `OrSet::apply` гасит метку, только если она уже добавлена,
    /// — а надгробие кладёт в любом случае, потому что добавление вправе
    /// прийти после удаления (§9.2). То есть обратный порядок дал бы тот же
    /// состав; прямой выбран за то, что он повторяет порядок, в котором
    /// операции происходили на самом деле.
    ///
    /// Удаления одного участника собираются в **одну** операцию: врозь они
    /// дали бы столько же надгробий, но `OrSet` пересчитывал бы состав на
    /// каждое, а смысл у них общий — «этого убрали».
    pub(super) fn ops_from_stored(rows: &[StoredMembershipOp]) -> Vec<OrSetOp<ActorId>> {
        let mut ops = Vec::new();
        let mut removals: BTreeMap<ActorId, BTreeSet<Tag>> = BTreeMap::new();
        for row in rows {
            let tag =
                Tag::new(Hlc::new(row.tag_wall, row.tag_logical), row.tag_actor, row.tag_uniq);
            // Добавление кладётся и для погашенной метки: без него надгробию
            // было бы нечего гасить, а состав после подъёма зависел бы
            // от того, дошло ли до нас само добавление.
            ops.push(OrSet::prepare_add(row.member_ik, tag));
            if row.removed {
                removals.entry(row.member_ik).or_default().insert(tag);
            }
        }
        ops.extend(removals.into_iter().map(|(elem, observed)| OrSetOp::Remove { elem, observed }));
        ops
    }
}
