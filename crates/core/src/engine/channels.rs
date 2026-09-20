//! Каналы (фаза 2, §3–§6): представление, подписка, права, работа.
//!
//! Канал отличается от группы тем, что состав его не общий: владелец
//! подписывает **представление**, подписчик его проверяет, и пригласивший
//! из цепочки доверия выпадает (§3.1). Всё, что здесь лежит, — про эту
//! разницу; общее с группами живёт в `groups`.

use super::*;

impl<S: Store> Engine<S> {
    /// Ссылка на канал — для QR и пересылки (фаза 2, §10.1, §10.2).
    ///
    /// # Собирает её **тот, кто делится**, а не владелец
    ///
    /// §10.2: адреса в ссылке недоверенные, и класть их вправе кто
    /// угодно. Отсюда следствие, о которое легко споткнуться: **ссылки
    /// на один канал у двух людей — разные строки**, и сравнивать их
    /// как строки нельзя нигде. Тождество канала — это `chat`.
    ///
    /// # Ключ чтения кладётся только у открытого
    ///
    /// Его наличие и есть порода (§6.1). У канала по приглашению ключ
    /// выдаёт владелец, и в ссылке ему делать нечего: она там только
    /// опознаёт (§10.7).
    ///
    /// # Порог версии — **нынешний**
    ///
    /// Ссылка называет минимальную версию, и ею же владелец закрывает
    /// дверь: подняв версию, он делает все прежние ссылки негодными
    /// (§10.7). Значит здесь стоит та версия, что действует сейчас,
    /// а не единица.
    ///
    /// # Адреса
    ///
    /// Кладутся свои — onion и почта, если они есть. Чужих мы не знаем,
    /// а выдумывать нечего: пустой список законен, остаются почта
    /// и реле (§10.5).
    ///
    /// # Errors
    ///
    /// [`EngineError::NotAChannel`] — чат не канал либо представления
    /// у нас нет; [`EngineError::UnknownGroup`] — такого чата нет.
    pub fn channel_link(&self, chat: ChatId) -> Result<String, EngineError> {
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        let stored = self.store.channel(&chat)?.ok_or(EngineError::NotAChannel)?;
        let kind =
            channel::Kind::from_code(u64::from(stored.kind)).ok_or(EngineError::NotAChannel)?;
        let key = match kind {
            channel::Kind::Open => {
                // Поколение открытого канала одно и не поворачивается
                // (§10.4). Нет его — делиться нечем: ссылка без ключа
                // к открытому каналу обещала бы приглашение, которого
                // там не бывает.
                Some(self.store.archive_keys(&chat)?.first().ok_or(EngineError::NotAChannel)?.key)
            }
            channel::Kind::ByInvite => None,
        };

        let mut endpoints = Vec::new();
        if !self.addresses.onion.is_empty() {
            endpoints.push(channel::Endpoint::Onion(self.addresses.onion.clone()));
        }
        if !self.addresses.chatmail.is_empty() {
            endpoints.push(channel::Endpoint::Chatmail(self.addresses.chatmail.clone()));
        }

        channel::Invitation {
            group: chat,
            owner: stored.owner_ik,
            min_version: stored.version,
            key,
            endpoints,
        }
        .to_uri()
        .map_err(|_| EngineError::NotAChannel)
    }

    /// Заводит канал (фаза 2, §6.1).
    ///
    /// # Что здесь то же, что у группы, и почему
    ///
    /// Случайный идентификатор, своя цепочка отправителя, подписанный блок
    /// со своим добавлением, строка чата. Всё это канал наследует **как
    /// группа**, потому что он и есть группа: раздача звездой (§7.5.2) —
    /// это тот же цикл по получателям, что возит группы сегодня.
    ///
    /// # Что здесь своё
    ///
    /// Подписанное представление версии 1 (§6.1). Оно кладётся **после**
    /// строки чата, и порядок не случаен: у `channel_representations`
    /// внешний ключ на `chats`, и документ без чата не существует
    /// физически.
    ///
    /// # Порода задаётся здесь и больше нигде
    ///
    /// Перехода между открытым и по приглашению нет: это разные обещания
    /// (§6.1). В открытом ключ чтения лежит в ссылке, и отобрать его нельзя
    /// ни у кого; в канале по приглашению впускает владелец поимённо.
    /// Сменить одно на другое значит завести новый канал — и так надо
    /// говорить человеку, а не заводить команду смены.
    ///
    /// # Выдач при заведении нет ни одной, и это не пропуск
    ///
    /// У владельца все права и отнять их нельзя (5вп). Строка «владельцу
    /// всё» была бы данными, обязанными совпадать с правилом, то есть
    /// вторым местом, где это правило живёт.
    pub(super) fn on_create_channel(
        &mut self,
        now_ms: u64,
        title: &str,
        open: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(EngineError::GroupTitleEmpty);
        }
        // **Оба предела, а не один.** В символах — тот же, что у группы:
        // поле ввода одно. В байтах — предел представления; сегодня они
        // сходятся (64 символа по четыре байта против 256), и проверка
        // ниже стережёт, чтобы это осталось правдой. Порядок такой:
        // человеку важнее услышать про символы, которые он видит, чем
        // про байты, которых он не считает.
        if title.chars().count() > MAX_GROUP_TITLE_CHARS || title.len() > channel::MAX_TITLE_BYTES {
            return Err(EngineError::GroupTitleTooLong);
        }

        let chat: GroupId = self.entropy.msg_id();
        let me = self.identity.public().ik;
        let at = self.fresh_tag(now_ms, me)?;
        let group = Group::create(chat, me, at);

        let mut chain = [0u8; 32];
        self.entropy.fill(&mut chain);
        let chain = SenderChain::new(zeroize::Zeroizing::new(chain));

        let title_hlc = self.clock.now(now_ms)?;
        self.store.put_group(&StoredGroup {
            chat_id: chat,
            owner_ik: me,
            title: title.to_owned(),
            title_wall: title_hlc.wall_ms,
            title_logical: title_hlc.logical,
            created_ms: now_ms,
            profile: Profile::Channel.code(),
        })?;

        let kind = if open { channel::Kind::Open } else { channel::Kind::ByInvite };
        let representation = channel::Representation {
            group: chat,
            owner: me,
            // Единица, а не ноль: ссылка называет **минимальную** версию
            // (§10.1), и нулевая не отличалась бы от «версии не назвали».
            version: 1,
            kind,
            title: title.to_owned(),
            pow_bits: channel::DEFAULT_POW_BITS,
            seed_days: channel::DEFAULT_SEED_DAYS,
            seed_bytes: channel::DEFAULT_SEED_BYTES,
            grants: Vec::new(),
        };
        // Пара «байты и подпись», а не карта для провода: на диск ложатся
        // ровно те байты, над которыми подпись и считана (§6). Собери их
        // заново перед проверкой — и расхождение канонизации на один байт
        // превратило бы законный документ в испорченный после перезапуска.
        let (block_bytes, signature) =
            channel::sign_representation(&self.identity, &representation)
                .map_err(|_| EngineError::GroupTitleTooLong)?;
        self.store.put_channel(&StoredChannel {
            chat_id: chat,
            version: representation.version,
            owner_ik: me,
            kind: u32::try_from(kind.code()).unwrap_or(u32::MAX),
            title: title.to_owned(),
            pow_bits: representation.pow_bits,
            seed_days: representation.seed_days,
            seed_bytes: representation.seed_bytes,
            block_bytes,
            signature,
            received_ms: now_ms,
            grants: Vec::new(),
        })?;

        // **Ключ чтения рождается здесь у обеих пород**, и разница только
        // в том, где он публикуется. У открытого он ложится в ссылку
        // и живёт вечно: отобрать его у всех, кому ссылку переслали,
        // нельзя (§6.1, §10.7). У канала по приглашению его отдают
        // впущенному запечатанным (§10.4) и поворачивают (§6.4).
        //
        // Сперва он заводился только у открытого, «а по приглашению
        // родится первым поворотом». Это значило, что владелец не может
        // впустить никого, пока не повернёт ключ, которого ещё нет, —
        // порядок, которого спека не требует и человек не ожидает.
        let mut key = [0u8; 32];
        self.entropy.fill(&mut key);
        self.store.put_archive_key(
            &chat,
            &ratatosk_store::StoredArchiveKey { generation: 0, key, created_ms: now_ms },
        )?;

        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: me,
                chain: *chain.export(),
                counter: chain.counter(),
                chain_wall: title_hlc.wall_ms,
                chain_logical: title_hlc.logical,
                skipped: Vec::new(),
            },
        )?;
        self.record_own_ops(now_ms, chat, &[OrSet::prepare_add(me, at)])?;

        self.groups.insert(
            chat,
            GroupState {
                group,
                title: title.to_owned(),
                title_hlc,
                avatar_hlc: Hlc::default(),
                created_ms: now_ms,
                profile: Profile::Channel,
            },
        );

        Ok(vec![Effect::Notify(Event::ChannelCreated { chat, title: title.to_owned(), open })])
    }

    /// Подписывается на канал по ссылке (фаза 2, §10.3, §10.4).
    ///
    /// # Что ложится и в каком порядке
    ///
    /// Строка чата с профилем `channel` — и **владельцем из ссылки**.
    /// Это тот самый `owner_ik`, которым §10.3 шаг 3 велит проверять
    /// подпись представления; положив его владельцем чата, мы делаем
    /// проверку возможной ещё до того, как документ приедет.
    ///
    /// Затем запись подписки с порогом версии: без неё §10.3 шаг 4
    /// и §10.7 не работают — правило есть, а числа нет.
    ///
    /// # Себя в состав кладём сразу, и у обеих пород
    ///
    /// Иначе кадры канала не откроются: `open_group_frame` требует,
    /// чтобы мы состояли. У открытого канала состава не существует вовсе
    /// (§6.1) — там это запись только у себя, и никто о ней не узнает.
    /// У канала по приглашению владелец узнает о нас заявкой, и до впуска
    /// наша запись тоже ничего никому не обещает.
    ///
    /// # Ключ чтения — только у открытого
    ///
    /// §10.4: в открытом канале `AK` совпадает с ключом из ссылки
    /// и не поворачивается никогда. Кладётся поколением **нулевым**:
    /// у него нет предшественников, и поворота у открытого канала
    /// не бывает — отобрать ключ, который у всех, кому переслали ссылку,
    /// нельзя (§10.7).
    ///
    /// # Ссылка с ключом у канала по приглашению — отказ
    ///
    /// Она обещает доступ, которого нет: там ключ выдаёт владелец.
    /// Принять такую значило бы завести чат, который никогда ничего
    /// не покажет, и человеку об этом не сказать.
    ///
    /// # Чего здесь нет
    ///
    /// **Заявки владельцу** (§10.4): блок с нашей карточкой. Для неё
    /// нужен путь к владельцу, а адреса из ссылки мы не храним — они
    /// недоверенные и живут неделями. Подписка на канал по приглашению
    /// поэтому ложится состоянием «заявка», и перевести её в «участвуем»
    /// пока может только впуск приглашением.
    ///
    /// **Предпросмотра** (§10.3, шаги 2 и 5): достать представление
    /// по адресам нечем, это работа транспорта.
    pub(super) fn on_subscribe_to_channel(
        &mut self,
        now_ms: u64,
        uri: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let invitation =
            channel::Invitation::from_uri(uri).map_err(|_| EngineError::BadChannelLink)?;
        let chat = invitation.group;
        if self.groups.contains_key(&chat) {
            // Уже знаем этот канал: своей же ссылкой или второй копией
            // чужой. Заводить его заново значило бы стереть принятое
            // представление и состав.
            return Err(EngineError::AlreadySubscribed);
        }

        let open = invitation.claims_open();
        let me = self.identity.public().ik;
        let at = self.fresh_tag(now_ms, me)?;
        let title_hlc = self.clock.now(now_ms)?;

        self.store.put_group(&StoredGroup {
            chat_id: chat,
            // Владелец — **из ссылки**. Её `owner` недоверен ровно
            // до первой подписи: документ, который он подпишет, это
            // и подтвердит (§10.3, шаг 3).
            owner_ik: invitation.owner,
            // Названия у нас нет: оно внутри представления, а ссылка
            // его не несёт — подписать его в ссылке нечем (§10.5).
            // Пустая строка честнее выдуманной.
            title: String::new(),
            title_wall: title_hlc.wall_ms,
            title_logical: title_hlc.logical,
            created_ms: now_ms,
            profile: Profile::Channel.code(),
        })?;
        self.store.put_subscription(&ratatosk_store::StoredSubscription {
            chat_id: chat,
            owner_ik: invitation.owner,
            min_version: invitation.min_version,
            kind_claimed: if open { 1 } else { 2 },
            state: if open { SUBSCRIPTION_JOINED } else { SUBSCRIPTION_REQUESTED },
            joined_ms: now_ms,
        })?;
        if let Some(key) = invitation.key {
            self.store.put_archive_key(
                &chat,
                &ratatosk_store::StoredArchiveKey { generation: 0, key, created_ms: now_ms },
            )?;
        }

        // Своя цепочка отправителя — как у всякого участника: без неё
        // нам нечем будет сказать ни слова, даже получив право.
        let mut chain = [0u8; 32];
        self.entropy.fill(&mut chain);
        let chain = SenderChain::new(zeroize::Zeroizing::new(chain));
        self.store.put_sender_chain(
            &chat,
            &StoredSenderChain {
                member_ik: me,
                chain: *chain.export(),
                counter: chain.counter(),
                chain_wall: title_hlc.wall_ms,
                chain_logical: title_hlc.logical,
                skipped: Vec::new(),
            },
        )?;
        self.record_own_ops(now_ms, chat, &[OrSet::prepare_add(me, at)])?;

        let mut group = Group::restore(chat, invitation.owner);
        group.apply(OrSet::prepare_add(me, at));
        self.groups.insert(
            chat,
            GroupState {
                group,
                title: String::new(),
                title_hlc,
                avatar_hlc: Hlc::default(),
                created_ms: now_ms,
                profile: Profile::Channel,
            },
        );

        Ok(vec![Effect::Notify(Event::ChannelSubscribed { chat, awaiting: !open })])
    }

    /// Впускает человека в канал (фаза 2, §6.5, §10.4).
    ///
    /// # Три вещи сверх приглашения
    ///
    /// Право «впускать» (§6.2); **поколение ключа чтения**, запечатанное
    /// на его `IK`; подписанная запись о впуске. Без первого впустить
    /// мог бы всякий, без второго впущенный не прочёл бы ничего,
    /// без третьего владелец не увидел бы, кто воспользовался правом.
    ///
    /// # Запись подписываем мы, а не владелец
    ///
    /// Она — след того, кто впустил. Подпиши её владелец, она перестала
    /// бы что-либо говорить о делегате (§6.5).
    ///
    /// # Ключ отдаётся **нынешнего** поколения
    ///
    /// Прежних мы не даём: впущенный сегодня не получает архив до своего
    /// впуска. Спека этого прямо не требует, но и обратного не обещает,
    /// а отдать прежние поколения значило бы раздать весь архив каждому
    /// новому — решение, которое принимает владелец окном сидирования
    /// (§9.3), а не эта команда.
    ///
    /// # Поколения может не быть вовсе
    ///
    /// У канала по приглашению ключ родится первым поворотом (§6.4),
    /// и до него отдавать нечего. Отказ, а не молчаливый впуск без ключа:
    /// человек оказался бы в чате, который ничего не покажет.
    pub(super) fn on_admit_to_channel(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        if state.group.contains(&peer_ik) {
            return Err(EngineError::AlreadyInGroup);
        }
        if !self.contacts.contains_key(&peer_ik) {
            return Err(EngineError::UnknownPeer);
        }
        if !self.right_holds(now_ms, chat, &me, channel::Rights::ADMIT)? {
            return Err(EngineError::NotAllowedInChannel);
        }
        let Some(current) = self.store.archive_keys(&chat)?.pop() else {
            return Err(EngineError::NoReadKeyYet);
        };

        let mut effects = self.join_member(now_ms, chat, peer_ik)?;

        // Ключ — **запечатанным**, тем же блоком, что и при повороте
        // (§5.3): у нас с ним есть сессия, но форма одна на оба случая,
        // и второй дороги ключу заводить незачем.
        let sealed = ratatosk_crypto::seal::seal_to_static(&peer_ik, &current.key)
            .map_err(|_| EngineError::UnknownPeer)?;
        let key_action = ratatosk_proto::group_action::Action::ArchiveKey {
            generation: current.generation,
            recipient_ik: peer_ik,
            sealed,
        };
        let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &key_action)?;
        effects.extend(self.send_group_copy(now_ms, msg_id, peer_ik, &bytes)?);

        // Запись о впуске — **всем**, а не только впущенному: это учёт,
        // и смотрит в него владелец.
        let admission = channel::Admission {
            group: chat,
            who: peer_ik,
            admitted_by: me,
            generation: current.generation,
        };
        let (block_bytes, signature) = channel::sign_admission(&self.identity, &admission)
            .map_err(|_| EngineError::UnknownGroup)?;
        self.store.put_admit(
            &chat,
            &ratatosk_store::StoredAdmit {
                who: peer_ik,
                admitted_by: me,
                generation: current.generation,
                block_bytes: block_bytes.clone(),
                signature,
                created_ms: now_ms,
            },
        )?;
        let record_action = ratatosk_proto::group_action::Action::Admission {
            bytes: ratatosk_codec::canonical::encode(&channel::admission_wire_value(
                block_bytes,
                &signature,
            ))
            .map_err(|_| EngineError::UnknownGroup)?,
        };
        let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &record_action)?;
        effects.extend(self.fan_out_group(now_ms, chat, msg_id, &bytes)?);

        effects.push(Effect::Notify(Event::ChannelAdmitted {
            chat,
            who: peer_ik,
            admitted_by: me,
        }));
        Ok(effects)
    }

    /// Назначает сложность работы на запись (фаза 2, §11).
    ///
    /// Новой версией представления — иначе подписчик не узнал бы цену
    /// до того, как заплатит. Подписывает владелец: список прав
    /// не делегируется, а сложность лежит в том же документе.
    ///
    /// Потолок проверяется здесь, а не только в `pow::solve`: человек,
    /// поставивший сорок бит, должен услышать отказ сразу, а не узнать
    /// о нём от каждого, кто не смог написать.
    pub(super) fn on_set_channel_pow(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        bits: u32,
    ) -> Result<Vec<Effect>, EngineError> {
        if bits > ratatosk_crypto::pow::MAX_BITS {
            return Err(EngineError::PowTooHard);
        }
        self.publish_representation(now_ms, chat, |next| next.pow_bits = bits)
    }

    /// Поворачивает ключ чтения канала (фаза 2, §6.4).
    ///
    /// # Что это на самом деле делает
    ///
    /// Заводит новое поколение и рассылает его **по запечатанному блоку
    /// на читателя** — каждому, кто есть в составе сейчас. Кого там нет,
    /// тот остаётся с прежними поколениями: архив он дочитает, будущего
    /// не увидит. Это и есть исключение читателя; другого в канале нет.
    ///
    /// # Поворот нужен не ради тайны
    ///
    /// §6.4 говорит это прямо: «чтобы утечка не жила вечно». Ключ,
    /// утёкший вместе с базой, открывает архив до поворота и ничего
    /// после.
    ///
    /// # Нижний предел — не декорация
    ///
    /// Не чаще раза в неделю. Каждый поворот стоит по запечатанному блоку
    /// на читателя, и в канале без предела размера это прямая цена
    /// трафика у всех сразу. Отказ здесь — единственное место, где она
    /// называется вслух.
    ///
    /// # У открытого канала — отказ
    ///
    /// Ключ лежит в ссылке и у всех, кому её переслали (§6.1, §10.7):
    /// отобрать его не у кого. Промолчи мы — человек решил бы, что
    /// исключил читателя, и это была бы ложь в самом дорогом месте.
    ///
    /// # Первый потребитель `crypto::seal`
    ///
    /// Печать написана в очереди 1 и до сих пор не звалась ниоткуда.
    /// Правило её заголовка — «есть живая сессия, отдавай по ней» —
    /// здесь не нарушается: блок едет **всем**, в том числе через руки,
    /// с которыми сессии нет, и на том стоит §5.3.
    pub(super) fn on_rotate_channel_key(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        let stored = self.store.channel(&chat)?.ok_or(EngineError::UnknownGroup)?;
        let kind =
            channel::Kind::from_code(u64::from(stored.kind)).ok_or(EngineError::NotAChannel)?;
        if kind == channel::Kind::Open {
            return Err(EngineError::OpenChannelHasNoRotation);
        }
        // Право «исключать»: поворот и есть механизм исключения (§6.4).
        // Спрашивается тем же местом, что и всё остальное, — иначе
        // у прав завелось бы второе толкование.
        if !self.right_holds(now_ms, chat, &me, channel::Rights::EVICT)? {
            return Err(EngineError::NotAllowedInChannel);
        }

        let known = self.store.archive_keys(&chat)?;
        // **Предел считается от последнего поворота, а не от последнего
        // ключа.** Нулевое поколение — это рождение канала, а не поворот:
        // его никому не рассылали, и оно никому ничего не стоило.
        // Считай мы от него, владелец не мог бы повернуть ключ первую
        // неделю жизни канала — запрет, которого спека не вводит и цена
        // которого никем не платится.
        //
        // Часы здесь местные, и это осознанно: предел защищает **наш**
        // трафик и трафик наших читателей, а не чужой порядок. Сверять
        // его с чужими часами значило бы пускать сдвиг времени управлять
        // расходом.
        if let Some(last) = known.iter().rev().find(|key| key.generation > 0) {
            if now_ms.saturating_sub(last.created_ms) < MIN_KEY_ROTATION_MS {
                return Err(EngineError::RotatedTooRecently);
            }
        }
        let generation = known.last().map_or(0, |last| last.generation + 1);

        let mut key = [0u8; 32];
        self.entropy.fill(&mut key);
        // Кладётся **до** рассылки. Упади процесс между рассылкой
        // и записью — читатели знали бы поколение, которого у нас нет,
        // и следующий поворот выдал бы тот же номер другому ключу.
        self.store.put_archive_key(
            &chat,
            &ratatosk_store::StoredArchiveKey { generation, key, created_ms: now_ms },
        )?;

        let recipients: Vec<[u8; 32]> = match self.groups.get(&chat) {
            Some(state) => state.group.recipients(&me),
            None => return Err(EngineError::UnknownGroup),
        };
        let mut effects = Vec::new();
        for member in recipients {
            let Ok(sealed) = ratatosk_crypto::seal::seal_to_static(&member, &key) else {
                // Ключ участника не годится точкой X25519: его карточка
                // испорчена. Пропускаем **его одного** — тем же правилом,
                // по какому отказ одному участнику не обрывает рассылку
                // остальным.
                tracing::warn!(
                    участник = %Self::short_label(&member),
                    "ключ чтения этому участнику не запечатать"
                );
                continue;
            };
            let action = ratatosk_proto::group_action::Action::ArchiveKey {
                generation,
                recipient_ik: member,
                sealed,
            };
            // Свой кадр каждому: блок называет адресата, и общий кадр
            // означал бы, что каждый читатель тянет по восемьдесят байт
            // за каждого другого (§5.3).
            let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &action)?;
            match self.send_group_copy(now_ms, msg_id, member, &bytes) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::warn!(
                    ?error,
                    участник = %Self::short_label(&member),
                    "поколение ключа участнику не поставилось в очередь"
                ),
            }
        }

        effects.push(Effect::Notify(Event::ChannelKeyRotated { chat, generation }));
        Ok(effects)
    }

    /// Выдаёт или снимает право в канале (фаза 2, §6.2, §6.3).
    ///
    /// # Новая версия целиком, а не правка списка
    ///
    /// Документ версионирован, и меняется он **заменой**: список выдач
    /// в новой версии — это всё, что действует. Снятие права выражается
    /// тем, что строки в списке больше нет, и отдельного надгробия ему
    /// не нужно — а в рое надгробие и не работало бы: его неприход
    /// неотличим от «не отзывали».
    ///
    /// # Подписывает владелец, и только он
    ///
    /// §6.2: «раздача прав не делегируется никогда. Иначе это
    /// совладение». Держатель права «менять представление» правит
    /// описательные поля — но список прав не его.
    ///
    /// # Свой же документ уезжает действием и **не** применяется дважды
    ///
    /// Он кладётся здесь и рассылается копией каждому. Вернись копия
    /// к нам, [`Engine::apply_representation`] отвергнет её как
    /// устаревшую — версии равны, — и это правильный путь, а не
    /// счастливое совпадение: то же произойдёт с любой копией из роя.
    pub(super) fn on_set_channel_right(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        who: [u8; 32],
        rights: u32,
        until_ms: u64,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            // В группе прав не раздают: там пишут все, кто состоит (§3.2).
            // Отказ, а не молчание: команда пришла не туда, и человеку
            // надо это сказать.
            return Err(EngineError::NotAChannel);
        }
        let stored = self.store.channel(&chat)?.ok_or(EngineError::UnknownGroup)?;
        if stored.owner_ik != me {
            return Err(EngineError::NotAllowedInChannel);
        }
        if who == me {
            // У владельца все права и отнять их нельзя (5вп). Выдать ему
            // что-то тоже бессмысленно: строка «владельцу всё» была бы
            // данными, обязанными совпадать с правилом.
            return Err(EngineError::NotAllowedInChannel);
        }

        let mut grants: Vec<channel::Grant> = stored
            .grants
            .iter()
            .filter(|grant| grant.who != who)
            .map(|grant| channel::Grant {
                who: grant.who,
                rights: channel::Rights::from_bits(grant.rights),
                until_ms: grant.until_ms,
            })
            .collect();
        if rights != 0 {
            grants.push(channel::Grant {
                who,
                rights: channel::Rights::from_bits(rights),
                until_ms,
            });
        }
        // Порядок задан целиком: документ подписывается, и два устройства
        // владельца обязаны получить **одни и те же байты** из одного
        // и того же списка.
        grants.sort_by_key(|grant| grant.who);
        if grants.len() > channel::MAX_GRANTS {
            return Err(EngineError::TooManyGrants);
        }

        self.publish_representation(now_ms, chat, |next| next.grants = grants)
    }

    /// Подписывает и рассылает **следующую** версию представления (§6.1).
    ///
    /// # Одно место на все правки документа
    ///
    /// Версия поднимается, подпись считается, байты ложатся на диск
    /// и уезжают действием. Правка передаётся замыканием и трогает
    /// только то, что меняет команда; всё остальное переносится
    /// из принятого как есть.
    ///
    /// Общее это не ради экономии строк: версия, подпись, запись
    /// и рассылка обязаны случиться **вместе**. Разойдись две копии
    /// этой последовательности, одна из команд однажды подняла бы
    /// версию, не разослав её, и подписчики остались бы с документом,
    /// которого у владельца уже нет.
    ///
    /// # Владелец, и только он
    ///
    /// §6.2: «раздача прав не делегируется никогда». Сложность PoW
    /// и прочие поля лежат в том же документе и подписываются той же
    /// подписью, поэтому правило здесь одно на всё.
    pub(super) fn publish_representation(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        edit: impl FnOnce(&mut channel::Representation),
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            return Err(EngineError::NotAChannel);
        }
        let stored = self.store.channel(&chat)?.ok_or(EngineError::UnknownGroup)?;
        if stored.owner_ik != me {
            return Err(EngineError::NotAllowedInChannel);
        }
        let kind = channel::Kind::from_code(u64::from(stored.kind))
            .ok_or(EngineError::NotAllowedInChannel)?;

        let mut next = channel::Representation {
            group: chat,
            owner: me,
            version: stored.version + 1,
            kind,
            title: stored.title.clone(),
            pow_bits: stored.pow_bits,
            seed_days: stored.seed_days,
            seed_bytes: stored.seed_bytes,
            grants: stored
                .grants
                .iter()
                .map(|grant| channel::Grant {
                    who: grant.who,
                    rights: channel::Rights::from_bits(grant.rights),
                    until_ms: grant.until_ms,
                })
                .collect(),
        };
        edit(&mut next);
        if next.grants.len() > channel::MAX_GRANTS {
            return Err(EngineError::TooManyGrants);
        }

        let (block_bytes, signature) = channel::sign_representation(&self.identity, &next)
            .map_err(|_| EngineError::TooManyGrants)?;
        self.store.put_channel(&StoredChannel {
            chat_id: chat,
            version: next.version,
            owner_ik: me,
            kind: stored.kind,
            title: next.title.clone(),
            pow_bits: next.pow_bits,
            seed_days: next.seed_days,
            seed_bytes: next.seed_bytes,
            block_bytes: block_bytes.clone(),
            signature,
            received_ms: now_ms,
            grants: next
                .grants
                .iter()
                .map(|grant| ratatosk_store::StoredGrant {
                    who: grant.who,
                    rights: grant.rights.bits(),
                    until_ms: grant.until_ms,
                })
                .collect(),
        })?;

        // Уезжает **та карта, что ляжет у получателя под проверку**,
        // а не наши разобранные поля: подпись считана над `block_bytes`,
        // и собирать их заново на той стороне никто не будет.
        let action = ratatosk_proto::group_action::Action::Representation {
            bytes: ratatosk_codec::canonical::encode(&channel::wire_value(block_bytes, &signature))
                .map_err(|_| EngineError::TooManyGrants)?,
        };
        let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &action)?;
        let mut effects = self.fan_out_group(now_ms, chat, msg_id, &bytes)?;
        effects.push(Effect::Notify(Event::ChannelChanged {
            chat,
            version: next.version,
            title: next.title,
        }));
        Ok(effects)
    }

    /// Принимает новую версию представления канала (фаза 2, §6.1, §10.3).
    ///
    /// # Подпись решает, а не отправитель
    ///
    /// Кто привёз документ — неважно. Он **самопроверяем** (§3.1), и ровно
    /// поэтому его может ретранслировать кто угодно, не читая. Проверять
    /// здесь `sender == owner` значило бы отменить это свойство ещё до
    /// того, как появится рой, ради которого оно заведено.
    ///
    /// # Чьим ключом проверяется подпись
    ///
    /// Владельцем **уже принятого** представления, а если его нет —
    /// владельцем чата. §10.3 шаг 3 говорит «ключом `owner_ik` из ссылки»,
    /// и это то же самое: ссылку мы принимаем, заводя чат, и её `owner`
    /// ложится владельцем.
    ///
    /// # Порог версии — из записи подписки
    ///
    /// §10.3 шаг 4: версии ниже названной ссылкой не принимать. На этом
    /// держится §10.7 — отзыва ссылки не бывает, но владелец поднимает
    /// версию, и старые ссылки перестают пускать. Число берётся
    /// из `channel_subscriptions`; у канала, который завели сами или куда
    /// позвали приглашением, записи нет — ссылки не было, — и порог там
    /// нулевой, что верно.
    ///
    /// # Отказ молчит, и это не небрежность
    ///
    /// Устаревшая версия приезжает **штатно**: в рое одна и та же копия
    /// приходит от десятка раздающих. Считать это аномалией значило бы
    /// наказывать соседа за исправную работу. Аномалия ложится только
    /// на то, что не могло приехать честно: чужая подпись и подмена
    /// канала.
    pub(super) fn apply_representation(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        let Ok(value) = ratatosk_codec::canonical::decode(bytes) else {
            return Ok(Vec::new());
        };
        let Ok(unchecked) = channel::parse_representation(&value) else {
            return Ok(Vec::new());
        };
        // Документ обязан говорить о **том** чате, в котором приехал.
        // Без этого один канал возил бы представления другого, и принятое
        // легло бы не туда.
        if *unchecked.claims_group() != chat {
            return Ok(Vec::new());
        }

        let authority = match self.store.channel(&chat)? {
            Some(known) => known.owner_ik,
            None => match self.groups.get(&chat) {
                Some(state) => state.group.owner,
                None => return Ok(Vec::new()),
            },
        };
        // **Молчим, а не отмечаем аномалию.** Карточка владельца едет
        // отдельным кадром и вправе опоздать (§4.3), и «проверить нечем»
        // это не «подпись не сошлась». Очереди для документов, ждущих
        // карточку, пока нет — записано как незакрытое.
        let Some(owner) = self.public_identity_of(&authority)? else {
            return Ok(Vec::new());
        };
        self.take_representation(now_ms, chat, &owner, unchecked)
    }

    /// Проверяет подпись и правило перехода, кладёт принятое.
    ///
    /// Отделено от [`Engine::apply_representation`] ровно затем, чтобы
    /// «чьим ключом проверять» и «можно ли это принять» не смешивались:
    /// первое зависит от того, откуда мы узнали про канал, второе —
    /// только от документов.
    pub(super) fn take_representation(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        owner: &ratatosk_crypto::PublicIdentity,
        unchecked: channel::UncheckedRepresentation,
    ) -> Result<Vec<Effect>, EngineError> {
        // Байты и подпись снимаются **до** проверки: `verify` забирает
        // значение целиком, а на диск обязаны лечь именно принятые байты
        // (§6), а не пересобранные из разобранного.
        let block_bytes = unchecked.signed_bytes().to_vec();
        let signature = *unchecked.signature();
        let Ok(next) = unchecked.verify(owner) else {
            // Чужая подпись приехать честно не могла.
            self.sessions.note_anomaly(owner.ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        };

        let stored = self.store.channel(&chat)?;
        let previous = stored.as_ref().and_then(|known| {
            channel::Kind::from_code(u64::from(known.kind)).map(|kind| channel::Representation {
                group: known.chat_id,
                owner: known.owner_ik,
                version: known.version,
                kind,
                title: known.title.clone(),
                pow_bits: known.pow_bits,
                seed_days: known.seed_days,
                seed_bytes: known.seed_bytes,
                grants: known
                    .grants
                    .iter()
                    .map(|grant| channel::Grant {
                        who: grant.who,
                        rights: channel::Rights::from_bits(grant.rights),
                        until_ms: grant.until_ms,
                    })
                    .collect(),
            })
        });
        // **Порог — из записи подписки** (§10.3, шаг 4). Её нет у канала,
        // который завели сами или куда позвали приглашением: ссылки
        // не было, называть порог некому, и ноль тут верен.
        let subscription = self.store.subscription(&chat)?;
        let min_version = subscription.map_or(0, |it| it.min_version);
        // Обещание ссылки против подписанного (§6.1). Расхождение значит,
        // что ссылка сулила доступ, которого нет: ключ был в ней, а канал
        // оказался по приглашению. Принять документ значило бы оставить
        // человека с чатом, который никогда ничего не покажет, и не
        // сказать почему.
        if let Some(it) = subscription {
            if u64::from(it.kind_claimed) != next.kind.code() {
                self.sessions.note_anomaly(owner.ik, |c| c.malformed += 1);
                return Ok(Vec::new());
            }
        }
        match channel::accepts(previous.as_ref(), &next, min_version) {
            Ok(()) => {}
            // Устаревшая копия — штатное дело роя, молчим без отметки.
            Err(channel::ChannelError::StaleVersion) => return Ok(Vec::new()),
            Err(_) => {
                self.sessions.note_anomaly(owner.ik, |c| c.malformed += 1);
                return Ok(Vec::new());
            }
        }

        self.store.put_channel(&StoredChannel {
            chat_id: chat,
            version: next.version,
            owner_ik: next.owner,
            kind: u32::try_from(next.kind.code()).unwrap_or(u32::MAX),
            title: next.title.clone(),
            pow_bits: next.pow_bits,
            seed_days: next.seed_days,
            seed_bytes: next.seed_bytes,
            block_bytes,
            signature,
            received_ms: now_ms,
            grants: next
                .grants
                .iter()
                .map(|grant| ratatosk_store::StoredGrant {
                    who: grant.who,
                    rights: grant.rights.bits(),
                    until_ms: grant.until_ms,
                })
                .collect(),
        })?;

        Ok(vec![Effect::Notify(Event::ChannelChanged {
            chat,
            version: next.version,
            title: next.title,
        })])
    }
}
