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

        let endpoints = self.own_endpoints();

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

    /// Свои адреса для ссылки — **все, какие есть** (§10.1).
    ///
    /// # Почему список, а не два поля
    ///
    /// §10.1 говорит прямо: «`addrs[]` — адреса всех доступных видов,
    /// **как в карточке контакта**», и §10.2 добавляет, зачем это нужно:
    /// «ссылка провисит год… откроется она через почту и nostr».
    ///
    /// Здесь стояли onion и почта, и только они. Узел, у которого путь
    /// один — меш или реле, — раздавал ссылку **без единого адреса**:
    /// заявка (§10.4) ложилась в очередь и ждала, пока владельца станет
    /// слышно в эфире, а в другой сети этого не случается никогда. Нашлось
    /// на стенде, где у владельца был поднят один nostr.
    ///
    /// # Ключ nostr и реле — два разных адреса, и оба обязательны
    ///
    /// Реле говорит, куда положить событие, ключ — кому оно. Порознь
    /// ни то ни другое не адрес; отсюда два вида в ссылке и правило
    /// `Peer::nostr`, по которому доступность считается по ключу.
    ///
    /// # Предел
    ///
    /// Адресов в ссылке не больше [`channel::MAX_ENDPOINTS`], иначе она
    /// не соберётся вовсе. Реле — последние в списке и первые под нож:
    /// без реле собеседник возьмёт наши из карточки, когда она до него
    /// доедет, а без onion или ключа меша ступени нет совсем.
    pub(super) fn own_endpoints(&self) -> Vec<channel::Endpoint> {
        let mut endpoints = Vec::new();
        if !self.addresses.onion.is_empty() {
            endpoints.push(channel::Endpoint::Onion(self.addresses.onion.clone()));
        }
        if !self.addresses.chatmail.is_empty() {
            endpoints.push(channel::Endpoint::Chatmail(self.addresses.chatmail.clone()));
        }
        if let Ok(key) = <[u8; 32]>::try_from(self.ygg.as_slice()) {
            endpoints.push(channel::Endpoint::Ygg(key));
        }
        if let Ok(key) = <[u8; 32]>::try_from(self.nostr.as_slice()) {
            endpoints.push(channel::Endpoint::Nostr(key));
            for relay in self.nostr_card_relays() {
                if endpoints.len() == channel::MAX_ENDPOINTS {
                    break;
                }
                endpoints.push(channel::Endpoint::NostrRelay(relay));
            }
        }
        endpoints
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

        Ok(vec![Effect::Notify(Event::ChannelCreated {
            chat,
            title: title.to_owned(),
            // Породу здесь знаем точно: её только что выбрал человек.
            open: Some(open),
        })])
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

        // **Владелец запоминается пиром, а не контактом** (§8.3, §10.4).
        //
        // Раньше адреса из ссылки выбрасывались, и записано это было так:
        // «они недоверенные, одноразовые и живут неделями, а строка
        // проживёт год; хранить их значило бы завести кэш, устаревающий
        // молча». Довод верен ровно до тех пор, пока до владельца нечем
        // дотянуться: заявка (§10.4) без адреса не уедет никуда.
        //
        // Поэтому они кладутся — но **пиром**, а не контактом, и §10.4
        // говорит про подписку прямо: «контакт не заводится». Пир — это
        // «куда слать этому ключу», и ничего больше: ни чата, ни сверки,
        // ни строки в списке знакомых.
        //
        // Устаревание названо, а не забыто: адрес из ссылки ничем
        // не подтверждён (§10.2), и не дозвонившись, лестница §5.4
        // спустится ниже сама. Приедет настоящая карточка — адреса
        // обновятся из неё.
        self.remember_peer(
            now_ms,
            invitation.owner,
            &invitation.endpoints,
            ratatosk_store::PEER_CHANNEL_OWNER,
        )?;

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

        // **Заявка владельцу** (§10.4) — и только у канала по приглашению:
        // у открытого владелец «не участвует и не узнаёт», и стучаться
        // к нему значило бы сказать ему то, чего он знать не должен.
        //
        // Едет она один на один, а не в канал: в канале заявитель ещё
        // никто — ни состава, ни цепочки у него там нет, и групповой кадр
        // от него владелец не открыл бы. Дотянуться до владельца стало
        // чем ровно сейчас: он лежит пиром, с адресами из ссылки (§8.3).
        //
        // Ответа у заявки нет и не предусмотрено: §10.4 говорит «впустил
        // — присылает ключ», и впуск и есть ответ. Пока его нет, подписка
        // числится заявкой, и человек видит ожидание (§10.5).
        let mut effects = vec![Effect::Notify(Event::ChannelSubscribed { chat, awaiting: !open })];
        if !open {
            let (_, sent) = self.enqueue_request(
                now_ms,
                invitation.owner,
                PayloadType::ChannelRequest,
                channel::request_value(&chat),
            )?;
            effects.extend(sent);
        }
        Ok(effects)
    }

    /// Принимает заявку на подписку (фаза 2, §10.4).
    ///
    /// # Что здесь проверяется и чего не проверяется
    ///
    /// Канал обязан быть нашим и быть каналом: заявка в чужой чат —
    /// это кадр не по адресу, и молчать на него нечего. А вот право
    /// или порода заявителя не спрашиваются вовсе: просить вправе кто
    /// угодно, на то она и просьба. Решает владелец, и решает руками.
    ///
    /// # Открытый канал заявок не принимает
    ///
    /// §10.4: у открытого владелец «не участвует и не узнаёт». Заявка
    /// туда — либо чужая ошибка, либо попытка узнать, жив ли владелец;
    /// ни на что из этого отвечать не надо.
    ///
    /// # Повтор не двигает время
    ///
    /// Заявка, посланная второй раз, — это та же просьба, на которую
    /// ещё не ответили. Время в строке остаётся временем первой:
    /// §10.5 меряет ожидание от неё, и обновляй мы его, ожидание
    /// начиналось бы заново при каждом повторе.
    pub(super) fn on_channel_request(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // **Квитанция — до разбора, и она про кадр, а не про решение.**
        // Заявка едет обычной очередью §5.4, и у неё есть срок: не ответь
        // мы, отправитель объявит неудачу, а §5.4 отправит сессию на покой
        // — и следующие кадры начнут пропадать. Молчаливым этот кадр
        // не назван (`silent_frame`), так что молчать на него нельзя.
        //
        // Что заявка не принята (чужой канал, открытый канал), квитанция
        // не говорит и говорить не должна: она про доставку, а не про
        // согласие. Ответ на саму заявку один — впуск (§10.4).
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Ok(chat) = channel::request_from_value(&envelope.payload) else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };
        let me = self.identity.public().ik;
        let Some(state) = self.groups.get(&chat) else { return Ok(effects) };
        if state.profile.everyone_writes() || state.group.owner != me {
            return Ok(effects);
        }
        // Порода — из подписанного документа: у открытого канала заявок
        // не бывает (§10.4).
        let open = self
            .store
            .channel(&chat)?
            .and_then(|it| channel::Kind::from_code(u64::from(it.kind)))
            .is_some_and(|kind| kind == channel::Kind::Open);
        if open {
            return Ok(effects);
        }
        // Уже впущенному просить нечего: он в составе, ключ у него есть.
        // Молчим, а не отмечаем аномалию: так выглядит повтор заявки,
        // разминувшийся со впуском по дороге.
        if state.group.contains(&peer_ik) {
            return Ok(effects);
        }

        self.store.put_channel_request(&chat, &peer_ik, now_ms)?;
        effects.push(Effect::Notify(Event::ChannelRequested { chat, who: peer_ik }));
        Ok(effects)
    }

    /// Запоминает пира-не-контакта по адресам из ссылки (§8.3, §10.2).
    ///
    /// Адреса разбираются в те же поля, что у контакта, потому что
    /// решение §5.4 принимается по одной структуре: у пира и у контакта
    /// лестница обязана быть одна, иначе один и тот же собеседник
    /// получал бы разные ответы в зависимости от того, как мы о нём
    /// узнали.
    ///
    /// Пустой список адресов — законный случай: ссылку вправе собрать
    /// тот, у кого своих адресов нет вовсе (§10.2). Пир тогда заводится
    /// без единого адреса, и §5.4 честно скажет «отправлять некуда»,
    /// а не промолчит.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn remember_peer(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        endpoints: &[channel::Endpoint],
        why: u32,
    ) -> Result<(), EngineError> {
        // Контакта пиром не переписываем: у него есть карточка, подпись
        // и сверка, и адрес из чужой ссылки её не улучшает.
        if self.contacts.contains_key(&peer_ik) {
            return Ok(());
        }

        // Карточка сохраняется, если она у нас уже была: пожавший руку
        // незнакомец мог стать владельцем канала, чью ссылку нам дали, —
        // и терять его карточку из-за адресов из ссылки нельзя. Адреса
        // же из ссылки недоверенные (§10.2), а карточка подписана.
        let known = self.peers.get(&peer_ik);
        let mut stored = ratatosk_store::StoredPeer {
            ik: peer_ik,
            onion: String::new(),
            chatmail: String::new(),
            ygg: Vec::new(),
            relays: Vec::new(),
            nostr: Vec::new(),
            card: known.map(|peer| peer.card.clone()).unwrap_or_default(),
            // Прежняя причина сильнее новой: тот, кого мы знали владельцем
            // канала, остаётся им, даже если потом объявился сидом.
            known_as: known.map_or(why, |peer| peer.known_as),
            // Знакомство не переписывается: пир, пожавший руку раньше,
            // узнан тогда, а не сейчас.
            added_ms: known.map_or(now_ms, |peer| peer.added_ms),
        };
        for endpoint in endpoints {
            match endpoint {
                // Первый адрес каждого вида, а не последний: ссылку
                // собирает тот, кто делится (§10.2), и порядок в ней
                // его — а «последний побеждает» означало бы, что
                // выбирает его хвост списка.
                channel::Endpoint::Onion(address) if stored.onion.is_empty() => {
                    stored.onion.clone_from(address);
                }
                channel::Endpoint::Chatmail(address) if stored.chatmail.is_empty() => {
                    stored.chatmail.clone_from(address);
                }
                channel::Endpoint::Ygg(key) if stored.ygg.is_empty() => {
                    stored.ygg = key.to_vec();
                }
                channel::Endpoint::NostrRelay(relay) => stored.relays.push(relay.clone()),
                channel::Endpoint::Nostr(key) if stored.nostr.is_empty() => {
                    stored.nostr = key.to_vec();
                }
                _ => {}
            }
        }
        self.store.put_peer(&stored)?;

        let availability = PeerAvailability {
            has_ygg: !stored.ygg.is_empty(),
            has_onion: !stored.onion.is_empty(),
            // По ключу, а не по реле (см. `Peer::nostr`): реле без ключа —
            // не адрес, и лестница, поверившая им, уводила заявку
            // на ступень, где раннеру некого называть получателем.
            has_nostr: !stored.nostr.is_empty(),
            has_chatmail: !stored.chatmail.is_empty(),
            enabled: self.announcing(),
            ready: self.ready,
            // Видимость в эфире с диска не поднимается и здесь не
            // выдумывается: её говорит только эфир (§5.1).
            seen_on_lan: false,
            seen_on_bt: false,
        };
        self.peers.insert(
            peer_ik,
            Peer {
                onion: stored.onion,
                chatmail: stored.chatmail,
                ygg: stored.ygg,
                relays: stored.relays,
                nostr: stored.nostr,
                availability,
                sk: ContactCard::decode(&stored.card)
                    .ok()
                    .map_or([0u8; 32], |card| card.into_parts().1.sk),
                card: stored.card,
                known_as: stored.known_as,
                added_ms: stored.added_ms,
            },
        );
        Ok(())
    }

    /// Отписывается от канала (фаза 2, §10.6).
    ///
    /// # Блок ухода — по составу, а не по породе
    ///
    /// §10.6 велит по приглашению прислать блок ухода, а в открытом
    /// канале владельцу говорить нечего: он о нас и не знал (§10.4).
    /// Разводить эти случаи **условием на породу** не надо — они уже
    /// разведены составом: у открытого канала его не существует (§6.1),
    /// наша запись о себе лежит только у нас, и рассылать блок некому.
    /// Одно правило вместо двух ветвей: кому наш уход что-то значит,
    /// тот о нём узнает.
    ///
    /// Уход **уезжает раньше уборки**, и очередь доставки его переживает:
    /// конверт лежит в `outbox` за своим `msg_id` и на чат не ссылается.
    /// Стирали бы мы чат первым — блок собирать было бы уже нечем:
    /// он подписывается нашей же цепочкой отправителя.
    ///
    /// # Что именно стирается
    ///
    /// Чат целиком: история, вложения, состав, цепочки, представление,
    /// выдачи, записи о впусках, подписка и **все поколения ключа
    /// чтения**. Последнее и есть цена отписки: архив канала хранится
    /// у читателя, и с ключами он закрывается навсегда — вернувшись
    /// по той же ссылке, человек прочтёт только то, что приедет заново.
    /// Сказать это обязан клиент до команды (§14).
    ///
    /// Отложенные кадры этого чата выбрасываются здесь же. Оставь мы их
    /// в очереди — они пролежали бы там до вытеснения, а разобрать их
    /// всё равно некому: чата больше нет.
    ///
    /// # Чего здесь нет, потому что нет в дереве
    ///
    /// «Раздача прекращается» и «`PeerRecord` перестаёт продлеваться»
    /// (§10.6) — ни раздачи, ни записей пира в ядре пока не существует,
    /// это очередь 3. Стирать нечего, и делать вид, что стёрли,
    /// не стоит.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownGroup`] — такого чата нет;
    /// [`EngineError::NotAChannel`] — это обычная группа, из неё выходят
    /// ([`Command::LeaveGroup`]); [`EngineError::CannotUnsubscribeOwnChannel`]
    /// — канал наш собственный.
    pub(super) fn on_unsubscribe_from_channel(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let state = self.groups.get(&chat).ok_or(EngineError::UnknownGroup)?;
        if state.profile.everyone_writes() {
            // Из группы выходят, а не отписываются: там состав общий,
            // и уход — заявление, которое видят все.
            return Err(EngineError::NotAChannel);
        }
        if state.group.owner == me {
            return Err(EngineError::CannotUnsubscribeOwnChannel);
        }

        // **Блок ухода едет владельцу, и только ему** (§10.6, §3.2).
        //
        // Из группы уходят заявлением, которое видят все; в канале состав
        // ведёт владелец — остальные читатели друг о друге не знают,
        // и рассылать им нечего. Владельцу же сказать надо: пока он
        // не узнал, он платит за нас рассылкой каждого слова.
        //
        // Уход собирается **до** уборки: он подписывается нашей же
        // цепочкой отправителя, а её через минуту не станет. Очередь
        // доставки его переживёт — конверт лежит в `outbox` за своим
        // номером и на чат не ссылается.
        //
        // У подписки по ссылке владелец нам не контакт, и `tell_member`
        // тогда молча ничего не делает: сказать ему нечем, он о нас
        // и не знал (§10.4).
        let owner = state.group.owner;
        let mut effects = Vec::new();
        if state.group.contains(&me) {
            let op = state.group.leave(me)?;
            let block = self.record_own_ops(now_ms, chat, std::slice::from_ref(&op))?;
            if let Some(state) = self.groups.get_mut(&chat) {
                state.group.apply(op);
            }
            effects.extend(self.tell_member(now_ms, owner, PayloadType::GroupMembership, block)?);
        }

        // Порядок как в `on_clear_chat`: сперва снять с очередей то, что
        // иначе уехало бы после удаления, потом стереть.
        let doomed: Vec<MsgId> =
            self.store.messages(&chat, usize::MAX, None)?.into_iter().map(|m| m.msg_id).collect();
        for msg_id in &doomed {
            self.forget_files(msg_id);
            self.deferred.retain(|d| d.msg_id != *msg_id);
            self.outbox.retain(|d| d.msg_id != *msg_id);
            self.store.delete_outbox_all(msg_id)?;
        }
        self.read_upto.remove(&chat);
        // **Пира забываем вместе с причиной, по которой он был нужен**
        // (§8.3): владельца этого канала мы знали ради заявки и доставки,
        // а канала больше нет. Если он владеет ещё каким-то нашим каналом
        // — остаётся: причина никуда не делась.
        //
        // Сессия с ним при этом не трогается. Она живёт своей жизнью
        // (§8.5) и исчезнет сама; рвать её здесь значило бы гасить связь,
        // по которой, может быть, прямо сейчас едет наш же блок ухода.
        let owner_elsewhere =
            self.groups.iter().any(|(other, state)| *other != chat && state.group.owner == owner);
        if !owner_elsewhere {
            self.store.delete_peer(&owner)?;
            self.peers.remove(&owner);
        }
        self.pending_group.retain(|frame| frame.chat != chat);
        self.persist_pending_group();
        self.groups.remove(&chat);
        self.store.delete_chat(&chat)?;

        effects.push(Effect::Notify(Event::ChannelUnsubscribed { chat }));
        Ok(effects)
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
        // Контакт **или пир** (§8.3): заявитель пожал руку и лёг пиром,
        // а контактом владельцу не становится — §3.2 не обещал ему
        // списка знакомых из читателей. Требуй мы здесь контакта, впуск
        // отказывал бы ровно тому, кто только что попросился.
        if !self.contacts.contains_key(&peer_ik) && !self.peers.contains_key(&peer_ik) {
            return Err(EngineError::UnknownPeer);
        }
        if !self.right_holds(now_ms, chat, &me, channel::Rights::ADMIT)? {
            return Err(EngineError::NotAllowedInChannel);
        }
        let Some(current) = self.store.archive_keys(&chat)?.pop() else {
            return Err(EngineError::NoReadKeyYet);
        };

        let mut effects = self.join_channel_reader(now_ms, chat, peer_ik)?;

        // **Представление — нынешнее, и отдаёт его впуск.**
        //
        // `join_member` отдаёт новичку всё групповое: состав, карточки,
        // цепочки, название и породу. Канального в этом нет ничего:
        // права, цена слова и окно сидирования живут **в документе**,
        // а документ едет отдельным действием и только при правке (см.
        // `publish_representation`).
        //
        // Пока его не отдавали здесь, впущенный видел канал без породы,
        // с нулевой версией и без единого права — включая право, которое
        // владелец выдал ему **до** впуска. Документ приезжал только
        // со следующей правкой, то есть у канала, который никто не правит,
        // не приезжал никогда. Нашёл это стенд: «каналы создаются,
        // а обмена сведениями о них нет».
        //
        // Едет он **тем же действием**, каким едут новые версии, и потому
        // проходит тот же приём: подпись владельца, правило перехода,
        // порог версии из ссылки (§10.3). Своего пути для «первой копии»
        // не заводится — разойдись они, первая копия однажды принималась
        // бы по более слабому правилу, чем все последующие.
        let stored = self.store.channel(&chat)?.ok_or(EngineError::UnknownGroup)?;
        let document = ratatosk_proto::group_action::Action::Representation {
            bytes: ratatosk_codec::canonical::encode(&channel::wire_value(
                stored.block_bytes,
                &stored.signature,
            ))?,
        };
        let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &document)?;
        effects.extend(self.send_group_copy(now_ms, msg_id, peer_ik, &bytes)?);

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

        // **Каталог — вместе с впуском** (§7.5, §7.4 шаг 1: «представление
        // и `PeerRecord`ы — чтобы было у кого спрашивать»).
        //
        // Нашёл это замер: появление новичка в канале с сидом стоило
        // ровно столько же, сколько без сида, — он не привязывался
        // ни к кому. Записи каталога развозятся, когда сид объявляется
        // или продлевает запись (раз в несколько суток), а впущенный
        // между этими событиями не узнавал о сидах до следующего
        // продления. Снаружи это выглядело как «рой работает только
        // для тех, кто пришёл раньше сида».
        //
        // Едет тем же действием, что и развоз: подпись внутри — самого
        // сида, и впущенный проверит её сам, когда узнает его карточку.
        for seed in self.store.seeds(&chat)? {
            if seed.valid_until_ms <= now_ms || seed.ik == peer_ik {
                continue;
            }
            let record = ratatosk_proto::group_action::Action::SeedRecord {
                bytes: ratatosk_codec::canonical::encode(&ratatosk_proto::swarm::wire_value(
                    seed.record_bytes.clone(),
                    &seed.signature,
                ))?,
            };
            let (msg_id, _, bytes) = self.seal_group_action(now_ms, chat, &record)?;
            effects.extend(self.send_group_copy(now_ms, msg_id, peer_ik, &bytes)?);
        }

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
        // **Учёт смотрит владелец** (§6.5), и ему запись и едет — одним
        // адресованным кадром, а не веером по каналу.
        //
        // Веером она ехала раньше, и это был тот же самый промах, что
        // и у состава: «кто кого впустил» — сведение о составе, а §3.2
        // оставляет состав владельцу. Разослав запись читателям, мы
        // рассказали бы каждому из них, кто ещё читает канал.
        //
        // Свою же запись владелец никуда не шлёт: она у него и так лежит.
        let owner = self.groups.get(&chat).map_or(me, |state| state.group.owner);
        if owner != me {
            effects.extend(self.send_group_copy(now_ms, msg_id, owner, &bytes)?);
        }

        // Заявка отвечена — строка уходит: §10.4 называет впуск ответом
        // на неё, и держать её дальше значило бы показывать владельцу
        // просьбу, которую он уже выполнил.
        self.store.delete_channel_request(&chat, &peer_ik)?;

        effects.push(Effect::Notify(Event::ChannelAdmitted {
            chat,
            who: peer_ik,
            admitted_by: me,
        }));
        Ok(effects)
    }

    /// Вводит читателя в канал — **не раскрывая канал остальным** (§3.2).
    ///
    /// # Чем это отличается от вступления в группу
    ///
    /// [`Engine::join_member`] делает две вещи, которых в канале делать
    /// нельзя: рассказывает о новичке **каждому** уже состоящему (блок
    /// состава плюс карточка) и отдаёт новичку карточки и цепочки
    /// **всех** остальных. Для группы это и задумано — §11.5 прямо
    /// обещает, что участники увидят адреса друг друга. Для канала §3.2
    /// обещает обратное:
    ///
    /// | | `closed` | `channel` |
    /// |---|---|---|
    /// | Состав известен | всем | владельцу |
    /// | Адреса раскрыты | всем | только вызвавшимся раздавать |
    ///
    /// # Чем это обходилось, пока дорога была общей
    ///
    /// Не только свойством. Впуск стоил кадров по числу уже впущенных,
    /// то есть построение канала — квадрата; на двадцати читателях
    /// новичок получал разом больше сорока кадров, очередь отложенного
    /// (`MAX_PENDING_GROUP`) переполнялась и вытесняла **самые старые** —
    /// вместе с ключом чтения и представлением. Читатель оставался
    /// в составе и навсегда глухим. Нашёл это стенд на двадцати узлах.
    ///
    /// # Что получает новичок
    ///
    /// Ровно то, чем он читает канал, и ничего о других читателях:
    ///
    /// * вводный блок — название, владелец, порода, картинка;
    /// * карточки **владельца и впустившего** — первой проверяется
    ///   представление (§10.3 шаг 3), второй — блок, которым его впустили;
    /// * блок состава, который добавляет **его самого**: по нему он знает,
    ///   что впущен, и им же сможет уйти (§10.6). Чужих блоков нет;
    /// * цепочка отправителя **владельца**: в звезде публикует только он
    ///   ([`EngineError::OnlyOwnerPublishesYet`]), и больше ничьи ключи
    ///   читателю не нужны.
    ///
    /// Представление и ключ чтения досылает вызывающий: они канальные,
    /// а здесь то, что общее у всякого вступления.
    ///
    /// # Порядок кадров выбран, а не случаен
    ///
    /// Вводный блок первым: он заводит чат, и всё остальное, приехав
    /// раньше него, легло бы в очередь отложенного. Очередь это переживёт
    /// — но чем короче она в самый частый момент, тем меньше у неё
    /// поводов переполниться, а цену переполнения мы уже заплатили.
    pub(super) fn join_channel_reader(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let me = self.identity.public().ik;
        let at = self.fresh_tag(now_ms, me)?;
        let op = self.groups[&chat].group.invite(peer_ik, at)?;
        let block = self.record_own_ops(now_ms, chat, std::slice::from_ref(&op))?;
        if let Some(state) = self.groups.get_mut(&chat) {
            state.group.apply(op);
        }

        // Владелец — **тот, кого называет подписанный документ**
        // (`channel_owner`): им проверяется подпись представления, его
        // цепочкой открывается сказанное, и он же ведёт состав. Брать
        // его из состояния в памяти значило бы завести второй ответ
        // на тот же вопрос.
        let owner = self.channel_owner(chat).unwrap_or(me);
        let cards = self.cards_by_ik()?;
        let mut effects = Vec::new();

        // Вводный блок — первым (см. заголовок).
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
                profile: state.profile,
            };
            let value = group::intro_value(&intro);
            effects.extend(self.tell_member(now_ms, peer_ik, PayloadType::GroupIntro, value)?);
        }

        // Карточки — только владельца и впустившего. Ими проверяются
        // представление и блок о впуске; больше читателю проверять нечего.
        let needed: Vec<Vec<u8>> = [owner, me]
            .into_iter()
            .filter(|ik| *ik != peer_ik)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|ik| cards.get(&ik).cloned())
            .collect();
        if !needed.is_empty() {
            let roster = group::Roster { group: chat, cards: needed };
            effects.extend(self.tell_member(
                now_ms,
                peer_ik,
                PayloadType::GroupRoster,
                group::roster_value(&roster),
            )?);
        }

        // Блок, которым впустили **его самого**, — и только он.
        effects.extend(self.tell_member(
            now_ms,
            peer_ik,
            PayloadType::GroupMembership,
            block.clone(),
        )?);

        // Цепочка владельца: ею открывается всё, что в канале говорится.
        if let Some(chain) = self.store.sender_chain(&chat, &owner)? {
            let key_block = group::SenderKeyBlock {
                group: chat,
                member: owner,
                secret: group::ChainSecret::Open { chain: chain.chain, counter: chain.counter },
                // Метка чужая, как лежит: своей мы обогнали бы поворот
                // владельца и закрепили бы у новичка мёртвый ключ.
                chain_hlc: Hlc::new(chain.chain_wall, chain.chain_logical),
            };
            let value = self.sender_key_for(&key_block, peer_ik)?;
            effects.extend(self.tell_member(now_ms, peer_ik, PayloadType::SenderKey, value)?);
        }

        // **Владельцу — блок о новом читателе**, если впустил делегат:
        // состав ведёт владелец, и без этого кадра его список отстал бы
        // от впусков, а доставка — от состава.
        //
        // Вместе с блоком — **своя цепочка отправителя**. Блок состава
        // подписан и едет открытым, а запись о впуске (§6.5) уезжает
        // владельцу **действием**, то есть под ключом нашей цепочки.
        // Не скажи мы её вслух, владелец отложил бы учёт до появления
        // ключа, которого больше неоткуда взять: читатели друг друга
        // не знают, и прежняя рассылка «всем участникам» до него
        // не доходит.
        if owner != me {
            effects.extend(self.tell_member(now_ms, owner, PayloadType::GroupMembership, block)?);
            let mine = self.current_sender_key(chat)?;
            let value = self.sender_key_for(&mine, owner)?;
            effects.extend(self.tell_member(now_ms, owner, PayloadType::SenderKey, value)?);
        }

        effects.push(Effect::Notify(Event::GroupMembershipChanged { chat }));
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

    /// Поворачивает ключи чтения, которым пора (фаза 2, §6.4).
    ///
    /// # Расписание, а не таймер
    ///
    /// Повод спросить даёт драйвер — тот же, что у уборки (§12): цикл
    /// просыпается на каждое сообщение, а телефон значительную часть
    /// времени спит (§13.1), и таймер там не гарантирует ничего. Поэтому
    /// «пора или нет» — вопрос ко **времени последнего поворота**,
    /// лежащему в `channel_archive_keys`, а не к сработавшему сроку.
    /// Месяц, проспанный устройством, наступает при первом пробуждении
    /// после него.
    ///
    /// Сам опрос притормаживается часом (`KEY_ROTATION_SCAN_MS`):
    /// иначе поколения ключей всех каналов перечитывались бы с диска
    /// на каждое входящее слово.
    ///
    /// # Поворачивает только **владелец**
    ///
    /// Право «исключать» даёт поворот и делегату (§6.2), но расписание
    /// — политика канала, а не каждого держателя права. Крутись оно
    /// у всех, канал с тремя делегатами платил бы четыре рассылки в месяц
    /// вместо одной, и каждая стоит по запечатанному блоку на читателя.
    /// Делегат поворачивает руками, когда исключает читателя, — для этого
    /// право ему и дано.
    ///
    /// # Читателей может не быть, и это не повод пропускать
    ///
    /// Поворот в канале без читателей не стоит ни кадра: рассылать
    /// некому. Зато он держит верным обещание §6.4 — «свежему ключу
    /// не больше месяца», — и не заводит второго правила для случая
    /// «пока никого не впустили».
    ///
    /// # Errors
    ///
    /// Отказ хранилища на обходе. Отказ **одного** канала обходу
    /// не мешает: он записывается в журнал, и остальные поворачиваются.
    pub fn rotate_channels_if_due(&mut self, now_ms: u64) -> Result<Vec<Effect>, EngineError> {
        if now_ms.saturating_sub(self.last_rotation_scan_ms) < KEY_ROTATION_SCAN_MS {
            return Ok(Vec::new());
        }
        self.last_rotation_scan_ms = now_ms;

        // **Каталог роя освежается тем же обходом** (§7.5), и это не
        // экономия строк: оба дела меряются сутками и месяцами, а часов
        // у ядра нет — обход даёт им обоим единственный повод, который
        // случается на спящем телефоне. Заведи каталог свой обход,
        // он ходил бы по тому же признаку «прошло ли столько-то»,
        // то есть был бы второй копией этого.
        let mut effects = self.keep_catalogue_fresh(now_ms)?;

        let me = self.identity.public().ik;
        let mine: Vec<ChatId> = self
            .groups
            .iter()
            .filter(|(_, state)| !state.profile.everyone_writes() && state.group.owner == me)
            .map(|(chat, _)| *chat)
            .collect();

        let mut due = Vec::new();
        for chat in mine {
            // Порода спрашивается у документа: у открытого канала
            // поворота не бывает вовсе (§6.1, §10.7), и звать команду,
            // чтобы услышать отказ, значило бы писать отказ в журнал
            // раз в час до скончания века.
            let Some(stored) = self.store.channel(&chat)? else { continue };
            if channel::Kind::from_code(u64::from(stored.kind)) != Some(channel::Kind::ByInvite) {
                continue;
            }
            // Самый свежий ключ, какого бы он ни был поколения. Нулевое
            // — рождение канала (§6.5), и месяц расписания считается
            // от него так же, как от поворота: обещание §6.4 говорит
            // о возрасте **действующего** ключа, а не о частоте кнопки.
            let newest =
                self.store.archive_keys(&chat)?.into_iter().map(|key| key.created_ms).max();
            if newest.is_some_and(|at| now_ms.saturating_sub(at) >= KEY_ROTATION_PERIOD_MS) {
                due.push(chat);
            }
        }

        for chat in due {
            // Через ту же команду, что и кнопка. Второй путь поворота
            // означал бы второе место, где живут нижний предел, порода
            // и право, — и однажды они разошлись бы.
            match self.on_rotate_channel_key(now_ms, chat) {
                Ok(produced) => effects.extend(produced),
                Err(error) => tracing::warn!(
                    ?error,
                    канал = ?chat,
                    "ключ чтения по расписанию не повернулся"
                ),
            }
        }
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
            //
            // Отказ **свой**, а не «нет права»: право у владельца как раз
            // есть, и сказав ему обратное, мы отправили бы его искать,
            // кто это право отнял. Разница поймана на стенде — владелец
            // набрал свой ключ вместо чужого.
            return Err(EngineError::OwnerNeedsNoGrant);
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
        // **Молчим, а не отмечаем аномалию.** «Проверить нечем» — это
        // не «подпись не сошлась»: карточка едет отдельным кадром
        // и вправе опоздать (§4.3).
        //
        // # Почему здесь не откладывают, хотя везде вокруг откладывают
        //
        // Сюда доходят только **расшифрованные** кадры, а номер цепочки
        // к этому моменту израсходован (`open_group_frame` фиксирует его
        // до разбора). Положи мы кадр в очередь отложенного, на втором
        // заходе он не открылся бы вовсе: ключ этого номера уже отдан
        // и стёрт. Очередь приняла бы кадр, разбор бы его потерял,
        // и починка выглядела бы работающей, ничего не чиня.
        //
        // # Случай, в который эта ветка попадает, сегодня недостижим
        //
        // Документ везёт владелец, а его кадр открывается его же
        // цепочкой — и карточку `open_group_frame` спросил **до**
        // расшифровки и отложил бы кадр там, где откладывать ещё можно.
        // Значит сюда попадает лишь документ, привезённый **чужими
        // руками**: ретрансляция (§3.1) или чужая сборка. Первой ещё нет,
        // второй мы ничего не должны.
        //
        // Когда ретрансляция появится, чинить это надо не очередью
        // кадров, а очередью **документов**: байты здесь уже разобраны
        // и от цепочки не зависят.
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

        // **Название чата берётся отсюда, и это правка поломки со стенда.**
        // У канала имя живёт в подписанном представлении (§6.1), а строка
        // чата у читателя заводится пустой: при переходе по ссылке названия
        // ещё нет, его привозит документ. Записывали мы его только
        // в `channel_representations` — и канал у читателя навсегда
        // оставался чатом без имени, хотя событие о новой версии имя
        // называло. Снаружи: «332b07081e64 «»» в списке чатов.
        //
        // Метка берётся у часов **сейчас**, а не сравнивается с прежней:
        // порядок представлений задаёт версия (её стережёт `accepts`
        // выше), а не HLC. Строка чата у читателя родилась с его
        // собственной меткой в миг подписки, и метка владельца — из более
        // раннего документа — проиграла бы ей молча.
        let at = self.clock.now(now_ms)?;
        self.apply_rename(chat, &next.title, at)?;

        Ok(vec![Effect::Notify(Event::ChannelChanged {
            chat,
            version: next.version,
            title: next.title,
        })])
    }
}
