//! Контакты, карточки и аватарки.
//!
//! Заведение контакта, обновление карточки, обмен контактами (§4.3)
//! и аватарки — всё, что описывает **собеседника**, а не разговор с ним.
//!
//! Карточка едет в рукопожатии, а не до него (§8.2), и потому контакт
//! заводится на приёме сам: `add_contact` здесь — точка, где незнакомец
//! становится известным.

use super::*;

impl<S: Store> Engine<S> {
    /// Складывает контакт на диск (§4, §12).
    ///
    /// Времени не берёт, и это не мелочь. Раньше брало — и подставляло
    /// в `created_ms`, отчего столбец «когда добавлен» означал на деле
    /// «когда последний раз трогали»: контакт пишется и при сверке,
    /// и при каждом обновлении карточки (§4.3). Момент добавления теперь
    /// живёт в `Contact::added_ms` и не зависит от того, когда мы решили
    /// сохраниться.
    ///
    /// Параметр убран, а не подчёркнут: неиспользуемый аргумент — это
    /// приглашение вернуть в него `now_ms` и починить «ошибку», которой нет.
    pub(super) fn persist_contact(&mut self, peer_ik: &[u8; 32]) -> Result<(), EngineError> {
        let Some(contact) = self.contacts.get(peer_ik) else {
            return Ok(());
        };
        // §6: подпись считается над принятыми байтами, поэтому карточка
        // сохраняется целиком и неизменной, а не пересобирается из полей.
        let card_bytes = contact.card.encode()?;
        let stored = ratatosk_store::StoredContact {
            ik: contact.card.ik,
            sk: contact.card.sk,
            onion: contact.card.onion.clone(),
            chatmail: contact.card.chatmail.clone(),
            display_name: contact.card.display_name.clone(),
            card_version: contact.card.version,
            card_bytes,
            verified: contact.verified,
            // Момент добавления, а не момент записи. Раньше здесь стояло
            // `now_ms`, и первое же обновление карточки (§4.3) или снятие
            // сверки переписывало «добавлен» на «сегодня».
            created_ms: contact.added_ms,
            local_name: contact.local_name.clone(),
            ygg: contact.card.ygg.clone(),
        };
        self.store.put_contact(&stored)?;
        Ok(())
    }

    pub(super) fn add_contact(
        &mut self,
        now_ms: u64,
        card_bytes: &[u8],
        met_in_person: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let card = ContactCard::decode(card_bytes)?.into_parts().1;
        let peer_ik = card.ik;
        let fingerprint =
            ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk)?.fingerprint();

        let availability = PeerAvailability {
            // Меш наравне с onion и почтой: ключ в карточке — это путь,
            // и появиться он может уже в первой карточке, добытой по QR.
            // Пропусти его здесь — ступень поднялась бы только после
            // перезапуска, когда `restore` пересчитает всё с диска.
            has_ygg: !card.ygg.is_empty(),
            has_onion: !card.onion.is_empty(),
            has_nostr: !card.nostr.is_empty(),
            has_chatmail: !card.chatmail.is_empty(),
            ..PeerAvailability::default()
        };

        // §4.2: QR при личной встрече — канал доверенный по построению,
        // ссылка — нет, и контакт остаётся непроверенным до сверки голосом.
        // Новый контакт наследует текущее состояние LAN: иначе контакт,
        // добавленный после включения, остался бы с выключенным LAN,
        // и §5.4 отправил бы его сообщения мимо локальной сети — молча,
        // потому что onion и почта тоже «работают».
        let availability = PeerAvailability {
            enabled: self.announcing(),
            ready: self.ready,
            seen_on_lan: self.seen_on_lan.remove(&peer_ik),
            // И то же про эфир: объявление могло прозвучать раньше, чем
            // человек досканировал карточку. Потерять отметку значило бы
            // отправить почтой сообщение тому, кто сидит за столом
            // напротив.
            seen_on_bt: self.seen_on_bt.remove(&peer_ik),
            ..availability
        };

        // Аватарка могла приехать раньше карточки: контакт добавляют после
        // того, как сессия уже установлена и что-то по ней приходило.
        let has_avatar = self.store.has_avatar(&peer_ik)?;
        // Локальное имя переживает всё, кроме удаления контакта: карточка
        // может приехать заново (§4.3), а подпись пользователя — его, и
        // затирать её обновлением с той стороны нельзя.
        let local_name = self.contacts.get(&peer_ik).and_then(|c| c.local_name.clone());
        // Та же причина, что у локального имени: `add_contact` зовётся
        // не только при первом добавлении, но и когда карточка приехала
        // заново (§4.3) или пришла третьим человеком. Момент добавления
        // при этом не меняется.
        let added_ms = self.contacts.get(&peer_ik).map_or(now_ms, |c| c.added_ms);
        self.contacts.insert(
            peer_ik,
            Contact {
                card,
                verified: met_in_person,
                availability,
                local_name,
                has_avatar,
                added_ms,
            },
        );
        self.by_chat.insert(Self::chat_id_for(&peer_ik), peer_ik);
        self.persist_contact(&peer_ik)?;

        let mut effects = vec![Effect::Notify(Event::ContactAdded {
            peer_ik,
            fingerprint,
            verified: met_in_person,
        })];
        // Маяк нового контакта транспорт ещё не ищет — список изменился.
        // Без оглядки на включённые ступени: эфиров два, и разбор, почему
        // оглядки здесь нет, лежит у самого `watch_peers`.
        effects.push(self.watch_peers());
        // Появившаяся карточка — это появившийся путь, и ждущее её обязано
        // поехать. Здесь ждут копии участника группы, которого добавил
        // кто-то другой: в составе он был сразу, а карточка приехала сейчас
        // (§11.5, `park_for_card`). Без этой строки они лежали бы до первого
        // постороннего повода, а сказанное в окно между составом и карточкой
        // не доехало бы вовсе.
        effects.extend(self.retry_deferred(Some(peer_ik))?);
        Ok(effects)
    }

    /// Поделиться контактом: отправить в чат карточку известного человека.
    ///
    /// Своей карточкой — можно, и это та же операция: `peer_ik` совпадает
    /// с собственным `IK`, карточка берётся своя. Отдельного механизма
    /// «передать визитку» заводить незачем.
    ///
    /// Что **не** едет: локальное имя, которым пользователь подписал человека
    /// у себя (§4.1 — «по проводу не едет никогда»: это заметка о своём
    /// отношении, а не свойство контакта), и признак сверки — присланный
    /// контакт непроверен всегда.
    pub(super) fn on_share_contact(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let own_ik = self.identity.public().ik;
        let card_bytes = if peer_ik == own_ik {
            self.own_card().encode()?
        } else {
            let contact = self.contacts.get(&peer_ik).ok_or(EngineError::UnknownPeer)?;
            contact.card.encode()?
        };

        // Группа — первой, как и везде, где берётся `chat`. Карточка едет
        // туда своим видом действия: тот же смысл, та же обвязка (§11.3).
        if self.groups.contains_key(&chat) {
            return self.share_contact_in_group(now_ms, chat, peer_ik, card_bytes);
        }
        let Some(&recipient) = self.by_chat.get(&chat) else {
            return Err(EngineError::UnknownPeer);
        };
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();

        // Тело пустое: карточка лежит записью рядом, как вложение. Класть
        // её байты в текст значило бы показать человеку CBOR, если клиент
        // забудет про отдельное поле, — а §14 просит не показывать того,
        // чего человек не поймёт.
        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: own_ik,
            hlc,
            body: Vec::new(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        self.store.put_contact_share(&StoredContactShare {
            msg_id,
            ik: peer_ik,
            card_bytes: card_bytes.clone(),
        })?;

        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::ContactShare,
            ratatosk_proto::contact_share::payload(&card_bytes, false),
        );
        self.enqueue(Delivery {
            msg_id,
            peer_ik: recipient,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            silent: false,
        })
    }

    /// Делится карточкой в группе (§11.3).
    ///
    /// Отличий от 1:1 два, и оба общие для всего группового: кадр собирается
    /// действием под ключом отправителя, а у копии нет статуса доставки.
    /// Всё остальное — то же самое, включая пустое тело и запись карточки
    /// рядом с сообщением.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки группового кадра.
    pub(super) fn share_contact_in_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        card_bytes: Vec<u8>,
    ) -> Result<Vec<Effect>, EngineError> {
        let action = ratatosk_proto::group_action::Action::ContactShare {
            card_bytes: card_bytes.clone(),
            forwarded: false,
        };
        // Кадр — до записи в базу, тот же порядок и тот же довод, что везде
        // в группе: сборка вправе отказать, а запись после отказа человек
        // видел бы вечно отправляющейся.
        let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: Vec::new(),
            received_ms: now_ms,
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        self.store.put_contact_share(&StoredContactShare { msg_id, ik: peer_ik, card_bytes })?;
        self.fan_out_group(now_ms, chat, msg_id, &bytes)
    }

    /// Адреса устройства изменились — сказать об этом контактам (§4.3).
    ///
    /// **Всем сразу, а не тому, кто спросит.** Устройство не знает, какую
    /// версию карточки помнит каждый: карточка расходится по QR, ссылкам
    /// и пересылкам, и обратной связи в этом канале нет. Обновление уходит
    /// каждому контакту отдельной доставкой, дальше §5.4 разбирается сам,
    /// а тем, кого сейчас нет в сети, оно ждёт в очереди наравне с текстом.
    ///
    /// **Тот же адрес — ничего не происходит.** Иначе каждый подъём Tor
    /// поднимал бы версию и рассылал обновление всем, а на телефоне подъём
    /// случается при каждом возвращении сети.
    ///
    /// Записью в истории не становится: адрес — свойство устройства,
    /// а не сообщение человеку. В чате показывать нечего.
    pub(super) fn on_announce_addresses(
        &mut self,
        now_ms: u64,
        onion: Option<String>,
        chatmail: Option<String>,
    ) -> Result<Vec<Effect>, EngineError> {
        // `None` — «не трогать». Разворачивается в текущее значение первым
        // делом, до всякого сравнения: дальше по функции обе половины
        // карточки уже равноправны.
        //
        // Раньше `None` не существовало, и вызывающий, знающий только одну
        // половину, подставлял во вторую пустую строку — то есть **стирал**
        // работающий адрес. Так стенд терял почтовый ящик по команде `/onion`,
        // а на устройстве с одной только почтой это означало «до меня больше
        // не достучаться»: собеседник терял адрес, а сказать ему новый было
        // уже не по чему.
        let onion = onion.unwrap_or_else(|| self.addresses.onion.clone());
        let chatmail = chatmail.unwrap_or_else(|| self.addresses.chatmail.clone());
        // Сравнивается с **объявленным**, а не с текущим состоянием в памяти:
        // после перезапуска адреса подняты с диска именно оттуда, и повтор
        // того же объявления обязан остаться бесплатным.
        //
        // Имя тоже участвует: карточка везёт его целиком, и человек,
        // переименовавшийся между запусками, иначе остался бы для контактов
        // под прежним именем навсегда.
        let unchanged = self.announced.as_ref().is_some_and(|last| {
            last.onion == onion
                && last.chatmail == chatmail
                && last.display_name == self.addresses.display_name
                // Ключ меша (0.2) участвует наравне с адресами: он часть
                // карточки, а значит его появление или смена — та же смена
                // карточки, и §4.3 обязан о ней узнать.
                && last.ygg == self.ygg
                // И ключ nostr (0.3) — по тому же доводу, что ключ меша:
                // он часть карточки, и его появление или смена есть смена
                // карточки.
                && last.nostr == self.nostr
                // И список реле: собеседник кладёт события туда, куда
                // он указывает. Смени человек реле и не объяви — события
                // продолжали бы уходить на прежние, то есть в никуда.
                && last.nostr_relays == self.nostr_card_relays()
        });
        if unchanged {
            return Ok(Vec::new());
        }

        self.addresses.onion = onion;
        self.addresses.chatmail = chatmail;

        let version = self.announced.as_ref().map_or(1, |last| last.version) + 1;
        let card = ContactCard { version, ..self.own_card() };

        // Байты считаются один раз и служат трижды: их подписывают, их
        // отправляют, их же кладут на диск. §6 требует, чтобы проверяемое
        // проверялось над принятым представлением, и три разных вычисления
        // «того же самого» — способ однажды получить три разных ответа.
        let bytes = card.encode()?;
        let signature = self.identity.sign(&bytes);

        // Запись — до рассылки. Разослать и не сохранить значит после
        // перезапуска выдать ту же версию второй раз: у получателей она
        // уже не «строго больше», и следующая смена адреса до них не доедет.
        self.store.put_meta(ratatosk_store::META_SELF_CARD, &bytes)?;
        self.announced = Some(card);

        let payload = ratatosk_proto::card_update::payload(&bytes, &signature);
        let recipients: Vec<[u8; 32]> = self.contacts.keys().copied().collect();
        // Версия сменилась — значит всё, что досылалось раньше, относилось
        // к прежней карточке и больше ничего не значит.
        self.card_pushed.clear();
        let mut effects = Vec::new();
        for peer_ik in recipients {
            let (msg_id, produced) =
                self.enqueue_request(now_ms, peer_ik, PayloadType::CardUpdate, payload.clone())?;
            effects.extend(produced);
            // Отметка — **после** постановки и только если доставка выжила.
            //
            // Раньше она ставилась до неё, то есть по факту намерения.
            // Отметка означает «этому уже рассказали», и на ней стоит
            // страховка `push_own_card`: она досылает карточку, когда
            // появляется сессия. Пометив контакт, до которого рассылка
            // не доехала (адресов в его карточке нет, LAN выключен —
            // `remember_undelivered` честно отвечает «ждать нечего»),
            // мы разоружали страховку до конца запуска: набор живёт
            // в памяти. Собеседник дозванивался к нам сам, рукопожатие
            // проходило, а наши адреса он так и не узнавал.
            if self.delivery_alive(&msg_id, &peer_ik) {
                self.card_pushed.insert(peer_ik);
            }
        }
        // **И второму экрану — тоже.** Смена адреса это §4.3 для контактов
        // и `Notice::LinkAddress` для сопряжённых устройств: путь другой,
        // а факт один — нас теперь набирают иначе.
        //
        // Без этой строки десктоп узнавал бы о поднявшемся Tor или включённом
        // меше только при следующем подключении, а подключается он тогда,
        // когда прежний путь уже отказал, — то есть ровно тогда, когда новый
        // адрес и был нужен.
        effects.extend(self.tell_link_addresses(now_ms));
        Ok(effects)
    }

    /// Говорит всем подключённым устройствам, чем нас набрать (§13.4 + 0.2).
    ///
    /// Отказ одного устройства не мешает остальным и не роняет команду:
    /// смена адреса — событие про нас, а не про десктоп, и не состояться
    /// она не может из-за того, что кому-то не удалось об этом сказать.
    pub(super) fn tell_link_addresses(&mut self, now_ms: u64) -> Vec<Effect> {
        let links: Vec<([u8; 32], Transport)> =
            self.device_links.iter().map(|(key, via)| (*key, *via)).collect();
        let mut effects = Vec::new();
        for (pairing_public, via) in links {
            match self.tell_link_address(now_ms, pairing_public, via) {
                Ok(sent) => effects.extend(sent),
                Err(error) => tracing::warn!(?error, "свой адрес десктопу не ушёл"),
            }
        }
        effects
    }

    /// Досылает свою карточку одному контакту (§4.3).
    ///
    /// Дыра, которую это закрывает, видна только на двух устройствах, и она
    /// не в протоколе, а в том, **когда** мы им пользуемся.
    /// [`Engine::on_announce_addresses`] рассылает обновление тем контактам,
    /// которые есть на момент объявления, — и на этом останавливается. Дальше
    /// возможны три случая, и во всех трёх собеседник остаётся без адреса:
    ///
    /// * контакт добавлен **после** объявления — рассылка его не застала;
    /// * ссылка на карточку скопирована до объявления — в ней пустой `onion`,
    ///   а повторное объявление того же адреса бесплатно (и потому молчит);
    /// * контакт добавлен заново после перезапуска — `announced` поднят
    ///   с диска, объявлять нечего, рассылки нет.
    ///
    /// Карточка едет и в первом сообщении рукопожатия (§8.2), но там она
    /// применяется, только если контакт ещё не заведён: менять адреса уже
    /// известного человека кадром без подписи нельзя. Значит, единственный
    /// путь для нового адреса — подписанный `CardUpdate`, и досылать его надо
    /// самим.
    ///
    /// Момент выбран самый ранний из возможных — установление сессии
    /// и добавление контакта: раньше кадр всё равно некуда деть.
    pub(super) fn push_own_card(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        // Не объявляли ничего — и досылать нечего: у собеседника карточка
        // первой версии, ровно та же, что у нас.
        let Some(card) = self.announced.as_ref() else { return Ok(Vec::new()) };
        if !self.contacts.contains_key(&peer_ik) {
            return Ok(Vec::new());
        }
        // Второй раз одному и тому же в одном запуске — впустую: `Stale`
        // на той стороне (§4.3) и лишний кадр на этой. Но отметка ставится
        // ниже и по тому же правилу, что в рассылке: только если доставка
        // выжила. Иначе первая же неудачная досылка запирала бы все
        // следующие.
        if self.card_pushed.contains(&peer_ik) {
            return Ok(Vec::new());
        }

        // Байты пересобираются, а не берутся с диска, и это то же самое:
        // CBOR детерминированный (§6), подпись Ed25519 — тоже.
        let bytes = card.encode()?;
        let signature = self.identity.sign(&bytes);
        let payload = ratatosk_proto::card_update::payload(&bytes, &signature);
        let (msg_id, effects) =
            self.enqueue_request(now_ms, peer_ik, PayloadType::CardUpdate, payload)?;
        if self.delivery_alive(&msg_id, &peer_ik) {
            self.card_pushed.insert(peer_ik);
        }
        Ok(effects)
    }

    /// Собеседник сменил адреса (§4.3).
    ///
    /// Проверки — в `ratatosk_proto::card_update`, и там же объяснено, почему
    /// их пять и почему именно в таком порядке. Здесь остаётся то, что нельзя
    /// проверить без состояния: обновление о неизвестном человеке применять
    /// некуда, и это не ошибка — контакт могли удалить, пока кадр ехал.
    ///
    /// **Сверка (§4.2) переживает обновление.** `IK` и `SK` не изменились —
    /// значит, отпечаток тот же, значит, сверять заново нечего. Сбрасывать
    /// признак при каждой смене адреса значило бы просить человека звонить
    /// собеседнику всякий раз, когда у того поднялся Tor, — и приучить его
    /// подтверждать не глядя.
    ///
    /// **Локальное имя тоже остаётся.** Это подпись пользователя о своём
    /// отношении, и обновление с той стороны её не касается.
    pub(super) fn on_card_update(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — до всякого разбора, и по той же причине, что
        // у групповых кадров (`on_group_frame`): обновление §4.3 едет
        // через `enqueue_request`, то есть **не** молчаливым, а значит
        // у него заведён срок. Без подтверждения срок объявляет неудачу,
        // §5.4 отправляет сессию на покой и начинает новое рукопожатие —
        // и так на каждой рассылке карточки, пока кадры собеседника
        // не начнут пропадать как «сессия неизвестна».
        //
        // Именно до разбора: повтор старой карточки — обычное дело
        // (обновление уходит всем сразу, а пути §5.4 разной длины), но
        // отправитель ждёт подтверждения **приёма кадра**, а не согласия
        // с его содержимым. Промолчи мы на повторе — он слал бы его ещё
        // и ещё.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Some(known) = self.contacts.get(&peer_ik) else { return Ok(effects) };

        let card =
            match ratatosk_proto::card_update::accept(&envelope.payload, &peer_ik, &known.card) {
                Ok(card) => card,
                // Повтор старого — обычное дело: обновление ушло всем сразу,
                // а пути у §5.4 разной длины. Тишина, а не счётчик аномалий.
                Err(ratatosk_proto::card_update::UpdateError::Stale) => return Ok(effects),
                Err(_) => {
                    self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                    return Ok(effects);
                }
            };

        let Some(contact) = self.contacts.get_mut(&peer_ik) else { return Ok(effects) };
        // Все четыре пути пересчитываются разом. Ключ меша появляется в карточке
        // ровно так же, как onion после подъёма Tor, — обновлением §4.3, —
        // и забытая здесь строка означала бы «ключ знаем, а ступени нет»:
        // §5.4 меш не выбрал бы никогда, до самого перезапуска.
        contact.availability.has_ygg = !card.ygg.is_empty();
        contact.availability.has_onion = !card.onion.is_empty();
        contact.availability.has_nostr = !card.nostr.is_empty();
        contact.availability.has_chatmail = !card.chatmail.is_empty();
        contact.card = card;
        self.persist_contact(&peer_ik)?;

        // Появившийся адрес — это появившийся путь. Сообщения, которым
        // некуда было ехать, ждали именно этого (§5.4).
        effects.push(Effect::Notify(Event::ContactChanged { peer_ik }));
        effects.extend(self.retry_deferred(Some(peer_ik))?);
        // И наша карточка — туда же, если ещё не рассказывали. Собеседник
        // только что сообщил, где он; это самый ранний момент, когда наше
        // обновление до него вообще может доехать.
        //
        // Случай не выдуманный: двое, добавившие друг друга ссылкой раньше,
        // чем у них появились адреса, иначе не находят друг друга вовсе.
        // Рассылка в обе стороны легла в никуда (адресов не было), а `Stale`
        // на той стороне отсеет лишнее, если рассказать нам было нечего.
        effects.extend(self.push_own_card(now_ms, peer_ik)?);
        Ok(effects)
    }

    /// Пришла карточка третьего человека.
    ///
    /// Ложится в историю записью и **ничего не меняет**: ни контактов,
    /// ни адресов уже известного человека. Решение принимает пользователь
    /// ([`Command::AddSharedContact`]).
    pub(super) fn on_contact_share(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Разбор здесь, а не при показе: испорченная карточка не должна
        // добираться до истории и ждать там нажатия, которое всё равно
        // ничем не кончится.
        let (card_bytes, card, forwarded) =
            ratatosk_proto::contact_share::from_payload(&envelope.payload).map_err(|e| {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                e
            })?;
        // Ключи обязаны складываться в отпечаток: карточка с мусором вместо
        // `SK` не добавится никогда, и держать её в истории незачем.
        if ratatosk_crypto::PublicIdentity::from_bytes(card.ik, card.sk).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        let shared_ik = card.ik;
        // Пометка едет признаком в нагрузке, а не типом конверта, — и
        // применяется тем же путём, каким её применяет пересланный текст.
        let kind = if forwarded { TextKind::Forwarded } else { TextKind::Plain };
        let mut effects = self.on_incoming_text(now_ms, via, peer_ik, envelope, "", kind)?;
        // Запись — после сообщения: внешний ключ ведёт на него, и обратный
        // порядок был бы карточкой, приложенной к тому, чего ещё нет.
        // Если сообщение не легло (дубль, надгробие), карточке тем более
        // незачем ложиться.
        if self.store.message(&envelope.msg_id)?.is_some() {
            self.store.put_contact_share(&StoredContactShare {
                msg_id: envelope.msg_id,
                ik: shared_ik,
                card_bytes,
            })?;
        } else {
            effects.clear();
        }
        Ok(effects)
    }

    /// Человек решил добавить присланный контакт.
    ///
    /// **Всегда непроверенным.** Даже если тот, кто поделился, у нас сверен:
    /// §4.2 — про сверку отпечатка голосом с самим человеком, а поручительство
    /// друга это не она. Подпись бы тут не помогла — её у карточки нет
    /// и не бывает (`ratatosk_proto::contact_share`).
    ///
    /// **Известный контакт не трогается.** Ни адреса, ни версия карточки,
    /// ни признак сверки. Иначе кто угодно пришлёт «Кэрол версии 99» со своим
    /// onion-адресом и уведёт маршрут на себя; адреса меняет только
    /// подписанный `CardUpdate` из сессии самой Кэрол (§4.3).
    pub(super) fn on_add_shared_contact(
        &mut self,
        now_ms: u64,
        msg_id: MsgId,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(share) = self.store.contact_share_of(&msg_id)? else { return Ok(Vec::new()) };
        if share.ik == self.identity.public().ik {
            // Своя карточка, вернувшаяся к нам. Добавлять себя в контакты
            // нечего, и это не ошибка — просто нажатие ни к чему не ведёт.
            return Ok(Vec::new());
        }
        if self.contacts.contains_key(&share.ik) {
            // Уже знаем. Молча и без изменений — см. выше про подмену адресов.
            return Ok(Vec::new());
        }
        let peer_ik = share.ik;
        let mut effects = self.add_contact(now_ms, &share.card_bytes, false)?;
        // Присланная третьим человеком карточка тем более может быть старой:
        // она ехала через чужое устройство и чужую очередь.
        effects.extend(self.push_own_card(now_ms, peer_ik)?);
        Ok(effects)
    }

    /// Добавляет к своим знакомствам те, что лежат в архиве (§12).
    ///
    /// **Это не восстановление, и путать их нельзя.** Восстановление
    /// (`ratatosk_store::import_archive`) делает архив аккаунтом целиком
    /// и требует чистого места. Здесь личность остаётся **своя**, переписка
    /// своя, а из архива берутся только контакты — «добавь эти знакомства
    /// к моим». Вопроса «чья личность» тут не возникает, поэтому и делать
    /// это можно поверх живого аккаунта.
    ///
    /// # Известный контакт не трогается — никогда
    ///
    /// Ни адреса, ни версия карточки, ни сверка. Правило то же, что
    /// у присланного контакта (§4.1), и по той же причине: карточка
    /// в архиве **не подписана** — подпись есть у `CardUpdate`, а не
    /// у карточки. Разреши мы обновление, и граф, полученный от кого
    /// угодно, переписал бы onion-адрес моего собеседника на чужой.
    /// Настоящий путь для нового адреса один — подписанное обновление
    /// от самого человека (§4.3).
    ///
    /// # Сверка переносится только из **своего** прошлого
    ///
    /// Архив помнит, кого мы сверили голосом (§4.2). Если он вывезен этой же
    /// личностью — это наша собственная запись, и терять её при переезде
    /// незачем: иначе смена телефона молча снимала бы отметку со всех сразу.
    /// Если чужой — сверка не переносится ни при каких условиях: доверие
    /// не транзитивно, и поручительство друга сверкой голосом не является.
    ///
    /// По той же границе идут локальные имена: своё прошлое — своё, чужие
    /// подписи к людям — чужие.
    ///
    /// `scratch` — каталог для черновика (см. `open_snapshot`).
    ///
    /// # Errors
    ///
    /// Файла нет, это не архив, он оборван, ключ или фраза не те, схема
    /// новее этой сборки, отказ хранилища.
    pub fn merge_contacts_from(
        &mut self,
        now_ms: u64,
        archive: &Path,
        unlock: ratatosk_store::ArchiveUnlock<'_>,
        scratch: &Path,
    ) -> Result<(Merged, Vec<Effect>), EngineError> {
        let snapshot = ratatosk_store::open_snapshot(archive, unlock, scratch)?;

        // Чей это граф — свой или чужой. Ответ решает две вещи: переносится
        // ли сверка и переносятся ли локальные имена. Зерно личности лежит
        // в архиве запечатанным тем же ключом, каким открыт сам архив.
        let own_ik = self.identity.public().ik;
        let theirs = crate::vault::identity_in(&snapshot.store, &snapshot.key)?;
        let own_graph = theirs.map(|id| id.public().ik) == Some(own_ik);

        let mut merged = Merged { own_graph, added: 0, known: 0, refused: 0 };
        let mut effects = Vec::new();
        for contact in snapshot.store.contacts()? {
            // Сам себе не контакт: свой же `IK` в чужом графе — это запись
            // о нас у кого-то другого, и заводить из неё «контакт» нельзя.
            if contact.ik == own_ik {
                continue;
            }
            if self.contacts.contains_key(&contact.ik) {
                merged.known += 1;
                continue;
            }
            // Карточка обязана разбираться, а её ключ — совпадать с ключом
            // строки: архив мог быть собран не нами, и строка, чей `ik`
            // разошёлся с карточкой, — это попытка подсунуть одного человека
            // под именем другого.
            let card = match ContactCard::decode(&contact.card_bytes) {
                Ok(card) if card.value().ik == contact.ik => card,
                _ => {
                    merged.refused += 1;
                    continue;
                }
            };
            // И ключи обязаны складываться в отпечаток — то же, что при
            // присланном контакте: карточка с мусором вместо `SK`
            // не добавится никогда.
            if ratatosk_crypto::PublicIdentity::from_bytes(contact.ik, card.value().sk).is_err() {
                merged.refused += 1;
                continue;
            }

            // Аватарка — **до** контакта: `add_contact` спрашивает, есть ли
            // она, и порядок наоборот дал бы контакт с пометкой «аватарки
            // нет» при лежащей рядом аватарке.
            if let Some(avatar) = snapshot.store.avatar(&contact.ik)? {
                self.store.put_avatar(&contact.ik, &avatar)?;
            }

            // Дверь та же, через которую контакты добавляются всегда:
            // чат, событие, список маяков — всё оттуда.
            effects.extend(self.add_contact(
                now_ms,
                &contact.card_bytes,
                own_graph && contact.verified,
            )?);
            if own_graph {
                if let Some(name) = contact.local_name {
                    effects.extend(self.on_set_local_name(contact.ik, Some(name))?);
                }
            }
            merged.added += 1;
        }
        Ok((merged, effects))
    }

    /// Подписывает контакт своим именем — или снимает подпись.
    ///
    /// Пустая строка после обрезки пробелов считается снятием: человек,
    /// стёрший имя в поле ввода, имел в виду именно это, а не «подписать
    /// пустотой». Возвращать его к имени из карточки — правильный исход,
    /// и заставлять клиент отличать `Some("")` от `None` незачем.
    pub(super) fn on_set_local_name(
        &mut self,
        peer_ik: [u8; 32],
        name: Option<String>,
    ) -> Result<Vec<Effect>, EngineError> {
        let trimmed = name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
        if let Some(name) = &trimmed {
            if name.chars().count() > MAX_LOCAL_NAME_CHARS {
                return Err(EngineError::LocalNameTooLong);
            }
        }

        let contact = self.contacts.get_mut(&peer_ik).ok_or(EngineError::UnknownPeer)?;
        contact.local_name = trimmed;
        self.persist_contact(&peer_ik)?;
        Ok(vec![Effect::Notify(Event::ContactChanged { peer_ik })])
    }

    /// Удаляет контакт — и всё, что было привязано к его личности.
    ///
    /// Что уходит всегда: карточка, отметка о сверке (§4.2), аватарка, сессия
    /// вместе с ключевым материалом (§8.3), незаконченное рукопожатие и всё,
    /// что стояло в очереди этому человеку. Оставить сессию значило бы держать
    /// ключи для собеседника, которого у пользователя больше нет, — а §12
    /// требует, чтобы удаление удаляло.
    ///
    /// Что уходит по решению человека: переписка. Ядро её не выбрасывает само
    /// и не оставляет само — за это отвечает `purge_history`.
    ///
    /// **Чего эта команда не делает: она не мешает собеседнику вернуться.**
    /// Его рукопожатие (§8.2) заведёт контакт заново — уже несверенным, но
    /// заведёт. Удаление — это «убрать у себя», а не «запретить писать»;
    /// обещать второе, умея только первое, §14 запрещает прямо. Текст для UI
    /// лежит в [`crate::honest::DELETION_NOTICE`].
    pub(super) fn on_delete_contact(
        &mut self,
        peer_ik: [u8; 32],
        purge_history: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        if !self.contacts.contains_key(&peer_ik) {
            return Err(EngineError::UnknownPeer);
        }
        let chat = Self::chat_id_for(&peer_ik);

        // Сессии — первыми и из обоих мест сразу: из реестра в памяти и
        // с диска. Пережившая удаление запись в реестре продолжала бы
        // расшифровывать кадры от человека, которого больше нет в контактах.
        //
        // **Все**, а не «по одной на транспорт»: спрашивать здесь `for_peer`
        // значило бы пропустить отправленные на покой — а они как раз и живут
        // ради приёма, то есть ровно того, что удаление обязано прекратить.
        for session_id in self.sessions.all_for_peer(&peer_ik) {
            self.sessions.remove(session_id);
            self.store.delete_session(session_id)?;
        }

        // Незаконченное рукопожатие и очередь: без контакта `advance` всё
        // равно упрётся в `UnknownPeer`, и записи остались бы навсегда.
        self.pending.retain(|p| p.peer_ik != peer_ik);
        self.outbox.retain(|d| d.peer_ik != peer_ik);
        for waiting in std::mem::take(&mut self.deferred) {
            if waiting.peer_ik == peer_ik {
                self.store.delete_outbox(&waiting.msg_id, &peer_ik)?;
            } else {
                self.deferred.push(waiting);
            }
        }

        self.contacts.remove(&peer_ik);
        self.by_chat.remove(&chat);
        self.seen_on_lan.remove(&peer_ik);
        self.awaited_discovery.remove(&peer_ik);
        self.read_upto.remove(&chat);

        self.store.delete_contact(&peer_ik)?;
        self.store.delete_avatar(&peer_ik)?;
        if purge_history {
            // Байты вложений — **до** `delete_chat`, и только в этом порядке.
            // Он уносит сообщения, каскад внешних ключей уносит следом записи
            // о файлах, и после него спросить «какие вложения были в этом
            // чате» уже не у кого: каталоги с чанками остались бы на диске
            // навсегда, а переписка на гигабайт исчезла бы, не освободив
            // ни байта. Подобрать их потом умеет только
            // [`Engine::sweep_orphan_files`], и полагаться на неё здесь
            // значило бы оставлять мусор нарочно.
            for file_id in self.store.file_ids_of_chat(&chat).unwrap_or_default() {
                self.forget_file(&file_id);
            }
            self.store.delete_chat(&chat)?;
        }

        let mut effects = vec![Effect::Notify(Event::ContactRemoved { peer_ik })];
        // Список маяков изменился — транспорт больше не должен искать его
        // в эфире (§5.1). Без этого удалённый контакт продолжал бы
        // «находиться» в эфире, а ядро — заводить его заново.
        effects.push(self.watch_peers());
        Ok(effects)
    }

    /// Ставит или снимает свою аватарку и рассылает её сверенным контактам.
    pub(super) fn on_set_avatar(
        &mut self,
        now_ms: u64,
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // Проверка до записи, а не после: отказать пользователю сразу честнее,
        // чем принять картинку, которую потом не сможет принять собеседник.
        ratatosk_proto::avatar::check(bytes)?;

        let own_ik = self.identity.public().ik;
        if bytes.is_empty() {
            self.store.delete_avatar(&own_ik)?;
        } else {
            self.store.put_avatar(
                &own_ik,
                &ratatosk_store::StoredAvatar { bytes: bytes.to_vec(), updated_ms: now_ms },
            )?;
        }

        // Кому отдавать, решает §4.2, и только он. Список собирается заранее:
        // отправка занимает `self` целиком.
        let recipients: Vec<[u8; 32]> = self
            .contacts
            .iter()
            .filter(|(_, contact)| contact.verified)
            .map(|(peer_ik, _)| *peer_ik)
            .collect();

        // **Новость десктопу — своей рукой, а не через `note_for_companion`.**
        // Та функция читает события шага, а установка своей аватарки события
        // не порождает: `Event::AvatarChanged` означает «у контакта сменилось
        // лицо», и в нём лежит `peer_ik` контакта. Завести его и для себя
        // можно было бы, но тогда пять утверждений §4.2 в `tests/pair.rs`,
        // проверяющих, что установка своей аватарки несверенному ничего
        // не порождает, стали бы проверять не то, что написано в их именах.
        //
        // Опасность «забыли позвать» здесь мала ровно потому, что мест
        // одно: своя аватарка меняется только здесь — и с телефона,
        // и (в дальнейшем) с десктопа, который придёт в эту же функцию.
        self.companion_notices.push(PendingNotice::Ready(companion::Notice::AvatarChanged {
            chat: None,
            avatar_ms: if bytes.is_empty() { 0 } else { now_ms },
        }));

        // **Событие о своём лице, и оно приезжает всегда — даже когда
        // отправлять некому.** Пока смена шла только с телефона, экран
        // телефона знал о ней от себя же и события не требовал. Теперь
        // сюда приходит и десктоп (§13.4), и без этого экран телефона
        // показывал бы прежнюю картинку до перезапуска — то самое «экран
        // врёт», которое §14 запрещает.
        //
        // Отдельным видом, а не `AvatarChanged` с собственным `IK`:
        // по тому событию потребитель идёт за контактом, и со своим ключом
        // не нашёл бы там ничего.
        let mut effects = vec![Effect::Notify(Event::OwnAvatarChanged)];
        // Лицо сменилось — значит всё, что рассылалось раньше, показывало
        // прежнее. Отметки сбрасываются целиком, ровно как у карточки.
        self.avatar_pushed.clear();
        for peer_ik in recipients {
            // Живого канала больше не спрашиваем. Спрашивали — и контакт,
            // до которого достаёт только почта или реле, не узнавал о смене
            // лица никогда: ни сейчас, ни потом, потому что второго повода
            // разослать не бывает.
            effects.extend(self.send_avatar(now_ms, peer_ik, bytes)?);
        }
        Ok(effects)
    }

    /// Отправляет свою аватарку контакту, если она есть и если он сверен.
    ///
    /// Зовётся при установлении сессии: собеседник мог переустановить клиент
    /// или впервые нас увидеть, и узнать, что у него уже есть, нам неоткуда —
    /// спрашивать пришлось бы лишним круговым обменом. Сессия устанавливается
    /// редко и переживает перезапуск (§8.3), так что цена ограничена.
    ///
    /// Второй раз одному и тому же в одном запуске не уходит: набор
    /// [`Engine::avatar_pushed`] стережёт это так же, как `card_pushed`
    /// стережёт карточку. У аватарки довод весомее — тридцать два килобайта
    /// против четырёхсот байт, и по реле это восемь событий.
    pub(super) fn offer_avatar(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        if self.avatar_pushed.contains(&peer_ik) {
            return Ok(Vec::new());
        }
        let own_ik = self.identity.public().ik;
        let Some(avatar) = self.store.avatar(&own_ik)? else {
            // Своей аватарки нет — и сообщать об этом нечего: пустая
            // рассылка при каждом рукопожатии была бы трафиком ни о чём.
            return Ok(Vec::new());
        };
        self.send_avatar(now_ms, peer_ik, &avatar.bytes)
    }

    /// Ставит аватарку в очередь §5.4 — единственное место, где проверяется
    /// §4.2.
    ///
    /// Пустые байты законны: это «я снял аватарку», и сверенный контакт
    /// обязан об этом узнать, иначе у него навсегда останется прежнее лицо.
    ///
    /// # Здесь стоял отказ асинхронным ступеням, и он был неверен
    ///
    /// Стояло `if !via.is_direct() { return }` — без единого слова почему,
    /// и это само по себе было признаком: в этом дереве решения объясняются,
    /// а заглушки молчат. Следствие человек видел прямо: собеседник, до
    /// которого достаёт только почта или реле, оставался без лица навсегда.
    ///
    /// Кадр при этом уходил **мимо очереди** — `Effect::Send` с готовым
    /// кадром и живой сессией. Отсюда и запрет: у асинхронной ступени
    /// «живой сессии прямо сейчас» не бывает по устройству.
    ///
    /// Дорога для такого уже проложена, и не нами: обновление карточки
    /// (§4.3) — такая же служебная просьба без своей строки в истории, —
    /// ездит [`Engine::enqueue_request`], то есть по лестнице §5.4
    /// с повторами и переживая перезапуск. Аватарка идёт тем же путём,
    /// и второй дороги для неё заводить незачем.
    ///
    /// Размер это выдерживает по построению: `MAX_AVATAR_BYTES` выбран так,
    /// чтобы конверт укладывался в класс M, а класс M везут все ступени —
    /// у nostr он режется на части, у почты это одно письмо.
    pub(super) fn send_avatar(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        bytes: &[u8],
    ) -> Result<Vec<Effect>, EngineError> {
        // §4.2: несверенному контакту своё лицо не отдаётся. Он может быть
        // не тем, за кого себя выдаёт, — сверка ровно про эту возможность.
        if !self.contacts.get(&peer_ik).is_some_and(|c| c.verified) {
            return Ok(Vec::new());
        }
        let (msg_id, effects) = self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Avatar,
            Value::Bytes(bytes.to_vec()),
        )?;
        // Отметка — **после** постановки и только если доставка выжила.
        // Дословно то же правило и та же причина, что у `card_pushed`
        // (5аж): пометив контакт, до которого доставка не доехала, мы
        // разоружили бы досылку при появлении сессии — набор живёт в памяти.
        if self.delivery_alive(&msg_id, &peer_ik) {
            self.avatar_pushed.insert(peer_ik);
        }
        Ok(effects)
    }

    /// Пришла аватарка контакта.
    ///
    /// Сохраняется **и от несверенного** — но не показывается (см.
    /// [`Engine::avatar_of`]). Разница неочевидная, поэтому вот рассуждение.
    ///
    /// Сверка односторонняя: собеседник мог сверить наш отпечаток при встрече,
    /// а мы его — ещё нет. Тогда он законно шлёт нам лицо, а мы законно его
    /// не показываем. Выбросив байты, мы получили бы чат, где после сверки
    /// аватарка не появляется до следующего рукопожатия — а рукопожатие
    /// переживает перезапуск (§8.3) и может не случиться неделями. Поэтому
    /// байты лежат, а решение о показе принимается каждый раз заново.
    ///
    /// Цена ограничена: одна запись на контакт, не больше
    /// [`MAX_AVATAR_BYTES`](ratatosk_proto::MAX_AVATAR_BYTES), с перезаписью.
    pub(super) fn on_avatar(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — **до всякого разбора**, и это не вежливость.
        //
        // Аватарка теперь едет `enqueue_request`, то есть не молчаливым
        // кадром, а значит у неё заведён срок. Без подтверждения срок
        // объявляет неудачу, §5.4 отправляет сессию на покой и начинает
        // новое рукопожатие — и так при каждой смене лица, пока кадры
        // собеседника не начнут пропадать как «сессия неизвестна». Ровно
        // это правило и ровно эта цепочка записаны у обновления карточки
        // §4.3, и метелка `receipt_wiring` нашла здесь её отсутствие
        // в ту же минуту, как аватарка попала в очередь.
        //
        // До разбора, а не после: отправитель ждёт подтверждения **приёма
        // кадра**, а не согласия с содержимым. Промолчи мы на негодной
        // картинке или на устаревшей копии — он слал бы её ещё и ещё.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Value::Bytes(bytes) = &envelope.payload else {
            return Err(ratatosk_codec::CodecError::TypeMismatch.into());
        };
        // Здесь стоял отказ всему, что не прямой канал, — пара к такому же
        // отказу на отправке. Оба сняты вместе: лицо едет лестницей §5.4,
        // и приехать оно вправе хоть почтой, хоть с реле. Отбрасывать его
        // за это значило бы считать аномалией собственную доставку.
        //
        // Кадр расшифрован, то есть сессия есть; но контакт мог не успеть
        // появиться, если карточка из §8.2 почему-то не разобралась.
        if !self.contacts.contains_key(&peer_ik) {
            return Ok(effects);
        }
        // Негодная аватарка — не повод рвать сессию: сообщение отбрасывается
        // так же тихо, как мусорный кадр в §7.3, и записывается в аномалии.
        if ratatosk_proto::avatar::check(bytes).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }

        // Аватарка уходит заново при каждом установлении сессии, поэтому
        // две отправки легко обгоняют друг друга. Метка отправителя решает,
        // какая из них последняя; своим часам здесь верить нельзя — момент
        // приёма у более старой копии может оказаться более поздним.
        let arrived_ms = envelope.hlc.wall_ms;
        if let Some(stored) = self.store.avatar(&peer_ik)? {
            if stored.updated_ms > arrived_ms {
                return Ok(effects);
            }
        }

        if bytes.is_empty() {
            self.store.delete_avatar(&peer_ik)?;
        } else {
            self.store.put_avatar(
                &peer_ik,
                &ratatosk_store::StoredAvatar { bytes: bytes.clone(), updated_ms: arrived_ms },
            )?;
        }
        if let Some(contact) = self.contacts.get_mut(&peer_ik) {
            contact.has_avatar = !bytes.is_empty();
        }
        effects.push(Effect::Notify(Event::AvatarChanged { peer_ik }));
        Ok(effects)
    }

    /// Аватарка контакта — или `None`, если её нет **или он не сверен**.
    ///
    /// Правило показа живёт здесь, а не в клиенте: §13.3 не разрешает
    /// протокольной логике подниматься выше UniFFI-границы, а «показывать
    /// лицо только сверенному» — ровно она. Клиент, который решил бы иначе,
    /// не смог бы: байтов ему просто не отдадут.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn avatar_of(&self, peer_ik: &[u8; 32]) -> Result<Option<Vec<u8>>, EngineError> {
        let Some(contact) = self.contacts.get(peer_ik) else {
            return Ok(None);
        };
        if !contact.verified {
            return Ok(None);
        }
        Ok(self.store.avatar(peer_ik)?.map(|a| a.bytes))
    }

    /// Аватарка группы — или `None`, если её нет.
    ///
    /// **Сверки здесь нет, и это не забытая проверка.** У лица контакта
    /// показ ограничен §4.2 (см. [`Engine::avatar_of`]): подставленное
    /// чужое лицо покупает самозванцу доверие мимо всех предупреждений.
    /// Картинка группы такого заявления не делает — она отвечает не на
    /// вопрос «кто этот человек», а на вопрос «какой это разговор»,
    /// и рядом с ней стоит название, которое мы показываем несверенным
    /// без оговорок. Полное рассуждение — в `ratatosk_proto::avatar`.
    ///
    /// Участников группы ядро заводит несверенными (§11.5), так что
    /// правило §4.2 здесь означало бы «картинки почти никогда нет» —
    /// поведение, которого человеку не объяснить (§14).
    ///
    /// Пустые байты на диске — «создатель снял картинку»; наружу это
    /// то же `None`, что и «не ставили». Разница нужна только сравнению
    /// меток, а ему видна метка.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn group_avatar_of(&self, chat: &ChatId) -> Result<Option<Vec<u8>>, EngineError> {
        if !self.groups.contains_key(chat) {
            return Ok(None);
        }
        Ok(self.store.group_avatar(chat)?.map(|a| a.bytes).filter(|bytes| !bytes.is_empty()))
    }

    /// Метка аватарки группы — или `0`, если показывать нечего.
    ///
    /// **Метка, а не признак «есть картинка».** Булево на смену не
    /// реагирует, и клиент показывал бы прежнее лицо до перезапуска —
    /// та же причина, по какой метка едет и на проводе компаньона.
    ///
    /// Ноль означает ровно «показывать нечего», и покрывает он два
    /// случая: картинку не ставили и картинку сняли. У снятой метка
    /// на диске есть — она нужна сравнению, — но наружу эти два случая
    /// неразличимы, потому что рисуют по ним одно и то же.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn group_avatar_stamp(&self, chat: &ChatId) -> Result<u64, EngineError> {
        if !self.store.has_group_avatar(chat)? {
            return Ok(0);
        }
        Ok(self.groups.get(chat).map_or(0, |state| state.avatar_hlc.wall_ms))
    }

    /// Своя аватарка.
    ///
    /// # Errors
    ///
    /// Ошибка хранилища.
    pub fn own_avatar(&self) -> Result<Option<Vec<u8>>, EngineError> {
        Ok(self.store.avatar(&self.identity.public().ik)?.map(|a| a.bytes))
    }
}
