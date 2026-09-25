//! Сопряжённое устройство-компаньон (§13.4).
//!
//! Десктоп — не контакт: у него нет карточки, нет ступеней §5.4 и нет
//! своей истории. Это **вторая голова того же человека**, и потому
//! сквозь весь движок он идёт параллельной веткой — здесь она собрана
//! в одном месте.

//! Десктоп — терминал к телефону, а не второй участник разговора. Из этого
//! следует всё остальное здесь: у него нет своих `IK`/`SK`, своей истории
//! и своего места в §5.4; есть одна сессия Noise с телефоном и по ней —
//! просьбы и новости (`ratatosk_proto::companion`).
//!
//! **Только локальная сеть, и сознательно.** Onion отложен не из лени:
//! соединения односторонние (`ARCHITECTURE.md`, 5ц) — каждая сторона пишет
//! только в то, что набрала сама. Чтобы отвечать десктопу через Tor, телефон
//! обязан **набрать** его, то есть у десктопа должен быть свой onion-сервис.
//! Его нет, и заводить его — отдельная работа в транспорте.

use super::*;

impl<S: Store> Engine<S> {
    /// Превращает события шага в новости для десктопа (§13.4).
    ///
    /// Место выбрано именно такое — **по эффектам шага**, а не в функциях,
    /// которые эти события порождают. Функций полдюжины на каждый вид:
    /// список чатов меняют добавление руками, добавление из рукопожатия
    /// (§8.2), обновление карточки (§4.3), подпись именем (§4.1), сверка
    /// и её отзыв (§4.2), удаление; исчезновение сообщений — удаление у себя,
    /// отзыв собеседником и очистка чата. Разложив рассылку по ним, мы завели
    /// бы дюжину мест, где про десктоп надо помнить, и первое же забытое
    /// молча оставило бы у него на экране то, чего на телефоне уже нет.
    /// Через `step` же проходят **все** эффекты, и один разбор здесь заменяет
    /// дюжину аккуратно расставленных вызовов.
    ///
    /// Отказ хранилища здесь ничего не останавливает: новость десктопу —
    /// не то, ради чего стоит ронять шаг телефона.
    pub(super) fn note_for_companion(&mut self, effects: &[Effect]) {
        let mut chats_changed = false;
        let mut gone: Vec<(ChatId, Vec<MsgId>)> = Vec::new();
        let mut edited: Vec<MsgId> = Vec::new();
        let mut reacted: Vec<(ChatId, MsgId)> = Vec::new();
        let mut progress: Vec<([u8; 16], u64, u64)> = Vec::new();
        let mut gone_files: Vec<[u8; 16]> = Vec::new();
        let mut avatars: Vec<[u8; 32]> = Vec::new();
        let mut group_avatars: Vec<ChatId> = Vec::new();

        for effect in effects {
            let Effect::Notify(event) = effect else { continue };
            match event {
                Event::ContactAdded { .. }
                | Event::ContactChanged { .. }
                | Event::ContactRemoved { .. }
                // Группа — такая же строка в списке чатов, как контакт (§11).
                // Заведение добавляет её, смена состава меняет — а вот что
                // именно, десктоп спросит сам: список приезжает целиком.
                | Event::GroupCreated { .. }
                | Event::GroupMembershipChanged { .. }
                // Переименование меняет ровно то, что видно в списке, —
                // заголовок строки.
                | Event::GroupRenamed { .. } => chats_changed = true,
                Event::MessagesDeleted { chat, msg_ids } => gone.push((*chat, msg_ids.clone())),
                Event::MessageEdited { msg_id, .. } => edited.push(*msg_id),
                // Последняя за шаг побеждает: приход чанка и сборка файла
                // приезжают двумя событиями подряд, и рассказывать десктопу
                // «восемь из девяти», а следом «девять из девяти» незачем —
                // он всё равно нарисует второе.
                Event::FileProgress { file_id, received, total } => {
                    progress.retain(|known| known.0 != *file_id);
                    progress.push((*file_id, *received, *total));
                }
                Event::FileGone { file_id } => {
                    // И движение того же вложения за этот шаг отменяется:
                    // рассказывать про полоску того, чего больше нет, —
                    // ровно тот призрак, ради которого событие и заведено.
                    progress.retain(|known| known.0 != *file_id);
                    gone_files.push(*file_id);
                }
                Event::ReactionChanged { chat, msg_id, .. } => {
                    // Автор не запоминается: новость везёт **набор целиком**,
                    // и два события об одном сообщении за один шаг дали бы две
                    // одинаковые новости. Своё и чужое различит `mine`.
                    if !reacted.contains(&(*chat, *msg_id)) {
                        reacted.push((*chat, *msg_id));
                    }
                }
                // Аватарка контакта. Своя сюда не попадает: события о ней нет
                // (`Command::SetAvatar` — единственное место, где она меняется,
                // и новость оттуда уходит своей рукой), и заводить его ради
                // одного места значило бы переписать пять утверждений в тестах
                // §4.2 о том, чего установка своей аватарки **не** порождает.
                Event::AvatarChanged { peer_ik } => {
                    if !avatars.contains(peer_ik) {
                        avatars.push(*peer_ik);
                    }
                }
                // Своей новостью, а не `ChatsChanged`: десктоп по ней
                // перерисует один кружок, а не перечитает весь список.
                // Та же новость, что у лица контакта, и намеренно: снаружи
                // это один вопрос — «что рисовать в кружке этого чата».
                Event::GroupAvatarChanged { chat } if !group_avatars.contains(chat) => {
                    group_avatars.push(*chat);
                }
                _ => {}
            }
        }

        if chats_changed {
            self.companion_notices.push(PendingNotice::Ready(companion::Notice::ChatsChanged));
        }
        for peer_ik in avatars {
            // §4.2 и здесь тот же: несверенному контакту метка не едет,
            // и новость о его аватарке для десктопа — не новость. Байты
            // при этом сохранены (`on_avatar` объясняет почему), и после
            // сверки лицо появится без нового рукопожатия — по `ChatsChanged`,
            // которую породит смена признака.
            if !self.contacts.get(&peer_ik).is_some_and(|contact| contact.verified) {
                continue;
            }
            // Отказ хранилища здесь ничего не роняет — как и всюду в этой
            // функции. Ноль вместо метки означает «показывать нечего»:
            // десктоп сотрёт лицо и спросит заново со следующим списком чатов,
            // что честнее, чем оставить у него картинку с неизвестной меткой.
            let avatar_ms = self.store.avatar_stamp(&peer_ik).unwrap_or(None).unwrap_or(0);
            self.companion_notices.push(PendingNotice::Ready(companion::Notice::AvatarChanged {
                chat: Some(Self::chat_id_for(&peer_ik)),
                avatar_ms,
            }));
        }
        for chat in group_avatars {
            // §4.2 здесь нет — в отличие от лица контакта: картинку группы
            // видят все участники (`proto::avatar`). Ноль означает
            // «показывать нечего», и десктоп по нему сотрёт кружок.
            let avatar_ms = self.group_avatar_stamp(&chat).unwrap_or(0);
            self.companion_notices.push(PendingNotice::Ready(companion::Notice::AvatarChanged {
                chat: Some(chat),
                avatar_ms,
            }));
        }
        for (chat, msg_ids) in gone {
            // Режется здесь, а не у получателя: «очистить чат» уносит всю
            // переписку разом, и список идентификаторов в один кадр (§5.5)
            // может не влезть. Не влезший он не уехал бы вовсе — то есть
            // десктоп продолжал бы показывать стёртое.
            for part in msg_ids.chunks(companion::MAX_GONE_IDS) {
                self.companion_notices.push(PendingNotice::Ready(companion::Notice::Gone {
                    chat,
                    msg_ids: part.to_vec(),
                }));
            }
        }
        for msg_id in edited {
            // Текст читается здесь и едет целиком. Отдав десктопу голый
            // идентификатор, мы заставили бы его сходить за текстом отдельной
            // просьбой — заплатить кругом по сети за то, что у нас в руках.
            let found = self.store.message(&msg_id).map_err(EngineError::from).and_then(|found| {
                found.map(|message| self.companion_message(&message)).transpose()
            });
            match found {
                Ok(Some(message)) => {
                    self.companion_notices
                        .push(PendingNotice::Ready(companion::Notice::Edited(message)));
                }
                // Правку успели стереть — рассказывать нечего: об удалении
                // десктоп узнает своей новостью.
                Ok(None) => {}
                Err(error) => tracing::warn!(?error, "правку десктопу не рассказать"),
            }
        }
        for file_id in gone_files {
            self.companion_notices
                .push(PendingNotice::Ready(companion::Notice::FileGone { file_id }));
        }
        for (file_id, have_chunks, chunk_total) in progress {
            // Полоска обязана двигаться на глазах: без этой новости «идёт
            // приём» и «зависло» на втором экране выглядят одинаково (§14),
            // а узнать разницу можно было бы только перечитыванием истории —
            // то есть опросом вместо новости.
            //
            // Согласие едет вместе с числами, а не отдельной новостью: движение
            // и решение — про одно и то же вложение, и раздельно они однажды
            // разъехались бы. Отсутствие записи читается как «согласия нет»:
            // так выглядит отказ, который её уносит, — и «файла больше нет»
            // честнее показать как «не принято, ноль из нуля», чем промолчать.
            let accepted = match self.store.file(&file_id) {
                Ok(found) => found.is_some_and(|file| file.accepted),
                Err(error) => {
                    tracing::warn!(?error, "решение по вложению десктопу не рассказать");
                    false
                }
            };
            self.companion_notices.push(PendingNotice::Ready(companion::Notice::FileProgress {
                file_id,
                have_chunks,
                chunk_total,
                accepted,
            }));
        }
        for (chat, msg_id) in reacted {
            // Набор читается заново, а не собирается из события: событие
            // говорит «у этого сообщения что-то изменилось», и восстанавливать
            // по нему состояние значило бы вести на телефоне вторую копию
            // таблицы реакций.
            match self.companion_reactions(&msg_id) {
                Ok(reactions) => {
                    let notice = companion::Notice::Reacted { chat, msg_id, reactions };
                    self.companion_notices.push(PendingNotice::Ready(notice));
                }
                Err(error) => tracing::warn!(?error, "реакцию десктопу не рассказать"),
            }
        }
    }

    /// Заводит сопряжение и отдаёт приглашение (§13.4).
    ///
    /// **Секрет в приглашении — зерно, а не готовый ключ.** Спецификация
    /// говорит про «X25519 pairing_key», и буквальное прочтение — «сгенерируй
    /// пару, отдай секретную половину» — здесь отвергнуто. Причина в том,
    /// какой ключ нужен десктопу на самом деле: он выступает инициатором
    /// Noise IK, а инициатору нужен **статический ключ в том виде, в каком
    /// его строит `Identity`**. Отдав зерно, мы отдаём ровно то, из чего
    /// десктоп соберёт `Identity::from_seed` — ту же самую, что построили
    /// здесь мы, — и обе стороны получают один и тот же публичный ключ,
    /// не сговариваясь о формате.
    ///
    /// Телефон секрет **не хранит**. Хранить его незачем: узнать своё
    /// устройство в рукопожатии можно по публичной половине, а лежащее
    /// на диске зерно — это ключ, которым можно представиться нами же.
    /// Отсюда и правило показа: ссылка живёт только в этом событии.
    pub(super) fn on_pair_device(
        &mut self,
        now_ms: u64,
        label: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        companion::check_label(label)?;

        let mut seed = [0u8; 32];
        self.entropy.fill(&mut seed);
        let pairing_public = Identity::from_seed(seed).public().ik;
        let device_id = companion::device_id(&pairing_public);

        let device = StoredPairedDevice {
            device_id,
            label: label.trim().to_owned(),
            pairing_public,
            paired_ms: now_ms,
            // Ноль, а не `now_ms`: устройство ещё ни разу не подключалось.
            // Поставив здесь текущее время, мы дали бы десктопу тридцать
            // суток жизни кэша (§13.4), которого у него пока нет.
            last_seen_ms: 0,
            // Адреса пока нет и быть не может: десктоп ещё не сказал ни слова.
            // Скажет он его в первом же рукопожатии — там, где карточка
            // у контактов (§8.2).
            onion: String::new(),
            // И ключа меша тоже: тем же путём и в тот же миг.
            ygg: Vec::new(),
        };
        self.store.put_paired_device(&device)?;
        self.devices.insert(pairing_public, device);

        let card = self.own_card();
        let invite = companion::PairingInvite {
            ik: card.ik,
            secret: companion::PairingSecret::new(seed),
            onion: card.onion.clone(),
            // Ключ меша — из своей же карточки: там он и лежит (§4.1),
            // и второго места, где его взять, нет. Пусто, если меш выключен,
            // а выключен он по умолчанию: ступень не работает, пока человек
            // не назвал пира (см. `Transport::Ygg`).
            //
            // Приглашение — не единственный путь: включённый **после**
            // сопряжения меш доедет до десктопа объявлением по живому каналу
            // (`companion::Notice::LinkAddress`). Здесь ключ нужен для первой
            // минуты, пока живого канала ещё нет.
            ygg: card.ygg.clone(),
            // Пиры — оттуда же, откуда их берёт свой узел. Без них ключ меша
            // в приглашении бесполезен: десктопу нужен **свой** узел, узлу
            // нужны пиры, а до первого живого канала взять их неоткуда.
            // Лишние отрежет `to_uri` (`MAX_INVITE_PEERS`) — предел про
            // площадь QR, и знать о нём здесь незачем.
            ygg_peers: self.ygg_peers().to_vec(),
            display_name: card.display_name.clone(),
        };
        let uri = invite.to_uri()?;

        let mut effects = vec![Effect::Notify(Event::PairingReady { device_id, uri })];
        // Список маяков изменился: десктоп объявится от ключа сопряжения,
        // и без этого телефон его в эфире не услышит (§5.1).
        effects.push(self.watch_peers());
        Ok(effects)
    }

    /// Отзывает сопряжение (§13.4).
    ///
    /// «Отзыв — удаление записи и **немедленный** разрыв сессии.» Разрыв
    /// здесь выражается тем, чем ядро располагает: сессия убирается из реестра
    /// и с диска сразу, в этом же шаге. Дальше кадры отозванного десктопа
    /// не расшифровываются вовсе — они уходят в «неизвестная сессия» (§7.3), —
    /// а маяк его больше не слушается. Отдельного эффекта «закрыть сокет»
    /// у ядра нет и не заведено нарочно: сокет закрывает та сторона, которая
    /// его набрала, а решает вопрос не он, а отсутствие ключей.
    pub(super) fn on_revoke_pairing(
        &mut self,
        now_ms: u64,
        device_id: &[u8; 16],
    ) -> Result<Vec<Effect>, EngineError> {
        let pairing_public = self
            .devices
            .iter()
            .find(|(_, device)| device.device_id == *device_id)
            .map(|(key, _)| *key)
            .ok_or(EngineError::UnknownDevice)?;

        // **Прощание — до сноса ключей, и другого места у него нет.** После
        // удаления сессии запечатать нечем, а очередь новостей выгребается
        // в конце шага, когда ключей уже не будет. Поэтому кадр собирается
        // здесь, своей рукой, и уезжает вместе с остальными эффектами.
        //
        // Не гарантия, а сообщение: доедет оно только до включённого
        // десктопа, который телефону сейчас достижим. Отзывают же чаще
        // всего потерянный ноутбук — то есть выключенный. Гарантия в §13.4
        // одна, и она другая: тридцать суток без подключения.
        //
        // Отказ сборки кадра ничего не останавливает: отзыв — решение
        // человека о своём телефоне, и не состояться он не может из-за того,
        // что кому-то не удалось об этом сказать.
        let mut effects = Vec::new();
        if let Some(via) = self.device_links.get(&pairing_public).copied() {
            match self.send_to_device(
                now_ms,
                pairing_public,
                via,
                PayloadType::CompanionNotice,
                companion::notice_payload(&companion::Notice::Revoked),
            ) {
                Ok(sent) => effects.extend(sent),
                Err(error) => tracing::warn!(?error, "прощание отозванному не собралось"),
            }
        }

        // **Все** сессии, а не одна на транспорт: отправленная на покой
        // живёт ради приёма — то есть ровно ради того, что отзыв обязан
        // прекратить. То же рассуждение, что в `on_delete_contact`.
        for session_id in self.sessions.all_for_peer(&pairing_public) {
            self.sessions.remove(session_id);
            self.store.delete_session(session_id)?;
        }
        self.devices.remove(&pairing_public);
        self.device_links.remove(&pairing_public);
        self.device_seen.remove(&pairing_public);
        self.store.delete_paired_device(device_id)?;

        // **Надгробие — ради того, кто был выключен.** Прощание выше доедет
        // только до включённого; отзывают же чаще потерянный ноутбук, а он
        // вернётся в сеть когда-нибудь потом. Тогда он постучится, и вот
        // по этой записи ему ответят причиной вместо тишины (5вл).
        //
        // Заодно убираются просроченные: срок тот же, что у кэша десктопа
        // (§13.4), и совпадение не случайно — к его концу десктоп стирает
        // кэш сам, и говорить ему уже нечего. Уборка здесь, на редкой
        // записи, а не на каждом чужом рукопожатии: там она была бы записью
        // в базу по чужому кадру.
        self.store.remember_revocation(&pairing_public, now_ms)?;
        let _ = self.store.prune_revocations(now_ms.saturating_sub(DESKTOP_CACHE_TTL_MS));

        effects.push(Effect::Notify(Event::PairingRevoked { device_id: *device_id }));
        effects.push(self.watch_peers());
        Ok(effects)
    }

    /// Отвечает отозванному десктопу, что он отозван (§13.4).
    ///
    /// Пусто, если это не наш отозванный: незнакомцу, чьё рукопожатие
    /// не разобралось, отвечать нечего, а отвечать всем подряд значило бы
    /// сообщать любому, кто постучится, что мы здесь и мы что-то про него
    /// знаем.
    ///
    /// **Срок проверяется на чтении, а не только уборкой.** Уборка идёт
    /// на отзыве — то есть может не случиться годами, если отзывали один
    /// раз, — и без этой проверки надгробие пережило бы обещанные тридцать
    /// суток. Просроченному отвечают тишиной: к этому времени десктоп
    /// стёр кэш сам, и сказать ему нечего.
    ///
    /// Отказ хранилища или сборки кадра ничего не роняет: чужое рукопожатие
    /// не повод останавливать телефон, а человек об этом всё равно
    /// не узнает — новость едет не ему.
    pub(super) fn tell_revoked(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Vec<Effect> {
        let Ok(Some(revoked_ms)) = self.store.revocation(&peer_ik) else { return Vec::new() };
        if now_ms.saturating_sub(revoked_ms) >= DESKTOP_CACHE_TTL_MS {
            return Vec::new();
        }
        let key = ratatosk_crypto::companion::revocation_key(&self.identity, &peer_ik);
        let mut nonce = [0u8; ratatosk_wire::NONCE_LEN];
        self.entropy.fill(&mut nonce);
        match crate::frames::revoked(&key, nonce) {
            Ok(frame) => vec![Effect::Send { peer_ik, via, frame, handoff: None }],
            Err(error) => {
                tracing::warn!(?error, "кадр отзыва не собрался");
                Vec::new()
            }
        }
    }

    /// Отмечает, что обратный путь до десктопа доказан.
    ///
    /// Зовётся с каждой просьбы, а не только с первой: сессия переживает
    /// перезапуск телефона (§8.3), а признак в памяти — нет, и без этого
    /// живой десктоп после перезапуска числился бы отключённым навсегда.
    ///
    /// Отсюда и ранний выход: **на диск пишется только переход**. Отметка
    /// «последний раз подключалось» — про появление связи, а не про каждый
    /// кадр по ней; писать её на каждую просьбу значило бы гонять запись
    /// в базу телефона со скоростью, с какой человек печатает на десктопе.
    ///
    /// Транспорт обновляется всегда: десктоп мог вернуться другой ступенью,
    /// и слать новости надо туда, откуда он говорит сейчас.
    pub(super) fn note_device_link(
        &mut self,
        now_ms: u64,
        pairing_public: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        self.device_links.insert(pairing_public, via);
        if !self.device_seen.insert(pairing_public) {
            return Ok(Vec::new());
        }
        let Some(device) = self.devices.get_mut(&pairing_public) else { return Ok(Vec::new()) };
        device.last_seen_ms = now_ms;
        let device_id = device.device_id;
        // По этому же числу десктоп отмеряет тридцать суток жизни кэша
        // (§13.4), и разъехаться двум сторонам в нём нельзя.
        self.store.touch_paired_device(&device_id, now_ms)?;

        // **И сразу говорим, чем нас набрать.**
        //
        // Адреса в этом канале ехали несимметрично: десктоп объявляет свой
        // в каждом рукопожатии, а наш зашит в QR один раз при сопряжении.
        // Пока путей было два (общая сеть и onion), это сходило: Tor либо
        // поднят к моменту показа QR, либо нет. С мешем не сходится — его
        // включают когда угодно, в том числе неделей позже, — и требовать
        // за это пересопряжения значит требовать объяснимого только
        // реализацией.
        //
        // На подключении, а не на смене адреса: сменить его мог и лежащий
        // десктоп, и тогда «сказали один раз» означало бы «не сказали».
        // Здесь же мы говорим ровно тому, кто **только что** объявился,
        // и говорим то, что верно сейчас.
        let mut effects = vec![Effect::Notify(Event::DeviceLink { device_id, connected: true })];
        let told = self.tell_link_address(now_ms, pairing_public, via);
        match told {
            Ok(sent) => effects.extend(sent),
            Err(error) => tracing::warn!(?error, "свой адрес десктопу не ушёл"),
        }
        Ok(effects)
    }

    /// Говорит устройству, чем нас набрать (§13.4 + 0.2).
    ///
    /// Берётся из **своей карточки** (§4.1), а не из настроек: карточка и
    /// есть то, что мы о себе рассказываем, и второго места, где эти два
    /// адреса лежат вместе, нет.
    ///
    /// Пустые значения законны и означают «этого пути нет»: Tor не поднят,
    /// меш выключен. Промолчать вместо этого нельзя — молчание десктоп
    /// прочтёт как «ничего не изменилось», а это разные вещи.
    pub(super) fn tell_link_address(
        &mut self,
        now_ms: u64,
        pairing_public: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        let card = self.own_card();
        let address = companion::DeviceAddress { onion: card.onion.clone(), ygg: card.ygg.clone() };
        // **И пиров тоже.** Терминалу нужен свой узел меша: чужого демона
        // на машине человека может не быть, а ставить его ради второго
        // экрана — та сложность настройки, из-за которой ступень и не
        // включают. Узлу нужны зерно и пир; зерно терминал выводит сам,
        // а пиров назвал человек — здесь, на телефоне, один раз.
        //
        // Список отдаётся целиком и как есть: он и так виден человеку
        // в настройках, а урезать его до «первого годного» значило бы
        // решать за него, через кого ходить.
        let peers = self.ygg_peers().to_vec();
        self.send_to_device(
            now_ms,
            pairing_public,
            via,
            PayloadType::CompanionNotice,
            companion::notice_payload(&companion::Notice::LinkAddress {
                address,
                ygg_peers: peers,
            }),
        )
    }

    /// Десктоп отключился.
    pub(super) fn drop_device_link(
        &mut self,
        pairing_public: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        self.device_links.remove(&pairing_public);
        // Сказать «отключился» можно только тому, кому говорили «на связи».
        // Иначе человек увидел бы, что отключилось то, что не подключалось.
        if !self.device_seen.remove(&pairing_public) {
            return Ok(Vec::new());
        }
        let Some(device) = self.devices.get(&pairing_public) else { return Ok(Vec::new()) };
        Ok(vec![Effect::Notify(Event::DeviceLink {
            device_id: device.device_id,
            connected: false,
        })])
    }

    /// Пришёл кадр от сопряжённого устройства.
    pub(super) fn on_device_frame(
        &mut self,
        now_ms: u64,
        via: Transport,
        pairing_public: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Кусок (§9.3) — не «не тот разговор», а часть его. Разговор
        // терминала возит превью и куски выгружаемого файла, и по эфиру
        // они в кадр не влезают. Собрав все, приходим сюда же с целым
        // конвертом — и дальше он неотличим от приехавшего целым.
        if envelope.payload_type == PayloadType::Fragment {
            let Some(whole) = self.reassemble(now_ms, via, pairing_public, envelope)? else {
                return Ok(Vec::new());
            };
            return self.on_device_frame(now_ms, via, pairing_public, &whole);
        }

        // Устройство говорит только просьбами. Ответ и новость идут в другую
        // сторону, всё остальное — не его разговор: терминал, приславший
        // текстовое сообщение «как контакт», либо сломан, либо не тот,
        // за кого себя выдаёт.
        if envelope.payload_type != PayloadType::CompanionRequest {
            self.sessions.note_anomaly(pairing_public, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        let Ok((id, request)) = companion::request_from_payload(&envelope.payload) else {
            self.sessions.note_anomaly(pairing_public, |c| c.malformed += 1);
            return Ok(Vec::new());
        };

        // Просьба пришла — значит наш ответ дошёл и обратный путь есть.
        // Это единственное доказательство, какое у нас бывает, и потому
        // «на связи» ставится здесь.
        //
        // На каждой просьбе, а не только на первой: сессия переживает
        // перезапуск телефона (§8.3), а признаки в памяти — нет, и без этой
        // строки живой десктоп после перезапуска числился бы отключённым,
        // а новости ему не уходили бы вовсе.
        let mut effects = self.note_device_link(now_ms, pairing_public, via)?;

        let response = self.serve_companion(now_ms, via, request, &mut effects);
        let sealed = self.send_to_device(
            now_ms,
            pairing_public,
            via,
            PayloadType::CompanionResponse,
            companion::response_payload(id, &response),
        );
        match sealed {
            Ok(sent) => effects.extend(sent),
            Err(error) => {
                // Ответ не влез в кадр — история чата длинных сообщений или
                // список из сотен контактов. Молчание десктоп прочтёт как
                // «телефон завис»; слова влезут всегда (§14).
                tracing::warn!(?error, "ответ компаньону не собрался");
                let refusal = companion::Response::Refused(
                    "ответ не влезает в кадр — попросите меньше".to_owned(),
                );
                let told = self.send_to_device(
                    now_ms,
                    pairing_public,
                    via,
                    PayloadType::CompanionResponse,
                    companion::response_payload(id, &refusal),
                );
                match told {
                    Ok(sent) => effects.extend(sent),
                    Err(error) => tracing::warn!(?error, "и отказ не собрался"),
                }
            }
        }
        Ok(effects)
    }

    /// Выполняет просьбу десктопа и отвечает словами, что получилось.
    ///
    /// Отказ здесь — **ответ, а не ошибка шага**, и различие содержательное.
    /// Просьба пришла с другого устройства; уронив из-за неё шаг ядра, мы дали
    /// бы десктопу способ ронять телефон — пустой текст, чат которого удалили
    /// секунду назад, и приложение падает у человека в кармане. Поэтому всё,
    /// что не сложилось, возвращается словами: их покажет десктоп (§14),
    /// а телефон продолжает работать.
    pub(super) fn serve_companion(
        &mut self,
        now_ms: u64,
        via: Transport,
        request: companion::Request,
        effects: &mut Vec<Effect>,
    ) -> companion::Response {
        match self.try_serve_companion(now_ms, via, request, effects) {
            Ok(response) => response,
            Err(error) => {
                // Вслух: отказ на просьбе десктопа — единственный след того,
                // что на телефоне что-то не так, а увидит его человек
                // на другом экране и без подробностей.
                tracing::warn!(?error, "просьба компаньона не выполнена");
                companion::Response::Refused(error.to_string())
            }
        }
    }

    /// Чей это личный чат — по идентификатору, приехавшему с десктопа.
    ///
    /// **Единственное место, где десктоп называет человека.** §13.4 не
    /// пускает `IK` через границу устройства, и участник на том проводе
    /// назван идентификатором своего личного чата (`companion::Member`).
    /// Разворачивает его обратно телефон — тем же соответствием, которым
    /// он и так находит чат по контакту.
    ///
    /// # Errors
    ///
    /// [`EngineError::UnknownPeer`] — такого чата у нас нет. Отказ приедет
    /// словами (§14): «его нет в контактах» человек за ноутбуком поймёт,
    /// а тишину — нет.
    pub(super) fn peer_of_chat(&self, chat: ChatId) -> Result<[u8; 32], EngineError> {
        // Групп здесь не бывает: сюда приезжает идентификатор **личного**
        // чата участника — так §13.4 называет человека в составе группы, —
        // а не чат самой группы. Сказано вслух, потому что имя довода
        // (`chat`) об этом не говорит, а перепутанное значение дало бы
        // отказ там, где всё в порядке.
        self.by_chat.get(&chat).copied().ok_or(EngineError::UnknownPeer)
    }

    pub(super) fn try_serve_companion(
        &mut self,
        now_ms: u64,
        via: Transport,
        request: companion::Request,
        effects: &mut Vec<Effect>,
    ) -> Result<companion::Response, EngineError> {
        match request {
            companion::Request::Chats => Ok(companion::Response::Chats(self.chat_summaries()?)),
            companion::Request::History { chat, limit, before } => {
                match self.history_page(chat, limit, before)? {
                    Some(page) => Ok(companion::Response::History(page)),
                    // Словами, а не пустой страницей: человеку надо сказать,
                    // что делать, а сделать он может ровно одно — открыть чат
                    // заново. Отказ он увидит (§14); край истории — не увидит.
                    None => Ok(companion::Response::Refused(
                        "с этого места листать больше нечего — сообщения нет, откройте чат заново"
                            .to_owned(),
                    )),
                }
            }
            companion::Request::SendText { chat, text } => {
                effects.extend(self.send_text(now_ms, chat, &text)?);
                Ok(companion::Response::Done)
            }
            companion::Request::MarkRead { chat, up_to } => {
                effects.extend(self.on_mark_read(now_ms, chat, up_to)?);
                Ok(companion::Response::Done)
            }
            // Дальше — то, чем десктоп распоряжается чужой уже написанной
            // перепиской. Каждая ветка зовёт **тот же самый обработчик**,
            // что и команда с телефона, и это здесь главное: решение о том,
            // что можно править только своё и только неделю, что «удалить»
            // и «отозвать» — разные вещи, а очистка чата отзыва не имеет,
            // принимается в одном месте. Скопируй мы сюда хоть одно из этих
            // правил — и второй экран однажды разрешил бы то, чего не
            // разрешает первый.
            //
            // Отказы приезжают словами (`serve_companion` ловит `EngineError`
            // и превращает в `Refused`), и это не заглушка: «правка старше
            // недели» и «телефон сломался» человек за ноутбуком обязан
            // различать (§14).
            companion::Request::SetReaction { chat, msg_id, emoji } => {
                effects.extend(self.on_set_reaction(now_ms, chat, msg_id, &emoji)?);
                Ok(companion::Response::Done)
            }
            companion::Request::SendReply { chat, reply_to, text } => {
                effects.extend(self.on_send_reply(now_ms, chat, reply_to, &text)?);
                Ok(companion::Response::Done)
            }
            companion::Request::EditMessage { chat, msg_id, text } => {
                effects.extend(self.on_edit_message(now_ms, chat, msg_id, &text)?);
                Ok(companion::Response::Done)
            }
            companion::Request::DeleteMessages { chat, msg_ids } => {
                effects.extend(self.forget_messages(now_ms, chat, &msg_ids));
                Ok(companion::Response::Done)
            }
            companion::Request::RetractMessages { chat, msg_ids } => {
                effects.extend(self.on_retract_messages(now_ms, chat, &msg_ids)?);
                Ok(companion::Response::Done)
            }
            companion::Request::ForwardMessages { chat, msg_ids } => {
                effects.extend(self.on_forward_messages(now_ms, chat, &msg_ids)?);
                Ok(companion::Response::Done)
            }
            // Человек назван личным чатом, а разворачивает его телефон:
            // §13.4 не пускает `IK` через границу, и «поделиться контактом»
            // — то самое место, где соблазн его пустить наибольший.
            // Дальше — **тот же** обработчик, что у команды с телефона,
            // а значит и та же ветка на группу, и те же правила.
            companion::Request::ShareContact { chat, who } => {
                let peer_ik = match who {
                    Some(who) => self.peer_of_chat(who)?,
                    // Своя карточка: личного чата с самим собой не бывает,
                    // и отсутствие поля означает ровно это.
                    None => self.identity.public().ik,
                };
                effects.extend(self.on_share_contact(now_ms, chat, peer_ik)?);
                Ok(companion::Response::Done)
            }
            // Байты карточки лежат на телефоне и через границу не ездят
            // ни туда, ни обратно: приехавшая с десктопа «карточка» была бы
            // ключом, назначенным десктопом. Десктоп называет запись
            // в истории, телефон берёт байты у себя.
            companion::Request::AddSharedContact { msg_id } => {
                let Some(share) = self.store.contact_share_of(&msg_id)? else {
                    return Ok(companion::Response::Refused(
                        "карточки в этом сообщении нет — её могли удалить".to_owned(),
                    ));
                };
                // Сверки здесь нет и быть не может: §4.2 — это встреча
                // голосом, а не нажатие в окне. Присланный контакт
                // непроверен всегда, ровно как и добавленный по ссылке.
                effects.extend(self.add_contact(now_ms, &share.card_bytes, false)?);
                effects.extend(self.push_own_card(now_ms, share.ik)?);
                Ok(companion::Response::Done)
            }
            companion::Request::ClearChat { chat } => {
                effects.extend(self.on_clear_chat(now_ms, chat)?);
                Ok(companion::Response::Done)
            }
            // **Расшифровка происходит здесь, в цикле ядра, и это известная
            // цена.** `reader.rs` заведён ровно затем, чтобы чтение вложения
            // в цикле не стояло: открытие файла на полгигабайта — пятьсот
            // заходов по мебибайту, и всё это время не уходят сообщения
            // и не срабатывают таймеры. Здесь тот же счёт, и вынести его
            // некуда: ответ обязан быть запечатан сессией устройства, а она
            // живёт в ядре и на каждом кадре двигает цепочку (§7.3). Отдав
            // её другому потоку, мы получили бы две стороны, одновременно
            // расходующие позиции, — то есть разрушенное шифрование кадра
            // вместо задержки.
            //
            // Смягчение простое и честное: кусок за просьбу, а не файл
            // за просьбу. Между кусками ядро успевает всё остальное,
            // и «телефон замер на время выгрузки» превращается в «телефон
            // отвечает медленнее, пока идёт выгрузка».
            companion::Request::FileChunk { file_id, index, count } => {
                let Some(reader) = self.open_file(&file_id)? else {
                    return Ok(companion::Response::Refused(
                        "этого вложения у телефона нет".to_owned(),
                    ));
                };
                // **Пачкой, а не по куску.** Кадр ответа рассчитан на целый
                // мебибайт, и везти в нём четыре килобайта значило бы
                // платить кругом по сети за каждую трёхсотую долю того,
                // что и так влезает. Работы на просьбу при этом ровно
                // столько же, сколько её было до нарезки эфира: мебибайт
                // прочитать и расшифровать.
                //
                // Отдаём **сколько получится**: за концом файла и на первой
                // же дырке в приёме пачка кончается. Сколько отдали, видно
                // по длине — десктоп продолжит с этого места.
                let mut bytes = Vec::new();
                let want = count.min(companion::chunks_per_ask(u64::from(reader.chunk_bytes())));
                for step in 0..want {
                    let Some(piece) = reader.chunk(index.saturating_add(step))? else { break };
                    bytes.extend_from_slice(&piece);
                    if bytes.len() as u64 >= companion::ASK_BYTES {
                        break;
                    }
                }
                match (!bytes.is_empty()).then_some(bytes) {
                    Some(bytes) => Ok(companion::Response::FileChunk { index, bytes }),
                    // Три случая на один ответ, и различать их телефон
                    // не может сам (`FileReader::chunk`): кусок ещё не
                    // приехал, номер за концом файла, тег не сошёлся.
                    // Показывать нечего во всех трёх, а гадать о причине —
                    // не работа показа.
                    None => Ok(companion::Response::Refused(
                        "этого куска у телефона пока нет".to_owned(),
                    )),
                }
            }
            // Принять — это про **телефон**: начать качать у собеседника.
            // Забрать принятое себе десктоп просит отдельно, и порядок
            // обязателен: пока телефон не принял, забирать нечего.
            companion::Request::AcceptFile { file_id } => {
                effects.extend(self.on_accept_file(now_ms, file_id)?);
                Ok(companion::Response::Done)
            }
            companion::Request::DeclineFile { file_id } => {
                effects.extend(self.on_decline_file(file_id)?);
                Ok(companion::Response::Done)
            }
            // Единственная просьба, ответ на которую ничего не читает
            // и ничего не меняет: телефон называет свой провод. Сборка
            // постарше этого вида не знает и не ответит вовсе — по этому
            // молчанию десктоп её и узнаёт.
            companion::Request::PauseFile { file_id } => {
                effects.extend(self.on_pause_file(file_id)?);
                Ok(companion::Response::Done)
            }
            companion::Request::FileOffer { chat, name, size_bytes, preview } => {
                self.on_upload_offer(now_ms, via, chat, &name, size_bytes, preview)
            }
            companion::Request::FilePut { file_id, index, bytes } => {
                self.on_upload_put(file_id, index, &bytes)
            }
            companion::Request::FileSend { file_ids, text } => {
                let (response, produced) = self.on_upload_send(now_ms, &file_ids, &text)?;
                effects.extend(produced);
                Ok(response)
            }
            companion::Request::FileAbort { file_id } => self.on_upload_abort(file_id),
            // Превью (§10.3) — отдельной просьбой, а не в странице: тридцать
            // два килобайта на сотню сообщений не влезут в кадр. Читается оно
            // из записи файла, а не из содержимого: превью кладут рядом
            // с предложением, и оно есть до того, как приехал первый кусок.
            //
            // Пропавшее вложение — **не** отказ: `None` здесь честный ответ
            // «показать нечего», а `Refused` десктоп обязан донести до
            // человека словами (§14), и строка «превью нет» на каждой
            // картинке без превью — шум, а не сообщение.
            companion::Request::FilePreview { file_id } => Ok(companion::Response::FilePreview {
                bytes: self.store.file(&file_id)?.and_then(|file| file.preview),
            }),
            // Что осталось от прерванной выгрузки (§13.4). Спрашивается
            // при каждом подключении: отличить «связь пропала» от «телефон
            // перезапустился» десктоп не может, а ответ почти всегда пуст.
            companion::Request::Staged => Ok(companion::Response::Staged {
                files: self
                    .uploads
                    .iter()
                    .map(|upload| companion::StagedFile {
                        file_id: upload.file_id,
                        name: upload.name.clone(),
                        size_bytes: upload.size_bytes,
                        chunk_total: upload.chunk_total,
                        // Дырки, а не число: продолжать надо с пропущенного,
                        // и куски вправе были приехать не по порядку.
                        missing: (0..upload.chunk_total)
                            .filter(|index| !upload.have.contains(index))
                            .collect(),
                    })
                    .collect(),
            }),
            companion::Request::Hello => {
                Ok(companion::Response::Hello { wire: companion::WIRE_VERSION })
            }
            // Аватарка — своя или контакта. Правило §4.2 не повторяется здесь
            // ни строкой: `avatar_of` уже отвечает `None` на несверенного,
            // и второе такое же условие рядом однажды разошлось бы с первым.
            //
            // Неизвестный чат — тоже пустой ответ, а не отказ. Десктоп мог
            // спросить про чат, который телефон только что удалил: сказать
            // «нет такого чата» словами (§14) значило бы показать человеку
            // сообщение об ошибке там, где ошибки нет.
            // Тот же обработчик, что и у команды с телефона, — правило то же,
            // что у правок и удалений: §4.2 решает, кому лицо уедет, и решает
            // это в одном месте. Негодная картинка вернётся словами
            // (`serve_companion` ловит `EngineError::Avatar`), и слова там
            // человеческие: «формат не поддерживается» и «больше стольких-то
            // байт» — ровно то, что человеку за ноутбуком надо знать.
            companion::Request::SetMyAvatar { bytes } => {
                effects.extend(self.on_set_avatar(now_ms, &bytes)?);
                Ok(companion::Response::Done)
            }
            companion::Request::Avatar { chat } => {
                // Группа спрашивается тем же видом просьбы, что и человек,
                // и это не экономия на видах: снаружи это один вопрос —
                // «что рисовать в кружке этого чата». Развилка здесь,
                // потому что правила показа у них разные: у лица контакта
                // §4.2, у картинки группы никакого (`proto::avatar`).
                if let Some(chat) = chat.filter(|chat| self.groups.contains_key(chat)) {
                    let bytes = self.group_avatar_of(&chat)?;
                    return Ok(companion::Response::Avatar {
                        avatar_ms: if bytes.is_some() {
                            self.group_avatar_stamp(&chat)?
                        } else {
                            0
                        },
                        bytes,
                    });
                }
                let owner = match chat {
                    Some(chat) => self.by_chat.get(&chat).copied(),
                    None => Some(self.identity.public().ik),
                };
                let bytes = match (chat, owner) {
                    (Some(_), Some(peer_ik)) => self.avatar_of(&peer_ik)?,
                    (None, _) => self.own_avatar()?,
                    (Some(_), None) => None,
                };
                // Метка снимается **с той же строки**, из которой взяты байты,
                // и только когда байты есть. Иначе несверенный контакт уехал
                // бы с пустотой и живой меткой — то есть десктоп счёл бы,
                // что лицо у него теперь есть, и перестал спрашивать.
                let avatar_ms = match (&bytes, owner) {
                    (Some(_), Some(owner)) => self.store.avatar_stamp(&owner)?.unwrap_or(0),
                    _ => 0,
                };
                Ok(companion::Response::Avatar { bytes, avatar_ms })
            }
            // Дальше — распоряжение группой со второго экрана (§11).
            // Каждая ветка зовёт **тот же самый обработчик**, что и команда
            // с телефона, и это здесь то же главное, что у правок:
            // «исключать вправе только создатель», «выйти вправе всякий»,
            // «название непустое и не длиннее предела» — решения §11.2
            // принимаются в одном месте. Скопируй мы сюда хоть одно —
            // и второй экран однажды разрешил бы то, чего не разрешает
            // первый, причём молча.
            //
            // Два обязательных предупреждения (§11.5 при заведении, §11.4
            // при исключении) здесь **не проверяются и приехать не могут**:
            // это тексты, а не сведения, и живут они в биндингах того окна,
            // где нажимают кнопку. Телефон не знает, показали ли их, и
            // сделать вид, что знает, было бы хуже, чем не знать.
            companion::Request::CreateGroup { title } => {
                let effects_here = self.on_create_group(now_ms, &title)?;
                // Идентификатор берётся из уже собранного события, а не
                // считается заново: у группы он случаен, и второй источник
                // означал бы второе случайное число.
                let chat = effects_here.iter().find_map(|effect| match effect {
                    Effect::Notify(Event::GroupCreated { chat, .. }) => Some(*chat),
                    _ => None,
                });
                effects.extend(effects_here);
                match chat {
                    Some(chat) => Ok(companion::Response::GroupCreated { chat }),
                    // Недостижимо: `on_create_group` либо отказывает, либо
                    // порождает это событие. Отвечать `Done` было бы хуже
                    // отказа — десктоп решил бы, что группа заведена, и не
                    // нашёл бы её.
                    None => Ok(companion::Response::Refused(
                        "группа заведена, но её идентификатор не вернулся — сообщите об этом"
                            .to_owned(),
                    )),
                }
            }
            companion::Request::InviteToGroup { chat, member } => {
                let peer_ik = self.peer_of_chat(member)?;
                effects.extend(self.on_invite_to_group(now_ms, chat, peer_ik)?);
                Ok(companion::Response::Done)
            }
            companion::Request::EvictFromGroup { chat, member } => {
                let peer_ik = self.peer_of_chat(member)?;
                effects.extend(self.on_evict_from_group(now_ms, chat, peer_ik)?);
                Ok(companion::Response::Done)
            }
            companion::Request::RenameGroup { chat, title } => {
                effects.extend(self.on_rename_group(now_ms, chat, &title)?);
                Ok(companion::Response::Done)
            }
            companion::Request::SetGroupAvatar { chat, bytes } => {
                effects.extend(self.on_set_group_avatar(now_ms, chat, &bytes)?);
                Ok(companion::Response::Done)
            }
            companion::Request::LeaveGroup { chat } => {
                effects.extend(self.on_leave_group(now_ms, chat)?);
                Ok(companion::Response::Done)
            }
            companion::Request::Members { chat } => {
                // Имя и признак «это я» считает телефон — той же функцией,
                // что и для своего UI. Десктоп искал бы имя перебором
                // и не нашёл бы **себя**: своей карточки в контактах нет.
                //
                // Участник назван идентификатором своего личного чата:
                // §13.4 не пускает `IK` через эту границу, а такой
                // идентификатор десктоп и так видит у каждой строки списка
                // чатов. Заодно им же он умеет написать участнику лично —
                // без единой новой просьбы.
                let owner = self.groups.get(&chat).map(|state| state.group.owner);
                let members = self
                    .group_members(&chat)
                    .into_iter()
                    .map(|member| companion::Member {
                        chat: Self::chat_id_for(&member.ik),
                        name: member.name,
                        mine: member.mine,
                        // Права десктопа читаются отсюда и больше ниоткуда:
                        // §11.2 разрешает исключать, переименовывать
                        // и менять картинку только создателю, и без этого
                        // признака окно рисовало бы кнопки, на которые
                        // телефон отвечает отказом.
                        owner: owner == Some(member.ik),
                    })
                    .collect();
                Ok(companion::Response::Members { members })
            }
        }
    }

    /// Переводит запись истории в то, что видит десктоп.
    ///
    /// «Своё ли» считает телефон: сравнение с собственным `IK` — протокольное
    /// знание, а `IK` границу устройства не пересекает (§13.4).
    /// # Errors
    ///
    /// Отказ хранилища при чтении реакций.
    pub(super) fn companion_message(
        &self,
        message: &StoredMessage,
    ) -> Result<companion::Message, EngineError> {
        Ok(companion::Message {
            msg_id: message.msg_id,
            chat: message.chat_id,
            mine: message.sender_ik == self.identity.public().ik,
            // Подпись автора — той же функцией, что и для своего UI, а не
            // вторым правилом рядом. `None` означает «выводится из `mine`»
            // (переписка двоих), `Some` приходит у групповых сообщений.
            // Имя, а не ключ: §13.4 не пускает `IK` через эту границу,
            // а имя считать десктоп всё равно не смог бы — своей карточки
            // в контактах нет, и хозяин телефона вышел бы «неизвестным».
            author: self.message_author(&message.chat_id, &message.sender_ik),
            // Потерянные байты — не повод потерять сообщение: тело пришло
            // из сети и могло быть каким угодно, а десктоп ждёт текст.
            text: String::from_utf8_lossy(&message.body).into_owned(),
            wall_ms: message.hlc.wall_ms,
            status: message.status,
            // Читаются здесь, а не у вызывающих, и функция ради этого стала
            // возвращать `Result`. Дверь одна по той же причине, что и у
            // [`Engine::remember`]: сообщение уезжает к десктопу из трёх мест
            // — из истории, из новости о приходе, из новости о правке, —
            // и забытые в одном из них реакции выглядели бы как снятые.
            reactions: self.companion_reactions(&message.msg_id)?,
            // Три отметки, которые телефон показывает у себя с самого начала
            // (`FfiMessage`), а десктопу не отдавал. «Изменено» из них —
            // не украшение: прежнего текста нет ни у кого, и без отметки
            // подменённые слова выглядят так, будто их такими и написали.
            // §14 это запрещает, и запрещает на **обоих** экранах.
            edited_ms: message.edited_ms,
            forwarded: message.forwarded,
            reply_to: message.reply_to,
            files: self.companion_files(&message.msg_id)?,
            shared: self.companion_shared(&message.msg_id)?,
        })
    }

    /// Присланная карточка в том виде, в каком её видит десктоп (§4.1, §13.4).
    ///
    /// **Ключ остаётся здесь.** Наружу едут имя и — если человек уже
    /// в контактах — идентификатор личного чата с ним. Этого довольно
    /// и чтобы нарисовать карточку, и чтобы решить, предлагать ли
    /// «добавить»: у знакомого чат есть, у незнакомого нет.
    ///
    /// Имя берётся **из самой карточки**, а не локальное: карточка
    /// рассказывает, как человек назвал себя сам, и подменять это своей
    /// заметкой (§4.1 — она по проводу не едет никогда) значило бы
    /// показать не то, чем поделились.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или разбор карточки.
    pub(super) fn companion_shared(
        &self,
        msg_id: &MsgId,
    ) -> Result<Option<companion::SharedContact>, EngineError> {
        let Some(share) = self.store.contact_share_of(msg_id)? else { return Ok(None) };
        let card = ContactCard::decode(&share.card_bytes)?.into_parts().1;
        Ok(Some(companion::SharedContact {
            name: card.display_name,
            // Свою же карточку присылать могут (§4.1: «поделиться собой» —
            // та же операция), и «чат с самим собой» тут был бы ложью:
            // его не бывает. Хозяин телефона — не контакт, и `None` здесь
            // означает ровно то же, что у незнакомца: предложить нечего.
            chat: self.contacts.contains_key(&share.ik).then(|| Self::chat_id_for(&share.ik)),
        }))
    }

    /// Вложения сообщения в том виде, в каком их видит десктоп (§10, §13.4).
    ///
    /// **Ключ файла остаётся здесь.** §13.4 не пускает его через границу
    /// устройства, и потому наружу едет `file_id` — им десктоп адресует
    /// просьбу, — а расшифровывает телефон, отдавая уже открытые байты
    /// куском за просьбу.
    ///
    /// «Сколько уже приехало» считается так же, как для своего UI
    /// (`Driver`): у исходящего и у собранного — все куски, у остальных
    /// спрашивается хранилище. Повтор этого счёта в двух местах — плата
    /// за то, что `MessageView` собирает драйвер, а не ядро; свести их
    /// стоило бы протаскивания драйверного типа ниже границы.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn companion_files(
        &self,
        msg_id: &MsgId,
    ) -> Result<Vec<companion::Attachment>, EngineError> {
        let mut out = Vec::new();
        for file in self.store.files_of(msg_id)?.into_iter().take(companion::MAX_ATTACHMENTS) {
            let have_chunks = if !file.incoming || file.complete {
                file.chunk_total
            } else {
                self.store.received_chunks(&file.file_id)?
            };
            out.push(companion::Attachment {
                file_id: file.file_id,
                name: file.name,
                size_bytes: file.size_bytes,
                chunk_total: file.chunk_total,
                // Нарезка **этого** файла (миграция 0026), а не умолчание:
                // по ней десктоп считает смещение, когда складывает куски.
                chunk_bytes: u64::from(file.chunk_bytes),
                have_chunks,
                accepted: file.accepted,
                // Признак, а не байты: сама картинка приедет отдельной
                // просьбой и только про то, что десктоп показывает сейчас.
                has_preview: file.preview.is_some(),
            });
        }
        Ok(out)
    }

    /// Реакции на сообщение в том виде, в каком их видит десктоп.
    ///
    /// Ни отсева снятых, ни сортировки здесь нет намеренно: и то и другое —
    /// обещание [`ratatosk_store::Store::reactions`], записанное там прямым
    /// текстом («фильтр живёт здесь, а не у каждого читателя»). Повторив его,
    /// мы завели бы второе место, которое выглядит как страховка, а работает
    /// как расхождение: правило поменяется в одном, останется в другом,
    /// и разойдутся они молча.
    ///
    /// Своё дело у этой функции ровно одно, и оно про границу устройства:
    /// превратить автора в «своё или чужое». `IK` наверх не уходит (§13.4),
    /// а сравнение с собственным — протокольное знание, которому §13.3
    /// не даёт подняться выше.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn companion_reactions(
        &self,
        msg_id: &MsgId,
    ) -> Result<Vec<companion::Reaction>, EngineError> {
        let own_ik = self.identity.public().ik;
        Ok(self
            .store
            .reactions(msg_id)?
            .into_iter()
            // Предел провода (§5.5), а не хранилища: у себя телефон держит
            // столько реакций, сколько поставили.
            .take(companion::MAX_REACTIONS)
            .map(|reaction| companion::Reaction {
                mine: reaction.author_ik == own_ik,
                emoji: reaction.emoji,
            })
            .collect())
    }

    /// Отдаёт накопленные за шаг новости всем подключённым устройствам.
    ///
    /// **Без `Result`, и это то же правило, что у [`Engine::serve_companion`],
    /// только в обратную сторону.** Там просьба с другого устройства не вправе
    /// уронить шаг ядра; здесь не вправе и новость к нему. Не собравшийся
    /// кадр — беда терминала, а не телефона: телефон продолжает работать,
    /// а десктоп увидит расхождение при первом же перечитывании истории.
    pub(super) fn flush_companion_notices(&mut self, now_ms: u64) -> Vec<Effect> {
        let notices = std::mem::take(&mut self.companion_notices);
        // Очередь выгребается **всегда**, даже когда слушать некому: она
        // не журнал и не кэш. Кэш — забота десктопа (§13.4), и он его
        // наполняет запросом истории при подключении; копить новости
        // здесь значило бы завести на телефоне вторую, никем не читаемую
        // историю, которая растёт, пока десктоп выключен.
        if notices.is_empty() || self.device_links.is_empty() {
            return Vec::new();
        }

        // Отложенные собираются **здесь**, когда шаг уже дописал всё, что
        // дописывал: вложения ложатся в базу после текста, и новость,
        // собранная в `remember`, уехала бы без них.
        //
        // Собирается только то, что будет отправлено: слушателей уже
        // проверили выше, и на телефоне без сопряжённых устройств чтений
        // из базы не прибавляется вовсе.
        let mut ready = Vec::with_capacity(notices.len());
        for notice in notices {
            match notice {
                PendingNotice::Ready(notice) => ready.push(notice),
                PendingNotice::Message(msg_id) => match self.store.message(&msg_id) {
                    // Сообщение успели стереть на том же шаге — рассказывать
                    // нечего: об удалении десктоп узнает своей новостью.
                    Ok(None) => {}
                    Ok(Some(message)) => match self.companion_message(&message) {
                        Ok(message) => ready.push(companion::Notice::Message(message)),
                        Err(error) => tracing::warn!(?error, "сообщение десктопу не собрать"),
                    },
                    Err(error) => tracing::warn!(?error, "сообщение десктопу не прочитать"),
                },
            }
        }
        let notices = ready;

        let links: Vec<([u8; 32], Transport)> =
            self.device_links.iter().map(|(key, via)| (*key, *via)).collect();
        let mut effects = Vec::new();
        for (pairing_public, via) in links {
            for notice in &notices {
                let sealed = self.send_to_device(
                    now_ms,
                    pairing_public,
                    via,
                    PayloadType::CompanionNotice,
                    companion::notice_payload(notice),
                );
                match sealed {
                    Ok(sent) => effects.extend(sent),
                    Err(error) => tracing::warn!(?error, "новость компаньону не ушла"),
                }
            }
        }
        effects
    }

    /// Запечатывает кадр в сессию устройства.
    ///
    /// Прямо в сессию, минуя очередь §5.4, и это не срез угла. Очередь —
    /// про доставку **сообщений**: она переживает перезапуск, перебирает
    /// ступени и в конце объявляет «не доставлено». Разговор с терминалом
    /// не таков ни в одной из трёх частей: пережившая перезапуск просьба
    /// протухла, ступеней у него одна, а «не доставлено» ему скажет
    /// собственная тишина.
    pub(super) fn send_to_device(
        &mut self,
        now_ms: u64,
        pairing_public: [u8; 32],
        via: Transport,
        payload_type: PayloadType,
        payload: Value,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(session_id) = self.sessions.for_peer(&pairing_public, via) else {
            return Ok(Vec::new());
        };
        let envelope =
            Envelope::new(self.entropy.msg_id(), self.clock.now(now_ms)?, payload_type, payload);
        let frames = self.seal_for(session_id, via, &envelope.encode()?)?;
        Ok(Self::sends(pairing_public, via, frames))
    }

    /// Адрес сопряжённого устройства, если оно его называло (§13.4).
    ///
    /// Отдельная выборка, а не обход [`Engine::paired_devices`]: спрашивают
    /// её на **каждый** уходящий кадр, а тот список собирается заново
    /// со всеми строками.
    #[must_use]
    pub fn device_onion(&self, pairing_public: &[u8; 32]) -> Option<&str> {
        self.devices
            .get(pairing_public)
            .map(|device| device.onion.as_str())
            .filter(|onion| !onion.is_empty())
    }

    /// Ключ меша сопряжённого устройства (0.2).
    ///
    /// `None` — «меша у него нет», и это самое частое: меш выключен
    /// по умолчанию (§14). Нужен драйверу для набора: телефон отвечает
    /// не в принятое соединение, а в своё (5ц), и набирать его надо
    /// по адресу, а не по тому, откуда пришёл кадр.
    #[must_use]
    pub fn device_ygg(&self, pairing_public: &[u8; 32]) -> Option<&[u8]> {
        self.devices
            .get(pairing_public)
            .map(|device| device.ygg.as_slice())
            .filter(|ygg| !ygg.is_empty())
    }

    /// Сопряжённые устройства (§13.4).
    #[must_use]
    pub fn paired_devices(&self) -> Vec<crate::companion::PairedDevice> {
        self.devices
            .values()
            .map(|d| crate::companion::PairedDevice {
                device_id: d.device_id,
                pairing_public: d.pairing_public,
                label: d.label.clone(),
                paired_ms: d.paired_ms,
                last_seen_ms: d.last_seen_ms,
                onion: d.onion.clone(),
            })
            .collect()
    }

    /// Есть ли прямо сейчас канал с этим устройством.
    #[must_use]
    pub fn device_connected(&self, device_id: &[u8; 16]) -> bool {
        // По доказанному пути, а не по тому, куда мы готовы слать: наружу
        // отдаётся то, что показывают человеку.
        self.device_seen
            .iter()
            .any(|key| self.devices.get(key).is_some_and(|d| d.device_id == *device_id))
    }
}
