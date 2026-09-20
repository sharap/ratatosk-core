//! Переписка один-на-один: текст, чтение, правка, отзыв, реакции.
//!
//! Всё, что человек делает **со словами**: пишет, отвечает, правит,
//! отзывает, помечает прочитанным, ставит знак. Доставка этих слов
//! живёт этажом ниже, в `delivery`: здесь решают, что сказать,
//! там — как довезти.

use super::*;

impl<S: Store> Engine<S> {
    /// Клиент сообщил, что пользователь прочитал чат до этого места (§9.4).
    ///
    /// **Единственный источник квитанции о прочтении.** Ни приём сообщения,
    /// ни открытие чата, ни запуск приложения её не порождают: ядро не знает
    /// и не может знать, что человек прочитал. Знает клиент — и говорит
    /// об этом вызовом. Из этого следует и то, что клиент, который квитанций
    /// о прочтении не хочет (или у которого они выключены настройкой), просто
    /// не зовёт эту команду; отдельного выключателя в ядре для этого не надо.
    ///
    /// Водяной знак — до какого места уже отправляли — **лежит на диске**.
    /// Раньше он жил в памяти, и это была ошибка ровно того же рода: после
    /// перезапуска первое же открытие чата выпускало квитанцию заново, то есть
    /// квитанция получалась следствием запуска приложения, а не действия
    /// человека. Одному собеседнику это выглядит как «он перечитывает нашу
    /// переписку» на пустом месте.
    pub(super) fn on_mark_read(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        up_to: MsgId,
    ) -> Result<Vec<Effect>, EngineError> {
        // **В группе делать нечего, и это не ошибка.** Квитанций там нет
        // по §11.3: копии молчаливые, и один значок на тридцать двух
        // получателей §14 всё равно не разрешает. Водяной знак тоже
        // не нужен — он существует ровно затем, чтобы не слать квитанцию
        // дважды.
        //
        // Важно, что это тихий возврат, а не отказ: до этой правки открытая
        // на десктопе группа отвечала «контакт неизвестен» на совершенно
        // законное «человек дочитал», и клиенту приходилось бы гадать,
        // сломалось у него что-то или нет.
        if self.groups.contains_key(&chat) {
            return Ok(Vec::new());
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        let window = self.store.messages(&chat, MAX_RECEIPT_IDS, None)?;
        // Граница задаётся сообщением, а не временем: клиент знает, до какого
        // места дочитал пользователь, но не знает меток HLC.
        let Some(edge) = window.iter().find(|m| m.msg_id == up_to).map(|m| m.hlc) else {
            // Сообщение вне окна или уже вычищено уборкой (§12) — не ошибка.
            return Ok(Vec::new());
        };

        let watermark = self.read_upto.get(&chat).copied();
        let ids: Vec<MsgId> = window
            .iter()
            // Квитанция о прочтении — про **чужие** сообщения: своим она
            // ничего не сообщает.
            .filter(|m| m.sender_ik == peer_ik)
            .filter(|m| m.hlc <= edge && watermark.is_none_or(|seen| m.hlc > seen))
            .map(|m| m.msg_id)
            .collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // Прямой канал, а не очередь §5.4: квитанция не начинает рукопожатие
        // и не уходит почтой. Но и не мимо §5.4 — какой из прямых каналов
        // сейчас годен, решает та же лестница, см. `direct_channel`.
        let Some(via) = self.direct_channel(&peer_ik) else {
            return Ok(Vec::new());
        };

        // Знак двигается вместе с отправкой, а не до неё: не ушло — значит
        // и отмечать нечего, иначе следующий вызов промолчит о сообщениях,
        // про которые собеседник так и не узнал.
        let effects = self.send_receipt(now_ms, peer_ik, via, Receipt::Read, &ids)?;
        if !effects.is_empty() {
            self.read_upto.insert(chat, edge);
            self.persist_read_upto(chat, edge)?;
        }
        Ok(effects)
    }

    /// Кладёт водяной знак прочтения на диск (§9.4).
    pub(super) fn persist_read_upto(&mut self, chat: ChatId, edge: Hlc) -> Result<(), EngineError> {
        let mut value = [0u8; 12];
        value[..8].copy_from_slice(&edge.wall_ms.to_be_bytes());
        value[8..].copy_from_slice(&edge.logical.to_be_bytes());
        self.store.put_meta(&ratatosk_store::read_upto_key(&chat), &value)?;
        Ok(())
    }

    /// Читает водяной знак прочтения с диска.
    ///
    /// Испорченное значение трактуется как его отсутствие: цена ошибки —
    /// одна лишняя квитанция, а отказ открыть базу из-за двенадцати байт
    /// служебной метки был бы несоразмерен.
    pub(super) fn load_read_upto(&self, chat: ChatId) -> Result<Option<Hlc>, EngineError> {
        let Some(raw) = self.store.meta(&ratatosk_store::read_upto_key(&chat))? else {
            return Ok(None);
        };
        let Ok(bytes): Result<[u8; 12], _> = raw.as_slice().try_into() else {
            return Ok(None);
        };
        let wall_ms = u64::from_be_bytes(bytes[..8].try_into().expect("восемь байт"));
        let logical = u32::from_be_bytes(bytes[8..].try_into().expect("четыре байта"));
        Ok(Some(Hlc::new(wall_ms, logical)))
    }

    /// Убирает сообщения из своей истории. Ничего никуда не отправляет.
    ///
    /// Возвращает событие только про те, что действительно были: список
    /// приходит от клиента, и половина названного могла быть удалена
    /// секунду назад с другого экрана.
    pub(super) fn forget_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Vec<Effect> {
        let mut gone = Vec::new();
        for msg_id in msg_ids {
            // Удалённое не должно уехать. Сообщение могло ждать сети со
            // статусом «отправим, когда появится»; отправить его после того,
            // как человек его удалил, — худшее из возможных поведений.
            self.deferred.retain(|d| d.msg_id != *msg_id);
            self.outbox.retain(|d| d.msg_id != *msg_id);
            let _ = self.store.delete_outbox_all(msg_id);

            // Вложения уходят вместе с сообщением — и записи, и байты.
            // Каскад внешнего ключа тут не поможет: надгробие не удаляет
            // строку сообщения, а гигабайт чанков на диске пережил бы «удалить»
            // и лежал бы там, где человек уверен, что уже ничего нет.
            self.forget_files(msg_id);

            // Отказ хранилища на одном сообщении не повод бросить остальные:
            // пользователь просил убрать список, а не «список или ничего».
            if self.store.tombstone_message(msg_id, now_ms).unwrap_or(false) {
                gone.push(*msg_id);
            }
        }
        if gone.is_empty() {
            return Vec::new();
        }
        vec![Effect::Notify(Event::MessagesDeleted { chat, msg_ids: gone })]
    }

    /// Удаляет у себя и просит собеседника удалить у себя.
    ///
    /// Просьба уходит только про **свои** сообщения. Чужие удаляются локально
    /// и молча: попросить человека забыть его собственные слова — не то, что
    /// протокол должен уметь выражать, и получатель такую просьбу всё равно
    /// отвергнет (см. [`Engine::on_retract`]).
    ///
    /// Отзыв едет **обычной очередью доставки** (§5.4), а не отдельным
    /// быстрым каналом, как квитанция (§9.4). Квитанция, не дошедшая до
    /// собеседника, — мелочь; отзыв, не дошедший потому, что человек был
    /// офлайн, — ровно та неудача, ради которой всё и затевалось.
    pub(super) fn on_retract_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        if self.groups.contains_key(&chat) {
            return self.retract_group_messages(now_ms, chat, msg_ids);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        let ours = self.own_of(chat, msg_ids)?;

        let mut effects = self.forget_messages(now_ms, chat, msg_ids);
        if ours.is_empty() {
            return Ok(effects);
        }

        let (_, produced) = self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Retract,
            ratatosk_proto::retract::payload(&ours),
        )?;
        effects.extend(produced);
        Ok(effects)
    }

    /// Отбирает из названного то, что **наше и в этом чате**.
    ///
    /// Одно место на 1:1 и на группу: правило про то, что вправе уехать
    /// в просьбе об отзыве, а разойдись две копии — разошлось бы и то,
    /// чем отзыв в группе отличается от отзыва в переписке.
    ///
    /// Чьё сообщение — знает хранилище, а не клиент: он мог прислать
    /// и чужой идентификатор, и вовсе выдуманный.
    ///
    /// **И в этом чате.** Правка и ответ чат проверяли всегда, отзыв —
    /// не проверял, и это давало утечку: назвав номер из другого разговора,
    /// клиент попросил бы удалить его у собеседника, тем самым рассказав,
    /// что такой номер вообще есть. В группе цена той же ошибки — тридцать
    /// два человека вместо одного.
    pub(super) fn own_of(
        &self,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<MsgId>, EngineError> {
        let own_ik = self.identity.public().ik;
        let mut ours = Vec::new();
        for msg_id in msg_ids.iter().take(ratatosk_proto::MAX_RETRACT_IDS) {
            if self
                .store
                .message(msg_id)?
                .is_some_and(|m| m.sender_ik == own_ik && m.chat_id == chat)
            {
                ours.push(*msg_id);
            }
        }
        Ok(ours)
    }

    /// Очищает чат у себя.
    pub(super) fn on_clear_chat(
        &mut self,
        now_ms: u64,
        chat: ChatId,
    ) -> Result<Vec<Effect>, EngineError> {
        // Идентификаторы собираются до уборки: событие обязано сказать UI,
        // что именно исчезло, а после надгробий история уже пуста.
        let doomed: Vec<MsgId> =
            self.store.messages(&chat, usize::MAX, None)?.into_iter().map(|m| m.msg_id).collect();
        if self.store.tombstone_chat(&chat, now_ms)? == 0 {
            return Ok(Vec::new());
        }
        // Ничего из очищенного не должно уехать позже — и ничего не должно
        // остаться на диске.
        for msg_id in &doomed {
            self.forget_files(msg_id);
            self.deferred.retain(|d| d.msg_id != *msg_id);
            self.outbox.retain(|d| d.msg_id != *msg_id);
            self.store.delete_outbox_all(msg_id)?;
        }
        // Водяной знак прочтения теряет смысл вместе с историей: сообщений,
        // про которые уже отправляли квитанцию, больше нет.
        self.read_upto.remove(&chat);
        Ok(vec![Effect::Notify(Event::MessagesDeleted { chat, msg_ids: doomed })])
    }

    /// Пришла просьба удалить сообщения.
    ///
    /// **Отозвать можно только своё.** Проверяет это получатель, а не
    /// отправитель: иначе достаточно прислать чужой идентификатор, чтобы
    /// стереть слова из чужой переписки. Стоит проверка одного сравнения
    /// `sender_ik`, а без неё «удалить у обоих» превращается в «удалить
    /// у кого угодно что угодно».
    ///
    /// Просьба про сообщение, которого нет, — не ошибка: копия могла быть
    /// удалена раньше или не дойти вовсе.
    pub(super) fn on_retract(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let msg_ids = ratatosk_proto::retract::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let mut gone = Vec::new();
        for msg_id in &msg_ids {
            let Some(message) = self.store.message(msg_id)? else { continue };
            if message.sender_ik != peer_ik || message.chat_id != chat {
                // Просьба про чужое. Это не «формат не тот», а попытка
                // распорядиться не своим, поэтому она считается аномалией
                // сессии, а не молча пропускается.
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                continue;
            }
            if self.store.tombstone_message(msg_id, now_ms)? {
                gone.push(*msg_id);
            }
        }

        // Квитанция — как на текст (§9.4), и по той же причине: отзыв едет
        // очередью §5.4, а запись в очереди закрывается подтверждением.
        // Без него страховочный срок прямого канала объявил бы неудачу
        // и послал бы ту же просьбу ещё раз, уже почтой.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;
        if !gone.is_empty() {
            effects.push(Effect::Notify(Event::MessagesDeleted { chat, msg_ids: gone }));
        }
        Ok(effects)
    }

    /// Кладёт сообщение в историю — единственная дверь, через которую оно
    /// туда попадает.
    ///
    /// Дверь одна затем, что за ней есть учёт: уборка (§12) запускается
    /// «каждые N сообщений», и считать их по трём разным местам значит
    /// однажды забыть четвёртое.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn remember(&mut self, message: &StoredMessage) -> Result<(), EngineError> {
        self.store.put_message(message)?;
        self.messages_since_compaction = self.messages_since_compaction.saturating_add(1);
        // Одно место на все сообщения — своё, принятое, пересланное, ответ, —
        // и десктоп (§13.4) узнаёт о них здесь же. Разослать новость из каждой
        // вызывающей функции значило бы завести пять мест, где про десктоп
        // надо помнить, и первая же забывшая тихо перестала бы его обновлять.
        self.companion_notices.push(PendingNotice::Message(message.msg_id));
        Ok(())
    }

    /// Заменяет текст своего сообщения и просит собеседника сделать то же.
    ///
    /// Три отказа, и все три — до записи: пустая правка (это удаление, у него
    /// своя команда), чужое сообщение, истёкшее окно. Отказ возвращается
    /// вызывающему, потому что человек ждёт ответа **сейчас**: он смотрит
    /// на поле ввода, и «ничего не произошло» здесь — худший исход.
    ///
    /// Прежний текст не сохраняется, но появляется отметка о правке: молча
    /// подменить слова в чужой истории §14 запрещает.
    ///
    /// **Очередь при этом не переписывается.** Если сообщение ещё ждёт сети,
    /// собеседник получит сперва прежний текст, а сразу за ним — правку,
    /// и увидит исправленное с пометкой «изменено». Это верно и без хитростей:
    /// сообщение действительно правили. Подменять конверт в очереди значило бы
    /// решать, дошла ли уже копия, — а этого мы не знаем (§9.2).
    pub(super) fn on_edit_message(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        // Группа — первой, как и у отправки текста: идентификаторы чатов
        // у групп и у 1:1 живут в одном пространстве, а записи `by_chat`
        // у группы нет вовсе.
        if self.groups.contains_key(&chat) {
            return self.edit_group_message(now_ms, chat, msg_id, text);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        ratatosk_proto::edit::check(text)?;
        // Правка едет своим кадром, и предел у неё тот же: иначе сообщение,
        // которое отправилось, стало бы непоправимым — или наоборот.
        if !ratatosk_proto::files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }

        // Чьё сообщение и когда оно появилось — знает хранилище, а не клиент.
        let own_ik = self.identity.public().ik;
        let message = self
            .store
            .message(&msg_id)?
            .filter(|m| m.sender_ik == own_ik && m.chat_id == chat)
            .ok_or(ratatosk_proto::EditError::NotYours)?;
        // Срок считается по **местным** часам: `received_ms` у своего
        // сообщения — момент, когда человек нажал «отправить». Физическая
        // компонента HLC для этого не годится, её вторая половина приходит
        // от собеседника (§9.1).
        if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
            return Err(ratatosk_proto::EditError::TooLate.into());
        }

        let trimmed = text.trim();
        let mut effects = Vec::new();
        if self.store.edit_message(&msg_id, trimmed.as_bytes(), now_ms)? {
            effects.push(Effect::Notify(Event::MessageEdited { chat, msg_id }));
        }
        let (_, produced) = self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Edit,
            ratatosk_proto::edit::payload(msg_id, trimmed),
        )?;
        effects.extend(produced);
        Ok(effects)
    }

    /// Пересылает сообщения в другой чат.
    ///
    /// Каждое уезжает своим новым сообщением: новый `msg_id`, своя метка,
    /// своя запись в очереди. Автор не указывается — см.
    /// `ratatosk_proto::forward`: подпись §6 при пересылке не сохраняется,
    /// и имя рядом с чужими словами было бы утверждением, которое получатель
    /// проверить не может.
    ///
    /// Пропущенное молча — то, чего уже нет или что нельзя прочитать текстом:
    /// список приходит от клиента, а половина названного могла быть удалена
    /// секунду назад с другого экрана.
    pub(super) fn on_forward_messages(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        // Группа — первой, как и у всего остального, что берёт `chat`.
        if self.groups.contains_key(&chat) {
            return self.forward_to_group(now_ms, chat, msg_ids);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;

        // Собирается заранее: отправка занимает `self` целиком.
        let picked = self.pick_forwards(msg_ids)?;

        let mut effects = Vec::new();
        for what in picked {
            match what {
                Forwarded::Text(text) => effects.extend(self.send_own_text(
                    now_ms,
                    chat,
                    peer_ik,
                    &text,
                    TextKind::Forwarded,
                )?),
                Forwarded::Files(text, offers) => {
                    effects.extend(self.forward_files(now_ms, chat, peer_ik, &text, offers)?);
                }
                Forwarded::Card(card_bytes) => {
                    effects.extend(self.forward_card(now_ms, chat, peer_ik, card_bytes)?);
                }
            }
        }
        Ok(effects)
    }

    /// Что именно уедет пересылкой: текст и вложения — по сообщению.
    ///
    /// **Вложения здесь появились не сразу, и это была настоящая потеря.**
    /// Пересылка брала одно тело сообщения, а у сообщения с файлами тело —
    /// это подпись к ним. Нет подписи — у получателя пустое сообщение,
    /// и файлы не доехали вовсе. Проверял это человек за другим экраном,
    /// потому что в тестах пересылали только текст.
    ///
    /// Едет **ключ и хэш**, а не байты заново: `proto::forward` обещал ровно
    /// это с самого начала. Предложение поэтому несёт **прежний** `file_id` —
    /// иначе чанки пришлось бы перешифровать (§10.1 кладёт `file_id` в AAD),
    /// а гигабайт крипты ради пересылки на телефоне не делают.
    ///
    /// Пропускается молча: сообщение, которого уже нет; тело не текстом
    /// (и без вложений — тогда пересылать нечего); вложение, которого у нас
    /// нет целиком. Последнее важнее прочего: предложить файл, чанков
    /// которого у нас нет, значит пообещать то, чего мы не отдадим,
    /// и получатель ждал бы вечно.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn pick_forwards(&self, msg_ids: &[MsgId]) -> Result<Vec<Forwarded>, EngineError> {
        let mut picked = Vec::new();
        for msg_id in msg_ids.iter().take(ratatosk_proto::MAX_FORWARD_IDS) {
            let Some(message) = self.store.message(msg_id)? else { continue };
            let Ok(text) = String::from_utf8(message.body) else { continue };
            let offers: Vec<ratatosk_proto::files::FileOffer> = self
                .store
                .files_of(msg_id)?
                .into_iter()
                .filter(|file| file.complete)
                // **Пересланный файл сохраняет прежний размер чанка,
                // и теперь он у нас есть.** Файл уже нарезан: принятые
                // чанки лежат по номерам, и перенумеровать их означало бы
                // перечитать его целиком. Размер, которым его резал первый
                // отправитель, лежит в записи файла с миграции 0026 —
                // до неё его брать было неоткуда, и здесь стояло своё
                // умолчание. Оно и делало пересылку по эфиру неработающей:
                // эфирный файл, нарезанный по три с половиной килобайта,
                // предлагался следующему как нарезанный по мебибайту,
                // и тот просил куски, которых нет.
                .map(|file| ratatosk_proto::files::FileOffer {
                    chunk_bytes: file.chunk_bytes as usize,
                    file_id: file.file_id,
                    name: file.name,
                    size_bytes: file.size_bytes,
                    key: file.key,
                    preview: file.preview,
                })
                .collect();
            // Карточка человека — третье, чем сообщение бывает наполнено,
            // и третий раз, когда пересылка про это забыла. Тело у такого
            // сообщения пустое по построению: карточка лежит записью рядом.
            let card = self.store.contact_share_of(msg_id)?.map(|share| share.card_bytes);
            // Ни слов, ни файлов, ни карточки — пересылать нечего. Пустое
            // сообщение у получателя и было тем, что сломалось трижды.
            let what = match (offers.is_empty(), card) {
                (_, Some(card_bytes)) => Forwarded::Card(card_bytes),
                (false, None) => Forwarded::Files(text, offers),
                (true, None) if !text.is_empty() => Forwarded::Text(text),
                (true, None) => continue,
            };
            picked.push(what);
        }
        Ok(picked)
    }

    /// Пересылает карточку одному собеседнику.
    ///
    /// Отличие от `on_share_contact` одно: байты берутся из **записи
    /// у пересылаемого сообщения**, а не из контактов. Человека, чью
    /// карточку переслали, у нас может не быть вовсе — в этом половина
    /// смысла: «вот его контакт» пересылают как раз незнакомому.
    ///
    /// # Errors
    ///
    /// Отказ хранилища, разбор карточки или сборка конверта.
    pub(super) fn forward_card(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        card_bytes: Vec<u8>,
    ) -> Result<Vec<Effect>, EngineError> {
        let ik = ContactCard::decode(&card_bytes)?.value().ik;
        let msg_id = self.entropy.msg_id();
        let hlc = self.clock.now(now_ms)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            // Пусто, как и у своей карточки: она лежит записью рядом.
            body: Vec::new(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: true,
            reply_to: None,
        })?;
        self.store.put_contact_share(&StoredContactShare {
            msg_id,
            ik,
            card_bytes: card_bytes.clone(),
        })?;

        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::ContactShare,
            ratatosk_proto::contact_share::payload(&card_bytes, true),
        );
        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: false,
        })
    }

    /// Пересылает вложения одному собеседнику.
    ///
    /// Отличие от `on_send_files` ровно одно: записи о файлах уже есть,
    /// и заводить их заново нельзя — `file_id` тот же, а вместе с ним те же
    /// байты, ключ и признак «собран». Новому сообщению файл **прикладывают**
    /// (`Store::attach_file`), а не создают.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки конверта.
    pub(super) fn forward_files(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        text: &str,
        offers: Vec<ratatosk_proto::files::FileOffer>,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        files::check_offers(&offers).map_err(EngineError::File)?;
        let msg_id = self.entropy.msg_id();
        let hlc = self.clock.now(now_ms)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: true,
            reply_to: None,
        })?;
        for (at, offer) in offers.iter().enumerate() {
            self.store.attach_file(
                &msg_id,
                &offer.file_id,
                u32::try_from(at).unwrap_or(u32::MAX),
            )?;
        }

        // Тип конверта — `FileOffer`, а не `Forward`: второй означал бы
        // вторую копию всего разбора вложений ради одного признака.
        // Признак поэтому едет **внутри** предложения — и едет обязательно:
        // без пометки чужие слова выглядят своими, а это ровно та неправда,
        // о которой весь `proto::forward`.
        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::FileOffer,
            files::offer_payload(text, &offers, true),
        );
        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: false,
        })
    }

    /// Пересылает сообщения в группу (§11.3).
    ///
    /// Каждое — своим действием и своим номером цепочки, как и всё
    /// остальное в группе: пересылка трёх сообщений это три строки
    /// в истории у всех участников, а не одна склеенная.
    ///
    /// Пустое и не-текст пропускаются молча — то же правило, что один
    /// на один: список приходит от клиента, а половина названного могла
    /// быть удалена секунду назад с другого экрана.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки группового кадра.
    pub(super) fn forward_to_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        let picked = self.pick_forwards(msg_ids)?;

        let mut effects = Vec::new();
        for what in picked {
            // Три вида действия на три случая, и различает их то, чем
            // сообщение наполнено. Слова — `Forward`; файлы (с подписью
            // или без) — `Files`; карточка — `ContactShare`. У двух
            // последних разбор своего содержимого уже есть, и отдельный
            // «пересланный» вид означал бы вторую его копию.
            //
            // Пустое сюда не доходит вовсе: такое отсеял `pick_forwards`.
            let (text, offers, card) = match what {
                Forwarded::Text(text) => (text, Vec::new(), None),
                Forwarded::Files(text, offers) => (text, offers, None),
                Forwarded::Card(card_bytes) => (String::new(), Vec::new(), Some(card_bytes)),
            };
            let action = match (&card, offers.is_empty()) {
                (Some(card_bytes), _) => ratatosk_proto::group_action::Action::ContactShare {
                    card_bytes: card_bytes.clone(),
                    forwarded: true,
                },
                (None, true) => {
                    ratatosk_proto::group_action::Action::Forward { text: text.clone() }
                }
                (None, false) => ratatosk_proto::group_action::Action::Files {
                    caption: text.clone(),
                    offers: offers.clone(),
                    forwarded: true,
                },
            };
            // Кадр — до записи в базу: сборка вправе отказать (цепочки может
            // не быть, нас могли исключить), а сообщение, легшее в историю
            // и не собравшееся в кадр, человек видел бы вечно отправляющимся.
            let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;
            self.remember(&StoredMessage {
                msg_id,
                chat_id: chat,
                sender_ik: self.identity.public().ik,
                hlc,
                body: text.into_bytes(),
                received_ms: now_ms,
                // Статуса нет — как у всякой групповой копии (§11.3).
                status: None,
                edited_ms: None,
                // Своя копия помечена так же, как копии участников: иначе
                // отправитель и получатели видели бы разное про одно и то же
                // сообщение.
                forwarded: true,
                reply_to: None,
            })?;
            // Файл прикладывается к новой строке, а не заводится заново:
            // `file_id` тот же, байты те же, и «собран» терять нельзя.
            for (at, offer) in offers.iter().enumerate() {
                self.store.attach_file(
                    &msg_id,
                    &offer.file_id,
                    u32::try_from(at).unwrap_or(u32::MAX),
                )?;
            }
            // Карточка — записью рядом, как и у своей: без неё пересланное
            // сообщение осталось бы пустым **у нас**, хотя участники его
            // увидят. Расхождение экранов про одно сообщение §14 запрещает.
            if let Some(card_bytes) = card {
                let ik = ContactCard::decode(&card_bytes)?.value().ik;
                self.store.put_contact_share(&StoredContactShare { msg_id, ik, card_bytes })?;
            }
            effects.extend(self.fan_out_group(now_ms, chat, msg_id, &bytes)?);
        }
        Ok(effects)
    }

    /// Ставит или снимает свою реакцию.
    ///
    /// Реагировать можно и на своё сообщение: запрещать это незачем, а правило
    /// «только чужое» пришлось бы объяснять.
    ///
    /// Метка HLC у реакции своя, и она существенна: реакция законно приезжает
    /// с опозданием (§9.2), и без метки запоздавшая копия возвращала бы то,
    /// что человек снял.
    pub(super) fn on_set_reaction(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        msg_id: MsgId,
        emoji: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        if self.groups.contains_key(&chat) {
            return self.react_in_group(now_ms, chat, msg_id, emoji);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        // Проверка та же, что и на приёме: отправить то, что сами не приняли
        // бы, — верный способ развести две стороны.
        ratatosk_proto::reaction::check(emoji)?;

        // Реакция на то, чего нет, — не ошибка ядра, но и делать нечего.
        if self.store.message(&msg_id)?.is_none_or(|m| m.chat_id != chat) {
            return Ok(Vec::new());
        }

        let hlc = self.clock.now(now_ms)?;
        let own_ik = self.identity.public().ik;
        self.store.put_reaction(&ratatosk_store::StoredReaction {
            msg_id,
            author_ik: own_ik,
            emoji: emoji.to_owned(),
            hlc,
        })?;

        let mut effects =
            vec![Effect::Notify(Event::ReactionChanged { chat, msg_id, author_ik: own_ik })];
        let (_, produced) = self.enqueue_request(
            now_ms,
            peer_ik,
            PayloadType::Reaction,
            ratatosk_proto::reaction::payload(msg_id, emoji),
        )?;
        effects.extend(produced);
        Ok(effects)
    }

    /// Пришла просьба заменить текст сообщения.
    ///
    /// **Править можно только своё**, и проверяет это получатель — ровно как
    /// с отзывом. Без проверки достаточно прислать чужой идентификатор, чтобы
    /// переписать слова в чужой переписке, а это хуже удаления: удаление
    /// видно, подмена — нет.
    ///
    /// Окно правки проверяется здесь **по своим часам**, и у этого есть цена:
    /// правка, пролежавшая в очереди дольше недели, не применится, а
    /// собеседник об этом не узнает — квитанция говорит «кадр пришёл», а не
    /// «правка принята». Отдельного отказа для этого случая нет намеренно:
    /// новый вид кадра ради события, которое требует недели офлайна, дороже
    /// пользы. Записано как известный пробел, а не как «работает».
    pub(super) fn on_edit(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, text) = ratatosk_proto::edit::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        // Квитанция — как на текст и как на отзыв (§9.4): запись в очереди
        // §5.4 закрывается подтверждением, иначе страховочный срок объявит
        // неудачу и пошлёт ту же просьбу ещё раз.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        // Правка про сообщение, которого нет, — не ошибка: копия могла быть
        // удалена раньше или не дойти вовсе.
        let Some(message) = self.store.message(&target)? else { return Ok(effects) };
        if message.sender_ik != peer_ik || message.chat_id != chat {
            // Попытка распорядиться не своим — аномалия сессии, а не «формат
            // не тот».
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }
        if !ratatosk_proto::edit::within_window(message.received_ms, now_ms) {
            return Ok(effects);
        }

        if self.store.edit_message(&target, text.as_bytes(), now_ms)? {
            effects.push(Effect::Notify(Event::MessageEdited { chat, msg_id: target }));
        }
        Ok(effects)
    }

    /// Пришла реакция собеседника.
    ///
    /// Реагировать он может и на своё сообщение, и на наше — но только в своём
    /// чате: реакция на сообщение из чужой переписки означала бы, что нам
    /// прислали идентификатор, которого знать не должны.
    pub(super) fn on_reaction(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, emoji) = ratatosk_proto::reaction::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;

        let Some(message) = self.store.message(&target)? else { return Ok(effects) };
        if message.chat_id != chat {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        }

        // §9.1: свежее не затирается старым. Сравнивается с записью **как
        // есть**, включая снятие: иначе опоздавшая реакция вернула бы то,
        // что собеседник убрал.
        if self.store.reaction(&target, &peer_ik)?.is_some_and(|known| known.hlc >= envelope.hlc) {
            return Ok(effects);
        }

        self.store.put_reaction(&ratatosk_store::StoredReaction {
            msg_id: target,
            author_ik: peer_ik,
            emoji,
            hlc: envelope.hlc,
        })?;
        effects.push(Effect::Notify(Event::ReactionChanged {
            chat,
            msg_id: target,
            author_ik: peer_ik,
        }));
        Ok(effects)
    }

    /// Отправляет квитанцию собеседнику (§9.4).
    ///
    /// Не через очередь доставки, и это важно. Квитанция — сведение о чужом
    /// сообщении, а не своё сообщение: у неё нет ни истории, ни статуса,
    /// и повторять её другим транспортом бессмысленно. Не дошла — собеседник
    /// увидит «отправлено» вместо «доставлено», что честно.
    ///
    /// Квитанция на квитанцию не отправляется по построению: сюда приходят
    /// только из ветки текста.
    pub(super) fn send_receipt(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        receipt: Receipt,
        msg_ids: &[MsgId],
    ) -> Result<Vec<Effect>, EngineError> {
        // §9.4: по почте квитанции не ходят — каждая была бы отдельным
        // письмом, то есть удвоением трафика и метаданных у сервера.
        if !ratatosk_proto::receipts::may_send_receipt(via) || msg_ids.is_empty() {
            return Ok(Vec::new());
        }
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            // Сессии нет — рукопожатие ради квитанции не начинаем: это
            // превратило бы сведение о доставке в повод для трафика.
            return Ok(Vec::new());
        };

        let hlc = self.clock.now(now_ms)?;
        let envelope = Envelope::new(
            self.entropy.msg_id(),
            hlc,
            PayloadType::Receipt,
            receipt.payload(msg_ids),
        );
        let frames = self.seal_for(session_id, via, &envelope.encode()?)?;
        Ok(Self::sends(peer_ik, via, frames))
    }

    /// Выставляет статус доставки и сообщает о нём UI (§9.4).
    ///
    /// Одна точка на все переходы, и это не удобство: статус обязан только
    /// расти, а правило «только растёт», размазанное по пяти местам, рано
    /// или поздно разойдётся. Хранилище возвращает статус, **который
    /// получился**, — его и показываем, а не тот, что просили.
    ///
    /// Неизвестный `msg_id` — не ошибка: квитанция может прийти на сообщение,
    /// уже вычищенное уборкой (§12), и ронять из-за этого сессию незачем.
    pub(super) fn note_status(
        &mut self,
        msg_id: MsgId,
        target: DeliveryStatus,
    ) -> Result<Vec<Effect>, EngineError> {
        let current = self.store.status(&msg_id)?.and_then(DeliveryStatus::from_code);
        // Допустимость перехода решает §9.4, а не хранилище и не это место:
        // правило неочевидное (`Undeliverable` перекрывает только `Pending`),
        // и записанное дважды оно однажды разойдётся.
        let Some(status) = ratatosk_proto::receipts::advance(current, target) else {
            // Ничего не изменилось — события об этом быть не должно.
            return Ok(Vec::new());
        };
        // Уборки очереди здесь **нет**, и её отсутствие — исправление
        // поломки, стоившей группам доставки.
        //
        // Прежде эта функция вместе со статусом снимала с очереди всё
        // с таким `msg_id`. Для разговора один на один это верно: номер
        // там принадлежит одной доставке. В группе номер один на N копий
        // (§11.3), и первая же дошедшая уносила из очереди — и из памяти,
        // и с диска — копии всех участников, до которых в тот момент было
        // не достучаться. Они не получали сообщение никогда, а следующие
        // доходили как ни в чём не бывало: «не всегда и не до всех».
        //
        // Снимает с очереди теперь тот, кто знает **получателя**, —
        // `retire_delivery`. Статус и очередь разведены: первый про
        // сообщение, вторая про доставку, и это разные вещи.

        // Хранилище отвечает, нашлась ли строка. Не нашлась — сообщать UI
        // не о чем: по очереди §5.4 ездят и отзывы, которых в истории нет,
        // и события о статусе несуществующего сообщения только запутали бы
        // клиента. То же и с удалённым: у надгробия статуса нет.
        if !self.store.set_status(&msg_id, status.code())? {
            return Ok(Vec::new());
        }
        // Десктопу — та же новость (§13.4): у него своя копия чата, и статус
        // «доставлено» обязан появиться там же, где на телефоне. Очередь
        // выгребается в конце шага, см. `Engine::step`.
        self.companion_notices.push(PendingNotice::Ready(companion::Notice::Status {
            msg_id,
            status: status.code(),
        }));
        Ok(vec![Effect::Notify(Event::StatusChanged { msg_id, status })])
    }

    pub(super) fn send_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        // Группа — первой: идентификаторы чатов у групп и у 1:1 живут
        // в одном пространстве, и спутать их нельзя. У группы `by_chat`
        // записи нет вовсе, так что порядок здесь про ясность, а не про
        // разрешение неоднозначности.
        if self.groups.contains_key(&chat) {
            return self.send_group_text(now_ms, chat, text);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        self.send_own_text(now_ms, chat, peer_ik, text, TextKind::Plain)
    }

    /// Отвечает на сообщение этого чата.
    ///
    /// По проводу едет ссылка, а не цитата: цитату каждая сторона рисует
    /// из своей копии, и подделать её поэтому нельзя. Цель проверяется здесь —
    /// она обязана существовать и лежать **в этом** чате: ответ на сообщение
    /// из чужого разговора и цитировать нечем, и рассказал бы получателю
    /// об идентификаторе, которого он знать не должен.
    pub(super) fn on_send_reply(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        reply_to: MsgId,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        if self.groups.contains_key(&chat) {
            return self.reply_in_group(now_ms, chat, reply_to, text);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        // Та же функция, что зовёт граница UniFFI, — правило одно и записано
        // в одном месте. Разница только в моменте: там раньше, здесь наверняка.
        ratatosk_proto::reply::check(text)?;
        if self.store.message(&reply_to)?.is_none_or(|m| m.chat_id != chat) {
            return Err(ratatosk_proto::ReplyError::TargetMissing.into());
        }
        self.send_own_text(now_ms, chat, peer_ik, text.trim(), TextKind::Reply(reply_to))
    }

    /// Кладёт своё текстовое сообщение в историю и в очередь §5.4.
    ///
    /// Одно место на обычную отправку, пересылку и ответ: различаются они ровно
    /// тем, что задаёт [`TextKind`] — типом конверта, нагрузкой и пометкой
    /// в истории. Разведи их по трём функциям, и первое же изменение в порядке
    /// «сначала записать, потом отправить» пришлось бы вносить трижды.
    pub(super) fn send_own_text(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        peer_ik: [u8; 32],
        text: &str,
        kind: TextKind,
    ) -> Result<Vec<Effect>, EngineError> {
        // Отказ **до** записи в историю: сообщение, легшее в базу и не
        // собравшееся в кадр, человек видел бы у себя вечно ждущим отправки.
        if !ratatosk_proto::files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }
        let hlc = self.clock.now(now_ms)?;
        let msg_id = self.entropy.msg_id();
        let envelope = Envelope::new(msg_id, hlc, kind.payload_type(), kind.payload(text));
        let bytes = envelope.encode()?;

        // Своё сообщение кладётся в историю сразу: доставка может занять
        // сутки почтового круга (§5.3), а в чате оно должно быть видно уже.
        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Своё сообщение начинает с «ждёт отправки» и растёт оттуда.
            // У принятого статуса нет вовсе — там нечему расти.
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: kind.forwarded(),
            reply_to: kind.reply_to(),
        })?;

        self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: bytes,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: false,
        })
    }

    /// Кладёт принятый текст в историю и подтверждает приём.
    ///
    /// Одно место на обычное сообщение, пересланное и ответ: различаются они
    /// только пометками ([`TextKind`]), а разведённые по трём функциям однажды
    /// разошлись бы в чём-то большем — например, в том, отправлена ли
    /// квитанция.
    pub(super) fn on_incoming_text(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
        text: &str,
        kind: TextKind,
    ) -> Result<Vec<Effect>, EngineError> {
        let chat = Self::chat_id_for(&peer_ik);
        self.remember(&StoredMessage {
            msg_id: envelope.msg_id,
            chat_id: chat,
            sender_ik: peer_ik,
            hlc: envelope.hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // У принятого сообщения статуса нет: статус — это судьба
            // отправки, а оно уже здесь.
            status: None,
            edited_ms: None,
            forwarded: kind.forwarded(),
            reply_to: kind.reply_to(),
        })?;

        let mut effects =
            vec![Effect::Notify(Event::MessageReceived { chat, msg_id: envelope.msg_id })];
        // §9.4: квитанция о доставке — сразу и только прямым каналом.
        // «Доставлено» означает ровно то, что кадр принят и расшифрован,
        // и узнать это может только получатель.
        effects.extend(self.send_receipt(
            now_ms,
            peer_ik,
            via,
            Receipt::Delivered,
            &[envelope.msg_id],
        )?);
        Ok(effects)
    }

    /// Пришло пересланное сообщение.
    ///
    /// Отличается от обычного одной пометкой в истории — и тем, что пометка
    /// **обязательна**: без неё чужие слова выглядят словами собеседника.
    /// Автора здесь нет и быть не может: при пересылке подпись §6 не
    /// сохраняется, и указать его можно было бы только на словах.
    pub(super) fn on_forwarded(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let text = Self::text_of(envelope)?;
        self.on_incoming_text(now_ms, via, peer_ik, envelope, &text, TextKind::Forwarded)
    }

    /// Пришёл ответ на сообщение.
    ///
    /// Ссылка **мягкая**, и это существенно. Цели может не быть вовсе: ответ
    /// мог опередить исходное сообщение (§9.2 — приход не равен порядку) или
    /// пережить его удаление. Терять из-за этого текст нельзя: ответ — это
    /// слова человека, а цитата — только контекст к ним. Ссылка сохраняется
    /// как есть, а «сообщение недоступно» скажет UI.
    ///
    /// Отвергается один случай: ссылка на сообщение, которое у нас есть,
    /// но **в другом чате**. Назвать такой `msg_id` собеседник не мог бы,
    /// не зная того, чего ему знать неоткуда, — поэтому это аномалия сессии.
    /// Текст и здесь сохраняется, теряется только ссылка.
    pub(super) fn on_replied(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (target, text) = ratatosk_proto::reply::from_payload(&envelope.payload)?;
        let chat = Self::chat_id_for(&peer_ik);

        let kind = match self.store.message(&target)? {
            Some(known) if known.chat_id != chat => {
                self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
                TextKind::Plain
            }
            _ => TextKind::Reply(target),
        };
        self.on_incoming_text(now_ms, via, peer_ik, envelope, &text, kind)
    }

    /// Достаёт текст из конверта обычного или пересланного сообщения.
    pub(super) fn text_of(envelope: &Envelope) -> Result<String, EngineError> {
        let Value::Text(text) = &envelope.payload else {
            return Err(ratatosk_codec::CodecError::TypeMismatch.into());
        };
        Ok(text.clone())
    }
}
