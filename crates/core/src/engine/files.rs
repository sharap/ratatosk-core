//! Передача файлов (§10): предложение, согласие, окно чанков, сроки.
//!
//! Здесь живёт всё, что касается **байтов**: полосы ступеней, окно
//! одновременности, сроки молчания и возобновление после разрыва.
//! Разговор о файле — предложение, согласие, отказ — тоже здесь, потому
//! что от передачи он неотделим: согласие открывает окно.
//!
//! Чего здесь нет: рассылки предложения по группе (это `group_msg`)
//! и уборки осиротевших кусков (это `maintenance`).

use super::*;

impl<S: Store> Engine<S> {
    /// Пускает на освободившуюся ступень следующие передачи (§10.2).
    ///
    /// # Почему это один раз в конце шага, а не на месте
    ///
    /// Потому что разбуженная передача вправе завершиться в тот же миг —
    /// у пустого файла, у собранного перед самым перезапуском, у того,
    /// чей последний кусок уже лежит. Завершившись, она снова освобождает
    /// ту же ступень. Буди мы прямо в `finish_file`, глубину рекурсии
    /// задавала бы длина очереди файлов, а не наш код.
    ///
    /// Здесь же всё плоско: помеченные ступени забираются разом, каждая
    /// разбирается один раз, а то, что освободилось по ходу разбора,
    /// достанется следующему шагу. Шаг этот всегда есть: своей отправкой
    /// разбуженная передача его и породит.
    ///
    /// # Будятся только те, кого завернули
    ///
    /// Здесь стоял перебор всех незаконченных файлов, и это было кольцо.
    /// Просьба про файл уходит с признаком «начните сначала», и признак
    /// этот отматывает отправителю окно назад — к нашей первой дырке.
    /// Переспрашивая передачи, которые шли своим чередом, пробуждение
    /// заставляло слать заново уже отправленное; новые чанки приносили
    /// новые подтверждения, каждое подтверждение — новое пробуждение,
    /// и провод переставал сходиться (тесты на несколько вложений
    /// в одном сообщении упёрлись в предел шагов).
    ///
    /// Поэтому очередь ведётся поимённо: `file_queued` на приёме,
    /// `sending_queued` на отдаче. Завернули — вписали, разбудили —
    /// вычеркнули, завернули снова — вписали снова. Файл, идущий своим
    /// чередом, в этих списках не значится и трогать его незачем.
    ///
    /// # Обе стороны
    ///
    /// Сперва отдача, потом приём, и порядок тут не случаен. Отдача
    /// продолжается **молча** — получатель уже спросил, и досылать можно
    /// сразу. Приём же начинается с просьбы, то есть с кадра в эфир,
    /// и пускать его вперёд значило бы занять ступень новой передачей
    /// прежде, чем на ней доедет начатая.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn wake_queued_files(&mut self, now_ms: u64) -> Result<Vec<Effect>, EngineError> {
        if !std::mem::take(&mut self.lanes_freed) {
            return Ok(Vec::new());
        }
        let mut effects = Vec::new();

        // Отдача: чьи-то чанки ждут только того, чтобы их досылали.
        // Список забирается целиком — завёрнутые снова впишут себя сами.
        for (file_id, peer_ik) in std::mem::take(&mut self.sending_queued) {
            // Записи о передаче могло уже не стать: получатель отказался,
            // файл удалили. Тогда и досылать нечего.
            if !self.sending.iter().any(|s| s.file_id == file_id && s.peer_ik == peer_ik) {
                continue;
            }
            let Some(file) = self.store.file(&file_id)? else { continue };
            effects.extend(self.pump_file(now_ms, &file, peer_ik)?);
        }

        // Приём: те, кому мы ответили «ждёт очереди», и только они.
        for (file_id, _) in std::mem::take(&mut self.file_queued) {
            let Some(file) = self.store.file(&file_id)? else { continue };
            if file.complete || !file.incoming || !file.accepted {
                continue;
            }
            // «Начните сначала»: у отправителя об этой передаче ещё ничего
            // нет — мы её и не начинали.
            effects.extend(self.ask_for_file(now_ms, &file, true)?);
        }
        Ok(effects)
    }

    /// Убирает вложения сообщения: записи, байты и идущие передачи.
    ///
    /// Отказы проглатываются намеренно: удаление не должно останавливаться
    /// на первом же файле, который не удалось стереть. Оставшийся чанк —
    /// мусор на диске, а незавершённое удаление — сообщение, которое человек
    /// считает удалённым.
    pub(super) fn forget_files(&mut self, msg_id: &MsgId) {
        // **Отвязать, а потом убрать осиротевшее.** Раньше здесь стояло
        // «убрать все вложения этого сообщения», и это было верно ровно
        // до пересылки: с ней тот же файл принадлежит ещё и пересланной
        // копии, и удаление исходного унесло бы байты у неё из-под ног.
        //
        // Кто осиротел — считает хранилище: там же, где отвязывает, и это
        // не мелочь. Разведи два шага — и однажды посчитают до отвязки.
        let orphans = self.store.detach_files_of(msg_id).unwrap_or_default();
        for file_id in orphans {
            self.forget_file(&file_id);
        }
    }

    /// Убирает одно вложение: идущую передачу, срок молчания, байты и запись.
    ///
    /// Порядок значим ровно в одном месте: байты уходят раньше записи. Иначе
    /// запись исчезает первой, и чанки на диске остаются без всякого следа
    /// о том, чьи они, — подобрать их сможет только сверка каталога с базой
    /// ([`Engine::sweep_orphan_files`]).
    pub(super) fn forget_file(&mut self, file_id: &FileId) {
        self.drop_sending(|s| s.file_id == *file_id);
        self.file_timers.remove(file_id);
        self.file_attempts.remove(file_id);
        self.file_queued.retain(|(id, _)| id != file_id);
        self.sending_queued.retain(|(id, _)| id != file_id);
        self.leave_lane(file_id);
        let _ = self.blobs.remove(file_id);
        let _ = self.store.delete_file(file_id);
    }

    /// Отправляет файлы одним сообщением.
    ///
    /// Что происходит сразу: сообщение ложится в историю (с подписью, если она
    /// есть), для каждого файла заводится запись и уезжает **предложение** —
    /// имя, размер, ключ и превью. Байты не читаются вовсе: чанки пойдут
    /// потом, и только если получатель их попросит.
    ///
    /// Ключ у каждого файла свой и генерируется здесь. Это не мелочь:
    /// `ratatosk_crypto::file` шифрует чанк ключом, выведенным из
    /// `file_key ‖ index`, с нулевым nonce — и это безопасно ровно до тех пор,
    /// пока один и тот же `file_key` не использован дважды для разного
    /// содержимого. Повторная отправка того же файла — это новое предложение
    /// с новым ключом.
    pub(super) fn on_send_files(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        files: &[OutgoingFile],
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        // Группа — первой, как и у текста: у неё записи в `by_chat` нет,
        // а идентификаторы чатов у групп и у 1:1 живут в одном пространстве.
        if self.groups.contains_key(&chat) {
            return self.send_group_files(now_ms, chat, files, text);
        }
        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        let offers = self.prepare_offers(files, text)?;

        let msg_id = self.entropy.msg_id();
        let hlc = self.clock.now(now_ms)?;
        let own_ik = self.identity.public().ik;
        let records = Self::records_for(&offers, files, msg_id);

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: own_ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        for record in &records {
            self.store.put_file(record)?;
        }

        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::FileOffer,
            files::offer_payload(text, &offers, false),
        );
        let mut effects = self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: false,
        })?;

        // Само предложение уедет любой ступенью §5.4, а чанки — той, которую
        // выберет `file_channel`. Совпадают они не всегда: почтой едет и то
        // и другое, но большой файл почтой не поедет (§10.3), и собеседник
        // получит письмо с описанием файла, а самого файла не получит, пока
        // не появится в сети.
        //
        // Сказать об этом надо здесь и сразу, а не когда человек заметит,
        // что полоска стоит: §10.3 задаёт для этого случая свой текст,
        // и он существовал в коде с самого начала, ни разу никому
        // не показанный.
        //
        // Спрашивается **про каждый файл отдельно**: предел почты — про
        // размер, и в одном сообщении может уехать и фотография, которая
        // поедет почтой, и видео, которое будет ждать.
        for record in &records {
            if let Some(reason) = self.file_wait_reason(&peer_ik, record.size_bytes) {
                effects.push(Effect::Notify(Event::FileWaitsForChannel {
                    file_id: record.file_id,
                    reason,
                }));
            }
        }
        Ok(effects)
    }

    /// Человек согласился принять файл.
    pub(super) fn on_accept_file(
        &mut self,
        now_ms: u64,
        file_id: FileId,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming || file.complete {
            return Ok(Vec::new());
        }
        self.store.set_accepted(&file_id, true)?;
        // Первая просьба про файл — «начните сначала», то есть тот же случай,
        // что и возобновление: у отправителя об этой передаче ещё ничего нет.
        self.ask_for_file(now_ms, &file, true)
    }

    /// Десктоп просит место под выгрузку файла (§13.4).
    ///
    /// **Здесь и только здесь проверяется правило §13.4 про 20 МБ**, и оно
    /// не про предел, а про то, чей трафик. Файл больше двадцати мегабайт
    /// разрешён «только когда оба устройства в одной сети» — иначе выгрузка
    /// идёт через мобильный канал телефона, и платит за неё человек
    /// с телефоном, а решает — человек с ноутбука.
    ///
    /// Спрашивается это **до** передачи, а не после: сказать «слишком
    /// большой» после гигабайта по проводу — издевательство.
    ///
    /// # Errors
    ///
    /// Имя не годится, файл больше [`files::MAX_FILE_BYTES`], правило §13.4
    /// не пускает, или мест под выгрузки больше нет.
    pub(super) fn on_upload_offer(
        &mut self,
        now_ms: u64,
        via: Transport,
        chat: ChatId,
        name: &str,
        size_bytes: u64,
        preview: Option<Vec<u8>>,
    ) -> Result<companion::Response, EngineError> {
        use ratatosk_proto::files;

        // Чат — либо переписка, либо группа. Проверка стояла только по
        // `by_chat`, и выгрузка в группу отказывалась «контакт неизвестен»
        // на первом же шаге, не передав ни байта. Спрашивать надо про оба
        // пространства: идентификаторы у них общие, и «неизвестен» верно
        // только тогда, когда чата нет ни там, ни там.
        if !self.by_chat.contains_key(&chat) && !self.groups.contains_key(&chat) {
            return Err(EngineError::UnknownPeer);
        }
        files::check_name(name)?;
        if size_bytes > files::MAX_FILE_BYTES {
            return Err(files::FileError::TooLarge.into());
        }
        // Предел превью проверяется и здесь, хотя провод его уже проверил:
        // проверка провода — про кадр, эта — про запись в базе, и жить она
        // обязана там же, где такая же проверка для файла с телефона
        // (`on_send_files`). Один предел, два входа — и оба его знают.
        if let Some(preview) = &preview {
            if !files::preview_fits(preview.len()) {
                return Err(files::FileError::PreviewTooLarge.into());
            }
        }
        // «В одной сети» — это про канал, которым разговаривают **сейчас**,
        // а не про то, каким сопрягались: сессия LAN не продолжается через
        // onion (§5.4), и вопрос всегда о нынешнем.
        if !files::companion_may_upload(size_bytes, via == Transport::Lan) {
            return Ok(companion::Response::Refused(
                "файл больше 20 МБ уедет через мобильный канал телефона — \
                 подключитесь к общей сети (§13.4)"
                    .to_owned(),
            ));
        }
        if self.uploads.len() >= companion::MAX_UPLOADS {
            return Ok(companion::Response::Refused(
                "телефон уже принимает другие файлы — дождитесь конца".to_owned(),
            ));
        }

        let file_id = self.entropy.msg_id();
        let mut key = [0u8; 32];
        self.entropy.fill(&mut key);
        let chunk_bytes = self.chunk_bytes_now();
        let chunk_total = files::chunk_count(size_bytes, chunk_bytes);
        // Число едет с выгрузкой на диск и в память: перезапуск телефона
        // посреди неё не должен менять нарезку, о которой уже договорились.
        let chunk_bytes = u32::try_from(chunk_bytes).unwrap_or(u32::MAX);
        // **На диск, а не только в память.** Перезапуск телефона посреди
        // выгрузки стирал её целиком; с пятью файлами это потеря четырёх
        // выгруженных ради пятого (`ARCHITECTURE.md`, 5вб).
        self.store.put_staged(&ratatosk_store::StagedUpload {
            file_id,
            chat_id: chat,
            name: name.to_owned(),
            size_bytes,
            chunk_total,
            chunk_bytes,
            key,
            preview: preview.clone(),
            started_ms: now_ms,
        })?;
        self.uploads.push(Upload {
            file_id,
            chat,
            name: name.to_owned(),
            size_bytes,
            chunk_total,
            chunk_bytes,
            key,
            preview,
            have: BTreeSet::new(),
        });
        // Нарезка едет вслух: её же телефон потом и спросит с каждого
        // куска, а вывести её из размера десктоп не может.
        Ok(companion::Response::FileOffer {
            file_id,
            chunk_total,
            chunk_bytes: u64::from(chunk_bytes),
        })
    }

    /// Приехал кусок выгружаемого файла.
    ///
    /// **Кладётся запечатанным тем же ключом, каким уедет собеседнику.**
    /// Открытым текстом на диск телефона он лечь не может: этот файл человек
    /// туда не клал, и оставлять его там в открытом виде — новая утечка,
    /// которой у отправляемого с самого телефона нет (тот и так лежит
    /// открытым там, куда его положил хозяин).
    ///
    /// Запечатывание детерминированное (nonce выводится, §10.1), поэтому
    /// отправка потом берёт эти же байты как есть — расшифровывать
    /// и запечатывать заново незачем.
    ///
    /// # Errors
    ///
    /// Выгрузки нет, номер за концом, кусок не той длины или отказ хранилища.
    pub(super) fn on_upload_put(
        &mut self,
        file_id: FileId,
        index: u64,
        bytes: &[u8],
    ) -> Result<companion::Response, EngineError> {
        let Some(upload) = self.uploads.iter().find(|u| u.file_id == file_id) else {
            return Ok(companion::Response::Refused(
                "про этот файл телефон не договаривался".to_owned(),
            ));
        };
        if index >= upload.chunk_total {
            return Ok(companion::Response::Refused("кусок за концом файла".to_owned()));
        }
        // Длина куска задана размером файла, и проверить её обязан тот, кто
        // размер объявлял. Иначе «файл на гигабайт» приехал бы гигабайтом
        // в одном куске и мегабайтом в остальных.
        // Размером **этого** файла, а не своим умолчанием: нарезка у него
        // своя (§10.2), и мерить чужим числом значило бы отвергнуть
        // законный кусок. Число записано при `FileOffer` и лежит рядом —
        // выводить его из размера и числа кусков больше не нужно.
        let chunk = upload.chunk_bytes as usize;
        let last = index + 1 == upload.chunk_total;
        let expected = if last {
            let tail = upload.size_bytes % chunk as u64;
            if tail == 0 && upload.size_bytes != 0 {
                chunk
            } else {
                usize::try_from(tail).unwrap_or(chunk)
            }
        } else {
            chunk
        };
        if bytes.len() != expected {
            return Ok(companion::Response::Refused(
                "кусок не той длины, какую обещал размер файла".to_owned(),
            ));
        }

        let sealed = ratatosk_crypto::file::seal_chunk(&upload.key, &file_id, index, bytes)?;
        self.blobs.put_chunk(&file_id, index, &sealed)?;
        // Отметка на диске **после** байтов: обратный порядок означал бы
        // «кусок есть», когда его нет, и выгрузка объявилась бы собранной
        // с дырой. Тот же порядок, что у принимаемых чанков.
        self.store.note_staged_chunk(&file_id, index)?;
        if let Some(upload) = self.uploads.iter_mut().find(|u| u.file_id == file_id) {
            upload.have.insert(index);
        }
        Ok(companion::Response::Done)
    }

    /// Выгрузка закончена — заводим сообщение и отправляем.
    ///
    /// Недостача — отказ словами, и **до** появления сообщения: файл с дырой,
    /// уехавший собеседнику, тот соберёт и не проверит (хэш считается от
    /// целого), а человек увидит «отправлено».
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки сообщения.
    pub(super) fn on_upload_send(
        &mut self,
        now_ms: u64,
        file_ids: &[FileId],
        text: &str,
    ) -> Result<(companion::Response, Vec<Effect>), EngineError> {
        // **Сперва проверяется всё, потом делается всё.** Половина сообщения
        // — вложения из одной выгрузки при недостаче в другой — это ровно
        // тот исход, которого §14 не разрешает: человек увидит «отправлено»
        // и не узнает, что уехало не то, что он выбрал.
        let mut at = Vec::with_capacity(file_ids.len());
        let mut chat = None;
        for file_id in file_ids {
            let Some(found) = self.uploads.iter().position(|u| u.file_id == *file_id) else {
                return Ok((
                    companion::Response::Refused(
                        "про этот файл телефон не договаривался".to_owned(),
                    ),
                    Vec::new(),
                ));
            };
            // Один и тот же файл, названный дважды, — это не два вложения,
            // а одно; вторая позиция указывала бы на уже вынутую выгрузку.
            if at.contains(&found) {
                return Ok((
                    companion::Response::Refused("один и тот же файл назван дважды".to_owned()),
                    Vec::new(),
                ));
            }
            let missing = self.uploads[found].chunk_total - self.uploads[found].have.len() as u64;
            if missing != 0 {
                return Ok((
                    companion::Response::Refused(format!(
                        "не хватает {missing} кусков — отправлять файл с дырой нельзя"
                    )),
                    Vec::new(),
                ));
            }
            // Сообщение одно, значит и чат один. Иначе половина вложений
            // уехала бы не тому человеку — и это худшая из ошибок,
            // какие тут возможны.
            match chat {
                None => chat = Some(self.uploads[found].chat),
                Some(first) if first != self.uploads[found].chat => {
                    return Ok((
                        companion::Response::Refused(
                            "вложения из разных чатов в одно сообщение не складываются".to_owned(),
                        ),
                        Vec::new(),
                    ));
                }
                Some(_) => {}
            }
            at.push(found);
        }

        // Вынимаются по одному с поиском заново: `remove` сдвигает индексы,
        // и запомненные позиции после первого же удаления врут. Порядок
        // сохраняется тот, в каком их назвал десктоп.
        let mut taken = Vec::with_capacity(file_ids.len());
        for file_id in file_ids {
            let Some(found) = self.uploads.iter().position(|u| u.file_id == *file_id) else {
                // Сюда попасть нельзя — список только что проверен целиком.
                // Но вернуть выгрузки на место дешевле, чем паниковать
                // в ядре, которое держит переписку.
                self.uploads.append(&mut taken);
                return Ok((
                    companion::Response::Refused("выгрузка пропала на полпути".to_owned()),
                    Vec::new(),
                ));
            };
            taken.push(self.uploads.remove(found));
            // Отметка с диска уходит вместе с выгрузкой: дальше эти байты
            // живут строкой в `files`, и вторая запись о них означала бы,
            // что уборка сирот однажды сотрёт отправленный файл.
            self.store.delete_staged(file_id)?;
        }

        let effects = self.send_uploaded(now_ms, taken, text)?;
        Ok((companion::Response::Done, effects))
    }

    /// Десктоп передумал: выбросить выгруженное.
    ///
    /// # Errors
    ///
    /// Отказ хранилища байтов.
    pub(super) fn on_upload_abort(
        &mut self,
        file_id: FileId,
    ) -> Result<companion::Response, EngineError> {
        let Some(at) = self.uploads.iter().position(|u| u.file_id == file_id) else {
            return Ok(companion::Response::Done);
        };
        self.uploads.remove(at);
        self.store.delete_staged(&file_id)?;
        self.blobs.remove(&file_id)?;
        Ok(companion::Response::Done)
    }

    /// Заводит сообщение с выгруженным файлом и отправляет предложение.
    ///
    /// Это `on_send_files` для файла, которого нет на диске телефона:
    /// байты уже лежат в хранилище **запечатанными**, и `source_path`
    /// у записи пустой. Всё остальное — то же самое, и намеренно: получатель
    /// не должен и не может отличить файл, отправленный с телефона,
    /// от выгруженного с ноутбука.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки конверта.
    pub(super) fn send_uploaded(
        &mut self,
        now_ms: u64,
        uploads: Vec<Upload>,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let Some(first) = uploads.first() else {
            return Err(EngineError::UnknownPeer);
        };
        let chat = first.chat;

        let chunk_bytes = self.chunk_bytes_now();
        let offers: Vec<files::FileOffer> = uploads
            .iter()
            .map(|upload| files::FileOffer {
                chunk_bytes,
                file_id: upload.file_id,
                name: upload.name.clone(),
                size_bytes: upload.size_bytes,
                key: upload.key,
                // Превью с десктопа приезжает в первой просьбе выгрузки
                // и дальше едет собеседнику наравне с превью своего файла:
                // §10.3 отдаёт его вместе с предложением, а собирает его тот,
                // кто видит содержимое, — то есть клиент, на обоих устройствах.
                preview: upload.preview.clone(),
            })
            .collect();
        // Проверяются **все** сразу: и каждое по отдельности, и их число.
        // Тот же вход, что у файлов с самого телефона, — правило одно
        // и живёт в одном месте.
        files::check_offers(&offers).map_err(EngineError::File)?;

        // **Группа — первой, как и у файлов с самого телефона.** Записи
        // в `by_chat` у неё нет, а идентификаторы чатов у групп и у 1:1
        // живут в одном пространстве, и без этой ветки поиск собеседника
        // отвечал «контакт неизвестен» на совершенно законную просьбу.
        //
        // Ветка была у `on_send_files` и не была здесь: путь выгрузки
        // с десктопа писался, когда групп ещё не было, а когда они
        // появились — правился тот файл, который про группы, а не этот.
        if self.groups.contains_key(&chat) {
            return self.send_uploaded_to_group(now_ms, chat, uploads, offers, text);
        }

        let peer_ik = *self.by_chat.get(&chat).ok_or(EngineError::UnknownPeer)?;
        let msg_id = self.entropy.msg_id();
        let hlc = self.clock.now(now_ms)?;
        let own_ik = self.identity.public().ik;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: own_ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            status: Some(DeliveryStatus::Pending.code()),
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        self.store_uploads(msg_id, uploads)?;

        let envelope = Envelope::new(
            msg_id,
            hlc,
            PayloadType::FileOffer,
            files::offer_payload(text, &offers, false),
        );
        let mut effects = self.enqueue(Delivery {
            msg_id,
            peer_ik,
            envelope: envelope.encode()?,
            attempt: Attempt::new(),
            state: DeliveryState::AwaitingSession,
            queued_ms: now_ms,
            session_reset_used: false,
            redial_used: false,
            silent: false,
        })?;
        // Предупреждение одно на сообщение — по первому файлу, которому
        // не хватило канала. Второе про то же самое ничего не добавляет:
        // ждать всё равно одного и того же — появления собеседника.
        for offer in &offers {
            if let Some(reason) = self.file_wait_reason(&peer_ik, offer.size_bytes) {
                effects.push(Effect::Notify(Event::FileWaitsForChannel {
                    file_id: offer.file_id,
                    reason,
                }));
                break;
            }
        }
        Ok(effects)
    }

    /// То же самое, но в группу (§11.3).
    ///
    /// Отличие от [`Engine::send_group_files`] ровно одно и то же, что
    /// у 1:1: байты уже лежат в хранилище запечатанными, и записи о файлах
    /// заводятся с пустым `source_path`. Всё остальное — общее с файлами
    /// с самого телефона, и намеренно: участник не должен и не может
    /// отличить файл, отправленный с телефона, от выгруженного с ноутбука.
    ///
    /// # Errors
    ///
    /// Отказ хранилища или сборки группового кадра — цепочки может не быть,
    /// нас могли исключить.
    pub(super) fn send_uploaded_to_group(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        uploads: Vec<Upload>,
        offers: Vec<ratatosk_proto::files::FileOffer>,
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let action = ratatosk_proto::group_action::Action::Files {
            caption: text.to_owned(),
            offers: offers.clone(),
            forwarded: false,
        };
        // Кадр собирается до записи в базу — тот же порядок и тот же довод,
        // что в `send_group_files`: сборка вправе отказать, а записи о файлах,
        // оставшиеся после отказа, человек видел бы вечно отправляющимися.
        let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Статуса нет, как и у всякой групповой копии: один значок
            // на тридцать двух получателей §14 не разрешает.
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        self.store_uploads(msg_id, uploads)?;

        let mut effects = self.spread_in_chat(now_ms, chat, msg_id, &bytes)?;
        // §10.3 про каждый файл отдельно, а про участников — «есть ли хоть
        // один, кому сейчас не увезти»: событие несёт только `file_id`,
        // имени получателя в нём нет. Слово в слово как в `send_group_files`,
        // и разойтись эти два места не вправе.
        let me = self.identity.public().ik;
        let members: Vec<[u8; 32]> = match self.groups.get(&chat) {
            Some(state) => state.group.recipients(&me),
            None => Vec::new(),
        };
        for offer in &offers {
            let reason = members.iter().find_map(|m| self.file_wait_reason(m, offer.size_bytes));
            if let Some(reason) = reason {
                effects.push(Effect::Notify(Event::FileWaitsForChannel {
                    file_id: offer.file_id,
                    reason,
                }));
            }
        }
        Ok(effects)
    }

    /// Заводит записи о выгруженных с десктопа файлах.
    ///
    /// Одно место на 1:1 и на группу — по тому же правилу, что у
    /// [`Engine::record_offers`] на приёме: разойдись они, вложение
    /// в группе вело бы себя не так, как в переписке.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn store_uploads(
        &mut self,
        msg_id: MsgId,
        uploads: Vec<Upload>,
    ) -> Result<(), EngineError> {
        for (at, upload) in uploads.into_iter().enumerate() {
            self.store.put_file(&StoredFile {
                file_id: upload.file_id,
                msg_id,
                name: upload.name,
                size_bytes: upload.size_bytes,
                // Порядок, в каком их назвал десктоп, — то есть тот,
                // в каком человек выбрал файлы.
                ordinal: u32::try_from(at).unwrap_or(u32::MAX),
                chunk_total: upload.chunk_total,
                // Нарезка, о которой договорились на `FileOffer`, а не
                // нынешняя ступень: куски уже лежат нарезанные ею.
                chunk_bytes: upload.chunk_bytes,
                key: upload.key,
                preview: upload.preview,
                // Не входящий: качать его не надо, он уже здесь.
                incoming: false,
                // **Пусто, и это признак «байты в хранилище, а не на диске».**
                // Отправка читает по нему: есть путь — читаем открытый файл
                // хозяина, нет — берём запечатанный кусок как есть. Работает
                // это одинаково для 1:1 и для группы: кусок берётся по записи
                // файла, а кому его отдают — вопрос отдельный.
                source_path: None,
                accepted: true,
                complete: true,
            })?;
        }
        Ok(())
    }

    /// Человек передумал качать — но не передумал получать.
    ///
    /// **Отличие от отказа в том, что остаётся.** Отказ уносит и байты,
    /// и запись: «этого файла у меня не будет». Здесь снимается только
    /// согласие — приехавшие куски лежат, предложение живёт, и согласие,
    /// поставленное заново, продолжает с той же дырки (§10.2).
    ///
    /// Это не украшение для медленной сети, а единственный честный ответ
    /// на «не сейчас». Без него у человека на мобильном канале два выхода:
    /// доплатить за гигабайт или потерять файл насовсем.
    ///
    /// Собеседнику не уходит ничего — по той же причине, что и при отказе:
    /// он увидит, что чанки перестали просить, и это всё, что ему полагается
    /// знать. Сроки молчания при этом снимаются: иначе через полчаса ядро
    /// само спросило бы продолжение того, что человек остановил.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn on_pause_file(&mut self, file_id: FileId) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming || file.complete {
            return Ok(Vec::new());
        }
        self.store.set_accepted(&file_id, false)?;
        self.file_timers.remove(&file_id);
        self.file_attempts.remove(&file_id);
        // Место на ступени отдаётся сразу: приостановленный файл её больше
        // не занимает, и держать её за ним значило бы наказать очередь
        // за чужое решение. Из очереди он тоже уходит: человек сказал
        // «не сейчас», и будить его нечего.
        self.file_queued.retain(|(id, _)| *id != file_id);
        self.leave_lane(&file_id);
        let received = self.store.received_chunks(&file_id)?;
        Ok(vec![Effect::Notify(Event::FileProgress { file_id, received, total: file.chunk_total })])
    }

    /// Человек отказался от файла.
    ///
    /// Собеседнику не уходит ничего: отказ — решение о своей памяти, а не
    /// сообщение о себе. Он увидит, что чанки перестали запрашивать, и это
    /// всё, что ему полагается знать.
    pub(super) fn on_decline_file(&mut self, file_id: FileId) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if !file.incoming {
            return Ok(Vec::new());
        }
        // Сперва байты, потом запись: обратный порядок оставил бы чанки
        // на диске без всякого следа о том, чьи они.
        self.blobs.remove(&file_id)?;
        self.store.delete_file(&file_id)?;
        // Своим событием, а не `FileProgress` с нулями: «строки больше нет»
        // и «полоска сдвинулась» — разные новости, и числом первую сказать
        // нельзя. Нулями это и говорилось, и обошлось в две ошибки сразу —
        // см. `Event::FileGone`.
        Ok(vec![Effect::Notify(Event::FileGone { file_id })])
    }

    /// Кто прислал предложение этого файла.
    ///
    /// **Одно место на три вопроса**, и все три про одно: у кого просить
    /// чанки, от кого их принимать и чью незаконченную передачу возобновлять
    /// при появлении собеседника. Раньше на все три отвечал чат, выведенный
    /// из ключа (`chat_id_for`), — и в группе не отвечал ни на один: там
    /// идентификатор чата из ключа не выводится вовсе.
    ///
    /// Ответ здесь строже прежнего и верен для обоих случаев: чанки есть
    /// только у того, кто прислал предложение, потому что пересылки в v1
    /// нет (§11.3). В переписке двоих это тот же самый собеседник, так что
    /// для 1:1 ничего не меняется.
    ///
    /// `None` — сообщения нет: копию удалили раньше, чем доехало вложение.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn offerer_of(&self, file: &StoredFile) -> Result<Option<[u8; 32]>, EngineError> {
        // Сообщение здесь — **самое раннее** из тех, к которым файл приложен
        // (`Store::file`), и это ровно то, что нужно: чанки есть у того, кто
        // предложил файл первым. Пересланная копия его не заводит и байтов
        // не добавляет, так что спрашивать надо у первоисточника.
        Ok(self.store.message(&file.msg_id)?.map(|m| m.sender_ik))
    }

    /// Просит собеседника продолжить (или начать) передачу файла.
    ///
    /// Просьба уходит тем же каналом, каким поедут чанки, — его выбирает
    /// [`Engine::file_channel`], и почта оттуда больше не исключена. Нет
    /// канала — нет и просьбы: собеседник появится, сессия установится,
    /// и мы спросим снова.
    ///
    /// # Тесный свой ящик останавливает приём почтой
    ///
    /// Просит — получатель, и открытое окно ляжет в **его** ящик. Места
    /// меньше, чем на окно (`MailLimits::crowded`), — значит часть писем
    /// сервер не примет, а отправитель получит отказ, которого не поймёт
    /// ни он, ни мы. Честнее не просить и сказать человеку, что файл ждёт
    /// (§14).
    ///
    /// Проверка стоит **здесь**, а не в [`Engine::file_channel`], и это
    /// не мелочь. Свой полный ящик мешает принимать и не мешает отправлять:
    /// исходящие письма в нашем ящике не лежат. Поставь её в общий выбор
    /// канала — и человек с забитым ящиком перестал бы отправлять файлы
    /// по причине, которая к отправке отношения не имеет.
    pub(super) fn ask_for_file(
        &mut self,
        now_ms: u64,
        file: &StoredFile,
        stalled: bool,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(peer_ik) = self.source_for(file)? else { return Ok(Vec::new()) };
        if peer_ik == self.identity.public().ik {
            // Своё же вложение. Сюда не приходят — просят только за
            // входящим, — но правило дешевле привычки: просьба к самому
            // себе ушла бы в очередь и не вернулась бы никогда.
            return Ok(Vec::new());
        }
        let next = self.store.next_missing_chunk(&file.file_id, file.chunk_total)?;
        let Some(next) = next else {
            // Просить нечего — всё на месте. Такое бывает у пустого файла
            // и у передачи, которая закончилась ровно перед перезапуском.
            return self.finish_file(now_ms, file);
        };
        let via = match self.file_route_of(&peer_ik, file.size_bytes) {
            FileRoute::Ready(via) => via,
            // **Дорога есть, сессии нет — просим рукопожатие.**
            //
            // Раньше здесь стояло только «ждём», а в расчёте было на то,
            // что сессию построит кто-то другой. Оно и построит — но лишь
            // если человек что-нибудь **напишет**: очередь доставки (§5.4)
            // сама зовёт `ensure_handshake`, а приём файла не звал никого.
            // Отсюда поломка, которая ни на что не похожа: сообщения ходят,
            // файлы стоят, и «чинится» это первым же отправленным словом.
            //
            // Срок молчания при этом не заводится, и это не забывчивость:
            // сессия, когда появится, сама позовёт `resume_files` — оба
            // места установки сессии это делают. Заведи мы здесь ещё
            // и таймер, он взводил бы сам себя, пока собеседника нет.
            FileRoute::Handshake(route) => {
                // **Ступень отдаётся, раз ехать всё равно не на чем.**
                // Иначе файл, чей собеседник ушёл на час, держал бы место
                // в очереди весь этот час — и ничем бы его не занимал.
                self.leave_lane(&file.file_id);
                let mut effects = vec![Effect::Notify(Event::FileWaitsForChannel {
                    file_id: file.file_id,
                    reason: FileWait::Handshaking,
                })];
                let (started, _) = self.ensure_handshake(peer_ik, route)?;
                effects.extend(started);
                return Ok(effects);
            }
            FileRoute::TooBig => {
                self.leave_lane(&file.file_id);
                return Ok(vec![Effect::Notify(Event::FileWaitsForChannel {
                    file_id: file.file_id,
                    reason: FileWait::TooBig,
                })]);
            }
            FileRoute::Nowhere => {
                self.leave_lane(&file.file_id);
                return Ok(vec![Effect::Notify(Event::FileWaitsForChannel {
                    file_id: file.file_id,
                    reason: FileWait::Nowhere,
                })]);
            }
        };
        if via == Transport::Mail && self.mail_limits.crowded() {
            // Свой ящик кончается. Просить чанки некуда — они в него
            // и лягут. Срок молчания при этом не заводится: спрашивать
            // заново каждые полчаса в полный ящик бессмысленно, а
            // возобновит передачу либо освободившееся место (квота
            // приезжает после каждой разборки ящика), либо появление
            // прямого канала.
            //
            // И вот это — единственный случай, в котором человек может
            // что-то сделать. Пока причина не ехала, ему говорили «ждёт
            // канала», то есть «сиди и жди», — §14 такого не разрешает.
            // И здесь тоже: чанкам некуда лечь — значит ступень свободна
            // для того, кому есть куда.
            self.leave_lane(&file.file_id);
            return Ok(vec![Effect::Notify(Event::FileWaitsForChannel {
                file_id: file.file_id,
                reason: FileWait::MailboxFull,
            })]);
        }

        // **Калитка одновременных загрузок (§10.2), и она здесь одна
        // на всё.** Просит всегда получатель — значит не спросили, и
        // отправитель окна не открыл: обе стороны сдержаны одним условием
        // в одном месте.
        //
        // Срок молчания при этом **не заводится**, и это то же правило,
        // что у полного ящика выше: ждать нечего, пока не освободится
        // ступень, а разбудит очередь `wake_queued_files` — сразу, как
        // только предыдущая передача сойдёт с неё.
        if !self.lane_has_room(&file.file_id, via) {
            // Записываемся в очередь **поимённо**. Пробуждение пойдёт
            // по этому списку и только по нему: перебирать все
            // незаконченные файлы значило бы переспрашивать и те, что идут
            // своим чередом, — а просьба с признаком «начните сначала»
            // отматывает отправителю окно назад.
            // **Встали в очередь — торопим того, кто ступень держит.**
            // Без этого ждать пришлось бы весь его разросшийся срок:
            // отступление считает, как часто спрашивать замолчавшего,
            // а не как долго не пускать к ступени других.
            let mut effects = if self.enqueue_file(file.file_id, via) {
                self.hurry_lane_holders(via)
            } else {
                Vec::new()
            };
            effects.push(Effect::Notify(Event::FileWaitsForChannel {
                file_id: file.file_id,
                reason: FileWait::Queued,
            }));
            return Ok(effects);
        }

        let mut effects = self.send_file_frame(
            now_ms,
            peer_ik,
            via,
            PayloadType::FileRequest,
            ratatosk_proto::files::request_payload(file.file_id, next, stalled),
        )?;
        // Место на ступени занимается **ушедшей просьбой**, а не согласием
        // человека: до просьбы канал ничем не занят, и держать за файлом
        // место всё то время, пока собеседника нет, значило бы отдать
        // ступень тому, кто ею не пользуется.
        self.file_lane.insert(file.file_id, via);
        self.file_queued.retain(|(id, _)| *id != file.file_id);
        effects.extend(self.watch_for_stall(file.file_id, via));
        Ok(effects)
    }

    /// Ставит файл в хвост очереди ожидания, если его там ещё нет.
    ///
    /// Повторной записи быть не должно: просьба про один файл уходит много
    /// раз, и каждый отказ добавлял бы его в очередь заново — она росла бы
    /// на каждом подтверждении, а место доставалось бы тому, кого завернули
    /// чаще, а не тому, кто ждёт дольше.
    pub(super) fn enqueue_file(&mut self, file_id: FileId, via: Transport) -> bool {
        if self.file_queued.iter().any(|(id, _)| *id == file_id) {
            return false;
        }
        self.file_queued.push((file_id, via));
        true
    }

    /// Ждёт ли очереди на **этой** ступени кто-нибудь, кроме названного.
    pub(super) fn someone_waits_for_rung(&self, via: Transport, except: FileId) -> bool {
        self.file_queued.iter().any(|(id, lane)| *lane == via && *id != except)
    }

    /// Укорачивает срок молчания тем, кто прямо сейчас держит эту ступень.
    ///
    /// **Зовётся в тот миг, когда кто-то встал в очередь**, и лечит вот
    /// что. Срок держащего взведён давно и, если тот молчит не первый
    /// раз, взведён надолго: отступление удваивает его до двенадцати
    /// часов. Ждущий об этом узнать не может, и ждал бы он ровно столько,
    /// сколько мертвецу осталось досидеть.
    ///
    /// Трогаются только те, у кого отступление уже началось (`attempt`
    /// больше нуля). У идущей своим чередом передачи срок и так короткий,
    /// и обновляет его каждый чанк.
    ///
    /// Прежняя метка не снимается, а забывается — отменить таймер драйверу
    /// нечем; сработав, она не найдёт себя в `file_timers` и ничего
    /// не сделает. Это то же правило, что и у [`Engine::watch_for_stall`].
    pub(super) fn hurry_lane_holders(&mut self, via: Transport) -> Vec<Effect> {
        let holders: Vec<FileId> = self
            .file_lane
            .iter()
            .filter(|(_, lane)| **lane == via)
            .map(|(file_id, _)| *file_id)
            .filter(|file_id| self.file_attempts.get(file_id).is_some_and(|tries| *tries > 0))
            .collect();
        let mut effects = Vec::new();
        for file_id in holders {
            let token = self.allocate_timer();
            self.file_timers.insert(file_id, token);
            tracing::info!(?via, "ступени ждут — укорачиваем срок тому, кто её держит");
            effects
                .push(Effect::SetTimer { after_ms: ratatosk_proto::files::stall_ms(via), token });
        }
        effects
    }

    /// Есть ли на ступени место под ещё одну входящую передачу (§10.2).
    ///
    /// Файл, уже занимающий эту ступень, place не отнимает у себя самого:
    /// просьба про него уходит на каждое подтверждение, и считай мы её
    /// заново, передача с пределом в одну остановилась бы после первого
    /// же окна.
    pub(super) fn lane_has_room(&self, file_id: &FileId, via: Transport) -> bool {
        if self.file_lane.get(file_id) == Some(&via) {
            return true;
        }
        let busy = self.file_lane.values().filter(|lane| **lane == via).count();
        busy < ratatosk_proto::files::parallel_files(via)
    }

    /// Снимает файл со ступени и отмечает, что там освободилось место.
    ///
    /// Одно место на все исходы передачи — собрался, отклонён,
    /// приостановлен, удалён, — потому что забыть его в одном из четырёх
    /// значит потерять слот навсегда: ступень числилась бы занятой файлом,
    /// которого больше нет, и следующая загрузка не начиналась бы никогда.
    pub(super) fn leave_lane(&mut self, file_id: &FileId) {
        if self.file_lane.remove(file_id).is_some() {
            self.lanes_freed = true;
        }
    }

    /// Ставит срок молчания по файлу.
    ///
    /// Без него оборванная передача не возобновится никогда: отправитель ждёт
    /// подтверждения, получатель ждёт чанков, и оба правы. Срок сторожит
    /// получатель — у него есть всё, чтобы спросить заново.
    ///
    /// Срок растёт с каждой безответной попыткой подряд
    /// (`files::stall_backoff_ms`), и нужно это почте. Без отступления
    /// брошенная почтовая передача спрашивала бы письмом каждые полчаса
    /// вечно: сорок восемь писем в сутки, каждое со своим следом
    /// у chatmail-сервера и своим куском чужой квоты. Счётчик обнуляет
    /// приход любого чанка — движение файла, а не удачно ушедшая просьба.
    pub(super) fn watch_for_stall(&mut self, file_id: FileId, via: Transport) -> Vec<Effect> {
        let token = self.allocate_timer();
        // Прежняя метка забывается, а не снимается: отменить уже поставленный
        // таймер драйверу нечем, но сработавшая метка, которой здесь больше
        // нет, ничего не делает. Живой срок у файла всегда один.
        self.file_timers.insert(file_id, token);
        let attempt = self.file_attempts.get(&file_id).copied().unwrap_or(0);
        // **Пока этой ступени ждут, отступления нет.** Удваивать срок
        // осмысленно, когда он стоит одних наших просьб; когда он стоит
        // чужой очереди, платит за него не тот, кто молчит. Поэтому
        // отступление считает, **как часто спрашивать**, а держать
        // ступень дольше базового срока оно не даёт.
        let after_ms = if self.someone_waits_for_rung(via, file_id) {
            ratatosk_proto::files::stall_ms(via)
        } else {
            ratatosk_proto::files::stall_backoff_ms(via, attempt)
        };
        vec![Effect::SetTimer { after_ms, token }]
    }

    /// Отправляет служебный кадр файла — просьбу или чанк.
    ///
    /// Мимо очереди §5.4, и это не нарушение, а её признание: очередь
    /// обслуживает **сообщения**, у которых есть статус, квитанция и место
    /// в истории. У чанка нет ничего из этого — его подтверждает следующая
    /// просьба, а не квитанция, и ставить тысячи чанков в очередь доставки
    /// значит забить её тем, чему там не место.
    pub(super) fn send_file_frame(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
        payload_type: PayloadType,
        payload: Value,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(session_id) = self.sessions.for_peer(&peer_ik, via) else {
            return Ok(Vec::new());
        };
        let envelope =
            Envelope::new(self.entropy.msg_id(), self.clock.now(now_ms)?, payload_type, payload);
        let frames = self.seal_for(session_id, via, &envelope.encode()?)?;
        Ok(Self::sends(peer_ik, via, frames))
    }

    /// Проверяет вложения и готовит предложения (§10.1).
    ///
    /// Одно место на 1:1 и на группу: пределы числа файлов, длины имени,
    /// размера и превью — те же, и разойдись они, в группе стало бы можно
    /// послать то, чего нельзя в переписке двоих.
    ///
    /// **Сперва собирается всё, потом пишется в базу.** Отказ на третьем
    /// файле не должен оставлять в истории сообщение с двумя вложениями,
    /// которых никто не просил, — поэтому проверки и генерация ключей
    /// живут здесь, до первой записи.
    ///
    /// Ключ у каждого файла свой и случайный. Это не мелочь: чанк
    /// шифруется ключом, выведенным из `file_key ‖ index`, с нулевым
    /// nonce (§10.1), и это безопасно ровно до тех пор, пока один ключ
    /// не использован дважды для разного содержимого. Повторная отправка
    /// того же файла — новое предложение с новым ключом.
    ///
    /// # Errors
    ///
    /// [`ratatosk_proto::files::FileError`] на любом из пределов;
    /// [`EngineError::TextTooLong`] на подписи.
    /// Каким чанком резать файл, который мы предлагаем прямо сейчас.
    ///
    /// # Спрашивается «включён», а не «слышен», и это нарочно
    ///
    /// Размер пинуется в предложении навсегда (§10.2), а ступень выберет
    /// §5.4 — потом, и не раз. Значит размер обязан годиться для **худшей
    /// ступени, на которую файл может попасть**, а не для той, которая
    /// выглядит вероятной сейчас. Слышен ли собеседник в эфире в эту
    /// секунду, ничего не говорит о том, куда передача свалится через
    /// минуту.
    ///
    /// Поэтому правило грубое и намеренно осторожное: **эфир включён —
    /// режем мелко**. Мелкий чанк проходит везде, просто большими файлами
    /// и большим числом кругов; крупный по эфиру не проходит вовсе, и файл
    /// не доезжает совсем.
    ///
    /// Цена названа честно: пока Bluetooth включён, мелко режутся и файлы,
    /// уходящие по локальной сети. Пропускная способность от этого
    /// не страдает — окно считается в байтах (§10.2), — платим накладными
    /// расходами конверта на чанк.
    pub(super) fn chunk_bytes_now(&self) -> usize {
        if self.enabled.contains(Transport::Bt) {
            ratatosk_proto::files::AIR_CHUNK_BYTES
        } else {
            ratatosk_proto::files::CHUNK_BYTES
        }
    }

    pub(super) fn prepare_offers(
        &mut self,
        files: &[OutgoingFile],
        text: &str,
    ) -> Result<Vec<ratatosk_proto::files::FileOffer>, EngineError> {
        use ratatosk_proto::files;

        let chunk_bytes = self.chunk_bytes_now();

        if files.is_empty() || files.len() > files::MAX_FILES_PER_MESSAGE {
            return Err(files::FileError::TooMany.into());
        }
        // Подпись считается тем же пределом, что и текст без вложений:
        // предел один на оба случая, и выведен он как раз из худшего —
        // десять вложений с превью плюс текст в одном кадре.
        if !files::text_fits(text.len()) {
            return Err(EngineError::TextTooLong);
        }

        let mut offers = Vec::with_capacity(files.len());
        for file in files {
            let size_bytes = self.blobs.size_of(&file.path)?;
            if size_bytes > files::MAX_FILE_BYTES {
                return Err(files::FileError::TooLarge.into());
            }
            let name = file
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(files::FileError::BadName)?
                .to_owned();
            files::check_name(&name)?;
            if let Some(preview) = &file.preview {
                if !files::preview_fits(preview.len()) {
                    return Err(files::FileError::PreviewTooLarge.into());
                }
            }

            let file_id = self.entropy.msg_id();
            let mut key = [0u8; 32];
            self.entropy.fill(&mut key);
            offers.push(files::FileOffer {
                chunk_bytes,
                file_id,
                name,
                size_bytes,
                key,
                preview: file.preview.clone(),
            });
        }
        files::check_offers(&offers).map_err(EngineError::File)?;
        Ok(offers)
    }

    /// Собирает записи хранилища по готовым предложениям.
    ///
    /// Выведено из предложений, а не собрано вторым проходом: разойдись
    /// они хоть в одном поле — `file_id`, ключе, размере, — получатель
    /// просил бы одно, а отдавали бы ему другое.
    ///
    /// `paths` идёт рядом, потому что путь к исходнику наружу не едет:
    /// он есть только у отправителя и в предложении ему делать нечего.
    pub(super) fn records_for(
        offers: &[ratatosk_proto::files::FileOffer],
        paths: &[OutgoingFile],
        msg_id: MsgId,
    ) -> Vec<StoredFile> {
        offers
            .iter()
            .zip(paths)
            .enumerate()
            .map(|(at, (offer, file))| StoredFile {
                file_id: offer.file_id,
                msg_id,
                name: offer.name.clone(),
                size_bytes: offer.size_bytes,
                // Порядок, в каком человек выбрал файлы: он приехал списком
                // и другого источника у него нет.
                ordinal: u32::try_from(at).unwrap_or(u32::MAX),
                // **Размером из предложения, а не своей константой.**
                // Нумерация чанков обязана совпасть у обеих сторон, а своя
                // константа разошлась бы с чужой в тот же миг, когда
                // собеседник выберет другой размер (§10.2).
                chunk_total: ratatosk_proto::files::chunk_count(
                    offer.size_bytes,
                    offer.chunk_bytes,
                ),
                // **И сам размер тоже, а не только выведенное из него число.**
                // Нарезка обязана пережить перезапуск: передача продолжается
                // с того чанка, на котором встала, и восстанавливать размер
                // перебором своих кандидатов у пересланного файла нечем —
                // резал его не мой аппарат и не по моей ступени.
                chunk_bytes: u32::try_from(offer.chunk_bytes).unwrap_or(u32::MAX),
                key: offer.key,
                preview: offer.preview.clone(),
                incoming: false,
                // Путь, а не байты: копировать файл ради отправки значит
                // требовать вдвое больше места, чем у него есть.
                source_path: Some(file.path.to_string_lossy().into_owned()),
                // Своё отправляем, ничего не спрашивая.
                accepted: true,
                complete: true,
            })
            .collect()
    }

    /// Отправляет файлы в группу (§10 поверх §11.3).
    ///
    /// # Групповым становится только предложение
    ///
    /// Чанк шифруется ключом из `file_key ‖ index` (§10.1) — **не
    /// сессионным**, — и потому его байты у всех участников одни и те же
    /// уже сейчас. Групповой обёртки им не нужно: каждый участник просит
    /// их сам и получает по своему 1:1-каналу, ровно как в переписке
    /// двоих. Отсюда весь объём работы: групповым едет одно предложение,
    /// пятым видом действия.
    ///
    /// # Цена названа: копий чанков столько же, сколько участников
    ///
    /// Файл в группе на семь человек — семь потоков. Уменьшить это в v1
    /// нечем: §11.3 запрещает список получателей, потому что он раскрыл
    /// бы состав почтовому серверу.
    pub(super) fn send_group_files(
        &mut self,
        now_ms: u64,
        chat: ChatId,
        files: &[OutgoingFile],
        text: &str,
    ) -> Result<Vec<Effect>, EngineError> {
        let offers = self.prepare_offers(files, text)?;
        let action = ratatosk_proto::group_action::Action::Files {
            caption: text.to_owned(),
            offers: offers.clone(),
            forwarded: false,
        };
        // Кадр собирается до записи в базу: сборка вправе отказать —
        // цепочки может не быть, нас могли исключить, — и записи о файлах,
        // оставшиеся после отказа, человек видел бы вечно отправляющимися.
        let (msg_id, hlc, bytes) = self.seal_group_action(now_ms, chat, &action)?;
        let records = Self::records_for(&offers, files, msg_id);

        self.remember(&StoredMessage {
            msg_id,
            chat_id: chat,
            sender_ik: self.identity.public().ik,
            hlc,
            body: text.as_bytes().to_vec(),
            received_ms: now_ms,
            // Статуса нет, как и у всякой групповой копии: один значок
            // на тридцать двух получателей §14 не разрешает.
            status: None,
            edited_ms: None,
            forwarded: false,
            reply_to: None,
        })?;
        for record in &records {
            self.store.put_file(record)?;
        }

        let mut effects = self.spread_in_chat(now_ms, chat, msg_id, &bytes)?;
        // §10.3 дословно, и спрашивается **про каждый файл отдельно**:
        // предел почты про размер, и в одном сообщении может уехать
        // и фотография, которая поедет почтой, и видео, которое будет ждать.
        //
        // Про участников спрашивается «есть ли хоть один, кому сейчас
        // не увезти»: событие несёт только `file_id`, имени получателя
        // в нём нет. Сказать «ждёт» один раз честнее, чем промолчать, —
        // и честнее, чем семь одинаковых строк на семерых.
        let me = self.identity.public().ik;
        let members: Vec<[u8; 32]> = match self.groups.get(&chat) {
            Some(state) => state.group.recipients(&me),
            None => Vec::new(),
        };
        for record in &records {
            // Причина берётся у **первого** участника, которому файл ехать
            // не на чем. Строка одна на сообщение (выше сказано, почему),
            // и одна причина в ней честнее самой мягкой из семи: человеку
            // важно, что мешает хоть кому-то.
            let reason = members.iter().find_map(|m| self.file_wait_reason(m, record.size_bytes));
            if let Some(reason) = reason {
                effects.push(Effect::Notify(Event::FileWaitsForChannel {
                    file_id: record.file_id,
                    reason,
                }));
            }
        }
        Ok(effects)
    }

    /// Заводит записи о принятых вложениях и отдаёт их.
    ///
    /// Одно место на 1:1 и на группу: порядок вложений, порог автоприёма
    /// и признак «пустой файл собран сразу» обязаны совпадать, иначе
    /// в группе вложение вело бы себя не так, как в переписке.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn record_offers(
        &mut self,
        msg_id: MsgId,
        offers: Vec<ratatosk_proto::files::FileOffer>,
    ) -> Result<Vec<StoredFile>, EngineError> {
        let mut records = Vec::with_capacity(offers.len());
        for offer in offers {
            // **Тот же `file_id` — обязан быть тот же файл.**
            //
            // Пересланное вложение приезжает под прежним идентификатором:
            // так и задумано, иначе байты пришлось бы перешифровывать
            // (§10.1 кладёт `file_id` в AAD чанка). Отсюда и новая
            // возможность: собеседник вправе прислать предложение про файл,
            // который у нас уже есть, — и тогда показывать его надо сразу,
            // ничего не качая.
            //
            // Но отсюда же и новая опасность: пришли он под знакомым
            // `file_id` **другое** имя, размер или ключ — и мы показали бы
            // человеку не то, что отправитель имел в виду, взяв содержимое
            // из своей старой записи. Поэтому расхождение — отказ и аномалия
            // (§7.3), а не «возьмём, что лежит».
            if let Some(known) = self.store.file(&offer.file_id)? {
                let same = known.key == offer.key
                    && known.size_bytes == offer.size_bytes
                    && known.name == offer.name;
                if !same {
                    tracing::warn!(
                        file_id = ?offer.file_id,
                        "предложение под знакомым идентификатором, но про другой файл"
                    );
                    continue;
                }
                // Всё сходится — приложить к новому сообщению и только.
                // Заводить запись заново нельзя: у нас файл может быть уже
                // собран, а у отправителя в предложении об этом нет ничего.
                self.store.attach_file(
                    &msg_id,
                    &offer.file_id,
                    u32::try_from(records.len()).unwrap_or(u32::MAX),
                )?;
                let mut attached = known;
                attached.msg_id = msg_id;
                attached.ordinal = u32::try_from(records.len()).unwrap_or(u32::MAX);
                records.push(attached);
                continue;
            }
            // Размером из предложения — см. разбор у отправляющей стороны.
            let chunk_total =
                ratatosk_proto::files::chunk_count(offer.size_bytes, offer.chunk_bytes);
            let record = StoredFile {
                file_id: offer.file_id,
                msg_id,
                name: offer.name,
                size_bytes: offer.size_bytes,
                // Порядок предложений в конверте — он же порядок, в каком
                // их выбрал отправитель. Своего мнения у получателя тут нет.
                ordinal: u32::try_from(records.len()).unwrap_or(u32::MAX),
                chunk_total,
                // Размером из предложения — он чужой, и своего у нас тут нет.
                chunk_bytes: u32::try_from(offer.chunk_bytes).unwrap_or(u32::MAX),
                key: offer.key,
                preview: offer.preview,
                incoming: true,
                source_path: None,
                // Порог — настройка, а не правило: `None` означает «спрашивать
                // всегда», и это законный выбор человека.
                accepted: ratatosk_proto::files::auto_accept(offer.size_bytes, self.auto_accept),
                // Пустой файл собран в тот же миг: чанков у него нет.
                complete: chunk_total == 0,
            };
            self.store.put_file(&record)?;
            records.push(record);
        }
        Ok(records)
    }

    /// Пришло предложение файлов.
    ///
    /// Сообщение с подписью ложится в историю обычным путём — с событием и
    /// квитанцией (§9.4). Файлы к нему прикладываются записями; те, что
    /// проходят по порогу, сразу запрашиваются, остальные ждут человека.
    pub(super) fn on_file_offer(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (caption, offers, forwarded) =
            ratatosk_proto::files::offer_from_payload(&envelope.payload)?;
        // Пометка едет признаком в предложении, а не типом конверта, — и
        // применяется тем же путём, каким её применяет пересланный текст.
        let kind = if forwarded { TextKind::Forwarded } else { TextKind::Plain };
        let mut effects = self.on_incoming_text(now_ms, via, peer_ik, envelope, &caption, kind)?;

        // Записи о файлах — только если сообщение действительно легло.
        //
        // `put_message` **молча ничего не пишет**, если на идентификатор уже
        // стоит надгробие (§9.2: удалённое не воскрешаем), и вернуть это
        // наружу нечем — подпись у него `Result<()>`. Спросить хранилище —
        // единственный способ узнать.
        //
        // **Внешний ключ тут ни при чём, хотя сперва казалось иначе.**
        // Первая версия этого комментария объясняла проверку тем, что
        // вложение упрётся в `files.msg_id → messages.msg_id` и остановит
        // ядро. Неверно: надгробие — это `UPDATE`, строка сообщения остаётся,
        // и ключ она удовлетворяет. Поймал это тест на настоящей базе
        // (`a_tombstone_satisfies_the_foreign_key_and_that_is_the_trap`).
        //
        // Настоящая цена промаха тише и потому противнее: вложения легли бы
        // к удалённому сообщению. В чате их не видно — надгробие не
        // показывается, — а чанки при этом качаются, занимая ящик (§5.3)
        // и трафик ради того, что человек уже стёр.
        //
        // Случай узкий: дубль предложения обычно отсекает дедупликация,
        // и сюда он доходит, только если её запись успела уйти по сроку,
        // а надгробие осталось. Но цена проверки — одна строка.
        if self.store.message(&envelope.msg_id)?.is_none() {
            effects.clear();
            return Ok(effects);
        }

        let records = self.record_offers(envelope.msg_id, offers)?;

        for record in records {
            if record.complete {
                effects.extend(self.finish_file(now_ms, &record)?);
            } else if record.accepted {
                effects.extend(self.ask_for_file(now_ms, &record, true)?);
            }
        }
        Ok(effects)
    }

    /// Пришла просьба продолжить передачу — она же подтверждение.
    pub(super) fn on_file_request(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        let (file_id, next_index, stalled) =
            ratatosk_proto::files::request_from_payload(&envelope.payload)?;

        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        // Отдаём только своё и только тому, кому отправляли: просьба про чужой
        // файл — попытка вычитать переписку, которой у собеседника нет.
        //
        // В группе «кому отправляли» — это **состав** (§11.3): копия ушла
        // каждому участнику, и просить вправе каждый. Проверка та же
        // по смыслу, но спрашивает у состава, а не у `chat_id_for`:
        // у группы идентификатор чата из ключа не выводится вовсе.
        // **Спрашивается по всем сообщениям файла, а не по одному.** С
        // пересылкой вложений (§10 + `proto::forward`) один файл принадлежит
        // нескольким сообщениям, и право даёт **любое** из них: участник
        // группы, куда файл переслали, просит законно, хотя первое
        // сообщение с этим файлом лежит в чужой переписке.
        //
        // Спроси мы одно — самое раннее, — и переслать файл в группу
        // значило бы отказывать всем её участникам. Снаружи это выглядит
        // как «файл не приходит», и искали бы это в сети.
        let mut may_ask = false;
        for msg_id in self.store.messages_of_file(&file_id)? {
            let Some(chat) = self.store.message(&msg_id)?.map(|m| m.chat_id) else { continue };
            let allowed = match self.groups.get(&chat) {
                // **В канале состав не спрашивается** (§7.6): «любой,
                // у кого есть идентификатор канала, вправе вытянуть
                // шифротекст». Куски и подавно: §9.1 шифрует их **до**
                // хеширования — «значит раздавать их может любой».
                //
                // Спрашивается вместо этого наше участие в раздаче
                // (§7.5.1, §12) — тем же `may_serve`, что и у блоков:
                // выключатель обязан гасить и файлы, иначе он врёт.
                //
                // Пока здесь стоял состав, у открытого канала (§6.1)
                // не проходил никто: состава там не существует, и файлы
                // владельца не качались ни к кому. Ровно это и описал
                // живой прогон.
                Some(state) if !state.profile.everyone_writes() => {
                    // **Своё отдаём всякому, кто спросил.** Мы сами
                    // положили этот файл в канал; §7.6 разрешает вытянуть
                    // шифротекст любому, у кого есть идентификатор,
                    // а §9.1 шифрует куски до хеширования — «значит
                    // раздавать их может любой».
                    //
                    // **Чужое — по правилам раздачи** (§7.5.1, §12): это
                    // уже ретрансляция, и выключатель обязан гасить
                    // и её тоже.
                    //
                    // Первая редакция спрашивала `may_serve` и про своё —
                    // и автор отказывал **владельцу** в собственном же
                    // файле: сам он ни к кому не привязан, а тихая
                    // раздача отдаёт только тем, к кому подключились
                    // сами. Снаружи: файл от подписчика не доходил
                    // никуда, а срок молчания взводился каждые
                    // двенадцать часов вечно.
                    !file.incoming || self.may_serve(chat, &peer_ik)?
                }
                // В группе «кому отправляли» — это **состав** (§11.3): копия
                // ушла каждому участнику, и просить вправе каждый.
                Some(state) => state.group.contains(&peer_ik),
                None => chat == Self::chat_id_for(&peer_ik),
            };
            if allowed {
                may_ask = true;
                break;
            }
        }
        // **Отдавать можно и принятое — если оно собрано целиком.**
        //
        // Здесь стояло «только исходящее», и это было верно ровно до
        // пересылки вложений: переслав полученный файл, человек становится
        // для третьего источником байтов, и отказ означал бы, что
        // пересланный файл не приезжает никогда. Снаружи — «сообщение
        // пришло, а файл не качается», и искали бы это в сети.
        //
        // Условие поэтому не про происхождение, а про **наличие**: у файла
        // с диска (`incoming = false`) байты есть по построению, у принятого
        // — когда он собран. Незавершённый принятый отдавать нечем, и это
        // не аномалия собеседника, а наше «пока нет»: он просит законно.
        // **Отдаём и недособранное** (§9.1): «куски расходятся между
        // участниками», и частичный держатель — тоже держатель. Что
        // у нас есть, тем и делимся; на первой дыре отдача остановится
        // сама (`pump_file`), а спросивший пойдёт к тому, у кого
        // продолжение есть, — карта кусков за тем и объявляется.
        //
        // Пока здесь стояло «только целое», объявленная карта ничего
        // не стоила: держатель звал, а на просьбу отвечал отказом.
        let have_bytes = !file.incoming || file.complete || file.accepted;
        if !may_ask {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        if !have_bytes {
            return Ok(Vec::new());
        }
        if next_index > file.chunk_total {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        // **По паре «файл и получатель», а не по одному файлу.** В группе
        // один и тот же файл просят несколько участников, и каждый идёт
        // по нему в своём темпе: у одного прямой канал, у другого почта
        // с минутным кругом. Одно окно на всех означало бы, что просьба
        // второго отматывает отправку первому.
        let position =
            self.sending.iter().position(|s| s.file_id == file_id && s.peer_ik == peer_ik);
        // Номер просьбы растёт на **каждую**, и по нему решается очерёдность
        // отдачи: кого спросили позже, тот и едет. Разбор — у
        // `sender_lane_has_room`.
        self.asked_seq = self.asked_seq.saturating_add(1);
        let asked_seq = self.asked_seq;
        let sending = match position {
            Some(at) => {
                let sending = &mut self.sending[at];
                sending.asked_seq = asked_seq;
                // Получатель сам сказал, что имеет в виду, — гадать не о чем.
                // «Ничего не дошло» отматывает отправку назад; подтверждение
                // только двигает окно, потому что то, что уже в полёте,
                // слать второй раз незачем.
                if stalled {
                    sending.sent_upto = next_index;
                } else {
                    sending.sent_upto = sending.sent_upto.max(next_index);
                }
                sending.acked_upto = next_index;
                *sending
            }
            None => {
                // Первая просьба — или первая после нашего перезапуска.
                // Своего состояния передачи отправитель не хранит: всё, что
                // нужно, только что приехало в просьбе.
                let sending = Sending {
                    file_id,
                    peer_ik,
                    chunk_total: file.chunk_total,
                    // Нарезкой, записанной вместе с файлом: у пересланного
                    // она чужая, и вывести её из размера и числа кусков
                    // нечем — резал его не мой аппарат и не по моей ступени.
                    chunk_bytes: file.chunk_bytes as usize,
                    size_bytes: file.size_bytes,
                    acked_upto: next_index,
                    sent_upto: next_index,
                    asked_seq,
                };
                self.sending.push(sending);
                sending
            }
        };

        if sending.acked_upto >= file.chunk_total {
            // Получатель сказал, что у него всё. Больше **этой** передаче
            // ничего не нужно — а остальным участникам группы ещё нужно,
            // и их окна остаются.
            self.drop_sending(|s| s.file_id == file_id && s.peer_ik == peer_ik);
            return Ok(Vec::new());
        }
        self.pump_file(now_ms, &file, peer_ik)
    }

    /// Снимает записи об отдаче и отмечает, что место освободилось.
    ///
    /// Одно место на все три случая — получатель всё подтвердил, исходник
    /// пропал, файл удалён, — потому что забыть отметку в одном из них
    /// значит потерять очередь отдачи навсегда: ступень числилась бы
    /// занятой передачей, которой больше нет, и следующая не началась бы
    /// никогда. Ровно это тут и было, пока записи снимались `retain`-ом
    /// на месте.
    ///
    /// Из очереди ожидающих снятое уходит тем же движением: будить
    /// передачу, которой не существует, незачем.
    pub(super) fn drop_sending(&mut self, gone: impl Fn(&Sending) -> bool) {
        // Список снимаемых собирается до всякой правки: перебирать одно
        // поле, держа второе на изменении, — задача для проверяльщика
        // заимствований, а не для читателя.
        let doomed: Vec<(FileId, [u8; 32])> = self
            .sending
            .iter()
            .filter(|sending| gone(sending))
            .map(|sending| (sending.file_id, sending.peer_ik))
            .collect();
        if doomed.is_empty() {
            return;
        }
        self.sending.retain(|s| !gone(s));
        for key in &doomed {
            self.sending_queued.remove(key);
        }
        self.lanes_freed = true;
    }

    /// Есть ли на ступени место под ещё одну **отдачу** (§10.2).
    ///
    /// # Очерёдность — по тому, кого спросили позже, и это не вкусовщина
    ///
    /// Здесь стояло «кто раньше завёл запись, тот и едет», и это была
    /// **взаимная блокировка**, найденная прогоном. Пределов на канал два:
    /// получатель решает, какие файлы просить, отправитель — каким отдавать.
    /// Считая по-разному, они выбирают разные файлы. Получатель просит B;
    /// отправитель держит свой единственный слот за A, потому что запись
    /// о нём старше. A никто не просит — он стоит в очереди получателя.
    /// B не отдают. Никто не двигается, и лечится это только сроком,
    /// которого нет.
    ///
    /// Правило «кого спросили позже» снимает это по построению: у самой
    /// свежей просьбы впереди никого, значит она проходит **всегда**.
    /// Отправитель поэтому не может отказать всем сразу — он обслуживает
    /// того, кто спрашивает.
    ///
    /// Голодания у этого правила тоже нет, и причина приятная: идущая
    /// передача сама себя обновляет — каждое подтверждение приходит
    /// просьбой (§10.2), и номер у неё растёт. Значит начатое доезжает
    /// до конца, а не уступает место на каждом чанке. Застрявший же
    /// получатель вернётся по сроку молчания и станет самым свежим.
    pub(super) fn sender_lane_has_room(&self, file_id: FileId, peer_ik: [u8; 32]) -> bool {
        let Some(mine) = self.sending.iter().find(|s| s.file_id == file_id && s.peer_ik == peer_ik)
        else {
            return false;
        };
        let Some(lane) = self.file_channel(&peer_ik, mine.size_bytes) else {
            // Канала нет — отказывать нечему: `pump_file` разберётся сам
            // и скажет человеку, чего именно ждёт.
            return true;
        };
        let limit = ratatosk_proto::files::parallel_files(lane);
        // Сколько таких же передач спрашивали **позже** нашей.
        let ahead = self
            .sending
            .iter()
            .filter(|other| other.asked_seq > mine.asked_seq)
            .filter(|other| self.file_channel(&other.peer_ik, other.size_bytes) == Some(lane))
            .count();
        ahead < limit
    }

    /// Досылает чанки одному получателю, пока его окно не закрылось.
    ///
    /// Получатель назван явно: в группе у одного файла их несколько, и
    /// у каждого своя дорога. Досылать «всем сразу» здесь нельзя — окно
    /// меряется подтверждениями, а они приходят порознь.
    pub(super) fn pump_file(
        &mut self,
        now_ms: u64,
        file: &StoredFile,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let Some(index) =
            self.sending.iter().position(|s| s.file_id == file.file_id && s.peer_ik == peer_ik)
        else {
            return Ok(Vec::new());
        };
        let sending = self.sending[index];
        // **Та же калитка, что и на приёме, только с другой стороны.**
        // Предел получателя один собеседник не удержит: в группе файл
        // просят несколько человек сразу, и каждый из них считает свою
        // передачу единственной. Пять окон на одном радио — ровно то,
        // ради чего предел и заводился.
        //
        // Отказ здесь молчаливый и ничего не ломает: запись о передаче
        // остаётся, получатель уже спросил, и как только ступень
        // освободится, `wake_queued_files` досылает чанки сам — без
        // второй просьбы и без ожидания срока молчания.
        if !self.sender_lane_has_room(file.file_id, peer_ik) {
            self.sending_queued.insert((file.file_id, peer_ik));
            return Ok(Vec::new());
        }
        self.sending_queued.remove(&(file.file_id, peer_ik));
        let Some(via) = self.file_channel(&sending.peer_ik, file.size_bytes) else {
            // Канала нет — чанкам ехать не на чем. Получатель спросит
            // снова, когда канал появится; своего расписания у отправителя нет.
            //
            // Но сказать об этом надо, и **чем именно** мешает — тоже:
            // иначе у отправителя файл висит «отправляется» ровно столько,
            // сколько собеседник вне сети, и объяснения этому нет ни
            // на экране, ни в журнале.
            let reason = self
                .file_wait_reason(&sending.peer_ik, file.size_bytes)
                .unwrap_or(FileWait::Nowhere);
            return Ok(vec![Effect::Notify(Event::FileWaitsForChannel {
                file_id: file.file_id,
                reason,
            })]);
        };
        let source = file.source_path.clone();
        let Some(session_id) = self.sessions.for_peer(&sending.peer_ik, via) else {
            return Ok(Vec::new());
        };

        // Окно берётся у транспорта, которым сейчас едем: у почты оно шире
        // (круг минутный, узким окном сто мегабайт не увезти) и означает
        // вдобавок «столько чужого ящика мы заняли».
        // Окно спрашивается в **байтах** и переводится в чанки по размеру
        // чанка этой передачи: связывать одно с другим значило бы получить
        // восемь килобайт в полёте, как только чанк станет мелким (§10.2).
        let window = files::chunk_window(via, sending.chunk_bytes);
        let limit = sending.chunk_total.min(sending.acked_upto.saturating_add(window));
        let mut effects = Vec::new();
        let mut next = sending.sent_upto;
        while next < limit {
            // Две дороги к одним и тем же байтам, и различает их **пустой
            // путь**. Файл, который человек выбрал на телефоне, лежит у него
            // открытым там, где лежал, — читаем и запечатываем. Файл,
            // выгруженный с ноутбука, на диск телефона открытым лечь не мог
            // (это была бы новая утечка), поэтому он лежит в хранилище уже
            // запечатанным — и берётся как есть.
            //
            // Как есть, а не «расшифровать и запечатать заново»: запечатывание
            // детерминированное (§10.1, выведенный nonce), так что второй
            // проход дал бы те же байты, потратив на это гигабайт работы.
            let sealed = match source.as_deref() {
                Some(path) => {
                    let offset = next * sending.chunk_bytes as u64;
                    // Отказ чтения и пустой ответ — один и тот же случай:
                    // файла там больше нет или он стал короче. Отказ **не**
                    // поднимается выше: это не поломка ядра, а исчезнувший
                    // исходник, и сказать о нём надо человеку.
                    let plain = self
                        .blobs
                        .read_at(std::path::Path::new(path), offset, sending.chunk_bytes)
                        .unwrap_or_default();
                    if plain.is_empty() {
                        Vec::new()
                    } else {
                        ratatosk_crypto::file::seal_chunk(&file.key, &file.file_id, next, &plain)?
                    }
                }
                // Пропал кусок из хранилища — тот же случай и тот же ответ:
                // передача встала, и сказать об этом надо человеку.
                None => self.blobs.chunk(&file.file_id, next)?.unwrap_or_default(),
            };
            if sealed.is_empty() {
                // Молчать нельзя: передача встанет, и человек будет думать,
                // что она идёт.
                //
                // Окна убираются **у всех** получателей, а не только
                // у этого: исходник пропал не для кого-то одного.
                let gone = file.file_id;
                self.drop_sending(|s| s.file_id == gone);
                effects.push(Effect::Notify(Event::HonestNotice {
                    text: crate::honest::FILE_SOURCE_GONE,
                }));
                break;
            }
            let envelope = Envelope::new(
                self.entropy.msg_id(),
                self.clock.now(now_ms)?,
                PayloadType::FileChunk,
                files::chunk_payload(file.file_id, next, &sealed),
            );
            let frames = self.seal_for(session_id, via, &envelope.encode()?)?;
            effects.extend(Self::sends(sending.peer_ik, via, frames));
            next += 1;
        }
        if let Some(slot) =
            self.sending.iter_mut().find(|s| s.file_id == file.file_id && s.peer_ik == peer_ik)
        {
            slot.sent_upto = next;
        }
        // **Только когда что-то действительно ушло.** `pump_file` зовётся
        // и вхолостую — окно закрыто, ждём подтверждения, — и строка
        // на каждый такой заход была бы не ходом передачи, а шумом.
        if next > sending.sent_upto {
            effects.push(Effect::Notify(Event::FileSending {
                file_id: file.file_id,
                peer_ik,
                sent: next,
                total: file.chunk_total,
            }));
        }
        Ok(effects)
    }

    /// Пришёл чанк файла.
    ///
    /// Квитанции (§9.4) здесь нет и не должно быть: чанк — не сообщение,
    /// и подтверждает его следующая просьба, а не отметка в истории.
    pub(super) fn on_file_chunk(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        use ratatosk_proto::files;

        let (file_id, index, sealed) = files::chunk_from_payload(&envelope.payload)?;
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        // Чанк принимается **только от того, кто предложил файл**.
        //
        // Раньше здесь сверялся чат: у 1:1 он выводится из ключа, и это
        // было то же самое. В группе — нет: идентификатор чата из ключа
        // не выводится, и сверка не сходилась бы никогда, то есть чанки
        // группового вложения отвергались бы как мусор все до одного.
        //
        // Правило про отправителя вдобавок **строже** прежнего и верно
        // для обоих случаев: чанки есть только у того, кто прислал
        // предложение, — пересылки в v1 нет (§11.3). Оно же зеркалит
        // `ask_for_file`: просим у отправителя, у него же и принимаем.
        // **И от объявившегося держателя — тоже** (§9.1). Куски
        // самопроверяемы: `chunk_id` выводится из ключа блока-носителя,
        // и подменённое тело не сойдётся ни у кого. Значит вопрос
        // не «от того ли», а «того ли файла».
        let expected = self.offerer_of(&file)? == Some(peer_ik)
            || self.file_holders.get(&file_id).is_some_and(|who| who.contains_key(&peer_ik));
        if !file.incoming || !file.accepted || !expected {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }
        if index >= file.chunk_total {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(Vec::new());
        }

        // Проверка тега — здесь и сейчас, до записи на диск. Она утверждает
        // три вещи разом: содержимое не изменено, чанк с этого места и из
        // этого файла (§10.1, AAD).
        if ratatosk_crypto::file::open_chunk(&file.key, &file_id, index, &sealed).is_err() {
            self.sessions.note_anomaly(peer_ik, |c| c.bad_tag += 1);
            return Ok(Vec::new());
        }

        // Повтор чанка законен (§9.2) и безвреден — но обрабатывать его как
        // новый нельзя: он потянул бы за собой и подтверждение, и новый срок
        // молчания, а значит и новые чанки в ответ. Ровно так передача
        // начинала разгонять сама себя.
        if self.store.has_chunk(&file_id, index)? {
            return Ok(Vec::new());
        }

        // Байты — раньше отметки. Наоборот было бы «файл собран из куска,
        // которого нет»: отметка переживает падение процесса, а незаписанный
        // чанк — нет.
        self.blobs.put_chunk(&file_id, index, &sealed)?;
        self.store.note_chunk(&file_id, index)?;
        // Файл сдвинулся — отступление сроков начинается заново. Обнуляет
        // счётчик именно приход чанка: удача здесь это движение файла,
        // а не то, что наша просьба ушла.
        self.file_attempts.remove(&file_id);

        let received = self.store.received_chunks(&file_id)?;
        // Нарезкой **этого** файла, а не своим умолчанием: от неё зависит,
        // как часто подтверждать (§10.2). Лежит она рядом с файлом.
        let chunk_bytes = file.chunk_bytes as usize;
        let mut effects = vec![Effect::Notify(Event::FileProgress {
            file_id,
            received,
            total: file.chunk_total,
        })];

        if received >= file.chunk_total {
            effects.extend(self.finish_file(now_ms, &file)?);
            return Ok(effects);
        }
        // Подтверждение — оно же просьба продолжать. Реже, чем каждый чанк:
        // окно не должно простаивать, но и кадр на каждый чанк ни к чему.
        // Подтверждение — «принял, шлите дальше», а не «начните заново»:
        // у отправителя в полёте ещё несколько чанков, и пересылать их
        // не нужно. Различие едет флагом, а не угадывается на той стороне.
        if received % files::ack_every(via, chunk_bytes) == 0 {
            effects.extend(self.ask_for_file(now_ms, &file, false)?);
        } else {
            effects.extend(self.watch_for_stall(file_id, via));
        }
        Ok(effects)
    }

    /// Файл собран.
    /// Объявляет «этот файл у меня есть» тем, кто читает канал с нами
    /// (§9.1).
    ///
    /// # Зачем это нужно только каналу
    ///
    /// В переписке и в группе источник у файла один и известен:
    /// отправитель, и адрес его есть у каждого. В канале это не так —
    /// читатели друг друга не знают (§3.2), и файл, положенный
    /// подписчиком, доходил **до владельца и дальше никуда**: остальные
    /// видели сообщение с вложением, а взять байты им было не у кого.
    ///
    /// Объявление — второй источник, и большего §9.1 для начала
    /// не требует: «отправитель выгружает файл один раз, дальше куски
    /// расходятся между участниками».
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    fn announce_file(
        &mut self,
        now_ms: u64,
        file: &StoredFile,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(message) = self.store.message(&file.msg_id)? else { return Ok(Vec::new()) };
        let chat = message.chat_id;
        if self.groups.get(&chat).is_none_or(|state| state.profile.everyone_writes()) {
            return Ok(Vec::new());
        }
        // Тем же кругом, каким расходятся слова: владелец, сиды и те,
        // кто привязался к нам. Больше некому — состава у читателя нет.
        let bitmap = self.store.chunk_bitmap(&file.file_id, file.chunk_total)?;
        let payload = ratatosk_proto::files::have_payload(file.file_id, &bitmap);
        let mut effects = Vec::new();
        for peer in self.push_candidates(chat, true)? {
            if peer == message.sender_ik {
                // Тому, кто файл и предложил, объявлять нечего.
                continue;
            }
            let (_, sent) = self.enqueue_request(
                now_ms,
                peer,
                ratatosk_codec::PayloadType::FileHave,
                payload.clone(),
            )?;
            effects.extend(sent);
        }
        Ok(effects)
    }

    /// Пришло объявление «файл у меня есть» (§9.1).
    ///
    /// Кладём в список держателей и, если этот файл мы как раз ждём
    /// и ждать его больше не от кого, просим сразу: объявившийся —
    /// ровно тот второй источник, которого не было.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    pub(super) fn on_file_have(
        &mut self,
        now_ms: u64,
        via: Transport,
        peer_ik: [u8; 32],
        envelope: &Envelope,
    ) -> Result<Vec<Effect>, EngineError> {
        // Квитанция — до разбора, как у прочих служебных кадров очереди
        // §5.4: без неё отправитель объявит неудачу.
        let mut effects =
            self.send_receipt(now_ms, peer_ik, via, Receipt::Delivered, &[envelope.msg_id])?;
        let Ok((file_id, bitmap)) = ratatosk_proto::files::have_from_payload(&envelope.payload)
        else {
            self.sessions.note_anomaly(peer_ik, |c| c.malformed += 1);
            return Ok(effects);
        };
        self.file_holders.entry(file_id).or_default().insert(peer_ik, bitmap);

        let Some(file) = self.store.file(&file_id)? else { return Ok(effects) };
        if file.complete || !file.incoming || !file.accepted {
            return Ok(effects);
        }
        effects.extend(self.ask_for_file(now_ms, &file, false)?);
        Ok(effects)
    }

    /// У кого просить куски этого файла (§9.1, §10.2).
    ///
    /// Сперва тот, кто предложил: у него байты есть по построению.
    /// Не дотянуться — **любой объявившийся**, до кого дотянуться можно;
    /// §9.1 велит брать «случайного среди объявивших», и случайность
    /// берётся из того же сида, что и прочие решения (§16).
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    fn source_for(&mut self, file: &StoredFile) -> Result<Option<[u8; 32]>, EngineError> {
        let offerer = self.offerer_of(file)?;
        if let Some(offerer) = offerer {
            if !matches!(self.file_route_of(&offerer, file.size_bytes), FileRoute::Nowhere) {
                return Ok(Some(offerer));
            }
        }
        // **Спрашиваем того, у кого есть нужный кусок** (§9.1): карта
        // затем и объявляется. Частичный держатель — тоже держатель,
        // и у него берут то, что у него есть.
        //
        // **Проверкой это не покрыто, и покрывать дорого.** С одним
        // держателем разницы не видно вовсе, а с двумя она только
        // в числе попыток: спросив пустого, мы получим молчание,
        // подождём срок и спросим следующего. То есть карта здесь —
        // бережливость, а не правило, и стоит она одной строки.
        let next = self.store.next_missing_chunk(&file.file_id, file.chunk_total)?;
        let mut holders: Vec<[u8; 32]> = self
            .file_holders
            .get(&file.file_id)
            .into_iter()
            .flatten()
            .filter(|(ik, _)| Some(**ik) != offerer)
            .filter(|(_, bitmap)| {
                next.is_none_or(|index| ratatosk_proto::files::bitmap_has(bitmap, index))
            })
            .map(|(ik, _)| *ik)
            .filter(|ik| !matches!(self.file_route_of(ik, file.size_bytes), FileRoute::Nowhere))
            .collect();
        if holders.is_empty() {
            return Ok(offerer);
        }
        let mut raw = [0u8; 4];
        self.entropy.fill(&mut raw);
        let pick = usize::try_from(u32::from_le_bytes(raw)).unwrap_or(0) % holders.len();
        Ok(Some(holders.swap_remove(pick)))
    }

    pub(super) fn finish_file(
        &mut self,
        now_ms: u64,
        file: &StoredFile,
    ) -> Result<Vec<Effect>, EngineError> {
        self.store.complete_file(&file.file_id)?;
        self.file_timers.remove(&file.file_id);
        self.file_attempts.remove(&file.file_id);
        self.file_queued.retain(|(id, _)| *id != file.file_id);
        self.leave_lane(&file.file_id);
        let mut effects = vec![Effect::Notify(Event::FileProgress {
            file_id: file.file_id,
            received: file.chunk_total,
            total: file.chunk_total,
        })];
        // **Собрали — объявили** (§9.1). Теперь у файла есть второй
        // источник, и читатель, которому до автора не дотянуться,
        // возьмёт куски у нас.
        effects.extend(self.announce_file(now_ms, file)?);
        Ok(effects)
    }

    /// Срок молчания вышел — спрашиваем заново.
    pub(super) fn on_file_stall(
        &mut self,
        now_ms: u64,
        file_id: FileId,
    ) -> Result<Vec<Effect>, EngineError> {
        let Some(file) = self.store.file(&file_id)? else { return Ok(Vec::new()) };
        if file.complete || !file.incoming || !file.accepted {
            return Ok(Vec::new());
        }
        // **Заминка — повод объявить, что у нас уже есть** (§9.1).
        // Мы застряли, но часть кусков держим, и соседу они могут быть
        // нужны: объявление стоит одного кадра и делает из застрявшего
        // источник.
        let mut effects = self.announce_file(now_ms, &file)?;

        // Срок вышел впустую — следующий будет длиннее (`watch_for_stall`).
        // Счётчик растёт здесь, до просьбы: просьба его и прочитает.
        let attempt = self.file_attempts.entry(file_id).or_insert(0);
        *attempt = attempt.saturating_add(1);
        let fruitless = *attempt;

        // **Замолчавшая передача уступает ступень**, и это не вежливость,
        // а починка запирания. Предел одновременных загрузок на эфире
        // равен одному (§10.2), и пока этот файл числится идущим, все
        // остальные стоят в очереди — в том числе те, чьи отправители
        // прямо сейчас в эфире и готовы отдавать. Собеседник же, ушедший
        // посреди передачи, не возвращается вовсе, а срок у него
        // удваивается: через несколько минут приём стоит целиком за файлом,
        // которого никто не отдаёт.
        //
        // Уступив, передача не пропадает: `ask_for_file` тут же попробует
        // занять место снова, и если очередь пуста — займёт. А если
        // не пуста, встанет в неё и вернётся, когда место освободится.
        if fruitless >= ratatosk_proto::files::YIELD_AFTER_STALLS {
            // **И не спрашиваем в этот же раз.** Спросив, мы забрали бы
            // только что отпущенное место обратно: в этот миг оно свободно,
            // и калитка пустила бы нас, не заглянув в очередь. Ровно так
            // первая редакция уступки и не сработала — проверено прогоном.
            //
            // Вместо просьбы — хвост очереди. Разберёт её `wake_queued_files`
            // в конце шага, по порядку ожидания: голова получит место,
            // а мы вернёмся, когда оно освободится снова.
            // Ступень берётся до того, как её отдали: после `leave_lane`
            // спрашивать уже не у кого. Не нашлась — значит файл её
            // и не занимал, и вставать ему в очередь незачем.
            let Some(lane) = self.file_lane.get(&file_id).copied() else {
                return Ok(effects);
            };
            self.leave_lane(&file_id);
            self.enqueue_file(file_id, lane);
            effects.push(Effect::Notify(Event::FileWaitsForChannel {
                file_id,
                reason: FileWait::Queued,
            }));
            return Ok(effects);
        }

        // Срок вышел — значит за всё это время не пришло ничего. Вот теперь
        // отправителю и правда надо начать с названного номера.
        effects.extend(self.ask_for_file(now_ms, &file, true)?);

        // **Пятый случай, которого не было видно вовсе.** Если просьба
        // ушла — а она ушла, раз ожидания канала среди эффектов нет, —
        // значит канал есть, мы спросили, и в ответ тишина. Это про
        // собеседника, а не про нашу сторону, и чинится в другом месте:
        // «не спросили» и «спросили, молчат» выглядели на экране одинаково,
        // то есть не выглядели никак.
        //
        // Своё ожидание `ask_for_file` уже назвало точнее — второй строки
        // поверх него не надо.
        let already_waiting =
            effects.iter().any(|e| matches!(e, Effect::Notify(Event::FileWaitsForChannel { .. })));
        if !already_waiting {
            effects.push(Effect::Notify(Event::FileWaitsForChannel {
                file_id,
                reason: FileWait::Silent,
            }));
        }
        Ok(effects)
    }

    /// Возобновляет незаконченные приёмы **у всех** собеседников.
    ///
    /// Зовётся, когда заработала ступень (`on_transport_ready`), и нужно это
    /// почте. У прямых каналов возобновление держится на рукопожатии: сессия
    /// после перезапуска новая, рукопожатие проходит, `resume_files` спрашивает
    /// про недокачанное. У почты рукопожатия при старте нет — сессия поднимается
    /// с диска целой, — и без этого вызова приём файла почтой после перезапуска
    /// не возобновлялся бы **никогда**: срок молчания живёт в памяти и
    /// перезапуска не переживает, спросить некому, файл стоит навсегда.
    ///
    /// Найдено рассуждением, а не на стенде, и это тот случай, когда так
    /// и надо: поломка проявляется только если перезапустить приложение
    /// посреди почтовой передачи, то есть через час после её начала.
    pub(super) fn resume_all_files(&mut self, now_ms: u64) -> Result<Vec<Effect>, EngineError> {
        let peers: Vec<[u8; 32]> = self.contacts.keys().copied().collect();
        let mut effects = Vec::new();
        for peer_ik in peers {
            effects.extend(self.resume_files(now_ms, peer_ik)?);
        }
        Ok(effects)
    }

    /// Возобновляет незаконченные приёмы у этого собеседника.
    ///
    /// Зовётся, когда появляется канал: после рукопожатия и когда
    /// собеседник объявился в эфире. Это и есть возобновление после
    /// перезапуска — своего состояния передачи у получателя нет, всё нужное
    /// лежит в базе.
    pub(super) fn resume_files(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let unfinished: Vec<StoredFile> = self
            .store
            .unfinished_files()?
            .into_iter()
            .filter(|f| f.incoming && f.accepted)
            .collect();

        let mut effects = Vec::new();
        for file in unfinished {
            // Тем же правилом, что и приём чанка: возобновляем то, что
            // предлагал **этот** участник. Раньше сверялся чат, и групповое
            // вложение не возобновлялось никогда.
            if self.offerer_of(&file)? != Some(peer_ik) {
                continue;
            }
            effects.extend(self.ask_for_file(now_ms, &file, true)?);
        }
        Ok(effects)
    }

    /// Открывает вложение на чтение — **один раз на файл, а не на кусок**.
    ///
    /// Ядро отвечает на один вопрос и выдаёт [`FileReader`], в котором лежит
    /// всё нужное для расшифровки. Дальше клиент читает сам, из своего
    /// потока, и ядро в этом не участвует.
    ///
    /// Раньше он участвовал в каждом куске, и это был не выбор, а недосмотр:
    /// открытие вложения на полгигабайта означало пятьсот заходов в очередь
    /// драйвера, каждый на время чтения с диска и расшифровки мебибайта.
    /// Всё это время не уходили сообщения и не срабатывали таймеры. Чтение
    /// вложения ничего в состоянии не меняет — значит, ему незачем стоять
    /// в очереди за тем, что меняет.
    ///
    /// Работает и на **своё** отправленное вложение: у него нет запечатанных
    /// чанков (отправитель читает исходник с диска, ничего не копируя),
    /// поэтому читатель берёт его по пути и открытым текстом. До этой правки
    /// своё вложение через ядро не открывалось вовсе.
    ///
    /// `None` — такого файла нет: не приезжал, отклонён или удалён.
    ///
    /// # Errors
    ///
    /// Отказ хранилища.
    ///
    /// [`FileReader`]: crate::reader::FileReader
    pub fn open_file(&self, file_id: &FileId) -> Result<Option<FileReader>, EngineError> {
        let Some(file) = self.store.file(file_id)? else { return Ok(None) };
        Ok(Some(FileReader::new(
            *file_id,
            file.key,
            file.chunk_total,
            file.chunk_bytes,
            file.size_bytes,
            file.source_path.map(std::path::PathBuf::from),
            self.blobs.reader(),
        )))
    }

    // Дополнение к спецификации: v0.1 аватарок не описывает. Правила и пределы
    // собраны в `ratatosk_proto::avatar`, здесь — только их применение.
    /// Что сейчас можно сделать с чанками этого файла (§10.2, §10.3).
    ///
    /// # Одна ходка по лестнице вместо двух
    ///
    /// Здесь стояли **две** функции: `file_channel` («куда ехать сейчас»)
    /// и `file_route` («куда проситься, если сессии нет»). Обе обходили
    /// одну и ту же лестницу §5.4 и обязаны были совпадать в правиле
    /// «годен ли транспорт» — о чём в комментарии и было написано, что
    /// разойдись они, вторая звала бы рукопожатие на канал, которым файл
    /// всё равно не поедет. Теперь ходка одна, и расходиться нечему.
    ///
    /// # И заодно — почему нельзя
    ///
    /// Обе прежние функции отвечали `None` на четыре разных случая,
    /// и различить их снаружи было нечем. Это стоило двух потраченных
    /// гипотез на поломке «файл не качается, потом качается сам»
    /// и, что важнее, врало человеку: «ждёт канала» вместо «ваш ящик
    /// переполнен» (§14).
    ///
    /// Порядок ответов задан лестницей: [`FileRoute::Ready`] — первый
    /// годный транспорт **с сессией**, [`FileRoute::Handshake`] — первый
    /// годный вообще. Именно так вели себя обе прежние функции.
    pub(super) fn file_route_of(&self, peer_ik: &[u8; 32], size_bytes: u64) -> FileRoute {
        let Ok(availability) = self.availability_of(peer_ik) else {
            // Собеседник неизвестен: спрашивать не о чем и не у кого.
            return FileRoute::Nowhere;
        };
        let mut attempt = Attempt::new();
        let mut rideable = None;
        let mut offered = false;
        while let Some(Decision::Use(transport)) = attempt.next(availability) {
            offered = true;
            if !self.file_may_ride(transport, size_bytes) {
                continue;
            }
            if rideable.is_none() {
                rideable = Some(transport);
            }
            if self.sessions.for_peer(peer_ik, transport).is_some() {
                return FileRoute::Ready(transport);
            }
        }
        match (rideable, offered) {
            (Some(transport), _) => FileRoute::Handshake(transport),
            // Транспорты у собеседника есть, но ни один не повезёт файл
            // такого размера. На сегодня это всегда одно: осталась почта,
            // а файл ей не по размеру (§10.3) либо не по пределу письма.
            (None, true) => FileRoute::TooBig,
            (None, false) => FileRoute::Nowhere,
        }
    }

    /// Канал, которым можно везти чанки **прямо сейчас**.
    ///
    /// От [`Engine::direct_channel`] отличается одним: почта отсюда
    /// не исключена — файлы ей ходят (§10.2).
    pub(super) fn file_channel(&self, peer_ik: &[u8; 32], size_bytes: u64) -> Option<Transport> {
        match self.file_route_of(peer_ik, size_bytes) {
            FileRoute::Ready(transport) => Some(transport),
            _ => None,
        }
    }

    /// Почему передача стоит — или `None`, если она не стоит.
    ///
    /// Одно место на все пять мест выпуска [`Event::FileWaitsForChannel`]
    /// у **отправителя**. Переполненный свой ящик сюда не входит нарочно:
    /// он значит «чанкам некуда лечь», а чанки ложатся в ящик того, кто
    /// принимает. У отправки они уходят в чужой.
    pub(super) fn file_wait_reason(&self, peer_ik: &[u8; 32], size_bytes: u64) -> Option<FileWait> {
        match self.file_route_of(peer_ik, size_bytes) {
            FileRoute::Ready(_) => None,
            FileRoute::Handshake(_) => Some(FileWait::Handshaking),
            FileRoute::TooBig => Some(FileWait::TooBig),
            FileRoute::Nowhere => Some(FileWait::Nowhere),
        }
    }

    /// Годится ли такой транспорт для чанков такого размера.
    ///
    /// Почту отсекает не только §10.3, но и предел письма у **своего**
    /// сервера: чанк едет письмом на полтора мебибайта, и сервер,
    /// объявивший `SIZE` меньше, отверг бы каждый — передача начиналась бы
    /// заново вечно. Пока предел неизвестен, почта проходит: молчащий
    /// сервер не должен быть хуже скупого.
    pub(super) fn file_may_ride(&self, transport: Transport, size_bytes: u64) -> bool {
        if !ratatosk_proto::files::may_send_over(size_bytes, transport) {
            return false;
        }
        !(transport == Transport::Mail && !self.mail_limits.carries_file_chunks())
    }
}
