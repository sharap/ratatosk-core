//! Соседство: кого слышно сейчас и по какой ступени.
//!
//! Отметки присутствия живут со сроком: услышанное когда-то не значит
//! доступное теперь. Неконтакты копятся отдельно и подбираются, когда
//! человек заводит контакт.

use super::*;

impl<S: Store> Engine<S> {
    /// Откладывает попытку до ответа обнаружения — или не откладывает.
    ///
    /// Возвращает `Some(таймер)`, если ждать есть чего. Условий три, и все
    /// обязательны: LAN включён (иначе ждать нечего), собеседника в эфире
    /// ещё не слышали, и срок ему в этом сеансе ещё не выдавался. Последнее
    /// важнее, чем кажется: без него каждое сообщение собеседнику из другой
    /// сети начиналось бы с трёхсекундной паузы.
    pub(super) fn park_for_discovery(&mut self, delivery: &mut Delivery) -> Option<Effect> {
        if !self.enabled.contains(Transport::Lan) || !delivery.attempt.tried().is_empty() {
            return None;
        }
        let contact = self.contacts.get(&delivery.peer_ik)?;
        if contact.availability.seen_on_lan {
            return None;
        }
        if !self.awaited_discovery.insert(delivery.peer_ik) {
            return None;
        }

        let timer = self.allocate_timer();
        delivery.state = DeliveryState::AwaitingDiscovery { timer };
        Some(Effect::SetTimer { after_ms: LAN_DISCOVERY_GRACE_MS, token: timer })
    }

    /// Отмечает: собеседник **сейчас** в локальной сети — по принятому кадру.
    ///
    /// Это не «сессия есть, значит доступен». Сессия переживает и уход
    /// устройства из сети, и смену сети, и ровно поэтому §5.4 на неё
    /// не опирается: «сессия есть» очень быстро начинает означать «был
    /// вчера». Здесь другое свидетельство — кадр, **пришедший по локальной
    /// сети и прошедший проверку тега**. Он говорит то же самое, что маяк
    /// §5.1, только свежее, и гаснет от тех же двух событий: отказа
    /// соединения (§5.4) и смены сети (§5.1).
    ///
    /// Зачем понадобилось: адрес забывался по обрыву, собеседник тут же
    /// возвращался новым рукопожатием — и §5.4 всё равно не видел, куда
    /// слать, потому что маяк по расписанию звучит не сразу. Обрыв больше
    /// адрес не забывает, но одного этого мало: после **настоящего** отказа
    /// вернувшийся собеседник иначе ждал бы маяка, продолжая слать нам
    /// кадры (`HANDOFF.md`, 6б).
    ///
    /// Переход, а не факт: кадры идут потоком, и перебирать очередь на
    /// каждом — работа впустую. То же правило, что у `Input::SeenOnLan`.
    ///
    /// Недокачанные файлы отсюда не возобновляются, в отличие от маяка:
    /// канал у нас уже есть — по нему только что пришёл кадр, — и всё,
    /// что ждало канала, спросил тот, кто его открыл (§10.2).
    pub(super) fn note_presence(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        let appeared = match self.contacts.get_mut(&peer_ik) {
            Some(contact) => match via {
                Transport::Lan => !std::mem::replace(&mut contact.availability.seen_on_lan, true),
                Transport::Bt => !std::mem::replace(&mut contact.availability.seen_on_bt, true),
                // У прочих ступеней адрес берётся из карточки и от кадров
                // не зависит: помнить тут нечего.
                _ => return Ok(Vec::new()),
            },
            // Не контакт, а своё же устройство (§13.4): ступеней §5.4 у него
            // нет, и отмечать нечего.
            None => return Ok(Vec::new()),
        };
        // **Пришедший кадр — свидетельство не хуже объявления**, и отметку
        // он обновляет всегда, даже когда перехода не было и будить нечего.
        // Иначе значок гас бы посреди разговора: пока канал открыт, Android
        // уводит обзор в экономный режим, и объявлений можно не услышать
        // дольше срока.
        let mut fresh = self.note_nearby(now_ms, peer_ik, via);
        if !appeared && !self.something_waits_for(peer_ik, via) {
            return Ok(fresh);
        }
        tracing::info!(
            peer = %short_ik(&peer_ik),
            ?via,
            "собеседник достижим: кадр пришёл этой ступенью"
        );
        fresh.extend(self.resume_discovery(peer_ik)?);
        fresh.extend(self.retry_deferred(Some(peer_ik))?);
        Ok(fresh)
    }

    /// Отмечает, что собеседника слышно **сейчас**, и заводит срок.
    ///
    /// Зовут её оба свидетельства слышимости — пойманное объявление
    /// ([`Engine::note_heard`]) и пришедший кадр ([`Engine::note_presence`]),
    /// — и это не дублирование: кадр говорит то же, что маяк, только
    /// вернее. Пока идёт разговор, объявления могут и не попадаться:
    /// Android на время открытого канала уводит обзор в экономный режим.
    /// Не считай мы кадр за свидетельство — значок гас бы посреди беседы.
    ///
    /// Возвращает срок, если его надо взвести. Взводится он один на всех
    /// и только когда живого ещё не было: срок на каждое объявление
    /// означал бы десяток таймеров в секунду.
    pub(super) fn note_nearby(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Vec<Effect> {
        let entry = self.heard.entry(peer_ik).or_default();
        let Some(slot) = entry.slot(via) else { return Vec::new() };
        *slot = Some(now_ms);
        self.arm_presence()
    }

    /// Взводит срок гашения соседства, если он ещё не взведён.
    pub(super) fn arm_presence(&mut self) -> Vec<Effect> {
        if self.presence_timer.is_some() {
            return Vec::new();
        }
        let token = self.allocate_timer();
        self.presence_timer = Some(token);
        vec![Effect::SetTimer {
            after_ms: ratatosk_proto::transport_policy::PRESENCE_TTL_MS,
            token,
        }]
    }

    /// Гасит соседство у тех, кого давно не слышно (§5.1, 0.4).
    ///
    /// # Почему это таймер, а не вычисление на месте
    ///
    /// Вычислять свежесть при каждом чтении было бы дешевле и не требовало
    /// бы ни метки, ни прохода. Но тогда об уходе собеседника никто
    /// не узнаёт: признак меняется молча, а клиенту нужно **событие** —
    /// иначе список контактов показывает ушедшего рядом до тех пор, пока
    /// человек не откроет его заново.
    ///
    /// Поэтому проход: он снимает признак и рассылает `ContactChanged`
    /// ровно по тем, у кого соседство погасло.
    ///
    /// # Срок взводится заново, только пока есть кого гасить
    ///
    /// Иначе таймер тикал бы вечно на пустом месте. Никого рядом нет —
    /// метка снимается, и следующее объявление заведёт её снова.
    pub(super) fn forget_stale_presence(&mut self, now_ms: u64) -> Vec<Effect> {
        use ratatosk_proto::transport_policy::PRESENCE_TTL_MS;

        // **Метка забирается, чтобы вернуться той же.** Срок соседства
        // у узла один, и живёт он, пока хоть кого-то слышно; выдавать
        // ему новую метку на каждый круг значило бы менять имя вечной
        // вещи полторы тысячи раз в сутки. Дороже того: у того, кто
        // держит эту метку снаружи — а так устроены проверки, — она
        // молча протухала бы каждые полторы минуты, и спущенный срок
        // не делал бы ничего. Тихо проходящая проверка хуже падающей.
        let mine = self.presence_timer.take();
        let mut changed: Vec<[u8; 32]> = Vec::new();
        let mut anyone_near = false;
        for (peer_ik, contact) in &mut self.contacts {
            let heard = self.heard.get(peer_ik).copied().unwrap_or_default();
            let mut gone = false;
            for via in ratatosk_proto::transport_policy::presence_rungs() {
                let fresh = heard.fresh(via, now_ms, PRESENCE_TTL_MS);
                anyone_near |= fresh;
                let flag = match via {
                    Transport::Lan => &mut contact.availability.seen_on_lan,
                    _ => &mut contact.availability.seen_on_bt,
                };
                if *flag && !fresh {
                    *flag = false;
                    gone = true;
                }
            }
            if gone {
                changed.push(*peer_ik);
            }
        }

        let mut effects: Vec<Effect> = changed
            .into_iter()
            .map(|peer_ik| {
                tracing::info!(
                    peer = %short_ik(&peer_ik),
                    тишина_с = PRESENCE_TTL_MS / 1000,
                    "собеседника больше не слышно — соседство погасло"
                );
                Effect::Notify(Event::ContactChanged { peer_ik })
            })
            .collect();
        if anyone_near {
            let token = mine.unwrap_or_else(|| self.allocate_timer());
            self.presence_timer = Some(token);
            effects.push(Effect::SetTimer { after_ms: PRESENCE_TTL_MS, token });
        }
        effects
    }

    /// Ждёт ли чего-нибудь этот собеседник именно на этой ступени.
    ///
    /// # Зачем это нужно рядом с отметкой «слышно»
    ///
    /// **Отметка одна, а новостей две.** Ставят её два разных события:
    /// пришедший кадр ([`Engine::note_presence`]) и пойманное объявление
    /// ([`Engine::note_heard`]). Очередь же разбиралась только по переходу
    /// «не слышали → слышим» — и кто из двух приходил первым, тот переход
    /// и съедал; второму доставалось «ничего не изменилось», и он не будил
    /// ничего.
    ///
    /// В эфире это не редкий случай, а обычный порядок: собеседник
    /// открывает канал и здоровается раньше, чем мы ловим его объявление
    /// (объявления идут раз в несколько секунд, а рукопожатие — сразу).
    /// Кадр ставил отметку, объявление приходило следом и молчало,
    /// а запомненный ответ на рукопожатие оставался лежать до следующего
    /// повода — то есть до §8.5, которого ещё нет.
    ///
    /// Правильный ответ здесь не «завести вторую отметку»: слышимость для
    /// §5.4 — одно состояние, и разложить его на «кадр пришёл» и «объявление
    /// поймано» значило бы заставить лестницу складывать их обратно. Правильный
    /// — не терять пробуждение, когда ждать **есть чего**.
    ///
    /// # Почему это дёшево
    ///
    /// Проверка идёт на каждое повторное объявление, а они частые. Поэтому
    /// здесь два просмотра коротких списков и ни одного обхода очереди:
    /// незаконченных рукопожатий на ступень не больше одного на собеседника
    /// (`remember_reply`), а отложенные доставки и так лежат вектором,
    /// который `retry_deferred` всё равно разбирает целиком.
    pub(super) fn something_waits_for(&self, peer_ik: [u8; 32], via: Transport) -> bool {
        self.unsent_replies.iter().any(|held| held.peer_ik == peer_ik && held.via == via)
            || self.deferred.iter().any(|delivery| delivery.peer_ik == peer_ik)
    }

    /// Контакт слышен в эфире — в локальной сети или в Bluetooth.
    ///
    /// Одна функция на два эфира, и это не экономия строк. Правило здесь
    /// одно и то же, и оно не про радио: **важен переход** «не слышали →
    /// слышим». Объявления повторяются — mDNS по своему расписанию, BLE
    /// по своему, — и перебирать очередь на каждом повторе значит делать
    /// работу впустую; на первом — необходимо. Две копии этого правила
    /// разошлись бы, и разошлись бы молча: одна ступень возобновляла бы
    /// отложенное, другая нет.
    ///
    /// Поля при этом **разные** (`seen_on_lan`, `seen_on_bt`), и слить их
    /// нельзя: устройство бывает слышно в Bluetooth и невидимо в локальной
    /// сети — разные сети Wi-Fi, гостевая сеть с изоляцией клиентов, —
    /// и наоборот. Слитое поле отдало бы §5.4 ступень, которой нет.
    pub(super) fn note_heard(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Result<Vec<Effect>, EngineError> {
        let bt = via == Transport::Bt;
        let appeared = match self.contacts.get(&peer_ik) {
            Some(contact) if bt => !contact.availability.seen_on_bt,
            Some(contact) => !contact.availability.seen_on_lan,
            None => false,
        };
        match self.contacts.get_mut(&peer_ik) {
            Some(contact) if bt => contact.availability.seen_on_bt = true,
            Some(contact) => contact.availability.seen_on_lan = true,
            // Контакт и его слышимость приходят разными путями — командой
            // от UI и событием транспорта, — и порядок между ними
            // не гарантирован. Потерять отметку значило бы отправить почтой
            // сообщение собеседнику за стенкой, и разбираться потом, почему.
            None => {
                if bt {
                    self.seen_on_bt.insert(peer_ik);
                } else {
                    self.seen_on_lan.insert(peer_ik);
                }
                return Ok(Vec::new());
            }
        }
        // **Отметка времени — на каждое объявление, а не на переход.**
        // Соседство живёт сроком (`PRESENCE_TTL_MS`), и обновлять его надо
        // тем, что слышно сейчас, а не тем, что услышали впервые.
        let mut effects = self.note_nearby(now_ms, peer_ik, via);
        // Собеседник нашёлся — всё, что ждало этого ответа, едет
        // немедленно, не досиживая свой срок.
        effects.extend(self.resume_discovery(peer_ik)?);
        if appeared || self.something_waits_for(peer_ik, via) {
            // **Первым — незаконченное рукопожатие, и только потом всё
            // остальное.** Сообщения без сессии всё равно упрутся в неё,
            // а ответ, ушедший вторым, заставил бы собеседника ждать лишний
            // круг. Именно этот случай и разбирается в `unsent_replies`:
            // мы поздоровались в ответ, когда отвечать было некуда,
            // и вот собеседника стало слышно.
            effects.extend(self.resend_reply(now_ms, peer_ik, via));
            // И то, что не уехало раньше: он снова в сети.
            effects.extend(self.retry_deferred(Some(peer_ik))?);
            // Недокачанные файлы спрашиваются здесь же — но только если
            // сессия уже есть: просьба без прямого канала уйдёт в никуда,
            // а рукопожатие позовёт нас ещё раз.
            //
            // Эфиру Bluetooth это правило достаётся как есть, хотя файлы
            // им пока не ездят (0.4.4): спросить их можно и по нему —
            // поедут они той ступенью, которую выберет §5.4, а не этой.
            effects.extend(self.resume_files(now_ms, peer_ik)?);
        }
        Ok(effects)
    }

    /// Запоминает ответ на рукопожатие до доказательства, что он дошёл.
    ///
    /// На пару «собеседник и ступень» хранится **один** ответ, и новый
    /// вытесняет прежний: сессия на семейство тоже одна, и второй ответ
    /// означает, что первый уже не нужен. Без этого правила запись росла бы
    /// на каждое повторное рукопожатие — то есть ровно там, где связь и так
    /// плоха.
    pub(super) fn remember_reply(&mut self, peer_ik: [u8; 32], via: Transport, frame: &[u8]) {
        self.unsent_replies.retain(|held| held.peer_ik != peer_ik || held.via != via);
        self.unsent_replies.push(UnsentReply {
            peer_ik,
            via,
            frame: frame.to_vec(),
            resent_ms: None,
        });
    }

    /// Забывает ответ: доказано, что собеседник его получил.
    pub(super) fn forget_reply(&mut self, peer_ik: [u8; 32], via: Transport) {
        self.unsent_replies.retain(|held| held.peer_ik != peer_ik || held.via != via);
    }

    /// Отправляет запомненный ответ заново — собеседника снова слышно.
    ///
    /// Запись при этом **остаётся**: слышимость не есть доставка. Уйдёт она
    /// только по [`Engine::forget_reply`], то есть по первому кадру сессии —
    /// единственному доказательству, которое у нас бывает.
    pub(super) fn resend_reply(
        &mut self,
        now_ms: u64,
        peer_ik: [u8; 32],
        via: Transport,
    ) -> Vec<Effect> {
        let Some(held) =
            self.unsent_replies.iter_mut().find(|held| held.peer_ik == peer_ik && held.via == via)
        else {
            return Vec::new();
        };
        // **Не чаще круга — начиная со второго повтора.** Поводов
        // «собеседника снова слышно» подряд бывает несколько, и без этой
        // проверки ответ уходил пачкой: на стенде трижды за сто двадцать
        // миллисекунд. Ответа на первый к тому времени не могло быть
        // физически — круг по эфиру длиннее всей этой пачки.
        let gap = receipt_timeout_ms(via, held.frame.len()).unwrap_or(0);
        if held.resent_ms.is_some_and(|last| now_ms.saturating_sub(last) < gap) {
            return Vec::new();
        }
        held.resent_ms = Some(now_ms);
        let frame = held.frame.clone();
        tracing::info!(
            peer = %short_ik(&peer_ik),
            ?via,
            "ответ на рукопожатие уходит заново: собеседника снова слышно"
        );
        vec![Effect::Send { peer_ik, via, frame, handoff: None }]
    }

    /// Обнаружение ответило (или кончился срок) — двигаем отложенное.
    ///
    /// Вызывается и по маяку, и по таймеру: разница только в том, окажется ли
    /// LAN доступен на следующем шаге. Решает это [`Attempt`], а не эта
    /// функция, — здесь только снимается пауза.
    pub(super) fn resume_discovery(
        &mut self,
        peer_ik: [u8; 32],
    ) -> Result<Vec<Effect>, EngineError> {
        let mut effects = Vec::new();
        let mut queue = std::mem::take(&mut self.outbox);

        for delivery in &mut queue {
            if delivery.peer_ik != peer_ik
                || !matches!(delivery.state, DeliveryState::AwaitingDiscovery { .. })
            {
                continue;
            }
            // Состояние снимается до `advance`: иначе `park_for_discovery`
            // увидел бы нетронутую попытку и отложил её второй раз.
            delivery.state = DeliveryState::AwaitingSession;
            effects.extend(self.advance(delivery)?);
        }

        queue.retain(|d| !d.attempt.is_finished());
        self.outbox = queue;
        Ok(effects)
    }
}
