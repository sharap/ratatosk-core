//! Читатели для клиента: списки, заголовки, имена, страницы истории.
//!
//! Ничего не меняют и ничего не отправляют — только отвечают на вопросы
//! клиента о том, что уже есть. Вынесены отдельно нарочно: у читателя
//! и у обработчика разная цена ошибки, и смешивать их в одном файле
//! значит читать чужую половину каждый раз.

use super::*;

impl<S: Store> Engine<S> {
    /// Поднимает приёмную цепочку участника из того, что лежит на диске.
    ///
    /// Пустой кэш — обычное дело, а не отказ: так выглядит цепочка, по которой
    /// ещё ничего не переставлялось, и первое же сообщение от нового участника
    /// приходит именно так.
    ///
    /// Испорченный кэш стоит позиции: цепочка поднимается с записанного места,
    /// а пропуски теряются. Это честнее отказа — потерять хвосты хуже, чем
    /// потерять всю переписку с человеком, — и заметнее тишины: следующие
    /// сообщения открываются как ни в чём не бывало.
    pub(super) fn inbox_of(stored: &StoredSenderChain) -> ratatosk_crypto::ratchet::SenderInbox {
        use ratatosk_crypto::ratchet::SenderInbox;
        let fresh = || SenderInbox::resume(zeroize::Zeroizing::new(stored.chain), stored.counter);
        if stored.skipped.is_empty() {
            return fresh();
        }
        SenderInbox::restore(&stored.skipped).unwrap_or_else(|_| fresh())
    }

    /// Группы, какими их знает ядро (§11).
    ///
    /// Отдаётся всё состояние, а не список названий: клиенту нужен и состав
    /// (кого показывать в шапке), и владелец (рисовать ли «исключить»).
    #[must_use]
    pub fn groups(&self) -> &BTreeMap<ChatId, GroupState> {
        &self.groups
    }

    /// Список чатов для десктопа (§13.4).
    ///
    /// Заголовок считает телефон, и это правило §13.3, а не удобство:
    /// «локальное имя вытесняет имя из карточки» — протокольное решение
    /// (§4.1), и повторённое в десктопе оно однажды разошлось бы с этим.
    pub(super) fn chat_summaries(&self) -> Result<Vec<companion::ChatSummary>, EngineError> {
        let mut out = Vec::with_capacity(self.contacts.len());
        for (peer_ik, contact) in &self.contacts {
            let chat = Self::chat_id_for(peer_ik);
            // Одно сообщение — последнее: строка под именем в списке чатов.
            // Хранилище отдаёт хвост окна, надгробия (§12) отсеивая само.
            let last = self.store.messages(&chat, 1, None)?;
            let (last_text, last_ms) = last.last().map_or_else(
                || (String::new(), 0),
                |m| (String::from_utf8_lossy(&m.body).into_owned(), m.hlc.wall_ms),
            );
            out.push(companion::ChatSummary {
                chat,
                title: Self::title_of(contact, peer_ik),
                verified: contact.verified,
                last_text,
                last_ms,
                // §4.2 живёт здесь же, где и в `avatar_of`, и одинаково:
                // несверенному контакту метка не едет вовсе. Иначе десктоп
                // спрашивал бы аватарку, получал пустоту и спрашивал снова —
                // а заодно узнавал бы, что лицо у телефона есть, при том
                // что показать его нельзя.
                avatar_ms: if contact.verified {
                    self.store.avatar_stamp(peer_ik)?.unwrap_or(0)
                } else {
                    0
                },
                is_group: false,
                // Из переписки с человеком не выходят: её удаляют, и тогда
                // чата в списке нет вовсе.
                joined: true,
            });
        }

        // Группы — тем же списком и в том же порядке. Отдельного списка
        // у десктопа нет и не надо: чат есть чат, и различают их два
        // признака — те, что едут рядом.
        let me = self.identity.public().ik;
        for (chat, state) in &self.groups {
            let last = self.store.messages(chat, 1, None)?;
            let (last_text, last_ms) = last.last().map_or_else(
                || (String::new(), 0),
                |m| (String::from_utf8_lossy(&m.body).into_owned(), m.hlc.wall_ms),
            );
            out.push(companion::ChatSummary {
                chat: *chat,
                title: state.title.clone(),
                // Сверяют людей, а не круги знакомых. Ноль и `false` здесь
                // не «нечего показать пока», а «нечего показывать вовсе»,
                // и отличить одно от другого десктопу позволяет `is_group`.
                verified: false,
                last_text,
                last_ms,
                // Правило «показывать нечего» одно и живёт в ядре: ноль
                // здесь означает и «картинки не ставили», и «сняли».
                avatar_ms: self.group_avatar_stamp(chat)?,
                is_group: true,
                // Единственное место, где этот признак бывает `false`.
                // Считает его телефон, а не десктоп по составу: состава
                // десктоп не видит вовсе (§13.4).
                joined: state.group.contains(&me),
            });
        }
        // Свежие сверху — тот же порядок, в каком чаты показывает телефон.
        // Считает его телефон по той же причине, что и заголовок: правило
        // одно, и жить ему в одном месте.
        out.sort_by(|a, b| b.last_ms.cmp(&a.last_ms).then_with(|| a.chat.cmp(&b.chat)));
        Ok(out)
    }

    /// Как назвать чат в списке.
    ///
    /// Порядок: подпись пользователя (§4.1), имя из карточки, отпечаток.
    /// Последнее — не заглушка: имя в карточке задаёт собеседник, и пустым
    /// оно бывает законно, а чат без названия выбрать в списке нельзя.
    pub(super) fn title_of(contact: &Contact, peer_ik: &[u8; 32]) -> String {
        if let Some(name) = contact.local_name.as_ref().filter(|n| !n.trim().is_empty()) {
            return name.clone();
        }
        if !contact.card.display_name.trim().is_empty() {
            return contact.card.display_name.clone();
        }
        Self::short_label(peer_ik)
    }

    /// Как назвать того, у кого имени нет: начало отпечатка.
    ///
    /// Одно место на два случая — контакт без имени и участник группы,
    /// чья карточка ещё не доехала. Разойдись они, один и тот же человек
    /// подписывался бы в списке контактов иначе, чем под своим сообщением.
    pub(super) fn short_label(peer_ik: &[u8; 32]) -> String {
        peer_ik[..4].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Как подписать автора сообщения — если это вообще нужно.
    ///
    /// # `None` означает «выводится из `mine`», а не «неизвестно»
    ///
    /// В переписке двоих автор исчерпывается признаком «своё ли»: не своё —
    /// значит собеседника, а его имя уже стоит заголовком чата. Подписывать
    /// там каждую строку значит повторять одно и то же на весь экран.
    ///
    /// В группе так нельзя: «не своё» — это один из тридцати двух, и без
    /// имени сообщение не читается вовсе. Поэтому здесь `Some` ровно
    /// у групп, и это утверждение о том, **выводимо ли** имя, а не о том,
    /// известно ли оно.
    ///
    /// # Неизвестного автора не бывает
    ///
    /// Участник, чья карточка ещё не доехала (§11.5), подписывается началом
    /// отпечатка — тем же, каким подписан безымянный контакт. Пустой строки
    /// или `None` здесь не возвращается никогда: «имя не приехало» и «имя
    /// выводится из `mine`» — разные вещи, и путать их на границе нельзя.
    ///
    /// # Своё имя берётся из своей карточки
    ///
    /// Себя в списке контактов нет, и без этого собственное сообщение
    /// в группе подписывалось бы отпечатком. Что показать вместо имени —
    /// «вы» или имя, — решает клиент: у него для этого есть `mine`.
    #[must_use]
    pub fn message_author(&self, chat: &ChatId, sender_ik: &[u8; 32]) -> Option<String> {
        if !self.groups.contains_key(chat) {
            return None;
        }
        Some(self.name_of(sender_ik))
    }

    /// Как назвать человека по ключу — кем бы он ни был.
    ///
    /// **Одно место на три случая**, и третий тут главный: себя в списке
    /// контактов нет, и всякий, кто ищет имя по ключу перебором контактов,
    /// не находит там **себя**. Своё имя берётся из своей карточки; чужое —
    /// по §4.1 (местное вытесняет карточное); незнакомое — началом
    /// отпечатка.
    ///
    /// На этом уже спотыкались дважды: сперва подпись автора сообщения,
    /// потом список участников группы, где клиент показывал хозяина
    /// телефона «неизвестным пользователем». Ошибка одна и та же, и потому
    /// правило теперь одно.
    pub(super) fn name_of(&self, peer_ik: &[u8; 32]) -> String {
        if *peer_ik == self.identity.public().ik {
            let own = self.own_card().display_name;
            return if own.trim().is_empty() { Self::short_label(peer_ik) } else { own };
        }
        match self.contacts.get(peer_ik) {
            Some(contact) => Self::title_of(contact, peer_ik),
            None => Self::short_label(peer_ik),
        }
    }

    /// Состав группы в том виде, в каком его рисуют.
    ///
    /// Отдаётся списком записей, а не ключей, и это то же решение, что
    /// у заголовка чата: имя считает ядро (§4.1 и §11.5 живут здесь),
    /// а «это я» — тем более. Клиент, получавший голые ключи, искал имя
    /// перебором контактов и **себя там не находил**: своей карточки
    /// в контактах нет, и хозяин телефона показывался неизвестным.
    ///
    /// Пустой список означает, что группы нет вовсе.
    #[must_use]
    pub fn group_members(&self, chat: &ChatId) -> Vec<GroupMember> {
        let me = self.identity.public().ik;
        match self.groups.get(chat) {
            Some(state) => state
                .group
                .members()
                .map(|ik| GroupMember { ik: *ik, name: self.name_of(ik), mine: *ik == me })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Что клиент рисует у канала сверх группы (фаза 2, §6, §10).
    ///
    /// `None` у обычной группы — и это ответ, а не отсутствие ответа:
    /// экрана канала там нет.
    ///
    /// # Почему всё считается здесь, а не у клиента
    ///
    /// Каждое поле — правило §6, а не поле таблицы: права с учётом срока
    /// (§6.3), порода только из подписанного (§6.1), «можно ли
    /// поворачивать» из трёх правил разом (§6.4), порог молчания
    /// владельца (§6.3). Выведи их клиент из сырых строк — правила
    /// оказались бы в двух местах, а §13.3 держит их в одном.
    ///
    /// # Отказ хранилища здесь — это `None`
    ///
    /// Список чатов не должен падать из-за того, что не прочиталась
    /// одна выдача. Канал без документа выглядит так же, как канал,
    /// документ которого не прочёлся, и в обоих случаях показывать
    /// нечего, кроме ожидания.
    #[must_use]
    pub fn channel_facts(&self, chat: &ChatId, now_ms: u64) -> Option<ChannelFacts> {
        let state = self.groups.get(chat)?;
        if state.profile.everyone_writes() {
            return None;
        }
        let me = self.identity.public().ik;
        let stored = self.store.channel(chat).ok().flatten();
        // Владелец известен и **без документа**: он приехал ссылкой
        // (§10.3, шаг 3) либо вводным блоком и лёг владельцем чата.
        // Ровно поэтому подпись документа есть чем проверить, когда он
        // доедет.
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
        let rights = channel::rights_from(&owner, &grants, &me, now_ms);
        // Свой срок — из своей же выдачи. У владельца её нет и быть
        // не может (5вп), и ноль здесь значит «срока нет», а не «истёк».
        let rights_until_ms = grants
            .iter()
            .filter(|grant| grant.who == me && grant.live_at(now_ms))
            .map(|grant| grant.until_ms)
            .max()
            .unwrap_or(0);

        let kind = stored.as_ref().and_then(|it| channel::Kind::from_code(u64::from(it.kind)));
        let keys = self.store.archive_keys(chat).unwrap_or_default();
        // Те же три правила, что в `on_rotate_channel_key`, и спрошены
        // они здесь затем, чтобы человек не узнавал о них из отказа.
        // Порода неизвестна — кнопки нет: обещать поворот, не зная,
        // бывает ли он в этом канале, хуже, чем не обещать.
        let may_rotate =
            kind == Some(channel::Kind::ByInvite)
                && rights.has(channel::Rights::EVICT)
                && keys.iter().rev().find(|key| key.generation > 0).is_none_or(|last| {
                    now_ms.saturating_sub(last.created_ms) >= MIN_KEY_ROTATION_MS
                });

        // Молчание владельца (§6.3). Считается по **нашему** приёму:
        // приезд новой версии документа и последнее его слово в канале —
        // единственные свидетельства, которые у нас есть.
        let heard = [
            stored.as_ref().map(|it| it.received_ms),
            self.store.last_heard_in_chat(chat, &owner).ok().flatten(),
        ]
        .into_iter()
        .flatten()
        .max();
        // Своё же молчание не считается: владелец сам себе ничего
        // не присылает, и метка «от владельца ничего не приходит»
        // на его собственном экране означала бы поломку связи там,
        // где связь не нужна.
        let owner_quiet_ms =
            if owner == me { None } else { heard.map(|at| now_ms.saturating_sub(at)) };

        Some(ChannelFacts {
            version: stored.as_ref().map_or(0, |it| it.version),
            open: kind.map(|kind| kind == channel::Kind::Open),
            owner_ik: owner,
            rights: rights.bits(),
            rights_until_ms,
            pow_bits: stored.as_ref().map_or(0, |it| it.pow_bits),
            awaiting: self
                .store
                .subscription(chat)
                .ok()
                .flatten()
                .is_some_and(|it| it.state == SUBSCRIPTION_REQUESTED),
            readable: !keys.is_empty(),
            generation: keys.iter().map(|key| key.generation).max().unwrap_or(0),
            may_rotate,
            owner_quiet_ms,
            owner_unseen: owner_quiet_ms.is_some_and(|quiet| quiet >= OWNER_SILENCE_MS),
            // Чужие сроки — не наше дело: у не-владельца продлевать
            // нечего, и число, которое не к чему применить, на экране
            // только пугает.
            grants_expiring: if owner == me {
                u32::try_from(
                    grants
                        .iter()
                        .filter(|grant| {
                            grant.live_at(now_ms)
                                && grant.until_ms.saturating_sub(now_ms) < GRANT_PROLONG_AHEAD_MS
                        })
                        .count(),
                )
                .unwrap_or(u32::MAX)
            } else {
                0
            },
        })
    }

    /// Выдачи прав канала — для экрана владельца (§6.2, §6.3).
    ///
    /// Пустой список означает и «выдач нет», и «документа ещё нет»:
    /// различать их клиенту незачем — показывать в обоих случаях нечего,
    /// а «есть ли документ» говорит [`ChannelFacts::version`].
    #[must_use]
    pub fn channel_grants(&self, chat: &ChatId, now_ms: u64) -> Vec<ChannelGrantView> {
        let Some(stored) = self.store.channel(chat).ok().flatten() else { return Vec::new() };
        stored
            .grants
            .iter()
            .map(|grant| ChannelGrantView {
                who: grant.who,
                name: self.name_of(&grant.who),
                rights: grant.rights,
                until_ms: grant.until_ms,
                live: now_ms < grant.until_ms,
            })
            .collect()
    }

    /// Заявки на подписку — то, что видит владелец (фаза 2, §10.4).
    ///
    /// Пустой список означает «никто не просится», и у открытого канала
    /// он пуст всегда: там владелец не участвует и не узнаёт.
    ///
    /// Ответ на заявку один — впуск ([`Command::AdmitToChannel`]);
    /// отказа как сообщения не бывает, и показывать надо так же: список
    /// просящих и кнопка «впустить», а не «принять/отклонить».
    ///
    /// [`Command::AdmitToChannel`]: crate::io::Command::AdmitToChannel
    #[must_use]
    pub fn channel_requests(&self, chat: &ChatId) -> Vec<ChannelRequestView> {
        self.store
            .channel_requests(chat)
            .unwrap_or_default()
            .into_iter()
            .map(|(who, received_ms)| ChannelRequestView {
                who,
                name: self.name_of(&who),
                received_ms,
            })
            .collect()
    }

    /// Записи о впусках — учёт владельца (§6.5).
    ///
    /// Показываются **все**, включая впуски делегатами: в этом весь смысл
    /// учёта. Окно сидирования их не обрезает (§6.5), поэтому список
    /// полон настолько, насколько полна наша копия канала.
    #[must_use]
    pub fn channel_admits(&self, chat: &ChatId) -> Vec<ChannelAdmitView> {
        self.store
            .admits(chat)
            .unwrap_or_default()
            .into_iter()
            .map(|admit| ChannelAdmitView {
                who: admit.who,
                name: self.name_of(&admit.who),
                admitted_by: admit.admitted_by,
                admitted_by_name: self.name_of(&admit.admitted_by),
                generation: admit.generation,
                created_ms: admit.created_ms,
            })
            .collect()
    }

    /// Страница истории чата для десктопа.
    ///
    /// `None` означает, что **курсор мёртв**: сообщение, «перед» которым
    /// просили страницу, у нас исчезло. Это не то же, что пустая страница,
    /// и раньше было тем же — с последствием, которое видно только на втором
    /// экране. Пустая страница читается как «дальше ничего нет», то есть как
    /// край истории; но за мёртвым курсором история как раз есть, просто
    /// отсчитывать от него больше не от чего. Десктоп, услышав «край»,
    /// переставал листать назад — и переписка недельной давности выглядела
    /// отсутствующей до тех пор, пока человек не откроет чат заново.
    ///
    /// Начало чата вместо этого отдавать нельзя: десктоп листает **назад**,
    /// и хвост в ответ на «дай что было раньше» устроил бы бесконечный
    /// список из одной и той же страницы.
    pub(super) fn history_page(
        &self,
        chat: ChatId,
        limit: u32,
        before: Option<MsgId>,
    ) -> Result<Option<Vec<companion::Message>>, EngineError> {
        // Предел свой, а не тот, что попросили: §13.4 отдаёт десктопу окно,
        // а не всю историю, и верить числу с другого устройства в вопросе
        // «сколько прочитать из базы» нельзя — ноль вернул бы пустую
        // страницу навсегда, миллион прочитал бы весь чат в память телефона.
        let limit = limit.clamp(1, companion::MAX_PAGE) as usize;

        let before_hlc = match before {
            Some(msg_id) => match self.store.message(&msg_id)? {
                Some(message) => Some(message.hlc),
                // Сообщение удалили, отозвали или унесла очистка чата,
                // пока десктоп был не на связи.
                None => return Ok(None),
            },
            None => None,
        };

        let stored = self.store.messages(&chat, limit, before_hlc)?;
        let mut page = Vec::with_capacity(stored.len());
        for message in &stored {
            page.push(self.companion_message(message)?);
        }
        Ok(Some(page))
    }
}
