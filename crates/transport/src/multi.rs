//! Несколько транспортов сразу (§5.4).
//!
//! До этого модуля драйвер держал ровно один [`Runner`], и это было незаметно
//! ровно до тех пор, пока транспорт был один. §5.4 описывает лестницу из трёх:
//! LAN, onion, почта, — и лестница из одной ступени не лестница.
//!
//! # Почему не `Box<dyn Runner>`
//!
//! Напрашивалось: список раннеров, перебираемый по `via`. Но у [`Runner`]
//! асинхронные методы, а трейт с `async fn` не годится для динамической
//! диспетчеризации. Поэтому состав задан **типами**: три параметра, по одному
//! на транспорт из §5. Список транспортов закрыт спецификацией и меняться
//! не будет, так что гибкость здесь была бы гибкостью ради неё самой.
//!
//! Чего ещё нет — [`Disabled`]: раннер, который честно отказывает. Сегодня
//! это onion и почта, и отказ у них не заглушка, а правда о сборке.
//!
//! # Отмена: требование к `next_event`
//!
//! Составной раннер ждёт события у всех трёх сразу и берёт то, что пришло
//! первым. Проигравшие ожидания при этом **отменяются**, поэтому
//! [`Runner::next_event`] обязан быть устойчив к отмене: событие, снятое
//! на полпути, не должно теряться.
//!
//! Для всех реализаций в этом крейте это выполняется даром — они ждут
//! на `mpsc::Receiver::recv`, а он отменяем без потери. Но написать это
//! надо здесь, потому что нарушение проявится не отказом, а редкой пропажей
//! сообщения, и искать её будут не там.
//!
//! # Что кому достаётся
//!
//! Команды с явным транспортом (`Send`, `Connect`, `SetEnabled`) уходят
//! по нему. Команды с именем транспорта в названии (`WatchLanPeers`,
//! `RestartLan`) — ему же. А `Disconnect` уходит **всем**: в нём нет `via`,
//! и кто именно держит соединение с этим контактом, знает только сам раннер.

use ratatosk_proto::transport_policy::Transport;

use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Транспорт, которого в этой сборке нет.
///
/// Отказывает на всё и не порождает событий никогда. Отказ здесь честнее
/// молчаливого успеха: §5.4 обязан узнать, что ступень не сработала,
/// и перейти к следующей, а не ждать ответа, которого не будет.
#[derive(Debug, Default, Clone, Copy)]
pub struct Disabled;

impl Runner for Disabled {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match command {
            // Сказать несобранному транспорту, что он разрешён, — не ошибка.
            // Разрешение относится к §5.4, а его здесь всё равно нет; отказ
            // же выглядел бы в журнале поломкой, которой не случилось.
            TransportCommand::SetEnabled { .. } => Ok(()),
            _ => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        // Именно вечное ожидание, а не `None`. `None` означает «раннер
        // остановлен», и составной раннер, увидев его от всех троих, решил бы,
        // что транспорта в приложении не осталось вовсе, — а не собранный
        // транспорт и остановленный это разные вещи.
        std::future::pending().await
    }
}

/// Три транспорта §5 под одной ручкой.
///
/// Сам является [`Runner`], поэтому драйвер о нём ничего не знает: он
/// по-прежнему держит один раннер, просто теперь этот раннер разводит команды.
#[derive(Debug)]
pub struct Transports<L, O, M> {
    lan: L,
    onion: O,
    mail: M,
    /// Кто уже остановился.
    ///
    /// Нужно затем, чтобы остановка одного транспорта не выглядела остановкой
    /// всех. LAN, выключенный человеком, не должен уносить с собой onion.
    stopped: [bool; 3],
}

impl<L: Runner, O: Runner, M: Runner> Transports<L, O, M> {
    /// Собирает состав.
    pub fn new(lan: L, onion: O, mail: M) -> Transports<L, O, M> {
        Transports { lan, onion, mail, stopped: [false; 3] }
    }

    /// LAN-раннер — за настройками, которые есть только у него.
    pub fn lan(&self) -> &L {
        &self.lan
    }

    /// Изменяемый LAN-раннер.
    pub fn lan_mut(&mut self) -> &mut L {
        &mut self.lan
    }

    /// Onion-раннер.
    pub fn onion(&self) -> &O {
        &self.onion
    }

    /// Почтовый раннер.
    pub fn mail(&self) -> &M {
        &self.mail
    }

    async fn to_one(
        &mut self,
        via: Transport,
        command: TransportCommand,
    ) -> Result<(), TransportError> {
        match via {
            Transport::Lan => self.lan.execute(command).await,
            Transport::Onion => self.onion.execute(command).await,
            Transport::Mail => self.mail.execute(command).await,
        }
    }

    /// Раздаёт команду всем трём, возвращая первый настоящий отказ.
    ///
    /// Обход не прерывается на первом: команда без `via` относится ко всем,
    /// и прервавшись, мы оставили бы часть транспортов в прежнем состоянии.
    /// Ровно та же логика, что у «объявляется один аккаунт» в реестре, — и
    /// та же причина: частично применённое правило хуже неприменённого,
    /// потому что выглядит применённым.
    ///
    /// [`TransportError::Unavailable`] отказом здесь **не** считается.
    /// Команда, адресованная всем, выполнена, если её выполнили все, кто
    /// есть; «этого транспорта нет в сборке» — не провал разъединения,
    /// а сведение о составе. Считай мы иначе, каждое `Disconnect` возвращало бы
    /// ошибку, пока onion и почта не написаны, — и в журнале завёлся бы шум,
    /// в котором потом потерялся бы настоящий отказ.
    async fn to_all(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        let mut failure = None;
        for via in [Transport::Lan, Transport::Onion, Transport::Mail] {
            match self.to_one(via, command.clone()).await {
                Ok(()) | Err(TransportError::Unavailable) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl<L: Runner, O: Runner, M: Runner> Runner for Transports<L, O, M> {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match &command {
            // Транспорт назван явно — §5.4 выбрал его и отвечает за выбор.
            TransportCommand::Send { via, .. } | TransportCommand::Connect { via, .. } => {
                let via = *via;
                self.to_one(via, command).await
            }
            // Транспорт назван полем — как и у отправки.
            TransportCommand::SetEnabled { transport, .. } => {
                let transport = *transport;
                self.to_one(transport, command).await
            }
            // Имя транспорта в названии команды: адресат очевиден.
            TransportCommand::WatchLanPeers(_) | TransportCommand::RestartLan => {
                self.lan.execute(command).await
            }
            // А тут `via` нет, и знать, кто держит соединение с этим
            // контактом, может только сам раннер.
            TransportCommand::Disconnect { .. } => self.to_all(command).await,
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        loop {
            if self.stopped.iter().all(|done| *done) {
                // Остановились все — вот теперь транспорта не осталось.
                return None;
            }

            // `biased` не ставится намеренно: у транспортов нет старшинства,
            // и постоянный порядок опроса дал бы LAN преимущество на ровном
            // месте. Приоритет §5.4 — про выбор при отправке, а не про
            // очередь входящих.
            let (which, event) = tokio::select! {
                event = self.lan.next_event(), if !self.stopped[0] => (0, event),
                event = self.onion.next_event(), if !self.stopped[1] => (1, event),
                event = self.mail.next_event(), if !self.stopped[2] => (2, event),
            };

            match event {
                Some(event) => return Some(event),
                // Остановка одного — не остановка всех. Помечаем и ждём
                // дальше у оставшихся: выключенный человеком LAN не должен
                // уносить с собой onion.
                None => self.stopped[which] = true,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::PeerAddress;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    /// Раннер, который записывает, что ему велели, и отдаёт что скажут.
    struct Recorder {
        name: &'static str,
        seen: Arc<Mutex<Vec<(&'static str, String)>>>,
        events: mpsc::Receiver<TransportEvent>,
        refuse: bool,
    }

    impl Recorder {
        fn new(
            name: &'static str,
            seen: &Arc<Mutex<Vec<(&'static str, String)>>>,
        ) -> (Recorder, mpsc::Sender<TransportEvent>) {
            let (tx, rx) = mpsc::channel(8);
            (Recorder { name, seen: Arc::clone(seen), events: rx, refuse: false }, tx)
        }
    }

    impl Runner for Recorder {
        async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
            let what = match command {
                TransportCommand::Send { .. } => "send",
                TransportCommand::Connect { .. } => "connect",
                TransportCommand::Disconnect { .. } => "disconnect",
                TransportCommand::SetEnabled { .. } => "set-enabled",
                TransportCommand::WatchLanPeers(_) => "watch",
                TransportCommand::RestartLan => "restart",
            };
            self.seen.lock().unwrap().push((self.name, what.to_owned()));
            if self.refuse {
                // Настоящий отказ, а не `Unavailable`: последний означает
                // «транспорта нет в сборке» и при раздаче всем не считается
                // провалом.
                return Err(TransportError::Timeout);
            }
            Ok(())
        }

        async fn next_event(&mut self) -> Option<TransportEvent> {
            self.events.recv().await
        }
    }

    fn peer() -> PeerAddress {
        PeerAddress { ik: [1u8; 32], onion: None, chatmail: None }
    }

    fn send(via: Transport) -> TransportCommand {
        TransportCommand::Send { peer: peer(), via, frame: vec![0u8; 4096] }
    }

    #[tokio::test]
    async fn a_named_transport_gets_the_command_and_the_others_do_not() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, _l) = Recorder::new("lan", &seen);
        let (onion, _o) = Recorder::new("onion", &seen);
        let (mail, _m) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        transports.execute(send(Transport::Onion)).await.unwrap();
        transports.execute(send(Transport::Mail)).await.unwrap();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![("onion", "send".to_owned()), ("mail", "send".to_owned())],
            "кадр обязан уйти тем транспортом, который выбрал §5.4, и только им"
        );
    }

    #[tokio::test]
    async fn lan_only_commands_go_to_lan() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, _l) = Recorder::new("lan", &seen);
        let (onion, _o) = Recorder::new("onion", &seen);
        let (mail, _m) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        transports
            .execute(TransportCommand::SetEnabled { transport: Transport::Lan, enabled: true })
            .await
            .unwrap();
        transports.execute(TransportCommand::RestartLan).await.unwrap();

        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter().all(|(who, _)| *who == "lan"),
            "не LAN про это знать незачем: {seen:?}"
        );
        assert_eq!(seen.len(), 2);
    }

    #[tokio::test]
    async fn disconnect_reaches_everyone() {
        // В команде нет `via`, и кто держит соединение с этим контактом,
        // знает только сам раннер.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, _l) = Recorder::new("lan", &seen);
        let (onion, _o) = Recorder::new("onion", &seen);
        let (mail, _m) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        transports.execute(TransportCommand::Disconnect { peer: peer() }).await.unwrap();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "всем троим: {seen:?}");
    }

    #[tokio::test]
    async fn a_refusal_does_not_stop_the_round() {
        // Частично применённая команда хуже неприменённой: она выглядит
        // применённой.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (mut lan, _l) = Recorder::new("lan", &seen);
        lan.refuse = true;
        let (onion, _o) = Recorder::new("onion", &seen);
        let (mail, _m) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        let verdict = transports.execute(TransportCommand::Disconnect { peer: peer() }).await;
        assert!(verdict.is_err(), "отказ обязан дойти до вызывающего");
        assert_eq!(seen.lock().unwrap().len(), 3, "но обход дошёл до всех");
    }

    #[tokio::test]
    async fn events_from_every_transport_come_through() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, lan_tx) = Recorder::new("lan", &seen);
        let (onion, onion_tx) = Recorder::new("onion", &seen);
        let (mail, _m) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        onion_tx
            .send(TransportEvent::Connected { peer_ik: [2u8; 32], via: Transport::Onion })
            .await
            .unwrap();
        assert!(matches!(
            transports.next_event().await,
            Some(TransportEvent::Connected { via: Transport::Onion, .. })
        ));

        lan_tx
            .send(TransportEvent::Connected { peer_ik: [3u8; 32], via: Transport::Lan })
            .await
            .unwrap();
        assert!(matches!(
            transports.next_event().await,
            Some(TransportEvent::Connected { via: Transport::Lan, .. })
        ));
    }

    #[tokio::test]
    async fn one_transport_stopping_does_not_stop_the_rest() {
        // Ошибка, которую легко сделать: `select!` вернул `None` — значит
        // всё кончилось. Нет: выключенный человеком LAN не должен уносить
        // с собой onion.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, lan_tx) = Recorder::new("lan", &seen);
        let (onion, onion_tx) = Recorder::new("onion", &seen);
        let (mail, mail_tx) = Recorder::new("mail", &seen);
        let mut transports = Transports::new(lan, onion, mail);

        drop(lan_tx);
        onion_tx
            .send(TransportEvent::Connected { peer_ik: [2u8; 32], via: Transport::Onion })
            .await
            .unwrap();
        assert!(transports.next_event().await.is_some(), "остановка LAN не отменяет событий onion");

        drop(onion_tx);
        drop(mail_tx);
        assert!(transports.next_event().await.is_none(), "а когда встали все — вот теперь конец");
    }

    #[tokio::test]
    async fn a_transport_that_is_not_built_refuses_out_loud() {
        // Молчаливый успех здесь был бы худшим исходом: §5.4 решил бы, что
        // кадр ушёл, и не перешёл бы к следующей ступени.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (lan, _l) = Recorder::new("lan", &seen);
        let mut transports = Transports::new(lan, Disabled, Disabled);

        assert!(transports.execute(send(Transport::Onion)).await.is_err());
        assert!(transports.execute(send(Transport::Mail)).await.is_err());
        assert!(seen.lock().unwrap().is_empty(), "и до LAN это не дошло");

        // А вот команда, адресованная всем, проходит: «транспорта нет
        // в сборке» — не провал разъединения. Иначе каждое `Disconnect`
        // возвращало бы ошибку, пока onion и почта не написаны.
        transports.execute(TransportCommand::Disconnect { peer: peer() }).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "LAN своё получил");
    }
}
