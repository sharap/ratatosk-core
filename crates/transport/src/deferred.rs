//! Транспорт, который ещё поднимается (§5.2, §13.1).
//!
//! Проблема, ради которой этот файл существует: bootstrap Tor идёт десятки
//! секунд, а открытие аккаунта обязано быть мгновенным. Собери мы составной
//! раннер сразу с готовым onion-транспортом — человек смотрел бы на пустой
//! экран минуту, и вся локальная сеть, которая работает сразу, ждала бы
//! вместе с ним.
//!
//! Отсюда [`Deferred`]: раннер, который сначала **честно отказывает**, а потом
//! становится настоящим. §5.4 такое переживает даром — отказ ступени для него
//! штатное событие, и доставка просто идёт следующей.
//!
//! # Почему это не отдельная задача
//!
//! Напрашивалось: `tokio::spawn` на подъём, канал для готового раннера.
//! Но подъём тогда идёт **сам по себе**, а раннер обязан быть остановим
//! вместе с драйвером — иначе после закрытия аккаунта в фоне остаётся
//! Tor-клиент с открытыми цепочками. Здесь подъём двигается ровно тогда,
//! когда драйвер опрашивает [`Runner::next_event`], и умирает вместе с ним.
//!
//! # Отмена
//!
//! [`Runner::next_event`] у составного раннера отменяется на каждом
//! срабатывании `select!`. Незавершённый подъём переживает отмену: будущее
//! лежит в поле, отменяется только текущий опрос, и следующий продолжает
//! с того же места. Забери мы будущее из поля перед ожиданием — bootstrap
//! начинался бы заново каждые несколько миллисекунд и не кончился бы никогда.

use std::future::Future;
use std::pin::Pin;

use tokio::sync::mpsc;

use crate::runner::{Runner, TransportCommand, TransportError, TransportEvent};

/// Будущее, поднимающее транспорт.
type Rising<R> = Pin<Box<dyn Future<Output = Result<R, TransportError>> + Send>>;

/// Сколько новостей о подъёме помещается в очередь.
///
/// Немного намеренно: новости — это состояние, а не история. Отстал
/// читатель — важна последняя строка, а не все пропущенные.
const PROGRESS_QUEUE: usize = 16;

/// Чем кончился один круг ожидания в состоянии подъёма.
enum Step<R> {
    /// Пришла новость о ходе дел.
    News(Option<TransportEvent>),
    /// Подъём завершился — успехом или отказом.
    Done(Result<R, TransportError>),
}

/// Состояние подъёма.
enum State<R> {
    /// Поднимается. Пока — отказ на любую команду.
    Rising(Rising<R>),
    /// Поднялся.
    Ready(R),
    /// Не поднялся. Насовсем: повторять попытку здесь некому и нечем.
    Failed,
}

/// Транспорт, который станет собой позже.
pub struct Deferred<R> {
    state: State<R>,
    /// Новости подъёма — они идут **до** того, как раннер появился,
    /// и потому не могут идти через него самого.
    progress: mpsc::Receiver<TransportEvent>,
    /// Открыт ли канал новостей. Закрытый надо перестать опрашивать:
    /// `recv` на нём возвращает `None` мгновенно, и цикл ожидания
    /// превратился бы в холостой прогон процессора.
    progress_open: bool,
}

impl<R> Deferred<R> {
    /// Заводит раннер, который поднимется в фоне опросов драйвера.
    ///
    /// Новостей о подъёме не будет: для них есть [`Deferred::rising`].
    pub fn new<F>(rising: F) -> Deferred<R>
    where
        F: Future<Output = Result<R, TransportError>> + Send + 'static,
    {
        let (_tx, progress) = mpsc::channel(1);
        Deferred { state: State::Rising(Box::pin(rising)), progress, progress_open: false }
    }

    /// То же, но подъём получает канал, по которому рассказывает о себе.
    ///
    /// Канал заводится здесь, а не снаружи, потому что оба его конца нужны
    /// в разных местах: отправитель уезжает внутрь подъёма, приёмник обязан
    /// остаться тут. Отдай мы это вызывающему, он завёл бы их порознь —
    /// и однажды перепутал бы.
    pub fn rising<F, Fut>(make: F) -> Deferred<R>
    where
        F: FnOnce(mpsc::Sender<TransportEvent>) -> Fut,
        Fut: Future<Output = Result<R, TransportError>> + Send + 'static,
    {
        let (tx, progress) = mpsc::channel(PROGRESS_QUEUE);
        Deferred { state: State::Rising(Box::pin(make(tx))), progress, progress_open: true }
    }

    /// Поднялся ли транспорт.
    ///
    /// Нужно тому, кто показывает состояние человеку: «Tor поднимается» —
    /// это правда, которую §14 требует говорить вслух, а не изображать
    /// работающую сеть.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self.state, State::Ready(_))
    }

    /// Отказался ли транспорт подниматься.
    #[must_use]
    pub const fn has_failed(&self) -> bool {
        matches!(self.state, State::Failed)
    }
}

impl<R: Runner> Runner for Deferred<R> {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        match &mut self.state {
            State::Ready(runner) => runner.execute(command).await,
            // Отказ, а не ожидание. Ждать здесь означало бы задержать весь
            // цикл ядра на время bootstrap — вместе с локальной сетью,
            // которая работает уже сейчас.
            State::Rising(_) | State::Failed => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        loop {
            match &mut self.state {
                State::Rising(rising) => {
                    // Новости идут вперёд подъёма (`biased`), и это не вкус:
                    // очередь новостей короткая, а подъём длинный. Не читай
                    // мы её первой, она переполнилась бы, и человек увидел бы
                    // «10 %» до самого конца.
                    //
                    // `as_mut()` — не украшение: так опрашивается будущее,
                    // остающееся в поле. Отмена ожидания при этом теряет
                    // только текущий опрос, а не весь подъём.
                    let step = tokio::select! {
                        biased;
                        news = self.progress.recv(), if self.progress_open => Step::News(news),
                        outcome = rising.as_mut() => Step::Done(outcome),
                    };
                    match step {
                        Step::News(Some(event)) => return Some(event),
                        // Канал закрыт: рассказывать о подъёме больше некому.
                        Step::News(None) => self.progress_open = false,
                        Step::Done(Ok(runner)) => self.state = State::Ready(runner),
                        Step::Done(Err(error)) => {
                            tracing::warn!(?error, "транспорт не поднялся");
                            self.state = State::Failed;
                            // Вслух, а не только в журнал (§14). Не поднявшийся
                            // транспорт выглядит снаружи как «собеседника нет
                            // в сети» у каждого сообщения — то есть как чужая
                            // неисправность вместо своей. Один раз сказать
                            // правду дешевле, чем разбирать это потом
                            // по пачке одинаковых «ждём, когда появится».
                            //
                            // Событие onion-овое, и это не натяжка: ради Tor
                            // этот тип и существует (см. заголовок файла),
                            // а другого способа сказать что-то человеку
                            // в словаре транспортов нет.
                            return Some(TransportEvent::TorProgress {
                                fraction: 1.0,
                                note: "транспорт не поднялся — доставки через него не будет"
                                    .to_owned(),
                                blocked: Some(error.to_string()),
                            });
                        }
                    }
                }
                // Новости не кончаются вместе с подъёмом: Tor теряет сеть
                // и восстанавливает её на ходу, и об этом человеку тоже
                // полагается знать. Заодно очередь остаётся вычитанной —
                // иначе задача, которая её наполняет, встала бы навсегда.
                State::Ready(runner) => {
                    return tokio::select! {
                        biased;
                        news = self.progress.recv(), if self.progress_open => match news {
                            Some(event) => Some(event),
                            None => {
                                self.progress_open = false;
                                runner.next_event().await
                            }
                        },
                        event = runner.next_event() => event,
                    }
                }
                // Ровно то же, что делает `Disabled`: вечное ожидание,
                // а не `None`. `None` означает «раннер остановлен», и
                // составной, увидев его, решил бы, что транспорта
                // в приложении не осталось вовсе.
                State::Failed => return std::future::pending().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ratatosk_proto::transport_policy::Transport;
    use tokio::sync::mpsc;

    use super::*;
    use crate::runner::PeerAddress;

    /// Раннер-пустышка: принимает всё и выдаёт одно событие.
    struct Fake {
        events: mpsc::Receiver<TransportEvent>,
    }

    impl Runner for Fake {
        async fn execute(&mut self, _command: TransportCommand) -> Result<(), TransportError> {
            Ok(())
        }

        async fn next_event(&mut self) -> Option<TransportEvent> {
            self.events.recv().await
        }
    }

    fn command() -> TransportCommand {
        TransportCommand::Connect {
            peer: PeerAddress { ik: [1u8; 32], onion: None, chatmail: None },
            via: Transport::Onion,
        }
    }

    #[tokio::test]
    async fn a_rising_transport_refuses_instead_of_waiting() {
        // Ожидание здесь задержало бы весь цикл ядра на время bootstrap —
        // вместе с локальной сетью, которая работает уже сейчас.
        let (_tx, rx) = mpsc::channel(1);
        let mut deferred = Deferred::new(async move {
            std::future::pending::<()>().await;
            Ok(Fake { events: rx })
        });

        assert!(matches!(deferred.execute(command()).await, Err(TransportError::Unavailable)));
        assert!(!deferred.is_ready());
    }

    #[tokio::test]
    async fn once_it_is_up_everything_goes_through_it() {
        let (tx, rx) = mpsc::channel(1);
        let mut deferred = Deferred::new(async move { Ok(Fake { events: rx }) });

        // Подъём двигается опросом событий — это и есть весь его двигатель.
        tx.send(TransportEvent::TorReady { onion: "тест.onion".into() }).await.unwrap();
        let event = deferred.next_event().await.expect("событие поднявшегося раннера");
        assert!(matches!(event, TransportEvent::TorReady { .. }));

        assert!(deferred.is_ready());
        assert!(deferred.execute(command()).await.is_ok(), "поднявшийся раннер обязан работать");
    }

    #[tokio::test]
    async fn a_failed_start_refuses_out_loud_and_does_not_stop_the_rest() {
        let mut deferred: Deferred<Fake> =
            Deferred::new(async { Err(TransportError::Unavailable) });

        // Первый опрос узнаёт об отказе — и **говорит о нём вслух** (§14).
        // Молчание здесь снаружи выглядит как «собеседника нет в сети»
        // у каждого сообщения, то есть как чужая неисправность вместо своей.
        let news =
            tokio::time::timeout(std::time::Duration::from_millis(50), deferred.next_event()).await;
        assert!(
            matches!(news, Ok(Some(TransportEvent::TorProgress { blocked: Some(_), .. }))),
            "об отказе подъёма обязана быть новость с причиной: {news:?}"
        );
        assert!(deferred.has_failed());

        // А вот дальше — **ждать вечно**, а не возвращать `None`: `None`
        // означает «остановлен», и составной раннер решил бы, что транспортов
        // не осталось вовсе.
        let outcome =
            tokio::time::timeout(std::time::Duration::from_millis(50), deferred.next_event()).await;
        assert!(outcome.is_err(), "отказавший раннер не вправе объявлять себя остановленным");
        assert!(matches!(deferred.execute(command()).await, Err(TransportError::Unavailable)));
    }

    #[tokio::test]
    async fn news_about_the_rise_reach_the_core_before_it_finishes() {
        // Ради этого канал и заведён: пока транспорт поднимается, раннера
        // ещё нет, и рассказать о ходе дел через него нечем. Без этого
        // «поднимается долго» и «не поднимется никогда» снаружи
        // неотличимы — а §14 их различать обязывает.
        let (tx, rx) = mpsc::channel(1);
        let mut deferred = Deferred::rising(|progress| async move {
            progress
                .send(TransportEvent::TorProgress {
                    fraction: 0.3,
                    note: "ищем сторожевой узел".into(),
                    blocked: None,
                })
                .await
                .ok();
            // Подъём при этом ещё не закончен.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Ok(Fake { events: rx })
        });

        let news = deferred.next_event().await.expect("новость о подъёме");
        match news {
            TransportEvent::TorProgress { fraction, blocked, .. } => {
                assert!((fraction - 0.3).abs() < f32::EPSILON);
                assert!(blocked.is_none());
            }
            other => panic!("ожидалась новость о подъёме, пришло {other:?}"),
        }
        assert!(!deferred.is_ready(), "новость пришла до конца подъёма");

        // А потом подъём заканчивается, и дальше события идут от раннера.
        tx.send(TransportEvent::TorReady { onion: "тест.onion".into() }).await.unwrap();
        let event = deferred.next_event().await.expect("событие поднявшегося раннера");
        assert!(matches!(event, TransportEvent::TorReady { .. }));
        assert!(deferred.is_ready());
    }

    #[tokio::test]
    async fn a_cancelled_wait_does_not_restart_the_bootstrap() {
        // Главное свойство: составной раннер отменяет ожидание на каждом
        // срабатывании `select!`. Забери мы будущее из поля перед ожиданием,
        // подъём начинался бы заново каждые несколько миллисекунд.
        let (tx, rx) = mpsc::channel(1);
        let (started_tx, mut started_rx) = mpsc::channel(8);
        let mut deferred = Deferred::new(async move {
            started_tx.send(()).await.ok();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            Ok(Fake { events: rx })
        });

        // Несколько отменённых ожиданий подряд.
        for _ in 0..3 {
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(5), deferred.next_event())
                    .await;
        }

        tx.send(TransportEvent::TorReady { onion: "тест.onion".into() }).await.unwrap();
        deferred.next_event().await.expect("подъём обязан был продолжиться, а не начаться заново");

        started_rx.recv().await.expect("подъём начинался");
        assert!(started_rx.try_recv().is_err(), "подъём начинался больше одного раза");
    }
}
