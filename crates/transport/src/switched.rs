//! Транспорт под выключателем: гаснет и поднимается по команде (§5.2, §5.4).
//!
//! Этот тип раньше назывался `Deferred` и умел ровно половину: подняться
//! один раз в фоне опросов драйвера. Половина была та, что видна сразу —
//! bootstrap Tor идёт десятки секунд, а открытие аккаунта обязано быть
//! мгновенным, и раннер, который сначала честно отказывает, решает это
//! целиком. Вторая половина появилась вместе с общим выключателем (§5.4,
//! `ARCHITECTURE.md` 5э): переключатель, который не гасит транспорт, —
//! настройка про §5.4, а не про Tor, и человек, выключивший Tor, вправе
//! ожидать, что Tor выключился.
//!
//! # Состояния и переходы
//!
//! ```text
//! Off ──включили──→ Rising ──поднялся──→ Ready
//!  ↑                  │                    │
//!  └──выключили───────┴────────────────────┘
//!
//! Rising ──не поднялся──→ Failed ──включили──→ Rising
//! ```
//!
//! Начальное состояние — [`State::Off`], и это не мелочь: ядро объявляет
//! включённые транспорты первым делом при старте
//! (`Engine::startup_effects`), поэтому выключенный в прошлый раз Tor
//! **не поднимается вовсе** — ни bootstrap, ни каталога сети, ни цепочек.
//!
//! Повторное включение после отказа — заодно и «попробовать ещё раз»:
//! из [`State::Failed`] выхода не было, и единственным лечением был
//! перезапуск приложения.
//!
//! # Что значит «погасить»
//!
//! Уронить раннера. Всё, что держит Tor живым, висит на нём: `TorClient`
//! с цепочками, `RunningOnionService` (пока жив — сервис опубликован),
//! соединения с контактами. Отдельного «стоп» у arti нет и не нужно —
//! владение и есть выключатель.
//!
//! Оговорка, которая стоит того, чтобы её записать: уронить **достаточно**
//! только если задачи, порождённые раннером, не держат его части у себя.
//! Наблюдатель за состоянием сервиса держал `Arc<RunningOnionService>` —
//! то есть сервис пережил бы собственный раннер и остался бы опубликованным.
//! Поэтому `OnionRunner` помнит свои задачи и снимает их в `Drop`.
//!
//! # Почему не отдельная задача
//!
//! Напрашивалось: `tokio::spawn` на подъём, канал для готового раннера.
//! Но подъём тогда идёт **сам по себе**, а раннер обязан умирать вместе
//! с драйвером — иначе после закрытия аккаунта в фоне остаётся Tor-клиент
//! с открытыми цепочками. Здесь подъём двигается ровно тогда, когда драйвер
//! опрашивает [`Runner::next_event`], и заканчивается вместе с ним.
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

/// Как поднять транспорт ещё раз.
///
/// `Fn`, а не `FnOnce`, и в этом вся разница между прежним типом и нынешним:
/// поднять придётся столько раз, сколько человек передумает. Значит, всё
/// нужное для подъёма закрытие обязано **одалживать**, а не забирать —
/// на практике это `Arc`, клонируемый на каждый заход.
type Factory<R> = Box<dyn Fn(mpsc::Sender<TransportEvent>) -> Rising<R> + Send>;

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

/// Состояние транспорта.
enum State<R> {
    /// Выключен человеком — или ещё не включён. Ничего не поднято.
    Off,
    /// Поднимается. Пока — отказ на любую команду доставки.
    Rising(Rising<R>),
    /// Поднялся.
    Ready(R),
    /// Не поднялся. Лечится включением заново.
    Failed,
}

/// Транспорт, которым управляет выключатель.
pub struct Switched<R> {
    state: State<R>,
    /// Чем поднимать. Зовётся при каждом включении.
    factory: Factory<R>,
    /// Новости подъёма — они идут **до** того, как раннер появился,
    /// и потому не могут идти через него самого.
    ///
    /// Заводится заново на каждый подъём: отправитель уезжает внутрь
    /// будущего и умирает вместе с ним, а переживший его приёмник отдавал бы
    /// `None` мгновенно — то есть следующий подъём остался бы без голоса.
    progress: Option<mpsc::Receiver<TransportEvent>>,
}

impl<R> Switched<R> {
    /// Заводит транспорт **выключенным**.
    ///
    /// Поднимется он, когда ядро скажет, что человек его включил
    /// ([`TransportCommand::SetEnabled`]). Ядро говорит это первым делом
    /// при старте, так что нормальный путь короче, чем кажется: включённый
    /// в прошлый раз Tor начинает подниматься сразу.
    ///
    /// Замыкание получает канал, по которому подъём рассказывает о себе,
    /// и зовётся на каждое включение — значит, забирать в себя ничего
    /// не должно.
    pub fn new<F, Fut>(rise: F) -> Switched<R>
    where
        F: Fn(mpsc::Sender<TransportEvent>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<R, TransportError>> + Send + 'static,
    {
        Switched {
            state: State::Off,
            factory: Box::new(move |progress| Box::pin(rise(progress))),
            progress: None,
        }
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

    /// Выключен ли он человеком.
    #[must_use]
    pub const fn is_off(&self) -> bool {
        matches!(self.state, State::Off)
    }

    /// Включает: начинает подъём, если его ещё нет.
    fn switch_on(&mut self) {
        match self.state {
            // Уже поднимается или поднят — включать нечего.
            State::Rising(_) | State::Ready(_) => {}
            State::Off | State::Failed => {
                let (tx, rx) = mpsc::channel(PROGRESS_QUEUE);
                self.progress = Some(rx);
                self.state = State::Rising((self.factory)(tx));
            }
        }
    }

    /// Выключает: роняет всё, что было поднято.
    ///
    /// Ронять — и есть весь механизм: Tor живёт ровно столько, сколько живёт
    /// раннер. Незавершённый подъём тоже роняется, и это правильно — довести
    /// bootstrap до конца, чтобы тут же погасить, значит потратить минуту
    /// и батарею на то, от чего человек только что отказался.
    fn switch_off(&mut self) {
        self.state = State::Off;
        self.progress = None;
    }
}

impl<R: Runner> Runner for Switched<R> {
    async fn execute(&mut self, command: TransportCommand) -> Result<(), TransportError> {
        // Переключатель обрабатывается здесь и **не** уходит дальше:
        // включать и гасить — дело этого типа, а не того, кого он держит.
        if let TransportCommand::SetEnabled { enabled, .. } = &command {
            if *enabled {
                self.switch_on();
            } else {
                self.switch_off();
            }
            return Ok(());
        }

        match &mut self.state {
            State::Ready(runner) => runner.execute(command).await,
            // Отказ, а не ожидание. Ждать здесь означало бы задержать весь
            // цикл ядра на время bootstrap — вместе с локальной сетью,
            // которая работает уже сейчас. Для §5.4 отказ ступени —
            // штатное событие: доставка идёт следующей.
            State::Off | State::Rising(_) | State::Failed => Err(TransportError::Unavailable),
        }
    }

    async fn next_event(&mut self) -> Option<TransportEvent> {
        loop {
            // Приёмник новостей и состояние берутся по отдельности: в ветке
            // подъёма нужны оба сразу, а взять их одним `&mut self` нельзя.
            let progress = &mut self.progress;
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
                        news = recv(progress) => Step::News(news),
                        outcome = rising.as_mut() => Step::Done(outcome),
                    };
                    match step {
                        Step::News(Some(event)) => return Some(event),
                        // Канал закрыт: рассказывать о подъёме больше некому.
                        Step::News(None) => *progress = None,
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
                        news = recv(progress) => match news {
                            Some(event) => Some(event),
                            // Канал кончился вместе с подъёмом: отправитель
                            // жил внутри будущего. Забываем его, иначе каждый
                            // опрос начинался бы с холостого круга.
                            None => {
                                *progress = None;
                                runner.next_event().await
                            }
                        },
                        event = runner.next_event() => event,
                    };
                }
                // Ровно то же, что делает `Disabled`: вечное ожидание,
                // а не `None`. `None` означает «раннер остановлен», и
                // составной, увидев его, решил бы, что транспорта
                // в приложении не осталось вовсе.
                //
                // Из выключенного состояния этот сон прерывает не событие,
                // а команда: `execute` меняет состояние, а составной раннер
                // отменяет ожидание на каждом `select!` и заходит сюда заново.
                State::Off | State::Failed => return std::future::pending().await,
            }
        }
    }
}

/// Ждёт новость, если приёмник есть; иначе не возвращается никогда.
///
/// Отдельной функцией, потому что `select!` не умеет ветку, которой может
/// не быть: условие `if` в нём вычисляется до опроса, а `Option` надо ещё
/// и раскрыть. Вечное ожидание вместо отсутствующей ветки — то же самое
/// по смыслу и читается честнее, чем `Option` внутри макроса.
async fn recv(progress: &mut Option<mpsc::Receiver<TransportEvent>>) -> Option<TransportEvent> {
    match progress {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use ratatosk_proto::transport_policy::Transport;

    use super::*;
    use crate::runner::PeerAddress;

    /// Раннер-пустышка: принимает всё и выдаёт события из канала.
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
            peer: PeerAddress {
                ik: [1u8; 32],
                onion: None,
                chatmail: None,
                ygg: None,
                nostr: None,
                nostr_relays: Vec::new(),
            },
            via: Transport::Onion,
        }
    }

    fn switch(enabled: bool) -> TransportCommand {
        TransportCommand::SetEnabled { transport: Transport::Onion, enabled }
    }

    /// Ждёт события не дольше срока: `None` — не дождались.
    async fn briefly(runner: &mut Switched<Fake>) -> Option<Option<TransportEvent>> {
        tokio::time::timeout(std::time::Duration::from_millis(50), runner.next_event()).await.ok()
    }

    #[tokio::test]
    async fn a_switched_off_transport_does_not_rise_at_all() {
        // Смысл всей поставки: выключенный в прошлый раз Tor не поднимается
        // вовсе — ни bootstrap, ни каталога сети, ни цепочек. Раннер заводится
        // выключенным, и без команды подъём не начинается.
        let risen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&risen);
        let mut runner: Switched<Fake> = Switched::new(move |_progress| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let (_tx, events) = mpsc::channel(1);
                Ok(Fake { events })
            }
        });

        assert!(runner.is_off());
        assert!(briefly(&mut runner).await.is_none(), "выключенный не отдаёт событий");
        assert_eq!(risen.load(Ordering::SeqCst), 0, "подъём не начинался");
        assert!(matches!(runner.execute(command()).await, Err(TransportError::Unavailable)));
    }

    #[tokio::test]
    async fn switching_on_rises_and_switching_off_drops_it() {
        // Роняем — и Tor кончается: всё, что его держит, висит на раннере.
        // Проверяется наблюдаемое следствие: после выключения раннера нет,
        // а после повторного включения он поднимается **заново**.
        let risen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&risen);
        let mut runner: Switched<Fake> = Switched::new(move |_progress| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let (_tx, events) = mpsc::channel(1);
                Ok(Fake { events })
            }
        });

        runner.execute(switch(true)).await.unwrap();
        // Один опрос доводит подъём до конца: будущее готово сразу.
        let _ = briefly(&mut runner).await;
        assert!(runner.is_ready(), "включённый обязан подняться");
        assert_eq!(risen.load(Ordering::SeqCst), 1);
        assert!(runner.execute(command()).await.is_ok(), "поднятый принимает команды");

        runner.execute(switch(false)).await.unwrap();
        assert!(runner.is_off(), "выключённый обязан погаснуть");
        assert!(
            matches!(runner.execute(command()).await, Err(TransportError::Unavailable)),
            "погашенный ничего не принимает"
        );

        runner.execute(switch(true)).await.unwrap();
        let _ = briefly(&mut runner).await;
        assert!(runner.is_ready());
        assert_eq!(risen.load(Ordering::SeqCst), 2, "второе включение поднимает заново");
    }

    #[tokio::test]
    async fn a_failed_start_refuses_out_loud_and_can_be_retried() {
        // Об отказе подъёма надо сказать: молчание снаружи выглядит как
        // «собеседника нет в сети» у каждого сообщения, то есть как чужая
        // неисправность вместо своей.
        //
        // А включение заново — это ещё и «попробовать ещё раз»: раньше
        // из отказа выхода не было, и лечился он перезапуском приложения.
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);
        let mut runner: Switched<Fake> = Switched::new(move |_progress| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TransportError::Unavailable)
            }
        });

        runner.execute(switch(true)).await.unwrap();
        let news = briefly(&mut runner).await;
        assert!(
            matches!(news, Some(Some(TransportEvent::TorProgress { blocked: Some(_), .. }))),
            "об отказе подъёма обязана быть новость с причиной: {news:?}"
        );
        assert!(runner.has_failed());

        // И после неё — вечное ожидание, а не `None`: `None` означает
        // «раннер остановлен», и составной решил бы, что транспорта нет вовсе.
        assert!(briefly(&mut runner).await.is_none());

        runner.execute(switch(true)).await.unwrap();
        let _ = briefly(&mut runner).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 2, "включение заново — это и повтор попытки");
    }

    #[tokio::test]
    async fn news_about_the_rise_reach_the_core_before_it_finishes() {
        // Ради этого канал и заведён: пока транспорт поднимается, раннера
        // ещё нет, и рассказать о ходе дел через него нечем.
        let mut runner: Switched<Fake> = Switched::new(move |progress| async move {
            let _ = progress
                .send(TransportEvent::TorProgress {
                    fraction: 0.1,
                    note: "поднимаемся".to_owned(),
                    blocked: None,
                })
                .await;
            // Дальше подъём не кончается никогда — так проверяется, что
            // новость доходит **до** его конца, а не вместе с ним.
            std::future::pending().await
        });

        runner.execute(switch(true)).await.unwrap();
        let news = briefly(&mut runner).await;
        assert!(
            matches!(news, Some(Some(TransportEvent::TorProgress { .. }))),
            "новость о ходе подъёма обязана дойти до его конца: {news:?}"
        );
        assert!(!runner.is_ready(), "новость пришла до конца подъёма");
    }
}
