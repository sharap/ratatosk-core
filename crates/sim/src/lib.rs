//! Детерминированная симуляция сети (§16).
//!
//! §16 — «ключевая позиция, а не приложение к спецификации», и §17 требует,
//! чтобы харнесс делался первым, а не последним. Крейт даёт то, ради чего это
//! требование существует: вся сеть в одном процессе, время виртуальное,
//! случайность из фиксированного сида, найденное расхождение воспроизводится
//! по номеру сида.
//!
//! Узел подключается через трейт [`SimNode`]; крейт ничего не знает ни о
//! кадрах, ни о криптографии, поэтому одним и тем же харнессом гоняются и
//! `ratatosk-core` целиком, и отдельная подсистема.
//!
//! Обязательные сценарии из §16 разобраны в `tests/scenarios.rs`.
//!
//! ```
//! use ratatosk_sim::{Ctx, NodeId, Sim, SimNode, TransportKind};
//!
//! struct Echo { heard: Vec<Vec<u8>> }
//!
//! impl SimNode for Echo {
//!     fn on_deliver(&mut self, _c: &mut Ctx<'_>, _f: NodeId, _k: TransportKind, b: &[u8]) {
//!         self.heard.push(b.to_vec());
//!     }
//! }
//!
//! let mut sim = Sim::new(1234, vec![Echo { heard: vec![] }, Echo { heard: vec![] }]);
//! sim.start();
//! sim.inject(NodeId(0), NodeId(1), TransportKind::Onion, b"hi".to_vec());
//! sim.run_to_idle(100).unwrap();
//! assert_eq!(sim.node(NodeId(1)).heard, vec![b"hi".to_vec()]);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod net;
pub mod rng;
pub mod sim;

pub use net::{Delivery, LinkProfile, Network, NodeId, TransportKind};
pub use rng::Rng;
pub use sim::{Ctx, Sim, SimNode, Stats};
