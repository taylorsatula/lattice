//! Lattice protocol core, sans I/O.
//!
//! A state machine: events in (frame arrived, timer fired, application sent
//! something), actions out (send a frame, deliver to the app, update status).
//! Time, randomness, sockets and disk are injected by the caller — the
//! simulator or the daemon.

#![forbid(unsafe_code)]

mod error;
mod frame_budget;
pub mod graph;
pub mod node;
mod outbound;
pub mod reconcile;
pub mod rng;
pub mod types;
mod u256;

pub use error::NodeError;
pub use node::{Identity, LookupResult, Node, RetiredEnvelopeKey, RotationKind};
pub use rng::Rng;
pub use types::{Action, AppSend, Config, Diagnostic, Event, LinkId};
