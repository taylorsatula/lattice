//! Lattice protocol core, sans I/O.
//!
//! A state machine: events in (frame arrived, timer fired, application sent
//! something), actions out (send a frame, deliver to the app, update status).
//! Time, randomness, sockets and disk are injected by the caller — the
//! simulator or the daemon.

#![forbid(unsafe_code)]

pub mod graph;
pub mod node;
pub mod reconcile;
pub mod rng;
pub mod types;
mod u256;

pub use node::{Identity, Node};
pub use rng::Rng;
pub use types::{Action, AppSend, Config, Event, LinkId};
