//! Lattice protocol core, sans I/O.
//!
//! A state machine: events in (frame arrived, timer fired, application sent
//! something), actions out (send a frame, deliver to the app, update status).
//! Time, randomness, sockets and disk are injected by the caller — the
//! simulator or the daemon.
//!
//! Time base: milliseconds since the Unix epoch, everywhere in the public
//! API (`Event` timestamps, `Node::new`, `Node::next_deadline`). The wire
//! format and the store keep Unix seconds; conversions happen at those
//! boundaries. Callers drive the core by arming a timer for the instant
//! returned by [`Node::next_deadline`] and delivering [`Event::Tick`] then;
//! there is no periodic tick.

#![forbid(unsafe_code)]

pub mod cidr;
mod error;
mod frame_budget;
pub mod graph;
mod neighbor;
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
