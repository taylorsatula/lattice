//! Lattice protocol core, sans I/O.
//!
//! A state machine fed by events (frame arrived, timer fired, application sent)
//! returning actions (send frame, store, deliver). Time, randomness and storage
//! are injected, so the same core runs under the simulator and the daemon.
//! Implements gossip, routing, custody, receipts, fair-share custody, snow,
//! gateways, key lifecycle and the immune system. Never touches a socket, the
//! clock, or the heap through any path that bypasses the injected seams.
//!

#![forbid(unsafe_code)]
