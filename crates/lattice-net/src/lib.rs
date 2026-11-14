//! Lattice network transport.
//!
//! Noise (IK/XX) inside a WebSocket, wire-size enforcement before assembly,
//! cookie mode under load, connect-time scope checks, endpoint proving, the
//! /status endpoint and the derived upgrade path. All protocol decisions are
//! delegated to lattice-core; this crate frames and moves bytes.
//!

#![forbid(unsafe_code)]
