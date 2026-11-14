//! Lattice local-API client.
//!
//! Synchronous client for the daemon's application socket: hello, send, status,
//! fetch, ack, lookup, and events. Used by embedders and by lattice-client-based
//! tests; applications other than Rust use their own client (see clients/).
//!

#![forbid(unsafe_code)]
