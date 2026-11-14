//! Lattice network transport: Noise (IK/XX) inside a WebSocket, bucket
//! padding for every frame, cookie-based anti-exhaustion under load, and a
//! probe-resistant listener (derived upgrade path, opaque 404 otherwise,
//! optional /status).

#![forbid(unsafe_code)]

pub mod client;
pub mod cookie;
pub mod dial;
pub mod errors;
pub mod frame;
pub mod handshake;
pub mod path;
pub mod peer;
pub mod server;

pub use client::{PeerContact, connect};
pub use dial::{EndpointUrl, connect_scoped, parse_endpoint, scoped_addresses};
pub use errors::NetError;
pub use frame::{FRAME_BUCKETS, FrameError, decode_wire, encode_wire};
pub use path::upgrade_path;
pub use peer::PeerIo;
pub use server::{ListenerConfig, serve};

pub const MAX_WIRE_BYTES: usize = 40 * 1024;
