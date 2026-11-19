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
pub mod prefix;
pub mod server;

pub use client::{DialTarget, PeerContact, connect};
pub use dial::{EndpointUrl, Scheme, connect_scoped, parse_endpoint, scoped_addresses};
pub use errors::NetError;
pub use frame::{FRAME_BUCKETS, FrameError, decode_wire, encode_wire, encode_wire_to_bucket};
pub use path::{upgrade_path, validate_upgrade_path};
pub use peer::PeerIo;
pub use prefix::{SourcePrefix, prefix_of};
pub use server::{ListenerConfig, ServeHandle, serve};

/// Largest post-handshake wire message: the 32768-byte bucket plus the
/// 16-byte Poly1305 tag. Handshake frames are padded to 2048 and capped
/// separately (see handshake.rs).
pub const MAX_WIRE_BYTES: usize = 32768 + 16;

/// Enable TCP keepalive on a connected socket: probe after 60s idle, then
/// every 10s, giving up after 3 unanswered probes (~90s to detect a dead
/// peer). This is the half-open detector for the mesh; without it a silently
/// dead peer holds its slot forever (there is no application-level ping —
/// the core echoes Ping frames, so a transport keepalive must live below
/// the protocol).
pub fn set_tcp_keepalive(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    let ka = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(10))
        .with_retries(3);
    socket2::SockRef::from(stream).set_tcp_keepalive(&ka)
}
