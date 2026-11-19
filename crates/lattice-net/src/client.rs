//! The dialing side: derive the upgrade path, complete the Noise handshake,
//! return an established PeerIo.
//!
//! Two modes:
//! - `Ik { channel_key }`: responder's record known; path is derived from it
//!   and mac1 is computable. IK handshake, one round trip.
//! - `Xx { path }`: bare root with an operator-supplied path; handshake is XX.
//!   mac1 is sent as zeros; the derived upgrade path is the gate, and the
//!   optional cookie flow applies under load.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use futures_util::SinkExt;
use futures_util::StreamExt;
use lattice_proto::frames::{Frame, InitFrame};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::client::{Request, generate_key};

type WsStream = WebSocketStream<crate::peer::BoxedStream>;

use lattice_types::{ChannelPublicKey, ChannelSeed, Mac16, X25519PublicKey};

use crate::cookie::{mac1, mac2};
use crate::errors::{HandshakeError, NetError};
use crate::handshake::{Pending, encode_handshake_frame};
use crate::peer::PeerIo;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
// A black-holed peer must not hold the dial for the OS connect timeout
// (~75-130s); fail fast so the caller can retry on its own schedule.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where to dial and how to address the peer in the HTTP upgrade.
///
/// `addr` is the resolved address to connect to. `host` is the value for
/// the `Host` header (the endpoint URL's host, not the resolved address);
/// `path_prefix` is prepended to the derived upgrade path in the request
/// line; `tls` selects `wss://` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialTarget {
    pub addr: SocketAddr,
    /// `Host` header value: the URL's host (bracketed if IPv6), with
    /// `:port` appended when it is not the scheme's default.
    pub host: String,
    /// URL path prefix prepended to the derived upgrade path ("" when none).
    pub path_prefix: String,
    /// `wss://` endpoint: the TCP stream must be wrapped in TLS before the
    /// WebSocket handshake. The certificate is not validated; Noise
    /// authenticates the peer.
    pub tls: bool,
}

impl DialTarget {
    /// A plain `ws://` target with no path prefix (e.g. configured roots):
    /// the `Host` header is the address itself.
    pub fn plain(addr: SocketAddr) -> Self {
        Self {
            addr,
            host: addr.to_string(),
            path_prefix: String::new(),
            tls: false,
        }
    }
}

pub enum PeerContact {
    Ik {
        target: DialTarget,
        channel_key: ChannelPublicKey,
    },
    Xx {
        target: DialTarget,
        path: String,
    },
}

pub async fn connect(contact: PeerContact, channel_seed: &ChannelSeed) -> Result<PeerIo, NetError> {
    let (target, path, mut hs, mac_key) = match &contact {
        PeerContact::Ik {
            target,
            channel_key,
        } => {
            let derived = crate::upgrade_path(channel_key);
            let path = format!("{}{}", target.path_prefix, derived);
            let prologue = crate::handshake::prologue(&path);
            (
                target,
                path,
                Pending::initiator_ik(channel_seed, channel_key, &prologue)
                    .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?,
                Some(*channel_key),
            )
        }
        PeerContact::Xx { target, path } => {
            crate::path::validate_upgrade_path(path)?;
            let full = format!("{}{}", target.path_prefix, path);
            let prologue = crate::handshake::prologue(&full);
            (
                target,
                full,
                Pending::initiator_xx(channel_seed, &prologue)
                    .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?,
                None,
            )
        }
    };

    if target.tls {
        // No TLS stack is linked into this build; refusing here rather than
        // falling back to a plaintext handshake keeps wss:// from silently
        // downgrading. The Noise layer would still authenticate the peer,
        // but the operator asked for an outer TLS wrapper.
        return Err(NetError::InvalidInput(
            "wss:// endpoints require a TLS stack, which this build does not include",
        ));
    }
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target.addr))
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(NetError::Io)?;
    let _ = crate::set_tcp_keepalive(&tcp);
    let boxed: crate::peer::BoxedStream = Box::pin(tcp);
    let request = build_request(target, &path)?;
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_frame_size(Some(crate::MAX_WIRE_BYTES + 64))
        .max_message_size(Some(crate::MAX_WIRE_BYTES + 64));
    let (mut ws, _) = tokio_tungstenite::client_async_with_config(request, boxed, Some(ws_config))
        .await
        .map_err(NetError::WebSocket)?;

    let msg1 = hs
        .write_message(&[])
        .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?;
    let mac1_bytes = match &mac_key {
        Some(k) => mac1(k, &msg1),
        None => Mac16::from_bytes([0u8; 16]),
    };
    send_init(&mut ws, &msg1, mac1_bytes, None).await?;

    // Handshake loop: expect Cookie (optional) then Resp.
    let resp_noise = loop {
        let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws.next())
            .await
            .map_err(|_| NetError::Timeout)?
            .ok_or_else(|| {
                NetError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed during handshake",
                ))
            })?
            .map_err(NetError::WebSocket)?;
        let Message::Binary(bytes) = msg else {
            // No control frames: drop the socket without further writes so a
            // queued automatic Pong/Close reply is never flushed.
            eprintln!("[lattice-net] handshake: non-binary WebSocket frame received; closing");
            return Err(NetError::UnexpectedFrame);
        };
        let frame = parse_frame(&bytes)?;
        match frame {
            Frame::Cookie(c) => {
                // Re-send the same init with mac2 filled in.
                send_init(&mut ws, &msg1, mac1_bytes, Some(mac2(&c.cookie, &msg1))).await?;
            }
            Frame::Resp(r) => break r.noise_msg,
            _ => return Err(NetError::UnexpectedFrame),
        }
    };
    // IK: one response completes the handshake. XX: one more client message.
    let _ = hs
        .read_message(&resp_noise)
        .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?;
    if matches!(contact, PeerContact::Xx { .. }) {
        let msg3 = hs
            .write_message(&[])
            .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?;
        let mac1_3 = match &mac_key {
            Some(k) => mac1(k, &msg3),
            None => Mac16::from_bytes([0u8; 16]),
        };
        send_init(&mut ws, &msg3, mac1_3, None).await?;
    }

    let remote_static = X25519PublicKey::from_bytes(
        hs.remote_static()
            .ok_or(NetError::Handshake(HandshakeError::RemoteStatic))?
            .as_slice()
            .try_into()
            .map_err(|_| NetError::Handshake(HandshakeError::RemoteStatic))?,
    );

    // IK mode pins the responder static to the record's channel key
    // (Ed25519; the handshake runs on the derived X25519 key).
    if let PeerContact::Ik { channel_key, .. } = &contact {
        let expected = lattice_crypto::channel_x25519_public_from_ed25519(channel_key)
            .ok_or(NetError::Handshake(HandshakeError::ChannelKey))?;
        if remote_static != expected {
            return Err(NetError::Handshake(HandshakeError::PeerMismatch));
        }
    }

    let transport = hs
        .finish()
        .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?;
    Ok(PeerIo::new(ws, transport, remote_static, target.addr))
}

/// Build the upgrade request. The request-target path is `path` (the URL's
/// path prefix followed by the derived upgrade path); the `Host` header
/// carries the endpoint URL's host, not the resolved address, so fronts
/// that route by name see the name they expect.
fn build_request(target: &DialTarget, path: &str) -> Result<Request, NetError> {
    let scheme = if target.tls { "wss" } else { "ws" };
    let uri = format!("{scheme}://{}{path}", target.host);
    Request::builder()
        .uri(uri)
        .header("Host", &target.host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| NetError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))
}

fn parse_frame(bytes: &[u8]) -> Result<Frame, NetError> {
    let v = lattice_proto::decode(bytes).map_err(|e| NetError::BadFrame(e.into()))?;
    Frame::from_value(&v).map_err(NetError::BadFrame)
}

async fn send_init(
    ws: &mut WsStream,
    noise_msg: &[u8],
    mac1: Mac16,
    mac2: Option<Mac16>,
) -> Result<(), NetError> {
    let frame = Frame::Init(InitFrame {
        noise_msg: noise_msg.to_vec(),
        mac1,
        mac2,
        padding: vec![],
    });
    // Handshake frames are padded to the 2 KB bucket.
    let bytes = encode_handshake_frame(&frame).ok_or(NetError::FrameTooLarge)?;
    ws.send(Message::Binary(Bytes::from(bytes)))
        .await
        .map_err(NetError::WebSocket)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(host: &str, port: u16, path_prefix: &str, tls: bool) -> DialTarget {
        DialTarget {
            addr: SocketAddr::new("192.0.2.1".parse().unwrap(), port),
            host: host.to_string(),
            path_prefix: path_prefix.to_string(),
            tls,
        }
    }

    #[test]
    fn request_carries_url_host_not_resolved_addr() {
        // The resolved address is unrelated to the URL host (e.g. DNS or a
        // front); the Host header must carry the URL's host.
        let t = target("front.example.com", 443, "", false);
        let req = build_request(&t, "/k7f3").unwrap();
        assert_eq!(req.headers()["Host"], "front.example.com");
        assert_eq!(req.uri().path(), "/k7f3");
    }

    #[test]
    fn request_appends_url_path_prefix_to_upgrade_path() {
        let t = target("front.example.com", 443, "/lattice", false);
        let req = build_request(&t, "/lattice/k7f3").unwrap();
        assert_eq!(req.uri().path(), "/lattice/k7f3");
        assert_eq!(req.headers()["Host"], "front.example.com");
    }

    #[test]
    fn request_host_includes_non_default_port() {
        let t = target("front.example.com:8443", 8443, "", false);
        let req = build_request(&t, "/k7f3").unwrap();
        assert_eq!(req.headers()["Host"], "front.example.com:8443");
    }

    #[test]
    fn request_host_brackets_ipv6() {
        let t = target("[2001:4860:4860::8888]:8443", 8443, "", false);
        let req = build_request(&t, "/k7f3").unwrap();
        assert_eq!(req.headers()["Host"], "[2001:4860:4860::8888]:8443");
        assert_eq!(req.uri().path(), "/k7f3");
    }

    #[tokio::test]
    async fn wss_target_is_refused_before_any_network_io() {
        // No TLS stack is linked into this build; a wss:// target must fail
        // fast with a clear error rather than fall back to plaintext.
        let seed = ChannelSeed::from_bytes([0xA1; 32]);
        let t = target("front.example.com", 443, "", true);
        let contact = PeerContact::Ik {
            target: t,
            channel_key: lattice_crypto::channel_public(&ChannelSeed::from_bytes([0xB2; 32])),
        };
        let err = match connect(contact, &seed).await {
            Ok(_) => panic!("wss:// must not connect without a TLS stack"),
            Err(e) => e,
        };
        assert!(matches!(err, NetError::InvalidInput(_)));
    }
}
