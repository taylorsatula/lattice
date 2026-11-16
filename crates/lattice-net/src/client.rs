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

pub enum PeerContact {
    Ik {
        addr: SocketAddr,
        channel_key: ChannelPublicKey,
    },
    Xx {
        addr: SocketAddr,
        path: String,
    },
}

pub async fn connect(contact: PeerContact, channel_seed: &ChannelSeed) -> Result<PeerIo, NetError> {
    let (addr, path, mut hs, mac_key) = match &contact {
        PeerContact::Ik { addr, channel_key } => (
            *addr,
            crate::upgrade_path(channel_key),
            Pending::initiator_ik(channel_seed, channel_key)
                .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?,
            Some(*channel_key),
        ),
        PeerContact::Xx { addr, path } => (
            *addr,
            path.clone(),
            Pending::initiator_xx(channel_seed)
                .map_err(|e| NetError::Handshake(HandshakeError::Snow(e)))?,
            None,
        ),
    };

    crate::path::validate_upgrade_path(&path)?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| NetError::Timeout)?
        .map_err(NetError::Io)?;
    let _ = crate::set_tcp_keepalive(&tcp);
    let boxed: crate::peer::BoxedStream = Box::pin(tcp);
    let request = Request::builder()
        .uri(format!("ws://{addr}{path}"))
        .header("Host", addr.to_string())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|e| NetError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
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
    Ok(PeerIo::new(ws, transport, remote_static))
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
