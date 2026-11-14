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

use crate::cookie::{mac1, mac2};
use crate::errors::NetError;
use crate::handshake::{Pending, encode_handshake_frame};
use crate::peer::PeerIo;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub enum PeerContact {
    Ik {
        addr: SocketAddr,
        channel_key: [u8; 32],
    },
    Xx {
        addr: SocketAddr,
        path: String,
    },
}

pub async fn connect(contact: PeerContact, channel_seed: &[u8; 32]) -> Result<PeerIo, NetError> {
    let (addr, path, mut hs, mac_key) = match &contact {
        PeerContact::Ik { addr, channel_key } => (
            *addr,
            crate::upgrade_path(channel_key),
            Pending::initiator_ik(channel_seed, channel_key).map_err(|_| NetError::Handshake)?,
            Some(*channel_key),
        ),
        PeerContact::Xx { addr, path } => (
            *addr,
            path.clone(),
            Pending::initiator_xx(channel_seed).map_err(|_| NetError::Handshake)?,
            None,
        ),
    };

    let tcp = TcpStream::connect(addr).await.map_err(|_| NetError::Io)?;
    let boxed: crate::peer::BoxedStream = Box::pin(tcp);
    let request = Request::builder()
        .uri(format!("ws://{addr}{path}"))
        .header("Host", addr.to_string())
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .body(())
        .map_err(|_| NetError::Io)?;
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_frame_size(Some(crate::MAX_WIRE_BYTES + 64))
        .max_message_size(Some(crate::MAX_WIRE_BYTES + 64));
    let (mut ws, _) = tokio_tungstenite::client_async_with_config(request, boxed, Some(ws_config))
        .await
        .map_err(|_| NetError::Io)?;

    let msg1 = hs.write_message(&[]).map_err(|_| NetError::Handshake)?;
    let mac1_bytes = match &mac_key {
        Some(k) => mac1(k, &msg1),
        None => [0u8; 16],
    };
    send_init(&mut ws, &msg1, mac1_bytes, None).await?;

    // Handshake loop: expect Cookie (optional) then Resp.
    let mut cookie: Option<[u8; crate::cookie::COOKIE_BYTES]> = None;
    let resp_noise = loop {
        let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, ws.next())
            .await
            .map_err(|_| NetError::Timeout)?
            .ok_or(NetError::Io)?
            .map_err(|_| NetError::Io)?;
        let Message::Binary(bytes) = msg else {
            return Err(NetError::UnexpectedFrame);
        };
        let frame = parse_frame(&bytes)?;
        match frame {
            Frame::Cookie(c) => {
                if c.cookie.len() != crate::cookie::COOKIE_BYTES {
                    return Err(NetError::BadCookie);
                }
                let mut ck = [0u8; crate::cookie::COOKIE_BYTES];
                ck.copy_from_slice(&c.cookie);
                // Re-send the same init with mac2 filled in.
                send_init(&mut ws, &msg1, mac1_bytes, Some(mac2(&ck, &msg1))).await?;
                cookie = Some(ck);
            }
            Frame::Resp(r) => break r.noise_msg,
            _ => return Err(NetError::UnexpectedFrame),
        }
    };
    let _ = cookie;

    // IK: one response completes the handshake. XX: one more client message.
    let _ = hs
        .read_message(&resp_noise)
        .map_err(|_| NetError::Handshake)?;
    if matches!(contact, PeerContact::Xx { .. }) {
        let msg3 = hs.write_message(&[]).map_err(|_| NetError::Handshake)?;
        let mac1_3 = match &mac_key {
            Some(k) => mac1(k, &msg3),
            None => [0u8; 16],
        };
        send_init(&mut ws, &msg3, mac1_3, None).await?;
    }

    let remote_static: [u8; 32] = hs
        .remote_static()
        .ok_or(NetError::Handshake)?
        .try_into()
        .map_err(|_| NetError::Handshake)?;

    // IK mode pins the responder static to the record's channel key.
    if let PeerContact::Ik { channel_key, .. } = &contact {
        if &remote_static != channel_key {
            return Err(NetError::Handshake);
        }
    }

    let transport = hs.finish().map_err(|_| NetError::Handshake)?;
    Ok(PeerIo::new(ws, transport, remote_static))
}

fn parse_frame(bytes: &[u8]) -> Result<Frame, NetError> {
    let v = lattice_proto::decode(bytes).map_err(|_| NetError::BadFrame)?;
    Frame::from_value(&v).map_err(|_| NetError::BadFrame)
}

async fn send_init(
    ws: &mut WsStream,
    noise_msg: &[u8],
    mac1: [u8; 16],
    mac2: Option<[u8; 16]>,
) -> Result<(), NetError> {
    let frame = Frame::Init(InitFrame {
        noise_msg: noise_msg.to_vec(),
        mac1,
        mac2,
        padding: vec![],
    });
    // Handshake frames are padded to the 2 KB bucket.
    let bytes = encode_handshake_frame(&frame).ok_or(NetError::BadFrame)?;
    ws.send(Message::Binary(Bytes::from(bytes)))
        .await
        .map_err(|_| NetError::Io)
}
