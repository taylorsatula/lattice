//! PeerIo: a post-handshake, framed connection to one neighbor.
//!
//! Wire posture: no WebSocket control frames in either direction. Every
//! frame we send is Binary. Any non-binary frame we receive tears the link
//! down. tungstenite 0.30 cannot be configured to suppress its automatic
//! Pong (on Ping) or Close reply (on Close) — `WebSocketConfig` has no such
//! switch, and the reply is queued inside the socket and flushed by the
//! next read/write/flush — so the guarantee is enforced by never touching
//! the socket again after a non-binary frame arrives (see `poisoned`).

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use lattice_proto::frames::Frame;
use snow::TransportState;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use lattice_types::X25519PublicKey;

use crate::frame::{decode_wire, encode_wire, encode_wire_to_bucket};
use crate::{MAX_WIRE_BYTES, errors::NetError};

/// Type-erased async stream so server-side (peeked) and client-side
/// connections produce one PeerIo type.
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + ?Sized> AsyncReadWrite for T {}
pub type BoxedStream = std::pin::Pin<Box<dyn AsyncReadWrite + Send>>;

pub struct PeerIo {
    ws: WebSocketStream<BoxedStream>,
    transport: TransportState,
    pub remote_static: X25519PublicKey,
    /// Set when a non-binary frame is received. tungstenite 0.30 queues an
    /// automatic Pong (on Ping) or Close reply (on Close) inside the socket
    /// and flushes it on the next read/write/flush; there is no config to
    /// disable this. Once poisoned, no further operation may touch the
    /// socket, so a queued control frame can never reach the wire.
    poisoned: bool,
}

impl PeerIo {
    pub(crate) fn new(
        ws: WebSocketStream<BoxedStream>,
        transport: TransportState,
        remote_static: X25519PublicKey,
    ) -> Self {
        Self {
            ws,
            transport,
            remote_static,
            poisoned: false,
        }
    }

    pub async fn send_frame(
        &mut self,
        frame: &Frame,
        pad_to: Option<usize>,
    ) -> Result<(), NetError> {
        if self.poisoned {
            return Err(NetError::Closed);
        }
        let inner = lattice_proto::encode(&frame.to_value());
        let plaintext = match pad_to {
            Some(bucket) => encode_wire_to_bucket(&inner, bucket),
            None => encode_wire(&inner),
        }
        .map_err(|_| NetError::FrameTooLarge)?;
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(&plaintext, &mut buf)
            .map_err(NetError::Crypto)?;
        buf.truncate(n);
        debug_assert!(buf.len() <= MAX_WIRE_BYTES);
        self.ws
            .send(Message::Binary(Bytes::from(buf)))
            .await
            .map_err(NetError::WebSocket)?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, NetError> {
        {
            let msg = match self.ws.next().await {
                None => return Ok(None),
                Some(Err(e)) => return Err(NetError::WebSocket(e)),
                Some(Ok(m)) => m,
            };
            let Message::Binary(bytes) = msg else {
                // No control frames in either direction. Any non-binary
                // frame (Ping, Pong, Close, Text) tears the link down.
                // tungstenite 0.30 has no option to disable its automatic
                // Pong/Close replies (WebSocketConfig carries no such
                // switch); they are queued inside the socket and flushed by
                // the next read/write/flush. Poisoning the link here
                // guarantees no such flush ever happens, so the reply never
                // reaches the wire.
                eprintln!("[lattice-net] closing link: non-binary WebSocket frame received");
                self.poisoned = true;
                return Ok(None);
            };
            if bytes.len() > MAX_WIRE_BYTES {
                return Err(NetError::FrameTooLarge);
            }
            let mut plaintext = vec![0u8; bytes.len()];
            let n = self
                .transport
                .read_message(&bytes, &mut plaintext)
                .map_err(NetError::Crypto)?;
            plaintext.truncate(n);
            let inner = decode_wire(&plaintext).map_err(NetError::BadWire)?;
            let frame = Frame::from_bytes(&inner).map_err(NetError::BadFrame)?;
            Ok(Some(frame))
        }
    }

    pub async fn close(mut self) {
        if self.poisoned {
            // A close handshake would flush any queued Pong/Close reply;
            // drop the socket instead.
            return;
        }
        let _ = self.ws.close(None).await;
    }
}
