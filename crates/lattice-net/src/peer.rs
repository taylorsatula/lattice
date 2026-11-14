//! PeerIo: a post-handshake, framed connection to one neighbor.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use lattice_proto::frames::Frame;
use snow::TransportState;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

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
    pub remote_static: [u8; 32],
}

impl PeerIo {
    pub(crate) fn new(
        ws: WebSocketStream<BoxedStream>,
        transport: TransportState,
        remote_static: [u8; 32],
    ) -> Self {
        Self {
            ws,
            transport,
            remote_static,
        }
    }

    pub async fn send_frame(
        &mut self,
        frame: &Frame,
        pad_to: Option<usize>,
    ) -> Result<(), NetError> {
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
            .map_err(|_| NetError::Crypto)?;
        buf.truncate(n);
        debug_assert!(buf.len() <= MAX_WIRE_BYTES);
        self.ws
            .send(Message::Binary(Bytes::from(buf)))
            .await
            .map_err(|_| NetError::Io)?;
        Ok(())
    }

    pub async fn recv_frame(&mut self) -> Result<Option<Frame>, NetError> {
        {
            let msg = match self.ws.next().await {
                None => return Ok(None),
                Some(Err(_)) => return Err(NetError::Io),
                Some(Ok(m)) => m,
            };
            let Message::Binary(bytes) = msg else {
                // Close frames and control frames end the stream from our side.
                return Ok(None);
            };
            if bytes.len() > MAX_WIRE_BYTES {
                return Err(NetError::FrameTooLarge);
            }
            let mut plaintext = vec![0u8; bytes.len()];
            let n = self
                .transport
                .read_message(&bytes, &mut plaintext)
                .map_err(|_| NetError::Crypto)?;
            plaintext.truncate(n);
            let inner = decode_wire(&plaintext).map_err(|_| NetError::BadWire)?;
            let frame = Frame::from_bytes(&inner).map_err(|_| NetError::BadFrame)?;
            Ok(Some(frame))
        }
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}
