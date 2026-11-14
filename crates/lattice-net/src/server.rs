//! The listener: probe-resistant upgrade, /status, and the Noise handshake.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use lattice_proto::frames::{CookieFrame, Frame, InitFrame, RespFrame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

use subtle::ConstantTimeEq;

use crate::cookie::{CookieState, mac1};
use crate::errors::NetError;
use crate::handshake::{Pending, XX_MSG1_LEN, encode_handshake_frame};
use crate::peer::PeerIo;

const MAX_HEAD: usize = 8192;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections above this many in flight (pre-auth) set the under-load
/// flag; it clears only when the count drops below [`PREAUTH_LOW_WATER`].
/// Hysteresis avoids flapping at the boundary.
pub const PREAUTH_HIGH_WATER: u64 = 64;
/// See [`PREAUTH_HIGH_WATER`].
pub const PREAUTH_LOW_WATER: u64 = 32;
/// Hard cap on concurrent connections (pre- and post-handshake). Excess
/// connections are closed immediately, not queued.
pub const MAX_CONNECTIONS: u64 = 1024;

pub struct ListenerConfig {
    /// This node's static X25519 channel key seed (32 bytes).
    pub channel_seed: [u8; 32],
    /// Serve `GET /status` on the same listener.
    pub status_enabled: bool,
    /// Drain flag shared with the daemon: when set, `/status` reports
    /// `accepting = false`. The daemon sets this on drain and on signal.
    pub draining: Arc<std::sync::atomic::AtomicBool>,
    /// Force cookie-required mode regardless of load. Intended for tests;
    /// production leaves this false and lets the pre-auth counter decide.
    pub force_under_load: bool,
    /// Called once per established peer.
    pub on_peer: mpsc::UnboundedSender<PeerIo>,
}

/// Shared load state for one listener. `under_load` is derived from the
/// pre-auth in-flight counter with hysteresis; `force_under_load` (config)
/// overrides it. Only the boolean is ever exposed (via /status), never the
/// raw count.
struct LoadState {
    preauth_inflight: std::sync::atomic::AtomicU64,
    total_connections: std::sync::atomic::AtomicU64,
    under_load: std::sync::atomic::AtomicBool,
    force_under_load: bool,
}

impl LoadState {
    fn new(force_under_load: bool) -> Self {
        Self {
            preauth_inflight: std::sync::atomic::AtomicU64::new(0),
            total_connections: std::sync::atomic::AtomicU64::new(0),
            under_load: std::sync::atomic::AtomicBool::new(force_under_load),
            force_under_load,
        }
    }
    fn under_load(&self) -> bool {
        self.force_under_load || self.under_load.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn preauth_enter(&self) -> u64 {
        let n = self
            .preauth_inflight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if n > PREAUTH_HIGH_WATER {
            self.under_load
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        n
    }
    fn preauth_leave(&self) {
        let n = self
            .preauth_inflight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
            - 1;
        if n < PREAUTH_LOW_WATER {
            self.under_load
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }
    /// Try to admit a new connection. Returns false when at capacity.
    fn admit(&self) -> bool {
        let n = self
            .total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        if n > MAX_CONNECTIONS {
            self.total_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return false;
        }
        true
    }
    fn release(&self) {
        self.total_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Decrements the total connection count on drop.
struct ConnGuard(Arc<LoadState>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Decrements the pre-auth in-flight count on drop.
struct PreAuthGuard(Arc<LoadState>);
impl Drop for PreAuthGuard {
    fn drop(&mut self) {
        self.0.preauth_leave();
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A TCP stream whose first bytes were already peeked for HTTP parsing.
struct PrefixedStream {
    prefix: Vec<u8>,
    inner: TcpStream,
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let data = self.prefix.drain(..n).collect::<Vec<u8>>();
            buf.put_slice(&data);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct HeadParsed {
    method: String,
    path: String,
}

fn head_has_header(head: &[u8], name: &str, value_substr: &str) -> bool {
    let text = String::from_utf8_lossy(head).to_ascii_lowercase();
    text.lines().skip(1).any(|line| match line.split_once(':') {
        Some((k, v)) => k.trim() == name && v.to_ascii_lowercase().contains(value_substr),
        None => false,
    })
}

fn parse_head(head: &[u8]) -> Option<HeadParsed> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    if method.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some(HeadParsed { method, path })
}

async fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(pos) = find_double_crlf(&buf) {
            return Some(buf[..pos].to_vec());
        }
        if buf.len() >= MAX_HEAD {
            return None;
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Serve one listener forever. Returns the bound address immediately.
pub async fn serve(
    cfg: ListenerConfig,
    bind: Vec<SocketAddr>,
) -> io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(&bind[..]).await?;
    let local = listener.local_addr()?;
    let cookie_state = Arc::new(Mutex::new(CookieState::new(now_secs())));
    let load = Arc::new(LoadState::new(cfg.force_under_load));
    let cfg = Arc::new(cfg);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = crate::set_tcp_keepalive(&stream);
            if !load.admit() {
                // At capacity: close immediately rather than queue.
                drop(stream);
                continue;
            }
            let _conn_guard = ConnGuard(load.clone());
            let cfg = cfg.clone();
            let cookie_state = cookie_state.clone();
            let load = load.clone();
            tokio::spawn(async move {
                let _conn_guard = _conn_guard;
                match handle_conn(stream, peer, cfg.clone(), cookie_state, load).await {
                    Ok(peer_io) => {
                        let _ = cfg.on_peer.send(peer_io);
                    }
                    Err(_) => {
                        // Probes, wrong paths and aborted handshakes are routine.
                    }
                }
            });
        }
    });
    Ok((local, handle))
}

#[allow(clippy::result_large_err)] // tungstenite's ErrorResponse is the fixed callback signature
async fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<ListenerConfig>,
    cookie_state: Arc<Mutex<CookieState>>,
    load: Arc<LoadState>,
) -> Result<PeerIo, NetError> {
    load.preauth_enter();
    let _preauth = PreAuthGuard(load.clone());
    cookie_state.lock().unwrap().tick();
    let head = read_head(&mut stream).await.ok_or(NetError::Io)?;
    let parsed = parse_head(&head).ok_or(NetError::Io)?;
    let derived = crate::upgrade_path(&lattice_crypto::x25519_public(&cfg.channel_seed));

    if parsed.path == "/status" && cfg.status_enabled && parsed.method == "GET" {
        let draining = cfg.draining.load(std::sync::atomic::Ordering::Relaxed);
        let accepting = !draining && !load.under_load();
        let body = lattice_proto::local::encode_status(true, accepting, &[1]);
        let resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/cbor\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let mut out = resp.into_bytes();
        out.extend_from_slice(&body);
        let _ = stream.write_all(&out).await;
        let _ = stream.shutdown().await;
        return Err(NetError::Io); // connection handled; not a peer
    }

    let is_upgrade = head_has_header(&head, "upgrade", "websocket")
        && head_has_header(&head, "connection", "upgrade");
    if parsed.method != "GET" || parsed.path != derived || !is_upgrade {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 9\r\nconnection: close\r\n\r\nnot found").await;
        return Err(NetError::Io);
    }

    let prefixed = PrefixedStream {
        prefix: head,
        inner: stream,
    };
    let boxed: crate::peer::BoxedStream = Box::pin(prefixed);
    let expected = derived.clone();
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_frame_size(Some(crate::MAX_WIRE_BYTES + 64))
        .max_message_size(Some(crate::MAX_WIRE_BYTES + 64));
    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        boxed,
        move |req: &Request, resp: Response| {
            if req.uri().path() == expected {
                Ok(resp)
            } else {
                Err(Response::builder()
                    .status(404)
                    .body(Some("not found".into()))
                    .unwrap())
            }
        },
        Some(ws_config),
    )
    .await
    .map_err(|_| NetError::Handshake)?;

    handshake_server(ws, peer, &cfg, &cookie_state, &load).await
}

async fn next_binary(
    ws: &mut WebSocketStream<crate::peer::BoxedStream>,
) -> Result<Vec<u8>, NetError> {
    let fut = ws.next();
    let msg = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| NetError::Timeout)?
        .ok_or(NetError::Io)?
        .map_err(|_| NetError::Io)?;
    match msg {
        Message::Binary(b) => Ok(b.to_vec()),
        _ => Err(NetError::UnexpectedFrame),
    }
}

fn parse_init(ws_msg: &[u8]) -> Result<InitFrame, NetError> {
    let v = lattice_proto::decode(ws_msg).map_err(|_| NetError::BadFrame)?;
    match Frame::from_value(&v).map_err(|_| NetError::BadFrame)? {
        Frame::Init(i) => Ok(i),
        _ => Err(NetError::UnexpectedFrame),
    }
}

async fn handshake_server(
    mut ws: WebSocketStream<crate::peer::BoxedStream>,
    peer: SocketAddr,
    cfg: &ListenerConfig,
    cookie_state: &Arc<Mutex<CookieState>>,
    load: &LoadState,
) -> Result<PeerIo, NetError> {
    let addr_bytes = peer.to_string().into_bytes();
    let under_load = load.under_load();

    // First init, possibly preceded by a cookie exchange.
    let init_msg = next_binary(&mut ws).await?;
    let mut init = parse_init(&init_msg)?;
    let is_xx = init.noise_msg.len() == XX_MSG1_LEN;
    if !is_xx {
        let mac1_ok = bool::from(
            mac1(
                &lattice_crypto::x25519_public(&cfg.channel_seed),
                &init.noise_msg,
            )
            .ct_eq(&init.mac1),
        );
        if !mac1_ok {
            return Err(NetError::BadMac);
        }
    }
    if under_load {
        let ok = match &init.mac2 {
            Some(m2) => cookie_state
                .lock()
                .unwrap()
                .verify_mac2(&addr_bytes, &init.noise_msg, m2),
            None => false,
        };
        if !ok {
            let cookie = cookie_state.lock().unwrap().issue(&addr_bytes);
            let frame = Frame::Cookie(CookieFrame {
                cookie,
                padding: vec![],
            });
            ws.send(Message::Binary(Bytes::from(
                encode_handshake_frame(&frame).ok_or(NetError::BadFrame)?,
            )))
            .await
            .map_err(|_| NetError::Io)?;
            let retry = next_binary(&mut ws).await?;
            init = parse_init(&retry)?;
            if init.noise_msg.len() != 32
                && !bool::from(
                    mac1(
                        &lattice_crypto::x25519_public(&cfg.channel_seed),
                        &init.noise_msg,
                    )
                    .ct_eq(&init.mac1),
                )
            {
                return Err(NetError::BadMac);
            }
            let ok2 = match &init.mac2 {
                Some(m2) => {
                    cookie_state
                        .lock()
                        .unwrap()
                        .verify_mac2(&addr_bytes, &init.noise_msg, m2)
                }
                None => false,
            };
            if !ok2 {
                return Err(NetError::BadCookie);
            }
        }
    }

    // Choose pattern by first-message length: XX msg1 = 32 bytes; IK msg1 is longer.
    let (mut hs, pattern) = if init.noise_msg.len() == XX_MSG1_LEN {
        (
            Pending::responder_xx(&cfg.channel_seed).map_err(|_| NetError::Handshake)?,
            "xx",
        )
    } else {
        (
            Pending::responder_ik(&cfg.channel_seed).map_err(|_| NetError::Handshake)?,
            "ik",
        )
    };

    if let Err(e) = hs.read_message(&init.noise_msg) {
        eprintln!("[lattice-net] responder read failed: {e:?}");
        return Err(NetError::Handshake);
    }
    let resp_bytes = match hs.write_message(&[]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[lattice-net] responder write failed: {e:?}");
            return Err(NetError::Handshake);
        }
    };
    let resp = RespFrame {
        noise_msg: resp_bytes.clone(),
        padding: vec![],
    };
    ws.send(Message::Binary(Bytes::from(
        encode_handshake_frame(&Frame::Resp(resp)).ok_or(NetError::BadFrame)?,
    )))
    .await
    .map_err(|_| NetError::Io)?;

    if pattern == "xx" {
        // Third leg of XX: initiator's static delivery. No mac1 — the
        // initiator cannot know our channel key; Noise authenticates it.
        let msg3 = next_binary(&mut ws).await?;
        let init3 = parse_init(&msg3)?;
        let _ = hs
            .read_message(&init3.noise_msg)
            .map_err(|_| NetError::Handshake)?;
    }

    debug_assert!(hs.is_finished());
    let remote_static: [u8; 32] = hs
        .remote_static()
        .ok_or(NetError::Handshake)?
        .try_into()
        .map_err(|_| NetError::Handshake)?;
    let transport = hs.finish().map_err(|_| NetError::Handshake)?;
    Ok(PeerIo::new(ws, transport, remote_static))
}
