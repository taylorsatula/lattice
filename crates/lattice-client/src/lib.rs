//! Lattice local-API client.
//!
//! Talks to a running `latticed` over its Unix sockets: the application
//! socket (service-authenticated) or the admin socket (owner-only). Wire
//! format is the spec's length-prefixed CBOR (`lattice_proto::local`).
//!
//! This client only ever sees local-API frames; it never parses network
//! frames (`offer`, `custody`, `reconcile`, `kels`, …), so the v1 frame set
//! cannot trip it. The custody result codes are re-exported below for
//! callers that interpret wire-level diagnostics.
//!
//! Application events (`inbox`, `status`) arrive interleaved with responses;
//! [`Client::call`] stashes them and they can be drained with
//! [`Client::take_events`] or awaited with [`Client::next_event`].

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::path::Path;

use lattice_proto::local::{
    ERR_BAD_ARGS, ERR_NOT_FOUND, Event, LOCAL_MAX_FRAME, LOCAL_PREFIX_LEN, OP_ABANDON, OP_ACK,
    OP_DRAIN, OP_FETCH, OP_HELLO, OP_LINK, OP_LOOKUP, OP_NODE, OP_ROTATE, OP_ROTATE_ENVELOPE,
    OP_SEND, OP_STATUS, OP_UNLINK, Request, Response, deframe_local, err_name, frame_local,
};
use lattice_proto::{ProtoError, Value, decode, encode};
use lattice_types::{ChannelPublicKey, DeliveryId, Identifier, MessageId};

/// Custody result codes carried by the wire `custody` frame (spec §6).
/// The local API never carries these — custody is negotiated hop by hop on
/// the wire and is invisible to applications — but they are re-exported so
/// the complete v1 set, including `CUSTODY_SEEN` (4: the receiver saw the
/// leg but does not hold the message; the sender should try another link),
/// is available to callers that inspect wire-level diagnostics.
pub use lattice_proto::frames::{
    CUSTODY_ACCEPTED, CUSTODY_ALREADY_HAVE, CUSTODY_BUSY, CUSTODY_REFUSED, CUSTODY_SEEN,
};
/// `MessageStatus::detail` (re-exported here) never carries a custody
/// result code: the local API carries the sender-side failure detail (the
/// `ERR_*` codes from lattice-core, or a negative-receipt reason), not the
/// wire custody namespace (`CUSTODY_*`, 0–4).
pub use lattice_proto::local::{DrainRequest, DrainState, DrainStatus, Lookup, MessageStatus};
/// Text forms for identifiers and addresses (spec §1): base32 identifiers,
/// `service:mailbox@identifier` addresses. Re-exported so callers can print
/// and parse the text forms without depending on `lattice-proto` directly.
pub use lattice_proto::text;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Why the connection to the daemon failed or became unusable.
#[derive(Debug)]
pub enum ConnectionError {
    /// A frame from the daemon could not be decoded (CBOR or framing).
    Decode(ProtoError),
    /// The daemon closed the socket.
    Closed,
    /// No frame arrived within the read timeout.
    Timeout,
    /// A response frame carried a different request id than the one in flight.
    ResponseIdMismatch { expected: u64, got: u64 },
    /// `next_event` received a response frame instead of an event.
    ExpectedEvent,
    /// A frame that is neither a response nor an event.
    UnrecognizedFrame,
    /// The buffered frame exceeded the local maximum size.
    FrameTooLarge,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::Decode(e) => write!(f, "undecodable frame: {e}"),
            ConnectionError::Closed => write!(f, "daemon closed the socket"),
            ConnectionError::Timeout => write!(f, "timed out waiting for a frame"),
            ConnectionError::ResponseIdMismatch { expected, got } => {
                write!(f, "response id mismatch (expected {expected}, got {got})")
            }
            ConnectionError::ExpectedEvent => write!(f, "expected an event frame, got a response"),
            ConnectionError::UnrecognizedFrame => write!(f, "unrecognized frame"),
            ConnectionError::FrameTooLarge => write!(f, "frame exceeds the local maximum size"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectionError::Decode(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The connection to the daemon failed or became unusable.
    Connection(ConnectionError),
    /// The daemon rejected the request with an error code (see `ERR_*` constants).
    Rejected(u64),
    BadResponse(&'static str),
    /// The request exceeds the local frame limit and was not sent.
    RequestTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Connection(c) => write!(f, "connection: {c}"),
            Error::Rejected(code) => {
                write!(f, "request rejected: {} (code {code})", err_name(*code))
            }
            Error::BadResponse(m) => write!(f, "malformed response: {m}"),
            Error::RequestTooLarge => write!(f, "request exceeds the local frame limit"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Connection(c) => Some(c),
            Error::Rejected(_) | Error::BadResponse(_) | Error::RequestTooLarge => None,
        }
    }
}

impl Error {
    /// The daemon's rejection code and its name, if this is a rejection.
    pub fn rejection(&self) -> Option<(u64, &'static str)> {
        match self {
            Error::Rejected(code) => Some((*code, err_name(*code))),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// A message to send through the local API.
#[derive(Clone, Debug)]
pub struct Send {
    pub to: Identifier,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub fmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub exp: Option<u64>,
    pub priority: Option<u8>,
    /// 0 = default, 1 = waypoint, 2 = direct (see `ROUTE_*`).
    pub route: Option<u64>,
}

/// One inbox delivery, as returned by `fetch`.
#[derive(Clone, Debug, PartialEq)]
pub struct Delivery {
    pub delivery_id: DeliveryId,
    pub mid: MessageId,
    pub from: Identifier,
    pub fsvc: String,
    pub fmbx: Vec<u8>,
    pub tmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub received: u64,
}

/// Result of `node` (admin).
#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: Identifier,
    pub mode: String,
    pub links: u64,
    pub records: u64,
    pub custody_bytes: u64,
    pub draining: bool,
}

/// Outcome of an `unlink` request: whether at least one open link to the
/// peer was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlinkOutcome {
    Removed,
    NotFound,
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    stream: UnixStream,
    buf: Vec<u8>,
    next_id: u64,
    events: VecDeque<Event>,
}

fn bytes_at(v: &Value, key: u64) -> Option<&[u8]> {
    lattice_proto::cbor::map_get(v, key).and_then(Value::as_bytes)
}

impl Client {
    async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            stream,
            buf: Vec::new(),
            next_id: 1,
            events: VecDeque::new(),
        })
    }

    /// Connect to the application socket and authenticate as `service`.
    pub async fn connect_app(path: &Path, service: &str, secret: &[u8]) -> Result<Self> {
        let mut c = Self::connect(path).await?;
        let args = Value::map(vec![
            (Value::UInt(0), Value::Text(service.to_string())),
            (Value::UInt(1), Value::Bytes(secret.to_vec())),
        ]);
        c.call(OP_HELLO, args).await?;
        Ok(c)
    }

    /// Connect to the admin socket. The socket itself is the credential
    /// (mode 0600, owner-only); there is no handshake.
    pub async fn connect_admin(path: &Path) -> Result<Self> {
        Self::connect(path).await
    }

    /// Drain events received while waiting for responses.
    pub fn take_events(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }

    /// Wait for the next event from the daemon.
    ///
    /// Only call this when no request is in flight; a response frame
    /// arriving here is a protocol violation. Previously stashed events
    /// (received during earlier calls) are returned first.
    pub async fn next_event(&mut self) -> Result<Event> {
        if let Some(ev) = self.events.pop_front() {
            return Ok(ev);
        }
        let payload = self.read_frame().await?;
        let v =
            decode(&payload).map_err(|e| Error::Connection(ConnectionError::Decode(e.into())))?;
        match Event::from_value(&v) {
            Ok(ev) => Ok(ev),
            Err(_) => Err(Error::Connection(ConnectionError::ExpectedEvent)),
        }
    }

    /// Send a message; returns the message id.
    pub async fn send(&mut self, msg: &Send) -> Result<MessageId> {
        let mut args = vec![
            (Value::UInt(0), Value::Bytes(msg.to.to_vec())),
            (Value::UInt(1), Value::Text(msg.tsvc.clone())),
            (Value::UInt(2), Value::Bytes(msg.tmbx.clone())),
            (Value::UInt(3), Value::Bytes(msg.fmbx.clone())),
            (Value::UInt(4), Value::Bytes(msg.body.clone())),
        ];
        if let Some(exp) = msg.exp {
            args.push((Value::UInt(5), Value::UInt(exp)));
        }
        if let Some(p) = msg.priority {
            if p > 3 {
                return Err(Error::BadResponse("priority above 3"));
            }
            args.push((Value::UInt(6), Value::UInt(p as u64)));
        }
        if let Some(r) = msg.route {
            args.push((Value::UInt(7), Value::UInt(r)));
        }
        let result = self.call(OP_SEND, Value::map(args)).await?;
        take_mid(&result)
    }

    /// Status of a message id. `Ok(None)` means the daemon has no record of it.
    pub async fn status(&mut self, mid: &MessageId) -> Result<Option<MessageStatus>> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(mid.to_vec()))]);
        match self.call(OP_STATUS, args).await {
            Ok(v) => {
                let status = uint_at(&v, 0)?;
                let detail = lattice_proto::cbor::map_get(&v, 1).and_then(Value::as_uint);
                Ok(Some(MessageStatus { status, detail }))
            }
            Err(Error::Rejected(ERR_NOT_FOUND)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Fetch up to `max` deliveries from this service's inbox.
    pub async fn fetch(&mut self, max: u64) -> Result<Vec<Delivery>> {
        let args = Value::map(vec![(Value::UInt(0), Value::UInt(max))]);
        let result = self.call(OP_FETCH, args).await?;
        let items = lattice_proto::cbor::map_get(&result, 0)
            .and_then(Value::as_array)
            .ok_or(Error::BadResponse("fetch: missing items"))?;
        items.iter().map(parse_delivery).collect()
    }

    /// Acknowledge deliveries; returns how many were removed.
    pub async fn ack(&mut self, ids: &[DeliveryId]) -> Result<u64> {
        let arr = Value::Array(ids.iter().map(|id| Value::Bytes(id.to_vec())).collect());
        let args = Value::map(vec![(Value::UInt(0), arr)]);
        let result = self.call(OP_ACK, args).await?;
        uint_at(&result, 0)
    }

    /// Whether a valid record for `id` is held, its mode, and whether a path exists now.
    pub async fn lookup(&mut self, id: &Identifier) -> Result<Lookup> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(id.to_vec()))]);
        let result = self.call(OP_LOOKUP, args).await?;
        let have = lattice_proto::cbor::map_get(&result, 0)
            .and_then(Value::as_bool)
            .ok_or(Error::BadResponse("lookup: missing have"))?;
        let path = lattice_proto::cbor::map_get(&result, 2)
            .and_then(Value::as_bool)
            .ok_or(Error::BadResponse("lookup: missing path"))?;
        let mode = match lattice_proto::cbor::map_get(&result, 1) {
            None => None,
            Some(v) => {
                let raw = v.as_uint().ok_or(Error::BadResponse("lookup: bad mode"))?;
                Some(
                    lattice_proto::record::Mode::from_u64(raw)
                        .map_err(|_| Error::BadResponse("lookup: bad mode"))?,
                )
            }
        };
        // A `have: false` reply carrying a mode is malformed but harmless;
        // the record half is dropped.
        Ok(if have {
            Lookup::Present { mode, path }
        } else {
            Lookup::Absent { path }
        })
    }

    // ── admin operations ─────────────────────────────────────────────

    pub async fn node(&mut self) -> Result<NodeInfo> {
        let result = self.call(OP_NODE, Value::map(vec![])).await?;
        let get = |k: u64| lattice_proto::cbor::map_get(&result, k);
        Ok(NodeInfo {
            id: bytes_at(&result, 0)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(Identifier::from_bytes)
                .ok_or(Error::BadResponse("node: bad id"))?,
            mode: get(1)
                .and_then(Value::as_text)
                .ok_or(Error::BadResponse("node: missing mode"))?
                .to_string(),
            links: get(2)
                .and_then(Value::as_uint)
                .ok_or(Error::BadResponse("node: missing links"))?,
            records: get(3)
                .and_then(Value::as_uint)
                .ok_or(Error::BadResponse("node: missing records"))?,
            custody_bytes: get(4)
                .and_then(Value::as_uint)
                .ok_or(Error::BadResponse("node: missing custody_bytes"))?,
            draining: get(5)
                .and_then(Value::as_bool)
                .ok_or(Error::BadResponse("node: missing draining"))?,
        })
    }

    /// Query or set drain mode. [`DrainRequest::Query`] reports;
    /// [`DrainRequest::Set`] sets and then reports.
    pub async fn drain(&mut self, request: DrainRequest) -> Result<DrainStatus> {
        let args = match request {
            DrainRequest::Query => Value::map(vec![]),
            DrainRequest::Set(state) => {
                Value::map(vec![(Value::UInt(0), Value::Bool(state.is_draining()))])
            }
        };
        let result = self.call(OP_DRAIN, args).await?;
        Ok(DrainStatus {
            draining: lattice_proto::cbor::map_get(&result, 0)
                .and_then(Value::as_bool)
                .ok_or(Error::BadResponse("drain: missing draining"))?,
            custody_bytes: uint_at(&result, 1)?,
        })
    }

    /// Queue a dial to `addr`. Exactly one of `channel_key` (IK dial) or
    /// `path` (XX dial) is required; `id` pins the expected peer.
    ///
    /// Returns `Ok(())` once the daemon has accepted the dial; the daemon
    /// rejects with `ERR_BAD_ARGS` when the address is unparseable or
    /// neither a key nor a path is given.
    pub async fn link(
        &mut self,
        addr: &str,
        channel_key: Option<ChannelPublicKey>,
        path: Option<String>,
        id: Option<Identifier>,
    ) -> Result<()> {
        let mut args = vec![(Value::UInt(0), Value::Text(addr.to_string()))];
        if let Some(k) = channel_key {
            args.push((Value::UInt(1), Value::Bytes(k.to_vec())));
        }
        if let Some(p) = path {
            args.push((Value::UInt(2), Value::Text(p)));
        }
        if let Some(i) = id {
            args.push((Value::UInt(3), Value::Bytes(i.to_vec())));
        }
        let result = self.call(OP_LINK, Value::map(args)).await?;
        match lattice_proto::cbor::map_get(&result, 0).and_then(Value::as_bool) {
            Some(true) => Ok(()),
            // The daemon answers `false` only when it refused the dial; it
            // normally rejects with ERR_BAD_ARGS instead.
            Some(false) => Err(Error::Rejected(ERR_BAD_ARGS)),
            None => Err(Error::BadResponse("link: missing result")),
        }
    }

    /// Rotate the signing key. `next_key` is the offline, pre-committed
    /// next signing key; `next_next_commitment` is the BLAKE3 commitment to
    /// the following key, generated offline. The daemon verifies `next_key`
    /// against the commitment stored in its identity directory and refuses
    /// the rotation on mismatch.
    pub async fn rotate(
        &mut self,
        next_key: &[u8; 32],
        next_next_commitment: &[u8; 32],
    ) -> Result<String> {
        let args = Value::map(vec![
            (Value::UInt(0), Value::Bytes(next_key.to_vec())),
            (Value::UInt(1), Value::Bytes(next_next_commitment.to_vec())),
        ]);
        let result = self.call(OP_ROTATE, args).await?;
        text_at(&result, 0)
    }

    /// Permanently abandon the identity (a rotation with no next-key commitment).
    /// `next_key` is the offline, pre-committed next signing key.
    pub async fn abandon(&mut self, next_key: &[u8; 32]) -> Result<String> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(next_key.to_vec()))]);
        let result = self.call(OP_ABANDON, args).await?;
        text_at(&result, 0)
    }

    /// Rotate the envelope (X-Wing) key; the old key is kept decrypt-only
    /// for a grace period, then deleted.
    pub async fn rotate_envelope(&mut self) -> Result<String> {
        let result = self.call(OP_ROTATE_ENVELOPE, Value::map(vec![])).await?;
        text_at(&result, 0)
    }

    /// Drop every link to the given peer id.
    pub async fn unlink(&mut self, id: &Identifier) -> Result<UnlinkOutcome> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(id.to_vec()))]);
        let result = self.call(OP_UNLINK, args).await?;
        match lattice_proto::cbor::map_get(&result, 0).and_then(Value::as_bool) {
            Some(true) => Ok(UnlinkOutcome::Removed),
            Some(false) => Ok(UnlinkOutcome::NotFound),
            None => Err(Error::BadResponse("unlink: missing result")),
        }
    }

    // ── internals ────────────────────────────────────────────────────

    async fn call(&mut self, op: u64, args: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let req = Request { id, op, args };
        let frame = frame_local(&encode(&req.to_value())).map_err(|_| Error::RequestTooLarge)?;
        self.stream.write_all(&frame).await?;
        loop {
            let payload = self.read_frame().await?;
            let v = decode(&payload)
                .map_err(|e| Error::Connection(ConnectionError::Decode(e.into())))?;
            match Response::from_value(&v) {
                Ok(Response::Ok { id: rid, result }) if rid == id => return Ok(result),
                Ok(Response::Err { id: rid, code }) if rid == id => {
                    return Err(Error::Rejected(code));
                }
                Ok(Response::Ok { id: rid, .. }) | Ok(Response::Err { id: rid, .. }) => {
                    return Err(Error::Connection(ConnectionError::ResponseIdMismatch {
                        expected: id,
                        got: rid,
                    }));
                }
                Err(_) => match Event::from_value(&v) {
                    Ok(ev) => self.events.push_back(ev),
                    Err(_) => return Err(Error::Connection(ConnectionError::UnrecognizedFrame)),
                },
            }
        }
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(frame) = deframe_local(&self.buf)
                .map_err(|e| Error::Connection(ConnectionError::Decode(e)))?
            {
                let out = frame.payload.to_vec();
                self.buf.drain(..frame.consumed);
                return Ok(out);
            }
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                self.stream.read(&mut chunk),
            )
            .await
            {
                Ok(r) => r?,
                Err(_) => return Err(Error::Connection(ConnectionError::Timeout)),
            };
            if n == 0 {
                return Err(Error::Connection(ConnectionError::Closed));
            }
            self.buf.extend_from_slice(&chunk[..n]);
            if self.buf.len() > LOCAL_MAX_FRAME + LOCAL_PREFIX_LEN {
                return Err(Error::Connection(ConnectionError::FrameTooLarge));
            }
        }
    }
}

fn text_at(v: &Value, key: u64) -> Result<String> {
    lattice_proto::cbor::map_get(v, key)
        .and_then(Value::as_text)
        .map(String::from)
        .ok_or(Error::BadResponse("expected text field"))
}

fn uint_at(v: &Value, key: u64) -> Result<u64> {
    lattice_proto::cbor::map_get(v, key)
        .and_then(Value::as_uint)
        .ok_or(Error::BadResponse("expected uint field"))
}

fn take_mid(v: &Value) -> Result<MessageId> {
    bytes_at(v, 0)
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .map(MessageId::from_bytes)
        .ok_or(Error::BadResponse("send: missing mid"))
}

fn parse_delivery(v: &Value) -> Result<Delivery> {
    let bytes = |k: u64| -> Result<&[u8]> {
        bytes_at(v, k).ok_or(Error::BadResponse("delivery: missing bytes field"))
    };
    Ok(Delivery {
        delivery_id: <[u8; 16]>::try_from(bytes(0)?)
            .map(DeliveryId::from_bytes)
            .map_err(|_| Error::BadResponse("delivery: bad id"))?,
        mid: <[u8; 16]>::try_from(bytes(1)?)
            .map(MessageId::from_bytes)
            .map_err(|_| Error::BadResponse("delivery: bad mid"))?,
        from: <[u8; 32]>::try_from(bytes(2)?)
            .map(Identifier::from_bytes)
            .map_err(|_| Error::BadResponse("delivery: bad from"))?,
        fsvc: lattice_proto::cbor::map_get(v, 3)
            .and_then(Value::as_text)
            .ok_or(Error::BadResponse("delivery: missing fsvc"))?
            .to_string(),
        fmbx: bytes(4)?.to_vec(),
        tmbx: bytes(5)?.to_vec(),
        body: bytes(6)?.to_vec(),
        received: uint_at(v, 7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;
    use tokio::net::UnixListener;

    /// Serve exactly one request on a fresh Unix socket and reply with
    /// `result` as the response payload. Returns the socket path.
    async fn serve_once(dir: &std::path::Path, result: Value) -> std::path::PathBuf {
        let path = dir.join("daemon.sock");
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let payload = loop {
                if let Some(frame) = deframe_local(&buf).unwrap() {
                    break frame.payload.to_vec();
                }
                let n = tokio::io::AsyncReadExt::read(&mut sock, &mut chunk)
                    .await
                    .unwrap();
                assert!(n > 0, "client closed before sending a frame");
                buf.extend_from_slice(&chunk[..n]);
            };
            let req = decode(&payload).unwrap();
            let id = lattice_proto::cbor::map_get(&req, 0)
                .and_then(Value::as_uint)
                .unwrap();
            let resp = Value::map(vec![
                (Value::UInt(0), Value::UInt(id)),
                (Value::UInt(1), result),
            ]);
            let frame = frame_local(&encode(&resp)).unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut sock, &frame)
                .await
                .unwrap();
        });
        path
    }

    fn node_result(links: Option<u64>) -> Value {
        let mut pairs = vec![
            (Value::UInt(0), Value::Bytes(vec![7; 32])),
            (Value::UInt(1), Value::Text("public".into())),
        ];
        if let Some(l) = links {
            pairs.push((Value::UInt(2), Value::UInt(l)));
        }
        pairs.extend([
            (Value::UInt(3), Value::UInt(9)),
            (Value::UInt(4), Value::UInt(1234)),
            (Value::UInt(5), Value::Bool(false)),
        ]);
        Value::map(pairs)
    }

    #[tokio::test]
    async fn node_missing_links_is_an_error_not_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = serve_once(dir.path(), node_result(None)).await;
        let mut client = Client::connect_admin(&path).await.unwrap();
        let err = client.node().await.unwrap_err();
        assert!(matches!(err, Error::BadResponse("node: missing links")));
    }

    #[tokio::test]
    async fn node_full_response_parses() {
        let dir = tempfile::tempdir().unwrap();
        let path = serve_once(dir.path(), node_result(Some(3))).await;
        let mut client = Client::connect_admin(&path).await.unwrap();
        let info = client.node().await.unwrap();
        assert_eq!(info.links, 3);
        assert_eq!(info.records, 9);
        assert_eq!(info.custody_bytes, 1234);
        assert!(!info.draining);
        assert_eq!(info.mode, "public");
    }

    #[tokio::test]
    async fn drain_missing_draining_is_an_error_not_false() {
        let dir = tempfile::tempdir().unwrap();
        // custody_bytes present, draining (key 0) absent.
        let path = serve_once(
            dir.path(),
            Value::map(vec![(Value::UInt(1), Value::UInt(42))]),
        )
        .await;
        let mut client = Client::connect_admin(&path).await.unwrap();
        let err = client.drain(DrainRequest::Query).await.unwrap_err();
        assert!(matches!(err, Error::BadResponse("drain: missing draining")));
    }

    #[test]
    fn rejection_display_names_the_code() {
        let err = Error::Rejected(ERR_NOT_FOUND);
        assert_eq!(err.to_string(), "request rejected: not_found (code 4)");
        assert_eq!(err.rejection(), Some((ERR_NOT_FOUND, "not_found")));
        let err = Error::Rejected(999);
        assert_eq!(err.to_string(), "request rejected: unknown (code 999)");
        assert_eq!(err.rejection(), Some((999, "unknown")));
    }

    #[test]
    fn error_source_chain_is_wired() {
        let io = Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert_eq!(
            io.source()
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .map(|e| e.kind()),
            Some(std::io::ErrorKind::ConnectionRefused)
        );
        let conn = Error::Connection(ConnectionError::Decode(ProtoError::Cbor(
            lattice_proto::DecodeError::UnexpectedEof,
        )));
        let source = conn.source().expect("connection error has a source");
        assert!(source.is::<ConnectionError>());
        let inner = source.source().expect("decode error has a source");
        assert!(inner.is::<ProtoError>());
        assert!(
            inner.source().is_some(),
            "ProtoError::Cbor carries the DecodeError"
        );
    }
}
