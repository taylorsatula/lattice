//! Lattice local-API client.
//!
//! Talks to a running `latticed` over its Unix sockets: the application
//! socket (service-authenticated) or the admin socket (owner-only). Wire
//! format is the spec's length-prefixed CBOR (`lattice_proto::local`).
//!
//! Application events (`inbox`, `status`) arrive interleaved with responses;
//! [`Client::call`] stashes them and they can be drained with
//! [`Client::take_events`] or awaited with [`Client::next_event`].

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::fmt;
use std::path::Path;

use lattice_proto::local::*;
use lattice_proto::{Value, decode, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// The peer closed the connection or sent an undecodable frame.
    Connection(String),
    /// The daemon rejected the request with an error code (see `ERR_*` constants).
    Rejected(u64),
    BadResponse(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Connection(m) => write!(f, "connection: {m}"),
            Error::Rejected(c) => write!(f, "request rejected with error code {c}"),
            Error::BadResponse(m) => write!(f, "malformed response: {m}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// A message to send through the local API.
#[derive(Clone, Debug)]
pub struct Send {
    pub to: [u8; 32],
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
    pub delivery_id: [u8; 16],
    pub mid: [u8; 16],
    pub from: [u8; 32],
    pub fsvc: String,
    pub fmbx: Vec<u8>,
    pub tmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub received: u64,
}

/// Result of `lookup`.
#[derive(Clone, Copy, Debug)]
pub struct Lookup {
    pub have: bool,
    pub mode: Option<u64>,
    pub path: bool,
}

/// Result of `node` (admin).
#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: [u8; 32],
    pub mode: String,
    pub links: u64,
    pub records: u64,
    pub custody_bytes: u64,
    pub draining: bool,
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

    /// Send a message; returns the message id.
    pub async fn send(&mut self, msg: &Send) -> Result<[u8; 16]> {
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
    pub async fn status(&mut self, mid: &[u8; 16]) -> Result<Option<(u64, Option<u64>)>> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(mid.to_vec()))]);
        match self.call(OP_STATUS, args).await {
            Ok(v) => {
                let status = uint_at(&v, 0)?;
                let detail = lattice_proto::cbor::map_get(&v, 1).and_then(Value::as_uint);
                Ok(Some((status, detail)))
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
    pub async fn ack(&mut self, ids: &[[u8; 16]]) -> Result<u64> {
        let arr = Value::Array(ids.iter().map(|id| Value::Bytes(id.to_vec())).collect());
        let args = Value::map(vec![(Value::UInt(0), arr)]);
        let result = self.call(OP_ACK, args).await?;
        uint_at(&result, 0)
    }

    /// Whether a valid record for `id` is held, its mode, and whether a path exists now.
    pub async fn lookup(&mut self, id: &[u8; 32]) -> Result<Lookup> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(id.to_vec()))]);
        let result = self.call(OP_LOOKUP, args).await?;
        Ok(Lookup {
            have: lattice_proto::cbor::map_get(&result, 0)
                .and_then(Value::as_bool)
                .ok_or(Error::BadResponse("lookup: missing have"))?,
            mode: lattice_proto::cbor::map_get(&result, 1).and_then(Value::as_uint),
            path: lattice_proto::cbor::map_get(&result, 2)
                .and_then(Value::as_bool)
                .ok_or(Error::BadResponse("lookup: missing path"))?,
        })
    }

    // ── admin operations ─────────────────────────────────────────────

    pub async fn node(&mut self) -> Result<NodeInfo> {
        let result = self.call(OP_NODE, Value::map(vec![])).await?;
        let get = |k: u64| lattice_proto::cbor::map_get(&result, k);
        Ok(NodeInfo {
            id: bytes_at(&result, 0)
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .ok_or(Error::BadResponse("node: bad id"))?,
            mode: get(1).and_then(Value::as_text).unwrap_or("").to_string(),
            links: get(2).and_then(Value::as_uint).unwrap_or(0),
            records: get(3).and_then(Value::as_uint).unwrap_or(0),
            custody_bytes: get(4).and_then(Value::as_uint).unwrap_or(0),
            draining: get(5).and_then(Value::as_bool).unwrap_or(false),
        })
    }

    /// Set or query drain mode. `None` reports, `Some(d)` sets.
    pub async fn drain(&mut self, draining: Option<bool>) -> Result<(bool, u64)> {
        let args = match draining {
            Some(d) => Value::map(vec![(Value::UInt(0), Value::Bool(d))]),
            None => Value::map(vec![]),
        };
        let result = self.call(OP_DRAIN, args).await?;
        Ok((
            lattice_proto::cbor::map_get(&result, 0)
                .and_then(Value::as_bool)
                .unwrap_or(false),
            uint_at(&result, 1)?,
        ))
    }

    /// Queue a dial to `addr`. Exactly one of `channel_key` (IK dial) or
    /// `path` (XX dial) is required; `id` pins the expected peer.
    pub async fn link(
        &mut self,
        addr: &str,
        channel_key: Option<[u8; 32]>,
        path: Option<String>,
        id: Option<[u8; 32]>,
    ) -> Result<bool> {
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
        lattice_proto::cbor::map_get(&result, 0)
            .and_then(Value::as_bool)
            .ok_or(Error::BadResponse("link: missing result"))
    }

    /// Drop every link to the given peer id. Returns true if any were open.
    pub async fn unlink(&mut self, id: &[u8; 32]) -> Result<bool> {
        let args = Value::map(vec![(Value::UInt(0), Value::Bytes(id.to_vec()))]);
        let result = self.call(OP_UNLINK, args).await?;
        lattice_proto::cbor::map_get(&result, 0)
            .and_then(Value::as_bool)
            .ok_or(Error::BadResponse("unlink: missing result"))
    }

    // ── internals ────────────────────────────────────────────────────

    async fn call(&mut self, op: u64, args: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let req = Request { id, op, args };
        let frame = frame_local(&encode(&req.to_value()))
            .map_err(|_| Error::BadResponse("frame too large"))?;
        self.stream.write_all(&frame).await?;
        loop {
            let payload = self.read_frame().await?;
            let v = decode(&payload).map_err(|e| Error::Connection(format!("decode: {e}")))?;
            match Response::from_value(&v) {
                Ok(Response::Ok { id: rid, result }) if rid == id => return Ok(result),
                Ok(Response::Err { id: rid, code }) if rid == id => {
                    return Err(Error::Rejected(code));
                }
                Ok(_) => return Err(Error::Connection("response id mismatch".into())),
                Err(_) => match Event::from_value(&v) {
                    Ok(ev) => self.events.push_back(ev),
                    Err(_) => return Err(Error::Connection("unrecognized frame".into())),
                },
            }
        }
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some((payload, used)) = deframe_local(&self.buf)
                .map_err(|e| Error::Connection(format!("bad frame: {e}")))?
            {
                let out = payload.to_vec();
                self.buf.drain(..used);
                return Ok(out);
            }
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Connection("daemon closed the socket".into()));
            }
            self.buf.extend_from_slice(&chunk[..n]);
            if self.buf.len() > LOCAL_MAX_FRAME + LOCAL_PREFIX_LEN {
                return Err(Error::Connection("frame exceeds maximum size".into()));
            }
        }
    }
}

fn uint_at(v: &Value, key: u64) -> Result<u64> {
    lattice_proto::cbor::map_get(v, key)
        .and_then(Value::as_uint)
        .ok_or(Error::BadResponse("expected uint field"))
}

fn take_mid(v: &Value) -> Result<[u8; 16]> {
    bytes_at(v, 0)
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .ok_or(Error::BadResponse("send: missing mid"))
}

fn parse_delivery(v: &Value) -> Result<Delivery> {
    let bytes = |k: u64| -> Result<&[u8]> {
        bytes_at(v, k).ok_or(Error::BadResponse("delivery: missing bytes field"))
    };
    Ok(Delivery {
        delivery_id: <[u8; 16]>::try_from(bytes(0)?)
            .map_err(|_| Error::BadResponse("delivery: bad id"))?,
        mid: <[u8; 16]>::try_from(bytes(1)?)
            .map_err(|_| Error::BadResponse("delivery: bad mid"))?,
        from: <[u8; 32]>::try_from(bytes(2)?)
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
