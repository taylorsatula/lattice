//! Local API servers. Two unix sockets:
//!
//! * application socket — per-service auth (constant-time secret check),
//!   exposes app operations only.
//! * admin socket — owner-only, exposes node/drain/link operations.
//!
//! Wire format: 4-byte big-endian length prefix, then one CBOR local-API
//! object (see V2_SPEC §7 and lattice-proto::local).

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use lattice_proto::local::*;
use lattice_proto::{Value, decode, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::runtime::{ApiCmd, ServiceEvent};

const MAX_FRAME: usize = LOCAL_MAX_FRAME;

async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    let framed = frame_local(payload)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&framed).await
}

/// Outcome of reading one local-API frame. `Eof` is a clean peer close;
/// `BadFrame` is bytes the deframer rejected (or an over-long unframed
/// buffer) — the stream is desynced and must not be read further.
enum FrameRead {
    Frame(Vec<u8>),
    Eof,
    BadFrame,
}

async fn read_frame(stream: &mut UnixStream, buf: &mut Vec<u8>) -> std::io::Result<FrameRead> {
    let mut chunk = [0u8; 8192];
    loop {
        match deframe_local(buf) {
            Ok(Some(frame)) => {
                let out = frame.payload.to_vec();
                buf.drain(..frame.consumed);
                return Ok(FrameRead::Frame(out));
            }
            Ok(None) => {}
            Err(_) => return Ok(FrameRead::BadFrame),
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(FrameRead::Eof);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_FRAME + LOCAL_PREFIX_LEN + 1 {
            return Ok(FrameRead::BadFrame);
        }
    }
}

fn resp_ok(id: u64, result: Value) -> Vec<u8> {
    encode(&Response::Ok { id, result }.to_value())
}
fn resp_err(id: u64, code: u64) -> Vec<u8> {
    encode(&Response::Err { id, code }.to_value())
}

fn args_map(v: &Value) -> Option<&[(Value, Value)]> {
    v.as_map()
}

/// Reject any key outside `allowed`; the request args must be a map.
fn deny_unknown_args(v: &Value, allowed: &[u64]) -> Result<(), ()> {
    match v.as_map() {
        Some(map) => {
            for (k, _) in map {
                match k.as_uint() {
                    Some(k) if allowed.contains(&k) => {}
                    _ => return Err(()),
                }
            }
            Ok(())
        }
        None => Err(()),
    }
}

fn args_get(v: &Value, key: u64) -> Option<&Value> {
    args_map(v)?
        .iter()
        .find(|(k, _)| k.as_uint() == Some(key))
        .map(|(_, v)| v)
}

fn secret_eq(a: &[u8], b: &str) -> bool {
    // Hash both sides so the comparison never branches on the configured
    // secret's length: ct_eq runs over fixed-size digests, and the only
    // length-dependent work is hashing the client-supplied input, whose
    // length the client already knows.
    let a = lattice_crypto::hash(a);
    let b = lattice_crypto::hash(b.as_bytes());
    a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

/// Application-socket connection handler.
async fn handle_app(
    mut stream: UnixStream,
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
    mut events: broadcast::Receiver<ServiceEvent>,
) {
    let mut buf = Vec::new();

    // First frame must be hello, within the deadline.
    let hello = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_frame(&mut stream, &mut buf),
    )
    .await
    {
        Ok(Ok(FrameRead::Frame(f))) => f,
        // Pre-auth: stay silent toward the peer (probe resistance), but log.
        Ok(Ok(FrameRead::BadFrame)) => {
            eprintln!("lattice: app socket: undecodable hello frame; closing");
            return;
        }
        Ok(Ok(FrameRead::Eof)) => return,
        Ok(Err(e)) => {
            eprintln!("lattice: app socket: read error during hello: {e}");
            return;
        }
        Err(_) => return,
    };
    let req = match decode(&hello)
        .ok()
        .and_then(|v| Request::from_value(&v).ok())
    {
        Some(r) => r,
        None => {
            eprintln!("lattice: app socket: hello frame did not decode as a request; closing");
            return;
        }
    };
    if req.op != OP_HELLO {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_AUTH)).await;
        return;
    }
    let (service, secret) = match (
        args_get(&req.args, 0)
            .and_then(Value::as_text)
            .map(String::from),
        args_get(&req.args, 1)
            .and_then(Value::as_bytes)
            .map(|b| b.to_vec()),
    ) {
        (Some(s), Some(k)) => (s, k),
        _ => {
            let _ = write_frame(&mut stream, &resp_err(req.id, ERR_BAD_ARGS)).await;
            return;
        }
    };
    let ok = cfg
        .services
        .get(&service)
        .map(|s| secret_eq(&secret, &s.secret))
        .unwrap_or(false);
    if !ok {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_AUTH)).await;
        return;
    }
    // Hello reply carries the node identifier so apps can pin it.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let node_id = match api.send(ApiCmd::NodeInfo { respond: tx }) {
        Ok(()) => match rx.await {
            Ok(info) => info.id,
            Err(_) => {
                let _ = write_frame(&mut stream, &resp_err(req.id, ERR_INTERNAL)).await;
                return;
            }
        },
        Err(_) => {
            let _ = write_frame(&mut stream, &resp_err(req.id, ERR_INTERNAL)).await;
            return;
        }
    };
    let hello_ok = Value::map(vec![
        (Value::UInt(0), Value::Bytes(node_id.to_vec())),
        (Value::UInt(1), Value::Text(service.clone())),
    ]);
    let _ = write_frame(&mut stream, &resp_ok(req.id, hello_ok)).await;

    loop {
        tokio::select! {
            ev = events.recv() => {
                // Events are tagged with the originating service; a
                // connection only ever sees its own service's events.
                if let Ok(ev) = ev {
                    if ev.service == service {
                        if let Ok(framed) = frame_local(&ev.payload) {
                            if stream.write_all(&framed).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
            frame = read_frame(&mut stream, &mut buf) => {
                let frame = match frame {
                    Ok(FrameRead::Frame(f)) => f,
                    Ok(FrameRead::Eof) => return,
                    // Authenticated peer: tell it the stream is unusable instead of
                    // dropping the connection without a word.
                    Ok(FrameRead::BadFrame) => {
                        eprintln!("lattice: app socket: undecodable frame; closing connection");
                        let _ = write_frame(&mut stream, &resp_err(0, ERR_BAD_ARGS)).await;
                        return;
                    }
                    Err(e) => {
                        eprintln!("lattice: app socket: read error: {e}");
                        return;
                    }
                };
                let Some(req) = decode(&frame).ok().and_then(|v| Request::from_value(&v).ok()) else {
                    let _ = write_frame(&mut stream, &resp_err(0, ERR_BAD_ARGS)).await;
                    continue;
                };
                let service = service.as_str();
                let out = dispatch_app(&api, service, &req).await;
                if write_frame(&mut stream, &out).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn dispatch_app(
    api: &mpsc::UnboundedSender<ApiCmd>,
    _service: &str,
    req: &Request,
) -> Vec<u8> {
    match req.op {
        OP_SEND => {
            let Some(args) = SendArgs::from_value(&req.args).ok() else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let send = lattice_core::AppSend {
                service: _service.to_string(),
                mid_hint: Some(lattice_types::MessageId::from_bytes(
                    lattice_crypto::os_bytes::<16>(),
                )),
                to: args.to,
                tsvc: args.tsvc,
                tmbx: args.tmbx,
                fmbx: args.fmbx,
                body: args.body,
                exp: args.exp,
                priority: args.priority.unwrap_or(1) as u8,
                route: args.route.unwrap_or(ROUTE_DEFAULT) as u8,
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::AppSend { send, respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(mid) => resp_ok(
                    req.id,
                    Value::map(vec![(Value::UInt(0), Value::Bytes(mid.to_vec()))]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_STATUS => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let Some(mid_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(mid) = <[u8; 16]>::try_from(mid_bytes).map(lattice_types::MessageId::from_bytes)
            else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::Status { mid, respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Ok(Some(status))) => {
                    let mut pairs = vec![(Value::UInt(0), Value::UInt(status.status))];
                    if let Some(d) = status.detail {
                        pairs.push((Value::UInt(1), Value::UInt(d)));
                    }
                    resp_ok(req.id, Value::map(pairs))
                }
                Ok(Ok(None)) => resp_err(req.id, ERR_NOT_FOUND),
                Ok(Err(e)) => {
                    eprintln!("lattice: status_get failed: {e}");
                    resp_err(req.id, ERR_INTERNAL)
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_FETCH => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let max = args_get(&req.args, 0)
                .and_then(Value::as_uint)
                .unwrap_or(16)
                .min(64) as usize;
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::Fetch {
                    service: _service.to_string(),
                    max,
                    respond: tx,
                })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Ok(rows)) => {
                    let items: Vec<Value> = rows
                        .into_iter()
                        .map(|e| {
                            Value::map(vec![
                                (Value::UInt(0), Value::Bytes(e.delivery_id.to_vec())),
                                (Value::UInt(1), Value::Bytes(e.mid.to_vec())),
                                (Value::UInt(2), Value::Bytes(e.from.to_vec())),
                                (Value::UInt(3), Value::Text(e.fsvc)),
                                (Value::UInt(4), Value::Bytes(e.fmbx)),
                                (Value::UInt(5), Value::Bytes(e.tmbx)),
                                (Value::UInt(6), Value::Bytes(e.body)),
                                (Value::UInt(7), Value::UInt(e.received)),
                            ])
                        })
                        .collect();
                    resp_ok(
                        req.id,
                        Value::map(vec![(Value::UInt(0), Value::Array(items))]),
                    )
                }
                Ok(Err(e)) => {
                    eprintln!("lattice: inbox_fetch failed: {e}");
                    resp_err(req.id, ERR_INTERNAL)
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_ACK => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let ids: Vec<lattice_types::DeliveryId> =
                match args_get(&req.args, 0).and_then(Value::as_array) {
                    Some(arr) => {
                        let mut out = Vec::with_capacity(arr.len());
                        for v in arr {
                            match v.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()) {
                                Some(id) => out.push(lattice_types::DeliveryId::from_bytes(id)),
                                None => return resp_err(req.id, ERR_BAD_ARGS),
                            }
                        }
                        out
                    }
                    None => return resp_err(req.id, ERR_BAD_ARGS),
                };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::Ack {
                    service: _service.to_string(),
                    ids,
                    respond: tx,
                })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Ok(n)) => resp_ok(
                    req.id,
                    Value::map(vec![(Value::UInt(0), Value::UInt(n as u64))]),
                ),
                Ok(Err(e)) => {
                    eprintln!("lattice: inbox_ack failed: {e}");
                    resp_err(req.id, ERR_INTERNAL)
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_LOOKUP => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let Some(id_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(id) = <[u8; 32]>::try_from(id_bytes).map(lattice_types::Identifier::from_bytes)
            else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::Lookup { id, respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(lookup) => {
                    let mut pairs = vec![
                        (Value::UInt(0), Value::Bool(lookup.have)),
                        (Value::UInt(2), Value::Bool(lookup.path)),
                    ];
                    if let Some(m) = lookup.mode {
                        pairs.push((Value::UInt(1), Value::UInt(m)));
                    }
                    resp_ok(req.id, Value::map(pairs))
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        _ => resp_err(req.id, ERR_UNKNOWN_OP),
    }
}

/// Admin-socket connection handler.
async fn handle_admin(mut stream: UnixStream, api: mpsc::UnboundedSender<ApiCmd>) {
    let mut buf = Vec::new();
    loop {
        let frame = match read_frame(&mut stream, &mut buf).await {
            Ok(FrameRead::Frame(f)) => f,
            Ok(FrameRead::Eof) => return,
            // Owner-only socket, no probe threat: say why the connection ends.
            Ok(FrameRead::BadFrame) => {
                eprintln!("lattice: admin socket: undecodable frame; closing connection");
                let _ = write_frame(&mut stream, &resp_err(0, ERR_BAD_ARGS)).await;
                return;
            }
            Err(e) => {
                eprintln!("lattice: admin socket: read error: {e}");
                return;
            }
        };
        let Some(req) = decode(&frame)
            .ok()
            .and_then(|v| Request::from_value(&v).ok())
        else {
            let _ = write_frame(&mut stream, &resp_err(0, ERR_BAD_ARGS)).await;
            continue;
        };
        let out = dispatch_admin(&api, &req).await;
        if write_frame(&mut stream, &out).await.is_err() {
            return;
        }
    }
}

async fn dispatch_admin(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    match req.op {
        OP_NODE => {
            if deny_unknown_args(&req.args, &[]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::NodeInfo { respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(info) => resp_ok(
                    req.id,
                    Value::map(vec![
                        (Value::UInt(0), Value::Bytes(info.id.to_vec())),
                        (Value::UInt(1), Value::Text(info.mode.into())),
                        (Value::UInt(2), Value::UInt(info.links as u64)),
                        (Value::UInt(3), Value::UInt(info.records as u64)),
                        (Value::UInt(4), Value::UInt(info.custody_bytes)),
                        (Value::UInt(5), Value::Bool(info.draining)),
                    ]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_DRAIN => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let setting = args_get(&req.args, 0).and_then(Value::as_bool);
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::Drain {
                    draining: setting,
                    respond: tx,
                })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(state) => resp_ok(
                    req.id,
                    Value::map(vec![
                        (Value::UInt(0), Value::Bool(state.draining)),
                        (Value::UInt(1), Value::UInt(state.custody_bytes)),
                    ]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_LINK => {
            if deny_unknown_args(&req.args, &[0, 1, 2, 3]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let Some(addr) = args_get(&req.args, 0)
                .and_then(Value::as_text)
                .map(String::from)
            else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let ik_key = match args_get(&req.args, 1) {
                Some(Value::Bytes(b)) => match <[u8; 32]>::try_from(b.as_slice()) {
                    Ok(k) => Some(lattice_types::ChannelPublicKey::from_bytes(k)),
                    Err(_) => return resp_err(req.id, ERR_BAD_ARGS),
                },
                Some(_) => return resp_err(req.id, ERR_BAD_ARGS),
                None => None,
            };
            let path = args_get(&req.args, 2)
                .and_then(Value::as_text)
                .map(String::from);
            let peer_id = match args_get(&req.args, 3) {
                Some(Value::Bytes(b)) => match <[u8; 32]>::try_from(b.as_slice()) {
                    Ok(k) => Some(lattice_types::Identifier::from_bytes(k)),
                    Err(_) => return resp_err(req.id, ERR_BAD_ARGS),
                },
                Some(_) => return resp_err(req.id, ERR_BAD_ARGS),
                None => None,
            };
            if ik_key.is_none() && path.is_none() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::Link {
                    addr,
                    ik_key,
                    path,
                    peer_id,
                    respond: tx,
                })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(true) => resp_ok(
                    req.id,
                    Value::map(vec![(Value::UInt(0), Value::Bool(true))]),
                ),
                Ok(false) => resp_err(req.id, ERR_BAD_ARGS),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_ROTATE | OP_ABANDON => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let next_key_file = match args_get(&req.args, 0) {
                None => None,
                Some(Value::Text(t)) => Some(t.clone()),
                Some(_) => return resp_err(req.id, ERR_BAD_ARGS),
            };
            let abandon = req.op == OP_ABANDON;
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::Rotate {
                    next_key_file,
                    abandon,
                    respond: tx,
                })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Ok(msg)) => {
                    resp_ok(req.id, Value::map(vec![(Value::UInt(0), Value::Text(msg))]))
                }
                Ok(Err(e)) => {
                    eprintln!("lattice: rotate failed: {e}");
                    resp_err(req.id, ERR_FAILED)
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_ROTATE_ENVELOPE => {
            if deny_unknown_args(&req.args, &[]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::RotateEnvelope { respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Ok(msg)) => {
                    resp_ok(req.id, Value::map(vec![(Value::UInt(0), Value::Text(msg))]))
                }
                Ok(Err(e)) => {
                    eprintln!("lattice: envelope rotation failed: {e}");
                    resp_err(req.id, ERR_FAILED)
                }
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_UNLINK => {
            if deny_unknown_args(&req.args, &[0]).is_err() {
                return resp_err(req.id, ERR_BAD_ARGS);
            }
            let Some(id) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(peer) = <[u8; 32]>::try_from(id).map(lattice_types::Identifier::from_bytes)
            else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api
                .send(ApiCmd::UnlinkByPeer { peer, respond: tx })
                .is_err()
            {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(found) => resp_ok(
                    req.id,
                    Value::map(vec![(Value::UInt(0), Value::Bool(found))]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        _ => resp_err(req.id, ERR_UNKNOWN_OP),
    }
}

/// Bind a socket path with the given mode.
///
/// Refuses to touch anything that is not a socket; refuses to start if a
/// live socket answers (another latticed is running); removes a stale
/// socket file otherwise. The mode is applied before the listener is
/// returned, so no connection is ever accepted with wider permissions.
fn bind_unix(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                ),
            ));
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!(
                    "{} answers connections; is another latticed running?",
                    path.display()
                ),
            ));
        }
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    // chmod before the listener is handed out: no accept happens before this.
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(listener)
}

/// Pre-bind the application socket (mode 0660; see note in README about the
/// group story — deliberately unchanged pending the D5 decision).
pub fn bind_app(cfg: &Config) -> std::io::Result<UnixListener> {
    bind_unix(&cfg.app_socket, 0o660)
}

/// Pre-bind the admin socket (mode 0600, owner-only).
pub fn bind_admin(cfg: &Config) -> std::io::Result<UnixListener> {
    bind_unix(&cfg.admin_socket, 0o600)
}

pub async fn serve_app(
    listener: UnixListener,
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
    events: broadcast::Sender<ServiceEvent>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = cfg.clone();
        let api = api.clone();
        let events = events.subscribe();
        tokio::spawn(handle_app(stream, cfg, api, events));
    }
}

pub async fn serve_admin(
    listener: UnixListener,
    api: mpsc::UnboundedSender<ApiCmd>,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let api = api.clone();
        tokio::spawn(handle_admin(stream, api));
    }
}
