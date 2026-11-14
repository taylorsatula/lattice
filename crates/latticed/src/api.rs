//! Local API servers. Two unix sockets:
//!
//! * application socket — per-service auth (constant-time secret check),
//!   exposes app operations only.
//! * admin socket — owner-only, exposes node/drain/link operations.
//!
//! Wire format: 4-byte big-endian length prefix, then one CBOR local-API
//! object (see V2_SPEC §7 and lattice-proto::local).

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use lattice_proto::local::*;
use lattice_proto::{Value, decode, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::runtime::ApiCmd;

const MAX_FRAME: usize = LOCAL_MAX_FRAME;

async fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    let framed = frame_local(payload)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&framed).await
}

async fn read_frame(
    stream: &mut UnixStream,
    buf: &mut Vec<u8>,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut chunk = [0u8; 8192];
    loop {
        match deframe_local(buf) {
            Ok(Some((payload, used))) => {
                let out = payload.to_vec();
                buf.drain(..used);
                return Ok(Some(out));
            }
            Ok(None) => {}
            Err(_) => return Ok(None),
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_FRAME + LOCAL_PREFIX_LEN + 1 {
            return Ok(None);
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

fn args_get(v: &Value, key: u64) -> Option<&Value> {
    args_map(v)?
        .iter()
        .find(|(k, _)| k.as_uint() == Some(key))
        .map(|(_, v)| v)
}

fn secret_eq(a: &[u8], b: &str) -> bool {
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).unwrap_u8() == 1
}

/// Application-socket connection handler.
async fn handle_app(
    mut stream: UnixStream,
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
    mut events: broadcast::Receiver<Vec<u8>>,
) {
    let mut buf = Vec::new();

    // First frame must be hello, within the deadline.
    let hello = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_frame(&mut stream, &mut buf),
    )
    .await
    {
        Ok(Ok(Some(f))) => f,
        _ => return,
    };
    let req = match decode(&hello)
        .ok()
        .and_then(|v| Request::from_value(&v).ok())
    {
        Some(r) => r,
        None => return,
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
    let node_id = if api.send(ApiCmd::NodeInfo { respond: tx }).is_ok() {
        rx.await.map(|info| info.id).unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };
    let hello_ok = Value::map(vec![
        (Value::UInt(0), Value::Bytes(node_id.to_vec())),
        (Value::UInt(1), Value::Text(service.clone())),
    ]);
    let _ = write_frame(&mut stream, &resp_ok(req.id, hello_ok)).await;

    loop {
        tokio::select! {
            ev = events.recv() => {
                if let Ok(bytes) = ev {
                    if let Ok(framed) = frame_local(&bytes) {
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                }
            }
            frame = read_frame(&mut stream, &mut buf) => {
                let Some(frame) = frame.ok().flatten() else { return };
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
                mid_hint: Some(lattice_crypto::os_bytes::<16>()),
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
            let Some(mid_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(mid) = <[u8; 16]>::try_from(mid_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::Status { mid, respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok(Some((status, detail))) => {
                    let mut pairs = vec![(Value::UInt(0), Value::UInt(status))];
                    if let Some(d) = detail {
                        pairs.push((Value::UInt(1), Value::UInt(d)));
                    }
                    resp_ok(req.id, Value::map(pairs))
                }
                Ok(None) => resp_err(req.id, ERR_NOT_FOUND),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_FETCH => {
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
                Ok(rows) => {
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
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_ACK => {
            let ids: Vec<[u8; 16]> = match args_get(&req.args, 0).and_then(Value::as_array) {
                Some(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()))
                    .collect(),
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
                Ok(n) => resp_ok(
                    req.id,
                    Value::map(vec![(Value::UInt(0), Value::UInt(n as u64))]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_LOOKUP => {
            let Some(id_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(id) = <[u8; 32]>::try_from(id_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            if api.send(ApiCmd::Lookup { id, respond: tx }).is_err() {
                return resp_err(req.id, ERR_INTERNAL);
            }
            match rx.await {
                Ok((have, mode, path)) => {
                    let mut pairs = vec![
                        (Value::UInt(0), Value::Bool(have)),
                        (Value::UInt(2), Value::Bool(path)),
                    ];
                    if let Some(m) = mode {
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
        let Some(frame) = read_frame(&mut stream, &mut buf).await.ok().flatten() else {
            return;
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
                Ok((draining, custody_bytes)) => resp_ok(
                    req.id,
                    Value::map(vec![
                        (Value::UInt(0), Value::Bool(draining)),
                        (Value::UInt(1), Value::UInt(custody_bytes as u64)),
                    ]),
                ),
                Err(_) => resp_err(req.id, ERR_INTERNAL),
            }
        }
        OP_LINK => {
            let Some(addr) = args_get(&req.args, 0)
                .and_then(Value::as_text)
                .map(String::from)
            else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let ik_key = match args_get(&req.args, 1) {
                Some(Value::Bytes(b)) => match <[u8; 32]>::try_from(b.as_slice()) {
                    Ok(k) => Some(k),
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
                    Ok(k) => Some(k),
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
        OP_UNLINK => {
            let Some(id) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
                return resp_err(req.id, ERR_BAD_ARGS);
            };
            let Ok(peer) = <[u8; 32]>::try_from(id) else {
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

/// Bind a socket path with the given mode, replacing any stale socket file.
fn bind_unix(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(listener)
}

pub async fn serve_app(
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
    events: broadcast::Sender<Vec<u8>>,
) -> std::io::Result<()> {
    let listener = bind_unix(&cfg.app_socket, 0o660)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = cfg.clone();
        let api = api.clone();
        let events = events.subscribe();
        tokio::spawn(handle_app(stream, cfg, api, events));
    }
}

pub async fn serve_admin(
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
) -> std::io::Result<()> {
    let listener = bind_unix(&cfg.admin_socket, 0o600)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let api = api.clone();
        tokio::spawn(handle_admin(stream, api));
    }
}
