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

use lattice_proto::local::{
    DrainRequest, DrainState, ERR_AUTH, ERR_BAD_ARGS, ERR_FAILED, ERR_INTERNAL, ERR_NOT_FOUND,
    ERR_UNKNOWN_OP, LOCAL_MAX_FRAME, LOCAL_PREFIX_LEN, Lookup, OP_ABANDON, OP_ACK, OP_DRAIN,
    OP_FETCH, OP_HELLO, OP_LINK, OP_LOOKUP, OP_NODE, OP_PING, OP_ROTATE, OP_ROTATE_ENVELOPE,
    OP_SEND, OP_STATUS, OP_UNLINK, ROUTE_DEFAULT, Request, Response, SendArgs, deframe_local,
    frame_local,
};
use lattice_proto::{Value, decode, encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot};

use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::runtime::{ApiCmd, LinkOutcome, ServiceEvent};
use lattice_core::RotationKind;

const MAX_FRAME: usize = LOCAL_MAX_FRAME;

/// Maximum simultaneous application-socket connections.
///
/// Fixed cap, not configurable. At the cap a new connection is dropped at
/// accept time without a single byte read or written (pre-auth silence,
/// same posture as the undecodable-hello path); the accept loop keeps
/// running. Slots are held by an owned semaphore permit for the life of
/// the connection task, so every exit path releases exactly one slot.
const MAX_APP_CONNECTIONS: usize = 64;

/// Read-idle timeout for an authenticated application-socket connection.
///
/// After the hello handshake completes, a connection that delivers no
/// inbound frame for this long is closed. Event-only subscribers (apps
/// that send nothing after hello) should send `OP_PING` periodically to
/// stay connected; any inbound frame resets the deadline.
const APP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

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

/// Send `cmd` (built around a fresh oneshot) to the runtime and map the
/// reply to response bytes. A send failure or a cancelled oneshot both
/// yield `ERR_INTERNAL`; `on_resp` encodes a successful reply.
async fn call_api<T>(
    api: &mpsc::UnboundedSender<ApiCmd>,
    req_id: u64,
    make_cmd: impl FnOnce(oneshot::Sender<T>) -> ApiCmd,
    on_resp: impl FnOnce(T) -> Vec<u8>,
) -> Vec<u8> {
    let (tx, rx) = oneshot::channel();
    if api.send(make_cmd(tx)).is_err() {
        return resp_err(req_id, ERR_INTERNAL);
    }
    match rx.await {
        Ok(resp) => on_resp(resp),
        Err(_) => resp_err(req_id, ERR_INTERNAL),
    }
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
///
/// `_permit` holds this connection's slot against MAX_APP_CONNECTIONS;
/// dropping it on any exit path releases the slot.
async fn handle_app(
    mut stream: UnixStream,
    cfg: Arc<Config>,
    api: mpsc::UnboundedSender<ApiCmd>,
    mut events: broadcast::Receiver<ServiceEvent>,
    _permit: OwnedSemaphorePermit,
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
    let Some(req) = decode(&hello)
        .ok()
        .and_then(|v| Request::from_value(&v).ok())
    else {
        eprintln!("lattice: app socket: hello frame did not decode as a request; closing");
        return;
    };
    if req.op != OP_HELLO {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_AUTH)).await;
        return;
    }
    let (Some(service), Some(secret)) = (
        args_get(&req.args, 0)
            .and_then(Value::as_text)
            .map(String::from),
        args_get(&req.args, 1)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
    ) else {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_BAD_ARGS)).await;
        return;
    };
    let ok = cfg
        .services
        .get(&service)
        .is_some_and(|s| secret_eq(&secret, &s.secret));
    if !ok {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_AUTH)).await;
        return;
    }
    // Hello reply carries the node identifier so apps can pin it.
    let (tx, rx) = oneshot::channel();
    let Ok(()) = api.send(ApiCmd::NodeInfo { respond: tx }) else {
        let _ = write_frame(&mut stream, &resp_err(req.id, ERR_INTERNAL)).await;
        return;
    };
    let node_id = match rx.await {
        Ok(info) => info.id,
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

    // Post-hello read-idle deadline. Only an inbound frame resets it;
    // outbound event traffic does not, so a silent subscriber is reaped.
    let mut idle_deadline = tokio::time::Instant::now() + APP_IDLE_TIMEOUT;
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
            frame = tokio::time::timeout_at(idle_deadline, read_frame(&mut stream, &mut buf)) => {
                let frame = match frame {
                    Ok(Ok(FrameRead::Frame(f))) => {
                        idle_deadline = tokio::time::Instant::now() + APP_IDLE_TIMEOUT;
                        f
                    }
                    Ok(Ok(FrameRead::Eof)) => return,
                    // Authenticated peer: tell it the stream is unusable instead of
                    // dropping the connection without a word.
                    Ok(Ok(FrameRead::BadFrame)) => {
                        eprintln!("lattice: app socket: undecodable frame; closing connection");
                        let _ = write_frame(&mut stream, &resp_err(0, ERR_BAD_ARGS)).await;
                        return;
                    }
                    Ok(Err(e)) => {
                        eprintln!("lattice: app socket: read error: {e}");
                        return;
                    }
                    Err(_) => {
                        eprintln!(
                            "lattice: app socket: no inbound frame for {}s; closing connection",
                            APP_IDLE_TIMEOUT.as_secs()
                        );
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
    service: &str,
    req: &Request,
) -> Vec<u8> {
    match req.op {
        OP_SEND => handle_send(api, service, req).await,
        OP_STATUS => handle_status(api, service, req).await,
        OP_FETCH => handle_fetch(api, service, req).await,
        OP_ACK => handle_ack(api, service, req).await,
        OP_LOOKUP => handle_lookup(api, req).await,
        OP_PING => {
            if deny_unknown_args(&req.args, &[]).is_err() {
                resp_err(req.id, ERR_BAD_ARGS)
            } else {
                // No-op; reaching this arm already reset the connection's
                // idle deadline in the read loop.
                resp_ok(req.id, Value::map(vec![]))
            }
        }
        _ => resp_err(req.id, ERR_UNKNOWN_OP),
    }
}

async fn handle_send(api: &mpsc::UnboundedSender<ApiCmd>, service: &str, req: &Request) -> Vec<u8> {
    let Some(args) = SendArgs::from_value(&req.args).ok() else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    let send = lattice_core::AppSend {
        service: service.to_string(),
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
    call_api(
        api,
        req.id,
        |tx| ApiCmd::AppSend { send, respond: tx },
        |mid| {
            resp_ok(
                req.id,
                Value::map(vec![(Value::UInt(0), Value::Bytes(mid.to_vec()))]),
            )
        },
    )
    .await
}

async fn handle_status(
    api: &mpsc::UnboundedSender<ApiCmd>,
    service: &str,
    req: &Request,
) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let Some(mid_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    let Ok(mid) = <[u8; 16]>::try_from(mid_bytes).map(lattice_types::MessageId::from_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Status {
            mid,
            service: service.to_string(),
            respond: tx,
        },
        |resp| match resp {
            Ok(Some(status)) => {
                let mut pairs = vec![(Value::UInt(0), Value::UInt(status.status))];
                if let Some(d) = status.detail {
                    pairs.push((Value::UInt(1), Value::UInt(d)));
                }
                resp_ok(req.id, Value::map(pairs))
            }
            Ok(None) => resp_err(req.id, ERR_NOT_FOUND),
            Err(e) => {
                eprintln!("lattice: status_get failed: {e}");
                resp_err(req.id, ERR_INTERNAL)
            }
        },
    )
    .await
}

fn fetch_item(e: lattice_store::InboxEntry) -> Value {
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
}

fn fetch_result(items: &[Value]) -> Value {
    Value::map(vec![(Value::UInt(0), Value::Array(items.to_vec()))])
}

/// Encode the `fetch` response, adding deliveries until the encoded frame
/// would exceed `LOCAL_MAX_FRAME`. At least one delivery is included
/// whenever any exist (a single delivery is far below the cap: a message
/// fits a 32 KiB bucket); the rest stay in the inbox for the next fetch,
/// which is safe because `fetch` does not consume. If a lone delivery
/// somehow exceeds the cap, an error response is returned instead of an
/// over-cap frame.
fn fetch_response(req_id: u64, rows: Vec<lattice_store::InboxEntry>) -> Vec<u8> {
    let mut items: Vec<Value> = Vec::with_capacity(rows.len().min(64));
    let mut encoded = None;
    for e in rows {
        items.push(fetch_item(e));
        let candidate = encode(
            &Response::Ok {
                id: req_id,
                result: fetch_result(&items),
            }
            .to_value(),
        );
        if candidate.len() > LOCAL_MAX_FRAME {
            if items.len() == 1 {
                return resp_err(req_id, ERR_INTERNAL);
            }
            items.pop();
            break;
        }
        encoded = Some(candidate);
    }
    encoded.unwrap_or_else(|| resp_ok(req_id, fetch_result(&items)))
}

async fn handle_fetch(
    api: &mpsc::UnboundedSender<ApiCmd>,
    service: &str,
    req: &Request,
) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let max = args_get(&req.args, 0)
        .and_then(Value::as_uint)
        .unwrap_or(16)
        .min(64) as usize;
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Fetch {
            service: service.to_string(),
            max,
            respond: tx,
        },
        |resp| match resp {
            Ok(rows) => fetch_response(req.id, rows),
            Err(e) => {
                eprintln!("lattice: inbox_fetch failed: {e}");
                resp_err(req.id, ERR_INTERNAL)
            }
        },
    )
    .await
}

async fn handle_ack(api: &mpsc::UnboundedSender<ApiCmd>, service: &str, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let ids: Vec<lattice_types::DeliveryId> = match args_get(&req.args, 0).and_then(Value::as_array)
    {
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
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Ack {
            service: service.to_string(),
            ids,
            respond: tx,
        },
        |resp| match resp {
            Ok(n) => resp_ok(
                req.id,
                Value::map(vec![(Value::UInt(0), Value::UInt(n as u64))]),
            ),
            Err(e) => {
                eprintln!("lattice: inbox_ack failed: {e}");
                resp_err(req.id, ERR_INTERNAL)
            }
        },
    )
    .await
}

async fn handle_lookup(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let Some(id_bytes) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    let Ok(id) = <[u8; 32]>::try_from(id_bytes).map(lattice_types::Identifier::from_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Lookup { id, respond: tx },
        |lookup| {
            let mut pairs = vec![
                (Value::UInt(0), Value::Bool(lookup.have())),
                (Value::UInt(2), Value::Bool(lookup.path())),
            ];
            if let Lookup::Present { mode: Some(m), .. } = lookup {
                pairs.push((Value::UInt(1), Value::UInt(m.as_u64())));
            }
            resp_ok(req.id, Value::map(pairs))
        },
    )
    .await
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
        OP_NODE => handle_node(api, req).await,
        OP_DRAIN => handle_drain(api, req).await,
        OP_LINK => handle_link(api, req).await,
        OP_ROTATE | OP_ABANDON => handle_rotate(api, req).await,
        OP_ROTATE_ENVELOPE => handle_rotate_envelope(api, req).await,
        OP_UNLINK => handle_unlink(api, req).await,
        _ => resp_err(req.id, ERR_UNKNOWN_OP),
    }
}

async fn handle_node(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    call_api(
        api,
        req.id,
        |tx| ApiCmd::NodeInfo { respond: tx },
        |info| {
            resp_ok(
                req.id,
                Value::map(vec![
                    (Value::UInt(0), Value::Bytes(info.id.to_vec())),
                    (Value::UInt(1), Value::Text(info.mode.into())),
                    (Value::UInt(2), Value::UInt(info.links as u64)),
                    (Value::UInt(3), Value::UInt(info.records as u64)),
                    (Value::UInt(4), Value::UInt(info.custody_bytes)),
                    (Value::UInt(5), Value::Bool(info.draining)),
                ]),
            )
        },
    )
    .await
}

async fn handle_drain(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    // Absent key 0 = query; present key 0 must be a bool.
    let request = match args_get(&req.args, 0) {
        None => DrainRequest::Query,
        Some(v) => match v.as_bool() {
            Some(true) => DrainRequest::Set(DrainState::Draining),
            Some(false) => DrainRequest::Set(DrainState::Serving),
            None => return resp_err(req.id, ERR_BAD_ARGS),
        },
    };
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Drain {
            request,
            respond: tx,
        },
        |state| {
            resp_ok(
                req.id,
                Value::map(vec![
                    (Value::UInt(0), Value::Bool(state.draining)),
                    (Value::UInt(1), Value::UInt(state.custody_bytes)),
                ]),
            )
        },
    )
    .await
}

async fn handle_link(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
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
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Link {
            addr,
            ik_key,
            path,
            peer_id,
            respond: tx,
        },
        |outcome| match outcome {
            LinkOutcome::Queued => resp_ok(
                req.id,
                Value::map(vec![(Value::UInt(0), Value::Bool(true))]),
            ),
            LinkOutcome::Rejected => resp_err(req.id, ERR_BAD_ARGS),
        },
    )
    .await
}

async fn handle_rotate(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    let abandon = req.op == OP_ABANDON;
    // Rotate takes the offline next key (0) and the commitment to the
    // following key (1); abandon takes only the next key.
    let allowed: &[u64] = if abandon { &[0] } else { &[0, 1] };
    if deny_unknown_args(&req.args, allowed).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let next_key: [u8; 32] = match args_get(&req.args, 0)
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
    {
        Some(k) => k,
        None => return resp_err(req.id, ERR_BAD_ARGS),
    };
    let next_next_commitment: Option<[u8; 32]> = if abandon {
        None
    } else {
        match args_get(&req.args, 1)
            .and_then(Value::as_bytes)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            Some(c) => Some(c),
            None => return resp_err(req.id, ERR_BAD_ARGS),
        }
    };
    let kind = if abandon {
        RotationKind::Abandon
    } else {
        RotationKind::Rotate
    };
    call_api(
        api,
        req.id,
        |tx| ApiCmd::Rotate {
            next_key,
            next_next_commitment,
            kind,
            respond: tx,
        },
        |result| match result {
            Ok(msg) => resp_ok(req.id, Value::map(vec![(Value::UInt(0), Value::Text(msg))])),
            Err(e) => {
                eprintln!("lattice: rotate failed: {e}");
                resp_err(req.id, ERR_FAILED)
            }
        },
    )
    .await
}

async fn handle_rotate_envelope(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    call_api(
        api,
        req.id,
        |tx| ApiCmd::RotateEnvelope { respond: tx },
        |result| match result {
            Ok(msg) => resp_ok(req.id, Value::map(vec![(Value::UInt(0), Value::Text(msg))])),
            Err(e) => {
                eprintln!("lattice: envelope rotation failed: {e}");
                resp_err(req.id, ERR_FAILED)
            }
        },
    )
    .await
}

async fn handle_unlink(api: &mpsc::UnboundedSender<ApiCmd>, req: &Request) -> Vec<u8> {
    if deny_unknown_args(&req.args, &[0]).is_err() {
        return resp_err(req.id, ERR_BAD_ARGS);
    }
    let Some(id) = args_get(&req.args, 0).and_then(Value::as_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    let Ok(peer) = <[u8; 32]>::try_from(id).map(lattice_types::Identifier::from_bytes) else {
        return resp_err(req.id, ERR_BAD_ARGS);
    };
    call_api(
        api,
        req.id,
        |tx| ApiCmd::UnlinkByPeer { peer, respond: tx },
        |removed| {
            resp_ok(
                req.id,
                Value::map(vec![(Value::UInt(0), Value::Bool(removed > 0))]),
            )
        },
    )
    .await
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
    let slots = Arc::new(Semaphore::new(MAX_APP_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        // At the cap: drop the connection without reading or writing a
        // byte (pre-auth silence) and keep accepting.
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!(
                "lattice: app socket: at {MAX_APP_CONNECTIONS} connections; dropping new connection"
            );
            drop(stream);
            continue;
        };
        let cfg = cfg.clone();
        let api = api.clone();
        let events = events.subscribe();
        tokio::spawn(handle_app(stream, cfg, api, events, permit));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(body_len: usize, tag: u8) -> lattice_store::InboxEntry {
        lattice_store::InboxEntry {
            delivery_id: lattice_types::DeliveryId::from_bytes([tag; 16]),
            mid: lattice_types::MessageId::from_bytes([tag.wrapping_add(1); 16]),
            from: lattice_types::Identifier::from_bytes([tag.wrapping_add(2); 32]),
            fsvc: "svc".to_string(),
            fmbx: b"fmbx".to_vec(),
            tsvc: "svc".to_string(),
            tmbx: b"tmbx".to_vec(),
            body: vec![tag; body_len],
            received: 1_700_000_000,
        }
    }

    fn decode_fetch_response(bytes: &[u8]) -> (u64, Vec<Value>) {
        let v = decode(bytes).expect("response decodes");
        match Response::from_value(&v).expect("response parses") {
            Response::Ok { id, result } => {
                let items = lattice_proto::cbor::map_get(&result, 0)
                    .and_then(Value::as_array)
                    .map(<[Value]>::to_vec)
                    .expect("fetch result carries an items array");
                (id, items)
            }
            Response::Err { code, .. } => panic!("expected ok response, got error {code}"),
        }
    }

    #[test]
    fn fetch_response_caps_at_frame_limit() {
        // ~30 KB bodies: two fit under the 64 KiB cap, three do not.
        let rows: Vec<_> = (0..5).map(|i| entry(30 * 1024, i + 1)).collect();
        let out = fetch_response(7, rows);
        assert!(out.len() <= LOCAL_MAX_FRAME);
        let (id, items) = decode_fetch_response(&out);
        assert_eq!(id, 7);
        assert!(!items.is_empty(), "at least one delivery must be returned");
        assert!(items.len() < 5);
    }

    #[test]
    fn fetch_response_returns_a_maximal_prefix() {
        let rows: Vec<_> = (0..5).map(|i| entry(30 * 1024, i + 1)).collect();
        let out = fetch_response(7, rows.clone());
        let (_, items) = decode_fetch_response(&out);
        // One more delivery on top of the returned set must exceed the cap.
        let mut bigger = items.clone();
        bigger.push(fetch_item(rows[items.len()].clone()));
        let encoded = encode(
            &Response::Ok {
                id: 7,
                result: fetch_result(&bigger),
            }
            .to_value(),
        );
        assert!(encoded.len() > LOCAL_MAX_FRAME);
    }

    #[test]
    fn fetch_response_returns_all_when_small() {
        let rows: Vec<_> = (0..3).map(|i| entry(16, i + 1)).collect();
        let out = fetch_response(9, rows);
        let (id, items) = decode_fetch_response(&out);
        assert_eq!(id, 9);
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn fetch_response_empty_inbox() {
        let out = fetch_response(11, vec![]);
        let (id, items) = decode_fetch_response(&out);
        assert_eq!(id, 11);
        assert!(items.is_empty());
    }

    #[test]
    fn fetch_response_single_oversized_delivery_errors_instead_of_overflowing() {
        // A lone delivery larger than the frame cap must not produce an
        // over-cap frame; the daemon reports an internal error instead.
        let out = fetch_response(13, vec![entry(LOCAL_MAX_FRAME + 1, 1)]);
        assert!(out.len() <= LOCAL_MAX_FRAME);
        let v = decode(&out).unwrap();
        match Response::from_value(&v).unwrap() {
            Response::Err { id, code } => {
                assert_eq!(id, 13);
                assert_eq!(code, ERR_INTERNAL);
            }
            Response::Ok { .. } => panic!("expected error response"),
        }
    }

    #[tokio::test]
    async fn ping_returns_empty_ok() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let req = Request {
            id: 42,
            op: OP_PING,
            args: Value::map(vec![]),
        };
        let out = dispatch_app(&tx, "svc", &req).await;
        let v = decode(&out).expect("response decodes");
        match Response::from_value(&v).expect("response parses") {
            Response::Ok { id, result } => {
                assert_eq!(id, 42);
                assert_eq!(result, Value::map(vec![]));
            }
            Response::Err { code, .. } => panic!("expected ok, got error {code}"),
        }
    }

    #[tokio::test]
    async fn ping_rejects_args() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let req = Request {
            id: 43,
            op: OP_PING,
            args: Value::map(vec![(Value::UInt(0), Value::UInt(1))]),
        };
        let out = dispatch_app(&tx, "svc", &req).await;
        let v = decode(&out).expect("response decodes");
        match Response::from_value(&v).expect("response parses") {
            Response::Err { id, code } => {
                assert_eq!(id, 43);
                assert_eq!(code, ERR_BAD_ARGS);
            }
            Response::Ok { .. } => panic!("expected error"),
        }
    }
}
