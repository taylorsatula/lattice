//! The daemon runtime: wires lattice-core to the transport and the two
//! local sockets (application and admin).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lattice_core::{Action, Event, Node};
use lattice_crypto::os_bytes;
use lattice_proto::frames::Frame;
use lattice_store::{RedbStore, Store, StoreError};
use lattice_types::{
    ChannelPublicKey, ChannelSeed, DeliveryId, Identifier, MessageId, X25519PublicKey,
};
use tokio::sync::{broadcast, mpsc};

use crate::config::Config;

/// Events coming up from links into the node.
pub enum LinkEvent {
    Frame { link: u64, frame: Frame },
    Down { link: u64 },
}

pub enum Cmd {
    Dial {
        addr: String,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
    },
}

/// Oneshot reply channel for store-backed queries; the socket layer maps
/// the error to ERR_INTERNAL.
type StoreReply<T> = tokio::sync::oneshot::Sender<Result<T, StoreError>>;

/// Requests arriving over the local API sockets. Each carries a oneshot for
/// its reply. Processed inside the runtime loop so the Node is never
/// contended across tasks.
pub enum ApiCmd {
    AppSend {
        send: lattice_core::AppSend,
        respond: tokio::sync::oneshot::Sender<MessageId>,
    },
    Status {
        mid: MessageId,
        respond: StoreReply<Option<(u64, Option<u64>)>>,
    },
    Fetch {
        service: String,
        max: usize,
        respond: StoreReply<Vec<lattice_store::InboxEntry>>,
    },
    Ack {
        service: String,
        ids: Vec<DeliveryId>,
        respond: StoreReply<usize>,
    },
    Lookup {
        id: Identifier,
        respond: tokio::sync::oneshot::Sender<(bool, Option<u64>, bool)>,
    },
    NodeInfo {
        respond: tokio::sync::oneshot::Sender<NodeInfo>,
    },
    /// None = report only; Some(d) = set draining to d. Returns (draining, custody_bytes).
    Drain {
        draining: Option<bool>,
        respond: tokio::sync::oneshot::Sender<(bool, usize)>,
    },
    /// Rotate the signing key. `next_key_file` overrides the default location.
    Rotate {
        next_key_file: Option<String>,
        abandon: bool,
        respond: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Rotate the envelope (X-Wing) key; old key kept decrypt-only for 2 days.
    RotateEnvelope {
        respond: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    UnlinkByPeer {
        peer: Identifier,
        respond: tokio::sync::oneshot::Sender<bool>,
    },
    Link {
        addr: String,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
        respond: tokio::sync::oneshot::Sender<bool>,
    },
}

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub id: Identifier,
    pub mode: &'static str,
    pub links: usize,
    pub records: usize,
    pub custody_bytes: u64,
    pub draining: bool,
}

/// A frame plus the transport's padding hint (bucket index).
pub(crate) struct OutFrame {
    frame: Frame,
    pad_to: Option<usize>,
}

/// A configured root to dial, with redial backoff state. The daemon keeps
/// trying roots that are unreachable at startup (or that drop later) instead
/// of giving up after one attempt.
pub struct RootSpec {
    pub addr: std::net::SocketAddr,
    pub ik_key: Option<ChannelPublicKey>,
    pub path: Option<String>,
    pub peer_id: Option<Identifier>,
}

struct RootDial {
    addr: std::net::SocketAddr,
    ik_key: Option<ChannelPublicKey>,
    path: Option<String>,
    peer_id: Option<Identifier>,
    next_attempt: u64,
    attempts: u32,
    in_flight: bool,
}

struct LinkHandle {
    peer: Option<Identifier>,
    addr: Option<std::net::SocketAddr>,
    tx: mpsc::UnboundedSender<OutFrame>,
    task: tokio::task::AbortHandle,
}

pub struct Runtime {
    pub node: Arc<std::sync::Mutex<Node<RedbStore>>>,
    pub draining: Arc<AtomicBool>,
    mode: &'static str,
    identity_dir: std::path::PathBuf,
    channel_seed: ChannelSeed,
    links: HashMap<u64, LinkHandle>,
    peer_rx: Option<mpsc::UnboundedReceiver<lattice_net::PeerIo>>,
    link_rx: Option<mpsc::UnboundedReceiver<LinkEvent>>,
    link_tx: mpsc::UnboundedSender<LinkEvent>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    roots: Vec<RootDial>,
    api_rx: Option<mpsc::UnboundedReceiver<ApiCmd>>,
    api_tx: mpsc::UnboundedSender<ApiCmd>,
    pub app_broadcast: broadcast::Sender<(String, Vec<u8>)>,
    next_link: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Outbound frame writer for one link.
async fn link_task(
    id: u64,
    mut io: lattice_net::PeerIo,
    inbound: mpsc::UnboundedSender<LinkEvent>,
    mut outbound: mpsc::UnboundedReceiver<OutFrame>,
) {
    loop {
        tokio::select! {
            f = outbound.recv() => {
                match f {
                    Some(out) => {
                        if io.send_frame(&out.frame, out.pad_to).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            res = io.recv_frame() => {
                match res {
                    Ok(Some(frame)) => {
                        let _ = inbound.send(LinkEvent::Frame { link: id, frame });
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
    let _ = inbound.send(LinkEvent::Down { link: id });
}

impl Runtime {
    pub fn new(
        cfg: &Config,
        identity: lattice_core::Identity,
        store: RedbStore,
        now: u64,
        peer_rx: mpsc::UnboundedReceiver<lattice_net::PeerIo>,
        draining: Arc<AtomicBool>,
    ) -> Self {
        let channel_seed = identity.channel_seed.clone();
        let mode = if cfg.mode == "private" {
            lattice_proto::record::Mode::Private
        } else {
            lattice_proto::record::Mode::Public
        };
        let gateways: Vec<Identifier> = cfg
            .gateways
            .iter()
            .map(|h| {
                Identifier::from_bytes(
                    crate::config::decode_hex32(h).expect("config validation checked gateway hex"),
                )
            })
            .collect();
        let core_cfg = lattice_core::Config {
            snow_per_min: cfg.limits.snow_per_min,
            sideways_prob: cfg.limits.sideways_prob,
            waypoint_share: cfg.limits.waypoint_share,
            reconcile_interval_secs: cfg.limits.reconcile_interval_secs,
            custody_allowance: cfg.limits.custody_allowance,
            transit_cap: cfg.limits.transit_cap,
            inbox_max_deliveries: cfg.limits.inbox_max,
            inbox_max_total: cfg.limits.inbox_max_total,
            rng_seed: u64::from_le_bytes(os_bytes::<8>()),
            advertise: cfg.advertise.clone(),
            gateways,
            mode,
            ..lattice_core::Config::default()
        };
        let mut node = Node::new(core_cfg, identity, store, now).expect("node init");
        if draining.load(Ordering::Relaxed) {
            node.set_draining(true);
        }
        let (link_tx, link_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (api_tx, api_rx) = mpsc::unbounded_channel();
        let (app_broadcast, _) = broadcast::channel(256);
        Self {
            node: Arc::new(std::sync::Mutex::new(node)),
            draining,
            mode: if cfg.mode == "private" {
                "private"
            } else {
                "public"
            },
            identity_dir: cfg.identity_dir.clone(),
            channel_seed,
            links: HashMap::new(),
            link_rx: Some(link_rx),
            link_tx,
            peer_rx: Some(peer_rx),
            cmd_rx,
            cmd_tx,
            roots: Vec::new(),
            api_rx: Some(api_rx),
            api_tx,
            app_broadcast,
            next_link: 1,
        }
    }

    pub fn api_tx(&self) -> mpsc::UnboundedSender<ApiCmd> {
        self.api_tx.clone()
    }

    /// Register an established peer connection.
    pub fn attach_link(
        &mut self,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
        io: lattice_net::PeerIo,
        addr: Option<std::net::SocketAddr>,
    ) -> u64 {
        let id = self.next_link;
        self.next_link += 1;
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let inbound = self.link_tx.clone();
        let task = tokio::spawn(link_task(id, io, inbound, outbound_rx));
        self.links.insert(
            id,
            LinkHandle {
                peer,
                addr,
                tx: outbound_tx,
                task: task.abort_handle(),
            },
        );
        // The link is registered, so the actions returned by LinkUp (the
        // attestation frame) can be routed to it.
        let actions = {
            let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
            node.handle(Event::LinkUp {
                at: now_secs(),
                link: id,
                peer,
                remote_ck,
                wan: true,
            })
        };
        self.apply_actions(actions);
        id
    }

    /// Register the configured roots. Each is dialed immediately and then
    /// retried with exponential backoff (capped at 60s) until a link to it
    /// is established; if the link later drops, dialing resumes.
    pub fn set_roots(&mut self, roots: Vec<RootSpec>) {
        self.roots = roots
            .into_iter()
            .map(|r| RootDial {
                addr: r.addr,
                ik_key: r.ik_key,
                path: r.path,
                peer_id: r.peer_id,
                next_attempt: 0,
                attempts: 0,
                in_flight: false,
            })
            .collect();
        self.redial_roots();
    }

    /// Queue a dial for every root that is due and not currently connected.
    fn redial_roots(&mut self) {
        let now = now_secs();
        for root in &mut self.roots {
            let connected = self.links.values().any(|l| l.addr == Some(root.addr));
            if connected {
                root.attempts = 0;
                root.next_attempt = now + 5;
                continue;
            }
            if root.in_flight || now < root.next_attempt {
                continue;
            }
            root.in_flight = true;
            let backoff = (1u64 << root.attempts.min(6)).min(60);
            root.attempts += 1;
            root.next_attempt = now + backoff;
            let _ = self.cmd_tx.send(Cmd::Dial {
                addr: root.addr.to_string(),
                ik_key: root.ik_key,
                path: root.path.clone(),
                peer_id: root.peer_id,
            });
        }
    }

    /// Enter drain: refuse new custody, persist the flag, and report.
    /// Called on SIGTERM/SIGINT before the process exits.
    fn begin_drain(&mut self) {
        self.draining.store(true, Ordering::Relaxed);
        let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
        node.set_draining(true);
        if let Err(e) = node.store_mut().drain_set(true) {
            eprintln!("lattice: failed to persist drain flag: {e}");
        }
        eprintln!("lattice: draining (refusing new custody); exiting");
    }

    pub async fn run(mut self, shutdown: impl std::future::Future<Output = ()>) {
        let mut link_rx = self.link_rx.take().expect("run once");
        let mut api_rx = self.api_rx.take().expect("run once");
        let mut peer_rx = self.peer_rx.take().expect("run once");
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    self.begin_drain();
                    return;
                }
                Some(peer) = peer_rx.recv() => {
                    let ck = peer.remote_static;
                    self.attach_link(None, ck, peer, None);
                }
                Some(api) = api_rx.recv() => self.handle_api(api),
                Some(cmd) = self.cmd_rx.recv() => match cmd {
                    Cmd::Dial { addr, ik_key, path, peer_id } => self.handle_dial(addr, ik_key, path, peer_id).await,
                },
                Some(ev) = link_rx.recv() => match ev {
                    LinkEvent::Frame { link, frame } => {
                        let peer = self.links.get(&link).and_then(|l| l.peer);
                        self.apply(Event::Frame { at: now_secs(), link, from: peer.unwrap_or(Identifier::from_bytes([0u8; 32])), frame });
                    }
                    LinkEvent::Down { link } => {
                        if self.links.remove(&link).is_some() {
                            self.apply(Event::LinkDown { at: now_secs(), link });
                        }
                    }
                },
                _ = tick.tick() => {
                    self.redial_roots();
                    self.apply(Event::Tick { at: now_secs() });
                }
            }
        }
    }

    fn apply(&mut self, event: Event) {
        let actions = {
            let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
            node.handle(event)
        };
        self.apply_actions(actions);
    }

    fn apply_actions(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::SendFrame {
                    link,
                    frame,
                    pad_to,
                } => {
                    if let Some(h) = self.links.get(&link) {
                        let _ = h.tx.send(OutFrame { frame, pad_to });
                    }
                }
                // Deliver is followed by an Inbox action carrying the unread
                // count; the Inbox event is the one apps consume.
                Action::Deliver { .. } => {}
                Action::Status {
                    mid,
                    status,
                    service,
                    ..
                } => {
                    let _ = self
                        .app_broadcast
                        .send((service, encode_status_event(mid, status)));
                }
                Action::Inbox { service, unread } => {
                    let _ = self
                        .app_broadcast
                        .send((service, encode_inbox_event(unread)));
                }
            }
        }
    }

    fn handle_api(&mut self, api: ApiCmd) {
        match api {
            ApiCmd::AppSend { send, respond } => {
                let mid = send
                    .mid_hint
                    .unwrap_or_else(|| MessageId::from_bytes(lattice_crypto::os_bytes::<16>()));
                let send = lattice_core::AppSend {
                    mid_hint: Some(mid),
                    ..send
                };
                let actions = {
                    let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                    node.handle(Event::AppSend(send))
                };
                self.apply_actions(actions);
                let _ = respond.send(mid);
            }
            ApiCmd::Status { mid, respond } => {
                let node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                let value = node.store_ref().status_get(&mid);
                let _ = respond.send(value);
            }
            ApiCmd::Fetch {
                service,
                max,
                respond,
            } => {
                let node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                let rows = node.store_ref().inbox_fetch(&service, max);
                let _ = respond.send(rows);
            }
            ApiCmd::Ack {
                service,
                ids,
                respond,
            } => {
                let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                let n = node.store_mut().inbox_ack(&service, &ids);
                let _ = respond.send(n);
            }
            ApiCmd::Lookup { id, respond } => {
                let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                let (have, mode) = node.lookup(&id);
                let path = node.has_path(&id);
                let _ = respond.send((have, mode, path));
            }
            ApiCmd::NodeInfo { respond } => {
                let node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                let info = NodeInfo {
                    id: node.own_id,
                    mode: self.mode,
                    links: self.links.len(),
                    records: node.debug_record_count(),
                    custody_bytes: node.custody_bytes(),
                    draining: node.is_draining(),
                };
                let _ = respond.send(info);
            }
            ApiCmd::Drain { draining, respond } => {
                let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(d) = draining {
                    node.set_draining(d);
                    self.draining.store(d, Ordering::Relaxed);
                    if let Err(e) = node.store_mut().drain_set(d) {
                        eprintln!("lattice: failed to persist drain flag: {e}");
                    }
                }
                let _ = respond.send((node.is_draining(), node.custody_bytes() as usize));
            }
            ApiCmd::Link {
                addr,
                ik_key,
                path,
                peer_id,
                respond,
            } => {
                let ok = addr.parse::<std::net::SocketAddr>().is_ok()
                    && (ik_key.is_some() || path.is_some());
                if ok {
                    let _ = self.cmd_tx.send(Cmd::Dial {
                        addr,
                        ik_key,
                        path,
                        peer_id,
                    });
                }
                let _ = respond.send(ok);
            }
            ApiCmd::Rotate {
                next_key_file,
                abandon,
                respond,
            } => {
                let result = (|| {
                    let dir = self.identity_dir.clone();
                    let rotation = crate::keys::rotate_signing_key(
                        &dir,
                        next_key_file.as_deref().map(std::path::Path::new),
                        abandon,
                    )
                    .map_err(|e| e.to_string())?;
                    let now = now_secs();
                    let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                    node.reload_identity(rotation.identity, now, !abandon)
                        .map_err(|e| e.to_string())?;
                    if abandon {
                        node.set_draining(true);
                        self.draining.store(true, Ordering::Relaxed);
                        if let Err(e) = node.store_mut().drain_set(true) {
                            eprintln!("lattice: failed to persist drain flag: {e}");
                        }
                    }
                    Ok(if abandon {
                        "identity abandoned".to_string()
                    } else {
                        format!(
                            "rotated; next key written to {}",
                            rotation
                                .next_key_path
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "<none>".into())
                        )
                    })
                })();
                let _ = respond.send(result);
            }
            ApiCmd::RotateEnvelope { respond } => {
                let result = (|| {
                    let dir = self.identity_dir.clone();
                    let identity = crate::keys::rotate_envelope_key(&dir, 2 * 24 * 3600)
                        .map_err(|e| e.to_string())?;
                    let now = now_secs();
                    let mut node = self.node.lock().unwrap_or_else(|e| e.into_inner());
                    node.reload_identity(identity, now, true)
                        .map_err(|e| e.to_string())?;
                    Ok("envelope key rotated; old key kept decrypt-only for 2 days".to_string())
                })();
                let _ = respond.send(result);
            }
            ApiCmd::UnlinkByPeer { peer, respond } => {
                let before = self.links.len();
                self.unlink(peer);
                let _ = respond.send(self.links.len() < before);
            }
        }
    }

    async fn handle_dial(
        &mut self,
        addr: String,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
    ) {
        let addr: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        let pinned = pinned_peer(ik_key.is_some(), peer_id);
        if peer_id.is_some() && pinned.is_none() {
            eprintln!(
                "lattice: ignoring configured peer id for {addr}: XX dials authenticate no one; \
                 attribution will come from records"
            );
        }
        let contact = match (ik_key, path) {
            (Some(ck), _) => lattice_net::PeerContact::Ik {
                addr,
                channel_key: ck,
            },
            (None, Some(p)) => lattice_net::PeerContact::Xx { addr, path: p },
            (None, None) => return,
        };
        match lattice_net::connect(contact, &self.channel_seed).await {
            Ok(io) => {
                let remote_ck = io.remote_static;
                self.attach_link(pinned, remote_ck, io, Some(addr));
                if let Some(root) = self.roots.iter_mut().find(|r| r.addr == addr) {
                    root.attempts = 0;
                    root.next_attempt = now_secs() + 60;
                }
            }
            Err(e) => {
                eprintln!("lattice: dial {addr} failed: {e}");
            }
        }
        if let Some(root) = self.roots.iter_mut().find(|r| r.addr == addr) {
            root.in_flight = false;
        }
    }

    fn unlink(&mut self, peer: Identifier) {
        let dead: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| l.peer == Some(peer))
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            if let Some(h) = self.links.remove(&id) {
                h.task.abort();
            }
            self.apply(Event::LinkDown {
                at: now_secs(),
                link: id,
            });
        }
    }
}

fn encode_inbox_event(unread: u64) -> Vec<u8> {
    encode_event(
        1,
        &lattice_proto::Value::map(vec![(
            lattice_proto::Value::UInt(1),
            lattice_proto::Value::UInt(unread),
        )]),
    )
}

fn encode_event(event: u64, data: &lattice_proto::Value) -> Vec<u8> {
    let v = lattice_proto::Value::map(vec![
        (
            lattice_proto::Value::UInt(3),
            lattice_proto::Value::UInt(event),
        ),
        (lattice_proto::Value::UInt(2), data.clone()),
    ]);
    lattice_proto::encode(&v)
}

fn encode_status_event(mid: MessageId, status: u64) -> Vec<u8> {
    encode_event(
        2,
        &lattice_proto::Value::map(vec![
            (
                lattice_proto::Value::UInt(0),
                lattice_proto::Value::Bytes(mid.to_vec()),
            ),
            (
                lattice_proto::Value::UInt(1),
                lattice_proto::Value::UInt(status),
            ),
        ]),
    )
}

/// Pin the configured peer id only for IK-authenticated dials. An XX dial
/// proves nothing about who is on the other end; pinning then would bind the
/// link to an unverified id. Record-based attribution binds it later.
fn pinned_peer(ik: bool, peer_id: Option<Identifier>) -> Option<Identifier> {
    if ik { peer_id } else { None }
}

#[cfg(test)]
mod tests {
    use super::pinned_peer;
    use lattice_types::Identifier;

    #[test]
    fn ik_dial_pins_configured_id() {
        let id = Identifier::from_bytes([7u8; 32]);
        assert_eq!(pinned_peer(true, Some(id)), Some(id));
        assert_eq!(pinned_peer(true, None), None);
    }

    #[test]
    fn xx_dial_never_pins() {
        let id = Identifier::from_bytes([7u8; 32]);
        assert_eq!(pinned_peer(false, Some(id)), None);
        assert_eq!(pinned_peer(false, None), None);
    }
}
