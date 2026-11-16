//! The daemon runtime: wires lattice-core to the transport and the two
//! local sockets (application and admin).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use lattice_core::{Action, Event, Node, RotationKind};
use lattice_crypto::os_bytes;
use lattice_proto::frames::Frame;
use lattice_proto::local::{DrainRequest, DrainState, DrainStatus, Lookup, MessageStatus};
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
        addr: std::net::SocketAddr,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
    },
}

/// Outcome of a dial spawned off the event loop, delivered back over a
/// channel the loop selects on. `pinned` is the peer id to attribute the
/// link to (IK dials only), resolved before the dial was spawned.
pub struct DialOutcome {
    addr: std::net::SocketAddr,
    pinned: Option<Identifier>,
    result: Result<lattice_net::PeerIo, lattice_net::NetError>,
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
        respond: StoreReply<Option<MessageStatus>>,
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
        respond: tokio::sync::oneshot::Sender<Lookup>,
    },
    NodeInfo {
        respond: tokio::sync::oneshot::Sender<NodeInfo>,
    },
    /// Query or set drain mode; the reply carries the resulting state.
    Drain {
        request: DrainRequest,
        respond: tokio::sync::oneshot::Sender<DrainStatus>,
    },
    /// Rotate the signing key. `next_key` is the offline pre-committed key
    /// the operator supplied over the admin socket; `next_next_commitment`
    /// commits to the following key (`None` for abandon).
    Rotate {
        next_key: [u8; 32],
        next_next_commitment: Option<[u8; 32]>,
        kind: RotationKind,
        respond: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    /// Rotate the envelope (X-Wing) key; old key kept decrypt-only for 2 days.
    RotateEnvelope {
        respond: tokio::sync::oneshot::Sender<Result<String, String>>,
    },
    UnlinkByPeer {
        peer: Identifier,
        respond: tokio::sync::oneshot::Sender<usize>,
    },
    Link {
        addr: String,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
        respond: tokio::sync::oneshot::Sender<LinkOutcome>,
    },
}

/// Outcome of a link request: whether the daemon queued the dial, or
/// rejected it (unparseable address).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    Queued,
    Rejected,
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

/// An application-facing event tagged with the service it belongs to; the
/// daemon fans it out to that service's connections only.
#[derive(Clone, Debug)]
pub struct ServiceEvent {
    pub service: String,
    pub payload: Vec<u8>,
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

/// Overall deadline for one dial (connect, WebSocket upgrade, handshake).
/// The TCP connect itself has its own 5s timeout in lattice-net; this
/// bounds everything else so a spawned dial cannot hang forever and pin a
/// root's `in_flight` slot.
const DIAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

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
    dial_rx: Option<mpsc::UnboundedReceiver<DialOutcome>>,
    dial_tx: mpsc::UnboundedSender<DialOutcome>,
    link_rx: Option<mpsc::UnboundedReceiver<LinkEvent>>,
    link_tx: mpsc::UnboundedSender<LinkEvent>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    roots: Vec<RootDial>,
    api_rx: Option<mpsc::UnboundedReceiver<ApiCmd>>,
    api_tx: mpsc::UnboundedSender<ApiCmd>,
    pub app_broadcast: broadcast::Sender<ServiceEvent>,
    next_link: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Surface non-fatal internal failures reported by the sans-IO core.
/// `eprintln!` is the daemon's diagnostic channel (see `main.rs`).
fn report_diagnostics(diags: Vec<lattice_core::Diagnostic>) {
    for d in diags {
        eprintln!("lattice: node diagnostic: {}: {}", d.op, d.detail);
    }
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
    ) -> Result<Self, lattice_core::NodeError> {
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
                Ok(Identifier::from_bytes(
                    crate::config::decode_hex32(h).map_err(|e| {
                        lattice_core::NodeError::Config(format!("gateway {h:?}: {e}"))
                    })?,
                ))
            })
            .collect::<Result<_, lattice_core::NodeError>>()?;
        let mut services: Vec<String> = cfg.services.keys().cloned().collect();
        services.sort_unstable();
        let core_cfg = lattice_core::Config {
            services,
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
        let mut node = Node::new(core_cfg, identity, store, now)?;
        if draining.load(Ordering::Relaxed) {
            node.set_drain(DrainState::Draining);
        }
        let (link_tx, link_rx) = mpsc::unbounded_channel();
        let (dial_tx, dial_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (api_tx, api_rx) = mpsc::unbounded_channel();
        let (app_broadcast, _) = broadcast::channel(256);
        Ok(Self {
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
            dial_rx: Some(dial_rx),
            dial_tx,
            cmd_rx,
            cmd_tx,
            roots: Vec::new(),
            api_rx: Some(api_rx),
            api_tx,
            app_broadcast,
            next_link: 1,
        })
    }

    pub fn api_tx(&self) -> mpsc::UnboundedSender<ApiCmd> {
        self.api_tx.clone()
    }

    /// Lock the node, recovering a poisoned mutex by taking the inner
    /// value. The node is the source of truth for custody state; a panic
    /// elsewhere must not wedge the daemon, so poisoning is recovered here
    /// and nowhere else.
    fn with_node<R>(&self, f: impl FnOnce(&mut Node<RedbStore>) -> R) -> R {
        let mut node = self
            .node
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut node)
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
        let (actions, diags) = self.with_node(|node| {
            node.handle(Event::LinkUp {
                at: now_secs(),
                link: id,
                peer,
                remote_ck,
            })
        });
        report_diagnostics(diags);
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
                addr: root.addr,
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
        self.with_node(|node| {
            node.set_drain(DrainState::Draining);
            if let Err(e) = node.store_mut().drain_set(DrainState::Draining) {
                eprintln!("lattice: failed to persist drain flag: {e}");
            }
        });
        eprintln!("lattice: draining (refusing new custody); exiting");
    }

    pub async fn run(mut self, shutdown: impl std::future::Future<Output = ()>) {
        let mut link_rx = self.link_rx.take().expect("run once");
        let mut api_rx = self.api_rx.take().expect("run once");
        let mut peer_rx = self.peer_rx.take().expect("run once");
        let mut dial_rx = self.dial_rx.take().expect("run once");
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
                Some(outcome) = dial_rx.recv() => self.handle_dial_outcome(outcome),
                Some(api) = api_rx.recv() => self.handle_api(api),
                Some(cmd) = self.cmd_rx.recv() => match cmd {
                    Cmd::Dial { addr, ik_key, path, peer_id } => self.spawn_dial(addr, ik_key, path, peer_id),
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
        let (actions, diags) = self.with_node(|node| node.handle(event));
        report_diagnostics(diags);
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
                    let _ = self.app_broadcast.send(ServiceEvent {
                        service,
                        payload: encode_status_event(mid, status),
                    });
                }
                Action::Inbox { service, unread } => {
                    let _ = self.app_broadcast.send(ServiceEvent {
                        service,
                        payload: encode_inbox_event(unread),
                    });
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
                let (actions, diags) = self.with_node(|node| node.handle(Event::AppSend(send)));
                report_diagnostics(diags);
                self.apply_actions(actions);
                let _ = respond.send(mid);
            }
            ApiCmd::Status { mid, respond } => {
                let value = self.with_node(|node| node.store_ref().status_get(&mid));
                let _ = respond.send(value);
            }
            ApiCmd::Fetch {
                service,
                max,
                respond,
            } => {
                let rows = self.with_node(|node| node.store_ref().inbox_fetch(&service, max));
                let _ = respond.send(rows);
            }
            ApiCmd::Ack {
                service,
                ids,
                respond,
            } => {
                let n = self.with_node(|node| node.store_mut().inbox_ack(&service, &ids));
                let _ = respond.send(n);
            }
            ApiCmd::Lookup { id, respond } => {
                let lookup = self.with_node(|node| {
                    let path = node.has_path(&id);
                    match node.lookup(&id) {
                        lattice_core::LookupResult::Absent => Lookup::Absent { path },
                        lattice_core::LookupResult::Present { mode } => {
                            Lookup::Present { mode, path }
                        }
                    }
                });
                let _ = respond.send(lookup);
            }
            ApiCmd::NodeInfo { respond } => {
                let info = self.with_node(|node| NodeInfo {
                    id: node.own_id,
                    mode: self.mode,
                    links: self.links.len(),
                    records: node.debug_record_count(),
                    custody_bytes: node.custody_bytes(),
                    draining: node.drain_state().is_draining(),
                });
                let _ = respond.send(info);
            }
            ApiCmd::Drain { request, respond } => {
                let status = self.with_node(|node| {
                    if let DrainRequest::Set(state) = request {
                        node.set_drain(state);
                        self.draining.store(state.is_draining(), Ordering::Relaxed);
                        if let Err(e) = node.store_mut().drain_set(state) {
                            eprintln!("lattice: failed to persist drain flag: {e}");
                        }
                    }
                    DrainStatus {
                        draining: node.drain_state().is_draining(),
                        custody_bytes: node.custody_bytes(),
                    }
                });
                let _ = respond.send(status);
            }
            ApiCmd::Link {
                addr,
                ik_key,
                path,
                peer_id,
                respond,
            } => {
                let parsed = addr.parse::<std::net::SocketAddr>();
                match parsed {
                    Ok(addr) if ik_key.is_some() || path.is_some() => {
                        let _ = self.cmd_tx.send(Cmd::Dial {
                            addr,
                            ik_key,
                            path,
                            peer_id,
                        });
                        let _ = respond.send(LinkOutcome::Queued);
                    }
                    _ => {
                        let _ = respond.send(LinkOutcome::Rejected);
                    }
                }
            }
            ApiCmd::Rotate {
                next_key,
                next_next_commitment,
                kind,
                respond,
            } => {
                let result = (|| {
                    let dir = self.identity_dir.clone();
                    let commitment =
                        next_next_commitment.map(lattice_types::Commitment::from_bytes);
                    let rotation =
                        crate::keys::rotate_signing_key(&dir, &next_key, commitment.as_ref(), kind)
                            .map_err(|e| e.to_string())?;
                    let now = now_secs();
                    self.with_node(|node| -> Result<(), String> {
                        node.reload_identity(rotation.identity, now, kind)
                            .map_err(|e| e.to_string())?;
                        if kind == RotationKind::Abandon {
                            node.set_drain(DrainState::Draining);
                            self.draining.store(true, Ordering::Relaxed);
                            if let Err(e) = node.store_mut().drain_set(DrainState::Draining) {
                                eprintln!("lattice: failed to persist drain flag: {e}");
                            }
                        }
                        Ok(())
                    })?;
                    Ok(if kind == RotationKind::Abandon {
                        "identity abandoned".to_string()
                    } else {
                        "rotated; the following key's commitment is stored in the identity directory"
                            .to_string()
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
                    self.with_node(|node| {
                        node.reload_identity(identity, now, RotationKind::Rotate)
                            .map_err(|e| e.to_string())
                    })?;
                    Ok("envelope key rotated; old key kept decrypt-only for 2 days".to_string())
                })();
                let _ = respond.send(result);
            }
            ApiCmd::UnlinkByPeer { peer, respond } => {
                let before = self.links.len();
                self.unlink(peer);
                let _ = respond.send(before - self.links.len());
            }
        }
    }

    /// Spawn the dial as a task; the outcome comes back through `dial_rx`.
    /// The event loop never awaits a dial, so an unreachable peer cannot
    /// stall frame processing, ticks or the local API.
    fn spawn_dial(
        &mut self,
        addr: std::net::SocketAddr,
        ik_key: Option<ChannelPublicKey>,
        path: Option<String>,
        peer_id: Option<Identifier>,
    ) {
        let pinned = pinned_peer(ik_key.as_ref(), peer_id);
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
            (None, None) => {
                self.clear_root_in_flight(addr);
                return;
            }
        };
        let seed = self.channel_seed.clone();
        let tx = self.dial_tx.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(DIAL_DEADLINE, lattice_net::connect(contact, &seed))
                .await
                .unwrap_or(Err(lattice_net::NetError::Timeout));
            let _ = tx.send(DialOutcome {
                addr,
                pinned,
                result,
            });
        });
    }

    fn clear_root_in_flight(&mut self, addr: std::net::SocketAddr) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.addr == addr) {
            root.in_flight = false;
        }
    }

    /// Apply the outcome of a spawned dial: attach the link on success,
    /// log on failure, and release the root's in-flight slot either way.
    fn handle_dial_outcome(&mut self, outcome: DialOutcome) {
        match outcome.result {
            Ok(io) => {
                let remote_ck = io.remote_static;
                self.attach_link(outcome.pinned, remote_ck, io, Some(outcome.addr));
                if let Some(root) = self.roots.iter_mut().find(|r| r.addr == outcome.addr) {
                    root.attempts = 0;
                    root.next_attempt = now_secs() + 60;
                }
            }
            Err(e) => {
                eprintln!("lattice: dial {} failed: {e}", outcome.addr);
            }
        }
        self.clear_root_in_flight(outcome.addr);
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
fn pinned_peer(
    ik_key: Option<&ChannelPublicKey>,
    peer_id: Option<Identifier>,
) -> Option<Identifier> {
    if ik_key.is_some() { peer_id } else { None }
}

#[cfg(test)]
mod tests {
    use super::pinned_peer;
    use lattice_types::{ChannelPublicKey, Identifier};

    #[test]
    fn ik_dial_pins_configured_id() {
        let id = Identifier::from_bytes([7u8; 32]);
        let ck = ChannelPublicKey::from_bytes([9u8; 32]);
        assert_eq!(pinned_peer(Some(&ck), Some(id)), Some(id));
        assert_eq!(pinned_peer(Some(&ck), None), None);
    }

    #[test]
    fn xx_dial_never_pins() {
        let id = Identifier::from_bytes([7u8; 32]);
        assert_eq!(pinned_peer(None, Some(id)), None);
        assert_eq!(pinned_peer(None, None), None);
    }
}
