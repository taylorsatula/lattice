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

use crate::cidr::Cidr;
use crate::config::Config;

/// Events coming up from links into the node.
pub enum LinkEvent {
    Frame {
        link: u64,
        frame: Frame,
        /// Bucket index of the wire frame, as reported by the transport.
        bucket: usize,
    },
    Down {
        link: u64,
    },
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
        service: String,
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

/// Cadence for deleting expired retired-envelope-key files. Matches the
/// core's data-sweep interval (`DATA_SWEEP_SECS` in lattice-core), which is
/// what drops the keys from memory; the files must not outlive the keys.
const RETIRED_KEY_SWEEP_SECS: u64 = 3600;

/// Per-link outbound queue capacity, in frames. Frames are at most 32 KiB,
/// so a full queue is at most ~2 MiB per link.
const OUTBOUND_CAPACITY: usize = 64;
/// Depth at which low-priority classes (snow, then gossip) are shed instead
/// of enqueued, and from which the over-mark timer runs.
const OUTBOUND_HIGH_WATER: usize = 48;
/// How long the outbound queue may stay at/over the high-water mark before
/// the link is closed. A peer that cannot drain its queue is worse than a
/// reconnect; TCP keepalive (~90s) is the backstop when no frames flow.
const OVER_MARK_SECS: u64 = 10;
/// Consecutive core wakes deferred because a dial was in flight before the
/// wake is forced through anyway.
const MAX_WAKE_DEFERRALS: u32 = 10;
/// Delay before re-checking after a deferred wake.
const WAKE_DEFER_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
/// Inbound (socket -> event loop) channel capacity, in frames. A peer that
/// floods past this is disconnected by `link_task` rather than buffered.
const INBOUND_CAPACITY: usize = 256;
/// Established-link caps. WAN links get the plan's hard cap (32); hive
/// links get the plan's 128. Per-prefix caps bound how many links one
/// /24 (or /48) may hold: 8 for WAN, and the hive cap for hive prefixes
/// (a hive behind one NAT shares a prefix; capping it lower would defeat
/// the hive cap). Links whose address is unknown are treated as WAN
/// (fail closed).
const MAX_WAN_LINKS: usize = 32;
const MAX_HIVE_LINKS: usize = 128;
const MAX_WAN_LINKS_PER_PREFIX: usize = 8;
const MAX_HIVE_LINKS_PER_PREFIX: usize = MAX_HIVE_LINKS;
/// How long a link may stay unbound (no record claim) before it is
/// dropped. Binding normally completes within a reconcile round (~1s);
/// 60s is generous headroom for a slow peer.
const UNBOUND_LINK_DEADLINE_SECS: u64 = 60;

/// Outbound/inbound frame classes for per-peer rate limiting and shedding.
/// Custody is message custody (offers and custody replies): shed last.
/// Gossip is record anti-entropy (reconcile/want/records/kels): shed second.
/// Snow is cover traffic: shed first. Control is ping (and the handshake
/// frames, which never reach the runtime): shed after gossip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FrameClass {
    Custody,
    Gossip,
    Snow,
    Control,
}

impl FrameClass {
    fn of(frame: &Frame) -> Self {
        match frame {
            Frame::Offer(_) | Frame::Custody(_) => Self::Custody,
            Frame::Reconcile(_) | Frame::Want(_) | Frame::Records(_) | Frame::Kels(_) => {
                Self::Gossip
            }
            Frame::Dummy(_) => Self::Snow,
            Frame::Ping(_) | Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => Self::Control,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Custody => 0,
            Self::Gossip => 1,
            Self::Snow => 2,
            Self::Control => 3,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Custody => "custody",
            Self::Gossip => "gossip",
            Self::Snow => "snow",
            Self::Control => "control",
        }
    }
}

/// Token bucket: `capacity` burst, `refill_per_sec` sustained.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: u64,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64, now: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_refill: now,
        }
    }

    fn allow(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed > 0 {
            self.tokens = (self.tokens + elapsed as f64 * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-link (capacity, refill/sec) for outbound classes. Custody is sized
/// for a relay pushing offers; gossip covers a reconcile round (~3 frames
/// per interval, plus KEL nudges during bootstrap, which can fire once per
/// second) with headroom — 1/sec starved bootstrap sync in the six-node
/// gate; snow caps even a misconfigured snow_per_min.
const OUT_CUSTODY: (f64, f64) = (64.0, 16.0);
const OUT_GOSSIP: (f64, f64) = (64.0, 8.0);
const OUT_SNOW: (f64, f64) = (4.0, 0.25);
const OUT_CONTROL: (f64, f64) = (16.0, 2.0);
/// Per-link (capacity, refill/sec) for inbound classes. Gossip inbound is a
/// touch more generous than outbound: a peer answering our wants may push a
/// burst of records.
const IN_CUSTODY: (f64, f64) = (64.0, 16.0);
const IN_GOSSIP: (f64, f64) = (64.0, 16.0);
const IN_SNOW: (f64, f64) = (4.0, 0.5);
const IN_CONTROL: (f64, f64) = (16.0, 2.0);

fn out_buckets(now: u64) -> [TokenBucket; 4] {
    [
        TokenBucket::new(OUT_CUSTODY.0, OUT_CUSTODY.1, now),
        TokenBucket::new(OUT_GOSSIP.0, OUT_GOSSIP.1, now),
        TokenBucket::new(OUT_SNOW.0, OUT_SNOW.1, now),
        TokenBucket::new(OUT_CONTROL.0, OUT_CONTROL.1, now),
    ]
}

fn in_buckets(now: u64) -> [TokenBucket; 4] {
    [
        TokenBucket::new(IN_CUSTODY.0, IN_CUSTODY.1, now),
        TokenBucket::new(IN_GOSSIP.0, IN_GOSSIP.1, now),
        TokenBucket::new(IN_SNOW.0, IN_SNOW.1, now),
        TokenBucket::new(IN_CONTROL.0, IN_CONTROL.1, now),
    ]
}

/// Per-link drop/shed counters, logged (throttled) as they happen and
/// summarized when the link closes.
#[derive(Default)]
struct LinkStats {
    shed_snow: u64,
    shed_gossip: u64,
    shed_control: u64,
    shed_custody: u64,
    rate_limited: u64,
    inbound_dropped: u64,
    high_water_hits: u64,
}

impl LinkStats {
    fn shed(&mut self, class: FrameClass) -> u64 {
        let n = match class {
            FrameClass::Snow => &mut self.shed_snow,
            FrameClass::Gossip => &mut self.shed_gossip,
            FrameClass::Control => &mut self.shed_control,
            FrameClass::Custody => &mut self.shed_custody,
        };
        *n += 1;
        *n
    }

    fn total_shed(&self) -> u64 {
        self.shed_snow + self.shed_gossip + self.shed_control + self.shed_custody
    }

    fn is_quiet(&self) -> bool {
        self.total_shed() == 0
            && self.rate_limited == 0
            && self.inbound_dropped == 0
            && self.high_water_hits == 0
    }

    fn summary(&self) -> String {
        format!(
            "shed(snow={} gossip={} control={} custody={}) rate_limited={} inbound_dropped={} high_water_hits={}",
            self.shed_snow,
            self.shed_gossip,
            self.shed_control,
            self.shed_custody,
            self.rate_limited,
            self.inbound_dropped,
            self.high_water_hits
        )
    }
}

/// Which cap pool a link draws from. Hive membership is decided by the
/// configured hive CIDRs (the only place scope is visible); everything
/// else is WAN.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkScope {
    Wan,
    Hive,
}

impl LinkScope {
    fn name(self) -> &'static str {
        match self {
            LinkScope::Wan => "wan",
            LinkScope::Hive => "hive",
        }
    }
}

/// Classify a link by its remote address. Unknown addresses are WAN: the
/// tighter cap is the safe default.
fn scope_of(addr: Option<&std::net::SocketAddr>, hive: &[Cidr]) -> LinkScope {
    match addr {
        Some(a) if hive.iter().any(|c| c.contains(a.ip())) => LinkScope::Hive,
        _ => LinkScope::Wan,
    }
}

/// Why a link was refused at admission.
enum LinkCap {
    /// The per-scope cap was reached.
    Scope(LinkScope, usize),
    /// The per-prefix cap was reached.
    Prefix(lattice_net::SourcePrefix, usize),
}

struct LinkHandle {
    peer: Option<Identifier>,
    addr: Option<std::net::SocketAddr>,
    tx: mpsc::Sender<OutFrame>,
    task: tokio::task::AbortHandle,
    buckets: [TokenBucket; 4],
    in_buckets: [TokenBucket; 4],
    stats: LinkStats,
    /// When the outbound queue first reached the high-water mark and has
    /// not drained below it since. `None` while under the mark.
    over_mark_since: Option<u64>,
    /// When the link became unbound (no record claim), if it currently is.
    /// Set at attach time and whenever a binding is cleared; cleared when a
    /// binding is established. Drives the unbound-link deadline.
    unbound_since: Option<u64>,
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
    /// Dials currently in flight. Ticks are deferred while any dial is
    /// outstanding: a tick dispatches queued messages, and dispatching
    /// before the link exists parks the message behind a NoRoute backoff.
    dials_in_flight: u32,
    link_rx: Option<mpsc::Receiver<LinkEvent>>,
    link_tx: mpsc::Sender<LinkEvent>,
    cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    roots: Vec<RootDial>,
    api_rx: Option<mpsc::UnboundedReceiver<ApiCmd>>,
    api_tx: mpsc::UnboundedSender<ApiCmd>,
    pub app_broadcast: broadcast::Sender<ServiceEvent>,
    /// Hive ranges from the config; links whose address falls in one are
    /// hive-scope for the established-link caps. Empty means every link is
    /// WAN-scope.
    hive_cidrs: Vec<Cidr>,
    /// Next time the retired-envelope-key file sweep runs. Mirrors the
    /// core's data-sweep cadence (`DATA_SWEEP_SECS` in lattice-core); the
    /// core drops expired keys from memory, this deletes the files.
    next_retired_key_sweep: u64,
}

/// Milliseconds since the Unix epoch — the core's time base.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Whole seconds since the Unix epoch, for the daemon's own second-granularity
/// timers (dial backoff, token buckets, the retired-key sweep).
fn now_secs() -> u64 {
    now_ms() / 1000
}

/// Convert a Unix-millisecond deadline to a tokio instant.
fn instant_from_unix_ms(ms: u64) -> tokio::time::Instant {
    let now = now_ms();
    tokio::time::Instant::now() + std::time::Duration::from_millis(ms.saturating_sub(now))
}

/// Surface non-fatal internal failures reported by the sans-IO core.
/// `eprintln!` is the daemon's diagnostic channel (see `main.rs`).
fn report_diagnostics(diags: Vec<lattice_core::Diagnostic>) {
    for d in diags {
        eprintln!("lattice: node diagnostic: {}: {}", d.op, d.detail);
    }
}

/// Outbound frame writer for one link.
///
/// The inbound channel is bounded: when it is full the peer is flooding
/// faster than the event loop drains, so the link is torn down instead of
/// buffering without bound. The final `Down` is awaited so the runtime
/// always learns the link died; it completes once the loop drains one slot.
async fn link_task(
    id: u64,
    mut io: lattice_net::PeerIo,
    inbound: mpsc::Sender<LinkEvent>,
    mut outbound: mpsc::Receiver<OutFrame>,
) {
    loop {
        tokio::select! {
            f = outbound.recv() => {
                match f {
                    Some(out) => {
                        match io.send_frame(&out.frame, out.pad_to).await {
                            Ok(()) => {}
                            // An unencodable frame is a local bug, not a link
                            // failure: the core drops oversize frames before
                            // they get here, so this is a backstop. Log and
                            // keep the link up.
                            Err(lattice_net::NetError::FrameTooLarge) => {
                                eprintln!(
                                    "lattice: link {id}: dropping unencodable frame (local bug)"
                                );
                            }
                            Err(_) => break,
                        }
                    }
                    None => break,
                }
            }
            res = io.recv_frame() => {
                match res {
                    Ok(Some((frame, bucket))) => {
                        match inbound.try_send(LinkEvent::Frame { link: id, frame, bucket }) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                eprintln!(
                                    "lattice: link {id}: inbound queue full ({INBOUND_CAPACITY} frames); disconnecting flooding peer"
                                );
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        }
    }
    let _ = inbound.send(LinkEvent::Down { link: id }).await;
}

impl Runtime {
    /// `now` is milliseconds since the Unix epoch (the core's time base).
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
            republish_min_interval_secs: cfg.limits.republish_min_interval_secs,
            custody_allowance: cfg.limits.custody_allowance,
            transit_cap: cfg.limits.transit_cap,
            inbox_max_deliveries: cfg.limits.inbox_max,
            inbox_max_total: cfg.limits.inbox_max_total,
            rng_seed: u64::from_le_bytes(os_bytes::<8>()),
            advertise: cfg.advertise.clone(),
            advertise_ips: cfg
                .ips
                .iter()
                .map(|s| {
                    s.parse::<std::net::IpAddr>().map_err(|e| {
                        lattice_core::NodeError::Config(format!("ips entry {s:?}: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
            gateways,
            mode,
            ..lattice_core::Config::default()
        };
        // The config validator already rejected malformed CIDRs; a parse
        // failure here means the config was built by hand (tests), so skip
        // the entry and treat those links as WAN (the tighter cap).
        let hive_cidrs: Vec<Cidr> = cfg
            .hive
            .iter()
            .filter_map(|s| match Cidr::parse(s) {
                Ok(c) => Some(c),
                Err(e) => {
                    eprintln!("lattice: ignoring hive CIDR {s:?}: {e}");
                    None
                }
            })
            .collect();
        let mut node = Node::new(core_cfg, identity, store, now)?;
        if draining.load(Ordering::Relaxed) {
            node.set_drain(DrainState::Draining);
        }
        let (link_tx, link_rx) = mpsc::channel(INBOUND_CAPACITY);
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
            dials_in_flight: 0,
            cmd_rx,
            cmd_tx,
            roots: Vec::new(),
            api_rx: Some(api_rx),
            api_tx,
            app_broadcast,
            hive_cidrs,
            // The startup load already deleted expired files; first sweep an
            // hour from now. (`now` is milliseconds; the sweep is tracked
            // in seconds.)
            next_retired_key_sweep: now / 1000 + RETIRED_KEY_SWEEP_SECS,
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

    /// Count established links in `scope` and in `prefix` (when known).
    fn count_links(
        &self,
        scope: LinkScope,
        prefix: Option<lattice_net::SourcePrefix>,
    ) -> (usize, usize) {
        let mut scope_n = 0;
        let mut prefix_n = 0;
        for l in self.links.values() {
            if scope_of(l.addr.as_ref(), &self.hive_cidrs) == scope {
                scope_n += 1;
            }
            if let (Some(p), Some(a)) = (prefix, l.addr.as_ref()) {
                if lattice_net::prefix_of(a) == p {
                    prefix_n += 1;
                }
            }
        }
        (scope_n, prefix_n)
    }

    /// Check the established-link caps for a prospective link. The cap is
    /// enforced here, at admission, because only the runtime can see both
    /// the link's scope (via the configured hive CIDRs) and the current
    /// link table; the listener cannot.
    fn check_link_admission(&self, addr: Option<&std::net::SocketAddr>) -> Result<(), LinkCap> {
        let scope = scope_of(addr, &self.hive_cidrs);
        let (scope_cap, prefix_cap) = match scope {
            LinkScope::Wan => (MAX_WAN_LINKS, MAX_WAN_LINKS_PER_PREFIX),
            LinkScope::Hive => (MAX_HIVE_LINKS, MAX_HIVE_LINKS_PER_PREFIX),
        };
        let prefix = addr.map(lattice_net::prefix_of);
        let (scope_n, prefix_n) = self.count_links(scope, prefix);
        if scope_n >= scope_cap {
            return Err(LinkCap::Scope(scope, scope_cap));
        }
        if let Some(p) = prefix {
            if prefix_n >= prefix_cap {
                return Err(LinkCap::Prefix(p, prefix_cap));
            }
        }
        Ok(())
    }

    /// Register an established peer connection. Returns the link id, or
    /// `None` when the link was refused by the established-link caps (the
    /// connection is dropped without a response).
    pub async fn attach_link(
        &mut self,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
        io: lattice_net::PeerIo,
    ) -> Option<u64> {
        let addr = Some(io.remote_addr);
        if let Err(cap) = self.check_link_admission(addr.as_ref()) {
            match cap {
                LinkCap::Scope(scope, cap) => eprintln!(
                    "lattice: refusing link from {}: {scope_name} link cap reached ({cap})",
                    addr.map(|a| a.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    scope_name = scope.name(),
                ),
                LinkCap::Prefix(prefix, cap) => eprintln!(
                    "lattice: refusing link from {}: per-prefix cap reached ({cap} per {prefix})",
                    addr.map(|a| a.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                ),
            }
            // `io` is dropped here: the connection is closed without a
            // response, consistent with the listener's other refusals.
            return None;
        }
        // Link ids come from a persisted counter so a custody entry's
        // `upstream` never aliases an unrelated peer after a restart.
        let id = match self.with_node(|n| n.store_mut().alloc_link_id()) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("lattice: refusing link: could not allocate a link id: {e}");
                return None;
            }
        };
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let inbound = self.link_tx.clone();
        let task = tokio::spawn(link_task(id, io, inbound, outbound_rx));
        let now = now_secs();
        self.links.insert(
            id,
            LinkHandle {
                peer,
                addr,
                tx: outbound_tx,
                task: task.abort_handle(),
                buckets: out_buckets(now),
                in_buckets: in_buckets(now),
                stats: LinkStats::default(),
                over_mark_since: None,
                unbound_since: peer.is_none().then_some(now),
            },
        );
        // The link is registered, so the actions returned by LinkUp can be
        // routed to it.
        self.apply(Event::LinkUp {
            at: now_ms(),
            link: id,
            peer,
            remote_ck,
        })
        .await;
        Some(id)
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
        // The core reports the next instant it wants to be woken
        // (`Node::next_deadline`); the daemon arms a timer for exactly that
        // instant — there is no periodic tick. The wake also covers the
        // daemon's own deadlines (root redials, the retired-key sweep).
        // `None` means nothing is pending: sleep until the next event.
        let mut wake_at = self.next_wake_instant();
        // Consecutive wakes deferred because a dial was in flight. Bounded
        // so a lost dial outcome (e.g. a panicked dial task) cannot stall
        // the loop forever.
        let mut tick_deferrals = 0u32;
        tokio::pin!(shutdown);
        loop {
            let wake = async {
                match wake_at {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    self.begin_drain();
                    return;
                }
                Some(peer) = peer_rx.recv() => {
                    let ck = peer.remote_static;
                    self.attach_link(None, ck, peer).await;
                }
                Some(outcome) = dial_rx.recv() => self.handle_dial_outcome(outcome).await,
                Some(api) = api_rx.recv() => self.handle_api(api).await,
                Some(cmd) = self.cmd_rx.recv() => match cmd {
                    Cmd::Dial { addr, ik_key, path, peer_id } => self.spawn_dial(addr, ik_key, path, peer_id),
                },
                Some(ev) = link_rx.recv() => match ev {
                    LinkEvent::Frame { link, frame, bucket } => {
                        let now = now_ms();
                        // Per-link inbound rate limit, applied at the core
                        // boundary. Frames from a link we already tore down
                        // are dropped: the core has been told LinkDown.
                        let admitted = match self.links.get_mut(&link) {
                            Some(h) => {
                                let class = FrameClass::of(&frame);
                                if h.in_buckets[class.index()].allow(now / 1000) {
                                    Some(h.peer)
                                } else {
                                    h.stats.inbound_dropped += 1;
                                    let n = h.stats.inbound_dropped;
                                    if n == 1 || n % 64 == 0 {
                                        eprintln!(
                                            "lattice: link {link}: dropping inbound {} frame (rate limited; {n} total)",
                                            class.name()
                                        );
                                    }
                                    None
                                }
                            }
                            None => None,
                        };
                        if admitted.is_some() {
                            self.apply(Event::Frame { at: now, link, frame, bucket: Some(bucket) }).await;
                        }
                    }
                    LinkEvent::Down { link } => {
                        if self.remove_link(link) {
                            self.apply(Event::LinkDown { at: now_ms(), link }).await;
                        }
                    }
                },
                _ = wake => {
                    // Drop links that have been unbound longer than the
                    // deadline; the core is told via LinkDown below.
                    for link in self.sweep_unbound_links() {
                        self.apply(Event::LinkDown {
                            at: now_ms(),
                            link,
                        })
                        .await;
                    }
                    // Attach any dials that completed since the last arm ran,
                    // then defer the core wake while a dial is still in
                    // flight: dispatching now would find no link and park
                    // the message behind a NoRoute backoff.
                    while let Ok(outcome) = dial_rx.try_recv() {
                        self.handle_dial_outcome(outcome).await;
                    }
                    if self.dials_in_flight > 0 && tick_deferrals < MAX_WAKE_DEFERRALS {
                        tick_deferrals += 1;
                        wake_at = Some(tokio::time::Instant::now() + WAKE_DEFER_DELAY);
                        continue;
                    }
                    tick_deferrals = 0;
                    self.redial_roots();
                    let now = now_ms();
                    // Fire the core only if its deadline is actually due;
                    // the wake may have been armed for a root dial or the
                    // retired-key sweep instead.
                    let core_due = self
                        .with_node(|n| n.next_deadline())
                        .is_some_and(|d| now >= d);
                    if core_due {
                        self.apply(Event::Tick { at: now }).await;
                    }
                    let now_s = now_secs();
                    if now_s >= self.next_retired_key_sweep {
                        crate::keys::sweep_expired_retired_envelope_keys(
                            &self.identity_dir,
                            now_s,
                        );
                        self.next_retired_key_sweep = now_s + RETIRED_KEY_SWEEP_SECS;
                    }
                }
            }
            // Re-arm after every iteration: any event may have moved the
            // core's deadline (earlier or later), and the daemon's own
            // deadlines (root redials, the retired-key sweep) may have
            // changed too. A wake that fires late is not replayed: the
            // core recomputes its deadline from current state, so a stall
            // costs one catch-up wake, never a burst of them. (The defer
            // path above `continue`s and keeps its own short re-arm.)
            wake_at = self.next_wake_instant();
        }
    }

    /// The next instant the daemon must wake for: the core's reported
    /// deadline, the next root redial, or the retired-key sweep —
    /// whichever is earliest. `None` when nothing is pending.
    fn next_wake_instant(&self) -> Option<tokio::time::Instant> {
        let mut best: Option<u64> = self.with_node(|n| n.next_deadline());
        if let Some(r) = self
            .roots
            .iter()
            .filter(|r| !r.in_flight)
            .map(|r| r.next_attempt)
            .min()
        {
            let ms = r.saturating_mul(1000);
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
        let rk = self.next_retired_key_sweep.saturating_mul(1000);
        best = Some(best.map_or(rk, |b| b.min(rk)));
        // Unbound links have a hard deadline; arm the wake for the earliest.
        if let Some(t) = self.links.values().filter_map(|l| l.unbound_since).min() {
            let ms = t
                .saturating_add(UNBOUND_LINK_DEADLINE_SECS)
                .saturating_mul(1000);
            best = Some(best.map_or(ms, |b| b.min(ms)));
        }
        best.map(instant_from_unix_ms)
    }

    /// Drop links that have been unbound (no record claim) for longer than
    /// [`UNBOUND_LINK_DEADLINE_SECS`]. Returns the dropped link ids; the
    /// caller feeds `LinkDown` for each back into the core.
    fn sweep_unbound_links(&mut self) -> Vec<u64> {
        let now = now_secs();
        let expired: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| {
                l.unbound_since
                    .is_some_and(|t| now.saturating_sub(t) >= UNBOUND_LINK_DEADLINE_SECS)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            if let Some(l) = self.links.get(id) {
                let secs = l.unbound_since.map(|t| now.saturating_sub(t)).unwrap_or(0);
                eprintln!("lattice: link {id} dropped: unbound (no record claim) for {secs}s");
            }
            self.remove_link(*id);
        }
        expired
    }

    /// Run one event through the core and apply the resulting actions.
    /// The core performs synchronous store I/O (redb commits with fsync),
    /// so `handle` runs on the blocking thread pool and the async loop
    /// only awaits the outcome; the worker is never blocked on a commit.
    /// Events are still processed strictly in order: each event's actions
    /// are applied before the next event is dispatched. A link dropped or
    /// force-closed while applying actions is fed back through the same
    /// queue as a LinkDown, so the core observes it after the binding
    /// change that caused it.
    async fn apply(&mut self, event: Event) {
        let mut queue = std::collections::VecDeque::from([event]);
        while let Some(event) = queue.pop_front() {
            let node = Arc::clone(&self.node);
            let result = tokio::task::spawn_blocking(move || {
                let mut node = node
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                node.handle(event)
            })
            .await;
            let (actions, diags) = match result {
                Ok(out) => out,
                Err(e) => {
                    // The core panicked. The mutex is poisoned but
                    // recoverable (with_node takes the inner value), so
                    // keep the daemon alive and say so.
                    eprintln!("lattice: node task failed: {e}");
                    continue;
                }
            };
            report_diagnostics(diags);
            for link in self.apply_actions(actions) {
                queue.push_back(Event::LinkDown { at: now_ms(), link });
            }
        }
    }

    /// Apply the actions returned by the core. Returns the ids of links
    /// dropped as duplicates (a newer link to the same peer exists) or
    /// force-closed because the peer cannot keep up; the caller feeds
    /// `Event::LinkDown` for each back into the core.
    fn apply_actions(&mut self, actions: Vec<Action>) -> Vec<u64> {
        let mut dropped = Vec::new();
        for action in actions {
            match action {
                Action::SendFrame {
                    link,
                    frame,
                    pad_to,
                } => {
                    if let Some(closed) = self.enqueue_outbound(link, frame, pad_to) {
                        dropped.push(closed);
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
                Action::LinkBound { link, peer } => {
                    if let Some(h) = self.links.get_mut(&link) {
                        h.peer = peer;
                        h.unbound_since = if peer.is_some() {
                            None
                        } else {
                            Some(now_secs())
                        };
                    }
                    if let Some(p) = peer {
                        // One connection per peer: keep the newest link
                        // bound to this peer, drop the rest.
                        let mut bound: Vec<u64> = self
                            .links
                            .iter()
                            .filter(|(_, l)| l.peer == Some(p))
                            .map(|(id, _)| *id)
                            .collect();
                        if bound.len() > 1 {
                            bound.sort_unstable();
                            let keep = bound.pop().expect("len > 1");
                            for dup in bound {
                                if self.remove_link(dup) {
                                    eprintln!(
                                        "lattice: dropping duplicate link {dup} to peer {} (keeping link {keep})",
                                        lattice_proto::text::encode_id(&p)
                                    );
                                    dropped.push(dup);
                                }
                            }
                        }
                    }
                }
            }
        }
        dropped
    }

    /// Remove a link from the table and abort its writer task. Returns
    /// true if the link was present.
    fn remove_link(&mut self, id: u64) -> bool {
        match self.links.remove(&id) {
            Some(h) => {
                h.task.abort();
                if !h.stats.is_quiet() {
                    eprintln!("lattice: link {id} closed: {}", h.stats.summary());
                }
                true
            }
            None => false,
        }
    }

    /// Admit a frame to a link's outbound queue, applying the per-class
    /// token bucket, the high-water mark and the hard cap. Returns the
    /// link id if the link was closed because the peer cannot keep up;
    /// the caller feeds `LinkDown` back to the core.
    ///
    /// Order of checks:
    /// 1. Token bucket for the frame's class; an empty bucket drops the
    ///    frame (counted) regardless of queue depth.
    /// 2. At/over the high-water mark, snow and gossip are shed (counted);
    ///    custody and control fall through to the hard cap.
    /// 3. A queue that stays at/over the mark for `OVER_MARK_SECS` closes
    ///    the link; a custody frame that cannot be enqueued at the hard
    ///    cap closes it immediately.
    fn enqueue_outbound(&mut self, link: u64, frame: Frame, pad_to: Option<usize>) -> Option<u64> {
        let now = now_secs();
        let class = FrameClass::of(&frame);
        let mut force_close = false;
        if let Some(h) = self.links.get_mut(&link) {
            // 1. Per-class token bucket.
            if !h.buckets[class.index()].allow(now) {
                h.stats.rate_limited += 1;
                let n = h.stats.rate_limited;
                if n == 1 || n % 64 == 0 {
                    eprintln!(
                        "lattice: link {link}: outbound {} frame dropped (rate limited; {n} total)",
                        class.name()
                    );
                }
                return None;
            }
            let depth = h.tx.max_capacity() - h.tx.capacity();
            // 2. High-water bookkeeping.
            if depth >= OUTBOUND_HIGH_WATER {
                if h.over_mark_since.is_none() {
                    h.over_mark_since = Some(now);
                    eprintln!(
                        "lattice: link {link}: outbound queue at high-water mark ({depth}/{OUTBOUND_CAPACITY})"
                    );
                }
                h.stats.high_water_hits += 1;
            } else {
                h.over_mark_since = None;
            }
            // 3. Queue stuck over the mark: the peer is not draining.
            if let Some(since) = h.over_mark_since {
                if now.saturating_sub(since) >= OVER_MARK_SECS {
                    eprintln!(
                        "lattice: link {link}: outbound queue over high-water for {}s; closing link",
                        now.saturating_sub(since)
                    );
                    force_close = true;
                }
            }
            // 4. Shed low-priority classes at/over the mark.
            let shed_low = !force_close
                && depth >= OUTBOUND_HIGH_WATER
                && matches!(class, FrameClass::Snow | FrameClass::Gossip);
            if shed_low {
                let n = h.stats.shed(class);
                if n == 1 || n % 64 == 0 {
                    eprintln!(
                        "lattice: link {link}: shedding {class_name} frame at high-water ({n} total)",
                        class_name = class.name()
                    );
                }
            } else if force_close {
                h.stats.shed(class);
            } else {
                // 5. Enqueue; the hard cap applies to every class.
                match h.tx.try_send(OutFrame { frame, pad_to }) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        let n = h.stats.shed(class);
                        eprintln!(
                            "lattice: link {link}: outbound queue full; shedding {} frame ({n} total)",
                            class.name()
                        );
                        if class == FrameClass::Custody {
                            // A custody frame had to be dropped: the peer is
                            // not draining. A reconnect beats a wedged link.
                            force_close = true;
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {}
                }
            }
        }
        if force_close && self.remove_link(link) {
            eprintln!("lattice: link {link} closed: peer cannot keep up with outbound traffic");
            return Some(link);
        }
        None
    }

    async fn handle_api(&mut self, api: ApiCmd) {
        match api {
            ApiCmd::AppSend { send, respond } => {
                let mid = send
                    .mid_hint
                    .unwrap_or_else(|| MessageId::from_bytes(lattice_crypto::os_bytes::<16>()));
                let send = lattice_core::AppSend {
                    mid_hint: Some(mid),
                    ..send
                };
                self.apply(Event::AppSend(send)).await;
                let _ = respond.send(mid);
            }
            ApiCmd::Status {
                mid,
                service,
                respond,
            } => {
                // Scope to the calling service, like Fetch/Ack: a status is
                // only visible to the service that sent the message. The
                // outbound record carries the sender's service; without it
                // the status cannot be attributed, so fail closed.
                let value = self.with_node(|node| match node.store_ref().outbound_get(&mid) {
                    Ok(Some(msg)) if msg.envelope.fsvc == service => {
                        node.store_ref().status_get(&mid)
                    }
                    Ok(Some(_)) | Ok(None) => Ok(None),
                    Err(e) => Err(e),
                });
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
                    let now = now_ms();
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
                    let now = now_ms();
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
                self.unlink(peer).await;
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
        let target = lattice_net::DialTarget::plain(addr);
        let contact = match (ik_key, path) {
            (Some(ck), _) => lattice_net::PeerContact::Ik {
                target,
                channel_key: ck,
            },
            (None, Some(p)) => lattice_net::PeerContact::Xx { target, path: p },
            (None, None) => {
                self.clear_root_in_flight(addr);
                return;
            }
        };
        let seed = self.channel_seed.clone();
        let tx = self.dial_tx.clone();
        self.dials_in_flight += 1;
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
    async fn handle_dial_outcome(&mut self, outcome: DialOutcome) {
        self.dials_in_flight = self.dials_in_flight.saturating_sub(1);
        match outcome.result {
            Ok(io) => {
                let remote_ck = io.remote_static;
                // A link refused by the admission caps does not count as a
                // successful dial: keep the root's backoff so we do not
                // hammer the cap every 60s.
                if self
                    .attach_link(outcome.pinned, remote_ck, io)
                    .await
                    .is_some()
                {
                    if let Some(root) = self.roots.iter_mut().find(|r| r.addr == outcome.addr) {
                        root.attempts = 0;
                        root.next_attempt = now_secs() + 60;
                    }
                }
            }
            Err(e) => {
                eprintln!("lattice: dial {} failed: {e}", outcome.addr);
            }
        }
        self.clear_root_in_flight(outcome.addr);
    }

    async fn unlink(&mut self, peer: Identifier) {
        let dead: Vec<u64> = self
            .links
            .iter()
            .filter(|(_, l)| l.peer == Some(peer))
            .map(|(id, _)| *id)
            .collect();
        for id in dead {
            if self.remove_link(id) {
                self.apply(Event::LinkDown {
                    at: now_ms(),
                    link: id,
                })
                .await;
            }
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
    use super::*;
    use lattice_proto::frames::{
        CustodyFrame, DummyFrame, Frame, OfferFrame, PingFrame, ReconcileFrame,
    };
    use lattice_types::{ChannelPublicKey, Identifier};

    fn test_runtime(dir: &std::path::Path) -> Runtime {
        std::fs::create_dir_all(dir).unwrap();
        crate::keys::init_identity(dir, None).unwrap();
        let identity = crate::keys::load_identity(dir).unwrap();
        let store = lattice_store::RedbStore::open(dir.join("node.redb")).unwrap();
        let cfg = crate::config::Config {
            identity_dir: dir.to_path_buf(),
            mode: "public".to_string(),
            listen: vec![],
            hive: vec![],
            roots: vec![],
            services: std::collections::HashMap::new(),
            status: false,
            app_socket: dir.join("app.sock"),
            admin_socket: dir.join("admin.sock"),
            advertise: vec![],
            ips: vec![],
            gateways: vec![],
            limits: crate::config::Limits::default(),
        };
        let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let draining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        Runtime::new(&cfg, identity, store, 1_000, peer_rx, draining).unwrap()
    }

    fn attach_test_link(rt: &mut Runtime, link: u64) {
        attach_test_link_full(rt, link, None, None);
    }

    fn attach_test_link_full(
        rt: &mut Runtime,
        link: u64,
        addr: Option<std::net::SocketAddr>,
        unbound_since: Option<u64>,
    ) {
        let (tx, _rx) = mpsc::channel(OUTBOUND_CAPACITY);
        // Keep the receiver alive by leaking it into the test's runtime; the
        // queue depth is what the test manipulates.
        std::mem::forget(_rx);
        let task = tokio::spawn(async {}).abort_handle();
        let now = now_secs();
        rt.links.insert(
            link,
            LinkHandle {
                peer: None,
                addr,
                tx,
                task,
                buckets: out_buckets(now),
                in_buckets: in_buckets(now),
                stats: LinkStats::default(),
                over_mark_since: None,
                unbound_since,
            },
        );
    }

    fn custody_frame() -> Frame {
        Frame::Offer(OfferFrame {
            message: vec![7u8; 32],
        })
    }

    fn snow_frame() -> Frame {
        Frame::Dummy(DummyFrame { echo: false })
    }

    fn gossip_frame() -> Frame {
        Frame::Reconcile(ReconcileFrame { ranges: vec![] })
    }

    #[tokio::test]
    async fn high_water_sheds_snow_and_gossip_but_not_custody() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-shed-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        attach_test_link(&mut rt, 1);
        // Fill to the high-water mark with custody frames.
        for _ in 0..OUTBOUND_HIGH_WATER {
            assert_eq!(rt.enqueue_outbound(1, custody_frame(), None), None);
        }
        // Snow and gossip are shed at the mark; custody still gets through.
        assert_eq!(rt.enqueue_outbound(1, snow_frame(), None), None);
        assert_eq!(rt.enqueue_outbound(1, gossip_frame(), None), None);
        let h = rt.links.get(&1).unwrap();
        assert_eq!(h.stats.shed_snow, 1);
        assert_eq!(h.stats.shed_gossip, 1);
        assert_eq!(h.tx.max_capacity() - h.tx.capacity(), OUTBOUND_HIGH_WATER);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn custody_frame_at_hard_cap_closes_the_link() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-cap-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        attach_test_link(&mut rt, 1);
        for _ in 0..OUTBOUND_CAPACITY {
            assert_eq!(rt.enqueue_outbound(1, custody_frame(), None), None);
        }
        // Refill the custody bucket so the bucket is not what stops us.
        rt.links.get_mut(&1).unwrap().buckets[FrameClass::Custody.index()].tokens = 10.0;
        // One more custody frame cannot be enqueued: the link is closed.
        assert_eq!(rt.enqueue_outbound(1, custody_frame(), None), Some(1));
        assert!(!rt.links.contains_key(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn token_bucket_rate_limits_outbound() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-rate-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        attach_test_link(&mut rt, 1);
        // Snow bucket holds 4; the 5th snow frame is rate limited.
        for _ in 0..4 {
            assert_eq!(rt.enqueue_outbound(1, snow_frame(), None), None);
        }
        assert_eq!(rt.enqueue_outbound(1, snow_frame(), None), None);
        let h = rt.links.get(&1).unwrap();
        assert_eq!(h.stats.rate_limited, 1);
        assert_eq!(h.tx.max_capacity() - h.tx.capacity(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn over_mark_timeout_closes_the_link() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-overmark-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        attach_test_link(&mut rt, 1);
        for _ in 0..OUTBOUND_HIGH_WATER {
            assert_eq!(rt.enqueue_outbound(1, custody_frame(), None), None);
        }
        // Simulate the queue having been stuck over the mark for long enough.
        let past = now_secs().saturating_sub(OVER_MARK_SECS + 1);
        rt.links.get_mut(&1).unwrap().over_mark_since = Some(past);
        // Any further frame (even gossip, which would otherwise be shed)
        // closes the link.
        assert_eq!(rt.enqueue_outbound(1, gossip_frame(), None), Some(1));
        assert!(!rt.links.contains_key(&1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frame_class_assignment() {
        assert_eq!(
            FrameClass::of(&Frame::Offer(OfferFrame { message: vec![] })),
            FrameClass::Custody
        );
        assert_eq!(
            FrameClass::of(&Frame::Custody(CustodyFrame {
                leg: lattice_types::LegId::from_bytes([0u8; 16]),
                result: 0,
                retry_after: None,
            })),
            FrameClass::Custody
        );
        assert_eq!(
            FrameClass::of(&Frame::Reconcile(ReconcileFrame { ranges: vec![] })),
            FrameClass::Gossip
        );
        assert_eq!(
            FrameClass::of(&Frame::Dummy(DummyFrame { echo: false })),
            FrameClass::Snow
        );
        assert_eq!(
            FrameClass::of(&Frame::Ping(PingFrame { nonce: 1 })),
            FrameClass::Control
        );
    }

    #[test]
    fn token_bucket_bursts_then_throttles() {
        let mut b = TokenBucket::new(2.0, 1.0, 1000);
        assert!(b.allow(1000));
        assert!(b.allow(1000));
        assert!(!b.allow(1000));
        // One second later one token has refilled.
        assert!(b.allow(1001));
        assert!(!b.allow(1001));
        // Tokens accumulate up to capacity, not beyond.
        assert!(b.allow(1010));
        assert!(b.allow(1010));
        assert!(!b.allow(1010));
    }

    #[test]
    fn token_bucket_refill_is_capped_by_capacity() {
        let mut b = TokenBucket::new(1.0, 10.0, 0);
        // Long idle: refill must not exceed capacity.
        assert!(b.allow(1000));
        assert!(!b.allow(1000));
    }

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

    fn wan_addr(last: u8) -> std::net::SocketAddr {
        format!("203.0.113.{last}:4000").parse().unwrap()
    }

    fn hive_addr(last: u8) -> std::net::SocketAddr {
        format!("10.1.2.{last}:4000").parse().unwrap()
    }

    fn test_runtime_with_hive(dir: &std::path::Path) -> Runtime {
        std::fs::create_dir_all(dir).unwrap();
        crate::keys::init_identity(dir, None).unwrap();
        let identity = crate::keys::load_identity(dir).unwrap();
        let store = lattice_store::RedbStore::open(dir.join("node.redb")).unwrap();
        let cfg = crate::config::Config {
            identity_dir: dir.to_path_buf(),
            mode: "public".to_string(),
            listen: vec![],
            hive: vec!["10.0.0.0/8".to_string()],
            roots: vec![],
            services: std::collections::HashMap::new(),
            status: false,
            app_socket: dir.join("app.sock"),
            admin_socket: dir.join("admin.sock"),
            advertise: vec![],
            ips: vec![],
            gateways: vec![],
            limits: crate::config::Limits::default(),
        };
        let (_peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let draining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        Runtime::new(&cfg, identity, store, 1_000, peer_rx, draining).unwrap()
    }

    #[test]
    fn scope_classification_uses_hive_cidrs() {
        let hive = vec![Cidr::parse("10.0.0.0/8").unwrap()];
        assert_eq!(scope_of(Some(&hive_addr(7)), &hive), LinkScope::Hive);
        assert_eq!(scope_of(Some(&wan_addr(7)), &hive), LinkScope::Wan);
        // Unknown address fails closed to WAN.
        assert_eq!(scope_of(None, &hive), LinkScope::Wan);
        // No hive CIDRs configured: everything is WAN.
        assert_eq!(scope_of(Some(&hive_addr(7)), &[]), LinkScope::Wan);
    }

    #[tokio::test]
    async fn wan_scope_cap_refuses_links_beyond_32() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-wan-cap-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        // 32 WAN links, each from its own /24 so the per-prefix cap
        // (8) does not bind first.
        for i in 0..MAX_WAN_LINKS {
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, i as u8, 1)),
                4000,
            );
            attach_test_link_full(&mut rt, i as u64 + 1, Some(addr), None);
        }
        let extra: std::net::SocketAddr = "203.0.250.1:4000".parse().unwrap();
        assert!(matches!(
            rt.check_link_admission(Some(&extra)),
            Err(LinkCap::Scope(LinkScope::Wan, MAX_WAN_LINKS))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn per_prefix_cap_refuses_ninth_link_from_same_prefix() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-prefix-cap-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        for i in 0..MAX_WAN_LINKS_PER_PREFIX {
            attach_test_link_full(&mut rt, i as u64 + 1, Some(wan_addr(i as u8 + 1)), None);
        }
        // The 9th link from the same /24 is refused.
        let addr = wan_addr(200);
        assert!(matches!(
            rt.check_link_admission(Some(&addr)),
            Err(LinkCap::Prefix(_, MAX_WAN_LINKS_PER_PREFIX))
        ));
        // A different /24 is admitted.
        let other: std::net::SocketAddr = "198.51.100.7:4000".parse().unwrap();
        assert!(rt.check_link_admission(Some(&other)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn hive_links_use_hive_cap() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-hive-cap-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime_with_hive(&dir);
        // 32 hive links from one /16: fine (hive per-prefix cap is the
        // hive cap, not the WAN 8).
        for i in 0..40u8 {
            attach_test_link_full(&mut rt, i as u64 + 1, Some(hive_addr(i)), None);
        }
        let addr = hive_addr(200);
        assert!(rt.check_link_admission(Some(&addr)).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wan_scope_cap_counts_only_wan_links() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-scope-cap-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime_with_hive(&dir);
        // Fill the WAN scope to its cap with distinct prefixes.
        for i in 0..MAX_WAN_LINKS {
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    198,
                    (i % 250) as u8 + 1,
                    (i / 250) as u8,
                    1,
                )),
                4000,
            );
            attach_test_link_full(&mut rt, i as u64 + 1, Some(addr), None);
        }
        let wan_addr: std::net::SocketAddr = "203.0.113.9:4000".parse().unwrap();
        assert!(matches!(
            rt.check_link_admission(Some(&wan_addr)),
            Err(LinkCap::Scope(LinkScope::Wan, MAX_WAN_LINKS))
        ));
        // Hive scope is independent and still has room.
        assert!(rt.check_link_admission(Some(&hive_addr(9))).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unbound_links_expire_and_bound_links_do_not() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-unbound-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        let now = now_secs();
        // One link unbound for longer than the deadline, one freshly
        // unbound, one bound.
        attach_test_link_full(&mut rt, 1, None, Some(now - UNBOUND_LINK_DEADLINE_SECS - 1));
        attach_test_link_full(&mut rt, 2, None, Some(now));
        attach_test_link_full(&mut rt, 3, None, None);
        let dropped = rt.sweep_unbound_links();
        assert_eq!(dropped, vec![1]);
        assert!(!rt.links.contains_key(&1));
        assert!(rt.links.contains_key(&2));
        assert!(rt.links.contains_key(&3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn link_bound_action_clears_and_sets_unbound_since() {
        let dir = std::env::temp_dir().join(format!(
            "latticed-linkbound-test-{}-{}",
            std::process::id(),
            now_secs()
        ));
        let mut rt = test_runtime(&dir);
        attach_test_link_full(&mut rt, 1, None, Some(now_secs()));
        let peer = Identifier::from_bytes([9u8; 32]);
        rt.apply_actions(vec![Action::LinkBound {
            link: 1,
            peer: Some(peer),
        }]);
        assert_eq!(rt.links.get(&1).unwrap().unbound_since, None);
        assert_eq!(rt.links.get(&1).unwrap().peer, Some(peer));
        // A cleared binding starts a fresh unbound window.
        rt.apply_actions(vec![Action::LinkBound {
            link: 1,
            peer: None,
        }]);
        assert!(rt.links.get(&1).unwrap().unbound_since.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
