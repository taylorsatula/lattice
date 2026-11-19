//! Deterministic in-process simulator for the Lattice protocol.
//!
//! A `Sim` owns some number of nodes (`lattice_core::Node<MemStore>`), a set
//! of links between them, a virtual clock, and an event queue. Every run is
//! fully determined by the seed. Tests drive time explicitly with
//! `run_for`, cut partitions with `set_link`, and crash nodes with
//! `crash_node`.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};

use lattice_core::{Action, AppSend, Config, Event, Node};
use lattice_proto::frames::Frame;
use lattice_proto::record::Scope;
use lattice_store::{MemStore, Store};
use lattice_types::{Identifier, MessageId, X25519PublicKey};

pub type NodeIndex = usize;

/// Why a frame could not be put on (or taken off) the simulated wire.
///
/// The sim treats these as hard errors (panics at the call site): a frame
/// that fails wire encoding indicates a bug in the node that emitted it,
/// and a frame that fails wire decoding indicates corruption the
/// transport would never deliver.
#[derive(Debug)]
pub enum WireError {
    /// The frame does not fit any bucket (or the requested bucket), or the
    /// wire bytes are not a bucket-sized, zero-padded `[frame, padding]`.
    Frame(lattice_net::FrameError),
    /// The frame bytes decoded as CBOR but not as a valid frame.
    Proto(lattice_proto::ProtoError),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Frame(e) => write!(f, "{e}"),
            WireError::Proto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WireError::Frame(e) => Some(e),
            WireError::Proto(e) => Some(e),
        }
    }
}

/// Encode a frame exactly as the transport would: frame CBOR, then the
/// bucket-padded `[frame, padding]` wire payload. `pad_to` selects a
/// specific bucket (snow dummies), mirroring `Action::SendFrame::pad_to`.
pub fn encode_frame_wire(frame: &Frame, pad_to: Option<usize>) -> Result<Vec<u8>, WireError> {
    let inner = frame.encode();
    match pad_to {
        Some(bucket) => lattice_net::encode_wire_to_bucket(&inner, bucket),
        None => lattice_net::encode_wire(&inner),
    }
    .map_err(WireError::Frame)
}

/// Decode a wire payload back into a frame, exactly as the transport would
/// on receipt: bucket size and zero padding are mandatory.
pub fn decode_frame_wire(bytes: &[u8]) -> Result<Frame, WireError> {
    let inner = lattice_net::decode_wire(bytes).map_err(WireError::Frame)?;
    Frame::from_bytes(&inner).map_err(WireError::Proto)
}

/// Whether a simulated link is carrying traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

/// Per-link fault model. The default is a perfect link.
///
/// All probabilities are drawn from the simulator's seeded RNG, so a run
/// with a given seed and configuration is exactly reproducible.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkBehavior {
    /// Probability in [0, 1] that a frame traversing the link is dropped.
    pub loss: f64,
    /// Probability in [0, 1] that a frame is delivered twice.
    pub duplicate: f64,
    /// Extra per-frame one-way delay drawn uniformly from [0, jitter_ms].
    /// Nonzero values let frames overtake each other (reordering).
    pub jitter_ms: u64,
}

impl Default for LinkBehavior {
    fn default() -> Self {
        Self {
            loss: 0.0,
            duplicate: 0.0,
            jitter_ms: 0,
        }
    }
}

/// Adversarial behavior for one node. Default is an honest node.
///
/// The adversary acts on frames the node sends or receives; it does not
/// get to forge identities (it has no keys it does not own).
#[derive(Clone, Debug, Default)]
pub struct Adversary {
    /// Drop each outgoing frame with this probability.
    pub drop_outgoing: f64,
    /// Drop each incoming frame with this probability.
    pub drop_incoming: f64,
    /// Add this fixed delay to every outgoing frame.
    pub delay_outgoing_ms: u64,
    /// If set, inject `frame` on every link the node has, every
    /// `interval_ms`. Models a spamming or garbage-spewing peer.
    pub inject: Option<(Frame, u64)>,
}

struct Link {
    id: u64,
    a: NodeIndex,
    b: NodeIndex,
    state: LinkState,
    latency_ms: u64,
    behavior: LinkBehavior,
    /// Scope of the link: WAN links carry WAN records, hive links carry
    /// hive records. Set at creation; test-created links default to WAN.
    scope: Scope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEvent {
    Deliver {
        to: NodeIndex,
        link: u64,
        from: NodeIndex,
        /// The bucket-padded wire payload, as it would ride the transport.
        wire: Vec<u8>,
    },
    /// Wake a node whose deadline (as reported by `Node::next_deadline`)
    /// has arrived. `gen` invalidates stale wakes scheduled before the
    /// node's deadline moved.
    Wake { node: NodeIndex, generation: u64 },
    /// An adversary's periodic injection tick for `node`.
    Inject { node: NodeIndex },
}

pub struct Delivery {
    pub node: NodeIndex,
    pub service: String,
    pub mid: MessageId,
    pub from: Identifier,
    pub body: Vec<u8>,
}

/// A status transition observed on a node, for tests to assert on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusObservation {
    pub mid: MessageId,
    pub status: u64,
}

/// An event scheduled on the virtual clock. `seq` breaks ties between
/// events at the same time; lower seq runs first.
struct ScheduledEvent {
    at: u64,
    seq: u64,
    event: SimEvent,
}

/// Default seed for `Sim::new`. Node `i` draws its identity and RNG seed
/// from `DEFAULT_SEED + i * GOLDEN`, so `Sim::new` runs are reproducible.
pub const DEFAULT_SEED: u64 = 0x5EED_0000;
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

/// Hard cap on events processed in one `run_for` call. A healthy scenario
/// processes orders of magnitude fewer; exceeding this means an event is
/// re-arming itself without the clock advancing.
const MAX_EVENTS_PER_RUN: u64 = 1_000_000;

pub struct Sim<S: Store = MemStore> {
    pub nodes: Vec<Node<S>>,
    pub ids: Vec<Identifier>,
    pub channel_keys: BTreeMap<Identifier, X25519PublicKey>,
    links: Vec<Link>,
    next_link: u64,
    now: u64,
    queue: VecDeque<ScheduledEvent>,
    seq: u64,
    pub deliveries: Vec<Delivery>,
    pub statuses: Vec<StatusObservation>,
    pub frame_counts: BTreeMap<&'static str, u64>,
    /// Frames dropped by link loss or an adversary.
    pub dropped_frames: u64,
    /// Extra frame copies delivered by link duplication.
    pub duplicated_frames: u64,
    /// Frames injected by adversaries.
    pub injected_frames: u64,
    configs: Vec<Config>,
    prototype: Config,
    store_factory: Box<dyn FnMut(usize) -> S>,
    /// Per-node generation for wake events; bumped on every (re)arm so a
    /// stale queued wake is ignored.
    wake_gen: Vec<u64>,
    /// The deadline the currently pending wake is for, per node. Avoids
    /// queueing a duplicate wake when the deadline has not moved.
    wake_armed: Vec<Option<u64>>,
    /// Per-node adversary; `None` (the default) is an honest node.
    adversaries: Vec<Option<Adversary>>,
    /// Seed the whole run derives from. `Sim::new` uses [`DEFAULT_SEED`].
    seed: u64,
    /// Simulator-side randomness (link loss/jitter/duplication, adversary
    /// decisions). Independent of the nodes' own streams.
    rng: lattice_core::Rng,
    /// (from, to) pairs whose dials always fail. Used to exercise
    /// dial-failure paths (e.g. test-before-evict).
    dial_blocked: std::collections::HashSet<(NodeIndex, NodeIndex)>,
    /// Per-instance counter behind `app_send`'s default message ids.
    mid_counter: u64,
}

impl Sim<MemStore> {
    pub fn new(config: Config) -> Self {
        Self::with_seed(config, DEFAULT_SEED)
    }

    /// A simulator whose every random draw derives from `seed`.
    pub fn with_seed(config: Config, seed: u64) -> Self {
        Self::with_stores_and_seed(config, seed, |_| MemStore::new())
    }
}

impl<S: Store> Sim<S> {
    /// A simulator whose nodes are backed by stores from `factory`
    /// (called once per added node, with the node index).
    pub fn with_stores(config: Config, factory: impl FnMut(usize) -> S + 'static) -> Self {
        Self::with_stores_and_seed(config, DEFAULT_SEED, factory)
    }

    /// A simulator with a caller-chosen seed and store factory.
    pub fn with_stores_and_seed(
        config: Config,
        seed: u64,
        factory: impl FnMut(usize) -> S + 'static,
    ) -> Self {
        let prototype = config;
        Sim {
            nodes: Vec::new(),
            ids: Vec::new(),
            links: Vec::new(),
            next_link: 1,
            now: 1_000,
            queue: VecDeque::new(),
            seq: 0,
            deliveries: Vec::new(),
            statuses: Vec::new(),
            frame_counts: BTreeMap::new(),
            dropped_frames: 0,
            duplicated_frames: 0,
            injected_frames: 0,
            configs: Vec::new(),
            prototype,
            store_factory: Box::new(factory),
            wake_gen: Vec::new(),
            wake_armed: Vec::new(),
            adversaries: Vec::new(),
            dial_blocked: std::collections::HashSet::new(),
            seed,
            rng: lattice_core::Rng::new(seed ^ 0xD1B5_4A32_D192_ED03),
            mid_counter: 0x9E37_79B9_7F4A_7C15,
            channel_keys: BTreeMap::new(),
        }
    }

    pub fn add_node(&mut self) -> NodeIndex {
        self.add_node_with(|_| {})
    }

    /// Add a node with a tweaked config (e.g. private mode with gateways).
    pub fn add_node_with(&mut self, f: impl FnOnce(&mut Config)) -> NodeIndex {
        let mut cfg = self.configs_prototype();
        f(&mut cfg);
        let seed = self
            .seed
            .wrapping_add((self.nodes.len() as u64).wrapping_mul(GOLDEN));
        cfg.rng_seed = seed;
        let store = (self.store_factory)(self.nodes.len());
        let idx = self.nodes.len() as u64;
        let mut id_bytes = [0u8; 32];
        id_bytes[..8].copy_from_slice(&idx.to_le_bytes());
        id_bytes[8..16].copy_from_slice(&0x5EED_5EED_5EED_5EED_u64.to_le_bytes());
        let identity = lattice_core::Identity::from_seed(&id_bytes);
        let channel_key = lattice_crypto::channel_x25519_public(&identity.channel_seed);
        let node = Node::new(cfg.clone(), identity, store, self.now).expect("node construction");
        let id = node.own_id;
        self.channel_keys.insert(id, channel_key);
        self.nodes.push(node);
        self.ids.push(id);
        let node_idx = self.nodes.len() - 1;
        self.configs.push(cfg);
        self.wake_gen.push(0);
        self.wake_armed.push(None);
        self.adversaries.push(None);
        self.arm_wake(node_idx);
        node_idx
    }

    /// Schedule a wake for the node's current core-reported deadline.
    /// Any previously queued wake for this node is invalidated. If a wake
    /// for the same deadline is already pending, does nothing.
    fn arm_wake(&mut self, node: NodeIndex) {
        let deadline = self.nodes[node].next_deadline();
        if self.wake_armed[node] == deadline {
            return;
        }
        self.wake_gen[node] += 1;
        let generation = self.wake_gen[node];
        self.wake_armed[node] = deadline;
        if let Some(at) = deadline {
            self.push_event(at, SimEvent::Wake { node, generation });
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn push_event(&mut self, at: u64, ev: SimEvent) {
        let seq = self.next_seq();
        self.queue.push_back(ScheduledEvent { at, seq, event: ev });
    }

    pub fn connect(&mut self, a: NodeIndex, b: NodeIndex) -> u64 {
        self.connect_scoped(a, b, Scope::Wan)
    }

    /// Connect two nodes with an explicit link scope. Hive links carry
    /// only hive records in each direction; WAN links only WAN records.
    pub fn connect_scoped(&mut self, a: NodeIndex, b: NodeIndex, scope: Scope) -> u64 {
        let id = self.next_link;
        self.next_link += 1;
        self.links.push(Link {
            id,
            a,
            b,
            state: LinkState::Up,
            latency_ms: 0,
            behavior: LinkBehavior::default(),
            scope,
        });
        self.link_up(
            a,
            id,
            Some(self.ids[b]),
            self.channel_keys[&self.ids[b]],
            scope,
        );
        self.link_up(
            b,
            id,
            Some(self.ids[a]),
            self.channel_keys[&self.ids[a]],
            scope,
        );
        id
    }

    /// Connect two nodes without pinning either side's peer id (as an
    /// inbound/unsolicited link behaves); attribution must come from records.
    pub fn connect_unpinned(&mut self, a: NodeIndex, b: NodeIndex) -> u64 {
        self.connect_unpinned_scoped(a, b, Scope::Wan)
    }

    /// Like [`Sim::connect_unpinned`] with an explicit link scope.
    pub fn connect_unpinned_scoped(&mut self, a: NodeIndex, b: NodeIndex, scope: Scope) -> u64 {
        let id = self.next_link;
        self.next_link += 1;
        self.links.push(Link {
            id,
            a,
            b,
            state: LinkState::Up,
            latency_ms: 0,
            behavior: LinkBehavior::default(),
            scope,
        });
        for (from, to) in [(a, b), (b, a)] {
            self.link_up(from, id, None, self.channel_keys[&self.ids[to]], scope);
        }
        id
    }

    /// Fire a LinkUp at a node and apply the actions it returns. LinkUp's
    /// return value carries any frames the node wants on the wire; dropping
    /// them would leave the peer without them.
    fn link_up(
        &mut self,
        node: NodeIndex,
        link: u64,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
        scope: Scope,
    ) {
        let (actions, _diags) = self.nodes[node].handle(Event::LinkUp {
            at: self.now,
            link,
            peer,
            remote_ck,
            scope,
        });
        self.apply_actions(node, actions);
        self.arm_wake(node);
    }

    pub fn set_link(&mut self, link_id: u64, state: LinkState) {
        let idx = self
            .links
            .iter()
            .position(|l| l.id == link_id)
            .expect("link exists");
        if self.links[idx].state == state {
            return;
        }
        self.links[idx].state = state;
        let (a, b) = (self.links[idx].a, self.links[idx].b);
        if state == LinkState::Up {
            let scope = self.links[idx].scope;
            self.link_up(
                a,
                link_id,
                Some(self.ids[b]),
                self.channel_keys[&self.ids[b]],
                scope,
            );
            self.link_up(
                b,
                link_id,
                Some(self.ids[a]),
                self.channel_keys[&self.ids[a]],
                scope,
            );
        } else {
            for end in [a, b] {
                let (actions, _diags) = self.nodes[end].handle(Event::LinkDown {
                    at: self.now,
                    link: link_id,
                });
                self.apply_actions(end, actions);
                self.arm_wake(end);
            }
        }
    }

    /// Set the one-way latency of a link, in milliseconds.
    pub fn set_latency(&mut self, link: u64, ms: u64) {
        if let Some(l) = self.links.iter_mut().find(|l| l.id == link) {
            l.latency_ms = ms;
        }
    }

    /// Set the loss/duplication/jitter behavior of a link.
    pub fn set_link_behavior(&mut self, link: u64, behavior: LinkBehavior) {
        if let Some(l) = self.links.iter_mut().find(|l| l.id == link) {
            l.behavior = behavior;
        }
    }

    /// Install (or clear, with the default) an adversary on a node.
    ///
    /// If the adversary injects frames, the first injection is scheduled
    /// one interval from now and repeats until the adversary is cleared.
    pub fn set_adversary(&mut self, node: NodeIndex, adversary: Adversary) {
        let inject = adversary.inject.clone();
        self.adversaries[node] = Some(adversary);
        if let Some((_, interval_ms)) = inject {
            self.push_event(self.now + interval_ms, SimEvent::Inject { node });
        }
    }

    /// Ids of all links (up or down), in creation order.
    pub fn link_ids(&self) -> Vec<u64> {
        self.links.iter().map(|l| l.id).collect()
    }

    pub fn link_between(&self, a: NodeIndex, b: NodeIndex) -> Option<u64> {
        self.links
            .iter()
            .find(|l| (l.a == a && l.b == b) || (l.a == b && l.b == a))
            .map(|l| l.id)
    }

    /// The id of the *up* link between `a` and `b`, if any.
    pub fn up_link_between(&self, a: NodeIndex, b: NodeIndex) -> Option<u64> {
        self.links
            .iter()
            .find(|l| {
                l.state == LinkState::Up && ((l.a == a && l.b == b) || (l.a == b && l.b == a))
            })
            .map(|l| l.id)
    }

    /// Block or unblock dials from `from` to `to` (dial-failure injection).
    pub fn set_dial_blocked(&mut self, from: NodeIndex, to: NodeIndex, blocked: bool) {
        if blocked {
            self.dial_blocked.insert((from, to));
        } else {
            self.dial_blocked.remove(&(from, to));
        }
    }

    /// Full-control send used by tests that need a custom AppSend.
    pub fn force_app_send(&mut self, from: NodeIndex, send: lattice_core::AppSend) {
        self.dispatch(from, Event::AppSend(send));
    }

    /// Inject a raw frame into a node as if it arrived from `link`'s peer.
    /// Test hook for adversarial inputs. The frame is round-tripped through
    /// the wire encoding first, so an unencodable frame is a hard error.
    pub fn inject_frame(
        &mut self,
        target: NodeIndex,
        link: u64,
        frame: lattice_proto::frames::Frame,
    ) {
        let wire = encode_frame_wire(&frame, None)
            .unwrap_or_else(|e| panic!("sim: injected frame failed wire encoding: {e}"));
        let bucket = lattice_net::FRAME_BUCKETS
            .iter()
            .position(|&b| b == wire.len());
        let frame = decode_frame_wire(&wire)
            .unwrap_or_else(|e| panic!("sim: injected frame failed wire decoding: {e}"));
        self.dispatch(
            target,
            Event::Frame {
                at: self.now,
                link,
                frame,
                bucket,
            },
        );
    }

    /// Wrap a message in an Offer frame and inject it at `target`.
    pub fn inject_offer(&mut self, target: NodeIndex, link: u64, message: Vec<u8>) {
        self.inject_frame(
            target,
            link,
            lattice_proto::frames::Frame::Offer(lattice_proto::frames::OfferFrame { message }),
        );
    }

    /// Send a message from node `from` to the *identity* of node `to`.
    pub fn app_send(&mut self, from: NodeIndex, to: NodeIndex, body: &[u8]) -> MessageId {
        let to_id = self.ids[to];
        let send = AppSend {
            service: "test".to_string(),
            mid_hint: Some(self.next_mid()),
            to: to_id,
            tsvc: "test".to_string(),
            tmbx: b"inbox".to_vec(),
            fmbx: b"outbox".to_vec(),
            body: body.to_vec(),
            exp: None,
            priority: 1,
            route: 0,
        };
        let mid_hint = send.mid_hint.unwrap();
        self.dispatch(from, Event::AppSend(send));
        mid_hint
    }

    /// Run the simulation for `secs` virtual seconds.
    ///
    /// Panics if more than [`MAX_EVENTS_PER_RUN`] events are processed in a
    /// single call: that means some event keeps re-arming itself at a time
    /// the clock never advances past, which is a bug, not a slow scenario.
    pub fn run_for(&mut self, secs: u64) {
        let end = self.now + secs.saturating_mul(1000);
        let mut events: u64 = 0;
        while let Some(ev) = self.pop_event() {
            events += 1;
            assert!(
                events <= MAX_EVENTS_PER_RUN,
                "sim: exceeded {MAX_EVENTS_PER_RUN} events in run_for({secs}) at t={}; \
                 an event is re-arming without the clock advancing",
                self.now
            );
            if ev.at > end {
                let seq = self.next_seq();
                self.queue.push_front(ScheduledEvent {
                    at: ev.at,
                    seq,
                    event: ev.event,
                });
                break;
            }
            self.now = ev.at;
            self.dispatch_event(ev.event);
        }
        self.now = end;
    }

    fn pop_event(&mut self) -> Option<ScheduledEvent> {
        // queue is kept roughly ordered; do a linear-scan min extraction to keep it simple
        if self.queue.is_empty() {
            return None;
        }
        let mut best = 0;
        for (i, e) in self.queue.iter().enumerate() {
            if e.at < self.queue[best].at
                || (e.at == self.queue[best].at && e.seq < self.queue[best].seq)
            {
                best = i;
            }
        }
        self.queue.remove(best)
    }

    fn dispatch_event(&mut self, ev: SimEvent) {
        match ev {
            SimEvent::Deliver {
                to,
                link,
                from,
                wire,
            } => {
                // Adversarial receiver: drop the frame before the node sees it.
                if let Some(adv) = &self.adversaries[to] {
                    if adv.drop_incoming > 0.0 && self.rng.chance(adv.drop_incoming) {
                        self.dropped_frames += 1;
                        return;
                    }
                }
                let bucket = lattice_net::FRAME_BUCKETS
                    .iter()
                    .position(|&b| b == wire.len());
                let frame = decode_frame_wire(&wire).unwrap_or_else(|e| {
                    panic!("sim: wire frame from node {from} to node {to} failed decoding: {e}")
                });
                let (actions, _diags) = self.nodes[to].handle(Event::Frame {
                    at: self.now,
                    link,
                    frame,
                    bucket,
                });
                self.apply_actions(to, actions);
                self.arm_wake(to);
            }
            SimEvent::Inject { node } => {
                let Some(adv) = self.adversaries[node].clone() else {
                    return;
                };
                let Some((frame, interval_ms)) = adv.inject else {
                    return;
                };
                // Encode once; the frame rides every up link the node has.
                match encode_frame_wire(&frame, None) {
                    Ok(wire) => {
                        let links: Vec<u64> = self
                            .links
                            .iter()
                            .filter(|l| l.state == LinkState::Up && (l.a == node || l.b == node))
                            .map(|l| l.id)
                            .collect();
                        for link in links {
                            self.injected_frames += 1;
                            self.route_frame(node, link, wire.clone());
                        }
                    }
                    Err(e) => panic!("sim: adversary frame failed wire encoding: {e}"),
                }
                self.push_event(self.now + interval_ms, SimEvent::Inject { node });
            }
            SimEvent::Wake { node, generation } => {
                // A newer wake was armed after this one was queued; skip.
                if generation != self.wake_gen[node] {
                    return;
                }
                self.wake_armed[node] = None;
                let (actions, _diags) = self.nodes[node].handle(Event::Tick { at: self.now });
                self.apply_actions(node, actions);
                self.arm_wake(node);
            }
        }
    }

    fn dispatch(&mut self, node: NodeIndex, ev: Event) {
        let (actions, _diags) = self.nodes[node].handle(ev);
        self.apply_actions(node, actions);
        self.arm_wake(node);
    }

    fn apply_actions(&mut self, from: NodeIndex, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::SendFrame {
                    link,
                    frame,
                    pad_to,
                } => {
                    let tag = match &frame {
                        Frame::Offer(_) => "offer",
                        Frame::Custody(_) => "custody",
                        Frame::Reconcile(_) => "reconcile",
                        Frame::Want(_) => "want",
                        Frame::Records(_) => "records",
                        Frame::Ping(_) => "ping",
                        Frame::Dummy(_) => "dummy",
                        Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => "handshake",
                        Frame::Kels(_) => "kels",
                    };
                    let wire = encode_frame_wire(&frame, pad_to).unwrap_or_else(|e| {
                        panic!("sim: {tag} frame from node {from} failed wire encoding: {e}")
                    });
                    *self.frame_counts.entry(tag).or_insert(0) += 1;
                    self.route_frame(from, link, wire);
                }
                Action::Deliver {
                    service,
                    mid,
                    from: f,
                    body,
                    ..
                } => {
                    self.deliveries.push(Delivery {
                        node: from,
                        service,
                        mid,
                        from: f,
                        body,
                    });
                }
                Action::Status { mid, status, .. } => {
                    self.statuses.push(StatusObservation { mid, status });
                }
                Action::Inbox { .. } => {}
                // The simulator tracks links itself; binding changes are a
                // runtime concern.
                Action::LinkBound { .. } => {}
                Action::Dial { peer, scope, .. } => {
                    // Perform the dial: connect the two nodes if the
                    // target exists and the dial is not blocked, else
                    // report the failure back to the dialing node. The
                    // link takes the scope of the candidate record the
                    // dial came from.
                    let target = self.ids.iter().position(|id| *id == peer);
                    match target {
                        Some(t) if !self.dial_blocked.contains(&(from, t)) => {
                            let id = self.next_link;
                            self.next_link += 1;
                            self.links.push(Link {
                                id,
                                a: from,
                                b: t,
                                state: LinkState::Up,
                                latency_ms: 0,
                                behavior: LinkBehavior::default(),
                                scope,
                            });
                            let ck_to = self.channel_keys[&self.ids[t]];
                            let ck_from = self.channel_keys[&self.ids[from]];
                            // The dialer pins the peer (IK dial); the
                            // callee sees an unsolicited inbound link.
                            self.link_up(from, id, Some(self.ids[t]), ck_to, scope);
                            self.link_up(t, id, None, ck_from, scope);
                        }
                        _ => {
                            let (actions, _diags) =
                                self.nodes[from].handle(Event::DialFailed { at: self.now, peer });
                            self.apply_actions(from, actions);
                        }
                    }
                }
                Action::CloseLink { link } => {
                    if let Some(idx) = self.links.iter().position(|l| l.id == link) {
                        if self.links[idx].state == LinkState::Up {
                            self.links[idx].state = LinkState::Down;
                            let (a, b) = (self.links[idx].a, self.links[idx].b);
                            for end in [a, b] {
                                let (actions, _diags) =
                                    self.nodes[end].handle(Event::LinkDown { at: self.now, link });
                                self.apply_actions(end, actions);
                                self.arm_wake(end);
                            }
                        }
                    }
                }
            }
        }
    }

    fn route_frame(&mut self, from: NodeIndex, link_id: u64, wire: Vec<u8>) {
        // Adversarial sender: drop or delay before the link sees the frame.
        if let Some(adv) = &self.adversaries[from] {
            if adv.drop_outgoing > 0.0 && self.rng.chance(adv.drop_outgoing) {
                self.dropped_frames += 1;
                return;
            }
        }
        let Some(link) = self.links.iter().find(|l| l.id == link_id) else {
            return;
        };
        if link.state == LinkState::Down {
            return; // dropped: link down
        }
        let behavior = link.behavior;
        let to = if link.a == from { link.b } else { link.a };
        let mut at = self.now + link.latency_ms;
        if let Some(adv) = &self.adversaries[from] {
            at += adv.delay_outgoing_ms;
        }
        if behavior.jitter_ms > 0 {
            at += self.rng.below(behavior.jitter_ms + 1);
        }
        if behavior.loss > 0.0 && self.rng.chance(behavior.loss) {
            self.dropped_frames += 1;
            return;
        }
        let duplicate = behavior.duplicate > 0.0 && self.rng.chance(behavior.duplicate);
        if duplicate {
            self.duplicated_frames += 1;
        }
        self.push_event(
            at,
            SimEvent::Deliver {
                to,
                link: link_id,
                from,
                wire: wire.clone(),
            },
        );
        if duplicate {
            self.push_event(
                at,
                SimEvent::Deliver {
                    to,
                    link: link_id,
                    from,
                    wire,
                },
            );
        }
    }

    /// Crash a node: drop its in-memory state, keep the store, rebuild.
    pub fn crash_node(&mut self, idx: NodeIndex) {
        let placeholder = self.placeholder_node();
        let old = std::mem::replace(&mut self.nodes[idx], placeholder);
        let (identity, store) = old.into_parts();
        let cfg = self.configs[idx].clone();
        let node = Node::new(cfg, identity, store, self.now).expect("restore");
        self.nodes[idx] = node;
        // re-announce links
        let up_links: Vec<(usize, usize, u64, Scope)> = self
            .links
            .iter()
            .filter(|l| l.state == LinkState::Up)
            .map(|l| (l.a, l.b, l.id, l.scope))
            .collect();
        for (a, b, lid, scope) in up_links {
            if a == idx {
                self.link_up(
                    a,
                    lid,
                    Some(self.ids[b]),
                    self.channel_keys[&self.ids[b]],
                    scope,
                );
                self.link_up(
                    b,
                    lid,
                    Some(self.ids[a]),
                    self.channel_keys[&self.ids[a]],
                    scope,
                );
            } else if b == idx {
                self.link_up(
                    b,
                    lid,
                    Some(self.ids[a]),
                    self.channel_keys[&self.ids[a]],
                    scope,
                );
                self.link_up(
                    a,
                    lid,
                    Some(self.ids[b]),
                    self.channel_keys[&self.ids[b]],
                    scope,
                );
            }
        }
        self.arm_wake(idx);
    }

    fn placeholder_node(&mut self) -> Node<S> {
        let mut cfg = self.configs_prototype();
        cfg.rng_seed = u64::MAX;
        Node::new(
            cfg,
            lattice_core::Identity::from_seed(&[0xFF; 32]),
            (self.store_factory)(usize::MAX),
            self.now,
        )
        .expect("placeholder")
    }

    fn configs_prototype(&self) -> Config {
        self.prototype.clone()
    }

    /// The Ed25519 channel key in a node's own record (what a forger would
    /// claim). Read from the node's store.
    pub fn channel_key_of(&self, node: NodeIndex) -> lattice_types::ChannelPublicKey {
        let id = self.ids[node];
        let stored = self.nodes[node]
            .store_ref()
            .record_get(&id, lattice_proto::record::Scope::Wan)
            .expect("record read")
            .expect("own record present");
        let kel_bytes = self.nodes[node]
            .store_ref()
            .kel_get(&id)
            .expect("kel read")
            .expect("own kel present");
        let kel = lattice_proto::kel::ValidatedKel::from_object_bytes(&kel_bytes)
            .expect("own kel validates");
        lattice_proto::record::PeerRecord::from_bytes(&stored.bytes, self.now, &kel)
            .expect("own record parses")
            .into_inner()
            .channel_key
    }

    /// Number of undelivered envelopes queued inside a node (debug).
    pub fn custody_count(&mut self, node: NodeIndex) -> usize {
        self.nodes[node].debug_custody_count()
    }

    /// Bytes held in custody by a node (debug).
    pub fn custody_bytes(&mut self, node: NodeIndex) -> u64 {
        self.nodes[node].custody_bytes()
    }

    fn next_mid(&mut self) -> MessageId {
        let v = self.mid_counter;
        self.mid_counter = self.mid_counter.wrapping_add(GOLDEN);
        let mut mid = [0u8; 16];
        mid[..8].copy_from_slice(&v.to_le_bytes());
        mid[8..].copy_from_slice(&v.rotate_left(32).to_le_bytes());
        MessageId::from_bytes(mid)
    }

    pub fn node_ids(&self) -> &[Identifier] {
        &self.ids
    }
}
