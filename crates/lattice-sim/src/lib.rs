//! Deterministic in-process simulator for the Lattice protocol.
//!
//! A `Sim` owns some number of nodes (`lattice_core::Node<MemStore>`), a set
//! of links between them, a virtual clock, and an event queue. Every run is
//! fully determined by the seed. Tests drive time explicitly with
//! `run_for`, cut partitions with `set_link`, and crash nodes with
//! `crash_node`.

#![forbid(unsafe_code)]

use std::collections::VecDeque;

use lattice_core::{Action, AppSend, Config, Event, Node};
use lattice_proto::frames::Frame;
use lattice_store::{MemStore, Store};
use lattice_types::{Identifier, MessageId, X25519PublicKey};

pub type NodeIndex = usize;

/// Whether a simulated link is carrying traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

struct Link {
    id: u64,
    a: NodeIndex,
    b: NodeIndex,
    state: LinkState,
    latency_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEvent {
    Deliver {
        to: NodeIndex,
        link: u64,
        from: NodeIndex,
        frame: Frame,
    },
    Tick {
        node: NodeIndex,
    },
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

/// The two endpoints of a link, as node indices.
struct LinkEndpoints {
    a: NodeIndex,
    b: NodeIndex,
}

pub struct Sim<S: Store = MemStore> {
    pub nodes: Vec<Node<S>>,
    pub ids: Vec<Identifier>,
    pub channel_keys: std::collections::HashMap<Identifier, X25519PublicKey>,
    links: Vec<Link>,
    next_link: u64,
    now: u64,
    queue: VecDeque<ScheduledEvent>,
    seq: u64,
    pub deliveries: Vec<Delivery>,
    pub statuses: Vec<StatusObservation>,
    pub frame_counts: std::collections::HashMap<&'static str, u64>,
    configs: Vec<Config>,
    prototype: Config,
    store_factory: Box<dyn FnMut(usize) -> S>,
}

impl Sim<MemStore> {
    pub fn new(config: Config) -> Self {
        Self::with_stores(config, |_| MemStore::new())
    }
}

impl<S: Store> Sim<S> {
    /// A simulator whose nodes are backed by stores from `factory`
    /// (called once per added node, with the node index).
    pub fn with_stores(config: Config, factory: impl FnMut(usize) -> S + 'static) -> Self {
        let prototype = config;
        Sim {
            nodes: Vec::new(),
            ids: Vec::new(),
            links: Vec::new(),
            next_link: 1,
            now: 1,
            queue: VecDeque::new(),
            seq: 0,
            deliveries: Vec::new(),
            statuses: Vec::new(),
            channel_keys: std::collections::HashMap::new(),
            frame_counts: std::collections::HashMap::new(),
            configs: Vec::new(),
            prototype,
            store_factory: Box::new(factory),
        }
    }

    pub fn add_node(&mut self) -> NodeIndex {
        self.add_node_with(|_| {})
    }

    /// Add a node with a tweaked config (e.g. private mode with gateways).
    pub fn add_node_with(&mut self, f: impl FnOnce(&mut Config)) -> NodeIndex {
        let mut cfg = self.configs_prototype();
        f(&mut cfg);
        let seed = 0x5EED_0000u64
            .wrapping_add((self.nodes.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
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
        let seq = self.next_seq();
        self.queue.push_back(ScheduledEvent {
            at: self.now + 1,
            seq,
            event: SimEvent::Tick { node: node_idx },
        });
        node_idx
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
        let id = self.next_link;
        self.next_link += 1;
        self.links.push(Link {
            id,
            a,
            b,
            state: LinkState::Up,
            latency_ticks: 0,
        });
        self.link_up(a, id, Some(self.ids[b]), self.channel_keys[&self.ids[b]]);
        self.link_up(b, id, Some(self.ids[a]), self.channel_keys[&self.ids[a]]);
        id
    }

    /// Connect two nodes without pinning either side's peer id (as an
    /// inbound/unsolicited link behaves); attribution must come from records.
    pub fn connect_unpinned(&mut self, a: NodeIndex, b: NodeIndex) -> u64 {
        let id = self.next_link;
        self.next_link += 1;
        self.links.push(Link {
            id,
            a,
            b,
            state: LinkState::Up,
            latency_ticks: 0,
        });
        for (from, to) in [(a, b), (b, a)] {
            self.link_up(from, id, None, self.channel_keys[&self.ids[to]]);
        }
        id
    }

    /// Fire a LinkUp at a node and apply the actions it returns (the
    /// attestation frame, in particular). LinkUp's return value carries the
    /// attestation; dropping it would leave the link unattested.
    fn link_up(
        &mut self,
        node: NodeIndex,
        link: u64,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
    ) {
        let (actions, _diags) = self.nodes[node].handle(Event::LinkUp {
            at: self.now,
            link,
            peer,
            remote_ck,
        });
        self.apply_actions(node, actions);
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
            self.link_up(
                a,
                link_id,
                Some(self.ids[b]),
                self.channel_keys[&self.ids[b]],
            );
            self.link_up(
                b,
                link_id,
                Some(self.ids[a]),
                self.channel_keys[&self.ids[a]],
            );
        } else {
            let _ = self.nodes[a].handle(Event::LinkDown {
                at: self.now,
                link: link_id,
            });
            let _ = self.nodes[b].handle(Event::LinkDown {
                at: self.now,
                link: link_id,
            });
        }
    }

    pub fn set_latency(&mut self, link: u64, ticks: u64) {
        if let Some(l) = self.links.iter_mut().find(|l| l.id == link) {
            l.latency_ticks = ticks;
        }
    }

    pub fn link_between(&self, a: NodeIndex, b: NodeIndex) -> Option<u64> {
        self.links
            .iter()
            .find(|l| (l.a == a && l.b == b) || (l.a == b && l.b == a))
            .map(|l| l.id)
    }

    /// Full-control send used by tests that need a custom AppSend.
    pub fn force_app_send(&mut self, from: NodeIndex, send: lattice_core::AppSend) {
        self.dispatch(from, Event::AppSend(send));
    }

    /// Inject a raw frame into a node as if it arrived from `link`'s peer.
    /// Test hook for adversarial inputs.
    pub fn inject_frame(
        &mut self,
        target: NodeIndex,
        link: u64,
        frame: lattice_proto::frames::Frame,
    ) {
        let LinkEndpoints { a, b } = self.link_endpoints(link);
        let from = if a == target { b } else { a };
        self.dispatch(
            target,
            Event::Frame {
                at: self.now,
                link,
                from: self.ids[from],
                frame,
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

    fn link_endpoints(&self, link: u64) -> LinkEndpoints {
        let l = self
            .links
            .iter()
            .find(|l| l.id == link)
            .expect("link exists");
        LinkEndpoints { a: l.a, b: l.b }
    }

    /// Send a message from node `from` to the *identity* of node `to`.
    pub fn app_send(&mut self, from: NodeIndex, to: NodeIndex, body: &[u8]) -> MessageId {
        let to_id = self.ids[to];
        let send = AppSend {
            service: "test".to_string(),
            mid_hint: Some(crate::test_mid()),
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
    pub fn run_for(&mut self, secs: u64) {
        let end = self.now + secs;
        while let Some(ev) = self.pop_event() {
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
                frame,
            } => {
                let from_id = self.ids[from];
                let (actions, _diags) = self.nodes[to].handle(Event::Frame {
                    at: self.now,
                    link,
                    from: from_id,
                    frame,
                });
                self.apply_actions(to, actions);
            }
            SimEvent::Tick { node } => {
                let (actions, _diags) = self.nodes[node].handle(Event::Tick { at: self.now });
                self.apply_actions(node, actions);
                // re-arm the tick
                let seq = self.next_seq();
                self.queue.push_back(ScheduledEvent {
                    at: self.now + 1,
                    seq,
                    event: SimEvent::Tick { node },
                });
            }
        }
    }

    fn dispatch(&mut self, node: NodeIndex, ev: Event) {
        let (actions, _diags) = self.nodes[node].handle(ev);
        self.apply_actions(node, actions);
    }

    fn apply_actions(&mut self, from: NodeIndex, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::SendFrame { link, frame, .. } => {
                    let tag = match &frame {
                        Frame::Offer(_) => "offer",
                        Frame::Custody(_) => "custody",
                        Frame::Reconcile(_) => "reconcile",
                        Frame::Want(_) => "want",
                        Frame::Records(_) => "records",
                        Frame::Ping(_) => "ping",
                        Frame::Dummy(_) => "dummy",
                        Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => "handshake",
                        Frame::Attest(_) => "attest",
                    };
                    *self.frame_counts.entry(tag).or_insert(0) += 1;
                    self.route_frame(from, link, frame);
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
            }
        }
    }

    fn route_frame(&mut self, from: NodeIndex, link_id: u64, frame: Frame) {
        let Some(link) = self.links.iter().find(|l| l.id == link_id) else {
            return;
        };
        if link.state == LinkState::Down {
            return; // dropped: link down
        }
        let to = if link.a == from { link.b } else { link.a };
        let at = self.now + link.latency_ticks;
        self.push_event(
            at,
            SimEvent::Deliver {
                to,
                link: link_id,
                from,
                frame,
            },
        );
    }

    /// Crash a node: drop its in-memory state, keep the store, rebuild.
    pub fn crash_node(&mut self, idx: NodeIndex) {
        let placeholder = self.placeholder_node();
        let old = std::mem::replace(&mut self.nodes[idx], placeholder);
        let (identity, store) = old.into_parts();
        let cfg = self.configs[idx].clone();
        let node = Node::restore(cfg, identity, store, self.now).expect("restore");
        self.nodes[idx] = node;
        // re-announce links
        let up_links: Vec<(usize, usize, u64)> = self
            .links
            .iter()
            .filter(|l| l.state == LinkState::Up)
            .map(|l| (l.a, l.b, l.id))
            .collect();
        for (a, b, lid) in up_links {
            if a == idx {
                self.link_up(a, lid, Some(self.ids[b]), self.channel_keys[&self.ids[b]]);
                self.link_up(b, lid, Some(self.ids[a]), self.channel_keys[&self.ids[a]]);
            } else if b == idx {
                self.link_up(b, lid, Some(self.ids[a]), self.channel_keys[&self.ids[a]]);
                self.link_up(a, lid, Some(self.ids[b]), self.channel_keys[&self.ids[b]]);
            }
        }
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
        lattice_proto::record::PeerRecord::from_bytes(&stored.bytes, self.now, None)
            .expect("own record parses")
            .into_inner()
            .channel_key
    }

    /// Number of undelivered envelopes queued inside a node (debug).
    pub fn custody_count(&mut self, node: NodeIndex) -> usize {
        self.nodes[node].debug_custody_count()
    }

    pub fn node_ids(&self) -> &[Identifier] {
        &self.ids
    }
}

fn test_mid() -> MessageId {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut mid = [0u8; 16];
    let v = COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    mid[..8].copy_from_slice(&v.to_le_bytes());
    mid[8..].copy_from_slice(&v.rotate_left(32).to_le_bytes());
    MessageId::from_bytes(mid)
}
