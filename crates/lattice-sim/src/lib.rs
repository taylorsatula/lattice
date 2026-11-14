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
use lattice_store::MemStore;

pub type NodeIndex = usize;

struct Link {
    id: u64,
    a: NodeIndex,
    b: NodeIndex,
    up: bool,
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
    pub mid: [u8; 16],
    pub from: [u8; 32],
    pub body: Vec<u8>,
}

pub struct Sim {
    pub nodes: Vec<Node<MemStore>>,
    pub ids: Vec<[u8; 32]>,
    pub channel_keys: std::collections::HashMap<[u8; 32], [u8; 32]>,
    links: Vec<Link>,
    next_link: u64,
    now: u64,
    queue: VecDeque<(u64, u64, SimEvent)>,
    seq: u64,
    pub deliveries: Vec<Delivery>,
    pub statuses: Vec<([u8; 16], u64)>,
    pub frame_counts: std::collections::HashMap<&'static str, u64>,
    configs: Vec<Config>,
    prototype: Config,
}

impl Sim {
    pub fn new(config: Config) -> Self {
        let prototype = config.clone();
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
        }
    }

    pub fn add_node(&mut self) -> NodeIndex {
        let seed =
            0x5EED_0000u64.wrapping_add((self.nodes.len() as u64).wrapping_mul(0x9E3779B97F4A7C15));
        let mut cfg = self.configs_prototype();
        cfg.rng_seed = seed;
        let store = MemStore::new();
        let identity = lattice_core::Identity::generate();
        let channel_key = lattice_crypto::x25519_public(&identity.channel_seed);
        let node = Node::new(cfg.clone(), identity, store, self.now).expect("node construction");
        let id = node.own_id;
        self.channel_keys.insert(id, channel_key);
        self.nodes.push(node);
        self.ids.push(id);
        let idx = self.nodes.len() - 1;
        self.configs.push(cfg);
        let seq = self.next_seq();
        self.queue
            .push_back((self.now + 1, seq, SimEvent::Tick { node: idx }));
        idx
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn push_event(&mut self, at: u64, ev: SimEvent) {
        let seq = self.next_seq();
        self.queue.push_back((at, seq, ev));
    }

    pub fn connect(&mut self, a: NodeIndex, b: NodeIndex) -> u64 {
        let id = self.next_link;
        self.next_link += 1;
        self.links.push(Link {
            id,
            a,
            b,
            up: true,
            latency_ticks: 0,
        });
        self.nodes[a].handle(Event::LinkUp {
            at: self.now,
            link: id,
            peer: Some(self.ids[b]),
            remote_ck: self.channel_keys[&self.ids[b]],
            wan: true,
        });
        self.nodes[b].handle(Event::LinkUp {
            at: self.now,
            link: id,
            peer: Some(self.ids[a]),
            remote_ck: self.channel_keys[&self.ids[a]],
            wan: true,
        });
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
            up: true,
            latency_ticks: 0,
        });
        for (from, to) in [(a, b), (b, a)] {
            self.nodes[from].handle(Event::LinkUp {
                at: self.now,
                link: id,
                peer: None,
                remote_ck: self.channel_keys[&self.ids[to]],
                wan: true,
            });
        }
        id
    }

    pub fn set_link(&mut self, link_id: u64, up: bool) {
        let idx = self
            .links
            .iter()
            .position(|l| l.id == link_id)
            .expect("link exists");
        if self.links[idx].up == up {
            return;
        }
        self.links[idx].up = up;
        let (a, b) = (self.links[idx].a, self.links[idx].b);
        if up {
            self.nodes[a].handle(Event::LinkUp {
                at: self.now,
                link: link_id,
                peer: Some(self.ids[b]),
                remote_ck: self.channel_keys[&self.ids[b]],
                wan: true,
            });
            self.nodes[b].handle(Event::LinkUp {
                at: self.now,
                link: link_id,
                peer: Some(self.ids[a]),
                remote_ck: self.channel_keys[&self.ids[a]],
                wan: true,
            });
        } else {
            self.nodes[a].handle(Event::LinkDown {
                at: self.now,
                link: link_id,
            });
            self.nodes[b].handle(Event::LinkDown {
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
        let (a, b) = self.link_endpoints(link);
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

    fn link_endpoints(&self, link: u64) -> (NodeIndex, NodeIndex) {
        let l = self
            .links
            .iter()
            .find(|l| l.id == link)
            .expect("link exists");
        (l.a, l.b)
    }

    /// Send a message from node `from` to the *identity* of node `to`.
    pub fn app_send(&mut self, from: NodeIndex, to: NodeIndex, body: &[u8]) -> [u8; 16] {
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
        while let Some((at, _, ev)) = self.pop_event() {
            if at > end {
                let seq = self.next_seq();
                self.queue.push_front((at, seq, ev));
                break;
            }
            self.now = at;
            self.dispatch_event(ev);
        }
        self.now = end;
    }

    fn pop_event(&mut self) -> Option<(u64, u64, SimEvent)> {
        // queue is kept roughly ordered; do a linear-scan min extraction to keep it simple
        if self.queue.is_empty() {
            return None;
        }
        let mut best = 0;
        for (i, e) in self.queue.iter().enumerate() {
            if e.0 < self.queue[best].0 || (e.0 == self.queue[best].0 && e.1 < self.queue[best].1) {
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
                let actions = self.nodes[to].handle(Event::Frame {
                    at: self.now,
                    link,
                    from: from_id,
                    frame,
                });
                self.apply_actions(to, actions);
            }
            SimEvent::Tick { node } => {
                let actions = self.nodes[node].handle(Event::Tick { at: self.now });
                self.apply_actions(node, actions);
                // re-arm the tick
                let seq = self.next_seq();
                self.queue
                    .push_back((self.now + 1, seq, SimEvent::Tick { node }));
            }
        }
    }

    fn dispatch(&mut self, node: NodeIndex, ev: Event) {
        let actions = self.nodes[node].handle(ev);
        self.apply_actions(node, actions);
    }

    fn apply_actions(&mut self, from: NodeIndex, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::SendFrame { link, frame } => {
                    let tag = match &frame {
                        Frame::Offer(_) => "offer",
                        Frame::Custody(_) => "custody",
                        Frame::Reconcile(_) => "reconcile",
                        Frame::Want(_) => "want",
                        Frame::Records(_) => "records",
                        Frame::Ping(_) => "ping",
                        Frame::Dummy(_) => "dummy",
                        Frame::Wary(_) => "wary",
                        Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => "handshake",
                    };
                    *self.frame_counts.entry(tag).or_insert(0) += 1;
                    self.route_frame(from, link, frame)
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
                    self.statuses.push((mid, status));
                }
                Action::Inbox { .. } => {}
            }
        }
    }

    fn route_frame(&mut self, from: NodeIndex, link_id: u64, frame: Frame) {
        let Some(link) = self.links.iter().find(|l| l.id == link_id) else {
            return;
        };
        if !link.up {
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
        for link in &self.links {
            if !link.up {
                continue;
            }
            let (a, b, lid) = (link.a, link.b, link.id);
            if a == idx {
                self.nodes[a].handle(Event::LinkUp {
                    at: self.now,
                    link: lid,
                    peer: Some(self.ids[b]),
                    remote_ck: self.channel_keys[&self.ids[b]],
                    wan: true,
                });
                self.nodes[b].handle(Event::LinkUp {
                    at: self.now,
                    link: lid,
                    peer: Some(self.ids[a]),
                    remote_ck: self.channel_keys[&self.ids[a]],
                    wan: true,
                });
            } else if b == idx {
                self.nodes[b].handle(Event::LinkUp {
                    at: self.now,
                    link: lid,
                    peer: Some(self.ids[a]),
                    remote_ck: self.channel_keys[&self.ids[a]],
                    wan: true,
                });
                self.nodes[a].handle(Event::LinkUp {
                    at: self.now,
                    link: lid,
                    peer: Some(self.ids[b]),
                    remote_ck: self.channel_keys[&self.ids[b]],
                    wan: true,
                });
            }
        }
    }

    fn placeholder_node(&self) -> Node<MemStore> {
        let mut cfg = self.configs_prototype();
        cfg.rng_seed = u64::MAX;
        Node::new(
            cfg,
            lattice_core::Identity::generate(),
            MemStore::new(),
            self.now,
        )
        .expect("placeholder")
    }

    fn configs_prototype(&self) -> Config {
        self.prototype.clone()
    }

    /// Number of undelivered envelopes queued inside a node (debug).
    pub fn custody_count(&self, node: NodeIndex) -> usize {
        self.nodes[node].debug_custody_count()
    }

    pub fn node_ids(&self) -> &[[u8; 32]] {
        &self.ids
    }
}

fn test_mid() -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
    let mut mid = [0u8; 16];
    let v = COUNTER.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    mid[..8].copy_from_slice(&v.to_le_bytes());
    mid[8..].copy_from_slice(&v.rotate_left(32).to_le_bytes());
    mid
}
