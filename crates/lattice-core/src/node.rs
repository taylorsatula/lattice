//! The sans-IO node state machine. Events in, actions out; all time,
//! randomness and persistence are injected.

use std::collections::{HashMap, HashSet};

use lattice_proto::frames::*;
use lattice_proto::kel::{self, KeyEvent};
use lattice_proto::local;
use lattice_proto::message::{
    BuildParams, Envelope, GatewaySeal, HopLayerPlain, KIND_MESSAGE, KIND_NEGATIVE_RECEIPT,
    KIND_RECEIPT, Message, WaypointSeal,
};
use lattice_proto::record::{Mode, PeerRecord, Scope, compare_lww};
use lattice_store::{CustodyEntry, InboxEntry, OutboundState, Store};

use crate::graph::Graph;
use crate::reconcile::{self, ReconcileSession};
use crate::rng::Rng;
use crate::types::*;

pub struct Identity {
    pub signing_seed: [u8; 32],
    pub kel: Vec<KeyEvent>,
    pub channel_seed: [u8; 32],
    pub xwing_secret: [u8; 32],
    pub xwing_public: [u8; 1216],
}

impl Identity {
    pub fn generate() -> Self {
        let signing_seed = lattice_crypto::generate_seed();
        let next_seed = lattice_crypto::generate_seed();
        let inception = KeyEvent::inception(&signing_seed, hash_next(&next_seed));
        // Keep the next seed only if the caller wants pre-rotation; for now the
        // daemon stores it separately (see lattice-crypto). The inception
        // commits to it; losing it strands rotation, which is the intended UX.
        let _ = next_seed;
        let kp = lattice_crypto::generate_keypair();
        Identity {
            signing_seed,
            kel: vec![inception],
            channel_seed: lattice_crypto::os_bytes::<32>(),
            xwing_secret: kp.secret,
            xwing_public: kp.public,
        }
    }

    pub fn id(&self) -> [u8; 32] {
        kel::identifier(&self.kel).expect("inception validates")
    }
}

fn hash_next(seed: &[u8; 32]) -> [u8; 32] {
    lattice_crypto::hash(&lattice_crypto::public_key(seed))
}

struct PendingOffer {
    origin: PendingOrigin,
    sent_at: u64,
    excluded: Vec<(LinkId, u64)>,
}

enum PendingOrigin {
    Outbound {
        mid: [u8; 16],
    },
    /// Custody-entry key of the relay entry this offer belongs to.
    Relay {
        custody_leg: [u8; 16],
    },
}

struct LinkState {
    /// `None` while the peer's identity is not safely established.
    peer: Option<[u8; 32]>,
    remote_ck: [u8; 32],
    /// True when the peer id was pinned by operator config (root `id`); pinned
    /// bindings are never re-derived from records or revoked by contest.
    pinned: bool,
}

pub struct Node<S: Store> {
    pub config: Config,
    identity: Identity,
    store: S,
    pub own_id: [u8; 32],
    scope: Scope,
    own_seq: u64,
    links: HashMap<LinkId, LinkState>,
    next_link_order: Vec<LinkId>,
    neighbors_dirty: bool,
    reconcile_sessions: HashMap<LinkId, ReconcileSession>,
    pending: HashMap<[u8; 16], PendingOffer>,
    outbound_exclusions: HashMap<[u8; 16], Vec<(LinkId, u64)>>,
    snow_next: u64,
    frames_since_snow_tick: u32,
    snow_history: [u64; 3],
    inner_pending_echo: Vec<(u64, LinkId)>,
    record_refresh_at: u64,
    next_reconcile_at: u64,
    rng: Rng,
    now: u64,
    draining: bool,
    equivocations: u64,
    /// channel_key -> set of node ids whose records claim that key.
    /// Attribution of a link to a peer is allowed only when exactly one id
    /// claims the link's channel key; more than one fails closed.
    ck_claims: HashMap<[u8; 32], std::collections::HashSet<[u8; 32]>>,
    contested: u64,
}

impl<S: Store> Node<S> {
    pub fn new(config: Config, identity: Identity, store: S, now: u64) -> Result<Self, String> {
        if config.mode == Mode::Private && (config.gateways.is_empty() || config.gateways.len() > 3)
        {
            return Err("private mode requires 1-3 gateways".to_string());
        }
        if config.mode == Mode::Public && !config.gateways.is_empty() {
            return Err("gateways are only valid in private mode".to_string());
        }
        let rng_seed = config.rng_seed;
        let id = identity.id();
        // Publish our own record if absent.
        let own_exists = store
            .record_get(&id, Scope::Wan)
            .map_err(|e| e.to_string())?
            .is_some();
        let mut node = Node {
            config,
            identity,
            store,
            own_id: id,
            scope: Scope::Wan,
            own_seq: 1,
            links: HashMap::new(),
            next_link_order: Vec::new(),
            neighbors_dirty: true,
            reconcile_sessions: HashMap::new(),
            pending: HashMap::new(),
            outbound_exclusions: HashMap::new(),
            snow_next: now,
            frames_since_snow_tick: 0,
            snow_history: [0; 3],
            inner_pending_echo: Vec::new(),
            record_refresh_at: now + 3600,
            next_reconcile_at: now + 1,
            rng: Rng::new(rng_seed),
            now,
            draining: false,
            equivocations: 0,
            ck_claims: HashMap::new(),
            contested: 0,
        };
        // Seed the claim set from records already in the store so links can be
        // attributed immediately after a restart.
        if let Ok(records) = node.store.record_all() {
            for (_, _, bytes, _) in records {
                if let Ok((rec, _)) = PeerRecord::from_bytes(&bytes, now, None) {
                    node.ck_claims
                        .entry(rec.channel_key)
                        .or_default()
                        .insert(rec.id);
                }
            }
        }
        if !own_exists {
            node.publish_record(now).map_err(|e| e.to_string())?;
        } else if let Some((bytes, _)) = node
            .store
            .record_get(&id, Scope::Wan)
            .map_err(|e| e.to_string())?
        {
            node.own_seq = lattice_proto::record::PeerRecord::from_bytes(&bytes, now, None)
                .map(|(r, _)| r.seq)
                .unwrap_or(1);
        }
        Ok(node)
    }

    pub fn handle(&mut self, event: Event) -> Vec<Action> {
        match event {
            Event::LinkUp {
                at,
                link,
                peer,
                remote_ck,
                wan,
            } => self.on_link_up(at, link, peer, remote_ck, wan),
            Event::LinkDown { at, link } => self.on_link_down(at, link),
            Event::Frame {
                at,
                link,
                from,
                frame,
            } => self.on_frame(at, link, from, frame),
            Event::Tick { at } => self.on_tick(at),
            Event::AppSend(send) => self.on_app_send(send),
            Event::AppAck {
                service,
                delivery_ids,
                at,
            } => self.on_app_ack(at, &service, &delivery_ids),
        }
    }
}

impl<S: Store> Node<S> {
    fn touch(&mut self, at: u64) {
        self.now = at;
    }

    // ---------- records ----------

    fn build_own_record(&self, seq: u64, now: u64) -> Result<(PeerRecord, Vec<u8>), String> {
        let exp = now + 7 * 24 * 3600;
        let private = self.config.mode == Mode::Private;
        let links: Vec<[u8; 32]> = if private {
            vec![]
        } else {
            self.links.values().filter_map(|l| l.peer).collect()
        };
        let endpoints: Vec<lattice_proto::record::Endpoint> = if private {
            Vec::new()
        } else {
            self.config
                .advertise
                .iter()
                .map(|url| lattice_proto::record::Endpoint {
                    url: url.clone(),
                    ips: Vec::new(),
                })
                .collect()
        };
        let gateways = if private {
            self.config.gateways.clone()
        } else {
            Vec::new()
        };
        let rec = PeerRecord::build(
            lattice_proto::record::RecordParams {
                kel: self.identity.kel.clone(),
                seq,
                exp,
                channel_key: lattice_crypto::x25519_public(&self.identity.channel_seed),
                envelope_key: self.identity.xwing_public,
                mode: self.config.mode,
                scope: self.scope,
                endpoints,
                links,
                gateways,
                capabilities: 1,
            },
            &self.identity.signing_seed,
        )
        .map_err(|e| e.to_string())?;
        let bytes = rec.encode();
        Ok((rec, bytes))
    }

    fn publish_record(&mut self, now: u64) -> Result<(), String> {
        let (_rec, bytes) = self.build_own_record(self.own_seq, now)?;
        let id = self.own_id;
        self.store
            .record_put(&id, self.scope, &bytes, now)
            .map_err(|e| e.to_string())?;
        self.neighbors_dirty = true;
        Ok(())
    }

    fn on_link_up(
        &mut self,
        at: u64,
        link: LinkId,
        peer: Option<[u8; 32]>,
        remote_ck: [u8; 32],
        wan: bool,
    ) -> Vec<Action> {
        self.touch(at);
        let _ = wan;
        self.links.insert(
            link,
            LinkState {
                peer,
                remote_ck,
                pinned: peer.is_some(),
            },
        );
        self.next_link_order.push(link);
        self.reconcile_sessions
            .insert(link, ReconcileSession::new());
        // Reconcile promptly: the peer needs our record (and we need theirs)
        // for routing to work at all; waiting a full interval stalls delivery.
        self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        self.neighbors_dirty = true;
        // Publish the new link set immediately so peers can route via us.
        self.own_seq += 1;
        let _ = self.publish_record(at);
        self.reevaluate_link_bindings(at);
        Vec::new()
    }

    fn on_link_down(&mut self, at: u64, link: LinkId) -> Vec<Action> {
        self.touch(at);
        self.links.remove(&link);
        self.next_link_order.retain(|l| *l != link);
        self.reconcile_sessions.remove(&link);
        self.neighbors_dirty = true;
        self.own_seq += 1;
        let _ = self.publish_record(at);
        Vec::new()
    }

    fn build_graph(&self) -> Graph {
        let ids_and_links: Vec<([u8; 32], Vec<[u8; 32]>)> = self
            .store
            .record_all()
            .unwrap_or_default()
            .iter()
            .filter_map(|(id, _scope, bytes, _recv)| {
                PeerRecord::from_bytes(bytes, self.now, None)
                    .ok()
                    .map(|(r, _)| (*id, r.links))
            })
            .collect();
        Graph::build(
            &self.own_id,
            ids_and_links.iter().map(|(i, l)| (i, l.as_slice())),
        )
    }

    fn record_items(&self) -> Vec<reconcile::Item> {
        let mut items: Vec<reconcile::Item> = self
            .store
            .record_all()
            .unwrap_or_default()
            .iter()
            .filter_map(|(id, scope, bytes, _)| {
                PeerRecord::from_bytes(bytes, self.now, None)
                    .ok()
                    .map(|(r, _)| reconcile::Item {
                        id: *id,
                        scope: scope_as_u8(*scope),
                        seq: r.seq,
                    })
            })
            .collect();
        items.sort();
        items.dedup();
        items
    }

    // ---------- reconcile ----------

    fn reconcile_with(&mut self, _at: u64, link: LinkId) -> Vec<Action> {
        let items = self.record_items();
        // a fresh round gets a fresh session so entries echo exactly once per range
        self.reconcile_sessions
            .insert(link, ReconcileSession::new());
        vec![Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Reconcile(ReconcileFrame {
                ranges: reconcile::initiate(&items),
            }),
        }]
    }

    fn on_reconcile(&mut self, _at: u64, link: LinkId, frame: &ReconcileFrame) -> Vec<Action> {
        let items = self.record_items();
        let session = self.reconcile_sessions.entry(link).or_default();
        let (reply, wants) = reconcile::respond(&items, &frame.ranges, session);
        let mut actions = Vec::new();
        if !reply.is_empty() {
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Reconcile(ReconcileFrame { ranges: reply }),
            });
        }
        if !wants.is_empty() {
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Want(WantFrame { wants }),
            });
        }
        actions
    }

    fn on_want(&mut self, link: LinkId, frame: &WantFrame) -> Vec<Action> {
        let mut records = Vec::new();
        for (id, scope) in &frame.wants {
            let scope = scope_from_u8(*scope);
            if let Ok(Some((bytes, _))) = self.store.record_get(id, scope) {
                records.push(bytes);
            }
        }
        if records.is_empty() {
            return Vec::new();
        }
        vec![Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Records(RecordsFrame { records }),
        }]
    }

    fn on_records(&mut self, at: u64, records: Vec<Vec<u8>>) -> Vec<Action> {
        for bytes in records {
            self.admit_record(at, &bytes);
        }
        if self.neighbors_dirty {
            // graph rebuilt lazily at next routing decision; just note it
        }
        Vec::new()
    }

    /// Fold a record's (channel_key, id) claim into the claim set.
    fn note_ck_claim(&mut self, rec: &PeerRecord) {
        self.ck_claims
            .entry(rec.channel_key)
            .or_default()
            .insert(rec.id);
    }

    /// Recompute link attribution from the current claim sets.
    ///
    /// A link is attributed to an id only when exactly one id claims the
    /// link's channel key. Zero claims: unbound. More than one: contested —
    /// unbound, and our own record drops the link. Attribution comes only
    /// from signed records and can still be poisoned by forged claims, so
    /// this fails closed: misattribution is never published in our record.
    /// The cryptographic fix (attestation over the handshake) is tracked
    /// separately; until then, contested links are dead weight, not
    /// misrouted traffic.
    fn reevaluate_link_bindings(&mut self, at: u64) {
        let mut changed = false;
        for link in self.links.values_mut() {
            if link.pinned {
                continue;
            }
            let binding = match self.ck_claims.get(&link.remote_ck).map(|s| s.len()) {
                Some(1) => self
                    .ck_claims
                    .get(&link.remote_ck)
                    .and_then(|s| s.iter().next().copied()),
                // Contested or absent: no attribution.
                Some(_) => {
                    if link.peer.is_some() {
                        self.contested += 1;
                    }
                    None
                }
                None => link.peer, // no claims seen yet; keep existing (None) state
            };
            match (link.peer == binding, binding) {
                (true, _) => {}
                (false, Some(id)) => {
                    link.peer = Some(id);
                    changed = true;
                }
                (false, None) => {
                    link.peer = None;
                    changed = true;
                }
            }
        }
        if changed {
            self.own_seq += 1;
            let _ = self.publish_record(at);
            self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        }
    }
    fn admit_record(&mut self, at: u64, bytes: &[u8]) -> bool {
        let known = match PeerRecord::from_bytes(bytes, at, None) {
            Ok((rec, _)) => self
                .store
                .kel_head(&rec.id)
                .ok()
                .flatten()
                .map(|(seq, commitment, _)| (seq, commitment)),
            Err(_) => return false,
        };
        match PeerRecord::from_bytes(bytes, at, known) {
            Ok((rec, head)) => {
                let scope = rec.scope;
                let existing = self.store.record_get(&rec.id, scope).ok().flatten();
                if let Some((old_bytes, _)) = existing {
                    // Lower-hash wins at equal seq (equivocation rule);
                    // otherwise normal last-writer-wins by seq.
                    let old_seq = PeerRecord::from_bytes(&old_bytes, at, None)
                        .map(|(r, _)| r.seq)
                        .unwrap_or(0);
                    if rec.seq == old_seq && bytes != old_bytes.as_slice() {
                        self.equivocations += 1;
                    }
                    if compare_lww(bytes, rec.seq, &old_bytes, old_seq)
                        != std::cmp::Ordering::Greater
                    {
                        return false; // keep ours
                    }
                }
                let _ = self.store.record_put(&rec.id, scope, bytes, at);
                let known = self.store.kel_head(&rec.id).ok().flatten();
                if known.map(|(seq, _, _)| head.seq > seq).unwrap_or(true) {
                    let _ = self
                        .store
                        .kel_head_put(&rec.id, head.seq, head.commitment, at);
                }
                self.neighbors_dirty = true;
                self.note_ck_claim(&rec);
                self.reevaluate_link_bindings(at);
                true
            }
            Err(_) => false,
        }
    }
}

// ============================================================
// Messaging engine
// ============================================================

type BuildResult = (Vec<u8>, [u8; 32], Option<[u8; 32]>);

enum DispatchResult {
    Sent,
    NoRoute,
}

const CUSTODY_TIMEOUT_SECS: u64 = 30;
const BUF_CLASSES: usize = 16;

impl<S: Store> Node<S> {
    fn on_app_send(&mut self, send: AppSend) -> Vec<Action> {
        let now = self.now;
        let mid: [u8; 16] = send.mid_hint.unwrap_or_else(lattice_crypto::os_bytes::<16>);
        if self.lookup_record(&send.to).is_none() {
            return vec![Action::Status {
                mid,
                status: local::MSG_STATUS_FAILED,
                detail: Some(ERR_NO_RECORD),
            }];
        }

        let exp = send
            .exp
            .unwrap_or(now + self.config.default_message_horizon)
            .min(now + lattice_proto::MAX_MESSAGE_HORIZON);

        let envelope = Envelope {
            kind: KIND_MESSAGE,
            mid,
            from: self.own_id,
            fsvc: send.service.clone(),
            fmbx: send.fmbx.clone(),
            tsvc: send.tsvc.clone(),
            tmbx: send.tmbx.clone(),
            created: now,
            body: Some(send.body.clone()),
            reference: None,
            reason: None,
            sig: [0; 64],
        };

        let recipient_private = self.record_mode(&send.to) == Some(Mode::Private);
        let receipt_timeout = if recipient_private {
            self.config.receipt_timeout_private
        } else {
            self.config.receipt_timeout_public
        };

        let outbound = lattice_store::OutboundMessage {
            mid,
            recipient: send.to,
            envelope,
            priority: send.priority,
            exp,
            state: OutboundState::Queued,
            waypoints_tried: Vec::new(),
            receipt_deadline: Some(now + receipt_timeout),
            attempts: 0,
            next_attempt: now,
            route: send.route,
        };
        if self.store.outbound_push(&outbound).is_err() {
            return vec![Action::Status {
                mid,
                status: local::MSG_STATUS_FAILED,
                detail: Some(ERR_INTERNAL),
            }];
        }
        let mut actions = vec![Action::Status {
            mid,
            status: local::MSG_STATUS_QUEUED,
            detail: None,
        }];
        actions.extend(self.pump_outbound(now));
        actions
    }

    fn lookup_record(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        for scope in [Scope::Wan, Scope::Hive] {
            if let Ok(Some((bytes, _))) = self.store.record_get(id, scope) {
                return Some(bytes);
            }
        }
        None
    }

    fn record_mode(&self, id: &[u8; 32]) -> Option<Mode> {
        PeerRecord::from_bytes(&self.lookup_record(id)?, self.now, None)
            .ok()
            .map(|(r, _)| r.mode)
    }

    fn record_envelope_key(&self, id: &[u8; 32]) -> Option<[u8; 1216]> {
        PeerRecord::from_bytes(&self.lookup_record(id)?, self.now, None)
            .ok()
            .map(|(r, _)| r.envelope_key)
    }

    fn record_gateways(&self, id: &[u8; 32]) -> Vec<[u8; 32]> {
        self.lookup_record(id)
            .and_then(|b| PeerRecord::from_bytes(&b, self.now, None).ok())
            .map(|(r, _)| r.gateways)
            .unwrap_or_default()
    }

    /// Build a wire message for one attempt. Returns (bytes, routing destination, waypoint used).
    fn build_attempt(
        &mut self,
        msg: &lattice_store::OutboundMessage,
        force_waypoint: bool,
    ) -> Result<BuildResult, ()> {
        let recipient_private = self.record_mode(&msg.recipient) == Some(Mode::Private);
        let gateway_choice = if recipient_private {
            self.record_gateways(&msg.recipient)
                .into_iter()
                .find(|g| self.record_envelope_key(g).is_some())
        } else {
            None
        };
        if recipient_private && gateway_choice.is_none() {
            return Err(());
        }

        let want_waypoint = force_waypoint
            || match msg.route {
                1 => true,  // explicitly via waypoint
                2 => false, // explicitly direct
                _ => {
                    self.config.waypoint_share > 0.0 && self.rng.chance(self.config.waypoint_share)
                }
            };
        let waypoint_choice = if want_waypoint {
            self.pick_waypoint(&msg.recipient, &msg.waypoints_tried)
        } else {
            None
        };

        let recipient_ek = self.record_envelope_key(&msg.recipient).ok_or(())?;
        let real_dst = gateway_choice.unwrap_or(msg.recipient);
        let gateway = gateway_choice.map(|g| GatewaySeal {
            gateway_ek: self.record_envelope_key(&g).expect("checked above"),
            rcpt: msg.recipient,
        });
        let waypoint = waypoint_choice.map(|(id, ek)| WaypointSeal {
            waypoint_id: id,
            waypoint_ek: ek,
            leg: lattice_crypto::os_bytes::<16>(),
            exp: msg.exp,
        });
        let used_waypoint_id = waypoint.as_ref().map(|w| w.waypoint_id);
        let wire = Message::build(BuildParams {
            envelope: msg.envelope.clone(),
            sender_seed: &self.identity.signing_seed,
            recipient_ek: &recipient_ek,
            real_dst,
            leg: lattice_crypto::os_bytes::<16>(),
            exp: msg.exp,
            gateway,
            waypoint,
        })
        .map_err(|_| ())?;
        Ok((wire, real_dst, used_waypoint_id))
    }

    fn pick_waypoint(
        &mut self,
        recipient: &[u8; 32],
        exclude: &[[u8; 32]],
    ) -> Option<([u8; 32], [u8; 1216])> {
        let mut candidates: Vec<([u8; 32], [u8; 1216])> = self
            .store
            .record_all()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(id, _scope, bytes, _)| {
                if id == self.own_id || &id == recipient || exclude.contains(&id) {
                    return None;
                }
                let (rec, _) = PeerRecord::from_bytes(&bytes, self.now, None).ok()?;
                (rec.mode == Mode::Public).then_some((id, rec.envelope_key))
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let idx = (self.rng.next_u64() as usize) % candidates.len();
        Some(candidates.swap_remove(idx))
    }

    fn pump_outbound(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let due = match self.store.outbound_due(now) {
            Ok(d) => d,
            Err(_) => return actions,
        };
        for mut msg in due {
            if msg.state != OutboundState::Queued {
                continue;
            }
            let force_waypoint = msg.attempts > 0;
            match self.build_attempt(&msg, force_waypoint) {
                Ok((wire, _real_dst, used_wp)) => {
                    match self.dispatch_wire(now, &wire, &msg, &mut actions) {
                        DispatchResult::Sent => {
                            msg.attempts += 1;
                            if let Some(wp) = used_wp {
                                msg.waypoints_tried.push(wp);
                            }
                            msg.state = OutboundState::InFlight;
                            msg.next_attempt = now + self.config.retry_base_secs;
                            let _ = self.store.outbound_put(&msg);
                        }
                        DispatchResult::NoRoute => {
                            msg.attempts += 1;
                            msg.state = OutboundState::Queued;
                            msg.next_attempt = now + self.backoff(msg.attempts);
                            let _ = self.store.outbound_put(&msg);
                        }
                    }
                }
                Err(()) => {
                    msg.attempts += 1;
                    if msg.attempts > self.config.fresh_waypoint_retries + 1 {
                        msg.state = OutboundState::Failed;
                        let _ = self.store.outbound_put(&msg);
                        let _ = self.store.status_set(
                            &msg.mid,
                            local::MSG_STATUS_FAILED,
                            Some(ERR_NO_ROUTE),
                        );
                        actions.push(Action::Status {
                            mid: msg.mid,
                            status: local::MSG_STATUS_FAILED,
                            detail: Some(ERR_NO_ROUTE),
                        });
                    } else {
                        msg.next_attempt = now + self.config.retry_base_secs;
                        let _ = self.store.outbound_put(&msg);
                    }
                }
            }
        }
        actions
    }

    fn backoff(&self, attempts: u32) -> u64 {
        let shift = attempts.min(16);
        let base = self.config.retry_base_secs.saturating_mul(1u64 << shift);
        base.min(self.config.retry_max_secs)
    }

    fn note_frame_sent(&mut self, link: LinkId, action: Action, actions: &mut Vec<Action>) {
        let bucket = match &action {
            Action::SendFrame {
                pad_to: None,
                frame: Frame::Offer(o),
                ..
            } => {
                if o.message.len() <= 2048 {
                    0
                } else if o.message.len() <= 8192 {
                    1
                } else {
                    2
                }
            }
            Action::SendFrame {
                pad_to: None,
                frame: Frame::Records(r),
                ..
            } => {
                let n: usize = r.records.iter().map(|r| r.len()).sum();
                if n <= 2048 {
                    0
                } else if n <= 8192 {
                    1
                } else {
                    2
                }
            }
            _ => 0,
        };
        self.store.size_bucket_sample(bucket);
        self.frames_since_snow_tick += 1;
        actions.push(action);
        let _ = link;
    }

    fn pick_next_hop(
        &mut self,
        dst: &[u8; 32],
        exclude: &[(LinkId, u64)],
        now: u64,
    ) -> Option<(LinkId, [u8; 32])> {
        // Distances are measured from the destination; the graph is undirected,
        // so BFS from dst gives each node's distance to the destination.
        let graph = self.build_graph();
        let dist = graph.distances(dst);
        let excluded_peers: HashSet<[u8; 32]> = exclude
            .iter()
            .filter(|(_, until)| *until > now)
            .filter_map(|(l, _)| self.links.get(l).and_then(|s| s.peer))
            .collect();
        let up: HashSet<[u8; 32]> = self.links.values().filter_map(|l| l.peer).collect();
        let mut excluded = excluded_peers;
        for _ in 0..self.links.len().max(1) + 1 {
            match graph.next_hop(
                &self.own_id,
                &dist,
                self.config.sideways_prob,
                &excluded,
                &mut self.rng,
            ) {
                Some(peer) if up.contains(&peer) => {
                    let link = self
                        .links
                        .iter()
                        .find(|(_, l)| l.peer == Some(peer))
                        .map(|(id, _)| *id)?;
                    return Some((link, peer));
                }
                Some(peer) => {
                    excluded.insert(peer);
                }
                None => break,
            }
        }
        None
    }

    fn dispatch_wire(
        &mut self,
        now: u64,
        wire: &[u8],
        msg: &lattice_store::OutboundMessage,
        actions: &mut Vec<Action>,
    ) -> DispatchResult {
        let parsed = match Message::parse(wire, now) {
            Ok(m) => m,
            Err(_) => return DispatchResult::NoRoute,
        };
        let dst = parsed.header.dst;
        let leg = parsed.header.leg;
        let exclusion = self.outbound_exclusions.entry(msg.mid).or_default();
        exclusion.retain(|(_, until)| *until > now);
        let exclusion = exclusion.clone();
        let Some((link, _peer)) = self.pick_next_hop(&dst, &exclusion, now) else {
            return DispatchResult::NoRoute;
        };
        self.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Outbound { mid: msg.mid },
                sent_at: now,
                excluded: exclusion,
            },
        );
        self.note_frame_sent(
            link,
            Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Offer(OfferFrame {
                    message: wire.to_vec(),
                }),
            },
            actions,
        );
        DispatchResult::Sent
    }
}

// ──────────── inbound custody offers ────────────

impl<S: Store> Node<S> {
    fn on_offer(&mut self, now: u64, link: LinkId, offer: &OfferFrame) -> Vec<Action> {
        let mut actions = Vec::new();
        let msg = match Message::parse(&offer.message, now) {
            Ok(m) => m,
            Err(_) => return actions, // undecodable: no leg to answer to; drop
        };
        let leg = msg.header.leg;
        if self.draining {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let leg_hash = lattice_crypto::hash(&leg);
        if self.store.seen_contains(&leg_hash, now).unwrap_or(false) {
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Custody(CustodyFrame {
                    leg,
                    result: CUSTODY_ALREADY_HAVE,
                    retry_after: None,
                }),
            });
            return actions;
        }
        let dst = msg.header.dst;
        let msg_len = offer.message.len() as u64;

        if dst == self.own_id {
            return self.on_offer_for_us(now, link, &msg, &offer.message, &leg_hash, actions);
        }

        // Relay path: buffer class (forwarding priority / wait order), fair
        // share per destination upstream, transit cap.
        let dist = {
            let g = self.build_graph();
            let d = g.distances(&self.own_id);
            d.get(&dst).copied().unwrap_or(u32::MAX) as usize
        };
        let class = dist.min(BUF_CLASSES - 1) as u8;
        let upstream_count = self.links.len().max(1) as u64;
        let share_limit = self.config.custody_allowance / upstream_count;
        if self.store.share_get(&dst, link).unwrap_or(0) + msg_len > share_limit {
            actions.push(self.busy(link, leg));
            return actions;
        }
        if self.store.custody_bytes().unwrap_or(0) + msg_len > self.config.transit_cap {
            actions.push(self.busy(link, leg));
            return actions;
        }

        let entry = CustodyEntry {
            leg,
            message: offer.message.clone(),
            upstream: link,
            destination: dst,
            class,
            exp: msg.header.exp,
            lease_until: now + CUSTODY_TIMEOUT_SECS,
            excluded: Vec::new(),
        };
        if self.store.custody_put(entry).is_err() {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let _ = self.store.share_add(&dst, link, msg_len as i64);
        let _ = self.store.seen_add(leg_hash, msg.header.exp);
        actions.push(Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_ACCEPTED,
                retry_after: None,
            }),
        });
        self.forward_custody(now, leg, &mut actions);
        actions
    }

    fn busy(&self, link: LinkId, leg: [u8; 16]) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_BUSY,
                retry_after: Some(self.config.retry_base_secs),
            }),
        }
    }

    fn on_offer_for_us(
        &mut self,
        now: u64,
        link: LinkId,
        msg: &Message,
        raw: &[u8],
        leg_hash: &[u8; 32],
        mut actions: Vec<Action>,
    ) -> Vec<Action> {
        let leg = msg.header.leg;

        if msg.hop_layer.is_some() {
            match msg.open_hop_layer(&self.identity.xwing_secret) {
                Ok(HopLayerPlain::Waypoint { hdr, inner }) => {
                    let hdr_dst = hdr.dst;
                    let hdr_exp = hdr.exp;
                    let inner = match msg
                        .clone()
                        .into_after_waypoint(HopLayerPlain::Waypoint { hdr, inner })
                    {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            actions.push(self.refuse(link, leg));
                            return actions;
                        }
                    };
                    // A waypoint accepts the first leg only if it can hold the
                    // second leg: fair-share + transit cap apply, same as relay.
                    let msg_len = inner.len() as u64;
                    let class = self.class_for(hdr_dst);
                    let upstream_count = self.links.len().max(1) as u64;
                    let share_limit = self.config.custody_allowance / upstream_count;
                    if self.store.share_get(&hdr_dst, link).unwrap_or(0) + msg_len > share_limit {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    if self.store.custody_bytes().unwrap_or(0) + msg_len > self.config.transit_cap {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    let entry = CustodyEntry {
                        leg,
                        message: inner,
                        upstream: link,
                        destination: hdr_dst,
                        class,
                        exp: hdr_exp,
                        lease_until: now + CUSTODY_TIMEOUT_SECS,
                        excluded: Vec::new(),
                    };
                    if self.store.custody_put(entry).is_err() {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    let _ = self.store.share_add(&hdr_dst, link, msg_len as i64);
                    let _ = self.store.seen_add(*leg_hash, hdr_exp);
                    actions.push(Action::SendFrame {
                        pad_to: None,
                        link,
                        frame: Frame::Custody(CustodyFrame {
                            leg,
                            result: CUSTODY_ACCEPTED,
                            retry_after: None,
                        }),
                    });
                    self.forward_custody(now, leg, &mut actions);
                    return actions;
                }
                Ok(HopLayerPlain::Gateway { rcpt }) => {
                    let msg_len = raw.len() as u64;
                    let class = self.class_for(rcpt);
                    let upstream_count = self.links.len().max(1) as u64;
                    let share_limit = self.config.custody_allowance / upstream_count;
                    if self.store.share_get(&rcpt, link).unwrap_or(0) + msg_len > share_limit {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    if self.store.custody_bytes().unwrap_or(0) + msg_len > self.config.transit_cap {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    let entry = CustodyEntry {
                        leg,
                        message: raw.to_vec(),
                        upstream: link,
                        destination: rcpt,
                        class,
                        exp: msg.header.exp,
                        lease_until: now + CUSTODY_TIMEOUT_SECS,
                        excluded: Vec::new(),
                    };
                    if self.store.custody_put(entry).is_err() {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    let _ = self.store.share_add(&rcpt, link, msg_len as i64);
                    let _ = self.store.seen_add(*leg_hash, msg.header.exp);
                    actions.push(Action::SendFrame {
                        pad_to: None,
                        link,
                        frame: Frame::Custody(CustodyFrame {
                            leg,
                            result: CUSTODY_ACCEPTED,
                            retry_after: None,
                        }),
                    });
                    self.forward_custody(now, leg, &mut actions);
                    return actions;
                }
                Err(_) => {
                    actions.push(Action::SendFrame {
                        pad_to: None,
                        link,
                        frame: Frame::Custody(CustodyFrame {
                            leg,
                            result: CUSTODY_REFUSED,
                            retry_after: None,
                        }),
                    });
                    return actions;
                }
            }
        }

        // Final recipient: open the envelope now (cheap; rejects garbage early),
        // then authenticate the sender before spending any state on the message.
        let opened = match msg.open_envelope(&self.identity.xwing_secret) {
            Ok(e) => e,
            Err(_) => {
                actions.push(self.refuse(link, leg));
                return actions;
            }
        };
        match self.signing_key_for(&opened.from) {
            Some(key) => {
                if !opened.verify_signature(&key, msg.routing_header_bytes()) {
                    // Well-formed envelope, bad signature: refuse, and tell the
                    // sender if we can authenticate them at all.
                    let _ = self.store.seen_add(*leg_hash, msg.header.exp);
                    actions.push(self.refuse(link, leg));
                    actions.extend(self.send_negative_receipt(
                        now,
                        opened.from,
                        &opened,
                        lattice_proto::message::REASON_INVALID,
                        &opened.fsvc.clone(),
                    ));
                    return actions;
                }
            }
            None => {
                // No record for the sender; cannot verify. Ask for it via the
                // normal path by refusing softly (busy): the sender retries
                // after gossip delivers the record.
                actions.push(self.busy(link, leg));
                return actions;
            }
        }
        if opened.kind == KIND_RECEIPT || opened.kind == KIND_NEGATIVE_RECEIPT {
            // Receipts get custody-acknowledged but never receipt-replied (no ping-pong).
            let _ = self.store.seen_add(*leg_hash, msg.header.exp);
            actions.extend(self.on_receipt(now, &opened));
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Custody(CustodyFrame {
                    leg,
                    result: CUSTODY_ACCEPTED,
                    retry_after: None,
                }),
            });
            return actions;
        }
        let mid_bytes = opened.mid;
        let mid_hash = lattice_crypto::hash(&mid_bytes);
        if self
            .store
            .delivered_contains(&mid_hash, now)
            .unwrap_or(false)
        {
            let _ = self.store.seen_add(*leg_hash, msg.header.exp);
            actions.extend(self.send_receipt(now, &opened));
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Custody(CustodyFrame {
                    leg,
                    result: CUSTODY_ALREADY_HAVE,
                    retry_after: None,
                }),
            });
            return actions;
        }
        let inbox_len = self.store.inbox_len(&opened.tsvc).unwrap_or(0);
        if inbox_len >= self.config.inbox_max_deliveries {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let entry = InboxEntry {
            delivery_id: lattice_crypto::os_bytes::<16>(),
            mid: mid_bytes,
            from: opened.from,
            fsvc: opened.fsvc.clone(),
            fmbx: opened.fmbx.clone(),
            tsvc: opened.tsvc.clone(),
            tmbx: opened.tmbx.clone(),
            body: opened.body.clone().unwrap_or_default(),
            received: now,
        };
        if self.store.inbox_push(&opened.tsvc, entry.clone()).is_err() {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let _ = self.store.delivered_add(mid_hash, msg.header.exp);
        let _ = self.store.seen_add(*leg_hash, msg.header.exp);
        actions.push(Action::Deliver {
            service: opened.tsvc.clone(),
            delivery_id: entry.delivery_id,
            mid: mid_bytes,
            from: opened.from,
            fsvc: opened.fsvc.clone(),
            fmbx: opened.fmbx.clone(),
            tmbx: opened.tmbx.clone(),
            body: opened.body.clone().unwrap_or_default(),
            received: now,
        });
        let unread = self.store.inbox_len(&opened.tsvc).unwrap_or(0);
        actions.push(Action::Inbox {
            service: opened.tsvc.clone(),
            unread,
        });
        actions.push(Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_ACCEPTED,
                retry_after: None,
            }),
        });
        actions.extend(self.send_receipt(now, &opened));
        actions
    }

    fn refuse(&self, link: LinkId, leg: [u8; 16]) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_REFUSED,
                retry_after: None,
            }),
        }
    }

    fn signing_key_for(&self, id: &[u8; 32]) -> Option<[u8; 32]> {
        for scope in [Scope::Wan, Scope::Hive] {
            if let Ok(Some((bytes, _))) = self.store.record_get(id, scope) {
                if let Ok((rec, _)) = PeerRecord::from_bytes(&bytes, self.now, None) {
                    return Some(rec.current_signing_key());
                }
            }
        }
        None
    }

    fn class_for(&self, dst: [u8; 32]) -> u8 {
        let g = self.build_graph();
        let d = g.distances(&self.own_id);
        d.get(&dst)
            .copied()
            .unwrap_or(u32::MAX)
            .min((BUF_CLASSES - 1) as u32) as u8
    }

    fn forward_custody(&mut self, now: u64, leg: [u8; 16], actions: &mut Vec<Action>) {
        let entry = match self.store.custody_get(&leg) {
            Ok(Some(e)) => e,
            _ => return,
        };
        if entry.exp <= now {
            let _ = self.store.custody_remove(&leg);
            let _ = self.store.share_add(
                &entry.destination,
                entry.upstream,
                -(entry.message.len() as i64),
            );
            return;
        }
        let dst = entry.destination;
        // The offer we send may carry a *different* leg than the custody key
        // (waypoint re-origination): key `pending` by the leg on the wire.
        let offer_leg = lattice_proto::Message::parse(&entry.message, now)
            .map(|m| m.header.leg)
            .unwrap_or(entry.leg);
        let excluded: Vec<(LinkId, u64)> = entry
            .excluded
            .iter()
            .filter(|(_, until)| *until > now)
            .cloned()
            .collect();
        let Some((next_link, _peer)) = self.pick_next_hop(&dst, &excluded, now) else {
            return; // no route right now; retried on tick
        };
        self.pending.insert(
            offer_leg,
            PendingOffer {
                origin: PendingOrigin::Relay {
                    custody_leg: entry.leg,
                },
                sent_at: now,
                excluded,
            },
        );
        self.note_frame_sent(
            next_link,
            Action::SendFrame {
                pad_to: None,
                link: next_link,
                frame: Frame::Offer(OfferFrame {
                    message: entry.message.clone(),
                }),
            },
            actions,
        );
    }
}

// ──────────── custody replies & receipts ────────────

impl<S: Store> Node<S> {
    fn on_custody_reply(&mut self, now: u64, link: LinkId, frame: &CustodyFrame) -> Vec<Action> {
        let mut actions = Vec::new();
        let leg = frame.leg;
        let pending = self.pending.remove(&leg);
        match frame.result {
            CUSTODY_ACCEPTED => match pending.as_ref().map(|p| &p.origin) {
                Some(PendingOrigin::Outbound { mid }) => {
                    if let Ok(Some(mut msg)) = self.store.outbound_get(mid) {
                        msg.state = OutboundState::InFlight;
                        let _ = self.store.outbound_put(&msg);
                    }
                    let _ = self
                        .store
                        .status_set(mid, local::MSG_STATUS_IN_TRANSIT, None);
                    actions.push(Action::Status {
                        mid: *mid,
                        status: local::MSG_STATUS_IN_TRANSIT,
                        detail: None,
                    });
                }
                Some(PendingOrigin::Relay { custody_leg }) => {
                    if let Ok(Some(e)) = self.store.custody_remove(custody_leg) {
                        let _ = self.store.share_add(
                            &e.destination,
                            e.upstream,
                            -(e.message.len() as i64),
                        );
                    }
                }
                None => {}
            },
            CUSTODY_ALREADY_HAVE | CUSTODY_BUSY => {
                let busy = frame.result == CUSTODY_BUSY;
                let retry = frame
                    .retry_after
                    .unwrap_or(self.config.retry_base_secs)
                    .clamp(1, 3600);
                if let Some(p) = pending {
                    match p.origin {
                        PendingOrigin::Outbound { mid } => {
                            if let Ok(Some(mut msg)) = self.store.outbound_get(&mid) {
                                let until = if busy { now + retry } else { msg.exp };
                                add_exclusion(
                                    self.outbound_exclusions.entry(mid).or_default(),
                                    link,
                                    until,
                                );
                                msg.state = OutboundState::Queued;
                                msg.next_attempt = now + if busy { retry } else { 0 };
                                let _ = self.store.outbound_put(&msg);
                            }
                            // Immediate retry against a different neighbor, if one exists now.
                            if !busy {
                                actions.extend(self.pump_outbound(now));
                            }
                        }
                        PendingOrigin::Relay { custody_leg } => {
                            if busy {
                                if let Ok(Some(mut e)) = self.store.custody_get(&custody_leg) {
                                    add_exclusion(&mut e.excluded, link, now + retry);
                                    let _ = self.store.custody_put(e);
                                }
                                self.forward_custody(now, custody_leg, &mut actions);
                            } else {
                                // The downstream already holds it: drop ours and release the share.
                                if let Ok(Some(done)) = self.store.custody_remove(&custody_leg) {
                                    let _ = self.store.share_add(
                                        &done.destination,
                                        done.upstream,
                                        -(done.message.len() as i64),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            CUSTODY_REFUSED => {
                if let Some(p) = pending {
                    match p.origin {
                        PendingOrigin::Outbound { mid } => {
                            if let Ok(Some(mut msg)) = self.store.outbound_get(&mid) {
                                msg.state = OutboundState::Failed;
                                self.outbound_exclusions.remove(&msg.mid);
                                let _ = self.store.outbound_put(&msg);
                            }
                            let _ = self.store.status_set(
                                &mid,
                                local::MSG_STATUS_FAILED,
                                Some(ERR_REFUSED),
                            );
                            actions.push(Action::Status {
                                mid,
                                status: local::MSG_STATUS_FAILED,
                                detail: Some(ERR_REFUSED),
                            });
                        }
                        PendingOrigin::Relay { custody_leg } => {
                            if let Ok(Some(e)) = self.store.custody_remove(&custody_leg) {
                                let _ = self.store.share_add(
                                    &e.destination,
                                    e.upstream,
                                    -(e.message.len() as i64),
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        actions
    }

    fn on_receipt(&mut self, now: u64, envelope: &Envelope) -> Vec<Action> {
        let mut actions = Vec::new();
        let Some(reference) = envelope.reference else {
            return actions;
        };
        match envelope.kind {
            KIND_RECEIPT => {
                if let Ok(Some(mut msg)) = self.store.outbound_get(&reference) {
                    if matches!(msg.state, OutboundState::Queued | OutboundState::InFlight) {
                        msg.state = OutboundState::Delivered;
                        let _ = self.store.outbound_put(&msg);
                    }
                }
                let _ = self
                    .store
                    .status_set(&reference, local::MSG_STATUS_DELIVERED, None);
                self.outbound_exclusions.remove(&reference);
                actions.push(Action::Status {
                    mid: reference,
                    status: local::MSG_STATUS_DELIVERED,
                    detail: None,
                });
            }
            KIND_NEGATIVE_RECEIPT => {
                if let Ok(Some(mut msg)) = self.store.outbound_get(&reference) {
                    msg.state = OutboundState::Failed;
                    let _ = self.store.outbound_put(&msg);
                }
                let _ =
                    self.store
                        .status_set(&reference, local::MSG_STATUS_FAILED, envelope.reason);
                actions.push(Action::Status {
                    mid: reference,
                    status: local::MSG_STATUS_FAILED,
                    detail: envelope.reason,
                });
            }
            _ => {}
        }
        let _ = now;
        actions
    }

    fn send_receipt(&mut self, now: u64, delivered: &Envelope) -> Vec<Action> {
        let envelope = Envelope {
            kind: KIND_RECEIPT,
            mid: lattice_crypto::os_bytes::<16>(),
            from: self.own_id,
            fsvc: delivered.tsvc.clone(),
            fmbx: delivered.tmbx.clone(),
            tsvc: delivered.fsvc.clone(),
            tmbx: delivered.fmbx.clone(),
            created: now,
            body: None,
            reference: Some(delivered.mid),
            reason: None,
            sig: [0; 64],
        };
        self.enqueue_control(now, delivered.from, envelope)
    }

    #[allow(dead_code)]
    fn send_negative_receipt(
        &mut self,
        now: u64,
        original_from: [u8; 32],
        original: &Envelope,
        reason: u64,
        my_service: &str,
    ) -> Vec<Action> {
        let envelope = Envelope {
            kind: KIND_NEGATIVE_RECEIPT,
            mid: lattice_crypto::os_bytes::<16>(),
            from: self.own_id,
            fsvc: my_service.to_string(),
            fmbx: Vec::new(),
            tsvc: original.fsvc.clone(),
            tmbx: original.fmbx.clone(),
            created: now,
            body: None,
            reference: Some(original.mid),
            reason: Some(reason),
            sig: [0; 64],
        };
        self.enqueue_control(now, original_from, envelope)
    }

    fn enqueue_control(
        &mut self,
        now: u64,
        recipient: [u8; 32],
        envelope: Envelope,
    ) -> Vec<Action> {
        let mid = envelope.mid;
        let outbound = lattice_store::OutboundMessage {
            mid,
            recipient,
            envelope,
            priority: 3,
            exp: now + self.config.default_message_horizon,
            state: OutboundState::Queued,
            waypoints_tried: Vec::new(),
            receipt_deadline: None,
            attempts: 0,
            next_attempt: now,
            route: 0,
        };
        if self.store.outbound_push(&outbound).is_err() {
            return Vec::new();
        }
        self.pump_outbound(now)
    }
}

// ──────────── tick, snow, frame dispatch, app ack ────────────

impl<S: Store> Node<S> {
    fn on_tick(&mut self, now: u64) -> Vec<Action> {
        self.now = now;
        let mut actions = Vec::new();

        // Snow first: never crowd out real work in the same tick.
        actions.extend(self.snow_tick(now));

        if now >= self.next_reconcile_at {
            if let Some(link) = self.random_link() {
                actions.extend(self.reconcile_with(now, link));
            }
            self.next_reconcile_at = now + self.config.reconcile_interval_secs;
        }

        if self.neighbors_dirty && now >= self.record_refresh_at {
            self.own_seq += 1;
            let _ = self.publish_record(now);
            self.record_refresh_at = now + self.config.record_refresh_secs;
            self.neighbors_dirty = false;
        }

        // Expire originated messages.
        if let Ok(all) = self.store.outbound_all() {
            for mut msg in all {
                if matches!(msg.state, OutboundState::Queued | OutboundState::InFlight)
                    && msg.exp <= now
                {
                    msg.state = OutboundState::Expired;
                    let _ = self.store.outbound_put(&msg);
                    let _ = self.store.status_set(
                        &msg.mid,
                        local::MSG_STATUS_EXPIRED,
                        Some(ERR_EXPIRED),
                    );
                    actions.push(Action::Status {
                        mid: msg.mid,
                        status: local::MSG_STATUS_EXPIRED,
                        detail: Some(ERR_EXPIRED),
                    });
                }
            }
        }

        // Receipt deadlines: retry via a fresh waypoint, else fail.
        if let Ok(all) = self.store.outbound_all() {
            for mut msg in all {
                if msg.state != OutboundState::InFlight {
                    continue;
                }
                let Some(deadline) = msg.receipt_deadline else {
                    continue;
                };
                if now < deadline {
                    continue;
                }
                msg.attempts += 1;
                if msg.attempts > self.config.fresh_waypoint_retries {
                    msg.state = OutboundState::Failed;
                    let _ = self.store.outbound_put(&msg);
                    let _ = self.store.status_set(
                        &msg.mid,
                        local::MSG_STATUS_FAILED,
                        Some(ERR_NO_ROUTE),
                    );
                    actions.push(Action::Status {
                        mid: msg.mid,
                        status: local::MSG_STATUS_FAILED,
                        detail: Some(ERR_NO_ROUTE),
                    });
                } else {
                    msg.state = OutboundState::Queued;
                    msg.next_attempt = now;
                    let recipient_private = self.record_mode(&msg.recipient) == Some(Mode::Private);
                    let timeout = if recipient_private {
                        self.config.receipt_timeout_private
                    } else {
                        self.config.receipt_timeout_public
                    };
                    msg.receipt_deadline = Some(now + timeout);
                    let _ = self.store.outbound_put(&msg);
                }
            }
        }

        // Custody offers that never got an answer: exclude the link and retry.
        let stale: Vec<[u8; 16]> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.sent_at) > CUSTODY_TIMEOUT_SECS)
            .map(|(leg, _)| *leg)
            .collect();
        for leg in stale {
            if let Some(p) = self.pending.remove(&leg) {
                match p.origin {
                    PendingOrigin::Outbound { mid } => {
                        for (l, u) in p.excluded {
                            add_exclusion(self.outbound_exclusions.entry(mid).or_default(), l, u);
                        }
                        if let Ok(Some(mut msg)) = self.store.outbound_get(&mid) {
                            if msg.state == OutboundState::InFlight {
                                msg.state = OutboundState::Queued;
                                msg.next_attempt = now + self.config.retry_base_secs;
                                let _ = self.store.outbound_put(&msg);
                            }
                        }
                    }
                    PendingOrigin::Relay { custody_leg } => {
                        if let Ok(Some(mut e)) = self.store.custody_get(&custody_leg) {
                            for (l, u) in p.excluded {
                                add_exclusion(&mut e.excluded, l, u);
                            }
                            let _ = self.store.custody_put(e);
                        }
                        self.forward_custody(now, custody_leg, &mut actions);
                    }
                }
            }
        }

        // Custody entries with nothing in flight get a forwarding attempt.
        if let Ok(all) = self.store.custody_all() {
            for entry in all {
                let offer_leg = lattice_proto::Message::parse(&entry.message, now)
                    .map(|m| m.header.leg)
                    .unwrap_or(entry.leg);
                let in_flight = self.pending.contains_key(&offer_leg);
                if !in_flight {
                    self.forward_custody(now, entry.leg, &mut actions);
                }
            }
        }

        // Expire custody entries whose messages timed out.
        if let Ok(all) = self.store.custody_all() {
            for entry in all {
                if entry.exp <= now {
                    if let Ok(Some(e)) = self.store.custody_remove(&entry.leg) {
                        let _ = self.store.share_add(
                            &e.destination,
                            e.upstream,
                            -(e.message.len() as i64),
                        );
                    }
                }
            }
        }

        let _ = self.store.sweep_expired(now);
        actions.extend(self.pump_outbound(now));
        actions
    }

    /// Build a dummy whose padded size lands in the given bucket class
    /// (0=2K, 1=8K, 2=32K). Sizes approximate frame overhead.
    fn dummy_frame(echo: bool) -> Frame {
        // Bucket selection happens at the transport: the frame is padded
        // into the sampled bucket via `Action::SendFrame::pad_to`.
        Frame::Dummy(DummyFrame { echo })
    }

    fn random_link(&mut self) -> Option<LinkId> {
        let links: Vec<LinkId> = self.next_link_order.to_vec();
        if links.is_empty() {
            return None;
        }
        Some(links[self.rng.below(links.len() as u64) as usize])
    }

    fn snow_tick(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let due: Vec<(u64, LinkId)> = self
            .inner_pending_echo
            .iter()
            .filter(|(t, _)| *t <= now)
            .cloned()
            .collect();
        self.inner_pending_echo.retain(|(t, _)| *t > now);
        for (_, link) in due {
            if self.links.contains_key(&link) {
                let bucket = self.sample_snow_bucket();
                actions.push(Action::SendFrame {
                    pad_to: Some(bucket),
                    link,
                    frame: Self::dummy_frame(false),
                });
                self.note_snow_send(bucket);
            }
        }

        if now < self.snow_next {
            return actions;
        }
        let interval = if self.config.snow_per_min > 0.0 {
            (self.rng.expovariate(self.config.snow_per_min / 60.0)).max(0.001) as u64
        } else {
            u64::MAX / 2
        };
        self.snow_next = now + interval.max(1);

        if self.frames_since_snow_tick > 0 {
            self.frames_since_snow_tick = 0;
            return actions;
        }
        if let Some(link) = self.random_link() {
            self.frames_since_snow_tick = 0;
            let echo = self.rng.chance(self.config.echo_share);
            let b = self.sample_snow_bucket();
            actions.push(Action::SendFrame {
                pad_to: Some(b),
                link,
                frame: Self::dummy_frame(echo),
            });
            self.note_snow_send(b);
        }
        actions
    }

    fn note_snow_send(&mut self, bucket: usize) {
        self.snow_history[bucket.min(2)] += 1;
        self.store.size_bucket_sample(bucket.min(2) as u8);
    }

    fn sample_snow_bucket(&mut self) -> usize {
        let counts = self.store.size_bucket_counts();
        let min_share = 0.10f64;
        let total: f64 = counts.iter().map(|&c| c as f64).sum();
        let mut weights = [0.0f64; 3];
        for b in 0..3 {
            let base = if total > 0.0 {
                counts[b] as f64 / total
            } else {
                1.0 / 3.0
            };
            weights[b] = base.max(min_share);
        }
        let sum: f64 = weights.iter().sum();
        let mut r = self.rng_float() * sum;
        for (i, w) in weights.iter().enumerate() {
            if r < *w {
                return i;
            }
            r -= w;
        }
        2
    }

    fn rng_float(&mut self) -> f64 {
        self.rng.next_u64() as f64 / u64::MAX as f64
    }

    fn on_frame(&mut self, at: u64, link: LinkId, from: [u8; 32], frame: Frame) -> Vec<Action> {
        self.now = at;
        let _ = from;
        match frame {
            Frame::Offer(offer) => self.on_offer(at, link, &offer),
            Frame::Custody(custody) => self.on_custody_reply(at, link, &custody),
            Frame::Reconcile(rec) => self.on_reconcile(at, link, &rec),
            Frame::Want(want) => self.on_want(link, &want),
            Frame::Records(recs) => self.on_records(at, recs.records),
            Frame::Ping(p) => vec![Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Ping(PingFrame { nonce: p.nonce }),
            }],
            Frame::Dummy(d) => {
                if d.echo {
                    let jitter = (self.rng.next_u64() % 900) + 50;
                    self.inner_pending_echo.push((at + jitter, link));
                }
                Vec::new()
            }
            Frame::Wary(w) => self.on_wary(at, &w),
            Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => Vec::new(),
        }
    }

    fn on_wary(&mut self, now: u64, w: &WaryFrame) -> Vec<Action> {
        for id in &w.ids {
            let _ = self.store.wary_add(id, 0, w.exp);
        }
        let _ = now;
        Vec::new()
    }

    /// Split into identity and store, for crash/restart simulation.
    pub fn into_parts(self) -> (Identity, S) {
        (self.identity, self.store)
    }

    /// Rebuild from parts after a simulated crash. The store holds the
    /// pre-crash custody state; the node re-announces nothing and simply
    /// resumes (it holds its own record already).
    pub fn restore(config: Config, identity: Identity, store: S, now: u64) -> Result<Self, String> {
        Self::new(config, identity, store, now)
    }

    /// Enter or leave draining: while draining, every custody offer is
    /// answered `busy` and nothing new starts. Existing custody is finished
    /// and reported via custody count.
    pub fn set_draining(&mut self, draining: bool) {
        self.draining = draining;
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    /// Bytes currently held in custody (for drain reporting).
    pub fn custody_bytes(&self) -> u64 {
        self.store.custody_bytes().unwrap_or(0)
    }

    /// Is there currently a path to `dst` over the known record graph?
    pub fn has_path(&mut self, dst: &[u8; 32]) -> bool {
        let g = self.build_graph();
        g.distances(&self.own_id).contains_key(dst)
    }

    pub fn uptime_links(&self) -> usize {
        self.links.len()
    }

    #[doc(hidden)]
    pub fn debug_equivocations(&self) -> u64 {
        self.equivocations
    }

    #[doc(hidden)]
    pub fn debug_contested(&self) -> u64 {
        self.contested
    }

    /// Test/diagnostic accessors (not part of the daemon API).
    #[doc(hidden)]
    pub fn debug_custody_count(&self) -> usize {
        self.store.custody_all().map(|v| v.len()).unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn debug_custody_upstreams(&self) -> Vec<u64> {
        self.store
            .custody_all()
            .map(|v| v.into_iter().map(|e| e.upstream).collect())
            .unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn debug_custody_destinations(&self) -> Vec<[u8; 32]> {
        self.store
            .custody_all()
            .map(|v| v.into_iter().map(|e| e.destination).collect())
            .unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn debug_record_count(&self) -> usize {
        self.store.record_count().unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn debug_record_ids(&self) -> Vec<[u8; 32]> {
        self.store
            .record_all()
            .unwrap_or_default()
            .into_iter()
            .map(|(id, _, _, _)| id)
            .collect()
    }

    #[doc(hidden)]
    pub fn debug_inbox_len(&self, service: &str) -> u64 {
        self.store.inbox_len(service).unwrap_or(0)
    }

    #[doc(hidden)]
    pub fn store_ref(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// (have record, mode as 0=public/1=private)
    pub fn lookup(&self, id: &[u8; 32]) -> (bool, Option<u64>) {
        for scope in [
            lattice_proto::record::Scope::Wan,
            lattice_proto::record::Scope::Hive,
        ] {
            if let Ok(Some((bytes, _))) = self.store.record_get(id, scope) {
                let mode = lattice_proto::record::PeerRecord::from_bytes(&bytes, self.now, None)
                    .map(|(r, _)| match r.mode {
                        lattice_proto::record::Mode::Public => 0,
                        lattice_proto::record::Mode::Private => 1,
                    })
                    .ok();
                return (true, mode);
            }
        }
        (false, None)
    }

    fn on_app_ack(&mut self, now: u64, service: &str, delivery_ids: &[[u8; 16]]) -> Vec<Action> {
        let _ = now;
        let _ = self.store.inbox_ack(service, delivery_ids);
        let unread = self.store.inbox_len(service).unwrap_or(0);
        vec![Action::Inbox {
            service: service.to_string(),
            unread,
        }]
    }
}

const ERR_NO_RECORD: u64 = crate::types::ERR_NO_RECORD;
const ERR_NO_ROUTE: u64 = crate::types::ERR_NO_ROUTE;
const ERR_INTERNAL: u64 = crate::types::ERR_INTERNAL;
const ERR_REFUSED: u64 = crate::types::ERR_REFUSED;
const ERR_EXPIRED: u64 = crate::types::ERR_EXPIRED;

/// Insert or merge an exclusion: (link, not_before). Existing entries keep
/// the later expiry.
fn add_exclusion(list: &mut Vec<(u64, u64)>, link: u64, until: u64) {
    match list.iter_mut().find(|(l, _)| *l == link) {
        Some(existing) => existing.1 = existing.1.max(until),
        None => list.push((link, until)),
    }
}

fn scope_as_u8(s: Scope) -> u8 {
    match s {
        Scope::Wan => 0,
        Scope::Hive => 1,
    }
}

fn scope_from_u8(v: u8) -> Scope {
    if v == 1 { Scope::Hive } else { Scope::Wan }
}
