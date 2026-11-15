//! The sans-IO node state machine. Events in, actions out; all time,
//! randomness and persistence are injected.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lattice_proto::frames::*;
use lattice_proto::kel::{KeyEvent, ValidatedKel};
use lattice_proto::local;
use lattice_proto::message::{
    BuildParams, Envelope, GatewaySeal, HopLayerPlain, KIND_MESSAGE, KIND_NEGATIVE_RECEIPT,
    KIND_RECEIPT, Message, WaypointSeal,
};
use lattice_proto::record::{Mode, PeerRecord, Scope, compare_lww};
use lattice_store::{CustodyAccept, CustodyEntry, InboxEntry, OutboundState, Store};

use lattice_types::{
    ChannelPublicKey, ChannelSeed, Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId,
    Signature, SigningPublicKey, SigningSeed, X25519PublicKey, XWingPublicKey, XWingSecretKey,
};

use crate::error::NodeError;
use crate::graph::Graph;
use crate::reconcile::{self, ReconcileSession};
use crate::rng::Rng;
use crate::types::*;

pub struct Identity {
    pub signing_seed: SigningSeed,
    /// The validated key event log. Validated at construction; rotation
    /// re-validates on every append.
    pub kel: ValidatedKel,
    pub channel_seed: ChannelSeed,
    pub xwing_secret: XWingSecretKey,
    pub xwing_public: XWingPublicKey,
    /// Retired envelope (X-Wing) private keys kept for decryption only,
    /// each with the unix time after which it must be deleted. Rotation
    /// replaces the active key; retired keys decrypt envelopes that were
    /// in flight when the rotation happened.
    pub retired_xwing: Vec<(XWingSecretKey, u64)>,
}

impl Identity {
    /// Rotate the signing key using the pre-committed next key.
    ///
    /// `next_seed` must hash to the current head's `next` commitment.
    /// `new_next_seed` is the next-next key to commit to; `None` abandons
    /// the identity permanently (a rotation with no next-key commitment).
    pub fn rotate(
        &mut self,
        next_seed: &SigningSeed,
        new_next_seed: Option<SigningSeed>,
    ) -> Result<(), NodeError> {
        let head = self.kel.events().last().ok_or(NodeError::EmptyKel)?;
        let committed = head.next.ok_or(NodeError::Abandoned)?;
        if hash_next(next_seed) != committed {
            return Err(NodeError::NextKeyMismatch);
        }
        let next_hash = new_next_seed.as_ref().map(hash_next);
        let event = KeyEvent::rotation(head, next_seed, next_hash);
        self.kel.append(event)?;
        self.signing_seed = next_seed.clone();
        Ok(())
    }

    /// True if the KEL ends in an abandonment (a rotation with no next-key
    /// commitment). An abandoned identity must not sign or publish.
    pub fn is_abandoned(&self) -> bool {
        self.kel.is_abandoned()
    }

    /// Rotate the envelope key: generate a fresh X-Wing keypair, move the
    /// current private key into the retired set (decrypt-only) until
    /// `retire_at`, and return the new public key.
    pub fn rotate_envelope(&mut self, retire_at: u64) -> XWingPublicKey {
        let kp = lattice_crypto::generate_keypair();
        let old = std::mem::replace(&mut self.xwing_secret, kp.secret);
        self.retired_xwing.push((old, retire_at));
        self.xwing_public = kp.public;
        self.xwing_public
    }

    /// Drop retired envelope keys whose grace period has elapsed.
    pub fn sweep_retired_envelope_keys(&mut self, now: u64) {
        self.retired_xwing.retain(|(_, exp)| *exp > now);
    }

    /// Try to open an envelope with the current key, then any retired keys
    /// still within their grace period.
    pub fn open_envelope_any(
        &self,
        msg: &lattice_proto::message::Message,
    ) -> Result<lattice_proto::message::Envelope, lattice_proto::ProtoError> {
        match msg.open_envelope(&self.xwing_secret) {
            Ok(e) => Ok(e),
            Err(first_err) => {
                for (seed, _) in &self.retired_xwing {
                    if let Ok(e) = msg.open_envelope(seed) {
                        return Ok(e);
                    }
                }
                Err(first_err)
            }
        }
    }

    /// Build an identity deterministically from a 32-byte seed. Used by the
    /// simulator so runs are reproducible.
    ///
    /// The caller must retain `seed` to rotate later: the next signing key
    /// is derived from it (`seed || "next"`), and the daemon never stores
    /// it. Dropping the seed strands the identity's rotation capability,
    /// though the identity itself remains valid.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let derive = |tag: &[u8]| {
            let mut v = Vec::with_capacity(32 + tag.len());
            v.extend_from_slice(seed);
            v.extend_from_slice(tag);
            lattice_crypto::hash(&v)
        };
        let signing_seed = SigningSeed::from_bytes(derive(b"signing").into_bytes());
        let next_seed = SigningSeed::from_bytes(derive(b"next").into_bytes());
        let inception = KeyEvent::inception(&signing_seed, hash_next(&next_seed));
        let kel = ValidatedKel::validate(vec![inception])
            .expect("a freshly built inception event is valid by construction");
        let channel_seed = ChannelSeed::from_bytes(derive(b"channel").into_bytes());
        let xwing_secret = XWingSecretKey::from_bytes(derive(b"xwing").into_bytes());
        let xwing_public = lattice_crypto::xwing_public_key(&xwing_secret);
        Identity {
            signing_seed,
            kel,
            channel_seed,
            xwing_secret,
            xwing_public,
            retired_xwing: Vec::new(),
        }
    }

    pub fn id(&self) -> Identifier {
        self.kel.identifier()
    }
}

fn hash_next(seed: &SigningSeed) -> Commitment {
    Commitment::from_bytes(
        lattice_crypto::hash(lattice_crypto::public_key(seed).as_ref()).into_bytes(),
    )
}

/// Preimage for a channel attestation: binds the signer's Ed25519 channel
/// key and the verifier's X25519 channel key. Both sides can compute it:
/// the signer knows both keys, the verifier knows the signer's (from the
/// record) and its own (from its seed).
fn attestation_preimage(
    signer_ed_ck: &ChannelPublicKey,
    verifier_x_ck: &X25519PublicKey,
) -> Hash32 {
    let mut h = Vec::with_capacity(22 + 64);
    h.extend_from_slice(b"lattice attestation v1");
    h.extend_from_slice(signer_ed_ck.as_ref());
    h.extend_from_slice(verifier_x_ck.as_ref());
    lattice_crypto::hash(&h)
}

struct PendingOffer {
    origin: PendingOrigin,
    sent_at: u64,
    excluded: Vec<(LinkId, u64)>,
    /// The link this offer was sent on; excluded on timeout so the retry
    /// does not immediately re-offer to a peer that never answered.
    link: LinkId,
}

enum PendingOrigin {
    Outbound {
        mid: MessageId,
    },
    /// Custody-entry key of the relay entry this offer belongs to.
    Relay {
        custody_leg: LegId,
    },
}

struct LinkState {
    /// `None` while the peer's identity is not safely established.
    peer: Option<Identifier>,
    remote_ck: X25519PublicKey,
    /// True when the peer id was pinned by operator config (root `id`); pinned
    /// bindings are never re-derived from records or revoked by contest.
    pinned: bool,
    /// The peer's attestation (id, signature), received on this link.
    /// Verified against our records in `reevaluate_link_bindings`.
    attestation: Option<(Identifier, Signature)>,
}

pub struct Node<S: Store> {
    pub config: Config,
    identity: Identity,
    store: S,
    pub own_id: Identifier,
    scope: Scope,
    own_seq: u64,
    links: HashMap<LinkId, LinkState>,
    next_link_order: Vec<LinkId>,
    reconcile_sessions: HashMap<LinkId, ReconcileSession>,
    pending: HashMap<LegId, PendingOffer>,
    outbound_exclusions: HashMap<MessageId, Vec<(LinkId, u64)>>,
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
    ck_claims: HashMap<X25519PublicKey, std::collections::HashSet<Identifier>>,
    next_claim_sweep_at: u64,
    next_data_sweep_at: u64,
    contested: u64,
    /// Bumped on every record-set mutation (admit, sweep, publish, or any
    /// `store_mut`). Keys the derived-data caches below.
    records_version: u64,
    /// Memoized routing graph. Stored bytes are untrusted and are
    /// re-validated whenever the record set changes (see `records_version`);
    /// within a stable record set the graph is a pure function of the
    /// records, so re-validating on every routing decision would be a
    /// remote-triggerable CPU amplifier.
    graph_cache: Option<(u64, u64, Arc<Graph>)>,
    /// Memoized reconcile item list; same invalidation as `graph_cache`.
    items_cache: Option<(u64, u64, Vec<reconcile::Item>)>,
    /// Memoized validation of stored records, keyed by (id, scope). Same
    /// invalidation as the graph cache; bounded, cleared when full.
    record_cache: HashMap<(Identifier, u8), (u64, u64, Option<PeerRecord>)>,
    /// Non-fatal internal failures observed since the last `handle` call.
    /// Drained by `handle` and returned alongside the actions; the caller
    /// decides how to surface them.
    diagnostics: Vec<Diagnostic>,
    /// Consecutive `outbound_due` failures; reset on success. Keeps a
    /// persistently failing outbound queue loud instead of silent.
    outbound_due_failures: u32,
}

impl<S: Store> Node<S> {
    pub fn new(config: Config, identity: Identity, store: S, now: u64) -> Result<Self, NodeError> {
        if config.mode == Mode::Private && (config.gateways.is_empty() || config.gateways.len() > 3)
        {
            return Err(NodeError::Config(
                "private mode requires 1-3 gateways".to_string(),
            ));
        }
        if identity.is_abandoned() {
            return Err(NodeError::Abandoned);
        }
        if config.mode == Mode::Public && !config.gateways.is_empty() {
            return Err(NodeError::Config(
                "gateways are only valid in private mode".to_string(),
            ));
        }
        let rng_seed = config.rng_seed;
        let id = identity.id();
        // Publish our own record if absent.
        let own_exists = store.record_get(&id, Scope::Wan)?.is_some();
        let mut node = Node {
            config,
            identity,
            store,
            own_id: id,
            scope: Scope::Wan,
            own_seq: 1,
            links: HashMap::new(),
            next_link_order: Vec::new(),
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
            next_claim_sweep_at: now + CLAIM_SWEEP_SECS,
            next_data_sweep_at: now + DATA_SWEEP_SECS,
            contested: 0,
            records_version: 0,
            graph_cache: None,
            items_cache: None,
            record_cache: HashMap::new(),
            diagnostics: Vec::new(),
            outbound_due_failures: 0,
        };
        // Seed the claim set from records already in the store so links can be
        // attributed immediately after a restart. Best-effort: on failure the
        // claims rebuild as records are re-admitted; report it.
        match node.store.record_all() {
            Ok(records) => {
                for (_, _, bytes, _) in records {
                    if let Ok((rec, _)) = PeerRecord::from_bytes(&bytes, now, None) {
                        if let Some(k) = Self::claim_key(&rec) {
                            node.ck_claims.entry(k).or_default().insert(rec.id);
                        }
                    }
                }
            }
            Err(e) => node.diag("record_all", &e),
        }
        if !own_exists {
            node.publish_record(now)?;
        } else if let Some((bytes, _)) = node.store.record_get(&id, Scope::Wan)? {
            node.own_seq = lattice_proto::record::PeerRecord::from_bytes(&bytes, now, None)
                .map(|(r, _)| r.seq)
                .unwrap_or(1);
        }
        // Crash recovery: anything InFlight at boot may or may not have
        // reached the next hop. Requeue it now; the recipient dedups by mid,
        // so at-least-once survives a restart.
        match node.store.outbound_all() {
            Ok(all) => {
                for mut msg in all {
                    if msg.state == OutboundState::InFlight {
                        msg.state = OutboundState::Queued;
                        msg.next_attempt = now;
                        if let Err(e) = node.store.outbound_put(&msg) {
                            node.diag("outbound_put", &e);
                        }
                    }
                }
            }
            Err(e) => node.diag("outbound_all", &e),
        }
        Ok(node)
    }

    /// Handle one event. Returns the actions to perform and any diagnostics
    /// (non-fatal internal failures, e.g. store errors) observed while
    /// handling it. Diagnostics are drained on every call; a caller that
    /// drops them loses them.
    pub fn handle(&mut self, event: Event) -> (Vec<Action>, Vec<Diagnostic>) {
        let actions = self.handle_inner(event);
        self.note_outbound_frames(&actions);
        (actions, std::mem::take(&mut self.diagnostics))
    }

    /// Record a non-fatal internal failure. The sans-IO core cannot log;
    /// the caller drains these from [`Node::handle`] and decides how to
    /// surface them.
    fn diag(&mut self, op: &'static str, detail: impl std::fmt::Display) {
        self.diagnostics.push(Diagnostic {
            op,
            detail: detail.to_string(),
        });
    }

    fn note_outbound_frames(&mut self, actions: &[Action]) {
        for action in actions {
            if let Action::SendFrame { frame, .. } = action {
                if matches!(frame, Frame::Dummy(_)) {
                    continue; // snow does not suppress itself
                }
                self.frames_since_snow_tick += 1;
                let bucket = match frame {
                    Frame::Offer(o) => {
                        if o.message.len() <= 2048 {
                            0
                        } else if o.message.len() <= 8192 {
                            1
                        } else {
                            2
                        }
                    }
                    Frame::Records(r) => {
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
                // Snow telemetry is best-effort: a failed counter write must
                // not stall frame handling, and a persistent store failure is
                // surfaced by every other store path, so this drop is
                // deliberate.
                let _ = self.store.size_bucket_sample(bucket);
            }
        }
    }

    fn handle_inner(&mut self, event: Event) -> Vec<Action> {
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

    fn build_own_record(&self, seq: u64, now: u64) -> Result<(PeerRecord, Vec<u8>), NodeError> {
        let exp = now + 7 * 24 * 3600;
        let private = self.config.mode == Mode::Private;
        let links: Vec<Identifier> = if private {
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
                channel_key: lattice_crypto::channel_public(&self.identity.channel_seed),
                channel_seed: self.identity.channel_seed.clone(),
                envelope_key: self.identity.xwing_public,
                mode: self.config.mode,
                scope: self.scope,
                endpoints,
                links,
                gateways,
                capabilities: 1,
            },
            &self.identity.signing_seed,
        )?;
        let bytes = rec.encode();
        Ok((rec, bytes))
    }

    fn publish_record(&mut self, now: u64) -> Result<(), NodeError> {
        let (_rec, bytes) = self.build_own_record(self.own_seq, now)?;
        let id = self.own_id;
        self.store.record_put(&id, self.scope, &bytes, now)?;
        self.records_version += 1;
        Ok(())
    }

    fn on_link_up(
        &mut self,
        at: u64,
        link: LinkId,
        peer: Option<Identifier>,
        remote_ck: X25519PublicKey,
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
                attestation: None,
            },
        );
        self.next_link_order.push(link);
        self.reconcile_sessions
            .insert(link, ReconcileSession::new());
        // Reconcile promptly: the peer needs our record (and we need theirs)
        // for routing to work at all; waiting a full interval stalls delivery.
        self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        // Publish the new link set immediately so peers can route via us.
        self.own_seq += 1;
        if let Err(e) = self.publish_record(at) {
            self.diag("publish_record", &e);
        }
        self.reevaluate_link_bindings(at);
        // Prove possession of our KEL key to the peer, bound to this
        // channel. The peer folds this into its link binding; without it
        // the link is attributed only from record claims.
        vec![self.attestation_frame(link, &remote_ck)]
    }

    /// Build the attestation frame for a link: proof that we hold the KEL
    /// signing key for our id, bound to this channel.
    fn attestation_frame(&self, link: LinkId, remote_ck: &X25519PublicKey) -> Action {
        let own_ck = lattice_crypto::channel_public(&self.identity.channel_seed);
        let preimage = attestation_preimage(&own_ck, remote_ck);
        let sig = lattice_crypto::sign(&self.identity.signing_seed, preimage.as_ref());
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Attest(lattice_proto::frames::AttestFrame {
                id: self.own_id,
                sig,
            }),
        }
    }

    fn on_link_down(&mut self, at: u64, link: LinkId) -> Vec<Action> {
        self.touch(at);
        self.links.remove(&link);
        self.next_link_order.retain(|l| *l != link);
        self.reconcile_sessions.remove(&link);
        self.own_seq += 1;
        if let Err(e) = self.publish_record(at) {
            self.diag("publish_record", &e);
        }
        Vec::new()
    }

    /// Build the routing graph from the stored records.
    ///
    /// Stored bytes are untrusted and re-validated on read; the result is
    /// memoized on `(records_version, now)` so repeated calls within one
    /// operation (relay path, `class_for`, `pick_next_hop`) validate the
    /// store once instead of once per call. Any record-set mutation or the
    /// passage of time invalidates the memo.
    fn build_graph(&mut self) -> Arc<Graph> {
        let key = (self.records_version, self.now);
        if let Some((v, t, g)) = &self.graph_cache {
            if (*v, *t) == key {
                return Arc::clone(g);
            }
        }
        type RecordParts = (Identifier, Vec<Identifier>, Vec<Identifier>);
        // On store failure the graph is empty: routing degrades to "no
        // route" (retried next call) rather than crashing or fabricating
        // routes. The diagnostic makes the failure visible.
        let stored = match self.store.record_all() {
            Ok(records) => records,
            Err(e) => {
                self.diag("record_all", &e);
                Vec::new()
            }
        };
        let records: Vec<RecordParts> = stored
            .iter()
            .filter_map(|(id, _scope, bytes, _recv)| {
                PeerRecord::from_bytes(bytes, self.now, None)
                    .ok()
                    .map(|(r, _)| (*id, r.links, r.gateways))
            })
            .collect();
        let mut graph = Graph::build(
            &self.own_id,
            records.iter().map(|(i, l, _)| (i, l.as_slice())),
        );
        // A private instance publishes no links, so the mutual-claim rule
        // would leave it unreachable. Its record names its gateways; add a
        // pseudo-edge to each so the graph can route to (and from) it.
        for (id, _, gateways) in &records {
            for gw in gateways {
                graph.add_edge(*id, *gw);
            }
        }
        let graph = Arc::new(graph);
        self.graph_cache = Some((key.0, key.1, Arc::clone(&graph)));
        graph
    }

    /// Reconcile item list for the stored records. Memoized on the same
    /// key as [`Self::build_graph`]. Returns `None` when the record set
    /// cannot be read: answering a reconcile with an empty set would tell
    /// the peer we hold nothing, so the round is skipped instead.
    fn record_items(&mut self) -> Option<Vec<reconcile::Item>> {
        let key = (self.records_version, self.now);
        if let Some((v, t, items)) = &self.items_cache {
            if (*v, *t) == key {
                return Some(items.clone());
            }
        }
        let stored = match self.store.record_all() {
            Ok(records) => records,
            Err(e) => {
                self.diag("record_all", &e);
                return None;
            }
        };
        let mut items: Vec<reconcile::Item> = stored
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
        self.items_cache = Some((key.0, key.1, items.clone()));
        Some(items)
    }

    // ---------- reconcile ----------

    fn reconcile_with(&mut self, _at: u64, link: LinkId) -> Vec<Action> {
        // Store unreadable: skip this round rather than advertise an empty set.
        let Some(items) = self.record_items() else {
            return Vec::new();
        };
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
        // Store unreadable: say nothing rather than claim we hold nothing.
        let Some(items) = self.record_items() else {
            return Vec::new();
        };
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
            match self.store.record_get(id, scope) {
                Ok(Some((bytes, _))) => records.push(bytes),
                Ok(None) => {}
                Err(e) => self.diag("record_get", &e),
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
        Vec::new()
    }

    /// Drop claims whose backing record is gone or no longer valid
    /// (expired). Records are never removed from the store today (record
    /// lifecycle is a separate decision), so this keys off validity at
    /// `now`; when a record-expiry sweep lands it will plug in here.
    fn sweep_ck_claims(&mut self, now: u64) {
        let mut fresh: HashMap<X25519PublicKey, std::collections::HashSet<Identifier>> =
            HashMap::new();
        match self.store.record_all() {
            Ok(records) => {
                for (_, _, bytes, _) in records {
                    if let Ok((rec, _)) = PeerRecord::from_bytes(&bytes, now, None) {
                        if let Some(k) = Self::claim_key(&rec) {
                            fresh.entry(k).or_default().insert(rec.id);
                        }
                    }
                }
            }
            // Keep the old claim set rather than dropping all claims on a
            // transient read failure; report it.
            Err(e) => {
                self.diag("record_all", &e);
                return;
            }
        }
        if fresh != self.ck_claims {
            self.ck_claims = fresh;
            self.reevaluate_link_bindings(now);
        }
    }

    /// Retention sweep: drop records and terminal outbound messages past
    /// expiry + grace, and KEL heads not seen for a year. Records are the
    /// only unbounded growth left in the store; everything else already
    /// expires (seen/delivered) or is capped (inbox, custody).
    fn sweep_expired_data(&mut self, now: u64) {
        match self.store.record_all() {
            Ok(records) => {
                for (id, scope, bytes, _) in records {
                    if id == self.own_id {
                        continue;
                    }
                    // Skip the time check: expired records must still decode so
                    // the grace period can elapse; undecodable records are dropped.
                    let expired = match PeerRecord::from_bytes_unchecked_time(&bytes, None) {
                        Ok((rec, _)) => rec.exp.saturating_add(RETENTION_GRACE_SECS) < now,
                        Err(_) => true,
                    };
                    if expired {
                        match self.store.record_remove(&id, scope) {
                            Ok(()) => self.records_version += 1,
                            Err(e) => self.diag("record_remove", &e),
                        }
                    }
                }
            }
            Err(e) => self.diag("record_all", &e),
        }
        if let Err(e) = self.store.inbox_sweep_expired(INBOX_TTL_SECS, now) {
            self.diag("inbox_sweep_expired", &e);
        }
        match self.store.outbound_all() {
            Ok(all) => {
                for msg in all {
                    let terminal = matches!(
                        msg.state,
                        OutboundState::Delivered | OutboundState::Failed | OutboundState::Expired
                    );
                    if terminal && msg.exp.saturating_add(RETENTION_GRACE_SECS) < now {
                        if let Err(e) = self.store.outbound_remove(&msg.mid) {
                            self.diag("outbound_remove", &e);
                        }
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }
        if let Err(e) = self
            .store
            .kel_head_sweep(now.saturating_sub(KEL_HEAD_MAX_AGE_SECS))
        {
            self.diag("kel_head_sweep", &e);
        }
        self.identity.sweep_retired_envelope_keys(now);
    }

    /// The claim key for a record's channel key: the X25519 form, matching
    /// what the Noise handshake reports as the peer's static key.
    fn claim_key(rec: &PeerRecord) -> Option<X25519PublicKey> {
        lattice_crypto::channel_x25519_public_from_ed25519(&rec.channel_key)
    }

    /// Fold a record's (channel_key, id) claim into the claim set.
    fn note_ck_claim(&mut self, rec: &PeerRecord) {
        if let Some(k) = Self::claim_key(rec) {
            self.ck_claims.entry(k).or_default().insert(rec.id);
        }
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
    /// Verify a peer's attestation against our records. The record for
    /// `id` must claim this link's channel key, and the signature must
    /// verify under that record's KEL key.
    fn attestation_valid(
        &mut self,
        remote_ck: &X25519PublicKey,
        id: &Identifier,
        sig: &Signature,
    ) -> bool {
        let own_x = lattice_crypto::channel_x25519_public(&self.identity.channel_seed);
        for scope in [Scope::Wan, Scope::Hive] {
            let Some(rec) = self.validated_record(id, scope) else {
                continue;
            };
            let Some(x) = lattice_crypto::channel_x25519_public_from_ed25519(&rec.channel_key)
            else {
                continue;
            };
            if &x != remote_ck {
                continue;
            }
            let preimage = attestation_preimage(&rec.channel_key, &own_x);
            if lattice_crypto::verify(&rec.current_signing_key(), preimage.as_ref(), sig) {
                return true;
            }
        }
        false
    }

    fn reevaluate_link_bindings(&mut self, at: u64) {
        // Pass 1: attestation wins over record claims — it is direct proof
        // of KEL possession, not a third-party claim about a channel key.
        let pending: Vec<(LinkId, X25519PublicKey, Identifier, Signature)> = self
            .links
            .iter()
            .filter(|(_, link)| !link.pinned)
            .filter_map(|(link_id, link)| {
                link.attestation
                    .as_ref()
                    .map(|(id, sig)| (*link_id, link.remote_ck, *id, *sig))
            })
            .collect();
        let mut attested: HashMap<LinkId, Identifier> = HashMap::new();
        for (link_id, remote_ck, id, sig) in pending {
            if self.attestation_valid(&remote_ck, &id, &sig) {
                attested.insert(link_id, id);
            }
        }
        let mut changed = false;
        for (link_id, link) in self.links.iter_mut() {
            if link.pinned {
                continue;
            }
            if let Some(id) = attested.get(link_id) {
                if link.peer != Some(*id) {
                    link.peer = Some(*id);
                    changed = true;
                }
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
            if let Err(e) = self.publish_record(at) {
                self.diag("publish_record", &e);
            }
            self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        }
    }
    fn admit_record(&mut self, at: u64, bytes: &[u8]) -> bool {
        // Decode once to learn the claimed id, look up the known head,
        // then validate exactly once. Validating the bytes twice (the old
        // behavior) doubled the KEL signature checks on every admission.
        let decoded = match lattice_proto::record::PeerRecord::decode(bytes) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let known = match self.store.kel_head(&decoded.id()) {
            Ok(k) => k.map(|(seq, commitment, _)| (seq, commitment)),
            // Fail closed: without the known head we cannot rule out
            // equivocation, so refuse the record.
            Err(e) => {
                self.diag("kel_head", &e);
                return false;
            }
        };
        match decoded.validate(Some(at), known) {
            Ok((rec, head)) => {
                let scope = rec.scope;
                let existing = match self.store.record_get(&rec.id, scope) {
                    Ok(e) => e,
                    // Fail closed: without the current row we cannot apply
                    // last-writer-wins, so keep what we have.
                    Err(e) => {
                        self.diag("record_get", &e);
                        return false;
                    }
                };
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
                match self.store.record_put(&rec.id, scope, bytes, at) {
                    Ok(()) => self.records_version += 1,
                    Err(e) => self.diag("record_put", &e),
                }
                // Advance the stored head only when we could read it, and
                // record a first-seen head when none exists. On a read error
                // leave the stored head alone rather than overwrite blindly.
                match self.store.kel_head(&rec.id) {
                    Ok(Some((seq, _, _))) if head.seq <= seq => {}
                    Ok(_) => {
                        if let Err(e) =
                            self.store
                                .kel_head_put(&rec.id, head.seq, head.commitment, at)
                        {
                            self.diag("kel_head_put", &e);
                        }
                    }
                    Err(e) => self.diag("kel_head", &e),
                }
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

type BuildResult = (Vec<u8>, Identifier, Option<Identifier>);

/// Why a message could not be built for sending.
enum BuildError {
    /// No route to the destination (no record, no gateway, no waypoint).
    /// Retryable: the network may learn a route later.
    NoRoute,
    /// Cryptographic or encoding failure. Deterministic for the same inputs,
    /// so retrying is pointless; surfaces as ERR_INTERNAL. The underlying
    /// error is dropped: the sans-IO core has no diagnostic channel yet.
    Crypto,
}

impl From<lattice_proto::ProtoError> for BuildError {
    fn from(_: lattice_proto::ProtoError) -> Self {
        BuildError::Crypto
    }
}

enum DispatchResult {
    Sent,
    NoRoute,
}

const CUSTODY_TIMEOUT_SECS: u64 = 30;
const CLAIM_SWEEP_SECS: u64 = 60;
const MAX_PENDING_ECHOES: usize = 256;
/// How often the retention sweep runs.
const DATA_SWEEP_SECS: u64 = 3600;
/// Grace period past a record's/message's expiry before it is purged.
const RETENTION_GRACE_SECS: u64 = 7 * 24 * 3600;
/// Undelivered inbox entries older than this are dropped by the sweep.
const INBOX_TTL_SECS: u64 = 30 * 24 * 3600;
/// KEL heads not seen for this long are dropped (spec: one year).
const KEL_HEAD_MAX_AGE_SECS: u64 = 365 * 24 * 3600;
const BUF_CLASSES: usize = 16;

impl<S: Store> Node<S> {
    fn on_app_send(&mut self, send: AppSend) -> Vec<Action> {
        let now = self.now;
        let mid: MessageId = send
            .mid_hint
            .unwrap_or_else(|| MessageId::from_bytes(lattice_crypto::os_bytes::<16>()));
        if !self.has_record(&send.to) {
            return vec![Action::Status {
                mid,
                status: local::MSG_STATUS_FAILED,
                detail: Some(ERR_NO_RECORD),
                service: send.service.clone(),
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
            sig: Signature::from_bytes([0; 64]),
        };

        let receipt_timeout = if self.record_mode(&send.to) == Some(Mode::Private) {
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
        if let Err(e) = self.store.outbound_push(&outbound) {
            self.diag("outbound_push", &e);
            return vec![Action::Status {
                mid,
                status: local::MSG_STATUS_FAILED,
                detail: Some(ERR_INTERNAL),
                service: send.service.clone(),
            }];
        }
        let mut actions = vec![Action::Status {
            mid,
            status: local::MSG_STATUS_QUEUED,
            detail: None,
            service: send.service.clone(),
        }];
        actions.extend(self.pump_outbound(now));
        actions
    }

    /// Presence check only; does not validate. Used where a missing record
    /// is the error condition and validation happens (and is memoized)
    /// downstream.
    fn has_record(&mut self, id: &Identifier) -> bool {
        for scope in [Scope::Wan, Scope::Hive] {
            match self.store.record_get(id, scope) {
                Ok(Some(_)) => return true,
                Ok(None) => {}
                Err(e) => self.diag("record_get", &e),
            }
        }
        false
    }

    /// Validate a stored record, memoized on `(records_version, now)`.
    /// Stored bytes are untrusted; the memo is keyed on the record-set
    /// version and the current time, so it never serves a result that a
    /// fresh read would not produce. Bounded; cleared when full.
    fn validated_record(&mut self, id: &Identifier, scope: Scope) -> Option<PeerRecord> {
        let key = (*id, scope_as_u8(scope));
        let tag = (self.records_version, self.now);
        if let Some((v, t, rec)) = self.record_cache.get(&key) {
            if (*v, *t) == tag {
                return rec.clone();
            }
        }
        let rec = match self.store.record_get(id, scope) {
            Ok(Some((bytes, _))) => PeerRecord::from_bytes(&bytes, self.now, None)
                .ok()
                .map(|(r, _)| r),
            Ok(None) => None,
            // Store error: treat as missing (callers fail closed), but say so.
            Err(e) => {
                self.diag("record_get", &e);
                None
            }
        };
        if self.record_cache.len() >= 256 {
            self.record_cache.clear();
        }
        self.record_cache.insert(key, (tag.0, tag.1, rec.clone()));
        rec
    }

    /// Look up and validate a record in either scope (WAN first, then hive).
    fn lookup_validated(&mut self, id: &Identifier) -> Option<PeerRecord> {
        for scope in [Scope::Wan, Scope::Hive] {
            if let Some(rec) = self.validated_record(id, scope) {
                return Some(rec);
            }
        }
        None
    }

    fn record_mode(&mut self, id: &Identifier) -> Option<Mode> {
        self.lookup_validated(id).map(|r| r.mode)
    }

    fn record_envelope_key(&mut self, id: &Identifier) -> Option<XWingPublicKey> {
        self.lookup_validated(id).map(|r| r.envelope_key)
    }

    fn record_gateways(&mut self, id: &Identifier) -> Vec<Identifier> {
        self.lookup_validated(id)
            .map(|r| r.gateways)
            .unwrap_or_default()
    }

    /// Build a wire message for one attempt. Returns (bytes, routing destination, waypoint used).
    fn build_attempt(
        &mut self,
        msg: &lattice_store::OutboundMessage,
        force_waypoint: bool,
    ) -> Result<BuildResult, BuildError> {
        let recipient_rec = self.lookup_validated(&msg.recipient);
        let recipient_private = recipient_rec
            .as_ref()
            .is_some_and(|r| r.mode == Mode::Private);
        let gateway_choice = if recipient_private {
            recipient_rec
                .as_ref()
                .map(|r| r.gateways.clone())
                .unwrap_or_default()
                .into_iter()
                .find_map(|g| self.record_envelope_key(&g).map(|ek| (g, ek)))
        } else {
            None
        };
        if recipient_private && gateway_choice.is_none() {
            return Err(BuildError::NoRoute);
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

        let recipient_ek = recipient_rec
            .map(|r| r.envelope_key)
            .ok_or(BuildError::NoRoute)?;
        let real_dst = gateway_choice
            .as_ref()
            .map(|(g, _)| *g)
            .unwrap_or(msg.recipient);
        let gateway = gateway_choice.map(|(_g, gateway_ek)| GatewaySeal {
            gateway_ek,
            rcpt: msg.recipient,
        });
        let waypoint = waypoint_choice.map(|(id, ek)| WaypointSeal {
            waypoint_id: id,
            waypoint_ek: ek,
            leg: LegId::from_bytes(lattice_crypto::os_bytes::<16>()),
            exp: msg.exp,
        });
        let used_waypoint_id = waypoint.as_ref().map(|w| w.waypoint_id);
        let wire = Message::build(BuildParams {
            envelope: msg.envelope.clone(),
            sender_seed: &self.identity.signing_seed,
            recipient_ek: &recipient_ek,
            real_dst,
            leg: LegId::from_bytes(lattice_crypto::os_bytes::<16>()),
            exp: msg.exp,
            gateway,
            waypoint,
        })
        .map_err(|_| BuildError::Crypto)?;
        Ok((wire, real_dst, used_waypoint_id))
    }

    fn pick_waypoint(
        &mut self,
        recipient: &Identifier,
        exclude: &[Identifier],
    ) -> Option<(Identifier, XWingPublicKey)> {
        // Spec: exclude the sender's own links and the recipient's gateways
        // (a gateway is already the entry point; it is not a waypoint).
        let own_links: HashSet<Identifier> = self.links.values().filter_map(|l| l.peer).collect();
        let recipient_gateways: HashSet<Identifier> =
            self.record_gateways(recipient).into_iter().collect();
        // On store failure there is no candidate set; report and skip
        // waypoint selection (a direct route may still work).
        let stored = match self.store.record_all() {
            Ok(records) => records,
            Err(e) => {
                self.diag("record_all", &e);
                return None;
            }
        };
        let mut candidates: Vec<(Identifier, XWingPublicKey)> = stored
            .into_iter()
            .filter_map(|(id, _scope, bytes, _)| {
                if id == self.own_id
                    || &id == recipient
                    || exclude.contains(&id)
                    || own_links.contains(&id)
                    || recipient_gateways.contains(&id)
                {
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
            Ok(d) => {
                self.outbound_due_failures = 0;
                d
            }
            Err(e) => {
                // The queue stalls until the store recovers. That is the safe
                // direction (nothing is lost or double-sent), but it must not
                // be silent: report every failure with a consecutive count so
                // a persistent outage is loud, not a one-off.
                self.outbound_due_failures = self.outbound_due_failures.saturating_add(1);
                let n = self.outbound_due_failures;
                self.diag(
                    "outbound_due",
                    format_args!("{e} (consecutive failure #{n})"),
                );
                return actions;
            }
        };
        for mut msg in due {
            if msg.state != OutboundState::Queued {
                continue;
            }
            let force_waypoint = msg.attempts > 0;
            // Every pass through the pump is one send attempt; count it in
            // exactly one place.
            msg.attempts += 1;
            match self.build_attempt(&msg, force_waypoint) {
                Ok((wire, _real_dst, used_wp)) => {
                    match self.dispatch_wire(now, &wire, &msg, &mut actions) {
                        DispatchResult::Sent => {
                            if let Some(wp) = used_wp {
                                msg.waypoints_tried.push(wp);
                            }
                            msg.state = OutboundState::InFlight;
                            msg.next_attempt = now + self.config.retry_base_secs;
                            // The receipt clock starts when the message
                            // actually goes on the wire, not at enqueue.
                            msg.receipt_deadline = Some(now + self.receipt_timeout_for(&msg));
                            if let Err(e) = self.store.outbound_put(&msg) {
                                self.diag("outbound_put", &e);
                            }
                        }
                        DispatchResult::NoRoute => {
                            msg.state = OutboundState::Queued;
                            msg.next_attempt = now + self.backoff(msg.attempts);
                            if let Err(e) = self.store.outbound_put(&msg) {
                                self.diag("outbound_put", &e);
                            }
                        }
                    }
                }
                Err(BuildError::NoRoute) => {
                    if msg.attempts > self.config.fresh_waypoint_retries + 1 {
                        msg.state = OutboundState::Failed;
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                        if let Err(e) = self.store.status_set(
                            &msg.mid,
                            local::MSG_STATUS_FAILED,
                            Some(ERR_NO_ROUTE),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid: msg.mid,
                            status: local::MSG_STATUS_FAILED,
                            detail: Some(ERR_NO_ROUTE),
                            service: msg.envelope.fsvc.clone(),
                        });
                    } else {
                        msg.next_attempt = now + self.config.retry_base_secs;
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                    }
                }
                Err(BuildError::Crypto) => {
                    // Deterministic failure: retrying cannot help.
                    msg.state = OutboundState::Failed;
                    if let Err(e) = self.store.outbound_put(&msg) {
                        self.diag("outbound_put", &e);
                    }
                    if let Err(e) = self.store.status_set(
                        &msg.mid,
                        local::MSG_STATUS_FAILED,
                        Some(ERR_INTERNAL),
                    ) {
                        self.diag("status_set", &e);
                    }
                    actions.push(Action::Status {
                        mid: msg.mid,
                        status: local::MSG_STATUS_FAILED,
                        detail: Some(ERR_INTERNAL),
                        service: msg.envelope.fsvc.clone(),
                    });
                }
            }
        }
        actions
    }

    fn receipt_timeout_for(&mut self, msg: &lattice_store::OutboundMessage) -> u64 {
        if self.record_mode(&msg.recipient) == Some(Mode::Private) {
            self.config.receipt_timeout_private
        } else {
            self.config.receipt_timeout_public
        }
    }

    fn backoff(&self, attempts: u32) -> u64 {
        let shift = attempts.min(16);
        let base = self.config.retry_base_secs.saturating_mul(1u64 << shift);
        base.min(self.config.retry_max_secs)
    }

    fn pick_next_hop(
        &mut self,
        dst: &Identifier,
        exclude: &[(LinkId, u64)],
        now: u64,
    ) -> Option<(LinkId, Identifier)> {
        // A directly connected peer is always one hop away, even when the
        // record graph has no path to it (a private instance publishes no
        // links). Honor exclusions like any other hop.
        if let Some((id, _)) = self.links.iter().find(|(id, l)| {
            l.peer == Some(*dst) && !exclude.iter().any(|(l, until)| l == *id && *until > now)
        }) {
            return Some((*id, *dst));
        }
        // Distances are measured from the destination; the graph is undirected,
        // so BFS from dst gives each node's distance to the destination.
        let graph = self.build_graph();
        let dist = graph.distances(dst);
        let excluded_peers: HashSet<Identifier> = exclude
            .iter()
            .filter(|(_, until)| *until > now)
            .filter_map(|(l, _)| self.links.get(l).and_then(|s| s.peer))
            .collect();
        let up: HashSet<Identifier> = self.links.values().filter_map(|l| l.peer).collect();
        let peer = graph.next_hop(
            &self.own_id,
            &dist,
            self.config.sideways_prob,
            &excluded_peers,
            &up,
            &mut self.rng,
        )?;
        let link = self
            .links
            .iter()
            .find(|(_, l)| l.peer == Some(peer))
            .map(|(id, _)| *id)?;
        Some((link, peer))
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
                link,
            },
        );
        actions.push(Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Offer(OfferFrame {
                message: wire.to_vec(),
            }),
        });
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
        let leg_hash = lattice_crypto::hash(leg.as_ref());
        // Fail closed on store error: treat the leg as already seen so a
        // broken store cannot cause double-processing.
        let seen = match self.store.seen_contains(&leg_hash, now) {
            Ok(v) => v,
            Err(e) => {
                self.diag("seen_contains", &e);
                true
            }
        };
        if seen {
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
            return self.on_offer_for_us(now, link, &msg, &leg_hash, actions);
        }
        // A message forwarded by our gateway arrives with hop_layer null and
        // dst naming the gateway, not us; the envelope is sealed to us. If it
        // opens, it is ours regardless of dst. Only pay the decapsulation
        // when dst is one of our gateways — any other dst is relay traffic.
        if msg.hop_layer.is_none()
            && self.config.gateways.iter().any(|g| g == &dst)
            && self.identity.open_envelope_any(&msg).is_ok()
        {
            return self.on_offer_for_us(now, link, &msg, &leg_hash, actions);
        }

        // Relay path: buffer class (forwarding priority / wait order), fair
        // share per destination upstream, transit cap.
        let dist = {
            let g = self.build_graph();
            let d = g.distances(&self.own_id);
            d.get(&dst).copied().unwrap_or(u32::MAX) as usize
        };
        let class = dist.min(BUF_CLASSES - 1) as u8;
        // Fair-share accounting is per (destination, upstream link): each
        // upstream gets custody_allowance/N per destination. The spec's
        // wording suggests a per-upstream aggregate cap; the per-destination
        // form is strictly more permissive for single-destination floods and
        // equivalent otherwise. If per-upstream aggregate accounting is ever
        // wanted, add a second counter keyed by upstream alone and check both
        // here — the store already keys shares by (dest, upstream).
        if self.share_exceeded(&dst, link, msg_len) {
            actions.push(self.busy(link, leg));
            return actions;
        }
        // Merlin-Schweitzer buffer classes: each class gets an equal slice
        // of the transit cap, so a flood in one class cannot starve the
        // others and waits can't form a cycle (a class-d message only ever
        // waits on class < d room at the next hop).
        if self.class_full(class, msg_len) {
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
            excluded: Vec::new(),
        };
        let accept = CustodyAccept {
            entry,
            share_dest: dst,
            share_upstream: link,
            share_bytes: msg_len as i64,
            seen_hash: leg_hash,
            seen_exp: msg.header.exp,
        };
        if let Err(e) = self.store.custody_accept(accept) {
            self.diag("custody_accept", &e);
            actions.push(self.busy(link, leg));
            return actions;
        }
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

    /// Fair-share check for a destination on an upstream link. On store
    /// error, fail closed (treat the allowance as exhausted) and report.
    fn share_exceeded(&mut self, dest: &Identifier, link: LinkId, msg_len: u64) -> bool {
        let upstream_count = self.links.len().max(1) as u64;
        let share_limit = self.config.custody_allowance / upstream_count;
        let used = match self.store.share_get(dest, link) {
            Ok(v) => v,
            Err(e) => {
                self.diag("share_get", &e);
                u64::MAX
            }
        };
        used.saturating_add(msg_len) > share_limit
    }

    /// Transit-cap check for a buffer class. On store error, fail closed
    /// (treat the class as full) and report.
    fn class_full(&mut self, class: u8, msg_len: u64) -> bool {
        let class_bytes = match self.store.custody_class_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.diag("custody_class_bytes", &e);
                [u64::MAX; 16]
            }
        };
        class_bytes[class as usize].saturating_add(msg_len)
            > self.config.transit_cap / BUF_CLASSES as u64
    }

    fn busy(&self, link: LinkId, leg: LegId) -> Action {
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
        leg_hash: &Hash32,
        mut actions: Vec<Action>,
    ) -> Vec<Action> {
        let leg = msg.header.leg;

        if msg.hop_layer.is_some() {
            match msg.open_hop_layer(&self.identity.xwing_secret) {
                Ok(HopLayerPlain::Waypoint { hdr, inner }) => {
                    // The outer header's expiry is checked in Message::parse;
                    // the inner header's is not, so enforce the same horizon
                    // here before the expiry is used for custody accounting.
                    if hdr.exp <= now
                        || hdr.exp
                            > now + lattice_proto::MAX_MESSAGE_HORIZON + lattice_proto::CLOCK_SKEW
                    {
                        actions.push(self.refuse(link, leg));
                        return actions;
                    }
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
                    let class = self.class_for(&hdr_dst);
                    if self.share_exceeded(&hdr_dst, link, msg_len) {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    if self.class_full(class, msg_len) {
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
                        excluded: Vec::new(),
                    };
                    let accept = CustodyAccept {
                        entry,
                        share_dest: hdr_dst,
                        share_upstream: link,
                        share_bytes: msg_len as i64,
                        seen_hash: *leg_hash,
                        seen_exp: hdr_exp,
                    };
                    if let Err(e) = self.store.custody_accept(accept) {
                        self.diag("custody_accept", &e);
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
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
                    // The private recipient cannot open the gateway layer
                    // (it is sealed to us), so it is stripped before the
                    // message is stored and forwarded. Header and envelope
                    // are unchanged: the header is the envelope's AAD.
                    let stripped = match msg.clone().into_after_gateway() {
                        Ok(bytes) => bytes,
                        Err(_) => {
                            actions.push(self.refuse(link, leg));
                            return actions;
                        }
                    };
                    let msg_len = stripped.len() as u64;
                    let class = self.class_for(&rcpt);
                    if self.share_exceeded(&rcpt, link, msg_len) {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    if self.class_full(class, msg_len) {
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
                    let entry = CustodyEntry {
                        leg,
                        message: stripped,
                        upstream: link,
                        destination: rcpt,
                        class,
                        exp: msg.header.exp,
                        excluded: Vec::new(),
                    };
                    let accept = CustodyAccept {
                        entry,
                        share_dest: rcpt,
                        share_upstream: link,
                        share_bytes: msg_len as i64,
                        seen_hash: *leg_hash,
                        seen_exp: msg.header.exp,
                    };
                    if let Err(e) = self.store.custody_accept(accept) {
                        self.diag("custody_accept", &e);
                        actions.push(self.busy(link, leg));
                        return actions;
                    }
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
        let opened = match self.identity.open_envelope_any(msg) {
            Ok(e) => e,
            Err(_) => {
                actions.push(self.refuse(link, leg));
                return actions;
            }
        };
        if opened.validate_created(now).is_err() {
            // Absurd `created` (future beyond skew, or older than the
            // message horizon): refuse custody rather than store or relay it.
            actions.push(self.refuse(link, leg));
            return actions;
        }
        match self.signing_key_for(&opened.from) {
            Some(key) => {
                if !opened.verify_signature(&key, msg.routing_header_bytes()) {
                    // Well-formed envelope, bad signature: refuse, and tell the
                    // sender if we can authenticate them at all.
                    if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
                        self.diag("seen_add", &e);
                    }
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
            if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
                self.diag("seen_add", &e);
            }
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
        let mid_hash = lattice_crypto::hash(mid_bytes.as_ref());
        // Fail closed on store error: treat the message as already delivered
        // so a broken store cannot cause duplicate delivery.
        let already_delivered = match self.store.delivered_contains(&mid_hash, now) {
            Ok(v) => v,
            Err(e) => {
                self.diag("delivered_contains", &e);
                true
            }
        };
        if already_delivered {
            if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
                self.diag("seen_add", &e);
            }
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
        // Fail closed on store error: treat the inbox as full rather than
        // accept a delivery we cannot account for.
        let inbox_len = match self.store.inbox_len(&opened.tsvc) {
            Ok(v) => v,
            Err(e) => {
                self.diag("inbox_len", &e);
                u64::MAX
            }
        };
        let inbox_total = match self.store.inbox_len_total() {
            Ok(v) => v,
            Err(e) => {
                self.diag("inbox_len_total", &e);
                u64::MAX
            }
        };
        if inbox_len >= self.config.inbox_max_deliveries
            || inbox_total >= self.config.inbox_max_total
        {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let entry = InboxEntry {
            delivery_id: DeliveryId::from_bytes(lattice_crypto::os_bytes::<16>()),
            mid: mid_bytes,
            from: opened.from,
            fsvc: opened.fsvc.clone(),
            fmbx: opened.fmbx.clone(),
            tsvc: opened.tsvc.clone(),
            tmbx: opened.tmbx.clone(),
            body: opened.body.clone().unwrap_or_default(),
            received: now,
        };
        if let Err(e) = self.store.inbox_push(entry.clone()) {
            self.diag("inbox_push", &e);
            actions.push(self.busy(link, leg));
            return actions;
        }
        if let Err(e) = self.store.delivered_add(mid_hash, msg.header.exp) {
            self.diag("delivered_add", &e);
        }
        if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
            self.diag("seen_add", &e);
        }
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
        // Best effort: on store error report 0 rather than fail the delivery;
        // the diagnostic carries the real failure.
        let unread = match self.store.inbox_len(&opened.tsvc) {
            Ok(v) => v,
            Err(e) => {
                self.diag("inbox_len", &e);
                0
            }
        };
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

    fn refuse(&self, link: LinkId, leg: LegId) -> Action {
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

    fn signing_key_for(&mut self, id: &Identifier) -> Option<SigningPublicKey> {
        self.lookup_validated(id).map(|r| r.current_signing_key())
    }

    fn class_for(&mut self, dst: &Identifier) -> u8 {
        let g = self.build_graph();
        let d = g.distances(&self.own_id);
        d.get(dst)
            .copied()
            .unwrap_or(u32::MAX)
            .min((BUF_CLASSES - 1) as u32) as u8
    }

    fn forward_custody(&mut self, now: u64, leg: LegId, actions: &mut Vec<Action>) {
        let entry = match self.store.custody_get(&leg) {
            Ok(Some(e)) => e,
            // The entry is gone (already delivered or swept): nothing to do.
            Ok(None) => return,
            Err(e) => {
                self.diag("custody_get", &e);
                return;
            }
        };
        if entry.exp <= now {
            if let Err(e) = self.store.custody_remove(&leg) {
                self.diag("custody_remove", &e);
            }
            if let Err(e) = self.store.share_add(
                &entry.destination,
                entry.upstream,
                -(entry.message.len() as i64),
            ) {
                self.diag("share_add", &e);
            }
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
                link: next_link,
            },
        );
        actions.push(Action::SendFrame {
            pad_to: None,
            link: next_link,
            frame: Frame::Offer(OfferFrame {
                message: entry.message.clone(),
            }),
        });
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
                    let mut service = String::new();
                    match self.store.outbound_get(mid) {
                        Ok(Some(mut msg)) => {
                            msg.state = OutboundState::InFlight;
                            service = msg.envelope.fsvc.clone();
                            if let Err(e) = self.store.outbound_put(&msg) {
                                self.diag("outbound_put", &e);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => self.diag("outbound_get", &e),
                    }
                    if let Err(e) = self
                        .store
                        .status_set(mid, local::MSG_STATUS_IN_TRANSIT, None)
                    {
                        self.diag("status_set", &e);
                    }
                    actions.push(Action::Status {
                        mid: *mid,
                        status: local::MSG_STATUS_IN_TRANSIT,
                        detail: None,
                        service,
                    });
                }
                Some(PendingOrigin::Relay { custody_leg }) => {
                    match self.store.custody_remove(custody_leg) {
                        Ok(Some(e)) => {
                            if let Err(e) = self.store.share_add(
                                &e.destination,
                                e.upstream,
                                -(e.message.len() as i64),
                            ) {
                                self.diag("share_add", &e);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => self.diag("custody_remove", &e),
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
                            match self.store.outbound_get(&mid) {
                                Ok(Some(mut msg)) => {
                                    let until = if busy { now + retry } else { msg.exp };
                                    add_exclusion(
                                        self.outbound_exclusions.entry(mid).or_default(),
                                        link,
                                        until,
                                    );
                                    msg.state = OutboundState::Queued;
                                    msg.next_attempt = now + if busy { retry } else { 0 };
                                    if let Err(e) = self.store.outbound_put(&msg) {
                                        self.diag("outbound_put", &e);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => self.diag("outbound_get", &e),
                            }
                            // Immediate retry against a different neighbor, if one exists now.
                            if !busy {
                                actions.extend(self.pump_outbound(now));
                            }
                        }
                        PendingOrigin::Relay { custody_leg } => {
                            if busy {
                                match self.store.custody_get(&custody_leg) {
                                    Ok(Some(mut e)) => {
                                        add_exclusion(&mut e.excluded, link, now + retry);
                                        if let Err(e) = self.store.custody_put(e) {
                                            self.diag("custody_put", &e);
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => self.diag("custody_get", &e),
                                }
                                self.forward_custody(now, custody_leg, &mut actions);
                            } else {
                                // The downstream already holds it: drop ours and release the share.
                                match self.store.custody_remove(&custody_leg) {
                                    Ok(Some(done)) => {
                                        if let Err(e) = self.store.share_add(
                                            &done.destination,
                                            done.upstream,
                                            -(done.message.len() as i64),
                                        ) {
                                            self.diag("share_add", &e);
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => self.diag("custody_remove", &e),
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
                            let mut service = String::new();
                            match self.store.outbound_get(&mid) {
                                Ok(Some(mut msg)) => {
                                    msg.state = OutboundState::Failed;
                                    self.outbound_exclusions.remove(&msg.mid);
                                    service = msg.envelope.fsvc.clone();
                                    if let Err(e) = self.store.outbound_put(&msg) {
                                        self.diag("outbound_put", &e);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => self.diag("outbound_get", &e),
                            }
                            if let Err(e) = self.store.status_set(
                                &mid,
                                local::MSG_STATUS_FAILED,
                                Some(ERR_REFUSED),
                            ) {
                                self.diag("status_set", &e);
                            }
                            actions.push(Action::Status {
                                mid,
                                status: local::MSG_STATUS_FAILED,
                                detail: Some(ERR_REFUSED),
                                service,
                            });
                        }
                        PendingOrigin::Relay { custody_leg } => {
                            match self.store.custody_remove(&custody_leg) {
                                Ok(Some(e)) => {
                                    if let Err(e) = self.store.share_add(
                                        &e.destination,
                                        e.upstream,
                                        -(e.message.len() as i64),
                                    ) {
                                        self.diag("share_add", &e);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => self.diag("custody_remove", &e),
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
        let terminal_status = |s: u64| {
            matches!(
                s,
                local::MSG_STATUS_DELIVERED | local::MSG_STATUS_FAILED | local::MSG_STATUS_EXPIRED
            )
        };
        let already_terminal = match self.store.status_get(&reference) {
            Ok(Some((s, _))) => terminal_status(s),
            Ok(None) => false,
            // Store error: fail closed and ignore the receipt.
            Err(e) => {
                self.diag("status_get", &e);
                true
            }
        };
        match envelope.kind {
            KIND_RECEIPT | KIND_NEGATIVE_RECEIPT => {
                let mut msg = match self.store.outbound_get(&reference) {
                    Ok(Some(msg)) => msg,
                    // Not one of ours (or already forgotten): nothing to update.
                    Ok(None) => return actions,
                    Err(e) => {
                        self.diag("outbound_get", &e);
                        return actions;
                    }
                };
                // A receipt is authoritative only from the message's recipient.
                // The signature is verified by the caller; this binds the
                // signer to the original message.
                if msg.recipient != envelope.from {
                    return actions;
                }
                let was_active =
                    matches!(msg.state, OutboundState::Queued | OutboundState::InFlight);
                if was_active {
                    msg.state = if envelope.kind == KIND_RECEIPT {
                        OutboundState::Delivered
                    } else {
                        OutboundState::Failed
                    };
                    if let Err(e) = self.store.outbound_put(&msg) {
                        self.diag("outbound_put", &e);
                    }
                }
                // Terminal states are sticky: a late receipt must not flip
                // Delivered/Failed/Expired.
                if !was_active || already_terminal {
                    return actions;
                }
                let (status, detail) = if envelope.kind == KIND_RECEIPT {
                    (local::MSG_STATUS_DELIVERED, None)
                } else {
                    (local::MSG_STATUS_FAILED, envelope.reason)
                };
                if let Err(e) = self.store.status_set(&reference, status, detail) {
                    self.diag("status_set", &e);
                }
                self.outbound_exclusions.remove(&reference);
                actions.push(Action::Status {
                    mid: reference,
                    status,
                    detail,
                    service: msg.envelope.fsvc.clone(),
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
            mid: MessageId::from_bytes(lattice_crypto::os_bytes::<16>()),
            from: self.own_id,
            fsvc: delivered.tsvc.clone(),
            fmbx: delivered.tmbx.clone(),
            tsvc: delivered.fsvc.clone(),
            tmbx: delivered.fmbx.clone(),
            created: now,
            body: None,
            reference: Some(delivered.mid),
            reason: None,
            sig: Signature::from_bytes([0; 64]),
        };
        self.enqueue_control(now, delivered.from, envelope)
    }

    fn send_negative_receipt(
        &mut self,
        now: u64,
        original_from: Identifier,
        original: &Envelope,
        reason: u64,
        my_service: &str,
    ) -> Vec<Action> {
        let envelope = Envelope {
            kind: KIND_NEGATIVE_RECEIPT,
            mid: MessageId::from_bytes(lattice_crypto::os_bytes::<16>()),
            from: self.own_id,
            fsvc: my_service.to_string(),
            fmbx: Vec::new(),
            tsvc: original.fsvc.clone(),
            tmbx: original.fmbx.clone(),
            created: now,
            body: None,
            reference: Some(original.mid),
            reason: Some(reason),
            sig: Signature::from_bytes([0; 64]),
        };
        self.enqueue_control(now, original_from, envelope)
    }

    fn enqueue_control(
        &mut self,
        now: u64,
        recipient: Identifier,
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
        if let Err(e) = self.store.outbound_push(&outbound) {
            self.diag("outbound_push", &e);
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

        if now >= self.record_refresh_at {
            self.own_seq += 1;
            if let Err(e) = self.publish_record(now) {
                self.diag("publish_record", &e);
            }
            self.record_refresh_at = now + self.config.record_refresh_secs;
        }

        if now >= self.next_claim_sweep_at {
            self.sweep_ck_claims(now);
            self.next_claim_sweep_at = now + CLAIM_SWEEP_SECS;
        }

        if now >= self.next_data_sweep_at {
            self.sweep_expired_data(now);
            self.next_data_sweep_at = now + DATA_SWEEP_SECS;
        }

        // Expire originated messages.
        match self.store.outbound_all() {
            Ok(all) => {
                for mut msg in all {
                    if matches!(msg.state, OutboundState::Queued | OutboundState::InFlight)
                        && msg.exp <= now
                    {
                        msg.state = OutboundState::Expired;
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                        if let Err(e) = self.store.status_set(
                            &msg.mid,
                            local::MSG_STATUS_EXPIRED,
                            Some(ERR_EXPIRED),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid: msg.mid,
                            status: local::MSG_STATUS_EXPIRED,
                            detail: Some(ERR_EXPIRED),
                            service: msg.envelope.fsvc.clone(),
                        });
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }

        // Receipt deadlines: retry via a fresh waypoint, else fail.
        match self.store.outbound_all() {
            Ok(all) => {
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
                    if msg.attempts > self.config.fresh_waypoint_retries {
                        msg.state = OutboundState::Failed;
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                        if let Err(e) = self.store.status_set(
                            &msg.mid,
                            local::MSG_STATUS_FAILED,
                            Some(ERR_NO_ROUTE),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid: msg.mid,
                            status: local::MSG_STATUS_FAILED,
                            detail: Some(ERR_NO_ROUTE),
                            service: msg.envelope.fsvc.clone(),
                        });
                    } else {
                        msg.state = OutboundState::Queued;
                        msg.next_attempt = now;
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }

        // Custody offers that never got an answer: exclude the link and retry.
        let stale: Vec<LegId> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.sent_at) > CUSTODY_TIMEOUT_SECS)
            .map(|(leg, _)| *leg)
            .collect();
        for leg in stale {
            if let Some(p) = self.pending.remove(&leg) {
                match p.origin {
                    PendingOrigin::Outbound { mid } => {
                        let excl = self.outbound_exclusions.entry(mid).or_default();
                        add_exclusion(excl, p.link, now + self.config.retry_base_secs);
                        for (l, u) in p.excluded {
                            add_exclusion(excl, l, u);
                        }
                        match self.store.outbound_get(&mid) {
                            Ok(Some(mut msg)) => {
                                if msg.state == OutboundState::InFlight {
                                    msg.state = OutboundState::Queued;
                                    msg.next_attempt = now + self.config.retry_base_secs;
                                    if let Err(e) = self.store.outbound_put(&msg) {
                                        self.diag("outbound_put", &e);
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(e) => self.diag("outbound_get", &e),
                        }
                    }
                    PendingOrigin::Relay { custody_leg } => {
                        match self.store.custody_get(&custody_leg) {
                            Ok(Some(mut e)) => {
                                add_exclusion(
                                    &mut e.excluded,
                                    p.link,
                                    now + self.config.retry_base_secs,
                                );
                                for (l, u) in p.excluded {
                                    add_exclusion(&mut e.excluded, l, u);
                                }
                                if let Err(e) = self.store.custody_put(e) {
                                    self.diag("custody_put", &e);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => self.diag("custody_get", &e),
                        }
                        self.forward_custody(now, custody_leg, &mut actions);
                    }
                }
            }
        }

        // Custody entries with nothing in flight get a forwarding attempt.
        // Lower classes first: messages closer to their destination drain
        // first, which is what keeps the class partition deadlock-free.
        match self.store.custody_all() {
            Ok(mut all) => {
                all.sort_by_key(|e| e.class);
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
            Err(e) => self.diag("custody_all", &e),
        }

        // Expire custody entries whose messages timed out.
        match self.store.custody_all() {
            Ok(all) => {
                for entry in all {
                    if entry.exp <= now {
                        match self.store.custody_remove(&entry.leg) {
                            Ok(Some(e)) => {
                                if let Err(e) = self.store.share_add(
                                    &e.destination,
                                    e.upstream,
                                    -(e.message.len() as i64),
                                ) {
                                    self.diag("share_add", &e);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => self.diag("custody_remove", &e),
                        }
                    }
                }
            }
            Err(e) => self.diag("custody_all", &e),
        }

        if let Err(e) = self.store.sweep_expired(now) {
            self.diag("sweep_expired", &e);
        }
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
        if self.config.snow_per_min <= 0.0 {
            // Snow disabled: never originate dummies (echo replies above
            // still work).
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
        // Snow telemetry is best-effort: a failed counter write must not
        // stall sending, and a persistent store failure is surfaced by every
        // other store path, so this drop is deliberate.
        let _ = self.store.size_bucket_sample(bucket.min(2) as u8);
    }

    fn sample_snow_bucket(&mut self) -> usize {
        // On store failure fall back to the in-memory snow histogram rather
        // than failing the send; the persisted counts are only a hint.
        let counts = self.store.size_bucket_counts().unwrap_or(self.snow_history);
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

    fn on_frame(&mut self, at: u64, link: LinkId, from: Identifier, frame: Frame) -> Vec<Action> {
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
                if d.echo && self.inner_pending_echo.len() < MAX_PENDING_ECHOES {
                    // The node's clock has 1s granularity; the spec's "short
                    // random delay" (same distribution as a custody reply,
                    // i.e. ~immediate) is expressed as 0-1 ticks. Sub-second
                    // delay needs a millisecond time base.
                    let jitter = self.rng.next_u64() % 2;
                    self.inner_pending_echo.push((at + jitter, link));
                }
                Vec::new()
            }
            Frame::Attest(a) => self.on_attest(at, link, &a),
            Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => Vec::new(),
        }
    }

    fn on_attest(
        &mut self,
        now: u64,
        link: LinkId,
        a: &lattice_proto::frames::AttestFrame,
    ) -> Vec<Action> {
        // Never let an invalid attestation displace a valid one: a peer
        // that already proved itself keeps its binding even if the peer
        // (or a MITM replaying on the link) sends garbage afterwards.
        let existing = self.links.get(&link).map(|l| (l.remote_ck, l.attestation));
        let keep_old = match existing {
            Some((remote_ck, Some((id, sig)))) => self.attestation_valid(&remote_ck, &id, &sig),
            _ => false,
        };
        if !keep_old {
            if let Some(l) = self.links.get_mut(&link) {
                l.attestation = Some((a.id, a.sig));
            }
        }
        self.reevaluate_link_bindings(now);
        Vec::new()
    }

    /// Split into identity and store, for crash/restart simulation.
    pub fn into_parts(self) -> (Identity, S) {
        (self.identity, self.store)
    }

    /// Rebuild from parts after a simulated crash. The store holds the
    /// pre-crash custody state; the node re-announces nothing and simply
    /// resumes (it holds its own record already).
    pub fn restore(
        config: Config,
        identity: Identity,
        store: S,
        now: u64,
    ) -> Result<Self, NodeError> {
        Self::new(config, identity, store, now)
    }

    /// Swap in a new identity (after a rotation) and republish the record.
    /// The identifier is unchanged by rotation, so the record keeps its id.
    /// `publish` is false for abandonment: peers reject abandoned records at
    /// validation, so there is nothing useful to publish.
    pub fn reload_identity(
        &mut self,
        identity: Identity,
        now: u64,
        publish: bool,
    ) -> Result<(), NodeError> {
        self.identity = identity;
        if !publish {
            return Ok(());
        }
        self.own_seq += 1;
        self.publish_record(now)
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

    /// Bytes currently held in custody (for drain reporting). On store
    /// error, reports 0 and records a diagnostic; the drain report is
    /// best-effort and the daemon logs the diagnostic.
    pub fn custody_bytes(&mut self) -> u64 {
        match self.store.custody_bytes() {
            Ok(v) => v,
            Err(e) => {
                self.diag("custody_bytes", &e);
                0
            }
        }
    }

    /// Is there currently a path to `dst` over the known record graph?
    pub fn has_path(&mut self, dst: &Identifier) -> bool {
        let g = self.build_graph();
        g.distances(&self.own_id).contains_key(dst)
    }

    #[doc(hidden)]
    pub fn debug_contested(&self) -> u64 {
        self.contested
    }

    #[doc(hidden)]
    pub fn debug_equivocations(&self) -> u64 {
        self.equivocations
    }

    /// Peer id a link is currently bound to, if any. Test/diagnostic only.
    #[doc(hidden)]
    pub fn debug_link_peer(&self, link: u64) -> Option<Option<Identifier>> {
        self.links.get(&link).map(|l| l.peer)
    }

    /// Test/diagnostic accessors (not part of the daemon API). Store errors
    /// read as zero/empty and are recorded as diagnostics.
    #[doc(hidden)]
    pub fn debug_custody_count(&mut self) -> usize {
        match self.store.custody_all() {
            Ok(v) => v.len(),
            Err(e) => {
                self.diag("custody_all", &e);
                0
            }
        }
    }

    #[doc(hidden)]
    pub fn debug_custody_classes(&mut self) -> Vec<u8> {
        match self.store.custody_all() {
            Ok(v) => v.into_iter().map(|e| e.class).collect(),
            Err(e) => {
                self.diag("custody_all", &e);
                Vec::new()
            }
        }
    }

    #[doc(hidden)]
    pub fn debug_custody_upstreams(&mut self) -> Vec<u64> {
        match self.store.custody_all() {
            Ok(v) => v.into_iter().map(|e| e.upstream).collect(),
            Err(e) => {
                self.diag("custody_all", &e);
                Vec::new()
            }
        }
    }

    #[doc(hidden)]
    pub fn debug_record_count(&mut self) -> usize {
        match self.store.record_count() {
            Ok(v) => v,
            Err(e) => {
                self.diag("record_count", &e);
                0
            }
        }
    }

    #[doc(hidden)]
    pub fn debug_record_ids(&mut self) -> Vec<Identifier> {
        match self.store.record_all() {
            Ok(v) => v.into_iter().map(|(id, _, _, _)| id).collect(),
            Err(e) => {
                self.diag("record_all", &e);
                Vec::new()
            }
        }
    }

    #[doc(hidden)]
    pub fn store_ref(&self) -> &S {
        &self.store
    }

    /// Mutable access to the store. Bumps the record-set version so the
    /// memoized graph and reconcile items are rebuilt on next use; callers
    /// must not use this to mutate records behind the node's back without
    /// accepting that cost.
    pub fn store_mut(&mut self) -> &mut S {
        self.records_version += 1;
        &mut self.store
    }

    /// (have record, mode as 0=public/1=private)
    pub fn lookup(&mut self, id: &Identifier) -> (bool, Option<u64>) {
        for scope in [
            lattice_proto::record::Scope::Wan,
            lattice_proto::record::Scope::Hive,
        ] {
            match self.store.record_get(id, scope) {
                Ok(Some((bytes, _))) => {
                    let mode =
                        lattice_proto::record::PeerRecord::from_bytes(&bytes, self.now, None)
                            .map(|(r, _)| match r.mode {
                                lattice_proto::record::Mode::Public => 0,
                                lattice_proto::record::Mode::Private => 1,
                            })
                            .ok();
                    return (true, mode);
                }
                Ok(None) => {}
                Err(e) => self.diag("record_get", &e),
            }
        }
        (false, None)
    }

    fn on_app_ack(&mut self, now: u64, service: &str, delivery_ids: &[DeliveryId]) -> Vec<Action> {
        let _ = now;
        if let Err(e) = self.store.inbox_ack(service, delivery_ids) {
            self.diag("inbox_ack", &e);
        }
        let unread = match self.store.inbox_len(service) {
            Ok(v) => v,
            Err(e) => {
                self.diag("inbox_len", &e);
                0
            }
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use lattice_store::{MemStore, OutboundMessage, OutboundState};

    fn test_node() -> Node<MemStore> {
        let cfg = Config {
            snow_per_min: 0.0,
            ..Config::default()
        };
        Node::new(
            cfg,
            Identity::from_seed(&lattice_crypto::os_bytes::<32>()),
            MemStore::new(),
            1_000,
        )
        .expect("node construction")
    }

    fn outbound(mid: MessageId, recipient: Identifier, state: OutboundState) -> OutboundMessage {
        OutboundMessage {
            mid,
            recipient,
            envelope: lattice_proto::message::Envelope {
                kind: KIND_MESSAGE,
                mid,
                from: Identifier::from_bytes([0xF1; 32]),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: "svc".into(),
                tmbx: b"in".to_vec(),
                created: 1,
                body: Some(b"hi".to_vec()),
                reference: None,
                reason: None,
                sig: Signature::from_bytes([0; 64]),
            },
            priority: 1,
            exp: u64::MAX / 2,
            state,
            waypoints_tried: vec![],
            receipt_deadline: Some(u64::MAX / 2),
            attempts: 0,
            next_attempt: 0,
            route: 0,
        }
    }

    fn receipt(kind: u64, reference: MessageId, from: Identifier) -> Envelope {
        Envelope {
            kind,
            mid: MessageId::from_bytes([0xEE; 16]),
            from,
            fsvc: "svc".into(),
            fmbx: b"in".to_vec(),
            tsvc: "svc".into(),
            tmbx: b"out".to_vec(),
            created: 1,
            body: None,
            reference: Some(reference),
            reason: None,
            sig: Signature::from_bytes([0; 64]),
        }
    }

    #[test]
    fn receipt_from_recipient_marks_delivered() {
        let mut node = test_node();
        let recipient = Identifier::from_bytes([0xA1; 32]);
        let mid = MessageId::from_bytes([0x11; 16]);
        node.store
            .outbound_push(&outbound(mid, recipient, OutboundState::InFlight))
            .unwrap();
        let actions = node.on_receipt(1_000, &receipt(KIND_RECEIPT, mid, recipient));
        assert_eq!(actions.len(), 1);
        let msg = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(msg.state, OutboundState::Delivered);
        assert_eq!(
            node.store.status_get(&mid).unwrap().unwrap().0,
            local::MSG_STATUS_DELIVERED
        );
    }

    #[test]
    fn receipt_from_non_recipient_is_ignored() {
        let mut node = test_node();
        let recipient = Identifier::from_bytes([0xA1; 32]);
        let attacker = Identifier::from_bytes([0xB2; 32]);
        let mid = MessageId::from_bytes([0x22; 16]);
        node.store
            .outbound_push(&outbound(mid, recipient, OutboundState::InFlight))
            .unwrap();
        let actions = node.on_receipt(1_000, &receipt(KIND_RECEIPT, mid, attacker));
        assert!(actions.is_empty());
        let msg = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(msg.state, OutboundState::InFlight);
        assert_eq!(node.store.status_get(&mid).unwrap(), None);
        // A negative receipt from a non-recipient is ignored too.
        let actions = node.on_receipt(1_000, &receipt(KIND_NEGATIVE_RECEIPT, mid, attacker));
        assert!(actions.is_empty());
        let msg = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(msg.state, OutboundState::InFlight);
    }

    #[test]
    fn late_receipt_does_not_flip_terminal_states() {
        let mut node = test_node();
        let recipient = Identifier::from_bytes([0xA1; 32]);

        // Expired message stays Expired when a receipt arrives late.
        let mid1 = MessageId::from_bytes([0x33; 16]);
        node.store
            .outbound_push(&outbound(mid1, recipient, OutboundState::Expired))
            .unwrap();
        node.store
            .status_set(&mid1, local::MSG_STATUS_EXPIRED, Some(ERR_EXPIRED))
            .unwrap();
        let actions = node.on_receipt(1_000, &receipt(KIND_RECEIPT, mid1, recipient));
        assert!(actions.is_empty());
        assert_eq!(
            node.store.status_get(&mid1).unwrap().unwrap().0,
            local::MSG_STATUS_EXPIRED
        );
        assert_eq!(
            node.store.outbound_get(&mid1).unwrap().unwrap().state,
            OutboundState::Expired
        );

        // Delivered message stays Delivered when a negative receipt arrives late.
        let mid2 = MessageId::from_bytes([0x44; 16]);
        node.store
            .outbound_push(&outbound(mid2, recipient, OutboundState::Delivered))
            .unwrap();
        node.store
            .status_set(&mid2, local::MSG_STATUS_DELIVERED, None)
            .unwrap();
        let actions = node.on_receipt(1_000, &receipt(KIND_NEGATIVE_RECEIPT, mid2, recipient));
        assert!(actions.is_empty());
        assert_eq!(
            node.store.status_get(&mid2).unwrap().unwrap().0,
            local::MSG_STATUS_DELIVERED
        );
        assert_eq!(
            node.store.outbound_get(&mid2).unwrap().unwrap().state,
            OutboundState::Delivered
        );
    }

    fn test_identity() -> (Identity, SigningSeed, SigningSeed) {
        let signing_seed = SigningSeed::from_bytes([1u8; 32]);
        let next_seed = SigningSeed::from_bytes([2u8; 32]);
        let next_next_seed = SigningSeed::from_bytes([3u8; 32]);
        let inception = KeyEvent::inception(&signing_seed, hash_next(&next_seed));
        let kel = ValidatedKel::validate(vec![inception]).expect("fresh inception validates");
        let kp = lattice_crypto::generate_keypair();
        let id = Identity {
            signing_seed,
            kel,
            channel_seed: ChannelSeed::from_bytes([4u8; 32]),
            xwing_secret: kp.secret,
            xwing_public: kp.public,
            retired_xwing: Vec::new(),
        };
        (id, next_seed, next_next_seed)
    }

    #[test]
    fn rotate_produces_valid_kel_and_preserves_id() {
        let (mut id, next_seed, next_next) = test_identity();
        let id_before = id.id();
        id.rotate(&next_seed, Some(next_next)).unwrap();
        assert_eq!(id.id(), id_before, "identifier must survive rotation");
        assert_eq!(id.kel.len(), 2);
        assert_eq!(id.signing_seed, next_seed);
        assert!(!id.is_abandoned());
        let head = KeyEvent::validate_chain(&id.kel).unwrap();
        assert!(!head.abandoned);
        assert_eq!(head.seq, 1);
    }

    #[test]
    fn rotate_rejects_wrong_next_key() {
        let (mut id, _next_seed, next_next) = test_identity();
        let err = id
            .rotate(&SigningSeed::from_bytes([9u8; 32]), Some(next_next))
            .unwrap_err();
        assert!(
            matches!(err, NodeError::NextKeyMismatch),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn abandon_is_terminal() {
        let (mut id, next_seed, _) = test_identity();
        id.rotate(&next_seed, None).unwrap();
        assert!(id.is_abandoned());
        let err = id
            .rotate(&SigningSeed::from_bytes([7u8; 32]), None)
            .unwrap_err();
        assert!(
            matches!(err, NodeError::Abandoned),
            "unexpected error: {err}"
        );
        let head = KeyEvent::validate_chain(&id.kel).unwrap();
        assert!(head.abandoned);
    }

    fn sealed_message_to(id: &Identity, body: &[u8]) -> lattice_proto::message::Message {
        use lattice_proto::message::{BuildParams, Envelope, KIND_MESSAGE, Message};
        let envelope = Envelope {
            kind: KIND_MESSAGE,
            mid: MessageId::from_bytes([0x42; 16]),
            from: Identifier::from_bytes([0xAA; 32]),
            fsvc: "svc".into(),
            fmbx: b"out".to_vec(),
            tsvc: "svc".into(),
            tmbx: b"in".to_vec(),
            created: 1,
            body: Some(body.to_vec()),
            reference: None,
            reason: None,
            sig: Signature::from_bytes([0; 64]),
        };
        let bytes = Message::build(BuildParams {
            envelope,
            sender_seed: &SigningSeed::from_bytes([0xBB; 32]),
            recipient_ek: &id.xwing_public,
            real_dst: Identifier::from_bytes([0xCC; 32]),
            leg: LegId::from_bytes([0xDD; 16]),
            exp: 2_000_000,
            gateway: None,
            waypoint: None,
        })
        .unwrap();
        Message::parse(&bytes, 1_000_000).unwrap()
    }

    #[test]
    fn envelope_rotation_keeps_old_messages_readable_until_grace_expires() {
        let (mut id, _n, _n2) = test_identity();
        let msg = sealed_message_to(&id, b"hello before rotation");
        // Rotate; old key moves to the retired set with a 2-day grace.
        let now = 1_000_000u64;
        let retire_at = now + 2 * 24 * 3600;
        let old_secret = id.xwing_secret.clone();
        id.rotate_envelope(retire_at);
        assert_ne!(id.xwing_secret, old_secret);
        assert_eq!(id.retired_xwing.len(), 1);
        // The pre-rotation envelope still opens (via the retired key).
        let opened = id
            .open_envelope_any(&msg)
            .expect("retired key must still open");
        assert_eq!(opened.body.as_deref(), Some(&b"hello before rotation"[..]));
        // A new envelope (sealed to the new key) also opens.
        let msg2 = sealed_message_to(&id, b"after rotation");
        let opened2 = id
            .open_envelope_any(&msg2)
            .expect("new key opens new envelopes");
        assert_eq!(opened2.body.as_deref(), Some(&b"after rotation"[..]));
        // After the grace period, the retired key is swept and old mail is unreadable.
        id.sweep_retired_envelope_keys(retire_at + 1);
        assert!(id.retired_xwing.is_empty());
        assert!(id.open_envelope_any(&msg).is_err());
    }

    #[test]
    fn sweep_expired_data_keeps_records_within_grace_and_drops_garbage() {
        use lattice_proto::kel::KeyEvent;
        use lattice_proto::record::{Endpoint, Mode, PeerRecord, RecordParams, Scope};

        let mut node = test_node();
        let seed = lattice_crypto::generate_seed();
        let next_seed = lattice_crypto::generate_seed();
        let kel = vec![KeyEvent::inception(
            &seed,
            Commitment::from_bytes(
                lattice_crypto::hash(lattice_crypto::public_key(&next_seed).as_ref()).into_bytes(),
            ),
        )];
        let channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
        let exp = 10_000u64;
        let rec = PeerRecord::build(
            RecordParams {
                kel,
                seq: 1,
                exp,
                channel_key: lattice_crypto::channel_public(&channel_seed),
                channel_seed,
                envelope_key: XWingPublicKey::from_bytes([7u8; 1216]),
                mode: Mode::Public,
                scope: Scope::Wan,
                endpoints: vec![Endpoint {
                    url: "ws://mesh.example.com/".into(),
                    ips: vec![],
                }],
                links: vec![],
                gateways: vec![],
                capabilities: 0,
            },
            &seed,
        )
        .unwrap();
        let id = rec.id;
        node.store
            .record_put(&id, Scope::Wan, &rec.encode(), 0)
            .unwrap();
        node.store
            .record_put(
                &Identifier::from_bytes([0xAB; 32]),
                Scope::Wan,
                b"garbage",
                0,
            )
            .unwrap();

        // Within the grace window the record must survive; garbage is dropped.
        node.sweep_expired_data(exp + RETENTION_GRACE_SECS - 1);
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_some());
        assert!(
            node.store
                .record_get(&Identifier::from_bytes([0xAB; 32]), Scope::Wan)
                .unwrap()
                .is_none()
        );

        // Past the grace window the expired record is dropped.
        node.sweep_expired_data(exp + RETENTION_GRACE_SECS + 1);
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());
    }
}
