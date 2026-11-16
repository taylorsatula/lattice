//! The sans-IO node state machine. Events in, actions out; all time,
//! randomness and persistence are injected.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lattice_proto::frames::{
    CUSTODY_ACCEPTED, CUSTODY_ALREADY_HAVE, CUSTODY_BUSY, CUSTODY_REFUSED, CUSTODY_SEEN,
    CustodyFrame, DummyFrame, Frame, KelsFrame, OfferFrame, PingFrame, ReconcileFrame,
    RecordsFrame, SCOPE_KEL, WantFrame,
};
use lattice_proto::kel::{KeyEvent, ValidatedKel};
use lattice_proto::local;
use lattice_proto::message::{
    BuildParams, Envelope, GatewaySeal, HopLayerPlain, KIND_MESSAGE, KIND_NEGATIVE_RECEIPT,
    KIND_RECEIPT, Message, WaypointSeal,
};
use lattice_proto::record::{Mode, PeerRecord, Scope, record_order_parts};
use lattice_store::{
    CustodyAccept, CustodyEntry, Exclusion, InboxEntry, KelHeadSeen, OutboundState, Store,
};

use lattice_types::{
    ChannelSeed, Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId, Signature,
    SigningPublicKey, SigningSeed, X25519PublicKey, XWingPublicKey, XWingSecretKey,
};

use crate::error::NodeError;
use crate::graph::Graph;
use crate::outbound::{OutboundMessageExt, OutboundStateExt};
use crate::reconcile::{self, ReconcileSession};
use crate::rng::Rng;
use crate::types::{
    Action, AppSend, Config, Diagnostic, ERR_EXPIRED, ERR_INTERNAL, ERR_NO_RECORD, ERR_NO_ROUTE,
    ERR_REFUSED, Event, LinkId,
};

/// First 8 bytes of the record's hash; the `hash-prefix` used by
/// reconciliation entries (spec §6).
fn record_hash_prefix(bytes: &[u8]) -> [u8; 8] {
    lattice_proto::record::record_hash(bytes).as_bytes()[..8]
        .try_into()
        .expect("hash is 32 bytes")
}

/// Map a payload size to its frame bucket index (2048/4096/8192/32768).
fn bucket_index(len: usize) -> usize {
    if len <= 2048 {
        0
    } else if len <= 4096 {
        1
    } else if len <= 8192 {
        2
    } else {
        3
    }
}

/// Which kind of rotation an identity reload represents.
///
/// `Rotate` publishes the updated record. `Abandon` is a rotation with no
/// next-key commitment: the abandoned KEL is stored and gossiped like any
/// other KEL (it is the only carrier of the abandonment), no further record
/// is published, and the caller then drains. Peers drop the identity's
/// records once they hold the abandoned KEL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationKind {
    Rotate,
    Abandon,
}

/// What a dummy frame asks of the peer: an echo reply, or silence.
/// The wire carries this as `DummyFrame.echo`; this enum is the internal
/// form so call sites don't pass a bare bool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DummyKind {
    Echo,
    Silent,
}

impl From<DummyKind> for bool {
    fn from(kind: DummyKind) -> bool {
        matches!(kind, DummyKind::Echo)
    }
}

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
    pub retired_xwing: Vec<RetiredEnvelopeKey>,
}

/// A retired X-Wing private key kept for decryption, with the unix time
/// after which it must be deleted.
#[derive(Clone)]
pub struct RetiredEnvelopeKey {
    pub secret: XWingSecretKey,
    pub retire_at: u64,
}

/// Result of [`Node::lookup`]: whether a valid record is held, and its
/// mode if so. `Present` with `mode: None` means a record is held but its
/// stored bytes no longer decode (e.g. it expired); the record is still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupResult {
    Absent,
    Present { mode: Option<Mode> },
}

impl Identity {
    /// Rotate the signing key using the pre-committed next key.
    ///
    /// `next_seed` must hash to the current head's `next` commitment.
    /// `new_next_commitment` is the commitment to the following key, which
    /// the caller holds but the daemon never sees; `None` abandons the
    /// identity permanently (a rotation with no next-key commitment).
    pub fn rotate(
        &mut self,
        next_seed: &SigningSeed,
        new_next_commitment: Option<Commitment>,
    ) -> Result<(), NodeError> {
        let committed = self.kel.head().next.ok_or(NodeError::Abandoned)?;
        if hash_next(next_seed) != committed {
            return Err(NodeError::NextKeyMismatch);
        }
        let next_hash = new_next_commitment;
        // The rotation event chains off the last event; the log is
        // non-empty by construction (a validated KEL holds ≥1 event).
        let prev = self.kel.events().last().ok_or(NodeError::EmptyKel)?;
        let event = KeyEvent::rotation(prev, next_seed, next_hash);
        self.kel.append(event)?;
        self.signing_seed = next_seed.clone();
        Ok(())
    }

    /// True if the KEL ends in an abandonment (a rotation with no next-key
    /// commitment). An abandoned identity must not sign or publish; the
    /// abandoned KEL is the only carrier of the abandonment.
    #[must_use]
    pub fn is_abandoned(&self) -> bool {
        self.kel.is_abandoned()
    }

    /// Rotate the envelope key: generate a fresh X-Wing keypair, move the
    /// current private key into the retired set (decrypt-only) until
    /// `retire_at`, and return the new public key.
    pub fn rotate_envelope(&mut self, retire_at: u64) -> XWingPublicKey {
        let kp = lattice_crypto::generate_keypair();
        let old = std::mem::replace(&mut self.xwing_secret, kp.secret);
        self.retired_xwing.push(RetiredEnvelopeKey {
            secret: old,
            retire_at,
        });
        self.xwing_public = kp.public;
        self.xwing_public
    }

    /// Drop retired envelope keys whose grace period has elapsed.
    pub fn sweep_retired_envelope_keys(&mut self, now: u64) {
        self.retired_xwing.retain(|k| k.retire_at > now);
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
                for retired in &self.retired_xwing {
                    if let Ok(e) = msg.open_envelope(&retired.secret) {
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

struct PendingOffer {
    origin: PendingOrigin,
    sent_at: u64,
    excluded: Vec<Exclusion>,
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

/// The parts of an inbound offer the custody-accept path needs,
/// independent of which path (relay, waypoint, gateway) produced it.
struct CustodyOffer {
    leg: LegId,
    message: Vec<u8>,
    destination: Identifier,
    exp: u64,
    class: u8,
    leg_hash: Hash32,
}

struct LinkState {
    /// `None` while the peer's identity is not safely established.
    peer: Option<Identifier>,
    remote_ck: X25519PublicKey,
    /// True when the peer id was pinned by operator config (root `id`); pinned
    /// bindings are never re-derived from records or revoked by contest.
    pinned: bool,
}

/// A dummy frame scheduled to be sent after a short random delay.
#[derive(Clone, Copy)]
struct PendingEcho {
    due: u64,
    link: LinkId,
}

/// Outcome of validating a stored record against the KEL we hold.
enum StoredRecord {
    /// The record is valid (and, if requested, unexpired). Boxed to keep
    /// the enum small.
    Valid(Box<lattice_proto::record::ValidatedRecord>),
    /// The record is unusable: undecodable, unverifiable, or no KEL held.
    Invalid,
    /// The store could not be read; validity is unknown. Callers must not
    /// destroy data on this verdict.
    Unknown,
}

impl StoredRecord {
    /// The validated record, if valid.
    fn valid(self) -> Option<lattice_proto::record::ValidatedRecord> {
        match self {
            StoredRecord::Valid(v) => Some(*v),
            _ => None,
        }
    }
}

/// Outcome of admitting a KEL object from the wire.
enum KelAdmission {
    /// The KEL was stored (or refreshed).
    Stored,
    /// The KEL was rejected: invalid, behind the stored head, or a losing
    /// fork at the same sn.
    Dropped,
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
    outbound_exclusions: HashMap<MessageId, Vec<Exclusion>>,
    snow_next: u64,
    frames_since_snow_tick: u32,
    snow_history: [u64; 4],
    inner_pending_echo: Vec<PendingEcho>,
    record_refresh_at: u64,
    next_reconcile_at: u64,
    rng: Rng,
    now: u64,
    draining: local::DrainState,
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
    /// Memoized public-mode (id, envelope key) pairs for waypoint
    /// selection; same invalidation as `graph_cache`.
    waypoint_cache: Option<(u64, u64, Arc<WaypointCandidates>)>,
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
            own_seq: 0,
            links: HashMap::new(),
            next_link_order: Vec::new(),
            reconcile_sessions: HashMap::new(),
            pending: HashMap::new(),
            outbound_exclusions: HashMap::new(),
            snow_next: now,
            frames_since_snow_tick: 0,
            snow_history: [0; 4],
            inner_pending_echo: Vec::new(),
            record_refresh_at: now + 3600,
            next_reconcile_at: now + 1,
            rng: Rng::new(rng_seed),
            now,
            draining: local::DrainState::Serving,
            ck_claims: HashMap::new(),
            next_claim_sweep_at: now + CLAIM_SWEEP_SECS,
            next_data_sweep_at: now + DATA_SWEEP_SECS,
            contested: 0,
            records_version: 0,
            graph_cache: None,
            items_cache: None,
            waypoint_cache: None,
            record_cache: HashMap::new(),
            diagnostics: Vec::new(),
            outbound_due_failures: 0,
        };
        // Seed the claim set from records already in the store so links can be
        // attributed immediately after a restart. Best-effort: on failure the
        // claims rebuild as records are re-admitted; report it.
        match node.store.record_all() {
            Ok(records) => {
                for record in records {
                    if let Some(parsed) = node.validate_stored(&record.bytes, now, true).valid() {
                        if let Some(k) = Self::claim_key(&parsed) {
                            node.ck_claims.entry(k).or_default().insert(parsed.id);
                        }
                    }
                }
            }
            Err(e) => node.diag("record_all", &e),
        }
        if !own_exists {
            node.publish_record(now)?;
        } else if let Some(stored) = node.store.record_get(&id, Scope::Wan)? {
            node.own_seq = lattice_proto::record::PeerRecord::parse(&stored.bytes)
                .map(|p| p.seq())
                .unwrap_or(0);
        }
        // Serve our own KEL to peers: store it so the `kels` frame can
        // carry it. Unconditional — cheap, and covers stores written by
        // older builds that never kept the object.
        node.store_own_kel(now)?;
        // Crash recovery: anything InFlight at boot may or may not have
        // reached the next hop. Requeue it now; the recipient dedups by mid,
        // so at-least-once survives a restart.
        match node.store.outbound_all() {
            Ok(all) => {
                for mut msg in all {
                    if msg.state == OutboundState::InFlight && msg.requeue(now) {
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
                    Frame::Offer(o) => bucket_index(o.message.len()),
                    Frame::Records(r) => bucket_index(r.records.iter().map(|r| r.len()).sum()),
                    Frame::Kels(k) => bucket_index(k.kels.iter().map(|k| k.len()).sum()),
                    Frame::Init(_)
                    | Frame::Cookie(_)
                    | Frame::Resp(_)
                    | Frame::Custody(_)
                    | Frame::Reconcile(_)
                    | Frame::Want(_)
                    | Frame::Ping(_)
                    | Frame::Dummy(_) => 0,
                };
                // Snow telemetry is best-effort: a failed counter write must
                // not stall frame handling, and a persistent store failure is
                // surfaced by every other store path, so this drop is
                // deliberate.
                let _ = self.store.size_bucket_sample(bucket as u8);
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
            } => self.on_link_up(at, link, peer, remote_ck),
            Event::LinkDown { at, link } => self.on_link_down(at, link),
            Event::Frame {
                at, link, frame, ..
            } => self.on_frame(at, link, frame),
            Event::Tick { at } => self.on_tick(at),
            Event::AppSend(send) => self.on_app_send(&send),
            Event::AppAck {
                service,
                delivery_ids,
                ..
            } => self.on_app_ack(&service, &delivery_ids),
        }
    }
}

impl<S: Store> Node<S> {
    fn touch(&mut self, at: u64) {
        self.now = at;
    }

    // ---------- records ----------

    fn build_own_record(&self, prev_seq: u64, now: u64) -> Result<Vec<u8>, NodeError> {
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
                prev_seq,
                now,
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
                serves: Vec::new(),
            },
            &self.identity.signing_seed,
        )?;
        Ok(rec.encode())
    }

    /// Store our own KEL object so peers can fetch it with a `want` for
    /// scope 255. Called at startup and on every identity reload.
    fn store_own_kel(&mut self, now: u64) -> Result<(), NodeError> {
        let bytes = self.identity.kel.to_object_bytes()?;
        let head = self.identity.kel.head();
        let seen = KelHeadSeen {
            seq: head.seq,
            commitment: head.commitment,
            seen: now,
            abandoned: head.is_abandoned(),
        };
        self.store.kel_put(&self.own_id, &bytes, &seen)?;
        Ok(())
    }

    fn publish_record(&mut self, now: u64) -> Result<(), NodeError> {
        let bytes = self.build_own_record(self.own_seq, now)?;
        let id = self.own_id;
        // Adopt the seq the builder assigned (max(prev + 1, now)).
        if let Ok(parsed) = PeerRecord::parse(&bytes) {
            self.own_seq = parsed.seq();
        }
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
    ) -> Vec<Action> {
        self.touch(at);
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
        // Publish the new link set immediately so peers can route via us.
        if let Err(e) = self.publish_record(at) {
            self.diag("publish_record", &e);
        }
        self.reevaluate_link_bindings(at)
    }

    fn on_link_down(&mut self, at: u64, link: LinkId) -> Vec<Action> {
        self.touch(at);
        self.links.remove(&link);
        self.next_link_order.retain(|l| *l != link);
        self.reconcile_sessions.remove(&link);
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
        let mut records: Vec<RecordParts> = Vec::with_capacity(stored.len());
        for record in &stored {
            if let Some(p) = self.validate_stored(&record.bytes, self.now, true).valid() {
                let r = p.into_inner();
                records.push((record.id, r.links, r.gateways));
            }
        }
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
            .filter_map(|record| {
                // Only unexpired, currently-valid records are advertised.
                let validated = self
                    .validate_stored(&record.bytes, self.now, true)
                    .valid()?;
                Some(reconcile::Item {
                    id: record.id,
                    scope: scope_as_u8(record.scope),
                    khs: validated.khs,
                    seq: validated.seq,
                    hash_prefix: record_hash_prefix(&record.bytes),
                })
            })
            .collect();
        // KELs reconcile in the same set as records (spec §6): scope 255,
        // khs == seq == head sn, hash-prefix = first 8 bytes of the head
        // event's event hash.
        match self.store.kel_heads_all() {
            Ok(heads) => {
                for (id, head) in heads {
                    items.push(reconcile::Item {
                        id,
                        scope: SCOPE_KEL,
                        khs: head.seq,
                        seq: head.seq,
                        hash_prefix: head.commitment.as_bytes()[..8]
                            .try_into()
                            .expect("commitment is 32 bytes"),
                    });
                }
            }
            Err(e) => {
                self.diag("kel_heads_all", &e);
                return None;
            }
        }
        items.sort();
        items.dedup();
        self.items_cache = Some((key.0, key.1, items.clone()));
        Some(items)
    }

    // ---------- reconcile ----------

    fn reconcile_with(&mut self, link: LinkId) -> Vec<Action> {
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

    fn on_reconcile(&mut self, link: LinkId, frame: &ReconcileFrame) -> Vec<Action> {
        // Store unreadable: say nothing rather than claim we hold nothing.
        let Some(items) = self.record_items() else {
            return Vec::new();
        };
        let session = self.reconcile_sessions.entry(link).or_default();
        let reconcile::ReconcileResponse {
            ranges: reply,
            wants,
        } = reconcile::respond(&items, &frame.ranges, session);
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
        // Collect the wanted payloads, then emit frames that fit a bucket;
        // a frame that does not fit cannot be sent at all.
        const MAX_FRAME_PAYLOAD: usize = 30 * 1024;
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut kels: Vec<Vec<u8>> = Vec::new();
        for want in &frame.wants {
            if want.scope == SCOPE_KEL {
                match self.store.kel_get(&want.id) {
                    Ok(Some(bytes)) => kels.push(bytes),
                    Ok(None) => {}
                    Err(e) => self.diag("kel_get", &e),
                }
            } else {
                let scope = scope_from_u8(want.scope);
                match self.store.record_get(&want.id, scope) {
                    Ok(Some(stored)) => records.push(stored.bytes),
                    Ok(None) => {}
                    Err(e) => self.diag("record_get", &e),
                }
            }
        }
        let mut actions = Vec::new();
        let mut chunk: Vec<Vec<u8>> = Vec::new();
        let mut chunk_len = 0usize;
        for r in records {
            if !chunk.is_empty() && chunk_len + r.len() > MAX_FRAME_PAYLOAD {
                actions.push(Self::records_frame(link, std::mem::take(&mut chunk)));
                chunk_len = 0;
            }
            chunk_len += r.len();
            chunk.push(r);
        }
        if !chunk.is_empty() {
            actions.push(Self::records_frame(link, chunk));
        }
        let mut chunk: Vec<Vec<u8>> = Vec::new();
        let mut chunk_len = 0usize;
        for k in kels {
            if !chunk.is_empty() && chunk_len + k.len() > MAX_FRAME_PAYLOAD {
                actions.push(Self::kels_frame(link, std::mem::take(&mut chunk)));
                chunk_len = 0;
            }
            chunk_len += k.len();
            chunk.push(k);
        }
        if !chunk.is_empty() {
            actions.push(Self::kels_frame(link, chunk));
        }
        actions
    }

    fn records_frame(link: LinkId, records: Vec<Vec<u8>>) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Records(RecordsFrame { records }),
        }
    }

    fn kels_frame(link: LinkId, kels: Vec<Vec<u8>>) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Kels(KelsFrame { kels }),
        }
    }

    /// Ask the peer for the KEL for `id` (scope 255). Sent when a record
    /// arrives whose KEL we do not hold or whose head is ahead of ours.
    fn want_kel(&self, link: LinkId, id: Identifier) -> Vec<Action> {
        vec![Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Want(WantFrame {
                wants: vec![lattice_proto::frames::RecordRef {
                    id,
                    scope: SCOPE_KEL,
                }],
            }),
        }]
    }

    fn on_records(&mut self, at: u64, link: LinkId, records: Vec<Vec<u8>>) -> Vec<Action> {
        let mut actions = Vec::new();
        for bytes in records {
            actions.extend(self.admit_record(at, link, &bytes));
        }
        actions
    }

    /// Handle a `kels` frame: validate and store each KEL object. A KEL is
    /// stored only if it extends the stored chain, is identical to it, or
    /// diverges at the same sn with a lower head event hash (spec §2);
    /// anything else is dropped. Storing a KEL whose head moved drops the
    /// stored records that cite the old head.
    fn on_kels(&mut self, at: u64, _link: LinkId, frame: &KelsFrame) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut changed = false;
        let mut abandoned: Vec<Identifier> = Vec::new();
        for bytes in &frame.kels {
            let kel = match ValidatedKel::from_object_bytes(bytes) {
                Ok(k) => k,
                Err(e) => {
                    self.diag("kel_decode", &e);
                    continue;
                }
            };
            match self.admit_kel(at, &kel, bytes) {
                KelAdmission::Stored => {
                    changed = true;
                    if kel.is_abandoned() {
                        abandoned.push(kel.identifier());
                    }
                }
                KelAdmission::Dropped => {}
            }
        }
        if changed {
            self.records_version += 1;
            // The records that cite these KELs can now be validated; ask
            // for them on the next round rather than waiting a full interval.
            self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        }
        for id in abandoned {
            actions.extend(self.drop_records_for(at, &id));
        }
        actions
    }

    /// Validate a KEL object against what we hold and store it if it wins.
    fn admit_kel(&mut self, at: u64, kel: &ValidatedKel, bytes: &[u8]) -> KelAdmission {
        let id = kel.identifier();
        let head = kel.head();
        let stored = match self.store.kel_head(&id) {
            Ok(s) => s,
            Err(e) => {
                self.diag("kel_head", &e);
                return KelAdmission::Dropped;
            }
        };
        let accept = match &stored {
            None => true,
            Some(s) => {
                if head.seq > s.seq {
                    // Accept only a candidate that extends the stored chain:
                    // its event at the stored head's position must hash to
                    // the stored commitment.
                    kel.events()
                        .get(s.seq as usize)
                        .is_some_and(|e| e.commitment() == s.commitment)
                } else if head.seq == s.seq {
                    if head.commitment == s.commitment {
                        true // the same KEL; refresh `seen`
                    } else {
                        // Divergent at the same sn: the lower head event
                        // hash wins (spec §2).
                        lattice_proto::kel::compare_heads(
                            head.seq,
                            &head.commitment,
                            s.seq,
                            &s.commitment,
                        ) == std::cmp::Ordering::Less
                    }
                } else {
                    // A prefix of, or divergent from, a longer known KEL.
                    false
                }
            }
        };
        if !accept {
            return KelAdmission::Dropped;
        }
        let head_seen = lattice_store::KelHeadSeen {
            seq: head.seq,
            commitment: head.commitment,
            seen: at,
            abandoned: head.is_abandoned(),
        };
        let head_changed = stored.as_ref().map(|s| s.commitment) != Some(head.commitment);
        match self.store.kel_put(&id, bytes, &head_seen) {
            Ok(()) => {
                if head_changed {
                    // Records citing the old head are stale now.
                    self.drop_records_for(at, &id);
                }
                KelAdmission::Stored
            }
            Err(e) => {
                self.diag("kel_put", &e);
                KelAdmission::Dropped
            }
        }
    }

    /// Load and validate the KEL stored for `id`. The stored KEL was
    /// validated when it was admitted; it is re-validated here so a corrupt
    /// store fails closed rather than vouching for a bad chain.
    ///
    /// `Ok(None)` means the store definitively holds no KEL for `id`;
    /// `Err(())` means the store could not be read (transient).
    fn load_kel(&mut self, id: &Identifier) -> Result<Option<ValidatedKel>, ()> {
        let bytes = match self.store.kel_get(id) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.diag("kel_get", &e);
                return Err(());
            }
        };
        match ValidatedKel::from_object_bytes(&bytes) {
            Ok(k) => Ok(Some(k)),
            Err(e) => {
                self.diag("kel_decode", &e);
                // A corrupt stored KEL is treated as absent: the record can
                // never be validated against it.
                Ok(None)
            }
        }
    }

    /// Validate stored record bytes against the KEL we hold.
    fn validate_stored(&mut self, bytes: &[u8], now: u64, check_time: bool) -> StoredRecord {
        let parsed = match PeerRecord::parse(bytes) {
            Ok(p) => p,
            Err(_) => return StoredRecord::Invalid,
        };
        let kel = match self.load_kel(&parsed.id()) {
            Ok(Some(k)) => k,
            // No KEL: the record can never be validated.
            Ok(None) => return StoredRecord::Invalid,
            // Store error: unknown, not invalid.
            Err(()) => return StoredRecord::Unknown,
        };
        let result = if check_time {
            parsed.validate(Some(now), &kel)
        } else {
            parsed.validate(None, &kel)
        };
        match result {
            Ok(v) => StoredRecord::Valid(Box::new(v)),
            Err(_) => StoredRecord::Invalid,
        }
    }

    /// Drop every stored record for `id` (both scopes) and any channel-key
    /// claims it held. Used when the KEL head moves or the identity is
    /// abandoned: records citing the old head can never validate again.
    fn drop_records_for(&mut self, at: u64, id: &Identifier) -> Vec<Action> {
        for scope in [Scope::Wan, Scope::Hive] {
            match self.store.record_remove(id, scope) {
                Ok(()) => self.records_version += 1,
                Err(e) => self.diag("record_remove", &e),
            }
        }
        for claims in self.ck_claims.values_mut() {
            claims.remove(id);
        }
        self.reevaluate_link_bindings(at)
    }

    /// Drop claims whose backing record is gone or no longer valid
    /// (expired). Records are never removed from the store today (record
    /// lifecycle is a separate decision), so this keys off validity at
    /// `now`; when a record-expiry sweep lands it will plug in here.
    fn sweep_ck_claims(&mut self, now: u64) -> Vec<Action> {
        let mut fresh: HashMap<X25519PublicKey, std::collections::HashSet<Identifier>> =
            HashMap::new();
        match self.store.record_all() {
            Ok(records) => {
                for record in records {
                    if let Some(parsed) = self.validate_stored(&record.bytes, now, true).valid() {
                        if let Some(k) = Self::claim_key(&parsed) {
                            fresh.entry(k).or_default().insert(parsed.id);
                        }
                    }
                }
            }
            // Keep the old claim set rather than dropping all claims on a
            // transient read failure; report it.
            Err(e) => {
                self.diag("record_all", &e);
                return Vec::new();
            }
        }
        if fresh != self.ck_claims {
            self.ck_claims = fresh;
            return self.reevaluate_link_bindings(now);
        }
        Vec::new()
    }

    /// Retention sweep: drop records and terminal outbound messages past
    /// expiry + grace, and KEL heads not seen for a year. Records are the
    /// only unbounded growth left in the store; everything else already
    /// expires (seen/delivered) or is capped (inbox, custody).
    fn sweep_expired_data(&mut self, now: u64) {
        match self.store.record_all() {
            Ok(records) => {
                for record in records {
                    if record.id == self.own_id {
                        continue;
                    }
                    // Keep records that still validate and are within the
                    // grace period past expiry. Records that no longer
                    // validate (stale KEL, undecodable, KEL swept) are
                    // dropped: they can never be used again. A record we
                    // could not check (store error) is kept.
                    let keep = match self.validate_stored(&record.bytes, now, false) {
                        StoredRecord::Valid(p) => p.exp.saturating_add(RETENTION_GRACE_SECS) >= now,
                        StoredRecord::Invalid => false,
                        StoredRecord::Unknown => true,
                    };
                    if keep {
                        continue;
                    }
                    match self.store.record_remove(&record.id, record.scope) {
                        Ok(()) => self.records_version += 1,
                        Err(e) => self.diag("record_remove", &e),
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
                    let terminal = msg.state.is_terminal();
                    if terminal && msg.exp.saturating_add(RETENTION_GRACE_SECS) < now {
                        if let Err(e) = self.store.outbound_remove(&msg.mid) {
                            self.diag("outbound_remove", &e);
                        }
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }
        match self
            .store
            .kel_sweep(now.saturating_sub(KEL_HEAD_MAX_AGE_SECS))
        {
            Ok(n) => {
                if n > 0 {
                    // The reconcile set changed (KEL entries are gone).
                    self.records_version += 1;
                }
            }
            Err(e) => self.diag("kel_sweep", &e),
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
    /// from signed records (the record's `csig` proves the channel key
    /// endorsed the record) together with the post-handshake check that the
    /// peer's Noise static key equals the channel key in that record; it can
    /// still be poisoned by forged claims, so this fails closed:
    /// misattribution is never published in our record.
    fn reevaluate_link_bindings(&mut self, at: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut changed = false;
        for (link_id, link) in self.links.iter_mut() {
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
                    actions.push(Action::LinkBound {
                        link: *link_id,
                        peer: Some(id),
                    });
                }
                (false, None) => {
                    link.peer = None;
                    changed = true;
                    actions.push(Action::LinkBound {
                        link: *link_id,
                        peer: None,
                    });
                }
            }
        }
        if changed {
            if let Err(e) = self.publish_record(at) {
                self.diag("publish_record", &e);
            }
            self.next_reconcile_at = self.next_reconcile_at.min(at + 1);
        }
        actions
    }

    /// Admit a record into the store. Rejections are silent by design:
    /// the caller (`on_records`) cannot act on them, and store failures
    /// are logged.
    fn admit_record(&mut self, at: u64, link: LinkId, bytes: &[u8]) -> Vec<Action> {
        // Parse once to learn the claimed id and KEL head, then validate
        // exactly once against the KEL we hold.
        let Ok(parsed) = PeerRecord::parse(bytes) else {
            return Vec::new();
        };
        let id = parsed.id();
        let kel = match self.load_kel(&id) {
            Ok(Some(k)) => k,
            // We hold no KEL for this identifier: ask the peer for it and
            // drop the record. Reconciliation re-delivers the record once
            // the KEL arrives.
            Ok(None) => return self.want_kel(link, id),
            // Store error: drop the record; asking for the KEL would not
            // help while the store is unreadable.
            Err(()) => return Vec::new(),
        };
        let head = kel.head();
        if parsed.khs() > head.seq || (parsed.khs() == head.seq && parsed.khc() != head.commitment)
        {
            // The record cites a KEL head we do not hold (ahead of ours, or
            // a fork at the same sn). Ask for the KEL; drop the record.
            return self.want_kel(link, id);
        }
        let Ok(validated) = parsed.validate(Some(at), &kel) else {
            // Stale (cites a head behind ours), malformed, or badly signed.
            return Vec::new();
        };
        // A validated record is evidence the identity is alive; keep its
        // KEL from aging out of the retention sweep.
        if let Err(e) = self.store.kel_touch(&id, at) {
            self.diag("kel_touch", &e);
        }
        let rec = validated.into_inner();
        let scope = rec.scope;
        let existing = match self.store.record_get(&rec.id, scope) {
            Ok(e) => e,
            // Fail closed: without the current row we cannot apply the
            // record order, so keep what we have.
            Err(e) => {
                self.diag("record_get", &e);
                return Vec::new();
            }
        };
        // Total order (khs, seq, record hash): a record supersedes the
        // stored one when it compares greater. Equal (khs, seq) falls back
        // to the lower hash winning (the equivocation rule).
        let mut admit = true;
        if let Some(existing) = &existing {
            // Stored bytes undecodable: admit; the put overwrites them.
            if let Ok(old) = PeerRecord::parse(&existing.bytes) {
                let ord = record_order_parts(
                    rec.khs,
                    rec.seq,
                    &lattice_proto::record::record_hash(bytes),
                    old.khs(),
                    old.seq(),
                    &lattice_proto::record::record_hash(&existing.bytes),
                );
                if ord == std::cmp::Ordering::Less {
                    admit = false; // keep ours
                }
            }
        }
        if admit {
            match self.store.record_put(&rec.id, scope, bytes, at) {
                Ok(()) => self.records_version += 1,
                Err(e) => self.diag("record_put", &e),
            }
            self.note_ck_claim(&rec);
            return self.reevaluate_link_bindings(at);
        }
        Vec::new()
    }
}

// ============================================================
// Messaging engine
// ============================================================

/// The wire bytes of a built message and the waypoint it was sealed to, if any.
struct BuildOutput {
    wire: Vec<u8>,
    waypoint: Option<Identifier>,
}

/// The next hop for a message: the link to send on and the peer at the
/// other end.
struct NextHop {
    link: LinkId,
    peer: Identifier,
}

/// A public-mode (id, envelope key) pair eligible for waypoint selection.
#[derive(Clone)]
struct WaypointChoice {
    id: Identifier,
    envelope_key: XWingPublicKey,
}

/// Public-mode (id, envelope key) pairs eligible for waypoint selection.
type WaypointCandidates = Vec<WaypointChoice>;

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
    fn on_app_send(&mut self, send: &AppSend) -> Vec<Action> {
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

    /// Presence check for a usable record. Validation happens (and is
    /// memoized) downstream.
    #[must_use]
    fn has_record(&mut self, id: &Identifier) -> bool {
        self.lookup_validated(id).is_some()
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
            Ok(Some(stored)) => self
                .validate_stored(&stored.bytes, self.now, true)
                .valid()
                .map(|v| v.into_inner()),
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
    /// A retry (`attempts > 0` on entry) forces waypoint routing: the direct
    /// path already failed once. Counts the attempt, so this is the one
    /// place `attempts` is incremented.
    fn build_attempt(
        &mut self,
        msg: &mut lattice_store::OutboundMessage,
    ) -> Result<BuildOutput, BuildError> {
        let force_waypoint = msg.attempts > 0;
        msg.attempts += 1;
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
        let real_dst = gateway_choice.as_ref().map_or(msg.recipient, |(g, _)| *g);
        let gateway = gateway_choice.map(|(_g, gateway_ek)| GatewaySeal {
            gateway_ek,
            rcpt: msg.recipient,
        });
        let waypoint = waypoint_choice.map(|choice| WaypointSeal {
            waypoint_id: choice.id,
            waypoint_ek: choice.envelope_key,
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
        Ok(BuildOutput {
            wire,
            waypoint: used_waypoint_id,
        })
    }

    fn pick_waypoint(
        &mut self,
        recipient: &Identifier,
        exclude: &[Identifier],
    ) -> Option<WaypointChoice> {
        // Spec: exclude the sender's own links and the recipient's gateways
        // (a gateway is already the entry point; it is not a waypoint).
        let own_links: HashSet<Identifier> = self.links.values().filter_map(|l| l.peer).collect();
        let recipient_gateways: HashSet<Identifier> =
            self.record_gateways(recipient).into_iter().collect();
        let cached = self.waypoint_candidates()?;
        let mut candidates: Vec<WaypointChoice> = cached
            .iter()
            .filter(|c| {
                c.id != self.own_id
                    && &c.id != recipient
                    && !exclude.contains(&c.id)
                    && !own_links.contains(&c.id)
                    && !recipient_gateways.contains(&c.id)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let idx = (self.rng.next_u64() as usize) % candidates.len();
        Some(candidates.swap_remove(idx))
    }

    /// Public-mode (id, envelope key) pairs from the store, memoized on
    /// `(records_version, now)` like the graph cache. On store failure
    /// there is no candidate set; report and skip waypoint selection (a
    /// direct route may still work).
    fn waypoint_candidates(&mut self) -> Option<Arc<WaypointCandidates>> {
        let key = (self.records_version, self.now);
        if let Some((v, t, cached)) = &self.waypoint_cache {
            if (*v, *t) == key {
                return Some(Arc::clone(cached));
            }
        }
        let stored = match self.store.record_all() {
            Ok(records) => records,
            Err(e) => {
                self.diag("record_all", &e);
                return None;
            }
        };
        let mut candidates: WaypointCandidates = Vec::new();
        for record in &stored {
            if let Some(parsed) = self.validate_stored(&record.bytes, self.now, true).valid() {
                if parsed.mode == Mode::Public {
                    candidates.push(WaypointChoice {
                        id: record.id,
                        envelope_key: parsed.envelope_key,
                    });
                }
            }
        }
        let candidates = Arc::new(candidates);
        self.waypoint_cache = Some((key.0, key.1, Arc::clone(&candidates)));
        Some(candidates)
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
            match self.build_attempt(&mut msg) {
                Ok(built) => {
                    match self.dispatch_wire(now, &built.wire, &msg, &mut actions) {
                        DispatchResult::Sent => {
                            if let Some(wp) = built.waypoint {
                                msg.waypoints_tried.push(wp);
                            }
                            msg.mark_in_flight();
                            msg.next_attempt = now + self.config.retry_base_secs;
                            // The receipt clock starts when the message
                            // actually goes on the wire, not at enqueue.
                            msg.receipt_deadline = Some(now + self.receipt_timeout_for(&msg));
                            if let Err(e) = self.store.outbound_put(&msg) {
                                self.diag("outbound_put", &e);
                            }
                        }
                        DispatchResult::NoRoute => {
                            msg.requeue(now + self.backoff(msg.attempts));
                            if let Err(e) = self.store.outbound_put(&msg) {
                                self.diag("outbound_put", &e);
                            }
                        }
                    }
                }
                Err(BuildError::NoRoute) => {
                    if msg.attempts > self.config.fresh_waypoint_retries + 1 {
                        msg.mark_failed();
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
                    msg.mark_failed();
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
        exclude: &[Exclusion],
        now: u64,
    ) -> Option<NextHop> {
        // A directly connected peer is always one hop away, even when the
        // record graph has no path to it (a private instance publishes no
        // links). Honor exclusions like any other hop.
        if let Some((id, _)) = self.links.iter().find(|(id, l)| {
            l.peer == Some(*dst) && !exclude.iter().any(|e| e.link == **id && e.until > now)
        }) {
            return Some(NextHop {
                link: *id,
                peer: *dst,
            });
        }
        // Distances are measured from the destination; the graph is undirected,
        // so BFS from dst gives each node's distance to the destination.
        let graph = self.build_graph();
        let dist = graph.distances(dst);
        let excluded_peers: HashSet<Identifier> = exclude
            .iter()
            .filter(|e| e.until > now)
            .filter_map(|e| self.links.get(&e.link).and_then(|s| s.peer))
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
        Some(NextHop { link, peer })
    }

    fn dispatch_wire(
        &mut self,
        now: u64,
        wire: &[u8],
        msg: &lattice_store::OutboundMessage,
        actions: &mut Vec<Action>,
    ) -> DispatchResult {
        let Ok(parsed) = Message::parse(wire, now) else {
            return DispatchResult::NoRoute;
        };
        let dst = parsed.header.dst;
        let leg = parsed.header.leg;
        let exclusion = self.outbound_exclusions.entry(msg.mid).or_default();
        exclusion.retain(|e| e.until > now);
        let exclusion = exclusion.clone();
        let Some(NextHop { link, peer: _peer }) = self.pick_next_hop(&dst, &exclusion, now) else {
            return DispatchResult::NoRoute;
        };
        // Mark the leg seen as it goes on the wire, so the leg cannot
        // bounce back to us and be mistaken for a fresh offer (or delete
        // state on an `already have` answer).
        let leg_hash = lattice_crypto::hash(leg.as_ref());
        if let Err(e) = self.store.seen_add(leg_hash, parsed.header.exp) {
            self.diag("seen_add", &e);
        }
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
    /// True when the offer is a receipt (or negative receipt) whose envelope
    /// opens for this node. Such an offer terminates here and takes no relay
    /// custody, so a draining node still accepts it.
    fn offer_is_receipt_for_us(&self, msg: &lattice_proto::message::Message) -> bool {
        let for_us = msg.header.dst == self.own_id
            || (msg.hop_layer.is_none()
                && self.config.gateways.iter().any(|g| g == &msg.header.dst));
        if !for_us {
            return false;
        }
        match self.identity.open_envelope_any(msg) {
            Ok(opened) => opened.kind == KIND_RECEIPT || opened.kind == KIND_NEGATIVE_RECEIPT,
            Err(_) => false,
        }
    }

    fn on_offer(&mut self, now: u64, link: LinkId, offer: &OfferFrame) -> Vec<Action> {
        let mut actions = Vec::new();
        // Undecodable: no leg to answer to; drop.
        let Ok(msg) = Message::parse(&offer.message, now) else {
            return actions;
        };
        let leg = msg.header.leg;
        // A draining node refuses new custody, but a receipt addressed to
        // this node creates none: refusing it would only hide the fact that
        // an outbound message was delivered. Receipts (and negative
        // receipts) addressed to us are let through.
        if self.draining.is_draining() && !self.offer_is_receipt_for_us(&msg) {
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
            // The message is held (custody, inbox, or our own outbound).
            actions.push(Self::already_have(link, leg));
            return actions;
        }
        // Seen but not held (refused or dropped earlier): SEEN. On store
        // error, fail toward SEEN: never reprocess a leg we cannot account
        // for.
        let unheld = match self.store.seen_unheld_contains(&leg_hash, now) {
            Ok(v) => v,
            Err(e) => {
                self.diag("seen_unheld_contains", &e);
                true
            }
        };
        if unheld {
            actions.push(Self::seen(link, leg));
            return actions;
        }
        let dst = msg.header.dst;

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
        self.accept_custody(
            now,
            link,
            CustodyOffer {
                leg,
                message: offer.message.clone(),
                destination: dst,
                exp: msg.header.exp,
                class,
                leg_hash,
            },
            &mut actions,
        );
        actions
    }

    /// Fair-share check for a destination on an upstream link. On store
    /// error, fail closed (treat the allowance as exhausted) and report.
    #[must_use]
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
    #[must_use]
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

    /// The custody-accepted frame for `leg`.
    fn custody_accepted(link: LinkId, leg: LegId) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_ACCEPTED,
                retry_after: None,
            }),
        }
    }

    /// The custody-already-have frame for `leg`.
    fn already_have(link: LinkId, leg: LegId) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_ALREADY_HAVE,
                retry_after: None,
            }),
        }
    }

    /// The custody-seen frame for `leg`: the leg was seen but the message
    /// is not held (it was refused or dropped). The sender tries elsewhere.
    fn seen(link: LinkId, leg: LegId) -> Action {
        Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Custody(CustodyFrame {
                leg,
                result: CUSTODY_SEEN,
                retry_after: None,
            }),
        }
    }

    /// Shared tail of the three custody-accept paths (relay, waypoint,
    /// gateway): fair-share and transit-cap checks, the custody-entry
    /// write, the ACCEPTED frame, and the forwarding kick. `class` is
    /// computed by the caller (relay: distance class; waypoint/gateway:
    /// `class_for`). On rejection the appropriate reply (busy) is pushed
    /// onto `actions`.
    fn accept_custody(
        &mut self,
        now: u64,
        link: LinkId,
        offer: CustodyOffer,
        actions: &mut Vec<Action>,
    ) {
        let CustodyOffer {
            leg,
            message,
            destination,
            exp,
            class,
            leg_hash,
        } = offer;
        let msg_len = message.len() as u64;
        // Fair-share accounting is per (destination, upstream link): each
        // upstream gets custody_allowance/N per destination. The spec's
        // wording suggests a per-upstream aggregate cap; the per-destination
        // form is strictly more permissive for single-destination floods and
        // equivalent otherwise. If per-upstream aggregate accounting is ever
        // wanted, add a second counter keyed by upstream alone and check both
        // here — the store already keys shares by (dest, upstream).
        if self.share_exceeded(&destination, link, msg_len) {
            actions.push(self.busy(link, leg));
            return;
        }
        // Merlin-Schweitzer buffer classes: each class gets an equal slice
        // of the transit cap, so a flood in one class cannot starve the
        // others and waits can't form a cycle (a class-d message only ever
        // waits on class < d room at the next hop).
        if self.class_full(class, msg_len) {
            actions.push(self.busy(link, leg));
            return;
        }
        let entry = CustodyEntry {
            leg,
            message,
            upstream: link,
            destination,
            class,
            exp,
            // Never hand the message back to the link it arrived on.
            excluded: vec![Exclusion { link, until: exp }],
        };
        let accept = CustodyAccept {
            entry,
            share_dest: destination,
            share_upstream: link,
            share_bytes: msg_len as i64,
            seen_hash: leg_hash,
            seen_exp: exp,
        };
        if let Err(e) = self.store.custody_accept(accept) {
            self.diag("custody_accept", &e);
            actions.push(self.busy(link, leg));
            return;
        }
        actions.push(Self::custody_accepted(link, leg));
        self.forward_custody(now, leg, actions);
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
                        actions.push(Self::refuse(link, leg));
                        return actions;
                    }
                    let hdr_dst = hdr.dst;
                    let hdr_exp = hdr.exp;
                    let Ok(inner) = msg
                        .clone()
                        .into_after_waypoint(HopLayerPlain::Waypoint { hdr, inner })
                    else {
                        actions.push(Self::refuse(link, leg));
                        return actions;
                    };
                    // A waypoint accepts the first leg only if it can hold the
                    // second leg: fair-share + transit cap apply, same as relay.
                    let class = self.class_for(&hdr_dst);
                    self.accept_custody(
                        now,
                        link,
                        CustodyOffer {
                            leg,
                            message: inner,
                            destination: hdr_dst,
                            exp: hdr_exp,
                            class,
                            leg_hash: *leg_hash,
                        },
                        &mut actions,
                    );
                    return actions;
                }
                Ok(HopLayerPlain::Gateway { rcpt }) => {
                    // The private recipient cannot open the gateway layer
                    // (it is sealed to us), so it is stripped before the
                    // message is stored and forwarded. Header and envelope
                    // are unchanged: the header is the envelope's AAD.
                    let Ok(stripped) = msg.clone().into_after_gateway() else {
                        actions.push(Self::refuse(link, leg));
                        return actions;
                    };
                    let class = self.class_for(&rcpt);
                    self.accept_custody(
                        now,
                        link,
                        CustodyOffer {
                            leg,
                            message: stripped,
                            destination: rcpt,
                            exp: msg.header.exp,
                            class,
                            leg_hash: *leg_hash,
                        },
                        &mut actions,
                    );
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
        let Ok(opened) = self.identity.open_envelope_any(msg) else {
            actions.push(Self::refuse(link, leg));
            return actions;
        };
        if opened.validate_created(now).is_err() {
            // Absurd `created` (future beyond skew, or older than the
            // message horizon): refuse custody rather than store or relay it.
            actions.push(Self::refuse(link, leg));
            return actions;
        }
        let Some(key) = self.signing_key_for(&opened.from) else {
            // No record for the sender; cannot verify. Ask for it via the
            // normal path by refusing softly (busy): the sender retries
            // after gossip delivers the record.
            actions.push(self.busy(link, leg));
            return actions;
        };
        if !opened.verify_signature(&key, msg.routing_header_bytes()) {
            // Well-formed envelope, bad signature: the claimed sender is
            // unauthenticated, so a negative receipt would be a reflection
            // vector. Refuse custody and send nothing.
            if let Err(e) = self.store.seen_unheld_add(*leg_hash, msg.header.exp) {
                self.diag("seen_unheld_add", &e);
            }
            actions.push(Self::refuse(link, leg));
            return actions;
        }
        if opened.kind == KIND_RECEIPT || opened.kind == KIND_NEGATIVE_RECEIPT {
            // Receipts get custody-acknowledged but never receipt-replied (no ping-pong).
            if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
                self.diag("seen_add", &e);
            }
            actions.extend(self.on_receipt(&opened));
            actions.push(Self::custody_accepted(link, leg));
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
        // An unknown tsvc must not consume the shared inbox cap: record the
        // mid as delivered so redeliveries dedup, and answer with a negative
        // receipt instead of storing or delivering.
        if !self.config.services.iter().any(|s| s == &opened.tsvc) {
            if !already_delivered {
                if let Err(e) = self.store.delivered_add(mid_hash, msg.header.exp) {
                    self.diag("delivered_add", &e);
                }
            }
            if let Err(e) = self.store.seen_unheld_add(*leg_hash, msg.header.exp) {
                self.diag("seen_unheld_add", &e);
            }
            actions.push(if already_delivered {
                Self::already_have(link, leg)
            } else {
                Self::custody_accepted(link, leg)
            });
            actions.extend(self.send_negative_receipt(
                now,
                opened.from,
                &opened,
                lattice_proto::message::REASON_UNKNOWN_SERVICE,
                &opened.tsvc,
            ));
            return actions;
        }
        if already_delivered {
            if let Err(e) = self.store.seen_add(*leg_hash, msg.header.exp) {
                self.diag("seen_add", &e);
            }
            actions.extend(self.send_receipt(now, &opened));
            actions.push(Self::already_have(link, leg));
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
        actions.push(Self::custody_accepted(link, leg));
        actions.extend(self.send_receipt(now, &opened));
        actions
    }

    fn refuse(link: LinkId, leg: LegId) -> Action {
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
        let offer_leg =
            lattice_proto::Message::parse(&entry.message, now).map_or(entry.leg, |m| m.header.leg);
        let excluded: Vec<Exclusion> = entry
            .excluded
            .iter()
            .filter(|e| e.until > now)
            .copied()
            .collect();
        let Some(NextHop {
            link: next_link,
            peer: _peer,
        }) = self.pick_next_hop(&dst, &excluded, now)
        else {
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
        // A custody reply is only meaningful on the link the offer went
        // out on. Leg ids are visible to every hop on the path, so a reply
        // from any other link is ignored and the pending entry kept.
        if let Some(p) = self.pending.get(&leg) {
            if p.link != link {
                self.diag(
                    "custody_reply_wrong_link",
                    "custody reply arrived on a different link than the offer",
                );
                return actions;
            }
        }
        let pending = self.pending.remove(&leg);
        match frame.result {
            CUSTODY_ACCEPTED => self.custody_accepted_reply(pending, &mut actions),
            // SEEN behaves like ALREADY_HAVE for the sender: exclude the
            // link for this leg and choose again; custody is kept.
            CUSTODY_ALREADY_HAVE | CUSTODY_SEEN | CUSTODY_BUSY => {
                self.custody_busy_reply(now, link, frame, pending, &mut actions)
            }
            CUSTODY_REFUSED => self.custody_refused_reply(pending, &mut actions),
            _ => {}
        }
        actions
    }

    /// Load an outbound message, reporting store errors. `None` means "not
    /// found or unreadable"; callers treat both as "nothing to update".
    fn load_outbound(&mut self, mid: &MessageId) -> Option<lattice_store::OutboundMessage> {
        match self.store.outbound_get(mid) {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => None,
            Err(e) => {
                self.diag("outbound_get", &e);
                None
            }
        }
    }

    fn store_outbound(&mut self, msg: &lattice_store::OutboundMessage) {
        if let Err(e) = self.store.outbound_put(msg) {
            self.diag("outbound_put", &e);
        }
    }

    /// Drop a relay custody entry and release its share of the upstream's
    /// allowance. Used when the downstream side resolves (accepted or
    /// refused). `ALREADY_HAVE` does not release: the downstream may only
    /// have seen the leg, not hold the message.
    fn release_relay_custody(&mut self, custody_leg: LegId) {
        match self.store.custody_remove(&custody_leg) {
            Ok(Some(e)) => {
                if let Err(e) =
                    self.store
                        .share_add(&e.destination, e.upstream, -(e.message.len() as i64))
                {
                    self.diag("share_add", &e);
                }
            }
            Ok(None) => {}
            Err(e) => self.diag("custody_remove", &e),
        }
    }

    fn custody_accepted_reply(&mut self, pending: Option<PendingOffer>, actions: &mut Vec<Action>) {
        match pending.map(|p| p.origin) {
            Some(PendingOrigin::Outbound { mid }) => {
                let mut service = String::new();
                if let Some(mut msg) = self.load_outbound(&mid) {
                    msg.mark_in_flight();
                    service.clone_from(&msg.envelope.fsvc);
                    self.store_outbound(&msg);
                }
                if let Err(e) = self
                    .store
                    .status_set(&mid, local::MSG_STATUS_IN_TRANSIT, None)
                {
                    self.diag("status_set", &e);
                }
                actions.push(Action::Status {
                    mid,
                    status: local::MSG_STATUS_IN_TRANSIT,
                    detail: None,
                    service,
                });
            }
            Some(PendingOrigin::Relay { custody_leg }) => self.release_relay_custody(custody_leg),
            None => {}
        }
    }

    fn custody_busy_reply(
        &mut self,
        now: u64,
        link: LinkId,
        frame: &CustodyFrame,
        pending: Option<PendingOffer>,
        actions: &mut Vec<Action>,
    ) {
        let busy = frame.result == CUSTODY_BUSY;
        let retry = frame
            .retry_after
            .unwrap_or(self.config.retry_base_secs)
            .clamp(1, 3600);
        let Some(p) = pending else { return };
        match p.origin {
            PendingOrigin::Outbound { mid } => {
                if let Some(mut msg) = self.load_outbound(&mid) {
                    let until = if busy { now + retry } else { msg.exp };
                    add_exclusion(
                        self.outbound_exclusions.entry(mid).or_default(),
                        link,
                        until,
                    );
                    msg.requeue(now + if busy { retry } else { 0 });
                    self.store_outbound(&msg);
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
                    self.forward_custody(now, custody_leg, actions);
                } else {
                    // ALREADY_HAVE or SEEN: the downstream holds the message
                    // or saw the leg. Keep custody, exclude that link for
                    // this leg, and re-forward via another candidate.
                    // Custody is released only on ACCEPTED or REFUSED.
                    match self.store.custody_get(&custody_leg) {
                        Ok(Some(mut e)) => {
                            add_exclusion(&mut e.excluded, link, e.exp);
                            if let Err(e) = self.store.custody_put(e) {
                                self.diag("custody_put", &e);
                            }
                        }
                        Ok(None) => {}
                        Err(e) => self.diag("custody_get", &e),
                    }
                    self.forward_custody(now, custody_leg, actions);
                }
            }
        }
    }

    fn custody_refused_reply(&mut self, pending: Option<PendingOffer>, actions: &mut Vec<Action>) {
        let Some(p) = pending else { return };
        match p.origin {
            PendingOrigin::Outbound { mid } => {
                let mut service = String::new();
                if let Some(mut msg) = self.load_outbound(&mid) {
                    msg.mark_failed();
                    self.outbound_exclusions.remove(&msg.mid);
                    service.clone_from(&msg.envelope.fsvc);
                    self.store_outbound(&msg);
                }
                if let Err(e) =
                    self.store
                        .status_set(&mid, local::MSG_STATUS_FAILED, Some(ERR_REFUSED))
                {
                    self.diag("status_set", &e);
                }
                actions.push(Action::Status {
                    mid,
                    status: local::MSG_STATUS_FAILED,
                    detail: Some(ERR_REFUSED),
                    service,
                });
            }
            PendingOrigin::Relay { custody_leg } => self.release_relay_custody(custody_leg),
        }
    }

    fn on_receipt(&mut self, envelope: &Envelope) -> Vec<Action> {
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
            Ok(Some(s)) => terminal_status(s.status),
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
                let was_active = !msg.state.is_terminal();
                if was_active {
                    if envelope.kind == KIND_RECEIPT {
                        msg.mark_delivered();
                    } else {
                        msg.mark_failed();
                    }
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
        actions.extend(self.reconcile_if_due(now));
        self.refresh_record_if_due(now);
        actions.extend(self.sweep_claims_if_due(now));
        self.sweep_data_if_due(now);
        actions.extend(self.expire_outbound(now));
        actions.extend(self.sweep_receipt_deadlines(now));
        actions.extend(self.sweep_stale_custody(now));
        actions.extend(self.drain_custody(now));
        self.sweep_custody_expiry(now);
        self.sweep_store_expired(now);
        actions.extend(self.pump_outbound(now));
        actions
    }

    /// Reconcile with a random link when the interval has elapsed.
    fn reconcile_if_due(&mut self, now: u64) -> Vec<Action> {
        if now < self.next_reconcile_at {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if let Some(link) = self.random_link() {
            actions.extend(self.reconcile_with(link));
        }
        self.next_reconcile_at = now + self.config.reconcile_interval_secs;
        actions
    }

    /// Republish our record when the refresh interval has elapsed.
    fn refresh_record_if_due(&mut self, now: u64) {
        if now < self.record_refresh_at {
            return;
        }
        if let Err(e) = self.publish_record(now) {
            self.diag("publish_record", &e);
        }
        self.record_refresh_at = now + self.config.record_refresh_secs;
    }

    fn sweep_claims_if_due(&mut self, now: u64) -> Vec<Action> {
        if now < self.next_claim_sweep_at {
            return Vec::new();
        }
        let actions = self.sweep_ck_claims(now);
        self.next_claim_sweep_at = now + CLAIM_SWEEP_SECS;
        actions
    }

    fn sweep_data_if_due(&mut self, now: u64) {
        if now < self.next_data_sweep_at {
            return;
        }
        self.sweep_expired_data(now);
        self.next_data_sweep_at = now + DATA_SWEEP_SECS;
    }

    /// Expire originated messages whose horizon has passed.
    fn expire_outbound(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        match self.store.outbound_all() {
            Ok(all) => {
                for mut msg in all {
                    if !msg.state.is_terminal() && msg.exp <= now {
                        msg.mark_expired();
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
        actions
    }

    /// Receipt deadlines: retry via a fresh waypoint, else fail.
    fn sweep_receipt_deadlines(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
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
                        msg.mark_failed();
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
                        msg.requeue(now);
                        if let Err(e) = self.store.outbound_put(&msg) {
                            self.diag("outbound_put", &e);
                        }
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }
        actions
    }

    /// Custody offers that never got an answer: exclude the link and retry.
    fn sweep_stale_custody(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
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
                        for e in p.excluded {
                            add_exclusion(excl, e.link, e.until);
                        }
                        match self.store.outbound_get(&mid) {
                            Ok(Some(mut msg)) => {
                                if msg.state == OutboundState::InFlight {
                                    msg.requeue(now + self.config.retry_base_secs);
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
                                for ex in p.excluded {
                                    add_exclusion(&mut e.excluded, ex.link, ex.until);
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
        actions
    }

    /// Custody entries with nothing in flight get a forwarding attempt.
    /// Lower classes first: messages closer to their destination drain
    /// first, which is what keeps the class partition deadlock-free.
    fn drain_custody(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        match self.store.custody_all() {
            Ok(mut all) => {
                all.sort_by_key(|e| e.class);
                for entry in all {
                    let offer_leg = lattice_proto::Message::parse(&entry.message, now)
                        .map_or(entry.leg, |m| m.header.leg);
                    let in_flight = self.pending.contains_key(&offer_leg);
                    if !in_flight {
                        self.forward_custody(now, entry.leg, &mut actions);
                    }
                }
            }
            Err(e) => self.diag("custody_all", &e),
        }
        actions
    }

    /// Expire custody entries whose messages timed out.
    fn sweep_custody_expiry(&mut self, now: u64) {
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
    }

    fn sweep_store_expired(&mut self, now: u64) {
        if let Err(e) = self.store.sweep_expired(now) {
            self.diag("sweep_expired", &e);
        }
    }

    /// Build a dummy whose padded size lands in the given bucket class
    /// (0=2K, 1=8K, 2=32K). Sizes approximate frame overhead.
    fn dummy_frame(kind: DummyKind) -> Frame {
        // Bucket selection happens at the transport: the frame is padded
        // into the sampled bucket via `Action::SendFrame::pad_to`.
        Frame::Dummy(DummyFrame { echo: kind.into() })
    }

    fn random_link(&mut self) -> Option<LinkId> {
        let len = self.next_link_order.len();
        if len == 0 {
            return None;
        }
        let idx = self.rng.below(len as u64) as usize;
        Some(self.next_link_order[idx])
    }

    fn snow_tick(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let due: Vec<PendingEcho> = self
            .inner_pending_echo
            .iter()
            .filter(|p| p.due <= now)
            .copied()
            .collect();
        self.inner_pending_echo.retain(|p| p.due > now);
        for echo in due {
            let link = echo.link;
            if self.links.contains_key(&link) {
                let bucket = self.sample_snow_bucket();
                actions.push(Action::SendFrame {
                    pad_to: Some(bucket),
                    link,
                    frame: Self::dummy_frame(DummyKind::Silent),
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
                frame: Self::dummy_frame(if echo {
                    DummyKind::Echo
                } else {
                    DummyKind::Silent
                }),
            });
            self.note_snow_send(b);
        }
        actions
    }

    fn note_snow_send(&mut self, bucket: usize) {
        self.snow_history[bucket.min(3)] += 1;
        // Snow telemetry is best-effort: a failed counter write must not
        // stall sending, and a persistent store failure is surfaced by every
        // other store path, so this drop is deliberate.
        let _ = self.store.size_bucket_sample(bucket.min(3) as u8);
    }

    fn sample_snow_bucket(&mut self) -> usize {
        // On store failure fall back to the in-memory snow histogram rather
        // than failing the send; the persisted counts are only a hint.
        let counts = self.store.size_bucket_counts().unwrap_or(self.snow_history);
        let min_share = 0.10f64;
        let total: f64 = counts.iter().map(|&c| c as f64).sum();
        let mut weights = [0.0f64; 4];
        for b in 0..4 {
            let base = if total > 0.0 {
                counts[b] as f64 / total
            } else {
                1.0 / 4.0
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
        3
    }

    fn rng_float(&mut self) -> f64 {
        self.rng.next_u64() as f64 / u64::MAX as f64
    }

    fn on_frame(&mut self, at: u64, link: LinkId, frame: Frame) -> Vec<Action> {
        self.now = at;
        match frame {
            Frame::Offer(offer) => self.on_offer(at, link, &offer),
            Frame::Custody(custody) => self.on_custody_reply(at, link, &custody),
            Frame::Reconcile(rec) => self.on_reconcile(link, &rec),
            Frame::Want(want) => self.on_want(link, &want),
            Frame::Records(recs) => self.on_records(at, link, recs.records),
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
                    self.inner_pending_echo.push(PendingEcho {
                        due: at + jitter,
                        link,
                    });
                }
                Vec::new()
            }
            Frame::Kels(k) => self.on_kels(at, link, &k),
            Frame::Init(_) | Frame::Cookie(_) | Frame::Resp(_) => Vec::new(),
        }
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
    /// `kind` is [`RotationKind::Abandon`] for abandonment: no record is
    /// published; the abandoned KEL is stored and gossiped instead, and
    /// peers drop the identity's records once they hold it. Callers drain
    /// after this returns.
    pub fn reload_identity(
        &mut self,
        identity: Identity,
        now: u64,
        kind: RotationKind,
    ) -> Result<(), NodeError> {
        debug_assert_eq!(
            identity.is_abandoned(),
            kind == RotationKind::Abandon,
            "RotationKind must match the identity's KEL"
        );
        // The identifier is unchanged by rotation; keep own_id in step in
        // case a caller reloads a different identity.
        self.own_id = identity.id();
        self.identity = identity;
        // The KEL is the only carrier of a rotation or an abandonment;
        // store it so peers can fetch it via the `kels` frame.
        self.store_own_kel(now)?;
        if kind == RotationKind::Abandon {
            // No record is published: one citing the abandoned head would be
            // rejected by every peer. Drop our stored records; the abandoned
            // KEL does the talking from here.
            let id = self.own_id;
            self.drop_records_for(now, &id);
            self.next_reconcile_at = self.next_reconcile_at.min(now + 1);
            return Ok(());
        }
        self.publish_record(now)
    }

    /// Enter or leave draining: while draining, every custody offer is
    /// answered `busy` and nothing new starts — except receipts addressed
    /// to this node, which create no relay custody and are still accepted.
    /// Existing custody is finished and reported via custody count.
    pub fn set_drain(&mut self, state: local::DrainState) {
        self.draining = state;
    }

    pub fn drain_state(&self) -> local::DrainState {
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
    #[must_use]
    pub fn has_path(&mut self, dst: &Identifier) -> bool {
        let g = self.build_graph();
        g.distances(&self.own_id).contains_key(dst)
    }

    #[doc(hidden)]
    pub fn debug_contested(&self) -> u64 {
        self.contested
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
            Ok(v) => v.into_iter().map(|r| r.id).collect(),
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

    /// Whether we hold a usable record for `id`, and its mode if so.
    /// A record that fails validation is not usable, so it reports `Absent`.
    pub fn lookup(&mut self, id: &Identifier) -> LookupResult {
        for scope in [
            lattice_proto::record::Scope::Wan,
            lattice_proto::record::Scope::Hive,
        ] {
            match self.store.record_get(id, scope) {
                Ok(Some(stored)) => {
                    return match self.validate_stored(&stored.bytes, self.now, true) {
                        StoredRecord::Valid(p) => LookupResult::Present { mode: Some(p.mode) },
                        // Held but not valid: report absent.
                        _ => LookupResult::Absent,
                    };
                }
                Ok(None) => {}
                Err(e) => self.diag("record_get", &e),
            }
        }
        LookupResult::Absent
    }

    fn on_app_ack(&mut self, service: &str, delivery_ids: &[DeliveryId]) -> Vec<Action> {
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

/// Insert or merge an exclusion: the link may not carry custody until
/// `until`. Existing entries keep the later expiry.
fn add_exclusion(list: &mut Vec<Exclusion>, link: LinkId, until: u64) {
    match list.iter_mut().find(|e| e.link == link) {
        Some(existing) => existing.until = existing.until.max(until),
        None => list.push(Exclusion { link, until }),
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
    use lattice_store::{KelHeadSeen, MemStore, OutboundMessage, OutboundState};

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
        let actions = node.on_receipt(&receipt(KIND_RECEIPT, mid, recipient));
        assert_eq!(actions.len(), 1);
        let msg = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(msg.state, OutboundState::Delivered);
        assert_eq!(
            node.store.status_get(&mid).unwrap().unwrap().status,
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
        let actions = node.on_receipt(&receipt(KIND_RECEIPT, mid, attacker));
        assert!(actions.is_empty());
        let msg = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(msg.state, OutboundState::InFlight);
        assert_eq!(node.store.status_get(&mid).unwrap(), None);
        // A negative receipt from a non-recipient is ignored too.
        let actions = node.on_receipt(&receipt(KIND_NEGATIVE_RECEIPT, mid, attacker));
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
        let actions = node.on_receipt(&receipt(KIND_RECEIPT, mid1, recipient));
        assert!(actions.is_empty());
        assert_eq!(
            node.store.status_get(&mid1).unwrap().unwrap().status,
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
        let actions = node.on_receipt(&receipt(KIND_NEGATIVE_RECEIPT, mid2, recipient));
        assert!(actions.is_empty());
        assert_eq!(
            node.store.status_get(&mid2).unwrap().unwrap().status,
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
        id.rotate(&next_seed, Some(hash_next(&next_next))).unwrap();
        assert_eq!(id.id(), id_before, "identifier must survive rotation");
        assert_eq!(id.kel.len(), 2);
        assert_eq!(id.signing_seed, next_seed);
        assert!(!id.is_abandoned());
        let head = KeyEvent::validate_chain(&id.kel).unwrap();
        assert!(!head.is_abandoned());
        assert_eq!(head.seq, 1);
    }

    #[test]
    fn rotate_rejects_wrong_next_key() {
        let (mut id, _next_seed, next_next) = test_identity();
        let err = id
            .rotate(
                &SigningSeed::from_bytes([9u8; 32]),
                Some(hash_next(&next_next)),
            )
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
        assert!(head.is_abandoned());
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
        let kel = ValidatedKel::validate(kel).unwrap();
        let head = kel.head();
        let kel_bytes = kel.to_object_bytes().unwrap();
        let rec = PeerRecord::build(
            RecordParams {
                kel,
                prev_seq: 0,
                now: 1,
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
                serves: vec![],
            },
            &seed,
        )
        .unwrap();
        let id = rec.id;
        // The record can only be validated (and so retained) if the node
        // holds the KEL; store it as admission would.
        node.store
            .kel_put(
                &id,
                &kel_bytes,
                &KelHeadSeen {
                    seq: head.seq,
                    commitment: head.commitment,
                    seen: 0,
                    abandoned: false,
                },
            )
            .unwrap();
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

    fn build_record(
        kel: Vec<KeyEvent>,
        seq: u64,
        scope: Scope,
        signing_seed: &SigningSeed,
        channel_seed: &ChannelSeed,
    ) -> lattice_proto::record::PeerRecord {
        let kel = ValidatedKel::validate(kel).unwrap();
        lattice_proto::record::PeerRecord::build(
            lattice_proto::record::RecordParams {
                kel,
                prev_seq: seq.saturating_sub(1),
                now: 1,
                exp: 1_000 + 86_400,
                channel_key: lattice_crypto::channel_public(channel_seed),
                channel_seed: channel_seed.clone(),
                envelope_key: XWingPublicKey::from_bytes([7u8; 1216]),
                mode: Mode::Public,
                scope,
                endpoints: vec![lattice_proto::record::Endpoint {
                    url: "ws://mesh.example.com/".into(),
                    ips: vec![],
                }],
                links: vec![],
                gateways: vec![],
                capabilities: 0,
                serves: vec![],
            },
            signing_seed,
        )
        .unwrap()
    }

    /// Feed a KEL to the node through the `kels` frame path.
    fn admit_kel(node: &mut Node<MemStore>, kel: &ValidatedKel, at: u64) {
        let frame = Frame::Kels(lattice_proto::frames::KelsFrame {
            kels: vec![kel.to_object_bytes().unwrap()],
        });
        let _ = node.handle(Event::Frame {
            at,
            link: 999,
            from: kel.identifier(),
            frame,
        });
    }

    fn stored_record(
        node: &Node<MemStore>,
        id: &Identifier,
        scope: Scope,
    ) -> Option<lattice_proto::record::PeerRecord> {
        let stored = node.store.record_get(id, scope).unwrap()?;
        let kel_bytes = node.store.kel_get(id).unwrap()?;
        let kel = ValidatedKel::from_object_bytes(&kel_bytes).unwrap();
        lattice_proto::record::PeerRecord::from_bytes_unchecked_time(&stored.bytes, &kel)
            .ok()
            .map(|v| v.into_inner())
    }

    #[test]
    fn r01_stolen_key_max_seq_loses_to_owner_rotation() {
        let (owner, next_seed, next_next_seed) = test_identity();
        let id = owner.id();
        let channel_seed = owner.channel_seed.clone();
        let inception = owner.kel.events().to_vec();
        let inception_seed = owner.signing_seed.clone();
        let mut node = test_node();

        // A record whose KEL we do not hold is dropped, and the node asks
        // for the KEL.
        let attacker = build_record(
            inception.clone(),
            u64::MAX,
            Scope::Wan,
            &inception_seed,
            &channel_seed,
        );
        node.admit_record(1_000, 999, &attacker.encode());
        assert!(stored_record(&node, &id, Scope::Wan).is_none());

        // The inception KEL arrives; the attacker's record is admitted.
        admit_kel(
            &mut node,
            &ValidatedKel::validate(inception.clone()).unwrap(),
            1_000,
        );
        node.admit_record(1_001, 999, &attacker.encode());
        assert_eq!(stored_record(&node, &id, Scope::Wan).unwrap().seq, u64::MAX);

        // The owner rotates; the rotated KEL arrives and the head advances.
        // The attacker's record (citing the old head) is dropped.
        let mut owner = owner;
        owner
            .rotate(&next_seed, Some(hash_next(&next_next_seed)))
            .unwrap();
        admit_kel(&mut node, &owner.kel, 1_002);
        assert!(stored_record(&node, &id, Scope::Wan).is_none());

        // The rotated record must win despite its lower seq.
        let rotated = build_record(
            owner.kel.events().to_vec(),
            1,
            Scope::Wan,
            &owner.signing_seed,
            &channel_seed,
        );
        node.admit_record(1_003, 999, &rotated.encode());
        let stored = stored_record(&node, &id, Scope::Wan).unwrap();
        assert_eq!(
            stored.seq, 1,
            "owner's rotation must displace the attacker's record"
        );
        assert_eq!(stored.khs, 1);
        let head = node.store.kel_head(&id).unwrap().unwrap();
        assert_eq!(head.seq, 1);
        assert!(!head.abandoned);

        // A record behind the stored KEL is rejected even with a higher seq.
        let stale = build_record(
            inception,
            u64::MAX,
            Scope::Wan,
            &inception_seed,
            &channel_seed,
        );
        node.admit_record(1_004, 999, &stale.encode());
        let stored = stored_record(&node, &id, Scope::Wan).unwrap();
        assert_eq!(stored.seq, 1);
        assert_eq!(stored.khs, 1);
        assert_eq!(node.store.kel_head(&id).unwrap().unwrap().seq, 1);
    }

    #[test]
    fn r01_head_advance_evicts_records_behind_it() {
        let (owner, next_seed, next_next_seed) = test_identity();
        let id = owner.id();
        let channel_seed = owner.channel_seed.clone();
        let inception = owner.kel.events().to_vec();
        let mut node = test_node();

        // The identity is present in both scopes with the pre-rotation KEL.
        admit_kel(
            &mut node,
            &ValidatedKel::validate(inception.clone()).unwrap(),
            1_000,
        );
        let wan = build_record(
            inception.clone(),
            7,
            Scope::Wan,
            &owner.signing_seed,
            &channel_seed,
        );
        let hive = build_record(
            inception,
            7,
            Scope::Hive,
            &owner.signing_seed,
            &channel_seed,
        );
        node.admit_record(1_000, 999, &wan.encode());
        node.admit_record(1_000, 999, &hive.encode());
        assert!(node.store.record_get(&id, Scope::Hive).unwrap().is_some());

        // The owner rotates; the rotated KEL arrives, the head advances,
        // and both pre-rotation records are dropped.
        let mut owner = owner;
        owner
            .rotate(&next_seed, Some(hash_next(&next_next_seed)))
            .unwrap();
        admit_kel(&mut node, &owner.kel, 1_001);
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());
        assert!(node.store.record_get(&id, Scope::Hive).unwrap().is_none());

        // The rotated WAN record is admitted against the new head.
        let rotated = build_record(
            owner.kel.events().to_vec(),
            1,
            Scope::Wan,
            &owner.signing_seed,
            &channel_seed,
        );
        node.admit_record(1_002, 999, &rotated.encode());
        let wan_stored = stored_record(&node, &id, Scope::Wan).unwrap();
        assert_eq!(wan_stored.khs, 1);
        assert!(node.store.record_get(&id, Scope::Hive).unwrap().is_none());
    }

    #[test]
    fn r02_abandoned_kel_drops_records_and_stops_routing() {
        let (owner, next_seed, _) = test_identity();
        let id = owner.id();
        let channel_seed = owner.channel_seed.clone();
        let inception = owner.kel.events().to_vec();
        let mut node = test_node();

        admit_kel(
            &mut node,
            &ValidatedKel::validate(inception.clone()).unwrap(),
            1_000,
        );
        let wan = build_record(
            inception.clone(),
            1,
            Scope::Wan,
            &owner.signing_seed,
            &channel_seed,
        );
        let hive = build_record(
            inception,
            1,
            Scope::Hive,
            &owner.signing_seed,
            &channel_seed,
        );
        node.admit_record(1_000, 999, &wan.encode());
        node.admit_record(1_000, 999, &hive.encode());
        assert!(node.has_record(&id));

        // The owner abandons the identity; the abandoned KEL is the only
        // carrier of the abandonment.
        let mut owner = owner;
        owner.rotate(&next_seed, None).unwrap();
        assert!(owner.is_abandoned());
        admit_kel(&mut node, &owner.kel, 1_001);

        // Both records are dropped; the node holds only the abandoned KEL.
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());
        assert!(node.store.record_get(&id, Scope::Hive).unwrap().is_none());
        let head = node.store.kel_head(&id).unwrap().unwrap();
        assert!(head.abandoned);
        assert_eq!(head.seq, 1);
        // No routing, delivery, or waypoint use.
        assert!(!node.has_record(&id));
        assert!(matches!(node.lookup(&id), LookupResult::Absent));
        let graph = node.build_graph();
        assert!(!graph.distances(&node.own_id).contains_key(&id));
        // The KEL stays in the reconciliation set (scope 255) so the
        // abandonment propagates; no record for the id is advertised.
        let items = node.record_items().unwrap();
        assert!(items.iter().any(|i| i.id == id && i.scope == 255));
        assert!(!items.iter().any(|i| i.id == id && i.scope != 255));
    }

    #[test]
    fn r02_after_abandonment_every_record_for_id_is_rejected() {
        let (owner, next_seed, _) = test_identity();
        let id = owner.id();
        let channel_seed = owner.channel_seed.clone();
        let inception = owner.kel.events().to_vec();
        let inception_seed = owner.signing_seed.clone();
        let mut node = test_node();

        let mut owner = owner;
        owner.rotate(&next_seed, None).unwrap();
        admit_kel(&mut node, &owner.kel, 1_000);

        // Attacker with the superseded (pre-abandonment) key, max seq.
        let stale = build_record(
            inception,
            u64::MAX,
            Scope::Wan,
            &inception_seed,
            &channel_seed,
        );
        node.admit_record(1_001, 999, &stale.encode());
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());

        // Attacker with the abandonment key itself, same KEL, max seq.
        let same_kel = build_record(
            owner.kel.events().to_vec(),
            u64::MAX,
            Scope::Wan,
            &owner.signing_seed,
            &channel_seed,
        );
        node.admit_record(1_002, 999, &same_kel.encode());
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());
        assert!(node.store.kel_head(&id).unwrap().unwrap().abandoned);
    }

    #[test]
    fn r02_abandoned_kel_outlives_record_grace_until_head_ages_out() {
        let (owner, next_seed, _) = test_identity();
        let id = owner.id();
        let mut node = test_node();

        let mut owner = owner;
        owner.rotate(&next_seed, None).unwrap();
        admit_kel(&mut node, &owner.kel, 1_000);

        // Past the record grace period the KEL is still held: the head is
        // fresh, and the KEL is the only carrier of the abandonment for
        // peers that were offline.
        node.sweep_expired_data(1_000 + RETENTION_GRACE_SECS + 1);
        assert!(node.store.kel_head(&id).unwrap().is_some());
        assert!(node.store.kel_get(&id).unwrap().is_some());
        assert!(node.record_items().unwrap().iter().any(|i| i.id == id));

        // Once the head itself is stale, the KEL (and its head row) is swept.
        let head = node.store.kel_head(&id).unwrap().unwrap();
        let kel_bytes = node.store.kel_get(&id).unwrap().unwrap();
        node.store
            .kel_put(
                &id,
                &kel_bytes,
                &KelHeadSeen {
                    seq: head.seq,
                    commitment: head.commitment,
                    seen: 0,
                    abandoned: true,
                },
            )
            .unwrap();
        node.sweep_expired_data(KEL_HEAD_MAX_AGE_SECS + 1);
        assert!(node.store.kel_head(&id).unwrap().is_none());
        assert!(node.store.kel_get(&id).unwrap().is_none());
        assert!(!node.record_items().unwrap().iter().any(|i| i.id == id));
    }

    #[test]
    fn r02_abandon_publishes_kel_not_record() {
        let (owner, next_seed, _) = test_identity();
        let id = owner.id();
        let mut node = test_node();
        let mut owner = owner;
        owner.rotate(&next_seed, None).unwrap();
        node.reload_identity(owner, 1_001, RotationKind::Abandon)
            .unwrap();
        // The abandon path publishes no record: one citing the abandoned
        // head would be rejected by every peer. The KEL is stored and
        // served instead.
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_none());
        assert!(!node.has_record(&id));
        let head = node.store.kel_head(&id).unwrap().unwrap();
        assert!(head.abandoned);
        assert_eq!(head.seq, 1);
        assert!(node.store.kel_get(&id).unwrap().is_some());
    }

    fn wire_message(leg: LegId, dst: Identifier, exp: u64) -> Vec<u8> {
        Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_MESSAGE,
                mid: MessageId::from_bytes([0x42; 16]),
                from: Identifier::from_bytes([0xAA; 32]),
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
            sender_seed: &SigningSeed::from_bytes([0xBB; 32]),
            recipient_ek: &XWingPublicKey::from_bytes([7u8; 1216]),
            real_dst: dst,
            leg,
            exp,
            gateway: None,
            waypoint: None,
        })
        .expect("wire message builds")
    }

    fn link_up(node: &mut Node<MemStore>, link: u64, peer: Identifier, at: u64) {
        let remote_ck = lattice_crypto::channel_x25519_public(&ChannelSeed::from_bytes([0x77; 32]));
        node.handle(Event::LinkUp {
            at,
            link,
            peer: Some(peer),
            remote_ck,
        });
    }

    fn custody_frame(leg: LegId, result: u64) -> Frame {
        Frame::Custody(CustodyFrame {
            leg,
            result,
            retry_after: None,
        })
    }

    fn insert_relay_custody(
        node: &mut Node<MemStore>,
        leg: LegId,
        message: Vec<u8>,
        upstream: u64,
        destination: Identifier,
        exp: u64,
    ) {
        node.store
            .custody_put(CustodyEntry {
                leg,
                message,
                upstream,
                destination,
                class: 0,
                exp,
                excluded: Vec::new(),
            })
            .unwrap();
    }

    fn offer_links(actions: &[Action]) -> Vec<u64> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendFrame {
                    link,
                    frame: Frame::Offer(_),
                    ..
                } => Some(*link),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn already_have_on_relayed_entry_keeps_custody_and_excludes_link() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let upstream = Identifier::from_bytes([0x01; 32]);
        let mut node = test_node();
        link_up(&mut node, 100, upstream, 1_000);
        link_up(&mut node, 200, dst, 1_000);
        link_up(&mut node, 201, dst, 1_000);
        let now = 1_000u64;
        let leg = LegId::from_bytes([0x11; 16]);
        let exp = now + 10_000;
        let wire = wire_message(leg, dst, exp);
        insert_relay_custody(&mut node, leg, wire, 100, dst, exp);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Relay { custody_leg: leg },
                sent_at: now,
                excluded: Vec::new(),
                link: 200,
            },
        );
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            from: dst,
            frame: custody_frame(leg, CUSTODY_ALREADY_HAVE),
        });
        // Custody is kept, not released.
        let entry = node
            .store
            .custody_get(&leg)
            .unwrap()
            .expect("custody entry must survive ALREADY_HAVE");
        // The answering link is excluded for this leg's remaining life.
        assert!(
            entry
                .excluded
                .iter()
                .any(|e| e.link == 200 && e.until == exp),
            "link 200 must be excluded for the leg's remaining life: {:?}",
            entry.excluded
        );
        // The message is re-offered on another candidate, never back on 200.
        let offered = offer_links(&actions);
        assert!(
            offered.contains(&201),
            "expected re-offer on link 201, got {offered:?}"
        );
        assert!(!offered.contains(&200));
    }

    #[test]
    fn already_have_on_originated_entry_keeps_outbound_copy() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let mut node = test_node();
        link_up(&mut node, 200, dst, 1_000);
        let now = 1_000u64;
        let mid = MessageId::from_bytes([0x11; 16]);
        let mut msg = outbound(mid, dst, OutboundState::InFlight);
        msg.exp = now + 10_000;
        node.store.outbound_put(&msg).unwrap();
        let leg = LegId::from_bytes([0x22; 16]);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Outbound { mid },
                sent_at: now,
                excluded: Vec::new(),
                link: 200,
            },
        );
        let (_actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            from: dst,
            frame: custody_frame(leg, CUSTODY_ALREADY_HAVE),
        });
        // Our copy is kept and requeued, not deleted or failed.
        let stored = node
            .store
            .outbound_get(&mid)
            .unwrap()
            .expect("outbound message must survive ALREADY_HAVE");
        assert_eq!(stored.state, OutboundState::Queued);
        assert!(
            node.outbound_exclusions
                .get(&mid)
                .is_some_and(|v| v.iter().any(|e| e.link == 200)),
            "answering link must be excluded for this mid"
        );
    }

    #[test]
    fn accepted_and_refused_release_relay_custody() {
        for result in [CUSTODY_ACCEPTED, CUSTODY_REFUSED] {
            let dst = Identifier::from_bytes([0xD5; 32]);
            let upstream = Identifier::from_bytes([0x01; 32]);
            let mut node = test_node();
            link_up(&mut node, 100, upstream, 1_000);
            link_up(&mut node, 200, dst, 1_000);
            let now = 1_000u64;
            let leg = LegId::from_bytes([0x33; 16]);
            let exp = now + 10_000;
            let wire = wire_message(leg, dst, exp);
            insert_relay_custody(&mut node, leg, wire, 100, dst, exp);
            node.pending.insert(
                leg,
                PendingOffer {
                    origin: PendingOrigin::Relay { custody_leg: leg },
                    sent_at: now,
                    excluded: Vec::new(),
                    link: 200,
                },
            );
            let (_actions, _) = node.handle(Event::Frame {
                at: now,
                link: 200,
                from: dst,
                frame: custody_frame(leg, result),
            });
            assert!(
                node.store.custody_get(&leg).unwrap().is_none(),
                "custody must be released on result {result}"
            );
        }
    }

    #[test]
    fn custody_reply_from_unrelated_link_is_ignored() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let upstream = Identifier::from_bytes([0x01; 32]);
        let stray = Identifier::from_bytes([0x02; 32]);
        let mut node = test_node();
        link_up(&mut node, 100, upstream, 1_000);
        link_up(&mut node, 200, dst, 1_000);
        link_up(&mut node, 300, stray, 1_000);
        let now = 1_000u64;
        let leg = LegId::from_bytes([0x33; 16]);
        let exp = now + 10_000;
        let wire = wire_message(leg, dst, exp);
        insert_relay_custody(&mut node, leg, wire, 100, dst, exp);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Relay { custody_leg: leg },
                sent_at: now,
                excluded: Vec::new(),
                link: 200,
            },
        );
        // A reply from a link the offer never went out on is ignored:
        // custody is kept and the pending entry survives.
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 300,
            from: stray,
            frame: custody_frame(leg, CUSTODY_ACCEPTED),
        });
        assert!(actions.is_empty());
        assert!(node.pending.contains_key(&leg));
        assert!(node.store.custody_get(&leg).unwrap().is_some());
        // The reply on the link the offer went out on is honored.
        let (_actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            from: dst,
            frame: custody_frame(leg, CUSTODY_ACCEPTED),
        });
        assert!(!node.pending.contains_key(&leg));
        assert!(node.store.custody_get(&leg).unwrap().is_none());
    }

    #[test]
    fn custody_refused_from_unrelated_link_does_not_fail_outbound() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let stray = Identifier::from_bytes([0x02; 32]);
        let mut node = test_node();
        link_up(&mut node, 200, dst, 1_000);
        link_up(&mut node, 300, stray, 1_000);
        let now = 1_000u64;
        let mid = MessageId::from_bytes([0x44; 16]);
        let mut msg = outbound(mid, dst, OutboundState::InFlight);
        msg.exp = now + 10_000;
        node.store.outbound_put(&msg).unwrap();
        let leg = LegId::from_bytes([0x55; 16]);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Outbound { mid },
                sent_at: now,
                excluded: Vec::new(),
                link: 200,
            },
        );
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 300,
            from: stray,
            frame: custody_frame(leg, CUSTODY_REFUSED),
        });
        assert!(actions.is_empty());
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::InFlight);
        assert!(node.pending.contains_key(&leg));
        // The reply on the offering link fails the message as before.
        let (_actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            from: dst,
            frame: custody_frame(leg, CUSTODY_REFUSED),
        });
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Failed);
        assert!(!node.pending.contains_key(&leg));
    }

    /// Build a wire message from `sender` to this node, signed with
    /// `signing_seed` (which need not match the sender's identity, to
    /// exercise signature verification).
    fn sealed_to_node(
        node: &Node<MemStore>,
        sender: &Identity,
        signing_seed: &SigningSeed,
        kind: u64,
        reference: Option<MessageId>,
        leg: LegId,
        now: u64,
    ) -> Vec<u8> {
        Message::build(BuildParams {
            envelope: Envelope {
                kind,
                mid: MessageId::from_bytes([0x77; 16]),
                from: sender.id(),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: "svc".into(),
                tmbx: b"in".to_vec(),
                created: now,
                body: (kind == KIND_MESSAGE).then(|| b"hi".to_vec()),
                reference,
                reason: (kind == KIND_NEGATIVE_RECEIPT)
                    .then_some(lattice_proto::message::REASON_UNKNOWN_SERVICE),
                sig: Signature::from_bytes([0; 64]),
            },
            sender_seed: signing_seed,
            recipient_ek: &node.identity.xwing_public,
            real_dst: node.own_id,
            leg,
            exp: now + 10_000,
            gateway: None,
            waypoint: None,
        })
        .expect("message builds")
    }

    fn admit_sender(node: &mut Node<MemStore>, sender: &Identity, at: u64) {
        admit_kel(node, &sender.kel, at);
        let record = build_record(
            sender.kel.events().to_vec(),
            1,
            Scope::Wan,
            &sender.signing_seed,
            &sender.channel_seed,
        );
        node.admit_record(at, 999, &record.encode());
    }

    #[test]
    fn bad_signature_gets_refusal_and_no_negative_receipt() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        // Signed with a key that does not match the sender's record.
        let wire = sealed_to_node(
            &node,
            &sender,
            &SigningSeed::from_bytes([0x99; 32]),
            KIND_MESSAGE,
            None,
            LegId::from_bytes([0x88; 16]),
            now,
        );
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_REFUSED
            )),
            "a bad signature must be refused"
        );
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Offer(_),
                    ..
                }
            )),
            "no message (in particular no negative receipt) may be sent to an unauthenticated sender"
        );
        assert!(
            node.store.outbound_all().unwrap().is_empty(),
            "no negative receipt may be queued for an unauthenticated sender"
        );
    }

    #[test]
    fn draining_node_accepts_receipt_addressed_to_it() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5B; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let mid = MessageId::from_bytes([0x66; 16]);
        let mut msg = outbound(mid, sender.id(), OutboundState::InFlight);
        msg.exp = now + 10_000;
        node.store.outbound_put(&msg).unwrap();
        let wire = sealed_to_node(
            &node,
            &sender,
            &sender.signing_seed,
            KIND_RECEIPT,
            Some(mid),
            LegId::from_bytes([0x89; 16]),
            now,
        );
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "a receipt addressed to a draining node must be accepted, got {actions:?}"
        );
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Delivered);
    }

    #[test]
    fn draining_node_accepts_negative_receipt_addressed_to_it() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5C; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let mid = MessageId::from_bytes([0x67; 16]);
        let mut msg = outbound(mid, sender.id(), OutboundState::InFlight);
        msg.exp = now + 10_000;
        node.store.outbound_put(&msg).unwrap();
        let wire = sealed_to_node(
            &node,
            &sender,
            &sender.signing_seed,
            KIND_NEGATIVE_RECEIPT,
            Some(mid),
            LegId::from_bytes([0x8A; 16]),
            now,
        );
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "a negative receipt addressed to a draining node must be accepted, got {actions:?}"
        );
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Failed);
    }

    #[test]
    fn draining_private_node_accepts_receipt_addressed_to_its_gateway() {
        let gw = Identifier::from_bytes([0x77; 32]);
        let cfg = Config {
            snow_per_min: 0.0,
            mode: Mode::Private,
            gateways: vec![gw],
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&lattice_crypto::os_bytes::<32>()),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let sender = Identity::from_seed(&[0x5B; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let mid = MessageId::from_bytes([0x68; 16]);
        let mut msg = outbound(mid, sender.id(), OutboundState::InFlight);
        msg.exp = now + 10_000;
        node.store.outbound_put(&msg).unwrap();
        // Sealed to this node, addressed to its gateway: the gateway strips
        // the gateway layer and forwards with dst naming the gateway.
        let wire = Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_RECEIPT,
                mid: MessageId::from_bytes([0x79; 16]),
                from: sender.id(),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: "svc".into(),
                tmbx: b"in".to_vec(),
                created: now,
                body: None,
                reference: Some(mid),
                reason: None,
                sig: Signature::from_bytes([0; 64]),
            },
            sender_seed: &sender.signing_seed,
            recipient_ek: &node.identity.xwing_public,
            real_dst: gw,
            leg: LegId::from_bytes([0x8D; 16]),
            exp: now + 10_000,
            gateway: None,
            waypoint: None,
        })
        .expect("message builds");
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "a receipt forwarded by our gateway must be accepted while draining, got {actions:?}"
        );
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Delivered);
    }

    #[test]
    fn draining_node_still_refuses_ordinary_messages() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5D; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let wire = sealed_to_node(
            &node,
            &sender,
            &sender.signing_seed,
            KIND_MESSAGE,
            None,
            LegId::from_bytes([0x8B; 16]),
            now,
        );
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_BUSY
            )),
            "an ordinary message must still be refused while draining, got {actions:?}"
        );
        assert_eq!(node.store.inbox_len_total().unwrap(), 0);
    }

    #[test]
    fn draining_node_refuses_receipt_sealed_to_someone_else() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5E; 32]);
        let other = Identity::from_seed(&[0x5F; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        // A receipt sealed to `other`, not to this node: not ours, so the
        // drain refusal still applies.
        let wire = Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_RECEIPT,
                mid: MessageId::from_bytes([0x78; 16]),
                from: sender.id(),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: "svc".into(),
                tmbx: b"in".to_vec(),
                created: now,
                body: None,
                reference: Some(MessageId::from_bytes([0x66; 16])),
                reason: None,
                sig: Signature::from_bytes([0; 64]),
            },
            sender_seed: &sender.signing_seed,
            recipient_ek: &other.xwing_public,
            real_dst: node.own_id,
            leg: LegId::from_bytes([0x8C; 16]),
            exp: now + 10_000,
            gateway: None,
            waypoint: None,
        })
        .expect("message builds");
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: sender.id(),
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_BUSY
            )),
            "a receipt not sealed to this node must be refused while draining, got {actions:?}"
        );
    }

    #[test]
    fn accepted_custody_excludes_the_upstream_link() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let upstream = Identifier::from_bytes([0x01; 32]);
        let mut node = test_node();
        link_up(&mut node, 100, upstream, 1_000);
        let now = 1_000u64;
        let leg = LegId::from_bytes([0x44; 16]);
        let exp = now + 10_000;
        let wire = wire_message(leg, dst, exp);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            from: upstream,
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "offer must be accepted"
        );
        let entry = node
            .store
            .custody_get(&leg)
            .unwrap()
            .expect("custody entry must be stored");
        assert!(
            entry.excluded.iter().any(|e| e.link == 100),
            "upstream link must be excluded for this leg: {:?}",
            entry.excluded
        );
        // With no other route, nothing is offered back to the upstream.
        assert!(!offer_links(&actions).contains(&100));
    }

    #[test]
    fn dispatch_marks_originated_leg_seen() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let mut node = test_node();
        link_up(&mut node, 200, dst, 1_000);
        let now = 1_000u64;
        let leg = LegId::from_bytes([0x55; 16]);
        let exp = now + 10_000;
        let wire = wire_message(leg, dst, exp);
        let mid = MessageId::from_bytes([0x66; 16]);
        let msg = outbound(mid, dst, OutboundState::Queued);
        let mut actions = Vec::new();
        let result = node.dispatch_wire(now, &wire, &msg, &mut actions);
        assert!(matches!(result, DispatchResult::Sent));
        let leg_hash = lattice_crypto::hash(leg.as_ref());
        assert!(node.store.seen_contains(&leg_hash, now).unwrap());
    }

    #[test]
    fn originated_leg_bouncing_back_gets_already_have() {
        let dst = Identifier::from_bytes([0xD5; 32]);
        let stray = Identifier::from_bytes([0x01; 32]);
        let mut node = test_node();
        link_up(&mut node, 200, dst, 1_000);
        link_up(&mut node, 300, stray, 1_000);
        let now = 1_000u64;
        let leg = LegId::from_bytes([0x55; 16]);
        let exp = now + 10_000;
        let wire = wire_message(leg, dst, exp);
        let mid = MessageId::from_bytes([0x66; 16]);
        let msg = outbound(mid, dst, OutboundState::Queued);
        let mut actions = Vec::new();
        assert!(matches!(
            node.dispatch_wire(now, &wire, &msg, &mut actions),
            DispatchResult::Sent
        ));
        // The same leg comes back to us as an offer from another link.
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 300,
            from: stray,
            frame: Frame::Offer(OfferFrame { message: wire }),
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ALREADY_HAVE
            )),
            "a bounced-back originated leg must be answered ALREADY_HAVE"
        );
        // We must not take custody of our own message.
        assert!(node.store.custody_get(&leg).unwrap().is_none());
    }
}
