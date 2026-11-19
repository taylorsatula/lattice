//! The sans-IO node state machine. Events in, actions out; all time,
//! randomness and persistence are injected.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use lattice_proto::frames::{
    CUSTODY_ACCEPTED, CUSTODY_ALREADY_HAVE, CUSTODY_BUSY, CUSTODY_REFUSED, CUSTODY_SEEN,
    CustodyFrame, DummyFrame, Frame, KelsFrame, OfferFrame, PingFrame, ReconcileFrame, RecordRef,
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
    CustodyAccept, CustodyEntry, Exclusion, InboxEntry, KelHeadSeen, OutboundState, SavedPeer,
    Store, StoreError,
};

use lattice_types::{
    ChannelSeed, Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId, Signature,
    SigningPublicKey, SigningSeed, X25519PublicKey, XWingPublicKey, XWingSecretKey,
};

use crate::error::NodeError;
use crate::frame_budget;
use crate::graph::{Graph, GraphRecord};
use crate::neighbor::{self, Candidate};
use crate::outbound::{OutboundMessageExt, OutboundStateExt};
use crate::reconcile::{self, ReconcileSession};
use crate::rng::Rng;
use crate::types::{
    Action, AppSend, Config, Diagnostic, ERR_EXPIRED, ERR_INTERNAL, ERR_NO_RECORD, ERR_NO_ROUTE,
    ERR_REFUSED, Event, LinkId,
};

/// The core's internal clock is milliseconds since the Unix epoch. The
/// wire format and the store keep Unix seconds; conversions happen at
/// those boundaries (`secs_to_ms` / `ms_to_secs`).
const MS_PER_SEC: u64 = 1_000;

fn secs_to_ms(s: u64) -> u64 {
    s.saturating_mul(MS_PER_SEC)
}

fn ms_to_secs(ms: u64) -> u64 {
    ms / MS_PER_SEC
}

/// Receipts and negative receipts are control traffic: they are sealed,
/// routed and stored like any other message, but the sender needs no
/// status for them — they are terminal on their first custody ACCEPTED
/// and carry no receipt of their own.
fn is_receipt_envelope(kind: u64) -> bool {
    kind == KIND_RECEIPT || kind == KIND_NEGATIVE_RECEIPT
}

/// The refresh interval with ±10% jitter, so a fleet does not republish in
/// lockstep. `base_secs` is clamped to at least 60s so a misconfigured
/// zero cannot spin the refresh loop.
fn refresh_interval_ms(rng: &mut Rng, base_secs: u64) -> u64 {
    let base = base_secs.max(60);
    let spread = base / 10;
    let jitter = rng.below(2 * spread + 1);
    secs_to_ms(base - spread + jitter)
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

/// Short tag for a frame, for diagnostics.
fn frame_kind(frame: &Frame) -> &'static str {
    match frame {
        Frame::Init(_) => "init",
        Frame::Cookie(_) => "cookie",
        Frame::Resp(_) => "resp",
        Frame::Offer(_) => "offer",
        Frame::Custody(_) => "custody",
        Frame::Reconcile(_) => "reconcile",
        Frame::Want(_) => "want",
        Frame::Records(_) => "records",
        Frame::Kels(_) => "kels",
        Frame::Ping(_) => "ping",
        Frame::Dummy(_) => "dummy",
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

    /// Try to open a hop layer with the current key, then any retired keys
    /// still within their grace period. Hop layers are sealed to the same
    /// X-Wing key as envelopes, so a rotation must not strand a waypoint
    /// or gateway layer that was sealed just before it.
    pub fn open_hop_layer_any(
        &self,
        msg: &lattice_proto::message::Message,
    ) -> Result<lattice_proto::message::HopLayerPlain, lattice_proto::ProtoError> {
        match msg.open_hop_layer(&self.xwing_secret) {
            Ok(h) => Ok(h),
            Err(first_err) => {
                for retired in &self.retired_xwing {
                    if let Ok(h) = msg.open_hop_layer(&retired.secret) {
                        return Ok(h);
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

/// In-memory bookkeeping for a custody entry: the leg to offer on the
/// wire (cached so retries do not re-parse the message), the retry
/// backoff state, and the class slot (for drain ordering). Rebuilt at
/// startup from the custody rows; the store remains the source of truth
/// for the message itself.
struct CustodyMeta {
    offer_leg: Option<LegId>,
    attempts: u32,
    next_attempt: u64,
    class_slot: u8,
}

/// The fields of an outbound message the due-time indexes are keyed on.
/// Mirrors the store row; rebuilt at startup and maintained on every
/// outbound mutation.
#[derive(Clone, Copy)]
struct OutboundIndexEntry {
    next_attempt: u64,
    receipt_deadline: Option<u64>,
    exp: u64,
    state: lattice_store::OutboundState,
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
    /// True when the stored message carries a hop layer (it is traveling
    /// toward a waypoint or gateway). Selects the first-leg class phase.
    has_hop_layer: bool,
}

struct LinkState {
    /// `None` while the peer's identity is not safely established.
    peer: Option<Identifier>,
    remote_ck: X25519PublicKey,
    /// True when the peer id was pinned by operator config (root `id`); pinned
    /// bindings are never re-derived from records or revoked by contest.
    pinned: bool,
    /// When the link came up (ms). Orders the advertised set by longevity.
    since: u64,
    /// Token bucket for echo replies (R-29): a peer cannot make us emit
    /// more than a small burst plus a slow trickle of echo replies per
    /// link. Refilled lazily from the clock.
    echo_tokens: f64,
    echo_refilled_at: u64,
    /// Record-wants we have sent on this link that no `Records` frame has
    /// answered yet. Records arriving with no credit are unsolicited and
    /// spend the push budget instead.
    want_credits: u32,
    /// Token bucket for unsolicited records (records no `want` asked
    /// for). Refilled lazily from the clock.
    push_tokens: f64,
    push_refilled_at: u64,
}

/// A link that went down but is still inside the grace window; the peer
/// stays in the advertised set until the grace elapses.
struct LostLink {
    peer: Identifier,
    pinned: bool,
    since: u64,
    lost_at: u64,
}

impl LinkState {
    fn new(peer: Option<Identifier>, remote_ck: X25519PublicKey, pinned: bool, now: u64) -> Self {
        Self {
            peer,
            remote_ck,
            pinned,
            since: now,
            echo_tokens: ECHO_BUDGET_CAPACITY,
            echo_refilled_at: now,
            want_credits: 0,
            push_tokens: PUSH_BUDGET_CAPACITY,
            push_refilled_at: now,
        }
    }

    /// Take one echo-reply token, refilling from the elapsed time first.
    /// Returns false when the bucket is empty (the echo is dropped).
    fn echo_budget_take(&mut self, now: u64) -> bool {
        let elapsed_ms = now.saturating_sub(self.echo_refilled_at);
        if elapsed_ms > 0 {
            let refill = elapsed_ms as f64 * (ECHO_BUDGET_REFILL_PER_SEC / 1000.0);
            self.echo_tokens = (self.echo_tokens + refill).min(ECHO_BUDGET_CAPACITY);
            self.echo_refilled_at = now;
        }
        if self.echo_tokens >= 1.0 {
            self.echo_tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Take one unsolicited-record token, refilling from the elapsed time
    /// first. Returns false when the bucket is empty (the record is
    /// dropped without validation).
    fn push_budget_take(&mut self, now: u64) -> bool {
        let elapsed_ms = now.saturating_sub(self.push_refilled_at);
        if elapsed_ms > 0 {
            let refill = elapsed_ms as f64 * (PUSH_BUDGET_REFILL_PER_SEC / 1000.0);
            self.push_tokens = (self.push_tokens + refill).min(PUSH_BUDGET_CAPACITY);
            self.push_refilled_at = now;
        }
        if self.push_tokens >= 1.0 {
            self.push_tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A dial the core asked the daemon to make, not yet resolved. Matched
/// to a link on `LinkUp` by the peer's channel key; matched to a failure
/// by peer id on `DialFailed`.
struct PendingDial {
    peer: Identifier,
    scope: Scope,
    /// X25519 form of the candidate's channel key; how the link is
    /// matched to this dial.
    ck: X25519PublicKey,
    /// Salted selection hash of the candidate.
    hash: u64,
    /// Incumbent link to evict once this dial binds (test-before-evict).
    evict_on_success: Option<LinkId>,
    /// When the dial was emitted (ms); pending dials that never resolve
    /// are dropped after `PENDING_DIAL_TIMEOUT_MS`.
    since: u64,
    /// Range group of the candidate; counts toward the per-group sub-cap.
    range: neighbor::RangeKey,
}

/// An outbound (core-dialed) link. Tracked so the selection can count
/// outbound links against the per-scope cap and pick an eviction victim.
struct OutboundLink {
    peer: Identifier,
    scope: Scope,
    /// Salted selection hash of the candidate this link was dialed from.
    hash: u64,
    /// Incumbent to evict once this link binds; cleared once evicted
    /// (or once the link binds without an eviction pending).
    evict_on_success: Option<LinkId>,
    /// Range group of the peer; counts toward the per-group sub-cap.
    range: neighbor::RangeKey,
}

/// A dummy frame scheduled to be sent after a short random delay.
#[derive(Clone, Copy)]
struct PendingEcho {
    due: u64,
    link: LinkId,
    /// Bucket of the echo request that triggered this reply; the reply
    /// goes out in the same bucket (R-29).
    bucket: usize,
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

/// A record held in the in-memory index. Validation happened once, at
/// admission (or at startup load); reads never re-validate. `hash` is the
/// BLAKE3 of the stored bytes: the reconcile item hash-prefix and the
/// (khs, seq, hash) admission order both derive from it.
struct IndexedRecord {
    record: lattice_proto::record::PeerRecord,
    hash: Hash32,
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
    links: BTreeMap<LinkId, LinkState>,
    next_link_order: Vec<LinkId>,
    reconcile_sessions: BTreeMap<LinkId, ReconcileSession>,
    pending: BTreeMap<LegId, PendingOffer>,
    outbound_exclusions: BTreeMap<MessageId, Vec<Exclusion>>,
    snow_next: u64,
    frames_since_snow_tick: u32,
    snow_history: [u64; 4],
    inner_pending_echo: Vec<PendingEcho>,
    /// Exponentially smoothed mean of observed custody-reply RTTs (ms).
    /// Echo replies are scheduled by sampling from an exponential
    /// distribution with this mean, so dummy exchanges look like an
    /// offer and its custody reply (spec §6, snow).
    custody_rtt_ema_ms: Option<f64>,
    /// Per-leg custody bookkeeping (offer leg, retry backoff, class
    /// slot). Rebuilt at startup from the custody rows.
    custody_meta: std::collections::HashMap<LegId, CustodyMeta>,
    /// Custody legs waiting for their retry backoff to expire, keyed by
    /// the time they become due. Entries whose offer is in flight are
    /// not in this index.
    custody_retry: std::collections::BTreeMap<u64, std::collections::HashSet<LegId>>,
    /// Custody legs by message expiry (ms), for the expiry sweep.
    custody_expiry: std::collections::BTreeMap<u64, std::collections::HashSet<LegId>>,
    /// Bytes of custody held per upstream link, rebuilt at startup from
    /// the custody rows. Drives the per-upstream aggregate cap.
    upstream_bytes: std::collections::HashMap<u64, u64>,
    /// Outbound queue index, keyed by message id. Rebuilt at startup.
    outbound_index: std::collections::HashMap<MessageId, OutboundIndexEntry>,
    /// Queued outbound messages by next attempt (ms).
    outbound_due: std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
    /// In-flight outbound messages by receipt deadline (ms).
    outbound_deadline: std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
    /// Non-terminal outbound messages by expiry (ms).
    outbound_expiry: std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
    /// Consecutive no-route waits per message, driving the backoff for a
    /// message with no current route. In-memory only: a restart resets the
    /// backoff to its base, which is harmless. Bounded; cleared when full.
    no_route_backoff: std::collections::HashMap<MessageId, u32>,
    /// Messages queued while the recipient's record is unknown, keyed by
    /// recipient. The grace deadline is persisted as the message's
    /// `next_attempt`; this index only makes record admission able to
    /// re-arm the waiters. Rebuilt at startup from the store.
    awaiting_record: std::collections::HashMap<Identifier, HashSet<MessageId>>,
    /// Memoized distance maps, keyed by (records_version, now_secs,
    /// source). Bounded; cleared when full.
    distance_cache: std::collections::HashMap<
        (u64, u64, Identifier),
        Arc<std::collections::BTreeMap<Identifier, u32>>,
    >,
    record_refresh_at: u64,
    /// Links that went down within the grace window; still advertised.
    recently_lost: Vec<LostLink>,
    /// The link list as last published, in published order; used for
    /// change detection. Empty until the first publish.
    last_published_links: Vec<Identifier>,
    /// When the last record publish happened (ms); `None` until the first.
    last_publish_at: Option<u64>,
    /// A republish is owed but the spacing floor has not elapsed.
    publish_pending: bool,
    /// After a failed publish, the earliest time to retry (backoff).
    publish_retry_at: Option<u64>,
    /// Per-node salt for record-eviction hashing, drawn from the RNG at
    /// startup. Makes the eviction order unpredictable to a peer that
    /// chooses which records to push.
    record_salt: [u8; 32],
    /// Per-node salt for neighbor selection, derived from the channel
    /// seed (see `neighbor::selection_salt`). Stable across restarts so
    /// saved anchors keep their meaning; unpredictable to anyone who
    /// does not hold the seed.
    neighbor_salt: [u8; 32],
    /// Dials the core asked the daemon to make, not yet resolved.
    pending_dials: Vec<PendingDial>,
    /// Per-(peer, scope) dial backoff: consecutive failures and the time
    /// before which the candidate must not be dialed again.
    dial_backoff: std::collections::HashMap<(Identifier, Scope), (u32, u64)>,
    /// Set when a record with endpoints was admitted; the next tick
    /// (scheduled at this time) runs neighbor selection.
    neighbor_check_at: Option<u64>,
    /// Outbound (core-dialed) links, by link id.
    outbound_links: std::collections::HashMap<LinkId, OutboundLink>,
    /// Saved peers, keyed by (id, scope). Mirrors the `saved_peers`
    /// store table; loaded at startup, written through on change.
    saved_peers: std::collections::HashMap<(Identifier, Scope), SavedPeer>,
    /// Expiry (unix seconds) of our current record; drives the refresh.
    own_record_exp: u64,
    next_reconcile_at: u64,
    rng: Rng,
    now: u64,
    draining: local::DrainState,
    /// channel_key -> set of node ids whose records claim that key.
    /// Attribution of a link to a peer is allowed only when exactly one id
    /// claims the link's channel key; more than one fails closed.
    ck_claims: BTreeMap<X25519PublicKey, BTreeSet<Identifier>>,
    next_claim_sweep_at: u64,
    next_data_sweep_at: u64,
    contested: u64,
    /// In-memory index of the stored records, keyed by (id, scope).
    /// Populated at startup and on admission; entries leave at expiry
    /// (the retention sweep evicts them) or when the record is dropped.
    /// Reads filter on `exp > now`; nothing here re-validates. The store
    /// remains the system of record for bytes; this index is the read
    /// path for routing, reconcile and waypoint selection.
    record_index: BTreeMap<(Identifier, u8), IndexedRecord>,
    /// Bumped on every change to the index or to the KEL head set (KEL
    /// admission, KEL sweep). Keys the derived-data caches below; cheap
    /// to bump, so callers never have to reason about which cache a
    /// change affects.
    derived_version: u64,
    /// Memoized routing graph. Rebuilt from the index (no re-validation)
    /// when the index changes or the clock moves; building it is a BFS
    /// over already-validated records, so a rebuild never touches the
    /// store or the signature verifier.
    graph_cache: Option<(u64, u64, Arc<Graph>)>,
    /// Memoized reconcile item list; same invalidation as `graph_cache`.
    items_cache: Option<(u64, u64, Vec<reconcile::Item>)>,
    /// Memoized public-mode (id, envelope key) pairs for waypoint
    /// selection; same invalidation as `graph_cache`.
    waypoint_cache: Option<(u64, u64, Arc<WaypointCandidates>)>,
    /// Test-only count of stored-byte validations, so tests can prove
    /// the per-tick path never re-validates.
    #[cfg(test)]
    validation_count: u64,
    /// Non-fatal internal failures observed since the last `handle` call.
    /// Drained by `handle` and returned alongside the actions; the caller
    /// decides how to surface them.
    diagnostics: Vec<Diagnostic>,
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
        if config.mode == Mode::Private && !config.serves.is_empty() {
            return Err(NodeError::Config(
                "serves is only valid in public mode".to_string(),
            ));
        }
        if config.serves.len() > 16 {
            return Err(NodeError::Config("serves is limited to 16 ids".to_string()));
        }
        let rng_seed = config.rng_seed;
        let id = identity.id();
        // Per-node salt for record eviction, drawn from a separate stream
        // so the main stream is undisturbed.
        let mut salt_rng = Rng::new(rng_seed ^ 0x9E37_79B9_7F4A_7C15);
        let mut record_salt = [0u8; 32];
        for chunk in record_salt.chunks_mut(8) {
            chunk.copy_from_slice(&salt_rng.next_u64().to_le_bytes());
        }
        let neighbor_salt = neighbor::selection_salt(identity.channel_seed.as_bytes());
        let mut rng = Rng::new(rng_seed);
        let first_refresh = now + refresh_interval_ms(&mut rng, config.record_refresh_secs);
        // Publish our own record if absent.
        let own_exists = store.record_get(&id, Scope::Wan)?.is_some();
        let mut node = Node {
            config,
            identity,
            store,
            own_id: id,
            scope: Scope::Wan,
            own_seq: 0,
            links: BTreeMap::new(),
            next_link_order: Vec::new(),
            reconcile_sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
            outbound_exclusions: BTreeMap::new(),
            snow_next: now,
            frames_since_snow_tick: 0,
            snow_history: [0; 4],
            inner_pending_echo: Vec::new(),
            custody_rtt_ema_ms: None,
            custody_meta: std::collections::HashMap::new(),
            custody_retry: std::collections::BTreeMap::new(),
            custody_expiry: std::collections::BTreeMap::new(),
            upstream_bytes: std::collections::HashMap::new(),
            outbound_index: std::collections::HashMap::new(),
            outbound_due: std::collections::BTreeMap::new(),
            outbound_deadline: std::collections::BTreeMap::new(),
            outbound_expiry: std::collections::BTreeMap::new(),
            no_route_backoff: std::collections::HashMap::new(),
            awaiting_record: std::collections::HashMap::new(),
            distance_cache: std::collections::HashMap::new(),
            record_refresh_at: first_refresh,
            recently_lost: Vec::new(),
            last_published_links: Vec::new(),
            last_publish_at: None,
            publish_pending: false,
            publish_retry_at: None,
            record_salt,
            neighbor_salt,
            pending_dials: Vec::new(),
            dial_backoff: std::collections::HashMap::new(),
            neighbor_check_at: None,
            outbound_links: std::collections::HashMap::new(),
            saved_peers: std::collections::HashMap::new(),
            own_record_exp: 0,
            next_reconcile_at: now + secs_to_ms(1),
            rng,
            now,
            draining: local::DrainState::Serving,
            ck_claims: BTreeMap::new(),
            next_claim_sweep_at: now + CLAIM_SWEEP_MS,
            next_data_sweep_at: now + DATA_SWEEP_MS,
            contested: 0,
            record_index: BTreeMap::new(),
            derived_version: 0,
            graph_cache: None,
            items_cache: None,
            waypoint_cache: None,
            #[cfg(test)]
            validation_count: 0,
            diagnostics: Vec::new(),
        };
        // Load and validate the stored records once; the index serves
        // every later read. Records that fail validation stay in the store
        // (the retention sweep drops them) but are never served. Seed the
        // claim set from the same pass so links can be attributed
        // immediately after a restart. Best-effort: on failure the claims
        // rebuild as records are re-admitted; report it.
        match node.store.record_all() {
            Ok(records) => {
                for record in records {
                    if let Some(parsed) = node.validate_stored(&record.bytes, now, true).valid() {
                        let rec = parsed.into_inner();
                        if let Some(k) = Self::claim_key(&rec) {
                            node.ck_claims.entry(k).or_default().insert(rec.id);
                        }
                        node.index_record(&record.bytes, rec);
                    }
                }
            }
            Err(e) => node.diag("record_all", &e),
        }
        // Load the saved neighbor set; `startup_dials` re-dials them
        // (anchors first) before the daemon dials its configured roots.
        match node.store.saved_peer_all() {
            Ok(peers) => {
                for p in peers {
                    node.saved_peers.insert((p.id, p.scope), p);
                }
            }
            Err(e) => node.diag("saved_peer_all", &e),
        }
        if !own_exists {
            node.publish_record(now)?;
            // The startup publish does not arm the republish floor: the
            // first link-triggered publish must go out immediately, or a
            // fresh node stays unroutable for a whole republish interval.
            node.last_publish_at = None;
        } else if let Some(stored) = node.store.record_get(&id, Scope::Wan)? {
            // Seed the change detector from the stored record so the first
            // tick does not see a spurious difference against an empty
            // advertised set.
            match lattice_proto::record::PeerRecord::parse(&stored.bytes) {
                Ok(p) => {
                    node.own_seq = p.seq();
                    node.own_record_exp = p.exp();
                    node.last_published_links = p.links().to_vec();
                }
                Err(_) => {
                    node.own_seq = 0;
                    node.own_record_exp = 0;
                }
            }
            // A stored record nearing expiry is refreshed on the first
            // tick rather than after a full refresh interval.
            if node.own_record_exp.saturating_sub(ms_to_secs(now)) < REFRESH_EXP_HORIZON_SECS {
                node.record_refresh_at = now;
            }
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
                for msg in all {
                    let mut msg = outbound_from_store(msg);
                    if msg.state == OutboundState::InFlight && msg.requeue(now) {
                        if let Err(e) = node.store.outbound_put(&outbound_to_store(&msg)) {
                            node.diag("outbound_put", &e);
                        }
                    }
                }
            }
            Err(e) => node.diag("outbound_all", &e),
        }
        // Rebuild the in-memory due-time indexes and the per-upstream byte
        // counts from the store; neither is persisted. Custody entries are
        // re-armed for immediate forwarding. Queued messages whose recipient
        // has no record are awaiting one; their grace deadline is the
        // persisted `next_attempt`.
        match node.store.outbound_all() {
            Ok(all) => {
                for msg in all {
                    let msg = outbound_from_store(msg);
                    if msg.state == OutboundState::Queued && !node.has_record(&msg.recipient) {
                        node.awaiting_record
                            .entry(msg.recipient)
                            .or_default()
                            .insert(msg.mid);
                    }
                    node.index_outbound(&msg);
                }
            }
            Err(e) => node.diag("outbound_all", &e),
        }
        match node.store.custody_all() {
            Ok(all) => {
                for entry in all {
                    let entry = custody_from_store(entry);
                    node.track_custody_insert(&entry, now);
                }
            }
            Err(e) => node.diag("custody_all", &e),
        }
        Ok(node)
    }

    /// Handle one event. Returns the actions to perform and any diagnostics
    /// (non-fatal internal failures, e.g. store errors) observed while
    /// handling it. Diagnostics are drained on every call; a caller that
    /// drops them loses them.
    ///
    /// All timestamps are milliseconds since the Unix epoch. After handling
    /// an event, call [`Node::next_deadline`] to learn when the core next
    /// wants to be woken (via [`Event::Tick`]); there is no periodic tick.
    pub fn handle(&mut self, event: Event) -> (Vec<Action>, Vec<Diagnostic>) {
        let actions = self.handle_inner(event);
        let actions = self.drop_oversize_frames(actions);
        self.note_outbound_frames(&actions);
        (actions, std::mem::take(&mut self.diagnostics))
    }

    /// Handle a batch of events inside one store transaction.
    ///
    /// The batch is the unit of durability: every store operation the
    /// events trigger is staged in one transaction, committed once, and
    /// the returned actions are released only after the commit succeeds.
    /// If any store operation fails, or the commit itself fails, the
    /// batch is discarded: no action is returned, so no
    /// durability-dependent action (a custody `ACCEPTED`, an app send
    /// acceptance) is released for work that did not become durable.
    ///
    /// The events are processed in order, exactly as if [`Node::handle`]
    /// had been called on each in turn; only the commit boundary moves.
    /// On error the node's in-memory state may reflect events whose
    /// effects were rolled back; the caller must treat the node as
    /// untrusted (the daemon exits and rebuilds from the store).
    pub fn handle_batch(
        &mut self,
        events: Vec<Event>,
    ) -> Result<(Vec<Action>, Vec<Diagnostic>), StoreError> {
        self.store.begin_batch()?;
        let mut actions = Vec::new();
        let mut diagnostics = Vec::new();
        for event in events {
            let (a, d) = self.handle(event);
            actions.extend(a);
            diagnostics.extend(d);
        }
        match self.store.commit_batch() {
            Ok(()) => Ok((actions, diagnostics)),
            Err(e) => {
                // The commit failed; the batch was discarded by the
                // store. Drop the actions on the floor: none of them may
                // be released. `abort_batch` is a no-op if the store
                // already discarded the batch, and discards it otherwise.
                self.store.abort_batch();
                Err(e)
            }
        }
    }

    /// Drop any outbound frame that cannot be encoded into a bucket. An
    /// unencodable frame is a local bug, not a link failure: log it and
    /// drop it here so the transport never sees it.
    fn drop_oversize_frames(&mut self, actions: Vec<Action>) -> Vec<Action> {
        actions
            .into_iter()
            .filter(|action| {
                let Action::SendFrame { frame, pad_to, .. } = action else {
                    return true;
                };
                if frame_budget::frame_fits(frame, *pad_to) {
                    return true;
                }
                self.diag(
                    "frame_too_large",
                    format!("dropping unencodable {} frame", frame_kind(frame)),
                );
                false
            })
            .collect()
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
            Event::DialFailed { at, peer } => self.on_dial_failed(at, peer),
            Event::Frame {
                at,
                link,
                frame,
                bucket,
                ..
            } => self.on_frame(at, link, frame, bucket),
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
    /// The next instant at which the core wants to be woken, in
    /// milliseconds since the Unix epoch, or `None` if nothing is pending.
    ///
    /// The caller (daemon or simulator) arms a timer for exactly this
    /// instant and delivers [`Event::Tick`] then; the core does no work
    /// between wakes. Recomputed from current state on every call.
    pub fn next_deadline(&self) -> Option<u64> {
        let mut best: Option<u64> = None;
        // `u64::MAX` means "no deadline" (e.g. snow disabled).
        let mut consider = |t: u64| {
            if t == u64::MAX {
                return;
            }
            best = Some(best.map_or(t, |b: u64| b.min(t)));
        };
        if self.config.snow_per_min > 0.0 {
            consider(self.snow_next);
        }
        if let Some(d) = self.inner_pending_echo.iter().map(|p| p.due).min() {
            consider(d);
        }
        consider(self.next_reconcile_at);
        consider(self.record_refresh_at);
        consider(self.next_claim_sweep_at);
        consider(self.next_data_sweep_at);
        // A spaced-out republish comes due at the end of the spacing
        // window; a lost link leaves the advertised set when its grace expires.
        if self.publish_pending {
            if let Some(t) = self.publish_retry_at {
                consider(t);
            } else if let Some(t) = self.last_publish_at {
                consider(t.saturating_add(secs_to_ms(self.config.republish_min_interval_secs)));
            }
        }
        if let Some(t) = self.recently_lost.iter().map(|l| l.lost_at).min() {
            // Wake one tick past the grace boundary, when the entry is
            // actually pruned and the advertised set changes.
            consider(t.saturating_add(LINK_GRACE_MS).saturating_add(1));
        }
        if let Some(t) = self.custody_retry.keys().next() {
            consider(*t);
        }
        if let Some(t) = self
            .dial_backoff
            .values()
            .map(|(_, t)| *t)
            .filter(|t| *t > self.now)
            .min()
        {
            consider(t);
        }
        if let Some(t) = self.neighbor_check_at {
            consider(t);
        }
        if let Some(t) = self
            .pending
            .values()
            .map(|p| p.sent_at.saturating_add(CUSTODY_TIMEOUT_MS))
            .min()
        {
            consider(t);
        }
        if let Some(t) = self.outbound_due.keys().next() {
            consider(*t);
        }
        if let Some(t) = self.outbound_deadline.keys().next() {
            consider(*t);
        }
        if let Some(t) = self.outbound_expiry.keys().next() {
            consider(*t);
        }
        if let Some(t) = self.custody_expiry.keys().next() {
            consider(*t);
        }
        best
    }

    fn touch(&mut self, at: u64) {
        self.now = at;
    }

    // ---------- records ----------

    fn build_own_record(&mut self, prev_seq: u64, now: u64) -> Result<Vec<u8>, NodeError> {
        // Wire times are seconds.
        let now_secs = ms_to_secs(now);
        let exp = now_secs + RECORD_LIFETIME_SECS;
        let private = self.config.mode == Mode::Private;
        let links: Vec<Identifier> = if private {
            vec![]
        } else {
            self.advertised_links(now)
        };
        let requested_links = links.len();
        let endpoints: Vec<lattice_proto::record::Endpoint> = if private {
            Vec::new()
        } else {
            self.config
                .advertise
                .iter()
                .map(|url| lattice_proto::record::Endpoint {
                    url: url.clone(),
                    ips: self.config.advertise_ips.clone(),
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
                now: now_secs,
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
                serves: if private {
                    Vec::new()
                } else {
                    self.config.serves.clone()
                },
            },
            &self.identity.signing_seed,
        )?;
        if rec.links.len() < requested_links {
            self.diag(
                "record_links_dropped",
                format!(
                    "record exceeded the size cap; dropped {} link(s)",
                    requested_links - rec.links.len()
                ),
            );
        }
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
        self.store
            .kel_put(&self.own_id, &bytes, &kel_head_to_store(seen))?;
        Ok(())
    }

    /// The links to advertise, in preference order: live links first,
    /// then pinned (anchor) links, then longest-lived, deduplicated by
    /// peer and capped at the record link cap. Links that went down
    /// within the grace window stay in the set. Callers pass the result
    /// to `PeerRecord::build`, which drops from the tail if the record
    /// would exceed the wire cap.
    fn advertised_links(&mut self, now: u64) -> Vec<Identifier> {
        self.recently_lost
            .retain(|l| now.saturating_sub(l.lost_at) <= LINK_GRACE_MS);
        let mut cand: Vec<(bool, bool, u64, Identifier)> =
            Vec::with_capacity(self.links.len() + self.recently_lost.len());
        for l in self.links.values() {
            if let Some(peer) = l.peer {
                cand.push((true, l.pinned, l.since, peer));
            }
        }
        for l in &self.recently_lost {
            if cand.iter().any(|c| c.3 == l.peer) {
                continue;
            }
            cand.push((false, l.pinned, l.since, l.peer));
        }
        // Live links first, then anchors, then longest-lived, then id for
        // a deterministic order.
        cand.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.1.cmp(&a.1))
                .then(a.2.cmp(&b.2))
                .then(a.3.cmp(&b.3))
        });
        let mut seen = HashSet::with_capacity(cand.len());
        let mut out = Vec::with_capacity(lattice_proto::record::MAX_LINKS);
        for (_, _, _, id) in cand {
            if seen.insert(id) {
                out.push(id);
                if out.len() >= lattice_proto::record::MAX_LINKS {
                    break;
                }
            }
        }
        out
    }

    /// Mark the advertised set dirty if it changed, and publish if the
    /// spacing floor allows. Called after every link event and on ticks
    /// (so grace-period expiry is noticed).
    fn note_link_set_changed(&mut self, now: u64) {
        if self.advertised_links(now) != self.last_published_links {
            self.publish_pending = true;
        }
        self.flush_pending_publish(now);
    }

    /// Publish if a republish is owed and the spacing floor has elapsed.
    fn flush_pending_publish(&mut self, now: u64) {
        if !self.publish_pending {
            return;
        }
        if let Some(t) = self.publish_retry_at {
            if now < t {
                return;
            }
        }
        if let Some(t) = self.last_publish_at {
            if now < t.saturating_add(secs_to_ms(self.config.republish_min_interval_secs)) {
                return;
            }
        }
        if let Err(e) = self.publish_record(now) {
            self.diag("publish_record", &e);
            // Back off before retrying so a persistent failure cannot
            // spin the event loop.
            self.publish_retry_at = Some(now + PUBLISH_RETRY_MS);
        } else {
            self.publish_retry_at = None;
        }
    }

    fn publish_record(&mut self, now: u64) -> Result<(), NodeError> {
        let bytes = self.build_own_record(self.own_seq, now)?;
        let id = self.own_id;
        // Adopt the seq the builder assigned (max(prev + 1, now)).
        if let Ok(parsed) = PeerRecord::parse(&bytes) {
            self.own_seq = parsed.seq();
            self.own_record_exp = parsed.exp();
        }
        self.store
            .record_put(&id, self.scope, &bytes, ms_to_secs(now))?;
        // The own record is validated here too, so the index only ever
        // holds records that passed full validation.
        match PeerRecord::parse(&bytes)
            .and_then(|p| p.validate(Some(ms_to_secs(now)), &self.identity.kel))
        {
            Ok(v) => self.index_record(&bytes, v.into_inner()),
            Err(e) => self.diag("own_record_validate", &e),
        }
        self.last_publish_at = Some(now);
        self.last_published_links = self.advertised_links(now);
        self.publish_pending = false;
        self.publish_retry_at = None;
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
        // A core-initiated dial is recognized by the peer's channel key;
        // the link becomes an outbound link for cap accounting and
        // eviction.
        if let Some(pos) = self.pending_dials.iter().position(|d| d.ck == remote_ck) {
            let d = self.pending_dials.remove(pos);
            self.dial_backoff.remove(&(d.peer, d.scope));
            self.outbound_links.insert(
                link,
                OutboundLink {
                    peer: d.peer,
                    scope: d.scope,
                    hash: d.hash,
                    evict_on_success: d.evict_on_success,
                    range: d.range,
                },
            );
        }
        self.links
            .insert(link, LinkState::new(peer, remote_ck, peer.is_some(), at));
        self.next_link_order.push(link);
        self.reconcile_sessions
            .insert(link, ReconcileSession::new());
        // Reconcile promptly: the peer needs our record (and we need theirs)
        // for routing to work at all; waiting a full interval stalls delivery.
        self.next_reconcile_at = self.next_reconcile_at.min(at + secs_to_ms(1));
        let mut actions = self.reevaluate_link_bindings(at);
        actions.extend(self.maybe_evict_after_bind(link));
        // Publish if the advertised set changed (spaced; see
        // `flush_pending_publish`).
        self.note_link_set_changed(at);
        // A new link may open routes for custody entries that had none.
        actions.extend(self.drain_custody(at));
        actions
    }

    fn on_link_down(&mut self, at: u64, link: LinkId) -> Vec<Action> {
        self.touch(at);
        if let Some(ob) = self.outbound_links.remove(&link) {
            // A dropped outbound link frees a slot; back off briefly so a
            // flapping peer is not redialed in a tight loop.
            self.dial_backoff.insert(
                (ob.peer, ob.scope),
                (1, at.saturating_add(neighbor::LINK_DOWN_BACKOFF_MS)),
            );
        }
        if let Some(l) = self.links.remove(&link) {
            if let Some(peer) = l.peer {
                // Keep the peer in the advertised set for the grace window.
                self.recently_lost.push(LostLink {
                    peer,
                    pinned: l.pinned,
                    since: l.since,
                    lost_at: at,
                });
                // Bound the grace list; the oldest entries age out first.
                if self.recently_lost.len() > 128 {
                    self.recently_lost.remove(0);
                }
            }
        }
        self.next_link_order.retain(|l| *l != link);
        self.reconcile_sessions.remove(&link);
        self.note_link_set_changed(at);
        // A freed slot may fit a candidate; re-run the selection on the
        // next tick rather than inline, so a burst of link drops is
        // re-filled in one batched pass (the per-range sub-caps are only
        // meaningful when the whole candidate set is considered at once).
        self.set_neighbor_check(at);
        Vec::new()
    }

    /// Insert (or replace) a validated record in the index. Bumps the
    /// derived-data version. `bytes` are the stored bytes the record was
    /// validated from; their hash keys the reconcile item hash-prefix and
    /// the admission order.
    fn index_record(&mut self, bytes: &[u8], record: lattice_proto::record::PeerRecord) {
        let hash = lattice_proto::record::record_hash(bytes);
        self.record_index.insert(
            (record.id, scope_as_u8(record.scope)),
            IndexedRecord { record, hash },
        );
        self.derived_version += 1;
    }

    /// Drop an index entry, if present. Bumps the derived-data version
    /// only when something was actually removed.
    fn unindex_record(&mut self, id: &Identifier, scope: Scope) {
        if self
            .record_index
            .remove(&(*id, scope_as_u8(scope)))
            .is_some()
        {
            self.derived_version += 1;
        }
    }

    /// Evict index entries whose expiry has passed. Reads filter on expiry
    /// anyway; this keeps the index bounded. Driven by the retention
    /// sweep; the store keeps the bytes until the grace period elapses.
    fn evict_expired_records(&mut self, now: u64) {
        let now_secs = ms_to_secs(now);
        let before = self.record_index.len();
        self.record_index.retain(|_, e| e.record.exp > now_secs);
        if self.record_index.len() != before {
            self.derived_version += 1;
        }
    }

    /// Salted eviction key for a stored record. The salt is per-node and
    /// drawn from the RNG at startup, so a peer choosing which records to
    /// push cannot predict which will be evicted.
    fn record_eviction_key(&self, id: &Identifier, scope: Scope) -> Hash32 {
        let mut buf = Vec::with_capacity(32 + 1 + 32);
        buf.extend_from_slice(&self.record_salt);
        buf.extend_from_slice(id.as_bytes());
        buf.push(scope_as_u8(scope));
        lattice_crypto::hash(&buf)
    }

    /// Enforce the record cap: evict the lowest-salted-hash records until
    /// at most `cap` remain. Our own record is never evicted.
    fn enforce_record_cap(&mut self, cap: usize) {
        let count = match self.store.record_count() {
            Ok(c) => c,
            Err(e) => {
                self.diag("record_count", &e);
                return;
            }
        };
        if count <= cap {
            return;
        }
        let all = match self.store.record_all() {
            Ok(a) => a,
            Err(e) => {
                self.diag("record_all", &e);
                return;
            }
        };
        let mut keyed: Vec<(Hash32, Identifier, Scope)> = all
            .into_iter()
            .filter(|r| r.id != self.own_id)
            .map(|r| (self.record_eviction_key(&r.id, r.scope), r.id, r.scope))
            .collect();
        keyed.sort_by_key(|k| k.0);
        let mut to_remove = count - cap;
        for (_, id, scope) in keyed {
            if to_remove == 0 {
                break;
            }
            match self.store.record_remove(&id, scope) {
                Ok(()) => {
                    self.unindex_record(&id, scope);
                    to_remove -= 1;
                }
                Err(e) => self.diag("record_remove", &e),
            }
        }
    }

    /// Build the routing graph from the in-memory index.
    ///
    /// Records were validated once, at admission or startup; building the
    /// graph is a BFS over already-validated entries, so it never touches
    /// the store or the signature verifier. The result is memoized on
    /// `(derived_version, now_secs)` so repeated calls within one second
    /// and one index mutation share one build.
    fn build_graph(&mut self) -> Arc<Graph> {
        let key = (self.derived_version, ms_to_secs(self.now));
        if let Some((v, t, g)) = &self.graph_cache {
            if (*v, *t) == key {
                return Arc::clone(g);
            }
        }
        let now_secs = ms_to_secs(self.now);
        let mut records: Vec<GraphRecord> = Vec::with_capacity(self.record_index.len());
        for entry in self.record_index.values() {
            if entry.record.exp <= now_secs {
                continue;
            }
            records.push(GraphRecord {
                id: entry.record.id,
                links: entry.record.links.clone(),
                private: entry.record.mode == Mode::Private,
                gateways: entry.record.gateways.clone(),
                serves: entry.record.serves.clone(),
            });
        }
        // A private instance publishes no links, so the mutual-claim rule
        // would leave it unreachable. Its record names its gateways; the
        // graph adds a pseudo-edge to a gateway only when the gateway's
        // record names the private id in `serves` (spec §3, gateway
        // consent). Private nodes are leaves: reachable, never transit.
        let graph = Graph::build(&self.own_id, records);
        let graph = Arc::new(graph);
        self.graph_cache = Some((key.0, key.1, Arc::clone(&graph)));
        graph
    }

    /// Distance map from `source` to every reachable node, memoized per
    /// (records_version, now_secs, source). BFS is O(V + E); without this
    /// every custody forward recomputed it per entry per tick.
    fn distances_cached(&mut self, source: &Identifier) -> Arc<BTreeMap<Identifier, u32>> {
        let key = (self.derived_version, ms_to_secs(self.now), *source);
        if let Some(d) = self.distance_cache.get(&key) {
            return Arc::clone(d);
        }
        let graph = self.build_graph();
        let dist = Arc::new(graph.distances(source));
        if self.distance_cache.len() >= 256 {
            self.distance_cache.clear();
        }
        self.distance_cache.insert(key, Arc::clone(&dist));
        dist
    }

    /// Reconcile item list for the stored records. Memoized on the same
    /// key as [`Self::build_graph`]. Returns `None` when the KEL head set
    /// cannot be read: answering a reconcile with an incomplete set would
    /// tell the peer we hold less than we do, so the round is skipped
    /// instead.
    fn record_items(&mut self) -> Option<Vec<reconcile::Item>> {
        let key = (self.derived_version, self.now);
        if let Some((v, t, items)) = &self.items_cache {
            if (*v, *t) == key {
                return Some(items.clone());
            }
        }
        let now_secs = ms_to_secs(self.now);
        // Only unexpired records are advertised.
        let mut items: Vec<reconcile::Item> = self
            .record_index
            .values()
            .filter(|e| e.record.exp > now_secs)
            .map(|e| reconcile::Item {
                id: e.record.id,
                scope: scope_as_u8(e.record.scope),
                khs: e.record.khs,
                seq: e.record.seq,
                hash_prefix: e.hash.as_bytes()[..8].try_into().expect("hash is 32 bytes"),
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
        // A frame that opens a new round (a single unbounded fingerprint
        // range) invalidates the echo state of any round still in flight
        // on this link; start the round with a fresh session.
        if reconcile::opens_new_round(&frame.ranges) {
            self.reconcile_sessions
                .insert(link, ReconcileSession::new());
        }
        // Store unreadable: say nothing rather than claim we hold nothing.
        let Some(items) = self.record_items() else {
            return Vec::new();
        };
        let session = self.reconcile_sessions.entry(link).or_default();
        let reconcile::ReconcileResponse {
            ranges: reply,
            wants,
        } = reconcile::respond(&items, &frame.ranges, session);
        // Chunk the reply so every frame fits a bucket and carries at most
        // MAX_RANGES_PER_MSG ranges; the remainder goes in follow-up frames
        // rather than being dropped. Per-item sizes come from encoding a
        // one-element frame, an upper bound on the item's size inside the
        // real frame.
        let mut actions = Vec::new();
        for chunk in frame_budget::chunk_by_budget(reply, reconcile::MAX_RANGES_PER_MSG, |r| {
            Frame::Reconcile(ReconcileFrame {
                ranges: vec![r.clone()],
            })
            .encode()
            .len()
        }) {
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Reconcile(ReconcileFrame { ranges: chunk }),
            });
        }
        // Credit the link for the record-wants we send: records that
        // arrive against these credits are solicited and bypass the
        // unsolicited-push budget. KEL wants (scope 255) are not records.
        let record_wants = wants.iter().filter(|w| w.scope != SCOPE_KEL).count() as u32;
        if record_wants > 0 {
            if let Some(l) = self.links.get_mut(&link) {
                l.want_credits = l
                    .want_credits
                    .saturating_add(record_wants)
                    .min(MAX_WANT_CREDITS);
            }
        }
        for chunk in frame_budget::chunk_by_budget(wants, usize::MAX, |w| {
            Frame::Want(WantFrame { wants: vec![*w] }).encode().len()
        }) {
            actions.push(Action::SendFrame {
                pad_to: None,
                link,
                frame: Frame::Want(WantFrame { wants: chunk }),
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
                wants: vec![RecordRef {
                    id,
                    scope: SCOPE_KEL,
                }],
            }),
        }]
    }

    /// Ask `link` for the record for `id` in both scopes (WAN and hive).
    /// Sent when an offer arrives from an unknown sender: the record is
    /// needed to authenticate the sender (spec §5). Credits the link for
    /// the wants, like the reconcile path, so the records are admitted
    /// without spending the unsolicited-push budget.
    fn want_record(&mut self, link: LinkId, id: Identifier) -> Vec<Action> {
        let wants = vec![
            RecordRef {
                id,
                scope: scope_as_u8(Scope::Wan),
            },
            RecordRef {
                id,
                scope: scope_as_u8(Scope::Hive),
            },
        ];
        if let Some(l) = self.links.get_mut(&link) {
            l.want_credits = l
                .want_credits
                .saturating_add(wants.len() as u32)
                .min(MAX_WANT_CREDITS);
        }
        vec![Action::SendFrame {
            pad_to: None,
            link,
            frame: Frame::Want(WantFrame { wants }),
        }]
    }

    fn on_records(&mut self, at: u64, link: LinkId, records: Vec<Vec<u8>>) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut dropped = 0usize;
        for bytes in records {
            // Records we asked for (a `want` is outstanding) are admitted
            // freely; anything else spends from the per-link push budget.
            // Unsolicited records past the budget are dropped before
            // validation — they cost the sender nothing to forge, so they
            // must not cost us a validation and an fsync each.
            let admitted = match self.links.get_mut(&link) {
                Some(l) => {
                    if l.want_credits > 0 {
                        l.want_credits -= 1;
                        true
                    } else {
                        l.push_budget_take(at)
                    }
                }
                None => false,
            };
            if !admitted {
                dropped += 1;
                continue;
            }
            actions.extend(self.admit_record(at, link, &bytes));
        }
        if dropped > 0 {
            self.diag(
                "unsolicited_records_dropped",
                format!("dropped {dropped} unsolicited record(s) on link {link}"),
            );
        }
        // New records may open routes for custody entries that had none.
        actions.extend(self.drain_custody(at));
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
            // KEL heads are part of the reconcile item set; invalidate the
            // derived-data caches.
            self.derived_version += 1;
            // The records that cite these KELs can now be validated; ask
            // for them on the next round rather than waiting a full interval.
            self.next_reconcile_at = self.next_reconcile_at.min(at + secs_to_ms(1));
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
            Ok(s) => s.map(kel_head_from_store),
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
        let head_seen = kel_head_to_store(head_seen);
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
    ///
    /// This is the only place stored bytes are re-validated; it runs at
    /// startup and on the cold path of the retention sweep. The per-tick
    /// read paths (graph, reconcile items, waypoints, lookups) never call
    /// it — they read the in-memory index.
    fn validate_stored(&mut self, bytes: &[u8], now: u64, check_time: bool) -> StoredRecord {
        #[cfg(test)]
        {
            self.validation_count += 1;
        }
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
            parsed.validate(Some(ms_to_secs(now)), &kel)
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
                Ok(()) => self.unindex_record(id, scope),
                Err(e) => self.diag("record_remove", &e),
            }
        }
        for claims in self.ck_claims.values_mut() {
            claims.remove(id);
        }
        self.reevaluate_link_bindings(at)
    }

    /// Drop claims whose backing record is gone or no longer valid
    /// (expired). Rebuilt from the in-memory index, so this costs no
    /// store reads and no re-validation.
    fn sweep_ck_claims(&mut self, now: u64) -> Vec<Action> {
        let now_secs = ms_to_secs(now);
        let mut fresh: BTreeMap<X25519PublicKey, BTreeSet<Identifier>> = BTreeMap::new();
        for entry in self.record_index.values() {
            if entry.record.exp <= now_secs {
                continue;
            }
            if let Some(k) = Self::claim_key(&entry.record) {
                fresh.entry(k).or_default().insert(entry.record.id);
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
        // Entries whose expiry has passed leave the index; reads filter on
        // expiry anyway, this just keeps the index bounded. The store
        // keeps the bytes until the grace period elapses.
        self.evict_expired_records(now);
        self.enforce_record_cap(RECORD_CAP);
        match self.store.record_all() {
            Ok(records) => {
                for record in records {
                    if record.id == self.own_id {
                        continue;
                    }
                    if self
                        .record_index
                        .contains_key(&(record.id, scope_as_u8(record.scope)))
                    {
                        // Unexpired and validated at admission; keep.
                        continue;
                    }
                    // Not in the index: expired (evicted above or never
                    // admitted) or never valid. Fall back to a full
                    // validation to decide; this path is cold in normal
                    // operation. A record we could not check (store error)
                    // is kept.
                    let keep = match self.validate_stored(&record.bytes, now, false) {
                        // Record expiry is a wire time (seconds); compare in ms.
                        StoredRecord::Valid(p) => {
                            secs_to_ms(p.exp).saturating_add(RETENTION_GRACE_MS) >= now
                        }
                        StoredRecord::Invalid => false,
                        StoredRecord::Unknown => true,
                    };
                    if keep {
                        continue;
                    }
                    match self.store.record_remove(&record.id, record.scope) {
                        Ok(()) => self.unindex_record(&record.id, record.scope),
                        Err(e) => self.diag("record_remove", &e),
                    }
                }
            }
            Err(e) => self.diag("record_all", &e),
        }
        if let Err(e) = self
            .store
            .inbox_sweep_expired(INBOX_TTL_SECS, ms_to_secs(now))
        {
            self.diag("inbox_sweep_expired", &e);
        }
        match self.store.outbound_all() {
            Ok(all) => {
                for msg in all.into_iter().map(outbound_from_store) {
                    let terminal = msg.state.is_terminal();
                    if terminal && msg.exp.saturating_add(RETENTION_GRACE_MS) < now {
                        if let Err(e) = self.store.outbound_remove(&msg.mid) {
                            self.diag("outbound_remove", &e);
                        } else {
                            self.unindex_outbound(&msg.mid);
                        }
                    }
                }
            }
            Err(e) => self.diag("outbound_all", &e),
        }
        match self
            .store
            .kel_sweep(ms_to_secs(now).saturating_sub(KEL_HEAD_MAX_AGE_SECS))
        {
            Ok(n) => {
                if n > 0 {
                    // The reconcile set changed (KEL entries are gone).
                    self.derived_version += 1;
                }
            }
            Err(e) => self.diag("kel_sweep", &e),
        }
        // Retired-key grace times are wall-clock seconds (file names).
        self.identity.sweep_retired_envelope_keys(ms_to_secs(now));
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
            self.note_link_set_changed(at);
            self.next_reconcile_at = self.next_reconcile_at.min(at + secs_to_ms(1));
        }
        // Test-before-evict: a candidate that just bound evicts its
        // incumbent.
        let outbound: Vec<LinkId> = self.outbound_links.keys().copied().collect();
        for link in outbound {
            actions.extend(self.maybe_evict_after_bind(link));
        }
        // Refresh saved peers for every bound peer (cheap: writes only
        // when something changed or the entry is stale).
        let bound: Vec<Identifier> = self.links.values().filter_map(|l| l.peer).collect();
        for peer in bound {
            self.note_saved_peer(peer, at);
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
        let Ok(validated) = parsed.validate(Some(ms_to_secs(at)), &kel) else {
            // Stale (cites a head behind ours), malformed, or badly signed.
            return Vec::new();
        };
        // A validated record is evidence the identity is alive; keep its
        // KEL from aging out of the retention sweep.
        if let Err(e) = self.store.kel_touch(&id, ms_to_secs(at)) {
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
            match self.store.record_put(&rec.id, scope, bytes, ms_to_secs(at)) {
                Ok(()) => {
                    self.note_ck_claim(&rec);
                    let id = rec.id;
                    let has_endpoints = !rec.endpoints.is_empty();
                    self.index_record(bytes, rec);
                    self.enforce_record_cap(RECORD_CAP);
                    // The record is in the index: messages that were
                    // queued waiting for it can now be dispatched.
                    let mut actions = self.release_awaiting_record(&id, at);
                    actions.extend(self.reevaluate_link_bindings(at));
                    if has_endpoints {
                        // A new candidate may have appeared; ask for a
                        // near-term neighbor pass rather than running one
                        // per record in a gossip burst.
                        self.set_neighbor_check(at);
                    }
                    return actions;
                }
                Err(e) => {
                    self.diag("record_put", &e);
                    self.note_ck_claim(&rec);
                }
            }
            return self.reevaluate_link_bindings(at);
        }
        Vec::new()
    }

    // ============================================================
    // Neighbor selection (design §5)
    // ============================================================

    /// Dial actions for the saved neighbor set, anchors first. Called by
    /// the daemon once at startup, before it dials configured roots: a
    /// node that was connected before a restart re-forms its mesh before
    /// falling back to bootstrap hints.
    pub fn startup_dials(&mut self) -> Vec<Action> {
        let now = self.now;
        let mut actions = Vec::new();
        for scope in [Scope::Wan, Scope::Hive] {
            let cap = neighbor::scope_cap(scope);
            let mut outbound = self.outbound_count(scope);
            let mut group_counts = self.group_counts(scope);
            actions.extend(self.dial_saved_peers(
                now,
                scope,
                cap,
                &mut outbound,
                &mut group_counts,
            ));
        }
        actions
    }

    /// Ask for a neighbor-selection pass shortly after `now`. Keeps the
    /// earliest pending request.
    fn set_neighbor_check(&mut self, now: u64) {
        let at = now.saturating_add(NEIGHBOR_CHECK_DELAY_MS);
        self.neighbor_check_at = Some(self.neighbor_check_at.map_or(at, |t| t.min(at)));
    }

    /// Candidates derived from the record index: validated, unexpired
    /// records with endpoints, excluding our own record.
    fn neighbor_candidates(&self) -> Vec<Candidate> {
        self.record_index
            .values()
            .filter(|e| e.record.id != self.own_id && !e.record.endpoints.is_empty())
            .map(|e| {
                let rec = &e.record;
                let mut ips = Vec::new();
                for ep in &rec.endpoints {
                    ips.extend_from_slice(&ep.ips);
                }
                Candidate {
                    id: rec.id,
                    scope: rec.scope,
                    endpoint: rec.endpoints[0].url.clone(),
                    ips,
                    channel_key: rec.channel_key,
                    range: neighbor::range_key(&rec.endpoints),
                    hash: neighbor::candidate_hash(&self.neighbor_salt, rec.scope, &rec.id),
                }
            })
            .collect()
    }

    fn outbound_count(&self, scope: Scope) -> usize {
        let links = self
            .outbound_links
            .values()
            .filter(|l| l.scope == scope)
            .count();
        let pending = self
            .pending_dials
            .iter()
            .filter(|d| d.scope == scope)
            .count();
        links + pending
    }

    fn peer_linked(&self, id: &Identifier) -> bool {
        self.links.values().any(|l| l.peer.as_ref() == Some(id))
    }

    fn pending_peer(&self, id: &Identifier) -> bool {
        self.pending_dials.iter().any(|d| &d.peer == id)
    }

    fn in_backoff(&self, id: &Identifier, scope: Scope, now: u64) -> bool {
        self.dial_backoff
            .get(&(*id, scope))
            .is_some_and(|(_, until)| now < *until)
    }

    fn is_anchor(&self, id: &Identifier, scope: Scope) -> bool {
        self.saved_peers
            .get(&(*id, scope))
            .is_some_and(|p| p.anchor)
    }

    /// The worst (highest-hash) evictable outbound link in `scope`:
    /// not an anchor and not already targeted by a pending eviction.
    fn worst_evictable(&self, scope: Scope, reserved: &HashSet<LinkId>) -> Option<(LinkId, u64)> {
        self.outbound_links
            .iter()
            .filter(|(link, l)| {
                l.scope == scope && !reserved.contains(*link) && !self.is_anchor(&l.peer, scope)
            })
            .max_by_key(|(_, l)| l.hash)
            .map(|(link, l)| (*link, l.hash))
    }

    /// Emit a Dial action for a candidate and record the pending dial.
    /// Returns `None` (and skips the candidate) if the channel key does
    /// not convert to X25519.
    #[allow(clippy::too_many_arguments)]
    fn emit_dial(
        &mut self,
        id: Identifier,
        scope: Scope,
        endpoint: String,
        ips: Vec<std::net::IpAddr>,
        channel_key: lattice_types::ChannelPublicKey,
        hash: u64,
        evict_on_success: Option<LinkId>,
        now: u64,
        range: neighbor::RangeKey,
    ) -> Option<Action> {
        let Some(ck) = lattice_crypto::channel_x25519_public_from_ed25519(&channel_key) else {
            self.diag(
                "neighbor",
                "candidate channel key does not convert to X25519; skipping",
            );
            return None;
        };
        self.pending_dials.push(PendingDial {
            peer: id,
            scope,
            ck,
            hash,
            evict_on_success,
            since: now,
            range,
        });
        Some(Action::Dial {
            endpoint,
            ips,
            scope,
            channel_key,
            peer: id,
            evict_on_success,
        })
    }

    /// Per-range-group occupancy (outbound links + pending dials) for a
    /// scope. The per-group sub-cap is enforced against this count across
    /// both the saved-peer and the candidate dial paths.
    fn group_counts(&self, scope: Scope) -> std::collections::HashMap<neighbor::RangeKey, usize> {
        let mut counts = std::collections::HashMap::new();
        for l in self.outbound_links.values().filter(|l| l.scope == scope) {
            *counts.entry(l.range.clone()).or_default() += 1;
        }
        for d in self.pending_dials.iter().filter(|d| d.scope == scope) {
            *counts.entry(d.range.clone()).or_default() += 1;
        }
        counts
    }

    /// Dial saved peers (anchors first, then most recently saved), up to
    /// the per-scope cap and the per-group sub-cap. Used at startup and
    /// on every maintenance pass.
    fn dial_saved_peers(
        &mut self,
        now: u64,
        scope: Scope,
        cap: usize,
        outbound: &mut usize,
        group_counts: &mut std::collections::HashMap<neighbor::RangeKey, usize>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let mut peers: Vec<SavedPeer> = self
            .saved_peers
            .values()
            .filter(|p| p.scope == scope)
            .cloned()
            .collect();
        peers.sort_by(|a, b| {
            b.anchor
                .cmp(&a.anchor)
                .then_with(|| b.saved_at.cmp(&a.saved_at))
        });
        for p in peers {
            if *outbound >= cap {
                break;
            }
            if self.peer_linked(&p.id) || self.pending_peer(&p.id) {
                continue;
            }
            if self.in_backoff(&p.id, scope, now) {
                continue;
            }
            let rk = neighbor::range_key_of(&p.endpoint, &p.ips);
            if group_counts.get(&rk).copied().unwrap_or(0) >= rk.sub_cap() {
                continue;
            }
            let hash = neighbor::candidate_hash(&self.neighbor_salt, scope, &p.id);
            if let Some(a) = self.emit_dial(
                p.id,
                scope,
                p.endpoint.clone(),
                p.ips.clone(),
                p.channel_key,
                hash,
                None,
                now,
                rk.clone(),
            ) {
                actions.push(a);
                *group_counts.entry(rk).or_default() += 1;
                *outbound += 1;
            }
        }
        actions
    }

    /// One maintenance pass: drop stale pending dials, re-dial saved
    /// peers, then fill remaining slots from the candidate set — or, when
    /// at cap, dial a strictly better candidate to replace the worst
    /// incumbent (test-before-evict). The per-range sub-cap is shared
    /// across both paths.
    fn maintain_neighbors(&mut self, now: u64) -> Vec<Action> {
        let before = self.pending_dials.len();
        self.pending_dials
            .retain(|d| now.saturating_sub(d.since) < PENDING_DIAL_TIMEOUT_MS);
        if self.pending_dials.len() != before {
            self.diag("neighbor", "dropped stale pending dials");
        }
        // Expired backoff entries have done their job; drop them so they
        // do not linger as stale deadlines.
        self.dial_backoff.retain(|_, (_, until)| *until > now);

        let candidates = self.neighbor_candidates();
        let mut actions = Vec::new();
        for scope in [Scope::Wan, Scope::Hive] {
            let cap = neighbor::scope_cap(scope);
            let mut outbound = self.outbound_count(scope);
            let mut group_counts = self.group_counts(scope);
            actions.extend(self.dial_saved_peers(
                now,
                scope,
                cap,
                &mut outbound,
                &mut group_counts,
            ));
            // Candidates in hash order.
            let mut idx: Vec<usize> = (0..candidates.len())
                .filter(|&i| candidates[i].scope == scope)
                .collect();
            idx.sort_by(|&a, &b| {
                candidates[a]
                    .hash
                    .cmp(&candidates[b].hash)
                    .then_with(|| candidates[a].id.as_bytes().cmp(candidates[b].id.as_bytes()))
            });
            // Incumbents already targeted by a pending eviction; a second
            // eviction dial must pick a different victim.
            let mut reserved: HashSet<LinkId> = self
                .pending_dials
                .iter()
                .filter_map(|d| d.evict_on_success)
                .collect();
            for i in idx {
                let c = &candidates[i];
                if self.peer_linked(&c.id)
                    || self.pending_peer(&c.id)
                    || self.in_backoff(&c.id, scope, now)
                {
                    continue;
                }
                let rk = &c.range;
                let used = group_counts.get(rk).copied().unwrap_or(0);
                if outbound < cap {
                    if used >= rk.sub_cap() {
                        continue;
                    }
                    if let Some(a) = self.emit_dial(
                        c.id,
                        scope,
                        c.endpoint.clone(),
                        c.ips.clone(),
                        c.channel_key,
                        c.hash,
                        None,
                        now,
                        rk.clone(),
                    ) {
                        actions.push(a);
                        *group_counts.entry(rk.clone()).or_default() += 1;
                        outbound += 1;
                    }
                    continue;
                }
                // At cap: test-before-evict. Dial the better candidate;
                // the incumbent is evicted only after the candidate binds.
                if let Some((inc, inc_hash)) = self.worst_evictable(scope, &reserved) {
                    if c.hash >= inc_hash {
                        continue;
                    }
                    // The sub-cap still applies, unless the eviction
                    // victim is in the same group (a straight swap).
                    let same_group = self
                        .outbound_links
                        .get(&inc)
                        .is_some_and(|l| &l.range == rk);
                    if used < rk.sub_cap() || same_group {
                        if let Some(a) = self.emit_dial(
                            c.id,
                            scope,
                            c.endpoint.clone(),
                            c.ips.clone(),
                            c.channel_key,
                            c.hash,
                            Some(inc),
                            now,
                            rk.clone(),
                        ) {
                            reserved.insert(inc);
                            actions.push(a);
                            *group_counts.entry(rk.clone()).or_default() += 1;
                        }
                    }
                }
            }
        }
        self.maintain_anchors(&candidates, now);
        actions
    }

    /// Designate anchors: keep existing anchors that are still linked or
    /// still known (record present), drop the rest, and fill free slots
    /// from the best-hashed linked candidates. Anchors are persisted in
    /// the saved-peer table and are never evicted by selection.
    fn maintain_anchors(&mut self, candidates: &[Candidate], now: u64) {
        let linked: HashSet<Identifier> = self.outbound_links.values().map(|l| l.peer).collect();
        let known: HashSet<(Identifier, Scope)> =
            candidates.iter().map(|c| (c.id, c.scope)).collect();
        let mut changed: Vec<(Identifier, Scope)> = Vec::new();
        for p in self.saved_peers.values_mut() {
            if p.anchor && !linked.contains(&p.id) && !known.contains(&(p.id, p.scope)) {
                p.anchor = false;
                changed.push((p.id, p.scope));
            }
        }
        let mut anchors = self.saved_peers.values().filter(|p| p.anchor).count();
        if anchors < neighbor::ANCHOR_COUNT {
            let mut linked_cands: Vec<&Candidate> = candidates
                .iter()
                .filter(|c| linked.contains(&c.id))
                .filter(|c| {
                    !self
                        .saved_peers
                        .get(&(c.id, c.scope))
                        .is_some_and(|p| p.anchor)
                })
                .collect();
            linked_cands.sort_by(|a, b| {
                a.hash
                    .cmp(&b.hash)
                    .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
            });
            for c in linked_cands {
                if anchors >= neighbor::ANCHOR_COUNT {
                    break;
                }
                let entry = self
                    .saved_peers
                    .entry((c.id, c.scope))
                    .or_insert_with(|| SavedPeer {
                        id: c.id,
                        scope: c.scope,
                        endpoint: c.endpoint.clone(),
                        ips: c.ips.clone(),
                        channel_key: c.channel_key,
                        saved_at: ms_to_secs(now),
                        anchor: false,
                    });
                if !entry.anchor {
                    entry.anchor = true;
                    changed.push((c.id, c.scope));
                    anchors += 1;
                }
            }
        }
        for (id, scope) in changed {
            if let Some(p) = self.saved_peers.get(&(id, scope)) {
                let p = p.clone();
                if let Err(e) = self.store.saved_peer_put(&p) {
                    self.diag("saved_peer_put", &e);
                }
            }
        }
    }

    /// Persist (or refresh) the saved-peer entry for `peer` from its
    /// record, if it has endpoints. Called when a link binds and when a
    /// record is admitted for a linked peer.
    fn note_saved_peer(&mut self, peer: Identifier, now: u64) {
        for scope in [Scope::Wan, Scope::Hive] {
            let Some(rec) = self
                .record_index
                .get(&(peer, scope_as_u8(scope)))
                .map(|e| &e.record)
            else {
                continue;
            };
            if rec.endpoints.is_empty() {
                continue;
            }
            let endpoint = rec.endpoints[0].url.clone();
            let ips: Vec<std::net::IpAddr> = rec
                .endpoints
                .iter()
                .flat_map(|e| e.ips.iter().copied())
                .collect();
            let now_secs = ms_to_secs(now);
            let existed = self.saved_peers.contains_key(&(peer, scope));
            let entry = self
                .saved_peers
                .entry((peer, scope))
                .or_insert_with(|| SavedPeer {
                    id: peer,
                    scope,
                    endpoint: endpoint.clone(),
                    ips: ips.clone(),
                    channel_key: rec.channel_key,
                    saved_at: now_secs,
                    anchor: false,
                });
            let stale = now_secs.saturating_sub(entry.saved_at) >= SAVED_PEER_REFRESH_SECS;
            let changed = !existed
                || entry.endpoint != endpoint
                || entry.ips != ips
                || entry.channel_key != rec.channel_key;
            if changed || stale {
                entry.endpoint = endpoint;
                entry.ips = ips;
                entry.channel_key = rec.channel_key;
                entry.saved_at = now_secs;
                let p = entry.clone();
                if let Err(e) = self.store.saved_peer_put(&p) {
                    self.diag("saved_peer_put", &e);
                }
            }
        }
        // Bound the table: evict the oldest non-anchor entries, preferring
        // peers we are not currently linked to (a linked peer re-saves
        // itself on the next bind anyway, but there is no reason to drop
        // it first).
        while self.saved_peers.len() > neighbor::MAX_SAVED_PEERS {
            let linked: HashSet<Identifier> =
                self.links.values().filter_map(|l| l.peer).collect();
            let victim = self
                .saved_peers
                .values()
                .filter(|p| !p.anchor && !linked.contains(&p.id))
                .min_by_key(|p| p.saved_at)
                .or_else(|| {
                    self.saved_peers
                        .values()
                        .filter(|p| !p.anchor)
                        .min_by_key(|p| p.saved_at)
                })
                .map(|p| (p.id, p.scope));
            let Some((id, scope)) = victim else { break };
            self.saved_peers.remove(&(id, scope));
            if let Err(e) = self.store.saved_peer_remove(&id, scope) {
                self.diag("saved_peer_remove", &e);
            }
        }
    }

    /// If `link` was dialed to replace an incumbent and is now bound to
    /// the candidate, close the incumbent (test-before-evict).
    fn maybe_evict_after_bind(&mut self, link: LinkId) -> Vec<Action> {
        let Some(ob) = self.outbound_links.get(&link) else {
            return Vec::new();
        };
        let Some(incumbent) = ob.evict_on_success else {
            return Vec::new();
        };
        let bound = self.links.get(&link).and_then(|l| l.peer);
        if bound != Some(ob.peer) {
            return Vec::new();
        }
        if let Some(ob) = self.outbound_links.get_mut(&link) {
            ob.evict_on_success = None;
        }
        vec![Action::CloseLink { link: incumbent }]
    }

    /// Handle a failed candidate dial: clear the pending entry and back
    /// off. The incumbent (if any) is untouched — that is the point of
    /// test-before-evict.
    fn on_dial_failed(&mut self, at: u64, peer: Identifier) -> Vec<Action> {
        if let Some(pos) = self.pending_dials.iter().position(|d| d.peer == peer) {
            let d = self.pending_dials.remove(pos);
            let attempts = self
                .dial_backoff
                .get(&(peer, d.scope))
                .map(|(n, _)| *n)
                .unwrap_or(0);
            let shift = attempts.min(6);
            let delay = neighbor::DIAL_BACKOFF_BASE_MS
                .saturating_mul(1u64 << shift)
                .min(neighbor::DIAL_BACKOFF_MAX_MS);
            self.dial_backoff
                .insert((peer, d.scope), (attempts + 1, at.saturating_add(delay)));
        }
        // A slot may have freed up; re-run the selection on the next
        // tick rather than inline, so a burst of dial failures is
        // handled in one batched pass.
        self.set_neighbor_check(at);
        Vec::new()
    }
}

// ============================================================
// Messaging engine
// ============================================================

/// The wire bytes of a built message.
struct BuildOutput {
    wire: Vec<u8>,
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

const CUSTODY_TIMEOUT_MS: u64 = 30_000;
const CLAIM_SWEEP_MS: u64 = 60_000;
const MAX_PENDING_ECHOES: usize = 256;
/// How long a lost link stays in the advertised set (spec §3 grace).
const LINK_GRACE_MS: u64 = 5 * 60 * 1000;
/// How long a pending dial may go unresolved before it is dropped and the
/// candidate becomes dialable again. The daemon's dial deadline is 15s;
/// this is the backstop for a lost outcome.
const PENDING_DIAL_TIMEOUT_MS: u64 = 30_000;
/// How soon after a record with endpoints is admitted the neighbor
/// selection runs. Batches a gossip burst into one selection pass.
const NEIGHBOR_CHECK_DELAY_MS: u64 = 1_000;
/// How often a saved peer's stored entry is refreshed even if nothing
/// changed (keeps `saved_at` roughly current for eviction ordering).
const SAVED_PEER_REFRESH_SECS: u64 = 3600;
/// Cap on stored records; eviction is by salted hash (see `record_salt`).
const RECORD_CAP: usize = 4096;
/// Republish the record when its expiry is this close, even if nothing
/// else changed — otherwise a quiet node's record would lapse.
const REFRESH_EXP_HORIZON_SECS: u64 = 3 * 24 * 3600;
/// Lifetime of a published record (seconds).
const RECORD_LIFETIME_SECS: u64 = 7 * 24 * 3600;
/// Per-link budget for unsolicited records (records no `want` asked for):
/// burst capacity, refilled at this rate per second.
const PUSH_BUDGET_CAPACITY: f64 = 16.0;
const PUSH_BUDGET_REFILL_PER_SEC: f64 = 16.0 / 60.0;
/// Cap on outstanding record-want credits per link; bounds how many
/// records a peer may send us "on request" before we have seen them.
const MAX_WANT_CREDITS: u32 = 4096;
/// Backoff before retrying a failed record publish.
const PUBLISH_RETRY_MS: u64 = 30_000;
/// How often the retention sweep runs.
const DATA_SWEEP_MS: u64 = 3_600_000;
/// Grace period past a record's/message's expiry before it is purged.
const RETENTION_GRACE_MS: u64 = 7 * 24 * 3600 * 1000;
/// Undelivered inbox entries older than this are dropped by the sweep
/// (the store takes seconds).
const INBOX_TTL_SECS: u64 = 30 * 24 * 3600;
/// KEL heads not seen for this long are dropped (spec: one year; the
/// store takes seconds).
const KEL_HEAD_MAX_AGE_SECS: u64 = 365 * 24 * 3600;
const BUF_CLASSES: usize = 16;
/// Class slots: two leg phases of [`BUF_CLASSES`] classes each. Slot =
/// phase * 16 + class, where phase 0 (slots 0..16) is the second leg (no
/// hop layer; the message is traveling toward its final destination) and
/// phase 1 (slots 16..32) is the first leg (hop layer present; toward the
/// waypoint or gateway). Slots are internal; the wire never sees them.
const CLASS_SLOTS: usize = 2 * BUF_CLASSES;
/// Base delay for the per-entry custody retry backoff. Doubles per failed
/// attempt up to the configured `retry_max_secs`.
const CUSTODY_RETRY_BASE_MS: u64 = 5_000;
/// Per-link budget for echo replies (R-29): a peer cannot make us emit
/// more than a small burst plus a slow trickle of echo replies.
const ECHO_BUDGET_CAPACITY: f64 = 8.0;
const ECHO_BUDGET_REFILL_PER_SEC: f64 = 0.5;
/// Uninformed prior for the custody-reply RTT, used to schedule echo
/// replies before any sample exists (100 ms).
const DEFAULT_CUSTODY_RTT_MS: f64 = 100.0;
/// Cap on a sampled echo delay, so one bad sample cannot park a reply
/// absurdly far in the future.
const MAX_ECHO_DELAY_MS: u64 = 60_000;
/// Exponential smoothing factor for the custody-reply RTT estimate.
const CUSTODY_RTT_ALPHA: f64 = 0.125;

/// Per-slot reserve for the buffer classes: the minimum bytes a class
/// slot can always hold, even when the shared pool is exhausted. Sized so
/// every slot holds at least one minimum-bucket message on any cap of
/// 64 KiB or more, and never more than a quarter of the cap in total.
/// The shared pool is what remains after all reserves.
fn class_reserve(transit_cap: u64) -> u64 {
    (transit_cap / 128).max(2048.min(transit_cap / 32)).max(1)
}

/// Bytes available to all slots above their reserves.
fn shared_pool_cap(transit_cap: u64) -> u64 {
    transit_cap.saturating_sub(CLASS_SLOTS as u64 * class_reserve(transit_cap))
}

/// The class slot for a (phase, class) pair. `has_hop_layer` selects the
/// first-leg phase (toward the waypoint/gateway); otherwise the message is
/// on its second leg (toward the final destination).
fn class_slot(has_hop_layer: bool, class: u8) -> u8 {
    if has_hop_layer {
        BUF_CLASSES as u8 + class
    } else {
        class
    }
}

/// Exponential backoff for a relayed custody entry that cannot be placed:
/// `base * 2^(attempts - 1)`, capped at `retry_max_secs`.
fn custody_backoff_ms(attempts: u32, retry_max_secs: u64) -> u64 {
    let shift = attempts.saturating_sub(1).min(20);
    let cap = secs_to_ms(retry_max_secs).max(CUSTODY_RETRY_BASE_MS);
    CUSTODY_RETRY_BASE_MS.saturating_mul(1u64 << shift).min(cap)
}

// ── store boundary conversions ──────────────────────────────────────
// The store keeps Unix seconds; the core keeps milliseconds. These
// convert the time fields of the store's row types in both directions.
// Wire-derived expiries (message/record headers) enter the core as
// seconds and are converted to ms at the ingestion point.

fn outbound_to_store(m: &lattice_store::OutboundMessage) -> lattice_store::OutboundMessage {
    let mut m = m.clone();
    m.exp = ms_to_secs(m.exp);
    m.receipt_deadline = m.receipt_deadline.map(ms_to_secs);
    m.next_attempt = ms_to_secs(m.next_attempt);
    m
}

fn outbound_from_store(mut m: lattice_store::OutboundMessage) -> lattice_store::OutboundMessage {
    m.exp = secs_to_ms(m.exp);
    m.receipt_deadline = m.receipt_deadline.map(secs_to_ms);
    m.next_attempt = secs_to_ms(m.next_attempt);
    m
}

fn custody_to_store(mut e: CustodyEntry) -> CustodyEntry {
    e.exp = ms_to_secs(e.exp);
    for ex in &mut e.excluded {
        ex.until = ms_to_secs(ex.until);
    }
    e
}

fn custody_from_store(mut e: CustodyEntry) -> CustodyEntry {
    e.exp = secs_to_ms(e.exp);
    for ex in &mut e.excluded {
        ex.until = secs_to_ms(ex.until);
    }
    e
}

fn kel_head_to_store(mut h: KelHeadSeen) -> KelHeadSeen {
    h.seen = ms_to_secs(h.seen);
    h
}

fn kel_head_from_store(mut h: KelHeadSeen) -> KelHeadSeen {
    h.seen = secs_to_ms(h.seen);
    h
}

impl<S: Store> Node<S> {
    /// 16 bytes of core-RNG entropy for ids (mids, legs, delivery ids).
    fn rand_id16(&mut self) -> [u8; 16] {
        let mut b = [0u8; 16];
        self.rng.fill_bytes(&mut b);
        b
    }

    fn on_app_send(&mut self, send: &AppSend) -> Vec<Action> {
        let now = self.now;
        let mid: MessageId = match send.mid_hint {
            Some(mid) => mid,
            None => MessageId::from_bytes(self.rand_id16()),
        };
        // `send.exp` is a wire time (Unix seconds); the core keeps ms.
        let exp = send
            .exp
            .map(secs_to_ms)
            .unwrap_or(now + secs_to_ms(self.config.default_message_horizon))
            .min(now + secs_to_ms(lattice_proto::MAX_MESSAGE_HORIZON));

        let envelope = Envelope {
            kind: KIND_MESSAGE,
            mid,
            from: self.own_id,
            fsvc: send.service.clone(),
            fmbx: send.fmbx.clone(),
            tsvc: send.tsvc.clone(),
            tmbx: send.tmbx.clone(),
            created: ms_to_secs(now),
            body: Some(send.body.clone()),
            reference: None,
            reason: None,
            sig: Signature::from_bytes([0; 64]),
        };

        if !self.has_record(&send.to) {
            // No record for the recipient yet: hold the message in an
            // "awaiting record" state for a bounded grace period instead of
            // failing outright. The grace deadline is persisted as
            // `next_attempt`; when the record arrives (admission path) the
            // message is re-armed and dispatched, and when the grace
            // expires the message fails with ERR_NO_RECORD. Ask for the
            // record on up to two links so a single lost want does not
            // stall the send.
            let grace = secs_to_ms(self.config.awaiting_record_grace_secs);
            let outbound = lattice_store::OutboundMessage {
                mid,
                recipient: send.to,
                envelope,
                priority: send.priority,
                exp,
                state: OutboundState::Queued,
                waypoints_tried: Vec::new(),
                receipt_deadline: None,
                attempts: 0,
                next_attempt: now + grace,
                route: send.route,
            };
            if let Err(e) = self.push_outbound(&outbound) {
                self.diag("outbound_push", &e);
                return vec![Action::Status {
                    mid,
                    status: local::MSG_STATUS_FAILED,
                    detail: Some(ERR_INTERNAL),
                    service: send.service.clone(),
                }];
            }
            self.awaiting_record.entry(send.to).or_default().insert(mid);
            let mut actions = vec![Action::Status {
                mid,
                status: local::MSG_STATUS_QUEUED,
                detail: None,
                service: send.service.clone(),
            }];
            let links: Vec<LinkId> = self.links.keys().copied().collect();
            let chosen: Vec<LinkId> = if links.len() <= 2 {
                links
            } else {
                let mut pool = links;
                let mut picked = Vec::with_capacity(2);
                while picked.len() < 2 && !pool.is_empty() {
                    let idx = (self.rng.next_u64() as usize) % pool.len();
                    picked.push(pool.swap_remove(idx));
                }
                picked
            };
            for link in chosen {
                actions.extend(self.want_record(link, send.to));
            }
            return actions;
        }

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
            receipt_deadline: Some(now + secs_to_ms(receipt_timeout)),
            attempts: 0,
            next_attempt: now,
            route: send.route,
        };
        if let Err(e) = self.push_outbound(&outbound) {
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

    /// Presence check for a usable record. Records in the index were
    /// validated at admission; expiry is checked here.
    #[must_use]
    fn has_record(&self, id: &Identifier) -> bool {
        self.lookup_validated(id).is_some()
    }

    /// Look up a record in the in-memory index. Records were validated at
    /// admission (or at startup); the only check here is expiry.
    fn validated_record(&self, id: &Identifier, scope: Scope) -> Option<PeerRecord> {
        let now_secs = ms_to_secs(self.now);
        self.record_index
            .get(&(*id, scope_as_u8(scope)))
            .filter(|e| e.record.exp > now_secs)
            .map(|e| e.record.clone())
    }

    /// Look up a record in either scope (WAN first, then hive).
    fn lookup_validated(&self, id: &Identifier) -> Option<PeerRecord> {
        for scope in [Scope::Wan, Scope::Hive] {
            if let Some(rec) = self.validated_record(id, scope) {
                return Some(rec);
            }
        }
        None
    }

    fn record_mode(&self, id: &Identifier) -> Option<Mode> {
        self.lookup_validated(id).map(|r| r.mode)
    }

    fn record_envelope_key(&self, id: &Identifier) -> Option<XWingPublicKey> {
        self.lookup_validated(id).map(|r| r.envelope_key)
    }

    fn record_gateways(&self, id: &Identifier) -> Vec<Identifier> {
        self.lookup_validated(id)
            .map(|r| r.gateways)
            .unwrap_or_default()
    }

    /// Choose a gateway for a private recipient: uniformly at random
    /// among the gateways with a known record, preferring ones not yet
    /// tried for this message. When every known gateway has been tried
    /// without a receipt, fall back to the full set rather than strand
    /// the message — a gateway that failed once may deliver on retry.
    fn pick_gateway(
        &mut self,
        gateways: &[Identifier],
        tried: &[Identifier],
    ) -> Option<(Identifier, XWingPublicKey)> {
        let known: Vec<(Identifier, XWingPublicKey)> = gateways
            .iter()
            .filter_map(|g| self.record_envelope_key(g).map(|ek| (*g, ek)))
            .collect();
        if known.is_empty() {
            return None;
        }
        let mut pool: Vec<(Identifier, XWingPublicKey)> = known
            .into_iter()
            .filter(|(g, _)| !tried.contains(g))
            .collect();
        if pool.is_empty() {
            // Every known gateway was tried without a receipt; fall back
            // to the full set rather than strand the message.
            pool = gateways
                .iter()
                .filter_map(|g| self.record_envelope_key(g).map(|ek| (*g, ek)))
                .collect();
        }
        let idx = (self.rng.next_u64() as usize) % pool.len();
        Some(pool.swap_remove(idx))
    }

    /// Build a wire message for one attempt. Returns the wire bytes.
    /// A retry (`attempts > 0` on entry) forces waypoint routing: the direct
    /// path already failed once. `attempts` is NOT incremented here; the
    /// caller increments it when a first hop accepts the message.
    fn build_attempt(
        &mut self,
        msg: &mut lattice_store::OutboundMessage,
    ) -> Result<BuildOutput, BuildError> {
        let force_waypoint = msg.attempts > 0;
        let recipient_rec = self.lookup_validated(&msg.recipient);
        let recipient_private = recipient_rec
            .as_ref()
            .is_some_and(|r| r.mode == Mode::Private);
        let gateway_choice = if recipient_private {
            let gateways = recipient_rec
                .as_ref()
                .map(|r| r.gateways.clone())
                .unwrap_or_default();
            self.pick_gateway(&gateways, &msg.waypoints_tried)
        } else {
            None
        };
        if let Some((g, _)) = &gateway_choice {
            // Record the gateway as tried at selection time, so a dispatch
            // that finds no route still burns it (same rule as waypoints).
            msg.waypoints_tried.push(*g);
        }
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
        if let Some(choice) = &waypoint_choice {
            // Record the waypoint as tried at selection time, so a dispatch
            // that finds no route does not select it again next attempt.
            msg.waypoints_tried.push(choice.id);
        }

        let recipient_ek = recipient_rec
            .map(|r| r.envelope_key)
            .ok_or(BuildError::NoRoute)?;
        let real_dst = gateway_choice.as_ref().map_or(msg.recipient, |(g, _)| *g);
        let gateway = gateway_choice.map(|(_g, gateway_ek)| GatewaySeal {
            gateway_ek,
            rcpt: msg.recipient,
        });
        let waypoint_leg = LegId::from_bytes(self.rand_id16());
        let waypoint = waypoint_choice.map(|choice| WaypointSeal {
            waypoint_id: choice.id,
            waypoint_ek: choice.envelope_key,
            leg: waypoint_leg,
            exp: ms_to_secs(msg.exp),
        });
        let real_leg = LegId::from_bytes(self.rand_id16());
        let wire = Message::build(BuildParams {
            envelope: msg.envelope.clone(),
            sender_seed: &self.identity.signing_seed,
            recipient_ek: &recipient_ek,
            real_dst,
            leg: real_leg,
            exp: ms_to_secs(msg.exp),
            gateway,
            waypoint,
            entropy: &mut |buf| self.rng.fill_bytes(buf),
        })
        .map_err(|_| BuildError::Crypto)?;
        Ok(BuildOutput { wire })
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
        // A waypoint we cannot reach cannot carry the message; drop
        // candidates with no path from here. The graph is undirected, so
        // reachability from here is the same component membership the
        // waypoint would need to reach the destination.
        let own = self.own_id;
        let reachable = self.distances_cached(&own);
        let cached = self.waypoint_candidates();
        let mut candidates: Vec<WaypointChoice> = cached
            .iter()
            .filter(|c| {
                c.id != self.own_id
                    && &c.id != recipient
                    && !exclude.contains(&c.id)
                    && !own_links.contains(&c.id)
                    && !recipient_gateways.contains(&c.id)
                    && reachable.contains_key(&c.id)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let idx = (self.rng.next_u64() as usize) % candidates.len();
        Some(candidates.swap_remove(idx))
    }

    /// Public-mode (id, envelope key) pairs from the index, memoized on
    /// `(derived_version, now)` like the graph cache.
    fn waypoint_candidates(&mut self) -> Arc<WaypointCandidates> {
        let key = (self.derived_version, self.now);
        if let Some((v, t, cached)) = &self.waypoint_cache {
            if (*v, *t) == key {
                return Arc::clone(cached);
            }
        }
        let now_secs = ms_to_secs(self.now);
        let mut candidates: WaypointCandidates = self
            .record_index
            .values()
            .filter(|e| e.record.exp > now_secs && e.record.mode == Mode::Public)
            .map(|e| WaypointChoice {
                id: e.record.id,
                envelope_key: e.record.envelope_key,
            })
            .collect();
        candidates.sort_by_key(|c| c.id);
        let candidates = Arc::new(candidates);
        self.waypoint_cache = Some((key.0, key.1, Arc::clone(&candidates)));
        candidates
    }

    fn pump_outbound(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        // Collect the due messages from the in-memory index, then process
        // them in (priority, next_attempt) order.
        let due_mids: Vec<MessageId> = self
            .outbound_due
            .range(..=now)
            .flat_map(|(_, mids)| mids.iter().copied())
            .collect();
        let mut due: Vec<lattice_store::OutboundMessage> = Vec::with_capacity(due_mids.len());
        for mid in due_mids {
            match self.store.outbound_get(&mid) {
                Ok(Some(msg)) => {
                    let msg = outbound_from_store(msg);
                    if msg.state == OutboundState::Queued
                        && msg.next_attempt <= now
                        && msg.exp > now
                    {
                        due.push(msg);
                    } else {
                        // Index drifted; re-sync it.
                        self.index_outbound(&msg);
                    }
                }
                Ok(None) => self.unindex_outbound(&mid),
                Err(e) => self.diag("outbound_get", &e),
            }
        }
        due.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.next_attempt.cmp(&b.next_attempt))
        });
        for mut msg in due {
            if msg.state != OutboundState::Queued {
                continue;
            }
            if !self.has_record(&msg.recipient) {
                if self
                    .awaiting_record
                    .get(&msg.recipient)
                    .is_some_and(|s| s.contains(&msg.mid))
                {
                    // Awaiting-record grace period elapsed with no record:
                    // fail with ERR_NO_RECORD.
                    self.awaiting_remove(&msg.recipient, &msg.mid);
                    msg.mark_failed();
                    self.clear_no_route(&msg.mid);
                    self.store_outbound(&msg);
                    if let Err(e) = self.store.status_set(
                        &msg.mid,
                        local::MSG_STATUS_FAILED,
                        Some(ERR_NO_RECORD),
                        ms_to_secs(now),
                    ) {
                        self.diag("status_set", &e);
                    }
                    actions.push(Action::Status {
                        mid: msg.mid,
                        status: local::MSG_STATUS_FAILED,
                        detail: Some(ERR_NO_RECORD),
                        service: msg.envelope.fsvc.clone(),
                    });
                    continue;
                }
                // The record vanished after the message was queued: treat
                // it as no-route and back off rather than fail it.
                self.requeue_no_route(now, &mut msg);
                continue;
            }
            match self.build_attempt(&mut msg) {
                Ok(built) => {
                    match self.dispatch_wire(now, &built.wire, &msg, &mut actions) {
                        DispatchResult::Sent => {
                            // A first hop accepted the message: this is an attempt.
                            msg.attempts += 1;
                            self.clear_no_route(&msg.mid);
                            self.awaiting_remove(&msg.recipient, &msg.mid);
                            msg.mark_in_flight();
                            msg.next_attempt = now + secs_to_ms(self.config.retry_base_secs);
                            // The receipt clock starts when the message
                            // actually goes on the wire, not at enqueue.
                            // Receipts are fire-and-forget: nobody receipts
                            // a receipt, so they carry no deadline.
                            msg.receipt_deadline = if is_receipt_envelope(msg.envelope.kind) {
                                None
                            } else {
                                Some(now + self.receipt_timeout_for(&msg))
                            };
                            self.store_outbound(&msg);
                        }
                        DispatchResult::NoRoute => {
                            self.requeue_no_route(now, &mut msg);
                        }
                    }
                }
                Err(BuildError::NoRoute) => {
                    self.requeue_no_route(now, &mut msg);
                }
                Err(BuildError::Crypto) => {
                    // Deterministic failure: retrying cannot help.
                    self.clear_no_route(&msg.mid);
                    self.awaiting_remove(&msg.recipient, &msg.mid);
                    if is_receipt_envelope(msg.envelope.kind) {
                        // Receipts fail silently: no status row, no event.
                        self.drop_outbound(&msg.mid);
                        continue;
                    }
                    msg.mark_failed();
                    self.store_outbound(&msg);
                    if let Err(e) = self.store.status_set(
                        &msg.mid,
                        local::MSG_STATUS_FAILED,
                        Some(ERR_INTERNAL),
                        ms_to_secs(now),
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
        secs_to_ms(if self.record_mode(&msg.recipient) == Some(Mode::Private) {
            self.config.receipt_timeout_private
        } else {
            self.config.receipt_timeout_public
        })
    }

    fn backoff(&self, attempts: u32) -> u64 {
        let shift = attempts.min(16);
        let base = secs_to_ms(self.config.retry_base_secs).saturating_mul(1u64 << shift);
        base.min(secs_to_ms(self.config.retry_max_secs))
    }

    /// Note a no-route wait for `mid` and return the consecutive count
    /// (0-based) to feed the backoff. Bounded; the map clears itself
    /// when full.
    fn note_no_route(&mut self, mid: &MessageId) -> u32 {
        if self.no_route_backoff.len() >= 1024 {
            self.no_route_backoff.clear();
        }
        let n = self.no_route_backoff.get(mid).copied().unwrap_or(0);
        self.no_route_backoff.insert(*mid, n.saturating_add(1));
        n
    }

    fn clear_no_route(&mut self, mid: &MessageId) {
        self.no_route_backoff.remove(mid);
    }

    /// Drop a message from the awaiting-record index.
    fn awaiting_remove(&mut self, recipient: &Identifier, mid: &MessageId) {
        if let Some(set) = self.awaiting_record.get_mut(recipient) {
            set.remove(mid);
            if set.is_empty() {
                self.awaiting_record.remove(recipient);
            }
        }
    }

    /// Re-arm every message awaiting `id`'s record: their grace deadline is
    /// replaced by `now` so the next pump dispatches them. Called when the
    /// record is admitted.
    fn release_awaiting_record(&mut self, id: &Identifier, now: u64) -> Vec<Action> {
        let Some(mids) = self.awaiting_record.remove(id) else {
            return Vec::new();
        };
        let mut rearmed = false;
        for mid in mids {
            match self.store.outbound_get(&mid) {
                Ok(Some(stored)) => {
                    let mut msg = outbound_from_store(stored);
                    if msg.state == OutboundState::Queued && msg.recipient == *id {
                        msg.next_attempt = now;
                        self.store_outbound(&msg);
                        rearmed = true;
                    }
                }
                Ok(None) => {}
                Err(e) => self.diag("outbound_get", &e),
            }
        }
        if rearmed {
            self.pump_outbound(now)
        } else {
            Vec::new()
        }
    }

    /// Remove an outbound message from the store and the in-memory index.
    fn drop_outbound(&mut self, mid: &MessageId) {
        if let Err(e) = self.store.outbound_remove(mid) {
            self.diag("outbound_remove", &e);
        }
        self.unindex_outbound(mid);
    }

    /// A message with no route right now: wait with exponential backoff
    /// until the message expires (or its receipt deadline passes, for a
    /// message already in flight). This is not an attempt and does not
    /// consume the fresh-waypoint-retry budget.
    fn requeue_no_route(&mut self, now: u64, msg: &mut lattice_store::OutboundMessage) {
        let n = self.note_no_route(&msg.mid);
        msg.requeue(now + self.backoff(n));
        self.store_outbound(msg);
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
        let dist = self.distances_cached(dst);
        let excluded_peers: HashSet<Identifier> = exclude
            .iter()
            .filter(|e| e.until > now)
            .filter_map(|e| self.links.get(&e.link).and_then(|s| s.peer))
            .collect();
        let up: HashSet<Identifier> = self.links.values().filter_map(|l| l.peer).collect();
        let peer = graph.next_hop(
            &self.own_id,
            dst,
            dist.as_ref(),
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
        let Ok(parsed) = Message::parse(wire, ms_to_secs(now)) else {
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
        let Ok(msg) = Message::parse(&offer.message, ms_to_secs(now)) else {
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
        let seen = match self.store.seen_contains(&leg_hash, ms_to_secs(now)) {
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
        let unheld = match self.store.seen_unheld_contains(&leg_hash, ms_to_secs(now)) {
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
            let d = self.distances_cached(&self.own_id.clone());
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
                exp: secs_to_ms(msg.header.exp),
                class,
                leg_hash,
                has_hop_layer: msg.hop_layer.is_some(),
            },
            &mut actions,
        );
        actions
    }

    /// Fair-share check for a destination on an upstream link. On store
    /// error, fail closed (treat the allowance as exhausted) and report.
    #[must_use]
    fn share_exceeded(&mut self, dest: &Identifier, link: LinkId, msg_len: u64) -> bool {
        // Per-destination allowance, divided among the upstreams currently
        // active for that destination (those holding a non-zero share). An
        // upstream with no share yet is counted too, so a newcomer cannot
        // ride on the shares of those already present. On store error,
        // fail closed.
        let used = match self.store.share_get(dest, link) {
            Ok(v) => v,
            Err(e) => {
                self.diag("share_get", &e);
                u64::MAX
            }
        };
        let active = match self.store.share_upstream_count(dest) {
            Ok(v) => v,
            Err(e) => {
                self.diag("share_upstream_count", &e);
                u64::MAX
            }
        };
        let divisor = if used > 0 {
            active
        } else {
            active.saturating_add(1)
        }
        .max(1);
        let share_limit = self.config.custody_allowance / divisor;
        if used.saturating_add(msg_len) > share_limit {
            return true;
        }
        // Per-upstream aggregate cap across all destinations: one upstream
        // flooding many destinations cannot fill a class slice.
        let bound_links = self
            .links
            .values()
            .filter(|l| l.peer.is_some())
            .count()
            .max(1) as u64;
        let aggregate_cap = self.config.transit_cap / bound_links;
        let aggregate_used = self.upstream_bytes.get(&link).copied().unwrap_or(0);
        aggregate_used.saturating_add(msg_len) > aggregate_cap
    }

    /// Buffer-class admission check for one class slot. Each slot has a
    /// small reserve it can always use; above the reserve, slots draw from
    /// a shared pool. First-leg (hop layer present) and second-leg slots
    /// never share a reserve, so a second-leg wait never depends on
    /// first-leg space; both may draw on the shared pool, which is what
    /// lets a first leg wait on second-leg space. On store error, fail
    /// closed (treat the slot as full) and report.
    #[must_use]
    fn class_full(&mut self, slot: u8, msg_len: u64) -> bool {
        let class_bytes = match self.store.custody_class_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.diag("custody_class_bytes", &e);
                [u64::MAX; CLASS_SLOTS]
            }
        };
        let reserve = class_reserve(self.config.transit_cap);
        let slot_used = class_bytes[slot as usize];
        if slot_used.saturating_add(msg_len) <= reserve {
            return false;
        }
        let shared_used: u64 = class_bytes
            .iter()
            .map(|&used| used.saturating_sub(reserve))
            .sum();
        shared_used.saturating_add(msg_len) > shared_pool_cap(self.config.transit_cap)
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
            has_hop_layer,
        } = offer;
        // A private instance never carries transit traffic (R-23): custody
        // is accepted only when the message's destination is this node
        // itself. This covers the relay path, the waypoint path and the
        // gateway path alike.
        if self.config.mode == Mode::Private && destination != self.own_id {
            actions.push(Self::refuse(link, leg));
            return;
        }
        let msg_len = message.len() as u64;
        // Fair-share accounting is per (destination, upstream link), with
        // the allowance divided among the upstreams currently active for
        // the destination, plus a per-upstream aggregate cap so one
        // upstream flooding many destinations cannot fill a class slice.
        if self.share_exceeded(&destination, link, msg_len) {
            actions.push(self.busy(link, leg));
            return;
        }
        // Buffer classes: a shared pool plus a small per-slot reserve.
        // First-leg (hop layer present) and second-leg slots never share
        // a reserve, so a second-leg wait never depends on first-leg
        // space; both may draw on the shared pool, which is what lets a
        // first leg wait on second-leg space. A class-d message only ever
        // waits on class < d room at the next hop, so waits cannot cycle.
        let slot = class_slot(has_hop_layer, class);
        if self.class_full(slot, msg_len) {
            actions.push(self.busy(link, leg));
            return;
        }
        let entry = CustodyEntry {
            leg,
            message,
            upstream: link,
            destination,
            class: slot,
            exp,
            // Never hand the message back to the link it arrived on.
            excluded: vec![Exclusion { link, until: exp }],
        };
        let accept = CustodyAccept {
            entry: custody_to_store(entry.clone()),
            share_dest: destination,
            share_upstream: link,
            share_bytes: msg_len as i64,
            seen_hash: leg_hash,
            seen_exp: ms_to_secs(exp),
        };
        if let Err(e) = self.store.custody_accept(accept) {
            self.diag("custody_accept", &e);
            actions.push(self.busy(link, leg));
            return;
        }
        // The store committed; track the entry in the in-memory indexes.
        self.track_custody_insert(&entry, now);
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
            match self.identity.open_hop_layer_any(msg) {
                Ok(HopLayerPlain::Waypoint { hdr, inner }) => {
                    // The outer header's expiry is checked in Message::parse;
                    // the inner header's is not, so enforce the same horizon
                    // here before the expiry is used for custody accounting.
                    if secs_to_ms(hdr.exp) <= now
                        || secs_to_ms(hdr.exp)
                            > now
                                + secs_to_ms(
                                    lattice_proto::MAX_MESSAGE_HORIZON + lattice_proto::CLOCK_SKEW,
                                )
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
                            exp: secs_to_ms(hdr_exp),
                            class,
                            leg_hash: *leg_hash,
                            has_hop_layer: false,
                        },
                        &mut actions,
                    );
                    return actions;
                }
                Ok(HopLayerPlain::Gateway { rcpt }) => {
                    // H-21: a gateway carries traffic only for the private
                    // ids it serves (its record's `serves`). Anything else
                    // is refused.
                    if !self.config.serves.contains(&rcpt) {
                        actions.push(Self::refuse(link, leg));
                        return actions;
                    }
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
                            exp: secs_to_ms(msg.header.exp),
                            class,
                            leg_hash: *leg_hash,
                            has_hop_layer: false,
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
        if opened.validate_created(ms_to_secs(now)).is_err() {
            // Absurd `created` (future beyond skew, or older than the
            // message horizon): refuse custody rather than store or relay it.
            actions.push(Self::refuse(link, leg));
            return actions;
        }
        let Some(key) = self.signing_key_for(&opened.from) else {
            // No record for the sender; cannot verify. Ask for it through
            // gossip (spec §5): a want on the offering link and on one
            // other link, then refuse softly (busy) so the sender retries
            // after the record arrives.
            actions.push(self.busy(link, leg));
            actions.extend(self.want_record(link, opened.from));
            let others: Vec<LinkId> = self.links.keys().filter(|&&l| l != link).copied().collect();
            if let Some(&other) = self.rng.pick(&others) {
                actions.extend(self.want_record(other, opened.from));
            }
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
        let already_delivered = match self.store.delivered_contains(&mid_hash, ms_to_secs(now)) {
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
        // Per-service reservation: a service at or over its reservation is
        // answered busy; services under their reservation are admitted.
        // Fail closed on store error: treat the inbox as full rather than
        // accept a delivery we cannot account for.
        let inbox_len = match self.store.inbox_len(&opened.tsvc) {
            Ok(v) => v,
            Err(e) => {
                self.diag("inbox_len", &e);
                u64::MAX
            }
        };
        // The global cap is a memory backstop, not a shared pool: it can
        // only trip when the sum of the configured reservations exceeds it
        // (each service is hard-capped at its reservation, so the total can
        // only reach the cap when the reservations themselves over-commit
        // memory). When it trips, deliveries are refused regardless of
        // service — that is what makes it a backstop.
        let reservation = self.config.inbox_max_deliveries;
        let reservations_total = reservation.saturating_mul(self.config.services.len() as u64);
        let backstop_armed = reservations_total > self.config.inbox_max_total;
        let backstop_tripped = backstop_armed
            && match self.store.inbox_len_total() {
                Ok(v) => v >= self.config.inbox_max_total,
                Err(e) => {
                    self.diag("inbox_len_total", &e);
                    true
                }
            };
        if inbox_len >= reservation || backstop_tripped {
            actions.push(self.busy(link, leg));
            return actions;
        }
        let entry = InboxEntry {
            delivery_id: DeliveryId::from_bytes(self.rand_id16()),
            mid: mid_bytes,
            from: opened.from,
            fsvc: opened.fsvc.clone(),
            fmbx: opened.fmbx.clone(),
            tsvc: opened.tsvc.clone(),
            tmbx: opened.tmbx.clone(),
            body: opened.body.clone().unwrap_or_default(),
            received: ms_to_secs(now),
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
            received: ms_to_secs(now),
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
        let d = self.distances_cached(&self.own_id.clone());
        d.get(dst)
            .copied()
            .unwrap_or(u32::MAX)
            .min((BUF_CLASSES - 1) as u32) as u8
    }

    fn forward_custody(&mut self, now: u64, leg: LegId, actions: &mut Vec<Action>) {
        let entry = match self.store.custody_get(&leg) {
            Ok(Some(e)) => custody_from_store(e),
            // The entry is gone (already delivered or swept): nothing to do.
            Ok(None) => return,
            Err(e) => {
                self.diag("custody_get", &e);
                return;
            }
        };
        if entry.exp <= now {
            self.release_custody(leg);
            return;
        }
        let dst = entry.destination;
        // The offer we send may carry a *different* leg than the custody key
        // (waypoint re-origination): key `pending` by the leg on the wire.
        // Parsed once and cached in the custody meta.
        let offer_leg = match self.custody_meta.get(&leg).and_then(|m| m.offer_leg) {
            Some(l) => l,
            None => {
                let parsed = lattice_proto::Message::parse(&entry.message, ms_to_secs(now))
                    .map(|m| m.header.leg)
                    .unwrap_or(entry.leg);
                if let Some(meta) = self.custody_meta.get_mut(&leg) {
                    meta.offer_leg = Some(parsed);
                }
                parsed
            }
        };
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
            // No route right now. Back off exponentially (capped); events
            // that create routes (link up, records arriving) also re-drive
            // custody, but only once one of them happens.
            let attempts = self
                .custody_meta
                .get(&leg)
                .map(|m| m.attempts)
                .unwrap_or(0)
                .saturating_add(1);
            let backoff = custody_backoff_ms(attempts, self.config.retry_max_secs);
            self.reschedule_custody(leg, now.saturating_add(backoff), attempts);
            return;
        };
        // The entry is now in flight; it leaves the retry index until the
        // reply arrives or the offer times out.
        self.untrack_custody_retry(leg);

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
        // Track the custody-reply RTT: echo replies are scheduled from
        // this distribution so dummy exchanges look like an offer and
        // its custody reply (spec §6, snow).
        if let Some(p) = &pending {
            self.observe_custody_rtt(now.saturating_sub(p.sent_at));
        }
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
            Ok(Some(msg)) => Some(outbound_from_store(msg)),
            Ok(None) => None,
            Err(e) => {
                self.diag("outbound_get", &e);
                None
            }
        }
    }

    fn store_outbound(&mut self, msg: &lattice_store::OutboundMessage) {
        if let Err(e) = self.store.outbound_put(&outbound_to_store(msg)) {
            self.diag("outbound_put", &e);
            return;
        }
        self.index_outbound(msg);
    }

    /// Push a new outbound message to the store and index it.
    fn push_outbound(
        &mut self,
        msg: &lattice_store::OutboundMessage,
    ) -> Result<(), lattice_store::StoreError> {
        self.store.outbound_push(&outbound_to_store(msg))?;
        self.index_outbound(msg);
        Ok(())
    }

    /// Insert or refresh an outbound message's due-time index entries.
    fn index_outbound(&mut self, msg: &lattice_store::OutboundMessage) {
        let entry = OutboundIndexEntry {
            next_attempt: msg.next_attempt,
            receipt_deadline: msg.receipt_deadline,
            exp: msg.exp,
            state: msg.state,
        };
        if let Some(old) = self.outbound_index.insert(msg.mid, entry) {
            Self::outbound_index_remove(
                &mut self.outbound_due,
                &mut self.outbound_deadline,
                &mut self.outbound_expiry,
                msg.mid,
                &old,
            );
        }
        if entry.state == OutboundState::Queued {
            self.outbound_due
                .entry(entry.next_attempt)
                .or_default()
                .insert(msg.mid);
        }
        if entry.state == OutboundState::InFlight {
            if let Some(d) = entry.receipt_deadline {
                self.outbound_deadline.entry(d).or_default().insert(msg.mid);
            }
        }
        if !entry.state.is_terminal() {
            self.outbound_expiry
                .entry(entry.exp)
                .or_default()
                .insert(msg.mid);
        }
    }

    /// Drop an outbound message's due-time index entries.
    fn unindex_outbound(&mut self, mid: &MessageId) {
        if let Some(old) = self.outbound_index.remove(mid) {
            Self::outbound_index_remove(
                &mut self.outbound_due,
                &mut self.outbound_deadline,
                &mut self.outbound_expiry,
                *mid,
                &old,
            );
        }
    }

    fn outbound_index_remove(
        due: &mut std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
        deadline: &mut std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
        expiry: &mut std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
        mid: MessageId,
        old: &OutboundIndexEntry,
    ) {
        fn remove_from(
            map: &mut std::collections::BTreeMap<u64, std::collections::HashSet<MessageId>>,
            key: u64,
            mid: &MessageId,
        ) {
            if let Some(set) = map.get_mut(&key) {
                set.remove(mid);
                if set.is_empty() {
                    map.remove(&key);
                }
            }
        }
        if old.state == OutboundState::Queued {
            remove_from(due, old.next_attempt, &mid);
        }
        if old.state == OutboundState::InFlight {
            if let Some(d) = old.receipt_deadline {
                remove_from(deadline, d, &mid);
            }
        }
        if !old.state.is_terminal() {
            remove_from(expiry, old.exp, &mid);
        }
    }

    /// Register a custody entry in the in-memory indexes. `next_attempt`
    /// is when the entry first becomes due for a forwarding attempt.
    fn track_custody_insert(&mut self, entry: &CustodyEntry, next_attempt: u64) {
        self.custody_meta.insert(
            entry.leg,
            CustodyMeta {
                offer_leg: None,
                attempts: 0,
                next_attempt,
                class_slot: entry.class,
            },
        );
        self.custody_retry
            .entry(next_attempt)
            .or_default()
            .insert(entry.leg);
        self.custody_expiry
            .entry(entry.exp)
            .or_default()
            .insert(entry.leg);
        *self.upstream_bytes.entry(entry.upstream).or_insert(0) += entry.message.len() as u64;
    }

    /// Drop a custody entry from the in-memory indexes.
    fn track_custody_remove(&mut self, entry: &CustodyEntry) {
        if let Some(meta) = self.custody_meta.remove(&entry.leg) {
            if let Some(set) = self.custody_retry.get_mut(&meta.next_attempt) {
                set.remove(&entry.leg);
                if set.is_empty() {
                    self.custody_retry.remove(&meta.next_attempt);
                }
            }
        }
        if let Some(set) = self.custody_expiry.get_mut(&entry.exp) {
            set.remove(&entry.leg);
            if set.is_empty() {
                self.custody_expiry.remove(&entry.exp);
            }
        }
        if let Some(v) = self.upstream_bytes.get_mut(&entry.upstream) {
            *v = v.saturating_sub(entry.message.len() as u64);
            if *v == 0 {
                self.upstream_bytes.remove(&entry.upstream);
            }
        }
    }

    /// Re-arm a custody entry's retry timer with a fresh backoff.
    fn reschedule_custody(&mut self, leg: LegId, next_attempt: u64, attempts: u32) {
        if let Some(meta) = self.custody_meta.get_mut(&leg) {
            if let Some(set) = self.custody_retry.get_mut(&meta.next_attempt) {
                set.remove(&leg);
                if set.is_empty() {
                    self.custody_retry.remove(&meta.next_attempt);
                }
            }
            meta.next_attempt = next_attempt;
            meta.attempts = attempts;
            self.custody_retry
                .entry(next_attempt)
                .or_default()
                .insert(leg);
        }
    }

    /// Remove a custody entry from the retry index (its offer is in
    /// flight; the reply or the stale-offer sweep re-arms it).
    fn untrack_custody_retry(&mut self, leg: LegId) {
        if let Some(meta) = self.custody_meta.get(&leg) {
            let at = meta.next_attempt;
            if let Some(set) = self.custody_retry.get_mut(&at) {
                set.remove(&leg);
                if set.is_empty() {
                    self.custody_retry.remove(&at);
                }
            }
        }
    }

    /// Atomically release a custody entry (row delete + share decrement in
    /// one store transaction) and drop it from the in-memory indexes.
    fn release_custody(&mut self, leg: LegId) -> Option<CustodyEntry> {
        match self.store.custody_release(&leg) {
            Ok(Some(e)) => {
                let e = custody_from_store(e);
                self.track_custody_remove(&e);
                Some(e)
            }
            Ok(None) => None,
            Err(e) => {
                self.diag("custody_release", &e);
                None
            }
        }
    }

    /// Fold one custody-reply RTT sample (ms) into the running estimate.
    fn observe_custody_rtt(&mut self, sample_ms: u64) {
        let sample = sample_ms as f64;
        self.custody_rtt_ema_ms = Some(match self.custody_rtt_ema_ms {
            None => sample,
            Some(ema) => ema + CUSTODY_RTT_ALPHA * (sample - ema),
        });
    }

    /// Sample an echo-reply delay (ms) from the estimated custody-reply
    /// latency distribution: exponential with the observed mean, or the
    /// uninformed prior before the first sample. Capped so a bad sample
    /// cannot park a reply arbitrarily far out.
    fn sample_custody_rtt_ms(&mut self) -> u64 {
        let mean = self
            .custody_rtt_ema_ms
            .unwrap_or(DEFAULT_CUSTODY_RTT_MS)
            .max(1.0);
        let sample = self.rng.expovariate(1.0 / mean);
        (sample as u64).min(MAX_ECHO_DELAY_MS)
    }

    /// Drop a relay custody entry and release its share of the upstream's
    /// allowance. Used when the downstream side resolves (accepted or
    /// refused). `ALREADY_HAVE` does not release: the downstream may only
    /// have seen the leg, not hold the message.
    fn release_relay_custody(&mut self, custody_leg: LegId) {
        // One atomic store operation: custody row delete + share decrement.
        self.release_custody(custody_leg);
    }

    fn custody_accepted_reply(&mut self, pending: Option<PendingOffer>, actions: &mut Vec<Action>) {
        match pending.map(|p| p.origin) {
            Some(PendingOrigin::Outbound { mid }) => {
                match self.load_outbound(&mid) {
                    Some(msg) if is_receipt_envelope(msg.envelope.kind) => {
                        // A receipt is terminal on its first ACCEPTED:
                        // custody of the receipt is all the sender needs.
                        // Drop it; no status row, no status event.
                        self.awaiting_remove(&msg.recipient, &msg.mid);
                        self.drop_outbound(&msg.mid);
                    }
                    Some(mut msg) => {
                        msg.mark_in_flight();
                        let service = msg.envelope.fsvc.clone();
                        self.store_outbound(&msg);
                        if let Err(e) = self.store.status_set(
                            &mid,
                            local::MSG_STATUS_IN_TRANSIT,
                            None,
                            ms_to_secs(self.now),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid,
                            status: local::MSG_STATUS_IN_TRANSIT,
                            detail: None,
                            service,
                        });
                    }
                    None => {
                        if let Err(e) = self.store.status_set(
                            &mid,
                            local::MSG_STATUS_IN_TRANSIT,
                            None,
                            ms_to_secs(self.now),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid,
                            status: local::MSG_STATUS_IN_TRANSIT,
                            detail: None,
                            service: String::new(),
                        });
                    }
                }
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
        // `retry_after` is a wire time (seconds).
        let retry = secs_to_ms(
            frame
                .retry_after
                .unwrap_or(self.config.retry_base_secs)
                .clamp(1, 3600),
        );
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
                        Ok(Some(e)) => {
                            let mut e = custody_from_store(e);
                            add_exclusion(&mut e.excluded, link, now + retry);
                            if let Err(e) = self.store.custody_put(custody_to_store(e)) {
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
                        Ok(Some(e)) => {
                            let mut e = custody_from_store(e);
                            add_exclusion(&mut e.excluded, link, e.exp);
                            if let Err(e) = self.store.custody_put(custody_to_store(e)) {
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
                match self.load_outbound(&mid) {
                    Some(msg) if is_receipt_envelope(msg.envelope.kind) => {
                        // A refused receipt is dropped, not failed: no
                        // status row, no status event.
                        self.awaiting_remove(&msg.recipient, &msg.mid);
                        self.outbound_exclusions.remove(&msg.mid);
                        self.drop_outbound(&msg.mid);
                    }
                    Some(mut msg) => {
                        msg.mark_failed();
                        self.outbound_exclusions.remove(&msg.mid);
                        let service = msg.envelope.fsvc.clone();
                        self.store_outbound(&msg);
                        if let Err(e) = self.store.status_set(
                            &mid,
                            local::MSG_STATUS_FAILED,
                            Some(ERR_REFUSED),
                            ms_to_secs(self.now),
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
                    None => {
                        if let Err(e) = self.store.status_set(
                            &mid,
                            local::MSG_STATUS_FAILED,
                            Some(ERR_REFUSED),
                            ms_to_secs(self.now),
                        ) {
                            self.diag("status_set", &e);
                        }
                        actions.push(Action::Status {
                            mid,
                            status: local::MSG_STATUS_FAILED,
                            detail: Some(ERR_REFUSED),
                            service: String::new(),
                        });
                    }
                }
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
                    Ok(Some(msg)) => outbound_from_store(msg),
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
                    self.clear_no_route(&msg.mid);
                    if envelope.kind == KIND_RECEIPT {
                        msg.mark_delivered();
                    } else {
                        msg.mark_failed();
                    }
                    self.store_outbound(&msg);
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
                if let Err(e) =
                    self.store
                        .status_set(&reference, status, detail, ms_to_secs(self.now))
                {
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
            mid: MessageId::from_bytes(self.rand_id16()),
            from: self.own_id,
            fsvc: delivered.tsvc.clone(),
            fmbx: delivered.tmbx.clone(),
            tsvc: delivered.fsvc.clone(),
            tmbx: delivered.fmbx.clone(),
            created: ms_to_secs(now),
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
            mid: MessageId::from_bytes(self.rand_id16()),
            from: self.own_id,
            fsvc: my_service.to_string(),
            fmbx: Vec::new(),
            tsvc: original.fsvc.clone(),
            tmbx: original.fmbx.clone(),
            created: ms_to_secs(now),
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
            exp: now + secs_to_ms(self.config.default_message_horizon),
            state: OutboundState::Queued,
            waypoints_tried: Vec::new(),
            receipt_deadline: None,
            attempts: 0,
            next_attempt: now,
            route: 0,
        };
        if let Err(e) = self.push_outbound(&outbound) {
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
        // Notice grace-period expiries and publish anything owed.
        self.note_link_set_changed(now);
        self.refresh_record_if_due(now);
        actions.extend(self.sweep_claims_if_due(now));
        self.sweep_data_if_due(now);
        actions.extend(self.expire_outbound(now));
        actions.extend(self.sweep_receipt_deadlines(now));
        actions.extend(self.sweep_stale_custody(now));
        actions.extend(self.drain_custody(now));
        self.sweep_custody_expiry(now);
        actions.extend(self.pump_outbound(now));
        self.neighbor_check_at = None;
        actions.extend(self.maintain_neighbors(now));
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
        self.next_reconcile_at = now + secs_to_ms(self.config.reconcile_interval_secs);
        actions
    }

    /// Daily refresh (with jitter). Republishes only when something
    /// actually changed — the advertised set differs, or the record is
    /// close enough to expiry that letting it lapse would be worse than a
    /// no-op republish. Spacing against other publishes is enforced by
    /// `flush_pending_publish`.
    fn refresh_record_if_due(&mut self, now: u64) {
        if now < self.record_refresh_at {
            return;
        }
        self.record_refresh_at =
            now + refresh_interval_ms(&mut self.rng, self.config.record_refresh_secs);
        let changed = self.advertised_links(now) != self.last_published_links;
        let exp_soon =
            self.own_record_exp.saturating_sub(ms_to_secs(now)) < REFRESH_EXP_HORIZON_SECS;
        if changed || exp_soon {
            self.publish_pending = true;
            self.flush_pending_publish(now);
        }
    }

    fn sweep_claims_if_due(&mut self, now: u64) -> Vec<Action> {
        if now < self.next_claim_sweep_at {
            return Vec::new();
        }
        let actions = self.sweep_ck_claims(now);
        self.next_claim_sweep_at = now + CLAIM_SWEEP_MS;
        actions
    }

    fn sweep_data_if_due(&mut self, now: u64) {
        if now < self.next_data_sweep_at {
            return;
        }
        self.sweep_expired_data(now);
        self.sweep_store_expired(now);
        self.next_data_sweep_at = now + DATA_SWEEP_MS;
    }

    /// Expire originated messages whose horizon has passed.
    fn expire_outbound(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let due: Vec<MessageId> = self
            .outbound_expiry
            .range(..=now)
            .flat_map(|(_, mids)| mids.iter().copied())
            .collect();
        for mid in due {
            let mut msg = match self.store.outbound_get(&mid) {
                Ok(Some(m)) => outbound_from_store(m),
                // Gone from the store: drop the stale index entry.
                Ok(None) => {
                    self.unindex_outbound(&mid);
                    continue;
                }
                // Store error: keep the index entry and retry next tick.
                Err(e) => {
                    self.diag("outbound_get", &e);
                    continue;
                }
            };
            if msg.state.is_terminal() || msg.exp > now {
                // Index drifted; re-sync it.
                self.index_outbound(&msg);
                continue;
            }
            self.awaiting_remove(&msg.recipient, &msg.mid);
            if is_receipt_envelope(msg.envelope.kind) {
                // Receipts expire silently: no status row, no event.
                self.clear_no_route(&msg.mid);
                self.drop_outbound(&msg.mid);
                continue;
            }
            msg.mark_expired();
            self.clear_no_route(&msg.mid);
            self.store_outbound(&msg);
            if let Err(e) = self.store.status_set(
                &msg.mid,
                local::MSG_STATUS_EXPIRED,
                Some(ERR_EXPIRED),
                ms_to_secs(now),
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
        actions
    }

    /// Receipt deadlines: retry via a fresh waypoint, else fail.
    fn sweep_receipt_deadlines(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let due: Vec<MessageId> = self
            .outbound_deadline
            .range(..=now)
            .flat_map(|(_, mids)| mids.iter().copied())
            .collect();
        for mid in due {
            let mut msg = match self.store.outbound_get(&mid) {
                Ok(Some(m)) => outbound_from_store(m),
                Ok(None) => {
                    self.unindex_outbound(&mid);
                    continue;
                }
                Err(e) => {
                    self.diag("outbound_get", &e);
                    continue;
                }
            };
            if is_receipt_envelope(msg.envelope.kind) {
                // Receipts carry no deadline; drop any legacy row.
                self.awaiting_remove(&msg.recipient, &msg.mid);
                self.drop_outbound(&msg.mid);
                continue;
            }
            if msg.state != OutboundState::InFlight {
                self.index_outbound(&msg);
                continue;
            }
            let Some(deadline) = msg.receipt_deadline else {
                self.index_outbound(&msg);
                continue;
            };
            if now < deadline {
                self.index_outbound(&msg);
                continue;
            }
            self.clear_no_route(&msg.mid);
            if msg.attempts > self.config.fresh_waypoint_retries {
                msg.mark_failed();
                self.store_outbound(&msg);
                if let Err(e) = self.store.status_set(
                    &msg.mid,
                    local::MSG_STATUS_FAILED,
                    Some(ERR_NO_ROUTE),
                    ms_to_secs(now),
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
                self.store_outbound(&msg);
            }
        }
        actions
    }

    /// Custody offers that never got an answer: exclude the link and retry.
    fn sweep_stale_custody(&mut self, now: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        let stale: Vec<LegId> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.sent_at) >= CUSTODY_TIMEOUT_MS)
            .map(|(leg, _)| *leg)
            .collect();
        for leg in stale {
            if let Some(p) = self.pending.remove(&leg) {
                match p.origin {
                    PendingOrigin::Outbound { mid } => {
                        let excl = self.outbound_exclusions.entry(mid).or_default();
                        add_exclusion(excl, p.link, now + secs_to_ms(self.config.retry_base_secs));
                        for e in p.excluded {
                            add_exclusion(excl, e.link, e.until);
                        }
                        match self.store.outbound_get(&mid) {
                            Ok(Some(msg)) => {
                                let mut msg = outbound_from_store(msg);
                                if msg.state == OutboundState::InFlight {
                                    msg.requeue(now + secs_to_ms(self.config.retry_base_secs));
                                    self.store_outbound(&msg);
                                }
                            }
                            Ok(None) => {}
                            Err(e) => self.diag("outbound_get", &e),
                        }
                    }
                    PendingOrigin::Relay { custody_leg } => {
                        match self.store.custody_get(&custody_leg) {
                            Ok(Some(e)) => {
                                let mut e = custody_from_store(e);
                                add_exclusion(
                                    &mut e.excluded,
                                    p.link,
                                    now + secs_to_ms(self.config.retry_base_secs),
                                );
                                for ex in p.excluded {
                                    add_exclusion(&mut e.excluded, ex.link, ex.until);
                                }
                                if let Err(e) = self.store.custody_put(custody_to_store(e)) {
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
        // Only entries whose retry backoff has expired are due. Second-leg
        // slots drain before first-leg slots (their slots sort first), and
        // within a slot lower classes drain first — the order that keeps
        // the class partition deadlock-free.
        let mut due: Vec<(u8, LegId)> = self
            .custody_retry
            .range(..=now)
            .flat_map(|(_, legs)| legs.iter().copied())
            .map(|leg| {
                let slot = self.custody_meta.get(&leg).map_or(0, |m| m.class_slot);
                (slot, leg)
            })
            .collect();
        due.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (_, leg) in due {
            self.untrack_custody_retry(leg);
            self.forward_custody(now, leg, &mut actions);
        }
        actions
    }

    /// Expire custody entries whose messages timed out.
    fn sweep_custody_expiry(&mut self, now: u64) {
        let due: Vec<LegId> = self
            .custody_expiry
            .range(..=now)
            .flat_map(|(_, legs)| legs.iter().copied())
            .collect();
        for leg in due {
            self.release_custody(leg);
        }
    }

    fn sweep_store_expired(&mut self, now: u64) {
        if let Err(e) = self.store.sweep_expired(ms_to_secs(now)) {
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
                // The reply goes out in the same bucket as the request
                // (R-29), not a freshly sampled one.
                let bucket = echo.bucket;
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
            // Exponential gap in milliseconds (snow_per_min per 60_000 ms).
            (self.rng.expovariate(self.config.snow_per_min / 60_000.0)).max(1.0) as u64
        } else {
            u64::MAX
        };
        self.snow_next = now.saturating_add(interval.max(1));

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

    fn on_frame(
        &mut self,
        at: u64,
        link: LinkId,
        frame: Frame,
        bucket: Option<usize>,
    ) -> Vec<Action> {
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
                    // Per-link echo budget (R-29): a peer cannot make us
                    // emit more than a small burst plus a slow trickle of
                    // echo replies. The dummy itself is ignored either way.
                    let allowed = self
                        .links
                        .get_mut(&link)
                        .map(|l| l.echo_budget_take(at))
                        .unwrap_or(false);
                    if allowed {
                        // The reply is scheduled with a delay drawn from the
                        // measured custody-reply latency distribution, and
                        // goes out in the request's bucket (R-29). If the
                        // bucket is unknown (e.g. a synthetic frame), fall
                        // back to a sampled bucket.
                        let delay = self.sample_custody_rtt_ms();
                        let bucket = bucket.unwrap_or_else(|| self.sample_snow_bucket());
                        self.inner_pending_echo.push(PendingEcho {
                            due: at + delay,
                            link,
                            bucket,
                        });
                    }
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
            self.next_reconcile_at = self.next_reconcile_at.min(now + secs_to_ms(1));
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

    /// Buffer-class slots of the held custody entries (0..16 second leg,
    /// 16..32 first leg). Test/diagnostic only.
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

    /// Mutable access to the store for non-record state (drain flag,
    /// inbox acks). Record writes through this handle are not reflected
    /// in the in-memory index — the routing graph and reconcile set would
    /// serve stale data — so records go through the admission path only.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Whether we hold a usable record for `id`, and its mode if so.
    /// A record that fails validation is not usable, so it reports `Absent`.
    pub fn lookup(&mut self, id: &Identifier) -> LookupResult {
        for scope in [
            lattice_proto::record::Scope::Wan,
            lattice_proto::record::Scope::Hive,
        ] {
            if let Some(rec) = self.validated_record(id, scope) {
                return LookupResult::Present {
                    mode: Some(rec.mode),
                };
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
            Identity::from_seed(&[0xA5; 32]),
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
            .status_set(&mid1, local::MSG_STATUS_EXPIRED, Some(ERR_EXPIRED), 1_000)
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
            .status_set(&mid2, local::MSG_STATUS_DELIVERED, None, 1_000)
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
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
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
        let channel_seed = ChannelSeed::from_bytes([0x5A; 32]);
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
        node.sweep_expired_data(secs_to_ms(exp) + RETENTION_GRACE_MS - 1);
        assert!(node.store.record_get(&id, Scope::Wan).unwrap().is_some());
        assert!(
            node.store
                .record_get(&Identifier::from_bytes([0xAB; 32]), Scope::Wan)
                .unwrap()
                .is_none()
        );

        // Past the grace window the expired record is dropped.
        node.sweep_expired_data(secs_to_ms(exp) + RETENTION_GRACE_MS + 1);
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
    fn admit_kel<S: Store>(node: &mut Node<S>, kel: &ValidatedKel, at: u64) {
        let frame = Frame::Kels(lattice_proto::frames::KelsFrame {
            kels: vec![kel.to_object_bytes().unwrap()],
        });
        let _ = node.handle(Event::Frame {
            at,
            link: 999,
            frame,
            bucket: None,
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
    fn advertised_ips_land_in_own_record() {
        let cfg = Config {
            snow_per_min: 0.0,
            advertise: vec!["ws://mesh.example.com/".to_string()],
            advertise_ips: vec![
                "1.2.3.4".parse().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ],
            ..Config::default()
        };
        let node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let rec = stored_record(&node, &node.own_id, Scope::Wan).expect("own record stored");
        assert_eq!(rec.endpoints.len(), 1);
        assert_eq!(
            rec.endpoints[0].ips,
            vec![
                "1.2.3.4".parse::<std::net::IpAddr>().unwrap(),
                "2001:4860:4860::8888".parse().unwrap(),
            ]
        );
    }

    // ── Record hygiene: advertised set, refresh, caps (R-11..R-13, R-17) ──

    fn insert_link(
        node: &mut Node<MemStore>,
        link: u64,
        peer: Option<Identifier>,
        pinned: bool,
        since: u64,
    ) {
        let ck = lattice_crypto::channel_x25519_public(&ChannelSeed::from_bytes([0x77; 32]));
        node.links
            .insert(link, LinkState::new(peer, ck, pinned, since));
    }

    #[test]
    fn advertised_set_dedups_by_peer() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xA1; 32]);
        insert_link(&mut node, 1, Some(peer), false, 1_000);
        insert_link(&mut node, 2, Some(peer), false, 2_000);
        assert_eq!(node.advertised_links(3_000), vec![peer]);
    }

    #[test]
    fn advertised_set_prefers_pinned_then_oldest_and_caps_at_max_links() {
        let mut node = test_node();
        // 32 unpinned links (oldest) and 8 pinned links (newest).
        for i in 0..32u8 {
            insert_link(
                &mut node,
                u64::from(i) + 1,
                Some(Identifier::from_bytes([i + 1; 32])),
                false,
                1_000 + u64::from(i),
            );
        }
        for i in 0..8u8 {
            insert_link(
                &mut node,
                100 + u64::from(i),
                Some(Identifier::from_bytes([0x80 + i; 32])),
                true,
                9_000 + u64::from(i),
            );
        }
        let advertised = node.advertised_links(10_000);
        assert_eq!(advertised.len(), lattice_proto::record::MAX_LINKS);
        // All 8 pinned links are kept despite being the newest.
        for i in 0..8u8 {
            assert!(advertised.contains(&Identifier::from_bytes([0x80 + i; 32])));
        }
        // The 24 oldest unpinned links are kept; the 8 newest are dropped.
        for i in 0..24u8 {
            assert!(advertised.contains(&Identifier::from_bytes([i + 1; 32])));
        }
        for i in 24..32u8 {
            assert!(!advertised.contains(&Identifier::from_bytes([i + 1; 32])));
        }
    }

    #[test]
    fn lost_link_stays_advertised_for_the_grace_period() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xA1; 32]);
        link_up(&mut node, 1, peer, 1_000);
        assert_eq!(node.advertised_links(1_000), vec![peer]);
        node.handle(Event::LinkDown { at: 2_000, link: 1 });
        // Still advertised inside the grace window...
        assert_eq!(node.advertised_links(2_000 + LINK_GRACE_MS), vec![peer]);
        // ...and gone once it elapses.
        assert!(node.advertised_links(2_000 + LINK_GRACE_MS + 1).is_empty());
    }

    #[test]
    fn grace_expiry_republishes_without_the_lost_link() {
        let mut node = test_node();
        node.config.republish_min_interval_secs = 0;
        let peer = Identifier::from_bytes([0xA1; 32]);
        link_up(&mut node, 1, peer, 1_000);
        let rec = stored_record(&node, &node.own_id, Scope::Wan).unwrap();
        assert_eq!(rec.links, vec![peer]);
        // The link goes down; the grace keeps it in the record.
        node.handle(Event::LinkDown { at: 2_000, link: 1 });
        let rec = stored_record(&node, &node.own_id, Scope::Wan).unwrap();
        assert_eq!(rec.links, vec![peer]);
        // Once the grace elapses, the next tick drops it and republishes.
        node.handle(Event::Tick {
            at: 2_000 + LINK_GRACE_MS + 1,
        });
        let rec = stored_record(&node, &node.own_id, Scope::Wan).unwrap();
        assert!(rec.links.is_empty());
    }

    #[test]
    fn record_advertises_each_peer_once() {
        let mut node = test_node();
        node.config.republish_min_interval_secs = 0;
        let peer = Identifier::from_bytes([0xA1; 32]);
        link_up(&mut node, 1, peer, 1_000);
        link_up(&mut node, 2, peer, 1_100);
        let rec = stored_record(&node, &node.own_id, Scope::Wan).unwrap();
        assert_eq!(rec.links, vec![peer]);
    }

    #[test]
    fn republish_is_spaced_after_a_change() {
        let mut node = test_node();
        node.config.republish_min_interval_secs = 120;
        let peer = Identifier::from_bytes([0xA1; 32]);
        let peer2 = Identifier::from_bytes([0xB2; 32]);
        let before = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        // The first link-triggered publish goes out immediately: the
        // startup publish does not arm the floor.
        link_up(&mut node, 1, peer, 1_001);
        let first = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        assert_ne!(before.bytes, first.bytes);
        // A second change within the spacing window: no republish yet.
        link_up(&mut node, 2, peer2, 1_002);
        let during = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        assert_eq!(first.bytes, during.bytes);
        // After the window elapses, the pending publish flushes on a tick.
        node.handle(Event::Tick {
            at: 1_001 + 120_000 + 1,
        });
        let after = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        assert_ne!(during.bytes, after.bytes);
        let rec = stored_record(&node, &node.own_id, Scope::Wan).unwrap();
        assert_eq!(rec.links, vec![peer, peer2]);
    }

    #[test]
    fn refresh_republishes_only_when_something_changed() {
        let mut node = test_node();
        node.config.republish_min_interval_secs = 0;
        // Make the refresh due immediately; nothing has changed and the
        // record is fresh, so nothing is republished.
        node.record_refresh_at = 2_000;
        let before = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        node.handle(Event::Tick { at: 2_000 });
        let after = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        assert_eq!(before.bytes, after.bytes);
        // With the record near expiry the refresh must republish.
        node.own_record_exp = 1;
        node.record_refresh_at = 3_000;
        node.handle(Event::Tick { at: 3_000 });
        let after = node
            .store
            .record_get(&node.own_id, Scope::Wan)
            .unwrap()
            .unwrap();
        assert_ne!(before.bytes, after.bytes);
    }

    #[test]
    fn status_rows_are_swept_after_the_ttl() {
        let mut node = test_node();
        let mid = MessageId::from_bytes([0x42; 16]);
        node.store
            .status_set(&mid, local::MSG_STATUS_DELIVERED, None, 1_000)
            .unwrap();
        // Within the TTL the row survives the sweep.
        node.sweep_store_expired(secs_to_ms(1_000 + lattice_store::STATUS_TTL_SECS - 1));
        assert!(node.store.status_get(&mid).unwrap().is_some());
        // Past the TTL the row is gone.
        node.sweep_store_expired(secs_to_ms(1_000 + lattice_store::STATUS_TTL_SECS + 1));
        assert!(node.store.status_get(&mid).unwrap().is_none());
    }

    #[test]
    fn record_cap_evicts_by_salted_hash_and_keeps_own_record() {
        let mut node = test_node();
        let own = node.own_id;
        for i in 0..6u8 {
            let id = Identifier::from_bytes([i + 1; 32]);
            node.store.record_put(&id, Scope::Wan, &[i; 16], 0).unwrap();
        }
        assert_eq!(node.store.record_count().unwrap(), 7);
        node.enforce_record_cap(4);
        assert_eq!(node.store.record_count().unwrap(), 4);
        assert!(node.store.record_get(&own, Scope::Wan).unwrap().is_some());
        // Idempotent: a second pass evicts nothing.
        node.enforce_record_cap(4);
        assert_eq!(node.store.record_count().unwrap(), 4);
    }

    #[test]
    fn unsolicited_records_are_dropped_past_the_push_budget() {
        let mut node = test_node();
        let link = 7u64;
        link_up(&mut node, link, Identifier::from_bytes([0xCC; 32]), 1_000);
        let frame = Frame::Records(lattice_proto::frames::RecordsFrame {
            records: (0..20u8).map(|i| vec![i; 8]).collect(),
        });
        let (_actions, diags) = node.handle(Event::Frame {
            at: 1_001,
            link,
            frame,
            bucket: None,
        });
        let dropped = diags
            .iter()
            .find(|d| d.op == "unsolicited_records_dropped")
            .unwrap_or_else(|| panic!("expected a drop diagnostic, got {diags:?}"));
        assert!(dropped.detail.contains('4'), "{}", dropped.detail);
    }

    #[test]
    fn solicited_record_bypasses_the_push_budget() {
        let mut node = test_node();
        let link = 7u64;
        link_up(&mut node, link, Identifier::from_bytes([0xCC; 32]), 1_000);
        // Drain the budget and grant one want credit, as if we had asked.
        if let Some(l) = node.links.get_mut(&link) {
            l.push_tokens = 0.0;
            l.want_credits = 1;
        }
        let sender = Identity::from_seed(&[0x5B; 32]);
        admit_kel(&mut node, &sender.kel, 1_001);
        let record = build_record(
            sender.kel.events().to_vec(),
            1,
            Scope::Wan,
            &sender.signing_seed,
            &sender.channel_seed,
        );
        let frame = Frame::Records(lattice_proto::frames::RecordsFrame {
            records: vec![record.encode()],
        });
        node.handle(Event::Frame {
            at: 1_002,
            link,
            frame,
            bucket: None,
        });
        assert!(
            node.store
                .record_get(&sender.id(), Scope::Wan)
                .unwrap()
                .is_some(),
            "a solicited record must be admitted even with an empty push budget"
        );
    }

    #[test]
    fn rotation_is_refused_when_the_record_cannot_be_published() {
        // Pre-seed the store with a valid own record so startup does not
        // publish; the node then comes up with a config whose endpoints
        // make any record unpublishable, and rotation must fail rather
        // than publish bytes peers reject.
        let seed = [0x5C; 32];
        let identity = Identity::from_seed(&seed);
        let kel = identity.kel.clone();
        let rec = lattice_proto::record::PeerRecord::build(
            lattice_proto::record::RecordParams {
                kel: kel.clone(),
                prev_seq: 0,
                now: 1,
                exp: 100_000,
                channel_key: lattice_crypto::channel_public(&identity.channel_seed),
                channel_seed: identity.channel_seed.clone(),
                envelope_key: identity.xwing_public,
                mode: Mode::Public,
                scope: Scope::Wan,
                endpoints: vec![lattice_proto::record::Endpoint {
                    url: "ws://mesh.example.com/".into(),
                    ips: vec![],
                }],
                links: vec![],
                gateways: vec![],
                capabilities: 1,
                serves: vec![],
            },
            &identity.signing_seed,
        )
        .unwrap();
        let mut store = MemStore::new();
        store
            .record_put(&identity.id(), Scope::Wan, &rec.encode(), 0)
            .unwrap();
        store
            .kel_put(
                &identity.id(),
                &kel.to_object_bytes().unwrap(),
                &KelHeadSeen {
                    seq: kel.head().seq,
                    commitment: kel.head().commitment,
                    seen: 0,
                    abandoned: false,
                },
            )
            .unwrap();
        let cfg = Config {
            snow_per_min: 0.0,
            advertise: (0..16)
                .map(|i| format!("ws://{}.example.com/", "a".repeat(180) + &i.to_string()))
                .collect(),
            ..Config::default()
        };
        let mut node = Node::new(cfg, identity, store, 1_000).expect("node starts");
        let err = node
            .reload_identity(Identity::from_seed(&seed), 2_000, RotationKind::Rotate)
            .expect_err("rotation must be refused when the record cannot be published");
        let msg = err.to_string();
        assert!(msg.contains("RECORD_MAX"), "unexpected error: {msg}");
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
        node.sweep_expired_data(1_000 + RETENTION_GRACE_MS + 1);
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
        node.sweep_expired_data(secs_to_ms(KEL_HEAD_MAX_AGE_SECS + 1));
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
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("wire message builds")
    }

    fn link_up<S: Store>(node: &mut Node<S>, link: u64, peer: Identifier, at: u64) {
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
        let entry = CustodyEntry {
            leg,
            message,
            upstream,
            destination,
            class: 0,
            exp,
            excluded: Vec::new(),
        };
        node.store.custody_put(entry.clone()).unwrap();
        // Track in the in-memory indexes without scheduling a retry: the
        // entry is treated as in flight (the tests drive it via explicit
        // replies or expiry).
        node.track_custody_insert(&custody_from_store(entry), u64::MAX);
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
            frame: custody_frame(leg, CUSTODY_ALREADY_HAVE),
            bucket: None,
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
        node.store_outbound(&msg);
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
            frame: custody_frame(leg, CUSTODY_ALREADY_HAVE),
            bucket: None,
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
                frame: custody_frame(leg, result),
                bucket: None,
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
            frame: custody_frame(leg, CUSTODY_ACCEPTED),
            bucket: None,
        });
        assert!(actions.is_empty());
        assert!(node.pending.contains_key(&leg));
        assert!(node.store.custody_get(&leg).unwrap().is_some());
        // The reply on the link the offer went out on is honored.
        let (_actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            frame: custody_frame(leg, CUSTODY_ACCEPTED),
            bucket: None,
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
        node.store_outbound(&msg);
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
            frame: custody_frame(leg, CUSTODY_REFUSED),
            bucket: None,
        });
        assert!(actions.is_empty());
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::InFlight);
        assert!(node.pending.contains_key(&leg));
        // The reply on the offering link fails the message as before.
        let (_actions, _) = node.handle(Event::Frame {
            at: now,
            link: 200,
            frame: custody_frame(leg, CUSTODY_REFUSED),
            bucket: None,
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
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
        node.store_outbound(&msg);
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
        node.store_outbound(&msg);
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
            Identity::from_seed(&[0xA5; 32]),
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
        node.store_outbound(&msg);
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
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("message builds");
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("message builds");
        node.set_drain(local::DrainState::Draining);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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
    fn new_round_frame_resets_reconcile_session() {
        use lattice_proto::frames::{Range, RangeBound};
        let peer = Identifier::from_bytes([0xA7; 32]);
        let mut node = test_node();
        link_up(&mut node, 100, peer, 1_000);
        let now = 1_000u64;
        let own = node.store.record_all().unwrap();
        assert_eq!(own.len(), 1, "node publishes its own record on link-up");
        let own_id = own[0].id;
        let range = Range::Entries {
            lower: Some(RangeBound {
                id: own_id,
                scope: 0,
            }),
            upper: None,
            entries: vec![],
        };
        let echoes = |actions: &[Action]| -> usize {
            actions
                .iter()
                .filter_map(|a| match a {
                    Action::SendFrame {
                        frame: Frame::Reconcile(r),
                        ..
                    } => Some(r),
                    _ => None,
                })
                .flat_map(|r| r.ranges.iter())
                .filter(|r| matches!(r, Range::Entries { entries, .. } if !entries.is_empty()))
                .count()
        };
        let send = |node: &mut Node<MemStore>, ranges: Vec<Range>| {
            node.handle(Event::Frame {
                at: now,
                link: 100,
                frame: Frame::Reconcile(ReconcileFrame { ranges }),
                bucket: None,
            })
            .0
        };
        // First Entries frame: the node echoes its own record.
        let actions = send(&mut node, vec![range.clone()]);
        assert_eq!(echoes(&actions), 1, "first Entries frame must be echoed");
        // Same frame again within the round: the echo is suppressed.
        let actions = send(&mut node, vec![range.clone()]);
        assert_eq!(echoes(&actions), 0, "echo is suppressed within a round");
        // A frame opening a new round (a single unbounded fingerprint
        // range) resets the session...
        let _ = send(
            &mut node,
            vec![Range::Fingerprint {
                lower: None,
                upper: None,
                count: 0,
                sum: Hash32::from_bytes([0; 32]),
            }],
        );
        // ...so the same Entries frame is echoed again.
        let actions = send(&mut node, vec![range]);
        assert_eq!(
            echoes(&actions),
            1,
            "a new round must reset echo suppression"
        );
    }

    #[test]
    fn oversize_frame_is_dropped_with_diagnostic() {
        let mut node = test_node();
        let big = Action::SendFrame {
            pad_to: None,
            link: 100,
            frame: Frame::Records(RecordsFrame {
                records: vec![vec![7u8; 40_000]],
            }),
        };
        let small = Action::SendFrame {
            pad_to: None,
            link: 100,
            frame: Frame::Ping(PingFrame { nonce: 1 }),
        };
        let out = node.drop_oversize_frames(vec![big, small]);
        assert_eq!(out.len(), 1);
        assert!(matches!(
            &out[0],
            Action::SendFrame {
                frame: Frame::Ping(_),
                ..
            }
        ));
        let diags = std::mem::take(&mut node.diagnostics);
        assert!(diags.iter().any(|d| d.op == "frame_too_large"));
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
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
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

    // ── deadline reporting, echo bucket/budget, RTT sampling ─────────

    /// Set every internal timer to "never" so tests can observe exactly
    /// which deadline the core reports.
    fn silence_timers(node: &mut Node<MemStore>) {
        node.next_reconcile_at = u64::MAX;
        node.record_refresh_at = u64::MAX;
        node.next_claim_sweep_at = u64::MAX;
        node.next_data_sweep_at = u64::MAX;
        node.snow_next = u64::MAX;
    }

    fn dummy_echo_actions(actions: &[Action]) -> Vec<(u64, Option<usize>)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendFrame {
                    link,
                    frame: Frame::Dummy(_),
                    pad_to,
                } => Some((*link, *pad_to)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn next_deadline_is_none_when_nothing_is_pending() {
        let mut node = test_node();
        silence_timers(&mut node);
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn next_deadline_reports_reconcile_when_only_housekeeping_pending() {
        let node = test_node();
        // Fresh node: reconcile is due 1s after construction (t=1000 ms).
        assert_eq!(node.next_deadline(), Some(2_000));
    }

    #[test]
    fn next_deadline_is_min_of_pending_timers() {
        let mut node = test_node();
        silence_timers(&mut node);
        // Custody entry expiring at t=5s (store holds seconds).
        let leg = LegId::from_bytes([0x42; 16]);
        let dst = Identifier::from_bytes([0xD5; 32]);
        let wire = wire_message(leg, dst, 60);
        insert_relay_custody(&mut node, leg, wire, 100, dst, 5);
        assert_eq!(node.next_deadline(), Some(5_000));
        // A queued outbound with an earlier next_attempt wins.
        let mid = MessageId::from_bytes([0x43; 16]);
        let mut msg = outbound(mid, dst, OutboundState::Queued);
        msg.next_attempt = 2_000; // ms
        node.store_outbound(&msg);
        assert_eq!(node.next_deadline(), Some(2_000));
        // A pending custody offer with an even earlier timeout wins.
        let leg2 = LegId::from_bytes([0x44; 16]);
        node.pending.insert(
            leg2,
            PendingOffer {
                origin: PendingOrigin::Relay { custody_leg: leg2 },
                sent_at: 1_000,
                excluded: Vec::new(),
                link: 100,
            },
        );
        // sent_at (1000) + CUSTODY_TIMEOUT_MS (30_000) = 31_000, which is
        // later than 2_000, so the outbound still wins.
        assert_eq!(node.next_deadline(), Some(2_000));
        // An echo due sooner than everything wins.
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        node.handle(Event::Frame {
            at: 1_000,
            link: 100,
            frame: Frame::Dummy(DummyFrame { echo: true }),
            bucket: Some(1),
        });
        let echo_due = node.inner_pending_echo[0].due;
        assert_eq!(node.next_deadline(), Some(echo_due.min(2_000)));
    }

    #[test]
    fn next_deadline_clears_after_tick_processes_timers() {
        let mut node = test_node();
        silence_timers(&mut node);
        let leg = LegId::from_bytes([0x42; 16]);
        let dst = Identifier::from_bytes([0xD5; 32]);
        let wire = wire_message(leg, dst, 60);
        insert_relay_custody(&mut node, leg, wire, 100, dst, 5);
        assert_eq!(node.next_deadline(), Some(5_000));
        // The custody entry expires at t=5s; a tick there sweeps it.
        node.handle(Event::Tick { at: 5_000 });
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn echo_reply_uses_request_bucket() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        for bucket in [0usize, 1, 2, 3] {
            node.handle(Event::Frame {
                at: 1_000,
                link: 100,
                frame: Frame::Dummy(DummyFrame { echo: true }),
                bucket: Some(bucket),
            });
        }
        let (actions, _) = node.handle(Event::Tick {
            at: 1_000 + MAX_ECHO_DELAY_MS + 1,
        });
        let buckets = dummy_echo_actions(&actions);
        assert_eq!(buckets.len(), 4);
        assert_eq!(
            buckets.iter().map(|&(_, b)| b).collect::<Vec<_>>(),
            vec![Some(0), Some(1), Some(2), Some(3)],
            "echo replies must go out in the request's bucket"
        );
    }

    #[test]
    fn echo_reply_without_bucket_hint_uses_a_valid_bucket() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        node.handle(Event::Frame {
            at: 1_000,
            link: 100,
            frame: Frame::Dummy(DummyFrame { echo: true }),
            bucket: None,
        });
        let (actions, _) = node.handle(Event::Tick {
            at: 1_000 + MAX_ECHO_DELAY_MS + 1,
        });
        let buckets = dummy_echo_actions(&actions);
        assert_eq!(buckets.len(), 1);
        assert!(buckets[0].1.is_some_and(|b| b < 4));
    }

    #[test]
    fn echo_budget_limits_replies_per_link() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        // Flood the node with echo requests; only the budget is honored.
        for _ in 0..20 {
            node.handle(Event::Frame {
                at: 1_000,
                link: 100,
                frame: Frame::Dummy(DummyFrame { echo: true }),
                bucket: Some(2),
            });
        }
        assert_eq!(node.inner_pending_echo.len(), ECHO_BUDGET_CAPACITY as usize);
        let (actions, _) = node.handle(Event::Tick {
            at: 1_000 + MAX_ECHO_DELAY_MS + 1,
        });
        assert_eq!(
            dummy_echo_actions(&actions).len(),
            ECHO_BUDGET_CAPACITY as usize
        );
    }

    #[test]
    fn echo_budget_refills_over_time() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        for _ in 0..20 {
            node.handle(Event::Frame {
                at: 1_000,
                link: 100,
                frame: Frame::Dummy(DummyFrame { echo: true }),
                bucket: Some(2),
            });
        }
        assert_eq!(node.inner_pending_echo.len(), ECHO_BUDGET_CAPACITY as usize);
        // 3 seconds later the bucket has refilled by 1.5 tokens: one more
        // echo is allowed, the next is not.
        node.handle(Event::Frame {
            at: 4_000,
            link: 100,
            frame: Frame::Dummy(DummyFrame { echo: true }),
            bucket: Some(2),
        });
        assert_eq!(
            node.inner_pending_echo.len(),
            ECHO_BUDGET_CAPACITY as usize + 1
        );
        node.handle(Event::Frame {
            at: 4_000,
            link: 100,
            frame: Frame::Dummy(DummyFrame { echo: true }),
            bucket: Some(2),
        });
        assert_eq!(
            node.inner_pending_echo.len(),
            ECHO_BUDGET_CAPACITY as usize + 1
        );
    }

    #[test]
    fn echo_budget_is_per_link() {
        let mut node = test_node();
        let peer_a = Identifier::from_bytes([0xE1; 32]);
        let peer_b = Identifier::from_bytes([0xE2; 32]);
        link_up(&mut node, 100, peer_a, 1_000);
        link_up(&mut node, 200, peer_b, 1_000);
        for _ in 0..20 {
            node.handle(Event::Frame {
                at: 1_000,
                link: 100,
                frame: Frame::Dummy(DummyFrame { echo: true }),
                bucket: Some(2),
            });
        }
        // The other link has its own budget.
        node.handle(Event::Frame {
            at: 1_000,
            link: 200,
            frame: Frame::Dummy(DummyFrame { echo: true }),
            bucket: Some(2),
        });
        assert_eq!(
            node.inner_pending_echo.len(),
            ECHO_BUDGET_CAPACITY as usize + 1
        );
    }

    #[test]
    fn custody_rtt_estimate_converges_and_samples() {
        let mut node = test_node();
        // No samples yet: the prior is used and every sample is in range.
        for _ in 0..100 {
            assert!(node.sample_custody_rtt_ms() <= MAX_ECHO_DELAY_MS);
        }
        // Feed a steady 50 ms RTT; the EMA converges on it.
        for _ in 0..200 {
            node.observe_custody_rtt(50);
        }
        let ema = node.custody_rtt_ema_ms.expect("samples recorded");
        assert!((ema - 50.0).abs() < 1.0, "ema was {ema}");
        // Samples drawn from the fitted distribution average near 50 ms.
        let n = 2_000u64;
        let sum: u64 = (0..n).map(|_| node.sample_custody_rtt_ms()).sum();
        let mean = sum as f64 / n as f64;
        assert!((30.0..75.0).contains(&mean), "mean sample was {mean}");
    }

    #[test]
    fn custody_reply_updates_rtt_estimate() {
        let mut node = test_node();
        let peer = Identifier::from_bytes([0xE1; 32]);
        link_up(&mut node, 100, peer, 1_000);
        let leg = LegId::from_bytes([0x77; 16]);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Relay { custody_leg: leg },
                sent_at: 1_000,
                excluded: Vec::new(),
                link: 100,
            },
        );
        node.handle(Event::Frame {
            at: 1_050,
            link: 100,
            frame: custody_frame(leg, CUSTODY_ACCEPTED),
            bucket: None,
        });
        let ema = node.custody_rtt_ema_ms.expect("reply observed");
        assert!((ema - 50.0).abs() < f64::EPSILON);
    }

    /// R-21: stored records are validated once — at admission or at
    /// startup — and never on the per-tick read paths. The test-only
    /// `validation_count` counts every call to `validate_stored`.
    #[test]
    fn stored_records_are_validated_once_not_per_tick() {
        let ext_a = Identity::from_seed(&[0xA1; 32]);
        let ext_b = Identity::from_seed(&[0xB2; 32]);

        // Pre-populate the store as a previous run would have left it.
        let mut store = MemStore::new();
        for ext in [&ext_a, &ext_b] {
            let kel_bytes = ext.kel.to_object_bytes().unwrap();
            let head = ext.kel.head();
            store
                .kel_put(
                    &ext.id(),
                    &kel_bytes,
                    &KelHeadSeen {
                        seq: head.seq,
                        commitment: head.commitment,
                        seen: 0,
                        abandoned: false,
                    },
                )
                .unwrap();
            let rec = build_record(
                ext.kel.events().to_vec(),
                1,
                Scope::Wan,
                &ext.signing_seed,
                &ext.channel_seed,
            );
            store
                .record_put(&ext.id(), Scope::Wan, &rec.encode(), 0)
                .unwrap();
        }

        let mut node = Node::new(
            Config {
                snow_per_min: 0.0,
                ..Config::default()
            },
            Identity::from_seed(&[0xC3; 32]),
            store,
            1_000,
        )
        .expect("node construction");

        // Startup validated each stored record exactly once.
        assert_eq!(node.validation_count, 2);
        // Two external records plus our own published record.
        assert_eq!(node.record_index.len(), 3);

        // From here on, no read path may re-validate stored bytes.
        node.validation_count = 0;
        for at in [2_000, 3_000, 4_000] {
            node.handle(Event::Tick { at });
        }
        assert!(matches!(
            node.lookup(&ext_a.id()),
            LookupResult::Present { .. }
        ));
        assert!(matches!(
            node.lookup(&ext_b.id()),
            LookupResult::Present { .. }
        ));
        let items = node.record_items().expect("items");
        assert!(items.iter().any(|i| i.id == ext_a.id()));
        let _ = node.build_graph();
        let _ = node.waypoint_candidates();
        node.sweep_ck_claims(5_000);
        node.sweep_expired_data(5_000);
        assert_eq!(node.validation_count, 0);
        // The sweep kept the unexpired records.
        assert!(
            node.store
                .record_get(&ext_a.id(), Scope::Wan)
                .unwrap()
                .is_some()
        );
    }

    /// Records leave the index at expiry; reads filter on expiry even
    /// before the retention sweep evicts the entry.
    #[test]
    fn expired_record_leaves_index_and_reads() {
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_kel(&mut node, &sender.kel, 1_000);
        let kel = ValidatedKel::validate(sender.kel.events().to_vec()).unwrap();
        let rec = lattice_proto::record::PeerRecord::build(
            lattice_proto::record::RecordParams {
                kel,
                prev_seq: 0,
                now: 1,
                exp: 2,
                channel_key: lattice_crypto::channel_public(&sender.channel_seed),
                channel_seed: sender.channel_seed.clone(),
                envelope_key: XWingPublicKey::from_bytes([7u8; 1216]),
                mode: Mode::Public,
                scope: Scope::Wan,
                endpoints: vec![lattice_proto::record::Endpoint {
                    url: "ws://mesh.example.com/".into(),
                    ips: vec![],
                }],
                links: vec![],
                gateways: vec![],
                capabilities: 0,
                serves: vec![],
            },
            &sender.signing_seed,
        )
        .unwrap();
        node.admit_record(1_000, 999, &rec.encode());
        assert!(matches!(
            node.lookup(&sender.id()),
            LookupResult::Present { .. }
        ));
        // One second past expiry: filtered from every read path.
        node.handle(Event::Tick { at: 3_000 });
        assert!(matches!(node.lookup(&sender.id()), LookupResult::Absent));
        let items = node.record_items().expect("items");
        assert!(
            !items
                .iter()
                .any(|i| i.id == sender.id() && i.scope == scope_as_u8(Scope::Wan))
        );
        // The retention sweep evicts the stale entry from the index;
        // the store keeps the bytes until the grace period elapses.
        node.sweep_expired_data(3_000);
        assert!(
            !node
                .record_index
                .values()
                .any(|e| e.record.id == sender.id())
        );
        assert!(
            node.store
                .record_get(&sender.id(), Scope::Wan)
                .unwrap()
                .is_some()
        );
    }

    fn insert_custody_slot(
        node: &mut Node<MemStore>,
        leg_byte: u8,
        slot: u8,
        len: usize,
        upstream: u64,
        destination: Identifier,
    ) {
        node.store
            .custody_put(CustodyEntry {
                leg: LegId::from_bytes([leg_byte; 16]),
                message: vec![7u8; len],
                upstream,
                destination,
                class: slot,
                exp: u64::MAX / 2,
                excluded: Vec::new(),
            })
            .unwrap();
    }

    #[test]
    fn class_reserve_admits_when_shared_pool_is_full() {
        let mut node = test_node();
        node.config.transit_cap = 100_000;
        // reserve = max(100_000/128, min(2048, 100_000/32)) = 2048;
        // shared pool = 100_000 - 32 * 2048 = 34_464.
        let dst = Identifier::from_bytes([0xD5; 32]);
        // Fill the shared pool via slot 0 (second-leg class 0): 2048 reserve
        // plus 34_464 shared-pool bytes.
        insert_custody_slot(&mut node, 1, 0, 2048 + 34_464, 100, dst);
        // Slot 0 is now full: reserve exhausted and the shared pool is full.
        assert!(node.class_full(0, 1));
        // A different second-leg slot still has its reserve: admitted.
        assert!(!node.class_full(1, 2048));
        // A first-leg slot is unaffected by second-leg pressure.
        assert!(!node.class_full(16, 2048));
        // Fill the first-leg slot 16 too; now it is full as well.
        insert_custody_slot(&mut node, 2, 16, 2048, 100, dst);
        assert!(node.class_full(16, 1));
        // Second-leg slot 1 still has its reserve (first-leg bytes cannot
        // touch it).
        assert!(!node.class_full(1, 2048));
    }

    #[test]
    fn second_leg_cannot_use_first_leg_reserve() {
        let mut node = test_node();
        node.config.transit_cap = 100_000;
        let dst = Identifier::from_bytes([0xD5; 32]);
        // Fill the shared pool and second-leg slot 0's reserve.
        insert_custody_slot(&mut node, 1, 0, 2048 + 34_464, 100, dst);
        // Fill first-leg slot 16's reserve completely.
        insert_custody_slot(&mut node, 2, 16, 2048, 100, dst);
        // Second-leg slot 0 is full even though first-leg slot 16's reserve
        // is now also full — neither phase may borrow the other's reserve.
        assert!(node.class_full(0, 1));
        // And first-leg slot 16 is full even though second-leg slot 1 is free.
        assert!(node.class_full(16, 1));
        assert!(!node.class_full(17, 2048));
    }

    #[test]
    fn share_exceeded_divides_by_active_upstreams() {
        let mut node = test_node();
        node.config.custody_allowance = 1_000;
        node.config.transit_cap = 1_000_000; // aggregate cap stays out of the way
        let dst = Identifier::from_bytes([0xD5; 32]);
        let peer_a = Identifier::from_bytes([0xA1; 32]);
        let peer_b = Identifier::from_bytes([0xB2; 32]);
        link_up(&mut node, 100, peer_a, 1_000);
        link_up(&mut node, 200, peer_b, 1_000);
        // Upstream 100 holds a 400-byte share for dst; upstream 200 has none.
        node.store.share_add(&dst, 100, 400).unwrap();
        // New upstream (no share yet): divisor = active (1) + 1 = 2.
        assert!(!node.share_exceeded(&dst, 200, 500));
        assert!(node.share_exceeded(&dst, 200, 501));
        // Established upstream: divisor = active = 1, limit = 1000.
        assert!(!node.share_exceeded(&dst, 100, 600));
        assert!(node.share_exceeded(&dst, 100, 601));
    }

    #[test]
    fn custody_backoff_grows_exponentially_and_caps() {
        assert_eq!(custody_backoff_ms(1, 1800), 5_000);
        assert_eq!(custody_backoff_ms(2, 1800), 10_000);
        assert_eq!(custody_backoff_ms(3, 1800), 20_000);
        assert_eq!(custody_backoff_ms(4, 1800), 40_000);
        // Capped at retry_max_secs.
        assert_eq!(custody_backoff_ms(100, 1800), 1_800_000);
        // A zero retry_max_secs still yields the base delay, never zero.
        assert_eq!(custody_backoff_ms(1, 0), 5_000);
    }

    #[test]
    fn custody_entry_without_route_backs_off() {
        let mut node = test_node();
        let dst = Identifier::from_bytes([0xD5; 32]);
        let leg = LegId::from_bytes([0x42; 16]);
        let wire = wire_message(leg, dst, 60);
        // No links up: the entry has no route and must back off.
        let entry = CustodyEntry {
            leg,
            message: wire,
            upstream: 100,
            destination: dst,
            class: 0,
            exp: 60,
            excluded: Vec::new(),
        };
        node.store.custody_put(entry.clone()).unwrap();
        node.track_custody_insert(&custody_from_store(entry), 1_000);
        let actions = node.drain_custody(1_000);
        assert!(actions.is_empty());
        let meta = node.custody_meta.get(&leg).expect("entry is tracked");
        assert_eq!(meta.attempts, 1);
        assert_eq!(meta.next_attempt, 6_000);
        // Not due before the backoff elapses.
        assert!(node.drain_custody(5_999).is_empty());
        assert_eq!(node.custody_meta.get(&leg).unwrap().attempts, 1);
        // Due after the backoff; backs off further.
        let _ = node.drain_custody(6_000);
        let meta = node.custody_meta.get(&leg).expect("entry is tracked");
        assert_eq!(meta.attempts, 2);
        assert_eq!(meta.next_attempt, 16_000);
    }

    #[test]
    fn upstream_bytes_track_accept_and_release() {
        let mut node = test_node();
        let dst = Identifier::from_bytes([0xD5; 32]);
        let entry = CustodyEntry {
            leg: LegId::from_bytes([0x43; 16]),
            message: vec![7u8; 100],
            upstream: 100,
            destination: dst,
            class: 0,
            exp: u64::MAX / 2,
            excluded: Vec::new(),
        };
        node.store.custody_put(entry.clone()).unwrap();
        node.track_custody_insert(&custody_from_store(entry.clone()), 1_000);
        assert_eq!(node.upstream_bytes.get(&100), Some(&100));
        let released = node.release_custody(entry.leg).expect("entry exists");
        assert_eq!(released.message.len(), 100);
        assert_eq!(node.upstream_bytes.get(&100), None);
        assert!(node.custody_meta.is_empty());
        assert!(node.custody_retry.is_empty());
        assert!(node.custody_expiry.is_empty());
    }

    #[test]
    fn upstream_aggregate_cap_binds_across_destinations() {
        let mut node = test_node();
        node.config.custody_allowance = 1_000_000; // per-destination share stays out of the way
        node.config.transit_cap = 100_000; // aggregate cap = 100_000 / 2 bound links = 50_000
        let dst1 = Identifier::from_bytes([0xD1; 32]);
        let dst2 = Identifier::from_bytes([0xD2; 32]);
        let peer_a = Identifier::from_bytes([0xA1; 32]);
        let peer_b = Identifier::from_bytes([0xB2; 32]);
        link_up(&mut node, 100, peer_a, 1_000);
        link_up(&mut node, 200, peer_b, 1_000);
        // Upstream 100 has already pushed 50_000 bytes across two destinations.
        node.upstream_bytes.insert(100, 50_000);
        // One more byte from upstream 100 is refused even for a fresh destination.
        assert!(node.share_exceeded(&dst1, 100, 1));
        assert!(node.share_exceeded(&dst2, 100, 1));
        // Upstream 200 is unaffected.
        assert!(!node.share_exceeded(&dst1, 200, 1));
    }

    /// Admit a record for `identity` with the given mode, links and
    /// gateways; returns the identity's id.
    fn admit_peer(
        node: &mut Node<MemStore>,
        identity: &Identity,
        mode: Mode,
        links: Vec<Identifier>,
        gateways: Vec<Identifier>,
        at: u64,
    ) -> Identifier {
        admit_peer_serves(node, identity, mode, links, gateways, Vec::new(), at)
    }

    /// As [`admit_peer`], with an explicit `serves` list (public records
    /// only; private records carry none).
    fn admit_peer_serves(
        node: &mut Node<MemStore>,
        identity: &Identity,
        mode: Mode,
        links: Vec<Identifier>,
        gateways: Vec<Identifier>,
        serves: Vec<Identifier>,
        at: u64,
    ) -> Identifier {
        admit_kel(node, &identity.kel, at);
        let (endpoints, links, gateways, serves) = match mode {
            Mode::Public => (
                vec![lattice_proto::record::Endpoint {
                    url: "ws://mesh.example.com/".into(),
                    ips: vec![],
                }],
                links,
                Vec::new(),
                serves,
            ),
            Mode::Private => (Vec::new(), Vec::new(), gateways, Vec::new()),
        };
        let record = lattice_proto::record::PeerRecord::build(
            lattice_proto::record::RecordParams {
                kel: ValidatedKel::validate(identity.kel.events().to_vec()).unwrap(),
                prev_seq: 0,
                now: 1,
                exp: 1_000 + 86_400,
                channel_key: lattice_crypto::channel_public(&identity.channel_seed),
                channel_seed: identity.channel_seed.clone(),
                envelope_key: identity.xwing_public,
                mode,
                scope: Scope::Wan,
                endpoints,
                links,
                gateways,
                capabilities: 0,
                serves,
            },
            &identity.signing_seed,
        )
        .unwrap();
        node.admit_record(at, 999, &record.encode());
        identity.id()
    }

    /// The `dst` of the offer carried by `actions`, if any.
    fn sent_dst(actions: &[Action], now: u64) -> Option<Identifier> {
        actions.iter().find_map(|a| match a {
            Action::SendFrame {
                frame: Frame::Offer(o),
                ..
            } => Message::parse(&o.message, ms_to_secs(now))
                .ok()
                .map(|m| m.header.dst),
            _ => None,
        })
    }

    // ── R-36: gateway selection ─────────────────────────────────────

    #[test]
    fn gateway_selection_prefers_untried_gateways() {
        let mut node = test_node();
        let now = 1_000u64;
        let gw1 = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE1; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let gw2 = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE2; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE3; 32]),
            Mode::Private,
            vec![],
            vec![gw1, gw2],
            now,
        );
        link_up(&mut node, 100, gw1, now);
        link_up(&mut node, 200, gw2, now);

        let mid = MessageId::from_bytes([0x71; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::Queued);
        msg.exp = now + 100_000;
        msg.next_attempt = now;
        node.push_outbound(&msg).unwrap();

        // First attempt: one of the two gateways is chosen and recorded.
        let actions = node.pump_outbound(now);
        let first = sent_dst(&actions, now).expect("message must be sent");
        assert!(first == gw1 || first == gw2);
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.waypoints_tried, vec![first]);
        assert_eq!(stored.attempts, 1);

        // Force a requeue (as the receipt-deadline sweep would) and pump
        // again: the untried gateway must be chosen.
        let mut stored = outbound_from_store(stored);
        stored.state = OutboundState::Queued;
        stored.next_attempt = now + 1;
        node.store_outbound(&stored);
        let actions = node.pump_outbound(now + 1);
        let second = sent_dst(&actions, now + 1).expect("second attempt must be sent");
        assert_ne!(first, second, "the tried gateway must not be chosen again");
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.waypoints_tried, vec![first, second]);
        assert_eq!(stored.attempts, 2);

        // Both gateways tried: the fallback still sends (to one of them)
        // rather than stranding the message.
        let mut stored = outbound_from_store(stored);
        stored.state = OutboundState::Queued;
        stored.next_attempt = now + 2;
        node.store_outbound(&stored);
        let actions = node.pump_outbound(now + 2);
        let third = sent_dst(&actions, now + 2).expect("third attempt must still be sent");
        assert!(third == gw1 || third == gw2);
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.attempts, 3);
    }

    #[test]
    fn gateway_choice_is_not_always_the_first_listed() {
        let mut node = test_node();
        let now = 1_000u64;
        let gw1 = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE1; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let gw2 = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE2; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mut picks = std::collections::HashSet::new();
        for _ in 0..32 {
            let picked = node.pick_gateway(&[gw1, gw2], &[]).expect("a gateway").0;
            picks.insert(picked);
        }
        assert_eq!(
            picks.len(),
            2,
            "both gateways should be chosen over 32 draws"
        );
    }

    // ── H-21 / R-23: gateway consent and private leaves ─────────────

    /// Build a message addressed to `dst` (not this node), sealed to
    /// `dst_ek`. Used to offer the node a relay custody candidate.
    fn sealed_to_foreign(
        dst: Identifier,
        dst_ek: &XWingPublicKey,
        sender: &Identity,
        leg_byte: u8,
        now: u64,
    ) -> Vec<u8> {
        Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_MESSAGE,
                mid: MessageId::from_bytes([leg_byte; 16]),
                from: sender.id(),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: "svc".into(),
                tmbx: b"in".to_vec(),
                created: now,
                body: Some(b"hi".to_vec()),
                reference: None,
                reason: None,
                sig: Signature::from_bytes([0; 64]),
            },
            sender_seed: &sender.signing_seed,
            recipient_ek: dst_ek,
            real_dst: dst,
            leg: LegId::from_bytes([leg_byte; 16]),
            exp: now + 10_000,
            gateway: None,
            waypoint: None,
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("message builds")
    }

    fn private_test_node() -> Node<MemStore> {
        let gw = Identifier::from_bytes([0xE7; 32]);
        Node::new(
            Config {
                snow_per_min: 0.0,
                mode: Mode::Private,
                gateways: vec![gw],
                ..Config::default()
            },
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction")
    }

    #[test]
    fn private_node_refuses_relay_custody() {
        let mut node = private_test_node();
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let foreign = Identity::from_seed(&[0x5B; 32]);
        let wire = sealed_to_foreign(foreign.id(), &foreign.xwing_public, &sender, 0x61, now);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_REFUSED
            )),
            "a private node must refuse relay custody for a foreign destination, got {actions:?}"
        );
        assert_eq!(node.debug_custody_count(), 0);
    }

    #[test]
    fn public_node_accepts_relay_custody() {
        // Control: the same offer is accepted by a public node.
        let mut node = test_node();
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let now = 1_000u64;
        let foreign = Identity::from_seed(&[0x5B; 32]);
        let wire = sealed_to_foreign(foreign.id(), &foreign.xwing_public, &sender, 0x62, now);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "a public node accepts relay custody, got {actions:?}"
        );
    }

    #[test]
    fn pseudo_edge_requires_gateway_consent() {
        // Gateway without `serves`: no edge, no route to the private node.
        let mut node = test_node();
        let now = 1_000u64;
        let gw_id = Identity::from_seed(&[0xE1; 32]);
        let priv_id = Identity::from_seed(&[0xB1; 32]);
        let gw = admit_peer_serves(&mut node, &gw_id, Mode::Public, vec![], vec![], vec![], now);
        let p = admit_peer(&mut node, &priv_id, Mode::Private, vec![], vec![gw], now);
        let graph = node.build_graph();
        assert!(!graph.distances(&gw).contains_key(&p));
        assert!(!graph.distances(&p).contains_key(&gw));

        // Same topology, but the gateway lists the private id in `serves`:
        // the edge exists in both directions.
        let mut node = test_node();
        let priv_id2 = Identity::from_seed(&[0xB1; 32]);
        let priv_id2_id = priv_id2.id();
        let gw = admit_peer_serves(
            &mut node,
            &gw_id,
            Mode::Public,
            vec![],
            vec![],
            vec![priv_id2_id],
            now,
        );
        let p = admit_peer(&mut node, &priv_id2, Mode::Private, vec![], vec![gw], now);
        let graph = node.build_graph();
        assert_eq!(graph.distances(&gw).get(&p), Some(&1));
        assert_eq!(graph.distances(&p).get(&gw), Some(&1));
    }

    #[test]
    fn gateway_consent_is_per_private_id() {
        // The gateway serves a *different* private id: no edge to this one.
        let mut node = test_node();
        let now = 1_000u64;
        let gw_id = Identity::from_seed(&[0xE1; 32]);
        let priv_id = Identity::from_seed(&[0xB1; 32]);
        let other = Identity::from_seed(&[0xB2; 32]);
        let gw = admit_peer_serves(
            &mut node,
            &gw_id,
            Mode::Public,
            vec![],
            vec![],
            vec![other.id()],
            now,
        );
        let p = admit_peer(&mut node, &priv_id, Mode::Private, vec![], vec![gw], now);
        let graph = node.build_graph();
        assert!(!graph.distances(&gw).contains_key(&p));
    }

    #[test]
    fn gateway_layer_refused_without_serves_accepted_with() {
        let recipient = Identifier::from_bytes([0xD1; 32]);
        let sender = Identity::from_seed(&[0x5C; 32]);
        for serves in [vec![], vec![recipient]] {
            let mut node = Node::new(
                Config {
                    snow_per_min: 0.0,
                    serves: serves.clone(),
                    ..Config::default()
                },
                Identity::from_seed(&[0xA5; 32]),
                MemStore::new(),
                1_000,
            )
            .expect("node construction");
            let now = 1_000u64;
            let wire = Message::build(BuildParams {
                envelope: Envelope {
                    kind: KIND_MESSAGE,
                    mid: MessageId::from_bytes([0x53; 16]),
                    from: sender.id(),
                    fsvc: "svc".into(),
                    fmbx: b"out".to_vec(),
                    tsvc: "svc".into(),
                    tmbx: b"in".to_vec(),
                    created: now,
                    body: Some(b"hi".to_vec()),
                    reference: None,
                    reason: None,
                    sig: Signature::from_bytes([0; 64]),
                },
                sender_seed: &sender.signing_seed,
                recipient_ek: &XWingPublicKey::from_bytes([7u8; 1216]),
                real_dst: node.own_id,
                leg: LegId::from_bytes([0x53; 16]),
                exp: now + 10_000,
                gateway: Some(GatewaySeal {
                    gateway_ek: node.identity.xwing_public,
                    rcpt: recipient,
                }),
                waypoint: None,
                entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
            })
            .expect("message builds");
            link_up(&mut node, 100, sender.id(), now);
            let (actions, _) = node.handle(Event::Frame {
                at: now,
                link: 100,
                frame: Frame::Offer(OfferFrame { message: wire }),
                bucket: None,
            });
            let accepted = actions.iter().any(|a| {
                matches!(
                    a,
                    Action::SendFrame {
                        frame: Frame::Custody(c),
                        ..
                    } if c.result == CUSTODY_ACCEPTED
                )
            });
            let refused = actions.iter().any(|a| {
                matches!(
                    a,
                    Action::SendFrame {
                        frame: Frame::Custody(c),
                        ..
                    } if c.result == CUSTODY_REFUSED
                )
            });
            if serves.is_empty() {
                assert!(refused, "a gateway without the id in serves must refuse");
                assert!(!accepted);
            } else {
                assert!(
                    accepted,
                    "a gateway serving the id must accept, got {actions:?}"
                );
            }
        }
    }

    // ── R-39: attempt accounting and no-route backoff ───────────────

    #[test]
    fn no_route_waits_with_backoff_and_expires_without_failing() {
        let cfg = Config {
            snow_per_min: 0.0,
            retry_base_secs: 10,
            retry_max_secs: 1_000,
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let now = 1_000u64;
        // A recipient with a record but no path: the build succeeds, the
        // dispatch finds no route.
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE5; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mid = MessageId::from_bytes([0x72; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::Queued);
        msg.exp = now + 45_000;
        msg.next_attempt = now;
        node.push_outbound(&msg).unwrap();

        // First pump: no route; backs off by retry_base, attempts stay 0.
        let actions = node.pump_outbound(now);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendFrame { .. }))
        );
        let stored = outbound_from_store(node.store.outbound_get(&mid).unwrap().unwrap());
        assert_eq!(stored.attempts, 0);
        assert_eq!(stored.state, OutboundState::Queued);
        assert_eq!(stored.next_attempt, now + 10_000);

        // Second pump: backoff doubles.
        let _ = node.pump_outbound(now + 10_000);
        let stored = outbound_from_store(node.store.outbound_get(&mid).unwrap().unwrap());
        assert_eq!(stored.attempts, 0);
        assert_eq!(stored.next_attempt, now + 10_000 + 20_000);

        // Third pump: still waiting, still not failed.
        let _ = node.pump_outbound(now + 30_000);
        let stored = outbound_from_store(node.store.outbound_get(&mid).unwrap().unwrap());
        assert_eq!(stored.attempts, 0);
        assert_eq!(stored.state, OutboundState::Queued);
        assert_eq!(stored.next_attempt, now + 30_000 + 40_000);

        // The message is not failed early; it expires at its horizon.
        node.expire_outbound(now + 45_001);
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Expired);
        let status = node.store.status_get(&mid).unwrap().unwrap();
        assert_eq!(status.status, local::MSG_STATUS_EXPIRED);
        assert_eq!(status.detail, Some(ERR_EXPIRED));
    }

    #[test]
    fn missing_recipient_record_waits_instead_of_failing() {
        let cfg = Config {
            snow_per_min: 0.0,
            retry_base_secs: 1,
            retry_max_secs: 10,
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let now = 1_000u64;
        // No record for the recipient at all: the build itself finds no
        // route. The message must wait, not fail.
        let ghost = Identifier::from_bytes([0xE6; 32]);
        let mid = MessageId::from_bytes([0x73; 16]);
        let mut msg = outbound(mid, ghost, OutboundState::Queued);
        msg.exp = now + 30_000;
        msg.next_attempt = now;
        node.push_outbound(&msg).unwrap();
        for tick in 0..6 {
            let at = now + tick * 1_000;
            let actions = node.pump_outbound(at);
            assert!(
                !actions.iter().any(|a| matches!(
                    a,
                    Action::Status {
                        status: local::MSG_STATUS_FAILED,
                        ..
                    }
                )),
                "a no-route message must not fail early"
            );
        }
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Queued);
        assert_eq!(stored.attempts, 0);
        node.expire_outbound(now + 30_001);
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Expired);
    }

    #[test]
    fn receipt_deadline_fails_after_fresh_waypoint_retries_are_spent() {
        let mut node = test_node();
        let now = 1_000u64;
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE7; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mid = MessageId::from_bytes([0x74; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::InFlight);
        msg.attempts = 4; // > fresh_waypoint_retries (3)
        msg.exp = now + 100_000;
        msg.receipt_deadline = Some(now - 1);
        node.store_outbound(&msg);
        let actions = node.sweep_receipt_deadlines(now);
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.state, OutboundState::Failed);
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_FAILED,
                detail: Some(ERR_NO_ROUTE),
                ..
            }
        )));
    }

    #[test]
    fn receipt_deadline_requeues_while_retries_remain() {
        let mut node = test_node();
        let now = 1_000u64;
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xE7; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mid = MessageId::from_bytes([0x75; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::InFlight);
        msg.attempts = 2; // <= fresh_waypoint_retries (3)
        msg.exp = now + 100_000;
        msg.receipt_deadline = Some(now - 1);
        node.store_outbound(&msg);
        let actions = node.sweep_receipt_deadlines(now);
        assert!(actions.is_empty());
        let stored = outbound_from_store(node.store.outbound_get(&mid).unwrap().unwrap());
        assert_eq!(stored.state, OutboundState::Queued);
        assert_eq!(stored.next_attempt, now);
    }

    // ── R-40: waypoint candidates ───────────────────────────────────

    #[test]
    fn waypoint_candidates_must_be_reachable() {
        let mut node = test_node();
        let now = 1_000u64;
        // w1 is reachable via x (A—x—w1); w2 has no path from here.
        let own_id = node.own_id;
        let x_id = Identity::from_seed(&[0xE8; 32]);
        let w1_id = Identity::from_seed(&[0xE9; 32]);
        let w1 = admit_peer(
            &mut node,
            &w1_id,
            Mode::Public,
            vec![x_id.id()],
            vec![],
            now,
        );
        let _w2 = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xEA; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let _x = admit_peer(
            &mut node,
            &x_id,
            Mode::Public,
            vec![own_id, w1],
            vec![],
            now,
        );
        link_up(&mut node, 100, x_id.id(), now);
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xEB; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mid = MessageId::from_bytes([0x76; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::Queued);
        msg.route = 1; // force waypoint
        msg.exp = now + 100_000;
        msg.next_attempt = now;
        node.push_outbound(&msg).unwrap();
        let actions = node.pump_outbound(now);
        let dst = sent_dst(&actions, now).expect("message must be sent via a waypoint");
        assert_eq!(dst, w1, "the unreachable waypoint must not be chosen");
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.waypoints_tried, vec![w1]);
    }

    #[test]
    fn waypoint_chosen_for_no_route_dispatch_is_recorded_as_tried() {
        let mut node = test_node();
        let now = 1_000u64;
        // w1 is reachable via x (A—x—w1); the link to x goes down, so
        // dispatch finds no route. The waypoint must still be recorded
        // as tried.
        let own_id = node.own_id;
        let x_id = Identity::from_seed(&[0xE8; 32]);
        let w1_id = Identity::from_seed(&[0xE9; 32]);
        let w1 = admit_peer(
            &mut node,
            &w1_id,
            Mode::Public,
            vec![x_id.id()],
            vec![],
            now,
        );
        let _x = admit_peer(
            &mut node,
            &x_id,
            Mode::Public,
            vec![own_id, w1],
            vec![],
            now,
        );
        link_up(&mut node, 100, x_id.id(), now);
        node.handle(Event::LinkDown {
            at: now + 1,
            link: 100,
        });
        let recipient = admit_peer(
            &mut node,
            &Identity::from_seed(&[0xEA; 32]),
            Mode::Public,
            vec![],
            vec![],
            now,
        );
        let mid = MessageId::from_bytes([0x77; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::Queued);
        msg.route = 1; // force waypoint
        msg.exp = now + 100_000;
        msg.next_attempt = now + 2;
        node.push_outbound(&msg).unwrap();
        let actions = node.pump_outbound(now + 2);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::SendFrame { .. }))
        );
        let stored = node.store.outbound_get(&mid).unwrap().unwrap();
        assert_eq!(stored.waypoints_tried, vec![w1]);
        assert_eq!(stored.attempts, 0);
        assert_eq!(stored.state, OutboundState::Queued);
    }

    // ── R-37: hop layers sealed to retired keys ─────────────────────

    #[test]
    fn hop_layer_sealed_to_retired_key_is_opened() {
        let mut node = test_node();
        let now = 1_000u64;
        let old_ek = node.identity.xwing_public;
        // Rotate: the current key is retired (grace period), a fresh key
        // becomes current.
        node.identity.rotate_envelope(now + 100_000);
        let sender = Identity::from_seed(&[0x5C; 32]);
        let recipient = Identifier::from_bytes([0xD1; 32]);
        let own_id = node.own_id;
        let build = |leg: u8| {
            Message::build(BuildParams {
                envelope: Envelope {
                    kind: KIND_MESSAGE,
                    mid: MessageId::from_bytes([leg; 16]),
                    from: sender.id(),
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
                sender_seed: &sender.signing_seed,
                recipient_ek: &XWingPublicKey::from_bytes([7u8; 1216]),
                real_dst: recipient,
                leg: LegId::from_bytes([leg; 16]),
                exp: 10_000,
                gateway: None,
                waypoint: Some(WaypointSeal {
                    waypoint_id: own_id,
                    waypoint_ek: old_ek,
                    leg: LegId::from_bytes([leg; 16]),
                    exp: 10_000,
                }),
                entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
            })
            .expect("message builds")
        };
        link_up(&mut node, 100, sender.id(), now);
        // A waypoint layer sealed to the retired key is accepted.
        let wire = build(0x51);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "waypoint layer sealed to a retired key must open, got {actions:?}"
        );
        // After the grace period the retired key is gone; the same layer
        // is refused.
        node.identity.sweep_retired_envelope_keys(now + 100_001);
        let wire = build(0x52);
        let (actions, _) = node.handle(Event::Frame {
            at: now + 100_001,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_REFUSED
            )),
            "waypoint layer sealed to a swept key must be refused, got {actions:?}"
        );
    }

    #[test]
    fn gateway_layer_sealed_to_retired_key_is_opened() {
        let recipient = Identifier::from_bytes([0xD1; 32]);
        // The node serves `recipient` as a gateway (spec §3, gateway
        // consent); without that, the gateway layer is refused.
        let mut node = Node::new(
            Config {
                snow_per_min: 0.0,
                serves: vec![recipient],
                ..Config::default()
            },
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let now = 1_000u64;
        let old_ek = node.identity.xwing_public;
        node.identity.rotate_envelope(now + 100_000);
        let sender = Identity::from_seed(&[0x5C; 32]);
        let wire = Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_MESSAGE,
                mid: MessageId::from_bytes([0x53; 16]),
                from: sender.id(),
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
            sender_seed: &sender.signing_seed,
            recipient_ek: &XWingPublicKey::from_bytes([7u8; 1216]),
            real_dst: node.own_id,
            leg: LegId::from_bytes([0x53; 16]),
            exp: 10_000,
            gateway: Some(GatewaySeal {
                gateway_ek: old_ek,
                rcpt: recipient,
            }),
            waypoint: None,
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("message builds");
        link_up(&mut node, 100, sender.id(), now);
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_ACCEPTED
            )),
            "gateway layer sealed to a retired key must open, got {actions:?}"
        );
    }

    // ── R-38: unknown sender elicits a want for their record ────────

    #[test]
    fn unknown_sender_gets_busy_and_a_want_on_two_links() {
        let mut node = test_node();
        let now = 1_000u64;
        let sender = Identity::from_seed(&[0x5A; 32]);
        // No record for the sender is admitted.
        link_up(&mut node, 100, sender.id(), now);
        link_up(&mut node, 200, Identifier::from_bytes([0x33; 32]), now);
        let wire = sealed_to_node(
            &node,
            &sender,
            &sender.signing_seed,
            KIND_MESSAGE,
            None,
            LegId::from_bytes([0x66; 16]),
            now,
        );
        let (actions, _) = node.handle(Event::Frame {
            at: now,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        });
        // The offer is answered with busy.
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::SendFrame {
                link: 100,
                frame: Frame::Custody(c),
                ..
            } if c.result == CUSTODY_BUSY
        )));
        // A want for (sender, WAN) and (sender, hive) goes out on the
        // offering link and on one other link.
        let mut want_links = Vec::new();
        for a in &actions {
            if let Action::SendFrame {
                link,
                frame: Frame::Want(w),
                ..
            } = a
            {
                assert!(w.wants.iter().all(|r| r.id == sender.id()));
                let scopes: Vec<u8> = w.wants.iter().map(|r| r.scope).collect();
                assert_eq!(scopes, vec![0, 1]);
                want_links.push(*link);
            }
        }
        assert!(
            want_links.contains(&100),
            "want must go on the offering link"
        );
        assert_eq!(want_links.len(), 2, "want must go on one other link too");
        assert!(want_links.contains(&200));
        // Both links are credited for the wants.
        assert_eq!(node.links.get(&100).unwrap().want_credits, 2);
        assert_eq!(node.links.get(&200).unwrap().want_credits, 2);
    }

    // ──────────── H-13: awaiting-record queue ────────────

    fn app_send<S: Store>(node: &mut Node<S>, to: Identifier, tsvc: &str) -> Vec<Action> {
        node.handle(Event::AppSend(AppSend {
            service: "svc".to_string(),
            mid_hint: None,
            to,
            tsvc: tsvc.to_string(),
            tmbx: b"in".to_vec(),
            fmbx: b"out".to_vec(),
            body: b"hi".to_vec(),
            exp: None,
            priority: 1,
            route: 0,
        }))
        .0
    }

    fn admit_identity<S: Store>(node: &mut Node<S>, id: &Identity, at: u64) -> Vec<Action> {
        admit_kel(node, &id.kel, at);
        let record = build_record(
            id.kel.events().to_vec(),
            1,
            Scope::Wan,
            &id.signing_seed,
            &id.channel_seed,
        );
        node.admit_record(at, 999, &record.encode())
    }

    #[test]
    fn send_to_unknown_record_queues_and_sends_want() {
        let cfg = Config {
            snow_per_min: 0.0,
            awaiting_record_grace_secs: 600,
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let recipient = Identity::from_seed(&[0xB1; 32]);
        link_up(&mut node, 100, recipient.id(), 1_000);
        link_up(&mut node, 200, Identifier::from_bytes([0x33; 32]), 1_000);
        let actions = app_send(&mut node, recipient.id(), "svc");
        // Queued, not failed.
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_QUEUED,
                ..
            }
        )));
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_FAILED,
                ..
            }
        )));
        // No dispatch attempt yet.
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::SendFrame {
                frame: Frame::Offer(_),
                ..
            }
        )));
        // A want for both scopes went out on both links.
        let mut want_links = Vec::new();
        for a in &actions {
            if let Action::SendFrame {
                link,
                frame: Frame::Want(w),
                ..
            } = a
            {
                assert!(w.wants.iter().all(|r| r.id == recipient.id()));
                let scopes: Vec<u8> = w.wants.iter().map(|r| r.scope).collect();
                assert_eq!(scopes, vec![0, 1]);
                want_links.push(*link);
            }
        }
        want_links.sort_unstable();
        assert_eq!(want_links, vec![100, 200]);
        // The message is persisted as queued with the grace deadline.
        let rows: Vec<_> = node
            .store
            .outbound_all()
            .unwrap()
            .into_iter()
            .map(outbound_from_store)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, OutboundState::Queued);
        assert_eq!(rows[0].next_attempt, 1_000 + 600_000);
    }

    #[test]
    fn send_to_unknown_record_fails_with_err_no_record_after_grace() {
        let cfg = Config {
            snow_per_min: 0.0,
            awaiting_record_grace_secs: 5,
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let recipient = Identifier::from_bytes([0xB1; 32]);
        link_up(&mut node, 100, recipient, 1_000);
        let actions = app_send(&mut node, recipient, "svc");
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_QUEUED,
                ..
            }
        )));
        // Before the grace expires: no failure.
        let (actions, _) = node.handle(Event::Tick { at: 5_999 });
        assert!(!actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_FAILED,
                ..
            }
        )));
        // After the grace expires: failed with ERR_NO_RECORD.
        let (actions, _) = node.handle(Event::Tick { at: 6_001 });
        let failed = actions.iter().find_map(|a| match a {
            Action::Status { status, detail, .. } if *status == local::MSG_STATUS_FAILED => {
                Some(*detail)
            }
            _ => None,
        });
        assert_eq!(failed, Some(Some(ERR_NO_RECORD)));
        let rows = node.store.outbound_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, OutboundState::Failed);
    }

    #[test]
    fn send_to_unknown_record_dispatches_when_record_arrives() {
        let cfg = Config {
            snow_per_min: 0.0,
            awaiting_record_grace_secs: 600,
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let recipient = Identity::from_seed(&[0xB1; 32]);
        link_up(&mut node, 100, recipient.id(), 1_000);
        let actions = app_send(&mut node, recipient.id(), "svc");
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Status {
                status: local::MSG_STATUS_QUEUED,
                ..
            }
        )));
        // The record arrives: the queued message must become dispatchable.
        let actions = admit_identity(&mut node, &recipient, 1_001);
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Offer(_),
                    ..
                }
            )),
            "expected the queued message to be dispatched once the record arrives, got {actions:?}"
        );
        let rows = node.store.outbound_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, OutboundState::InFlight);
    }

    #[test]
    fn awaiting_record_message_survives_restart() {
        let dir = std::env::temp_dir().join(format!(
            "lattice-awaiting-record-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.redb");
        let recipient = Identity::from_seed(&[0xB1; 32]).id();
        let cfg = || Config {
            snow_per_min: 0.0,
            awaiting_record_grace_secs: 600,
            ..Config::default()
        };
        {
            let store = lattice_store::RedbStore::open(&path).unwrap();
            let mut node = Node::new(cfg(), Identity::from_seed(&[0xA5; 32]), store, 1_000)
                .expect("node construction");
            link_up(&mut node, 100, recipient, 1_000);
            let actions = app_send(&mut node, recipient, "svc");
            assert!(actions.iter().any(|a| matches!(
                a,
                Action::Status {
                    status: local::MSG_STATUS_QUEUED,
                    ..
                }
            )));
        }
        {
            let store = lattice_store::RedbStore::open(&path).unwrap();
            let mut node = Node::new(cfg(), Identity::from_seed(&[0xA5; 32]), store, 1_500)
                .expect("node construction");
            // The message is still queued, not failed, across the restart.
            let rows: Vec<_> = node
                .store
                .outbound_all()
                .unwrap()
                .into_iter()
                .map(outbound_from_store)
                .collect();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].state, OutboundState::Queued);
            assert_eq!(rows[0].next_attempt, 1_000 + 600_000);
            // Admitting the record dispatches the message.
            link_up(&mut node, 100, recipient, 1_500);
            let recipient_identity = Identity::from_seed(&[0xB1; 32]);
            let actions = admit_identity(&mut node, &recipient_identity, 1_500);
            assert!(
                actions.iter().any(|a| matches!(
                    a,
                    Action::SendFrame {
                        frame: Frame::Offer(_),
                        ..
                    }
                )),
                "expected the queued message to be dispatched after restart, got {actions:?}"
            );
            let rows = node.store.outbound_all().unwrap();
            assert_eq!(rows[0].state, OutboundState::InFlight);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ──────────── H-14: per-service inbox reservations ────────────

    fn inbox_node(services: &[&str], reservation: u64, global_cap: u64) -> Node<MemStore> {
        let cfg = Config {
            snow_per_min: 0.0,
            services: services.iter().map(|s| s.to_string()).collect(),
            inbox_max_deliveries: reservation,
            inbox_max_total: global_cap,
            ..Config::default()
        };
        Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction")
    }

    fn sealed_to_node_svc(
        node: &Node<MemStore>,
        sender: &Identity,
        mid_byte: u8,
        tsvc: &str,
        now: u64,
    ) -> Vec<u8> {
        Message::build(BuildParams {
            envelope: Envelope {
                kind: KIND_MESSAGE,
                mid: MessageId::from_bytes([mid_byte; 16]),
                from: sender.id(),
                fsvc: "svc".into(),
                fmbx: b"out".to_vec(),
                tsvc: tsvc.into(),
                tmbx: b"in".to_vec(),
                created: now,
                body: Some(b"hi".to_vec()),
                reference: None,
                reason: None,
                sig: Signature::from_bytes([0; 64]),
            },
            sender_seed: &sender.signing_seed,
            recipient_ek: &node.identity.xwing_public,
            real_dst: node.own_id,
            leg: LegId::from_bytes([mid_byte; 16]),
            exp: now + 10_000,
            gateway: None,
            waypoint: None,
            entropy: &mut |b: &mut [u8; 64]| b.fill(0x5A),
        })
        .expect("message builds")
    }

    fn offer_to(
        node: &mut Node<MemStore>,
        sender: &Identity,
        mid_byte: u8,
        tsvc: &str,
        at: u64,
    ) -> Vec<Action> {
        let wire = sealed_to_node_svc(node, sender, mid_byte, tsvc, at);
        node.handle(Event::Frame {
            at,
            link: 100,
            frame: Frame::Offer(OfferFrame { message: wire }),
            bucket: None,
        })
        .0
    }

    fn is_busy(actions: &[Action]) -> bool {
        actions.iter().any(|a| {
            matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Custody(c),
                    ..
                } if c.result == CUSTODY_BUSY
            )
        })
    }

    fn is_delivered(actions: &[Action]) -> bool {
        actions.iter().any(|a| matches!(a, Action::Deliver { .. }))
    }

    #[test]
    fn service_over_reservation_gets_busy_while_others_accept() {
        let mut node = inbox_node(&["svc", "other"], 1, 4096);
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        // First message to "svc" fills its reservation.
        let a = offer_to(&mut node, &sender, 0x01, "svc", 1_000);
        assert!(is_delivered(&a), "first message must be delivered: {a:?}");
        // Second message to "svc" is over the reservation: busy.
        let a = offer_to(&mut node, &sender, 0x02, "svc", 1_001);
        assert!(is_busy(&a), "over-reservation service must get busy: {a:?}");
        assert!(!is_delivered(&a));
        // A different service still accepts.
        let a = offer_to(&mut node, &sender, 0x03, "other", 1_002);
        assert!(is_delivered(&a), "other service must still accept: {a:?}");
    }

    #[test]
    fn global_backstop_trips_only_when_reservations_exceed_it() {
        // Three services, reservation 1 each: the reservations sum to 3.
        // With a global cap of 2 the reservations over-commit memory, so
        // the backstop is armed and refuses once the total reaches 2 —
        // even a service under its own reservation.
        let mut node = inbox_node(&["a", "b", "c"], 1, 2);
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let a = offer_to(&mut node, &sender, 0x01, "a", 1_000);
        assert!(is_delivered(&a));
        let b = offer_to(&mut node, &sender, 0x02, "b", 1_001);
        assert!(is_delivered(&b));
        // Total is now 2 = the cap; "c" is under its reservation but the
        // backstop is armed (sum of reservations 3 > cap 2).
        let c = offer_to(&mut node, &sender, 0x03, "c", 1_002);
        assert!(is_busy(&c), "armed backstop must refuse: {c:?}");
        // Same shape, but the cap equals the sum of reservations: the
        // backstop is not armed and "c" is admitted.
        let mut node = inbox_node(&["a", "b", "c"], 1, 3);
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let a = offer_to(&mut node, &sender, 0x01, "a", 1_000);
        assert!(is_delivered(&a));
        let b = offer_to(&mut node, &sender, 0x02, "b", 1_001);
        assert!(is_delivered(&b));
        let c = offer_to(&mut node, &sender, 0x03, "c", 1_002);
        assert!(
            is_delivered(&c),
            "backstop must not trip when the sum of reservations does not exceed it: {c:?}"
        );
    }

    #[test]
    fn unknown_service_is_still_refused() {
        let mut node = inbox_node(&["svc"], 1024, 4096);
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let actions = offer_to(&mut node, &sender, 0x01, "nope", 1_000);
        assert!(!is_delivered(&actions));
        assert_eq!(node.store.inbox_len("nope").unwrap(), 0);
        // A negative receipt is sent instead.
        assert!(
            actions.iter().any(|a| matches!(
                a,
                Action::SendFrame {
                    frame: Frame::Offer(_),
                    ..
                }
            )),
            "expected a negative receipt offer, got {actions:?}"
        );
        let rows = node.store.outbound_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].envelope.kind, KIND_NEGATIVE_RECEIPT);
    }

    // ──────────── H-15 / R-18: receipts are cheap ────────────

    /// Offer a message to the node and return the receipt it sends back
    /// (wire bytes), if any.
    fn offer_and_take_receipt(
        node: &mut Node<MemStore>,
        sender: &Identity,
        mid_byte: u8,
        tsvc: &str,
        at: u64,
    ) -> (Vec<Action>, Option<Vec<u8>>) {
        let actions = offer_to(node, sender, mid_byte, tsvc, at);
        let receipt = actions.iter().find_map(|a| match a {
            Action::SendFrame {
                frame: Frame::Offer(o),
                ..
            } => Some(o.message.clone()),
            _ => None,
        });
        (actions, receipt)
    }

    #[test]
    fn receipt_is_dropped_on_first_accept_with_no_status() {
        let cfg = Config {
            snow_per_min: 0.0,
            services: vec!["svc".to_string()],
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        let (actions, receipt) = offer_and_take_receipt(&mut node, &sender, 0x01, "svc", 1_000);
        assert!(is_delivered(&actions));
        let receipt_wire = receipt.expect("node must send a receipt");
        let parsed = Message::parse(&receipt_wire, 1).expect("receipt parses");
        let receipt_leg = parsed.header.leg;
        // The receipt is the only outbound row; read its mid and kind from
        // the store (the envelope is stored unsealed).
        let rows = node.store.outbound_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].envelope.kind, KIND_RECEIPT);
        let receipt_mid = rows[0].mid;
        // The receipt is in flight with no receipt deadline.
        let stored = node
            .store
            .outbound_get(&receipt_mid)
            .unwrap()
            .expect("receipt must be stored");
        assert_eq!(stored.receipt_deadline, None);
        // The first hop accepts the receipt.
        let (actions, _) = node.handle(Event::Frame {
            at: 1_001,
            link: 100,
            frame: custody_frame(receipt_leg, CUSTODY_ACCEPTED),
            bucket: None,
        });
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Status { .. })),
            "a receipt must never emit a status event: {actions:?}"
        );
        assert!(
            node.store.outbound_get(&receipt_mid).unwrap().is_none(),
            "the receipt must be dropped from the outbound table on ACCEPTED"
        );
        assert!(
            node.store.status_get(&receipt_mid).unwrap().is_none(),
            "the receipt must not get a status row"
        );
    }

    #[test]
    fn negative_receipt_is_dropped_on_first_accept_with_no_status() {
        let cfg = Config {
            snow_per_min: 0.0,
            services: vec!["svc".to_string()],
            ..Config::default()
        };
        let mut node = Node::new(
            cfg,
            Identity::from_seed(&[0xA5; 32]),
            MemStore::new(),
            1_000,
        )
        .expect("node construction");
        let sender = Identity::from_seed(&[0x5A; 32]);
        admit_sender(&mut node, &sender, 1_000);
        link_up(&mut node, 100, sender.id(), 1_000);
        // Unknown service: the node answers with a negative receipt.
        let (actions, receipt) = offer_and_take_receipt(&mut node, &sender, 0x01, "nope", 1_000);
        assert!(!is_delivered(&actions));
        let receipt_wire = receipt.expect("node must send a negative receipt");
        let parsed = Message::parse(&receipt_wire, 1).expect("receipt parses");
        let receipt_leg = parsed.header.leg;
        let rows = node.store.outbound_all().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].envelope.kind, KIND_NEGATIVE_RECEIPT);
        let receipt_mid = rows[0].mid;
        let (actions, _) = node.handle(Event::Frame {
            at: 1_001,
            link: 100,
            frame: custody_frame(receipt_leg, CUSTODY_ACCEPTED),
            bucket: None,
        });
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Status { .. })),
            "a negative receipt must never emit a status event: {actions:?}"
        );
        assert!(node.store.outbound_get(&receipt_mid).unwrap().is_none());
        assert!(node.store.status_get(&receipt_mid).unwrap().is_none());
    }

    #[test]
    fn receipt_refusal_drops_it_without_status() {
        let mut node = test_node();
        let recipient = Identifier::from_bytes([0xB1; 32]);
        let mid = MessageId::from_bytes([0x66; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::InFlight);
        msg.envelope.kind = KIND_RECEIPT;
        msg.receipt_deadline = None;
        msg.exp = 10_000;
        node.store_outbound(&msg);
        let leg = LegId::from_bytes([0x77; 16]);
        node.pending.insert(
            leg,
            PendingOffer {
                origin: PendingOrigin::Outbound { mid },
                sent_at: 1_000,
                excluded: Vec::new(),
                link: 100,
            },
        );
        let (actions, _) = node.handle(Event::Frame {
            at: 1_001,
            link: 100,
            frame: custody_frame(leg, CUSTODY_REFUSED),
            bucket: None,
        });
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Status { .. })),
            "a refused receipt must not emit a status event: {actions:?}"
        );
        assert!(node.store.outbound_get(&mid).unwrap().is_none());
        assert!(node.store.status_get(&mid).unwrap().is_none());
    }

    // ──────────── Group commit (handle_batch) ────────────

    fn send_event(to: Identifier) -> Event {
        Event::AppSend(AppSend {
            service: "svc".to_string(),
            mid_hint: None,
            to,
            tsvc: "svc".to_string(),
            tmbx: b"in".to_vec(),
            fmbx: b"out".to_vec(),
            body: b"hi".to_vec(),
            exp: None,
            priority: 1,
            route: 0,
        })
    }

    #[test]
    fn handle_batch_commits_once_for_many_events() {
        let mut node = test_node();
        let to = Identifier::from_bytes([0xA1; 32]);
        let before = node.store.commit_count();
        let events = vec![
            send_event(to),
            send_event(to),
            send_event(to),
            Event::Tick { at: 2_000 },
        ];
        let (actions, _diags) = node.handle_batch(events).expect("batch commits");
        assert_eq!(node.store.commit_count(), before + 1);
        let queued = actions
            .iter()
            .filter(|a| matches!(a, Action::Status { status, .. } if *status == local::MSG_STATUS_QUEUED))
            .count();
        assert_eq!(queued, 3);
    }

    #[test]
    fn handle_batch_commit_failure_releases_no_actions() {
        let mut node = test_node();
        let to = Identifier::from_bytes([0xA2; 32]);
        node.store.fail_next_commit();
        let result = node.handle_batch(vec![send_event(to)]);
        assert!(
            result.is_err(),
            "a failed commit must surface as an error, not as released actions"
        );
        // No action was released, and nothing the batch staged survived:
        // the outbound row and the QUEUED status are gone with the batch.
        assert!(node.store.outbound_all().unwrap().is_empty());
        // The store is usable again afterwards.
        let (actions, _) = node
            .handle_batch(vec![send_event(to)])
            .expect("a later batch commits");
        assert!(actions.iter().any(
            |a| matches!(a, Action::Status { status, .. } if *status == local::MSG_STATUS_QUEUED)
        ));
    }

    #[test]
    fn handle_batch_matches_sequential_handle() {
        // A batch of events produces the same actions as handling them
        // one by one (modulo the commit boundary).
        let to = Identifier::from_bytes([0xA3; 32]);
        let mut batched = test_node();
        let mut sequential = test_node();
        let events = vec![send_event(to), send_event(to), Event::Tick { at: 2_000 }];
        let (batch_actions, _) = batched.handle_batch(events.clone()).expect("batch commits");
        let mut seq_actions = Vec::new();
        for event in events {
            let (a, _) = sequential.handle(event);
            seq_actions.extend(a);
        }
        let key = |a: &Action| match a {
            Action::Status { mid, status, .. } => (0, mid.as_bytes().to_vec(), *status),
            Action::Inbox { service, unread } => (1, service.as_bytes().to_vec(), *unread),
            Action::SendFrame { .. } => (2, Vec::new(), 0),
            Action::Deliver { .. } => (3, Vec::new(), 0),
            Action::LinkBound { link, .. } => (4, link.to_be_bytes().to_vec(), 0),
            Action::Dial { peer, .. } => (5, peer.as_bytes().to_vec(), 0),
            Action::CloseLink { link } => (6, link.to_be_bytes().to_vec(), 0),
        };
        let mut b: Vec<_> = batch_actions.iter().map(key).collect();
        let mut s: Vec<_> = seq_actions.iter().map(key).collect();
        b.sort();
        s.sort();
        assert_eq!(b, s);
    }

    // ── Neighbor selection (design §5) ─────────────────────────────

    fn build_record_ep(
        kel: Vec<KeyEvent>,
        seq: u64,
        scope: Scope,
        signing_seed: &SigningSeed,
        channel_seed: &ChannelSeed,
        endpoint: &str,
        ips: &[&str],
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
                    url: endpoint.into(),
                    ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
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

    /// Admit a candidate identity's KEL and record (one endpoint).
    /// Returns the identity.
    fn admit_candidate<S: Store>(
        node: &mut Node<S>,
        seed: u8,
        scope: Scope,
        endpoint: &str,
        ips: &[&str],
        at: u64,
    ) -> Identity {
        let identity = Identity::from_seed(&[seed; 32]);
        admit_kel(node, &identity.kel, at);
        let record = build_record_ep(
            identity.kel.events().to_vec(),
            1,
            scope,
            &identity.signing_seed,
            &identity.channel_seed,
            endpoint,
            ips,
        );
        node.admit_record(at, 999, &record.encode());
        identity
    }

    fn dialed_peers(actions: &[Action]) -> Vec<Identifier> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Dial { peer, .. } => Some(*peer),
                _ => None,
            })
            .collect()
    }

    /// Link up every dialed candidate, returning peer -> link id.
    fn link_dialed<S: Store>(
        node: &mut Node<S>,
        actions: &[Action],
        identities: &[Identity],
        at: u64,
        next_link: &mut u64,
    ) -> Vec<(Identifier, u64)> {
        let mut out = Vec::new();
        for a in actions {
            if let Action::Dial { peer, .. } = a {
                let id = identities
                    .iter()
                    .find(|i| i.id() == *peer)
                    .expect("dialed peer is a known candidate");
                let ck = lattice_crypto::channel_x25519_public(&id.channel_seed);
                let link = *next_link;
                *next_link += 1;
                node.handle(Event::LinkUp {
                    at,
                    link,
                    peer: Some(*peer),
                    remote_ck: ck,
                });
                out.push((*peer, link));
            }
        }
        out
    }

    fn candidate_hash<S: Store>(node: &Node<S>, id: &Identifier) -> u64 {
        crate::neighbor::candidate_hash(&node.neighbor_salt, Scope::Wan, id)
    }

    #[test]
    fn neighbor_selection_dials_best_candidates_up_to_cap() {
        let mut node = test_node();
        let mut identities = Vec::new();
        for i in 1..=20u8 {
            identities.push(admit_candidate(
                &mut node,
                i,
                Scope::Wan,
                &format!("ws://203.0.{i}.1/"),
                &[],
                1_000,
            ));
        }
        let (actions, _) = node.handle(Event::Tick { at: 2_000 });
        let dialed = dialed_peers(&actions);
        assert_eq!(dialed.len(), 16, "cap is 16 outbound WAN links");
        // The selected set is the 16 lowest-hash candidates.
        let mut by_hash: Vec<(u64, Identifier)> = identities
            .iter()
            .map(|id| (candidate_hash(&node, &id.id()), id.id()))
            .collect();
        by_hash.sort();
        let expected: std::collections::HashSet<Identifier> =
            by_hash[..16].iter().map(|(_, id)| *id).collect();
        let actual: std::collections::HashSet<Identifier> = dialed.into_iter().collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn neighbor_selection_respects_per_group_sub_cap() {
        let mut node = test_node();
        let mut identities = Vec::new();
        // Six candidates in one /24, fourteen elsewhere.
        for i in 1..=6u8 {
            identities.push(admit_candidate(
                &mut node,
                i,
                Scope::Wan,
                &format!("ws://203.0.77.{i}/"),
                &[],
                1_000,
            ));
        }
        for i in 7..=20u8 {
            identities.push(admit_candidate(
                &mut node,
                i,
                Scope::Wan,
                &format!("ws://198.51.{i}.1/"),
                &[],
                1_000,
            ));
        }
        let (actions, _) = node.handle(Event::Tick { at: 2_000 });
        let dialed = dialed_peers(&actions);
        assert_eq!(dialed.len(), 16);
        let shared = dialed
            .iter()
            .filter(|id| identities[..6].iter().any(|i| i.id() == **id))
            .count();
        assert!(shared <= 2, "at most 2 links per /24, got {shared}");
    }

    #[test]
    fn neighbor_selection_is_stable_for_same_salt() {
        let run = || {
            let mut node = test_node();
            let mut identities = Vec::new();
            for i in 1..=20u8 {
                identities.push(admit_candidate(
                    &mut node,
                    i,
                    Scope::Wan,
                    &format!("ws://203.0.{i}.1/"),
                    &[],
                    1_000,
                ));
            }
            let (actions, _) = node.handle(Event::Tick { at: 2_000 });
            let mut dialed = dialed_peers(&actions);
            dialed.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            dialed
        };
        assert_eq!(run(), run());
    }

    /// Fill the node to the WAN cap and return the linked (peer, link)
    /// pairs plus the identities.
    fn fill_to_cap(node: &mut Node<MemStore>, at: u64) -> (Vec<(Identifier, u64)>, Vec<Identity>) {
        let mut identities = Vec::new();
        for i in 1..=16u8 {
            identities.push(admit_candidate(
                node,
                i,
                Scope::Wan,
                &format!("ws://203.0.{i}.1/"),
                &[],
                at,
            ));
        }
        let (actions, _) = node.handle(Event::Tick { at: at + 1_000 });
        let mut next_link = 1_000;
        let linked = link_dialed(node, &actions, &identities, at + 1_000, &mut next_link);
        assert_eq!(linked.len(), 16);
        (linked, identities)
    }

    /// Find a seed whose candidate hash is below `ceiling`.
    fn seed_below(node: &Node<MemStore>, ceiling: u64) -> u8 {
        for seed in 100..=250u8 {
            let id = Identity::from_seed(&[seed; 32]).id();
            if candidate_hash(node, &id) < ceiling {
                return seed;
            }
        }
        panic!("no seed below the ceiling");
    }

    #[test]
    fn test_before_evict_evicts_only_after_bind() {
        let mut node = test_node();
        let (linked, identities) = fill_to_cap(&mut node, 1_000);
        // The worst incumbent (highest hash) is the eviction target.
        let worst = linked
            .iter()
            .max_by_key(|(peer, _)| candidate_hash(&node, peer))
            .copied()
            .unwrap();
        let worst_hash = candidate_hash(&node, &worst.0);
        // A strictly better candidate appears.
        let seed = seed_below(&node, worst_hash);
        let better = admit_candidate(
            &mut node,
            seed,
            Scope::Wan,
            &format!("ws://203.0.200.{seed}/"),
            &[],
            5_000,
        );
        let (actions, _) = node.handle(Event::Tick { at: 6_000 });
        let eviction = actions.iter().find_map(|a| match a {
            Action::Dial {
                peer,
                evict_on_success,
                ..
            } if *peer == better.id() => evict_on_success.map(|l| (*peer, l)),
            _ => None,
        });
        let (dialed_peer, incumbent) =
            eviction.expect("a better candidate at cap must be dialed with an eviction target");
        assert_eq!(incumbent, worst.1);
        assert_eq!(dialed_peer, better.id());
        // The candidate binds: the incumbent is evicted.
        let ck = lattice_crypto::channel_x25519_public(&better.channel_seed);
        let (actions, _) = node.handle(Event::LinkUp {
            at: 6_100,
            link: 9_000,
            peer: Some(better.id()),
            remote_ck: ck,
        });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::CloseLink { link } if *link == incumbent)),
            "the incumbent must be closed once the candidate binds: {actions:?}"
        );
        let _ = identities;
    }

    #[test]
    fn test_before_evict_failed_dial_keeps_incumbent() {
        let mut node = test_node();
        let (linked, _) = fill_to_cap(&mut node, 1_000);
        let worst = linked
            .iter()
            .max_by_key(|(peer, _)| candidate_hash(&node, peer))
            .copied()
            .unwrap();
        let worst_hash = candidate_hash(&node, &worst.0);
        let seed = seed_below(&node, worst_hash);
        let better = admit_candidate(
            &mut node,
            seed,
            Scope::Wan,
            &format!("ws://203.0.200.{seed}/"),
            &[],
            5_000,
        );
        let (actions, _) = node.handle(Event::Tick { at: 6_000 });
        assert!(actions.iter().any(|a| matches!(
            a,
            Action::Dial { peer, evict_on_success: Some(_), .. } if *peer == better.id()
        )));
        // The dial fails: the incumbent must survive.
        let (actions, _) = node.handle(Event::DialFailed {
            at: 6_100,
            peer: better.id(),
        });
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::CloseLink { .. })),
            "a failed dial must not evict the incumbent"
        );
        assert!(
            node.links.contains_key(&worst.1),
            "the incumbent link must still be present"
        );
    }

    #[test]
    fn anchors_are_designated_and_never_evicted() {
        let mut node = test_node();
        let (linked, _) = fill_to_cap(&mut node, 1_000);
        // A tick designates anchors from the linked candidates.
        let _ = node.handle(Event::Tick { at: 2_000 });
        let anchors: Vec<Identifier> = node
            .saved_peers
            .values()
            .filter(|p| p.anchor)
            .map(|p| p.id)
            .collect();
        assert_eq!(anchors.len(), 3, "three anchors are designated");
        // A better candidate appears; the eviction target must not be an anchor.
        let non_anchor_worst = linked
            .iter()
            .filter(|(peer, _)| !anchors.contains(peer))
            .max_by_key(|(peer, _)| candidate_hash(&node, peer))
            .copied()
            .unwrap();
        let worst_hash = candidate_hash(&node, &non_anchor_worst.0);
        let seed = seed_below(&node, worst_hash);
        let better = admit_candidate(
            &mut node,
            seed,
            Scope::Wan,
            &format!("ws://203.0.200.{seed}/"),
            &[],
            5_000,
        );
        let (actions, _) = node.handle(Event::Tick { at: 6_000 });
        let evicted = actions.iter().find_map(|a| match a {
            Action::Dial {
                peer,
                evict_on_success: Some(link),
                ..
            } if *peer == better.id() => Some(*link),
            _ => None,
        });
        let evicted = evicted.expect("a better candidate must be dialed for eviction");
        let evicted_peer = linked.iter().find(|(_, l)| *l == evicted).unwrap().0;
        assert!(
            !anchors.contains(&evicted_peer),
            "an anchor must never be the eviction target"
        );
    }

    #[test]
    fn saved_peers_are_persisted_and_redialed_at_boot() {
        let dir = std::env::temp_dir().join(format!(
            "lattice-saved-peers-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store_path = dir.join("node.redb");
        let peer_id;
        {
            let store = lattice_store::RedbStore::open(&store_path).unwrap();
            let cfg = Config {
                snow_per_min: 0.0,
                ..Config::default()
            };
            let mut node = Node::new(cfg, Identity::from_seed(&[0xA5; 32]), store, 1_000)
                .expect("node construction");
            let candidate =
                admit_candidate(&mut node, 7, Scope::Wan, "ws://203.0.201.7/", &[], 1_000);
            peer_id = candidate.id();
            let (actions, _) = node.handle(Event::Tick { at: 2_000 });
            let mut next_link = 1;
            let _ = link_dialed(&mut node, &actions, &[candidate], 2_000, &mut next_link);
            // The link bound; the peer must be in the saved-peer table.
            let saved = node.store.saved_peer_all().unwrap();
            assert!(
                saved.iter().any(|p| p.id == peer_id),
                "the bound peer must be saved: {saved:?}"
            );
        }
        // A fresh node over the same store re-dials the saved peer at boot.
        let store = lattice_store::RedbStore::open(&store_path).unwrap();
        let cfg = Config {
            snow_per_min: 0.0,
            ..Config::default()
        };
        let mut node = Node::new(cfg, Identity::from_seed(&[0xA5; 32]), store, 10_000)
            .expect("node construction");
        let actions = node.startup_dials();
        let dialed = dialed_peers(&actions);
        assert!(
            dialed.contains(&peer_id),
            "the saved peer must be re-dialed at boot: {dialed:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dial_failure_backs_off_and_recovers() {
        let mut node = test_node();
        let candidate = admit_candidate(&mut node, 7, Scope::Wan, "ws://203.0.201.7/", &[], 1_000);
        let (actions, _) = node.handle(Event::Tick { at: 2_000 });
        assert_eq!(dialed_peers(&actions), vec![candidate.id()]);
        // The dial fails: no immediate redial.
        let (actions, _) = node.handle(Event::DialFailed {
            at: 2_100,
            peer: candidate.id(),
        });
        assert!(dialed_peers(&actions).is_empty());
        // Still in backoff shortly after.
        let (actions, _) = node.handle(Event::Tick { at: 3_000 });
        assert!(dialed_peers(&actions).is_empty());
        // After the backoff expires the candidate is dialed again.
        let (actions, _) = node.handle(Event::Tick { at: 2_100 + 5_001 });
        assert_eq!(dialed_peers(&actions), vec![candidate.id()]);
    }

    #[test]
    fn receipt_expiry_drops_it_without_status() {
        let mut node = test_node();
        let recipient = Identifier::from_bytes([0xB1; 32]);
        let mid = MessageId::from_bytes([0x67; 16]);
        let mut msg = outbound(mid, recipient, OutboundState::InFlight);
        msg.envelope.kind = KIND_RECEIPT;
        msg.receipt_deadline = None;
        msg.exp = 2_000; // expires at t = 2s
        node.store_outbound(&msg);
        let (actions, _) = node.handle(Event::Tick { at: 3_000 });
        assert!(
            !actions.iter().any(|a| matches!(a, Action::Status { .. })),
            "an expired receipt must not emit a status event: {actions:?}"
        );
        assert!(node.store.outbound_get(&mid).unwrap().is_none());
        assert!(node.store.status_get(&mid).unwrap().is_none());
    }
}
