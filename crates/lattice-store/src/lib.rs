//! Lattice storage: the Store trait and its two implementations — an
//! in-memory store for the simulator and tests (`MemStore`), and a redb-backed
//! store for the daemon (`RedbStore`).
//!
//! The trait is the contract the core depends on. The two backends are
//! contract-tested for equivalence. All time is passed in by the caller
//! (Unix seconds); the store never reads a clock.
//!
//! Batching: [`Store::begin_batch`] / [`Store::commit_batch`] /
//! [`Store::abort_batch`] let a caller group many operations into one
//! atomic, durable commit (the daemon's group commit). Outside a batch,
//! every write is its own durable transaction, exactly as before.

#![forbid(unsafe_code)]

mod mem;
mod redb_store;
mod row_codec;

pub use mem::MemStore;
pub use redb_store::RedbStore;

use lattice_proto::local::{DrainState, MessageStatus};
use lattice_proto::record::Scope;
use std::net::IpAddr;

use lattice_types::{
    ChannelPublicKey, Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId,
};

/// How long a status row is kept before the retention sweep drops it.
/// Matches the 7-day outbound retention: a status is only useful while
/// the sender might still act on it.
pub const STATUS_TTL_SECS: u64 = 7 * 24 * 3600;

/// Number of buffer-class slots tracked per custody row: two leg phases
/// (see `CustodyEntry::class`) times 16 classes per phase.
pub const CLASS_SLOTS: usize = 32;

/// Base for link ids allocated by [`Store::alloc_link_id`].
///
/// Pre-upgrade daemons numbered links from 1, so custody rows persisted
/// before the upgrade may carry small `upstream` values. Starting the
/// persisted counter at 2^32 guarantees a freshly allocated id never
/// aliases an id recorded before the upgrade.
pub const LINK_ID_BASE: u64 = 1 << 32;

/// Error returned by every store operation.
///
/// `Backend` preserves the underlying backend error as `source` and names the
/// store operation (`op`, e.g. `"record_get"`) that failed, so an operator can
/// tell which operation against which backend failed and why.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The storage backend rejected an operation. `op` names the store
    /// operation; `source` is the underlying error.
    #[error("{op}: {source}")]
    Backend {
        op: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// A value failed to (de)serialize or re-validate on read. `context`
    /// names the value being encoded, decoded or validated (e.g. `"decode
    /// custody entry"`).
    #[error("{context}: {source}")]
    Codec {
        context: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// An internal counter would overflow.
    #[error("counter {0} overflow")]
    CounterOverflow(String),
    /// An internal counter would underflow.
    #[error("counter {0} underflow")]
    CounterUnderflow(String),
    /// A stored key or value failed a structural check (e.g. wrong length).
    #[error("corrupt {0}")]
    Corrupt(&'static str),
    /// The database schema version is newer than this build understands.
    #[error("schema version {found} is newer than this build understands ({supported})")]
    SchemaTooNew { found: u64, supported: u64 },
    /// No migration path from the on-disk schema version to this build's.
    #[error("no migration path from schema version {from}")]
    NoMigration { from: u64 },
}

impl StoreError {
    /// Fill in the operation context if the error does not already carry one.
    /// Backends call this at the transaction boundary so errors created deep
    /// inside a closure are named after the store operation that ran them.
    pub(crate) fn at(mut self, op: &'static str) -> Self {
        if let StoreError::Backend { op: slot, .. } = &mut self {
            if slot.is_empty() {
                *slot = op;
            }
        }
        self
    }
}

/// A stored record as returned by `record_all`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub id: Identifier,
    pub scope: Scope,
    /// The record bytes exactly as received.
    pub bytes: Vec<u8>,
    /// Unix time the record was received.
    pub received: u64,
}

/// A stored record's bytes and the time they were received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordBytes {
    pub bytes: Vec<u8>,
    pub received: u64,
}

/// The KEL head this node last saw for an identity, and when.
///
/// `abandoned` is set once the head's event ends the identity (a rotation
/// with no next-key commitment). It is never cleared: no record for the
/// identifier is accepted afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KelHeadSeen {
    pub seq: u64,
    pub commitment: Commitment,
    pub seen: u64,
    pub abandoned: bool,
}

/// A peer the node has connected to, kept so it can be re-dialed at boot
/// even after its record has expired. Written when a link binds to the
/// peer; refreshed on every re-bind. `anchor` marks the few peers the
/// neighbor selection treats as anchors (never evicted).
///
/// Encoded as a CBOR map `{0: endpoint, 1: [ips], 2: saved_at, 3: anchor,
/// 4: channel_key}`; the table key is `id || scope byte`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedPeer {
    pub id: Identifier,
    pub scope: Scope,
    /// Endpoint URL from the peer's record (or the dialed endpoint).
    pub endpoint: String,
    /// Literal IPs from the record; preferred over DNS at dial time.
    pub ips: Vec<IpAddr>,
    /// The peer's channel key from its record; used for the IK dial.
    pub channel_key: ChannelPublicKey,
    /// Unix seconds when this entry was last refreshed.
    pub saved_at: u64,
    /// Anchor peers are never evicted by the neighbor selection.
    pub anchor: bool,
}

/// A neighbor excluded from custody forwarding until `until` (unix time).
///
/// Encoded as a CBOR map `{0: link, 1: until}` inside custody entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion {
    pub link: u64,
    pub until: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OutboundMessage {
    pub mid: MessageId,
    /// Final recipient (never the gateway).
    pub recipient: Identifier,
    /// The sealed envelope, kept so retries can rebuild the message with
    /// fresh leg ids and waypoints without re-encrypting.
    pub envelope: lattice_proto::message::Envelope,
    /// 0-3; higher is more urgent. Orders the queue only; never sent.
    pub priority: u8,
    /// Expiry as Unix seconds.
    pub exp: u64,
    pub state: OutboundState,
    /// Waypoints already used, so retries can avoid them.
    pub waypoints_tried: Vec<Identifier>,
    /// Receipt deadline; on expiry the message is retried via a fresh waypoint or failed.
    pub receipt_deadline: Option<u64>,
    pub attempts: u32,
    /// Next allowed attempt time (backoff).
    pub next_attempt: u64,
    /// 0 = default routing (waypoint share decides), 1 = force waypoint, 2 = force direct.
    pub route: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundState {
    Queued,
    InFlight,
    Delivered,
    Failed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyEntry {
    pub leg: LegId,
    pub message: Vec<u8>,
    pub upstream: u64, // link id of the neighbor we accepted from; 0 = locally originated
    pub destination: Identifier,
    /// Buffer-class slot: `0..16` is the second leg (no hop layer; toward
    /// the final destination), `16..32` is the first leg (hop layer present;
    /// toward the waypoint/gateway). Within a phase, the value is the
    /// distance class (0 = closest to the destination). Classes are
    /// internal; the wire never sees them.
    pub class: u8,
    pub exp: u64,
    /// Neighbors that already replied busy/already-have for this leg,
    /// with the unix time after which they may be retried.
    pub excluded: Vec<Exclusion>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxEntry {
    pub delivery_id: DeliveryId,
    pub mid: MessageId,
    pub from: Identifier,
    pub fsvc: String,
    pub fmbx: Vec<u8>,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub received: u64,
}

/// Everything that must commit atomically when a node accepts custody of a
/// message: the custody row, the fair-share debit, and the dedup marker.
/// Splitting these across transactions can strand a message (custody row
/// without a dedup marker) or leak share accounting on crash.
pub struct CustodyAccept {
    pub entry: CustodyEntry,
    pub share_dest: Identifier,
    pub share_upstream: u64,
    pub share_bytes: i64,
    pub seen_hash: Hash32,
    pub seen_exp: u64,
}

pub trait Store {
    // peer records (raw bytes + received time), keyed by (id, scope)
    fn record_get(&self, id: &Identifier, scope: Scope) -> Result<Option<RecordBytes>, StoreError>;
    fn record_put(
        &mut self,
        id: &Identifier,
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError>;
    fn record_remove(&mut self, id: &Identifier, scope: Scope) -> Result<(), StoreError>;
    fn record_all(&self) -> Result<Vec<StoredRecord>, StoreError>;
    fn record_count(&self) -> Result<usize, StoreError>;

    // KEL objects and their heads (kept one year beyond last sighting by
    // the caller). The object bytes are stored so the node can serve the
    // KEL to peers (the `kels` frame) and re-validate records after a
    // restart; the head row is the fast index for monotonicity checks,
    // reconciliation items and the abandonment flag.
    fn kel_head(&self, id: &Identifier) -> Result<Option<KelHeadSeen>, StoreError>;
    /// Store a validated KEL object and its head row, atomically.
    fn kel_put(
        &mut self,
        id: &Identifier,
        bytes: &[u8],
        head: &KelHeadSeen,
    ) -> Result<(), StoreError>;
    /// The stored KEL object bytes for `id`, if any.
    fn kel_get(&self, id: &Identifier) -> Result<Option<Vec<u8>>, StoreError>;
    /// All stored KEL heads (for reconciliation and sweeps).
    fn kel_heads_all(&self) -> Result<Vec<(Identifier, KelHeadSeen)>, StoreError>;
    /// Drop KEL heads (and their objects) last seen before `older_than`.
    /// Returns how many heads were removed.
    fn kel_sweep(&mut self, older_than: u64) -> Result<usize, StoreError>;
    /// Refresh the `seen` timestamp on a stored KEL head without touching
    /// the object. Called when a record citing the KEL is admitted, so the
    /// retention clock tracks "last record seen", not "last KEL fetched".
    fn kel_touch(&mut self, id: &Identifier, seen: u64) -> Result<(), StoreError>;

    // outbound queue
    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError>;
    fn outbound_remove(&mut self, mid: &MessageId) -> Result<(), StoreError>;
    fn outbound_get(&self, mid: &MessageId) -> Result<Option<OutboundMessage>, StoreError>;
    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError>;
    fn outbound_all(&self) -> Result<Vec<OutboundMessage>, StoreError>;

    // custody
    fn custody_accept(&mut self, accept: CustodyAccept) -> Result<(), StoreError>;
    fn custody_put(&mut self, entry: CustodyEntry) -> Result<(), StoreError>;
    fn custody_get(&self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError>;
    /// Remove a custody entry and release its share of the upstream's
    /// allowance in one transaction (custody row delete + share
    /// decrement). Returns the removed entry, if any.
    fn custody_release(&mut self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError>;
    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError>;
    fn custody_bytes(&self) -> Result<u64, StoreError>;
    /// Bytes held per buffer-class slot (see [`CLASS_SLOTS`]).
    fn custody_class_bytes(&self) -> Result<[u64; CLASS_SLOTS], StoreError>;

    // fair-share accounting per (destination, upstream link). The share
    // counters are derived from the custody rows at open (they are fully
    // derivable), so a crash can never strand one.
    fn share_add(
        &mut self,
        dest: &Identifier,
        upstream: u64,
        bytes: i64,
    ) -> Result<u64, StoreError>;
    fn share_get(&self, dest: &Identifier, upstream: u64) -> Result<u64, StoreError>;
    /// Number of upstreams holding a non-zero share for `dest`.
    fn share_upstream_count(&self, dest: &Identifier) -> Result<u64, StoreError>;

    /// Allocate a link id that is unique across restarts. Backed by a
    /// persisted counter starting at [`LINK_ID_BASE`], so an id never
    /// aliases a link id recorded in a custody row by an earlier run.
    fn alloc_link_id(&mut self) -> Result<u64, StoreError>;

    // saved peers: the neighbor set persisted across restarts, so a node
    // that was offline longer than record lifetime can still re-dial its
    // former neighbors. Keyed by (id, scope).
    fn saved_peer_put(&mut self, peer: &SavedPeer) -> Result<(), StoreError>;
    fn saved_peer_remove(&mut self, id: &Identifier, scope: Scope) -> Result<(), StoreError>;
    fn saved_peer_all(&self) -> Result<Vec<SavedPeer>, StoreError>;

    // dedup
    fn seen_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError>;
    fn seen_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError>;
    /// Mark a leg as seen but *not* held (refused or dropped). Kept apart
    /// from `seen_add` so the custody reply can distinguish ALREADY_HAVE
    /// (held) from SEEN (seen, not held).
    fn seen_unheld_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError>;
    fn seen_unheld_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError>;
    fn delivered_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError>;
    fn delivered_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError>;
    /// Drop expired dedup markers (`seen`, `seen_unheld`, `delivered`) and
    /// status rows older than [`STATUS_TTL_SECS`]. `now` is unix seconds.
    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError>;

    // inbox (per service). Entries carry their target service in `tsvc`;
    // the read-side methods filter on it.
    fn inbox_push(&mut self, entry: InboxEntry) -> Result<(), StoreError>;
    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError>;
    fn inbox_ack(
        &mut self,
        service: &str,
        delivery_ids: &[DeliveryId],
    ) -> Result<usize, StoreError>;
    fn inbox_len(&self, service: &str) -> Result<u64, StoreError>;
    /// Total undelivered entries across all services.
    fn inbox_len_total(&self) -> Result<u64, StoreError>;
    /// Drop inbox entries older than `max_age_secs` (by `received`). Returns the count dropped.
    fn inbox_sweep_expired(&mut self, max_age_secs: u64, now: u64) -> Result<u64, StoreError>;

    // per-service delivery status, for the local API. `now` is the unix
    // time (seconds) of the write; rows older than [`STATUS_TTL_SECS`]
    // are dropped by `sweep_expired`.
    fn status_set(
        &mut self,
        mid: &MessageId,
        status: u64,
        detail: Option<u64>,
        now: u64,
    ) -> Result<(), StoreError>;
    fn status_get(&self, mid: &MessageId) -> Result<Option<MessageStatus>, StoreError>;

    // transmission counters used for snow sizing
    fn size_bucket_sample(&mut self, bucket: u8) -> Result<(), StoreError>;
    fn size_bucket_counts(&self) -> Result<[u64; 4], StoreError>;

    // drain flag: persisted so a restart does not silently accept new work.
    // Backends store it as 0/1; the enum is the in-memory form.
    fn drain_get(&self) -> Result<DrainState, StoreError>;
    fn drain_set(&mut self, state: DrainState) -> Result<(), StoreError>;

    /// Begin a batch: subsequent reads and writes are staged and become
    /// durable atomically at [`Store::commit_batch`]. Reads issued during
    /// the batch observe the staged writes. If any operation fails inside
    /// the batch, the batch is poisoned: [`Store::commit_batch`] discards
    /// it and reports the error, so no staged write becomes durable.
    ///
    /// The default implementation does nothing; the in-memory store is
    /// atomic per call. Backends with a real transaction override this.
    fn begin_batch(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    /// Commit the active batch atomically. On failure the batch is
    /// discarded and the store is left as it was before the batch began.
    /// With no batch active this is a no-op.
    fn commit_batch(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    /// Discard the active batch without committing. With no batch active
    /// this is a no-op.
    fn abort_batch(&mut self) {}
}
