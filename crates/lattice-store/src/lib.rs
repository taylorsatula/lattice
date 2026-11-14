//! Lattice storage: the Store trait, an in-memory implementation for the
//! simulator, and (later) a redb implementation for the daemon.
//!
//! The trait is the contract the core depends on; redb slots in behind it.
//! All time is passed in by the caller (Unix seconds); the store never
//! reads a clock.

#![forbid(unsafe_code)]

mod mem;
mod redb_store;

pub use mem::MemStore;
pub use redb_store::RedbStore;

use lattice_proto::record::Scope;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store full")]
    Full,
    #[error("not found")]
    NotFound,
    #[error("backend: {0}")]
    Backend(String),
}

/// Stored record as returned by `record_all`: (id, scope, bytes, received_at).
pub type StoredRecord = ([u8; 32], Scope, Vec<u8>, u64);

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OutboundMessage {
    pub mid: [u8; 16],
    /// Final recipient (never the gateway).
    pub recipient: [u8; 32],
    /// The sealed envelope, kept so retries can rebuild the message with
    /// fresh leg ids and waypoints without re-encrypting.
    pub envelope: lattice_proto::message::Envelope,
    /// 0-3; higher is more urgent. Orders the queue only; never sent.
    pub priority: u8,
    /// Expiry as Unix seconds.
    pub exp: u64,
    pub state: OutboundState,
    /// Waypoints already used, so retries can avoid them.
    pub waypoints_tried: Vec<[u8; 32]>,
    /// Receipt deadline; on expiry the message is retried via a fresh waypoint or failed.
    pub receipt_deadline: Option<u64>,
    pub attempts: u32,
    /// Next allowed attempt time (backoff).
    pub next_attempt: u64,
    /// 0 = default routing (waypoint share decides), 1 = force waypoint, 2 = force direct.
    #[serde(default)]
    pub route: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutboundState {
    Queued,
    InFlight,
    Delivered,
    Failed,
    Expired,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustodyEntry {
    pub leg: [u8; 16],
    pub message: Vec<u8>,
    pub upstream: u64, // link id of the neighbor we accepted from; 0 = locally originated
    pub destination: [u8; 32],
    pub class: u8,
    pub exp: u64,
    pub lease_until: u64,
    /// Neighbors that already answered busy/already-have for this leg.
    /// Neighbors that already replied busy/already-have for this leg,
    /// with the unix time after which they may be retried.
    pub excluded: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InboxEntry {
    pub delivery_id: [u8; 16],
    pub mid: [u8; 16],
    pub from: [u8; 32],
    pub fsvc: String,
    pub fmbx: Vec<u8>,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub received: u64,
}

/// One custody share counter per (destination, upstream link).
#[derive(Clone, Debug, Default)]
pub struct ShareCounters {
    pub held_bytes: u64,
}

pub trait Store {
    // peer records (raw bytes + received time), keyed by (id, scope)
    fn record_get(&self, id: &[u8; 32], scope: Scope)
    -> Result<Option<(Vec<u8>, u64)>, StoreError>;
    fn record_put(
        &mut self,
        id: &[u8; 32],
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError>;
    fn record_remove(&mut self, id: &[u8; 32], scope: Scope) -> Result<(), StoreError>;
    fn record_all(&self) -> Result<Vec<StoredRecord>, StoreError>;
    fn record_count(&self) -> Result<usize, StoreError>;

    // KEL heads (kept one year beyond last sighting by the caller)
    fn kel_head(&self, id: &[u8; 32]) -> Result<Option<(u64, [u8; 32], u64)>, StoreError>; // seq, commitment, seen
    fn kel_head_put(
        &mut self,
        id: &[u8; 32],
        seq: u64,
        commitment: [u8; 32],
        seen: u64,
    ) -> Result<(), StoreError>;

    // saved peer addresses, kept beyond record expiry
    fn peer_save(&mut self, id: &[u8; 32], address: &str) -> Result<(), StoreError>;
    fn peer_saved(&self) -> Result<Vec<([u8; 32], String)>, StoreError>;

    // outbound queue
    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError>;
    fn outbound_get(&self, mid: &[u8; 16]) -> Result<Option<OutboundMessage>, StoreError>;
    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError>;
    fn outbound_due(&self, now: u64) -> Result<Vec<OutboundMessage>, StoreError>;
    fn outbound_all(&self) -> Result<Vec<OutboundMessage>, StoreError>;

    // custody
    fn custody_put(&mut self, entry: CustodyEntry) -> Result<(), StoreError>;
    fn custody_get(&self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError>;
    fn custody_remove(&mut self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError>;
    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError>;
    fn custody_bytes(&self) -> Result<u64, StoreError>;

    // fair-share accounting per (destination, upstream link)
    fn share_add(&mut self, dest: &[u8; 32], upstream: u64, bytes: i64) -> Result<u64, StoreError>;
    fn share_get(&self, dest: &[u8; 32], upstream: u64) -> Result<u64, StoreError>;

    // dedup
    fn seen_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError>;
    fn seen_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError>;
    fn delivered_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError>;
    fn delivered_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError>;
    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError>;

    // inbox (per service)
    fn inbox_push(&mut self, service: &str, entry: InboxEntry) -> Result<(), StoreError>;
    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError>;
    fn inbox_ack(&mut self, service: &str, delivery_ids: &[[u8; 16]]) -> Result<usize, StoreError>;
    fn inbox_len(&self, service: &str) -> Result<u64, StoreError>;

    // per-service delivery status, for the local API
    fn status_set(
        &mut self,
        mid: &[u8; 16],
        status: u64,
        detail: Option<u64>,
    ) -> Result<(), StoreError>;
    fn status_get(&self, mid: &[u8; 16]) -> Result<Option<(u64, Option<u64>)>, StoreError>;

    // wary list observations: (identifier, source range tag) with expiry
    fn wary_add(&mut self, id: &[u8; 32], source_range: u64, exp: u64) -> Result<(), StoreError>;
    fn wary_ranges(&self, id: &[u8; 32], now: u64) -> Result<Vec<u64>, StoreError>;
    fn wary_sweep(&mut self, now: u64) -> Result<(), StoreError>;

    // transmission counters used for snow sizing
    fn size_bucket_sample(&mut self, bucket: u8);
    fn size_bucket_counts(&self) -> [u64; 3];
}
