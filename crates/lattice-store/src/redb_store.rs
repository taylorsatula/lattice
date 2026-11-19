//! redb-backed Store. One table per logical store, schema version in `meta`.
//!
//! Durability: every write transaction commits with `Durability::Immediate`,
//! so a committed custody accept is on disk before `Ok` returns. The mem
//! backend exists for the simulator; behavior is contract-tested for
//! equivalence.
//!
//! Batching: `begin_batch` opens one write transaction that every
//! subsequent read and write joins; `commit_batch` commits it once
//! (one fsync for the whole batch) and `abort_batch` discards it. If any
//! operation fails inside a batch, the batch is poisoned and
//! `commit_batch` fails without committing, so a half-applied batch
//! never becomes durable. Outside a batch, behavior is exactly as
//! before: one transaction per write.
//!
//! Read-path validation policy: rows are CBOR bytes (see `row_codec`) and
//! are never trusted as-is. On every decode, a row is re-validated where a
//! validator exists (the outbound envelope, via `Envelope::from_value`); a
//! failed validation fails the read loudly with `StoreError::Codec`, which
//! the core surfaces on its diagnostic channel. Bounded integer fields
//! (outbound `priority` and `route`, custody `class`) are clamped to their
//! valid ranges rather than rejected. Everything else is decode-trusted:
//! if it decodes, it is accepted as-is.

use std::borrow::Borrow;
use std::cell::Cell;
use std::ops::RangeBounds;
use std::path::Path;

use redb::{
    AccessGuard, Database, Key, Range, ReadOnlyTable, ReadableTable, ReadableTableMetadata, Table,
    TableDefinition, TableStats, Value,
};

use crate::row_codec::{
    decode_custody, decode_inbox, decode_outbound, decode_status, encode_custody, encode_inbox,
    encode_outbound, encode_status,
};
use crate::*;
use lattice_proto::local::DrainState;
use lattice_proto::record::Scope;
use lattice_types::{Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId};

// redb error types convert mechanically into `StoreError::Backend` with an
// empty op; the `read`/`write`/`open` boundaries fill in the operation name
// via `StoreError::at`. Serde errors are converted at the site with a
// `Codec` context instead.
impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        StoreError::Backend {
            op: "",
            source: Box::new(e),
        }
    }
}

impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        StoreError::Backend {
            op: "",
            source: Box::new(e),
        }
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        StoreError::Backend {
            op: "",
            source: Box::new(e),
        }
    }
}

impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        StoreError::Backend {
            op: "",
            source: Box::new(e),
        }
    }
}

impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        StoreError::Backend {
            op: "",
            source: Box::new(e),
        }
    }
}

/// Attach operation context to a backend error conversion.
fn ctx<E: Into<StoreError>>(op: &'static str) -> impl FnOnce(E) -> StoreError {
    move |e| e.into().at(op)
}

/// Copy `bytes` into a fixed-size array, or report a corrupt row.
/// redb's fixed-width table types make a wrong length impossible in a
/// healthy database; this keeps a corrupt or foreign row from panicking
/// the daemon.
fn fixed<const N: usize>(bytes: &[u8], context: &'static str) -> Result<[u8; N], StoreError> {
    bytes.try_into().map_err(|_| StoreError::Corrupt(context))
}

/// A read handle over either a standalone read transaction or the active
/// batch's write transaction (which supports reads and observes the
/// batch's staged writes). Lets the read helpers serve both cases without
/// duplicating their bodies.
enum ReadTx<'a> {
    Read(&'a redb::ReadTransaction),
    Write(&'a redb::WriteTransaction),
}

impl<'a> ReadTx<'a> {
    fn open_table<K: Key + 'static, V: Value + 'static>(
        &self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<AnyTable<'_, K, V>, StoreError> {
        match self {
            ReadTx::Read(t) => Ok(AnyTable::Read(t.open_table(definition)?)),
            ReadTx::Write(t) => Ok(AnyTable::Write(t.open_table(definition)?)),
        }
    }
}

/// A table opened for reading from either transaction kind. Implements
/// the `ReadableTable` traits by delegation so the read helpers are
/// agnostic to which kind of transaction they run in.
enum AnyTable<'a, K: Key + 'static, V: Value + 'static> {
    Read(ReadOnlyTable<K, V>),
    Write(Table<'a, K, V>),
}

impl<K: Key + 'static, V: Value + 'static> ReadableTableMetadata for AnyTable<'_, K, V> {
    fn stats(&self) -> Result<TableStats, redb::StorageError> {
        match self {
            AnyTable::Read(t) => t.stats(),
            AnyTable::Write(t) => t.stats(),
        }
    }

    fn len(&self) -> Result<u64, redb::StorageError> {
        match self {
            AnyTable::Read(t) => t.len(),
            AnyTable::Write(t) => t.len(),
        }
    }
}

impl<K: Key + 'static, V: Value + 'static> ReadableTable<K, V> for AnyTable<'_, K, V> {
    fn get<'a>(
        &self,
        key: impl Borrow<K::SelfType<'a>>,
    ) -> Result<Option<AccessGuard<'_, V>>, redb::StorageError> {
        match self {
            AnyTable::Read(t) => t.get(key),
            AnyTable::Write(t) => t.get(key),
        }
    }

    fn range<'a, KR>(
        &self,
        range: impl RangeBounds<KR> + 'a,
    ) -> Result<Range<'_, K, V>, redb::StorageError>
    where
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        match self {
            AnyTable::Read(t) => t.range(range),
            AnyTable::Write(t) => t.range(range),
        }
    }

    fn first(
        &self,
    ) -> Result<Option<(AccessGuard<'_, K>, AccessGuard<'_, V>)>, redb::StorageError> {
        match self {
            AnyTable::Read(t) => t.first(),
            AnyTable::Write(t) => t.first(),
        }
    }

    fn last(&self) -> Result<Option<(AccessGuard<'_, K>, AccessGuard<'_, V>)>, redb::StorageError> {
        match self {
            AnyTable::Read(t) => t.last(),
            AnyTable::Write(t) => t.last(),
        }
    }
}

/// Open each listed table so reads never fail on a fresh database.
/// Table definitions have heterogeneous key/value types, so they cannot
/// share one array; this expands to one `open_table` call per table.
macro_rules! ensure_tables {
    ($txn:expr, $op:expr, $($table:expr),+ $(,)?) => {{
        $($txn.open_table($table).map_err(ctx($op))?;)+
    }};
}

// v2: rows are CBOR (was serde_json) and custody rows store the message
// with its wire padding stripped plus the bucket index. There is no
// migration from v1: pre-release, no deployed base, so a v1 database fails
// loudly at open (see `migrate`).
// v3: the message bucket ladder gained 4096 (2048/4096/8192/32768), so the
// bucket index stored in custody rows changed meaning. There is no
// migration from v2: pre-release, no deployed base, so a v2 database fails
// loudly at open (see `migrate`).
const SCHEMA_VERSION: u64 = 3;

const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const RECORDS: TableDefinition<[u8; 33], Vec<u8>> = TableDefinition::new("records");
const RECORD_RECV: TableDefinition<[u8; 33], u64> = TableDefinition::new("record_recv");
const KEL_HEADS: TableDefinition<[u8; 32], [u8; 49]> = TableDefinition::new("kel_heads");
const KELS: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("kels");
const OUTBOUND: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("outbound");
const CUSTODY: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("custody");
const SHARES: TableDefinition<[u8; 40], u64> = TableDefinition::new("shares");
const SEEN: TableDefinition<[u8; 32], u64> = TableDefinition::new("seen");
const SEEN_UNHELD: TableDefinition<[u8; 32], u64> = TableDefinition::new("seen_unheld");
const DELIVERED: TableDefinition<[u8; 32], u64> = TableDefinition::new("delivered");
const INBOX: TableDefinition<&[u8], Vec<u8>> = TableDefinition::new("inbox");

/// Custody buffer-class slots; `class` is clamped to `< CLASS_SLOTS` on
/// read. Two leg phases of 16 classes each share the byte.
const BUF_CLASSES: u8 = CLASS_SLOTS as u8;
const STATUS: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("status");

fn scope_byte(s: Scope) -> u8 {
    match s {
        Scope::Wan => 0,
        Scope::Hive => 1,
    }
}

fn record_key(id: &Identifier, scope: Scope) -> [u8; 33] {
    let mut k = [0u8; 33];
    k[..32].copy_from_slice(id.as_bytes());
    k[32] = scope_byte(scope);
    k
}

fn share_key(dest: &Identifier, upstream: u64) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(dest.as_bytes());
    k[32..].copy_from_slice(&upstream.to_be_bytes());
    k
}

/// Inbox key: `u16be(service_len) || service || received:u64be || delivery_id`.
/// Fixed layout, collision-free, and prefix-scannable per service; ordering
/// within a service is `(received, delivery_id)`, i.e. FIFO.
fn inbox_key(
    service: &str,
    received: u64,
    delivery_id: &DeliveryId,
) -> Result<Vec<u8>, StoreError> {
    let svc = service.as_bytes();
    let svc_len =
        u16::try_from(svc.len()).map_err(|_| StoreError::Corrupt("inbox service name"))?;
    let mut k = Vec::with_capacity(2 + svc.len() + 8 + 16);
    k.extend_from_slice(&svc_len.to_be_bytes());
    k.extend_from_slice(svc);
    k.extend_from_slice(&received.to_be_bytes());
    k.extend_from_slice(delivery_id.as_bytes());
    Ok(k)
}

/// The key prefix shared by every inbox row for `service`.
fn inbox_prefix(service: &str) -> Result<Vec<u8>, StoreError> {
    let svc = service.as_bytes();
    let svc_len =
        u16::try_from(svc.len()).map_err(|_| StoreError::Corrupt("inbox service name"))?;
    let mut k = Vec::with_capacity(2 + svc.len());
    k.extend_from_slice(&svc_len.to_be_bytes());
    k.extend_from_slice(svc);
    Ok(k)
}

/// Inclusive upper bound for the prefix scan: `prefix || [0xFF; 24]` covers
/// every possible `(received, delivery_id)` suffix.
fn inbox_range_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    end.extend_from_slice(&[0xFF; 24]);
    end
}

/// Re-validate a decoded outbound message. The envelope is checked against
/// the wire invariants via `Envelope::from_value`; failure fails the read.
/// Bounded integer fields are clamped, not rejected: a row with priority 7
/// is still deliverable, just not more urgent than 3.
fn sanitize_outbound(mut msg: OutboundMessage) -> Result<OutboundMessage, StoreError> {
    lattice_proto::message::Envelope::from_value(&msg.envelope.to_value()).map_err(|e| {
        StoreError::Codec {
            context: "validate outbound envelope",
            source: Box::new(e),
        }
    })?;
    msg.priority = msg.priority.min(3);
    msg.route = msg.route.min(2);
    Ok(msg)
}

/// Clamp a decoded custody entry's buffer-class slot into range. Nothing
/// else about a custody entry is meaningfully validatable.
fn sanitize_custody(mut entry: CustodyEntry) -> CustodyEntry {
    entry.class = entry.class.min(BUF_CLASSES - 1);
    entry
}

/// Ordered schema migrations. Each step upgrades the database from version
/// `n` to `n + 1`. There are no steps: v2 was a clean break from v1 (rows
/// changed encoding wholesale) and v3 changed the custody bucket index
/// semantics; there is no deployed base to migrate. A v1 or v2 database
/// fails loudly here rather than being silently misread.
fn migrate(from: u64) -> Result<(), StoreError> {
    // Ordered steps would go here: 3 => migrate_3_to_4(txn)?, etc.
    Err(StoreError::NoMigration { from })
}

/// Subtract `delta` from a u64 counter in the meta table, saturating at
/// zero. Used by custody release, where a drifted counter must not block
/// the release; the open-time rebuild recomputes exact values.
fn meta_sub(txn: &redb::WriteTransaction, key: &str, delta: u64) -> Result<(), StoreError> {
    let cur = meta_u64(txn, key)?;
    let mut meta = txn.open_table(META)?;
    meta.insert(key, cur.saturating_sub(delta))?;
    Ok(())
}

/// Read a u64 counter from the meta table inside a write transaction.
fn meta_u64(txn: &redb::WriteTransaction, key: &str) -> Result<u64, StoreError> {
    let meta = txn.open_table(META)?;
    Ok(meta.get(key)?.map_or(0, |v| v.value()))
}

/// Add `delta` (signed) to a u64 counter in the meta table.
fn meta_add(txn: &redb::WriteTransaction, key: &str, delta: i64) -> Result<u64, StoreError> {
    let cur = meta_u64(txn, key)?;
    let next = (cur as i64)
        .checked_add(delta)
        .ok_or_else(|| StoreError::CounterOverflow(format!("meta counter {key}")))?;
    if next < 0 {
        return Err(StoreError::CounterUnderflow(format!("meta counter {key}")));
    }
    let mut meta = txn.open_table(META)?;
    meta.insert(key, next as u64)?;
    Ok(next as u64)
}

/// An active batch: one write transaction shared by every operation
/// until `commit_batch` (or `abort_batch`). `poisoned` records the first
/// operation that failed inside the batch; a poisoned batch is discarded,
/// never committed, so a half-applied batch never becomes durable.
struct BatchState {
    txn: redb::WriteTransaction,
    poisoned: Cell<Option<&'static str>>,
}

pub struct RedbStore {
    db: Database,
    batch: Option<BatchState>,
    /// Number of transactions committed (both standalone writes and
    /// batches). Instrumentation for the group-commit work; not used by
    /// the store itself.
    commit_count: Cell<u64>,
}

impl RedbStore {
    /// Open (or create) a store at `path`. Refuses to open a database whose
    /// schema version is newer than this build understands.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        const OP: &str = "open";
        let db = Database::create(path).map_err(ctx(OP))?;
        let txn = db.begin_write().map_err(ctx(OP))?;
        {
            let mut meta = txn.open_table(META).map_err(ctx(OP))?;
            let existing = meta
                .get("schema_version")
                .map_err(ctx(OP))?
                .map(|v| v.value());
            match existing {
                None => {
                    meta.insert("schema_version", SCHEMA_VERSION)
                        .map_err(ctx(OP))?;
                }
                Some(v) if v > SCHEMA_VERSION => {
                    return Err(StoreError::SchemaTooNew {
                        found: v,
                        supported: SCHEMA_VERSION,
                    });
                }
                Some(v) if v < SCHEMA_VERSION => {
                    migrate(v).map_err(|e| e.at(OP))?;
                }
                Some(_) => {}
            }
        }
        ensure_tables!(
            txn,
            OP,
            RECORDS,
            RECORD_RECV,
            KEL_HEADS,
            KELS,
            OUTBOUND,
            CUSTODY,
            SHARES,
            SEEN,
            SEEN_UNHELD,
            DELIVERED,
            INBOX,
            STATUS,
        );
        rebuild_custody_counters(&txn, OP)?;
        txn.commit().map_err(ctx(OP))?;
        Ok(Self {
            db,
            batch: None,
            commit_count: Cell::new(0),
        })
    }

    /// Number of transactions committed since the store was opened
    /// (excluding the schema-setup transaction). Instrumentation for the
    /// group-commit work.
    #[must_use]
    pub fn commit_count(&self) -> u64 {
        self.commit_count.get()
    }

    fn read<R>(
        &self,
        op: &'static str,
        f: impl FnOnce(ReadTx<'_>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        match &self.batch {
            // Inside a batch, reads go through the batch's write
            // transaction so they observe the staged writes. A failed read
            // poisons the batch like any other store error.
            Some(batch) => {
                let result = f(ReadTx::Write(&batch.txn)).map_err(|e| e.at(op));
                if result.is_err() && batch.poisoned.get().is_none() {
                    batch.poisoned.set(Some(op));
                }
                result
            }
            None => {
                let txn = self.db.begin_read().map_err(ctx(op))?;
                f(ReadTx::Read(&txn)).map_err(|e| e.at(op))
            }
        }
    }

    fn write<R>(
        &self,
        op: &'static str,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        if let Some(batch) = &self.batch {
            // Inside a batch the write joins the batch's transaction; it
            // becomes durable only when the batch commits. A failed write
            // poisons the batch: commit_batch will discard it.
            let result = f(&batch.txn).map_err(|e| e.at(op));
            if result.is_err() && batch.poisoned.get().is_none() {
                batch.poisoned.set(Some(op));
            }
            return result;
        }
        let txn = self.db.begin_write().map_err(ctx(op))?;
        let mut txn = txn;
        txn.set_durability(redb::Durability::Immediate);
        let out = f(&txn).map_err(|e| e.at(op))?;
        txn.commit().map_err(ctx(op))?;
        self.commit_count.set(self.commit_count.get() + 1);
        Ok(out)
    }

    fn bucket_counts(&self) -> Result<[u64; 4], StoreError> {
        self.read("bucket_counts", |txn| {
            let table = txn.open_table(META)?;
            let mut out = [0u64; 4];
            for (i, key) in ["bucket_0", "bucket_1", "bucket_2", "bucket_3"]
                .iter()
                .enumerate()
            {
                out[i] = table.get(*key)?.map_or(0, |v| v.value());
            }
            Ok(out)
        })
    }

    fn bucket_bump(&self, bucket: u8) -> Result<(), StoreError> {
        self.write("bucket_bump", |txn| {
            let mut table = txn.open_table(META)?;
            let key = format!("bucket_{}", bucket.min(3));
            let cur = table.get(key.as_str())?.map_or(0, |v| v.value());
            table.insert(key.as_str(), cur + 1)?;
            Ok(())
        })
    }
}

/// Rebuild the custody byte counters and the share table from the CUSTODY
/// table so neither can drift from the rows actually present. Runs on
/// open. The share counters are fully derivable from the custody rows, so
/// rebuilding here is what keeps a crash between the custody write and a
/// share write from leaking allowance forever.
fn rebuild_custody_counters(
    txn: &redb::WriteTransaction,
    op: &'static str,
) -> Result<(), StoreError> {
    let mut custody_bytes: u64 = 0;
    let mut class_bytes = [0u64; CLASS_SLOTS];
    let mut shares: std::collections::BTreeMap<(Identifier, u64), u64> =
        std::collections::BTreeMap::new();
    {
        let t = txn.open_table(CUSTODY).map_err(ctx(op))?;
        for entry in t.iter().map_err(ctx(op))? {
            let (_, v) = entry.map_err(ctx(op))?;
            let e = sanitize_custody(decode_custody(&v.value())?);
            custody_bytes += e.message.len() as u64;
            class_bytes[e.class as usize] += e.message.len() as u64;
            *shares.entry((e.destination, e.upstream)).or_insert(0) += e.message.len() as u64;
        }
    }
    {
        let mut meta = txn.open_table(META).map_err(ctx(op))?;
        meta.insert("custody_bytes", custody_bytes)
            .map_err(ctx(op))?;
        for (i, b) in class_bytes.iter().enumerate() {
            meta.insert(format!("custody_class_{i}").as_str(), *b)
                .map_err(ctx(op))?;
        }
    }
    {
        let mut t = txn.open_table(SHARES).map_err(ctx(op))?;
        let stale: Vec<[u8; 40]> = t
            .iter()
            .map_err(ctx(op))?
            .map(|entry| entry.map(|(k, _)| k.value()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(ctx(op))?;
        for key in stale {
            t.remove(key).map_err(ctx(op))?;
        }
        for ((dest, upstream), bytes) in shares {
            t.insert(share_key(&dest, upstream), bytes)
                .map_err(ctx(op))?;
        }
    }
    Ok(())
}

/// Insert a custody row and bump the byte counter, in the caller's txn.
/// `bytes` must be the serialization of `entry`; the counters are updated
/// from `entry` directly rather than by re-decoding `bytes`.
fn custody_put_txn(
    txn: &redb::WriteTransaction,
    entry: &CustodyEntry,
    bytes: Vec<u8>,
) -> Result<(), StoreError> {
    let leg = entry.leg;
    let msg_len = entry.message.len() as i64;
    let new_class = entry.class.min((CLASS_SLOTS - 1) as u8) as usize;
    let mut t = txn.open_table(CUSTODY)?;
    // The byte counters track message bytes, so recover the old entry's
    // message length and class from the stored row if this leg is overwritten.
    let (old_msg_len, old_class) = match t.get(leg.as_bytes())? {
        Some(v) => {
            let e = sanitize_custody(decode_custody(&v.value())?);
            (e.message.len() as u64, e.class as usize)
        }
        None => (0, 0),
    };
    t.insert(*leg.as_bytes(), bytes)?;
    if old_msg_len > 0 {
        meta_sub(txn, "custody_bytes", old_msg_len)?;
        meta_sub(txn, &format!("custody_class_{old_class}"), old_msg_len)?;
    }
    meta_add(txn, "custody_bytes", msg_len)?;
    meta_add(txn, &format!("custody_class_{new_class}"), msg_len)?;
    Ok(())
}

/// Subtract `bytes` from a share row, saturating at zero and removing the
/// row when it empties. Used by `custody_release`: the share is derived
/// from the custody rows (rebuilt at open), so a shortfall means the books
/// drifted, not that the release should fail — the custody row must not
/// be left behind.
fn share_sub_txn(
    txn: &redb::WriteTransaction,
    dest: &Identifier,
    upstream: u64,
    bytes: u64,
) -> Result<(), StoreError> {
    let key = share_key(dest, upstream);
    let mut t = txn.open_table(SHARES)?;
    let cur = t.get(key)?.map_or(0, |v| v.value());
    let next = cur.saturating_sub(bytes);
    if next == 0 {
        t.remove(key)?;
    } else {
        t.insert(key, next)?;
    }
    Ok(())
}

/// Fair-share accounting with checked arithmetic; no silent clamping.
fn share_add_txn(
    txn: &redb::WriteTransaction,
    dest: &Identifier,
    upstream: u64,
    bytes: i64,
) -> Result<u64, StoreError> {
    let key = share_key(dest, upstream);
    let mut t = txn.open_table(SHARES)?;
    let cur = t.get(key)?.map_or(0, |v| v.value());
    let next = (cur as i64)
        .checked_add(bytes)
        .ok_or_else(|| StoreError::CounterOverflow("share".into()))?;
    if next < 0 {
        return Err(StoreError::CounterUnderflow("share".into()));
    }
    if next == 0 {
        t.remove(key)?;
    } else {
        t.insert(key, next as u64)?;
    }
    Ok(next as u64)
}

fn seen_add_txn(txn: &redb::WriteTransaction, hash: Hash32, exp: u64) -> Result<(), StoreError> {
    let mut t = txn.open_table(SEEN)?;
    t.insert(*hash.as_bytes(), exp)?;
    Ok(())
}

impl Store for RedbStore {
    fn record_get(&self, id: &Identifier, scope: Scope) -> Result<Option<RecordBytes>, StoreError> {
        let key = record_key(id, scope);
        self.read("record_get", |txn| {
            let t = txn.open_table(RECORDS)?;
            let Some(bytes) = t.get(key)?.map(|v| v.value()) else {
                return Ok(None);
            };
            let recv = txn.open_table(RECORD_RECV)?;
            let at = recv.get(key)?.map_or(0, |v| v.value());
            Ok(Some(RecordBytes {
                bytes,
                received: at,
            }))
        })
    }

    fn record_put(
        &mut self,
        id: &Identifier,
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError> {
        let key = record_key(id, scope);
        self.write("record_put", |txn| {
            let mut t = txn.open_table(RECORDS)?;
            t.insert(key, bytes.to_vec())?;
            let mut r = txn.open_table(RECORD_RECV)?;
            r.insert(key, received)?;
            Ok(())
        })
    }

    fn record_remove(&mut self, id: &Identifier, scope: Scope) -> Result<(), StoreError> {
        let key = record_key(id, scope);
        self.write("record_remove", |txn| {
            let mut t = txn.open_table(RECORDS)?;
            t.remove(key)?;
            let mut r = txn.open_table(RECORD_RECV)?;
            r.remove(key)?;
            Ok(())
        })
    }

    fn record_all(&self) -> Result<Vec<StoredRecord>, StoreError> {
        self.read("record_all", |txn| {
            let t = txn.open_table(RECORDS)?;
            let r = txn.open_table(RECORD_RECV)?;
            let mut out = Vec::new();
            for entry in t.iter()? {
                let (k, v) = entry?;
                let key = k.value();
                if key.len() != 33 {
                    return Err(StoreError::Corrupt("records key"));
                }
                let id = Identifier::from_bytes(fixed(&key[..32], "records key")?);
                let scope = if key[32] == 0 {
                    Scope::Wan
                } else {
                    Scope::Hive
                };
                let recv = r.get(key)?.map_or(0, |v| v.value());
                out.push(StoredRecord {
                    id,
                    scope,
                    bytes: v.value(),
                    received: recv,
                });
            }
            Ok(out)
        })
    }

    fn record_count(&self) -> Result<usize, StoreError> {
        self.read("record_count", |txn| {
            let t = txn.open_table(RECORDS)?;
            Ok(t.len()? as usize)
        })
    }

    fn kel_head(&self, id: &Identifier) -> Result<Option<KelHeadSeen>, StoreError> {
        self.read("kel_head", |txn| {
            let t = txn.open_table(KEL_HEADS)?;
            match t.get(id.as_bytes())? {
                None => Ok(None),
                Some(v) => {
                    let raw = v.value();
                    if raw.len() != 49 {
                        return Err(StoreError::Corrupt("kel_heads value"));
                    }
                    let seq = u64::from_le_bytes(fixed(&raw[..8], "kel_heads value")?);
                    let commitment = Commitment::from_bytes(fixed(&raw[8..40], "kel_heads value")?);
                    let seen = u64::from_le_bytes(fixed(&raw[40..48], "kel_heads value")?);
                    let abandoned = raw[48] != 0;
                    Ok(Some(KelHeadSeen {
                        seq,
                        commitment,
                        seen,
                        abandoned,
                    }))
                }
            }
        })
    }

    fn kel_put(
        &mut self,
        id: &Identifier,
        bytes: &[u8],
        head: &KelHeadSeen,
    ) -> Result<(), StoreError> {
        let mut raw = [0u8; 49];
        raw[..8].copy_from_slice(&head.seq.to_le_bytes());
        raw[8..40].copy_from_slice(head.commitment.as_ref());
        raw[40..48].copy_from_slice(&head.seen.to_le_bytes());
        raw[48] = u8::from(head.abandoned);
        self.write("kel_put", |txn| {
            let mut heads = txn.open_table(KEL_HEADS)?;
            heads.insert(*id.as_bytes(), raw)?;
            let mut kels = txn.open_table(KELS)?;
            kels.insert(*id.as_bytes(), bytes.to_vec())?;
            Ok(())
        })
    }

    fn kel_get(&self, id: &Identifier) -> Result<Option<Vec<u8>>, StoreError> {
        self.read("kel_get", |txn| {
            let t = txn.open_table(KELS)?;
            Ok(t.get(id.as_bytes())?.map(|v| v.value()))
        })
    }

    fn kel_heads_all(&self) -> Result<Vec<(Identifier, KelHeadSeen)>, StoreError> {
        self.read("kel_heads_all", |txn| {
            let t = txn.open_table(KEL_HEADS)?;
            let mut out = Vec::new();
            for entry in t.iter()? {
                let (k, v) = entry?;
                let raw = v.value();
                if raw.len() != 49 {
                    return Err(StoreError::Corrupt("kel_heads value"));
                }
                let seq = u64::from_le_bytes(fixed(&raw[..8], "kel_heads value")?);
                let commitment = Commitment::from_bytes(fixed(&raw[8..40], "kel_heads value")?);
                let seen = u64::from_le_bytes(fixed(&raw[40..48], "kel_heads value")?);
                let abandoned = raw[48] != 0;
                out.push((
                    Identifier::from_bytes(k.value()),
                    KelHeadSeen {
                        seq,
                        commitment,
                        seen,
                        abandoned,
                    },
                ));
            }
            Ok(out)
        })
    }

    fn kel_touch(&mut self, id: &Identifier, seen: u64) -> Result<(), StoreError> {
        self.write("kel_touch", |txn| {
            let mut t = txn.open_table(KEL_HEADS)?;
            let raw = match t.get(id.as_bytes())? {
                Some(v) => v.value(),
                None => return Ok(()),
            };
            if raw.len() != 49 {
                return Err(StoreError::Corrupt("kel_heads value"));
            }
            let mut raw = raw;
            raw[40..48].copy_from_slice(&seen.to_le_bytes());
            t.insert(*id.as_bytes(), raw)?;
            Ok(())
        })
    }

    fn kel_sweep(&mut self, older_than: u64) -> Result<usize, StoreError> {
        self.write("kel_sweep", |txn| {
            let mut heads = txn.open_table(KEL_HEADS)?;
            let stale: Vec<[u8; 32]> = {
                let mut out = Vec::new();
                for entry in heads.iter()? {
                    let (k, v) = entry?;
                    let raw = v.value();
                    if raw.len() != 49 {
                        return Err(StoreError::Corrupt("kel_heads value"));
                    }
                    let seen = u64::from_le_bytes(fixed(&raw[40..48], "kel_heads value")?);
                    if seen < older_than {
                        out.push(k.value());
                    }
                }
                out
            };
            let n = stale.len();
            let mut kels = txn.open_table(KELS)?;
            for k in stale {
                heads.remove(k)?;
                kels.remove(k)?;
            }
            Ok(n)
        })
    }

    fn outbound_remove(&mut self, mid: &MessageId) -> Result<(), StoreError> {
        self.write("outbound_remove", |txn| {
            let mut t = txn.open_table(OUTBOUND)?;
            t.remove(mid.as_bytes())?;
            Ok(())
        })
    }

    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        let bytes = encode_outbound(msg);
        self.write("outbound_push", |txn| {
            let mut t = txn.open_table(OUTBOUND)?;
            t.insert(*msg.mid.as_bytes(), bytes)?;
            Ok(())
        })
    }

    fn outbound_get(&self, mid: &MessageId) -> Result<Option<OutboundMessage>, StoreError> {
        self.read("outbound_get", |txn| {
            let t = txn.open_table(OUTBOUND)?;
            match t.get(mid.as_bytes())? {
                None => Ok(None),
                Some(v) => {
                    let msg = decode_outbound(&v.value())?;
                    Ok(Some(sanitize_outbound(msg)?))
                }
            }
        })
    }

    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound_push(msg)
    }

    fn outbound_all(&self) -> Result<Vec<OutboundMessage>, StoreError> {
        self.read("outbound_all", |txn| {
            let t = txn.open_table(OUTBOUND)?;
            let mut out = Vec::new();
            for entry in t.iter()? {
                let (_, v) = entry?;
                let msg = decode_outbound(&v.value())?;
                out.push(sanitize_outbound(msg)?);
            }
            Ok(out)
        })
    }

    fn custody_accept(&mut self, accept: CustodyAccept) -> Result<(), StoreError> {
        let CustodyAccept {
            entry,
            share_dest,
            share_upstream,
            share_bytes,
            seen_hash,
            seen_exp,
        } = accept;
        let bytes = encode_custody(&entry);
        self.write("custody_accept", |txn| {
            custody_put_txn(txn, &entry, bytes)?;
            share_add_txn(txn, &share_dest, share_upstream, share_bytes)?;
            seen_add_txn(txn, seen_hash, seen_exp)?;
            Ok(())
        })
    }

    fn custody_put(&mut self, entry: CustodyEntry) -> Result<(), StoreError> {
        let bytes = encode_custody(&entry);
        self.write("custody_put", |txn| custody_put_txn(txn, &entry, bytes))
    }

    fn custody_get(&self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError> {
        self.read("custody_get", |txn| {
            let t = txn.open_table(CUSTODY)?;
            match t.get(leg.as_bytes())? {
                None => Ok(None),
                Some(v) => {
                    let e = decode_custody(&v.value())?;
                    Ok(Some(sanitize_custody(e)))
                }
            }
        })
    }

    fn custody_release(&mut self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError> {
        // One transaction: custody row delete, byte-counter decrement and
        // share decrement. A crash either releases all three or none, and
        // the open-time rebuild heals any drift regardless.
        self.write("custody_release", |txn| {
            let existing = {
                let t = txn.open_table(CUSTODY)?;
                match t.get(leg.as_bytes())? {
                    Some(v) => Some(sanitize_custody(decode_custody(&v.value())?)),
                    None => None,
                }
            };
            let Some(e) = existing else { return Ok(None) };
            let msg_len = e.message.len() as u64;
            let class = e.class as usize; // already clamped by sanitize_custody
            let mut t = txn.open_table(CUSTODY)?;
            t.remove(leg.as_bytes())?;
            drop(t);
            meta_sub(txn, "custody_bytes", msg_len)?;
            meta_sub(txn, &format!("custody_class_{class}"), msg_len)?;
            share_sub_txn(txn, &e.destination, e.upstream, msg_len)?;
            Ok(Some(e))
        })
    }

    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError> {
        self.read("custody_all", |txn| {
            let t = txn.open_table(CUSTODY)?;
            let mut out = Vec::new();
            for entry in t.iter()? {
                let (_, v) = entry?;
                let e = decode_custody(&v.value())?;
                out.push(sanitize_custody(e));
            }
            Ok(out)
        })
    }

    fn custody_bytes(&self) -> Result<u64, StoreError> {
        self.read("custody_bytes", |txn| {
            let meta = txn.open_table(META)?;
            Ok(meta.get("custody_bytes")?.map_or(0, |v| v.value()))
        })
    }

    fn custody_class_bytes(&self) -> Result<[u64; CLASS_SLOTS], StoreError> {
        self.read("custody_class_bytes", |txn| {
            let meta = txn.open_table(META)?;
            let mut out = [0u64; CLASS_SLOTS];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = meta
                    .get(format!("custody_class_{i}").as_str())?
                    .map_or(0, |v| v.value());
            }
            Ok(out)
        })
    }

    fn share_add(
        &mut self,
        dest: &Identifier,
        upstream: u64,
        bytes: i64,
    ) -> Result<u64, StoreError> {
        self.write("share_add", |txn| share_add_txn(txn, dest, upstream, bytes))
    }

    fn share_get(&self, dest: &Identifier, upstream: u64) -> Result<u64, StoreError> {
        let key = share_key(dest, upstream);
        self.read("share_get", |txn| {
            let t = txn.open_table(SHARES)?;
            Ok(t.get(key)?.map_or(0, |v| v.value()))
        })
    }

    fn share_upstream_count(&self, dest: &Identifier) -> Result<u64, StoreError> {
        self.read("share_upstream_count", |txn| {
            let t = txn.open_table(SHARES)?;
            // SHARES keys are dest(32) || upstream(8); scan from the dest
            // prefix and count while the prefix holds.
            let mut start = [0u8; 40];
            start[..32].copy_from_slice(dest.as_bytes());
            let mut count = 0u64;
            for entry in t.range(start..)? {
                let (k, _) = entry?;
                if k.value()[..32] != start[..32] {
                    break;
                }
                count += 1;
            }
            Ok(count)
        })
    }

    fn alloc_link_id(&mut self) -> Result<u64, StoreError> {
        self.write("alloc_link_id", |txn| {
            let cur = meta_u64(txn, "next_link_id")?;
            let id = if cur == 0 { LINK_ID_BASE } else { cur };
            let next = id
                .checked_add(1)
                .ok_or_else(|| StoreError::CounterOverflow("next_link_id".into()))?;
            let mut meta = txn.open_table(META)?;
            meta.insert("next_link_id", next)?;
            Ok(id)
        })
    }

    fn seen_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        self.read("seen_contains", |txn| {
            let t = txn.open_table(SEEN)?;
            Ok(t.get(hash.as_bytes())?.is_some_and(|v| v.value() > now))
        })
    }

    fn seen_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.write("seen_add", |txn| seen_add_txn(txn, hash, exp))
    }

    fn seen_unheld_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.write("seen_unheld_add", |txn| {
            let mut t = txn.open_table(SEEN_UNHELD)?;
            t.insert(*hash.as_bytes(), exp)?;
            Ok(())
        })
    }

    fn seen_unheld_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        self.read("seen_unheld_contains", |txn| {
            let t = txn.open_table(SEEN_UNHELD)?;
            Ok(t.get(hash.as_bytes())?
                .map(|v| v.value() > now)
                .unwrap_or(false))
        })
    }

    fn delivered_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        self.read("delivered_contains", |txn| {
            let t = txn.open_table(DELIVERED)?;
            Ok(t.get(hash.as_bytes())?.is_some_and(|v| v.value() > now))
        })
    }

    fn delivered_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.write("delivered_add", |txn| {
            let mut t = txn.open_table(DELIVERED)?;
            t.insert(*hash.as_bytes(), exp)?;
            Ok(())
        })
    }

    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError> {
        self.write("sweep_expired", |txn| {
            for table_def in [SEEN, SEEN_UNHELD, DELIVERED] {
                let mut t = txn.open_table(table_def)?;
                let expired: Vec<[u8; 32]> = t
                    .iter()?
                    .map(|e| e.map(|(k, v)| (k.value(), v.value())))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|(_, v)| *v <= now)
                    .map(|(k, _)| k)
                    .collect();
                for k in expired {
                    t.remove(k)?;
                }
            }
            // Status rows carry their write time; drop rows older than the
            // TTL. Rows written before the timestamp existed decode with
            // set_at = 0 and are treated as ancient.
            let mut t = txn.open_table(STATUS)?;
            let expired: Vec<[u8; 16]> = t
                .iter()?
                .map(|e| e.map(|(k, v)| (k.value(), v.value())))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(_, v)| match decode_status(v) {
                    Ok((_, set_at)) => set_at.saturating_add(STATUS_TTL_SECS) <= now,
                    // Undecodable rows are dropped rather than kept forever.
                    Err(_) => true,
                })
                .map(|(k, _)| k)
                .collect();
            for k in expired {
                t.remove(k)?;
            }
            Ok(())
        })
    }

    fn inbox_push(&mut self, entry: InboxEntry) -> Result<(), StoreError> {
        let bytes = encode_inbox(&entry);
        let key = inbox_key(&entry.tsvc, entry.received, &entry.delivery_id)?;
        self.write("inbox_push", |txn| {
            let mut t = txn.open_table(INBOX)?;
            t.insert(key.as_slice(), bytes)?;
            Ok(())
        })
    }

    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError> {
        let prefix = inbox_prefix(service)?;
        let end = inbox_range_end(&prefix);
        self.read("inbox_fetch", |txn| {
            let t = txn.open_table(INBOX)?;
            let mut out = Vec::new();
            // Key order is (received, delivery_id), so the scan yields FIFO.
            for entry in t.range(prefix.as_slice()..=end.as_slice())? {
                if out.len() >= max {
                    break;
                }
                let (_, v) = entry?;
                let e = decode_inbox(&v.value())?;
                // Defense in depth: the key prefix already scopes the scan to
                // this service; a row whose tsvc disagrees with its key is
                // skipped rather than delivered to the wrong service.
                if e.tsvc == service {
                    out.push(e);
                }
            }
            Ok(out)
        })
    }

    fn inbox_ack(
        &mut self,
        service: &str,
        delivery_ids: &[DeliveryId],
    ) -> Result<usize, StoreError> {
        let prefix = inbox_prefix(service)?;
        let end = inbox_range_end(&prefix);
        self.write("inbox_ack", |txn| {
            let mut t = txn.open_table(INBOX)?;
            // The delivery id is the key suffix, so matching needs no decode.
            let doomed: Vec<Vec<u8>> = {
                let mut out = Vec::new();
                for entry in t.range(prefix.as_slice()..=end.as_slice())? {
                    let (k, _) = entry?;
                    let key = k.value();
                    let id = key
                        .get(key.len().saturating_sub(16)..)
                        .and_then(|tail| <[u8; 16]>::try_from(tail).ok());
                    if let Some(id) = id {
                        if delivery_ids.iter().any(|d| d.as_bytes() == &id) {
                            out.push(key.to_vec());
                        }
                    }
                }
                out
            };
            let removed = doomed.len();
            for key in doomed {
                t.remove(key.as_slice())?;
            }
            Ok(removed)
        })
    }

    fn inbox_len(&self, service: &str) -> Result<u64, StoreError> {
        let prefix = inbox_prefix(service)?;
        let end = inbox_range_end(&prefix);
        self.read("inbox_len", |txn| {
            let t = txn.open_table(INBOX)?;
            let mut count = 0u64;
            for entry in t.range(prefix.as_slice()..=end.as_slice())? {
                entry?;
                count += 1;
            }
            Ok(count)
        })
    }

    fn inbox_len_total(&self) -> Result<u64, StoreError> {
        self.read("inbox_len_total", |txn| {
            let t = txn.open_table(INBOX)?;
            Ok(t.len()?)
        })
    }

    fn inbox_sweep_expired(&mut self, max_age_secs: u64, now: u64) -> Result<u64, StoreError> {
        self.write("inbox_sweep_expired", |txn| {
            let mut t = txn.open_table(INBOX)?;
            let mut stale = Vec::new();
            for entry in t.iter()? {
                let (k, v) = entry?;
                let e = decode_inbox(&v.value())?;
                if e.received.saturating_add(max_age_secs) <= now {
                    stale.push(k.value().to_vec());
                }
            }
            let dropped = stale.len() as u64;
            for key in stale {
                t.remove(key.as_slice())?;
            }
            Ok(dropped)
        })
    }

    fn status_set(
        &mut self,
        mid: &MessageId,
        status: u64,
        detail: Option<u64>,
        now: u64,
    ) -> Result<(), StoreError> {
        let bytes = encode_status(&MessageStatus { status, detail }, now);
        self.write("status_set", |txn| {
            let mut t = txn.open_table(STATUS)?;
            t.insert(*mid.as_bytes(), bytes)?;
            Ok(())
        })
    }

    fn status_get(&self, mid: &MessageId) -> Result<Option<MessageStatus>, StoreError> {
        self.read("status_get", |txn| {
            let t = txn.open_table(STATUS)?;
            match t.get(mid.as_bytes())? {
                None => Ok(None),
                Some(v) => decode_status(&v.value()).map(|(s, _)| Some(s)),
            }
        })
    }

    fn size_bucket_sample(&mut self, bucket: u8) -> Result<(), StoreError> {
        self.bucket_bump(bucket)
    }

    fn size_bucket_counts(&self) -> Result<[u64; 4], StoreError> {
        self.bucket_counts()
    }

    fn drain_get(&self) -> Result<DrainState, StoreError> {
        self.read("drain_get", |txn| {
            let meta = txn.open_table(META)?;
            Ok(meta
                .get("drain")?
                .map_or(DrainState::Serving, |v| DrainState::from(v.value() != 0)))
        })
    }

    fn drain_set(&mut self, state: DrainState) -> Result<(), StoreError> {
        self.write("drain_set", |txn| {
            let mut meta = txn.open_table(META)?;
            meta.insert("drain", u64::from(state.is_draining()))?;
            Ok(())
        })
    }

    fn begin_batch(&mut self) -> Result<(), StoreError> {
        if self.batch.is_some() {
            return Err(StoreError::Backend {
                op: "begin_batch",
                source: "a batch is already active".into(),
            });
        }
        let txn = self.db.begin_write().map_err(ctx("begin_batch"))?;
        let mut txn = txn;
        txn.set_durability(redb::Durability::Immediate);
        self.batch = Some(BatchState {
            txn,
            poisoned: Cell::new(None),
        });
        Ok(())
    }

    fn commit_batch(&mut self) -> Result<(), StoreError> {
        let Some(batch) = self.batch.take() else {
            return Ok(());
        };
        if let Some(op) = batch.poisoned.get() {
            // Discard the transaction without committing: nothing the
            // batch staged becomes durable.
            drop(batch.txn);
            return Err(StoreError::Backend {
                op: "commit_batch",
                source: format!("batch discarded: store operation {op} failed").into(),
            });
        }
        batch.txn.commit().map_err(ctx("commit_batch"))?;
        self.commit_count.set(self.commit_count.get() + 1);
        Ok(())
    }

    fn abort_batch(&mut self) {
        // Dropping the write transaction discards it without committing.
        self.batch.take();
    }
}

impl RedbStore {
    /// Accept many custody entries in one write transaction, so the whole
    /// batch becomes durable with a single fsync — the group-commit pattern
    /// the custody path needs for custody throughput.
    pub fn custody_put_batch(&self, entries: &[CustodyEntry]) -> Result<(), StoreError> {
        self.write("custody_put_batch", |txn| {
            for entry in entries {
                let bytes = encode_custody(entry);
                custody_put_txn(txn, entry, bytes)?;
            }
            Ok(())
        })
    }
}
