//! redb-backed Store. One table per logical store, schema version in `meta`.
//!
//! Durability: every write transaction commits with `Durability::Immediate`,
//! so a committed custody accept is on disk before `Ok` returns. The mem
//! backend exists for the simulator; behavior is contract-tested for
//! equivalence.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::*;
use lattice_proto::record::Scope;

const SCHEMA_VERSION: u64 = 1;

const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const RECORDS: TableDefinition<[u8; 33], Vec<u8>> = TableDefinition::new("records");
const RECORD_RECV: TableDefinition<[u8; 33], u64> = TableDefinition::new("record_recv");
const KEL_HEADS: TableDefinition<[u8; 32], [u8; 48]> = TableDefinition::new("kel_heads");
const PEERS: TableDefinition<[u8; 32], &str> = TableDefinition::new("peers");
const OUTBOUND: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("outbound");
const CUSTODY: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("custody");
const SHARES: TableDefinition<[u8; 40], u64> = TableDefinition::new("shares");
const SEEN: TableDefinition<[u8; 32], u64> = TableDefinition::new("seen");
const DELIVERED: TableDefinition<[u8; 32], u64> = TableDefinition::new("delivered");
const INBOX: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("inbox");
const STATUS: TableDefinition<[u8; 16], Vec<u8>> = TableDefinition::new("status");
const WARY: TableDefinition<[u8; 32], Vec<u8>> = TableDefinition::new("wary");

fn scope_byte(s: Scope) -> u8 {
    match s {
        Scope::Wan => 0,
        Scope::Hive => 1,
    }
}

fn record_key(id: &[u8; 32], scope: Scope) -> [u8; 33] {
    let mut k = [0u8; 33];
    k[..32].copy_from_slice(id);
    k[32] = scope_byte(scope);
    k
}

fn share_key(dest: &[u8; 32], upstream: u64) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(dest);
    k[32..].copy_from_slice(&upstream.to_be_bytes());
    k
}

/// Ordered schema migrations. Each step upgrades the database from version
/// `n` to `n + 1`. There are no steps yet (v1 is the initial schema); the
/// framework exists so a future bump fails loudly instead of silently
/// opening a mismatched database.
fn migrate(txn: &redb::WriteTransaction, from: u64) -> Result<(), StoreError> {
    // Ordered steps would go here: 1 => migrate_1_to_2(txn)?, etc.
    // v1 is the initial schema, so there is nothing to do yet; any other
    // older version has no path and must fail loudly.
    if from != 1 {
        return Err(StoreError::Backend(format!(
            "no migration path from schema version {from}"
        )));
    }
    let mut meta = txn
        .open_table(META)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    meta.insert("schema_version", SCHEMA_VERSION)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(())
}

/// Read a u64 counter from the meta table inside a write transaction.
fn meta_u64(txn: &redb::WriteTransaction, key: &str) -> Result<u64, StoreError> {
    let meta = txn
        .open_table(META)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(meta
        .get(key)
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .map(|v| v.value())
        .unwrap_or(0))
}

/// Add `delta` (signed) to a u64 counter in the meta table.
fn meta_add(txn: &redb::WriteTransaction, key: &str, delta: i64) -> Result<u64, StoreError> {
    let cur = meta_u64(txn, key)?;
    let next = (cur as i64)
        .checked_add(delta)
        .ok_or_else(|| StoreError::Backend(format!("meta counter {key} overflow")))?;
    if next < 0 {
        return Err(StoreError::Backend(format!("meta counter {key} underflow")));
    }
    let mut meta = txn
        .open_table(META)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    meta.insert(key, next as u64)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(next as u64)
}

pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Open (or create) a store at `path`. Refuses to open a database whose
    /// schema version is newer than this build understands.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(|e| StoreError::Backend(e.to_string()))?;
        let txn = db
            .begin_write()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let existing = meta
                .get("schema_version")
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value());
            match existing {
                None => {
                    meta.insert("schema_version", SCHEMA_VERSION)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                }
                Some(v) if v > SCHEMA_VERSION => {
                    return Err(StoreError::Backend(format!(
                        "schema version {v} is newer than this build understands ({SCHEMA_VERSION})"
                    )));
                }
                Some(v) if v < SCHEMA_VERSION => {
                    drop(meta);
                    migrate(&txn, v)?;
                }
                Some(_) => {}
            }
        }
        // Initialize empty tables so reads never fail on a fresh database.
        txn.open_table(RECORDS)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(RECORD_RECV)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(KEL_HEADS)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(PEERS)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(OUTBOUND)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(CUSTODY)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(SHARES)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(SEEN)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(DELIVERED)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(INBOX)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(STATUS)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        txn.open_table(WARY)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        // Rebuild the custody byte counter from the table so it can never
        // drift from the rows actually present.
        let custody_bytes: u64 = {
            let t = txn
                .open_table(CUSTODY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut sum = 0u64;
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (_, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                let e: CustodyEntry = serde_json::from_slice(&v.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                sum += e.message.len() as u64;
            }
            sum
        };
        {
            let mut meta = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            meta.insert("custody_bytes", custody_bytes)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(Self { db })
    }

    fn read<R>(
        &self,
        f: impl FnOnce(&redb::ReadTransaction) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        f(&txn)
    }

    fn write<R>(
        &self,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut txn = txn;
        txn.set_durability(redb::Durability::Immediate);
        let out = f(&txn)?;
        txn.commit()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(out)
    }

    fn bucket_counts(&self) -> Result<[u64; 3], StoreError> {
        self.read(|txn| {
            let table = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = [0u64; 3];
            for (i, key) in ["bucket_0", "bucket_1", "bucket_2"].iter().enumerate() {
                out[i] = table
                    .get(*key)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .map(|v| v.value())
                    .unwrap_or(0);
            }
            Ok(out)
        })
    }

    fn bucket_bump(&self, bucket: u8) -> Result<(), StoreError> {
        self.write(|txn| {
            let mut table = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let key = format!("bucket_{}", bucket.min(2));
            let cur = table
                .get(key.as_str())
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value())
                .unwrap_or(0);
            table
                .insert(key.as_str(), cur + 1)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }
}

/// Insert a custody row and bump the byte counter, in the caller's txn.
fn custody_put_txn(
    txn: &redb::WriteTransaction,
    leg: [u8; 16],
    bytes: Vec<u8>,
    msg_len: i64,
) -> Result<(), StoreError> {
    let mut t = txn
        .open_table(CUSTODY)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    // The byte counter tracks message bytes, so recover the old entry's
    // message length from the stored row if this leg is being overwritten.
    let old_msg_len = match t.get(leg).map_err(|e| StoreError::Backend(e.to_string()))? {
        Some(v) => serde_json::from_slice::<CustodyEntry>(&v.value())
            .map(|e| e.message.len() as i64)
            .unwrap_or(0),
        None => 0,
    };
    t.insert(leg, bytes)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    meta_add(txn, "custody_bytes", msg_len - old_msg_len)?;
    Ok(())
}

/// Fair-share accounting with checked arithmetic; no silent clamping.
fn share_add_txn(
    txn: &redb::WriteTransaction,
    dest: &[u8; 32],
    upstream: u64,
    bytes: i64,
) -> Result<u64, StoreError> {
    let key = share_key(dest, upstream);
    let mut t = txn
        .open_table(SHARES)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    let cur = t
        .get(key)
        .map_err(|e| StoreError::Backend(e.to_string()))?
        .map(|v| v.value())
        .unwrap_or(0);
    let next = (cur as i64)
        .checked_add(bytes)
        .ok_or_else(|| StoreError::Backend("share counter overflow".into()))?;
    if next < 0 {
        return Err(StoreError::Backend("share counter underflow".into()));
    }
    if next == 0 {
        t.remove(key)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
    } else {
        t.insert(key, next as u64)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
    }
    Ok(next as u64)
}

fn seen_add_txn(txn: &redb::WriteTransaction, hash: [u8; 32], exp: u64) -> Result<(), StoreError> {
    let mut t = txn
        .open_table(SEEN)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    t.insert(hash, exp)
        .map_err(|e| StoreError::Backend(e.to_string()))?;
    Ok(())
}

impl Store for RedbStore {
    fn record_get(
        &self,
        id: &[u8; 32],
        scope: Scope,
    ) -> Result<Option<(Vec<u8>, u64)>, StoreError> {
        let key = record_key(id, scope);
        self.read(|txn| {
            let t = txn
                .open_table(RECORDS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let Some(bytes) = t
                .get(key)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value())
            else {
                return Ok(None);
            };
            let recv = txn
                .open_table(RECORD_RECV)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let at = recv
                .get(key)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value())
                .unwrap_or(0);
            Ok(Some((bytes, at)))
        })
    }

    fn record_put(
        &mut self,
        id: &[u8; 32],
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError> {
        let key = record_key(id, scope);
        self.write(|txn| {
            let mut t = txn
                .open_table(RECORDS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(key, bytes.to_vec())
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut r = txn
                .open_table(RECORD_RECV)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            r.insert(key, received)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn record_remove(&mut self, id: &[u8; 32], scope: Scope) -> Result<(), StoreError> {
        let key = record_key(id, scope);
        self.write(|txn| {
            let mut t = txn
                .open_table(RECORDS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.remove(key)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut r = txn
                .open_table(RECORD_RECV)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            r.remove(key)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn record_all(&self) -> Result<Vec<StoredRecord>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(RECORDS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let r = txn
                .open_table(RECORD_RECV)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (k, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                let key = k.value();
                let id: [u8; 32] = key[..32].try_into().unwrap();
                let scope = if key[32] == 0 {
                    Scope::Wan
                } else {
                    Scope::Hive
                };
                let recv = r
                    .get(key)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .map(|v| v.value())
                    .unwrap_or(0);
                out.push((id, scope, v.value(), recv));
            }
            Ok(out)
        })
    }

    fn record_count(&self) -> Result<usize, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(RECORDS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(t.len().map_err(|e| StoreError::Backend(e.to_string()))? as usize)
        })
    }

    fn kel_head(&self, id: &[u8; 32]) -> Result<Option<(u64, [u8; 32], u64)>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(KEL_HEADS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match t.get(id).map_err(|e| StoreError::Backend(e.to_string()))? {
                None => Ok(None),
                Some(v) => {
                    let raw = v.value();
                    let seq = u64::from_le_bytes(raw[..8].try_into().unwrap());
                    let commitment: [u8; 32] = raw[8..40].try_into().unwrap();
                    let seen = u64::from_le_bytes(raw[40..].try_into().unwrap());
                    Ok(Some((seq, commitment, seen)))
                }
            }
        })
    }

    fn kel_head_put(
        &mut self,
        id: &[u8; 32],
        seq: u64,
        commitment: [u8; 32],
        seen: u64,
    ) -> Result<(), StoreError> {
        let mut raw = [0u8; 48];
        raw[..8].copy_from_slice(&seq.to_le_bytes());
        raw[8..40].copy_from_slice(&commitment);
        raw[40..].copy_from_slice(&seen.to_le_bytes());
        self.write(|txn| {
            let mut t = txn
                .open_table(KEL_HEADS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(*id, raw)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn peer_save(&mut self, id: &[u8; 32], address: &str) -> Result<(), StoreError> {
        self.write(|txn| {
            let mut t = txn
                .open_table(PEERS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(*id, address)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn peer_saved(&self) -> Result<Vec<([u8; 32], String)>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(PEERS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (k, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                out.push((k.value(), v.value().to_string()));
            }
            Ok(out)
        })
    }

    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(msg).map_err(|e| StoreError::Backend(e.to_string()))?;
        self.write(|txn| {
            let mut t = txn
                .open_table(OUTBOUND)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(msg.mid, bytes)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn outbound_get(&self, mid: &[u8; 16]) -> Result<Option<OutboundMessage>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(OUTBOUND)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match t.get(mid).map_err(|e| StoreError::Backend(e.to_string()))? {
                None => Ok(None),
                Some(v) => serde_json::from_slice(&v.value())
                    .map(Some)
                    .map_err(|e| StoreError::Backend(e.to_string())),
            }
        })
    }

    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound_push(msg)
    }

    fn outbound_due(&self, now: u64) -> Result<Vec<OutboundMessage>, StoreError> {
        let mut due: Vec<OutboundMessage> = self
            .outbound_all()?
            .into_iter()
            .filter(|m| m.state == OutboundState::Queued && m.next_attempt <= now && m.exp > now)
            .collect();
        due.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.next_attempt.cmp(&b.next_attempt))
        });
        Ok(due)
    }

    fn outbound_all(&self) -> Result<Vec<OutboundMessage>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(OUTBOUND)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (_, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                let msg: OutboundMessage = serde_json::from_slice(&v.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                out.push(msg);
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
        let bytes = serde_json::to_vec(&entry).map_err(|e| StoreError::Backend(e.to_string()))?;
        let msg_len = entry.message.len() as i64;
        let leg = entry.leg;
        self.write(|txn| {
            custody_put_txn(txn, leg, bytes, msg_len)?;
            share_add_txn(txn, &share_dest, share_upstream, share_bytes)?;
            seen_add_txn(txn, seen_hash, seen_exp)?;
            Ok(())
        })
    }

    fn custody_put(&mut self, entry: CustodyEntry) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(&entry).map_err(|e| StoreError::Backend(e.to_string()))?;
        let leg = entry.leg;
        let msg_len = entry.message.len() as i64;
        self.write(|txn| custody_put_txn(txn, leg, bytes, msg_len))
    }

    fn custody_get(&self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(CUSTODY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match t.get(leg).map_err(|e| StoreError::Backend(e.to_string()))? {
                None => Ok(None),
                Some(v) => serde_json::from_slice(&v.value())
                    .map(Some)
                    .map_err(|e| StoreError::Backend(e.to_string())),
            }
        })
    }

    fn custody_remove(&mut self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError> {
        let existing = self.custody_get(leg)?;
        if let Some(e) = &existing {
            let msg_len = e.message.len() as i64;
            self.write(|txn| {
                let mut t = txn
                    .open_table(CUSTODY)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                t.remove(leg)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                meta_add(txn, "custody_bytes", -msg_len)?;
                Ok(())
            })?;
        }
        Ok(existing)
    }

    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(CUSTODY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (_, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                out.push(
                    serde_json::from_slice(&v.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?,
                );
            }
            Ok(out)
        })
    }

    fn custody_bytes(&self) -> Result<u64, StoreError> {
        self.read(|txn| {
            let meta = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(meta
                .get("custody_bytes")
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value())
                .unwrap_or(0))
        })
    }

    fn share_add(&mut self, dest: &[u8; 32], upstream: u64, bytes: i64) -> Result<u64, StoreError> {
        self.write(|txn| share_add_txn(txn, dest, upstream, bytes))
    }

    fn share_get(&self, dest: &[u8; 32], upstream: u64) -> Result<u64, StoreError> {
        let key = share_key(dest, upstream);
        self.read(|txn| {
            let t = txn
                .open_table(SHARES)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(t.get(key)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value())
                .unwrap_or(0))
        })
    }

    fn seen_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(SEEN)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(t.get(hash)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value() > now)
                .unwrap_or(false))
        })
    }

    fn seen_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError> {
        self.write(|txn| seen_add_txn(txn, hash, exp))
    }

    fn delivered_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(DELIVERED)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(t.get(hash)
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value() > now)
                .unwrap_or(false))
        })
    }

    fn delivered_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError> {
        self.write(|txn| {
            let mut t = txn
                .open_table(DELIVERED)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(hash, exp)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError> {
        self.write(|txn| {
            for table_def in [SEEN, DELIVERED] {
                let mut t = txn
                    .open_table(table_def)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                let expired: Vec<[u8; 32]> = t
                    .iter()
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .filter_map(|e| e.ok())
                    .filter(|(_, v)| v.value() <= now)
                    .map(|(k, _)| k.value())
                    .collect();
                for k in expired {
                    t.remove(k)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                }
            }
            // Wary entries carry JSON rows of (range, exp); drop expired ones.
            let mut t = txn
                .open_table(WARY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let keys: Vec<[u8; 32]> = t
                .iter()
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value())
                .collect();
            for id in keys {
                let Some(v) = t
                    .get(id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .map(|v| v.value())
                else {
                    continue;
                };
                let mut rows: Vec<(u64, u64)> =
                    serde_json::from_slice(&v).map_err(|e| StoreError::Backend(e.to_string()))?;
                let before = rows.len();
                rows.retain(|(_, exp)| *exp > now);
                if rows.len() != before {
                    if rows.is_empty() {
                        t.remove(id)
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                    } else {
                        let bytes = serde_json::to_vec(&rows)
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                        t.insert(id, bytes)
                            .map_err(|e| StoreError::Backend(e.to_string()))?;
                    }
                }
            }
            Ok(())
        })
    }

    fn inbox_push(&mut self, service: &str, entry: InboxEntry) -> Result<(), StoreError> {
        let mut e = entry;
        let _ = service; // service is carried inside the entry
        let bytes = serde_json::to_vec(&e).map_err(|e| StoreError::Backend(e.to_string()))?;
        let id = e.delivery_id;
        self.write(|txn| {
            let mut t = txn
                .open_table(INBOX)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(id, bytes)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })?;
        let _ = &mut e;
        Ok(())
    }

    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(INBOX)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut out = Vec::new();
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                if out.len() >= max {
                    break;
                }
                let (_, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                let e: InboxEntry = serde_json::from_slice(&v.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                if e.tsvc == service {
                    out.push(e);
                }
            }
            Ok(out)
        })
    }

    fn inbox_ack(&mut self, service: &str, delivery_ids: &[[u8; 16]]) -> Result<usize, StoreError> {
        self.write(|txn| {
            let mut t = txn
                .open_table(INBOX)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut removed = 0;
            for id in delivery_ids {
                let entry = t
                    .get(*id)
                    .map_err(|e| StoreError::Backend(e.to_string()))?
                    .map(|v| v.value());
                let belongs = match &entry {
                    Some(bytes) => serde_json::from_slice::<InboxEntry>(bytes)
                        .map(|e| e.tsvc == service)
                        .unwrap_or(false),
                    None => false,
                };
                if belongs {
                    t.remove(id)
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    removed += 1;
                }
            }
            Ok(removed)
        })
    }

    fn inbox_len(&self, service: &str) -> Result<u64, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(INBOX)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut count = 0u64;
            for entry in t.iter().map_err(|e| StoreError::Backend(e.to_string()))? {
                let (_, v) = entry.map_err(|e| StoreError::Backend(e.to_string()))?;
                let e: InboxEntry = serde_json::from_slice(&v.value())
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                if e.tsvc == service {
                    count += 1;
                }
            }
            Ok(count)
        })
    }

    fn status_set(
        &mut self,
        mid: &[u8; 16],
        status: u64,
        detail: Option<u64>,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(&(status, detail))
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        self.write(|txn| {
            let mut t = txn
                .open_table(STATUS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(*mid, bytes)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn status_get(&self, mid: &[u8; 16]) -> Result<Option<(u64, Option<u64>)>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(STATUS)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match t.get(mid).map_err(|e| StoreError::Backend(e.to_string()))? {
                None => Ok(None),
                Some(v) => serde_json::from_slice(&v.value())
                    .map(Some)
                    .map_err(|e| StoreError::Backend(e.to_string())),
            }
        })
    }

    fn wary_add(&mut self, id: &[u8; 32], source_range: u64, exp: u64) -> Result<(), StoreError> {
        self.write(|txn| {
            let mut t = txn
                .open_table(WARY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            let mut rows: Vec<(u64, u64)> =
                match t.get(id).map_err(|e| StoreError::Backend(e.to_string()))? {
                    Some(v) => serde_json::from_slice(&v.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?,
                    None => Vec::new(),
                };
            rows.retain(|(r, _)| *r != source_range);
            rows.push((source_range, exp));
            let bytes =
                serde_json::to_vec(&rows).map_err(|e| StoreError::Backend(e.to_string()))?;
            t.insert(*id, bytes)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }

    fn wary_ranges(&self, id: &[u8; 32], now: u64) -> Result<Vec<u64>, StoreError> {
        self.read(|txn| {
            let t = txn
                .open_table(WARY)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            match t.get(id).map_err(|e| StoreError::Backend(e.to_string()))? {
                None => Ok(Vec::new()),
                Some(v) => {
                    let rows: Vec<(u64, u64)> = serde_json::from_slice(&v.value())
                        .map_err(|e| StoreError::Backend(e.to_string()))?;
                    Ok(rows
                        .into_iter()
                        .filter(|(_, e)| *e > now)
                        .map(|(r, _)| r)
                        .collect())
                }
            }
        })
    }

    fn wary_sweep(&mut self, now: u64) -> Result<(), StoreError> {
        self.sweep_expired(now)
    }

    fn size_bucket_sample(&mut self, bucket: u8) {
        let _ = self.bucket_bump(bucket);
    }

    fn size_bucket_counts(&self) -> [u64; 3] {
        self.bucket_counts().unwrap_or([0, 0, 0])
    }

    fn drain_get(&self) -> Result<bool, StoreError> {
        self.read(|txn| {
            let meta = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(meta
                .get("drain")
                .map_err(|e| StoreError::Backend(e.to_string()))?
                .map(|v| v.value() != 0)
                .unwrap_or(false))
        })
    }

    fn drain_set(&mut self, draining: bool) -> Result<(), StoreError> {
        self.write(|txn| {
            let mut meta = txn
                .open_table(META)
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            meta.insert("drain", if draining { 1 } else { 0 })
                .map_err(|e| StoreError::Backend(e.to_string()))?;
            Ok(())
        })
    }
}

impl RedbStore {
    /// Accept many custody entries in one write transaction, so the whole
    /// batch becomes durable with a single fsync — the group-commit pattern
    /// the custody path needs for custody throughput.
    pub fn custody_put_batch(&self, entries: &[CustodyEntry]) -> Result<(), StoreError> {
        self.write(|txn| {
            for entry in entries {
                let bytes =
                    serde_json::to_vec(entry).map_err(|e| StoreError::Backend(e.to_string()))?;
                let msg_len = entry.message.len() as i64;
                custody_put_txn(txn, entry.leg, bytes, msg_len)?;
            }
            Ok(())
        })
    }
}
