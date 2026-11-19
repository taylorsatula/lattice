//! In-memory Store. Used by the simulator and tests; the daemon uses the
//! redb-backed `RedbStore`. Behavior is contract-tested for equivalence
//! with the redb backend.

use std::collections::BTreeMap;

use crate::*;
use lattice_proto::local::DrainState;
use lattice_types::{DeliveryId, Hash32, Identifier, LegId, MessageId};

#[derive(Default)]
pub struct MemStore {
    records: BTreeMap<(Identifier, u8), RecordBytes>,
    kel_heads: BTreeMap<Identifier, KelHeadSeen>,
    kels: BTreeMap<Identifier, Vec<u8>>,
    outbound: BTreeMap<MessageId, OutboundMessage>,
    custody: BTreeMap<LegId, CustodyEntry>,
    shares: BTreeMap<(Identifier, u64), u64>,
    seen: BTreeMap<Hash32, u64>,
    seen_unheld: BTreeMap<Hash32, u64>,
    delivered: BTreeMap<Hash32, u64>,
    inbox: BTreeMap<String, Vec<InboxEntry>>,
    status: BTreeMap<MessageId, (MessageStatus, u64)>,
    buckets: [u64; 4],
    custody_bytes: u64,
    custody_class_bytes: [u64; CLASS_SLOTS],
    drain: DrainState,
    next_link_id: u64,
}

impl MemStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_link_id: LINK_ID_BASE,
            ..Self::default()
        }
    }
}

fn scope_key(s: Scope) -> u8 {
    match s {
        Scope::Wan => 0,
        Scope::Hive => 1,
    }
}

fn scope_of(b: u8) -> Scope {
    if b == 0 { Scope::Wan } else { Scope::Hive }
}

impl Store for MemStore {
    fn record_get(&self, id: &Identifier, scope: Scope) -> Result<Option<RecordBytes>, StoreError> {
        Ok(self.records.get(&(*id, scope_key(scope))).cloned())
    }
    fn record_put(
        &mut self,
        id: &Identifier,
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError> {
        self.records.insert(
            (*id, scope_key(scope)),
            RecordBytes {
                bytes: bytes.to_vec(),
                received,
            },
        );
        Ok(())
    }
    fn record_remove(&mut self, id: &Identifier, scope: Scope) -> Result<(), StoreError> {
        self.records.remove(&(*id, scope_key(scope)));
        Ok(())
    }
    fn record_all(&self) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .records
            .iter()
            .map(|((id, s), rb)| StoredRecord {
                id: *id,
                scope: scope_of(*s),
                bytes: rb.bytes.clone(),
                received: rb.received,
            })
            .collect())
    }
    fn record_count(&self) -> Result<usize, StoreError> {
        Ok(self.records.len())
    }

    fn kel_head(&self, id: &Identifier) -> Result<Option<KelHeadSeen>, StoreError> {
        Ok(self.kel_heads.get(id).copied())
    }
    fn kel_put(
        &mut self,
        id: &Identifier,
        bytes: &[u8],
        head: &KelHeadSeen,
    ) -> Result<(), StoreError> {
        self.kels.insert(*id, bytes.to_vec());
        self.kel_heads.insert(*id, *head);
        Ok(())
    }
    fn kel_get(&self, id: &Identifier) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.kels.get(id).cloned())
    }
    fn kel_heads_all(&self) -> Result<Vec<(Identifier, KelHeadSeen)>, StoreError> {
        Ok(self.kel_heads.iter().map(|(k, v)| (*k, *v)).collect())
    }
    fn kel_touch(&mut self, id: &Identifier, seen: u64) -> Result<(), StoreError> {
        if let Some(h) = self.kel_heads.get_mut(id) {
            h.seen = seen;
        }
        Ok(())
    }
    fn kel_sweep(&mut self, older_than: u64) -> Result<usize, StoreError> {
        let before = self.kel_heads.len();
        let stale: Vec<Identifier> = self
            .kel_heads
            .iter()
            .filter(|(_, h)| h.seen < older_than)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale {
            self.kel_heads.remove(id);
            self.kels.remove(id);
        }
        Ok(before - self.kel_heads.len())
    }

    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound.insert(msg.mid, msg.clone());
        Ok(())
    }
    fn outbound_remove(&mut self, mid: &MessageId) -> Result<(), StoreError> {
        self.outbound.remove(mid);
        Ok(())
    }
    fn outbound_get(&self, mid: &MessageId) -> Result<Option<OutboundMessage>, StoreError> {
        Ok(self.outbound.get(mid).cloned())
    }
    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound.insert(msg.mid, msg.clone());
        Ok(())
    }
    fn outbound_all(&self) -> Result<Vec<OutboundMessage>, StoreError> {
        Ok(self.outbound.values().cloned().collect())
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
        self.custody_put(entry)?;
        self.share_add(&share_dest, share_upstream, share_bytes)?;
        self.seen_add(seen_hash, seen_exp)?;
        Ok(())
    }
    fn custody_put(&mut self, entry: CustodyEntry) -> Result<(), StoreError> {
        let new_len = entry.message.len() as u64;
        let new_class = entry.class.min((CLASS_SLOTS - 1) as u8) as usize;
        if let Some(old) = self.custody.insert(entry.leg, entry) {
            self.custody_bytes = self.custody_bytes.saturating_sub(old.message.len() as u64);
            let old_class = old.class.min((CLASS_SLOTS - 1) as u8) as usize;
            self.custody_class_bytes[old_class] =
                self.custody_class_bytes[old_class].saturating_sub(old.message.len() as u64);
        }
        self.custody_bytes += new_len;
        self.custody_class_bytes[new_class] += new_len;
        Ok(())
    }
    fn custody_get(&self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError> {
        Ok(self.custody.get(leg).cloned())
    }
    fn custody_release(&mut self, leg: &LegId) -> Result<Option<CustodyEntry>, StoreError> {
        let removed = self.custody.remove(leg);
        if let Some(e) = &removed {
            self.custody_bytes = self.custody_bytes.saturating_sub(e.message.len() as u64);
            let class = e.class.min((CLASS_SLOTS - 1) as u8) as usize;
            self.custody_class_bytes[class] =
                self.custody_class_bytes[class].saturating_sub(e.message.len() as u64);
            // Release the upstream's share in the same operation.
            let key = (e.destination, e.upstream);
            if let Some(share) = self.shares.get_mut(&key) {
                let next = (*share as i64) - e.message.len() as i64;
                if next <= 0 {
                    self.shares.remove(&key);
                } else {
                    *share = next as u64;
                }
            }
        }
        Ok(removed)
    }
    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError> {
        Ok(self.custody.values().cloned().collect())
    }
    fn custody_bytes(&self) -> Result<u64, StoreError> {
        Ok(self.custody_bytes)
    }
    fn custody_class_bytes(&self) -> Result<[u64; CLASS_SLOTS], StoreError> {
        Ok(self.custody_class_bytes)
    }

    fn share_add(
        &mut self,
        dest: &Identifier,
        upstream: u64,
        bytes: i64,
    ) -> Result<u64, StoreError> {
        let e = self.shares.entry((*dest, upstream)).or_insert(0);
        let next = (*e as i64)
            .checked_add(bytes)
            .ok_or_else(|| StoreError::CounterOverflow("share".into()))?;
        if next < 0 {
            return Err(StoreError::CounterUnderflow("share".into()));
        }
        *e = next as u64;
        Ok(*e)
    }
    fn share_get(&self, dest: &Identifier, upstream: u64) -> Result<u64, StoreError> {
        Ok(*self.shares.get(&(*dest, upstream)).unwrap_or(&0))
    }
    fn share_upstream_count(&self, dest: &Identifier) -> Result<u64, StoreError> {
        Ok(self.shares.keys().filter(|(d, _)| d == dest).count() as u64)
    }
    fn alloc_link_id(&mut self) -> Result<u64, StoreError> {
        let id = self.next_link_id;
        self.next_link_id = self
            .next_link_id
            .checked_add(1)
            .ok_or_else(|| StoreError::CounterOverflow("link id".into()))?;
        Ok(id)
    }

    fn seen_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        Ok(self.seen.get(hash).is_some_and(|exp| *exp > now))
    }
    fn seen_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.seen.insert(hash, exp);
        Ok(())
    }
    fn seen_unheld_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.seen_unheld.insert(hash, exp);
        Ok(())
    }
    fn seen_unheld_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        Ok(self.seen_unheld.get(hash).is_some_and(|exp| *exp > now))
    }
    fn delivered_contains(&self, hash: &Hash32, now: u64) -> Result<bool, StoreError> {
        Ok(self.delivered.get(hash).is_some_and(|exp| *exp > now))
    }
    fn delivered_add(&mut self, hash: Hash32, exp: u64) -> Result<(), StoreError> {
        self.delivered.insert(hash, exp);
        Ok(())
    }
    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError> {
        self.seen.retain(|_, exp| *exp > now);
        self.seen_unheld.retain(|_, exp| *exp > now);
        self.delivered.retain(|_, exp| *exp > now);
        self.status
            .retain(|_, (_, set_at)| set_at.saturating_add(STATUS_TTL_SECS) > now);
        Ok(())
    }

    fn inbox_push(&mut self, entry: InboxEntry) -> Result<(), StoreError> {
        self.inbox
            .entry(entry.tsvc.clone())
            .or_default()
            .push(entry);
        Ok(())
    }
    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError> {
        // Match the redb backend's (received, delivery_id) order rather than
        // bare insertion order, so ties on `received` break by delivery id.
        let mut entries: Vec<InboxEntry> = self
            .inbox
            .get(service)
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        entries.sort_by(|a, b| {
            a.received
                .cmp(&b.received)
                .then(a.delivery_id.cmp(&b.delivery_id))
        });
        entries.truncate(max);
        Ok(entries)
    }
    fn inbox_ack(
        &mut self,
        service: &str,
        delivery_ids: &[DeliveryId],
    ) -> Result<usize, StoreError> {
        let Some(entries) = self.inbox.get_mut(service) else {
            return Ok(0);
        };
        let before = entries.len();
        entries.retain(|e| !delivery_ids.contains(&e.delivery_id));
        Ok(before - entries.len())
    }
    fn inbox_len(&self, service: &str) -> Result<u64, StoreError> {
        Ok(self.inbox.get(service).map_or(0, |v| v.len() as u64))
    }
    fn inbox_len_total(&self) -> Result<u64, StoreError> {
        Ok(self.inbox.values().map(|v| v.len() as u64).sum())
    }
    fn inbox_sweep_expired(&mut self, max_age_secs: u64, now: u64) -> Result<u64, StoreError> {
        let mut dropped = 0u64;
        for entries in self.inbox.values_mut() {
            let before = entries.len();
            entries.retain(|e| e.received.saturating_add(max_age_secs) > now);
            dropped += (before - entries.len()) as u64;
        }
        self.inbox.retain(|_, v| !v.is_empty());
        Ok(dropped)
    }

    fn status_set(
        &mut self,
        mid: &MessageId,
        status: u64,
        detail: Option<u64>,
        now: u64,
    ) -> Result<(), StoreError> {
        self.status
            .insert(*mid, (MessageStatus { status, detail }, now));
        Ok(())
    }
    fn status_get(&self, mid: &MessageId) -> Result<Option<MessageStatus>, StoreError> {
        Ok(self.status.get(mid).map(|(s, _)| *s))
    }

    fn size_bucket_sample(&mut self, bucket: u8) -> Result<(), StoreError> {
        self.buckets[bucket.min(3) as usize] += 1;
        Ok(())
    }
    fn size_bucket_counts(&self) -> Result<[u64; 4], StoreError> {
        Ok(self.buckets)
    }

    fn drain_get(&self) -> Result<DrainState, StoreError> {
        Ok(self.drain)
    }
    fn drain_set(&mut self, state: DrainState) -> Result<(), StoreError> {
        self.drain = state;
        Ok(())
    }
}
