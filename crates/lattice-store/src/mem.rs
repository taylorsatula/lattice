//! In-memory Store. Used by the simulator and tests; redb lands in Phase 3.

use std::collections::HashMap;

use crate::*;

#[derive(Default)]
pub struct MemStore {
    records: HashMap<([u8; 32], u8), (Vec<u8>, u64)>,
    kel_heads: HashMap<[u8; 32], (u64, [u8; 32], u64)>,
    saved_peers: HashMap<[u8; 32], String>,
    outbound: HashMap<[u8; 16], OutboundMessage>,
    custody: HashMap<[u8; 16], CustodyEntry>,
    shares: HashMap<([u8; 32], u64), u64>,
    seen: HashMap<[u8; 32], u64>,
    delivered: HashMap<[u8; 32], u64>,
    inbox: HashMap<String, Vec<InboxEntry>>,
    status: HashMap<[u8; 16], (u64, Option<u64>)>,
    wary: HashMap<[u8; 32], Vec<(u64, u64)>>, // id -> [(source_range, exp)]
    buckets: [u64; 3],
    custody_bytes: u64,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
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
    fn record_get(
        &self,
        id: &[u8; 32],
        scope: Scope,
    ) -> Result<Option<(Vec<u8>, u64)>, StoreError> {
        Ok(self.records.get(&(*id, scope_key(scope))).cloned())
    }
    fn record_put(
        &mut self,
        id: &[u8; 32],
        scope: Scope,
        bytes: &[u8],
        received: u64,
    ) -> Result<(), StoreError> {
        self.records
            .insert((*id, scope_key(scope)), (bytes.to_vec(), received));
        Ok(())
    }
    fn record_remove(&mut self, id: &[u8; 32], scope: Scope) -> Result<(), StoreError> {
        self.records.remove(&(*id, scope_key(scope)));
        Ok(())
    }
    fn record_all(&self) -> Result<Vec<([u8; 32], Scope, Vec<u8>, u64)>, StoreError> {
        Ok(self
            .records
            .iter()
            .map(|((id, s), (b, t))| (*id, scope_of(*s), b.clone(), *t))
            .collect())
    }
    fn record_count(&self) -> Result<usize, StoreError> {
        Ok(self.records.len())
    }

    fn kel_head(&self, id: &[u8; 32]) -> Result<Option<(u64, [u8; 32], u64)>, StoreError> {
        Ok(self.kel_heads.get(id).copied())
    }
    fn kel_head_put(
        &mut self,
        id: &[u8; 32],
        seq: u64,
        commitment: [u8; 32],
        seen: u64,
    ) -> Result<(), StoreError> {
        self.kel_heads.insert(*id, (seq, commitment, seen));
        Ok(())
    }

    fn peer_save(&mut self, id: &[u8; 32], address: &str) -> Result<(), StoreError> {
        self.saved_peers.insert(*id, address.to_string());
        Ok(())
    }
    fn peer_saved(&self) -> Result<Vec<([u8; 32], String)>, StoreError> {
        Ok(self
            .saved_peers
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect())
    }

    fn outbound_push(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound.insert(msg.mid, msg.clone());
        Ok(())
    }
    fn outbound_get(&self, mid: &[u8; 16]) -> Result<Option<OutboundMessage>, StoreError> {
        Ok(self.outbound.get(mid).cloned())
    }
    fn outbound_put(&mut self, msg: &OutboundMessage) -> Result<(), StoreError> {
        self.outbound.insert(msg.mid, msg.clone());
        Ok(())
    }
    fn outbound_due(&self, now: u64) -> Result<Vec<OutboundMessage>, StoreError> {
        let mut due: Vec<_> = self
            .outbound
            .values()
            .filter(|m| m.state == OutboundState::Queued && m.next_attempt <= now && m.exp > now)
            .cloned()
            .collect();
        due.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(a.next_attempt.cmp(&b.next_attempt))
        });
        Ok(due)
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
        if let Some(old) = self.custody.insert(entry.leg, entry) {
            self.custody_bytes = self.custody_bytes.saturating_sub(old.message.len() as u64);
        }
        self.custody_bytes += new_len;
        Ok(())
    }
    fn custody_get(&self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError> {
        Ok(self.custody.get(leg).cloned())
    }
    fn custody_remove(&mut self, leg: &[u8; 16]) -> Result<Option<CustodyEntry>, StoreError> {
        let removed = self.custody.remove(leg);
        if let Some(e) = &removed {
            self.custody_bytes = self.custody_bytes.saturating_sub(e.message.len() as u64);
        }
        Ok(removed)
    }
    fn custody_all(&self) -> Result<Vec<CustodyEntry>, StoreError> {
        Ok(self.custody.values().cloned().collect())
    }
    fn custody_bytes(&self) -> Result<u64, StoreError> {
        Ok(self.custody_bytes)
    }

    fn share_add(&mut self, dest: &[u8; 32], upstream: u64, bytes: i64) -> Result<u64, StoreError> {
        let e = self.shares.entry((*dest, upstream)).or_insert(0);
        let next = (*e as i64)
            .checked_add(bytes)
            .ok_or(StoreError::Backend("share counter overflow".into()))?;
        if next < 0 {
            return Err(StoreError::Backend("share counter underflow".into()));
        }
        *e = next as u64;
        Ok(*e)
    }
    fn share_get(&self, dest: &[u8; 32], upstream: u64) -> Result<u64, StoreError> {
        Ok(*self.shares.get(&(*dest, upstream)).unwrap_or(&0))
    }

    fn seen_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError> {
        Ok(self.seen.get(hash).is_some_and(|exp| *exp > now))
    }
    fn seen_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError> {
        self.seen.insert(hash, exp);
        Ok(())
    }
    fn delivered_contains(&self, hash: &[u8; 32], now: u64) -> Result<bool, StoreError> {
        Ok(self.delivered.get(hash).is_some_and(|exp| *exp > now))
    }
    fn delivered_add(&mut self, hash: [u8; 32], exp: u64) -> Result<(), StoreError> {
        self.delivered.insert(hash, exp);
        Ok(())
    }
    fn sweep_expired(&mut self, now: u64) -> Result<(), StoreError> {
        self.seen.retain(|_, exp| *exp > now);
        self.delivered.retain(|_, exp| *exp > now);
        self.wary
            .values_mut()
            .for_each(|v| v.retain(|(_, exp)| *exp > now));
        self.wary.retain(|_, v| !v.is_empty());
        Ok(())
    }

    fn inbox_push(&mut self, service: &str, entry: InboxEntry) -> Result<(), StoreError> {
        self.inbox
            .entry(service.to_string())
            .or_default()
            .push(entry);
        Ok(())
    }
    fn inbox_fetch(&self, service: &str, max: usize) -> Result<Vec<InboxEntry>, StoreError> {
        Ok(self
            .inbox
            .get(service)
            .into_iter()
            .flatten()
            .take(max)
            .cloned()
            .collect())
    }
    fn inbox_ack(&mut self, service: &str, delivery_ids: &[[u8; 16]]) -> Result<usize, StoreError> {
        let Some(entries) = self.inbox.get_mut(service) else {
            return Ok(0);
        };
        let before = entries.len();
        entries.retain(|e| !delivery_ids.contains(&e.delivery_id));
        Ok(before - entries.len())
    }
    fn inbox_len(&self, service: &str) -> Result<u64, StoreError> {
        Ok(self.inbox.get(service).map(|v| v.len() as u64).unwrap_or(0))
    }

    fn status_set(
        &mut self,
        mid: &[u8; 16],
        status: u64,
        detail: Option<u64>,
    ) -> Result<(), StoreError> {
        self.status.insert(*mid, (status, detail));
        Ok(())
    }
    fn status_get(&self, mid: &[u8; 16]) -> Result<Option<(u64, Option<u64>)>, StoreError> {
        Ok(self.status.get(mid).copied())
    }

    fn wary_add(&mut self, id: &[u8; 32], source_range: u64, exp: u64) -> Result<(), StoreError> {
        let entry = self.wary.entry(*id).or_default();
        // keep at most one entry per source range, latest wins
        entry.retain(|(r, _)| *r != source_range);
        entry.push((source_range, exp));
        Ok(())
    }
    fn wary_ranges(&self, id: &[u8; 32], now: u64) -> Result<Vec<u64>, StoreError> {
        Ok(self
            .wary
            .get(id)
            .map(|v| {
                v.iter()
                    .filter(|(_, e)| *e > now)
                    .map(|(r, _)| *r)
                    .collect()
            })
            .unwrap_or_default())
    }
    fn wary_sweep(&mut self, now: u64) -> Result<(), StoreError> {
        self.sweep_expired(now)
    }

    fn size_bucket_sample(&mut self, bucket: u8) {
        if (bucket as usize) < 3 {
            self.buckets[bucket as usize] += 1;
        }
    }
    fn size_bucket_counts(&self) -> [u64; 3] {
        self.buckets
    }
}
