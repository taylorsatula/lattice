//! Range-based set reconciliation (V2_SPEC §6; after Meyer 2022 and Negentropy).
//!
//! Each side holds (id, scope, seq) triples for every known record.
//! They exchange count+sum fingerprints over half-open ranges of the id
//! space, split 16-way per round, until differing leaves hold at most
//! `LEAF_LIMIT` entries, which are listed explicitly. An unchanged network
//! converges in one small frame each way.
//!
//! Both sides run `respond` symmetrically per received ranges block. Entries
//! are echoed at most once per range per session, which is what terminates
//! the exchange; wants then drive a Records exchange.

use std::collections::HashSet;

use lattice_crypto::hash;
use lattice_proto::frames::Range;
use lattice_types::{Hash32, Identifier};

pub const LEAF_LIMIT: usize = 32;
const SPLIT: u64 = 16;
const MAX_RANGES_PER_MSG: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    pub id: Identifier,
    pub scope: u8,
    pub seq: u64,
}

impl Item {
    pub fn key(&self) -> (Identifier, u8) {
        (self.id, self.scope)
    }
    fn hash(&self) -> crate::u256::U256 {
        let mut h = Vec::with_capacity(41);
        h.extend_from_slice(self.id.as_ref());
        h.push(self.scope);
        h.extend_from_slice(&self.seq.to_le_bytes());
        crate::u256::U256::from_bytes(hash(&h).as_bytes())
    }
}

fn in_range(
    item: &Item,
    lower: &Option<(Identifier, u8)>,
    upper: &Option<(Identifier, u8)>,
) -> bool {
    let key = (item.id, item.scope);
    if let Some(l) = lower {
        if key < *l {
            return false;
        }
    }
    if let Some(u) = upper {
        if key >= *u {
            return false;
        }
    }
    true
}

type RangeBounds = (Option<(Identifier, u8)>, Option<(Identifier, u8)>);

fn range_parts(range: &Range) -> RangeBounds {
    match range {
        Range::Fingerprint { lower, upper, .. } | Range::Entries { lower, upper, .. } => {
            (*lower, *upper)
        }
    }
}

/// Split `range` into 16 id-space subranges. Bounds carry scope 0.
/// Returns None when the range is too narrow to split.
fn split(range: &Range) -> Option<Vec<Range>> {
    let (lower, upper) = range_parts(range);
    let lo_bytes = lower.map(|(id, _)| id);
    let hi_bytes = upper.map(|(id, _)| id);
    let lo = lo_bytes
        .map(|b| crate::u256::U256::from_bytes(b.as_bytes()))
        .unwrap_or_default();
    let hi = hi_bytes
        .map(|b| crate::u256::U256::from_bytes(b.as_bytes()))
        .unwrap_or_default(); // 0 == end of space
    let width = hi.sub(lo);
    let step = if width.is_zero() {
        if hi_bytes.is_none() && lo_bytes.is_none() {
            // full space: 2^252 per 1/16th
            let mut b = [0u8; 32];
            b[0] = 0x10;
            crate::u256::U256::from_bytes(&b)
        } else {
            return None;
        }
    } else {
        width.shr(4)
    };
    if step.is_zero() {
        return None;
    }
    let mut out = Vec::with_capacity(SPLIT as usize);
    for k in 0..SPLIT {
        #[allow(clippy::explicit_counter_loop)]
        let sub_lo = lo.add(step.mul_small(k));
        let is_last = k == SPLIT - 1;
        let lower_b = if k == 0 {
            lower
        } else {
            Some((Identifier::from_bytes(sub_lo.to_bytes()), 0))
        };
        let upper_b = if is_last {
            upper
        } else {
            Some((
                Identifier::from_bytes(lo.add(step.mul_small(k + 1)).to_bytes()),
                0,
            ))
        };
        out.push(Range::Fingerprint {
            lower: lower_b,
            upper: upper_b,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        });
    }
    Some(out)
}

pub fn fingerprint(items: &[Item], range: &Range) -> (u64, Hash32) {
    let (lower, upper) = range_parts(range);
    let mut count = 0u64;
    let mut sum = crate::u256::U256::default();
    for item in items {
        if in_range(item, &lower, &upper) {
            count += 1;
            sum = sum.add(item.hash());
        }
    }
    (count, Hash32::from_bytes(sum.to_bytes()))
}

pub fn entries_in(items: &[Item], range: &Range) -> Vec<Item> {
    let (lower, upper) = range_parts(range);
    items
        .iter()
        .filter(|i| in_range(i, &lower, &upper))
        .cloned()
        .collect()
}

/// Per-neighbor session state: an entry may be echoed once per range.
#[derive(Default)]
pub struct ReconcileSession {
    echoed: HashSet<String>,
}

impl ReconcileSession {
    pub fn new() -> Self {
        Self::default()
    }
    fn mark_echo(&mut self, range: &Range) -> bool {
        let (l, u) = range_parts(range);
        self.echoed.insert(format!("{l:?}:{u:?}"))
    }
}

fn with_fp(items: &[Item], r: &Range) -> Range {
    let (lower, upper) = range_parts(r);
    let (count, sum) = fingerprint(items, r);
    Range::Fingerprint {
        lower,
        upper,
        count,
        sum,
    }
}

/// Compute our reply to a peer's reconcile ranges, and the (id, scope)
/// pairs we want records for.
pub fn respond(
    items: &[Item],
    msgs: &[Range],
    session: &mut ReconcileSession,
) -> (Vec<Range>, Vec<(Identifier, u8)>) {
    let mut out = Vec::new();
    let mut wants = Vec::new();
    // A peer may not make us do unbounded work: cap the ranges we process
    // and the entries we echo per response.
    for m in msgs.iter().take(MAX_RANGES_PER_MSG) {
        // Reject inverted ranges before doing any arithmetic on them.
        let (lo, hi) = range_parts(m);
        if let (Some(l), Some(h)) = (lo, hi) {
            if l > h {
                continue;
            }
        }
        match m {
            Range::Fingerprint {
                lower,
                upper,
                count,
                sum,
            } => {
                let probe = Range::Fingerprint {
                    lower: *lower,
                    upper: *upper,
                    count: *count,
                    sum: *sum,
                };
                let (my_count, my_sum) = fingerprint(items, &probe);
                if my_count == *count && my_sum == *sum {
                    continue;
                }
                let my_items = entries_in(items, &probe);
                if my_items.len() <= LEAF_LIMIT {
                    session.mark_echo(&probe);
                    out.push(Range::Entries {
                        lower: *lower,
                        upper: *upper,
                        entries: my_items
                            .into_iter()
                            .map(|i| (i.id, i.scope, i.seq))
                            .collect(),
                    });
                } else if let Some(subs) = split(&probe) {
                    for sub in subs {
                        if out.len() >= MAX_RANGES_PER_MSG {
                            break;
                        }
                        out.push(with_fp(items, &sub));
                    }
                } else {
                    session.mark_echo(&probe);
                    out.push(Range::Entries {
                        lower: *lower,
                        upper: *upper,
                        entries: my_items
                            .into_iter()
                            .map(|i| (i.id, i.scope, i.seq))
                            .collect(),
                    });
                }
            }
            Range::Entries {
                lower,
                upper,
                entries,
            } => {
                let probe = Range::Entries {
                    lower: *lower,
                    upper: *upper,
                    entries: entries.clone(),
                };
                if session.mark_echo(&probe) {
                    let mine = entries_in(items, &probe);
                    if !mine.is_empty() {
                        out.push(Range::Entries {
                            lower: *lower,
                            upper: *upper,
                            entries: mine
                                .into_iter()
                                .take(LEAF_LIMIT)
                                .map(|i| (i.id, i.scope, i.seq))
                                .collect(),
                        });
                    }
                }
                for (id, scope, seq) in entries {
                    let want = match items.binary_search_by(|i| i.key().cmp(&(*id, *scope))) {
                        Ok(idx) => items[idx].seq < *seq,
                        Err(_) => true,
                    };
                    if want && wants.len() < MAX_RANGES_PER_MSG && !wants.contains(&(*id, *scope)) {
                        wants.push((*id, *scope));
                    }
                }
            }
        }
    }
    (out, wants)
}

/// The initiator's opening ranges.
pub fn initiate(items: &[Item]) -> Vec<Range> {
    vec![with_fp(
        items,
        &Range::Fingerprint {
            lower: None,
            upper: None,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(n: u8) -> Item {
        Item {
            id: Identifier::from_bytes([n; 32]),
            scope: 0,
            seq: n as u64,
        }
    }

    fn sorted(mut v: Vec<Item>) -> Vec<Item> {
        v.sort();
        v
    }

    #[test]
    fn split_covers_space() {
        let full = Range::Fingerprint {
            lower: None,
            upper: None,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        };
        let subs = split(&full).unwrap();
        assert_eq!(subs.len(), 16);
        for id in [0x00u8, 0x07, 0x10, 0x7f, 0x80, 0xfe, 0xff] {
            let id = Identifier::from_bytes([id; 32]);
            let hits = subs
                .iter()
                .filter(|r| {
                    range_parts(r).0.map(|(l, _)| l <= id).unwrap_or(true)
                        && range_parts(r).1.map(|(u, _)| id < u).unwrap_or(true)
                })
                .count();
            assert_eq!(hits, 1, "id {id:?} covered by {hits} subranges");
        }
    }

    #[test]
    fn fingerprint_detects_differences() {
        let a = vec![item(1), item(2), item(3)];
        let b = vec![item(1), item(2), item(4)];
        let full = Range::Fingerprint {
            lower: None,
            upper: None,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        };
        assert_ne!(fingerprint(&a, &full), fingerprint(&b, &full));
    }

    type Wants = Vec<(Identifier, u8)>;
    fn reconcile_pair(a: &[Item], b: &[Item]) -> (Wants, Wants) {
        let mut a_msg = initiate(a);
        let mut a_wants = Vec::new();
        let mut b_wants = Vec::new();
        let mut sa = ReconcileSession::new();
        let mut sb = ReconcileSession::new();
        for _ in 0..64 {
            let (b_out, bw) = respond(b, &a_msg, &mut sb);
            b_wants.extend(bw);
            let (a_out, aw) = respond(a, &b_out, &mut sa);
            a_wants.extend(aw);
            if a_out.is_empty() && b_out.is_empty() {
                break;
            }
            a_msg = a_out;
        }
        (a_wants, b_wants)
    }

    #[test]
    fn reconcile_finds_missing_items() {
        let a = sorted(vec![item(1), item(2), item(3)]);
        let b = sorted(vec![item(2), item(3), item(4)]);
        let (a_wants, b_wants) = reconcile_pair(&a, &b);
        assert!(a_wants.contains(&(Identifier::from_bytes([4u8; 32]), 0)));
        assert!(b_wants.contains(&(Identifier::from_bytes([1u8; 32]), 0)));
    }

    #[test]
    fn reconcile_identical_sets() {
        let a = sorted(vec![item(1), item(2), item(3)]);
        let b = a.clone();
        let (a_wants, b_wants) = reconcile_pair(&a, &b);
        assert!(a_wants.is_empty() && b_wants.is_empty());
    }

    #[test]
    fn large_sets_reconcile() {
        let base: Vec<Item> = (0u16..300)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = (i >> 8) as u8;
                id[1] = i as u8;
                Item {
                    id: Identifier::from_bytes(id),
                    scope: 0,
                    seq: 1,
                }
            })
            .collect();
        let mut a = base.clone();
        a.push(Item {
            id: Identifier::from_bytes([0xde; 32]),
            scope: 0,
            seq: 1,
        });
        let mut b = base;
        b.push(Item {
            id: Identifier::from_bytes([0xad; 32]),
            scope: 0,
            seq: 1,
        });
        a.sort();
        b.sort();
        let (a_wants, b_wants) = reconcile_pair(&a, &b);
        assert!(a_wants.contains(&(Identifier::from_bytes([0xad; 32]), 0)));
        assert!(b_wants.contains(&(Identifier::from_bytes([0xde; 32]), 0)));
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn item(n: u8) -> Item {
        Item {
            id: Identifier::from_bytes([n; 32]),
            scope: 0,
            seq: n as u64,
        }
    }

    #[test]
    fn oversized_range_list_is_truncated() {
        // A peer sending 500 ranges gets at most MAX_RANGES_PER_MSG processed.
        let items = vec![item(1)];
        let msgs: Vec<Range> = (0..500)
            .map(|_| Range::Fingerprint {
                lower: None,
                upper: None,
                count: 0,
                sum: Hash32::from_bytes([0; 32]),
            })
            .collect();
        let mut session = ReconcileSession::new();
        let (out, _wants) = respond(&items, &msgs, &mut session);
        // 64 processed ranges, one output each (all mismatch), capped at 64.
        assert!(out.len() <= MAX_RANGES_PER_MSG);
    }

    #[test]
    fn entries_echo_is_capped_at_leaf_limit() {
        // Peer sends an Entries range covering 100 of our items; we must
        // echo at most LEAF_LIMIT of them.
        let items: Vec<Item> = (0..100u8).map(item).collect();
        let entries: Vec<(Identifier, u8, u64)> =
            items.iter().map(|i| (i.id, i.scope, i.seq)).collect();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries,
        }];
        let mut session = ReconcileSession::new();
        let (out, _wants) = respond(&items, &msgs, &mut session);
        let echoed: usize = out
            .iter()
            .map(|r| match r {
                Range::Entries { entries, .. } => entries.len(),
                _ => 0,
            })
            .sum();
        assert!(echoed <= LEAF_LIMIT, "echoed {echoed} entries");
    }

    #[test]
    fn wants_are_capped() {
        let items: Vec<Item> = vec![];
        let entries: Vec<(Identifier, u8, u64)> = (0..200u16)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..2].copy_from_slice(&i.to_be_bytes());
                (Identifier::from_bytes(id), 0u8, 1u64)
            })
            .collect();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries,
        }];
        let mut session = ReconcileSession::new();
        let (_out, wants) = respond(&items, &msgs, &mut session);
        assert!(wants.len() <= MAX_RANGES_PER_MSG);
    }
}
