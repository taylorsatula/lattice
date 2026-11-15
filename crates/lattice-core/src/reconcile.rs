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
use lattice_proto::frames::{Range, RangeBound, RangeBounds, RecordEntry, RecordRef};
use lattice_types::{Hash32, Identifier};

pub const LEAF_LIMIT: usize = 32;
const SPLIT: u64 = 16;
const MAX_RANGES_PER_MSG: usize = 64;

/// A reconcile item: a record's (id, scope, seq). Alias for the wire
/// type so the reconcile code and the frames share one definition.
pub type Item = RecordEntry;

impl ItemExt for RecordEntry {
    fn hash(&self) -> crate::u256::U256 {
        let mut h = Vec::with_capacity(41);
        h.extend_from_slice(self.id.as_ref());
        h.push(self.scope);
        h.extend_from_slice(&self.seq.to_le_bytes());
        crate::u256::U256::from_bytes(hash(&h).as_bytes())
    }
}

/// Hashing for reconcile items. Implemented as an extension trait because
/// `Item` is an alias for the proto crate's `RecordEntry`.
trait ItemExt {
    fn hash(&self) -> crate::u256::U256;
}

fn in_range(item: &Item, lower: &Option<RangeBound>, upper: &Option<RangeBound>) -> bool {
    let key = (item.id, item.scope);
    if let Some(l) = lower {
        if key < (l.id, l.scope) {
            return false;
        }
    }
    if let Some(u) = upper {
        if key >= (u.id, u.scope) {
            return false;
        }
    }
    true
}

fn range_parts(range: &Range) -> RangeBounds {
    match range {
        Range::Fingerprint { lower, upper, .. } | Range::Entries { lower, upper, .. } => {
            RangeBounds {
                lower: *lower,
                upper: *upper,
            }
        }
    }
}

/// Split `range` into 16 id-space subranges. Bounds carry scope 0.
/// Returns None when the range is too narrow to split.
fn split(range: &Range) -> Option<Vec<Range>> {
    let RangeBounds { lower, upper } = range_parts(range);
    let lo_bytes = lower.map(|b| b.id);
    let hi_bytes = upper.map(|b| b.id);
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
            Some(RangeBound {
                id: Identifier::from_bytes(sub_lo.to_bytes()),
                scope: 0,
            })
        };
        let upper_b = if is_last {
            upper
        } else {
            Some(RangeBound {
                id: Identifier::from_bytes(lo.add(step.mul_small(k + 1)).to_bytes()),
                scope: 0,
            })
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

/// Count and XOR-sum of the items in a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub count: u64,
    pub sum: Hash32,
}

pub fn fingerprint(items: &[Item], range: &Range) -> Fingerprint {
    let RangeBounds { lower, upper } = range_parts(range);
    let mut count = 0u64;
    let mut sum = crate::u256::U256::default();
    for item in items {
        if in_range(item, &lower, &upper) {
            count += 1;
            sum = sum.add(item.hash());
        }
    }
    Fingerprint {
        count,
        sum: Hash32::from_bytes(sum.to_bytes()),
    }
}

pub fn entries_in(items: &[Item], range: &Range) -> Vec<Item> {
    let RangeBounds { lower, upper } = range_parts(range);
    items
        .iter()
        .filter(|i| in_range(i, &lower, &upper))
        .cloned()
        .collect()
}

/// Whether a range has been echoed before in this session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EchoMark {
    /// First time this range is echoed.
    Fresh,
    /// This range was already echoed; do not echo it again.
    Seen,
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
    /// Record that `range` has been echoed; reports whether this is the
    /// first time.
    fn note_echo(&mut self, range: &Range) -> EchoMark {
        let RangeBounds { lower, upper } = range_parts(range);
        if self.echoed.insert(format!("{lower:?}:{upper:?}")) {
            EchoMark::Fresh
        } else {
            EchoMark::Seen
        }
    }
}

fn with_fp(items: &[Item], r: &Range) -> Range {
    let RangeBounds { lower, upper } = range_parts(r);
    let fp = fingerprint(items, r);
    Range::Fingerprint {
        lower,
        upper,
        count: fp.count,
        sum: fp.sum,
    }
}

/// The result of answering a peer's reconcile ranges: the ranges to send
/// back, and the records we want from the peer.
pub struct ReconcileResponse {
    pub ranges: Vec<Range>,
    pub wants: Vec<RecordRef>,
}

/// Compute our reply to a peer's reconcile ranges, and the (id, scope)
/// pairs we want records for.
pub fn respond(
    items: &[Item],
    msgs: &[Range],
    session: &mut ReconcileSession,
) -> ReconcileResponse {
    let mut out = Vec::new();
    let mut wants: Vec<RecordRef> = Vec::new();
    // A peer may not make us do unbounded work: cap the ranges we process
    // and the entries we echo per response.
    for m in msgs.iter().take(MAX_RANGES_PER_MSG) {
        // Reject inverted ranges before doing any arithmetic on them.
        let RangeBounds { lower, upper } = range_parts(m);
        if let (Some(l), Some(h)) = (lower, upper) {
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
                let mine = fingerprint(items, &probe);
                if mine.count == *count && mine.sum == *sum {
                    continue;
                }
                let my_items = entries_in(items, &probe);
                if my_items.len() <= LEAF_LIMIT {
                    session.note_echo(&probe);
                    out.push(Range::Entries {
                        lower: *lower,
                        upper: *upper,
                        entries: my_items,
                    });
                } else if let Some(subs) = split(&probe) {
                    for sub in subs {
                        if out.len() >= MAX_RANGES_PER_MSG {
                            break;
                        }
                        out.push(with_fp(items, &sub));
                    }
                } else {
                    session.note_echo(&probe);
                    out.push(Range::Entries {
                        lower: *lower,
                        upper: *upper,
                        entries: my_items,
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
                if session.note_echo(&probe) == EchoMark::Fresh {
                    let mine = entries_in(items, &probe);
                    if !mine.is_empty() {
                        out.push(Range::Entries {
                            lower: *lower,
                            upper: *upper,
                            entries: mine.into_iter().take(LEAF_LIMIT).collect(),
                        });
                    }
                }
                for entry in entries {
                    let key = entry.key();
                    let want = match items.binary_search_by(|i| i.key().cmp(&key)) {
                        Ok(idx) => items[idx].seq < entry.seq,
                        Err(_) => true,
                    };
                    if want && wants.len() < MAX_RANGES_PER_MSG && !wants.contains(&key) {
                        wants.push(key);
                    }
                }
            }
        }
    }
    ReconcileResponse { ranges: out, wants }
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
                    let b = range_parts(r);
                    b.lower.map(|l| l.id <= id).unwrap_or(true)
                        && b.upper.map(|u| id < u.id).unwrap_or(true)
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

    type Wants = Vec<RecordRef>;
    fn reconcile_pair(a: &[Item], b: &[Item]) -> (Wants, Wants) {
        let mut a_msg = initiate(a);
        let mut a_wants = Vec::new();
        let mut b_wants = Vec::new();
        let mut sa = ReconcileSession::new();
        let mut sb = ReconcileSession::new();
        for _ in 0..64 {
            let b_resp = respond(b, &a_msg, &mut sb);
            b_wants.extend(b_resp.wants);
            let a_resp = respond(a, &b_resp.ranges, &mut sa);
            a_wants.extend(a_resp.wants);
            if a_resp.ranges.is_empty() && b_resp.ranges.is_empty() {
                break;
            }
            a_msg = a_resp.ranges;
        }
        (a_wants, b_wants)
    }

    #[test]
    fn reconcile_finds_missing_items() {
        let a = sorted(vec![item(1), item(2), item(3)]);
        let b = sorted(vec![item(2), item(3), item(4)]);
        let (a_wants, b_wants) = reconcile_pair(&a, &b);
        assert!(a_wants.contains(&RecordRef {
            id: Identifier::from_bytes([4u8; 32]),
            scope: 0,
        }));
        assert!(b_wants.contains(&RecordRef {
            id: Identifier::from_bytes([1u8; 32]),
            scope: 0,
        }));
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
        assert!(a_wants.contains(&RecordRef {
            id: Identifier::from_bytes([0xad; 32]),
            scope: 0,
        }));
        assert!(b_wants.contains(&RecordRef {
            id: Identifier::from_bytes([0xde; 32]),
            scope: 0,
        }));
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
        let resp = respond(&items, &msgs, &mut session);
        // 64 processed ranges, one output each (all mismatch), capped at 64.
        assert!(resp.ranges.len() <= MAX_RANGES_PER_MSG);
    }

    #[test]
    fn entries_echo_is_capped_at_leaf_limit() {
        // Peer sends an Entries range covering 100 of our items; we must
        // echo at most LEAF_LIMIT of them.
        let items: Vec<Item> = (0..100u8).map(item).collect();
        let entries: Vec<RecordEntry> = items
            .iter()
            .map(|i| RecordEntry {
                id: i.id,
                scope: i.scope,
                seq: i.seq,
            })
            .collect();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries,
        }];
        let mut session = ReconcileSession::new();
        let resp = respond(&items, &msgs, &mut session);
        let echoed: usize = resp
            .ranges
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
        let entries: Vec<RecordEntry> = (0..200u16)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..2].copy_from_slice(&i.to_be_bytes());
                RecordEntry {
                    id: Identifier::from_bytes(id),
                    scope: 0,
                    seq: 1,
                }
            })
            .collect();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries,
        }];
        let mut session = ReconcileSession::new();
        let resp = respond(&items, &msgs, &mut session);
        assert!(resp.wants.len() <= MAX_RANGES_PER_MSG);
    }
}
