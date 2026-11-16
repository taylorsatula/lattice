//! Range-based set reconciliation (V2_SPEC §6; after Meyer 2022 and Negentropy).
//!
//! Each side holds (id, scope, khs, seq, hash-prefix) entries for every
//! known record and KEL (KELs are scope 255). They exchange count+sum
//! fingerprints over half-open ranges of the id space, split 16-way per
//! round, until differing leaves hold at most `LEAF_LIMIT` entries, which
//! are listed explicitly. An unchanged network converges in one small frame
//! each way.
//!
//! A range is listed explicitly only when *both* sides hold at most
//! `LEAF_LIMIT` entries in it; otherwise it is split, so an empty side never
//! answers a differing range with a (useless) empty list while the peer
//! holds thousands. Entries are never truncated: a range that cannot be
//! split is listed in full.
//!
//! Both sides run `respond` symmetrically per received ranges block. Entries
//! are echoed at most once per range per session, which is what terminates
//! the exchange; wants then drive a Records/Kels exchange. A session covers
//! one round: the caller resets it when a frame opens a new round (see
//! [`opens_new_round`]).
//!
//! `items` passed to [`respond`], [`fingerprint`] and [`entries_in`] must be
//! sorted by (id, scope); the range slicing relies on it.

use std::collections::HashSet;

use lattice_crypto::hash;
use lattice_proto::frames::{Range, RangeBound, RangeBounds, RecordEntry, RecordRef};
use lattice_types::{Hash32, Identifier};

pub const LEAF_LIMIT: usize = 32;
const SPLIT: u64 = 16;
pub const MAX_RANGES_PER_MSG: usize = 64;

/// A reconcile item: a record's or KEL's (id, scope, khs, seq, hash-prefix).
/// Alias for the wire type so the reconcile code and the frames share one
/// definition. For a KEL entry, `khs` and `seq` are both the head sn and
/// `hash_prefix` is the first 8 bytes of the head event's event hash.
pub type Item = RecordEntry;

impl ItemExt for RecordEntry {
    /// The item hash (spec §6): BLAKE3(id ‖ scope ‖ khs ‖ seq ‖ hash-prefix),
    /// with `scope` a single byte, `khs` and `seq` as 8 little-endian bytes
    /// each, and `hash-prefix` the 8 bytes carried in the entry.
    fn hash(&self) -> crate::u256::U256 {
        let mut h = Vec::with_capacity(57);
        h.extend_from_slice(self.id.as_ref());
        h.push(self.scope);
        h.extend_from_slice(&self.khs.to_le_bytes());
        h.extend_from_slice(&self.seq.to_le_bytes());
        h.extend_from_slice(&self.hash_prefix);
        crate::u256::U256::from_bytes(hash(&h).as_bytes())
    }
}

/// Hashing for reconcile items. Implemented as an extension trait because
/// `Item` is an alias for the proto crate's `RecordEntry`.
trait ItemExt {
    fn hash(&self) -> crate::u256::U256;
}

/// Slice of `items` (sorted by (id, scope)) falling in [lower, upper).
fn range_slice<'a>(
    items: &'a [Item],
    lower: &Option<RangeBound>,
    upper: &Option<RangeBound>,
) -> &'a [Item] {
    let start = match lower {
        Some(l) => items.partition_point(|i| (i.id, i.scope) < (l.id, l.scope)),
        None => 0,
    };
    let end = match upper {
        Some(u) => items.partition_point(|i| (i.id, i.scope) < (u.id, u.scope)),
        None => items.len(),
    };
    &items[start..end]
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

/// Count and additive sum (mod 2^256) of the items in a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub count: u64,
    pub sum: Hash32,
}

pub fn fingerprint(items: &[Item], range: &Range) -> Fingerprint {
    let RangeBounds { lower, upper } = range_parts(range);
    let mut count = 0u64;
    let mut sum = crate::u256::U256::default();
    for item in range_slice(items, &lower, &upper) {
        count += 1;
        sum = sum.add(item.hash());
    }
    Fingerprint {
        count,
        sum: Hash32::from_bytes(sum.to_bytes()),
    }
}

pub fn entries_in(items: &[Item], range: &Range) -> Vec<Item> {
    let RangeBounds { lower, upper } = range_parts(range);
    range_slice(items, &lower, &upper).to_vec()
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
///
/// Scoped to one round: the caller resets it when a frame opens a new
/// round (see [`opens_new_round`]). Keyed by the range bounds themselves,
/// never by their `Debug` rendering.
#[derive(Default)]
pub struct ReconcileSession {
    echoed: HashSet<(Option<RangeBound>, Option<RangeBound>)>,
}

impl ReconcileSession {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record that `range` has been echoed; reports whether this is the
    /// first time.
    fn note_echo(&mut self, range: &Range) -> EchoMark {
        let RangeBounds { lower, upper } = range_parts(range);
        if self.echoed.insert((lower, upper)) {
            EchoMark::Fresh
        } else {
            EchoMark::Seen
        }
    }
}

/// Whether `ranges` is the opening frame of a new round: a single
/// unbounded fingerprint range, which is exactly what [`initiate`] emits.
/// A peer that opens a new round invalidates the echo state of any round
/// still in flight, so the caller resets the session before responding.
pub fn opens_new_round(ranges: &[Range]) -> bool {
    matches!(
        ranges,
        [Range::Fingerprint {
            lower: None,
            upper: None,
            ..
        }]
    )
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
///
/// `items` must be sorted by (id, scope). At most [`MAX_RANGES_PER_MSG`]
/// input ranges are processed; output ranges are *not* truncated — the
/// caller is responsible for chunking them into frames that fit a bucket
/// (see `crate::frame_budget`). A range is answered with an explicit list
/// only when both sides hold at most `LEAF_LIMIT` entries in it; otherwise
/// it is split. An entries echo is never truncated: an over-full range is
/// split instead, and an unsplittable one is listed in full.
pub fn respond(
    items: &[Item],
    msgs: &[Range],
    session: &mut ReconcileSession,
) -> ReconcileResponse {
    let mut out = Vec::new();
    let mut wants: Vec<RecordRef> = Vec::new();
    let mut want_set: HashSet<RecordRef> = HashSet::new();
    // A peer may not make us do unbounded work: cap the ranges we process.
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
                // Split unless both sides hold at most LEAF_LIMIT entries;
                // the peer's advertised count decides as much as ours.
                if (my_items.len() as u64).max(*count) <= LEAF_LIMIT as u64 {
                    session.note_echo(&probe);
                    out.push(Range::Entries {
                        lower: *lower,
                        upper: *upper,
                        entries: my_items,
                    });
                } else if let Some(subs) = split(&probe) {
                    for sub in subs {
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
                        if (mine.len() as u64) <= LEAF_LIMIT as u64 {
                            out.push(Range::Entries {
                                lower: *lower,
                                upper: *upper,
                                entries: mine,
                            });
                        } else if let Some(subs) = split(&probe) {
                            // Never truncate an echo: split instead.
                            for sub in subs {
                                out.push(with_fp(items, &sub));
                            }
                        } else {
                            out.push(Range::Entries {
                                lower: *lower,
                                upper: *upper,
                                entries: mine,
                            });
                        }
                    }
                }
                for entry in entries {
                    let key = entry.key();
                    let want = match items.binary_search_by(|i| i.key().cmp(&key)) {
                        // Want the peer's entry when it is newer than ours:
                        // a higher (khs, seq), or an equal (khs, seq) with a
                        // lower hash-prefix (the lower hash wins). Equal
                        // prefixes are treated as identical.
                        Ok(idx) => {
                            let mine = &items[idx];
                            (mine.khs, mine.seq) < (entry.khs, entry.seq)
                                || ((mine.khs, mine.seq) == (entry.khs, entry.seq)
                                    && mine.hash_prefix > entry.hash_prefix)
                        }
                        Err(_) => true,
                    };
                    if want && want_set.insert(key) {
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
            khs: 0,
            seq: n as u64,
            hash_prefix: [n; 8],
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
                    b.lower.is_none_or(|l| l.id <= id) && b.upper.is_none_or(|u| id < u.id)
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

    /// Feed `msgs` through `respond` in wire-sized chunks (at most
    /// MAX_RANGES_PER_MSG ranges per message, as the transport delivers
    /// them), accumulating wants.
    fn respond_chunked(
        items: &[Item],
        msgs: &[Range],
        session: &mut ReconcileSession,
    ) -> ReconcileResponse {
        let mut ranges = Vec::new();
        let mut wants = Vec::new();
        for chunk in msgs.chunks(MAX_RANGES_PER_MSG) {
            let resp = respond(items, chunk, session);
            ranges.extend(resp.ranges);
            wants.extend(resp.wants);
        }
        ReconcileResponse { ranges, wants }
    }

    /// Run a full reconciliation between `a` and `b`; `a_starts` selects
    /// the initiator. Returns both sides' wants and the number of rounds.
    /// Mirrors the node: a frame that opens a new round resets the
    /// receiver's session.
    fn reconcile_pair(a: &[Item], b: &[Item], a_starts: bool) -> (Wants, Wants, usize) {
        let mut sa = ReconcileSession::new();
        let mut sb = ReconcileSession::new();
        let mut a_wants = Vec::new();
        let mut b_wants = Vec::new();
        let mut a_msg: Option<Vec<Range>> = a_starts.then(|| initiate(a));
        let mut b_msg: Option<Vec<Range>> = (!a_starts).then(|| initiate(b));
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds <= 64, "reconciliation did not converge");
            let mut progress = false;
            if let Some(msg) = a_msg.take() {
                if opens_new_round(&msg) {
                    sb = ReconcileSession::new();
                }
                let resp = respond_chunked(b, &msg, &mut sb);
                b_wants.extend(resp.wants);
                if !resp.ranges.is_empty() {
                    b_msg = Some(resp.ranges);
                    progress = true;
                }
            }
            if let Some(msg) = b_msg.take() {
                if opens_new_round(&msg) {
                    sa = ReconcileSession::new();
                }
                let resp = respond_chunked(a, &msg, &mut sa);
                a_wants.extend(resp.wants);
                if !resp.ranges.is_empty() {
                    a_msg = Some(resp.ranges);
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        (a_wants, b_wants, rounds)
    }

    #[test]
    fn reconcile_finds_missing_items() {
        let a = sorted(vec![item(1), item(2), item(3)]);
        let b = sorted(vec![item(2), item(3), item(4)]);
        let (a_wants, b_wants, _) = reconcile_pair(&a, &b, true);
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
        let (a_wants, b_wants, _) = reconcile_pair(&a, &b, true);
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
                    khs: 0,
                    seq: 1,
                    hash_prefix: [i as u8; 8],
                }
            })
            .collect();
        let mut a = base.clone();
        a.push(Item {
            id: Identifier::from_bytes([0xde; 32]),
            scope: 0,
            khs: 0,
            seq: 1,
            hash_prefix: [0xde; 8],
        });
        let mut b = base;
        b.push(Item {
            id: Identifier::from_bytes([0xad; 32]),
            scope: 0,
            khs: 0,
            seq: 1,
            hash_prefix: [0xad; 8],
        });
        a.sort();
        b.sort();
        let (a_wants, b_wants, _) = reconcile_pair(&a, &b, true);
        assert!(a_wants.contains(&RecordRef {
            id: Identifier::from_bytes([0xad; 32]),
            scope: 0,
        }));
        assert!(b_wants.contains(&RecordRef {
            id: Identifier::from_bytes([0xde; 32]),
            scope: 0,
        }));
    }

    /// Regression for the P9 stall: an empty node initiating against a
    /// peer holding many records must learn all of them, not stall at
    /// LEAF_LIMIT per top-level range.
    #[test]
    fn empty_initiator_converges_against_full_peer() {
        let mut rng = SplitMix64(0xDEAD_BEEF_CAFE_F00D);
        let full: Vec<Item> = {
            let mut v: Vec<Item> = (0..2000).map(|_| random_item(&mut rng)).collect();
            v.sort();
            v
        };
        let empty: Vec<Item> = Vec::new();
        let (a_wants, b_wants, rounds) = reconcile_pair(&empty, &full, true);
        let full_keys: HashSet<_> = full.iter().map(|i| i.key()).collect();
        let a_want: HashSet<_> = a_wants.iter().copied().collect();
        assert_eq!(a_want, full_keys, "empty initiator must learn every entry");
        assert!(b_wants.is_empty());
        let bound = 2 * (usize::BITS - (full.len() as u64).leading_zeros()) as usize + 2;
        assert!(
            rounds <= bound,
            "{rounds} rounds exceeds O(log n) bound {bound}"
        );
    }

    /// Deterministic PRNG (splitmix64) so the property test is reproducible.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    fn random_item(rng: &mut SplitMix64) -> Item {
        let mut id = [0u8; 32];
        rng.fill(&mut id);
        let mut hash_prefix = [0u8; 8];
        rng.fill(&mut hash_prefix);
        Item {
            id: Identifier::from_bytes(id),
            scope: 0,
            khs: 0,
            seq: 1,
            hash_prefix,
        }
    }

    /// Two random sets of up to ~10^4 entries must converge in O(log n)
    /// exchanges, whichever side initiates: the wants each side produces
    /// must cover exactly the symmetric difference, within a logarithmic
    /// number of rounds.
    #[test]
    fn random_sets_converge_regardless_of_initiator() {
        let mut rng = SplitMix64(0x243F_6A88_85A3_08D3);
        for &n in &[100usize, 1_000, 10_000] {
            // Pool of 1.5n unique items; a and b each take n of them with
            // n/2 in common.
            let mut pool: Vec<Item> = (0..n + n / 2).map(|_| random_item(&mut rng)).collect();
            for i in (1..pool.len()).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                pool.swap(i, j);
            }
            let mut a: Vec<Item> = pool[..n].to_vec();
            let mut b: Vec<Item> = pool[n / 2..n + n / 2].to_vec();
            a.sort();
            b.sort();
            assert_eq!(a.len(), n);
            assert_eq!(b.len(), n);
            for a_starts in [true, false] {
                let (a_wants, b_wants, rounds) = reconcile_pair(&a, &b, a_starts);
                let a_set: HashSet<_> = a.iter().map(|i| i.key()).collect();
                let b_set: HashSet<_> = b.iter().map(|i| i.key()).collect();
                let a_want: HashSet<_> = a_wants.iter().copied().collect();
                let b_want: HashSet<_> = b_wants.iter().copied().collect();
                let a_missing: HashSet<_> = b_set.difference(&a_set).copied().collect();
                let b_missing: HashSet<_> = a_set.difference(&b_set).copied().collect();
                assert_eq!(
                    a_want, a_missing,
                    "n={n} a_starts={a_starts}: A's wants must cover exactly B\\A"
                );
                assert_eq!(
                    b_want, b_missing,
                    "n={n} a_starts={a_starts}: B's wants must cover exactly A\\B"
                );
                let bound = 2 * (usize::BITS - (n as u64).leading_zeros()) as usize + 2;
                assert!(
                    rounds <= bound,
                    "n={n} a_starts={a_starts}: {rounds} rounds exceeds the O(log n) bound {bound}"
                );
            }
        }
    }
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn item(n: u8) -> Item {
        Item {
            id: Identifier::from_bytes([n; 32]),
            scope: 0,
            khs: 0,
            seq: n as u64,
            hash_prefix: [n; 8],
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
        // 64 processed ranges, one output each (all mismatch).
        assert_eq!(resp.ranges.len(), MAX_RANGES_PER_MSG);
    }

    #[test]
    fn split_output_is_not_silently_dropped() {
        // 64 input fingerprints, each forcing a split, must yield 64*16
        // output ranges; the caller chunks them into frames.
        let items: Vec<Item> = (0..100u8).map(item).collect();
        let msgs: Vec<Range> = (0..MAX_RANGES_PER_MSG)
            .map(|_| Range::Fingerprint {
                lower: None,
                upper: None,
                count: 0,
                sum: Hash32::from_bytes([0; 32]),
            })
            .collect();
        let mut session = ReconcileSession::new();
        let resp = respond(&items, &msgs, &mut session);
        assert_eq!(resp.ranges.len(), MAX_RANGES_PER_MSG * 16);
    }

    #[test]
    fn entries_echo_is_never_truncated() {
        // Peer sends an Entries range covering 100 of our items; we hold
        // more than LEAF_LIMIT, so the range is split into fingerprints
        // instead of echoing a truncated list.
        let items: Vec<Item> = (0..100u8).map(item).collect();
        let entries: Vec<RecordEntry> = items.to_vec();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries,
        }];
        let mut session = ReconcileSession::new();
        let resp = respond(&items, &msgs, &mut session);
        assert!(
            resp.ranges
                .iter()
                .all(|r| matches!(r, Range::Fingerprint { .. })),
            "over-full echo must split, got {:?}",
            resp.ranges
        );
        assert_eq!(resp.ranges.len(), 16);
        // A small range is echoed in full, not capped at LEAF_LIMIT.
        let small: Vec<Item> = (0..20u8).map(item).collect();
        let msgs = vec![Range::Entries {
            lower: None,
            upper: None,
            entries: small.clone(),
        }];
        let mut session = ReconcileSession::new();
        let resp = respond(&small, &msgs, &mut session);
        let echoed: usize = resp
            .ranges
            .iter()
            .map(|r| match r {
                Range::Entries { entries, .. } => entries.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(echoed, 20);
    }

    #[test]
    fn wants_are_not_capped() {
        let items: Vec<Item> = vec![];
        let entries: Vec<RecordEntry> = (0..200u16)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..2].copy_from_slice(&i.to_be_bytes());
                RecordEntry {
                    id: Identifier::from_bytes(id),
                    scope: 0,
                    khs: 0,
                    seq: 1,
                    hash_prefix: [0; 8],
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
        assert_eq!(resp.wants.len(), 200);
    }

    #[test]
    fn opens_new_round_detects_single_unbounded_fingerprint() {
        let unbounded = Range::Fingerprint {
            lower: None,
            upper: None,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        };
        assert!(opens_new_round(std::slice::from_ref(&unbounded)));
        assert!(!opens_new_round(&[]));
        assert!(!opens_new_round(&[unbounded.clone(), unbounded]));
        let bounded = Range::Fingerprint {
            lower: Some(RangeBound {
                id: Identifier::from_bytes([1; 32]),
                scope: 0,
            }),
            upper: None,
            count: 0,
            sum: Hash32::from_bytes([0; 32]),
        };
        assert!(!opens_new_round(&[bounded]));
        let entries = Range::Entries {
            lower: None,
            upper: None,
            entries: vec![],
        };
        assert!(!opens_new_round(&[entries]));
    }
}
