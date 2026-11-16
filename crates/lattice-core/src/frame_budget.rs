//! Frame-size budget: verify an outbound frame fits a bucket *before* it is
//! emitted, so an oversized frame is dropped (and logged) as the local bug
//! it is, instead of tearing the link down in the transport.
//!
//! lattice-core cannot depend on lattice-net (the dependency points the
//! other way), so the bucket-fit rule is mirrored here. Keep
//! `FRAME_BUCKETS` in sync with `lattice_net::frame::FRAME_BUCKETS`; the
//! fit rule mirrors `encode_wire` / `encode_wire_to_bucket`.

use lattice_proto::frames::Frame;

/// Bucket sizes in bytes. Mirror of `lattice_net::FRAME_BUCKETS`.
const FRAME_BUCKETS: [usize; 4] = [2048, 4096, 8192, 32768];

/// Byte budget for the summed per-item encoded sizes inside one frame.
/// Leaves room for the frame envelope, the array header and the
/// `[frame, padding]` wrapper inside the largest bucket; the exact
/// [`frame_fits`] check at emission is the backstop.
const CHUNK_ITEM_BUDGET: usize = 32768 - 1024;

fn cbor_head_len(n: usize) -> usize {
    if n <= 23 {
        1
    } else if n <= 0xff {
        2
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// True if `frame_len` bytes of CBOR frame fit in `bucket`, using the same
/// rule as the wire encoder: a `[frame, padding]` array whose padding head
/// length matches the actual padding length.
fn fits_bucket(frame_len: usize, bucket: usize) -> bool {
    for head in [1usize, 2, 3, 5, 9] {
        let Some(pad) = bucket.checked_sub(1 + cbor_head_len(frame_len) + frame_len + head) else {
            continue;
        };
        if cbor_head_len(pad) == head {
            return true;
        }
    }
    false
}

/// True if `frame` fits the bucket selected by `pad_to` (`Some(i)` selects
/// `FRAME_BUCKETS[i]`; an out-of-range index fits nothing), or, with
/// `None`, any bucket.
pub(crate) fn frame_fits(frame: &Frame, pad_to: Option<usize>) -> bool {
    let len = frame.encode().len();
    match pad_to {
        Some(i) => FRAME_BUCKETS.get(i).is_some_and(|&b| fits_bucket(len, b)),
        None => FRAME_BUCKETS.iter().any(|&b| fits_bucket(len, b)),
    }
}

/// Pack `items` into chunks that each hold at most `max_items` items and
/// whose summed `item_len` stays within [`CHUNK_ITEM_BUDGET`]. `item_len`
/// must upper-bound the item's encoded size inside the frame; the caller
/// gets exact accounting by encoding a one-element frame per item. A single
/// item larger than the budget is emitted alone; the frame-size check at
/// emission will drop it and log.
pub(crate) fn chunk_by_budget<T>(
    items: Vec<T>,
    max_items: usize,
    item_len: impl Fn(&T) -> usize,
) -> Vec<Vec<T>> {
    let mut chunks = Vec::new();
    let mut cur: Vec<T> = Vec::new();
    let mut cur_bytes = 0usize;
    for item in items {
        let len = item_len(&item);
        if !cur.is_empty() && (cur.len() >= max_items || cur_bytes + len > CHUNK_ITEM_BUDGET) {
            chunks.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur_bytes += len;
        cur.push(item);
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_fit_matches_wire_sizes() {
        // A frame of exactly the largest bucket minus minimal overhead fits;
        // one byte more does not.
        assert!(fits_bucket(32768 - 19, 32768));
        assert!(!fits_bucket(32768, 32768));
        assert!(!fits_bucket(2048, 2047));
        assert!(fits_bucket(0, 2048));
    }

    #[test]
    fn chunk_respects_item_cap() {
        let chunks = chunk_by_budget(vec![1, 2, 3, 4, 5], 2, |_| 1);
        assert_eq!(chunks, vec![vec![1, 2], vec![3, 4], vec![5]]);
    }

    #[test]
    fn chunk_splits_on_budget() {
        // Two items fit the budget (22000 <= 31744), three do not.
        let chunks = chunk_by_budget(vec![10usize, 20, 30, 40, 50], 10, |_| 11_000);
        assert_eq!(chunks, vec![vec![10, 20], vec![30, 40], vec![50]]);
    }

    #[test]
    fn chunk_emits_oversized_single_item_alone() {
        let chunks = chunk_by_budget(vec![1usize, 2, 3], 10, |_| CHUNK_ITEM_BUDGET + 1);
        assert_eq!(chunks, vec![vec![1], vec![2], vec![3]]);
    }
}
