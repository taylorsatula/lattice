//! Rough throughput comparison for custody writes. Run with
//! `cargo run --release --example group_commit`.
//!
//! What is and isn't comparable here:
//!
//! - `custody_put` (one transaction per entry) vs `custody_put_batch` (one
//!   transaction for all entries) is apples-to-apples: same table, same
//!   rows, same bytes; only the number of commits differs.
//! - `custody_accept` (the production path) does strictly more work per
//!   entry than either of those: the custody row, the fair-share update
//!   and the dedup marker, all in one transaction. There is no batched
//!   equivalent of it, so its absolute throughput is not comparable to the
//!   batch number; it is printed as a reference point only. An earlier
//!   version of this example compared `custody_accept` against
//!   `custody_put_batch` directly, which conflated fewer transactions with
//!   less work per transaction and overstated the group-commit win.
use lattice_store::{CustodyAccept, CustodyEntry, RedbStore, Store};
use lattice_types::{Hash32, Identifier, LegId};
use std::time::Instant;

fn entry(n: u8) -> CustodyEntry {
    CustodyEntry {
        leg: LegId::from_bytes([n; 16]),
        message: vec![n; 2048],
        upstream: 1,
        destination: Identifier::from_bytes([9; 32]),
        class: 1,
        exp: u64::MAX / 2,
        excluded: vec![],
    }
}

fn main() {
    let dir = std::env::temp_dir().join("lattice-group-commit-demo");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let iterations = 200usize;

    // Reference point: the production accept path, one transaction per
    // entry (custody row + share + dedup marker).
    let path = dir.join("bench-accept.redb");
    let mut store = RedbStore::open(&path).unwrap();
    let t0 = Instant::now();
    for i in 0..iterations {
        let e = entry(i as u8);
        let accept = CustodyAccept {
            share_dest: e.destination,
            share_upstream: e.upstream,
            share_bytes: e.message.len() as i64,
            seen_hash: Hash32::from_bytes([i as u8; 32]),
            seen_exp: e.exp,
            entry: e,
        };
        store.custody_accept(accept).unwrap();
    }
    let accept_each = t0.elapsed();
    drop(store);

    // Like-for-like: one transaction per entry, custody table only.
    let path = dir.join("bench-individual.redb");
    let mut store = RedbStore::open(&path).unwrap();
    let t0 = Instant::now();
    for i in 0..iterations {
        store.custody_put(entry(i as u8)).unwrap();
    }
    let individual = t0.elapsed();
    drop(store);

    // Group commit: one transaction for the same rows.
    let path = dir.join("bench-batch.redb");
    let store = RedbStore::open(&path).unwrap();
    let batch: Vec<CustodyEntry> = (0..iterations).map(|i| entry(i as u8)).collect();
    let t0 = Instant::now();
    store.custody_put_batch(&batch).unwrap();
    let batched = t0.elapsed();

    println!(
        "accept path (3 tables, 1 txn each): {} accepts in {:?} ({:.1} accepts/s) [reference only]",
        iterations,
        accept_each,
        iterations as f64 / accept_each.as_secs_f64()
    );
    println!(
        "individual commits (1 table, 1 txn each): {} puts in {:?} ({:.1} puts/s)",
        iterations,
        individual,
        iterations as f64 / individual.as_secs_f64()
    );
    println!(
        "group commit (1 table, 1 txn total):      {} puts in {:?} ({:.1} puts/s)",
        iterations,
        batched,
        iterations as f64 / batched.as_secs_f64()
    );
}
