//! Rough throughput comparison: one transaction per custody accept vs one
//! group-committed transaction. Run with `cargo run --release --example group_commit`.
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
    let path = dir.join("bench.redb");

    let iterations = 200usize;
    // Individual commits.
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
    let individual = t0.elapsed();
    drop(store);

    // Group commit of the same writes (fresh db).
    let path2 = dir.join("bench2.redb");
    let store = RedbStore::open(&path2).unwrap();
    let batch: Vec<CustodyEntry> = (0..iterations).map(|i| entry(i as u8)).collect();
    let t0 = Instant::now();
    store.custody_put_batch(&batch).unwrap();
    let batched = t0.elapsed();

    println!(
        "individual commits: {} accepts in {:?} ({:.1} accepts/s)",
        iterations,
        individual,
        iterations as f64 / individual.as_secs_f64()
    );
    println!(
        "group commit:       {} accepts in {:?} ({:.1} accepts/s)",
        iterations,
        batched,
        iterations as f64 / batched.as_secs_f64()
    );
}
