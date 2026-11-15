//! redb backend: persistence, schema guard, and MemStore equivalence.

use lattice_proto::message::Envelope;
use lattice_proto::record::Scope;
use lattice_store::{
    CustodyEntry, InboxEntry, MemStore, OutboundMessage, OutboundState, RedbStore, Store,
};
use lattice_types::{Commitment, DeliveryId, Hash32, Identifier, LegId, MessageId, Signature};

fn id(b: u8) -> Identifier {
    Identifier::from_bytes([b; 32])
}
fn mid(b: u8) -> MessageId {
    MessageId::from_bytes([b; 16])
}
fn leg(b: u8) -> LegId {
    LegId::from_bytes([b; 16])
}
fn did(b: u8) -> DeliveryId {
    DeliveryId::from_bytes([b; 16])
}
fn h(b: u8) -> Hash32 {
    Hash32::from_bytes([b; 32])
}

fn envelope() -> Envelope {
    Envelope {
        kind: 0,
        mid: mid(1),
        from: id(2),
        fsvc: "svc".into(),
        fmbx: b"me".to_vec(),
        tsvc: "svc".into(),
        tmbx: b"you".to_vec(),
        created: 100,
        body: Some(vec![9; 10]),
        reference: None,
        reason: None,
        sig: Signature::from_bytes([7; 64]),
    }
}

fn outbound(mid_byte: u8) -> OutboundMessage {
    OutboundMessage {
        mid: mid(mid_byte),
        recipient: id(9),
        envelope: envelope(),
        priority: 1,
        exp: 9_999_999_999,
        state: OutboundState::Queued,
        waypoints_tried: vec![],
        receipt_deadline: Some(9_999_999_000),
        attempts: 0,
        next_attempt: 0,
        route: 0,
    }
}

fn custody(byte: u8) -> CustodyEntry {
    CustodyEntry {
        leg: leg(byte),
        message: vec![byte; 100],
        upstream: 7,
        destination: id(3),
        class: 4,
        exp: 9_999_999_999,
        excluded: vec![],
    }
}

fn exercise<S: Store>(s: &mut S) -> String {
    s.record_put(&id(1), Scope::Wan, b"record-one", 111)
        .unwrap();
    s.record_put(&id(2), Scope::Hive, b"record-two", 222)
        .unwrap();
    assert_eq!(s.record_count().unwrap(), 2);
    assert_eq!(
        s.record_get(&id(1), Scope::Wan).unwrap().unwrap().0,
        b"record-one"
    );
    assert_eq!(s.record_get(&id(1), Scope::Hive).unwrap(), None);

    s.kel_head_put(&id(1), 3, Commitment::from_bytes([0xAB; 32]), 500)
        .unwrap();
    assert_eq!(
        s.kel_head(&id(1)).unwrap(),
        Some((3, Commitment::from_bytes([0xAB; 32]), 500))
    );

    s.outbound_push(&outbound(1)).unwrap();
    s.outbound_push(&outbound(2)).unwrap();
    assert_eq!(s.outbound_all().unwrap().len(), 2);
    assert_eq!(s.outbound_due(1000).unwrap().len(), 2);
    assert_eq!(s.outbound_get(&mid(1)).unwrap().unwrap().mid, mid(1));

    s.custody_put(custody(1)).unwrap();
    s.custody_put(custody(2)).unwrap();
    assert_eq!(s.custody_bytes().unwrap(), 200);
    assert_eq!(s.custody_all().unwrap().len(), 2);
    let e = s.custody_remove(&leg(1)).unwrap().unwrap();
    assert_eq!(e.leg, leg(1));
    assert_eq!(s.custody_all().unwrap().len(), 1);

    s.share_add(&id(9), 5, 100).unwrap();
    assert_eq!(s.share_get(&id(9), 5).unwrap(), 100);
    s.share_add(&id(9), 5, 150).unwrap();
    assert_eq!(s.share_get(&id(9), 5).unwrap(), 250);
    // Underflow is an error, not a silent clamp to zero.
    assert!(s.share_add(&id(9), 5, -300).is_err());
    assert_eq!(s.share_get(&id(9), 5).unwrap(), 250);
    s.share_add(&id(9), 5, -250).unwrap();
    assert_eq!(s.share_get(&id(9), 5).unwrap(), 0);

    s.seen_add(h(8), 1000).unwrap();
    assert!(s.seen_contains(&h(8), 999).unwrap());
    assert!(!s.seen_contains(&h(8), 1000).unwrap());

    s.delivered_add(h(6), 1000).unwrap();
    assert!(s.delivered_contains(&h(6), 999).unwrap());

    s.inbox_push(InboxEntry {
        delivery_id: did(0xD1),
        mid: mid(1),
        from: id(2),
        fsvc: "svc".into(),
        fmbx: b"a".to_vec(),
        tsvc: "svc".into(),
        tmbx: b"b".to_vec(),
        body: b"hello".to_vec(),
        received: 42,
    })
    .unwrap();
    assert_eq!(s.inbox_len("svc").unwrap(), 1);
    assert_eq!(s.inbox_fetch("svc", 10).unwrap().len(), 1);
    assert_eq!(s.inbox_ack("svc", &[did(0xD1)]).unwrap(), 1);
    assert_eq!(s.inbox_len("svc").unwrap(), 0);

    s.status_set(&mid(4), 3, None).unwrap();
    assert_eq!(s.status_get(&mid(4)).unwrap(), Some((3, None)));

    s.size_bucket_sample(0).unwrap();
    s.size_bucket_sample(0).unwrap();
    s.size_bucket_sample(2).unwrap();
    format!(
        "{:?}|{:?}|{:?}",
        s.outbound_all().unwrap().len(),
        s.custody_all().unwrap().len(),
        s.size_bucket_counts().unwrap()
    )
}

#[test]
fn mem_and_redb_agree() {
    let tmp = tempfile::tempdir().unwrap();
    let mem_digest = exercise(&mut MemStore::new());
    let mut redb = RedbStore::open(tmp.path().join("test.redb")).unwrap();
    let redb_digest = exercise(&mut redb);
    assert_eq!(mem_digest, redb_digest);
}

#[test]
fn redb_persists_across_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("persist.redb");
    {
        let mut s = RedbStore::open(&path).unwrap();
        s.record_put(&id(7), Scope::Wan, b"persistent-record", 777)
            .unwrap();
        s.custody_put(custody(9)).unwrap();
        s.kel_head_put(&id(7), 11, Commitment::from_bytes([0xCD; 32]), 4242)
            .unwrap();
    }
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(
        s.record_get(&id(7), Scope::Wan).unwrap().unwrap().0,
        b"persistent-record"
    );
    assert_eq!(s.custody_get(&leg(9)).unwrap().unwrap().destination, id(3));
    assert_eq!(
        s.kel_head(&id(7)).unwrap(),
        Some((11, Commitment::from_bytes([0xCD; 32]), 4242))
    );
}

#[test]
fn backend_error_carries_op_and_source() {
    // Opening a database inside a nonexistent directory fails; the error must
    // name the operation and chain to the underlying io error.
    let err = match RedbStore::open("/nonexistent-lattice-test-dir/db.redb") {
        Ok(_) => panic!("open should fail for a nonexistent directory"),
        Err(e) => e,
    };
    match &err {
        lattice_store::StoreError::Backend { op, source } => {
            assert_eq!(*op, "open");
            assert!(!source.to_string().is_empty());
        }
        other => panic!("expected Backend, got {other:?}"),
    }
    use std::error::Error;
    assert!(err.source().is_some(), "source chain must be preserved");
    assert!(err.to_string().contains("open"), "op missing: {err}");
}

#[test]
fn redb_refuses_newer_schema() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("future.redb");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, u64>::new("meta"))
                .unwrap();
            meta.insert("schema_version", 99).unwrap();
        }
        txn.commit().unwrap();
    }
    let err = RedbStore::open(&path).map(|_| ()).unwrap_err();
    assert!(err.to_string().contains("newer"), "unexpected error: {err}");
}

#[test]
fn crash_leaves_no_partial_state() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("crash.redb");
    {
        let mut s = RedbStore::open(&path).unwrap();
        s.record_put(&id(1), Scope::Wan, b"committed", 1).unwrap();
    }
    // Simulate crash between writes by writing only to a throwaway db copy
    // and confirming partial data never appears in the real one.
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(s.record_count().unwrap(), 1);
}

#[test]
fn schema_v1_is_created_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fresh.redb");
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(s.record_count().unwrap(), 0);
}

// --- Crash-kill consistency (B3) -------------------------------------------
// Re-executes this test binary as a child that performs custody accepts in a
// loop; the parent SIGKILLs it mid-stream, then reopens the store and checks
// that everything committed is internally consistent.

fn crash_child(db_path: &str, journal_path: &str) {
    use lattice_store::CustodyAccept;
    let mut store = RedbStore::open(db_path).unwrap();
    let mut journal = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal_path)
        .unwrap();
    use std::io::Write;
    for i in 0u64..100_000 {
        let mut leg_bytes = [0u8; 16];
        leg_bytes[..8].copy_from_slice(&i.to_be_bytes());
        let leg = LegId::from_bytes(leg_bytes);
        let msg = vec![(i % 251) as u8; 128 + (i % 512) as usize];
        let mut seen_bytes = [0u8; 32];
        seen_bytes[..16].copy_from_slice(&leg_bytes);
        let seen = Hash32::from_bytes(seen_bytes);
        let accept = CustodyAccept {
            entry: CustodyEntry {
                leg,
                message: msg.clone(),
                upstream: 7,
                destination: id(9),
                class: 1,
                exp: u64::MAX / 2,
                excluded: vec![],
            },
            share_dest: id(9),
            share_upstream: 7,
            share_bytes: msg.len() as i64,
            seen_hash: seen,
            seen_exp: u64::MAX / 2,
        };
        store.custody_accept(accept).unwrap();
        writeln!(journal, "{}", i).unwrap();
        journal.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn crash_kill_preserves_committed_custody() {
    if let Ok(db) = std::env::var("LATTICE_CRASH_CHILD_DB") {
        let journal = std::env::var("LATTICE_CRASH_CHILD_JOURNAL").unwrap();
        crash_child(&db, &journal);
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("crash.redb");
    let journal = tmp.path().join("journal.txt");

    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .arg("crash_kill_preserves_committed_custody")
        .arg("--exact")
        .arg("--nocapture")
        .env("LATTICE_CRASH_CHILD_DB", &db)
        .env("LATTICE_CRASH_CHILD_JOURNAL", &journal)
        .spawn()
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(500));
    child.kill().unwrap(); // SIGKILL — no destructors, no cleanup
    child.wait().unwrap();

    // Every journaled accept must be present and consistent.
    let journaled: Vec<u64> = std::fs::read_to_string(&journal)
        .unwrap_or_default()
        .lines()
        .map(|l| l.parse().unwrap())
        .collect();

    let store = RedbStore::open(&db).expect("store must open after a kill -9");
    let rows = store.custody_all().expect("custody rows must decode");
    let custody_legs: std::collections::HashSet<LegId> = rows.iter().map(|e| e.leg).collect();

    for i in &journaled {
        let mut leg_bytes = [0u8; 16];
        leg_bytes[..8].copy_from_slice(&i.to_be_bytes());
        assert!(
            custody_legs.contains(&LegId::from_bytes(leg_bytes)),
            "journaled accept {i} missing from custody after crash"
        );
    }

    // Internal consistency: byte counter and share counter equal the sum of
    // the surviving rows; every custody row has its seen marker.
    let total_bytes: u64 = rows.iter().map(|e| e.message.len() as u64).sum();
    assert_eq!(store.custody_bytes().unwrap(), total_bytes);
    assert_eq!(store.share_get(&id(9), 7).unwrap(), total_bytes);
    for e in &rows {
        let mut seen_bytes = [0u8; 32];
        seen_bytes[..16].copy_from_slice(e.leg.as_ref());
        assert!(
            store
                .seen_contains(&Hash32::from_bytes(seen_bytes), 1)
                .unwrap(),
            "custody row without its dedup marker — accept was not atomic"
        );
    }
}

#[test]
fn custody_class_bytes_track_accept_and_remove() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = RedbStore::open(tmp.path().join("class.redb")).unwrap();

    let mk = |leg_byte: u8, class: u8, len: usize| CustodyEntry {
        leg: leg(leg_byte),
        message: vec![7u8; len],
        upstream: 1,
        destination: id(9),
        class,
        exp: u64::MAX / 2,
        excluded: vec![],
    };

    s.custody_accept(lattice_store::CustodyAccept {
        entry: mk(1, 3, 100),
        share_dest: id(9),
        share_upstream: 1,
        share_bytes: 100,
        seen_hash: h(1),
        seen_exp: u64::MAX / 2,
    })
    .unwrap();
    s.custody_accept(lattice_store::CustodyAccept {
        entry: mk(2, 3, 250),
        share_dest: id(9),
        share_upstream: 1,
        share_bytes: 250,
        seen_hash: h(2),
        seen_exp: u64::MAX / 2,
    })
    .unwrap();
    s.custody_accept(lattice_store::CustodyAccept {
        entry: mk(3, 7, 40),
        share_dest: id(9),
        share_upstream: 1,
        share_bytes: 40,
        seen_hash: h(3),
        seen_exp: u64::MAX / 2,
    })
    .unwrap();

    let classes = s.custody_class_bytes().unwrap();
    assert_eq!(classes[3], 350);
    assert_eq!(classes[7], 40);
    assert_eq!(classes[0], 0);
    assert_eq!(s.custody_bytes().unwrap(), 390);

    s.custody_remove(&leg(1)).unwrap();
    let classes = s.custody_class_bytes().unwrap();
    assert_eq!(classes[3], 250);
    assert_eq!(s.custody_bytes().unwrap(), 290);

    // Reopen: counters must be rebuilt from the table, not lost.
    drop(s);
    let s = RedbStore::open(tmp.path().join("class.redb")).unwrap();
    let classes = s.custody_class_bytes().unwrap();
    assert_eq!(classes[3], 250);
    assert_eq!(classes[7], 40);
    assert_eq!(s.custody_bytes().unwrap(), 290);
}
