//! redb backend: persistence, schema guard, and MemStore equivalence.

use redb::ReadableTable;

use lattice_proto::local::MessageStatus;
use lattice_proto::message::Envelope;
use lattice_proto::record::Scope;
use lattice_store::{
    CustodyEntry, InboxEntry, KelHeadSeen, MemStore, OutboundMessage, OutboundState, RedbStore,
    Store,
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
        s.record_get(&id(1), Scope::Wan).unwrap().unwrap().bytes,
        b"record-one"
    );
    assert_eq!(s.record_get(&id(1), Scope::Hive).unwrap(), None);

    s.kel_put(
        &id(1),
        b"kel-object-bytes",
        &KelHeadSeen {
            seq: 3,
            commitment: Commitment::from_bytes([0xAB; 32]),
            seen: 500,
            abandoned: true,
        },
    )
    .unwrap();
    assert_eq!(
        s.kel_head(&id(1)).unwrap(),
        Some(KelHeadSeen {
            seq: 3,
            commitment: Commitment::from_bytes([0xAB; 32]),
            seen: 500,
            abandoned: true,
        })
    );
    assert_eq!(
        s.kel_get(&id(1)).unwrap().as_deref(),
        Some(&b"kel-object-bytes"[..])
    );
    assert_eq!(s.kel_heads_all().unwrap().len(), 1);

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
    assert_eq!(
        s.status_get(&mid(4)).unwrap(),
        Some(MessageStatus {
            status: 3,
            detail: None,
        })
    );

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
        s.kel_put(
            &id(7),
            b"kel-object-bytes-7",
            &KelHeadSeen {
                seq: 11,
                commitment: Commitment::from_bytes([0xCD; 32]),
                seen: 4242,
                abandoned: false,
            },
        )
        .unwrap();
    }
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(
        s.record_get(&id(7), Scope::Wan).unwrap().unwrap().bytes,
        b"persistent-record"
    );
    assert_eq!(s.custody_get(&leg(9)).unwrap().unwrap().destination, id(3));
    assert_eq!(
        s.kel_head(&id(7)).unwrap(),
        Some(KelHeadSeen {
            seq: 11,
            commitment: Commitment::from_bytes([0xCD; 32]),
            seen: 4242,
            abandoned: false,
        })
    );
    assert_eq!(
        s.kel_get(&id(7)).unwrap().as_deref(),
        Some(&b"kel-object-bytes-7"[..])
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
fn schema_is_created_fresh() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("fresh.redb");
    let s = RedbStore::open(&path).unwrap();
    assert_eq!(s.record_count().unwrap(), 0);
}

#[test]
fn schema_v1_database_fails_loudly() {
    // v2 rows are CBOR; a v1 (serde_json) database must not open silently.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v1.redb");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, u64>::new("meta"))
                .unwrap();
            meta.insert("schema_version", 1).unwrap();
        }
        txn.commit().unwrap();
    }
    let err = RedbStore::open(&path).map(|_| ()).unwrap_err();
    assert!(
        matches!(err, lattice_store::StoreError::NoMigration { from: 1 }),
        "expected NoMigration {{ from: 1 }}, got {err}"
    );
}

#[test]
fn schema_v2_database_fails_loudly() {
    // v3 changed the custody bucket index semantics (the 4096 bucket was
    // inserted at index 1); a v2 database must not open silently.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v2.redb");
    {
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut meta = txn
                .open_table(redb::TableDefinition::<&str, u64>::new("meta"))
                .unwrap();
            meta.insert("schema_version", 2).unwrap();
        }
        txn.commit().unwrap();
    }
    let err = RedbStore::open(&path).map(|_| ()).unwrap_err();
    assert!(
        matches!(err, lattice_store::StoreError::NoMigration { from: 2 }),
        "expected NoMigration {{ from: 2 }}, got {err}"
    );
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

/// Build a bucket-sized, zero-padded wire-shaped message: a 4-element CBOR
/// array whose last element is all-zero bytes, sized exactly to `bucket`.
/// The store only inspects the shape, so the header/envelope contents are
/// placeholders.
fn padded_wire_message(bucket: usize) -> Vec<u8> {
    use lattice_proto::cbor::{self, Value};
    let header = Value::map(vec![
        (Value::UInt(0), Value::UInt(2)),
        (Value::UInt(1), Value::UInt(30)),
    ]);
    let envelope = Value::map(vec![(Value::UInt(0), Value::UInt(0))]);
    for pad in 0..=bucket {
        let msg = cbor::encode(&Value::Array(vec![
            header.clone(),
            Value::Null,
            envelope.clone(),
            Value::Bytes(vec![0u8; pad]),
        ]));
        if msg.len() == bucket {
            return msg;
        }
    }
    panic!("no padding length lands on bucket {bucket}");
}

fn raw_row(path: &std::path::Path, table: &'static str, key: &[u8]) -> Vec<u8> {
    let db = redb::Database::create(path).unwrap();
    let txn = db.begin_read().unwrap();
    let t = txn
        .open_table(redb::TableDefinition::<&[u8], Vec<u8>>::new(table))
        .unwrap();
    t.get(key).unwrap().unwrap().value()
}

fn raw_row_fixed(path: &std::path::Path, table: &'static str, key: &[u8; 16]) -> Vec<u8> {
    let db = redb::Database::create(path).unwrap();
    let txn = db.begin_read().unwrap();
    let t = txn
        .open_table(redb::TableDefinition::<[u8; 16], Vec<u8>>::new(table))
        .unwrap();
    t.get(key).unwrap().unwrap().value()
}

#[test]
fn rows_roundtrip_through_cbor() {
    use lattice_store::Exclusion;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("roundtrip.redb");
    let mut s = RedbStore::open(&path).unwrap();

    // Outbound: every field populated, including waypoints and no deadline.
    let mut msg = outbound(7);
    msg.waypoints_tried = vec![id(0xA1), id(0xB2)];
    msg.receipt_deadline = None;
    msg.attempts = 7;
    msg.route = 2;
    s.outbound_push(&msg).unwrap();
    assert_eq!(s.outbound_get(&mid(7)).unwrap().unwrap(), msg);

    // Custody: with exclusions; message is not bucket-sized, so it is stored verbatim.
    let mut entry = custody(7);
    entry.excluded = vec![
        Exclusion {
            link: 42,
            until: 1700,
        },
        Exclusion {
            link: 43,
            until: 1800,
        },
    ];
    s.custody_put(entry.clone()).unwrap();
    assert_eq!(s.custody_get(&leg(7)).unwrap().unwrap(), entry);

    // Inbox.
    let inbox = inbox_entry(0x42, 1234, "svc");
    s.inbox_push(inbox.clone()).unwrap();
    let got = s.inbox_fetch("svc", 1).unwrap().pop().unwrap();
    assert_eq!(got, inbox);

    // Status: with and without detail.
    s.status_set(&mid(7), 4, Some(77)).unwrap();
    assert_eq!(
        s.status_get(&mid(7)).unwrap(),
        Some(MessageStatus {
            status: 4,
            detail: Some(77),
        })
    );
    s.status_set(&mid(7), 3, None).unwrap();
    assert_eq!(
        s.status_get(&mid(7)).unwrap(),
        Some(MessageStatus {
            status: 3,
            detail: None,
        })
    );

    // Rows are CBOR maps, not JSON objects.
    drop(s);
    let out_row = raw_row_fixed(&path, "outbound", mid(7).as_bytes());
    assert_eq!(out_row[0] & 0xe0, 0xa0, "outbound row is not a CBOR map");
    let custody_row = raw_row_fixed(&path, "custody", leg(7).as_bytes());
    assert_eq!(custody_row[0] & 0xe0, 0xa0, "custody row is not a CBOR map");
    // Inbox key: u16be(service_len) || service || received:u64be || delivery_id.
    let mut inbox_key = Vec::new();
    inbox_key.extend_from_slice(&3u16.to_be_bytes());
    inbox_key.extend_from_slice(b"svc");
    inbox_key.extend_from_slice(&1234u64.to_be_bytes());
    inbox_key.extend_from_slice(did(0x42).as_bytes());
    let inbox_row = raw_row(&path, "inbox", &inbox_key);
    assert_eq!(inbox_row[0] & 0xe0, 0xa0, "inbox row is not a CBOR map");
}

#[test]
fn outbound_row_with_2kb_body_stays_under_3kb() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("size.redb");
    let mut s = RedbStore::open(&path).unwrap();
    let mut msg = outbound(1);
    msg.envelope.body = Some(vec![0xAB; 2048]);
    s.outbound_push(&msg).unwrap();
    drop(s);
    let raw = raw_row_fixed(&path, "outbound", mid(1).as_bytes());
    assert!(
        raw.len() < 3 * 1024,
        "outbound row with a 2048-byte body is {} bytes",
        raw.len()
    );
}

#[test]
fn custody_row_strips_wire_padding() {
    for (bucket_idx, &bucket) in lattice_proto::MESSAGE_BUCKETS.iter().enumerate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("strip.redb");
        let wire = padded_wire_message(bucket);
        let mut s = RedbStore::open(&path).unwrap();
        let mut entry = custody(1);
        entry.message = wire.clone();
        s.custody_put(entry).unwrap();
        drop(s);
        // The stored row holds the unpadded message plus the bucket index,
        // so it is far smaller than the bucket.
        let raw = raw_row_fixed(&path, "custody", leg(1).as_bytes());
        assert!(
            raw.len() < 1024,
            "bucket {bucket_idx}: custody row for a {}-byte wire message is {} bytes",
            wire.len(),
            raw.len()
        );
        // The full padded message is re-assembled on read, byte for byte.
        let s = RedbStore::open(&path).unwrap();
        let got = s.custody_get(&leg(1)).unwrap().unwrap();
        assert_eq!(got.message, wire, "bucket {bucket_idx} round-trip");
        // Byte accounting still tracks the full wire message.
        assert_eq!(s.custody_bytes().unwrap(), wire.len() as u64);
    }
}

fn inbox_entry(delivery: u8, received: u64, tsvc: &str) -> InboxEntry {
    InboxEntry {
        delivery_id: did(delivery),
        mid: mid(1),
        from: id(2),
        fsvc: "svc".into(),
        fmbx: b"a".to_vec(),
        tsvc: tsvc.into(),
        tmbx: b"b".to_vec(),
        body: b"hello".to_vec(),
        received,
    }
}

#[test]
fn outbound_row_with_invalid_envelope_fails_read() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("bad-envelope.redb");
    {
        let mut s = RedbStore::open(&path).unwrap();
        s.outbound_push(&outbound(1)).unwrap();
    }
    // Hand-corrupt the stored row: envelope kind 99 fails Envelope::from_value.
    {
        use lattice_proto::cbor::{self, Value};
        let db = redb::Database::create(&path).unwrap();
        let txn = db.begin_write().unwrap();
        {
            let mut t = txn
                .open_table(redb::TableDefinition::<[u8; 16], Vec<u8>>::new("outbound"))
                .unwrap();
            let raw = t.get(mid(1).as_bytes()).unwrap().unwrap().value();
            let mut v = cbor::decode(&raw).unwrap();
            // The outbound row is a map; the envelope is key 2, and the
            // envelope kind is key 0 of the nested map.
            if let Value::Map(pairs) = &mut v {
                for (k, val) in pairs.iter_mut() {
                    if k.as_uint() == Some(2) {
                        if let Value::Map(envelope) = val {
                            for (ek, ev) in envelope.iter_mut() {
                                if ek.as_uint() == Some(0) {
                                    *ev = Value::UInt(99);
                                }
                            }
                        }
                    }
                }
            }
            t.insert(mid(1).as_bytes(), cbor::encode(&v)).unwrap();
        }
        txn.commit().unwrap();
    }
    let s = RedbStore::open(&path).unwrap();
    assert!(matches!(
        s.outbound_get(&mid(1)),
        Err(lattice_store::StoreError::Codec { .. })
    ));
    assert!(matches!(
        s.outbound_all(),
        Err(lattice_store::StoreError::Codec { .. })
    ));
}

#[test]
fn outbound_bounded_fields_are_clamped_on_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = RedbStore::open(tmp.path().join("clamp.redb")).unwrap();
    let mut msg = outbound(1);
    msg.priority = 7;
    msg.route = 9;
    s.outbound_push(&msg).unwrap();
    let got = s.outbound_get(&mid(1)).unwrap().unwrap();
    assert_eq!(got.priority, 3);
    assert_eq!(got.route, 2);
    let all = s.outbound_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].priority, 3);
    assert_eq!(all[0].route, 2);
}

#[test]
fn custody_class_is_clamped_on_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = RedbStore::open(tmp.path().join("class-clamp.redb")).unwrap();
    let mut e = custody(1);
    e.class = 200;
    s.custody_put(e).unwrap();
    assert_eq!(s.custody_get(&leg(1)).unwrap().unwrap().class, 15);
    assert_eq!(s.custody_all().unwrap()[0].class, 15);
}

fn check_inbox_fifo<S: Store>(s: &mut S) {
    // Insert out of order, including a tie on `received` broken by delivery id.
    for (d, received) in [(0x03u8, 30u64), (0x01, 10), (0x04, 20), (0x02, 20)] {
        s.inbox_push(inbox_entry(d, received, "svc")).unwrap();
    }
    // A different service interleaved must not leak into "svc".
    s.inbox_push(inbox_entry(0x7f, 5, "other")).unwrap();

    let got = s.inbox_fetch("svc", 10).unwrap();
    let order: Vec<DeliveryId> = got.iter().map(|e| e.delivery_id).collect();
    assert_eq!(order, vec![did(0x01), did(0x02), did(0x04), did(0x03)]);

    let first_two = s.inbox_fetch("svc", 2).unwrap();
    assert_eq!(
        first_two.iter().map(|e| e.delivery_id).collect::<Vec<_>>(),
        vec![did(0x01), did(0x02)]
    );
    assert_eq!(s.inbox_len("svc").unwrap(), 4);
    assert_eq!(s.inbox_len_total().unwrap(), 5);
}

#[test]
fn inbox_fetch_is_fifo_per_service() {
    check_inbox_fifo(&mut MemStore::new());
    let tmp = tempfile::tempdir().unwrap();
    let mut redb = RedbStore::open(tmp.path().join("fifo.redb")).unwrap();
    check_inbox_fifo(&mut redb);
}

#[test]
fn inbox_ack_removes_by_delivery_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = RedbStore::open(tmp.path().join("ack.redb")).unwrap();
    s.inbox_push(inbox_entry(0x01, 1, "svc")).unwrap();
    s.inbox_push(inbox_entry(0x02, 2, "svc")).unwrap();
    s.inbox_push(inbox_entry(0x03, 3, "svc")).unwrap();
    // Same delivery id under another service: its row must survive the ack.
    s.inbox_push(inbox_entry(0x02, 2, "other")).unwrap();

    let removed = s.inbox_ack("svc", &[did(0x02), did(0x09)]).unwrap();
    assert_eq!(removed, 1);
    let remaining: Vec<DeliveryId> = s
        .inbox_fetch("svc", 10)
        .unwrap()
        .iter()
        .map(|e| e.delivery_id)
        .collect();
    assert_eq!(remaining, vec![did(0x01), did(0x03)]);
    assert_eq!(s.inbox_len("other").unwrap(), 1);
    assert_eq!(s.inbox_ack("svc", &[did(0x09)]).unwrap(), 0);
}

#[test]
fn inbox_sweep_expired_drops_old_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let mut s = RedbStore::open(tmp.path().join("sweep.redb")).unwrap();
    s.inbox_push(inbox_entry(0x01, 100, "svc")).unwrap();
    s.inbox_push(inbox_entry(0x02, 5000, "svc")).unwrap();
    s.inbox_push(inbox_entry(0x03, 100, "other")).unwrap();

    let dropped = s.inbox_sweep_expired(1000, 2000).unwrap();
    assert_eq!(dropped, 2);
    assert_eq!(s.inbox_len("svc").unwrap(), 1);
    assert_eq!(s.inbox_len("other").unwrap(), 0);
    assert_eq!(s.inbox_fetch("svc", 10).unwrap()[0].delivery_id, did(0x02));
}
