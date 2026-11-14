//! The core sim invariant suite, run against the redb backend instead of
//! MemStore. Same scenarios as sim.rs; each node gets its own redb file in a
//! tempdir. Guards against backend-specific divergence (e.g. transaction
//! boundaries hiding bugs the in-memory store tolerates).

use lattice_core::Config;
use lattice_sim::Sim;
use lattice_store::RedbStore;

fn fast_config() -> Config {
    Config {
        reconcile_interval_secs: 1,
        record_refresh_secs: 3600,
        snow_per_min: 0.0,
        receipt_timeout_public: 30,
        fresh_waypoint_retries: 1,
        ..Config::default()
    }
}

fn redb_sim(dir: &std::path::Path, cfg: Config) -> Sim<RedbStore> {
    let path = dir.to_path_buf();
    Sim::with_stores(cfg, move |i| {
        RedbStore::open(path.join(format!("node{i}.redb"))).expect("open redb store")
    })
}

fn full_mesh(sim: &mut Sim<RedbStore>, n: usize) {
    for a in 0..n {
        for b in (a + 1)..n {
            sim.connect(a, b);
        }
    }
}

#[test]
fn redb_records_converge_after_gossip() {
    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    let n = 6;
    for _ in 0..n {
        sim.add_node();
    }
    full_mesh(&mut sim, n);
    sim.run_for(10);
    for node in 0..n {
        let count = sim.nodes[node].debug_record_count();
        assert_eq!(count, n, "node {node} knows {count} records, expected {n}");
    }
}

#[test]
fn redb_message_delivers_end_to_end_and_sender_sees_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    for _ in 0..4 {
        sim.add_node();
    }
    full_mesh(&mut sim, 4);
    sim.run_for(5);
    let mid = sim.app_send(0, 3, b"hello mesh");
    sim.run_for(20);
    let got: Vec<_> = sim.deliveries.iter().filter(|d| d.mid == mid).collect();
    assert_eq!(got.len(), 1, "exactly one delivery expected");
    assert_eq!(got[0].node, 3);
    assert_eq!(got[0].body, b"hello mesh");
    let delivered = sim
        .statuses
        .iter()
        .filter(|(m, s)| *m == mid && *s == 3)
        .count();
    assert!(delivered >= 1, "sender should observe Delivered status");
}

#[test]
fn redb_partition_holds_then_heals() {
    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    let link = sim.link_between(1, 2).unwrap();
    sim.run_for(6);
    sim.set_link(link, false);
    let mid = sim.app_send(0, 2, b"after heal");
    sim.run_for(3);
    assert!(
        sim.deliveries.iter().all(|d| d.mid != mid),
        "no delivery while partitioned"
    );
    sim.set_link(link, true);
    sim.run_for(20);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "delivery expected after heal"
    );
}

#[test]
fn redb_crash_during_custody_preserves_message() {
    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    let link_bc = sim.link_between(1, 2).unwrap();
    sim.run_for(6);
    sim.set_link(link_bc, false);
    let mid = sim.app_send(0, 2, b"survive my crash");
    sim.run_for(4);
    assert_eq!(
        sim.custody_count(1),
        1,
        "B should hold the message in custody"
    );
    sim.crash_node(1);
    sim.set_link(link_bc, true);
    sim.run_for(20);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "custody must survive a crash and be delivered after heal"
    );
}

#[test]
fn redb_duplicate_mid_is_not_delivered_twice() {
    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    for _ in 0..2 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.run_for(4);
    let mid = [0xABu8; 16];
    let to_id = sim.ids[1];
    let make = || lattice_core::AppSend {
        service: "test".into(),
        mid_hint: Some(mid),
        to: to_id,
        tsvc: "test".into(),
        tmbx: b"inbox".to_vec(),
        fmbx: b"outbox".to_vec(),
        body: b"once".to_vec(),
        exp: None,
        priority: 1,
        route: 0,
    };
    sim.force_app_send(0, make());
    sim.run_for(5);
    sim.force_app_send(0, make());
    sim.run_for(10);
    let n = sim.deliveries.iter().filter(|d| d.mid == mid).count();
    assert_eq!(n, 1, "duplicate mid must not be delivered twice");
}

#[test]
fn redb_contested_channel_key_claim_unbinds_link() {
    use lattice_proto::record::{Mode, PeerRecord, RecordParams, Scope};

    let dir = tempfile::tempdir().unwrap();
    let mut sim = redb_sim(dir.path(), fast_config());
    let a = sim.add_node();
    let b = sim.add_node();
    let att = sim.add_node();
    sim.connect_unpinned(a, b);
    sim.connect_unpinned(a, att);
    sim.run_for(5);

    let mid = sim.app_send(a, b, b"before contest");
    sim.run_for(10);
    assert_eq!(
        sim.deliveries.iter().filter(|d| d.mid == mid).count(),
        1,
        "message should route over the uncontested link"
    );

    let b_ck = sim.channel_keys[&sim.ids[b]];
    let attacker = lattice_core::Identity::generate();
    let forged = PeerRecord::build(
        RecordParams {
            kel: attacker.kel.clone(),
            seq: 1,
            exp: 1_000_000,
            channel_key: b_ck,
            envelope_key: [9u8; 1216],
            mode: Mode::Public,
            scope: Scope::Wan,
            endpoints: vec![],
            links: vec![],
            gateways: vec![],
            capabilities: 0,
        },
        &attacker.signing_seed,
    )
    .unwrap()
    .encode();

    let att_link = sim.link_between(a, att).unwrap();
    sim.inject_frame(
        a,
        att_link,
        lattice_proto::frames::Frame::Records(lattice_proto::frames::RecordsFrame {
            records: vec![forged],
        }),
    );
    sim.run_for(2);

    assert!(
        sim.nodes[a].debug_contested() >= 1,
        "contested claim must be counted"
    );
    let mid2 = sim.app_send(a, b, b"after contest");
    sim.run_for(15);
    assert_eq!(
        sim.deliveries.iter().filter(|d| d.mid == mid2).count(),
        0,
        "contested link must not be used for routing"
    );
}
