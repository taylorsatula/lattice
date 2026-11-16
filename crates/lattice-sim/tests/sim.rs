use lattice_core::Config;
use lattice_proto::local::DrainState;
use lattice_sim::{LinkState, Sim};
use lattice_types::{ChannelSeed, Identifier, LegId, MessageId, Signature, XWingPublicKey};

fn fast_config() -> Config {
    Config {
        reconcile_interval_secs: 1,
        record_refresh_secs: 3600,
        snow_per_min: 0.0,
        receipt_timeout_public: 30,
        fresh_waypoint_retries: 1,
        services: vec!["test".to_string()],
        ..Config::default()
    }
}

fn full_mesh(sim: &mut Sim, n: usize) {
    for a in 0..n {
        for b in (a + 1)..n {
            sim.connect(a, b);
        }
    }
}

/// Run the sim until `from` has a route to `to` (records converge), or
/// panic. Fixed sleeps are not enough: gossip order is random, and a send
/// before the route exists fails permanently with ERR_NO_RECORD.
fn wait_for_path(sim: &mut Sim, from: usize, to: usize) {
    let to_id = sim.ids[to];
    for _ in 0..30 {
        if sim.nodes[from].has_path(&to_id) {
            return;
        }
        sim.run_for(1);
    }
    panic!("node {from} never learned a path to node {to}");
}

/// Run the sim until `node`'s link is bound to `id` (attestation or record
/// claims, whichever lands first), or panic.
fn wait_for_binding(sim: &mut Sim, node: usize, link: u64, id: Identifier) {
    for _ in 0..30 {
        if sim.nodes[node].debug_link_peer(link) == Some(Some(id)) {
            return;
        }
        sim.run_for(1);
    }
    panic!("node {node} never bound link {link} to the expected peer");
}

#[test]
fn records_converge_after_gossip() {
    let mut sim = Sim::new(fast_config());
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
fn message_delivers_end_to_end_and_sender_sees_receipt() {
    let mut sim = Sim::new(fast_config());
    for _ in 0..4 {
        sim.add_node();
    }
    full_mesh(&mut sim, 4);
    wait_for_path(&mut sim, 0, 3);
    let mid = sim.app_send(0, 3, b"hello mesh");
    sim.run_for(20);
    let got: Vec<_> = sim.deliveries.iter().filter(|d| d.mid == mid).collect();
    assert_eq!(got.len(), 1, "exactly one delivery expected");
    assert_eq!(got[0].node, 3);
    assert_eq!(got[0].body, b"hello mesh");
    let delivered = sim
        .statuses
        .iter()
        .filter(|s| s.mid == mid && s.status == 3)
        .count();
    assert!(delivered >= 1, "sender should observe Delivered status");
}

#[test]
fn partition_holds_then_heals() {
    let mut sim = Sim::new(fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    let link = sim.link_between(1, 2).unwrap();
    sim.run_for(6);
    sim.set_link(link, LinkState::Down);
    let mid = sim.app_send(0, 2, b"after heal");
    sim.run_for(3);
    assert!(
        sim.deliveries.iter().all(|d| d.mid != mid),
        "no delivery while partitioned"
    );
    sim.set_link(link, LinkState::Up);
    sim.run_for(20);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "delivery expected after heal"
    );
}

#[test]
fn crash_during_custody_preserves_message() {
    let mut sim = Sim::new(fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    let link_bc = sim.link_between(1, 2).unwrap();
    sim.run_for(6);
    sim.set_link(link_bc, LinkState::Down);
    let mid = sim.app_send(0, 2, b"survive my crash");
    sim.run_for(4);
    assert_eq!(
        sim.custody_count(1),
        1,
        "B should hold the message in custody"
    );
    sim.crash_node(1);
    sim.set_link(link_bc, LinkState::Up);
    sim.run_for(20);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "custody must survive a crash and be delivered after heal"
    );
}

#[test]
fn waypoint_route_delivers() {
    let mut cfg = fast_config();
    cfg.waypoint_share = 1.0;
    let mut sim = Sim::new(cfg);
    for _ in 0..4 {
        sim.add_node();
    }
    full_mesh(&mut sim, 4);
    sim.run_for(6);
    let mid = MessageId::from_bytes([7u8; 16]);
    let to = sim.ids[3];
    let send = lattice_core::AppSend {
        service: "test".into(),
        mid_hint: Some(mid),
        to,
        tsvc: "test".into(),
        tmbx: b"inbox".to_vec(),
        fmbx: b"outbox".to_vec(),
        body: b"via waypoint".to_vec(),
        exp: None,
        priority: 1,
        route: 1,
    };
    sim.force_app_send(0, send);
    sim.run_for(20);
    assert!(sim.deliveries.iter().any(|d| d.body == b"via waypoint"));
}

#[test]
fn expired_message_is_not_delivered() {
    let mut sim = Sim::new(fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    let link_bc = sim.link_between(1, 2).unwrap();
    sim.run_for(6);
    // Slow the B->C hop so custody dwells at B, then cut it.
    sim.set_latency(link_bc, 100);
    let start = 7; // after the 6s convergence below
    let send = lattice_core::AppSend {
        service: "test".into(),
        mid_hint: Some(MessageId::from_bytes([9u8; 16])),
        to: sim.ids[2],
        tsvc: "test".into(),
        tmbx: b"inbox".to_vec(),
        fmbx: b"outbox".to_vec(),
        body: b"expires".to_vec(),
        exp: Some(start + 3),
        priority: 1,
        route: 0,
    };
    sim.run_for(1); // settle at t≈7
    sim.force_app_send(0, send);
    sim.run_for(1);
    assert_eq!(sim.custody_count(1), 1, "B holds the message in custody");
    sim.set_link(link_bc, LinkState::Down);
    sim.run_for(10);
    assert_eq!(sim.custody_count(1), 0, "expired custody must be dropped");
    sim.set_link(link_bc, LinkState::Up);
    sim.run_for(10);
    assert!(
        sim.deliveries.iter().all(|d| d.body != b"expires"),
        "expired message must not be delivered"
    );
}

#[test]
fn fair_share_caps_a_flooded_upstream() {
    // F floods destination D via relay R. Honest node H also sends to D.
    // R's custody link budget toward D is split equally between F and H;
    // F's excess must be refused while H keeps its slot.
    let mut cfg = fast_config();
    // Each 2KB-bucket message counts full size; per-upstream share must fit two of them.
    // With the R->D link down, R sees two upstreams; per-upstream share is
    // allowance/2. F floods, H sends two. F may fill its own share only.
    cfg.custody_allowance = 13000;
    // Per-class slice is transit_cap / 16; keep it well above the combined
    // fair shares (2 × 6500) so the class cap does not bind and the
    // fair-share mechanism is what the test observes.
    cfg.transit_cap = 16 * 20_000;
    let mut sim = Sim::new(cfg);
    let f = sim.add_node();
    let r = sim.add_node();
    let d = sim.add_node();
    let h = sim.add_node();
    sim.connect(f, r);
    sim.connect(h, r);
    let rd = sim.connect(r, d);
    sim.run_for(6); // converge
    // Jam the R->D link so custody backs up at R.
    sim.set_link(rd, LinkState::Down);
    // F floods.
    for i in 0..20u8 {
        sim.app_send(f, d, &vec![i; 400]);
    }
    // H sends its fair share.
    sim.app_send(h, d, b"honest one");
    sim.app_send(h, d, b"honest two");
    sim.run_for(3);
    let fr = sim.link_between(f, r).unwrap();
    let hr = sim.link_between(h, r).unwrap();
    let upstreams = sim.nodes[r].debug_custody_upstreams();
    let from_f = upstreams.iter().filter(|&&u| u == fr).count();
    let from_h = upstreams.iter().filter(|&&u| u == hr).count();
    eprintln!("fr={fr} hr={hr} upstreams={upstreams:?}");
    eprintln!("frame_counts={:?}", sim.frame_counts);
    eprintln!(
        "n_statuses={} in_transit={}",
        sim.statuses.len(),
        sim.statuses.iter().filter(|s| s.status == 2).count()
    );
    assert!(
        from_f <= 3,
        "flooder exceeded its share: {from_f} messages held"
    );
    assert_eq!(
        from_h, 2,
        "honest node's messages must not be displaced by the flood"
    );
}

#[test]
fn snow_emits_at_configured_rate_and_backs_off_when_busy() {
    let mut cfg = fast_config();
    cfg.snow_per_min = 120.0; // 2 per second
    // Quiet network: any real frame suppresses a snow tick, so keep
    // reconcile/gossip off the wire for this measurement.
    cfg.reconcile_interval_secs = 3600;
    cfg.record_refresh_secs = 3600;
    let mut sim = Sim::new(cfg);
    let a = sim.add_node();
    let b = sim.add_node();
    sim.connect(a, b);
    sim.run_for(20);
    let dummies = *sim.frame_counts.get("dummy").unwrap_or(&0);
    // Two nodes each ticking at 2/s for 20s => expect ~80; accept wide bounds.
    assert!(dummies >= 20, "too few dummies: {dummies}");
    assert!(dummies <= 160, "too many dummies: {dummies}");
}

#[test]
fn duplicate_mid_is_not_delivered_twice() {
    let mut sim = Sim::new(fast_config());
    for _ in 0..2 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.run_for(4);
    let mid = MessageId::from_bytes([0xABu8; 16]);
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
    wait_for_path(&mut sim, 0, 1);
    sim.force_app_send(0, make());
    sim.run_for(5);
    sim.force_app_send(0, make());
    sim.run_for(10);
    let n = sim.deliveries.iter().filter(|d| d.mid == mid).count();
    assert_eq!(n, 1, "duplicate mid must not be delivered twice");
}

#[test]
fn unknown_service_gets_negative_receipt_and_no_inbox_entry() {
    use lattice_store::Store;

    let mut sim = Sim::new(fast_config());
    for _ in 0..2 {
        sim.add_node();
    }
    sim.connect(0, 1);
    wait_for_path(&mut sim, 0, 1);
    wait_for_path(&mut sim, 1, 0);
    let mid = MessageId::from_bytes([0x5Au8; 16]);
    let to_id = sim.ids[1];
    let make = || lattice_core::AppSend {
        service: "test".into(),
        mid_hint: Some(mid),
        to: to_id,
        tsvc: "no-such-service".into(),
        tmbx: b"inbox".to_vec(),
        fmbx: b"outbox".to_vec(),
        body: b"hello?".to_vec(),
        exp: None,
        priority: 1,
        route: 0,
    };
    sim.force_app_send(0, make());
    sim.run_for(10);
    assert!(
        sim.deliveries.iter().all(|d| d.mid != mid),
        "unknown service must not be delivered"
    );
    assert_eq!(
        sim.nodes[1]
            .store_ref()
            .inbox_len("no-such-service")
            .unwrap(),
        0,
        "unknown service must not consume inbox space"
    );
    let status = sim.nodes[0]
        .store_ref()
        .status_get(&mid)
        .unwrap()
        .expect("sender must record a status for the mid");
    assert_eq!(status.status, lattice_proto::local::MSG_STATUS_FAILED);
    assert_eq!(
        status.detail,
        Some(lattice_proto::message::REASON_UNKNOWN_SERVICE),
        "negative receipt must carry reason 1 (unknown service)"
    );

    // Redelivery of the same mid: still no delivery, no inbox entry, and the
    // sender stays on the failed status.
    sim.force_app_send(0, make());
    sim.run_for(10);
    assert!(
        sim.deliveries.iter().all(|d| d.mid != mid),
        "redelivered mid must not be delivered"
    );
    assert_eq!(
        sim.nodes[1]
            .store_ref()
            .inbox_len("no-such-service")
            .unwrap(),
        0,
        "redelivered mid must not consume inbox space"
    );
    let status = sim.nodes[0]
        .store_ref()
        .status_get(&mid)
        .unwrap()
        .expect("sender must record a status for the mid");
    assert_eq!(status.status, lattice_proto::local::MSG_STATUS_FAILED);
    assert_eq!(
        status.detail,
        Some(lattice_proto::message::REASON_UNKNOWN_SERVICE)
    );
}

#[test]
fn equivocating_records_converge_to_lower_hash() {
    use lattice_proto::record::{Mode, PeerRecord, RecordParams, Scope};

    let mut sim = Sim::new(fast_config());
    let a = sim.add_node();
    let b = sim.add_node();
    let victim = sim.add_node(); // the equivocating party (never sends data itself)
    sim.connect(a, b);
    sim.connect(a, victim);
    sim.connect(b, victim);
    sim.run_for(4);

    // Craft two validly-signed records for the same identity with the same
    // seq but different capabilities — an equivocation by the key holder.
    let attacker = lattice_core::Identity::from_seed(&[0xA7; 32]);
    let kel = attacker.kel.clone();
    let id = lattice_proto::kel::identifier(&kel).unwrap();
    let attacker_channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let attacker_channel = lattice_crypto::channel_public(&attacker_channel_seed);
    let mk = |caps: u64| {
        PeerRecord::build(
            RecordParams {
                kel: kel.clone(),
                seq: 7,
                exp: 1_000_000,
                channel_key: attacker_channel,
                channel_seed: attacker_channel_seed.clone(),
                envelope_key: XWingPublicKey::from_bytes([2u8; 1216]),
                mode: Mode::Public,
                scope: Scope::Wan,
                endpoints: vec![],
                links: vec![],
                gateways: vec![],
                capabilities: caps,
            },
            &attacker.signing_seed,
        )
        .unwrap()
    };
    let r1 = mk(1);
    let r2 = mk(2);
    let b1 = r1.encode();
    let b2 = r2.encode();
    use lattice_proto::record::record_hash;
    let (first, second) = if record_hash(&b1) < record_hash(&b2) {
        (b1.clone(), b2.clone())
    } else {
        (b2.clone(), b1.clone())
    };

    let _ = sim.link_between(a, b);
    for victim_node in [a, b] {
        // Feed in reverse-hash order: whichever is stored first, the lower-hash rule must win.
        for bytes in [second.clone(), first.clone()] {
            // Both nodes receive the same two records from the "attacker" link.
            let attacker_link = sim.link_between(victim_node, victim).unwrap();
            sim.inject_frame(
                victim_node,
                attacker_link,
                lattice_proto::frames::Frame::Records(lattice_proto::frames::RecordsFrame {
                    records: vec![bytes],
                }),
            );
        }
    }
    use lattice_store::Store;
    let stored_a = sim.nodes[a]
        .store_ref()
        .record_get(&id, Scope::Wan)
        .unwrap()
        .unwrap()
        .bytes;
    let stored_b = sim.nodes[b]
        .store_ref()
        .record_get(&id, Scope::Wan)
        .unwrap()
        .unwrap()
        .bytes;
    assert_eq!(stored_a, first, "node A must keep the lower-hash record");
    assert_eq!(stored_b, first, "node B must keep the lower-hash record");
}

#[test]
fn everyone_flooding_still_delivers() {
    let mut sim = Sim::new(fast_config());
    let n = 5;
    for _ in 0..n {
        sim.add_node();
    }
    full_mesh(&mut sim, n);
    sim.run_for(5);
    // Everyone sends to everyone; bounded run; delivery counter must advance
    // and the node must not wedge.
    for i in 0..n {
        for j in 0..n {
            if i != j {
                sim.app_send(i, j, format!("{i}->{j}").as_bytes());
            }
        }
    }
    sim.run_for(30);
    assert!(
        !sim.deliveries.is_empty(),
        "some deliveries must land under full load"
    );
    let expected_at_least = 5;
    assert!(sim.deliveries.len() >= expected_at_least);
}

#[test]
fn forged_envelope_is_not_delivered() {
    use lattice_proto::message::{BuildParams, Envelope, KIND_MESSAGE, Message};
    use lattice_proto::record::{PeerRecord, Scope};
    use lattice_store::Store;

    let mut sim = Sim::new(fast_config());
    for _ in 0..3 {
        sim.add_node();
    }
    full_mesh(&mut sim, 3);
    sim.run_for(5); // converge: everyone holds everyone's records

    // Attacker crafts a message claiming to be from node 0 to node 1,
    // signed with the attacker's key (not node 0's key).
    let attacker_seed = lattice_crypto::generate_seed();
    let victim_id = sim.ids[0];
    let target_id = sim.ids[1];
    let target_rec = sim.nodes[1]
        .store_ref()
        .record_get(&target_id, Scope::Wan)
        .unwrap()
        .unwrap()
        .bytes;
    let target_rec = PeerRecord::from_bytes(&target_rec, 0, None)
        .unwrap()
        .into_inner();

    let envelope = Envelope {
        kind: KIND_MESSAGE,
        mid: MessageId::from_bytes([0xEE; 16]),
        from: victim_id,
        fsvc: "test".into(),
        fmbx: b"outbox".to_vec(),
        tsvc: "test".into(),
        tmbx: b"inbox".to_vec(),
        created: 1_800_000_000,
        body: Some(b"forged".to_vec()),
        reference: None,
        reason: None,
        sig: Signature::from_bytes([0; 64]),
    };
    let msg = Message::build(BuildParams {
        envelope,
        sender_seed: &attacker_seed,
        recipient_ek: &target_rec.envelope_key,
        real_dst: target_id,
        leg: LegId::from_bytes([0x42; 16]),
        exp: 1_900_000_000,
        gateway: None,
        waypoint: None,
    })
    .unwrap();

    let link_01 = sim.link_between(0, 1).unwrap();
    sim.inject_offer(1, link_01, msg);
    sim.run_for(10);
    assert!(
        sim.deliveries
            .iter()
            .all(|d| d.mid != MessageId::from_bytes([0xEE; 16])),
        "forged envelope must not be delivered"
    );
    assert_eq!(
        sim.custody_count(1),
        0,
        "forged offer must not be accepted into custody"
    );
}

#[test]
fn custody_drains_after_delivery() {
    let mut cfg = fast_config();
    cfg.waypoint_share = 1.0;
    let mut sim = Sim::new(cfg);
    for _ in 0..4 {
        sim.add_node();
    }
    full_mesh(&mut sim, 4);
    wait_for_path(&mut sim, 0, 3);
    let to = sim.ids[3];
    let send = lattice_core::AppSend {
        service: "test".into(),
        mid_hint: Some(MessageId::from_bytes([0x77; 16])),
        to,
        tsvc: "test".into(),
        tmbx: b"inbox".to_vec(),
        fmbx: b"outbox".to_vec(),
        body: b"track me".to_vec(),
        exp: None,
        priority: 1,
        route: 1,
    };
    sim.force_app_send(0, send);
    sim.run_for(20);
    assert!(sim.deliveries.iter().any(|d| d.body == b"track me"));
    for (i, node) in sim.nodes.iter_mut().enumerate() {
        assert_eq!(
            node.debug_custody_count(),
            0,
            "node {i} still holds custody after delivery"
        );
    }
}

#[test]
fn contested_channel_key_claim_unbinds_link() {
    use lattice_proto::record::{Mode, PeerRecord, RecordParams, Scope};

    // a--b unpinned both ways; a--attacker unpinned as well.
    let mut sim = Sim::new(fast_config());
    let a = sim.add_node();
    let b = sim.add_node();
    let att = sim.add_node();
    sim.connect_unpinned(a, b);
    sim.connect_unpinned(a, att);
    wait_for_path(&mut sim, a, b);

    // With only honest records in flight, `a` binds both links by channel key
    // and can route to `b`.
    let mid = sim.app_send(a, b, b"before contest");
    sim.run_for(10);
    assert_eq!(
        sim.deliveries.iter().filter(|d| d.mid == mid).count(),
        1,
        "message should route over the uncontested link"
    );

    // The attacker tries to bind the *victim's* (b's) channel key to the
    // attacker's own id. With cross-signed records this record cannot be
    // produced: the attacker cannot sign with b's channel key. It must be
    // rejected at admission, the link must stay bound to b, and traffic
    // must flow.
    let _att_id = sim.ids[att];
    let b_ck = sim.channel_key_of(b);
    let attacker = lattice_core::Identity::from_seed(&[0xA7; 32]);
    let attacker_channel_seed = ChannelSeed::from_bytes(lattice_crypto::os_bytes::<32>());
    let forged = PeerRecord::build(
        RecordParams {
            kel: attacker.kel.clone(),
            seq: 1,
            exp: 1_000_000,
            channel_key: b_ck, // the theft: b's channel key under a foreign id
            channel_seed: attacker_channel_seed.clone(), // ...but not b's channel key
            envelope_key: XWingPublicKey::from_bytes([9u8; 1216]),
            mode: Mode::Public,
            scope: Scope::Wan,
            endpoints: vec![],
            links: vec![],
            gateways: vec![],
            capabilities: 0,
        },
        &attacker.signing_seed,
    );
    // build() does not cross-check channel_key against channel_seed (the
    // admission check is the enforcement point), so this produces a record
    // whose channel signature cannot verify under b's key.
    let forged_bytes = forged
        .expect("build does not cross-check channel_key")
        .encode();

    let att_link = sim.link_between(a, att).unwrap();
    sim.inject_frame(
        a,
        att_link,
        lattice_proto::frames::Frame::Records(lattice_proto::frames::RecordsFrame {
            records: vec![forged_bytes],
        }),
    );
    sim.run_for(2);

    // The forged record must have been rejected: no contested claim, link
    // still bound to b, traffic flows.
    assert_eq!(
        sim.nodes[a].debug_contested(),
        0,
        "forged record must not create a contested claim"
    );
    let mid2 = sim.app_send(a, b, b"after forgery attempt");
    sim.run_for(15);
    assert_eq!(
        sim.deliveries.iter().filter(|d| d.mid == mid2).count(),
        1,
        "link must stay bound to b after a rejected forgery"
    );
}

#[test]
fn queued_message_survives_receipt_timeout_and_delivers() {
    // Receipt timeout is 2s; the link stays down far longer, so the message
    // sits Queued well past its original deadline. Once the link heals it
    // must still deliver — the deadline is re-armed at send time, not at
    // enqueue time.
    let mut cfg = fast_config();
    cfg.receipt_timeout_public = 2;
    cfg.retry_base_secs = 1;
    cfg.retry_max_secs = 2;
    let mut sim = Sim::new(cfg);
    for _ in 0..2 {
        sim.add_node();
    }
    sim.connect(0, 1);
    let link = sim.link_between(0, 1).unwrap();
    sim.run_for(6); // let records converge before partitioning
    sim.set_link(link, LinkState::Down);
    sim.run_for(2);
    let mid = sim.app_send(0, 1, b"late but alive");
    sim.run_for(30);
    sim.set_link(link, LinkState::Up);
    sim.run_for(15);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "message queued past its original receipt deadline must still deliver"
    );
}

#[test]
fn buffer_class_isolates_full_classes() {
    // A—B—C—D line. B holds transit custody toward D (class 2) and toward C
    // (class 1). With a per-class cap that fits exactly one message, a
    // second class-2 message must be refused while a class-1 message is
    // still accepted.
    let mut cfg = fast_config();
    // Per-class slice = transit_cap / 16. A wire message is ~1.5 KB
    // (KEM ciphertext dominates), so one fits in 2000 and two do not.
    cfg.transit_cap = 16 * 2000;
    let mut sim = Sim::new(cfg);
    let a = sim.add_node();
    let b = sim.add_node();
    let c = sim.add_node();
    let d = sim.add_node();
    sim.connect(a, b);
    sim.connect(b, c);
    sim.connect(c, d);
    // C is draining: B cannot hand off, so B holds what it accepts.
    sim.nodes[c].set_drain(DrainState::Draining);
    // Wait until A has a route to D (records gossip through B).
    let d_id = sim.ids[d];
    for _ in 0..30 {
        if sim.nodes[a].has_path(&d_id) {
            break;
        }
        sim.run_for(1);
    }
    assert!(sim.nodes[a].has_path(&d_id), "A never learned a path to D");

    let body = vec![7u8; 64];
    let send = |sim: &mut Sim, to: usize, tag: u8| {
        let to_id = sim.ids[to];
        sim.force_app_send(
            a,
            lattice_core::AppSend {
                service: "test".into(),
                mid_hint: Some(MessageId::from_bytes([tag; 16])),
                to: to_id,
                tsvc: "test".into(),
                tmbx: b"inbox".to_vec(),
                fmbx: b"outbox".to_vec(),
                body: body.clone(),
                exp: None,
                priority: 1,
                route: 0,
            },
        );
    };

    // msg1: A -> D. B is 2 hops from D, so B holds it in class 2.
    send(&mut sim, d, 0xD1);
    sim.run_for(4);
    let classes = sim.nodes[b].debug_custody_classes();
    assert_eq!(
        classes,
        vec![2],
        "B should hold one class-2 message, got {classes:?}"
    );

    // msg2: A -> D again. Class 2 is now full at B; the offer must be refused.
    send(&mut sim, d, 0xD2);
    sim.run_for(4);
    let classes = sim.nodes[b].debug_custody_classes();
    assert_eq!(
        classes.iter().filter(|&&c| c == 2).count(),
        1,
        "second class-2 message must be refused, got {classes:?}"
    );

    // msg3: A -> C. B is 1 hop from C, so this is class 1 — a different
    // class, which must still be accepted even though class 2 is full.
    send(&mut sim, c, 0xC1);
    sim.run_for(4);
    let classes = sim.nodes[b].debug_custody_classes();
    assert!(
        classes.contains(&1),
        "class-1 message must be accepted while class 2 is full, got {classes:?}"
    );
}

#[test]
fn attestation_binds_unpinned_link() {
    // Two nodes connect without pinning each other's id. After the link-up
    // attestation exchange, each side must bind the link to the peer's id
    // without any configured peer id.
    let mut sim = Sim::new(fast_config());
    let a = sim.add_node();
    let b = sim.add_node();
    let link = sim.connect_unpinned(a, b);
    let (id_a, id_b) = (sim.ids[a], sim.ids[b]);
    wait_for_binding(&mut sim, a, link, id_b);
    wait_for_binding(&mut sim, b, link, id_a);
    assert_eq!(
        sim.nodes[a].debug_link_peer(link),
        Some(Some(sim.ids[b])),
        "a must bind the link to b's id"
    );
    assert_eq!(
        sim.nodes[b].debug_link_peer(link),
        Some(Some(sim.ids[a])),
        "b must bind the link to a's id"
    );
}

#[test]
fn forged_attestation_does_not_bind() {
    // A forged attestation — an id with no record, and a garbage signature —
    // must never bind the link to the forged id. The honest attestation (or
    // failing that, record claims) binds it to the real peer.
    let mut sim = Sim::new(fast_config());
    let a = sim.add_node();
    let b = sim.add_node();
    let link = sim.connect_unpinned(a, b);
    let id_b = sim.ids[b];
    let forged_id = Identifier::from_bytes([0xEE; 32]);
    sim.inject_frame(
        a,
        link,
        lattice_proto::frames::Frame::Attest(lattice_proto::frames::AttestFrame {
            id: forged_id,
            sig: Signature::from_bytes([0u8; 64]),
        }),
    );
    wait_for_binding(&mut sim, a, link, id_b);
    assert_ne!(
        sim.nodes[a].debug_link_peer(link),
        Some(Some(forged_id)),
        "forged attestation must not bind the link"
    );
    assert_eq!(
        sim.nodes[a].debug_link_peer(link),
        Some(Some(sim.ids[b])),
        "link must bind to the real peer"
    );
}

#[test]
fn private_instance_receives_via_gateway() {
    // A private instance publishes no endpoints and no links; senders route
    // to its gateway, the gateway opens the gateway layer and forwards the
    // message over the direct link. The private instance must receive it.
    let mut sim = Sim::new(fast_config());
    let sender = sim.add_node();
    let gw = sim.add_node();
    let gw_id = sim.ids[gw];
    let priv_node = sim.add_node_with(|c| {
        c.mode = lattice_proto::record::Mode::Private;
        c.gateways = vec![gw_id];
    });
    let priv_id = sim.ids[priv_node];
    let sender_id = sim.ids[sender];
    sim.connect(sender, gw);
    sim.connect(gw, priv_node);
    // Wait for records to converge: the sender needs the private instance's
    // record (to learn it is private and which gateway to use) and the
    // gateway's record; the private instance needs the sender's record to
    // verify the envelope signature.
    for _ in 0..30 {
        let s = sim.nodes[sender].debug_record_ids();
        let g = sim.nodes[gw].debug_record_ids();
        let p = sim.nodes[priv_node].debug_record_ids();
        if s.contains(&priv_id)
            && s.contains(&gw_id)
            && g.contains(&sender_id)
            && p.contains(&sender_id)
        {
            break;
        }
        sim.run_for(1);
    }
    let mid = sim.app_send(sender, priv_node, b"via gateway");
    sim.run_for(20);
    let got: Vec<_> = sim.deliveries.iter().filter(|d| d.mid == mid).collect();
    assert_eq!(got.len(), 1, "private instance must receive the message");
    assert_eq!(got[0].node, priv_node);
    assert_eq!(got[0].body, b"via gateway");
    // The sender must observe the receipt come back through the gateway.
    let delivered = sim
        .statuses
        .iter()
        .filter(|s| s.mid == mid && s.status == 3)
        .count();
    assert!(delivered >= 1, "sender should observe Delivered status");
}
