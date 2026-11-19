//! Phase 5 gate: the six-node end-to-end scenario.
//!
//! Topology (all on loopback, real daemons, real local API). The hive is
//! the IPv6 loopback `::1/128`; the WAN side is IPv4 `127.0.0.1`. (macOS
//! only binds explicitly assigned loopback addresses, so a 127.x/16 hive
//! is not available; ::1 is the one extra loopback address that is always
//! present, and it is disjoint from 127.0.0.1, so the two scopes are
//! genuinely distinct.)
//!
//! ```text
//!   h2 ──[hive]──┐
//!   h3 ──[hive]──┤
//!                h1 ──[wan]── gw ──[wan]── wan
//!                              │
//!                           [hive]
//!                              │
//!                             (gw is dual-homed: [::1] in the hive,
//!                              127.0.0.1 on the WAN side)
//!   priv ──[wan]── gw          (private instance; no endpoints)
//! ```
//!
//! h1, h2, h3 and gw are hive members (their listen addresses fall inside
//! the hive CIDR) and publish hive records; h1, h2 and h3 are hive-only
//! (no WAN endpoints) and publish only a hive record. gw is dual-homed
//! and, as a gateway serving `priv`, also publishes a WAN record (a
//! gateway's WAN record carries the `serves` list WAN clients need). The
//! `wan` node is outside the hive and publishes only a WAN record.
//!
//! Links: h2 and h3 root to h1 over hive links; gw roots to h2 over a
//! hive link; h1 roots to gw over a WAN link (so h1 can reach the WAN
//! node, which it cannot do over a hive link); wan and priv root to gw
//! over WAN links. There is no h2–h3 or gw–h2 link.
//!
//! Covers: a hive, a WAN link, a private instance behind a gateway, a
//! partition that heals, a key rotation, and a drain — with applications
//! sending and receiving through the local API throughout.

mod common;

use std::time::{Duration, Instant};

use common::*;
use lattice_client::{Client, DrainRequest, DrainState};

const SERVICES: &[ServiceSpec] = &[ServiceSpec {
    name: "test",
    secret: "test-secret-with-plenty-of-entropy",
}];

#[tokio::test]
async fn six_node_gate() {
    let tmp = std::env::temp_dir().join(format!("lattice-six-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    const HIVE: &str = "::1/128";
    // gw's port is pre-allocated so h1 (which boots first) can root to
    // gw's WAN address. gw's identity is pre-created for the same reason.
    let gw_port = free_port();
    let gw_wan_addr = format!("127.0.0.1:{gw_port}");
    // The private instance's identity is pre-created so the gateway can
    // name it in `serves` (spec §3, gateway consent): the gateway carries
    // traffic for the private instance only when both records name each
    // other.
    let priv_dir = tmp.join("priv");
    let priv_keys = init_node(&priv_dir);
    let priv_id = priv_keys.id;
    let gw_dir = tmp.join("gw");
    let gw_keys = init_node(&gw_dir);
    let gw_id = gw_keys.id;
    let gw_channel_key = gw_keys.channel_key;

    let hive_extras = |port: Option<u16>| NodeExtras {
        port,
        listen: vec!["[::1]:{port}".to_string()],
        hive: vec![HIVE.to_string()],
        advertise: vec!["ws://[::1]:{port}/".to_string()],
        ips: vec!["::1".to_string()],
        ..NodeExtras::default()
    };

    // h1: hive-only. Roots to gw's WAN address (a WAN link, so h1 can
    // reach the WAN node; a hive link would carry no WAN records).
    let h1 = boot_node_ex(
        &tmp,
        "h1",
        None,
        Some(PeerSpec {
            addr: &gw_wan_addr,
            channel_key: gw_channel_key,
            id: gw_id,
        }),
        SERVICES,
        hive_extras(None),
    );
    let h1_hive_addr = format!("[::1]:{}", h1.port);
    let h2 = boot_node_ex(
        &tmp,
        "h2",
        None,
        Some(PeerSpec {
            addr: &h1_hive_addr,
            channel_key: h1.channel_key,
            id: h1.id,
        }),
        SERVICES,
        hive_extras(None),
    );
    let h2_hive_addr = format!("[::1]:{}", h2.port);
    let h3 = boot_node_ex(
        &tmp,
        "h3",
        None,
        Some(PeerSpec {
            addr: &h1_hive_addr,
            channel_key: h1.channel_key,
            id: h1.id,
        }),
        SERVICES,
        hive_extras(None),
    );
    // gw: dual-homed (hive [::1] + WAN 127.0.0.1). Roots to h2 over a
    // hive link. Serves the private instance, so it publishes a WAN
    // record (a gateway's WAN record carries `serves`).
    let gw = boot_node_ex(
        &tmp,
        "gw",
        Some(gw_keys),
        Some(PeerSpec {
            addr: &h2_hive_addr,
            channel_key: h2.channel_key,
            id: h2.id,
        }),
        SERVICES,
        NodeExtras {
            port: Some(gw_port),
            listen: vec!["[::1]:{port}".to_string(), "127.0.0.1:{port}".to_string()],
            hive: vec![HIVE.to_string()],
            advertise: vec!["ws://[::1]:{port}/".to_string()],
            ips: vec!["::1".to_string()],
            serves: Some(vec![priv_id]),
            ..NodeExtras::default()
        },
    );
    let wan = boot_node_ex(
        &tmp,
        "wan",
        None,
        Some(PeerSpec {
            addr: &gw_wan_addr,
            channel_key: gw.channel_key,
            id: gw.id,
        }),
        SERVICES,
        NodeExtras::default(),
    );
    let priv_node = boot_node_ex(
        &tmp,
        "priv",
        Some(priv_keys),
        Some(PeerSpec {
            addr: &gw_wan_addr,
            channel_key: gw.channel_key,
            id: gw.id,
        }),
        SERVICES,
        NodeExtras {
            private_gateways: Some(vec![gw.id]),
            ..NodeExtras::default()
        },
    );

    for n in [&h1, &h2, &h3, &gw, &wan, &priv_node] {
        wait_sockets(n).await;
    }

    let mut c_h1 = Client::connect_app(&h1.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect h1");
    let mut c_h2 = Client::connect_app(&h2.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect h2");
    let mut c_h3 = Client::connect_app(&h3.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect h3");
    let mut c_wan = Client::connect_app(&wan.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("connect wan");
    let mut c_priv = Client::connect_app(
        &priv_node.app,
        "test",
        b"test-secret-with-plenty-of-entropy",
    )
    .await
    .expect("connect priv");

    // ---- Convergence: everyone learns the paths they need. ----
    wait_for_path(&mut c_wan, &priv_node.id, 60).await; // wan -> priv via gw
    wait_for_path(&mut c_priv, &wan.id, 60).await; // priv -> wan via gw
    wait_for_path(&mut c_h2, &h3.id, 60).await; // hive-internal
    wait_for_path(&mut c_h3, &h2.id, 60).await; // hive-internal (reverse)
    // h1 reaches wan only via gw (h1 is hive-only and cannot learn wan's
    // WAN record over a hive link), so wait for that path to converge
    // before partitioning wan.
    wait_for_path(&mut c_h1, &wan.id, 60).await; // h1 -> wan via gw

    // ---- 1. WAN -> private instance, through the gateway. ----
    let d = send_and_fetch(
        &mut c_wan,
        &mut c_priv,
        priv_node.id,
        b"hello private",
        None,
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(d.body, b"hello private");
    assert_eq!(d.from, wan.id);

    // ---- 2. Private instance -> WAN, back through the gateway. ----
    let d = send_and_fetch(
        &mut c_priv,
        &mut c_wan,
        wan.id,
        b"hello back",
        None,
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(d.body, b"hello back");
    assert_eq!(d.from, priv_node.id);

    // ---- 3. Hive-internal delivery. ----
    let d = send_and_fetch(
        &mut c_h2,
        &mut c_h3,
        h3.id,
        b"hive hello",
        None,
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(d.body, b"hive hello");

    // ---- 4. Partition: kill the WAN node; a message to it must queue, ----
    // ---- not vanish; after heal it must be delivered.                ----
    let mut wan = wan;
    wan.kill9();
    // Let h1 notice the dead link before it tries to send; otherwise the
    // offer can go into a dying socket and sit InFlight until the receipt
    // deadline instead of queueing for retry.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mid = c_h1
        .send(&lattice_client::Send {
            to: wan.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-h1".to_vec(),
            body: b"during partition".to_vec(),
            exp: None,
            priority: None,
            route: None,
        })
        .await
        .expect("send during partition");
    // While the partition holds, the message must not be delivered.
    tokio::time::sleep(Duration::from_secs(5)).await;
    if let Some(s) = c_h1.status(&mid).await.expect("status") {
        if s.status == 3 {
            panic!("message delivered while the WAN node was down");
        }
    }
    // Heal: restart wan; it redials h1. The queued message must arrive.
    wan.restart();
    wait_sockets(&wan).await;
    let mut c_wan = Client::connect_app(&wan.app, "test", b"test-secret-with-plenty-of-entropy")
        .await
        .expect("reconnect wan");
    let deadline = Instant::now() + Duration::from_secs(75);
    let delivered = loop {
        let batch = c_wan.fetch(16).await.expect("fetch after heal");
        if let Some(d) = batch.into_iter().find(|d| d.mid == mid) {
            break d;
        }
        assert!(
            Instant::now() < deadline,
            "message sent during partition never arrived after heal"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(delivered.body, b"during partition");

    // ---- 5. Rotation: h2 rotates its signing key; the mesh keeps working. ----
    let mut admin_h2 = Client::connect_admin(&h2.admin).await.expect("admin h2");
    let before = admin_h2.node().await.expect("node before rotate");
    // The following key is generated offline; only its commitment is sent.
    let following = lattice_crypto::generate_seed();
    let commitment = lattice_crypto::hash(lattice_crypto::public_key(&following).as_ref());
    let msg = admin_h2
        .rotate(&h2.next_key, commitment.as_bytes())
        .await
        .expect("rotate");
    assert!(msg.contains("rotated"), "unexpected rotate reply: {msg}");
    let after = admin_h2.node().await.expect("node after rotate");
    assert_eq!(before.id, after.id, "rotation must not change the node id");
    // Give the new record a moment to gossip, then h3 -> h2 must still work.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let d = send_and_fetch(
        &mut c_h3,
        &mut c_h2,
        h2.id,
        b"after rotation",
        None,
        Duration::from_secs(30),
    )
    .await;
    assert_eq!(d.body, b"after rotation");

    // ---- 6. Drain: h3 drains; new custody is refused; after un-drain, delivery resumes. ----
    let mut admin_h3 = Client::connect_admin(&h3.admin).await.expect("admin h3");
    let draining = admin_h3
        .drain(DrainRequest::Set(DrainState::Draining))
        .await
        .expect("drain on")
        .draining;
    assert!(draining);
    let mid = c_h2
        .send(&lattice_client::Send {
            to: h3.id,
            tsvc: "test".into(),
            tmbx: b"mbx".to_vec(),
            fmbx: b"from-h2".to_vec(),
            body: b"while draining".to_vec(),
            exp: None,
            priority: None,
            route: None,
        })
        .await
        .expect("send to draining node");
    // While draining, h3 refuses custody; the message must not be delivered.
    tokio::time::sleep(Duration::from_secs(6)).await;
    if let Some(s) = c_h2.status(&mid).await.expect("status") {
        if s.status == 3 {
            panic!("message delivered to a draining node");
        }
    }
    let batch = c_h3.fetch(16).await.expect("fetch while draining");
    assert!(
        !batch.iter().any(|d| d.mid == mid),
        "draining node must not accept new messages"
    );
    let draining = admin_h3
        .drain(DrainRequest::Set(DrainState::Serving))
        .await
        .expect("drain off")
        .draining;
    assert!(!draining);
    // After un-drain, the queued message is delivered (sender retries).
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        let batch = c_h3.fetch(16).await.expect("fetch after un-drain");
        if batch.iter().any(|d| d.mid == mid) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "message never delivered after un-drain"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
