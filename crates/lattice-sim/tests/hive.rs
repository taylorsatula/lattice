//! Hive scope filtering: two hives joined by a WAN link, plus a WAN node.
//!
//! Topology (link scopes in brackets):
//!
//! ```text
//!   a1 ──[hive]── a2          hive A (10.0.0.0/16)
//!   │
//!  [wan]
//!   │
//!   b1 ──[hive]── b2          hive B (10.1.0.0/16)
//!   │
//!  [wan]
//!   │
//!   w                          WAN-only node
//! ```
//!
//! a1 and b1 are dual-homed (a hive endpoint and a WAN endpoint each), so
//! they publish both a hive record and a WAN record. a2 and b2 are
//! hive-only and publish only a hive record. w publishes only a WAN
//! record.
//!
//! The test asserts that hive records never appear on WAN links and WAN
//! records never appear on hive links, in both directions, across both
//! hives.

use lattice_core::Config;
use lattice_proto::record::Scope;
use lattice_sim::Sim;
use lattice_store::Store;

const HIVE_A: &str = "10.0.0.0/16";
const HIVE_B: &str = "10.1.0.0/16";

fn fast_config() -> Config {
    Config {
        reconcile_interval_secs: 1,
        republish_min_interval_secs: 0,
        record_refresh_secs: 3600,
        snow_per_min: 0.0,
        receipt_timeout_public: 30,
        fresh_waypoint_retries: 1,
        services: vec!["test".to_string()],
        hive_cidrs: vec![HIVE_A.to_string(), HIVE_B.to_string()],
        ..Config::default()
    }
}

/// A dual-homed node: one hive endpoint, one WAN endpoint. Publishes both
/// a hive record and a WAN record.
fn add_dual_homed(sim: &mut Sim, hive_ip: &str, wan_ip: &str) -> usize {
    sim.add_node_with(|c| {
        c.advertise = vec![
            format!("ws://{hive_ip}:8443/"),
            format!("ws://{wan_ip}:8443/"),
        ];
        c.advertise_ips = vec![hive_ip.parse().unwrap(), wan_ip.parse().unwrap()];
    })
}

/// A hive-only node: one hive endpoint. Publishes only a hive record.
fn add_hive_only(sim: &mut Sim, hive_ip: &str) -> usize {
    sim.add_node_with(|c| {
        c.advertise = vec![format!("ws://{hive_ip}:8443/")];
        c.advertise_ips = vec![hive_ip.parse().unwrap()];
    })
}

/// A WAN-only node: one WAN endpoint. Publishes only a WAN record.
fn add_wan_only(sim: &mut Sim, wan_ip: &str) -> usize {
    sim.add_node_with(|c| {
        c.advertise = vec![format!("ws://{wan_ip}:8443/")];
        c.advertise_ips = vec![wan_ip.parse().unwrap()];
        c.hive_cidrs = Vec::new();
    })
}

fn has_record(sim: &Sim, node: usize, id: lattice_types::Identifier, scope: Scope) -> bool {
    sim.nodes[node]
        .store_ref()
        .record_get(&id, scope)
        .expect("record_get")
        .is_some()
}

#[test]
fn hive_records_stay_in_the_hive() {
    let mut sim = Sim::new(fast_config());
    let a1 = add_dual_homed(&mut sim, "10.0.0.1", "1.1.1.1");
    let a2 = add_hive_only(&mut sim, "10.0.0.2");
    let b1 = add_dual_homed(&mut sim, "10.1.0.1", "1.0.0.1");
    let b2 = add_hive_only(&mut sim, "10.1.0.2");
    let w = add_wan_only(&mut sim, "1.0.0.2");

    sim.connect_scoped(a1, a2, Scope::Hive);
    sim.connect_scoped(b1, b2, Scope::Hive);
    sim.connect_scoped(a1, b1, Scope::Wan);
    sim.connect_scoped(b1, w, Scope::Wan);

    // Let records converge.
    sim.run_for(15);

    let id = |n: usize| sim.ids[n];

    // Each node publishes the records its scopes call for.
    assert!(
        has_record(&sim, a1, id(a1), Scope::Hive),
        "a1 publishes a hive record"
    );
    assert!(
        has_record(&sim, a1, id(a1), Scope::Wan),
        "a1 publishes a WAN record"
    );
    assert!(
        has_record(&sim, a2, id(a2), Scope::Hive),
        "a2 publishes a hive record"
    );
    assert!(
        !has_record(&sim, a2, id(a2), Scope::Wan),
        "a2 (hive-only) publishes no WAN record"
    );
    assert!(
        has_record(&sim, b1, id(b1), Scope::Hive),
        "b1 publishes a hive record"
    );
    assert!(
        has_record(&sim, b1, id(b1), Scope::Wan),
        "b1 publishes a WAN record"
    );
    assert!(
        has_record(&sim, b2, id(b2), Scope::Hive),
        "b2 publishes a hive record"
    );
    assert!(
        !has_record(&sim, b2, id(b2), Scope::Wan),
        "b2 (hive-only) publishes no WAN record"
    );
    assert!(
        has_record(&sim, w, id(w), Scope::Wan),
        "w publishes a WAN record"
    );
    assert!(
        !has_record(&sim, w, id(w), Scope::Hive),
        "w (WAN-only) publishes no hive record"
    );

    // Hive links carry hive records: a2 learns a1's hive record.
    assert!(
        has_record(&sim, a2, id(a1), Scope::Hive),
        "hive record flows on a hive link"
    );
    assert!(
        has_record(&sim, b2, id(b1), Scope::Hive),
        "hive record flows on a hive link"
    );
    // ... but not WAN records.
    assert!(
        !has_record(&sim, a2, id(a1), Scope::Wan),
        "WAN record must not flow on a hive link"
    );
    assert!(
        !has_record(&sim, b2, id(b1), Scope::Wan),
        "WAN record must not flow on a hive link"
    );

    // WAN links carry WAN records: b1 learns a1's WAN record and vice versa.
    assert!(
        has_record(&sim, b1, id(a1), Scope::Wan),
        "WAN record flows on a WAN link"
    );
    assert!(
        has_record(&sim, a1, id(b1), Scope::Wan),
        "WAN record flows on a WAN link"
    );
    // ... but not hive records.
    assert!(
        !has_record(&sim, b1, id(a1), Scope::Hive),
        "hive record must not flow on a WAN link"
    );
    assert!(
        !has_record(&sim, a1, id(b1), Scope::Hive),
        "hive record must not flow on a WAN link"
    );

    // The WAN node learns WAN records but no hive records.
    assert!(
        has_record(&sim, w, id(b1), Scope::Wan),
        "w learns b1's WAN record"
    );
    assert!(
        has_record(&sim, w, id(a1), Scope::Wan),
        "w learns a1's WAN record via b1"
    );
    assert!(
        !has_record(&sim, w, id(b1), Scope::Hive),
        "w must not learn b1's hive record"
    );
    assert!(
        !has_record(&sim, w, id(a1), Scope::Hive),
        "w must not learn a1's hive record"
    );

    // Hive records do not cross between the two hives (the only path is a
    // WAN link).
    assert!(
        !has_record(&sim, a2, id(b1), Scope::Hive),
        "hive record must not cross hives over a WAN link"
    );
    assert!(
        !has_record(&sim, a2, id(b2), Scope::Hive),
        "hive record must not cross hives over a WAN link"
    );
    assert!(
        !has_record(&sim, b2, id(a1), Scope::Hive),
        "hive record must not cross hives over a WAN link"
    );
    assert!(
        !has_record(&sim, b2, id(a2), Scope::Hive),
        "hive record must not cross hives over a WAN link"
    );
    // And WAN records do not leak into the hives.
    assert!(
        !has_record(&sim, a2, id(b1), Scope::Wan),
        "WAN record must not flow onto a hive link"
    );
    assert!(
        !has_record(&sim, b2, id(a1), Scope::Wan),
        "WAN record must not flow onto a hive link"
    );
}
