//! Neighbor selection end to end: a node with no configured roots dials
//! record-derived candidates, respects the outbound cap and the per-range
//! sub-cap, and re-forms its mesh after a partition.

use lattice_core::Config;
use lattice_sim::{LinkState, Sim};

fn fast_config() -> Config {
    Config {
        reconcile_interval_secs: 1,
        republish_min_interval_secs: 0,
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

/// Node 0 has no advertised endpoint (nobody can dial it); every other
/// node advertises one. After a full mesh converges and node 0's links
/// are all torn down, node 0 must re-dial candidates on its own.
#[test]
fn node_with_records_dials_candidates_without_roots() {
    let mut sim = Sim::new(fast_config());
    sim.add_node(); // node 0: no endpoint
    for i in 1..=8 {
        sim.add_node_with(|c| {
            c.advertise = vec![format!("ws://node{i}.example.com/")];
        });
    }
    full_mesh(&mut sim, 9);
    sim.run_for(10);
    assert!(sim.nodes[0].debug_record_count() >= 8);
    for j in 1..9 {
        if let Some(l) = sim.link_between(0, j) {
            sim.set_link(l, LinkState::Down);
        }
    }
    sim.run_for(15);
    let relinked = (1..9)
        .filter(|&j| sim.up_link_between(0, j).is_some())
        .count();
    assert!(
        relinked >= 4,
        "node 0 should re-dial record-derived candidates, got {relinked} links"
    );
}

/// More candidates than the WAN cap: exactly 16 outbound links form.
#[test]
fn outbound_links_are_capped_at_sixteen() {
    let mut sim = Sim::new(fast_config());
    sim.add_node(); // node 0: no endpoint
    for i in 1..=20 {
        sim.add_node_with(|c| {
            c.advertise = vec![format!("ws://203.0.{i}.1/")];
        });
    }
    full_mesh(&mut sim, 21);
    sim.run_for(5);
    for j in 1..21 {
        if let Some(l) = sim.link_between(0, j) {
            sim.set_link(l, LinkState::Down);
        }
    }
    sim.run_for(15);
    let linked = (1..21)
        .filter(|&j| sim.up_link_between(0, j).is_some())
        .count();
    assert_eq!(linked, 16, "the outbound cap is 16 WAN links");
}

/// At most two links into one /24, even when more candidates live there.
#[test]
fn per_range_group_sub_cap_is_enforced() {
    let mut sim = Sim::new(fast_config());
    sim.add_node(); // node 0: no endpoint
    // Six candidates in one /24 (203.0.77.0/24), fourteen elsewhere.
    for i in 1..=6 {
        sim.add_node_with(|c| {
            c.advertise = vec![format!("ws://203.0.77.{i}/")];
        });
    }
    for i in 1..=14 {
        sim.add_node_with(|c| {
            c.advertise = vec![format!("ws://198.51.{i}.1/")];
        });
    }
    full_mesh(&mut sim, 21);
    sim.run_for(5);
    for j in 1..21 {
        if let Some(l) = sim.link_between(0, j) {
            sim.set_link(l, LinkState::Down);
        }
    }
    sim.run_for(15);
    let shared = (1..=6)
        .filter(|&j| sim.up_link_between(0, j).is_some())
        .count();
    assert!(shared <= 2, "at most 2 links per /24, got {shared}");
    let total = (1..21)
        .filter(|&j| sim.up_link_between(0, j).is_some())
        .count();
    assert_eq!(total, 16);
}

/// A candidate whose dial always fails is never linked; the others are.
#[test]
fn blocked_dial_candidate_is_not_linked() {
    let mut sim = Sim::new(fast_config());
    sim.add_node(); // node 0: no endpoint
    for i in 1..=4 {
        sim.add_node_with(|c| {
            c.advertise = vec![format!("ws://203.0.{i}.1/")];
        });
    }
    full_mesh(&mut sim, 5);
    sim.run_for(5);
    for j in 1..5 {
        if let Some(l) = sim.link_between(0, j) {
            sim.set_link(l, LinkState::Down);
        }
    }
    sim.set_dial_blocked(0, 1, true);
    sim.run_for(15);
    assert!(
        sim.up_link_between(0, 1).is_none(),
        "a blocked candidate must never link"
    );
    let others = (2..=4)
        .filter(|&j| sim.up_link_between(0, j).is_some())
        .count();
    assert_eq!(others, 3, "the unblocked candidates must link");
}
