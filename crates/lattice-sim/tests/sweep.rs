//! Seed sweep and invariant checker for the simulator.
//!
//! `seed_sweep_invariants_hold` runs the same scenario under many seeds and
//! checks, for each run:
//!
//!   (a) convergence — every node holds every node's record;
//!   (b) no silent loss — every sent message is either delivered or the
//!       sender was told (a terminal status: delivered, failed, expired);
//!   (c) bounded state — custody bytes stay within `transit_cap` and the
//!       inbox stays within `inbox_max_total` on every node;
//!   (d) routing termination — no message is delivered twice to the same
//!       node, and every message reaches a terminal state (a message that
//!       loops forever never does).
//!
//! The scenario is a random connected topology (a random spanning tree plus
//! two extra edges) with per-link loss, duplication and jitter, so the
//! invariants are checked under faults, not just on a clean mesh.
//!
//! Every run is fully determined by its seed: same seed, same trace. The
//! failing seed is printed on failure. Set `LATTICE_SWEEP_SEEDS` to change
//! the number of seeds (default 16).
//!
//! `checker_flags_unterminated_message` demonstrates the checker catching a
//! violation: with all links at 100% loss and a receipt timeout far beyond
//! the horizon, no message can terminate, and the checker must say so.

use std::collections::HashSet;

use lattice_core::Config;
use lattice_proto::local;
use lattice_sim::{LinkBehavior, Sim};
use lattice_store::Store;
use lattice_types::MessageId;

const TERMINAL: [u64; 3] = [
    local::MSG_STATUS_DELIVERED,
    local::MSG_STATUS_FAILED,
    local::MSG_STATUS_EXPIRED,
];

fn sweep_config() -> Config {
    Config {
        reconcile_interval_secs: 1,
        record_refresh_secs: 3600,
        snow_per_min: 0.0,
        receipt_timeout_public: 5,
        receipt_timeout_private: 5,
        retry_base_secs: 1,
        retry_max_secs: 2,
        fresh_waypoint_retries: 1,
        default_message_horizon: 3600,
        transit_cap: 64 * 1024,
        inbox_max_total: 64,
        services: vec!["test".to_string()],
        ..Config::default()
    }
}

/// SplitMix64: scenario construction only; the sim has its own seeded RNG.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

const NODES: usize = 6;
const MESSAGES: usize = 8;

/// Build the scenario for `seed`: a random connected topology with lossy,
/// jittery links, converged records, and `MESSAGES` messages in flight.
fn build_scenario(seed: u64) -> (Sim, Vec<(MessageId, usize, usize)>) {
    let mut rng = SplitMix64(seed ^ 0xA076_1D64_78BD_642F);
    let mut sim = Sim::with_seed(sweep_config(), seed);
    for _ in 0..NODES {
        sim.add_node();
    }
    // Random spanning tree: node i attaches to a uniformly chosen earlier node.
    for i in 1..NODES {
        let j = (rng.next() % i as u64) as usize;
        sim.connect(i, j);
    }
    // Two extra edges for path diversity.
    for _ in 0..2 {
        let a = (rng.next() % NODES as u64) as usize;
        let b = (rng.next() % NODES as u64) as usize;
        if a != b && sim.link_between(a, b).is_none() {
            sim.connect(a, b);
        }
    }
    for id in sim.link_ids() {
        let latency = 5 + rng.next() % 26; // 5..=30 ms
        sim.set_latency(id, latency);
        sim.set_link_behavior(
            id,
            LinkBehavior {
                loss: 0.10,
                duplicate: 0.05,
                jitter_ms: 40,
            },
        );
    }
    // Let records converge before sending.
    for _ in 0..60 {
        let converged = (0..NODES).all(|i| {
            (0..NODES).all(|j| i == j || sim.nodes[i].has_path(&sim.ids[j]))
        });
        if converged {
            break;
        }
        sim.run_for(1);
    }
    let mut sent = Vec::with_capacity(MESSAGES);
    for _ in 0..MESSAGES {
        let from = (rng.next() % NODES as u64) as usize;
        let mut to = (rng.next() % (NODES as u64 - 1)) as usize;
        if to >= from {
            to += 1;
        }
        let mid = sim.app_send(from, to, b"sweep-payload");
        sent.push((mid, from, to));
    }
    (sim, sent)
}

/// Check the invariants; returns one string per violation.
fn check_invariants(
    sim: &mut Sim,
    sent: &[(MessageId, usize, usize)],
    cfg: &Config,
) -> Vec<String> {
    let mut violations = Vec::new();

    // (a) Convergence: every node holds every node's record.
    for i in 0..NODES {
        let held = sim.nodes[i].debug_record_count();
        if held < NODES {
            violations.push(format!("node {i}: holds {held}/{NODES} records (convergence)"));
        }
    }

    // (b) No silent loss: every sent message is delivered or the sender
    // was told (terminal status).
    for &(mid, from, _) in sent {
        let delivered = sim.deliveries.iter().any(|d| d.mid == mid);
        let terminal = sim
            .statuses
            .iter()
            .any(|s| s.mid == mid && TERMINAL.contains(&s.status));
        if !delivered && !terminal {
            violations.push(format!(
                "mid {mid:?} from node {from}: neither delivered nor terminated (silent loss)"
            ));
        }
    }

    // (c) Bounded state: custody bytes and inbox occupancy within caps.
    for i in 0..NODES {
        let bytes = sim.custody_bytes(i);
        if bytes > cfg.transit_cap {
            violations.push(format!(
                "node {i}: custody holds {bytes} bytes, cap is {}",
                cfg.transit_cap
            ));
        }
        let inbox = sim.nodes[i].store_ref().inbox_len_total().unwrap_or(u64::MAX);
        if inbox > cfg.inbox_max_total {
            violations.push(format!(
                "node {i}: inbox holds {inbox}, cap is {}",
                cfg.inbox_max_total
            ));
        }
    }

    // (d) Routing termination: no message delivered twice to the same node.
    // (A message looping forever never reaches a terminal state, which (b)
    // already flags; this catches the other half — duplication.)
    let mut seen = HashSet::new();
    for d in &sim.deliveries {
        if !seen.insert((d.mid, d.node)) {
            violations.push(format!(
                "mid {:?} delivered more than once to node {}",
                d.mid, d.node
            ));
        }
    }

    violations
}

#[test]
fn seed_sweep_invariants_hold() {
    let seeds: u64 = std::env::var("LATTICE_SWEEP_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    let cfg = sweep_config();
    let mut failures = Vec::new();
    for seed in 0..seeds {
        let (mut sim, sent) = build_scenario(seed);
        sim.run_for(150);
        let violations = check_invariants(&mut sim, &sent, &cfg);
        if !violations.is_empty() {
            failures.push(format!("seed {seed}:\n  {}", violations.join("\n  ")));
        }
    }
    assert!(
        failures.is_empty(),
        "invariant violations in {} seed(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn same_seed_same_trace() {
    let run = || {
        let (mut sim, _sent) = build_scenario(0xC0FFEE);
        sim.run_for(60);
        let deliveries: Vec<_> = sim
            .deliveries
            .iter()
            .map(|d| (d.mid, d.node, d.body.clone()))
            .collect();
        let statuses: Vec<_> = sim.statuses.iter().map(|s| (s.mid, s.status)).collect();
        (
            deliveries,
            statuses,
            sim.frame_counts.clone(),
            sim.dropped_frames,
            sim.duplicated_frames,
        )
    };
    assert_eq!(run(), run(), "same seed must reproduce the same trace");
}

/// The checker must flag a run in which a message can never terminate:
/// 100% loss on every link and a receipt timeout far beyond the horizon.
/// The sender can neither deliver nor be told; invariant (b) is violated.
#[test]
fn checker_flags_unterminated_message() {
    let mut cfg = sweep_config();
    cfg.receipt_timeout_public = 86_400; // 1 day: no timeout within the run
    let mut sim = Sim::with_seed(cfg, 0xBAD5EED);
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    sim.run_for(10); // converge while links are clean
    for id in sim.link_ids() {
        sim.set_link_behavior(
            id,
            LinkBehavior {
                loss: 1.0,
                duplicate: 0.0,
                jitter_ms: 0,
            },
        );
    }
    let mid = sim.app_send(0, 2, b"doomed");
    sim.run_for(30);
    let sent = vec![(mid, 0usize, 2usize)];
    let violations = check_invariants(&mut sim, &sent, &sweep_config());
    assert!(
        violations.iter().any(|v| v.contains("silent loss")),
        "checker must flag the unterminated message, got: {violations:?}"
    );
}

/// A node that drops every outgoing frame: messages routed through it can
/// never arrive, but the sender must still be told (terminal status).
#[test]
fn adversary_blackhole_node_still_terminates_messages() {
    let mut cfg = sweep_config();
    cfg.receipt_timeout_public = 5;
    let mut sim = Sim::with_seed(cfg, 7);
    for _ in 0..4 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    sim.connect(2, 3);
    sim.run_for(10); // converge before the adversary wakes up
    sim.set_adversary(
        1,
        lattice_sim::Adversary {
            drop_outgoing: 1.0,
            ..Default::default()
        },
    );
    let mid = sim.app_send(0, 3, b"through the black hole");
    sim.run_for(60);
    let delivered = sim.deliveries.iter().any(|d| d.mid == mid);
    let terminal = sim
        .statuses
        .iter()
        .any(|s| s.mid == mid && TERMINAL.contains(&s.status));
    assert!(
        !delivered,
        "black-holed message must not be delivered"
    );
    assert!(
        terminal,
        "sender must be told the message failed (terminal status)"
    );
}

/// A node that injects garbage frames must not wedge the mesh: honest
/// traffic still flows and no node crashes.
#[test]
fn adversary_injecting_garbage_does_not_wedge_the_mesh() {
    let mut sim = Sim::with_seed(sweep_config(), 11);
    for _ in 0..3 {
        sim.add_node();
    }
    sim.connect(0, 1);
    sim.connect(1, 2);
    sim.connect(0, 2);
    sim.run_for(5);
    sim.set_adversary(
        1,
        lattice_sim::Adversary {
            inject: Some((
                lattice_proto::frames::Frame::Offer(lattice_proto::frames::OfferFrame {
                    message: vec![0xDE, 0xAD, 0xBE, 0xEF],
                }),
                100,
            )),
            ..Default::default()
        },
    );
    sim.run_for(2);
    let mid = sim.app_send(0, 2, b"still works");
    sim.run_for(30);
    assert!(
        sim.deliveries.iter().any(|d| d.mid == mid),
        "honest traffic must flow despite injected garbage"
    );
    assert!(sim.injected_frames > 0, "adversary must have injected");
}
