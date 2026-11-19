//! The routing graph: built from records' link claims.
//!
//! An edge exists between A and B only if both records list each other.
//! Distances are BFS hop counts from the local node. Next-hop selection
//! implements the spec's randomized progress with opportunistic sideways
//! turns.
//!
//! A private instance publishes no links, so it is reachable only through
//! its gateways. The private↔gateway pseudo-edge exists only when both
//! records name each other: the private record's `gw` lists the gateway
//! and the gateway's record lists the private id in `serves` (spec §3,
//! "Gateway consent"). A private node is a leaf in the BFS: reachable as
//! a destination, never expanded as a transit vertex.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use lattice_types::Identifier;

use crate::rng::Rng;

/// One record's contribution to the routing graph.
pub struct GraphRecord {
    pub id: Identifier,
    /// Links the record claims. Empty for private records.
    pub links: Vec<Identifier>,
    /// True for a private record (`mode = 1`).
    pub private: bool,
    /// Gateways the private record names (`gw`); empty otherwise.
    pub gateways: Vec<Identifier>,
    /// Private ids this record consents to serve (`serves`); public
    /// records only, empty otherwise.
    pub serves: Vec<Identifier>,
}

/// Adjacency is ordered so that neighbor iteration — which feeds the
/// randomized next-hop choice — is identical on every run with the same
/// seed.
#[derive(Default)]
pub struct Graph {
    adjacency: BTreeMap<Identifier, BTreeSet<Identifier>>,
    /// Ids of private records. Leaves in the BFS: reachable, never
    /// expanded, never chosen as a transit hop.
    private: BTreeSet<Identifier>,
}

impl Graph {
    /// Build the graph from the known records, including our own.
    ///
    /// A private↔gateway pseudo-edge is added only when both records name
    /// each other: the private record's `gw` lists the gateway and the
    /// gateway's record lists the private id in `serves`. A gateway that
    /// does not list the private id confers no edge.
    pub fn build<I>(own: &Identifier, records: I) -> Self
    where
        I: IntoIterator<Item = GraphRecord>,
    {
        let mut claims: BTreeMap<Identifier, BTreeSet<Identifier>> = BTreeMap::new();
        let mut private: BTreeSet<Identifier> = BTreeSet::new();
        let mut serves: BTreeMap<Identifier, BTreeSet<Identifier>> = BTreeMap::new();
        let mut private_gateways: Vec<(Identifier, Vec<Identifier>)> = Vec::new();
        for r in records {
            if r.private {
                private.insert(r.id);
                private_gateways.push((r.id, r.gateways));
                // A private record claims no links and carries no serves
                // (validation enforces both); it contributes no claims.
                claims.entry(r.id).or_default();
            } else {
                claims.insert(r.id, r.links.into_iter().collect());
                serves.insert(r.id, r.serves.into_iter().collect());
            }
        }
        let mut adjacency: BTreeMap<Identifier, BTreeSet<Identifier>> = BTreeMap::new();
        let ids: Vec<Identifier> = claims
            .keys()
            .copied()
            .chain(std::iter::once(*own))
            .collect();
        for a in &ids {
            let a_links = claims.get(a).cloned().unwrap_or_default();
            for b in a_links {
                // Edge only when both sides claim it.
                if claims.get(&b).is_some_and(|bl| bl.contains(a)) {
                    adjacency.entry(*a).or_default().insert(b);
                    adjacency.entry(b).or_default().insert(*a);
                }
            }
        }
        // Pseudo-edges: only on mutual naming. The gateway's `serves` is
        // the consent; without it the private record alone creates nothing.
        for (p, gws) in private_gateways {
            for gw in gws {
                let consents = serves.get(&gw).is_some_and(|s| s.contains(&p));
                if consents {
                    adjacency.entry(p).or_default().insert(gw);
                    adjacency.entry(gw).or_default().insert(p);
                }
            }
        }
        Graph { adjacency, private }
    }

    pub fn neighbors(&self, id: &Identifier) -> impl Iterator<Item = &Identifier> {
        self.adjacency.get(id).into_iter().flatten()
    }

    /// BFS distances from `from`.
    ///
    /// A private node is a leaf: it is reachable as a destination, but it
    /// is never expanded, so no path routes through it. The source of the
    /// BFS is exempt — distances from a private destination are still
    /// needed to route to it.
    pub fn distances(&self, from: &Identifier) -> BTreeMap<Identifier, u32> {
        let mut dist = BTreeMap::new();
        let mut q = VecDeque::new();
        dist.insert(*from, 0u32);
        q.push_back(*from);
        while let Some(n) = q.pop_front() {
            let d = dist[&n];
            if n != *from && self.private.contains(&n) {
                continue;
            }
            for m in self.neighbors(&n) {
                if !dist.contains_key(m) {
                    dist.insert(*m, d + 1);
                    q.push_back(*m);
                }
            }
        }
        dist
    }

    /// Choose the next hop toward `dst` from `from`.
    ///
    /// - progress: uniform among neighbors strictly closer to dst;
    /// - sideways: only opportunistically, with probability `sideways_prob`,
    ///   uniform among neighbors exactly as close (never farther);
    /// - a private neighbor is never chosen unless it is `dst` itself;
    /// - returns `None` when no progress neighbor is usable, even if a
    ///   sideways one exists: waiting on a sideways neighbor can cycle, so
    ///   the caller holds instead (caller retries on the next tick).
    ///
    /// `exclude` skips neighbors that already reported "already have" for
    /// this leg.
    #[allow(clippy::too_many_arguments)]
    pub fn next_hop(
        &self,
        from: &Identifier,
        dst: &Identifier,
        dist: &BTreeMap<Identifier, u32>,
        sideways_prob: f64,
        exclude: &HashSet<Identifier>,
        up: &HashSet<Identifier>,
        rng: &mut Rng,
    ) -> Option<Identifier> {
        let my_dist = *dist.get(from)?;
        let mut progress: Vec<Identifier> = Vec::new();
        let mut sideways: Vec<Identifier> = Vec::new();
        for n in self.neighbors(from) {
            if exclude.contains(n) || !up.contains(n) {
                continue;
            }
            // A private node is a valid destination but never a transit
            // hop: it may be chosen only when it is the destination.
            if n != dst && self.private.contains(n) {
                continue;
            }
            match dist.get(n) {
                Some(&d) if d < my_dist => progress.push(*n),
                Some(&d) if d == my_dist => sideways.push(*n),
                _ => {}
            }
        }
        if !sideways.is_empty() && rng.chance(sideways_prob) {
            return rng.pick(&sideways).copied();
        }
        if !progress.is_empty() {
            return rng.pick(&progress).copied();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_id(b: u8) -> Identifier {
        Identifier::from_bytes([b; 32])
    }

    fn public(id: Identifier, links: &[u8], serves: &[u8]) -> GraphRecord {
        GraphRecord {
            id,
            links: links.iter().map(|b| mk_id(*b)).collect(),
            private: false,
            gateways: Vec::new(),
            serves: serves.iter().map(|b| mk_id(*b)).collect(),
        }
    }

    fn private(id: Identifier, gateways: &[u8]) -> GraphRecord {
        GraphRecord {
            id,
            links: Vec::new(),
            private: true,
            gateways: gateways.iter().map(|b| mk_id(*b)).collect(),
            serves: Vec::new(),
        }
    }

    /// Destination D with two arms: D—A—F and D—B—S, plus F—S.
    /// dist from D: A=1, B=1, F=2, S=2. From F, A is progress and S is
    /// sideways.
    fn fixture() -> (Graph, Identifier, Identifier, Identifier, Identifier) {
        let (d, a, b, f, s) = (
            mk_id(0xD0),
            mk_id(0xA0),
            mk_id(0xB0),
            mk_id(0xF0),
            mk_id(0x50),
        );
        let records = [
            public(d, &[0xA0, 0xB0], &[]),
            public(a, &[0xD0, 0xF0], &[]),
            public(b, &[0xD0, 0x50], &[]),
            public(f, &[0xA0, 0x50], &[]),
            public(s, &[0xB0, 0xF0], &[]),
        ];
        let graph = Graph::build(&f, records);
        (graph, d, a, f, s)
    }

    #[test]
    fn sideways_only_returns_none() {
        let (g, d, a, f, s) = fixture();
        let dist = g.distances(&d);
        let up: HashSet<Identifier> = [a, s].into_iter().collect();
        // The only progress neighbor is excluded (it already answered
        // "already have"), leaving only the sideways neighbor S.
        let exclude: HashSet<Identifier> = [a].into_iter().collect();
        let mut rng = Rng::new(7);
        assert_eq!(
            g.next_hop(&f, &d, &dist, 0.0, &exclude, &up, &mut rng),
            None
        );
    }

    #[test]
    fn sideways_still_allowed_opportunistically() {
        let (g, d, a, f, s) = fixture();
        let dist = g.distances(&d);
        let up: HashSet<Identifier> = [a, s].into_iter().collect();
        let exclude: HashSet<Identifier> = [a].into_iter().collect();
        let mut rng = Rng::new(7);
        assert_eq!(
            g.next_hop(&f, &d, &dist, 1.0, &exclude, &up, &mut rng),
            Some(s)
        );
    }

    #[test]
    fn progress_neighbor_is_preferred() {
        let (g, d, a, f, s) = fixture();
        let dist = g.distances(&d);
        let up: HashSet<Identifier> = [a, s].into_iter().collect();
        let exclude = HashSet::new();
        let mut rng = Rng::new(7);
        assert_eq!(
            g.next_hop(&f, &d, &dist, 0.0, &exclude, &up, &mut rng),
            Some(a)
        );
    }

    /// A private record naming a gateway whose record does not list the
    /// private id confers no edge.
    #[test]
    fn pseudo_edge_requires_gateway_consent() {
        let p = mk_id(0x91);
        let gw = mk_id(0x6A);
        // Gateway does not list P in serves: no edge either way.
        let g = Graph::build(&gw, [private(p, &[0x6A]), public(gw, &[], &[])]);
        assert!(!g.distances(&gw).contains_key(&p));
        assert_eq!(
            g.distances(&p).len(),
            1,
            "P must be unreachable without consent"
        );
        // Gateway lists P in serves: the edge exists in both directions.
        let g = Graph::build(&gw, [private(p, &[0x6A]), public(gw, &[], &[0x91])]);
        assert_eq!(g.distances(&gw).get(&p), Some(&1));
        assert_eq!(g.distances(&p).get(&gw), Some(&1));
    }

    /// A private record naming a gateway that does not reciprocate creates
    /// no edge, even when the gateway consents to a *different* private id.
    #[test]
    fn pseudo_edge_consent_is_per_private_id() {
        let p = mk_id(0x91);
        let other = mk_id(0xB2);
        let gw = mk_id(0x6A);
        let g = Graph::build(
            &gw,
            [
                private(p, &[0x6A]),
                public(gw, &[], &[0xB2]), // serves `other`, not `p`
                private(other, &[0x6A]),
            ],
        );
        assert!(!g.distances(&gw).contains_key(&p));
        assert_eq!(g.distances(&gw).get(&other), Some(&1));
    }

    /// A consenting gateway that is itself private confers no edge:
    /// serves is a public-record field.
    #[test]
    fn private_gateway_confers_no_edge() {
        let p = mk_id(0x91);
        let gw = mk_id(0x6A);
        let mut gw_rec = private(gw, &[]);
        gw_rec.serves = vec![p]; // not a valid private record; ignored
        let g = Graph::build(&gw, [private(p, &[0x6A]), gw_rec]);
        assert!(!g.distances(&gw).contains_key(&p));
    }

    /// BFS never expands a private node: the only path to B goes through
    /// the private node P, so B is unreachable.
    #[test]
    fn private_node_blocks_transit() {
        // A — P — B, where P is private and consented by both A and B.
        let (a, p, b) = (mk_id(0xA1), mk_id(0x91), mk_id(0xB1));
        let g = Graph::build(
            &a,
            [
                public(a, &[], &[0x91]),
                private(p, &[0xA1, 0xB1]),
                public(b, &[], &[0x91]),
            ],
        );
        let dist = g.distances(&b);
        assert_eq!(dist.get(&p), Some(&1), "P is reachable as a destination");
        assert!(!dist.contains_key(&a), "A must not be reachable through P");
        let dist_a = g.distances(&a);
        assert!(
            !dist_a.contains_key(&b),
            "B must not be reachable through P"
        );
    }

    /// A private node is never selected as a next hop unless it is the
    /// destination itself.
    #[test]
    fn private_node_is_never_a_transit_hop() {
        // X—A—P—Y with P private: X—A and X—Y are mutual claims, A—P and
        // Y—P are pseudo-edges (A and Y both serve P).
        // BFS from A: dist = {A:0, X:1, P:1, Y:2}; P is never expanded.
        let (x, a, p, y) = (mk_id(0x11), mk_id(0xA1), mk_id(0x91), mk_id(0x59));
        let g = Graph::build(
            &y,
            [
                public(x, &[0xA1, 0x59], &[]),
                public(a, &[0x11], &[0x91]),
                private(p, &[0xA1, 0x59]),
                public(y, &[0x11], &[0x91]),
            ],
        );
        let dist = g.distances(&a);
        assert_eq!(dist.get(&p), Some(&1));
        assert_eq!(dist.get(&y), Some(&2));
        let up: HashSet<Identifier> = [x, p].into_iter().collect();
        let mut rng = Rng::new(7);
        // From Y toward A: X and P are both progress hops by distance, but
        // P is private and not the destination, so it must not be picked.
        let exclude = HashSet::new();
        assert_eq!(
            g.next_hop(&y, &a, &dist, 0.0, &exclude, &up, &mut rng),
            Some(x)
        );
        // With X excluded, P is the only progress candidate left; it must
        // not be picked, so there is no route.
        let exclude: HashSet<Identifier> = [x].into_iter().collect();
        assert_eq!(
            g.next_hop(&y, &a, &dist, 0.0, &exclude, &up, &mut rng),
            None
        );
        // With P as the destination, P is a valid next hop.
        let dist_p = g.distances(&p);
        let up_p: HashSet<Identifier> = [x, p].into_iter().collect();
        let exclude = HashSet::new();
        let mut rng = Rng::new(7);
        assert_eq!(
            g.next_hop(&y, &p, &dist_p, 0.0, &exclude, &up_p, &mut rng),
            Some(p)
        );
    }

    /// The BFS source is exempt from the leaf rule: distances from a
    /// private destination are still computed (its neighbors are reached).
    #[test]
    fn private_source_is_expanded() {
        let p = mk_id(0x91);
        let gw = mk_id(0x6A);
        let g = Graph::build(&p, [private(p, &[0x6A]), public(gw, &[], &[0x91])]);
        let dist = g.distances(&p);
        assert_eq!(dist.get(&gw), Some(&1));
    }
}
