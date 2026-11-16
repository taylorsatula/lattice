//! The routing graph: built from records' link claims.
//!
//! An edge exists between A and B only if both records list each other.
//! Distances are BFS hop counts from the local node. Next-hop selection
//! implements the spec's randomized progress with opportunistic sideways
//! turns.

use std::collections::{HashMap, HashSet, VecDeque};

use lattice_types::Identifier;

use crate::rng::Rng;

pub const MAX_LINKS_WAN: usize = 16;

#[derive(Default)]
pub struct Graph {
    adjacency: HashMap<Identifier, HashSet<Identifier>>,
}

impl Graph {
    /// `links` iterates over (node, its claimed links) for every known record,
    /// including our own.
    pub fn build<'a, I>(own: &Identifier, records: I) -> Self
    where
        I: IntoIterator<Item = (&'a Identifier, &'a [Identifier])>,
    {
        let claims: HashMap<Identifier, HashSet<Identifier>> = records
            .into_iter()
            .map(|(id, links)| (*id, links.iter().copied().collect()))
            .collect();
        let mut adjacency: HashMap<Identifier, HashSet<Identifier>> = HashMap::new();
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
        Graph { adjacency }
    }

    /// Add an unconditional edge in both directions. Used for private
    /// instances, which publish no links but are reachable via the gateways
    /// named in their record.
    pub fn add_edge(&mut self, a: Identifier, b: Identifier) {
        self.adjacency.entry(a).or_default().insert(b);
        self.adjacency.entry(b).or_default().insert(a);
    }

    pub fn neighbors(&self, id: &Identifier) -> impl Iterator<Item = &Identifier> {
        self.adjacency.get(id).into_iter().flatten()
    }

    /// BFS distances from `from`.
    pub fn distances(&self, from: &Identifier) -> HashMap<Identifier, u32> {
        let mut dist = HashMap::new();
        let mut q = VecDeque::new();
        dist.insert(*from, 0u32);
        q.push_back(*from);
        while let Some(n) = q.pop_front() {
            let d = dist[&n];
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
    /// - returns `None` when no progress neighbor is usable, even if a
    ///   sideways one exists: waiting on a sideways neighbor can cycle, so
    ///   the caller holds instead (caller retries on the next tick).
    ///
    /// `exclude` skips neighbors that already reported "already have" for
    /// this leg.
    pub fn next_hop(
        &self,
        from: &Identifier,
        dist: &HashMap<Identifier, u32>,
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

    fn id(b: u8) -> Identifier {
        Identifier::from_bytes([b; 32])
    }

    /// Destination D with two arms: D—A—F and D—B—S, plus F—S.
    /// dist from D: A=1, B=1, F=2, S=2. From F, A is progress and S is
    /// sideways.
    fn fixture() -> (Graph, Identifier, Identifier, Identifier, Identifier) {
        let (d, a, b, f, s) = (id(0xD0), id(0xA0), id(0xB0), id(0xF0), id(0x50));
        let records = [
            (d, vec![a, b]),
            (a, vec![d, f]),
            (b, vec![d, s]),
            (f, vec![a, s]),
            (s, vec![b, f]),
        ];
        let graph = Graph::build(&f, records.iter().map(|(i, l)| (i, l.as_slice())));
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
        assert_eq!(g.next_hop(&f, &dist, 0.0, &exclude, &up, &mut rng), None);
    }

    #[test]
    fn sideways_still_allowed_opportunistically() {
        let (g, d, a, f, s) = fixture();
        let dist = g.distances(&d);
        let up: HashSet<Identifier> = [a, s].into_iter().collect();
        let exclude: HashSet<Identifier> = [a].into_iter().collect();
        let mut rng = Rng::new(7);
        assert_eq!(g.next_hop(&f, &dist, 1.0, &exclude, &up, &mut rng), Some(s));
    }

    #[test]
    fn progress_neighbor_is_preferred() {
        let (g, d, a, f, s) = fixture();
        let dist = g.distances(&d);
        let up: HashSet<Identifier> = [a, s].into_iter().collect();
        let exclude = HashSet::new();
        let mut rng = Rng::new(7);
        assert_eq!(g.next_hop(&f, &dist, 0.0, &exclude, &up, &mut rng), Some(a));
    }
}
