//! The routing graph: built from records' link claims.
//!
//! An edge exists between A and B only if both records list each other.
//! Distances are BFS hop counts from the local node. Next-hop selection
//! implements the spec's randomized progress with opportunistic sideways
//! turns.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::rng::Rng;

pub const MAX_LINKS_WAN: usize = 16;

#[derive(Default)]
pub struct Graph {
    adjacency: HashMap<[u8; 32], HashSet<[u8; 32]>>,
}

impl Graph {
    /// `links` iterates over (node, its claimed links) for every known record,
    /// including our own.
    pub fn build<'a, I>(own: &[u8; 32], records: I) -> Self
    where
        I: IntoIterator<Item = (&'a [u8; 32], &'a [[u8; 32]])>,
    {
        let claims: HashMap<[u8; 32], HashSet<[u8; 32]>> = records
            .into_iter()
            .map(|(id, links)| (*id, links.iter().copied().collect()))
            .collect();
        let mut adjacency: HashMap<[u8; 32], HashSet<[u8; 32]>> = HashMap::new();
        let ids: Vec<[u8; 32]> = claims
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

    pub fn neighbors(&self, id: &[u8; 32]) -> impl Iterator<Item = &[u8; 32]> {
        self.adjacency.get(id).into_iter().flatten()
    }

    /// BFS distances from `from`.
    pub fn distances(&self, from: &[u8; 32]) -> HashMap<[u8; 32], u32> {
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
    /// - sideways: with probability `sideways_prob`, uniform among neighbors
    ///   exactly as close (never farther);
    /// - returns `None` when there is no non-increasing move (caller holds or drops).
    ///
    /// `exclude` skips neighbors that already reported "already have" for
    /// this leg.
    pub fn next_hop(
        &self,
        from: &[u8; 32],
        dist: &HashMap<[u8; 32], u32>,
        sideways_prob: f64,
        exclude: &HashSet<[u8; 32]>,
        up: &HashSet<[u8; 32]>,
        rng: &mut Rng,
    ) -> Option<[u8; 32]> {
        let my_dist = *dist.get(from)?;
        let mut progress: Vec<[u8; 32]> = Vec::new();
        let mut sideways: Vec<[u8; 32]> = Vec::new();
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
        if !sideways.is_empty() {
            return rng.pick(&sideways).copied();
        }
        None
    }
}
