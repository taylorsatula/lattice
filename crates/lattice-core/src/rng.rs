//! Deterministic RNG for the core. Not cryptographic; used for decisions
//! that must be reproducible in the simulator (route choice, snow timing).
//! Seeds come from the caller: OS randomness in the daemon, fixed seeds in
//! tests.

/// SplitMix64. Cheap, deterministic, fine for load-balancing decisions.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    /// Uniform value in [0, n). n must be > 0.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    /// True with probability p in [0, 1].
    #[must_use]
    pub fn chance(&mut self, p: f64) -> bool {
        (self.next_u64() as f64 / u64::MAX as f64) < p
    }
    /// Exponential inter-arrival time (mean 1/lambda), in the same units as lambda.
    pub fn expovariate(&mut self, lambda: f64) -> f64 {
        let u = (self.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 1.0);
        -(u.ln()) / lambda
    }
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[self.below(items.len() as u64) as usize])
        }
    }
}
