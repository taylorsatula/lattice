//! Deterministic RNG for the core: ChaCha20 keyed from a 64-bit seed.
//!
//! The daemon seeds from OS entropy, the simulator and tests from fixed
//! seeds; the same seed always yields the same stream, which is what makes
//! simulator runs reproducible.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};

/// Domain separator for seed expansion, so a seed never hashes to the same
/// key as any other BLAKE3 use in the workspace.
const SEED_CONTEXT: &[u8] = b"lattice-core rng seed v1";

/// ChaCha20 stream keyed from a 64-bit seed.
///
/// The seed is not secret material: it selects which stream the node draws
/// from, and an observer who learns it learns routing and timing jitter, not
/// keys. Unpredictability against an outside observer comes from the daemon
/// seeding from OS entropy, not from the seed's width.
pub struct Rng {
    cipher: ChaCha20,
}

impl core::fmt::Debug for Rng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rng(..)")
    }
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut preimage = Vec::with_capacity(SEED_CONTEXT.len() + 8);
        preimage.extend_from_slice(SEED_CONTEXT);
        preimage.extend_from_slice(&seed.to_le_bytes());
        let key = lattice_crypto::hash(&preimage);
        // Zero nonce: each key drives exactly one stream.
        let cipher = ChaCha20::new(key.as_bytes().into(), (&[0u8; 12]).into());
        Self { cipher }
    }
    pub fn next_u64(&mut self) -> u64 {
        let mut out = [0u8; 8];
        self.cipher.apply_keystream(&mut out);
        u64::from_le_bytes(out)
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
