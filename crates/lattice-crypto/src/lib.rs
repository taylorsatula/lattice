//! Lattice cryptography primitives.
//!
//! No lattice policy lives here: this crate provides byte-level primitives
//! and the X-Wing seal/open used by the protocol layers. Keys are plain
//! byte arrays end to end; lattice-proto turns bytes into objects.

#![forbid(unsafe_code)]

mod random;
mod seal;
mod sign;
mod xwing;

pub use random::{os_bytes, os_fill};
pub use seal::{ENVELOPE_CONTEXT, HOP_CONTEXT, Sealed, open, seal};
pub use sign::generate_seed;
pub use sign::{public_key, sign, verify};
pub use xwing::generate_keypair;
pub use xwing::{
    KEM_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN, XWING_SECRET_KEY_LEN, XWingKeypair, XWingSecretKey,
};

pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Constant-time equality for fixed-size secrets and commitments.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
