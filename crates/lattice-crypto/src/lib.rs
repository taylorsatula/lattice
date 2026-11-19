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

pub use lattice_types::{
    AeadKey, ChannelPublicKey, ChannelSeed, Commitment, DeliveryId, Hash32, Identifier,
    KemCiphertext, LegId, Mac16, MessageId, SharedSecret, Signature, SigningPublicKey, SigningSeed,
    X25519PublicKey, X25519Secret, XWingPublicKey, XWingSecretKey,
};
pub use random::{os_bytes, os_fill};
pub use seal::{ENVELOPE_CONTEXT, HOP_CONTEXT, Sealed, open, seal, seal_with_entropy};
pub use sign::generate_seed;
pub use sign::{
    channel_public, channel_x25519_public, channel_x25519_public_from_ed25519, channel_x25519_seed,
    public_key, sign, verify,
};
pub use xwing::generate_keypair;
pub use xwing::{SealError, XWingKeypair, public_key as xwing_public_key};

pub fn hash(data: &[u8]) -> Hash32 {
    Hash32::from_bytes(*blake3::hash(data).as_bytes())
}

/// BLAKE3 keyed hash (a PRF). Used where a secret key must select among
/// public inputs unpredictably (e.g. neighbor-selection salts).
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> Hash32 {
    Hash32::from_bytes(*blake3::keyed_hash(key, data).as_bytes())
}

/// BLAKE3 KDF: derive a 32-byte subkey from `key_material` under
/// `context`. The context string is the domain separator; two derivations
/// with different contexts are independent.
pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

/// Constant-time equality for fixed-size secrets and commitments.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
pub use sign::{KEY_EVENT_CONTEXT, RECEIPT_CONTEXT, RECORD_CONTEXT, signing_preimage};
