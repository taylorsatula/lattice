//! Ed25519 signatures over exact bytes. Callers sign encodings, never
//! re-serializations computed at verify time.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::random::os_bytes;

/// Generate a new signing seed (32 bytes).
pub fn generate_seed() -> [u8; 32] {
    os_bytes()
}

/// Derive the public key for a seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// The channel key published in records: an Ed25519 public key. The Noise
/// handshake uses the matching X25519 key, derived from the same seed; see
/// `channel_x25519_seed` and `channel_x25519_public`.
pub fn channel_public(seed: &[u8; 32]) -> [u8; 32] {
    public_key(seed)
}

/// The X25519 private key bytes for a channel seed, for the Noise handshake.
/// This is the first half of SHA-512(seed); Noise clamps it internally.
/// Matches `SigningKey::to_scalar_bytes`, so the X25519 and Ed25519 keys
/// are the same scalar in two representations.
pub fn channel_x25519_seed(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let h = Sha512::digest(seed);
    h[..32].try_into().expect("sha512 is 64 bytes")
}

/// The X25519 public key for a channel seed (what Noise uses on the wire).
pub fn channel_x25519_public(seed: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(channel_x25519_seed(seed));
    PublicKey::from(&secret).to_bytes()
}

/// Derive the X25519 public key from a channel Ed25519 public key (as found
/// in a record). Peers use this to run the Noise handshake against a record.
pub fn channel_x25519_public_from_ed25519(ed_pub: &[u8; 32]) -> Option<[u8; 32]> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed_pub).ok()?;
    Some(vk.to_montgomery().to_bytes())
}

/// Sign `message`; returns the 64-byte signature.
pub fn sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verify a 64-byte signature. Returns false on any mismatch, never panics.
pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    key.verify_strict(message, &Signature::from_bytes(signature))
        .is_ok()
}
