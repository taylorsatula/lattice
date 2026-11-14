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

/// X25519 public key for a 32-byte seed (channel/noise static key).
pub fn x25519_public(seed: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*seed);
    PublicKey::from(&secret).to_bytes()
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
