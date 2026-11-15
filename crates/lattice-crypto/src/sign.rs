//! Ed25519 signatures over exact bytes. Callers sign encodings, never
//! re-serializations computed at verify time.

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, VerifyingKey};
use lattice_types::{
    ChannelPublicKey, ChannelSeed, Signature, SigningPublicKey, SigningSeed, X25519PublicKey,
    X25519Secret,
};

/// Seed types that may sign. Sealed to the two Ed25519 seed newtypes so a
/// hash or commitment can never be passed as a key.
pub trait Ed25519Seed: AsRef<[u8]> {}
impl Ed25519Seed for SigningSeed {}
impl Ed25519Seed for ChannelSeed {}

/// Public key types that may verify. Sealed to the two Ed25519 public keys.
pub trait Ed25519PublicKey: AsRef<[u8]> {}
impl Ed25519PublicKey for SigningPublicKey {}
impl Ed25519PublicKey for ChannelPublicKey {}

use crate::random::os_bytes;

/// Generate a new signing seed.
pub fn generate_seed() -> SigningSeed {
    SigningSeed::from_bytes(os_bytes())
}

/// Derive the public key for a seed.
pub fn public_key(seed: &SigningSeed) -> SigningPublicKey {
    SigningPublicKey::from_bytes(
        SigningKey::from_bytes(seed.as_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

/// The channel key published in records: an Ed25519 public key. The Noise
/// handshake uses the matching X25519 key, derived from the same seed; see
/// `channel_x25519_seed` and `channel_x25519_public`.
pub fn channel_public(seed: &ChannelSeed) -> ChannelPublicKey {
    ChannelPublicKey::from_bytes(
        SigningKey::from_bytes(seed.as_bytes())
            .verifying_key()
            .to_bytes(),
    )
}

/// The X25519 private key for a channel seed, for the Noise handshake.
/// This is the first half of SHA-512(seed); Noise clamps it internally.
/// Matches `SigningKey::to_scalar_bytes`, so the X25519 and Ed25519 keys
/// are the same scalar in two representations.
pub fn channel_x25519_seed(seed: &ChannelSeed) -> X25519Secret {
    use sha2::{Digest, Sha512};
    let h = Sha512::digest(seed.as_bytes());
    X25519Secret::from_bytes(h[..32].try_into().expect("sha512 is 64 bytes"))
}

/// The X25519 public key for a channel seed (what Noise uses on the wire).
pub fn channel_x25519_public(seed: &ChannelSeed) -> X25519PublicKey {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*channel_x25519_seed(seed).as_bytes());
    X25519PublicKey::from_bytes(PublicKey::from(&secret).to_bytes())
}

/// Derive the X25519 public key from a channel Ed25519 public key (as found
/// in a record). Peers use this to run the Noise handshake against a record.
pub fn channel_x25519_public_from_ed25519(ed_pub: &ChannelPublicKey) -> Option<X25519PublicKey> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed_pub.as_bytes()).ok()?;
    Some(X25519PublicKey::from_bytes(vk.to_montgomery().to_bytes()))
}

/// Sign `message`; returns the signature.
pub fn sign(seed: &impl Ed25519Seed, message: &[u8]) -> Signature {
    let seed: &[u8; 32] = seed.as_ref().try_into().expect("seed is 32 bytes");
    Signature::from_bytes(SigningKey::from_bytes(seed).sign(message).to_bytes())
}

/// Verify a signature. Returns false on any mismatch, never panics.
pub fn verify(public: &impl Ed25519PublicKey, message: &[u8], signature: &Signature) -> bool {
    let Ok(public) = <&[u8; 32]>::try_from(public.as_ref()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public) else {
        return false;
    };
    key.verify_strict(message, &DalekSignature::from_bytes(signature.as_bytes()))
        .is_ok()
}
