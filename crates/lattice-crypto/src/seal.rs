//! Sealed layers: X-Wing KEM + ChaCha20-Poly1305, keyed by BLAKE3 derivation.
//!
//! Layout on the wire is defined by lattice-proto; this module produces the
//! `(kem_ciphertext, ciphertext)` pair and consumes it. The AAD is the exact
//! encoding of the header that travels with the layer, so a hop that alters
//! the header makes the next opening fail.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use lattice_types::{AeadKey, KemCiphertext, SharedSecret, XWingPublicKey, XWingSecretKey};

use crate::xwing::{self, SealError};

/// BLAKE3 KDF context for the envelope layer (recipient only).
pub const ENVELOPE_CONTEXT: &str = "lattice v1 envelope";
/// BLAKE3 KDF context for hop layers (waypoint or gateway).
pub const HOP_CONTEXT: &str = "lattice v1 hop";

const ZERO_NONCE: [u8; 12] = [0u8; 12];
const TAG_LEN: usize = 16;

pub struct Sealed {
    pub kem_ciphertext: KemCiphertext,
    pub ciphertext: Vec<u8>,
}

fn aead_key(context: &str, shared_secret: &SharedSecret) -> AeadKey {
    AeadKey::from_bytes(blake3::derive_key(context, shared_secret.as_bytes()))
}

/// Seal `plaintext` to `public` under `context`, binding `aad`.
pub fn seal(
    context: &str,
    public: &XWingPublicKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, SealError> {
    seal_with_entropy(context, public, aad, plaintext, &mut |buf| {
        crate::random::os_fill(buf)
    })
}

/// Seal with caller-supplied entropy for the KEM (64 bytes, drawn fresh per
/// call). The simulator passes its seeded stream; production callers use
/// [`seal`], which draws from the OS.
pub fn seal_with_entropy(
    context: &str,
    public: &XWingPublicKey,
    aad: &[u8],
    plaintext: &[u8],
    entropy: &mut dyn FnMut(&mut [u8; 64]),
) -> Result<Sealed, SealError> {
    let (kem_ct, shared) = xwing::encapsulate_with_entropy(public, entropy)?;
    let key = Zeroizing::new(aead_key(context, &shared));
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(ZERO_NONCE),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError::BadCiphertext)?;
    Ok(Sealed {
        kem_ciphertext: kem_ct,
        ciphertext,
    })
}

/// Open a layer sealed by [`seal`].
pub fn open(
    context: &str,
    secret: &XWingSecretKey,
    aad: &[u8],
    kem_ciphertext: &KemCiphertext,
    ciphertext: &[u8],
) -> Result<Vec<u8>, SealError> {
    if ciphertext.len() < TAG_LEN {
        return Err(SealError::BadCiphertext);
    }
    let shared = xwing::decapsulate(secret, kem_ciphertext)?;
    let key = Zeroizing::new(aead_key(context, &shared));
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).expect("32-byte key");
    cipher
        .decrypt(
            &Nonce::from(ZERO_NONCE),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError::BadCiphertext)
}
