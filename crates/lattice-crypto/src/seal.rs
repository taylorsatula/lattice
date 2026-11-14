//! Sealed layers: X-Wing KEM + ChaCha20-Poly1305, keyed by BLAKE3 derivation.
//!
//! Layout on the wire is defined by lattice-proto; this module produces the
//! `(kem_ciphertext, ciphertext)` pair and consumes it. The AAD is the exact
//! encoding of the header that travels with the layer, so a hop that alters
//! the header makes the next opening fail.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::xwing::{
    self, KEM_CIPHERTEXT_LEN, SealError, XWING_PUBLIC_KEY_LEN, XWING_SECRET_KEY_LEN,
};

/// BLAKE3 KDF context for the envelope layer (recipient only).
pub const ENVELOPE_CONTEXT: &str = "lattice v1 envelope";
/// BLAKE3 KDF context for hop layers (waypoint or gateway).
pub const HOP_CONTEXT: &str = "lattice v1 hop";

const ZERO_NONCE: [u8; 12] = [0u8; 12];
const TAG_LEN: usize = 16;

pub struct Sealed {
    pub kem_ciphertext: [u8; KEM_CIPHERTEXT_LEN],
    pub ciphertext: Vec<u8>,
}

fn aead_key(context: &str, shared_secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(context, shared_secret)
}

/// Seal `plaintext` to `public` under `context`, binding `aad`.
pub fn seal(
    context: &str,
    public: &[u8; XWING_PUBLIC_KEY_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, SealError> {
    let (kem_ct, shared) = xwing::encapsulate(public)?;
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
    secret: &[u8; XWING_SECRET_KEY_LEN],
    aad: &[u8],
    kem_ciphertext: &[u8; KEM_CIPHERTEXT_LEN],
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
