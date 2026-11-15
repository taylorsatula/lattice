//! X-Wing (X25519 + ML-KEM-768) key establishment and key encapsulation.
//!
//! Public keys are the 1216-byte encapsulation keys defined by the X-Wing
//! draft; secret keys are the 32-byte decapsulation seeds. Decapsulation
//! rejects non-contributory X25519 shares, matching the draft's behavior.
//! Note: X-Wing is still an IETF draft (the `x-wing` crate implements
//! draft-06), not a published RFC; the wire format may change if the draft
//! is revised.

use lattice_types::{KemCiphertext, SharedSecret, XWingPublicKey, XWingSecretKey};
use x_wing::{
    DecapsulationKeyRejectNonContrib, Decapsulator, Encapsulate, EncapsulationKey, Kem, KeyExport,
    TryDecapsulate, XWingKem, kem,
};

/// A generated keypair.
pub struct XWingKeypair {
    pub secret: XWingSecretKey,
    pub public: XWingPublicKey,
}

/// Derive the encapsulation key for a decapsulation seed.
pub fn public_key(secret: &XWingSecretKey) -> XWingPublicKey {
    XWingPublicKey::from_bytes(
        DecapsulationKeyRejectNonContrib::from(*secret.as_bytes())
            .encapsulation_key()
            .to_bytes()
            .into(),
    )
}

pub fn generate_keypair() -> XWingKeypair {
    let (dk, ek) = XWingKem::generate_keypair();
    XWingKeypair {
        secret: XWingSecretKey::from_bytes(dk.to_bytes().into()),
        public: XWingPublicKey::from_bytes(ek.to_bytes().into()),
    }
}

pub(crate) fn encapsulate(
    public: &XWingPublicKey,
) -> Result<(KemCiphertext, SharedSecret), SealError> {
    let ek = EncapsulationKey::try_from(public.as_bytes().as_slice())
        .map_err(|_| SealError::BadPublicKey)?;
    let (ct, ss) = ek.encapsulate();
    Ok((
        KemCiphertext::from_bytes(ct.into()),
        SharedSecret::from_bytes(ss.into()),
    ))
}

pub(crate) fn decapsulate(
    secret: &XWingSecretKey,
    ciphertext: &KemCiphertext,
) -> Result<SharedSecret, SealError> {
    let dk = DecapsulationKeyRejectNonContrib::from(*secret.as_bytes());
    let ct: kem::Ciphertext<XWingKem> = (*ciphertext.as_bytes()).into();
    dk.try_decapsulate(&ct)
        .map(|ss| SharedSecret::from_bytes(ss.into()))
        .map_err(|_| SealError::Decapsulation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    BadPublicKey,
    Decapsulation,
    BadCiphertext,
}

impl core::fmt::Display for SealError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealError::BadPublicKey => write!(f, "invalid X-Wing public key"),
            SealError::Decapsulation => write!(f, "X-Wing decapsulation rejected the ciphertext"),
            SealError::BadCiphertext => write!(f, "invalid AEAD ciphertext"),
        }
    }
}

impl std::error::Error for SealError {}
