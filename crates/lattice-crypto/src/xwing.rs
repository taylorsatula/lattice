//! X-Wing (X25519 + ML-KEM-768) key establishment and key encapsulation.
//!
//! Public keys are the 1216-byte encapsulation keys defined by the X-Wing
//! draft; secret keys are the 32-byte decapsulation seeds. Decapsulation
//! rejects non-contributory X25519 shares, matching the draft's final
//! behaviour.

use x_wing::{
    DecapsulationKeyRejectNonContrib, Decapsulator, Encapsulate, EncapsulationKey, Kem, KeyExport,
    TryDecapsulate, XWingKem, kem,
};

pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_SECRET_KEY_LEN: usize = 32;
pub const KEM_CIPHERTEXT_LEN: usize = 1120;

/// A generated keypair. `secret` is the 32-byte decapsulation seed.
pub struct XWingKeypair {
    pub secret: [u8; XWING_SECRET_KEY_LEN],
    pub public: [u8; XWING_PUBLIC_KEY_LEN],
}

pub struct XWingSecretKey([u8; XWING_SECRET_KEY_LEN]);

impl XWingSecretKey {
    pub fn from_bytes(bytes: [u8; XWING_SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }
    pub fn public_key(&self) -> [u8; XWING_PUBLIC_KEY_LEN] {
        DecapsulationKeyRejectNonContrib::from(self.0)
            .encapsulation_key()
            .to_bytes()
            .into()
    }
    pub fn expose(&self) -> &[u8; XWING_SECRET_KEY_LEN] {
        &self.0
    }
}

impl Drop for XWingSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

pub fn generate_keypair() -> XWingKeypair {
    let (dk, ek) = XWingKem::generate_keypair();
    XWingKeypair {
        secret: dk.to_bytes().into(),
        public: ek.to_bytes().into(),
    }
}

pub(crate) fn encapsulate(
    public: &[u8; XWING_PUBLIC_KEY_LEN],
) -> Result<([u8; KEM_CIPHERTEXT_LEN], [u8; 32]), SealError> {
    let ek = EncapsulationKey::try_from(public.as_slice()).map_err(|_| SealError::BadPublicKey)?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.into(), ss.into()))
}

pub(crate) fn decapsulate(
    secret: &[u8; XWING_SECRET_KEY_LEN],
    ciphertext: &[u8; KEM_CIPHERTEXT_LEN],
) -> Result<[u8; 32], SealError> {
    let dk = DecapsulationKeyRejectNonContrib::from(*secret);
    let ct: kem::Ciphertext<XWingKem> = (*ciphertext).into();
    dk.try_decapsulate(&ct)
        .map(Into::into)
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
