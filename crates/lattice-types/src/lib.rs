//! Domain newtypes for the lattice wire and storage formats.
//!
//! Every fixed-size byte string that crosses an API boundary gets its own
//! type so that passing a signing seed where a public key is expected — or a
//! message id where a leg id is expected — is a compile error, not a silent
//! misbehavior. Serialization is transparent: a newtype encodes exactly as
//! its inner byte array, so the wire format and the redb on-disk format are
//! unchanged.
//!
//! Secret types are not `Copy`, redact themselves in `Debug`, and zeroize on
//! drop. Public types are `Copy`.

#![forbid(unsafe_code)]

use std::fmt;

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

macro_rules! public_type {
    ($name:ident, $n:expr, $doc:literal) => {
        public_type!(@body $name, $n, $doc, serde_derive);
    };
    (@big $name:ident, $n:expr, $doc:literal) => {
        public_type!(@body $name, $n, $doc, serde_bytes);
    };
    (@body $name:ident, $n:expr, $doc:literal, $serde:ident) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(transparent)]
        pub struct $name([u8; $n]);

        impl $name {
            pub const LEN: usize = $n;
            pub const fn from_bytes(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }
            pub const fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
            pub const fn into_bytes(self) -> [u8; $n] {
                self.0
            }
            pub fn to_vec(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl From<[u8; $n]> for $name {
            fn from(b: [u8; $n]) -> Self {
                Self(b)
            }
        }
        impl TryFrom<&[u8]> for $name {
            type Error = std::array::TryFromSliceError;
            fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(<[u8; $n]>::try_from(b)?))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({}…)"), hex_prefix(&self.0))
            }
        }
        public_type!(@serde $serde, $name, $n);
    };
    (@serde serde_derive, $name:ident, $n:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(s)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Self(<[u8; $n]>::deserialize(d)?))
            }
        }
    };
    (@serde serde_bytes, $name:ident, $n:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(&self.0)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = Vec::<u8>::deserialize(d)?;
                Ok(Self(<[u8; $n]>::try_from(v.as_slice()).map_err(|_| {
                    serde::de::Error::custom(concat!("expected ", stringify!($n), " bytes"))
                })?))
            }
        }
    };
}

macro_rules! secret_type {
    ($name:ident, $n:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
        #[repr(transparent)]
        pub struct $name([u8; $n]);

        impl $name {
            pub const LEN: usize = $n;
            pub const fn from_bytes(bytes: [u8; $n]) -> Self {
                Self(bytes)
            }
            pub fn as_bytes(&self) -> &[u8; $n] {
                &self.0
            }
            pub fn to_vec(&self) -> Vec<u8> {
                self.0.to_vec()
            }
            pub fn into_bytes(mut self) -> [u8; $n] {
                let out = self.0;
                self.0 = [0; $n];
                out
            }
            /// Constant-time equality.
            pub fn ct_eq(&self, other: &Self) -> bool {
                let mut acc = 0u8;
                for (a, b) in self.0.iter().zip(other.0.iter()) {
                    acc |= a ^ b;
                }
                acc == 0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl From<[u8; $n]> for $name {
            fn from(b: [u8; $n]) -> Self {
                Self(b)
            }
        }
        impl TryFrom<&[u8]> for $name {
            type Error = std::array::TryFromSliceError;
            fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(<[u8; $n]>::try_from(b)?))
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(REDACTED)"))
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other)
            }
        }
        impl Eq for $name {}
        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(s)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Ok(Self(<[u8; $n]>::deserialize(d)?))
            }
        }
    };
}

public_type!(
    Identifier,
    32,
    "Node identifier: BLAKE3 of the inception event."
);
public_type!(
    SigningPublicKey,
    32,
    "Ed25519 public key for a KEL signing key."
);
public_type!(
    ChannelPublicKey,
    32,
    "Ed25519 public key for a record's channel key."
);
public_type!(
    X25519PublicKey,
    32,
    "X25519 public key (Noise static / channel key agreement)."
);
public_type!(
    Commitment,
    32,
    "BLAKE3 commitment to a key event's unsigned encoding."
);
public_type!(Hash32, 32, "A BLAKE3 digest with no more specific domain.");
public_type!(MessageId, 16, "End-to-end message id (`mid`).");
public_type!(LegId, 16, "Per-hop custody leg id.");
public_type!(DeliveryId, 16, "Per-inbox-delivery id.");
public_type!(@big Signature, 64, "Ed25519 signature.");
public_type!(Mac16, 16, "BLAKE2s-128 MAC (mac1/mac2).");
public_type!(Cookie, 24, "Anti-DoS cookie token.");
public_type!(@big XWingPublicKey, 1216, "X-Wing encapsulation (public) key.");
public_type!(@big KemCiphertext, 1120, "X-Wing KEM ciphertext.");

secret_type!(SigningSeed, 32, "Ed25519 seed for a KEL signing key.");
secret_type!(ChannelSeed, 32, "Ed25519 seed for a record's channel key.");
secret_type!(
    X25519Secret,
    32,
    "X25519 private key derived from a channel seed."
);
secret_type!(XWingSecretKey, 32, "X-Wing decapsulation seed.");
secret_type!(SharedSecret, 32, "X-Wing decapsulation output.");
secret_type!(
    AeadKey,
    32,
    "ChaCha20-Poly1305 key derived from a shared secret."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_serde_roundtrip_matches_raw_array() {
        let id = Identifier::from_bytes([7u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let raw: [u8; 32] = serde_json::from_str(&json).unwrap();
        assert_eq!(json, serde_json::to_string(&[7u8; 32]).unwrap());
        assert_eq!(raw, [7u8; 32]);
        let back: Identifier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn try_from_slice_checks_length() {
        assert!(Identifier::try_from(&[0u8; 31][..]).is_err());
        assert!(Identifier::try_from(&[0u8; 33][..]).is_err());
        assert!(Identifier::try_from(&[0u8; 32][..]).is_ok());
    }

    #[test]
    fn secrets_redact_debug_and_zeroize() {
        let s = SigningSeed::from_bytes([0xAB; 32]);
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("ab"), "debug leaks key material: {dbg}");
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn secret_ct_eq() {
        let a = ChannelSeed::from_bytes([1u8; 32]);
        let b = ChannelSeed::from_bytes([1u8; 32]);
        let c = ChannelSeed::from_bytes([2u8; 32]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
