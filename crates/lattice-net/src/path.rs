//! The upgrade path is derived from the responder's channel key: anyone
//! holding the peer's record can compute it; a scanner cannot.

use base32ct::{Base32Unpadded, Encoding};

const CONTEXT: &str = "lattice v1 path";

pub fn upgrade_path(channel_key: &[u8; 32]) -> String {
    let derived = blake3::derive_key(CONTEXT, channel_key);
    format!("/{}", Base32Unpadded::encode_string(&derived[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_stable_and_key_dependent() {
        let a = upgrade_path(&[1u8; 32]);
        let b = upgrade_path(&[2u8; 32]);
        assert_ne!(a, b);
        assert_eq!(a, upgrade_path(&[1u8; 32]));
        assert!(a.starts_with('/'));
        assert_eq!(a.len(), 1 + 26); // 16 bytes -> 26 base32 chars
    }
}
