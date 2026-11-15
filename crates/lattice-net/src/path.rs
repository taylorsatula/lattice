//! The upgrade path is derived from the responder's channel key: anyone
//! holding the peer's record can compute it; a scanner cannot.

use base32ct::{Base32Unpadded, Encoding};
use lattice_types::ChannelPublicKey;

const CONTEXT: &str = "lattice v1 path";

pub fn upgrade_path(channel_key: &ChannelPublicKey) -> String {
    let derived = blake3::derive_key(CONTEXT, channel_key.as_ref());
    format!("/{}", Base32Unpadded::encode_string(&derived[..16]))
}

/// An upgrade path is interpolated into a `ws://host{path}` request URI, so
/// it must not be able to rewrite the authority component. Requires a leading
/// slash and rejects anything that could terminate or extend the authority
/// or smuggle a different request target.
pub fn validate_upgrade_path(path: &str) -> Result<(), crate::NetError> {
    let ok = path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'@' | b'?' | b'#' | b'\\'));
    if ok {
        Ok(())
    } else {
        Err(crate::NetError::InvalidInput("invalid upgrade path"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_stable_and_key_dependent() {
        let a = upgrade_path(&ChannelPublicKey::from_bytes([1u8; 32]));
        let b = upgrade_path(&ChannelPublicKey::from_bytes([2u8; 32]));
        assert_ne!(a, b);
        assert_eq!(a, upgrade_path(&ChannelPublicKey::from_bytes([1u8; 32])));
        assert!(a.starts_with('/'));
        assert_eq!(a.len(), 1 + 26); // 16 bytes -> 26 base32 chars
    }
}
