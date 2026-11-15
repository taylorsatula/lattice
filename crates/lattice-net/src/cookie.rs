//! Cookie anti-exhaustion, à la WireGuard.
//!
//! Stateless: the cookie is a pure function of a rotating server-side key
//! and the client's address. The client receives the raw cookie and echoes
//! `mac2 = BLAKE2s-256(cookie, init_msg)[..16]` on its retry; the server
//! recomputes the cookie from the peer address and verifies. Rotation
//! invalidates old cookies within one window.
//!
//! `mac1 = BLAKE2s-256(channel_key, init_msg)[..16]` is required on IK
//! handshakes. XX initiators cannot know the channel key (that is what XX is
//! for), so they send zeros there and the server does not check mac1 — the
//! upgrade path is the gate for XX; see `XX_MSG1_LEN` in handshake.rs.

use blake2::Blake2sMac256;
use blake2::digest::{KeyInit, Mac};
use subtle::ConstantTimeEq;

use lattice_types::{ChannelPublicKey, Cookie, Mac16};

pub const COOKIE_BYTES: usize = 24;
const CONTEXT: &[u8] = b"lattice v1 cookie";
const ROTATION_SECS: u64 = 7200; // two hours

pub struct CookieState {
    key: [u8; 32],
    next_rotation: u64,
    prev_key: Option<[u8; 32]>,
    now: u64,
}

fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    debug_assert!(key.len() <= 32, "Blake2s accepts at most 32-byte keys");
    let mut m = <Blake2sMac256 as KeyInit>::new_from_slice(key)
        .expect("Blake2s accepts keys of 0..=32 bytes");
    m.update(msg);
    m.finalize().into_bytes().into()
}

fn mac16(key: &[u8], msg: &[u8]) -> Mac16 {
    Mac16::from_bytes(mac(key, msg)[..16].try_into().unwrap())
}

impl CookieState {
    pub fn new(now: u64) -> Self {
        Self {
            key: lattice_crypto::os_bytes::<32>(),
            next_rotation: now + ROTATION_SECS,
            prev_key: None,
            now,
        }
    }

    /// Advance the clock explicitly (tests).
    pub fn advance(&mut self, now: u64) {
        if now <= self.now {
            self.now = now;
            return;
        }
        self.now = now;
        while self.now >= self.next_rotation {
            self.prev_key = Some(self.key);
            self.key = lattice_crypto::os_bytes::<32>();
            self.next_rotation += ROTATION_SECS;
        }
    }

    /// Advance to wall-clock now; used by the server once per connection.
    pub fn tick(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.advance(now);
    }

    fn cookie_for_key(key: &[u8; 32], addr: &[u8]) -> Cookie {
        let mut h = Vec::with_capacity(CONTEXT.len() + addr.len());
        h.extend_from_slice(CONTEXT);
        h.extend_from_slice(addr);
        let full = mac(key, &h);
        Cookie::from_bytes(full[..COOKIE_BYTES].try_into().unwrap())
    }

    pub fn issue(&self, addr: &[u8]) -> Cookie {
        Self::cookie_for_key(&self.key, addr)
    }

    fn cookie_candidates(&self, addr: &[u8]) -> Vec<Cookie> {
        let mut out = vec![Self::cookie_for_key(&self.key, addr)];
        if let Some(prev) = &self.prev_key {
            out.push(Self::cookie_for_key(prev, addr));
        }
        out
    }

    /// Verify `mac2` for the given client address and init message.
    pub fn verify_mac2(&self, addr: &[u8], init_msg: &[u8], mac2: &Mac16) -> bool {
        self.cookie_candidates(addr).iter().any(|cookie| {
            mac16(cookie.as_ref(), init_msg)
                .as_ref()
                .ct_eq(mac2.as_ref())
                .unwrap_u8()
                == 1
        })
    }
}

/// mac1 over the init message, keyed by the responder's channel key.
pub fn mac1(channel_key: &ChannelPublicKey, init_msg: &[u8]) -> Mac16 {
    mac16(channel_key.as_ref(), init_msg)
}

/// mac2 over the init message, keyed by the cookie the client received.
pub fn mac2(cookie: &Cookie, init_msg: &[u8]) -> Mac16 {
    mac16(cookie.as_ref(), init_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_roundtrip_and_mac2() {
        let state = CookieState::new(10_000);
        let addr = b"192.0.2.1:443";
        let cookie = state.issue(addr);
        let msg = b"noise-init-message";
        let m2 = mac2(&cookie, msg);
        assert!(state.verify_mac2(addr, msg, &m2));
        // Wrong address fails.
        assert!(!state.verify_mac2(b"198.51.100.7:443", msg, &m2));
        // Wrong message fails.
        assert!(!state.verify_mac2(addr, b"other", &m2));
    }

    #[test]
    fn mac1_depends_on_channel_key_and_msg() {
        let k = |b: u8| ChannelPublicKey::from_bytes([b; 32]);
        let a = mac1(&k(1), b"hello");
        assert_ne!(a, mac1(&k(2), b"hello"));
        assert_ne!(a, mac1(&k(1), b"hellp"));
        assert_eq!(a, mac1(&k(1), b"hello"));
    }

    #[test]
    fn cookie_survives_one_rotation_then_expires() {
        let mut state = CookieState::new(0);
        let cookie = state.issue(b"addr");
        let m = mac2(&cookie, b"msg");
        state.advance(ROTATION_SECS + 1); // one rotation: previous key still valid
        assert!(state.verify_mac2(b"addr", b"msg", &m));
        state.advance(2 * ROTATION_SECS + 1); // two rotations: previous is gone
        assert!(!state.verify_mac2(b"addr", b"msg", &m));
    }
}
