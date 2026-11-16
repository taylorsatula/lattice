//! Noise handshake plumbing shared by client and server.

use lattice_types::{ChannelPublicKey, ChannelSeed};
use snow::{Builder, HandshakeState, TransportState};

pub const PARAMS_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const PARAMS_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// The Noise prologue (spec §6): `"lattice v1" ‖ 0x00 ‖` the upgrade path
/// exactly as it appears in the request line, including the leading `/`.
/// Both patterns use the same prologue. Binding the protocol name and the
/// path into the handshake hash keeps a handshake from one path from being
/// replayed on another, and separates this protocol's handshakes from any
/// other Noise protocol that shares the pattern.
pub fn prologue(upgrade_path: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(10 + 1 + upgrade_path.len());
    p.extend_from_slice(b"lattice v1\x00");
    p.extend_from_slice(upgrade_path.as_bytes());
    p
}

/// Size of an XX first message (a bare 32-byte ephemeral key).
/// An IK first message is strictly larger (32 + 48-byte encrypted static +
/// 16-byte tag for the empty payload), so length discrimination is exact
/// for these two patterns. If either pattern or its payload changes, these
/// constants and the server-side branch must change with it; the
/// `msg1_lengths_match_pattern_constants` test pins both.
pub const XX_MSG1_LEN: usize = 32;

/// Size of an IK first message: 32-byte ephemeral + 48-byte encrypted
/// static key (32-byte key + 16-byte Poly1305 tag) + 16-byte tag for the
/// empty payload.
pub const IK_MSG1_LEN: usize = 96;

pub struct Pending {
    pub state: HandshakeState,
}

impl Pending {
    pub fn initiator_ik(
        seed: &ChannelSeed,
        responder_static: &ChannelPublicKey,
        prologue: &[u8],
    ) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let x_pub = lattice_crypto::channel_x25519_public_from_ed25519(responder_static)
            .ok_or(snow::Error::Input)?;
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(x_seed.as_ref())?
            .remote_public_key(x_pub.as_ref())?
            .prologue(prologue)?
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn initiator_xx(seed: &ChannelSeed, prologue: &[u8]) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(x_seed.as_ref())?
            .prologue(prologue)?
            .build_initiator()?;
        Ok(Self { state })
    }

    pub fn responder_ik(seed: &ChannelSeed, prologue: &[u8]) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(x_seed.as_ref())?
            .prologue(prologue)?
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn responder_xx(seed: &ChannelSeed, prologue: &[u8]) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(x_seed.as_ref())?
            .prologue(prologue)?
            .build_responder()?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; 2048];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; 2048];
        let n = self.state.read_message(msg, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn remote_static(&self) -> Option<Vec<u8>> {
        self.state.get_remote_static().map(<[u8]>::to_vec)
    }

    pub fn finish(self) -> Result<TransportState, snow::Error> {
        self.state.into_transport_mode()
    }
}

/// Encode a handshake frame (Init/Resp/Cookie) padded to exactly 2048 bytes.
pub fn encode_handshake_frame(frame: &lattice_proto::frames::Frame) -> Option<Vec<u8>> {
    use lattice_proto::frames::{CookieFrame, Frame, InitFrame, RespFrame};
    let build = |pad: usize| -> Option<Vec<u8>> {
        let padded = match frame {
            Frame::Init(f) => Frame::Init(InitFrame {
                padding: vec![0u8; pad],
                ..f.clone()
            }),
            Frame::Resp(f) => Frame::Resp(RespFrame {
                padding: vec![0u8; pad],
                ..f.clone()
            }),
            Frame::Cookie(f) => Frame::Cookie(CookieFrame {
                padding: vec![0u8; pad],
                ..f.clone()
            }),
            // Only handshake frames may be padded; anything else is a
            // caller bug, reported as None rather than a panic.
            _ => return None,
        };
        Some(lattice_proto::encode(&padded.to_value()))
    };
    let base = build(0)?.len();
    let mut pad = 2048usize.saturating_sub(base);
    for _ in 0..16 {
        let enc = build(pad)?;
        match enc.len().cmp(&2048) {
            std::cmp::Ordering::Equal => return Some(enc),
            std::cmp::Ordering::Less => pad += 2048 - enc.len(),
            std::cmp::Ordering::Greater => pad = pad.saturating_sub(enc.len() - 2048),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // The server dispatches IK vs XX on the msg1 length; if either pattern's
    // msg1 ever changes size, the dispatch silently mis-routes. Pin both.
    #[test]
    fn msg1_lengths_match_pattern_constants() {
        let seed = ChannelSeed::from_bytes([0xA1; 32]);
        let responder = lattice_crypto::channel_public(&ChannelSeed::from_bytes([0xB2; 32]));
        let pro = prologue("/abc");
        let mut ik = Pending::initiator_ik(&seed, &responder, &pro).unwrap();
        let mut xx = Pending::initiator_xx(&seed, &pro).unwrap();
        assert_eq!(ik.write_message(&[]).unwrap().len(), IK_MSG1_LEN);
        assert_eq!(xx.write_message(&[]).unwrap().len(), XX_MSG1_LEN);
    }

    #[test]
    fn prologue_is_spec_shaped() {
        // "lattice v1" ‖ 0x00 ‖ the upgrade path, leading slash included.
        assert_eq!(prologue("/k7f3"), b"lattice v1\x00/k7f3");
    }

    #[test]
    fn prologue_mismatch_fails_handshake() {
        // A handshake bound to one path must not complete on another.
        let seed_a = ChannelSeed::from_bytes([0xA1; 32]);
        let seed_b = ChannelSeed::from_bytes([0xB2; 32]);
        let responder = lattice_crypto::channel_public(&seed_b);
        let mut initiator =
            Pending::initiator_ik(&seed_a, &responder, &prologue("/path-one")).unwrap();
        let mut responder = Pending::responder_ik(&seed_b, &prologue("/path-two")).unwrap();
        let msg1 = initiator.write_message(&[]).unwrap();
        assert!(responder.read_message(&msg1).is_err());
    }
}
