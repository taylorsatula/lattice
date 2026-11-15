//! Noise handshake plumbing shared by client and server.

use lattice_types::{ChannelPublicKey, ChannelSeed};
use snow::{Builder, HandshakeState, TransportState};

pub const PARAMS_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const PARAMS_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

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
    pub ik: bool,
}

impl Pending {
    pub fn initiator_ik(
        seed: &ChannelSeed,
        responder_static: &ChannelPublicKey,
    ) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let x_pub = lattice_crypto::channel_x25519_public_from_ed25519(responder_static)
            .ok_or(snow::Error::Input)?;
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(x_seed.as_ref())?
            .remote_public_key(x_pub.as_ref())?
            .build_initiator()?;
        Ok(Self { state, ik: true })
    }

    pub fn initiator_xx(seed: &ChannelSeed) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(x_seed.as_ref())?
            .build_initiator()?;
        Ok(Self { state, ik: false })
    }

    pub fn responder_ik(seed: &ChannelSeed) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(x_seed.as_ref())?
            .build_responder()?;
        Ok(Self { state, ik: true })
    }

    pub fn responder_xx(seed: &ChannelSeed) -> Result<Self, snow::Error> {
        let x_seed = lattice_crypto::channel_x25519_seed(seed);
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(x_seed.as_ref())?
            .build_responder()?;
        Ok(Self { state, ik: false })
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
        self.state.get_remote_static().map(|s| s.to_vec())
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
        let mut ik = Pending::initiator_ik(&seed, &responder).unwrap();
        let mut xx = Pending::initiator_xx(&seed).unwrap();
        assert_eq!(ik.write_message(&[]).unwrap().len(), IK_MSG1_LEN);
        assert_eq!(xx.write_message(&[]).unwrap().len(), XX_MSG1_LEN);
    }
}
