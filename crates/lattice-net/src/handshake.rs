//! Noise handshake plumbing shared by client and server.

use snow::{Builder, HandshakeState, TransportState};

pub const PARAMS_IK: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const PARAMS_XX: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Size of an XX first message (a bare 32-byte ephemeral key).
/// An IK first message is strictly larger (32 + 48-byte encrypted static +
/// 16-byte tag for the empty payload), so length discrimination is exact
/// for these two patterns. If either pattern or its payload changes, this
/// constant and the server-side branch must change with it.
pub const XX_MSG1_LEN: usize = 32;

pub enum Role {
    Initiator,
    Responder,
}

pub struct Pending {
    pub state: HandshakeState,
    /// The exact bytes of the first message, for mac1/mac2 recomputation on retry.
    pub first_message: Option<Vec<u8>>,
    pub ik: bool,
}

impl Pending {
    pub fn initiator_ik(seed: &[u8; 32], responder_static: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(seed)?
            .remote_public_key(responder_static)?
            .build_initiator()?;
        Ok(Self {
            state,
            first_message: None,
            ik: true,
        })
    }

    pub fn initiator_xx(seed: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(seed)?
            .build_initiator()?;
        Ok(Self {
            state,
            first_message: None,
            ik: false,
        })
    }

    pub fn responder_ik(seed: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = Builder::new(PARAMS_IK.parse()?)
            .local_private_key(seed)?
            .build_responder()?;
        Ok(Self {
            state,
            first_message: None,
            ik: true,
        })
    }

    pub fn responder_xx(seed: &[u8; 32]) -> Result<Self, snow::Error> {
        let state = Builder::new(PARAMS_XX.parse()?)
            .local_private_key(seed)?
            .build_responder()?;
        Ok(Self {
            state,
            first_message: None,
            ik: false,
        })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; 2048];
        let n = self.state.write_message(payload, &mut buf)?;
        buf.truncate(n);
        if self.first_message.is_none() {
            self.first_message = Some(buf.clone());
        }
        Ok(buf)
    }

    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>, snow::Error> {
        let mut buf = vec![0u8; 2048];
        let n = self.state.read_message(msg, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
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
    let build = |pad: usize| -> Vec<u8> {
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
            _ => panic!("only handshake frames are padded"),
        };
        lattice_proto::encode(&padded.to_value())
    };
    let base = build(0).len();
    let mut pad = 2048usize.saturating_sub(base);
    for _ in 0..16 {
        let enc = build(pad);
        match enc.len().cmp(&2048) {
            std::cmp::Ordering::Equal => return Some(enc),
            std::cmp::Ordering::Less => pad += 2048 - enc.len(),
            std::cmp::Ordering::Greater => pad = pad.saturating_sub(enc.len() - 2048),
        }
    }
    None
}
