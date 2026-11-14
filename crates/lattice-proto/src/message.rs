//! Messages: headers, hop layers, envelopes, padding, buckets (V2_SPEC §4-5).
//!
//! A message on the wire is the array `[header, hop_layer | nil, envelope, padding]`.
//! Layers are sealed with X-Wing; the associated data is the exact encoding of
//! the header that travels in the same array slot. The envelope's signature
//! covers the *real* (routing) header followed by the unsigned envelope map,
//! so the outer header of a waypoint-routed message is never signed and never
//! needs to be secret.

use lattice_crypto::{ENVELOPE_CONTEXT, HOP_CONTEXT, open, seal};

use crate::cbor::{Value, decode, encode};
use crate::error::ProtoError;
use crate::obj::fixed_bytes;
use crate::{CLOCK_SKEW, MAX_MESSAGE_HORIZON, MESSAGE_BUCKETS};

pub const KIND_MESSAGE: u64 = 0;
pub const KIND_RECEIPT: u64 = 1;
pub const KIND_NEGATIVE_RECEIPT: u64 = 2;

pub const HOP_KIND_WAYPOINT: u64 = 0;
pub const HOP_KIND_GATEWAY: u64 = 1;

pub const REASON_UNKNOWN_SERVICE: u64 = 1;
pub const REASON_INVALID: u64 = 2;

const HEADER_KEYS: [u64; 5] = [0, 1, 2, 3, 4];
const HOP_LAYER_KEYS: [u64; 4] = [0, 1, 2, 3];
const ENVELOPE_KEYS: [u64; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const SEALED_KEYS: [u64; 2] = [0, 1];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub leg: [u8; 16],
    pub dst: [u8; 32],
    pub exp: u64,
}

impl Header {
    pub(crate) fn unsigned_value(&self) -> Value {
        Value::map(vec![
            (Value::UInt(0), Value::UInt(crate::kel::PROTOCOL_VERSION)),
            (Value::UInt(1), Value::UInt(30)),
            (Value::UInt(2), Value::Bytes(self.leg.to_vec())),
            (Value::UInt(3), Value::Bytes(self.dst.to_vec())),
            (Value::UInt(4), Value::UInt(self.exp)),
        ])
    }
    pub fn encode(&self) -> Vec<u8> {
        encode(&self.unsigned_value())
    }
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&HEADER_KEYS)?;
        if v.req_uint(0)? != crate::kel::PROTOCOL_VERSION {
            return Err(ProtoError::Invalid("unsupported protocol version"));
        }
        if v.req_uint(1)? != 30 {
            return Err(ProtoError::Invalid("not a header"));
        }
        Ok(Self {
            leg: fixed_bytes(v, 2)?,
            dst: fixed_bytes(v, 3)?,
            exp: v.req_uint(4)?,
        })
    }
}

/// A sealed layer as it rides on the wire: `{0: kem, 1: ct}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedLayer {
    pub kem: [u8; 1120],
    pub ct: Vec<u8>,
}

impl SealedLayer {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (Value::UInt(0), Value::Bytes(self.kem.to_vec())),
            (Value::UInt(1), Value::Bytes(self.ct.clone())),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&SEALED_KEYS)?;
        Ok(Self {
            kem: fixed_bytes(v, 0)?,
            ct: v.req_bytes(1)?.to_vec(),
        })
    }
    fn seal_to(
        context: &str,
        public: &[u8; 1216],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Self, ProtoError> {
        let s =
            seal(context, public, aad, plaintext).map_err(|e| ProtoError::Crypto(e.to_string()))?;
        Ok(Self {
            kem: s.kem_ciphertext,
            ct: s.ciphertext,
        })
    }
    fn open_with(
        &self,
        context: &str,
        secret: &[u8; 32],
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtoError> {
        open(context, secret, aad, &self.kem, &self.ct)
            .map_err(|e| ProtoError::Crypto(e.to_string()))
    }
}

/// Plaintext of a hop layer (waypoint or gateway).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HopLayerPlain {
    Waypoint {
        hdr: Header,
        inner: Option<Box<SealedLayer>>,
    },
    Gateway {
        rcpt: [u8; 32],
    },
}

impl HopLayerPlain {
    fn to_value(&self) -> Value {
        match self {
            HopLayerPlain::Waypoint { hdr, inner } => {
                let mut pairs = vec![
                    (Value::UInt(0), Value::UInt(HOP_KIND_WAYPOINT)),
                    (Value::UInt(1), hdr.unsigned_value()),
                ];
                if let Some(inner) = inner {
                    pairs.push((Value::UInt(2), inner.to_value()));
                }
                Value::map(pairs)
            }
            HopLayerPlain::Gateway { rcpt } => Value::map(vec![
                (Value::UInt(0), Value::UInt(HOP_KIND_GATEWAY)),
                (Value::UInt(3), Value::Bytes(rcpt.to_vec())),
            ]),
        }
    }
    fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&HOP_LAYER_KEYS)?;
        match v.req_uint(0)? {
            HOP_KIND_WAYPOINT => {
                let hdr = Header::from_value(v.req(1)?)?;
                let inner = match v.get_key(2)? {
                    None => None,
                    Some(inner) => Some(Box::new(SealedLayer::from_value(inner)?)),
                };
                Ok(HopLayerPlain::Waypoint { hdr, inner })
            }
            HOP_KIND_GATEWAY => Ok(HopLayerPlain::Gateway {
                rcpt: fixed_bytes(v, 3)?,
            }),
            _ => Err(ProtoError::Invalid("unknown hop layer kind")),
        }
    }
}

/// Envelope plaintext. `sig` covers `header_bytes || encode(unsigned envelope)`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    pub kind: u64,
    pub mid: [u8; 16],
    pub from: [u8; 32],
    pub fsvc: String,
    pub fmbx: Vec<u8>,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub created: u64,
    pub body: Option<Vec<u8>>,
    pub reference: Option<[u8; 16]>,
    pub reason: Option<u64>,
    #[serde(with = "crate::serde_arrays::sig64")]
    pub sig: [u8; 64],
}

impl Envelope {
    fn unsigned_pairs(&self) -> Vec<(Value, Value)> {
        let mut p = vec![
            (Value::UInt(0), Value::UInt(self.kind)),
            (Value::UInt(11), Value::Bytes(self.mid.to_vec())),
            (Value::UInt(1), Value::Bytes(self.from.to_vec())),
            (Value::UInt(2), Value::Text(self.fsvc.clone())),
            (Value::UInt(3), Value::Bytes(self.fmbx.clone())),
            (Value::UInt(4), Value::Text(self.tsvc.clone())),
            (Value::UInt(5), Value::Bytes(self.tmbx.clone())),
            (Value::UInt(6), Value::UInt(self.created)),
        ];
        if let Some(b) = &self.body {
            p.push((Value::UInt(7), Value::Bytes(b.clone())));
        }
        if let Some(r) = &self.reference {
            p.push((Value::UInt(8), Value::Bytes(r.to_vec())));
        }
        if let Some(r) = &self.reason {
            p.push((Value::UInt(9), Value::UInt(*r)));
        }
        p
    }
    fn unsigned_value(&self) -> Value {
        Value::map(self.unsigned_pairs())
    }

    /// Sign this envelope against `routing_header_bytes`.
    pub fn sign(&mut self, signing_seed: &[u8; 32], routing_header_bytes: &[u8]) {
        let mut preimage = routing_header_bytes.to_vec();
        preimage.extend_from_slice(&encode(&self.unsigned_value()));
        self.sig = lattice_crypto::sign(signing_seed, &preimage);
    }

    pub fn verify_signature(&self, from_key: &[u8; 32], routing_header_bytes: &[u8]) -> bool {
        let mut preimage = routing_header_bytes.to_vec();
        preimage.extend_from_slice(&encode(&self.unsigned_value()));
        lattice_crypto::verify(from_key, &preimage, &self.sig)
    }

    pub fn to_value(&self) -> Value {
        let mut pairs = self.unsigned_pairs();
        pairs.push((Value::UInt(10), Value::Bytes(self.sig.to_vec())));
        Value::map(pairs)
    }

    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&ENVELOPE_KEYS)?;
        let kind = v.req_uint(0)?;
        if kind > 2 {
            return Err(ProtoError::Invalid("unknown envelope kind"));
        }
        let body = match v.get_key(7)? {
            None => None,
            Some(b) => Some(
                b.as_bytes()
                    .ok_or(ProtoError::WrongType(7, "bytes"))?
                    .to_vec(),
            ),
        };
        let reference = match v.get_key(8)? {
            None => None,
            Some(b) => Some(
                b.as_bytes()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    .ok_or(ProtoError::WrongType(8, "16-byte id"))?,
            ),
        };
        let reason = match v.get_key(9)? {
            None => None,
            Some(r) => Some(r.as_uint().ok_or(ProtoError::WrongType(9, "uint"))?),
        };
        match kind {
            KIND_MESSAGE => {
                if body.is_none() || reference.is_some() || reason.is_some() {
                    return Err(ProtoError::Invalid("message envelope needs body only"));
                }
            }
            KIND_RECEIPT | KIND_NEGATIVE_RECEIPT => {
                if body.is_some() || reference.is_none() {
                    return Err(ProtoError::Invalid("receipt needs a reference, no body"));
                }
                if kind == KIND_NEGATIVE_RECEIPT
                    && !matches!(reason, Some(REASON_UNKNOWN_SERVICE | REASON_INVALID))
                {
                    return Err(ProtoError::Invalid("negative receipt needs a known reason"));
                }
                if kind == KIND_RECEIPT && reason.is_some() {
                    return Err(ProtoError::Invalid("receipt carries no reason"));
                }
            }
            _ => unreachable!(),
        }
        Ok(Self {
            kind,
            mid: fixed_bytes(v, 11)?,
            from: fixed_bytes(v, 1)?,
            fsvc: v.req_text(2)?.to_string(),
            fmbx: v.req_bytes(3)?.to_vec(),
            tsvc: v.req_text(4)?.to_string(),
            tmbx: v.req_bytes(5)?.to_vec(),
            created: v.req_uint(6)?,
            body,
            reference,
            reason,
            sig: fixed_bytes(v, 10)?,
        })
    }
}

/// A fully parsed and structurally validated message. The routing decision
/// is the caller's; crypto is not attempted here.
#[derive(Clone, Debug)]
pub struct Message {
    pub header: Header,
    pub hop_layer: Option<SealedLayer>,
    pub envelope: SealedLayer,
    raw_header: Vec<u8>,
    total_len: usize,
}

/// How the message reaches its final recipient.
#[derive(Clone)]
pub struct GatewaySeal {
    /// The gateway's X-Wing encapsulation (public) key.
    pub gateway_ek: [u8; 1216],
    /// The private recipient's identifier, placed in the gateway layer.
    pub rcpt: [u8; 32],
}

#[derive(Clone)]
pub struct WaypointSeal {
    pub waypoint_id: [u8; 32],
    pub waypoint_ek: [u8; 1216],
    pub leg: [u8; 16],
    pub exp: u64,
}

pub struct BuildParams<'a> {
    pub envelope: Envelope,
    pub sender_seed: &'a [u8; 32],
    /// Envelope key of the final recipient.
    pub recipient_ek: &'a [u8; 1216],
    /// Routing destination of the real header: the recipient for a direct
    /// public route, or the gateway for a private one.
    pub real_dst: [u8; 32],
    /// Leg id and expiry of the real header.
    pub leg: [u8; 16],
    pub exp: u64,
    pub gateway: Option<GatewaySeal>,
    pub waypoint: Option<WaypointSeal>,
}

/// Assemble the 4-element message array with exactly `bucket` bytes of
/// padding. Returns the encoded message.
fn assemble(
    outer: &Header,
    hop: &Option<SealedLayer>,
    envelope: &SealedLayer,
    bucket: usize,
) -> Option<Vec<u8>> {
    let header_val = outer.unsigned_value();
    let hop_val = match hop {
        Some(l) => l.to_value(),
        None => Value::Null,
    };
    let env_val = envelope.to_value();
    let body = 1 // array header
        + encode(&header_val).len()
        + encode(&hop_val).len()
        + encode(&env_val).len();
    // Choose a padding length whose encoded size lands exactly on the bucket.
    for (head_len, min_pad, max_pad) in [
        (1usize, 0usize, 23usize),
        (2, 24, 0xff),
        (3, 0x100, 0xffff),
        (5, 0x1_0000, 0xffff_ffff),
    ] {
        let pad = bucket as i64 - (body as i64 + head_len as i64);
        if pad >= min_pad as i64 && pad <= max_pad as i64 {
            let arr = Value::Array(vec![
                header_val,
                hop_val,
                env_val,
                Value::Bytes(vec![0u8; pad as usize]),
            ]);
            let bytes = encode(&arr);
            debug_assert_eq!(bytes.len(), bucket);
            return Some(bytes);
        }
    }
    None
}

impl Message {
    pub fn build(params: BuildParams<'_>) -> Result<Vec<u8>, ProtoError> {
        let mut envelope = params.envelope;
        let real = Header {
            leg: params.leg,
            dst: params.real_dst,
            exp: params.exp,
        };
        let real_bytes = real.encode();

        envelope.sign(params.sender_seed, &real_bytes);
        let env_pt = encode(&envelope.to_value());
        let env_layer =
            SealedLayer::seal_to(ENVELOPE_CONTEXT, params.recipient_ek, &real_bytes, &env_pt)?;

        // A gateway layer, when present, travels adjacent to the real header.
        let gateway_layer = match &params.gateway {
            Some(gw) => {
                let pt = encode(&HopLayerPlain::Gateway { rcpt: gw.rcpt }.to_value());
                Some(SealedLayer::seal_to(
                    HOP_CONTEXT,
                    &gw.gateway_ek,
                    &real_bytes,
                    &pt,
                )?)
            }
            None => None,
        };

        let (outer, outer_layer) = match &params.waypoint {
            Some(wp) => {
                let outer = Header {
                    leg: wp.leg,
                    dst: wp.waypoint_id,
                    exp: wp.exp.min(params.exp),
                };
                let outer_bytes = outer.encode();
                let inner = HopLayerPlain::Waypoint {
                    hdr: real.clone(),
                    inner: gateway_layer.map(Box::new),
                };
                let wp_pt = encode(&inner.to_value());
                let layer =
                    SealedLayer::seal_to(HOP_CONTEXT, &wp.waypoint_ek, &outer_bytes, &wp_pt)?;
                (outer, Some(layer))
            }
            None => (real, gateway_layer),
        };

        for bucket in MESSAGE_BUCKETS {
            if let Some(bytes) = assemble(&outer, &outer_layer, &env_layer, bucket) {
                return Ok(bytes);
            }
        }
        Err(ProtoError::TooBig(usize::MAX))
    }

    /// Parse without opening any sealed layer; checks structure and buckets.
    pub fn parse(bytes: &[u8], now: u64) -> Result<Self, ProtoError> {
        if !MESSAGE_BUCKETS.contains(&bytes.len()) {
            return Err(ProtoError::TooBig(bytes.len()));
        }
        let value = decode(bytes)?;
        let arr = value
            .as_array()
            .ok_or(ProtoError::Invalid("message is not an array"))?;
        if arr.len() != 4 {
            return Err(ProtoError::Invalid("message must have 4 elements"));
        }
        let header = Header::from_value(&arr[0])?;
        if header.exp <= now {
            return Err(ProtoError::Expired);
        }
        if header.exp > now + MAX_MESSAGE_HORIZON + CLOCK_SKEW {
            return Err(ProtoError::Invalid("message expiry beyond the horizon"));
        }
        let hop_layer = match &arr[1] {
            Value::Null => None,
            v => Some(SealedLayer::from_value(v)?),
        };
        let envelope = SealedLayer::from_value(&arr[2])?;
        let padding = arr[3]
            .as_bytes()
            .ok_or(ProtoError::WrongType(3, "padding bytes"))?;
        if !padding.iter().all(|&b| b == 0) {
            return Err(ProtoError::Invalid("non-zero padding"));
        }
        Ok(Self {
            raw_header: encode(&arr[0]),
            header,
            hop_layer,
            envelope,
            total_len: bytes.len(),
        })
    }

    pub fn raw_header(&self) -> &[u8] {
        &self.raw_header
    }

    pub fn routing_header_bytes(&self) -> &[u8] {
        &self.raw_header
    }

    pub fn encoded_len(&self) -> usize {
        self.total_len
    }

    /// Open the outer hop layer with the given hop secret key. Returns the
    /// plaintext for the node's role: Waypoint or Gateway.
    pub fn open_hop_layer(&self, hop_secret: &[u8; 32]) -> Result<HopLayerPlain, ProtoError> {
        let layer = self
            .hop_layer
            .as_ref()
            .ok_or(ProtoError::Invalid("no hop layer"))?;
        let pt = layer.open_with(HOP_CONTEXT, hop_secret, &self.raw_header)?;
        let value = decode(&pt)?;
        HopLayerPlain::from_value(&value)
    }

    /// After a waypoint replaces the header with the inner routing header,
    /// the gateway layer it carried (if any) becomes the hop layer; the
    /// message is re-padded to the same bucket.
    pub fn into_after_waypoint(self, inner: HopLayerPlain) -> Result<Vec<u8>, ProtoError> {
        let new_header = match inner {
            HopLayerPlain::Waypoint { hdr, inner } => (hdr, inner.map(|b| *b)), // unbox: SealedLayer moves into assemble()
            HopLayerPlain::Gateway { .. } => {
                return Err(ProtoError::Invalid(
                    "gateway layer cannot be unwrapped as a waypoint",
                ));
            }
        };
        let (hdr, gw_layer) = new_header;
        for bucket in MESSAGE_BUCKETS {
            if let Some(bytes) = assemble(&hdr, &gw_layer, &self.envelope, bucket) {
                return Ok(bytes);
            }
        }
        Err(ProtoError::TooBig(usize::MAX))
    }

    /// Decrypt the envelope with the recipient's key. The AAD is the routing
    /// header — the header in the same array slot the recipient received.
    pub fn open_envelope(&self, recipient_secret: &[u8; 32]) -> Result<Envelope, ProtoError> {
        let pt = self
            .envelope
            .open_with(ENVELOPE_CONTEXT, recipient_secret, &self.raw_header)?;
        let value = decode(&pt)?;
        Envelope::from_value(&value)
    }
}
