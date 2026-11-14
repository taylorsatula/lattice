//! Peer records (V2_SPEC §3): build, sign, validate, order.

use std::net::{IpAddr, Ipv4Addr};

use lattice_crypto::{hash, sign, verify};

use crate::cbor::{Value, encode};
use crate::error::ProtoError;
use crate::kel::{KelHead, KelRelation, KeyEvent, classify, identifier};
use crate::obj::{decode_limited, fixed_bytes};
use crate::{CLOCK_SKEW, MAX_RECORD_HORIZON, RECORD_MAX};

pub const KIND_RECORD: u64 = 10;
pub const SCOPE_WAN: u64 = 0;
pub const SCOPE_HIVE: u64 = 1;
pub const MODE_PUBLIC: u64 = 0;
pub const MODE_PRIVATE: u64 = 1;

const MAX_LINKS: usize = 32;
const MAX_GATEWAYS: usize = 3;
const MAX_ENDPOINTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Wan,
    Hive,
}

impl Scope {
    fn as_u64(self) -> u64 {
        match self {
            Scope::Wan => SCOPE_WAN,
            Scope::Hive => SCOPE_HIVE,
        }
    }
    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            SCOPE_WAN => Ok(Self::Wan),
            SCOPE_HIVE => Ok(Self::Hive),
            _ => Err(ProtoError::Invalid("unknown scope")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Public,
    Private,
}

impl Mode {
    fn as_u64(self) -> u64 {
        match self {
            Mode::Public => MODE_PUBLIC,
            Mode::Private => MODE_PRIVATE,
        }
    }
    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            MODE_PUBLIC => Ok(Self::Public),
            MODE_PRIVATE => Ok(Self::Private),
            _ => Err(ProtoError::Invalid("unknown mode")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub url: String,
    pub ips: Vec<IpAddr>,
}

impl Endpoint {
    fn to_value(&self) -> Value {
        let mut pairs = vec![(Value::UInt(0), Value::Text(self.url.clone()))];
        if !self.ips.is_empty() {
            pairs.push((
                Value::UInt(1),
                Value::Array(
                    self.ips
                        .iter()
                        .map(|ip| Value::Text(ip.to_string()))
                        .collect(),
                ),
            ));
        }
        Value::map(pairs)
    }
    fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[0, 1])?;
        let url = v.req_text(0)?.to_string();
        let ips = match v.get_key(1)? {
            None => Vec::new(),
            Some(ips) => ips
                .as_array()
                .ok_or(ProtoError::WrongType(1, "array"))?
                .iter()
                .map(|x| {
                    x.as_text()
                        .ok_or(ProtoError::WrongType(1, "text"))
                        .and_then(|s| {
                            s.parse::<IpAddr>()
                                .map_err(|_| ProtoError::Invalid("invalid IP literal"))
                        })
                })
                .collect::<Result<_, _>>()?,
        };
        Ok(Self { url, ips })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub id: [u8; 32],
    pub scope: Scope,
    pub seq: u64,
    pub exp: u64,
    pub kel: Vec<KeyEvent>,
    pub channel_key: [u8; 32],
    pub envelope_key: [u8; 1216],
    pub mode: Mode,
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<[u8; 32]>,
    pub gateways: Vec<[u8; 32]>,
    pub capabilities: u64,
    pub sig: [u8; 64],
}

/// Parameters for [`PeerRecord::build`].
pub struct RecordParams {
    pub kel: Vec<KeyEvent>,
    pub seq: u64,
    pub exp: u64,
    pub channel_key: [u8; 32],
    pub envelope_key: [u8; 1216],
    pub mode: Mode,
    pub scope: Scope,
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<[u8; 32]>,
    pub gateways: Vec<[u8; 32]>,
    pub capabilities: u64,
}

const RECORD_KEYS: [u64; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

impl PeerRecord {
    /// The unsigned portion, as a CBOR map.
    fn unsigned_value(&self) -> Value {
        let mut pairs = vec![
            (Value::UInt(0), Value::UInt(crate::kel::PROTOCOL_VERSION)),
            (Value::UInt(1), Value::UInt(KIND_RECORD)),
            (Value::UInt(2), Value::Bytes(self.id.to_vec())),
            (Value::UInt(3), Value::UInt(self.scope.as_u64())),
            (Value::UInt(4), Value::UInt(self.seq)),
            (Value::UInt(5), Value::UInt(self.exp)),
            (
                Value::UInt(6),
                Value::Array(self.kel.iter().map(|e| e.to_value()).collect()),
            ),
            (Value::UInt(7), Value::Bytes(self.channel_key.to_vec())),
            (Value::UInt(8), Value::Bytes(self.envelope_key.to_vec())),
            (Value::UInt(9), Value::UInt(self.mode.as_u64())),
        ];
        if self.mode == Mode::Public {
            pairs.push((
                Value::UInt(10),
                Value::Array(self.endpoints.iter().map(Endpoint::to_value).collect()),
            ));
            pairs.push((
                Value::UInt(11),
                Value::Array(
                    self.links
                        .iter()
                        .map(|l| Value::Bytes(l.to_vec()))
                        .collect(),
                ),
            ));
        } else {
            pairs.push((
                Value::UInt(12),
                Value::Array(
                    self.gateways
                        .iter()
                        .map(|g| Value::Bytes(g.to_vec()))
                        .collect(),
                ),
            ));
        }
        pairs.push((Value::UInt(13), Value::UInt(self.capabilities)));
        Value::map(pairs)
    }

    fn to_value(&self) -> Value {
        let mut pairs = match self.unsigned_value() {
            Value::Map(m) => m,
            _ => unreachable!(),
        };
        pairs.push((Value::UInt(14), Value::Bytes(self.sig.to_vec())));
        Value::map(pairs)
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    /// Build and sign a record. Caller supplies fresh seq and expiry.
    pub fn build(params: RecordParams, signing_seed: &[u8; 32]) -> Result<PeerRecord, ProtoError> {
        let RecordParams {
            kel,
            seq,
            exp,
            channel_key,
            envelope_key,
            mode,
            scope,
            endpoints,
            links,
            gateways,
            capabilities,
        } = params;
        // Refuse to sign structurally invalid records; validation also runs on the wire.
        match mode {
            Mode::Public => {
                if !gateways.is_empty() {
                    return Err(ProtoError::Invalid("public record carries gateways"));
                }
            }
            Mode::Private => {
                if !endpoints.is_empty() || !links.is_empty() {
                    return Err(ProtoError::Invalid(
                        "private record carries endpoints or links",
                    ));
                }
                if gateways.is_empty() || gateways.len() > MAX_GATEWAYS {
                    return Err(ProtoError::Invalid("private record needs 1-3 gateways"));
                }
            }
        }
        let id = identifier(&kel)?;
        let mut rec = PeerRecord {
            id,
            scope,
            seq,
            exp,
            kel,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            sig: [0; 64],
        };
        rec.sig = sign(signing_seed, &encode(&rec.unsigned_value()));
        Ok(rec)
    }
}

impl PeerRecord {
    /// Parse and fully validate a record from the wire.
    ///
    /// `now` is injected so the same code runs in the simulator and the
    /// daemon. `known_head`, when supplied, is the head this node already
    /// holds for the record's identifier; a record whose KEL is behind or
    /// divergent is rejected.
    pub fn from_bytes(
        bytes: &[u8],
        now: u64,
        known_head: Option<&KelHead>,
    ) -> Result<(PeerRecord, KelHead), ProtoError> {
        let value = decode_limited(bytes, RECORD_MAX)?;
        value.deny_unknown_keys(&RECORD_KEYS)?;
        if value.req_uint(0)? != crate::kel::PROTOCOL_VERSION {
            return Err(ProtoError::Invalid("unsupported protocol version"));
        }
        if value.req_uint(1)? != KIND_RECORD {
            return Err(ProtoError::Invalid("not a peer record"));
        }
        let id = fixed_bytes::<32>(&value, 2)?;
        let scope = Scope::from_u64(value.req_uint(3)?)?;
        let seq = value.req_uint(4)?;
        let exp = value.req_uint(5)?;
        let kel: Vec<KeyEvent> = value
            .req_array(6)?
            .iter()
            .map(KeyEvent::from_value)
            .collect::<Result<_, _>>()?;
        let channel_key = fixed_bytes(&value, 7)?;
        let envelope_key = fixed_bytes(&value, 8)?;
        let mode = Mode::from_u64(value.req_uint(9)?)?;
        let capabilities = value.req_uint(13)?;
        let sig = fixed_bytes::<64>(&value, 14)?;

        let endpoints = match value.get_key(10)? {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ProtoError::WrongType(10, "array"))?
                .iter()
                .map(Endpoint::from_value)
                .collect::<Result<_, _>>()?,
        };
        let links = match value.get_key(11)? {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ProtoError::WrongType(11, "array"))?
                .iter()
                .map(|x| {
                    x.as_bytes()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .ok_or(ProtoError::WrongType(11, "32-byte id"))
                })
                .collect::<Result<_, _>>()?,
        };
        let gateways = match value.get_key(12)? {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ProtoError::WrongType(12, "array"))?
                .iter()
                .map(|x| {
                    x.as_bytes()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .ok_or(ProtoError::WrongType(12, "32-byte id"))
                })
                .collect::<Result<_, _>>()?,
        };

        // Structural validation.
        if exp <= now {
            return Err(ProtoError::Expired);
        }
        if exp > now + MAX_RECORD_HORIZON + CLOCK_SKEW {
            return Err(ProtoError::Invalid("record expiry beyond the horizon"));
        }
        match mode {
            Mode::Public => {
                if !gateways.is_empty() {
                    return Err(ProtoError::Invalid("public record carries gateways"));
                }
                if endpoints.len() > MAX_ENDPOINTS {
                    return Err(ProtoError::Invalid("too many endpoints"));
                }
                if links.len() > MAX_LINKS {
                    return Err(ProtoError::Invalid("too many links"));
                }
            }
            Mode::Private => {
                if !endpoints.is_empty() || !links.is_empty() {
                    return Err(ProtoError::Invalid(
                        "private record carries endpoints or links",
                    ));
                }
                if gateways.is_empty() || gateways.len() > MAX_GATEWAYS {
                    return Err(ProtoError::Invalid("private record needs 1-3 gateways"));
                }
            }
        }
        for ep in &endpoints {
            validate_endpoint(ep, scope)?;
        }

        // KEL validation and monotonicity.
        let head = KeyEvent::validate_chain(&kel)?;
        if head.abandoned {
            return Err(ProtoError::BadKeyLog("identity abandoned"));
        }
        let expected_id = identifier(&kel)?;
        if expected_id != id {
            return Err(ProtoError::BadKeyLog(
                "identifier does not match inception event",
            ));
        }
        if let Some(known) = known_head {
            match classify(known, &kel) {
                KelRelation::Extends | KelRelation::Same => {}
                KelRelation::Behind => {
                    return Err(ProtoError::BadKeyLog("KEL is behind the known head"));
                }
                KelRelation::Divergent => {
                    return Err(ProtoError::BadKeyLog("KEL diverges from the known head"));
                }
            }
        }

        let record = PeerRecord {
            id,
            scope,
            seq,
            exp,
            kel,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            sig,
        };
        let preimage = encode(&record.unsigned_value());
        if !verify(&head.current_key, &preimage, &record.sig) {
            return Err(ProtoError::BadSignature);
        }
        Ok((record, head))
    }
}

pub fn record_hash(bytes: &[u8]) -> [u8; 32] {
    hash(bytes)
}

/// Equivocation: two records, same (id, scope, seq), different bytes.
/// Callers must have validated both signatures before calling.
pub fn is_equivocation(a: &PeerRecord, a_bytes: &[u8], b: &PeerRecord, b_bytes: &[u8]) -> bool {
    a.id == b.id && a.scope == b.scope && a.seq == b.seq && a_bytes != b_bytes
}

/// Last-writer-wins comparison: higher seq wins; equal seq, lower hash wins.
/// Returns Ordering of `a` vs `b` (Greater means a wins).
pub fn compare_lww(a_bytes: &[u8], a_seq: u64, b_bytes: &[u8], b_seq: u64) -> std::cmp::Ordering {
    match a_seq.cmp(&b_seq) {
        // Equal seq: the record with the lower BLAKE3 hash wins.
        std::cmp::Ordering::Equal => record_hash(b_bytes).cmp(&record_hash(a_bytes)),
        other => other,
    }
}

fn validate_endpoint(ep: &Endpoint, scope: Scope) -> Result<(), ProtoError> {
    let rest = ep
        .url
        .strip_prefix("wss://")
        .or_else(|| ep.url.strip_prefix("ws://"))
        .ok_or(ProtoError::Invalid("endpoint scheme must be ws or wss"))?;
    if scope == Scope::Wan && !ep.url.starts_with("wss://") {
        return Err(ProtoError::Invalid("WAN endpoints must use wss"));
    }
    let hostport = rest.split('/').next().unwrap_or("");
    if hostport.is_empty() || hostport.contains('@') {
        return Err(ProtoError::Invalid(
            "endpoint has no host or carries userinfo",
        ));
    }
    let host = match hostport.rsplit_once(':') {
        Some((h, port)) => {
            if h.is_empty() || port.parse::<u16>().is_err() || port.parse::<u16>() == Ok(0) {
                return Err(ProtoError::Invalid("bad endpoint port"));
            }
            h
        }
        None => hostport,
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        if scope == Scope::Wan && !is_globally_routable(ip) {
            return Err(ProtoError::Invalid(
                "WAN endpoint host is not globally routable",
            ));
        }
    } else if host
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
        || host.starts_with('-')
        || host.ends_with('-')
    {
        return Err(ProtoError::Invalid("bad endpoint hostname"));
    }
    for ip in &ep.ips {
        if scope == Scope::Wan && !is_globally_routable(*ip) {
            return Err(ProtoError::Invalid(
                "WAN endpoint address is not globally routable",
            ));
        }
    }
    Ok(())
}

pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_v4_global(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_v4_global(mapped);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)) // documentation 2001:db8::/32
        }
    }
}

fn is_v4_global(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let private = matches!(
        o,
        [0, ..]
            | [10, ..]
            | [100, 64..=127, ..]
            | [127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0, 0, _]
            | [192, 0, 2, _]
            | [192, 168, ..]
            | [198, 18 | 19, ..]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
            | [224..=255, ..]
    );
    !private
}
