//! Channel frames (V2_SPEC §6). These are the plaintexts carried inside a
//! Noise transport message, itself a CBOR array `[frame, padding]`.
//! lattice-net owns padding and the Noise layer; this module owns shapes.

use lattice_types::{Cookie, Hash32, Identifier, LegId, Mac16, Signature};

use crate::cbor::{Value, encode};
use crate::error::ProtoError;
use crate::obj::fixed_bytes;

pub const T_INIT: u64 = 40;
pub const T_COOKIE: u64 = 41;
pub const T_RESP: u64 = 42;
pub const T_OFFER: u64 = 50;
pub const T_CUSTODY: u64 = 51;
pub const T_RECONCILE: u64 = 20;
pub const T_WANT: u64 = 21;
pub const T_RECORDS: u64 = 22;
pub const T_PING: u64 = 60;
pub const T_DUMMY: u64 = 61;
pub const T_ATTEST: u64 = 62;

/// Maximum ranges in a single reconcile frame; anything larger is rejected
/// at decode. Mirrors lattice-core's responder cap.
pub const MAX_RANGES_PER_MSG: usize = 64;

/// Maximum entries in one range's explicit list.
pub const MAX_ENTRIES_PER_RANGE: usize = 32;

pub const CUSTODY_ACCEPTED: u64 = 0;
pub const CUSTODY_ALREADY_HAVE: u64 = 1;
pub const CUSTODY_BUSY: u64 = 2;
pub const CUSTODY_REFUSED: u64 = 3;

fn mac_bytes(v: &Value, key: u64) -> Result<Mac16, ProtoError> {
    Ok(Mac16::from_bytes(fixed_bytes(v, key)?))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitFrame {
    pub noise_msg: Vec<u8>,
    pub mac1: Mac16,
    pub mac2: Option<Mac16>,
    pub padding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CookieFrame {
    /// Opaque 24-byte cookie issued by the server; echoed back in mac2.
    pub cookie: Cookie,
    pub padding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RespFrame {
    pub noise_msg: Vec<u8>,
    pub padding: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferFrame {
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustodyFrame {
    pub leg: LegId,
    pub result: u64,
    pub retry_after: Option<u64>,
}

/// A reconciliation range. `lower`/`upper` are (id, scope) bounds, half-open
/// [lower, upper); `None` is unbounded on that side. Bounds have scope 0 at
/// split points so both scopes of an id interval stay inside one range.
/// A bound of a reconciliation range: `(id, scope)`.
pub type RangeBound = (Identifier, u8);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Range {
    Fingerprint {
        lower: Option<(Identifier, u8)>,
        upper: Option<(Identifier, u8)>,
        count: u64,
        sum: Hash32,
    },
    Entries {
        lower: Option<(Identifier, u8)>,
        upper: Option<(Identifier, u8)>,
        entries: Vec<(Identifier, u8, u64)>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileFrame {
    pub ranges: Vec<Range>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WantFrame {
    /// (identifier, scope) pairs to fetch.
    pub wants: Vec<(Identifier, u8)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsFrame {
    /// Raw record encodings, exactly as received (needed for hashing).
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingFrame {
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DummyFrame {
    pub echo: bool,
}

/// Proof that the sender holds the KEL signing key for `id`, bound to this
/// channel: `sig` signs H("lattice attestation v1" || signer_channel_key ||
/// verifier_channel_key), where the signer's key is the Ed25519 channel key
/// in its record and the verifier's key is the X25519 key from the Noise
/// handshake. Lets a peer attribute a link without trusting record claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestFrame {
    pub id: Identifier,
    pub sig: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Init(InitFrame),
    Cookie(CookieFrame),
    Resp(RespFrame),
    Offer(OfferFrame),
    Custody(CustodyFrame),
    Reconcile(ReconcileFrame),
    Want(WantFrame),
    Records(RecordsFrame),
    Ping(PingFrame),
    Dummy(DummyFrame),
    Attest(AttestFrame),
}

fn bound_value(b: &(Identifier, u8)) -> Value {
    Value::map(vec![
        (Value::UInt(0), Value::Bytes(b.0.to_vec())),
        (Value::UInt(1), Value::UInt(b.1 as u64)),
    ])
}

fn parse_bound(v: &Value) -> Result<(Identifier, u8), ProtoError> {
    v.deny_unknown_keys(&[0, 1])?;
    let id = Identifier::from_bytes(fixed_bytes(v, 0)?);
    let scope = v.req_uint(1)?;
    if scope > 1 {
        return Err(ProtoError::Invalid("scope out of range"));
    }
    Ok((id, scope as u8))
}

impl Range {
    fn bound_value(b: &Option<(Identifier, u8)>) -> Option<Value> {
        b.map(|(id, scope)| bound_value(&(id, scope)))
    }

    fn bounds(&self) -> (Option<RangeBound>, Option<RangeBound>) {
        match self {
            Range::Fingerprint { lower, upper, .. } => (*lower, *upper),
            Range::Entries { lower, upper, .. } => (*lower, *upper),
        }
    }

    fn parse_bounds(v: &Value) -> Result<(Option<RangeBound>, Option<RangeBound>), ProtoError> {
        let lower = match v.get_key(0)? {
            None => None,
            Some(b) => Some(parse_bound(b)?),
        };
        let upper = match v.get_key(1)? {
            None => None,
            Some(b) => Some(parse_bound(b)?),
        };
        Ok((lower, upper))
    }

    fn to_value(&self) -> Value {
        let (lower, upper) = self.bounds();
        let mut pairs = Vec::with_capacity(4);
        if let Some(b) = Self::bound_value(&lower) {
            pairs.push((Value::UInt(0), b));
        }
        if let Some(b) = Self::bound_value(&upper) {
            pairs.push((Value::UInt(1), b));
        }
        match self {
            Range::Fingerprint { count, sum, .. } => {
                pairs.push((
                    Value::UInt(2),
                    Value::Array(vec![Value::UInt(*count), Value::Bytes(sum.to_vec())]),
                ));
            }
            Range::Entries { entries, .. } => {
                pairs.push((
                    Value::UInt(3),
                    Value::Array(
                        entries
                            .iter()
                            .map(|(id, scope, seq)| {
                                Value::Array(vec![
                                    Value::Bytes(id.to_vec()),
                                    Value::UInt(*scope as u64),
                                    Value::UInt(*seq),
                                ])
                            })
                            .collect(),
                    ),
                ));
            }
        }
        Value::map(pairs)
    }

    fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[0, 1, 2, 3])?;
        let (lower, upper) = Self::parse_bounds(v)?;
        if v.get_key(2)?.is_some() && v.get_key(3)?.is_some() {
            return Err(ProtoError::Invalid(
                "range must carry fingerprint (key 2) or entries (key 3), not both",
            ));
        }
        if let (Some((lo_id, lo_scope)), Some((hi_id, hi_scope))) = (&lower, &upper) {
            if (lo_id, lo_scope) > (hi_id, hi_scope) {
                return Err(ProtoError::Invalid("range lower bound exceeds upper bound"));
            }
        }
        if let Some(fp) = v.get_key(2)? {
            let arr = fp.as_array().ok_or(ProtoError::WrongType(2, "array"))?;
            if arr.len() != 2 {
                return Err(ProtoError::Invalid("fingerprint must be [count, sum]"));
            }
            let count = arr[0]
                .as_uint()
                .ok_or(ProtoError::WrongType(2, "uint count"))?;
            let sum = Hash32::from_bytes(
                arr[1]
                    .as_bytes()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or(ProtoError::WrongType(2, "32-byte sum"))?,
            );
            return Ok(Range::Fingerprint {
                lower,
                upper,
                count,
                sum,
            });
        }
        if let Some(list) = v.get_key(3)? {
            let list = list.as_array().ok_or(ProtoError::WrongType(3, "array"))?;
            if list.len() > MAX_ENTRIES_PER_RANGE {
                return Err(ProtoError::Invalid("too many entries in range"));
            }
            let entries = list
                .iter()
                .map(|e| {
                    let a = e.as_array().ok_or(ProtoError::WrongType(3, "array"))?;
                    if a.len() != 3 {
                        return Err(ProtoError::Invalid("entry must be [id, scope, seq]"));
                    }
                    let id = Identifier::from_bytes(
                        a[0].as_bytes()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .ok_or(ProtoError::WrongType(3, "32-byte id"))?,
                    );
                    let scope = u8::try_from(
                        a[1].as_uint()
                            .ok_or(ProtoError::WrongType(3, "uint scope"))?,
                    )
                    .map_err(|_| ProtoError::Invalid("scope out of range"))?;
                    if scope > 1 {
                        return Err(ProtoError::Invalid("scope out of range"));
                    }
                    let seq = a[2].as_uint().ok_or(ProtoError::WrongType(3, "uint seq"))?;
                    Ok((id, scope, seq))
                })
                .collect::<Result<Vec<_>, ProtoError>>()?;
            return Ok(Range::Entries {
                lower,
                upper,
                entries,
            });
        }
        Err(ProtoError::Invalid(
            "range needs either a fingerprint (key 2) or entries (key 3)",
        ))
    }
}

impl Frame {
    pub fn kind(&self) -> u64 {
        match self {
            Frame::Init(_) => T_INIT,
            Frame::Cookie(_) => T_COOKIE,
            Frame::Resp(_) => T_RESP,
            Frame::Offer(_) => T_OFFER,
            Frame::Custody(_) => T_CUSTODY,
            Frame::Reconcile(_) => T_RECONCILE,
            Frame::Want(_) => T_WANT,
            Frame::Records(_) => T_RECORDS,
            Frame::Ping(_) => T_PING,
            Frame::Dummy(_) => T_DUMMY,
            Frame::Attest(_) => T_ATTEST,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Frame::Init(f) => {
                let mut pairs = vec![
                    (Value::UInt(0), Value::UInt(T_INIT)),
                    (Value::UInt(2), Value::Bytes(f.noise_msg.clone())),
                    (Value::UInt(3), Value::Bytes(f.mac1.to_vec())),
                ];
                if let Some(m2) = &f.mac2 {
                    pairs.push((Value::UInt(4), Value::Bytes(m2.to_vec())));
                }
                pairs.push((Value::UInt(5), Value::Bytes(f.padding.clone())));
                Value::map(pairs)
            }
            Frame::Cookie(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_COOKIE)),
                (Value::UInt(2), Value::Bytes(f.cookie.to_vec())),
                (Value::UInt(5), Value::Bytes(f.padding.clone())),
            ]),
            Frame::Resp(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_RESP)),
                (Value::UInt(2), Value::Bytes(f.noise_msg.clone())),
                (Value::UInt(5), Value::Bytes(f.padding.clone())),
            ]),
            Frame::Offer(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_OFFER)),
                (Value::UInt(2), Value::Bytes(f.message.clone())),
            ]),
            Frame::Custody(f) => {
                let mut pairs = vec![
                    (Value::UInt(0), Value::UInt(T_CUSTODY)),
                    (Value::UInt(2), Value::Bytes(f.leg.to_vec())),
                    (Value::UInt(3), Value::UInt(f.result)),
                ];
                if let Some(ra) = f.retry_after {
                    pairs.push((Value::UInt(4), Value::UInt(ra)));
                }
                Value::map(pairs)
            }
            Frame::Reconcile(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_RECONCILE)),
                (
                    Value::UInt(2),
                    Value::Array(f.ranges.iter().map(Range::to_value).collect()),
                ),
            ]),
            Frame::Want(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_WANT)),
                (
                    Value::UInt(2),
                    Value::Array(
                        f.wants
                            .iter()
                            .map(|(id, scope)| {
                                Value::Array(vec![
                                    Value::Bytes(id.to_vec()),
                                    Value::UInt(*scope as u64),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]),
            Frame::Records(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_RECORDS)),
                (
                    Value::UInt(2),
                    Value::Array(f.records.iter().map(|r| Value::Bytes(r.clone())).collect()),
                ),
            ]),
            Frame::Ping(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_PING)),
                (Value::UInt(2), Value::UInt(f.nonce)),
            ]),
            Frame::Dummy(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_DUMMY)),
                (Value::UInt(2), Value::Bool(f.echo)),
            ]),
            Frame::Attest(f) => Value::map(vec![
                (Value::UInt(0), Value::UInt(T_ATTEST)),
                (Value::UInt(2), Value::Bytes(f.id.to_vec())),
                (Value::UInt(3), Value::Bytes(f.sig.to_vec())),
            ]),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        let kind = v.req_uint(0)?;
        match kind {
            T_INIT => {
                v.deny_unknown_keys(&[0, 2, 3, 4, 5])?;
                Ok(Frame::Init(InitFrame {
                    noise_msg: v.req_bytes(2)?.to_vec(),
                    mac1: mac_bytes(v, 3)?,
                    mac2: match v.get_key(4)? {
                        None => None,
                        Some(_) => Some(Mac16::from_bytes(fixed_bytes(v, 4)?)),
                    },
                    padding: v.req_bytes(5)?.to_vec(),
                }))
            }
            T_COOKIE => {
                v.deny_unknown_keys(&[0, 2, 5])?;
                Ok(Frame::Cookie(CookieFrame {
                    cookie: Cookie::from_bytes(fixed_bytes(v, 2)?),
                    padding: v.req_bytes(5)?.to_vec(),
                }))
            }
            T_RESP => {
                v.deny_unknown_keys(&[0, 2, 5])?;
                Ok(Frame::Resp(RespFrame {
                    noise_msg: v.req_bytes(2)?.to_vec(),
                    padding: v.req_bytes(5)?.to_vec(),
                }))
            }
            T_OFFER => {
                v.deny_unknown_keys(&[0, 2])?;
                Ok(Frame::Offer(OfferFrame {
                    message: v.req_bytes(2)?.to_vec(),
                }))
            }
            T_CUSTODY => {
                v.deny_unknown_keys(&[0, 2, 3, 4])?;
                let result = v.req_uint(3)?;
                if result > CUSTODY_REFUSED {
                    return Err(ProtoError::Invalid("unknown custody result"));
                }
                Ok(Frame::Custody(CustodyFrame {
                    leg: LegId::from_bytes(fixed_bytes(v, 2)?),
                    result,
                    retry_after: match v.get_key(4)? {
                        None => None,
                        Some(x) => Some(x.as_uint().ok_or(ProtoError::WrongType(4, "uint"))?),
                    },
                }))
            }
            T_RECONCILE => {
                v.deny_unknown_keys(&[0, 2])?;
                let raw = v.req_array(2)?;
                if raw.len() > MAX_RANGES_PER_MSG {
                    return Err(ProtoError::Invalid("too many reconcile ranges"));
                }
                let ranges = raw
                    .iter()
                    .map(Range::from_value)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Frame::Reconcile(ReconcileFrame { ranges }))
            }
            T_WANT => {
                v.deny_unknown_keys(&[0, 2])?;
                let wants = v
                    .req_array(2)?
                    .iter()
                    .map(|e| {
                        let a = e.as_array().ok_or(ProtoError::WrongType(2, "array"))?;
                        if a.len() != 2 {
                            return Err(ProtoError::Invalid("want entry must be [id, scope]"));
                        }
                        let id = Identifier::from_bytes(
                            a[0].as_bytes()
                                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                                .ok_or(ProtoError::WrongType(2, "32-byte id"))?,
                        );
                        let scope = u8::try_from(
                            a[1].as_uint()
                                .ok_or(ProtoError::WrongType(2, "uint scope"))?,
                        )
                        .map_err(|_| ProtoError::Invalid("scope out of range"))?;
                        if scope > 1 {
                            return Err(ProtoError::Invalid("scope out of range"));
                        }
                        Ok((id, scope))
                    })
                    .collect::<Result<Vec<_>, ProtoError>>()?;
                Ok(Frame::Want(WantFrame { wants }))
            }
            T_RECORDS => {
                v.deny_unknown_keys(&[0, 2])?;
                let records = v
                    .req_array(2)?
                    .iter()
                    .map(|e| {
                        e.as_bytes()
                            .map(|b| b.to_vec())
                            .ok_or(ProtoError::WrongType(2, "bytes"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Frame::Records(RecordsFrame { records }))
            }
            T_PING => {
                v.deny_unknown_keys(&[0, 2])?;
                Ok(Frame::Ping(PingFrame {
                    nonce: v.req_uint(2)?,
                }))
            }
            T_DUMMY => {
                v.deny_unknown_keys(&[0, 2])?;
                Ok(Frame::Dummy(DummyFrame {
                    echo: v.req_bool(2)?,
                }))
            }
            T_ATTEST => {
                v.deny_unknown_keys(&[0, 2, 3])?;
                Ok(Frame::Attest(AttestFrame {
                    id: Identifier::from_bytes(fixed_bytes(v, 2)?),
                    sig: Signature::from_bytes(fixed_bytes(v, 3)?),
                }))
            }
            _ => Err(ProtoError::Invalid("unknown frame type")),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_value(&crate::cbor::decode(bytes)?)
    }
}
