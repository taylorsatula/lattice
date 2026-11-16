//! Channel frames (V2_SPEC §6). These are the plaintexts carried inside a
//! Noise transport message, itself a CBOR array `[frame, padding]`.
//! lattice-net owns padding and the Noise layer; this module owns shapes.

use lattice_types::{Cookie, Hash32, Identifier, LegId, Mac16};

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
pub const T_KELS: u64 = 24;
pub const T_PING: u64 = 60;
pub const T_DUMMY: u64 = 61;
// 62 was `attest` in early drafts; reserved, never sent, never accepted.

/// Scope value for KEL entries in the reconciliation set (spec §6). Never
/// valid in a record.
pub const SCOPE_KEL: u8 = 255;

/// Maximum ranges in a single reconcile frame; anything larger is rejected
/// at decode. Mirrors lattice-core's responder cap.
pub const MAX_RANGES_PER_MSG: usize = 64;

/// Maximum entries in one range's explicit list.
pub const MAX_ENTRIES_PER_RANGE: usize = 32;

pub const CUSTODY_ACCEPTED: u64 = 0;
pub const CUSTODY_ALREADY_HAVE: u64 = 1;
pub const CUSTODY_BUSY: u64 = 2;
pub const CUSTODY_REFUSED: u64 = 3;
pub const CUSTODY_SEEN: u64 = 4;

fn mac_bytes(v: &Value, key: u64) -> Result<Mac16, ProtoError> {
    Ok(Mac16::from_bytes(fixed_bytes(v, key)?))
}

fn kind_pair(kind: u64) -> (Value, Value) {
    (Value::UInt(0), Value::UInt(kind))
}

fn padding_pair(padding: &[u8]) -> (Value, Value) {
    (Value::UInt(5), Value::Bytes(padding.to_vec()))
}

fn req_padding(v: &Value) -> Result<Vec<u8>, ProtoError> {
    Ok(v.req_bytes(5)?.to_vec())
}

/// Parse a scope byte: 0 (WAN), 1 (hive) or 255 (KEL reconciliation
/// entries). Anything else is rejected.
fn parse_scope(v: &Value) -> Result<u8, ProtoError> {
    let scope = u8::try_from(v.as_uint().ok_or(ProtoError::WrongType(0, "uint scope"))?)
        .map_err(|_| ProtoError::Invalid("scope out of range"))?;
    match scope {
        0 | 1 | SCOPE_KEL => Ok(scope),
        _ => Err(ProtoError::Invalid("scope out of range")),
    }
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

/// A reference to a record: its identifier and scope. Used for reconcile
/// wants and anywhere a record is named without its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordRef {
    pub id: Identifier,
    pub scope: u8,
}

/// An entry in a range's explicit list (spec §6): the record's (or KEL's)
/// id, scope, `khs`, `seq` and the first 8 bytes of its hash. For a KEL
/// entry, `khs` and `seq` are both the head sn and the hash prefix is the
/// first 8 bytes of the head event's event hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordEntry {
    pub id: Identifier,
    pub scope: u8,
    pub khs: u64,
    pub seq: u64,
    pub hash_prefix: [u8; 8],
}

impl RecordEntry {
    /// The (id, scope) pair identifying the record, without the seq.
    pub fn key(&self) -> RecordRef {
        RecordRef {
            id: self.id,
            scope: self.scope,
        }
    }
}

/// A bound of a reconciliation range: `(id, scope)`. Bounds have scope 0 at
/// split points so both scopes of an id interval stay inside one range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RangeBound {
    pub id: Identifier,
    pub scope: u8,
}

/// The half-open bounds of a range; `None` is unbounded on that side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeBounds {
    pub lower: Option<RangeBound>,
    pub upper: Option<RangeBound>,
}

/// A reconciliation range. `lower`/`upper` are (id, scope) bounds, half-open
/// [lower, upper); `None` is unbounded on that side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Range {
    Fingerprint {
        lower: Option<RangeBound>,
        upper: Option<RangeBound>,
        count: u64,
        sum: Hash32,
    },
    Entries {
        lower: Option<RangeBound>,
        upper: Option<RangeBound>,
        entries: Vec<RecordEntry>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileFrame {
    pub ranges: Vec<Range>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WantFrame {
    /// Records to fetch.
    pub wants: Vec<RecordRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsFrame {
    /// Raw record encodings, exactly as received (needed for hashing).
    pub records: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KelsFrame {
    /// Raw KEL object encodings (spec §2), exactly as received.
    pub kels: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingFrame {
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DummyFrame {
    pub echo: bool,
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
    Kels(KelsFrame),
    Ping(PingFrame),
    Dummy(DummyFrame),
}

fn bound_value(b: &RangeBound) -> Value {
    Value::map(vec![
        (Value::UInt(0), Value::Bytes(b.id.to_vec())),
        (Value::UInt(1), Value::UInt(b.scope as u64)),
    ])
}

fn parse_bound(v: &Value) -> Result<RangeBound, ProtoError> {
    v.deny_unknown_keys(&[0, 1])?;
    let id = Identifier::from_bytes(fixed_bytes(v, 0)?);
    let scope = v.req_uint(1)?;
    let scope = u8::try_from(scope).map_err(|_| ProtoError::Invalid("scope out of range"))?;
    Ok(RangeBound { id, scope })
}

impl Range {
    fn bound_value(b: Option<&RangeBound>) -> Option<Value> {
        b.map(bound_value)
    }

    fn bounds(&self) -> RangeBounds {
        match self {
            Range::Fingerprint { lower, upper, .. } | Range::Entries { lower, upper, .. } => {
                RangeBounds {
                    lower: *lower,
                    upper: *upper,
                }
            }
        }
    }

    fn parse_bounds(v: &Value) -> Result<RangeBounds, ProtoError> {
        let lower = match v.get_key(0)? {
            None => None,
            Some(b) => Some(parse_bound(b)?),
        };
        let upper = match v.get_key(1)? {
            None => None,
            Some(b) => Some(parse_bound(b)?),
        };
        Ok(RangeBounds { lower, upper })
    }

    fn to_value(&self) -> Value {
        let RangeBounds { lower, upper } = self.bounds();
        let mut pairs = Vec::with_capacity(4);
        if let Some(b) = Self::bound_value(lower.as_ref()) {
            pairs.push((Value::UInt(0), b));
        }
        if let Some(b) = Self::bound_value(upper.as_ref()) {
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
                            .map(|e| {
                                Value::Array(vec![
                                    Value::Bytes(e.id.to_vec()),
                                    Value::UInt(e.scope as u64),
                                    Value::Bytes(e.khs.to_le_bytes().to_vec()),
                                    Value::Bytes(e.seq.to_le_bytes().to_vec()),
                                    Value::Bytes(e.hash_prefix.to_vec()),
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
        let RangeBounds { lower, upper } = Self::parse_bounds(v)?;
        if v.get_key(2)?.is_some() && v.get_key(3)?.is_some() {
            return Err(ProtoError::Invalid(
                "range must carry fingerprint (key 2) or entries (key 3), not both",
            ));
        }
        if let (Some(lo), Some(hi)) = (&lower, &upper) {
            if lo > hi {
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
                    if a.len() != 5 {
                        return Err(ProtoError::Invalid(
                            "entry must be [id, scope, khs, seq, hash-prefix]",
                        ));
                    }
                    let id = Identifier::from_bytes(
                        a[0].as_bytes()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .ok_or(ProtoError::WrongType(3, "32-byte id"))?,
                    );
                    let scope = parse_scope(&a[1])?;
                    let khs = a[2]
                        .as_bytes()
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .map(u64::from_le_bytes)
                        .ok_or(ProtoError::WrongType(3, "8-byte khs"))?;
                    let seq = a[3]
                        .as_bytes()
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .map(u64::from_le_bytes)
                        .ok_or(ProtoError::WrongType(3, "8-byte seq"))?;
                    let hash_prefix: [u8; 8] = a[4]
                        .as_bytes()
                        .and_then(|b| <[u8; 8]>::try_from(b).ok())
                        .ok_or(ProtoError::WrongType(3, "8-byte hash-prefix"))?;
                    Ok(RecordEntry {
                        id,
                        scope,
                        khs,
                        seq,
                        hash_prefix,
                    })
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

fn encode_init(f: &InitFrame) -> Value {
    let mut pairs = vec![
        kind_pair(T_INIT),
        (Value::UInt(2), Value::Bytes(f.noise_msg.clone())),
        (Value::UInt(3), Value::Bytes(f.mac1.to_vec())),
    ];
    if let Some(m2) = &f.mac2 {
        pairs.push((Value::UInt(4), Value::Bytes(m2.to_vec())));
    }
    pairs.push(padding_pair(&f.padding));
    Value::map(pairs)
}

fn encode_cookie(f: &CookieFrame) -> Value {
    Value::map(vec![
        kind_pair(T_COOKIE),
        (Value::UInt(2), Value::Bytes(f.cookie.to_vec())),
        padding_pair(&f.padding),
    ])
}

fn encode_resp(f: &RespFrame) -> Value {
    Value::map(vec![
        kind_pair(T_RESP),
        (Value::UInt(2), Value::Bytes(f.noise_msg.clone())),
        padding_pair(&f.padding),
    ])
}

fn encode_offer(f: &OfferFrame) -> Value {
    Value::map(vec![
        kind_pair(T_OFFER),
        (Value::UInt(2), Value::Bytes(f.message.clone())),
    ])
}

fn encode_custody(f: &CustodyFrame) -> Value {
    let mut pairs = vec![
        kind_pair(T_CUSTODY),
        (Value::UInt(2), Value::Bytes(f.leg.to_vec())),
        (Value::UInt(3), Value::UInt(f.result)),
    ];
    if let Some(ra) = f.retry_after {
        pairs.push((Value::UInt(4), Value::UInt(ra)));
    }
    Value::map(pairs)
}

fn encode_reconcile(f: &ReconcileFrame) -> Value {
    Value::map(vec![
        kind_pair(T_RECONCILE),
        (
            Value::UInt(2),
            Value::Array(f.ranges.iter().map(Range::to_value).collect()),
        ),
    ])
}

fn encode_want(f: &WantFrame) -> Value {
    Value::map(vec![
        kind_pair(T_WANT),
        (
            Value::UInt(2),
            Value::Array(
                f.wants
                    .iter()
                    .map(|w| {
                        Value::Array(vec![
                            Value::Bytes(w.id.to_vec()),
                            Value::UInt(w.scope as u64),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn encode_records(f: &RecordsFrame) -> Value {
    Value::map(vec![
        kind_pair(T_RECORDS),
        (
            Value::UInt(2),
            Value::Array(f.records.iter().map(|r| Value::Bytes(r.clone())).collect()),
        ),
    ])
}

fn encode_kels(f: &KelsFrame) -> Value {
    Value::map(vec![
        kind_pair(T_KELS),
        (
            Value::UInt(2),
            Value::Array(f.kels.iter().map(|k| Value::Bytes(k.clone())).collect()),
        ),
    ])
}

fn encode_ping(f: &PingFrame) -> Value {
    Value::map(vec![
        kind_pair(T_PING),
        (Value::UInt(2), Value::UInt(f.nonce)),
    ])
}

fn encode_dummy(f: &DummyFrame) -> Value {
    Value::map(vec![
        kind_pair(T_DUMMY),
        (Value::UInt(2), Value::Bool(f.echo)),
    ])
}

fn decode_init(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2, 3, 4, 5])?;
    Ok(Frame::Init(InitFrame {
        noise_msg: v.req_bytes(2)?.to_vec(),
        mac1: mac_bytes(v, 3)?,
        mac2: match v.get_key(4)? {
            None => None,
            Some(_) => Some(Mac16::from_bytes(fixed_bytes(v, 4)?)),
        },
        padding: req_padding(v)?,
    }))
}

fn decode_cookie(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2, 5])?;
    Ok(Frame::Cookie(CookieFrame {
        cookie: Cookie::from_bytes(fixed_bytes(v, 2)?),
        padding: req_padding(v)?,
    }))
}

fn decode_resp(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2, 5])?;
    Ok(Frame::Resp(RespFrame {
        noise_msg: v.req_bytes(2)?.to_vec(),
        padding: req_padding(v)?,
    }))
}

fn decode_offer(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2])?;
    Ok(Frame::Offer(OfferFrame {
        message: v.req_bytes(2)?.to_vec(),
    }))
}

fn decode_custody(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2, 3, 4])?;
    let result = v.req_uint(3)?;
    if result > CUSTODY_SEEN {
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

fn decode_reconcile(v: &Value) -> Result<Frame, ProtoError> {
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

fn decode_want(v: &Value) -> Result<Frame, ProtoError> {
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
            let scope = parse_scope(&a[1])?;
            Ok(RecordRef { id, scope })
        })
        .collect::<Result<Vec<_>, ProtoError>>()?;
    Ok(Frame::Want(WantFrame { wants }))
}

fn decode_records(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2])?;
    let records = v
        .req_array(2)?
        .iter()
        .map(|e| {
            e.as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or(ProtoError::WrongType(2, "bytes"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Frame::Records(RecordsFrame { records }))
}

fn decode_kels(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2])?;
    let kels = v
        .req_array(2)?
        .iter()
        .map(|e| {
            e.as_bytes()
                .map(<[u8]>::to_vec)
                .ok_or(ProtoError::WrongType(2, "bytes"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Frame::Kels(KelsFrame { kels }))
}

fn decode_ping(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2])?;
    Ok(Frame::Ping(PingFrame {
        nonce: v.req_uint(2)?,
    }))
}

fn decode_dummy(v: &Value) -> Result<Frame, ProtoError> {
    v.deny_unknown_keys(&[0, 2])?;
    Ok(Frame::Dummy(DummyFrame {
        echo: v.req_bool(2)?,
    }))
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
            Frame::Kels(_) => T_KELS,
            Frame::Ping(_) => T_PING,
            Frame::Dummy(_) => T_DUMMY,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Frame::Init(f) => encode_init(f),
            Frame::Cookie(f) => encode_cookie(f),
            Frame::Resp(f) => encode_resp(f),
            Frame::Offer(f) => encode_offer(f),
            Frame::Custody(f) => encode_custody(f),
            Frame::Reconcile(f) => encode_reconcile(f),
            Frame::Want(f) => encode_want(f),
            Frame::Records(f) => encode_records(f),
            Frame::Kels(f) => encode_kels(f),
            Frame::Ping(f) => encode_ping(f),
            Frame::Dummy(f) => encode_dummy(f),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        let kind = v.req_uint(0)?;
        match kind {
            T_INIT => decode_init(v),
            T_COOKIE => decode_cookie(v),
            T_RESP => decode_resp(v),
            T_OFFER => decode_offer(v),
            T_CUSTODY => decode_custody(v),
            T_RECONCILE => decode_reconcile(v),
            T_WANT => decode_want(v),
            T_RECORDS => decode_records(v),
            T_KELS => decode_kels(v),
            T_PING => decode_ping(v),
            T_DUMMY => decode_dummy(v),
            _ => Err(ProtoError::Invalid("unknown frame type")),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_value(&crate::cbor::decode(bytes)?)
    }
}
