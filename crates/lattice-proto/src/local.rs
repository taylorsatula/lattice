//! Local API objects (V2_SPEC §7).
//!
//! The local API is length-prefixed CBOR over a Unix socket. The length prefix
//! is 4 bytes, big-endian, and the frame may not exceed LOCAL_MAX_FRAME.
//! The spec does not fix the prefix width; 4 big-endian bytes is chosen here
//! and mirrored by any client implementation.
//!
//! Request  = {0: id, 1: op, 2: args}
//! Response = {0: id, 1: result} | {0: id, 2: error code}
//! Event    = {3: event, 2: data}
//!
//! Op codes, events and error codes are assigned by this module (the spec
//! names the operations but not their numbers); they are part of the wire
//! contract for all clients.

use crate::cbor::Value;
use crate::error::ProtoError;

pub const LOCAL_MAX_FRAME: usize = 64 * 1024;
pub const LOCAL_PREFIX_LEN: usize = 4;

pub const OP_HELLO: u64 = 1;
pub const OP_SEND: u64 = 2;
pub const OP_STATUS: u64 = 3;
pub const OP_FETCH: u64 = 4;
pub const OP_ACK: u64 = 5;
pub const OP_LOOKUP: u64 = 6;
// Admin ops (owner-only socket).
pub const OP_NODE: u64 = 101;
pub const OP_ROTATE: u64 = 102;
pub const OP_ABANDON: u64 = 103;
pub const OP_ROTATE_ENVELOPE: u64 = 104;
pub const OP_LINK: u64 = 105;
pub const OP_UNLINK: u64 = 106;
pub const OP_DRAIN: u64 = 107;

pub const ERR_UNKNOWN_OP: u64 = 1;
pub const ERR_BAD_ARGS: u64 = 2;
pub const ERR_AUTH: u64 = 3;
pub const ERR_NOT_FOUND: u64 = 4;
/// The requested operation failed (e.g. rotation failed). Distinct from
/// `ERR_INTERNAL`, which signals a daemon-side fault.
pub const ERR_FAILED: u64 = 6;
/// The daemon hit an internal error while handling the request.
pub const ERR_INTERNAL: u64 = 5;

/// Human-readable name for an error code, for diagnostics. Unknown codes
/// yield `"unknown"`.
pub fn err_name(code: u64) -> &'static str {
    match code {
        ERR_UNKNOWN_OP => "unknown_op",
        ERR_BAD_ARGS => "bad_args",
        ERR_AUTH => "auth",
        ERR_NOT_FOUND => "not_found",
        ERR_INTERNAL => "internal",
        ERR_FAILED => "failed",
        _ => "unknown",
    }
}

pub const EVENT_INBOX: u64 = 1;
pub const EVENT_STATUS: u64 = 2;

pub const ROUTE_DEFAULT: u64 = 0;
pub const ROUTE_WAYPOINT: u64 = 1;
pub const ROUTE_DIRECT: u64 = 2;

pub const MSG_STATUS_QUEUED: u64 = 1;
pub const MSG_STATUS_IN_TRANSIT: u64 = 2;
pub const MSG_STATUS_DELIVERED: u64 = 3;
pub const MSG_STATUS_FAILED: u64 = 4;
pub const MSG_STATUS_EXPIRED: u64 = 5;

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub id: u64,
    pub op: u64,
    pub args: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    Ok { id: u64, result: Value },
    Err { id: u64, code: u64 },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Event {
    pub event: u64,
    pub data: Value,
}

impl Request {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (Value::UInt(0), Value::UInt(self.id)),
            (Value::UInt(1), Value::UInt(self.op)),
            (Value::UInt(2), self.args.clone()),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[0, 1, 2])?;
        Ok(Self {
            id: v.req_uint(0)?,
            op: v.req_uint(1)?,
            args: v.req(2)?.clone(),
        })
    }
}

impl Response {
    pub fn to_value(&self) -> Value {
        match self {
            Response::Ok { id, result } => Value::map(vec![
                (Value::UInt(0), Value::UInt(*id)),
                (Value::UInt(1), result.clone()),
            ]),
            Response::Err { id, code } => Value::map(vec![
                (Value::UInt(0), Value::UInt(*id)),
                (Value::UInt(2), Value::UInt(*code)),
            ]),
        }
    }
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[0, 1, 2])?;
        let id = v.req_uint(0)?;
        match (v.get_key(1)?, v.get_key(2)?) {
            (Some(_), Some(_)) => Err(ProtoError::Invalid(
                "response carries both result and error",
            )),
            (Some(result), None) => Ok(Response::Ok {
                id,
                result: result.clone(),
            }),
            (None, Some(_)) => {
                let code = v.req_uint(2)?;
                Ok(Response::Err { id, code })
            }
            (None, None) => Err(ProtoError::Invalid(
                "response carries neither result nor error",
            )),
        }
    }
}

impl Event {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            (Value::UInt(3), Value::UInt(self.event)),
            (Value::UInt(2), self.data.clone()),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[2, 3])?;
        Ok(Self {
            event: v.req_uint(3)?,
            data: v.req(2)?.clone(),
        })
    }
}

/// Service names are 1-64 bytes of `[A-Za-z0-9._-]`. The spec does not
/// constrain them; this bound keeps names printable, path-safe and
/// comparable, and matches the daemon's config validation exactly.
fn valid_service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Decoded `send` arguments.
#[derive(Clone, Debug, PartialEq)]
pub struct SendArgs {
    pub to: lattice_types::Identifier,
    pub tsvc: String,
    pub tmbx: Vec<u8>,
    pub fmbx: Vec<u8>,
    pub body: Vec<u8>,
    pub exp: Option<u64>,
    pub priority: Option<u64>,
    pub route: Option<u64>,
}

impl SendArgs {
    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        Self::from_value_at(v, unix_now())
    }

    fn from_value_at(v: &Value, now: u64) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&[0, 1, 2, 3, 4, 5, 6, 7])?;
        let to = lattice_types::Identifier::from_bytes(
            v.req_bytes(0)?
                .try_into()
                .map_err(|_| ProtoError::WrongType(0, "32-byte id"))?,
        );
        let priority = match v.get_key(6)? {
            Some(p) => {
                let p = p.as_uint().ok_or(ProtoError::WrongType(6, "uint"))?;
                if p > 3 {
                    return Err(ProtoError::Invalid("priority above 3"));
                }
                Some(p)
            }
            None => None,
        };
        let route = match v.get_key(7)? {
            Some(r) => {
                let r = r.as_uint().ok_or(ProtoError::WrongType(7, "uint"))?;
                if r > ROUTE_DIRECT {
                    return Err(ProtoError::Invalid("unknown route"));
                }
                Some(r)
            }
            None => None,
        };
        let tsvc = v.req_text(1)?.to_string();
        if !valid_service_name(&tsvc) {
            return Err(ProtoError::Invalid(
                "tsvc must be 1-64 bytes of [A-Za-z0-9._-]",
            ));
        }
        let exp = match v.get_key(5)? {
            Some(e) => {
                let e = e.as_uint().ok_or(ProtoError::WrongType(5, "uint"))?;
                if e <= now {
                    return Err(ProtoError::Invalid("exp is not in the future"));
                }
                Some(e)
            }
            None => None,
        };
        Ok(Self {
            to,
            tsvc,
            tmbx: v.req_bytes(2)?.to_vec(),
            fmbx: v.req_bytes(3)?.to_vec(),
            body: v.req_bytes(4)?.to_vec(),
            exp,
            priority,
            route,
        })
    }
}

/// Frame the payload with the local-socket length prefix.
pub fn frame_local(payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if payload.len() > LOCAL_MAX_FRAME {
        return Err(ProtoError::TooBig(payload.len()));
    }
    let mut out = Vec::with_capacity(LOCAL_PREFIX_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Split one frame off the front of `buf`; returns (payload, bytes consumed).
pub fn deframe_local(buf: &[u8]) -> Result<Option<(&[u8], usize)>, ProtoError> {
    if buf.len() < LOCAL_PREFIX_LEN {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > LOCAL_MAX_FRAME {
        return Err(ProtoError::TooBig(len));
    }
    if buf.len() < LOCAL_PREFIX_LEN + len {
        return Ok(None);
    }
    Ok(Some((
        &buf[LOCAL_PREFIX_LEN..LOCAL_PREFIX_LEN + len],
        LOCAL_PREFIX_LEN + len,
    )))
}

/// The public `/status` object served on the WebSocket listener.
pub fn encode_status(up: bool, accepting: bool, versions: &[u64]) -> Vec<u8> {
    crate::cbor::encode(&Value::map(vec![
        (Value::UInt(0), Value::UInt(1)),
        (Value::UInt(1), Value::Bool(up)),
        (Value::UInt(2), Value::Bool(accepting)),
        (
            Value::UInt(3),
            Value::Array(versions.iter().map(|v| Value::UInt(*v)).collect()),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_args_value(tsvc: &str, exp: Option<u64>) -> Value {
        let mut pairs = vec![
            (Value::UInt(0), Value::Bytes(vec![1; 32])),
            (Value::UInt(1), Value::Text(tsvc.to_string())),
            (Value::UInt(2), Value::Bytes(b"inbox".to_vec())),
            (Value::UInt(3), Value::Bytes(b"me".to_vec())),
            (Value::UInt(4), Value::Bytes(b"payload".to_vec())),
        ];
        if let Some(e) = exp {
            pairs.push((Value::UInt(5), Value::UInt(e)));
        }
        Value::map(pairs)
    }

    #[test]
    fn send_args_accepts_valid_tsvc() {
        for name in ["a", "mira", "Mira", "backup-2", "a.b_c-d", &"x".repeat(64)] {
            let v = send_args_value(name, None);
            assert!(SendArgs::from_value(&v).is_ok(), "tsvc {name:?} rejected");
        }
    }

    #[test]
    fn send_args_rejects_bad_tsvc() {
        for name in [
            "",
            &"x".repeat(65),
            "has space",
            "slash/name",
            "semi;colon",
            "uni\u{00e9}",
        ] {
            let v = send_args_value(name, None);
            assert!(SendArgs::from_value(&v).is_err(), "tsvc {name:?} accepted");
        }
    }

    #[test]
    fn send_args_rejects_past_and_present_exp() {
        const NOW: u64 = 1_700_000_000;
        let past = send_args_value("mira", Some(NOW - 1));
        assert!(SendArgs::from_value_at(&past, NOW).is_err());
        let present = send_args_value("mira", Some(NOW));
        assert!(SendArgs::from_value_at(&present, NOW).is_err());
        let future = send_args_value("mira", Some(NOW + 1));
        assert!(SendArgs::from_value_at(&future, NOW).is_ok());
    }

    #[test]
    fn err_name_covers_all_codes() {
        assert_eq!(err_name(ERR_UNKNOWN_OP), "unknown_op");
        assert_eq!(err_name(ERR_BAD_ARGS), "bad_args");
        assert_eq!(err_name(ERR_AUTH), "auth");
        assert_eq!(err_name(ERR_NOT_FOUND), "not_found");
        assert_eq!(err_name(ERR_INTERNAL), "internal");
        assert_eq!(err_name(ERR_FAILED), "failed");
        assert_eq!(err_name(999), "unknown");
    }
}
