//! CBOR codecs for the redb row types (outbound, custody, inbox, status).
//!
//! Rows are `lattice_proto::cbor` values: maps with integer keys, matching
//! how the rest of the codebase encodes objects. Decoding is strict —
//! unknown keys are rejected and every field is range-checked by type — and
//! every field round-trips. Encoding is deterministic (shortest-form
//! integers, canonical key order) because `Value::map` sorts keys.
//!
//! Custody rows store the message with its wire padding stripped, plus the
//! bucket index, when the message is a bucket-sized, zero-padded wire
//! message (which is what every message that reaches custody is, since it
//! passed `Message::parse`). The full padded message is re-assembled on
//! read, so in-memory `CustodyEntry` values and all downstream consumers see
//! exactly what they saw before. A message that is not a bucket-sized
//! padded wire message is stored verbatim with no bucket key.

use lattice_proto::MESSAGE_BUCKETS;
use lattice_proto::cbor::{self, Value};
use lattice_proto::error::ProtoError;
use lattice_proto::local::MessageStatus;
use lattice_proto::message::Envelope;
use lattice_types::{DeliveryId, Identifier, LegId, MessageId};

use crate::{
    CustodyEntry, Exclusion, InboxEntry, OutboundMessage, OutboundState, SavedPeer, StoreError,
};

fn codec<E: Into<ProtoError>>(context: &'static str) -> impl FnOnce(E) -> StoreError {
    move |e| StoreError::Codec {
        context,
        source: Box::new(e.into()),
    }
}

fn deny_unknown_keys(v: &Value, allowed: &[u64]) -> Result<(), ProtoError> {
    for (k, _) in v.as_map().ok_or(ProtoError::Invalid("expected map"))? {
        let n = k
            .as_uint()
            .ok_or(ProtoError::Invalid("non-integer map key"))?;
        if !allowed.contains(&n) {
            return Err(ProtoError::UnknownKey(n));
        }
    }
    Ok(())
}

fn req(v: &Value, key: u64) -> Result<&Value, ProtoError> {
    cbor::map_get(v, key).ok_or(ProtoError::MissingKey(key))
}

fn req_uint(v: &Value, key: u64) -> Result<u64, ProtoError> {
    req(v, key)?
        .as_uint()
        .ok_or(ProtoError::WrongType(key, "uint"))
}

fn opt_uint(v: &Value, key: u64) -> Result<Option<u64>, ProtoError> {
    match cbor::map_get(v, key) {
        None | Some(Value::Null) => Ok(None),
        Some(x) => Ok(Some(x.as_uint().ok_or(ProtoError::WrongType(key, "uint"))?)),
    }
}

fn req_bytes(v: &Value, key: u64) -> Result<&[u8], ProtoError> {
    req(v, key)?
        .as_bytes()
        .ok_or(ProtoError::WrongType(key, "bytes"))
}

fn req_text(v: &Value, key: u64) -> Result<&str, ProtoError> {
    req(v, key)?
        .as_text()
        .ok_or(ProtoError::WrongType(key, "text"))
}

fn req_array(v: &Value, key: u64) -> Result<&[Value], ProtoError> {
    req(v, key)?
        .as_array()
        .ok_or(ProtoError::WrongType(key, "array"))
}

fn fixed<const N: usize>(v: &Value, key: u64) -> Result<[u8; N], ProtoError> {
    req_bytes(v, key)?
        .try_into()
        .map_err(|_| ProtoError::WrongType(key, "bytes of wrong length"))
}

fn u8_field(v: &Value, key: u64) -> Result<u8, ProtoError> {
    u8::try_from(req_uint(v, key)?).map_err(|_| ProtoError::WrongType(key, "u8"))
}

fn u32_field(v: &Value, key: u64) -> Result<u32, ProtoError> {
    u32::try_from(req_uint(v, key)?).map_err(|_| ProtoError::WrongType(key, "u32"))
}

fn bytes_value(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}

fn exclusion_to_value(e: &Exclusion) -> Value {
    Value::map(vec![
        (Value::UInt(0), Value::UInt(e.link)),
        (Value::UInt(1), Value::UInt(e.until)),
    ])
}

fn exclusion_from_value(v: &Value) -> Result<Exclusion, ProtoError> {
    deny_unknown_keys(v, &[0, 1])?;
    Ok(Exclusion {
        link: req_uint(v, 0)?,
        until: req_uint(v, 1)?,
    })
}

fn state_to_value(s: OutboundState) -> Value {
    Value::UInt(match s {
        OutboundState::Queued => 0,
        OutboundState::InFlight => 1,
        OutboundState::Delivered => 2,
        OutboundState::Failed => 3,
        OutboundState::Expired => 4,
    })
}

fn state_from_value(v: &Value) -> Result<OutboundState, ProtoError> {
    match v.as_uint() {
        Some(0) => Ok(OutboundState::Queued),
        Some(1) => Ok(OutboundState::InFlight),
        Some(2) => Ok(OutboundState::Delivered),
        Some(3) => Ok(OutboundState::Failed),
        Some(4) => Ok(OutboundState::Expired),
        _ => Err(ProtoError::Invalid("unknown outbound state")),
    }
}

pub(crate) fn encode_outbound(m: &OutboundMessage) -> Vec<u8> {
    cbor::encode(&Value::map(vec![
        (Value::UInt(0), bytes_value(m.mid.as_bytes())),
        (Value::UInt(1), bytes_value(m.recipient.as_bytes())),
        (Value::UInt(2), m.envelope.to_value()),
        (Value::UInt(3), Value::UInt(u64::from(m.priority))),
        (Value::UInt(4), Value::UInt(m.exp)),
        (Value::UInt(5), state_to_value(m.state)),
        (
            Value::UInt(6),
            Value::Array(
                m.waypoints_tried
                    .iter()
                    .map(|w| bytes_value(w.as_bytes()))
                    .collect(),
            ),
        ),
        (
            Value::UInt(7),
            m.receipt_deadline.map_or(Value::Null, Value::UInt),
        ),
        (Value::UInt(8), Value::UInt(u64::from(m.attempts))),
        (Value::UInt(9), Value::UInt(m.next_attempt)),
        (Value::UInt(10), Value::UInt(u64::from(m.route))),
    ]))
}

pub(crate) fn decode_outbound(bytes: &[u8]) -> Result<OutboundMessage, StoreError> {
    const CTX: &str = "decode outbound message";
    let v = cbor::decode(bytes).map_err(codec(CTX))?;
    outbound_from_value(&v).map_err(codec(CTX))
}

fn outbound_from_value(v: &Value) -> Result<OutboundMessage, ProtoError> {
    deny_unknown_keys(v, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
    let waypoints = req_array(v, 6)?
        .iter()
        .map(|w| {
            w.as_bytes()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .map(Identifier::from_bytes)
                .ok_or(ProtoError::WrongType(6, "32-byte id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OutboundMessage {
        mid: MessageId::from_bytes(fixed(v, 0)?),
        recipient: Identifier::from_bytes(fixed(v, 1)?),
        envelope: Envelope::from_value(req(v, 2)?)?,
        priority: u8_field(v, 3)?,
        exp: req_uint(v, 4)?,
        state: state_from_value(req(v, 5)?)?,
        waypoints_tried: waypoints,
        receipt_deadline: opt_uint(v, 7)?,
        attempts: u32_field(v, 8)?,
        next_attempt: req_uint(v, 9)?,
        route: u8_field(v, 10)?,
    })
}

/// If `message` is a bucket-sized, zero-padded wire message, return the
/// encoding of its 3-element `[header, hop_layer, envelope]` array and the
/// bucket index. Otherwise return `None` (the caller stores it verbatim).
fn strip_padding(message: &[u8]) -> Option<(Vec<u8>, u8)> {
    let bucket = MESSAGE_BUCKETS.iter().position(|&b| b == message.len())? as u8;
    let value = cbor::decode(message).ok()?;
    let arr = value.as_array()?;
    if arr.len() != 4 {
        return None;
    }
    let padding = arr[3].as_bytes()?;
    if !padding.iter().all(|&b| b == 0) {
        return None;
    }
    let unpadded = cbor::encode(&Value::Array(arr[..3].to_vec()));
    // Only strip when re-padding reproduces the input byte-for-byte.
    if repad(&unpadded, bucket).ok().as_deref() != Some(message) {
        return None;
    }
    Some((unpadded, bucket))
}

/// Re-assemble a bucket-sized wire message from the unpadded 3-element
/// encoding and the bucket index stored alongside it.
fn repad(unpadded: &[u8], bucket: u8) -> Result<Vec<u8>, ProtoError> {
    let bucket_size = *MESSAGE_BUCKETS
        .get(bucket as usize)
        .ok_or(ProtoError::Invalid("custody bucket index out of range"))?;
    let value = cbor::decode(unpadded)?;
    let arr = value.as_array().ok_or(ProtoError::Invalid(
        "unpadded custody message is not an array",
    ))?;
    if arr.len() != 3 {
        return Err(ProtoError::Invalid(
            "unpadded custody message must have 3 elements",
        ));
    }
    // The 3- and 4-element array headers are both one byte, so the final
    // length is unpadded.len() + head_len(pad) + pad.
    for (head_len, min_pad, max_pad) in [
        (1usize, 0i64, 23i64),
        (2, 24, 0xff),
        (3, 0x100, 0xffff),
        (5, 0x1_0000, 0xffff_ffff),
    ] {
        let pad = bucket_size as i64 - unpadded.len() as i64 - head_len as i64;
        if (min_pad..=max_pad).contains(&pad) {
            let mut elems = arr.to_vec();
            elems.push(Value::Bytes(vec![0u8; pad as usize]));
            return Ok(cbor::encode(&Value::Array(elems)));
        }
    }
    Err(ProtoError::Invalid(
        "unpadded custody message does not fit its bucket",
    ))
}

pub(crate) fn encode_custody(entry: &CustodyEntry) -> Vec<u8> {
    let (message, bucket) = match strip_padding(&entry.message) {
        Some((unpadded, bucket)) => (unpadded, Some(bucket)),
        None => (entry.message.clone(), None),
    };
    let mut pairs = vec![
        (Value::UInt(0), bytes_value(entry.leg.as_bytes())),
        (Value::UInt(1), Value::Bytes(message)),
        (Value::UInt(2), Value::UInt(entry.upstream)),
        (Value::UInt(3), bytes_value(entry.destination.as_bytes())),
        (Value::UInt(4), Value::UInt(u64::from(entry.class))),
        (Value::UInt(5), Value::UInt(entry.exp)),
        (
            Value::UInt(6),
            Value::Array(entry.excluded.iter().map(exclusion_to_value).collect()),
        ),
    ];
    if let Some(b) = bucket {
        pairs.push((Value::UInt(7), Value::UInt(u64::from(b))));
    }
    cbor::encode(&Value::map(pairs))
}

pub(crate) fn decode_custody(bytes: &[u8]) -> Result<CustodyEntry, StoreError> {
    const CTX: &str = "decode custody entry";
    let v = cbor::decode(bytes).map_err(codec(CTX))?;
    custody_from_value(&v).map_err(codec(CTX))
}

fn custody_from_value(v: &Value) -> Result<CustodyEntry, ProtoError> {
    deny_unknown_keys(v, &[0, 1, 2, 3, 4, 5, 6, 7])?;
    let message = req_bytes(v, 1)?.to_vec();
    let message = match opt_uint(v, 7)? {
        Some(b) => {
            let bucket = u8::try_from(b)
                .map_err(|_| ProtoError::Invalid("custody bucket index out of range"))?;
            repad(&message, bucket)?
        }
        None => message,
    };
    let excluded = req_array(v, 6)?
        .iter()
        .map(exclusion_from_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CustodyEntry {
        leg: LegId::from_bytes(fixed(v, 0)?),
        message,
        upstream: req_uint(v, 2)?,
        destination: Identifier::from_bytes(fixed(v, 3)?),
        class: u8_field(v, 4)?,
        exp: req_uint(v, 5)?,
        excluded,
    })
}

pub(crate) fn encode_inbox(entry: &InboxEntry) -> Vec<u8> {
    cbor::encode(&Value::map(vec![
        (Value::UInt(0), bytes_value(entry.delivery_id.as_bytes())),
        (Value::UInt(1), bytes_value(entry.mid.as_bytes())),
        (Value::UInt(2), bytes_value(entry.from.as_bytes())),
        (Value::UInt(3), Value::Text(entry.fsvc.clone())),
        (Value::UInt(4), Value::Bytes(entry.fmbx.clone())),
        (Value::UInt(5), Value::Text(entry.tsvc.clone())),
        (Value::UInt(6), Value::Bytes(entry.tmbx.clone())),
        (Value::UInt(7), Value::Bytes(entry.body.clone())),
        (Value::UInt(8), Value::UInt(entry.received)),
    ]))
}

pub(crate) fn decode_inbox(bytes: &[u8]) -> Result<InboxEntry, StoreError> {
    const CTX: &str = "decode inbox entry";
    let v = cbor::decode(bytes).map_err(codec(CTX))?;
    inbox_from_value(&v).map_err(codec(CTX))
}

fn inbox_from_value(v: &Value) -> Result<InboxEntry, ProtoError> {
    deny_unknown_keys(v, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
    Ok(InboxEntry {
        delivery_id: DeliveryId::from_bytes(fixed(v, 0)?),
        mid: MessageId::from_bytes(fixed(v, 1)?),
        from: Identifier::from_bytes(fixed(v, 2)?),
        fsvc: req_text(v, 3)?.to_string(),
        fmbx: req_bytes(v, 4)?.to_vec(),
        tsvc: req_text(v, 5)?.to_string(),
        tmbx: req_bytes(v, 6)?.to_vec(),
        body: req_bytes(v, 7)?.to_vec(),
        received: req_uint(v, 8)?,
    })
}

pub(crate) fn encode_status(status: &MessageStatus, set_at: u64) -> Vec<u8> {
    cbor::encode(&Value::map(vec![
        (Value::UInt(0), Value::UInt(status.status)),
        (
            Value::UInt(1),
            status.detail.map_or(Value::Null, Value::UInt),
        ),
        (Value::UInt(2), Value::UInt(set_at)),
    ]))
}

/// Decode a status row. Returns the status and the unix time (seconds) the
/// row was written; rows written before the timestamp was added decode
/// with `set_at` 0, which the retention sweep treats as ancient.
pub(crate) fn decode_status(bytes: &[u8]) -> Result<(MessageStatus, u64), StoreError> {
    const CTX: &str = "decode status";
    let v = cbor::decode(bytes).map_err(codec(CTX))?;
    status_from_value(&v).map_err(codec(CTX))
}

fn status_from_value(v: &Value) -> Result<(MessageStatus, u64), ProtoError> {
    deny_unknown_keys(v, &[0, 1, 2])?;
    Ok((
        MessageStatus {
            status: req_uint(v, 0)?,
            detail: opt_uint(v, 1)?,
        },
        opt_uint(v, 2)?.unwrap_or(0),
    ))
}

pub(crate) fn encode_saved_peer(peer: &SavedPeer) -> Vec<u8> {
    cbor::encode(&Value::map(vec![
        (Value::UInt(0), Value::Text(peer.endpoint.clone())),
        (
            Value::UInt(1),
            Value::Array(
                peer.ips
                    .iter()
                    .map(|ip| Value::Text(ip.to_string()))
                    .collect(),
            ),
        ),
        (Value::UInt(2), Value::UInt(peer.saved_at)),
        (Value::UInt(3), Value::Bool(peer.anchor)),
        (Value::UInt(4), bytes_value(peer.channel_key.as_bytes())),
    ]))
}

pub(crate) fn decode_saved_peer(
    bytes: &[u8],
    id: lattice_types::Identifier,
    scope: lattice_proto::record::Scope,
) -> Result<SavedPeer, StoreError> {
    const CTX: &str = "decode saved peer";
    let v = cbor::decode(bytes).map_err(codec(CTX))?;
    saved_peer_from_value(&v, id, scope).map_err(codec(CTX))
}

fn saved_peer_from_value(
    v: &Value,
    id: lattice_types::Identifier,
    scope: lattice_proto::record::Scope,
) -> Result<SavedPeer, ProtoError> {
    deny_unknown_keys(v, &[0, 1, 2, 3, 4])?;
    let ips = req_array(v, 1)?
        .iter()
        .map(|ip| {
            ip.as_text()
                .ok_or(ProtoError::WrongType(1, "text"))?
                .parse::<std::net::IpAddr>()
                .map_err(|_| ProtoError::Invalid("bad ip in saved peer"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let anchor = match cbor::map_get(v, 3) {
        Some(Value::Bool(b)) => *b,
        _ => return Err(ProtoError::WrongType(3, "bool")),
    };
    Ok(SavedPeer {
        id,
        scope,
        endpoint: req_text(v, 0)?.to_string(),
        ips,
        saved_at: req_uint(v, 2)?,
        anchor,
        channel_key: lattice_types::ChannelPublicKey::from_bytes(fixed(v, 4)?),
    })
}
