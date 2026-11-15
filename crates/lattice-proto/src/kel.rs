//! Key events and key event logs (V2_SPEC §2).
//!
//! A key event log (KEL) is the append-only chain of inception and rotation
//! events for one identity. The inception event's unsigned encoding hashes
//! to the identifier; every later event's `prev` binds it to the exact hash
//! of its predecessor, so the chain is self-verifying and prefix-comparable.
//!
//! The commitment of an event is `BLAKE3(encode(event without sig))` — the
//! same rule used for the identifier — and it is what `prev` refers to.

use lattice_crypto::{hash, sign, verify};
use lattice_types::{Commitment, Identifier, Signature, SigningPublicKey, SigningSeed};

use crate::cbor::{Value, encode};
use crate::error::ProtoError;
use crate::obj::fixed_bytes;

pub const PROTOCOL_VERSION: u64 = 1;
pub const EVENT_INCEPTION: u64 = 1;
pub const EVENT_ROTATION: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEventKind {
    Inception,
    Rotation,
}

impl KeyEventKind {
    fn from_u64(v: u64) -> Result<Self, ProtoError> {
        match v {
            EVENT_INCEPTION => Ok(Self::Inception),
            EVENT_ROTATION => Ok(Self::Rotation),
            _ => Err(ProtoError::Invalid("unknown key event kind")),
        }
    }
    fn as_u64(self) -> u64 {
        match self {
            Self::Inception => EVENT_INCEPTION,
            Self::Rotation => EVENT_ROTATION,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEvent {
    pub kind: KeyEventKind,
    pub seq: u64,
    /// Hash (commitment) of the previous event. Absent in inception.
    pub prev: Option<Commitment>,
    /// The signing key this event establishes.
    pub key: SigningPublicKey,
    /// BLAKE3 of the next signing key. Absent means abandonment (rotation only).
    pub next: Option<Commitment>,
    pub sig: Signature,
}

const KEY_EVENT_KEYS: [u64; 7] = [0, 1, 2, 3, 4, 5, 6];

impl KeyEvent {
    /// The event without its signature, as a CBOR value.
    pub fn unsigned_value(&self) -> Value {
        let mut pairs = vec![
            (Value::UInt(0), Value::UInt(PROTOCOL_VERSION)),
            (Value::UInt(1), Value::UInt(self.kind.as_u64())),
            (Value::UInt(2), Value::UInt(self.seq)),
        ];
        if let Some(prev) = &self.prev {
            pairs.push((Value::UInt(3), Value::Bytes(prev.to_vec())));
        }
        pairs.push((Value::UInt(4), Value::Bytes(self.key.to_vec())));
        if let Some(next) = &self.next {
            pairs.push((Value::UInt(5), Value::Bytes(next.to_vec())));
        }
        Value::map(pairs)
    }

    pub fn to_value(&self) -> Value {
        let mut pairs = match self.unsigned_value() {
            Value::Map(m) => m,
            _ => unreachable!(),
        };
        pairs.push((Value::UInt(6), Value::Bytes(self.sig.to_vec())));
        Value::map(pairs)
    }

    /// BLAKE3 of the unsigned encoding; what `prev` refers to.
    pub fn commitment(&self) -> Commitment {
        Commitment::from_bytes(hash(&encode(&self.unsigned_value())).into_bytes())
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    pub fn from_value(v: &Value) -> Result<Self, ProtoError> {
        v.deny_unknown_keys(&KEY_EVENT_KEYS)?;
        if v.req_uint(0)? != PROTOCOL_VERSION {
            return Err(ProtoError::Invalid("unsupported protocol version"));
        }
        let kind = KeyEventKind::from_u64(v.req_uint(1)?)?;
        let seq = v.req_uint(2)?;
        let prev = match v.get_key(3)? {
            None => None,
            Some(_) => Some(Commitment::from_bytes(fixed_bytes(v, 3)?)),
        };
        let key = SigningPublicKey::from_bytes(fixed_bytes(v, 4)?);
        let next = match v.get_key(5)? {
            None => None,
            Some(_) => Some(Commitment::from_bytes(fixed_bytes(v, 5)?)),
        };
        let sig = Signature::from_bytes(fixed_bytes(v, 6)?);
        Ok(Self {
            kind,
            seq,
            prev,
            key,
            next,
            sig,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::from_value(&crate::cbor::decode(bytes)?)
    }

    /// Signature check for this single event against its own key.
    pub fn verify_signature(&self) -> bool {
        verify(&self.key, &encode(&self.unsigned_value()), &self.sig)
    }

    /// Create and sign an inception event.
    pub fn inception(signing_seed: &SigningSeed, next_key_hash: Commitment) -> Self {
        Self::build(
            KeyEventKind::Inception,
            0,
            None,
            signing_seed_public(signing_seed),
            Some(next_key_hash),
            signing_seed,
        )
    }

    /// Create and sign a rotation event against `prev`.
    pub fn rotation(
        prev: &KeyEvent,
        new_signing_seed: &SigningSeed,
        next_key_hash: Option<Commitment>,
    ) -> Self {
        Self::build(
            KeyEventKind::Rotation,
            prev.seq + 1,
            Some(prev.commitment()),
            public_key_of(new_signing_seed),
            next_key_hash,
            new_signing_seed,
        )
    }

    fn build(
        kind: KeyEventKind,
        seq: u64,
        prev: Option<Commitment>,
        key: SigningPublicKey,
        next: Option<Commitment>,
        signing_seed: &SigningSeed,
    ) -> Self {
        let mut ev = KeyEvent {
            kind,
            seq,
            prev,
            key,
            next,
            sig: Signature::from_bytes([0u8; 64]),
        };
        ev.sig = sign(signing_seed, &encode(&ev.unsigned_value()));
        ev
    }
}

fn signing_seed_public(seed: &SigningSeed) -> SigningPublicKey {
    public_key_of(seed)
}

fn public_key_of(seed: &SigningSeed) -> SigningPublicKey {
    lattice_crypto::public_key(seed)
}

/// The point a KEL comparison converges on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KelHead {
    pub seq: u64,
    pub commitment: Commitment,
    pub abandoned: bool,
    pub current_key: SigningPublicKey,
}

impl KeyEvent {
    /// Validate a complete KEL (inception through `events.last()`).
    ///
    /// Enforces: inception shape, chain linkage, per-event signature, that
    /// every rotation's key matches the previous commitment to the next key,
    /// and that nothing follows an abandonment.
    pub fn validate_chain(events: &[KeyEvent]) -> Result<KelHead, ProtoError> {
        let first = events.first().ok_or(ProtoError::BadKeyLog("empty log"))?;
        if first.kind != KeyEventKind::Inception {
            return Err(ProtoError::BadKeyLog("first event is not an inception"));
        }
        if first.seq != 0 || first.prev.is_some() {
            return Err(ProtoError::BadKeyLog(
                "inception must have seq 0 and no prev",
            ));
        }
        if !first.verify_signature() {
            return Err(ProtoError::BadSignature);
        }
        for i in 1..events.len() {
            let prev = &events[i - 1];
            let ev = &events[i];
            if prev.next.is_none() {
                return Err(ProtoError::BadKeyLog("event follows an abandonment"));
            }
            if ev.kind != KeyEventKind::Rotation {
                return Err(ProtoError::BadKeyLog("non-initial event is not a rotation"));
            }
            if ev.seq != prev.seq + 1 {
                return Err(ProtoError::BadKeyLog("sequence gap"));
            }
            if ev.prev != Some(prev.commitment()) {
                return Err(ProtoError::BadKeyLog("prev does not match predecessor"));
            }
            if Some(Commitment::from_bytes(hash(ev.key.as_ref()).into_bytes())) != prev.next {
                return Err(ProtoError::BadKeyLog(
                    "rotated key does not match the committed next-key hash",
                ));
            }
            if !ev.verify_signature() {
                return Err(ProtoError::BadSignature);
            }
        }
        let Some(last) = events.last() else {
            return Err(ProtoError::BadKeyLog("empty log"));
        };
        Ok(KelHead {
            seq: last.seq,
            commitment: last.commitment(),
            abandoned: last.next.is_none(),
            current_key: last.key,
        })
    }
}

/// A key event log that has passed full chain validation.
///
/// Constructed only by [`ValidatedKel::validate`] (or [`decode_kel`]); the
/// events are private, so the "this chain was verified" fact travels with
/// the value instead of being a convention enforced by callers. Cloning is
/// cheap enough for the records that embed a KEL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedKel {
    events: Vec<KeyEvent>,
    head: KelHead,
    id: Identifier,
}

impl ValidatedKel {
    /// Validate a complete KEL (inception through the last event) and
    /// return it in its validated form.
    pub fn validate(events: Vec<KeyEvent>) -> Result<Self, ProtoError> {
        let head = KeyEvent::validate_chain(&events)?;
        let id = identifier(&events)?;
        Ok(Self { events, head, id })
    }

    /// The validated events, in order.
    pub fn events(&self) -> &[KeyEvent] {
        &self.events
    }

    /// Number of events in the chain. Always at least one.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Always false: a validated KEL holds at least the inception event.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The head of the validated chain.
    pub fn head(&self) -> KelHead {
        self.head
    }

    /// The identifier of this chain (hash of the inception event).
    pub fn identifier(&self) -> Identifier {
        self.id
    }

    /// The current signing key: the key established by the head event.
    pub fn current_key(&self) -> SigningPublicKey {
        self.head.current_key
    }

    /// True if the chain ends in an abandonment (a rotation with no
    /// next-key commitment).
    pub fn is_abandoned(&self) -> bool {
        self.head.abandoned
    }

    /// Append `event`, re-validating the whole chain. Used by rotation;
    /// rotations are rare, so re-validating is simpler and safer than
    /// maintaining a second, incremental check that could drift from
    /// [`KeyEvent::validate_chain`].
    pub fn append(&mut self, event: KeyEvent) -> Result<(), ProtoError> {
        let mut events = self.events.clone();
        events.push(event);
        *self = Self::validate(events)?;
        Ok(())
    }

    /// Consume the validated log and return the raw events.
    pub fn into_events(self) -> Vec<KeyEvent> {
        self.events
    }
}

impl std::ops::Deref for ValidatedKel {
    type Target = [KeyEvent];
    fn deref(&self) -> &[KeyEvent] {
        &self.events
    }
}

impl From<ValidatedKel> for Vec<KeyEvent> {
    fn from(kel: ValidatedKel) -> Self {
        kel.events
    }
}

/// How a candidate chain relates to a locally known head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KelRelation {
    /// Candidate extends the known head; caller should adopt it.
    Extends,
    /// Candidate is identical to the known head.
    Same,
    /// Candidate ends before the known head with the same hash at the known
    /// position; it is stale and carries nothing new.
    Behind,
    /// Candidate contradicts the known head (different event at a held position).
    Divergent,
}

/// Compare a validated candidate chain against a known head.
///
/// Only the boundary commitment is held, so a candidate that ends before the
/// known seq cannot be distinguished from a prefix of what we held; such
/// candidates are reported as `Behind` (rejected either way). Full-chain
/// fork detection requires retaining the chain or its commitments.
///
/// `commitments` is the per-event commitment list of the candidate chain.
pub fn classify(
    known_seq: u64,
    known_commitment: &Commitment,
    candidate: &[KeyEvent],
) -> KelRelation {
    let commitments: Vec<Commitment> = candidate.iter().map(|e| e.commitment()).collect();
    // We only hold the head commitment, not the full known chain: only the
    // boundary position can be compared directly. A candidate that at least
    // reaches our known seq must commit to the same event there.
    if (known_seq as usize) < commitments.len() {
        return if commitments[known_seq as usize] == *known_commitment {
            if commitments.len() as u64 == known_seq + 1 {
                KelRelation::Same
            } else {
                KelRelation::Extends
            }
        } else {
            KelRelation::Divergent
        };
    }
    // Candidate ends at or before our known seq.
    KelRelation::Behind
}

/// The identifier a KEL belongs to: hash of the inception event's unsigned encoding.
pub fn identifier(events: &[KeyEvent]) -> Result<Identifier, ProtoError> {
    let first = events.first().ok_or(ProtoError::BadKeyLog("empty log"))?;
    if first.kind != KeyEventKind::Inception {
        return Err(ProtoError::BadKeyLog("first event is not an inception"));
    }
    Ok(Identifier::from_bytes(
        hash(&encode(&first.unsigned_value())).into_bytes(),
    ))
}

/// Encode a KEL as the concatenated event encodings preceded by a u32 count.
/// This is a private serialization for on-disk storage, not a wire format.
pub fn encode_kel(events: &[KeyEvent]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(events.len() as u32).to_le_bytes());
    for e in events {
        let bytes = e.encode();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    out
}

/// Decode a KEL written by [`encode_kel`].
///
/// The returned log has passed full chain validation; there is no way to
/// obtain an unvalidated `ValidatedKel` from the wire.
pub fn decode_kel(bytes: &[u8]) -> Result<ValidatedKel, ProtoError> {
    fn take<'a>(buf: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], ProtoError> {
        if *at + n > buf.len() {
            return Err(ProtoError::BadKeyLog("truncated KEL file"));
        }
        let out = &buf[*at..*at + n];
        *at += n;
        Ok(out)
    }
    let mut at = 0usize;
    let count = u32::from_le_bytes(
        take(bytes, &mut at, 4)?
            .try_into()
            .map_err(|_| ProtoError::BadKeyLog("truncated KEL file"))?,
    ) as usize;
    let mut events = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let len = u32::from_le_bytes(
            take(bytes, &mut at, 4)?
                .try_into()
                .map_err(|_| ProtoError::BadKeyLog("truncated KEL file"))?,
        ) as usize;
        let raw = take(bytes, &mut at, len)?;
        events.push(KeyEvent::from_bytes(raw)?);
    }
    ValidatedKel::validate(events)
}
