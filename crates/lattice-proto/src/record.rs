//! Peer records (V2_SPEC §3): build, sign, validate, order.

use std::net::{IpAddr, Ipv4Addr};

use lattice_crypto::{hash, sign, verify};
use lattice_types::{
    ChannelPublicKey, ChannelSeed, Commitment, Hash32, Identifier, Signature, SigningPublicKey,
    SigningSeed, XWingPublicKey,
};

use lattice_crypto::RECORD_CONTEXT;

use crate::cbor::{Value, encode};
use crate::error::ProtoError;
use crate::kel::{KelHead, ValidatedKel};
use crate::obj::{decode_limited, fixed_bytes};
use crate::{CLOCK_SKEW, MAX_RECORD_HORIZON, RECORD_MAX};

pub const KIND_RECORD: u64 = 10;
pub const SCOPE_WAN: u64 = 0;
pub const SCOPE_HIVE: u64 = 1;
pub const MODE_PUBLIC: u64 = 0;
pub const MODE_PRIVATE: u64 = 1;

/// Maximum links a record may carry. Enforced on build and on validate.
pub const MAX_LINKS: usize = 32;
const MAX_GATEWAYS: usize = 3;
const MAX_ENDPOINTS: usize = 16;
/// Most ids a public record may name in `serves` (spec §3).
pub const MAX_SERVES: usize = 16;

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
    /// Wire encoding: 0 = public, 1 = private.
    pub fn as_u64(self) -> u64 {
        match self {
            Mode::Public => MODE_PUBLIC,
            Mode::Private => MODE_PRIVATE,
        }
    }
    /// Inverse of [`Mode::as_u64`]; rejects values other than 0 and 1.
    pub fn from_u64(v: u64) -> Result<Self, ProtoError> {
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
    pub id: Identifier,
    pub scope: Scope,
    pub seq: u64,
    pub exp: u64,
    /// sn of the KEL head this record cites.
    pub khs: u64,
    /// Event hash of the KEL head this record cites.
    pub khc: Commitment,
    /// Current signing key; must equal the KEL head event's `k`.
    pub k: SigningPublicKey,
    pub channel_key: ChannelPublicKey,
    pub envelope_key: XWingPublicKey,
    pub mode: Mode,
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<Identifier>,
    pub gateways: Vec<Identifier>,
    pub capabilities: u64,
    /// Private ids this gateway serves; public records only, ≤ 16 distinct.
    pub serves: Vec<Identifier>,
    pub sig: Signature,
    /// Signature by the channel key over the same preimage as `sig`.
    /// Proves the channel-key holder endorsed this record; a record claiming
    /// someone else's channel key cannot be produced without that key.
    pub channel_sig: Signature,
}

/// Parameters for [`PeerRecord::build`].
///
/// `seq` is assigned by the builder as `max(prev_seq + 1, now)` (spec §3),
/// so callers pass the previously published seq and the current time, not a
/// seq of their choosing.
pub struct RecordParams {
    /// The validated KEL this record cites. The record's `khs`/`khc`/`k`
    /// and its `id` are derived from the KEL head; the KEL itself is not
    /// embedded in the record.
    pub kel: ValidatedKel,
    /// The seq of the caller's previously published record (0 if none).
    pub prev_seq: u64,
    /// Current time, used for the `max(prev_seq + 1, now)` seq assignment.
    pub now: u64,
    pub exp: u64,
    pub channel_key: ChannelPublicKey,
    /// The channel private key, used to sign the record (cross-signature).
    pub channel_seed: ChannelSeed,
    pub envelope_key: XWingPublicKey,
    pub mode: Mode,
    pub scope: Scope,
    pub endpoints: Vec<Endpoint>,
    /// Links to advertise. The caller passes them in preference order
    /// (anchors and longest-lived links first); [`PeerRecord::build`]
    /// drops from the tail to stay within the link and size caps.
    pub links: Vec<Identifier>,
    pub gateways: Vec<Identifier>,
    pub capabilities: u64,
    /// Private ids this gateway serves (public records only, ≤ 16 distinct).
    pub serves: Vec<Identifier>,
}

const RECORD_KEYS: [u64; 19] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
];

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
            (Value::UInt(6), Value::UInt(self.khs)),
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
        pairs.push((Value::UInt(16), Value::Bytes(self.khc.to_vec())));
        pairs.push((Value::UInt(17), Value::Bytes(self.k.to_vec())));
        if !self.serves.is_empty() {
            pairs.push((
                Value::UInt(18),
                Value::Array(
                    self.serves
                        .iter()
                        .map(|s| Value::Bytes(s.to_vec()))
                        .collect(),
                ),
            ));
        }
        Value::map(pairs)
    }

    fn to_value(&self) -> Value {
        let Value::Map(mut pairs) = self.unsigned_value() else {
            unreachable!("unsigned_value always returns a map")
        };
        pairs.push((Value::UInt(14), Value::Bytes(self.sig.to_vec())));
        pairs.push((Value::UInt(15), Value::Bytes(self.channel_sig.to_vec())));
        Value::map(pairs)
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    /// Build and sign a record. Caller supplies fresh seq and expiry.
    ///
    /// The KEL is validated before anything is signed; a record is never
    /// produced from an unverifiable chain.
    ///
    /// The record is guaranteed to fit the wire caps: at most
    /// [`MAX_LINKS`] links, and at most [`RECORD_MAX`] bytes encoded.
    /// Links are dropped from the tail of the caller's preference order
    /// until the record fits; if it still does not fit with no links at
    /// all, the build is refused rather than emitting a record peers
    /// would reject at parse time.
    pub fn build(
        params: RecordParams,
        signing_seed: &SigningSeed,
    ) -> Result<PeerRecord, ProtoError> {
        let RecordParams {
            kel,
            prev_seq,
            now,
            exp,
            channel_key,
            channel_seed,
            envelope_key,
            mode,
            scope,
            endpoints,
            links,
            gateways,
            capabilities,
            serves,
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
                if !serves.is_empty() {
                    return Err(ProtoError::Invalid("private record carries serves"));
                }
            }
        }
        validate_serves(&serves, mode)?;
        for ep in &endpoints {
            validate_endpoint(ep, scope)?;
        }
        // The signing seed must match the KEL head's key, or every peer will
        // reject the record at validation.
        if lattice_crypto::public_key(signing_seed) != kel.head().current_key {
            return Err(ProtoError::Invalid(
                "signing seed does not match the KEL head key",
            ));
        }
        // Drop links from the tail of the caller's preference order to
        // stay within the link cap; the size check below drops more if
        // the record still does not fit.
        let mut links = links;
        if links.len() > MAX_LINKS {
            links.truncate(MAX_LINKS);
        }
        let seq = prev_seq.saturating_add(1).max(now);
        let head = kel.head();
        let id = kel.identifier();
        let mut rec = PeerRecord {
            id,
            scope,
            seq,
            exp,
            khs: head.seq,
            khc: head.commitment,
            k: head.current_key,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            serves,
            sig: Signature::from_bytes([0; 64]),
            channel_sig: Signature::from_bytes([0; 64]),
        };
        loop {
            let preimage =
                lattice_crypto::signing_preimage(RECORD_CONTEXT, &encode(&rec.unsigned_value()));
            rec.sig = sign(signing_seed, &preimage);
            rec.channel_sig = sign(&channel_seed, &preimage);
            if rec.encode().len() <= RECORD_MAX {
                return Ok(rec);
            }
            if rec.links.is_empty() {
                return Err(ProtoError::Invalid("record exceeds RECORD_MAX"));
            }
            rec.links.pop();
        }
    }
}

/// A record decoded from the wire, before any validation.
///
/// Carries no trust: every field is attacker-controlled until
/// [`ParsedRecord::validate`] succeeds. Exists so callers can learn the
/// record's claimed id and KEL head (e.g. to look up the KEL to validate
/// against) without paying for full validation, then validate exactly once.
pub struct ParsedRecord {
    id: Identifier,
    scope: Scope,
    seq: u64,
    exp: u64,
    khs: u64,
    khc: Commitment,
    k: SigningPublicKey,
    channel_key: ChannelPublicKey,
    envelope_key: XWingPublicKey,
    mode: Mode,
    endpoints: Vec<Endpoint>,
    links: Vec<Identifier>,
    gateways: Vec<Identifier>,
    capabilities: u64,
    serves: Vec<Identifier>,
    sig: Signature,
    channel_sig: Signature,
}

/// A record that passed full validation: structure, expiry, the KEL head it
/// cites (matched against the caller-supplied KEL), identifier binding, and
/// both signatures.
///
/// Validation is *not* self-contained: the caller must supply the KEL the
/// record cites (see [`ParsedRecord::validate`]). The caller — the core —
/// holds KEL state and is responsible for monotonicity: it stores only the
/// newest KEL it has validated per identifier, so a record citing an older
/// head fails the `khs`/`khc` check, and a record citing a newer head cannot
/// be validated until that KEL arrives.
///
/// Derefs to [`PeerRecord`]; call [`ValidatedRecord::into_inner`] to
/// consume the wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRecord {
    record: PeerRecord,
    head: KelHead,
}

impl ValidatedRecord {
    /// Consume the wrapper and return the inner record.
    pub fn into_inner(self) -> PeerRecord {
        self.record
    }

    /// The KEL head the record cites (and was validated against).
    pub fn kel_head(&self) -> KelHead {
        self.head
    }
}

impl std::ops::Deref for ValidatedRecord {
    type Target = PeerRecord;

    fn deref(&self) -> &PeerRecord {
        &self.record
    }
}

impl ParsedRecord {
    /// The record's claimed identifier. Not yet verified against the KEL;
    /// only meaningful for lookups, never for trust decisions.
    pub fn id(&self) -> Identifier {
        self.id
    }

    /// The record's seq. Only meaningful for ordering; never for trust
    /// decisions.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The record's expiry (unix seconds).
    pub fn exp(&self) -> u64 {
        self.exp
    }

    /// The record's advertised links, in the order they were built.
    pub fn links(&self) -> &[Identifier] {
        &self.links
    }

    /// The KEL head sn the record cites. Only meaningful for deciding
    /// whether to fetch a newer KEL; never for trust decisions.
    pub fn khs(&self) -> u64 {
        self.khs
    }

    /// The KEL head event hash the record cites. Only meaningful for
    /// deciding whether to fetch a newer KEL; never for trust decisions.
    pub fn khc(&self) -> Commitment {
        self.khc
    }
}

impl PeerRecord {
    /// Parse a record from the wire without validating it.
    ///
    /// The result proves nothing about the bytes; call
    /// [`ParsedRecord::validate`] before trusting any field.
    pub fn parse(bytes: &[u8]) -> Result<ParsedRecord, ProtoError> {
        let value = decode_limited(bytes, RECORD_MAX)?;
        value.deny_unknown_keys(&RECORD_KEYS)?;
        if value.req_uint(0)? != crate::kel::PROTOCOL_VERSION {
            return Err(ProtoError::Invalid("unsupported protocol version"));
        }
        if value.req_uint(1)? != KIND_RECORD {
            return Err(ProtoError::Invalid("not a peer record"));
        }
        let id = Identifier::from_bytes(fixed_bytes::<32>(&value, 2)?);
        let scope = Scope::from_u64(value.req_uint(3)?)?;
        let seq = value.req_uint(4)?;
        let exp = value.req_uint(5)?;
        let khs = value.req_uint(6)?;
        let channel_key = ChannelPublicKey::from_bytes(fixed_bytes(&value, 7)?);
        let envelope_key = XWingPublicKey::from_bytes(fixed_bytes(&value, 8)?);
        let mode = Mode::from_u64(value.req_uint(9)?)?;
        let capabilities = value.req_uint(13)?;
        let sig = Signature::from_bytes(fixed_bytes::<64>(&value, 14)?);
        let channel_sig = Signature::from_bytes(fixed_bytes::<64>(&value, 15)?);
        let khc = Commitment::from_bytes(fixed_bytes(&value, 16)?);
        let k = SigningPublicKey::from_bytes(fixed_bytes(&value, 17)?);

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
                        .map(Identifier::from_bytes)
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
                        .map(Identifier::from_bytes)
                        .ok_or(ProtoError::WrongType(12, "32-byte id"))
                })
                .collect::<Result<_, _>>()?,
        };
        let serves = match value.get_key(18)? {
            None => Vec::new(),
            Some(v) => v
                .as_array()
                .ok_or(ProtoError::WrongType(18, "array"))?
                .iter()
                .map(|x| {
                    x.as_bytes()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .map(Identifier::from_bytes)
                        .ok_or(ProtoError::WrongType(18, "32-byte id"))
                })
                .collect::<Result<_, _>>()?,
        };

        Ok(ParsedRecord {
            id,
            scope,
            seq,
            exp,
            khs,
            khc,
            k,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            serves,
            sig,
            channel_sig,
        })
    }

    /// Parse and fully validate a record from the wire against `kel`.
    ///
    /// `now` is injected so the same code runs in the simulator and the
    /// daemon. `kel` is the KEL the caller holds for the record's
    /// identifier; the record is accepted only if it cites exactly this
    /// KEL's head. A record whose KEL head is an abandonment is rejected
    /// (spec §3: the KEL object is the only carrier of an abandonment).
    pub fn from_bytes(
        bytes: &[u8],
        now: u64,
        kel: &ValidatedKel,
    ) -> Result<ValidatedRecord, ProtoError> {
        Self::parse(bytes)?.validate(Some(now), kel)
    }

    /// Parse and validate a record without checking the expiry horizon.
    /// Retention sweeps need to read records whose `exp` has already passed;
    /// every other check (structure, KEL binding, signatures) is identical.
    pub fn from_bytes_unchecked_time(
        bytes: &[u8],
        kel: &ValidatedKel,
    ) -> Result<ValidatedRecord, ProtoError> {
        Self::parse(bytes)?.validate(None, kel)
    }
}

impl ParsedRecord {
    /// Validate the parsed record against the caller-supplied KEL: expiry
    /// horizon, structure, the KEL head binding (`khs`/`khc`/`k` must match
    /// the supplied KEL's head), identifier binding, and both signatures.
    ///
    /// The caller is responsible for holding the right KEL: it must be the
    /// newest KEL the caller has validated for this identifier. A record
    /// citing any other head is rejected here, which is what makes a stale
    /// or forked record unacceptable without further checks.
    pub fn validate(
        self,
        now: Option<u64>,
        kel: &ValidatedKel,
    ) -> Result<ValidatedRecord, ProtoError> {
        let Self {
            id,
            scope,
            seq,
            exp,
            khs,
            khc,
            k,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            serves,
            sig,
            channel_sig,
        } = self;

        // Structural validation.
        if let Some(now) = now {
            if exp <= now {
                return Err(ProtoError::Expired);
            }
            if exp > now + MAX_RECORD_HORIZON + CLOCK_SKEW {
                return Err(ProtoError::Invalid("record expiry beyond the horizon"));
            }
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
                if !serves.is_empty() {
                    return Err(ProtoError::Invalid("private record carries serves"));
                }
            }
        }
        validate_serves(&serves, mode)?;
        for ep in &endpoints {
            validate_endpoint(ep, scope)?;
        }

        // KEL binding. The caller holds the KEL; the record must cite its
        // exact head, and the head must not be an abandonment.
        let head = kel.head();
        if kel.identifier() != id {
            return Err(ProtoError::BadKeyLog(
                "identifier does not match inception event",
            ));
        }
        if khs != head.seq {
            return Err(ProtoError::BadKeyLog(
                "record cites a different KEL head sn than the held KEL",
            ));
        }
        if khc != head.commitment {
            return Err(ProtoError::BadKeyLog(
                "record cites a different KEL head event than the held KEL",
            ));
        }
        if k != head.current_key {
            return Err(ProtoError::BadKeyLog(
                "record key does not match the KEL head event's key",
            ));
        }
        if head.is_abandoned() {
            // The KEL object is the only carrier of an abandonment; a record
            // citing an abandoned head is not accepted (spec §3).
            return Err(ProtoError::BadKeyLog("KEL head is an abandonment"));
        }

        let record = PeerRecord {
            id,
            scope,
            seq,
            exp,
            khs,
            khc,
            k,
            channel_key,
            envelope_key,
            mode,
            endpoints,
            links,
            gateways,
            capabilities,
            serves,
            sig,
            channel_sig,
        };
        let preimage =
            lattice_crypto::signing_preimage(RECORD_CONTEXT, &encode(&record.unsigned_value()));
        if !verify(&record.k, &preimage, &record.sig) {
            return Err(ProtoError::BadSignature);
        }
        // The channel key must endorse the record too: without this, anyone
        // could publish a record claiming someone else's channel key.
        if !verify(&channel_key, &preimage, &record.channel_sig) {
            return Err(ProtoError::BadSignature);
        }
        Ok(ValidatedRecord { record, head })
    }
}

impl PeerRecord {
    /// The current signing key (the KEL head event's key).
    pub fn current_signing_key(&self) -> SigningPublicKey {
        self.k
    }
}

/// Validate the `serves` field: at most [`MAX_SERVES`] distinct ids, and
/// only on public records.
fn validate_serves(serves: &[Identifier], mode: Mode) -> Result<(), ProtoError> {
    if serves.len() > MAX_SERVES {
        return Err(ProtoError::Invalid("too many serves entries"));
    }
    if mode == Mode::Private && !serves.is_empty() {
        return Err(ProtoError::Invalid("private record carries serves"));
    }
    let mut seen = std::collections::HashSet::with_capacity(serves.len());
    for id in serves {
        if !seen.insert(*id) {
            return Err(ProtoError::Invalid("duplicate serves entry"));
        }
    }
    Ok(())
}

pub fn record_hash(bytes: &[u8]) -> Hash32 {
    hash(bytes)
}

/// Equivocation: two records, same (id, scope, seq), different bytes.
/// Only validated records can be passed, so both signatures are known good.
#[must_use]
pub fn is_equivocation(
    a: &ValidatedRecord,
    a_bytes: &[u8],
    b: &ValidatedRecord,
    b_bytes: &[u8],
) -> bool {
    a.id == b.id && a.scope == b.scope && a.seq == b.seq && a_bytes != b_bytes
}

/// The total order on records for the same (id, scope) (spec §3):
/// `(khs, seq, record hash)`. A record supersedes another when its `khs` is
/// higher, or its `khs` is equal and its `seq` is higher, or both are equal
/// and its hash (BLAKE3 of its exact encoding) is lower. Returns `Greater`
/// when `a` supersedes `b`.
///
/// Hashing is done on the encoded bytes, so this is O(record size); callers
/// on hot paths should compare `(khs, seq)` first and only fall back to
/// this when both are equal.
#[must_use]
pub fn record_order(a: &PeerRecord, b: &PeerRecord) -> std::cmp::Ordering {
    record_order_parts(
        a.khs,
        a.seq,
        &record_hash(&a.encode()),
        b.khs,
        b.seq,
        &record_hash(&b.encode()),
    )
}

/// The order, over precomputed parts. See [`record_order`].
#[must_use]
pub fn record_order_parts(
    a_khs: u64,
    a_seq: u64,
    a_hash: &Hash32,
    b_khs: u64,
    b_seq: u64,
    b_hash: &Hash32,
) -> std::cmp::Ordering {
    a_khs
        .cmp(&b_khs)
        .then(a_seq.cmp(&b_seq))
        // Lower hash wins at equal (khs, seq): invert the comparison.
        .then_with(|| b_hash.cmp(a_hash))
}

fn validate_endpoint(ep: &Endpoint, scope: Scope) -> Result<(), ProtoError> {
    // ws:// is the default; wss:// is an opaque outer TLS wrapper (no
    // certificate trust decisions; Noise authenticates the peer).
    let rest = ep
        .url
        .strip_prefix("ws://")
        .or_else(|| ep.url.strip_prefix("wss://"))
        .ok_or(ProtoError::Invalid("endpoint scheme must be ws or wss"))?;
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    if hostport.is_empty() || hostport.contains('@') {
        return Err(ProtoError::Invalid(
            "endpoint has no host or carries userinfo",
        ));
    }
    let host = parse_host_port(hostport)?;
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

/// Split `host[:port]` or `[v6][:port]` into the bare host, validating the
/// port. A bracketed host must be a valid IPv6 literal; a bare host with
/// colons is not accepted (IPv6 literals must be bracketed).
fn parse_host_port(hostport: &str) -> Result<&str, ProtoError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or(ProtoError::Invalid("unterminated [v6] host"))?;
        let host = &rest[..end];
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| ProtoError::Invalid("bad bracketed IPv6 host"))?;
        match rest[end + 1..].strip_prefix(':') {
            Some(port) => check_port(port)?,
            None if rest[end + 1..].is_empty() => {}
            None => return Err(ProtoError::Invalid("trailing data after [v6] host")),
        }
        return Ok(host);
    }
    match hostport.rsplit_once(':') {
        Some((h, port)) => {
            if h.is_empty() {
                return Err(ProtoError::Invalid("bad endpoint port"));
            }
            check_port(port)?;
            Ok(h)
        }
        None => Ok(hostport),
    }
}

fn check_port(port: &str) -> Result<(), ProtoError> {
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(ProtoError::Invalid("bad endpoint port")),
        Ok(_) => Ok(()),
    }
}

#[must_use]
pub fn is_globally_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_v4_global(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_v4_global(mapped);
            }
            if is_ipv4_embedding(&v6) {
                return false;
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated, RFC 3879)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // 100::/64 discard-only (RFC 6666)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // 2001:10::/28 ORCHID (RFC 4843)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0020) // 2001:20::/28 ORCHIDv2 (RFC 7343)
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation 2001:db8::/32
        }
    }
}

/// IPv6 ranges that embed an IPv4 address. A WAN endpoint naming one of
/// these is either a deprecated transition mechanism or a tunnel whose
/// embedded destination we cannot vet, so fail closed.
#[must_use]
fn is_ipv4_embedding(v6: &std::net::Ipv6Addr) -> bool {
    let s = v6.segments();
    // ::/96 — deprecated IPv4-compatible addresses (::a.b.c.d)
    if s[..6].iter().all(|&seg| seg == 0) {
        return true;
    }
    // 64:ff9b::/96 — NAT64 well-known prefix
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|&seg| seg == 0) {
        return true;
    }
    // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215); embeds an IPv4 address
    // and is only valid inside a translation domain.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        return true;
    }
    // ::ffff:0:0:0/96 — IPv4-translated addresses (RFC 2765, SIIT)
    if s[..4].iter().all(|&seg| seg == 0) && s[4] == 0xffff && s[5] == 0 {
        return true;
    }
    // 2002::/16 — 6to4
    if s[0] == 0x2002 {
        return true;
    }
    // 2001::/32 — Teredo
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return true;
    }
    false
}

#[must_use]
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
            | [192, 88, 99, _]
            | [192, 175, 48, _]
            | [192, 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
            | [224..=255, ..]
    );
    !private
}

#[cfg(test)]
mod tests {
    use super::is_globally_routable;

    #[test]
    fn nat64_local_use_prefix_is_not_globally_routable() {
        // 64:ff9b:1::/48 — local-use NAT64 (RFC 8215)
        assert!(!is_globally_routable("64:ff9b:1::".parse().unwrap()));
        assert!(!is_globally_routable("64:ff9b:1:ffff::1".parse().unwrap()));
    }

    #[test]
    fn discard_only_prefix_is_not_globally_routable() {
        // 100::/64 — discard-only (RFC 6666)
        assert!(!is_globally_routable("100::".parse().unwrap()));
        assert!(!is_globally_routable(
            "100::ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn orchid_prefix_is_not_globally_routable() {
        // 2001:10::/28 — ORCHID (RFC 4843)
        assert!(!is_globally_routable("2001:10::".parse().unwrap()));
        assert!(!is_globally_routable("2001:1f:ffff::".parse().unwrap()));
    }

    #[test]
    fn orchidv2_prefix_is_not_globally_routable() {
        // 2001:20::/28 — ORCHIDv2 (RFC 7343)
        assert!(!is_globally_routable("2001:20::".parse().unwrap()));
        assert!(!is_globally_routable("2001:2f:ffff::".parse().unwrap()));
    }

    #[test]
    fn site_local_prefix_is_not_globally_routable() {
        // fec0::/10 — site-local (deprecated, RFC 3879)
        assert!(!is_globally_routable("fec0::".parse().unwrap()));
        assert!(!is_globally_routable("feff::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_translated_prefix_is_not_globally_routable() {
        // ::ffff:0:0:0/96 — IPv4-translated (RFC 2765, SIIT)
        assert!(!is_globally_routable("::ffff:0:0:0".parse().unwrap()));
        assert!(!is_globally_routable("::ffff:0:1.2.3.4".parse().unwrap()));
    }
}
