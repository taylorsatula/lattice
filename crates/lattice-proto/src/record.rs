//! Peer records (V2_SPEC §3): build, sign, validate, order.

use std::net::{IpAddr, Ipv4Addr};

use lattice_crypto::{hash, sign, verify};
use lattice_types::{
    ChannelPublicKey, ChannelSeed, Commitment, Hash32, Identifier, Signature, SigningPublicKey,
    SigningSeed, XWingPublicKey,
};

use crate::cbor::{Value, encode};
use crate::error::ProtoError;
use crate::kel::{KelRelation, KeyEvent, ValidatedKel, classify};
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
    /// The record's key event log, validated at decode (or build) time.
    pub kel: ValidatedKel,
    pub channel_key: ChannelPublicKey,
    pub envelope_key: XWingPublicKey,
    pub mode: Mode,
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<Identifier>,
    pub gateways: Vec<Identifier>,
    pub capabilities: u64,
    pub sig: Signature,
    /// Signature by the channel key over the same preimage as `sig`.
    /// Proves the channel-key holder endorsed this record; a record claiming
    /// someone else's channel key cannot be produced without that key.
    pub channel_sig: Signature,
}

/// Parameters for [`PeerRecord::build`].
///
/// `kel` accepts anything that converts into the chain's events: a
/// `Vec<KeyEvent>` (validated here before signing) or an already-validated
/// [`ValidatedKel`].
pub struct RecordParams<K = Vec<KeyEvent>> {
    pub kel: K,
    pub seq: u64,
    pub exp: u64,
    pub channel_key: ChannelPublicKey,
    /// The channel private key, used to sign the record (cross-signature).
    pub channel_seed: ChannelSeed,
    pub envelope_key: XWingPublicKey,
    pub mode: Mode,
    pub scope: Scope,
    pub endpoints: Vec<Endpoint>,
    pub links: Vec<Identifier>,
    pub gateways: Vec<Identifier>,
    pub capabilities: u64,
}

const RECORD_KEYS: [u64; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

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
    pub fn build<K: Into<Vec<KeyEvent>>>(
        params: RecordParams<K>,
        signing_seed: &SigningSeed,
    ) -> Result<PeerRecord, ProtoError> {
        let RecordParams {
            kel,
            seq,
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
        for ep in &endpoints {
            validate_endpoint(ep, scope)?;
        }
        let kel = ValidatedKel::validate(kel.into())?;
        let id = kel.identifier();
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
            sig: Signature::from_bytes([0; 64]),
            channel_sig: Signature::from_bytes([0; 64]),
        };
        let preimage = encode(&rec.unsigned_value());
        rec.sig = sign(signing_seed, &preimage);
        rec.channel_sig = sign(&channel_seed, &preimage);
        Ok(rec)
    }
}

/// The KEL head this node already holds for an identity, passed to
/// validation so a record whose chain is behind or divergent can be
/// rejected.
///
/// `abandoned` is set once the head's event ends the identity (a rotation
/// with no next-key commitment). No record for the identifier is accepted
/// afterwards: the KEL cannot extend past an abandonment, so anything
/// presented later is either stale or forged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownHead {
    pub seq: u64,
    pub commitment: Commitment,
    pub abandoned: bool,
}

/// A record decoded from the wire, before any validation.
///
/// Carries no trust: every field is attacker-controlled until
/// [`ParsedRecord::validate`] succeeds. Exists so callers can learn the
/// record's claimed id (e.g. to look up a known KEL head) without paying
/// for full validation, then validate exactly once.
pub struct ParsedRecord {
    id: Identifier,
    scope: Scope,
    seq: u64,
    exp: u64,
    kel: Vec<KeyEvent>,
    channel_key: ChannelPublicKey,
    envelope_key: XWingPublicKey,
    mode: Mode,
    endpoints: Vec<Endpoint>,
    links: Vec<Identifier>,
    gateways: Vec<Identifier>,
    capabilities: u64,
    sig: Signature,
    channel_sig: Signature,
}

/// A record that passed full validation: structure, KEL chain, identifier
/// binding, known-head monotonicity, and both signatures.
///
/// Derefs to [`PeerRecord`]; call [`ValidatedRecord::into_inner`] to
/// consume the wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRecord(PeerRecord);

impl ValidatedRecord {
    /// Consume the wrapper and return the inner record.
    pub fn into_inner(self) -> PeerRecord {
        self.0
    }
}

impl std::ops::Deref for ValidatedRecord {
    type Target = PeerRecord;

    fn deref(&self) -> &PeerRecord {
        &self.0
    }
}

impl ParsedRecord {
    /// The record's claimed identifier. Not yet verified against the KEL;
    /// only meaningful for lookups, never for trust decisions.
    pub fn id(&self) -> Identifier {
        self.id
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
        let kel: Vec<KeyEvent> = value
            .req_array(6)?
            .iter()
            .map(KeyEvent::from_value)
            .collect::<Result<_, _>>()?;
        let channel_key = ChannelPublicKey::from_bytes(fixed_bytes(&value, 7)?);
        let envelope_key = XWingPublicKey::from_bytes(fixed_bytes(&value, 8)?);
        let mode = Mode::from_u64(value.req_uint(9)?)?;
        let capabilities = value.req_uint(13)?;
        let sig = Signature::from_bytes(fixed_bytes::<64>(&value, 14)?);
        let channel_sig = Signature::from_bytes(fixed_bytes::<64>(&value, 15)?);

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

        Ok(ParsedRecord {
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
            channel_sig,
        })
    }

    /// Parse and fully validate a record from the wire.
    ///
    /// `now` is injected so the same code runs in the simulator and the
    /// daemon. `known_head`, when supplied, is the head this node already
    /// holds for the record's identifier; a record whose KEL is behind or
    /// divergent is rejected, as is any record once the known head is
    /// abandoned. A record whose KEL ends in an abandonment validates as a
    /// tombstone; see [`PeerRecord::is_tombstone`].
    pub fn from_bytes(
        bytes: &[u8],
        now: u64,
        known_head: Option<KnownHead>,
    ) -> Result<ValidatedRecord, ProtoError> {
        Self::parse(bytes)?.validate(Some(now), known_head)
    }

    /// Parse and validate a record without checking the expiry horizon.
    /// Retention sweeps need to read records whose `exp` has already passed;
    /// every other check (structure, KEL chain, signatures) is identical.
    pub fn from_bytes_unchecked_time(
        bytes: &[u8],
        known_head: Option<KnownHead>,
    ) -> Result<ValidatedRecord, ProtoError> {
        Self::parse(bytes)?.validate(None, known_head)
    }
}

impl ParsedRecord {
    /// Validate the parsed record: expiry horizon, structure, KEL chain,
    /// identifier binding, known-head monotonicity, and both signatures.
    /// A record whose KEL ends in an abandonment is valid (a tombstone);
    /// it is never usable for routing, delivery, waypoint selection or
    /// link binding — see [`PeerRecord::is_tombstone`].
    pub fn validate(
        self,
        now: Option<u64>,
        known_head: Option<KnownHead>,
    ) -> Result<ValidatedRecord, ProtoError> {
        let Self {
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
            }
        }
        for ep in &endpoints {
            validate_endpoint(ep, scope)?;
        }

        // KEL validation and monotonicity. A KEL ending in an abandonment
        // is valid: the record is a tombstone (see `PeerRecord::is_tombstone`)
        // and callers decide how to treat it. What is never valid is a
        // record for an identifier whose known head is already abandoned.
        let kel = ValidatedKel::validate(kel)?;
        if kel.identifier() != id {
            return Err(ProtoError::BadKeyLog(
                "identifier does not match inception event",
            ));
        }
        if let Some(known) = known_head {
            if known.abandoned {
                return Err(ProtoError::BadKeyLog("identity abandoned"));
            }
            match classify(known.seq, &known.commitment, kel.events()) {
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
            channel_sig,
        };
        let preimage = encode(&record.unsigned_value());
        if !verify(&record.kel.current_key(), &preimage, &record.sig) {
            return Err(ProtoError::BadSignature);
        }
        // The channel key must endorse the record too: without this, anyone
        // could publish a record claiming someone else's channel key.
        if !verify(&channel_key, &preimage, &record.channel_sig) {
            return Err(ProtoError::BadSignature);
        }
        Ok(ValidatedRecord(record))
    }
}

impl PeerRecord {
    /// The current signing key (head of the validated KEL).
    pub fn current_signing_key(&self) -> SigningPublicKey {
        self.kel.current_key()
    }

    /// True if this record's KEL ends in an abandonment. A tombstone is a
    /// full, validly signed record; it exists so the abandonment can
    /// propagate. It is never used for routing, delivery, waypoint
    /// selection or link binding, it replaces the identity's stored
    /// records, and it is retained for the KEL-head retention period like
    /// any record.
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.kel.is_abandoned()
    }
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

/// Last-writer-wins comparison: higher seq wins; equal seq, lower hash wins.
/// Returns Ordering of `a` vs `b` (Greater means a wins).
#[must_use]
pub fn compare_lww(a_bytes: &[u8], a_seq: u64, b_bytes: &[u8], b_seq: u64) -> std::cmp::Ordering {
    match a_seq.cmp(&b_seq) {
        // Equal seq: the record with the lower BLAKE3 hash wins.
        std::cmp::Ordering::Equal => record_hash(b_bytes).cmp(&record_hash(a_bytes)),
        other => other,
    }
}

fn validate_endpoint(ep: &Endpoint, scope: Scope) -> Result<(), ProtoError> {
    let rest = ep.url.strip_prefix("ws://").ok_or(ProtoError::Invalid(
        "endpoint scheme must be ws (Noise provides confidentiality; TLS is not used)",
    ))?;
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
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)) // documentation 2001:db8::/32
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
