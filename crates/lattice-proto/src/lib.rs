//! Lattice wire objects.
//!
//! Deterministic CBOR codec, every protocol object's encode/decode and
//! validation, and the local-API surface. Decoding rejects non-canonical
//! encodings and anything beyond the spec's limits; no object is trusted
//! because of where it came from. Editing the wire format here means
//! editing `V2_SPEC.md` in the same change.

#![forbid(unsafe_code)]

pub mod cbor;
pub mod error;
pub mod frames;
pub mod kel;
pub mod local;
pub mod message;
mod obj;
pub mod record;

pub use cbor::{DecodeError, Value, decode, encode};
pub use error::ProtoError;
pub use frames::Frame;
pub use kel::{KelHead, KelRelation, KeyEvent, KeyEventKind, classify};
pub use message::{
    BuildParams, Envelope, GatewaySeal, Header, HopLayerPlain, Message, SealedLayer, WaypointSeal,
};
pub use record::{
    Endpoint, Mode, PeerRecord, Scope, compare_lww, is_equivocation, is_globally_routable,
    record_hash,
};

/// Largest message on the wire (bucket 3) and the derived message buckets.
pub const MESSAGE_BUCKETS: [usize; 3] = [2048 - 64, 8192 - 64, 32768 - 64];
pub const FRAME_BUCKETS: [usize; 3] = [2048, 8192, 32768];
pub const RECORD_MAX: usize = 3072;
/// Longest a message may live, from minting.
pub const MAX_MESSAGE_HORIZON: u64 = 14 * 24 * 3600;
/// Longest a record may live, from issue.
pub const MAX_RECORD_HORIZON: u64 = 30 * 24 * 3600;
/// Clock skew tolerance applied on top of horizons.
pub const CLOCK_SKEW: u64 = 6 * 3600;

/// Serde helpers for fixed-size byte arrays larger than serde's built-in 32.
pub mod serde_arrays {
    pub mod sig64 {
        use serde::{Deserialize, Deserializer, Serializer};
        pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(v)
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            let v = Vec::<u8>::deserialize(d)?;
            v.try_into()
                .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
        }
    }
}
