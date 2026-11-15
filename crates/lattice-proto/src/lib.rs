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
pub use message::Message;

/// Largest message on the wire (bucket 3) and the derived message buckets.
pub const MESSAGE_BUCKETS: [usize; 3] = [2048 - 64, 8192 - 64, 32768 - 64];
pub const RECORD_MAX: usize = 3200;
/// Longest a message may live, from minting.
pub const MAX_MESSAGE_HORIZON: u64 = 14 * 24 * 3600;
/// Longest a record may live, from issue.
pub const MAX_RECORD_HORIZON: u64 = 30 * 24 * 3600;
/// Clock skew tolerance applied on top of horizons.
pub const CLOCK_SKEW: u64 = 6 * 3600;
