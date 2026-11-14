//! Lattice protocol objects.
//!
//! Deterministic CBOR encode/decode under the decoding limits in V2_SPEC.md,
//! every wire and storage object's construction and validation, and the signature
//! preimage rules. Unknown keys and over-limit encodings are rejected, never
//! skipped. No I/O; pure encode/validate.
//!

#![forbid(unsafe_code)]
