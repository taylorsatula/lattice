//! Lattice cryptography primitives and key-event handling.
//!
//! Ed25519 signatures, X25519 and X-Wing (X25519 + ML-KEM-768) key establishment,
//! ChaCha20-Poly1305, BLAKE3, OS randomness, constant-time comparison, and the
//! key event log (inception, rotation, abandonment) with identifier derivation.
//! No I/O; callers supply randomness where the API does not take it from the OS.
//!

#![forbid(unsafe_code)]
