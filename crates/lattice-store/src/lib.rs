//! Lattice storage.
//!
//! The Store trait used by lattice-core, an in-memory implementation for the
//! simulator, and a redb implementation for the daemon. Schema version 1 with
//! ordered migrations; startup refuses a newer schema.
//!

#![forbid(unsafe_code)]
