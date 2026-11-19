//! Error type for node construction and identity rotation.
//!
//! The sans-IO core reports per-event store failures through
//! [`crate::Diagnostic`]; this type covers the operations that cannot
//! proceed at all.

use lattice_store::StoreError;

/// Errors from [`crate::Node::new`], [`crate::Node::reload_identity`]
/// and [`crate::Identity::rotate`].
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Invalid node configuration (e.g. private mode without 1-3 gateways).
    #[error("invalid configuration: {0}")]
    Config(String),
    /// The identity's key event log ends in an abandonment; the identity is
    /// terminal and must not be used.
    #[error("identity is abandoned")]
    Abandoned,
    /// The supplied next key does not hash to the KEL head's commitment.
    #[error("next key does not match the committed pre-rotation hash")]
    NextKeyMismatch,
    /// The key event log is empty; cannot happen for a validated identity.
    #[error("key event log is empty")]
    EmptyKel,
    #[error(transparent)]
    Proto(#[from] lattice_proto::ProtoError),
    #[error(transparent)]
    Store(#[from] StoreError),
}
