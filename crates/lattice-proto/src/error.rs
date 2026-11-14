use thiserror::Error;

use crate::cbor::DecodeError;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("cbor: {0}")]
    Cbor(#[from] DecodeError),
    #[error("object exceeds size limit ({0} bytes)")]
    TooBig(usize),
    #[error("missing key {0}")]
    MissingKey(u64),
    #[error("wrong type for key {0}: expected {1}")]
    WrongType(u64, &'static str),
    #[error("unknown key {0}")]
    UnknownKey(u64),
    #[error("invalid value: {0}")]
    Invalid(&'static str),
    #[error("invalid signature")]
    BadSignature,
    #[error("invalid key event log: {0}")]
    BadKeyLog(&'static str),
    #[error("expired or too-far-horizon object")]
    Expired,
    #[error("crypto: {0}")]
    Crypto(String),
}
