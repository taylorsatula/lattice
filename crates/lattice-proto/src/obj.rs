//! Shared helpers for the object layer: bounded map reading and key sets.

use crate::cbor::{Value, decode};
use crate::error::ProtoError;

/// Decode bytes that must not exceed `limit`, then require the object.
pub(crate) fn decode_limited(bytes: &[u8], limit: usize) -> Result<Value, ProtoError> {
    if bytes.len() > limit {
        return Err(ProtoError::TooBig(bytes.len()));
    }
    Ok(decode(bytes)?)
}

impl Value {
    pub(crate) fn expect_map(&self) -> Result<&[(Value, Value)], ProtoError> {
        self.as_map().ok_or(ProtoError::Invalid("expected map"))
    }
    pub(crate) fn get_key(&self, key: u64) -> Result<Option<&Value>, ProtoError> {
        Ok(self
            .expect_map()?
            .iter()
            .find(|(k, _)| k.as_uint() == Some(key))
            .map(|(_, v)| v))
    }
    pub(crate) fn req(&self, key: u64) -> Result<&Value, ProtoError> {
        self.get_key(key)?.ok_or(ProtoError::MissingKey(key))
    }
    pub(crate) fn req_uint(&self, key: u64) -> Result<u64, ProtoError> {
        self.req(key)?
            .as_uint()
            .ok_or(ProtoError::WrongType(key, "uint"))
    }
    pub(crate) fn req_bool(&self, key: u64) -> Result<bool, ProtoError> {
        self.req(key)?
            .as_bool()
            .ok_or(ProtoError::WrongType(key, "bool"))
    }
    pub(crate) fn req_text(&self, key: u64) -> Result<&str, ProtoError> {
        self.req(key)?
            .as_text()
            .ok_or(ProtoError::WrongType(key, "text"))
    }
    pub(crate) fn req_bytes(&self, key: u64) -> Result<&[u8], ProtoError> {
        self.req(key)?
            .as_bytes()
            .ok_or(ProtoError::WrongType(key, "bytes"))
    }
    pub(crate) fn req_array(&self, key: u64) -> Result<&[Value], ProtoError> {
        self.req(key)?
            .as_array()
            .ok_or(ProtoError::WrongType(key, "array"))
    }
    pub(crate) fn deny_unknown_keys(&self, allowed: &[u64]) -> Result<(), ProtoError> {
        for (k, _) in self.expect_map()? {
            let n = k
                .as_uint()
                .ok_or(ProtoError::Invalid("non-integer map key"))?;
            if !allowed.contains(&n) {
                return Err(ProtoError::UnknownKey(n));
            }
        }
        Ok(())
    }
}

/// Exactly-N-bytes bstr field.
pub(crate) fn fixed_bytes<const N: usize>(v: &Value, key: u64) -> Result<[u8; N], ProtoError> {
    let b = v
        .req(key)?
        .as_bytes()
        .ok_or(ProtoError::WrongType(key, "bytes"))?;
    b.try_into()
        .map_err(|_| ProtoError::WrongType(key, "bytes of wrong length"))
}
