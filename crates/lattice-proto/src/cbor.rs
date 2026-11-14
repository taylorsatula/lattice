//! Deterministic CBOR (RFC 8949 §4.2), restricted to what Lattice uses.
//!
//! Encoding is fully deterministic: shortest-form integers and lengths,
//! definite lengths only, map keys sorted length-first then bytewise.
//! Decoding enforces the spec's limits: depth 8, at most 512 entries per
//! container, strings bounded by the input, and a total-value budget bounded
//! by the input length. Canonical-form violations are hard errors, never
//! silently accepted.

use std::fmt;

pub const MAX_DEPTH: usize = 8;
pub const MAX_CONTAINER_ITEMS: usize = 512;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    UInt(u64),
    /// Negative integer, stored as the raw n where value == -1 - n.
    NInt(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in canonical order (enforced on construction via `Value::map`).
    Map(Vec<(Value, Value)>),
    Bool(bool),
    /// CBOR null. Used only for absent optional fields (e.g. a message with no hop layer).
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof,
    UnsupportedMajor(u8),
    UnsupportedSimple(u8),
    NonCanonicalInt,
    BadUtf8,
    TooDeep,
    TooManyItems,
    TooManyValues,
    MapKeysNotCanonical,
    DuplicateMapKey,
    TrailingBytes,
    IndefiniteLength,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "truncated input"),
            Self::UnsupportedMajor(m) => write!(f, "unsupported major type {m}"),
            Self::UnsupportedSimple(v) => write!(f, "unsupported simple/float value {v}"),
            Self::NonCanonicalInt => write!(f, "integer not in shortest form"),
            Self::BadUtf8 => write!(f, "invalid UTF-8 in text string"),
            Self::TooDeep => write!(f, "nesting deeper than {MAX_DEPTH}"),
            Self::TooManyItems => write!(f, "container with more than {MAX_CONTAINER_ITEMS} items"),
            Self::TooManyValues => write!(f, "too many values for input size"),
            Self::MapKeysNotCanonical => write!(f, "map keys not in canonical order"),
            Self::DuplicateMapKey => write!(f, "duplicate map key"),
            Self::TrailingBytes => write!(f, "trailing bytes after top-level value"),
            Self::IndefiniteLength => write!(f, "indefinite-length item"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Value {
    pub fn map(pairs: Vec<(Value, Value)>) -> Value {
        let mut indexed: Vec<(Vec<u8>, Value, Value)> =
            pairs.into_iter().map(|(k, v)| (encode(&k), k, v)).collect();
        indexed.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
        Value::Map(indexed.into_iter().map(|(_, k, v)| (k, v)).collect())
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Value::UInt(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

// ---------- encoding ----------

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    encode_into(value, &mut out);
    out
}

fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    match arg {
        0..=23 => out.push(major << 5 | arg as u8),
        24..=0xff => out.extend_from_slice(&[major << 5 | 24, arg as u8]),
        0x100..=0xffff => {
            out.push(major << 5 | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major << 5 | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(major << 5 | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::UInt(n) => head(0, *n, out),
        Value::NInt(n) => head(1, *n, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        Value::Map(pairs) => {
            head(5, pairs.len() as u64, out);
            for (k, v) in pairs {
                encode_into(k, out);
                encode_into(v, out);
            }
        }
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => out.push(0xf6),
    }
}

// ---------- decoding ----------

pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut d = Decoder {
        input: bytes,
        pos: 0,
        values_left: bytes.len().max(1),
    };
    let v = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(v)
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    values_left: usize,
}

impl<'a> Decoder<'a> {
    fn byte(&mut self) -> Result<u8, DecodeError> {
        let b = *self.input.get(self.pos).ok_or(DecodeError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::UnexpectedEof)?;
        let slice = self
            .input
            .get(self.pos..end)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_arg(&mut self, info: u8) -> Result<u64, DecodeError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(DecodeError::NonCanonicalInt);
                }
                Ok(v)
            }
            25 => {
                let b = self.take(2)?;
                let v = u16::from_be_bytes([b[0], b[1]]) as u64;
                if v <= 0xff {
                    return Err(DecodeError::NonCanonicalInt);
                }
                Ok(v)
            }
            26 => {
                let b = self.take(4)?;
                let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if v <= 0xffff {
                    return Err(DecodeError::NonCanonicalInt);
                }
                Ok(v)
            }
            27 => {
                let b = self.take(8)?;
                let v = u64::from_be_bytes(b.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err(DecodeError::NonCanonicalInt);
                }
                Ok(v)
            }
            31 => Err(DecodeError::IndefiniteLength),
            _ => Err(DecodeError::UnsupportedMajor(info)), // 28..=30 reserved
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if self.values_left == 0 {
            return Err(DecodeError::TooManyValues);
        }
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooDeep);
        }
        self.values_left -= 1;
        let ib = self.byte()?;
        let major = ib >> 5;
        let info = ib & 0x1f;
        let value = match major {
            0 => Value::UInt(self.read_arg(info)?),
            1 => Value::NInt(self.read_arg(info)?),
            2 => {
                let n = self.read_arg(info)? as usize;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.read_arg(info)? as usize;
                let bytes = self.take(n)?;
                let text = std::str::from_utf8(bytes).map_err(|_| DecodeError::BadUtf8)?;
                Value::Text(text.to_string())
            }
            4 => {
                let n = self.read_arg(info)? as usize;
                if n > MAX_CONTAINER_ITEMS {
                    return Err(DecodeError::TooManyItems);
                }
                if n > self.input.len().saturating_sub(self.pos) {
                    // every element needs at least one byte
                    return Err(DecodeError::UnexpectedEof);
                }
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.read_arg(info)? as usize;
                if n > MAX_CONTAINER_ITEMS {
                    return Err(DecodeError::TooManyItems);
                }
                if n as u64 > self.input.len().saturating_sub(self.pos) as u64 {
                    // each key/value pair needs at least one byte; this is cheap insurance
                    return Err(DecodeError::UnexpectedEof);
                }
                let mut pairs = Vec::with_capacity(n);
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..n {
                    let key_start = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = self.input[key_start..self.pos].to_vec();
                    if let Some(prev) = &prev_key {
                        match prev
                            .len()
                            .cmp(&key_bytes.len())
                            .then_with(|| prev.as_slice().cmp(&key_bytes))
                        {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => return Err(DecodeError::DuplicateMapKey),
                            std::cmp::Ordering::Greater => {
                                return Err(DecodeError::MapKeysNotCanonical);
                            }
                        }
                    }
                    prev_key = Some(key_bytes);
                    let val = self.value(depth + 1)?;
                    pairs.push((key, val));
                }
                Value::Map(pairs)
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(DecodeError::UnsupportedSimple(ib)),
            },
            other => return Err(DecodeError::UnsupportedMajor(other)),
        };
        Ok(value)
    }
}
