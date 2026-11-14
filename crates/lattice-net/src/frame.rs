//! Wire framing: every post-handshake frame rides one WebSocket binary
//! message whose payload is the CBOR array `[frame, padding]`, padded to
//! exactly one bucket. Sizes outside the buckets are rejected before parsing.

use lattice_proto::cbor::{self, Value};

pub const FRAME_BUCKETS: [usize; 3] = [2048, 8192, 32768];

#[derive(Debug)]
pub enum FrameError {
    TooLarge,
    BadShape,
    BadPadding,
    BadFrame(String),
}

fn cbor_head_len(n: usize) -> usize {
    if n <= 23 {
        1
    } else if n <= 0xff {
        2
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Encode a frame into a bucket-padded wire payload (the WS message body).
pub fn encode_wire(frame_bytes: &[u8]) -> Result<Vec<u8>, FrameError> {
    for &bucket in &FRAME_BUCKETS {
        for head in [1usize, 2, 3, 5, 9] {
            let pad = bucket as i64
                - (1 /* array hdr */ + cbor_head_len(frame_bytes.len()) as i64 + frame_bytes.len() as i64 + head as i64);
            if pad >= 0 && cbor_head_len(pad as usize) == head {
                let arr = Value::Array(vec![
                    Value::Bytes(frame_bytes.to_vec()),
                    Value::Bytes(vec![0u8; pad as usize]),
                ]);
                let bytes = cbor::encode(&arr);
                debug_assert_eq!(bytes.len(), bucket);
                return Ok(bytes);
            }
        }
    }
    Err(FrameError::TooLarge)
}

/// Encode a frame padded to exactly `FRAME_BUCKETS[bucket]`. Used for snow
/// dummies, whose size is drawn from the mix of real frame buckets.
/// Errors if the frame does not fit the chosen bucket.
pub fn encode_wire_to_bucket(frame_bytes: &[u8], bucket: usize) -> Result<Vec<u8>, FrameError> {
    let Some(&target) = FRAME_BUCKETS.get(bucket) else {
        return Err(FrameError::TooLarge);
    };
    for head in [1usize, 2, 3, 5, 9] {
        let pad = target as i64
            - (1 + cbor_head_len(frame_bytes.len()) as i64
                + frame_bytes.len() as i64
                + head as i64);
        if pad >= 0 && cbor_head_len(pad as usize) == head {
            let arr = Value::Array(vec![
                Value::Bytes(frame_bytes.to_vec()),
                Value::Bytes(vec![0u8; pad as usize]),
            ]);
            let bytes = cbor::encode(&arr);
            debug_assert_eq!(bytes.len(), target);
            return Ok(bytes);
        }
    }
    Err(FrameError::TooLarge)
}

/// Decode a wire payload back into the frame bytes. Exact bucket size and
/// all-zero padding are mandatory.
pub fn decode_wire(bytes: &[u8]) -> Result<Vec<u8>, FrameError> {
    if !FRAME_BUCKETS.contains(&bytes.len()) {
        return Err(FrameError::TooLarge);
    }
    let v = cbor::decode(bytes).map_err(|e| FrameError::BadFrame(e.to_string()))?;
    let arr = v.as_array().ok_or(FrameError::BadShape)?;
    if arr.len() != 2 {
        return Err(FrameError::BadShape);
    }
    let frame = arr[0].as_bytes().ok_or(FrameError::BadShape)?.to_vec();
    let pad = arr[1].as_bytes().ok_or(FrameError::BadShape)?;
    if !pad.iter().all(|&b| b == 0) {
        return Err(FrameError::BadPadding);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_every_bucket() {
        for frame_len in [10usize, 2000, 7000, 30000] {
            let frame = vec![0xAB; frame_len];
            let wire = encode_wire(&frame).unwrap();
            assert!(FRAME_BUCKETS.contains(&wire.len()));
            assert_eq!(decode_wire(&wire).unwrap(), frame);
        }
    }

    #[test]
    fn rejects_non_bucket_sizes_and_bad_padding() {
        assert!(decode_wire(&[0u8; 100]).is_err());
        let mut wire = encode_wire(b"hello").unwrap();
        let n = wire.len();
        wire[n - 1] = 1; // non-zero padding
        assert!(decode_wire(&wire).is_err());
    }
}
