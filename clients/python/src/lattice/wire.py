"""CBOR framing for the local API (V2_SPEC §7).

Each frame is a 4-byte big-endian length prefix followed by that many
bytes of CBOR. The payload may not exceed LOCAL_MAX_FRAME bytes.

The codec is canonical (RFC 7049 §3.9): shortest-form integers and map
keys sorted by (length, bytewise), matching the Rust implementation, so
re-encoding a decoded value reproduces the original bytes exactly.
"""

from __future__ import annotations

import io

import cbor2

LOCAL_MAX_FRAME = 64 * 1024
LOCAL_PREFIX_LEN = 4


def encode(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def decode(data: bytes):
    # Reject trailing bytes, matching the Rust decoder: a frame or message
    # with extra bytes after the top-level value is malformed.
    stream = io.BytesIO(data)
    decoder = cbor2.CBORDecoder(stream)
    value = decoder.decode()
    if stream.read():
        raise ValueError("trailing bytes after CBOR value")
    return value


def frame(payload: bytes) -> bytes:
    if len(payload) > LOCAL_MAX_FRAME:
        raise ValueError(f"frame too large: {len(payload)} > {LOCAL_MAX_FRAME}")
    return len(payload).to_bytes(LOCAL_PREFIX_LEN, "big") + payload


def deframe(buf: bytearray):
    """Split one frame off the front of buf.

    Returns (payload, bytes_consumed), or (None, 0) if more bytes are needed.
    Raises ValueError if the length prefix exceeds LOCAL_MAX_FRAME.
    """
    if len(buf) < LOCAL_PREFIX_LEN:
        return None, 0
    length = int.from_bytes(buf[:LOCAL_PREFIX_LEN], "big")
    if length > LOCAL_MAX_FRAME:
        raise ValueError(f"frame too large: {length} > {LOCAL_MAX_FRAME}")
    if len(buf) < LOCAL_PREFIX_LEN + length:
        return None, 0
    return bytes(buf[LOCAL_PREFIX_LEN : LOCAL_PREFIX_LEN + length]), LOCAL_PREFIX_LEN + length
