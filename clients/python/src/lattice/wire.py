"""CBOR framing for the local API (V2_SPEC §7).

Each frame is a 4-byte big-endian length prefix followed by that many
bytes of CBOR. The payload may not exceed LOCAL_MAX_FRAME bytes.

The codec is canonical (RFC 8949 §4.2): shortest-form integers, definite
lengths only, map keys sorted by (length, bytewise), matching the Rust
implementation, so re-encoding a decoded value reproduces the original
bytes exactly. Decoding rejects anything else: non-shortest-form integers,
indefinite-length items, duplicate map keys, out-of-order map keys, floats,
tags, nesting deeper than 8, containers with more than 512 items, and
trailing bytes.
"""

from __future__ import annotations

import io

import cbor2

LOCAL_MAX_FRAME = 64 * 1024
LOCAL_PREFIX_LEN = 4

# Matches the Rust decoder's limits (crates/lattice-proto/src/cbor.rs).
MAX_DEPTH = 8
MAX_CONTAINER_ITEMS = 512


def encode(obj) -> bytes:
    return cbor2.dumps(obj, canonical=True)


def decode(data: bytes):
    # Reject trailing bytes, duplicate keys, indefinite-length items and
    # excessive nesting up front; then reject anything whose re-encoding is
    # not byte-identical to the input (non-shortest-form integers, map keys
    # out of canonical order), and anything outside the wire value set.
    stream = io.BytesIO(data)
    decoder = cbor2.CBORDecoder(
        stream,
        allow_duplicate_keys=False,
        allow_indefinite=False,
        max_depth=MAX_DEPTH,
    )
    try:
        value = decoder.decode()
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"invalid CBOR: {e}") from e
    if stream.read():
        raise ValueError("trailing bytes after CBOR value")
    _check_value(value, 0)
    if cbor2.dumps(value, canonical=True) != bytes(data):
        raise ValueError("non-canonical CBOR encoding")
    return value


def _check_value(value, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("nesting too deep")
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("too many map entries")
        for key, item in value.items():
            _check_key(key)
            _check_value(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise ValueError("too many array items")
        for item in value:
            _check_value(item, depth + 1)
    elif isinstance(value, float):
        # The wire format has no floats; the Rust decoder rejects them.
        raise ValueError("floats are not valid on the wire")
    elif isinstance(value, cbor2.CBORTag):
        raise ValueError("tags are not valid on the wire")


def _check_key(key) -> None:
    if isinstance(key, (float, cbor2.CBORTag)):
        raise ValueError("invalid map key")


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
