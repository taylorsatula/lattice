"""Canonical JSON serialization and signature preimages for Lattice v1."""

from __future__ import annotations

import json
from typing import Any

import rfc8785

from lattice.protocol.constants import MEDIA_TYPE, SIGNATURE_DOMAIN_PREFIX


class JSONParseError(ValueError):
    """Raised when input JSON does not satisfy Lattice strict parsing rules."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys during JSON parsing."""
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise JSONParseError(f"duplicate key: {key!r}")
        seen.add(key)
        result[key] = value
    return result


def _reject_non_finite(obj: Any) -> Any:
    """Recursively reject NaN, Infinity, and -Infinity values."""
    if isinstance(obj, float):
        if not (-float("inf") < obj < float("inf")):
            raise JSONParseError("non-finite floating-point value")
        return obj
    if isinstance(obj, dict):
        return {k: _reject_non_finite(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_reject_non_finite(v) for v in obj]
    return obj


def strict_json_loads(data: str | bytes) -> Any:
    """Parse JSON with Lattice strict rules.

    Rules:
    - Duplicate object keys are rejected.
    - NaN, Infinity, and -Infinity are rejected.
    - UTF-8 is enforced for bytes input.
    - Object key order is not semantically significant.

    Numbers outside the I-JSON safe range are validated during model
    construction, not here, because this function returns plain Python values.
    """
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise JSONParseError(f"invalid JSON: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise JSONParseError("invalid UTF-8") from exc

    return _reject_non_finite(parsed)


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 JCS canonical byte representation of ``obj``."""
    return rfc8785.dumps(obj)


def signature_preimage(kind: str, canonical_bytes: bytes) -> bytes:
    """Build the Ed25519 signature preimage for a signed object kind.

    The preimage is::

        "lattice-signature-v1\0" || kind || "\0" || media_type || "\0" || canonical_bytes

    where ``\0`` is the NUL byte (0x00).
    """
    header = f"{SIGNATURE_DOMAIN_PREFIX}\0{kind}\0{MEDIA_TYPE}\0"
    return header.encode("utf-8") + canonical_bytes
