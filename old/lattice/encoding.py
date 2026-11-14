"""Base32/Base64url encoding helpers used by Lattice identity and signing."""

from __future__ import annotations

import base64


def b64url_encode(data: bytes) -> str:
    """Return unpadded base64url encoding of ``data``."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded or padded base64url text."""
    pad = -len(text) % 4
    return base64.urlsafe_b64decode(text + ("=" * pad))


def b32lower_encode(data: bytes) -> str:
    """Return lowercase unpadded RFC 4648 Base32 encoding of ``data``."""
    return base64.b32encode(data).decode("ascii").lower().rstrip("=")
