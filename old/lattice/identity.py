"""Node identity derivation and operational identity for Lattice v1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lattice.canonical import canonicalize, signature_preimage
from lattice.crypto import (
    load_public_key_b64url,
    public_key_b64url,
    public_key_bytes,
    sign,
    verify,
)
from lattice.encoding import b32lower_encode, b64url_decode, b64url_encode
from lattice.protocol.constants import (
    MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS,
    NODE_ID_DOMAIN_PREFIX,
)


class IdentityError(ValueError):
    """Raised when an identity or certificate is invalid."""


def derive_node_id(root_public_key: Ed25519PublicKey) -> str:
    """Derive the immutable node ID from a root Ed25519 public key."""
    raw = public_key_bytes(root_public_key)
    digest = hashlib.sha256(NODE_ID_DOMAIN_PREFIX + raw).digest()
    return "lat_" + b32lower_encode(digest)


def node_id_from_public_key_b64url(text: str) -> str:
    """Derive a node ID from an unpadded base64url Ed25519 public key."""
    public_key = load_public_key_b64url(text)
    return derive_node_id(public_key)


def sign_with_root(
    root_key: Ed25519PrivateKey, obj: dict[str, object], kind: str
) -> dict[str, object]:
    """Sign a canonical object of ``kind`` with the root key."""
    signed = {k: v for k, v in obj.items() if k != "signature"}
    canonical = canonicalize(signed)
    preimage = signature_preimage(kind, canonical)
    signature = sign(root_key, preimage)
    signed["signature"] = b64url_encode(signature)
    return signed


def verify_with_root(root_public_key: Ed25519PublicKey, obj: dict[str, object], kind: str) -> None:
    """Verify a root signature on ``obj`` of ``kind``."""
    sig_text = _str(obj, "signature")
    signature = b64url_decode(sig_text)
    signed = {k: v for k, v in obj.items() if k != "signature"}
    canonical = canonicalize(signed)
    preimage = signature_preimage(kind, canonical)
    verify(root_public_key, preimage, signature)


@dataclass(frozen=True)
class RootIdentity:
    """Immutable root identity of a Lattice node.

    The root private key is intentionally not a field of this class. Daemon code
    receives only :class:`OperationalIdentity`. Root operations happen through
    CLI tooling that loads the root key from encrypted host credentials.
    """

    node_id: str
    public_key: Ed25519PublicKey

    @classmethod
    def from_public_key(cls, public_key: Ed25519PublicKey) -> RootIdentity:
        return cls(node_id=derive_node_id(public_key), public_key=public_key)


@dataclass(frozen=True)
class OperationalCertificate:
    """A root-signed operational certificate authorizing an operational key."""

    node_id: str
    operational_public_key: Ed25519PublicKey
    valid_from: datetime
    valid_until: datetime
    sequence: int
    signature: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": "operational_certificate",
            "node_id": self.node_id,
            "operational_public_key": public_key_b64url(self.operational_public_key),
            "valid_from": _format_ts(self.valid_from),
            "valid_until": _format_ts(self.valid_until),
            "sequence": self.sequence,
            "signature": b64url_encode(self.signature),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> OperationalCertificate:
        _require_kind(data, "operational_certificate")
        node_id = _str(data, "node_id")
        op_pub_text = _str(data, "operational_public_key")
        valid_from = _parse_ts(_str(data, "valid_from"))
        valid_until = _parse_ts(_str(data, "valid_until"))
        sequence = _int(data, "sequence")
        signature = b64url_decode(_str(data, "signature"))
        return cls(
            node_id=node_id,
            operational_public_key=load_public_key_b64url(op_pub_text),
            valid_from=valid_from,
            valid_until=valid_until,
            sequence=sequence,
            signature=signature,
        )

    def verify(self, root_identity: RootIdentity) -> None:
        """Verify the certificate signature against the root identity.

        The signature preimage is the certificate's canonical form —
        ``to_dict()`` without ``signature``: UTC ``Z`` timestamps at second
        precision (see ``_format_ts``). ``from_dict`` accepts any timezone
        encoding (e.g. ``+00:00``) and normalizes to this form, so every
        verify site agrees regardless of how the certificate was encoded
        on the wire; peer cards and messages, by contrast, are verified
        over their received object dicts (see ``verify_object``).
        """
        if self.node_id != root_identity.node_id:
            raise IdentityError("certificate node ID mismatch")
        derived = derive_node_id(root_identity.public_key)
        if derived != root_identity.node_id:
            raise IdentityError("root public key does not match node ID")
        signed = self.to_dict()
        del signed["signature"]
        canonical = canonicalize(signed)
        preimage = signature_preimage("operational_certificate", canonical)
        verify(root_identity.public_key, preimage, self.signature)

    def is_valid_at(self, when: datetime | None = None) -> bool:
        """Return True if ``when`` falls within the certificate validity window."""
        when = when or datetime.now(UTC)
        return self.valid_from <= when < self.valid_until


@dataclass(frozen=True)
class OperationalIdentity:
    """The signing identity available to the Lattice daemon.

    Contains the active operational private key and its root-signed certificate.
    The root private key is not included.
    """

    node_id: str
    private_key: Ed25519PrivateKey
    certificate: OperationalCertificate

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def sign_object(self, obj: dict[str, object], kind: str) -> dict[str, object]:
        """Sign a canonical object of ``kind`` and return it with signature."""
        signed = {k: v for k, v in obj.items() if k != "signature"}
        canonical = canonicalize(signed)
        preimage = signature_preimage(kind, canonical)
        signature = sign(self.private_key, preimage)
        signed["signature"] = b64url_encode(signature)
        return signed

    def verify_object(
        self,
        obj: dict[str, object],
        kind: str,
    ) -> None:
        """Verify the operational signature on ``obj``."""
        verify_object(self.public_key, obj, kind)


def verify_object(public_key: Ed25519PublicKey, obj: dict[str, object], kind: str) -> None:
    """Verify an Ed25519 signature on ``obj`` of ``kind``."""
    sig_text = _str(obj, "signature")
    signature = b64url_decode(sig_text)
    signed = {k: v for k, v in obj.items() if k != "signature"}
    canonical = canonicalize(signed)
    preimage = signature_preimage(kind, canonical)
    verify(public_key, preimage, signature)


def verify_transfer(
    transfer: dict[str, object],
    old_root_public_key: Ed25519PublicKey,
    new_root_public_key: Ed25519PublicKey,
) -> None:
    """Verify both signatures on a ``transfer`` statement.

    Per docs/PROTOCOL.md §4.4 a transfer is signed by the old root (the
    ``signature`` field) and the new root (the ``new_signature`` field). Both
    signatures cover the same bare object — the statement without any
    signature fields (see tests/vectors/generate_vectors.py).
    """
    _require_kind(transfer, "transfer")
    bare = {k: v for k, v in transfer.items() if k not in ("signature", "new_signature")}
    canonical = canonicalize(bare)
    preimage = signature_preimage("transfer", canonical)
    verify(old_root_public_key, preimage, b64url_decode(_str(transfer, "signature")))
    verify(new_root_public_key, preimage, b64url_decode(_str(transfer, "new_signature")))


def verify_rotation(
    rotation: dict[str, object],
    root_public_key: Ed25519PublicKey,
    old_operational_public_key: Ed25519PublicKey,
    new_operational_public_key: Ed25519PublicKey,
) -> None:
    """Verify all three signatures on a ``rotation`` statement.

    The root signs the ``signature`` field; the old and new operational keys
    sign ``old_signature`` and ``new_signature``. All three cover the same
    bare object (see tests/vectors/generate_vectors.py).
    """
    _require_kind(rotation, "rotation")
    bare = {
        k: v
        for k, v in rotation.items()
        if k not in ("signature", "old_signature", "new_signature")
    }
    canonical = canonicalize(bare)
    preimage = signature_preimage("rotation", canonical)
    verify(root_public_key, preimage, b64url_decode(_str(rotation, "signature")))
    verify(
        old_operational_public_key,
        preimage,
        b64url_decode(_str(rotation, "old_signature")),
    )
    verify(
        new_operational_public_key,
        preimage,
        b64url_decode(_str(rotation, "new_signature")),
    )


def create_operational_certificate(
    root_key: Ed25519PrivateKey,
    operational_public_key: Ed25519PublicKey,
    sequence: int,
    valid_from: datetime,
    valid_until: datetime,
) -> OperationalCertificate:
    """Create and sign a new operational certificate.

    The certificate lifetime is bounded by
    ``MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS``.
    """
    root_identity = RootIdentity.from_public_key(root_key.public_key())
    if valid_from >= valid_until:
        raise IdentityError("valid_from must be before valid_until")
    if (valid_until - valid_from).total_seconds() > MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS:
        raise IdentityError("operational certificate lifetime exceeds maximum")
    if sequence < 1:
        raise IdentityError("certificate sequence must be positive")

    cert = OperationalCertificate(
        node_id=root_identity.node_id,
        operational_public_key=operational_public_key,
        valid_from=valid_from,
        valid_until=valid_until,
        sequence=sequence,
        signature=b"",
    )
    signed = cert.to_dict()
    del signed["signature"]
    canonical = canonicalize(signed)
    preimage = signature_preimage("operational_certificate", canonical)
    cert_signature = sign(root_key, preimage)
    return OperationalCertificate(
        node_id=cert.node_id,
        operational_public_key=cert.operational_public_key,
        valid_from=cert.valid_from,
        valid_until=cert.valid_until,
        sequence=cert.sequence,
        signature=cert_signature,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _format_ts(when: datetime) -> str:
    if when.tzinfo is None:
        raise IdentityError("timestamp must be timezone-aware")
    utc = when.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(text: str) -> datetime:
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IdentityError(f"invalid timestamp: {text}") from exc
    if when.tzinfo is None:
        raise IdentityError("timestamp must be timezone-aware")
    return when.astimezone(UTC)


def _require_kind(data: dict[str, object], kind: str) -> None:
    actual = data.get("kind")
    if actual != kind:
        raise IdentityError(f"expected kind {kind!r}, got {actual!r}")


def _str(data: dict[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise IdentityError(f"{key} must be a string")
    return value


def _int(data: dict[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise IdentityError(f"{key} must be an integer")
    return value
