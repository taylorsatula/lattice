"""Ed25519 cryptographic primitives for Lattice v1."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lattice.encoding import b64url_decode, b64url_encode


class SignatureError(ValueError):
    """Raised when a signature cannot be verified."""


def generate_private_key() -> Ed25519PrivateKey:
    """Generate a new Ed25519 private key."""
    return Ed25519PrivateKey.generate()


def load_private_key(data: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from PKCS#8 PEM or DER bytes."""
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except ValueError:
        key = serialization.load_der_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("private key is not Ed25519")
    return key


def save_private_key(
    key: Ed25519PrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialize an Ed25519 private key to PKCS#8 PEM bytes.

    If ``password`` is provided, the key is encrypted with PBKDF2/HMAC-SHA256
    and AES-256-CBC using BestAvailableEncryption semantics via cryptography's
    default PKCS#8 encryption.
    """
    encryption: serialization.KeySerializationEncryption
    if password is None:
        encryption = serialization.NoEncryption()
    else:
        encryption = serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def load_public_key(data: bytes) -> Ed25519PublicKey:
    """Load an Ed25519 public key from raw 32-byte, PEM, or DER bytes."""
    if len(data) == 32:
        return Ed25519PublicKey.from_public_bytes(data)
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        key = serialization.load_der_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("public key is not Ed25519")
    return key


def save_public_key(key: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to PEM bytes."""
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    """Return the 32-byte raw public key."""
    return key.public_bytes_raw()


def public_key_b64url(key: Ed25519PublicKey) -> str:
    """Return the unpadded base64url public key."""
    return b64url_encode(public_key_bytes(key))


def load_public_key_b64url(text: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from unpadded base64url text."""
    return Ed25519PublicKey.from_public_bytes(b64url_decode(text))


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign ``message`` with ``private_key`` and return 64-byte signature."""
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, message: bytes, signature: bytes) -> None:
    """Verify ``signature`` over ``message`` with ``public_key``.

    Raises:
        SignatureError: If the signature is invalid.
    """
    try:
        public_key.verify(signature, message)
    except Exception as exc:
        raise SignatureError("signature verification failed") from exc
