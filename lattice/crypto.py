"""
Ed25519 signing primitives.

Public keys and signatures travel as unpadded base64url strings. Every
signature covers a kind-prefixed canonical JSON encoding, so a signature made
for one message kind can never verify as another.
"""

import base64
import json
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL = "lattice/1"


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def private_key_to_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def private_key_from_pem(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Private key is not Ed25519")
    return key


def public_key_of(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64encode(raw)


def canonical(kind: str, payload: Dict[str, Any]) -> bytes:
    """The exact bytes a signature of `kind` covers."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{PROTOCOL}/{kind}\n{body}".encode()


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    return b64encode(private_key.sign(data))


def verify(public_key: str, data: bytes, signature: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64decode(public_key)).verify(b64decode(signature), data)
        return True
    except (InvalidSignature, ValueError):
        return False
