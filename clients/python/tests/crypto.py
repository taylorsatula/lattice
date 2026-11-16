"""Cryptographic primitives used by Lattice's wire format.

Implements the X-Wing KEM (X25519 + ML-KEM-768, draft-connolly-cfrg-xwing-kem,
draft-06) as used by the reference Rust implementation, plus the BLAKE3-keyed
ChaCha20-Poly1305 seal used for hop and envelope layers.

There is no ``x-wing`` package dependency: the draft-06 combiner
(SHA3-256 over ss_m || ss_x || ct_x || pk_x || "\\.//^\\") is implemented
here on top of ``cryptography``'s ML-KEM-768 and X25519. The draft-06
combiner is pinned by the shared test vectors; if the draft advances to an
RFC, re-check the label and concatenation order against the new document,
regenerate vectors/vectors.json from the Rust implementation, and bump the
``cryptography`` floor in pyproject.toml in lockstep with the Rust ``x-wing``
crate. See the README ("X-Wing") for the full version-bump plan.

Only what the vectors and the local client need is implemented. This is not
a general-purpose crypto library.
"""

from __future__ import annotations

import hashlib

import blake3
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

XWING_PUBLIC_KEY_LEN = 1216
XWING_SECRET_KEY_LEN = 32
KEM_CIPHERTEXT_LEN = 1120
_MLKEM_CT_LEN = 1088
_X25519_CT_LEN = 32

# The X-Wing combiner label (draft-connolly-cfrg-xwing-kem).
_XWING_LABEL = b"\\.//^\\"

ENVELOPE_CONTEXT = "lattice v1 envelope"
HOP_CONTEXT = "lattice v1 hop"

_ZERO_NONCE = b"\x00" * 12


def xwing_public_key(seed: bytes) -> bytes:
    """Derive the 1216-byte X-Wing public key from a 32-byte seed."""
    if len(seed) != XWING_SECRET_KEY_LEN:
        raise ValueError("X-Wing seed must be 32 bytes")
    expanded = hashlib.shake_256(seed).digest(96)
    seed_m, sk_x = expanded[:64], expanded[64:]
    mlkem = MLKEM768PrivateKey.from_seed_bytes(seed_m)
    pk_m = mlkem.public_key().public_bytes_raw()
    pk_x = X25519PrivateKey.from_private_bytes(sk_x).public_key().public_bytes_raw()
    return pk_m + pk_x


def xwing_decapsulate(seed: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a 1120-byte X-Wing ciphertext to the 32-byte shared secret."""
    if len(seed) != XWING_SECRET_KEY_LEN:
        raise ValueError("X-Wing seed must be 32 bytes")
    if len(ciphertext) != KEM_CIPHERTEXT_LEN:
        raise ValueError(f"X-Wing ciphertext must be {KEM_CIPHERTEXT_LEN} bytes")
    expanded = hashlib.shake_256(seed).digest(96)
    seed_m, sk_x = expanded[:64], expanded[64:]
    mlkem = MLKEM768PrivateKey.from_seed_bytes(seed_m)
    xsk = X25519PrivateKey.from_private_bytes(sk_x)
    ct_m, ct_x = ciphertext[:_MLKEM_CT_LEN], ciphertext[_MLKEM_CT_LEN:]
    ss_m = mlkem.decapsulate(ct_m)
    pk_x = xsk.public_key().public_bytes_raw()
    ss_x = xsk.exchange(X25519PublicKey.from_public_bytes(ct_x))
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()


def aead_key(context: str, shared_secret: bytes) -> bytes:
    """BLAKE3 KDF used for the hop and envelope layers."""
    return blake3.blake3(shared_secret, derive_key_context=context).digest()


def open_layer(context: str, secret: bytes, aad: bytes, kem_ciphertext: bytes, ciphertext: bytes) -> bytes:
    """Open a sealed layer (X-Wing + ChaCha20-Poly1305)."""
    shared = xwing_decapsulate(secret, kem_ciphertext)
    key = aead_key(context, shared)
    return ChaCha20Poly1305(key).decrypt(_ZERO_NONCE, ciphertext, aad)
