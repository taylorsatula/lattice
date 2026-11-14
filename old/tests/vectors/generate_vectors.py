"""Generate canonicalization and signature vectors for Lattice v1.

Run with:
    uv run python tests/vectors/generate_vectors.py

The script writes:
    tests/vectors/canonical.json
    tests/vectors/signatures.json

These vectors are language-neutral golden fixtures. They MUST be regenerated only
when the protocol specification intentionally changes.
"""

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ROOT_SEED = b"lattice-test-root-seed-000000000000000000000000000000"
OLD_OP_SEED = b"lattice-test-old-op-seed-00000000000000000000000000000"
NEW_OP_SEED = b"lattice-test-new-op-seed-00000000000000000000000000000"
RECIPIENT_ROOT_SEED = b"lattice-test-recipient-seed-000000000000000000000000000"

MEDIA_TYPE = "application/vnd.lattice+json; version=1"
NODE_ID_PREFIX = b"lattice-node-id-v1\0"
SIG_PREFIX = "lattice-signature-v1"

VECTORS_DIR = Path(__file__).resolve().parent


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b32lower(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").lower().rstrip("=")


def key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    """Deterministically derive an Ed25519 private key from a seed."""
    # Ed25519 private keys are 32 bytes expanded; use SHA-256 to derive a 32-byte seed.
    digest = hashlib.sha256(seed).digest()
    return Ed25519PrivateKey.from_private_bytes(digest)


def derive_node_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    digest = hashlib.sha256(NODE_ID_PREFIX + raw).digest()
    return "lat_" + _b32lower(digest)


def canonicalize(obj: Any) -> bytes:
    return rfc8785.dumps(obj)


def sign_object(
    obj: dict[str, object], kind: str, private_key: Ed25519PrivateKey
) -> dict[str, object]:
    signed = {k: v for k, v in obj.items() if k != "signature"}
    canonical = canonicalize(signed)
    preimage = f"{SIG_PREFIX}\0{kind}\0{MEDIA_TYPE}\0".encode() + canonical
    signature = private_key.sign(preimage)
    signed["signature"] = _b64url(signature)
    return signed


def verify_object(obj: dict[str, object], kind: str, public_key: Ed25519PublicKey) -> None:
    sig_value = obj["signature"]
    if not isinstance(sig_value, str):
        raise TypeError("signature must be a string")
    signature = base64.urlsafe_b64decode(_pad_b64url(sig_value))
    signed = {k: v for k, v in obj.items() if k != "signature"}
    canonical = canonicalize(signed)
    preimage = f"{SIG_PREFIX}\0{kind}\0{MEDIA_TYPE}\0".encode() + canonical
    public_key.verify(signature, preimage)


def _pad_b64url(s: str) -> str:
    pad = -len(s) % 4
    return s + ("=" * pad)


def _without_keys(obj: dict[str, object], *keys: str) -> dict[str, object]:
    return {k: v for k, v in obj.items() if k not in keys}


def make_certificate(
    node_id: str,
    op_public_key: Ed25519PublicKey,
    sequence: int,
    valid_from: str,
    valid_until: str,
    root_key: Ed25519PrivateKey,
) -> dict[str, object]:
    cert: dict[str, object] = {
        "kind": "operational_certificate",
        "node_id": node_id,
        "operational_public_key": _b64url(op_public_key.public_bytes_raw()),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "sequence": sequence,
    }
    return sign_object(cert, "operational_certificate", root_key)


def main() -> None:
    root_key = key_from_seed(ROOT_SEED)
    old_op_key = key_from_seed(OLD_OP_SEED)
    new_op_key = key_from_seed(NEW_OP_SEED)
    recipient_root_key = key_from_seed(RECIPIENT_ROOT_SEED)

    root_pub = root_key.public_key()
    node_id = derive_node_id(root_pub)

    old_op_pub = old_op_key.public_key()
    new_op_pub = new_op_key.public_key()
    recipient_root_pub = recipient_root_key.public_key()
    recipient_node_id = derive_node_id(recipient_root_pub)

    # ------------------------------------------------------------------
    # Canonicalization vectors
    # ------------------------------------------------------------------
    canonical_vectors: dict[str, Any] = {
        "description": "RFC 8785 JCS canonicalization vectors for Lattice v1.",
        "media_type": MEDIA_TYPE,
        "vectors": [
            {
                "name": "simple_object",
                "input": {"b": 2, "a": 1},
                "canonical": '{"a":1,"b":2}',
            },
            {
                "name": "unicode_keys_and_strings",
                "input": {"\u00e9": "caf\u00e9", "a": "hello"},
                "canonical": '{"a":"hello","\u00e9":"caf\u00e9"}',
            },
            {
                "name": "floating_point",
                "input": {"pi": 3.14159, "zero": 0.0, "neg_zero": -0.0},
                "canonical": '{"neg_zero":0,"pi":3.14159,"zero":0}',
            },
            {
                "name": "nested_and_array",
                "input": {"z": [True, False, None], "a": {"c": 3, "b": 2}},
                "canonical": '{"a":{"b":2,"c":3},"z":[true,false,null]}',
            },
            {
                "name": "large_integer",
                "input": {"max_safe": 9007199254740991, "min_safe": -9007199254740991},
                "canonical": '{"max_safe":9007199254740991,"min_safe":-9007199254740991}',
            },
        ],
    }

    # Verify canonical vectors round-trip through our chosen library.
    for vec in canonical_vectors["vectors"]:
        input_value = vec["input"]
        expected = vec["canonical"]
        assert isinstance(input_value, dict)
        assert isinstance(expected, str)
        canonical_bytes = rfc8785.dumps(input_value)
        assert canonical_bytes.decode("utf-8") == expected, vec["name"]

    # ------------------------------------------------------------------
    # Signature vectors
    # ------------------------------------------------------------------
    issued_at = "2024-01-15T10:30:00Z"

    op_cert = make_certificate(
        node_id=node_id,
        op_public_key=old_op_pub,
        sequence=1,
        valid_from="2024-01-01T00:00:00Z",
        valid_until="2024-04-01T00:00:00Z",
        root_key=root_key,
    )

    well_known: dict[str, object] = {
        "kind": "well_known",
        "node_id": node_id,
        "domain": "example.com",
        "root_public_key": _b64url(root_pub.public_bytes_raw()),
        "operational_certificate": op_cert,
        "endpoints": {
            "gossip": "https://example.com/lattice/v1/gossip",
            "messages": "https://example.com/lattice/v1/messages",
        },
        "issued_at": issued_at,
    }
    well_known = sign_object(well_known, "well_known", root_key)
    verify_object(well_known, "well_known", root_pub)

    peer_card: dict[str, object] = {
        "kind": "peer_card",
        "node_id": node_id,
        "domain": "example.com",
        "root_public_key": _b64url(root_pub.public_bytes_raw()),
        "operational_certificate": op_cert,
        "endpoints": {
            "gossip": "https://example.com/lattice/v1/gossip",
            "messages": "https://example.com/lattice/v1/messages",
        },
        "sequence": 1,
        "issued_at": issued_at,
        "expires_at": "2024-01-22T10:30:00Z",
    }
    peer_card = sign_object(peer_card, "peer_card", old_op_key)
    verify_object(peer_card, "peer_card", old_op_pub)

    message: dict[str, object] = {
        "kind": "message",
        "message_id": "msg_2jmj7l5rSw0yVb_vlWAYkK_YBwk",
        "from_address": f"alice@{node_id}",
        "to_address": f"bob@{recipient_node_id}",
        "content": "Hello, Lattice!",
        "priority": "normal",
        "ttl_seconds": 86400,
        "timestamp": issued_at,
    }
    message = sign_object(message, "message", old_op_key)
    verify_object(message, "message", old_op_pub)

    receipt: dict[str, object] = {
        "kind": "receipt",
        "message_id": "msg_2jmj7l5rSw0yVb_vlWAYkK_YBwk",
        "node_id": recipient_node_id,
        "status": "accepted",
        "received_at": issued_at,
    }
    receipt = sign_object(receipt, "receipt", old_op_key)
    verify_object(receipt, "receipt", old_op_pub)

    block: dict[str, object] = {
        "kind": "block",
        "node_id": node_id,
        "blocked_node_id": recipient_node_id,
        "reason": "spam",
        "issued_at": issued_at,
    }
    block = sign_object(block, "block", old_op_key)
    verify_object(block, "block", old_op_pub)

    transfer: dict[str, object] = {
        "kind": "transfer",
        "domain": "example.com",
        "old_node_id": node_id,
        "new_node_id": recipient_node_id,
        "issued_at": issued_at,
    }
    # Transfer must be signed by both old root and new root.
    transfer = sign_object(transfer, "transfer", root_key)
    transfer["new_signature"] = _b64url(
        recipient_root_key.sign(
            f"{SIG_PREFIX}\0transfer\0{MEDIA_TYPE}\0".encode()
            + canonicalize(_without_keys(transfer, "signature", "new_signature"))
        )
    )

    rotation: dict[str, object] = {
        "kind": "rotation",
        "node_id": node_id,
        "old_operational_public_key": _b64url(old_op_pub.public_bytes_raw()),
        "new_operational_public_key": _b64url(new_op_pub.public_bytes_raw()),
        "old_certificate_sequence": 1,
        "new_certificate_sequence": 2,
        "issued_at": issued_at,
    }
    rotation = sign_object(rotation, "rotation", root_key)
    rotation["old_signature"] = _b64url(
        old_op_key.sign(
            f"{SIG_PREFIX}\0rotation\0{MEDIA_TYPE}\0".encode()
            + canonicalize(_without_keys(rotation, "signature", "old_signature", "new_signature"))
        )
    )
    rotation["new_signature"] = _b64url(
        new_op_key.sign(
            f"{SIG_PREFIX}\0rotation\0{MEDIA_TYPE}\0".encode()
            + canonicalize(_without_keys(rotation, "signature", "old_signature", "new_signature"))
        )
    )

    signature_vectors = {
        "description": "Lattice v1 signature vectors using Ed25519 and RFC 8785 JCS.",
        "media_type": MEDIA_TYPE,
        "signature_prefix": SIG_PREFIX,
        "node_id_prefix": NODE_ID_PREFIX.decode("ascii"),
        "keys": {
            "root": {
                "seed": _b64url(ROOT_SEED),
                "public_key": _b64url(root_pub.public_bytes_raw()),
                "node_id": node_id,
            },
            "old_operational": {
                "seed": _b64url(OLD_OP_SEED),
                "public_key": _b64url(old_op_pub.public_bytes_raw()),
            },
            "new_operational": {
                "seed": _b64url(NEW_OP_SEED),
                "public_key": _b64url(new_op_pub.public_bytes_raw()),
            },
            "recipient_root": {
                "seed": _b64url(RECIPIENT_ROOT_SEED),
                "public_key": _b64url(recipient_root_pub.public_bytes_raw()),
                "node_id": recipient_node_id,
            },
        },
        "objects": {
            "operational_certificate": op_cert,
            "well_known": well_known,
            "peer_card": peer_card,
            "message": message,
            "receipt": receipt,
            "block": block,
            "transfer": transfer,
            "rotation": rotation,
        },
    }

    # Write files deterministically.
    with open(VECTORS_DIR / "canonical.json", "w", encoding="utf-8") as f:
        json.dump(canonical_vectors, f, indent=2, ensure_ascii=False)
        f.write("\n")

    with open(VECTORS_DIR / "signatures.json", "w", encoding="utf-8") as f:
        json.dump(signature_vectors, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote vectors to {VECTORS_DIR}")  # noqa: T201
    print(f"Node ID: {node_id}")  # noqa: T201
    print(f"Recipient Node ID: {recipient_node_id}")  # noqa: T201


if __name__ == "__main__":
    main()
