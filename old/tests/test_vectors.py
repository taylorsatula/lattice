"""Verify the implementation reproduces the language-neutral protocol vectors."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.canonical import canonicalize
from lattice.crypto import SignatureError, load_public_key_b64url
from lattice.identity import (
    OperationalCertificate,
    OperationalIdentity,
    RootIdentity,
    create_operational_certificate,
    derive_node_id,
    verify_object,
    verify_with_root,
)
from lattice.protocol.constants import MEDIA_TYPE

VECTORS_DIR = Path(__file__).resolve().parent / "vectors"


def load_json(name: str) -> dict[str, Any]:
    with open(VECTORS_DIR / name, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise TypeError(f"{name} must contain a JSON object")
    return data


class TestCanonicalVectors:
    def test_all_vectors(self) -> None:
        data = load_json("canonical.json")
        assert data["media_type"] == MEDIA_TYPE
        for vec in data["vectors"]:
            canonical = canonicalize(vec["input"])
            assert canonical.decode("utf-8") == vec["canonical"], vec["name"]


class TestSignatureVectors:
    @pytest.fixture
    def vectors(self) -> dict[str, Any]:
        return load_json("signatures.json")

    def test_node_id_derivation(self, vectors: dict[str, Any]) -> None:
        for name in ("root", "recipient_root"):
            key_data = vectors["keys"][name]
            public_key = load_public_key_b64url(key_data["public_key"])
            assert derive_node_id(public_key) == key_data["node_id"]

    def test_operational_certificate(self, vectors: dict[str, Any]) -> None:
        cert_dict = vectors["objects"]["operational_certificate"]
        cert = OperationalCertificate.from_dict(cert_dict)
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        assert cert.node_id == root_key_data["node_id"]

    def test_well_known(self, vectors: dict[str, Any]) -> None:
        doc = vectors["objects"]["well_known"]
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        verify_with_root(root_public_key, doc, "well_known")

    def test_peer_card(self, vectors: dict[str, Any]) -> None:
        card = vectors["objects"]["peer_card"]
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        verify_object(cert.operational_public_key, card, "peer_card")

    def test_message(self, vectors: dict[str, Any]) -> None:
        message = vectors["objects"]["message"]
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        verify_object(cert.operational_public_key, message, "message")

    def test_receipt(self, vectors: dict[str, Any]) -> None:
        receipt = vectors["objects"]["receipt"]
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        verify_object(cert.operational_public_key, receipt, "receipt")

    def test_block(self, vectors: dict[str, Any]) -> None:
        block = vectors["objects"]["block"]
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        verify_object(cert.operational_public_key, block, "block")


class TestTampering:
    def test_signature_fails_on_tampered_object(self) -> None:
        vectors = load_json("signatures.json")
        message = dict(vectors["objects"]["message"])
        message["content"] = "tampered"
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        with pytest.raises(SignatureError):
            verify_object(cert.operational_public_key, message, "message")

    def test_signature_fails_on_wrong_kind(self) -> None:
        vectors = load_json("signatures.json")
        message = dict(vectors["objects"]["message"])
        cert = OperationalCertificate.from_dict(vectors["objects"]["operational_certificate"])
        root_key_data = vectors["keys"]["root"]
        root_public_key = load_public_key_b64url(root_key_data["public_key"])
        root_identity = RootIdentity.from_public_key(root_public_key)
        cert.verify(root_identity)
        with pytest.raises(SignatureError):
            verify_object(cert.operational_public_key, message, "receipt")

    def test_signature_fails_on_wrong_key(self) -> None:
        vectors = load_json("signatures.json")
        message = vectors["objects"]["message"]
        recipient_public_key = load_public_key_b64url(
            vectors["keys"]["recipient_root"]["public_key"]
        )
        with pytest.raises(SignatureError):
            verify_object(recipient_public_key, message, "message")


class TestOperationalRotation:
    def test_rotation_preserves_node_id(self) -> None:
        root_key = Ed25519PrivateKey.generate()
        old_op_key = Ed25519PrivateKey.generate()
        new_op_key = Ed25519PrivateKey.generate()
        node_id = derive_node_id(root_key.public_key())

        now = datetime.now(UTC)
        old_cert = create_operational_certificate(
            root_key=root_key,
            operational_public_key=old_op_key.public_key(),
            sequence=1,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )
        new_cert = create_operational_certificate(
            root_key=root_key,
            operational_public_key=new_op_key.public_key(),
            sequence=2,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )

        assert old_cert.node_id == node_id
        assert new_cert.node_id == node_id

        root_identity = RootIdentity.from_public_key(root_key.public_key())
        old_cert.verify(root_identity)
        new_cert.verify(root_identity)

        op_identity = OperationalIdentity(
            node_id=node_id,
            private_key=old_op_key,
            certificate=old_cert,
        )
        assert op_identity.node_id == node_id
