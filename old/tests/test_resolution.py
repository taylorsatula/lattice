"""Tests for well-known resolution and address resolution."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.crypto import public_key_b64url
from lattice.identity import (
    OperationalCertificate,
    create_operational_certificate,
    derive_node_id,
    sign_with_root,
)
from lattice.resolution import ResolutionError, WellKnownResolver, resolve_address
from lattice.storage.connection import open_connection
from lattice.storage.migrations import migrate
from lattice.storage.repositories import DomainPinRepository
from lattice.transport import OutboundTransport


@pytest.fixture
def node_credentials() -> tuple[Ed25519PrivateKey, Ed25519PrivateKey, OperationalCertificate]:
    root_key = Ed25519PrivateKey.generate()
    op_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    cert = create_operational_certificate(
        root_key=root_key,
        operational_public_key=op_key.public_key(),
        sequence=1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )
    return root_key, op_key, cert


@pytest.fixture
def well_known_document(
    node_credentials: tuple[Ed25519PrivateKey, Ed25519PrivateKey, OperationalCertificate],
) -> dict[str, Any]:
    root_key, op_key, cert = node_credentials
    node_id = derive_node_id(root_key.public_key())
    doc: dict[str, object] = {
        "kind": "well_known",
        "node_id": node_id,
        "domain": "example.com",
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": cert.to_dict(),
        "endpoints": {
            "gossip": "https://example.com/lattice/v1/gossip",
            "messages": "https://example.com/lattice/v1/messages",
        },
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return sign_with_root(root_key, doc, "well_known")


class TestWellKnownResolver:
    def test_resolve_valid_document(self, well_known_document: dict[str, Any]) -> None:
        transport = MagicMock(spec=OutboundTransport)
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "application/vnd.lattice+json; version=1"}
        response.data = json.dumps(well_known_document).encode("utf-8")
        transport.request.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                resolver = WellKnownResolver(transport, repo)
                doc = resolver.resolve("example.com")
                assert doc["domain"] == "example.com"
            finally:
                conn.close()

    def test_domain_mismatch(self, well_known_document: dict[str, Any]) -> None:
        transport = MagicMock(spec=OutboundTransport)
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "application/vnd.lattice+json; version=1"}
        response.data = json.dumps(well_known_document).encode("utf-8")
        transport.request.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                resolver = WellKnownResolver(transport, repo)
                with pytest.raises(ResolutionError):
                    resolver.resolve("other.com")
            finally:
                conn.close()

    def test_pin_persists_document(self, well_known_document: dict[str, Any]) -> None:
        transport = MagicMock(spec=OutboundTransport)
        response = MagicMock()
        response.status = 200
        response.headers = {"Content-Type": "application/vnd.lattice+json; version=1"}
        response.data = json.dumps(well_known_document).encode("utf-8")
        transport.request.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                resolver = WellKnownResolver(transport, repo)
                resolver.pin("example.com")
                pin = resolver.get_pin("example.com")
                assert pin is not None
                assert pin["domain"] == "example.com"
            finally:
                conn.close()


class TestResolveAddress:
    def test_canonical_address_no_lookup(self) -> None:
        transport = MagicMock(spec=OutboundTransport)
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                resolver = WellKnownResolver(transport, repo)
                username, node_id = resolve_address("alice@lat_abc234", resolver)
                assert username == "alice"
                assert node_id == "lat_abc234"
                transport.request.assert_not_called()
            finally:
                conn.close()
