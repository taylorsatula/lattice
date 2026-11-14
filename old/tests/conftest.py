"""Shared test fixtures for the Lattice v1 rewrite."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.crypto import public_key_b64url
from lattice.identity import (
    OperationalCertificate,
    OperationalIdentity,
    create_operational_certificate,
    derive_node_id,
    sign_with_root,
)
from lattice.network_policy import NetworkPolicy
from lattice.storage.cache import initialize_cache_db
from lattice.storage.connection import open_connection
from lattice.storage.migrations import migrate
from lattice.storage.repositories import (
    CacheRepository,
    DomainPinRepository,
    PeerRepository,
)
from lattice.transport import OutboundTransport

OtherNode = tuple[Ed25519PrivateKey, Ed25519PrivateKey, OperationalCertificate, OperationalIdentity]


# ---------------------------------------------------------------------------
# Integration-test helpers
# ---------------------------------------------------------------------------


class _FakeTransportResponse:
    def __init__(
        self,
        status: int,
        data: bytes,
        headers: dict[str, str],
        resolved_ip: str | None = None,
    ) -> None:
        self.status = status
        self.data = data
        self.headers = headers
        self.resolved_ip = resolved_ip


class _FakeTransport:
    """Routes HTTPS requests between in-memory Lattice nodes."""

    def __init__(self) -> None:
        self._apps: dict[str, Any] = {}
        self._well_known: dict[str, dict[str, Any]] = {}

    def register(self, domain: str, app: Any, well_known: dict[str, Any]) -> None:
        self._apps[domain.lower()] = app
        self._well_known[domain.lower()] = well_known

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> _FakeTransportResponse:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path

        if path == "/.well-known/lattice":
            doc = self._well_known.get(host)
            if doc is None:
                raise RuntimeError(f"no well-known for {host}")
            return _FakeTransportResponse(
                status=200,
                data=json.dumps(doc).encode("utf-8"),
                headers={"Content-Type": "application/vnd.lattice+json; version=1"},
            )

        client = self._apps.get(host)
        if client is None:
            raise RuntimeError(f"no app registered for {host}")

        response = client.request(method, path, content=body, headers=headers)
        return _FakeTransportResponse(
            status=response.status_code,
            data=response.content,
            headers=dict(response.headers),
        )


def _make_node(tmp_path: Path, domain: str, public_base_url: str) -> Any:
    """Create a fully initialized runtime for integration tests."""
    from lattice.config import Config
    from lattice.crypto import generate_private_key, public_key_b64url
    from lattice.identity import (
        OperationalIdentity,
        RootIdentity,
        create_operational_certificate,
        sign_with_root,
    )
    from lattice.runtime import RuntimeCoordinator
    from lattice.storage.cache import initialize_cache_db
    from lattice.storage.connection import open_connection

    root_key = generate_private_key()
    op_key = generate_private_key()
    root_identity = RootIdentity.from_public_key(root_key.public_key())
    node_id = root_identity.node_id
    now = datetime.now(UTC)
    cert = create_operational_certificate(
        root_key=root_key,
        operational_public_key=op_key.public_key(),
        sequence=1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )
    identity = OperationalIdentity(node_id=node_id, private_key=op_key, certificate=cert)

    config = Config(
        {
            "node": {"domain": domain},
            "server": {
                "bind_host": "127.0.0.1",
                "bind_port": 1113,
                "public_base_url": public_base_url,
                "workers": 1,
            },
            "gossip": {
                "guard_slots": 1,
                "discovery_slots": 1,
                "candidate_ttl_seconds": 86400,
            },
            "webhook": {
                "url": "http://127.0.0.1:8080/lattice/webhook",
                "bearer_credential_name": "webhook_bearer",
            },
            "rate_limit": {"messages_per_minute": 60, "gossip_per_minute": 30},
            "network": {"mode": "public"},
            "message": {"default_ttl_seconds": 86400},
        }
    )

    base = public_base_url.rstrip("/")
    well_known = sign_with_root(
        root_key,
        {
            "kind": "well_known",
            "node_id": node_id,
            "domain": domain,
            "root_public_key": public_key_b64url(root_key.public_key()),
            "operational_certificate": cert.to_dict(),
            "endpoints": {
                "gossip": f"{base}/lattice/v1/gossip",
                "messages": f"{base}/lattice/v1/messages",
            },
            "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "well_known",
    )

    durable_path = tmp_path / f"{domain}.durable.db"
    cache_path = tmp_path / f"{domain}.cache.db"
    migrate(durable_path)
    durable_conn = open_connection(durable_path)
    cache_conn = initialize_cache_db(cache_path)

    runtime = RuntimeCoordinator(
        config=config,
        identity=identity,
        root_public_key=root_key.public_key(),
        durable_conn=durable_conn,
        cache_conn=cache_conn,
        well_known_document=well_known,
        admin_bearer="admin",
        webhook_bearer="webhook",
    )
    return runtime


@pytest.fixture
def two_nodes() -> Generator[tuple[Any, Any], None, None]:
    """Two fully wired runtimes ready to exchange messages."""
    from fastapi.testclient import TestClient

    from lattice.api import create_app
    from lattice.crypto import public_key_b64url
    from lattice.peers import PeerState
    from lattice.storage.repositories import DomainPinRepository

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        alpha = _make_node(tmp_path, "alpha.example.com", "https://alpha.example.com")
        beta = _make_node(tmp_path, "beta.example.com", "https://beta.example.com")

        alpha_app = create_app(alpha)
        beta_app = create_app(beta)

        transport = _FakeTransport()
        transport.register("alpha.example.com", TestClient(alpha_app), alpha.well_known_document)
        transport.register("beta.example.com", TestClient(beta_app), beta.well_known_document)

        for runtime in (alpha, beta):
            runtime._transport = transport
            runtime._resolver._transport = transport

        # Seed each node as a verified peer and domain pin of the other.
        for a, b in ((alpha, beta), (beta, alpha)):
            a._peer_store.ensure_root_history(
                b.node_id, public_key_b64url(b._root_public_key), datetime.now(UTC)
            )
            a._peer_store.create_peer(
                b.node_id,
                state=PeerState.VERIFIED,
                domain=b.config.domain,
                current_certificate_sequence=1,
                endpoints={
                    "gossip": f"https://{b.config.domain}/lattice/v1/gossip",
                    "messages": f"https://{b.config.domain}/lattice/v1/messages",
                },
            )
            pin_repo = DomainPinRepository(a._durable_conn)
            pin_repo.upsert(
                domain=b.config.domain,
                node_id=b.node_id,
                root_public_key=public_key_b64url(b._root_public_key),
                operational_certificate=b.identity.certificate.to_dict(),
                endpoints={
                    "gossip": f"https://{b.config.domain}/lattice/v1/gossip",
                    "messages": f"https://{b.config.domain}/lattice/v1/messages",
                },
            )

        yield alpha, beta

        for client in transport._apps.values():
            client.close()


@pytest.fixture
def other_root_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def other_node(
    other_root_key: Ed25519PrivateKey,
) -> OtherNode:
    op_key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    cert = create_operational_certificate(
        root_key=other_root_key,
        operational_public_key=op_key.public_key(),
        sequence=1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )
    op_identity = OperationalIdentity(
        node_id=cert.node_id,
        private_key=op_key,
        certificate=cert,
    )
    return other_root_key, op_key, cert, op_identity


@pytest.fixture
def tmp_db() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def root_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def op_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def operational_certificate(
    root_key: Ed25519PrivateKey,
    op_key: Ed25519PrivateKey,
) -> OperationalCertificate:
    now = datetime.now(UTC)
    return create_operational_certificate(
        root_key=root_key,
        operational_public_key=op_key.public_key(),
        sequence=1,
        valid_from=now,
        valid_until=now + timedelta(days=30),
    )


@pytest.fixture
def operational_identity(
    op_key: Ed25519PrivateKey,
    operational_certificate: OperationalCertificate,
) -> OperationalIdentity:
    return OperationalIdentity(
        node_id=operational_certificate.node_id,
        private_key=op_key,
        certificate=operational_certificate,
    )


@pytest.fixture
def well_known_document(
    root_key: Ed25519PrivateKey,
    operational_certificate: OperationalCertificate,
) -> dict[str, Any]:
    node_id = derive_node_id(root_key.public_key())
    doc: dict[str, object] = {
        "kind": "well_known",
        "node_id": node_id,
        "domain": "example.com",
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": operational_certificate.to_dict(),
        "endpoints": {
            "gossip": "https://example.com/lattice/v1/gossip",
            "messages": "https://example.com/lattice/v1/messages",
        },
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return sign_with_root(root_key, doc, "well_known")


@pytest.fixture
def mock_transport() -> MagicMock:
    return MagicMock(spec=OutboundTransport)


@pytest.fixture
def public_network_policy() -> NetworkPolicy:
    return NetworkPolicy.public()


@pytest.fixture
def peer_repository(tmp_db: Path) -> Generator[PeerRepository, None, None]:
    migrate(tmp_db / "durable.db")
    conn = open_connection(tmp_db / "durable.db")
    try:
        yield PeerRepository(conn)
    finally:
        conn.close()


@pytest.fixture
def cache_repository(tmp_db: Path) -> Generator[CacheRepository, None, None]:
    conn = initialize_cache_db(tmp_db / "cache.db")
    try:
        yield CacheRepository(conn)
    finally:
        conn.close()


@pytest.fixture
def domain_pin_repository(tmp_db: Path) -> Generator[DomainPinRepository, None, None]:
    migrate(tmp_db / "durable.db")
    conn = open_connection(tmp_db / "durable.db")
    try:
        yield DomainPinRepository(conn)
    finally:
        conn.close()
