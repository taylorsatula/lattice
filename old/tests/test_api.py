"""Tests for the Lattice FastAPI application."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lattice.api import create_app
from lattice.config import Config
from lattice.crypto import public_key_b64url
from lattice.identity import OperationalIdentity, sign_with_root, verify_object
from lattice.peers import PeerState
from lattice.protocol.constants import MEDIA_TYPE
from lattice.runtime import RuntimeCoordinator, RuntimeSettings
from lattice.storage.cache import initialize_cache_db
from lattice.storage.connection import open_connection
from lattice.storage.migrations import migrate
from lattice.storage.repositories import PeerRepository


@pytest.fixture
def admin_bearer() -> str:
    return "lab_test_" + "x" * 32


@pytest.fixture
def webhook_bearer() -> str:
    return "lwb_test_" + "x" * 32


@pytest.fixture
def api_config() -> Config:
    return Config(
        {
            "node": {"domain": "example.com"},
            "server": {
                "bind_host": "127.0.0.1",
                "bind_port": 1113,
                "public_base_url": "https://example.com",
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
            "rate_limit": {"messages_per_minute": 2, "gossip_per_minute": 2},
            "network": {"mode": "public"},
            "message": {"default_ttl_seconds": 86400},
        }
    )


@pytest.fixture
def api_dirs() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def runtime(
    api_dirs: Path,
    root_key: Ed25519PrivateKey,
    op_key: Ed25519PrivateKey,
    operational_certificate: Any,
    operational_identity: OperationalIdentity,
    api_config: Config,
    admin_bearer: str,
    webhook_bearer: str,
) -> Generator[RuntimeCoordinator, None, None]:
    durable_path = api_dirs / "durable.db"
    cache_path = api_dirs / "cache.db"
    migrate(durable_path)
    durable_conn = open_connection(durable_path)
    cache_conn = initialize_cache_db(cache_path)

    well_known = {
        "kind": "well_known",
        "node_id": operational_identity.node_id,
        "domain": "example.com",
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": operational_certificate.to_dict(),
        "endpoints": {
            "gossip": "https://example.com/lattice/v1/gossip",
            "messages": "https://example.com/lattice/v1/messages",
        },
        "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    well_known = sign_with_root(root_key, well_known, "well_known")

    runtime = RuntimeCoordinator(
        config=api_config,
        identity=operational_identity,
        root_public_key=root_key.public_key(),
        durable_conn=durable_conn,
        cache_conn=cache_conn,
        well_known_document=well_known,
        admin_bearer=admin_bearer,
        webhook_bearer=webhook_bearer,
        settings=RuntimeSettings(
            delivery_interval_seconds=60.0,
            webhook_interval_seconds=60.0,
            gossip_interval_seconds=60.0,
            verify_interval_seconds=60.0,
            refresh_interval_seconds=60.0,
            expiry_interval_seconds=60.0,
        ),
    )
    try:
        yield runtime
    finally:
        runtime.stop(timeout=5.0)
        durable_conn.close()
        cache_conn.close()


@pytest.fixture
def client(runtime: RuntimeCoordinator) -> Generator[TestClient, None, None]:
    app = create_app(runtime)
    with TestClient(app) as tc:
        yield tc


class TestPublicRoutes:
    def test_well_known(self, client: TestClient, runtime: RuntimeCoordinator) -> None:
        response = client.get("/.well-known/lattice")
        assert response.status_code == 200
        assert response.headers["content-type"] == MEDIA_TYPE
        assert response.json()["node_id"] == runtime.node_id

    def test_gossip_accepts_cards(
        self,
        client: TestClient,
        operational_identity: OperationalIdentity,
        root_key: Ed25519PrivateKey,
    ) -> None:
        card = {
            "kind": "peer_card",
            "node_id": "lat_remote",
            "domain": "remote.example.com",
            "root_public_key": public_key_b64url(root_key.public_key()),
            "operational_certificate": operational_identity.certificate.to_dict(),
            "endpoints": {
                "gossip": "https://remote.example.com/lattice/v1/gossip",
                "messages": "https://remote.example.com/lattice/v1/messages",
            },
            "sequence": 1,
            "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (datetime.now(UTC) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "signature": "invalid-signature-for-test",
        }
        response = client.post(
            "/lattice/v1/gossip",
            json={"cards": [card]},
            headers={"Content-Type": MEDIA_TYPE},
        )
        assert response.status_code == 200
        body = response.json()
        assert "accepted" in body
        assert "rejected" in body

    def test_gossip_rate_limit(self, client: TestClient) -> None:
        for _ in range(3):
            response = client.post(
                "/lattice/v1/gossip",
                json={"cards": []},
                headers={"Content-Type": MEDIA_TYPE},
            )
        assert response.status_code == 429

    def test_gossip_rate_limit_keyed_by_sender_identity(
        self,
        client: TestClient,
        other_node: Any,
    ) -> None:
        """docs/PROTOCOL.md §5.2: when the first card verifies as the sender's
        own signed peer card, gossip is rate limited by that node ID — two
        different source IPs sharing one identity share one bucket."""
        from tests.test_topology import make_peer_card

        root_key, _op_key, _cert, op_identity = other_node
        sender_card = make_peer_card(root_key, op_identity, "sender.example.com")
        filler = dict(sender_card)
        for _ in range(3):
            response = client.post(
                "/lattice/v1/gossip",
                json={"cards": [sender_card, filler], "introduced_by": op_identity.node_id},
                headers={"Content-Type": MEDIA_TYPE},
            )
        assert response.status_code == 429

    def test_gossip_invalid_sender_card_falls_back_to_ip(
        self,
        client: TestClient,
    ) -> None:
        """Unverifiable first cards fall back to IP-keyed buckets, so garbage
        traffic cannot exhaust identity buckets."""
        bad_card = {"kind": "peer_card", "node_id": "lat_bogus"}
        for _ in range(3):
            response = client.post(
                "/lattice/v1/gossip",
                json={"cards": [bad_card]},
                headers={"Content-Type": MEDIA_TYPE},
            )
        assert response.status_code == 429

    def test_receive_message(
        self,
        client: TestClient,
        runtime: RuntimeCoordinator,
        root_key: Ed25519PrivateKey,
        operational_identity: OperationalIdentity,
        operational_certificate: Any,
    ) -> None:
        peer_repo = PeerRepository(runtime._durable_conn)
        peer_repo.ensure_root_history(
            operational_identity.node_id,
            public_key_b64url(root_key.public_key()),
            datetime.now(UTC),
        )
        runtime._pin_repo.upsert(
            domain="example.com",
            node_id=operational_identity.node_id,
            root_public_key=public_key_b64url(root_key.public_key()),
            operational_certificate=operational_certificate.to_dict(),
            endpoints={
                "gossip": "https://example.com/lattice/v1/gossip",
                "messages": "https://example.com/lattice/v1/messages",
            },
        )
        signed = runtime.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_remote",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        response = client.post(
            "/lattice/v1/messages",
            json=signed,
            headers={"Content-Type": MEDIA_TYPE},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["kind"] == "receipt"
        assert body["message_id"] == "msg-1"

    def test_receive_message_rejects_unknown_sender(
        self,
        client: TestClient,
        runtime: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        signed = runtime.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_remote",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        response = client.post(
            "/lattice/v1/messages",
            json=signed,
            headers={"Content-Type": MEDIA_TYPE},
        )
        assert response.status_code == 401

    def test_blocked_sender_gets_signed_rejected_receipt(
        self,
        client: TestClient,
        runtime: RuntimeCoordinator,
        root_key: Ed25519PrivateKey,
        operational_identity: OperationalIdentity,
        operational_certificate: Any,
    ) -> None:
        """docs/PROTOCOL.md §8: a signature-verified message from a blocked
        sender gets a final signed rejected receipt with HTTP 202."""
        peer_repo = PeerRepository(runtime._durable_conn)
        peer_repo.ensure_root_history(
            operational_identity.node_id,
            public_key_b64url(root_key.public_key()),
            datetime.now(UTC),
        )
        runtime._pin_repo.upsert(
            domain="example.com",
            node_id=operational_identity.node_id,
            root_public_key=public_key_b64url(root_key.public_key()),
            operational_certificate=operational_certificate.to_dict(),
            endpoints={
                "gossip": "https://example.com/lattice/v1/gossip",
                "messages": "https://example.com/lattice/v1/messages",
            },
        )
        runtime._block_store.block(operational_identity.node_id, "abuse")
        signed = runtime.sign_local_message(
            message_id="msg-blocked",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_remote",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        response = client.post(
            "/lattice/v1/messages",
            json=signed,
            headers={"Content-Type": MEDIA_TYPE},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["kind"] == "receipt"
        assert body["status"] == "rejected"
        assert body["message_id"] == "msg-blocked"
        assert body["node_id"] == runtime.node_id
        # No custody was taken.
        assert runtime.inbound_service.get("msg-blocked") is None
        # The rejected receipt is root-of-trust verifiable.
        verify_object(
            operational_identity.public_key,
            body,
            "receipt",
        )


class TestAdminRoutes:
    def test_status_requires_bearer(self, client: TestClient) -> None:
        response = client.get("/lattice/v1/admin/status")
        assert response.status_code == 401

    def test_status_with_bearer(
        self, client: TestClient, admin_bearer: str, runtime: RuntimeCoordinator
    ) -> None:
        response = client.get(
            "/lattice/v1/admin/status",
            headers={"Authorization": f"Bearer {admin_bearer}"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["node_id"] == runtime.node_id
        assert body["ready"] is True

    def test_submit_message(
        self,
        client: TestClient,
        admin_bearer: str,
        runtime: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        runtime._peer_store.ensure_root_history("lat_remote", "pk", datetime.now(UTC))
        runtime._peer_store.create_peer(
            "lat_remote",
            state=PeerState.VERIFIED,
            domain="remote.example.com",
            current_certificate_sequence=1,
            endpoints={
                "gossip": "https://remote.example.com/lattice/v1/gossip",
                "messages": "https://remote.example.com/lattice/v1/messages",
            },
        )
        response = client.post(
            "/lattice/v1/admin/messages/submit",
            headers={"Authorization": f"Bearer {admin_bearer}"},
            json={
                "message_id": "msg-1",
                "from_address": f"user@{operational_identity.node_id}",
                "to_address": "bob@lat_remote",
                "content": "hello",
            },
        )
        assert response.status_code == 202
        body = response.json()
        assert body["message_id"] == "msg-1"
        row = runtime.outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["to_node_id"] == "lat_remote"

    def test_submit_backpressure(
        self,
        client: TestClient,
        admin_bearer: str,
        runtime: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        runtime._settings.max_pending_submissions = 1
        runtime._peer_store.ensure_root_history("lat_remote", "pk", datetime.now(UTC))
        runtime._peer_store.create_peer(
            "lat_remote",
            state=PeerState.VERIFIED,
            domain="remote.example.com",
            current_certificate_sequence=1,
            endpoints={
                "gossip": "https://remote.example.com/lattice/v1/gossip",
                "messages": "https://remote.example.com/lattice/v1/messages",
            },
        )
        first = client.post(
            "/lattice/v1/admin/messages/submit",
            headers={"Authorization": f"Bearer {admin_bearer}"},
            json={
                "message_id": "msg-1",
                "from_address": f"user@{operational_identity.node_id}",
                "to_address": "bob@lat_remote",
                "content": "hello",
            },
        )
        assert first.status_code == 202
        second = client.post(
            "/lattice/v1/admin/messages/submit",
            headers={"Authorization": f"Bearer {admin_bearer}"},
            json={
                "message_id": "msg-2",
                "from_address": f"user@{operational_identity.node_id}",
                "to_address": "bob@lat_remote",
                "content": "hello",
            },
        )
        assert second.status_code == 503
