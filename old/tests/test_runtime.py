"""Tests for the autonomous runtime coordinator."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.config import Config
from lattice.crypto import public_key_b64url
from lattice.identity import OperationalIdentity, sign_with_root
from lattice.peers import PeerState
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
def runtime_config() -> Config:
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
            "rate_limit": {"messages_per_minute": 60, "gossip_per_minute": 30},
            "network": {"mode": "public"},
            "message": {"default_ttl_seconds": 86400},
        }
    )


@pytest.fixture
def runtime_dirs() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def runtime_coordinator(
    runtime_dirs: Path,
    root_key: Ed25519PrivateKey,
    op_key: Ed25519PrivateKey,
    operational_certificate: Any,
    operational_identity: OperationalIdentity,
    runtime_config: Config,
    admin_bearer: str,
    webhook_bearer: str,
) -> Generator[RuntimeCoordinator, None, None]:
    durable_path = runtime_dirs / "durable.db"
    cache_path = runtime_dirs / "cache.db"
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
        config=runtime_config,
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


class TestLifecycle:
    def test_runtime_is_ready(self, runtime_coordinator: RuntimeCoordinator) -> None:
        assert runtime_coordinator.is_ready() is True

    def test_runtime_not_ready_without_well_known(
        self,
        runtime_dirs: Path,
        root_key: Ed25519PrivateKey,
        operational_identity: OperationalIdentity,
        runtime_config: Config,
        admin_bearer: str,
        webhook_bearer: str,
    ) -> None:
        migrate(runtime_dirs / "durable.db")
        durable_conn = open_connection(runtime_dirs / "durable.db")
        cache_conn = initialize_cache_db(runtime_dirs / "cache.db")
        runtime = RuntimeCoordinator(
            config=runtime_config,
            identity=operational_identity,
            root_public_key=root_key.public_key(),
            durable_conn=durable_conn,
            cache_conn=cache_conn,
            well_known_document={},
            admin_bearer=admin_bearer,
            webhook_bearer=webhook_bearer,
        )
        assert runtime.is_ready() is False
        runtime.stop(timeout=1.0)
        durable_conn.close()
        cache_conn.close()

    def test_runtime_start_stop(self, runtime_coordinator: RuntimeCoordinator) -> None:
        runtime_coordinator.start()
        assert runtime_coordinator.is_running is True
        runtime_coordinator.stop()
        assert runtime_coordinator.is_running is False


class TestMessageHandling:
    def test_sign_local_message(
        self,
        runtime_coordinator: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        signed = runtime_coordinator.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_other",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        assert signed["kind"] == "message"
        assert signed["message_id"] == "msg-1"
        assert "signature" in signed

    def test_verify_inbound_message(
        self,
        runtime_coordinator: RuntimeCoordinator,
        root_key: Ed25519PrivateKey,
        operational_identity: OperationalIdentity,
        operational_certificate: Any,
    ) -> None:
        # Seed peer root history and domain pin so verification can locate keys.
        peer_repo = PeerRepository(runtime_coordinator._durable_conn)
        peer_repo.ensure_root_history(
            operational_identity.node_id,
            public_key_b64url(root_key.public_key()),
            datetime.now(UTC),
        )
        runtime_coordinator._pin_repo.upsert(
            domain="example.com",
            node_id=operational_identity.node_id,
            root_public_key=public_key_b64url(root_key.public_key()),
            operational_certificate=operational_certificate.to_dict(),
            endpoints={
                "gossip": "https://example.com/lattice/v1/gossip",
                "messages": "https://example.com/lattice/v1/messages",
            },
        )
        signed = runtime_coordinator.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_other",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        sender, cold = runtime_coordinator.verify_inbound_message(signed)
        assert sender == operational_identity.node_id
        assert cold is False

    def test_verify_inbound_message_rejects_blocked(
        self,
        runtime_coordinator: RuntimeCoordinator,
        root_key: Ed25519PrivateKey,
        operational_identity: OperationalIdentity,
        operational_certificate: Any,
    ) -> None:
        peer_repo = PeerRepository(runtime_coordinator._durable_conn)
        peer_repo.ensure_root_history(
            operational_identity.node_id,
            public_key_b64url(root_key.public_key()),
            datetime.now(UTC),
        )
        runtime_coordinator._pin_repo.upsert(
            domain="example.com",
            node_id=operational_identity.node_id,
            root_public_key=public_key_b64url(root_key.public_key()),
            operational_certificate=operational_certificate.to_dict(),
            endpoints={
                "gossip": "https://example.com/lattice/v1/gossip",
                "messages": "https://example.com/lattice/v1/messages",
            },
        )
        runtime_coordinator._block_store.block(operational_identity.node_id, "test block")
        signed = runtime_coordinator.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_other",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        with pytest.raises(RuntimeError, match="blocked"):
            runtime_coordinator.verify_inbound_message(signed)


class TestDeliveryTasks:
    def test_run_outbound_delivery_success(
        self,
        runtime_coordinator: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        signed = runtime_coordinator.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_remote",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        runtime_coordinator.outbound_service.submit(signed, "lat_remote")

        # Seed a peer endpoint for the destination.
        runtime_coordinator._peer_store.ensure_root_history("lat_remote", "pk", datetime.now(UTC))
        runtime_coordinator._peer_store.create_peer(
            "lat_remote",
            state=PeerState.VERIFIED,
            domain="remote.example.com",
            current_certificate_sequence=1,
            endpoints={
                "gossip": "https://remote.example.com/lattice/v1/gossip",
                "messages": "https://remote.example.com/lattice/v1/messages",
            },
        )

        receipt_bytes = (
            b'{"kind":"receipt","message_id":"msg-1","node_id":"lat_remote","status":"accepted"}'
        )
        response = MagicMock()
        response.status = 202
        response.data = receipt_bytes
        with patch.object(runtime_coordinator.transport, "request", return_value=response):
            runtime_coordinator._run_outbound_delivery()

        row = runtime_coordinator.outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["status"] == "delivered"

    def test_run_webhook_delivery_success(
        self,
        runtime_coordinator: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        signed = runtime_coordinator.sign_local_message(
            message_id="msg-1",
            from_address=f"user@{operational_identity.node_id}",
            to_address="bob@lat_remote",
            content="hello",
            priority="normal",
            ttl_seconds=86400,
        )
        runtime_coordinator.inbound_service.accept(signed, operational_identity.node_id)

        result = MagicMock()
        result.success = True
        result.retryable = False
        with patch.object(runtime_coordinator.webhook_service, "deliver", return_value=result):
            runtime_coordinator._run_webhook_delivery()

        row = runtime_coordinator.inbound_service.get("msg-1")
        assert row is not None
        assert row["status"] == "delivered"


class TestSubmissionBackpressure:
    def test_allow_submission_respects_threshold(
        self,
        runtime_coordinator: RuntimeCoordinator,
        operational_identity: OperationalIdentity,
    ) -> None:
        runtime_coordinator._settings.max_pending_submissions = 2
        for i in range(2):
            signed = runtime_coordinator.sign_local_message(
                message_id=f"msg-{i}",
                from_address=f"user@{operational_identity.node_id}",
                to_address="bob@lat_remote",
                content="hello",
                priority="normal",
                ttl_seconds=86400,
            )
            runtime_coordinator.outbound_service.submit(signed, "lat_remote")
        assert runtime_coordinator.allow_submission() is False
