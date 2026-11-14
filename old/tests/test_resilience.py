"""Resilience tests: cache loss, DNS outage, and operational rotation."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from lattice.cli import main
from lattice.protocol.signing import sign_message
from lattice.storage.cache import initialize_cache_db
from lattice.storage.repositories import CacheRepository


@pytest.fixture
def password() -> str:
    return "test-password-123"


class TestOperationalRotation:
    def test_rotation_preserves_node_id_and_updates_well_known(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            assert rc == 0

            manifest_before = json.loads((tmp_path / "identity.json").read_text(encoding="utf-8"))
            well_known_before = json.loads(
                (tmp_path / "well-known.json").read_text(encoding="utf-8")
            )

            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(["--config", str(config_path), "keys", "rotate-operational"])
            assert rc == 0

            manifest_after = json.loads((tmp_path / "identity.json").read_text(encoding="utf-8"))
            well_known_after = json.loads(
                (tmp_path / "well-known.json").read_text(encoding="utf-8")
            )

            assert manifest_after["node_id"] == manifest_before["node_id"]
            assert well_known_after["node_id"] == well_known_before["node_id"]
            assert (
                well_known_after["operational_certificate"]["sequence"]
                > well_known_before["operational_certificate"]["sequence"]
            )


class TestCacheDeletion:
    def test_message_delivery_survives_cache_deletion(
        self,
        two_nodes: tuple[Any, Any],
    ) -> None:
        alpha, beta = two_nodes

        # Locate and delete beta's cache database, then reopen it fresh.
        row = beta._cache_conn.execute("PRAGMA database_list").fetchone()
        assert row is not None
        cache_path = Path(row[2])
        beta._cache_conn.close()
        cache_path.unlink()

        beta._cache_conn = initialize_cache_db(cache_path)
        beta._cache_repo = CacheRepository(beta._cache_conn)

        msg = sign_message(
            alpha.identity,
            {
                "kind": "message",
                "message_id": "msg-cache",
                "from_address": "alice@alpha.example.com",
                "to_address": "bob@beta.example.com",
                "content": "after cache deletion",
                "priority": "normal",
                "ttl_seconds": 86400,
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        alpha.outbound_service.submit(msg, beta.node_id)
        alpha._run_outbound_delivery()

        row = beta.inbound_service.get("msg-cache")
        assert row is not None
        assert row["content"] == "after cache deletion"


class TestDNSOutage:
    def test_delivery_uses_pinned_peer_during_dns_outage(
        self,
        two_nodes: tuple[Any, Any],
    ) -> None:
        alpha, beta = two_nodes

        # Simulate DNS outage: alpha's resolver transport cannot reach beta's
        # well-known endpoint, but alpha already has beta as a pinned peer.
        class _FailingTransport:
            def request(self, *args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("DNS outage")

        alpha._resolver._transport = _FailingTransport()

        msg = sign_message(
            alpha.identity,
            {
                "kind": "message",
                "message_id": "msg-dns",
                "from_address": "alice@alpha.example.com",
                "to_address": "bob@beta.example.com",
                "content": "during dns outage",
                "priority": "normal",
                "ttl_seconds": 86400,
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        alpha.outbound_service.submit(msg, beta.node_id)
        alpha._run_outbound_delivery()

        row = beta.inbound_service.get("msg-dns")
        assert row is not None
        assert row["content"] == "during dns outage"
