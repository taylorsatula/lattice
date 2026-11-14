"""End-to-end integration tests for Lattice v1."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from lattice.protocol.signing import sign_message


class TestDirectMessage:
    def test_alpha_sends_message_to_beta(self, two_nodes: tuple[Any, Any]) -> None:
        alpha, beta = two_nodes

        msg = sign_message(
            alpha.identity,
            {
                "kind": "message",
                "message_id": "msg-1",
                "from_address": "alice@alpha.example.com",
                "to_address": "bob@beta.example.com",
                "content": "hello beta",
                "priority": "normal",
                "ttl_seconds": 86400,
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        alpha.outbound_service.submit(msg, beta.node_id)
        alpha._run_outbound_delivery()

        row = beta.inbound_service.get("msg-1")
        assert row is not None
        assert row["from_node_id"] == alpha.node_id
        assert row["content"] == "hello beta"

    def test_cold_sender_returns_503(self, two_nodes: tuple[Any, Any]) -> None:
        """A message from an unknown sender gets 503 Service Unavailable.

        The receiver queues the domain for background resolution and asks
        the sender to retry later. The sender retains its own outbound queue.
        No receiver-side staging or provisional receipt exists.
        """
        alpha, beta = two_nodes
        # Remove alpha's pin from beta so the sender is unknown.
        beta._pin_repo.delete("alpha.example.com")

        msg = sign_message(
            alpha.identity,
            {
                "kind": "message",
                "message_id": "msg-2",
                "from_address": "alice@alpha.example.com",
                "to_address": "bob@beta.example.com",
                "content": "hello beta",
                "priority": "normal",
                "ttl_seconds": 86400,
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        )
        alpha.outbound_service.submit(msg, beta.node_id)
        alpha._run_outbound_delivery()

        # Sender got rejected — message stays in alpha's outbound queue.
        row_alpha = alpha.outbound_service._repo.get("msg-2")
        assert row_alpha is not None
        assert row_alpha["status"] == "pending"

        # Receiver never accepted it — no inbound row, no staging.
        assert beta.inbound_service.get("msg-2") is None
