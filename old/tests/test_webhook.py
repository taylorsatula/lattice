"""Tests for webhook delivery, idempotency, and response classification."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import urllib3

from lattice.storage.connection import open_connection
from lattice.storage.migrations import migrate
from lattice.storage.repositories import (
    InboundMessageRepository,
    PeerRepository,
    WebhookStateRepository,
)
from lattice.webhook import WebhookDeliveryService


@pytest.fixture
def webhook_repo(tmp_path_factory: Any) -> Generator[WebhookStateRepository, None, None]:
    tmp = tmp_path_factory.mktemp("webhook")
    db_path = tmp / "durable.db"
    migrate(db_path)
    conn = open_connection(db_path)
    peer_repo = PeerRepository(conn)
    peer_repo.ensure_root_history("lat_sender", "pk", datetime.now(UTC))
    inbound_repo = InboundMessageRepository(conn)
    inbound_repo.create(
        message_id="msg-1",
        from_node_id="lat_sender",
        from_address="sender@example.com",
        to_address="recipient@example.com",
        content="hello",
        extension=None,
        message_json={"kind": "message", "message_id": "msg-1"},
        priority="normal",
        receipt={"kind": "receipt", "message_id": "msg-1"},
        received_at=datetime.now(UTC),
    )
    try:
        yield WebhookStateRepository(conn)
    finally:
        conn.close()


@pytest.fixture
def service(webhook_repo: WebhookStateRepository) -> WebhookDeliveryService:
    return WebhookDeliveryService(webhook_repo)


class TestResponseClassification:
    def test_2xx_is_success(self, service: WebhookDeliveryService) -> None:
        result = service.classify_status(200)
        assert result.success is True
        assert result.retryable is False

    def test_429_is_retryable(self, service: WebhookDeliveryService) -> None:
        result = service.classify_status(429)
        assert result.success is False
        assert result.retryable is True

    def test_5xx_is_retryable(self, service: WebhookDeliveryService) -> None:
        result = service.classify_status(503)
        assert result.success is False
        assert result.retryable is True

    def test_4xx_is_terminal(self, service: WebhookDeliveryService) -> None:
        result = service.classify_status(400)
        assert result.success is False
        assert result.retryable is False


class TestDeliver:
    def test_success_stores_state(
        self,
        service: WebhookDeliveryService,
        webhook_repo: WebhookStateRepository,
    ) -> None:
        response = MagicMock(spec=urllib3.BaseHTTPResponse)
        response.status = 202
        response.data = b"ok"

        with patch.object(service._pool, "urlopen", return_value=response):
            result = service.deliver("https://example.com/webhook", "msg-1", {"x": 1})

        assert result.success is True
        state = webhook_repo.get("msg-1")
        assert state is not None
        assert state["last_status_code"] == 202
        assert state["last_error"] is None

    def test_retryable_failure(
        self,
        service: WebhookDeliveryService,
        webhook_repo: WebhookStateRepository,
    ) -> None:
        response = MagicMock(spec=urllib3.BaseHTTPResponse)
        response.status = 503
        response.data = b"unavailable"

        with patch.object(service._pool, "urlopen", return_value=response):
            result = service.deliver("https://example.com/webhook", "msg-1", {"x": 1})

        assert result.success is False
        assert result.retryable is True
        assert result.status_code == 503

    def test_terminal_failure(
        self,
        service: WebhookDeliveryService,
        webhook_repo: WebhookStateRepository,
    ) -> None:
        response = MagicMock(spec=urllib3.BaseHTTPResponse)
        response.status = 400
        response.data = b"bad request"

        with patch.object(service._pool, "urlopen", return_value=response):
            result = service.deliver("https://example.com/webhook", "msg-1", {"x": 1})

        assert result.success is False
        assert result.retryable is False
        assert result.status_code == 400

    def test_network_error_is_retryable(
        self,
        service: WebhookDeliveryService,
        webhook_repo: WebhookStateRepository,
    ) -> None:
        with patch.object(
            service._pool,
            "urlopen",
            side_effect=urllib3.exceptions.HTTPError("timeout"),
        ):
            result = service.deliver("https://example.com/webhook", "msg-1", {"x": 1})

        assert result.success is False
        assert result.retryable is True
        assert result.status_code is None

    def test_idempotency_key_is_stable(
        self,
        service: WebhookDeliveryService,
    ) -> None:
        key1 = service._idempotency_key("msg-1")
        key2 = service._idempotency_key("msg-1")
        assert key1 == key2
        assert len(key1) == 32
