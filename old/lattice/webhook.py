"""Webhook delivery, idempotency, and retry classification for inbound messages."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import urllib3

from lattice.storage.repositories import WebhookStateRepository


class WebhookError(RuntimeError):
    """Raised when a webhook delivery operation fails."""


@dataclass(frozen=True)
class WebhookResult:
    """Outcome of a single webhook delivery attempt."""

    success: bool
    retryable: bool
    status_code: int | None
    error: str | None


class Clock(Protocol):
    """Injectable clock for deterministic testing."""

    def now(self) -> datetime: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class WebhookDeliveryService:
    """Deliver accepted inbound messages to a configured webhook URL.

    Uses stable idempotency keys so retries are recognized by the receiver.
    Classifies HTTP responses into success, retryable, and terminal failures.
    """

    def __init__(
        self,
        repository: WebhookStateRepository,
        *,
        timeout: urllib3.Timeout | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._repo = repository
        self._timeout = timeout or urllib3.Timeout(connect=10.0, read=30.0)
        self._clock = clock or _SystemClock()
        self._pool = urllib3.PoolManager(timeout=self._timeout)

    def _idempotency_key(self, message_id: str) -> str:
        """Return a stable idempotency key for ``message_id``."""
        digest = hashlib.sha256(f"lattice-webhook:{message_id}".encode()).hexdigest()
        return digest[:32]

    def _headers(self, message_id: str, bearer_token: str | None) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json; charset=utf-8",
            "Idempotency-Key": self._idempotency_key(message_id),
        }
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"
        return headers

    def deliver(
        self,
        webhook_url: str,
        message_id: str,
        payload: dict[str, Any],
        *,
        bearer_token: str | None = None,
    ) -> WebhookResult:
        """Deliver ``payload`` to ``webhook_url``.

        Returns a :class:`WebhookResult` without raising on HTTP/network
        failures so the caller can drive retry logic.
        """
        idempotency_key = self._idempotency_key(message_id)
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        try:
            response = self._pool.urlopen(
                "POST",
                webhook_url,
                body=body,
                headers=self._headers(message_id, bearer_token),
                preload_content=True,
            )
        except urllib3.exceptions.HTTPError as exc:
            self._repo.upsert(message_id, idempotency_key, None, str(exc))
            return WebhookResult(
                success=False,
                retryable=True,
                status_code=None,
                error=str(exc),
            )

        status = response.status
        error: str | None = None
        try:
            response_body = response.data.decode("utf-8", errors="replace")[:256]
        except Exception as exc:
            response_body = str(exc)

        if 200 <= status < 300:
            self._repo.upsert(message_id, idempotency_key, status, None)
            return WebhookResult(
                success=True,
                retryable=False,
                status_code=status,
                error=None,
            )

        error = f"HTTP {status}: {response_body}"
        self._repo.upsert(message_id, idempotency_key, status, error)

        # 429 Too Many Requests and 5xx are retryable; other 4xx are terminal.
        retryable = status == 429 or status >= 500
        return WebhookResult(
            success=False,
            retryable=retryable,
            status_code=status,
            error=error,
        )

    def classify_status(self, status_code: int) -> WebhookResult:
        """Classify a status code without performing a request."""
        if 200 <= status_code < 300:
            return WebhookResult(
                success=True,
                retryable=False,
                status_code=status_code,
                error=None,
            )
        retryable = status_code == 429 or status_code >= 500
        return WebhookResult(
            success=False,
            retryable=retryable,
            status_code=status_code,
            error=f"HTTP {status_code}",
        )

    def close(self) -> None:
        self._pool.clear()
