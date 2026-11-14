"""Outbound/inbound custody, priority queue, retry, expiry, and erasure."""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

from lattice.identity import OperationalIdentity
from lattice.protocol.constants import (
    MAX_TTL_SECONDS,
)
from lattice.protocol.models import Message, Receipt
from lattice.protocol.signing import sign_receipt
from lattice.storage.repositories import (
    InboundMessageRepository,
    OutboundMessageRepository,
    PeerRepository,
)


class CustodyError(ValueError):
    """Raised when a custody operation is invalid."""


class Clock(Protocol):
    """Injectable clock for deterministic testing."""

    def now(self) -> datetime: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass
class RetryPolicy:
    """Bounded exponential backoff with jitter."""

    max_attempts: int = 10
    base_delay_seconds: float = 60.0
    max_delay_seconds: float = 86400.0
    jitter_fraction: float = 0.25

    def next_attempt_at(self, attempt_count: int, now: datetime) -> datetime:
        """Return the next attempt time for ``attempt_count`` (1-based)."""
        if attempt_count < 1:
            attempt_count = 1
        delay = self.base_delay_seconds * (2 ** (attempt_count - 1))
        delay = min(delay, self.max_delay_seconds)
        jitter = delay * self.jitter_fraction * (random.random() * 2 - 1)
        return now + timedelta(seconds=delay + jitter)

    def should_retry(self, attempt_count: int) -> bool:
        return attempt_count < self.max_attempts


# ---------------------------------------------------------------------------
# Outbound custody
# ---------------------------------------------------------------------------


class OutboundMessageService:
    """Local custody of messages we are trying to deliver to remote nodes."""

    def __init__(
        self,
        repository: OutboundMessageRepository,
        peer_repository: PeerRepository,
        retry_policy: RetryPolicy | None = None,
        clock: Clock | None = None,
        erase_value: str = "[erased]",
        root_key_lookup: Callable[[str], str] | None = None,
    ) -> None:
        self._repo = repository
        self._peer_repo = peer_repository
        self._retry = retry_policy or RetryPolicy()
        self._clock = clock or _SystemClock()
        self._erase_value = erase_value
        # Returns the known b64url root public key for a node, or "" when
        # unknown. Used so root-history rows never carry placeholder keys when
        # the real key is already pinned.
        self._root_key_lookup = root_key_lookup

    def submit(
        self,
        message: dict[str, Any],
        to_node_id: str,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store a validated outbound message for delivery.

        ``message`` must be a signed Lattice message dict. The caller is
        responsible for signature and policy validation.
        """
        try:
            model = Message.model_validate(message)
        except Exception as exc:
            raise CustodyError(f"invalid message: {exc}") from exc

        ttl = ttl_seconds or model.ttl_seconds
        if ttl < 1 or ttl > MAX_TTL_SECONDS:
            raise CustodyError(f"ttl out of range: {ttl}")

        now = self._clock.now()
        expires_at = now + timedelta(seconds=ttl)

        root_public_key = self._root_key_lookup(to_node_id) if self._root_key_lookup else ""
        self._peer_repo.ensure_root_history(to_node_id, root_public_key, now)

        try:
            self._repo.create(
                message_id=model.message_id,
                to_node_id=to_node_id,
                to_address=model.to_address,
                from_address=model.from_address,
                content=model.content,
                extension=model.extension.model_dump(mode="json") if model.extension else None,
                message_json=message,
                priority=model.priority,
                ttl_seconds=ttl,
                created_at=now,
                expires_at=expires_at,
            )
        except Exception as exc:
            if "UNIQUE constraint" in str(exc):
                raise CustodyError(f"message already exists: {model.message_id}") from exc
            raise

    def claim_for_delivery(
        self,
        owner: str,
        *,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Atomically claim pending outbound messages for delivery."""
        return self._repo.claim_pending(owner, self._clock.now(), limit)

    def record_success(
        self,
        message_id: str,
        owner: str,
    ) -> bool:
        """Mark a leased outbound message as delivered and erase content."""
        return self._repo.mark_terminal(
            message_id,
            owner,
            "delivered",
            self._clock.now(),
            erase_content=True,
            erase_value=self._erase_value,
        )

    def record_failure(
        self,
        message_id: str,
        owner: str,
        *,
        retryable: bool = True,
    ) -> bool:
        """Record a delivery failure.

        If the failure is retryable and attempts remain, the lease is released
        and scheduled for retry. Otherwise the message is marked failed and
        its content is erased.
        """
        now = self._clock.now()
        row = self._repo.get(message_id)
        if row is None:
            raise CustodyError(f"message not found: {message_id}")

        if not retryable:
            return self._repo.mark_terminal(
                message_id,
                owner,
                "failed",
                now,
                erase_content=True,
                erase_value=self._erase_value,
            )

        attempt_count = int(row.get("attempt_count", 0))
        if not self._retry.should_retry(attempt_count):
            return self._repo.mark_terminal(
                message_id,
                owner,
                "failed",
                now,
                erase_content=True,
                erase_value=self._erase_value,
            )

        next_attempt = self._retry.next_attempt_at(attempt_count, now)
        return self._repo.release_lease(message_id, owner, next_attempt, now)

    def expire(self) -> list[str]:
        """Mark expired messages as terminal and erase content."""
        return self._repo.expire_messages(self._clock.now(), erase_value=self._erase_value)

    def list_pending(self) -> list[dict[str, Any]]:
        return self._repo.list_pending(self._clock.now())


# ---------------------------------------------------------------------------
# Inbound custody
# ---------------------------------------------------------------------------


class InboundMessageService:
    """Durable custody of accepted inbound messages and webhook retries."""

    def __init__(
        self,
        repository: InboundMessageRepository,
        peer_repository: PeerRepository,
        identity: OperationalIdentity,
        webhook_retry_policy: RetryPolicy | None = None,
        clock: Clock | None = None,
        erase_value: str = "[erased]",
        root_key_lookup: Callable[[str], str] | None = None,
    ) -> None:
        self._repo = repository
        self._peer_repo = peer_repository
        self._identity = identity
        self._retry = webhook_retry_policy or RetryPolicy(
            max_attempts=10,
            base_delay_seconds=30.0,
            max_delay_seconds=3600.0,
        )
        self._clock = clock or _SystemClock()
        self._erase_value = erase_value
        # Returns the known b64url root public key for a node, or "" when
        # unknown. Used so root-history rows never carry placeholder keys when
        # the real key is already pinned.
        self._root_key_lookup = root_key_lookup

    def accept(
        self,
        message: dict[str, Any],
        from_node_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Accept a validated inbound message into durable custody.

        If the same ``message_id`` has already been accepted from the same
        node, the byte-identical signed receipt is returned without mutation.
        """
        when = now or self._clock.now()
        try:
            model = Message.model_validate(message)
        except Exception as exc:
            raise CustodyError(f"invalid message: {exc}") from exc

        existing = self._repo.get_existing_receipt(model.message_id, from_node_id)
        if existing is not None:
            return existing

        self._peer_repo.ensure_root_history(
            from_node_id,
            self._root_key_lookup(from_node_id) if self._root_key_lookup else "",
            when,
        )

        signed = self.build_receipt(model.message_id, "accepted", now=when)

        try:
            self._repo.create(
                message_id=model.message_id,
                from_node_id=from_node_id,
                from_address=model.from_address,
                to_address=model.to_address,
                content=model.content,
                extension=model.extension.model_dump(mode="json") if model.extension else None,
                message_json=message,
                priority=model.priority,
                receipt=signed,
                received_at=when,
            )
        except Exception as exc:
            if "UNIQUE constraint" in str(exc):
                # Race: another worker inserted first; return stored receipt.
                existing = self._repo.get_existing_receipt(model.message_id, from_node_id)
                if existing is not None:
                    return existing
            raise CustodyError(f"failed to accept message: {exc}") from exc

        return signed

    def build_receipt(
        self,
        message_id: str,
        status: Literal["accepted", "rejected"],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Build and sign a durable-custody receipt.

        ``status`` is ``"accepted"`` or ``"rejected"`` per
        docs/PROTOCOL.md §8. A ``rejected`` receipt is final: the destination
        node will not take custody and the sender stops retrying.
        """
        when = now or self._clock.now()
        receipt_obj = Receipt(
            kind="receipt",
            message_id=message_id,
            node_id=self._identity.node_id,
            status=status,
            received_at=when,
            signature="",
        )
        return sign_receipt(self._identity, receipt_obj.model_dump(mode="json"))

    def claim_for_webhook(
        self,
        owner: str,
        *,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Atomically claim accepted messages for webhook delivery."""
        return self._repo.claim_for_webhook(owner, self._clock.now(), limit)

    def record_webhook_success(
        self,
        message_id: str,
        owner: str,
    ) -> bool:
        """Mark a webhook delivery as successful and erase content."""
        return self._repo.mark_terminal(
            message_id,
            owner,
            "delivered",
            self._clock.now(),
            erase_content=True,
            erase_value=self._erase_value,
        )

    def record_webhook_failure(
        self,
        message_id: str,
        owner: str,
        *,
        retryable: bool = True,
    ) -> bool:
        """Record a webhook failure and either retry or mark terminal."""
        now = self._clock.now()
        row = self._repo.get(message_id)
        if row is None:
            raise CustodyError(f"message not found: {message_id}")

        if not retryable:
            return self._repo.mark_terminal(
                message_id,
                owner,
                "failed",
                now,
                erase_content=True,
                erase_value=self._erase_value,
            )

        attempt_count = int(row.get("webhook_attempt_count", 0))
        if not self._retry.should_retry(attempt_count):
            return self._repo.mark_terminal(
                message_id,
                owner,
                "failed",
                now,
                erase_content=True,
                erase_value=self._erase_value,
            )

        next_attempt = self._retry.next_attempt_at(attempt_count, now)
        return self._repo.release_webhook_lease(message_id, owner, next_attempt, now)

    def get(self, message_id: str) -> dict[str, Any] | None:
        return self._repo.get(message_id)
