"""Tests for outbound/inbound message custody, retry, and erasure."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from lattice.identity import OperationalIdentity
from lattice.messages import (
    InboundMessageService,
    OutboundMessageService,
    RetryPolicy,
)
from lattice.protocol.signing import sign_message
from lattice.storage.repositories import (
    InboundMessageRepository,
    OutboundMessageRepository,
    PeerRepository,
)


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


def make_message(
    identity: OperationalIdentity,
    *,
    message_id: str = "msg-1",
    to_address: str = "alice@example.com",
    content: str = "hello",
    ttl_seconds: int = 86400,
) -> dict[str, Any]:
    msg = {
        "kind": "message",
        "message_id": message_id,
        "from_address": f"user@{identity.node_id}",
        "to_address": to_address,
        "content": content,
        "priority": "normal",
        "ttl_seconds": ttl_seconds,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return sign_message(identity, msg)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))


@pytest.fixture
def outbound_service(
    peer_repository: PeerRepository,
    clock: FakeClock,
) -> OutboundMessageService:
    repo = OutboundMessageRepository(peer_repository.conn)
    return OutboundMessageService(
        repository=repo,
        peer_repository=peer_repository,
        retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=60.0),
        clock=clock,
    )


@pytest.fixture
def inbound_service(
    peer_repository: PeerRepository,
    operational_identity: OperationalIdentity,
    clock: FakeClock,
) -> InboundMessageService:
    repo = InboundMessageRepository(peer_repository.conn)
    return InboundMessageService(
        repository=repo,
        peer_repository=peer_repository,
        identity=operational_identity,
        webhook_retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=30.0),
        clock=clock,
    )


class TestOutboundCustody:
    def test_submit_and_claim(
        self,
        outbound_service: OutboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity, to_address="bob@lat_remote")
        outbound_service.submit(msg, "lat_remote")
        claimed = outbound_service.claim_for_delivery("worker-1")
        assert len(claimed) == 1
        assert claimed[0]["message_id"] == "msg-1"
        assert claimed[0]["status"] == "leased"

    def test_record_success_erases_content(
        self,
        outbound_service: OutboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity, content="secret")
        outbound_service.submit(msg, "lat_remote")
        outbound_service.claim_for_delivery("worker-1")
        result = outbound_service.record_success("msg-1", "worker-1")
        assert result is True
        row = outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["status"] == "delivered"
        assert row["content"] == "[erased]"
        assert row["lease_owner"] is None

    def test_record_failure_retries_then_fails(
        self,
        outbound_service: OutboundMessageService,
        clock: FakeClock,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        outbound_service.submit(msg, "lat_remote")

        for _attempt in range(3):
            claimed = outbound_service.claim_for_delivery("worker-1")
            assert len(claimed) == 1
            result = outbound_service.record_failure("msg-1", "worker-1", retryable=True)
            assert result is True
            clock.advance(timedelta(minutes=10))

        # After max attempts, failure becomes terminal.
        claimed = outbound_service.claim_for_delivery("worker-1")
        assert len(claimed) == 1
        result = outbound_service.record_failure("msg-1", "worker-1", retryable=True)
        assert result is True
        row = outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["status"] == "failed"
        assert row["content"] == "[erased]"

    def test_non_retryable_failure_is_terminal(
        self,
        outbound_service: OutboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        outbound_service.submit(msg, "lat_remote")
        outbound_service.claim_for_delivery("worker-1")
        result = outbound_service.record_failure("msg-1", "worker-1", retryable=False)
        assert result is True
        row = outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["status"] == "failed"

    def test_double_claim_prevented(
        self,
        outbound_service: OutboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        outbound_service.submit(msg, "lat_remote")
        first = outbound_service.claim_for_delivery("worker-1")
        second = outbound_service.claim_for_delivery("worker-2")
        assert len(first) == 1
        assert len(second) == 0

    def test_expire_erases_content(
        self,
        outbound_service: OutboundMessageService,
        clock: FakeClock,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity, ttl_seconds=60)
        outbound_service.submit(msg, "lat_remote")
        clock.advance(timedelta(minutes=2))
        expired = outbound_service.expire()
        assert "msg-1" in expired
        row = outbound_service._repo.get("msg-1")
        assert row is not None
        assert row["status"] == "expired"
        assert row["content"] == "[erased]"


class TestInboundCustody:
    def test_accept_returns_signed_receipt(
        self,
        inbound_service: InboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        receipt = inbound_service.accept(msg, operational_identity.node_id)
        assert receipt["kind"] == "receipt"
        assert receipt["message_id"] == "msg-1"
        assert receipt["status"] == "accepted"
        assert "signature" in receipt

    def test_duplicate_returns_identical_receipt(
        self,
        inbound_service: InboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        receipt1 = inbound_service.accept(msg, operational_identity.node_id)
        receipt2 = inbound_service.accept(msg, operational_identity.node_id)
        assert receipt1 == receipt2

    def test_claim_and_deliver_webhook(
        self,
        inbound_service: InboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity, content="secret")
        inbound_service.accept(msg, operational_identity.node_id)
        claimed = inbound_service.claim_for_webhook("worker-1")
        assert len(claimed) == 1
        result = inbound_service.record_webhook_success("msg-1", "worker-1")
        assert result is True
        row = inbound_service.get("msg-1")
        assert row is not None
        assert row["status"] == "delivered"
        assert row["content"] == "[erased]"

    def test_webhook_retry_then_terminal(
        self,
        inbound_service: InboundMessageService,
        clock: FakeClock,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        inbound_service.accept(msg, operational_identity.node_id)

        for _ in range(3):
            claimed = inbound_service.claim_for_webhook("worker-1")
            assert len(claimed) == 1
            result = inbound_service.record_webhook_failure("msg-1", "worker-1", retryable=True)
            assert result is True
            clock.advance(timedelta(minutes=10))

        claimed = inbound_service.claim_for_webhook("worker-1")
        assert len(claimed) == 1
        result = inbound_service.record_webhook_failure("msg-1", "worker-1", retryable=True)
        assert result is True
        row = inbound_service.get("msg-1")
        assert row is not None
        assert row["status"] == "failed"

    def test_non_retryable_webhook_failure_terminal(
        self,
        inbound_service: InboundMessageService,
        operational_identity: OperationalIdentity,
    ) -> None:
        msg = make_message(operational_identity)
        inbound_service.accept(msg, operational_identity.node_id)
        inbound_service.claim_for_webhook("worker-1")
        result = inbound_service.record_webhook_failure("msg-1", "worker-1", retryable=False)
        assert result is True
        row = inbound_service.get("msg-1")
        assert row is not None
        assert row["status"] == "failed"
