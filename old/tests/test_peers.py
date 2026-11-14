"""Tests for peer state records and blocks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from lattice.peers import BlockStore, PeerError, PeerState, PeerStore
from lattice.storage.repositories import CacheRepository, PeerRepository


class TestPeerStore:
    def test_create_and_get_peer(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer(
            "lat_abc123",
            PeerState.CANDIDATE,
            domain="example.com",
            current_certificate_sequence=1,
            endpoints={"messages": "https://example.com/messages"},
        )
        peer = store.get_peer("lat_abc123")
        assert peer is not None
        assert peer.state == PeerState.CANDIDATE
        assert peer.domain == "example.com"

    def test_create_duplicate_raises(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer("lat_abc123", PeerState.CANDIDATE)
        with pytest.raises(PeerError):
            store.create_peer("lat_abc123", PeerState.CANDIDATE)

    def test_transition_records_verified_timestamp(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer("lat_abc123", PeerState.CANDIDATE)
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        store.transition("lat_abc123", PeerState.VERIFIED, now=now)
        peer = store.get_peer("lat_abc123")
        assert peer is not None
        assert peer.state == PeerState.VERIFIED
        assert peer.verified_at == now

    def test_transition_unknown_raises(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        with pytest.raises(PeerError):
            store.transition("lat_abc123", PeerState.VERIFIED)

    def test_observation_days(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer("lat_abc123", PeerState.VERIFIED)
        store.record_observation("lat_abc123", now=datetime(2026, 1, 1, tzinfo=UTC))
        store.record_observation("lat_abc123", now=datetime(2026, 1, 2, tzinfo=UTC))
        store.record_observation("lat_abc123", now=datetime(2026, 1, 2, 23, 59, tzinfo=UTC))
        assert store.observation_days("lat_abc123") == 2

    def test_record_operational_key(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer("lat_abc123", PeerState.VERIFIED)
        now = datetime.now(UTC)
        store.record_operational_key(
            "lat_abc123",
            "opk123",
            1,
            valid_from=now,
            valid_until=now + timedelta(days=30),
        )


class TestBlockStore:
    def test_block_and_unblock(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        store = PeerStore(peer_repository, cache_repository)
        blocks = BlockStore(peer_repository)
        store.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        store.create_peer("lat_abc123", PeerState.CANDIDATE)
        blocks.block("lat_abc123", "spam", now=datetime(2026, 1, 1, tzinfo=UTC))
        assert blocks.is_blocked("lat_abc123")
        peer = store.get_peer("lat_abc123")
        assert peer is not None
        assert peer.state == PeerState.BLOCKED
        assert peer.block_reason == "spam"

    def test_unblock_removes_block_row(
        self,
        peer_repository: PeerRepository,
        cache_repository: CacheRepository,
    ) -> None:
        blocks = BlockStore(peer_repository)
        blocks.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
        blocks.block("lat_abc123", "spam")
        assert blocks.is_blocked("lat_abc123")
        blocks.unblock("lat_abc123")
        assert not blocks.is_blocked("lat_abc123")
