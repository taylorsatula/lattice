"""Tests for gossip peer-card exchange."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.gossip import GossipService
from lattice.identity import (
    OperationalIdentity,
)
from lattice.peers import BlockStore, PeerStore
from lattice.protocol.constants import MAX_GOSSIP_BATCH_SIZE
from lattice.resolution import WellKnownResolver
from lattice.storage.repositories import CacheRepository, PeerRepository
from lattice.topology import TopologyConfig, TopologyService
from tests.conftest import OtherNode
from tests.test_topology import FakeClock, make_peer_card


@pytest.fixture
def gossip(
    peer_repository: PeerRepository,
    cache_repository: CacheRepository,
    operational_identity: OperationalIdentity,
    root_key: Ed25519PrivateKey,
) -> tuple[GossipService, TopologyService, FakeClock, MagicMock]:
    clock = FakeClock(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC))
    resolver = MagicMock(spec=WellKnownResolver)
    peer_store = PeerStore(peer_repository, cache_repository)
    block_store = BlockStore(peer_repository)
    topology = TopologyService(
        peer_store=peer_store,
        block_store=block_store,
        cache=cache_repository,
        resolver=resolver,
        local_node_id=operational_identity.node_id,
        config=TopologyConfig(max_candidates=10),
        clock=clock,
    )
    gossip = GossipService(topology, cache_repository, operational_identity, clock=clock)
    return gossip, topology, clock, resolver


class TestReceiveBatch:
    def test_receive_valid_batch(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        root_key, _op_key, _cert, op_identity = other_node
        card = make_peer_card(root_key, op_identity, "peer.example.com")
        results = gsvc.receive_batch([card], introduced_by="lat_introducer")
        assert len(results) == 1
        assert results[0].accepted is True
        assert topology._cache.count_candidates() == 1

    def test_receive_self_card_rejected(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        operational_identity: OperationalIdentity,
        root_key: Ed25519PrivateKey,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        card = make_peer_card(root_key, operational_identity, "self.example.com")
        results = gsvc.receive_batch([card], introduced_by="lat_introducer")
        assert results[0].accepted is False

    def test_receive_batch_respects_limit(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        root_key, _op_key, _cert, op_identity = other_node
        cards = [
            make_peer_card(root_key, op_identity, f"peer{i}.example.com")
            for i in range(MAX_GOSSIP_BATCH_SIZE + 5)
        ]
        results = gsvc.receive_batch(cards, introduced_by="lat_introducer")
        assert len(results) == MAX_GOSSIP_BATCH_SIZE


class TestSendBatch:
    def test_select_batch_includes_transient_cards(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        root_key, _op_key, _cert, op_identity = other_node
        card = make_peer_card(root_key, op_identity, "peer.example.com")
        gsvc.receive_batch([card], introduced_by="lat_introducer")
        batch = gsvc.select_batch_to_send()
        assert len(batch.cards) == 1
        assert batch.cards[0]["node_id"] == op_identity.node_id

    def test_select_batch_excludes_node(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        root_key, _op_key, _cert, op_identity = other_node
        card = make_peer_card(root_key, op_identity, "peer.example.com")
        gsvc.receive_batch([card], introduced_by="lat_introducer")
        batch = gsvc.select_batch_to_send(exclude={op_identity.node_id})
        assert len(batch.cards) == 0


class TestSignCard:
    def test_build_own_card(
        self,
        gossip: tuple[GossipService, TopologyService, FakeClock, MagicMock],
        operational_identity: OperationalIdentity,
        root_key: Ed25519PrivateKey,
    ) -> None:
        gsvc, topology, clock, _ = gossip
        card = gsvc.build_own_card(
            domain="example.com",
            root_public_key=root_key.public_key(),
            endpoints={
                "gossip": "https://example.com/lattice/v1/gossip",
                "messages": "https://example.com/lattice/v1/messages",
            },
        )
        assert card["node_id"] == operational_identity.node_id
        assert card["domain"] == "example.com"
        assert "signature" in card
