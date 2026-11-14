"""Tests for topology controls: caps, maturity, guards, and blocks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lattice.crypto import public_key_b64url
from lattice.identity import (
    OperationalCertificate,
    OperationalIdentity,
    create_operational_certificate,
    sign_with_root,
)
from lattice.peers import BlockStore, PeerState, PeerStore
from lattice.protocol.signing import sign_peer_card
from lattice.resolution import WellKnownResolver
from lattice.storage.repositories import CacheRepository, PeerRepository
from lattice.topology import TopologyConfig, TopologyService
from tests.conftest import OtherNode


class FakeClock:
    def __init__(self, start: datetime) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


def make_peer_card(
    root_key: Ed25519PrivateKey,
    op_identity: OperationalIdentity,
    domain: str,
    *,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    issued = issued_at or datetime.now(UTC)
    if expires_at is None:
        expires_at = issued + timedelta(days=7)
    card = {
        "kind": "peer_card",
        "node_id": op_identity.node_id,
        "domain": domain.lower(),
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": op_identity.certificate.to_dict(),
        "endpoints": {
            "gossip": f"https://{domain}/lattice/v1/gossip",
            "messages": f"https://{domain}/lattice/v1/messages",
        },
        "sequence": op_identity.certificate.sequence,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return sign_peer_card(op_identity, card)


def make_well_known(
    root_key: Ed25519PrivateKey,
    cert: OperationalCertificate,
    domain: str,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    issued = issued_at or datetime.now(UTC)
    doc: dict[str, object] = {
        "kind": "well_known",
        "node_id": cert.node_id,
        "domain": domain.lower(),
        "root_public_key": public_key_b64url(root_key.public_key()),
        "operational_certificate": cert.to_dict(),
        "endpoints": {
            "gossip": f"https://{domain}/lattice/v1/gossip",
            "messages": f"https://{domain}/lattice/v1/messages",
        },
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return sign_with_root(root_key, doc, "well_known")


@pytest.fixture
def topology(
    peer_repository: PeerRepository,
    cache_repository: CacheRepository,
    operational_identity: OperationalIdentity,
) -> tuple[TopologyService, FakeClock, MagicMock]:
    clock = FakeClock(datetime.now(UTC))
    resolver = MagicMock(spec=WellKnownResolver)
    peer_store = PeerStore(peer_repository, cache_repository)
    block_store = BlockStore(peer_repository)
    config = TopologyConfig(
        max_candidates=10,
        max_candidates_per_introducer=2,
        max_candidates_per_prefix=2,
        guard_count=2,
        discovery_count=3,
        established_maturity_days=2,
        candidate_expiry_seconds=86400,
    )
    topology = TopologyService(
        peer_store=peer_store,
        block_store=block_store,
        cache=cache_repository,
        resolver=resolver,
        local_node_id=operational_identity.node_id,
        config=config,
        clock=clock,
    )
    return topology, clock, resolver


class TestCandidateAcceptance:
    def test_accept_candidate(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, _ = topology
        root_key, _op_key, _cert, op_identity = other_node
        card = make_peer_card(root_key, op_identity, "peer.example.com")
        assert svc.accept_candidate(card, introduced_by="lat_introducer") is True
        assert svc._cache.count_candidates() == 1

    def test_reject_self_card(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        operational_identity: OperationalIdentity,
        root_key: Ed25519PrivateKey,
    ) -> None:
        svc, clock, _ = topology
        card = make_peer_card(root_key, operational_identity, "self.example.com")
        # Self-card is rejected by topology because it matches the local node ID.
        assert svc.accept_candidate(card, introduced_by="lat_introducer") is False

    def test_per_introducer_cap(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
    ) -> None:
        svc, clock, _ = topology
        introducer = "lat_introducer"
        for i in range(2):
            # Each candidate must be a distinct node, so use a distinct root key.
            root_key = Ed25519PrivateKey.generate()
            opk = Ed25519PrivateKey.generate()
            cert = create_operational_certificate(
                root_key=root_key,
                operational_public_key=opk.public_key(),
                sequence=1,
                valid_from=clock.now(),
                valid_until=clock.now() + timedelta(days=30),
            )
            oid = OperationalIdentity(node_id=cert.node_id, private_key=opk, certificate=cert)
            card = make_peer_card(root_key, oid, f"peer{i}.example.com")
            assert svc.accept_candidate(card, introduced_by=introducer) is True

        # Third candidate from same introducer exceeds cap.
        root_key = Ed25519PrivateKey.generate()
        opk = Ed25519PrivateKey.generate()
        cert = create_operational_certificate(
            root_key=root_key,
            operational_public_key=opk.public_key(),
            sequence=1,
            valid_from=clock.now(),
            valid_until=clock.now() + timedelta(days=30),
        )
        oid = OperationalIdentity(node_id=cert.node_id, private_key=opk, certificate=cert)
        card = make_peer_card(root_key, oid, "peer3.example.com")
        assert svc.accept_candidate(card, introduced_by=introducer) is False


class TestVerification:
    def test_verify_candidate_promotes_to_verified(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, resolver = topology
        root_key, _op_key, cert, op_identity = other_node
        domain = "peer.example.com"
        card = make_peer_card(root_key, op_identity, domain)
        well_known = make_well_known(root_key, cert, domain)
        resolver.resolve_with_ip.return_value = (well_known, "198.51.100.7")

        svc.accept_candidate(card, introduced_by="lat_introducer")
        result = svc.verify_candidate(op_identity.node_id)
        assert result is not None
        assert result.node_id == op_identity.node_id

        peer = svc._peers.get_peer(op_identity.node_id)
        assert peer is not None
        assert peer.state == PeerState.VERIFIED
        assert peer.domain == domain


class TestMaturity:
    def test_fake_clock_maturity(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, resolver = topology
        root_key, _op_key, cert, op_identity = other_node
        domain = "peer.example.com"
        card = make_peer_card(root_key, op_identity, domain)
        well_known = make_well_known(root_key, cert, domain)
        resolver.resolve_with_ip.return_value = (well_known, "198.51.100.7")

        svc.accept_candidate(card, introduced_by="lat_introducer")
        svc.verify_candidate(op_identity.node_id)

        # Need observations on multiple distinct days.
        for _day in range(2):
            clock.advance(timedelta(days=1))
            svc.record_observation(op_identity.node_id)

        svc.promote_to_established(op_identity.node_id)
        peer = svc._peers.get_peer(op_identity.node_id)
        assert peer is not None
        assert peer.state == PeerState.ESTABLISHED

    def test_insufficient_days_not_promoted(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, resolver = topology
        root_key, _op_key, cert, op_identity = other_node
        domain = "peer.example.com"
        card = make_peer_card(root_key, op_identity, domain)
        well_known = make_well_known(root_key, cert, domain)
        resolver.resolve_with_ip.return_value = (well_known, "198.51.100.7")

        svc.accept_candidate(card, introduced_by="lat_introducer")
        svc.verify_candidate(op_identity.node_id)

        clock.advance(timedelta(days=2))
        # No observations recorded.
        promoted = svc.promote_to_established(op_identity.node_id)
        assert promoted is False


class TestGuards:
    def test_guard_filled_from_established(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, resolver = topology
        root_key, _op_key, cert, op_identity = other_node
        domain = "peer.example.com"
        card = make_peer_card(root_key, op_identity, domain)
        well_known = make_well_known(root_key, cert, domain)
        resolver.resolve_with_ip.return_value = (well_known, "198.51.100.7")

        svc.accept_candidate(card, introduced_by="lat_introducer")
        svc.verify_candidate(op_identity.node_id)
        for _ in range(2):
            clock.advance(timedelta(days=1))
            svc.record_observation(op_identity.node_id)
        svc.promote_to_established(op_identity.node_id)

        svc.refresh_topology_slots()
        guards = svc._peers.list_guards()
        assert len(guards) == 1
        assert guards[0]["node_id"] == op_identity.node_id


class TestBlocks:
    def test_blocked_candidate_removed(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, _ = topology
        root_key, _op_key, _cert, op_identity = other_node
        card = make_peer_card(root_key, op_identity, "peer.example.com")
        svc.accept_candidate(card, introduced_by="lat_introducer")
        svc.block(op_identity.node_id, "abuse")
        assert svc._cache.get_candidate(op_identity.node_id) is None
        assert svc._blocks.is_blocked(op_identity.node_id)

    def test_block_unseen_node_id(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
    ) -> None:
        """Migration-free schema: blocks have no FK, so a node ID that was
        never observed or introduced can be blocked directly."""
        svc, _clock, _resolver = topology
        unseen = "lat_neverseen0000000000000000000000000000000000000000000000000"
        svc.block(unseen, "operator block")
        assert svc._blocks.is_blocked(unseen)
        assert svc.can_accept_candidate(unseen, None, None) is False


class TestPrefixDerivation:
    def test_prefix_from_ip_ipv4_groups_by_24(self) -> None:
        assert TopologyService.prefix_from_ip("198.51.100.7") == "198.51.100.0/24"
        assert TopologyService.prefix_from_ip("198.51.100.9") == "198.51.100.0/24"
        assert TopologyService.prefix_from_ip("203.0.113.7") == "203.0.113.0/24"

    def test_prefix_from_ip_ipv6_groups_by_48(self) -> None:
        assert TopologyService.prefix_from_ip("2001:db8:1a2b::1") == "2001:db8:1a2b::/48"

    def test_prefix_from_ip_mapped_v4_uses_v4_prefix(self) -> None:
        assert TopologyService.prefix_from_ip("::ffff:198.51.100.7") == "198.51.100.0/24"

    def test_prefix_from_ip_invalid_returns_none(self) -> None:
        assert TopologyService.prefix_from_ip("not-an-ip") is None

    def test_verified_peer_stores_observed_prefix(
        self,
        topology: tuple[TopologyService, FakeClock, MagicMock],
        other_node: OtherNode,
    ) -> None:
        svc, clock, resolver = topology
        root_key, _op_key, cert, op_identity = other_node
        domain = "peer.example.com"
        card = make_peer_card(root_key, op_identity, domain)
        well_known = make_well_known(root_key, cert, domain)
        resolver.resolve_with_ip.return_value = (well_known, "198.51.100.7")

        svc.accept_candidate(card, introduced_by="lat_introducer")
        svc.verify_candidate(op_identity.node_id)
        peer = svc._peers.get_peer(op_identity.node_id)
        assert peer is not None
        assert peer.observed_prefix == "198.51.100.0/24"
