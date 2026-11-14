"""Gossip peer-card exchange for Lattice v1."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from lattice.crypto import public_key_b64url
from lattice.identity import OperationalIdentity
from lattice.protocol.constants import MAX_GOSSIP_BATCH_SIZE
from lattice.protocol.models import PeerCard
from lattice.protocol.signing import sign_peer_card, verify_peer_card
from lattice.storage.repositories import CacheRepository
from lattice.topology import TopologyService


class GossipError(ValueError):
    """Raised when a gossip operation is invalid."""


class Clock(Protocol):
    """Injectable clock for deterministic testing."""

    def now(self) -> datetime: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True)
class ReceivedCard:
    """A peer card received from gossip with attribution."""

    node_id: str
    domain: str
    introduced_by: str | None
    accepted: bool
    reason: str | None = None


@dataclass(frozen=True)
class GossipBatch:
    """A batch of peer cards to send to a neighbor."""

    cards: list[dict[str, Any]]
    attributed_to: list[str | None]


class GossipService:
    """Receive and send gossip peer-card batches with attribution."""

    def __init__(
        self,
        topology: TopologyService,
        cache: CacheRepository,
        identity: OperationalIdentity,
        *,
        clock: Clock | None = None,
    ) -> None:
        self._topology = topology
        self._cache = cache
        self._identity = identity
        self._clock = clock or _SystemClock()

    # -----------------------------------------------------------------------
    # Receiving
    # -----------------------------------------------------------------------

    def receive_batch(
        self,
        cards: list[dict[str, Any]],
        *,
        introduced_by: str | None = None,
        observed_prefix: str | None = None,
        now: datetime | None = None,
    ) -> list[ReceivedCard]:
        """Process a batch of gossiped peer cards.

        Cards are validated, capped, and stored as candidates awaiting
        independent verification. Attribution is recorded but never trusted.
        """
        when = now or self._clock.now()
        results: list[ReceivedCard] = []

        for card in cards[:MAX_GOSSIP_BATCH_SIZE]:
            try:
                model = PeerCard.model_validate(card)
            except Exception as exc:
                results.append(
                    ReceivedCard(
                        node_id="",
                        domain="",
                        introduced_by=introduced_by,
                        accepted=False,
                        reason=f"invalid card: {exc}",
                    )
                )
                continue

            if model.node_id == self._identity.node_id:
                results.append(
                    ReceivedCard(
                        node_id=model.node_id,
                        domain=model.domain,
                        introduced_by=introduced_by,
                        accepted=False,
                        reason="refusing self-card",
                    )
                )
                continue

            prefix = observed_prefix or self._topology.prefix_from_endpoints(
                {
                    "gossip": model.endpoints.gossip,
                    "messages": model.endpoints.messages,
                }
            )

            try:
                accepted = self._topology.accept_candidate(
                    card,
                    introduced_by=introduced_by,
                    observed_prefix=prefix,
                    now=when,
                )
            except Exception as exc:
                results.append(
                    ReceivedCard(
                        node_id=model.node_id,
                        domain=model.domain,
                        introduced_by=introduced_by,
                        accepted=False,
                        reason=f"accept failed: {exc}",
                    )
                )
                continue

            if accepted:
                # Also store as a transient card so we can propagate it even
                # before independent verification completes.
                self._cache.add_transient_card(
                    node_id=model.node_id,
                    card_json=json.dumps(card, separators=(",", ":"), ensure_ascii=False),
                    received_at=when,
                    expires_at=model.expires_at,
                )
                results.append(
                    ReceivedCard(
                        node_id=model.node_id,
                        domain=model.domain,
                        introduced_by=introduced_by,
                        accepted=True,
                        reason=None,
                    )
                )
            else:
                results.append(
                    ReceivedCard(
                        node_id=model.node_id,
                        domain=model.domain,
                        introduced_by=introduced_by,
                        accepted=False,
                        reason="rejected by topology caps",
                    )
                )

        return results

    # -----------------------------------------------------------------------
    # Sending
    # -----------------------------------------------------------------------

    def build_own_card(
        self,
        domain: str,
        root_public_key: Any,
        endpoints: dict[str, str],
        *,
        now: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Build and sign the local node's peer card.

        ``root_public_key`` must be the Ed25519 public key object or a
        base64url-encoded string. The daemon's :class:`OperationalIdentity`
        does not contain the root key, so callers must supply it.
        """
        from datetime import timedelta

        from lattice.protocol.constants import MAX_PEER_CARD_LIFETIME_SECONDS

        when = now or self._clock.now()
        if expires_at is None:
            expires_at = when + timedelta(seconds=MAX_PEER_CARD_LIFETIME_SECONDS)

        if isinstance(root_public_key, str):
            from lattice.crypto import load_public_key_b64url

            root_public_key = load_public_key_b64url(root_public_key)

        card = {
            "kind": "peer_card",
            "node_id": self._identity.node_id,
            "domain": domain.lower(),
            "root_public_key": public_key_b64url(root_public_key),
            "operational_certificate": self._identity.certificate.to_dict(),
            "endpoints": {
                "gossip": endpoints["gossip"],
                "messages": endpoints["messages"],
            },
            "sequence": self._identity.certificate.sequence,
            "issued_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return sign_peer_card(self._identity, card)

    def sign_card(self, card: dict[str, Any]) -> dict[str, Any]:
        """Sign an already-constructed peer card with the operational key."""
        return sign_peer_card(self._identity, card)

    def select_batch_to_send(
        self,
        *,
        exclude: set[str] | None = None,
        limit: int = MAX_GOSSIP_BATCH_SIZE,
    ) -> GossipBatch:
        """Select a bounded batch of peer cards to send to a neighbor.

        Prefers verified/established transient cards. Includes attribution only
        for local audit/logging, not for transitive trust.
        """
        exclude = exclude or set()
        cards: list[dict[str, Any]] = []
        attributed_to: list[str | None] = []

        for row in self._cache.list_transient_cards():
            node_id = row["node_id"]
            if node_id in exclude:
                continue
            try:
                card = json.loads(row["card_json"])
            except Exception:
                continue
            if not isinstance(card, dict):
                continue
            cards.append(card)
            attributed_to.append(row.get("introduced_by"))
            if len(cards) >= limit:
                break

        return GossipBatch(cards=cards, attributed_to=attributed_to)

    # -----------------------------------------------------------------------
    # Verification helpers
    # -----------------------------------------------------------------------

    def verify_card_against_pin(
        self,
        card: dict[str, Any],
        root_identity: Any,
        certificate: Any,
    ) -> None:
        """Verify a peer card signature and certificate.

        This is a thin wrapper around :func:`lattice.protocol.signing.verify_peer_card`
        for callers that already have a pinned root identity/certificate.
        """
        verify_peer_card(card, certificate, root_identity)
