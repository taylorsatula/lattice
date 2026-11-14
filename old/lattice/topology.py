"""Peer topology controls: caps, maturity, guards, discovery, and blocks."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lattice.encoding import b64url_decode
from lattice.identity import (
    OperationalCertificate,
    RootIdentity,
    derive_node_id,
    verify_with_root,
)
from lattice.peers import BlockStore, PeerState, PeerStore
from lattice.protocol.constants import (
    ESTABLISHED_MATURITY_DAYS,
)
from lattice.protocol.models import PeerCard, WellKnownDocument
from lattice.protocol.signing import verify_peer_card
from lattice.resolution import WellKnownResolver
from lattice.storage.repositories import CacheRepository, RepositoryError


class TopologyError(ValueError):
    """Raised when a topology operation is invalid or a cap is exceeded."""


@dataclass
class TopologyConfig:
    """Configuration for topology slot and candidate caps."""

    max_candidates: int = 256
    max_candidates_per_introducer: int = 8
    max_candidates_per_prefix: int = 4
    guard_count: int = 3
    discovery_count: int = 6
    established_maturity_days: int = ESTABLISHED_MATURITY_DAYS
    candidate_expiry_seconds: int = 24 * 60 * 60


class Clock(Protocol):
    """Injectable clock for deterministic testing."""

    def now(self) -> datetime: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass
class VerificationResult:
    """Outcome of independent well-known verification."""

    node_id: str
    domain: str
    root_public_key: str
    operational_certificate: dict[str, Any]
    endpoints: dict[str, str]
    certificate_sequence: int
    observed_prefix: str | None = None


class TopologyService:
    """Enforces Sybil-resistant topology rules and drives peer maturity."""

    def __init__(
        self,
        peer_store: PeerStore,
        block_store: BlockStore,
        cache: CacheRepository,
        resolver: WellKnownResolver,
        *,
        local_node_id: str,
        config: TopologyConfig | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._peers = peer_store
        self._blocks = block_store
        self._cache = cache
        self._resolver = resolver
        self._local_node_id = local_node_id
        self._config = config or TopologyConfig()
        self._clock = clock or _SystemClock()

    # -----------------------------------------------------------------------
    # Candidate acceptance
    # -----------------------------------------------------------------------

    def prefix_from_endpoints(self, endpoints: dict[str, str]) -> str | None:
        """Derive a coarse network/host grouping from endpoint URLs.

        Used at candidate intake, before any network fetch, so no extra
        traffic is spent on rejected cards. After independent verification
        the real IP prefix (see :meth:`prefix_from_ip`) supersedes this.
        """
        messages_url = endpoints.get("messages") or endpoints.get("gossip")
        if not messages_url:
            return None
        parsed = urlparse(messages_url)
        hostname = parsed.hostname
        if not hostname:
            return None
        return hostname.lower()

    @staticmethod
    def prefix_from_ip(ip_text: str) -> str | None:
        """Derive a routable prefix from a verified resolved IP address.

        IPv4 addresses group by /24 and IPv6 addresses by /48 — coarse enough
        that a single operator controlling a /24 cannot fill every discovery
        slot, fine enough to preserve real topology diversity.
        """
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        prefix_len = 24 if isinstance(ip, ipaddress.IPv4Address) else 48
        network = ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False)
        return str(network.network_address) + f"/{prefix_len}"

    def can_accept_candidate(
        self,
        node_id: str,
        introduced_by: str | None,
        observed_prefix: str | None,
    ) -> bool:
        """Return True if accepting this candidate respects caps."""
        if node_id == self._local_node_id:
            return False

        if self._blocks.is_blocked(node_id):
            return False

        # Already known in durable state: not a candidate.
        if self._peers.get_peer(node_id) is not None:
            return False

        if self._cache.count_candidates() >= self._config.max_candidates:
            return False

        if introduced_by is not None and (
            self._cache.count_candidates_by_introducer(introduced_by)
            >= self._config.max_candidates_per_introducer
        ):
            return False

        return observed_prefix is None or (
            self._cache.count_candidates_by_prefix(observed_prefix)
            < self._config.max_candidates_per_prefix
        )

    def accept_candidate(
        self,
        card: dict[str, Any],
        *,
        introduced_by: str | None = None,
        observed_prefix: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Store a gossip-introduced peer card as a candidate.

        Returns True if accepted, False if rejected by caps or blocks.
        """
        when = now or self._clock.now()
        try:
            model = PeerCard.model_validate(card)
        except Exception as exc:
            raise TopologyError(f"invalid peer card: {exc}") from exc

        node_id = model.node_id
        if not self.can_accept_candidate(node_id, introduced_by, observed_prefix):
            return False

        expires_at = model.expires_at
        self._cache.add_candidate(
            node_id=node_id,
            introduced_by=introduced_by,
            observed_prefix=observed_prefix,
            card_json=json.dumps(card, separators=(",", ":"), ensure_ascii=False),
            received_at=when,
            expires_at=expires_at,
        )
        return True

    # -----------------------------------------------------------------------
    # Independent verification
    # -----------------------------------------------------------------------

    def verify_candidate(self, node_id: str) -> VerificationResult | None:
        """Independently fetch and verify a candidate via well-known.

        If verification succeeds, the candidate is promoted to ``verified`` and
        a transient card is retained for gossip. Returns the verification
        result or None if the candidate is missing/invalid.
        """
        candidate = self._cache.get_candidate(node_id)
        if candidate is None:
            return None

        # Verify over the received card dict: the sender's signature covers
        # the card as it was sent (timestamps may be encoded as +00:00),
        # so a re-serialized model dump must not be substituted for it.
        raw_card = json.loads(candidate["card_json"])
        try:
            card = PeerCard.model_validate(raw_card)
        except Exception as exc:
            self._cache.remove_candidate(node_id)
            raise TopologyError(f"candidate card invalid: {exc}") from exc

        if self._blocks.is_blocked(node_id):
            self._cache.remove_candidate(node_id)
            raise TopologyError(f"peer is blocked: {node_id}")

        try:
            well_known, resolved_ip = self._resolver.resolve_with_ip(card.domain)
        except Exception as exc:
            # Fail closed: any resolution failure (ResolutionError, or a
            # leaked ValueError/TransportError sibling) becomes TopologyError
            # instead of aborting candidate verification.
            raise TopologyError(f"well-known resolution failed: {exc}") from exc

        try:
            result = self._verify_against_well_known(card, well_known, raw_card)
        except TopologyError:
            self._cache.remove_candidate(node_id)
            raise

        now = self._clock.now()
        observed_prefix = self.prefix_from_ip(resolved_ip) if resolved_ip else None
        self._peers.ensure_root_history(
            result.node_id,
            result.root_public_key,
            first_seen_at=now,
        )

        # Stateful sequence gate across the pin and peer rows: first contact
        # passes (prior absent); a certificate sequence that does not advance
        # the recorded prior is a retired key rolling back into legitimacy.
        existing = self._peers.get_peer(result.node_id)
        prior: int | None = existing.current_certificate_sequence if existing else None
        pin = self._resolver.get_pin(result.domain)
        if pin is not None and pin.get("node_id") == result.node_id:
            pin_cert = pin.get("operational_certificate")
            if isinstance(pin_cert, dict) and isinstance(pin_cert.get("sequence"), int):
                pin_seq = int(pin_cert["sequence"])
                prior = pin_seq if prior is None else max(prior, pin_seq)
        if prior is not None and result.certificate_sequence < prior:
            self._cache.remove_candidate(node_id)
            raise TopologyError(
                f"certificate sequence rollback for {result.node_id}: "
                f"{result.certificate_sequence} does not advance {prior}"
            )

        # Record the accepted key BEFORE transitioning the peer row so a
        # refused key leaves no partially adopted state behind.
        try:
            self._peers.record_operational_key(
                result.node_id,
                result.operational_certificate["operational_public_key"],
                result.certificate_sequence,
                valid_from=datetime.fromisoformat(
                    result.operational_certificate["valid_from"].replace("Z", "+00:00")
                ),
                valid_until=datetime.fromisoformat(
                    result.operational_certificate["valid_until"].replace("Z", "+00:00")
                ),
            )
        except RepositoryError as exc:
            self._cache.remove_candidate(node_id)
            raise TopologyError(f"operational key rejected for {result.node_id}: {exc}") from exc

        if existing is None:
            self._peers.create_peer(
                result.node_id,
                PeerState.VERIFIED,
                domain=result.domain,
                current_certificate_sequence=result.certificate_sequence,
                endpoints=result.endpoints,
                observed_prefix=observed_prefix,
                now=now,
            )
        else:
            self._peers.transition(
                result.node_id,
                PeerState.VERIFIED,
                domain=result.domain,
                current_certificate_sequence=result.certificate_sequence,
                endpoints=result.endpoints,
                observed_prefix=observed_prefix,
                now=now,
            )

        self._cache.remove_candidate(node_id)
        self._cache.add_transient_card(
            node_id=result.node_id,
            # Store the received, signed card dict verbatim — a re-serialized
            # model dump could break the card signature for +00:00 encodings.
            card_json=candidate["card_json"],
            received_at=now,
            expires_at=card.expires_at,
        )

        return result

    def _verify_against_well_known(
        self,
        card: PeerCard,
        well_known: dict[str, Any],
        card_dict: dict[str, Any] | None = None,
    ) -> VerificationResult:
        """Verify a peer card against a fetched well-known document.

        The card's operational signature is verified over the received card
        dict (``card_dict``), not over a re-serialized model dump, so a card
        whose timestamps are encoded as ``+00:00`` verifies identically here
        and in ``RuntimeCoordinator.verify_gossip_sender_card``. Certificate
        signatures use the canonical certificate form (UTC ``Z``, second
        precision) via ``OperationalCertificate.from_dict``.
        """
        doc = WellKnownDocument.model_validate(well_known)

        if card.node_id != doc.node_id:
            raise TopologyError(
                f"card node ID {card.node_id} does not match well-known {doc.node_id}"
            )

        if card.domain != doc.domain:
            raise TopologyError(f"card domain {card.domain} does not match well-known {doc.domain}")

        # Verify root public key and node-ID derivation.
        try:
            root_bytes = b64url_decode(doc.root_public_key)
            root_key = Ed25519PublicKey.from_public_bytes(root_bytes)
        except Exception as exc:
            raise TopologyError(f"invalid root public key: {exc}") from exc

        derived_node_id = derive_node_id(root_key)
        if derived_node_id != doc.node_id:
            raise TopologyError(f"derived node ID {derived_node_id} does not match {doc.node_id}")

        # Verify well-known root signature.
        try:
            verify_with_root(root_key, well_known, "well_known")
        except Exception as exc:
            raise TopologyError(f"well-known signature invalid: {exc}") from exc

        # Verify operational certificate.
        root_identity = RootIdentity(node_id=doc.node_id, public_key=root_key)
        try:
            cert = OperationalCertificate.from_dict(
                doc.operational_certificate.model_dump(mode="json")
            )
            cert.verify(root_identity)
        except Exception as exc:
            # Fail closed: from_dict raises plain ValueError for malformed key
            # material and verify raises SignatureError — siblings of
            # IdentityError that must also become TopologyError.
            raise TopologyError(f"operational certificate invalid: {exc}") from exc
        # Reject an expired or not-yet-valid certificate at intake, mirroring
        # verify_gossip_sender_card: verify, then is_valid_at.
        if not cert.is_valid_at(self._clock.now()):
            raise TopologyError(
                f"operational certificate for {doc.node_id} is expired or not yet valid"
            )

        # Verify peer card operational signature over the received dict.
        try:
            verify_peer_card(
                card_dict if card_dict is not None else card.model_dump(mode="json"),
                cert,
                root_identity,
            )
        except Exception as exc:
            raise TopologyError(f"peer card signature invalid: {exc}") from exc

        return VerificationResult(
            node_id=doc.node_id,
            domain=doc.domain,
            root_public_key=doc.root_public_key,
            operational_certificate=doc.operational_certificate.model_dump(mode="json"),
            endpoints={
                "gossip": doc.endpoints.gossip,
                "messages": doc.endpoints.messages,
            },
            certificate_sequence=doc.operational_certificate.sequence,
        )

    # -----------------------------------------------------------------------
    # Maturity and topology slots
    # -----------------------------------------------------------------------

    def record_observation(
        self,
        node_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Record a successful observation and possibly promote to established."""
        when = now or self._clock.now()
        peer = self._peers.get_peer(node_id)
        if peer is None or peer.state == PeerState.BLOCKED:
            return False

        new_day = self._peers.record_observation(node_id, now=when)
        if peer.state == PeerState.VERIFIED:
            self._maybe_promote(node_id, when)
        return new_day

    def _maybe_promote(self, node_id: str, now: datetime) -> bool:
        peer = self._peers.get_peer(node_id)
        if peer is None or peer.state != PeerState.VERIFIED:
            return False

        verified_at = peer.verified_at or now
        min_age = timedelta(days=self._config.established_maturity_days)
        if now - verified_at < min_age:
            return False

        days = self._peers.observation_days(node_id)
        if days < self._config.established_maturity_days:
            return False

        self._peers.transition(node_id, PeerState.ESTABLISHED, now=now)
        return True

    def promote_to_established(self, node_id: str, now: datetime | None = None) -> bool:
        """Idempotently promote a verified peer if maturity rules are met."""
        return self._maybe_promote(node_id, now or self._clock.now())

    # -----------------------------------------------------------------------
    # Guards and discovery
    # -----------------------------------------------------------------------

    def refresh_topology_slots(self, now: datetime | None = None) -> None:
        """Promote verified/established peers to guards and discovery.

        Guards are filled with the oldest established peers. Discovery slots are
        filled with verified peers not already in a topology slot, preferring
        prefix diversity.
        """
        when = now or self._clock.now()
        self._fill_guards(when)
        self._fill_discovery(when)

    def _fill_guards(self, now: datetime) -> None:
        current = self._peers.list_guards()
        established = self._peers.list_by_state(PeerState.ESTABLISHED)
        established_ids = {p.node_id for p in established}

        # Demote guards that are no longer established or are blocked.
        for guard in current:
            node_id = guard["node_id"]
            if node_id not in established_ids or self._blocks.is_blocked(node_id):
                self._peers.demote_guard(node_id)

        # Fill slots from oldest established peers.
        current = self._peers.list_guards()
        slots = {g["slot"] for g in current}
        next_slot = 1
        for peer in sorted(established, key=lambda p: p.established_at or now):
            if len(self._peers.list_guards()) >= self._config.guard_count:
                break
            while next_slot in slots:
                next_slot += 1
            if not self._peers.is_guard(peer.node_id):
                self._peers.promote_guard(peer.node_id, next_slot, now)
                slots.add(next_slot)
                next_slot += 1

    def _fill_discovery(self, now: datetime) -> None:
        verified = self._peers.list_by_state(PeerState.VERIFIED)
        guard_ids = {g["node_id"] for g in self._peers.list_guards()}
        available = [
            p
            for p in verified
            if p.node_id not in guard_ids and not self._blocks.is_blocked(p.node_id)
        ]

        # Prefer prefix diversity: group by observed network prefix (real IP
        # prefix recorded at verification time) and fall back to the hostname
        # grouping for peers verified before prefixes were recorded.
        by_prefix: dict[str, list[str]] = {}
        for peer in available:
            prefix = (
                peer.observed_prefix
                or self.prefix_from_endpoints(peer.endpoints or {})
                or "_unknown"
            )
            by_prefix.setdefault(prefix, []).append(peer.node_id)

        selected: list[str] = []
        while len(selected) < self._config.discovery_count and any(by_prefix.values()):
            for prefix in list(by_prefix.keys()):
                if by_prefix[prefix]:
                    selected.append(by_prefix[prefix].pop(0))
                if len(selected) >= self._config.discovery_count:
                    break

        # Discovery set stored in dedicated table for efficient lookup.
        for node_id in selected:
            self._cache.add_to_discovery_set(
                node_id=node_id,
                selected_at=now,
                expires_at=now + timedelta(days=1),
            )

    def select_gossip_targets(self) -> list[str]:
        """Return node IDs to gossip with: guards first, then discovery."""
        guards = {g["node_id"] for g in self._peers.list_guards()}
        discovery = [nid for nid in self._cache.list_discovery_set() if nid not in guards]
        return list(guards) + discovery[: self._config.discovery_count]

    def list_candidates_for_verification(self) -> list[str]:
        """Return candidate node IDs that should be independently verified."""
        return [c["node_id"] for c in self._cache.list_candidates()]

    def prune(self, now: datetime | None = None) -> dict[str, int]:
        """Expire cache entries and demote stale topology."""
        when = now or self._clock.now()
        candidates = self._cache.prune_candidates(when)
        cards = self._cache.prune_transient_cards(when)
        disc = self._cache.prune_discovery_set(when)
        self._fill_guards(when)
        self._fill_discovery(when)
        return {
            "candidates": candidates,
            "transient_cards": cards,
            "discovery_set": disc,
        }

    # -----------------------------------------------------------------------
    # Blocks
    # -----------------------------------------------------------------------

    def block(self, node_id: str, reason: str, now: datetime | None = None) -> None:
        """Block ``node_id`` and remove it from topology.

        Since migration 002 the ``blocks`` table has no foreign key, so any
        node ID may be blocked — including nodes that were never observed or
        introduced (docs/LOOSE_ENDS.md Phase 6).
        """
        when = now or self._clock.now()
        self._blocks.block(node_id, reason, when)
        self._cache.remove_candidate(node_id)
        self._cache.remove_transient_card(node_id)
        if self._peers.is_guard(node_id):
            self._peers.demote_guard(node_id)
