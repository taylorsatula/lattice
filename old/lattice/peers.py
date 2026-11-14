"""Peer state records, transitions, and local blocks for Lattice v1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from lattice.storage.repositories import CacheRepository, PeerRepository


class PeerState(StrEnum):
    """Lifecycle states for a known peer."""

    CANDIDATE = "candidate"
    VERIFIED = "verified"
    ESTABLISHED = "established"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class Peer:
    """Durable peer record."""

    node_id: str
    state: PeerState
    domain: str | None
    current_certificate_sequence: int | None
    endpoints: dict[str, str] | None
    observed_prefix: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    verified_at: datetime | None
    established_at: datetime | None
    blocked_at: datetime | None
    block_reason: str | None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Peer:
        return cls(
            node_id=row["node_id"],
            state=PeerState(row["state"]),
            domain=row.get("domain"),
            current_certificate_sequence=row.get("current_certificate_sequence"),
            endpoints=_json_loads(row.get("endpoints")),
            observed_prefix=row.get("observed_prefix"),
            first_seen_at=_parse_ts(row["first_seen_at"]),
            last_seen_at=_parse_ts(row["last_seen_at"]),
            verified_at=_parse_ts(row["verified_at"]) if row.get("verified_at") else None,
            established_at=_parse_ts(row["established_at"]) if row.get("established_at") else None,
            blocked_at=_parse_ts(row["blocked_at"]) if row.get("blocked_at") else None,
            block_reason=row.get("block_reason"),
        )


class PeerStore:
    """High-level peer state management backed by durable storage."""

    def __init__(
        self,
        durable: PeerRepository,
        cache: CacheRepository,
    ) -> None:
        self._durable = durable
        self._cache = cache

    def ensure_root_history(
        self,
        node_id: str,
        root_public_key: str,
        first_seen_at: datetime | None = None,
    ) -> None:
        """Ensure ``node_id`` has an immutable root-history row."""
        self._durable.ensure_root_history(
            node_id,
            root_public_key,
            first_seen_at or datetime.now(UTC),
        )

    def create_peer(
        self,
        node_id: str,
        state: PeerState,
        *,
        domain: str | None = None,
        current_certificate_sequence: int | None = None,
        endpoints: dict[str, str] | None = None,
        observed_prefix: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Create a new peer row. Raises if the peer already exists."""
        if self._durable.get_peer(node_id) is not None:
            raise PeerError(f"peer already exists: {node_id}")
        when = now or datetime.now(UTC)
        self._durable.upsert_peer(
            node_id,
            state.value,
            domain,
            current_certificate_sequence,
            endpoints,
            observed_prefix=observed_prefix,
        )
        if state != PeerState.CANDIDATE:
            self._durable.transition_peer(node_id, state.value, now=when)

    def get_peer(self, node_id: str) -> Peer | None:
        """Return the durable peer record, if any."""
        row = self._durable.get_peer(node_id)
        if row is None:
            return None
        return Peer.from_row(row)

    def get_peer_by_domain(self, domain: str) -> Peer | None:
        """Return a peer by domain name, if any."""
        rows = self._durable.conn.execute(
            "SELECT * FROM peers WHERE domain = ?",
            (domain.lower(),),
        ).fetchall()
        if not rows:
            return None
        return Peer.from_row(dict(rows[0]))

    def transition(
        self,
        node_id: str,
        state: PeerState,
        *,
        domain: str | None = None,
        current_certificate_sequence: int | None = None,
        endpoints: dict[str, str] | None = None,
        observed_prefix: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Transition an existing peer to ``state``."""
        if self._durable.get_peer(node_id) is None:
            raise PeerError(f"cannot transition unknown peer: {node_id}")
        self._durable.transition_peer(
            node_id,
            state.value,
            domain=domain,
            current_certificate_sequence=current_certificate_sequence,
            endpoints=endpoints,
            observed_prefix=observed_prefix,
            now=now,
        )

    def record_operational_key(
        self,
        node_id: str,
        operational_public_key: str,
        certificate_sequence: int,
        valid_from: datetime,
        valid_until: datetime,
    ) -> None:
        """Record an accepted operational certificate for a peer."""
        self._durable.record_operational_key(
            node_id,
            operational_public_key,
            certificate_sequence,
            valid_from,
            valid_until,
        )

    def record_observation(
        self,
        node_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Record a successful observation day for ``node_id``.

        ``now`` is used to derive the day key, so fake-clock tests can drive
        maturity deterministically.
        """
        when = now or datetime.now(UTC)
        day = when.strftime("%Y-%m-%d")
        return self._durable.record_observation(node_id, day, when)

    def observation_days(self, node_id: str) -> int:
        """Return the number of distinct successful observation days."""
        return self._durable.observation_days(node_id)

    def list_by_state(self, state: PeerState) -> list[Peer]:
        return [Peer.from_row(row) for row in self._durable.list_peers_by_state(state.value)]

    def list_all(self) -> list[Peer]:
        return [Peer.from_row(row) for row in self._durable.list_all_peers()]

    # -----------------------------------------------------------------------
    # Guard helpers exposed for topology service
    # -----------------------------------------------------------------------

    def promote_guard(self, node_id: str, slot: int, now: datetime | None = None) -> None:
        self._durable.promote_guard(node_id, slot, now)

    def demote_guard(self, node_id: str) -> None:
        self._durable.demote_guard(node_id)

    def list_guards(self) -> list[dict[str, Any]]:
        return self._durable.list_guards()

    def is_guard(self, node_id: str) -> bool:
        return self._durable.is_guard(node_id)


class BlockStore:
    """Explicit local blocks of remote nodes."""

    def __init__(self, durable: PeerRepository) -> None:
        self._durable = durable

    def ensure_root_history(
        self, node_id: str, root_public_key: str, first_seen_at: datetime | None = None
    ) -> None:
        self._durable.ensure_root_history(
            node_id, root_public_key, first_seen_at or datetime.now(UTC)
        )

    def block(self, node_id: str, reason: str, now: datetime | None = None) -> None:
        """Block ``node_id`` locally, overriding any existing peer state."""
        self._durable.add_block(node_id, reason, now)

    def unblock(self, node_id: str) -> None:
        """Remove a local block.

        The caller must decide whether to leave the peer row as ``blocked`` or
        transition it after unblocking.
        """
        self._durable.remove_block(node_id)

    def is_blocked(self, node_id: str) -> bool:
        return self._durable.is_blocked(node_id)

    def list_blocks(self) -> list[dict[str, Any]]:
        return self._durable.list_blocks()


class PeerError(ValueError):
    """Raised when a peer operation is invalid."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_loads(value: Any) -> Any:
    import json

    if value is None:
        return None
    if isinstance(value, dict):
        return value
    return json.loads(value)


def _parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))
