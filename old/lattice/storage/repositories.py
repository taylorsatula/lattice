"""Transaction-per-workflow repositories for Lattice durable state."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Generic, TypeVar

from lattice.storage.connection import StorageError, open_connection


class RepositoryError(StorageError):
    """Raised when a repository operation fails."""


T = TypeVar("T")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_ts(when: datetime) -> str:
    if when.tzinfo is None:
        raise RepositoryError("timestamp must be timezone-aware")
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _json_loads(text: str | None) -> Any:
    if text is None:
        return None
    return json.loads(text)


@dataclass
class Lease:
    """A compare-and-set lease returned by claim operations."""

    owner: str
    expires_at: datetime


class BaseRepository(Generic[T]):
    """Base class for repositories operating on a single SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @classmethod
    @contextmanager
    def connect(cls, db_path: Path | str) -> Generator[BaseRepository[T], None, None]:
        """Open a repository with a fresh connection and close it on exit."""
        conn = open_connection(db_path)
        try:
            yield cls(conn)
        finally:
            conn.close()

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn


class DomainPinRepository(BaseRepository[Any]):
    """Repository for durable domain-to-node pins."""

    def upsert(
        self,
        domain: str,
        node_id: str,
        root_public_key: str,
        operational_certificate: dict[str, Any],
        endpoints: dict[str, str],
    ) -> None:
        """Upsert the durable pin for ``domain``.

        Compare-and-set: when the pin already binds ``domain`` to the same
        node, the certificate sequence may only advance. The recorded prior
        is the maximum of the pin's stored sequence, the peer row's
        ``current_certificate_sequence``, and the highest sequence in
        ``peer_operational_keys``; a lower sequence, or an equal sequence
        carrying a different operational key, is refused. Rebinding to a
        DIFFERENT node is deliberately not refused here so the trust
        accept-transfer rewrite keeps working; node-binding refusal lives at
        the re-resolution/pin boundary (``WellKnownResolver.pin``), backed
        by an explicit local reset (``reset_domain``).
        """
        domain_key = domain.lower()
        existing = self.get(domain_key)
        if existing is not None and existing.get("node_id") == node_id:
            new_cert = operational_certificate if isinstance(operational_certificate, dict) else {}
            new_seq = new_cert.get("sequence")
            new_key = new_cert.get("operational_public_key")
            old_cert = existing.get("operational_certificate")
            if not isinstance(old_cert, dict):
                old_cert = {}
            priors: list[int] = []
            if isinstance(old_cert.get("sequence"), int):
                priors.append(int(old_cert["sequence"]))
            peer_row = self._conn.execute(
                "SELECT current_certificate_sequence FROM peers WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            if peer_row is not None and peer_row["current_certificate_sequence"] is not None:
                priors.append(int(peer_row["current_certificate_sequence"]))
            key_row = self._conn.execute(
                "SELECT MAX(certificate_sequence) AS max_seq FROM peer_operational_keys "
                "WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            if key_row is not None and key_row["max_seq"] is not None:
                priors.append(int(key_row["max_seq"]))
            prior = max(priors) if priors else None
            if prior is not None:
                if not isinstance(new_seq, int):
                    raise RepositoryError(
                        f"refusing pin rewrite for {domain_key}: "
                        "certificate sequence is missing or malformed"
                    )
                if new_seq < prior:
                    raise RepositoryError(
                        f"refusing pin rewrite for {domain_key}: certificate "
                        f"sequence {new_seq} would roll back recorded sequence {prior}"
                    )
                if new_seq == prior:
                    # Equal sequence: an operational key swap is a rollback in
                    # disguise. Refuse unless the recorded key is unknown.
                    known_key = None
                    pin_seq = old_cert.get("sequence")
                    if isinstance(pin_seq, int) and pin_seq == new_seq:
                        known_key = old_cert.get("operational_public_key")
                    if known_key is None:
                        seq_row = self._conn.execute(
                            "SELECT operational_public_key FROM peer_operational_keys "
                            "WHERE node_id = ? AND certificate_sequence = ?",
                            (node_id, new_seq),
                        ).fetchone()
                        if seq_row is not None:
                            known_key = seq_row["operational_public_key"]
                    if known_key is not None and known_key != new_key:
                        raise RepositoryError(
                            f"refusing pin rewrite for {domain_key}: sequence "
                            f"{new_seq} would swap the recorded operational key"
                        )
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO domain_pins
                    (domain, node_id, root_public_key, operational_certificate,
                     endpoints, pinned_at, last_verified_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    node_id = excluded.node_id,
                    root_public_key = excluded.root_public_key,
                    operational_certificate = excluded.operational_certificate,
                    endpoints = excluded.endpoints,
                    last_verified_at = excluded.last_verified_at,
                    transfer_node_id = NULL,
                    trust_reset_at = NULL
                """,
                (
                    domain_key,
                    node_id,
                    root_public_key,
                    _json_dumps(operational_certificate),
                    _json_dumps(endpoints),
                    _format_ts(_utc_now()),
                    _format_ts(_utc_now()),
                ),
            )

    def get(self, domain: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT domain, node_id, root_public_key, operational_certificate, "
            "endpoints, pinned_at, last_verified_at, transfer_node_id, trust_reset_at "
            "FROM domain_pins WHERE domain = ?",
            (domain.lower(),),
        ).fetchone()
        if row is None:
            return None
        return {
            "domain": row["domain"],
            "node_id": row["node_id"],
            "root_public_key": row["root_public_key"],
            "operational_certificate": _json_loads(row["operational_certificate"]),
            "endpoints": _json_loads(row["endpoints"]),
            "pinned_at": row["pinned_at"],
            "last_verified_at": row["last_verified_at"],
            "transfer_node_id": row["transfer_node_id"],
            "trust_reset_at": row["trust_reset_at"],
        }

    def delete(self, domain: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM domain_pins WHERE domain = ?", (domain.lower(),))

    def get_by_node_id(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT domain, node_id, root_public_key, operational_certificate, "
            "endpoints, pinned_at, last_verified_at, transfer_node_id, trust_reset_at "
            "FROM domain_pins WHERE node_id = ? ORDER BY pinned_at DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "domain": row["domain"],
            "node_id": row["node_id"],
            "root_public_key": row["root_public_key"],
            "operational_certificate": _json_loads(row["operational_certificate"]),
            "endpoints": _json_loads(row["endpoints"]),
            "pinned_at": row["pinned_at"],
            "last_verified_at": row["last_verified_at"],
            "transfer_node_id": row["transfer_node_id"],
            "trust_reset_at": row["trust_reset_at"],
        }


class PeerRepository(BaseRepository[Any]):
    """Repository for peer root/operational history and mutable state."""

    def ensure_root_history(
        self, node_id: str, root_public_key: str, first_seen_at: datetime
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO peer_root_history (node_id, root_public_key, first_seen_at)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id) DO NOTHING
                """,
                (node_id, root_public_key, _format_ts(first_seen_at)),
            )

    def get_root_history(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT node_id, root_public_key, first_seen_at, retired_at "
            "FROM peer_root_history WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_peer(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM peers WHERE node_id = ?", (node_id,)).fetchone()
        if row is None:
            return None
        return dict(row)

    def upsert_peer(
        self,
        node_id: str,
        state: str,
        domain: str | None,
        current_certificate_sequence: int | None,
        endpoints: dict[str, str] | None,
        *,
        observed_prefix: str | None = None,
    ) -> None:
        now = _format_ts(_utc_now())
        with self._conn:
            existing = self.get_peer(node_id)
            if existing is None:
                self._conn.execute(
                    """
                    INSERT INTO peers
                        (node_id, state, domain, current_certificate_sequence,
                         endpoints, observed_prefix, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        node_id,
                        state,
                        domain,
                        current_certificate_sequence,
                        _json_dumps(endpoints) if endpoints else None,
                        observed_prefix,
                        now,
                        now,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE peers SET
                        state = ?,
                        domain = COALESCE(?, domain),
                        current_certificate_sequence = COALESCE(?, current_certificate_sequence),
                        endpoints = COALESCE(?, endpoints),
                        observed_prefix = COALESCE(?, observed_prefix),
                        last_seen_at = ?
                    WHERE node_id = ?
                    """,
                    (
                        state,
                        domain,
                        current_certificate_sequence,
                        _json_dumps(endpoints) if endpoints else None,
                        observed_prefix,
                        now,
                        node_id,
                    ),
                )

    def transition_peer(
        self,
        node_id: str,
        state: str,
        *,
        domain: str | None = None,
        current_certificate_sequence: int | None = None,
        endpoints: dict[str, str] | None = None,
        observed_prefix: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Transition a peer to ``state`` and record the matching timestamp."""
        when = now or _utc_now()
        ts = _format_ts(when)
        with self._conn:
            existing = self.get_peer(node_id)
            if existing is None:
                raise RepositoryError(f"cannot transition missing peer: {node_id}")

            state_col = {
                "verified": "verified_at",
                "established": "established_at",
                "blocked": "blocked_at",
            }.get(state)
            updates = ["state = ?"]
            params: list[Any] = [state]
            if domain is not None:
                updates.append("domain = ?")
                params.append(domain)
            if current_certificate_sequence is not None:
                updates.append("current_certificate_sequence = ?")
                params.append(current_certificate_sequence)
            if endpoints is not None:
                updates.append("endpoints = ?")
                params.append(_json_dumps(endpoints))
            if observed_prefix is not None:
                updates.append("observed_prefix = ?")
                params.append(observed_prefix)
            if state_col is not None:
                updates.append(f"{state_col} = ?")
                params.append(ts)
            updates.append("last_seen_at = ?")
            params.append(ts)
            params.append(node_id)

            sql = f"UPDATE peers SET {', '.join(updates)} WHERE node_id = ?"
            self._conn.execute(sql, params)

    def record_operational_key(
        self,
        node_id: str,
        operational_public_key: str,
        certificate_sequence: int,
        valid_from: datetime,
        valid_until: datetime,
    ) -> None:
        """Record an accepted operational key/certificate for a peer.

        Stateful sequence gate: the certificate sequence must advance the
        node's recorded prior — the highest sequence already recorded here
        and the peer row's ``current_certificate_sequence``. An equal
        sequence is idempotent only for the identical key; a lower sequence,
        or an equal sequence carrying a different key, is refused so a
        retired key cannot be rolled back into legitimacy.
        """
        with self._conn:
            same_seq = self._conn.execute(
                "SELECT operational_public_key FROM peer_operational_keys "
                "WHERE node_id = ? AND certificate_sequence = ?",
                (node_id, certificate_sequence),
            ).fetchone()
            if (
                same_seq is not None
                and same_seq["operational_public_key"] != operational_public_key
            ):
                raise RepositoryError(
                    f"operational key conflict for {node_id} "
                    f"at sequence {certificate_sequence}"
                )
            top = self._conn.execute(
                "SELECT MAX(certificate_sequence) AS max_seq FROM peer_operational_keys "
                "WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            top_seq = top["max_seq"] if top is not None else None
            if top_seq is not None and certificate_sequence < int(top_seq):
                raise RepositoryError(
                    f"certificate sequence rollback for {node_id}: "
                    f"{certificate_sequence} < {int(top_seq)}"
                )
            peer_row = self._conn.execute(
                "SELECT current_certificate_sequence FROM peers WHERE node_id = ?",
                (node_id,),
            ).fetchone()
            if peer_row is not None and peer_row["current_certificate_sequence"] is not None:
                prior = int(peer_row["current_certificate_sequence"])
                if certificate_sequence < prior:
                    raise RepositoryError(
                        f"certificate sequence rollback for {node_id}: "
                        f"{certificate_sequence} < {prior}"
                    )
            self._conn.execute(
                """
                INSERT INTO peer_operational_keys
                    (node_id, operational_public_key, certificate_sequence,
                     valid_from, valid_until, received_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, certificate_sequence) DO UPDATE SET
                    operational_public_key = excluded.operational_public_key,
                    valid_from = excluded.valid_from,
                    valid_until = excluded.valid_until,
                    received_at = excluded.received_at
                """,
                (
                    node_id,
                    operational_public_key,
                    certificate_sequence,
                    _format_ts(valid_from),
                    _format_ts(valid_until),
                    _format_ts(_utc_now()),
                ),
            )

    def record_observation(self, node_id: str, day: str, now: datetime) -> bool:
        """Record a successful observation day for ``node_id``.

        Returns True if a new row was inserted, False if the day already exists.
        """
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO peer_observations (node_id, day, observed_at)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id, day) DO NOTHING
                """,
                (node_id, day, _format_ts(now)),
            )
            return cursor.rowcount == 1

    def observation_days(self, node_id: str) -> int:
        """Return the number of distinct observation days for ``node_id``."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS count FROM peer_observations WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        assert row is not None
        return int(row["count"])

    def list_peers_by_state(self, state: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM peers WHERE state = ? ORDER BY first_seen_at", (state,)
        ).fetchall()
        return [dict(row) for row in rows]

    def list_all_peers(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM peers ORDER BY first_seen_at").fetchall()
        return [dict(row) for row in rows]

    # -----------------------------------------------------------------------
    # Blocks
    # -----------------------------------------------------------------------

    def add_block(self, node_id: str, reason: str, now: datetime | None = None) -> None:
        """Add or update a local block for ``node_id``."""
        when = now or _utc_now()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO blocks (node_id, blocked_at, reason)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    blocked_at = excluded.blocked_at,
                    reason = excluded.reason
                """,
                (node_id, _format_ts(when), reason),
            )
            self._conn.execute(
                "UPDATE peers SET state = 'blocked', blocked_at = ?, block_reason = ? "
                "WHERE node_id = ?",
                (_format_ts(when), reason, node_id),
            )

    def remove_block(self, node_id: str) -> None:
        """Remove a local block for ``node_id``."""
        with self._conn:
            self._conn.execute("DELETE FROM blocks WHERE node_id = ?", (node_id,))

    def is_blocked(self, node_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM blocks WHERE node_id = ?", (node_id,)).fetchone()
        return row is not None

    def list_blocks(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT node_id, blocked_at, reason FROM blocks ORDER BY blocked_at"
        ).fetchall()
        return [dict(row) for row in rows]

    # -----------------------------------------------------------------------
    # Guards
    # -----------------------------------------------------------------------

    def promote_guard(self, node_id: str, slot: int, now: datetime | None = None) -> None:
        """Promote ``node_id`` to the stable guard ``slot``."""
        when = now or _utc_now()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO guards (node_id, slot, promoted_at)
                VALUES (?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    slot = excluded.slot,
                    promoted_at = excluded.promoted_at
                """,
                (node_id, slot, _format_ts(when)),
            )

    def demote_guard(self, node_id: str) -> None:
        """Remove ``node_id`` from the guard set."""
        with self._conn:
            self._conn.execute("DELETE FROM guards WHERE node_id = ?", (node_id,))

    def list_guards(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT node_id, slot, promoted_at FROM guards ORDER BY slot"
        ).fetchall()
        return [dict(row) for row in rows]

    def is_guard(self, node_id: str) -> bool:
        row = self._conn.execute("SELECT 1 FROM guards WHERE node_id = ?", (node_id,)).fetchone()
        return row is not None


# Retention window and aggregate ceiling for persisted rate-bucket rows.
# Peer identities are attacker-chosen (self-attested card node_ids), so
# persisted identity-keyed state needs an age rule and a global bound.
_RATE_BUCKET_RETENTION_SECONDS = 86400.0
_MAX_RATE_BUCKET_ROWS = 10_000


class CacheRepository(BaseRepository[Any]):
    """Repository for disposable cache state."""

    # -----------------------------------------------------------------------
    # Candidates
    # -----------------------------------------------------------------------

    def count_candidates(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS count FROM candidates").fetchone()
        assert row is not None
        return int(row["count"])

    def count_candidates_by_introducer(self, introducer: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS count FROM candidates WHERE introduced_by = ?",
            (introducer,),
        ).fetchone()
        assert row is not None
        return int(row["count"])

    def count_candidates_by_prefix(self, prefix: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS count FROM candidates WHERE observed_prefix = ?",
            (prefix,),
        ).fetchone()
        assert row is not None
        return int(row["count"])

    def add_candidate(
        self,
        node_id: str,
        introduced_by: str | None,
        observed_prefix: str | None,
        card_json: str,
        received_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO candidates
                    (node_id, introduced_by, observed_prefix, card_json,
                     received_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    introduced_by = excluded.introduced_by,
                    observed_prefix = excluded.observed_prefix,
                    card_json = excluded.card_json,
                    received_at = excluded.received_at,
                    expires_at = excluded.expires_at
                """,
                (
                    node_id,
                    introduced_by,
                    observed_prefix,
                    card_json,
                    _format_ts(received_at),
                    _format_ts(expires_at),
                ),
            )

    def get_candidate(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM candidates WHERE node_id = ?", (node_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def remove_candidate(self, node_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM candidates WHERE node_id = ?", (node_id,))

    def list_candidates(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM candidates ORDER BY received_at").fetchall()
        return [dict(row) for row in rows]

    def prune_candidates(self, now: datetime) -> int:
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM candidates WHERE expires_at <= ?",
                (_format_ts(now),),
            )
            return cursor.rowcount

    # -----------------------------------------------------------------------
    # Transient cards
    # -----------------------------------------------------------------------

    def add_transient_card(
        self,
        node_id: str,
        card_json: str,
        received_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO transient_cards (node_id, card_json, received_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    card_json = excluded.card_json,
                    received_at = excluded.received_at,
                    expires_at = excluded.expires_at
                """,
                (node_id, card_json, _format_ts(received_at), _format_ts(expires_at)),
            )

    def get_transient_card(self, node_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM transient_cards WHERE node_id = ?", (node_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_transient_cards(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM transient_cards ORDER BY received_at").fetchall()
        return [dict(row) for row in rows]

    def remove_transient_card(self, node_id: str) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM transient_cards WHERE node_id = ?", (node_id,))

    # -----------------------------------------------------------------------
    # Discovery set
    # -----------------------------------------------------------------------

    def add_to_discovery_set(
        self,
        node_id: str,
        selected_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO discovery_set (node_id, selected_at, expires_at) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET "
                "selected_at = excluded.selected_at, "
                "expires_at = excluded.expires_at",
                (node_id, _format_ts(selected_at), _format_ts(expires_at)),
            )

    def list_discovery_set(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT node_id FROM discovery_set WHERE expires_at > ?",
            (_format_ts(datetime.now(UTC)),),
        ).fetchall()
        return [str(row["node_id"]) for row in rows]

    def remove_from_discovery_set(self, node_id: str) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM discovery_set WHERE node_id = ?",
                (node_id,),
            )

    def prune_discovery_set(self, now: datetime) -> int:
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM discovery_set WHERE expires_at <= ?",
                (_format_ts(now),),
            )
            return cursor.rowcount

    # -----------------------------------------------------------------------
    # Rate bucket persistence
    # -----------------------------------------------------------------------

    def save_rate_bucket(
        self,
        node_id: str,
        message_tokens: float,
        gossip_tokens: float,
        last_updated: str,
    ) -> None:
        """Upsert a persisted rate bucket row and enforce retention.

        Rows untouched longer than the retention window are deleted, and the
        table is trimmed to its aggregate row ceiling (oldest first) so a
        churn of attacker-chosen node_ids cannot grow it without bound.
        """
        with self._conn:
            self._conn.execute(
                "INSERT INTO rate_buckets (node_id, message_tokens, gossip_tokens, last_updated) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(node_id) DO UPDATE SET "
                "message_tokens = excluded.message_tokens, "
                "gossip_tokens = excluded.gossip_tokens, "
                "last_updated = excluded.last_updated",
                (node_id, message_tokens, gossip_tokens, last_updated),
            )
            row = self._conn.execute("SELECT COUNT(*) AS count FROM rate_buckets").fetchone()
            assert row is not None
            if int(row["count"]) > _MAX_RATE_BUCKET_ROWS:
                self._prune_rate_buckets(float(last_updated))

    def prune_rate_buckets(self, now_epoch: float) -> int:
        """Delete rate-bucket rows past retention, then trim to the ceiling."""
        with self._conn:
            return self._prune_rate_buckets(now_epoch)

    def _prune_rate_buckets(self, now_epoch: float) -> int:
        """Prune; caller owns the transaction."""
        cursor = self._conn.execute(
            "DELETE FROM rate_buckets WHERE CAST(last_updated AS REAL) < ?",
            (now_epoch - _RATE_BUCKET_RETENTION_SECONDS,),
        )
        deleted = cursor.rowcount
        cursor = self._conn.execute(
            "DELETE FROM rate_buckets WHERE node_id NOT IN ("
            "SELECT node_id FROM rate_buckets "
            "ORDER BY CAST(last_updated AS REAL) DESC LIMIT ?)",
            (_MAX_RATE_BUCKET_ROWS,),
        )
        return deleted + cursor.rowcount

    def load_rate_buckets(
        self,
    ) -> list[tuple[str, float, float, float]]:
        """Load persisted rate buckets still within the retention window."""
        cutoff = time.time() - _RATE_BUCKET_RETENTION_SECONDS
        rows = self._conn.execute(
            "SELECT node_id, message_tokens, gossip_tokens, last_updated "
            "FROM rate_buckets WHERE CAST(last_updated AS REAL) >= ?",
            (cutoff,),
        ).fetchall()
        result: list[tuple[str, float, float, float]] = []
        for row in rows:
            result.append(
                (
                    row["node_id"],
                    float(row["message_tokens"]),
                    float(row["gossip_tokens"]),
                    float(row["last_updated"]),
                )
            )
        return result

    def prune_transient_cards(self, now: datetime) -> int:
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM transient_cards WHERE expires_at <= ?",
                (_format_ts(now),),
            )
            return cursor.rowcount


class OutboundMessageRepository(BaseRepository[Any]):
    """Repository for outbound message custody state."""

    def create(
        self,
        message_id: str,
        to_node_id: str,
        to_address: str,
        from_address: str,
        content: str,
        extension: dict[str, Any] | None,
        message_json: dict[str, Any],
        priority: str,
        ttl_seconds: int,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO outbound_messages
                    (message_id, to_node_id, to_address, from_address, content,
                     extension, message_json, priority, ttl_seconds, status, attempt_count,
                     next_attempt_at, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
                """,
                (
                    message_id,
                    to_node_id,
                    to_address,
                    from_address,
                    content,
                    _json_dumps(extension) if extension else None,
                    _json_dumps(message_json),
                    priority,
                    ttl_seconds,
                    _format_ts(created_at),
                    _format_ts(created_at),
                    _format_ts(expires_at),
                ),
            )

    def get(self, message_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM outbound_messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def claim_pending(
        self,
        owner: str,
        now: datetime,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Atomically claim pending/expired-lease messages for delivery."""
        ts = _format_ts(now)
        with self._conn:
            # Mark up to ``limit`` rows as leased by ``owner``; RETURNING yields
            # exactly the rows this UPDATE claimed, never rows leased by a
            # previous claim still held by the same owner.
            cursor = self._conn.execute(
                """
                UPDATE outbound_messages
                SET status = 'leased',
                    lease_owner = ?,
                    lease_expires_at = ?,
                    attempt_count = attempt_count + 1
                WHERE id IN (
                    SELECT id FROM outbound_messages
                    WHERE status IN ('pending', 'leased')
                      AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                      AND expires_at > ?
                      AND (lease_owner IS NULL OR lease_expires_at <= ?)
                    ORDER BY
                        CASE priority
                            WHEN 'urgent' THEN 1
                            WHEN 'high' THEN 2
                            ELSE 3
                        END,
                        created_at
                    LIMIT ?
                )
                RETURNING *
                """,
                (owner, _format_ts(now + timedelta(minutes=5)), ts, ts, ts, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    def release_lease(
        self,
        message_id: str,
        owner: str,
        next_attempt_at: datetime,
        now: datetime,
    ) -> bool:
        """Release a lease and schedule the next attempt.

        Returns True if the row was owned by ``owner`` and updated.
        """
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE outbound_messages
                SET status = 'pending',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    next_attempt_at = ?
                WHERE message_id = ?
                  AND lease_owner = ?
                  AND lease_expires_at > ?
                """,
                (
                    _format_ts(next_attempt_at),
                    message_id,
                    owner,
                    _format_ts(now),
                ),
            )
            return cursor.rowcount == 1

    def mark_terminal(
        self,
        message_id: str,
        owner: str,
        status: str,
        now: datetime,
        *,
        erase_content: bool = True,
        erase_value: str | None = None,
    ) -> bool:
        """Mark an outbound message as terminal and optionally erase content."""
        with self._conn:
            if erase_content:
                cursor = self._conn.execute(
                    """
                    UPDATE outbound_messages
                    SET status = ?,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = NULL,
                        content = ?,
                        extension = NULL,
                        message_json = ?
                    WHERE message_id = ?
                      AND lease_owner = ?
                      AND status = 'leased'
                    """,
                    (
                        status,
                        erase_value or "[erased]",
                        erase_value or "[erased]",
                        message_id,
                        owner,
                    ),
                )
            else:
                cursor = self._conn.execute(
                    """
                    UPDATE outbound_messages
                    SET status = ?,
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        next_attempt_at = NULL
                    WHERE message_id = ?
                      AND lease_owner = ?
                      AND status = 'leased'
                    """,
                    (status, message_id, owner),
                )
            return cursor.rowcount == 1

    def list_pending(self, now: datetime) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT * FROM outbound_messages
            WHERE status IN ('pending', 'leased')
              AND expires_at > ?
            ORDER BY
                CASE priority
                    WHEN 'urgent' THEN 1
                    WHEN 'high' THEN 2
                    ELSE 3
                END,
                created_at
            """,
            (_format_ts(now),),
        ).fetchall()
        return [dict(row) for row in rows]

    def expire_messages(self, now: datetime, *, erase_value: str | None = None) -> list[str]:
        """Mark expired pending/leased messages as expired and erase content."""
        ts = _format_ts(now)
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE outbound_messages
                SET status = 'expired',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    next_attempt_at = NULL,
                    content = ?,
                    extension = NULL,
                    message_json = ?
                WHERE status IN ('pending', 'leased')
                  AND expires_at <= ?
                  AND (lease_owner IS NULL OR lease_expires_at <= ?)
                RETURNING message_id
                """,
                (erase_value or "[erased]", erase_value or "[erased]", ts, ts),
            )
            return [str(row["message_id"]) for row in cursor.fetchall()]


class InboundMessageRepository(BaseRepository[Any]):
    """Repository for inbound durable custody state."""

    def create(
        self,
        message_id: str,
        from_node_id: str,
        from_address: str,
        to_address: str,
        content: str,
        extension: dict[str, Any] | None,
        message_json: dict[str, Any],
        priority: str,
        receipt: dict[str, Any],
        received_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO inbound_messages
                    (message_id, from_node_id, from_address, to_address, content,
                     extension, message_json, priority, status, receipt, received_at,
                     webhook_attempt_count, webhook_next_attempt_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'accepted', ?, ?, 0, ?)
                """,
                (
                    message_id,
                    from_node_id,
                    from_address,
                    to_address,
                    content,
                    _json_dumps(extension) if extension else None,
                    _json_dumps(message_json),
                    priority,
                    _json_dumps(receipt),
                    _format_ts(received_at),
                    _format_ts(received_at),
                ),
            )

    def get(self, message_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM inbound_messages WHERE message_id = ?", (message_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_existing_receipt(self, message_id: str, from_node_id: str) -> dict[str, Any] | None:
        """Return the existing receipt for a duplicate message, if any."""
        row = self._conn.execute(
            "SELECT receipt FROM inbound_messages WHERE message_id = ? AND from_node_id = ?",
            (message_id, from_node_id),
        ).fetchone()
        if row is None:
            return None
        receipt = _json_loads(row["receipt"])
        if isinstance(receipt, dict):
            return receipt
        return None

    def claim_for_webhook(
        self,
        owner: str,
        now: datetime,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        """Atomically claim accepted messages for webhook delivery."""
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE inbound_messages
                SET status = 'webhook_leased',
                    webhook_lease_owner = ?,
                    webhook_lease_expires_at = ?,
                    webhook_attempt_count = webhook_attempt_count + 1
                WHERE id IN (
                    SELECT id FROM inbound_messages
                    WHERE status IN ('accepted', 'webhook_leased')
                      AND (webhook_next_attempt_at IS NULL OR webhook_next_attempt_at <= ?)
                      AND (webhook_lease_owner IS NULL OR webhook_lease_expires_at <= ?)
                    ORDER BY
                        CASE priority
                            WHEN 'urgent' THEN 1
                            WHEN 'high' THEN 2
                            ELSE 3
                        END,
                        received_at
                    LIMIT ?
                )
                RETURNING *
                """,
                (
                    owner,
                    _format_ts(now + timedelta(minutes=5)),
                    _format_ts(now),
                    _format_ts(now),
                    limit,
                ),
            )
            return [dict(row) for row in cursor.fetchall()]

    def release_webhook_lease(
        self,
        message_id: str,
        owner: str,
        next_attempt_at: datetime,
        now: datetime,
    ) -> bool:
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE inbound_messages
                SET status = 'accepted',
                    webhook_lease_owner = NULL,
                    webhook_lease_expires_at = NULL,
                    webhook_next_attempt_at = ?
                WHERE message_id = ?
                  AND webhook_lease_owner = ?
                  AND webhook_lease_expires_at > ?
                """,
                (
                    _format_ts(next_attempt_at),
                    message_id,
                    owner,
                    _format_ts(now),
                ),
            )
            return cursor.rowcount == 1

    def mark_terminal(
        self,
        message_id: str,
        owner: str,
        status: str,
        now: datetime,
        *,
        erase_content: bool = True,
        erase_value: str | None = None,
    ) -> bool:
        """Mark an inbound message as terminal and erase content."""
        with self._conn:
            if erase_content:
                cursor = self._conn.execute(
                    """
                    UPDATE inbound_messages
                    SET status = ?,
                        webhook_lease_owner = NULL,
                        webhook_lease_expires_at = NULL,
                        webhook_next_attempt_at = NULL,
                        terminal_at = ?,
                        content = ?,
                        extension = NULL,
                        message_json = ?
                    WHERE message_id = ?
                      AND webhook_lease_owner = ?
                      AND status = 'webhook_leased'
                    """,
                    (
                        status,
                        _format_ts(now),
                        erase_value or "[erased]",
                        erase_value or "[erased]",
                        message_id,
                        owner,
                    ),
                )
            else:
                cursor = self._conn.execute(
                    """
                    UPDATE inbound_messages
                    SET status = ?,
                        webhook_lease_owner = NULL,
                        webhook_lease_expires_at = NULL,
                        webhook_next_attempt_at = NULL,
                        terminal_at = ?
                    WHERE message_id = ?
                      AND webhook_lease_owner = ?
                      AND status = 'webhook_leased'
                    """,
                    (status, _format_ts(now), message_id, owner),
                )
            return cursor.rowcount == 1


class ContactRepository(BaseRepository[Any]):
    """Repository for the operator contact book of verified human bindings."""

    def upsert(
        self,
        node_id: str,
        username: str,
        domain: str | None,
        display_name: str | None,
        avatar_url: str | None,
        root_public_key: str,
        card_json: str,
        imported_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO contacts
                    (node_id, username, domain, display_name, avatar_url,
                     root_public_key, card_json, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id, username) DO UPDATE SET
                    domain = excluded.domain,
                    display_name = excluded.display_name,
                    avatar_url = excluded.avatar_url,
                    root_public_key = excluded.root_public_key,
                    card_json = excluded.card_json,
                    imported_at = excluded.imported_at
                """,
                (
                    node_id,
                    username,
                    domain,
                    display_name,
                    avatar_url,
                    root_public_key,
                    card_json,
                    _format_ts(imported_at),
                ),
            )

    def get(self, node_id: str, username: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM contacts WHERE node_id = ? AND username = ?",
            (node_id, username),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_by_username(self, username: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM contacts WHERE username = ? ORDER BY imported_at LIMIT 1",
            (username,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def list_all(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM contacts ORDER BY username, node_id").fetchall()
        return [dict(row) for row in rows]

    def delete(self, node_id: str, username: str) -> None:
        with self._conn:
            self._conn.execute(
                "DELETE FROM contacts WHERE node_id = ? AND username = ?",
                (node_id, username),
            )


class AuditLogRepository(BaseRepository[Any]):
    """Repository for structured audit events."""

    def insert(
        self,
        event_code: str,
        node_id: str | None,
        message_id: str | None,
        details: dict[str, Any] | None,
        recorded_at: datetime,
    ) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO audit_log (event_code, node_id, message_id, details, recorded_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    event_code,
                    node_id,
                    message_id,
                    _json_dumps(details) if details else None,
                    _format_ts(recorded_at),
                ),
            )


class WebhookStateRepository(BaseRepository[Any]):
    """Repository for webhook idempotency and retry state."""

    def upsert(
        self,
        message_id: str,
        idempotency_key: str,
        last_status_code: int | None,
        last_error: str | None,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO webhook_state
                    (message_id, idempotency_key, last_status_code, last_error)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(message_id) DO UPDATE SET
                    idempotency_key = excluded.idempotency_key,
                    last_status_code = excluded.last_status_code,
                    last_error = excluded.last_error
                """,
                (message_id, idempotency_key, last_status_code, last_error),
            )

    def get(self, message_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM webhook_state WHERE message_id = ?", (message_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)
