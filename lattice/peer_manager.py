"""
Peer records: who we know, how we learned their key, and who we gossip with.
"""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union

from .models import KeyRotation, PeerRecord, ServerAnnouncement, now_iso
from .sqlite_client import SQLiteClient

logger = logging.getLogger(__name__)

ACTIVE_TRUST = ("direct", "introduced")
RATE_LIMIT_PER_MINUTE = 100
PEER_COLUMNS = "server_uuid, server_id, public_key, endpoint, trust, last_seen_at, is_neighbor"

Peer = Dict[str, Any]
PeerIdentity = Union[PeerRecord, ServerAnnouncement]


def _ago(**delta: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(**delta)).isoformat()


class PeerManager:
    """Stores peer identities and selects gossip neighbors."""

    def __init__(self, db: SQLiteClient, max_neighbors: int = 8):
        self.db = db
        self.max_neighbors = max_neighbors
        self._rng = secrets.SystemRandom()

    def get(self, server_uuid: str) -> Optional[Peer]:
        return self.db.execute_single(f"SELECT {PEER_COLUMNS} FROM lattice_peers WHERE server_uuid = ?", (server_uuid,))

    def get_by_server_id(self, server_id: str) -> Optional[Peer]:
        return self.db.execute_single(f"SELECT {PEER_COLUMNS} FROM lattice_peers WHERE server_id = ?", (server_id.lower(),))

    def with_trust(self, *trust: str) -> List[Peer]:
        placeholders = ", ".join("?" for _ in trust)
        return self.db.execute_query(
            f"SELECT {PEER_COLUMNS} FROM lattice_peers WHERE trust IN ({placeholders}) ORDER BY server_id",
            trust
        )

    def hit(self, column: str, value: str) -> Optional[Peer]:
        """Count a request from a peer against its rate limit and return the peer with request_count."""
        if column not in ("server_uuid", "server_id"):
            raise ValueError(f"Cannot look up peers by {column}")
        return self.db.execute_single(
            f"""
            UPDATE lattice_peers
            SET request_count = CASE
                    WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now') THEN 1
                    ELSE request_count + 1
                END,
                rate_limit_reset_at = CASE
                    WHEN rate_limit_reset_at IS NULL OR rate_limit_reset_at < datetime('now') THEN datetime('now', '+1 minute')
                    ELSE rate_limit_reset_at
                END
            WHERE {column} = ?
            RETURNING {PEER_COLUMNS}, request_count
            """,
            (value,)
        )

    # -----------------------------------------------------------------
    # Admission and updates
    # -----------------------------------------------------------------

    def conflict(self, peer: PeerIdentity) -> Optional[str]:
        """Why `peer` cannot be admitted, or None if it can."""
        existing = self.get(peer.server_uuid)
        if existing and existing["trust"] not in ACTIVE_TRUST:
            return f"server is {existing['trust']}"
        if existing and existing["public_key"] != peer.public_key:
            return "public key differs from the key on record"

        owner = self.get_by_server_id(peer.server_id)
        if owner and owner["server_uuid"] != peer.server_uuid:
            return f"server_id '{peer.server_id}' belongs to {owner['server_uuid']}"
        return None

    def admit(self, peer: PeerIdentity, trust: str) -> bool:
        """Record a peer at `trust`. An existing record with the same key keeps 'direct' if it had it."""
        reason = self.conflict(peer)
        if reason:
            logger.warning("Not admitting %s (%s): %s", peer.server_id, peer.server_uuid, reason)
            return False

        self.db.execute(
            """
            INSERT INTO lattice_peers (server_uuid, server_id, public_key, endpoint, trust, first_seen_at, last_seen_at)
            VALUES (:server_uuid, :server_id, :public_key, :endpoint, :trust, :now, :now)
            ON CONFLICT(server_uuid) DO UPDATE SET
                server_id = excluded.server_id,
                endpoint = excluded.endpoint,
                trust = CASE WHEN lattice_peers.trust = 'direct' THEN 'direct' ELSE excluded.trust END,
                last_seen_at = excluded.last_seen_at
            """,
            {
                "server_uuid": peer.server_uuid,
                "server_id": peer.server_id,
                "public_key": peer.public_key,
                "endpoint": peer.endpoint,
                "trust": trust,
                "now": now_iso()
            }
        )
        logger.info("Admitted %s (%s) as %s", peer.server_id, peer.server_uuid, trust)
        return True

    def apply_announcement(self, announcement: ServerAnnouncement) -> bool:
        """Update a known peer from its own announcement. The caller has verified the signature."""
        owner = self.get_by_server_id(announcement.server_id)
        if owner and owner["server_uuid"] != announcement.server_uuid:
            logger.error(
                "Rejecting announcement: server_id '%s' claimed by %s but owned by %s",
                announcement.server_id, announcement.server_uuid, owner["server_uuid"]
            )
            return False

        updated = self.db.execute_single(
            """
            UPDATE lattice_peers SET server_id = ?, endpoint = ?, last_seen_at = ?
            WHERE server_uuid = ? AND public_key = ?
            RETURNING server_uuid
            """,
            (announcement.server_id, announcement.endpoint, now_iso(), announcement.server_uuid, announcement.public_key)
        )
        return updated is not None

    def rotate_key(self, rotation: KeyRotation) -> bool:
        """Apply a key rotation. The caller has verified it against the stored (old) key."""
        updated = self.db.execute_single(
            """
            UPDATE lattice_peers SET public_key = ?
            WHERE server_uuid = ? AND public_key = ?
            RETURNING server_id
            """,
            (rotation.new_public_key, rotation.server_uuid, rotation.old_public_key)
        )
        if updated:
            logger.info("Rotated key for %s: %s -> %s", updated["server_id"], rotation.old_public_key, rotation.new_public_key)
        return updated is not None

    def set_trust(self, server_uuid: str, trust: str) -> bool:
        """Set a peer's trust level. Blocked and revoked peers also stop being neighbors."""
        updated = self.db.execute_single(
            """
            UPDATE lattice_peers
            SET trust = :trust,
                is_neighbor = CASE WHEN :trust IN ('blocked', 'revoked') THEN 0 ELSE is_neighbor END
            WHERE server_uuid = :server_uuid
            RETURNING server_id
            """,
            {"trust": trust, "server_uuid": server_uuid}
        )
        if updated:
            logger.warning("Peer %s (%s) is now %s", updated["server_id"], server_uuid, trust)
        return updated is not None

    # -----------------------------------------------------------------
    # Neighbors
    # -----------------------------------------------------------------

    def get_active_neighbors(self) -> List[Peer]:
        """Neighbors heard from in the last 24 hours."""
        return self.db.execute_query(
            f"""
            SELECT {PEER_COLUMNS} FROM lattice_peers
            WHERE is_neighbor = 1 AND trust IN ('direct', 'introduced') AND last_seen_at > ?
            """,
            (_ago(hours=24),)
        )

    def select_new_neighbors(self) -> None:
        """Fill the neighbor set from peers seen this week, or occasionally rotate one for diversity."""
        count = self.db.execute_single("SELECT COUNT(*) AS n FROM lattice_peers WHERE is_neighbor = 1")["n"]
        candidates = [
            row["server_uuid"] for row in self.db.execute_query(
                """
                SELECT server_uuid FROM lattice_peers
                WHERE is_neighbor = 0 AND trust IN ('direct', 'introduced') AND last_seen_at > ?
                """,
                (_ago(days=7),)
            )
        ]
        if not candidates:
            return

        if count < self.max_neighbors:
            added = self._rng.sample(candidates, min(self.max_neighbors - count, len(candidates)))
        elif self._rng.random() < 0.2:
            added = [self._rng.choice(candidates)]
            self.db.execute(
                """
                UPDATE lattice_peers SET is_neighbor = 0
                WHERE server_uuid = (SELECT server_uuid FROM lattice_peers WHERE is_neighbor = 1 ORDER BY RANDOM() LIMIT 1)
                """
            )
        else:
            return

        for server_uuid in added:
            self.db.execute("UPDATE lattice_peers SET is_neighbor = 1 WHERE server_uuid = ?", (server_uuid,))
        logger.info("Added %d neighbors", len(added))

    def cleanup_stale_peers(self, days: int = 30) -> int:
        """Drop stale neighbors, and forget introduced peers unseen for 90 days. Direct and blocked peers are kept."""
        dropped = self.db.execute_query(
            "UPDATE lattice_peers SET is_neighbor = 0 WHERE is_neighbor = 1 AND last_seen_at < ? RETURNING server_uuid",
            (_ago(days=days),)
        )
        forgotten = self.db.execute_query(
            "DELETE FROM lattice_peers WHERE trust = 'introduced' AND last_seen_at < ? RETURNING server_uuid",
            (_ago(days=90),)
        )
        return len(dropped) + len(forgotten)
