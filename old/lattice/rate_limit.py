"""In-memory authenticated per-peer token buckets for Lattice v1."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field


class RateLimitError(ValueError):
    """Raised when a rate-limit configuration is invalid."""


# Aggregate ceiling on tracked (peer_id, kind) buckets. Peer identities are
# attacker-chosen (self-attested card node_ids, XFF-derived values), so
# identity-keyed state needs a global bound, not just per-key quotas.
_MAX_TRACKED_BUCKETS = 10_000
# A bucket untouched for this long is expired and evictable. Eviction loses
# nothing: after this idle the bucket would have refilled to full capacity
# anyway.
_BUCKET_IDLE_SECONDS = 3600.0


@dataclass
class TokenBucket:
    """A simple token bucket with lazy refill.

    Uses wall-clock time internally so state can be persisted across
    process restarts without drift.
    """

    rate_per_second: float
    capacity: float
    _tokens: float = field(init=False)
    _last_updated: float = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise RateLimitError("rate_per_second must be positive")
        if self.capacity <= 0:
            raise RateLimitError("capacity must be positive")
        self._tokens = self.capacity
        self._last_updated = time.time()

    @classmethod
    def restore(
        cls,
        rate_per_second: float,
        capacity: float,
        saved_tokens: float,
        saved_last_updated: float,
    ) -> TokenBucket:
        """Restore a bucket from previously persisted state."""
        if rate_per_second <= 0 or capacity <= 0:
            raise RateLimitError("rate and capacity must be positive")
        instance = cls.__new__(cls)
        instance.rate_per_second = rate_per_second
        instance.capacity = capacity
        instance._tokens = saved_tokens
        instance._last_updated = saved_last_updated
        instance._lock = threading.Lock()
        return instance

    def state(self) -> tuple[float, float]:
        """Return (current_tokens, last_updated_epoch) for persistence."""
        with self._lock:
            return (self._tokens, self._last_updated)

    def consume(self, tokens: float = 1.0) -> bool:
        """Try to consume ``tokens`` from the bucket.

        Non-finite requests are rejected, and a bucket whose computed state
        has gone non-finite is normalized to empty rather than locking the
        peer out forever with a NaN comparison.
        """
        if not math.isfinite(tokens) or tokens <= 0:
            return False
        with self._lock:
            now = time.time()
            elapsed = now - self._last_updated
            if math.isfinite(self._tokens):
                self._tokens = min(
                    self.capacity, self._tokens + elapsed * self.rate_per_second
                )
            if not math.isfinite(self._tokens):
                self._tokens = 0.0
            self._last_updated = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class RateLimiter:
    """Authenticated per-peer token buckets for messages and gossip."""

    def __init__(
        self,
        messages_per_minute: float,
        gossip_per_minute: float,
        capacity_minutes: float = 1.0,
    ) -> None:
        if not (
            math.isfinite(messages_per_minute)
            and math.isfinite(gossip_per_minute)
            and math.isfinite(capacity_minutes)
        ):
            raise RateLimitError("rate limits must be finite")
        if (
            messages_per_minute <= 0
            or gossip_per_minute <= 0
            or capacity_minutes <= 0
        ):
            raise RateLimitError("rate limits must be positive")
        self._messages_rate = messages_per_minute / 60.0
        self._gossip_rate = gossip_per_minute / 60.0
        self._capacity_minutes = capacity_minutes
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, peer_id: str, kind: str) -> TokenBucket:
        key = (peer_id, kind)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                rate = self._messages_rate if kind == "message" else self._gossip_rate
                # Capacity is floored at one token so a legitimate sub-1/min
                # rate still admits one message per window instead of
                # locking every peer out forever.
                capacity = max(1.0, rate * 60.0 * self._capacity_minutes)
                bucket = TokenBucket(rate, capacity)
                self._buckets[key] = bucket
                self._enforce_ceiling_locked()
            return bucket

    def _enforce_ceiling_locked(self) -> None:
        """Drop oldest-tracked buckets until at the aggregate ceiling.

        Caller must hold ``self._lock``. Keys are attacker-chosen, so this
        ceiling is the only bound on limiter memory; eviction is FIFO (dict
        insertion order) to stay O(1) per admitted key. An evicted bucket is
        recreated full on next use, which is indistinguishable from a bucket
        idle past its refill window.
        """
        excess = len(self._buckets) - _MAX_TRACKED_BUCKETS
        for _ in range(excess):
            del self._buckets[next(iter(self._buckets))]

    def _evict_expired_locked(self) -> None:
        """Drop buckets idle past the expiry window. Caller holds the lock.

        Eviction loses no quota: after this much idle a bucket would have
        refilled to full capacity anyway.
        """
        now = time.time()
        for key, bucket in list(self._buckets.items()):
            _tokens, last = bucket.state()
            if now - last > _BUCKET_IDLE_SECONDS:
                del self._buckets[key]

    def allow_message(self, peer_id: str) -> bool:
        """Consume one message token for ``peer_id``."""
        return self._bucket(peer_id, "message").consume(1.0)

    def allow_gossip(self, peer_id: str) -> bool:
        """Consume one gossip token for ``peer_id``."""
        return self._bucket(peer_id, "gossip").consume(1.0)

    # -------------------------------------------------------------------
    # Persistence helpers
    # -------------------------------------------------------------------

    def snapshot(
        self,
    ) -> Iterator[tuple[str, float, float, float]]:
        """Yield ``(node_id, message_tokens, gossip_tokens, epoch)`` snapshots.

        Buckets that have never been touched are initialized at full capacity
        so persistence does not lose unused allowance.
        """
        peers: dict[str, list[tuple[str, TokenBucket]]] = {}
        with self._lock:
            self._evict_expired_locked()
            self._enforce_ceiling_locked()
            for (peer_id, kind), bucket in self._buckets.items():
                peers.setdefault(peer_id, []).append((kind, bucket))
        now = time.time()
        for peer_id, entries in peers.items():
            rate_m = self._messages_rate
            rate_g = self._gossip_rate
            cap_m = max(1.0, rate_m * 60.0 * self._capacity_minutes)
            cap_g = max(1.0, rate_g * 60.0 * self._capacity_minutes)
            msg_tok = cap_m  # default full if never used
            gos_tok = cap_g
            for kind, bucket in entries:
                tok, last = bucket.state()
                refilled = min(
                    bucket.capacity,
                    tok + (now - last) * bucket.rate_per_second,
                )
                if kind == "message":
                    msg_tok = refilled
                else:
                    gos_tok = refilled
            yield (peer_id, msg_tok, gos_tok, now)

    def restore(
        self,
        states: Iterator[tuple[str, float, float, float]],
    ) -> None:
        """Restore bucket state from a previous snapshot.

        Idle-expired and over-ceiling state is dropped, so a restart cannot
        flood memory with stale or attacker-churned rows.
        """
        for node_id, msg_tok, gos_tok, _epoch in states:
            with self._lock:
                rate_m = self._messages_rate
                rate_g = self._gossip_rate
                cap_m = max(1.0, rate_m * 60.0 * self._capacity_minutes)
                cap_g = max(1.0, rate_g * 60.0 * self._capacity_minutes)
                self._buckets[(node_id, "message")] = TokenBucket.restore(
                    rate_m, cap_m, msg_tok, _epoch
                )
                self._buckets[(node_id, "gossip")] = TokenBucket.restore(
                    rate_g, cap_g, gos_tok, _epoch
                )
                self._enforce_ceiling_locked()
        with self._lock:
            self._evict_expired_locked()
            self._enforce_ceiling_locked()
