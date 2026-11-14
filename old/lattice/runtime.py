"""Autonomous runtime coordinator for Lattice v1."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lattice.addressing import parse_address
from lattice.config import Config
from lattice.encoding import b64url_decode
from lattice.gossip import GossipService
from lattice.identity import (
    IdentityError,
    OperationalCertificate,
    OperationalIdentity,
    RootIdentity,
    derive_node_id,
    verify_object,
)
from lattice.messages import InboundMessageService, OutboundMessageService
from lattice.network_policy import NetworkPolicy
from lattice.peers import BlockStore, PeerState, PeerStore
from lattice.protocol.constants import (
    MEDIA_TYPE,
)
from lattice.protocol.models import DeliveryMetadata, Message, PeerCard, WebhookEnvelope
from lattice.protocol.signing import sign_message, verify_message
from lattice.rate_limit import RateLimiter
from lattice.resolution import ResolutionError, WellKnownResolver, resolve_address
from lattice.storage.repositories import (
    AuditLogRepository,
    CacheRepository,
    DomainPinRepository,
    InboundMessageRepository,
    OutboundMessageRepository,
    PeerRepository,
    WebhookStateRepository,
)
from lattice.topology import TopologyConfig, TopologyService
from lattice.transport import OutboundTransport, TransportError
from lattice.webhook import WebhookDeliveryService

logger = logging.getLogger(__name__)


class RuntimeCoordinatorError(RuntimeError):
    """Raised when the runtime coordinator is misconfigured or unhealthy."""


class BlockedSenderError(RuntimeError):
    """Raised when a signature-valid inbound message comes from a blocked node.

    Callers convert this into a signed ``rejected`` receipt (HTTP 202) per
    docs/PROTOCOL.md §8: a rejected receipt is final and the sender stops
    retrying.
    """


class Clock(Protocol):
    """Injectable clock for deterministic testing."""

    def now(self) -> datetime: ...


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _write_audit_entry(
    repo: AuditLogRepository,
    logger: logging.Logger,
    level: int,
    event_code: str,
    node_id: str | None,
    message_id: str | None,
    details: dict[str, Any] | None,
    timestamp: datetime,
) -> None:
    """Write an audit entry gated by Python logging level."""
    if logger.isEnabledFor(level):
        repo.insert(event_code, node_id, message_id, details, timestamp)


@dataclass
class RuntimeSettings:
    """Tunable runtime intervals and limits."""

    delivery_workers: int = 4
    maintenance_workers: int = 2
    delivery_interval_seconds: float = 10.0
    webhook_interval_seconds: float = 10.0
    gossip_interval_seconds: float = 60.0
    verify_interval_seconds: float = 60.0
    refresh_interval_seconds: float = 300.0
    expiry_interval_seconds: float = 60.0
    max_pending_submissions: int = 1000


@dataclass
class _RecurringTask:
    """A single monotonic recurring task with non-overlap locking."""

    name: str
    interval_seconds: float
    fn: Any
    executor: ThreadPoolExecutor
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_run: float = field(default=0.0)

    def maybe_run(self, now: float) -> bool:
        if now - self._last_run < self.interval_seconds:
            return False
        if not self._lock.acquire(blocking=False):
            return False
        self._last_run = now
        self.executor.submit(self._run)
        return True

    def _run(self) -> None:
        try:
            self.fn()
        except Exception:
            logger.exception("recurring task %s failed", self.name)
        finally:
            self._lock.release()


class _RuntimeScheduler(threading.Thread):
    """Coordinator thread that schedules recurring maintenance/delivery work."""

    def __init__(self, tasks: list[_RecurringTask], tick_seconds: float = 1.0) -> None:
        super().__init__(name="lattice-runtime-scheduler", daemon=True)
        self._tasks = tasks
        self._tick_seconds = tick_seconds
        self._stopped_event = threading.Event()

    def run(self) -> None:
        while not self._stopped_event.wait(timeout=self._tick_seconds):
            now = time.monotonic()
            for task in self._tasks:
                task.maybe_run(now)

    def stop(self, timeout: float | None = None) -> None:
        self._stopped_event.set()
        self.join(timeout=timeout)


# Cold-sender resolution queue bounds. Unauthenticated senders can enqueue
# one attacker-chosen domain per POST, so the queue is capped, entries age
# out, and only a bounded batch is attempted per maintenance tick (mirrors
# the bounded claim batch in ``_run_outbound_delivery``).
_UNRESOLVED_DOMAINS_MAX = 512
_UNRESOLVED_DOMAINS_TTL_SECONDS = 900.0
_UNRESOLVED_DOMAINS_BATCH = 5


class RuntimeCoordinator:
    """Owns all services, executors, scheduling, and lifecycle state."""

    def __init__(
        self,
        config: Config,
        identity: OperationalIdentity,
        root_public_key: Ed25519PublicKey,
        durable_conn: sqlite3.Connection,
        cache_conn: sqlite3.Connection,
        well_known_document: dict[str, Any],
        admin_bearer: str,
        webhook_bearer: str,
        *,
        own_domains: set[str] | None = None,
        settings: RuntimeSettings | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._config = config
        self._identity = identity
        self._root_public_key = root_public_key
        self._root_identity = RootIdentity(node_id=identity.node_id, public_key=root_public_key)
        self._durable_conn = durable_conn
        self._cache_conn = cache_conn
        self._well_known_document = well_known_document
        self._admin_bearer = admin_bearer
        self._webhook_bearer = webhook_bearer
        self._settings = settings or RuntimeSettings()
        self._clock = clock or _SystemClock()

        # Repositories
        self._peer_repo = PeerRepository(durable_conn)
        self._pin_repo = DomainPinRepository(durable_conn)
        self._outbound_repo = OutboundMessageRepository(durable_conn)
        self._inbound_repo = InboundMessageRepository(durable_conn)
        self._webhook_repo = WebhookStateRepository(durable_conn)
        self._audit_repo = AuditLogRepository(durable_conn)
        self._cache_repo = CacheRepository(cache_conn)

        # Stores
        self._peer_store = PeerStore(self._peer_repo, self._cache_repo)
        self._block_store = BlockStore(self._peer_repo)

        # Network
        self._network_policy = NetworkPolicy(
            mode=config.network.mode,
            private_cidrs=tuple(config.network.private_cidrs),
            private_suffixes=tuple(config.network.private_suffixes),
            private_ca_path=config.network.private_ca_path,
        )
        self._transport = OutboundTransport(self._network_policy)
        self._resolver = WellKnownResolver(self._transport, self._pin_repo)

        # Services
        topology_config = TopologyConfig(
            guard_count=config.gossip.guard_slots,
            discovery_count=config.gossip.discovery_slots,
            candidate_expiry_seconds=config.gossip.candidate_ttl_seconds,
        )
        self._topology = TopologyService(
            peer_store=self._peer_store,
            block_store=self._block_store,
            cache=self._cache_repo,
            resolver=self._resolver,
            local_node_id=identity.node_id,
            config=topology_config,
            clock=self._clock,
        )
        self._gossip = GossipService(
            topology=self._topology,
            cache=self._cache_repo,
            identity=identity,
            clock=self._clock,
        )
        self._outbound = OutboundMessageService(
            repository=self._outbound_repo,
            peer_repository=self._peer_repo,
            clock=self._clock,
            erase_value=config.erase_content_value,
            root_key_lookup=self._known_root_key_for_node,
        )
        self._inbound = InboundMessageService(
            repository=self._inbound_repo,
            peer_repository=self._peer_repo,
            identity=identity,
            clock=self._clock,
            erase_value=config.erase_content_value,
            root_key_lookup=self._known_root_key_for_node,
        )
        self._webhook = WebhookDeliveryService(
            repository=self._webhook_repo,
        )

        # Domains this node owns — used to reject messages not addressed here.
        self._own_domains: set[str] = own_domains or set()

        # Queue of unresolved domains awaiting background well-known
        # resolution, mapping domain -> enqueue time (dict insertion order
        # is FIFO). Bounded by ``_UNRESOLVED_DOMAINS_MAX`` and aged out by
        # ``_UNRESOLVED_DOMAINS_TTL_SECONDS``.
        self._unresolved_domains_lock = threading.Lock()
        self._unresolved_domains: dict[str, datetime] = {}

        # Audit logger (gated by Python log level)
        self._audit_logger = logging.getLogger(__name__)

        # Rate limiting
        self._rate_limiter = RateLimiter(
            messages_per_minute=config.rate_limit.messages_per_minute,
            gossip_per_minute=config.rate_limit.gossip_per_minute,
        )

        # Executors
        self._delivery_executor = ThreadPoolExecutor(
            max_workers=self._settings.delivery_workers,
            thread_name_prefix="lattice-delivery-",
        )
        self._maintenance_executor = ThreadPoolExecutor(
            max_workers=self._settings.maintenance_workers,
            thread_name_prefix="lattice-maint-",
        )

        # Scheduler
        self._scheduler = self._build_scheduler()
        self._started = False
        self._stopped = False

    # -----------------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------------

    @property
    def config(self) -> Config:
        return self._config

    @property
    def identity(self) -> OperationalIdentity:
        return self._identity

    @property
    def node_id(self) -> str:
        return self._identity.node_id

    @property
    def well_known_document(self) -> dict[str, Any]:
        return self._well_known_document

    @property
    def admin_bearer(self) -> str:
        return self._admin_bearer

    @property
    def rate_limiter(self) -> RateLimiter:
        return self._rate_limiter

    @property
    def gossip_service(self) -> GossipService:
        return self._gossip

    @property
    def inbound_service(self) -> InboundMessageService:
        return self._inbound

    @property
    def outbound_service(self) -> OutboundMessageService:
        return self._outbound

    @property
    def topology_service(self) -> TopologyService:
        return self._topology

    @property
    def webhook_service(self) -> WebhookDeliveryService:
        return self._webhook

    @property
    def transport(self) -> OutboundTransport:
        return self._transport

    @property
    def resolver(self) -> WellKnownResolver:
        return self._resolver

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def _build_scheduler(self) -> _RuntimeScheduler:
        tasks: list[_RecurringTask] = [
            _RecurringTask(
                "cold_sender_resolution",
                30.0,
                self._resolve_pending_senders,
                self._maintenance_executor,
            ),
            _RecurringTask(
                "outbound_delivery",
                self._settings.delivery_interval_seconds,
                self._run_outbound_delivery,
                self._delivery_executor,
            ),
            _RecurringTask(
                "webhook_delivery",
                self._settings.webhook_interval_seconds,
                self._run_webhook_delivery,
                self._delivery_executor,
            ),
            _RecurringTask(
                "gossip_round",
                self._settings.gossip_interval_seconds,
                self._run_gossip_round,
                self._maintenance_executor,
            ),
            _RecurringTask(
                "verify_candidates",
                self._settings.verify_interval_seconds,
                self._run_verify_candidates,
                self._maintenance_executor,
            ),
            _RecurringTask(
                "refresh_topology",
                self._settings.refresh_interval_seconds,
                self._run_refresh_topology,
                self._maintenance_executor,
            ),
            _RecurringTask(
                "expiry_cleanup",
                self._settings.expiry_interval_seconds,
                self._run_expiry_cleanup,
                self._maintenance_executor,
            ),
        ]
        return _RuntimeScheduler(tasks)

    def start(self) -> None:
        """Start the runtime coordinator."""
        if self._started:
            raise RuntimeError("runtime already started")
        if self._stopped:
            raise RuntimeError("runtime has been stopped")
        self._started = True
        self._restore_rate_limits()
        self._pin_bootstrap_peers()
        self._scheduler.start()
        logger.info("runtime started for node %s", self.node_id)

    def _restore_rate_limits(self) -> None:
        """Restore rate-limit token buckets from the cache database."""
        try:
            states = self._cache_repo.load_rate_buckets()
            self._rate_limiter.restore(iter(states))
            if states:
                logger.debug("restored %d rate-limit buckets from cache", len(states))
        except Exception:
            logger.exception("failed to restore rate-limit state; starting fresh")

    def _pin_bootstrap_peers(self) -> None:
        """Resolve and pin bootstrap peers as established.

        Bootstrap peers are trusted by configuration; they skip independent
        verification and go straight to ``established`` status. A restart
        never silently rewrites a pin: re-resolution is compared against
        the existing pin and refused when it advertises a different node —
        a pin changes only via an accepted transfer statement or an
        explicit local reset — and the pin upsert's compare-and-set refuses
        a certificate sequence rollback across the pin and peer rows.
        """
        now = self._clock.now()
        for url in self._config.gossip.bootstrap:
            parsed = urlparse(url)
            domain = parsed.hostname
            if domain is None:
                logger.warning("bootstrap URL has no hostname: %s", url)
                continue
            domain = domain.lower()
            existing_pin = self._resolver.get_pin(domain)
            if (
                existing_pin is not None
                and self._peer_store.get_peer_by_domain(domain) is not None
            ):
                continue  # already pinned and known
            try:
                doc = self._resolver.resolve(domain)
            except ResolutionError as exc:
                logger.warning("bootstrap resolution failed for %s: %s", domain, exc)
                continue
            node_id = doc.get("node_id")
            if not node_id or not isinstance(node_id, str):
                logger.warning("bootstrap document missing node_id for %s", domain)
                continue
            # PIN: refuse to rebind a pinned domain to a different node.
            if existing_pin is not None and existing_pin.get("node_id") != node_id:
                logger.warning(
                    "refusing to re-pin %s to node %s; pinned to %s "
                    "(accepted transfer or local reset required)",
                    domain,
                    node_id,
                    existing_pin.get("node_id"),
                )
                continue
            root_pub_key = doc.get("root_public_key") or ""
            self._peer_repo.ensure_root_history(node_id, root_pub_key, now)
            # Extract endpoints from well-known.
            endpoints_raw = doc.get("endpoints") or {}
            if not isinstance(endpoints_raw, dict):
                endpoints_raw = {}
            endpoints: dict[str, str] = {
                "gossip": str(endpoints_raw.get("gossip", "")),
                "messages": str(endpoints_raw.get("messages", "")),
            }
            # Extract certificate sequence.
            op_cert = doc.get("operational_certificate") or {}
            if not isinstance(op_cert, dict):
                op_cert = {}
            raw_seq = op_cert.get("sequence")
            cert_seq = raw_seq if isinstance(raw_seq, int) else 0
            # Pin the domain using data we already resolved (avoids 2nd
            # lookup). The upsert compare-and-set refuses a sequence
            # rollback or key swap, so adoption only ever advances the
            # stored trust anchor (e.g. to a rotated certificate).
            try:
                self._pin_repo.upsert(
                    domain=domain,
                    node_id=node_id,
                    root_public_key=root_pub_key,
                    operational_certificate=op_cert,
                    endpoints=endpoints,
                )
            except Exception as exc:
                logger.warning("bootstrap pin failed for %s: %s", domain, exc)
                continue
            # Record the adopted operational key in the peer ledger; the
            # repository's sequence gate refuses rollbacks and key swaps.
            try:
                self._peer_store.record_operational_key(
                    node_id,
                    str(op_cert.get("operational_public_key", "")),
                    cert_seq,
                    valid_from=datetime.fromisoformat(
                        str(op_cert.get("valid_from", "")).replace("Z", "+00:00")
                    ),
                    valid_until=datetime.fromisoformat(
                        str(op_cert.get("valid_until", "")).replace("Z", "+00:00")
                    ),
                )
            except Exception as exc:
                logger.warning("bootstrap key record failed for %s: %s", node_id, exc)
            # Create or transition peer as established (skips verification).
            existing = self._peer_store.get_peer(node_id)
            if existing is None:
                self._peer_store.create_peer(
                    node_id,
                    PeerState.ESTABLISHED,
                    domain=domain,
                    current_certificate_sequence=cert_seq,
                    endpoints=endpoints,
                    now=now,
                )
            else:
                self._peer_store.transition(
                    node_id,
                    PeerState.ESTABLISHED,
                    domain=domain,
                    current_certificate_sequence=cert_seq,
                    endpoints=endpoints,
                    now=now,
                )
            logger.info("bootstrap peer %s (%s) pinned as established", node_id, domain)

    def stop(self, timeout: float = 30.0) -> None:
        """Stop the runtime coordinator gracefully within ``timeout`` seconds.

        The scheduler join AND the executor drains are bounded by the same
        budget: an unbounded ``shutdown(wait=True)`` could exceed the
        supervisor's stop deadline (systemd ``TimeoutStopSec``) and get
        SIGKILLed before rate-limit state is persisted. Queued-but-not-
        started work is cancelled once the budget is spent; leased rows
        recover at-least-once via lease expiry.
        """
        if not self._started or self._stopped:
            return
        self._stopped = True
        deadline = time.monotonic() + timeout
        self._scheduler.stop(timeout=timeout)
        for executor in (self._delivery_executor, self._maintenance_executor):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                executor.shutdown(wait=False, cancel_futures=True)
                continue
            # ``shutdown(wait=True)`` has no timeout parameter, so bound the
            # drain by joining a helper thread for the remaining budget.
            drain = threading.Thread(
                target=executor.shutdown,
                kwargs={"wait": True, "cancel_futures": False},
                daemon=True,
            )
            drain.start()
            drain.join(timeout=remaining)
            if drain.is_alive():
                # Budget exhausted: cancel queued futures so pending work
                # stops; running work finishes in the background. Persist
                # rate limits now rather than never.
                executor.shutdown(wait=False, cancel_futures=True)
        # Persist rate limits AFTER executors drain (bounded) to avoid stale snapshots.
        self._persist_rate_limits()
        self._transport.close()
        self._webhook.close()
        logger.info("runtime stopped for node %s", self.node_id)

    def _persist_rate_limits(self) -> None:
        """Persist rate-limit token buckets to the cache database."""
        try:
            snapshots = list(self._rate_limiter.snapshot())
            for node_id, msg_tok, gos_tok, epoch in snapshots:
                self._cache_repo.save_rate_bucket(
                    node_id=node_id,
                    message_tokens=msg_tok,
                    gossip_tokens=gos_tok,
                    last_updated=str(epoch),
                )
            if snapshots:
                logger.debug("persisted %d rate-limit buckets", len(snapshots))
        except Exception:
            logger.exception("failed to persist rate-limit state")

    def is_ready(self) -> bool:
        """Return True if the node is ready to handle traffic."""
        if self._stopped:
            return False
        if not self._well_known_document:
            return False
        try:
            _ = self._config.domain
            _ = self._identity.node_id
            self._durable_conn.execute("SELECT 1")
            self._cache_conn.execute("SELECT 1")
        except Exception:
            return False
        return True

    @property
    def is_running(self) -> bool:
        return self._started and not self._stopped and self._scheduler.is_alive()

    # -----------------------------------------------------------------------
    # Gossip sender identity
    # -----------------------------------------------------------------------

    def verify_gossip_sender_card(self, card: Any) -> str | None:
        """Verify a gossip sender's own peer card; return its node ID or None.

        The first card of a gossip batch identifies the sender (PROTOCOL.md
        §5.2). Verification is self-consistent: the card's operational
        certificate must be signed by the root key the card itself advertises,
        the node ID must derive from that root key, and the card signature
        must verify with the certified operational key. This gives rate
        limiting a stable per-identity key without trusting the transport.
        """
        if not isinstance(card, dict):
            return None
        try:
            model = PeerCard.model_validate(card)
        except Exception:
            return None
        try:
            root_key = Ed25519PublicKey.from_public_bytes(b64url_decode(model.root_public_key))
        except Exception:
            return None
        if derive_node_id(root_key) != model.node_id:
            return None
        try:
            cert = OperationalCertificate.from_dict(
                model.operational_certificate.model_dump(mode="json")
            )
            root_identity = RootIdentity(node_id=model.node_id, public_key=root_key)
            cert.verify(root_identity)
            if not cert.is_valid_at(self._clock.now()):
                return None
            verify_object(cert.operational_public_key, card, "peer_card")
        except Exception:
            return None
        return model.node_id

    # -----------------------------------------------------------------------
    # Addressing and verification helpers used by the API
    # -----------------------------------------------------------------------

    def resolve_local_address(self, address: str) -> tuple[str, str]:
        """Resolve ``address`` to ``(username, local_node_id)``.

        Raises RuntimeError if the address does not belong to this node.
        """
        parsed = parse_address(address)
        if parsed.node_id is not None and parsed.node_id != self.node_id:
            raise RuntimeError(f"address does not belong to this node: {address}")
        if parsed.domain is not None and parsed.domain != self._config.domain:
            raise RuntimeError(f"address does not belong to this node: {address}")
        return parsed.username, self.node_id

    def resolve_destination(self, address: str) -> tuple[str, str]:
        """Resolve ``address`` to ``(username, node_id)``."""
        return resolve_address(address, self._resolver)

    def sign_local_message(
        self,
        *,
        message_id: str,
        from_address: str,
        to_address: str,
        content: str,
        priority: str,
        ttl_seconds: int,
        extension: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build and sign a message originating from this node."""
        self.resolve_local_address(from_address)
        when = self._clock.now()
        msg: dict[str, Any] = {
            "kind": "message",
            "message_id": message_id,
            "from_address": from_address,
            "to_address": to_address,
            "content": content,
            "priority": priority,
            "ttl_seconds": ttl_seconds,
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if extension is not None:
            msg["extension"] = extension
        return sign_message(self._identity, msg)

    def verify_inbound_message(
        self,
        message: dict[str, Any],
    ) -> tuple[str, bool]:
        """Verify an inbound message signature and return ``(node_id, resolved_async)``.

        If ``resolved_async`` is True, the sender domain was unknown and was
        queued for asynchronous well-known resolution. The caller should accept
        the message into custody now and allow a later re-verification once
        resolution completes.

        Raises RuntimeError only for structural problems (bad address format
        etc.) that cannot be recovered by async resolution.
        """
        try:
            model = Message.model_validate(message)
        except Exception as exc:
            raise RuntimeError(f"invalid message: {exc}") from exc

        parsed = parse_address(model.from_address)
        if parsed.node_id is not None:
            from_node_id = parsed.node_id
        elif parsed.domain is not None:
            pin = self._resolver.get_pin(parsed.domain)
            if pin is not None:
                from_node_id = pin["node_id"]
            else:
                # Cold sender — caller stages via inbound_service.stage().
                return (parsed.domain, True)
        else:
            raise RuntimeError("message from_address has no domain or node ID")

        # Fast path: we know the sender. Verify the signature first so a
        # rejected-custody response (blocked sender) is only ever issued for a
        # signature-verified message (docs/PROTOCOL.md §8).
        cert = self._certificate_for_node(from_node_id)
        if cert is None:
            raise RuntimeError(f"no operational certificate for sender: {from_node_id}")
        try:
            verify_message(message, cert, self._root_identity_for_node(from_node_id))
        except (IdentityError, ValueError) as exc:
            raise RuntimeError(f"message signature invalid: {exc}") from exc
        if self._block_store.is_blocked(from_node_id):
            raise BlockedSenderError(f"sender is blocked: {from_node_id}")
        return (from_node_id, False)

    def _certificate_for_node(self, node_id: str) -> OperationalCertificate | None:
        peer = self._peer_store.get_peer(node_id)
        pin: dict[str, Any] | None = None
        domain: str | None = None
        if peer is not None and peer.domain:
            domain = peer.domain
            pin = self._resolver.get_pin(peer.domain)
        if pin is None:
            domain = self._domain_for_node(node_id)
            if domain is not None:
                pin = self._resolver.get_pin(domain)
        if pin is not None and domain is not None:
            cert = self._certificate_from_pin(pin)
            # Freshness mechanism: while the pinned certificate is valid and
            # the pin was verified recently, serve the stored anchor. When it
            # has lapsed (or the pin has not been re-verified within the
            # refresh interval), advance the trust anchor from the live
            # well-known: the pin compare-and-set adopts only a rotated
            # certificate whose sequence advances the recorded prior, and it
            # persists into the pin table this method's caller reads. A
            # different node ID is never adopted; a failing refresh keeps the
            # stored anchor and fails closed at verification time.
            stale = True
            last_verified = pin.get("last_verified_at")
            if isinstance(last_verified, str):
                try:
                    when = datetime.fromisoformat(last_verified.replace("Z", "+00:00"))
                    stale = (
                        self._clock.now() - when
                    ).total_seconds() > self._settings.refresh_interval_seconds
                except ValueError:
                    stale = True
            if not cert.is_valid_at(self._clock.now()) or stale:
                try:
                    data = self._resolver.pin(domain)
                    fresh = self._certificate_from_pin(data)
                    if fresh.node_id == node_id:
                        return fresh
                except ResolutionError:
                    pass
            return cert
        if domain is not None:
            # No durable pin yet: resolve and persist the anchor so it is not
            # re-fetched on every inbound message. resolve_with_ip already
            # rejected expired certificates and mismatched node IDs.
            try:
                doc = self._resolver.resolve(domain)
            except ResolutionError:
                return None
            cert = self._certificate_from_pin(doc)
            if cert.node_id != node_id or not cert.is_valid_at(self._clock.now()):
                return None
            raw_cert = doc.get("operational_certificate")
            op_cert: dict[str, Any] = raw_cert if isinstance(raw_cert, dict) else {}
            try:
                self._pin_repo.upsert(
                    domain=domain,
                    node_id=str(doc.get("node_id", "")),
                    root_public_key=str(doc.get("root_public_key", "")),
                    operational_certificate=op_cert,
                    endpoints={
                        "gossip": str((doc.get("endpoints") or {}).get("gossip", "")),
                        "messages": str((doc.get("endpoints") or {}).get("messages", "")),
                    },
                )
            except Exception as exc:
                logger.warning("failed to persist pin for %s: %s", domain, exc)
            return cert
        return None

    def _domain_for_node(self, node_id: str) -> str | None:
        peer = self._peer_store.get_peer(node_id)
        if peer is not None and peer.domain:
            return peer.domain
        pin = self._pin_repo.get_by_node_id(node_id)
        if pin is not None:
            domain = pin["domain"]
            if isinstance(domain, str):
                return domain
        return None

    def _root_identity_for_node(self, node_id: str) -> RootIdentity:
        # If we have a pinned root key, use it; otherwise derive from the
        # claimed root public key in the message (only possible for canonical
        # addresses where we already trust the node ID).
        history = self._peer_repo.get_root_history(node_id)
        if history is not None and history.get("root_public_key"):
            key = self._load_public_key(history["root_public_key"])
            return RootIdentity(node_id=node_id, public_key=key)
        # Fallback: this only works if we have previously resolved the domain.
        domain = self._domain_for_node(node_id)
        if domain is not None:
            pin = self._resolver.get_pin(domain)
            if pin is not None:
                key = self._load_public_key(pin["root_public_key"])
                return RootIdentity(node_id=node_id, public_key=key)
        raise RuntimeError(f"no root identity known for {node_id}")

    @staticmethod
    def _load_public_key(text: str) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(b64url_decode(text))

    def _known_root_key_for_node(self, node_id: str) -> str:
        """Return the known b64url root public key for ``node_id", or "".

        Consults peer root history first, then the domain-pin repository. Used
        by custody services so root-history rows carry real keys whenever the
        key has already been learned.
        """
        history = self._peer_repo.get_root_history(node_id)
        if history is not None:
            value = history.get("root_public_key")
            if isinstance(value, str) and value:
                return value
        pin = self._pin_repo.get_by_node_id(node_id)
        if pin is not None:
            value = pin.get("root_public_key")
            if isinstance(value, str) and value:
                return value
        return ""

    @staticmethod
    def _certificate_from_pin(pin: dict[str, Any]) -> OperationalCertificate:
        return OperationalCertificate.from_dict(pin["operational_certificate"])

    def peer_endpoint_for_node(self, node_id: str) -> str | None:
        """Return the messages endpoint for ``node_id``, if known."""
        peer = self._peer_store.get_peer(node_id)
        if peer is not None and peer.endpoints:
            endpoint = peer.endpoints.get("messages")
            if isinstance(endpoint, str):
                return endpoint
        pin = self._pin_repo.get_by_node_id(node_id)
        if pin is not None:
            endpoints = pin.get("endpoints") or {}
            endpoint = endpoints.get("messages")
            if isinstance(endpoint, str):
                return endpoint
        return None

    # -----------------------------------------------------------------------
    # Submission backpressure
    # -----------------------------------------------------------------------

    def allow_submission(self) -> bool:
        """Return False when the outbound queue is too full."""
        pending = len(self._outbound.list_pending())
        return pending < self._settings.max_pending_submissions

    # -----------------------------------------------------------------------
    # Circuit breaker (exponential backoff per peer)
    # -----------------------------------------------------------------------

    _CB_THRESHOLD: int = 3
    _CB_BASE_DELAY_S: float = 5.0
    _CB_MAX_DELAY_S: float = 60.0

    def _circuit_is_open(self, node_id: str) -> bool:
        """Return True if ``node_id`` is currently in backoff.

        Uses exponential backoff: base * 2^(failures-1), capped at 60s.
        """
        row = self._cache_repo.conn.execute(
            "SELECT consecutive_failures, last_failure_at FROM circuit_observations "
            "WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if row is None or not row["consecutive_failures"]:
            return False
        if row["last_failure_at"] is None:
            return False
        last_fail_str: str = str(row["last_failure_at"])
        try:
            last_fail = datetime.fromisoformat(last_fail_str.replace("Z", "+00:00"))
        except ValueError:
            return False
        failures: int = int(row["consecutive_failures"])
        if failures < self._CB_THRESHOLD:
            # Circuit not yet tripped — allow attempts.
            return False
        raw_delay: float = self._CB_BASE_DELAY_S * (2 ** max(0, failures - self._CB_THRESHOLD))
        delay_s: float = min(raw_delay, self._CB_MAX_DELAY_S)
        delta = self._clock.now() - last_fail
        elapsed: float = delta.total_seconds()
        return elapsed < delay_s

    def _circuit_record_success(self, node_id: str) -> None:
        """Reset circuit breaker for ``node_id`` on success.

        The write commits within its own ``with`` boundary: otherwise the
        UPDATE sits in an implicit transaction that a later unrelated cache
        block's commit/rollback silently governs. Durability is best-effort
        (the cache DB is disposable state), but the write is never left in
        an open transaction owned by other work.
        """
        try:
            with self._cache_repo.conn:
                self._cache_repo.conn.execute(
                    "INSERT INTO circuit_observations (node_id, consecutive_failures) "
                    "VALUES (?, 0) ON CONFLICT(node_id) DO UPDATE SET "
                    "consecutive_failures = 0, last_failure_at = NULL",
                    (node_id,),
                )
        except Exception:
            logger.exception("failed to update circuit breaker for %s", node_id)

    def _circuit_record_failure(self, node_id: str) -> None:
        """Record a delivery failure; may open circuit after N failures.

        Commits within its own ``with`` boundary for the same reason as
        ``_circuit_record_success``: best-effort durability (disposable
        cache DB), never an open transaction left to unrelated work.
        """
        now_str = self._clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            with self._cache_repo.conn:
                self._cache_repo.conn.execute(
                    "INSERT INTO circuit_observations "
                    "(node_id, consecutive_failures, last_failure_at) "
                    "VALUES (?, 1, ?) ON CONFLICT(node_id) DO UPDATE SET "
                    "consecutive_failures = circuit_observations.consecutive_failures + 1, "
                    "last_failure_at = ?",
                    (node_id, now_str, now_str),
                )
        except Exception:
            logger.exception("failed to record circuit failure for %s", node_id)

    # -----------------------------------------------------------------------
    # Log-level-gated audit helpers
    # -----------------------------------------------------------------------

    def _audit_inbound_accepted(self, *, message_id: str, from_node_id: str) -> None:
        _write_audit_entry(
            self._audit_repo,
            self._audit_logger,
            logging.INFO,
            "INBOUND_ACCEPTED",
            from_node_id,
            message_id,
            None,
            self._clock.now(),
        )

    def _audit_outbound_delivered(self, *, message_id: str, to_node_id: str) -> None:
        _write_audit_entry(
            self._audit_repo,
            self._audit_logger,
            logging.INFO,
            "OUTBOUND_DELIVERED",
            to_node_id,
            message_id,
            None,
            self._clock.now(),
        )

    def _audit_outbound_failed(self, *, message_id: str, to_node_id: str, reason: str) -> None:
        _write_audit_entry(
            self._audit_repo,
            self._audit_logger,
            logging.WARNING,
            "OUTBOUND_FAILED",
            to_node_id,
            message_id,
            {"reason": reason},
            self._clock.now(),
        )

    def _audit_webhook_delivered(self, *, message_id: str, status_code: int) -> None:
        _write_audit_entry(
            self._audit_repo,
            self._audit_logger,
            logging.INFO,
            "WEBHOOK_DELIVERED",
            None,
            message_id,
            {"status_code": status_code},
            self._clock.now(),
        )

    def _audit_webhook_failed(self, *, message_id: str, error: str, retryable: bool) -> None:
        _write_audit_entry(
            self._audit_repo,
            self._audit_logger,
            logging.INFO if retryable else logging.WARNING,
            "WEBHOOK_FAILED",
            None,
            message_id,
            {"error": error, "retryable": retryable},
            self._clock.now(),
        )

    # -----------------------------------------------------------------------
    # Cold-sender async resolution
    # -----------------------------------------------------------------------

    def queue_domain_resolution(self, domain: str) -> None:
        """Queue ``domain`` for background well-known resolution.

        Malformed domains are rejected at ingestion so a poison domain can
        never enter the resolution queue. The queue is capped: once full, the
        oldest entry is evicted so it can never grow without bound.
        """
        domain = domain.strip().lower()
        if (
            not domain
            or len(domain) > 253
            or any(c in domain for c in ":/@")
            or any(c.isspace() for c in domain)
        ):
            logger.warning("refusing to queue malformed domain for resolution: %r", domain)
            return
        now = self._clock.now()
        with self._unresolved_domains_lock:
            if domain in self._unresolved_domains:
                # Already queued: keep the original enqueue time so repeat
                # POSTs cannot refresh a domain's TTL.
                return
            while len(self._unresolved_domains) >= _UNRESOLVED_DOMAINS_MAX:
                self._unresolved_domains.pop(next(iter(self._unresolved_domains)))
            self._unresolved_domains[domain] = now

    def _resolve_pending_senders(self) -> None:
        """Resolve domains queued during cold-sender inbound handling.

        On success, pins the domain so future messages can be delivered.
        On failure, drops it from the queue — the sender will retry later
        and receive a new 503 response. Only a bounded batch of the oldest
        entries is attempted per tick and entries past the TTL are expired,
        so unauthenticated senders can neither grow the queue without bound
        nor occupy a maintenance worker indefinitely.
        """
        now = self._clock.now()
        batch: list[str]
        with self._unresolved_domains_lock:
            # Expire stale entries first; dict insertion order is FIFO, so
            # this also frees room for fresh queues.
            expired = [
                domain
                for domain, enqueued_at in self._unresolved_domains.items()
                if (now - enqueued_at).total_seconds() >= _UNRESOLVED_DOMAINS_TTL_SECONDS
            ]
            for domain in expired:
                del self._unresolved_domains[domain]
            batch = list(self._unresolved_domains)[:_UNRESOLVED_DOMAINS_BATCH]

        for domain in batch:
            try:
                self._resolver.pin(domain)
            except ResolutionError as exc:
                logger.debug("async pin failed for %s: %s", domain, exc)
            except Exception as exc:
                # Per-item isolation at the domain boundary: one hostile or
                # broken domain must not abort the batch (e.g. a
                # TransportError escaping resolve_with_ip).
                logger.warning("async pin raised unexpected error for %s: %s", domain, exc)
            else:
                logger.info("domain %s resolved via async pin", domain)
            finally:
                # Drop the domain whether the pin succeeded or failed, so a
                # permanently-failing domain is never re-resolved every
                # 30 s forever; the sender retries and re-queues it.
                with self._unresolved_domains_lock:
                    self._unresolved_domains.pop(domain, None)

    def _run_outbound_delivery(self) -> None:
        owner = f"delivery-{threading.current_thread().name}"
        messages = self._outbound.claim_for_delivery(owner, limit=5)
        for row in messages:
            message_json = row.get("message_json")
            if not isinstance(message_json, dict):
                try:
                    message_json = json.loads(str(message_json))
                except Exception:
                    self._outbound.record_failure(row["message_id"], owner, retryable=False)
                    continue
            endpoint = self.peer_endpoint_for_node(row["to_node_id"])
            if endpoint is None:
                self._outbound.record_failure(row["message_id"], owner, retryable=True)
                self._circuit_record_failure(row["to_node_id"])
                continue
            if self._circuit_is_open(row["to_node_id"]):
                self._outbound.record_failure(row["message_id"], owner, retryable=True)
                continue
            self._send_outbound_message(
                owner,
                row["message_id"],
                message_json,
                endpoint,
                to_node_id=row["to_node_id"],
            )

    def _send_outbound_message(
        self,
        owner: str,
        message_id: str,
        message_json: dict[str, Any],
        endpoint: str,
        *,
        to_node_id: str,
    ) -> None:
        body = json.dumps(message_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": MEDIA_TYPE,
            "Accept": MEDIA_TYPE,
        }
        try:
            response = self._transport.request("POST", endpoint, body=body, headers=headers)
        except TransportError as exc:
            logger.warning("outbound delivery to %s failed: %s", endpoint, exc)
            self._outbound.record_failure(message_id, owner, retryable=True)
            self._circuit_record_failure(to_node_id)
            self._audit_outbound_failed(
                message_id=message_id,
                to_node_id=to_node_id,
                reason=f"TransportError: {exc}",
            )
            return

        if response.status == 202:
            # Validate the signed custody receipt before transferring ownership.
            try:
                data = json.loads(response.data.decode("utf-8"))
            except Exception:
                data = {}
            if (
                data.get("message_id") != message_id
                or data.get("node_id") != to_node_id
                or data.get("status") != "accepted"
            ):
                logger.warning(
                    "invalid custody receipt from %s for %s: %s",
                    endpoint,
                    message_id,
                    data,
                )
                self._outbound.record_failure(message_id, owner, retryable=True)
                self._circuit_record_failure(to_node_id)
                self._audit_outbound_failed(
                    message_id=message_id,
                    to_node_id=to_node_id,
                    reason="invalid custody receipt",
                )
                return
            delivered = self._outbound.record_success(message_id, owner)
            # The peer returned a valid custody receipt, so the remote node
            # is healthy regardless of the durable row's lease state.
            self._circuit_record_success(to_node_id)
            if delivered:
                self._audit_outbound_delivered(message_id=message_id, to_node_id=to_node_id)
            else:
                # The 60s expiry sweep already flipped this row to a terminal
                # status (``expired``) before the terminal write landed, so
                # ``mark_terminal``'s leased-by-owner guard matched nothing.
                # The durable status governs the audit: never claim
                # OUTBOUND_DELIVERED for a row the durable store does not
                # record as delivered (the terminal writer wins).
                self._audit_outbound_failed(
                    message_id=message_id,
                    to_node_id=to_node_id,
                    reason="row already terminal (expired) before delivered write",
                )
        elif response.status == 429 or response.status >= 500:
            self._outbound.record_failure(message_id, owner, retryable=True)
            self._circuit_record_failure(to_node_id)
            self._audit_outbound_failed(
                message_id=message_id,
                to_node_id=to_node_id,
                reason=f"HTTP {response.status}",
            )
        else:
            self._outbound.record_failure(message_id, owner, retryable=False)
            self._circuit_record_failure(to_node_id)
            self._audit_outbound_failed(
                message_id=message_id,
                to_node_id=to_node_id,
                reason=f"HTTP {response.status} terminal",
            )

    def _run_webhook_delivery(self) -> None:
        owner = f"webhook-{threading.current_thread().name}"
        rows = self._inbound.claim_for_webhook(owner, limit=5)
        for row in rows:
            message_json = row.get("message_json")
            if not isinstance(message_json, dict):
                try:
                    message_json = json.loads(str(message_json))
                except Exception:
                    self._inbound.record_webhook_failure(row["message_id"], owner, retryable=False)
                    continue
            # Build full signed webhook envelope.
            # Use locally recorded receipt time — not sender-controlled timestamp.
            raw_received = row.get("received_at") or ""
            try:
                received_at = datetime.fromisoformat(str(raw_received).replace("Z", "+00:00"))
            except ValueError:
                received_at = self._clock.now()

            metadata = DeliveryMetadata(
                received_at=received_at,
                delivered_at=self._clock.now(),
                delivery_node_id=self.node_id,
            ).model_dump(mode="json")

            envelope: dict[str, Any] = {
                "kind": "webhook_envelope",
                "message": message_json,
                "metadata": metadata,
            }
            signed_env = self._identity.sign_object(envelope, "webhook_envelope")
            env_model = WebhookEnvelope.model_validate(signed_env)
            result = self._webhook.deliver(
                self._config.webhook.url,
                row["message_id"],
                env_model.model_dump(mode="json"),
                bearer_token=self._webhook_bearer,
            )
            if result.success:
                self._inbound.record_webhook_success(row["message_id"], owner)
                self._audit_webhook_delivered(
                    message_id=row["message_id"],
                    status_code=result.status_code or 200,
                )
            else:
                self._inbound.record_webhook_failure(
                    row["message_id"], owner, retryable=result.retryable
                )
                self._audit_webhook_failed(
                    message_id=row["message_id"],
                    error=result.error or "unknown",
                    retryable=result.retryable,
                )

    # -----------------------------------------------------------------------
    # Background maintenance tasks
    # -----------------------------------------------------------------------

    def _run_gossip_round(self) -> None:
        targets = self._topology.select_gossip_targets()
        if not targets:
            return
        own_card = self._gossip.build_own_card(
            domain=self._config.domain,
            root_public_key=self._root_public_key,
            endpoints={
                "gossip": self._config.gossip_endpoint,
                "messages": self._config.messages_endpoint,
            },
            now=self._clock.now(),
        )
        for node_id in targets:
            self._send_gossip_batch(node_id, own_card)

    def _send_gossip_batch(self, node_id: str, own_card: dict[str, Any]) -> None:
        peer = self._peer_store.get_peer(node_id)
        if peer is None or not peer.endpoints:
            return
        endpoint = peer.endpoints.get("gossip")
        if endpoint is None:
            return
        batch = self._gossip.select_batch_to_send(exclude={node_id}, limit=16)
        cards = [own_card] + batch.cards
        payload: dict[str, Any] = {
            "cards": cards,
            "introduced_by": self.node_id,
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": MEDIA_TYPE, "Accept": MEDIA_TYPE}
        if self._circuit_is_open(node_id):
            return
        try:
            response = self._transport.request("POST", endpoint, body=body, headers=headers)
        except TransportError as exc:
            logger.warning("gossip to %s failed: %s", endpoint, exc)
            self._circuit_record_failure(node_id)
            return
        if 200 <= response.status < 300:
            self._topology.record_observation(node_id, now=self._clock.now())
            self._circuit_record_success(node_id)
        else:
            self._circuit_record_failure(node_id)

    def _run_verify_candidates(self) -> None:
        for node_id in self._topology.list_candidates_for_verification():
            try:
                self._topology.verify_candidate(node_id)
            except Exception:
                logger.exception("candidate verification failed for %s", node_id)

    def _run_refresh_topology(self) -> None:
        self._topology.refresh_topology_slots(now=self._clock.now())

    def _run_expiry_cleanup(self) -> None:
        self._outbound.expire()
        self._topology.prune(now=self._clock.now())
