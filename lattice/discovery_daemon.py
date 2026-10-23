"""
Lattice discovery daemon.

FastAPI service for gossip, pairing, key cross-checks and federated message
delivery. Public endpoints serve peers; admin endpoints require
X-Lattice-Admin-Token and serve the local application and operator.

Endpoints are synchronous: FastAPI runs them in its threadpool, so blocking
SQLite and HTTP calls never stall the event loop.
"""

import hmac
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .identity import Identity
from .models import (
    MAX_METADATA_BYTES,
    FederatedMessage,
    GossipMessage,
    GossipPayload,
    IdentityRevocation,
    Introduction,
    KeyQuery,
    KeyRotation,
    MessageAcknowledgment,
    PairRequest,
    ServerAnnouncement,
    _validate_endpoint_url,
    _validate_json_size,
    now_iso,
    parse_timestamp,
    require_fresh,
)
from .peer_manager import ACTIVE_TRUST, RATE_LIMIT_PER_MINUTE, Peer, PeerManager
from .secrets import load_config
from .sqlite_client import SQLiteClient
from .trust import TrustError, TrustService
from .username_resolver import has_username_resolver, resolve_username

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VERSION = "2.0.0"
MAX_REQUEST_BODY_BYTES = 1024 * 1024
GOSSIP_MAX_AGE = timedelta(hours=1)
MESSAGE_MAX_AGE = timedelta(hours=24)
ACK_MAX_AGE = timedelta(minutes=15)


# =====================================================================
# API Models
# =====================================================================

class AnnouncementRequest(BaseModel):
    force: bool = Field(default=False, description="Gossip even if a round ran in the last minute")


class InviteRequest(BaseModel):
    ttl_hours: int = Field(default=24, ge=1, le=168)


class InviteResponse(BaseModel):
    token: str
    expires_at: str


class AcceptInviteRequest(BaseModel):
    token: str = Field(max_length=2048)


class PeerStatus(BaseModel):
    server_uuid: str
    server_id: str
    public_key: str
    endpoint: str
    trust: str
    is_neighbor: bool
    last_seen: str


class InboundMessageResponse(BaseModel):
    status: Literal["accepted", "rejected"]
    message_id: str
    ack: Dict[str, Any]


class SendMessageRequest(BaseModel):
    to_address: str = Field(description="Recipient address (e.g., alex@remote-server)")
    from_address: str = Field(description="Sender address on this server (e.g., taylor@this-server)")
    content: str = Field(max_length=10000)
    message_type: Literal["pager", "location", "ai_to_ai"] = "pager"
    priority: int = Field(default=0, ge=0, le=2, description="0=normal, 1=high, 2=urgent")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, value):
        return _validate_json_size(value, MAX_METADATA_BYTES, "metadata")


class SendMessageResponse(BaseModel):
    status: Literal["queued"]
    message_id: str
    immediate_delivery: bool = True


# =====================================================================
# Access Control and Middleware
# =====================================================================

class PermanentDeliveryFailure(Exception):
    """A message failed in a way retrying cannot fix."""


def _load_admin_token() -> Optional[str]:
    return os.getenv("LATTICE_ADMIN_TOKEN") or os.getenv("ADMIN_TOKEN") or load_config("ADMIN_TOKEN")


def admin_only(request: Request) -> str:
    """
    Require the admin token.

    Reverse proxies can make every request appear local, so locality is not
    trusted; admin endpoints always need the shared token.
    """
    expected = _load_admin_token()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API token is not configured")

    supplied = request.headers.get("X-Lattice-Admin-Token", "")
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="Admin API token required")
    return "admin"


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies, including chunked bodies."""

    def __init__(self, app: Any, max_body_bytes: int):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_body_bytes:
                    await JSONResponse(status_code=413, content={"detail": "Request body too large"})(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})(scope, receive, send)
                return

        bytes_received = 0
        buffered_messages: List[Dict[str, Any]] = []

        while True:
            message = await receive()
            buffered_messages.append(message)
            if message.get("type") != "http.request":
                break
            bytes_received += len(message.get("body") or b"")
            if bytes_received > self.max_body_bytes:
                await JSONResponse(status_code=413, content={"detail": "Request body too large"})(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive() -> Dict[str, Any]:
            if buffered_messages:
                return buffered_messages.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


# =====================================================================
# Service
# =====================================================================

class DiscoveryService:
    """Gossip, trust and message delivery for this server."""

    def __init__(self, db: Optional[SQLiteClient] = None, http: Optional[httpx.Client] = None):
        self.db = db or SQLiteClient()
        self.http = http or httpx.Client(timeout=10.0)
        self.peers = PeerManager(self.db)
        self.identity: Optional[Identity] = None
        self.trust: Optional[TrustService] = None
        self._rng = secrets.SystemRandom()

        self.start_time = datetime.now(timezone.utc)
        self.last_gossip_time: Optional[datetime] = None
        self.maintenance_mode = False
        self.cached_saturation = 0.0

        self._circuit_breaker_threshold = 5
        self._circuit_breaker_timeout = timedelta(minutes=15)

    def use_identity(self, identity: Identity) -> None:
        self.identity = identity
        quorum = int(load_config("INTRODUCTION_QUORUM") or 1)
        self.trust = TrustService(self.db, self.peers, identity, self.http, quorum=quorum)

    def initialize(self) -> None:
        if self.identity is None:
            self.use_identity(Identity.load_or_create(self.db))
        stuck = self._reset_stuck_messages()
        if stuck:
            logger.info("Crash recovery: reset %d stuck messages to pending", stuck)

    # -----------------------------------------------------------------
    # Gossip
    # -----------------------------------------------------------------

    def handle_gossip(self, payload: GossipPayload, sender: Peer) -> List[str]:
        """
        Apply gossip from a known peer. Every payload must be signed with the
        sender's key on record. Returns servers to evaluate for introduction.
        """
        if not payload.verify(sender["public_key"]):
            raise TrustError("Signature does not match the sender's key on record")
        try:
            require_fresh(payload.timestamp, GOSSIP_MAX_AGE)
        except ValueError as exc:
            raise TrustError(str(exc)) from exc

        if isinstance(payload, ServerAnnouncement):
            if payload.public_key != sender["public_key"]:
                raise TrustError("Announced key differs from the key on record; keys change only by rotation")
            if not self.peers.apply_announcement(payload):
                raise TrustError("Announcement conflicts with another peer")
        elif isinstance(payload, Introduction):
            return self.trust.record_introduction(payload, sender)
        elif isinstance(payload, KeyRotation):
            if payload.old_public_key != sender["public_key"] or not self.peers.rotate_key(payload):
                raise TrustError("Rotation does not start from the key on record")
        elif isinstance(payload, IdentityRevocation):
            self.peers.set_trust(payload.server_uuid, "revoked")
            self.trust.prune()
        return []

    def gossip_round(self) -> None:
        """Announce to every direct peer and a few other neighbors; introduce direct peers to each other."""
        announcement = GossipMessage.wrap(self.identity.announcement())
        direct = self.peers.with_trust("direct")
        others = [peer for peer in self.peers.get_active_neighbors() if peer["trust"] != "direct"]

        for peer in direct + self._rng.sample(others, min(3, len(others))):
            self._send_gossip(peer, announcement)
            if peer["trust"] == "direct":
                self._send_gossip(peer, GossipMessage.wrap(self.trust.introduction_for(peer["server_uuid"])))

        self.last_gossip_time = datetime.now(timezone.utc)
        self._update_saturation()
        logger.info("Completed gossip round")

    def _send_gossip(self, peer: Peer, message: GossipMessage) -> None:
        if self._post_json(f"{peer['endpoint']}/api/v1/gossip/receive", message.model_dump(), timeout=5.0) is None:
            logger.warning("Gossip %s to %s failed", message.kind, peer["server_id"])

    def _update_saturation(self) -> None:
        """
        Estimate network visibility for /status: 0.0 just started, 1.0 well connected.

        Weighted mix of neighbor connectivity (against a target that grows with
        the network) and the fraction of peers heard from in the last hour.
        """
        stats = self.db.execute_single(
            """
            SELECT COUNT(*) AS total,
                   COUNT(CASE WHEN is_neighbor = 1 THEN 1 END) AS neighbors,
                   COUNT(CASE WHEN last_seen_at > ? THEN 1 END) AS active
            FROM lattice_peers WHERE trust IN ('direct', 'introduced')
            """,
            ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),)
        )
        if not stats["total"]:
            self.cached_saturation = 0.0
            return
        neighbor_saturation = min(1.0, stats["neighbors"] / max(10, stats["total"] // 5))
        self.cached_saturation = 0.7 * neighbor_saturation + 0.3 * stats["active"] / stats["total"]

    def cleanup_stale_data(self) -> None:
        now = now_iso()
        stale_peers = self.peers.cleanup_stale_peers(days=30)
        self.db.execute("DELETE FROM lattice_invites WHERE expires_at < ?", (now,))
        self.db.execute("DELETE FROM lattice_messages WHERE expires_at < ?", (now,))
        self.db.execute(
            "DELETE FROM lattice_received_messages WHERE received_at < ?",
            ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),)
        )
        self.db.execute(
            "DELETE FROM lattice_received_messages WHERE status = 'processing' AND received_at < ?",
            ((datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(),)
        )
        forgotten = self.trust.prune()
        self._reset_stuck_messages()
        logger.info("Cleanup removed %d stale peers and %d unvouched introductions", stale_peers, forgotten)

    # -----------------------------------------------------------------
    # Outbound messages
    # -----------------------------------------------------------------

    def queue_outbound_message(
        self,
        to_address: str,
        from_address: str,
        content: str,
        message_type: str = "pager",
        priority: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Sign and queue a message for delivery. Raises ValueError on invalid input."""
        message = FederatedMessage(
            to_address=to_address,
            from_address=from_address,
            content=content,
            message_type=message_type,
            priority=priority,
            metadata=metadata or {}
        )
        if message.from_address.split("@", 1)[1] != self.identity.server_id:
            raise ValueError("from_address must use this server's domain")
        self.identity.sign(message)

        now = message.timestamp
        self.db.execute(
            """
            INSERT INTO lattice_messages
                (message_id, to_domain, priority, message, next_attempt_at, last_status_change_at, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message.message_id,
                message.to_address.split("@", 1)[1],
                message.priority,
                json.dumps(message.model_dump()),
                now,
                now,
                now,
                (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
            )
        )
        logger.info("Queued message %s to %s", message.message_id, message.to_address)
        return message.message_id

    def process_message_queue(self, max_messages: int = 10) -> Dict[str, Any]:
        now = now_iso()
        messages = self.db.execute_query(
            """
            SELECT * FROM lattice_messages
            WHERE status = 'pending' AND next_attempt_at <= ? AND expires_at > ?
            ORDER BY priority DESC, created_at ASC
            LIMIT ?
            """,
            (now, now, max_messages)
        )

        delivered = failed = 0
        for row in messages:
            try:
                self._deliver(row)
                delivered += 1
            except PermanentDeliveryFailure as exc:
                logger.error("Message %s permanently failed: %s", row["message_id"], exc)
                failed += 1
            except Exception as exc:
                logger.error("Failed to deliver message %s: %s", row["message_id"], exc)
                self._handle_delivery_failure(row, str(exc))
                failed += 1

        return {"processed": len(messages), "delivered": delivered, "failed": failed}

    def deliver_message_async(self, message_id: str) -> None:
        """Attempt immediate delivery of a queued message (run as a background task)."""
        row = self.db.execute_single("SELECT * FROM lattice_messages WHERE message_id = ?", (message_id,))
        if not row or row["status"] != "pending":
            return
        try:
            self._deliver(row)
        except PermanentDeliveryFailure as exc:
            logger.warning("Immediate delivery permanently failed for %s: %s", message_id, exc)
        except Exception as exc:
            logger.warning("Immediate delivery failed for %s: %s", message_id, exc)
            self._handle_delivery_failure(row, str(exc))

    def _deliver(self, row: Dict[str, Any]) -> None:
        message_id = row["message_id"]
        peer = self.peers.get_by_server_id(row["to_domain"])
        if not peer:
            raise ValueError(f"No route to domain: {row['to_domain']}")
        if peer["trust"] not in ACTIVE_TRUST:
            reason = f"Recipient server is {peer['trust']}"
            self._fail_message_permanently(message_id, reason)
            raise PermanentDeliveryFailure(reason)

        server_id = peer["server_id"]
        if not self._check_circuit_breaker(server_id):
            raise ValueError(f"Circuit breaker open for {server_id}")

        now = now_iso()
        self.db.execute(
            "UPDATE lattice_messages SET status = 'sending', last_status_change_at = ? WHERE message_id = ?",
            (now, message_id)
        )

        response = self._send_to_remote_server(
            f"{peer['endpoint']}/api/v1/federation/messages/receive",
            json.loads(row["message"])
        )
        if not response:
            self._record_delivery_failure(server_id)
            raise ValueError("Remote server did not return a delivery response")

        try:
            ack = self._verify_delivery_ack(response.get("ack") or {}, message_id, server_id, peer["public_key"])
        except ValueError as exc:
            logger.warning("Invalid ack from %s: %s", server_id, exc)
            self._record_delivery_failure(server_id)
            raise

        if ack.status == "delivered":
            self._record_delivery_success(server_id)
            self._complete_message(message_id, response["ack"])
            logger.info("Message %s delivered to %s", message_id, server_id)
            return

        reason = ack.error_message or "Remote server rejected message"
        self._fail_message_permanently(message_id, reason, ack_data=response["ack"])
        raise PermanentDeliveryFailure(reason)

    def _verify_delivery_ack(
        self,
        ack_data: Dict[str, Any],
        message_id: str,
        server_id: str,
        public_key: str
    ) -> MessageAcknowledgment:
        if not ack_data:
            raise ValueError("Remote server did not return a signed acknowledgment")

        ack = MessageAcknowledgment(**ack_data)
        if ack.message_id != message_id:
            raise ValueError("Acknowledgment message_id mismatch")
        if ack.recipient_server != server_id:
            raise ValueError("Acknowledgment recipient_server mismatch")
        if (ack.status, ack.ack_type) not in {("delivered", "message_received"), ("rejected", "message_failed")}:
            raise ValueError("Remote server returned an invalid acknowledgment status")
        require_fresh(ack.timestamp, ACK_MAX_AGE)
        if not ack.verify(public_key):
            raise ValueError("Acknowledgment signature verification failed")
        return ack

    def _send_to_remote_server(self, url: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return self._post_json(url, data, timeout=30.0)

    def _post_json(self, url: str, data: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
        """POST to a peer. Returns the JSON body on 200, otherwise None."""
        parsed = urlparse(url)
        try:
            _validate_endpoint_url(f"{parsed.scheme}://{parsed.netloc}")
            response = self.http.post(url, json=data, timeout=timeout)
            if response.status_code != 200:
                logger.warning("POST %s returned %d: %s", url, response.status_code, response.text[:200])
                return None
            return response.json()
        except (ValueError, httpx.HTTPError) as exc:
            logger.warning("POST %s failed: %s", url, exc)
            return None

    def _check_circuit_breaker(self, server_id: str) -> bool:
        """True if the circuit is closed (deliveries allowed)."""
        peer = self.db.execute_single("SELECT circuit_open_until FROM lattice_peers WHERE server_id = ?", (server_id,))
        if not peer or not peer["circuit_open_until"]:
            return True

        try:
            open_until = parse_timestamp(peer["circuit_open_until"])
        except ValueError:
            open_until = datetime.now(timezone.utc)

        if open_until <= datetime.now(timezone.utc):
            self._record_delivery_success(server_id)
            return True
        logger.warning("Circuit breaker open for %s until %s", server_id, open_until.isoformat())
        return False

    def _record_delivery_success(self, server_id: str) -> None:
        self.db.execute(
            "UPDATE lattice_peers SET circuit_failures = 0, circuit_open_until = NULL WHERE server_id = ?",
            (server_id,)
        )

    def _record_delivery_failure(self, server_id: str) -> None:
        peer = self.db.execute_single(
            "UPDATE lattice_peers SET circuit_failures = circuit_failures + 1 WHERE server_id = ? RETURNING circuit_failures",
            (server_id,)
        )
        if peer and peer["circuit_failures"] >= self._circuit_breaker_threshold:
            open_until = datetime.now(timezone.utc) + self._circuit_breaker_timeout
            self.db.execute(
                "UPDATE lattice_peers SET circuit_open_until = ? WHERE server_id = ?",
                (open_until.isoformat(), server_id)
            )
            logger.error("Circuit breaker opened for %s until %s", server_id, open_until.isoformat())

    def _handle_delivery_failure(self, row: Dict[str, Any], error: str) -> None:
        """Retry with exponential backoff (2, 4, 8... minutes, capped at 60) until max_attempts."""
        attempt_count = row["attempt_count"] + 1
        if attempt_count >= row["max_attempts"]:
            self._fail_message_permanently(row["message_id"], f"Max retries exceeded: {error}")
            return

        next_attempt = datetime.now(timezone.utc) + timedelta(minutes=min(2 ** attempt_count, 60))
        self.db.execute(
            """
            UPDATE lattice_messages
            SET status = 'pending', attempt_count = ?, next_attempt_at = ?, last_error = ?, last_status_change_at = ?
            WHERE message_id = ?
            """,
            (attempt_count, next_attempt.isoformat(), error, now_iso(), row["message_id"])
        )

    def _complete_message(self, message_id: str, ack_data: Dict[str, Any]) -> None:
        now = now_iso()
        self.db.execute(
            """
            UPDATE lattice_messages
            SET status = 'delivered', delivered_at = ?, last_status_change_at = ?, ack_data = ?
            WHERE message_id = ?
            """,
            (now, now, json.dumps(ack_data), message_id)
        )

    def _fail_message_permanently(self, message_id: str, error: str, ack_data: Optional[Dict[str, Any]] = None) -> None:
        self.db.execute(
            """
            UPDATE lattice_messages
            SET status = 'failed', last_error = ?, last_status_change_at = ?, ack_data = ?
            WHERE message_id = ?
            """,
            (error, now_iso(), json.dumps(ack_data) if ack_data else None, message_id)
        )
        logger.error("Message %s permanently failed: %s", message_id, error)

    def _reset_stuck_messages(self) -> int:
        """Return messages stuck in 'sending' for 5+ minutes (a crash mid-delivery) to the queue."""
        now = now_iso()
        reset = self.db.execute_query(
            """
            UPDATE lattice_messages SET status = 'pending', next_attempt_at = ?, last_status_change_at = ?
            WHERE status = 'sending' AND last_status_change_at < ?
            RETURNING message_id
            """,
            (now, now, (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat())
        )
        return len(reset)

    # -----------------------------------------------------------------
    # Inbound messages
    # -----------------------------------------------------------------

    def receive_message(self, message: FederatedMessage, sender: Peer) -> InboundMessageResponse:
        """Verify, deduplicate and deliver an inbound message to the local webhook."""
        recipient_username = message.to_address.split("@", 1)[0]

        if not message.verify(sender["public_key"]):
            logger.error("Invalid signature on message %s from %s", message.message_id, sender["server_id"])
            raise HTTPException(status_code=403, detail="Message signature verification failed")

        existing = self._received(message.message_id)
        if existing:
            return existing
        try:
            self.db.execute(
                "INSERT INTO lattice_received_messages (message_id, from_address, received_at, status) VALUES (?, ?, ?, 'processing')",
                (message.message_id, message.from_address, now_iso())
            )
        except Exception:
            existing = self._received(message.message_id)
            if existing:
                return existing
            raise

        def complete(status: str, ack: Dict[str, Any]) -> InboundMessageResponse:
            self.db.execute(
                "UPDATE lattice_received_messages SET status = ?, completed_at = ?, ack_data = ? WHERE message_id = ?",
                (status, now_iso(), json.dumps(ack), message.message_id)
            )
            return InboundMessageResponse(status=status, message_id=message.message_id, ack=ack)

        def release() -> None:
            self.db.execute(
                "DELETE FROM lattice_received_messages WHERE message_id = ? AND status = 'processing'",
                (message.message_id,)
            )

        try:
            if not has_username_resolver():
                raise HTTPException(status_code=503, detail="Server not configured to receive federated messages")

            user_id = resolve_username(recipient_username)
            if not user_id:
                return complete("rejected", self._ack(message.message_id, f"Unknown recipient: {recipient_username}"))

            webhook = os.getenv("LATTICE_DELIVERY_WEBHOOK") or load_config("DELIVERY_WEBHOOK")
            if not webhook:
                raise HTTPException(status_code=503, detail="Delivery webhook not configured")

            response = self.http.post(
                webhook,
                json={
                    "from_address": message.from_address,
                    "to_user_id": user_id,
                    "content": message.content,
                    "priority": message.priority,
                    "message_id": message.message_id,
                    "metadata": message.metadata,
                    "sender_verified": True,
                    "sender_server_id": sender["server_id"]
                },
                timeout=30.0
            )
            if response.status_code == 200:
                return complete("accepted", self._ack(message.message_id))
            if 400 <= response.status_code < 500:
                logger.warning("Webhook rejected message %s: %d", message.message_id, response.status_code)
                return complete("rejected", self._ack(message.message_id, f"Delivery rejected: {response.status_code}"))
            raise HTTPException(status_code=502, detail=f"Delivery backend error: {response.status_code}")

        except httpx.TimeoutException:
            release()
            raise HTTPException(status_code=504, detail="Delivery webhook timeout")
        except Exception:
            release()
            raise

    def _received(self, message_id: str) -> Optional[InboundMessageResponse]:
        """The recorded outcome for an already-received message, if any."""
        row = self.db.execute_single(
            "SELECT status, ack_data FROM lattice_received_messages WHERE message_id = ?",
            (message_id,)
        )
        if not row:
            return None
        if row["status"] == "processing":
            raise HTTPException(status_code=409, detail="Message is already being processed")
        return InboundMessageResponse(status=row["status"], message_id=message_id, ack=json.loads(row["ack_data"] or "{}"))

    def _ack(self, message_id: str, rejection: Optional[str] = None) -> Dict[str, Any]:
        return self.identity.sign(MessageAcknowledgment(
            ack_type="message_failed" if rejection else "message_received",
            message_id=message_id,
            status="rejected" if rejection else "delivered",
            recipient_server=self.identity.server_id,
            error_message=rejection
        )).model_dump()


# =====================================================================
# Endpoints
# =====================================================================

router = APIRouter()


def get_service(request: Request) -> DiscoveryService:
    return request.app.state.service


def _known_peer(service: DiscoveryService, column: str, value: str) -> Peer:
    """Rate-limit and return an active peer, or reject the request."""
    peer = service.peers.hit(column, value)
    if not peer:
        raise HTTPException(status_code=403, detail="Unknown sender; pair with an invite first")
    if peer["request_count"] > RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if peer["trust"] not in ACTIVE_TRUST:
        raise HTTPException(status_code=403, detail=f"Sender is {peer['trust']}")
    return peer


# --- Public ----------------------------------------------------------

@router.get("/status")
def public_status(service: DiscoveryService = Depends(get_service)):
    """Lightweight liveness information for peers."""
    peer_count = service.db.execute_single(
        "SELECT COUNT(*) AS n FROM lattice_peers WHERE trust IN ('direct', 'introduced')"
    )["n"]
    return {
        "alive": True,
        "accepting_messages": not service.maintenance_mode,
        "peer_count": peer_count,
        "saturation": round(service.cached_saturation, 2),
        "version": VERSION
    }


@router.get("/api/v1/announcement")
def get_announcement(service: DiscoveryService = Depends(get_service)):
    """Our self-signed announcement. Invitees check it against the key in their invite."""
    return service.identity.announcement().model_dump()


@router.post("/api/v1/gossip/receive")
def receive_gossip(
    message: GossipMessage,
    background_tasks: BackgroundTasks,
    service: DiscoveryService = Depends(get_service)
):
    try:
        payload = message.unwrap()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {message.kind} payload: {exc}")

    sender = _known_peer(service, "server_uuid", payload.server_uuid)
    try:
        subjects = service.handle_gossip(payload, sender)
    except TrustError as exc:
        logger.warning("Rejected %s from %s: %s", message.kind, sender["server_id"], exc)
        raise HTTPException(status_code=403, detail=str(exc))

    for subject_uuid in subjects:
        background_tasks.add_task(service.trust.evaluate, subject_uuid)
    return {"status": "accepted"}


@router.post("/api/v1/pair")
def pair(request: PairRequest, service: DiscoveryService = Depends(get_service)):
    """Complete an invite: the invitee proves it holds the invite secret."""
    try:
        service.trust.handle_pair(request)
    except TrustError as exc:
        logger.warning("Rejected pairing from %s: %s", request.announcement.server_id, exc)
        raise HTTPException(status_code=403, detail=str(exc))
    return {"status": "paired", "server_id": service.identity.server_id}


@router.post("/api/v1/keys/query")
def key_query(query: KeyQuery, service: DiscoveryService = Depends(get_service)):
    """Tell a peer which key we hold for a server, so it can cross-check an introduction."""
    requester = _known_peer(service, "server_uuid", query.requester_uuid)
    try:
        return service.trust.answer_key_query(query, requester).model_dump()
    except TrustError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.post("/api/v1/federation/messages/receive")
def receive_federated_message(
    message: FederatedMessage,
    service: DiscoveryService = Depends(get_service)
) -> InboundMessageResponse:
    """Receive a signed message from a peer and hand it to the local delivery webhook."""
    if message.to_address.split("@", 1)[1] != service.identity.server_id:
        raise HTTPException(status_code=403, detail="Recipient domain is not local")
    try:
        require_fresh(message.timestamp, MESSAGE_MAX_AGE)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    sender = _known_peer(service, "server_id", message.from_address.split("@", 1)[1])
    return service.receive_message(message, sender)


# --- Admin -----------------------------------------------------------

@router.get("/health", dependencies=[Depends(admin_only)])
def health_check(service: DiscoveryService = Depends(get_service)):
    now = now_iso()
    queue = service.db.execute_single(
        """
        SELECT COUNT(CASE WHEN status = 'pending' THEN 1 END) AS pending,
               COUNT(CASE WHEN status = 'sending' THEN 1 END) AS sending,
               COUNT(CASE WHEN status = 'failed' THEN 1 END) AS failed
        FROM lattice_messages WHERE expires_at > ?
        """,
        (now,)
    )
    peers = service.db.execute_single(
        """
        SELECT COUNT(*) AS total_peers,
               COUNT(CASE WHEN trust = 'direct' THEN 1 END) AS direct,
               COUNT(CASE WHEN trust = 'introduced' THEN 1 END) AS introduced,
               COUNT(CASE WHEN circuit_open_until > ? THEN 1 END) AS open_circuits
        FROM lattice_peers WHERE trust IN ('direct', 'introduced')
        """,
        (now,)
    )
    return {
        "status": "healthy",
        "service": "discovery_daemon",
        "server_id": service.identity.server_id,
        "last_gossip": service.last_gossip_time.isoformat() if service.last_gossip_time else None,
        "maintenance_mode": service.maintenance_mode,
        "queues": queue,
        "peers": peers,
        "saturation": round(service.cached_saturation, 2),
        "uptime_seconds": int((datetime.now(timezone.utc) - service.start_time).total_seconds())
    }


@router.get("/api/v1/identity", dependencies=[Depends(admin_only)])
def get_identity(service: DiscoveryService = Depends(get_service)):
    return {
        "server_id": service.identity.server_id,
        "server_uuid": service.identity.server_uuid,
        "public_key": service.identity.public_key,
        "endpoint": service.identity.endpoint
    }


@router.post("/api/v1/invites", dependencies=[Depends(admin_only)])
def create_invite(request: InviteRequest, service: DiscoveryService = Depends(get_service)) -> InviteResponse:
    """Issue a single-use invite token to carry to another server's admin out of band."""
    token, expires_at = service.trust.create_invite(timedelta(hours=request.ttl_hours))
    return InviteResponse(token=token, expires_at=expires_at)


@router.post("/api/v1/invites/accept", dependencies=[Depends(admin_only)])
def accept_invite(request: AcceptInviteRequest, service: DiscoveryService = Depends(get_service)):
    """Pair with the server that issued an invite token."""
    try:
        inviter = service.trust.accept_invite(request.token)
    except TrustError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"status": "paired", "server_id": inviter.server_id, "server_uuid": inviter.server_uuid}


@router.get("/api/v1/peers", dependencies=[Depends(admin_only)])
def list_peers(
    active_only: bool = True,
    include_blocked: bool = False,
    service: DiscoveryService = Depends(get_service)
) -> List[PeerStatus]:
    trust = ("direct", "introduced", "blocked", "revoked") if include_blocked else ACTIVE_TRUST
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    return [
        PeerStatus(
            server_uuid=peer["server_uuid"],
            server_id=peer["server_id"],
            public_key=peer["public_key"],
            endpoint=peer["endpoint"],
            trust=peer["trust"],
            is_neighbor=bool(peer["is_neighbor"]),
            last_seen=peer["last_seen_at"]
        )
        for peer in service.peers.with_trust(*trust)
        if not active_only or peer["trust"] == "direct" or peer["last_seen_at"] > cutoff
    ]


@router.post("/api/v1/peers/{server_id}/block", dependencies=[Depends(admin_only)])
def block_peer(server_id: str, service: DiscoveryService = Depends(get_service)):
    """Block a peer and forget the servers only it introduced."""
    peer = service.peers.get_by_server_id(server_id)
    if not peer:
        raise HTTPException(status_code=404, detail="Unknown peer")
    service.trust.block(peer["server_uuid"])
    return {"status": "blocked", "server_id": peer["server_id"]}


@router.post("/api/v1/announce", dependencies=[Depends(admin_only)])
def announce(
    request: AnnouncementRequest,
    background_tasks: BackgroundTasks,
    service: DiscoveryService = Depends(get_service)
):
    if not request.force and service.last_gossip_time:
        since = (datetime.now(timezone.utc) - service.last_gossip_time).total_seconds()
        if since < 60:
            return {"status": "rate_limited", "next_allowed": int(60 - since)}
    background_tasks.add_task(service.gossip_round)
    return {"status": "scheduled"}


@router.post("/api/v1/messages/send", dependencies=[Depends(admin_only)])
def send_federated_message(
    request: SendMessageRequest,
    background_tasks: BackgroundTasks,
    service: DiscoveryService = Depends(get_service)
) -> SendMessageResponse:
    """Sign and queue a message, then attempt delivery immediately in the background."""
    try:
        message_id = service.queue_outbound_message(**request.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    background_tasks.add_task(service.deliver_message_async, message_id)
    return SendMessageResponse(status="queued", message_id=message_id)


@router.post("/api/v1/maintenance/update_neighbors", dependencies=[Depends(admin_only)])
def update_neighbors(background_tasks: BackgroundTasks, service: DiscoveryService = Depends(get_service)):
    background_tasks.add_task(service.peers.select_new_neighbors)
    return {"status": "scheduled"}


@router.post("/api/v1/maintenance/process_messages", dependencies=[Depends(admin_only)])
def process_messages(service: DiscoveryService = Depends(get_service)):
    return {"status": "completed", **service.process_message_queue(max_messages=20)}


@router.post("/api/v1/maintenance/cleanup", dependencies=[Depends(admin_only)])
def cleanup(service: DiscoveryService = Depends(get_service)):
    service.cleanup_stale_data()
    return {"status": "completed"}


# =====================================================================
# Application
# =====================================================================

def create_app(service: Optional[DiscoveryService] = None) -> FastAPI:
    service = service or DiscoveryService()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        service.initialize()
        yield

    app = FastAPI(title="Lattice Discovery Daemon", version=VERSION, lifespan=lifespan)
    app.state.service = service
    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=MAX_REQUEST_BODY_BYTES)
    app.include_router(router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("LATTICE_BIND_HOST", "127.0.0.1"), port=1113, log_level="info")
