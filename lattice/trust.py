"""
Out-of-band trust: invite pairing, introductions and key cross-checks.

A peer's key is trusted in one of two ways:

direct
    An admin carried an invite token from the inviter to the invitee out of
    band. The token holds the inviter's public key, so the invitee
    authenticates the inviter without trusting the network. The invitee then
    proves it holds the token's single-use secret, which authenticates the
    invitee's key to the inviter.

introduced
    Direct peers vouch for their own direct peers. A vouched key is admitted
    once `quorum` direct peers agree on it and no other direct peer, asked
    over its own channel, reports a different key for that server.

Introductions travel one hop: we only vouch for servers we paired with, and
only accept vouches from servers we paired with.
"""

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from . import crypto
from .identity import Identity
from .models import (
    MAX_INTRODUCED_PEERS,
    Introduction,
    KeyAnswer,
    KeyQuery,
    PairRequest,
    PeerRecord,
    ServerAnnouncement,
    _validate_endpoint_url,
    now_iso,
    require_fresh,
)
from .peer_manager import ACTIVE_TRUST, Peer, PeerManager
from .sqlite_client import SQLiteClient

logger = logging.getLogger(__name__)

INVITE_PREFIX = "lattice1:"
INVITE_SECRET_BYTES = 16
WITNESSES = 3
VOUCH_TTL = timedelta(days=30)
ANNOUNCEMENT_MAX_AGE = timedelta(hours=1)
KEY_QUERY_MAX_AGE = timedelta(minutes=5)


class TrustError(Exception):
    """A pairing, introduction or key query was rejected."""


@dataclass(frozen=True)
class InviteToken:
    """`lattice1:` + base64url(public key (32) || secret (16) || endpoint)."""
    public_key: str
    secret: bytes
    endpoint: str

    def encode(self) -> str:
        raw = crypto.b64decode(self.public_key) + self.secret + self.endpoint.encode()
        return INVITE_PREFIX + crypto.b64encode(raw)

    @classmethod
    def decode(cls, token: str) -> "InviteToken":
        token = token.strip()
        if not token.startswith(INVITE_PREFIX):
            raise TrustError("Not a lattice invite")
        try:
            raw = crypto.b64decode(token[len(INVITE_PREFIX):])
            secret = raw[32:32 + INVITE_SECRET_BYTES]
            if len(secret) != INVITE_SECRET_BYTES:
                raise ValueError("token is truncated")
            endpoint = _validate_endpoint_url(raw[32 + INVITE_SECRET_BYTES:].decode())
        except ValueError as exc:
            raise TrustError(f"Malformed invite: {exc}") from exc
        return cls(crypto.b64encode(raw[:32]), secret, endpoint)

    @property
    def invite_id(self) -> str:
        return hashlib.sha256(self.secret).hexdigest()[:32]


def pairing_proof(secret: bytes, inviter_key: str, invitee_key: str) -> str:
    """HMAC binding the invitee's key to the invite secret and the inviter's key."""
    message = crypto.canonical("pair", {"inviter": inviter_key, "invitee": invitee_key})
    return crypto.b64encode(hmac.new(secret, message, hashlib.sha256).digest())


def _fresh(timestamp: str, max_age: timedelta) -> None:
    try:
        require_fresh(timestamp, max_age)
    except ValueError as exc:
        raise TrustError(str(exc)) from exc


def _record(row: Dict[str, Any]) -> PeerRecord:
    """A PeerRecord from our own stored data, which was validated on the way in."""
    return PeerRecord.model_construct(**{field: row[field] for field in PeerRecord.model_fields})


class TrustService:
    """Establishes trust in peer keys."""

    def __init__(
        self,
        db: SQLiteClient,
        peers: PeerManager,
        identity: Identity,
        http: httpx.Client,
        quorum: int = 1
    ):
        self.db = db
        self.peers = peers
        self.identity = identity
        self.http = http
        self.quorum = max(1, quorum)
        self._rng = secrets.SystemRandom()

    # -----------------------------------------------------------------
    # Invites (direct trust)
    # -----------------------------------------------------------------

    def create_invite(self, ttl: timedelta) -> Tuple[str, str]:
        """Issue a single-use invite. Returns (token, expires_at)."""
        secret = secrets.token_bytes(INVITE_SECRET_BYTES)
        token = InviteToken(self.identity.public_key, secret, self.identity.endpoint)
        expires_at = (datetime.now(timezone.utc) + ttl).isoformat()
        self.db.execute(
            "INSERT INTO lattice_invites (id, secret, expires_at) VALUES (?, ?, ?)",
            (token.invite_id, crypto.b64encode(secret), expires_at)
        )
        return token.encode(), expires_at

    def accept_invite(self, token_text: str) -> ServerAnnouncement:
        """Pair with the server that issued the invite. Returns its announcement."""
        token = InviteToken.decode(token_text)
        try:
            inviter = ServerAnnouncement(**self._request("GET", token.endpoint, "/api/v1/announcement"))
        except (TypeError, ValueError) as exc:
            raise TrustError(f"Inviter returned an invalid announcement: {exc}") from exc

        if inviter.public_key != token.public_key or not inviter.verify(token.public_key):
            raise TrustError("Inviter's announcement is not signed by the key in the invite")
        if inviter.endpoint != token.endpoint:
            raise TrustError("Inviter's announced endpoint does not match the invite")
        if inviter.server_uuid == self.identity.server_uuid:
            raise TrustError("Cannot pair with ourselves")
        _fresh(inviter.timestamp, ANNOUNCEMENT_MAX_AGE)
        reason = self.peers.conflict(inviter)
        if reason:
            raise TrustError(f"Cannot pair with {inviter.server_id}: {reason}")

        ours = self.identity.announcement()
        request = PairRequest(
            invite_id=token.invite_id,
            announcement=ours,
            proof=pairing_proof(token.secret, token.public_key, ours.public_key)
        )
        self._request("POST", token.endpoint, "/api/v1/pair", json=request.model_dump())
        self.peers.admit(inviter, "direct")
        return inviter

    def handle_pair(self, request: PairRequest) -> None:
        """Admit an invitee that proves it holds one of our invite secrets."""
        invitee = request.announcement
        if not invitee.verify(invitee.public_key):
            raise TrustError("Announcement is not self-signed")
        if invitee.server_uuid == self.identity.server_uuid:
            raise TrustError("Cannot pair with ourselves")
        _fresh(invitee.timestamp, ANNOUNCEMENT_MAX_AGE)

        invite = self.db.execute_single(
            "SELECT secret FROM lattice_invites WHERE id = ? AND expires_at > ?",
            (request.invite_id, now_iso())
        )
        if not invite:
            raise TrustError("Unknown or expired invite")
        expected = pairing_proof(crypto.b64decode(invite["secret"]), self.identity.public_key, invitee.public_key)
        if not hmac.compare_digest(expected, request.proof):
            raise TrustError("Invalid pairing proof")

        reason = self.peers.conflict(invitee)
        if reason:
            raise TrustError(f"Cannot pair with {invitee.server_id}: {reason}")
        if not self.db.execute_single("DELETE FROM lattice_invites WHERE id = ? RETURNING id", (request.invite_id,)):
            raise TrustError("Invite already used")
        self.peers.admit(invitee, "direct")

    # -----------------------------------------------------------------
    # Introductions (introduced trust)
    # -----------------------------------------------------------------

    def introduction_for(self, recipient_uuid: str) -> Introduction:
        """Our signed vouches for our direct peers other than the recipient: the complete set, possibly empty."""
        records = [_record(peer) for peer in self.peers.with_trust("direct") if peer["server_uuid"] != recipient_uuid]
        return self.identity.sign(Introduction(
            server_uuid=self.identity.server_uuid,
            peers=records[:MAX_INTRODUCED_PEERS]
        ))

    def record_introduction(self, introduction: Introduction, voucher: Peer) -> List[str]:
        """
        Replace a direct peer's vouches with its latest introduction. The caller
        has verified the signature.

        Returns the vouched-for servers we do not know yet, for evaluate().
        """
        if voucher["trust"] != "direct":
            raise TrustError("Only direct peers can introduce servers")

        records = [r for r in introduction.peers if r.server_uuid not in (self.identity.server_uuid, voucher["server_uuid"])]
        placeholders = ", ".join("?" for _ in records)
        withdrawn = self.db.execute_query(
            f"DELETE FROM lattice_vouches WHERE voucher_uuid = ? AND subject_uuid NOT IN ({placeholders}) RETURNING subject_uuid",
            (voucher["server_uuid"], *(r.server_uuid for r in records))
        )

        unknown = []
        now = now_iso()
        for record in records:
            self.db.execute(
                """
                INSERT INTO lattice_vouches (subject_uuid, voucher_uuid, server_id, public_key, endpoint, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(subject_uuid, voucher_uuid) DO UPDATE SET
                    server_id = excluded.server_id,
                    public_key = excluded.public_key,
                    endpoint = excluded.endpoint,
                    updated_at = excluded.updated_at
                """,
                (record.server_uuid, voucher["server_uuid"], record.server_id, record.public_key, record.endpoint, now)
            )
            known = self.peers.get(record.server_uuid)
            if not known:
                unknown.append(record.server_uuid)
            elif known["public_key"] != record.public_key:
                logger.error(
                    "%s vouches for a different key for %s than the one we hold",
                    voucher["server_id"], known["server_id"]
                )
        if withdrawn:
            self.prune()
        return unknown

    def evaluate(self, subject_uuid: str) -> bool:
        """Admit an unknown vouched-for server if direct peers agree on its key and no witness disputes it."""
        if self.peers.get(subject_uuid):
            return False

        vouches = self.db.execute_query(
            """
            SELECT v.subject_uuid AS server_uuid, v.server_id, v.public_key, v.endpoint, v.voucher_uuid
            FROM lattice_vouches v
            JOIN lattice_peers p ON p.server_uuid = v.voucher_uuid
            WHERE v.subject_uuid = ? AND p.trust = 'direct'
            ORDER BY v.updated_at DESC
            """,
            (subject_uuid,)
        )
        keys = {vouch["public_key"] for vouch in vouches}
        if len(keys) > 1:
            logger.error("Direct peers disagree on the key for %s; not admitting", subject_uuid)
            return False
        if len(vouches) < self.quorum:
            return False

        record = _record(vouches[0])
        reason = self.peers.conflict(record)
        if reason:
            logger.warning("Not admitting introduced %s: %s", record.server_id, reason)
            return False

        dissenter = self._find_dissent(record, exclude={vouch["voucher_uuid"] for vouch in vouches})
        if dissenter:
            logger.error(
                "%s reports a different key for %s than its vouchers; not admitting "
                "(possible MITM or compromised voucher)",
                dissenter, record.server_id
            )
            return False

        return self.peers.admit(record, "introduced")

    def prune(self) -> int:
        """Drop vouches from non-direct or silent vouchers, then introduced peers left below quorum."""
        self.db.execute(
            """
            DELETE FROM lattice_vouches
            WHERE updated_at < ?
               OR voucher_uuid NOT IN (SELECT server_uuid FROM lattice_peers WHERE trust = 'direct')
            """,
            ((datetime.now(timezone.utc) - VOUCH_TTL).isoformat(),)
        )
        orphans = self.db.execute_query(
            """
            DELETE FROM lattice_peers
            WHERE trust = 'introduced' AND server_uuid NOT IN (
                SELECT subject_uuid FROM lattice_vouches GROUP BY subject_uuid HAVING COUNT(*) >= ?
            )
            RETURNING server_id
            """,
            (self.quorum,)
        )
        for orphan in orphans:
            logger.warning("Forgot introduced peer %s: no longer vouched for", orphan["server_id"])
        return len(orphans)

    def block(self, server_uuid: str) -> bool:
        """Block a peer and forget anything it alone introduced."""
        if not self.peers.set_trust(server_uuid, "blocked"):
            return False
        self.prune()
        return True

    # -----------------------------------------------------------------
    # Key cross-checks
    # -----------------------------------------------------------------

    def answer_key_query(self, query: KeyQuery, requester: Peer) -> KeyAnswer:
        """Tell a peer which key we hold for a server."""
        if not query.verify(requester["public_key"]):
            raise TrustError("Invalid key query signature")
        _fresh(query.timestamp, KEY_QUERY_MAX_AGE)

        if query.subject_uuid == self.identity.server_uuid:
            public_key = self.identity.public_key
        else:
            subject = self.peers.get(query.subject_uuid)
            public_key = subject["public_key"] if subject and subject["trust"] in ACTIVE_TRUST else None

        return self.identity.sign(KeyAnswer(
            responder_uuid=self.identity.server_uuid,
            subject_uuid=query.subject_uuid,
            public_key=public_key,
            nonce=query.nonce
        ))

    def _find_dissent(self, record: PeerRecord, exclude: set) -> Optional[str]:
        """Ask up to WITNESSES other direct peers for their key; return the first that disagrees."""
        witnesses = [peer for peer in self.peers.with_trust("direct") if peer["server_uuid"] not in exclude]
        for witness in self._rng.sample(witnesses, min(WITNESSES, len(witnesses))):
            public_key = self._ask_key(witness, record.server_uuid)
            if public_key and public_key != record.public_key:
                return witness["server_id"]
        return None

    def _ask_key(self, witness: Peer, subject_uuid: str) -> Optional[str]:
        query = self.identity.sign(KeyQuery(
            requester_uuid=self.identity.server_uuid,
            subject_uuid=subject_uuid,
            nonce=secrets.token_hex(16)
        ))
        try:
            answer = KeyAnswer(**self._request("POST", witness["endpoint"], "/api/v1/keys/query", json=query.model_dump()))
        except (TrustError, TypeError, ValueError) as exc:
            logger.info("Key query to %s failed: %s", witness["server_id"], exc)
            return None

        expected = (witness["server_uuid"], subject_uuid, query.nonce)
        if (answer.responder_uuid, answer.subject_uuid, answer.nonce) != expected or not answer.verify(witness["public_key"]):
            logger.warning("Ignoring invalid key answer from %s", witness["server_id"])
            return None
        return answer.public_key

    def _request(self, method: str, endpoint: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        url = endpoint + path
        try:
            _validate_endpoint_url(endpoint)
            response = self.http.request(method, url, timeout=10.0, **kwargs)
        except (ValueError, httpx.HTTPError) as exc:
            raise TrustError(f"{method} {url} failed: {exc}") from exc
        if response.status_code != 200:
            raise TrustError(f"{method} {url} returned {response.status_code}: {response.text[:200]}")
        try:
            return response.json()
        except ValueError as exc:
            raise TrustError(f"{method} {url} returned invalid JSON") from exc
