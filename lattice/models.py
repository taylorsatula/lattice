"""
Lattice protocol models.

Every protocol message is a SignedModel: signed by its author over the
canonical encoding of all fields except the signature.
"""

import ipaddress
import json
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Type
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dateutil import parser as dateutil_parser
from pydantic import AfterValidator, BaseModel, Field, field_validator

from . import crypto

MAX_METADATA_BYTES = 8 * 1024
MAX_LOCATION_BYTES = 4 * 1024
MAX_GOSSIP_PAYLOAD_BYTES = 64 * 1024
MAX_INTRODUCED_PEERS = 200


# =====================================================================
# VALIDATION HELPERS
# =====================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(value: str) -> datetime:
    """Parse a protocol timestamp as an aware UTC datetime."""
    try:
        parsed = dateutil_parser.parse(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"Invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def require_fresh(value: str, max_age: timedelta, future_skew: timedelta = timedelta(minutes=5)) -> None:
    """Reject stale or future-dated protocol messages."""
    age = datetime.now(timezone.utc) - parse_timestamp(value)
    if age > max_age:
        raise ValueError("Timestamp is stale")
    if age < -future_skew:
        raise ValueError("Timestamp is too far in the future")


def _validate_json_size(value: Any, max_bytes: int, field_name: str) -> Any:
    """Reject nested JSON fields that are too large to safely process."""
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON serializable") from exc

    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} bytes")

    return value


def _is_internal_address(hostname: str) -> bool:
    """
    Check if a hostname is, or resolves to, an internal address.

    Blocks loopback, private, link-local, reserved and unspecified addresses,
    including hostnames that resolve to them (DNS rebinding protection).
    Unresolvable hostnames are treated as internal.
    """
    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return True

    def _is_internal_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified

    try:
        return _is_internal_ip(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return True

    for _, _, _, _, sockaddr in results:
        ip = ipaddress.ip_address(sockaddr[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if _is_internal_ip(ip):
            return True
    return False


def _validate_endpoint_url(url: str) -> str:
    """Validate a peer base URL: https, no credentials, not internal (SSRF protection)."""
    if not url:
        raise ValueError("Endpoint URL cannot be empty")

    url = url.rstrip("/")
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"Endpoint URL must use https scheme: {url}")
    if parsed.username or parsed.password:
        raise ValueError(f"Endpoint URL must not contain credentials: {url}")
    if parsed.query or parsed.fragment:
        raise ValueError(f"Endpoint URL must not contain a query or fragment: {url}")
    if not parsed.hostname:
        raise ValueError(f"Endpoint URL must include host: {url}")
    if _is_internal_address(parsed.hostname):
        raise ValueError(f"Endpoint URL cannot point to internal/link-local address: {url}")

    return url


def _validate_public_key(value: str) -> str:
    try:
        raw = crypto.b64decode(value)
    except ValueError as exc:
        raise ValueError("Public key must be base64url") from exc
    if len(raw) != 32:
        raise ValueError("Public key must be 32 bytes (Ed25519)")
    return value


def _validate_server_id(value: str) -> str:
    if not value or "://" in value or "@" in value or " " in value:
        raise ValueError("server_id must be a valid domain name")
    return value.lower()


def _validate_uuid(value: str) -> str:
    return str(uuid.UUID(value))


PublicKey = Annotated[str, AfterValidator(_validate_public_key)]
Endpoint = Annotated[str, AfterValidator(_validate_endpoint_url)]
ServerId = Annotated[str, AfterValidator(_validate_server_id)]
ServerUUID = Annotated[str, AfterValidator(_validate_uuid)]


# =====================================================================
# SIGNED MESSAGES
# =====================================================================

class SignedModel(BaseModel):
    """A protocol message signed by its author. KIND domain-separates signatures."""
    KIND: ClassVar[str]
    signature: str = ""

    def signing_bytes(self) -> bytes:
        return crypto.canonical(self.KIND, self.model_dump(exclude={"signature"}))

    def sign(self, private_key: Ed25519PrivateKey) -> "SignedModel":
        self.signature = crypto.sign(private_key, self.signing_bytes())
        return self

    def verify(self, public_key: str) -> bool:
        return crypto.verify(public_key, self.signing_bytes(), self.signature)


class GossipPayload(SignedModel):
    """A gossip message authored and signed by the server identified by server_uuid."""
    server_uuid: ServerUUID
    timestamp: str = Field(default_factory=now_iso)


class ServerAnnouncement(GossipPayload):
    """A server's self-signed identity and endpoint."""
    KIND = "announcement"
    server_id: ServerId
    public_key: PublicKey
    endpoint: Endpoint


class PeerRecord(BaseModel):
    """A peer identity as vouched for in an introduction."""
    server_uuid: ServerUUID
    server_id: ServerId
    public_key: PublicKey
    endpoint: Endpoint


class Introduction(GossipPayload):
    """A server vouching for the peers it paired with directly."""
    KIND = "introduction"
    peers: List[PeerRecord] = Field(max_length=MAX_INTRODUCED_PEERS)


class KeyRotation(GossipPayload):
    """Replace a server's key. Signed with the old key."""
    KIND = "key_rotation"
    old_public_key: PublicKey
    new_public_key: PublicKey
    reason: Literal["scheduled", "compromise_suspected", "upgrade"] = "scheduled"


class IdentityRevocation(GossipPayload):
    """Permanently revoke a server identity (cyanide pill)."""
    KIND = "revocation"
    reason: str = Field(max_length=500)


GOSSIP_KINDS: Dict[str, Type[GossipPayload]] = {
    cls.KIND: cls for cls in (ServerAnnouncement, Introduction, KeyRotation, IdentityRevocation)
}


class GossipMessage(BaseModel):
    """Wrapper routing a signed gossip payload to its model."""
    kind: Literal["announcement", "introduction", "key_rotation", "revocation"]
    payload: Dict[str, Any]

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, v):
        return _validate_json_size(v, MAX_GOSSIP_PAYLOAD_BYTES, "payload")

    @classmethod
    def wrap(cls, payload: GossipPayload) -> "GossipMessage":
        return cls(kind=payload.KIND, payload=payload.model_dump())

    def unwrap(self) -> GossipPayload:
        return GOSSIP_KINDS[self.kind](**self.payload)


# =====================================================================
# PAIRING AND KEY CROSS-CHECKS
# =====================================================================

class PairRequest(BaseModel):
    """Invitee's half of pairing: its announcement plus proof it holds the invite secret."""
    invite_id: str = Field(min_length=32, max_length=32)
    announcement: ServerAnnouncement
    proof: str


class KeyQuery(SignedModel):
    """Ask a peer which key it holds for a server."""
    KIND = "key_query"
    requester_uuid: ServerUUID
    subject_uuid: ServerUUID
    nonce: str = Field(min_length=16, max_length=64)
    timestamp: str = Field(default_factory=now_iso)


class KeyAnswer(SignedModel):
    """A peer's signed statement of the key it holds for a server, if any."""
    KIND = "key_answer"
    responder_uuid: ServerUUID
    subject_uuid: ServerUUID
    public_key: Optional[PublicKey] = None
    nonce: str


# =====================================================================
# FEDERATED MESSAGES
# =====================================================================

class FederatedMessage(SignedModel):
    """Cross-server message, signed by the sending server."""
    KIND = "message"
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    message_type: Literal["pager", "location", "ai_to_ai"] = "pager"
    from_address: str
    to_address: str
    content: str = Field(max_length=10000)
    priority: int = Field(default=0, ge=0, le=2, description="0=normal, 1=high, 2=urgent")
    timestamp: str = Field(default_factory=now_iso)
    location: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("location")
    @classmethod
    def validate_location_size(cls, v):
        if v is None:
            return v
        return _validate_json_size(v, MAX_LOCATION_BYTES, "location")

    @field_validator("metadata")
    @classmethod
    def validate_metadata_size(cls, v):
        return _validate_json_size(v, MAX_METADATA_BYTES, "metadata")

    @field_validator("from_address", "to_address")
    @classmethod
    def validate_address_format(cls, v):
        user, _, domain = v.partition("@")
        if not user or not domain:
            raise ValueError(f"Address must be in user@domain format, got: {v}")
        return v.lower()


class MessageAcknowledgment(SignedModel):
    """Recipient server's signed delivery outcome for a message."""
    KIND = "ack"
    ack_type: Literal["message_received", "message_failed"]
    message_id: str
    status: Literal["delivered", "rejected"]
    recipient_server: str
    timestamp: str = Field(default_factory=now_iso)
    error_message: Optional[str] = None
