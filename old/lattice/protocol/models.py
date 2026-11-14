"""Pydantic models for Lattice v1 protocol objects."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)

from lattice.encoding import b64url_decode
from lattice.protocol.constants import (
    MAX_MESSAGE_CONTENT_BYTES,
    MAX_MESSAGE_EXTENSION_BYTES,
    MAX_PEER_CARD_LIFETIME_SECONDS,
    MAX_TTL_SECONDS,
)


class ModelError(ValueError):
    """Raised when a protocol model fails validation."""


NODE_ID_RE = re.compile(r"^lat_[a-z2-7]+$")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _encode_size(text: str) -> int:
    return len(text.encode("utf-8"))


def _validate_node_id(value: str) -> str:
    if not value:
        raise ModelError("node ID cannot be empty")
    if not NODE_ID_RE.match(value):
        raise ModelError(f"invalid node ID: {value}")
    return value


def _validate_https_url(value: str, field_name: str) -> str:
    if not value.startswith("https://"):
        raise ModelError(f"{field_name} must use https scheme: {value}")
    if value.count("@") > 0:
        raise ModelError(f"{field_name} must not contain credentials: {value}")
    return value


class Endpoints(BaseModel):
    """Public federation endpoints advertised by a node."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    gossip: str
    messages: str

    @field_validator("gossip", "messages")
    @classmethod
    def _check_url(cls, v: str, info: Any) -> str:
        return _validate_https_url(v, str(info.field_name))


class OperationalCertificateModel(BaseModel):
    """Root-signed operational certificate model."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["operational_certificate"] = "operational_certificate"
    node_id: str
    operational_public_key: str
    valid_from: datetime
    valid_until: datetime
    sequence: int = Field(ge=1)
    signature: str

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("operational_public_key", "signature")
    @classmethod
    def _check_base64url(cls, v: str, info: Any) -> str:
        try:
            b64url_decode(v)
        except Exception as exc:
            raise ModelError(f"{info.field_name} is not valid base64url") from exc
        return v

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("timestamp must be timezone-aware")
        return v.astimezone(UTC)


class WellKnownDocument(BaseModel):
    """Document returned by ``GET /.well-known/lattice``."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["well_known"] = "well_known"
    node_id: str
    domain: str = Field(min_length=1, max_length=253)
    root_public_key: str
    operational_certificate: OperationalCertificateModel
    endpoints: Endpoints
    issued_at: datetime
    signature: str

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return v.lower()

    @field_validator("root_public_key", "signature")
    @classmethod
    def _check_base64url(cls, v: str, info: Any) -> str:
        try:
            b64url_decode(v)
        except Exception as exc:
            raise ModelError(f"{info.field_name} is not valid base64url") from exc
        return v

    @field_validator("issued_at")
    @classmethod
    def _check_issued_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("issued_at must be timezone-aware")
        return v.astimezone(UTC)


class PeerCard(BaseModel):
    """Gossip peer card model."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["peer_card"] = "peer_card"
    node_id: str
    domain: str = Field(min_length=1, max_length=253)
    root_public_key: str
    operational_certificate: OperationalCertificateModel
    endpoints: Endpoints
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    signature: str

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return v.lower()

    @field_validator("root_public_key")
    @classmethod
    def _check_root_public_key(cls, v: str) -> str:
        try:
            b64url_decode(v)
        except Exception as exc:
            raise ModelError("root_public_key is not valid base64url") from exc
        return v

    @field_validator("expires_at")
    @classmethod
    def _check_expiry(cls, v: datetime, info: Any) -> datetime:
        data = info.data
        issued_at = data.get("issued_at")
        if isinstance(issued_at, datetime):
            max_lifetime = timedelta(seconds=MAX_PEER_CARD_LIFETIME_SECONDS)
            if v > issued_at + max_lifetime:
                raise ModelError("peer card lifetime exceeds maximum")
        if v.tzinfo is None:
            raise ModelError("expires_at must be timezone-aware")
        return v.astimezone(UTC)

    @field_validator("issued_at")
    @classmethod
    def _check_issued_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("issued_at must be timezone-aware")
        return v.astimezone(UTC)


class Extension(BaseModel):
    """Optional namespaced message extension."""

    model_config = ConfigDict(extra="forbid")

    namespace: str = Field(min_length=1)
    data: Any

    @field_validator("namespace")
    @classmethod
    def _check_namespace(cls, v: str) -> str:
        if not v.startswith(("https://", "http://")):
            raise ModelError("extension namespace must be an absolute URI")
        return v


class Message(BaseModel):
    """Federated message model."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["message"] = "message"
    message_id: str = Field(min_length=1, max_length=128)
    from_address: str = Field(min_length=1, max_length=320)
    to_address: str = Field(min_length=1, max_length=320)
    content: str
    priority: Literal["normal", "high", "urgent"] = "normal"
    ttl_seconds: int = Field(default=86400, ge=1, le=MAX_TTL_SECONDS)
    extension: Extension | None = None
    timestamp: datetime
    signature: str

    @field_validator("content")
    @classmethod
    def _check_content_size(cls, v: str) -> str:
        if _encode_size(v) > MAX_MESSAGE_CONTENT_BYTES:
            raise ModelError(f"content exceeds {MAX_MESSAGE_CONTENT_BYTES} bytes")
        return v

    @field_validator("extension")
    @classmethod
    def _check_extension_size(cls, v: Extension | None) -> Extension | None:
        if v is None:
            return v
        # Re-serialize to bound encoded JSON size.
        encoded = v.model_dump_json().encode("utf-8")
        if len(encoded) > MAX_MESSAGE_EXTENSION_BYTES:
            raise ModelError(f"extension exceeds {MAX_MESSAGE_EXTENSION_BYTES} bytes")
        return v

    @field_validator("timestamp")
    @classmethod
    def _check_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("timestamp must be timezone-aware")
        return v.astimezone(UTC)


class DeliveryMetadata(BaseModel):
    """Delivery metadata added by the receiving node."""

    model_config = ConfigDict(extra="forbid")

    received_at: datetime
    delivered_at: datetime
    delivery_node_id: str

    @field_validator("received_at", "delivered_at")
    @classmethod
    def _check_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("timestamp must be timezone-aware")
        return v.astimezone(UTC)


class WebhookEnvelope(BaseModel):
    """Full signed webhook delivery envelope.

    Wraps the original signed message with delivery metadata and an
    additional signature from the delivering node so the receiver can
    verify both the message origin and the delivery provenance.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["webhook_envelope"] = "webhook_envelope"
    message: dict[str, Any]  # original signed Lattice message
    metadata: DeliveryMetadata
    signature: str  # operational cert signature over [message, metadata]

    @field_validator("signature")
    @classmethod
    def _check_base64url(cls, v: str, info: Any) -> str:
        try:
            b64url_decode(v)
        except Exception as exc:
            raise ModelError("signature is not valid base64url") from exc
        return v


class Receipt(BaseModel):
    """Durable-custody receipt model."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["receipt"] = "receipt"
    message_id: str = Field(min_length=1, max_length=128)
    node_id: str
    status: Literal["accepted", "rejected"]
    received_at: datetime
    signature: str

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("received_at")
    @classmethod
    def _check_received_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("received_at must be timezone-aware")
        return v.astimezone(UTC)


class Block(BaseModel):
    """Signed block declaration."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["block"] = "block"
    node_id: str
    blocked_node_id: str
    reason: str = Field(min_length=1, max_length=256)
    issued_at: datetime
    signature: str

    @field_validator("node_id", "blocked_node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("issued_at")
    @classmethod
    def _check_issued_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("issued_at must be timezone-aware")
        return v.astimezone(UTC)


class Transfer(BaseModel):
    """Domain/node transfer authorization."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["transfer"] = "transfer"
    domain: str = Field(min_length=1, max_length=253)
    old_node_id: str
    new_node_id: str
    issued_at: datetime
    signature: str
    new_signature: str

    @field_validator("old_node_id", "new_node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("domain")
    @classmethod
    def _check_domain(cls, v: str) -> str:
        return v.lower()

    @field_validator("issued_at")
    @classmethod
    def _check_issued_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("issued_at must be timezone-aware")
        return v.astimezone(UTC)


class Rotation(BaseModel):
    """Operational key rotation statement."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["rotation"] = "rotation"
    node_id: str
    old_operational_public_key: str
    new_operational_public_key: str
    old_certificate_sequence: int = Field(ge=1)
    new_certificate_sequence: int = Field(ge=1)
    issued_at: datetime
    signature: str
    old_signature: str
    new_signature: str

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        return _validate_node_id(v)

    @field_validator("old_operational_public_key", "new_operational_public_key")
    @classmethod
    def _check_public_key(cls, v: str, info: Any) -> str:
        try:
            b64url_decode(v)
        except Exception as exc:
            raise ModelError(f"{info.field_name} is not valid base64url") from exc
        return v

    @field_validator("issued_at")
    @classmethod
    def _check_issued_at(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ModelError("issued_at must be timezone-aware")
        return v.astimezone(UTC)
