"""
This server's federation identity: name, permanent UUID, endpoint and Ed25519 key.
"""

import logging
import os
import uuid
from typing import TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto
from .models import IdentityRevocation, KeyRotation, ServerAnnouncement, SignedModel, now_iso
from .secrets import load_config, load_private_key, save_private_key
from .sqlite_client import SQLiteClient

logger = logging.getLogger(__name__)

M = TypeVar("M", bound=SignedModel)


class Identity:
    """Signs protocol messages as this server."""

    def __init__(self, server_id: str, server_uuid: str, endpoint: str, private_key: Ed25519PrivateKey):
        self.server_id = server_id
        self.server_uuid = server_uuid
        self.endpoint = endpoint.rstrip("/")
        self._private_key = private_key

    @property
    def public_key(self) -> str:
        return crypto.public_key_of(self._private_key)

    @classmethod
    def load_or_create(cls, db: SQLiteClient) -> "Identity":
        """Load the stored identity, generating one on first run."""
        endpoint = load_config("APP_URL")
        if not endpoint:
            raise RuntimeError("APP_URL is not configured")

        row = db.execute_single("SELECT server_id, server_uuid FROM lattice_identity WHERE id = 1")
        if row:
            identity = cls(row["server_id"], row["server_uuid"], endpoint, crypto.private_key_from_pem(load_private_key()))
            logger.info("Loaded identity %s (%s)", identity.server_id, identity.server_uuid)
            return identity

        server_uuid = str(uuid.uuid4())
        server_id = (os.getenv("LATTICE_DOMAIN") or load_config("DOMAIN") or f"lattice-{server_uuid[:8]}").lower()
        private_key = crypto.generate_private_key()
        save_private_key(crypto.private_key_to_pem(private_key))
        db.execute(
            "INSERT INTO lattice_identity (id, server_id, server_uuid, created_at) VALUES (1, ?, ?, ?)",
            (server_id, server_uuid, now_iso())
        )
        identity = cls(server_id, server_uuid, endpoint, private_key)
        logger.info("Created identity %s (%s) with key %s", server_id, server_uuid, identity.public_key)
        return identity

    def sign(self, model: M) -> M:
        model.sign(self._private_key)
        return model

    def announcement(self) -> ServerAnnouncement:
        return self.sign(ServerAnnouncement(
            server_uuid=self.server_uuid,
            server_id=self.server_id,
            public_key=self.public_key,
            endpoint=self.endpoint
        ))

    def rotate(self, reason: str = "scheduled") -> KeyRotation:
        """Replace our key. Returns the rotation, signed with the old key, for broadcast to peers."""
        new_key = crypto.generate_private_key()
        rotation = self.sign(KeyRotation(
            server_uuid=self.server_uuid,
            old_public_key=self.public_key,
            new_public_key=crypto.public_key_of(new_key),
            reason=reason
        ))
        save_private_key(crypto.private_key_to_pem(new_key))
        self._private_key = new_key
        logger.info("Rotated key %s -> %s", rotation.old_public_key, rotation.new_public_key)
        return rotation

    def revocation(self, reason: str) -> IdentityRevocation:
        return self.sign(IdentityRevocation(server_uuid=self.server_uuid, reason=reason))
