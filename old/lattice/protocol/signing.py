"""High-level signing and verification helpers for Lattice protocol objects."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from lattice.identity import (
    IdentityError,
    OperationalCertificate,
    OperationalIdentity,
    RootIdentity,
    sign_with_root,
    verify_object,
    verify_with_root,
)


def sign_well_known(root_key: Ed25519PrivateKey, doc: dict[str, Any]) -> dict[str, Any]:
    """Sign a well-known document with the root key."""
    return sign_with_root(root_key, doc, "well_known")


def verify_well_known(root_identity: RootIdentity, doc: dict[str, Any]) -> None:
    """Verify the root signature on a well-known document."""
    verify_with_root(root_identity.public_key, doc, "well_known")


def sign_peer_card(op_identity: OperationalIdentity, card: dict[str, Any]) -> dict[str, Any]:
    """Sign a peer card with the operational key."""
    return op_identity.sign_object(card, "peer_card")


def verify_peer_card(
    card: dict[str, Any],
    certificate: OperationalCertificate,
    root_identity: RootIdentity,
) -> None:
    """Verify a peer card operational signature and its certificate.

    Mirrors ``RuntimeCoordinator.verify_gossip_sender_card``: the
    certificate signature is checked against the root identity first, then
    the certificate's validity window against the current time, so an
    expired or de-authorized operational key cannot authenticate a card.
    The card signature is verified over the received object dict.
    """
    certificate.verify(root_identity)
    if not certificate.is_valid_at():
        raise IdentityError("operational certificate is expired or not yet valid")
    verify_object(certificate.operational_public_key, card, "peer_card")


def sign_message(op_identity: OperationalIdentity, message: dict[str, Any]) -> dict[str, Any]:
    """Sign a federated message with the operational key."""
    return op_identity.sign_object(message, "message")


def verify_message(
    message: dict[str, Any],
    certificate: OperationalCertificate,
    root_identity: RootIdentity,
) -> None:
    """Verify a message operational signature and its certificate.

    Mirrors ``RuntimeCoordinator.verify_gossip_sender_card``: the
    certificate signature is checked against the root identity first, then
    the certificate's validity window against the current time, so an
    expired or de-authorized operational key cannot land a message in
    durable custody.
    """
    certificate.verify(root_identity)
    if not certificate.is_valid_at():
        raise IdentityError("operational certificate is expired or not yet valid")
    verify_object(certificate.operational_public_key, message, "message")


def sign_receipt(op_identity: OperationalIdentity, receipt: dict[str, Any]) -> dict[str, Any]:
    """Sign a durable-custody receipt with the operational key."""
    return op_identity.sign_object(receipt, "receipt")


def sign_block(op_identity: OperationalIdentity, block: dict[str, Any]) -> dict[str, Any]:
    """Sign a block declaration with the operational key."""
    return op_identity.sign_object(block, "block")


def verify_webhook_envelope(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> None:
    """Verify the delivering node's signature over a webhook envelope.

    The envelope is signed with the delivering node's operational key using
    the ``webhook_envelope`` kind, binding the original signed message and
    the delivery metadata into one preimage. Receivers verify this signature
    against the operational certificate advertised in the delivering domain's
    well-known document (see docs/LOOSE_ENDS.md Phase 7).
    """
    verify_object(public_key, envelope, "webhook_envelope")
