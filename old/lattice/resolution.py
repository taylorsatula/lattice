"""Well-known resolution, durable pinning, and domain binding for Lattice."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lattice.addressing import parse_address
from lattice.canonical import strict_json_loads
from lattice.encoding import b64url_decode
from lattice.identity import (
    OperationalCertificate,
    RootIdentity,
    derive_node_id,
    verify_with_root,
)
from lattice.network_policy import NetworkPolicyError
from lattice.protocol.models import WellKnownDocument
from lattice.storage.repositories import DomainPinRepository, RepositoryError
from lattice.transport import OutboundTransport, TransportError


class ResolutionError(ValueError):
    """Raised when well-known resolution or pinning fails."""


class WellKnownResolver:
    """Resolve ``https://domain/.well-known/lattice`` and manage durable pins."""

    def __init__(
        self,
        transport: OutboundTransport,
        repository: DomainPinRepository,
    ) -> None:
        self._transport = transport
        self._repository: DomainPinRepository = repository

    def resolve_with_ip(self, domain: str) -> tuple[dict[str, Any], str | None]:
        """Fetch and validate a well-known document for ``domain``.

        Returns ``(document, resolved_ip)`` where ``resolved_ip`` is the
        policy-validated IP the connection was made to (None when the
        transport does not report one). Raises ResolutionError on failure.
        """
        domain = domain.lower().strip()
        url = f"https://{domain}/.well-known/lattice"
        try:
            response = self._transport.request("GET", url)
        except (TransportError, NetworkPolicyError) as exc:
            raise ResolutionError(f"cannot fetch {url}: {exc}") from exc

        if response.status != 200:
            raise ResolutionError(f"well-known returned status {response.status} for {domain}")

        content_type = response.headers.get("Content-Type", "")
        if "application/vnd.lattice+json" not in content_type:
            raise ResolutionError(f"unexpected content type {content_type} for {domain}")

        try:
            data = strict_json_loads(response.data)
        except Exception as exc:
            raise ResolutionError(f"invalid well-known JSON for {domain}: {exc}") from exc

        if not isinstance(data, dict):
            raise ResolutionError(f"well-known JSON is not an object for {domain}")

        # Validate with Pydantic model for schema enforcement.
        try:
            doc = WellKnownDocument.model_validate(data)
        except Exception as exc:
            raise ResolutionError(f"well-known document invalid for {domain}: {exc}") from exc

        if doc.domain != domain:
            raise ResolutionError(
                f"well-known domain mismatch: expected {domain}, got {doc.domain}"
            )

        # Extract and verify root public key.
        try:
            root_public_key = b64url_decode(doc.root_public_key)
        except Exception as exc:
            raise ResolutionError(f"invalid root_public_key for {domain}: {exc}") from exc

        # Verify node ID derivation.
        try:
            root_key_obj = Ed25519PublicKey.from_public_bytes(root_public_key)
        except Exception as exc:
            raise ResolutionError(f"invalid root public key bytes for {domain}: {exc}") from exc
        derived_node_id = derive_node_id(root_key_obj)
        if derived_node_id != doc.node_id:
            raise ResolutionError(
                f"node ID mismatch for {domain}: expected {derived_node_id}, got {doc.node_id}"
            )

        # Verify root signature on the document.
        try:
            verify_with_root(root_key_obj, data, "well_known")
        except Exception as exc:
            raise ResolutionError(f"well-known signature invalid for {domain}: {exc}") from exc

        # Verify operational certificate. The whole block parses and checks
        # remote content, so every failure — including plain ValueError for
        # malformed key material and SignatureError, siblings of IdentityError
        # — must fail closed into ResolutionError per the resolve/pin contract.
        root_identity = RootIdentity(node_id=doc.node_id, public_key=root_key_obj)
        try:
            cert = OperationalCertificate.from_dict(
                doc.operational_certificate.model_dump(mode="json")
            )
            cert.verify(root_identity)
        except Exception as exc:
            raise ResolutionError(f"operational certificate invalid for {domain}: {exc}") from exc
        # Reject an already-expired (or not-yet-valid) certificate at
        # intake: an expired or de-authorized key must not be able to land
        # messages in durable custody via a freshly pinned document.
        if not cert.is_valid_at():
            raise ResolutionError(
                f"operational certificate for {domain} is expired or not yet valid"
            )

        resolved_ip: str | None = getattr(response, "resolved_ip", None)
        return data, resolved_ip

    def resolve(self, domain: str) -> dict[str, Any]:
        """Fetch and validate a well-known document for ``domain``.

        Returns the validated document dict. Raises ResolutionError on failure.
        """
        data, _resolved_ip = self.resolve_with_ip(domain)
        return data

    def pin(self, domain: str) -> dict[str, Any]:
        """Resolve ``domain`` and persist a durable pin.

        Returns the pinned document. A pin changes only via an accepted
        transfer statement or an explicit local reset, so re-resolution
        that advertises a different node ID is refused instead of silently
        rebinding the domain; the repository's compare-and-set refuses a
        certificate sequence rollback (see ``DomainPinRepository.upsert``).
        """
        data = self.resolve(domain)
        doc = WellKnownDocument.model_validate(data)
        existing = self._repository.get(domain)
        if existing is not None and existing.get("node_id") != doc.node_id:
            raise ResolutionError(
                f"refusing to re-pin {domain} to node {doc.node_id}: pinned to "
                f"{existing.get('node_id')} (accepted transfer or local reset required)"
            )
        try:
            self._repository.upsert(
                domain=domain,
                node_id=doc.node_id,
                root_public_key=doc.root_public_key,
                operational_certificate=doc.operational_certificate.model_dump(mode="json"),
                endpoints={
                    "gossip": doc.endpoints.gossip,
                    "messages": doc.endpoints.messages,
                },
            )
        except RepositoryError as exc:
            raise ResolutionError(f"cannot pin {domain}: {exc}") from exc
        return data

    def get_pin(self, domain: str) -> dict[str, Any] | None:
        """Return an existing durable pin, if any."""
        result: dict[str, Any] | None = self._repository.get(domain)
        return result

    def reset_domain(self, domain: str) -> None:
        """Remove the durable pin for ``domain``.

        Use after a domain transfer or to force re-resolution.
        """
        self._repository.delete(domain)


def resolve_address(
    address: str,
    resolver: WellKnownResolver,
) -> tuple[str, str]:
    """Resolve a human or canonical address to ``(username, node_id)``.

    If the address is already canonical, no network lookup is performed.
    Otherwise the domain is resolved and pinned.
    """
    parsed = parse_address(address)
    if parsed.node_id is not None:
        return parsed.username, parsed.node_id

    if parsed.domain is None:
        raise ResolutionError(f"address has no domain: {address}")

    pin: dict[str, Any] | None = resolver.get_pin(parsed.domain)
    if pin is None:
        resolver.pin(parsed.domain)
        pin = resolver.get_pin(parsed.domain)
    if pin is None:
        raise ResolutionError(f"could not pin domain: {parsed.domain}")

    node_id = pin.get("node_id")
    if not isinstance(node_id, str):
        raise ResolutionError(f"pin for {parsed.domain} has no node_id")

    return parsed.username, node_id
