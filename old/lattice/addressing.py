"""Address parsing and canonicalization for Lattice identities."""

from __future__ import annotations

import re
from dataclasses import dataclass

NODE_ID_RE = re.compile(r"^lat_[a-z2-7]+$")


class AddressError(ValueError):
    """Raised when an address is malformed."""


@dataclass(frozen=True)
class LatticeAddress:
    """A parsed Lattice address.

    Both ``user@domain`` and ``user@lat_...`` forms are accepted locally.
    The canonical form uses the node ID.
    """

    username: str
    domain: str | None
    node_id: str | None

    @property
    def is_canonical(self) -> bool:
        return self.node_id is not None

    def to_canonical(self) -> str:
        if self.node_id is None:
            raise AddressError("address has no canonical node ID")
        return f"{self.username}@{self.node_id}"

    def to_human(self) -> str:
        if self.domain is not None:
            return f"{self.username}@{self.domain}"
        if self.node_id is not None:
            return f"{self.username}@{self.node_id}"
        raise AddressError("address has no display form")


def parse_address(address: str) -> LatticeAddress:
    """Parse a Lattice address.

    Accepts ``username@domain`` and ``username@lat_<node_id>``.
    """
    address = address.strip().lower()
    if "@" not in address:
        raise AddressError(f"address must contain '@': {address}")

    username, host = address.rsplit("@", 1)
    username = username.strip()
    host = host.strip()

    if not username:
        raise AddressError("username cannot be empty")
    if not host:
        raise AddressError("host cannot be empty")

    if NODE_ID_RE.match(host):
        return LatticeAddress(username=username, domain=None, node_id=host)

    # Validate minimal domain shape.
    if any(c in host for c in ":/@"):
        raise AddressError(f"invalid domain: {host}")
    if len(host) > 253:
        raise AddressError(f"domain too long: {host}")

    return LatticeAddress(username=username, domain=host, node_id=None)


def node_id_from_address(address: str) -> str | None:
    """Return the node ID if ``address`` is already canonical, else None."""
    try:
        parsed = parse_address(address)
    except AddressError:
        return None
    return parsed.node_id
