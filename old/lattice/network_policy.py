"""Public/private network policy and IP validation for outbound connections."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field


class NetworkPolicyError(ValueError):
    """Raised when a destination violates network policy."""


@dataclass(frozen=True)
class NetworkPolicy:
    """Policy for outbound federation connections.

    Public mode rejects private, loopback, link-local, reserved, and unspecified
    addresses. Private mode restricts destinations to configured CIDRs or DNS
    suffixes and validates the destination against a private CA bundle.
    """

    mode: str = "public"  # "public" or "private"
    private_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(
        default_factory=tuple
    )
    private_suffixes: tuple[str, ...] = field(default_factory=tuple)
    private_ca_path: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("public", "private"):
            raise NetworkPolicyError("mode must be 'public' or 'private'")
        normalized_suffixes = []
        for s in self.private_suffixes:
            normalized = s.strip().lower().strip(".")
            if not normalized:
                raise NetworkPolicyError(f"invalid private suffix: {s!r}")
            normalized_suffixes.append(normalized)
        object.__setattr__(self, "private_suffixes", tuple(normalized_suffixes))
        if self.mode == "private" and not self.private_cidrs and not self.private_suffixes:
            raise NetworkPolicyError("private mode requires private_cidrs or private_suffixes")

    @classmethod
    def public(cls) -> NetworkPolicy:
        return cls(mode="public")

    @classmethod
    def private(
        cls,
        cidrs: Iterable[str] = (),
        suffixes: Iterable[str] = (),
        ca_path: str | None = None,
    ) -> NetworkPolicy:
        return cls(
            mode="private",
            private_cidrs=tuple(ipaddress.ip_network(c, strict=False) for c in cidrs),
            private_suffixes=tuple(s.lower().strip(".") for s in suffixes),
            private_ca_path=ca_path,
        )

    def _is_internal(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )

    def validate_ip(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        hostname: str,
    ) -> None:
        """Validate a resolved IP against the policy.

        Raises:
            NetworkPolicyError: If the IP is not allowed.
        """
        if self.mode == "public":
            if self._is_internal(ip):
                raise NetworkPolicyError(
                    f"public mode rejects internal address {ip} for {hostname}"
                )
            return

        # Private mode: destination must match a configured CIDR or suffix.
        in_cidr = any(ip in network for network in self.private_cidrs)
        hostname_lower = hostname.lower().rstrip(".")
        in_suffix = any(
            hostname_lower == s or hostname_lower.endswith("." + s) for s in self.private_suffixes
        )
        if not in_cidr and not in_suffix:
            raise NetworkPolicyError(
                f"private mode rejects {hostname}/{ip}: not in configured CIDRs or suffixes"
            )

    def hostname_allowed(self, hostname: str) -> bool:
        """Return True if ``hostname`` is allowed by policy without resolving."""
        if self.mode == "public":
            return True
        hostname_lower = hostname.lower().rstrip(".")
        return any(
            hostname_lower == s or hostname_lower.endswith("." + s) for s in self.private_suffixes
        )
