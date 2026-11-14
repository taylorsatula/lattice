"""SSRF-safe synchronous HTTPS transport for Lattice federation."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import urllib3
from urllib3.util.url import parse_url

from lattice.network_policy import NetworkPolicy, NetworkPolicyError

DEFAULT_TIMEOUT = urllib3.Timeout(connect=10.0, read=30.0)


class TransportError(RuntimeError):
    """Raised when an outbound transport operation fails."""


@dataclass(frozen=True)
class FederationResponse:
    """Normalized response returned by :class:`OutboundTransport`.

    ``resolved_ip`` is the policy-validated IP address the connection was
    made to, surfaced so callers can record real network prefixes for
    topology diversity (docs/LOOSE_ENDS.md Phase 6).
    """

    status: int
    data: bytes
    headers: Mapping[str, str]
    resolved_ip: str | None = None


class OutboundTransport:
    """Pooled HTTPS client with resolved-address validation.

    Uses urllib3 to connect to a policy-validated IP address while preserving
    the original hostname for TLS SNI and certificate verification. This avoids
    the common TOCTOU bug where DNS is validated once and the transport then
    resolves the hostname independently.
    """

    def __init__(
        self,
        policy: NetworkPolicy,
        *,
        timeout: urllib3.Timeout | None = None,
        max_pool_size: int = 10,
    ) -> None:
        self._policy = policy
        self._timeout = timeout or DEFAULT_TIMEOUT

        ssl_context = ssl.create_default_context()
        if policy.mode == "private" and policy.private_ca_path:
            ca_path = Path(policy.private_ca_path)
            if not ca_path.exists():
                raise TransportError(f"private CA bundle not found: {ca_path}")
            ssl_context.load_verify_locations(str(ca_path))

        self._pool = urllib3.PoolManager(
            num_pools=max_pool_size,
            maxsize=max_pool_size,
            timeout=self._timeout,
            ssl_context=ssl_context,
        )

    def _resolve_and_validate(self, hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """Resolve ``hostname`` and return the first policy-allowed IP.

        ``getaddrinfo`` rejects bracketed IPv6 literals, but the URL parser
        keeps the brackets, so strip them before resolving. Address-family
        fallback is delegated to ``getaddrinfo`` with ``AF_UNSPEC``: results
        come back in the platform's reachability order and the first
        policy-allowed address of either family wins.
        """
        if hostname.startswith("[") and hostname.endswith("]"):
            hostname = hostname[1:-1]
        self._policy.hostname_allowed(hostname)
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TransportError(f"DNS resolution failed for {hostname}") from exc

        for _family, _, _, _, sockaddr in results:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            # Handle IPv4-mapped IPv6 addresses.
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            try:
                self._policy.validate_ip(ip, hostname)
            except NetworkPolicyError:
                continue
            return ip

        raise TransportError(f"no allowed IP address found for {hostname}")

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> FederationResponse:
        """Make an HTTP request with resolved-address validation.

        Only HTTPS URLs are supported. The hostname is resolved before
        connecting, the IP is validated against the network policy, and the
        original hostname is used for TLS certificate verification. The
        validated IP is returned in ``FederationResponse.resolved_ip``.

        Redirects are never followed: a 3xx response is returned to the
        caller instead of silently re-resolving and reconnecting to an
        unvalidated ``Location`` target.
        """
        try:
            parsed = parse_url(url)
        except urllib3.exceptions.HTTPError as exc:
            raise TransportError(f"invalid URL: {url}") from exc
        if parsed.scheme != "https":
            raise TransportError(f"only https URLs are allowed: {url}")
        hostname = parsed.host
        if hostname is None:
            raise TransportError(f"URL has no host: {url}")

        ip = self._resolve_and_validate(hostname)

        # Rewrite URL to use the validated IP while preserving path/query.
        # IPv6 address literals must be bracketed in the URL authority.
        port = parsed.port or 443
        authority = f"[{ip}]" if ip.version == 6 else str(ip)
        target_url = f"https://{authority}:{port}{parsed.request_uri}"

        request_headers = dict(headers) if headers else {}
        request_headers.setdefault("Host", hostname)
        request_headers.setdefault("Accept", "application/vnd.lattice+json; version=1")

        # urllib3 2.x only honours connection options (server_hostname,
        # assert_hostname) when the pool is constructed, not per request;
        # per-request extras surface as TypeError from _make_request. Bind
        # TLS trust at pool construction: the original hostname drives SNI
        # and certificate verification under check_hostname=True while the
        # socket connects to the validated IP.
        pool = self._pool.connection_from_url(
            target_url, pool_kwargs={"server_hostname": hostname}
        )
        try:
            response = pool.urlopen(
                method,
                parsed.request_uri,
                body=body,
                headers=request_headers,
                redirect=False,
                preload_content=True,
            )
        except urllib3.exceptions.HTTPError as exc:
            raise TransportError(f"HTTP request failed: {exc}") from exc
        if not isinstance(response, urllib3.BaseHTTPResponse):
            raise TransportError("unexpected response type from urllib3")
        return FederationResponse(
            status=int(response.status),
            data=response.data,
            headers=dict(response.headers.items()),
            resolved_ip=str(ip),
        )

    def close(self) -> None:
        self._pool.clear()
