"""Tests for SSRF-safe outbound transport."""

from __future__ import annotations

import pytest

from lattice.network_policy import NetworkPolicy
from lattice.transport import OutboundTransport, TransportError


class TestOutboundTransport:
    def test_rejects_http_url(self) -> None:
        transport = OutboundTransport(NetworkPolicy.public())
        with pytest.raises(TransportError):
            transport.request("GET", "http://example.com/")

    def test_rejects_internal_host_without_resolution(self) -> None:
        transport = OutboundTransport(NetworkPolicy.public())
        # This will attempt DNS resolution; localhost should resolve and be rejected.
        with pytest.raises(TransportError):
            transport.request("GET", "https://localhost/")

    def test_rejects_private_ip_url(self) -> None:
        transport = OutboundTransport(NetworkPolicy.public())
        # Direct IP URLs are also validated.
        with pytest.raises(TransportError):
            transport.request("GET", "https://10.0.0.1/")
