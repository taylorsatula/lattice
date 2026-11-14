"""Tests for network policy validation."""

from __future__ import annotations

import ipaddress

import pytest

from lattice.network_policy import NetworkPolicy, NetworkPolicyError


class TestPublicPolicy:
    def test_allows_public_ip(self) -> None:
        policy = NetworkPolicy.public()
        policy.validate_ip(ipaddress.ip_address("8.8.8.8"), "example.com")

    def test_rejects_loopback(self) -> None:
        policy = NetworkPolicy.public()
        with pytest.raises(NetworkPolicyError):
            policy.validate_ip(ipaddress.ip_address("127.0.0.1"), "example.com")

    def test_rejects_private(self) -> None:
        policy = NetworkPolicy.public()
        with pytest.raises(NetworkPolicyError):
            policy.validate_ip(ipaddress.ip_address("10.0.0.1"), "example.com")

    def test_rejects_link_local(self) -> None:
        policy = NetworkPolicy.public()
        with pytest.raises(NetworkPolicyError):
            policy.validate_ip(ipaddress.ip_address("169.254.1.1"), "example.com")


class TestPrivatePolicy:
    def test_requires_cidrs_or_suffixes(self) -> None:
        with pytest.raises(NetworkPolicyError):
            NetworkPolicy.private()

    def test_allows_matching_cidr(self) -> None:
        policy = NetworkPolicy.private(cidrs=["10.0.0.0/8"])
        policy.validate_ip(ipaddress.ip_address("10.0.0.1"), "host.internal")

    def test_allows_matching_suffix(self) -> None:
        policy = NetworkPolicy.private(suffixes=["internal.example.com"])
        policy.validate_ip(ipaddress.ip_address("8.8.8.8"), "host.internal.example.com")

    def test_rejects_non_matching(self) -> None:
        policy = NetworkPolicy.private(suffixes=["internal.example.com"])
        with pytest.raises(NetworkPolicyError):
            policy.validate_ip(ipaddress.ip_address("8.8.8.8"), "example.com")

    def test_hostname_allowed(self) -> None:
        policy = NetworkPolicy.private(suffixes=["internal.example.com"])
        assert policy.hostname_allowed("host.internal.example.com")
        assert not policy.hostname_allowed("example.com")
