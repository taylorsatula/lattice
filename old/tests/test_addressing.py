"""Tests for Lattice address parsing."""

from __future__ import annotations

import pytest

from lattice.addressing import AddressError, parse_address


class TestParseAddress:
    def test_human_address(self) -> None:
        addr = parse_address("alice@example.com")
        assert addr.username == "alice"
        assert addr.domain == "example.com"
        assert addr.node_id is None
        assert not addr.is_canonical
        assert addr.to_human() == "alice@example.com"

    def test_canonical_address(self) -> None:
        addr = parse_address("alice@lat_abc234")
        assert addr.username == "alice"
        assert addr.domain is None
        assert addr.node_id == "lat_abc234"
        assert addr.is_canonical
        assert addr.to_canonical() == "alice@lat_abc234"
        assert addr.to_human() == "alice@lat_abc234"

    def test_lowercases_input(self) -> None:
        addr = parse_address("Alice@Example.COM")
        assert addr.username == "alice"
        assert addr.domain == "example.com"

    def test_rejects_missing_at(self) -> None:
        with pytest.raises(AddressError):
            parse_address("alice")

    def test_rejects_empty_username(self) -> None:
        with pytest.raises(AddressError):
            parse_address("@example.com")

    def test_rejects_empty_host(self) -> None:
        with pytest.raises(AddressError):
            parse_address("alice@")

    def test_rejects_invalid_domain_chars(self) -> None:
        with pytest.raises(AddressError):
            parse_address("alice@https://example.com")
