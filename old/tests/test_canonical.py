"""Tests for strict JSON parsing and RFC 8785 canonicalization."""

from __future__ import annotations

import pytest

from lattice.canonical import JSONParseError, canonicalize, strict_json_loads


class TestStrictJsonLoads:
    def test_rejects_duplicate_keys(self) -> None:
        with pytest.raises(JSONParseError):
            strict_json_loads('{"a": 1, "a": 2}')

    def test_rejects_nan(self) -> None:
        with pytest.raises(JSONParseError):
            strict_json_loads("NaN")

    def test_rejects_infinity(self) -> None:
        with pytest.raises(JSONParseError):
            strict_json_loads("Infinity")

    def test_rejects_negative_infinity(self) -> None:
        with pytest.raises(JSONParseError):
            strict_json_loads("-Infinity")

    def test_rejects_invalid_utf8(self) -> None:
        with pytest.raises(JSONParseError):
            strict_json_loads(b"\xff\xfe")

    def test_accepts_valid_json(self) -> None:
        result = strict_json_loads('{"b": 2, "a": 1}')
        assert result == {"b": 2, "a": 1}


class TestCanonicalize:
    def test_sorts_keys(self) -> None:
        assert canonicalize({"b": 2, "a": 1}) == b'{"a":1,"b":2}'

    def test_normalizes_negative_zero(self) -> None:
        assert canonicalize({"x": -0.0}) == b'{"x":0}'

    def test_preserves_unicode(self) -> None:
        assert canonicalize({"é": "café"}) == '{"é":"café"}'.encode()
