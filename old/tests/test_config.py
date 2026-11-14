"""Tests for Lattice configuration parsing and validation."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from lattice.config import ConfigError, load_config, render_default_config


class TestLoadConfig:
    def test_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                render_default_config("example.com", "https://example.com"),
                encoding="utf-8",
            )
            config = load_config(path)
            assert config.domain == "example.com"
            assert config.public_base_url == "https://example.com"
            assert config.gossip_endpoint == "https://example.com/lattice/v1/gossip"
            assert config.messages_endpoint == "https://example.com/lattice/v1/messages"

    def test_missing_config(self) -> None:
        with pytest.raises(ConfigError):
            load_config("/nonexistent/config.toml")

    def test_missing_domain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                '[server]\npublic_base_url = "https://example.com"\n',
                encoding="utf-8",
            )
            with pytest.raises(ConfigError):
                load_config(path)

    def test_invalid_public_base_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                '[node]\ndomain = "example.com"\n[server]\npublic_base_url = "http://example.com"\n',
                encoding="utf-8",
            )
            with pytest.raises(ConfigError):
                load_config(path)

    def test_private_mode_requires_cidrs_or_suffixes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            text = render_default_config("example.com", "https://example.com").replace(
                'mode = "public"', 'mode = "private"'
            )
            path.write_text(text, encoding="utf-8")
            with pytest.raises(ConfigError):
                load_config(path)

    def test_private_mode_with_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            default = render_default_config("example.com", "https://example.com")
            text = default.replace(
                '[network]\nmode = "public"',
                '[network]\nmode = "private"\nprivate_suffixes = ["internal.example.com"]',
            )
            path.write_text(text, encoding="utf-8")
            config = load_config(path)
            assert config.network.mode == "private"
