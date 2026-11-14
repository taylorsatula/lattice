"""Lattice configuration schema and validation."""

from __future__ import annotations

import ipaddress
import math
import tomllib
from pathlib import Path
from typing import Any, Literal

from lattice.protocol.constants import MAX_TTL_SECONDS


class ConfigError(ValueError):
    """Raised when configuration is invalid or inconsistent."""


DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 1113
DEFAULT_WORKERS = 1
DEFAULT_MESSAGE_TTL_SECONDS = 86400
DEFAULT_MESSAGES_PER_MINUTE = 60
DEFAULT_GOSSIP_PER_MINUTE = 30
DEFAULT_GUARD_SLOTS = 3
DEFAULT_DISCOVERY_SLOTS = 2
DEFAULT_CANDIDATE_TTL_SECONDS = 86400
DEFAULT_ERASE_CONTENT_VALUE = "[erased]"

_NETWORK_MODE = Literal["public", "private"]


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    # Reject protocol, path, and userinfo.
    return not any(c in domain for c in ":/@")


def _is_https_url(url: str) -> bool:
    return url.startswith("https://") and "@" not in url


def _parse_cidr(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ConfigError(f"invalid CIDR: {text}") from exc


class GossipConfig:
    """Gossip and topology configuration."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.bootstrap: list[str] = []
        raw_bootstrap = data.get("bootstrap", [])
        if isinstance(raw_bootstrap, str):
            raw_bootstrap = [raw_bootstrap]
        for url in raw_bootstrap:
            if not _is_https_url(url):
                raise ConfigError(
                    f"gossip bootstrap must be an https URL without credentials: {url}"
                )
            self.bootstrap.append(url)

        self.guard_slots: int = int(data.get("guard_slots", DEFAULT_GUARD_SLOTS))
        self.discovery_slots: int = int(data.get("discovery_slots", DEFAULT_DISCOVERY_SLOTS))
        self.candidate_ttl_seconds: int = int(
            data.get("candidate_ttl_seconds", DEFAULT_CANDIDATE_TTL_SECONDS)
        )

        if self.guard_slots < 0 or self.discovery_slots < 0:
            raise ConfigError("guard_slots and discovery_slots must be non-negative")
        if self.candidate_ttl_seconds <= 0:
            raise ConfigError("candidate_ttl_seconds must be positive")


class WebhookConfig:
    """Loopback webhook configuration."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.url: str = data.get("url", "")
        if not self.url:
            raise ConfigError("webhook.url is required")
        if "@" in self.url:
            raise ConfigError("webhook.url must not contain credentials")
        self.bearer_credential_name: str = data.get("bearer_credential_name", "webhook_bearer")


class RateLimitConfig:
    """Authenticated per-peer rate limits."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.messages_per_minute: float = float(
            data.get("messages_per_minute", DEFAULT_MESSAGES_PER_MINUTE)
        )
        self.gossip_per_minute: float = float(
            data.get("gossip_per_minute", DEFAULT_GOSSIP_PER_MINUTE)
        )
        if not math.isfinite(self.messages_per_minute) or not math.isfinite(
            self.gossip_per_minute
        ):
            raise ConfigError("rate limits must be finite numbers")
        if self.messages_per_minute <= 0 or self.gossip_per_minute <= 0:
            raise ConfigError("rate limits must be positive")


class NetworkConfig:
    """Public/private network policy."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.mode: _NETWORK_MODE = data.get("mode", "public")
        if self.mode not in ("public", "private"):
            raise ConfigError("network.mode must be 'public' or 'private'")

        self.private_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        raw_cidrs = data.get("private_cidrs", [])
        for text in raw_cidrs:
            self.private_cidrs.append(_parse_cidr(text))

        self.private_suffixes: list[str] = []
        for text in data.get("private_suffixes", []):
            if not isinstance(text, str):
                raise ConfigError(f"network.private_suffixes entries must be strings: {text!r}")
            normalized = text.strip().lower().strip(".")
            if not normalized:
                raise ConfigError(f"network.private_suffixes entries must be non-empty: {text!r}")
            self.private_suffixes.append(normalized)
        self.private_ca_path: str | None = data.get("private_ca_path")

        if self.mode == "private" and not self.private_cidrs and not self.private_suffixes:
            raise ConfigError("private network mode requires private_cidrs or private_suffixes")


class Config:
    """Validated Lattice node configuration."""

    def __init__(self, data: dict[str, Any]) -> None:
        node = data.get("node", {})
        self.domain: str = node.get("domain", "")
        if not _is_valid_domain(self.domain):
            raise ConfigError("node.domain is required and must be a valid domain")

        server = data.get("server", {})
        self.bind_host: str = server.get("bind_host", DEFAULT_BIND_HOST)
        self.bind_port: int = int(server.get("bind_port", DEFAULT_BIND_PORT))
        self.workers: int = int(server.get("workers", DEFAULT_WORKERS))
        self.public_base_url: str = server.get("public_base_url", "")
        if not _is_https_url(self.public_base_url):
            raise ConfigError(
                "server.public_base_url is required and must be an https URL without credentials"
            )

        self.gossip = GossipConfig(data.get("gossip", {}))
        self.webhook = WebhookConfig(data.get("webhook", {}))
        self.rate_limit = RateLimitConfig(data.get("rate_limit", {}))
        self.network = NetworkConfig(data.get("network", {}))

        msg_config = data.get("message", {})
        self.default_ttl_seconds: int = int(
            msg_config.get("default_ttl_seconds", DEFAULT_MESSAGE_TTL_SECONDS)
        )
        if self.default_ttl_seconds <= 0 or self.default_ttl_seconds > MAX_TTL_SECONDS:
            raise ConfigError(
                f"message.default_ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
            )
        self.erase_content_value: str = msg_config.get(
            "erase_content_value", DEFAULT_ERASE_CONTENT_VALUE
        )

    @property
    def gossip_endpoint(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/lattice/v1/gossip"

    @property
    def messages_endpoint(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/lattice/v1/messages"

    @property
    def well_known_url(self) -> str:
        return f"{self.public_base_url.rstrip('/')}/.well-known/lattice"


def load_config(path: Path | str) -> Config:
    """Load and validate a TOML configuration file."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"configuration file not found: {path}")
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return Config(data)


def render_default_config(domain: str, public_base_url: str) -> str:
    """Render a default configuration file for a new node."""
    return f"""# Lattice v1 node configuration.
# This file is non-secret; all secrets are delivered via systemd credentials.

[node]
domain = "{domain}"

[server]
bind_host = "127.0.0.1"
bind_port = 1113
public_base_url = "{public_base_url}"
workers = 1

[gossip]
#bootstrap = ["https://bootstrap.example.com"]
guard_slots = 3
discovery_slots = 2
candidate_ttl_seconds = 86400

[webhook]
url = "http://127.0.0.1:8080/lattice/webhook"
bearer_credential_name = "webhook_bearer"

[rate_limit]
messages_per_minute = 60
gossip_per_minute = 30

[network]
mode = "public"

[message]
default_ttl_seconds = 86400
"""
