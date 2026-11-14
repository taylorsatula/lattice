"""Deployment artifact verification for Lattice v1."""

from __future__ import annotations

import configparser
import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def nginx_full_config() -> Generator[Path, None, None]:
    """Render the Nginx snippet inside a minimal valid configuration."""
    snippet = (REPO_ROOT / "deploy" / "lattice.nginx.conf").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        # Create dummy certificate files so nginx -t does not fail on paths.
        (tmp_path / "cert.pem").write_text("dummy", encoding="utf-8")
        (tmp_path / "key.pem").write_text("dummy", encoding="utf-8")
        config = tmp_path / "nginx.conf"
        cert = tmp_path / "cert.pem"
        key = tmp_path / "key.pem"
        adapted = snippet.replace("/etc/ssl/certs/example.com.fullchain.pem", str(cert)).replace(
            "/etc/ssl/private/example.com.key.pem", str(key)
        )
        config.write_text(
            f"""
worker_processes 1;
events {{ }}
http {{
    {adapted}
}}
""",
            encoding="utf-8",
        )
        yield config


class TestSystemdUnit:
    def test_service_unit_exists_and_parses(self) -> None:
        unit_path = REPO_ROOT / "deploy" / "lattice.service"
        assert unit_path.exists()
        # systemd unit files allow duplicate keys (e.g. multiple Environment=
        # lines), so disable strict parsing.
        parser = configparser.ConfigParser(strict=False)
        parser.read(unit_path, encoding="utf-8")
        assert "Unit" in parser.sections()
        assert "Service" in parser.sections()
        assert "Install" in parser.sections()

    def test_service_unit_uses_encrypted_credentials(self) -> None:
        unit_path = REPO_ROOT / "deploy" / "lattice.service"
        text = unit_path.read_text(encoding="utf-8")
        assert "LoadCredentialEncrypted=operational_key" in text
        assert "LoadCredentialEncrypted=webhook_bearer" in text
        assert "LoadCredentialEncrypted=admin_bearer" in text
        assert "LoadCredential=" not in text

    def test_service_unit_hardening(self) -> None:
        unit_path = REPO_ROOT / "deploy" / "lattice.service"
        text = unit_path.read_text(encoding="utf-8")
        assert "NoNewPrivileges=true" in text
        assert "ProtectSystem=strict" in text
        assert "ProtectHome=yes" in text
        assert "StateDirectory=lattice" in text
        assert "CacheDirectory=lattice" in text
        assert "UMask=0077" in text

    def test_service_unit_runs_serve_command(self) -> None:
        unit_path = REPO_ROOT / "deploy" / "lattice.service"
        text = unit_path.read_text(encoding="utf-8")
        assert "lattice serve --config /etc/lattice/config.toml" in text


class TestNginxConfig:
    def test_nginx_config_exists(self) -> None:
        path = REPO_ROOT / "deploy" / "lattice.nginx.conf"
        assert path.exists()

    def test_public_routes_exact(self) -> None:
        text = (REPO_ROOT / "deploy" / "lattice.nginx.conf").read_text(encoding="utf-8")
        assert "location = /.well-known/lattice" in text
        assert "location = /lattice/v1/gossip" in text
        assert "location = /lattice/v1/messages" in text

    def test_public_methods_restricted(self) -> None:
        text = (REPO_ROOT / "deploy" / "lattice.nginx.conf").read_text(encoding="utf-8")
        # Each public route should limit the allowed method.
        assert text.count("limit_except GET { deny all; }") >= 1
        assert text.count("limit_except POST { deny all; }") >= 2

    def test_body_size_limits(self) -> None:
        text = (REPO_ROOT / "deploy" / "lattice.nginx.conf").read_text(encoding="utf-8")
        assert "client_max_body_size 256k" in text
        assert "client_max_body_size 128k" in text

    def test_local_routes_loopback_only(self) -> None:
        text = (REPO_ROOT / "deploy" / "lattice.nginx.conf").read_text(encoding="utf-8")
        assert "location ^~ /lattice/v1/admin/" in text
        assert "location ^~ /lattice/v1/health/" in text
        assert text.count("allow 127.0.0.1;") >= 2
        assert text.count("deny all;") >= 2

    def test_nginx_syntax(self, nginx_full_config: Path) -> None:
        nginx = shutil.which("nginx")
        if nginx is None:
            pytest.skip("nginx not available")
        import subprocess

        result = subprocess.run(
            [nginx, "-t", "-c", str(nginx_full_config)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
