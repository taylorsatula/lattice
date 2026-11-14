"""Tests for the Lattice operator CLI."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from lattice.cli import main


@pytest.fixture
def password() -> str:
    return "test-password-123"


class TestInit:
    def test_init_creates_config_and_identity(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            assert rc == 0
            assert config_path.exists()
            manifest_path = tmp_path / "identity.json"
            assert manifest_path.exists()
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            assert manifest["domain"] == "example.com"
            assert manifest["node_id"].startswith("lat_")
            assert (tmp_path / "root_key.pem").exists()
            assert (tmp_path / "operational_key.pem").exists()
            assert (tmp_path / "well-known.json").exists()

    def test_init_refuses_overwrite_without_force(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            config_path.write_text("existing", encoding="utf-8")
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            assert rc == 1


class TestConfigCheck:
    def test_config_check_valid(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            rc = main(["--config", str(config_path), "config"])
            assert rc == 0

    def test_config_check_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            config_path.write_text(
                '[node]\ndomain = "example.com"\n[server]\npublic_base_url = "http://example.com"\n',
                encoding="utf-8",
            )
            rc = main(["--config", str(config_path), "config"])
            assert rc == 1


class TestUpgrade:
    def test_upgrade_runs_migrations(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            rc = main(
                [
                    "--config",
                    str(config_path),
                    "upgrade",
                    "--state-dir",
                    str(tmp_path),
                    "--cache-dir",
                    str(tmp_path),
                ]
            )
            assert rc == 0
            assert (tmp_path / "lattice.durable.db").exists()
            assert (tmp_path / "lattice.cache.db").exists()


class TestStatus:
    def test_status_after_init(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            rc = main(
                [
                    "--config",
                    str(config_path),
                    "status",
                    "--state-dir",
                    str(tmp_path),
                    "--cache-dir",
                    str(tmp_path),
                ]
            )
            assert rc == 0

    def test_status_before_init(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.toml"
            rc = main(["--config", str(config_path), "status"])
            assert rc == 1


class TestTrustResetDomain:
    def test_reset_domain_removes_pin(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )

            # Create a pin directly, then remove it through the CLI.
            from lattice.storage.connection import open_connection
            from lattice.storage.migrations import migrate
            from lattice.storage.repositories import DomainPinRepository

            durable_path = tmp_path / "lattice.durable.db"
            migrate(durable_path)
            conn = open_connection(durable_path)
            try:
                DomainPinRepository(conn).upsert(
                    domain="peer.example.com",
                    node_id="lat_peer123",
                    root_public_key="pk",
                    operational_certificate={},
                    endpoints={"messages": "https://peer.example.com/messages"},
                )
            finally:
                conn.close()

            rc = main(
                [
                    "--config",
                    str(config_path),
                    "trust",
                    "reset-domain",
                    "--domain",
                    "peer.example.com",
                    "--state-dir",
                    str(tmp_path),
                ]
            )
            assert rc == 0

            conn = open_connection(durable_path)
            try:
                assert DomainPinRepository(conn).get("peer.example.com") is None
            finally:
                conn.close()

    def test_reset_domain_unknown_domain_succeeds(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            rc = main(
                [
                    "--config",
                    str(config_path),
                    "trust",
                    "reset-domain",
                    "--domain",
                    "unknown.example.com",
                    "--state-dir",
                    str(tmp_path),
                ]
            )
            assert rc == 0


class TestTransferStatements:
    @staticmethod
    def _init_node(config_path: Path, password: str) -> dict[str, Any]:
        with patch("lattice.cli.getpass.getpass", return_value=password):
            rc = main(
                [
                    "--config",
                    str(config_path),
                    "init",
                    "--domain",
                    "example.com",
                    "--public-base-url",
                    "https://example.com",
                ]
            )
        assert rc == 0
        manifest: dict[str, Any] = json.loads(
            config_path.parent.joinpath("identity.json").read_text()
        )
        return manifest

    def test_create_cosign_accept_round_trip(self, password: str) -> None:
        from types import SimpleNamespace

        from lattice.credentials import load_root_key
        from lattice.identity import sign_with_root
        from lattice.protocol.constants import MEDIA_TYPE
        from lattice.storage.connection import open_connection
        from lattice.storage.migrations import migrate
        from lattice.storage.repositories import DomainPinRepository

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path_a = root / "a" / "config.toml"
            path_b = root / "b" / "config.toml"
            manifest_a = self._init_node(path_a, password)
            manifest_b = self._init_node(path_b, password)
            transfer_path = root / "transfer.json"
            cert_a: dict[str, Any] = manifest_a["operational_certificate"]

            # Old root creates the statement.
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(path_a),
                        "keys",
                        "create-transfer",
                        "--domain",
                        "example.com",
                        "--new-node-id",
                        str(manifest_b["node_id"]),
                        "--output",
                        str(transfer_path),
                    ]
                )
            assert rc == 0
            transfer = json.loads(transfer_path.read_text(encoding="utf-8"))
            assert transfer["old_node_id"] == manifest_a["node_id"]
            assert "new_signature" not in transfer

            # New root co-signs.
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(path_b),
                        "keys",
                        "co-sign-transfer",
                        "--input",
                        str(transfer_path),
                    ]
                )
            assert rc == 0
            transfer = json.loads(transfer_path.read_text(encoding="utf-8"))
            assert "new_signature" in transfer

            # Build the new node's live well-known document for the domain.
            root_key_b = load_root_key(path_b.parent / "root_key.pem", password.encode())
            doc: dict[str, object] = {
                "kind": "well_known",
                "node_id": manifest_b["node_id"],
                "domain": "example.com",
                "root_public_key": manifest_b["root_public_key"],
                "operational_certificate": manifest_b["operational_certificate"],
                "endpoints": {
                    "gossip": "https://example.com/lattice/v1/gossip",
                    "messages": "https://example.com/lattice/v1/messages",
                },
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            doc = sign_with_root(root_key_b, doc, "well_known")

            class _WKTransport:
                def request(self, method: str, url: str, **kwargs: object) -> object:
                    return SimpleNamespace(
                        status=200,
                        data=json.dumps(doc).encode("utf-8"),
                        headers={"Content-Type": MEDIA_TYPE},
                        resolved_ip=None,
                    )

            # Seed a pre-transfer pin for node A.
            durable_path = root / "a" / "lattice.durable.db"
            migrate(durable_path)
            conn = open_connection(durable_path)
            try:
                DomainPinRepository(conn).upsert(
                    domain="example.com",
                    node_id=str(manifest_a["node_id"]),
                    root_public_key=str(manifest_a["root_public_key"]),
                    operational_certificate=cert_a,
                    endpoints={
                        "gossip": "https://example.com/lattice/v1/gossip",
                        "messages": "https://example.com/lattice/v1/messages",
                    },
                )
            finally:
                conn.close()

            with patch("lattice.cli.OutboundTransport", return_value=_WKTransport()):
                rc = main(
                    [
                        "--config",
                        str(path_a),
                        "trust",
                        "accept-transfer",
                        "--input",
                        str(transfer_path),
                        "--state-dir",
                        str(root / "a"),
                    ]
                )
            assert rc == 0

            conn = open_connection(durable_path)
            try:
                pin = DomainPinRepository(conn).get("example.com")
            finally:
                conn.close()
            assert pin is not None
            assert pin["node_id"] == manifest_b["node_id"]
            assert pin["root_public_key"] == manifest_b["root_public_key"]

    def test_accept_transfer_rejects_tampered_signature(self, password: str) -> None:
        from types import SimpleNamespace

        from lattice.credentials import load_root_key
        from lattice.identity import sign_with_root
        from lattice.protocol.constants import MEDIA_TYPE
        from lattice.storage.connection import open_connection
        from lattice.storage.migrations import migrate
        from lattice.storage.repositories import DomainPinRepository

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path_a = root / "a" / "config.toml"
            path_b = root / "b" / "config.toml"
            manifest_a = self._init_node(path_a, password)
            manifest_b = self._init_node(path_b, password)
            transfer_path = root / "transfer.json"
            cert_a: dict[str, Any] = manifest_a["operational_certificate"]

            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(path_a),
                        "keys",
                        "create-transfer",
                        "--domain",
                        "example.com",
                        "--new-node-id",
                        str(manifest_b["node_id"]),
                        "--output",
                        str(transfer_path),
                    ]
                )
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(path_b),
                        "keys",
                        "co-sign-transfer",
                        "--input",
                        str(transfer_path),
                    ]
                )

            # Tamper with the new root's signature.
            transfer = json.loads(transfer_path.read_text(encoding="utf-8"))
            transfer["new_signature"] = "A" * 86
            transfer_path.write_text(json.dumps(transfer), encoding="utf-8")

            root_key_b = load_root_key(path_b.parent / "root_key.pem", password.encode())
            doc: dict[str, object] = {
                "kind": "well_known",
                "node_id": manifest_b["node_id"],
                "domain": "example.com",
                "root_public_key": manifest_b["root_public_key"],
                "operational_certificate": manifest_b["operational_certificate"],
                "endpoints": {
                    "gossip": "https://example.com/lattice/v1/gossip",
                    "messages": "https://example.com/lattice/v1/messages",
                },
                "issued_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            doc = sign_with_root(root_key_b, doc, "well_known")

            class _WKTransport:
                def request(self, method: str, url: str, **kwargs: object) -> object:
                    return SimpleNamespace(
                        status=200,
                        data=json.dumps(doc).encode("utf-8"),
                        headers={"Content-Type": MEDIA_TYPE},
                        resolved_ip=None,
                    )

            durable_path = root / "a" / "lattice.durable.db"
            migrate(durable_path)
            conn = open_connection(durable_path)
            try:
                DomainPinRepository(conn).upsert(
                    domain="example.com",
                    node_id=str(manifest_a["node_id"]),
                    root_public_key=str(manifest_a["root_public_key"]),
                    operational_certificate=cert_a,
                    endpoints={
                        "gossip": "https://example.com/lattice/v1/gossip",
                        "messages": "https://example.com/lattice/v1/messages",
                    },
                )
            finally:
                conn.close()

            with patch("lattice.cli.OutboundTransport", return_value=_WKTransport()):
                rc = main(
                    [
                        "--config",
                        str(path_a),
                        "trust",
                        "accept-transfer",
                        "--input",
                        str(transfer_path),
                        "--state-dir",
                        str(root / "a"),
                    ]
                )
            assert rc == 1

            conn = open_connection(durable_path)
            try:
                pin = DomainPinRepository(conn).get("example.com")
            finally:
                conn.close()
            assert pin is not None
            assert pin["node_id"] == manifest_a["node_id"]


class TestContacts:
    @staticmethod
    def _init_node(config_path: Path, password: str) -> dict[str, Any]:
        with patch("lattice.cli.getpass.getpass", return_value=password):
            rc = main(
                [
                    "--config",
                    str(config_path),
                    "init",
                    "--domain",
                    "example.com",
                    "--public-base-url",
                    "https://example.com",
                ]
            )
        assert rc == 0
        manifest: dict[str, Any] = json.loads(
            config_path.parent.joinpath("identity.json").read_text()
        )
        return manifest

    def test_export_import_round_trip(self, password: str) -> None:
        from lattice.canonical import canonicalize, signature_preimage
        from lattice.crypto import SignatureError, verify
        from lattice.encoding import b64url_decode
        from lattice.identity import OperationalCertificate
        from lattice.storage.connection import open_connection
        from lattice.storage.migrations import migrate
        from lattice.storage.repositories import ContactRepository, DomainPinRepository

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            path_alice = tmp_path / "alice" / "config.toml"
            path_bob = tmp_path / "bob" / "config.toml"
            manifest_alice = self._init_node(path_alice, password)
            manifest_bob = self._init_node(path_bob, password)
            card_path = tmp_path / "alice.contact.json"

            # Alice exports her card (signed by her operational key).
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(path_alice),
                        "contacts",
                        "export",
                        "--username",
                        "alice",
                        "--display-name",
                        "Alice A",
                        "--output",
                        str(card_path),
                    ]
                )
            assert rc == 0
            card = json.loads(card_path.read_text(encoding="utf-8"))
            assert card["kind"] == "contact_card"
            assert card["address"] == f"alice@{manifest_alice['node_id']}"

            # Bob pins Alice's node directly, then imports the card.
            durable_path = tmp_path / "bob" / "lattice.durable.db"
            migrate(durable_path)
            conn = open_connection(durable_path)
            try:
                DomainPinRepository(conn).upsert(
                    domain="example.com",
                    node_id=str(manifest_alice["node_id"]),
                    root_public_key=str(manifest_alice["root_public_key"]),
                    operational_certificate=manifest_alice["operational_certificate"],
                    endpoints={
                        "gossip": "https://example.com/lattice/v1/gossip",
                        "messages": "https://example.com/lattice/v1/messages",
                    },
                )
            finally:
                conn.close()

            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(path_bob),
                        "contacts",
                        "import",
                        "--input",
                        str(card_path),
                        "--state-dir",
                        str(tmp_path / "bob"),
                    ]
                )
            assert rc == 0

            conn = open_connection(durable_path)
            try:
                row = ContactRepository(conn).get(str(manifest_alice["node_id"]), "alice")
            finally:
                conn.close()
            assert row is not None
            assert row["display_name"] == "Alice A"
            assert row["root_public_key"] == manifest_alice["root_public_key"]

            # The signature in the stored card verifies against the pinned
            # operational certificate chain.
            stored = json.loads(str(row["card_json"]))
            op_cert = OperationalCertificate.from_dict(manifest_alice["operational_certificate"])
            verify(
                op_cert.operational_public_key,
                signature_preimage(
                    "contact_card",
                    canonicalize({k: v for k, v in stored.items() if k != "signature"}),
                ),
                b64url_decode(stored["signature"]),
            )
            # Bob's own operational key does not verify the card.
            bob_cert = OperationalCertificate.from_dict(manifest_bob["operational_certificate"])
            with pytest.raises(SignatureError):
                verify(
                    bob_cert.operational_public_key,
                    signature_preimage(
                        "contact_card",
                        canonicalize({k: v for k, v in stored.items() if k != "signature"}),
                    ),
                    b64url_decode(stored["signature"]),
                )

    def test_import_fails_closed_without_pin(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            path_alice = tmp_path / "alice" / "config.toml"
            path_bob = tmp_path / "bob" / "config.toml"
            self._init_node(path_alice, password)
            self._init_node(path_bob, password)
            card_path = tmp_path / "alice.contact.json"

            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(path_alice),
                        "contacts",
                        "export",
                        "--username",
                        "alice",
                        "--output",
                        str(card_path),
                    ]
                )

            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(
                    [
                        "--config",
                        str(path_bob),
                        "contacts",
                        "import",
                        "--input",
                        str(card_path),
                        "--state-dir",
                        str(tmp_path / "bob"),
                    ]
                )
            assert rc == 1


class TestRotateOperational:
    def test_rotate_operational_key(self, password: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
                manifest_before = json.loads(
                    (tmp_path / "identity.json").read_text(encoding="utf-8")
                )
                seq_before = manifest_before["operational_certificate"]["sequence"]

                rc = main(
                    [
                        "--config",
                        str(config_path),
                        "keys",
                        "rotate-operational",
                    ]
                )
                assert rc == 0

                manifest_after = json.loads(
                    (tmp_path / "identity.json").read_text(encoding="utf-8")
                )
                seq_after = manifest_after["operational_certificate"]["sequence"]
                assert seq_after == seq_before + 1
                assert manifest_after["node_id"] == manifest_before["node_id"]
                well_known = json.loads((tmp_path / "well-known.json").read_text(encoding="utf-8"))
                assert well_known["node_id"] == manifest_before["node_id"]
                assert well_known["operational_certificate"]["sequence"] == seq_after

    def test_rotation_statement_is_three_signed(self, password: str) -> None:
        """docs/PROTOCOL.md §4.4: rotation carries root + old-op + new-op
        signatures over the same canonical object."""
        from lattice.canonical import canonicalize, signature_preimage
        from lattice.crypto import load_public_key_b64url, verify
        from lattice.encoding import b64url_decode

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            config_path = tmp_path / "config.toml"
            with patch("lattice.cli.getpass.getpass", return_value=password):
                main(
                    [
                        "--config",
                        str(config_path),
                        "init",
                        "--domain",
                        "example.com",
                        "--public-base-url",
                        "https://example.com",
                    ]
                )
            manifest_before = json.loads((tmp_path / "identity.json").read_text(encoding="utf-8"))
            with patch("lattice.cli.getpass.getpass", return_value=password):
                rc = main(["--config", str(config_path), "keys", "rotate-operational"])
            assert rc == 0

            rotation = json.loads((tmp_path / "rotation.json").read_text(encoding="utf-8"))
            assert rotation["kind"] == "rotation"
            assert rotation["node_id"] == manifest_before["node_id"]
            assert rotation["old_certificate_sequence"] == 1
            assert rotation["new_certificate_sequence"] == 2

            root_public_key = load_public_key_b64url(manifest_before["root_public_key"])
            old_public_key = load_public_key_b64url(rotation["old_operational_public_key"])
            new_public_key = load_public_key_b64url(rotation["new_operational_public_key"])

            def _preimage(obj: dict[str, object]) -> bytes:
                return signature_preimage("rotation", canonicalize(obj))

            # All three signatures cover the same bare object (see
            # tests/vectors/generate_vectors.py): root first, then each
            # operational key.
            bare = {
                k: v
                for k, v in rotation.items()
                if k not in ("signature", "old_signature", "new_signature")
            }
            verify(root_public_key, _preimage(bare), b64url_decode(rotation["signature"]))
            verify(old_public_key, _preimage(bare), b64url_decode(rotation["old_signature"]))
            verify(new_public_key, _preimage(bare), b64url_decode(rotation["new_signature"]))
