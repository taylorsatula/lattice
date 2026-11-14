"""Tests for SQLite storage, migrations, cache lifecycle, and repositories."""

from __future__ import annotations

import tempfile
from datetime import UTC
from pathlib import Path

import pytest

from lattice.storage.cache import initialize_cache_db
from lattice.storage.connection import open_connection
from lattice.storage.migrations import MigrationError, get_available_version, migrate
from lattice.storage.repositories import DomainPinRepository, PeerRepository


class TestMigrations:
    def test_migrate_fresh_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            version = migrate(db_path)
            assert version == get_available_version()

    def test_migrate_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            version = migrate(db_path)
            assert version == get_available_version()

    def test_migrate_refuses_newer_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            conn.execute("PRAGMA user_version = 999")
            conn.close()
            with pytest.raises(MigrationError):
                migrate(db_path)

    def test_migrate_creates_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_str:
            tmp = Path(tmp_str)
            db_path = tmp / "durable.db"
            # Create the raw file without migrations so the first migration has
            # data worth backing up.
            conn = open_connection(db_path)
            conn.execute("CREATE TABLE preexisting (id INTEGER PRIMARY KEY, data TEXT)")
            conn.execute("INSERT INTO preexisting (data) VALUES (?)", ("preserve me",))
            conn.close()

            migrate(db_path)

            backups = list(tmp.glob("*-pre-migration-*"))
            assert len(backups) == 1


class TestCacheLifecycle:
    def test_initialize_creates_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cache.db"
            conn = initialize_cache_db(db_path)
            try:
                row = conn.execute(
                    "SELECT schema_hash FROM schema_version WHERE version = 1"
                ).fetchone()
                assert row is not None
                assert len(row["schema_hash"]) == 32
            finally:
                conn.close()

    def test_initialize_recreates_on_schema_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "cache.db"
            conn = initialize_cache_db(db_path)
            try:
                conn.execute("UPDATE schema_version SET schema_hash = ?", ("wrong",))
            finally:
                conn.close()

            conn2 = initialize_cache_db(db_path)
            try:
                row = conn2.execute(
                    "SELECT schema_hash FROM schema_version WHERE version = 1"
                ).fetchone()
                assert row is not None
                assert row["schema_hash"] != "wrong"
            finally:
                conn2.close()


class TestDomainPinRepository:
    def test_upsert_and_get(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                repo.upsert(
                    domain="example.com",
                    node_id="lat_abc123",
                    root_public_key="pk123",
                    operational_certificate={"seq": 1},
                    endpoints={"messages": "https://example.com/messages"},
                )
                result = repo.get("example.com")
                assert result is not None
                assert result["node_id"] == "lat_abc123"
                assert result["operational_certificate"] == {"seq": 1}
            finally:
                conn.close()

    def test_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                repo.upsert(
                    domain="example.com",
                    node_id="lat_abc123",
                    root_public_key="pk123",
                    operational_certificate={"seq": 1},
                    endpoints={"messages": "https://example.com/messages"},
                )
                repo.delete("example.com")
                assert repo.get("example.com") is None
            finally:
                conn.close()


class TestPeerRepository:
    def test_ensure_root_history_and_upsert_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = PeerRepository(conn)
                from datetime import datetime

                repo.ensure_root_history("lat_abc123", "pk123", datetime.now(UTC))
                repo.upsert_peer(
                    "lat_abc123",
                    state="candidate",
                    domain="example.com",
                    current_certificate_sequence=1,
                    endpoints={"messages": "https://example.com/messages"},
                )
                peer = repo.get_peer("lat_abc123")
                assert peer is not None
                assert peer["state"] == "candidate"
            finally:
                conn.close()


class TestJSONTextPreservation:
    def test_json_looking_text_stored_as_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "durable.db"
            migrate(db_path)
            conn = open_connection(db_path)
            try:
                repo = DomainPinRepository(conn)
                repo.upsert(
                    domain="example.com",
                    node_id="lat_abc123",
                    root_public_key='{"looks_like": "json"}',
                    operational_certificate={"seq": 1},
                    endpoints={"messages": "https://example.com/messages"},
                )
                result = repo.get("example.com")
                assert result is not None
                assert result["root_public_key"] == '{"looks_like": "json"}'
            finally:
                conn.close()
