"""Durable schema migration fixtures and upgrade tests."""

from __future__ import annotations

import sqlite3
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from lattice.storage.migrations import (
    MigrationError,
    get_available_version,
    migrate,
)


def _fixture_paths() -> list[Path]:
    repo = Path(__file__).resolve().parents[1]
    return sorted((repo / "tests" / "fixtures" / "durable_schema").glob("v*.sql"))


@pytest.fixture
def tmp_db() -> Generator[Path, None, None]:
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp) / "durable.db"


class TestSchemaUpgrades:
    def test_migrate_from_empty_database(self, tmp_db: Path) -> None:
        """A fresh empty database migrates to the current schema."""
        expected = get_available_version()
        version = migrate(tmp_db)
        assert version == expected
        conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True)
        try:
            user_version = conn.execute("PRAGMA user_version").fetchone()[0]
            assert user_version == expected
        finally:
            conn.close()

    def test_migrate_refuses_newer_database(self, tmp_db: Path) -> None:
        """A database newer than the binary is rejected."""
        conn = sqlite3.connect(tmp_db)
        try:
            conn.execute("PRAGMA user_version = 99")
        finally:
            conn.close()
        with pytest.raises(MigrationError, match="newer"):
            migrate(tmp_db)

    def test_migrate_from_released_fixtures_is_idempotent(self, tmp_db: Path) -> None:
        """Applying any released schema fixture and then migrating is a no-op."""
        for fixture in _fixture_paths():
            with tempfile.TemporaryDirectory() as tmp:
                db = Path(tmp) / "durable.db"
                conn = sqlite3.connect(db)
                try:
                    conn.executescript(fixture.read_text(encoding="utf-8"))
                finally:
                    conn.close()
                expected = get_available_version()
                assert migrate(db) == expected
                assert migrate(db) == expected

    def test_migration_creates_backup(self, tmp_db: Path) -> None:
        """A pre-migration backup is created when the database is non-empty."""
        conn = sqlite3.connect(tmp_db)
        try:
            conn.execute("PRAGMA user_version = 0")
            conn.execute("CREATE TABLE old_table (x TEXT)")
            conn.execute("INSERT INTO old_table VALUES ('data')")
            conn.commit()
        finally:
            conn.close()
        expected = get_available_version()
        version = migrate(tmp_db)
        assert version == expected
        backups = list(tmp_db.parent.glob("*-pre-migration-*.db"))
        assert len(backups) == 1
        assert backups[0].stat().st_size > 0
