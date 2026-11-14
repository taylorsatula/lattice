"""Cache database lifecycle: create or recreate on schema mismatch."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from lattice.storage.connection import StorageError, execute_script, open_connection

CACHE_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "migrations" / "cache_schema.sql"


class CacheError(StorageError):
    """Raised when the cache database cannot be initialized."""


def _schema_hash() -> str:
    """Return a stable hash of the cache schema script."""
    text = CACHE_SCHEMA_PATH.read_text(encoding="utf-8")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _current_schema_hash(conn: sqlite3.Connection) -> str | None:
    try:
        row = conn.execute("SELECT schema_hash FROM schema_version WHERE version = 1").fetchone()
    except sqlite3.OperationalError:
        return None
    if row is None:
        return None
    return str(row[0])


def initialize_cache_db(db_path: Path | str) -> sqlite3.Connection:
    """Open the cache database, recreating it if the schema has changed.

    The cache database is disposable; all irreplaceable state belongs in the
    durable database. A schema hash mismatch is fixed by recreating the file,
    but a corrupt or non-SQLite file is NOT recreated automatically: it fails
    with a ``CacheError`` telling the operator to clear the file manually.
    """
    db_path = Path(db_path)
    expected_hash = _schema_hash()

    if db_path.exists():
        try:
            conn = open_connection(db_path)
            current_hash = _current_schema_hash(conn)
        except sqlite3.DatabaseError as exc:
            raise CacheError(
                f"cache database at '{db_path}' is corrupt or not a SQLite "
                f"database ({exc}). It is not recreated automatically: remove "
                f"'{db_path}' and its '-wal'/'-shm' sidecars manually, then "
                f"start again. The cache is disposable; durable state is "
                f"unaffected."
            ) from exc
        if current_hash == expected_hash:
            return conn
        conn.close()
        db_path.unlink()
        # Also remove WAL files if present.
        for suffix in ("-wal", "-shm"):
            extra = db_path.with_suffix(db_path.suffix + suffix)
            if extra.exists():
                extra.unlink()

    script = CACHE_SCHEMA_PATH.read_text(encoding="utf-8")
    conn = open_connection(db_path)
    try:
        execute_script(conn, script)
        with conn:
            conn.execute(
                "INSERT INTO schema_version (version, schema_hash) VALUES (?, ?)",
                (1, expected_hash),
            )
    except sqlite3.Error as exc:
        raise CacheError(f"failed to initialize cache database: {exc}") from exc
    return conn
