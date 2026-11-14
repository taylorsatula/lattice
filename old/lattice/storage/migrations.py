"""Durable database migration runner using cumulative numbered SQL scripts."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from lattice.storage.connection import StorageError, execute_script, open_connection

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "migrations" / "durable"


class MigrationError(StorageError):
    """Raised when a migration cannot be applied safely."""


def _list_migrations() -> list[tuple[int, Path]]:
    """Return migration number/path pairs in ascending order."""
    migrations: list[tuple[int, Path]] = []
    if not MIGRATIONS_DIR.exists():
        return migrations
    for path in MIGRATIONS_DIR.iterdir():
        if path.suffix != ".sql":
            continue
        name = path.stem
        try:
            number = int(name.split("_", 1)[0])
        except ValueError:
            continue
        migrations.append((number, path))
    migrations.sort(key=lambda item: item[0])
    return migrations


def _current_user_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("PRAGMA user_version").fetchone()
    assert row is not None
    return int(row[0])


def _backup_path(db_path: Path, conn: sqlite3.Connection) -> Path:
    """Return the pre-migration backup path for ``db_path``.

    The digest must reflect logically-current content: the database runs in
    WAL mode, so committed rows can live only in the ``-wal`` sidecar, and
    hashing just the main file could silently reuse a stale backup. The WAL
    checkpoint folds committed frames into the main file before hashing.
    """
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    digest = hashlib.sha256(db_path.read_bytes()).hexdigest()[:16]
    suffix = db_path.suffix
    stem = db_path.stem
    return db_path.with_name(f"{stem}-pre-migration-{digest}{suffix}")


def migrate(
    db_path: Path | str,
    *,
    target: int | None = None,
    backup: bool = True,
) -> int:
    """Apply all missing durable migrations to ``db_path``.

    Args:
        db_path: Path to the durable SQLite database.
        target: Optional target schema version. If omitted, all available
            migrations are applied.
        backup: If True, create a pre-migration backup before writing.

    Returns:
        The final ``PRAGMA user_version``.

    Raises:
        MigrationError: If the database is newer than the target, or if a
            migration fails.
    """
    db_path = Path(db_path)
    migrations = _list_migrations()
    if not migrations:
        raise MigrationError("no durable migration scripts found")

    available_target = migrations[-1][0]
    if target is None:
        target = available_target
    elif target > available_target:
        raise MigrationError(
            f"target version {target} exceeds available migrations {available_target}"
        )

    conn = open_connection(db_path)
    try:
        current = _current_user_version(conn)
        if current > target:
            raise MigrationError(f"database user_version {current} is newer than target {target}")
        if current == target:
            return current

        integrity_ok = conn.execute("PRAGMA integrity_check").fetchone()
        if integrity_ok is None or integrity_ok[0] != "ok":
            raise MigrationError("database integrity check failed")

        fk_ok = conn.execute("PRAGMA foreign_key_check").fetchall()
        if fk_ok:
            raise MigrationError("foreign key check failed")

        pending = [(n, p) for n, p in migrations if current < n <= target]
        if not pending:
            return current

        if backup and db_path.exists() and db_path.stat().st_size > 0:
            backup_file = _backup_path(db_path, conn)
            if not backup_file.exists():
                # Connection.backup() copies a consistent snapshot that
                # includes WAL-resident committed state; shutil.copy2 of the
                # main file alone could miss it.
                backup_dest = sqlite3.connect(str(backup_file))
                try:
                    conn.backup(backup_dest)
                finally:
                    backup_dest.close()

        for number, migration_path in pending:
            script = migration_path.read_text(encoding="utf-8")
            try:
                execute_script(conn, script)
            except sqlite3.Error as exc:
                raise MigrationError(
                    f"migration {number} ({migration_path.name}) failed: {exc}"
                ) from exc
            applied = _current_user_version(conn)
            if applied != number:
                raise MigrationError(
                    f"migration {number} did not set user_version to {number} (got {applied})"
                )

        return _current_user_version(conn)
    finally:
        conn.close()


def get_available_version() -> int:
    """Return the highest available durable migration version."""
    migrations = _list_migrations()
    if not migrations:
        return 0
    return migrations[-1][0]
