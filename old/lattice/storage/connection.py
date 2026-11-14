"""SQLite connection setup for durable and cache databases."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, Self


class StorageError(RuntimeError):
    """Raised for storage layer failures."""


DEFAULT_BUSY_TIMEOUT_MS = 5000


def _json_dumps(value: Any) -> str:
    """Serialize a value to compact JSON text."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _json_loads(data: bytes) -> Any:
    """Deserialize JSON bytes, returning plain Python values."""
    return json.loads(data.decode("utf-8"))


class _LockedConnection(sqlite3.Connection):
    """SQLite connection with a reentrant lock for cross-thread sharing.

    Python's ``sqlite3`` module by default forbids using a connection from a
    thread other than the one that created it. This subclass disables that
    restriction and adds a coarse reentrant lock so a single connection can
    safely be shared by Uvicorn's worker thread pool and the runtime's
    background executors.

    Individual ``execute``/``commit``/``rollback`` calls take the lock, and
    ``__enter__``/``__exit__`` additionally hold it across a whole ``with``
    transaction block: without that, thread B's failing ``with self._conn:``
    block would roll back thread A's uncommitted DML, and a normal with-exit
    would commit another thread's half-finished block. The reentrant lock
    also keeps nested ``with`` blocks (e.g. ``get_peer`` calling itself)
    safe.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._lattice_lock = threading.RLock()

    def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
        with self._lattice_lock:
            return super().execute(sql, parameters)

    def executemany(self, sql: str, parameters: Any) -> sqlite3.Cursor:
        with self._lattice_lock:
            return super().executemany(sql, parameters)

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        with self._lattice_lock:
            return super().executescript(sql_script)

    def commit(self) -> None:
        with self._lattice_lock:
            super().commit()

    def rollback(self) -> None:
        with self._lattice_lock:
            super().rollback()

    def __enter__(self) -> Self:
        # Hold the lock across the whole transaction block so concurrent
        # threads cannot interleave DML into (or roll back / prematurely
        # commit) another thread's in-flight transaction.
        self._lattice_lock.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> Literal[False]:
        try:
            # Commit/rollback under the lock acquired in __enter__. The C-level
            # super() calls matter: Connection.__exit__ would otherwise bypass
            # the Python-level commit/rollback overrides entirely.
            if exc_type is None:
                super().commit()
            else:
                super().rollback()
        finally:
            self._lattice_lock.release()
        return False


def configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Apply standard Lattice pragmas to a SQLite connection.

    - Enables foreign keys.
    - Sets WAL journal mode (best-effort; some platforms may ignore).
    - Sets a busy timeout so writers briefly wait rather than erroring.
    - Registers JSON conversion helpers.
    """
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute(f"PRAGMA busy_timeout = {DEFAULT_BUSY_TIMEOUT_MS}")
    conn.row_factory = sqlite3.Row

    sqlite3.register_adapter(dict, _json_dumps)
    sqlite3.register_adapter(list, _json_dumps)
    sqlite3.register_converter("JSON", _json_loads)

    return conn


def open_connection(path: Path | str) -> sqlite3.Connection:
    """Open a SQLite connection at ``path`` and configure it.

    The path's parent directories are created if they do not exist.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        detect_types=sqlite3.PARSE_DECLTYPES,
        factory=_LockedConnection,
        check_same_thread=False,
    )
    return configure_connection(conn)


def execute_script(conn: sqlite3.Connection, script: str) -> None:
    """Execute a SQL script as a single atomic transaction.

    ``executescript`` commits any pending transaction first and then runs the
    script with no further transaction control, so a mid-script failure
    would otherwise leave earlier statements durably committed (sqlite3 only
    auto-begins for DML, not DDL). Wrapping the script in an explicit
    BEGIN/COMMIT keeps every statement — including the schema version bump
    — in one transaction, which the connection context manager rolls back
    completely if any statement fails.
    """
    with conn:
        conn.executescript(f"BEGIN;\n{script}\nCOMMIT;")
