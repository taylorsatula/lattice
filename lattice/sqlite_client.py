"""
SQLite database client.

Queries use native SQLite parameters (`?` or `:name`). JSON columns are
stored as TEXT and decoded by callers.
"""

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

Params = Union[Dict[str, Any], Sequence[Any], None]

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


class SQLiteClient:
    """SQLite database client for Lattice."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("LATTICE_DB_PATH", "lattice.db")
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_PATH.read_text())
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _run(self, query: str, params: Params) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            # Fetch before commit: SQLite holds RETURNING locks until rows are read.
            rows = [dict(row) for row in conn.execute(query, params or ()).fetchall()]
            conn.commit()
            return rows
        finally:
            conn.close()

    def execute(self, query: str, params: Params = None) -> None:
        """Execute a statement that returns nothing."""
        self._run(query, params)

    def execute_query(self, query: str, params: Params = None) -> List[Dict[str, Any]]:
        """Execute a query (or a statement with RETURNING) and return all rows."""
        return self._run(query, params)

    def execute_single(self, query: str, params: Params = None) -> Optional[Dict[str, Any]]:
        """Execute a query (or a statement with RETURNING) and return the first row."""
        rows = self._run(query, params)
        return rows[0] if rows else None
