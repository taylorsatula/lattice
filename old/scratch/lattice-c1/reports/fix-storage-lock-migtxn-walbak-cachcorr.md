# Fix report — lattice/storage/{connection,migrations,cache}.py (rows LOCK 6b8f, MIGTXN hv81, WALBAK dqa1, CACHCORR kvbw)

## Changed
File: `lattice/storage/connection.py` (only region: `_LockedConnection`, `execute_script`)
- `_LockedConnection.__enter__`/`__exit__` (NEW): `__enter__` acquires the RLock so it spans the
  whole `with self._conn:` transaction; `__exit__` commits/rolls back via C-level `super()` calls
  under that same lock (bypassing-`__exit__` hazard OV-1), then releases in `finally`. Per-call
  locking on execute/executemany/executescript/commit/rollback kept unchanged; reads covered via
  per-call `execute` lock + transaction lock. Nested `with` blocks (get_peer recursion) safe via
  RLock reentrancy. +33/-3.
- `execute_script`: script text wrapped as `BEGIN;\n{script}\nCOMMIT;` so `executescript` runs the
  whole script — including the `user_version` bump — as one transaction; `with conn:` exit rolls
  back everything on mid-script failure (verified: PRAGMA journal_mode=WAL inside BEGIN is a no-op
  when already WAL, which `configure_connection` guarantees). Docstring rewritten. +12/-3.
- Imports: `TracebackType`, `Literal`, `Self` (typing/types).

File: `lattice/storage/migrations.py` (only regions: `_backup_path`, `migrate`)
- `_backup_path(db_path, conn)` (signature change; sole caller is `migrate`): runs
  `PRAGMA wal_checkpoint(TRUNCATE)` before hashing so the digest reflects logically-current
  committed content (WAL-resident rows folded into the main file) — fixes stale-backup dedup reuse.
- `migrate` backup block: `shutil.copy2` replaced with `sqlite3.Connection.backup()` to a fresh
  connection on the backup path — a consistent snapshot that includes WAL-resident committed state.
  Removed now-unused `import shutil`. +18/-6.

File: `lattice/storage/cache.py` (only region: `initialize_cache_db` incl. the `open_connection` call)
- The `open_connection` call and the `_current_schema_hash` probe are wrapped in
  `except sqlite3.DatabaseError` → `CacheError` naming the path, the underlying error, and the
  directive to remove the file and its `-wal`/`-shm` sidecars manually. Per the human binding
  directive: corrupt cache is NOT auto-recreated; the file is left in place. Schema-hash-mismatch
  recreate path (different hazard) unchanged. `_current_schema_hash` itself untouched.
  +14/-2 (plus docstring note).

## Exemplar mirrored
- `lattice/storage/repositories.py` `with self._conn:` idiom (e.g. `:155`) — lock acquisition is
  transparent to it; `StorageError`/`CacheError` contracts mirrored from
  `cache.py:CacheError` / `migrations.py:MigrationError`.

## Extensions beyond the enumerated set
- `initialize_cache_db` also wraps the `_current_schema_hash` call (not just `open_connection`):
  same hazard in the same named function — a file that opens but raises `DatabaseError` on the read
  must neither escape as a raw traceback nor flow into the auto-recreate path (binding directive).
- Removed `import shutil` in migrations.py — dead after the WALBAK fix; required for ruff F401.
- typeshed requires `__exit__ -> Literal[False]` for `sqlite3.Connection` overrides; the override
  returns `False` to match.

## Verification — EXECUTED
All commands run with the repo venv, `timeout`-bounded; hostile inputs; probe fixtures under
/tmp removed after the run.

1. LOCK: `/tmp/probe_lattice_fixes.py` (real `open_connection`, two threads sharing one
   connection). Hostile input: thread A commits `'accepted-202'` inside a `with conn:` block
   held open 0.5s; thread B enters a `with conn:` block in that window and fails mid-block
   (`INSERT INTO no_such_table`). Observed: B raised `OperationalError: no such table`, table
   rows after join = `['accepted-202']` — sibling committed write survives B's rollback. Also
   observed: a concurrent read blocks >0.3s while the transaction lock is held (lock spans the
   block, covers reads).
2. MIGTXN: `execute_script` with a script whose last statement calls a nonexistent function.
   Observed: raises `OperationalError: no such function`, `half_applied` table absent,
   `user_version` still 0 — nothing partially committed.
3. WALBAK: durable db with committed rows living only in the `-wal` sidecar (wal size 12392 bytes,
   main file without them); `migrate` applied migration 001 → backup
   `wal2-pre-migration-62e725721b16793e.db` opened and read back `custody-row-in-wal`.
   Second probe (`probe_wal_digest.py`): `_backup_path` digest identical with rows WAL-resident
   vs after checkpoint (same logical content → same name), and changes after a new commit —
   no stale dedup reuse.
4. CACHCORR: cache paths seeded with (a) garbage bytes, (b) a truncated SQLite header (20 bytes).
   Both: `initialize_cache_db` raised `CacheError` ("cache database at '<path>' is corrupt or not a
   SQLite database (...). It is not recreated automatically: remove ... and its '-wal'/'-shm'
   sidecars manually ...") and the corrupt file was preserved on disk (not auto-deleted).

Repo gates: `.venv/bin/ruff check lattice/` — "All checks passed!";
`.venv/bin/mypy --strict lattice/` — "Success: no issues found in 30 source files";
`timeout 600 .venv/bin/python -m pytest -q` — all dots, 1 skip, 0 failures.

## Found but not touched
- Working tree contains large pre-existing untracked/modified state (legacy `sqlite_client.py`,
  `runme.sh`, old tests deleted, whole `lattice/storage/` untracked) — other agents' wave output,
  left exactly as found.
- `Connection.backup()`/the checkpoint are not serialized by `_LockedConnection`'s RLock
  (`backup` is not overridden); both take their own SQLite-level locks and `migrate` is
  startup-only, so I did not add locking there.
- `lattice/runtime.py` pings connections with bare `execute("SELECT 1")` outside `with` blocks;
  now blocks behind any in-flight transaction lock by design (that serialization is the point of
  row LOCK).
