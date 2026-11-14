# hunt-c2 — connection & cache layer (lattice/storage/connection.py, lattice/storage/cache.py)

Pass type: blind hunter. Python 3.12.11. All files read end to end. Both files are untracked in
git (no prior history), so "changed or got worse" for E5 is evaluated against the current text
only. All demonstrations below were run in /tmp against the real classes and the real durable
schema via `migrate()`; nothing in the tree was modified.

## Findings

### 1. [H] — `with conn:` transactions on the shared connection cross-commit and cross-rollback across daemon threads

- Location: `lattice/storage/connection.py:_LockedConnection` (lock design), consumed by every
  `with self._conn:` block in `lattice/storage/repositories.py` (36 such blocks in tree), reached
  from `lattice/runtime.py:RuntimeCoordinator` (one `durable_conn` shared by 6 repositories,
  `runtime.py:190-196`) across three concurrent thread populations.
- Evidence: `"""adds a coarse reentrant lock around the main mutating operations so a single
  connection can safely be shared"""` — but the lock is acquired per *statement*
  (`with self._lattice_lock: return super().execute(...)`), while every repository mutator runs a
  multi-statement *transaction* via `with self._conn:`. The lock is released between the
  statements of a block, so a second thread's `with conn:` block executes inside the first
  thread's open transaction; whichever block exits first commits or rolls back **both** threads'
  writes.
- Trigger: PRODUCTION. RuntimeCoordinator shares `durable_conn` between (a) the Uvicorn/Starlette
  threadpool serving sync routes `POST /lattice/v1/messages` → `InboundMessageRepository.create`
  and `POST /lattice/v1/gossip` → cache/durable writes, (b) `_delivery_executor` threads running
  `outbound_delivery`/`webhook_delivery` ticks → `claim_pending`/`claim_for_webhook`, and (c)
  `_maintenance_executor` threads (`runtime.py:344-388`). The `outbound_delivery` tick (every
  `delivery_interval_seconds`) calls `claim_pending`, whose `with conn:` block spans an UPDATE +
  SELECT. If any other thread's `with conn:` block raises in that window — e.g. a peer retrying a
  duplicate message makes `InboundMessageRepository.create` fail with `IntegrityError` on the
  message_id PK — its `Connection.__exit__` rollback discards the claim's uncommitted UPDATE.
- Frequency: coincidence race, plausible in normal operation. The window is the interval between
  the statements of a `with conn:` block (sub-millisecond), but the populations overlap
  continuously (every inbound HTTP message, every gossip card, every scheduler tick writes on the
  same connection), and duplicate-message retries are a normal peer behavior that produces failing
  `with conn:` blocks. Demonstrated end to end (below), not asserted.
- Outcome: demonstrated with the real schema and repository SQL: worker 1's `claim_pending`
  returned message `m1` (it proceeds to deliver), while the concurrent block's rollback reverted
  the lease UPDATE — the row stayed `{'lease_owner': None, 'status': 'pending'}` and worker 2's
  `claim_pending` returned the same `m1` → **duplicate delivery of one outbound message**. The
  mirror variant: a `POST /lattice/v1/messages` handler's custody INSERT is rolled back by a
  concurrent failing block, `create` returns normally, and the route returns **202 with no durable
  custody row** (invariant 5 violation — accepted message silently lost). Third variant: a block
  exiting early commits another thread's half-finished multi-statement block (`add_block`,
  `upsert_peer`), persisting partial state its own rollback then cannot undo.
- Confidence: traced. Mechanism proven empirically twice: (T2) with real threads, a write made
  *while holding `_lattice_lock`* was discarded by another thread's failed `with conn:` block
  (rows: 0 after rollback); (T5) with the real `OutboundMessageRepository.claim_pending` SQL,
  deterministic interleave produced the double-claim above. Relation to E5 (KNOWN): this is the
  wider-reaching instance the assignment asks for — it does not depend on the `__exit__` lock
  bypass at all; even fully-lock-covered statements interleave inside each other's transactions,
  so the stated sharing contract is unenforceable by a per-statement lock. Reachability:
  production. Unproven component: frequency — the exact interleave is a race; no live daemon was
  run to observe it in the wild.
- Reproduction sketch (both run in /tmp, exit the repo tree untouched):
  - T2: threads A/B on one `open_connection()`; B inserts under `with conn2._lattice_lock:`;
    A's `with conn2:` block raises; B's committed-under-lock row is gone (COUNT = 0).
  - T5: real `migrate()` schema, real repo; interloper injected between `claim_pending`'s UPDATE
    and its commit fails with `sqlite3.IntegrityError` inside `with conn:` → claim returns `m1`,
    DB shows `pending`/no lease, second worker claims `m1` again.

### 2. [L] — Corrupt cache file crashes startup with a raw `sqlite3.DatabaseError` instead of recreating the disposable DB

- Location: `lattice/storage/cache.py:_current_schema_hash` / `initialize_cache_db`.
- Evidence: `except sqlite3.OperationalError: return None` — only `OperationalError` is treated
  as "schema absent"; a garbage or corrupt file makes the first statement raise
  `sqlite3.DatabaseError`, which is neither caught here nor by the `except sqlite3.Error` around
  the creation path (that only wraps the fresh-creation branch), and is not a `CacheError`
  despite the module's contract (`CacheError: "Raised when the cache database cannot be
  initialized"`).
- Trigger: PRODUCTION (daemon or `lattice init` startup, `cli.py:236` / `cli.py:703`) with a
  non-SQLite or corrupt file at the configured cache path — truncated by power loss/disk-full,
  or a stray file at the path.
- Frequency: environment-armed; no normal-operation cadence produces a corrupt cache file (WAL
  makes torn writes unlikely). Latent by the calibration's frequency rule.
- Outcome: verified (T3): `initialize_cache_db` on a garbage file raises
  `DatabaseError: file is not a database` out of the function. The documented
  "recreate on mismatch" self-healing never runs, `cli.py`'s `except CacheError` handlers don't
  match it, and startup stays broken until an operator manually deletes the file — for a database
  the module docstring declares "disposable".
- Confidence: traced (mechanism and trigger demonstrated; frequency ungrounded → latent).

### 3. [L] — Extensionless cache path makes the mismatch-recreate path crash with `ValueError: Invalid suffix`

- Location: `lattice/storage/cache.py:initialize_cache_db` (WAL sidecar cleanup).
- Evidence: `extra = db_path.with_suffix(db_path.suffix + suffix)` with `suffix = "-wal"` —
  `Path.with_suffix` requires the argument to start with a dot; when the configured cache filename
  has no extension (`Path("/var/lib/lattice/cache")`), `suffix` is `""` and
  `with_suffix("-wal")` raises `ValueError`.
- Trigger: PRODUCTION, GATED on a schema change: requires (a) operator-configured cache path
  with no `.` in the filename and (b) a schema-hash mismatch, i.e. startup after a cache schema
  edit — the exact scenario this branch exists to handle.
- Frequency: latent — two conditions must coincide; no in-tree default produces an extensionless
  cache path.
- Outcome: verified (T4): recreation aborts with `ValueError: Invalid suffix '-wal'` (not
  `CacheError`), leaving the old file deleted and no cache DB created — startup fails.
- Confidence: traced (mechanism demonstrated; frequency ungrounded → latent).

## Checked and clean

- **E5 KNOWN site, unchanged and not independently worse**: instrumented a `_LockedConnection`
  subclass with spy `commit`/`rollback`; a normally-exiting `with conn:` block called neither
  override (calls list empty), confirming `Connection.__exit__` still bypasses the Python
  overrides. Reported only its wider consequence (finding 1); the bare mechanism is not re-reported.
- **Lock override surface is complete for everything the tree calls**: `execute`,
  `executemany`, `executescript`, `commit`, `rollback` all hold `_lattice_lock`; the lock exists
  before `configure_connection` runs (set in `__init__` after `super().__init__`). The unoverridden
  mutating-surface class (`cursor()`, `backup`, `iterdump`, `create_function`, `load_extension`,
  `setconfig`, `set_progress_handler`, `create_collation`, `set_trace_callback`) is entirely
  unused in tree — enumeration command below returns zero hits.
- **No `conn.cursor()` bypass**: zero occurrences in the tree; all repository access goes through
  the overridden `Connection.execute`.
- **`configure_connection`**: `foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000`,
  `row_factory=Row`, JSON adapter/converter registration — applied before the connection is
  returned; adapter registration is process-global and idempotent; converter receives bytes and
  decodes correctly. No defect found.
- **`open_connection`**: parent-directory creation, `detect_types=PARSE_DECLTYPES`,
  `factory=_LockedConnection`, `check_same_thread=False` wiring is correct; `__init__` ordering
  gives the lock before any use.
- **`execute_script`**: `executescript`'s implicit pre-commit and the `with conn:` wrapper are
  single-threaded at every call site (CLI `init`, `migrate`, `initialize_cache_db` before the
  runtime starts) — no interleaving consequence reachable today.
- **cache.py happy paths**: matching hash returns the existing connection with no writes; a
  0-byte file is treated by SQLite as an empty DB → `OperationalError` ("no such table") →
  caught → recreate (verified in T4 setup); after `conn.close()` SQLite checkpoints and removes
  WAL sidecars, so the explicit `-wal`/`-shm` unlink is belt-and-braces, correct for paths with a
  suffix; partial `execute_script` failure self-heals on next start (no `schema_version` row →
  `OperationalError` → recreate); `schema_version` `CHECK (version = 1)` is consistent with the
  `WHERE version = 1` probe.
- **Timestamp-string expiry comparisons** in the cache lifecycle context: `_format_ts` emits
  zero-padded `YYYY-MM-DDTHH:MM:SSZ`, which is lexicographically order-consistent — no expiry
  boundary defect introduced by the storage layer.

## Enumeration

Lock-coverage class (unoverridden `sqlite3.Connection` mutation surface used anywhere in tree):

```
rg -n "\.cursor\(|\.backup\(|iterdump|create_function|load_extension|setconfig|\
set_trace_callback|set_progress_handler|create_collation" lattice/
# exit=1 (zero matches) — class empty
rg -n "\.cursor\(" lattice/            # zero matches
rg -c "with self\._conn:|with conn:" lattice/storage/repositories.py \
      lattice/storage/cache.py lattice/storage/connection.py
# repositories.py: 34, cache.py: 1, connection.py: 1 — all 36 dispositioned in finding 1
```

E5 disposition: verified unchanged (spy test), wider instance reported as finding 1; the bare
`__exit__`-bypass mechanism itself is NOT re-reported, per assignment.

Instance table for the enumeration instances:
| Instance | Disposition |
|---|---|
| E5 (`cache.py:60`, `connection.py:102`) — `with conn:` implicit commit/rollback not under RLock | KNOWN; verified unchanged; wider consequence → **finding 1** |
| Unoverridden mutating methods (`cursor`, `backup`, …) | examined-clean — zero call sites in tree |
| 36 `with conn:` transaction blocks | all rely on the per-statement lock → **finding 1** |

## Design risks (max 2)

1. `initialize_cache_db` unlinks and recreates the cache file with no cross-process guard; a CLI
   command (`cli.py:236`) run against a live daemon during a schema upgrade would swap the file
   under the daemon's open fd, forking the cache into two divergent inodes. Disposable data only;
   no in-tree path runs both concurrently today.
2. `configure_connection` registers `dict`/`list` adapters globally
   (`sqlite3.register_adapter`), deprecated since Python 3.12 — a future CPython will turn this
   into a hard error at import time. No current misbehavior.

## Side discoveries (single-pass candidates, not confirmed work)

- `repositories.py:claim_pending`/`claim_for_webhook` select claimed rows back by exact
  `lease_expires_at` string equality; two claims by the same owner within the same wall-clock
  second would collide — but the owner embeds the thread name, and same-thread re-entrance is
  impossible while a lease is live. Out of assigned files; not pursued.
- `repositories.py:list_discovery_set` uses `datetime.now(UTC)` instead of the injected clock,
  unlike its neighbors. Out of assigned files; not pursued.

## Bound

- Assigned files `connection.py` and `cache.py` were read end to end; nothing skipped.
- The wider consequences were traced into `repositories.py`, `runtime.py`, `api.py`, `cli.py`,
  and `migrations.py` only as needed to establish caller populations for finding 1; those files
  were not themselves hunted for independent defects (other passes own them).
- No live daemon was run; the race frequency for finding 1 is argued from thread populations and
  tick cadences, not measured. The C-level behavior of `sqlite3` was verified on Python 3.12.11
  only; other versions were not tested.
