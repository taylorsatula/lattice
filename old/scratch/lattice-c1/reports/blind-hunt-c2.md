# blind-hunt-c2 — storage connection wrapper + cache layer

Scope read end to end: `lattice/storage/connection.py`, `lattice/storage/cache.py`.
Callers traced: `lattice/storage/repositories.py`, `lattice/storage/migrations.py`,
`lattice/messages.py` (`InboundMessageService.accept`), `lattice/runtime.py` (executors/threads),
`lattice/api.py` (sync handlers → threadpool), `lattice/cli.py` (`serve`).

Neutral question: does the shared SQLite connection wrapper and the cache layer preserve their
stated concurrency and lifecycle contracts — lock coverage of every mutating/transactional
operation, thread sharing, WAL/pragma setup, cache expiry and snapshot/restore?

Verdict: the wrapper does NOT preserve its stated contract. The RLock covers individual statements,
not the transaction boundary those statements compose. The stated contract
(`docs/LOOSE_ENDS.md` Phase 8: "`_LockedConnection` serializes all SQLite operations on a single
connection shared by the request thread pool and background executors. This is correct for v1") is
false as written, and the failure is silent custody data loss, not a throughput concern.

## Findings

1. [H] — `_LockedConnection` locks each statement, not the transaction; a cross-thread rollback on
   the shared connection silently discards another thread's committed-intent write (custody ack
   without durable custody).
- Location: `lattice/storage/connection.py:_LockedConnection` (`execute`/`commit`/`rollback`);
  victim path `lattice/storage/repositories.py:InboundMessageRepository.create`
  (`with self._conn: ... INSERT`) reached from `lattice/messages.py:InboundMessageService.accept`.
- Evidence (decisive mechanism, probed against the real class, not read):
  ```
  # thread A: with conn: conn.execute("INSERT INTO t(id,v) VALUES('A','from-A')"); <pause>
  # thread B: with conn: conn.execute("INSERT INTO t(id,v) VALUES('A','from-B')")
  B IntegrityError -> __exit__ rollback: UNIQUE constraint failed: t.id
  rows: []
  A with-block completed (commit returned normally): True
  ```
  `sqlite3.Connection.__exit__` on an exception calls `self.rollback()`. `_LockedConnection`
  overrides `rollback` to take the same RLock and call SQLite rollback — but rollback is
  **connection-global**, and the RLock was released between A's `execute` and A's `commit`
  (both `execute` and `commit` acquire/release individually). A's still-uncommitted row lives in the
  same shared transaction, so B's rollback erases it. A's own `commit()` then commits nothing and
  returns normally.
- Trigger (exact production path): `POST /lattice/v1/messages` is a sync handler
  (`lattice/api.py:receive_message`, `def`), so Starlette runs it on the anyio worker threadpool
  concurrently. Two requests carrying the **same `message_id` from the same node** (sender retry /
  duplicate delivery — explicitly anticipated by `accept`, which catches "UNIQUE constraint") reach
  `accept`: both `get_existing_receipt` return None, both call `create`. The first thread's INSERT is
  uncommitted for the duration of its `with self._conn:` block; the second thread is blocked on the
  RLock during that INSERT and is the natural next acquirer when the first releases. The second
  INSERT sees the first's uncommitted row on the *same connection* and raises `IntegrityError`;
  its `with conn:` block exits via `rollback()`, discarding the first thread's row. The first handler
  then proceeds to `_audit_inbound_accepted` and returns `202` with a signed `accepted` receipt; the
  second finds no existing receipt and raises `CustodyError` → signed `rejected` receipt. The message
  is not in `inbound_messages`.
- Frequency: DEMONSTRATED population, probabilistic coincidence. Operation population: every inbound
  `POST /lattice/v1/messages` (concurrent, uvicorn threadpool) and every delivery/maintenance worker
  (4 delivery + 2 maintenance threads, `RuntimeSettings`) that opens a `with self._conn:` block on the
  same durable connection. The rollback victim occurs whenever any thread raises inside a
  `with self._conn:` block while another thread has uncommitted work on that connection. The direct
  trigger is the duplicate-accept race the code already names.
- Outcome: durable-custody acknowledgment (`202` + signed `accepted` receipt) returned for a message
  that was never stored; legitimate senders stop retrying on an accepted receipt → permanent message
  loss. This is invariant 5's explicit reportable form ("A 202 returned when custody was NOT durably
  established IS reportable"). Any concurrent writer (e.g., an outbound `mark_terminal`, a maintenance
  `expire_messages`, an audit INSERT) can equally be the victim, losing its uncommitted commit.
- Reachability: PRODUCTION.
- Confidence: mechanism traced AND reproduced with the real `_LockedConnection`; trigger traced
  through `api.py`→`messages.py`→`repositories.py`; frequency is demonstrated at the population level
  but the exact interleaving coincidence is probabilistic (unproven: the real-world hit rate).

2. [L] — `initialize_cache_db` does not recreate a corrupt cache file; it only treats
   `OperationalError` as "schema mismatch", so a `DatabaseError` escapes and the daemon fails to
   start.
- Location: `lattice/storage/cache.py:_current_schema_hash` (catches `sqlite3.OperationalError` only),
  `initialize_cache_db`.
- Evidence (probe):
  ```
  db.write_bytes(b"not a sqlite database at all, garbage bytes")
  initialize_cache_db(db)
  -> raised: sqlite3.DatabaseError file is not a database
  ```
  `sqlite3.OperationalError` is a *subclass* of `sqlite3.DatabaseError`; catching the subclass does not
  catch the parent. The `except sqlite3.Error` in `initialize_cache_db` only wraps `execute_script`,
  so the `DatabaseError` from the hash check propagates out of `cmd_serve`
  (`lattice/cli.py`, `cache_conn = initialize_cache_db(cache_path)`) before `RuntimeCoordinator` starts.
- Trigger: the cache file at `cache_path` is truncated or corrupted at startup (partial write after
  power loss, disk full, external truncation). `open_connection` succeeds (SQLite opens lazily); the
  first statement `SELECT schema_hash FROM schema_version` raises `DatabaseError: file is not a
  database`.
- Frequency: LATENT. Grounded only on an environment/operator event (cache-file corruption), not on
  any routine operation population. Marked latent per calibration; tier capped accordingly.
- Outcome: the disposable cache database — documented as "recreatable" and "all irreplaceable state
  belongs in the durable database" — is not recreated; the node fails to start until an operator
  manually deletes the file. Availability/lifecycle fault, not data loss (cache is disposable).
- Reachability: PRODUCTION (trigger is an operator/environment condition, not routine traffic).
- Confidence: mechanism traced and reproduced; trigger plausible; frequency latent/ungrounded.

## Refuted sub-claims

Blind pass — no claim provided. Internally considered and refuted/downgraded:

- "The lock makes the single shared connection safe" (the Phase 8 doc position). REFUTED by Finding 1.
- "`execute_script`'s `with conn:` provides a migration transaction." REFUTED as a *defect*:
  `executescript` implicitly commits any pending transaction and runs its script in autocommit, so the
  surrounding `with conn:` commit/rollback is a no-op. This is not reportable because every durable
  migration statement is `CREATE ... IF NOT EXISTS` and `PRAGMA user_version` is set last
  (`001_initial.sql` lines 5/6/208), so a partially-applied script reruns cleanly; the cache schema is
  likewise all `IF NOT EXISTS`. Examined-clean.
- "`cursor()`/`close()` bypass the lock → defect." REFUTED for reachability: no caller in the tree uses
  `conn.cursor(...)` (enumeration below); `close()` runs only after `runtime.stop()` drains the
  executors and joins the scheduler (`cli.py`). Examined-clean, not a finding.

## Checked and clean

- WAL/pragma setup: `configure_connection` runs `foreign_keys=ON`, `journal_mode=WAL` (documented
  best-effort), `busy_timeout=5000`, sets `row_factory`, and registers JSON adapters/converters. WAL is
  set on a fresh connection with no open transaction — correct placement. Verified against
  `cache_schema.sql`/`001_initial.sql` which also set these.
- Thread sharing: `check_same_thread=False` plus `factory=_LockedConnection` is a deliberate, working
  way to allow cross-thread use of one connection; the attribute set in `__init__` is supported
  (probed: subclass has `__dict__`). The *sharing* works; the transaction atomicity it is claimed to
  provide does not (Finding 1).
- `_LockedConnection` lock attachment: `execute`, `executemany`, `executescript`, `commit`, `rollback`
  all acquire the same `RLock` (reentrant, so same-thread nesting does not deadlock). No repository
  method nests two `with self._conn:` blocks of different repo methods, so early-commit-on-nesting is
  not reachable today (examined `repositories.py` in full).
- `initialize_cache_db` recreation-on-schema-mismatch for the *normal* cases: missing
  `schema_version` table → `OperationalError` → None → recreate; empty/zero-byte file → same;
  hash changed → close, unlink, remove `-wal`/`-shm` (suffix handling correct for `.db` paths used by
  all callers), recreate and stamp hash. Verified against `tests/test_storage.py`.
- Cache expiry/snapshot/restore: `cache.py` owns only creation/recreation; expiry
  (`prune_candidates`, `prune_transient_cards`, `prune_discovery_set`) and the rate-bucket
  snapshot/restore (`_persist_rate_limits`/`_restore_rate_limits`) live in `repositories.py`/`runtime.py`
  and were traced to be called from the scheduler tasks and `RuntimeCoordinator.start/stop`. No defect
  found in this scope for those paths.
- `open_connection` parent-directory creation and `migrate`'s own connection lifecycle (open →
  check → migrate → close in `finally`) checked; single-threaded at startup, no defect.

## Enumeration

Composed command and result:
```
$ rg -n "\.cursor\(" lattice --glob '!scratch/**'      # lock-bypassing cursor use
(no matches)
$ rg -n "isolation_level|BEGIN|SAVEPOINT|BEGIN IMMEDIATE" lattice --glob '!scratch/**'
(no matches)                                            # no explicit tx control anywhere
$ rg -n "with self\._conn:|with conn:|with self\._repository" lattice --glob '!scratch/**'
repositories.py: 30+ `with self._conn:` transaction blocks; cache.py:1; runtime.py:0 (repos only)
$ rg -n "\.execute\(|\.executemany\(|\.executescript\(" lattice --glob '!scratch/**'
all statements route through _LockedConnection.execute* (no raw cursor path)
```
Instance table:
- `cursor()` bypass sites: none → class closed (clean).
- explicit `BEGIN`/`SAVEPOINT` sites: none → every transaction is the implicit one begun by the first
  DML on the shared connection → the cross-thread rollback mechanism is the *only* transaction model,
  and it is connection-global (Finding 1).
- `with *conn` transaction blocks: `repositories.py` (all mutating repo methods), `cache.py:60`;
  all use the same shared connection → all are exposed to Finding 1's victim mechanism.
- `executescript` sites: only `execute_script` (`connection.py`) ← `migrations.py` and `cache.py`;
  autocommit semantics, idempotent scripts → clean.

## Side discoveries (separate from verdicts)

- S1 [single-pass, same root as Finding 1] Shared-connection non-isolation: because there is one
  connection (one transaction) for all threads, a thread's `commit()` commits another thread's
  uncommitted multi-statement operation early, and reads on the connection observe uncommitted writes.
  Multi-statement ops like `PeerRepository.add_block` (INSERT `blocks` + UPDATE `peers`) can therefore
  be observed half-applied by a concurrent reader, and their atomicity is not guaranteed even without
  an exception. Severity M (wrong/partial state under concurrent readers), frequency: same population
  as Finding 1 (concurrent request threads + 4 delivery + 2 maintenance workers), PRODUCTION.
  Fix-direction: cannot be repaired by widening per-statement locks; requires one lock held across the
  whole transaction or per-thread connections.
- S2 [single-pass] `docs/LOOSE_ENDS.md` Phase 8 asserts the design "is correct for v1"; that claim is
  now demonstrably false and should not be relied on by later passes as evidence of correctness.
  Documentation-only, not a code defect.

## Fix-direction constraints

- Finding 1: a repair must make the lock (or connection ownership) span the *transaction*, not the
  statement. Acquiring the RLock in `__enter__`/releasing in `__exit__` (and leaving reentrancy to
  handle same-thread nesting) is the minimal correct shape; alternative is one connection per thread.
  Merely wrapping more statements in the existing lock does NOT fix it, because `commit`/`rollback`
  are connection-global and can erase a peer thread's work. Escaping the structure-breaking (no
  cross-thread rollback) is not the same as isolation: even with a transaction-spanning lock, the
  `get_existing_receipt` read-then-`create` in `accept` is still check-then-act across separate
  transactions and relies on the UNIQUE catch; the UNIQUE catch is only safe once the rollback can no
  longer damage a peer.
- Finding 2: catch `sqlite3.DatabaseError` (the base, which also subsumes `OperationalError`) around
  the hash probe and treat "cannot read a disposable cache" as mismatch → recreate. Must also handle a
  file that cannot be unlinked/opened (surface as `CacheError`, not an uncaught traceback).

## Bound

- Real multi-thread HTTP timing under uvicorn was not reproduced; the hit rate of the
  Finding 1 interleaving window is unproven (mechanism and trigger proven, frequency probabilistic).
- OS/filesystem behaviour that produces cache corruption (Finding 2 trigger) was not exercised; the
  trigger is a plausible environment event, not demonstrated here.
- `workers=1` is hardcoded for uvicorn (`cli.py`), so multi-*process* cache/durable sharing was not
  considered; only in-process thread sharing.
