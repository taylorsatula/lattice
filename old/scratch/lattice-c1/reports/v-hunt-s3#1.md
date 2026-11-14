# v-hunt-s3#1 — PRIMED VERIFIER

Claim under test: **hunt-s3#1** in `scratch/lattice-c1/reports/seam-s3.md`, reported tier **L** —
"Circuit-breaker writes bypass repository transaction boundary and are never committed".

Adversarial and symmetric. Re-derived the frame from source before checking the claim.

---

## Re-derived frame (independent of the claim)

- `lattice/cli.py:702-703` serve path opens two connections: `durable_conn = open_connection(durable_path)`
  and `cache_conn = initialize_cache_db(cache_path)`. `lattice/runtime.py:167-196` receives both and builds
  `self._cache_repo = CacheRepository(cache_conn)`, separate from all durable repos.
- `lattice/storage/connection.py:open_connection` calls `sqlite3.connect(...)` with **no** `isolation_level`
  argument, so the connection is the Python default `isolation_level=""` (legacy implicit transaction
  control). `_LockedConnection` subclasses `sqlite3.Connection`, adds a per-statement `RLock`, and
  overrides only `execute/executemany/executescript/commit/rollback`; it does **not** change
  `isolation_level` or the `__enter__`/`__exit__` protocol.
- `lattice/migrations/cache_schema.sql:88` defines `circuit_observations(node_id PK, consecutive_failures,
  last_failure_at)` in the **cache** database. `lattice/storage/cache.py` documents that database as
  disposable and recreatable on schema-hash mismatch.
- Every durable and cache repository mutation in `lattice/storage/repositories.py` is wrapped in
  `with self._conn:` (35 sites). `lattice/runtime.py:776/803/816` read/write
  `circuit_observations` via raw `self._cache_repo.conn.execute(...)` with **no** `with`/commit.
- The two write sites are `_circuit_record_success` (803) and `_circuit_record_failure` (816); the read
  site 776 is a `SELECT`. Reached from `_run_outbound_delivery`/`_send_outbound_message` (delivery executor)
  and `_send_gossip_batch` (maintenance executor).

## Verdict: **CONFIRMED** (severity L stands)

Each component traced independently:

- **Mechanism — CONFIRMED (experimental).** Python 3.12.11, default-isolation connection: a raw DML
  statement leaves `conn.in_transaction == True`; a subsequent `with conn:` block commits the *whole*
  connection, materializing the earlier raw write in a second connection; `conn.close()` with the
  transaction still pending rolls it back (row absent on reopen). Reproduced both directions in
  `/tmp` and `:memory:`. The claim's experimental step is accurate.
- **Trigger — CONFIRMED.** A peer that is down / returns 429/5xx / sends an invalid custody receipt /
  has no known endpoint drives `_circuit_record_failure`; a successful delivery or gossip round drives
  `_circuit_record_success`. Concrete statement order in `_run_outbound_delivery` (runtime.py:924-943):
  `claim_for_delivery` → `peer_endpoint_for_node` is None → `_outbound.record_failure(...)` (durable conn
  commit, **does not** touch cache_conn) → `_circuit_record_failure` (cache_conn, uncommitted).
  `_send_gossip_batch` (1104-1123): TransportError → `_circuit_record_failure(node_id)`. Both run on
  background executor threads. Reachability kind: **PRODUCTION**.
- **Frequency — CORRECTED (harm window narrower than the trigger window).** The *trigger* population is
  demonstrated: every failed delivery attempt (delivery loop default 10 s, up to 5 rows/claim) and every
  failed gossip round (60 s). The *loss* requires that pending write to be discarded before any cache
  commit. But `expiry_cleanup` runs every 60 s (`RuntimeSettings.expiry_interval_seconds = 60.0`) and
  `_run_expiry_cleanup` → `TopologyService.prune` → `prune_candidates`/`prune_transient_cards`/
  `prune_discovery_set`, each a `with self._conn:` block that commits *unconditionally on exit even with
  rowcount 0* (the DELETE still opens and commits a transaction). So in any running daemon the pending
  circuit write is committed within ≤60 s of the failure. Harm therefore needs a crash/SIGKILL within
  that ≤60 s window, or the graceful-stop-with-empty-rate-buckets path. The claim's "every failing peer
  interaction" is the trigger cadence, not the harm cadence; the two are not the same.

## Sub-claims dispositioned

- "raw `conn.execute` with no commit, unlike every method in repositories.py" — **CONFIRMED** (enumeration
  below; exactly two write sites).
- "implicit transaction only a later `with conn:` commit closes" — **CONFIRMED** (also closes by
  explicit `commit()`/`rollback()`; rollback-on-exception is the harmful close — see added mechanisms).
- "committed only incidentally by another cache repository method" — **CONFIRMED**; gossip candidate /
  transient-card writes and the 60 s prune are the usual incidental committers.
- "on graceful stop when no rate-bucket rows exist … pending writes are rolled back on close" —
  **CONFIRMED as a path, but narrowed**: `_persist_rate_limits` (runtime.py:497-511) commits only if
  `snapshot()` is non-empty; `cli.py:730` then closes `cache_conn`. In a live deployment any peer that
  consumed a rate-limit token produces a bucket, so this path requires a node that never rate-limited
  an inbound message. Narrow, as claimed.
- **REFUTED half**: the finding *title* says the writes "are never committed". They **are** committed —
  incidentally, on the next cache `with self._conn:` exit, which occurs at least every 60 s while the
  daemon runs. The body states this correctly; the title overstates. Nothing in the outcome depends on
  the write never being committed; the defect is transaction-boundary bypass and incidental-commit
  coupling, not permanent non-persistence.
- **Outcome framing corrected**: the "backoff counters reset" cost is bounded and, because
  `circuit_observations` lives in the explicitly *disposable* cache database, losing it across a
  restart is close to intended. In-process circuit-breaker behaviour is correct (same connection sees its
  own uncommitted rows). Net effect is transaction-discipline/durability hygiene, not a functional break.

## Additional mechanisms / earlier failure sites (same trace)

1. **Cache-side instance of the connection-wide-rollback class** (same class as the report's finding 4,
   on the cache connection instead of the durable one). Because the circuit write is left uncommitted,
   any *later* failing cache repository `with self._conn:` block on that connection calls
   `self.rollback()` in `__exit__`, discarding the pending circuit observation too. This is in-process
   (not just restart) state loss. Gated behind a cache-repo exception (rare: the cache writers are
   ON CONFLICT upserts / DELETEs), so it is a real but low-frequency secondary effect. It is the
   *earlier failure site* the claim did not name for the in-process case.
2. **Non-atomic read-modify-write across threads.** `_circuit_is_open` (SELECT) and
   `_circuit_record_failure` (UPDATE) are separate locked statements; two executor threads can interleave
   between them, so the failure counter increment and the open-check are not atomic. Benign in outcome
   (worst case one extra attempt or one skipped backoff), but it is part of the same missing-boundary
   mechanism. No elevation.

## Fix-direction constraints

- The minimal repair — wrapping `_circuit_record_success`/`_circuit_record_failure` bodies in
  `with self._cache_repo.conn:` — restores the repository transaction boundary and closes this finding,
  but does **not** close the connection-wide-rollback class (added mechanism 1, finding 4) nor the
  non-atomic read-modify-write. A fix that only adds the `with` block will still let another thread's
  failing cache transaction roll back a freshly committed circuit write.
- A repair must decide whether circuit state is meant to be durable. If `circuit_observations` is
  deliberately disposable, the correct fix is to make the write *explicitly* self-contained and document
  that durability is best-effort — not to route it through the durable connection. If it is meant to
  survive restart, it belongs behind the same discipline as other state; the current incidental-commit
  coupling is the wrong answer either way.
- Do not "fix" by calling `conn.commit()` inline without the `with` block in a way that also commits a
  concurrent thread's half-finished cache transaction; the lock is per-connection, so a bare commit
  publishes other threads' uncommitted writes.

## Enumeration (class closure)

```
rg -n "\.conn\.execute\(|_conn\.execute\(" lattice/runtime.py
rg -n "_circuit_record_(failure|success)\(" lattice/runtime.py
```

Raw connection executes in `runtime.py`: 522 `_durable_conn.execute("SELECT 1")`, 523
`_cache_conn.execute("SELECT 1")` (health reads, not DML); 776 `_cache_repo.conn.execute(SELECT …)`
(read only); 803, 816 the two circuit DML sites. No other unguarded DML on a shared connection exists in
`runtime.py`. Every mutating method in `lattice/storage/repositories.py` is inside `with self._conn:`
(35 sites). The class is closed: exactly the two cited write sites bypass the boundary.

## Checked and clean

- `_circuit_is_open` read path: `row is None` / `not consecutive_failures` / `last_failure_at is None` /
  `ValueError` all short-circuit before arithmetic; no crash on malformed rows. Correct.
- `_circuit_record_success` INSERT … `ON CONFLICT DO UPDATE SET consecutive_failures = 0,
  last_failure_at = NULL` and `_circuit_record_failure` increment — both syntactically correct against
  the cache schema's `PRIMARY KEY(node_id)`. The uncommitted-write defect does not affect their
  correctness within a process (same-connection visibility).
- `cache_conn` is not the durable connection and `circuit_observations` is not in the durable schema, so
  no durable-state or custody semantics are implicated by this finding.
- `_LockedConnection` locking is correct for per-statement thread safety; it is transactional atomicity,
  not statement locking, that is missing here.

## Bound

- No live daemon, no live WAL file pair. Transaction semantics reproduced with isolated Python 3.12.11
  sqlite3 only (in-memory and `/tmp` file DB). The exact SQLite/WAL durability behaviour of the
  production files under SIGKILL was not exercised.
- Whether a real deployment ever reaches the graceful-stop-with-empty-rate-buckets state was not observed;
  derived from `_persist_rate_limits` source, not a run.
- Did not run `tests/`; the production reachability classification is from source tracing.
