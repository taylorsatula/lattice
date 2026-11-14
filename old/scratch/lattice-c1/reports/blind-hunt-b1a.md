# blind-hunt-b1a — runtime/config lifecycle (blind third pass)

Surface: `lattice/runtime.py` (`_RecurringTask`, `_RuntimeScheduler`, `RuntimeCoordinator.__init__`,
`_build_scheduler`, `start`, `stop`, `_restore_rate_limits`, `_persist_rate_limits`, `is_ready`,
`is_running`, `_write_audit_entry`), `lattice/config.py`, `lattice/__init__.py`.
Read end-to-end: runtime.py (1136 lines, paged), config.py (214), `__init__.py` (8).

## Findings

1. [M] — Cross-thread transaction interleaving on the shared SQLite connection silently discards
   another thread's durable write
- Location: `lattice/runtime.py:RuntimeCoordinator` writes (all repositories; `_write_audit_entry`
  is representative) over the shared `durable_conn`/`cache_conn`.
  Mechanism: `lattice/storage/connection.py:_LockedConnection`.
- Evidence: `_LockedConnection` wraps only the individual calls —
  `def execute(...): with self._lattice_lock: return super().execute(...)` (same for `commit`,
  `rollback`) — and never holds the lock across a `with self._conn:` transaction. There are 34
  `with self._conn:` blocks in `lattice/storage/repositories.py`; the transaction opened by the
  first DML inside such a block is not covered by the lock.
- Trigger (production): uvicorn serves the sync `def` federation/admin routes on its worker
  threadpool while the runtime's `ThreadPoolExecutor`s run delivery/webhook/maintenance — all on
  the same two connections (opened once in `cli.py:cmd_serve`, passed into the coordinator). Thread
  A is inside a repository `with self._conn:` block between its DML and the block's exit (uncommitted
  write). Thread B enters its own `with self._conn:` block and exits it with an exception — before
  or after its own statement. `__exit__` calls the shared `rollback()`, which rolls the connection
  back, discarding A's uncommitted rows; A then exits and its `commit()` is a no-op while A's caller
  believes the write succeeded.
  In-tree exception sources on a `with` block: `PeerRepository.transition_peer` raises
  `RepositoryError("cannot transition missing peer")` (repositories.py:262),
  `_format_ts` raises `RepositoryError("timestamp must be timezone-aware")` (repositories.py:30),
  any UNIQUE-constraint `sqlite3.IntegrityError` from a `create` (duplicate `message_id`), or any
  `sqlite3` error (disk, `database is locked` from a concurrent out-of-process CLI reader/writer).
- Frequency: LATENT. The population is routine (concurrent writers on the shared connection exist
  on every request + every scheduler tick), but the trigger requires an in-block exception to land
  inside another thread's sub-millisecond uncommitted window, and no routine caller raises there
  today. Cap and low frequency stated deliberately.
- Outcome: silent loss of a durable write while the losing workflow reports success. Depending on
  which write is discarded: an `inbound_messages` custody row (destination returned a signed 202
  receipt but holds no message — the sender stops retrying → dropped message), an
  `outbound_messages` row (locally accepted message never delivered), a `domain_pins`/`peers` trust
  transition, or an `audit_log` row. Impact ceiling is H (data loss); held at M because the trigger
  is a narrow interleaving, and frequency cannot be grounded.
- Reachability: PRODUCTION.
- Confidence: mechanism traced and demonstrated (probe below under Checked-and-clean/Enumeration);
  trigger sources traced in-tree; frequency LATENT/unproven.

2. [L] — Recurring tasks' first execution is delayed by up to one full interval when the process
   starts soon after host boot
- Location: `lattice/runtime.py:_RecurringTask.maybe_run` / field `_last_run: float = 0.0`.
- Evidence: `if now - self._last_run < self.interval_seconds: return False`, with `now =
  time.monotonic()` supplied by `_RuntimeScheduler.run`. `0.0` is used as the "never run" sentinel,
  but `time.monotonic()` is not a large epoch — its reference point is boot.
- Trigger (production, Linux): `_RuntimeScheduler.run` ticks every 1s and calls
  `maybe_run(time.monotonic())`. On a host whose uptime is less than a task's interval (systemd
  starts `lattice serve` shortly after boot), every task with `interval > uptime` is skipped. Tasks
  and intervals: `outbound_delivery`/`webhook_delivery` 10s, `cold_sender_resolution` 30s,
  `gossip_round`/`verify_candidates`/`expiry_cleanup` 60s, `refresh_topology` 300s
  (`runtime.py:_build_scheduler`). A node that boots with the service enabled therefore postpones
  `refresh_topology` up to ~5 min and gossip/verify/expiry up to ~1 min.
- Frequency: DEMONSTRATED. Every boot where the service starts within `interval` of host boot —
  i.e., the documented systemd deployment (`deploy/lattice.service`, `WantedBy=multi-user.target`).
- Outcome: background delivery/gossip/candidate-verification/expiry/topology-refresh muted for up
  to one interval after each boot; self-correcting, bounded.
- Reachability: PRODUCTION (Linux). `time.monotonic()`'s reference point is platform-defined, so the
  trigger holds only where it is boot-relative (bound stated below).
- Confidence: mechanism traced; trigger traced; frequency grounded for the boot-start population.

3. [L] — `stop(timeout)` does not bound executor drain; graceful shutdown can overrun systemd's
   stop timeout and be SIGKILLed before rate-limit persistence and transport close
- Location: `lattice/runtime.py:RuntimeCoordinator.stop`.
- Evidence: `self._scheduler.stop(timeout=timeout)` is bounded, but the next two lines are
  `self._delivery_executor.shutdown(wait=True, cancel_futures=False)` and
  `self._maintenance_executor.shutdown(wait=True, ...)` — `wait=True` has no timeout, so the
  `timeout` argument does not bound total shutdown.
- Trigger (production): `systemctl stop/restart` while `_run_outbound_delivery`/`_run_webhook_delivery`
  is mid-batch. Each run claims up to 5 rows (`claim_for_delivery(owner, limit=5)`), and each
  `_send_outbound_message` can block up to connect 10s + read 30s (`transport.DEFAULT_TIMEOUT`),
  with `socket.getaddrinfo` in `_resolve_and_validate` unbounded. The drain therefore can exceed
  systemd's default `TimeoutStopSec=90`; `deploy/lattice.service` sets no `TimeoutStopSec`.
- Frequency: DEMONSTRATED population — any stop/restart while delivery leases are draining slow or
  unreachable peers; with a pending retry queue this recurs each restart.
- Outcome: SIGKILL before `_persist_rate_limits()`, `self._transport.close()`, `self._webhook.close()`
  run. Rate-limit token state is not persisted (peers resume at full quota next start); in-flight
  leases recover only via 5-minute expiry. Durable DB writes are already committed, so no message
  loss is claimed.
- Reachability: PRODUCTION. The SIGKILL boundary depends on systemd's default stop timeout; the
  in-code defect (unbounded drain despite a `timeout` parameter) is independent of it.
- Confidence: mechanism traced; frequency grounded; systemd timing untested (bound stated).

## Sub-claims / framing checked

- "Executor shutdown ordering" — scheduler is joined before either executor is shut down
  (`stop()` order), and no task submits to another executor, so the normal drain has no
  submit-after-shutdown hole. Clean; only the missing bound (finding 3) is defective.
- "Recurring-task cadence arithmetic" — interval is start-to-start, the non-blocking `_lock`
  prevents overlap, and a busy task does not lose its next run. Clean except the sentinel (finding 2).
- "Scheduler stop handshake" — `stop()` sets `_stopped_event` then `join(timeout)`; `run()` exits on
  the set event. Clean.
- "Rate-limit restore/persist ordering" — restore in `start()` before the scheduler, persist in
  `stop()` after drain; both wrap failures and never raise into the lifecycle. Ordering clean.
- "Readiness gating" — `is_ready` is not production-reachable-before-start (see S1 below).
- "Audit writes under contention" — the contention defect is finding 1 (mechanism in
  `connection.py`, exercised through every runtime write).

## Checked and clean

- `RuntimeCoordinator.__init__`: executors created before `_build_scheduler()`; every `_RecurringTask`
  references an existing executor. No executor threads are spawned at construction (ThreadPoolExecutor
  is lazy), so an unstarted coordinator leaks no threads.
- `start()`: rejects double-start and start-after-stop; sets `_started` before `_scheduler.start()`.
- `_RuntimeScheduler.stop`/`run`: event-set + join handshake is correct; tick granularity is 1s.
- `_RecurringTask._run`: releases `_lock` in `finally`; exceptions are logged, not propagated.
- `stop()` idempotency guard (`if not self._started or self._stopped: return`).
- `_restore_rate_limits` / `_persist_rate_limits`: snapshot = `(node_id, msg_tok, gos_tok, epoch)`;
  persisted `last_updated` is `str(time.time())` into a `TEXT NOT NULL` column
  (`migrations/cache_schema.sql:69`); `load_rate_buckets` parses it back with `float(...)`. Round-trip
  is type-consistent. Both methods catch and log; neither can abort the lifecycle.
- `RateLimiter.snapshot/restore`: absent buckets default to full capacity; `TokenBucket.restore` uses
  the persisted value directly and clamps refill by `capacity`.
- `is_ready`: returns False when `_stopped`; checks well-known doc, config/identity fields, and both
  connections with `SELECT 1` inside try/except.
- `is_running`: `_started and not _stopped and scheduler.is_alive()`.
- `config.py`: domain charset/length (`_is_valid_domain`), https-without-credentials for bootstrap
  and `public_base_url`, positive rate limits, positive/`MAX_TTL_SECONDS`-bounded TTL, private-mode
  CIDR/suffix requirement, and `private_suffixes`/CIDR parsing are all enforced.

## Enumeration

Composed command (class-closing):

```
rg -n '_RecurringTask\(' -A4 lattice/runtime.py \
 && rg -c 'with self\._conn:' lattice/storage/repositories.py \
 && rg -n 'raise RepositoryError|raise CustodyError|raise PeerError' \
      lattice/storage/repositories.py lattice/messages.py lattice/peers.py \
 && rg -n 'ThreadPoolExecutor|threading.Thread|uvicorn.run|def receive_|def admin_' \
      lattice/runtime.py lattice/api.py lattice/cli.py
```

Result:
- 7 `_RecurringTask` instances (cold_sender_resolution 30, outbound_delivery 10, webhook_delivery 10,
  gossip_round 60, verify_candidates 60, refresh_topology 300, expiry_cleanup 60) — disposition:
  all affected by finding 2's sentinel; none by any other arithmetic defect.
- 34 `with self._conn:` transaction boundaries — disposition: every one is a candidate for finding 1;
  only `claim_pending` and `claim_for_webhook` hold two statements, the rest one. None is
  individually wrong.
- Raise sites: repositories.py:262 (`transition_peer` missing peer) and :30 (`_format_ts` naive ts)
  are the two in-store raises that can fire inside a `with` block; messages.py raises are outside
  `with` blocks (they wrap `create`) and peers.py raises are pre-store. Disposition: named as
  finding-1 trigger sources.
- Writers: two `ThreadPoolExecutor`s (maintenance 2, delivery 4) + the scheduler thread +
  uvicorn's sync-endpoint threadpool, all sharing the two connections — the finding-1 population.

Live probes (bounded, no state changed, temp DBs only):
- `/tmp/probe_txn.py` — thread A commits a row inside `with conn:` while thread B's `with conn:`
  raises after an insert. Output: `results {'a': 'committed', 'b': 'err boom'}`, `rows []`. A's
  committed row is gone.
- `/tmp/probe_txn2.py` — same, but B raises without executing any statement. Output: `a committed`,
  `rows []`. Confirms a pre-DML raise also rolls back the peer's transaction.
- `_RecurringTask("refresh_topology", 300.0, ...)` with `maybe_run` at t=5 and t=299 returns False,
  at t=301 returns True — confirms finding 2.

## Side discoveries

- S1 [L] — `is_ready()` never consults `_started`, so a constructed-but-unstarted coordinator reports
  ready. Reachability: TESTS ONLY today (`tests/conftest.py:two_nodes` serves unstarted runtimes via
  `TestClient`; `tests/test_runtime.py::test_runtime_is_ready` asserts it). The only production
  server path (`cli.py:cmd_serve`) calls `runtime.start()` before `uvicorn.run`, so no request can
  arrive pre-start. Fix-direction: gate readiness on `_started` as well as `not _stopped`.
- S2 [L] — `_persist_rate_limits()` saves buckets one at a time inside one `try`; the first failing
  `save_rate_bucket` aborts persistence of all remaining buckets. Frequency: narrow (needs one write
  to fail — disk/lock error). Outcome: later peers' token state lost on restart. Fix-direction:
  per-bucket error handling (continue past a failed row), not a single outer catch.
- S3 [L] — `config._is_https_url` accepts a scheme-only string: `"https://"` starts with `https://`
  and contains no `@`, so it passes for `public_base_url` and for `gossip.bootstrap`, producing
  host-less endpoints (`https:///lattice/v1/...`). Operator-misconfig only; no attacker control.
  Fix-direction: require a non-empty host component, not just the prefix.

## Design risks (max 2)

- `docs/LOOSE_ENDS.md` (Phase 8) asserts `_LockedConnection` "serializes all SQLite operations on a
  single connection … This is correct for v1." It serializes statements, not transactions, so the
  assertion is false under concurrent `with self._conn:` blocks (finding 1). A v1 fix is to make the
  lock cover the transaction boundary, or give each worker a thread-local connection.
- The graceful-stop contract is only half-defined: `stop(timeout)` bounds the scheduler but not the
  executor drain, and the deployment unit sets no `TimeoutStopSec`. Either bound the drain or make
  `stop` reject a `timeout` it cannot honor.

## Bound (unreachable / unverified)

- `time.monotonic()`'s reference point is platform-defined; finding 2 holds where it is boot-relative
  (Linux `CLOCK_MONOTONIC`, the documented production target) and may not fire on a platform whose
  origin is large.
- systemd's actual `TimeoutStopSec` and real shutdown timing were not exercised; finding 3's SIGKILL
  step is bounded to that default, though the unbounded-drain defect is code-level.
- Finding 1's interleaving probability was not measured — only the rollback mechanism was
  demonstrated. No routine caller currently raises inside a `with self._conn:` block, so frequency is
  LATENT; the trigger requires a future/seldom exception (or an out-of-process writer) at the wrong
  instant.
- No live peers, TLS, DNS, or webhook endpoints were used; probes were in-process with stub
  executors and temp SQLite files. Python/sqlite3 threadsafety mode and version were not varied.
- Prior reports in `scratch/lattice-c1/reports/` were deliberately not consulted (blind pass).
