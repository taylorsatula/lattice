# hunt-b1a — orchestration core: lifecycle & cadence mechanism

Assigned files read end-to-end: `lattice/runtime.py` (all 1136 lines, every assigned symbol),
`lattice/config.py`, `lattice/__init__.py`. Traced callers/callees: `lattice/cli.py` (cmd_serve),
`lattice/api.py` (create_app routes), `lattice/messages.py` (custody services),
`lattice/storage/repositories.py`, `lattice/storage/connection.py`, `lattice/storage/cache.py`,
`lattice/migrations/cache_schema.sql`, `lattice/rate_limit.py`, `lattice/transport.py`,
`lattice/webhook.py`. Mechanism claims verified with throwaway in-memory SQLite scripts
(outside the repo tree); no repo file was modified.

## Findings

1. [H] — Shared durable connection: one thread's failed repository block rolls back other
   threads' in-flight writes (lost audit rows; 202 "accepted" receipt without durable custody)
   - Location: `lattice/storage/connection.py:_LockedConnection` (mechanism);
   `lattice/storage/repositories.py:InboundMessageRepository.create` / `OutboundMessageRepository.create`
   (the `with self._conn:` idiom, ~35 sites); reached through `lattice/runtime.py:_write_audit_entry`
   and `lattice/runtime.py:_run_webhook_delivery` / `_send_outbound_message` (delivery executor
   threads) racing `lattice/api.py:receive_message` (uvicorn threadpool) on the single
   `durable_conn` shared by all repositories.
   - Evidence: `class _LockedConnection` comment: "adds a coarse reentrant lock around the main
     mutating operations so a single connection can safely be shared" — but the lock serializes
     individual `execute` calls only. With `isolation_level=""` all DML on the connection joins
     ONE implicit SQLite transaction; any `with self._conn:` block that raises calls
     `Connection.__exit__` → `rollback()` on that shared transaction.
   - Trigger: (a) an inbound `POST /lattice/v1/messages` thread executes the custody `INSERT`
   (message M) inside `with self._conn:` and is scheduled out between `execute` and the
   `__exit__` commit (the RLock is released in that gap); (b) concurrently an admin
   `POST /lattice/v1/admin/submit` with an already-existing `message_id` runs
   `OutboundMessageService.submit` → `create` → UNIQUE violation → `with` exit → `rollback()`,
   which discards thread (a)'s uncommitted INSERT. Thread (a)'s `accept()` then returns the
   signed receipt and `receive_message` responds **HTTP 202** for a message that no longer has a
   durable custody row. The same rollback discards any concurrent `_write_audit_entry` INSERT
   (INBOUND_ACCEPTED/OUTBOUND_*) — silently lost audit rows.
   - Frequency: coincidence race. Population: the ~46 threads sharing `durable_conn`
   (uvicorn AnyIO pool + 4 delivery + 2 maintenance workers) hitting the execute→commit gap,
   coinciding with a failing `with self._conn` block — today reachable via admin duplicate
   outbound submit (api.py:406 → CustodyError) or a rare storage error. Duplicates are a normal
   operator action; the microsecond window is the unproven part.
   - Outcome: durable custody promised (202 accepted, invariant 5) but not established —
   webhook never fires, sender never retries, message lost; audit trail loses entries with no
   error anywhere.
   - Confidence: mechanism TRACED and empirically demonstrated (in-memory `_LockedConnection`
   repro: thread B's UNIQUE failure rolled back thread A's in-flight INSERT; audit table empty
   afterwards). Trigger traced to in-tree code paths. Frequency unproven (window is the
   execute→commit gap). Note: empirically `Connection.__exit__` on CPython 3.12 bypasses the
   Python-level `commit`/`rollback` overrides (instance monkeypatch count stayed 0), so
   `with`-exit commits are additionally not lock-serialized — the interleaving is easier than
   the class comment implies.
   - Related side fact: an inbound duplicate does NOT raise UNIQUE (`get_existing_receipt`
   reads the uncommitted row on the same connection — verified), so the rollback trigger is
   the outbound/admin side plus genuine storage errors.

2. [L] — `_RecurringTask` first-run arithmetic delays all maintenance on freshly booted hosts
   - Location: `lattice/runtime.py:_RecurringTask` (`_last_run: float = field(default_factory=...)`
   default `0.0`, `maybe_run`).
   - Evidence: `if now - self._last_run < self.interval_seconds: return False` with
   `now = time.monotonic()` (scheduler `run()` at runtime.py:149-151).
   - Trigger: daemon start on a host whose uptime is below the task interval — the normal case
   for a systemd-enabled node rebooting (`systemd` starts `lattice serve` seconds after boot;
   `time.monotonic()` is time since boot). E.g. uptime 20s: `expiry_cleanup`/`gossip_round`/
   `verify_candidates` (60s) wait ~40s, `refresh_topology` (300s) waits ~280s before their
   FIRST execution ever.
   - Frequency: DEMONSTRATED — every daemon start on a machine with uptime < interval; a
   one-time per-start delay, bounded by the interval (≤5 min for refresh_topology).
   - Outcome: after reboot the node rejoins gossip/verification/topology-refresh late and does
   not prune stale candidates/discovery state for up to one full interval; intended
   "run at startup" behavior (implicit in `_last_run=0.0`) silently does not happen.
   - Confidence: fully traced; no test asserts first-tick timing (tests inject large-uptime
   machines implicitly). Mechanism, trigger, and frequency all proven.

## Checked and clean

- **`_RecurringTask` cadence arithmetic (doubled/missed ticks, drift):** the non-blocking
  per-task lock plus single scheduler thread makes double submission impossible; a task that
  overruns its interval simply skips ticks until the lock frees (no catch-up burst); the
  interval is measured submit-to-submit so drift is bounded by processing time; `time.monotonic`
  never steps backward. Clean apart from finding 2.
- **`_RuntimeScheduler.run/stop` handshake:** loop body is strictly non-blocking
  (`maybe_run` uses `acquire(blocking=False)`, `ThreadPoolExecutor.submit` does not block), so
  `stop()`'s `Event.set()` + `join(timeout)` completes within ~1 tick. Executors are shut down
  only AFTER the scheduler join, so `executor.submit` at runtime.py:127 can never hit a shut-down
  executor via the graceful path (the only way `submit` could raise, which would otherwise strand
  the task lock and `_last_run`).
- **`RuntimeCoordinator.stop` ordering:** `_stopped` flag set first (idempotent against double /
  concurrent stop); scheduler stopped before executors; executors drained with
  `wait=True, cancel_futures=False` BEFORE `_persist_rate_limits` (comment in code says "to avoid
  stale snapshots" and the ordering honors it); `_persist_rate_limits` runs after `uvicorn.run`
  has returned in `cmd_serve`, so no request thread can consume/modify buckets concurrently with
  the snapshot. `transport.close()`/`webhook.close()` last, after the threads using them drained.
- **E2 candidate (durable claim held by an in-flight future at stop):** NOT a defect.
  `shutdown(wait=True, cancel_futures=False)` lets queued and running delivery futures complete;
  each writes its terminal/release outcome. For a hard kill (SIGKILL / systemd
  `TimeoutStopSec`), `claim_pending`/`claim_for_webhook` (repositories.py) lease with a 5-minute
  `lease_expires_at` and explicitly re-claim rows with `status IN ('pending','leased') AND
  lease_expires_at <= now` — a crashed claim self-heals within one lease interval after restart.
  Drain duration is bounded (transport `Timeout(connect=10, read=30)`; webhook
  `Timeout(connect=10, read=30)`), so graceful stop cannot hang indefinitely.
- **Rate-limit restore/persist round-trip:** restore in `start()` before scheduler and before
  uvicorn serves; `str(epoch)`/`float()` round-trip of `last_updated` is consistent;
  `RateLimiter.snapshot` refills from each bucket's own `last_updated`, so mixed-epoch rows are
  per-bucket self-consistent; per-row upserts are idempotent; `_restore_rate_limits` and
  `_persist_rate_limits` are fully exception-wrapped (a cache failure logs and continues, never
  blocks start/stop). Caveats accepted as cache-tier design: crash loses buckets (disposable),
  and restoring tokens saved under a higher old limit can transiently exceed a newly lowered
  capacity.
- **`is_ready` / `is_running`:** `is_ready` checks `_stopped`, well-known document, config,
  identity, and both DB connections; it does not check `_started`/scheduler liveness, but the
  only in-tree caller (`cmd_serve`) starts the runtime before uvicorn serves, and
  `admin_status` merely reports both flags — no reachable misbehavior today.
- **`_write_audit_entry` itself:** level gate is explicit design ("gated by Python logging
  level", docstring); insert shape correct; failure surfaces as a logged task exception, not a
  custody-affecting error (see Design risks for the observable effect).
- **`config.py` end-to-end:** validation is strict (domain charset/length, https-only URLs
  without userinfo, positive rate limits, TTL bounds against MAX_TTL_SECONDS, private-mode
  requires cidrs/suffixes); no lifecycle interaction beyond construction; nothing reportable.
- **`lattice/__init__.py`:** version shim only. Clean.

## Enumeration

Composed commands (run against the tree):

- E1: `rg -n "Thread\(|run_in_executor|copy_context|ContextVar|submit\(" lattice`
  (note: this pattern misses `ThreadPoolExecutor(`; the executor creations are covered by
  `rg -n "ThreadPoolExecutor\(" lattice` → `runtime.py:269,273`).
- E2: `rg -n "\.result\(|\.join\(|wait_for|shutdown\(|Event\(|\.wait\(" lattice`
- E5 (this hunt's scope): `rg -n "with self\._conn|save_rate_bucket|load_rate_buckets|\.snapshot\(|\.restore\(" lattice/runtime.py lattice/rate_limit.py lattice/storage/repositories.py`

Instance dispositions:

| Instance | Disposition |
|---|---|
| `runtime.py:127` `executor.submit(self._run)` | examined-clean — submit cannot fail while the scheduler lives (executors shut down after scheduler join; loop body non-blocking). If it ever raised, the task lock would be stranded — no in-tree path reaches that today. |
| `runtime.py:269,273` `ThreadPoolExecutor(...)` | examined-clean — created in `__init__` before any submit; workers spawn lazily; non-daemon workers joined by interpreter atexit; scheduler thread is daemon. Shared delivery executor (outbound+webhook tasks) has 4 workers vs. serial 5×≤40s work per tick — no starvation deadlock; maintenance executor (2 workers) can delay `cold_sender_resolution` under slow gossip, bounded by transport timeouts. |
| `runtime.py:146,149,156` scheduler wait/join | examined-clean — bounded 1s tick wait, join with timeout, handshake cannot deadlock (see Checked and clean). |
| `runtime.py:489,490` `shutdown(wait=True, cancel_futures=False)` | examined-clean — full drain plus 5-minute lease re-claim recovery; no durable claim is stranded by graceful stop (detail above). This is the E2 candidate the orchestrator flagged: dispositioned NOT a defect. |
| `api.py:385/406`, `messages.py:88` `submit(...)` (E1) | examined as part of Finding 1's trigger trace — enqueue-only, no spawn; the duplicate-submit rollback is Finding 1's reachable trigger. |
| rate-limit snapshot persistence (`runtime.py:397/405-406/492/500-502`) | examined-clean — ordering, atomicity-per-row, and round-trip all correct; caveats are cache-tier by design (above). |

## Design risks (max 2)

1. Audit entries are gated on the Python log level of the `lattice` logger
   (`_write_audit_entry` → `logger.isEnabledFor(level)`), but nothing in `cmd_serve` configures
   that logger, and uvicorn only configures its own loggers — with the default root level
   (WARNING), every INFO-level audit code (INBOUND_ACCEPTED, OUTBOUND_DELIVERED,
   WEBHOOK_DELIVERED, retryable WEBHOOK_FAILED) is silently never written to `audit_log` in a
   stock deployment. Explicit code intent ("gated by Python logging level"), hence a design risk,
   not a finding — but the durable audit trail is empty-by-default for the most common events.
2. Rate-limit buckets persist only at graceful shutdown; a crash/SIGKILL restores no buckets and
   grants every peer a fresh full allowance on restart. Cache-tier state is documented as
   disposable, but a flapping node effectively multiplies its rate budget by restart count.

## Side discoveries (single-pass candidates, not confirmed work)

- `_circuit_record_success`/`_circuit_record_failure` (runtime.py) execute INSERT/UPDATE on the
  cache connection with no `with conn:` and no commit; the writes are only visible because all
  readers share the connection, are incidentally committed by unrelated threads' `with` blocks,
  and are lost to any cache-connection rollback (same mechanism as Finding 1, cache side).
  Effect: circuit breaker state can silently reset, reopening delivery to a failing peer.
  Needs a dedicated pass over the delivery mechanism.
- `cmd_serve` (cli.py:718) calls `runtime.start()` outside the `try/finally` that owns
  `runtime.stop()`; a partial `start()` failure (e.g. `int(op_cert.get("sequence", 0))` in
  `_pin_bootstrap_peers` raising on a malformed remote bootstrap document) skips stop/conn-close
  entirely. Also, if `stop()` were ever called after such a partial start,
  `_RuntimeScheduler.stop` would raise `RuntimeError` (join on a never-started thread) and skip
  executor shutdown + rate-limit persistence. No in-tree caller reaches the stop-after-failed-
  start path today — latent only.
- `RuntimeSettings` intervals are not configurable via TOML (hardcoded defaults, only code/tests
  can change them) — observed, not judged.

## Bound

- `lattice/cli.py` and `lattice/api.py` were read only around the serve/lifecycle/rate-limit
  paths and the routes listed; full-file defect review of those belongs to other hunts.
- No live infrastructure was run: the scheduler/executors were not observed under load; the
  interleaving window in Finding 1 was demonstrated on an in-memory connection, not against the
  deployed WAL database under production concurrency.
- The E5 enumeration command cannot see transaction boundaries inside `connection.py`'s C-level
  `with` semantics (which bypass the Python overrides); the finding covers the observable effect.
- `tests/` were consulted for lifecycle expectations (test_runtime.py TestLifecycle) but not read
  exhaustively.
