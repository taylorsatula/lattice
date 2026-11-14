# Orientation: runtime orchestration, persistence, entry surfaces, configuration

## 1. Concept
`RuntimeCoordinator` (`runtime.py:RuntimeCoordinator`) owns all services, two `ThreadPoolExecutor`s, a daemon `_RuntimeScheduler` thread, and both SQLite connections. `start()` restores rate buckets, pins bootstrap peers, and starts the scheduler; `stop()` drains executors then persists rate limits. Entry surfaces: HTTP via `api.py:create_app` (fixed public routes plus admin/health), CLI via `cli.py:main`, and `cli.py:cmd_serve`, which migrates, opens both DBs, constructs the coordinator, and calls `uvicorn.run(..., workers=1)`. Persistence splits into a durable DB (`migrations/durable/001_initial.sql`, `migrations.migrate`) and a disposable cache DB (`cache_schema.sql`, `cache.initialize_cache_db`), both opened via `connection.open_connection`.

## 2. Invariants
- Root-key confinement: daemon loads only `operational_key` (`credentials.load_operational_key`); `RuntimeCoordinator` takes `root_public_key: Ed25519PublicKey` and builds a public-only `RootIdentity` (`runtime.py:__init__`).
- Synchronous core: repos/transport are plain sync calls; async exists only in FastAPI handlers and the scheduler glue (`_RuntimeScheduler.run`).
- Fixed public routes: `protocol/constants.py:ROUTE_WELL_KNOWN/ROUTE_GOSSIP/ROUTE_MESSAGES`, used in `api.py` decorators.
- Durable custody: `messages.InboundMessageService.accept`/`build_receipt`; sender validates the receipt body before transfer (`runtime.py:_send_outbound_message`).
- No relay: outbound delivery targets only `row["to_node_id"]` (`runtime.py:_run_outbound_delivery`); gossip carries cards only.
- Nginx/systemd boundary: `cmd_serve` binds `config.bind_host` (default 127.0.0.1); admin/health isolation is enforced by `deploy/lattice.nginx.conf`, not code.

## 3. Mechanism inventory
- Coordinator lifecycle: `runtime.py:RuntimeCoordinator.start/stop/is_ready`.
- Scheduler/non-overlap: `_RecurringTask.maybe_run`/`_run`, `_RuntimeScheduler.run`. Executors: two in `runtime.py:__init__`.
- Queue claim/retry/expiry: `OutboundMessageRepository.claim_pending/release_lease/mark_terminal/expire_messages`; `messages.RetryPolicy.next_attempt_at`.
- Circuit breaker: `runtime.py:_circuit_is_open/_circuit_record_success/_circuit_record_failure`. Custody write: `InboundMessageService.accept`, `OutboundMessageService.submit`. Webhook delivery: `WebhookDeliveryService.deliver`, `runtime.py:_run_webhook_delivery`.
- Rate-limit restore/persist: `runtime.py:_restore_rate_limits/_persist_rate_limits`; `rate_limit.RateLimiter.restore/snapshot`.
- Connection sharing: `connection._LockedConnection` (RLock, `check_same_thread=False`). Transaction idiom: `with self._conn:` everywhere; `connection.execute_script`. Migrations: `migrations.migrate`, `cache.initialize_cache_db`.

## 4. Sanctioned idioms + exemplars
- Durable write: wrap in `with self._conn:`, use `_format_ts`/`_json_dumps`; mirror `repositories.py:OutboundMessageRepository.create` or `PeerRepository.upsert_peer`. Never invent a second transaction style.
- Background task: add a `_RecurringTask` to `_build_scheduler` with an interval from `RuntimeSettings`; mirror `runtime.py:_run_outbound_delivery`.
- Claim a queue item: `repo.claim_pending(owner, now, limit)` then `record_success`/`record_failure`; never select/update rows inline.
- HTTP error: return `api.py:_problem(...)`; `_STATUS_PROBLEM_MAP` is the code source of truth.
- Load config/credentials: `config.load_config`; `credentials.load_credential(path=...)`; CLI resolves via `cli._credential_path`.
- Neutral divergences: `api.py` reaches into runtime privates (`runtime._own_domains`, `runtime._audit_inbound_accepted`, `runtime.topology_service._peers`); circuit/rate code runs raw SQL on `_cache_repo.conn`; health route strings are not in `constants.py`.

## 5. Consequence map
- Data/custody loss: `InboundMessageService.accept`, `OutboundMessageRepository.mark_terminal`/`expire_messages` (irreversible content erasure)
- Stuck queue: `claim_pending` leases 5 min; a crash between claim and `record_failure` strands a row until lease expiry. Cadence, mostly silent.
- Crash: scheduler is a daemon thread; task exceptions are caught, but if the thread dies all cadence stops silently.
- Wrong status: receipt validation in `_send_outbound_message`; 4xx terminal → `retryable=False`. Audit rows are silent above the entry's log level (`_write_audit_entry`).
- Silent failures: `_restore_rate_limits`, `_persist_rate_limits`, `_circuit_record_*`, `_resolve_pending_senders` catch broadly and log only.
- Hot path: `receive_message`, `receive_gossip`, `admin_submit`, `well_known`. Background: the seven recurring tasks.

## 6. Intentional design decisions
- Synchronous core with bounded thread pools and a coordinator thread is deliberate (docs/ARCHITECTURE.md §Design forces). Boundary: no async in repositories/services.
- 202 means durable custody, not delivery (`messages.py:build_receipt`; `api.py:receive_message`). Boundary: never read 202 as human delivery.
- Broad `except Exception` in maintenance paths is resilience (`_RecurringTask._run`, `_restore_rate_limits`, `_persist_rate_limits`, `_circuit_record_*`, `_resolve_pending_senders`). Boundary: the coordinator must survive one failing task/peer.
- Admin/health isolation relies on Nginx allow/deny, not code (`api.py`; `deploy/lattice.nginx.conf`). Boundary: never assume internet exposure.
- `_LockedConnection` deliberately disables sqlite's thread check and serializes with a reentrant lock so Uvicorn's pool and background executors share one connection. Boundary: correctness over throughput; known bottleneck (LOOSE_ENDS.md).
- Cache DB is disposable, recreated on schema-hash mismatch (`cache.initialize_cache_db`); circuit/rate state there is intentionally transient.
- Cold senders get 503 + async resolution (`api.py:receive_message`, `runtime.queue_domain_resolution`) so the sender retains custody.
- Bootstrap peers are pinned as established without independent verification (`runtime.py:_pin_bootstrap_peers`).
- `workers=1` is hardcoded in `cmd_serve` despite `Config.workers` — the single-process assumption of the shared connection/coordinator. `stop()` persists rate limits only after executors drain.

## 7. Doc ↔ code drift
- Root `AGENTS.md` map cites `lattice/app.py`, `api_public.py`, `api_local.py`, `queue.py`, `client.py` — none exist; actual is `api.py`, `messages.py`, `storage/repositories.py` (`AGENTS.md:87` §TODO admits this).
- `AGENTS.md` cites `tests/fixtures/schema_versions/` (empty dir) and `tests/e2e/` (absent); the actual fixture is `tests/fixtures/durable_schema/v1.sql`.
- `AGENTS.md` cites `deploy/nginx-lattice.conf`; actual is `deploy/lattice.nginx.conf`.
- `docs/AGENTS.md:14-16` registers `OPERATIONS.md`, `INTEGRATION.md`, `adr/` — the first two absent and `docs/adr/` empty; it omits existing `ARCHITECTURE.md`, `LATTICE_SYSTEMD.md`, `LOOSE_ENDS.md`. `AGENTS.md:74` routes to a nonexistent `docs/OPERATIONS.md §Configuration`.
- `docs/MIGRATIONS.md` says missing migrations apply "in a single transaction"; `migrations.migrate` loops with one `with conn:` per script. It also claims CI runs every fixture; there is no CI config and only `v1.sql`.

## 8. Verification surface
Exercised: `test_runtime.py` (real SQLite; transport and webhook patched; intervals pinned so task fns run directly), `test_api.py` (`TestClient`, real runtime/DB), `test_storage.py`/`test_schema_upgrades.py` (real SQLite + `durable_schema/v1.sql`), `test_resilience.py`/`two_nodes` (`_FakeTransport`; cache deletion, DNS outage), `test_cli.py` (`getpass`, `OutboundTransport` patched).
Mocked: outbound HTTP, webhook pool, credential prompts, DNS/well-known.
Not exercised: claim contention, restart and rate-limit restore/persist, the scheduler tick thread, lease expiry/reclaim, circuit-breaker timing, crash mid-custody, `_LockedConnection` blocking. A live probe needs a writable state dir, real credentials, and a bound socket.

## 9. Surprises
- `claim_pending` uses `lease_expires_at = now+5min` as both claim marker and re-select key; concurrency rests on the single `UPDATE ... WHERE id IN (...)`.
- `api.py:receive_message` returns 401 with a pin but no cert, yet 503 when the domain is unpinned.
- `is_ready()` runs `SELECT 1` on the shared connection, so readiness can block on the `_LockedConnection` RLock.
- `WebhookDeliveryService` uses its own `urllib3.PoolManager`, bypassing `OutboundTransport`/`NetworkPolicy`; `WebhookConfig` checks only for URL credentials, not loopback host/scheme.
- `cmd_serve` closes both DB connections in `finally`, but `runtime.stop()` closes only transport/webhook and is a no-op unless `start()` succeeded.
