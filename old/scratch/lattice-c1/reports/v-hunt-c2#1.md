# v-hunt-c2#1 — PRIMED VERIFIER

Claim under test: **hunt-c2 #1 [H]** in `scratch/lattice-c1/reports/hunt-c2.md` —
"`with conn:` transactions on the shared connection cross-commit and cross-rollback across daemon
threads".

Method: frame re-derived from source before reading the claim's conclusion. Read to the end:
`lattice/storage/connection.py` (103 lines), `lattice/storage/cache.py` (67), `lattice/storage/repositories.py`
(1182), `lattice/runtime.py` (1136), `lattice/api.py` (414), `lattice/messages.py`, and the durable
migration `lattice/migrations/durable/001_initial.sql`. Reproduced the mechanism against the **real**
`_LockedConnection`, the real `migrate()` schema, and the real
`OutboundMessageRepository.claim_pending` / `InboundMessageRepository.create` classes. No live daemon,
proxy or load harness was run.

## Verdict: ADJUSTED — mechanism CONFIRMED, trigger CONFIRMED (production), outcome CONFIRMED, severity H → L (calibration frequency cap); one frequency sub-claim refuted

The defect is real. The sharing contract in `_LockedConnection`'s docstring is unenforceable by a
per-statement lock, and a rollback in one thread's `with conn:` block discards another thread's
already-executed, uncommitted writes on the same connection. I reproduced the claim's double-claim
variant and the 202-without-custody variant deterministically. The single tier correction is the
pinned calibration frequency cap; the claim's own frequency section concedes the rate is unmeasured
and its named failing-block source is partly wrong. This verdict is independent of, and agrees with,
the parallel adjudication of the same mechanism in `scratch/lattice-c1/reports/v-hunt-c1#1.md`.

### Frame re-derived from source

- **One durable connection, several thread populations.** `cmd_serve` (`cli.py:702-703`) opens one
  `durable_conn` and one `cache_conn`; `RuntimeCoordinator.__init__` (`runtime.py:190-196`) hands
  `durable_conn` to **six** repositories (peer, pin, outbound, inbound, webhook, audit) and
  `cache_conn` to `CacheRepository`. `uvicorn.run(..., workers=1)` (`cli.py:718`) is one process.
- **Sync routes run in the anyio threadpool.** `receive_message` (`api.py:287`) and `receive_gossip`
  (`api.py:242`) are synchronous `def` handlers, so FastAPI executes them concurrently on worker
  threads of the single app. The background writers are `_delivery_executor` (4 workers) and
  `_maintenance_executor` (2 workers) plus `_RuntimeScheduler` (`runtime.py:139-155, 268-279,
  344-388`). All durable writers therefore share `durable_conn`.
- **What the lock covers.** `_LockedConnection` (`connection.py:34-61`) overrides
  `execute`/`executemany`/`executescript`/`commit`/`rollback`, each taking `self._lattice_lock`
  around that one call. It does **not** override `__enter__`/`__exit__`. `with self._conn:` is
  sqlite3's own context manager: it begins nothing at enter, the implicit `BEGIN` fires at the first
  DML, and `__exit__` calls the C-level commit/rollback. Spied on the real class, a normal and a
  failing `with conn:` block each produced **zero** calls to the Python `commit`/`rollback`
  overrides — the lock is free across the whole transaction span (first DML → finalization).
- **One transaction per connection.** On Python 3.12.11 (`isolation_level=''`, legacy mode),
  statements from different threads on the same connection join one transaction. A `rollback()` in
  thread B discards thread A's uncommitted writes and a `commit()` in B finalizes A's open
  transaction. The per-statement lock serializes individual statements, not transactions.

### Component disposition

1. **Mechanism — CONFIRMED.** `with self._conn:` yields per-connection, not per-thread, transactions.
   There are 34 such blocks in `repositories.py` (`rg -c 'with self\._conn' → 34`) plus one each in
   `cache.py`/`connection.py`. Deterministic proof (in `/tmp`, tree untouched): thread A opened a
   `with conn:` block, executed an `INSERT` into `domain_pins`, and was held before its block exit;
   thread B then ran a `with conn:` block whose statement raised, so B's `__exit__` rollback ran; on
   release A's block exited normally — `SELECT COUNT(*) FROM domain_pins` returned **0**. A
   normal-returning block's write was silently discarded.

2. **Trigger — CONFIRMED, PRODUCTION, coincidence-gated.** `receive_message` (`api.py:287`) →
   `InboundMessageService.accept` (`messages.py:241`) → `InboundMessageRepository.create`
   (`repositories.py:870`) runs on a threadpool thread; concurrently `_run_outbound_delivery`
   (`runtime.py:~940`) → `OutboundMessageService.claim_for_delivery` → `OutboundMessageRepository.
   claim_pending` (`repositories.py`) runs on a delivery thread, and `_run_expiry_cleanup`
   (`runtime.py:~1130`) runs `expire_messages` on a maintenance thread. All on `durable_conn`. Any
   `with conn:` block that raises while another block is uncommitted rolls the other back.

3. **Outcome — CONFIRMED at the real site.**
   - **Double-claim (claim's T5) reproduced deterministically.** Using the real
     `OutboundMessageRepository.claim_pending` and the real durable schema, an interloper failing
     block injected in the finalization window left the row `{'status':'pending','lease_owner':None}`
     even though `claim_pending` had returned `['m1']` for worker 1; a second worker's
     `claim_pending` then returned the same `m1` with owner `delivery-2`. **Duplicate delivery.**
   - **202 with no custody reproduced deterministically.** With an interloper failing block in the
     finalization window of `InboundMessageRepository.create`, `create()` returned normally,
     `api.py:345-358` would emit a signed **`accepted`** 202 receipt, yet
     `SELECT COUNT(*) FROM inbound_messages WHERE message_id='m1'` returned **0** — invariant-5
     violation, message silently lost, no webhook.
   - The sender-side receipt handling (`runtime.py`, `_send_outbound_message`) validates
     `message_id`/`node_id`/`status` and then `record_success`, i.e. a 202 `accepted` terminates
     retries, so the loss is unrecoverable.

4. **Frequency — CORRECTED to LATENT / coincidence-gated.** See "Frequency correction" below.

### Sub-claims, individually

| Sub-claim | Disposition |
|---|---|
| Shared `durable_conn` across HTTP threadpool + delivery + maintenance threads | **CONFIRMED** (`runtime.py:190-196`, sync `def` routes, 4+2 executor workers) |
| `with self._conn:` block spans a transaction that interleaves across threads | **CONFIRMED** (deterministic repro; `__exit__` bypasses both lock and Python commit overrides) |
| Per-statement lock cannot enforce the docstring's sharing contract | **CONFIRMED** |
| Double-claim / duplicate delivery outcome | **CONFIRMED** (deterministic repro) |
| 202 accepted with no durable custody row | **CONFIRMED** (deterministic repro) |
| Names `claim_pending` as the delivery victim ("outbound_delivery tick calls claim_pending") | **CONFIRMED** — `_run_outbound_delivery` calls `self._outbound.claim_for_delivery`, which delegates to `OutboundMessageRepository.claim_pending` |
| **"duplicate-message retries are a normal peer behavior that produces failing `with conn:` blocks"** | **REFUTED as stated** — `accept()` calls `get_existing_receipt` first (`messages.py:253`) and returns the stored receipt without attempting the `INSERT`; an ordinary retry does **not** produce a failing block. Only a genuine concurrent same-`message_id` race (both threads pass the pre-check) reaches the `IntegrityError`, and the rate limiter bounds messages to 60/min/node. The failing-block population is narrower than the claim's wording implies. |
| "plausible in normal operation" / frequency demonstrated | **NARROWED to LATENT** — production-cadence measurement below produced no custody loss |
| Reachability "production" | **CONFIRMED** |
| Reported tier H | **CORRECTED to L** (outcome severity stays H; calibration frequency cap) |

### Severity correction

Reported **H** → corrected **L**. The *outcome* class is genuinely H (durable custody lost after a
202-accepted receipt; duplicate delivery of one outbound message; partial multi-statement state
persisted). The downgrade is solely the pinned calibration rule — "A frequency you cannot ground is
LATENT by definition — say so and cap at L" — and matches the precedent `v-hunt-c1#1` (same mechanism,
H → L) and `v-hunt-a2#1` (M → L). If telemetry later shows a non-trivial collision rate, the tier
escalates to H; that measurement is outside this pass. **Frequency: LATENT (coincidence race).**

### Frequency correction — trace that produced it

The claim asserts a "coincidence race, plausible in normal operation", grounds the *populations*
(every inbound POST, every gossip card, every scheduler tick), and says the rate is not demonstrated.
I checked the cadence two ways:

1. **The named failing-block source is narrower than claimed.** As above, an ordinary duplicate
   retry is short-circuited by `get_existing_receipt`; the `IntegrityError` block fires only under a
   genuine concurrent same-`message_id` accept. The named population ("duplicate-message retries") is
   therefore overstated.
2. **At production GIL cadence the loss did not reproduce under heavy load.** Stress harness (real
   `migrate()` schema, real `InboundMessageRepository`): 6 accept-worker threads (18,000 unique
   creates/trial) + 3 threads repeatedly issuing the failing duplicate block, at the **default**
   `sys.setswitchinterval()` (5 ms). Three trials: `LOST` (create returned normally but no committed
   row) = 0/0/0; one `EXTRA` (row committed although `create` raised) and one `OperationalError`
   across 54,000 creates. Only at an artificially reduced switch interval (1 µs, 5000×) did
   `LOST` appear (7 lost successes across 6 trials), and errors
   (`OperationalError: cannot commit - no transaction is active`, `SystemError: error return without
   exception set`) appeared. So the mechanism is real but its production cadence is ungrounded; no
   per-deployment rate can be justified from the tree. Frequency is LATENT.

## Additional mechanisms / earlier failure sites / new reachability

- **Earlier failure site (the enabling defect):** `connection.py:_LockedConnection`. Its docstring
  asserts the connection "can safely be shared by Uvicorn's worker thread pool and the runtime's
  background executors"; the lock scope contradicts that. A repair confined to `repositories.py`
  still leaves the unsafe connection in place.
- **Second mechanism, distinct statement (new):** cross-thread corruption of sqlite3's connection
  transaction state surfaces as raw driver errors — observed `OperationalError: cannot commit - no
  transaction is active` and **`SystemError: error return without exception set`** from repository
  calls under contention. `SystemError` is not a `sqlite3.Error` and not a normal dbapi failure; in
  `accept()` it is caught by the generic `except Exception` and converted to
  `CustodyError("failed to accept message: ...")` (`messages.py`), which `api.py` turns into a signed
  **rejected** 202 receipt — while the row may in fact have been committed by another thread
  (the `EXTRA` rows in the stress run). Wrong custody semantics on top of the data-loss route.
- **Mirror-image outcome (new):** `create()` can raise while the row *was* committed (`EXTRA` > 0 in
  the stress run). The caller then reports failure for a durably-stored message, inviting a
  duplicate custody insert or a rejected receipt for a stored message — the same root cause,
  opposite direction.
- **`transition_peer` is a second concrete failing-block source in tree (new):**
  `PeerRepository.transition_peer` raises `RepositoryError("cannot transition missing peer")`
  *inside* its `with self._conn:` block (`repositories.py:262`). `topology.verify_candidate` calls
  `self._peers.transition` on a candidate whose peer row can be concurrently absent. This rollback
  source needs no duplicate message at all.
- **Nested-`with` premature commit (new, narrow):** because `with conn:` finalizes the shared
  transaction on any exit, a nested `with conn:` block inside an outer one would commit the outer's
  uncommitted work. I saw no nested repository blocks in tree, so this is a code-shape hazard, not a
  demonstrated live path — noted, not promoted.

## Fix-direction constraints

1. The repair must cover the **whole** `with self._conn:` span, not individual `execute` calls.
   Wrapping `execute`/`commit`/`rollback` (today's design) cannot fix it: the transaction opens at
   the first DML and is finalized by a later call, possibly from another thread.
2. Adding the lock only in `__exit__` is insufficient — the `BEGIN` site must be covered too. A
   reentrant lock is required because `upsert_peer`/`transition_peer` call `get_peer` re-entrantly
   from inside a block.
3. Fixing only the `__exit__` lock bypass (known E5) does **not** fix this finding: the transactions
   still interleave. Do not treat E5's repair as this defect's repair.
4. A fix that serializes writes but not reads is insufficient: `accept`'s `get_existing_receipt`
   pre-check reads another thread's uncommitted state (dirty read) and must be covered.
5. Serializing only `durable_conn` misses `cache_conn`, which is also shared and used by
   `CacheRepository`/`CircuitBreaker` from both HTTP and background threads.
6. The idempotency check and the insert in `accept`/`submit` are separate statements on the shared
   connection; a durable fix should make check-and-insert atomic (e.g. `INSERT ... ON CONFLICT` then
   return the stored receipt) rather than relying on catch-and-reread.

## Checked and clean

- `_LockedConnection` overrides **do** take the RLock per call; the defect is lock *scope*, not
  absence. Confirmed by reading `connection.py:44-61`.
- `Connection.__exit__` does not invoke the Python `commit`/`rollback` overrides — confirmed with a
  spy subclass (zero override calls on both normal and failing `with` exits). This is the known E5
  site, verified unchanged and not re-reported as new.
- `receive_message`/`receive_gossip` are synchronous handlers and `uvicorn.run` uses `workers=1`;
  the single-process, multi-thread premise holds.
- `configure_connection` applies `foreign_keys=ON`, WAL, `busy_timeout=5000`, `row_factory`
  correctly before the connection is returned.
- The count of 34 `with self._conn:` blocks in `repositories.py` re-derived correctly; the claim's
  "6 repositories share `durable_conn`" (`runtime.py:190-195`) is correct.
- The durable schema's FKs (`inbound_messages.from_node_id → peer_root_history`,
  `outbound_messages.to_node_id`) and the `ON CONFLICT`/`CHECK (state IN ...)` constraints read
  consistent with the repository SQL.
- Sender-side receipt handling confirms a 202 `accepted` terminates retries, which is what makes the
  lost-custody outcome real.

## Enumeration

```
rg -n "with self\._conn:|with conn:" lattice/storage/*.py | wc -l        # 36
rg -c "with self\._conn:" lattice/storage/repositories.py                 # 34
rg -n "\.cursor\(|\.backup\(|iterdump|create_function|load_extension|setconfig|set_trace_callback|set_progress_handler|create_collation" lattice/
                                                                          # exit=1, zero matches (lock surface complete)
rg -n "raise " lattice/storage/repositories.py                            # two in-block raisers at :30 (guard, outside) and :262 (transition_peer, INSIDE with block)
```

| Instance | Disposition |
|---|---|
| 34 `.py:repositories` `with self._conn:` blocks | rely on per-statement lock → **finding (claim #1) CONFIRMED** |
| `cache.py` / `connection.py` `with conn:` blocks | single-threaded call sites (CLI/migrate) → examined-clean |
| E5 `Connection.__exit__` bypass (`connection.py:102`) | KNOWN; verified unchanged; wider instance is claim #1 |
| Unoverridden mutation surface (`cursor`, `backup`, …) | zero call sites in tree → examined-clean |
| `transition_peer` in-block `RepositoryError` (`:262`) | added failing-block source → side discovery |

## Bound

- No live daemon, proxy or load harness was run: the **production rate** of the required collision is
  unmeasured and unmeasurable from the tree. This is the frequency cap, stated as a boundary.
- The 1 µs-switch stress run that produced `LOST` overstates thread switching by ~5000×; the default
  5 ms run produced no loss under heavy load. The true production cadence sits between these and is
  not grounded here.
- Whether uvicorn's anI/O threadpool actually runs two `receive_message` calls concurrently in a
  given deployment is standard FastAPI behaviour, not observed here.
- `sqlite3` C-level behaviour and exception mapping were verified on Python 3.12.11 only; other
  versions untested.
