# v-hunt-c1#1 — PRIMED VERIFIER

Claim under test: **hunt-c1 #1 [H]** in `scratch/lattice-c1/reports/hunt-c1.md` —
"Shared-connection `with self._conn:` blocks cross-contaminate transactions — a duplicate-submit
rollback can void an accepted custody row".

Method: frame re-derived from source before reading the claim's conclusion. Read
`lattice/storage/connection.py` end-to-end (103 lines), `lattice/api.py:126-414`,
`lattice/messages.py:70-380`, `lattice/runtime.py:110-530, 920-1140`, and the relevant regions of
`lattice/storage/repositories.py` (`BaseRepository`, `PeerRepository`, `InboundMessageRepository`,
`OutboundMessageRepository`, `BlockStore.add_block`). Reproduced the mechanism twice: once in
isolation against a `_LockedConnection`, and once against the **actual**
`InboundMessageRepository`/`PeerRepository`/`InboundMessageService` classes over an in-memory
locked connection with a forced interleaving. No live daemon, proxy, or load harness was exercised.

## Verdict: ADJUSTED — mechanism and trigger CONFIRMED, outcome CONFIRMED, severity H → L (calibration frequency cap)

The defect is real and I reproduced the claimed data-loss outcome at the real service site. The
claim's mechanism, production reachability, and "202 accepted with no custody row" outcome all
re-derive. The single correction is the tier: the claim's own frequency section concedes the rate
is unmeasured, and the trigger is a coincidence race, so the pinned calibration caps an
ungroundable-frequency finding at **L**. The report already labels the "victim" site imprecisely
(`repositories.py:935`; the method is at **870**).

### Frame re-derived from source

- **One connection, many threads.** `open_connection` (`connection.py:88-98`) builds a
  `sqlite3.connect(..., factory=_LockedConnection, check_same_thread=False)`. `cmd_serve`
  (`cli.py:702-717`) opens exactly one `durable_conn` and passes it to one `RuntimeCoordinator`,
  which hands it to every repository (`runtime.py:190-196`). `uvicorn.run(..., workers=1)`
  (`cli.py:718-726`) is a single process.
- **Both HTTP and background threads touch it.** `receive_message` (`api.py:287`) and
  `receive_gossip` are synchronous `def` handlers → FastAPI runs them in the anyio worker
  threadpool. Background writers run on `ThreadPoolExecutor`s plus a `threading.Thread` scheduler
  (`runtime.py:139-155, 268-279`): webhook delivery, outbound delivery, verify/expiry/gossip every
  `settings.*_interval_seconds`.
- **What the lock actually covers.** `_LockedConnection` (`connection.py:34-61`) overrides
  `execute`/`executemany`/`executescript`/`commit`/`rollback` to take an `RLock` around each **call**.
  It does not override `__enter__`/`__exit__`. `with self._conn:` is sqlite3's own context manager,
  which only commits on clean exit / rollbacks on exception and **does not begin a transaction at
  enter**; the implicit `BEGIN` fires at the first DML statement. So the lock is free across the
  entire transaction span from first DML to commit/rollback.
- **One transaction per connection.** Confirmed on this environment (Python 3.12.11,
  `isolation_level=''`, `autocommit=-1`, legacy mode): statements from different threads on the same
  connection join one transaction; a `rollback()` in thread B discards thread A's uncommitted
  writes. Verified: a loser thread's `IntegrityError` inside `with conn:` caused the connection
  `rollback()` to delete the winner's already-executed, uncommitted `INSERT`; the winner's
  `with`-exit then "succeeded" committing nothing.

### Component disposition

1. **Mechanism — CONFIRMED.** `with self._conn:` gives per-*connection*, not per-*thread*,
   transactions. The 34 blocks are at
   `repositories.py:84,133,164,201,259,302,330,367,386,406,420,471,504,512,530,556,569,587,594,613,644,669,710,754,786,847,883,935,980,1012,1070,1120,1138,1162`
   (`rg -n 'with self\._conn' lattice/storage/repositories.py | wc -l` → 34). Each call opens the
   connection's transaction and leaves it open across other threads. The enabling site is
   `connection.py:_LockedConnection`, whose docstring asserts the opposite ("a single connection can
   safely be shared by Uvicorn's worker thread pool and the runtime's background executors").

2. **Trigger — CONFIRMED, PRODUCTION, coincidence-gated.** Sender POSTs
   `POST /lattice/v1/messages`; `api.py:receive_message` → `InboundMessageService.accept`
   (`messages.py:241`) → `InboundMessageRepository.create` (`repositories.py:870`). A duplicate
   request (same `message_id`, same `from_node_id`) racing the original on the shared connection sees
   the original's uncommitted row, raises `IntegrityError`, and its `with`-exit `rollback()` discards
   that row. I forced that exact ordering against the real classes and observed the outcome.

3. **Outcome — CONFIRMED at the real site.** Reproduction against
   `InboundMessageService.accept` + real repositories (in-memory `_LockedConnection`, waiter forcing
   the loser's `INSERT` into the winner's open span):
   - loser → `CustodyError` → `api.py:345-349` returns HTTP 202 with a **rejected** receipt;
   - winner → a signed `"accepted"` receipt object → HTTP 202 accepted;
   - `SELECT message_id,status FROM inbound_messages` → **zero rows**.
   The sender treats a 202 with `status == "accepted"` as success
   (`runtime.py:974-995`: validates `message_id`/`node_id`/`status`, then `record_success`) and stops
   retrying. The message is silently lost and no webhook fires — an invariant-5 violation. Confirmed.

4. **Frequency — CORRECTED to LATENT / coincidence-gated.** The report itself concedes "NOT
   demonstrated empirically as a rate" and "Frequency component unproven." The named population is
   groundable (every inbound message POST plus continuously-running background writers on the same
   `durable_conn`), but the trigger is a microsecond-scale collision between one thread's first DML
   and its `commit`, so no per-deployment rate can be grounded from the tree. Under the pinned
   calibration this is LATENT, and the tier is capped at L.

### Severity correction

Reported **H** → corrected **L**. The outcome class is genuinely H (durable custody lost after a
202 accepted receipt). The downgrade is purely the calibration's frequency rule, not a doubt about
the defect: "A frequency you cannot ground is LATENT by definition — say so and cap at L." This
matches the precedent set by `v-hunt-a2#1`, which corrected M → L for the same reason (a
coincidence-gated trigger whose rate is not groundable). If telemetry or a load harness later shows
a non-trivial collision rate under normal traffic, the tier escalates to H; that measurement is
outside this pass. Frequency: LATENT (coincidence race), population named above.

### Sub-claims refuted / narrowed

- **"A's fallback `get_existing_receipt` now finds nothing (row was rolled back)" — narrowed, not
  unconditional.** There is a *safe* ordering the claim's phrasing omits: if the loser's preceding
  `ensure_root_history` call (`messages.py:263`, its own `with self._conn:` block) executes its
  `with`-exit `commit` while the winner's `INSERT` is uncommitted, that commit **commits the winner's
  row**, after which the loser's `create` fails on an already-committed row and its fallback returns
  the stored receipt (no loss). I observed exactly this in one run. The bad outcome requires the
  narrower ordering where the loser has already passed `ensure_root_history` before the winner's
  first DML and inserts inside the winner's open span. The outcome is real but less probable than the
  claim's narration implies; this reinforces the frequency correction.
- **"all 34 `with self._conn:` blocks cross-contaminate" — imprecise.** Only blocks that issue DML
  open/join a transaction; SELECT-only bodies do not start one. Their exposure is a *dirty read* of
  another thread's uncommitted writes (a related but distinct mechanism, see below), not transaction
  finalization. Immaterial to the verdict.
- **Location line `repositories.py:935`** is wrong; `InboundMessageRepository.create` is at
  `repositories.py:870`. Immaterial.

## Additional mechanisms / earlier failure site / new reachability

- **Dirty reads are a second route to "accepted receipt without custody" (new reachability).**
  `accept`'s idempotency pre-check `get_existing_receipt` (`messages.py:253` →
  `repositories.py:915`) is a plain `SELECT` on the shared connection, so it can read another
  thread's *uncommitted* inbound row and return its receipt before that thread commits. If the other
  thread subsequently rolls back, the pre-check already returned a 202 accepted receipt for a row
  that will never exist. This route needs no `IntegrityError` at all — only a concurrent duplicate
  accept. Same root cause, distinct statement.
- **Normal-exit `commit()` contamination is the mirror-image defect (added mechanism).** A
  `with`-exit `commit` in thread B finalizes thread A's still-open transaction. `add_block`
  (`repositories.py:364-382`) writes `blocks` then `peers` in one block; `claim_pending` /
  `claim_for_webhook` write then re-SELECT; a foreign commit landing between those statements makes
  the block non-atomic even when no exception occurs. I observed this directly: the loser's
  `ensure_root_history` commit committed the winner's inbound row at `connection.py` level. The claim
  mentions commit contamination in passing but does not trace a site; this names one.
- **Outbound `submit` is a second victim path (new reachability).**
  `OutboundMessageService.submit` (`messages.py:113-122`) does the same `ensure_root_history` +
  `create` sequence on the shared connection; a duplicate outbound submit racing its original hits
  the same rollback-discard, losing the queued outbound message.
- **Earlier failure site:** the enabling defect is `connection.py:_LockedConnection` (statement-scope
  lock, no transaction-span lock, false safety docstring). The hunter report is bounded to
  `repositories.py`; a repair inside `repositories.py` alone must not assume the connection is
  transaction-safe.

## Fix-direction constraints

- A repair must hold the connection lock across the **whole** `with self._conn:` span, not around
  individual `execute` calls. Wrapping only `execute`/`commit`/`rollback` (today's design) cannot fix
  it, because the transaction begins at the first DML and is finalized by a later call from a
  different thread.
- The natural fix is to override `_LockedConnection.__enter__`/`__exit__` to acquire the `RLock` for
  the block's duration (the lock is already reentrant, and `upsert_peer`/`transition_peer` call
  `get_peer` re-entrantly from inside a block, so a non-reentrant lock would deadlock). Adding the
  lock only in `__exit__` does not help: the BEGIN site must be covered too.
- A fix that serializes only writes is insufficient: the dirty-read route (the `get_existing_receipt`
  pre-check) reads another thread's uncommitted state and must be covered as well.
- Serializing all repository calls through the one connection is the design the docstring already
  promises; a repair that instead gives each thread its own connection must still preserve WAL
  settings, `busy_timeout`, and the `_format_ts`/`ON CONFLICT` semantics, and must not reintroduce
  multi-connection write contention that the current single connection avoids.
- Correcting the connection lock does **not** remove the idempotency hazard that the pre-check and
  the insert are separate statements; a durable fix should make accept's check-and-insert atomic
  (e.g. `INSERT ... ON CONFLICT` then return the stored receipt) rather than relying on catch-and-reread.

## Checked and clean (coverage)

- `_LockedConnection.commit`/`rollback`/`execute` overrides do take the RLock per call; the failure
  is scope, not absence.
- `configure_connection` applies `foreign_keys=ON`, WAL, `busy_timeout=5000`, `row_factory`; all
  correct.
- `receive_message` is a synchronous handler and `workers=1`; the single-process, multi-thread
  premise holds.
- Sender-side receipt handling (`runtime.py:974-995`) confirms that a 202 + `status:"accepted"`
  terminates retries, which is what makes the lost-custody outcome real.
- `uvicorn.run` uses one process, so the shared-connection analysis is not split across processes.
- `PeerRepository.upsert_peer` read-then-INSERT and `transition_peer`'s in-block
  `RepositoryError` are additional rollback sources, but I did not find two concurrent production
  creators of the same new node: bootstrap runs in `start()` before `_scheduler.start()`, and gossip
  receive only writes the cache, not `peers`. Left as the hunter's design risk #2, not promoted.

## Bound

- No live daemon, proxy, or load harness was run: the production **rate** of the collision is
  unmeasured and unmeasurable from the tree. This is the frequency cap, stated as a boundary.
- Whether a real sender retries fast enough to overlap its original's `INSERT`→`commit` window
  depends on the transport retry cadence and network timing; the tree does not let me ground it.
- Whether uvicorn's default threadpool actually runs two `receive_message` calls concurrently in a
  given deployment is standard FastAPI behaviour, not observed here.
- `lattice/storage/connection.py` and `lattice/storage/cache.py` are outside the hunter's assigned
  set; I read them for the mechanism and report the enabling site there.
