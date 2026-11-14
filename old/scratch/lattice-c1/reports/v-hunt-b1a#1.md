# v-hunt-b1a#1 — PRIMED VERIFIER of finding hunt-b1a#1

Claim under test: `hunt-b1a#1` [reported H] — "Shared durable connection: one thread's failed
repository block rolls back other threads' in-flight writes (lost audit rows; 202 'accepted'
receipt without durable custody)"; specified trigger = concurrent inbound `POST /lattice/v1/messages`
custody INSERT vs. an admin duplicate `POST /lattice/v1/admin/messages/submit` UNIQUE failure.

VERDICT: **ADJUSTED** — mechanism CONFIRMED; the cited trigger is REFUTED; frequency is unproven
(latent). Corrected tier **L**.

## Frame re-derived from source (before checking the claim)

- **One connection, many threads.** `cli.py:702` `durable_conn = open_connection(durable_path)`; the
  single connection is handed to `RuntimeCoordinator` (`cli.py:705-709`) which builds every durable
  repository on it (`runtime.py:190-195`, all six take `durable_conn`). `create_app(runtime)` shares
  the same runtime, and `uvicorn.run(..., workers=1)` (`cli.py:718-724`) serves the sync FastAPI
  routes off AnyIO's threadpool. Background executors (`runtime.py:269,273`) call the same
  repositories. So request threads and 6 executor threads do concurrently execute DML on one
  `sqlite3.Connection`.
- **Transaction shape.** `sqlite3.connect(...)` uses the default `isolation_level=""` (verified:
  `repr(c.isolation_level) == "''"` on both the system 3.12 and the venv 3.11). Every `execute` of
  DML implicitly opens one transaction on that connection; only `commit()`/`rollback()` end it.
  There are **34** `with self._conn:` sites in `repositories.py` (`rg` below), each of which commits
  on normal exit and **rolls back the whole connection transaction on any exception**.
- **The lock does not span the transaction.** `_LockedConnection` (`connection.py:29-61`) wraps each
  individual `execute`/`commit`/`rollback` call in an `RLock`. The transaction boundary is the
  `with self._conn:` statement in the repository, which the lock does not cover: between a
  repository's `execute` returning (lock released) and its `with`-exit, any other thread may run a
  failing `with self._conn:` block and roll back the shared transaction.
- **`__exit__` bypasses the overrides.** Empirically (throwaway scripts on 3.12.11 and 3.11.13):
  `with conn:` that raises calls rollback without invoking the Python-level `rollback` override
  (override call count stayed 0 while the concurrent row was discarded). The claim's note is correct.

## Findings

### 1. [L, latent] — `with self._conn:` on a single shared connection: one thread's rollback discards another thread's uncommitted durable write

- **Location:** `lattice/storage/connection.py:_LockedConnection`; `lattice/storage/repositories.py`
  (`with self._conn:` at 34 sites); reached from `lattice/api.py:receive_message` /
  `receive_gossip` / `admin_submit` (AnyIO pool) racing `lattice/runtime.py` delivery & webhook
  executors.
- **Evidence:** `class _LockedConnection` docstring "adds a coarse reentrant lock around the main
  mutating operations so a single connection can safely be shared" — but `_lattice_lock` is held
  only for the duration of one `execute`. `Connection.__exit__` (C level) issues the commit/rollback
  itself, so even `commit`/`rollback` overrides do not run under the lock when entered via `with`.
- **Mechanism (CONFIRMED):** Demonstrated on a faithful `_LockedConnection` repro. Thread A does
  `with conn: conn.execute(INSERT inbound M)` and is preempted after `execute`; thread B runs a
  failing `with conn:` block and its `__exit__` rollback discards A's uncommitted row. A's row is
  gone (`SELECT` returns `[]`). Identical result on 3.11 and 3.12.
- **Cited trigger (REFUTED):** The admin-duplicate path does **not** cause the loss. In
  `OutboundMessageService.submit` (`messages.py:110-135`) the order is
  `ensure_root_history(...)` (its own `with self._conn:` → **commit**) *then* `create(...)`. That
  first commit flushes any concurrent in-flight row before `create` can UNIQUE-fail, so the later
  rollback only discards B's own already-aborted INSERT. Reproduced: with the duplicate outbound row
  pre-committed and A's inbound INSERT held open, B's duplicate `create` raised `IntegrityError` but
  A's row survived (`inbound rows: [('M',)]`). The claim's own "related side fact" (an inbound
  duplicate short-circuits at `get_existing_receipt`) is likewise the reason the *inbound* duplicate
  path almost never reaches `create` at all.
- **Actual reachable triggers (all races):**
  1. Two concurrent inbound copies of the same `message_id` from the same node where thread B's
     `get_existing_receipt` runs *before* A's INSERT lands but B's `create` runs *after* it: B's
     `create` UNIQUE-fails → rollback discards A's row; A's `with`-exit commit becomes a no-op and
     A returns the signed `accepted` receipt → **HTTP 202 with no custody row** (invariant-5
     breach). `InboundMessageService.accept` then re-queries, finds nothing, and raises `CustodyError`
     for B → B answers 202 `rejected`.
  2. Concurrent gossip creating the same `node_id` through `PeerRepository.upsert_peer`
     (`repositories.py:189-249`): `get_peer` read then `INSERT` → UNIQUE → rollback.
  3. Genuine storage errors on any `with self._conn:` block (disk full / I/O error) → rollback of
     every concurrent uncommitted write, including `audit_log` rows from `_write_audit_entry`.
- **Frequency: UNPROVEN (latent).** The population (one shared connection across the AnyIO pool +
  6 executor threads, 34 commit/rollback blocks) is real and in-tree, but the trigger requires the
  failing thread's entire enter→execute→raise→`__exit__` sequence to land inside another thread's
  `execute`→`__exit__` gap (a sub-millisecond, usually zero-bytecode window with no blocking call
  in it). No caller in the tree makes the coincidence deterministic, and no test drives it. Per the
  pinned calibration an ungrounded frequency is LATENT → cap at **L**.
- **Outcome (impact if it fires):** a signed `accepted` receipt (HTTP 202) for a message with no
  durable custody row — the webhook never fires, the sender stops retrying, the message is lost;
  and/or silently absent `audit_log` rows. That impact is H-class, but the latency of the trigger
  and the unproven frequency bind the finding to L.
- **Confidence:** mechanism **traced + empirically reproduced**; cited trigger **traced + refuted**;
  frequency **unproven**.

## Sub-claims, individually

| Sub-claim | Verdict |
|---|---|
| All DML on the connection joins one implicit transaction (`isolation_level=""`) | CONFIRMED (verified) |
| `_LockedConnection` serializes only individual `execute` calls, not the `with` transaction | CONFIRMED |
| A failing `with self._conn:` block rolls back concurrent uncommitted writes | CONFIRMED (repro) |
| `Connection.__exit__` bypasses the Python `commit`/`rollback` overrides | CONFIRMED (repro, 3.11 + 3.12) |
| Trigger is an admin duplicate outbound submit at `api.py:406` | **REFUTED** — `ensure_root_history` commits first; duplicate path flushes, does not discard, peer rows |
| Inbound duplicate "does NOT raise UNIQUE" | CONFIRMED for the common case; INCOMPLETE — it can UNIQUE-fail in the narrow race (above), which is itself a trigger |
| 202 "accepted" without durable custody is reachable | CONFIRMED as a mechanism; trigger race-dependent |
| Frequency "coincidence race ... microsecond window" | admitted unproven by the hunter; remains UNPROVEN |
| Route named `POST /lattice/v1/admin/submit` | minor: actual route is `/lattice/v1/admin/messages/submit` (`api.py:385`) |

## Additional mechanisms / earlier failure sites / new reachability

- **Earlier failure site (root):** the defect originates in `_LockedConnection`'s premise that a
  per-`execute` lock is sufficient to share a connection. It is not, because the transaction
  boundary is the containing `with` statement, not the `execute`. Any repair confined to
  `connection.py`'s lock will not close the gap.
- **Distinct mechanism — non-atomic multi-statement workflows:** a thread's global `with`-exit
  commit can flush *another* thread's half-finished multi-statement block. `PeerRepository.add_block`
  (INSERT `blocks` then UPDATE `peers`) and `claim_pending`/`claim_for_webhook` (UPDATE then SELECT)
  lose per-workflow atomicity: an intervening foreign commit persists the first statement while the
  second may still roll back. This can produce partial state (`blocks` row present, `peers.state`
  not `blocked`) even without a full transaction loss.
- **New reachability:** `PeerRepository.upsert_peer`'s read-then-INSERT under concurrent gossip for
  the same `node_id` is a second, independent UNIQUE-rollback trigger on the durable connection.

## Fix-direction constraints

A repair must give each workflow a transaction boundary that is independent of the shared
connection's global commit/rollback state. Merely widening `_LockedConnection`'s lock to cover a
block does not exist as a hook (the `with` is in the repository, not the connection); the viable
directions are (a) a thread-local/per-workflow connection with a single writer serialization point,
or (b) an explicit process-wide write lock held for the whole `with self._conn:` block plus
`BEGIN IMMEDIATE`, or (c) removing implicit transactions (`autocommit=True`) and writing explicit
`BEGIN`/`COMMIT`/`ROLLBACK` that are lock-held end to end. A fix must also preserve the custody
ordering — `ensure_root_history` and `create` must remain atomic per workflow so a later failing
sibling cannot undo `create`. Escaping the *structure*-breaking (the C-level `__exit__` bypassing
the lock) is necessary but not sufficient; the fix must prevent one workflow's `ROLLBACK` from
unwinding a peer workflow's durable-intent write.

## Checked and clean

- `receive_message`'s `accept` → receipt → 202 sequence is internally consistent; the
  duplicated-signed-receipt path (`get_existing_receipt`) is idempotent and byte-identical.
- `admin_submit` correctly maps `CustodyError` (a `ValueError`) and `RuntimeError` to 400; it does
  not mislabel the duplicate as accepted.
- The `with self._conn:` commit-on-success / rollback-on-exception semantics are correct *for a
  single-threaded owner*; no repository method builds malformed SQL or wrong column order on the
  paths read.
- `_write_audit_entry` level gating and insert shape are correct.
- No global lock exists that would mask the race; the absence was verified by enumerating
  `threading`/`Lock`/`RLock` uses (`rate_limit.py`, `peers.py`, `runtime.py:256/897-918` are all
  unrelated per-service locks).

## Enumeration

```
rg -n "with self\._conn:" lattice/storage/repositories.py | wc -l          # -> 34
rg -n "raise (RepositoryError|CustodyError|StorageError|PeerError)" lattice/storage/repositories.py lattice/messages.py
  # repositories.py:262 transition_peer (missing-peer guard, callers pre-check) — only in-with raise
  # messages.py:131 outbound duplicate; :290 inbound "failed to accept" — both issue AFTER create's rollback
rg -n "open_connection\(|initialize_cache_db\(" lattice/cli.py lattice/runtime.py
  # cli.py:702 single daemon durable_conn
rg -n "_LockedConnection|_lattice_lock" lattice/storage/connection.py
```

Instance disposition:

| Instance | Disposition |
|---|---|
| 34 `with self._conn:` blocks | mechanism site; commit/rollback global to connection — finding |
| `repositories.py:262` in-`with` `raise RepositoryError` | reachable only if `transition_peer` called on missing peer; all in-tree callers pre-check — examined, weak trigger |
| `messages.py:131` outbound duplicate | refuted as trigger (preceding commit) |
| `messages.py:290` inbound "failed to accept" | issues *after* the create rollback; the rollback is the defect, not the raise |

## Bound

- Not run against the deployed WAL database under production concurrency; the interleaving was
  demonstrated on in-memory `_LockedConnection` repros on 3.11/3.12 only. `busy_timeout`/WAL
  behaviour under real thread contention is unobserved.
- `isolate_level`/`autocommit` behaviour on Python ≥3.13 (where `autocommit` default changed) not
  tested; the tree pins 3.11 (venv) / 3.12 (system).
- `cli.py`/`api.py` were read on the serve/lifecycle and the four message/admin routes; full-file
  review of those belongs to other hunts.
- Could not reach live provider/network behaviour (webhook delivery timing, sender retry cadence)
  that would ground the duplicate-inbound frequency; that is why frequency stays latent.

## Side discovery (single-pass candidate, not folded into the verdict)

- `_circuit_record_success` / `_circuit_record_failure` (`runtime.py` ~line 800-825) issue
  INSERT/UPDATE on the **cache** connection with no `with conn:` and no commit; visibility depends
  on sharing the connection and on incidental commits by unrelated threads, and the writes are lost
  to any cache-side rollback. Same class as finding 1 on the cache connection. Priced: severity
  **L–M** (circuit-breaker state silently resets, reopening delivery to a failing peer), frequency
  **latent** (needs a cache rollback), trigger reachability **gated** behind cache-connection
  interference. Fix-direction: commit the circuit writes explicitly or run them inside a per-op
  transaction; do not rely on another thread's `with` to persist them. Needs a dedicated pass.
