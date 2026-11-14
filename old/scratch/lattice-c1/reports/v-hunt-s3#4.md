# v-hunt-s3#4 — PRIMED VERIFIER on hunt-s3#4 (seam-s3.md finding 4)

Claim under test: `scratch/lattice-c1/reports/seam-s3.md` finding 4, "Shared durable connection: a
failing repository call rolls back another thread's in-flight claim (claim observed-but-lost)",
reported tier **S-**.

## Verdict

**ADJUSTED.** The claim's mechanism, trigger, and named outcome are each reproduced against source
and against an isolated sqlite3 experiment. Nothing in the finding is refuted. The correction is
severity/scope: the finding is scoped to a *bounded* victim (duplicate outbound send) and its tier
was S- ("needs one more pass"). The pass is now done — the mechanism is a real defect, not noise —
and the **same mechanism reaches a data-loss site the finding did not name** (a 202 returned with no
durable custody). Latent frequency caps the corrected tier at **L**, but the class severity is H if
its trigger population is ever grounded.

- Verdict: ADJUSTED
- corrected tier: **L** (was S-). Scoped victim = L; class worst case = H (latent).
- Reachability kind: **PRODUCTION, rare coincidence**. The exceptional repo call is reachable from
  the public `POST /lattice/v1/messages` route (concurrent duplicate accept), so a network peer can
  occupy the window; frequency is latent.
- Confidence: mechanism **traced + reproduced experiment**; trigger **traced**; frequency **latent /
  unproven**.

## Frame re-derived from source (not from the claim)

1. **One connection, shared.** `cli.py:702` `durable_conn = open_connection(durable_path)` is passed
   to `RuntimeCoordinator` (`cli.py:709`). `runtime.py:181` stores it; `runtime.py:190-195`
   constructs `PeerRepository`, `DomainPinRepository`, `OutboundMessageRepository`,
   `InboundMessageRepository`, `WebhookStateRepository`, `AuditLogRepository` all on the *same*
   `durable_conn`. Every `BaseRepository.__init__` just stores `self._conn = conn`
   (`repositories.py:55-56`). So the "transaction-per-workflow" docstring is really
   transaction-per-connection.
2. **Threads overlap.** `receive_message` is a sync `def` (`api.py:287`) → FastAPI runs it in the
   anyio worker threadpool. The delivery/maintenance tasks run on `self._delivery_executor` /
   `self._maintenance_executor` (`runtime.py:269-273`, 349-385). `uvicorn.run(..., workers=1)` does
   not serialize the anyio workerpool against those executors.
3. **The lock does not cover `with conn:`.** `_LockedConnection` overrides `execute`, `executemany`,
   `executescript`, `commit`, `rollback` to take a reentrant lock *per call* (connection.py:44-65).
   `__enter__`/`__exit__` are NOT overridden, so the lock is released between statements inside a
   `with self._conn:` block. `with conn:` uses `sqlite3.Connection.__exit__`, which calls
   `self.commit()` on success and `self.rollback()` on exception — i.e. a **connection-wide**
   rollback that discards every uncommitted write on the shared connection, from every thread.
4. **The victim window is real.** `OutboundMessageRepository.claim_pending` (`repositories.py:702`)
   does `UPDATE ... WHERE id IN (subselect)` then `SELECT * ... WHERE lease_owner=? AND
   lease_expires_at=?` inside one `with self._conn:` block; the commit happens only at `__exit__`.
   Between the two statements the UPDATE is uncommitted and the lock is not held.
   `InboundMessageRepository.create` (`repositories.py:870`) is a single `INSERT` inside
   `with self._conn:`; between the INSERT and the `__exit__` commit it is likewise exposed.

Experiment (Python 3.12, `sqlite3`, shared `check_same_thread=False` connection; script omitted for
brevity, output quoted):

- A's UPDATE → B raises `UNIQUE constraint` inside `with conn:` → B's `__exit__` rolls back → A's
  later SELECT reads the **pre-UPDATE** value; A's commit commits nothing. `final: ('a',)`.
- A's SELECT **before** B's rollback → A holds `[('leased',)]` (rows it no longer owns); final DB
  value reverted to `('a',)`. This is finding 4's exact claim, reproduced.
- A's INSERT → B's rollback → A's `with conn:` `__exit__` **commit is a no-op and does not raise**;
  `A2: success (accept would return 202)`, `row present: (0,)`.

## Component verdicts

- **Mechanism — CONFIRMED.** Connection-wide rollback of the shared connection discards another
  thread's uncommitted claim UPDATE. Reproduced.
- **Trigger — CONFIRMED (as mechanism).** An exceptional repository `with conn:` (e.g.
  `InboundMessageRepository.create` on a concurrent duplicate accept, `repositories.py:870`;
  `messages.py:285` handles the `UNIQUE constraint` branch; outbound `create` on duplicate admin
  submit) coinciding with a delivery worker between `claim_pending`'s UPDATE and its commit.
- **Outcome (scoped) — CONFIRMED.** Worker holds rows that are no longer leased; its subsequent
  `mark_terminal`/`release_lease` owner guards (`status='leased' AND lease_owner=?`) match nothing,
  return `False`, and runtime ignores the `False` (`runtime.py:1001`), so the message stays `pending`
  and is re-claimed/re-delivered; destination dedup by `(message_id, from_node)` bounds it to a
  duplicate HTTP send.
- **Frequency — NOT refuted, remains LATENT.** The finding already labels it unproven; I could not
  ground a cadence. Concurrent duplicate accepts of the same `message_id` require the destination to
  not yet hold the row yet receive two copies simultaneously (sequential duplicates short-circuit on
  `get_existing_receipt`, `messages.py:259`). The tree's own outbound path does not generate
  concurrent duplicates; the window is instead openable by the public route. Ungrounded → cap L.

## Sub-claims refuted

**None.** Mechanism, trigger, and the scoped L outcome each reproduced. The claim is accurate; it is
*incomplete*, not wrong. I explicitly decline to kill it — a kill here would be a reflexive
refutation of a defect I reproduced.

## Additional mechanism / new reachability on the same trace (the substantive correction)

**Inbound custody lost while returning 202 (invariant-5 violation).** Same mechanism, higher
consequence. In `InboundMessageService.accept` (`messages.py:241`), `self._repo.create(...)`
(`repositories.py:883`) runs inside `with self._conn:`. If a *different* thread's failing repository
call rolls the connection back after the INSERT and before `accept`'s `__exit__` commit, the INSERT
is discarded, the commit is a silent no-op, `create` returns normally, and `accept` returns the
signed **accepted** receipt. `api.py:354` then returns **202** with that receipt. No row exists:

- The sender validates an "accepted / durable custody" receipt and stops retrying (§8).
- The message is permanently lost (content was never durably stored).
- `runtime._audit_inbound_accepted` (`api.py:348` → `runtime.py:831` → `AuditLogRepository.insert`,
  a separate `with conn:` INSERT) can still **commit**, so the audit log records `INBOUND_ACCEPTED`
  for a message with no custody row — audit and durable state diverge.

This is the reportable "202 returned when custody was NOT durably established" case from the
preamble, and it is on the same trace as finding 4. Priced at the same latent frequency (cap L); if
the concurrent-duplicate population is ever grounded, this site is **H** (data loss).

**Class generalisation.** Any uncommitted write in *any* repository method's `with self._conn:`
block is exposed to any other thread's exceptional repository call. Claim, custody insert, mark
terminal, audit insert, rate-bucket save — all share one transaction. Finding 4 is one victim of a
class; guarding only `claim_pending` would not close it.

## Fix-direction constraints

- The lock must span the **entire** `with conn:` transaction, not each statement. `_LockedConnection`
  currently acquires/releases per `execute`, so it serializes statements but not transactions; two
  `with conn:` blocks interleave and share one transaction.
- A repair scoped to `claim_pending` (e.g. `RETURNING` / captured ids) fixes finding 4's instance but
  NOT the custody-loss site; the safe fix is one writer serialization point held across the whole
  `with conn:` block, or a connection-per-thread/per-repository pool.
- Because `mark_terminal`/`release_lease` return `False` and runtime ignores it
  (`runtime.py:1001,1005`), nothing in the system currently *detects* a lost claim; a repair should
  also surface the owner-guard miss rather than silently discarding it.
- Any fix must preserve at-least-once semantics; the destination dedup is load-bearing and should
  not be removed to "fix" duplicates.

## Checked and clean (coverage)

- The lock's per-statement scope and `_LockedConnection`'s non-override of `__enter__`/`__exit__`
  (connection.py:44-65) — verified directly.
- Single shared connection construction path (`cli.py:702-710`, `runtime.py:181-195`) — verified.
- `claim_pending` UPDATE→SELECT window and `create` INSERT window — read in full.
- `mark_terminal`/`release_lease` owner-guard predicates — verified; they correctly reject a
  no-longer-leased row (this is *why* the harm is bounded, not why it is absent).
- `accept` returns success unconditionally after `create` returns, with no re-read of durability
  (messages.py:241-308) — verified.

## Unreachable / bound

- No live daemon, no real WAL files, no real peer traffic. Behaviour verified with an isolated
  in-memory `sqlite3` connection (Python 3.12), not the live database, so multi-process WAL and
  busy-timeout interactions are unverified.
- The actual cadence of concurrent duplicate accepts in a deployment cannot be observed here
  (no live traffic / no test run); frequency stays latent by construction.
- That uvicorn's anyio workerpool actually overlaps the `ThreadPoolExecutor` threads is inferred
  from `workers=1` + sync route + `ThreadPoolExecutor` wiring, not measured under load.
- `tests/` was not executed; no failing-test evidence was produced for either reachability.
