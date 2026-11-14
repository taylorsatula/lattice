# v-hunt-q-error#3 — PRIMED VERIFIER

Claim under test: `hunt-q-error#3` in `scratch/lattice-c1/reports/q-error.md`, reported tier **M**
("Transient storage failure is converted into a final 'rejected' custody receipt").
Verdict: **ADJUSTED** — mechanism CONFIRMED, severity corrected **M → L**, frequency label
"DEMONSTRATED" refuted and re-grounded as **LATENT**. Reachability: **PRODUCTION, environment-armed**
(requires a local durable-storage fault; not remotely triggerable).

---

## Frame re-derived from source (before reading the claim's conclusion)

Enumerator for the producer/consumer of the `rejected` receipt on this path:

```
rg -n '"rejected"' lattice/ -g '*.py'
rg -n "CustodyError|failed to accept|build_receipt|ensure_root_history|busy_timeout|UNIQUE" lattice/api.py lattice/messages.py lattice/storage/repositories.py lattice/storage/connection.py lattice/migrations/durable/001_initial.sql
```

Independently established facts:

- `InboundMessageService.accept` (`messages.py:250-290`): `Message.model_validate` and
  `get_existing_receipt` run first; `self._peer_repo.ensure_root_history(...)` and
  `self.build_receipt(...)` run **before** the `try`; only `self._repo.create(...)` is inside the
  `try`. The `except` wraps every non-UNIQUE exception as
  `raise CustodyError(f"failed to accept message: {exc}")` (`messages.py:284-290`). The UNIQUE
  branch first re-checks `get_existing_receipt` and only falls through to `CustodyError` when that
  returns `None`.
- `api.py:338-345` (`receive_message`): `except CustodyError:` builds a signed `"rejected"` receipt
  (`build_receipt(str(message.get("message_id","")), "rejected")`) and returns
  `JSONResponse(status_code=202, content=rejected)`. Nothing is persisted. The neighbouring
  `except RuntimeError` returns 400.
- The only other `except` between the route and here is `except RuntimeError` at `api.py:301`; there
  is **no generic `Exception`/`sqlite3.OperationalError` handler** in `create_app` (only
  `RequestValidationError` and `HTTPException` handlers, `api.py:136-175`). An uncaught
  `sqlite3.OperationalError` therefore becomes Starlette's default 500 (text/plain), not problem
  details.
- `accept` is called at `api.py:335-336` only after: `verify_inbound_message` (which itself runs
  `Message.model_validate` and raises `RuntimeError` on invalid input → 401), the cold-sender 503
  return, the recipient-ownership check, and `rate_limiter.allow_message`. So by the time `accept`
  runs, the body is schema-valid and signature-verified; the *only* way `accept` raises
  `CustodyError` is a failure inside `self._repo.create` (a genuine UNIQUE collision that survives
  the race branch, or a storage exception).
- `connection.py`: `DEFAULT_BUSY_TIMEOUT_MS = 5000`, `PRAGMA journal_mode = WAL`, single shared
  `_LockedConnection` with a re-entrant lock around each statement/commit — but **not** held across
  a whole transaction. So intra-process contention is serialised per statement; cross-process
  contention (a CLI writer against the same durable DB) is the real BUSY source.
- `001_initial.sql`: `inbound_messages.message_id TEXT NOT NULL UNIQUE` — single-column unique, so a
  UNIQUE failure with a *different* `from_node_id` is the only collision that reaches the
  `CustodyError` branch.
- `PROTOCOL.md §8` (`docs/PROTOCOL.md:237-250`): a `rejected` receipt "indicates the destination node
  will not take custody (e.g., recipient blocked, message malformed after signature check)… a
  `202 Accepted` with a rejected receipt is final", and "The receipt bytes MUST be persisted and
  returned identically for duplicate `message_id` values."
- Sender side (`runtime.py:978-1000`): a 202 whose body `status != "accepted"` is logged
  `"invalid custody receipt"`, audited `OUTBOUND_FAILED reason="invalid custody receipt"`, and
  `record_failure(retryable=True)`. In-tree, nothing honours §8 finality (the blocked-sender test
  records the *destination's* view, not a sender-side finality path).

## Component adjudication

| # | Component | Verdict |
|---|---|---|
| a | `accept` converts any `self._repo.create` exception into `CustodyError` (includes transient sqlite I/O, disk-full, BUSY beyond 5 s) | CONFIRMED |
| b | `api.py:339` returns 202 + a signed `"rejected"` receipt on that `CustodyError` | CONFIRMED |
| c | This misclassifies an inability-to-write as a deliberate final refusal (§8 `rejected` is final) | CONFIRMED |
| d | The receipt is not persisted, violating §8's "persisted… identically for duplicate `message_id`" | CONFIRMED (added, not in claim) |
| e | Trigger: a signature-verified inbound message arriving during a durable-write failure | CONFIRMED mechanism; the *cadence* is ungroundable |
| f | Frequency: "DEMONSTRATED" | **REFUTED** — LATENT |
| g | Producer list includes "cross-node `message_id` collision" as a concrete trigger | **REFUTED as a realistic trigger** — see below |
| h | Outcome today: our own sender retries anyway (Finding 2 masks loss) | CONFIRMED |
| i | Correct signal for a transient failure is 503 + Retry-After | CONFIRMED as fix direction |

### Why f is refuted (frequency)

The claim itself concedes: "I cannot ground a rate; the trigger requires a storage fault or a
cross-node `message_id` collision." The standing calibration is explicit — *a frequency you cannot
ground is LATENT by definition, say so and cap at L*. There is no routine inbound path into this
`except`: the body is already schema-validated upstream (`verify_inbound_message`), and the storage
failure it depends on is a durable-write fault (disk-full / I/O error / cross-process `SQLITE_BUSY`
beyond 5 s). Within the daemon there is exactly one shared `_LockedConnection`, so no intra-process
BUSY; only an operator CLI command writing the same durable DB concurrently (a rare, short-lived
action) or a disk fault arms it. This is an environment-armed condition with no cadence — LATENT,
cap L.

### Why g is refuted (the collision producer)

`inbound_messages.message_id` is single-column UNIQUE, and the UNIQUE branch first calls
`get_existing_receipt(message_id, from_node_id)` and returns the stored receipt on a hit. A collision
reaches `CustodyError` only when the *same* `message_id` exists under a *different* `from_node_id`.
UUIDv7 has 74 random bits — a birthday collision is negligible; a deliberate one requires the
attacker to know a `message_id` the node already holds from another sender, and messages are not
relayed through gossip (invariant 6) nor exposed by any route, so no in-tree path leaks one. The
collision producer is effectively unreachable and should not count toward the finding's trigger
population.

## Corrected severity — M → L

Mechanism and the reportable-invariant violation stand: invariant 5 flags "a 202 returned when
custody was NOT durably established", and §8 makes `rejected` a *deliberate, final* refusal. But the
severity scale's M gate is "…under a plausible normal operation". The only trigger here is a durable
storage fault or a negligible collision, neither of which is a normal-operation cadence. Per the
calibration's latent cap, corrected to **L**: a real defect (false finality / false audit statement)
with a narrow, environment-armed trigger. The impact *if* it fires is large for a conformant
external sender (every message during the storage outage is permanently dropped), which is why L
and not S-.

## Additional mechanisms / earlier failure sites (same trace)

1. **The storage-fault disposition is split and inconsistent.** Inside `accept`,
   `get_existing_receipt` (read), `ensure_root_history` (write), and `build_receipt` (signing) all
   sit **outside** the `try`. A durable-storage exception in `ensure_root_history` (or
   `get_existing_receipt`) is a raw `sqlite3.OperationalError`, which neither `except CustodyError`
   nor `except RuntimeError` catches → uncaught → Starlette default **HTTP 500, plain text**, no
   receipt at all. So a disk fault yields *either* 202+`rejected` (fault in `repo.create`) *or* 500
   (fault in `ensure_root_history`) depending only on the failing statement. Same trace, two
   dispositions, no barrier to reproduction other than the fault itself.
2. **The `rejected` receipt is not persisted** (claim does not state this). `build_receipt` signs and
   returns but `api.py:339` never writes it. §8 requires the receipt bytes be persisted and returned
   identically for duplicate `message_id`s; here a duplicate gets a freshly-signed, different receipt
   (new `received_at` → different bytes). This also makes the transient-failure path accidentally
   recoverable today: a duplicate sent by a retrying sender gets a fresh attempt and can be accepted
   once storage recovers. Any fix must not rely on this accident.
3. **Cross-process write contention is the only realistic arming mechanism** (read of
   `connection.py`): a single shared `_LockedConnection` serialises daemon threads per statement, so
   `SQLITE_BUSY` cannot arise intra-process; only a separately-opened CLI connection (or disk fault)
   arms it. Recorded as the frequency ground, not a separate finding.

## Fix-direction constraints

- Distinguish transient storage failure from a deliberate refusal. Transient → **503 + Retry-After**
  (§9), not 202+`rejected`. The 202+`rejected` disposition is correct only for the deliberate
  refusal it was written for (blocked sender, malformed-after-signature).
- Put **all** durable-storage statements in `accept` under the same disposition. Today
  `ensure_root_history`/`get_existing_receipt` fail to 500 while `repo.create` fails to
  202+`rejected`; a repair must not leave the 500 branch behind.
- If a `rejected` receipt is retained for any create-failure path, it **must be persisted** and
  returned byte-identically for duplicate `message_id`s (§8); today it is neither.
- This fix is **coupled to Finding 2** (`runtime.py:978-1000`). Today Finding 2 masks the data loss
  (the sender retries a `rejected` receipt). Repairing Finding 2 to honour §8 finality *before* this
  finding is repaired turns every storage-outage message — including from a conformant foreign
  sender that already honours §8 — into permanent silent loss. The transient-vs-final distinction
  must land with, or before, Finding 2's repair.

## Bound (could not reach)

- No live infrastructure: whether the daemon's `SQLITE_BUSY` beyond the 5 s `busy_timeout` is
  actually reachable against the real CLI write patterns (their transaction durations), and
  disk-full behaviour, are argued from `connection.py`/`repositories.py`, not measured.
- Intra-daemon transaction interleaving: `_LockedConnection` locks per statement/commit, not per
  transaction, so two daemon threads could in principle interleave into one transaction and commit
  each other's writes. I could not reproduce an `OperationalError` from this, so it is recorded as an
  unproven frequency amplifier and a possible independent durability hazard, not as a trigger for
  this finding.
- Sender-side conformance: whether a given federated peer honours §8 finality is out of tree
  (SUSPECTED — upstream/external implementation unverifiable). Our own sender demonstrably does not.

## Checked and clean

- The `CustodyError` type and its wrap sites (`messages.py:284-290`) re-raise with cause and message
  context — correct aside from the misclassification above.
- `build_receipt` signs correctly (`sign_receipt`, `messages.py:291-315`); the blocked-sender 202
  path (`api.py:293-299`) and its test (`tests/test_api.py:281-332`) confirm the intended §8
  semantics for a deliberate refusal — the transient path is the anomaly.
- The idempotency pre-check/race branch for `(message_id, from_node_id)` (pre-check at
  `messages.py:265`, UNIQUE race re-check in the `except`) returns stored receipts byte-identically —
  correct for the accepted path.
- `connection.py` pragmas (`foreign_keys`, WAL, 5 s busy timeout) and `_LockedConnection` statement
  serialisation read as intended.
- The sender's 202-receipt validation field check and its retryable disposition
  (`runtime.py:978-1000`) — read; the misstatement here is Finding 2's, not re-reported.

## Enumeration

Composed command (closes the create-failure → rejected class):

```
rg -n '"rejected"|CustodyError|build_receipt|ensure_root_history|repo\.create' \
   lattice/api.py lattice/messages.py
```

| Site | Disposition |
|---|---|
| `messages.py:265` `get_existing_receipt` | pre-check, outside `try` |
| `messages.py:275` `ensure_root_history` | outside `try` → **500 on storage fault** (added mechanism) |
| `messages.py:280` `build_receipt` (accepted) | outside `try` |
| `messages.py:283` `self._repo.create` | inside `try` → `CustodyError` → **202+rejected** (claim) |
| `api.py:293` `except BlockedSenderError` | 202+rejected, deliberate refusal, intended |
| `api.py:301` `except RuntimeError` | 401 |
| `api.py:339` `except CustodyError` | 202+rejected, misclassified transient — **the claim** |
| `api.py:346` `except RuntimeError` | 400 |

No other producer of `"rejected"` receipts exists (`rg '"rejected"'` returns only
`models.py:310` Literal, `api.py:277/298/343`, `messages.py:297/303`).
