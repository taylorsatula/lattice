# v-hunt-s3#3 — PRIMED VERIFIER

Claim under test: **hunt-s3#3** in `scratch/lattice-c1/reports/seam-s3.md`, reported tier **L** —
"claim re-select returns rows from any same-owner claim with the same lease expiry".

Adversarial and symmetric. Re-derived the frame from source before checking the claim.

---

## Re-derived frame (independent of the claim)

- `lattice/storage/repositories.py:28-31` (`_format_ts`) truncates to whole seconds:
  `when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")`. Absolute seconds granularity; two
  datetimes in the same wall-clock second format to the **same string**.
- `OutboundMessageRepository.claim_pending` (repositories.py:702-740): inside one `with self._conn:`
  block it (1) runs an `UPDATE ... WHERE id IN (SELECT ... LIMIT ?)` that sets `status='leased'`,
  `lease_owner=owner`, `lease_expires_at=now+5min`, then (2) **re-queries** with
  `SELECT * FROM outbound_messages WHERE lease_owner = ? AND lease_expires_at = ?` using the
  computed `now+5min` string, **not** the ids the UPDATE touched. The `limit` is applied only to
  the UPDATE subselect; the re-select has no `LIMIT`.
- `InboundMessageRepository.claim_for_webhook` (repositories.py:928-972) is the identical pattern
  against `inbound_messages` / `webhook_lease_owner` / `webhook_lease_expires_at`.
- Caller: `lattice/messages.py:134-141` `OutboundMessageService.claim_for_delivery(owner, limit)` →
  `claim_pending(owner, self._clock.now(), limit)`; and `messages.py:318-325` for webhook.
- Runtime caller: `lattice/runtime.py:922-924` `_run_outbound_delivery` →
  `owner = f"delivery-{threading.current_thread().name}"`, one `claim_for_delivery(owner, limit=5)`
  per invocation. `runtime.py:1021-1023` is the webhook twin with prefix `webhook-`.
- Scheduling: `runtime.py:112-136` `_RecurringTask.maybe_run` gates on
  `now - _last_run < interval_seconds` (monotonic `now`) plus a non-blocking `_lock`; the
  scheduler thread ticks at `tick_seconds=1.0` (`runtime.py:139-156`). Default intervals
  `delivery_interval_seconds=10.0`, `webhook_interval_seconds=10.0` (`runtime.py:101-102`).
- Production wiring: `lattice/cli.py:705-716` constructs `RuntimeCoordinator` **without** a
  `settings=` argument, so `runtime.py:186 self._settings = settings or RuntimeSettings()` uses the
  10.0 s defaults. `RuntimeSettings` is only overridden in tests (`tests/test_runtime.py:109`,
  `tests/test_api.py:111`, both 60.0).

**Mechanism reproduced (isolated in-memory experiment against the real repository classes).**
Three pending messages, one owner, one wall-clock second:

```
claim1 (same second): ['m1']              count 1   # limit=1
claim2 (same second): ['m1', 'm2']        count 2   # limit=1 VIOLATED
claim3 (same second): ['m1', 'm2', 'm3']  count 3   # limit=1 VIOLATED
claim4 (now+1s):      []                  count 0
rows: m1/m2/m3 status=leased attempt_count=1 lease_owner=worker-1
      lease_expires_at=2026-01-01T00:05:00Z   (all identical)
```

The second and later same-second claims re-select the earlier claim's still-leased rows. The UPDATE
subselect does not re-touch them (`lease_expires_at > now`), so `attempt_count` stays 1.

## Modified claims and refutation

### Confirmed
- **Mechanism.** Re-select by `(owner, now+5min-string)` returns every row the same owner leased in
  the same wall-clock second, not the rows this call claimed. Reproduced above; identical code in
  `claim_for_webhook`. Confidence: traced + experiment.
- **Production unreachability as the finding states.** `owner` embeds
  `threading.current_thread().name`; the delivery executor is one pool with unique thread names
  (`runtime.py:269-272`, `thread_name_prefix="lattice-delivery-"`). Only `_run_outbound_delivery`
  claims `outbound_messages`, and its `_RecurringTask` runs at most once per 10 s. `now` is wall
  clock; two claims therefore format to different second-truncated expiries. No live path produces
  two same-owner, same-second, still-leased claims. Confidence: traced.

### Refuted sub-claims
1. **"reachable through the test suite" — REFUTED (reachability kind is LATENT, no path in tree).**
   I enumerated every `claim_for_delivery`/`claim_for_webhook` occurrence in `tests/`
   (`rg -n 'claim_for_(delivery|webhook)' tests/`): `tests/test_messages.py:99,111,130,137,153,167,168,219,238,244,259`.
   Every same-owner repeat is separated by `record_failure`/`record_success` (which releases the
   lease) **and** `clock.advance(10 min)` (`test_messages.py:127-133, 236-242`); the only same-second
   pair uses *different* owners (`worker-1` then `worker-2`, lines 167-168). The runtime tests call
   `_run_outbound_delivery`/`_run_webhook_delivery` exactly once per test
   (`test_runtime.py:290,315`). No test, frozen clock or otherwise, executes a same-owner,
   same-second second claim with a residual lease. It is reachable only by a **newly written**
   frozen-clock test, i.e. the trigger is ungrounded — LATENT, not TESTS-ONLY. The preamble's
   TESTS-ONLY class means reachable through the existing suite/mocked dependency; that box is not
   ticked.
2. **"double-incremented attempt counts" — REFUTED.** The UPDATE's subselect requires
   `lease_expires_at <= now`; rows already leased by the same owner in the same second are excluded,
   so they are not re-updated. Experiment shows `attempt_count=1` for all three rows after three
   claims. Only the returned list is duplicated; the counter is not.
3. **"processed by two workers concurrently" / "another worker's rows" — REFUTED.** The re-select
   filters on `lease_owner`; the colliding rows belong to the *same* owner. Since `owner` encodes
   the thread name, that means the **same caller/thread** receives the same rows twice, not two
   concurrent workers. The accurate outcome is intra-caller duplicate processing and a return list
   longer than `limit`.

### Frequency correction
Finding says TESTS ONLY. Corrected: **LATENT / constructed** — no production path (confirmed) and
no current test path (refuted above). Per calibration an ungroundable frequency is latent and caps
at L.

## Severity correction

Tier left at **L**, unchanged, with the trace: the only bad outcome is a caller receiving duplicate
leased rows (duplicate outbound POST / duplicate webhook call) inside the 5-minute lease window,
bounded by destination-side `(message_id, from_node)` dedup; no data loss, no cross-peer/cross-user
reach, no corruption. The demonstrated mechanism rules out S-; the absent trigger rules out M.

## Reachability kind

**LATENT / CONSTRUCTED** — no live path today (confirmed by the scheduling trace above) and no
existing test reaches it (refuted above). Not gated behind another defect. A repair is a robustness
fix, not an urgent one; the observable symptom appears only under a frozen/repeating clock or a
future sub-second scheduler.

## Added mechanisms / earlier failure sites / new reachability

- **`limit` is not enforced on the return path.** The `LIMIT ?` constrains only the UPDATE
  subselect; the re-select has no `LIMIT`, so a same-second collision returns more than the
  caller's requested `limit` (experiment: `limit=1` returned 2 then 3 rows). Any caller that sizes
  batches from `limit` is exposed the moment a collision exists — same latent trigger, broadened
  symptom.
- **Same mechanism is duplicated in `claim_for_webhook`** (repositories.py:928-972). The finding
  names this; it is a second instance of the identical defect, so a repair touching only
  `claim_pending` leaves the inbound custody path unfixed.
- **Exotic production trigger, not counted:** because `_RecurringTask` measures the interval on
  `time.monotonic()` while `_format_ts` uses `clock.now()` (wall), a backward wall-clock step of
  ≥ the interval between two runs could land two claims in the same wall second. Operator
  clock-stepping is not normal operation and I could not ground a cadence; recorded as a bound, not
  a finding.

## Fix-direction constraints

- Capture the ids the UPDATE claimed (SQLite `RETURNING`, or re-select by the claimed `id` set)
  instead of re-querying by `(owner, computed-expiry-string)`. A repair that only adds
  `AND status='leased'` to the re-select is insufficient: the colliding rows *are* `leased`.
- Apply the same fix to both `claim_pending` and `claim_for_webhook`.
- Do not rely on "the same owner cannot claim twice in one second"; that assumption is enforced
  nowhere in the repository layer and is exactly what breaks.
- `RETURNING` requires SQLite ≥ 3.35; if the deployed floor is lower, re-select by the claimed id
  set (requires capturing ids) rather than by the expiry string.

## Checked and clean

- `claim_pending`/`claim_for_webhook` UPDATE predicates (`status IN (...)`, `next_attempt_at <= now`,
  `expires_at > now`, lease-takeover clause) are otherwise correct; expired-lease takeover is
  deliberate.
- `release_lease`/`mark_terminal`/`release_webhook_lease` owner guards (`lease_owner = ? AND
  status='leased'` / `lease_expires_at > now`) correctly prevent a foreign owner from mutating
  another caller's row.
- Default intervals (`delivery=10.0`, `webhook=10.0`) and the 1.0 s scheduler tick, read from
  `RuntimeSettings` and `_RuntimeScheduler`; `cli.py` serve uses defaults, so the production
  cadence asserted in the finding is accurate.
- One claim invocation per `_run_outbound_delivery`/`_run_webhook_delivery`; non-overlap lock
  prevents a second concurrent invocation of each task.

## Enumeration

```
rg -n "claim_for_(delivery|webhook)|claim_pending" tests/ lattice/ --glob '!*.pyc'
```
Output (call sites): `lattice/messages.py:134,141,318,325`; `lattice/runtime.py:924,1023`;
`lattice/storage/repositories.py:702,928`; tests `tests/test_messages.py:99,111,130,137,153,167,168,219,238,244,259`.
Disposition: every test instance separated by lease release + 10 min clock advance, or by a
different owner — examined-clean for this defect.

## Bound

- No live daemon or WAL database was run; the mechanism was verified with the real repository
  classes against a fresh migrated temp SQLite DB (Python 3.12), not the deployed files.
- The full test suite was not executed; TESTS-ONLY reachability was settled by enumerating and
  reading every claim call site in `tests/` plus the clock fixtures, not by a failing/passing run.
- Third-party production overrides of `RuntimeSettings` (outside `cli.py`) are not visible in the
  tree; if a future caller passes `delivery_interval_seconds < 1`, the trigger becomes
  production-reachable. Recorded as a boundary, not asserted.
