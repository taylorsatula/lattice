# v-hunt-h1#1 — PRIMED VERIFIER

Claim under test: finding id `hunt-h1#1` in `scratch/lattice-c1/reports/hunt-h1.md`,
reported tier **L**. Verdict: **ADJUSTED** (mechanism confirmed; one named
sub-claim refuted; trigger picture corrected; frequency LATENT; severity L kept).

## Frame re-derived from source (before checking the claim)

Read independently: `lattice/storage/repositories.py` (`claim_pending` :708,
`release_lease` :745, `mark_terminal` :775, `expire_messages` :844),
`lattice/messages.py` (`RetryPolicy` :37, `OutboundMessageService.record_success`
:143, `record_failure` :158, `expire` :200), `lattice/runtime.py`
(`_RecurringTask` :110, executor split :269–275, scheduler :338–387,
`_run_outbound_delivery` :922, `_send_outbound_message` :949,
`_run_expiry_cleanup` :1134, `_write_audit_entry` :80),
`lattice/storage/connection.py` (`_LockedConnection`), `lattice/transport.py`,
`lattice/protocol/models.py` (`Message` :219), `lattice/api.py` (`admin_submit`
:385), `lattice/config.py` (:147), `tests/test_messages.py`, `tests/test_runtime.py`.

Independently established frame facts:

- **Executor split.** `outbound_delivery` runs on `_delivery_executor`;
  `expiry_cleanup` runs on `_maintenance_executor` (runtime.py:349–385). Distinct
  pools ⇒ the sweep and an in-flight delivery run **concurrently**. Confirmed.
- **Connection granularity.** `_LockedConnection` serializes each statement with
  an `RLock`, not the claim→flight→terminal *sequence*. The claim's "single
  serialized connection" point is true per-statement and does not close the race.
  Confirmed.
- **`expire_messages` predicate.** `WHERE status IN ('pending','leased') AND
  expires_at <= ?` (repositories.py:844-865); it nulls `lease_owner` and
  `lease_expires_at` and erases content. No lease-liveness guard. Confirmed.
- **`mark_terminal` predicate.** `... WHERE message_id = ? AND lease_owner = ?
  AND status = 'leased'` (repositories.py:775-800); returns `rowcount == 1`.
  After a sweep the row is `expired` with `lease_owner = NULL`, so it matches
  nothing and returns `False`. Confirmed.
- **Audit call site.** runtime.py:1001–1002:
  `self._outbound.record_success(message_id, owner)` immediately followed by
  `self._audit_outbound_delivered(...)`, return value not inspected. Confirmed.
- **`_write_audit_entry` writes the DB audit row only when the logger level is
  enabled** (`if logger.isEnabledFor(level)`, runtime.py:91–92). At default
  WARNING, `OUTBOUND_DELIVERED` (INFO) is **not** persisted. The divergence is
  therefore conditional on INFO logging being enabled — an extra precondition
  the claim did not name.
- **Transport gate reproduced.** `urllib3 2.3.0`;
  `PoolManager().urlopen("POST", "https://127.0.0.1:1/", body=..., fields=None,
  assert_hostname=..., preload_content=True)` raises
  `TypeError: HTTPConnectionPool._make_request() got an unexpected keyword
  argument 'fields'` (reproduced live). `_send_outbound_message` catches only
  `TransportError`, so the 202 path is unreachable today. Gate is real.

## Verdict and corrections

**Mechanism — CONFIRMED.** All four mechanism statements hold on the source as
read (sweep steals an actively-leased row; `record_success`→`mark_terminal`
returns `False`; runtime ignores the return; `OUTBOUND_DELIVERED` is written
unconditionally). Reproduced the transport failure independently.

**One sub-claim REFUTED — the trigger arithmetic.**
The finding states: *"realistic for a message to a peer that was unreachable most
of its TTL (backoff reaches the 24 h cap = the default TTL), where the last retry
lands just before expiry."* This is false. `RetryPolicy` (`messages.py:37-64`)
has `max_attempts = 10`, `base_delay_seconds = 60`, `max_delay_seconds = 86400`.
`should_retry(n) = n < 10`, so failures at `attempt_count` 1..9 release and
attempt 10 is terminal. The release delays are
`60,120,240,480,960,1920,3840,7680,15360` s (the 86400 cap is reached only at
`n >= 12`, which is never used); cumulative **30660 s ≈ 8.52 h** (≤ ~10.7 h with
+25 % jitter). A retrying message therefore terminates `failed` at ~8.5 h, far
short of the default 24 h TTL. With the default TTL a retrying message is
**never** claimable near its `expires_at`; the cited backoff-to-24 h pathway does
not exist.

**Trigger — corrected.** The race needs a delivery flight that straddles
`expires_at` while the row is leased. Because retries terminate at ~8.5 h, the
only realistic way is an operator-chosen TTL that lands inside a flight window
`[claim_time, claim_time + flight]`: most naturally a **short TTL**
(`admin_submit` accepts `ttl_seconds >= 1`, `api.py:396`, `Message.ttl_seconds
ge=1`, `config.default_ttl_seconds` may also be set below ~8.5 h). Example: TTL
≈ 60–100 s with the scheduled retry at t≈60 s, or a TTL of seconds so the first
delivery tick's flight crosses expiry. `claim_pending` requires `expires_at >
now`, so once the schedule jumps past expiry the row is no longer claimable and
just waits for the sweep — the race is confined to the single claim whose flight
spans the deadline. Reachability kind: **GATED behind `hunt-b1b#1`** (transport
`TypeError`); not reachable in tests either (no test drives a concurrent sweep
during a mocked 202; `tests/test_runtime.py:255` runs the 202 path at
`ttl_seconds=86400` with no interleaving, and `tests/test_messages.py:172`
expires a *pending* row, never a leased one).

**Frequency — corrected to LATENT.** The claim already conceded
"frequency ungrounded"; its population argument was the refuted 24 h path. The
actual population is operator submissions with a TTL small enough (< ~flight
duration past a claim, i.e. seconds to ~100 s) whose flight coincides with a
60 s sweep tick — no demonstrated deployment cadence produces this. Mark LATENT.

**Severity — L unchanged.** Outcome is a mislabeled terminal state plus a
misleading audit record; the remote peer holds custody, so there is no message
loss and no duplicate send (the row is terminal and excluded from
`claim_pending`). Not H (no loss/corruption/cross-peer/secret). Not M: the
divergence is a wrong local record/audit field, and its trigger is not "plausible
normal operation" — it needs an operator-chosen short TTL. If the product treats
`ttl_seconds` in the single digits as supported-normal, M would be arguable
(wrong custody/acknowledgment state); on the current evidence it stays L.

## Sub-claims refuted / narrowed

1. REFUTED: "backoff reaches the 24 h cap = the default TTL." Arithmetic above;
   cap unreachable within `max_attempts`.
2. NARROWED: "the expansion tick must fire during the HTTP flight" — true, but
   the flight must straddle `expires_at`, which the default-TTL retry schedule
   cannot produce. Trigger is short-TTL driven.
3. CORRECTED precondition: the DB/audit divergence only materializes when the
   `lattice.runtime` logger is at INFO; otherwise `_write_audit_entry` skips the
   DB insert and only the log line is emitted.

## Additional mechanisms / earlier failure sites (same trace)

- **Failure-branch variant.** If the swept row's flight then errors
  (`TransportError` / 5xx), `_send_outbound_message` calls
  `record_failure` → `release_lease`, whose predicate requires `lease_owner = ?
  AND lease_expires_at > ?`; the sweep nulled both, so it returns `False`
  silently, and `_audit_outbound_failed` still writes an `OUTBOUND_FAILED` audit
  for an already-`expired` row. Same root cause, opposite audit event.
- **Root site.** The earlier failure site is the missing lease-liveness guard in
  `expire_messages`; `record_success`'s ignored return is the downstream half.
- **Side (single-pass, not promoted):** all `record_*` returns in
  `_run_outbound_delivery`/`_run_webhook_delivery` are ignored, so this class of
  "worker's terminal transition silently lost" generalizes; no other instance
  has a demonstrated divergent-audit trigger.

## Fix-direction constraints

- Suppressing the false `OUTBOUND_DELIVERED` audit is **insufficient**: the row
  would still read `expired` while the peer holds durable custody — the custody
  divergence survives. A correct fix keeps the sweep from stealing a live lease,
  e.g. sweep only `status='pending'` or `status='leased' AND lease_expires_at <=
  now`; then the in-flight worker's terminal transition is authoritative.
- Do **not** loosen `mark_terminal`'s `status='leased' AND lease_owner` guard to
  "repair" the no-op — that would let a late worker overwrite a swept/erased row
  and is the safety property that makes the crash-recovery reclaim correct.
- The fix must preserve (a) reclamation of crashed-worker leases (expired
  `lease_expires_at`) and (b) erasure of TTL-expired content.

## Checked and clean

- `claim_pending`'s `expires_at > now` and `expire_messages`' `expires_at <= now`
  are disjoint — the row cannot be simultaneously claimable and expirable; the
  race in the claim is genuinely the concurrency window, not a predicate overlap.
- `_RecurringTask` non-overlap lock (:120-137) + ≥10 s interval prevents
  same-task re-entry; the race is cross-task (delivery vs expiry) and survives it.
- `expire_messages` erases content/extension/message_json and nulls lease state
  together (single UPDATE, transaction) — no partial-erasure window.
- `record_success(good)` returns `True` and erases (test_messages.py:104).

## Enumeration

The assigned claim's decisive statements, closed by composed commands:

```
rg -n "expire_messages|mark_terminal|record_success|_run_expiry_cleanup|_run_outbound_delivery" lattice --glob '!*.md'
rg -n "expire|leased|record_success|expiry_cleanup|expire_messages" tests/
rg -n "status IN" lattice/storage/repositories.py
```

Instance table:

| Site | Disposition |
|---|---|
| repositories.py:844 `expire_messages` | DEFECT (missing lease guard) — Finding 1 root |
| repositories.py:775 `mark_terminal` | correct (owner+leased guard); returns False after sweep |
| runtime.py:1001-1002 | DEFECT (ignored return + unconditional audit) |
| runtime.py:922 `_run_outbound_delivery` | examined — claim path, no re-check of row after flight |
| runtime.py:1134 `_run_expiry_cleanup` | examined — calls `expire()`, discards returned IDs |
| tests/test_messages.py:172 | examined — expires a pending row only; no leased-sweep coverage |
| tests/test_runtime.py:255 | examined — 202 path at ttl=86400, no interleaving |
| repositories.py:721/945 `status IN` | examined — unrelated claim/webhook predicates |

## Bound

- The race was **not executed end-to-end**: it is gated behind the transport
  `TypeError` (`hunt-b1b#1`), reproduced live, which aborts the delivery loop
  before any 202 handling. Mechanism is confirmed by reading; the trigger is
  arithmetically reachable only after that gate is repaired.
- Live peer latency distributions, scheduler jitter, and whether a real
  deployment issues `ttl_seconds` in the single/low-double digits are unverified.
- Actual `lattice.runtime` logger level in deployment (governs whether the audit
  DB row is written at all) is configuration-dependent and unread here.

## Design risks (max 2)

1. **TTL-expiry vs durable custody is unordered.** The sweep treats `expires_at`
   as locally authoritative even after a peer has accepted custody; any future
   late-returning delivery (or receipt-verification change) inherits this
   DB/audit divergence. A protocol rule ("expiry after custody transfer is a
   no-op") would settle it, but nothing in the tree encodes one.
2. **All worker terminal transitions ignore their boolean.** The ignored
   `record_success`/`record_failure`/`record_webhook_*` returns mean any future
   interaction that makes a row non-`leased` under a live worker reproduces the
   same class silently; no invariant asserts the terminal write succeeded.
