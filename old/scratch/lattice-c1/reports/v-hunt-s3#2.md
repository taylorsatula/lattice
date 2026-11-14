# v-hunt-s3#2 — PRIMED VERIFIER

Claim under test: `seam-s3.md` finding 2 (journal id `n#2`, titled there "Expiry task expires
in-flight leased delivery"), reported tier **L**, reachability declared **PRODUCTION**.

**Verdict: ADJUSTED.** Mechanism CONFIRMED at the statement level; the distinctive *outcome*
(a delivered-and-acknowledged message recorded as `expired`) is **GATED behind OV-2** (every
`OutboundTransport.request()` raises before network I/O) and therefore cannot occur in the tree
today. Trigger description also corrected: the in-flight window is up to ~200 s, not ~40 s.
Tier unchanged at **L**.

## Frame re-derived from source (not from the claim)

- `OutboundMessageRepository.expire_messages` (`lattice/storage/repositories.py:844`): single
  `UPDATE ... SET status='expired', lease_owner=NULL, lease_expires_at=NULL,
  next_attempt_at=NULL, content=?, extension=NULL, message_json=? WHERE status IN
  ('pending','leased') AND expires_at <= ? RETURNING message_id`. **No lease guard.** Confirmed.
- `claim_pending` (`repositories.py:702`): claim predicate requires `expires_at > ?` (claim-time
  now) and `(lease_owner IS NULL OR lease_expires_at <= ?)`, sets `lease_expires_at = now+5min`.
  Confirmed.
- `mark_terminal` (`repositories.py:775`): `WHERE message_id=? AND lease_owner=? AND status='leased'`.
  Returns `cursor.rowcount == 1`. Confirmed.
- `create` (`repositories.py:666`): writes `next_attempt_at = created_at` (3rd-from-last `?`), so
  a fresh message is immediately claimable; `RetryPolicy` (`messages.py:46`) base delay 60 s with
  ±25% jitter, independent of `expires_at`.
- Runtime: `_run_expiry_cleanup` (`runtime.py:1134`) runs on `maintenance_executor`, every
  `expiry_interval_seconds=60`; `_run_outbound_delivery` (`runtime.py:922`) claims up to 5 and
  processes them **sequentially**, on `delivery_executor` (4 workers) → the two run concurrently.
- `_send_outbound_message` (`runtime.py:970`): only the 202+valid-receipt branch calls
  `record_success` (`runtime.py:1001`), whose `bool` return is discarded, then
  `_audit_outbound_delivered`. `TransportError` is caught; other exceptions are not.

## Sub-claim dispositions

| Sub-claim | Disposition |
|---|---|
| `expire_messages` matches actively-leased rows (`status IN ('pending','leased')`, no lease guard) | CONFIRMED — mechanism, source-verified |
| Row is flipped to `expired` and content erased mid-flight | CONFIRMED — same statement |
| `mark_terminal` then matches nothing; `False` ignored | CONFIRMED — `runtime.py:1001` discards return; guard requires `status='leased'` |
| Window "up to ~40 s read timeout" | REFUTED (understated) — a worker claims `limit=5` and processes sequentially, so a row later in the batch can be in-flight for up to ~5×(connect 10 s + read 30 s) = ~200 s. `DEFAULT_TIMEOUT = urllib3.Timeout(connect=10.0, read=30.0)`, `transport.py:18`. |
| Outcome: durable row `expired` while audit says `OUTBOUND_DELIVERED` | REFUTED as reachable-today — GATED behind OV-2. `transport.request()` always raises (`fields=` and `assert_hostname=` are not accepted by `HTTPConnectionPool._make_request`), so the 202 branch is never entered and `record_success` is never called. Reproduced below. |
| "audit and durable state diverge" | PARTIALLY REFUTED — `_audit_outbound_delivered` writes only when `logger.isEnabledFor(logging.INFO)` (`runtime.py:80-92,843`). At WARNING+ no audit row exists, so the *divergence* disappears while the wrong `expired` durable status remains. |
| "No re-delivery or data loss" | CONFIRMED — `list_pending` and `claim_pending` exclude `expired` (`repositories.py:820,702`); content erased either way. |
| Frequency | CONFIRMED LATENT — see below. |
| Reachability kind | CORRECTED to **GATED behind OV-2**; the residual lease-flip mechanism is production-reachable but naked (no delivery completes today). |

## Reproduced evidence

```
$ python3 -c "import urllib3; urllib3.PoolManager().urlopen('POST','https://127.0.0.1:9/x',
  body=b'{}', headers={'Host':'x'}, fields=None, assert_hostname='x', preload_content=True)"
TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'
```
`OutboundTransport.request()` always passes `fields=fields` (and `assert_hostname=hostname`) to
`self._pool.urlopen(...)` (`transport.py:130-140`). With a well-formed `https://{ipv4}:{port}` URL
the TypeError fires before I/O; with a malformed IPv6 target URL a `LocationParseError` fires
instead. Either way the 202 branch of `_send_outbound_message` is dead today. This is the
orchestrator-decided **OV-2** entry (`dedupe_brief.md`), the same defect as hunt-b1b's H.

No consumer of terminal outbound status exists (`rg "outbound_service|outbound_messages" lattice/api.py`
→ only `list_pending()` at `api.py:365`, which filters to pending/leased). So even post-OV-2 the
only consequence is an internal durable/audit inconsistency, not operator-visible state.

## Frequency correction

Left **LATENT**. The trigger needs `expires_at ∈ (T_claim, T_finish)` for a claimed, leased row
while the 60 s expiry task happens to fire in that window. Backoff is geometric (60,120,240,…,86400
capped, ±25% jitter) and is computed with no reference to `expires_at`, so alignment is a
coincidence; default `default_ttl_seconds=86400` puts the last attempt at ~17 h and the penultimate
at ~8.5 h, nowhere near expiry. Widening the window to ~200 s raises per-claim odds but does not
ground a cadence: the hunter's own "next attempt lands within seconds of expiry" population is not
measurable without production traces. Per calibration this caps at L. No test in `tests/` exercises
a leased+past-TTL row (`test_expire_erases_content` expires an unleased pending row).

## Severity correction

Unchanged at **L**. Wrong durable terminal status with no consumer; bounded outcome; latent
frequency. Post-OV-2 it is a narrow consistency fault, exactly L.

## Added mechanisms / earlier failure sites (same trace)

1. **Gating:** OV-2 (`transport.request` unreachable) is the earlier failure site on this trace;
   any repair of finding 2 that assumes successful delivery ships an unexercised path.
2. **Batch-widened window:** up to ~200 s per claim, not ~40 s (5 sequential deliveries × 40 s).
3. **Sibling divergence:** `record_failure(..., retryable=False)` → `mark_terminal('failed')` after
   an expiry flip also matches nothing and returns `False`, silently ignored. Same class as the
   reported success path.
4. **Audit-gating interaction:** the "audit/durable divergence" the finding leans on vanishes at
   log level ≥ WARNING (design risk 1 in `seam-s3.md`).

## Fix-direction constraints

- The repair must not simply exclude `leased` rows from expiry: `claim_pending` refuses rows with
  `expires_at <= now`, so a row whose lease was taken and whose TTL then passed would be stuck
  `leased` forever if expiry also skipped it. Tie expiry to **lease validity**
  (`AND (lease_owner IS NULL OR lease_expires_at <= ?)`), not to delivery success.
- Escaping structure-breaking is not enough: the terminal writer must win the race deterministically.
  Either have the delivery worker re-check/reconcile terminal status on completion, or make the
  worker's `mark_terminal` reconcile a row already flipped to `expired` (so a delivered message
  cannot end `expired`), and drive the audit from the *actual* resulting durable status rather than
  from the branch taken.
- Fixing OV-2 alone activates this defect; the two fixes must land together or the expiry guard must
  land first.

## Checked and clean

- `claim_pending` rejects expired rows at claim time (`expires_at > now`); `list_pending` likewise —
  no post-expiry re-claim.
- `mark_terminal`/`release_lease` owner+status+lease-validity guards; foreign/expired-lease workers
  cannot terminal another owner's row.
- `expire_messages` `RETURNING message_id` shape matches `expire()`/`_run_expiry_cleanup` (ignored).
- Ordering/priority CASE and `%Y-%m-%dT%H:%M:%SZ` lexicographic ordering unaffected.

## Enumeration

```
rg -n "expire_messages|\.expire\(\)" lattice/            # 3 hits: messages.py:202, repositories.py:844, runtime.py:1135
rg -n "outbound_service|outbound_messages" lattice/api.py # api.py:365 list_pending (pending/leased only), api.py:406 submit
```
Instance table: every `expire_messages` caller dispositioned (`runtime._run_expiry_cleanup` →
finding; `messages.expire` wrapper → clean), and every outbound-status consumer listed (none reads
terminal status → the divergence is consequence-free at the API surface).

## Reachability kind

**GATED behind OV-2** for the reported delivered-then-recorded-expired outcome. The lease-flip
statement itself is reachable in production today (rows are claimed/leased even though delivery
then raises), but it produces only an `expired` row over a failed/aborted attempt — not the claimed
audit/durable divergence. The finding keeps real severity L but is marked gated.

## Bound

- The daemon was not run against a live peer or WAL database; concurrency verified by source trace
  and isolated interpreter probes. OV-2 was reproduced on installed urllib3 2.3.0 (pinned 2.7.0,
  same `_make_request` kwarg surface per the dedupe brief); the exact production wheel was not
  installed here.
- No production traces exist to ground the TTL/backoff alignment rate, so frequency stays LATENT,
  not DEMONSTRATED.
- `tests/` was not executed; the absence of a leased-past-TTL test is from reading `test_messages.py`.
