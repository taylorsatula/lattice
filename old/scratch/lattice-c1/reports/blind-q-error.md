# blind-q-error — BLIND THIRD PASS: error paths report the truth?

Pass type: blind hunter (target withheld). Neutral question: does every error path report
the truth — is the caught/swallowed error correctly reflected in log level, HTTP status/code,
audit record, and the retry/terminal decision the caller makes, or is a failure silently
converted to success/no-op?

Scope read end-to-end: all 34 modules under `lattice/` (7,744 lines), driven by the composed
`except` enumeration below (98 clauses). Callees traced: `api.handle_*` ↔ `runtime.*`,
`messages`, `resolution`, `transport`, `webhook`, `topology`, `gossip`, `storage/*`, `cli`.

Independently derived before looking at any prior report. Prior `q-error`/`hunt-*` reports were
consulted only after my own trace, to mark corroboration vs new.

---

## Findings

### 1. [H] Cold-sender resolution queue admits an unbounded number of never-dropped domains from an unauthenticated public route

- Location: `lattice/runtime.py:_resolve_pending_senders` (900–921) and
  `RuntimeCoordinator.queue_domain_resolution` (895–898); reached from
  `lattice/api.py:receive_message` (303–307) via `runtime.verify_inbound_message`
  (`runtime.py:619–663`, cold-sender return at 647).
- Evidence:
  ```python
  # runtime.py queue_domain_resolution
  with self._unresolved_domains_lock:
      self._unresolved_domains.add(domain.lower())      # no cap, no TTL, no timestamp

  # runtime.py _resolve_pending_senders  (docstring: "On failure, drops it from the queue")
  try:
      self._resolver.pin(domain)
  except ResolutionError as exc:
      logger.debug("async pin failed for %s: %s", domain, exc)
      continue                                          # entry retained forever
  with self._unresolved_domains_lock:
      self._unresolved_domains.discard(domain)          # removal only on success
  ```
  `_build_scheduler` registers `_RecurringTask("cold_sender_resolution", 30.0, ...)` at
  `runtime.py:345–350` on the 2-worker `_maintenance_executor`.
- Trigger (PRODUCTION, unauthenticated): any network peer `POST /lattice/v1/messages` with a
  body that passes `Message.model_validate` and whose `from_address` is domain-form
  (`user@<host>`) for a host with no row in `domain_pins`. `verify_inbound_message` returns
  `(parsed.domain, True)` **before** `_certificate_for_node`, signature verification, and the
  block check; `receive_message` calls `queue_domain_resolution(domain)` and returns 503.
  `Message.signature` is an unvalidated `str` (`protocol/models.py:232`) and `from_address` is
  validated only to length 320, so no certificate or valid signature is needed. `parse_address`
  accepts any host without `:/@` up to 253 chars, so a random single-label host works and
  requires no DNS registration. A domain whose `pin()` fails (NXDOMAIN, non-200, bad
  content-type/JSON/signature — `resolution.resolve_with_ip`) stays queued permanently; only a
  fully valid well-known pin removes it, so the cheapest attacker input is a failing host.
- Frequency: DEMONSTRATED — population is every unauthenticated POST to the public messages
  route; one structurally valid request with a fresh `from_address` host permanently adds one
  set entry. Each entry is then re-resolved once per 30 s (`_resolver.pin` → DNS
  `getaddrinfo` + HTTPS GET, `DEFAULT_TIMEOUT = connect 10 s / read 30 s`, serial in one loop).
  This path runs before `allow_message` (`api.py:335`), so the message rate limiter does not
  gate it. No coincidence is required.
- Outcome: (a) unbounded memory growth in `_unresolved_domains`; (b) unbounded recurring
  outbound DNS/HTTPS egress driven by remote unauthenticated input — N entries ⇒ N lookups per
  30 s cycle; (c) failures logged only at DEBUG, invisible at the stock INFO level; (d) one
  maintenance worker can be occupied for hours (N × ≤40 s) on a single cycle, delaying
  `verify_candidates`/`gossip_round`/`refresh_topology`/`expiry_cleanup` that share the 2-worker
  pool. Docstring and code disagree ("drops it" vs `continue`).
- Confidence: traced — mechanism, trigger, frequency all verified by reading; no live daemon
  run. The code path is reachable today without any repair (nginx proxies the route, the
  `lattice` message schema is satisfied by the attacker's JSON, and rate limiting is after the
  503 return). Reachability: **PRODUCTION** (public fixed route, no auth).
- Corroboration: this is the H-survivor mechanism in `q-error.md` finding 1, independently
  re-derived here. Prior `v-hunt-q-error#1` confirmed it. My independent derivation agrees on
  mechanism/trigger/frequency; the only correction is below (sub-claim refuted).

#### Refuted sub-claim (of the source finding, not of my confirmation)
- "the whole batch resolves serially on one maintenance worker, **starving**
  `verify_candidates`/`gossip_round`/`refresh_topology`" is **overstated as starvation**. The
  executor has 2 workers; while `_resolve_pending_senders` holds one, the other
  maintenance task can still run. The correct statement is *contention/delay*, not starvation.
  (I agree with `v-hunt-q-error#1` on this; it is not a new refutation, recorded for
  completeness.)

#### Additional mechanism on the same trace (new)
- On success, `pin()` performs a durable `domain_pins` upsert. Because the cold path is
  pre-signature and pre-rate-limit, an unauthenticated peer can drive durable-table writes,
  not just cache/memory growth. Cost to the attacker is one valid well-known doc per domain,
  so this is the expensive branch and is bounded by the attacker's own domain count; the cheap
  branch (failing host, memory + egress) is the H above. No code bounds either branch.

---

## Checked and clean

The remaining 97 `except` clauses were dispositioned; none produced a new reportable defect.
Grouped:

- **`resolution.py` (7 sites)** — transport/policy/content-type/JSON/schema/key/signature/
  certificate failures are each re-raised as `ResolutionError` with cause; status and
  content-type mismatches included. Correct. (One narrow gap: `OperationalCertificate.from_dict`
  at ~106 is outside the wrapping try, but every field is already Pydantic-validated by
  `WellKnownDocument`, so I found no reachable escape.)
- **`topology.py` (9 sites)** — per-step verification failures re-raised as `TopologyError`
  with cause; candidate removed on card-invalid/verify-fail, retained on `ResolutionError`
  for retry until TTL (intended). `prefix_from_ip` `except ValueError → None` matches its
  documented contract. Correct.
- **`identity.py:299`, `canonical.py:57/59`, `crypto.py:27/62/105`, `protocol/models.py`
  (5 sites), `config.py:45`** — each converts to a narrower contextual error
  (`IdentityError`, `JSONParseError`, `SignatureError`, `ModelError`, `ConfigError`). Correct.
  (`config.load_config` does not catch `tomllib.TOMLDecodeError`, but that is a pre-existing
  known finding, `hunt-d2#3` / `v-hunt-a2#3`, and unchanged.)
- **`gossip.py:92/130/246`** — card validation/accept failures surface per-card as
  `accepted=False` with a reason in the 200 `errors[]` list; the corrupt-transient-card skip at
  246 operates on self-written cache JSON. Correct/benign.
- **`webhook.py:98/111`** — network/HTTP failures return `WebhookResult` with `retryable`
  classification matching the docstring (429/5xx retryable, other 4xx terminal) and upsert
  idempotency state. Correct. (408/425 classified terminal is a deliberate 4xx policy, not a
  truthfulness fault.)
- **`transport.py:78/85/92/141`** — gaierror and urllib3 `HTTPError` → `TransportError` with
  cause; per-address policy failures advance to the next resolved address before failing.
  `LocationValueError` is an `HTTPError` subclass so malformed URLs are also caught. Correct.
- **`cli.py` (21 sites)** — every site prints the failing operation to stderr and returns 1
  (KeyboardInterrupt → 130); root-key operations are offline CLI per invariant 2. Correct.
- **`storage/migrations.py:30/113`, `storage/cache.py:27/65`** — migration failure names the
  failed script; schema-hash mismatch rebuilds the disposable cache by design. Correct.
- **`addressing.py:78`** — documented `AddressError → None` contract. Correct.
- **`runtime.py` remaining 20 sites** — 133 recurring-task exception log; 409/510 rate-limit
  restore/persist logged, disposable; 429/458 bootstrap warnings + continue; 524 readiness
  fail-closed; 550/554/567 gossip sender-card verification → `None` (IP fallback per
  PROTOCOL §5.2, intended); 635/659 `Message`/signature failures → `RuntimeError` (upstream
  classification of 401 vs 400 is a known finding, unchanged); 680 `except ResolutionError:
  pass` in `_certificate_for_node` is a silent miss but the caller converts to
  `RuntimeError("no operational certificate")` → 401 (known); 788/809/824 circuit-breaker DB
  writes log-and-continue on the disposable cache; 930/1029/1037 corrupt-JSON/timestamp
  fallbacks terminate or substitute safely; 965 TransportError → retryable + circuit + audit;
  1114/1128 gossip/verify warnings. Each correctly reflects the error in its terminal/retry
  decision except the already-reported branches (`_send_outbound_message` rejected-receipt,
  the pre-send deferral branches with no audit) — all known.
- **`messages.py` (4 sites)** — `submit`/`accept` map model and UNIQUE failures to
  `CustodyError`; the duplicate race re-reads the stored receipt and returns it byte-identical
  per PROTOCOL §5.3. Correct.
- **`api.py:189`** — `int(content-length)` `ValueError` → 400; the `HTTPException(413)` raised
  inside the same try is not a `ValueError` (fastapi `HTTPException` is not a `ValueError`
  subclass — verified), so it is not swallowed. Correct.
- **`api.py:293/301/339/346/393/407`, `__init__.py:5`** — see side discoveries and known
  findings; dispositions below.

---

## Enumeration

Composed command (all `except` clauses in the package):

```
rg -n '^\s*except\b' lattice | sort
```

Output: 98 clauses, by file:

| File | clauses |
|---|---|
| runtime.py | 23 |
| cli.py | 21 |
| topology.py | 9 |
| resolution.py | 7 |
| api.py | 7 |
| protocol/models.py | 5 |
| transport.py | 4 |
| messages.py | 4 |
| gossip.py | 3 |
| crypto.py | 3 |
| webhook.py | 2 |
| storage/migrations.py | 2 |
| storage/cache.py | 2 |
| canonical.py | 2 |
| identity.py | 1 |
| config.py | 1 |
| addressing.py | 1 |
| `__init__.py` | 1 |

Disposition table (grouped; individual lines are in `/tmp` during the pass and listed
above by file):

| Instance group | Disposition |
|---|---|
| resolution.py:51,63,72,83,89,100,108 | examined-clean (all re-raised as `ResolutionError` with cause) |
| addressing.py:78 | examined-clean (documented None) |
| messages.py:102,129,256,284 | examined-clean (CustodyError mapping; duplicate receipt idempotent) |
| topology.py:125,179,214,224,229,303,313,323,333 | examined-clean |
| canonical.py:57,59 | examined-clean |
| gossip.py:92,130 | examined-clean (per-card `errors[]`) |
| gossip.py:246 | examined-clean (self-written cache) |
| cli.py:213,231,239,257,291,334,348,383,423,433,555,579,594,645,668,686,698,805,1008,1011,1014 | examined-clean (stderr + exit code) |
| crypto.py:27,62,105 | examined-clean |
| protocol/models.py:93,134,177,297,409 | examined-clean |
| storage/migrations.py:30,113 | examined-clean |
| storage/cache.py:27,65 | examined-clean |
| transport.py:78,85,92,141 | examined-clean |
| webhook.py:98,111 | examined-clean |
| config.py:45 | examined-clean (TOMLDecodeError escape is a known pre-existing finding) |
| api.py:189 | examined-clean |
| api.py:293,339 | examined-clean (202 + signed rejected receipt, PROTOCOL §8) |
| api.py:301,346,393,407 | known findings (reproduced; not new — see below) |
| runtime.py:133,409,429,458,510,524,550,554,567,635,659,680,788,809,824,930,965,1029,1037,1114,1128 | examined-clean |
| runtime.py:900–921 (`_resolve_pending_senders`, except at 914) | **FINDING 1** |
| `__init__.py`:5 | examined-clean (wheel-build version shim) |

---

## Side discoveries (single-pass candidates — priced, never folded into the verdict)

- **SD1 [L] — Router-generated 404/405 bypass the RFC 9457 handler; response uses
  `{"detail": ...}` with `application/json`.** `api._http_exception_handler` is registered for
  `fastapi.HTTPException`; Starlette's router raises `starlette.exceptions.HTTPException`, whose
  MRO does not include the fastapi subclass, so 404/405 fall back to Starlette's default handler.
  Verified with the repo venv on a minimal app using the same registration: explicit
  `fastapi.HTTPException(403)` → custom body; `GET /does-not-exist` → `404 {'detail':'Not Found'}`;
  `POST /x` → `405 {'detail':'Method Not Allowed'}`. Trigger: a request to an unknown path or
  wrong method that reaches the app (loopback, or any path under the `/lattice/v1/admin/` or
  `/lattice/v1/health/` nginx prefixes). Reachability: **PRODUCTION only via loopback/prefix
  paths; external unknown paths are answered by nginx's catch-all `return 404`**
  (`deploy/lattice.nginx.conf`, `hunt-k1`). Fix-direction: register the handler for
  `starlette.exceptions.HTTPException` (or add a dedicated 404/405 handler), and add
  `404`/`405`/`403` to `_STATUS_PROBLEM_MAP` so the `type`/`code` are not the
  `LATTICE_INTERNAL_ERROR` fallback.
- **SD2 [L] — Cold-sender 503 is returned before the recipient-ownership (403) check and before
  the message rate limiter.** `api.py:303–316` returns 503 for any unpinned domain-form sender
  before the `to_domain` guard at ~322 and before `allow_message` at ~335. An unauthenticated
  peer therefore neither gets rate-limited nor gets 403 for a message addressed elsewhere; it
  always gets 503 + `Retry-After: 60`. Same trace as Finding 1; the rate-limit exemption is the
  amplifier, the missing 403 is informational. Fix-direction: run the rate limiter (and the
  ownership check) before enqueueing/pinning a cold domain.
- **SD3 [S-] — `_certificate_for_node` swallows `ResolutionError` with `pass` (`runtime.py:680`),
  so a transient resolution failure and a genuine "no certificate" are indistinguishable; both
  become `RuntimeError("no operational certificate for sender")` → 401.** The 401
  classification is a known finding; the silent swallow is not separately reported. Needs one
  more pass to decide reportability.

---

## Design risks (max 2)

1. **Audit rows are gated on the Python log level and no logger is configured in `cmd_serve`.**
   `_write_audit_entry` writes only when `logger.isEnabledFor(level)`; uvicorn configures only
   its own loggers, so at the default root level (WARNING) every INFO audit code
   (INBOUND_ACCEPTED, OUTBOUND_DELIVERED, WEBHOOK_DELIVERED, retryable WEBHOOK_FAILED) is
   never persisted. Explicit code intent ("gated by Python logging level"), so not a finding,
   but the durable `audit_log` is empty-by-default for the most common events.
2. **`RateLimiter._buckets` has no eviction, and gossip falls back to the client-controlled
   leftmost `X-Forwarded-For`.** Rotating the header both bypasses the gossip limit (known,
   `hunt-a1#1`) and allocates fresh buckets without bound; the persistence path then writes
   them row-by-row at shutdown. An eviction/TTL policy is the missing safeguard.

---

## Bound (what I could not reach)

- No live daemon, nginx, or DNS was run; all mechanisms are traced from source (SD1's
  exception-handler routing was verified against the installed fastapi/starlette, not against
  a live deployment).
- Production request rate, nginx connection limits, and resolver behavior for attacker hostnames
  are outside the tree; the unbounded-ness of Finding 1 is a property of the code, not measured
  against a deployment.
- Whether any external client can reach the app's 404/405 path (SD1) depends on the nginx
  config's catch-all, which I read but did not run.
