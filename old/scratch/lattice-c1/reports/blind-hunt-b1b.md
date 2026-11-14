# blind-hunt-b1b — blind third pass

Scope read end-to-end: `lattice/runtime.py` (1136 lines), `lattice/messages.py` (380), `lattice/transport.py` (153),
plus the repositories and API callers needed to trace each candidate
(`lattice/storage/repositories.py:OutboundMessageRepository/InboundMessageRepository`,
`lattice/api.py:receive_message/admin_submit`, `lattice/resolution.py`, `lattice/protocol/signing.py`,
`lattice/identity.py`, `lattice/canonical.py`, `lattice/protocol/models.py`).

No prior claim was supplied (blind pass). Two production-reachable defects found; the remaining
neutral-question classes were traced and are clean.

## Findings

1. [M] — A signed `rejected` custody receipt is misclassified as an invalid receipt, so the sender retries a final rejection
- Location: `lattice/runtime.py:RuntimeCoordinator._send_outbound_message` (branch at lines 977–1000)
- Evidence:
  ```python
  if (data.get("message_id") != message_id
      or data.get("node_id") != to_node_id
      or data.get("status") != "accepted"):
      logger.warning("invalid custody receipt from %s for %s: %s", ...)
      self._outbound.record_failure(message_id, owner, retryable=True)
      self._circuit_record_failure(to_node_id)
  ```
  The destination issues exactly that shape of body for a final rejection:
  `lattice/api.py:295-300` (blocked sender) and `lattice/api.py:341-350` (custody-insert failure)
  return `JSONResponse(status_code=202, content=receipt)` where `receipt` is
  `inbound_service.build_receipt(message_id, "rejected")`.
- Trigger: this node is blocked by the destination (`_block_store.block`) or the destination's
  `accept()` raises `CustodyError`. On the next delivery cycle `_run_outbound_delivery` claims the
  queued message and `_send_outbound_message` POSTs it; the destination answers HTTP 202 with
  `status: "rejected"`. The sender parses the body, matches neither the `accepted` check nor a
  transport failure, and falls into the "invalid custody receipt" arm.
- Frequency: DEMONSTRATED. Population = every outbound message queued to a peer that has blocked
  this node, plus every message whose custody insert fails at the destination. Cadence = once per
  delivery attempt; `RetryPolicy` (`messages.py`) allows `max_attempts=10` with backoff
  60 s → 30720 s, and each attempt also increments the circuit-failure counter
  (`_CB_THRESHOLD=3`), so three rejections open the per-peer circuit and begin throttling delivery.
- Outcome: PROTOCOL.md §8 states "A `202 Accepted` with a rejected receipt is final." The code does
  the opposite: it keeps durable custody, re-sends to a peer that will never accept, and only stops
  after the retry budget is exhausted, at which point the content is erased as `failed`
  (`messages.py:record_failure`). The inbound sending path also documents the intent it violates —
  `runtime.py:BlockedSenderError` docstring: "a rejected receipt is final and the sender stops
  retrying." Wrong custody/acknowledgment semantics (M per the pinned scale).
- Confidence: traced — mechanism and trigger both read from source; no component is suspected.

2. [H] — Cold-sender domains that fail resolution are never dropped from an uncapped, unthrottled set and are re-resolved every cycle
- Location: `lattice/runtime.py:RuntimeCoordinator._resolve_pending_senders` (lines 900–920) and the
  cold-sender branch in `lattice/api.py:receive_message` (lines 302–310)
- Evidence:
  ```python
  """... On failure, drops it from the queue — the sender will retry later ..."""
  ...
      except ResolutionError as exc:
          logger.debug("async pin failed for %s: %s", domain, exc)
          continue                      # <- not discarded
      ...
      self._unresolved_domains.discard(domain)
  ```
  and, in the request path (order matters):
  ```python
  if cold_sender:
      runtime.queue_domain_resolution(from_node_id)   # from_node_id is the unverified from-domain
      return JSONResponse(status_code=503, ...)
  ...
  to_domain = _extract_domain_from_address(message.get("to_address", ""))
  if to_domain and runtime._own_domains and to_domain not in runtime._own_domains: ... 403
  if not runtime.rate_limiter.allow_message(from_node_id): ... 429
  ```
- Trigger: any unauthenticated network peer POSTs `POST /lattice/v1/messages` with a body that
  passes `Message.model_validate` (all fields present, `signature` any string — it is not verified
  on the cold path) whose `from_address` domain has no pin. `verify_inbound_message` returns
  `(parsed.domain, True)` (runtime.py ~600), the handler queues the domain and returns 503
  **before** the recipient-ownership check and **before** `allow_message`. If
  `WellKnownResolver.pin` subsequently raises `ResolutionError` (DNS failure, non-200, wrong
  content type, bad signature, domain mismatch, or policy rejection — all wrapped the same),
  `_resolve_pending_senders` `continue`s and the domain stays in `self._unresolved_domains`.
- Frequency: DEMONSTRATED. Population = unauthenticated federated clients; cadence = the
  `cold_sender_resolution` task runs every 30 s (`runtime.py:346-350`) and re-resolves the entire
  retained batch. A legitimate cold sender whose domain later comes up is discarded, so normal
  churn is small; a peer that sends N distinct permanently-failing domains pins N entries for the
  process lifetime (the set is only cleared by restart). No cap exists on the set and no rate
  limit is consulted on this path, and `docs/LOOSE_ENDS.md` Phase 9 records that the deployment
  "relies on Lattice's authenticated per-peer quotas for abuse control" — the cold path bypasses
  exactly that quota.
- Outcome: unbounded in-memory growth (one `str` per distinct failing domain) plus O(N) outbound
  `GET https://<domain>/.well-known/lattice` requests per 30 s cycle, each with
  `connect=10 s / read=30 s` (transport.py `DEFAULT_TIMEOUT`). A hostile peer supplies domains that
  black-hole the HTTP connect, pinning the single `cold_sender_resolution` maintenance worker (and
  one of two shared `_maintenance_executor` workers) for arbitrarily long, delaying gossip,
  candidate verification, topology refresh, and expiry cleanup. Unbounded resource exhaustion
  reachable by a network peer → H per the pinned scale.
- Confidence: traced — the ordering of the cold branch relative to `allow_message` and the
  `continue` are read directly; the only unproven part is achievable attacker volume/rate, which is
  a bound, not a mechanism gap.

## Checked and clean

- Queue claim/release semantics (`OutboundMessageRepository.claim_pending`, `release_lease`,
  `mark_terminal`, `InboundMessageRepository.claim_for_webhook`, `release_webhook_lease`): the
  `UPDATE ... WHERE id IN (SELECT ...)` + re-`SELECT` by `(lease_owner, lease_expires_at)` pair is
  consistent under the single shared `_LockedConnection`; `attempt_count` incremented once per
  claim; `release_lease`/`mark_terminal` correctly require owner + unexpired lease.
- Retry/backoff/expiry arithmetic (`messages.py:RetryPolicy`): `next_attempt_at` is 1-based against
  the already-incremented `attempt_count`, jitter ±25 %, max 10 attempts, `expires_at = now + ttl`
  with `claim` requiring `expires_at > now` and `expire_messages` requiring `expires_at <= now` — no
  off-by-one in the boundary pair.
- Circuit breaker threshold/reset (`_circuit_is_open` / `_circuit_record_failure` /
  `_circuit_record_success`): opens at `_CB_THRESHOLD=3`, delay capped at 60 s, success resets to 0
  and NULLs `last_failure_at`; the "circuit open" skip in `_run_outbound_delivery` does **not**
  record a further circuit failure. Docstring says `base*2^(failures-1)` while the code uses
  `failures-_CB_THRESHOLD`; with the 60 s cap the two converge, so this is a comment mismatch, not
  a runtime defect.
- `allow_submission` ↔ readiness: `allow_submission` counts pending+unexpired via
  `list_pending`; no divergence found between it and `is_ready`. `admin_submit` is admin-gated and
  does not depend on `require_ready`, which is intended for the admin surface.
- Local-message signing preimages (`sign_local_message` → `sign_message` → `op_identity.sign_object`,
  verified by `verify_message`/`verify_object`): the signed dict omits `signature`, `canonicalize`
  uses RFC 8785, and the receiver verifies the raw request dict against the same
  `signature_preimage("message", ...)`; the `timestamp` string written by `sign_local_message`
  round-trips through the model without changing canonical bytes. No preimage divergence.
- Custody receipt signature verification: `_send_outbound_message` checks only
  `message_id`/`node_id`/`status`, never the receipt `signature`. This is **not** reported as a new
  finding: `docs/LOOSE_ENDS.md` "Outbound custody receipt validation" records this exact three-field
  check as the resolved design, and `tests/test_runtime.py:test_run_outbound_delivery_success` asserts
  success on an unsigned body. It becomes the fix-direction constraint for Finding 1 (below).
- Transport request construction (`transport.py`): only `https`, `hostname_allowed`, resolved-IP
  validation, SNI preserved via `assert_hostname`; no defect on this trace.

## Enumeration

Composed command (one shot closing the receipt-status, circuit, and unresolved-domain classes):

```
rg -n "record_failure|record_success|record_webhook_failure|record_webhook_success" lattice --glob '*.py'
rg -n "status.*accepted|accepted.*status|\"rejected\"|'rejected'" lattice --glob '*.py'
rg -n "_circuit_is_open|_circuit_record" lattice --glob '*.py'
rg -n "_unresolved_domains|queue_domain_resolution|_resolve_pending_senders" lattice --glob '*.py'
```

Disposition of every enumerated instance:

| Class / site | Disposition |
|---|---|
| `runtime.py:985` receipt `status != "accepted"` | Finding 1 (no other site reads receipt status) |
| `api.py:296,343` emit `rejected` receipts | Producer of Finding 1's trigger — examined, correct |
| `messages.py:297,310` `Literal["accepted","rejected"]` | Type only — examined, clean |
| `runtime.py:931` invalid message_json → `retryable=False` | examined, correct terminal |
| `runtime.py:935` no endpoint → retryable | examined, correct |
| `runtime.py:939` circuit open → retryable | examined, correct (no circuit increment) |
| `runtime.py:967` TransportError → retryable | examined, correct |
| `runtime.py:993` invalid/unsigned receipt → retryable | Finding 1 |
| `runtime.py:1001-1003` accepted → success + circuit reset | examined, correct |
| `runtime.py:1005,1013` 429/5xx retryable, else terminal | examined, correct |
| `runtime.py:1030,1060,1066` webhook failure/success | examined, correct |
| `runtime.py:1116-1122` gossip circuit bookkeeping | examined, correct |
| `runtime.py:257,895-898,908-919` unresolved-domain set | Finding 2 |
| `api.py:307` sole producer of unresolved domains | Finding 2's trigger |

## Design risks (max 2)

1. **Unsigned custody receipt is trusted.** `_send_outbound_message` transfers ownership and erases
   the sender's copy on an unauthenticated 202 body. As noted, this is the recorded design
   (LOOSE_ENDS "resolved"), but it means a receipt whose `signature` is absent or wrong is treated
   identically to a genuine one. A future hardening pass should verify the receipt with the
   destination's pinned operational certificate before `record_success`.
2. **No bound on the cold-sender resolution queue.** Even after Finding 2's drop-on-failure is
   fixed, a fixed-length cap plus a per-cycle resolution budget is still needed so an
   unauthenticated peer cannot choose the receiver's outbound DNS/HTTPS workload.
