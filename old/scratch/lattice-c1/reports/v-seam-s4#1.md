# v-seam-s4#1 — PRIMED VERIFIER of seam-s4#1 (`rejected` receipt retried)

Claim under test: seam-s4#1 (tier M) — "A final `rejected` receipt is retried as a
retryable 'invalid custody receipt'".
Re-derived from source before checking the claim: `lattice/runtime.py:_send_outbound_message`
(202 branch), `lattice/runtime.py:verify_inbound_message`, `lattice/api.py:receive_message`
both error handlers, `lattice/messages.py:build_receipt`/`accept`, `lattice/transport.py:request`,
`lattice/storage/repositories.py:claim_pending`/`release_lease`, `docs/PROTOCOL.md` §8.
Empirical: reproduced the transport `TypeError` against urllib3 2.7.0 (the uv.lock pin);
recomputed the retry backoff from the code constants.

## Verdict — ADJUSTED (severity unchanged M)

The finding's **mechanism, trigger and outcome are CONFIRMED**; its **reachability
annotation and its frequency figure are wrong**, and one of its sub-claims is refuted.
Severity M is correct and is left unchanged.

### Confirmed components (each traced to the statement)

- **Mechanism.** `_send_outbound_message` (runtime.py:976) on `response.status == 202`
  evaluates:
  `if (data.get("message_id") != message_id or data.get("node_id") != to_node_id or data.get("status") != "accepted"):`
  (runtime.py:980–985) then calls `self._outbound.record_failure(message_id, owner, retryable=True)`
  (runtime.py:993) and `self._circuit_record_failure(to_node_id)` (runtime.py:994). A receipt with
  `status == "rejected"` has matching `message_id`/`node_id` but fails the third disjunct, so it
  enters the retryable branch. `rg -n '"accepted"' lattice/runtime.py` yields only line 985 —
  there is no `"rejected"` inspection anywhere in the sender (`rg -n "rejected" lattice/` shows
  `rejected` only as a producer string in `messages.py`/`api.py`, never a consumer).
- **Trigger producers exist in-tree.** `api.py:293-300` (`BlockedSenderError` handler) and
  `api.py:338-345` (`CustodyError` handler) both `build_receipt(..., "rejected")` and return
  `JSONResponse(status_code=202, content=rejected)`. `verify_inbound_message` raises
  `BlockedSenderError` after signature verification when `self._block_store.is_blocked(from_node_id)`
  (runtime.py:661-662). Receipt `node_id` is the destination's own identity (`build_receipt`,
  messages.py:308-316), which equals the sender's `to_node_id`.
- **Outcome.** `record_failure(retryable=True)` (messages.py:158-198) with `attempt_count < 10`
  calls `release_lease(...)` → retry with backoff; after `max_attempts=10` it marks terminal
  `failed` with `erase_content=True`. Each retry also fires `_circuit_record_failure`; the circuit
  keyed on `node_id` is the same one read by `_send_gossip_batch` (runtime.py:1110), so gossip to
  that peer is suppressed during the backoff windows. This contradicts PROTOCOL.md:250 ("A `202
  Accepted` with a rejected receipt is final") and the `BlockedSenderError` docstring
  (runtime.py:63-64, "the sender stops retrying"). The audit row is written with
  `reason="invalid custody receipt"` (runtime.py:998), misattributing an application-level
  rejection as a malformed-receipt fault.

### Refuted / corrected components (named individually)

1. **Sub-claim (reachability) — REFUTED.** "the handler branch itself is exercised today by the
   mocked-transport delivery tests" is false for the branch that matters. `tests/test_runtime.py:254`
   `TestDeliveryTasks` contains only `test_run_outbound_delivery_success`, which feeds
   `status":"accepted"` (line 284) and asserts the delivered branch. No in-tree test passes a
   `status: "rejected"` body to `_send_outbound_message`. The defect path is exercised by **no
   test**; it is reachable only after the transport repair below, or by a new mocked test.
2. **Frequency figure — REFUTED (arithmetic).** "~17 h of churn per message" is one retry too
   many. `claim_pending` increments `attempt_count` on each claim (repositories.py:718);
   `record_failure` retries while `attempt_count < 10` (messages.py:187) and schedules
   `next_attempt_at(attempt_count)` (messages.py:48-55, base 60 s, doubling, cap 86400 s). With 10
   attempts the scheduled delays are `n=1..9`, i.e. `60·(2^9−1) = 30660 s ≈ 8.5 h` (jitter ±25 %
   → ~6.4–10.6 h). The 17 h value equals `60·(2^10−1)`, i.e. 10 delays — a 10th retry is never
   scheduled. Corrected frequency: **~8.5 h per rejected message** (bounded by the 24 h default TTL).
3. **"only the two literal `"accepted"` comparisons" — minor, imprecise.** There is exactly one
   `"accepted"` literal comparison in runtime.py (line 985). Does not change the verdict.

## Reachability kind

**GATED behind hunt-b1b#1** (the `OutboundTransport.request` kwargs fault), and additionally
**not covered by any test**. Independently reproduced against the pinned stack:
`.venv/bin/python` with urllib3 **2.7.0** (= uv.lock), calling
`PoolManager.urlopen("POST", url, body=..., headers=..., fields=None, assert_hostname=..., preload_content=True)`
raises `TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'`.
`transport.request` catches only `urllib3.exceptions.HTTPError` (transport.py:132-133), so the
`TypeError` escapes and every `_send_outbound_message` aborts before the status branch. Therefore
the 202 branch is dead in production today. This is NOT "TESTS ONLY" in the seam-s4 sense (no test
reaches the rejected branch); it is production-unreachable-until-repaired. Per the calibration
rule the real severity is preserved (M).

## Severity correction

**Unchanged: M.** The trace supports wrong acknowledgment semantics (a final rejection is retried)
and a stuck queue item for hours under a normal operation (an operator block of a peer with pending
traffic). It is not H (no data loss/corruption of accepted data, no secret exposure, no auth
bypass, no cross-peer reach); the auto-erasure is of the *sender's own* undelivered copy after the
retry budget, and PROTOCOL §8 says a rejected message should not be retained anyway. Not L because
the outcome is wrong terminal state plus a multi-hour retry/circuit storm under a routine trigger.

## Added mechanisms / earlier failure site / new reachability (on the same trace)

- **Earlier failure site (dominant).** The transport `TypeError` in `OutboundTransport.request`
  aborts `_send_outbound_message` before any branch, so the 202 logic — including this defect — is
  unreachable in production. Already filed as hunt-b1b#1; not re-reported.
- **Second trigger population (new on this trace).** `InboundMessageService.accept` raises
  `CustodyError` when `create` hits a `UNIQUE constraint` for a `message_id` that exists from a
  *different* `from_node_id` (messages.py:284-290): `get_existing_receipt(message_id, from_node_id)`
  returns None, so the `CustodyError` handler at api.py:338-345 issues a 202 `rejected`. Thus any
  `message_id` collision across senders is a second (rarer) producer of the rejected receipt that
  drives the retry loop. Population is real but low-cadence; it does not raise the tier.
- **Confirmed outcome coupling.** The same per-`node_id` circuit rows gate gossip
  (`_send_gossip_batch`, runtime.py:1110), so the retry storm on a rejection degrades gossip to the
  same peer, not just message delivery.
- **Dedupe.** seam-s4#1 and hunt-b1b#2 describe the identical site/mechanism; merge them.
  hunt-b1b#2 repeats the same false test-coverage claim.

## Fix-direction constraints

- A repair must special-case `status == "rejected"` **before** the three-field equality check and
  terminate the message (`retryable=False`), including a terminal status/audit reason that names
  rejection rather than "invalid custody receipt".
- **Do not fire `_circuit_record_failure` for an application-level rejection** — a rejected receipt
  is a successful protocol exchange, not a transport failure; counting it opens the breaker and
  suppresses gossip.
- **Signature verification is a precondition, not a follow-up.** Because the sender never verifies
  the receipt signature (seam-s4#2 / hunt-b1b#5), a naive "rejected ⇒ terminal" repair converts
  this bug into a denial-of-delivery: any responder at the pinned URL returning
  `{message_id, node_id, status:"rejected"}` would terminally fail the message. The fix must verify
  the receipt under the pinned operational key before acting on `status`.
- The repair must not assume the transport gate is fixed; it also has to survive the
  `TypeError`-escapes-`except TransportError` lease leak on the same worker loop.

## Findings

None new. No additional defect on this trace meets the bar (mechanism + reachable trigger +
demonstrated frequency) independently of the already-filed transport fault and receipt-signature gap.

## Checked and clean

- The `status != "accepted"` disjunct is reached for `"rejected"`; verified by reading the full
  202 branch and its surrounding try/except (runtime.py:949-1015).
- `RetryPolicy.should_retry`/`next_attempt_at` semantics and `record_failure`'s terminal path
  (messages.py:42-58, 158-198) read in full; the retry count/delay arithmetic recomputed in an
  interpreter.
- `claim_pending` genuinely increments `attempt_count` per claim (repositories.py:708-746).
- Both rejected-receipt producers (`BlockedSenderError`, `CustodyError`) build a **signed** receipt
  with the correct `node_id`/`message_id`, so the sender's first two comparisons match and the
  failure deterministically lands on the status disjunct.
- The circuit breaker's per-`node_id` cache rows are shared between delivery and gossip
  (runtime.py:771-825, 1110).
- PROTOCOL.md:250 and the docstring runtime.py:62-66 state the "final" semantics the code violates.

## Enumeration

Composed command closing the class of sender-side receipt consumers:

`rg -n '"accepted"|"rejected"|verify_receipt|build_receipt|status' lattice/runtime.py lattice/api.py lattice/messages.py lattice/protocol/signing.py`

| instance | site | disposition |
|---|---|---|
| receipt producer (blocked) | api.py:296-300 `build_receipt(..., "rejected")` → 202 | finding trigger |
| receipt producer (custody) | api.py:341-345 `build_receipt(..., "rejected")` → 202 | finding trigger (secondary population) |
| receipt producer (accepted) | messages.py:269 `build_receipt(..., "accepted")` | clean |
| receipt consumer (sender) | runtime.py:980-993 three-field check → retryable | finding site |
| receipt verifier | none (`rg verify_receipt` → no definition) | seam-s4#2, not this claim |
| `"accepted"` literal in runtime | runtime.py:985 only | one comparison, claim said two |

## Design risks (max 2)

1. **Retry budget consumed by non-attempts.** `_run_outbound_delivery` claims rows (incrementing
   `attempt_count`) before `_circuit_is_open` (runtime.py:937-939); every circuit-blocked claim
   burns an attempt without a network try. Bounded today by the 60 s circuit cap, but a message can
   reach terminal `failed` partly on non-attempts. (Same note as hunt-b1b Design risk 1.)
2. **Receipt `status` has no independent verifier.** The sender's only check is plaintext field
   equality; kind `"receipt"` has a signer and no production verifier, so any future divergence
   between `build_receipt`'s preimage and a later-added verifier surfaces only as interop failure.

## Bound

- Did not run the daemon end-to-end against a live TLS peer. The transport gate is established by
  direct reproduction of the kwargs `TypeError` on urllib3 2.7.0 plus reading that
  `request()` catches only `HTTPError`; the "no live 202 today" conclusion follows.
- Did not empirically drive the destination→sender rejected-receipt loop (no in-tree test does);
  that component is traced by reading `_send_outbound_message` and `record_failure`, not executed.
- TLS/nginx edge behaviour and upstream urllib3 behaviour beyond the pinned 2.7.0 are out of scope.
