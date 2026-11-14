# v-hunt-b1b#2 — PRIMED VERIFIER

Claim under test: **hunt-b1b finding 2 [M]** — "A final `rejected` receipt (HTTP 202) is retried as
a retryable failure, contradicting PROTOCOL.md §8."

Verdict: **ADJUSTED** (core mechanism and defect CONFIRMED; reachability kind and frequency
corrected; one supporting sub-claim REFUTED). Corrected tier: **M** (unchanged).

---

## Frame re-derived from source (before checking the claim)

- **The 202 branch** (`lattice/runtime.py:_send_outbound_message`, ~L974–1003): after a
  202 response, `json.loads(response.data)`, then the guard
  `if data.get("message_id") != message_id or data.get("node_id") != to_node_id or
  data.get("status") != "accepted":` → `record_failure(retryable=True)` +
  `_circuit_record_failure(to_node_id)` + `_audit_outbound_failed(reason="invalid custody receipt")`.
  There is **no branch that inspects `status == "rejected"`**; the only successful path requires
  `status == "accepted"`. So any 202 whose status is not exactly `"accepted"` is retried.
- **What the destination returns.** `lattice/api.py:receive_message` returns HTTP 202 with a signed
  receipt on exactly two paths: (a) `BlockedSenderError` → `build_receipt(message_id, "rejected")`;
  (b) `CustodyError` from `inbound_service.accept` → `build_receipt(message_id, "rejected")`. Both
  are `kind="receipt"`, `node_id` = receiver's `identity.node_id` (== the sender's `to_node_id`),
  `message_id` = the message id. So on the sender, `data["message_id"]` and `data["node_id"]` both
  match and only `data["status"]` differs — the exact failing predicate.
- **What the protocol requires.** `docs/PROTOCOL.md` §8 (L250): "A `202 Accepted` with a rejected
  receipt is final." `runtime.py:BlockedSenderError` docstring (L60–68): "a rejected receipt is
  final and the sender stops retrying." `messages.py:InboundMessageService.build_receipt` docstring
  (L304): "A `rejected` receipt is final: the destination node will not take custody and the sender
  stops retrying." All three agree against the code.
- **Claim constant.** `RetryPolicy`: `max_attempts=10`, `base_delay_seconds=60`, cap 86400.

## Component-by-component

- **Mechanism — CONFIRMED.** A verified rejected receipt hits the `!= "accepted"` disjunct and is
  passed to `record_failure(retryable=True)`. `record_failure` (`messages.py:OutboundMessageService`,
  ~L176) with `should_retry(n)` true re-schedules via `release_lease(next_attempt_at)`. No terminal
  path exists for `status=="rejected"`.
- **Trigger — CONFIRMED.** Destination operator blocks the sender (`BlockStore.is_blocked`,
  `runtime.py:verify_inbound_message` L661–662 raises `BlockedSenderError`), or any `CustodyError` on
  `accept()`. Either yields 202 + `status:"rejected"`. Concrete: `tests/test_api.py:281
  test_blocked_sender_gets_signed_rejected_receipt` already drives the destination into the 202 +
  rejected response; the sender side then takes the retry branch.
- **Frequency — CORRECTED.** See below.
- **Reachability kind — CORRECTED from the claim.** The claim states the handler is exercised
  "in-tree via the delivery tests' mocked transport". Both delivery tests use a mocked transport
  returning `status "accepted"` (`tests/test_runtime.py:287`, `receipt_bytes … "status":"accepted"`).
  Its integration test (`tests/test_integration.py:63`) only asserts the *receiver* kept the sender
  pending; it never feeds a rejected 202 back through `_send_outbound_message`. No test in `tests/`
  feeds `status:"rejected"` to the sender path (`rg '"rejected"' tests/` → only the API receiver-side
  assertion at `test_api.py:324`). Reachability kind is therefore **GATED behind hunt-b1b#1**: the
  real `OutboundTransport.request` raises `TypeError` (unverified `fields=`/`assert_hostname=` kwargs,
  urllib3 2.7.0 `.venv` confirmed: `HTTPConnectionPool._make_request` has neither parameter and
  `**response_kw` is forwarded to it), and `_send_outbound_message` catches only `TransportError`, so
  no 202 is ever processed in production today. Not tests-only, because no test reaches the rejected
  branch either.
- **Protocol contradiction — CONFIRMED**, verbatim sources above.

## Corrections

- **Severity: M — left unchanged.** The rubric's M clause ("wrong custody/acknowledgment semantics …
  under a plausible normal operation") is met exactly: the sender treats a protocol-final rejection
  as retryable, mislabels the audit entry, and churns the message for hours. Not H — no cross-peer
  reach, no custody taken at the destination, no secret exposure; the destination returns rejected on
  every retry (idempotent), so harm is bounded to the sender's own queue and audit. Not L — this is
  the acknowledgment-semantics path itself, not a narrow boundary or log-field nit.
- **Frequency: DEMONSTRATED-low and gated.** The operation population is "an operator who blocks a
  peer node while the sender holds queued outbound traffic to that peer": `TopologyService.block` /
  `BlockStore.block`, an explicit operator action, per block event — not a per-request or periodic
  population. The `CustodyError` variant needs an unexpected failure in `accept` (message already
  re-validated, duplicate ids short-circuited to the stored accepted receipt), so it is rare.
  Cadence is therefore low, not "plausible in normal operation" in the high-frequency sense the
  claim's wording implies.
- **Retry-window arithmetic — CORRECTED.** `attempt_count` starts at 0 (`repositories.py:create`
  `'pending', 0`) and is incremented once per `claim_pending`. `should_retry(n)` is `n<10`, and the
  failure at attempt *n* schedules `min(60·2^(n−1), 86400)` seconds. The 24 h cap never binds in this
  path: the longest pre-terminal delay is attempt 9 → 15360 s (4.27 h). Total window =
  60·(2⁰+…+2⁸) = 30660 s ≈ **8.5 h**, not the claim's "roughly 17 h". Jitter ±25% does not close the
  gap. (Attempt 10 is terminal `failed` + content erasure.)

## Sub-claims refuted

1. "The handler code path itself is exercised in-tree today by `tests/test_runtime.py:TestDeliveryTasks`
   (mocked transport returning 202)" — refuted as to the *rejected* branch. The mocked response is
   `status:"accepted"`; the retry path is unexercised by any test.
2. "…with exponential backoff (60 s doubling toward 24 h — roughly 17 h of churn)" — refuted: the cap
   never binds and the window is ≈8.5 h.

## Additional mechanisms / earlier sites / new reachability (same trace)

- **Destination does not persist or replay the rejected receipt** (`api.py:295–300`): the block path
  calls `build_receipt(..., "rejected")` afresh on each request, so `received_at` and `signature`
  differ across duplicate `message_id` submissions. §8 requires the receipt bytes be "persisted and
  returned identically for duplicate `message_id` values." This is a distinct protocol violation on
  the receiver side, and it interacts with the fix: a repaired sender that verifies the receipt
  signature (hunt-b1b finding 5) would see non-identical bytes on retries. Single-pass candidate;
  priced L (wrong receipt identity/durability for a final receipt), frequency = every duplicate
  submission from a blocked sender; reachability production (receiver side is live today,
  independent of finding 1). Fix-direction: persist the rejected receipt or derive it
  deterministically.
- **Circuit pollution is real and node-keyed**: each rejected retry calls `_circuit_record_failure`;
  at ≥3 it opens and `_send_gossip_batch` returns early on `_circuit_is_open` — so retrying a
  *rejected* message also suppresses gossip to that peer. Confirmed at `runtime.py:1110` and
  `_send_gossip_batch` L1116. Note when the circuit is already open, `_run_outbound_delivery` skips
  the send and calls `record_failure(retryable=True)` **without** a circuit failure — so attempts are
  burned without a network attempt (same as the report's Design risk 1).
- **Audit reason is wrong**: `reason="invalid custody receipt"` is written for a well-formed, signed,
  final rejection. The entry shape is right; the reason string misreports.

## Fix-direction constraints (beyond the reported symptom)

A repair must:
1. Separate `status == "rejected"` (verified, final → terminal, no retry, no circuit failure) from a
   genuinely malformed/mismatched receipt (still retryable). A single `!= "accepted"` disjunct cannot
   express both.
2. Not count a final application-level rejection as a peer-reachability failure in the circuit
   breaker, or gossip to that peer stays suppressed after a block.
3. Write an audit reason that reflects rejection, not "invalid custody receipt".
4. Tolerate/reconcile the receiver's non-replayed rejected receipt (above), especially if receipt
   signature verification (finding 5) is later added — otherwise the fixed sender rejects the
   retry's receipt as inconsistent.
5. Set the terminal status to reflect rejection rather than overloading `"failed"`, if the ledger
   distinguishes them.

## Checked and clean (coverage)

- 202-branch structure for the success case: `status=="accepted"` + matching `message_id`/`node_id`
  → `record_success` + `_circuit_record_success`. Correct.
- 429/5xx → retryable; other non-202 → terminal `failed` with erasure. Internally consistent.
- `TransportError` → retryable + circuit failure + audit. Correct.
- Destination rejection construction (`build_receipt("rejected")`, both api.py sites) is
  signature-valid and returns HTTP 202 with `kind:"receipt"`, matching §8's status/fields.
- `record_failure` retry/terminal arithmetic (1-based attempts, `should_retry`, `release_lease`
  lease-owner guard) traced correct; only the *classification* of a rejection as retryable is wrong.

## Enumeration

Command: `rg -n "rejected" tests/ lattice/ | rg -v '\.pyc'` and
`rg -n 'status.*rejected' tests/`.
Instance table:
- `lattice/api.py:298,343` — receiver builds rejected receipt → **finding (this claim's trigger)**.
- `lattice/messages.py:297,304` — status literal + docstring "final" → **evidence**.
- `lattice/runtime.py:63–64` — BlockedSenderError docstring "final, stops retrying" → **evidence**.
- `lattice/runtime.py:974–1003` — sender 202 branch lacks a rejected case → **the defect site**.
- `tests/test_api.py:324` — receiver-side assertion only → **examined-clean (does not reach sender path)**.
- `tests/test_runtime.py:287` — mocked 202 `status:"accepted"` → **refutes the test-reachability sub-claim**.
- `tests/test_integration.py:63` — receiver kept pending only → **examined-clean**.
Class is not closed on the sender side: no code or test handles `status == "rejected"`.

## Bound

- Live transport unavailable: the gating claim (finding 1's `TypeError`) is demonstrated at the
  urllib3 layer in the repo `.venv` (`urlopen`/`_make_request` signatures) but not on a running
  daemon; the end-to-end "sender receives 202 rejected" round-trip was not executed on live hosts.
  Reachability kind GATED is traced from code, not observed.
- Provider/upstream not reached: the destination in the blocked case is a Lattice daemon per
  `api.py`; whether a real third-party configured as a peer's `messages` endpoint would emit this
  receipt is unverifiable here. Marked SUSPECTED only for that non-Lattice-endpoint variant; the
  Lattice-to-Lattice variant is fully traced.
- Frequency of operator blocks (how often a deployment blocks a peer with pending outbound) is not
  measurable from the tree; stated as low per-event cadence, not as a rate.
