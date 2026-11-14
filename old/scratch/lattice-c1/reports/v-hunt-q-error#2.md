# v-hunt-q-error#2 — primed verification of q-error finding #2

Claim under test: **q-error.md finding 2** — "[M] Sender retries a final 'rejected' receipt and
mislabels it 'invalid custody receipt'". Pass: PRIMED VERIFIER. Adversarial and symmetric; the
frame below was re-derived from source before the claim was read against it.

**Verdict: ADJUSTED.** Mechanism and trigger confirmed. Severity corrected M → L. Frequency
corrected from "DEMONSTRATED" to low-cadence / environment-armed. Reachability kind: PRODUCTION.

---

## Frame re-derived from source

- `_send_outbound_message` (`lattice/runtime.py:951–1017`) sends the message, then on
  `response.status == 202` parses the body and validates **only three plaintext fields**:
  `data.get("message_id") == message_id`, `data.get("node_id") == to_node_id`,
  `data.get("status") == "accepted"`. Anything else (including a well-formed `"rejected"` receipt)
  falls into one branch: `logger.warning("invalid custody receipt ...")`,
  `record_failure(retryable=True)`, `_circuit_record_failure(to_node_id)`,
  `_audit_outbound_failed(reason="invalid custody receipt")`. Lines 977–999.
- `record_failure(retryable=True)` (`lattice/messages.py:145–173`) checks
  `RetryPolicy.should_retry(attempt_count)` (`max_attempts=10`) and otherwise releases the lease;
  `claim_pending` (`repositories.py`) re-claims while `expires_at > now`. So a rejected receipt is
  retried up to 10 attempts / until TTL. Confirmed.
- §8 text (`docs/PROTOCOL.md` §8): the `status` field is `"accepted"` or `"rejected"`; "A `202
  Accepted` with a rejected receipt is final. The receipt bytes MUST be persisted and returned
  identically for duplicate `message_id` values."
- In-tree declaration of the intended sender behavior: `runtime.py:63–64` (`BlockedSenderError`
  docstring) — "a rejected receipt is final and **the sender stops retrying**"; `messages.py:304–306`
  (`build_receipt` docstring) — "A `rejected` receipt is final: the destination node will not take
  custody and **the sender stops retrying**." The code at runtime.py:981–999 contradicts its own
  stated contract.
- Admission that no other consumer exists: `verify_receipt` does not exist and no tree site verifies
  a receipt signature; the deliver path is the only consumer of receipt `status`.

---

## Findings

### 1. [L] Sender treats a protocol-final `rejected` receipt as an invalid/retryable one
- Location: `lattice/runtime.py:_send_outbound_message` (981–999)
- Evidence:
  ```python
  if (data.get("message_id") != message_id
      or data.get("node_id") != to_node_id
      or data.get("status") != "accepted"):
      logger.warning("invalid custody receipt from %s for %s: %s", ...)
      self._outbound.record_failure(message_id, owner, retryable=True)
      self._circuit_record_failure(to_node_id)
      self._audit_outbound_failed(..., reason="invalid custody receipt")
  ```
- Trigger (runtime path): node A's outbound worker claims a pending message
  (`_run_outbound_delivery` → `_send_outbound_message`) and delivery to node B returns HTTP 202 with
  a body whose `status == "rejected"`. Two production producers: (a) B's `api.py:339` `CustodyError`
  branch, which builds a signed `rejected` receipt and returns it with 202; (b) any federated peer
  that answers the public messages route with 202+rejected (outside-written content). A
  `status="rejected"` body is treated identically to a malformed one.
- Frequency: **LOW / environment-armed, not demonstrated as a standing cadence.** The population
  "outbound deliveries whose destination responds 202+rejected" exists, but its producers are a
  destination-side storage fault (F3, requires a UNIQUE/DB failure) or a hostile/buggy peer — not a
  normal-operation cadence. Producer (a) is armed only under F3; the blocked-sender producer
  (`api.py:293`) has no production caller (`TopologyService.block`, `topology.py:495`, is called
  only from tests — `tests/test_api.py:307`, `tests/test_runtime.py:241`). The claim's own text
  concedes "Not everyday." Corrected from "DEMONSTRATED."
- Outcome: (a) the audit record `OUTBOUND_FAILED reason="invalid custody receipt"` names a valid,
  deliberately final receipt as invalid/malformed; (b) the message is marked retryable and re-sent
  up to `max_attempts=10` (backoff to 24 h) or until TTL, violating §8 finality; (c) each rejection
  is also counted as a circuit failure against that peer. Eventual terminal state remains correct
  (`failed`, content erased). No data loss, no security, no crash.
- Severity correction: **M → L.** The claim's M reading rests on "wrong acknowledgment semantics /
  divergence between two paths that must agree". That reading is literal but the realized harm is
  bounded (a wrong audit field plus wasted retries that still terminate correctly), and M's
  qualifier "under a plausible normal operation" is not met — the trigger requires a storage fault
  or a hostile/buggy peer. That is the pinned L pattern: "a real defect with a narrow trigger or a
  bounded bad outcome: a wrong log/audit field." A reviewer could argue M on the explicit
  protocol-divergence; the trace does not support H.
- Confidence: **traced** (mechanism, trigger, and the eventual-terminal-state trace all read in
  source). The only unproven component is **frequency** — no deployment rate can be grounded; hence
  the low-cadence marking.
- Reachability kind: **PRODUCTION** (public messages route / hostile peer; or destination storage
  fault). The blocked-sender sub-producer is **TESTS ONLY**.

---

## Refuted sub-claims

- **"well-formed and deliberately final" is guaranteed at the sender.** Half-refuted as stated: the
  sender never verifies the receipt's signature (see side discovery A), so it cannot know the
  receipt is genuine — it only knows the three plaintext fields. The *validity* the claim asserts is
  not established by the sender; the claim's own outcome (a wrong audit label) does not depend on it.
- **The audit label is a "false statement about a valid receipt".** Confirmed but imprecise: the
  label is false about the *receipt*; the sender has no basis to know validity. The mechanism stands.
- **"or until TTL".** Confirmed correct — `claim_pending` filters `expires_at > now`, so retries stop
  at TTL as well as at `max_attempts`.

No sub-claim of mechanism or trigger is refuted outright. No kill is justified.

---

## Additional mechanisms / earlier failure sites / new reachability (same trace)

- **Rejected receipts are counted as circuit failures.** runtime.py:994 calls
  `_circuit_record_failure(to_node_id)` on a rejected receipt, so a peer that legitimately refuses
  messages repeatedly opens the circuit; further messages then take the F6 path at
  `runtime.py:939` (retryable failure with **no audit record**). This chains F2 into F6's audit gap
  for a peer that is merely refusing.
- **Rejected receipts violate §8 byte-identity** (earlier failure site, on the destination side):
  `api.py:296` and `api.py:341` call `build_receipt(..., "rejected")`, which signs a fresh
  `received_at` per call and is never persisted (only the accepted path stores `receipt=`, at
  `messages.py:281`). A duplicate rejected request therefore returns **different bytes**, contrary
  to §8 "MUST be persisted and returned identically". No current consumer compares receipt bytes, so
  this is latent today. Severity L, frequency latent. Fix-direction: persist the rejected receipt
  keyed by `(message_id, from_node_id)` before returning it, mirroring the accepted path.

---

## Side discoveries (single-pass; priced)

- **A. No receipt signature is ever verified.** runtime.py:977 comments "Validate the signed custody
  receipt before transferring ownership", but no `verify_receipt` exists and the deliver path checks
  only `message_id`/`node_id`/`status`. A response body with those three fields and `status="accepted"`
  is accepted as custody and the sender erases content, regardless of `signature`. Priced: **L**,
  reachability PRODUCTION but gated behind the trust model (the responder is the peer A chose to
  send to; nginx owns TLS, so an off-path forger is out of scope). Fix-direction: call
  `verify_object(<destination operational key>, receipt, "receipt")` on the 202 body before
  `record_success`. **Bound:** cannot reach whether an intermediary/proxy can inject a 202 (edge TLS)
  — SUSPECTED, unverifiable here. Listed, not folded into the verdict.
- **B. `_send_outbound_message` does not require `kind == "receipt"`.** 202 bodies without the
  discriminator are accepted on field match alone. Subsumed by A; not separately reportable.

---

## Checked and clean

- `record_failure` retry accounting (`messages.py:145–173`) and `claim_pending` TTL/attempt gating
  (`repositories.py`) — read; the "10 attempts / until TTL" statement holds.
- `RetryPolicy` (`messages.py:40–58`) — `max_attempts=10`, `max_delay_seconds=86400`, verified.
- `api.py:293` blocked-sender rejected receipt and `api.py:339` custody-error rejected receipt both
  return `status="rejected"` with HTTP 202 — verified producers of the trigger.
- `BlockedSenderError` producer chain: `runtime.py:661` raises it; `TopologyService.block`
  (`topology.py:495`) has no production caller (`rg '\.block\('` → only topology.py:503 internal
  delegation + tests). Confirms the claim's "TESTS ONLY" marking for the blocked-sender producer.
- `verify_inbound_message` (`runtime.py:619–663`) — signature verified before the blocked check, so a
  rejected receipt is only issued for signature-valid messages, as §8 requires.
- Sender handling of non-202 statuses (429/5xx retryable → 965–1016; other 4xx terminal) — read;
  classification is consistent with the surrounding code.

---

## Enumeration

Class-closing command for the receipt consumer / finality question:

```
rg -n "receipt" lattice/runtime.py lattice/messages.py lattice/api.py
rg -n "def verify_receipt|verify_receipt|status.*rejected|\"rejected\"" lattice/ tests/
rg -n '\.block\(' lattice/            # block() producers
```

Outputs: the only consumer of receipt `status` is `runtime.py:981–999`; no `verify_receipt` exists
in `lattice/`; the only `"rejected"` literals in `lattice/` are `messages.py:296/304` (build) and
`api.py:296/341` (emit); `TopologyService.block` is invoked only from `topology.py:503`.

---

## Fix-direction constraints

1. A repair must **distinguish the two failures**: a `status="rejected"` receipt is final
   (`record_failure(retryable=False)`, distinct audit reason) while a missing/unparseable/unsigned
   receipt stays retryable. Collapsing both to terminal would be wrong.
2. **Do not repair F2 alone.** The in-tree rejected producer today is F3's `CustodyError` branch,
   whose rejections are transient storage faults. Honoring §8 finality before F3 is fixed converts a
   transient destination outage into permanent message loss. F2 and F3 must be repaired together:
   F3 must return 503 + Retry-After for transient failures so that "rejected" only ever means a
   deliberate refusal.
3. Verify the receipt signature before trusting `status` (side discovery A); today "deliberately
   final" is unverifiable by the sender.
4. Decide deliberately whether a peer's refusal should count as a circuit failure
   (`runtime.py:994`); as written it chains into F6's un-audited terminal path.
5. If §8 byte-identity is to be honored, persist the rejected receipt keyed by
   `(message_id, from_node_id)`; regenerating it per request breaks duplicate idempotency.

## Bound

- No deployment rate for rejected receipts could be reached; frequency is asserted as low from the
  producer analysis, not measured.
- Edge/TLS and provider/peer behaviour are out of reach: whether an intermediary can inject a 202 is
  SUSPECTED, unverifiable in-tree (side discovery A).
- Reachability of a hostile-peer rejection is argued from the fixed public route, not from a live
  peer.
