# v-hunt-q-error#4 — PRIMED VERIFIER

Claim under test: finding **hunt-q-error#4** in `scratch/lattice-c1/reports/q-error.md`
(tier M) — "Unknown-sender / structural errors returned as 401; canonical-form senders get
terminal failure where domain-form senders get 503."

**Verdict: ADJUSTED.** Mechanism and trigger CONFIRMED; the reported DEMONSTRATED frequency is
overstated and is corrected below. Severity left at M with the trace that supports it. One side
discovery found on the same statement sequence (the missing `LATTICE_INVALID_SIGNATURE` code).

Reachability kind: **PRODUCTION**, operator-armed for the canonical-loss arm (a);
PRODUCTION, unauthenticated for the malformed-body arm (b).

---

## Frame re-derived from source (before checking the claim)

The claim's phrasing assumes several things. Each was established independently:

1. **What `verify_inbound_message` returns for each address form.**
   `lattice/runtime.py:619` `verify_inbound_message`:
   - `model = Message.model_validate(message)` failure → `raise RuntimeError("invalid message: …")`
     (line 635).
   - canonical `from_address` (`parse_address(...).node_id is not None`) → `from_node_id = node_id`,
     then `_certificate_for_node(node_id)` (line 654). If that returns `None` →
     `raise RuntimeError("no operational certificate for sender: …")` (line 656).
   - domain-form `from_address` with no pin → `return (parsed.domain, True)` — the cold-sender
     path, BEFORE any cert lookup or signature check.
   Established, not assumed: the two forms take different code branches.

2. **What `_certificate_for_node` does when the node is unseen** (`lattice/runtime.py:667`):
   `peer_store.get_peer` → None; `_domain_for_node` → `peer None` and `pin_repo.get_by_node_id` →
   None → returns `None` (line 664/681). No network attempt because no domain is known. Confirmed.

3. **What the caller does with the two outcomes** (`lattice/api.py:295` `receive_message`):
   `except RuntimeError` → `_problem(401, …)` (lines 301–302); `if cold_sender:` → 503 +
   `queue_domain_resolution` + `Retry-After: 60` (lines 303–316). Confirmed.

4. **What the sender does with each status** (`lattice/runtime.py:960` `_send_outbound_message`):
   `202` → receipt check; `429 or >=500` → `record_failure(retryable=True)` (line 1004);
   `else` → `record_failure(retryable=False)` (line 1017). `record_failure(retryable=False)` →
   `mark_terminal("failed", erase_content=True)` (`lattice/messages.py:154–158`). So **401 and 404
   and 403 all land in `else`** and terminally erase. Confirmed.

5. **`_STATUS_PROBLEM_MAP`** (`lattice/api.py:75`): 401 → `LATTICE_UNAUTHORIZED`. No
   `LATTICE_INVALID_SIGNATURE` / `LATTICE_UNKNOWN_NODE` / `LATTICE_INVALID_ADDRESS` constant exists
   anywhere in `lattice/` (`rg` empty). Every status-coded error reply funnels through one of eight
   generic codes.

The claim's frame survives re-derivation. The decisive artifact is the branch split at
`runtime.py:638–648` (canonical vs domain) combined with the sender's blanket `else` at
`runtime.py:1017`.

---

## Component verdicts

### Mechanism — CONFIRMED
Canonical `from_address` from a node absent from both `peer_store` and `pin_repo` yields
`RuntimeError` from `runtime.py:656`, caught at `api.py:301`, returned as `401 LATTICE_UNAUTHORIZED`.
The same logical condition in domain form returns `503` + queues resolution. The sender maps 401 to
a non-retryable terminal failure and erases content; it maps 503 to a retryable release. The two
paths diverge exactly as claimed. Test evidence: `tests/test_api.py:277`
`test_receive_message_rejects_unknown_sender` asserts 401 for a canonical unknown sender;
`tests/test_integration.py:36` `test_cold_sender_returns_503` asserts the domain path stays
`pending`. Both branches are live in code.

### Trigger — CONFIRMED, with one correction to the arm description
- **(a) canonical sender-loss.** Trigger: our node sends a message with a canonical `from_address`
  to a peer that has not yet verified/pinned us. Reachable in production: the only production sender
  is `POST /lattice/v1/admin/messages/submit` (`api.py:376`), which takes `from_address` verbatim
  from the operator (`SubmitRequest.from_address`) and calls `sign_local_message` → `outbound.submit`
  → `_run_outbound_delivery` → `_send_outbound_message`. No in-tree code auto-populates
  `from_address`; `rg` shows `sign_local_message` called only from that route and tests.
- **(b) malformed body → 401.** Trigger: any peer (or unauthenticated network caller — no signature
  is checked before `model_validate`) POSTs a JSON object that is a dict but fails `Message`
  validation (missing/wrong fields). `runtime.py:635` → `api.py:301` → 401. `RequestValidationError`
  (body not a dict) is separately 400 (`api.py:137`), so only the dict-but-invalid case hits 401.

### Frequency — ADJUSTED (this is the correction)
The report labels both arms DEMONSTRATED. Neither cadence is grounded:
- Arm (a) requires **the operator to choose the canonical form for their own `from_address`**. The
  report grounds this with "contact cards export exactly this form — `cmd_contacts_export` builds
  `username@node_id`". That conflates two different addresses: the contact card carries the
  **recipient's** address (`cli.py:302`), which is consumed as `to_address` through
  `resolve_destination` (where canonical is fine), not as `from_address`. `from_address` is
  operator-supplied on the admin route only; the identity manifest (`cli.py:145`) publishes
  `node_id` and `domain` separately, biasing neither form. So the population is "admin submissions
  whose operator typed a canonical self-address" — concrete, but no cadence is grounded. This is a
  **latent frequency for arm (a)**: say so, not "each new peer pairing".
- Arm (b) population is the public messages route, unauthenticated, but no in-tree client emits a
  malformed `Message` (both `submit` and `accept` pre-validate; our own senders are well-formed).
  The only producers are hostile peers and client bugs; not a normal-deployment cadence. Also
  **latent** as to frequency.

Per the pinned rule ("a frequency you cannot ground is LATENT by definition"), both arms are marked
latent-frequency. The finding therefore sits at the M/L boundary; see severity below.

### Severity — left at M, trace given
The claim's M rests on divergence between two paths that must agree plus a message permanently
erased. Both are traced (`api.py:301–316`, `runtime.py:1017`, `messages.py:154`). The M definition
names exactly "divergence between two paths that must agree — under a plausible normal operation",
and an operator supplying a canonical self-address to a new peer is plausible (docs call the
canonical form authoritative: `docs/ADDRESSING.md`). I keep M. Note the strict calibration would
permit L on the frequency ground above; I decline to drop it because the divergence and the
terminal content-erasure are traced, not merely asserted. If the merge layer weights
ungrounded-frequency at L, this is the finding to apply it to — the trace is given so the call is
mechanical.

### Sub-claims refuted
- **"contact cards export exactly this form [as `from_address`]"** — REFUTED as stated. The export
  form is the contact's address; nothing wires it into `from_address`. Corrected to
  "operator-supplied".
- **"happens on each new peer pairing"** — REFUTED as cadence. Nothing in the tree forces a
  canonical `from_address` at pairing; first contact with a domain `from_address` is the retry-safe
  path.
- **"(a) schema-invalid message body → 401"** — CONFIRMED (kept, not refuted), but note it is
  covered by the same `except RuntimeError` as the unknown-sender condition; it is not a separate
  branch.
- The remaining components (mechanism, sender-side terminal classification, divergence) are
  CONFIRMED, not refuted.

---

## Additional mechanisms, earlier failure sites, new reachability (same trace)

1. **Over-broad `except RuntimeError` at `api.py:301` conflates ≥4 distinct conditions into one
   401.** It catches: (i) schema-invalid body (`runtime.py:635`), (ii) unknown sender with no cert
   (`runtime.py:656`), (iii) signature failure (`runtime.py:659`), (iv) `_root_identity_for_node`
   failure (`runtime.py:714`, reached when a cert exists but no root key is known). Each has a
   different correct disposition (400 / 404 / 401 / 500-ish). The claim names (i) and (ii); (iii)
   and (iv) are on the same statement sequence and were not reported.

2. **Signature failure returns the wrong machine code.** `runtime.py:659` raises
   `RuntimeError("message signature invalid: …")`; `api.py:301` returns `_problem(401, …)` →
   `LATTICE_UNAUTHORIZED`. PROTOCOL §9 names `LATTICE_INVALID_SIGNATURE` for this case. The status
   is right, the code is wrong. `q-error.md`'s "Checked and clean" asserts "runtime.py:659 clean
   (401 per §9 `LATTICE_INVALID_SIGNATURE`)" — that is inaccurate; the code is never emitted.
   (Side discovery, priced below.)

3. **The canonical unknown-sender arm never bootstraps the peer relationship.** For domain-form,
   the receiver calls `queue_domain_resolution` (Finding 1's site) and can later resolve and pin the
   sender; the 503 tells the sender to retry. For canonical, nothing is queued and the sender is
   told to stop. So the path that the docs call "authoritative" cannot bootstrap at all through the
   message route; it depends on out-of-band gossip + candidate verification (`_run_verify_candidates`)
   completing first. This is a new consequence beyond the report's "divergence" framing.

---

## Fix-direction constraints (what a repair must account for beyond the symptom)

- **Changing 401 → 404 per §9 does NOT fix the loss.** The sender's `else` at `runtime.py:1017`
  treats 404 (and 403) as terminal too. Returning `LATTICE_UNKNOWN_NODE` 404 instead of 401 leaves
  the message erased. A fix must either return `503 + Retry-After` for the recoverable
  unknown-sender condition (which the sender already retries) or change the sender's
  status classification so an unknown-node 404 is retryable. The two ends must be changed together.
- **A 503 alone is insufficient for the canonical case.** The receiver has no domain to queue for a
  canonical sender (`parse_address` gives `domain=None`), so `queue_domain_resolution(from_node_id)`
  would be a no-op — the retry would never converge unless the receiver independently discovers and
  verifies the sender's card. Any fix that just mirrors the domain-form 503 must add a node-keyed
  discovery path, or the retry loop is perpetual.
- **Must preserve true authentication failures.** Splitting the catch must not reclassify genuine
  signature failure or expired-cert failure away from 401. The split should distinguish
  "unknown sender" from "signature invalid"; the latter should also emit the §9
  `LATTICE_INVALID_SIGNATURE` code, which does not exist in `constants.py` today.
- **The malformed-body arm must go to 400 (`LATTICE_INVALID_ADDRESS`/bad request), and 400 is also
  terminal at the sender** — which is correct only because our own senders always emit valid
  `Message`s (`submit`/`accept` pre-validate). A repair must not route unknown-sender through 400.

---

## Checked and clean (coverage)

- `lattice/runtime.py:638–648` branch split (canonical vs domain) — read and correct as described.
- `lattice/runtime.py:667–681` `_certificate_for_node` + `_domain_for_node` — the None return for an
  unseen node is correct given no domain; the defect is the caller's mapping, not this function.
- `lattice/runtime.py:960–1019` `_send_outbound_message` status classification — 202 / 429 / ≥500 /
  else are internally consistent; the terminal treatment of 4xx is by design.
- `lattice/messages.py:150–173` `record_failure` — `retryable=False` → `mark_terminal(..., erase_content=True)`
  confirmed; the content-erasure claim is accurate.
- `lattice/api.py:75–84, 87–110` `_problem` / `_STATUS_PROBLEM_MAP` — the mapping is the single
  source of the code mismatch; eight generic codes, no §9-specific codes.
- `lattice/api.py:137–156` `RequestValidationError` handler — non-dict bodies do get 400; only the
  dict-but-invalid case reaches the 401 branch. (Clean, and it narrows the claim's arm (b).)
- The domain-form cold-sender 503 + `queue_domain_resolution` path (`api.py:303–316`) — correct
  retry semantics; this is the path a canonical sender is denied.
- `tests/test_api.py:277`, `tests/test_integration.py:36` — tests pin both sides of the divergence;
  the code path is exercised in tests, and the admin route makes it production-reachable.

## Enumeration

Composed command (closes the "which conditions reach the 401 and which statuses are terminal"
classes):

```
rg -rn "verify_inbound_message" lattice/ tests/            # → api.py:295 (only production caller)
rg -n "401|PROBLEM_CODE_UNAUTHORIZED" lattice/api.py       # → :77 map, :302 sole protocol 401
rg -n "RuntimeError" lattice/runtime.py                    # → :635,656,659,714 reach the catch
rg -n "response.status" lattice/runtime.py                 # → :976,1004,1017 status classification
rg -rn "sign_local_message|outbound_service.submit" lattice/   # → api.py:376 only production sender
rg -rn "LATTICE_INVALID_SIGNATURE|LATTICE_UNKNOWN_NODE|INVALID_ADDRESS" lattice/  # → empty
```

Instance table:

| Site | Condition | Correct disposition | Observed | Disposition |
|---|---|---|---|---|
| runtime.py:635 → api.py:302 | schema-invalid body | 400 | 401 LATTICE_UNAUTHORIZED | finding arm (b) |
| runtime.py:656 → api.py:302 | canonical sender unknown | 404 or 503+retry | 401, terminal at sender | finding arm (a) |
| runtime.py:659 → api.py:302 | signature invalid | 401 LATTICE_INVALID_SIGNATURE | 401 LATTICE_UNAUTHORIZED | side discovery SD-1 |
| runtime.py:714 → api.py:302 | no root identity | 401/500 | 401 LATTICE_UNAUTHORIZED | additional mechanism (2) |
| runtime.py:1004 | 429/5xx | retryable | retryable | clean |
| runtime.py:1017 | all other 4xx incl. 404/403/400/401 | terminal | terminal | driver of the loss; clean-by-design, wrong only because receiver mislabels |

## Side discoveries (single-pass; not folded into the verdict)

- **SD-1 [L] — signature failure emits `LATTICE_UNAUTHORIZED`, not §9's `LATTICE_INVALID_SIGNATURE`.**
  `runtime.py:659` → `api.py:301` → `_problem(401,...)` → `_STATUS_PROBLEM_MAP[401]`. No
  `LATTICE_INVALID_SIGNATURE` constant exists. Trigger: any peer whose message signature fails
  (hostile or key-rotation mismatch) receives the wrong machine code; §9 says clients SHOULD key on
  `code`. Frequency: latent (no grounded cadence; hostile/misconfigured peers only). Reachability:
  PRODUCTION, unauthenticated. Fix-direction: split the catch and add §9 codes to
  `constants.py`/`_STATUS_PROBLEM_MAP`; do not change the 401 status itself.
- **SD-2 [S-] — `_root_identity_for_node` failure reaches the same 401 catch** (`runtime.py:714`).
  When a cert is obtainable but no root key is known, the sender is told 401 "Message rejected",
  which is an internal inconsistency reported as an auth failure. Reachable only when pin/peer
  state is partially populated; I did not find a live producer. Single pass; needs one more.

## Bound

- No live infrastructure: operator behavior (which `from_address` form is typed) is not observable
  from the tree, so arm (a)'s cadence is recorded as a boundary, not as evidence. This is the exact
  point where the report's "DEMONSTRATED" traveled past the code.
- No live federated peer: whether a real peer returns 401 for first contact was verified against the
  in-tree receiver only (`api.py:301`); a third-party implementation's behaviour is out of reach.
- Test-only evidence is labelled: `tests/test_api.py:277` is the only place a canonical unknown
  sender is driven end-to-end; the production path is the admin submit route, which no test drives
  against an unknown receiver.
- I did not run the suite; the terminal-erasure path was traced statically through
  `record_failure` → `mark_terminal`.
