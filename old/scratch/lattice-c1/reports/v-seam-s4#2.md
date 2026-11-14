# v-seam-s4#2 — PRIMED VERIFIER on seam-s4 finding #2

Claim under test: `seam-s4.md` finding **2 [L]** — "The custody receipt's signature is never
verified by any sender-side code." Reported tier **L**.

Method: frame re-derived from source before reading the claim against the code. Read
`lattice/runtime.py:_send_outbound_message` (949–1019), `_run_outbound_delivery` (922–948),
`_certificate_for_node`/`_domain_for_node`/`_root_identity_for_node` (666–720),
`lattice/messages.py:build_receipt`/`accept`/`record_success` (143–316),
`lattice/protocol/signing.py` (full), `lattice/protocol/models.py:Receipt` (302–325),
`lattice/api.py:receive_message` (285–355), `lattice/transport.py:request` (98–147),
`lattice/storage/repositories.py:mark_terminal` (775–823), `tests/test_runtime.py` (255–290),
`tests/test_vectors.py:90–131`, `docs/PROTOCOL.md` §8. Empirical: ran the unmodified
`OutboundTransport` call shape against the repo venv (urllib3 2.7.0).

## Verdict

**CONFIRMED** at **L**. The mechanism is fully traced and reproducible; the gating and the
latent frequency are correctly stated; the severity/tier is correct and I leave it unchanged.

## Sub-claim disposition

| # | Sub-claim | Verdict |
|---|---|---|
| a | Sender-side 202 handling compares only `message_id`/`node_id`/`status`; no signature is checked | CONFIRMED |
| b | `signing.py` defines `sign_receipt` and there is **no** production receipt verifier in the tree | CONFIRMED |
| c | The comment `# Validate the signed custody receipt...` misreports a three-field comparison as signature validation; `api.py:352` claims the sender validates it | CONFIRMED |
| d | Trigger is GATED behind the transport `TypeError` fault (hunt-b1b #1); reachable in TESTS ONLY until repaired | CONFIRMED (gate independently reproduced) |
| e | Frequency is latent/ungroundable → L | CONFIRMED |
| f | "`verify_webhook_envelope` is the only other kind-specific wrapper with a verifier" | **REFUTED (wording)** |
| g | Implied reading that §8 mandates sender-side verification | **REFUTED as stated** — §8 defines the `signature` field but contains no sender MUST-verify clause |

### Evidence for the refuted halves

- (f) `signing.py` contains **four** kind-specific verifier wrappers — `verify_well_known` (27),
  `verify_peer_card` (37), `verify_message` (52), `verify_webhook_envelope` (72). The clause is
  factually wrong. What is true: `sign_block` and `sign_receipt` each have no counterpart, and
  `webhook_envelope`'s signer is a bare `sign_object` call rather than a `sign_*` wrapper. The
  wording does not affect the core finding.
- (g) `docs/PROTOCOL.md` §8 (lines 237–250) lists `signature: Operational signature` and states the
  rejected-receipt finality and byte-identical-persistence rules, but never says the *sender* MUST
  verify the receipt. The claim's "the entire reason receipts are signed per §8" is an
  interpretation, not a quoted requirement. The gap is real regardless: the field exists, the
  destination signs, no consumer checks.

### Decisive trace (mechanism)

`lattice/protocol/signing.py:62` — `sign_receipt` exists; `rg "verify_receipt"` → zero hits in the
whole tree. `rg 'verify_object\('` production sites: `cli.py:367` (`contact_card`),
`runtime.py:566` (`peer_card`), `signing.py:44/59/84` (`peer_card`/`message`/`webhook_envelope`).
**No production `verify_object(..., "receipt")` call exists.** The only receipt verification in the
tree is `tests/test_vectors.py:97`.

`lattice/runtime.py:977–999` — the 202 branch parses `json.loads(response.data)` and gates solely on
three `.get()` comparisons (`message_id`, `node_id`, `status != "accepted"`); `signature`, `kind`,
and `received_at` are never inspected. `signature`/`kind`/`received_at` are all present in the
`Receipt` model (`protocol/models.py:302–322`) and the signed preimage.

## Severity correction

**None — L retained.** Trace that produces the correction: the bad outcome is silent message loss
(`record_success` → `mark_terminal(..., erase_content=True)` at `repositories.py:782` rewrites
`content`/`message_json` to `[erased]` and sets `status='delivered'`), which is H-shaped *data loss*.
But the loss only fires when a **non-destination** endpoint returns a 202 whose three plaintext
fields match. In normal operation the legitimate destination signs and returns a valid receipt, so
the three fields always match and the missing signature check never changes behavior — the gap is
purely defensive. The forger must sit at the TLS-verified, pinned host (`transport.py:134`
`assert_hostname=hostname`, pool TLS). Additionally the destination can always sign a false
`accepted` itself, so receipt verification removes no power from the legitimate peer. Narrow trigger
+ bounded outcome = L, by the pinned scale. Not M (no plausible normal-operation divergence), not
S- (mechanism is proven, not unproven).

## Frequency correction

**None — latent, L retained.** The claim grounds no operation population because none exists: the
only in-tree path exercising the 202 branch is the mocked-transport delivery test
(`tests/test_runtime.py:283–290`, which feeds an **unsigned** three-field body and asserts
`row["status"] == "delivered"`). That is reachability kind **TESTS ONLY / GATED behind hunt-b1b #1**
(the outbound transport fault). I reproduced the gate myself: calling the unmodified call shape on
`urllib3.PoolManager().urlopen("POST", …, body=…, fields=…, assert_hostname=…)` under venv urllib3
2.7.0 raises `TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument
'fields'`. uv.lock pins urllib3 2.7.0, so no live 202 is ever received today. A frequency I cannot
ground is latent by the standing rule.

## Additional mechanisms / earlier failure sites (same trace)

1. **The response body is never parsed as a `Receipt` model.** The 202 branch uses raw
   `json.loads` + `.get()`, so `Receipt`'s `extra="forbid"`, base64url `signature` validator, and
   tz-aware `received_at` validator (`models.py:310–322`) are all bypassed. `kind == "receipt"` is
   also unchecked — a body `{"kind":"message","message_id":…,"node_id":…,"status":"accepted"}`
   passes. Same root cause as finding #2, broader than signature-only.
2. **Unauthenticated `_circuit_record_success`.** A matching three-field body from a mispointed
   endpoint resets the circuit breaker against the destination (`runtime.py:1003`) and writes a
   `delivered` audit row (`_audit_outbound_delivered`), so a bogus endpoint launders the peer's
   circuit/audit state as well as destroying the message. Collateral of the same gate.
3. **No earlier failure site found.** `verify_inbound_message` (the receiver side) does correctly
   verify message signatures before custody; the receipt-signing receiver path
   (`messages.build_receipt`) is sound. The asymmetry is confined to the sender's 202 branch.

## Fix-direction constraints

- A repair must verify the receipt signature against the **destination's operational certificate
  obtained from local trust state** (`_certificate_for_node(to_node_id)` / pin — do NOT trust a key
  supplied in the response body), then `Receipt.model_validate` the body. Checking the signature
  against a key taken from the response would be self-authenticating and worthless.
- Verification is gated behind hunt-b1b #1 (transport `TypeError`); a fix that adds receipt
  verification without repairing the transport leaves the path dead, and a fix to the transport that
  omits redirect control re-exposes hunt-b1b #4 (SSRF). Order the repairs so receipt verification
  lands with, not after, the transport fix.
- Must not disturb rejected-receipt finality: verify first, then branch on `status`; a verified
  `rejected` must be terminal (seam-s4 #1 / hunt-b1b #2), not retryable.
- `_certificate_for_node` can trigger a network resolve; verification must tolerate resolution
  failure without mislabeling a verified receipt as "invalid custody receipt".

## Checked and clean

- The gate itself (hunt-b1b #1): re-derived and empirically reproduced on the repo venv — every
  `OutboundTransport.request` call raises before a request is sent. The gating premise of the claim
  holds.
- Receiver-side receipt production (`messages.build_receipt`, `accept`) signs correctly via
  `sign_object(receipt, "receipt")`; `api.py` returns it on both accepted and rejected paths.
- `verify_inbound_message` verifies message signatures before custody; the blocked-sender
  `BlockedSenderError` path issues a *signed* rejected receipt. No receiver-side gap.
- `mark_terminal(erase_content=True)` does what the claim's outcome describes.
- `tests/test_vectors.py:90–131` pins receipt preimage and cross-kind confusion — the verifier
  exists only as a test/vector consumer.

## Enumeration

Composed command closing the receipt-verifier class:

```
rg -n "verify_receipt|verify_object\(|sign_receipt|\"receipt\"" lattice/ --type py
```

Instance table:

| site | kind | disposition |
|---|---|---|
| `protocol/signing.py:62 sign_receipt` → `sign_object(...,"receipt")` | receipt | signer exists |
| `messages.py:316 build_receipt` (caller) | receipt | producer, signed |
| *(no `verify_receipt` definition anywhere)* | receipt | **missing verifier — finding #2** |
| *(no production `verify_object(...,"receipt")`)* | receipt | **missing call site — finding #2** |
| `tests/test_vectors.py:97 verify_object(...,"receipt")` | receipt | test-only, not production |
| `verify_object` production sites: `cli.py:367`, `runtime.py:566`, `signing.py:44/59/84` | contact_card / peer_card / message / webhook_envelope | none verify receipt |

## Bound

- Live infrastructure (real TLS peer, real DNS, mispointed-endpoint appliance) unavailable; the
  forger-set narrowing rests on the transport's TLS/`assert_hostname` and invariant 7, read not
  observed against a live pinned host.
- The gate's production persistence assumes the deployed urllib3 is the pinned 2.x. A deployment
  overriding urllib3 to 1.x could activate the 202 branch; not reachable from the tree.
- I did not run the daemon end-to-end; the 202 branch was exercised via the in-tree mocked-transport
  test, matching the claim's own stated reachability.

## Side discoveries (single-pass candidates, not confirmed work)

- **Unauthenticated circuit/audit launder** (mechanism 2 above). Severity L (bounded — needs a
  mispointed endpoint), frequency latent (same gate), fix constraint: gate circuit/audit success on
  the same verified-receipt predicate. Single pass; not independently confirmed.
