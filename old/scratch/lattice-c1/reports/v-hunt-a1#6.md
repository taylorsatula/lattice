# v-hunt-a1#6 — PRIMED VERIFIER on hunt-a1 finding 6

Claim under test: hunt-a1.md finding 6, "[L] — Structural message errors mapped to 401
Unauthorized instead of 400", reported tier L.

Method: re-derived the frame from source before reading the claim's consequence. Read
`lattice/api.py:receive_message` (lines 281–354), `lattice/runtime.py:verify_inbound_message`
(619–663), `lattice/addressing.py:parse_address` (44–75), `lattice/protocol/models.py:Message`
(218–257), `lattice/api.py:_problem`/`_STATUS_PROBLEM_MAP` (75–105),
`lattice/runtime.py:_send_outbound_message` (949–1019), `docs/PROTOCOL.md` §8–§11,
`tests/test_api.py`. Reproduced the decisive path against the in-repo app with the repository's
own `.venv` and `TestClient` (no file written; script passed on stdin).

## Verdict: ADJUSTED

The mechanism is confirmed and empirically reproduced for schema-invalid bodies. One of the two
named triggers is refuted; it is an uncaught `AddressError` (500), not the 401 branch. Frequency is
overstated.

## Findings

### Correction 1 — mechanism: CONFIRMED (reproduced)

- Location: `lattice/api.py:receive_message` (handler `except RuntimeError` at line 301) →
  `lattice/runtime.py:verify_inbound_message` (line 636).
- Evidence: `except RuntimeError as exc: return _problem(401, "Message rejected", str(exc))` at
  api.py:301; `except Exception as exc: raise RuntimeError(f"invalid message: {exc}")` at
  runtime.py:635-636. `_problem(401, …)` emits `LATTICE_UNAUTHORIZED`
  (`_STATUS_PROBLEM_MAP[401]`, api.py:77; `PROBLEM_CODE_UNAUTHORIZED="LATTICE_UNAUTHORIZED"`,
  constants.py:42).
- Trigger: a remote peer POSTs a body that is a JSON object but fails `Message.model_validate`
  (`extra="forbid"`, `priority: Literal["normal","high","urgent"]`, `ttl_seconds ge=1`,
  tz-aware `timestamp` — models.py:218-257). The route signature is `message: dict[str, Any]`
  (api.py:286), so FastAPI does not validate the schema; `model_validate` is the first check.
- Evidence (executed, `.venv`, TestClient against `create_app(runtime)`): signed-valid message with
  `priority="asap"` → `401 LATTICE_UNAUTHORIZED`; with `ttl_seconds=0` → `401 LATTICE_UNAUTHORIZED`.
- Outcome: a request body that is malformed (pre-signature) is reported as an authorization
  failure with code `LATTICE_UNAUTHORIZED`. Bounded: `_send_outbound_message` classifies any status
  that is not 202, not 429 and not >=500 as non-retryable (runtime.py:1012-1018), so the finding's
  note that 400 and 401 are both terminal is correct — no retry amplification.
- Severity: L, UNCHANGED. This is exactly the scale's "misreported error code" with a bounded
  outcome; the sender cannot confuse it for accepted custody.
- Frequency: CORRECTED to LATENT/hostile-trigger-only. The claim says "DEMONSTRATED — any remote
  peer, per message". A conforming Lattice sender cannot emit a schema-invalid message: outbound
  goes through `OutboundService.submit` → `Message.model_validate` (messages.py:101) and only rows
  that passed are posted by `_send_outbound_message`. The triggering population is therefore a
  hostile OR non-conforming/buggy peer implementation, not normal operations. The normal-operation
  cadence that produces this trigger is zero. Per the calibration rule the frequency is ungrounded,
  so it is LATENT and the tier is capped at L (which it already carries).
- Confidence: mechanism traced AND reproduced; trigger traced and reproduced; frequency corrected
  with the outbound-validation trace.

### Correction 2 — second named trigger: REFUTED

- Claim: "…or whose `from_address` has neither domain nor node ID. All return 401."
- Refutation (traced + reproduced): `verify_inbound_message` calls `parse_address(model.from_address)`
  at runtime.py:638 OUTSIDE any try. `parse_address` raises `AddressError` (a `ValueError`,
  addressing.py:10; `issubclass(AddressError, RuntimeError) is False`, verified in the interpreter)
  for a no-`@` address, empty username, empty host, or `:/@` in the host. The route catches only
  `BlockedSenderError` and `RuntimeError` (api.py:293,301), so the `AddressError` escapes the handler.
- Reproduced: signed-valid message with `from_address="alice"` raised
  `lattice.addressing.AddressError: address must contain '@': alice` out of
  `api.py:292 → runtime.py:638 → addressing.py:51`. In production this is an unhandled 500 (only
  `RequestValidationError` and `HTTPException` handlers are registered, api.py:135-173).
- The named branch is also dead code: `parse_address` returns either `node_id` (for `lat_…`) or a
  non-empty `domain` (host is checked non-empty at addressing.py:56), so
  `parsed.node_id is None and parsed.domain is None` is unreachable. The
  `raise RuntimeError("message from_address has no domain or node ID")` at runtime.py:648-649 can
  never execute.
- Consequence: this half is not the claimed 401 misreport; it is an uncaught-exception 500 on the
  same route (same class as hunt-a1 finding 4, but on `from_address` rather than `to_address`).

### Severity / frequency summary

- Severity: L (unchanged). The surviving mechanism is a misreported error code with a bounded,
  non-retryable outcome.
- Frequency: corrected to LATENT/hostile-trigger-only (see Correction 1).
- Reachability kind: PRODUCTION (public route, no auth required to reach the handler) for the
  schema-invalid half; the corrected trigger requires a hostile or non-conforming peer. The refuted
  half is also production but manifests as an uncaught 500.

## Additional mechanisms / earlier failure sites on the same trace

- The docstring at runtime.py:630-631 ("Raises RuntimeError only for structural problems (bad
  address format etc.)") is inverted relative to actual behavior. Structural *address* problems
  raise the unhandled `AddressError` (500); signature/cert failures raise `RuntimeError` (401). A
  fix that trusts the docstring will miscategorize both.
- 401 responses carry no `WWW-Authenticate` header: `_problem` (api.py:87-104) emits only the RFC
  9457 body. RFC 7235 requires the challenge header on 401. Side discovery, priced L
  (misreported/underspecified response, no state impact), frequency = every 401,
  production. Fix constraint: if 401 is retained, add the challenge; if the mapping moves to 400,
  this disappears.
- Unknown/nonexistent operational certificate also maps to 401 (runtime.py:654-656), while
  PROTOCOL.md §9 lists `LATTICE_UNKNOWN_NODE` = 404. `tests/test_api.py::test_receive_message_rejects_unknown_sender`
  asserts 401 for this, codifying it as intended. Side discovery, price L but effectively
  test-fixed; not folded into this finding.

## Fix-direction constraints

- A one-token repair changing `_problem(401, …)` to `_problem(400, …)` at api.py:301 would break
  signature/certificate failures, which PROTOCOL.md §9 assigns to 401
  (`LATTICE_INVALID_SIGNATURE`, `LATTICE_EXPIRED_CERTIFICATE`). The repair must distinguish the
  failure class inside `verify_inbound_message` — a typed exception (e.g. a structural/validation
  subclass) or a separate `ValidationError` branch — not the status code at the route.
- The repair must also cover the uncaught `AddressError` path at runtime.py:638, which is the same
  route's earlier failure site and currently produces a 500; otherwise schema/address errors still
  misreport (as 500). Note `PROBLEM_CODE_BAD_REQUEST`/`LATTICE_BAD_REQUEST` exists, but the
  documented `LATTICE_INVALID_ADDRESS` (=400) is defined nowhere in the code — a fix that intends to
  emit it must add the constant.
- PROTOCOL.md §8 states that a "message malformed after signature check" yields a 202 rejected
  receipt. The repair must decide whether pre-signature schema/address failure is 400 problem+json
  or a 202 rejected receipt, and keep that consistent with the sender's terminal/retry
  classification in `_send_outbound_message`.

## Checked and clean

- `BlockedSenderError(RuntimeError)` (runtime.py:60) is caught before the generic `RuntimeError`
  handler (api.py:293), so the blocked-sender 202-receipt path is not shadowed by the 401 branch.
- The route's parameter is `dict[str, Any]`, and a non-object JSON body yields a
  `RequestValidationError` → 400 problem+json (api.py:135-158), so non-object bodies do not reach
  the 401 branch.
- `_STATUS_PROBLEM_MAP` maps 401 → `LATTICE_UNAUTHORIZED` consistently; no mismatch between the
  emitted status, type URI, and code.
- No message relay, no root-key load, and the route stays behind `require_content_length` +
  `require_ready` as reported by the hunter; those sub-claims were spot-checked and hold.
- Outbound classification (runtime.py:1012-1018) confirms 400/401 are both non-retryable, so the
  finding's bounded-outcome claim is accurate.

## Enumeration

Command closing the "which exceptions escape a route handler" class (executed):

    rg -n "raise |except " lattice/api.py
    rg -n "class (AddressError|ResolutionError|CustodyError|BlockedSenderError|RateLimitError)" lattice/*.py

Result: `AddressError(ValueError)`, `ResolutionError(ValueError)`, `CustodyError(ValueError)`,
`BlockedSenderError(RuntimeError)`. `receive_message` catches only `BlockedSenderError` and
`RuntimeError`; `AddressError` (runtime.py:638, from_address) and `ResolutionError` (runtime.py
resolution path) escape their intended handlers. The from_address `AddressError` escape is the
refuted half of this claim; the ResolutionError escape is hunt-a1 finding 5 and was not re-audited.

| Site | Emitted | Actual failure | Disposition |
|---|---|---|---|
| api.py:301 `except RuntimeError` | 401 LATTICE_UNAUTHORIZED | schema-invalid body (RuntimeError from runtime.py:636) | confirmed (Correction 1) |
| api.py:301 `except RuntimeError` | 401 LATTICE_UNAUTHORIZED | from_address with neither domain nor node ID | **refuted** — dead branch; real cause is uncaught AddressError → 500 (Correction 2) |
| runtime.py:638 `parse_address` | escapes handler | malformed from_address | earlier failure site, same route (Correction 2) |

## Bound

- Production behaviour of uncaught exceptions was not observed against a live uvicorn server; the
  `TestClient` re-raises, and a plain 500 is inferred from FastAPI's default handler (no
  `Exception` handler is registered). Mechanism (escape from the handler) is confirmed; the exact
  500 body is SUSPECTED.
- No hostile peer implementation was stood up; the schema-invalid trigger was reproduced with a
  locally signed message submitted to the in-repo app, which is the same code path a remote peer
  would drive.
- Only `.venv` dependencies were available (system python3 lacks `rfc8785`); all reproduction ran
  in `.venv`.
