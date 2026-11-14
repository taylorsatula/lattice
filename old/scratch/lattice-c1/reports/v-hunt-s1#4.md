# v-hunt-s1#4 — PRIMED VERIFIER

**Claim under test:** finding `hunt-s1#4` in `scratch/lattice-c1/reports/seam-s1.md` (reported tier
L) — "Malformed address components on the public messages route raise unhandled `AddressError` →
500 instead of a 4xx problem detail."

## Verdict

**CONFIRMED** — mechanism, trigger, and the from-address half of the frequency re-derived from
source and reproduced by execution. Severity L left unchanged. **One frequency sub-claim refuted**
(the to-address half is not "trivially constructible by anyone"); see below.

## Frame re-derivation (done before reading the claim's conclusion)

Independently established from source:

1. `POST /lattice/v1/messages` is public (preamble invariant 3). Its body parameter is
   `message: dict[str, Any]`; the `Message` Pydantic model is validated *inside* the coordinator
   (`lattice/runtime.py:632`), not at the FastAPI boundary (`lattice/api.py:287-292`).
2. `Message.from_address` / `Message.to_address` are `Field(min_length=1, max_length=320)` with no
   shape validator; no `model_validator` and no `parse_address` reference exists in
   `lattice/protocol/models.py` (`rg "model_validator|parse_address" lattice/protocol/models.py` →
   no match). So `"alice"` (no `@`) and `"bob@foo:bar"` both pass `Message.model_validate`.
3. `AddressError(ValueError)` (`lattice/addressing.py:11`). Empirically: `AddressError.__mro__` is
   `(AddressError, ValueError, Exception, BaseException, object)`; `issubclass(AddressError,
   RuntimeError)` is `False`. `parse_address("alice")` raises `AddressError("address must contain
   '@'")`; `parse_address("bob@foo:bar")` raises `AddressError("invalid domain: foo:bar")`.
4. `verify_inbound_message` (`runtime.py:619-667`) wraps only `Message.model_validate` in
   `except Exception → RuntimeError` (line 632-634). `parsed = parse_address(model.from_address)`
   at **line 638 is outside any `try`**. It runs *before* certificate lookup and signature
   verification (line 643+), so the from-address branch is pre-authentication.
5. `receive_message` catches exactly two exception types around that call: `except
   BlockedSenderError` (line 293) and `except RuntimeError as exc` (line 301). `AddressError` is
   neither. Only two app-level handlers are registered (`RequestValidationError`, `HTTPException`,
   `api.py:137,158`); there is no `ValueError` handler (`rg "exception_handler" lattice/` → 2
   hits, both in `api.py`).
6. On the warm path the handler calls `_extract_domain_from_address(message.get("to_address",""))`
   at `api.py:322` — itself calling `parse_address` (`api.py:120-123`) — also outside any `try`.
7. FastAPI/Starlette default: an unhandled non-HTTP exception raised in a sync route is caught by
   `ServerErrorMiddleware` and returned as a bare 500. Executed in isolation against the installed
   versions (fastapi 0.111.0 / starlette 0.37.2): a route raising a `ValueError` subclass returns
   `status 500`, body `Internal Server Error` (plain text, **not** an RFC 9457 problem detail; the
   traceback goes to the server log, not the response).
8. `runtime._send_outbound_message` treats `response.status >= 500` as retryable
   (`runtime.py:999`), so the claim's retry framing matches this repo's own client.

## Decisive trace — the from-address half (the strong half)

Any network peer POSTs a JSON object passing `Message.model_validate` but with
`from_address` lacking `@`. Minimal body: `{"kind":"message","message_id":"x",
"from_address":"alice","to_address":"bob@example.com","content":"hi",
"timestamp":"2024-01-01T00:00:00Z","signature":"x"}`. Route dependencies `require_content_length`
(present) and `require_ready` (ready node) pass; `message` is a dict; `verify_inbound_message`
reaches line 638, `parse_address("alice")` raises `AddressError`; neither `except` in the handler
nor any app handler matches; `ServerErrorMiddleware` returns 500. **No signature is required** —
the raise precedes verification.

## Decisive trace — the to-address half (the narrow half)

`verify_inbound_message` returns a verified `(from_node_id, False)` only after cert lookup and
`verify_message` succeed (`runtime.py:643-663`). The handler then reaches `api.py:322`
(`_extract_domain_from_address`). A `to_address` of `"bob"` or `"bob@foo:bar"` raises
`AddressError` out of the handler → 500. This half therefore requires a **signature-verified**
message, i.e. a sender whose operational cert this node already holds and whose signature verifies
— a known/pinned peer, or a canonical `from_address` node for which a cert is available. (On the
cold path the handler returns 503 at `api.py:311` *before* line 322, so to-address parsing is
never reached there.)

## Sub-claims — individually dispositioned

- **Mechanism (both halves).** CONFIRMED. `AddressError` is a `ValueError`, not a `RuntimeError`;
  both call sites sit outside `try`; no `ValueError` app handler exists; Starlette returns 500.
- **Contract violation.** CONFIRMED. `verify_inbound_message`'s docstring at `runtime.py:630`
  states "Raises RuntimeError only for structural problems (bad address format etc.)", but the
  bad-address branch raises `AddressError(ValueError)`. The api handler's design depends on that
  contract.
- **Trigger reachability, from-address half.** CONFIRMED, PRODUCTION, pre-authentication, any peer.
- **Trigger reachability, to-address half.** CONFIRMED but under-stated in the claim. Reachable in
  production only by a sender that passes signature verification; not "anyone who can reach the
  route."
- **Frequency.** REFUTED IN PART. The claim's frequency sentence — "any remote sender (hostile or
  merely buggy client) posting such a body; trivially constructible by anyone who can reach the
  route" — is true for the from-address half and false for the to-address half. The to-address
  half is DEMONSTRATED only over the population of signature-verified senders (the same population
  the rate limiter already knows), so it is narrower; absent a known peer sending a malformed
  `to_address`, it does not fire. The from-address half alone grounds DEMONSTRATED frequency.
- **Outcome wording.** Minor imprecision: the response is a bare 500 `Internal Server Error` text
  body, not a "500 + traceback" — the traceback is server-side log output. The substance (no 4xx
  problem detail, log noise) holds. Not material.
- **Test coverage.** CONFIRMED absent: no test posts a malformed address to `/messages`
  (`rg "AddressError|from_address|to_address" tests/` — only `tests/test_addressing.py` exercises
  `parse_address` directly; `tests/test_api.py` message bodies all use valid forms). So the defect
  is production-reachable and untested.

## Severity correction

**L, unchanged.** The bad outcome is a misreported status code (500 in place of the intended
401/400 problem detail) plus server-log noise on a public route — the scale's L row
("misreported error code ... with no lasting harm"). It does not reach M: no wrong custody/ack
semantics, no stuck/lost queue item, no wrong rate/quota *decision* on the accepted path (see the
added mechanism below for the limiter, which is a bypass not a decision), and no divergence that
produces wrong state. It does not reach H: `ServerErrorMiddleware` contains the exception; the
process does not crash and per-request work is bounded. Report tier L is correct.

## Frequency correction

**From-address half: DEMONSTRATED.** Concrete population: any peer able to reach the route
(hostile scanner, fuzzer, or a buggy client that omits `@`); a single POST reproduces it. Cadence:
per malformed request; no coincidence required beyond the body shape.

**To-address half: narrower than claimed.** Population: signature-verified senders only — peers
whose cert is pinned and whose signature verifies, or canonical senders with an available cert.
This requires a known peer to emit a malformed `to_address`, which its own (in-tree) client will
not do because `resolve_destination`/`sign_local_message` parse the address first
(`runtime.py:580,607`). Demonstrated only over that narrower population.

## Reachability kind

- from-address half: **PRODUCTION** (unauthenticated network request).
- to-address half: **PRODUCTION**, sender-authenticated (requires a valid signature).

## Added mechanisms / earlier failure sites / new reachability (same trace)

1. **Malformed-address requests bypass the message rate limiter entirely.** The raise at
   `runtime.py:638` occurs before `receive_message` reaches `runtime.rate_limiter.allow_message`
   at `api.py:335`. So a peer can issue unbounded 500-triggering requests without consuming a
   single message token — a crash-path variant of seam-s1 finding 5's cold-sender bypass. Priced:
   **L** (bounded per-request cost: one JSON parse, one `parse_address`, one logged traceback;
   no state written). Fix-direction: rate limiting or request-size/velocity guarding must sit
   before body parsing, or malformed input must be counted; catching the exception to return 4xx
   alone does not close the bypass.
2. **Traceback-log amplification at ERROR level.** Each malformed request produces a full
   server-side traceback (`ServerErrorMiddleware` logs it), letting an unauthenticated peer drive
   log volume and disk growth. Priced: **L** (bounded per request, no durable state). Fix-direction:
   return a problem detail instead of raising so the error is logged at a bounded level.

These are additive to the claim; the claim did not name the rate-limiter bypass.

## Fix-direction constraints

- A repair that catches `AddressError` at only one of the two call sites leaves the other
  unguarded: both `verify_inbound_message` (from-address) and `_extract_domain_from_address`
  (to-address) must be covered. Catching at `api.py` alone does not make `verify_inbound_message`'s
  docstring contract true; catching inside `verify_inbound_message` alone does not cover the
  handler-local to-address parse.
- The robust fix is shape validation in the `Message` model so the failure surfaces as
  `RequestValidationError` → the existing 400 handler, closing both sites at once. That validator
  must accept the canonical `user@lat_*` form as well as the human `user@domain` form — the repo's
  own callers emit canonical `to_address`es, so a validator that only admits `user@domain` would
  break legitimate traffic.
- Escaping a 500 is not the same as classifying the error: the from-address failure is a bad
  *sender* credential (401-ish) while the to-address failure is a bad *recipient* (400/403-ish);
  a repair should not collapse both into one code. The message rate-limiter bypass (added
  mechanism 1) is not addressed by the code mapping at all.

## Checked and clean

- `AddressError` raised *inside* `verify_inbound_message`'s `except (IdentityError, ValueError)`
  block at `runtime.py:659` is converted to `RuntimeError`; the signature-failure surface in that
  block is closed. Clean.
- `Message.model_validate` failures are wrapped (`runtime.py:632-634`) → `RuntimeError` → 401.
  Clean.
- `_extract_domain_from_address` on a canonical `lat_*` `to_address` returns `""` without raising
  (`parsed.domain is None`). That is seam-s1 finding 1's mechanism, not this finding; no exception
  escapes here. Clean for this claim.
- The two registered app exception handlers correctly convert `RequestValidationError` and
  `HTTPException` (including 500) to RFC 9457 bodies; they simply do not see `ValueError`.
  Correct as written.

## Bound

- Could not run the package end to end (`rfc8785` absent from this environment), so the 500 result
  is established by an isolated FastAPI/Starlette reproduction of an unhandled `ValueError`
  subclass against the installed versions (fastapi 0.111.0, starlette 0.37.2), plus reading of the
  two app exception handlers, rather than by exercising `create_app` directly.
- Did not open `lattice/storage/repositories.py`, `lattice/topology.py` internals, `webhook.py`, or
  `transport.py` beyond the retry constant; none bear on this claim's mechanism.
- Not verified live: whether a real deployment's ASGI server variant logs the traceback at ERROR
  (assumed uvicorn default). The response status/body assertion (500, non-problem-detail) is
  reproduced, not assumed.
- The to-address half's population size (how often a pinned peer emits a malformed to_address) is
  a live-traffic property; stated as narrower than claimed, not quantified.
