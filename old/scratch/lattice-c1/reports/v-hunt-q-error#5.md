# v-hunt-q-error#5 — PRIMED VERIFIER

Claim under test: `hunt-q-error#5` in `scratch/lattice-c1/reports/q-error.md`, reported **L** —
"Malformed `to_address` crashes the handler — HTTP 500, non-problem-details body."

Verdict: **CONFIRMED** at tier **L** (severity and frequency unchanged). Mechanism reproduced
live, not merely traced. One consequence sub-claim is refuted; one earlier, more-reachable failure
site was found on the same trace and is reported as a side discovery.

---

## Frame re-derived from source

- Route: `lattice/api.py:receive_message` (line 279 onward). Body param is a raw `dict[str, Any]`;
  the route never binds the `Message` model directly.
- `lattice/runtime.py:verify_inbound_message`:
  1. `Message.model_validate(message)` inside a try that wraps everything as `RuntimeError`.
  2. `parsed = parse_address(model.from_address)` **at line 638, outside that try**.
  3. cold-sender return, cert lookup, signature verify, block check.
- `lattice/protocol/models.py:226`: `to_address: str = Field(min_length=1, max_length=320)` — a
  string length bound only, no address-shape validator. Same for `from_address` (line 225).
- `lattice/addressing.py:parse_address` raises `AddressError` (MRO: `AddressError -> ValueError ->
  Exception`) when the input has no `@`; `AddressError` is **not** a `RuntimeError`.
- `lattice/api.py:_extract_domain_from_address` (line 120) calls `parse_address` with no guard.
- `create_app` registers only two exception handlers (`RequestValidationError`, `HTTPException`);
  no generic `Exception` handler and no ASGI middleware is added anywhere in `lattice/` (grep for
  `add_middleware|exception_handler|ServerErrorMiddleware` returns only those two sites). Default
  Starlette `ServerErrorMiddleware` therefore renders uncaught exceptions as `500 text/plain
  "Internal Server Error"`.

## Reproduction (live, `TestClient`, `raise_server_exceptions=False`)

Built a real `RuntimeCoordinator` via the tree's own `_make_node` and posted to
`/lattice/v1/messages`:

| Case | Result |
|---|---|
| known, signature-valid sender; `to_address="garbage"` | **500** `text/plain; charset=utf-8` → `'Internal Server Error'` |
| known, signature-valid sender; `to_address="bob@example.com"` | 202 signed receipt |
| unauthenticated; `from_address="garbage"` (valid everything else) | **500** `text/plain` → `'Internal Server Error'` |
| unknown sender; `to_address="garbage"` | 503 (cold-sender path returns before line 322) |

This closes each component of the claim against observed behaviour, not against the claim text.

## Per-sub-claim disposition

- **Mechanism (CONFIRMED).** `to_address="garbage"` passes model validation (string, length OK),
  passes signature/authorization because the sender is known, then `api.py:322`
  `_extract_domain_from_address` → `parse_address` raises `AddressError`, which no handler catches
  (nearest handlers are `except BlockedSenderError`/`except RuntimeError` around
  `verify_inbound_message` only, and the route has no outer try). Uncaught → Starlette 500.
- **Trigger (CONFIRMED).** Requires a *known, signature-verified* sender that writes a
  schema-valid message with a non-address `to_address`. Unknown/cold senders never reach line 322
  (503 at 310; canonical-unknown → 401 at 301). Reproduced.
- **Frequency (CONFIRMED reachability, LATENT cadence).** Population = every malformed-`to_address`
  message from a verified peer. No in-tree sender can produce this (`admin_submit` resolves
  `to_address` before signing; `sign_local_message` is called only after `resolve_destination`), so
  the population is outside-written peers only. That is a real production population but not a
  normal-operation cadence — I cannot ground a rate. Kept at **L**; the claim's "once per such
  message" is accurate and does not change the tier.
- **Outcome, half 1 (CONFIRMED).** Input-validation fault surfaces as HTTP 500 in
  `text/plain "Internal Server Error"`, not the §9 problem-details body and not 400. Exactly as
  stated.
- **Outcome, half 2 (REFUTED / overstated).** "the sender-side treats 5xx as retryable, so it
  re-sends the doomed message for the full retry schedule." The retry map is real
  (`runtime.py:1005+`: `status == 429 or status >= 500` → `record_failure(retryable=True)`), but the
  sender that emits a malformed `to_address` **cannot be an in-tree Lattice node** — local submission
  validates the address before signing (`admin_submit` → `resolve_destination`). So the retry
  consequence applies only to a non-conforming peer whose retry behaviour is not in this tree and is
  unverifiable from it. The claim presents it as a tree consequence; it is not one. Doesn't affect
  the tier (the defect is the misreported 500, which is proved).

## Added mechanism / earlier failure site (side discovery, traced)

**Malformed `from_address` also escapes as an unhandled 500 — and is unauthenticated.**
`lattice/runtime.py:638` calls `parse_address(model.from_address)` outside the `try` that turns
model errors into `RuntimeError`, and `AddressError` is a `ValueError`, so `api.py:301`
`except RuntimeError` does not catch it. A single schema-valid POST with `from_address` lacking
`@` (e.g. `"garbage"`) reaches this line **before** cert lookup, signature verification, the block
check, and the message rate limiter (`allow_message` is at `api.py:335`, after `api.py:322`).
Reproduced: 500 `text/plain`, no signature required.

- Location: `lattice/runtime.py:638` (parse) escaping `lattice/api.py:301` (handler).
- Trigger: any network peer POSTs `/lattice/v1/messages` with a body that satisfies `Message`
  (`kind/message_id/content/ttl_seconds/timestamp/signature` present) but whose `from_address` has
  no `@`. No key, signature, or prior relationship needed.
- Frequency: DEMONSTRATED — every such POST yields one 500; the request is public and, being before
  the rate limiter, is not budget-limited.
- Outcome: attacker-controlled unhandled exception → 500, non-problem-details; same misreport
  class as the claim, but with adversarial-input reachability and no authentication. Not a process
  crash (per-request only) and no state change, so it does not rise above the claim's tier.
- Confidence: traced (both sites read, handler set enumerated) + live reproduction. Reachability:
  PRODUCTION (public route).
- Tier: **L**, same family as the claim.

## Fix-direction constraints

- A repair that only wraps `to_address` at `api.py:322` is incomplete: the sibling parse at
  `runtime.py:638` escapes through the same missing handler. Both parse sites must be guarded.
- The correct mapping is `400` problem-details for malformed addresses — **not** the existing
  `except RuntimeError -> 401` path. A blanket widening of the `api.py:301` handler to `Exception`
  would relabel storage/identity faults as 401; narrow it to `AddressError` (or validate addresses
  in the `Message` model / before signing).
- The 503 cold-sender (`api.py:310`) and 403 own-domain-mismatch (`api.py:322-333`) semantics must
  survive: malformed-address handling must not swallow the `pin is None` cold-sender return.
- Note the ordering constraint: both crash sites precede `allow_message` (`api.py:335`). A repair
  keeping address parsing before the rate limiter leaves the unauthenticated 500 (and its
  log/CPU cost) unbudgeted; consider validating address shape before or alongside the limiter.
- The to_address parse feeds the §7 own-domain check. Separately (side discovery in the parent
  report, out of this verdict), a canonical `user@lat_<other-node>` yields `domain == ""` and skips
  that check; a repair to the parser must not fold that distinct gap into this one.

## Checked and clean

- `_STATUS_PROBLEM_MAP` / `_problem`: malformed-address outcomes are not represented; confirmed no
  existing 400 mapping is being misused — the 500 is genuinely unhandled, not a mapped 500.
- `require_content_length` (`api.py:189`) and `require_ready` precede the body handling and are not
  the failure site.
- The three genuine in-route exception branches — `BlockedSenderError` (293), `RuntimeError` (301,
  346) — were each traced and are not the site; the crash falls *between* them.
- `parse_address` / `_extract_domain_from_address` semantics verified directly: `""` and
  `"garbage"` raise `AddressError`; `"user@lat_abc"` returns `domain=""`; `"user@foo/bar"` raises
  (the `":/@"` guard rejects `/`).

## Enumeration

The assignment is a single-site verification, not a class-enumeration; the enclosing class was
closed with:

```
rg -n "add_middleware|exception_handler|ServerErrorMiddleware|ExceptionMiddleware" lattice/ -g '*.py'
rg -n "parse_address\(" lattice/ -g '*.py'
```

Result: exactly two registered handlers (`RequestValidationError`, `HTTPException`), no generic
handler, no middleware anywhere in `lattice/`. `parse_address` call sites: `runtime.py:638`
(unguarded, escapes), `api.py:122` via `_extract_domain_from_address` (unguarded, escapes),
`addressing.py:77` (`node_id_from_address`, guarded by design), plus signature/test callers. The
two unguarded sites are exactly the two unhandled-500 paths confirmed above.

## Bound

- External peer retry behaviour is outside the tree and unverified; the "sender re-sends for the
  full schedule" sub-claim is bounded there, not observed.
- No live deployment / provider behaviour was exercised; all reproductions used the in-tree
  `TestClient` and real runtime. Nginx edge limits (invariant 7) were not in scope and could mask
  the unauthenticated-`from_address` 500 at the edge, but nothing in `lattice/` does.
- The address-shape gap in `parse_address` for domains containing `/` is noted but not priced here
  (not the claim's defect; adjacent).
