# v-hunt-a1#4 — PRIMED VERIFIER

Claim under test: **hunt-a1#4** in `scratch/lattice-c1/reports/hunt-a1.md`, reported tier **L**.
Title as filed: "Malformed to_address raises AddressError → unhandled 500 on public route".

Frame re-derived from source before reading the claim as a claim (see Enumeration). The
claim's own frame was not inherited: `to_address` validation in `Message` was read directly,
`parse_address` was executed against the malformed input, and the route's `try/except`
scope was read line-by-line.

## Findings

### 1. [L] — Malformed `to_address` escapes the route's handlers as an unhandled `AddressError` → HTTP 500 (CLAIM CONFIRMED)

- Location: `lattice/api.py:322` in `receive_message` → `_extract_domain_from_address`
  (`lattice/api.py:120`) → `parse_address` (`lattice/addressing.py:44`)
- Evidence: `to_domain = _extract_domain_from_address(message.get("to_address", ""))` sits at
  function scope, **outside** the `try/except (BlockedSenderError, RuntimeError)` that wraps
  only `runtime.verify_inbound_message(message)`. `_extract_domain_from_address` does
  `parsed = parse_address(address)` with no guard; `parse_address` raises
  `AddressError(ValueError)` for `"address must contain '@'"`, empty username/host, invalid
  domain chars, or length > 253. `AddressError.__mro__` verified by execution:
  `AddressError, ValueError, Exception`. Only `RequestValidationError` and `HTTPException`
  handlers are registered on the app (`lattice/api.py:137,158`); no `ValueError` handler and no
  middleware. `Message.to_address` is `Field(min_length=1, max_length=320)` with no format
  check (verified by executing `Message.model_validate` with `to_address="alice"` → accepted).
- Trigger: a **pinned/known** federated peer POSTs `/lattice/v1/messages` a body that
  `verify_inbound_message` fully accepts (its `from_address` resolves to a node with a known
  operational certificate — canonical `lat_…` or a pinned domain — and the message signature
  verifies over the raw dict, which includes the peer-chosen `to_address`) and whose
  `to_address` is malformed (`"alice"`, `"a@"`, `"@host"`, `"a@bad:host"`, >253-char host, …).
  `cold_sender` is False for a known peer, so the route proceeds past the 503 branch to line
  322 and crashes. A message whose `from_address` domain is unpinned returns 503 *before* line
  322, so an anonymous sender cannot reach the crash.
- Frequency: DEMONSTRATED but bounded to the federated-peer population. Concrete population:
  every peer whose messages this node has pinned a certificate for; cadence: one trigger per
  message that carries a malformed `to_address`. Honest peers construct `to_address` through
  `resolve_destination` → `resolve_address` → `parse_address` and therefore emit a well-formed
  address; the trigger requires a hostile peer or a peer with an address-formatting bug. No
  additional coincidence is needed beyond the malformed field itself — a single such peer
  triggers per-message at will. Reachability kind: **PRODUCTION** (public route, no auth beyond
  federated signature).
- Outcome: the receiver returns the framework default `500 Internal Server Error` instead of a
  `400` (`LATTICE_INVALID_ADDRESS`, docs/PROTOCOL.md §9) or `403`. No custody is taken and no
  state is mutated — the crash is at line 322, before `inbound_service.accept`. The sending
  node's outbound delivery treats `status >= 500` as retryable (`lattice/runtime.py:1004`) with
  `max_attempts = 10` (`lattice/messages.py:43`), so a single malformed message produces a
  bounded burst of ≤10 repeated 500s, then terminal drop.
- Severity correction: **L unchanged.** The trace above produces a misreported error code on a
  client-input fault with no state loss, no custody error, no cross-peer reach, and no
  client-visible stack trace (see refuted sub-claim). That is exactly the L definition.
- Frequency correction: **L-grade DEMONSTRATED, sharpened.** The claim's phrasing "any known
  peer, per message, with a client address-formatting bug" is accurate; I make explicit the
  gate the claim left implicit — the sender must be *known* (pinned cert), because cold senders
  exit at the 503 branch before line 322. Not reachable by an unauthenticated peer.
- Confidence: **traced** — mechanism, trigger, and frequency. The FastAPI/uvicorn
  unhandled-exception → plain-500 behaviour is the one component I checked statically only
  (no `debug=True` at `lattice/cli.py:720`); labelled in Bound.

## Refuted / corrected sub-claims

- **"500 + traceback on the public message route"** — partially refuted as to the *client*.
  `uvicorn.run(app, …)` (`lattice/cli.py:720`) is not constructed with `debug=True`, so the
  sender receives the framework's plain `500 Internal Server Error` body; the traceback is
  logged server-side only. The 500 is real; "traceback on the route" overstates a
  client-visible leak. Tier unchanged (L both ways).
- Mechanism, trigger, and the `<10`-attempt retry bound are **confirmed**, not refuted:
  `lattice/runtime.py:1004` (`response.status == 429 or response.status >= 500` →
  `retryable=True`) and `RetryPolicy(max_attempts=10)` (`lattice/messages.py:43,230`).

## Additional mechanisms / earlier failure sites (same trace)

1. **Earlier `AddressError` site — malformed `from_address`.** `runtime.verify_inbound_message`
   calls `parse_address(model.from_address)` at `lattice/runtime.py:638`, *outside* its
   `try/except` (that try wraps only `Message.model_validate`). A peer sending
   `from_address="alice"` passes model validation (length-only constraint) and raises
   `AddressError` — a `ValueError`, which the route's `except RuntimeError` does **not** catch —
   → the same unhandled 500, at a site *earlier* than finding #4's. The method docstring
   claims it "Raises RuntimeError only for structural problems (bad address format etc.)"; the
   code contradicts it for the bad-format subset. Reachable in PRODUCTION by any federated peer,
   independent of `to_address`. Same defect class and same fix (catch `AddressError`/`ValueError`;
   map to 400 per PROTOCOL §9). Related to hunt-a1#6's premise but distinct: #6 assumes
   structural errors surface as 401, whereas bad-format `from_address` surfaces as 500.
2. **`admin_submit` second escape.** `resolution.resolve_address` calls `parse_address` at
   `lattice/resolution.py:163`; `admin_submit` catches only `RuntimeError` around
   `resolve_destination` (`lattice/api.py`). A malformed `req.to_address` raises `AddressError`,
   a second `ValueError` that escapes the same handler that hunt-a1#5 identified for
   `ResolutionError`. Operator action; same 500 class.

## Fix-direction constraints

- Catching `AddressError` at the `to_address` extraction in `api.py:322` repairs **only**
  finding #4. The `from_address` parse at `runtime.py:638` fires *earlier* on the same request
  and must be handled too, or the malformed-address 500 survives under a different field.
- The repair should classify a malformed address as a client error — `400` /
  `LATTICE_INVALID_ADDRESS` per docs/PROTOCOL.md §9 — not `401` (reserved for signature/cert
  failures) and not `500`. Fixing it by broadening the existing `except RuntimeError` to also
  catch `ValueError` would silently reclassify genuine `CustodyError`/internal `ValueError`s
  that flow through adjacent handlers; the catch must be scoped to `AddressError`.
- Do not reorder the recipient-ownership check ahead of signature verification: the check at
  line 322 is deliberately post-`verify_inbound_message`. The ownership bypass (hunt-a1#2) and
  this crash share line 322; a fix touching that line must preserve verification-first
  ordering and must not "fix" #2 by simply skipping the extract on parse failure (that would
  extend #2's bypass to malformed addresses).

## Checked and clean

- `Message.to_address` constraint confirmed length-only; no hidden `field_validator`.
- Route `try/except` scope confirmed: handlers cover `verify_inbound_message` only; line 322
  and the 403 guard are unguarded.
- No app-level `ValueError` handler / middleware: `rg "exception_handler|add_exception_handler|middleware"` in `api.py` returns only the two handlers.
- `verify_message` (`lattice/protocol/signing.py:52`) does not touch `to_address` format; the
  signature canonicalizes the full raw dict (`lattice/identity.py:178-184`,
  `canonicalize`), so a peer can sign any `to_address` value.
- Retry bound: `status >= 500` → retryable, capped at 10 attempts; the retry-burst sub-claim is
  accurate.

## Enumeration

Exception-surface closure across route bodies (the assignment's enumerable question — which
exception types can cross a route body uncaught):

`rg -n "raise |except " lattice/api.py` cross-checked with
`rg -n "class (AddressError|ResolutionError|CustodyError|BlockedSenderError|RateLimitError)" lattice/*.py`
and `python3 -c "from lattice.addressing import AddressError; print(AddressError.__mro__)"`.

| Exception | Base(s) | Caught in `api.py`? | Site reaching it | Disposition |
|---|---|---|---|---|
| `AddressError` | `ValueError` | no | `api.py:322` (`to_address`) | **finding #4** |
| `AddressError` | `ValueError` | no | `runtime.py:638` (`from_address`) | added mechanism 1 |
| `AddressError` | `ValueError` | no | `resolution.py:163` via `admin_submit` | added mechanism 2 |
| `ResolutionError` | `ValueError` | no | `api.py:392` | hunt-a1#5 (not this claim) |
| `CustodyError` | `ValueError` | yes | `api.py:341` | clean |
| `BlockedSenderError` | `RuntimeError` | yes | `api.py:293` | clean |

Executed check: `Message.model_validate({… "to_address": "alice" …})` → accepted;
`parse_address("alice")` → `AddressError: address must contain '@': alice`.

## Design risks (max 2)

1. The message route has no top-level exception boundary; every `ValueError` subclass raised by
   a callee is one unguarded statement away from a 500. As the address/exception surface grows,
   the same class recurs (three instances already). A single `AddressError`-scoped boundary at
   the route would close the class; scattering `except ValueError` at call sites will not.
2. Recipient-ownership enforcement depends on a single parse helper whose failure mode is an
   exception rather than a reject (hunt-a1#2 bypasses the same line via canonical form). The
   validation should be total — return a reject, not raise.

## Bound

- No live daemon or HTTP client was run. FastAPI/uvicorn default unhandled-exception → plain
  `500 Internal Server Error` (no `debug=True`) is traced statically from `lattice/cli.py:720`.
  A deployment that enables debug or installs out-of-tree error middleware could change the
  client body; not verifiable from the repo.
- Did not audit downstream `inbound_service.accept`/repository paths beyond confirming the
  crash precedes them.
