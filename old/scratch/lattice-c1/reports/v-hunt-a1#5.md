# v-hunt-a1#5 — PRIMED VERIFIER on hunt-a1 finding 5

Claim under test: finding 5 in `scratch/lattice-c1/reports/hunt-a1.md` —
"[L] admin_submit: ResolutionError is not a RuntimeError → unhandled 500"
(`lattice/api.py:admin_submit`, E4 site line 393).

Method: re-derived the frame from source first (what `resolve_destination` actually calls, what
exceptions that path raises, what `except RuntimeError` at api.py:393 can catch, what exception
handlers are registered), then checked the claim against that. Read `lattice/api.py` end-to-end,
`lattice/resolution.py` end-to-end, `lattice/addressing.py`, `lattice/runtime.py:575-760`,
`lattice/protocol/models.py:216-256`, `deploy/lattice.nginx.conf`, `tests/test_api.py`. Then ran an
in-process `TestClient` reproduction against a real `RuntimeCoordinator` (see Reproduction).

## Verdict: CONFIRMED (tier L)

All components — mechanism, trigger, frequency — traced and empirically reproduced.

### Frame re-derived from source

- **What the caller passes.** `admin_submit` (`api.py:384`) takes `SubmitRequest`
  (`api.py:49`): `to_address` is `Field(min_length=1, max_length=320)` with no format validator.
  `require_admin` runs first (valid bearer required); `runtime.allow_submission()` gates
  backpressure only.
- **What the callee raises.** `runtime.resolve_destination` (`runtime.py:587`) is a one-line
  delegation to `resolve_address(address, self._resolver)` (`resolution.py:154`). That function
  raises only `ValueError` subclasses:
  - `ResolutionError(ValueError)` (`resolution.py:25`) on "address has no domain", failed `pin`
    (DNS/HTTP/`NetworkPolicyError`/well-known validation failures, all wrapped at
    `resolution.py:52-109`), "could not pin", or missing `node_id`.
  - `AddressError(ValueError)` (`addressing.py:11`) from `parse_address` for a malformed address
    (no `@`, empty user/host, `:/@` in host, host > 253).
  It never raises `RuntimeError`. Verified with the interpreter:
  `ResolutionError.__mro__ = [ResolutionError, ValueError, Exception, BaseException, object]`;
  `issubclass(ResolutionError, RuntimeError) is False`; `issubclass(AddressError, RuntimeError) is False`.
- **The decisive statement.** `api.py:391-394`:
  ```
  try:
      _, to_node_id = runtime.resolve_destination(req.to_address)
  except RuntimeError as exc:
      return _problem(400, "Address resolution failed", str(exc))
  ```
  The clause is dead for every input this path produces. The exception propagates to Starlette's
  `ServerErrorMiddleware`.
- **No handler.** `create_app` registers handlers only for `RequestValidationError` and
  `HTTPException` (`api.py:126,152`); neither covers a bare `ValueError`. Confirmed by reading the
  full factory. A minimal FastAPI app raising `ValueError` under `TestClient(raise_server_exceptions=False)`
  returns `500 Internal Server Error`.

### Sub-claim disposition

- "`ResolutionError` subclasses `ValueError`, not `RuntimeError`" — **CONFIRMED** (source + MRO).
- "`resolve_address` raises `ResolutionError`" — **CONFIRMED** (`resolution.py:168, 175, 179`).
- "Intended 400 branch is skipped; a plain 500 is produced" — **CONFIRMED** (handler registry +
  empirical 500, below).
- "Trigger: operator submits to an unresolvable domain (typo, dead domain, DNS failure)" —
  **CONFIRMED**, and broadened (see Additional mechanisms: a malformed `to_address` hits the same
  dead clause via `AddressError`).
- "No state corruption; nothing written before resolution" — **CONFIRMED**. `resolve_destination`
  performs no write for a failing domain; the 500 is returned before `sign_local_message` /
  `outbound_service.submit`.
- "Frequency: DEMONSTRATED" — **CONFIRMED with a narrowed population** (see Corrections).

No sub-claim refuted.

## Reproduction (executed, read-only)

Built a real `RuntimeCoordinator` (`tests/conftest.py` construction) and
`create_app`, then posted via `TestClient(raise_server_exceptions=False)`:

```
ADMIN unresolvable domain -> 500 Internal Server Error
ADMIN malformed to_address -> 500 Internal Server Error
PUBLIC malformed from_address -> 500 Internal Server Error
```
(`to_address="bob@does-not-resolve.invalid"` and `to_address="alice"` respectively, valid admin
bearer.) The third line is a separate site — see Side discoveries.

## Corrections

- **Severity: L, unchanged.** The outcome is a misreported error code (`500` instead of the
  intended `400`) on an authenticated loopback admin route, with no state change. That is the
  scale's canonical L ("a misreported error code ... with no lasting harm"). It does not reach M:
  no wrong state, no custody/ack divergence, nothing durably written before the failure. It does
  not reach H: the sender is an operator who holds the admin bearer; there is no secret exposure,
  no cross-peer reach, no crash.
- **Frequency: DEMONSTRATED, population narrowed.** The claim's population is "every admin
  submission to an unresolvable domain." The sharpened trace: `resolve_address` consults the pin
  cache first (`resolution.py:170`); if the domain is already pinned, no network lookup occurs and
  the 500 cannot fire. The trigger therefore requires a `to_address` whose domain is **not already
  pinned** and fails resolution — a first-contact domain typo, a domain added to the pin store that
  is later cleared, or a transient DNS/well-known failure on a first submission. This is the normal
  operator workflow (submitting to a peer not yet gossiped with) and typos are ordinary operator
  input, so the population is groundable and the frequency stays DEMONSTRATED. The tier is
  unaffected. The claim's parenthetical ("typo, dead domain, DNS failure") is accurate.
- **Reachability kind: PRODUCTION.** `POST /lattice/v1/admin/messages/submit` is loopback-restricted
  by nginx (`deploy/lattice.nginx.conf:74-76`, `allow 127.0.0.1/::1`) but is a live route an
  operator or any local process on the host reaches over HTTP. Not tests-only, not gated behind
  another defect. (The operator may alternatively use an offline CLI path that handles
  `ResolutionError` correctly at `cli.py:579`, but that is a different command, not the admin
  route; it does not gate this defect.)

## Additional mechanisms / earlier failure sites (same site)

1. **The `except RuntimeError` clause is wholly dead, not merely mismatched for one exception.**
   No statement reachable from `resolve_destination` raises `RuntimeError`. Both failure classes
   on this path — `ResolutionError` (unresolvable domain) and `AddressError` (malformed
   `to_address`, e.g. `"alice"`) — become 500. Confirmed empirically. A repair that catches only
   `ResolutionError` leaves the malformed-address 500 in place; the finding's title names only
   `ResolutionError`, so the fix must cover `AddressError` too.
2. **No earlier failure site.** The exception is raised inside `resolve_address` and first surfaces
   at `api.py:392`; nothing catches it between. The second `try` block's
   `except (RuntimeError, ValueError)` (`api.py:407`) is a *separate* try and cannot catch a
   failure from the first block.

## Fix-direction constraints

- The repair must make the caught type match the raised type. Catching `(RuntimeError, ValueError)`
  at `api.py:393` (aligning with the already-correct second block at `api.py:407`) covers both
  `ResolutionError` and `AddressError`. Catching bare `ValueError` has the same effect here because
  both exception classes in this path are `ValueError` subclasses; it would also risk masking a
  genuine internal `ValueError` from a repository, so the two-named-class catch is preferable.
- The intended response is 400 (`_problem(400, "Address resolution failed", ...)`). A repair must
  decide whether a transient DNS/transport failure deserves 400 (client input) or 502/503
  (upstream); `ResolutionError` conflates both by design, so a blanket 400 is coarse but matches
  the existing intent. Making `resolve_destination` document and raise a single typed error is the
  alternative and keeps the caller's catch honest.
- The same narrow-`except` shape exists on the public message route (`api.py:301`); a fix that
  reclassifies exceptions at one call site should not assume the other is covered. See Side
  discoveries.

## Checked and clean

- `require_admin` (`api.py:172`): case-insensitive `bearer ` prefix, `secrets.compare_digest`
  against the runtime bearer; both admin routes depend on it. No bypass.
- `runtime.resolve_destination` performs no write; a failing resolution leaves no durable trace
  (no pin row for a failed domain — `pin` upserts only after a successful resolve, `resolution.py:122-137`).
- `resolve_address` for an already-canonical `lat_...` address performs no network lookup
  (`resolution.py:161-162`), so canonical `to_address` submissions cannot hit this 500.
- The `admin_status` route and the second submit `try` block are unaffected; `api.py:407` correctly
  catches `(RuntimeError, ValueError)` including `CustodyError`.
- Both exception handlers emit `application/problem+json` with the mapped type/code; the missing
  coverage is only the bare-`ValueError` class, not a handler bug.

## Enumeration

Exception classes raised on the `resolve_destination` path, and every `except` in `api.py`:
```
rg -n "raise |except " lattice/api.py
rg -n "class (AddressError|ResolutionError|CustodyError|BlockedSenderError)" lattice/*.py
rg -n "def resolve_destination|def resolve_address" lattice/runtime.py lattice/resolution.py
```
Output (relevant):
```
lattice/resolution.py:25: class ResolutionError(ValueError):
lattice/addressing.py:11: class AddressError(ValueError):
lattice/runtime.py:587:    def resolve_destination(self, address: str) -> tuple[str, str]:
lattice/runtime.py:589:        return resolve_address(address, self._resolver)
lattice/resolution.py:154: def resolve_address(...)
lattice/api.py:390-394: try: resolve_destination ... except RuntimeError ...
lattice/api.py:301: except RuntimeError   (public route, see Side)
lattice/api.py:407: except (RuntimeError, ValueError)
```
The class is closed: only two exception types cross `resolve_destination`, neither is a
`RuntimeError`, so `api.py:393` catches none of them. Disposition: finding (this report).

## Side discoveries (single-pass, priced)

1. **Malformed `from_address` on the public message route → unhandled 500 (new, distinct site).**
   `receive_message` calls `runtime.verify_inbound_message` (`api.py:293`), which validates the
   `Message` model (only `from_address` length is constrained, `models.py:225`) and *then* calls
   `parse_address(model.from_address)` (`runtime.py:636`) **outside** the `try` that wraps
   `ModelError` into `RuntimeError`. A `from_address` with no `@` (e.g. `"alice"`) raises
   `AddressError(ValueError)`, which `except RuntimeError` at `api.py:301` does not catch →
   unhandled 500 on the public `POST /lattice/v1/messages`. Reproduced empirically. This refutes
   the third trigger in finding 6 ("from_address has neither domain nor node ID ... returns 401"):
   `parse_address` cannot yield a valueless parse (it either sets `domain` or `node_id`), and a
   non-parseable `from_address` produces 500, not 401. Severity **L** (misreported error code /
   traceback on a public route; a single request, no crash or resource growth). Frequency
   **DEMONSTRATED**: per request, unauthenticated — signature verification happens after the parse.
   Reachability **PRODUCTION** (public route). Fix-direction: wrap the `parse_address` call in
   `verify_inbound_message` so `AddressError` becomes a structural `RuntimeError` (or catch
   `AddressError` at the route and map to 400/401); the same `except`-narrowness class as the
   claim under test.
2. **`_extract_domain_from_address` also raises `AddressError` on the public route (latent).**
   `api.py:312` calls `_extract_domain_from_address(message.get("to_address",""))` with no
   `try`, so a signature-valid message whose `to_address` has no `@` also produces a 500. This is
   the public-route analogue of the admin `AddressError` failure (finding 4 reported the
   malformed-`to_address` public case already; recorded here only as the same-class confirmation,
   not re-priced). Frequency: known peer per malformed message. Reachability PRODUCTION.

## Design risks (max 2)

1. `ResolutionError` conflates client-input errors (bad address) and upstream failures (DNS,
   transport, invalid well-known); any single-status handler will misreport one class. Not a
   current fault beyond finding 5, but it constrains correct status mapping.
2. The two submit `try` blocks catch different type sets (`RuntimeError` vs
   `(RuntimeError, ValueError)`), so the same class of failure has two different status
   outcomes depending on which block raises. Not a current fault at `api.py:407`.

## Bound

- Live production behavior of the admin route was not exercised; reachability via the operator is
  traced through nginx (`allow 127.0.0.1/::1`) and the route definition. The reproduction used a
  `TestClient` in-process against a real `RuntimeCoordinator`; Starlette/Pydantic behavior is thus
  confirmed, but no live daemon, systemd socket, or nginx instance was involved.
- Whether the operator's *deployed* workflow would more commonly hit the admin route or the offline
  CLI path is not determinable from the tree; the CLI path (`cli.py:579`) handles `ResolutionError`
  correctly, so the defect's realized frequency depends on which surface operators use. Stated as a
  boundary, not resolved.
- Transient-vs-permanent DNS failure rates are environmental and unmeasured; the trigger is proven,
  its cadence is operator-driven and not quantifiable from the tree.
