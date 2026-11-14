# v-hunt-b1c#3 — PRIMED VERIFIER

Claim under test: **hunt-b1c finding 3 [L]** — "Malformed `from_address`/`to_address` raises
unhandled `AddressError`: HTTP 500 instead of a 4xx problem detail."

Verdict: **CONFIRMED** (mechanism, trigger, frequency, and tier all hold; two additional uncaught
sites of the same class found on the admin route). Corrected tier: **L** (unchanged).

---

## Frame re-derived from source (before checking the claim)

- `lattice/api.py:Create_app`: the only exception handlers registered are
  `@app.exception_handler(RequestValidationError)` (L137) and `@app.exception_handler(HTTPException)`
  (L158). No `ValueError` handler, no catch-all. `rg -n "exception_handler" lattice/api.py` → 2 hits.
- `lattice/api.py:receive_message`: `try: from_node_id, cold_sender = runtime.verify_inbound_message(...)`
  with `except BlockedSenderError` (L293) and `except RuntimeError as exc` (L301). The later accept
  block catches `CustodyError` (L339) and `RuntimeError` (L346).
- `lattice/runtime.py:verify_inbound_message` L638: `parsed = parse_address(model.from_address)` —
  outside any try/except (the only try/except in the method wraps `Message.model_validate` at
  L621-624).
- `lattice/api.py:_extract_domain_from_address` L121-124: `parsed = parse_address(address)` unguarded;
  called at L322 from `receive_message` for `message.get("to_address","")`.
- `lattice/addressing.py`: `class AddressError(ValueError)` (L11); `parse_address` raises it for no
  `@` (L51), empty user/host (L58/60), `:/@` in host (L67), host >253 (L69).
- `lattice/protocol/models.py:Message` (L218-249): `from_address`/`to_address` are `Field(min_length=1,
  max_length=320)` strings; no address-shape validator and `signature` has no base64url validator.
  So `"abc"` passes `Message.model_validate`.
- **Constant that decides the bug**: `AddressError` is a `ValueError`, `RuntimeError` is its sibling
  under `Exception`. `except RuntimeError` cannot catch `AddressError`. (Also
  `ResolutionError`/`CustodyError` are `ValueError`; `BlockedSenderError` is `RuntimeError`.)
- **What the route contract promises**: every other invalid-input path on this route returns an
  RFC 9457 problem-detail (`_problem` in `_STATUS_PROBLEM_MAP`); a `ValueError` escaping the route
  reaches Starlette `ServerErrorMiddleware` and is rendered as a 500.

## Component-by-component

- **Mechanism — CONFIRMED.** `parse_address(model.from_address)` at `runtime.py:638` runs before any
  signature work and outside the try/except; `AddressError(ValueError)` is not caught by the handler's
  `except RuntimeError`. Reproduced end-to-end.
- **Trigger — CONFIRMED, both variants reproduced.**
  - *from_address, unauthenticated*: `POST /lattice/v1/messages` with an otherwise-valid `Message`
    JSON body and `from_address:"abc"` → **HTTP 500, `text/plain`, body `Internal Server Error`**
    (harness: `tests.conftest._make_node` + `create_app` + `TestClient(raise_server_exceptions=False)`).
  - *to_address, authenticated peer*: a signature-valid message from a seeded known peer with
    `to_address:"abc"` reaches `api.py:322` → **HTTP 500**; the same message with a well-formed
    `to_address` returns **202**. Both reproduced on one runtime.
- **Frequency — CONFIRMED as demonstrated.** The from_address variant is reachable by any
  unauthenticated network client that can POST one well-formed-JSON message (public federation route,
  invariant 3); malformed addresses are routine scanner/fuzzer traffic and any client bug produces
  one. The to_address variant requires a certificate-valid known peer. Ungated, production.
- **Severity — L, unchanged.** Outcome is a misreported error class (500 + plain-text instead of a
  400 problem detail), plus a traceback in the logs; no state is written before the raise (verified:
  the raise is before `allow_message` and before any custody write), no corruption, no crash (uvicorn
  isolates the exception per request), no unbounded exhaustion. This is exactly the preamble's
  "misreported error code" tier. Not M: no custody/ack divergence is created (the 500 is headerless
  and the in-tree sender treats it as retryable, but nothing is lost or mis-accepted). Not H: no
  crash, no resource exhaustion.
- **Reachability kind — PRODUCTION.** from_address variant: unauthenticated production request.
  to_address variant: production request from a verified peer.

### Sub-claims checked and upheld

- "`AddressError` is a `ValueError`, not `RuntimeError`; handler catches only `BlockedSenderError` and
  `RuntimeError`" — accurate (api.py:293/301; addressing.py:11).
- "`create_app` registers handlers only for `RequestValidationError` and `HTTPException`" — accurate.
- "`Message` validates `from_address`/`to_address` only as length-bounded strings" — accurate
  (models.py:225-226).
- "same result for a well-formed `from_address` with a malformed `to_address` at line 322" — accurate,
  with the caveat the claim omits: reaching line 322 requires a signature-valid message from a known
  peer (the from_address must verify). Not a refutation; a precision note.

No sub-claim refuted.

---

## Additional mechanisms / earlier failure sites (same class)

**A. Admin route does not catch `AddressError` OR `ResolutionError` → HTTP 500.**
`lattice/api.py:admin_submit` (L385): `runtime.resolve_destination(req.to_address)` (L392) is wrapped
only by `except RuntimeError as exc: return _problem(400, ...)` (L393). `resolve_destination` →
`resolution.py:resolve_address` calls `parse_address` (raises `AddressError`) and raises
`ResolutionError` for an unresolvable domain — **both are `ValueError`**, so neither is caught and
both escape to a 500. Reproduced on the same harness (bearer `admin`):
- malformed `to_address:"abc"` → **500**;
- well-formed `to_address:"user@nonexistent.invalid"` (unresolvable) → **500**.
The later `except (RuntimeError, ValueError)` at L407 is a different try block (`sign_local_message` /
`outbound_service.submit`) and does not cover L392. Reachability: PRODUCTION, admin-authenticated.
Severity: L (misreported 400 → 500 for operator input/config errors). Frequency: operator typos and
unpinned destinations on the admin submit path — low but concrete. Fix-direction constraint: the same
as the main finding — the `RuntimeError`-only guard is structurally wrong for the `ValueError`-rooted
error family; patching only `receive_message` leaves this site live.

**B. `verify_inbound_message` docstring is wrong about its own error contract.** L627-628: "Raises
RuntimeError only for structural problems (bad address format etc.) that cannot be recovered by async
resolution." It does not convert `AddressError`; a bad address format raises `AddressError`. This is
the latent doc/contract divergence that produced the bug — a repair should align the docstring and the
code (convert at the source, or update the contract).

---

## Checked and clean

- **Model validation is not the guard**: `Message.model_validate` accepts `from_address`/`to_address`
  `"abc"` (length-only), so no earlier layer returns a 400 for this input. Confirmed by the 500
  reproduction.
- **No state written before the raise**: in `receive_message` the from_address raise is inside
  `verify_inbound_message`, before `queue_domain_resolution`, `allow_message`, and
  `inbound_service.accept`; the to_address raise at L322 precedes `allow_message`/`accept`. A 500
  here takes no custody, consumes no rate token, writes no row.
- **`BlockedSenderError` path is correct**: subclass of `RuntimeError`, caught at L293 → signed
  rejected receipt; not affected.
- **`CustodyError` at the accept site is caught**: `except CustodyError` (L339) precedes
  `except RuntimeError` (L346) and catches the `ValueError` subclass explicitly — correct at that
  site. (The other uncaught sites are A above.)
- **`cli.py:333` catches `AddressError`** for contact import — correct operator-facing handling; no
  defect.
- All `parse_address` callers enumerated (see Enumeration): `runtime.py:580` (admin/self-resolve,
  called from `sign_local_message` under the `except ValueError` block — clean),
  `runtime.py:589→resolution.py:163` (admin, site A), `runtime.py:638` (inbound, this finding),
  `api.py:122` (inbound, this finding), `api.py:322` (inbound, this finding),
  `addressing.py:77` (`node_id_from_address`, has its own `except AddressError`), `cli.py:333`
  (caught). No additional unguarded production site beyond A.

## Enumeration

Composed command closing the class of "`parse_address` results reached without a matching
`AddressError`/`ValueError` guard":

```
rg -n "parse_address|resolve_address|resolve_destination|resolve_local_address|_extract_domain_from_address" lattice/ -g '*.py'
```

Disposition of every call site:

| Site | Guard at runtime | Disposition |
|---|---|---|
| `addressing.py:77` `node_id_from_address` | `except AddressError: return None` (L78) | clean (documented) |
| `resolution.py:163` `resolve_address` | none in-function | propagates; only reached via below |
| `runtime.py:580` `resolve_local_address` | called from `sign_local_message` under `except (RuntimeError, ValueError)` (api.py:407) | clean |
| `runtime.py:589` `resolve_destination` | `admin_submit` `except RuntimeError` only | **site A (500, new)** |
| `runtime.py:638` `verify_inbound_message` | `receive_message` `except RuntimeError` only | **this finding (500)** |
| `api.py:122` `_extract_domain_from_address` | callers only | — |
| `api.py:322` → `:122` | `receive_message` `except RuntimeError` only | **this finding (500, to_address variant)** |
| `cli.py:333` | `except AddressError` (L334) | clean |

Guard-class check (`rg -n "except (RuntimeError|ValueError|AddressError|ResolutionError)" lattice/api.py`
→ `293 BlockedSenderError`, `301 RuntimeError`, `339 CustodyError`, `346 RuntimeError`,
`393 RuntimeError`, `407 (RuntimeError, ValueError)`). Confirms L392 and L301/322 are guarded only by
`RuntimeError`, while the escaping classes are `ValueError`-rooted.

## Design risks

None. The two-site class is mechanical and fully traced; no speculative item added.

## Bound

- Real deployment path was approximated with Starlette's `TestClient(raise_server_exceptions=False)`,
  which exercises the same `ServerErrorMiddleware`. I did not run a live uvicorn socket; production
  uvicorn renders the uncaught exception as `500 Internal Server Error` (standard Starlette behavior,
  not provider-dependent). Stated as a boundary, not silence.
- `httpx`/Starlette versions in `.venv` reproduced the behavior; no other runtime environment tested.
- No live DNS/network was exercised; the "unresolvable domain" admin case was driven in-process.
