# v-hunt-s1#3 — PRIMED VERIFIER

Claim under test: **hunt-s1#3** in `scratch/lattice-c1/reports/seam-s1.md` — "admin_submit maps a
failed destination resolution to 500, not the intended 400" (reported tier **L**).

## Verdict: CONFIRMED (tier L unchanged)

## Re-derived frame

`POST /lattice/v1/admin/messages/submit` → `lattice/api.py:admin_submit` (line 384). Sequence:

1. `require_admin` bearer check (line 385).
2. `if not runtime.allow_submission(): return 503` (line 388-389).
3. `try: _, to_node_id = runtime.resolve_destination(req.to_address) except RuntimeError as exc:
   return _problem(400, "Address resolution failed", str(exc))` (line 391-394).
4. Separate `try: … sign … submit … except (RuntimeError, ValueError): return _problem(400 …)`
   (line 395-407) — the catch the resolution call is **outside of**.

`runtime.resolve_destination` (runtime.py:587) is a straight passthrough to
`resolution.resolve_address(address, self._resolver)` (resolution.py:155).

`resolve_address` first calls `addressing.parse_address(address)` (resolution.py:163). The reachable
raise sites:

- `parse_address` raises `AddressError(ValueError)` for a `to_address` lacking `@`, empty user/host,
  invalid host chars, or >253 host (addressing.py:48-75).
- For an unpinned human domain, `resolver.pin(domain)` → `resolve()` → `resolve_with_ip()` raises
  `ResolutionError(ValueError)` on transport failure, non-200, content-type mismatch, bad JSON,
  domain mismatch, bad root key, node-ID mismatch, bad signature, bad op-cert (resolution.py:49-127).
- `if pin is None: raise ResolutionError(...)` and `node_id` non-str → `ResolutionError`
  (resolution.py:172-178).

Class hierarchy verified at runtime:

```
$ .venv/bin/python -c "from lattice.resolution import ResolutionError; from lattice.addressing import AddressError; print(issubclass(ResolutionError, RuntimeError), issubclass(AddressError, RuntimeError))"
False False
```

`ResolutionError` and `AddressError` are `ValueError` subclasses, **not** `RuntimeError`. The
handler catches `RuntimeError` only. No `app.exception_handler` in `create_app` handles `ValueError`
— only `RequestValidationError` (api.py:100) and `HTTPException` (api.py:120). So the exception
escapes the route, is caught by Starlette `ServerErrorMiddleware`, and becomes a bare 500.

Runtime reproduction (temp script, no repo write) using the tree's own `tests/conftest._make_node`:

```
'bob'                            -> 500 Internal Server Error
'bob@unresolvable.example.com'   -> 500 Internal Server Error   (BoomTransport raises TransportError)
```

With `raise_server_exceptions=True` the traceback terminates at `admin_submit` → `resolve_destination`
→ `resolve_address` → `parse_address` raising `AddressError`, confirming the escape site.

## Component disposition

- **Mechanism — CONFIRMED.** Wrong exception class caught; `ValueError` subclasses escape; 500
  instead of the handler's own `_problem(400, "Address resolution failed", …)`.
- **Trigger — CONFIRMED.** An authenticated admin POST with (a) a malformed `to_address` (no `@`,
  `SubmitRequest` imposes only `min_length=1, max_length=320`, api.py:66), or (b) a human-form
  `to_address` whose domain cannot be fetched/pinned. Canonical `user@lat_*` addresses return early
  in `resolve_address` without network and never trigger this. Production path (admin route is
  intended; bearer-authenticated).
- **Frequency — CONFIRMED, with correction to the claim's wording.** The claim's "routine failure
  mode of the submit operation" is right in kind but the population is narrower than "any admin
  submit": only human-form addresses to destinations that are unpinned **and** fail resolution, or
  syntactically malformed addresses. That is a real, recurring operator event (typo, remote down,
  DNS/well-known failure) but not every submit. Demonstrated, L-appropriate.
- **Reachability kind — PRODUCTION** (bearer-authenticated operator action against the live admin
  route). Not tests-only, not gated.

## Severity / frequency corrections

- **Severity: L unchanged.** The outcome is a misreported error code plus traceback log noise, with
  no state corruption, no custody taken, and no lost queue item (the message is never submitted).
  The pinned scale assigns "a misreported error code" to L. The admin-only caller base bounds blast
  radius. Not M.
- **Frequency: unchanged at L, wording tightened** (see above). It is grounded — the trigger
  population (admin submits with bad/unresolvable human destinations) is a concrete recurring
  operation, so it is DEMONSTRATED rather than latent.

## Refuted sub-claims

None. The claim's mechanism, trigger, and frequency each verified against source and against a live
reproduction. The only correction is to the frequency's phrasing (population narrower than "any admin
submit"), not its tier.

## Additional mechanisms / earlier failure sites / new reachability

- No new reachability: `resolve_destination` has exactly one caller in the tree
  (`api.py:392`), verified by `grep -rn resolve_destination lattice/ tests/`.
- Earlier failure site: none before the `resolve_destination` call; `allow_submission` (503) is a
  distinct, correctly-handled failure.
- The same `except RuntimeError`-too-narrow shape recurs at `receive_message` (api.py:301/346) for
  `verify_inbound_message` and at api.py:393; that is the sibling finding hunt-s1#4, not this claim's
  trace, and is not re-reported here.
- Dead defensive branch: `resolve_address`'s `if parsed.domain is None: raise ResolutionError(...)`
  (resolution.py:168-169) is unreachable — `parse_address` returns `node_id=None` only when `domain`
  is set, and the `node_id is not None` early return precedes it. Harmless; not a defect.

## Checked and clean

- `require_admin` / `require_ready` dependency chain around the route: bearer compare is
  constant-time, and no ValueError path originates in them.
- `allow_submission` backpressure 503 path: correct and distinct.
- The sign/submit `except (RuntimeError, ValueError)` block does close `sign_local_message`
  (RuntimeError) and `outbound_service.submit` (CustodyError(ValueError)) — the author's intent is
  demonstrably to map ValueErrors to 400; the resolution call is simply outside that block.
- `resolve_destination` is a pure passthrough with no additional wrapping that could convert or
  swallow the exception.
- Canonical-address path of `resolve_address` returns before any raise site, so canonical
  destinations never hit this defect.

## Enumeration

    $ rg -n "except RuntimeError|except \(RuntimeError" lattice/api.py
    301:        except RuntimeError as exc:
    346:        except RuntimeError as exc:
    393:        except RuntimeError as exc:          # finding 3 (this claim)
    407:        except (RuntimeError, ValueError) as exc:

    $ rg -n "resolve_destination" lattice/ tests/
    lattice/runtime.py:587:    def resolve_destination(self, address: str) -> tuple[str, str]:
    lattice/api.py:392:            _, to_node_id = runtime.resolve_destination(req.to_address)

    $ rg -n "Address resolution failed|unresolvable" tests/
    (no matches)

Instance table: one instance, `api.py:393`, disposition **finding (this claim, CONFIRMED)**. No test
covers the 400 branch.

## Fix-direction constraints

A repair must:

1. Catch `(ResolutionError, AddressError)` — or `(RuntimeError, ValueError)` — around
   `resolve_destination` and still return the `_problem(400, "Address resolution failed", …)`
   RFC 9457 body.
2. **Not** blanket-catch `ValueError` in a way that reclassifies genuine mid-operation failures
   (e.g. sqlite errors from `DomainPinRepository.get`/`upsert`) as client 400s — those should remain
   honest 500s. Catching the two specific exception classes is preferable to widening to bare
   `ValueError`.
3. Preserve the distinct 503 backpressure branch; catching too early would mask it.
4. Note the sibling defect (hunt-s1#4): the same narrow catch exists at api.py:301/346; fixing only
   `admin_submit` leaves the class open on the public messages route.

## Bound

- Upstream strictness of a *remotely deployed* peer's `/.well-known/lattice` is unverifiable here;
  the resolution-failure trigger is demonstrated with a stub transport that raises `TransportError`,
  which is the tree's own transport contract, not a live peer. The address-syntax branch (`@`-less
  `to_address`) is demonstrated without any transport at all.
- Production serving stack is `uvicorn` via cli.py; the 500 mapping was demonstrated through
  Starlette's `ServerErrorMiddleware` via `TestClient(raise_server_exceptions=False)`, which uses the
  same ASGI stack. Actual uvicorn log formatting was not exercised.
