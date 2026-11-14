# v-hunt-e2#2 — PRIMED VERIFIER of hunt-e2 finding #2

Claim under test: hunt-e2.md finding 2, "[L] No media-type/version enforcement on public routes
(§11 MUST)". Reported tier L.

Verdict: **CONFIRMED** at **L** (severity unchanged). Frequency sub-claim corrected from
"DEMONSTRATED" to latent/ungrounded. Reachability kind: **production** (route is externally
reachable; header is peer-controlled) but the triggering header is not produced by any in-tree
actor.

## Frame re-derived from source (not from the claim)

- Contract: `docs/PROTOCOL.md` §11 (lines 292–298): "The media type carries the major version:
  `application/vnd.lattice+json; version=1`" and "Implementations MUST reject requests with an
  unsupported or missing `version` parameter in the `Content-Type` or `Accept` header, as
  applicable."
- Route code: `lattice/api.py:create_app`. The two public POST routes declare a raw
  `dict[str, Any]` body parameter (`receive_gossip`, `receive_message`). Neither reads
  `Content-Type` or `Accept`. The only request-header gate is `require_content_length(max_bytes)`
  (content-length only), plus `require_admin` on admin routes. There is **no**
  `add_middleware`/`BaseHTTPMiddleware` anywhere in `lattice/`; `create_app` is invoked directly by
  `uvicorn.run(app, …)` in `lattice/cli.py:717`.
- Edge: `deploy/lattice.nginx.conf` proxies `/lattice/v1/gossip` and `/lattice/v1/messages`
  verbatim (`proxy_pass`) and performs **no** Content-Type/Accept inspection. So nothing upstream
  supplies the missing check or masks it (invariant-7 edge limits do not cover media-type
  negotiation).
- Body parsing is FastAPI/Starlette's, which JSON-decodes only for a `json`-ish Content-Type. I
  reproduced this against the **real** `create_app` (constructed runtime via `tests.conftest._make_node`,
  repo `.venv`: fastapi 0.141.1 / starlette 1.3.1):

```
POST /lattice/v1/gossip  Content-Type: application/vnd.lattice+json; version=1   -> 200 {"accepted":0,...}
POST /lattice/v1/gossip  Content-Type: application/vnd.lattice+json; version=2   -> 200 {"accepted":0,...}
POST /lattice/v1/gossip  Content-Type: application/vnd.lattice+json             -> 200   (no version param)
POST /lattice/v1/gossip  Content-Type: application/vnd.lattice+json; version=99  -> 200
POST /lattice/v1/gossip  Content-Type: application/json; version=2               -> 200
POST /lattice/v1/gossip  Content-Type: (empty/absent)                            -> 400 Validation Error
POST /lattice/v1/messages Content-Type: application/vnd.lattice+json; version=2  -> processed identically to version=1
```

## Sub-claim adjudication

- **"No Content-Type inspection anywhere in create_app"** — CONFIRMED. `grep -n 'Content-Type\|content_type' lattice/api.py` returns nothing.
- **Mechanism (unsupported version accepted)** — CONFIRMED. `version=2` and `version=99` return
  200/processed; the version parameter is never read.
- **Trigger (remote peer POSTs a non-conforming media type)** — CONFIRMED, production: an
  arbitrary HTTP client reaching the route sets its own `Content-Type`. Any federated peer is an
  outsider. Not tests-only, not gated.
- **"A missing Content-Type yields a generic FastAPI 422→400, not the protocol's version-mismatch
  rejection"** — accurate but *weak*: absent/empty Content-Type is actually **rejected** (400 via
  the `RequestValidationError` handler). So the "missing version" MUST is genuinely violated not by
  an absent header but by a **present** header lacking `version=` (`application/vnd.lattice+json`),
  which is **accepted with 200**. That instance is stricter evidence than the claim's example and
  is added below.
- **Frequency: "DEMONSTRATED"** — REFUTED as a demonstrated frequency. The reasoning "population is
  any remote request with a non-conforming media type" is a population of *possible* senders, not a
  cadence produced by the tree: every in-tree producer sends `MEDIA_TYPE` (`runtime.py:960`,
  `runtime.py:1109`, `resolution.py` fetch, tests). No in-tree actor emits a wrong/absent version,
  and no v2 peer exists. Per the calibration rule an ungroundable frequency is latent by definition,
  capped at L. Tier therefore stays L (unchanged); only the frequency label is corrected.
- **Outcome ("bounded to acceptance/misreported code/divergence, no wrong custody")** — CONFIRMED.
  Signature preimage hardcodes `lattice-signature-v1` and models pin kinds, so a genuinely v2 signed
  object fails verification (401); no wrong-custody path found. L is correct; not M.

## Additional mechanisms / earlier failure sites / new reachability (same trace)

1. **Present-but-versionless Content-Type is accepted** (`application/vnd.lattice+json`, no
   `version=`) → 200. This is the literal "missing version parameter" case of §11 and is the
   strongest instance; the claim's chosen example (absent header) is actually rejected 400.
2. **`Accept` header never inspected.** §11 covers "the `Content-Type` **or** `Accept` header, as
   applicable"; a client sending `Accept: application/vnd.lattice+json; version=2` receives a
   version=1 body with no negotiation and no rejection. Second half of the same MUST, unhandled.
3. **Wholesale media-type non-check.** Any `*json*`/`+json` type (`application/json; version=2`)
   is processed. Enforcement is delegated implicitly to FastAPI's content-type sniffing to decide
   *whether* to JSON-decode, which is not a version check and is inconsistent across types
   (`text/plain` body ⇒ 400, `application/json` body ⇒ processed).
4. **Divergent outbound policy (pre-existing, cross-reference only).** `lattice/resolution.py:58`
   gates inbound-to-us documents by substring `"application/vnd.lattice+json" in content_type` and
   likewise ignores `version`. This is already recorded as hunt-e2 side discovery 4 / q-contract.md;
   noted here only because a repair must touch both directions for consistency — not re-reported.

## Fix-direction constraints

- The check belongs at the route edge **before** model validation and signature verification (a
  route dependency, or explicit header read in `receive_gossip`/`receive_message`); a fix that only
  changes response codes leaves the body consumed.
- There is no existing problem code/type for a version/media-type mismatch in
  `lattice/protocol/constants.py`; a repair must either add one or reuse `LATTICE_BAD_REQUEST`, and
  must emit RFC 9457 Problem Details like the other rejections.
- Matching must be on media type **plus** the `version` parameter (not a substring), and applied to
  **both** `Content-Type` and `Accept`. A strict `== "application/vnd.lattice+json; version=1"` on
  Content-Type would pass every in-tree sender (`runtime.py:1109` sends exactly `MEDIA_TYPE`), but
  the same strictness must then be reconciled with `resolution.py:58`'s substring test or the two
  directions diverge.
- Rejecting unsupported versions is **not** the same as rejecting non-conforming payloads (§4.1
  strict-parse gap is hunt-e2 finding 1, separate); fixing §11 does not close finding 1 and vice
  versa.

## Checked and clean (coverage of this claim)

- `require_content_length` correctly enforces presence and size of `Content-Length`; not a
  media-type gate and not claimed to be.
- In-tree senders all emit conforming `MEDIA_TYPE` on `Content-Type`/`Accept` (`runtime.py:960`,
  `runtime.py:1109`; `tests/conftest.py:89`, `tests/test_resolution.py`), so a strict inbound check
  would not break the repo's own mesh.
- Nginx edge config read end-to-end: it performs no media-type/version enforcement, and its
  `client_max_body_size` values (256k/128k) match the protocol limits, so body-size enforcement is
  at the edge as intended and is not the missing gate.
- `create_app` is the whole ASGI app (no wrapping middleware in `lattice/`), so the gap cannot be
  attributed to a middleware layer outside the read file.

## Enumeration

```
grep -rn "Content-Type\|content_type\|content-type\|version" lattice/api.py
  -> only api.py:130 version="1" (FastAPI title version) ; no Content-Type read
grep -rn "add_middleware\|BaseHTTPMiddleware\|Middleware" lattice/*.py
  -> no hits
grep -n "MUST reject requests with an unsupported or missing" docs/PROTOCOL.md
  -> 295
```

Instance table:

| site | reads Content-Type? | reads Accept? | enforces version? | disposition |
|---|---|---|---|---|
| `receive_gossip` (api.py:244) | no | no | no | **finding (claim 2)** |
| `receive_message` (api.py:288) | no | no | no | **finding (claim 2)** |
| `well_known` GET (api.py:220) | n/a (response only) | no | no | examined-clean (response media type set to MEDIA_TYPE) |
| `resolution.resolve_with_ip` (resolution.py:58) | substring only | no | no | known side discovery, cross-ref only |
| `runtime` outbound (runtime.py:960, 1109) | sends | sends | n/a | conforming producer |
| nginx `lattice.nginx.conf` | no | no | no | no edge enforcement |

## Bound

- No live daemon or real network was exercised. Behavior was reproduced with `TestClient` against
  the **real** `create_app` and a constructed `RuntimeCoordinator`; starlette/fastapi versions are
  the pinned venv's. Provider/proxy behavior beyond the inspected nginx block (e.g. a CDN in front)
  is unreachable.
- Whether any real federated peer in a live deployment emits a missing/mismatched `version` is a
  deployment fact I cannot reach — this is exactly why the frequency is stated as latent. The
  route-level acceptance itself is fully demonstrated.
- `Accept`-negotiation semantics are unverified against any external implementation; the finding
  rests on the header never being read, demonstrated by grep, not on a spec-interop test.
