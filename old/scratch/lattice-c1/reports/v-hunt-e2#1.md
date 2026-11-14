# v-hunt-e2#1 — PRIMED VERIFIER

Claim under test: **hunt-e2#1** in `scratch/lattice-c1/reports/hunt-e2.md`, reported tier **L**.
Title: "Public routes bypass PROTOCOL.md §4.1 strict JSON parsing rules".

Verdict: **ADJUSTED** — core mechanism confirmed; two sub-claim halves narrowed/refuted; tier
unchanged at **L**; frequency characterization sharpened.

Reachability kind: **PRODUCTION** (public federation routes; any remote peer).

---

## Re-derived frame (before reading the claim's conclusion)

- `lattice/canonical.py:strict_json_loads` rejects duplicate keys (`object_pairs_hook=_reject_duplicate_keys`),
  NaN/Infinity (`_reject_non_finite`), enforces UTF-8 (`data.decode("utf-8")`), and delegates the
  I-JSON integer domain to model construction. `rg -n strict_json_loads` → non-test callers: **exactly
  one**, `lattice/resolution.py:62` (the outbound well-known fetch). Confirmed.
- `lattice/api.py` defines the two public POST routes via `FastAPI` body parameters
  (`body: dict[str, Any]` / `message: dict[str, Any]`); no custom body middleware exists in `api.py`.
  Starlette `Request.json` is `json.loads(await self.body())` — bytes passed directly, so CPython's
  `detect_encoding` auto-detects UTF-16/UTF-32.
- FastAPI 0.111.0 / Starlette 0.37.2 (repo venv; `uv.lock`). `fastapi.routing.get_request_handler`
  calls `request.json()` **only** when the Content-Type maintype is `application` and the subtype is
  `json` or ends with `+json` (source lines 61–75); any other/no Content-Type passes raw bytes and
  fails `dict` validation → 422→400. All body-parse exceptions (not just `JSONDecodeError`) are caught
  and re-raised as 400 "There was an error parsing the body" (lines 94–98).
- `docs/PROTOCOL.md` §4.1 (lines 71–79): "Before canonicalization or validation, a JSON payload MUST
  be parsed with these restrictions" — duplicate keys, I-JSON range, NaN/Infinity, UTF-8. The route
  bodies are JSON payloads, so the mandate applies to them.
- Signature verification (`identity.verify_object`, `verify_with_root`) canonicalizes the **parsed
  dict**; `runtime.verify_inbound_message` passes the raw `message` dict, `verify_gossip_sender_card`
  passes the raw `card`, `gossip.receive_batch` stores `json.dumps(card, ...)` of the same dict.

## Verdict components

| # | sub-claim | verdict | trace |
|---|---|---|---|
| a | strict_json_loads wired to one site only (resolution.py:62) | CONFIRMED | `rg -n strict_json_loads` — sole non-test caller |
| b | duplicate keys last-wins on route bodies | CONFIRMED | live: FastAPI mirror route, `{"cards":[],"cards":[{"a":1}]}` → 200, `{'cards':[{'a':1}]}` |
| c | NaN literal accepted by the route parser | CONFIRMED | live: `{"content": NaN}` → 200, `{'content': nan}` |
| d | UTF-16 bytes accepted (UTF-8 not enforced) | CONFIRMED | live: UTF-16-BOM body → 200, `{'a':1}` |
| e | NaN then reaches canonicalize and is **misreported 401** | PARTLY REFUTED as stated | see below |
| f | no in-tree signature/validation split (harm bounded) | CONFIRMED | message + gossip both verify the raw parsed dict; no re-sign/relay of received objects |

### Refuted / narrowed halves of e

1. **"body containing a bare NaN literal"** is not reachable. The route parameter is
   `dict[str, Any]`; a top-level `NaN` body is rejected by pydantic → `RequestValidationError` → 400,
   never reaching `canonicalize`. NaN must sit **inside** the object, and only in a
   schema-permitted free position. In `Message` the only such position is `Extension.data: Any`
   (`Message.model_validate` accepts `extension.data={"v": nan}` — verified live, repo model);
   `PeerCard` has no `Any` field, so the gossip route's `verify_gossip_sender_card` catches all
   exceptions → `None`, and `receive_batch`'s `PeerCard.model_validate` rejects. The misreport is
   therefore **message-route-specific**, not route-general as phrased.
2. **The 401 requires an already-known sender.** `runtime.verify_inbound_message` returns
   `(domain, True)` (cold sender → caller emits 503 Retry-After) *before* any canonicalization; only
   when a pinned certificate exists does `verify_message` run, raise `FloatDomainError` (subclass of
   `ValueError`, confirmed live), get caught by `except (IdentityError, ValueError)` and re-raised as
   `RuntimeError("message signature invalid: …")`, which `api.receive_message` maps to **401**. So
   the "parse error reported as signature failure" needs an established-peer precondition the finding
   omits.

## Severity

**Unchanged: L.** The finding's own "harm bounded" conclusion survives every refutation attempt
(refutation direction checked, not confirmed): no auth bypass is reachable because the signature
preimage is `canonicalize(parsed_dict minus signature)` on both the wire-parse and verify sides, so a
duplicate key cannot flip a signed value without the signer having signed the flipped value; the node
never re-signs or relays a received object (`gossip.add_transient_card` stores
`json.dumps(card)`, no re-sign; invariant-6 no-relay). No wrong custody/ack: the accepted body is the
same parsed dict that is signature-verified and then persisted. Residual harm = conformance
divergence, acceptance of forbidden input at the boundary, and one misreported error code (both
enumerated as L in the pinned scale). Not M (no wrong state / wrong custody / two in-tree paths that
must agree); not S- (mechanism demonstrated live, not single-pass).

## Frequency

**Correction (characterization, not tier).** The claim's label "DEMONSTRATED — population is every
remote request" conflates mechanism-demonstration with trigger cadence. Grounded frequency: the
trigger is **attacker/non-conforming-initiated** — no in-tree caller emits duplicate keys, NaN, or
UTF-16 (repo signers emit `strftime("%Y-%m-%dT%H:%M:%SZ")` compact JSON). So the cadence is "when a
hostile or non-conforming peer POSTs to `/lattice/v1/messages`|`/gossip` with a `+json`-suffixed
Content-Type"; it is not per-request. The finding's own prose already says this; the frequency line
alone overstates the population. Under the calibration rule this remains grounded
(hostile external peer is in the threat model) rather than latent.

## Additional mechanisms / earlier failure sites (same trace)

- **Parse gate is subtype-based** (`fastapi…get_request_handler` 61–75): the bypass only opens when
  the Content-Type maintype is `application` and subtype ends in `+json`. This is an *earlier*
  condition than the finding states and it is also why `; version=2` is ignored (feeds hunt-e2#2).
- **Second instance of the same missing check — I-JSON integers.** `Extension.data: Any` accepts
  integers ≥ 2^53; `rfc8785` raises `IntegerDomainError` (subclass `CanonicalizationError` → `ValueError`)
  mid-canonicalization. Same 401-on-known-sender path as NaN. The finding notes this but does not
  name it as a second reachable instance.
- **Verified-clean refutation of a plausible new mechanism.** Deeply nested JSON (`"["*1500+"]"*1500`,
  ~3 KB, well under `MAX_MESSAGE_BODY_BYTES=128 KiB`) raises `RecursionError`, but FastAPI's
  `except Exception` body-parse guard converts it to **400** (live, repo venv) — no 500 and no
  crash. Not a finding.

## Checked and clean

- `strict_json_loads` is correct and its behaviour intact (dup keys / NaN / Infinity / non-UTF-8 all
  rejected live); the defect is that the public routes never call it, exactly as §4.1 requires the
  *payload* parse to.
- No in-tree signature/validation split: `verify_inbound_message`, `verify_gossip_sender_card`,
  `gossip.receive_batch` all operate on the same parsed dict that was validated; no received object
  is re-signed or relayed. Confirms the finding's bounded-harm reasoning.
- Deep-nesting body parse is bounded to 400 (see above).
- `require_content_length` blocks absent Content-Length (411) and Content-Length > max (413), so the
  strict-parse gap cannot be combined with an unbounded-body read via chunked encoding.

## Fix-direction constraints

- A repair cannot be a body-parameter change: Starlette parses before the endpoint runs. It must read
  `await request.body()` and parse via `strict_json_loads`, or install a custom body dependency —
  while (a) preserving the `+json` gating so conforming clients keep working, (b) enforcing
  Content-Length/body-size **before** the strict read, and (c) **separating** parse/strictness
  failures from signature failures: today both surface as 401 "message signature invalid" and the
  distinct `LATTICE_*` codes exist in `docs/PROTOCOL.md` §9.
- `strict_json_loads` returns plain values; the model-validation + raw-dict-verify split must be kept
  (it is load-bearing for `Message.extension.data: Any`).

## Bound

- No live daemon or `RuntimeCoordinator` exercised; parse/gate behaviour verified against a FastAPI
  app in the repo venv (0.111.0 / starlette 0.37.2) mirroring `create_app`'s route signatures, plus
  the repo's own `Message` model. The 401-vs-503 precondition is **traced**, not live-demonstrated.
- Upstream strictness of other Lattice implementations is unverifiable here; a future FastAPI
  release could change the `except Exception → 400` body-parse guard, which the deep-nesting
  refutation depends on.
- Did not run the wire path against a real pinned peer; the "known-sender" precondition for the 401
  is read from `runtime.verify_inbound_message` control flow.
