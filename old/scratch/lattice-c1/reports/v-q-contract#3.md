# v-q-contract#3 — PRIMED VERIFIER

Claim under test: `q-contract#3` (report `scratch/lattice-c1/reports/q-contract.md`, reported tier **L**)
— "PROTOCOL §9 example error-code table: six of seven documented machine codes do not exist anywhere in the code."

Adversarial and symmetric. Frame re-derived from source before reading the claim body.

## Verdict: CONFIRMED (tier unchanged, L)

Mechanism, trigger, frequency each independently re-derived and hold. No component refuted.
One framing qualification recorded (see "Refuted / qualified halves").

---

## Frame re-derivation (done first, from source)

**What the doc actually says.** `docs/PROTOCOL.md` §9, verbatim, after the format example:

> The `code` field is stable and machine-readable. Clients SHOULD use `code`, not `title` or
> `detail`, for programmatic handling. **Example codes:**
> | Code | HTTP | Meaning |
> | `LATTICE_INVALID_SIGNATURE` | 401 | Signature verification failed. |
> | `LATTICE_UNKNOWN_NODE` | 404 | Node not pinned and resolution failed. |
> | `LATTICE_EXPIRED_CERTIFICATE` | 401 | Operational certificate expired. |
> | `LATTICE_RATE_LIMITED` | 429 | Per-peer quota exceeded. |
> | `LATTICE_MESSAGE_TOO_LARGE` | 413 | Request body exceeds limit. |
> | `LATTICE_INVALID_ADDRESS` | 400 | Address malformed or unsupported. |
> | `LATTICE_DOMAIN_BINDING_MISMATCH` | 403 | Well-known domain does not match requested host. |

7 rows. Table introduced as "**Example codes:**".

**What the code emits / what the constants hold.** `lattice/protocol/constants.py` defines exactly
nine `PROBLEM_CODE_*` literals. `lattice/api.py:_STATUS_PROBLEM_MAP` binds status→(type,code) for
400/401/411/413/429/500/503, with two inline literals in `receive_message` (503 SERVICE_UNAVAILABLE
cold-sender at api.py:315, 403 FORBIDDEN at api.py:331) and one in the `RequestValidationError`
handler (api.py:152, BAD_REQUEST). No other status→code map exists (`rg` for `_STATUS_PROBLEM_MAP` /
`PROBLEM_CODE` returns only constants.py and api.py).

**Who the caller is / what the response carries.** `_problem(status, ...)` (`lattice/api.py`) does
`problem_code = _STATUS_PROBLEM_MAP.get(status, _DEFAULT_TYPE_CODE)` and writes it into the
`code` field of the `application/problem+json` body. So the emitted `code` is a pure function of
HTTP status; the doc table and the code table are two literal sets that must agree.

## Independent enumeration (composed, closes the class)

```
doc §9:  sed -n '/^## 9/,/^## 10/p' docs/PROTOCOL.md | grep -o 'LATTICE_[A-Z_]*' | sort -u
code:    rg -o 'LATTICE_[A-Z_]+' lattice/ --no-filename | sort -u
reverse: for c in <9 code literal names>; do rg -l "$c" docs/; done
```

Output:

- doc-only (7): `INVALID_SIGNATURE, UNKNOWN_NODE, EXPIRED_CERTIFICATE, RATE_LIMITED, MESSAGE_TOO_LARGE, INVALID_ADDRESS, DOMAIN_BINDING_MISMATCH`
- code-only (9): `BAD_REQUEST, UNAUTHORIZED, FORBIDDEN, NOT_FOUND, LENGTH_REQUIRED, TOO_LARGE, RATE_LIMITED, SERVICE_UNAVAILABLE, INTERNAL_ERROR`
- intersection: `LATTICE_RATE_LIMITED` **only**.
- `rg -l` for each of the nine code literals under `docs/`: **empty** — the code's codes appear in no doc; the doc's codes appear in no code file. Symmetric drift, both directions.

So "6 of 7 doc codes are not emitted by the code" is exactly correct.

## Component-by-component adjudication

- **Mechanism** — traced. Two disjoint literal sets, compared by composed command; the signature-failure
  scenario is decisive: `receive_message` → `runtime.verify_inbound_message` raises `RuntimeError`
  → `_problem(401, "Message rejected", ...)` → map[401] = `LATTICE_UNAUTHORIZED`. Doc §9 says that
  scenario is `LATTICE_INVALID_SIGNATURE`. Disagreement on the exact scenario the doc names. Not
  refuted.
- **Trigger** — PRODUCTION. Any 4xx/5xx problem-detail response emitted by the three public routes
  (and admin routes) triggers it. A spec-conforming client branching per §9 on the named codes
  never matches. Not refuted.
- **Frequency** — the divergence is static (present at every response, from process start) and the
  response population is continuous. The per-code mismatch cadence is scenario-bound (e.g. 401 for
  signature/structural failures, 413 for oversize bodies), but the defect — doc contract lists codes
  the server never emits — is continuously present. DEMONSTRATED. Not refuted.
- **Severity** — L holds and I leave it unchanged. The scale explicitly lists "a misreported error
  code" as L; this is a bounded interop/error-handling fault. It does **not** meet M: no wrong
  state, custody, queue, or quota decision is produced; the drift is confined to the documented
  machine-code vocabulary. It does not rise to H (no auth bypass, no cross-peer reach). L is the
  correct tier.

## Refuted / qualified halves

- **No component refuted.** Mechanism, trigger, frequency, tier all stand under independent trace.
- **Qualification (not a refutation):** the doc introduces the table as "**Example codes:**", not as a
  closed normative enumeration. This softens the claim's strongest phrasing — "the documented machine
  contract is unusable as written" — toward "the doc's code table is misleading and contradicts the
  implementation on named scenarios." The defect survives the softening: the doc states the code
  field is "stable and machine-readable" and that clients SHOULD branch on it, then maps signature
  failure to a code the server never returns for signature failure. Direction is correctly stated as
  "either side must move"; from source, the code side is internally self-consistent (constants +
  map), so the drifted side is the doc.

## Additional mechanisms / earlier failure sites on the same trace

1. **Reverse-direction drift and undocumented statuses.** Eight of the nine emitted codes appear in
   no doc at all (`docs/` reverse grep: empty). Two emitted statuses are entirely absent from §9's
   table: **411 `LATTICE_LENGTH_REQUIRED`** (raised by `require_content_length` when `Content-Length`
   is missing — api.py:75-78) and **503 `LATTICE_SERVICE_UNAVAILABLE`** (cold-sender branch). A
   client written to §9 has no documented code for either. This widens the defect beyond the 6/7
   count: the doc table is neither a superset nor a subset of the emitted set.
2. **404 is emitted nowhere.** The doc's `LATTICE_UNKNOWN_NODE` (404) is doubly divergent: no 404
   response path exists in `lattice/api.py` (`rg '404' lattice/` → only the `title_map` label and the
   unused `PROBLEM_CODE_NOT_FOUND` constant); the "node not pinned" scenario instead returns 503
   (cold-sender). So the doc names a status+code pair the server cannot produce.
3. **No binding test.** `rg 'LATTICE_|problem\+json' tests/` returns nothing — no test asserts the
   emitted code vocabulary, so the drift recurs silently on every edit of either side (this is the
   concrete instantiability of q-contract's design risk #1).

## Fix-direction constraints

- A repair must first declare one side canonical. Because code is self-consistent and the doc is the
  outlier on every named scenario, the doc-side edit is the likely fix — but a doc-only edit that
  simply pastes the nine emitted codes still leaves 411/503 semantics unstated and the
  "SHOULD use code" obligation without a closed vocabulary.
- A code-only edit (rename constants to the doc's codes) would break the internal status→code
  symmetry for 411/503 (no doc codes exist) and for 403/404 (doc codes name different scenarios).
- Either way a conformance/snapshot test binding `PROBLEM_CODE_*` and `_STATUS_PROBLEM_MAP` to the
  doc table is required to close the class; without it the drift re-accumulates (added mechanism 3).

## Checked and clean

- All nine `PROBLEM_CODE_*` constants and their `PROBLEM_TYPE_*` type URIs are internally consistent
  with `_PROBLEM_BASE = https://lattice.dev/errors` and the §9 format example (`type` URI shape,
  `code` field). The drift is in the *vocabulary*, not the *envelope* — this confirms q-contract's
  own distinction against hunt-e2's "format matches" clean claim.
- `_STATUS_PROBLEM_MAP` covers every status api.py raises via `HTTPException`/`_problem`
  (400/401/411/413/429/500/503); no status falls through to `_DEFAULT_TYPE_CODE` in practice on the
  public routes.
- RATE_LIMITED genuinely overlaps and is emitted (429) as the doc specifies.

## Bound

- Authorial intent of "**Example codes:**" (illustrative vs closed normative set) is not resolvable
  from the tree; recorded as a qualification, not a verdict change.
- No live request was executed in this pass — the signature-failure mapping was traced statically
  through `verify_inbound_message` → `RuntimeError` → `_problem(401)`; q-contract's empirical run is
  consistent with that trace but was not independently re-run.
- Third-party client behavior (whether any real client hard-codes the §9 codes) is unverifiable
  from this repo; the finding rests on the spec server contract, not on an observed client break.
