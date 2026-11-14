# v-q-contract#5 — PRIMED VERIFIER

Claim under test: `q-contract#5` in `scratch/lattice-c1/reports/q-contract.md`, reported tier **L** —
"PROTOCOL §5.3 documents only a 202-with-signed-receipt response; the implemented cold-sender 503 is
absent from the normative spec."

Adversarial and symmetric. Frame re-derived from source before reading the claim body.

## Verdict: ADJUSTED (mechanism and trigger CONFIRMED; two framing sub-claims qualified/refuted;
tier held at **L**; frequency corrected to reachability-confirmed / cadence-latent)

Reachability kind: **PRODUCTION** (the public messages route; any peer, and — see added mechanism —
any unauthenticated client).

---

## Frame re-derived from source

- **Contract text.** `docs/PROTOCOL.md` §5.3 (line 179) reads, in full for the response:
  "Response is a signed `receipt` object (§8) with HTTP status `202 Accepted`." It then specifies
  the duplicate-`message_id` MUST. `grep -n "503\|cold\|Retry" docs/PROTOCOL.md` → **no hits**
  (only the §5.3 heading). §5.2, by contrast, carries the sentence "Errors use the standard Problem
  Details format (§9)."; §5.3 does not. §9 (normative, global): "All protocol errors use RFC 9457
  Problem Details with `Content-Type: application/problem+json`" and introduces its code table as
  "**Example codes:**" — non-exhaustive, and it does **not** list `LATTICE_SERVICE_UNAVAILABLE`.
- **Code.** `lattice/api.py:receive_message` (line 287). After `verify_inbound_message` returns
  `(from_node_id, cold_sender)`:
  - `if cold_sender:` → `runtime.queue_domain_resolution(...)` then `JSONResponse(status_code=503,
    content={... "code": PROBLEM_CODE_SERVICE_UNAVAILABLE}, media_type=PROBLEM_MEDIA_TYPE,
    headers={"Retry-After": "60"})` (api.py:303–318).
  - The 202-with-receipt success return is at api.py:355.
- **What `cold_sender` is.** `lattice/runtime.py:verify_inbound_message` (line 619):
  `parsed = parse_address(model.from_address)`; if `parsed.node_id is not None` use it; elif
  `parsed.domain is not None` look up `self._resolver.get_pin(parsed.domain)`; if there is **no pin**
  it returns `(parsed.domain, True)` (line 647) — *before* any certificate lookup, *before*
  signature verification, and before the block check. `Message.model_validate` is the only guard.
- **Where the 503 sits relative to other gates.** In `receive_message` the cold-sender return is at
  line 303–318; the rate limiter `runtime.rate_limiter.allow_message(from_node_id)` runs at line 335
  and `runtime.inbound_service.accept` at line 339. So the 503 is emitted **before** rate limiting
  and **without** a verified signature.
- **Sibling doc.** `docs/LOOSE_ENDS.md:27` and `:73` record the cold-sender-503/Retry-After behavior
  as a completed design decision (work log, non-normative).

## Per-component adjudication

| Component | Disposition | Trace |
|---|---|---|
| Mechanism: §5.3 specifies only 202; code emits 503 for cold senders | **CONFIRMED** | §5.3 text vs `api.py:303–318` |
| Trigger: any cold-sender message POST | **CONFIRMED** | `runtime.py:647` returns `(domain, True)` when no pin; route reaches line 303 |
| Reachability: production | **CONFIRMED** | public route; no auth needed to reach the 503 (rate limit is later) |
| Frequency: "DEMONSTRATED / common with any new peer" | **CORRECTED** | population is concrete (cold-sender messages) but the cadence depends on peer retry behaviour and cannot be grounded from the tree — reachability-confirmed, **cadence-latent** |
| "503 is absent from the normative spec" | **PARTLY REFUTED** | see below |
| "the retry-with-Retry-After flow the implementation depends on" | **REFUTED** as stated | see below |

### Refuted / qualified halves (named individually)

1. **"the implemented cold-sender 503 is absent from the normative spec" — overstated.**
   The *response format* is not absent: §9 normatively mandates that all protocol errors use
   RFC 9457 Problem Details, and the 503 response is exactly that (`PROBLEM_MEDIA_TYPE`,
   `type`/`title`/`status`/`detail`/`code`). §5.3 is a *success*-response description; protocol
   specs routinely describe success in the route section and defer error responses to a global
   error section (§9), which this doc has and §5.2 explicitly cites. What is genuinely absent is
   (a) the cold-sender trigger/behaviour and (b) the retry semantics — **not** the response itself.
   The claim's title sentence ("documents only a 202…response") is accurate; the "absent from the
   normative spec" gloss overstates the gap by treating §5.3 as the exhaustive response set.

2. **"the retry-with-Retry-After flow the implementation depends on" — refuted.**
   The in-tree sender depends on the 503 **status**, not on the `Retry-After` header.
   `runtime.py:1004` `elif response.status == 429 or response.status >= 500:` →
   `record_failure(retryable=True)`; the retry instant is computed by
   `RetryPolicy.next_attempt_at` (`messages.py:48`, exponential backoff + jitter) from the local
   attempt count. Nothing in `lattice/` reads `Retry-After` (`rg -n "Retry-After|retry_after"`
   → only `api.py:318`, the emitter). The header is advisory and unused in-tree. So the flow the
   implementation depends on is "sender retries any 5xx (or 429)", which every generic HTTP client
   already does; the Retry-After value is not load-bearing. This weakens the "unspecified server
   error" interop-harm framing: a conforming client that sees a `application/problem+json` 503
   already has §9 and standard-HTTP guidance, even without the cold-sender prose.

## Severity correction

Held at **L**; no change. Trace: the divergence is real and production-reachable, but the bad
outcome is bounded — the response is §9-conformant and standard-HTTP-describable, and the in-tree
sender already retries it correctly. This is the scale's L ("a real defect with a narrow trigger or
bounded bad outcome … a misreported error code"), not M (no wrong state, no custody/ack divergence —
the cold sender gets no receipt and retains custody, which is correct) and not H. It is also above
S-: the mechanism is a two-sided literal/behaviour comparison against source, reproduced in the
frame above, not a single-pass impression.

## Frequency correction

Claim said "DEMONSTRATED — one 503 per cold-sender message; common with any new peer." Corrected to
**reachability-confirmed, cadence-latent**. The operation population is concrete and produced by the
tree (`verify_inbound_message` line 647 returns the cold flag for any message whose `from_address`
domain has no pin), but the *rate* — how often a peer sends before its card is pinned — is a remote
behaviour the tree does not emit or bound (no in-tree sender/introducer produces an un-pinned-domain
message on purpose; `admin_submit` → `resolve_destination` pins before signing). Per the calibration
rule ("a frequency you cannot ground is LATENT by definition"), the cadence is latent. Tier is
unchanged because reachability is genuinely production and the bound is what holds it at L.

## Added mechanisms / earlier failure site on the same trace (side, already reported elsewhere)

- **The 503 is emitted before signature verification and before the rate limiter.** `api.py:303–318`
  precedes both `allow_message` (line 335) and any cert/`verify_message` (all in
  `verify_inbound_message` after the cold return at `runtime.py:647`). The cold-sender determination
  is therefore driven by the **unverified** `from_address` of the request body. An unauthenticated
  client can elicit a 503 and enqueue a domain resolution per request. This is the same trace as
  `q-error#1` (unbounded `_unresolved_domains`, re-fetch forever) and `seam-s2`; it is **not**
  re-reported here — recorded as a cross-reference, not a new finding.
- **§5.3's duplicate-receipt MUST is vacuous in the cold-sender branch:** a cold sender never
  reaches `inbound_service.accept`, so no receipt is persisted for it. Correct (no custody taken),
  but it means the §5.3 "response is a receipt" sentence has an unstated second mode.

## Fix-direction constraints

A repair that updates `docs/PROTOCOL.md` §5.3 to document the cold-sender 503 must also account for:

1. **Code-table coupling (finding q-contract#3).** The 503 uses `LATTICE_SERVICE_UNAVAILABLE`, which
   is absent from §9's (example) code table. A §5.3 prose fix that does not also reconcile the §9
   code table leaves the two-sided literal divergence reported in q-contract#3 in place.
2. **Verification ordering (q-error#1).** Documenting the 503 as-is blesses answering an
   *unauthenticated* request with a state-changing side effect (`queue_domain_resolution`). If the
   intended contract is "only a signature-verified peer can trigger the cold-sender retry flow",
   the fix is in code (verify before returning 503), not prose; a prose-only fix ships the ordering
   defect underneath.
3. **Do not claim Retry-After is load-bearing.** Any spec text or client guidance that says the
   sender relies on the `Retry-After` value is false for the in-tree implementation (backoff is
   local); state the status as retryable and the header as advisory.

## Bound

- No live third-party interop client exists in the tree to demonstrate the interop harm; the
  "spec-conforming client" consequence is reasoned from the spec text, not observed.
- `docs/LOOSE_ENDS.md` read as intent context only; it is not normative and its status as the sole
  record of the behaviour is the crux of the (qualified) gap.
- No live nginx/systemd execution (macOS host); deploy files not re-diffed for this claim (not on
  this trace).

---

## Checked and clean

- §5.3 text read end-to-end; the only response sentence is the 202 one, and no cold-sender/503/
  Retry-After mention exists anywhere in `docs/PROTOCOL.md` — the *fact* of the omission is verified.
- `api.py:receive_message` read in full (lines 279–356): cold-sender branch, blocked-sender 202,
  recipient-ownership 403, rate limit 429, custody 202, and both `except` paths all present and in
  the order stated.
- `runtime.py:verify_inbound_message` (619–662) read in full; the cold return at line 647 is before
  cert lookup, signature verify, and block check — confirmed.
- `runtime.py:_send_outbound_message` (949–1018) read in full; `>= 500` retry branch at line 1004,
  and no `Retry-After` read anywhere in `lattice/`.
- `messages.py:record_failure` / `RetryPolicy.next_attempt_at` read; backoff is local attempt-count
  based, confirming the retry does not depend on the response header.
