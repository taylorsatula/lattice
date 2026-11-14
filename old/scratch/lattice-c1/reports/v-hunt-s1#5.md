# v-hunt-s1#5 — PRIMED VERIFIER

Claim under test: `hunt-s1#5` in `scratch/lattice-c1/reports/seam-s1.md` — "[L] Cold-sender requests
bypass message rate limiting entirely (no IP fallback, unlike gossip)". Reported tier L.

Pass type: PRIMED VERIFIER. Adversarial and symmetric. Frame re-derived from source before reading
the claim's verdict; each of mechanism / trigger / frequency checked separately.

## Findings

1. [M] — The message rate limiter never throttles any unauthenticated or rejected request; only a
   fully signature-verified, correctly-addressed message consumes a token
- Location: lattice/api.py:receive_message, the branch order between
  `runtime.verify_inbound_message` (l. 296) and `runtime.rate_limiter.allow_message` (l. 335);
  contrast lattice/api.py:receive_gossip l. 264 (`peer_id = sender_node_id or _peer_ip(request)`).
- Evidence: the handler's early returns all precede the only `allow_message` call —
  `if cold_sender: ... return 503` (l. 309–322), the own-domain guard `if to_domain and
  runtime._own_domains and to_domain not in runtime._own_domains: return 403` (l. 323–334), and the
  `except RuntimeError as exc: return _problem(401, ...)` (l. 306). `allow_message` sits at l. 335,
  after all three. `allow_message` is keyed solely on `from_node_id`; the messages route never calls
  `_peer_ip` (l. 110, referenced only from gossip at l. 264).
- Trigger: PRODUCTION. Any network peer POSTs a body to `POST /lattice/v1/messages` that either
  (a) has a `from_address` whose domain has no pin — `verify_inbound_message` returns
  `(parsed.domain, True)` at runtime.py:641 *before* signature verification, and the handler queues
  and returns 503 without a token; or (b) fails signature/certificate verification — raised as
  `RuntimeError` and converted to 401, also before l. 335. Body size is capped at
  `MAX_MESSAGE_BODY_BYTES` = 128 KiB by `require_content_length` (l. 18 constants), so work per
  request is bounded but unthrottled in aggregate. `require_ready` and the content-length dependency
  are the only other gates; neither is a rate control.
- Frequency: DEMONSTRATED — the mechanism fires on 100% of requests that terminate in the cold-503,
  own-domain-403, or 401 branches. The cold branch is exercised in normal operation
  (tests/test_integration.py:36 `test_cold_sender_returns_503` drives the real handler to 503). No
  test exercises any 429 on the messages route: `rg -n "429" tests/test_api.py` yields only the
  three gossip assertions (l. 180, 201, 216), and the messages fixture config sets
  `messages_per_minute: 2` (tests/test_api.py:58) with no matching assertion. Population: every
  unauthenticated request (invalid-signature 401 and cold 503) plus every foreign-destination 403.
- Outcome: the per-minute message quota is applied only to the population that already passed
  signature verification — precisely the legitimate peers — while the unauthenticated population is
  unlimited. This diverges from `receive_gossip`, which the same file documents as falling back to
  client IP for unauthenticated traffic ("Unauthenticated traffic falls back to the client IP",
  l. 258–263), and from the deployment's stated abuse-control design. Wrong rate/quota decision at a
  public trust boundary.
- Reachability kind: PRODUCTION.
- Confidence: traced — mechanism (branch order read end to end at api.py:289–338), trigger (cold
  return at runtime.py:641 precedes signature verification; 401 conversion at api.py:306 precedes
  l. 335), frequency (100% of early returns; integration test drives the cold branch). Severity
  judgment M-vs-L is the only soft component; see correction below.

## Severity correction — L → M

The hunter's L rests on "per-request cost is bounded". The defect is the *absence of aggregate
bounding on the unauthenticated path*, which is the exact purpose of the quota. The pinned scale
lists "a wrong rate/quota decision" and "divergence between two paths that must agree" under M, and
this site is both. Traced grounding for the correction:

- The shipped edge config contains no compensating rate control: `rg -n "limit_req|limit_conn|zone"
  deploy/` returns no matches; `deploy/lattice.nginx.conf` sets only body/connection/read deadlines.
  docs/LOOSE_ENDS.md:78 states this explicitly: "The Nginx configuration does not include
  rate-limiting zones or fail2ban integration; it relies on Lattice's authenticated per-peer quotas
  for abuse control." So the Python quota is the only abuse control in the documented deployment,
  and it is bypassed for all unauthenticated requests.
- docs/ARCHITECTURE.md:80 claims nginx "owns ... IP rate limits", which contradicts the shipped
  config and LOOSE_ENDS:78. The contradiction is recorded as a deployment-dependent bound below; on
  the artifact in the tree (none, per the rg above) the bypass is unmitigated.
- It is not H: no single request exhausts a resource and the endpoint does not accumulate attacker
  state on its own (the unbounded `_unresolved_domains` growth is `hunt-s1#2`, a separate
  mechanism), so the remote-crash / unbounded-exhaustion rung is not reached by this finding alone.

Frequency correction: none — the hunter's frequency is correct and I only widened the triggering
population from "cold-sender requests" to "all pre-verification early returns (401/403/503)". The
cadence and grounding are unchanged.

## Refuted sub-claims

None. Each component was re-derived and holds:
- Mechanism (l. 335 sits after the cold/403/401 returns; no `_peer_ip` call on this route) — verified.
- Trigger (unpinned from-domain reaches the handler and returns 503 before verification) — verified
  at runtime.py:619–643, api.py:309–322.
- Frequency (fires on every such request; cold branch reachable in normal operation) — verified.
The only correction is severity L→M; the claim's own confidence note ("severity judgment L vs M is
the only soft part") is where it was wrong.

## Added mechanisms / earlier failure sites / new reachability (same trace)

- Broader reachability than claimed: the bypass is not specific to cold senders. The 401 branch
  (`verify_inbound_message` raising `RuntimeError` for an invalid message model, missing certificate,
  or signature failure) and the 403 own-domain branch also execute before l. 335, so an attacker can
  flood with invalid-signature bodies that need no pinned domain and no valid signature at all. The
  cold branch merely requires a well-formed `Message` with an unpinned `user@domain`; the 401 branch
  is at least as easy and is a strictly unauthenticated class.
- Coupling with `hunt-s1#2`: the cold branch calls `queue_domain_resolution(from_node_id)` at
  api.py:313 before the (missing) limiter, adding an attacker-chosen domain to the unbounded
  `_unresolved_domains` set (runtime.py:895–898). The missing limiter is what allows distinct-domain
  additions to be driven at line rate, so `#5` removes the natural throttle that would bound `#2`'s
  growth. They share a root cause (early-return placement) and should be repaired together.
- Coverage: the message rate limiter has zero 429 tests; the gossip limiter has three. A repair
  should add a messages-route 429 test, since nothing currently asserts the quota is reachable.

## Fix-direction constraints

- A repair must key the pre-verification paths on a source the sender cannot choose freely. Simply
  hoisting `allow_message(from_node_id)` above `verify_inbound_message` is **wrong**: on the cold and
  401 paths `from_node_id` is derived from attacker-supplied `from_address` (the claimed domain, or a
  canonical `lat_*` id), so an attacker rotates it to obtain unlimited buckets. The fix needs an
  IP-keyed (`_peer_ip`, which already honors `X-Forwarded-For` set by the shipped nginx config)
  fallback for unauthenticated traffic, or consumption of a token before verification keyed on the
  transport identity.
- The repair must preserve the existing response contract: cold senders must still receive the 503 +
  `Retry-After: 60` problem body, foreign destinations 403, and invalid signatures 401; only the
  consume/deny decision is added. Blocked-sender 202 ordering (`BlockedSenderError` before
  `RuntimeError`) and the `CustodyError → 202 rejected receipt` mapping must not be reordered.
- It must not double-consume for the warm path: a verified message should consume exactly one token
  from its identity bucket, not one identity token plus one IP token.
- A full repair at the Python layer does not by itself restore the documented nginx IP-limit design;
  if the operator adds nginx `limit_req` zones, the impact drops, so the fix scope (daemon quota vs
  edge limiter) should be stated, not assumed.

## Checked and clean

- Verified by reading, not assumed: `allow_message` and `allow_gossip` are distinct bucket kinds
  (`rate_limit.py:96–106`); the message bucket is keyed only on `peer_id=from_node_id`; the gossip
  route composes `sender_node_id or _peer_ip(request)` at api.py:264 and the messages route has no
  such composition.
- Branch order at api.py:289–338 read line by line: `verify_inbound_message` → `BlockedSenderError`
  202 → `RuntimeError` 401 → cold 503 → own-domain 403 → `allow_message` 429 → `accept` 202.
- `require_content_length(MAX_MESSAGE_BODY_BYTES=128*1024)` is enforced as a FastAPI dependency
  before the handler body; the body cap is real, so per-request work is bounded (supports L-not-H).
- `_peer_ip` honors `X-Forwarded-For` (api.py:110–117) and the shipped nginx config sets it, so an
  IP fallback would be meaningful if added.
- Cold-path semantics themselves (503 + Retry-After, no custody) are intended per docs/LOOSE_ENDS.md
  and tests/test_integration.py:36 — not re-reported as a defect.

## Enumeration

Composed command closing the class "every rate-limit consumption site on the API routes and the key
each uses":

    rg -n "allow_message\(|allow_gossip\(|_peer_ip\(" lattice/api.py

Output:

    lattice/api.py:110:def _peer_ip(request: Request) -> str:
    lattice/api.py:264:        peer_id = sender_node_id or _peer_ip(request)
    lattice/api.py:265:        if not runtime.rate_limiter.allow_gossip(peer_id):
    lattice/api.py:335:        if not runtime.rate_limiter.allow_message(from_node_id):

Instance table:

| Route | Limiter call | Key | Unauthenticated fallback? | Early returns before the call | Disposition |
|-------|--------------|-----|---------------------------|-------------------------------|-------------|
| /gossip | `allow_gossip(peer_id)` l.265 | node_id, else IP | yes (`or _peer_ip`) | none (call precedes `receive_batch`) | examined-clean |
| /messages | `allow_message(from_node_id)` l.335 | from_node_id only | **no** | 401 (l.306), cold 503 (l.319), 403 (l.329) | FINDING 1 |

Composed command closing "does any shipped edge control rate-limit these routes":

    rg -n "limit_req|limit_conn|zone" deploy/   # → no matches (exit 1)

## Bound

- Ran no live server; `rfc8785` is absent in this environment (noted in seam-s1's bound), so the 429
  threshold behaviour and the exact 500/401/503 surfacing were read from source and tests, not
  executed. Mechanism and branch ordering are from source, which is decisive here.
- Deployment config contradiction recorded: docs/ARCHITECTURE.md:80 asserts nginx owns IP rate
  limits; deploy/lattice.nginx.conf and docs/LOOSE_ENDS.md:78 say it does not. I resolved the
  severity toward M on the artifact in the tree (no edge limit), but an operator who adds nginx
  `limit_req` zones would lower the real-world impact. If the ARCHITECTURE line reflects the intended
  production edge, the finding's severity is L; this is stated as a live-infrastructure boundary, not
  settled.
- Did not open lattice/storage/repositories.py internals; `get_pin` → `DomainPinRepository.get` is
  confirmed to be a single SQLite read at callsite resolution.py:141, but its failure surface was not
  chased (not needed for this finding).
- Message rate limiter has no test coverage; the absence of a 429 messages test is a coverage fact,
  not proof the quota is intentionally unreachable.
