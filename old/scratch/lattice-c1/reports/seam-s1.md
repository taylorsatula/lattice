# seam-s1 — API ↔ runtime contract check

Pass type: blind hunter. Scope: `lattice/api.py` (receive_gossip, receive_message, admin_submit,
exception handlers, dependencies) and the `lattice/runtime.py` methods they call. Both sides read
end to end; every dependency reachable from the handlers' call graph was opened
(resolution.py, addressing.py, identity.py, crypto.py, signing.py, gossip.py, messages.py,
rate_limit.py, protocol/models.py) to close the exception surface of each call.

## Findings

1. [M] — Canonical `to_address` (node-ID form) bypasses the not-this-node custody guard
- Location: lattice/api.py:receive_message (guard block `if to_domain and runtime._own_domains ...`);
  helper lattice/api.py:_extract_domain_from_address
- Evidence: `to_domain = _extract_domain_from_address(message.get("to_address", ""))` /
  `if to_domain and runtime._own_domains and to_domain not in runtime._own_domains:` — the guard
  tests only `parsed.domain`; a canonical address `user@lat_<other>` parses with
  `domain=None`, so `_extract_domain_from_address` returns `""` and the `if to_domain and` short-
  circuits.
- Trigger: PRODUCTION. Any network peer POSTs a signature-valid message to
  `POST /lattice/v1/messages` whose `to_address` is in canonical node-ID form naming a node other
  than this one (e.g. `bob@lat_remote`). The daemon always configures
  `own_domains={config.domain}` (lattice/cli.py:714), so the guard is armed in every deployment.
  Must coincide with: sender uses canonical addressing (the wire-normal form — the repo's own
  `test_submit_message` and `sign_local_message` callers produce canonical to-addresses) and aims
  it at this node (sender error, stale pin, or deliberate).
- Frequency: DEMONSTRATED — every foreign-destination message that reaches this node's /messages
  route in canonical form; canonical to-addresses are the form the repo itself generates
  (`resolve_destination` returns a node_id and `SubmitRequest.to_address` is stored verbatim).
- Outcome: the same logical destination gets 403 in human form (`bob@remote.example.com`) but
  full custody acceptance in canonical form (`bob@lat_remote`): durable row inserted, signed
  "accepted" receipt returned (sender stops retrying, believing custody transferred), and the
  message body is webhook-delivered to this deployment's local consumer. Wrong custody semantics
  plus misdelivery of a third node's mail.
- Confidence: traced — mechanism (parse_address returns domain=None for `lat_*` hosts, verified in
  lattice/addressing.py:parse_address + NODE_ID_RE), trigger (guard code path), frequency (canonical
  to-addresses on the wire) all verified against source. Note: the test suite never exercises the
  guard (conftest builds runtimes without `own_domains`), so no test contradicts this.

2. [M] — Failed cold-sender domains are never evicted from `_unresolved_domains`; set grows without
   bound and is re-fetched every 30s forever
- Location: lattice/runtime.py:_resolve_pending_senders (called from the
  lattice/api.py:receive_message cold path via `runtime.queue_domain_resolution(from_node_id)`)
- Evidence: docstring says `On failure, drops it from the queue — the sender will retry later`;
  the code does `except ResolutionError as exc: logger.debug(...); continue` — the
  `self._unresolved_domains.discard(domain)` at line 919 is reached only on successful pin.
- Trigger: PRODUCTION. Any network peer POSTs to `POST /lattice/v1/messages` with a
  model-valid message whose `from_address` uses an unpinned domain (cold path:
  `verify_inbound_message` returns `(domain, True)` whenever no pin exists). The handler then calls
  `queue_domain_resolution(domain)`, unconditionally adding the domain (lowercased) to the set.
  Domains that never resolve (fabricated, expired, or permanently broken) are re-queued forever.
- Frequency: DEMONSTRATED — every cold-sender request adds one domain; distinct domains accumulate
  one-to-one with attacker-supplied `from_address` hosts; even absent abuse, any legitimate domain
  that permanently fails resolution (domain expires, node decommissioned) is retained and re-fetched
  every 30 seconds for the life of the process.
- Outcome: (a) unbounded in-process memory growth driven by unauthenticated input — each entry is
  attacker-chosen and never freed; (b) every 30s the maintenance executor serially issues
  `https://<domain>/.well-known/lattice` fetches for the whole accumulated set (transport default
  timeout applies per fetch), monopolizing the 2-worker maintenance executor that also runs
  gossip_round, verify_candidates, refresh_topology, and expiry_cleanup; (c) a persistent
  outbound-fetch amplification: an attacker chooses which public hosts this node repeatedly GETs.
- Confidence: traced — mechanism (grep confirms discard exists only on the success path),
  trigger (handler call chain), frequency (cold path requires only an unpinned from-domain) all
  verified. Severity M rather than H: growth is gradual and per-request work is bounded, not
  instant exhaustion.

3. [L] — admin_submit maps a failed destination resolution to 500, not the intended 400
- Location: lattice/api.py:admin_submit (`except RuntimeError as exc: return _problem(400,
  "Address resolution failed", str(exc))`); callee lattice/runtime.py:resolve_destination →
  lattice/resolution.py:resolve_address
- Evidence: handler catches only `RuntimeError`, but `resolve_address` raises
  `ResolutionError(ValueError)` (resolution fetch fails, domain unpinnable, pin lacks node_id) and
  `parse_address` raises `AddressError(ValueError)` (malformed `to_address`, e.g. no `@`).
  `class ResolutionError(ValueError)` — neither is a `RuntimeError`.
- Trigger: PRODUCTION. An authenticated admin POSTs `/lattice/v1/admin/messages/submit` with a
  `to_address` whose domain cannot be resolved (DNS failure, unreachable well-known, signature
  invalid at the remote) or whose syntax is malformed. The exception escapes the try block,
  bypasses both FastAPI exception handlers (they catch only RequestValidationError/HTTPException),
  and surfaces as a bare 500.
- Frequency: DEMONSTRATED — any admin submit against an unresolvable or malformed destination;
  a routine failure mode of the submit operation. The later `except (RuntimeError, ValueError)`
  around sign+submit shows the author knew the services raise ValueError subclasses — the
  resolution call simply sits outside it.
- Outcome: 500 "Internal Server Error" with a full traceback instead of the intended
  RFC 9457 400 problem detail ("Address resolution failed"); error-path misreport plus log noise
  on the admin route.
- Confidence: traced — mechanism (class hierarchies verified in resolution.py/addressing.py),
  trigger, frequency all verified. No test covers the failure path.

4. [L] — Malformed address components on the public messages route raise unhandled
   `AddressError` → 500 instead of a 4xx problem detail
- Location: lattice/runtime.py:verify_inbound_message (`parsed = parse_address(model.from_address)`
  — outside any try); lattice/api.py:receive_message →
  lattice/api.py:_extract_domain_from_address (`parse_address` on `to_address`)
- Evidence: `except BlockedSenderError:` / `except RuntimeError as exc:` are the only catches
  around `verify_inbound_message`; `parse_address("alice")` raises `AddressError(ValueError)`
  ("address must contain '@'"). The `Message` model enforces only `min_length=1, max_length=320`
  on `from_address`/`to_address` — no format constraint.
- Trigger: PRODUCTION. Any network peer POSTs a body that passes `Message.model_validate` but has
  a `from_address` without `@` (raises inside `verify_inbound_message`), or — on the warm path —
  a `to_address` without `@` or with an invalid domain (raises inside the handler's own
  `_extract_domain_from_address`). Both escape both except clauses → unhandled 500.
- Frequency: DEMONSTRATED — any remote sender (hostile or merely buggy client) posting such a
  body; trivially constructible by anyone who can reach the route.
- Outcome: 500 + traceback on the public federation route for what is client input error; the
  module's own docstring contract ("Raises RuntimeError only for structural problems (bad address
  format etc.)" in verify_inbound_message) is violated — the coordinator leaks a sibling
  `ValueError` the handler does not catch. Remote senders that treat 5xx as retryable (this
  repo's own `_send_outbound_message` does) will retry a permanently-failing message.
- Confidence: traced — mechanism (AddressError hierarchy; parse_address raise sites; Message field
  constraints), trigger, frequency all verified.

5. [L] — Cold-sender requests bypass message rate limiting entirely (no IP fallback, unlike gossip)
- Location: lattice/api.py:receive_message (cold block returns 503 before
  `if not runtime.rate_limiter.allow_message(from_node_id):`); contrast
  lattice/api.py:receive_gossip (`peer_id = sender_node_id or _peer_ip(request)`)
- Evidence: the cold block `runtime.queue_domain_resolution(from_node_id); return
  JSONResponse(status_code=503, ...)` executes before the `allow_message` check, and
  `allow_message` is keyed only on `from_node_id` — there is no `_peer_ip` fallback on the
  messages route.
- Trigger: PRODUCTION. Any network peer POSTs messages with `from_address` at unpinned domains;
  every such request is served (full `Message.model_validate` on a body up to
  MAX_MESSAGE_BODY_BYTES plus a durable-DB pin read) without consuming any rate-limit token.
- Frequency: DEMONSTRATED — every cold-sender request from any peer; sustained unthrottled
  request floods are available to anyone who can reach the route.
- Outcome: the per-minute message quota is enforced only against senders we already know —
  precisely the population that is signature-verified — while unknown senders are unlimited.
  Divergence from the gossip route, which the same file explicitly protects with IP-keyed
  fallback ("Unauthenticated traffic falls back to the client IP"). Wrong rate/quota decision at
  the trust boundary; per-request cost is bounded, hence L.
- Confidence: traced — mechanism, trigger, frequency verified; severity judgment (L vs M) is the
  only soft part.

## Checked and clean

- receive_gossip ↔ verify_gossip_sender_card: returns `str | None`, swallows every exception
  internally (bare `except Exception` on all four verification stages); handler's use of it as an
  optional rate-limit key matches. Clean.
- receive_gossip ↔ gossip_service.receive_batch: returns `list[ReceivedCard]` with
  `.accepted/.node_id/.reason` exactly as the handler's comprehension assumes; per-card
  validation and accept_candidate are individually wrapped in try/except and converted to
  per-card rejection results. Batch-size cap is enforced twice consistently
  (handler 400, service slice). Clean.
- receive_message ↔ inbound_service.accept / build_receipt: `accept` raises only `CustodyError`
  (raw sqlite failures inside `create` are converted; `get_existing_receipt` /
  `ensure_root_history` sit outside the conversion, but those are mid-operation DB failures — a
  plain 500 there is honest). BlockedSenderError ordering (subclass before RuntimeError) is
  correct; BlockedSenderError is raised only after signature verification, matching the §8
  comment. `CustodyError → 202 + signed rejected receipt` is the documented final-rejection
  mechanism, not a custody misreport.
- admin_submit ↔ allow_submission / sign_local_message / outbound_service.submit:
  `sign_local_message` raises only `RuntimeError` (from `resolve_local_address`) — caught;
  `outbound.submit` raises `CustodyError(ValueError)` — caught by
  `except (RuntimeError, ValueError)`. TTL/priority edge inputs (0, negative, bad priority)
  terminate in `CustodyError` → 400, verified through both services.
- require_ready ↔ is_ready: bool, all failures swallowed. require_admin: constant-time bearer
  compare against `runtime.admin_bearer`. require_content_length: 413/411/400 paths correct;
  HTTPException raised inside the try is not shadowed by `except ValueError`. Both registered
  exception handlers convert RequestValidationError/HTTPException to RFC 9457 bodies with the
  correct `_STATUS_PROBLEM_MAP` fallback for unmapped codes.
- verify_inbound_message signature verification chain: `verify_message` →
  `cert.verify` (IdentityError(ValueError)) and `verify_object` → `SignatureError(ValueError)`
  (crypto.py) — every signature-failure mode surfaces as ValueError, so the runtime's
  `except (IdentityError, ValueError)` → RuntimeError → 401 conversion is closed. Clean.
- admin_status: `list_all()`/`list_pending()` return lists as assumed. Clean.
- Cold-path 503 semantics (no custody, Retry-After, background resolution) is intended design,
  not reported. Synchronous network/DB work in handlers is intended (repo invariant 4).

## Enumeration

Composed command closing the exception surface of every coordinator call made from the handlers:

    rg -n "runtime\.|self\._resolver|parse_address\(" lattice/api.py | grep -o "runtime\.[a-z_]*" | sort -u
    rg -n "raise " lattice/runtime.py lattice/resolution.py lattice/addressing.py \
      lattice/crypto.py lattice/identity.py lattice/messages.py lattice/gossip.py

Route → coordinator method → handler-assumed shape → handler catches → actually raisable:

| # | Route | Method | Handler assumes | Handler catches | Actually raises | Disposition |
|---|-------|--------|-----------------|-----------------|------------------|-------------|
| 1 | POST /gossip | `verify_gossip_sender_card(card)` | `str \| None`, no raise | nothing (result used as key) | nothing (all swallowed) | examined-clean |
| 2 | POST /gossip | `gossip_service.receive_batch(cards, introduced_by=)` | `list[ReceivedCard{accepted,node_id,reason}]`, no raise | nothing | per-card exceptions converted to results; `add_transient_card`/`prefix_from_endpoints` outside per-card try → DB-failure 500 (mid-op, acceptable) | examined-clean |
| 3 | POST /messages | `verify_inbound_message(message)` | `(node_id, cold)`, raises BlockedSenderError/RuntimeError only | BlockedSenderError, RuntimeError | **also AddressError(ValueError)** from `parse_address` | FINDING 4 |
| 4 | POST /messages | `queue_domain_resolution(domain)` | no raise | nothing | nothing — but downstream eviction contract broken | FINDING 2 |
| 5 | POST /messages | `rate_limiter.allow_message(from_node_id)` | bool | n/a | nothing — **never called on cold path** | FINDING 5 |
| 6 | POST /messages | `inbound_service.accept(message, from_node_id)` | dict receipt; CustodyError/RuntimeError | CustodyError, RuntimeError | CustodyError(ValueError) (raw sqlite outside inner try → 500, mid-op acceptable) | examined-clean |
| 7 | POST /messages | `inbound_service.build_receipt(id, status)` | dict, no raise | nothing | nothing (own-key signing) | examined-clean |
| 8 | POST /messages | `_extract_domain_from_address(to_address)` (api helper) | domain string or "" | nothing | **AddressError(ValueError)**; "" for canonical form bypasses guard | FINDINGS 4, 1 |
| 9 | POST /admin/submit | `allow_submission()` | bool | n/a | nothing | examined-clean |
| 10 | POST /admin/submit | `resolve_destination(address)` | raises RuntimeError on failure | **RuntimeError only** | **ResolutionError(ValueError), AddressError(ValueError)**, sqlite errors | FINDING 3 |
| 11 | POST /admin/submit | `sign_local_message(...)` | signed dict; RuntimeError/ValueError | RuntimeError, ValueError | RuntimeError (resolve_local_address); nothing else | examined-clean |
| 12 | POST /admin/submit | `outbound_service.submit(signed, to_node_id, ttl)` | CustodyError/ValueError | RuntimeError, ValueError | CustodyError(ValueError); raw sqlite → 500 (mid-op acceptable) | examined-clean |
| 13 | all | `is_ready()` / `admin_bearer` | bool / str | n/a | nothing | examined-clean |
| 14 | all | FastAPI handlers: RequestValidationError, HTTPException | problem-detail JSON | per-handler | ValueError subclasses from handlers reach neither | FINDINGS 3, 4 |

## Design risks (max 2)

1. `runtime._send_outbound_message`'s comment says "Validate the signed custody receipt before
   transferring ownership," but it checks only three unsigned JSON fields — no signature
   verification. Under TLS this is mostly moot (the destination is the only party who could
   forge it, and a lying destination can drop mail after signing anyway). Noted as risk, not a
   finding.
2. The message rate limiter is keyed on attacker-influenced `from_node_id` (derived from the
   message body) even on the warm path; a hostile known-node identity can rotate claimed domains.
   Related to Finding 5 but speculative on its own.

## Side discoveries (single-pass candidates, not confirmed work)

- `runtime._send_outbound_message` treats a final signed "rejected" receipt (status != "accepted")
  as "invalid custody receipt" and records a *retryable* failure, so a node that returns the §8
  final rejection is retried up to 10 times before dead-lettering — contradicts the finality the
  receiving side implements (Finding-free observation; belongs to the outbound pass).
- `verify_inbound_message`'s comment "Cold sender — caller stages via inbound_service.stage()"
  references a method that does not exist anywhere in the tree (`rg "def stage"` → no match);
  its docstring likewise says the caller "should accept the message into custody now", while the
  API returns 503 without custody. Stale docstring, no runtime effect.

## Bound

- Files assigned: lattice/api.py and lattice/runtime.py read end to end (414 + 1136 lines,
  paged). Dependencies opened only as far as the handlers' call graph requires.
- Not opened: lattice/storage/repositories.py internals (sqlite exception surfaces inferred from
  messages.py call sites), lattice/topology.py beyond prefix_from_endpoints's signature,
  lattice/webhook.py, lattice/transport.py beyond the timeout default. Mid-operation DB/transport
  failures surfacing as 500 were treated as acceptable per the standing preamble and not
  chased further.
- Could not execute the package (missing `rfc8785` in this environment); all exception-hierarchy
  claims are verified by reading the class definitions (ResolutionError/AddressError/CustodyError/
  SignatureError/IdentityError → ValueError; BlockedSenderError → RuntimeError) rather than by
  running them. The 500 outcomes follow from Starlette's default handling of unhandled
  exceptions, not verified live.
- No live infrastructure: cold-sender and resolution behaviors are traced through source and the
  test suite (tests/test_api.py, tests/conftest.py read) only; the test suite never exercises the
  403 guard (no `own_domains` in fixtures) or any resolution-failure path.
