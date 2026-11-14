# hunt-a1 — HTTP entry surface (lattice/api.py)

Blind hunter pass. `lattice/api.py` read end-to-end (414 lines); callees traced into
`lattice/runtime.py` as needed, plus `lattice/messages.py`, `lattice/resolution.py`,
`lattice/addressing.py`, `lattice/rate_limit.py`, `lattice/protocol/models.py`,
`lattice/protocol/constants.py`, `lattice/protocol/signing.py`, `lattice/gossip.py`,
`lattice/cli.py` (daemon construction), `deploy/lattice.nginx.conf`. Nothing was executed
against a live server; all mechanisms are traced by reading.

## Findings

1. [M] — Gossip rate-limit key trusts first X-Forwarded-For element
- Location: lattice/api.py:_peer_ip (used by receive_gossip)
- Evidence: `forwarded = request.headers.get("x-forwarded-for"); if forwarded: return forwarded.split(",")[0].strip()`
- Trigger: any network peer POSTs to `/lattice/v1/gossip` with a client-supplied
  `X-Forwarded-For` header (or none) and a first card that does not verify, so the limiter
  falls back to `_peer_ip`. `deploy/lattice.nginx.conf` sets
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`, which APPENDS the real client
  IP after the client's own value — so the first element is always attacker-controlled when
  the attacker sends one. Rotating the header value yields a fresh token bucket per request.
- Frequency: DEMONSTRATED — every unauthenticated gossip POST whose first card fails
  `verify_gossip_sender_card`; per-request, no coincidence required. Reachable in PRODUCTION
  (public route, no auth).
- Outcome: the gossip rate limit ("wrong rate/quota decision") is bypassable by the simplest
  spoof; additionally each forged key allocates a new entry in the unbounded
  `RateLimiter._buckets` dict, which `_persist_rate_limits` later writes row-by-row to the
  cache DB.
- Confidence: mechanism traced (nginx append semantics + first-element parse both verified);
  trigger traced; frequency grounded in the per-request population. Note the limiter is
  documented "best-effort" and identity-keyed limits are also bypassable by key rotation —
  this finding is only the XFF parsing fault, which the nginx config (X-Real-IP is set but
  ignored) shows was not intended.

2. [M] — Canonical to_address bypasses the recipient-ownership check
- Location: lattice/api.py:receive_message → _extract_domain_from_address
- Evidence: `to_domain = _extract_domain_from_address(message.get("to_address", "")); if to_domain and runtime._own_domains and to_domain not in runtime._own_domains:` … `return parsed.domain if parsed.domain else ""`
- Trigger: a known (pinned) federated peer sends a signature-valid message whose `to_address`
  is in canonical form `user@lat_<node-id>` (any node id, including a foreign one).
  `parse_address` returns `domain=None` for the `lat_` form, `_extract_domain_from_address`
  returns `""`, the `if to_domain` guard skips the 403 check, and the message flows into
  `inbound_service.accept` → durable custody → local webhook delivery. `verify_inbound_message`
  only validates `from_address`, never `to_address` ownership.
- Frequency: DEMONSTRATED — any federated peer, per message, using a canonical to_address;
  also fires on stale canonical addresses after a node-id rotation. Reachable in PRODUCTION.
- Outcome: the node takes durable custody of, and webhooks to the local consumer, messages
  addressed to a different node — exactly what the "refuse custody of messages not addressed
  to this node" check exists to prevent. Wrong custody semantics.
- Confidence: traced (mechanism, trigger); frequency contingent on a hostile or misconfigured
  sender, which federation must assume.

3. [H] — Cold-sender path: unbounded domain queue, no rate limit, eternal 30s retries
- Location: lattice/api.py:receive_message (cold_sender branch) → lattice/runtime.py:queue_domain_resolution / _resolve_pending_senders
- Evidence: `if cold_sender: runtime.queue_domain_resolution(from_node_id); return JSONResponse(status_code=503, ...)` — placed BEFORE `runtime.rate_limiter.allow_message(from_node_id)`; and in runtime: `for domain in batch: try: self._resolver.pin(domain) except ResolutionError: continue` — failed domains are never discarded, the set has no size bound, and the task re-runs every 30 s.
- Trigger: any network peer POSTs to `/lattice/v1/messages` a body that passes
  `Message.model_validate` with a `from_address` whose domain has no pin. The cold path
  returns before signature verification, so the request is effectively unauthenticated, and
  before the rate limiter, so it is unthrottled. Each unique attacker-chosen domain (random
  subdomains pass `parse_address`'s minimal shape check, ≤253 chars) is added to
  `_unresolved_domains` and retried by DNS + HTTPS every 30 s forever.
- Frequency: DEMONSTRATED — per unique from-domain, per POST; a single bogus domain from one
  buggy sender already persists forever. Reachable in PRODUCTION (public route).
- Outcome: unbounded memory growth in the in-process set, plus a permanently recurring
  resolution workload (one maintenance worker) that scales with attacker-supplied domain
  count; nothing in the tree bounds either.
- Confidence: mechanism traced end-to-end (route → queue → scheduler task → resolver);
  trigger traced; frequency requires a hostile or badly buggy peer — but the cold path is
  unauthenticated and unthrottled, so no coincidence is needed.

4. [L] — Malformed to_address raises AddressError → unhandled 500 on public route
- Location: lattice/api.py:_extract_domain_from_address (called from receive_message)
- Evidence: `parsed = parse_address(address)` — `parse_address` raises `AddressError` ("address must contain '@'", "host cannot be empty", …) but `Message.model_validate` only constrains `to_address` to `Field(min_length=1, max_length=320)` with no format check.
- Trigger: a known federated peer sends a signature-valid message whose `to_address` has no
  `@` or an empty host (e.g. `"alice"`). Verification succeeds (attacker signed it), then the
  route's own check crashes. Only `RequestValidationError` and `HTTPException` handlers are
  registered, so the AddressError propagates as a plain 500 "Internal Server Error".
- Frequency: DEMONSTRATED — any known peer, per message, with a client address-formatting bug;
  hostile peers can trigger at will. Reachable in PRODUCTION.
- Outcome: 500 + traceback on the public message route instead of a 400/403 Problem Details
  response; the sending node's outbound logic treats 500 as retryable and re-sends (bounded,
  ≤10 attempts), so the bad message produces a burst of repeated 500s.
- Confidence: traced.

5. [L] — admin_submit: ResolutionError is not a RuntimeError → unhandled 500
- Location: lattice/api.py:admin_submit (E4 site at line 393)
- Evidence: `except RuntimeError as exc: return _problem(400, "Address resolution failed", str(exc))` — but `resolve_destination` → `resolve_address` raises `ResolutionError`, which subclasses `ValueError`, not `RuntimeError` (lattice/resolution.py:25).
- Trigger: an operator POSTs to `/lattice/v1/admin/messages/submit` (valid admin bearer) with
  a `to_address` whose domain cannot be resolved — typo, dead domain, DNS failure, or a
  network-policy block. The intended 400 problem-details branch is skipped.
- Frequency: DEMONSTRATED — every admin submission to an unresolvable domain; plausible in
  normal operation. Reachable in PRODUCTION (operator action).
- Outcome: 500 "Internal Server Error" (not RFC 9457 Problem Details) plus a server traceback,
  misreporting a client input error as an internal fault. No state corruption — nothing is
  written before resolution.
- Confidence: traced.

6. [L] — Structural message errors mapped to 401 Unauthorized instead of 400
- Location: lattice/api.py:receive_message (E4 site at line 301)
- Evidence: `except RuntimeError as exc: return _problem(401, "Message rejected", str(exc))` catches every failure from `verify_inbound_message`, whose docstring says it "Raises RuntimeError only for structural problems (bad address format etc.)".
- Trigger: a network peer POSTs a message that fails `Message.model_validate` (e.g.
  `priority: "asap"`, `ttl_seconds: 0`, naive `timestamp`) or whose `from_address` has neither
  domain nor node ID. All return 401 / `LATTICE_UNAUTHORIZED`.
- Frequency: DEMONSTRATED — any remote peer sending one schema-invalid message. Reachable in
  PRODUCTION. (Sender-side retry impact is nil: 400 and 401 are both terminal.)
- Outcome: an unauthenticated/malformed request is reported as an authorization failure,
  contradicting docs/PROTOCOL.md §9 which reserves 401 for signature/certificate failures and
  defines `LATTICE_INVALID_ADDRESS` = 400 for malformed addresses. Misleading error semantics
  for senders debugging protocol violations; bounded outcome.
- Confidence: traced.

## Checked and clean
- `require_admin`: bearer prefix parsed case-insensitively, token compared with
  `secrets.compare_digest` against the runtime-held bearer; no bypass. Both admin routes
  depend on it; parameter default `_admin: None = Depends(require_admin)` executes the
  dependency (FastAPI runs `Depends(...)` defaults for arguments too — verified usage
  pattern is standard).
- `require_content_length`: 411 when absent, 413 when over the per-route cap
  (256 KiB gossip / 128 KiB messages, matching nginx `client_max_body_size`), 400 on
  non-numeric. The `except ValueError` cannot swallow the 413 `HTTPException`. E4 site 189
  correct.
- Health routes lack auth by design; `deploy/lattice.nginx.conf` restricts
  `/lattice/v1/health/` and `/lattice/v1/admin/` to loopback, matching the code comment.
- Blocked-sender path (E4 site 293): raised only after signature verification
  (`verify_inbound_message` verifies, then checks `_block_store.is_blocked`); the 202 +
  signed `rejected` receipt matches docs/PROTOCOL.md §8 ("A `202 Accepted` with a rejected
  receipt is final"). Clean.
- CustodyError path (E4 site 339): returns 202 + signed receipt with `status: "rejected"`.
  Sender-side validation (`runtime._send_outbound_message`) requires `status == "accepted"`
  and treats this as a retryable failure, so the sender cannot mistake it for accepted
  custody. Per PROTOCOL.md §8 this is the designed final-rejection shape. See Disputes.
- E4 site 346 (`accept` RuntimeError → 400): `accept` re-raises only non-CustodyError
  failures; 400 is the right class. Clean.
- E4 site 407 (`except (RuntimeError, ValueError)`): `sign_local_message` raises RuntimeError
  for non-local from_address; `outbound_service.submit` validates the full `Message` model
  (priority Literal, TTL range, content/extension size caps) and raises `CustodyError` (a
  ValueError) — caught, 400. Invalid `priority`/`ttl` from the operator cannot enter the
  outbound queue. Clean.
- Gossip route body handling: non-object JSON → `RequestValidationError` → 400 problem+json;
  `cards` non-list, `introduced_by` non-string, batch > 32 → explicit 400s. `introduced_by`
  is only recorded in results, never trusted for authorization.
- No message relay: gossip route processes cards only; the message route never forwards a
  body to a third party. Invariant 6 respected.
- No root-key exposure: `api.py` touches only public key material for verification;
  no private root key is loaded, derived, or exported anywhere in the app factory. Invariant 2.
- Exception handlers for `RequestValidationError` / `HTTPException` emit
  `application/problem+json` with matching type/code from `_STATUS_PROBLEM_MAP`.
- `well_known` and both public POST routes are gated by `require_ready`; `is_ready` also
  fails closed after `stop()`.

## Enumeration
E4 error-path sites in `lattice/api.py` (lines 189, 293, 301, 339, 346, 393, 407):

| Site | Line | Emitted | Actual failure | Disposition |
|---|---|---|---|---|
| 189 | 189 | 400 "invalid Content-Length" | non-integer Content-Length header | examined-clean |
| 293 | 293 | 202 + rejected receipt | signature-verified blocked sender | examined-clean (PROTOCOL §8) |
| 301 | 301 | 401 LATTICE_UNAUTHORIZED | structural/invalid message (also auth failures) | **finding 6** |
| 339 | 339 | 202 + rejected receipt | custody not established (DB failure) | examined-clean (PROTOCOL §8; see Disputes) |
| 346 | 346 | 400 "Custody rejected" | accept() RuntimeError | examined-clean |
| 393 | 393 | 400 (intended) / **500 actual** | ResolutionError (ValueError subclass) | **finding 5** |
| 407 | 407 | 400 "Submit failed" | sign/submit RuntimeError+ValueError | examined-clean |

Command used to close the exception-surface class (uncaught exception types crossing route
bodies):
`rg -n "raise |except " lattice/api.py` cross-checked against exception bases:
`rg -n "class (AddressError|ResolutionError|CustodyError|BlockedSenderError|RateLimitError)" lattice/*.py`
→ `AddressError(ValueError)`, `ResolutionError(ValueError)`, `CustodyError(ValueError)`,
`BlockedSenderError(RuntimeError)`. Of these, only `CustodyError` and
`BlockedSenderError` are caught in `api.py`; `AddressError` (finding 4) and `ResolutionError`
(finding 5) escape their intended handlers.

## Design risks (max 2)
1. The message-route rate limiter is keyed on `from_node_id` derived from self-generated
   key material, so per-identity quotas are inherently bypassable by key rotation even after
   the XFF fix (finding 1) — a protocol-level cost-function gap, not a code bug.
2. `admin_status` reaches into private members (`topology_service._peers`,
   `runtime._own_domains`) — fragile coupling, not a current fault.

## Side discoveries
- `parse_address` lowercases domains but `config.domain` is not normalized
  (`lattice/config.py:127` only checks shape). A daemon configured with a mixed-case domain
  (e.g. `Example.com`) would 403 all legitimately-addressed inbound mail and reject its own
  local from_addresses in `resolve_local_address`. Operator-config-triggered; single-pass
  claim, not fully traced through every comparison site.
- The `RequestValidationError` handler puts a Python repr (`str(errors_list)`) into
  `detail` — cosmetic only.
- Cold-sender 503 responses are entirely unthrottled (rate limiter runs after the cold-path
  return) — folded into finding 3 rather than reported separately.

## Bound
- No live daemon or HTTP client was run; all trigger paths are traced statically, including
  FastAPI/uvicorn default behavior for unhandled exceptions (plain 500).
- Tests were not enumerated or executed.
- `lattice/runtime.py` was read end-to-end but only dispositioned for the paths the API
  surface depends on (verification, cold-sender queue, circuit breaker, rate-limit
  persistence); its background delivery loops were not audited beyond those traces.
- Did not audit `lattice/webhook.py`, `lattice/transport.py`, or storage repositories beyond
  the signatures the API routes call.
