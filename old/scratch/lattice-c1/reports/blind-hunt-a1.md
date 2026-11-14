# blind-hunt-a1 — BLIND THIRD PASS

Scope: `lattice/api.py` end to end, traced into `lattice/runtime.py`, `lattice/rate_limit.py`,
`lattice/address.py`, `lattice/protocol/models.py`, `lattice/messages.py`, and the deployment
edge (`deploy/lattice.nginx.conf`). Target withheld. Read-only; only this report written.

## Findings

### 1. [M] Unauthenticated malformed `from_address` raises `AddressError` out of `verify_inbound_message` → plain-text HTTP 500

- Location: `lattice/api.py:receive_message` (call at line 292, `except RuntimeError` at 301);
  root cause `lattice/runtime.py:verify_inbound_message` (`parse_address(model.from_address)` is
  outside the `try/except` that wraps `Message.model_validate`).
- Evidence:
  - `lattice/api.py:301`: `except RuntimeError as exc: return _problem(401, "Message rejected", str(exc))`
  - `lattice/runtime.py`: `parsed = parse_address(model.from_address)` executes after the
    `Message.model_validate` try-block; `AddressError(ValueError)` is neither `RuntimeError` nor
    `BlockedSenderError`.
  - `lattice/protocol/models.py:Message`: `from_address: str = Field(min_length=1, max_length=320)`
    — no address-format validator, so `"no-at-sign"` passes model validation.
- Trigger (production, unauthenticated): any network peer POSTs `/lattice/v1/messages` with a body
  that validates as a `Message` but whose `from_address` has no `@` (or has an otherwise invalid
  host), e.g.
  `{"kind":"message","message_id":"m1","from_address":"no-at-sign","to_address":"a@example.com","content":"hi","timestamp":"2024-01-01T00:00:00Z","signature":"AAAA"}`.
  No pinned peer, no valid signature, and no certificate are needed — `parse_address` runs before
  every identity check. nginx sets `Content-Length`, satisfying the dependency.
- Frequency: DEMONSTRATED — adversarial population. Any unauthenticated client can issue this with
  one request; normal well-behaved peers do not (their `from_address` is built by
  `resolve_local_address`, which rejects malformed input admin-side). Adversarial-only cadence.
- Outcome: unhandled exception escapes the route; Starlette returns `500 text/plain
  "Internal Server Error"` and logs a traceback. The public contract (`docs/PROTOCOL.md` §9,
  `LATTICE_INVALID_ADDRESS` → 400; all protocol errors RFC 9457) is violated: no
  `application/problem+json`, wrong status, and internal stack context enters the log.
- Reproduced end-to-end with the real `RuntimeCoordinator` + `create_app`: response
  `500 text/plain; charset=utf-8 'Internal Server Error'`.
- Confidence: traced + reproduced (mechanism, trigger, frequency all verified on a live app).
- Second site, same mechanism: `lattice/api.py:322` `_extract_domain_from_address(
  message.get("to_address",""))` also calls `parse_address` uncaught. This one is reached only
  *after* a successful `verify_inbound_message`, i.e. an authenticated (pinned) peer with
  `to_address` lacking `@` → same plain-text 500. Reproduced with a pinned self-peer:
  `500 'Internal Server Error'`. Lower reachability than the `from_address` site (requires a valid
  signed message from a known node).

### 2. [M] `_peer_ip` trusts the client-controlled leftmost `X-Forwarded-For` → IP-fallback gossip rate limit is bypassable

- Location: `lattice/api.py:_peer_ip` (110–118), consumed at `receive_gossip` line 265
  (`runtime.rate_limiter.allow_gossip(peer_id)`).
- Evidence: `forwarded = request.headers.get("x-forwarded-for"); if forwarded: return
  forwarded.split(",")[0].strip()`. The live edge `deploy/lattice.nginx.conf` sets
  `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` for `/lattice/v1/gossip`, which
  forwards `"<client-supplied XFF>, <$remote_addr>"`; the leftmost token is attacker-supplied.
  `X-Real-IP` is set by nginx but never read.
- Trigger (production, unauthenticated): a client POSTs `/lattice/v1/gossip` whose first card does
  not verify (or `cards` empty), so `sender_node_id is None` and the bucket key is the spoofed
  header value. Vary `X-Forwarded-For` per request.
- Frequency: DEMONSTRATED — the unauthenticated gossip fallback path is taken by any peer whose
  first card is absent/unverifiable (the documented fallback in PROTOCOL §5.2). Adversarial but
  on-demand.
- Outcome: wrong rate decision. Reproduced: `X-Forwarded-For: 9.9.9.9` ×3 → `[200,200,429]`;
  six requests with `10.0.0.0`…`10.0.0.5` → `[200,200,200,200,200,200]`, no 429. The rate limiter
  is the only application-level control limiting unauthenticated gossip (which performs Ed25519
  certificate + card verification per request), so spoofing removes it.
- Confidence: traced + reproduced (mechanism, trigger, frequency verified).

### 3. [H] `RateLimiter._buckets` has no eviction and is keyed by attacker-controlled `peer_id` → unbounded memory and cache-DB growth

- Location: `lattice/rate_limit.py:RateLimiter._bucket` (91–100) / `_buckets` (88); fed from
  `lattice/api.py:_peer_ip` (line 114) and `verify_gossip_sender_card` (runtime.py).
- Evidence: `self._buckets[key] = bucket` on first sight; no removal anywhere in the class
  (`snapshot`/`restore` only add). `RuntimeCoordinator.stop()` persists every bucket via
  `_persist_rate_limits` → `CacheRepository.save_rate_bucket`, and `start()` restores them, so the
  growth is durable across restarts, not just process memory.
- Trigger (production, unauthenticated): every distinct gossip bucket key creates a new entry and
  is retained forever. Two attacker-controllable key sources, either alone sufficient:
  (a) `X-Forwarded-For` (Finding 2) — a fresh spoofed value per request; or
  (b) a self-signed "sender" peer card as `cards[0]`: `verify_gossip_sender_card` accepts a card
  whose cert is signed by the root key derived from the card's own `node_id`, so an attacker can
  mint unlimited identities and each yields a fresh node-ID bucket.
- Frequency: DEMONSTRATED — one bucket per unauthenticated gossip request with a previously unseen
  key. Reproduced: 6 requests with distinct XFF created 7 buckets (`len(_buckets)==7`).
- Outcome: unbounded resource exhaustion reachable by a network peer (per the pinned severity
  scale). Memory grows with request count and the cache DB accumulates one rate-bucket row per
  identity; both persist. No `limit_req`/`limit_conn` exists in the edge config to bound request
  cardinality.
- Confidence: traced + reproduced for mechanism/trigger/frequency. The magnitude bound is
  SUSPECTED: growth rate is linear in accepted request throughput and depends on edge capacity
  (no edge rate limiting in the supplied nginx config; real deployments may add some).

### 4. [L] Public routes do not enforce the versioned media type (§11 MUST)

- Location: `lattice/api.py:receive_gossip` (line 235) and `receive_message` (line 280); no
  `Content-Type`/`Accept` check exists (`MEDIA_TYPE` is used only as a *response* media type for
  `well_known`).
- Evidence: `docs/PROTOCOL.md` §11: "Implementations MUST reject requests with an unsupported or
  missing `version` parameter in the `Content-Type` or `Accept` header, as applicable." No route
  inspects request headers for it.
- Trigger (production): any peer POSTing the body with `Content-Type:
  application/vnd.lattice+json; version=2`, or with `application/json` (no version), instead of
  `version=1`.
- Frequency: DEMONSTRATED — any peer using a non-v1 or unversioned content type. Reproduced:
  `version=2` → `200`; `application/json` → `200` (only `text/plain` is rejected, incidentally, by
  FastAPI body parsing → 400). Adversarial/misconfigured cadence.
- Outcome: a v1 daemon silently processes bodies advertising an unsupported protocol version,
  bypassing the version-negotiation guard. No state corruption today (there is no v2 parser), so L.
- Confidence: traced + reproduced.

## Checked and clean

- `require_admin` (`lattice/api.py:196–204`): both `/lattice/v1/admin/*` handlers carry it; missing
  header → 401, malformed scheme → 401, token compared with `secrets.compare_digest`. No admin
  route reachable without the bearer; admin bearer is always non-empty (`cli.py` generates
  `"lab_"+token_urlsafe(32)`).
- `require_ready` gating on all three public routes; `well_known` returns the pre-signed document
  with `MediaType` and `Cache-Control: public, max-age=3600`.
- `require_content_length` (`api.py:184–194`): absent header → 411; non-integer header → 400;
  over-limit → 413. All three statuses are present in `_STATUS_PROBLEM_MAP`, so the HTTPException
  handler produces well-formed Problem Details.
- `RequestValidationError` handler → 400 Problem Details; non-dict JSON bodies (arrays, strings)
  for `body`/`message` endpoints yield 400, not reachable abuse.
- Gossip parsing: `cards` must be a list and `introduced_by` a string (400 otherwise); batch cap
  `MAX_GOSSIP_BATCH_SIZE` enforced *before* verification; first-card identity keying with IP
  fallback implemented as documented.
- Message flow: signature verification precedes the block check, so the signed rejected receipt
  (HTTP 202) is only issued for signature-valid senders; `CustodyError` and `BlockedSenderError`
  both return signed `rejected` receipts at 202. Not reported: PROTOCOL §8 explicitly defines "202
  Accepted with a rejected receipt" as final, so invariant 5 is not violated by these paths.
- The 403 ownership response is built inline with the correct `FORBIDDEN` type/code, so the absence
  of `403` in `_STATUS_PROBLEM_MAP` is not reachable today (no `HTTPException(403)` is raised
  anywhere; the custom handler only fires for `fastapi.HTTPException`).
- Gated goss: `verify_gossip_sender_card` runs before `allow_gossip` is per PROTOCOL §5.2 (first
  card must be verified to obtain the identity key) — not a defect.
- Health routes return 200/503 without auth; admin/health loopback restriction lives in nginx
  (out of scope per invariant 7).
- No root key is loaded or exported on any serving path in `api.py`/`runtime.py` (invariant 2).

## Enumeration

Route/dependency closure:

```
rg -n "@app\.(get|post|put|delete|patch)|dependencies=|Depends\(" lattice/api.py
```

| Route | Method | Auth/edge deps | Contract check result |
|---|---|---|---|
| `/.well-known/lattice` | GET | `require_ready` | clean |
| `/lattice/v1/gossip` | POST | `require_content_length(256K)`, `require_ready` | Findings 2, 3, 4 |
| `/lattice/v1/messages` | POST | `require_content_length(128K)`, `require_ready` | Finding 1 (1st + 2nd site), 4 |
| `/lattice/v1/health/live` | GET | none (loopback) | intended |
| `/lattice/v1/health/ready` | GET | none (loopback) | intended |
| `/lattice/v1/admin/status` | GET | `require_admin` | clean |
| `/lattice/v1/admin/messages/submit` | POST | `require_admin` | clean (admin-only; `submit` re-validates Message limits) |

`AddressError` escape sites in `api.py`: lines 122 (`_extract_domain_from_address` → call at 322)
and the `parse_address` inside `runtime.verify_inbound_message` reached at line 292; only
`RuntimeError` is caught (301, 346, 393), never `ValueError`/`AddressError`.

## Side discoveries (single-pass, not folded into the findings above)

- **Canonical-address recipient check bypass.** `lattice/api.py:322–323` guards ownership with
  `if to_domain and runtime._own_domains and to_domain not in runtime._own_domains`, where
  `to_domain = _extract_domain_from_address(...)` returns `""` for canonical `user@lat_...`
  addresses (`parse_address` sets `domain=None`). So a message whose `to_address` is *another*
  node's canonical ID is accepted (`202` + `accepted` receipt + custody), contrary to PROTOCOL §7
  "Reject messages addressed to a different node". Reproduced with `_own_domains={"example.com"}`
  and `to_address="bob@lat_remote"` → `202 {"status":"accepted"}`. Severity L (wrong custody
  semantics; the sender chooses the endpoint, so no third party is redirected), frequency
  adversarial (a peer crafting a cross-node canonical recipient), production-reachable.
  Fix constraint: compare against owned node IDs as well as domains (`resolve_local_address`
  already encodes the right predicate), not just human domains.
- **Edge `Content-Type` filter is incidental.** Wrong media types (`text/plain`) are rejected with
  a 400 by FastAPI body parsing, not by an explicit 415; Finding 4 covers the version gap.

## Design risks (max 2, <200 words)

- Expensive gossip verification precedes the rate-limit decision (`api.py:255–265`): each request
  pays Ed25519 cert/card verification even when it is about to be 429'd. PROTOCOL requires
  verifying the first card to derive the identity key, so this ordering is defensible, but it
  means the limiter cannot protect the CPU it spends. No concrete over-limit misbehavior today.
- `admin/messages/submit` has no `Content-Length` dependency (admin-authenticated); a very large
  body is bounded only by server/edge limits. Admin-only, so not reportable, but worth a limit.
