# hunt-b1b — orchestration core: outbound delivery & message-signing mechanism

Blind hunter pass. Assigned files read end to end: `lattice/runtime.py` (all named symbols),
`lattice/messages.py`, `lattice/transport.py`, outbound/inbound queue logic in
`lattice/storage/repositories.py`; supporting reads: `api.py`, `resolution.py`, `gossip.py`,
`protocol/models.py`, `protocol/signing.py`, `addressing.py`, `network_policy.py`,
`storage/connection.py`, `storage/cache.py`, `migrations/cache_schema.sql`, `docs/PROTOCOL.md`
§5–8, `docs/LOOSE_ENDS.md`, `cli.py` (cmd_serve only). Empirical verification run against the
repo's own `.venv` (urllib3 2.7.0, pyproject `urllib3>=2.0.0`) with the **unmodified**
`OutboundTransport` class and `NetworkPolicy.private(...)`; all test scaffolding (DNS stub,
self-signed certs) lived in /tmp; no repo file was touched.

## Findings

1. [H] — `OutboundTransport.request()` raises `TypeError` on every call: all outbound federation I/O is dead
- Location: `lattice/transport.py:OutboundTransport.request` (the `self._pool.urlopen(...)` call)
- Evidence: `response = self._pool.urlopen(method, target_url, body=body, headers=request_headers, fields=fields, assert_hostname=hostname, preload_content=True)` — in urllib3 2.x, `fields` and `assert_hostname` are not per-request `urlopen` kwargs; both land in `**response_kw` and are forwarded to `HTTPConnectionPool._make_request()`, which rejects them. Empirically reproduced with the unmodified class against a local TLS server: `TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'` (with `fields` absent, the same call fails on `'assert_hostname'` — both kwarg names verified). The request is never sent. A second observed failure mode in the same function: when the first policy-allowed address is IPv6 the rewritten URL `https://::1:<port>/...` is unbracketed and urllib3 cannot parse it (`TransportError: Failed to parse: https://::1:55377/...`), so dual-stack hostnames fail even apart from the kwargs fault.
- Trigger: every deployment using the pinned urllib3 (uv.lock/`.venv` = 2.7.0; `pyproject.toml` `urllib3>=2.0.0`); every outbound HTTP operation. Blast radius, traced end to end:
  - `_run_outbound_delivery` → `_send_outbound_message` → `transport.request` raises `TypeError` (only `TransportError` is caught) → exception aborts the delivery loop; the claimed rows stay `leased` (re-claimable only after the 5-minute lease expiry), `record_failure`/`release_lease` never run, and the message is never marked terminal — it churns (claim → TypeError → lease expiry → reclaim, incrementing `attempt_count` each cycle) until `_run_expiry_cleanup` expires and erases it. **No outbound message is ever delivered; all expire undelivered with content erased.**
  - `_send_gossip_batch` (same catch gap) → no gossip is ever sent.
  - `_resolve_pending_senders` → `resolver.pin()` raises `TypeError`, which `except ResolutionError` does not catch → the whole batch loop aborts each 30 s; cold senders are never pinned and receive 503 forever.
  - `cmd_serve` → `RuntimeCoordinator.start()` → `_pin_bootstrap_peers` → `resolver.resolve()` raises `TypeError`, not caught by `except ResolutionError` → **start() propagates and the daemon exits at startup** on any fresh deployment with `gossip.bootstrap` configured and the peer not already known by domain.
  - `verify_inbound_message` → `_certificate_for_node` → `resolver.resolve()` `TypeError` escapes `except ResolutionError` → `api.py:receive_message` catches only `BlockedSenderError`/`RuntimeError` → unhandled → **HTTP 500 on the public messages route**, remotely triggerable by any peer sending a message whose sender node is known-with-domain but unpinned.
- Frequency: DEMONSTRATED — 100% of real network operations on the pinned dependency stack; the fault is masked in CI because every test mocks the transport (`conftest.py:344 MagicMock(spec=OutboundTransport)`) and LOOSE_ENDS Phase 11 records that no real-TLS end-to-end test exists.
- Outcome: complete functional failure of outbound delivery, gossip, and well-known resolution; startup crash for bootstrapped fresh deployments; remote-triggerable 500s on the public route; all queued outbound messages eventually expire undelivered and are erased.
- Confidence: traced — mechanism empirically demonstrated against the repo venv with the unmodified class; trigger and frequency demonstrated (every call). No component unproven.

2. [M] — A final `rejected` receipt (HTTP 202) is retried as a retryable failure, contradicting PROTOCOL.md §8
- Location: `lattice/runtime.py:_send_outbound_message` (202-handling branch)
- Evidence: `if (data.get("message_id") != message_id or data.get("node_id") != to_node_id or data.get("status") != "accepted"):` → `self._outbound.record_failure(message_id, owner, retryable=True)` and `_circuit_record_failure(to_node_id)`. A destination returning the protocol-mandated final rejection (202 + `status: "rejected"`, e.g. via the `BlockedSenderError` path in `api.py:receive_message`) matches `message_id` and `node_id` but not `"accepted"`, so the sender schedules a retry. This contradicts `docs/PROTOCOL.md` §8 ("A `202 Accepted` with a rejected receipt is final"), the `BlockedSenderError` docstring ("a rejected receipt is final and the sender stops retrying"), and `messages.py:build_receipt`'s own docstring.
- Trigger: a destination node blocks our node (operator action at the destination: `blocks` table / `TopologyService.block`) while our outbound queue holds messages to it, or any `CustodyError` on the destination's accept path (both return 202 + signed `rejected`). Our daemon then re-sends each such message up to `max_attempts=10` with exponential backoff (60 s doubling toward 24 h — roughly 17 h of churn), mislabels each attempt in the audit log as `reason="invalid custody receipt"`, and records a circuit failure per attempt.
- Frequency: plausible in normal operation — any operator-initiated block of a peer that has pending outbound traffic toward the blocker. The handler code path itself is exercised in-tree today by `tests/test_runtime.py:TestDeliveryTasks` (mocked transport returning 202); in production its activation is gated behind finding 1's repair (no live transport call succeeds today).
- Outcome: sender violates receipt finality (repeated sends of a rejected message), audit entries carry the wrong reason, and — collateral — each retry's `_circuit_record_failure` opens the circuit breaker against that peer, which also suppresses gossip to it (`_send_gossip_batch` returns early when `_circuit_is_open`), degrading topology for an unrelated protocol event.
- Confidence: traced — mechanism certain from code and protocol text; trigger concrete; frequency gated behind finding 1 for live peers (in-tree reachability via the delivery tests' mocked transport). Unproven part: none of mechanism, only production cadence.

3. [M] — `_resolve_pending_senders` never drops failed domains; the unresolved set grows without bound from an unauthenticated, pre-rate-limit path
- Location: `lattice/runtime.py:_resolve_pending_senders` / `queue_domain_resolution`; feed at `lattice/api.py:receive_message` cold-sender branch
- Evidence: docstring says "On failure, drops it from the queue — the sender will retry later", but the code is `except ResolutionError as exc: logger.debug(...); continue` — no `discard`, so every unresolvable domain stays in `_unresolved_domains` forever and is retried every 30 s indefinitely. The feed is unbounded: `if cold_sender: runtime.queue_domain_resolution(from_node_id); return JSONResponse(status_code=503, ...)` executes **before** `runtime.rate_limiter.allow_message(from_node_id)` and requires no authentication, so every distinct `from_address` domain adds a permanent set entry with no cap and no expiry.
- Trigger: any network peer POSTs a syntactically valid `Message` (≤128 KiB, model-valid) with `from_address` `user@<any-unpinned-domain>` to `POST /lattice/v1/messages`; one request = one permanent entry. Failed pins are retried every 30 s forever (each retry is a DNS lookup plus, once finding 1 is repaired, a full well-known HTTPS fetch); `sorted(self._unresolved_domains)` re-runs each cycle; the resolution loop can occupy a maintenance worker continuously. Today, the same `TypeError` from finding 1 aborts the batch loop each cycle, so cold senders additionally never get pinned at all.
- Frequency: attacker-driven for unbounded growth (unauthenticated, unrate-limited public route); benign accumulation also occurs for every distinct dead/typo domain any sender used. Memory growth is real today; the periodic network churn activates when finding 1 is repaired.
- Outcome: unbounded memory growth and (post-fix) perpetual outbound resolution traffic driven by unauthenticated input — resource exhaustion the rate limiter was designed to prevent, on the one path that skips it.
- Confidence: traced — mechanism certain (code contradicts docstring; rate-limit ordering verified); trigger reachable today via the public route; frequency of exhaustion is attacker-volume-dependent (would justify H under the "unbounded resource exhaustion reachable by a network peer" clause; rated M because per-request growth is one set entry and no crash occurs).
- Outcome: as above.

4. [L] — (latent, gated behind finding 1) Redirect following bypasses `NetworkPolicy` (SSRF)
- Location: `lattice/transport.py:OutboundTransport.request`
- Evidence: `self._pool.urlopen(method, target_url, ...)` passes no `redirect`/`retries` control; urllib3 2.7.0 `PoolManager.urlopen` defaults `redirect: bool = True` and recurses to the `Location` target with a fresh DNS resolution and connection. `_resolve_and_validate(hostname)` is applied only to the original hostname. Empirically verified with the transport's pool construction (minus the broken kwargs): a 302 from the first hop to `http://127.0.0.1:<port>/internal` was followed, the POST body (`{"kind":"message","content":"secret"}`) was re-sent to the loopback target, and its response became the final `FederationResponse`.
- Trigger: latent — unreachable while finding 1 stands (no request ever completes). Once the kwargs fault is repaired without also disabling redirects: any peer messages/gossip endpoint or resolved well-known host (outsider-controlled content by the brief's own rules) returning a 3xx to e.g. `http://169.254.169.254/...` or any private address directs the daemon to connect there — precisely what `NetworkPolicy` public mode exists to forbid. An `http://` redirect target also skips TLS entirely.
- Frequency: attacker-controlled (any HTTPS host we fetch); zero cost to trigger per request once live.
- Outcome: SSRF into private/link-local networks with the daemon's POST body (message content or gossip batch) — an H-class trust-boundary bypass if activated.
- Confidence: mechanism traced (empirical at the urllib3 layer, verified on the repo venv); trigger and frequency explicitly latent behind finding 1. Reported so that whoever repairs finding 1 does not ship the SSRF as a side effect.

5. [L] — (latent) The custody receipt's signature is never verified; the sender trusts a three-field match
- Location: `lattice/runtime.py:_send_outbound_message` (202 branch); no `verify_receipt` exists anywhere (`protocol/signing.py` defines only `sign_receipt`)
- Evidence: the comment says "Validate the signed custody receipt before transferring ownership", but the check is field comparison only (`message_id`, `node_id`, `status`) — the receipt's `signature` (and `kind`, and `received_at`) are ignored; `api.py` even documents "Return the signed receipt so sender can validate custody transfer". `tests/test_runtime.py:283` feeds an unsigned, three-field JSON body and the message is marked delivered.
- Trigger: latent — requires the endpoint at the peer/pin-declared URL to return 202 with matching fields without being the destination's Lattice daemon (misconfigured endpoint URL in a peer card, a domain repointed to another service behind a still-valid pin, an appliance that answers 202). TLS hostname verification narrows but does not define the check the protocol specifies.
- Frequency: ungroundable beyond "requires a misdirected or misbehaving endpoint" — latent by definition.
- Outcome: `record_success` fires, the local copy is erased, and the message is recorded `delivered` although no verified custody exists — silent message loss with a clean audit trail.
- Confidence: mechanism traced (code + test confirm no verification exists); trigger and frequency latent.

## Checked and clean

- **Queue claim/release semantics** (`OutboundMessageRepository.claim_pending`/`release_lease`/`mark_terminal`): claim is one transaction (UPDATE + owner/expiry-keyed re-SELECT); the task's non-overlap lock plus the ≥10 s interval makes the same-owner/same-expiry-second re-select collision unreachable; cross-owner stealing is blocked until lease expiry; crash mid-delivery leaves rows recoverable after the 5-minute lease expiry; `mark_terminal` re-checks `lease_owner` so a success recorded after a re-claim by another owner is discarded (duplicate re-send is deduped by the destination's `message_id` idempotency). No double-claim or loss path found.
- **Retry/backoff/expiry arithmetic** (`RetryPolicy`, `expire_messages`): 1-based attempt counts (incremented at claim), 10 attempts, 60 s·2^(n−1) capped at 24 h, release gates on unexpired lease (a boundary-equal timestamp only delays to lease expiry), TTL sweep covers both `pending` and `leased` rows and erases content.
- **Circuit-breaker threshold/reset**: opens only at ≥3 consecutive failures, backoff 5 s·2^(failures−3) capped 60 s, success resets to 0/NULL, monotonic-clock-independent comparisons on tz-aware datetimes. Note: writes use bare `conn.execute` without `with self._conn:` (implicit transactions committed incidentally by later cache-repo transactions; disposable DB, single connection) — benign, recorded under Design risks.
- **Custody-transfer handshake structure** (apart from findings 2/4/5): 429/5xx → retryable; other non-202 → terminal with erasure; `TransportError` → retryable + circuit failure + audit — internally consistent.
- **Webhook egress does not use `OutboundTransport`**: `webhook.py` builds its own `PoolManager` and passes only valid urlopen kwargs — webhook delivery is unaffected by finding 1 (though it does inherit default redirect-following; its URL is operator config, not peer-controlled).
- **`allow_submission`/readiness interaction**: `list_pending` counts pending+leased non-expired rows (backpressure includes in-flight), `is_ready` liveness-checks both DBs; `cmd_serve` creates the app then calls `runtime.start()` before `uvicorn.run`, so pre-start serving is not reachable.
- **Local-message signing preimage** (`sign_local_message`): local clock is correct by definition (we are the issuer); `resolve_local_address` rejects foreign node IDs and domains; bare usernames are rejected by `parse_address` (requires `@`); `to_address` resolution is enforced by `admin_submit` before signing.
- **Inbound idempotency** (`InboundMessageService.accept`): pre-check plus UNIQUE-constraint race fallback returns the stored receipt; receipt `received_at` uses the receiver's clock; webhook envelope `received_at` comes from the durable row, not the sender-controlled message timestamp.
- **Shutdown (E2 candidate)**: scheduler stopped first, executors drained with `shutdown(wait=True, cancel_futures=False)` so in-flight claims complete and record; hard crashes recover via lease expiry.

## Enumeration

**E5 — dual-write in the claim/custody write pair.**
Command: `rg -n "commit\(|with self\._conn|with conn|transaction" lattice/storage lattice/runtime.py`
- Outbound claim → UPDATE+SELECT in one `with self._conn:`; `record_success`/`record_failure` each a single transaction on the same durable connection — no cross-store pair. Disposition: **examined-clean**.
- Circuit observations (cache DB) are written outside any repository transaction (see Design risks). Disposition: **examined-clean with note**.
- `OutboundMessageService.submit` writes `ensure_root_history` and the message row in two transactions; a failed insert leaves only a benign root-history row. Disposition: **examined-clean**.

**E3 — clock sites in signed/canonicalized fields.**
Command: `rg -n "datetime\.now\(|time\.time\(" lattice`
- `messages.py:36` (`_SystemClock`): runtime injects the shared clock; produced timestamps are local custody metadata or receipts we sign — issuer clock correct. **examined-clean**
- `gossip.py:31`: card `issued_at`/`expires_at` signed by our own op key (we are the issuer). **examined-clean**
- `topology.py:57`: candidate expiry/observation timestamps — unsigned local state. **examined-clean**
- `webhook.py:38`: `WebhookDeliveryService._clock` is assigned but never read; envelope timestamps come from the runtime clock and the durable `received_at` row. **examined-clean**
- `repositories.py:25` (`_utc_now`): `first_seen_at`/`last_seen_at`/`observed_at`/`received_at` columns — unsigned metadata; all signed fields receive caller-supplied datetimes. **examined-clean**
- `protocol/models.py:33` (`_utc_now`): defined, never referenced — no default-valued signed timestamps. **out-of-scope-with-reason (dead code)**
- `runtime.py` `_SystemClock`/`sign_local_message` timestamp: locally originated message, we sign it. **examined-clean**

**E2 (attached to this pass's surface)** — `shutdown(wait=True, cancel_futures=False)`: dispositioned **examined-clean** (above).

## Design risks (max 2)

1. **Circuit-open claims consume retry attempts.** `_run_outbound_delivery` claims rows (incrementing `attempt_count`) before checking `_circuit_is_open`; each circuit-blocked claim burns one of the 10 attempts without a delivery ever being tried. Bounded effect in practice (backoff periods dominate the 60 s circuit window), but a message can reach terminal `failed` partly on non-attempts.
2. **Circuit-breaker writes without explicit commit.** `_circuit_record_success`/`_circuit_record_failure` execute bare `INSERT ... ON CONFLICT` with no `with self._conn:`; under sqlite3's default deferred isolation these ride an open transaction until some later cache-repo transaction commits, and a rollback elsewhere on that connection discards them. Benign on a disposable single-connection cache DB, but durability/ordering of circuit state is incidental rather than designed.

## Side discoveries (single-pass candidates, not confirmed work)

- The IPv6 URL-rewrite fault (`https://::1:<port>/` unbracketed → urllib3 parse failure) is folded into finding 1's evidence as an additional observed failure mode; if it is judged a separate defect it stands on its own reproduction.
- Every test mocks `OutboundTransport` (`conftest.py:344`); no test in the tree performs a real HTTP request through it — the structural reason finding 1 survived. Not itself reportable as a defect.
- `_run_outbound_delivery`'s owner string `f"delivery-{threading.current_thread().name}"` double-prefixes (`delivery-lattice-delivery-0`) — cosmetic only.

## Bound

- Assigned files fully read: `runtime.py`, `messages.py`, `transport.py`, and the outbound/inbound queue logic in `storage/repositories.py`.
- Not read end to end (out of assignment, consulted only via targeted excerpts): `cli.py` (cmd_serve only), `identity.py`, `peers.py`, `topology.py` (partially), `canonical.py`, `rate_limit.py`, `config.py`, migrations beyond `cache_schema.sql`, the `tests/` tree beyond the cited excerpts.
- No live infrastructure: real DNS, real TLS deployments, and a running daemon were unavailable; finding 1's production claim (daemon exit at startup with bootstrap) is traced from code (`cmd_serve` has no exception guard around `runtime.start()`), not observed on a live host.
- The redirect-bypass proof (finding 4) necessarily omitted the transport's broken kwargs to exercise the pool at all; end-to-end SSRF through the unmodified class is not demonstrable while finding 1 stands.
