# hunt-b1c — inbound custody, rate limiting, webhook mechanism

Blind hunter pass over `lattice/rate_limit.py`, `lattice/webhook.py`, the assigned
`lattice/runtime.py` methods, `lattice/api.py` handlers `receive_gossip`/`receive_message`,
with supporting traces through `lattice/messages.py`, `lattice/gossip.py`,
`lattice/topology.py`, `lattice/resolution.py`, `lattice/storage/repositories.py`,
`lattice/storage/connection.py`, `lattice/protocol/{models,signing,constants}.py`,
`lattice/addressing.py`, `lattice/identity.py`, `lattice/peers.py`, and the daemon
lifecycle in `lattice/cli.py:690-731`.

## Findings

1. [H] — Cold-sender domain queue never drains failed domains: unbounded growth and eternal outbound re-resolution
- Location: `lattice/runtime.py:_resolve_pending_senders` (lines 900-921), entered from
  `lattice/api.py:receive_message` cold-sender path (lines 303-318) via
  `runtime.queue_domain_resolution(from_node_id)` (line 308).
- Evidence: `except ResolutionError as exc: logger.debug("async pin failed for %s: %s", domain, exc); continue`
  — only the success path executes `self._unresolved_domains.discard(domain)`. The docstring
  states "On failure, drops it from the queue" — the code does not. There is no cap on
  `_unresolved_domains`, no TTL, no retry limit.
- Trigger: any network peer POSTs `/lattice/v1/messages` with a Message-shaped JSON whose
  `from_address` is `a@<unpinned-domain>`. The cold path in `verify_inbound_message`
  (line 647) returns before signature verification; the handler returns 503 at line 303
  before `allow_message`, so no rate-limit token is consumed and no signature is required
  (the `Message` model's `signature` field has no base64url validator — any string passes).
  Each such request adds one domain to the set. Every 30 s `_resolve_pending_senders` then
  performs a DNS resolution plus an outbound HTTPS GET to
  `https://<domain>/.well-known/lattice` for every queued domain that has not yet pinned.
- Frequency: DEMONSTRATED — every cold sender whose domain fails resolution stays queued
  forever (dead domain, typo'd domain, or attacker-generated random subdomains). The
  adversarial amplification is a plain request loop from any unauthenticated network peer.
- Outcome: (a) `_unresolved_domains` grows without bound (memory); (b) one outbound HTTPS
  request per queued domain every 30 s, forever — unbounded outbound network amplification;
  (c) the `cold_sender_resolution` task permanently occupies one of the 2
  `maintenance_workers` threads, serializing gossip/verify/refresh/expiry onto the other.
- Confidence: mechanism, trigger, and frequency all traced to code in tree. The queue is
  in-memory only, so a restart clears it — the defect is per-process-lifetime.

2. [M] — Recipient-ownership guard ignores canonical node-ID addressing: custody accepted for mail addressed to another node
- Location: `lattice/api.py:receive_message` lines 320-334, helper
  `_extract_domain_from_address` (lines 120-124); root cause is that only `parsed.domain`
  is inspected.
- Evidence: `to_domain = _extract_domain_from_address(message.get("to_address", ""))` then
  `if to_domain and runtime._own_domains and to_domain not in runtime._own_domains:` —
  for a canonical `to_address` of `user@lat_<other-node-id>`, `parse_address` returns
  `domain=None, node_id=<other>` (`lattice/addressing.py:parse_address`), so `to_domain`
  is `""`, the guard is skipped, and custody proceeds. The code's own comment states the
  intent: "refuse custody of messages not addressed to this node".
- Trigger: a signature-valid message from a known, non-blocked sender arrives at this
  node's `/lattice/v1/messages` with `to_address` in canonical `user@lat_...` form naming
  any node other than this one. Canonical addressing is first-class in the tree
  (`parse_address` accepts it; `resolve_destination` resolves it without lookup).
- Frequency: plausible in normal operation — any sender using canonical addressing that
  targets or mistypes another node's ID; also deliberately reachable by any verified peer
  that wants to dump content into this operator's webhook.
- Outcome: the node takes durable custody, returns a signed `accepted` receipt (sender
  stops retrying), and delivers the third party's message body to this node's configured
  webhook — the exact outcome the 403 guard exists to prevent, bypassed for one of the two
  supported address forms. The node's own `node_id` is available (`runtime.node_id`), so
  the check could compare it; it does not.
- Confidence: fully traced (api → verify_inbound_message → accept → 202). No other layer
  re-checks `to_address` ownership (`verify_inbound_message` and `InboundMessageService.accept`
  never inspect it).

3. [L] — Malformed `from_address`/`to_address` raises unhandled `AddressError`: HTTP 500 instead of a 4xx problem detail
- Location: `lattice/runtime.py:verify_inbound_message` (the `parsed = parse_address(model.from_address)`
  call is outside any try/except) and `lattice/api.py:322` (`_extract_domain_from_address`
  calls `parse_address` unguarded). Handler catches only `BlockedSenderError` and
  `RuntimeError` (lines 293-302); `AddressError` is a `ValueError`, not `RuntimeError`.
- Evidence: `parsed = parse_address(model.from_address)` — with `from_address = "abc"`
  (no `@`), `parse_address` raises `AddressError("address must contain '@': abc")`, which
  propagates through both `except` clauses. `create_app` registers handlers only for
  `RequestValidationError` and `HTTPException`.
- Trigger: unauthenticated POST `/lattice/v1/messages` with otherwise-valid Message JSON
  (all required fields present; `from_address` simply lacks `@` or contains `:`/`/` in the
  host part). Same result for a well-formed `from_address` with a malformed `to_address`
  via the `_extract_domain_from_address` call at line 322.
- Frequency: any network peer, trivially reachable; malformed input is common hostile
  traffic. No state is written before the raise.
- Outcome: a plain Starlette 500 "Internal Server Error" with an exception traceback in the
  logs, instead of the RFC 9457 problem-detail 400/401 every other invalid-input path on
  this route returns. Misreported error class; log noise; no crash or corruption.
- Confidence: fully traced.

4. [L] — Transient custody-write failure is converted into a final signed "rejected" receipt (LATENT)
- Location: `lattice/api.py:receive_message` `except CustodyError` block (lines ~343-350);
  `lattice/messages.py:InboundMessageService.accept` line 290.
- Evidence: `raise CustodyError(f"failed to accept message: {exc}") from exc` wraps any
  non-UNIQUE `repo.create` failure; the handler then returns a signed receipt with
  `status="rejected"` and HTTP 202. Per PROTOCOL §8 (cited in the code), a rejected receipt
  is final and the sender stops retrying.
- Trigger: an infrastructure failure during the durable insert (disk full, I/O error during
  commit) on the accept path for a signature-verified message.
- Frequency: LATENT — requires a database I/O failure; no demonstrated cadence. All
  connection access is serialized through `_LockedConnection`, so self-locking is not a
  producer; disk-full/OS-level errors remain.
- Outcome: an infrastructure error is reported to the sender as a deliberate, final refusal.
  The in-tree sender treats a non-`accepted` receipt as a retryable failure
  (`_send_outbound_message` records retryable failure), so no loss inside this codebase —
  but a §8-compliant sender drops the message permanently on a transient disk error.
- Confidence: mechanism traced; trigger and frequency unproven (failure-condition armed).

5. [L] — Per-minute rate below 1.0 permanently locks out all inbound traffic (LATENT)
- Location: `lattice/rate_limit.py:_bucket` line 97 (`capacity = rate * 60.0 * self._capacity_minutes`,
  `capacity_minutes` defaults to 1.0) and `TokenBucket.consume` line 64
  (`if self._tokens >= tokens:` with `tokens=1.0`).
- Evidence: with `messages_per_minute = 0.5`, `capacity = 0.5 < 1.0`, so `consume(1.0)` can
  never succeed — tokens are refilled to at most 0.5 and every `allow_message` returns
  False forever. `RateLimitConfig` (`lattice/config.py:92-98`) validates only
  `messages_per_minute > 0`, so a fractional value is accepted at startup with no warning.
- Trigger: operator configures `[rate_limit] messages_per_minute` (or `gossip_per_minute`)
  to a value below 1.0 — e.g. "30 per hour" expressed as 0.5 per minute.
- Frequency: LATENT — requires an operator config choice; not produced by any code path
  in tree.
- Outcome: every inbound message (or gossip batch) from every peer is rejected with 429
  permanently, silently, from process start.
- Confidence: mechanism traced arithmetic-exactly; trigger requires operator
  misconfiguration; frequency ungroundable by definition.

## Checked and clean

- **Ordering in `verify_inbound_message` / `receive_message`**: signature verification
  precedes the block check (so signed rejected receipts are only issued for
  signature-verified messages, per PROTOCOL §8); the recipient-ownership check and rate
  limit both precede the custody write; the custody write itself is inside
  `InboundMessageService.accept` with an idempotent duplicate path
  (`get_existing_receipt` first, UNIQUE-race fallback second) that returns the stored
  receipt byte-identically. Correct apart from findings 2 and 4.
- **Rate-limit bucket mechanics**: `_bucket` dict access under `RateLimiter._lock`;
  per-bucket `threading.Lock` in `state()`/`consume()`; refill arithmetic
  `min(capacity, tokens + elapsed * rate)` is correct and clamps; `consume` updates
  `_last_updated` even on failure (no double-crediting); `snapshot()` computes refilled
  values without mutating live buckets and defaults absent kinds to full capacity;
  `restore()` rebuilds both kinds per node with the persisted epoch; the
  save (`str(epoch)`) / load (`float(...)`) round trip through `rate_buckets` is
  lossless; config-change mismatches clamp on the next consume. Persist happens only on
  graceful `stop()` (cli.py `finally: runtime.stop(timeout=30.0)`), which is after
  executor drain — a crash loses only depletion state in a disposable cache DB, by design.
- **Webhook mechanism**: idempotency key is a stable sha256 of the message_id, sent as
  `Idempotency-Key` on every attempt; `WebhookStateRepository.upsert` records each attempt;
  retry classification (429 and 5xx retryable, other 4xx terminal, network errors
  retryable) is consistent between `deliver` and `classify_status`; the lease/claim pair
  (`claim_for_webhook` / `release_webhook_lease` / `mark_terminal`) is owner-checked and
  lease-expired rows are re-claimable after crash; the same-owner-same-expiry-second
  re-read in `claim_for_webhook` cannot re-deliver a live lease because
  `_RecurringTask`'s non-overlap lock prevents two concurrent rounds on one task.
  The envelope uses local `received_at` (not sender-controlled timestamp) and is signed
  with the operational key — no root key touched.
- **Gossip per-card loop**: a malformed card produces a rejected `ReceivedCard` with a
  reason and the batch continues — no abort; batch bounds are enforced before any card is
  processed (API 400 when `len(cards) > MAX_GOSSIP_BATCH_SIZE`, plus the
  `cards[:MAX_GOSSIP_BATCH_SIZE]` slice in `receive_batch`); outbound batches
  (`own_card` + `select_batch_to_send(limit=16)`) are 17 ≤ 32, within the receiver bound.
- **`verify_gossip_sender_card`**: self-consistent by design (advertised root key signs
  the cert, node ID derives from that root key, cert validity window checked, card signed
  by the certified operational key) — used only as a rate-limit key, never as an
  authentication decision; failures fall back to the peer IP key.
- **`_certificate_for_node` / `_domain_for_node` / `_root_identity_for_node` /
  `_known_root_key_for_node` / `_certificate_from_pin`**: all key material comes from
  pinned or root-history state; no message-supplied key is trusted on the inbound verify
  path; the network-resolve branch inside `_certificate_for_node` is synchronous by
  design (invariant 4) and reached only when the sender is already a known peer.
- **Candidate verification and topology cadence**: `_run_verify_candidates` (60 s)
  removes candidates on card/blocked/verify failures and leaves them to expire (24 h TTL)
  on resolution failure only; `_run_refresh_topology` (300 s) and `_run_expiry_cleanup`
  (60 s) demote stale guards, prune candidates/transient/discovery rows by expiry, and
  expire outbound messages with erasure. `_run_gossip_round` / `_send_gossip_batch` honor
  the circuit breaker, record observations on 2xx, and never relay message bodies
  (invariant 6 respected — gossip carries peer cards only).
- **SQLite concurrency**: single daemon process; both connections are `_LockedConnection`
  (`check_same_thread=False` + RLock around execute/commit), WAL + 5 s busy timeout —
  no cross-thread unsynchronized access on the inbound path.

## Enumeration

Instance classes E3/E4/E5 from `scratch/lattice-c1/instances.md`, dispositioned:

- **E3 — `time.time()` sites, `rate_limit.py:35,64,126` + restore/persist pair**
  (`rg -n "time\.time\(\)" lattice/rate_limit.py` → 3 hits):
  - `:35` `__post_init__` initial `_last_updated` — examined-clean (wall clock is required
    for cross-restart persistence; the class docstring states this).
  - `:64` `consume` refill clock — examined-clean; arithmetic verified above.
  - `:126` `snapshot` single `now` for all buckets — examined-clean; no per-bucket skew.
  - restore/persist pair (`runtime._restore_rate_limits` / `_persist_rate_limits` /
    `CacheRepository.save_rate_bucket` / `load_rate_buckets`) — examined-clean; see
    "Rate-limit bucket mechanics" above. No finding.
- **E4 — broad `except Exception` at `gossip.py:92,130,246` and `topology.py`**
  (`rg -n "except Exception" lattice/gossip.py lattice/topology.py` → gossip 3, topology 5):
  - `gossip.py:92` (card model validation) — examined-clean: per-card rejection with
    reason, batch continues, reported in the API `errors` list. Intended.
  - `gossip.py:130` (accept_candidate) — examined-clean as control flow, with a side note
    (see Side discoveries): the reason string can carry internal exception text to an
    unauthenticated peer.
  - `gossip.py:246` (transient-card JSON parse in `select_batch_to_send`) — examined-clean:
    a corrupt cache row is skipped.
  - `topology.py:179,214,303,313,333` — examined-clean: all convert to `TopologyError`
    with candidate removal where appropriate; the caller `_run_verify_candidates` catches
    and logs. No swallow-and-corrupt path found.
- **E5 — dual-write candidate between `cache_repo.save_rate_bucket` and durable
  transitions** (`rg -n "with self\._conn|commit\(" lattice/storage lattice/runtime.py`):
  examined-clean / out-of-scope-with-reason — rate-bucket state lives exclusively in the
  cache DB (written only at graceful stop, read only at start); no logical operation
  spans the cache and durable stores for rate limits, so there is no dual-write
  invariant to violate. The claim/custody pairs (`claim_for_webhook` → `mark_terminal` /
  `release_webhook_lease`) are owner-checked CAS updates on the single durable connection.

## Design risks (max 2)

1. Unauthenticated gossip rate limiting is decorative against a deliberate adversary: the
   fallback key is the client-controlled first `X-Forwarded-For` element
   (`api.py:_peer_ip`), and the identity key comes from a self-consistent (not
   web-of-trust-verified) first card, so rotating identities or rotating XFF values each
   get a fresh full bucket. Intended as best-effort per the code comments; edge-rate
   limiting is nginx's job per invariant 7.
2. A webhook receiver's single terminal 4xx (or 10 exhausted retryable attempts) marks the
   inbound message `failed` and erases its content, while the sender holds a signed
   `accepted` custody receipt. Custody-vs-delivery is intended (invariant 5), but there is
   no dead-letter retention after erasure — receiver-side bugs destroy custodied payloads
   with no recovery path.

## Side discoveries

- `gossip.py:130` (`reason=f"accept failed: {exc}"`) and `gossip.py:92` can surface raw
  internal exception strings (including sqlite error text) in the `errors` array of the
  200 response to an unauthenticated gossip peer. Bounded info disclosure; single-pass
  observation, not promoted to a finding.
- `RateLimiter.snapshot()` persists IP-fallback keys (e.g. `"203.0.113.9"`, `"unknown"`)
  as if they were node IDs — harmless on restore; no action needed.

## Bound

- Not opened end-to-end: `lattice/cli.py` beyond the daemon lifecycle block (lines
  690-731) and its offline root-key commands (out of scope for the serving path, and
  invariant 2 marks them intended); `lattice/transport.py` and `lattice/network_policy.py`
  internals (read only far enough to confirm the resolver routes through the policy and
  reports `resolved_ip`); `lattice/migrations/*` (relied on `rate_buckets` column names as
  used by the repositories); tests were not consulted.
- The `_resolve_pending_senders` loop's runtime behavior under a very large queue was
  reasoned about, not measured (no live infrastructure); the unboundedness argument does
  not depend on measurement.
- `_peer_ip`'s trustworthiness behind a specific nginx configuration could not be
  verified from the tree (deployment-config dependent) — folded into Design risk 1
  rather than a finding.
