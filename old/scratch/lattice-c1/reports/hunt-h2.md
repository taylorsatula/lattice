# hunt-h2 — webhook delivery & inbound custody

Pass: blind hunter. Assigned files read end-to-end: `lattice/webhook.py` (153 lines, complete),
`lattice/runtime.py` (1136 lines, complete). Traced callers/callees: `lattice/messages.py`
(inbound custody service), `lattice/storage/repositories.py` (InboundMessageRepository,
WebhookStateRepository, AuditLogRepository), `lattice/api.py` (`receive_message`,
`admin_submit`), `lattice/resolution.py`, `lattice/transport.py`, `lattice/addressing.py`,
`lattice/identity.py` (sign_object/verify_object), `lattice/protocol/models.py`
(Message/Receipt/WebhookEnvelope/DeliveryMetadata), `lattice/config.py` (WebhookConfig),
`lattice/migrations/durable/001_initial.sql`, tests (`test_webhook.py` complete,
`test_messages.py`/`test_runtime.py` relevant excerpts), `docs/PROTOCOL.md` (§5–§8),
`docs/LOOSE_ENDS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md` (webhook mentions).

## Findings

1. [H] — Crafted from-address domain permanently wedges cold-sender resolution for all later domains
- Location: lattice/runtime.py:`_resolve_pending_senders`; entry via lattice/api.py:`receive_message`
  cold-sender branch → lattice/runtime.py:`queue_domain_resolution`.
- Evidence: `for domain in batch: try: self._resolver.pin(domain) except ResolutionError as exc:
  logger.debug("async pin failed for %s: %s", domain, exc); continue` — the loop's only catch is
  `ResolutionError`. `WellKnownResolver.pin` → `resolve_with_ip` → `OutboundTransport.request`,
  which calls `parse_url(url)` outside any try and only catches
  `(TransportError, NetworkPolicyError)` in `resolve_with_ip`. A domain accepted by
  `parse_address` (it rejects only `:/@` and >253 chars) but rejected by urllib3 raises
  `LocationParseError`, which is a `ValueError`/`HTTPError` — not a `ResolutionError`.
  Empirically verified with the repo's own classes:
  `parse_address("user@![a").domain == "![a"`; `WellKnownResolver.pin("![a")` raises
  `LocationParseError: Failed to parse: https://![a/.well-known/lattice`.
- Trigger: any network peer sends `POST /lattice/v1/messages` (public fixed route) with a
  body that passes `Message.model_validate` (signature field present but never verified on this
  path) and `from_address: "user@![a"`. `verify_inbound_message` has no pin for the domain and
  returns `(domain, True)` before any signature check; `receive_message` queues the domain and
  returns 503 — before the rate limiter and before the own-domains check, so no auth, quota, or
  signature must coincide. The exception then escapes the per-domain loop and is caught only by
  `_RecurringTask._run`'s blanket handler, aborting the whole batch. `![a` (0x21) sorts before
  every lowercase domain, so every 30 s cycle aborts at it first.
- Frequency: DEMONSTRATED — one unauthenticated HTTP request; the task re-runs every 30 s
  (`cold_sender_resolution` task) and hits the poison entry every cycle for the life of the
  process. Every domain sorted after the poison entry (i.e. all normal domains) is never
  resolved.
- Outcome: every unresolvable-in-this-way entry permanently starves async cold-sender
  resolution. New senders' domains are never pinned, so their messages receive 503 indefinitely
  and can never enter durable custody. One peer blocks all other (new) peers — cross-peer
  reach, remote, unauthenticated, permanent until restart. Senders retain custody (no message
  loss on their side), but the node's core custody-acceptance function for new peers is denied.
- Confidence: traced — mechanism, trigger, and frequency all verified by execution of the real
  classes (parse_address, WellKnownResolver.pin, OutboundTransport) plus code reading of the
  scheduler/task loop. No unproven component. Reachability: PRODUCTION (a real peer request;
  no other defect gates it).

2. [H] — Failed domains are never discarded from the resolution queue: unbounded permanent retry set
- Location: lattice/runtime.py:`_resolve_pending_senders` / `_unresolved_domains`.
- Evidence: docstring: "On failure, drops it from the queue — the sender will retry later and
  receive a new 503 response." Code: the `except ResolutionError` branch does `logger.debug(...)`
  then `continue` — `self._unresolved_domains.discard(domain)` exists only in the success
  branch. Nothing else removes entries; there is no size cap, TTL, or per-domain backoff.
- Trigger: any `POST /lattice/v1/messages` whose `from_address` host is an unpinned,
  never-resolvable domain (cold-sender path queues it — unauthenticated and pre-rate-limit as
  in finding 1). Each distinct domain adds one permanent set entry. Honest case: any cold
  sender whose domain later becomes permanently unresolvable (decommissioned node, typo)
  leaves one entry.
- Frequency: DEMONSTRATED — every cold-sender POST with an unpinned from-domain enqueues; the
  set is in-memory and is cleared only by process restart. The recurring task re-attempts
  resolution of every queued domain every 30 s forever. An attacker generates unbounded
  distinct domains (any ≤253-char string without `:/@`) with one small POST each; nothing in
  the tree caps the set.
- Outcome: unbounded growth of `_unresolved_domains` (memory); every entry costs a DNS
  resolution + network-policy validation + HTTPS connection attempt (connect timeout 10 s)
  every 30 s indefinitely — sustained CPU/socket load and permanent outbound traffic toward
  attacker-chosen hostnames from a one-time cheap request. Also contradicts the function's own
  documented behavior, so this is a code-vs-intent defect, not a design choice.
- Confidence: traced — mechanism, trigger, frequency verified in code; no hypothetical code
  needed. Reachability: PRODUCTION.

3. [L] — Cross-sender message_id collision yields a final rejected receipt; identical-receipt MUST unimplemented
- Location: lattice/messages.py:`InboundMessageService.accept` with
  lattice/storage/migrations/durable/001_initial.sql:157 (`message_id TEXT NOT NULL UNIQUE`)
  and lattice/api.py:`receive_message` (`except CustodyError` → 202 signed rejected receipt).
- Evidence: dedupe is scoped per sender — `SELECT receipt FROM inbound_messages WHERE
  message_id = ? AND from_node_id = ?` — but the schema constraint is `message_id ... UNIQUE`
  alone. On collision from a different node, `create` raises IntegrityError, the UNIQUE-race
  fallback re-queries by `(message_id, from_node_id)`, finds nothing, and re-raises
  `CustodyError`, which api.py converts into a 202 signed `rejected` receipt.
- Trigger: a second, signature-valid message from a different node whose `message_id` equals one
  already in durable custody. One HTTP request; no other defect must coincide.
- Frequency: LATENT — requires a sender reusing an in-custody message_id. PROTOCOL.md §7 makes
  global uniqueness the sender's obligation ("UUIDv7 or 32-byte random base64url-unpadded;
  globally unique") but nothing enforces it: `Message.message_id` is `Field(min_length=1,
  max_length=128)` and no in-tree code generates or validates id format (ids are caller-supplied
  end to end, including via the admin submit API). Deliberate squatting or a non-random id
  convention triggers it; I cannot ground the sender population's id conventions from the tree.
- Outcome: the second sender's distinct message is permanently refused custody — a `rejected`
  receipt is final (PROTOCOL.md §8), so the sender stops retrying and drops it. Also diverges
  from PROTOCOL.md §5's MUST ("If the same `message_id` is received again and the message is
  already in durable custody, the receiver MUST return the identical signed receipt bytes"),
  which is implementable regardless of sender since Receipt carries no sender field.
- Confidence: mechanism traced (schema + code + api path); trigger requires a peer id
  collision; frequency unproven — latent by the frequency rule, capped at L. Reachability:
  PRODUCTION (real peer request).

## Checked and clean

- **`WebhookDeliveryService.deliver` exception surface**: empirically verified with
  urllib3 2.3.0 that every malformed-URL and connection-failure mode raises an `HTTPError`
  subclass (`LocationValueError`, `LocationParseError`, `MaxRetryError`,
  `NewConnectionError`, `ConnectTimeoutError`, `NameResolutionError`) — all caught by
  `except urllib3.exceptions.HTTPError` and classified retryable. No reachable non-HTTPError
  escape from `deliver` was found (envelope construction inputs are all guarded: `json.loads`
  fallback, `fromisoformat` fallback, tz-aware timestamps enforced by `_format_ts`).
- **Retry classification consistency**: `deliver` (network→retryable; 2xx→success;
  429/5xx→retryable; other→terminal) matches `classify_status` and the outbound classification
  in `_send_outbound_message` (`202`+receipt fields, `429 or >=500` retryable, else
  terminal). No divergence among the live branches.
- **Idempotency key**: `sha256("lattice-webhook:{message_id}")[:32]` — deterministic across
  restarts, 128 bits, header and `webhook_state` row both derive from the same function call
  path, so the recorded key always equals the sent `Idempotency-Key`. Verified in
  `_idempotency_key`, `_headers`, `deliver`, and `WebhookStateRepository.upsert`.
- **Claim/lease state machine** (inbound webhook): `claim_for_webhook` reclaims only expired
  leases and respects `webhook_next_attempt_at`; `mark_terminal` guards on
  `webhook_lease_owner = ?` and `status = 'webhook_leased'` with no expiry check (so a slow
  run still records its own success and cannot double-mark); `release_webhook_lease` requires
  an unexpired lease (rowcount 0 is benign — the row stays reclaimable). Attempt cap is
  enforced (`RetryPolicy` max 10, 30 s→1 h backoff) on every recorded failure path.
  Same-owner/same-second claim collision is unreachable in production (per-task non-overlap
  lock + fixed 10 s interval; `RuntimeSettings` is not constructed from operator config).
- **Duplicate-receipt idempotency (same sender)**: `get_existing_receipt(message_id,
  from_node_id)` returns byte-identical receipt bytes both pre-insert and on the UNIQUE-race
  fallback; `receipt` is retained after terminal erasure (only `content`/`extension`/
  `message_json` are erased), so post-terminal duplicates still satisfy the §5 MUST for the
  same sender.
- **At-least-once vs exactly-once**: crash between 2xx and `mark_terminal` re-delivers with
  the same idempotency key (receiver dedupes) — consistent with the documented design intent
  (durable custody ≠ delivery, invariant 5); no 202 is returned without a committed custody
  row (`create` commits inside `with self._conn` before the receipt is returned).
- **Envelope construction**: `sign_object` returns exactly
  {kind, message, metadata, signature}, matching `WebhookEnvelope` (`extra="forbid"`); the
  envelope is re-validated before send; `received_at` comes from the locally recorded
  `received_at`, not the sender timestamp (LOOSE_ENDS resolved item; code matches).
- **Outbound receipt check** (202 branch): field validation of message_id/node_id/status
  matches the documented resolved decision in LOOSE_ENDS ("validates the signed JSON receipt
  body (checks message_id, node_id, status == 'accepted')"). Not re-reported; see design risk 2.
- **Lifecycle ordering**: `stop()` drains executors before `close()` on the webhook pool and
  before persisting rate limits; `preload_content=True` responses release connections.
- **SQLite sharing**: single `_LockedConnection` serializes all repository access across the
  request thread pool and both executors (LOOSE_ENDS Phase 8 note); no concurrent-connection
  hazard in the webhook/claim paths.

## Enumeration

Assignment: every retry-classification branch and every idempotency-key use.

Command:
```
rg -n "retryable\s*=|Idempotency-Key|idempotency_key|should_retry|== 429|>= 500|record_failure|record_webhook_failure|mark_terminal|release_webhook_lease" lattice/ --type py
```
(42 matches; full output retained in transcript.)

Retry-classification branches — disposition:

| # | Site | Branch | Disposition |
|---|------|--------|-------------|
| 1 | webhook.py:97-105 deliver | `except HTTPError` → retryable | examined-clean |
| 2 | webhook.py:110-119 deliver | 2xx → success | examined-clean |
| 3 | webhook.py:127 deliver | `status == 429 or status >= 500` | examined-clean |
| 4 | webhook.py:135-149 classify_status | 2xx / 429 / 5xx split | production-dead (tests only) — side discovery |
| 5 | runtime.py:931 | outbound claim: non-dict message_json → terminal | examined-clean |
| 6 | runtime.py:935-936 | no endpoint → retryable + circuit | examined-clean |
| 7 | runtime.py:939 | circuit open → retryable (no circuit bump) | examined-clean |
| 8 | runtime.py:967-968 | TransportError → retryable + circuit | examined-clean |
| 9 | runtime.py:984-1002 | 202 + receipt field validation → success | examined-clean (see design risk 2) |
| 10 | runtime.py:1004-1006 | 429/5xx → retryable | examined-clean |
| 11 | runtime.py:1013-1014 | other status → terminal | examined-clean |
| 12 | runtime.py:1030 | webhook claim: non-dict message_json → terminal | examined-clean |
| 13 | runtime.py:1060-1073 | result.success → delivered / else → retryable flag | examined-clean |
| 14 | messages.py:356-362 record_webhook_failure | not retryable → terminal failed | examined-clean |
| 15 | messages.py:366-371 record_webhook_failure | should_retry cap → terminal failed | examined-clean |
| 16 | messages.py:377 record_webhook_failure | release lease with backoff | examined-clean |
| 17 | messages.py:177-191 record_failure (outbound) | same cap pattern | examined-clean |
| 18 | messages.py:57 RetryPolicy.should_retry | max_attempts=10 | examined-clean |
| 19 | runtime.py:_circuit_* | per-peer exponential backoff, threshold 3, cap 60 s | examined-clean (outbound/gossip only) |

Idempotency-key uses — disposition:

| # | Site | Use | Disposition |
|---|------|-----|-------------|
| 1 | webhook.py:60-62 `_idempotency_key` | derivation (sha256, [:32]) | examined-clean |
| 2 | webhook.py:68 `_headers` | `Idempotency-Key` header | examined-clean |
| 3 | webhook.py:87, 99, 115, 124 `deliver` | key computed once, upserted on all three outcome paths | examined-clean |
| 4 | repositories.py:1155-1174 `WebhookStateRepository.upsert` | persisted with ON CONFLICT(message_id) | examined-clean |
| 5 | migrations/durable/001_initial.sql:167-173 `webhook_state.idempotency_key` | column | examined-clean |
| 6 | repositories.py:1176 `WebhookStateRepository.get` | read side | no production callers — side discovery |

## Design risks (max 2)

1. **Transient custody-insert failures produce a final rejection.** `api.py` maps any
   `CustodyError` from `accept()` — including a transient storage error (disk full, lock
   timeout) raised as something other than the handled UNIQUE race — to a 202 signed
   `rejected` receipt, which is final: the sender stops retrying and the message is lost
   where a 503 would have preserved sender custody. Documented as intended in LOOSE_ENDS
   ("custody-insert failures now return HTTP 202 with a signed rejected receipt"), so listed
   here rather than as a finding.
2. **Outbound custody receipt is validated on field values only.** `_send_outbound_message`
   comments "Validate the signed custody receipt" but checks `message_id`/`node_id`/`status`
   fields, not the signature. Authenticity rests entirely on TLS to the pinned endpoint; a
   destination that fakes a receipt only harms its own mail. Documented resolved decision;
   listed as risk.

## Side discoveries (single-pass candidates, not confirmed work)

- `WebhookDeliveryService.classify_status` has no production caller (tests only) and diverges
  from `deliver` on 3xx: `deliver` follows redirects (empirically verified — urllib3
  PoolManager re-POSTs body and headers to the 302 Location and returns the final status as
  success) while `classify_status` classifies any 3xx as terminal.
- `WebhookStateRepository.get` has no production caller; `webhook_state` is write-only
  observability. The idempotency key derives from `message_id` alone with no node
  discriminator — harmless in the per-node loopback deployment the docs describe.
- No pruning exists for `inbound_messages` terminal rows, `webhook_state`, or `audit_log`
  (schema comment says audit is "retained 30 days" but no deletion code exists) — unbounded
  durable growth, retention observation only.
- The `LocationParseError` escape in finding 1's mechanism also applies to
  `RuntimeCoordinator._certificate_for_node`'s `resolver.resolve` (catches only
  `ResolutionError`), but its domain inputs come from the peer store and bootstrap config
  rather than unverified request fields; I did not trace a hostile input to that site.

## Bound

- Read completely: webhook.py, runtime.py, test_webhook.py, resolution.py, addressing.py,
  LOOSE_ENDS.md. Read in targeted full-function form: messages.py (inbound + retry policy),
  repositories.py (inbound/webhook/audit/pin), api.py (routes + models), transport.py,
  identity.py (sign/verify paths), protocol/models.py, config.py, migration 001,
  PROTOCOL.md §5–§8, test_messages.py and test_runtime.py excerpts.
- Not opened: cli.py offline commands, gossip.py/topology.py/peers.py internals, rate_limit.py
  internals, cache repositories beyond `circuit_observations`, systemd/nginx deployment files,
  migrations 002+ (deleted per LOOSE_ENDS).
- Not exercisable without live infrastructure: real DNS/TLS behavior against remote hosts,
  multi-process SQLite contention, systemd restart behavior; urllib3 behaviors were verified
  against the vendored version (2.3.0) in the local environment.
- Enumeration pattern matches identifier-level text only; a classification implemented via
  different identifiers than `retryable`/`429`/`>= 500` would not match (none observed while
  reading the assigned files end-to-end).
