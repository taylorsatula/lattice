# blind-hunt-h2 — webhook delivery / inbound custody (blind third pass)

Pass: blind hunter (target withheld). Assigned files read end-to-end: `lattice/webhook.py`
(153 lines, complete) and its caller `lattice/runtime.py` (`_run_webhook_delivery`, traced).
Adjacent files read in full-function form while following the inbound-custody trace:
`lattice/messages.py` (inbound custody + retry policy), `lattice/storage/repositories.py`
(InboundMessageRepository, WebhookStateRepository, OutboundMessageRepository), `lattice/api.py`
(`receive_message`), `lattice/transport.py`, `lattice/resolution.py`, `lattice/addressing.py`,
`lattice/protocol/models.py`, `lattice/protocol/signing.py`, `lattice/canonical.py`,
`lattice/identity.py`, `lattice/storage/connection.py`, `lattice/migrations/durable/001_initial.sql`,
`tests/test_webhook.py`, relevant `tests/test_runtime.py`.

**Neutral-question result first:** the webhook delivery path itself preserves the custody contract.
No defect found in `lattice/webhook.py` or in `_run_webhook_delivery`; the evidence is in *Checked
and clean*. The two H findings below are on the same inbound-custody admission trace, in the
assigned `runtime.py`, discovered independently and then verified against the sibling non-blind
report `hunt-h2.md` (which named the same sites). Each was re-derived from source and confirmed by
executing the repo's real classes, not by accepting that report's frame.

## Findings

### 1. [H] — Poison cold-sender domain aborts the whole resolution batch; permanent denial of new-peer admission
- Location: `lattice/runtime.py:_resolve_pending_senders` (lines 900–921); exception originates at
  `lattice/transport.py:OutboundTransport.request` line 114 (`parsed = parse_url(url)`), escapes
  `lattice/resolution.py:resolve_with_ip` (line 51 `except (TransportError, NetworkPolicyError)`),
  escapes `_resolve_pending_senders` line 914 (`except ResolutionError`).
- Evidence:
  ```python
  for domain in batch:
      try:
          self._resolver.pin(domain)
      except ResolutionError as exc:
          logger.debug("async pin failed for %s: %s", domain, exc)
          continue
  ```
  `WellKnownResolver.pin → resolve → resolve_with_ip` builds `https://{domain}/.well-known/lattice`
  and calls `OutboundTransport.request`; `parse_url` runs before any try and raises
  `urllib3.exceptions.LocationParseError` (a `ValueError`/`HTTPError`, neither a `ResolutionError`
  nor a `TransportError`). The for-loop catches only `ResolutionError`, so the exception escapes
  the loop and the function.
- Trigger: any network peer sends `POST /lattice/v1/messages` with a body that passes
  `Message.model_validate` and `from_address: "user@![a"`. `verify_inbound_message`
  (`runtime.py:642`) resolves `parse_address("user@![a") → domain "![a"`, finds no pin, and returns
  `("![a", True)` **before any signature verification**; `api.py:303-311` queues the domain and
  returns 503 — this branch precedes the own-domain check and the rate limiter, so no auth, quota,
  or valid signature must coincide. `AddressError` is not raised: `parse_address` rejects only
  `:/@` and >253 chars (`addressing.py:66-69`).
- Frequency: DEMONSTRATED. One unauthenticated HTTP request. The `cold_sender_resolution` task
  re-runs every 30 s (`runtime.py:346-349`) and re-reads `_unresolved_domains` via
  `sorted(...)`; `"![a"` is never discarded (see finding 2), so every cycle re-attempts it and
  aborts at the same point. Each domain whose key sorts after `"![a"` (all domains beginning with
  a digit, letter, `-`, `.`, `_`, `#`, `%`, etc.) is never resolved for the life of the process.
- Outcome: permanent functional denial of cold-sender admission — new peers' domains are never
  pinned, so their messages receive 503 indefinitely. One unauthenticated peer blocks all other
  new peers from entering durable custody. Cross-peer reach, remote, persistent until restart
  (and re-triggerable after restart). Senders retain their own outbound custody, so there is no
  message loss at the origin; the node's custody-acceptance function for new peers is denied.
- Verification performed: `parse_address("user@![a") → domain "![a"`; `parse_url("https://![a/.well-known/lattice")`
  raises `LocationParseError`; real `WellKnownResolver.pin("![a")` (with `NetworkPolicy(mode="public")`
  and `OutboundTransport`) raised **uncaught** `LocationParseError`, while
  `pin("nonexistent-zzz.invalid")` raised a caught `ResolutionError`. Result matches the claim.
- Confidence: traced — mechanism, trigger, and frequency each verified by execution of the real
  classes plus code reading. No unproven component. Reachability kind: **PRODUCTION**.

### 2. [H] — Failed domains are never removed from the resolution queue (code contradicts its docstring); unbounded set + sustained outbound load
- Location: `lattice/runtime.py:_resolve_pending_senders` / `_unresolved_domains`
  (`runtime.py:256-257`, `895-898`, `900-921`).
- Evidence: docstring says *"On failure, drops it from the queue — the sender will retry later and
  receive a new 503 response."* Code: the `except ResolutionError` branch logs at debug and
  `continue`; `self._unresolved_domains.discard(domain)` appears only in the success branch
  (line 919). `rg "_unresolved_domains"` shows the only removal is that success-branch discard —
  no size cap, TTL, or per-domain backoff.
- Trigger: any `POST /lattice/v1/messages` whose `from_address` host is an unpinned domain that is
  not currently resolvable — including well-formed-but-nonexistent domains and the finding-1
  poison. This is the unauthenticated cold-sender branch (`api.py:303-311`), pre-rate-limit. Each
  distinct domain adds one permanent set entry.
- Frequency: DEMONSTRATED. The set is in-memory, cleared only by process restart. The
  30 s `cold_sender_resolution` task retries every queued domain forever. An attacker generates
  unbounded distinct domains (any ≤253-char string without `:/@`, one small POST each); nothing
  caps the set. Even the honest case (a decommissioned node / typo'd domain a cold sender uses
  once) leaves a permanent entry.
- Outcome: two compounding effects. (a) Unbounded memory growth (a set of attacker-chosen
  strings). (b) Amplified outbound load: each cycle walks the whole batch **sequentially**, each
  entry costing a DNS lookup + network-policy validation + an HTTPS connect attempt (10 s connect
  timeout), so N entries can occupy one of only two `maintenance_workers`
  (`RuntimeSettings.maintenance_workers = 2`) nearly continuously and starve `expiry_cleanup`,
  `refresh_topology`, and `verify_candidates`, which share that executor. Sustained CPU/socket/DNS
  load and permanent outbound traffic toward attacker-chosen hostnames from one-time cheap
  requests.
- Confidence: traced — mechanism, trigger, frequency verified in code and partially by execution
  (the non-discard of a failing domain was observed). Reachability kind: **PRODUCTION**.

### 3. [L] — Cross-sender `message_id` collision yields a final rejected receipt (spec-divergent)
- Location: `lattice/messages.py:InboundMessageService.accept`; `lattice/migrations/durable/001_initial.sql:142`
  (`message_id TEXT NOT NULL UNIQUE`); `lattice/api.py:338-345` (`except CustodyError` → 202 signed
  `rejected` receipt).
- Evidence: dedupe is scoped per sender — `get_existing_receipt(message_id, from_node_id)` uses
  `WHERE message_id = ? AND from_node_id = ?` — but the schema constraint is `message_id ... UNIQUE`
  alone. On a collision from a different node, `create` raises an IntegrityError, the UNIQUE-race
  fallback re-queries by `(message_id, from_node_id)`, finds nothing, and re-raises `CustodyError`,
  which api.py converts into a final 202 `rejected` receipt.
- Trigger: a second, signature-valid message from a different node whose `message_id` equals one
  already in durable custody. One HTTP request; no other defect must coincide.
- Frequency: LATENT. Requires a sender reusing an in-custody `message_id`. PROTOCOL.md §7 makes
  global uniqueness the sender's obligation ("globally unique"), but nothing in the tree validates
  or generates ids (`Message.message_id` is `Field(min_length=1, max_length=128)`); the sender
  population's id conventions cannot be grounded from the tree. Capped at L by the frequency rule.
- Outcome: the second sender's distinct message is permanently refused custody; per PROTOCOL §8 a
  `rejected` receipt is final, so the sender stops retrying. Also diverges from PROTOCOL §5's MUST
  (identical signed receipt bytes for a duplicate `message_id`), since the receipt carries no sender
  field and is implementable regardless of sender.
- Confidence: mechanism traced (schema + code + api path); frequency unproven. Reachability kind:
  **PRODUCTION** (but latent frequency).

## Checked and clean

- **`WebhookDeliveryService.deliver` exception surface.** Empirically enumerated with the installed
  urllib3 (2.7.0): every malformed-URL and connection-failure mode raises an `HTTPError` subclass
  (`LocationValueError`, `LocationParseError`, `URLSchemeUnknown`, `MaxRetryError`,
  `NewConnectionError`, `ConnectTimeoutError`, `ProtocolError`, `DecodeError`, `SSLError`) — all
  caught by `except urllib3.exceptions.HTTPError` and classified retryable. No reachable
  non-`HTTPError` escape from `deliver` was found.
- **Retry classification consistency.** `deliver` (network→retryable; 2xx→success; 429/5xx→
  retryable; other→terminal) matches `classify_status` and the outbound classification in
  `_send_outbound_message` (`202` + receipt fields; `429 or >=500` retryable; else terminal). No
  divergence among live branches. `classify_status` has no production caller (tests only) — side
  discovery.
- **Idempotency key.** `sha256("lattice-webhook:{message_id}")[:32]` — deterministic across
  restarts, 128 bits; the header and the `webhook_state` row are both produced by the same
  `_idempotency_key` computation, so the recorded key always equals the sent `Idempotency-Key`.
  Verified in `_idempotency_key`, `_headers`, `deliver`, and `WebhookStateRepository.upsert`.
- **Signed envelope.** Verified by execution: `sign_object(envelope, "webhook_envelope")` →
  `WebhookEnvelope.model_validate` → `model_dump(mode="json")` re-serializes to byte-identical
  pre-image (metadata timestamps round-trip as `...Z`), and `verify_object` over the delivered dict
  **succeeds**. No canonicalization mismatch between what is signed and what is sent. `WebhookEnvelope`
  (`extra="forbid"`) matches the `sign_object` output keys exactly.
- **Timeout.** `urllib3.Timeout(connect=10.0, read=30.0)` applied on the `PoolManager`; `urlopen`
  uses the pool default. Present on every attempt.
- **Claim/lease state machine (inbound webhook).** `claim_for_webhook` reclaims only expired leases
  and honours `webhook_next_attempt_at`; `mark_terminal` guards on `webhook_lease_owner` and
  `status='webhook_leased'` with no expiry check (a slow run still records its own success and
  cannot double-mark); `release_webhook_lease` requires an unexpired lease (rowcount 0 is benign —
  the row stays reclaimable). Attempt cap enforced (`RetryPolicy` max 10, 30 s→1 h backoff) on every
  recorded failure path.
- **Exactly-once relative to custody receipt.** A duplicate `POST /messages` returns the stored
  receipt without inserting a row or re-claiming, so the webhook fires once per accepted
  `message_id`. Crash between a 2xx webhook response and `mark_terminal` re-delivers with the same
  idempotency key (receiver dedupes) — consistent with invariant 5 (durable custody ≠ delivery).
  No 202 is returned without a committed custody row (`create` commits inside `with self._conn`).
- **Envelope provenance.** `received_at` comes from the locally recorded `received_at` column, not
  the sender timestamp; `delivery_node_id = self.node_id`; signature made with `self._identity`, so
  `verify_webhook_envelope` against the well-known operational certificate is well-formed.
- **Lifecycle ordering.** `stop()` drains both executors before `close()` on the webhook pool and
  before persisting rate limits; `preload_content=True` releases connections.
- **SQLite sharing.** A single `_LockedConnection` serializes all repository access across the
  request pool and both executors; no concurrent-connection hazard in the webhook/claim paths.

## Enumeration

Assignment enumerables: (a) retry-classification branches; (b) idempotency-key use sites;
(c) every call site that can feed an arbitrary domain string into a resolver.

Command (c) — the decisive one for findings 1–2:
```
rg -n "resolve_with_ip|resolver\.(resolve|pin)|_resolver\.|parse_url|except ResolutionError|except \(TransportError" lattice/
```
Instance table (hostile-input reachability of an unparseable domain):

| # | Site | Input origin | Disposition |
|---|------|--------------|-------------|
| 1 | runtime.py:913 `_resolve_pending_senders` → `resolver.pin` | **unverified `from_address` (request body)** | **finding 1 (batch abort) + finding 2 (never discarded)** |
| 2 | runtime.py:428 `_pin_bootstrap_peers` → `resolver.resolve` | operator bootstrap config | examined-clean (trusted; catches ResolutionError) |
| 3 | runtime.py:678 `_certificate_for_node` → `resolver.resolve` | peer-store domain / pin | examined-clean — peer-store domains only exist after a *successful* resolution (bootstrap/verified card), so they are parseable; `_run_verify_candidates` also guards candidate verification per-item. Not reachable with an unparseable domain. |
| 4 | topology.py:223 `verify_candidate` → `resolve_with_ip` | gossip peer-card `domain` (attacker-controlled) | examined-containedly-dirty — raises LocationParseError, but `_run_verify_candidates` (runtime.py:1124-1129) wraps each candidate in `except Exception`, so a poisoned candidate cannot abort a batch. Candidate is not removed on this error but candidate count is capped by topology slots. No finding. |
| 5 | transport.py:114 `parse_url` | shared root cause | the only unguarded `parse_url`; callers 1–4 above |

Command (a): `rg -n "retryable\s*=|== 429|>= 500|should_retry|record_webhook_failure|mark_terminal|release_webhook_lease" lattice/` — 18 branches;
all examined-clean; disposition matches the table in `hunt-h2.md` (independently re-walked).
Command (b): `rg -n "Idempotency-Key|idempotency_key" lattice/` — 5 sites (derivation, header, upsert
×3 paths, column); all examined-clean.

## Corrections to the sibling account (hunt-h2.md)

I re-derived findings 1 and 2 from source and executed the real classes before comparing. Verdicts
per claim:
- Claim 1 [H]: **CONFIRMED.** Severity H stands (cross-peer reach, remote, unauthenticated,
  persistent). Frequency DEMONSTRATED stands. One wording nit only: "`![a` sorts before every
  lowercase domain" is stronger than needed — it sorts before every domain whose first byte is
  greater than `!` (U+0021), which is all realistic domains; the conclusion is unaffected. No
  material sub-claim refuted.
- Claim 2 [H]: **CONFIRMED.** Severity H stands; I add the sequential-batch cost and the
  two-worker `maintenance_workers` starvation as the mechanism that makes the load amplification
  concrete. Frequency DEMONSTRATED stands.
- Claim 3 [L]: **CONFIRMED** as latent, L. Mechanism, trigger, and the PROTOCOL §5 divergence all
  re-traced. Frequency ungrounded (sender id conventions) — latent.

No sub-claim is refuted. Nothing in the sibling account was found to be a sycophantic overreach;
the only adjustment is the wording nit in claim 1 and the mechanism amplification in claim 2.

## Fix-direction constraints

- **Finding 1** is fixed by isolating per-item failures, not only by widening the catch: the
  repair must (a) catch a broader base at the per-domain boundary (or per-item `except Exception`
  like `_run_verify_candidates` already does) so one bad domain cannot abort the batch, and
  (b) validate/normalise the domain before persisting it for later resolution. Widening the catch
  alone leaves the poison entry queued and re-attempted every 30 s.
- **Finding 2** must discard-or-quarantine a domain after a bounded number of attempts (and cap the
  set), otherwise the queue is an unbounded attacker-controlled retry set. Discarding on first
  failure is the documented intent; that alone fixes the growth but changes the retry semantics, so
  a bounded per-domain attempt counter with eviction is the safer direction. Removing finding 1's
  abort does not remove finding 2 (a `ResolutionError` domain is still never discarded), and
  removing finding 2 does not remove finding 1 (the exception escapes before any discard) — the two
  are independent and both must be repaired.
- **Finding 3**: enforcing a per-sender dedupe key that matches the global UNIQUE constraint
  (or returning the recorded receipt regardless of sender) is what closes the spec divergence; a
  UI-level "generate unique ids" change does not close the server-side enforcement gap.

## Design risks (max 2)

1. **Generic narrow `except ResolutionError` around resolver calls.** The same
   `except ResolutionError` shape recurs at `runtime.py:429`, `678`, and `topology.py:226`. Only
   site 1 (finding 1) is reachable with an attacker-controlled unparseable domain today; the others
   are contained by trusted inputs or per-item wrappers. A future caller that passes request-derived
   domains would inherit the same abort. Listed as a design risk, not a finding.
2. **Outbound custody receipt is authenticity-checked on fields only.** `_send_outbound_message`
   comments "Validate the signed custody receipt" but checks `message_id`/`node_id`/`status`
   without verifying the receipt signature, and no `verify_receipt` helper exists in the tree.
   Authenticity rests on TLS to the pinned endpoint; a destination that fakes acceptance only harms
   its own mail. Documented as a resolved decision in `docs/LOOSE_ENDS.md` ("checks message_id,
   node_id, status == 'accepted'"). Listed, not re-reported.

## Side discoveries (single-pass candidates, unpriced)

- `WebhookDeliveryService.classify_status` has no production caller and diverges from `deliver` on
  3xx: urllib3 follows redirects by default (re-POSTing body and `Authorization` header to the
  `Location`), so `deliver` can report the redirected status as success while `classify_status`
  would classify a 3xx as terminal. Reachable only through a redirecting loopback webhook; severity
  L if the webhook is trusted, higher if it is not. Fix constraint: pass `redirect=False` or align
  the two classifiers. Reachability: PRODUCTION but webhook-trust-dependent.
- `WebhookStateRepository.get` has no production caller; `webhook_state` is effectively
  write-only observability. No functional impact observed.
- No pruning of terminal `inbound_messages`/`webhook_state`/`audit_log` rows; `webhook_state`
  FK `ON DELETE CASCADE` would fire on delete, but no delete exists. Retention observation only.

## Bound

- Read completely: `lattice/webhook.py`, `tests/test_webhook.py`. Read in full-function form:
  `runtime.py` (`_run_webhook_delivery`, `_resolve_pending_senders`, `_send_outbound_message`,
  `queue_domain_resolution`, `verify_inbound_message`, `_certificate_for_node`, lifecycle),
  `messages.py`, `repositories.py` (inbound/webhook/outbound), `api.py` `receive_message`,
  `transport.py`, `resolution.py`, `addressing.py`, `canonical.py`, `identity.py` sign/verify,
  `protocol/models.py`, `storage/connection.py`, migration 001.
- Verified by execution (read-only, no state changes): `parse_address("user@![a")`,
  `parse_url` on the constructed URL, real `WellKnownResolver.pin` for the poison and a normal
  nonexistent domain, rfc8785/`FloatDomainError` behaviour, the full
  sign→validate→dump→verify envelope round-trip, and the urllib3 exception MROs against the
  installed urllib3 2.7.0.
- Not reached: a live end-to-end HTTP run of `POST /lattice/v1/messages` against a started daemon
  (the trigger's pre-auth branch position is established by code reading of `api.py:292-311`, not by
  a running server); multi-process SQLite contention; systemd/nginx deployment behaviour. The
  `_certificate_for_node` poisoned-domain alternative path is recorded as a bound: I traced it to
  non-reachability (peer-store domains are post-resolution) but did not exhaustively trace every
  gossip ingestion branch.
- The sibling `hunt-h2.md` was read after my independent derivation to cross-check; its findings 1–3
  were re-derived and re-executed before being accepted here. This is a same-source confirmation,
  not an independent second frame, and is labelled as such.
