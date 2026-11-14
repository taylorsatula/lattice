# hunt-h1 — message models & lifecycle (lattice/messages.py)

Blind hunter pass. `lattice/messages.py` read end to end (349 lines); traced into
`lattice/protocol/models.py` (all validators), `lattice/protocol/signing.py`,
`lattice/storage/repositories.py` (claim/lease/terminal/expire SQL),
`lattice/storage/migrations/durable/001_initial.sql` (schema), `lattice/runtime.py`
(delivery/webhook/expiry callers), `lattice/api.py` (submit/accept callers),
`lattice/webhook.py`, `lattice/protocol/constants.py`, `lattice/canonical.py`,
`tests/test_messages.py`. Prior pilots hunt-b1a/b1c covered the runtime delivery
surface around this file; their known findings are excluded here and re-checked only
for change.

## Findings

1. [L] — Expire sweep erases an in-flight leased message; a successful custody
transfer is recorded `expired` while the audit log records `delivered`
- Location: `lattice/storage/repositories.py:OutboundMessageRepository.expire_messages`
(called from `lattice/messages.py:OutboundMessageService.expire`, driven by
`lattice/runtime.py:_run_expiry_cleanup`); collateral at
`lattice/runtime.py:_send_outbound_message`.
- Evidence: `UPDATE outbound_messages SET status = 'expired', ... content = ?, ...
WHERE status IN ('pending', 'leased') AND expires_at <= ?` — the sweep takes
**leased** rows with no exclusion for an in-flight delivery; the worker's later
`record_success` runs `mark_terminal ... WHERE message_id = ? AND lease_owner = ?
AND status = 'leased'` which matches nothing (status is now `expired`,
`lease_owner` was nulled by the sweep), returns `False`, and the runtime ignores
the return while still writing the audit: `self._outbound.record_success(message_id,
owner)` is followed unconditionally by `self._audit_outbound_delivered(...)`.
- Trigger: production. `_run_outbound_delivery` claims a row (5-minute lease) in
the final seconds of the row's `expires_at` window — realistic for a message to a
peer that was unreachable most of its TTL (backoff reaches the 24 h cap = the
default TTL), where the last retry lands just before expiry. The maintenance
tick (`expiry_interval_seconds = 60`) must then fire during the HTTP flight
(connect 10 s + read 30 s per attempt). Who causes it: our own scheduler; what
must coincide: expiry tick ∩ in-flight delivery ∩ `expires_at <= now`.
- Frequency: coincidence race on a narrow population (messages claimed within
their final TTL moments whose delivery flight straddles a 60 s maintenance tick);
not observed in tests, arithmetically reachable today (transport H from hunt-b1b
currently masks all live delivery, so this is GATED behind that repair — once
delivery works, this race is live).
- Outcome: the remote peer accepted durable custody and returns a valid 202, but
the local row is terminal `expired` with content erased, while `audit_log`
carries `OUTBOUND_DELIVERED` — the DB and the audit log, the two records of the
same terminal event, permanently disagree. No loss and no duplicate send (the row
is terminal either way); the cost is a mislabeled terminal state plus a
misleading audit trail for reconciliation.
- Confidence: traced — mechanism certain (SQL predicates and the unconditional
audit verified by reading); trigger reachable in production but requires the
coincidence window above; frequency ungrounded beyond the population argument
(kept at L accordingly). Marked GATED behind hunt-b1b finding 1 (transport
`TypeError`) until that repair lands, per the reachability-kind rule.

## Checked and clean

- **Message semantic validation** (`messages.py:submit`/`accept` →
  `Message.model_validate`): `extra="forbid"`; `content` bounded to 64 KiB UTF-8
  (`MAX_MESSAGE_CONTENT_BYTES`), matching PROTOCOL §7; `extension` re-serialized
  and bounded to 16 KiB; `priority` Literal; `ttl_seconds` Field(ge=1,
  le=MAX_TTL_SECONDS=604800) re-checked in `submit` (`ttl out of range`); body
  size pre-bounded by `require_content_length(MAX_MESSAGE_BODY_BYTES)` (128 KiB >
  64+16 KiB payload + envelope). A malformed message cannot enter custody
  through either service. Signature validation is the caller's contract and is
  performed (`runtime.verify_inbound_message` signs-checked before `accept`;
  `sign_local_message` before `submit`).
- **Expiry arithmetic**: `expires_at = submit-time + ttl` (receiver/sender-local
  clock, not the signed `timestamp`); `claim_pending` requires `expires_at > now`,
  `expire_messages` requires `expires_at <= now` — disjoint predicates on a
  single serialized connection, so a row cannot be both claimable and expirable.
  `_format_ts` fixed-width format makes string comparison chronological. TTL is
  not anchored to the signed message `timestamp`, but the only in-tree submit
  path (`sign_local_message`) stamps `timestamp == now`, so no divergence is
  reachable today.
- **Retry arithmetic** (`RetryPolicy`): attempt_count is 1-based (incremented at
  claim); `should_retry` gives exactly `max_attempts` attempts; delay `base·2^(n-1)`
  capped by `max_delay`, jitter bounded to ±25% of delay — never negative;
  `2**(n-1)` cannot overflow Python ints and is capped before use.
- **Erasure completeness** (all six service call sites + three repository
  implementations): every terminal path (`record_success`,
  `record_failure` non-retryable, `record_failure` exhausted, `expire`,
  `record_webhook_success`, both `record_webhook_failure` terminal branches)
  sets `content`, `extension`, and `message_json` to the erase value and NULLs
  lease state. Content-bearing columns in the schema are exactly
  `content`/`extension`/`message_json` — none survives a terminal transition.
  `to_address`/`from_address` are retained metadata; `receipt` in
  `inbound_messages` is retained deliberately (PROTOCOL §8 requires the receipt
  bytes be replayed identically for duplicate `message_id`), which
  `get_existing_receipt` + the UNIQUE-race fallback implement correctly.
  `webhook_state` holds only a SHA-256 idempotency digest and a 256-byte
  operator-side error string — no message content. Terminal rows are never
  re-claimed (`claim_*` filters on non-terminal statuses), so the
  non-JSON `[erased]` value in `message_json` is never re-parsed on a live path.
- **Dedup key consistency**: `accept`'s pre-check, UNIQUE-race fallback, and
  `get_existing_receipt` all key on `(message_id, from_node_id)`. The schema's
  global `UNIQUE(message_id)` makes a **cross-sender** ID collision surface as
  `CustodyError` → api returns a final signed `rejected` receipt (202) —
  protocol-accurate ("destination will not take custody") and honest collision
  probability is negligible (32-byte random / UUIDv7 IDs, no relay path per
  invariant 6, admin-supplied IDs are operator-chosen). Examined, not a defect.
- **Receipt construction** (`build_receipt`): `Receipt` model enforces node-ID
  pattern and tz-aware `received_at`; `sign_receipt` → `identity.sign_object`
  covers the full canonical object (status and received_at included) via
  RFC 8785 + domain-separated preimage. Receipts use the receiver's clock —
  issuer-correct. The runtime's failure to *verify* peer receipts is
  hunt-b1b finding 5 (known; unchanged).
- **Lease/claim semantics**: same-owner same-expiry-second re-select collision in
  `claim_pending`/`claim_for_webhook` is unreachable (`_RecurringTask`
  non-overlap lock + ≥10 s intervals; unique thread-name owners);
  `release_lease`/`mark_terminal` re-check `lease_owner` so a stale worker cannot
  mutate a re-claimed row; lease-expired rows are re-claimable (self-healing
  after crash). `record_failure`'s `CustodyError` on a missing row is unreachable
  (nothing deletes message rows). Hunt-b1b reached the same conclusions.
- **E3 clock site `messages.py:36`**: `_SystemClock.now` is only the default; the
  runtime injects one shared clock. All timestamps it produces are local custody
  metadata (`created_at`, `expires_at`, `received_at`, lease bounds) or receipts
  we sign — issuer clock is the correct clock in every case. **examined-clean**.
- **`submit` UNIQUE detection**: `sqlite3.IntegrityError` propagates unwrapped
  through `_LockedConnection` and `with conn:`; its message contains
  `UNIQUE constraint failed:`, so the string match converts admin duplicate
  submits into `CustodyError` → 400 correctly.
- **FK hygiene**: both services call `ensure_root_history` before `create`,
  satisfying the `peer_root_history` FK; placeholder `""` root keys are the
  documented deliberate fallback.

## Enumeration

Field validators (composed command, closes the class):

```
rg -n "@field_validator" -A 1 lattice/protocol/models.py | rg "field_validator|def "
```

31 validator declarations, all dispositioned:

| Site (models.py) | Field(s) | Disposition |
|---|---|---|
| :64 `Endpoints._check_url` | gossip/messages URLs | examined-clean for message custody (https + no `@` enforced; weak host forms are peer-card/gossip surface, out of this assignment's scope — other hunts) |
| :83/:88/:97 `OperationalCertificateModel` | node_id, b64url keys, valid_from/until | examined-clean (tz normalized to UTC) |
| :119/:124/:129/:138 `WellKnownDocument` | node_id, domain, b64url, issued_at | examined-clean |
| :162/:167/:172/:181/:194 `PeerCard` | node_id, domain, root key, expires_at, issued_at | examined-clean (max-lifetime check present; past-expiry rejection lives in topology, out of scope) |
| :210 `Extension._check_namespace` | absolute URI | examined-clean |
| :234 `Message._check_content_size` | content ≤ 64 KiB | examined-clean — PROTOCOL §7 match |
| :241 `Message._check_extension_size` | extension ≤ 16 KiB re-serialized | examined-clean |
| :252 `Message._check_timestamp` | tz-aware → UTC | examined-clean (no freshness bound; protocol §7 does not require one — an old-dated message may be accepted, which is protocol-conformant) |
| :269 `DeliveryMetadata._check_utc` | received/delivered_at | examined-clean |
| :292 `WebhookEnvelope._check_base64url` | envelope signature | examined-clean |
| :314/:319 `Receipt` | node_id pattern, received_at | examined-clean |
| :339/:344 `Block`, :365/:370/:375 `Transfer`, :399/:404/:413 `Rotation` | node IDs, domains, b64url, issued_at | examined-clean (not message-lifecycle actors) |

Erasure sites (composed command):

```
rg -n "erase_content|erase_value|mark_terminal|expire_messages" lattice --glob '!*.md'
```

All 6 service-level sites (`messages.py:149,177,188,202` outbound;
`messages.py:333,356,367` inbound) and all 3 repository implementations
(`repositories.py:775,844,1001`) dispositioned **examined-clean** in the table
under Checked and clean, except the `expire_messages` leased-row interaction,
which is Finding 1.

## Design risks (max 2)

1. **SQLite remanence vs erasure intent.** Column overwriting with
   `[erased]` leaves prior page images in the WAL and freed pages in the main DB
   file until overwritten; nothing checkpoints/truncates on terminal transition.
   If content erasure is a privacy/custody-hygiene guarantee (the configurable
   `erase_content_value` suggests so), physical remanence is inherent to the
   storage choice and would need a secure-delete policy decision, not a bug fix.
2. **Erase-on-exhausted-webhook-retry destroys undelivered custody content.**
   `record_webhook_failure` terminal path erases content after 10 attempts
   (30 s doubling to 3600 s ≈ 2–3 h cumulative). The sender holds a signed
   `accepted` receipt (invariant 5 permits this), but the local human never
   receives the message and the content is then unrecoverable. Uniform
   erase-on-terminal is clearly deliberate; whether inbound `failed` rows should
   retain content for operator retrieval is a policy call.

## Side discoveries (single-pass candidates, not confirmed work)

- `lattice/runtime.py:646` comment references `inbound_service.stage()`, a method
  that does not exist on `InboundMessageService` (the caller returns 503 and
  queues the domain instead). Comment drift only.
- `_run_expiry_cleanup` discards `expire()`'s returned message IDs — outbound
  expiry produces no audit event, unlike `OUTBOUND_DELIVERED`/`OUTBOUND_FAILED`.
  A pending message can vanish from the queue with zero audit trail. Runtime-side,
  adjacent to Finding 1; not independently verified against audit requirements.

## Bound

Assigned file fully read. Out of reach without live infrastructure: actual SQLite
WAL behavior under concurrent api/runtime threads (relied on hunt-b1a's OV-1
execution evidence for the connection lock); actual peer HTTP timing distributions.
The field-validator and erasure enumerations above are closed by their commands;
nothing in `lattice/messages.py` falls outside them except `RetryPolicy` and
constructor wiring, both read line-by-line.
