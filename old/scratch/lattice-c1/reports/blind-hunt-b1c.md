# blind-hunt-b1c — BLIND THIRD PASS (target withheld)

Neutral question under test: does the inbound path enforce sender authenticity, custody, rate limits,
and webhook idempotency correctly — verify/block/custody ordering, token-bucket arithmetic and
restore, webhook retry classification and idempotency, gossip per-card failure isolation and batch
bounds?

Files read end to end: `lattice/runtime.py` (1136 lines), `lattice/rate_limit.py`, `lattice/webhook.py`,
`lattice/api.py` (all handlers, esp. `receive_gossip`/`receive_message`). Traced into
`lattice/messages.py`, `lattice/gossip.py`, `lattice/topology.py`, `lattice/identity.py`,
`lattice/protocol/{models,signing,constants}.py`, `lattice/storage/repositories.py`,
`lattice/migrations/durable/001_initial.sql`, `lattice/migrations/cache_schema.sql`,
`lattice/addressing.py`, `lattice/config.py`, `deploy/lattice.nginx.conf`, `lattice/cli.py` (serve path
only). Prior passes' reports were consulted only after my own frames were derived, to avoid
re-reporting known sites.

Frame re-derived from source before checking anything: `MAX_GOSSIP_BODY_BYTES = 256*1024` (receiver
dependency `require_content_length` in `receive_gossip`, `api.py:238`); `MAX_GOSSIP_BATCH_SIZE = 32`
(API 400 at `api.py:249` + `receive_batch` slice at `gossip.py:89`); nginx `client_max_body_size 256k`
for `/lattice/v1/gossip` (`deploy/lattice.nginx.conf:44`) and `128k` for `/lattice/v1/messages`
(`:56`); outbound gossip sender uses `select_batch_to_send(limit=16)` and prepends `own_card`
(`runtime.py:1102-1103`); there is **no byte-size bound on the outbound batch**.

## Findings

1. [M] — Outbound gossip batch is bounded by card count only; a peer can seed oversized cards so every
   gossip body exceeds the receiver's `MAX_GOSSIP_BODY_BYTES`, drawing 413 from every peer and opening
   the circuit breaker network-wide
- Location: `lattice/runtime.py:_send_gossip_batch` (1095-1136), feeding from
  `lattice/gossip.py:GossipService.select_batch_to_send` (225-258) and
  `lattice/gossip.py:GossipService.receive_batch` (77-155, transient-card store at 136-141).
- Evidence:
  - sender: `batch = self._gossip.select_batch_to_send(exclude={node_id}, limit=16)` then
    `cards = [own_card] + batch.cards` then `body = json.dumps(payload, separators=(",", ":"), ...)`.
    `select_batch_to_send` breaks on `if len(cards) >= limit` — count only, never serialized size.
  - receiver: `receive_gossip` gates on `require_content_length(MAX_GOSSIP_BODY_BYTES)` (256 KiB) and
    nginx `client_max_body_size 256k`; both are byte limits.
  - intake stores the raw card with no size cap: `receive_batch` → `accept_candidate` →
    `self._cache.add_transient_card(node_id=..., card_json=json.dumps(card, ...), expires_at=model.expires_at)`.
    `PeerCard` bounds only `domain` (≤253); `endpoints.gossip`/`.messages` are `_validate_https_url`
    (prefix + no `@`, **no length cap**), and `PeerCard.signature` has no validator while
    `accept_candidate` never verifies the card signature at all.
  - failure handling: `_send_gossip_batch` treats any non-2xx as `self._circuit_record_failure(node_id)`.
    `CacheRepository.list_transient_cards` (`ORDER BY received_at`) has **no `expires_at` filter**;
    `prune_transient_cards` only deletes at `expires_at`, which the card sets (≤7 days).
- Trigger (who causes it, what must coincide): an unauthenticated peer POSTs
  `/lattice/v1/gossip` (invariant 3 public route) with a batch of ≤32 structurally-valid `PeerCard`
  objects whose endpoint URLs are large (no signature required — `accept_candidate` validates the model
  only). `accept_candidate` accepts them under the candidate caps (use `introduced_by=null` and
  distinct endpoint hostnames to avoid the per-introducer/per-prefix caps) and `receive_batch` stores
  each as a transient card. On every subsequent `_run_gossip_round` (60 s) `_send_gossip_batch`
  serializes `own_card` + up to 16 stored cards. With 16 stored ~16 KiB cards (262 144 B) plus
  `own_card` (~0.8–1.5 KiB), the body is deterministically > 262 144 B, so the receiver's nginx/API
  answers 413 and the sender records a circuit failure. Reproduce by sizing stored transient cards to
  exceed `262 144 − len(own_card_json)`.
- Frequency: DEMONSTRATED — after one intake the poison card(s) are echoed in every gossip round (60 s)
  to every guard and discovery target until their `expires_at` (attacker-set, up to
  `MAX_PEER_CARD_LIFETIME_SECONDS` = 7 days); fresh cards can be re-seeded. `list_transient_cards`
  orders oldest-first, so the earliest-seeded card is always included.
- Outcome: every outbound gossip send is rejected 413 → `_circuit_record_failure` per peer → after 3
  consecutive failures `_circuit_is_open` suppresses gossip to that peer; the failure count keeps
  climbing each round (delay 5 s·2^(n−3), capped 60 s), so gossip to all peers is degraded for the
  card lifetime. Peer-discovery/candidate propagation stalls network-wide; message delivery is
  unaffected (invariant 6 intact — only peer cards are relayed). This is the sender-count-bound vs
  receiver-byte-bound divergence: two sides of the same protocol constant that must agree, bounded on
  one side only.
- Reachability kind: **GATED** behind hunt-b1b#1 (`OutboundTransport.request()` `TypeError`): no
  outbound HTTP completes today, so the 413 is not observed live. Reported per the preamble so the
  b1b#1 repair does not ship the hidden sender bound.
- Confidence: mechanism traced (both the unbounded sender and the bounded receiver read line-by-line);
  the overflow is arithmetic, not assumed — 16×16 KiB stored cards exceed the constant before
  `own_card`; the exact number needed is tunable by the attacker. No unproven component in the
  mechanism; the only reachability caveat is the gate above.

2. [L] — Blocked-sender (and custody-error) "rejected" receipts are never persisted and are not
   byte-identical for duplicate `message_id`, violating PROTOCOL.md §8 MUST
- Location: `lattice/api.py:receive_message` blocked branch (293-300) and custody-error branch
  (338-345); receipt construction `lattice/messages.py:InboundMessageService.build_receipt`
  (294-316).
- Evidence: `receipt = runtime.inbound_service.build_receipt(str(message.get("message_id", "")), "rejected")`
  / `rejected = runtime.inbound_service.build_receipt(..., "rejected")` — the return value is handed
  straight to `JSONResponse`; there is no `repo.create`/store call on either branch (`rg -n
  "build_receipt"` shows only `messages.py:269` (accepted, persisted via `_repo.create(..., receipt=signed)`)
  and the two `api.py` rejected sites). `build_receipt` sets `received_at = when = self._clock.now()`
  (`_SystemClock.now` → `datetime.now(UTC)`, microseconds), and `sign_receipt` canonicalizes
  `Receipt.model_dump(mode="json")` including that microsecond timestamp.
- Trigger: a signature-verified message from a node in the local block store (`BlockedSenderError`
  path), or an inbound `accept` that raises `CustodyError`, is delivered; the same `message_id` is
  delivered again (in-tree sender retry — hunt-b1b#2 shows a `rejected` 202 is treated as retryable —
  or ordinary network-level duplicate delivery). Each call constructs a fresh receipt with a different
  `received_at` and therefore a different signature and different bytes; nothing is stored to replay.
- Frequency: DEMONSTRATED population, narrow: any blocked peer with pending traffic whose message is
  retransmitted, plus any duplicate delivery of a custody-error message. The in-tree sender retries up
  to 10 times, so duplicates are expected once that path is live.
- Outcome: PROTOCOL §8 states "The receipt bytes MUST be persisted and returned identically for
  duplicate `message_id` values." The rejected path returns non-identical bytes and keeps no durable
  rejection record, so a §8-compliant sender cannot recognize the duplicate as the same final
  rejection. (The accepted path correctly satisfies §5/§8 via `get_existing_receipt` + the UNIQUE-race
  fallback.)
- Reachability kind: **PRODUCTION**.
- Confidence: traced. Note overlap: the *absence of persistence* on the rejected path is noted inside
  hunt-b1c#4; the *non-identical-bytes / §8 MUST* framing is the distinct site here and is adjacent to
  hunt-h2#3 (which raises the same MUST for the accepted/collision path). Listed so the merge layer can
  dedupe deliberately.

## Checked and clean

- **verify → block → custody ordering** (`verify_inbound_message` → `receive_message`): `Message.model_validate`
  first; signature verified before `is_blocked` (so a signed `rejected` receipt is only ever issued for
  a signature-verified message, per §8); cold-sender return happens before signature/rate-limit but
  takes no custody (returns 503); recipient-ownership check and rate-limit both precede
  `inbound_service.accept`. Correct apart from the known canonical-`to_address` bypass (hunt-a1#2 /
  hunt-b1c#2) and the known malformed-address 500 (hunt-a1#4 / hunt-b1c#3), both excluded here.
- **Rate-limit arithmetic and restore** (`rate_limit.py`): `_bucket` dict access under `RateLimiter._lock`;
  per-bucket lock in `consume`/`state`; refill `min(capacity, tokens + elapsed*rate)` clamps; `consume`
  updates `_last_updated` on failure too (no double-credit); `snapshot` reads under per-bucket locks and
  does not mutate live buckets; `restore` rebuilds both kinds at the persisted epoch; `str(epoch)` /
  `float(...)` round-trip is lossless. The known sub-1.0-per-minute permanent lockout (hunt-b1c#5) and
  the unbounded `_buckets` map keyed by attacker-controlled `peer_id` (blind-hunt-a1#3) are excluded as
  known.
- **Webhook idempotency and retry classification** (`webhook.py`): key is a deterministic
  `sha256("lattice-webhook:" + message_id)[:32]` sent on every attempt; `WebhookStateRepository.upsert`
  keys on `message_id`, so the recorded key always equals the sent header; classification
  (2xx success, 429/5xx and network errors retryable, other 4xx terminal) is consistent between
  `deliver` and `classify_status`; the `except urllib3.exceptions.HTTPError` surface covers the URL and
  connection failure modes; `_run_webhook_delivery` uses the durable `received_at` row (not the
  sender-controlled timestamp) and signs the envelope with the operational key (no root key).
- **Webhook lease/claim** (`claim_for_webhook`/`release_webhook_lease`/`mark_terminal`): owner-checked
  CAS; expired leases re-claimable (crash recovery); attempt cap enforced through `RetryPolicy`
  (max 10); terminal erasure keeps the retained receipt for same-sender duplicates.
- **Gossip per-card failure isolation and count bounds**: a malformed card yields a rejected
  `ReceivedCard` with a reason and the loop continues; `cards[:MAX_GOSSIP_BATCH_SIZE]` plus the API 400
  close the count bound (the byte bound is Finding 1).
- **Cert/root lookup chain** (`_certificate_for_node`/`_domain_for_node`/`_root_identity_for_node`/
  `_known_root_key_for_node`/`_certificate_from_pin`): all key material comes from pinned stores or
  root history; a message-supplied key is never trusted; empty history keys fall through to the pin;
  `cert.verify` re-derives the node ID. `verify_gossip_sender_card` is self-consistent (derive node ID
  → cert.verify → `is_valid_at` → `verify_object`) and is used only as a rate key. (The known missing
  `is_valid_at` on the message path is hunt-e1#1, excluded.)
- **`_run_verify_candidates` / `_run_refresh_topology` / `_run_expiry_cleanup`**: candidate verify
  failures remove the candidate; resolution failures retain it (bounded by the 24 h candidate TTL);
  guards/discovery refresh and `prune` are driven on their configured cadences.

## Enumeration

Classes most directly implied by the neutral question, one composed command each.

```
rg -n "allow_gossip|allow_message|\.consume\(" lattice/
```
| site | disposition |
|---|---|
| `rate_limit.py:104` `allow_message` → `consume(1.0)` | examined-clean (key = authenticated `from_node_id`) |
| `rate_limit.py:108` `allow_gossip` → `consume(1.0)` | examined-clean arithmetic; key-spoofing is known (hunt-f1#1, blind-hunt-a1#2) |
| `api.py:335` message consume | examined-clean ordering (after ownership, before custody) |
| `api.py:265` gossip consume | examined-clean ordering (before `receive_batch`) |

```
rg -n "build_receipt|\"rejected\"|receipt=" lattice/
```
| site | disposition |
|---|---|
| `messages.py:269` accepted receipt → `receipt=signed` in `_repo.create` | examined-clean (persisted, replayed) |
| `api.py:296` blocked-sender rejected receipt | **Finding 2** (not persisted, non-identical) |
| `api.py:341` custody-error rejected receipt | **Finding 2** (same) |

```
rg -n "select_batch_to_send|_send_gossip_batch|cards = \[own_card\]|MAX_GOSSIP_BATCH_SIZE|MAX_GOSSIP_BODY_BYTES" lattice/
```
| site | disposition |
|---|---|
| `gossip.py:89` `cards[:MAX_GOSSIP_BATCH_SIZE]` | examined-clean (count cap) |
| `api.py:249` API 400 over 32 cards | examined-clean (count cap) |
| `api.py:238` `require_content_length(MAX_GOSSIP_BODY_BYTES)` | examined-clean inbound; **no outbound counterpart** — Finding 1 |
| `runtime.py:1102-1103` `select_batch_to_send(limit=16)` + `own_card` | **Finding 1** (count-only) |
| `gossip.py:225-258` `select_batch_to_send` | **Finding 1** (breaks on count, no byte bound) |

## Design risks (max 2)

1. Transient-card intake has no per-card byte cap and transient cards persist up to 7 days
   (`add_transient_card` stores the received JSON verbatim; `prune_transient_cards` deletes only at
   `expires_at`). The only pacing is the gossip rate limit, which is itself bypassable (spoofable
   first card / XFF — hunt-f1#1, blind-hunt-a1#2). Disk growth in the cache DB is the steady-state cost
   of the same missing size bound as Finding 1; a fix should cap card bytes at intake as well as batch
   bytes at send.
2. `accept_candidate` admits cards without verifying their signature or certificate (verification is
   deferred to the 60 s `verify_candidate` cycle). This is the documented relay-before-verify behavior,
   but it means unauthenticated content is stored and re-broadcast before any trust decision — the
   property Finding 1 exploits. Not separately reportable as a choice; recorded as the enabling
   condition.

## Side discoveries

- **Transient-card growth (same mechanism as Finding 1).** Priced L: a network peer can accumulate
  up to ~256 concurrent candidates (global cap) and up to ~256 KiB per stored card, with earlier cards
  persisting to their 7-day `expires_at`; steady-state cache-DB growth is (intake rate × 7 days). Fix
  constraint: a per-card size cap at intake, independent of the candidate count caps.

## Bound

- No live infrastructure: the daemon, a real peer, and real TLS were not run. Finding 1's 413 is traced
  from the receiver's `require_content_length` + the shipped nginx config, and is GATED behind the
  transport defect (hunt-b1b#1) that currently prevents any outbound HTTP, so it was not observed
  end-to-end.
- Nginx `256k` is assumed to mean 256×1024 = 262 144 (matching `MAX_GOSSIP_BODY_BYTES`); if an operator
  deploys a different `client_max_body_size`, the threshold moves but the defect does not.
- `RuntimeSettings` cadences used in the frequency argument are the in-tree defaults (60 s gossip, 60 s
  expiry cleanup); an operator may override them.
- The outbound transport file (`transport.py`) was read through prior reports only; my Finding 1 is
  independent of its internals (it concerns the body the caller builds).
