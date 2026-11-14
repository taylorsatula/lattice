# seam-s3 — storage ↔ runtime contract (blind hunter)

Assigned files read end to end: `lattice/storage/repositories.py`, `lattice/runtime.py`.
Callees read for trigger tracing: `lattice/messages.py`, `lattice/peers.py`, `lattice/rate_limit.py`,
`lattice/storage/connection.py`, `lattice/storage/cache.py`, `lattice/storage/migrations.py`,
`lattice/migrations/cache_schema.sql`, `lattice/migrations/durable/001_initial.sql`,
`lattice/resolution.py`, `lattice/topology.py`, `lattice/gossip.py`, `lattice/webhook.py`,
`lattice/transport.py`, `lattice/api.py` (message/gossip/admin routes), `lattice/cli.py` (serve path).

Neutral question: can a claim be observed-but-lost, or a read return a shape the caller mis-handles?
Answer: the shape contract holds at every call site I traced; the defects found are in transaction
visibility/durability, not shapes. One observed-but-lost mechanism exists but needs a coincidence
race (finding 4).

## Findings

1. [L] — Circuit-breaker writes bypass repository transaction boundary and are never committed
- Location: lattice/runtime.py:_circuit_record_failure, _circuit_record_success (reads in _circuit_is_open)
- Evidence: `self._cache_repo.conn.execute("INSERT INTO circuit_observations ... ON CONFLICT(node_id) DO UPDATE ...")` — raw `conn.execute` with no `with self._conn:` / commit, unlike every method in repositories.py.
- Trigger: any outbound delivery or gossip round that fails against a peer (TransportError, HTTP 429/5xx, invalid custody receipt, endpoint unknown) executes this INSERT/UPDATE from a delivery/maintenance executor thread. sqlite3 default `isolation_level=""` opens an implicit transaction that only a later `with conn:` commit on the same shared cache connection closes.
- Frequency: DEMONSTRATED — every failing peer interaction in normal operation (peer downtime is routine); the write path runs on each one. Verified with an isolated sqlite3 experiment (Python 3.12): raw DML leaves `in_transaction == True` until an unrelated `with conn:` block commits.
- Outcome: circuit-breaker state is not durably persisted by its own write. It is committed only incidentally when some other cache repository method (gossip candidate/transient-card writes, prune, rate-bucket save at stop) next commits on the shared connection; on crash, or on graceful stop when no rate-bucket rows exist (no rate-limited peers → `_persist_rate_limits` performs no commit), the pending writes are rolled back on close. In-process behavior stays correct (same-connection reads see uncommitted rows), so the cost is non-durable breaker state (backoff counters reset) and transaction lifetime dictated by unrelated code.
- Confidence: mechanism traced (verified experimentally); trigger traced (live code path); frequency traced. REACHABILITY: PRODUCTION.

2. [L] — Expiry cleanup terminal-expires a leased message an in-flight worker then delivers
- Location: lattice/storage/repositories.py:OutboundMessageRepository.expire_messages (consumed by lattice/runtime.py:_run_expiry_cleanup → self._outbound.expire())
- Evidence: `WHERE status IN ('pending', 'leased') AND expires_at <= ?` — matches rows currently leased by a delivering worker; `claim_pending` only requires `expires_at > ?` at claim time with no margin.
- Trigger: a message whose retry backoff (`next_attempt_at`) lands within seconds of its TTL `expires_at` is claimed by `_run_outbound_delivery`; while the worker is mid-HTTP (up to ~40s read timeout), the 60s expiry task fires after `expires_at` passes and flips the row to `expired` + erases content; the worker's subsequent `record_success` → `mark_terminal` (requires `status = 'leased'`) matches nothing and its False return is ignored by runtime.
- Frequency: LATENT — requires a claim in the final seconds of TTL coinciding with the expiry tick; I cannot ground a cadence for messages whose next attempt lands that close to expiry. Per calibration this is capped as latent.
- Outcome: durable custody row says `expired` (content erased as expired) for a message that was in fact delivered and acknowledged; the audit log records OUTBOUND_DELIVERED, so audit and durable state diverge. No re-delivery or data loss (the row is terminal either way and the destination dedupes by message_id).
- Confidence: mechanism traced; trigger traced but narrow; frequency unproven (latent). REACHABILITY: PRODUCTION (narrow coincidence).

3. [L] — claim re-select returns rows from any same-owner claim with the same lease expiry
- Location: lattice/storage/repositories.py:OutboundMessageRepository.claim_pending (same pattern in InboundMessageRepository.claim_for_webhook)
- Evidence: rows are returned by `SELECT * FROM outbound_messages WHERE lease_owner = ? AND lease_expires_at = ?` — a re-query by (owner, computed-expiry-string), not a return of the rows the UPDATE just claimed.
- Trigger: two claims by the same owner whose `_clock.now()` truncates to the same second produce identical `lease_expires_at` strings; the second claim's re-select then returns the first claim's still-leased rows too (beyond `limit`), so those messages are processed by two workers concurrently.
- Frequency: in production the scheduler tick is 1.0s and per-task non-overlap locks plus ≥10s intervals make two same-owner claims land ≥1s apart (different truncated seconds) — unreachable. It is reachable through the test suite, where injected clocks freeze or repeat the same `now` across two `claim_for_delivery` calls.
- Outcome: double-processing/delivery and double-incremented attempt counts inside tests; a test asserting claim exclusivity can observe another worker's rows. Fix-shaped as RETURNING or claimed-id capture. Not reachable by any live path today.
- Confidence: mechanism traced; trigger TESTS ONLY; a live-path trigger does not exist in tree (marking this explicitly, per reachability-kind rule).

4. [S-] — Shared durable connection: a failing repository call rolls back another thread's in-flight claim (claim observed-but-lost)
- Location: lattice/storage/connection.py:_LockedConnection + repositories.py `with self._conn:` blocks; victim: OutboundMessageRepository.claim_pending UPDATE→SELECT window
- Evidence: all durable repositories share one connection (cli.py serve constructs a single `durable_conn`); `with conn:` `__exit__` on exception calls connection-wide `rollback()`, discarding *all* uncommitted writes on that connection, including another thread's just-executed claim UPDATE.
- Trigger: a repository `with` block raising (e.g. `InboundMessageRepository.create` UNIQUE violation on a concurrent duplicate accept, `OutboundMessageRepository.create` on duplicate admin submit) must coincide, at millisecond granularity, with a delivery worker sitting between claim_pending's UPDATE and its SELECT/commit; if the SELECT ran before the rollback, the worker returns rows it no longer owns.
- Frequency: requires a coincidence race between an exceptional repo call and another thread's claim commit window; the exceptional calls themselves are rare (concurrent duplicate accept of the same message_id).
- Outcome: the "claimed" rows are actually still pending; the worker delivers them, its `mark_terminal`/`release_lease` owner guards then match nothing (silently ignored), and the message is re-claimed and re-delivered by another worker. Destination-side (message_id, from_node) dedup bounds the harm to a duplicate HTTP send.
- Confidence: mechanism traced (rollback is connection-wide — this is the direct answer to "can a claim be observed-but-lost"); trigger unproven beyond construction; needs one more pass before promotion or kill.

## Checked and clean

- **Claim/lease guard predicates** (outbound + inbound): `release_lease`/`release_webhook_lease` and `mark_terminal` are guarded by `lease_owner = ?` (plus status); a foreign or expired-lease worker cannot release or terminal another owner's row. Expired-lease takeover in the claim subselect is deliberate and consistent with at-least-once redelivery, which the destination dedupes via `get_existing_receipt`.
- **Repository return shapes vs runtime callers**: `DomainPinRepository.get`/`get_by_node_id` return `operational_certificate` and `endpoints` as parsed dicts — matching `_certificate_from_pin` (`OperationalCertificate.from_dict`) and `peer_endpoint_for_node` (`.get("messages")`). `PeerRepository.get_peer` returns raw rows; every runtime caller goes through `PeerStore`, whose `Peer.from_row` parses the endpoints JSON and timestamps. `message_json` arrives as TEXT and both `_run_outbound_delivery` and `_run_webhook_delivery` re-parse with a terminal `record_*_failure(retryable=False)` fallback. `get_root_history`/pin `root_public_key` are shape-checked (`isinstance(str)`/truthy) before use, so the `""` placeholder keys that `ensure_root_history` can write are never treated as real keys.
- **Custody write / 202 semantics**: `InboundMessageService.accept` returns only after `create`'s `with conn:` commits, so HTTP 202 is returned only after durable custody exists; duplicate accepts short-circuit on `get_existing_receipt` and return the stored byte-identical receipt; the UNIQUE-race branch re-reads the receipt. FK ordering is satisfied everywhere (`ensure_root_history` precedes peers/messages/operational-key inserts).
- **Rate-bucket save/load**: `snapshot()` 4-tuples `(node_id, msg_tok, gos_tok, wall-epoch)` round-trip through `save_rate_bucket` (`str(epoch)` into TEXT) and `load_rate_buckets` (`float(row[...])`) into `RateLimiter.restore` with correct positional order; `TokenBucket.consume` clamps to capacity on first use, so config changes cannot leave over-capacity buckets for more than one consume.
- **Clock/epoch coherence**: buckets use wall clock end-to-end (docstring intent); downtime refill on restore is intended.
- **Ordering**: `claim_pending`'s priority CASE + created_at ordering works lexicographically on the `%Y-%m-%dT%H:%M:%SZ` format; `claim_pending`'s `expires_at > now` filter prevents claiming expired messages.
- **Transaction-per-workflow**: every mutating repository method wraps its statements in `with self._conn:` (commit on exit); the only writers bypassing this are the runtime circuit-breaker accesses (finding 1).
- **`_restore_rate_limits`/`_persist_rate_limits`**: both exception-guarded; persistence ordered after executor drain in `stop()`.
- **Topology/gossip storage calls**: candidate caps count queries, transient-card round-trip (TEXT card_json re-parsed), discovery-set expiry filters, and `record_observation`'s ON CONFLICT rowcount contract all match their callers.

## Enumeration

Composed command (runtime → storage-facing call sites):

```
rg -n "self\.(_outbound|_inbound|_cache_repo|_peer_repo|_pin_repo|_peer_store|_block_store|_webhook_repo|_audit_repo|_rate_limiter|_topology|_gossip|_resolver)\.[a-z_]+\(" lattice/runtime.py
```

Instance table (runtime call site → repository method → assumed return/visibility → actual):

| runtime:line | repo method | assumed | actual | disposition |
|---|---|---|---|---|
| 405 load_rate_buckets | CacheRepository.load_rate_buckets | list of (id, msg, gos, epoch) | matches; epoch str→float | clean |
| 425 get_peer_by_domain | PeerStore→raw SQL on peers | Peer or None | Peer from first matching row | clean |
| 437/723/699 ensure/get_root_history | PeerRepository | row dict or None; str key | matches; may be "" placeholder | clean (truthiness-guarded) |
| 451 pin upsert / 642,668,674,706 get_pin / 688,728,746 get_by_node_id | DomainPinRepository | parsed cert/endpoints dicts | matches | clean |
| 500-502 snapshot→save_rate_bucket | CacheRepository.save_rate_bucket | per-row upsert commit | matches | clean |
| 760 list_pending | OutboundMessageRepository.list_pending | pending rows incl. not-yet-due | matches (intended for backpressure) | clean |
| 924 claim_for_delivery | claim_pending | exactly the rows just claimed | re-query by (owner, expiry) | finding 3 |
| 931/935/939/967/993/1005/1013 record_failure | release_lease / mark_terminal | owner-guarded release/terminal | matches; False returns ignored by runtime | clean (bounded, at-least-once) |
| 1001 record_success | mark_terminal | terminal + erase | matches | finding 2 interaction |
| 1023 claim_for_webhook | claim_for_webhook | exactly rows just claimed | same re-query pattern | finding 3 (same mechanism) |
| 1060/1066/1030 webhook record_* | mark_terminal / release_webhook_lease | owner-guarded | matches | clean |
| 1135 expire() | expire_messages | terminal-expire pending+leased past TTL | matches — includes rows leased in-flight | finding 2 |
| circuit_is_open/record_* (runtime 779-850) | raw conn.execute on cache | durable breaker state | uncommitted until unrelated commit | finding 1 |
| 1119 record_observation | PeerRepository.record_observation | True iff new day row | rowcount==1 under ON CONFLICT DO NOTHING | clean |
| 913 resolver.pin / 428 resolver.resolve | DomainPinRepository.upsert / transport | validated doc dict | matches | clean |

## Design risks (max 2)

1. Durable audit records are gated on Python log level (`_write_audit_entry` checks `logger.isEnabledFor`). An operator raising the log level to WARNING silently stops durable audit rows (INBOUND_ACCEPTED, OUTBOUND_DELIVERED, …) — audit durability is coupled to log verbosity, not to an audit-on/off control.
2. All durable repositories share a single connection, so "transaction-per-workflow" is really "transaction-per-connection": concurrent repository calls interleave into one another's transactions and any exception rolls back peers (finding 4 is the concrete instance; a connection-per-repository or serialized writer would close the class).

## Side discoveries (single-pass candidates, not confirmed work)

- **Cold-sender path (runtime.py:646, 895-913; api.py:307)**: unauthenticated `POST /lattice/v1/messages` with an unpinned from-domain returns 503 *before* the rate limiter runs, and seeds `_unresolved_domains`, which is unbounded and never pruned on failure — every 30s the daemon re-attempts an HTTPS well-known fetch for every distinct attacker-supplied domain, indefinitely. Enforcement-gap-shaped; likely belongs to the public-route/runtime seam pass.
- **Rejected-receipt handling (runtime.py:_send_outbound_message)**: a signed final `rejected` receipt (blocked-sender path) fails the `status != "accepted"` check and is treated as a *retryable* "invalid custody receipt" — the node keeps re-sending a message the destination permanently rejected (up to 10 attempts / 24h max delay), contrary to PROTOCOL §8 "sender stops retrying". The receipt signature is also never verified on this path.
- **api.py CustodyError → 202 rejected**: `accept()` wrapping a transient sqlite3.OperationalError (disk full, I/O error) becomes a final signed rejection — a transient storage failure permanently kills the sender's message under §8 semantics.
- **gossip.py select_batch_to_send**: `row.get("introduced_by")` on transient_cards rows — that table has no `introduced_by` column, so `attributed_to` is always None (unconsumed by runtime today).

## Bound

- No live infrastructure: the daemon was not run against a real peer or database; DB behavior verified via an isolated in-memory sqlite3 experiment (autocommit/rollback semantics, Python 3.12.11) rather than the live WAL files.
- `lattice/api.py` and `lattice/cli.py` were read only around the trigger paths for the assigned seams (routes, serve wiring); they were not audited end-to-end and are not my assignment.
- `tests/` was not executed; finding 3's TESTS-ONLY reachability is derived from repository semantics and the injected-clock design, not from a failing test run.
- The enumeration pattern covers `self._<service>.method(` call sites in runtime.py; calls reaching storage only through `TopologyService`/`GossipService` internals (e.g. candidate caps inside `can_accept_candidate`) were traced by reading those files, not by the rg pattern.
