# Loose Ends and Known Issues

This file tracks non-blocking loose ends, bugs, and follow-up items discovered during implementation. Items are handled in a single cleanup pass at the end unless they block progress.

## Resolved

Items addressed in the design-decision pass (post review-fix pass):

- [x] **Rejected receipts reachable** — signature-verified messages from blocked senders and custody-insert failures now return HTTP 202 with a signed `rejected` receipt (PROTOCOL.md §8); routing errors (403) and pre-signature failures (401) remain Problem Details. `InboundMessageService.build_receipt` and `BlockedSenderError` added; signature verification now precedes the block check.
- [x] **Rotation statements produced** — `keys rotate-operational` writes a three-signed `rotation.json` (root + old op + new op, all over the same bare object) and refuses to rotate when the old staging key is missing. `identity.verify_rotation` verifies per vector semantics.
- [x] **Transfer statements implemented** — `keys create-transfer` (old root), `keys co-sign-transfer` (new root), and `trust accept-transfer` (verifies both signatures against the pinned old root key and the live well-known document, then rewrites the pin). `identity.verify_transfer` added.
- [x] **Real IP-prefix diversity** — `OutboundTransport` returns a `FederationResponse` carrying the policy-validated `resolved_ip`; `WellKnownResolver.resolve_with_ip` surfaces it; `TopologyService.prefix_from_ip` groups by /24 (IPv4) or /48 (IPv6); `peers.observed_prefix` stores it and discovery-slot selection prefers it. Candidate intake still groups by hostname (no network traffic before cap enforcement).
- [x] **Blocks without root-history rows** — schema now has no FK on `blocks.node_id`; `TopologyService.block` blocks arbitrary unseen node IDs.
- [x] **Identity-keyed gossip rate limits** — the first card of a gossip batch, when it verifies as the sender's own peer card, keys the gossip rate bucket by node ID; unauthenticated traffic falls back to client IP (PROTOCOL.md §5.2 updated).
- [x] **Contact cards implemented** — signed `contact_card` kind (PROTOCOL.md §4.4), durable `contacts` table, and `lattice contacts export/import/list`. Import fails closed unless the contact's node is pinned and the certificate chain verifies.

Items addressed in the review-fix pass:

- [x] **Outbound custody receipt validation** — `_send_outbound_message()` now validates the signed JSON receipt body (checks message_id, node_id, status == "accepted") before transferring custody. Invalid receipts trigger retry + audit failure.
- [x] **Recipient ownership enforcement** — `receive_message()` rejects messages whose `to_address` domain does not match any configured own_domain (returns 403 Problem Detail). Guard against accepting mail for other nodes.
- [x] **Gossip protocol alignment** — API now accepts `{cards: [...], introduced_by: ...}` object per PROTOCOL.md §5.2, returns `200 OK` with `{accepted: N, rejected: M, errors: [...]}` instead of bare list / 202.
- [x] **RequestValidationError handler** — explicit FastAPI exception handler converts Pydantic validation errors into RFC 9457 Problem Details alongside the existing HTTPException handler.
- [x] **Zero-token restore simplification** — snapshot initializes absent buckets to full capacity; restore always uses persisted value directly (no > 0 check).
- [x] **Broad Exception handler replaced** — two specific handlers: HTTPException + RequestValidationError; unexpected errors use framework defaults.
- [x] **Bootstrap conflict suppression explicit** — get_peer() check then create or transition explicitly; root/domain conflicts fail visibly rather than being swallowed by contextlib.suppress.
- [x] **Unused circuit_open_until removed** — state derived entirely from consecutive_failures + last_failure_at; column dropped from cache schema and SQL.
- [x] **Cold-sender → 503 Service Unavailable** — no receiver-side staging table (migration 002 deleted); queue domain for background pin and return retryable response. Sender retains outbound queue.
- [x] **Full content erasure** — both `content` and `message_json` columns cleared on terminal transitions
- [x] **Discovery table FK removed** — cross-database FOREIGN KEY constraint dropped
- [x] **Problem Details RFC 9457 compliance** — correct URI form (`https://lattice.dev/errors/LATTICE_CODE`), media type `application/problem+json`, stable machine-readable `code` field
- [x] **Durable pin root key fixed** — stores `root_public_key` not operational public key
- [x] **Circuit-breaker threshold enforced** — opens only after N consecutive failures
- [x] **Audit wiring completed** — `_audit_outbound_failed()` called on delivery failures
- [x] **Rate-limit snapshot timing** — persisted AFTER executors drain; absent buckets initialized at full capacity
- [x] **Webhook envelope received_at** — uses locally recorded time, not sender-controlled timestamp
- [x] **Bootstrap resolve de-duplication** — single network call; peer creation uses explicit exists-check
- [x] **Duplicate logger line removed**
- [x] **ruff format applied** — all files consistently formatted
- [x] **Migration 002 deleted** — inbound_staging table no longer used

## Previously resolved (prior cleanup)

- Stable Problem Detail type constants (initial attempt — later corrected for RFC 9457)
- Rate-limit bucket persistence (later hardened)
- Audit log gating by Python logging level
- Content erasure parameterization via `erase_content_value`
- Webhook signed envelope
- Circuit-breaker per-peer backoff
- Well-known graceful-restart guidance
- Bootstrap peer establishment on pin
- Dedicated `discovery_set` cache table

## Phase 1

- None.

## Phase 2

- None. Legacy tests were deleted in Phase 10 and FastAPI's default strict JSON parsing is used for public federation endpoints.

## Phase 6

- Resolved: prefix diversity now uses real /24 (IPv4) and /48 (IPv6) prefixes recorded at verification time; blocks work for arbitrary unseen node IDs (no FK on `blocks.node_id`). Candidate intake still groups by hostname because no network traffic is spent before cap enforcement.

## Phase 7

- Webhook envelope signature can be verified by downstream receivers via `lattice.protocol.signing.verify_webhook_envelope` against the operational certificate advertised in the domain's well-known document.

## Phase 8

- `_LockedConnection` serializes all SQLite operations on a single connection shared by the request thread pool and background executors. This is correct for v1 but may become a throughput bottleneck; a future pass can introduce a small connection pool or thread-local connections.
- Gossip rate limiting is identity-keyed when the sender's own card verifies (PROTOCOL.md §5.2); IP keying remains only as the unauthenticated fallback.
- Cold senders receive 503 Service Unavailable and are asked to retry later via Retry-After header. The sender's outbound queue retains custody until well-known resolution pins the domain.

## Phase 9

- `systemd-analyze verify` and `nginx -t` were not executed on Debian 12, Ubuntu 24.04, or RHEL-family 9 because development is on macOS. These must be verified on target distributions.
- The Nginx configuration does not include rate-limiting zones or fail2ban integration; it relies on Lattice's authenticated per-peer quotas for abuse control.
- Webhook delivery uses a shared `urllib3.PoolManager` without mTLS or a webhook-specific CA bundle. Production operators may need client-certificate authentication for the loopback webhook.
- No automated install script or packaging (deb/rpm) is provided; operators currently follow the manual steps in `docs/LATTICE_SYSTEMD.md`.
- Log rotation and journald retention policies are left to standard Linux configuration.

## Phase 10

- None. Legacy modules, tests, and artifacts were deleted; `README.md` and `docs/ARCHITECTURE.md` were rewritten.

## Phase 11

- CI workflows are configured but not executed on GitHub Actions in this session. The release workflow requires configuring the `release` environment and trusted publishing in PyPI before it will work.
- The two-node mesh integration test uses an in-memory fake transport rather than real TLS, Nginx, and DNS. A full end-to-end test on real Linux hosts with systemd and Nginx is still needed.
- Linux systemd deployment smoke tests (actual `systemctl start`, service hardening verification, and journald output checks) are not automated here.
- Dependency vulnerability scanning in CI uses `pip-audit` and `bandit` via `uvx`; configuration of fail-on-severity thresholds and suppression files is left to operators.
- Production constraint export (`uv export --frozen`) is not yet part of the CI/release workflows; consider adding it as a build step and attaching the resulting `constraints.txt` to each GitHub Release.
