# Lattice v1 architecture

Lattice is a DNS-bootstrapped, key-anchored flat mesh for cross-server messaging. Humans address each other as `user@domain`. The canonical identity is an immutable Ed25519-root-derived `lat_…` node ID. DNS locates a node, but a pinned public key prevents silent domain takeover.

## Design forces

- **End-to-end correctness:** install, initialize, identify, discover, deliver, retry, monitor, and document one coherent system.
- **Human usability without a central authority:** preserve `user@domain` without a Lattice naming registry.
- **Cryptographic continuity:** identity survives operational rotation and rejects silent domain takeover.
- **Flat-mesh resilience:** direct peer communication with bounded permissionless Sybil influence.
- **Sync simplicity:** synchronous business logic; bounded thread execution; no async propagation through protocol code.
- **Durable custody:** transactional ownership, crash safety, idempotency, expiry, and content erasure.
- **Standard infrastructure:** Nginx handles generic edge concerns; systemd handles supervision and encrypted credentials.
- **Long-term evolution:** canonicalization, explicit versions, cumulative migrations, and language-neutral vectors.

## Identity

- Root and operational keys are Ed25519.
- Node ID: `lat_` + base32(SHA-256("lattice-node-id-v1\0" || raw-root-public-key)).
- The root private key never loads into the network-facing daemon.
- Root signs operational certificates; operational keys sign messages, receipts, peer cards, and blocks.
- Operational rotation is signed by root, old operational key, and new operational key, with an overlap period.

## Addressing and discovery

- Local API accepts `user@domain` and canonical `user@lat_<id>`.
- New domains resolve only through `https://domain/.well-known/lattice`.
- Resolution verifies TLS, domain binding, root signature, node-ID derivation, operational certificate, document signature, media type, and endpoint policy before pinning.
- Gossip aliases are hints only; gossip cannot establish or replace a domain pin.

## Wire protocol

- RFC 8785 JSON Canonicalization Scheme (JCS) and strict I-JSON-compatible parsing.
- Media type: `application/vnd.lattice+json; version=1`.
- Signatures bind normalized media type and object kind into a domain-separated preimage.
- Fixed public routes:
  - `GET /.well-known/lattice`
  - `POST /lattice/v1/gossip`
  - `POST /lattice/v1/messages`
- Errors use RFC 9457 Problem Details.

## Messages and custody

- UTF-8 text content, maximum 64 KiB encoded bytes.
- One optional extension, maximum 16 KiB encoded JSON.
- Priorities: `normal`, `high`, `urgent`; global priority queue, FIFO within level.
- Default TTL 24 hours, maximum 7 days.
- Signed HTTP 202 receipt means durable custody accepted, not human delivery.
- Outbound/inbound custody uses atomic leases, bounded exponential backoff, jitter, and circuit-open deferral.
- Terminal states erase content; minimal audit metadata is retained.

## Gossip and topology

- Peer lifecycle: `candidate` → `verified` → `established` (7 days maturity) → `blocked`.
- Established peers occupy stable guard slots and receive full introduction budgets.
- Candidates are bounded globally, per-introducer, and per-prefix; they expire quickly.
- Receiver independently fetches well-known before verification.
- Bootstrap and neighbor nodes introduce cards only; messages always travel directly.

## Runtime

- Synchronous services, repositories, HTTP clients, and FastAPI handlers.
- Async is confined to framework lifecycle glue.
- One Uvicorn process/worker bound to loopback.
- Bounded delivery and maintenance executors; request handling cannot be starved by slow federation calls.
- Internal coordinator schedules recurring work with monotonic timing, non-overlap locks, heartbeats, and graceful stop.
- In-memory authenticated per-peer token buckets for messages and gossip.

## Persistence

- **Durable DB** (`/var/lib/lattice/lattice.durable.db`): pins, root/operational history, verified/established peers, guards, blocks, custody, receipts, webhook state, and audit metadata.
- **Cache DB** (`/var/cache/lattice/lattice.cache.db`): candidates, transient cards, DNS cache, replay windows, token buckets, and circuit observations. Recreated on schema mismatch.
- Native SQLite, WAL, foreign keys, busy timeout, cumulative numbered durable migrations.

## Deployment

- Linux + systemd 250+ + Nginx.
- `/etc/lattice/config.toml` is the only non-secret configuration source.
- Encrypted credentials via `LoadCredentialEncrypted=`.
- Nginx exposes only the three exact public routes and owns TLS, method allowlists, raw body/header limits, connection/read deadlines, and IP rate limits.
- Health: loopback-only cheap liveness and strict readiness.
- Observability: structured key/value event codes to journald, no message content.

## Documentation model

- Agent guidance is primary: `AGENTS.md` files give architecture, invariants, file maps, and task routing.
- Normative protocol and threat-model documents remain exact and human-readable.
- A dedicated addressing/pretty-print guide explains `user@domain` parsing, resolution, persistent contacts, fingerprints, and trust reset.
