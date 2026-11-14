# Agent Guide for Lattice

This document is the primary entry point for AI agents working on Lattice. Read it first, then follow the scoped guides in `docs/AGENTS.md` and the complete normative documents it references.

## Project purpose

Lattice is a DNS-bootstrapped, key-anchored flat mesh for cross-server messaging. A human address such as `mikey@other.network` resolves to a canonical `user@lat_…` identity, and messages travel directly between nodes. Bootstrap nodes introduce peers but never relay traffic.

## Invariants (never violate without explicit operator decision)

1. **Immutable root identity.** The root Ed25519 key derives the node ID. Operational keys rotate; root keys do not.
2. **No root key in daemon.** The network-facing daemon loads only the active operational key and bearer credentials.
3. **Fixed public routes.** Public HTTP routes are constants: `GET /.well-known/lattice`, `POST /lattice/v1/gossip`, `POST /lattice/v1/messages`.
4. **Synchronous core.** Business logic, repositories, and HTTP clients are synchronous. Async is confined to framework lifecycle glue.
5. **Durable custody receipts.** A signed HTTP 202 means the destination node accepted durable custody, not human delivery.
6. **No message relay.** Gossip propagates peer cards only; messages travel sender-to-destination only.
7. **Nginx/systemd boundary.** Nginx owns TLS and generic edge limits; systemd owns supervision and encrypted credentials.
8. **No legacy compatibility.** Do not add adapters for the pre-release protocol, schemas, or database.

## File map

| Path | Responsibility |
|------|----------------|
| `docs/PROTOCOL.md` | Normative wire protocol, serialization, schemas, and route contracts. |
| `docs/THREAT_MODEL.md` | Threats, trust assumptions, Sybil controls, and non-goals. |
| `docs/ADDRESSING.md` | `user@domain` resolution, contact cards, pretty printing, and trust reset. |
| `docs/KEY_MANAGEMENT.md` | Root/operational key lifecycle, rotation, backup, and recovery. |
| `docs/MIGRATIONS.md` | Durable/cache migration policy and fixture discipline. |
| `docs/OPERATIONS.md` | systemd, Nginx, logs, monitoring, and upgrades. |
| `docs/INTEGRATION.md` | Webhook contract and application integration. |
| `docs/adr/` | Architecture decision records. |
| `lattice/canonical.py` | RFC 8785 JCS, strict JSON parsing, media-type normalization, and signature preimages. |
| `lattice/crypto.py` | Ed25519 key operations, certificate/statement signatures, and serialization formats. |
| `lattice/identity.py` | Node ID derivation, operational identity, rotation, and recovery bundles. |
| `lattice/protocol/` | Protocol constants, models, signed-object kinds, and validation. |
| `lattice/storage/` | SQLite connection, repositories, migrations, and cache lifecycle. |
| `lattice/config.py` | `config.toml` schema and validation. |
| `lattice/credentials.py` | Encrypted credential loading and systemd-creds helpers. |
| `lattice/cli.py` | Operator commands: init, config check, upgrade, status, identity, keys, trust, peer. |
| `lattice/addressing.py` | Address parsing and canonical form. |
| `lattice/resolution.py` | Well-known resolution, durable pins, and transfer/reset handling. |
| `lattice/network_policy.py` | Public/private mode, CIDR/CA policy, and SSRF-safe outbound transport. |
| `lattice/transport.py` | Pooled synchronous HTTPS client with resolved-address validation. |
| `lattice/peers.py` | Peer records, root history, and state transitions. |
| `lattice/gossip.py` | Peer-card gossip receive/send and batch bounds. |
| `lattice/topology.py` | Candidate, verified, established, guards, rotating discovery, and quotas. |
| `lattice/messages.py` | Message models, serialization, and semantic validation. |
| `lattice/queue.py` | Outbound priority queue, claims, retry, expiry, and erasure. |
| `lattice/webhook.py` | Inbound custody, signed receipts, webhook delivery, and idempotency. |
| `lattice/rate_limit.py` | Authenticated per-peer token buckets. |
| `lattice/app.py` | App factory with no import-time I/O. |
| `lattice/api_public.py` | Public routes (well-known, gossip, messages). |
| `lattice/api_local.py` | Loopback-only routes (send, liveness, readiness). |
| `lattice/runtime.py` | Bounded executors, coordinator thread, and lifecycle. |
| `lattice/client.py` | Synchronous Python client matching server routes. |
| `tests/vectors/` | Language-neutral canonicalization and signature vectors. |
| `tests/fixtures/schema_versions/` | Durable schema fixtures for every released version. |
| `tests/e2e/` | Two-node TLS/Nginx/systemd integration tests. |

## Mandatory checks before changing code

- Run `ruff check .` and `ruff format --check .`.
- Run `mypy --strict lattice tests`.
- Run `pytest -q`.
- If you touched canonicalization or signatures, run the vector tests.
- If you touched the schema, update fixtures in `tests/fixtures/schema_versions/` and verify migration from every fixture.
- If you changed routes or config, update `docs/PROTOCOL.md`, `docs/OPERATIONS.md`, and the Nginx/systemd files.

## Task routing

- **Protocol change** → Read `docs/PROTOCOL.md` fully, then `lattice/canonical.py`, `lattice/protocol/`, and `tests/vectors/`.
- **Crypto/identity change** → Read `docs/PROTOCOL.md` §Identity and §Signatures, then `lattice/crypto.py`, `lattice/identity.py`, and `tests/test_vectors.py`.
- **Storage change** → Read `docs/MIGRATIONS.md`, then `lattice/storage/`, and add a fixture test.
- **Config/credential/CLI change** → Read `docs/OPERATIONS.md` §Configuration and `docs/KEY_MANAGEMENT.md`, then `lattice/config.py`, `lattice/credentials.py`, `lattice/cli.py`.
- **Resolution/addressing change** → Read `docs/ADDRESSING.md`, then `lattice/addressing.py`, `lattice/resolution.py`, `lattice/network_policy.py`.
- **Gossip/topology change** → Read `docs/THREAT_MODEL.md` §Sybil, then `lattice/gossip.py`, `lattice/topology.py`, `lattice/peers.py`.
- **Queue/webhook change** → Read `docs/INTEGRATION.md`, then `lattice/queue.py`, `lattice/webhook.py`.
- **API/runtime change** → Read `docs/PROTOCOL.md` §Routes, then `lattice/app.py`, `lattice/api_public.py`, `lattice/api_local.py`, `lattice/runtime.py`.
- **Deployment change** → Read `docs/OPERATIONS.md`, then `deploy/lattice.service` and `deploy/nginx-lattice.conf`.

## Communication rule

When asked to make a change, first restate the invariants that apply, then explain which documents and source files you read, then propose the smallest consistent change before editing.

## TODO (operator)

- **TODO: wholesale rewrite of this file and `docs/AGENTS.md` is pending.** The file map below is partially aspirational (references `lattice/app.py`, `api_public.py`, `api_local.py`, `queue.py`, `client.py`, `docs/OPERATIONS.md`, `docs/INTEGRATION.md`, `docs/adr/`, `tests/e2e/`, `tests/fixtures/schema_versions/`, none of which exist). To be reconciled with the actual tree by the operator after the current round of work is done.
