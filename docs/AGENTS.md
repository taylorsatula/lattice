# Documentation Guide for Agents

The Lattice documentation is layered. This file tells agents which complete documents to read for each area. Do not rely on summaries alone.

## Documents and their scope

| Document | Scope | Read when changing |
|----------|-------|-------------------|
| `PROTOCOL.md` | Wire protocol, serialization, schemas, routes, error format, version policy, and canonicalization. | Any protocol, schema, route, or signature behavior. |
| `THREAT_MODEL.md` | Threats, trust assumptions, attacker models, Sybil controls, key compromise, and non-goals. | Gossip, topology, identity, key management, or network policy. |
| `ADDRESSING.md` | Human and canonical addressing, contact cards, trust reset, pretty printing, and UI guidance. | Addressing, resolution, contact export/import, or user-facing displays. |
| `KEY_MANAGEMENT.md` | Root and operational key lifecycle, rotation, backup, recovery, and systemd credential mapping. | Keys, credentials, CLI identity commands, or rotation. |
| `MIGRATIONS.md` | Durable and cache migration policy, fixture discipline, and upgrade failure behavior. | Any SQL schema or storage repository. |
| `OPERATIONS.md` | systemd, Nginx, config.toml, logs, monitoring, readiness, and upgrades. | Deployment, service files, config, or operational commands. |
| `INTEGRATION.md` | Loopback webhook contract, `Idempotency-Key`, retry classification, and application responsibilities. | Webhook, inbound custody, queue, or message delivery. |
| `adr/` | Architecture decisions and their rationale. | Before proposing architectural changes. |

## Cross-cutting rules

- Every document is normative for its area. If code and a document disagree, fix the code or update the document; never leave them inconsistent.
- Examples in documentation are tested or marked explicitly as illustrative only.
- Agent guides (`AGENTS.md` files) may summarize and route, but the documents above contain the actual contracts.
- When adding a new document, register it in this file and the root `AGENTS.md` file map.
