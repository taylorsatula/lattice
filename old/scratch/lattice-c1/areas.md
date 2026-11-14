# Area decomposition — lattice-c1 (first census)

Source: `wc -l lattice/**/*.py` = 7,744 LOC; tests 4,137 LOC. Entire tree uncommitted
(last commit 2026-07-30, `chore: remove version-controlled build artifacts`). No prior kata run
ticket → **first census, no anchor, full map build**.

## Facet taxonomy (Phase 2 minimum facets → this repo's mechanisms)

| # | Facet | Mechanism | Instrument | Files / instances |
|---|---|---|---|---|
| A1 | Entry surfaces — HTTP | FastAPI route wiring, exception→Problem Details, auth dependency, peer-IP derivation | area | `lattice/api.py` |
| A2 | Entry surfaces — CLI | operator commands, arg parsing, credential handling, exit codes | area | `lattice/cli.py` |
| B1 | Orchestration core | RuntimeCoordinator lifecycle, executors, scheduler, coordinator thread, claim loop | area | `lattice/runtime.py` |
| C1 | Persistence — durable | SQLite connections, repositories, transactions, dual-write, migrations | area | `lattice/storage/repositories.py`, `connection.py`, `migrations.py`, `lattice/migrations/**` |
| C2 | Persistence — cache | cache schema lifecycle, expiry, snapshot/restore | area | `lattice/storage/cache.py` |
| D1 | External boundary — transport | SSRF-safe outbound, resolved-IP validation, pooling | area | `lattice/transport.py`, `lattice/network_policy.py` |
| D2 | External boundary — credentials | systemd-creds loading, encrypted credential files | area | `lattice/credentials.py`, `lattice/config.py` |
| E1 | Identity / crypto | root vs operational keys, node-id derivation, rotation, recovery | area | `lattice/identity.py`, `lattice/crypto.py` |
| E2 | Canonicalization / signatures | RFC 8785 JCS, strict JSON, preimages, signed-object kinds | area | `lattice/canonical.py`, `lattice/encoding.py`, `lattice/protocol/signing.py`, `models.py`, `constants.py` |
| F1 | Gossip | peer-card receive/send, batch bounds, verification, rate-limit keying | area | `lattice/gossip.py` |
| F2 | Topology / peers | candidate→verified→established, guards, prefix diversity, quotas, blocks | area | `lattice/topology.py`, `lattice/peers.py` |
| G1 | Resolution / addressing | domain parsing, well-known resolve, durable pins, transfer/reset | area | `lattice/resolution.py`, `lattice/addressing.py` |
| H1 | Messages | serialization, semantic validation, expiry, erasure | area | `lattice/messages.py` |
| H2 | Webhook / inbound custody | custody receipt, signed receipt, delivery, idempotency | area | `lattice/webhook.py` |
| I1 | Rate limiting | per-peer token buckets, persistence, refill arithmetic, zero-token restore | area | `lattice/rate_limit.py` |
| J1 | Config / lifecycle | config.toml schema, import-time I/O, boot gates, readiness | area | `lattice/config.py`, `lattice/__init__.py` |
| K1 | Deploy / install | systemd unit, nginx conf, packaging, wheel contents vs source | area | `deploy/**`, `pyproject.toml`, `tests/test_deployment.py`, `tests/test_wheel.py` |
| Q1 | Enumerations (question scope) | spawn/contextvar propagation; dual-write atomicity; sanctioned-path violations; error-path misreporting; documented-contract-vs-implementation | question | composed rg commands (see recipe library) |
| S1 | Seam — API↔runtime contract | route handler assumptions vs coordinator method contracts | seam | `api.py` ↔ `runtime.py` |
| S2 | Seam — transport↔topology contract | resolved-IP/policy result vs prefix grouping and peer state transitions | seam | `transport.py` ↔ `topology.py` |
| S3 | Seam — storage↔runtime contract | repository return shapes vs caller expectations (claim/lease semantics) | seam | `storage/repositories.py` ↔ `runtime.py` |
| S4 | Seam — protocol↔verification contract | signed-object preimage/kind vs verifier expectations | seam | `protocol/signing.py` ↔ `identity.py`/`gossip.py` |

## Hazard-enumeration recipe library (stable across runs)

Run before/with the hunts; instances feed the mechanism hunts as starting points.

- Spawn / context propagation: `rg "Thread\(|run_in_executor|copy_context|ContextVar"`
- Unbounded waits: `rg "\.result\(|Queue\(|wait_for|shutdown\("`
- Sanctioned-path violations: `rg "datetime\.now\(|getenv|os\.environ\[|open\("`
- Except-and-continue: `rg "except .*:|except:"` + `pass$|continue$`
- SQL string building: `rg "execute\(|f\"SELECT|f\"INSERT|f\"UPDATE"` in storage
- Dual-write sequences: persistent cache + durable writes in one operation
- Derived counters: rate-limit tokens, consecutive failures, quota counts

## Bootstrap notes

- Model gate: PASS — all four pinned models in `enabledModels`
  (`lunaroute/glm-5.3`, `lunaroute/glm-5.3-flash`, `lunaroute/deepseek-4.1-flash`).
- Registry: `kata v0.18.0`, `kata health` ok, `.kata.toml` bound (project `lattice`),
  `kata list --status all` → empty (no prior run ticket → first census).
- Map corpus drift noted (not this run's job): `docs/AGENTS.md` references
  `OPERATIONS.md`, `INTEGRATION.md`, `adr/`; `OPERATIONS.md` and `INTEGRATION.md` absent,
  `adr/` present; `ARCHITECTURE.md`, `LATTICE_SYSTEMD.md`, `LOOSE_ENDS.md` unregistered.
  Root `AGENTS.md` itself flags a pending rewrite.
- Candidates already visible to the orchestrator pre-hunt (do NOT feed as leads unless
  the human wants a seeded pass):
  - `repositories.py:290` builds `UPDATE peers SET {', '.join(updates)}` by string join —
    whitelist question.
  - `runtime.py:681` bare `pass` inside exception handling.
  - `runtime.py` executors `shutdown(wait=True, cancel_futures=False)`.
