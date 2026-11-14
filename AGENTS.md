# Agent Guide for Lattice

This document is the primary entry point for AI agents working on Lattice. Read it first, then the documents it routes you to.

## Project purpose

Lattice is a key-anchored mesh for cross-node messaging. There is no DNS dependency, no central server and no name system: addresses are `<service>:<mailbox>@<identifier>`, where the identifier is a BLAKE3 hash of a key event log. Messages cross the mesh hop by hop; hops guarantee only custody, never delivery. The current implementation effort is the v2 rewrite specified in `V2_DESIGN.md` and `V2_SPEC.md`, implemented per `V2_PLAN.md` (Rust, sans-IO core, simulator first). The Python tree is retired and lives under `old/`.

## Invariants (never violate without explicit operator decision)

1. **Custody, not delivery.** A hop guarantees only that it durably stored the message. Arrival is confirmed only by a receipt from the recipient; hops cannot see senders.
2. **Every object proves itself.** Signatures, size buckets, expiry horizons are protocol rules; who to trust, throttle or ignore is each server's policy. No field is trusted because of where it came from.
3. **No global agreement.** No ledger, no proof-of-work, no designated relays. Each node acts on its own view of the graph; nothing requires two nodes to agree beyond what each can verify alone.
4. **No names on the network.** Records carry identifiers only; human naming is the application's address book.
5. **No v1 compatibility.** On the wire or in storage. v2 starts clean; v1 behavior is historical reference only.
6. **The next signing key never lives in the daemon.** Rotation uses a pre-committed key; abandonment is a rotation without a next-key commitment.
7. **The local API is never network-exposed.** Unix sockets only; application socket per service with constant-time secret comparison; admin operations on an owner-only socket via `latticectl`. No network-facing admin routes.
8. **Self-proving objects, no fixed infrastructure.** Nothing in the protocol may depend on a particular relay, root, DNS resolver, or network product; links are the operator's business (WARP, Tailscale, plain TCP), routing across them is Lattice's.

## File map

| Path | Responsibility |
|------|----------------|
| `V2_DESIGN.md` | Normative design rationale: threat model, routing, privacy, abuse control, operations. Read first. |
| `V2_SPEC.md` | Normative wire format: CBOR objects, channels, message flow, local API, storage tables. |
| `V2_PLAN.md` | Implementation plan: phases, exit criteria, initial defaults, candidate dependencies, risks. |
| `V1_DESIGN_INVENTORY.md` | Inventory of v1 choices kept as redesign reference; not normative. |
| `docs/` | v1-era normative docs (`PROTOCOL.md`, `THREAT_MODEL.md`, ...). Superseded by the V2 documents; read only for historical behavior. `docs/AGENTS.md` still presents them as normative and is stale. |
| `old/` | The pre-v2 Python tree as it stood at the move (largely the unmerged Python v2 rewrite; its tests and packaging moved with it). Not built, not maintained, not a base for new work. Frozen at commit `d652a8f`. |
| `old/lattice-c1-RESUME.md` | Resume note for the abandoned Python effort; historical. |
| `LICENSE`, `.github/`, `.gitignore`, `.kata.toml`, `.pi/` | License, CI (Rust: fmt/clippy/test/msrv/deny/geiger/forbid-unsafe), ignore rules, tooling config. |
| `Cargo.toml`, `crates/` | The v2 Rust workspace: virtual manifest at the root, nine member crates under `crates/`, each with `#![forbid(unsafe_code)]`. Laid out in `V2_PLAN.md`. |

## Mandatory checks before changing code

Until `lattice-core` has behavior, the workspace is scaffolding; the checks already apply: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`, and a `cargo geiger` report per crate (CI runs all of these). MSRV is 1.85 (`rust-version` and the msrv CI job). From Phase 2 on, the simulator invariant suite joins these.

- If you change `V2_SPEC.md` objects, keep `V2_PLAN.md` phase exits and the test-vector plan consistent with it.
- If you change `V2_DESIGN.md` decisions, check `V2_SPEC.md` for dependent spec text in the same edit.
- Do not edit `old/` except to read it. Do not "fix" v1 references in `docs/` without being asked; they are historical record.

## Task routing

- **Design question** → `V2_DESIGN.md`; check `docs/THREAT_MODEL.md` only for the v1 threat analysis it replaced.
- **Wire format, objects, crypto, storage tables** → `V2_SPEC.md` fully, then plan the change in `V2_PLAN.md` terms.
- **Implementation sequencing, defaults, dependencies** → `V2_PLAN.md`.
- **"Why was X removed from v1"** → `V1_DESIGN_INVENTORY.md`, then `git log` under `old/`.
- **v1 behavior details** → `git show <pre-d652a8f ref>:<path>` or `old/`; `docs/PROTOCOL.md` for the old contract, with the caveat that it describes the retired Python build.

## Communication rule

When asked to make a change, first restate the invariants that apply, then explain which documents and source files you read, then propose the smallest consistent change before editing.

## Pending items

- `docs/AGENTS.md` still presents the v1 documents as normative; it is stale.
- GitHub has not run the new CI yet; local runs of every step pass. Push is the operator's call.
