# Lattice v2 Execution Plan

Companion to `V2_PLAN.md`. That document specifies *what* to build and in
what order; this one specifies *how the work is run* — readiness, sequence,
gates, and the points where the agent stops and asks. It is not a substitute
for `V2_PLAN.md`; where the two disagree, `V2_PLAN.md` wins on protocol and
this file wins on process.

Status: Phases 0–6 are implemented locally on `main` (Phase 0 `c9aa169` → Phase 4 `6c24519`, Phase 5 `4d676a1`, the 2026-11-14 review-sweep fixes `c39069f`, `733d4a8`, `ba66051`, the operator-ruling work `83119d8`…`b75830c`, the gateway→private delivery fix `1f388c3`, the six-node gate `49fb0e2`, and the Phase 6 Python client `71929d9`). Nothing has been pushed; GitHub CI has never run — all evidence is local. Local gates pass (fmt, clippy `-D warnings`, the full test suite, `cargo deny check`), but the phase gates as written are not all met (see the 2026-11-15 implementation review, `V2_IMPLEMENTATION_REVIEW.md`, §5.2): Phase 0 met locally only; Phase 1 partial (fuzz targets don't build; abandonment is not final mesh-wide); Phase 2 not met (no seed sweep, no invariant checker, runs not reproducible; several invariants violated); Phase 3 partial (crash tests pass; group commit measured but not in the production path); Phase 4 partial (loopback only; the connect-time scope check is not wired to a dial path; no network namespaces; no handshake fuzzing); Phase 5 met as written, with caveats (a star topology wired entirely by roots, no hive scope); Phase 6 met, with caveats (the Python client diverges from the Rust implementation). Phase 7 (release/soak) is not started.

**Scope of v2.0 (operator decision, H-20).** v2.0 attempts the full design:
neighbor selection (Phase 2), the hive/WAN dual-record model, group commit
(Phase 3), and the randomized seed sweep (Phase 2 exit) are all in scope.
Only the immune system, encrypted DNS (DoH/DoT), and the items in
`V2_PLAN.md`'s "Out of scope for v2.0" are deferred. `V2_PLAN.md` is the
source of truth for the deferral list.

## Readiness assessment

Environment, verified 2026-11 (this machine):

- Rust 1.98.1 stable (aarch64-apple-darwin); MSRV is 1.87 (`rust-version`,
  the `msrv` CI job, and the pinned fmt/clippy jobs). `cargo +1.87.0 fmt`
  and `cargo +1.87.0 clippy --all-targets --locked` both pass.
- `cargo-deny` 0.20.2 and `cargo-geiger` 0.14.0 are installed; `cargo deny
  check` passes (advisories, bans, licenses, sources, yanked).
- `cargo-fuzz` is installed; the fuzz targets have not been run in this
  environment and are not wired into CI.
- `git` identity configured; work happens on `main` (repo has no PR flow yet).
- The workspace lives at the root with `crates/` members; `old/` is frozen.
- `.github/workflows/ci.yml` runs fmt, clippy, tests (+ doc tests), an MSRV
  check, a workspace-lints check, `cargo deny`, and a `cargo geiger` report.
  GitHub has not run it yet; everything passes locally.
- `v1-final` tag exists.

Honest scope statement. This is a multi-month program of work executed by
one agent across many sessions, not a single run. It is executable exactly
to the extent that: each phase ends at a gate the operator can check; no
phase depends on trusting a previous phase's code, only its passing tests;
and every place the design leaves a parameter open is resolved by the
simulator or escalated, never guessed silently. The highest-risk items are
the X-Wing/ML-KEM crates (immature, draft-track) and the simulator's
fidelity — both have explicit verification phases before anything depends
on them.

## Ground rules for the work itself

- `#![forbid(unsafe_code)]` everywhere from the first commit; CI enforces it.
- No phase starts before the previous phase's exit criteria pass in CI.
- One crate never reaches into another's internals; crates depend in the
  order crypto → proto → core → {store, sim, net} → latticed/latticectl/client.
- `lattice-core` does no I/O. If a phase needs the clock, randomness, or a
  socket inside the core, the design has leaked; stop and fix the boundary.
- No dependencies added without a commit-message justification naming the
  alternative considered.
- Nothing logs sender or destination. Checked in review, testable in sim.
- `old/` is reference-only. No code is copied out of it; the Rust rewrite
  starts from the spec.

## Phase sequence and gates

Each phase names its deliverable and the gate that must hold before the next
begins. Gates are the exit criteria in `V2_PLAN.md`, restated as checkable
facts.

**Phase 0 — repo and guardrails.** Tag `v1-final` at `d652a8f` (already
existed). Create the root-anchored Cargo workspace — virtual manifest at the
repo root, nine member crates under `crates/`, no `new/` directory — each
crate with `#![forbid(unsafe_code)]` and a workspace-level
`unsafe_code = "forbid"` lint. Replace `.github/workflows/ci.yml` with the
Rust pipeline (fmt, clippy `-D warnings`, tests, forbid-unsafe check, MSRV
job, `cargo deny`, `cargo geiger` report) and delete the Python release
workflow. MSRV pinned at 1.87 via `rust-version` plus an msrv CI job.
*Gate:* every CI step passes locally (fmt, clippy, test, deny check); a
deliberate `unsafe` block fails the build. The GitHub-side CI run is pending
the first push, which the operator controls.

**Phase 1 — `lattice-crypto` and `lattice-proto`.** X-Wing validated against
the IETF draft test vectors before anything else is built on it (this is the
one dependency bet flagged in `V2_PLAN.md`; if the crate fails the vectors,
stop and escalate — the fallback is `ml-kem` + manual combiner, reviewed
against the draft, not a swap to a different primitive). Then: Ed25519,
BLAKE3, ChaCha20-Poly1305, OS randomness, constant-time compare; the strict
CBOR codec with pre-allocation length checks (if `minicbor` cannot enforce
them, a small hand-written codec — budget it explicitly, it is ~a day, not a
week); key events and KEL validation; peer records; sealed layers; messages
with buckets and receipts; channel and local-API frames; vectors written to
`vectors/`.
*Gate:* full round-trip suite green; property tests show any single-byte
mutation of signed/sealed objects rejects; non-canonical and oversized input
rejected; stolen-key rotation rejected; abandonment final; fuzz targets
run clean for an extended session.

**Phase 2 — core + simulator (`lattice-core`, `lattice-store` in-memory,
`lattice-sim`).** The largest phase; it is where the design either holds or
doesn't. Build in the order given in `V2_PLAN.md` (records/gossip → neighbor
selection → graph and routing → custody → queue and receipts → fair shares →
snow → gateways → key lifecycle), each landing with its invariants
passing. The immune system is deferred past v2.0 (see `V2_PLAN.md`,
"Out of scope for v2.0"). Adversarial nodes and partitions are first-class
from the start, not bolted on after. Simulator regressions get recorded as
seeds.
*Gate:* every invariant in `V2_PLAN.md` (convergence, no duplicate delivery,
no silent loss, custody durability, flood containment, routing termination,
reconciliation cost, bounded state, ...) holds across a randomized seed
sweep in CI; failures reproduce from seed. If an invariant fails, the fix
goes into the core and the seed joins the CI corpus — never the assertion.

**Phase 3 — redb storage.** Implement `lattice-store` against redb behind
the same trait the simulator uses. Crash-consistency testing at random write
points; migration framework from schema version 1; group commit measured on
throttled I/O to confirm custody throughput is not one-sync-per-message.
*Gate:* crash tests pass repeatedly; the Phase 2 invariant subset passes on
redb; group-commit acceptance rate measured and recorded in the docs.

**Phase 4 — transport (`lattice-net`).** WebSocket listener/client with size
caps before buffering; Noise IK/XX inside WebSocket; cookie path under load;
connect-time scope check (resolve → check every address against record
scope; encrypted DNS is deferred past v2.0, so resolution uses the system
resolver when unavoidable); endpoint proving before an
endpoint counts; padded frames, derived upgrade path, generic 404; optional
`/status`; endpoint-preference for IPs over hostnames.
*Gate:* three daemons on loopback and in network namespaces exchange
records/messages; cookie switchover under connection flood; a WAN record
resolving to a private address is never connected to; scanner without a
record sees only 404; fuzzing of handshake and frame decoders clean.

**Phase 5 — daemon, local API, CLI (`latticed`, `lattice-client`,
`latticectl`).** TOML config per `V2_PLAN.md`'s table; systemd credential
loading; key self-test at startup; local API on two Unix sockets; all spec'd
operations and events; admin ops through `latticectl`; hardened unit file and
example config in `deploy/`.
*Gate:* the ~6-node end-to-end scenario from `V2_PLAN.md` — hive + WAN link +
private instance behind a gateway, partition and heal, rotation, drain —
runs green with applications talking through the local API.

**Phase 6 — Python client (`clients/python/`).** Mirrors the Rust client;
passes the shared `vectors/`; integration test against a live daemon; hook-in
guide for MIRA.
*Gate:* vectors pass; integration test green.

**Phase 7 — release.** Hive multicast discovery; snow parameters confirmed
from soak; operator docs (including what Lattice cannot hide: who you connect
to, host fingerprints); multi-day soak with churn and injected faults;
external crypto and dependency review; `v2.0.0` tag. The immune system is
not part of v2.0 (deferred; see `V2_PLAN.md`, "Out of scope for v2.0").

## Verification log

- 2026-11-16 — Status line corrected after the 2026-11-15 implementation
  review: GitHub CI has never run, local gates are the only evidence, and
  several phase gates are not met (see the status line above and the
  review's §5.2). The group-commit bench
  (`crates/lattice-store/examples/group_commit.rs`) was corrected to compare
  like-for-like (`custody_put` one-transaction-each vs `custody_put_batch`,
  same table and rows); the 2026-11-14 figure above compared a 3-table
  accept against a 1-table batch insert and overstated the group-commit
  win. No library behavior changed.
- 2026-11-14 — Full local gate green: `cargo fmt --check`, `cargo clippy
  --workspace --all-targets --locked -- -D warnings` (also on 1.87.0),
  `cargo test --workspace --all-targets --locked` (30 suites), `cargo deny
  check` (advisories/bans/licenses/sources/yanked), e2e two-node delivery
  (`crates/latticed/tests/e2e.rs`, incl. drain, kill -9 recovery, per-service
  event scoping). GitHub CI has not run.
- 2026-11-14 — Phase 3 gate items: the simulator invariant suite also runs
  against redb (`crates/lattice-sim/tests/sim_redb.rs`, 6 scenarios: gossip
  convergence, end-to-end delivery, partition/heal, crash-during-custody,
  duplicate-mid suppression, contested-claim unbinding). Crash-consistency:
  a child process SIGKILLed mid-accept leaves a store that opens, with every
  journaled accept present, `custody_bytes` equal to the sum of surviving
  rows, share counters consistent, and a dedup marker per row
  (`crates/lattice-store/tests/redb.rs::crash_kill_preserves_committed_custody`).
  Group-commit bench (`cargo run --release -p lattice-store --example
  group_commit`, this machine): ~245 accepts/s one-transaction-each vs
  ~14,300 accepts/s group-committed (~58x). The production path uses one
  transaction per accept (custody + share + dedup marker), which is the
  durability requirement; group commit remains available for bulk load.
- 2026-11-14 — Phase 5 gate (six-node scenario) is MET. `crates/latticed/tests/six_node.rs`
  boots six real daemons on loopback — a hive (h1–h3), a WAN node, and a
  private instance behind a gateway — and drives applications through the
  local API throughout: WAN→private delivery through the gateway and back,
  hive-internal delivery, a SIGKILL partition that heals (queued message
  delivered after restart), a mid-run signing-key rotation, and a drain
  (new custody refused, delivered after un-drain). The gate surfaced a real
  defect: gateway→private delivery was impossible (the gateway forwarded
  the message with the gateway layer attached, and the routing graph could
  not reach a private instance, which publishes no links). Fixed in
  `1f388c3` (gateway strips the layer; the graph gains a private↔gateway
  pseudo-edge; the recipient recognizes a gateway-forwarded message by its
  envelope). The daemon also gained `reconcile_interval_secs` in `[limits]`
  (was hardcoded 60s) so gossip converges fast enough for the gate.
- 2026-11-14 — Phase 6 complete. `clients/python/`: a synchronous Python
  client for the local API (framing, hello, send/status/fetch/ack/lookup,
  events, admin ops), the shared vectors pass (`tests/test_vectors.py`,
  including a single-byte-flip rejection sweep), an integration test boots
  two daemons and drives the full roundtrip (`tests/test_integration.py`),
  and `clients/python/README.md` is the hook-in guide (services, mailboxes,
  opaque payloads, at-least-once + mid dedup, what "delivered" means).
  MIRA can be hooked in without changes to Lattice.

## Parameter defaults

`V2_DESIGN.md` §12 lists open questions (bucket sizes, snow parameters, waypoint share, k for the wary rule, hold, receipt timeouts). Rule: defaults from `V2_PLAN.md` ship unchanged until the Phase 2 simulator produces a measurement that argues otherwise, or the Phase 7 soak does. A default changes only with that evidence in the commit message — never by preference.

## Stop-and-ask triggers

Execution pauses and the operator is consulted when any of these occur:

1. The X-Wing/ML-KEM crates fail the draft vectors or show unsafe behavior.
2. An invariant in Phase 2 fails in a way that implicates the design (not
   the implementation) — e.g., no bound on flood harm without a mechanism
   the design lacks.
3. A wire-format change is needed (spec defect), because spec changes
   ripple into vectors, clients and the plan.
4. A dependency needs `unsafe` justification the `geiger` report can't
   support, or license review fails.
5. Phase scope is ambiguous between `V2_PLAN.md` and this file.
6. CI reality forces a ground-rule change (e.g., a GitHub Actions constraint).

Everything else — code layout, module splits inside a crate, test
organization, refactoring — is decided in the work and reported afterward.

## Working agreement while executing

- Commits are small enough to review by phase section; commit messages state
  the invariant or gate they advance, per the repo's git-workflow skill.
- Each phase ends with: gate evidence in the commit or PR description, the
  `AGENTS.md` map updated for new directories, and an explicit
  "phase N complete" report naming anything deferred.
- Nothing touches `old/` or `docs/`.
- `V2_EXECUTION.md` (this file) is updated only when the plan itself changes.
