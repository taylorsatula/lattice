# Lattice v2 Implementation Plan

Builds the system described in `V2_DESIGN.md` and `V2_SPEC.md`. Phases are
ordered so that each one is verified before the next depends on it. The
protocol is proven in a deterministic simulator before any real network code
exists.

## Architecture in one paragraph

The protocol logic is a **sans-IO core**: a state machine that takes events
(a frame arrived, a timer fired, the application sent something) and returns
actions (send this frame, store this, deliver that). Time, randomness and
storage are injected. The same core runs inside the simulator, where the
clock, randomness and network are controlled and every run can be replayed
from a seed, and inside the real daemon, where they come from the operating
system. This is what makes it possible to test the protocol against
partitions, crashes and lying nodes before networking code exists.

## Repository layout

Following the original proposal: v1 moves to `old/` (and is also tagged
`v1-final`), and v2 is built in `new/` as a Cargo workspace.

```
old/                      v1, unchanged, for reference
new/
  Cargo.toml              workspace
  crates/
    lattice-crypto/       Ed25519, X-Wing seal/open, BLAKE3, key events
    lattice-proto/        deterministic CBOR, every spec object, validation
    lattice-core/         sans-IO state machine: gossip, routing, custody,
                          receipts, fair shares, gateways, immune system
    lattice-store/        Store trait; in-memory and redb implementations
    lattice-net/          Noise inside WebSocket, cookies, listener, status,
                          connect-time scope checks
    lattice-sim/          deterministic simulator and invariant checks
    lattice-client/       Rust client for the local API
    latticed/             daemon binary: config, wiring, local API sockets
    latticectl/           admin CLI
  clients/python/         Python client for the local API (for MIRA)
  vectors/                shared test vectors for every wire object
  deploy/                 systemd unit, example configuration
```

## Ground rules for every phase

- `#![forbid(unsafe_code)]` in every crate, enforced in CI.
- CI runs:
  - `cargo fmt --check`
  - `cargo clippy -- -D warnings`
  - the full test suite
  - `cargo deny`, for advisories, licenses and duplicate dependencies
  - a `cargo-geiger` report of `unsafe` in dependencies, reviewed whenever it
    changes
- Dependencies are pure Rust wherever a mature option exists. Every new
  dependency is justified in its commit message.
- No blocking calls on async tasks. The core does no I/O at all.
- Nothing logs a message's sender or destination.
- A phase is done when its exit criteria pass in CI, not when its code is
  written.

## Candidate dependencies

To be confirmed at the start of the phase that first needs each one. "Verify"
marks the choices with the most uncertainty.

| Need | Candidate | Notes |
|---|---|---|
| Async runtime | `tokio` | |
| WebSocket | `tokio-tungstenite` | Must support a maximum frame and message size enforced before buffering |
| Noise | `snow` | Pure-Rust resolver; IK and XX patterns |
| Ed25519 | `ed25519-dalek` | |
| X25519 | `x25519-dalek` | |
| X-Wing / ML-KEM | RustCrypto `x-wing` and `ml-kem` | **Verify** maturity and that the X-Wing version matches the current draft; check against the draft's test vectors |
| AEAD | `chacha20poly1305` | |
| Hashing | `blake3` | Consider the `pure` feature to avoid assembly |
| CBOR | `minicbor`, with hand-written encode/decode | **Verify** that deterministic encoding and pre-allocation length checks can be enforced; otherwise write a small strict codec for our closed object set |
| Storage | `redb` | Confirm durability (fsync) semantics on commit |
| DNS | `hickory-resolver` | Returns every address, for the connect-time scope check |
| Constant time | `subtle` | |
| Randomness | `rand_core` with `OsRng` / `getrandom` | |
| Config | `toml` | |
| Logging | `tracing` | |
| Property tests, fuzzing | `proptest`, `cargo-fuzz` | Fuzzing is development tooling and runs on nightly |

## Phase 0: Repository and guardrails

- Tag the current tree `v1-final`. Move v1 into `old/`.
- Create the `new/` workspace with empty crates, each with
  `#![forbid(unsafe_code)]`.
- Set up CI with the ground rules above, and pin the minimum supported Rust
  version.

**Exit:** CI is green on the empty workspace, and a deliberate `unsafe` block
fails the build.

## Phase 1: Objects and cryptography

`lattice-crypto` and `lattice-proto`.

1. **Primitives:** Ed25519 sign and verify, X25519, X-Wing encapsulate and
   decapsulate, ChaCha20-Poly1305, BLAKE3, OS randomness, constant-time
   comparison.
2. **Deterministic CBOR codec** with the spec's decoding limits (nesting
   depth, entry counts, string lengths checked before allocation). It
   rejects non-canonical encodings, unknown keys and unsupported versions.
3. **Key events:** inception, rotation and abandonment. Building them,
   validating a KEL, and deriving the identifier.
4. **Peer records** (public and private, WAN and hive scope): building,
   signing, and the full validation list from the spec, including expiry
   horizons.
5. **Sealed layers:** X-Wing sealing with the routing header as associated
   data.
6. **Messages:** building with an optional gateway layer, padding to size
   buckets, refusing oversize messages, and opening at the gateway and the
   recipient. Receipts and negative receipts.
7. **Channel frames and local API frames:** encode and decode only; behavior
   comes later.
8. **Test vectors** for every object, written to `vectors/` for the Python
   client and for future implementations.

**Exit:**
- Every spec object round-trips.
- Property tests show that changing any byte of a signed or sealed object
  causes rejection.
- Non-canonical and oversized inputs are rejected.
- A stolen current key can't produce a valid rotation, and an abandoned
  identity accepts nothing further.
- X-Wing passes the draft's published test vectors.
- Fuzz targets for every decoder run clean for an extended session.

## Phase 2: The core, proven in the simulator

`lattice-core`, `lattice-store` (in-memory store only) and `lattice-sim`.

**Simulator capabilities:**
- Many nodes in one process, each running the real core.
- A virtual clock and seeded randomness, so every run is reproducible.
- Links with configurable latency, loss, reordering and bandwidth.
- Partitions that split and heal on a schedule.
- Crashes and restarts at arbitrary points, including mid-custody, with the
  store keeping only what was committed.
- Adversarial nodes:
  - forging records
  - equivocating
  - flooding
  - accepting custody and dropping messages
  - claiming links that don't exist
  - stealing keys
- Topologies: a single hive, multiple hives joined by WAN links, chains, and
  private instances behind gateways.

**Order of implementation within the core,** each step merged with its
invariants passing:

1. **Records and gossip:**
   - validation and storage, with last-writer-wins per (id, scope)
   - soft-state expiry and expiry horizons
   - anti-entropy by full digest
   - `want` for specific records
   - per-neighbor push limits
   - the hive/WAN scope rule
2. **Neighbor selection:**
   - grouping by network range
   - secret-salted keyed sampling
   - anchor peers
   - test before evicting
3. **The graph and routing:** links counted only when both ends claim them,
   and shortest-path routing.
4. **Custody:**
   - accept only after a durable store, and keep a dedup set until expiry
   - "already have it"
   - leases, retry with backoff, and waiting for a path when there is none
5. **Outbound queue and receipts:**
   - the queue, ordered by priority
   - receipts and negative receipts
   - the receipt timeout, and retry over a disjoint path
6. **Fair-share custody:**
   - a per-destination allowance shared across upstream links, with busy
     answers
   - the transit storage cap
   - per-service inbox caps
   - drain
7. **Snow:**
   - immediate dispatch of real frames, with the optional hold
   - Poisson snow ticks per node, skipped when real traffic went out
   - dummy sizes from the recent real mix with per-bucket minimums
   - echoes that mimic request and reply
8. **Private instances and gateways.**
9. **Key lifecycle across the mesh:**
   - spreading rotations and abandonments
   - detecting equivocation
   - rotating envelope keys
10. **Immune system (optional):** the wary list and the *k*-distinct-ranges
    rule.

**Invariants the simulator checks on every run:**
- **Convergence:** after any partition heals, every node holds the same
  valid records within a bounded time.
- **No duplicate delivery:** an application never receives the same message
  id twice, unless a crash occurs between delivery and `ack` (at least once
  by design).
- **No silent loss:** a message is either delivered or reported failed or
  expired to its sender. If a path exists for long enough before expiry, it
  is delivered.
- **Snow hides activity below the snow level:** for traffic below a node's
  snow level, the frame rate and size distribution an outside observer sees
  on the node's uplink are statistically indistinguishable (by a two-sample
  test) between runs where the node sends real messages and runs where it
  doesn't.
- **Dummies don't stand out by reply pattern:** the share of frames answered
  within a short interval is the same for real and dummy frames, within a
  set tolerance.
- **Snow cost:** an idle node's sent bytes stay within its snow budget, and a
  node whose real traffic exceeds its snow level sends almost no snow.
- **Quick dispatch:** with hold at 0, the delay snow adds to a real frame is
  negligible.
- **Custody is durable:** no node answers `accepted` for a message it would
  lose in a crash.
- **Flood containment:** under a flood from one attached node, delivery rate
  and latency for senders outside the abuser's branch stay within a set
  bound of the no-flood baseline.
- **Routing around droppers:** with a node that drops messages after taking
  custody, messages still arrive through disjoint-path retries.
- **Privacy:** no node other than a private instance's gateways ever holds
  that instance's identifier together with a message addressed to it; no
  hop's state contains a message's sender; hive-scoped records never reach
  a node outside the hive.
- **Key safety:** rotations signed by a stolen current key are rejected
  everywhere, and abandonment is final everywhere.
- **Bounded state:** every table on every node stays within its configured
  cap under adversarial load.

**Exit:** all invariants hold across a large randomized seed sweep in CI,
with a longer sweep run nightly, and any failure can be reproduced from its
seed.

## Phase 3: Storage

`lattice-store` with redb.

- A redb implementation of the same Store trait the simulator uses. Tables
  follow `V2_SPEC.md` §8.
- A `meta` table with schema version 1, and a migration framework: run
  migrations from older versions in order; refuse to start on a newer one.
- **Crash-consistency tests** with the real redb store: kill the process at
  random points during writes and check on restart that committed state is
  intact and nothing uncommitted was acknowledged.
- A subset of the Phase 2 invariant suite re-run against redb.

**Exit:** crash tests pass repeatedly, and the core passes its invariant
subset on redb.

## Phase 4: Network transport

`lattice-net`.

1. **WebSocket listener and client,** with frame and message size caps
   enforced before buffering.
2. **Noise inside the WebSocket:** IK when the peer's record is held, XX for
   a root given without an identifier, and a check after the handshake that
   the peer's static key matches the `ck` in its record.
3. **Cookies:** mac1 on every init, mac2 and the stateless cookie reply under
   load.
4. **Check order for new connections,** cheapest first.
5. **Connect-time scope check:** resolve every address and connect only to
   addresses that pass the record's scope.
6. **Endpoint proving** before an endpoint counts as reachable.
7. **Listener binding defaults:** hive interfaces only, unless the instance
   is public.
8. **Status endpoint** on the same listener, with its flag, and the generic
   404 for anything else.
9. **Padding, snow and probe resistance on real sockets:**
   - every frame padded to a bucket, handshake frames included
   - no WebSocket control frames
   - snow and the optional hold driven by the core
   - the upgrade path derived from the channel key, with a generic 404 for
     anything else
   - endpoint IP addresses preferred over hostnames, with encrypted DNS
     (DoH or DoT) and caching when a lookup is needed
10. Plumb all of this into the core's events and actions.

**Exit:**
- Three daemons on loopback, and in separate network namespaces, exchange
  records and messages.
- Handshake and frame fuzzing run clean.
- Under a simulated connection flood, the responder switches to cookies and
  keeps serving existing links.
- A WAN record whose hostname resolves to a private address is never
  connected to.
- A scanner without the record gets only generic 404s, and the status
  endpoint disappears when disabled.

## Phase 5: Daemon, local API and CLI

`latticed`, `latticectl` and `lattice-client`.

- **Configuration** (TOML), finalizing the configuration surface:

  | Setting | Purpose |
  |---|---|
  | `identity_dir`, `next_key_path` | Where keys live; the next key separately |
  | `mode` | `public` or `private` |
  | `listen` | Listen addresses; hive-only by default |
  | `advertise` | Endpoints to publish (public mode) |
  | `hive` | CIDRs that make up the hive |
  | `roots` | Addresses, each with an optional identifier |
  | `gateways` | For private mode |
  | `services` | Name and secret for each application |
  | `status` | Public status endpoint on or off (default on) |
  | `snow` | Snow level, echo share, hold |
  | `hive_interfaces` | Interfaces where multicast discovery runs; none by default |
  | `dns` | Encrypted resolver to use when a hostname must be resolved |
  | `limits` | Overrides for the defaults below |

- **Startup:** load secrets (systemd credentials first, then files with mode
  0600), check that the configuration is safe, run the key self-test (a test
  signature and a test decapsulation), open the store and migrate, then
  serve.
- **Local API** on Unix sockets:
  - the application socket, with services authenticated in constant time
  - every operation and event in the spec
- **Admin socket and `latticectl`:** `node`, `rotate`, `abandon`,
  `rotate_envelope`, `link`, `unlink`, `drain`.
- **Rust client library.**
- **Hardened systemd unit** and an example configuration in `deploy/`.

**Exit:** an end-to-end test on a small real mesh of about six nodes. It
covers a hive, a WAN link, a private instance behind a gateway, a partition
that heals, a rotation, and a drain. Applications send and receive through
the local API throughout.

## Phase 6: Python client and MIRA hook point

- **Python client** in `clients/python/`: framing, `hello`, `send`,
  `status`, `fetch`, `ack`, `lookup`, and events. It passes the shared test
  vectors in `vectors/`.
- An integration test against a running daemon.
- A short guide for hooking an application in: services, mailboxes, opaque
  payloads, at-least-once delivery with dedup by message id, and what
  "delivered" means.

**Exit:** the Python client passes the vectors and the integration test, and
MIRA can be hooked in without changes to Lattice.

## Phase 7: Remaining features and release

- Hive multicast discovery, only on configured hive interfaces.
- Snow defaults confirmed from the soak test: idle cost per node and the
  dummy share on busy nodes.
- **Operator documentation on what Lattice can't hide:** who a node connects
  to (use WARP, Tailscale or similar if that matters), and host-level
  fingerprints such as TCP timestamps.
- The immune system, if it wasn't finished in Phase 2.
- **Soak test:** the real mesh runs for days with churn and injected faults,
  watching memory, storage growth and delivery rates.
- **Review:** an external look at how the cryptography is used, the
  `cargo-geiger` report for dependencies, and dependency licenses.
- Operator documentation.
- Tag `v2.0.0`.

## Initial defaults

These are starting values, tuned in the simulator during Phase 2 and adjusted
from the soak test.

| Parameter | Default |
|---|---|
| Neighbors (links) | 16, hard cap 32 |
| Anti-entropy interval | 60 s |
| Record refresh / record expiry | 1 day / 7 days (horizon 30 days) |
| Message expiry | 3 days (horizon 14 days) |
| Retry backoff | 30 s doubling, capped at 30 min |
| Receipt timeout | 15 min |
| Disjoint-path retries | 3 |
| Custody allowance per destination | 4 MB |
| Transit storage cap | 256 MB |
| Inbox cap per service | 64 MB |
| Snow level | 2 frames per minute per node |
| Echo share / bucket minimum | 25% / 10% each |
| Hold | 0 ms (immediate dispatch) |
| Wary rule *k* / wary list size | 3 / 32 |
| Size buckets | 2, 8, 32 KB |

## Out of scope for v2.0

These are recorded in the design doc as open or deferred:

- anonymous senders
- messages over 32 KB and attachments
- post-quantum protection for the channel
- loop messages and constant-rate cover
- range-based set reconciliation, unless the simulator shows full-digest
  anti-entropy is too costly at the target scale
- Spray-and-Wait
- greedy-tree routing for very large meshes
- non-IP transports

## Risks

| Risk | Mitigation |
|---|---|
| X-Wing and ML-KEM crates are young | Check against the draft's vectors in Phase 1; wrap behind `lattice-crypto` so the implementation can be swapped |
| No CBOR library enforces our strictness | Our object set is small and closed; a hand-written strict codec is a few hundred lines |
| redb durability differs from expectations | Crash-consistency tests in Phase 3 before anything depends on it |
| The simulator diverges from real networks | Phase 4 and 5 tests run the same core over real sockets; any divergence becomes a simulator fix |
| Size overhead from ML-KEM | Already reflected in the size buckets; revisit only for non-IP transports |
