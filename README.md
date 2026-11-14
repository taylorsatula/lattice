# lattice

Lattice is a key-anchored, flat mesh for cross-server messaging.
A human address such as `mikey@other.network` resolves to a canonical
`user@lat_…` identity, and messages travel directly between nodes. Bootstrap
nodes introduce peers but never relay traffic.

This repository is the v2 rewrite (Rust). The v1 Python implementation lives
under `old/` for reference only.

**Status: in progress — Phase 5 (daemon, local API, CLI).** Not ready for
production use. See `V2_PLAN.md` for the full roadmap and `V2_SPEC.md` for
the protocol.

## Layout

| Path | What |
|---|---|
| `crates/lattice-crypto` | X-Wing/ML-KEM, Ed25519, BLAKE3, ChaCha20-Poly1305, constant-time ops |
| `crates/lattice-proto` | Wire objects: CBOR, KEL, records, messages, frames, local API |
| `crates/lattice-core` | The sans-IO node engine (records, custody, routing, snow, reconcile) |
| `crates/lattice-sim` | Deterministic in-process network simulator used to test the core |
| `crates/lattice-store` | `Store` trait + in-memory and redb implementations |
| `crates/lattice-net` | WebSocket transport, Noise IK/XX, cookie anti-DoS, sizing caps |
| `crates/latticed` | The daemon (`init`, `run`) |
| `crates/lattice-client` | Rust client for the local API |
| `crates/latticectl` | Admin CLI (`node`, `drain`, `link`, `unlink`) |
| `vectors/` | CBOR/signature test vectors (self-generated; see `vectors/README.md`) |
| `deploy/` | systemd unit and example configuration |
| repo root | Design documents (`V2_DESIGN.md` first, then `V2_SPEC.md`, `V2_PLAN.md`) |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

MSRV is 1.87. CI runs fmt, clippy (`-D warnings`), tests, `cargo deny` and a
`forbid(unsafe_code)` check.

## Running a node

```sh
cargo build --release
sudo install -Dm755 target/release/latticed /usr/local/bin/latticed
sudo install -Dm644 deploy/latticed.service /etc/systemd/system/latticed.service
sudo latticed init --dir /var/lib/lattice        # generates keys; prints node id
sudo install -Dm600 deploy/lattice.example.toml /etc/lattice/lattice.toml
sudo $EDITOR /etc/lattice/lattice.toml           # set services, listen, roots
sudo systemctl daemon-reload && sudo systemctl enable --now latticed
```

Applications talk to the node over the local API (length-prefixed CBOR over a
Unix socket, see `V2_SPEC.md` §7) using `lattice-client` or their own
implementation. Administration goes through `latticectl` on the admin socket.

### Local sockets and access

- The **admin socket** (`admin_socket`, default `/run/lattice/admin.sock`) is
  mode `0600`, owner-only. It carries node control (drain, link, unlink,
  node info) and is root-only in practice.
- The **application socket** (`app_socket`, default `/run/lattice/app.sock`)
  is mode `0660`. There is no dedicated `lattice` group yet; with the default
  root ownership that is effectively root-only as well. Widening access
  (group `lattice`, tmpfiles.d) is a deliberate decision still pending —
  until then, run application clients as root or adjust the mode yourself.
- Delivery to applications is **at least once**: a delivery stays in the
  inbox until acknowledged, and is re-fetched after a crash. Applications
  must dedup by message id (`mid`).
- The listener sheds load before it sheds correctness: at most 1024
  concurrent connections (excess are closed immediately), and when more
  than 64 pre-auth handshakes are in flight the node requires the cookie
  round-trip (clears below 32). TCP keepalive (60s idle, 10s interval,
  3 probes) reaps dead peers.

## Documentation

- `V2_SPEC.md` — normative protocol and local API
- `V2_DESIGN.md` — why it is built this way
- `V2_PLAN.md` / `V2_EXECUTION.md` — phased plan and gates
- `AGENTS.md` — orientation for AI-assisted contributors
