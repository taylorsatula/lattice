# lattice

Lattice is a key-anchored, flat mesh for cross-server messaging.
A human address such as `mikey@other.network` resolves to a canonical
`user@lat_…` identity, and messages travel directly between nodes. Bootstrap
nodes introduce peers but never relay traffic.

This repository is the v2 rewrite (Rust). The v1 Python implementation lives
under `old/` for reference only.

**Status: Phases 0–6 complete (through the Python client); Phase 7
(release/soak) not started.** Not ready for production use. See `V2_PLAN.md`
for the full roadmap and `V2_SPEC.md` for the protocol.

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
| `clients/python` | Python client for the local API (+ hook-in guide) |
| `crates/latticectl` | Admin CLI (`node`, `drain`, `link`, `unlink`) |
| `vectors/` | CBOR/signature test vectors (self-generated; see `vectors/README.md`) |
| `deploy/` | systemd unit and example configuration |
| repo root | Design documents (`V2_DESIGN.md` first, then `V2_SPEC.md`, `V2_PLAN.md`) |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
```

MSRV is 1.87. CI runs fmt and clippy (`-D warnings`, both pinned to 1.87.0),
tests (including doc tests), an MSRV check, `cargo deny`, and a check that
every crate opts into the workspace `unsafe_code = "forbid"` lint.

## Running a node

```sh
cargo build --release
sudo install -Dm755 target/release/latticed /usr/local/bin/latticed
sudo install -Dm644 deploy/latticed.service /etc/systemd/system/latticed.service
sudo install -Dm644 deploy/lattice.sysusers /etc/sysusers.d/lattice.conf
sudo install -Dm644 deploy/lattice.tmpfiles.conf /etc/tmpfiles.d/lattice.conf
sudo systemd-sysusers && sudo systemd-tmpfiles --create
sudo latticed init --dir /var/lib/lattice --next-key-out /secure/offline/next_signing_seed
sudo chown -R lattice:lattice /var/lib/lattice
sudo install -d -m 0750 -o root -g lattice /etc/lattice
sudo install -Dm640 -o root -g lattice deploy/lattice.example.toml /etc/lattice/lattice.toml
sudo $EDITOR /etc/lattice/lattice.toml           # set services, listen, roots
sudo systemctl daemon-reload && sudo systemctl enable --now latticed
```

The config file contains the service secrets in plaintext, so `latticed`
refuses to start unless it is mode `0600`/`0400` (owner only) or `0640`/`0440`
(owner plus group read) — anything more permissive is rejected with the
`chmod` to run. The shipped example installs as `0640 root:lattice`.

`latticed init` generates the identity and the *next* signing key. The next
key is the only way to rotate the identity later, so it is never written
into the identity directory: `--next-key-out` writes it to a path you choose
(keep it offline, e.g. on removable media); without the flag it is printed
once to stdout. The identity directory stores only its BLAKE3 commitment
(`next_key_commitment`). If `next_signing_seed` ever appears inside the
identity directory, the daemon refuses to start. To rotate later, generate
the following key offline, then run
`latticectl rotate --next-key-file <path> --next-next-commitment <hex>`;
`latticectl abandon --next-key-file <path>` retires the identity for good.

Applications talk to the node over the local API (length-prefixed CBOR over a
Unix socket, see `V2_SPEC.md` §7) using `lattice-client` (Rust),
`clients/python` (Python), or their own implementation. Administration goes
through `latticectl` on the admin socket.

### Local sockets and access

- The **admin socket** (`admin_socket`, default `/run/lattice/admin.sock`) is
  mode `0600`, owned by the `lattice` user. It carries node control (drain,
  link, unlink, rotate, abandon, node info). Root can connect (it bypasses
  file permissions); no one else can.
- The **application socket** (`app_socket`, default `/run/lattice/app.sock`)
  is mode `0660`, group `lattice`. Members of the `lattice` group may connect;
  everyone else cannot. Create the group with the shipped sysusers.d snippet
  (`deploy/lattice.sysusers`), add application users with
  `usermod -aG lattice <user>`, and let tmpfiles.d manage `/run/lattice`
  (`deploy/lattice.tmpfiles.conf`). The daemon runs as the `lattice` user
  (`User=lattice` in the unit), so the socket it creates is group-owned
  automatically. The unit grants no capabilities, filters the syscall set
  to `@system-service`, and limits writes to `/var/lib/lattice` and
  `/run/lattice`.
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
