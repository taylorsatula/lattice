# Lattice v1 Threat Model

This document describes the security model, trust assumptions, attacker capabilities, invariants, and accepted limitations of Lattice v1.

## 1. Assets

| Asset | Protection goal |
|-------|-----------------|
| Root private key | Confidentiality, integrity, availability (recovery). |
| Operational private key | Confidentiality, integrity, bounded lifetime. |
| Node ID / root public key | Integrity and immutability. |
| Domain-to-node pins | Integrity; prevent silent takeover. |
| Outbound/inbound message custody | Integrity, availability, idempotency, expiry, and erasure. |
| Peer maturity state | Integrity; prevent Sybil acceleration. |
| Blocks and guard lists | Integrity and availability. |
| Loopback webhook credential | Confidentiality and integrity. |

## 2. Trust assumptions

1. **Operator controls the host.** The operator installs keys, runs `lattice init`, and configures `/etc/lattice/config.toml`, Nginx, and systemd. Lattice cannot protect against a malicious or fully compromised operator host.
2. **Root key is generated and stored safely.** The root private key is a root-only encrypted host credential and is never loaded by the daemon. Compromise of the daemon host does not expose the root key.
3. **TLS infrastructure is honest for first contact.** The first resolution of `https://domain/.well-known/lattice` relies on the public or configured private PKI. After pinning, Lattice no longer trusts DNS or TLS alone.
4. **Receiving application resolves usernames correctly.** Lattice delivers to a loopback webhook; the local application decides whether a username exists and whether delivery is authorized.
5. **Clocks are roughly correct.** Signature and certificate validity windows require monotonic and wall-clock time within minutes, not microseconds.

## 3. Attacker capabilities

### Network attacker
- Can observe, modify, drop, replay, and delay traffic on the public internet.
- Cannot break Ed25519, SHA-256, or TLS 1.3 without a private key.

### Sybil attacker
- Can create arbitrarily many key pairs and nodes.
- Can run nodes at diverse IP addresses and prefixes.
- Cannot break Ed25519 or forge root signatures.

### Compromised peer
- A peer with a valid identity may send malformed or abusive traffic.
- A peer cannot forge traffic from another node.
- A peer does not learn the content of messages not addressed to it.

### Compromised daemon host
- An attacker who compromises the daemon process or host can read pending message content, drop messages, and sign messages as the operational key.
- The root key is not present, so the attacker cannot rotate the root, issue long-lived operational certificates, or bind new domains to the node ID.

### Compromised root key
- An attacker with the root key can issue operational certificates, rotate operational keys, and sign transfer statements.
- Recovery requires revocation/rotation through an out-of-band trust reset. Irrecoverable compromise means a new node identity.

## 4. Invariants

1. **Immutable identity.** A node ID is forever bound to one root public key. Operational keys rotate; root keys do not.
2. **No silent domain takeover.** A domain pin can change only through an old-root/new-root transfer statement or explicit local trust reset.
3. **Self-authenticating objects.** Every protocol object carries a kind, a signature, and a deterministic preimage that binds the kind and media type.
4. **Direct delivery.** Messages travel only from sender node to destination node. Bootstrap and neighbor nodes do not relay message bodies.
5. **Durable custody boundary.** A signed HTTP 202 receipt transfers retry ownership to the destination node. The sender stops retrying.
6. **Content minimization.** Terminal message content and extensions are erased. Audit metadata is retained only 30 days.
7. **Bounded concurrency.** Blocking work runs in bounded thread pools; request handling cannot be starved by slow federation peers.

## 5. Sybil controls

Lattice does not claim to eliminate Sybil attacks. It bounds their impact using objective, locally-verifiable rules:

- **Candidate state:** New peer cards become candidates, not verified peers. Candidates are capped globally, per introducer, and per observed network prefix.
- **Independent verification:** The receiver independently fetches `/.well-known/lattice` before promoting a candidate to verified.
- **Maturity:** A peer must remain verified for at least seven days with successful observations on multiple days before becoming established.
- **Topology diversity:** Stable guards plus a small rotating discovery set, prefix diversity, and slow replacement limit the value of flooding.
- **No propagated trust:** There are no trust scores, witness quorums, or reputation values forwarded through gossip.

A motivated attacker can still occupy many candidate slots or maintain long-lived malicious nodes. Operators block abusive nodes explicitly.

## 6. Key compromise scenarios

### Operational key compromise
- The attacker can sign messages and peer cards as the node until the certificate expires or is rotated.
- The operator rotates the operational key using the root key. Old certificates are rejected after the rotation window.

### Root key compromise
- The attacker can issue operational certificates and sign transfer statements.
- If detected, the operator creates a new root identity, publishes a trust reset, and peers re-pin the new binding manually or via an out-of-band transfer.
- There is no cryptographic undo in v1.

### Host compromise
- The attacker can read pending plaintext messages and sign as the operational key.
- The root key is not on the daemon host, so identity continuity is preserved after remediation.
- The operator rotates the operational key and investigates message custody gaps.

## 7. Non-goals

The following are explicitly out of scope for Lattice v1:

- End-to-end content encryption.
- Human-delivered or human-read receipts.
- Proof of one-human-per-node.
- Global decentralized consensus for domain ownership.
- Message relay through mesh neighbors.
- Built-in prompt-injection or content filtering.
- Multi-process or multi-host node runtime.
- First-class container deployment.
- Compatibility with the pre-release protocol.

## 8. Operational mitigations

- Run Lattice behind Nginx with exact-route exposure, TLS, and raw body/connection limits.
- Use systemd 250+ with `LoadCredentialEncrypted=` for the operational key and bearer credentials.
- Keep the root key offline or in a root-only encrypted host credential that the daemon cannot read.
- Monitor logs for repeated signature failures, candidate floods, and certificate/sequence anomalies.
- Back up the recovery bundle offline and test restoration.
