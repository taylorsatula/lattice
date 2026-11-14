# Lattice v2 Design (draft)

## Purpose

> Lattice was created originally so that Mira instances on the open internet
> could discover and communicate long after a central seed server went
> offline. I envision a system that is not ornamented.

Lattice connects peers over possibly shaky connections without a central
orchestrator. Instances in the same hive (a LAN, a tailnet, any network
where members reach each other directly) talk to each other, and instances
talk across the WAN.

## Principles

1. **End-to-end.** The transport guarantees custody (the next hop durably
   stored the message), never end-to-end outcomes. Anything only the
   application can know (read, understood, acted on) is an application
   message. (Saltzer, Reed & Clark 1984)
2. **Integrity is cryptographic; discovery is best-effort.** Every record
   proves itself, so it doesn't matter who relayed it. Discovery is allowed
   to be messy.
3. **Every node acts on its own view.** There is no global agreement, no
   ledger and no proof-of-work. Nothing requires two nodes to agree except
   what each can verify for itself.
4. **Easy to be law-abiding, hard to be disruptive.** Limits only bind at
   abusive volume. Speed bumps appear only when alarms are raised, and they
   cost time, not CPU, so low-power devices are never penalized for being
   honest.
5. **The protocol defines validity; servers define policy.** Signatures,
   formats and size limits are protocol rules. Who to trust, throttle or
   ignore is each server's business.
6. **Reachability is the operator's job.** WARP, Tailscale, Headscale,
   WireGuard, a public IP or port forwarding all work. Lattice assumes any
   address it holds for a peer is directly reachable and contains no code
   for a particular network product.
7. **Don't foreclose non-IP transports.** Objects stay small and
   self-proving, and nothing depends on a synchronous round trip, so a
   radio mesh such as Meshtastic remains possible later without designing
   for it now.

## 1. Identity

- **Keys:** Ed25519.
- **Pre-rotation (from KERI).** Every key state includes a hash of the
  *next* key, committed to before it's needed. A rotation is signed by that
  pre-committed key, and it commits to the hash of the key after that.
  Someone who steals the current key can sign messages but can't rotate,
  because the owner's rotation with the committed key always wins.
- **Abandonment** is a rotation with no next-key commitment. This one
  mechanism replaces both v1's key rotation and its "cyanide pill."
- **The next private key is stored separately from the running daemon.**
  If the current and next keys are both stolen, recovery isn't possible.
- **Identifier:** the hash of the instance's first key event (initial key
  plus the first next-key commitment). It stays the same across rotations
  and replaces v1's separate UUID.
- **Key event log:** the inception event plus any rotations. It is short,
  append-only and self-verifying.

### Names

- **Readable for display, key underneath** (a petname system). The display
  name is a claim inside the instance's signed record. It is never
  registered or checked network-wide.
- **A local name table on each instance** maps names to identifiers the
  first time it sees them, like SSH's `known_hosts`.
- **Collisions are shown, never silently resolved.** The first identifier
  an instance saw keeps the plain name; any later one is displayed with a
  short fingerprint suffix (`rocketcity#k7f3`). A name is never silently
  rebound to a different key.
- **Address format:** `user@name`, or `user@name#suffix` when shared out of
  band, so the recipient pins the correct identity on first contact.
- **Envelopes, replies and contact lists use identifiers.** Names are
  resolved only at the edges: when a user types an address and when the app
  displays one. Renames don't break contacts.
- **Users are the instance's business.** Lattice authenticates instances;
  each instance vouches for its own users, as in email.

## 2. Peer record

There is one record type. Each instance publishes and periodically
refreshes its own.

| Field | Purpose |
|---|---|
| identifier | Stable identity (§1) |
| current key + key event log | Verifies the signature and the rotation history |
| seq | Monotonic; the highest seq for an identifier wins |
| display name | Petname claim |
| endpoints | Addresses, each tagged with a scope (hive or WAN) |
| capabilities / protocol version | Feature flags and negotiation |
| expiry | Signed coarse expiry, on the order of days |
| signature | By the current key, over the exact encoded bytes |

- **Last-writer-wins by seq,** as in BitTorrent's BEP 44 mutable items.
  Partitions merge with no special logic.
- **Soft state.** The owner refreshes the record before it expires. A
  record that isn't refreshed fades out everywhere, so no cleanup jobs or
  liveness logic are needed.
- **Size capped,** on the order of 1 KB.
- **Equivocation proof.** Two different records signed by the same key with
  the same seq prove misbehavior or a stolen key. Anyone can verify this
  from the two records alone.
- **Endpoint scope rule.** An address is only valid in the context it was
  learned in. The operator declares which networks make up their hive.
  Private and overlay addresses (RFC 1918, 100.64.0.0/10 and similar) are
  accepted only from hive sources and dropped from records that arrive over
  the WAN. This replaces v1's fixed SSRF blocklist.
- **Prove an endpoint before using it.** An endpoint counts as reachable
  only after a handshake at that address proves the far end holds the
  record's key. That stops anyone using the mesh to aim traffic at a victim.

## 3. Transport

- **Channels authenticated by the two instances' keys,** in the style of
  Noise, WireGuard or SSB's Secret Handshake. There are no certificate
  authorities and no dependence on DNS for trust.
- **WireGuard-style cookies under load.** Normally the handshake proceeds as
  usual. Under load the server keeps no state and answers with a cookie
  derived from the sender's address and a rotating secret. The sender must
  echo it back before the server spends any resources. It costs honest
  peers one extra round trip, only during an attack. There is no
  proof-of-work.
- **Every protocol object is signed and self-proving,** so objects stay
  independent of the transport that carries them.

## 4. Bootstrap and discovery

The layers, tried in order:

1. **Saved peers** from previous runs. A node that has ever been connected
   never needs its root again.
2. **A configured root or roots.** Any instance can be any other instance's
   root. A root is given as an address with an optional fingerprint.
   - Without a fingerprint, the first contact is trusted on first use.
   - With a fingerprint, the root's identity is verified.
   - A missing fingerprint is allowed but logged as a warning.
3. **Multicast discovery on the hive.** On a LAN, members find each other
   with no configuration.

The root is an introducer only. After first contact it is an ordinary peer
with no special standing. Admission is never tied to "is this my root."

The network is whatever graph these links form. Two hives that never link
stay separate, which is correct; when any instance links them, gossip
merges them.

## 5. Gossip

- **Every node holds every peer record it accepts,** up to a local cap.
  There is no DHT; membership is small enough to replicate in full.
- **Anti-entropy with random neighbors** (Demers et al. 1987). Two nodes
  compare their sets of (identifier, seq) pairs and fetch only what's
  missing.
  - Initially, nodes exchange the full digest of those pairs.
  - When the set grows large, range-based set reconciliation (Meyer 2022,
    as used by Negentropy) replaces it.
- **Neighbor selection** (Heilman et al. 2015; Brahms 2008):
  - Random, from peers grouped by network range.
  - Which peers to keep is chosen by a hash salted with a local secret, so
    an attacker can't aim at the table's slots.
  - A few anchor peers are persisted across restarts.
  - A peer is tested before being evicted.
- **Relay only what you would accept.**
- **Per-peer push limits** on unsolicited records.

## 6. Delivery

- **Message object:** message id, sender identifier and user, recipient
  identifier and user, content, metadata, created time, expiry, and the
  sender instance's signature over the exact bytes. Size capped.
- **Durable outbound queue.** The message is signed at enqueue time and
  stored with its signature. The first attempt is made immediately; failures
  retry with exponential backoff until expiry. A message stuck in "sending"
  past its lease returns to pending, including after a crash.
- **Custody transfer** (Fall 2003). A receiver accepts only after durably
  storing the message. That acceptance is a transport-level result, not a
  signed receipt object. Read or delivery receipts, if MIRA wants them, are
  application messages.
- **Idempotent receive by message id.** Seen ids are retained at least as
  long as the message can still arrive (until its expiry). Retries are
  always safe.
- **Failure classes:**
  - **Transient** (unreachable, overloaded): retry with backoff, tracked per
    destination.
  - **Permanent** (not addressed to this instance, malformed, unknown user
    where the instance knows it): stop retrying.
- **No open relay.** An instance accepts custody only for messages addressed
  to itself.
- **Delivery is direct** to the recipient's endpoints. Relaying through
  intermediate nodes is not in the core; custody semantics leave room for it
  later.

## 7. Abuse resistance and the immune system

**The protocol enforces only validity:** signatures verify, formats parse,
size limits hold. Everything else is server-level policy.

**Baseline server limits** cost honest traffic nothing:

- A rate limit per peer.
- A rate limit per network range on first contact from unknown identifiers.
  The limit follows the address range, so churning through fresh keys
  doesn't help.
- Per-peer push limits on unsolicited records.
- A fixed cap on stored records, with eviction by the secret-salted hash.
- Soft-state expiry.
- Local bans, based on the server's own direct evidence.

### Immune system

The model is herd alarm signaling: an alarm triggers vigilance, never
flight, and false alarms are cheap, so the herd can afford to be
trigger-happy (the smoke detector principle).

- **Invariant:** secondhand alarms can only slow a key down. Only direct
  evidence, or an equivocation proof, can exclude it.
- **Wary list.** Each server attaches a short, capped, expiring list of
  identifiers it's wary of, based on its own observations, to the gossip
  exchange that already happens. There is no new message type.
- **Rule.** When peers from *k* distinct network ranges list the same
  identifier, the server applies a much tighter rate limit to it and stops
  relaying its records. When those lists drop it, the limits lift on their
  own.
- **Why this needs no reputation tracking:** a forged alarm can only slow
  its victim down for a while, so there's nothing to defend against and no
  caller reliability to track. A bad actor's reach also shrinks as more of
  the herd grows wary, because its records spread only through servers that
  haven't flagged it.

## 8. Time

- **Ordering uses seq numbers;** no clock is involved.
- **Replay protection** uses seq numbers plus the record of seen message
  ids.
- **The only timestamps are coarse signed expiries,** on peer records and
  messages, measured in days. Clocks only need to be right to within hours.

## 9. Operations (carried forward from v1)

- **The daemon runs its own timers.** No external scheduler calls admin
  endpoints.
- **Secrets** come from systemd credentials (encrypted when available), then
  from files with mode 0600/0700. Never from environment variables.
- **The private key file is created with mode 0600** from the start.
- **A hardened systemd unit:** dedicated user, `ProtectSystem=strict`,
  minimal writable paths, resource limits, a single process owning all
  state.
- **SQLite** in a single file, with an idempotent schema and additive
  migrations.
- **Public vs. local control plane.** Admin access requires a token,
  compared in constant time and failing closed. Exposure behind a reverse
  proxy is deny-by-default.
- **Bounded inputs:** caps on request body and field sizes, and timeouts on
  every outbound call.
- **A minimal public status endpoint** and a detailed admin health endpoint.
- **Lattice doesn't own users.** The application maps users and receives
  messages.

## 10. Removed from v1

| v1 | v2 |
|---|---|
| Server UUID + name + key | Identifier derived from key events |
| RSA-2048, fingerprint of PEM text | Ed25519, fingerprint of key bytes |
| Signing re-serialized JSON | Signing the exact encoded bytes |
| Network-wide name registration, confidence scores | Local petname table |
| Domain queries, route cache, hop counts, confidence decay | Full-membership gossip |
| Admission only via pinned bootstrap | Any valid record from any peer; root as introducer |
| Mandatory bootstrap pins | Optional fingerprint, trust on first use otherwise |
| Peer exchange defined but unused | Anti-entropy is the core mechanism |
| Trust levels (`trusted`/`untrusted`/…) | Local policy + immune system |
| Signed delivery acks | Custody acceptance; receipts are application messages |
| Separate key rotation and cyanide pill | Pre-rotation; abandonment is a rotation |
| Tiered peer aging, cleanup jobs | Soft-state expiry |
| Short timestamp freshness windows | Seq numbers + seen ids + coarse expiry |
| Fixed private-address blocklist | Endpoint scope rule |
| Saturation metric | Removed |
| External scheduler driving the daemon | Self-running daemon |

## 11. Open questions

- **Wire transport:** HTTP(S) carrying signed objects, or a Noise-style
  channel over TCP or UDP. This determines how the handshake and cookie
  mechanism are built.
- **Encoding:** deterministic CBOR or another canonical binary encoding, or
  signing raw payload bytes inside a simple envelope.
- **Handoff to the application:** whether the app pulls from Lattice's
  inbox or Lattice pushes to a webhook. Also, whether "unknown user" is
  checked at custody time (making it a permanent failure) or after.
- **Hive configuration:** how an operator declares hive networks, and which
  multicast discovery mechanism to use (mDNS or a minimal custom
  announcement).
- **Parameters:** record and message expiry, gossip cadence, storage and
  push caps, rate limits, the *k* threshold for the wary rule, wary list
  size.
- **Keeping the next key offline in practice:** where it lives and how a
  rotation is performed.
- **Protocol versioning and capability negotiation.**
- **Relaying through intermediates:** deferred; revisit only if direct
  delivery proves insufficient.

## References

- Saltzer, Reed & Clark, "End-to-End Arguments in System Design," ACM TOCS 1984.
- Douceur, "The Sybil Attack," IPTPS 2002.
- Demers et al., "Epidemic Algorithms for Replicated Database Maintenance," PODC 1987.
- Meyer, "Range-Based Set Reconciliation," arXiv:2212.13567.
- Heilman, Kendler, Zohar & Goldberg, "Eclipse Attacks on Bitcoin's Peer-to-Peer Network," USENIX Security 2015.
- Bortnikov et al., "Brahms: Byzantine Resilient Random Membership Sampling," PODC 2008.
- Smith, "Key Event Receipt Infrastructure (KERI)," arXiv:1907.02143.
- Tarr, Lavoie, Meyer & Tschudin, "Secure Scuttlebutt," ACM ICN 2019.
- Fall, "A Delay-Tolerant Network Architecture for Challenged Internets," SIGCOMM 2003.
- BitTorrent BEP 5 (DHT), BEP 9 (metadata exchange), BEP 11 (PEX), BEP 14 (LSD), BEP 44 (mutable items).
- Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel," NDSS 2017 (cookie mechanism).
- Laurie & Clayton, "Proof-of-Work Proves Not to Work," WEIS 2004.
- Stiegler, "An Introduction to Petname Systems," 2005.
- Nesse, "The Smoke-Detector Principle," Annals of the NY Academy of Sciences, 2001.
