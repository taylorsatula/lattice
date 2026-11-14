# Lattice v2 Design (draft)

## Purpose

> Lattice was created originally so that Mira instances on the open internet
> could discover and communicate long after a central seed server went
> offline. I envision a system that is not ornamented.

Lattice connects peers over possibly shaky connections without a central
orchestrator. Instances in the same hive (a LAN, a tailnet, any network
where members reach each other directly) talk to each other, and instances
talk across the WAN. A message must be able to cross the mesh resiliently
to reach an instance the sender can't reach directly, and it should reveal
as little as possible to the nodes it passes through.

## Principles

1. **End-to-end.** Each hop guarantees only custody: the next hop durably
   stored the message. Only the recipient can confirm arrival, so arrival is
   confirmed by a receipt from the recipient. Confidentiality and sender
   authentication are end to end as well. Anything only the application can
   know (read, understood, acted on) is an application message.
   (Saltzer, Reed & Clark 1984)
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
6. **Links are the operator's job; routing across them is Lattice's.**
   WARP, Tailscale, Headscale, WireGuard, a public IP or port forwarding all
   provide direct links between instances, and Lattice contains no code for
   any particular network product. Lattice routes messages across whatever
   graph of links exists, so instances with no direct path still reach each
   other through intermediates.
7. **Don't foreclose non-IP transports.** Objects stay small and
   self-proving, and nothing depends on a synchronous round trip, so a
   radio mesh such as Meshtastic remains possible later without designing
   for it now.
8. **Reveal and retain as little as possible.** A node learns only what it
   needs in order to do its job, and keeps it only as long as it needs it.
   Lattice is not an anonymity network (§7), but nothing is published,
   exposed to hops or stored without a reason.

## 1. Identity

- **Keys:** Ed25519 for signing, X25519 for encryption.
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

- **Readable for display, key underneath** (a petname system). An instance
  may claim a display name in its signed record. The claim is optional and
  is never registered or checked network-wide.
- **A local name table on each instance** maps names to identifiers the
  first time it sees them, like SSH's `known_hosts`.
- **Collisions are shown, never silently resolved.** The first identifier
  an instance saw keeps the plain name; any later one is displayed with a
  short fingerprint suffix (`rocketcity#k7f3`). A name is never silently
  rebound to a different key.
- **Address format:** `user@name`, or `user@name#suffix` when shared out of
  band, so the recipient pins the correct identity on first contact. An
  instance that publishes no display name is reachable only by an address
  shared this way.
- **Envelopes, replies and contact lists use identifiers.** Names are
  resolved only at the edges: when a user types an address and when the app
  displays one. Renames don't break contacts.
- **Users are the instance's business.** Lattice authenticates instances;
  each instance vouches for its own users, as in email.

## 2. Peer record

There is one record type. Each instance publishes and periodically
refreshes its own. An instance is either **public** or **private**:

- **Public instances** publish endpoints and links, and can be routed
  through.
- **Private instances** publish neither. They name gateways instead (§7).

| Field | Present for | Purpose |
|---|---|---|
| identifier | All | Stable identity (§1) |
| current key + key event log | All | Verifies the signature and the rotation history |
| seq | All | Monotonic; the highest seq for an identifier wins |
| encryption key | All | X25519 key that messages to this instance are encrypted to |
| expiry | All | Signed coarse expiry, on the order of days |
| signature | All | By the current key, over the exact encoded bytes |
| display name | Optional | Petname claim |
| endpoints | Public | Addresses, each tagged with a scope (hive or WAN) |
| links | Public | Identifiers this instance has recently proven direct reachability to (capped, about 32) |
| gateways | Private | One to three identifiers that accept messages for this instance (§7) |
| capabilities / protocol version | All | Feature flags and negotiation |

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
  Hive-scoped endpoints and links are gossiped only within the hive and
  never over the WAN. Private and overlay addresses (RFC 1918,
  100.64.0.0/10 and similar) arriving over the WAN are dropped. This
  replaces v1's fixed SSRF blocklist.
- **Prove an endpoint before using it.** An endpoint counts as reachable
  only after a handshake at that address proves the far end holds the
  record's key. That stops anyone using the mesh to aim traffic at a victim.
- **Links come from proven handshakes.** An instance lists another as a
  link only after a recent successful handshake with it, and drops the link
  when it goes stale.
- **The encryption key** is part of the signed record, so it changes the
  way everything else in the record does: a new record with a higher seq.

## 3. Transport

- **Channels authenticated by the two instances' keys,** in the style of
  Noise, WireGuard or SSB's Secret Handshake. There are no certificate
  authorities and no dependence on DNS for trust. Each node always knows
  which neighbor handed it traffic.
- **WireGuard-style cookies under load.** Normally the handshake proceeds as
  usual. Under load the server keeps no state and answers with a cookie
  derived from the sender's address and a rotating secret. The sender must
  echo it back before the server spends any resources. It costs honest
  peers one extra round trip, only during an attack. There is no
  proof-of-work.
- **Every protocol object is self-proving.** Peer records are signed
  publicly. Messages are authenticated end to end inside their encryption
  (§6). Either way, objects stay independent of the transport that carries
  them.
- **Two layers of encryption.** The channel is encrypted hop by hop. Each
  message's content is also encrypted end to end, to the recipient's
  encryption key, so intermediate nodes never see it.

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
- **Hive-scoped data stays in the hive** (§2).
- **Neighbor selection** (Heilman et al. 2015; Brahms 2008):
  - Random, from peers grouped by network range.
  - Which peers to keep is chosen by a hash salted with a local secret, so
    an attacker can't aim at the table's slots.
  - A few anchor peers are persisted across restarts.
  - A peer is tested before being evicted.
- **Relay only what you would accept.**
- **Per-peer push limits** on unsolicited records.

## 6. Routing and delivery

Messages cross the mesh by **link-state routing over the existing gossip**.
This is the routing model of OSPF and IS-IS, hardened in the manner of
Perlman's Byzantine-robust link-state design (1988): signed link records,
robust distribution, multipath around misbehaving nodes. There are no
designated relays and no per-message flooding.

### The graph

- **The graph is the public backbone:** the public instances and their
  links, plus hive links inside a hive. Private instances appear only as
  "reachable via gateway G."
- **A link counts only if both ends list each other.** A node that lies can
  invent links only to nodes that also claim it, so it can't make itself look
  adjacent to everyone to attract traffic.
- **Paths are computed locally** with shortest-path over the current graph.
  At thousands of nodes this takes milliseconds, even on low-power hardware.

### The message

| Part | Readable by | Contents |
|---|---|---|
| Routing header | Every hop | Message id, routing destination (the recipient, or a gateway of a private recipient), expiry |
| Gateway layer | That gateway only (encrypted to its key) | The private recipient's identifier. Present only for private recipients |
| Envelope | Recipient only (encrypted to its key) | Sender identifier and user, recipient user, content, metadata, created time, a copy of the header fields, and the sender instance's signature over all of it |
| Padding | Nobody | Fills the message to its size bucket (§7) |

- **Immutable end to end.** The sender builds the whole message, and nothing
  changes in transit.
- **Hops learn nothing about the sender.** The sender's signature sits inside
  the envelope, so only the recipient can see who sent the message and check
  that it's genuine. The recipient also checks that the header matches the
  copy inside the envelope, so tampering by any hop is detected at the end.
- **Hops judge traffic by who handed it to them.** A hop checks that a
  message is well formed, fits a size bucket and hasn't expired. It then
  accepts it from the neighbor that handed it over, subject to that
  neighbor's limits (§8).

### Forwarding

1. **Sender:** builds, encrypts and pads the message at enqueue time and
   writes it to the durable outbound queue. The first attempt is made
   immediately.
2. **Each hop,** including the sender:
   - If it is the routing destination and the final recipient, it opens the
     envelope, verifies the sender's signature, hands the message to the
     application, and sends a receipt.
   - If it is a gateway, it opens the gateway layer, learns which private
     instance the message is for, and forwards it over its direct link to
     that instance.
   - Otherwise it computes the next hop toward the routing destination on
     its own current view of the graph. The route isn't fixed by the sender,
     so each hop uses the freshest information available.
   - **Loops are prevented by dedup.** A node that already holds or has held
     the message id answers "already have it" and takes no further action.
     The forwarding hop then picks its next-best hop. This holds even while
     hops' views of the graph disagree.
   - **Each hop may hold the message for a small random delay** before
     forwarding (§7).
3. **Custody transfer** (Fall 2003). The next hop accepts only after
   durably storing the message. Responsibility then passes to it, and the
   previous hop deletes its copy.
4. **No path right now:** the message waits at the furthest node that took
   custody, retrying with backoff, and moves on when the graph changes. It
   is dropped at expiry. This is delay-tolerant behavior: traversal
   continues as connectivity allows, rather than failing all at once.
5. **Leases.** A message stuck in "sending" past its lease returns to
   pending at whichever hop holds it, including after a crash.

### Receipts and recovery

- **End-to-end receipt.** The recipient returns a small receipt for the
  message id, signed inside its own envelope. It uses the same format and
  padding as any other message, addressed to the sender, or to the sender's
  gateway if the sender is private. Custody tells each hop its own job is
  done; only the receipt tells the sender the message arrived.
- **Retry on a disjoint path.** If no receipt arrives within the receipt
  timeout, the sender sends the message again over a path that avoids the
  intermediate nodes it expected earlier attempts to use. This routes
  around a node that accepts custody and then silently drops messages.
- **Idempotent receive by message id.** Every hop and the recipient keep a
  hash of each message id they have seen until the message expires, not
  merely until they have forwarded it. This one rule makes retries and
  multiple paths harmless and is also what prevents routing loops.
- **Failure classes:**
  - **Transient** (unreachable, overloaded, no path): retry with backoff.
  - **Permanent** (malformed, invalid signature at the recipient, unknown
    user at the recipient): stop. A permanent failure at the recipient
    comes back as a negative receipt.

### Transit

- **Every node may carry traffic for others.** Accepting transit traffic is
  each server's policy, bounded by per-neighbor rate limits and a transit
  storage cap (§8).
- **Only the public backbone is visible.** Anyone can see which public
  instances link to which. Private instances and hive-internal links are
  not visible outside their hive.

## 7. Privacy

Lattice is not an anonymity network. It doesn't re-encrypt messages at each
hop the way onion routing does, so the routing model stays simple. Within
that limit, it minimizes what any node can learn or keep.

### Measures

1. **The sender is hidden from hops.** The sender's signature and identity
   are inside the envelope (§6). Because every node carries transit
   traffic, the first hop can't tell whether its neighbor wrote a message
   or is forwarding one.
2. **Private instances.** A private instance publishes no endpoints and no
   links. Its record names one to three gateways it chooses, usually hive
   peers. Senders route to a gateway, and only the gateway can open the
   layer that names the real recipient. This is a one-layer form of
   Lightning's blinded paths.
3. **Only the public backbone is published.** Endpoints and links come only
   from public instances. Hive-scoped data never leaves the hive (§2).
4. **Size buckets.** Every message, receipts included, is padded to one of a
   few fixed sizes (for example 1, 4 and 16 KB), so size doesn't
   distinguish messages.
5. **Random per-hop delay.** Each hop holds a message for a small random
   time before forwarding, a few seconds by default and set per server.
   Store-and-forward delivery makes this nearly free. It blunts simple
   timing correlation. There is no cover traffic.
6. **Receipts look like messages.** Same format, same padding, no separate
   channel.
7. **Minimal retention.** After handing off custody, a hop deletes the
   message and keeps only a hash of its id for dedup. By default nothing
   logs senders or destinations per message, so a seized or compromised
   server reveals little.
8. **Optional display names.** An instance shared only by
   address-with-suffix doesn't need to announce a name to the whole mesh.

### Who learns what

| Party | Learns | Does not learn |
|---|---|---|
| Any node, from gossip | The public backbone, which identities exist, which gateways private instances use | Private instances' locations, hive-internal links |
| A hop relaying a message | The neighbor it came from, the neighbor it goes to, the routing destination, its size bucket, a rough time | The sender, the content, the full path |
| A gateway | The above, plus which of its private instances the message is for | The sender, the content |
| The recipient | The sender instance and user, the content | The path |

### What remains exposed

- **Colluding hops on the same path can link it,** because the message is
  identical at every hop. Re-encrypting at each hop is what onion routing
  adds, and Lattice deliberately doesn't.
- **An observer who sees the whole network** can still correlate timing.
  Random delay makes that harder but doesn't prevent it.
- **Gateways see their private instances' traffic.** That's why instances
  choose their own gateways, usually within their hive.
- **The set of identities is public** within the mesh, though not their
  locations.

## 8. Abuse resistance and the immune system

**The protocol enforces only validity:** records' signatures verify, formats
parse, size buckets and expiries hold. Everything else is server-level
policy.

**Accountability follows the link.** Hops can't see senders, so a hop holds
the neighbor that handed it traffic responsible for that traffic. A neighbor
is a proven link and costs something to establish; a sender key is free to
make. The recipient, which can see the sender, applies its own limits on
senders.

**Baseline server limits** cost honest traffic nothing:

- A rate limit per neighbor, on messages and on records.
- Per-neighbor limits on transit messages accepted for forwarding, and a cap
  on total transit storage.
- At the recipient: a rate limit per network range on first contact from
  unknown sender identifiers. The limit follows the neighbor's address
  range, so churning through fresh keys doesn't help.
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
  exchange that already happens. There is no new message type. Observations
  include a neighbor abusing rate limits or sending invalid data, senders its
  users report as spam, and a node on whose expected paths messages
  repeatedly fail to produce receipts.
- **Rule.** When peers from *k* distinct network ranges list the same
  identifier, the server applies a much tighter rate limit to it, stops
  relaying its records, and routes around it when other paths exist. When
  those lists drop it, the limits lift on their own.
- **Why this needs no reputation tracking:** a forged alarm can only slow
  its victim down for a while, so there's nothing to defend against and no
  caller reliability to track. A bad actor's reach also shrinks as more of
  the herd grows wary, because its records spread only through servers that
  haven't flagged it.

## 9. Time

- **Ordering uses seq numbers;** no clock is involved.
- **Replay protection** uses seq numbers plus the record of seen message
  ids.
- **The only timestamps are coarse signed expiries,** on peer records and
  messages, measured in days. Clocks only need to be right to within hours.

## 10. Operations (carried forward from v1)

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
- **No per-message logging of senders or destinations by default** (§7).
- **Lattice doesn't own users.** The application maps users and receives
  messages.

## 11. Removed from v1

| v1 | v2 |
|---|---|
| Server UUID + name + key | Identifier derived from key events |
| RSA-2048, fingerprint of PEM text | Ed25519, fingerprint of key bytes |
| Signing re-serialized JSON | Signing the exact encoded bytes |
| Network-wide name registration, confidence scores | Local petname table |
| Domain queries, route cache, hop counts, confidence decay | Full-membership gossip; link-state routing over it |
| Direct delivery to the recipient's endpoint only | Hop-by-hop forwarding with custody across the mesh |
| Plaintext content; sender visible to the receiving daemon's path | Content and sender encrypted end to end; hops see neither |
| Every server's endpoints published | Endpoints published only by public instances |
| Admission only via pinned bootstrap | Any valid record from any peer; root as introducer |
| Mandatory bootstrap pins | Optional fingerprint, trust on first use otherwise |
| Peer exchange defined but unused | Anti-entropy is the core mechanism |
| Trust levels (`trusted`/`untrusted`/…) | Local policy + immune system |
| Signed delivery acks from the receiving server | Custody per hop + end-to-end receipt from the recipient |
| Separate key rotation and cyanide pill | Pre-rotation; abandonment is a rotation |
| Tiered peer aging, cleanup jobs | Soft-state expiry |
| Short timestamp freshness windows | Seq numbers + seen ids + coarse expiry |
| Fixed private-address blocklist | Endpoint scope rule |
| Saturation metric | Removed |
| External scheduler driving the daemon | Self-running daemon |

## 12. Open questions

- **Wire transport:** HTTP(S) carrying the objects, or a Noise-style channel
  over TCP or UDP. This determines how the handshake and cookie mechanism
  are built.
- **Encoding:** deterministic CBOR or another canonical binary encoding, or
  signing raw payload bytes inside a simple envelope.
- **Handoff to the application:** whether the app pulls from Lattice's
  inbox or Lattice pushes to a webhook. This determines when the recipient
  learns a user is unknown and sends its negative receipt.
- **Hive configuration:** how an operator declares hive networks, and which
  multicast discovery mechanism to use (mDNS or a minimal custom
  announcement).
- **Parameters:** record and message expiry, gossip cadence, storage and
  push caps, rate limits, the *k* threshold for the wary rule, wary list
  size.
- **Keeping the next key offline in practice:** where it lives and how a
  rotation is performed.
- **Protocol versioning and capability negotiation.**
- **Routing details:**
  - The path metric: hop count, or something weighted by link quality.
  - How often links are re-proven and when a stale link is dropped.
  - The receipt timeout and how many disjoint-path retries to make.
  - Whether a sender may send over two disjoint paths at once for
    high-priority messages.
- **End-to-end encryption scheme:** a sealed-box construction to X25519, or
  a ratcheting session between instances that talk often. The first is
  simpler and doesn't need a round trip.
- **Privacy details:**
  - The size buckets, and whether messages larger than the largest bucket
    are split or refused.
  - The default per-hop delay range.
  - How a private instance chooses its gateways, how many it lists, and what
    a private instance with no hive uses as a gateway.
  - Whether recipients may accept messages from anonymous senders. For now
    the recipient always learns the sender.
- **Scale ceiling:** if nodes can no longer hold the whole graph (very large
  meshes, or tiny radio devices), the documented next step is greedy routing
  on a self-re-rooting spanning tree, as in Yggdrasil (Kleinberg 2007).

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
- Perlman, "Network Layer Protocols with Byzantine Robustness," MIT PhD thesis, 1988 (MIT-LCS-TR-429).
- Moy, "OSPF Version 2," RFC 2328, 1998.
- Kleinberg, "Geographic Routing Using Hyperbolic Space," INFOCOM 2007.
- Yggdrasil network whitepaper and Ironwood routing library (greedy tree routing).
- Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format," IEEE S&P 2009 (the onion format Lattice deliberately doesn't adopt).
- Lightning Network BOLT 4, onion routing and route blinding (the full form of the gateway layer).
- Piotrowska et al., "The Loopix Anonymity System," USENIX Security 2017 (per-hop random delay; cover traffic not adopted).
- BitTorrent BEP 5 (DHT), BEP 9 (metadata exchange), BEP 11 (PEX), BEP 14 (LSD), BEP 44 (mutable items).
- Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel," NDSS 2017 (cookie mechanism).
- Laurie & Clayton, "Proof-of-Work Proves Not to Work," WEIS 2004.
- Stiegler, "An Introduction to Petname Systems," 2005.
- Nesse, "The Smoke-Detector Principle," Annals of the NY Academy of Sciences, 2001.
