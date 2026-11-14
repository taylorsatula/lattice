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
7. **Don't foreclose non-IP transports.** Objects stay self-proving, and
   nothing depends on a synchronous round trip, so a radio mesh such as
   Meshtastic remains possible later without designing for it now.
8. **Reveal and retain as little as possible.** A node learns only what it
   needs in order to do its job, and keeps it only as long as it needs it.
   Lattice is not an anonymity network (§7), but nothing is published,
   exposed to hops or stored without a reason.
9. **Identifiers, not names.** Lattice deals only in full cryptographic
   identifiers. Human-readable naming belongs to the application's address
   book.

## 1. Identity and cryptography

### Primitives

| Purpose | Primitive |
|---|---|
| Signatures (identity, records, envelopes, receipts) | Ed25519 |
| Channel (Noise static key) | X25519 |
| End-to-end encryption (envelope, gateway layer) | X-Wing: hybrid X25519 + ML-KEM-768 (FIPS 203) |
| Symmetric encryption | ChaCha20-Poly1305 |
| Hashes, identifiers, commitments | BLAKE3, full 256 bits, never truncated |

- **Ed25519's 128-bit security level is the current standard** for
  signatures. Strength against quantum attacks on signatures comes from
  pre-rotation (below), not from longer curve keys.
- **The hybrid KEM defends against "harvest now, decrypt later":** recording
  encrypted messages today to break them with a future quantum computer.
  Breaking an envelope requires breaking both X25519 and ML-KEM-768. This
  is the same approach OpenSSH, Signal and Apple's iMessage have adopted.
- **Each key has exactly one purpose.** The channel key is never used for
  envelopes, and the signing key is never used for encryption.

### Pre-rotation (from KERI)

- **Every key state publishes the hash of the *next* signing key,**
  committed to before it's needed. A rotation is signed by that
  pre-committed key, reveals it, and publishes the hash of the key after
  that.
- **Theft can't hijack the identity.** Someone who steals the current key
  can sign messages but can't rotate, because the owner's rotation with the
  committed key always wins.
- **Quantum recovery.** The next key exists publicly only as a hash, which a
  quantum computer can't invert. If Ed25519 is ever broken, owners can
  still rotate safely to a post-quantum signature scheme. The KERI
  specification describes this explicitly.
- **Abandonment** (the cyanide pill) is a rotation with no next-key
  commitment. This one mechanism replaces both v1's key rotation and its
  separate revocation.
- **The next private key is stored separately from the running daemon.**
  If the current and next keys are both stolen, recovery isn't possible.
- **The channel and envelope keys** are listed in the peer record and signed
  by the current signing key. They change by publishing a new record (§2);
  pre-rotation guards the signing key, which is the identity's authority.

### Identifier and addresses

- **Identifier:** the BLAKE3 hash of the instance's first key event (the
  initial signing key plus the first next-key commitment). It stays the
  same across rotations and replaces v1's separate UUID.
- **Key event log:** the inception event plus any rotations. It is short,
  append-only and self-verifying.
- **Address format:** `<service>:<mailbox>@<identifier>`, for example
  `mira:taylor@<identifier>`, with the identifier written as base32, 52
  characters. Addresses are exchanged by copy-paste or QR code, never typed.
- **No names on the network.** Lattice publishes no display names and keeps
  no name table. An application establishes a link using the full address
  and maps its own short name (`west`) to the identifier in its address
  book. Lattice's local API accepts identifiers only.
- **Lattice is general-purpose.** Any number of applications ("services")
  can use one instance. Lattice routes on the identifier and delivers on the
  service. The mailbox is opaque to Lattice and belongs to the service, so
  users and their schemas are the application's business.

## 2. Peer record

There is one record type. Each instance publishes and periodically
refreshes its own: one record per scope, so an instance on a hive publishes
a WAN record and a hive record. A signed record can't have its hive data
removed before it crosses the WAN, so the two are separate and the hive
record never leaves the hive. Exact layouts are in `V2_SPEC.md`.

An instance is either **public** or **private**:

- **Public instances** publish endpoints and links, and can be routed
  through.
- **Private instances** publish neither. They name gateways instead (§7).

| Field | Present for | Purpose |
|---|---|---|
| identifier | All | Stable identity (§1) |
| signing key + key event log | All | Verifies the signature and the rotation history |
| scope | All | WAN or hive |
| seq | All | Monotonic; the highest seq for an (identifier, scope) wins |
| channel key | All | X25519 static key for the Noise handshake |
| envelope key | All | X-Wing public key that messages to this instance are encrypted to |
| expiry | All | Signed coarse expiry, on the order of days |
| signature | All | By the current signing key, over the exact encoded bytes |
| endpoints | Public | Addresses, each tagged with a scope (hive or WAN) |
| links | Public | Identifiers this instance is currently linked to (capped, about 32) |
| gateways | Private | One to three identifiers that accept messages for this instance (§7) |
| capabilities / protocol version | All | Feature flags and negotiation |

- **Last-writer-wins by seq,** as in BitTorrent's BEP 44 mutable items.
  Partitions merge with no special logic.
- **Soft state.** The owner refreshes the record before it expires. A
  record that isn't refreshed fades out everywhere, so no cleanup jobs or
  liveness logic are needed.
- **Size capped** at about 3 KB. The ML-KEM-768 public key alone is about
  1.2 KB.
- **Equivocation proof.** Two different records signed by the same key with
  the same seq prove misbehavior or a stolen key. Anyone can verify this
  from the two records alone.
- **Endpoint scope rule.** An address is only valid in the context it was
  learned in. The operator declares which networks make up their hive.
  Hive-scoped endpoints and links are gossiped only within the hive and
  never over the WAN. Private and overlay addresses (RFC 1918,
  100.64.0.0/10 and similar) arriving over the WAN are dropped. This
  replaces v1's fixed SSRF blocklist.
- **IP addresses are preferred to hostnames.** An endpoint may list IP
  addresses alongside its URL, and connecting nodes use them when present,
  so no DNS lookup reveals which peer is being contacted. When a lookup is
  unavoidable it uses encrypted DNS (DoH or DoT) and is cached.
- **The scope rule is applied to resolved addresses at connect time.** A
  hostname in a WAN record can later resolve to a private address (DNS
  rebinding), so every connection attempt resolves the name, checks every
  resulting address against the record's scope, and connects only to an
  address that passes. Checking record contents alone isn't enough.
- **Prove an endpoint before using it.** An endpoint counts as reachable
  only after a handshake at that address proves the far end holds the
  record's channel key. That stops anyone using the mesh to aim traffic at a
  victim.
- **A link is a live authenticated connection** (§3). An instance lists
  another as a link while it holds a connection to it, and drops it when
  the connection goes stale.

## 3. Transport

- **Noise inside a WebSocket.** The WebSocket gets through reverse proxies,
  Cloudflare Tunnel and plain TCP alike. The Noise channel inside
  authenticates both instances by key, so there are no certificate
  authorities and no dependence on DNS for trust. Each node always knows
  which neighbor handed it traffic.
- **Handshake patterns:**
  - **IK** when the initiator already holds the responder's record, which is
    the usual case. It takes one round trip and hides the initiator's
    identity from passive observers.
  - **XX** for a root given without an identifier, where no key is known in
    advance.
- **WireGuard-style cookies under load,** sent before the Noise handshake.
  Normally the handshake proceeds as usual. Under load the server keeps no
  state and answers with a cookie derived from the client's address and a
  rotating secret. The client must echo it back before the server spends
  any resources. It costs honest peers one extra round trip, only during an
  attack. There is no proof-of-work.
- **Connections are long-lived and bounded.** Each instance holds
  authenticated connections to a bounded set of neighbors (about 8 to 32).
  Those connections are its links, and they carry gossip, routing traffic
  and custody alike.
- **Real frames go out immediately; snow fills the gaps.** Every frame after
  a handshake is padded to a size bucket. Real frames are sent as soon as
  they're ready. Dummy frames ("snow") fall at random in the quiet moments
  between them (§7). No unencrypted WebSocket control frames are used;
  keepalives are encrypted frames like any other.
- **Probe-resistant listener.** The WebSocket upgrade path is derived from
  the responder's channel key. Anyone holding the responder's record can
  compute it; a scanner can't, and a wrong path gets the same generic 404 as
  any web server. With the status endpoint disabled, an internet scan finds
  an ordinary web server and nothing more.
- **Handshake frames are padded** to a size bucket too, so the handshake
  pattern in use (IK, XX, cookie) isn't visible from message sizes.
- **Every protocol object is self-proving.** Peer records are signed
  publicly. Messages are authenticated end to end inside their encryption
  (§6). Either way, objects stay independent of the transport that carries
  them.
- **Two layers of encryption.** The Noise channel is encrypted hop by hop.
  Each message's content is also encrypted end to end with the hybrid KEM,
  so intermediate nodes never see it.

## 4. Bootstrap and discovery

The layers, tried in order:

1. **Saved peers** from previous runs. A node that has ever been connected
   never needs its root again.
2. **A configured root or roots.** Any instance can be any other instance's
   root. A root is given as an address with an optional identifier.
   - Without an identifier, the first contact is trusted on first use, using
     the XX handshake.
   - With an identifier, the root's identity is verified, using IK.
   - A missing identifier is allowed but logged as a warning.
3. **Multicast discovery on the hive.** On a LAN, members find each other
   with no configuration. Multicast runs only on interfaces explicitly
   configured as hive, never by default, so a node on café Wi-Fi doesn't
   announce itself.

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
- **Per-neighbor push limits** on unsolicited records.

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
- **Distances are computed locally** over the current graph: each node
  knows how many hops every neighbor is from any destination. At thousands
  of nodes this takes milliseconds, even on low-power hardware.

### Randomized routes

Messages don't take the same path every time. Varied routes spread traffic
across more nodes, which adds to the natural hum that covers everyone, and
they deny a watcher a predictable path to sit on. Randomness enters at two
levels.

**Random turns at every hop.**
- **Progress:** a hop chooses uniformly at random among all neighbors closer
  to the destination than itself, not always the single shortest one.
- **Sideways:** with a small probability (15% by default), it instead takes
  a neighbor that is *no closer*.
- **No loops:** dedup already answers "already have it" when a message
  reaches a node that has seen it, so a wandering message can never revisit
  a node. If every sideways choice has already seen it, the hop takes a
  progress step, which is always available while a path exists.
- **Cost:** the message is unchanged, and on average the route grows by well
  under one hop. Hops dispatch immediately, so responsiveness holds.

**Waypoints: the sender takes the long way round.** This is Valiant load
balancing (Valiant 1982). The sender routes a message to a randomly chosen
public waypoint first, and from there on to the recipient.
- **The sender builds everything in advance:** an outer header addressed to
  waypoint W, a layer sealed to W containing the real header (and the
  gateway layer, if any), and the envelope bound to the real header.
- **Hops on the first leg** see only "for W."
- **W opens its layer,** replaces the outer header with the real one, and
  forwards toward the recipient. Everything W sends on was built by the
  sender, so nothing becomes mutable or unverifiable.
- **Each leg has its own message id.** A node can easily land on both legs,
  and with a single id it would answer "already have it" to the second leg.
- **Privacy:** first-leg hops never learn the destination. W learns the
  recipient but not the sender. Second-leg hops learn the recipient but not
  where the message came from.
- **Cost:** the route roughly doubles, and so does the transit it creates.
  That extra transit is real traffic covering everyone. Waypoints are a
  per-message share the operator turns up, like snow: 0% by default, set per
  instance, or requested per message through `send`.

### The message

| Part | Readable by | Contents |
|---|---|---|
| Outer header | First-leg hops | Leg message id, the waypoint, expiry. Present only when a waypoint is used |
| Waypoint layer | That waypoint only (sealed to its envelope key) | The routing header and the gateway layer. Present only when a waypoint is used |
| Routing header | Every hop after the waypoint, or every hop if there is none | Message id, routing destination (the recipient, or a gateway of a private recipient), expiry |
| Gateway layer | That gateway only (sealed to its envelope key) | The private recipient's identifier. Present only for private recipients |
| Envelope | Recipient only (sealed to its envelope key) | Sender identifier, sending and receiving service and mailbox, created time, an opaque application payload, and the sender's signature over the header and all of it |
| Padding | Nobody | Fills the message to its size bucket (§7) |

- **Built entirely by the sender.** Nothing in the message is created or
  changed in transit. The one transformation, at a waypoint, uncovers a
  header the sender sealed in advance.
- **The payload is opaque.** Lattice never interprets it, so applications
  define and change their own schemas freely.
- **Hops learn nothing about the sender.** The sender's signature sits inside
  the envelope, so only the recipient can see who sent the message and check
  that it's genuine.
- **Headers are bound to their sealed layers.** The routing header is the
  associated data of the gateway layer and the envelope, and the outer
  header is the associated data of the waypoint layer. A hop that alters a
  header makes decryption fail at the next node that opens a layer.
- **Hops judge traffic by the link it arrived on.** A hop checks that a
  message is well formed, fits a size bucket, hasn't expired, and doesn't
  carry an expiry beyond the maximum horizon (§9). Whether it takes custody
  is then decided by fair-share custody for the link the message arrived on
  (step 3 below).
- **Overhead.** Each hybrid-encrypted layer carries about 1.1 KB of KEM
  ciphertext, so the smallest size bucket is at least 2 KB. A message with a
  waypoint, or to a private instance, carries an extra layer for each.

### Forwarding

1. **Sender:** builds, encrypts and pads the message at enqueue time and
   writes it to the durable outbound queue. The first attempt is made
   immediately. The application may give a message a priority, which orders
   the sender's own outbound queue (higher first, oldest first within a
   priority). Priority is never put on the wire, so it reveals nothing to
   hops.
2. **Each hop,** including the sender:
   - If it is the routing destination and the final recipient, it opens the
     envelope, verifies the sender's signature, hands the message to the
     application, and sends a receipt.
   - If it is the waypoint, it opens the waypoint layer, replaces the outer
     header with the routing header it finds there, and forwards toward the
     routing destination.
   - If it is a gateway, it opens the gateway layer, learns which private
     instance the message is for, and forwards it over its direct link to
     that instance.
   - Otherwise it chooses the next hop toward the current destination on its
     own current view of the graph, with random turns (above). The route
     isn't fixed by the sender, so each hop uses the freshest information
     available.
   - **Loops are prevented by dedup.** A node that already holds or has held
     the message id answers "already have it" and takes no further action.
     The forwarding hop then picks its next-best hop. This holds even while
     hops' views of the graph disagree.
   - **The forward goes out immediately.** An operator can optionally add a
     small random hold before forwarding (§7); the default is none.
3. **Custody transfer** (Fall 2003) **with fair shares.** The next hop
   accepts only after durably storing the message. Responsibility then
   passes to it, and the previous hop deletes its copy. Acceptance follows
   one rule:

   > For each destination, a hop holds a bounded amount of traffic, and its
   > upstream links share that allowance equally. When a link's share for
   > that destination is full, new messages from that link get "busy, retry
   > later."

   Busy is a transient failure. The upstream hop keeps the message and
   retries with backoff, while applying the same rule to its own upstream
   links. Gateways and recipients apply the same rule as every other hop.
   §8 explains how this contains floods.

   At the recipient, each service's inbox is also capped. When an
   application stops fetching and its inbox fills, the recipient answers
   busy for that service, so a stalled application pushes back across the
   mesh through the same mechanism.
4. **No path right now:** the message waits at the furthest node that took
   custody, retrying with backoff, and moves on when the graph changes. It
   is dropped at expiry. This is delay-tolerant behavior: traversal
   continues as connectivity allows, rather than failing all at once.
5. **Leases.** A message stuck in "sending" past its lease returns to
   pending at whichever hop holds it, including after a crash.

### Receipts and recovery

- **End-to-end receipt.** Once the recipient instance has durably stored the
  message for the target service, it returns a small receipt for the message
  id, signed inside its own envelope. It uses the same format and padding as
  any other message, addressed to the sender, or to the sender's gateway if
  the sender is private. Custody tells each hop its own job is done; only
  the receipt tells the sender the message arrived. Whether the application
  read or accepted it is application-level and goes in the application's own
  messages.
- **Retry through a fresh waypoint.** If no receipt arrives within the
  receipt timeout, the sender sends the message again through a different,
  randomly chosen waypoint, whatever the waypoint share. A new waypoint
  takes the message over a largely different route by construction, which
  routes around a node that accepts custody and then silently drops
  messages. The retry keeps the same real message id, so the recipient
  dedups it if an earlier attempt did arrive.
- **Idempotent receive by message id.** Every hop and the recipient keep a
  hash of each message id they have seen until the message expires, not
  merely until they have forwarded it. This one rule makes retries and
  multiple paths harmless and is also what prevents routing loops.
- **Failure classes:**
  - **Transient** (unreachable, busy, no path): retry with backoff.
  - **Permanent** (malformed, failing verification at the recipient, no such
    service at the recipient): stop. A permanent failure at the recipient
    comes back as a negative receipt. Lattice has no concept of users, so it
    never rejects on a mailbox.

### Transit

- **Every node may carry traffic for others,** bounded by fair-share custody
  and a total transit storage cap (§8).
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
3. **Randomized routes.** Random turns at each hop, and optional waypoints,
   vary the path every time (§6). With a waypoint, first-leg hops never
   learn the destination.
4. **Only the public backbone is published.** Endpoints and links come only
   from public instances. Hive-scoped data never leaves the hive (§2).
5. **Size buckets for every frame.** Every frame on a link (messages,
   receipts, custody replies, gossip, keepalives and dummies) is padded to
   one of a few fixed sizes (2, 8 and 32 KB). Size distinguishes nothing,
   and the gossip that flows constantly becomes indistinguishable from
   messages.
6. **Snow: cover traffic that fills the quiet.** See below.
7. **Receipts look like messages.** Same format, same padding, no separate
   channel.
8. **Minimal retention.** After handing off custody, a hop deletes the
   message and keeps only a hash of its id for dedup. By default nothing
   logs senders or destinations per message, so a seized or compromised
   server reveals little.
9. **No names on the network.** Records carry no display names (§1), so the
   mesh learns nothing about what an instance calls itself.

### Cover traffic: snow

Lattice is built for quick delivery first. Cover traffic is snow thrown in
around real traffic, never a metronome that real traffic has to wait for.

**Most cover is natural.** Every node relays other nodes' traffic, so an
outside observer watching a node's uplink already sees a stream that is
mostly not that node's own. Store-and-forward is constantly moving data
through every node, and none of it can be attributed. Snow only matters when
that natural traffic is thin.

**Snow tops up the quiet.** Each node emits dummy frames at random times,
as a Poisson process at the node's *snow level*. A snow tick is skipped if a
real frame went out since the previous tick. The node's observed rate is
then roughly whichever is higher, its snow level or its real traffic:

- **Below the snow level,** an observer sees the same random fall of frames
  whether the node is idle or active. Activity is hidden.
- **Above it,** snow stops entirely, because real and transit traffic
  already provide the cover. A busy node emits almost no snow.

The snow level therefore has a plain meaning: it's the rate below which a
node's activity is invisible. To hide a daily rhythm, an operator sets it at
or above the node's typical daytime traffic. The default is light: enough to
blur a quiet node's occasional messages, without real cost.

**Snow looks like real traffic.**
- **Sizes:** dummies draw their size from the node's recent real mix, but
  every bucket keeps a guaranteed minimum share (10% each). A single large
  frame on a quiet node is then unremarkable.
- **Exchanges:** a real offer gets a custody reply, so a frame that never
  gets an answer would mark itself as a dummy. A share of snow frames
  (25% by default) asks for an echo, and the receiving neighbor answers with
  a dummy after a short random delay, mimicking a request and its reply.
- **Links:** each snow frame goes out on a random current link.

**Snow is per node, not per link.** An outside observer watches a node's
uplink and sees all its links at once, so per-link cover would multiply the
cost for no added protection. A node's snow cost doesn't depend on network
size.

**What it costs.** At the default snow level of two frames a minute, an idle
node sends roughly 15 MB a day and receives about the same. A node whose real
traffic is above its snow level pays nothing.

**Turning it up.** Someone who wants a really snowy network raises the snow
level. Someone who also wants timing blurred sets a *hold*: a random delay of
up to that many milliseconds before each real frame goes out. Both default
to off-or-light, because Lattice favors quick dispatch.

**Precedent:** Crowds (Reiter & Rubin 1998) hides a node's traffic in traffic
it relays for others; Tarzan (Freedman & Morris 2002) confines cover to a
node's neighbor set; Loopix (Piotrowska et al. 2017) uses Poisson-timed
cover.

### Who learns what

| Party | Learns | Does not learn |
|---|---|---|
| Any node, from gossip | The public backbone, which identities exist, which gateways private instances use | Private instances' locations, hive-internal links, any names |
| A hop relaying a message | The neighbor it came from, the neighbor it goes to, the current destination (a waypoint, the recipient, or a gateway), its size bucket, a rough time | The sender, the content, the full path; on a first leg, the recipient |
| A waypoint | The above, plus the routing destination after it | The sender, the content |
| A gateway | The above, plus which of its private instances the message is for | The sender, the content |
| The recipient | The sender instance and user, the content | The path |

### What remains exposed

- **Colluding hops on the same path can link it,** because inside the Noise
  channel the message is identical at every hop. Re-encrypting at each hop is
  what onion routing adds, and Lattice deliberately doesn't. This applies to
  insiders only; outside observers see different ciphertext on every link.
- **Neighbors know which frames are dummies.** Cover traffic hides activity
  from outside observers, not from the node at the other end of the link.
- **Activity above the snow level is visible.** When a node's traffic
  exceeds its snow level, an observer sees more frames, though not which are
  the node's own and which are transit.
- **Bursts have a shape.** Real frames go out immediately, so a burst of
  them looks different from Poisson-timed snow even below the snow level.
  A hold setting blurs this, at the cost of latency.
- **A daily rhythm is visible** unless the snow level is set above daytime
  traffic.
- **That a node runs Lattice is visible.** Fixed frame sizes and a random
  fall of encrypted WebSocket frames are a fingerprint of their own, as are
  links opening and closing. Lattice aims for "you can tell it's Lattice,
  but not what it's doing," not for disguising itself as other traffic.
- **An observer who sees the whole network** can still attempt timing
  correlation. Store-and-forward re-times traffic at every hop, and that
  also erases timing patterns an active observer might impose (traffic
  watermarking), but it doesn't make correlation impossible.
- **Who a node connects to is visible** to its ISP. Hiding that is the job of
  the reachability layer: behind WARP or Tailscale, the ISP sees only
  Cloudflare or the tailnet.
- **Gateways see their private instances' traffic.** That's why instances
  choose their own gateways, usually within their hive.
- **A waypoint knows the recipient,** just as a gateway does, though not the
  sender. Waypoints are chosen at random per message, so no single waypoint
  sees a pattern.
- **The set of identities is public** within the mesh, though not their
  locations.
- **Envelopes have no forward secrecy.** They are encrypted to the
  recipient's published envelope key, so whoever later steals that private
  key can decrypt recorded envelopes sent to it. Rotating the envelope key
  regularly (a new record with a higher seq, deleting the old private key)
  limits how much a single theft exposes.
- **Deleting a key file doesn't guarantee the key is gone.** The mitigation
  above depends on old envelope private keys really being destroyed. On SSDs
  and journaling filesystems, deleting or even overwriting a file doesn't
  guarantee the bytes are unrecoverable. Real assurance needs full-disk
  encryption on the host, or keeping private keys only in memory-backed
  storage such as systemd credentials. Lattice deletes old keys, but
  promises no more than deletion can deliver.
- **Routing headers are protected only classically.** The hybrid KEM
  protects envelope content. The Noise channel uses X25519 alone, so a
  future quantum adversary that recorded traffic could recover routing
  headers, but not content or senders.

## 8. Abuse resistance and the immune system

**The protocol enforces only validity:** records' signatures verify, formats
parse, size buckets and expiries hold. Everything else is server-level
policy.

**Accountability follows the link.** Hops can't see senders, by design.
Attribution exists in only two places without weakening privacy: the link a
message arrived on, which every hop knows, and the recipient, which sees the
sender. Abuse control uses only those two.

### Fair-share custody

The custody rule in §6 is the core of abuse control. Each hop gives each
destination a bounded allowance, shared equally among its upstream links.
This is fair queuing (Demers, Keshav & Shenker 1989) applied to custody
rather than to packets.

Consider an abuser A flooding recipient R along A → X → Y → G → R:

- At G, traffic arriving from Y gets only Y's share of R's allowance.
  Traffic reaching G through other neighbors is unaffected.
- At Y, traffic arriving from X gets only X's share. At X, A gets only its
  own share.
- Each full share answers busy, so pressure accumulates hop by hop back
  toward A.

The only senders affected are those whose path to R shares A's branch,
which is A's own neighborhood. Harm stays local to where the abuser is
attached.

**Buying more shares doesn't work.** An abuser can't open many links to one
node to collect extra shares, because link slots are capped, grouped by
network range, and chosen by a secret-salted hash (§5). The eclipse defenses
cover this too.

**There is no separate intake or first-contact mechanism.** Gateways and
public recipients apply the same custody rule as every other hop. Whether a
recipient welcomes strangers is its own policy, applied after it opens the
envelope.

**What remains:** an abuser can still use transit bandwidth within its own
branch, and a recipient still decrypts whatever reaches it. Both are bounded
by the shares. Both fall mostly on the abuser's own neighbors, which are the
nodes best placed to fix it at the source by demoting or dropping that link.

### Baseline limits

All of these cost honest traffic nothing:

- Fair-share custody per destination per upstream link (§6).
- A cap on total transit storage.
- A cap on each service's inbox at the recipient, enforced through busy.
- A maximum expiry horizon on messages and records (§9), which bounds how
  long anything can occupy custody, dedup or record storage.
- A rate limit per neighbor on records and gossip.
- A fixed cap on stored records, with eviction by the secret-salted hash.
- Soft-state expiry.
- Local bans and link demotion, based on the server's own direct evidence.
- At the recipient, any sender policy it chooses, applied after opening the
  envelope.

### Immune system

This is optional, layered on top of fair-share custody. The model is herd
alarm signaling: an alarm triggers vigilance, never flight, and false alarms
are cheap, so the herd can afford to be trigger-happy (the smoke detector
principle).

- **Invariant:** secondhand alarms can only slow a key down. Only direct
  evidence, or an equivocation proof, can exclude it.
- **Wary list.** Each server attaches a short, capped, expiring list of
  identifiers it's wary of, based on its own observations, to the gossip
  exchange that already happens. There is no new message type. Observations
  include a neighbor abusing rate limits or sending invalid data, senders its
  users report as spam, and a waypoint or neighbor through which messages
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
- **Expiries have a maximum horizon.** Senders choose expiries, so hops
  refuse messages whose expiry is further out than a fixed maximum (on the
  order of 14 days), and gossip refuses records whose expiry is further out
  than the record maximum. Without this, one sender could make a message or
  record occupy every node's storage for a year. The horizon also puts a
  hard bound on the size of the seen-id table.

## 10. Implementation and operations

### Implementation

- **Rust, with `unsafe` forbidden.** Every Lattice crate declares
  `#![forbid(unsafe_code)]`, enforced in CI.
- **Dependencies:** that rule covers Lattice's own code, not its
  dependencies, so dependencies are chosen deliberately:
  - Prefer pure-Rust crates.
  - Audit what is pulled in.
  - Track the remaining `unsafe` with `cargo-geiger`.
- **Async runtime:** Tokio, with no blocking calls on async tasks.
- **Storage:** redb, a pure-Rust ACID embedded database, in a single file.
  It keeps C code out of the stack.
- **A simulated mesh is built first.** A test harness runs many nodes in one
  process over in-memory links and injects partitions, dropped and slow
  links, crashes during custody, and lying or dropping nodes. Every protocol
  rule is verified there before the real daemon depends on it.
- **Bounded decoding of untrusted input.** The CBOR decoder enforces a
  maximum nesting depth and maximum array, map and byte-string lengths, and
  checks declared lengths before allocating. The WebSocket layer enforces the
  frame size cap before assembling a frame in memory.
- **Cheapest check first.** Untrusted input is rejected by the cheapest test
  that can reject it, before any expensive work:
  - **A new connection:** frame size, then the handshake checksum, then the
    cookie when under load, then the Noise handshake.
  - **A message offered for custody:** size bucket, then expiry and
    horizon, then dedup, then fair share, then storage.
  - **At the recipient:** decryption, which fails fast, then signature
    verification.
- **Secrets and randomness.** Secrets (such as service secrets on the local
  API) are compared in constant time. Keys, message ids, salts and delays
  come from the operating system's random number generator.
- **Versioning.** Every wire object carries a protocol version (`V2_SPEC.md`
  §1), and the store carries a schema version, with explicit migrations run
  at startup when the schema changes in a future release. There is no
  compatibility with v1, on the wire or in storage; v2 starts clean.
- **Client libraries.** Lattice ships small client libraries for the local
  API, starting with Rust and Python (for MIRA), so applications don't
  implement the framing themselves.

### Operations (carried forward from v1)

- **The daemon runs its own timers.** No external scheduler calls admin
  endpoints.
- **Secrets** come from systemd credentials (encrypted when available), then
  from files with mode 0600/0700. Never from environment variables.
- **Private key files are created with mode 0600** from the start.
- **Keys are checked at startup.** The daemon loads all key material and
  performs a test signature and a test decapsulation before serving, so a
  corrupt or mismatched key stops it immediately instead of failing at the
  first message.
- **Safe default listen address.** The WebSocket listener binds only to
  configured hive interfaces by default, and to public interfaces only when
  the instance is in public mode.
- **Optional public status endpoint.** A plain HTTP `GET /status` on the
  WebSocket listener reports only that the node is up, whether it is
  accepting custody (not draining), and which protocol versions it speaks.
  It is enabled by default and disabled by a single configuration flag.
  When disabled, any request that isn't a WebSocket upgrade gets the same
  generic 404 as an unknown path, so a quiet node reveals nothing beyond an
  open WebSocket endpoint. See `V2_SPEC.md`.
- **Draining.** An admin drain operation stops accepting new custody
  (answering busy), keeps handing off what's held, and reports when empty,
  so planned shutdowns lose nothing and strand nothing.
- **A hardened systemd unit:** dedicated user, `ProtectSystem=strict`,
  minimal writable paths, resource limits, a single process owning all
  state.
- **Local API.** Applications talk to Lattice over a Unix socket that is
  never exposed to the network. Each service authenticates with its own
  configured secret and can read only its own inbox. Admin operations use a
  separate owner-only socket and the `latticectl` CLI. Details are in
  `V2_SPEC.md`.
- **Bounded inputs:** caps on frame and field sizes, and timeouts on every
  network operation.
- **No per-message logging of senders or destinations by default** (§7).
- **Lattice doesn't own users.** Applications own their users, their
  mailboxes, their address books and their payload schemas.

## 11. Removed from v1

| v1 | v2 |
|---|---|
| Python, FastAPI, SQLite | Rust with `unsafe` forbidden, Tokio, redb |
| HTTPS JSON endpoints | Noise channel inside a WebSocket |
| Server UUID + name + key | Identifier derived from key events |
| RSA-2048, fingerprint of PEM text, truncated fingerprints | Ed25519, hybrid X25519 + ML-KEM-768, full 256-bit BLAKE3 |
| Signing re-serialized JSON | Signing the exact encoded bytes |
| Network-wide name registration, confidence scores | No names on the network; the application's address book |
| Domain queries, route cache, hop counts, confidence decay | Full-membership gossip; link-state routing over it |
| Direct delivery to the recipient's endpoint only | Hop-by-hop forwarding with custody across the mesh |
| Plaintext content; sender visible along the way | Content and sender encrypted end to end; hops see neither |
| Every server's endpoints published | Endpoints published only by public instances |
| Admission only via pinned bootstrap | Any valid record from any peer; root as introducer |
| Mandatory bootstrap pins | Optional identifier, trust on first use otherwise |
| Peer exchange defined but unused | Anti-entropy is the core mechanism |
| Trust levels (`trusted`/`untrusted`/…) | Local policy + immune system |
| Per-peer rate limits and circuit breakers | Fair-share custody |
| Signed delivery acks from the receiving server | Custody per hop + end-to-end receipt from the recipient |
| Separate key rotation and cyanide pill | Pre-rotation; abandonment is a rotation |
| Tiered peer aging, cleanup jobs | Soft-state expiry |
| Short timestamp freshness windows | Seq numbers + seen ids + coarse expiry |
| Fixed private-address blocklist | Endpoint scope rule |
| Saturation metric | Removed |
| External scheduler driving the daemon | Self-running daemon |

## 12. Open questions

- **Configuration surface:** roots, hive networks, public or private,
  endpoints to advertise, gateways, services and their secrets, limit
  overrides.
- **Hive multicast discovery:** mDNS or a minimal custom announcement.
- **Parameters:** record and message expiry, gossip cadence, the
  per-destination custody allowance, the transit storage cap, push caps,
  rate limits, the *k* threshold for the wary rule, wary list size, neighbor
  count.
- **Keeping the next key offline in practice:** where it lives and how a
  rotation is performed.
- **Envelope key rotation cadence,** which limits exposure from the lack of
  forward secrecy.
- **Post-quantum protection for the channel:** whether to add a hybrid KEM to
  the Noise handshake later, so routing headers are covered too.
- **Routing details:**
  - The path metric: hop count, or something weighted by link quality.
  - How waypoints are chosen: uniformly among public instances, or
    excluding nodes too close to the sender or recipient to add diversity.
  - The sideways probability, tuned in the simulator.
  - The receipt timeout and how many fresh-waypoint retries to make.
  - Whether a sender may send through two waypoints at once for
    high-priority messages.
- **Privacy details:**
  - The exact size buckets. Messages larger than the largest bucket are
    refused in v2.0; attachments come later.
  - Snow parameters: the default snow level, echo share, bucket minimums,
    and hold.
  - Loop messages: cover messages a node routes through the mesh back to
    itself. They would look real even to hops, and their failure to return
    would be evidence for the immune system. Deferred.
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
- Demers, Keshav & Shenker, "Analysis and Simulation of a Fair Queueing Algorithm," SIGCOMM 1989.
- Meyer, "Range-Based Set Reconciliation," arXiv:2212.13567.
- Heilman, Kendler, Zohar & Goldberg, "Eclipse Attacks on Bitcoin's Peer-to-Peer Network," USENIX Security 2015.
- Bortnikov et al., "Brahms: Byzantine Resilient Random Membership Sampling," PODC 2008.
- Smith, "Key Event Receipt Infrastructure (KERI)," arXiv:1907.02143; Trust over IP KERI specification v1.1 (pre-rotation, quantum attack recovery).
- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism Standard" (ML-KEM), 2024.
- Connolly, Schwabe & Westerbaan, "X-Wing: general-purpose hybrid post-quantum KEM," IETF CFRG draft.
- Bormann & Hoffman, "Concise Binary Object Representation (CBOR)," RFC 8949, 2020 (§4.2 deterministic encoding).
- Perrin, "The Noise Protocol Framework."
- Tarr, Lavoie, Meyer & Tschudin, "Secure Scuttlebutt," ACM ICN 2019.
- Fall, "A Delay-Tolerant Network Architecture for Challenged Internets," SIGCOMM 2003.
- Perlman, "Network Layer Protocols with Byzantine Robustness," MIT PhD thesis, 1988 (MIT-LCS-TR-429).
- Moy, "OSPF Version 2," RFC 2328, 1998.
- Kleinberg, "Geographic Routing Using Hyperbolic Space," INFOCOM 2007.
- Valiant, "A Scheme for Fast Parallel Communication," SIAM Journal on Computing, 1982 (routing via a random intermediate).
- Yggdrasil network whitepaper and Ironwood routing library (greedy tree routing).
- Danezis & Goldberg, "Sphinx: A Compact and Provably Secure Mix Format," IEEE S&P 2009 (the onion format Lattice deliberately doesn't adopt).
- Lightning Network BOLT 4, onion routing and route blinding (the full form of the gateway layer).
- Piotrowska et al., "The Loopix Anonymity System," USENIX Security 2017 (Poisson-timed cover traffic).
- Reiter & Rubin, "Crowds: Anonymity for Web Transactions," ACM TISSEC 1998.
- Freedman & Morris, "Tarzan: A Peer-to-Peer Anonymizing Network Layer," ACM CCS 2002.
- Das et al., "Anonymity Trilemma: Strong Anonymity, Low Bandwidth Overhead, Low Latency — Choose Two," IEEE S&P 2018.
- BitTorrent BEP 5 (DHT), BEP 9 (metadata exchange), BEP 11 (PEX), BEP 14 (LSD), BEP 44 (mutable items).
- Donenfeld, "WireGuard: Next Generation Kernel Network Tunnel," NDSS 2017 (cookie mechanism).
- Laurie & Clayton, "Proof-of-Work Proves Not to Work," WEIS 2004.
- Nesse, "The Smoke-Detector Principle," Annals of the NY Academy of Sciences, 2001.
