# Lattice v2 Objects and Local API (draft)

Companion to `V2_DESIGN.md`. Every object here is derived from a decision in
that document; section references (§n) point back to it.

## 1. Conventions

- **Encoding:** deterministic CBOR (RFC 8949 §4.2): shortest-form integers,
  definite lengths, map keys sorted. Every signature and every hash covers
  the exact encoded bytes. The implementation sorts map keys length-first
  (§4.2.3), which coincides with the bytewise order of §4.2.1 for the
  integer keys Lattice uses.
- **Maps use small integer keys,** as COSE does, for compactness. The tables
  below give each key's number.
- **Every top-level object** carries `0: v` (protocol version, currently 1)
  and `1: t` (object type).
- **Unknown keys are rejected,** not ignored. Within a version the format is
  closed; extensions come with a new version number. A node refuses objects
  whose version it doesn't support, and advertises the versions it supports
  in its record's capabilities.
- **Sizes:**

  | Object | Limit |
  |---|---|
  | Peer record | 3 KB |
  | KEL object | 16 KB |
  | Frame after the handshake | Exactly one frame bucket: 2, 4, 8 or 32 KB of plaintext (§6) |
  | Message | Exactly one message bucket: its frame bucket minus 64 bytes, so an `offer` frame fits exactly |
  | Channel frame on the wire | 32784 bytes (32 KiB bucket + 16-byte AEAD tag), enforced by the WebSocket layer before the frame is assembled |
  | Local API frame | 64 KB |

- **Decoding limits.** Every decoder of untrusted bytes enforces, before
  allocating:

  | Limit | Value |
  |---|---|
  | Nesting depth | 8 |
  | Array or map length | 512 entries |
  | Byte or text string | The enclosing object's size limit |

  Anything beyond a limit is rejected outright, with nothing partially
  decoded kept.

- **Expiry horizons.** Expiries are chosen by their creators, so receivers
  bound them:

  | Object | Maximum expiry from now |
  |---|---|
  | Message (and receipt) | 14 days |
  | Peer record | 30 days |

  An object whose expiry is in the past, or beyond its horizon plus a few
  hours of clock skew, is refused.

### Primitive types

| Name | Encoding |
|---|---|
| `id` | 32-byte bstr: an identifier (BLAKE3-256) |
| `hash` | 32-byte bstr: BLAKE3-256 |
| `sigkey` | 32-byte bstr: Ed25519 public key |
| `sig` | 64-byte bstr: Ed25519 signature |
| `x25519` | 32-byte bstr |
| `xwing_pk` | 1216-byte bstr: X-Wing public key (ML-KEM-768 encapsulation key followed by X25519 key) |
| `time` | uint: Unix seconds |
| `mid` | 16-byte bstr: message id, random, carried inside the envelope |
| `leg` | 16-byte bstr: leg id, random and fresh for every leg of every attempt, carried in headers |

### Signing rule

Every signature preimage is prefixed with a context string naming the object
type, so a signature made for one object type is never valid for another.
The preimage is `context ‖ 0x00 ‖ body`, where `context` is the ASCII context
string from the table below and `body` is the object's own encoding with the
`sig` key omitted. The context string is never part of the encoded object;
it prefixes only the bytes fed to the signing function, so object encodings,
identifiers and event hashes are unchanged by this rule. To verify,
re-encode the body, prepend the context and the `0x00` separator, and check
the signature. Deterministic encoding makes the re-encoding exact.

| Object | Context string |
|---|---|
| Key event (inception or rotation) | `lattice v1 key event` |
| Record (`sig` and `csig`) | `lattice v1 record` |
| Envelope, message (kind 0) | `lattice v1 envelope` |
| Envelope, receipt or negative receipt (kind 1 or 2) | `lattice v1 receipt` |

The envelope's `body` is the encoded routing header (the real one, never an
outer header) followed by the envelope map without `sig`; see §5. The former
attestation context is gone with the attest frame (§6).

### Text forms

- **Identifier:** lowercase base32 (RFC 4648, no padding), 52 characters.
- **Hex:** lowercase hexadecimal (64 characters) is accepted everywhere an
  identifier is accepted, for compatibility. Implementations must emit
  base32.
- **Address:** `<service>:<mailbox>@<identifier>`, for example
  `mira:taylor@k7f3…`, where the identifier is in either form. Lattice
  routes on the identifier and delivers on the service. The mailbox is
  opaque to Lattice and belongs to the service. `service` and `mailbox`
  are non-empty and contain no `:`, `@` or whitespace; the identifier is
  the part after the `@`.

## 2. Key events and the key event log (§1)

Each event is a signed map.

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | v | uint | |
| 1 | t | uint | 1 = inception, 2 = rotation |
| 2 | sn | uint | Event number; inception is 0 |
| 3 | prev | hash | Event hash of the previous event. Absent in inception |
| 4 | k | sigkey | The signing key this event establishes |
| 5 | n | hash | BLAKE3 of the next signing key. **Absent means abandonment** |
| 6 | sig | sig | By `k`, over `lattice v1 key event ‖ 0x00 ‖` the event encoding without `sig` (§1) |

**Event hash.** The event hash of an event is BLAKE3 of its encoding without
`sig`. The identifier, `prev` and the KEL-head commitment in records (§3)
are all defined in terms of it.

**Rules:**
- **Identifier** = event hash of the inception event.
- **A rotation is valid only if** `BLAKE3(k)` equals the previous event's
  `n`, `prev` matches the previous event's event hash, `sn` is the previous
  event's plus one, and `sig` verifies under the new `k`. A stolen current
  key can't produce a valid rotation.
- **Abandonment.** A rotation without `n` ends the identity permanently. No
  later record or event for that identifier is accepted.
- **Monotonic history.** A node keeps the KEL object (or at least its head)
  for every identifier for one year after the last record it saw. A KEL
  that is a prefix of, or diverges from, a longer valid KEL already known
  is not accepted, and neither is a record citing it, whatever its `seq`.
  Two valid KELs for the same identifier that diverge at the same `sn`: the
  one with the lower head event hash wins.

### The key event log object

The KEL travels as its own object, not embedded in records.

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | v | uint | |
| 1 | t | uint | 11 |
| 2 | id | id | The identifier: event hash of the inception event |
| 3 | events | array of key events | Inception (sn 0) through the current head, contiguous |

- The object carries no signature of its own; its authenticity derives from
  the event chain.
- `id` must equal the event hash of `events[0]`. Each event must satisfy the
  rules above, and the array must be contiguous from sn 0.
- The encoded object is at most 16 KB and always fits in a single frame.
- **Retention.** KEL objects are retained for the KEL-head retention period
  (one year after the last record seen for the identifier), the same period
  that applies to the KEL head. A KEL whose head event is an abandonment is
  a *tombstone*: it is never used for routing or link binding, and once
  held, no record for the identifier is accepted and all stored records for
  it are dropped. The KEL object is the only carrier of an abandonment. The
  `abandon` admin operation (§7) publishes it before draining.
- **Reconciliation.** KEL objects are reconciled in the same set as records
  (§6), as entries with scope 255 (reserved; never valid in a record), `seq`
  and `khs` both equal to the head sn, and hash-prefix equal to the first 8
  bytes of the head event's event hash.

## 3. Peer record (§2)

| Key | Name | Type | Present | Notes |
|---|---|---|---|---|
| 0 | v | uint | All | |
| 1 | t | uint | All | 10 |
| 2 | id | id | All | |
| 3 | scope | uint | All | 0 = WAN, 1 = hive |
| 4 | seq | uint | All | Last-writer-wins per (id, scope); see Record order below |
| 5 | exp | time | All | Coarse expiry, days out |
| 6 | khs | uint | All | KEL head sn |
| 7 | ck | ed25519 | All | Channel key: Ed25519 public key; the Noise static key is the derived X25519 key (below) |
| 8 | ek | xwing_pk | All | Envelope key (§4) |
| 9 | mode | uint | All | 0 = public, 1 = private |
| 10 | ep | array of endpoint | Public | Endpoint = `{0: url, 1: [ip address, …] or absent}`. `url` is `ws://`. Connecting nodes prefer the listed IPs, using the URL's host only for the `Host` header |
| 11 | ln | array of id | Public | Current links, at most 32 |
| 12 | gw | array of id | Private | One to three gateways |
| 13 | cap | uint | All | Capability bitset |
| 14 | sig | sig | All | By the current signing key (§1) |
| 15 | csig | sig | All | By the channel key over the same preimage as `sig` |
| 16 | khc | hash | All | KEL head commitment: event hash of the head event |
| 17 | k | sigkey | All | Current signing key; must equal the KEL head event's `k` |
| 18 | serves | array of id | Public, optional | Private ids this gateway serves; at most 16 distinct ids |

**Channel key and Noise key.** The channel key is an Ed25519 public key.
The Noise handshake runs on the matching X25519 key, derived from the same
seed: the private half is the first 32 bytes of SHA-512(seed) (clamped by
X25519), and the public half is the Montgomery u-coordinate of the Ed25519
public point. Anyone can derive the X25519 public key from the record's
channel key, so no second key is published. The record carries two
signatures over the same preimage (everything except keys 14 and 15): `sig`
by the current KEL signing key, and `csig` by the channel key. A record
claiming someone else's channel key cannot be produced without that key, so
a forged record is rejected at validation — the channel-key claim cannot be
poisoned by a third party.

**One record per scope.** A signed record can't have hive data stripped out
of it before it goes over the WAN; removing fields would break the
signature. So an instance that is on a hive publishes two records: a WAN
record and a hive record. The hive record is gossiped only inside the hive.
Each is last-writer-wins on its own (id, scope) pair. Hive-only instances
publish only a hive record.

**Gateway consent.** A public record MAY carry `serves`: the private ids
the gateway agrees to serve, at most 16 distinct ids. The private↔gateway
pseudo-edge exists only when both records name each other: the private
record's `gw` lists the gateway, and the gateway's `serves` lists the
private id. If either side does not name the other, there is no edge, and
the gateway does not carry traffic for the private id. A gateway that
serves no private ids omits the field.

**Validation:**
- The KEL head named by `khs` and `khc` matches the head of a KEL held for
  this identifier, and that KEL is valid (§2) and not behind the KEL head
  already known (§2, monotonic history). If no such KEL is held, or the
  record's head is ahead of the held KEL, the record is not accepted: the
  node wants the KEL (§6) and drops the record; reconciliation re-delivers
  the record once the KEL arrives. If the record's head is behind the held
  KEL, the record is stale and is dropped. A record whose KEL head is an
  abandonment is not accepted.
- `k` equals the KEL head event's `k`.
- `sig` verifies under `k` (§1).
- `csig` verifies under the channel key, over the same preimage as `sig`.
- `id` matches the KEL's inception.
- `exp` is in the future and within the record horizon (§1).
- Fields match the mode: no `ep` or `ln` on a private record, no `gw` on a
  public one, no `serves` on a private record.
- `serves`, if present, carries at most 16 distinct ids.
- Every `ep` URL is consistent with the record's scope (§2 scope rule).
- The encoded record is within 3 KB.

**Equivocation:** two records with the same (id, scope, seq) and different
bytes, both validly signed. Every node keeps the one whose encoding has the
lower BLAKE3 hash, so all nodes converge, and treats the pair as an
equivocation proof. Reconciliation detects the pair (§6).

**Record order.** Records for the same (id, scope) are totally ordered by
(`khs`, `seq`, record hash): a record supersedes another when its `khs` is
higher, or its `khs` is equal and its `seq` is higher, or both are equal and
its hash (BLAKE3 of its exact encoding) is lower. Admission and
last-writer-wins use this order: a stored record is replaced only by a
superseding record. `seq` is assigned as `max(previous seq + 1, unix
seconds)`, so it does not decrease across rotations or store loss while the
clock is sane.

**Republishing:** an instance publishes a new record at most once per
*republish interval* (default 2 minutes), batching link changes; each
record's `seq` is `max(previous seq + 1, unix seconds)`. A link stays in
`ln` through disconnections shorter than the *link grace* (default
5 minutes).

## 4. Sealed layers (§1, §6)

Hop layers (waypoint and gateway) and the envelope are all sealed with
**X-Wing**, the standardized hybrid of X25519 and ML-KEM-768 (IETF CFRG
X-Wing draft). It yields a 32-byte shared secret and a 1120-byte KEM
ciphertext.

| Key | Name | Type |
|---|---|---|
| 0 | kem | 1120-byte bstr: X-Wing ciphertext |
| 1 | ct | bstr: ChaCha20-Poly1305 ciphertext |

- **AEAD key** = BLAKE3 key derivation from the X-Wing shared secret, with a
  context string per kind of layer (`"lattice v1 envelope"`,
  `"lattice v1 hop"`). The nonce is zero, since each key is single-use.
- **Associated data** is the encoded header that travels alongside the layer
  in the same message array. A hop that alters a header makes decryption fail
  at the next node that opens a layer, so no copy of a header is needed
  inside any layer.

## 5. Message (§6)

The wire form is a CBOR array:
`[header, hop_layer or null, envelope, padding]`.

- **Direct to a public recipient:** `header.dst` is the recipient, and
  `hop_layer` is null.
- **To a private recipient:** `header.dst` is a gateway, and `hop_layer` is a
  gateway layer.
- **Through a waypoint:** `header` is an outer header with its own leg id,
  `header.dst` is the waypoint, and `hop_layer` is a waypoint layer that
  contains the real header and, for a private recipient, the gateway layer.

The node named in `header.dst` opens `hop_layer` if present. Its kind says
what to do. Hops that aren't `dst` never learn which case applies, beyond
whether `hop_layer` is null.

### Header

Used for both the routing header and the outer header.

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | v | uint | |
| 1 | t | uint | 30 |
| 2 | leg | leg | Leg id. Hops dedup on it |
| 3 | dst | id | Recipient, gateway or waypoint |
| 4 | exp | time | Within the message horizon (§1). An outer header's expiry is no later than the real header's |

**Leg ids, not message ids, in headers.** Every leg of every attempt carries
a fresh random leg id. A node can be on both legs of a waypoint route, or on
the routes of two attempts, and with a shared id it would answer
`ALREADY_HAVE` and block the later one. The message id lives in the envelope
(below), where the recipient dedups on it.

### Hop layer plaintext

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | kind | uint | 0 = waypoint, 1 = gateway |
| 1 | hdr | header | Waypoint: the real routing header |
| 2 | inner | sealed layer or absent | Waypoint: the gateway layer, for a private recipient |
| 3 | rcpt | id | Gateway: the private recipient |

**At a waypoint:** the waypoint replaces the outer header with `hdr`, and
`hop_layer` with `inner` (or null). It re-pads to the **same bucket** the
message arrived in, so the leg change isn't visible by size. Then it forwards
toward `hdr.dst` as a new custody unit under `hdr.leg`. It accepts the
first leg only if it has room to hold the second leg as its own outbound
traffic (§6 buffer classes).

**At a gateway:** forward over the direct link to `rcpt`, unchanged.

### Envelope plaintext

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | kind | uint | 0 = message, 1 = receipt, 2 = negative receipt |
| 11 | mid | mid | Message id. The recipient dedups on it; retries keep it |
| 1 | from | id | Sending instance |
| 2 | fsvc | tstr | Sending service |
| 3 | fmbx | bstr | Sending mailbox; opaque |
| 4 | tsvc | tstr | Receiving service |
| 5 | tmbx | bstr | Receiving mailbox; opaque |
| 6 | created | time | |
| 7 | body | bstr | Kind 0: the application payload, opaque to Lattice |
| 8 | ref | mid | Kinds 1 and 2: the message being answered |
| 9 | reason | uint | Kind 2: 1 = unknown service, 2 = invalid (the signature verifies but the envelope is otherwise invalid) |
| 10 | sig | sig | By `from`'s current signing key, over `context ‖ 0x00 ‖` the encoded routing header (the real one, never an outer header) followed by this map without `sig`, where `context` is `lattice v1 envelope` for kind 0 and `lattice v1 receipt` for kinds 1 and 2 (§1) |

**Negative receipts.** A negative receipt (kind 2) is sent only when the
envelope signature verifies but the envelope is otherwise invalid (reason 2),
or when the recipient has no such service (reason 1). If the signature does
not verify, the recipient refuses custody and sends no receipt of any kind:
an unauthenticated sender must not be able to elicit a signed response.

**Padding:** zero bytes filling the encoded message to the smallest bucket
that fits it. A message that fits no bucket is refused at send.

**Sender's record:** a recipient that doesn't hold `from`'s record requests
it through gossip (§6) and holds the message until the record arrives
or the message expires.

## 6. Channel (§3)

Lattice uses plain WebSocket (`ws://`). Confidentiality and integrity come
from the Noise session, not from TLS: the payload is encrypted end to end
before the WebSocket ever sees it, so a second encryption layer would add
certificate management for nameless nodes without adding protection. `wss://`
is not used; implementations must reject it rather than silently downgrade.

Each WebSocket binary frame carries one CBOR value.

### Before and during the handshake

| t | Frame | Contents |
|---|---|---|
| 40 | init | `{2: noise msg, 3: mac1, 4: mac2 or absent, 5: padding}` |
| 41 | cookie | `{2: cookie, 5: padding}` |
| 42 | resp | `{2: noise msg, 5: padding}` |

- **Handshake frames are padded** to the 2 KB bucket. This equalizes size for
  observers that do not parse CBOR; it is not a confidentiality property of
  the handshake itself. A CBOR-literate observer can still tell an Init from
  a Resp or Cookie, an IK first message from an XX first message (by the
  length of `noise msg`), and whether a mac2 field is present. Post-handshake
  frames carry no type markers at all.
- **The upgrade path** is `/` followed by the base32 encoding of the first
  16 bytes of BLAKE3 keyed-derivation (context `"lattice v1 path"`) over the
  responder's channel key. Any upgrade request to another path, and any
  non-upgrade request other than an enabled `/status`, gets a generic `404`.
  A root given without an identifier publishes its path alongside its
  address, since its key isn't known in advance.

- **mac1** is keyed by the responder's channel key. A responder discards any
  init whose mac1 is wrong, at negligible cost. The XX pattern cannot use
  this: an initiator who does not know the channel key cannot compute mac1,
  so XX messages carry mac1 = zeros and the responder does not check it; the
  derived upgrade path remains the admission gate for that pattern. IK/XX is
  distinguished by first-message length (32 bytes = XX, otherwise IK);
  changing either pattern's message sizes requires changing this rule in the
  same version.
- **mac2** is keyed by the cookie and required only when the responder is
  under load. A responder under load that receives an init without a valid
  mac2 answers with a `cookie` frame and keeps no state. The cookie is an
  opaque 24-byte value, `BLAKE2s-256(rotating server secret, client address)`,
  recomputed by the server on demand; the server keeps no per-client state.
  The cookie is not encrypted — it is a PRF output bound to the client
  address, and is useless to any other address. Cookies rotate every two
  hours; the previous key remains valid during the overlap.
- **Patterns:** `Noise_IK_25519_ChaChaPoly_BLAKE2s` when the responder's
  channel key is known, `Noise_XX_25519_ChaChaPoly_BLAKE2s` otherwise. BLAKE2s
  is used inside Noise because that's what Noise implementations support;
  everywhere else uses BLAKE3.
- **Prologue.** The Noise prologue is `"lattice v1" ‖ 0x00 ‖` the upgrade
  path exactly as it appears in the request line, including the leading `/`,
  as ASCII bytes (for example `lattice v1\0/k7f3…`). Both patterns use the
  same prologue. Binding the protocol name and the path into the handshake
  hash keeps a handshake from one path from being replayed on another, and
  separates this protocol's handshakes from any other Noise protocol that
  shares the pattern.
- **After the handshake,** each side checks that the peer's Noise static key
  equals the `ck` in that peer's record. With XX, it first obtains the
  record through gossip. This check is the only binding between a link and
  an identity; there is no attestation frame.
  The cross-signed record (§3) plus the Noise static key are the whole
  binding.

### After the handshake

Every frame is a Noise transport message whose plaintext is the CBOR array
`[frame, padding]`. The padding is a byte string that brings the plaintext to
exactly one frame bucket (2, 4, 8 or 32 KB). A frame whose plaintext isn't
exactly a bucket size is refused. Frame types:

| t | Frame | Contents |
|---|---|---|
| 50 | offer | `{2: message}` (the encoded message, §5) |
| 51 | custody | `{2: leg, 3: result, 4: retry_after or absent}`. Result: 0 = accepted, 1 = ALREADY_HAVE, 2 = busy, 3 = refused, 4 = SEEN |
| 20 | reconcile | `{2: [range, …]}`. Range-based set reconciliation, below |
| 21 | want | `{2: [[id, scope], …]}` |
| 22 | records | `{2: [peer record, …]}` |
| 23 | reserved | Reserved for the wary list (see V2_DESIGN.md); not implemented in v2.0 |
| 24 | kels | `{2: [kel, …]}`. KEL objects (§2) |
| 60 | ping | `{2: nonce}`, answered with the same frame. Replaces WebSocket ping/pong, which is not used |
| 61 | dummy | `{2: echo}` (bool). Discarded on receipt; if `echo` is true, answered with a dummy (§ Snow) |
| 62 | reserved | Reserved (was `attest` in early drafts); not sent, not accepted |

- **Large gossip** that doesn't fit one 32 KB frame is split across several
  `reconcile`, `records` or `kels` frames.
- **Custody replies.** `ALREADY_HAVE` (1) means the receiver holds custody
  of this leg: the message is stored, or the leg id is in its seen set with
  the message held. `SEEN` (4) means the receiver has seen this leg but
  does not hold it (it refused or dropped it earlier); the sender should
  try elsewhere. Neither is a delivery signal, and neither releases the
  sender's custody. On `ALREADY_HAVE` the sender keeps custody and excludes
  the link for this leg, then chooses again. On `SEEN` the sender excludes
  the link for this leg and chooses again.

### Reconciliation (design §5)

The reconciliation set holds two kinds of entries: records (scope 0 or 1)
and KELs (scope 255, reserved; never valid in a record). Entries are
ordered by (id, scope). Each entry's item hash is
BLAKE3(id ‖ scope ‖ khs ‖ seq ‖ hash-prefix), with `scope` a single byte,
`khs` and `seq` as 8 little-endian bytes each (for a record, the record's
`khs` and `seq`; for a KEL entry, both equal the head sn), and
`hash-prefix` the first 8 bytes of the record's hash (BLAKE3 of its exact
encoding) or, for a KEL entry, the first 8 bytes of the head event's event
hash. A range's fingerprint is the count of entries and the sum of their
item hashes modulo 2²⁵⁶. The sum is carried as a 32-byte big-endian
integer. Sums can be maintained incrementally as entries change, and the
order of addition doesn't matter.

KELs are reconciled in the same set as records — one set, one fingerprint,
one round — rather than in a parallel domain, so a single round converges
both and the steady-state cost stays one small frame each way. The `kels`
frame carries KEL objects.

- **A bound** (`lower`/`upper`) is `{0: id (32 bytes), 1: scope (uint)}`.
- **Limits:** at most 64 ranges per reconcile message, at most 32 entries
  per explicit list, and at most 32 entries echoed per response. A receiver
  rejects a reconcile frame with more than 64 ranges, and ignores entries
  beyond the per-range limit.

- **A range** is `{0: lower bound, 1: upper bound, 2: [count, sum]}` or
  `{0: lower, 1: upper, 3: [[id, scope, khs, seq, hash-prefix], …]}` (an
  explicit list, used for small ranges; `khs` and `seq` are 8 bytes,
  `hash-prefix` is 8 bytes).
- **A round** starts with one range covering everything. The receiver
  compares fingerprints:
  - **Equal:** done.
  - **Different and large:** split the range into 16 subranges and reply
    with their fingerprints.
  - **Different and small** (32 entries or fewer): reply with the explicit
    list.
- **Fetching:** each side sends `want` for entries it lacks, holds at a
  lower (khs, seq) than the peer's, or holds at an equal (khs, seq) whose
  hash-prefix is higher than the peer's (the lower hash wins; equal prefixes
  are treated as identical). The same rule applies to KEL entries, whose
  `khs` and `seq` are both the head sn. The
  other side answers with `records`, or with `kels` for KEL entries (a KEL
  entry is wanted as `[id, 255]`). A node
  that receives a record whose KEL it does not hold, or whose head is ahead
  of the held KEL, drops the record and wants the KEL; when the KEL arrives
  it is validated and stored, and the next round delivers the record.
- **Cost:** a round on an unchanged set is one small frame each way,
  regardless of the number of entries. (Meyer, "Range-Based Set
  Reconciliation"; Negentropy.)

- **Custody rule:** a receiver answers `accepted` only after durably storing
  the message. Offers arriving close together are committed together (group
  commit), and each is answered only after its commit completes. `busy` is the fair-share answer (§6, §8), and also the answer
  at the recipient when the target service's inbox is full. `refused` means
  the message is malformed, expired, beyond the message horizon, or the
  wrong size for its bucket.
- **Check order for an offer,** cheapest first: frame and bucket size, then
  expiry and horizon, then dedup on the leg id (answer `ALREADY_HAVE` if the
  message is held, `SEEN` if the leg was seen but is not held), then
  buffer class and fair share (answer `busy`), then durable storage (answer
  `accepted`).
- **Buffer classes.** Transit storage is divided into classes 0 to *D*
  (default *D* = 16), each with an equal slice of the transit cap. An offer
  for which this node would be *d* hops from the message's current
  destination is stored in class min(*d*, *D*). Fair shares apply within each
  class. A node waits only for room in a lower class at a progress neighbor,
  never on a sideways neighbor, so waits can't form a cycle.
- **Check order for a new connection:** frame size, then mac1, then mac2 when
  under load, then the Noise handshake.
- **Next-hop choice** for a message held in custody, toward its current
  destination *d*, with *dist* the hop count to *d* over the current graph:
  - With probability *p_side* (default 15%), choose uniformly among links to
    neighbors with *dist* exactly equal to this node's own that haven't
    answered `ALREADY_HAVE` or `SEEN` for this leg. If that neighbor answers
    `busy`, `ALREADY_HAVE` or `SEEN`, fall through to a progress step at
    once; never wait on a sideways neighbor.
  - Otherwise, choose uniformly among links to neighbors with *dist* less
    than this node's own. On `ALREADY_HAVE` or `SEEN`, exclude that link for
    this leg and choose again; the sender keeps custody either way. On
    `busy`, try another progress neighbor, or wait with backoff if all are
    busy.
  - Never choose a neighbor with *dist* greater than this node's own.
- **Waypoint choice** at the sender: uniformly among public instances with a
  valid record, excluding the sender's own links and the recipient (and its
  gateways). A share *w* of messages use one (default 0%). Retries always use
  a waypoint not used by earlier attempts, and fresh leg ids for every leg.
- **Receipt timeout:** 15 minutes for a public recipient, 12 hours for a
  private one (known from its record), before a retry.
- **Equivocation proofs** need no frame of their own. Conflicting records
  travel in an ordinary `records` frame, and conflicting KELs in a `kels`
  frame; the receiver detects the conflict.

### Snow (design §7)

Real frames are sent as soon as they are ready. Snow is added around them:

- **Snow ticks** follow a Poisson process at the node's snow level *s*
  frames per minute, with exponentially distributed gaps drawn from OS
  randomness.
- **At each tick:**
  - If any real frame went out on any link since the previous tick, skip.
  - Otherwise send a `dummy` on a uniformly random current link.
- **Dummy size:** drawn from the node's mix of real frame buckets over the
  last 6 hours, with every bucket held to a minimum share of 10%. Use an
  equal mix when there is no history.
- **Echoes:** a dummy has `echo` set with probability *e*. A node receiving
  an echo request answers with a dummy (echo unset) after a random delay
  drawn from the same distribution as its custody reply times, so dummy
  exchanges look like an offer and its reply.
- **Hold (optional):** if *h* > 0, each real frame waits a uniformly random
  0–*h* ms before sending. The default is 0, meaning immediate dispatch.
- **Handshake frames** (40–42) are not snow and are not held, but they are
  padded (§6, before the handshake).
- **Defaults:**

  | Parameter | Default |
  |---|---|
  | *s*, snow level | 2 per minute per node |
  | *e*, echo share | 25% |
  | Bucket minimum share | 10% each |
  | *h*, hold | 0 ms |

  A snow level of 0 turns snow off.

### Public status (optional)

Served on the same listener as the WebSocket, as plain HTTP:

- **`GET /status`** returns `200` with a deterministic CBOR map:

  | Key | Name | Type | Notes |
  |---|---|---|---|
  | 0 | v | uint | Status format version |
  | 1 | up | bool | Always true when answering |
  | 2 | accepting | bool | False while draining |
  | 3 | versions | array of uint | Protocol versions supported |

- **What it deliberately leaves out:** the identifier, mode, peer counts,
  link counts, queue depths, uptime and anything else that profiles the
  node. Peers learn everything they need from records and links. The
  status endpoint exists only to answer "is something Lattice-shaped alive
  here?"
- **It is cheap and can't fail.** The response is built from in-memory state
  with no storage access, and it is subject to the same per-address
  connection limits as the listener.
- **Configuration:** `status = true` by default. With `status = false`,
  `GET /status` gets the same generic `404` as any other non-WebSocket
  request, so the node can't be distinguished by that path.

## 7. Local API (§10)

The local API is how any application, MIRA or otherwise, uses Lattice.

### Transport

- **Unix domain sockets** carrying length-prefixed CBOR frames. They are
  never exposed to the network.
- **Framing:** each frame is a 4-byte big-endian length prefix followed by
  that many bytes of CBOR. The payload may not exceed 65536 bytes.
- **Two sockets:**
  - **The application socket** is readable and writable by a configured
    group.
  - **The admin socket** is owner-only.
- **Services authenticate** on the application socket. Each service
  (`mira`, `backup`, …) is named in the configuration with a secret. A
  connection presents the service name and secret once, and can then send as
  that service and read only that service's inbox. The secret is compared in
  constant time.
- **Client libraries** for Rust and Python implement this framing and the
  operations below, so applications don't hand-roll CBOR.
- **Request:** `{0: request id, 1: op, 2: args}`
- **Response:** `{0: request id, 1: ok}` or `{0: request id, 2: error code}`
- **Event,** pushed without a request: `{3: event, 2: data}`

### Application operations

| Op | Args | Result |
|---|---|---|
| `hello` | service, secret | Own identifier and service; the session is bound to that service |
| `send` | to (id), tsvc, tmbx, fmbx, body, exp (optional, within the horizon), priority (optional, 0–3), route (optional: `default`, `waypoint` or `direct`) | mid. The message is accepted into the durable outbound queue. Priority orders only this instance's outbound queue and never goes on the wire. `default` uses a waypoint with the configured waypoint share |
| `status` | mid | `queued`, `in_transit`, `delivered`, `failed` (with reason) or `expired` |
| `fetch` | max | Deliveries: delivery id, mid, from, fsvc, fmbx, tmbx, body, received |
| `ack` | delivery ids | Removes them from the inbox |
| `lookup` | id | Whether a valid record is held, its mode, and whether a path exists right now |
| `ping` | (none) | Empty result; resets the connection's read-idle timer |

| Event | Data |
|---|---|
| `inbox` | Count of unfetched deliveries |
| `status` | mid and its new status |

Operation, event and error codes are part of the wire contract:

| Op | Code | | Event | Code | | Error | Code |
|---|---|---|---|---|---|---|---|
| `hello` | 1 | | `inbox` | 1 | | unknown op | 1 |
| `send` | 2 | | `status` | 2 | | bad args | 2 |
| `status` | 3 | | | | | auth failed | 3 |
| `fetch` | 4 | | | | | not found | 4 |
| `ack` | 5 | | | | | | |
| `lookup` | 6 | | | | | | |
| `ping` | 7 | | | | | | |
| `node` | 101 | | | | | | |
| `rotate` | 102 | | | | | | |
| `abandon` | 103 | | | | | | |
| `rotate_envelope` | 104 | | | | | | |
| `link` | 105 | | | | | | |
| `unlink` | 106 | | | | | | |
| `drain` | 107 | | | | | | |

**Delivery semantics:**
- **Lattice to the application is at least once.** A delivery stays in the
  inbox until acknowledged, and is re-fetched after a crash. Applications
  dedup by mid.
- **"Delivered" means the recipient instance's Lattice durably stored the
  message.** The receipt is sent at that point. Whether the application read
  it, accepted it or acted on it is application-level and goes in its own
  messages (design principle 1).
- **A receipt is authoritative only from the message's recipient.** The
  recipient's signature is verified as usual, and the signer must be the
  `to` of the original message; anything else is discarded.
- **Terminal states are sticky.** `delivered`, `failed` and `expired` are
  final; a late receipt never moves a message out of a terminal state.
- **A negative receipt is sent only for things Lattice itself knows:** no
  such service on this instance (reason 1), or a message whose signature
  verifies but which is otherwise invalid (reason 2). If the signature does
  not verify, the node refuses custody and sends no receipt of any kind:
  an unauthenticated sender must not be able to elicit a signed response.
  Lattice has no concept of users; mailboxes are the service's business.
- **Each service's inbox is capped.** When it is full, the recipient answers
  `busy` to offers for that service (§6), so an application that stops
  fetching creates backpressure instead of unbounded growth.

### Admin operations

| Op | Effect |
|---|---|
| `node` | Identity, mode, links, queue and custody counts, peer record count |
| `rotate` | Rotate the signing key: the operator supplies the offline next key (verified against the stored commitment) and the commitment to the following key |
| `abandon` | Abandon the identity permanently; publishes the final KEL (a rotation with no next-key commitment) before draining; the KEL object is the tombstone (§2) |
| `rotate_envelope` | Publish new envelope keys and delete the old private keys |
| `link` | Connect to an address, with an optional identifier (adds a root) |
| `unlink` | Drop and demote a link |
| `drain` | Stop accepting new custody (answer `busy`), keep handing off what's held, and report when empty |

`rotate` takes the 32-byte offline next key (arg 0) and the 32-byte BLAKE3
commitment to the following key (arg 1); the daemon verifies the key against
the commitment stored in the identity directory and refuses the rotation on
mismatch. `abandon` takes only the next key (arg 0) and commits to nothing.
The daemon never writes a secret key to disk during rotation; the following
key never leaves the operator's offline storage.

Admin operations are reached through a CLI (`latticectl`). Nothing
administrative is available on the application socket.

## 8. Storage (§10)

redb tables, derived from the objects above:

| Table | Key | Value |
|---|---|---|
| `meta` | singleton | Schema version |
| `identity` | singleton | Own KEL, current secret keys, configuration hash |
| `records` | (id, scope) | Peer record bytes, received time, plus range fingerprints maintained for reconciliation (records and KELs) |
| `outbound` | mid | Message bytes, priority, state, attempt, next attempt, receipt deadline, waypoints used |
| `custody` | leg | Message bytes, upstream link, current destination, buffer class |
| `shares` | (destination, upstream link) | Count held, for fair-share custody |
| `seen` | BLAKE3(leg) | Expiry. Hop-level dedup |
| `delivered` | BLAKE3(mid) | Expiry. Recipient-level dedup |
| `kels` | id | KEL object bytes, last-seen time (kept one year). The KEL head (sn, event hash) and the abandoned flag are derived from the object |
| `inbox` | (service, received, delivery_id) | Service, delivery fields, received |
| `status` | mid | Latest status, for the API |

Deliveries are returned oldest-first per service, ties broken by delivery id.

The next signing key's secret is never stored here. It lives offline with
the operator; the identity directory stores only its BLAKE3 commitment in
`next_key_commitment` (32 raw bytes), written at init and rewritten at each
rotation. Rotation supplies the next key over the admin socket; the daemon
verifies it against the commitment and never writes it to disk (§1).

**Schema versioning.** The store starts at schema version 1. At startup the
daemon reads `meta`. If the version is older than the daemon's, it runs the
explicit migrations for each step in order before serving. If it is newer,
the daemon refuses to start. There is no migration from the retired
Python implementation's SQLite database.
