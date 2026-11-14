# Lattice v2 Objects and Local API (draft)

Companion to `V2_DESIGN.md`. Every object here is derived from a decision in
that document; section references (§n) point back to it.

## 1. Conventions

- **Encoding:** deterministic CBOR (RFC 8949 §4.2): shortest-form integers,
  definite lengths, map keys sorted. Every signature and every hash covers
  the exact encoded bytes.
- **Maps use small integer keys,** as COSE does, for compactness. The tables
  below give each key's number.
- **Every top-level object** carries `0: v` (protocol version, currently 1)
  and `1: t` (object type).
- **Unknown keys are rejected,** not ignored. Within a version the format is
  closed; extensions come with a new version number. A node refuses objects
  whose version it doesn't support, and advertises the versions it supports
  in its record's capabilities. There is no compatibility with v1.
- **Sizes:**

  | Object | Limit |
  |---|---|
  | Peer record | 3 KB |
  | Message | Exactly one size bucket: 2, 8 or 32 KB |
  | Channel frame | 40 KB, enforced by the WebSocket layer before the frame is assembled |
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
| `mid` | 16-byte bstr: message id, random |

### Signing rule

A signed object is signed over its own encoding with the `sig` key omitted.
To verify, remove `sig`, re-encode deterministically, and check the
signature. Deterministic encoding makes that re-encoding exact.

### Text forms

- **Identifier:** lowercase base32 without padding, 52 characters.
- **Address:** `<service>:<mailbox>@<identifier>`, for example
  `mira:taylor@k7f3…`. Lattice routes on the identifier and delivers on the
  service. The mailbox is opaque to Lattice and belongs to the service.

## 2. Key events (§1)

Each event is a signed map.

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | v | uint | |
| 1 | t | uint | 1 = inception, 2 = rotation |
| 2 | sn | uint | Event number; inception is 0 |
| 3 | prev | hash | BLAKE3 of the previous event. Absent in inception |
| 4 | k | sigkey | The signing key this event establishes |
| 5 | n | hash | BLAKE3 of the next signing key. **Absent means abandonment** |
| 6 | sig | sig | By `k` |

**Rules:**
- **Identifier** = BLAKE3 of the inception event's encoding without `sig`.
- **A rotation is valid only if** `BLAKE3(k)` equals the previous event's
  `n`, `prev` matches, `sn` is the previous event's plus one, and `sig`
  verifies under the new `k`. A stolen current key can't produce a valid
  rotation.
- **Abandonment.** A rotation without `n` ends the identity permanently. No
  later record or event for that identifier is accepted.
- **Key event log (KEL):** the array of events from inception to the
  current one.

## 3. Peer record (§2)

| Key | Name | Type | Present | Notes |
|---|---|---|---|---|
| 0 | v | uint | All | |
| 1 | t | uint | All | 10 |
| 2 | id | id | All | |
| 3 | scope | uint | All | 0 = WAN, 1 = hive |
| 4 | seq | uint | All | Last-writer-wins per (id, scope) |
| 5 | exp | time | All | Coarse expiry, days out |
| 6 | kel | array of key events | All | Full KEL |
| 7 | ck | x25519 | All | Noise static key |
| 8 | ek | xwing_pk | All | Envelope key (§4) |
| 9 | mode | uint | All | 0 = public, 1 = private |
| 10 | ep | array of endpoint | Public | Endpoint = `{0: url}` (a `wss://` URL) |
| 11 | ln | array of id | Public | Current links, at most 32 |
| 12 | gw | array of id | Private | One to three gateways |
| 13 | cap | uint | All | Capability bitset |
| 14 | sig | sig | All | By the current signing key in `kel` |

**One record per scope.** A signed record can't have hive data stripped out
of it before it goes over the WAN; removing fields would break the
signature. So an instance that is on a hive publishes two records: a WAN
record and a hive record. The hive record is gossiped only inside the hive.
Each is last-writer-wins on its own (id, scope) pair. Hive-only instances
publish only a hive record.

**Validation:**
- The KEL is valid (§2) and not abandoned.
- `sig` verifies under the current key in the KEL.
- `id` matches the KEL's inception.
- `exp` is in the future and within the record horizon (§1).
- Fields match the mode: no `ep` or `ln` on a private record, no `gw` on a
  public one.
- Every `ep` URL is consistent with the record's scope (§2 scope rule).
- The encoded record is within 3 KB.

**Equivocation:** two records with the same (id, scope, seq) and different
bytes, both validly signed.

## 4. Sealed layers (§1, §6)

The gateway layer and the envelope are both sealed with **X-Wing**, the
standardized hybrid of X25519 and ML-KEM-768 (IETF CFRG X-Wing draft). It
yields a 32-byte shared secret and a 1120-byte KEM ciphertext.

| Key | Name | Type |
|---|---|---|
| 0 | kem | 1120-byte bstr: X-Wing ciphertext |
| 1 | ct | bstr: ChaCha20-Poly1305 ciphertext |

- **AEAD key** = BLAKE3 key derivation from the X-Wing shared secret, with a
  context string per layer (`"lattice v1 envelope"`, `"lattice v1 gateway"`).
  The nonce is zero, since each key is single-use.
- **Associated data** is the encoded routing header. This binds the header
  to both layers: a hop that alters the header makes decryption fail at the
  gateway or recipient, so no copy of the header is needed inside the
  envelope.

## 5. Message (§6)

The wire form is a CBOR array:
`[header, gateway_layer or null, envelope, padding]`.

### Routing header

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | v | uint | |
| 1 | t | uint | 30 |
| 2 | mid | mid | |
| 3 | dst | id | The recipient, or a gateway of a private recipient |
| 4 | exp | time | Within the message horizon (§1) |

### Gateway layer plaintext

| Key | Name | Type |
|---|---|---|
| 0 | rcpt | id: the private recipient |

### Envelope plaintext

| Key | Name | Type | Notes |
|---|---|---|---|
| 0 | kind | uint | 0 = message, 1 = receipt, 2 = negative receipt |
| 1 | from | id | Sending instance |
| 2 | fsvc | tstr | Sending service |
| 3 | fmbx | bstr | Sending mailbox; opaque |
| 4 | tsvc | tstr | Receiving service |
| 5 | tmbx | bstr | Receiving mailbox; opaque |
| 6 | created | time | |
| 7 | body | bstr | Kind 0: the application payload, opaque to Lattice |
| 8 | ref | mid | Kinds 1 and 2: the message being answered |
| 9 | reason | uint | Kind 2: 1 = unknown service, 2 = invalid |
| 10 | sig | sig | By `from`'s current signing key, over the encoded header followed by this map without `sig` |

**Padding:** zero bytes filling the encoded message to the smallest bucket
that fits it. A message that fits no bucket is refused at send.

**Sender's record:** a recipient that doesn't hold `from`'s record requests
it through gossip (§7 below) and holds the message until the record arrives
or the message expires.

## 6. Channel (§3)

Each WebSocket binary frame carries one CBOR value.

### Before and during the handshake

| t | Frame | Contents |
|---|---|---|
| 40 | init | `{2: noise msg, 3: mac1, 4: mac2 or absent}` |
| 41 | cookie | `{2: nonce, 3: encrypted cookie}` |
| 42 | resp | `{2: noise msg}` |

- **mac1** is keyed by the responder's channel key. A responder discards any
  init whose mac1 is wrong, at negligible cost.
- **mac2** is keyed by the cookie and required only when the responder is
  under load. A responder under load that receives an init without a valid
  mac2 answers with a `cookie` frame and keeps no state.
- **Patterns:** `Noise_IK_25519_ChaChaPoly_BLAKE2s` when the responder's
  channel key is known, `Noise_XX_25519_ChaChaPoly_BLAKE2s` otherwise. BLAKE2s
  is used inside Noise because that's what Noise implementations support;
  everywhere else uses BLAKE3.
- **After the handshake,** each side checks that the peer's Noise static key
  equals the `ck` in that peer's record. With XX, it first obtains the
  record through gossip.

### After the handshake

All frames are Noise transport messages wrapping CBOR:

| t | Frame | Contents |
|---|---|---|
| 50 | offer | `{2: message}` (the encoded message, §5) |
| 51 | custody | `{2: mid, 3: result, 4: retry_after or absent}`. Result: 0 = accepted, 1 = already have, 2 = busy, 3 = refused |
| 20 | digest | `{2: [[id, scope, seq], …]}` |
| 21 | want | `{2: [[id, scope], …]}` |
| 22 | records | `{2: [peer record, …]}` |
| 23 | wary | `{2: [id, …], 3: exp}` (optional, §8) |
| 60 | ping | `{2: nonce}`, answered with the same frame |

- **Custody rule:** a receiver answers `accepted` only after durably storing
  the message. `busy` is the fair-share answer (§6, §8), and also the answer
  at the recipient when the target service's inbox is full. `refused` means
  the message is malformed, expired, beyond the message horizon, or the
  wrong size for its bucket.
- **Check order for an offer,** cheapest first: frame and bucket size, then
  expiry and horizon, then dedup (answer `already have`), then fair share
  (answer `busy`), then durable storage (answer `accepted`).
- **Check order for a new connection:** frame size, then mac1, then mac2 when
  under load, then the Noise handshake.
- **Equivocation proofs** need no frame of their own. Conflicting records
  travel in an ordinary `records` frame, and the receiver detects the
  conflict.

## 7. Local API (§10)

The local API is how any application, MIRA or otherwise, uses Lattice.

### Transport

- **Unix domain sockets** carrying length-prefixed CBOR frames. They are
  never exposed to the network.
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
| `send` | to (id), tsvc, tmbx, fmbx, body, exp (optional, within the horizon), priority (optional, 0–3) | mid. The message is accepted into the durable outbound queue. Priority orders only this instance's outbound queue and never goes on the wire |
| `status` | mid | `queued`, `in_transit`, `delivered`, `failed` (with reason) or `expired` |
| `fetch` | max | Deliveries: delivery id, mid, from, fsvc, fmbx, tmbx, body, received |
| `ack` | delivery ids | Removes them from the inbox |
| `lookup` | id | Whether a valid record is held, its mode, and whether a path exists right now |

| Event | Data |
|---|---|
| `inbox` | Count of unfetched deliveries |
| `status` | mid and its new status |

**Delivery semantics:**
- **Lattice to the application is at least once.** A delivery stays in the
  inbox until acknowledged, and is re-fetched after a crash. Applications
  dedup by mid.
- **"Delivered" means the recipient instance's Lattice durably stored the
  message.** The receipt is sent at that point. Whether the application read
  it, accepted it or acted on it is application-level and goes in its own
  messages (design principle 1).
- **A negative receipt is sent only for things Lattice itself knows:** no
  such service on this instance (reason 1), or a message that fails
  verification (reason 2). Lattice has no concept of users; mailboxes are
  the service's business.
- **Each service's inbox is capped.** When it is full, the recipient answers
  `busy` to offers for that service (§6), so an application that stops
  fetching creates backpressure instead of unbounded growth.

### Admin operations

| Op | Effect |
|---|---|
| `node` | Identity, mode, links, queue and custody counts, peer record count |
| `rotate` | Rotate the signing key using the stored next key, and supply a new next-key hash |
| `abandon` | Abandon the identity permanently |
| `rotate_envelope` | Publish new envelope keys and delete the old private keys |
| `link` | Connect to an address, with an optional identifier (adds a root) |
| `unlink` | Drop and demote a link |
| `drain` | Stop accepting new custody (answer `busy`), keep handing off what's held, and report when empty |

Admin operations are reached through a CLI (`latticectl`). Nothing
administrative is available on the application socket.

## 8. Storage (§10)

redb tables, derived from the objects above:

| Table | Key | Value |
|---|---|---|
| `meta` | singleton | Schema version |
| `identity` | singleton | Own KEL, current secret keys, configuration hash |
| `records` | (id, scope) | Peer record bytes, received time |
| `outbound` | mid | Message bytes, priority, state, attempt, next attempt, receipt deadline, expected path |
| `custody` | mid | Message bytes, upstream link, destination, lease |
| `shares` | (destination, upstream link) | Count held, for fair-share custody |
| `seen` | BLAKE3(mid) | Expiry |
| `inbox` | delivery id | Service, delivery fields, received |
| `status` | mid | Latest status, for the API |
| `wary` | id | Source ranges, expiry |

The next signing key's secret is not stored here. It lives in a separate
file, or offline (§1).

**Schema versioning.** The store starts at schema version 1. At startup the
daemon reads `meta`. If the version is older than the daemon's, it runs the
explicit migrations for each step in order before serving. If it is newer,
the daemon refuses to start. There is no migration from v1's SQLite
database.
