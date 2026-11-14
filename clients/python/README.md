# lattice-client (Python)

Python client for the Lattice local API. It speaks the same wire protocol as
the Rust client (`lattice-client`): length-prefixed CBOR over a Unix socket,
per `V2_SPEC.md` §7. Use it to hook an application into a Lattice node —
send messages, receive them, and manage the node.

## Install

```sh
pip install ./clients/python          # from the repo root
# or, for development:
pip install -e './clients/python[test]'
```

Requires Python 3.9+. Dependencies: `cbor2`, `cryptography`, `blake3`.

## Quick start

```python
from lattice import Client

with Client.connect_app("/run/lattice/app.sock", "mira", b"the-service-secret") as c:
    mid = c.send(to=peer_id, tsvc="mira", tmbx=b"inbox",
                 fmbx=b"outbox", body=b"hello")
    print("queued", mid.hex())

    for delivery in c.fetch(16):
        print(delivery.from_.hex(), delivery.body)
        c.ack([delivery.delivery_id])
```

`peer_id` is the recipient's 32-byte node identifier (from its record or from
`latticectl node` / the `hello` response).

## Hooking an application in

### Services and mailboxes

A **service** is a name plus a secret, declared in the daemon's config:

```toml
[services]
mira = { secret = "a-long-random-secret" }
```

Your application connects to the **application socket** with the service name
and secret. The connection is then bound to that service: it can send as the
service and read only that service's inbox. Other services on the same node
cannot see your mail. The admin socket is separate and owner-only; do not
use it from application code.

A **mailbox** (`tmbx`) is an opaque byte string your service defines. Lattice
never interprets it; it is routed with the message and returned on delivery.
Use it to address sub-mailboxes inside your service (e.g. a user id), or
leave it constant if you don't need sub-addressing. `fmbx` is the sender's
mailbox, echoed back so replies can be addressed.

### Payloads are opaque

`body` is opaque bytes. Lattice never parses it. Put whatever your
application needs in it — JSON, protobuf, a serialized struct. There is no
schema registry and no content-type negotiation; versioning is your
application's business.

### At-least-once delivery — dedup by message id

Lattice delivers **at least once**. A delivery stays in the inbox until you
acknowledge it, and is re-delivered after a crash or a missed ack. Your
application **must dedup by `mid`** (the 16-byte message id):

```python
seen = set()
for delivery in c.fetch(16):
    if delivery.mid in seen:
        c.ack([delivery.delivery_id])   # duplicate; drop it
        continue
    seen.add(delivery.mid)
    handle(delivery)
    c.ack([delivery.delivery_id])
```

Persist `seen` (or the set of processed mids) if you need dedup to survive
restarts; the inbox itself survives restarts, so an un-acked delivery will
come back.

A good pattern is to ack only after the message is durably handled (written
to your own store), so a crash between handling and acking re-delivers
rather than loses.

### What "delivered" means

`status(mid)` reports the message's state:

| Code | Meaning |
|---|---|
| 1 | queued (accepted, not yet sent) |
| 2 | in transit (handed to the mesh) |
| 3 | **delivered** — the recipient instance durably stored the message |
| 4 | failed (with a reason code) |
| 5 | expired |

**Delivered means the recipient's Lattice node durably stored the message.**
It does **not** mean a human read it, that your application processed it, or
that it was acted on. Whether the application accepted the message is an
application-level fact and belongs in your own protocol (e.g. an application
ack message), not in Lattice's delivery receipt.

Receipts are authoritative only from the message's recipient: Lattice
verifies the receipt's signature and that the signer is the `to` of the
original message. Terminal states (`delivered`, `failed`, `expired`) are
sticky — a late receipt never moves a message out of a terminal state.

### Events

The daemon pushes events on the same socket, interleaved with responses:

- `inbox` (`EVENT_INBOX`): `{1: unread}` — the service's unfetched count changed.
- `status` (`EVENT_STATUS`): `{0: mid, 1: status}` — a message changed state.

```python
while True:
    ev = c.next_event(timeout=30)
    if ev.event == EVENT_INBOX:
        print("unread:", ev.data[1])
    elif ev.event == EVENT_STATUS:
        print("mid", ev.data[0].hex(), "->", ev.data[1])
```

`next_event` blocks; events that arrive while a request is in flight are
stashed and returned by the next `next_event()` (or `take_events()`).

### Identity and verification

`hello` returns the node's own id (`client.node_id`). Applications that want
to authenticate peers can use `lattice.objects` to parse and verify records
and messages (KEL validation, both record signatures, envelope decryption
and signature verification) — the same checks the node itself performs. The
shared test vectors in `vectors/` exercise exactly these paths.

## Admin operations

On the admin socket (owner-only): `node()`, `drain(draining)`, `link(...)`,
`unlink(id)`, `rotate()`, `abandon()`, `rotate_envelope()`. These mirror
`latticectl`; prefer `latticectl` for operator use.

## Running the tests

```sh
cd clients/python
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest                 # vectors + integration (boots real daemons)
```

The integration test needs a `latticed` binary; it uses `$LATTICE_DAEMON` if
set, else `target/debug/latticed` or `target/release/latticed`, building it
with cargo if missing. The vector tests need no daemon.
