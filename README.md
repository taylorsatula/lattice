# Lattice

A decentralized peer-to-peer protocol for cross-server messaging without a central coordinator.

Primarily developed to allow [taylorsatula/mira-OSS](https://github.com/taylorsatula/mira-OSS) instances to communicate in airgapped systems and after the root servers at [miraos.org](https://miraos.org) are shut down someday in the far-future.

## Overview

Lattice lets servers exchange messages across server boundaries. Users send messages to `user@remote-server` just like email, but for real-time messaging.

**Key Properties:**
- **Decentralized**: No central registry, coordinator or certificate authority
- **Out-of-band trust**: Servers authenticate each other with invite tokens carried by people, not by trusting the network
- **Cryptographically signed**: Every protocol message is signed with Ed25519
- **Spam-resistant**: Unknown servers are rejected outright; rate limits and circuit breakers protect known ones

---

## Quick Start

```bash
pip install -r requirements.txt

export LATTICE_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
# /etc/lattice/config.env must set APP_URL, this server's public https base URL.
# The identity and Ed25519 key are generated on first start.
uvicorn lattice.discovery_daemon:app --host 0.0.0.0 --port 1113
```

For a production install with systemd, run `./runme.sh` (see `docs/LATTICE_SYSTEMD.md`).

### Pairing two servers

On the server that already belongs to the network:

```bash
python -m lattice invite
# lattice1:6vx4aAM3OGSRjwMLrZVXJ232e9H59UYrhsTnJt5-JchCcAsnkc7fylfrewjCDEzHaHR0cHM6Ly8xLjEuMS4x
```

Carry the token to the other server's admin over a channel you trust: in person, on paper, a USB stick, or an end-to-end encrypted messenger. Then on the new server:

```bash
python -m lattice accept 'lattice1:...'
# Paired with alpha (550e8400-e29b-41d4-a716-446655440000)
```

Both servers now trust each other directly, and within one gossip round each is introduced to the other's direct peers.

### CLI

| Command | Description |
|---------|-------------|
| `python -m lattice invite [--ttl HOURS]` | Print a single-use invite token (default 24h) |
| `python -m lattice accept TOKEN` | Pair with the server that issued `TOKEN` |
| `python -m lattice peers` | List known peers with their trust level |
| `python -m lattice block SERVER_ID` | Block a peer and forget the servers only it introduced |

The CLI talks to the local daemon (`LATTICE_URL`, default `http://localhost:1113`) with the admin token from `LATTICE_ADMIN_TOKEN` or `/etc/lattice/config.env`.

### REST Endpoints

Admin endpoints require `X-Lattice-Admin-Token: <token>` and must not be exposed by a reverse proxy.

| Endpoint | Access | Description |
|----------|--------|-------------|
| `GET /status` | Public | Liveness status |
| `GET /api/v1/announcement` | Public | This server's self-signed announcement |
| `POST /api/v1/pair` | Public | Complete an invite (invitee proves it holds the secret) |
| `POST /api/v1/gossip/receive` | Peers | Announcements, introductions, key rotations, revocations |
| `POST /api/v1/keys/query` | Peers | Signed answer: which key do you hold for server X? |
| `POST /api/v1/federation/messages/receive` | Peers | Receive a signed federated message |
| `GET /health` | Admin | Operational health |
| `GET /api/v1/identity` | Admin | This server's identity and public key |
| `GET /api/v1/peers` | Admin | Peer list |
| `POST /api/v1/peers/{server_id}/block` | Admin | Block a peer |
| `POST /api/v1/invites` | Admin | Issue an invite token |
| `POST /api/v1/invites/accept` | Admin | Pair using an invite token |
| `POST /api/v1/announce` | Admin | Trigger a gossip round |
| `POST /api/v1/messages/send` | Admin | Sign, queue and deliver a message |
| `POST /api/v1/maintenance/*` | Admin | `process_messages`, `update_neighbors`, `cleanup` |

### Integration with External Systems

External systems (like MIRA) must configure the username resolver before federated message delivery works:

```python
from lattice.username_resolver import set_username_resolver

def resolve_username(username: str) -> Optional[str]:
    result = your_db.query("SELECT user_id FROM users WHERE username = ?", username)
    return str(result.user_id) if result else None

set_username_resolver(resolve_username)
```

Inbound messages are POSTed to `LATTICE_DELIVERY_WEBHOOK`. Periodic work (gossip, delivery, cleanup) is driven by the host application's scheduler via `lattice.init_lattice.initialize_lattice_services()`.

---

## Core Concepts

### Identity

Each Lattice server has a permanent identity:

```
server_id:   "acme-corp"                                      # Name used in addresses; may be renamed
server_uuid: "550e8400-e29b-41d4-a716-446655440000"           # Permanent identity
public_key:  "6vx4aAM3OGSRjwMLrZVXJ232e9H59UYrhsTnJt5-Jcg"    # Ed25519, raw 32 bytes, base64url
endpoint:    "https://acme-corp.example.com"                  # Base URL for all protocol paths
```

The `server_uuid` is the true identity. A server can rename (`acme-corp` to `acme-global`) by announcing the new name under its key. Its key changes only by a rotation signed with the old key.

### Trust

A server accepts protocol messages only from servers whose key it trusts. Every peer record carries how its key was learned:

| Trust | How | Can introduce others |
|-------|-----|----------------------|
| `direct` | Paired with an invite carried out of band | Yes |
| `introduced` | Vouched for by direct peers, then cross-checked | No |
| `blocked` | Blocked by this server's admin | - |
| `revoked` | Revoked by its owner | - |

There is no trust-on-first-use: a server that is neither paired nor introduced gets `403`.

**Invites** carry the inviter's public key, a 128-bit single-use secret and the inviter's endpoint:

```
lattice1: base64url( public_key[32] || secret[16] || endpoint )
```

```
   alpha (inviter)                                  bravo (invitee)
   ───────────────                                  ───────────────
   python -m lattice invite
   ── token carried out of band (person, paper, USB, E2E chat) ──▶
                                                    python -m lattice accept TOKEN
          ◀── GET /api/v1/announcement ──────────────
          ─── alpha's signed announcement ──────────▶  key == key in token?
                                                       signature valid?
          ◀── POST /api/v1/pair ─────────────────────
              { bravo's signed announcement,
                proof = HMAC(secret, alpha_key ‖ bravo_key) }
   proof valid? invite unused?
   consume invite, store bravo: direct
          ─── 200 ──────────────────────────────────▶  store alpha: direct
```

A man-in-the-middle on the first leg cannot present a key that matches the token. On the second leg it cannot bind its own key to the secret without knowing it. One token, moved one way, authenticates both directions.

**Introductions** spread trust one hop. Every gossip round, each server sends each direct peer the complete list of its other direct peers, signed. A receiver accepts a vouched-for server as `introduced` when:

1. at least `LATTICE_INTRODUCTION_QUORUM` (default 1) direct peers vouch for it,
2. all vouching direct peers agree on its key, and
3. no other direct peer, asked over its own channel with a signed nonce-bound `POST /api/v1/keys/query`, reports a different key for it (up to 3 are asked).

Introduced servers never introduce further; reaching friends-of-friends-of-friends takes another invite. If a voucher stops vouching for a server, or is blocked, servers it alone introduced are forgotten.

### Peers vs Neighbors

**Peers** are all servers whose key we trust. **Neighbors** are a random subset of up to 8 recently seen peers, rotated over time for diversity. Each gossip round goes to every direct peer plus 3 random other neighbors.

### Addresses

Users are addressed as `username@server_id`:

```
taylor@acme-corp        # User "taylor" on server "acme-corp"
alex@west-office        # User "alex" on server "west-office"
```

---

## Protocol Messages

Every message is signed over `lattice/1/<kind>\n` followed by its canonical JSON (sorted keys, no whitespace) without the `signature` field. The kind prefix means a signature for one message type never verifies as another.

### Gossip

`POST /api/v1/gossip/receive` carries `{"kind": ..., "payload": {...}}`. The payload's `server_uuid` is its author, which must be a known peer, and the payload must be signed with the key on record for it and be less than an hour old.

```json
{
  "kind": "announcement",
  "payload": {
    "server_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "server_id": "acme-corp",
    "public_key": "6vx4aAM3OGSRjwMLrZVXJ232e9H59UYrhsTnJt5-Jcg",
    "endpoint": "https://acme-corp.example.com",
    "timestamp": "2026-01-15T10:30:00+00:00",
    "signature": "base64url-ed25519-signature"
  }
}
```

| Kind | Payload | Effect |
|------|---------|--------|
| `announcement` | identity + endpoint | Updates name, endpoint and last-seen. The key must match the one on record |
| `introduction` | list of `{server_uuid, server_id, public_key, endpoint}` | Direct peers only. Replaces the sender's vouches |
| `key_rotation` | `old_public_key`, `new_public_key`, `reason` | Signed with the old key, which must match the one on record |
| `revocation` | `reason` | Permanently revokes the author |

### Federated Message

```json
{
  "message_id": "6f1c0e8a-0d5e-4a9e-9a43-6d1f3b2f9a10",
  "message_type": "pager",
  "from_address": "taylor@acme-corp",
  "to_address": "alex@west-office",
  "content": "Meeting in conference room 302 - please join ASAP",
  "priority": 2,
  "timestamp": "2026-01-15T10:35:00+00:00",
  "location": null,
  "metadata": {},
  "signature": "base64url-ed25519-signature"
}
```

The recipient verifies the signature with the key it holds for the sender's domain and returns a signed acknowledgment (`delivered` or `rejected`). Priority levels: `0` normal, `1` high, `2` urgent.

---

## Message Flow

Taylor on `acme-corp` sends a page to Alex on `west-office`:

```
┌──────────────────┐                              ┌──────────────────┐
│ acme-corp daemon │  POST /api/v1/federation/    │west-office daemon│
│                  │       messages/receive       │                  │
│ - Sign message   │ ───────────────────────────▶ │ - Known peer?    │
│ - Queue          │                              │ - Rate limit     │
│ - Look up peer   │                              │ - Verify sig     │
│ - Circuit check  │   { status, signed ack }     │ - Resolve "alex" │
│ - Verify ack     │ ◀─────────────────────────── │ - POST webhook   │
└──────────────────┘                              └──────────────────┘
```

1. The host application calls `POST /api/v1/messages/send` (admin)
2. The daemon checks the sender is on this server, signs the message, queues it, and attempts delivery immediately
3. It looks up `west-office` among its trusted peers and checks the circuit breaker
4. It POSTs the signed message to `west-office`'s endpoint
5. `west-office` verifies the sender's signature, deduplicates by `message_id`, resolves the recipient and delivers through its webhook
6. `west-office` returns a signed acknowledgment, and `acme-corp` marks the message delivered
7. Failures retry with exponential backoff; a signed rejection fails the message permanently
