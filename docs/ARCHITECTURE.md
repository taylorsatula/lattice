# Lattice Architecture

## Overview

Lattice enables decentralized cross-server messaging. Servers learn each other's keys out of band (invites) or from servers they already trust (introductions), then gossip and deliver signed messages directly. No central servers are required.

## Modules

| Module | Responsibility |
|--------|----------------|
| `crypto.py` | Ed25519 keys, canonical signing bytes, sign/verify |
| `models.py` | Protocol messages (all `SignedModel`), validation helpers |
| `identity.py` | This server's name, UUID, endpoint and signing key |
| `peer_manager.py` | Peer records, trust levels, rate limits, neighbor selection |
| `trust.py` | Invites, pairing, introductions, key cross-checks |
| `discovery_daemon.py` | `DiscoveryService` (gossip, delivery) and the FastAPI endpoints |
| `init_lattice.py` | Scheduler hooks for the host application |
| `client.py`, `__main__.py` | HTTP client and admin CLI for the local daemon |

## Sync Core, Threadpool Endpoints

All business logic is synchronous. The FastAPI endpoints are plain `def` functions, which FastAPI runs in its threadpool, so blocking SQLite and HTTP calls never stall the event loop. Outbound HTTP uses one shared `httpx.Client` per service, which tests replace with a transport that routes between in-process nodes.

`create_app(service)` builds an app around a `DiscoveryService`. The module-level `app` is what uvicorn serves; tests build several apps to run multi-server scenarios in one process.

---

## Trust Model

### Goals

- A man-in-the-middle on any network path cannot get its key accepted for a server.
- Trust can be established on an airgapped network with nothing but people moving short strings.
- A single compromised peer cannot silently inject keys.

### Direct trust: invites

An invite token is `lattice1:` + base64url(inviter public key ‖ 16-byte secret ‖ endpoint), about 90 characters, small enough for a QR code. It is single use, expires (default 24h, max 7 days), and the inviter stores only the secret and its expiry.

Pairing has two legs:

1. The invitee fetches the inviter's announcement and accepts it only if it is signed by the key in the token, for the endpoint in the token.
2. The invitee POSTs its own self-signed announcement with `proof = HMAC-SHA256(secret, "lattice/1/pair\n" + {"inviter": key, "invitee": key})`, plus `invite_id = SHA-256(secret)[:16]` so the inviter can find the invite. The inviter verifies the proof, then atomically consumes the invite.

The proof binds the invitee's key to both the secret and the inviter's key, so a man-in-the-middle cannot swap in its own key or replay the proof to another inviter. A failed proof does not consume the invite; a name or key conflict is rejected before it is consumed.

### Introduced trust: vouches

Each gossip round, a server sends every direct peer a signed `introduction` listing all its other direct peers. Receivers accept introductions only from direct peers and store each one as that voucher's complete current set of vouches, replacing the previous set.

A vouched-for server we do not know is evaluated after each introduction:

1. Count vouches from servers that are currently direct peers. All of them must name the same key, and there must be at least `quorum` (`LATTICE_INTRODUCTION_QUORUM`, default 1).
2. Its `server_id` must not belong to another UUID.
3. **Cross-check.** Up to 3 other direct peers (not the vouchers) are asked `POST /api/v1/keys/query`, a signed request with a random nonce. Each answers with a signed `{subject, public_key or null, nonce}`. If any answers with a different key, the server is not admitted and the dissent is logged as a possible MITM or compromised voucher.

Introductions travel one hop: introduced servers cannot introduce others. That keeps every accepted key within one step of a server a human verified.

Trust is withdrawn as well as granted. When a voucher drops a server from its list, is blocked or revoked, or has not refreshed its vouches in 30 days, any introduced server left below quorum is forgotten.

### What this does and does not protect against

| Threat | Outcome |
|--------|---------|
| MITM during pairing (either leg) | Rejected: key does not match the token, or proof fails |
| MITM between already-paired servers | Rejected: every message is signed with keys on record |
| Unknown server announcing itself | `403`; no trust on first use |
| Lying direct peer, quorum 1 | Can introduce a forged key for a server we have not met, unless another direct peer knows the real key (cross-check). Raise the quorum to require collusion |
| Disagreeing vouchers | Not admitted |
| Stolen invite token | Whoever redeems it first pairs as the invitee. Treat tokens like passwords, keep TTLs short |
| Attacker blocking cross-check traffic | Cross-checks are best-effort: they detect disagreement but do not require agreement |

### Keys

Ed25519 keys travel as raw 32-byte public keys in unpadded base64url. Every signature covers `lattice/1/<kind>\n` + canonical JSON (sorted keys, compact separators, UTF-8) of the message without its signature, so a signature for one message kind cannot be replayed as another. A rotation is signed with the old key and accepted only if that key matches the one on record. A revocation is permanent.

---

## Message Flow

### Local → Remote
1. The host application POSTs to `/api/v1/messages/send` with the admin token
2. The daemon checks the sender's domain is ours, builds and signs a `FederatedMessage`, and stores the signed JSON in `lattice_messages`
3. Immediate delivery is attempted in the background; the scheduler retries pending messages every minute
4. Delivery looks up the recipient's domain among trusted peers, checks the circuit breaker, and POSTs the stored message verbatim to `{endpoint}/api/v1/federation/messages/receive`
5. The recipient returns a signed acknowledgment, verified against the recipient's key on record
6. Failures retry with exponential backoff (2, 4, 8, 16 minutes) up to 5 attempts; signed rejections fail permanently; 5 consecutive failures open the circuit for 15 minutes

### Remote → Local
1. Recipient domain must be ours; timestamp within 24 hours
2. Sender's domain must be a trusted peer, within its rate limit
3. Signature verified with the sender's key on record
4. Duplicate `message_id`s return the recorded acknowledgment
5. Username resolved via the resolver set by `set_username_resolver()`
6. Delivered to `LATTICE_DELIVERY_WEBHOOK`; 2xx is delivered, 4xx is a signed rejection, 5xx or a timeout makes the sender retry

---

## Security

- **Federated content is untrusted**: the host application must filter it before it reaches users or models
- **No trust on first use**: keys come only from invites or cross-checked introductions
- **Signed everything**: gossip, pairing, key queries, messages and acknowledgments
- **Rate limiting**: 100 requests/minute per peer across gossip, key queries and messages
- **SSRF protection**: peer endpoints must be https and must not resolve to private, loopback, link-local or reserved addresses
- **Admin token**: admin endpoints require `X-Lattice-Admin-Token`; never expose them through a proxy
- **Secrets**: the private key is loaded from systemd credentials or `/etc/lattice/private_key.pem` (mode 600)

---

## Database Tables

| Table | Purpose |
|-------|---------|
| `lattice_identity` | Our server's name and UUID (singleton) |
| `lattice_peers` | Known servers, their keys, endpoints and trust |
| `lattice_invites` | Outstanding invites we issued |
| `lattice_vouches` | Direct peers' current vouches |
| `lattice_messages` | Outbound queue holding signed messages |
| `lattice_received_messages` | Inbound idempotency (7-day TTL) |

The schema is created on first use from `lattice/schema.sql`.

---

## Scheduled Tasks

| Task | Frequency | Endpoint |
|------|-----------|----------|
| Gossip round | 10 minutes | `POST /api/v1/announce` |
| Message delivery | 1 minute | `POST /api/v1/maintenance/process_messages` |
| Neighbor selection | 6 hours | `POST /api/v1/maintenance/update_neighbors` |
| Cleanup | Daily | `POST /api/v1/maintenance/cleanup` |

The host application's scheduler calls these on the daemon (port 1113) with `X-Lattice-Admin-Token`. Cleanup expires invites, vouches, messages and received-message records, and forgets introduced peers that are no longer vouched for or have not been seen in 90 days. Direct and blocked peers are never removed automatically.
