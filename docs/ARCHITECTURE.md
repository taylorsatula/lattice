# Lattice Architecture

## Overview

Lattice enables decentralized cross-server messaging using a gossip-based peer discovery protocol. No central servers required.

## Architectural Decision: Async vs Sync

### Business Logic (Synchronous)

**Modules:** `gossip_protocol.py`, `peer_manager.py`, `lattice_adapter.py`, `domain_registration.py`

- All core business logic is **synchronous** (no `async`/`await`)
- Follows the "Synchronous Over Async" principle
- Easier to test, debug, and reason about
- No async overhead for non-I/O operations

**Rationale:** Cryptographic operations (signing/verification), database queries, and peer selection algorithms are CPU-bound or use connection pooling. Async adds complexity without benefit.

### I/O Layer (Async)

**Module:** `discovery_daemon.py` - FastAPI endpoints

- FastAPI endpoints use `async def` for efficient HTTP I/O
- Allows concurrent request handling without blocking
- Internal method calls (gossip, delivery) remain synchronous
- Main scheduler calls daemon via synchronous `httpx.Client`

**Rationale:** FastAPI async endpoints don't block the event loop during network I/O (incoming gossip messages, domain queries). This is a framework-level optimization, not a business logic concern.

### HTTP Calls

**Outbound:** Always synchronous using `httpx.Client` (not `AsyncClient`)
- Gossip rounds: `_send_gossip_to_neighbor()` uses `httpx.Client`
- Message delivery: `_send_to_remote_server()` uses `httpx.Client`
- Scheduler calls: `init_lattice.py` uses `httpx.Client`

**Why synchronous HTTP?**
1. These operations happen in background tasks where blocking is acceptable
2. Simpler error handling and timeout management
3. No need to propagate `async`/`await` through call chains

## Key Principle

> **Async at the edges (HTTP I/O), sync in the core (business logic).**

This gives us FastAPI's concurrency benefits without infecting the entire codebase with async complexity.

---

## Database Client Lifecycle

All Lattice modules create `SQLiteClient()` in `__init__`:

```python
def __init__(self):
    self.db = SQLiteClient()
```

**Lifecycle:**
- Client created once per service instance (e.g., one per `GossipProtocol` object)
- SQLite database file created automatically on first access
- Default path: `lattice.db` (configurable via `LATTICE_DB_PATH` env var)
- Schema auto-initialized from `lattice/schema.sql`

**Why SQLite:**
- Lattice is a single-daemon service - no need for external database server
- Simpler deployment and operational overhead
- Sufficient performance for peer discovery and message queuing
- File-level locking handles concurrency

---

## Message Flow

### Local → Local (Same Server)
1. User sends to recipient using username only (e.g., "alice" not "alice@server")
2. PagerTool uses external username resolver (configured via `set_username_resolver()`)
3. If found locally, resolves username → user_id
4. Message delivered directly via PagerTool's normal delivery mechanism
5. **No federation involved** - stays entirely within local server

### Local → Remote (Cross-Server)
1. User sends to federated address (e.g., "bob@other-server.com")
2. PagerTool detects '@' in recipient, calls `LatticeAdapter.send_federated_message()`
3. Message queued to `lattice_messages` table with status='pending'
4. Scheduler calls discovery daemon every 1 minute
5. Discovery daemon's `process_message_queue()` reads pending messages
6. Circuit breaker check - skip if peer has too many failures
7. `_deliver_single_message()` sends HTTP POST to remote server's federation endpoint
8. Status updated to 'delivered' or retried with exponential backoff (2, 4, 8 minutes)
9. After 5 consecutive failures, circuit breaker opens for 15 minutes

### Remote → Local (Inbound)
1. Remote server POSTs to `/api/federation/v1/messages/receive`
2. **Rate limiting check** - 100 messages/minute per peer (sliding window)
3. Extract sender domain from `from_address`
4. Look up sender's peer record from `lattice_peers` table
5. **Signature verification** - verify RSA signature using sender's public key
6. **Prompt injection filtering** - all content treated as UNTRUSTED
7. Username resolution via external resolver (configured via `set_username_resolver()`)
8. Create PagerTool instance for recipient user
9. `PagerTool.deliver_federated_message()` writes message to user's local pager (write-only)
10. Return 200 OK with acceptance status

---

## Security

- **All federated content treated as UNTRUSTED** - filtered for prompt injection
- **Signature verification** - RSA-2048 signatures on all messages
- **Rate limiting** - 100 messages/minute per peer (sliding window)
- **Circuit breaker** - 5 failures → 15 minute timeout per peer
- **Write-only delivery** - Federation can't read user data, only write messages
- **Credentials in Vault** - Private keys stored in HashiCorp Vault

---

## Performance

- **Message delivery**: Every 1 minute (configurable via scheduler)
- **Gossip rounds**: Every 10 minutes
- **Neighbor updates**: Every 6 hours
- **Cleanup**: Daily
- **Crash recovery**: On daemon startup, all 'sending' → 'pending'

---

## Production Deployment

See `LATTICE_VAULT_SETUP.md` and `LATTICE_SYSTEMD.md` for setup instructions.

**Required:**
1. Database schema auto-created on startup (SQLite)
2. Configure Vault secrets (APP_URL, private key)
3. Run discovery daemon (systemd service: `deploy/lattice.service`)
4. Configure username resolver for message delivery to local users
5. Main scheduler automatically handles periodic tasks

**Monitoring:**
- Discovery daemon health: `http://localhost:1113/api/v1/health`
- Peer list: `http://localhost:1113/api/v1/peers`
- Message queue status: Query `lattice_messages` table in SQLite
- Circuit breaker state: Logged when failures occur
