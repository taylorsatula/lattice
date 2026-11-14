# Lattice v1 Design Inventory

Every network, protocol, security and operations design choice found in the
v1 codebase and its commit history, recorded so the v2 design can deliberately
keep, change or drop each one. Nothing here is filtered by whether v2 needs it.

Each entry: **what it is** — the problem it addresses. `where`. Status is
*live* unless marked **[partial]** (exists but not fully wired), **[history]**
(existed in an earlier commit, since removed), or **[defined only]** (model or
schema exists, no behavior).

Section 9 lists deliberate removals, which are decisions too. Section 10 lists
places where the code doesn't do what the design describes, so we know which
ideas were actually exercised and which were only written down.

---

## 1. Identity and cryptography

1. **Per-server asymmetric keypair is the root of trust.** RSA-2048, RSA-PSS
   with SHA-256 and MGF1, max salt length. Every authenticity check reduces to
   "signed by the key we hold for this server." `gossip_protocol.py:113,142`
2. **Fingerprint = SHA-256 of the public key, truncated to 128 bits (32 hex
   chars).** Short handle for out-of-band pinning and for the
   `sender_fingerprint` field on messages. Hashes the PEM text, not DER.
   `gossip_protocol.py:490`
3. **Permanent UUID distinct from the human-readable name.** The UUID is the
   identity and the name is mutable; a peer matched by UUID with a new
   `server_id` is treated as a rename, not a new server.
   `models.py:149`, `peer_manager.py:108`
4. **Human-readable `server_id` normalized to lowercase, with schemes and
   spaces rejected.** Prevents case and format aliasing of names.
   `models.py:156`
5. **Fresh nodes self-name from their own key: `lattice-<first 8 hex of
   fingerprint>`.** A new node gets a likely-unique name with no coordination;
   an operator override comes from `LATTICE_DOMAIN`. `init_lattice.py:65`
6. **Private key sanity-checked at load:** a minimum length check, then a
   test signature before the key is used. A corrupt key fails loudly at
   startup instead of at first send. `gossip_protocol.py:66-91`
7. **Self-describing announcements:** the announcement carries its own public
   key and signature, so it can be verified standalone and relayed by
   anyone. `models.py:145`
8. **Key continuity (TOFU-style pinning):** once a peer's key is stored, an
   announcement with a different key is rejected unless it arrives through a
   key rotation. Blocks silent key substitution / MITM.
   `discovery_daemon.py:1851`, `peer_manager.py:97`
9. **Key rotation signed by the old key:** a chain of custody from old key
   to new. The receiver checks that the old key in the message equals the
   stored key, the sender matches the stored peer, and the rotation is logged
   to history with a reason enum (`scheduled` / `compromise_suspected` /
   `upgrade`). Includes a full self-rotation routine.
   `models.py:278`, `peer_manager.py:424`, `gossip_protocol.py:505,558`,
   `schema.sql` `lattice_key_rotations`
10. **Identity revocation ("cyanide pill"):** a self-signed, permanent burn of
    a UUID. The revocation is stored with its signature; future announcements
    from that UUID are refused, and the peer is marked `revoked` and removed
    from the neighbors. Lets a compromised operator kill their own identity
    network-wide. `models.py:289`, `peer_manager.py:55,481`
11. **Canonical serialization for signing:** sorted-key JSON with the
    `signature` field excluded. A test asserts that Pydantic round-trips to
    identical canonical bytes, which is a known failure mode.
    `gossip_protocol.py:156`, `tests/test_signature_verification.py`
12. **Every protocol object is signed:** announcements, messages, delivery
    acks, domain queries, key rotations, revocations, peer exchanges. (Domain
    *responses* are deliberately not trusted on signature; see #24.)
13. **Message-to-key binding on receive:** the `sender_fingerprint` must equal
    the fingerprint of the key stored for the sender's domain, and only then
    is the signature checked against that stored key, never against a key
    supplied in the message. `discovery_daemon.py:2010-2026`
14. **Constant-time comparison** for the admin token and fingerprints
    (`hmac.compare_digest`). `discovery_daemon.py:152,324,2013`
15. **CSPRNG for every random topology choice** (`secrets.SystemRandom`).
    Makes neighbor and fan-out selection unpredictable, so an attacker can't
    steer it. `peer_manager.py:37`, `discovery_daemon.py:270`

## 2. Admission and trust

16. **Restricted first contact:** an announcement from an unknown server is
    accepted only if that server is one of *our* configured bootstraps and
    matches its out-of-band fingerprint pin. `discovery_daemon.py:1858-1886`
17. **Bootstrap pinning on by default:** `ALLOW_UNPINNED_BOOTSTRAP` is an
    explicit, logged opt-out, and `runme.sh` refuses to configure bootstrap
    servers without pins. `discovery_daemon.py:286-328`, `runme.sh`
18. **Bootstrap is pull-based and verified:** `GET /announcement`, then
    signature, 1 h freshness and pin checks, fetched in parallel with
    `return_exceptions=True` so one dead bootstrap doesn't block startup.
    `discovery_daemon.py:459`
19. **Default public bootstrap (`lattice.miraos.org`)** **[history]**: the
    original deploy script pointed new nodes at it so they could join without
    configuration. The current `runme.sh` defaults to none. `3a19a3b`
20. **Envelope/payload consistency:** the envelope `from_server` must equal
    the payload's `server_id` (announcements, revocations) or `from_server`
    (peer exchange); rotation and revocation senders must match the stored
    peer. Stops a peer relaying or forging claims about someone else in its
    own envelope. `discovery_daemon.py:1844,1904`, `gossip_protocol.py:292`
21. **Unknown senders get no expensive work:** for any type other than
    announcement, an unknown sender is rejected before any signature
    verification. `discovery_daemon.py:1888-1914`
22. **First-claim naming:** the first UUID seen with a `server_id` keeps it;
    the same name with a different UUID is rejected as a collision.
    `peer_manager.py:76`
23. **Trust-status levels:** `unknown`, `trusted`, `untrusted`, `blocked`,
    `revoked`, with blocked/revoked enforced on every path: gossip receive,
    query requester, query responder, route answer, inbound message, outbound
    message, neighbor selection, status counts. `schema.sql:24`
24. **Route answers never introduce trust:** a domain response is accepted
    only if its `server_id` equals the queried domain, the peer is already
    known locally and not blocked, and the endpoint equals the endpoint we
    stored from that peer's own signed announcement. Discovery and
    introduction are kept separate, so a malicious responder can't insert
    routes. `discovery_daemon.py:353-399`, `gossip_protocol.py:427`
25. **Separate typed blocklist:** identifier type `domain` / `server` / `ip`
    / `fingerprint`, with optional expiry, reason, `created_by` and a hit
    counter. It is distinct from per-peer trust status, so you can block
    things you've never peered with. `schema.sql` `lattice_blocklist`,
    `peer_manager.py:347`
26. **Fail-closed blocklist:** a DB error during the check means "blocked."
    `peer_manager.py:374`
27. **Outbound to a blocked peer fails permanently,** with no retry loop.
    `discovery_daemon.py:940`

## 3. Freshness and replay

28. **Per-object freshness windows:** announcement 1 h, domain query and
    response 5 min, delivery ack 15 min, message 24 h, plus a 5-minute
    future-skew tolerance, all through one central helper. The window is
    sized to how long each object legitimately lives.
    `discovery_daemon.py:178`
29. **Announcement replay window narrowed from 24 h to 1 h** (deliberate).
    `c47ec06`
30. **Tolerant timestamp parsing:** `dateutil`, naive timestamps treated as
    UTC, everything normalized to UTC. `discovery_daemon.py:166`
31. **Inbound idempotency by `message_id`:** a dedup table with 7-day
    retention; a replay or retry returns the *originally stored ack* instead
    of delivering again. `discovery_daemon.py:2030-2045`
32. **Query dedup by `query_id`:** a bounded `OrderedDict` (1000 entries,
    oldest evicted first) plus 5-minute TTL cleanup. Loop prevention in
    cyclic topologies, with bounded memory. `discovery_daemon.py:281-284,724,1570-1582`

## 4. Gossip and topology

33. **Peers vs. neighbors:** know many peers, talk to a few (at most 8).
    Bounds per-node fan-out independent of network size.
    `peer_manager.py:28`
34. **Random neighbor selection** from non-blocked peers seen in the last
    7 days. Diversity and partition resistance, and nothing to game.
    `peer_manager.py:203`
35. **Slow neighbor churn:** once the neighbor set is full, each refresh has
    a 20 % chance of swapping one random neighbor for one random candidate.
    Trades stability against exploration. `peer_manager.py:240`
36. **Gossip fan-out of 3** random active neighbors per round.
    `discovery_daemon.py:529`
37. **Cadence:** gossip every 10 min (shortened from 1 h for faster
    convergence in small networks), neighbor refresh every 6 h, cleanup
    daily, delivery sweep every 1 min. `init_lattice.py`, `5a0963f`
38. **Active-neighbor liveness filter:** only neighbors seen within 24 h are
    gossip targets. `peer_manager.py:156`
39. **Tiered peer aging:** a neighbor is demoted after 30 days unseen and the
    peer row deleted after 90 days, which keeps the peer table bounded.
    `peer_manager.py:376`
40. **Capabilities and `supported_versions` in the announcement:** a
    version-negotiation and feature-flag hook (`paging`, `ai_messaging`).
    `models.py:126`
41. **Separate `federation` and `discovery` endpoints per server:** the data
    plane is split from the control plane and each can be hosted separately.
    `models.py:133`
42. **Peer-exchange message** **[defined only]**: a signed list of known peer
    IDs. It is verified on receipt, then logged and dropped.
    `models.py:269`, `gossip_protocol.py:336`
43. **Peer-exchange file** **[defined only]**: an out-of-band curated seed
    list (`compiled_by`, `compiled_date`, `expires_at`, `contact`, per-peer
    `trust_level`). The import endpoint was removed because it produced
    unverifiable entries, and the comment lists what a correct
    re-implementation needs (fetch each peer's key, verify reachability,
    handle hostile responses). `models.py:325`, `discovery_daemon.py:2329-2357`
44. **Saturation metric:** 0.7 × neighbor ratio + 0.3 × recently-active
    ratio, computed after each gossip round rather than per request and
    exposed publicly. Lets outsiders judge how well-connected a node is.
    `discovery_daemon.py:587`
45. **Hop-limited query forwarding with hop-by-hop re-signing:** each relay
    re-signs the query as the immediate requester, decrements hops, skips the
    node it came from, and caps fan-out at 3. Authentication is per hop, not
    end to end. `discovery_daemon.py:1608-1660`
46. **Hop budget per purpose:** name registration 20, route resolution 10,
    model default 5, hard cap 20 (lowered from 50 to limit amplification).
    `models.py:240`, `a6a9d46`
47. **Per-hop confidence decay (×0.9)** on cached routes. Distance is treated
    as uncertainty. `gossip_protocol.py:396`
48. **Route cache:** 24 h TTL, `hop_count`, `discovered_via`, `confidence`,
    use counters. `schema.sql` `lattice_routes`, `gossip_protocol.py:462`
49. **Network-visibility confidence for name claims:** the number of *new
    peers learned during the query* is the signal of unexplored regions (0 →
    0.95, 1–2 → 0.8, 3–5 → 0.6, more → 0.4), multiplied by the fraction of
    neighbors that answered; registration needs ≥ 0.8 unless explicitly
    overridden. `domain_registration.py:226-247`
50. **Honest uncertainty with no neighbors:** reported as "available,
    confidence 0.0" rather than an error or a false "available."
    `domain_registration.py:169`

## 5. Delivery and the queue

51. **Durable outbound queue (store-and-forward):** messages land in the DB
    first and sending is decoupled from enqueueing.
    `schema.sql` `lattice_messages`
52. **Sign at enqueue time and store the signature:** retries resend the same
    signed object, and the signing key is the one current when the user sent
    it. `discovery_daemon.py:1204-1221`
53. **Explicit status state machine:** `pending → sending → delivered |
    failed | expired`, with `last_status_change_at`.
    `schema.sql`, `discovery_daemon.py:946`
54. **Lease-style stuck recovery:** a `sending` row older than 5 minutes
    goes back to `pending`, both during cleanup and on startup (crash
    recovery). `discovery_daemon.py:448,680,687`
55. **Exponential backoff:** 2^n minutes capped at 60, at most 5 attempts.
    `discovery_daemon.py:1067`
56. **Expiry independent of attempts:** 24 h, up from 1 h in the original;
    expired messages are never sent. `discovery_daemon.py:1224,780`
57. **Priority scheduling:** `priority DESC, created_at ASC` (urgent first,
    FIFO within a priority), bounded batch per sweep, and queue-specific
    indexes. `discovery_daemon.py:778`, `schema.sql`
58. **Push with poll backstop:** an immediate background attempt on send and
    a 1-minute sweep for retries. The immediate path only fires if the row is
    still `pending`, which prevents double sends.
    `discovery_daemon.py:1266,2225`
59. **Failure classification:** transport errors and missing or invalid acks
    are retryable and count toward the circuit breaker; a *signed business
    rejection* is permanent and does **not** count toward the breaker.
    `discovery_daemon.py:996-1013`, `846d982`
60. **Per-peer circuit breaker:** 5 consecutive failures open it for 15 min;
    it is keyed by the resolved `server_id` (an earlier version keyed it by
    the address domain), persisted in the DB so it survives restarts, and
    reset automatically when the timeout expires.
    `discovery_daemon.py:816-880`, `5a0963f`, `a6a9d46`
61. **Signed delivery acknowledgments:** bound to `message_id` and
    `recipient_server`, fresh within 15 min, verified with the recipient's
    *stored* key, and kept with the message. Stops a MITM from faking
    acceptance. `discovery_daemon.py:882`, `models.py:216`
62. **Two-phase inbound receive:** a `processing` row is inserted as a claim
    (the primary key enforces uniqueness), then completed as
    `accepted`/`rejected` with the stored ack; transient failures *release*
    the claim so the sender's retry can succeed; a concurrent duplicate gets
    409; stale claims are swept after 15 min.
    `discovery_daemon.py:2047-2090,673`
63. **Downstream status mapping:** webhook 2xx → accepted; 4xx → permanent
    signed rejection; 5xx or timeout → 502/504 with the claim released so
    the sender retries. Backpressure from the application reaches the remote
    sender. `discovery_daemon.py:2139-2175`
64. **Unknown recipient → signed permanent rejection,** not a retry.
    `discovery_daemon.py:2107`
65. **No open relay:** messages not addressed to our domain are refused.
    `discovery_daemon.py:1955-1961`
66. **No spoofing of other servers:** an outbound `from_address` must use our
    own domain. `discovery_daemon.py:1197`
67. **Per-user sender authorization** **[history]**: the original adapter
    required the caller's `user_id` to own the username in `from_address`,
    so one user couldn't send as another. It was lost when the adapter moved
    out of Lattice. `b5c7f6c` `federation_adapter.py`
68. **Address format `user@domain`:** both parts non-empty, lowercased.
    `models.py:200`
69. **Typed messages:** `pager` / `location` / `ai_to_ai`, priority 0–2, a
    free-form metadata bag, an optional location bag. `models.py:169`
70. **Provenance passed to the app:** the delivery payload includes
    `sender_verified` and `sender_server_id`, not just content.
    `discovery_daemon.py:2132`
71. **Write-only delivery:** federation can push messages into the app but
    never read user data. `ARCHITECTURE.md`
72. **All federated content is untrusted:** content filtering is the app's
    job and pluggable (LlamaGuard, etc.); MIRA's filter is not part of
    Lattice. `ARCHITECTURE.md`, `331f55b`

## 6. Abuse resistance and resource bounds

73. **Per-peer rate limit, 100/min:** a fixed window updated in a single
    atomic `UPDATE … RETURNING` (no read-modify-write race), returning 503
    if the DB errors (fail closed). `discovery_daemon.py:1806,1975`, `50d9aa7`
74. **Cheapest check first:** rate limit, then trust status, then
    fingerprint, then signature verification (the expensive step).
    `discovery_daemon.py:1971-2026`
75. **Request body cap of 1 MB at the ASGI layer,** including chunked bodies
    without `Content-Length`; tested both ways.
    `discovery_daemon.py:199`, `tests/test_request_body_limit.py`
76. **Field-level size bounds:** content 10 000 chars, metadata 8 KB,
    location 4 KB, gossip payload 64 KB, measured on compact canonical UTF-8
    JSON. `models.py:20-34`
77. **Query amplification limits:** fan-out 3, hops ≤ 20, dedup (#32, #45,
    #46).
78. **SSRF protection on every peer-supplied URL:** https only, no userinfo,
    host required; loopback, private, link-local, reserved and unspecified
    addresses rejected; DNS resolved and *every* address checked, including
    IPv4-mapped IPv6; DNS failure = reject. Checked at parse time **and
    again right before each outbound request** (DNS-rebinding defense).
    `models.py:41-123`, `discovery_daemon.py:466,559,1030,1638`
79. **Timeouts on every outbound call:** gossip 5 s, forward 3 s, bootstrap
    10 s, delivery and webhook 30 s.

## 7. Local control plane and operations

80. **Public vs. admin endpoint split:** admin endpoints need
    `X-Lattice-Admin-Token` (compared in constant time), and return 503 if no
    token is configured (fail closed). This replaced a localhost-only check
    because reverse proxies make every request look local.
    `discovery_daemon.py:127-158`, `20f945d`
81. **Deny-by-default reverse proxy:** an explicit allowlist of the five
    public routes; everything else returns 404. `docs/LATTICE_SYSTEMD.md`
82. **Two-tier status:** public `/status` is minimal (alive, accepting,
    peer_count, saturation, version) and never errors; admin `/health` has
    queue depths, open circuits and uptime. `discovery_daemon.py:1336-1434`,
    `7a88a30`
83. **`maintenance_mode` flag:** makes `/status` report
    `accepting_messages: false`. `discovery_daemon.py:274`
84. **Secrets chain:** systemd credentials first (`LoadCredential` or
    `LoadCredentialEncrypted`, TPM-bound when available), then files under
    `/etc/lattice` with 0600/0700. **Environment variables were rejected for
    secrets** because they leak via `/proc/<pid>/environ`, crash dumps and
    logs. `secrets.py`, `9b1e229`
85. **Key file created with mode 0600 from the start** (`os.open` with mode),
    so it is never readable by others, even briefly. `secrets.py:171`
86. **Config lookup tolerates naming variants:** a per-key credential file,
    a bundled `config` credential, the `LATTICE_` prefix or none.
    `secrets.py:127`
87. **Secure deletion of temporary key files** **[history]**: `shred -u -z`,
    falling back to a random overwrite plus `fsync`. `331f55b`
88. **systemd hardening:** dedicated user, `NoNewPrivileges`, `PrivateTmp`,
    `ProtectSystem=strict`, `ProtectHome`, minimal `ReadWritePaths`,
    `LimitNOFILE`, `MemoryMax=2G`, restart policy, `--workers 1` (one
    process owns all state). `deploy/lattice.service`
89. **Safe default bind address:** `127.0.0.1` when run directly;
    fixed port 1113. `discovery_daemon.py:2425`, `e5d18de`
90. **Single-file SQLite:** idempotent `IF NOT EXISTS` schema and additive
    `ALTER TABLE ADD COLUMN` migrations. Postgres was dropped for deployment
    simplicity. `sqlite_client.py`, `6601854`
91. **SQLite `RETURNING` gotcha handled:** `fetchall()` before `commit()`.
    `sqlite_client.py:259`, `4b45bdc`
92. **Single-row identity table** enforced by `CHECK (id = 1)`.
    `schema.sql`
93. **Self-rate-limited manual announce:** at most once per 60 s unless
    `force`. `discovery_daemon.py:1495`
94. **Retention policy:** received-message records 7 days; delivered,
    failed and expired outbound rows purged after expiry; routes purged after
    their TTL. `discovery_daemon.py:648`
95. **"Async at the edges, sync in the core":** a stated architectural
    principle. `ARCHITECTURE.md`
96. **Lattice doesn't own users:** a username resolver hook plus webhook
    delivery, with the app as a thin client. Motivated by MIRA having
    duplicated Lattice internals. `username_resolver.py`, `50d9aa7`
97. **Thin client library:** maps `reply_to` and `content_type` into
    metadata rather than growing the wire format. `client.py`

## 8. Integration contract with the application

98. **Inbound:** Lattice resolves the username to a `user_id` through the
    app's resolver, then POSTs to the app's webhook with content, priority,
    metadata and provenance.
99. **Outbound:** the app calls the admin `POST /api/v1/messages/send`;
    Lattice signs, queues and delivers.
100. **Scheduling** **[partial]**: the app's scheduler drives gossip,
     neighbor refresh, cleanup and the delivery sweep by calling admin
     endpoints. The daemon has no timers of its own. `init_lattice.py:152`

## 9. Decisions made by removal

| Removed | Replaced with / reason | Commit |
|---|---|---|
| Reputation scoring (`reputation_score`, `neighbor_score`) | Pure random neighbor selection; scoring judged premature and gameable | `c47ec06` |
| HashiCorp Vault | systemd credentials + files; Vault was overkill for one daemon | `9b1e229` |
| Postgres | SQLite; single-daemon service | `6601854` |
| Env vars for secrets | Rejected outright (leakage) | `9b1e229` |
| Localhost-only admin check | Admin token; proxies defeat source-IP checks | `20f945d` |
| CORS middleware | Removed as unused | `c47ec06` |
| 24 h announcement replay window | 1 h | `c47ec06` |
| `max_hops` up to 50 | 20 cap, fan-out 3 | `a6a9d46` |
| Peer-exchange-file import endpoint | Removed; entries were unverifiable | `discovery_daemon.py:2329` |
| Prompt-injection filter inside Lattice | App's responsibility | `331f55b` |
| MIRA adapter inside Lattice | Lattice standalone; "anything with a standalone systemd service is not a microservice" | `b5c7f6c`, `50d9aa7` |
| Signed domain responses | Never added; responses are constrained to locally known peers instead (#24) | `74ba7d1` |

## 10. Where the code doesn't match the design

These are from reading the code; I didn't run them, because the dependencies
aren't installed in this environment. They matter for v2 because they show
which ideas above were actually exercised.

1. **The mesh can't grow past bootstrap.** An unknown announcer is accepted
   only if it is one of the *receiver's* bootstraps (#16). Nothing relays
   third-party announcements: `_perform_gossip_round` sends only our own,
   and peer exchange is a no-op (#42). So when node A announces to bootstrap
   B, B rejects A unless A happens to be in B's bootstrap list. Every node
   knows only its own bootstraps, and the README's "epidemic spread" doesn't
   happen. `discovery_daemon.py:1858`, `:513`
2. **Endpoint paths don't line up.** Announcements advertise
   `{APP_URL}/api/federation` and `{APP_URL}/api/discovery`; senders POST to
   `{federation}/messages/receive` and `{discovery}/api/v1/gossip/receive`;
   the daemon serves `/api/v1/federation/messages/receive` and
   `/api/v1/gossip/receive`, and the shipped Nginx config proxies those at
   the root. This only works with a rewrite that isn't shipped.
   `gossip_protocol.py:240`, `discovery_daemon.py:569,976`
3. **Outbound message signatures likely never verify.**
   `queue_outbound_message` signs a `timestamp` from one `_now_iso()` call
   but stores `created_at` from a second call; delivery rebuilds the message
   with `timestamp=created_at`. The signed bytes and the sent bytes differ
   by microseconds. The test only checks that the signature is longer than
   100 chars. `discovery_daemon.py:1204,1225,960`,
   `tests/test_send_message.py:228`
4. **A stored ack replayed after 15 min fails the sender's freshness check.**
   If the receiver accepted a message but the sender timed out and retries
   later, the receiver correctly returns the original ack (#31), but its
   timestamp is older than the 15-minute window (#28). The sender treats that
   as an invalid ack: it retries, counts a circuit-breaker failure, and keeps
   doing so until the message expires. This is #28, #31 and #61 interacting.
5. **`FOR UPDATE` is silently stripped by the SQLite client,** so the
   collision race protection added in `a6a9d46` does nothing.
   `sqlite_client.py:137`
6. **One rate-limit counter is shared** by gossip, domain queries and inbound
   messages (`query_count`); the `message_count` column is never used.
7. **Nothing sets `trusted` or `untrusted`,** and there is no admin path to
   block, unblock or write to the blocklist. Those tables and columns are
   only ever read.
8. **Name registration can't succeed through the normal path:**
   `ensure_lattice_identity` always creates the identity row first, and
   `register_domain` refuses if one exists. `init_lattice.py:65`,
   `domain_registration.py:334`
9. **Blocking I/O in async handlers with one worker.** Synchronous `httpx`
   inside `async def` blocks the event loop, so one slow peer or webhook
   stalls the whole daemon. In a cycle, A forwards a query to B, B forwards
   back to A, and A can't answer because its loop is blocked on B; each hop
   waits out its timeout. `discovery_daemon.py:1626,2137`
10. **Retry counts disagree:** the queue insert uses 5 max attempts, the
    schema defaults to 3, and the docs describe 2/4/8 minutes over 3 tries.
11. **The fingerprint covers PEM text,** so a peer re-encoding the same key
    (line endings, wrapping) produces a different fingerprint.
12. **Per-user sender authorization is gone** (#67): any local caller with
    the admin token can send as any local username.
