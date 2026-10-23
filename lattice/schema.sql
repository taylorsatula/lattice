-- Lattice Schema (SQLite)
-- Timestamps are ISO-8601 UTC strings written by the application.

-- Our own federation identity (singleton). The private key lives in secrets.
CREATE TABLE IF NOT EXISTS lattice_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_id TEXT NOT NULL,
    server_uuid TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Known servers. trust records how the key was learned:
--   direct      paired out of band with an invite
--   introduced  vouched for by direct peers and cross-checked
--   blocked     rejected by an admin
--   revoked     self-revoked by its owner
CREATE TABLE IF NOT EXISTS lattice_peers (
    server_uuid TEXT PRIMARY KEY,
    server_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    trust TEXT NOT NULL CHECK (trust IN ('direct', 'introduced', 'blocked', 'revoked')),
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    is_neighbor INTEGER NOT NULL DEFAULT 0,

    -- Rate limiting (SQLite datetime() format)
    request_count INTEGER NOT NULL DEFAULT 0,
    rate_limit_reset_at TEXT,

    -- Circuit breaker
    circuit_failures INTEGER NOT NULL DEFAULT 0,
    circuit_open_until TEXT
);

CREATE INDEX IF NOT EXISTS idx_lattice_peers_trust ON lattice_peers(trust);
CREATE INDEX IF NOT EXISTS idx_lattice_peers_neighbors ON lattice_peers(is_neighbor);

-- Outstanding single-use pairing invites we issued.
CREATE TABLE IF NOT EXISTS lattice_invites (
    id TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Direct peers' claims about their own direct peers.
CREATE TABLE IF NOT EXISTS lattice_vouches (
    subject_uuid TEXT NOT NULL,
    voucher_uuid TEXT NOT NULL REFERENCES lattice_peers(server_uuid) ON DELETE CASCADE,
    server_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (subject_uuid, voucher_uuid)
);

-- Outbound message queue. message holds the signed FederatedMessage JSON.
CREATE TABLE IF NOT EXISTS lattice_messages (
    message_id TEXT PRIMARY KEY,
    to_domain TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    message TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'delivered', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    next_attempt_at TEXT NOT NULL,
    last_status_change_at TEXT NOT NULL,
    last_error TEXT,

    created_at TEXT NOT NULL,
    delivered_at TEXT,
    expires_at TEXT NOT NULL,
    ack_data TEXT
);

CREATE INDEX IF NOT EXISTS idx_lattice_messages_queue ON lattice_messages(status, next_attempt_at, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_lattice_messages_expires ON lattice_messages(expires_at);

-- Inbound message idempotency.
CREATE TABLE IF NOT EXISTS lattice_received_messages (
    message_id TEXT PRIMARY KEY,
    from_address TEXT NOT NULL,
    received_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('processing', 'accepted', 'rejected')),
    completed_at TEXT,
    ack_data TEXT
);

CREATE INDEX IF NOT EXISTS idx_received_messages_cleanup ON lattice_received_messages(received_at);
