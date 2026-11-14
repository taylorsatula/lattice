-- Lattice v1 durable schema initial migration.
-- This database stores identity pins, peer history, custody state, receipts,
-- blocks, guards, and minimal audit metadata. It must survive cache deletion.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- Domain pins: the result of well-known resolution.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS domain_pins (
    domain TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    root_public_key TEXT NOT NULL,
    operational_certificate TEXT NOT NULL,  -- JSON text
    endpoints TEXT NOT NULL,                -- JSON text
    pinned_at TEXT NOT NULL,
    last_verified_at TEXT,
    transfer_node_id TEXT,
    trust_reset_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_domain_pins_node_id ON domain_pins(node_id);

-- ---------------------------------------------------------------------------
-- Peer root history: immutable mapping of node_id -> root public key.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peer_root_history (
    node_id TEXT PRIMARY KEY,
    root_public_key TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    retired_at TEXT
);

-- ---------------------------------------------------------------------------
-- Peer operational keys: every operational key/certificate accepted for a node.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peer_operational_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    operational_public_key TEXT NOT NULL,
    certificate_sequence INTEGER NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE (node_id, certificate_sequence),
    FOREIGN KEY (node_id) REFERENCES peer_root_history(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_peer_operational_keys_node_id ON peer_operational_keys(node_id);

-- ---------------------------------------------------------------------------
-- Peers: mutable state for known nodes.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peers (
    node_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('candidate', 'verified', 'established', 'blocked')),
    domain TEXT,
    current_certificate_sequence INTEGER,
    endpoints TEXT,  -- JSON text
    observed_prefix TEXT,  -- network prefix observed at verification time
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    verified_at TEXT,
    established_at TEXT,
    blocked_at TEXT,
    block_reason TEXT,
    FOREIGN KEY (node_id) REFERENCES peer_root_history(node_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_peers_state ON peers(state);
CREATE INDEX IF NOT EXISTS idx_peers_domain ON peers(domain);

-- ---------------------------------------------------------------------------
-- Peer observations: one row per successful observation day.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS peer_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    day TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES peers(node_id) ON DELETE CASCADE,
    UNIQUE (node_id, day)
);

CREATE INDEX IF NOT EXISTS idx_peer_observations_node_id ON peer_observations(node_id);

-- ---------------------------------------------------------------------------
-- Guards: stable established peers used for topology slots.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS guards (
    node_id TEXT PRIMARY KEY,
    slot INTEGER NOT NULL UNIQUE,
    promoted_at TEXT NOT NULL,
    FOREIGN KEY (node_id) REFERENCES peers(node_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Blocks: explicit local blocks of remote nodes.
-- No foreign key: operators may block node IDs that were never observed or
-- introduced (docs/LOOSE_ENDS.md Phase 6).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blocks (
    node_id TEXT PRIMARY KEY,
    blocked_at TEXT NOT NULL,
    reason TEXT
);

-- ---------------------------------------------------------------------------
-- Outbound messages: local custody of messages we are trying to deliver.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS outbound_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    to_node_id TEXT NOT NULL,
    to_address TEXT NOT NULL,
    from_address TEXT NOT NULL,
    content TEXT NOT NULL,
    extension TEXT,  -- JSON text or NULL
    message_json TEXT NOT NULL,  -- full signed message as submitted
    priority TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered', 'failed', 'expired')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (to_node_id) REFERENCES peer_root_history(node_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_outbound_messages_status ON outbound_messages(status);
CREATE INDEX IF NOT EXISTS idx_outbound_messages_next_attempt ON outbound_messages(next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_outbound_messages_queue ON outbound_messages(status, priority, created_at);

-- ---------------------------------------------------------------------------
-- Inbound messages: durable custody of messages we accepted.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inbound_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    from_node_id TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    content TEXT NOT NULL,
    extension TEXT,  -- JSON text or NULL
    message_json TEXT NOT NULL,  -- full signed message as received
    priority TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('accepted', 'webhook_leased', 'delivered', 'failed')),
    receipt TEXT NOT NULL,  -- JSON text of signed receipt
    received_at TEXT NOT NULL,
    webhook_attempt_count INTEGER NOT NULL DEFAULT 0,
    webhook_next_attempt_at TEXT,
    webhook_lease_owner TEXT,
    webhook_lease_expires_at TEXT,
    terminal_at TEXT,
    FOREIGN KEY (from_node_id) REFERENCES peer_root_history(node_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_inbound_messages_status ON inbound_messages(status);
CREATE INDEX IF NOT EXISTS idx_inbound_messages_webhook_next_attempt ON inbound_messages(webhook_next_attempt_at);

-- ---------------------------------------------------------------------------
-- Webhook state: idempotency and retry tracking for inbound delivery.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_state (
    message_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    last_status_code INTEGER,
    last_error TEXT,
    FOREIGN KEY (message_id) REFERENCES inbound_messages(message_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Contacts: operator contact book of verified human bindings.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contacts (
    node_id TEXT NOT NULL,
    username TEXT NOT NULL,
    domain TEXT,
    display_name TEXT,
    avatar_url TEXT,
    root_public_key TEXT NOT NULL,
    card_json TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    PRIMARY KEY (node_id, username)
);

CREATE INDEX IF NOT EXISTS idx_contacts_username ON contacts(username);

-- ---------------------------------------------------------------------------
-- Audit log: minimal structured event records retained 30 days.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_code TEXT NOT NULL,
    node_id TEXT,
    message_id TEXT,
    details TEXT,  -- JSON text or NULL
    recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_recorded_at ON audit_log(recorded_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_event ON audit_log(event_code);

-- Bump schema version.
PRAGMA user_version = 1;
