-- Lattice v1 cache schema.
-- This database is disposable: it may be recreated on schema mismatch.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- Candidates: peer cards received before independent verification.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS candidates (
    node_id TEXT PRIMARY KEY,
    introduced_by TEXT,
    observed_prefix TEXT,
    card_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_expires ON candidates(expires_at);
CREATE INDEX IF NOT EXISTS idx_candidates_introduced_by ON candidates(introduced_by);
CREATE INDEX IF NOT EXISTS idx_candidates_prefix ON candidates(observed_prefix);

-- ---------------------------------------------------------------------------
-- Transient cards: recently seen peer cards, kept briefly for gossip.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transient_cards (
    node_id TEXT PRIMARY KEY,
    card_json TEXT NOT NULL,
    received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_transient_cards_expires ON transient_cards(expires_at);

-- ---------------------------------------------------------------------------
-- Discovery set: verified peers selected for gossip discovery rotation.
-- Separate from guards; these slots rotate based on prefix diversity.
-- NOTE: No FK constraint — the peers table lives in the durable DB,
-- which is a separate SQLite file from this cache DB.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS discovery_set (
    node_id TEXT PRIMARY KEY,
    selected_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discovery_set_expires ON discovery_set(expires_at);

-- ---------------------------------------------------------------------------
-- DNS cache: well-known resolution results.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_cache (
    domain TEXT PRIMARY KEY,
    node_id TEXT,
    well_known_json TEXT,
    cached_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_cache_expires ON dns_cache(expires_at);

-- ---------------------------------------------------------------------------
-- Rate buckets: authenticated per-peer token buckets.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rate_buckets (
    node_id TEXT PRIMARY KEY,
    message_tokens REAL NOT NULL,
    gossip_tokens REAL NOT NULL,
    last_updated TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Replay window: inbound message deduplication.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS replay_window (
    message_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_replay_window_expires ON replay_window(expires_at);

-- ---------------------------------------------------------------------------
-- Circuit observations: transient failure tracking.
-- circuit_is_open() derives state from consecutive_failures + last_failure_at.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS circuit_observations (
    node_id TEXT PRIMARY KEY,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_failure_at TEXT
);

-- Schema version marker for cache (managed by application, not PRAGMA).
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY CHECK (version = 1),
    schema_hash TEXT NOT NULL
);
