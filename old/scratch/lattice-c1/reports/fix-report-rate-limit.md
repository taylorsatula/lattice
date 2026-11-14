# Fix report — rate-limit cluster (BUCKET `67kb` + RATE1 `6qzz`)

Executor: swarm-executor (rate-limit file set). Files owned by sibling (runtime.py, api.py) untouched.

## Files and functions changed

- `lattice/rate_limit.py`
  - `TokenBucket.consume` (+13/-4): reject non-finite/<=0 token requests; normalize non-finite
    computed state to empty before admitting (checked before AND after the refill `min`, because
    `min(cap, nan)` silently returns `cap` — probe caught this on first run).
  - `RateLimiter.__init__` (+9/-2): `math.isfinite` rejection of non-finite rates and
    `capacity_minutes` (nan/inf passed the old `<= 0` guards), positivity now includes
    `capacity_minutes`.
  - `RateLimiter._bucket` (+4/-1): capacity floored via `max(1.0, rate*60*capacity_minutes)`;
    new-bucket insert calls ceiling enforcement.
  - New `_enforce_ceiling_locked` (+15): FIFO drop of oldest-tracked buckets down to
    `_MAX_TRACKED_BUCKETS = 10_000` (dict insertion order; O(1) amortized — a first-draft
    per-insert expired-sweep + sort was O(n log n) per insert and timed out the 50k-key probe;
    rewritten). Eviction is quota-neutral: an evicted bucket refills to full anyway after the
    1h idle window, so recreation-full is indistinguishable.
  - New `_evict_expired_locked` (+10): O(n) sweep dropping buckets idle >
    `_BUCKET_IDLE_SECONDS = 3600.0`; run only at snapshot/restore boundaries.
  - `snapshot` (+2/-0): evicts expired + enforces ceiling before collecting (persist no longer
    resurrects idle peers); capacity formulas floored at 1.0.
  - `restore` (+8/-0): per-row ceiling enforcement during load + final expired sweep/cap; capacity
    formulas floored at 1.0. A restart can no longer flood memory from a large persisted table.
- `lattice/config.py`
  - `RateLimitConfig.__init__` (~98) (+5/-0): `math.isfinite` rejection of non-finite
    `messages_per_minute`/`gossip_per_minute` (nan and ±inf previously passed `<= 0`);
    `import math` added.
- `lattice/storage/repositories.py` — `CacheRepository` rate-bucket save/load/prune
  - `save_rate_bucket` (+11/-1): after upsert, prunes when the table exceeds
    `_MAX_RATE_BUCKET_ROWS = 10_000` (cheap COUNT gate, mirroring the `count_candidates` idiom —
    ungated per-row DELETEs made the persist pass O(n²)).
  - New `prune_rate_buckets(now_epoch)` (+4): public retention/cap prune path (was none).
  - New `_prune_rate_buckets` (+15): deletes rows older than
    `_RATE_BUCKET_RETENTION_SECONDS = 86400.0`, then trims to the newest `_MAX_RATE_BUCKET_ROWS`
    rows (`ORDER BY CAST(last_updated AS REAL) DESC LIMIT ?`).
  - `load_rate_buckets` (+5/-2): only loads rows inside the retention window (stale/non-finite
    epochs filtered in SQL); `import time` added.
- `lattice/storage/cache.py` — **no change needed**: it has no rate-bucket-specific surface; the
  `rate_buckets` schema lives in `lattice/migrations/cache_schema.sql`, which is outside my write
  list. No index/DDL change was required for the prune (full scans on a ≤10k-row table, gated by
  COUNT, are sub-millisecond).

## Exemplars mirrored

- `prune_candidates`/`count_candidates` in `repositories.py` — DELETE-with-rowcount + COUNT-gate
  idiom for the prune; `assert row is not None` mirror.
- Config validation idiom in `config.py` — plain `ConfigError` raises in `RateLimitConfig`.

## Verification — EXECUTED

Probe: `/tmp/lattice-rl-probe/probe.py` (throwaway, now deleted), real venv
`.venv/bin/python`, real SQLite cache DB via `initialize_cache_db` + `CacheRepository`, no mocks.
`timeout 400`-bounded; final full run 25.4s, exit 0. Output:

- BUCKET: 50k distinct attacker keys (msg+gossip) -> `_buckets` map = 10_000 (ceiling held, was unbounded).
- BUCKET: restore of 500 peers idle 2h -> map 0 (expired-eviction at restore); snapshot yields none.
- BUCKET: restore of 30k rows -> map 10_000 (restart cannot flood memory).
- BUCKET: 11k distinct node_ids saved -> `rate_buckets` rows = 10_000; oldest (spoof-0..999) trimmed, newest kept.
- BUCKET: 25h-old row excluded by `load_rate_buckets` and deleted by `prune_rate_buckets` (deleted=1).
- RATE1: `messages_per_minute=0.5` -> bucket capacity 1.0; first consume True, immediate second
  False, consume after one refill window (wall clock backdated 130s on the real object) True.
- RATE1: nan / +inf / -inf rejected at `RateLimitConfig` (ConfigError) AND `RateLimiter.__init__`
  (RateLimitError). `consume(nan)`/`consume(inf)` denied; NaN bucket state normalized to 0.0.

Also: `.venv/bin/ruff check lattice/` -> All checks passed. `.venv/bin/mypy --strict lattice/` ->
no issues in 30 files. Existing suite `.venv/bin/python -m pytest tests/` -> 163 passed, 1 skipped
(pre-existing state, not residue from me).

## Found but not touched

- `TokenBucket.__post_init__`/`TokenBucket.restore` still admit non-finite rate/capacity/tokens
  (nan passes their `<= 0` guards). Not in my named regions; upstream guards (config, limiter
  `__init__`, `consume` normalization) cover the accepted trigger. Worth a follow-up row.
- Pre-existing dirty tree (large in-flight restructure, many deletions/untracked files) — left
  exactly as found; no residue added.
