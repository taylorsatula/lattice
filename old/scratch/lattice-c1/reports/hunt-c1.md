# hunt-c1 — durable persistence & migrations

Assigned: `lattice/storage/repositories.py` (end to end), `lattice/storage/migrations.py`,
every SQL file under `lattice/migrations/` (incl. `durable/` and `cache_schema.sql`).
Read end to end; callers (`messages.py`, `runtime.py`, `topology.py`, `peers.py`, `api.py`,
`cli.py`, `storage/connection.py`, `storage/cache.py`) read far enough to ground triggers.

## Findings

### 1. [H] Shared-connection `with self._conn:` blocks cross-contaminate transactions — a duplicate-submit rollback can void an accepted custody row

- Location: `lattice/storage/repositories.py:BaseRepository` (all 34 `with self._conn:` blocks;
  victim site `InboundMessageRepository.create`, repositories.py:935 region); enabled by
  `lattice/storage/connection.py:_LockedConnection` sharing one connection across threads.
- Evidence: every repository method wraps its statements in `with self._conn:` and
  `_LockedConnection`'s docstring states "a single connection can safely be shared by Uvicorn's
  worker thread pool and the runtime's background executors". Python's sqlite3 keeps **one
  transaction per connection**: thread B's statements executed while thread A's `with` block is
  open join A's transaction; A's exception-exit `rollback()` (or normal-exit `commit()`)
  finalizes B's writes too. The RLock guards individual statements only, not transaction spans.
- Trigger (PRODUCTION): sender POSTs a message to `POST /lattice/v1/messages` (sync endpoint →
  Starlette threadpool, `api.py:receive_message` → `InboundMessageService.accept` →
  `InboundMessageRepository.create`). Request C executes its `INSERT INTO inbound_messages`
  (transaction open, uncommitted). A duplicate request A — same `message_id`, i.e. a sender
  retry racing its still-in-flight original — executes the same INSERT on the shared
  connection, sees C's uncommitted row (same connection), and raises IntegrityError.
  Propagation out of A's `with self._conn:` calls `conn.rollback()`, which **discards C's
  uncommitted INSERT**. A's fallback `get_existing_receipt` now finds nothing (row was rolled
  back) → `CustodyError` → A answers 202 with a *rejected* receipt. C's `with` exit then
  commits nothing; C returns **202 with an "accepted" receipt while no custody row exists**.
  The sender honors the accepted receipt, stops retrying; the message is never webhooken and is
  lost. The same rollback mechanism also silently discards any concurrent background write
  (delivery `mark_terminal` 'delivered' → duplicate redelivery after lease expiry;
  maintenance `add_block` → operator block lost while the caller saw success).
- Frequency: NOT demonstrated empirically as a rate. Population that can produce it: every
  inbound message POST plus the continuously-running background writers (delivery/webhook every
  10 s, verify/expiry every 60 s) on the single shared `durable_conn`. The duplicate-submit
  variant requires a retry to land inside the millisecond INSERT→commit window of the original
  request — a coincidence race, but retries are protocol-normal in this system (receipts exist
  precisely because senders retry). The rollback-victim variant needs any repository exception
  (e.g. the `upsert_peer` PK race, see design risks) to coincide with a background write's open
  transaction. Mechanism verified by direct experiment (below); production rate unmeasured.
- Outcome: durable custody silently not established after a 202 + accepted receipt (invariant 5
  violation and message loss); background writes (blocks, delivered-marks) silently rolled back
  while their callers observed success.
- Confidence: mechanism **traced and empirically reproduced** (two threads on one
  `check_same_thread=False` connection; duplicate insert raises IntegrityError whose rollback
  deletes the winner's uncommitted row; winner's `with`-exit then "succeeds" committing nothing).
  Trigger is a race — frequency component unproven. Reachability: PRODUCTION.

### 2. [L] Migration scripts run without a transaction — mid-script failure leaves a partially applied, committed schema with stale `user_version`

- Location: `lattice/storage/migrations.py:migrate` (via `lattice/storage/connection.py:execute_script`,
  `with conn: conn.executescript(script)`).
- Evidence: `execute_script`'s docstring claims "Execute a SQL script within an explicit
  transaction", but `sqlite3`'s `executescript` first issues an implicit COMMIT of any pending
  transaction and then performs **no** transaction control — every statement in
  `durable/001_initial.sql` autocommits individually. The `with conn:` rollback is a no-op.
- Trigger (PRODUCTION, environment-armed): `lattice upgrade` / `lattice serve` / any CLI
  command calling `migrate()` (cli.py:229, 347, 432, 554, 697) with a pending migration whose
  script fails partway (disk full, I/O error, or a future script with a bad statement). All
  statements before the failure are permanently committed while `PRAGMA user_version` stays at
  the old value; `migrate` raises `MigrationError` implying the database was left alone.
- Frequency: latent — requires a mid-script failure (environment-armed). Today's only script
  (`001_initial.sql`) is entirely `CREATE ... IF NOT EXISTS`, so a re-run self-heals; the
  runner's atomicity contract is nevertheless broken and any future non-idempotent migration
  (ALTER TABLE, data backfill) corrupts on partial failure.
- Outcome: partially applied schema committed; `MigrationError` misreports the state as
  rolled-back-able; re-run of a non-idempotent future migration fails permanently.
- Confidence: mechanism **empirically reproduced** — a two-statement script failed on the second
  statement and the first table persisted despite `with conn:`'s rollback. Frequency component
  unproven (no production failure data). Reachability: PRODUCTION (environment-armed).

### 3. [L] Pre-migration backup copies only the main database file, silently omitting WAL-resident committed transactions

- Location: `lattice/storage/migrations.py:_backup_path` / `migrate`
  (`shutil.copy2(db_path, backup_file)`).
- Evidence: `backup_file = db_path.with_name(...)` + `shutil.copy2(db_path, backup_file)` —
  only the main file is copied. The durable database runs `PRAGMA journal_mode = WAL`; after an
  unclean shutdown (SIGKILL, power loss) or while a daemon still holds the file, committed
  transactions can live only in the `-wal` sidecar, not the main file. Nothing in `migrate`
  checkpoints before copying. The backup digest (`hashlib.sha256(db_path.read_bytes())`) also
  hashes only the main file, so the dedup key cannot distinguish WAL-differing states.
- Trigger (PRODUCTION, coincidence chain): daemon crashes leaving committed custody rows in
  the WAL → operator ships a new release adding migration 002 → runs `lattice upgrade` (backup
  taken from the main file alone) → later database corruption → operator restores the
  "pre-migration backup" → restored database is silently missing committed messages/peer state.
- Frequency: latent — requires crash + pending migration + operator restore. Population:
  pre-migration backups taken by every `migrate()` call that has work to do (`backup=True`
  default).
- Outcome: backup that looks complete but omits committed durable custody; restore = silent
  data loss. (Contrast: `storage/cache.py:initialize_cache_db` correctly unlinks `-wal`/`-shm`
  when recreating — the durable path has no equivalent handling.)
- Confidence: mechanism **empirically reproduced** (copy of main file while a `-wal` held a
  committed CREATE TABLE + INSERT produced a backup missing even the table). Frequency
  component unproven. Reachability: PRODUCTION (coincidence chain).

## Checked and clean

- **E6 SQL string-building** — all three assigned sites examined:
  - `repositories.py:284` `updates.append(f"{state_col} = ?")`: `state_col` comes only from the
    fixed dict `{"verified": "verified_at", "established": "established_at", "blocked":
    "blocked_at"}` — column names are literals; all values parameterized. Clean.
  - `repositories.py:290` `sql = f"UPDATE peers SET {', '.join(updates)} WHERE node_id = ?"`:
    every element of `updates` is a fixed literal string (`"state = ?"`, `"domain = ?"`, …);
    values parameterized. Clean.
  - `migrations.py:120` (and :115): f-string interpolation into an **error message**, not SQL.
    Clean.
  - Closure: `rg 'f"' repositories.py migrations.py` returns only the above plus
    `migrations.py:47` (backup filename) and :81/:88 (error messages). No dynamic SQL
    anywhere else; all data values bound via `?`.
- **E5 transaction sites** — all 34 `with self._conn:` blocks enumerated (see Enumeration).
  Subject to Finding 1's shared-connection defect, each block individually does what it claims:
  parameterized statements, correct ON CONFLICT clauses, correct lease compare-and-set
  predicates. `add_block`'s blocks+peers dual-write is inside one block; `transition_peer`'s
  missing-peer check raises before any DML.
- **Lease/queue semantics** (outbound and inbound): claim subqueries correctly restrict to
  `status IN (pending, leased)` + `next_attempt_at <= now` + `expires_at > now` + lease
  expired-or-null; `release_lease`/`mark_terminal` require owner AND unexpired lease AND
  status, so an expired-lease steal cannot corrupt another owner's terminal mark;
  `attempt_count` incremented at claim and consumed by `RetryPolicy.should_retry` (bounded at
  10); `expire_messages` uses RETURNING correctly and erases content/extension/message_json.
- **Timestamp discipline**: `_format_ts` enforces timezone-aware input and emits fixed-width
  UTC `%Y-%m-%dT%H:%M:%SZ`, so all lexicographic comparisons (claim windows, prunes, lease
  expiry) are chronologically correct.
- **FK graph in `durable/001_initial.sql`**: operational keys/peers/observations/guards
  cascade from their parents; outbound/inbound messages RESTRICT on `peer_root_history`;
  `blocks` is deliberately un-FK'd (documented in-script); `webhook_state` cascades from
  `inbound_messages`. Callers (`messages.py` submit/accept, `runtime.py` bootstrap) insert the
  root-history row before the message insert, so RESTRICT is satisfied on live paths.
- **Migration runner logic**: ordering by numeric prefix, `target > available` rejected,
  `current > target` rejected, `PRAGMA integrity_check` + `foreign_key_check` preflight,
  per-migration `user_version` assertion, backup dedup by content hash. Correct apart from
  Findings 2–3. Upgrade from the only prior version (0/empty file) applies 001 idempotently.
- **`cache_schema.sql`**: disposable-by-design; `storage/cache.py` recreates it on hash
  mismatch and correctly removes `-wal`/`-shm` sidecars when recreating.
- **`mark_terminal` erase paths**: clear lease fields, `next_attempt_at`, content, extension,
  `message_json`; inbound adds `terminal_at`. `erase_value or "[erased]"` only misbehaves for an
  empty-string erase value, which no caller passes.
- **Migration-backup-skip logic**: `if not backup_file.exists()` dedups by exact pre-migration
  content hash — reasonable apart from the WAL blindness in Finding 3.

## Enumeration

Composed commands (run from repo root):

```
rg -n 'with self\._conn' lattice/storage/repositories.py | wc -l          # → 34
rg -n 'f"|f\'' lattice/storage/repositories.py lattice/storage/migrations.py
fd -e sql . lattice/migrations                                            # → 2 files
```

Instance table:

| Instance | Disposition |
|---|---|
| repositories.py:84,133,164,201,259,302,330,367,386,406,420,471,504,512,530,556,569,587,594,613,644,669,710,754,786,847,883,935,980,1012,1070,1120,1138,1162 (34 `with self._conn:` blocks) | E5 — all structurally subject to Finding 1; individually examined-clean otherwise |
| repositories.py:284 (`f"{state_col} = ?"`) | E6 — examined-clean (fixed literal whitelist) |
| repositories.py:290 (f-string UPDATE assembly) | E6 — examined-clean (fixed literals, parameterized values) |
| migrations.py:120 (f-string in error message; also :115) | E6 — examined-clean (message text, not SQL) |
| migrations.py:47,81,88 (f-strings: backup filename, error messages) | examined-clean |
| durable/001_initial.sql | examined (Findings 2–3 concern the runner, not this script); idempotent, FKs correct |
| cache_schema.sql | examined-clean |

## Design risks (max 2)

1. `claim_pending`/`claim_for_webhook` re-SELECT the claimed rows by `(lease_owner,
   lease_expires_at)` equality rather than by the ids actually updated. Correct today because
   owner strings embed unique thread names and tasks run on ≥10 s non-overlapping intervals,
   but a tightened schedule or an owner-name collision across restarts would return rows from
   a previous claim and double-deliver.
2. `PeerRepository.upsert_peer` does read-then-INSERT (no ON CONFLICT) for new peers; two
   concurrent creators of the same new node raise IntegrityError. No two concurrent creators
   exist in tree today (verify task is non-overlapping; bootstrap runs pre-scheduler), so this
   is not a standalone finding — but it is an additional rollback trigger that widens
   Finding 1's window.

## Side discoveries (single-pass candidates, not confirmed work)

- **Placeholder root keys are permanent**: `PeerRepository.ensure_root_history` uses
  `ON CONFLICT(node_id) DO NOTHING` (first writer wins), and callers
  (`messages.py` `OutboundMessageService.submit` / `InboundMessageService.accept`,
  `runtime.py` bootstrap `doc.get("root_public_key") or ""`) pass `""` when the root key is
  unknown. A node first seen via a cold message gets a `peer_root_history` row with an empty
  `root_public_key` that can never be replaced with the real key; the immutable key-continuity
  record is silently degraded. Consumers guard against `""` (fall back to domain pins), so no
  immediate failure was traced — needs one more pass (callers are outside this pass's files).

## Bound

- `lattice/storage/connection.py` and `lattice/storage/cache.py` were read for context but are
  outside the assigned set; Finding 1's mechanism lives partly in `connection.py`
  (`_LockedConnection`) and is reported because the defective `with self._conn:` sites are in
  the assigned `repositories.py`.
- Race frequencies (Finding 1) are analytic; no production telemetry or load harness was run
  — the empirical checks were isolated two-thread reproductions outside the repo tree.
- The test suite was not audited for reachability harnesses; all three findings are reachable
  through live daemon/CLI paths, none test-only or gated.
