# blind-hunt-c1 — durable repositories & migrations

Pass type: blind third pass (target withheld). Scope read end-to-end:
`lattice/storage/repositories.py` (1182 lines), `lattice/storage/migrations.py` (133),
every SQL file under `lattice/migrations/` (`cache_schema.sql`, `durable/001_initial.sql`).
Adjacent read for the trace: `lattice/storage/connection.py`, `lattice/storage/cache.py`,
`lattice/messages.py`, `lattice/peers.py`, `lattice/runtime.py`, `lattice/cli.py`, `lattice/api.py`.

Method note: every candidate below was reproduced with an executable probe against the real
classes (Python 3.12, `_LockedConnection`, `open_connection`), not inferred from reading.
No file other than this report was written.

---

## Findings

### 1. [M] Shared SQLite connection: the per-call lock does not isolate transactions across threads — a failing repository write rolls back a concurrent thread's successful write

- Location: `lattice/storage/connection.py:_LockedConnection` (lines 29–63) +
  `lattice/storage/connection.py:open_connection` (84–98) +
  `lattice/storage/repositories.py:BaseRepository` / every `with self._conn:` block
  (e.g. `add_block` 364–382, `OutboundMessageRepository.create` 655–698,
  `InboundMessageRepository.create` 870–903).
- Evidence:
  - `connection.py:44-62` acquires `_lattice_lock` **inside** `execute`/`commit`/`rollback`,
    one call at a time; `__enter__`/`__exit__` are inherited and are **not** wrapped.
  - `connection.py:94-95` opens one connection with `factory=_LockedConnection,
    check_same_thread=False`; `RuntimeCoordinator.__init__` (runtime.py:181-193) hands that one
    `durable_conn` to six repositories, and one `cache_conn` to `CacheRepository`.
  - `docs/LOOSE_ENDS.md:71` asserts "`_LockedConnection` serializes all SQLite operations on a
    single connection shared by the request thread pool and background executors. This is correct
    for v1." The lock serializes individual operations, not the transaction spanning a
    repository method's `with self._conn:` block.
- Trigger (production): two threads share one connection.
  (a) A background executor thread (delivery/webhook/expiry/gossip/verify/refresh) or a Uvicorn
  threadpool handler (all FastAPI route handlers are sync `def`, api.py:226-410, so they run in
  the worker thread pool) executes a mutating repository method.
  (b) Concurrently another thread executes a mutating method whose `with self._conn:` block
  **raises**; `sqlite3.Connection.__exit__` then calls the overridden `rollback()` (connection.py:59),
  which rolls back the single still-open implicit transaction — including the first thread's
  not-yet-committed DML. The first method's own `__exit__` then calls `commit()`, a no-op, and it
  returns success.
  A remote peer can force (b) by replaying a `message_id` already accepted from a **different**
  node: `InboundMessageService.accept` (messages.py:236-292) calls `get_existing_receipt`
  (returns `None` for a different sender), then `InboundMessageRepository.create` raises
  `sqlite3.IntegrityError` on `message_id UNIQUE`; the `with self._conn:` block rolls back
  (repositories.py:883-903). A local duplicate `POST /admin/messages/submit` produces the same
  rollback via `OutboundMessageRepository.create`'s `message_id UNIQUE`.
- Reproduction (deterministic, run in-tree):
  - Generic: thread B `with conn: INSERT` then holds; main `with conn: INSERT` then raises →
    `SELECT` returns `[]`; B's row is gone though B exits normally.
  - Repository-level: thread B enters `with conn:` and inserts a `contacts` row (sets a barrier);
    thread A enters `with conn:`, inserts, then raises `sqlite3.IntegrityError`; result:
    `B reported success: True`, `contacts persisted: []`, `B's write lost: True`.
- Frequency: DEMONSTRATED mechanism; population is every concurrent writer on the shared durable
  connection (4 delivery + 2 maintenance executor workers plus the Uvicorn worker pool), and the
  losing write occurs on any repository failure concurrent with another in-flight write
  (duplicate `message_id`, FK/UNIQUE races, disk errors). The exact collision *rate* was not
  measured — that sub-part is SUSPECTED.
- Outcome: silent durable-state loss / non-atomic partial writes. A `mark_terminal` that erased
  custody (or a `claim_pending` lease, or an `add_block` half-pair) can be discarded while its
  caller logs/returns success, so messages can remain un-erased/leased and blocks half-applied.
- Confidence: mechanism traced and reproduced (traced); frequency rate unmeasured (suspected).
- Reachability kind: PRODUCTION.

### 2. [M] Pre-migration backup copies only the main DB file, omitting the WAL — the backup is stale/corrupt for a WAL database

- Location: `lattice/storage/migrations.py:_backup_path` (43-47) and `migrate` (105-107);
  `lattice/storage/connection.py:configure_connection` (73, `PRAGMA journal_mode = WAL`).
- Evidence:
  - `_backup_path` hashes `db_path.read_bytes()` (main file only) and `migrate` does
    `shutil.copy2(db_path, backup_file)` (106-107) while the WAL connection is still open.
  - SQLite WAL keeps committed pages in `<db>-wal` until a checkpoint; a raw copy of the main
    file is not a consistent snapshot.
- Trigger (production): operator runs `lattice upgrade` (cli.py:220-230) — or any CLI command that
  calls `migrate` (cli.py:347, 432, 554, 697) — on a durable DB whose last writer exited
  **uncleanly** (kill/crash) so the WAL still holds committed transactions, **and** at least one
  migration is pending (otherwise `migrate` returns at `current == target`, migrations.py:89-90,
  before the backup). The `cmd_serve` path closes `durable_conn`/`cache_conn` in `finally`
  (cli.py:729-730), so a clean shutdown checkpoints the WAL and masks this.
- Reproduction (real `migrate`, temp DB, one pending migration): create a WAL DB via
  `open_connection`, `CREATE TABLE old`, `INSERT 'precious'`, commit, do not close; call
  `migrate(p)`; the produced `durable-pre-migration-<hash>.db` returns
  `no such table: old` — the backup is missing even the schema. A minimal `shutil.copy2` of the
  same open WAL DB likewise yields `OperationalError: no such table: t`.
- Frequency: DEMONSTRATED for the mechanism; the production cadence is "an upgrade after an
  unclean shutdown with pending migrations", an episodic operator event (grounded, not steady-state).
- Outcome: the documented safety net is a partial database. Restoring it after a failed/corrupted
  migration silently discards every committed transaction not yet checkpointed (custody rows,
  pins, peer state). Additionally, because the backup name is a hash of the main-file bytes only,
  two DB states differing only in the WAL collide and `if not backup_file.exists()` (106) reuses a
  stale backup.
- Confidence: traced (mechanism + trigger); the frequency is a named operator cadence.
- Reachability kind: PRODUCTION.
- Fix-direction: checkpoint first (`PRAGMA wal_checkpoint(TRUNCATE)`) or use the SQLite backup
  API / `VACUUM INTO` while holding a consistent view; copying `-wal`/`-shm` alongside the main
  file also works but must be done under the same lock and is racy against live writers.

### 3. [L, latent] Migrations are not applied in a single transaction despite the documented invariant; a partially failed migration persists partial DDL

- Location: `lattice/storage/migrations.py:migrate` (112, `execute_script(conn, script)`) and
  `lattice/storage/connection.py:execute_script` (100-103);
  claim in `docs/MIGRATIONS.md:22` ("Applies each missing migration in a single transaction").
- Evidence: `execute_script` is `with conn: conn.executescript(script)`. Python's `executescript`
  issues an implicit COMMIT before running and then executes the script in autocommit; the
  surrounding `with conn:` cannot restore atomicity. `migrate` does not wrap the script in an
  explicit `BEGIN`.
- Reproduction (monkeypatched `MIGRATIONS_DIR`, migration 002 with a bad statement after a
  `CREATE TABLE c`): `migrate` raises `MigrationError`, yet `sqlite_master` contains `a`, `b`, `c`
  while `PRAGMA user_version` is still `1` — the failed migration's earlier DDL is committed.
- Trigger: a migration script failing partway (SQL error, disk full, interrupted process). Today
  `001_initial.sql` is unconditionally rerunnable (`CREATE TABLE/INDEX IF NOT EXISTS`), so the
  unchanged `user_version` lets the next run complete it — lasting harm is therefore LATENT and
  gated on the first non-idempotent migration (e.g. `ALTER TABLE ADD COLUMN`), which would fail
  permanently against the partially applied state.
- Frequency: LATENT — no current migration can produce an unrecoverable partial state.
- Outcome: today, recoverable partial schema with `user_version` unchanged; latent, a DB that can
  never be migrated by rerun.
- Confidence: mechanism traced and reproduced (traced); lasting-harm trigger unproven (suspected).
- Reachability kind: PRODUCTION trigger (migration failure), LASTING HARM latent.

---

## Checked and clean

- **SQL construction is parameterized; dynamic SQL is whitelisted.** The only f-string SQL is
  `PeerRepository.transition_peer` (repositories.py:290): `updates` contains only literal column
  fragments chosen from fixed `if` guards and a fixed `{verified,established,blocked}->*_at` map
  (257-262); all values are `?` parameters, `state` is a parameter. No caller-supplied identifier
  reaches the SQL. No injection path.
- **Repository columns match the schema.** Every INSERT/SELECT/UPDATE column in repositories.py
  exists in `durable/001_initial.sql` / `cache_schema.sql` (outbound: message_id,to_node_id,
  to_address,from_address,content,extension,message_json,priority,ttl_seconds,status,attempt_count,
  next_attempt_at,lease_owner,lease_expires_at,created_at,expires_at; inbound adds receipt,
  webhook_attempt_count,webhook_next_attempt_at,webhook_lease_owner,webhook_lease_expires_at,
  terminal_at; etc.). No missing/renamed column.
- **FK ordering at the custody boundary is correct.** `messages.OutboundMessageService.submit`
  (messages.py:113) and `InboundMessageService.accept` (messages.py:263) call
  `ensure_root_history` before `create`, satisfying
  `outbound_messages.to_node_id` / `inbound_messages.from_node_id`
  → `peer_root_history(node_id) ON DELETE RESTRICT` (001 sql:127,155) with `PRAGMA
  foreign_keys=ON` (connection.py:72).
- **`ensure_root_history` immutability is enforced** by `ON CONFLICT(node_id) DO NOTHING`
  (repositories.py:164-172) — a later different root key cannot overwrite peer history.
- **`transition_peer` rejects missing peers** (repositories.py:266-268) rather than silently
  no-op'ing.
- **Migration runner guards are correct**: refuses newer-than-target (82-83), runs
  `integrity_check` and `foreign_key_check` before applying (92-98), verifies each script set
  `user_version` to its own number (118-123), and is idempotent when `current == target`
  (89-90). Tests `test_storage.py` + `test_schema_upgrades.py` pass under `.venv` (14 passed).
- **`remove_block` not resetting `peers.state`** is intended, not a defect: the semantics are
  documented in `BlockStore.unblock` (peers.py:224-230, "The caller must decide whether to leave
  the peer row as blocked"), enforcement reads the `blocks` table (`is_blocked`,
  repositories.py:389-391), and no in-tree caller relies on `peers.state` for block enforcement.

---

## Enumeration

Assignment is enumerable (the SQL surface is finite). One composed command and its instance table:

```
$ find lattice/migrations -name '*.sql' -type f | sort
lattice/migrations/cache_schema.sql
lattice/migrations/durable/001_initial.sql

$ for f in $(find lattice/migrations -name '*.sql' -type f | sort); do echo "-- $f"; \
    grep -nE "CREATE TABLE|CREATE INDEX|user_version" "$f"; done
-- lattice/migrations/cache_schema.sql
Candidates, transient_cards, discovery_set, dns_cache, rate_buckets, replay_window,
circuit_observations, schema_version (9 tables) + indexes; no PRAGMA user_version.
-- lattice/migrations/durable/001_initial.sql
domain_pins, peer_root_history, peer_operational_keys, peers, peer_observations, guards,
blocks, outbound_messages, inbound_messages, webhook_state, contacts, audit_log (12 tables)
+ indexes; PRAGMA user_version = 1 (line 208).
```

`tests/fixtures/durable_schema/` holds one fixture, `v1.sql`, byte-identical to
`durable/001_initial.sql` (md5 `74e1ee6c49de5e2d1c351c0a7327e211`).

Disposition of every enumerated instance:
- `durable/001_initial.sql` — examined; schema/columns clean; contributes Findings 1–3 only via
  the runner/repositories, not via DDL defects.
- `cache_schema.sql` — examined; disposable cache (`cache.py` recreates on hash mismatch);
  columns match `CacheRepository`; no defect in the assigned surface.
- `durable/002_staging_and_erasure.sql` (under `build/lib/…` and every `dist/*.whl`) — not present
  in `lattice/migrations/`; see Side discovery S2.

---

## Side discoveries (single-pass, priced)

- **S1 [L, latent] — uncommitted cache writes.** `runtime.py:803-824`
  (`_circuit_record_success` / `_circuit_record_failure`) call `self._cache_repo.conn.execute(...)`
  with no `with conn:` and no `commit()`. In legacy isolation mode these mutations stay in an open
  transaction and persist only if some later `with conn:` on the shared cache connection commits
  (e.g. `_persist_rate_limits` on clean shutdown) or are lost on crash/`close()`. Cache state is
  disposable by invariant, so impact is bounded: circuit-breaker backoff resets after a restart.
  Trigger: any delivery failure then unclean shutdown. Fix-direction: wrap each in `with conn:`.
- **S2 [M, latent/out-of-scope-by-invariant] — migration/release mismatch.** `build/lib/lattice/migrations/durable/`
  and every `dist/lattice_mesh-*.whl` from 2026-08-01 through 2026-09-27 contain
  `002_staging_and_erasure.sql` (sets `user_version = 2`), but the source tree
  `lattice/migrations/durable/` has only `001` (which does **not** create `inbound_staging`).
  A database created by such a wheel is at `user_version = 2`; the current runner computes
  `available_target = 1` and raises `MigrationError("database user_version 2 is newer than target 1")`,
  so the daemon/CLI would refuse to proceed. No code in the tree uses `inbound_staging`
  (`rg inbound_staging lattice/` = none). Priced M if a v2 DB is in the field; treated as
  out-of-scope for a finding because the preamble declares pre-release schemas non-reportable
  (invariant 8) and no fixture `v2.sql` exists in-tree. Fix-direction if pursued: either restore a
  matching released `002` or add a v2 fixture and a downgrade/refusal policy.
- **S3 [L, latent] — release-fixture coverage gap.** `docs/MIGRATIONS.md` promises CI runs the
  upgrade tests "against every released durable schema fixture", but
  `tests/fixtures/durable_schema/` holds only `v1.sql`, and `test_migrate_from_released_fixtures_is_idempotent`
  loops over whatever is present. If S2's v2 was released, the upgrade path from it is untested.
  Fix-direction: add the v2 fixture alongside the restored migration.

---

## Design risks (≤2, <200 words)

1. **Cache schema hash covers only text, not applied state.** `cache._schema_hash` hashes the
   script text; `initialize_cache_db` compares it to a stored row. Any manual cache edit that
   leaves `schema_version` intact is never detected. Low impact (cache is disposable).
2. **Backup never verified.** `migrate` creates the backup and proceeds without a
   `PRAGMA integrity_check` on the copy, so a broken backup (Finding 2) is discovered only at
   restore time. Adding a post-copy integrity check would turn a silent durability gap into an
   immediate, loud failure.

---

## Bound

- Could not confirm whether durable schema v2 (`002_staging_and_erasure.sql`) was ever a
  *released* schema rather than a build artifact; the evidence is the contents of `dist/*.whl`
  and `build/lib`. Reported as S2 and left at invariant-8 scope.
- Did not run a live daemon or instrument a real deployment, so the collision *rate* for
  Finding 1 is unmeasured; the mechanism and the interleaving are reproduced deterministically.
- WAL/checkpoint behaviour was exercised on macOS/Python 3.12 only; the deployment target's
  filesystem is unverified (SUSPECTED for S1's crash-persistence).
