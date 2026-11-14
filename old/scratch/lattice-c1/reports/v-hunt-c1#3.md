# v-hunt-c1#3 — PRIMED VERIFIER

Claim under test: **hunt-c1#3** (reported tier L) — "Pre-migration backup copies only the main
database file, silently omitting WAL-resident committed transactions."
Source: `scratch/lattice-c1/reports/hunt-c1.md`, Finding 3.

## Verdict: ADJUSTED

Mechanism CONFIRMED (reproduced against the real `migrate()`). The claim's stated **reachability
kind is corrected**: it is not PRODUCTION-reachable today, it is LATENT — gated behind a future
durable migration script that does not exist in the tree. Severity L left unchanged. Frequency
confirmed latent.

## Findings

1. [L] — Pre-migration backup is WAL-blind: a `shutil.copy2` of the main DB file alone captures
   no committed transaction that still lives only in the `-wal` sidecar.

- Location: `lattice/storage/migrations.py:_backup_path` (lines 43–47) and `migrate`
  (lines 105–107); journal mode set in `lattice/storage/connection.py:configure_connection`
  (`PRAGMA journal_mode = WAL`, line ~66) and `lattice/migrations/durable/001_initial.sql`.
- Evidence:
  ```python
  digest = hashlib.sha256(db_path.read_bytes()).hexdigest()[:16]   # _backup_path:46
  ...
  backup_file = _backup_path(db_path)                              # migrate:105
  if not backup_file.exists():
      shutil.copy2(db_path, backup_file)                           # migrate:107
  ```
  No `PRAGMA wal_checkpoint`, no `sqlite3.Connection.backup()`, no sidecar handling anywhere in
  the runner (`rg 'checkpoint|\.backup\(|wal' lattice/storage/migrations.py` → none).
- Trigger (LATENT — see reachability correction below): a durable DB that (a) has committed
  transactions still resident only in `-wal` and (b) has a pending migration. Operator action is
  `lattice upgrade` or `lattice serve` with a migration newer than the DB (cli.py:229, 347, 432,
  554, 697; `cmd_serve` cli.py:697). `migrate` opens the connection, runs
  `PRAGMA integrity_check` / `foreign_key_check`, then takes the backup *with the connection
  open*. Opening a WAL DB does not checkpoint, and `integrity_check`/`foreign_key_check` do not
  checkpoint either, so the `-wal` is still unpromoted at copy time; the `-wal`/`-shm` sidecars
  are not copied.
- Frequency: LATENT. **Corrected population**: not "every migrate() call that has work to do" —
  today the backup block is entered only for a DB with `user_version < 1` and a non-empty main
  file, which no path in the tree produces (`cmd_init` creates no durable DB; the first
  `open_connection` yields a 0-byte file so `stat().st_size > 0` is false and the backup is
  skipped). With only `001_initial.sql` present, no initialized deployment has a pending
  migration, so no steady-state `lattice upgrade` takes a backup. The trigger therefore requires
  a **future** `002_*.sql`; cadence is "first release that ships a migration against a DB left
  dirty by an unclean shutdown." Ungroundable from the tree → capped at L.
- Outcome: the backup that "looks complete" omits every transaction still in the WAL. On a later
  operator restore it is silently missing committed custody/peer state. (The live DB is not
  harmed: `migrate`'s own `conn.close()` is the last close and does checkpoint the WAL after the
  copy — the defect is confined to the backup artifact.)
- Confidence: mechanism **traced and reproduced against the production function**; trigger
  reachability **corrected to latent**; frequency latent/unmeasured. Reachability kind: **LATENT**
  (gated behind a future migration script).

## Sub-claims: disposition

- "Only the main file is copied" — CONFIRMED (`copy2` on `db_path`; no sidecar copy).
- "WAL-resident committed transactions are omitted" — CONFIRMED. Reproduction against
  `lattice.storage.migrations.migrate` with a WAL holding the schema *and* a committed row
  (`domain_pins`) produced a backup with **0 tables / 4096 bytes**, while the live DB (WAL
  applied) held the full schema and the row. A separate SIGKILL simulation confirmed a fresh
  connection does **not** checkpoint on open (main file stayed 4096 B until clean close).
- "The digest hashes only the main file" — CONFIRMED (`read_bytes()` on `db_path`).
- "Nothing checkpoints before copying" — CONFIRMED.
- "`storage/cache.py:initialize_cache_db` correctly unlinks `-wal`/`-shm`; the durable path has
  no equivalent" — CONFIRMED (cache.py:49–54 vs migrations.py with no sidecar handling).
- **REFUTED sub-claim**: "Reachability: PRODUCTION (coincidence chain)." Today there is no
  migration beyond `001` (`ls lattice/migrations/durable/` → single file), so the backup block is
  not entered by any DB the tree produces; the failing behavior is unreachable in production and
  in tests (tests close connections cleanly, checkpointing the WAL before `migrate`).
- **REFUTED-in-part**: "Population: every `migrate()` call that has `backup=True` default and work
  to do." With only `001`, a normal deployment's DB is at `user_version=1` and `pending` is empty,
  so the backup line never executes. Frequency is latent, not a per-upgrade population.

## Additional mechanisms, earlier failure sites, new reachability (same trace)

1. **Digest dedup is WAL-blind and reuses stale backups.** `_backup_path` derives the filename
   from the *main-file* bytes (`migrations.py:46`), and `if not backup_file.exists()` (line 106)
   skips a fresh copy. Because recent commits sit in `-wal`, the main file can be byte-identical
   across two genuinely different DB states → the same path → the second `migrate` silently
   reuses a backup from an earlier state instead of the current pre-migration state. Same latent
   reachability; amplifies the same defect.
2. **Test coverage cannot catch it (false-negative).** `tests/test_storage.py:41`
   (`test_migrate_creates_backup`) and `tests/test_schema_upgrades.py` (`test_migration_creates_backup`)
   assert only `backups[0].stat().st_size > 0`. My WAL-blind backup is 4096 B with zero tables, so
   even a correct-looking size assertion passes. The tests `conn.close()` before `migrate`, which
   checkpoints the WAL, so they never exercise the failing condition. This is a coverage gap, not
   a standalone defect, but it is why the defect survived into a release candidate.

## Fix-direction constraints

- A repair must capture WAL-resident state, not merely copy additional files. The correct
  primitive is `sqlite3.Connection.backup()` (or `VACUUM INTO`), or a `PRAGMA wal_checkpoint`
  before copying — a naive `copy2` of `db` + `-wal` + `-shm` is itself racy under a concurrent
  writer and can produce an inconsistent snapshot. Escaping WAL-omission and taking a *consistent*
  snapshot are different requirements; state both.
- The dedup digest must cover the logical DB content (or a checkpointed file + mtime/size), not
  the stale main-file bytes, or a stale backup is silently reused.
- The two fixes are coupled: checkpointing before copy also changes the digest input, so doing one
  without the other leaves the dedup stale-backup mechanism intact.

## Reachability kind

LATENT (gated behind a future durable migration script). Not production-reachable today; the
backup block executes in tests only, and those tests avoid the WAL condition by closing cleanly.

## Checked and clean

- `migrate()` ordering: `current > target` and `target > available` rejected; `pending` filtered
  `current < n <= target`; per-migration `user_version` assertion; `MigrationError` on failure —
  all read end to end, correct apart from the backup block.
- `execute_script` (`connection.py`) is a distinct defect (hunt-c1#2) and is out of scope here;
  noted only so the two are not conflated.
- `_list_migrations` numeric-prefix ordering and `.sql` filtering — correct.
- `cache.py` sidecar unlink on schema-hash mismatch — correct (the contrast the claim draws).

## Enumeration

Composed commands (repo root):

```
ls lattice/migrations/durable/                       # → only 001_initial.sql
rg -n 'executescript|copy2|read_bytes|checkpoint|wal' lattice/storage/migrations.py
rg -n 'user_version' lattice/migrations/durable/*.sql  # → 001 sets user_version = 1
```

| Instance | Disposition |
|---|---|
| `migrations.py:46` `read_bytes()` digest | confirmed — main-file-only hash (additional mechanism 1) |
| `migrations.py:105–107` backup block | confirmed — WAL-blind copy; latent |
| `durable/001_initial.sql` (only migration) | examined — no migration >001 exists ⇒ backup block unreachable in steady state |
| `tests/test_storage.py:41`, `tests/test_schema_upgrades.py` backup tests | false-negative coverage (additional mechanism 2) |

## Design risks (max 2)

1. The backup artifact has no automatic restore path (`rg restore lattice/` → only rate-limit
   restoration); its value is entirely manual, so an operator who trusts it after corruption
   inherits the omission with no build-time warning.
2. `migrate` operates on `db_path` without excluding a concurrently running daemon. If an operator
   runs `lattice upgrade` while `serve` still holds the DB, the WAL is guaranteed non-empty for the
   copy and `busy_timeout` (5 s) can also convert a legitimately busy writer into a spurious
   migration failure. Deployment ordering (systemd stop-before-upgrade) is outside the tree and
   unverified.

## Bound

- Deployment/live behavior not reachable: whether operators stop the daemon before `lattice
  upgrade`, whether a systemd `ExecStartPre` runs the migration, and any production crash
  frequency — none groundable from the tree; the frequency is stated latent, not estimated.
- No live infrastructure, no telemetry, no load harness. Reproductions were self-contained
  Python/SQLite runs (SIGKILL-simulated `os._exit`, and a direct call into the real `migrate()`
  from the repo package).
- Tests were read for the backup assertions; the wider suite was not audited for other migration
  harnesses.
