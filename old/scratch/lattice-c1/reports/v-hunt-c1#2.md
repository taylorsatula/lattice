# v-hunt-c1#2 — PRIMED VERIFIER

Claim under test: **hunt-c1 #2 [L] — Migration scripts run without a transaction; mid-script
failure leaves a partially applied, committed schema with stale `user_version`**
(`scratch/lattice-c1/reports/hunt-c1.md`, finding 2, reported tier L, reachability "PRODUCTION
(environment-armed)").

Method: frame re-derived from source before reading the claim's conclusion. `migrations.py` and
`connection.py` read end-to-end; `lattice/migrations/durable/001_initial.sql` and
`lattice/migrations/cache_schema.sql` read end-to-end (all statement heads enumerated); the five
`migrate()` callers in `cli.py` read; `lattice/storage/cache.py` read for the second
`execute_script` caller; `tests/test_schema_upgrades.py` read for the harness. Mechanism and
frequency checked by direct interpreter experiments (Python 3.12.11 / 3.13.9 / 3.14, sqlite
3.45.3). No live daemon, CLI run, or disk-full condition was exercised.

## Verdict: CONFIRMED (L, latent / environment-armed)

Mechanism, trigger, and frequency re-derive to the claim. Severity stays L. No correction to tier
or frequency is issued; the trace that produced that (non-)correction is below, together with two
added mechanisms and one fix-direction constraint the claim does not state.

### Frame re-derived from source

- `execute_script` (connection.py:100-103) is exactly `with conn: conn.executescript(script)`; its
  docstring says "Execute a SQL script within an explicit transaction."
- `migrate` (migrations.py:104-125) loops over `pending`, calls `execute_script(conn, script)` once
  per migration, catches only `sqlite3.Error`, and raises `MigrationError` on failure. There is no
  explicit `BEGIN`/`COMMIT` anywhere in the runner.
- `conn` is opened via `open_connection` (connection.py:85-94), which sets
  `check_same_thread=False` and factory `_LockedConnection`, and `configure_connection` sets
  `PRAGMA foreign_keys = ON`, `journal_mode = WAL`, `busy_timeout`. `sqlite3.connect` default
  `isolation_level=""` is left unchanged (no `autocommit` argument is passed).
- The only two scripts run through `execute_script` are `cache_schema.sql` (disposable cache) and
  `durable/001_initial.sql` (the sole durable migration).
- The five CLI callers (`cli.py:229, 347, 432, 554, 697`) are `upgrade`, `serve`, and three
  offline commands; each calls `migrate(durable_path)` and prints `MIGRATION FAILED: {exc}` then
  returns 1 on `MigrationError`.

### Mechanism (CONFIRMED, empirically)

Three sub-assertions, each reproduced with the repo's own `execute_script`:

1. `executescript` issues an implicit COMMIT of any pending transaction. Confirmed:
   `conn.execute("INSERT ...")` leaves `in_transaction == True`; a subsequent `executescript`
   returns `in_transaction == False` and the INSERT is durable.
2. Each statement in the script autocommits individually. Confirmed: a two-`CREATE` script whose
   third statement is `INSERT INTO nonexistent` raised `sqlite3.Error` and left **both** tables in
   `sqlite_master` (`SELECT` after the failure returned `['a','b']`).
3. Therefore the `with conn:` rollback is a no-op. Confirmed — the context manager's
   `__exit__` has no open transaction to roll back, because `executescript` already committed each
   statement and committed/closed its own implicit transaction. Running the claim's exact shape
   through `lattice.storage.connection.execute_script` on a real `open_connection` DB reproduced
   the partial commit with `PRAGMA user_version` still 0.

Stable across the supported interpreters: Python 3.12.11, 3.13.9, 3.14 all leave `['a','b']`
committed. (3.11 not installed on this host; behavior is unchanged in CPython 3.11's `executescript`
and legacy `isolation_level` handling. Recorded as a bound, not a gap in the trace — 3.12/3.13/3.14
all confirm.)

### Trigger (CONFIRMED, environment-armed; not request-reachable)

A CLI/daemon start with a **pending** migration whose script fails partway. `pending` is non-empty
only on a fresh install (`user_version` 0 → 1) or a future version bump; `migrate` early-returns
when `current == target`, so steady-state restarts never enter the loop. The failure requires a
`sqlite3.Error` mid-script: disk full, I/O error, or a malformed future script. This is
**environment-armed**, i.e. latent-by-trigger — not reachable by a request or peer action, and not
gated behind another defect. The claim's label "PRODUCTION (environment-armed)" is accurate; I
would state it as **latent / environment-armed, production tooling** rather than request-reachable.

### Frequency (CONFIRMED latent; no correction)

The claim's frequency is already "latent". I confirm it and add the grounding it lacks: the
population that enters the loop is *fresh installs and version upgrades only* — one occurrence per
deployment for the former, one per release-with-a-migration for the latter, of which there are
zero today beyond 001. The trigger additionally needs a statement failure (disk-full/IO-error).
No telemetry exists for disk-full incidence; the operation population is therefore ungroundable and
the finding is LATENT by definition. No frequency correction issued.

### Outcome (CONFIRMED, with a precision correction)

Today's only durable script, `001_initial.sql`, is entirely `CREATE TABLE IF NOT EXISTS` /
`CREATE INDEX IF NOT EXISTS` plus two PRAGMAs and a trailing `PRAGMA user_version = 1`
(all statements enumerated below). I verified directly that a partially-applied state
(`user_version == 0`, `domain_pins` already present) migrates cleanly to 1 on re-run — **so a
mid-script failure on the current script self-heals and leaves no lasting damage.** The live,
persistent consequences the claim lists are therefore all downstream of a *future* non-idempotent
script: a committed partial schema with `user_version` still old, a `MigrationError` that does not
tell the operator the DB was half-written, and a permanently stuck re-run (`ALTER TABLE`/backfill
re-fails on objects the partial run already created). The claim states this dependency, so this is
a precision note, not a refuted half: the contract is broken today, the harm is future-script-armed.

### Severity correction

Left at **L**. The mechanism is proven (not S-), the trigger is narrow (disk-full/IO-error on a
migration with pending work), and the present outcome is bounded and self-healing, becoming
lasting only under a future non-idempotent migration. That is exactly the L band ("a real defect
with a narrow trigger or a bounded bad outcome"). I considered M and declined: no *plausible normal
operation* produces wrong durable state today, and the current script heals on retry. I considered
S- and declined: the mechanism is empirically reproduced, so the evidence bar is met. No
correction issued; trace above.

### Refuted / softened sub-claims

- **"`MigrationError` implying the database was left alone"** — softened, not refuted. The raised
  text is `f"migration {number} ({migration_path.name}) failed: {exc}"` and the CLI prints
  `MIGRATION FAILED: {exc}`. Neither text asserts rollback. The false-atomicity expectation lives
  in `execute_script`'s docstring ("within an explicit transaction") and in the `with conn:` shape,
  not in the error string. The sub-claim's *consequence* (operator misled about state) holds
  through the docstring contract; its stated *locus* (the error message) is imprecise.
- No other sub-claim is refuted. Each of the three mechanism assertions, the caller enumeration,
  and the idempotency-of-001 assertion re-derived to the claim.

## Added mechanisms / earlier failure sites / new reachability

1. **Second root cause the claim omits: `with conn:` could not have made DDL atomic even without
   `executescript`.** CPython's legacy `sqlite3` (default `isolation_level=""`) auto-begins an
   implicit transaction only for DML (INSERT/UPDATE/DELETE/REPLACE), not for DDL. Verified:
   `with conn: conn.execute("CREATE TABLE a(x)")` leaves `in_transaction == False`, while an
   explicit `conn.execute("BEGIN")` followed by `CREATE TABLE` does open a transaction and is
   rolled back by `rollback()`. So the runner's atomicity is absent for *two* independent reasons,
   and the `with conn:` wrapper is dead weight at the report-site. This changes the repair required
   (see constraints).
2. **Second call site of the same false contract: `cache.py:initialize_cache_db`** calls
   `execute_script(conn, script)` (without the `with conn:` wrapper) and then wraps only the
   `schema_version` INSERT in `with conn:`. The non-atomic schema create is harmless here because
   the cache is disposable-by-design and recreated on hash mismatch — checked-clean, not a finding.
3. **No earlier failure site** on this trace: the first mutating statement of a migration *is* the
   first autocommitted statement, so there is nothing upstream to blame; the runner's missing
   explicit transaction is the earliest controllable point.
4. **No new request-reachable path found.** `migrate` is not exposed on any HTTP route; all five
   callers are CLI lifecycle commands. The site is not test-only (the suite's
   `test_migration_creates_backup` / `test_migrate_from_empty_database` exercise success only;
   `test_schema_upgrades.py` has no failing-script fixture) and not gated behind another defect.

## Checked and clean

- **All statement heads in `001_initial.sql`** enumerated: 15 `CREATE TABLE IF NOT EXISTS`, 12
  `CREATE INDEX IF NOT EXISTS`, `PRAGMA foreign_keys`, `PRAGMA journal_mode`, `PRAGMA
  user_version`. Every statement is idempotent, so the current script self-heals on re-run
  (verified against a hand-built partial DB: `migrate` → 1).
- **`cache_schema.sql` re-creation path** — disposable-by-design; `initialize_cache_db` unlinks the
  DB and `-wal`/`-shm` on hash mismatch, so non-atomic create does not strand state. Clean.
- **`migrate` control flow** — `target > available` and `current > target` rejected;
  `integrity_check` / `foreign_key_check` preflight; per-migration `user_version` assertion;
  backup dedup by content hash. Correct apart from the transaction handling here and the WAL-backup
  blindness in hunt-c1 finding 3 (out of scope for this claim).
- **`_current_user_version` assertion** — `applied != number` catches a script that forgets to set
  `user_version`; it does not (and cannot) recover a partially committed script. Correct as written.
- **Interpreter stability** — reproduced on 3.12.11, 3.13.9, 3.14.9. Same result.

## Enumeration

Composed commands (repo root):

```
rg -n "executescript" --glob '*.py' lattice/          # → connection.py:51,53,103 (only production call is :103)
find lattice/migrations -name '*.sql'                 # → cache_schema.sql, durable/001_initial.sql
rg -n "migrate\(" lattice/                            # → cli.py:229,347,432,554,697 (+ def migrations.py:50)
grep -niE '^\s*(CREATE|DROP|ALTER|INSERT|UPDATE|DELETE|REPLACE|PRAGMA)' \
    lattice/migrations/durable/001_initial.sql        # → 15 CREATE TABLE IF NOT EXISTS, 12 CREATE INDEX IF NOT EXISTS, 3 PRAGMA
```

| Instance | Disposition |
|---|---|
| connection.py:100-103 `execute_script` | defective site — `with conn:` + `executescript` is not atomic (this claim) |
| migrations.py:112 `execute_script(conn, script)` | defective caller — no explicit `BEGIN`/`COMMIT` (this claim) |
| cache.py:59 `execute_script(conn, script)` | examined-clean — disposable cache, recreated on hash mismatch |
| migrations.py:104-125 pending loop | checked — correct apart from missing transaction |
| durable/001_initial.sql (all 30 statements) | examined-clean — fully idempotent; self-heals |
| cache_schema.sql | examined-clean — disposable |
| cli.py:229,347,432,554,697 | examined-clean — callers surface `MigrationError` as exit 1 |

## Fix-direction constraints

A repair must account for all of the following, beyond "wrap it in a transaction":

1. **Remove or fix the docstring contract** at connection.py:100. The current text asserts an
   explicit transaction that does not exist; the fix must either make it true or delete the claim.
2. **`executescript` cannot be fixed by the caller's `with conn:`** — it self-commits before and
   during the script. Atomicity requires transaction control *inside* the mechanism: either an
   explicit `BEGIN`/`COMMIT` embedded in the script text passed to `executescript`, or abandoning
   `executescript` for per-statement execution.
3. **Per-statement execution under `with conn:` is still not enough.** Because legacy sqlite3 does
   not auto-begin for DDL, the runner must issue an explicit `conn.execute("BEGIN")` (or set
   `isolation_level=None` and manage `BEGIN`/`COMMIT` itself) around each migration, or the DDL
   will still autocommit individually. This is the constraint the claim does not state.
4. **Interactive with `PRAGMA user_version`:** the version bump must land in the same transaction
   as the schema change, so a rollback leaves both unchanged. Setting the version in a separate
   committed statement re-opens the divergence the finding names.
5. **Must not break 001's idempotency** (re-running after a partial failure is currently the
   recovery mechanism) and must keep the backup (hunt-c1 finding 3) meaningful — a transaction fix
   does not repair the WAL-blind backup, so the restore guarantee needs both repairs.

## Bound

- Disk-full / I/O-error incidence is not measurable from the tree (no telemetry, no load harness);
  the trigger's real-world rate is ungroundable, which is why the finding is latent.
- Python 3.11 was not installed on this host; `executescript` behavior was confirmed on 3.12.11,
  3.13.9, and 3.14.9. CPython 3.11's behavior is the same by construction of the legacy
  `isolation_level` path, but I did not execute it.
- No live daemon, CLI, or SQLite fault injection was run; all mechanism evidence is isolated
  interpreter experiments plus in-tree reproduction through the repo's own `execute_script` and
  `migrate`.
