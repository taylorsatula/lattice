# v-hunt-c2#2 — primed verifier

Claim under test: finding 2 in `scratch/lattice-c1/reports/hunt-c2.md`
("[L] Corrupt cache file crashes startup with a raw `sqlite3.DatabaseError` instead of
recreating the disposable DB"), reported tier L.

## Verdict: ADJUSTED (finding survives; named failure site and half the trigger list refuted)

The defect is real: a corrupt cache file makes `initialize_cache_db` raise a raw
`sqlite3.DatabaseError` that escapes it and is not a `CacheError`, so the documented
"recreate on mismatch" self-heal never runs. The claim's **mechanism class** (a raw
`DatabaseError`, not the caught `OperationalError`, escapes) is correct. Its **named
location** is wrong, and one of its two listed triggers is guarded and does not crash.

## Re-derived frame (from source, before checking the claim)

- `initialize_cache_db` (cache.py:34) on an existing path calls `open_connection(db_path)`
  first (cache.py:44), *then* `_current_schema_hash(conn)` (cache.py:45), then the
  recreate branch.
- `open_connection` (connection.py:87) calls `configure_connection` (connection.py:61),
  which issues `PRAGMA foreign_keys = ON`, `PRAGMA journal_mode = WAL`,
  `PRAGMA busy_timeout = 5000` in order.
- `_current_schema_hash` (cache.py:22) catches only `sqlite3.OperationalError`.
- `main` (cli.py:1002) catches only `CLIError`, `ConfigError`, `CredentialError`,
  `KeyboardInterrupt` — not `sqlite3.Error`/`DatabaseError`.

## Trace of the actual failure site (decisive)

```
$ python3 -c "<initialize_cache_db on a garbage file>"
Traceback (most recent call last):
  File ".../cache.py", line 44, in initialize_cache_db
    conn = open_connection(db_path)
  File ".../connection.py", line 97, in open_connection
    return configure_connection(conn)
  File ".../connection.py", line 73, in configure_connection
    conn.execute("PRAGMA journal_mode = WAL")
sqlite3.DatabaseError: file is not a database
```

`PRAGMA journal_mode = WAL` is the statement that raises for a non-SQLite/truncated file,
inside `configure_connection`, **before `_current_schema_hash` is ever reached**.
Reproduced identically for a malformed page-1 image ("database disk image is malformed").
`_current_schema_hash`'s narrow `except OperationalError` is therefore *not* the operative
site for the demonstrated trigger; the escape happens one call earlier in
`connection.py:configure_connection`.

## Sub-claims, individually

| Sub-claim | Disposition |
|---|---|
| Raw `sqlite3.DatabaseError` escapes `initialize_cache_db` and is not a `CacheError` | **CONFIRMED** — reproduced; module docstring contract at cache.py:14. |
| Failure site is `_current_schema_hash` / "the first statement" | **REFUTED** — the first statement that reads the file is `PRAGMA journal_mode = WAL` in `configure_connection`; `_current_schema_hash` is not reached. |
| Trigger is "daemon or `lattice init` startup, `cli.py:236` / `cli.py:703`" | **HALF REFUTED** — `cli.py:236` is `cmd_upgrade`, not `init`; `cmd_init` (cli.py:93) never calls `initialize_cache_db`. `cmd_upgrade` wraps the call in `except Exception` (cli.py:239) so it prints `CACHE INITIALIZATION FAILED: file is not a database` and returns 1 — **it does not crash**. Only `cmd_serve` (cli.py:703) calls it unguarded, and there `main` does not catch `DatabaseError` → unhandled traceback, non-zero exit. |
| "`cli.py`'s `except CacheError` handlers don't match it" | **REFUTED** — there is no `except CacheError` anywhere in `cli.py` (rg returns zero). The upgrade path uses `except Exception`, which does match. |
| Frequency: environment-armed, latent | **CONFIRMED** — no normal-operation cadence produces a corrupt cache file; latent. |
| Outcome: documented self-heal never runs; DB stays broken until manual deletion | **CONFIRMED** — neither `serve` nor `upgrade` deletes/recreates the corrupt file; both require an operator to remove it. |

## Corrections

- **Severity: L, unchanged.** The bad outcome is a startup failure of a local daemon gated on
  an already-corrupt cache file. The pinned scale reserves H for remote/cross-peer crashes;
  this is operator-environment-armed with no normal cadence. L ("real defect, narrow trigger,
  bounded bad outcome") is correct. No trace produced a case for M (no "plausible normal
  operation" cadence creates the trigger) or for escalation to H.
- **Frequency: latent, unchanged and correctly grounded.** The trigger population is "daemon
  or operator starts against a cache file that is not valid SQLite"; no in-tree code writes a
  corrupt cache. Demonstrated mechanism, ungroundable cadence → stays L/latent.
- **Reachability kind: PRODUCTION for `cmd_serve`** (a real operator starting the daemon whose
  configured `cache_dir` holds a corrupt/truncated file); not test-only, not gated behind
  another defect. The `cmd_upgrade` instance is production too but is caught (`except
  Exception`), so it degrades to a misreported-but-handled error, not a crash.

## Additional mechanisms / earlier failure site

- **Earlier failure site (the correction that matters):** the escape is in
  `connection.py:configure_connection`, not in `cache.py:_current_schema_hash`. Any repair
  targeted at `_current_schema_hash`'s except clause alone leaves the demonstrated serve
  crash intact.
- **Second latent instance of the same class:** `_current_schema_hash` also lets
  `DatabaseError` escape (it catches only `OperationalError`), so a valid-header image whose
  schema page is malformed reaches the same uncaught escape. Not independently demonstrated
  in this pass (corrupting the schema page tended to raise `no such table`/succeed rather than
  `SQLITE_CORRUPT`), so this half is SUSPECTED — but it is the same fix surface.

## Fix-direction constraints

1. The repair must wrap the **`open_connection` call itself** (cache.py:44), or the
   `PRAGMA journal_mode = WAL` in `configure_connection`, not merely widen
   `_current_schema_hash`'s `except` — otherwise the demonstrated non-SQLite/truncated-file
   trigger is untouched.
2. Widening the catch must convert to `CacheError` (module contract) and must preserve the
   recreate path: the disposable cache should be deleted and rebuilt, not merely reported.
   A fix that only converts the exception to `CacheError` still fails to self-heal, since
   `cmd_upgrade`'s `except Exception` already reports without recreating.
3. Distinguish "corrupt file" from "valid but mismatched schema": both currently route to
   "recreate", but a valid-header malformed image must not be treated as an empty DB in a way
   that leaves WAL sidecars inconsistent.

## Bound

- `cache.py`, `connection.py`, and the `initialize_cache_db` call sites in `cli.py` were read
  in full; `repositories.py`/`runtime.py` were not re-hunted (other passes own them).
- Live daemon behaviour was not run end to end; the serve crash is established by the call
  chain `cmd_serve` → `initialize_cache_db` → `open_connection` → `configure_connection` plus
  `main`'s handler list, not by launching uvicorn.
- Whether a valid-header/malformed-schema-page image reliably produces `DatabaseError` (rather
  than `no such table`) in `_current_schema_hash` is unproven — marked SUSPECTED above.
- Python 3.12.11 sqlite3 exception mapping used throughout; other versions untested.
