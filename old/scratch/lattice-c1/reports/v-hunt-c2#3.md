# v-hunt-c2#3 — primed verifier

Claim under test: finding 3 in `scratch/lattice-c1/reports/hunt-c2.md`
("[L] Extensionless cache path makes the mismatch-recreate path crash with `ValueError: Invalid
suffix`"), reported tier L.

## Verdict: ADJUSTED (mechanism confirmed; the claimed PRODUCTION trigger is refuted — no in-tree
caller can produce an extensionless cache path)

The crash mechanism is real and reproduced: `initialize_cache_db` on an extensionless path whose
stored `schema_hash` does not match the current schema raises `ValueError: Invalid suffix '-wal'`.
But the claim's trigger — "PRODUCTION … operator-configured cache path with no `.`" — is not
reachable from any in-tree code path. `_state_paths` hardcodes the cache filename, so no operator,
no CLI flag, no config field, and no test in the tree supplies an extensionless path. The finding
is library-API-only.

## Re-derived frame (from source, before checking the claim)

- `initialize_cache_db(db_path)` (cache.py:34) does `db_path = Path(db_path)`. The recreate branch
  runs only when `db_path.exists()` (cache.py:42), the stored hash differs (cache.py:45-48), and it
  does, in order: `conn.close()` (47), `db_path.unlink()` (48), then
  `for suffix in ("-wal","-shm"): extra = db_path.with_suffix(db_path.suffix + suffix)` (51-52).
- `Path.with_suffix("")` is legal (returns the path unchanged); `Path.with_suffix("-wal")` is not —
  the argument must begin with `.`. Verified: `Path("/var/lib/lattice/cache").suffix == ""` and
  `with_suffix("" + "-wal")` → `ValueError: Invalid suffix '-wal'`.
- The `with_suffix` call is unconditional inside the loop: it executes before the `extra.exists()`
  guard, so it fires even when no sidecar file exists.
- The cache path producer is `_state_paths` (cli.py:83-90): `return (base_state /
  "lattice.durable.db", base_cache / "lattice.cache.db")`. `base_cache = cache_dir or
  DEFAULT_CACHE_DIR`; `DEFAULT_CACHE_DIR = Path("/var/cache/lattice")` (cli.py:62). The filename
  **`lattice.cache.db` is hardcoded**, so `db_path.suffix == ".db"` always.
- The only in-tree callers are `cmd_upgrade` (cli.py:236) and `cmd_serve` (cli.py:703), both through
  `_state_paths`. `--cache-dir` (cli.py:864/879/897) sets the *directory*, never the filename. The
  systemd unit runs `lattice serve --config /etc/lattice/config.toml` with no `--cache-dir`
  (deploy/lattice.service), and `Config` (config.py) has no cache-path field. Docs name the file
  `/var/cache/lattice/lattice.cache.db` (docs/MIGRATIONS.md:6, docs/ARCHITECTURE.md:72).

## Trace of the actual failure site (decisive)

```
$ python3 -c "<extensionless path, committed hash mismatch, call initialize_cache_db again>"
created True
after commit listing: ['cache']
recreate raised: ValueError Invalid suffix '-wal'
file exists after crash: False
dir listing after: []
```

The failure site is `cache.py:52` (`db_path.with_suffix(db_path.suffix + suffix)`), in the
`-wal` iteration, *after* `db_path.unlink()` at cache.py:48. Sequence: delete old cache file →
`with_suffix` raises → no new cache DB is created and the raw `ValueError` escapes
`initialize_cache_db` (it is raised outside the `try` at cache.py:64, and is not a `CacheError`).

## Sub-claims, individually

| Sub-claim | Disposition |
|---|---|
| Mechanism: `with_suffix` raises `ValueError` when the filename has no suffix | **CONFIRMED** — reproduced; `db_path.suffix == ""` → `with_suffix("-wal")` → `ValueError: Invalid suffix '-wal'`. |
| Failure site is the WAL sidecar-cleanup line, and the old file is deleted first | **CONFIRMED** — cache.py:52, after `db_path.unlink()` at cache.py:48 (verified: file absent after the raise). |
| Not a `CacheError`; the `except sqlite3.Error` at cache.py:64 does not catch it | **CONFIRMED** — the raise is in the pre-creation branch, outside that `try`; `ValueError` is not `sqlite3.Error`. |
| Trigger: "PRODUCTION … operator-configured cache path with no `.`" | **REFUTED** — no in-tree mechanism produces an extensionless cache path. `_state_paths` hardcodes `lattice.cache.db`; `--cache-dir` sets only the directory; the unit passes no flag; config has no cache-path field. `grep` for a cache-path env var/config key returns nothing. Only a direct call to `initialize_cache_db(Path("…/cache"))` reaches it, and no production or test caller does (all callers/tests use a `*.db` path). |
| Trigger condition (b): schema-hash mismatch | **CONFIRMED but not reachable in combination** — the mismatch branch is the intended, reachable path (fires after a `cache_schema.sql` edit), and it works correctly for every `.db` path in the tree. It cannot be paired with an extensionless path from any in-tree caller. |
| Frequency: "latent — two conditions must coincide; no in-tree default produces an extensionless cache path" | **CONFIRMED, and stronger than stated** — the enabling condition has no producer at all, not merely no default. Latent. |
| Outcome: "startup fails", old file deleted, no cache DB created | **CONFIRMED as stated for finding #3**, with a correction to persistence: the very call that crashes already unlinked the file, so the *next* `initialize_cache_db` sees `not exists()` and creates a fresh DB. Verified: attempt 1 raises with the file gone; attempt 2 returns a fresh cache DB. There is no "broken until an operator deletes the file" state for this finding (that phrasing lives in finding #2, which is a different mechanism). |

## Corrections

- **Severity: L → S-.** The mechanism is proven, but a reportable defect must name a concrete
  runtime trigger path reachable by code in the tree today. No in-tree caller (production or test)
  supplies an extensionless path, so the trigger is refuted and the finding as reported fails the
  evidence bar. This is not a kill of the mechanism — the code is genuinely wrong — but it is not a
  reachable L defect. S- is the correct bucket: a real code-shape concern, not a reportable one,
  pending a decision to treat `lattice.storage.cache.initialize_cache_db` as a supported public
  API that arbitrary embedders may call with arbitrary paths.
- **Frequency: latent, unchanged in character, and downgraded in substance.** The hunter's "latent —
  two conditions must coincide" is correct but incomplete: condition (a) (extensionless path) has
  no in-tree producer whatsoever, so the frequency is not an ungrounded cadence but a zero-population
  trigger. No normal operation, no operator action, no restart cadence reaches it.
- **Reachability kind: NOT REACHABLE through any in-tree caller** (not production, not tests-only,
  not gated behind another defect). It is reachable only by a direct library call to
  `initialize_cache_db` with a hand-built suffixless `Path` — no such caller exists in the tree.
  This is the decisive correction: the claim labeled it PRODUCTION.

## Additional mechanisms / earlier failure sites

None reachable. `with_suffix` appears exactly once in the tree (enumeration below); the recreate
branch is otherwise correct for every `.db` path the tree passes it. The only earlier site in this
function is the corrupt-file escape at `open_connection`/`configure_connection` (finding #2's
surface, separately verified in `v-hunt-c2#2.md`) — a different mechanism, not an extension of this
one.

## Fix-direction constraints

1. A repair must construct the sidecar name without `with_suffix` (e.g. `Path(str(db_path) + suffix)`)
   or guard the call; narrowing around the `with_suffix` argument only for the `.db` case leaves the
   suffixless case intact.
2. Ordering matters: sidecar cleanup currently runs *after* `db_path.unlink()`. A repair that merely
   makes the sidecar name legal still deletes the old cache before it knows the new one can be
   created; if creation subsequently fails, the cache is gone. Recreate should be
   unlink-then-create with the deletion inside the same guarded region that converts failures to
   `CacheError`, so a failed recreate self-heals on the next start rather than aborting.
3. The `ValueError` must be converted to `CacheError` for the module contract and the CLI's error
   handling (cli.py:236 catches `Exception`; cli.py:703 `cmd_serve` does not catch, so a raw
   `ValueError` there is an unhandled traceback). The conversion alone does not fix the deletion
   ordering.
4. If the intent is that `initialize_cache_db` only ever receives `lattice.cache.db`, encode that as
   a precondition/assert with `CacheError`, so a library caller gets a contract error rather than a
   mid-mutation `ValueError` after its file has been destroyed.

## Enumeration

Composed command (suffix-manipulation class; confirms the idiom is closed to one site):

```
rg -n "with_suffix" --glob '*.py' .
# lattice/storage/cache.py:52: extra = db_path.with_suffix(db_path.suffix + suffix)
# tests/test_config.py:61: def test_private_mode_with_suffix(self):   (unrelated name, no Path API)
```

Composed command (cache-path producers; confirms no operator-influenced filename):

```
rg -n "cache_dir|cache_path|initialize_cache_db\(|DEFAULT_CACHE_DIR" --glob '*.py' lattice/
# cli.py:62 DEFAULT_CACHE_DIR = Path("/var/cache/lattice")
# cli.py:90 return (base_state / "lattice.durable.db", base_cache / "lattice.cache.db")
# cli.py:236 initialize_cache_db(cache_path)   (cmd_upgrade, except Exception)
# cli.py:703 initialize_cache_db(cache_path)   (cmd_serve, unguarded)
# --cache-dir occurrences (864/879/897) set the directory only
```

Instance table:

| Instance | Disposition |
|---|---|
| `cache.py:52` `with_suffix` misuse | mechanism CONFIRMED; trigger REFUTED (no in-tree producer of extensionless path) → **finding survives only as S-** |
| `_state_paths` cache filename (`lattice.cache.db`) | examined-clean; hardcodes `.db`, so `suffix != ""` for every production call |
| `cmd_upgrade` / `cmd_serve` cache-path construction | examined-clean; both pass `.db` paths |
| CLI `--cache-dir` flags | examined-clean; directory only, cannot produce a suffixless filename |

## Checked and clean

- `Path.with_suffix` semantics on Python 3.12.11: `suffix == ""` → argument must still start with
  `.`; `"" + "-wal"` → `ValueError`; `".db" + "-wal"` → `.db-wal` (valid). The happy path is correct.
- The recreate branch executes as documented for a normal `.db` path (hash mismatch → close, unlink,
  recreate) — verified indirectly by `tests/test_storage.py::test_initialize_recreates_on_schema_mismatch`.
- `db_path.unlink()` precedes the failing call, so the crash leaves no stale file; the next call
  recreates cleanly (verified: attempt 2 succeeds).
- No cache-path configuration surface exists: no env var, no config field, no CLI flag affecting the
  filename; the systemd unit passes no cache-path flag.

## Side discoveries (single-pass candidates, not confirmed work)

- The same function's recreate branch is not itself guarded against a hand-constructed suffix that
  is already dot-prefixed-but-degenerate; not pursued (no producer).
- `cmd_serve` calls `initialize_cache_db` unguarded (cli.py:703) while `cmd_upgrade` guards it with
  `except Exception` (cli.py:239); any escape from this function is a raw traceback under `serve`.
  This is the `v-hunt-c2#2` surface, not a new mechanism — flagged for the merge layer only.

## Design risks (max 2)

1. `initialize_cache_db` is a public function in `lattice.storage.cache` with no precondition
   enforcement on its path shape; the suffix manipulation makes an arbitrary suffixless path a
   post-mutation hard failure. A caller-facing precondition would remove the class. No current
   caller violates it.
2. The recreate path unlinks the cache before establishing that a replacement can be created; a
   disposition for future cache-path configurability should treat delete/create as one recoverable
   step. No in-tree trigger today.

## Bound

- `cache.py` and `connection.py` read end to end; `cli.py` cache-path construction and call sites
  read in full; `runtime.py`/`repositories.py` not re-hunted (other passes own them).
- No live daemon or deployed systemd unit was exercised; the absence of an extensionless-path
  producer is established by reading every cache-path construction and its inputs (`_state_paths`,
  `--cache-dir`, config, unit file), not by running the deployment.
- Python 3.12.11 `pathlib`/`sqlite3` only; other versions and platforms untested.
