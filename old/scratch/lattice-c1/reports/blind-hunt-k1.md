# blind-hunt-k1 — blind third pass: deployed artifact vs source contract

Pass type: blind hunter (target withheld). Scope read end-to-end: `deploy/lattice.service`,
`deploy/lattice.nginx.conf`, `pyproject.toml`, `tests/test_deployment.py`, `tests/test_wheel.py`,
plus docs-vs-code comparison (`docs/LATTICE_SYSTEMD.md`, `docs/MIGRATIONS.md`,
`docs/ARCHITECTURE.md`, `docs/KEY_MANAGEMENT.md`, `README.md`) and a fresh wheel-contents-vs-source
diff. All checks against the dirty working tree at HEAD `60acd1c`.

Neutral question: does the deployed artifact match the source contract (systemd unit, Nginx config,
packaged file set, entry points, documented-vs-actual config)?

**Overlap note (dedupe for merge).** Two independent defects found here coincide with an existing
corpus report on the identical scope, `hunt-k1.md` findings #1 and #2. Passes are blind; this pass
re-derived both from source before reading that report. The merge layer should count them once. What
this pass adds is (a) independent reproduction by direct execution of the shipped console script,
(b) the web-verified systemd semantics that `hunt-k1#2`'s decisive claim rested on and that no
verifier had checked, and (c) a frequency correction on #2 (M→L by the pinned calibration rule).

## Findings

1. [M] — Shipped systemd `ExecStart` cannot start the daemon: top-level `--config` placed after
   the subcommand is rejected by the CLI parser
- Location: `deploy/lattice.service:26`; `lattice/cli.py:_build_parser`; `lattice/cli.py:main`.
  Same mechanism in `docs/LATTICE_SYSTEMD.md:29-30,75,126,132`, `docs/MIGRATIONS.md:15`,
  `README.md:21-22`.
- Evidence: unit line
  `ExecStart=/opt/lattice/venv/bin/lattice serve --config /etc/lattice/config.toml`.
  `_build_parser` declares `--config` **only** on the top-level parser; the `serve` subparser
  declares only `--state-dir`, `--cache-dir`, `--log-level`. Executed against the repo venv:
  - `.venv/bin/lattice serve --config /etc/lattice/config.toml` →
    `lattice: error: unrecognized arguments: --config /etc/lattice/config.toml`, exit 2.
  - Control: `_build_parser().parse_args(["--config", C, "serve"])` → OK; bare `serve` → OK
    (config defaults to `/etc/lattice/config.toml`).
- Trigger: every `systemctl start lattice` after installing per `docs/LATTICE_SYSTEMD.md` — fails
  deterministically on the first start; nothing must coincide. Reachability: **PRODUCTION**
  (operator action, the primary documented deploy path).
- Frequency: DEMONSTRATED — every deployment, every start; deterministic, no coincidence required.
- Outcome: the console script exits 2 before loading config/keys/DB. The shipped unit can never run;
  `Restart=on-failure` + `StartLimitBurst=3`/`StartLimitInterval=60` latches the unit to `failed`
  within ~30 s (systemd side not reproduced here — see Bound). No data loss, no exposure.
- Confidence: traced — mechanism (argparse), trigger (unit line, executed), frequency
  (deterministic) all proven by execution. Reachability PRODUCTION.
- Tier: **M**. The pinned H scale enumerates data loss/corruption, secret/root-key exposure, auth
  bypass, cross-peer reach, remote crash / unbounded resource exhaustion by a peer. A
  dead-on-arrival service is availability failure and fits none of them; it is a correctness fault
  under a plausible normal operation → M. (Consistent with v-hunt-k1#1's H→M adjustment.)
- Why the suite misses it: `tests/test_deployment.py:77`
  (`assert "lattice serve --config /etc/lattice/config.toml" in text`) grep-matches the broken string
  without executing it; `tests/test_cli.py` exclusively uses the pre-subcommand order
  (`main(["--config", path, "config"])`); `tests/test_wheel.py` runs only `lattice --help`.

2. [L] — `ExecReload=/bin/kill -HUP $MAINPID` kills the uvicorn daemon and `Restart=on-failure`
   does not bring it back
- Location: `deploy/lattice.service:27,29`; `lattice/cli.py:cmd_serve` (the only serve loop,
  `uvicorn.run(...)`).
- Evidence: unit lines `ExecReload=/bin/kill -HUP $MAINPID` and `Restart=on-failure`.
  `.venv/.../uvicorn/server.py:36-38` — `HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM)`
  (plus `SIGBREAK` on Windows); no SIGHUP handler anywhere in `lattice/`. Python's default SIGHUP
  action is process termination. systemd semantics (web-verified against
  `systemd.service(5)`/`man7` and multiple secondary sources): for `Restart=on-failure`, death by
  **SIGHUP, SIGINT, SIGTERM, SIGPIPE** is a *clean* exit and does **not** trigger a restart.
- Trigger: an operator runs `systemctl reload lattice` — a standard action the unit explicitly
  advertises by defining `ExecReload` (e.g. after editing `/etc/lattice/config.toml`). One operator
  action; nothing else must coincide. Reachability: **PRODUCTION** (operator-triggered); note the
  deployment guide tells operators to use `systemctl restart`, not `reload`, so this is not the
  documented path.
- Frequency: **LATENT** — the population is "operators who use the advertised `systemctl reload`",
  a habit cadence this tree does not ground to a deployment event; the docs' rotate/restart
  instructions do not exercise it. Per the pinned calibration rule an ungrounded frequency caps at L.
- Outcome: the daemon is killed mid-flight with no graceful drain and no auto-restart; the unit
  settles `inactive (dead)` until a human runs `systemctl start lattice`. Total outage from a
  single routine command, but recovery is one manual command and no data is lost/corrupted.
- Confidence: traced for mechanism (uvicorn handles only INT/TERM; SIGHUP default-terminates) and
  trigger (shipped `ExecReload` line); suspected for the systemd-side no-restart consequence
  (documented semantics, not reproducible on this macOS host). Reachability PRODUCTION.
- Severity correction vs. corpus: `hunt-k1#2` reported this M and no verifier checked it. Mechanism
  upheld; tier corrected **M→L** — the trigger is operator-habit, not grounded to a normal-operation
  cadence, and per the calibration rule an ungroundable frequency is latent and caps at L. If the
  ledger treats "total outage, no auto-restart" as outweighing the latent frequency, the trace
  supports M; the correction is recorded rather than silently applied.

## Checked and clean

- **Packaged file set vs source (fresh wheel build, `/tmp` copy — see Enumeration).** The wheel
  produced from a byte-identical copy of the current `pyproject.toml` + `lattice/` contains every
  source module, `py.typed`, `migrations/cache_schema.sql`, and `migrations/durable/001_initial.sql`;
  no missing/extra payload files. `entry_points.txt` = `lattice = lattice.cli:main`, matching
  `[project.scripts]`. `lattice/migrations` and `lattice/migrations/durable` have no `__init__.py`,
  but need none: `storage/migrations.py` and `storage/cache.py` locate SQL by filesystem path, which
  resolves inside the installed wheel (SQL files confirmed present by the build log).
- **Nginx config vs code contract.** Three exact-match locations = `ROUTE_WELL_KNOWN`, `ROUTE_GOSSIP`,
  `ROUTE_MESSAGES` in `lattice/protocol/constants.py`; `client_max_body_size 256k`/`128k` =
  `MAX_GOSSIP_BODY_BYTES`/`MAX_MESSAGE_BODY_BYTES`; method allowlists (GET well-known, POST
  gossip/messages) = the app's route methods; `^~ /lattice/v1/admin/` and `^~ /lattice/v1/health/`
  cover exactly the four local routes in `api.py`, loopback-only; `location / { return 404; }`
  rejects the rest; `proxy_pass` URIs in the exact locations equal the location paths (no mangling),
  prefix locations use URI-less `proxy_pass` (original URI preserved).
- **Systemd unit ↔ code wiring.** `LoadCredentialEncrypted` names (`operational_key`,
  `webhook_bearer`, `admin_bearer`) match `cli._credential_path`, which reads `$CREDENTIALS_DIRECTORY`
  (set by systemd) before the config-dir staging fallback; `StateDirectory=lattice` /
  `CacheDirectory=lattice` match `DEFAULT_STATE_DIR=/var/lib/lattice` and
  `DEFAULT_CACHE_DIR=/var/cache/lattice`; `WorkingDirectory=/var/lib/lattice` consistent; default
  `bind_host=127.0.0.1`/`bind_port=1113` match the nginx upstream; `cmd_serve` never loads
  `root_key.pem` (invariant 2 holds on the serve path).
- **`lattice init` outputs vs docs.** `cmd_init` writes exactly the seven files
  `docs/LATTICE_SYSTEMD.md` lists (config.toml, identity.json, well-known.json, root_key.pem,
  operational_key.pem, webhook_bearer, admin_bearer).
- **`docs/MIGRATIONS.md` vs `storage/migrations.py`.** integrity_check, foreign_key_check,
  pre-migration backup, `user_version` monotonicity, refusal of newer-than-binary DB — all present.
- **Theory-only tests.** `tests/test_deployment.py` asserts strings/modes, never executes the unit
  or the CLI (why finding 1 escapes). `tests/test_wheel.py` builds + installs + imports + `--help`.
- **Stale `dist/` wheels** (newest `...d20260927...whl`) contain 14 deleted legacy modules and
  `002_staging_and_erasure.sql` — out of scope with reason: `dist/` is gitignored, pre-rewrite build
  artifacts, invariant 8 excludes deleted legacy modules.

## Enumeration

**A. Packaged/module set vs source.** Built in a `/tmp` copy so no in-tree write occurred:

```
cp pyproject.toml README.md LICENSE /tmp/latprobe/ && cp -R lattice /tmp/latprobe/lattice
cd /tmp/latprobe && uv build --wheel --out-dir /tmp/latprobe/out
unzip -l out/*.whl
```

Result: 33 payload files under `lattice/` match the 33 source files exactly (modules + `py.typed` +
2 SQL scripts); `entry_points.txt` = `[console_scripts] lattice = lattice.cli:main`.
Dispositions: every source module → packaged/clean; `py.typed` + both SQL → clean
(`include-package-data` + explicit `package-data` globs); no orphan/missing entries.

**B. Documented/unit `--config` placement.** Command:
`grep -rn -- "--config" deploy/ docs/ README.md`, cross-checked against `cli._build_parser` and
executed.

| Site | Order | Parses? | Disposition |
|---|---|---|---|
| `deploy/lattice.service:26` (serve) | post-subcommand | no (exit 2) | finding 1 |
| `docs/LATTICE_SYSTEMD.md:29-30` (init) | post-subcommand | no (exit 2) | finding 1 |
| `docs/LATTICE_SYSTEMD.md:75` (upgrade) | post-subcommand | no | finding 1 |
| `docs/LATTICE_SYSTEMD.md:126` (status) | post-subcommand | no | finding 1 |
| `docs/LATTICE_SYSTEMD.md:132` (rotate-operational) | post-subcommand | no | finding 1 |
| `docs/MIGRATIONS.md:15` (upgrade) | post-subcommand | no | finding 1 |
| `README.md:21-22` (init) | post-subcommand | no | finding 1 |
| `docs/KEY_MANAGEMENT.md:19` (init) | no `--config` | yes | examined-clean |
| `docs/KEY_MANAGEMENT.md:47` (rotate-operational) | no `--config` | yes | examined-clean |
| `tests/test_cli.py` (29 sites) | pre-subcommand | yes | examined-clean |

## Side discoveries

1. **`X-Forwarded-For` spoofing defeats the unauthenticated gossip rate limit, and the bucket map
   grows without bound (belongs to the api/rate-limit pass; single-pass candidate).**
   `deploy/lattice.nginx.conf:37,51,65,82,96` sets
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (appends the real IP to any
   client-supplied value) while `api.py:_peer_ip` takes the **first** comma-separated XFF entry. A
   remote peer sending a fresh forged `X-Forwarded-For` per request gets a fresh key on the
   fallback (non-card-verifying) gossip path, so `rate_limiter.allow_gossip(peer_id)` never trips.
   Pricing: **M** (rate/quota decision defeated) with an **H-adjacent amplifier** —
   `RateLimiter._buckets` (`rate_limit.py:82,88-99`) is never evicted and each new key inserts two
   `TokenBucket`s, so spoofed keys cause unbounded in-memory growth and unbounded `rate_buckets`
   rows persisted at `runtime.py:500-501`. Reachability: PRODUCTION (unauthenticated network peer);
   mechanism read-traced, bucket growth read from source (no eviction anywhere in `rate_limit.py`),
   not runtime-tested. Fix-direction: trust only `X-Real-IP` (already set, unspoofable) or the
   right-most XFF entry, and add a bucket cap/TTL with eviction — an XFF-parsing fix alone leaves
   the unbounded map. Out of the assigned file set; recorded for the api pass.

## Design risks (max 2)

1. `docs/ARCHITECTURE.md:81` states Nginx "owns ... IP rate limits", but
   `deploy/lattice.nginx.conf` defines no `limit_req_zone`/`limit_req` (LOOSE_ENDS Phase 9 already
   admits this). The app's own IP-keyed fallback is spoofable (side discovery 1). This is a
   docs-vs-config inconsistency, not a runtime-triggered code defect, so it is not a finding; a
   repair should either add an Nginx `limit_req` zone or correct the doc.
2. Pre-start root-run migration (`docs/LATTICE_SYSTEMD.md:19,75`) may create `root:root` database
   files in `/var/lib/lattice` and `/var/cache/lattice` before the `User=lattice` daemon opens them;
   whether systemd `StateDirectory=`/`CacheDirectory=` repairs ownership of pre-existing files is
   unverifiable here. `cmd_serve` already runs `migrate()` itself, so the documented root-run step is
   redundant. No confirmed current misbehavior → design risk.

## Bound

- No live systemd or Nginx on this macOS host. `systemd-analyze verify`, actual
  `LoadCredentialEncrypted` decrypt/chown semantics, and the `nginx -t` test (skipped when `nginx`
  is absent) were not executed.
- Finding 2's decisive systemd consequence (death-by-SIGHUP is a clean exit for `Restart=on-failure`
  → no auto-restart) rests on documented `systemd.service(5)` semantics, web-verified from multiple
  sources, not reproduced on this host. Finding 2's core mechanism (SIGHUP terminates uvicorn) is
  source-verified.
- Finding 1's secondary "unit latches to `failed` within ~30 s" rests on
  `Restart=on-failure` + `StartLimitBurst`/`StartLimitInterval` semantics, not reproduced; its core
  failure site (argparse exit 2) is execution-verified and systemd-independent.
- The deployed `/opt/lattice/venv/bin/lattice` does not exist here; its wrapper is inferred from the
  equivalent repo-venv console script (verified standard setuptools shim).
- The fresh wheel was built from a `/tmp` copy (write authority forbids in-tree builds); the copy is
  byte-identical for `pyproject.toml` and `lattice/`, so package-set conclusions transfer. The
  version string differs (fallback `0.1.0.dev0` without git metadata) — content unaffected.
- `tests/test_wheel.py` was read, not executed (it would build inside the repo's `dist/`).
- No files modified; only this report written.
