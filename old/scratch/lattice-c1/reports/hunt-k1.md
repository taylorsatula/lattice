# hunt-k1 — deploy, packaging & install path

Pass type: blind hunter. Scope: `deploy/` (lattice.service, lattice.nginx.conf), `pyproject.toml`,
`tests/test_deployment.py`, `tests/test_wheel.py`, plus docs-vs-code route/config comparison
(`docs/LATTICE_SYSTEMD.md`, `docs/MIGRATIONS.md`, `docs/ARCHITECTURE.md`, `docs/KEY_MANAGEMENT.md`,
`README.md`) and wheel-contents-vs-source diff.

All claims below were verified against the working tree at HEAD 60acd1c + dirty state. Two CLI
invocation-order checks and one SIGHUP behavior check were executed empirically (read-only; the
test wheel was built in `/tmp`, never inside the repo).

## Findings

1. [H] — Shipped systemd ExecStart cannot start the daemon: `--config` after the subcommand is rejected by the CLI parser
- Location: `deploy/lattice.service` (ExecStart); `lattice/cli.py:_build_parser` / `main`; same bug in every command in `docs/LATTICE_SYSTEMD.md` and `docs/MIGRATIONS.md`.
- Evidence: unit line `ExecStart=/opt/lattice/venv/bin/lattice serve --config /etc/lattice/config.toml`; in `lattice/cli.py` `--config` is defined only on the top-level parser (`parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), ...)`), and the `serve` subparser defines only `--state-dir`, `--cache-dir`, `--log-level`. Empirically verified with the repo venv:
  - `main(["serve", "--config", "/etc/lattice/config.toml"])` → `lattice: error: unrecognized arguments: --config /etc/lattice/config.toml`, exit 2.
  - `main(["--config", "/etc/lattice/config.toml", "config"])` → parses fine (reaches config loading).
  - `main(["init", "--config", ..., "--domain", ...])` (the exact documented init command) → same argparse error, exit 2.
- Trigger: any operator who installs per `docs/LATTICE_SYSTEMD.md` and runs `systemctl start lattice` — i.e. every deployment of the shipped unit. Nothing must coincide; it fails deterministically on the first start.
- Frequency: DEMONSTRATED — every deployment, every start; also every documented `lattice init` / `lattice upgrade` / `lattice status` / `lattice keys rotate-operational` invocation (all place `--config` after the subcommand and fail identically).
- Outcome: the daemon process exits 2 before loading anything; `Restart=on-failure` + `StartLimitBurst=3`/`StartLimitInterval=60` put the unit into failed state within ~30 s. The deployed service can never run. Node is entirely down; no data is lost or corrupted. The docs' install path is equally dead: `lattice init` as documented fails before creating any files.
- Confidence: traced — mechanism (argparse rejects post-subcommand top-level options; verified empirically in the project venv), trigger (unit file string, verified by direct execution), frequency (deterministic, no coincidence required) all proven. Reachability: PRODUCTION (operator action, the primary documented deploy path).
- Note on why the test suite misses it: `tests/test_deployment.py::test_service_unit_runs_serve_command` only greps for the string `"lattice serve --config /etc/lattice/config.toml"` in the unit — it enshrines the broken order without executing it; `tests/test_cli.py` exclusively uses the pre-subcommand order (`main(["--config", path, "config"])`); `tests/test_wheel.py` runs only `lattice --help`.
- Tier note: this is a deterministic total availability failure of the shipped artifact (every deployment, service dead on arrival). The pinned H list is security-flavored; if the ledger reads the scale strictly by its enumerated outcomes, this is the top of M. Flagged in Disputes.

2. [M] — `ExecReload` sends SIGHUP, which terminates the uvicorn daemon; `Restart=on-failure` then does not bring it back
- Location: `deploy/lattice.service` (ExecReload / Restart); `lattice/cli.py:cmd_serve` (the only serve loop, `uvicorn.run(...)`).
- Evidence: unit lines `ExecReload=/bin/kill -HUP $MAINPID` and `Restart=on-failure`. uvicorn 0.52.0 (installed in `.venv`, matches `uvicorn[standard]>=0.27.0` constraint) handles only `signal.SIGINT` and `signal.SIGTERM` (`uvicorn/server.py`: `HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM)` in `capture_signals`); no code in `lattice/` installs a SIGHUP handler. Empirically verified: launched a uvicorn-run app from the repo venv, sent `kill -HUP` → process died with "Hangup", exit status 129.
- Trigger: operator runs `systemctl reload lattice` on a deployed node — a standard operation the unit explicitly advertises by defining ExecReload (e.g. after editing `/etc/lattice/config.toml`). Requires only that one operator action; nothing else must coincide. systemd classifies death-by-SIGHUP as a *clean* exit for `Restart=on-failure` (systemd.service: restart is triggered by signals "excluding SIGHUP, SIGINT, SIGTERM, SIGPIPE"), so no restart occurs.
- Frequency: plausible in normal operation — one operator command; cadence is whatever the operator's reload habit is. Not automatic.
- Outcome: the daemon is killed mid-flight with no graceful shutdown and the unit settles to `inactive (dead)` with no auto-restart — total outage until someone notices and runs `systemctl start lattice`. In-flight requests are severed abruptly (no uvicorn graceful drain).
- Confidence: traced — mechanism proven two ways (uvicorn source inspection + live SIGHUP kill test on the repo venv); trigger is the shipped ExecReload line; the only unproven component is the systemd-side restart suppression, which rests on documented systemd semantics not reproducible on this macOS host (no systemd). Reachability: PRODUCTION (operator action).

## Checked and clean

- **Wheel file set vs source tree (fresh build, executed in /tmp — see Enumeration):** the wheel produced from a byte-identical copy of the current `pyproject.toml` + `lattice/` contains every source module, `py.typed`, `migrations/cache_schema.sql`, and `migrations/durable/001_initial.sql` — `comm -3` between the source file set and wheel contents is empty (no missing, no extra). Entry point `lattice = lattice.cli:main` present in `entry_points.txt` and matches `[project.scripts]`.
- **Declared packages cover the module tree:** `[tool.setuptools] packages` lists `lattice`, `lattice.protocol`, `lattice.storage`, `lattice.migrations`, `lattice.migrations.durable`; every `.py` file under `lattice/` lives in one of these. `lattice/migrations` has no `__init__.py` but needs none: `lattice/storage/migrations.py` locates SQL by filesystem path (`Path(__file__).resolve().parents[1] / "migrations" / "durable"`), which resolves correctly inside the installed wheel (files confirmed present in the built wheel).
- **Dependency declarations:** every third-party import in the package (`cryptography`, `fastapi`, `pydantic`, `urllib3`, `rfc8785`, `uvicorn`) is declared in `[project] dependencies`; no undeclared imports. (`httpx` is declared but not imported directly — harmless over-declaration.)
- **Nginx config vs code contract:** the three exact-match locations match `lattice/protocol/constants.py` (`ROUTE_WELL_KNOWN`, `ROUTE_GOSSIP`, `ROUTE_MESSAGES`); `client_max_body_size 256k`/`128k` match `MAX_GOSSIP_BODY_BYTES`/`MAX_MESSAGE_BODY_BYTES` exactly; method allowlists (`GET` well-known, `POST` gossip/messages) match the app's route methods; `^~ /lattice/v1/admin/` and `^~ /lattice/v1/health/` prefixes cover exactly the four local routes in `lattice/api.py` (`/lattice/v1/admin/status`, `/lattice/v1/admin/messages/submit`, `/lattice/v1/health/live`, `/lattice/v1/health/ready`), loopback-only; catch-all `location / { return 404; }` blocks everything else; `proxy_pass` URIs in exact-match locations are identical to the location paths (no URI mangling); admin/health prefix locations use URI-less `proxy_pass` (original URI preserved).
- **Systemd unit ↔ code wiring:** `LoadCredentialEncrypted` names (`operational_key`, `webhook_bearer`, `admin_bearer`) match the names `lattice/cli.py:_credential_path` looks up; that function reads `$CREDENTIALS_DIRECTORY` (which systemd sets for loaded credentials) before falling back to staging files in the config dir; `cmd_serve` never touches `root_key.pem` (invariant 2 holds on this path); `StateDirectory=lattice`/`CacheDirectory=lattice` match `DEFAULT_STATE_DIR=/var/lib/lattice` and `DEFAULT_CACHE_DIR=/var/cache/lattice` used by `cmd_serve`/`cmd_upgrade` via `_state_paths`; `WorkingDirectory=/var/lib/lattice` is consistent; default `bind_host=127.0.0.1`/port 1113 in `lattice/config.py` matches the nginx upstream `127.0.0.1:1113` and the docs' "daemon binds only to the loopback interface"; health paths in docs match api.py; docs' "systemd 250+" matches `LoadCredentialEncrypted` requirements.
- **`lattice init` file outputs vs docs:** `cmd_init` writes exactly the seven files `docs/LATTICE_SYSTEMD.md` lists (config.toml, identity.json, well-known.json, root_key.pem, operational_key.pem, webhook_bearer, admin_bearer), with the modes the docs tell the operator to set.
- **`tests/test_deployment.py` / `tests/test_wheel.py`:** their assertions about the unit and nginx files are all satisfied by the current artifacts (the tests check strings/modes, not behavior — which is exactly why Finding 1 escaped them).
- **`docs/MIGRATIONS.md` runner description vs `lattice/storage/migrations.py`:** integrity/foreign-key checks, pre-migration backup, user_version monotonicity, refusal of newer-than-binary databases — all match the code (each step verified present).

## Enumeration

**A. Packaged/module file set vs source tree.** Composed commands (executed from a `/tmp` copy of the tree so no build output touched the repo):

```
cp pyproject.toml README.md LICENSE /tmp/huntk1-build/ && cp -R lattice /tmp/huntk1-build/
cd /tmp/huntk1-build && uv build --wheel --out-dir /tmp/huntk1-out
comm -3 <(find lattice -type f \( -name '*.py' -o -name '*.sql' -o -name 'py.typed' \) | grep -v __pycache__ | sort) \
       <(python3 -c "import zipfile; z=zipfile.ZipFile(glob('/tmp/huntk1-out/*.whl')[0]);
           print('\n'.join(n for n in z.namelist() if n.startswith('lattice/')))" | sort)
```

Result: empty diff — 33 packaged payload files match the 33 source files exactly; `entry_points.txt` = `lattice = lattice.cli:main`. Instance dispositions: every source module → examined-clean (packaged); `py.typed` + 2 SQL files → examined-clean (packaged via `[tool.setuptools.package-data]`, confirmed present in the built wheel); no orphan or missing entries.

Pre-existing wheels in `dist/` (newest `...d20260927...whl`) contain 14 deleted legacy modules (`client.py`, `secrets.py`, `models.py`, `002_staging_and_erasure.sql`, …) — **out of scope with reason**: `dist/` is gitignored, these are stale build artifacts of the pre-rewrite tree, and invariant 8 excludes deleted legacy modules. Not a finding; noted so no later pass re-chases it.

**B. Documented routes/config vs code constants.** Command: `grep -rn "lattice/v1\|well-known\|1113\|8080" docs/*.md README.md` cross-checked against `lattice/protocol/constants.py`, `lattice/api.py`, `lattice/config.py`, `deploy/lattice.nginx.conf`, `deploy/lattice.service`.

| Documented item | Code constant/artifact | Disposition |
|---|---|---|
| `GET /.well-known/lattice` | `ROUTE_WELL_KNOWN` / nginx exact loc / api `@app.get` | examined-clean |
| `POST /lattice/v1/gossip` | `ROUTE_GOSSIP` / nginx / api | examined-clean |
| `POST /lattice/v1/messages` | `ROUTE_MESSAGES` / nginx / api | examined-clean |
| health `/lattice/v1/health/{live,ready}` on 127.0.0.1:1113 | api routes + `DEFAULT_BIND_*` | examined-clean |
| admin `/lattice/v1/admin/*` loopback-only | api routes + nginx `^~` block | examined-clean |
| body limits 256k/128k | `MAX_GOSSIP_BODY_BYTES`/`MAX_MESSAGE_BODY_BYTES` | examined-clean |
| credential names operational_key/webhook_bearer/admin_bearer | unit `LoadCredentialEncrypted` + `_credential_path` | examined-clean |
| state/cache dirs /var/lib/lattice, /var/cache/lattice | `DEFAULT_STATE_DIR`/`DEFAULT_CACHE_DIR`, `StateDirectory=`/`CacheDirectory=` | examined-clean |
| docs command invocations (`lattice init --config …`, `lattice serve --config …`, `lattice upgrade --config …`, `keys rotate-operational --config …`) | `cli.py:_build_parser` | **finding #1** (arg order rejected) |
| `ExecReload=/bin/kill -HUP $MAINPID` + `Restart=on-failure` | `cmd_serve` uvicorn signal handling | **finding #2** |

## Design risks (max 2)

1. Docs-ordered pre-start migration as root may leave the daemon unable to open its databases.
   `docs/LATTICE_SYSTEMD.md` and `docs/MIGRATIONS.md` instruct `sudo mkdir -p /var/lib/lattice
   /var/cache/lattice` followed by `sudo lattice upgrade`, which creates `lattice.durable.db` and
   `lattice.cache.db` owned by `root:root` (mode 644 under default umask). The daemon runs as
   `User=lattice`; `lattice/storage/connection.py:open_connection` needs read-write access
   (`sqlite3.connect` + `PRAGMA journal_mode = WAL`), so root-owned files would abort startup.
   Whether systemd's `StateDirectory=`/`CacheDirectory=` repair ownership of *pre-existing files*
   (vs. only the directory itself) decides if this bites; that behavior is not verifiable on this
   host. `cmd_serve` already runs `migrate()` itself, so the documented root-run step is redundant
   as well as risky. No confirmed current misbehavior → design risk, not a finding.

## Side discoveries

1. Unauthenticated gossip rate limit is bypassable via client-supplied `X-Forwarded-For` — needs
   the api/rate-limit pass, not mine. `deploy/lattice.nginx.conf` sets
   `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` (preserves client-supplied
   entries, appends the real IP) while also setting the unspoofable `X-Real-IP $remote_addr` — but
   `lattice/api.py:_peer_ip` takes the *first* comma-separated XFF entry. A remote peer rotating
   fake `X-Forwarded-For` values gets a fresh rate-limit bucket per request on the fallback
   (non-card-verifying) gossip path, defeating the unauthenticated limiter and allowing unbounded
   card-verification CPU. Single-pass candidate; mechanism read-traced, not runtime-tested.
2. Environment note, not a defect: almost all current sources (`pyproject.toml`, `lattice/*.py`,
   tests, `deploy/lattice.nginx.conf`, most docs) are untracked in git (mid-rewrite tree).
   setuptools-scm derives the sdist file list from git, so `uv build --sdist` from this tree would
   omit nearly everything (`lattice_mesh.egg-info/scm_file_list.json` lists only 7 tracked files).
   Wheel builds are unaffected (explicit `packages` list, verified above). Committing the tree fixes
   it; nothing in code misbehaves.

## Bound

- No live systemd or Nginx on this macOS host: `systemd-analyze verify`, actual
  `LoadCredentialEncrypted` decryption, `StateDirectory` chown semantics, and the
  nginx-syntax test (skipped when `nginx` is absent, per `tests/test_deployment.py`) were not
  executed. Findings rest on file contents plus empirical CLI/signal tests, not on a live daemon
  under systemd.
- The fresh wheel was built from a `/tmp` copy of the tree (write authority forbids building
  in-tree). The copy is byte-identical for `pyproject.toml` + `lattice/`, so the file-set
  conclusion transfers; the version string differs (fallback `0.1.0.dev0` without git metadata),
  which does not affect contents.
- `tests/test_wheel.py` was read but not executed (it builds into the repo's `dist/`, which would
  write inside the tree).
- The stale `dist/` wheels were inspected via zipfile listing only; their runtime behavior was
  not exercised.
