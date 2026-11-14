# v-hunt-k1#1 — primed verifier on hunt-k1 finding #1

Pass type: PRIMED VERIFIER. Claim under test: `hunt-k1.md` finding **#1**, reported tier **H**
("Shipped systemd ExecStart cannot start the daemon: `--config` after the subcommand is rejected
by the CLI parser").

Frame re-derived from source before reading the claim's framing:
- `deploy/lattice.service:26` — `ExecStart=/opt/lattice/venv/bin/lattice serve --config /etc/lattice/config.toml`.
- `pyproject.toml:48-49` — `[project.scripts] lattice = "lattice.cli:main"`; `.venv/bin/lattice` is
  the standard setuptools wrapper `sys.exit(main())`, no argument injection.
- `lattice/cli.py:_build_parser` — `--config` is added **only** to the top-level parser
  (`parser.add_argument("--config", ...)`). The `serve` subparser adds only `--state-dir`,
  `--cache-dir`, `--log-level`.
- `lattice/cli.py:main` — `parser.parse_args(argv)`; no `parse_known_args`, no pre-scan, no
  post-filter. An unknown token is fatal.

## Findings

**1. [ADJUSTED — H→M] — the shipped ExecStart deterministically fails argument parsing; the
mechanism is exactly as claimed, the tier is not.**

- Location: `deploy/lattice.service:26`; `lattice/cli.py:_build_parser`; `lattice/cli.py:main`.
  Same defect in `README.md:21-22`, `docs/LATTICE_SYSTEMD.md:29-30,75,126,132`,
  `docs/MIGRATIONS.md:15`.
- Evidence (executed against the repo venv, `.venv/bin/python`):
  `main(["serve","--config","/etc/lattice/config.toml"])` →
  `lattice: error: unrecognized arguments: --config /etc/lattice/config.toml`, `SystemExit 2`.
  `main(["init","--config","/etc/lattice/config.toml","--domain","x","--public-base-url","https://x"])`
  → same `SystemExit 2`.
  Control: `_build_parser().parse_args(["--config", C, "init", ...])` → OK (config=C);
  `parse_args(["serve"])` → OK (config defaults to `/etc/lattice/config.toml`).
- **Mechanism: CONFIRMED.** Top-level options are not recognized after the subcommand unless the
  subparser also declares them; `serve` does not, so argparse raises `unrecognized arguments` and
  exits 2. Verified by direct execution, not by reading.
- **Trigger: CONFIRMED.** `systemctl start lattice` after installing per `docs/LATTICE_SYSTEMD.md`
  — deterministic on the first start; nothing must coincide.
- **Frequency: CONFIRMED, DEMONSTRATED.** Every deployment, every start; the same order in the
  documented `init`/`upgrade`/`status`/`keys rotate-operational` invocations fails identically.
- **Severity correction: H → M.** The pinned H scale enumerates data loss/corruption, secret/root-
  key exposure, auth bypass, cross-peer/cross-user reach, and remote crash / unbounded resource
  exhaustion by a network peer. A dead-on-arrival service is *availability* failure; it fits none of
  the H outcomes. It is a correctness fault under a plausible normal operation → **M** on the pinned
  scale. The hunter already flagged this in Disputes; I agree with the strict reading and correct
  the tier downward. (If the ledger overrides the pinned scale to treat total availability as H, the
  trace supports that escalation — but the scale as written does not.)
- **Frequency correction: none.** Left DEMONSTRATED; the trigger is deterministic and unconditional.
- Outcome: daemon exits 2 before loading anything; no data loss/corruption, no exposure.
- Confidence: **traced** — mechanism, trigger, frequency all proven by execution in the repo venv.
- Reachability: **PRODUCTION** (operator action; the primary documented deploy path).

**Sub-claims refuted (individual):**
- The claim's phrase "*also every documented `lattice init` / `lattice upgrade` / `lattice status` /
  `lattice keys rotate-operational` invocation (all place `--config` after the subcommand and fail
  identically)*" is **overbroad and refuted in part**. `docs/KEY_MANAGEMENT.md:19` documents
  `lattice init --domain example.com --public-base-url https://example.com` with **no** `--config`,
  and `docs/KEY_MANAGEMENT.md:47` documents `lattice keys rotate-operational` with no `--config`.
  `_build_parser().parse_args([...])` accepts both (config falls to the default `/etc/lattice/
  config.toml`). Only the documented commands that *pass* `--config` after the subcommand fail.
  The core finding is unaffected; only the "every documented command" sweep is wrong.
- No other sub-claim refuted: mechanism (top-level-only `--config` + subparser lacking it),
  trigger (unit string), and frequency (deterministic) all hold.

**Additional mechanisms / earlier failure sites / new reachability:** none beyond the finding. The
docs/README instances are the same mechanism, already named by the claim. `serve` without
`--config` already defaults to the same path, so a repair can simply drop the flag.

**Fix-direction constraints (what a repair must account for beyond the symptom):**
- Fixing only the unit line is insufficient: `docs/LATTICE_SYSTEMD.md` (4 sites), `docs/MIGRATIONS.md:15`,
  and `README.md:22` carry the same broken order and would re-seed the bug for operators.
- `tests/test_deployment.py:77` **asserts the broken string verbatim**
  (`assert "lattice serve --config /etc/lattice/config.toml" in text`); any repair that changes the
  unit must also update this assertion, or the test will pin the defect in place.
- The structural fix is to make `--config` a global option accepted on both sides of the subcommand
  (e.g. a `parents=[common]` parser reused by each subparser), not merely to reorder the unit token
  — otherwise every future doc/script author can reintroduce it.

## Checked and clean

- `_build_parser` option placement: re-read end-to-end; `--config` is top-level only; the `serve`
  parser's three options are exactly `--state-dir`, `--cache-dir`, `--log-level`. Confirmed.
- `main()` has no lenient parsing path (`parse_known_args`, argv pre-scan, `--` handling) that could
  absorb the flag. Confirmed by reading `lattice/cli.py:main`.
- Console-script wrapper `.venv/bin/lattice` is the standard setuptools shim calling `main()`
  unchanged. Confirmed by reading.
- `DEFAULT_CONFIG_PATH = /etc/lattice/config.toml` equals the path the unit passes, so the value is
  not the issue — the token position is. Confirmed.
- Control invocations (`--config` before subcommand; bare `serve`; bare `init` without `--config`)
  parse and reach their handlers. Confirmed empirically.
- `tests/test_deployment.py::test_service_unit_runs_serve_command` and `tests/test_cli.py` /
  `tests/test_resilience.py` use only the pre-subcommand order — consistent with the claim's
  "why the suite misses it." Confirmed by reading/grep.

## Enumeration

Composed command (executed):

```bash
grep -rn -- "--config" docs/ README.md tests/ deploy/ deploy/lattice.service
```

Cross-checked against `_build_parser`:

| Documented/unit site | Order | Parses? | Disposition |
|---|---|---|---|
| `deploy/lattice.service:26` | post-subcommand | **no (exit 2)** | finding |
| `docs/LATTICE_SYSTEMD.md:29-30` (init) | post-subcommand | **no** | finding |
| `docs/LATTICE_SYSTEMD.md:75` (upgrade) | post-subcommand | **no** | finding |
| `docs/LATTICE_SYSTEMD.md:126` (status) | post-subcommand | **no** | finding |
| `docs/LATTICE_SYSTEMD.md:132` (rotate-operational) | post-subcommand | **no** | finding |
| `docs/MIGRATIONS.md:15` (upgrade) | post-subcommand | **no** | finding |
| `README.md:21-22` (init) | post-subcommand | **no** | finding |
| `docs/KEY_MANAGEMENT.md:19` (init) | no `--config` | yes | examined-clean (refutes "every command") |
| `docs/KEY_MANAGEMENT.md:47` (rotate-operational) | no `--config` | yes | examined-clean |
| `docs/KEY_MANAGEMENT.md:68,71,74`, `docs/ADDRESSING.md:58,59,80,89-91` | no `--config` | yes | examined-clean |
| `tests/test_cli.py`, `tests/test_resilience.py` | pre-subcommand | yes | examined-clean |

## Bound

- No live systemd on this macOS host. The finding's **core failure site (argparse exit 2) does not
  depend on systemd** and is verified by execution; the claim's secondary statement that the unit
  settles into `failed` state within ~30 s rests on documented `Restart=on-failure` +
  `StartLimitBurst=3`/`StartLimitInterval=60` semantics, which were **not** reproduced here and are
  bounded as unverified.
- The deployed interpreter path `/opt/lattice/venv/bin/lattice` does not exist on this host; the
  wrapper behavior is inferred from the equivalent repo-venv console script (verified to be the
  standard setuptools shim). No argument-injecting wrapper is present.
- Nothing in the tree was modified; the working-tree (dirty) contents of `cli.py` and
  `lattice.service` were the objects checked.
