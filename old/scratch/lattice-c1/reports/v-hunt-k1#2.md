# v-hunt-k1#2 — primed verifier on hunt-k1 finding #2

Pass type: PRIMED VERIFIER. Claim under test: `hunt-k1.md` finding **#2**, reported tier **M**
("`ExecReload` sends SIGHUP, which terminates the uvicorn daemon; `Restart=on-failure` then does not
bring it back").

Frame re-derived from source before reading the claim's framing:

- `deploy/lattice.service:27` — `ExecReload=/bin/kill -HUP $MAINPID`.
- `deploy/lattice.service:29` — `Restart=on-failure` (`RestartSec=10`).
- `lattice/cli.py:cmd_serve` (638) runs the daemon in-process: `uvicorn.run(app, ..., workers=1)`
  at line 720; the only other lifecycle code is `finally: runtime.stop(...)` (727).
- `uvicorn 0.52.0` (repo `.venv`, matches `uvicorn[standard]>=0.27.0`) — `HANDLED_SIGNALS =
  (signal.SIGINT, signal.SIGTERM)` in `.venv/.../uvicorn/server.py:36-38`; with `workers=1` and no
  `reload`, `uvicorn.main.run` calls `server.run()` in the main process (no supervisor/child).
- `rg 'signal\.' lattice/` → no matches; no SIGHUP handler is installed anywhere in the package.
- Confirmed empirically: after importing `uvicorn` and `lattice.cli`, `signal.getsignal(SIGHUP)`
  is `SIG_DFL` (0).
- **Gate re-derived:** `hunt-k1#1` (independently verified as **ADJUSTED — H→M, CONFIRMED
  mechanism**) establishes that `deploy/lattice.service:26`
  `ExecStart=... lattice serve --config /etc/lattice/config.toml` is rejected by argparse (verified
  again here: `.venv/bin/lattice serve --config ...` → `unrecognized arguments`, exit 2). The unit
  therefore cannot start the daemon at all; no live daemon exists under the shipped unit for
  `systemctl reload` to reach.

## Findings

**1. [M] — `ExecReload` kills the daemon (SIGHUP is unhandled) and `Restart=on-failure` does not
restart it; the reported mechanism is confirmed, the reachability is gated.**

- Location: `deploy/lattice.service:27` (`ExecReload`), `:29` (`Restart=on-failure`);
  `lattice/cli.py:cmd_serve` (uvicorn in-process); `uvicorn/server.py:HANDLED_SIGNALS`.
- Evidence:
  - `ExecReload=/bin/kill -HUP $MAINPID`.
  - `HANDLED_SIGNALS = (signal.SIGINT, signal.SIGTERM)` — SIGHUP absent.
  - `signal.getsignal(SIGHUP)` after importing `uvicorn` + `lattice.cli` → `0` (`SIG_DFL`).
  - Live probe (bounded, `timeout 30`, process reaped): an in-process `uvicorn.run` app receiving
    `os.kill(self, SIGHUP)` died with `Hangup: 1`, shell exit **129** (128+SIGHUP); no graceful
    return, port released, no orphan.
  - systemd source (`service.c`, main): `is_clean_exit(code, status, EXIT_CLEAN_DAEMON,
    success_status)` classifies SIGHUP as clean → `f = SERVICE_SUCCESS`; main-pid exit in
    `SERVICE_RELOAD` routes through `service_enter_running` → `service_enter_exited_or_stop` →
    `service_enter_stop(…, SERVICE_SUCCESS)` → `service_enter_dead`; `service_shall_restart`
    for `SERVICE_RESTART_ON_FAILURE` returns `!IN_SET(s->result, SERVICE_SUCCESS, …)` → **false**.
    No restart. `s->reload_result` is set `SERVICE_SUCCESS`.
- **Mechanism: CONFIRMED** (traced twice — pytest-style live kill + systemd source path).
- **Trigger: CONFIRMED** — an operator runs `systemctl reload lattice` (or
  `reload-or-restart`, which chooses reload because `ExecReload` exists) while the unit is
  active. Requires the daemon to be running, which the shipped unit cannot achieve — see Gate.
- **Frequency: operator-driven, only partially grounded.** Population = operators of a deployed
  node; operation = the reload verb the unit advertises; cadence = operator config-change events.
  No code in the tree and no documented workflow (`docs/LATTICE_SYSTEMD.md` instructs
  `systemctl restart lattice`, never reload) invokes it, and nothing is automatic. The claim's own
  "cadence is whatever the operator's reload habit is. Not automatic." is accurate. Per the
  preamble this is not a DEMONSTRATED frequency in the code sense; if the latent-frequency cap is
  applied strictly it would force L. I do not apply it, for the reason below.
- **Severity correction: none — M stands.** Real symptom is a total node outage that does not
  self-heal (`Type=simple`, no auto-restart on a clean signal). The pinned H scale enumerates
  data loss/corruption, secret exposure, auth bypass, cross-peer reach, and network-peer
  crash/exhaustion — none apply; this is availability, same class as `hunt-k1#1`, which the ledger
  corrected H→M. The gated clause ("a gated finding keeps its real severity") preserves M; the
  frequency-cadence gap is real but the trigger *existence* is certain and the population concrete
  (an operator running a systemd verb the unit explicitly enables), analogous to the preamble's
  own "an operator who supplies a /?# password" example. M is the consistent reading.
- Outcome: the daemon is terminated mid-flight with no graceful drain (`finally: runtime.stop` /
  connection close never run); the unit settles to `inactive (dead)` with no auto-restart.
  Availability only: SQLite WAL is crash-safe and durable custody is already committed, so no data
  loss or corruption (checked, not assumed — see Checked and clean).
- Confidence: **traced** for mechanism and trigger. The systemd-side restart suppression is traced
  against systemd `main` source; it was not exercised on a live systemd host (see Bound).
- **Reachability: GATED behind `hunt-k1#1`.** With the tree as-is, `ExecStart` fails to parse, the
  service never runs, and `systemctl reload lattice` on an inactive unit fails before sending any
  signal. Finding #2 becomes live exactly when #1 is repaired. A repair of #1 that ignores #2 ships
  a daemon that dies on every advertised reload.

**Sub-claims refuted (individual):**

- *"Reachability: PRODUCTION (operator action)"* — **REFUTED as an unconditional production
  path.** It is production-shaped but gated behind `hunt-k1#1`; no live daemon exists under the
  shipped unit today. Corrected to **gated-behind-hunt-k1#1**.
- *"systemd ... does not bring it back" rests on documented semantics not reproducible here* —
  **strengthened, not refuted**: the restart-suppression is confirmed at the systemd C-source
  level (`service_shall_restart`), not merely by man-page citation. No version evidence contradicts
  it (the clean-signal rule predates all systemd 250+ deployments).
- Mechanism, trigger, and outcome sub-claims are each **CONFIRMED**, including the empirical
  SIGHUP-kill (exit 129) and the `SIG_DFL` disposition.

## Additional mechanisms / earlier failure sites / new reachability

- **`reload-or-restart` widens the trigger population.** Because `ExecReload` is defined, the
  standard `systemctl reload-or-restart lattice` performs a *reload* (SIGHUP), not a restart — so
  operators who reach for the "safe" verb are hit too. Same site, same fix.
- **The reload intent is unimplemented, not merely mishandled.** `rg 'SIGHUP|reload' lattice/`
  finds no config hot-reload path; even a daemon that survived SIGHUP would not re-read
  `config.toml`. The `ExecReload` line promises a capability the code does not have. This is
  subsumed by the kill (the process dies before any reload could matter) but a repair must decide
  whether to implement reload or drop `ExecReload`.
- **Earlier failure site:** `hunt-k1#1` (line 26) fires before line 27 is ever reached in a
  real deployment — recorded for ordering, not re-reported.
- **No network-peer reachability:** the trigger is operator/systemd only; nothing an HTTP peer
  sends can resurrect or avoid the service.

## Fix-direction constraints

- A minimal "remove `ExecReload`" repair restores `Restart=on-failure` semantics but silently drops
  the reload capability the unit advertised; if reload is intended, add a real SIGHUP handler (or
  `Type=notify-reload` + `RELOADING=1`/`READY=1`) **and** a config-reload path — none exists.
- Do **not** fix by switching to `Restart=always`: that would also mask genuine clean-exit bugs and
  turns a crash-loop into a restart-loop; the defect is that the reload signal is unhandled, and
  that must be the thing repaired.
- `Restart=on-failure` + `StartLimitBurst=3`/`StartLimitInterval=60` interacts with `hunt-k1#1`'s
  repair: once `ExecStart` parses, the first reload kills a *healthy* node with no self-recovery, so
  #1 and #2 should be fixed together (order: #1 first, else #2 is untestable live).
- `tests/test_deployment.py` does not assert `ExecReload` at all (grep: no `ExecReload`, no
  `SIGHUP`), so nothing in the suite pins or exercises it — a repair cannot rely on the suite to
  catch a regression here.

## Checked and clean

- uvicorn 0.52.0 signal set (`SIGINT`, `SIGTERM` only) and single-process execution for
  `workers=1`: confirmed by reading `uvicorn/server.py` and `uvicorn/main.py` `run()`.
- No `signal`/`SIGHUP` handler anywhere in `lattice/`: confirmed by `rg`.
- Abrupt SIGHUP termination and exit status 129: confirmed by bounded live probe (process reaped,
  port `18432` released, no leftover).
- systemd clean-signal/restart decision for `on-failure`: confirmed against `service.c`
  (`is_clean_exit` → `SERVICE_SUCCESS`; `service_shall_restart` ON_FAILURE false).
- `cmd_serve`'s `finally` (runtime.stop + connection close) cannot run under SIGHUP default
  termination — consistent with the "no graceful shutdown" outcome.
- No data-loss/corruption consequence: `hunt-k1#1`'s frame and the storage layer's WAL/transaction
  usage give no evidence of mid-write corruption on abrupt exit; the finding is availability-only.
- `hunt-k1#1` (the gate) independently re-confirmed here (argparse exit 2 for the unit's ExecStart
  order) — consistent with `v-hunt-k1#1.md` (ADJUSTED H→M). Not re-reported.
- `docs/LATTICE_SYSTEMD.md` never documents `systemctl reload lattice` (only `reload nginx`,
  `restart lattice`) — confirmed by grep; relevant to frequency grounding.

## Enumeration

Composed command (executed):

```bash
rg -n 'ExecReload|ExecStart|Restart=|SIGHUP|reload' deploy/lattice.service \
   tests/test_deployment.py docs/*.md lattice/
# plus: signal.getsignal(SIGHUP) after import; live SIGHUP probe under `timeout 30`
# plus: grep HANDLED_SIGNALS .venv/lib/python3.11/site-packages/uvicorn/server.py
```

| Site | Content | Disposition |
|---|---|---|
| `deploy/lattice.service:27` | `ExecReload=/bin/kill -HUP $MAINPID` | **finding #2** |
| `deploy/lattice.service:29` | `Restart=on-failure` | **finding #2** (no restart on clean signal) |
| `deploy/lattice.service:26` | `ExecStart=... serve --config ...` | gate `hunt-k1#1` (verified, not re-reported) |
| `lattice/cli.py:720` | `uvicorn.run(..., workers=1)` | examined-clean (in-process; signal disposition applies to MAINPID) |
| `lattice/cli.py:727-730` | `finally: runtime.stop/close` | examined-clean (never runs under SIGHUP; availability-only) |
| `uvicorn/server.py:36-38` | `HANDLED_SIGNALS=(SIGINT,SIGTERM)` | examined-clean (confirms no SIGHUP handling) |
| `tests/test_deployment.py` | no `ExecReload`/`SIGHUP` assertion | examined-clean (no coverage; noted as fix constraint) |
| `docs/LATTICE_SYSTEMD.md:104,137` | `reload nginx`, `restart lattice` | examined-clean (no documented `reload lattice`) |

## Design risks (max 2)

1. **`Restart=on-failure` leaves any clean-signal death unrestarted.** SIGHUP, SIGINT, SIGTERM and
   SIGPIPE all map to `SERVICE_SUCCESS`; if the daemon ever exits via one of them (e.g. an
   accidental `systemctl kill -s TERM`), it stays down. Today the only in-tree path to a
   clean-signal death is the `ExecReload` bug, so this is subsumed by finding #2, not a separate
   defect. If a repair removes `ExecReload` and adds a SIGTERM handler that exits 0, the node again
   will not self-restart — worth deciding deliberately.
2. **`MemoryDenyWriteExecute=yes` / `SystemCallFilter=@system-service` against the Python+
   `cryptography` stack.** No concrete current misbehaviour was found (the daemon never starts
   today, so this is untested); flagged only so a post-#1 deployment smoke test covers the
   hardening directives. Not reportable on this evidence.

## Bound

- **No live systemd on this macOS host.** The restart-suppression half is traced against systemd
  `main` `src/core/service.c`, not exercised against a running PID 1. If a deployment pins an
  ancient or patched systemd whose clean-signal set differs, the "no restart" outcome could change;
  the clean-signal rule is long-standing and consistent across freedesktop docs and source.
- **No live deployment of the shipped unit** (it cannot start — `hunt-k1#1`). The gated call is
  reasoned from #1's verified parse failure plus systemd's refusal to reload an inactive unit.
- The `/opt/lattice/venv` interpreter and `$CREDENTIALS_DIRECTORY` were not exercised; irrelevant to
  the signal path (the console-script wrapper is the standard setuptools shim, no argument/signal
  injection).
- A deployment-level `RestartForceExitStatus=`/`SuccessExitStatus=` override in a drop-in (not in
  this tree) could alter the restart decision; none is present here.
- Nothing in the tree was modified; the report is the only file written.
