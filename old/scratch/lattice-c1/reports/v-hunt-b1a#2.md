# v-hunt-b1a#2 — PRIMED VERIFIER

Claim under test: **hunt-b1a #2 [L] — `_RecurringTask` first-run arithmetic delays all maintenance
on freshly booted hosts** (`scratch/lattice-c1/reports/hunt-b1a.md`, finding 2, reported tier L).

Method: frame re-derived from source before reading the claim's conclusion. Read
`lattice/runtime.py:96-160` (`RuntimeSettings`, `_RecurringTask`, `_RuntimeScheduler`),
`runtime.py:330-392` (`_build_scheduler`), `runtime.py:390-420` (`start`/`stop`),
`runtime.py:1079-1140` (`_run_*` task bodies), `runtime.py:50-74` (`_write_audit_entry`);
`tests/test_runtime.py` (fixture settings, `TestLifecycle`); `deploy/lattice.service`;
`docs/ARCHITECTURE.md`. Enumerated every reference to the mechanism across the tree. Mechanism
checked with a standalone arithmetic replica (not a repo file) and a direct probe of
`time.monotonic()` vs `CLOCK_UPTIME_RAW`/`CLOCK_MONOTONIC` on this host. No repo file modified.

## Verdict: CONFIRMED (L)

Mechanism traced and reproduced arithmetically; trigger is production-reachable on the documented
Linux/systemd target; frequency is grounded for the host-boot population. Severity stays L.

### Frame re-derived from source

- `RuntimeSettings` (runtime.py:96-108) defaults: `delivery=10.0`, `webhook=10.0`, `gossip=60.0`,
  `verify=60.0`, `refresh=300.0`, `expiry=60.0`. Not TOML-configurable: `settings or
  RuntimeSettings()` at runtime.py:186 and the only in-tree constructor is
  `self._settings = settings or RuntimeSettings()`. Confirmed by `rg -n "RuntimeSettings" lattice/`
  → runtime.py:96,174,186 only (tests construct it directly).
- `_build_scheduler` (runtime.py:343-390) creates seven `_RecurringTask`s, in this order:
  `cold_sender_resolution` 30s (maintenance executor), `outbound_delivery` 10s (delivery executor),
  `webhook_delivery` 10s (delivery executor), `gossip_round` 60s, `verify_candidates` 60s,
  `refresh_topology` 300s, `expiry_cleanup` 60s (all maintenance executor).
- `_RecurringTask._last_run` is `field(default=0.0)` (runtime.py:119). `maybe_run(now)` returns
  False while `now - self._last_run < interval` (runtime.py:122). `_last_run` is never initialised
  anywhere else: `rg -n "monotonic|_last_run|_RecurringTask" --glob '!scratch/**' .` returns only
  runtime.py:111,112,119,122,126,142,150,152,344-381.
- `_RuntimeScheduler.run` (runtime.py:148-152) waits **one tick (1s)** before the first evaluation,
  then `now = time.monotonic()`.
- `time.monotonic()` is boot-relative on the target. Verified empirically on this darwin host:
  `time.monotonic() == time.clock_gettime(CLOCK_UPTIME_RAW)` (1993499s) and differs from
  `CLOCK_MONOTONIC` (3118615s) — i.e. CPython's monotonic is the since-boot clock. On Linux (the
  documented deployment, `docs/LATTICE_SYSTEMD.md`, `deploy/lattice.service`) CPython uses
  `clock_gettime(CLOCK_MONOTONIC)`, likewise boot-relative. Therefore `now` at daemon start is
  exactly the host uptime.
- `deploy/lattice.service` has `After=network-online.target`, `Type=simple`, no `ExecStartPre`
  sleep. systemd therefore execs `lattice serve` within seconds of reaching network-online — host
  uptime at `start()` is on the order of a few seconds to a few tens of seconds.

### Mechanism (CONFIRMED)

With `_last_run = 0.0` and `now = host_uptime`, `maybe_run` fires on the first tick iff
`host_uptime >= interval_seconds`; otherwise it fires only once `host_uptime` reaches the interval,
i.e. after `(interval - host_uptime)` seconds. Standalone replica of the exact conditional:

```
interval= 10.0 uptime=  5.0 fires_at_first_tick=False first_fire_uptime=10.0
interval= 60.0 uptime= 20.0 fires_at_first_tick=False first_fire_uptime=60.0
interval=300.0 uptime=120.0 fires_at_first_tick=False first_fire_uptime=300.0
interval= 60.0 uptime=120.0 fires_at_first_tick=True
```

So the claim's arithmetic ("uptime 20s → 60s tasks wait ~40s, refresh_topology waits ~280s") is
correct. First execution is pinned to absolute host uptime = interval, not to scheduler start.

### Trigger (CONFIRMED — production)

Host reboot on the documented Linux/systemd deployment. Nothing else must coincide. The scheduler
is created in `__init__` and started in `start()`, and `_last_run` is unconditionally 0.0, so on a
freshly booted host the long-interval tasks cannot run until uptime = interval. `refresh_topology`
(300s) is delayed on essentially every host boot (network-online rarely takes 5 min); `gossip_round`
/ `verify_candidates` / `expiry_cleanup` (60s) are delayed on the common boot (uptime < 60s);
`outbound_delivery`/`webhook_delivery` (10s) may be delayed by a few seconds.

### Frequency (CONFIRMED, with one clarification)

DEMONSTRATED for the population "host boots", cadence "every reboot of the node's host" (kernel
patch windows, power events, VM resets). The claim's own qualifier ("a machine with uptime <
interval") is precise. Clarification, not a correction: a `systemctl restart lattice` / `Restart=
on-failure` restart on a long-uptime host leaves `time.monotonic()` large, so those daemon starts
are **not** affected — the trigger population is host boots, not all service starts. The claim does
not overstate this (it names host reboot, not service restart), so the frequency statement stands
unchanged. It is a one-time-per-boot delay bounded by the interval.

### Outcome (CONFIRMED)

After a host reboot the node's first gossip round, candidate verification, topology refresh, and
expiry cleanup occur late by up to one full interval (≤300s); stale candidates / discovery state /
unexpired-but-expired rows persist for that extra window. Bounded and self-healing: every affected
task is periodic, so the second run and onward are unaffected. Delayed `expiry_cleanup` does not
cause wrong acceptance — outbound delivery (`claim_pending`, repositories.py:708-724) independently
filters `expires_at > now`, so expired messages are never delivered regardless of cleanup timing;
the only effect is content retained up to one extra interval. No data loss, no stuck item, no
custody violation. This is a real behavioral inconsistency (first-run timing depends on an
irrelevant environmental variable, host uptime) with a bounded outcome — the L bracket.

## Severity: unchanged (L)

No correction. The outcome is bounded by one interval, self-healing, and produces no wrong state,
lost item, or custody/ack fault. It is not M (no stuck/lost queue item, no wrong custody decision).
It is above S-: mechanism, trigger, and frequency are all traced, not single-pass. L is correct.

## Frequency: unchanged (DEMONSTRATED — host boots)

See above. The one nuance (service-only restarts on long-uptime hosts are unaffected) is already
inside the claim's qualifier; recorded here so a downstream reader does not widen the population.

## Sub-claims

- **Refuted/weakened — "intended 'run at startup' behavior (implicit in `_last_run=0.0`)".** The
  *intent* is an inference, not sourced. No comment, docstring, or `docs/ARCHITECTURE.md` line
  states that recurring tasks must fire at startup; ARCHITECTURE.md:66 only says "schedules
  recurring work with monotonic timing, non-overlap locks, heartbeats, and graceful stop". Marked
  UNPROVEN (intent). It does not affect the verdict: the defect is the *inconsistency* — on a
  high-uptime host the first run is immediate, on a low-uptime host it is delayed to uptime =
  interval — so no single "wait one interval" intent is honored either, and the site is wrong on
  one host class regardless of which intent was held.
- **Minor imprecision — `field(default_factory=...)`.** The source is `field(default=0.0)`
  (runtime.py:119), not `default_factory`. The value and mechanism are as claimed; no substance.
- **Held — "no test asserts first-tick timing".** `tests/test_runtime.py` sets all intervals to 60s
  and never injects `time.monotonic` or asserts first-tick timing; the tests run on long-uptime CI
  hosts, so they exercise the immediate-first-run branch only. The mechanism has no test coverage.
- Mechanism, trigger, frequency, outcome (other than the intent inference): CONFIRMED.

## Additional mechanisms / earlier failure sites on the same trace

- **Compounding wait in `_RuntimeScheduler.run` (runtime.py:149).** `while not
  self._stopped_event.wait(timeout=self._tick_seconds)` sleeps up to one full tick (1s) before the
  first `maybe_run` of every boot, adding ≤1s to every task's first run. Same first-run-delay
  family; bounded, no independent defect.
- No second consumer of `_last_run` / `time.monotonic` exists (enumeration above), so the class is
  closed at this one site.

## Fix-direction constraints

- The fix must make first-run timing independent of the monotonic reference point. Two safe shapes:
  initialise `_last_run` to `time.monotonic() - interval_seconds` when the scheduler is built (so
  the first tick always fires), or use a sentinel (`_last_run: float | None = None` and only apply
  the guard when not None). Do **not** switch to `time.time()` — it reintroduces wall-clock steps
  that `time.monotonic` deliberately avoids.
- If "immediate at startup" is the chosen semantics, the first tick fires **all seven tasks at
  once**; the fix must keep the non-overlap lock and per-task executor assignment, and must not
  serialize them on one worker (already handled by `acquire(blocking=False)` + separate executors).
- The fix must not change `maybe_run`'s ordering (`_last_run = now` before `executor.submit`): a
  submit on a shut-down executor already strands `_lock` without releasing it (runtime.py:126);
  touching this ordering is out of scope for this defect.

## Checked and clean

- Interval values and deadline arithmetic: `now - _last_run < interval` and the `_last_run = now`
  update are internally consistent; no off-by-one beyond the documented tick.
- `_run_expiry_cleanup` (runtime.py:1134) delegates to `_outbound.expire()` + `_topology.prune()`;
  delivery selection independently enforces `expires_at > now` (repositories.py:723), so cleanup
  delay cannot deliver an expired message. Clean.
- `start()` ordering (runtime.py:392-404): restore rate limits → pin bootstrap → scheduler.start.
  The scheduler is started after bootstrap pinning, so bootstrap DNS waits do not eat task
  intervals. Clean.
- Enumeration closure: `rg -n "monotonic|_last_run|_RecurringTask" --glob '!scratch/**' .` →
  runtime.py only (lines listed in Frame). No parallel scheduling primitive elsewhere.
- `tests/test_runtime.py`: fixture uses 60s intervals, does not assert first-tick behavior; no test
  would catch this on a freshly booted host. Confirms missing coverage (not a defect itself).

## Enumeration

Composed command and output:

```
$ rg -n "monotonic|_last_run|_RecurringTask" --glob '!scratch/**' .
./lattice/runtime.py:111:class _RecurringTask:
./lattice/runtime.py:112:    """A single monotonic recurring task with non-overlap locking."""
./lattice/runtime.py:119:    _last_run: float = field(default=0.0)
./lattice/runtime.py:122:        if now - self._last_run < self.interval_seconds:
./lattice/runtime.py:126:        self._last_run = now
./lattice/runtime.py:142:    def __init__(self, tasks, tick_seconds=1.0):
./lattice/runtime.py:150:            now = time.monotonic()
./lattice/runtime.py:152:                task.maybe_run(now)
./lattice/runtime.py:344-381: seven _RecurringTask constructions

$ rg -n "RuntimeSettings" lattice/
lattice/runtime.py:96,174,186
```

| Instance | Disposition |
|---|---|
| runtime.py:119 `_last_run = 0.0` | finding — root of this claim |
| runtime.py:122 guard | finding — the comparison against boot-relative `now` |
| runtime.py:126 update | examined-clean — ordering correct for the non-overlap contract |
| runtime.py:150 `time.monotonic()` | finding — supplies the boot-relative epoch |
| runtime.py:344-381 tasks | examined-clean — intervals/executors correct; each affected |
| runtime.py:174/186 settings construction | examined-clean — no TOML path; defaults fixed |

## Bounds

- I did not run the daemon on the Linux target. `time.monotonic()` = boot-relative was verified
  directly on darwin (`CLOCK_UPTIME_RAW` equality); the Linux `CLOCK_MONOTONIC` mapping is from
  documented CPython behavior, not executed on Linux here.
- I did not observe real systemd boot timing on Debian/Ubuntu/RHEL; the claim "systemd starts
  lattice serve seconds after boot" is accepted from `deploy/lattice.service` structure plus
  `docs/LOOSE_ENDS.md:77,91` (target-distro smoke tests not automated).
- Containerized deployments: if `lattice serve` runs in a container on a long-uptime host,
  `time.monotonic()` reflects host uptime and the trigger does not occur. Trigger reachability is
  therefore "PRODUCTION (bare-metal/VM host boot on Linux/systemd)"; container-restart deployments
  are outside the affected population.
