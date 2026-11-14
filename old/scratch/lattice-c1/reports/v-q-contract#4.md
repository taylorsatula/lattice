# v-q-contract#4 — PRIMED VERIFIER

Claim under test: **q-contract#4** (`scratch/lattice-c1/reports/q-contract.md`, finding 4,
reported tier **L**) — "THREAT_MODEL invariant 6 'Audit metadata is retained only 30 days' has no
implementation."

Method: re-derived the frame from source before reading the claim's conclusion. Read
`docs/THREAT_MODEL.md` §4 invariant 6, `lattice/migrations/durable/001_initial.sql`,
`lattice/storage/repositories.py:AuditLogRepository`, `lattice/runtime.py` (`_write_audit_entry`,
the five `_audit_*` helpers, `_run_expiry_cleanup`), and every audit call site. Independently
enumerated all writers and any deleter.

## Verdict: ADJUSTED

Mechanism CONFIRMED. Two frequency/trigger sub-claims REFUTED. Severity unchanged at **L**.

### Re-derived frame (before checking the claim)

- **Doc.** `docs/THREAT_MODEL.md:57` §4 invariant 6: "**Content minimization.** Terminal message
  content and extensions are erased. Audit metadata is retained only 30 days." The migration
  repeats the claim: `001_initial.sql:193` "-- Audit log: minimal structured event records retained
  30 days."
- **Schema.** `audit_log(id, event_code, node_id, message_id, details, recorded_at)` with an index
  on `recorded_at`. No `TRIGGER`, no `ON DELETE`, no purge column. (`rg -i 'trigger|DELETE|retention|30'
  lattice/migrations/durable/*.sql` → only the line-193 comment; the `DELETE` hits are all foreign-key
  clauses on other tables.)
- **Writer.** The only insert path is `AuditLogRepository.insert`, reached solely through
  `runtime._write_audit_entry` (five wrappers). `AuditLogRepository` has `insert` and **no** delete /
  prune / expire method.
- **Reaper.** `_run_expiry_cleanup` (runtime.py:1134) calls exactly `self._outbound.expire()` and
  `self._topology.prune(now=...)`. Nothing else. Hooked on a 60 s recurring task.
- **Reader.** None. `rg -n 'audit_log|AuditLog|_audit_repo' lattice/` returns only the definition,
  the insert, and the five write wrappers. No admin route, no query method reads the table.

### Sub-claim disposition

| Sub-claim | Verdict | Trace |
|---|---|---|
| Mechanism: no retention/prune code exists; doc states a 30-day bound | **CONFIRMED** | No delete/prune method on `AuditLogRepository`; `_run_expiry_cleanup` does not touch `audit_log`; no SQL trigger or migration deletes rows. |
| Trigger: "every accepted inbound message … appends a row" | **REFUTED** | `_write_audit_entry` (runtime.py:80) gates the insert behind `if logger.isEnabledFor(level)`; `_audit_inbound_accepted` passes `logging.INFO`. The audit logger is `logging.getLogger(__name__)` = `lattice.runtime`, whose effective level is the root default **WARNING (30)**. Iterating the daemon's own log config: `cmd_serve` passes `log_level` only to `uvicorn.run`, and uvicorn's `LOGGING_CONFIG` configures only the `uvicorn*` loggers — it never sets root or `lattice.runtime`. Empirically, with `uvicorn.config.Config('x', log_level='info').configure_logging()`, `logging.getLogger('lattice.runtime').isEnabledFor(logging.INFO)` is `False` and `getEffectiveLevel()` is `30`. A direct `_write_audit_entry` call with an INFO vs WARNING pair writes **only** the WARNING row. Therefore `_audit_inbound_accepted`, `_audit_outbound_delivered`, `_audit_webhook_delivered`, and `retryable=True` `_audit_webhook_failed` write **no row** in a default deployment. |
| Frequency: "unbounded accumulation … at the rate of all message traffic" | **REFUTED (overstated)** | Only the two WARNING paths append: `_audit_outbound_failed` (runtime.py:960, 995, 1007, 1015 — TransportError, invalid custody receipt, HTTP 429/≥500, terminal response) and `_audit_webhook_failed` with `retryable=False` (runtime.py:1069 → wrapper line 883 chooses WARNING). Accumulation is still unbounded, but the population is delivery-failure and permanent-webhook-failure events, not all inbound/delivered traffic. |

### Corrected frequency (with its trace)

Unity of the writer gate establishes that, absent external logging configuration, every INFO-level
audit event is dropped at `_write_audit_entry`. Demonstrated population: one row per **failed
outbound delivery attempt** (unreachable peer, bad receipt, 429/5xx, terminal status) and one row per
**non-retryable webhook failure**. Cadence: continuous but sparse, proportional to failure rate, not
message volume. The table therefore grows without bound but orders of magnitude slower than the
claim states. The missing 30-day retention is still unmet for every row that does land.

### Severity

Left at **L** and unchanged. Retaining failure metadata past the documented 30-day bound is a
bounded bad outcome (privacy/retention invariant unmet; slow durable-DB growth), not data loss, not
cross-peer reach, not a crash — it does not meet the M bar (no wrong custody, no stuck/lost queue
item, no wrong rate decision) nor the H bar (no unbounded exhaustion at a network-driver's chosen
rate; the writer is failure-gated). The claim's own L is correct; only its frequency was wrong.

### Reachability kind

**PRODUCTION** — a running daemon (`cmd_serve`) reaches the insert path on any outbound failure or
non-retryable webhook failure. Not tests-only and not gated behind another finding. The trigger's
*population* is failure events, which is the correction above, not a gate.

### Fix-direction constraints

1. Retention must be a time-based delete keyed on `recorded_at` (the index
   `idx_audit_log_recorded_at` exists) and run inside the existing `_run_expiry_cleanup` 60 s hook
   **and** once at `start()`, so a daemon that runs only briefly still prunes.
2. A repair **must not assume the INFO path is active**. If any future change raises
   `lattice.runtime` to INFO (or adds a root `basicConfig`), the write rate jumps from
   failure-rate to all-traffic-rate — retention is a prerequisite for that change, not an
   independent nice-to-have.
3. `audit_log` has no foreign keys and no in-tree reader; a repair should decide whether the table
   is a needed facility at all rather than only bolting a `DELETE` onto a write-only table.
4. Escaping the retention violation does not by itself make the audit facility functional or
   observable; do not conflate "prunes at 30 days" with "audit trail works."

### Additional mechanisms / earlier failure sites

- The `_write_audit_entry` **logging-level gate** is the decisive mechanism the claim omitted. It
  sits *before* the repository call and silently suppresses the majority of would-be rows. This is
  the earlier failure site on the same trace (runtime.py:80 rather than repositories.py:1127).
- No new reachability path beyond the failure rows above.

## Checked and clean

- `docs/THREAT_MODEL.md` §4 invariant 6 text matches the quoted 30-day statement.
- `001_initial.sql:193` and `tests/fixtures/durable_schema/v1.sql:195` carry the same table
  definition and the "retained 30 days" comment; the schema has an index on `recorded_at` suitable
  for a retention delete.
- `_run_expiry_cleanup` correctly does what it says (outbound expiry + topology prune); the absence
  of audit pruning is a *missing* action, not a wrong one.
- The five `_audit_*` wrappers pass the levels the wrapping log line implies; the gate semantics are
  internally consistent with `_write_audit_entry`'s docstring ("Write an audit entry gated by Python
  logging level") — intentional, not an off-by-one bug.
- `AuditLogRepository.insert` stores `details` as JSON-or-NULL and `recorded_at` through
  `_format_ts`; no corruption of written rows.

## Enumeration

```
# writers vs deleters of audit_log (whole tree, code only)
rg -n 'audit_log|AuditLog|_audit_repo|DELETE FROM audit' lattice/ tests/ --iglob '!*.md'
```
Instance table:
- `repositories.py:1127` AuditLogRepository class — writer only, no prune/delete — **FINDING (retention)**
- `repositories.py:1140` INSERT INTO audit_log — sole insert — **writer, gated upstream**
- `runtime.py:80` `_write_audit_entry` — logging-level gate — **mechanism correction (this report)**
- `runtime.py:195` `self._audit_repo = AuditLogRepository(durable_conn)` — construction — clean
- `runtime.py:831/843/855/867/879` `_audit_*` wrappers — writers — **INFO ones dead by default**
- `runtime.py:969/995/1002/1007/1015` outbound call sites; `1061/1069` webhook call sites — **WARNING population**
- `api.py:348` `_audit_inbound_accepted` — INFO, drops — **refutes "every accepted message appends a row"**
- `001_initial.sql:195` / `tests/fixtures/...:195` schema — no deleter
- any `DELETE FROM audit_log` — **none** — closes the class

```
# any logging configuration that could raise the audit logger
rg -n 'logging\.|basicConfig|setLevel|dictConfig|addHandler|log_level' lattice/ deploy/ --iglob '!*.md'
```
Only hits: `runtime.py:53` and `:260` (`getLogger(__name__)`), `cli.py:725/903` (`--log-level` →
`uvicorn.run`). No root/`lattice` logger configuration exists. Closes the class: the audit logger is
WARNING-effective in every in-tree entry point.

## Side discoveries (single-pass candidates, not confirmed work)

1. **audit_log is write-only dead data.** No reader exists in the tree (see Enumeration). Not
   reportable on its own (no runtime misbehavior); priced as context: any repair should scope to the
   retention invariant only, and a reviewer may reasonably ask whether the facility is wanted at all.
2. **The audit trail is effectively empty in a default deployment** because the audit logger never
   reaches INFO and no code enables it. Intentional per the `_write_audit_entry` docstring, so not a
   defect; recorded so a future pass does not "fix" the gate and turn the retention violation into an
   all-traffic growth fault. Fix-direction: enable INFO only together with retention.

## Bound

- No live full-daemon run and no long-duration DB-growth test. The logging gate was proved at unit
  level plus by inspecting the installed `uvicorn` 0.36.0 `LOGGING_CONFIG` and a live
  `Config.configure_logging()` call.
- **Unverifiable from the tree:** external logging configuration an operator may impose
  (`PYTHONSTARTUP`, a `sitecustomize`, a wrapper that calls `basicConfig`) could raise
  `lattice.runtime` to INFO and restore the claim's original all-traffic frequency. Nothing in the
  repo does so; that path is outside the code under review and is stated as a boundary, not a
  refutation.
- The claim's empirical TestClient run was not reproduced end-to-end here; the decisive gate is
  fully traced without it.
