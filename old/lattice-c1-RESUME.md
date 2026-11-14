# lattice-c1 — RESUME (bugfix-swarm run, still open)

Run: `lattice-c1`, first full census, repo `/Users/taylut/Programming/GitHub/lattice`.
Written for a fresh session to pull the remaining work back into context. **Files are the state; this
file is an index.**

## 0. How to resume (do this first)

1. Read `scratch/lattice-c1/ledger.md` — newest FLUSH block (currently FLUSH 10) then the tail.
2. Read `scratch/lattice-c1/slice.md` — the full round/bucket slice.
3. Confirm tree state + gates (must all pass):
   `.venv/bin/ruff check lattice/ && .venv/bin/mypy --strict lattice/ && .venv/bin/python -m pytest -q`
4. Enumerate open katas: `kata list --label lattice-c1 --status open --json`.
5. Runbook: skill `bugfix-swarm`; continuity: `bugfix-swarm-handoff`.

Registry: kata v0.18.0, project `lattice`, bound. Run-level ticket: **kata#1824**.
Pre-fix snapshot commit: **b145ad9** (lattice/ is untracked, so diff with:
`git archive b145ad9 lattice | tar -x -C /tmp/snap && diff -ru /tmp/snap/lattice lattice`).

## 1. Fix state so far

- **C1 (outbound/SSRF) — LANDED, VERIFIED, tickets CLOSED** (7).
- **C2 (identity/cert) — LANDED, VERIFIED, tickets CLOSED** (6 done; 2 declined `--wontfix`: jzv1, wz8m).
- **C3 (rate-limit/DoS) — LANDED, VERIFIED, tickets CLOSED** (6).
- **C4 (storage concurrency/migration) — LANDED, gates GREEN, TICKETS NOT YET CLOSED** (8).
  Executors finished EXECUTED; **review the diff and close these 8** before dispatch proceeds.
- 15 files changed vs snapshot. All fixes are in the working tree, uncommitted.

Commit policy (human): the pre-existing rewrite stays uncommitted; at run close, **only our fix hunks**
are staged into bugfix commits. Do not commit the whole tree.

## 2. REPAIRED, PENDING REVIEW+CLOSE (C4) — do this next

| kata | tier | title |
|---|---|---|
| 6b8f | H | Shared SQLite connection: per-statement lock does not isolate transactions |
| dqa1 | M | Pre-migration backup copies only the main DB file, omits WAL-resident commits |
| hv81 | L | Migration scripts run without a transaction |
| ym88 | L | claim re-select returns rows from any same-owner claim, same lease-expiry second |
| st0g | L | Expiry sweep terminal-expires an in-flight leased message |
| hna1 | L | Circuit-breaker writes bypass the repository transaction boundary |
| kvbw | L | Corrupt cache file crashes startup with raw DatabaseError instead of recreate |
| zmks | L | stop(timeout) does not bound executor drain |

Close with: `kata close <id> --done --message "<fix narrative>" --evidence reviewed-paths:<file>
--evidence test:.venv/bin/python -m pytest -q`.
NOTE: `kvbw` had a **binding human note** — do NOT auto-recreate the cache; crash with a helpful
reason + directive to clear manually. Confirm the landed fix honored it.

## 3. ROUND 2 — pickers not yet presented (open katas)

**C5 — custody receipt semantics (7).** The C5 picker was started then CANCELLED — re-present it.
Every row was gated behind the transport fix, which is now LANDED, so they are LIVE.
- jbbw (M) — custody receipt signature never verified; ownership transferred on 3-field match
- twpy (M) — final 'rejected' receipt retried as retryable (~8.5h churn), false circuit open
- rq3k (M) — canonical to_address bypasses the ownership guard
- 47qy (M) — structural/unknown-sender errors misreported as 401; canonical unknown sender erased
- snfv (L) — rejected receipts never persisted; rebuilt with fresh received_at (8 idempotency)
- yv24 (L) — cross-sender message_id collision yields final rejection
- pb3v (L) — transient custody-write failure becomes a final signed rejected

**C6 — HTTP error mapping & public-route contract (5).**
- pdb3 (L) — admin_submit maps Resolution/AddressError to 500, not 400
- 99bq (M) — malformed from/to_address → unhandled AddressError → plain 500
- 2k63 (L) — PROTOCOL 11 media-type/version rejection unimplemented on public routes + well-known
- ak3t (L) — strict-JSON parse rules not applied to public bodies (dup keys, NaN, I-JSON range)
- wy8z (L) — PROTOCOL 9 error-code table not implemented

**C7 — topology, gossip & discovery (5).**
- ktws (M) — escaping ValueError leaves a stuck candidate re-fetched every cycle
- vckf (M) — block() does not clear the discovery set (blocked peers get gossip up to 24h)
- g3fy (M) — outbound gossip batch bounded by card count only; oversized bodies 413 + open circuit
- axh1 (L) — gossip batch attribution always None (no introduced_by column)
- x2g2 (L) — stale candidate demotes a bootstrap-established peer after restart

**C8 — config, credentials & CLI (4).**
- 6bse (L) — invalid TOML / wrong-typed config escapes ConfigError
- mpne (L) — malformed credential files escape CredentialError (raw traceback)
- njgm (L) — webhook.bearer_credential_name ignored by credential loading
- 47n1 (L) — 'lattice init' accepts --domain/--public-base-url values its validator rejects

**C9 — outbound queue & scheduler cadence (2).**
- 1jnj (L) — terminal transitions consume retry attempts and leave no audit record
- 0p5c (L) — _RecurringTask first-run arithmetic delays all maintenance on fresh boot

## 4. ROUND 3 — polish/docs, OPT-IN (open katas)

- **C10 — deploy/systemd (2):** q04n (M) ExecReload SIGHUP kills daemon; fz1a (M) shipped ExecStart
  --config rejected by the CLI parser.
- **C11 — doc ↔ code drift (3):** z0fw PROTOCOL 6 omits root_public_key; 4m8d PROTOCOL 5.3 omits the
  cold-sender 503; ag8g THREAT_MODEL 4.6 audit retention unimplemented.

## 5. Decisions already made (do not re-ask)

- Kickoff: full census / Standard stakes / no calibration changes.
- C1: accept all 7. C2: accept 6, decline jzv1+wz8m. C3: accept all 6. C4: accept all 8.
- Calibration rule added after batch 1: **REACHABILITY KIND IS STATED** (production / tests-only /
  gated-behind-`<id>`).
- Dispute adjudicated: `CustodyError→202` is DOCUMENTED (PROTOCOL §8) — examined-clean, no ticket.
- Declined rows (`jzv1`, `wz8m`) are closed `--wontfix`; do not re-open.

## 6. Open items / caveats

- Coverage caveat: private-mode `validate_ip` still ORs suffix-vs-CIDR (accepted C1 HOW was the
  anchor fix; out of scope).
- Verdict disagreements preserved (not resolved): 6b8f (H/M/L), dqa1 (M/L), jbbw (M/L), rq3k (M/L),
  47qy (M/L).
- 4 `S-` entries remain "needs one more pass" (from dedupe) — not ticketed, not offered.
- At run close: write coverage summary + decay reading to the run-level ticket kata#1824, then close it.

## 7. Out-of-band meta-task (NOT run state)

`~/.pi/agent/plans/bugfix-swarm-v1.1-observations.md` — append Phases 4–9 observations at session
close. Do not fold into the registry or pickers.
