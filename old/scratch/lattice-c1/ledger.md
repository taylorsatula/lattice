# Ledger — lattice-c1

Single source of truth for coordination. Append-only. Notate as results land, never from memory.
See `bugfix-swarm` (State) and `bugfix-swarm-handoff` (Flush cadence).

## Run header

- Run label: `lattice-c1`
- Run type: **first full census** (no anchor; entire tree uncommitted since 2026-07-30) — human-confirmed 2026-09-28
- Repo: `/Users/taylut/Programming/GitHub/lattice`
- Stakes tier: **Standard** (2026-09-28) — primed verify every finding; blind 3rd pass on H survivors
  where the repair's shape depends on it; adjudicate disagreements; **no** refutation recheck
- Calibration rules: **none** (2026-09-28) — the eight repo invariants are the only doctrine
  exclusions; evidence bar and severity scale as drafted in `preamble.md`
- Registry: kata v0.18.0, project `lattice`, bound
- **Run-level ticket: `kata#1824`** (uid 01M3JZEQZFKH3K7F37YG951824, labels `lattice-c1`+`run-level`)
  — created 2026-09-28 22:03, late (see v1.1 note: "first decision" timing was ambiguous)
- **RESUME INDEX (repo root): `lattice-c1-RESUME.md`** — grouped open-kata list, fix state,
  decisions, caveats. Written 2026-09-29 23:30 for a fresh session. Read it first.
- Model gate: PASS (2026-09-28)
- Reports dir: `scratch/lattice-c1/reports/`
- Merge manifest: `scratch/lattice-c1/merge_manifest.md` (pending Phase 5)
- Area taxonomy: `scratch/lattice-c1/areas.md`
- Full-wave script: `.pi/workflows/lattice-c1-hunt.js` (20 hunters, preamble baked byte-verified)
- **Workflow runId: `wf_d7f44811005f`** (full hunt wave, COMPLETE 20/20)
- **Verify workflow runId: `wf_850a5c320756`** (Phase 4, 92 agents, in flight)
- **Orientation dispatches (2026-09-28 22:20, applied §F retroactively):** 4 `general-purpose`
  terrain agents → `scratch/lattice-c1/orientation/{core,federation,runtime,contract}.md`.
  IDs: orient-core `ff302244-8023-45a`, orient-federation `06409128-1f84-453`,
  orient-runtime `b9408fa6-c8a7-4cd`, orient-contract `51df939c-96d2-4cf`. Contract: 9-section
  synthesis (concept, invariants, mechanism inventory, sanctioned idioms+exemplars, consequence map,
  intentional decisions, doc↔code drift, verification surface, surprises); ≤900-word report file,
  ≤500-word synthesis returned into orchestrator context. **Terrain, not findings.**
- **Commit strategy (human-set 2026-09-28 22:05):** the pre-existing uncommitted rewrite is NOT
  committed by this run. At run close, only OUR fix hunks are selectively staged into bugfix
  commits (hunk-level), so other developers can keep working the same dirty worktree without the
  commits getting tangled. Requirement: **snapshot the tree BEFORE the first fix-wave dispatch**
  (e.g. `git stash create` or a tar of tracked files) so our hunks are identifiable against the
  pre-fix state — `git diff` vs HEAD shows the whole rewrite, not our change. Load `git-workflow`
  at commit time.
- **Pre-fix snapshot: `b145ad956d9e074ce01e5ce0ff862ededb65162d`** (2026-09-28 22:06, created via a
  temp index; real index/worktree untouched). SHA also in `scratch/lattice-c1/.pre_fix_snapshot`.
  Isolate our hunks later with `git diff b145ad9 -- lattice/`.
- **OUT-OF-BAND META-TASK (human-requested 2026-09-28):** retrospective for the next orchestration
  agent that cold-opens "enable bugfix-swarm skill and prepare your workspace." **Not run state** —
  lives in `~/.pi/agent/plans/bugfix-swarm-v1.1-observations.md`; append Phases 4–9 findings there at
  session close, do not fold into this run's registry or pickers. Only this pointer stays in the ledger.

## Bootstrap record (Phase 1)

1. Registry read: `kata list --status all` → empty. No refuted set. No prior run-level ticket.
2. Anchor: none → first census, full map build.
3. Churn: `git log --stat --since` inapplicable — all current source is uncommitted/untracked
   (`git status` shows the rewrite in progress). Churn map = the working tree itself.
4. Kickoff inputs: **recorded 2026-09-28** — census / Standard / no calibration changes.
   Preamble used as drafted (no edit needed).
5. Exclusion payload: none (empty registry).
6. Terrain: `AGENTS.md` + `docs/AGENTS.md` read; drift noted in `areas.md`. No per-directory maps
   exist beyond these two, so no map-build pass is needed — the two maps cover the tree.

## Dispatches

| pass-id | agent type | model | assignment | status | report file |
|---|---|---|---|---|---|
| hunt-b1a | swarm-investigator | lunaroute/glm-5.3 | runtime lifecycle/cadence + config.py | LANDED (179a0d41-4435-4d3) — 1H/0M/1L/0S- | `reports/hunt-b1a.md` (14.5 KB) |
| hunt-b1b | swarm-investigator | lunaroute/glm-5.3 | outbound delivery/signing + messages/transport | LANDED (a99f358e-b8ea-480) — 1H/2M/2L/0S- | `reports/hunt-b1b.md` (20.3 KB) |
| hunt-b1c | swarm-investigator | lunaroute/glm-5.3 | inbound custody/rate-limit/webhook | LANDED (39492482-bb3d-4b9) — 1H/1M/3L/0S- | `reports/hunt-b1c.md` (17.7 KB) |

Pilot batch — 3 hunters on the highest-consequence area (`runtime.py`, split by mechanism).
Dispatch mechanism: plain `Agent` background dispatch (swarm request is the SubagentWorkflow opt-in,
stated here once; a 3-agent pilot needs no script).

## Envelopes / findings

### hunt-b1c (landed 2026-09-28)
- Findings: **1 H / 1 M / 3 L / 0 S-** (2 of the L latent, at cap). Report `reports/hunt-b1c.md`.
- Clean: inbound verify→block→custody ordering + idempotent accept; rate-limit lock/refill/
  restore/persist round trip; webhook idempotency key, retry classification, lease/claim CAS;
  gossip per-card loop continuation with pre-enforced batch bounds; cert/root-key lookup chain;
  verify/refresh/expiry cadence.
- Enumeration: 10 instances dispositioned — E3 (3 `time.time()` sites + restore/persist pair,
  clean), E4 (gossip 92/130/246 + topology 5, clean; one side note), E5 (rate-bucket dual-write —
  no dual-write exists, out-of-scope-with-reason).
- Disputes/uncertainty: H (cold-sender resolution queue never drains — unbounded set + perpetual
  outbound re-resolution) fully traced; M (canonical node-ID `to_address` bypasses
  recipient-ownership guard) mechanism solid, frequency depends on sender misaddressing; a
  500-on-malformed-address finding is unauthenticated and trivially reachable but bounded to
  wrong-status/log noise.
- Convergence: pending other pilots.

### hunt-b1a (landed 2026-09-28)
- Findings: **1 H / 0 M / 1 L / 0 S-**. Report `reports/hunt-b1a.md`.
- Clean: scheduler stop handshake; executor creation/shutdown ordering; recurring-task cadence
  arithmetic (no doubled/missed ticks, no drift); rate-limit restore/persist round-trip and
  ordering; `is_ready`/`is_running` gating; `config.py`; `__init__.py`; `_write_audit_entry` level
  gate.
- Enumeration: all E1/E2/E5 instances dispositioned (7 rows, incl. the E2 `shutdown(cancel_futures=False)`
  candidate → examined-clean with lease-recovery evidence; E1 api/messages submit sites traced into
  Finding 1's trigger).
- Disputes/uncertainty: Finding 1 is H (data loss) but its trigger is a **coincidence race** — a
  microsecond execute→commit window needing a failing `with conn` block; reachable today via admin
  duplicate outbound submit; mechanism empirically demonstrated on an in-memory connection, not
  under production concurrency. CPython 3.12 `Connection.__exit__` bypasses the
  `_LockedConnection.commit/rollback` overrides (agent says verified), widening the window beyond
  the class comment. Side discoveries (circuit-breaker missing commit; `start` outside
  try/finally in `cmd_serve`) are latent and passed to future passes.
- **Orchestrator self-verification OV-1:** confirmed by direct execution that CPython 3.12
  `Connection.__exit__` bypasses the `_LockedConnection` commit/rollback overrides — the lock does
  not cover the implicit transaction commit. See annotation below.

### hunt-b1b (landed 2026-09-28)
- Findings: **1 H / 2 M / 2 L / 0 S-** (both L latent; one gated behind the H). Report
  `reports/hunt-b1b.md`.
- Clean: queue claim/release/lease semantics; retry/backoff/expiry arithmetic; circuit
  threshold+reset math; custody-transfer status handling; webhook egress path;
  `allow_submission`/readiness wiring; local-message signing preimages; inbound receipt
  idempotency; shutdown drain.
- Enumeration: E5 (3/3), E3 (7/7), E2 (1/1) dispositioned.
- Disputes/uncertainty: (1) **H** — every `OutboundTransport.request()` raises `TypeError` before
  network I/O, killing all outbound delivery/resolution/gossip and crashing `start()` on
  bootstrapped fresh deployments; **masked in CI because all tests mock the transport**. (2) A
  redirect-SSRF bypass of `NetworkPolicy` is verified at the urllib3 layer but unreachable until
  the H is repaired — reported as **latent L** so the repair does not ship it. (3) Finding 2
  (rejected-receipt retry divergence) is in-tree reachable via mocked-transport tests but
  production-gated behind the H — flagged. (4) Minor: uncommitted circuit-breaker writes and
  circuit-open attempt burn filed under Design risks.
- **Orchestrator self-verification OV-2:** reproduced the H directly (see annotation below).

## Pilot calibration (batch 1 → full wave)

Three pilots (hunt-b1a/b/c) over `runtime.py`. Aggregate: **3 H / 3 M / 6 L / 0 S-** across 12
findings. Reading: **preamble holds** — no design-as-bug leakage on the
intentional-pattern-dense core; evidence bar applied (frequencies honestly graded: coincidence
race, latent, production-gated); all three H findings decisive, two independently reproduced by
the orchestrator (OV-1, OV-2).

One calibration rule added from batch 1 (applied to `preamble.md` this turn, stands for every later
prompt): **REACHABILITY KIND IS STATED** — each finding marks production / tests-only /
gated-behind, because the transport H masked every downstream defect in CI and two pilots correctly
reported gated findings rather than dropping them.

## Phase 3 full wave — COMPLETE (2026-09-28 21:37–22:07, `wf_d7f44811005f`)
- 20/20 envelopes returned (1,352,454 tokens, 1,799,311 ms). 23 reports total (20 wave + 3 pilot).
- **Finding inventory: 79 (14 H / 24 M / 39 L / 2 S-)** across all 23 passes. Envelopes saved to
  `scratch/lattice-c1/hunt_envelopes.json`; journal copied to `hunt_journal.jsonl`. Pilot inventories
  reconstructed from report headers (id = tier+title index only).
- Exit gate met: every pass wrote its report file; every enumerated instance dispositioned.
- **Phase 4 coverage diff (exit gate): 28/30 source `.py` files referenced by some pass.** Untraced:
  `lattice/_version.py` (version constant) and `lattice/storage/__init__.py` (1-line init) — neither
  mechanism-bearing, no residual pass needed. Gate closed.
- **Cross-area convergence (notated while hot):**
  - cold-sender domain queue (unbounded growth) — `hunt-a1#3` (H) and `hunt-b1c#1` (H): same root
    mechanism reached from two different frames → frame-independent agreement.
  - canonical `to_address` bypass of recipient-ownership — `hunt-a1#2` (M) and `hunt-b1c#2` (M).
- **Flagged dispute (enters Phase 4):** `CustodyError → 202` at `api.py:339` literally matches the
  preamble's "202 without durable custody IS reportable" clause, but `docs/PROTOCOL.md` §8 blesses
  "202 + rejected receipt is final" and sender-side validation requires `status=="accepted"`. Pass
  dispositioned examined-clean and asked for arbitration.
  **ADJUDICATED 2026-09-28 (orchestrator, decisive artifact = normative doc):** `PROTOCOL.md §8`
  states "A 202 Accepted with a rejected receipt is final. The receipt bytes MUST be persisted and
  returned identically for duplicate message_id." So `202 + rejected receipt` on custody rejection
  is DOCUMENTED, not a defect — the receipt is the durable record; 202 means request-recorded, not
  custody-taken. Disposition: **examined-clean, no ticket**. No preamble conflict: the preamble's
  clause targets a 202 with NO durable record, which is not this case.
- **Contract orientation landed** (`orient-contract`): `docs/adr/` is EMPTY (areas.md had assumed a
  corpus); deploy↔code map consistent; `LOOSE_ENDS.md` already names the `_LockedConnection`
  single-connection bottleneck (adjacent to OV-1); THREAT_MODEL §7 non-goals bound the census (no
  e2e encryption, no relay, no multi-process runtime, etc.). Synthesis saved to
  `orientation/contract.md`.

## Orchestrator annotations

### Orientation syntheses (terrain, 2026-09-28; files in `scratch/lattice-c1/orientation/`)
- **contract** (landed): `docs/adr/` empty; PROTOCOL §8 adjudicates the 202/rejected-receipt dispute
  (see above); THREAT_MODEL §7 non-goals bound the census; deploy↔code map consistent.
- **core** (landed): idiom-divergence families to help score/slice verified tickets — (a) cert
  validation exemplar is `cert.verify()` + `cert.is_valid_at(now)` but `resolution.py` and
  `topology._verify_against_well_known` call only `verify`; (b) strict-JSON exemplar is
  `strict_json_loads` but HTTP gossip/message ingress uses FastAPI defaults and `topology.py` uses
  `json.loads`; (c) I-JSON range check absent; (d) sequence monotonicity absent. Doc drift: §4.4
  kind table omits `webhook_envelope`, lists `contact_card` with no model; `signing.py` has
  `sign_receipt`/`sign_block` but no verifiers. Intentional boundary: FastAPI default ingress JSON is
  claimed intentional in `LOOSE_ENDS.md` Phase 10 — any dup-key/NaN finding there must beat that
  rationale.
- **federation** (landed, `orientation/federation.md`): ranked consequence — SSRF
  (`transport._resolve_and_validate`/`validate_ip`) → unverified→verified promotion
  (`topology._verify_against_well_known`) → wrong pin (`resolution.pin`) → rate-bucket keying →
  candidate caps. Intentional: bootstrap introduces-never-relays; intake groups by hostname pre-cap;
  first-card trust is rate-key only; XFF fallback and caps are best-effort. **Test-mask (critical for
  verdict interpretation): `conftest._FakeTransport` bypasses the whole urllib3/TLS/SSRF path in
  integration tests — this is what hid OV-2; `RateLimiter` has no direct test.** Drift: PROTOCOL §6
  omits `root_public_key`; expired-card + sequence rules unenforced in `verify_candidate`; ADDRESSING
  "fails closed on re-resolution" has no enforcing symbol.
- **runtime** (landed, `orientation/runtime.md`): ranked consequence — `InboundMessageService.accept`
  (durable custody) + `OutboundMessageRepository.mark_terminal`/`expire_messages` (irreversible
  erasure) → stuck queue (5-min lease; crash between claim and `record_failure` strands a row
  silently) → silent scheduler-thread death → audit gated by log level. Drift: `AGENTS.md` map cites
  nonexistent `app.py`/`api_public.py`/`api_local.py`/`queue.py`/`client.py`; `docs/AGENTS.md`
  registers nonexistent `OPERATIONS.md`/`INTEGRATION.md`; `MIGRATIONS.md` claims one-transaction
  application (code uses one `with conn:` per script).

### Fix-prompt exemplars (from orientation — flow verbatim into Phase 8 prompts)
- durable write → `storage/repositories.py:OutboundMessageRepository.create` (or `PeerRepository.upsert_peer`) with `with self._conn:` + `_format_ts`/`_json_dumps`
- background cadence → `runtime.py:_run_outbound_delivery` (a `_RecurringTask` in `_build_scheduler`)
- queue item → `repo.claim_pending(owner, now, limit)` then `record_success`/`record_failure`; never inline SQL
- HTTP error → `api.py:_problem(...)`; `_STATUS_PROBLEM_MAP` authoritative
- cert validation → `cert.verify(root_identity)` THEN `cert.is_valid_at(now)`; mirror `runtime.py:verify_gossip_sender_card`
- resolve+connect external host → `transport.OutboundTransport.request` / `_resolve_and_validate`; never raw sockets
- verify peer card → `topology.py:TopologyService._verify_against_well_known` (the weaker `runtime.verify_gossip_sender_card` is the deliberate rate-key variant)
- admit candidate → `gossip.GossipService.receive_batch` → `topology.accept_candidate`; never insert rows directly
- parse address → `addressing.py:parse_address`
- untrusted JSON → `canonical.strict_json_loads` then model_validate
- preimage → `identity.OperationalIdentity.sign_object`/`verify_object` with `signature_preimage(kind, canonicalize(obj_without_signature))`
- **federation / runtime**: pending.

### OV-1 — self-verification of hunt-b1a Finding 1 mechanism (2026-09-28, orchestrator-decided)
Claim: CPython 3.12 `Connection.__exit__` bypasses the `_LockedConnection.commit/rollback`
overrides, so the coarse RLock does not cover the implicit transaction commit/rollback of a `with
conn:` block. **CONFIRMED by direct execution.** `sqlite3.connect(':memory:', factory=<subclass
overriding commit/rollback>)`: both clean-exit and failing-exit `with conn:` produced 0 calls to the
overridden methods. Implication: writes issued via `execute` are locked, but the implicit commit
that makes them durable in `__exit__` is not — the lock does not serialize transactions, only
statements. Supports the H finding's widened-window mechanism and is itself a distinct
concurrency defect at `lattice/storage/connection.py:_LockedConnection`. Enters the corpus as
orchestrator-decided input (frame: the lock's stated contract vs its actual coverage).

### OV-2 — self-verification of hunt-b1b Finding 1 (2026-09-28, orchestrator-decided)
Claim: every `OutboundTransport.request()` raises `TypeError` before network I/O because `fields=`
is passed to `PoolManager.urlopen`. **CONFIRMED by direct execution** against the repo venv
(`urllib3 2.7.0`): `pool.urlopen('GET', url, body=None, headers=..., fields=None,
assert_hostname=..., preload_content=True)` → `TypeError: HTTPConnectionPool._make_request() got
an unexpected keyword argument 'fields'`. Live breakage: all outbound delivery, resolution, and
gossip fail; `start()` crashes on a fresh bootstrapped deployment. It is the gate masking several
other findings (redirect-SSRF, rejected-receipt retry divergence). Enters corpus as
orchestrator-decided; the Phase 4 blind third pass still runs on it (repair shape depends on the
frame).

### Phase 4 incident — barrier stall (2026-09-28 03:19 → 17:20, ~14 h)
- **Symptom:** human reported "one of them hung." Verify journal stalled at 78/92; all child
  activity stopped ~03:30.
- **Root cause:** verify script used `parallel(primed)` **then** `parallel(blind)` — an inter-phase
  **barrier**. One primed agent (`v-hunt-k1#2`, primed verifier on `hunt-k1`) was doing a **live
  probe** (spawning `uvicorn` to test SIGHUP handling) and its **model call hung mid-turn** at
  03:19:45 with no terminal error. Because the primed `parallel` never resolved, the 13 blind
  passes **were never dispatched** (confirmed: no session anywhere contains a blind assignment
  except the main session's script source).
- **Missing set (14):** 13 blind (`blind-hunt-a1,c1,c2,d1,g1,h2,k1,seam-s2,q-error,q-contract,
  b1a,b1b,b1c`) + 1 primed (`v-hunt-k1#2`).
- **Harvest (from journal — authoritative):** 78 primed verdicts → `verify_verdicts.json`:
  **41 CONFIRMED / 37 ADJUSTED / 0 REFUTED**; corrected tiers H14/M18/L44/S-2.
- **Orphan cleanup:** killed `/tmp/sighup_test.py` (PID 29631) left by the hung probe.
- **Recovery:** `.pi/workflows/gen_verify_residual.py` → `.pi/workflows/lattice-c1-verify-residual.js`,
  a **single flat `parallel` over only the 14 missing tasks** (no barrier), with explicit
  probe-cleanup instructions injected into every prompt. Launched **`wf_0919fef46fb8`**.
- **Duplicate risk recorded:** the original `wf_850a5c320756` is still nominally running on the hung
  agent; if it ever returns `v-hunt-k1#2` it will duplicate the residual. Low risk (hung 14 h);
  harvest from journal wins.
- **RESOLVED 2026-09-28 17:12:** human stopped the original workflow (`wf_850a5c320756` → Stopped,
  78/394 agents). Duplicate risk eliminated; the residual `wf_0919fef46fb8` is the sole in-flight
  verify pass and covers all 14 missing tasks including `v-hunt-k1#2`.

## Human decisions and notes

- **2026-09-28 21:44 — human reported "agents are dead"; orchestrator verified on disk and refuted it.**
  Evidence: 8 wave children still growing (last toolUse ≤10 s prior), a 9th child spawned at
  `02:42:54` proving the runner still schedules, `reports/hunt-d2.md` landed, zero non-`message`
  records, `pi` PID alive. Human confirmed "must've just showed stale." **No re-dispatch made** —
  a re-dispatch here would have duplicated the ledger (Queued-is-not-dead rule held).

## FLUSH

### FLUSH 1 — 2026-09-28 (index, not snapshot)
Queue: kickoff inputs → preamble finalize → Phase 2 seam/instance ledger → Phase 3 pilot → full wave
Picker: none
In flight: none · workflow runId none
Decided this turn, not yet written: none
Pending corrections: none
Preamble file: draft written, calibration sections pending kickoff answers
Fix state: n/a · tree dirty (entire rewrite uncommitted)
Harvest owed: none
Next: (1) collect kickoff answers; (2) finalize preamble; (3) build seam inventory + instance ledger; (4) pilot
Detail lives in: registry (empty) · this ledger · areas.md

### FLUSH 3 — 2026-09-28 (index, not snapshot)
Queue: pilot land → calibrate preamble vs pilot output → full census wave (~14-18 hunters) → verify → dedupe → slice → pickers → fix waves
Picker: none
In flight: hunt-b1a (179a0d41-4435-4d3) · hunt-b1b (a99f358e-b8ea-480) · hunt-b1c (39492482-bb3d-4b9) — all plain dispatch, results land in `reports/hunt-b*.md`
Decided this turn, not yet written: none (dispatch written above)
Pending corrections: none
Preamble file: current
Fix state: n/a · tree dirty
Harvest owed: none yet
Next: (1) confirm preamble delivery via child session files; (2) on pilot land, compare output to intent; (3) fix preamble; (4) queue full wave
Detail lives in: registry (empty) · this ledger · areas.md · instances.md · reports/hunt-b*.md

### FLUSH 4 — 2026-09-28 (index, not snapshot)
Queue: full hunt wave (running) → per-finding primed verifiers → blind 3rd passes on H → adjudicate → dedupe → slice → pickers → fix waves
Picker: none
In flight: workflow runId `wf_d7f44811005f` — 20 hunters, script `.pi/workflows/lattice-c1-hunt.js`, reports land in `scratch/lattice-c1/reports/`
Decided this turn, not yet written: none (calibration + dispatch written)
Pending corrections: none
Preamble file: current (REACHABILITY KIND rule added; byte-verified in script)
Fix state: n/a · tree dirty
Harvest owed: none
Next: (1) verify script-preamble delivery; (2) on land, read envelopes from journal/sessions; (3) fan out per-finding verifiers
Detail lives in: registry (empty) · this ledger · areas.md · instances.md · wave-plan.md · verify-plan.md · reports/

### FLUSH 5 — 2026-09-28 (index, not snapshot)
Queue: hunt wave (running, 1/20 landed) → per-finding primed verifiers → blind 3rd passes on H → adjudicate → dedupe → slice → pickers → fix waves
Picker: none
In flight: workflow runId `wf_d7f44811005f`, alive and scheduling (8 concurrent + queued remainder); reports `hunt-d2.md` landed
Decided this turn, not yet written: none
Pending corrections: none
Preamble file: current
Fix state: n/a · tree dirty
Harvest owed: none (false stall; nothing to harvest)
Next: (1) on workflow return, read envelopes; (2) save them to `scratch/lattice-c1/hunt_envelopes.json`; (3) run `.venv/bin/python .pi/workflows/gen_verify.py` (built + tested this turn) then launch `.pi/workflows/lattice-c1-verify.js`
Detail lives in: registry (empty) · this ledger · areas.md · instances.md · wave-plan.md · verify-plan.md · reports/

### FLUSH 6 — 2026-09-28 22:14 (index, not snapshot)
Queue: Phase 4 verify wave (launching now, 92 agents) → read verdicts → adjudicate dispute + disagreements → coverage diff/residual passes → Phase 5 dedupe → slice → pickers → fix waves → Phase 9 close
Picker: none
In flight: verify workflow runId `wf_850a5c320756` (92 agents) · hunt wave `wf_d7f44811005f` COMPLETE (20/20)
Decided this turn, not yet written: none
Pending corrections: none
Preamble file: current; verify script regenerated from it
Fix state: nothing applied · tree dirty · pre-fix snapshot `b145ad9`
Harvest owed: none
Next: (1) launch verify wave; (2) verify prompt delivery; (3) on return, extract verdicts, resolve the convergence bar
Detail lives in: registry (run-level kata#1824) · this ledger · hunt_envelopes.json · hunt_journal.jsonl · reports/

### FLUSH 7 — 2026-09-28 22:15 (index, not snapshot)
Queue: Phase 4 verify (running 19/92) → extract verdicts → adjudicate §8 dispute + disagreements → coverage residual → Phase 5 dedupe → Phase 6 slice → PICKERS → fix waves → Phase 9 close
Picker: none yet (human is waiting for the first picker; keep working autonomously to it)
In flight: verify workflow `wf_850a5c320756` (92 agents, 19 reports landed)
Decided this turn, not yet written: none (prep written)
Pending corrections: none
Preamble file: current
Fix state: nothing applied · tree dirty · pre-fix snapshot `b145ad9`
Harvest owed: none
Prep ready for Phase 5: `scratch/lattice-c1/dedupe_brief.md` written; `.pi/workflows/gen_verify_verdicts.py` written + glob-tested (joins verify envelopes to finding ids via the `v-<id>` pass-id convention)
Next: (1) on verify return, run gen_verify_verdicts.py; (2) dispatch swarm-dedupe with dedupe_brief.md; (3) enumerate kata tickets; (4) slice by defect class/round; (5) present first picker
Detail lives in: registry (kata#1824) · this ledger · hunt_envelopes.json · verify_verdicts.json · reports/

### FLUSH 8 — 2026-09-28 17:25 (index, not snapshot)
Queue: residual verify wave (14 tasks) → merge verdicts → Phase 5 dedupe → Phase 6 slice → PICKERS → fix waves → close
Picker: none yet
In flight: residual `wf_0919fef46fb8` (14 tasks, flat) · original `wf_850a5c320756` STOPPED by human 17:12 (duplicate risk cleared)
Decided this turn, not yet written: none
Pending corrections: none
Preamble file: current
Fix state: nothing applied · tree dirty · pre-fix snapshot `b145ad9`
Harvest owed: none (78 harvested; 14 re-dispatched)
Next: (1) on residual return, re-run gen_verify_verdicts.py (merge residual journal); (2) dispatch dedupe with dedupe_brief.md; (3) slice; (4) first picker
Detail lives in: registry (kata#1824) · this ledger · verify_verdicts.json · hunt_envelopes.json · orientation/ · reports/

### FLUSH 9 — 2026-09-28 17:35 (index, not snapshot)
Queue: Phase 5 dedupe (running) → enumerate tickets → Phase 6 slice → PICKERS → fix waves → close
Picker: none yet
In flight: dedupe agent `fd379e1a-709f-46f` (swarm-dedupe, glm-5.3-flash) — reads `dedupe_brief.md`, creates tickets, writes `merge_manifest.md`
Decided this turn, not yet written: none
Pending corrections: none
Preamble file: current
Fix state: nothing applied · tree dirty · pre-fix snapshot `b145ad9`
Harvest owed: none
Verify final: 79 primed (41 CONFIRMED / 38 ADJUSTED / 0 REFUTED; tiers H14/M19/L44/S-2) + 13 blind (41 new findings) = 120 findings, 115 reports. Verdict index `verify_verdicts.json`.
Next: (1) on dedupe return, `kata list --label lattice-c1 --json`; (2) read each ticket with `kata show`; (3) slice by defect class + round; (4) present first picker
Detail lives in: registry (kata#1824) · this ledger · verify_verdicts.json · hunt_envelopes.json · orientation/ · reports/

### FLUSH 10 — 2026-09-28 (index, not snapshot)
Queue: C3 fixes (running) → C4 fixes (DEFERRED until C3 frees runtime.py/api.py) → round 2 (C5–C9) → round 3 opt-in → close
Picker: C1,C2,C3,C4 all submitted; next picker = C5 (round 2)
In flight: C3 executors fix-ratelimit `4ddcfb69-52cb-4a1`, fix-apikey `54879751-cc06-4c6`, fix-queue `8e220992-b270-437`
Decided this turn, not yet written: none
Preamble file: current
Fix state: **C1+C2 landed+verified** (ruff clean, mypy --strict clean, pytest -q green 1 skip). 13 repaired tickets closed `--done --evidence reviewed-paths:… test:.venv/bin/python -m pytest -q`; 2 declined (`jzv1`,`wz8m`) `--wontfix`. C3 in flight. C4 accepted, dispatch deferred (file conflicts with C3). Tree dirty; snapshot `b145ad9`.
Owed residue (coverage caveat): private-mode `validate_ip` still ORs suffix-vs-CIDR (accepted HOW was the anchor fix; out of scope).
**Human margin note (binding):** CACHCORR (`kvbw`) — do NOT auto-recreate the corrupt cache; crash with a helpful reason + a directive to clear it manually. Overrides the row's "preserve the recreate path".
Decisions so far: C1 accept all 7; C2 accept 6 (REC note: add --reuse-root-key) / decline `jzv1`,`wz8m`; C3 accept all 6; C4 accept all 8 (CACHCORR note above).
Next: (1) land C3 → repo gates → close C3 tickets; (2) dispatch C4 with the CACHCORR note; (3) present C5
Detail lives in: registry (kata#1824) · this ledger · slice.md · reports/
