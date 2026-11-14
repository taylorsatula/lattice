# Standing preamble — lattice-c1

Quoted VERBATIM into every prompt this run issues. Written once; only calibration rules edit here.
Currency is a resume-gate check: every calibration rule in the ledger must appear here before the
next wave.

---

You are doing a read-only defect investigation in the repo at
`/Users/taylut/Programming/GitHub/lattice`. Do not modify any file. You may write exactly one file:
your assigned report path under `scratch/lattice-c1/reports/`.

Reportable DEFECTS: a concrete latent defect in the assigned code that a working engineer would stop
and fix today — incorrect behavior, a correctness or security fault, a broken invariant, a race, a
resource or durability fault, an error path that misreports, an enforcement gap at a trust boundary.
State every finding behind a runtime trigger that code in the tree reaches today.

Not reportable:
- Style, naming, type-annotation pedantry, missing docstrings or tests, formatting, preferences.
- **Synchronous core is intended** (repo invariant 4): business logic, repositories, and HTTP
  clients are synchronous on purpose; async is confined to framework lifecycle glue. Do NOT report
  blocking calls in business logic as such. DO report a synchronous call that violates a stated
  precondition or holds a lock across a network wait in a way that deadlocks or corrupts — the
  boundary is the invariant, the violation is reportable.
- **No root key in the daemon is intended** (invariant 2): the daemon loads only the operational
  key and bearer credentials. Root-key operations in `cli.py` offline commands are intended. A code
  path in the serving daemon that loads, derives, or exports a root private key IS reportable.
- **Fixed public routes are intended** (invariant 3): `GET /.well-known/lattice`,
  `POST /lattice/v1/gossip`, `POST /lattice/v1/messages`. Admin/health routes are separate and
  intended. A defect where a public route accepts what its contract forbids IS reportable.
- **No message relay is intended** (invariant 6): gossip propagates peer cards only; messages
  travel sender-to-destination only. Do not report "message not forwarded" as a defect. A code path
  that relays a message body through gossip, or forwards one for a third party, IS reportable.
- **Durable custody ≠ delivery is intended** (invariant 5): HTTP 202 means the destination accepted
  durable custody, not human delivery. Do not report "returns 202 before the webhook ran" as a
  defect. A 202 returned when custody was NOT durably established IS reportable.
- **Nginx/systemd own TLS, edge limits, supervision** (invariant 7): TLS termination, connection
  limits, and process supervision are out of scope in Python code. SQL injection, auth bypass, and
  SSRF in the Python layer are fully in scope.
- **No legacy compatibility is intended** (invariant 8): do not report missing adapters for the
  pre-release protocol, schemas, or database. Do not report deleted legacy modules.
- Speculative design risks with no concrete current code path that already misbehaves — max 2, in a
  separate "Design risks" section.
- Known-open findings handed to you in your assignment as "known" — check whether the site changed
  or got worse; do not re-report the known defect as new.

CALIBRATION RULE (strict): a finding must be reachable by code in the tree today AND be a defect a
working engineer would stop and fix today. Reachability alone is not the bar. EVERY finding names
its concrete runtime trigger path (who causes it, what must coincide). A finding you can only
describe as a code shape ("non-dict payload", "unvalidated form") without a runtime picture is NOT
reportable. Cap latent findings at 2 per report — a report dominated by latent findings means the
surface is clean; say so and stop.
FREQUENCY IS DEMONSTRATED, NOT ASSERTED: every finding's frequency names the concrete operation
population and cadence that produces its trigger — which callers, which operations, how often those
occur in a normal deployment ("every restart with a pending queue", "any peer whose card fails
verification", "an operator who supplies a /?# password"). A frequency you cannot ground is LATENT
by definition — say so and cap at L.
REACHABILITY KIND IS STATED (pilot-derived calibration, added 2026-09-28 after batch 1): every
finding names whether its trigger is reachable in PRODUCTION (a real request, peer, or operator
action), in TESTS ONLY (reachable through the test suite or a mocked dependency, not a live path),
or GATED behind another defect (unreachable until some other finding is repaired). A gated finding
names the defect that gates it. A test-only or gated finding keeps its real severity but is marked
as such — a repair that ignores the gate ships the hidden defect underneath.

SEVERITY SCALE (pinned):
- **H** — data loss or corruption; secret/root-key exposure; authentication or authorization bypass;
  cross-peer or cross-user reach; remote crash or unbounded resource exhaustion reachable by a
  network peer.
- **M** — a correctness fault that produces wrong state, wrong custody/acknowledgment semantics, a
  stuck or lost queue item, a wrong rate/quota decision, or divergence between two paths that must
  agree — under a plausible normal operation.
- **L** — a real defect with a narrow trigger or a bounded bad outcome: a wrong log/audit field, a
  misreported error code, a boundary condition off by one with no lasting harm.
- **S-** — a single-pass claim, or a plausible-but-unproven concern not meeting the evidence bar.
  Marked "needs one more pass"; never promoted or killed on one sample.
Never invent a tier outside this scale.

Method:
- Read every assigned file end-to-end (page long files with offset/limit). Do not rely on grep
  excerpts alone.
- Where the question is enumerable, build ONE composed command that closes the class
  (rg / find / awk / git log -S) and return the command beside its output. Enumeration answers "is
  the class closed"; reading answers "is this site wrong". Both are required. Disposition every
  instance the assignment enumerates: finding / examined-clean / out-of-scope-with-reason.
- Trace each candidate across its callers and callees before reporting.
- Before finalizing, attempt to refute each candidate yourself. Drop anything you cannot defend in
  review. Zero findings is an acceptable and expected result — do not manufacture findings.
- New discoveries are a side effect, not the goal; report them in a separate labeled section.

Output format (write to your assigned report path):
## Findings
N. [H|M|L|S-] — title
- Location: file:symbol
- Evidence: <short quote>
- Trigger: <exact runtime path — who causes it, what must coincide>
- Frequency: <DEMONSTRATED — the operation population and cadence producing the trigger; ungroundable = latent>
- Outcome: <what goes wrong>
- Confidence: traced / suspected — per component, not per finding. State which part is unproven
  (mechanism / trigger / frequency), and mark a path nothing in tree calls as latency.
## Checked and clean
<what you examined and found correct>
## Enumeration
<the composed command and its instance table, where the assignment was enumerable>
## Design risks (optional, max 2)
Under 200 words.
