# Phase 8 executor prompt template — lattice-c1

Terse-brief shape (executors die on long investigations + long outputs). One `swarm-executor` per
file; files disjoint across agents. Seam repairs: both sides of the boundary in ONE executor's
prompt. No commits. Never edit orientation maps (orchestrator does that).

## Template

```
Repair ONE accepted, verified defect in `/Users/taylut/Programming/GitHub/lattice`. Do not
re-litigate it, widen it, or reconsider whether it is real.

FILES YOU MAY WRITE — exactly these, and within them only the named functions:
- <file>: <function(s)>
Everything else is out of scope. Do not touch any other file or function. Do not commit. Do not
edit any AGENTS.md or docs file.

THE DEFECT (verified; row <ID>):
- Location: <file:symbol>
- Mechanism: <one-line operational description>
- Trigger: <who causes it, what must coincide>
- Evidence: <the verifying pass's decisive quote/trace>

HOW (bind your approach to exactly this): <the picker row's HOW, verbatim>
WHY (the property this restores): <the picker row's WHY, verbatim>
Verifier fix-constraint: <any constraint a verifier recorded, or "none">

SIBLING PATTERN TO MIRROR (the repo's own idiom):
- <exemplar file:symbol from the orientation map> — follow this pattern; do not invent a new one.

METHOD (read narrowly; do not read whole large files):
- grep first for the named function, then read only its region (<=120 lines).
- Make the smallest correct change that resolves the trigger.
- Same-hazard extension inside the named function is allowed; anything outside is not.

VERIFY BY RUNNING, NOT BY ASSERTING:
- Exercise the changed path with hostile input (the trigger's input class) and show the result.
- No mocks, no test files, no simulation. Use the repo venv (`.venv/bin/python`).
- Report EXECUTED (with the exact command and observed output) or UNVERIFIED (name the probe that
  would cover it and what blocked it).

STOP AND REPORT at your boundary instead of improvising. If the assignment is ambiguous or a
required edit is outside the named function, stop and report — do not guess.

Final message: <=5 lines. `Status: EXECUTED|UNVERIFIED | file:function changed | probe command |
observed result | anything owed`. No narrated investigation. Keep the report under 40 lines.
```

## Per-bucket notes

- Group rows by FILE, not tier. One executor per file.
- A fix agent editing a file a running verifier is reading: confine to the named functions; record
  the overlap in the ledger (verdicts on other functions stay valid).
- After each fix wave lands: read every diff; revert anything outside the out-of-scope list; then
  the orchestrator edits orientation maps for changed files before any commit.
