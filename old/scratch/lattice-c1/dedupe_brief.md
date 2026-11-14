# Phase 5 dedupe brief — lattice-c1

Quoted into the `swarm-dedupe` agent prompt. The agent reads TERRAIN + EVIDENCE and writes kata
tickets. It never judges whether a finding is real; verification already did that.

## Corpus (inputs)

Read these **36 reports** and the verdict index. Do NOT read `reports/v-*.md` — their content is
summarized in the verdict index.

- `scratch/lattice-c1/reports/hunt-*.md`, `seam-*.md`, `q-*.md` — **23** hunter reports (the finding
  text: Location / Evidence / Trigger / Frequency / Outcome / Confidence). Read these end to end.
- `scratch/lattice-c1/reports/blind-*.md` — **13** blind third-pass reports. These contain the **41
  new findings** discovered by blind passes + their refutations of candidate sub-claims. Read these
  end to end; fold their findings in as their own entries.
- `scratch/lattice-c1/verify_verdicts.json` — machine index of all **92** verification passes.
  - `.primed{<finding-id>: {verdict, corrected_tier, refuted_subclaims, added_mechanisms,
    fix_constraints}}` — the authoritative verdict for every one of the 79 primed findings. Use it;
    do not re-derive. REFUTED → killed, no ticket (record in manifest). ADJUSTED → use the
    corrected tier + corrections. **Result: 41 CONFIRMED / 38 ADJUSTED / 0 REFUTED.**
  - `.blind[]` — the 13 blind passes' envelopes with their new findings.

## Merge rules (from bugfix-swarm Phase 5)

1. **One entry per defect:** same site (file:symbol) plus same mechanism is ONE entry, whatever the
   wording, whoever reported it, however many passes reached it. The convergence record carries the
   multiplicity (name each pass type); the entry does not.
2. **Same-site seam and local findings are NOT duplicates.** A seam finding's frame is the boundary
   contract, not either module. Carry edge-anchored provenance (boundary class + contract name +
   endpoint symbols). Keep them separate from area findings at the same symbols.
3. **Keep distinct defects at one site separate.** Two mechanisms in one function are two entries —
   merging them forfeits accepting one and declining the other.
4. **Apply the current calibration rules to every entry, including older-preamble entries.** Drop
   what a now-standing exclusion covers, and LIST the drop in the manifest. Current standing rules:
   the eight repo invariants (root key, sync core, fixed routes, no relay, custody≠delivery,
   nginx/systemd boundary, no legacy compat) and the REACHABILITY KIND rule.
5. **Carry per entry:** verifier-corrected severity and frequency; confidence per component
   (mechanism / trigger / frequency); latency marker (a path nothing in tree calls); provenance
   (external / verbatim-user / internal-model-authored / orchestrator-decided); any fix-direction
   constraint a verifier recorded.
6. **Publish a merge manifest** to `scratch/lattice-c1/merge_manifest.md`: every input entry with its
   disposition — kept (ticket ref), merged into `<ID>`, dropped by rule `<n>`, or novel. An
   over-merge is otherwise silent and a finding vanishing between reports and picker is unrecoverable.
7. **Carry verified-clean surfaces and census caveats** into the manifest (Phase 9 folds them into
   the coverage summary).
8. **Do NOT slice, rank, group, or recommend.** The ticket corpus is merged evidence; grouping is the
   orchestrator's job (Phase 6).

## Orchestrator-decided inputs (enter as their own entries, labeled orchestrator-decided)

- **OV-1** — `_LockedConnection` RLock does not cover the implicit `with conn:` commit (CPython
  3.12 bypasses the overrides). CONFIRMED by direct execution.
- **OV-2** — every `OutboundTransport.request()` raises `TypeError` on `fields=` before network I/O
  (urllib3 2.7.0). CONFIRMED by direct execution. Highest-consequence finding of the run.

## Kata commands

Run from the workspace. One ticket per merged defect:

```
kata create "<title>" --body-file <tmpfile> --label lattice-c1 --label tier:<h|m|l> --json
```

- tier label from the VERIFIER-CORRECTED severity (H/M/L). S- entries are NOT given tickets — they
  go in the manifest as "needs one more pass".
- body carries: verifier-corrected severity + frequency, confidence per component, latency marker,
  provenance, convergence record (passes and types), any fix-direction constraint.
- `--json` returns the short id; record it in the manifest beside each kept entry.
- Do NOT slice, do NOT close, do NOT edit other tickets. Do NOT create the run-level ticket
  (already exists: kata#1824).

Return ONE line: the run label and the count of tickets created.
