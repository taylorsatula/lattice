# Verification plan & pass templates — lattice-c1 (Standard tier)

Phase 4. Not a formality before a picker: kill hallucinated findings, catch what hunters missed.
Every pass writes `reports/<pass-id>.md` and returns only an envelope. Uses `swarm-verifier`.

## What runs (Standard tier)

1. **Primed verifier on EVERY finding.** pass-id `v-<sourcePass>-<n>`. Reads the source report
   (`reports/<sourcePass>.md`), the claim, and the traced files. Verifies inside the claim's frame
   but re-derives the frame from source before checking details.
2. **Blind third pass on every H survivor whose repair shape depends on the frame.** pass-id
   `blind-<sourcePass>-<n>`. Gets the files + a neutral question; the target is withheld.
3. **Adjudicator on every disagreement** (`adj-<topic>`): both accounts, no verdicts; demand the
   mechanism.
4. **Orchestrator self-verification** for enumeration-decidable claims and narrow disputes
   (arithmetic / ≤30-line read): recorded as an annotation on the run-level ticket, labeled
   orchestrator-decided; enters the corpus as input.
5. **Coverage diff**: after hunts, diff files traced by all passes against the tree; files nothing
   traced get one residual pass each. Un-dispositioned enumeration instances are a coverage hole.

No refutation recheck (Standard tier).

## Convergence bar

Two passes agreeing, at least one not sharing the claim's frame. Single-pass claims → **S-**
candidates marked "needs one more pass" — not promoted, not killed. Independent convergence (two
hunters, different assignments, same defect) counts as two frame-independent samples — record
skip-verified with both IDs. A seam finding is frame-disjoint from any area finding at its
endpoints, so cross-channel agreement on a seam mechanism satisfies the bar.

## Primed verifier prompt template

```
Read-only verification in `/Users/taylut/Programming/GitHub/lattice`. Do not modify any file.
You may write exactly one file: `scratch/lattice-c1/reports/<pass-id>.md`.
Pass type: PRIMED VERIFIER. Stance adversarial and symmetric — do not assume the claim is correct,
do not assume it is incorrect. Two failures are equally fatal: sycophantic confirmation (checking
inside the claim's frame and inheriting its errors) and reflexive refutation (killing a real
finding to look rigorous).

<STANDING PREAMBLE VERBATIM>

CLAIM UNDER TEST (from report `reports/<sourcePass>.md`, finding <n>):
<the claim's Location / Evidence / Trigger / Frequency / Outcome / Confidence, verbatim>

Method:
- FIRST re-derive the claim's frame from source — what rows the query returns, what the caller
  passes, what the constant holds. Do not begin from the claim's phrasing.
- Trace the named runtime path to its actual failure site. Confirm or refute each component:
  mechanism / trigger / frequency. A finding is often half right — name the refuted half.
- Apply the severity scale; correct severity and frequency with the trace that produced it.
- Record additional mechanisms, earlier failure sites, new reachability paths, and fix-direction
  constraints on the same trace.
- Record what you could not reach as a boundary, not silence.

Output (write to the report path):
## Verdict
CONFIRMED | REFUTED | ADJUSTED
## Components
- Mechanism: confirmed/refuted + trace
- Trigger: confirmed/refuted + trace (who causes it, what must coincide)
- Frequency: corrected + the operation population/cadence, or LATENT
## Corrections
- Severity (final tier + why)
- Refuted sub-claims
- Added mechanisms / earlier failure sites / new reachability
- Fix-direction constraints (what a repair must account for beyond the symptom)
## Unreachable boundary
<what this pass could not check>
```

## Blind third-pass prompt template

Same as primed but: withhold the claim entirely; give the files and the neutral question the hunter
was given; the output contract is the full hunter schema. Use wherever the repair's shape depends on
the frame — a blind pass routinely returns more than it was asked to check.

## Envelope returned by every verification pass

`pass-id | report path | verdict (CONFIRMED/REFUTED/ADJUSTED) | corrected tier | refuted sub-claims | added mechanisms | fix-direction constraints | unreachable boundary`
