# Full census wave plan — lattice-c1 (draft; finalize after pilot calibration)

Pilot = hunt-b1a/b1c (runtime.py, 3 mechanisms). Full wave reuses pilot findings and adds the
remaining instruments. Counts below are areas, not budgets. Seam and question scopes are separate
instruments.

## Hunters (Phase 3)

| pass-id | instrument | files / contract / command | disposition target |
|---|---|---|---|
| hunt-a1 | area | `lattice/api.py` end-to-end | E4 error-path map |
| hunt-a2 | area | `lattice/cli.py` end-to-end | E3 env/open sites |
| hunt-c1 | area | `lattice/storage/repositories.py`, `migrations.py`, `lattice/migrations/**` | E5, E6 |
| hunt-c2 | area | `lattice/storage/cache.py`, `connection.py` | E5 transaction boundary |
| hunt-d1 | area | `lattice/transport.py`, `network_policy.py` | SSRF, resolved-IP validation |
| hunt-d2 | area | `lattice/credentials.py`, `config.py` | credential schema, root-key absence |
| hunt-e1 | area | `lattice/identity.py`, `crypto.py` | key lifecycle, rotation, recovery |
| hunt-e2 | area | `lattice/canonical.py`, `encoding.py`, `protocol/{signing,models,constants}.py` | JCS, strict parse, preimage |
| hunt-f1 | area | `lattice/gossip.py` | E4 per-card loop, batch bounds |
| hunt-f2 | area | `lattice/topology.py`, `peers.py` | candidate/quota/prefix arithmetic |
| hunt-g1 | area | `lattice/resolution.py`, `addressing.py` | parse, pin transfer/reset |
| hunt-h1 | area | `lattice/messages.py` | expiry, erasure, validation |
| hunt-h2 | area | `lattice/webhook.py` | idempotency, retry class, envelope |
| hunt-i1 | area | `lattice/rate_limit.py` (if not fully covered by hunt-b1c, residual) | bucket arithmetic |
| hunt-k1 | area | `deploy/**`, `pyproject.toml`, `tests/test_deployment.py`, `tests/test_wheel.py` | documented-vs-actual install |
| seam-s1 | seam | `api.py` handlers ↔ `runtime` coordinator methods + exception map | contract check: raised vs handled |
| seam-s2 | seam | `transport.FederationResponse.resolved_ip` ↔ `topology.prefix_from_ip` / candidate intake | contract check: validated IP semantics |
| seam-s3 | seam | `repositories` return shapes / transaction boundaries ↔ `runtime` caller expectations, claim/lease semantics | contract check: claim + custody pair |
| seam-s4 | seam | `protocol/signing.verify_*` + `canonical.signature_preimage` ↔ `identity.sign/verify_object` call sites | contract check: kind/preimage/media-type agreement |
| q-error | question | composed enumeration: every `except` → what it logs/returns vs what the caller reports | misreported error class closure |
| q-contract | question | `diff` documented route/schema/field set (PROTOCOL.md, THREAT_MODEL.md, ADDRESSING.md) vs code constants and parsers | contract-drift class closure |

## Verification (Phase 4, Standard tier)

- Primed verifier on every finding (hunter → `swarm-verifier`, claim + files).
- Blind third pass on every H survivor whose repair shape depends on the frame.
- Adjudicator on every verifier/hunter disagreement; orchestrator self-verification for
  arithmetic/30-line disputes.
- No refutation recheck (Standard tier).

## Dedupe / slice / fix

- Phase 5: one `swarm-dedupe` over `reports/*.md` → kata tickets (`--label lattice-c1
  --label tier:<h|m|l>`) + `merge_manifest.md`. Measure corpus first; two-level only if large.
- Phase 6: slice by defect class and round (round 1 egregious/security/data-loss; round 2
  consistency; round 3 polish opt-in).
- Phase 8: one `swarm-executor` per file; seam repairs both sides in one prompt; no commits unless
  the human asks; map edits by orchestrator after each fix wave.

## Open question for calibration after pilot

- Does the preamble's doctrine-exclusion set hold on runtime.py (high intentional-pattern density),
  or does it leak design-as-bug noise? If it leaks, fix the preamble before the full wave.
