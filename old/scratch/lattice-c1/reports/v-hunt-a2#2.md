# v-hunt-a2#2 — PRIMED VERIFIER

Claim under test: **hunt-a2#2** in `scratch/lattice-c1/reports/hunt-a2.md`, reported tier **L** —
"`keys rotate-operational` performs all destructive writes before validating the config".

Frame re-derived from source before checking the claim: `lattice/cli.py:cmd_keys_rotate_operational`
(lines 734–831), `lattice/config.py:load_config` / `Config.__init__`, `lattice/cli.py:cmd_serve`
(636–731) and the runtime paths that consume `identity.json` / `well-known.json`
(`gossip.build_own_card`, `runtime.verify_gossip_sender_card`, `runtime.verify_inbound_message` →
`_certificate_for_node`, `topology._verify_against_well_known`), `storage/repositories.py:DomainPinRepository`,
`identity.verify_rotation`, `docs/KEY_MANAGEMENT.md`, `docs/PROTOCOL.md` §5.1.

## Findings

1. [L] — Verdict: CONFIRMED. `keys rotate-operational` commits the key + identity manifest before
   the only config validation, so a `ConfigError` leaves the served well-known document inconsistent
   with the node's key and certificate.
- Location: `lattice/cli.py:cmd_keys_rotate_operational`, write sequence 791 → 795 → 800, validation
  at 804, well-known write at 823.
- Evidence: `op_key_path.write_bytes(...)` (791) → `rotation_path.write_text(...)` (795) →
  `manifest_path.write_text(...)` (800) → `config = load_config(config_path)` (804) →
  `print(f"CONFIG INVALID: {exc}")` / `return 1` (806–807). `well_known_path.write_text(...)` is
  reachable only after 804 succeeds.
- Trigger: PRODUCTION. Operator runs `lattice keys rotate-operational --config …` while
  `config.toml` fails `load_config` (a pending edit, a bad TOML edit, or a config produced by the
  `init` defect in hunt-a2#3). The command prompts for the root password, overwrites
  `operational_key.pem` with the new key, rewrites `rotation.json`, rewrites `identity.json` with
  the new certificate, then aborts at 806 leaving `well-known.json` untouched (old certificate).
- Frequency: LATENT — the trigger is the coincidence of `config.toml` being invalid at the moment of
  a rotation. A node that is running had a valid config at its last `serve` (cmd_serve validates at
  644), so the invalid state can only be introduced by a post-start edit the operator has not
  validated; rotation itself is a routine monthly operation (30-day certificate lifetime,
  cli.py:770). The two states are independent. Per the calibration rule the un-grounded frequency
  caps this finding at L. The hunter's own "requires a coincidence" wording is retained.
- Outcome (re-derived, each half checked):
  - mechanism: TRUE — validation is the first statement after all three destructive writes.
  - `identity.json` + `operational_key.pem` = new cert/key, `well-known.json` = old cert: TRUE
    (`well-known.json` is written only at 823; `cmd_serve` loads it verbatim at 660 and hands it to
    `RuntimeCoordinator` as `well_known_document`).
  - consequence: TRUE and slightly stronger than the claim states. A peer that resolves the node's
    domain fetches the stale well-known and pins the old `operational_certificate`
    (`resolution.WellKnownResolver.pin` → `DomainPinRepository.upsert`). Two consumers then reject
    the node:
    (a) `runtime.verify_inbound_message` → `_certificate_for_node` returns the pinned old cert and
        `verify_message` fails → the node's outbound messages are rejected;
    (b) `topology._verify_against_well_known` (lines 285–350) verifies the card signature against the
        **well-known's** cert, not the card's embedded cert, so the node's peer cards fail candidate
        verification and the node cannot become a VERIFIED/established peer at all.
    (Gossip batch acceptance uses `runtime.verify_gossip_sender_card`, which is self-consistent
    against the card's own cert, so the node is not wholly invisible — the claim does not assert
    otherwise.)
- Confidence: traced. Mechanism, ordering, and both rejection consumers followed to the decisive
  calls. The only unproven component is frequency, which is why it is capped at L, not M.
- Severity: retained at **L** (corrected_tier L). In isolation the impact is M by the scale
  ("divergence between two paths that must agree": `identity.json`/key vs. a served well-known whose
  lineage is broken, and the node cannot be peer-verified). Retained at L because the frequency is an
  un-grounded coincidence; the calibration rule caps it. If a later pass grounds the config-invalid
  trigger as routine, promote to M.
- Reachability kind: PRODUCTION (operator CLI invocation).

## Sub-claims refuted

- **"`cmd_serve` is the only other reader"** (frequency rationale) — REFUTED as stated. `load_config`
  is also called by `cmd_config_check` (cli.py:212), `cmd_status` (256), and
  `cmd_trust_reset_domain` (422). `lattice config check` is an explicit validator the operator can
  run, so a broken config need not "sit unnoticed until this command half-executes." This weakens the
  frequency argument but does not touch the mechanism.
- **Re-run recovery detail** ("produces a `rotation.json` whose `old_signature` is by a key that was
  never publicly certified") — mechanism CONFIRMED (`old_op_key` is loaded from the already-overwritten
  `operational_key.pem` at 758), but the implied impact is REFUTED as inert: `verify_rotation`
  (identity.py:208) has **no production caller** (`rg 'verify_rotation' lattice/` returns only its
  definition) and `rotation.json` is written only at cli.py:795 and read nowhere in-tree
  (`rg 'rotation.json' lattice/`). The statement is documented as a durable audit artifact
  (docs/KEY_MANAGEMENT.md:54). A cosmetically wrong audit artifact is not an operational fault.

## Additional mechanisms / earlier failure sites / new reachability

- **Broader trigger class than the claim states (non-atomic commit).** The divergence does not require
  an invalid config. `identity.json` (800) and `well-known.json` (823) are separate non-atomic writes;
  a SIGKILL, OOM, host reboot, or a write failure between them (or the `chmod`/`sign_with_root` between
  them) leaves the same new-identity / old-well-known state. The claim's config-error path is the
  more likely of an already-narrow class, but it is not the only one. This is why atomicity, not only
  pre-validation, is the repair constraint.
- **Protocol invariant violated.** docs/PROTOCOL.md §5.1 states the well-known "MUST regenerate when
  the operational certificate … change[s]." After abort, the daemon serves a well-known whose
  `operational_certificate` (sequence N) disagrees with `identity.json` (sequence N+1), and no
  startup check reconciles them (`cmd_serve` 644–687 checks only `cert.node_id == manifest["node_id"]`).
- **Node cannot be peer-verified**, not merely message-rejected — see Outcome (b). This is a
  stronger outcome than the finding's "cannot verify the node's signatures" and belongs in the repair
  scope.

## Fix-direction constraints

- Move `load_config` to the top of `cmd_keys_rotate_operational`, before any destructive write, so an
  invalid config aborts with zero mutation. This is necessary but **not sufficient**.
- Make the identity update crash-safe as a unit: the four artifacts (`operational_key.pem`,
  `rotation.json`, `identity.json`, `well-known.json`) must not be observable in a mixed generation.
  Write each to a temp file and `os.replace` atomically, or regenerate the well-known from the same
  validated config before committing `identity.json`, so no interruption leaves cert/key/well-known
  divergent. A repair that only adds pre-validation still ships the crash window in
  "Additional mechanisms."
- Do not rely on the operator re-running rotate as recovery: recovery is only guaranteed if the
  operator re-runs the whole command; a plain `serve` after the abort serves the stale well-known
  indefinitely. Consider an optional startup consistency check (well-known cert lineage ==
  `identity.json` cert) that refuses to serve with a clear message.

## Checked and clean

- Write order and line numbers 791/795/800/804/806/823/826 verified by direct read of the function
  body (`awk 'NR>=734 && NR<=840'`).
- `cmd_serve` loads `well-known.json` verbatim (cli.py:660) and passes it as `well_known_document`;
  it never regenerates or cross-checks it against the manifest cert — so the stale file is what is
  served. Verified in `cmd_serve` and `RuntimeCoordinator.__init__` (runtime.py:169–183).
- `DomainPinRepository.upsert` stores `operational_certificate`; `runtime._certificate_for_node`
  returns the pinned cert; `topology._verify_against_well_known` verifies the card against the
  well-known's cert. Both rejection paths traced to their decisive calls.
- The claim's stated write order and its "config-error path is the only non-environmental failure
  between the first write and completion" are accurate: `ConfigError` is the one deterministic
  non-environmental abort between 791 and 823.
- Consistent with the rest of hunt-a2's "checked and clean" for this function's neighbours (root-key
  confinement, password-gated root load at 761); not re-litigated.

## Design risks

None raised in this pass beyond the non-atomic-commit risk already folded into finding 1's mechanics.

## Bound

- Did not execute `lattice` against a live systemd host; the config-invalid/rotation coincidence is
  reasoned from the code and docs, not observed.
- `CREDENTIALS_DIRECTORY` / systemd credential behaviour and `crypto.save_private_key` /
  `load_private_key` formats are out of reach in this pass; no assumption about them is load-bearing
  for this verdict.
- Did not run the test suite; tests/test_cli.py:685 and tests/test_resilience.py:50 exercise the
  happy path only and do not cover the ordering defect.
- The topology-rejection consequence (Outcome (b)) is traced through source, not observed between two
  live nodes.
