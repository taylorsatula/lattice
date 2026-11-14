# v-q-contract#2 — verification of finding q-contract#2

Claim under test (from `scratch/lattice-c1/reports/q-contract.md`, finding 2, tier M):
"Documented recovery procedure `lattice init --force` destroys the root key it is supposed to
preserve."

**Verdict: CONFIRMED.** Corrected tier: **M** (unchanged). Reachability kind: **PRODUCTION**
(operator action, no gate, no test coverage — see Enumeration ENUM C).

## Frame re-derived from source (before reading the claim's wording)

- `docs/KEY_MANAGEMENT.md` §Backup and recovery lines 82–92: backup root key offline; on a
  replacement host (1) copy the encrypted root key to `/etc/lattice/root_key.pem`, (2) run
  `lattice init --force` "to generate a new operational key and config", (3) re-encrypt creds.
  The stated purpose is identity recovery.
- `docs/THREAT_MODEL.md` §1 (line 9) lists the root private key's protection goal as
  **"Confidentiality, integrity, availability (recovery)."** §Compromised-root (line 48) says a new
  node identity is required *only* for irrecoverable compromise. §8 (line 108): "Back up the
  recovery bundle offline and test restoration." The doc set treats root-key restoration as a
  supported property.
- `lattice/cli.py:cmd_init` (93–206): `root_key = generate_private_key()` (line 103) — unconditional,
  no branch that inspects an existing `root_key.pem`; `save_root_key(root_key, root_key_path,
  password)` (line 127) — unconditional overwrite. It also writes a fresh `identity.json`,
  `well-known.json`, `config.toml`, `operational_key.pem`, and both bearers.
- `lattice/credentials.py:save_root_key` (75–86): `path.write_bytes(data)` with no existence check.
- `lattice/credentials.py:load_root_key` (88–101): the only reader of an existing root key, used by
  `keys rotate-operational` (cli.py:470), `keys create-transfer` (cli.py:519), and
  `trust accept-transfer` (cli.py:761). `cmd_init` never calls it (Enumeration ENUM A closes the
  class: `cmd_init` is the sole `save_root_key` caller; every other root-key consumer loads).

The documented recovery therefore instructs the operator to place a root key and then runs the one
command in the CLI that regenerates and overwrites it. Nothing reuses it.

## Empirical demonstration (repo venv, temp dir; no repo files touched)

```
old_node = lat_hkkehbf76oebmenb3blaqcufarvbenbz5vy244x5jvgl76hedohq
$ lattice init --domain example.com --public-base-url https://example.com --force
new_node = lat_ecfryqutmea4odm4imb3nsjnzmlsekubreiuqzieo5kgrq5h2guq
root_key.pem overwritten: True
manifest node == new_node: True
```

Pre-existing `root_key.pem` (encrypted under the operator's backup passphrase `old-pass`) was
replaced by a new file encrypted under the passphrase entered at init time; the on-host node id
changed and `identity.json`/`well-known.json` describe the new identity, so the daemon starts
self-consistently as a *different* node with rc 0 and no warning.

## Component adjudication

- **Mechanism — CONFIRMED.** `cmd_init` has no "reuse an existing root key" branch; the overwrite
  is unconditional (cli.py:103/127; `save_root_key` writes unconditionally). Not a claim frame
  artifact — re-derived from the two source sites, and demonstrated.
- **Trigger — CONFIRMED, with one refinement.** The operator action is exactly the documented
  procedure; it needs no adversary and no coincidence. Refinement: the destructiveness does **not
  depend on `--force`**. Plain `init` on a host with a `root_key.pem` but no `config.toml` (a
  partially-restored host) overwrites the same way; `--force` only governs the config-existence
  guard (cli.py:95–96). The claim's title names `--force` as the hazard, which is slightly
  narrower than the code.
- **Frequency — CONFIRMED as stated.** Grounded population: every operator executing the
  documented replacement-host recovery. Cadence is rare, but the doc itself names the exact
  command, so the trigger is not merely latent. This is a demonstrated-population / rare-cadence
  finding, not an asserted one.
- **Outcome — CONFIRMED.** The restored identity is silently replaced; peers holding a pin for the
  domain (old `node_id`) now see a different node and fail closed, and any operator who deletes the
  offline backup after believing recovery succeeded has permanently lost the identity. Membership
  in the node's own trust graph is not re-established. The claim's outcome paragraph is accurate.

## Severity correction

**Unchanged at M.** Trace: the tiering anchors are (a) the scale's M clause "divergence between two
paths that must agree" — here the documented recovery path and the implemented `cmd_init` path —
and "produces wrong state under a plausible normal operation"; (b) THREAT_MODEL §1 names root-key
availability as a protection goal, so violating it is not cosmetic. It is not H: no secret is
*exposed*, and the backup copy survives, so the key material is recoverable — the harm is the
silently wrong identity and dead pins, not irreversible loss. It is more than L: the outcome is not
a bounded "wrong log field / misreported code"; the node comes up as the wrong identity. The point
is defensibly on the M/L boundary because the trigger is rare and the operator still holds the
offline backup; I leave M because the M clause fits the mechanism exactly.

## Refuted sub-claims

- `"--force"` as the specific hazard: **partially refuted**. The root-key overwrite is
  unconditional in `cmd_init`; `--force` only bypasses the config-existence guard. Plain `init`
  destroys a restored root key just as silently.
- Otherwise no sub-claim is refuted. The mechanism, trigger, frequency, and outcome as written all
  hold.

## Additional mechanisms / earlier failure sites / new reachability (same trace)

1. **The recovery is unimplementable with the current CLI, not merely misordered.** Re-copying
   `root_key.pem` after init leaves `identity.json`/`well-known.json` describing the new identity.
   The only command that re-signs from an on-disk root key, `keys rotate-operational`
   (cli.py:734–815), reads `manifest["node_id"]` and `manifest["root_public_key"]` (new identity)
   while signing the new certificate with the loaded root key — `create_operational_certificate`
   (identity.py:240) derives `cert.node_id` from *that* root key, so the regenerated well-known
   would carry the new `node_id` alongside a certificate deriving from the restored root. There is
   no CLI path that rewrites `identity.json`/`well-known.json` from a restored root key.
2. **Passphrase divergence.** `cmd_init` prompts for a new passphrase; the on-host
   `root_key.pem` is re-encrypted under it. The operator's backup passphrase no longer decrypts the
   on-host file (demonstrated: `old-pass` file replaced by a `new-pass` file). No code surfaces
   this; the init output prints the new node id but does not flag that a root key was replaced.
3. **Earlier site: none.** Step 1 (copy) is an operator action with no code; `cmd_init` is the
   first code site on the trace. No new network reachability: this is an offline CLI path, and
   CONFIRMED it does not touch the daemon (invariant 2 unaffected).

## Fix-direction constraints

- A code-side fix must make `cmd_init` **load and reuse an existing `root_key.pem`** (prompting for
  its passphrase) and derive `node_id`, `identity.json`, `well-known.json`, and the operational
  certificate from that key. Merely skipping the overwrite is insufficient: the manifest and
  well-known written by the same function would still describe a freshly generated root.
  `--force` must be scoped to config/operational/bearer overwrite, or an explicit
  `--reuse-root-key` / `--recover` path added.
- A doc-side fix must not just reorder the three steps: with today's CLI, placing the root key
  after init still leaves the manifest/well-known inconsistent (constraint 1 above). The doc must
  name a code path that re-derives the identity from the restored root key, which does not exist
  today.
- Either fix MUST preserve: root-key confidentiality and the invariant-2 boundary (no daemon path
  loads the root key), and the fail-closed behavior of `trust accept-transfer`.
- A test should pin the contract (init over an existing root key must preserve `node_id`); none
  exists today (ENUM C).

## Checked and clean

- Enumeration ENUM A closes the root-key save/load class: `cmd_init` is the only writer; all three
  other consumers (`rotate-operational`, `create-transfer`, `co-sign-transfer`/`accept-transfer`)
  load the existing key. The bug is localized to `cmd_init`.
- `cmd_keys_rotate_operational` correctly reuses the on-disk root key and increments the certificate
  sequence (cli.py:761–770) — the operational-rotation procedure in KEY_MANAGEMENT.md is NOT
  affected by this defect.
- The "Root key compromise" section's instruction ("Generate a new root identity with `lattice
  init`", cli.py interface) is consistent with `cmd_init` generating a fresh root key; the
  contradiction is confined to the recovery section.
- `save_root_key`/`load_root_key` round-trip and mode 600 are correct; the confidentiality of the
  new file is intact.
- `lattice init` writes exactly the files `docs/LATTICE_SYSTEMD.md`/`KEY_MANAGEMENT.md` list with
  the modes claimed (previously verified by hunt-k1; re-confirmed here)

## Enumeration

ENUM A — root-key writers/readers in the CLI:
```
rg -n "save_root_key|load_root_key|generate_private_key\(\)" lattice/cli.py
```
| Site | Disposition |
|---|---|
| cli.py:103 `root_key = generate_private_key()` | `cmd_init` — regenerates unconditionally = defect |
| cli.py:127 `save_root_key(...)` | `cmd_init` — unconditional overwrite = defect |
| cli.py:470 `load_root_key(...)` | `keys rotate-operational` — reuses existing (clean) |
| cli.py:519 `load_root_key(...)` | `keys create-transfer` — reuses existing (clean) |
| cli.py:761 `load_root_key(...)` | `trust accept-transfer` — reuses existing (clean) |

ENUM B — every `init` mention in docs:
```
rg -n "lattice init|init --force" docs/
```
`KEY_MANAGEMENT.md:89` is the only `init --force` and the only recovery usage; `KEY_MANAGEMENT.md:98`
(compromise → new identity) is consistent with the code; `THREAT_MODEL.md:20`,
`LATTICE_SYSTEMD.md:26/29/161` are first-install usage. One instance dispositioned:

| Instance | Disposition |
|---|---|
| KEY_MANAGEMENT.md:89 recovery | FINDING (this) |
| KEY_MANAGEMENT.md:98 new identity | examined-clean (consistent with code) |
| others (install) | examined-clean |

ENUM C — recovery/restore command:
```
rg -n "add_parser\(" lattice/cli.py
```
No `recover`/`restore`/`reuse-root-key` subcommand exists. `init` is the only command reachable from
the documented recovery, and no test exercises `init --force` over a pre-existing `root_key.pem`
(`tests/test_cli.py` covers only create, refuse-without-force, and config/status/upgrade flows).

## Design risks (1)

A recovery procedure that depends on a flag (`--force`) whose help text is "overwrite existing
configuration" invites the operator to assume the root key is configuration. Any reproduction of
this class (a command documented for recovery that does not distinguish key material from
config) recurs silently on each doc edit; a conformance test binding the recovery steps to the CLI
would close it. (Not a code path that misbehaves today beyond the finding above.)

## Adjudication note (conflict with a prior pass)

`hunt-e1.md` §Checked-and-clean, "Recovery handling", states: "docs (KEY_MANAGEMENT.md) define
recovery as root-key backup + `init --force`, out of code scope. Nothing to defect." That
disposition accepted the document's frame without checking whether `cmd_init` preserves the
restored key — the exact failure mode this verification guards against. The source trace above
shows the doc describes a procedure the code cannot perform; `hunt-e1`'s clean line is incorrect at
this site, and q-contract#2 is not a re-report of any hunt-e1 finding.

## Bound

- No live `/etc/lattice` host or systemd unit was exercised; the demonstration used a temp dir with
  the real `cmd_init`. Systemd credential interaction was not needed — the defect is in `cmd_init`
  before any credential staging.
- The operator's exact real-world intent (whether they would `--force` on a fresh vs. existing host)
  is not observable; I tested the documented command verbatim. If an operator skips step 1 and only
  runs `init`, no recovery was attempted anyway.
- Recoverability after the overwrite assumes the operator's offline backup is intact; whether
  operators actually retain it is not verifiable in the tree.
