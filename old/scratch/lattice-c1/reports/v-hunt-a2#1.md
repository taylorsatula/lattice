# v-hunt-a2#1 — PRIMED VERIFIER

Claim under test: **hunt-a2#1** (report `scratch/lattice-c1/reports/hunt-a2.md`), reported tier **M** —
"Daemon starts and runs with an operational key that does not match its certificate."

Re-derived the frame from source before checking the claim: what `cmd_serve` loads, from where,
what `OperationalIdentity` holds, what peers verify, and whether any code path enforces
key↔certificate correspondence.

## Verdict: ADJUSTED

Mechanism, trigger, and outcome are all traceable and confirmed as written. The severity and the
stated frequency are corrected downward. One named consequence (durable-custody receipts) is
refuted as an effect.

## Frame re-derivation (independent of the claim)

- `cmd_serve` (cli.py:638-731) loads `op_key = load_operational_key(path=_credential_path("operational_key", config_dir))`
  (cli.py:664), then `cert = OperationalCertificate.from_dict(manifest["operational_certificate"])`
  (cli.py:672), then checks only `if cert.node_id != manifest["node_id"]` (cli.py:673), then builds
  `OperationalIdentity(node_id=cert.node_id, private_key=op_key, certificate=cert)` (cli.py:676).
- `_credential_path` (cli.py:626-637) returns `$CREDENTIALS_DIRECTORY/<name>` when the env var is
  set, else the config-dir staging file `name{,.pem,.txt}`. In the systemd unit
  (`deploy/lattice.service:22`) `LoadCredentialEncrypted=operational_key:/etc/lattice/operational_key.cred`
  makes systemd set `CREDENTIALS_DIRECTORY`, so precedence is the credential-dir copy.
- `keys rotate-operational` (cli.py:734-831) overwrites the staging file
  `config_dir/operational_key.pem` with the NEW key (cli.py:791), rewrites `identity.json` with the
  NEW certificate (cli.py:800), rewrites `well-known.json` (cli.py:823), and prints only
  `"...staged at: (encrypt with systemd-creds)"` (cli.py:829) — re-encryption of the `.cred` is left
  to the operator (docs/LATTICE_SYSTEMD.md, "Rotate the operational key": re-encrypt → rm → restart).
- No code anywhere compares the loaded private key to the certificate. Confirmed by enumeration below.

So the claim's frame is accurate. The credential-dir copy is stale until the operator re-encrypts,
while `identity.json`/`well-known.json` are already new.

## Sub-claim resolution

1. **Mechanism — CONFIRMED.** No correspondence check exists at startup or in `_load_local_identity`
   (cli.py:275-283, same shape). Enumeration: `rg -n "public_key\(\)" lattice/` returns only
   `identity.py:158` (`OperationalIdentity.public_key` property) plus certificate-construction sites
   (cli.py:106/112/148/167, identity.py:253, cli.py:767/778/779); no comparison. `rg -n "public_key\(\)\s*==" lattice/` → empty.

2. **Trigger — CONFIRMED, production-reachable, coincidence-gated.** A daemon restart while the
   `.cred` still holds the pre-rotation key: manual restart, crash (`Restart=on-failure`,
   `deploy/lattice.service:30`), or host reboot inside the window between `keys rotate-operational`
   completing and the operator's `systemd-creds encrypt` step. The window is real and is created by
   the documented procedure (re-encryption is a separate manual step, cli.py:829). A pure
   `contacts export` path (cli.py:275) reaches the same mismatch without a restart.

3. **Frequency — CORRECTED to LATENT.** The report labels it "DEMONSTRATED — every daemon restart
   that lands between a periodic rotation and the manual re-encrypt step." That is tautological: it
   names the condition as the population. The population that actually produces the trigger is
   *unplanned daemon restarts* (crash, reboot, manual) crossed with the *minutes-long manual window*
   between a monthly rotation and the operator's re-encryption. The joint cadence cannot be grounded
   from the tree; whether a restart lands in the window is an operator coincidence. A faithful
   ordering (rotate → re-encrypt → rm → restart), as documented, never produces the mismatch. So the
   frequency is coincidence-dependent, not demonstrated.

4. **Outcome — CONFIRMED but one named consequence REFUTED, and it is broader than reported.**
   - Confirmed: the daemon embeds the NEW cert (`gossip.build_own_card`, gossip.py:210
     `"operational_certificate": self._identity.certificate.to_dict()`) and signs with the OLD key.
   - Confirmed: peers' `verify_gossip_sender_card` (runtime.py:536-568) does
     `cert.verify(root_identity)` then `verify_object(cert.operational_public_key, card, "peer_card")`
     (runtime.py:566); the NEW cert is root-signed (passes `cert.verify`), but the card signature was
     made with the OLD key → `verify_object` raises → the `except Exception` at runtime.py:567 returns
     `None` → the sender is unauthenticated. Gossip from the node is not attributable.
   - **REFUTED sub-claim (durable-custody receipts):** the report lists "durable-custody receipt" as
     one of the things whose verification "fails." It does not. `messages.InboundService.build_receipt`
     (messages.py:301-310) signs with the operational key, but nothing verifies a receipt signature —
     `runtime.py:977-1000` validates only `message_id`, `node_id`, and `status` on the 202 body. There
     is no receipt-verification site in the tree (`rg -n "verify_receipt" lattice/` → empty). So the
     receipt-signing mismatch has no failed-verification consequence. This half of the outcome is noise.
   - **Broader than reported (additional failure site):** inbound-message verification also fails.
     `verify_inbound_message` (runtime.py:619-669) resolves the sender's cert from its pin/resolution
     and calls `verify_message(message, cert, ...)` (runtime.py:648-652) against
     `cert.operational_public_key`. A peer receiving an outbound message from the mismatched node sees
     the NEW pinned cert but a signature made with the OLD key → `RuntimeError("message signature
     invalid")` → HTTP 401. The node is cut off in both directions, not only for gossip cards.

## Severity correction

Reported **M** → corrected **L**. Reason: outcome severity alone would sit in M, but the pinned
severity scale's M requires the divergence "under a plausible normal operation," while the trigger is
an *unplanned* daemon restart inside a *manual* rotate window — the scale's L is defined as "a real
defect with a narrow trigger," and the frequency correction (LATENT) invokes the calibration cap at
L. The defect is real and worth fixing; only the rate of occurrence pulls it down. This is a
severity/frequency correction, not a refutation of the defect.

## Reachability kind

PRODUCTION (a real operator procedure plus a real daemon restart). Not tests-only, not gated behind
another finding. It is coincidence-gated on the restart landing in the window, which is what
forces LATENT frequency.

## Fix-direction constraints

- A repair must compare the *loaded* key's public half to `cert.operational_public_key` and fail
  closed at startup — but the comparison must be added to **both** `cmd_serve` (cli.py:676) and
  `_load_local_identity` (cli.py:283). Adding it only to `cmd_serve` leaves `contacts export` signing
  cards with the stale key that then fail `verify_object` at the importer (cli.py:367).
- A mere check does not remove the root cause: the documented rotation procedure inherently leaves the
  systemd credential stale between `rotate` and the manual `systemd-creds encrypt`. The durable fix
  must also make the stale window detectable/actionable (e.g., a distinct, explicit error naming the
  re-encrypt step), not a generic mismatch message an operator cannot act on.
- The check must not assume the key came from the credential dir; the staging-file fallback path must
  be covered too, or a mis-staged deployment slips through.
- Escaping this check off is not enough to make rotation safe: `keys rotate-operational` never
  verifies that the `.cred` was re-encrypted, so any future caller of rotate inherits the same window.

## Checked and clean (coverage)

- `_credential_path` precedence, fail-closed `CredentialError` on a missing credential-dir file, and
  the staging-suffix fallback (`name`, `name.pem`, `name.txt`) match `init`'s filenames — correct.
- `OperationalIdentity` contains no root material (identity.py:143-170); `cmd_serve` never loads the
  root private key — invariant 2 holds on the serve path.
- The single existing startup invariant `cert.node_id != manifest["node_id"]` (cli.py:673) is checked
  and correct; it is simply incomplete (it does not cover the key).
- `cert.is_valid_at` is enforced on the gossip path (runtime.py:564); the cert-validity window itself
  is not implicated in this finding.
- Message sender-side receipt handling at runtime.py:977-1000 is *as designed* (no signature check) —
  named here only because the report's receipt claim depends on it.

## Enumeration

Composed commands and output:

```
$ rg -n "public_key\(\)" lattice/
lattice/identity.py:158        (OperationalIdentity.public_key property)
lattice/identity.py:253        (create_operational_certificate)
lattice/cli.py:106,112,148,167,767,778,779   (cert/key construction)
# no comparison of a loaded key against cert.operational_public_key

$ rg -n "public_key\(\)\s*==" lattice/
(no output)

$ rg -n "operational_public_key" lattice/runtime.py
runtime.py:566   verify_object(cert.operational_public_key, card, "peer_card")

$ rg -n "verify_receipt" lattice/
(no output)
```

| Instance | Disposition |
|---|---|
| `cmd_serve` identity assembly, cli.py:672-679 | finding — no key/cert correspondence check |
| `_load_local_identity`, cli.py:275-283 | finding — same missing check, CLI signing path |
| `verify_gossip_sender_card`, runtime.py:566 | examined-clean — correctly fails on the mismatch |
| `verify_inbound_message`, runtime.py:648-652 | additional failure site (message signatures) |
| receipt validation, runtime.py:977-1000 | examined-clean — receipt claim refuted |

## Side discoveries (single-pass, not folded into the verdict)

- **Receipt signatures are never verified.** `messages.py:301-310` signs durable-custody receipts with
  the operational key, and `runtime.py:977-1000` accepts a 202 body by checking only message_id /
  node_id / status, with no signature and no cert check. A forged `{"message_id","node_id","status":
  "accepted"}` 202 from a hijacked/MITM transport would be accepted as custody. Reachability:
  PRODUCTION (any peer on the message path). Severity: M (wrong custody/acknowledgment semantics — a
  sender records delivery based on unauthenticated data). Frequency: DEMONSTRATED for any outbound
  delivery (every 202). Fix-direction: verify the receipt signature against the destination's
  resolved operational cert before `record_success`. Latent/single-pass: `lattice/messages.py` and
  the transport trust boundary belong to another pass; not traced to a live attacker here.
- **`contacts import` does not enforce cert validity** (`cmd_contacts_import`, cli.py:318-390):
  `cert.verify(root_identity)` is called but `cert.is_valid_at(...)` is not, while the gossip path
  (runtime.py:564) does. An expired-cert card imports. Severity: L. Frequency: LATENT (requires an
  expired cert window). Reachability: PRODUCTION (operator importing a card).

## Bound

- Not executed against a live systemd host: `LoadCredentialEncrypted` in-flight decryption and the
  exact `$CREDENTIALS_DIRECTORY` contents on restart were traced from code + `deploy/lattice.service`
  + `docs/LATTICE_SYSTEMD.md`, not observed in a running unit.
- Whether any operator deployment automation runs `keys rotate-operational` and the `systemd-creds
  encrypt` step atomically (which would collapse the window) is unknown — outside the tree.
- `crypto.py` encryption format and the transport trust model for the receipt side discovery were not
  audited end to end; those are boundaries, not silences.
