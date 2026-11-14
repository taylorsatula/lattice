# v-hunt-e1#4 — PRIMED VERIFIER on hunt-e1#4

Claim under test: hunt-e1.md finding 4, tier **L** — "Daemon starts and serves with an expired or
key-mismatched certificate, undetected." Location claimed: `lattice/cli.py:cmd_serve`.

Verdict: **ADJUSTED**. The key-mismatch half of the mechanism is CONFIRMED by reading; the
expired-certificate half's stated outcome is overstated (refuted in part); the frequency assertion
("DEMONSTRATED") is not grounded and is corrected. Severity left at **L** with reasons.

---

## Re-derived frame (independent of the claim's phrasing)

`cmd_serve` (cli.py:638) assembles the daemon identity at cli.py:672-681:

```
cert = OperationalCertificate.from_dict(manifest["operational_certificate"])
if cert.node_id != manifest["node_id"]:
    print("Identity manifest node_id/certificate mismatch.", ...); return 1
identity = OperationalIdentity(node_id=cert.node_id, private_key=op_key, certificate=cert)
```

`op_key` comes from `load_operational_key(path=_credential_path("operational_key", config_dir))`
(cli.py:665). `_credential_path` (cli.py:626) returns `$CREDENTIALS_DIRECTORY/operational_key`
when systemd credentials are present, else scans `operational_key{,.pem,.txt}` in the config dir.
`root_public_key` is loaded at cli.py:684-688 and handed to `RuntimeCoordinator`, which builds
`RootIdentity(node_id=identity.node_id, public_key=root_public_key)` (runtime.py:180) — no use of
`identity.certificate` at all.

Read every place `identity.certificate` / the own cert is consumed:
`rg -n "\.certificate\b|identity\.certificate|_certificate" lattice/` →
- gossip.py:210/215 — `self._identity.certificate.to_dict()` / `.sequence`, publishing the own cert
  in the gossip card.
- No other own-certificate consumer in the daemon. The message path's certificate comes from the
  *receiver's* stored pin (`_certificate_for_node`, runtime.py:665-681), not from the sender.

Facts established independently:
1. `cmd_serve` never compares `op_key.public_key()` to `cert.operational_public_key`.
2. `cmd_serve` never calls `cert.verify(RootIdentity(...))`.
3. `cmd_serve` never calls `cert.is_valid_at(...)`.
4. `RuntimeCoordinator.__init__` (runtime.py:164-180) likewise never verifies its own cert.
5. `RuntimeCoordinator.start` (runtime.py:390) performs no self-check; it pins bootstrap peers only.
6. `cmd_keys_rotate_operational` write order (cli.py): `operational_key.pem` at 791, `rotation.json`
   at 795, `identity.json` manifest at 798-800, `well-known.json` at 823 — four non-atomic writes,
   no temp-and-rename, no fsync.
7. The daemon serves `well-known.json` verbatim as its public well-known document
   (api.py:227-233, `runtime.well_known_document`), and does not check that the served
   `operational_certificate` equals `identity.certificate`.
8. `_send_outbound_message` (runtime.py:945-1019): HTTP 401 falls into the `else` branch →
   `record_failure(..., retryable=False)`; `OutboundMessageRepository.record_failure`
   (messages.py:158-186) then `mark_terminal(..., erase_content=True)` — the message is failed
   permanently and its content erased.

Sub-claims 1-3 confirmed. Sub-claims 4-8 are the mechanism the finding rests on and are confirmed.

---

## Per-component disposition

**Mechanism (confirmed).** There is no startup consistency check between the operational private
key, the manifest certificate, and the served well-known document. A daemon whose `op_key` does not
match `cert.operational_public_key` starts, logs `runtime started for node ...`, serves inbound, and
signs every outbound object with a key no peer's pinned certificate authorizes.

**Trigger (confirmed, narrower and partly different than stated).**
- Named crash window: real. Crash between cli.py:791 (key write) and cli.py:800 (manifest write) →
  new key on disk, old cert in the manifest → mismatch. The window is a specific inter-statement
  boundary in a single CLI invocation.
- Stronger, more routine trigger (new reachability on the same trace): the documented production
  credential flow. `deploy/lattice.service:22` uses
  `LoadCredentialEncrypted=operational_key:/etc/lattice/operational_key.cred`, so in production
  `_credential_path` returns `/run/credentials/lattice.service/operational_key`, decrypted from the
  `.cred` file — **not** the `operational_key.pem` that rotate rewrites. `cmd_keys_rotate_operational`
  never regenerates `operational_key.cred` (no `systemd-creds`/cred write anywhere in cli.py).
  `docs/KEY_MANAGEMENT.md:50` requires the operator to manually re-encrypt and restart. An operator
  who restarts after `keys rotate-operational` before re-encrypting the `.cred` (or who re-encrypts
  from a stale source) gets old key in the credential directory + new cert in the manifest → same
  mismatch, with no crash required.
- Missed-30-day-rotation ("expired") trigger: real absence, but see refuted sub-claim below.

**Frequency (corrected).** The claim's "DEMONSTRATED for the rotation-crash window" is **not**
demonstrated — a crash landing exactly between cli.py:791 and 800 is an event with no grounded
cadence, and the operator visibly sees the command abort (no success banner) and would normally
re-run rather than serve. The empirical basis that survives is the manual credential step: any
rotation is a 4-file + systemd-credential sequence whose `.cred` half is operator-executed and
out-of-band, and the failure is silent until the first outbound attempt. Ground it as *occasional,
operator-induced, production* (a rotation whose credential re-encryption lags the restart), not as
a demonstrated cadence. Cadence is therefore LATENT-adjacent but the trigger is a documented
routine procedure, so it stays above pure speculation and at L.

**Reachability kind:** PRODUCTION (operator action), not test-only, not gated behind another finding.

---

## Sub-claims refuted (named)

- **R1 — "expired → all outbound messages fail terminally."** Refuted for the expiry variant. The
  inbound message path does **not** check `is_valid_at` — `verify_message` (protocol/signing.py)
  calls only `certificate.verify(root_identity)` + `verify_object`, and `runtime.verify_inbound_message`
  does not pass a time (this is hunt-e1#1). An expired *own* cert therefore still produces message
  signatures that pinned peers accept; only the gossip-card path checks expiry
  (runtime.py:563-566 `if not cert.is_valid_at(...)` → card dropped). The expired variant's real
  outcome is loss of gossip propagation of this node's card, not "all outbound messages fail
  terminally." That sentence in finding 4's Outcome is true only for the key-mismatch variant.
- **R2 — "DEMONSTRATED" frequency for the crash window.** Not demonstrated; see Frequency above.
  The grounded population is the manual `.cred` re-encryption step, which is occasional.
- **R3 — "undetected."** Partially refuted. The mismatch is not detected at startup and never causes
  a fail-fast, but outbound delivery does emit `_audit_outbound_failed(reason="HTTP 401 terminal")`
  and a circuit-breaker `_circuit_record_failure` (runtime.py:1013-1019), so the operator receives an
  eventual log signal. "Undetected" is accurate only up to the first outbound attempt; "no fail-fast
  guard" is the precise statement.

Severity of the confirmed key-mismatch half: **L** stands. Trigger is operator-induced and the bad
outcome is self-inflicted (all outbound conversion to terminal, content erased). One could argue
toward M via the scale's "lost queue item," since the effect is total outbound loss; the narrow,
operator-local trigger holds it at L. No severity change issued.

---

## Additional mechanisms / earlier failure site / new reachability (same trace)

**A1 — Served well-known diverges from the signing identity (earlier failure site, unaddressed by
the claim).** The rotate sequence writes the key (791), then rotation.json (795), then the manifest
(800), then well-known.json (823). A crash *after* the manifest write but *before* the well-known
write leaves: `op_key` = new key, `manifest` = new cert (matches the key), `well-known.json` = **old
cert**. On restart the daemon signs with the new key but *serves* the old cert in
`GET /.well-known/lattice` (api.py:227-233 reads `runtime.well_known_document`, loaded from
well-known.json at cli.py:659-660). Peers that resolve/pin the domain pin the old cert and reject the
daemon's new-key signatures. This is a second, independent inconsistency direction on the same
non-atomic write — the daemon's published authorization and its actual key disagree. No path checks
`well_known_document["operational_certificate"] == identity.certificate` at startup. Fix constraint
of A1 differs from the claim's: a key-vs-manifest check does not catch it.

**A2 — credential staleness (stronger trigger; see Frequency).** Described above.

Both are production-reachable and both argue that the repair belongs at startup (validate the
identity triangle) rather than at any one call site.

---

## Fix-direction constraints (what a repair must account for beyond the symptom)

- A single `op_key.public_key() == cert.operational_public_key` guard fixes only the named
  key-mismatch case. It does **not** cover A1 (served well-known vs. signing key) and does **not**
  cover the expired-cert half, which additionally needs `cert.is_valid_at(now)`.
- A complete startup validation must check the whole triangle and the signature: (i) op key ↔
  manifest `operational_public_key`; (ii) manifest cert ↔ served `well_known_document`
  `operational_certificate`; (iii) `cert.verify(RootIdentity(node_id, root_public_key))` so a
  corrupted manifest cannot start a node that can never be verified; (iv) `is_valid_at`. Failing
  fast at `cmd_serve` is the correct site for all four.
- Validation alone leaves the underlying non-atomicity. `cmd_keys_rotate_operational` should write
  the four artifacts via temp-and-rename (or a single atomic state blob) so no interleaving yields a
  consistent-looking-but-wrong start; and it should regenerate/notify the systemd `.cred` rather than
  relying on a manual, silently-skippable step. Note the boundary: making writes atomic prevents the
  *structure-breaking* window but does not by itself prevent a mismatched-key start (the operator
  can still skip re-encryption); both a consistency guard and atomicity are required.
- Do not patch only `gossip.py` or the message path: the defect is that the daemon has no
  self-consistency assertion, not that a specific consumer misreads the cert.

---

## Checked and clean

- `OperationalCertificate.verify` (identity.py:125-136) and `is_valid_at` (identity.py:138-141) are
  correct; the gap is that they are simply not called for the local identity at startup.
- `RuntimeCoordinator.__init__` / `start` verified: no own-cert validation exists, so the claim's
  citation of runtime.py:178-180 is accurate (not a hidden check).
- `_credential_path` (cli.py:626-635) verified: systemd path takes precedence, confirming A2/A2's
  credential-vs-pem divergence is a real production pathway.
- `OutboundMessageRepository.record_failure` (messages.py:158-186) verified: `retryable=False`
  erases content — the terminal 401 outcome is real, not a soft failure.
- `api.py:227-233` verified: served well-known is read verbatim from the startup-loaded document,
  confirming A1.
- `gossip.py:210-215` verified: own cert is published only here; consistent with the frame.

## Enumeration

Commands run:
```
rg -n "\.certificate\b|identity\.certificate|_certificate" lattice/ --type py
rg -n "op_key_path.write_bytes|rotation_path.write_text|manifest\[.operational_certificate.\]|manifest_path.write_text|well_known_path.write_text" lattice/cli.py
rg -n "well_known|well-known" lattice/api.py
rg -n "LoadCredential|operational_key" deploy/ docs/
```
Instance table:

| Site | Disposition |
|---|---|
| cli.py:672-681 cmd_serve identity assembly | finding 4 — no key-match / cert.verify / is_valid_at |
| cli.py:791 / 795 / 800 / 823 rotation writes | non-atomic; A1/A2 trigger |
| runtime.py:178-180 RootIdentity build | examined-clean as a *consumer*; confirms no self-check |
| runtime.py:390-399 start | examined-clean; no self-check |
| gossip.py:210-215 own cert publish only | examined-clean |
| api.py:227-233 served well-known | examined-clean; source of A1 |
| deploy/lattice.service:22 LoadCredentialEncrypted | examined-clean; grounds A2 |
| messages.py:158-186 record_failure | examined-clean; grounds terminal erase outcome |

## Bound

- Could not exercise the systemd credential flow live; A2 and R1's gossip-only outcome rest on
  reading `deploy/lattice.service`, `docs/KEY_MANAGEMENT.md`, `_credential_path`, `gossip.py`, and
  `runtime.py:563-566`, not on a running deployment.
- Did not run a real rotation against a serving peer; the terminal-401 outcome for the key-mismatch
  half rests on reading `_send_outbound_message` and `record_failure`, not observation.
- Not opened this pass: cli.py parser tail, the bulk of runtime.py maintenance/webhook internals,
  tests/ (grepped only). No inline `public_key.verify(` outside crypto.py observed in files read.
- No live infrastructure; provider/upstream behaviour not testable here.
