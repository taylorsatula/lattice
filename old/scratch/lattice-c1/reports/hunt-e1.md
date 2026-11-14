# hunt-e1 — identity & key lifecycle (lattice/identity.py, lattice/crypto.py)

Blind hunter. Scope per assignment: node-id derivation, operational identity, certificate
validation, rotation, recovery handling. Supporting callers traced: resolution.py, topology.py,
runtime.py, api.py, gossip.py, cli.py, messages.py, protocol/signing.py, protocol/models.py,
storage/repositories.py. All findings are production-reachable unless stated otherwise.

## Findings

1. [M] — Expired operational certificates accepted into durable custody on the inbound message path
- Location: lattice/protocol/signing.py:verify_message; lattice/runtime.py:verify_inbound_message / _certificate_for_node
- Evidence: `verify_message` calls only `certificate.verify(root_identity)` and `verify_object(...)` — no validity-window check. `runtime.verify_inbound_message` (runtime.py:654-658) obtains the cert from `_certificate_for_node` (runtime.py:665-681, stale domain pin, live resolve only when no pin exists) and calls `verify_message` with no `is_valid_at`. Contrast runtime.py:563-564 (`verify_gossip_sender_card`): `cert.verify(root_identity)` followed by `if not cert.is_valid_at(self._clock.now()): return None`.
- Trigger: a remote peer POSTs /lattice/v1/messages signed with an operational key whose root-signed certificate's `valid_until` has passed; the local node's stored domain pin for that sender still holds the same expired cert (no scheduled task refreshes pins — `_build_scheduler` runtime.py:342-393 has no pin-refresh job; `verify_inbound_message` failure raises RuntimeError → 401 with no re-resolution).
- Frequency: DEMONSTRATED — `lattice init`/`keys rotate-operational` mint 30-day certs (cli.py:115, 770); nothing in the daemon checks its own cert either (see finding 4), so a sender that misses rotation keeps signing; receivers accept. Any peer pin older than the peer's cert lifetime with no intervening topology re-verification. PROTOCOL.md §3.3 (line 61) states the daemon MUST reject a certificate whose `valid_until` is in the past, and error code `LATTICE_EXPIRED_CERTIFICATE` (PROTOCOL.md:272) does not exist anywhere in code.
- Outcome: messages signed by a de-authorized (expired) operational key are accepted into durable custody, acknowledged with a signed 202 receipt, and delivered to the local user — the certificate's expiry, which is the protocol's only de-authorization mechanism for operational keys, is not enforced. Two verification paths that must agree (gossip sender card checks expiry; message custody does not) diverge. Additional unchecked sites: topology.py:322-328 (`_verify_against_well_known` / `verify_peer_card` — also persists the cert via `record_operational_key`), resolution.py:107-118 (resolve/pin), cli.py:366-367 (contacts import).
- Confidence: traced (mechanism, trigger, frequency all verified by reading; no test exercises expiry rejection — `rg is_valid_at tests/` returns nothing).

2. [M] — Operational-key rotation has no receiving-side path: rotated peers are permanently rejected
- Location: lattice/runtime.py:_certificate_for_node / verify_inbound_message; lattice/identity.py:verify_rotation (no callers)
- Evidence: `_certificate_for_node` returns `self._certificate_from_pin(pin)` from the stored domain pin whenever one exists; a live `resolve()` happens only when no pin exists. `verify_rotation` (identity.py:208-238) has zero call sites in `lattice/` — dead code. On verification failure `verify_inbound_message` raises → api.py returns 401; the sender's delivery loop marks non-202/429/5xx as terminal: runtime.py `record_failure(message_id, owner, retryable=False)` with reason `HTTP 401 terminal`.
- Trigger: the operator of node A runs the documented `lattice keys rotate-operational` (cli.py:733-829 — new cert, sequence+1, republished well-known). Any node B that previously pinned A's domain (pin created on first human-address send, resolution.py:172, or cold-sender resolution, runtime.py:913) thereafter has A's message signature verified against the stale pinned cert → mismatch → 401 on every message. Nothing refreshes the pin: `verify_candidate` updates the peer record and `record_operational_key` but never the domain pin (topology.py:240-283); the scheduler runs no pin-refresh job; the CLI offers only manual `trust reset-domain` / `trust accept-transfer` (root transfer, not op rotation).
- Frequency: DEMONSTRATED — every operational-key rotation on any peer that others have pinned. Rotation is a documented lifecycle operation (docs/KEY_MANAGEMENT.md, PROTOCOL.md §4.4 lists the three-signed `rotation` statement as a protocol object).
- Outcome: after a legitimate rotation, all messages from the rotated node to pinned peers fail terminally (dropped after first attempt, `retryable=False`) until an operator manually resets the domain pin on every receiving node. The rotation statement, which exists precisely to prove key continuity, is never consumed.
- Confidence: traced (mechanism, trigger, frequency all verified).

3. [M] — Certificate sequence monotonicity is never enforced (PROTOCOL.md §3.3 MUST)
- Location: lattice/topology.py:verify_candidate (applies `current_certificate_sequence=result.certificate_sequence` unconditionally, topology.py:247/257); lattice/resolution.py:pin (persists whatever the domain serves); lattice/storage/repositories.py:record_operational_key (upsert `ON CONFLICT(node_id, certificate_sequence) DO UPDATE`, no max-sequence comparison); lattice/runtime.py:468/477 (bootstrap)
- Evidence: PROTOCOL.md line 61: "A daemon MUST reject a certificate whose `valid_until` is in the past, whose `sequence` is not greater than the previously accepted certificate for that node, or whose signature does not verify...". No code in the tree compares an accepted certificate's `sequence` against stored `current_certificate_sequence` or `peer_operational_keys` history before adopting it. `rg` for sequence comparisons at adoption sites returns none.
- Trigger: a domain's well-known endpoint serves an older, still-root-signed, lower-sequence certificate (operator restores a pre-rotation backup of well-known.json/manifest — plausible, no adversary needed; or an attacker with DNS/TLS-era control of the domain serving position). The daemon adopts it: pin upsert, peer `current_certificate_sequence` regression, and `record_operational_key` re-register the old operational key.
- Frequency: no-adversary variant: operator backup-restore mistake, rare but real. Adversary variant: requires coincident control of the domain's serving position plus possession of a previously compromised operational key — the exact rollback scenario the MUST names (environment-armed). Reachability kind: PRODUCTION (a real domain fetch) but trigger-gated on hostile or erroneous domain content.
- Outcome: rollback to a de-authorized operational key; combined with finding 1 (no expiry enforcement on the message path), a key retired by rotation can be re-legitimized by serving the old cert. Wrong trust decision in the certificate chain.
- Confidence: traced mechanism; frequency grounded only for the operator-error variant. Mechanism, trigger, frequency: mechanism proven, adversary-frequency asserted from the protocol's own threat statement.

4. [L] — Daemon starts and serves with an expired or key-mismatched certificate, undetected
- Location: lattice/cli.py:cmd_serve (identity assembly, ~cli.py:666-681)
- Evidence: `cert = OperationalCertificate.from_dict(manifest["operational_certificate"]); if cert.node_id != manifest["node_id"]: ...; identity = OperationalIdentity(node_id=cert.node_id, private_key=op_key, certificate=cert)` — no check that `op_key.public_key() == cert.operational_public_key`, no `cert.verify(RootIdentity(..., root_public_key))`, no `is_valid_at`. RuntimeCoordinator likewise never verifies its own certificate (runtime.py:178-180).
- Trigger: operator misses the 30-day rotation window (daemon keeps serving, no warning), or `cmd_keys_rotate_operational` crashes between writing the new operational key and the new manifest (it writes the key file first, cli.py:782-784, then rotation.json, then manifest, then well-known.json) — restart yields old manifest + new key.
- Frequency: DEMONSTRATED for the rotation-crash window (multi-file write sequence with no atomicity); operator-inaction variant requires >30 days without rotation. Reachability: production, operator-triggered.
- Outcome: node silently emits signatures no peer can verify (all outbound messages fail terminally) or keeps serving long-expired credentials; a one-line startup check would fail fast. Bounded bad outcome, narrow trigger → L.
- Confidence: traced.

## Checked and clean

- `derive_node_id` / `node_id_from_public_key_b64url`: domain-separated SHA-256 over raw 32-byte key; matches PROTOCOL.md §3.2 exactly (prefix, base32 lower unpadded). All consumers that trust a node_id re-derive it from the key and compare (resolution.py:87-91, topology.py:306-309, runtime.py:556-558) — immutable-root-identity binding holds at every site examined.
- `OperationalCertificate.verify` (identity.py:125-136): enforces node_id equality AND that the root key re-derives the node_id before signature verification — a forged root-key/node-id pairing cannot pass. Signature clause of the §3.3 MUST is enforced at every verification site.
- `verify_transfer` + `cmd_trust_accept_transfer` (cli.py:549-607): fails closed — requires existing pin, pinned root key re-derives `old_node_id`, live well-known derives `new_node_id`, both signatures verified against those exact keys. Correct dual-signature preimage (`signature`/`new_signature` both cover the bare object). Clean.
- `create_operational_certificate` (identity.py:240-281): enforces `valid_from < valid_until`, lifetime ≤ 90 days, sequence ≥ 1. CLI is the only caller; params are sane (sequence 1, or +1 on rotation). Clean.
- `sign_with_root` / `verify_with_root` / `verify_object` (identity.py:46-66, 178-186): consistent preimage construction (domain prefix + kind + media type + JCS canonical of object minus signature fields); signer and verifier strip the same fields. No malleability: a modified field breaks the JCS preimage.
- `crypto.py` end-to-end: `verify` wraps all exceptions into SignatureError (no exception-type confusion); `load_public_key` enforces Ed25519 type; `load_public_key_b64url` → `from_public_bytes` enforces exactly 32 bytes. `save_private_key` uses BestAvailableEncryption when passworded. Clean.
- Root-key boundary (invariant 2): daemon (`cmd_serve`) loads only the operational key and bearer tokens; root private key appears exclusively in offline CLI commands. No daemon path loads, derives, or exports a root private key.
- `verify_gossip_sender_card` (runtime.py:536-569): self-consistent by documented design; the only path in the tree that checks `is_valid_at`. Rate-limit identity cannot be forged without a root key (cert must be root-signed and derive the claimed node_id).
- Root history (`ensure_root_history`, repositories.py:161-172): insert-once keyed by node_id; `_root_identity_for_node` treats an empty stored key as unknown and falls through to the pin; since `cert.verify` re-derives node_id from the loaded key, a bogus history key cannot impersonate a node_id.
- Recovery handling: no code handles a "recovery bundle"; docs (KEY_MANAGEMENT.md) define recovery as root-key backup + `init --force`, out of code scope. Nothing to defect.

## Enumeration

Commands:
```
rg -n "\bverify\(|\bverify_with_root\(|\bverify_object\(|\bverify_transfer\(|\bverify_rotation\(|\bsign\(|\bsign_with_root\(|\bsign_object\(" lattice/ --type py
rg -n "is_valid_at|valid_until|valid_from|sequence" lattice/ --type py
```
(both run with `__pycache__` excluded)

Sign/verify call sites:

| Site | Kind | Disposition |
|---|---|---|
| identity.py:53 sign (sign_with_root) | root sign | examined-clean (CLI/protocol signers only) |
| identity.py:65 verify (verify_with_root) | root verify | examined-clean (signature clause) |
| identity.py:136 OperationalCertificate.verify | cert verify | examined-clean as signature check; window/sequence gaps = findings 1/3 |
| identity.py:165/175 sign_object/verify_object | op sign/verify | examined-clean |
| identity.py:185 verify_object | op verify | examined-clean |
| identity.py:204-205 verify_transfer | transfer verify | examined-clean (cli.py:593, fails closed) |
| identity.py:228-238 verify_rotation | rotation verify | finding 2 — zero callers, dead code |
| identity.py:273 sign (create_operational_certificate) | root sign | examined-clean (bounds enforced) |
| crypto.py:92-94 sign / 97-104 verify | primitives | examined-clean |
| cli.py:175, 480, 521, 786-788 | root signing (offline CLI) | examined-clean, intended per invariant 2 |
| cli.py:310 sign contact card | op sign | examined-clean |
| cli.py:366-367 verify cert + contact card vs pin | verify | finding 1 site (no is_valid_at) |
| cli.py:593 verify_transfer | verify | examined-clean |
| protocol/signing.py:24-84 (all wrappers) | sign/verify | examined-clean; verify_message lacks window check = finding 1 |
| resolution.py:99, 107 | well-known verify | finding 1 site (no is_valid_at at pin time) |
| topology.py:312, 322, 328 | well-known/cert/card verify | findings 1 and 3 sites |
| runtime.py:563-566 | gossip sender card verify | examined-clean — the only complete path (checks is_valid_at) |
| runtime.py:658 verify_message | message verify | finding 1 |
| runtime.py:1051 sign webhook envelope | op sign | examined-clean |
| runtime.py:436-477 bootstrap | pin/verify | examined-clean (resolver.resolve verifies); sequence not compared = finding 3 site |

Validity-window / sequence checks:

| Check | Where | Disposition |
|---|---|---|
| `is_valid_at` call sites | runtime.py:564 ONLY, in the entire tree | 1 of ~7 certificate-consuming paths — findings 1 |
| sequence bounds at creation | identity.py:258-259, cli.py:113, 768 | examined-clean |
| sequence monotonicity at adoption | none anywhere | finding 3 |
| cert lifetime bound | identity.py:256, MAX 90d | examined-clean |
| `LATTICE_EXPIRED_CERTIFICATE` (PROTOCOL.md:272) | absent from code | finding 1 corroborating evidence |

## Design risks (max 2)

1. `verify_gossip_sender_card` keys rate limits on a self-asserted identity: anyone can generate a fresh root key + cert + card and obtain a new rate-limit identity for the cost of an Ed25519 keypair (no domain proof on that path). Message rate limiting is unaffected (pinned-cert verification required). Marginal today because gossip candidates carry no trust until independent domain verification.
2. Domain pins have no TTL, no refresh interval, and no invalidation on verification failure — this is the shared root of findings 1 and 2; any repair of either should treat pin freshness as the mechanism, not per-call-site patching.

## Side discoveries (single-pass candidates, not confirmed work)

- `encoding.b64url_decode` uses `urlsafe_b64decode` without validation: accepts `+`/`/` standard-alphabet chars and silently discards non-alphabet characters, so distinct strings can decode to the same bytes. No exploitable consequence found — all security decisions operate on decoded bytes, and 32-byte length is enforced at `from_public_bytes`. Noted for a future pass on encoding.
- `Message.timestamp` is never freshness-checked on ingest (no replay window on the message itself, only message_id idempotency in `accept`). Likely belongs to the messages hunt; not dispositioned here.

## Bound

- Read end-to-end: identity.py, crypto.py (both assigned in full). Read in full or in relevant part: resolution.py, gossip.py, topology.py (through line ~370), protocol/signing.py, protocol/models.py (through line ~258), storage/repositories.py (through line ~330), messages.py (custody paths), api.py (public routes), runtime.py (lifecycle, identity, verification, delivery, maintenance), cli.py (identity/transfer/rotation/serve/contacts commands, lines 1-860).
- Not opened: cli.py 860-1022 (parser tail), runtime.py 200-330 and 760-900 and 1040-1131 (webhook/maintenance internals), storage/ remainder, webhook.py, transport.py, network_policy.py, tests/ (only grepped, not read).
- Enumeration pattern limits: the rg patterns cover named verify/sign helpers; an inline `public_key.verify(` call outside crypto.py would be missed — none was observed in the files read.
- No live infrastructure: I could not exercise a real rotation against a running peer; finding 2's terminal-401 outcome rests on reading the delivery loop, not observation.
