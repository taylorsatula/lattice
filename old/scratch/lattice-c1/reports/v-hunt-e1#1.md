# v-hunt-e1#1 — PRIMED VERIFIER: hunt-e1 finding 1

Claim under test: **hunt-e1#1 [M] — Expired operational certificates accepted into durable custody on
the inbound message path** (`scratch/lattice-c1/reports/hunt-e1.md`).

Verdict: **CONFIRMED** (tier M, unchanged). All sub-claims verified. Two clarifications to the frame
and one frequency caveat, recorded below.

Reachability kind: **PRODUCTION** (a real remote peer POSTs `/lattice/v1/messages`).

---

## Frame re-derived from source (before checking the claim)

- **What the inbound message path does.** `POST /lattice/v1/messages` → `api.py:receive_message`
  (api.py:284-354) → `runtime.verify_inbound_message` (runtime.py:619-663). That method obtains a
  certificate from `_certificate_for_node` (runtime.py:665-681) and calls
  `verify_message(message, cert, root_identity)` (protocol/signing.py:45-54).
- **What `verify_message` checks.** Only `certificate.verify(root_identity)` and
  `verify_object(cert.operational_public_key, message, "message")`. No `is_valid_at`. Verified by
  reading protocol/signing.py:45-54.
- **What `_certificate_for_node` returns.** Peer record → `peer.domain` → `resolver.get_pin(domain)`
  → `_certificate_from_pin(pin)` — returned **whenever a pin exists** (runtime.py:666-672). Live
  `resolve()` runs only when no pin exists (runtime.py:673-681). Confirmed by reading.
- **Whether pins are ever refreshed.** `resolver.pin()` is called only from `resolve_address`
  (resolution.py:172, only when `get_pin` is None) and `_resolve_pending_senders` (runtime.py:913,
  cold senders only). `topology.verify_candidate` calls `resolve_with_ip` but never `record_operational_key`
  → pin (topology.py:223, 240-291). The scheduler (`_build_scheduler`, runtime.py:342-393) has no
  pin-refresh task; `refresh_topology_slots` only fills guard/discovery slots. The `domain_pins`
  upsert (repositories.py:76-110) is reachable only through those two callers. **A pin is never
  updated once created.** Confirmed by composed grep:
  `rg -n "\.pin\(|resolve_address|\.resolve\(|resolve_with_ip" lattice/` → pin() only at
  resolution.py:172 and runtime.py:913.
- **What the cert window is.** `lattice init` and `keys rotate-operational` mint 30-day certs
  (cli.py:113-116, cli.py:766-771). Cert lifetimes bounded ≤90d at creation (identity.py:256).
- **Protocol requirement.** docs/PROTOCOL.md:61: "A daemon MUST reject a certificate whose
  `valid_until` is in the past, whose `sequence` is not greater than the previously accepted
  certificate…". docs/PROTOCOL.md:272 defines error `LATTICE_EXPIRED_CERTIFICATE` (401).
- **Sole window check in the tree.** `rg -n "is_valid_at" lattice/` → identity.py:138 (definition)
  and runtime.py:564 (gossip sender card) only. `rg EXPIRED lattice/` → no code match.

## Sub-claim disposition

| Sub-claim | Verdict | Decisive artifact |
|---|---|---|
| `verify_message` omits validity-window check | CONFIRMED | signing.py:45-54 |
| `_certificate_for_node` serves the stale pin cert; live resolve only when no pin | CONFIRMED | runtime.py:665-681 |
| No scheduled pin refresh | CONFIRMED | runtime.py:342-393; pin() callers enumerated above |
| PROTOCOL MUST + `LATTICE_EXPIRED_CERTIFICATE` absent from code | CONFIRMED | PROTOCOL.md:61/272 vs `rg EXPIRED` |
| Two cert-consuming paths diverge (gossip checks window, message does not) | CONFIRMED | runtime.py:563-566 vs runtime.py:658 |
| Additional unchecked sites (topology, resolution, cli) | CONFIRMED | topology.py:318-328, resolution.py:112-118, cli.py:363-367 |
| No test exercises expiry rejection on this path | CONFIRMED | `grep -rn is_valid_at tests/` → none |

**Refuted sub-claims: none.** The claim's framing ("the pin still holds the same expired cert") is
one enabling path; it is not the only one, and the finding is stronger than stated — see Added
mechanism A1.

## Severity / frequency

- **Severity: M — unchanged.** Outcome is a trust-boundary enforcement gap under a plausible normal
  operation: a message signed by a peer whose operational certificate has passed `valid_until` is
  accepted into durable custody, acknowledged with a signed 202 receipt, and delivered to the local
  user. It is not an authentication bypass in the cryptographic sense — `certificate.verify`
  succeeds and the signing key is the certificate's key — so the H clause "authentication or
  authorization bypass" is arguable but not compelled: the sender is the legitimate node, and the
  harm is a revocation/enforcement lapse, not forged identity or cross-peer reach. docs/THREAT_MODEL.md:75-76
  makes expiry a security control ("attacker can sign… until the certificate expires"), which is why
  M, not L: the outcome is a wrong custody/authorization decision, matching the M definition
  ("wrong custody/acknowledgment semantics… divergence between two paths that must agree"), and the
  divergence from the gossip path is explicit. H would require demonstrating a live path where an
  unauthorized principal (not merely a peer that missed rotation) gains reach; I could not.
- **Frequency: DEMONSTRATED for the mechanism; population caveat recorded.** Certification cadence is
  30 days and pins are never refreshed, so the trigger population is "any pin whose stored certificate
  has passed `valid_until` while the sender still signs with that same key." That population is
  produced by the normal operation "peer was pinned and has not rotated within 30 days"; per-message
  cadence is every message from such a peer. The one condition I cannot ground from code is that the
  peer **missed rotation** — if the peer *did* rotate, the stale pin causes a signature mismatch and
  the 401 of hunt-e1 finding 2 instead. The code neither forces nor detects rotation (see finding 4
  of the underlying report: the daemon never validates its own cert), so the non-rotation case is
  permitted, undocumented as safe, and undetected. I therefore do not demote frequency to latent, but
  I record that its trigger is operator-cadence-gated, not guaranteed by any code path.

## Added mechanisms / earlier failure sites / new reachability

- **A1 (stronger mechanism, same trace).** The finding does not depend on a pin at all. Even with no
  pin, `_certificate_for_node` calls `resolver.resolve(domain)` (runtime.py:673-681), and
  `resolve_with_ip` verifies only the cert **signature**, never `is_valid_at` (resolution.py:99-118).
  A live-resolved well-known document is itself served from the sender's `well-known.json` containing
  its cert, so a non-rotated sender's expired cert is accepted on the cold-resolve path too. This
  widens the untested surface beyond the pin case the claim names.
- **A2 (earlier failure site).** `_pin_bootstrap_peers` (runtime.py:412-486) pins bootstrap peers
  from a well-known fetch using only `node_id`/`root_public_key`/cert **sequence** extraction
  (runtime.py:428-477); it never checks `is_valid_at` and never compares sequence against stored
  state. Bootstrap peers are then trusted as `ESTABLISHED`. This is an earlier adoption site on the
  same trust chain that seeds the pin used by the message path.
- **A3 (second consumer).** `cli.py` contact import (cli.py:363-367) verifies the pinned chain with
  `cert.verify(...)` and `verify_object(..., "contact_card")` and no window check — a fourth
  independent consumer.
- Count of certificate-consuming paths lacking the window check: message verify (runtime.py:658),
  resolution pin/resolve (resolution.py:107-118), topology candidate verify (topology.py:312-328),
  bootstrap pin (runtime.py:428-477), contacts import (cli.py:363-367). The gossip path
  (runtime.py:563-566) is the only one that checks.

## Fix-direction constraints

1. Adding `is_valid_at` to `verify_message` alone does **not** repair the finding. The cert is
   supplied by `_certificate_for_node` from a never-refreshed pin, so the check either (a) rejects
   messages a peer legitimately sent under the correct, refreshed cert (converting finding 1 into
   finding 2's permanent 401), or (b) leaves the other four consumers unchecked. A repair must fix
   pin/peer-record freshness at the point of supply, plus the check at every consumer.
2. Certificate **sequence monotonicity** must be enforced at every adoption site (pin upsert,
   `verify_candidate`, bootstrap, resolution) or a replayed older-but-valid cert re-legitimizes a
   retired key (hunt-e1 finding 3). Expiry alone does not close the rollback.
3. The fix cannot rely on the sender detecting its own expiry; the daemon validates neither its
   private-key/cert pairing nor its cert window at startup (hunt-e1 finding 4). Receiver-side
   enforcement is the only available control.
4. Interaction with `_root_identity_for_node`: any refresh must preserve root-history/pin
   consistency, since verification uses root history first (runtime.py:684-707).

## Checked and clean

- `verify_gossip_sender_card` (runtime.py:536-569) is the one complete path: it calls
  `cert.is_valid_at(self._clock.now())` after `cert.verify` and before `verify_object`. Correct as
  written; it is the contrast point the finding cites.
- `OperationalCertificate.verify` (identity.py:125-136) correctly binds node_id to the root key
  (re-derives and compares) before signature verification — the signature clause of PROTOCOL §3.3 is
  enforced at every consuming site enumerated above.
- `is_valid_at` itself (identity.py:138-141) is correct: half-open `valid_from <= when < valid_until`,
  UTC-aware. The defect is caller omission, not the predicate.
- `create_operational_certificate` (identity.py:240-281) enforces lifetime ≤ 90d and sequence ≥ 1.
- `domain_pins.upsert` (repositories.py:76-110) does refresh `last_verified_at` and
  `operational_certificate` **when called** — the gap is that no periodic caller exists, not that the
  repository refuses to update.
- protocol/signing.py wrapper set: every other wrapper routes through a verifier that is exercised;
  `verify_message` is the only message-path wrapper and its omission is the finding.

## Enumeration

```
rg -n "is_valid_at|valid_until|valid_from|sequence" lattice/ --glob '!__pycache__'
```
Output (non-binary): identity.py (definition/creation bounds), runtime.py:564 (gossip only). No
`is_valid_at` in api.py, topology.py, resolution.py, protocol/signing.py, cli.py, messages.py.

```
rg -n "\.pin\(|resolve_address|\.resolve\(|resolve_with_ip" lattice/ --glob '!__pycache__'
```
Output: resolution.py:40,119,127,154,172; topology.py:223; runtime.py:428,589,678,913; cli.py:578.
`pin()` call sites: resolution.py:172 and runtime.py:913 only.

```
grep -rn "is_valid_at\|valid_until\|expired" tests/    # (excluding vendored fixtures/vectors)
```
Output: test_resolution.py:39, conftest.py:128/268/305, test_vectors.py:156/163, test_peers.py:95,
test_topology.py:157/171 — all **construct** certs with a 30-day window; `test_messages.py:181-185`
is outbound TTL expiry, unrelated. No test drives an expired certificate into any verify path.

## Side discoveries

None new. The one adjacent gap found on the return leg — the custody receipt's signature is never
verified by the sender (`runtime.py:_send_outbound_message`, 202 branch checks only three plaintext
fields) — is already reported in this run's hunt-b1b#5, q-error (side note), and seam-s4#2. Per the
"known" rule I do not re-report it.

## Bound

- I did not run the daemon or execute a live rotation against a peer; the 202/401 outcomes rest on
  reading the delivery loop and API dispatch, not observation.
- Upstream well-known serving strictness is unverifiable from the tree: whether a real deployment's
  `/.well-known/lattice` continues to serve an expired cert after rotation is a deployment fact.
- I did not read the full test suite; `tests/` was grepped for window/expiry coverage only.
