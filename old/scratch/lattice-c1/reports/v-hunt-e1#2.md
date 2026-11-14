# v-hunt-e1#2 — PRIMED VERIFIER

Claim under test: **hunt-e1#2** (reported tier M) — "Operational-key rotation has no receiving-side
path: rotated peers are permanently rejected." Source: `scratch/lattice-c1/reports/hunt-e1.md`.

Verdict: **CONFIRMED** at tier **M**. All three components (mechanism / trigger / frequency) traced
independently from source; no refuted half. Reachability kind: **PRODUCTION**.

## Re-derived frame (before reading the claim's own wording back)

The decisive question is not "does rotation exist" but "which certificate does the inbound message
verification path consult, and does anything ever replace it."

1. `runtime.verify_inbound_message` (runtime.py:619) resolves the sender, then calls
   `self._certificate_for_node(from_node_id)` (runtime.py:654) and verifies the message signature
   with that certificate (runtime.py:658 `verify_message`).
2. `_certificate_for_node` (runtime.py:665-681):
   - if `peer.domain` exists and `self._resolver.get_pin(peer.domain)` is not None → returns
     `_certificate_from_pin(pin)` (runtime.py:668-670);
   - else if a pinned domain for the node exists → same, returns the pin's cert (runtime.py:674-676);
   - a live `self._resolver.resolve(domain)` happens **only when no pin exists** (runtime.py:678-679).
   `_certificate_from_pin` is `OperationalCertificate.from_dict(pin["operational_certificate"])`
   (runtime.py:736-737), and `domain_pins.operational_certificate` is a persisted JSON TEXT column
   (migrations/durable/001_initial.sql:15).
3. So the inbound message path's trust anchor is the durable domain pin, and only the pin.

## Mechanism (confirmed)

`lattice keys rotate-operational` (cli.py:734-829) generates a new operational keypair, builds a
certificate with `sequence = old_cert.sequence + 1` (cli.py:765-772), overwrites
`operational_key.pem`, writes `rotation.json`, rewrites `identity.json`, and regenerates
`well-known.json` with the new cert. The node ID and root key are unchanged. The daemon then signs
`message` objects with the new operational key (`sign_message` → `self._identity`, runtime.py:618).

Nothing on any *receiving* node replaces the pinned certificate:

- Pin writers are exactly three: bootstrap `_pin_bootstrap_peers` (runtime.py:451 — guarded by
  `if self._peer_store.get_peer_by_domain(domain) is not None: continue`, so it never refreshes a
  known peer), `WellKnownResolver.pin` (resolution.py:129), and `trust accept-transfer`
  (cli.py:599). None runs on a schedule and none re-pins an existing domain pin in response to a
  new certificate.
- `TopologyService.verify_candidate` (topology.py:240-283) runs only for *candidates*: its intake
  gate `can_accept_candidate` returns `False` when `get_peer(node_id) is not None`
  (topology.py:143-144), and `GossipService.receive_batch` routes every inbound card through
  `accept_candidate` (gossip.py:124). A rotated peer is already known, so its card is rejected and
  its new cert never lands anywhere. `_run_verify_candidates` only iterates
  `list_candidates_for_verification` (runtime.py:1124-1129) — known peers are not candidates.
- `_build_scheduler` (runtime.py:343-393) has no pin-refresh or re-verification task. The seven
  tasks are cold-sender resolution, outbound/webhook delivery, gossip round, candidate verification,
  topology-slot refresh, expiry cleanup.
- Even where a new key is *recorded*, nothing reads it: `PeerStore.record_operational_key`
  (peers.py:148) writes `peer_operational_keys`, and a repo-wide search finds no SELECT against that
  table (only 001_initial.sql DDL and the INSERT). `current_certificate_sequence` on `peers` is
  likewise write-only (`record_operational_key` / `transition`).
- `identity.verify_rotation` (identity.py:208-238) and `GossipService.verify_card_against_pin`
  (gossip.py:261-272) are both dead code — zero call sites in `lattice/`. These are the two hooks the
  documented propagation model would use.

The documented intent is explicit: `docs/KEY_MANAGEMENT.md` ("Operational key rotation") says "peers
learn the new operational key through peer cards, which they already validate by certificate-sequence
monotonicity." The code path that would implement that (`verify_candidate` on known peers) is closed
by the candidate-only gate, and the table that stores the learned key is never read.

## Trigger and outcome (confirmed)

Remote peer A (`node_id_A`, pinned domain `a.example`) rotates its operational key. Peer B holds a
durable pin for `a.example` created before the rotation. B receives A's next message:

- `verify_inbound_message` → `_certificate_for_node(node_id_A)` returns the pin's *old* cert;
- `verify_message` verifies against the old `operational_public_key` while the message was signed
  with the new key → `SignatureError` → `RuntimeError` (runtime.py:659-661);
- `api.receive_message` maps `RuntimeError` to `_problem(401, ...)` (api.py:292-302);
- A's delivery loop `_send_outbound_message`: status 401 is neither 202, nor 429, nor ≥500, so it
  takes the `else` branch → `record_failure(..., retryable=False)` and
  `reason=f"HTTP {response.status} terminal"` (runtime.py:1012-1019);
- `OutboundService.record_failure(retryable=False)` → `mark_terminal(..., "failed", erase_content=True)`
  (messages.py:158-191): the outbound message is terminal and its content erased.

Outcome: after a legitimate, documented rotation, every message from the rotated node to any node
that had pinned it is terminally failed and its content erased, until an operator manually runs
`lattice trust reset-domain --domain a.example` on every receiving node. B→A traffic is unaffected
(B's key is unchanged), so the failure is one-directional as the claim states.

## Frequency (confirmed, with one bound)

DEMONSTRATED. The operation population is operational-key rotations performed by operators on nodes
that at least one peer has pinned. Rotation is a documented lifecycle operation
(KEY_MANAGEMENT.md; PROTOCOL.md §4.4 lists the three-signed `rotation` object), certificates are
minted with a 30-day lifetime (`create_operational_certificate`, cli.py:765-772; `cmd_serve` init
cli.py:110-115), and pins are created by ordinary traffic (`resolve_address` on the first human-address
send, resolution.py:172; cold-sender async pin, runtime.py:913). No test exercises the receiving side
of a rotation (`tests/test_resilience.py:26` asserts only node-id preservation and well-known
regeneration). The trigger is certain given a rotation on a pinned peer.

Bound on frequency: the *cadence* is operator-dependent (there is no automatic rotation in the
daemon), so "how often" is the rotation policy, not a code constant. The finding does not depend on
that cadence for its correctness; the population is grounded.

## Severity (unchanged)

M. It is a lost/stuck queue item under a plausible normal operation — the severity scale's own
wording ("a stuck or lost queue item"). Not H: no secret exposure, auth bypass, cross-peer reach, or
remote crash. Not L: content is destroyed (`erase_content=True`) and delivery is permanently broken
for the peer pair, not a bounded misreported field.

## Sub-claims: none refuted

Each named sub-claim was re-traced and holds:

| Sub-claim | Verdict |
|---|---|
| `_certificate_for_node` uses the pin cert whenever a pin exists; live resolve only when no pin | CONFIRMED (runtime.py:665-681) |
| `verify_rotation` has zero call sites | CONFIRMED (repo grep: definition only) |
| Verification failure raises → api.py 401 | CONFIRMED (runtime.py:659-661, api.py:292-302) |
| Sender marks non-202/429/5xx terminal, `retryable=False`, reason "HTTP 401 terminal" | CONFIRMED (runtime.py:1012-1019) |
| Rotation mints sequence+1 and republishes well-known | CONFIRMED (cli.py:765-829) |
| `verify_candidate` records key/sequence but never the pin | CONFIRMED (topology.py:240-283; only pin writers are bootstrap/resolution.pin/transfer) |
| Scheduler has no pin refresh | CONFIRMED (runtime.py:343-393) |
| Rotation statement never consumed | CONFIRMED (`verify_rotation` dead; `rotation.json` is local-only, never published in well-known) |

## Additional mechanisms / earlier failure sites / new reachability

- **Root cause is broader than a missing refresh**: the mount point for the documented propagation
  mechanism is write-only end to end. `peer_operational_keys` is INSERT-only, `peers.current_certificate_sequence`
  is write-only, and both `verify_rotation` and `GossipService.verify_card_against_pin` are dead.
  A repair that only re-pins on one call site leaves the learned-key table still unread.
- **The rotation statement cannot reach peers by any channel**: it is written only to a local
  `rotation.json` (cli.py:794-796) and is absent from the well-known document (cli.py:809-820). The
  only peer-facing channel is peer cards, which known peers' intake rejects. So "consume the rotation
  statement" is not sufficient without a transport for it.
- **`can_accept_candidate` also rejects blocked peers and exists purely as a Sybil cap**, so relaxing
  it to admit known-peer cards interacts with the topology-guard rules (topology.py:143-160) — the
  repair must not open candidate accounting to known peers.
- Adjacent (not this finding): the same stale-pin read means `hunt-e1#2` and `hunt-e1#1` (expiry)
  share one fix mechanism (pin freshness / pin update), as the hunter's design-risk note states.
  Findings 1 and 2 are otherwise independent: finding 2 is a key mismatch, not a validity-window
  miss, and repairing `is_valid_at` alone does not fix it.

## Fix-direction constraints

1. A fix must cause the receiving node's *message-verification trust anchor* to advance to the
   rotated certificate. Adding `is_valid_at` checks (finding 1's repair) does not advance a rotated
   key; the certificate must actually be replaced or the verification must consult the newest
   accepted cert (by sequence) rather than the pin snapshot.
2. Certificate-sequence monotonicity (finding 3, PROTOCOL.md §3.3) must gate any adoption: without
   it, "accept the newest cert" becomes a rollback vector to a retired operational key.
3. Do not repair by making 401 retryable. A genuinely invalid signature must stay terminal; the fix
   is to refresh trust, not to retry into an infinite loop.
4. Preserve invariant 5 (202 = durable custody) and invariant 6 (no message relay): the repair is in
   certificate resolution, not in delivery semantics, and must not forward message bodies.
5. If the fix is "known-peer cards update the operational key," it must route through the existing
   chip-intake/cap logic without letting known peers re-enter candidate accounting, and it must
   persist into a table that message verification actually reads.

## Checked and clean

- `verify_inbound_message`'s structural rejection (bad address/JSON) → 401 is correct; no custody is
  taken. Blocked-sender and cold-sender branches are correct and unrelated to this finding.
- `OutboundService.record_failure`/`mark_terminal` semantics: non-retryable → terminal + content
  erasure is intended; the defect is that a *legitimate* peer reaches this branch, not the branch
  itself.
- `trust accept-transfer` (cli.py:549-610) *does* re-pin the domain via `repo.upsert` after verifying
  the dual-signed transfer — so domain transfer (root change) is handled; only operational rotation
  is not. Contrast is clean.
- `_pin_bootstrap_peers` correctly avoids re-pinning known domains; that guard is intended, not a bug
  on its own.
- The `rotation` object construction and its three signatures (cli.py:776-792; `verify_rotation`
  preimage) are internally consistent; `tests/test_cli.py:726-776` verifies the three signatures.
- `PROTOCOL.md` §3.3 signature clause and `OperationalCertificate.verify` root/node-id binding are
  correct; independent of this finding.

## Enumeration

Composed commands (run from repo root; `__pycache__` excluded):

```
# every writer/reader of a durable domain pin
rg -n "_pin_repo\.|resolver\.pin\(|DomainPinRepository|\.upsert\(" lattice/ --type py
# every consumer of an operational certificate
rg -n "operational_certificate|_certificate_for_node|_certificate_from_pin|verify_rotation|verify_card_against_pin|record_operational_key|current_certificate_sequence|peer_operational_keys" lattice/ --type py --glob '!**/__pycache__/**'
# every task registered on the daemon scheduler
rg -n "_RecurringTask\(" lattice/runtime.py
```

Instance table — pin writes / cert consumers:

| Site | Kind | Disposition |
|---|---|---|
| runtime.py:451 `_pin_bootstrap_peers` upsert | pin write | examined-clean; guarded by `get_peer_by_domain is not None → continue`, never refreshes known peer |
| resolution.py:129 `WellKnownResolver.pin` | pin write | examined-clean; caller `_resolve_pending_senders` runs only for never-pinned domains |
| cli.py:599 `cmd_trust_accept_transfer` upsert | pin write | examined-clean; root-transfer path, re-pins correctly |
| runtime.py:665-681 `_certificate_for_node` | cert read | **finding 2 site**: pin cert preferred, no refresh |
| runtime.py:736-737 `_certificate_from_pin` | cert read | pin JSON → cert; no validity/sequence gate |
| runtime.py:678 `resolver.resolve` | live cert read | reached only when no pin exists |
| topology.py:240-283 `verify_candidate` | cert/key write | candidates only; writes `peers`/`peer_operational_keys`, never the pin |
| topology.py:394 `refresh_topology_slots` | scheduler task | guards/discovery only; no cert or pin work |
| peers.py:148 `record_operational_key` | key write | INSERT-only; no reader anywhere |
| identity.py:208-238 `verify_rotation` | rotation verify | zero call sites |
| gossip.py:261-272 `verify_card_against_pin` | card verify | zero call sites |
| cli.py:734-829 `cmd_keys_rotate_operational` | rotation producer | writes key/manifest/well-known; local `rotation.json` only |
| tests/ | — | no receiving-side rotation test (`test_resilience.py:26` only checks node-id + well-known) |

## Design risks (max 2)

1. Domain pins have no TTL, no refresh interval, and no invalidation on verification failure. This is
   the shared root of `hunt-e1#1` (expiry) and `hunt-e1#2` (rotation): both are this one latent
   property. A repair of either should treat pin freshness as the mechanism, not per-call-site
   patching.
2. The documented propagation model ("peers learn the new operational key through peer cards")
   depends on a listener for known-peer cards that does not exist, and on a `peer_operational_keys`
   table no code reads. Any future card-based trust update inherits this dead end unless the read
   path is built with it.

## Bound

- No live infrastructure: I could not run a real two-node rotation against a running peer. The
  terminal-401 outcome rests on the traced delivery loop (runtime.py:1012-1019 → messages.py:176-183)
  and the api 401 mapping, not on observation.
- Not opened in full here: cli.py 840-1022 (parser tail), runtime.py maintenance/webhook internals
  (760-905, 1035-1136), webhook.py, transport.py, network_policy.py. None of these is on the traced
  path; the scheduler registration (runtime.py:343-393) was read in full to close the
  "no pin-refresh job" claim.
- Operator rotation cadence is not a code constant; the frequency population is grounded, the
  cadence is a policy boundary.
