# v-hunt-e1#3 — PRIMED VERIFIER

Claim under test: finding `hunt-e1#3` in `scratch/lattice-c1/reports/hunt-e1.md`
("Certificate sequence monotonicity is never enforced (PROTOCOL.md §3.3 MUST)"),
reported tier M.

## Verdict: ADJUSTED

Mechanism CONFIRMED. Severity M unchanged. The trigger and frequency as worded in the
claim are materially wrong on one half (the adoption is not the pin-upsert /
`record_operational_key` path the claim names), but a real, production-reachable
adoption path exists, so the finding survives.

---

## Re-derived frame (before reading the claim's conclusions)

**What the MUST requires.** `docs/PROTOCOL.md:61`: a daemon "MUST reject a certificate whose
`valid_until` is in the past, whose `sequence` is **not greater than the previously accepted
certificate for that node**, or whose signature does not verify". Sequence monotonicity is a
per-node, stateful check: the receiver must hold the last accepted sequence and compare.

**What state the tree actually holds.** `peer_operational_keys` (`migrations/durable/001_initial.sql:38-48`)
has `UNIQUE (node_id, certificate_sequence)` — a lower sequence inserts a *new* row, it does not
conflict. `peers.current_certificate_sequence` is a plain `INTEGER` with no CHECK or trigger
(`001_initial.sql:59`). So the durable store is *capable* of holding the prior sequence.

**Is the stored sequence ever read for a decision?** No.
- `current_certificate_sequence` is written at `topology.py:247,257`, `runtime.py:468,477`,
  `repositories.py:274-276`; it is read only in `peers.py:45` (`Peer.from_row`). No caller uses
  `Peer.current_certificate_sequence` for any comparison (`rg` below returns nothing).
- `peer_operational_keys` is written by `repositories.py:293-322` and **never SELECTed anywhere** —
  write-only history.
- No `<`/`>`/`max`/`min`/`!=` comparison on any `certificate_sequence`/`.sequence` exists in
  `lattice/` (enumeration below, empty).

So the claim's *headline mechanism* — no code compares an adopted certificate's sequence against the
previously accepted one — is fully accurate.

## Per-component adjudication

**Mechanism — CONFIRMED.** `topology.py:_verify_against_well_known` returns
`certificate_sequence=doc.operational_certificate.sequence` (topology.py:345) and
`verify_candidate` writes it unconditionally via `create_peer`/`transition`
(topology.py:247,257) with no read of the pre-existing value. `resolution.py:pin` upserts whatever
`resolve()` returned (resolution.py:129). `repositories.py:record_operational_key` upserts on
`(node_id, certificate_sequence)` with no max comparison. `runtime.py:_pin_bootstrap_peers`
(`runtime.py:448,468,477`) does the same for bootstrap. Confirmed. Finding 3's sub-claims
3a–3d all hold.

**Trigger — PARTIALLY REFUTED / CORRECTED.** The claim states the daemon "adopts it: pin upsert,
peer `current_certificate_sequence` regression, and `record_operational_key` re-register the old
operational key." That is not what the tree does for an **already-pinned** peer:
- `resolve_address` (`resolution.py:165-172`) re-resolves **only when `get_pin(domain) is None`**.
- `_resolve_pending_senders` (`runtime.py:908-917`) pins only domains queued by a *cold-sender*
  message (`api.py:305-307`, reached only when `verify_inbound_message` finds no pin,
  `runtime.py:648-652`).
- `_pin_bootstrap_peers` skips any domain already known (`runtime.py:424-425`).

A durable pin is never refreshed while it exists (no TTL/refresh job; consistent with the claim's
own design-risk #2). Therefore a domain that merely **republishes an old well-known.json** does
**not** cause a pinned receiver to re-adopt it, and `record_operational_key` is **not** called on
the inbound message path at all. The claim's persistence narrative is wrong for the pinned case.

**But a real adoption path exists** — the claim missed it. A peer learned through **gossip/candidate
verification is never pinned**: `TopologyService.verify_candidate` creates only a peer row and a
transient card (topology.py:236-283); it does not touch `DomainPinRepository`. For such a peer,
`RuntimeCoordinator._certificate_for_node` (`runtime.py:663-682`) finds `get_pin(domain) is None`,
falls through to `self._resolver.resolve(domain)` **live on every inbound message**, and returns
`_certificate_from_pin(doc)` — the certificate *currently served by the sender's domain* — with
no read of the stored `peers.current_certificate_sequence` from the earlier verification. This is
production: gossip discovery is the intended peer-introduction mechanism
(`runtime.py:1124-1128`, `_run_verify_candidates`).

Trigger (corrected), production-reachable:
1. B discovers A via gossip; `verify_candidate(A)` stores peer A with `current_certificate_sequence = N`
   and `record_operational_key(keyN, N)`; **no pin** is created.
2. A's domain subsequently serves a lower-sequence, still-root-signed certificate M (operator
   backup-restore of a pre-rotation well-known/manifest, or an attacker with serving-position
   control who retained the retired operational private key M).
3. A (or the attacker) sends a message signed by op-key M to B; B's
   `verify_inbound_message` → `_certificate_for_node(A)` live-resolves the domain, adopts cert M,
   and `verify_message` passes. No comparison to stored N. Message accepted into durable custody
   with a signed 202 receipt.

A second, *persisting* variant: if a node has a peer row but no domain pin (gossip-verified), a
later `resolve_address` / cold-sender resolution **creates** the pin from whatever the domain
serves (`resolution.py:129`) and overwrites `peers.current_certificate_sequence` with the lower
value (topology.py:247/257). Persisted regression.

**Frequency — CORRECTED.** The claim's "operator backup-restore mistake, rare but real" is the
weak half; the *adoption of whatever the domain serves on each message* is what is DEMONSTRATED
(any gossip-verified peer receives a message → live resolve → adopt). The *regression* itself
requires the domain to serve a lower sequence **and** a message signed by that retired key — the
adversary variant needs possession of a retired operational private key plus serving-position
control (the exact rollback scenario the MUST names), while the no-adversary variant needs only a
stale well-known. The mechanism/adoption is traced; the *regression event* frequency is grounded
for the operator/stale-serving variant and **SUSPECTED** for the adversary variant. Not test-only.

**Severity — M, unchanged.** It is a trust-decision correctness fault (wrong state: a de-authorized
key re-legitimized) and a divergence between two paths that must agree (gossip sender-card path
checks `is_valid_at`; this path checks neither window nor sequence — see finding 1). It is arguable
as H (accepting messages from a re-legitimized retired key is effectively an authentication
bypass), but the regression precondition (the attacker must already hold a retired operational
private key and control the domain's serving position) keeps the demonstrated frequency narrow.
Repair is still mandatory because the MUST is explicit. Tier left at M.

---

## Checked and clean

- `TopologyService.verify_candidate` peer-write (topology.py:236-283): examined; confirmed it does
  **not** consult any prior sequence before overwriting, and confirmed it does **not** create a
  domain pin (the reason the unpinned path exists).
- `PeerRepository.ensure_root_history` (repositories.py:161-172): insert-once; no sequence role.
- `PeerRepository.transition_peer` (repositories.py:244-291): unconditionally overwrites
  `current_certificate_sequence` when supplied; no comparison. Correctly characterized.
- `PeerRepository.record_operational_key` (repositories.py:293-322): upsert keyed by
  `(node_id, certificate_sequence)`; no max-sequence guard. Correctly characterized.
- `WellKnownResolver.resolve` (resolution.py:40-105): verifies root sig, node-id derivation, and
  `cert.verify(root_identity)` — but not window and not sequence; matches finding 3's premise.
- `_certificate_for_node` / `_domain_for_node` / `_certificate_from_pin` (runtime.py:663-737):
  read for the corrected trigger; the live-resolve branch is the adoption site.
- Schema (`001_initial.sql:38-59`): no CHECK/trigger enforcing monotonic sequence.

## Enumeration

Composed command (closes the "is any sequence comparison present" class):

```
rg -n "certificate_sequence|\.sequence" lattice/ --type py | grep -v __pycache__ \
  | grep -E "<|>|>=|<=|max\(|min\(|!="
```

Output: **empty** — no comparison of any certificate sequence anywhere in `lattice/`.

Composed command (closes "is stored sequence ever read for a decision"):

```
rg -n "current_certificate_sequence|peer_operational_keys" lattice/ --type py \
  | grep -v __pycache__ | grep -iE "select|from_row|get_peer|row\[|fetch"
```

Output: only `peers.py:45` (`Peer.from_row`), a pure decode — **no consumer**.

Instance table:

| Site | Disposition |
|---|---|
| `topology.py:247/257` write `current_certificate_sequence=result...` | unchecked-adoption (finding 3) |
| `topology.py:263-274` `record_operational_key` | unchecked-adoption (finding 3) |
| `resolution.py:129-139` `pin` upsert | unchecked-adoption (finding 3) |
| `runtime.py:448/468/477` bootstrap sequence write | unchecked-adoption (finding 3; first-adoption, no prior) |
| `runtime.py:678-679` `_certificate_for_node` live resolve | **corrected trigger** — adopts per-message, unpinned |
| `runtime.py:563-565` `verify_gossip_sender_card` | examined — self-consistent path, no stored prior; not a §3.3 violation |
| `identity.py:258` sequence ≥ 1 at creation | examined-clean (bound only) |
| `protocol/models.py:80,157,392,393` `Field(ge=1)` | examined-clean (bound only) |
| `peers.py:45` read of `current_certificate_sequence` | examined — decode only, unused |

`rg is_valid_at tests/` and `rg sequence tests/` (see run): no test exercises a sequence
regression or expiry rejection.

## Additional mechanisms / earlier failure sites (same trace)

- **Documentation/code divergence, not cited by the claim.** `docs/KEY_MANAGEMENT.md:59-60`
  asserts: "peers learn the new operational key through peer cards, **which they already validate
  by certificate-sequence monotonicity**." No such validation exists anywhere. This is a stated
  invariant in the operator-facing doc that the code violates, strengthening the finding beyond the
  `PROTOCOL.md` MUST it cited.
- **`peer_operational_keys` is write-only.** Every accepted certificate for every peer accumulates
  but the table is never read (`repositories.py:293-322` insert is the only touch). The durable
  state that would implement the MUST is populated and discarded — a repair can read it directly.

## Fix-direction constraints

- The check must be **stateful across the pin and the peer row**, not per-call-site. The receiver
  holds the prior sequence in `peers.current_certificate_sequence` and in `peer_operational_keys`;
  the decision point is *adoption*, which today occurs in at least three distinct places
  (`verify_candidate`, `resolve`/`pin`, bootstrap) plus the transient `_certificate_for_node`
  live-resolve branch. Patching only `record_operational_key` would leave the transient
  message-path adoption (the corrected trigger) unfixed.
- `_certificate_for_node` deliberately does not persist a pin on the live-resolve branch; a repair
  that only guards writes to `domain_pins` would not cover it. The guard must sit where the
  *certificate is selected for verification*, comparing against the stored prior sequence for that
  node_id.
- Enforcing sequence *without* finding 1's expiry check still allows a stale-but-higher-sequence or
  in-window retired cert; the two MUST clauses are independent and both required.
- `TopologyService.verify_candidate` rejecting a lower sequence must not be a no-op: for a
  first-ever adoption there is no prior sequence, so the check must be "if prior exists and
  new ≤ prior → reject", not "reject unless greater" (which would break first contact).

## Bound

- No live infrastructure: I could not run a real gossip-discovery-then-rollback against a serving
  peer. The corrected trigger is **traced by reading** `_certificate_for_node` /
  `verify_inbound_message` / `verify_candidate`; the end-to-end adoption was not observed at
  runtime.
- Adversary-frequency (possession of a retired operational private key + serving-position control)
  is unverifiable in-tree — stated as SUSPECTED, not demonstrated.
- `cli.py` contacts-import path and `topology.py` lines beyond 370 were not re-read for this
  finding; the claim cited `cli.py:366-367` as an additional unchecked site — not re-adjudicated here.
