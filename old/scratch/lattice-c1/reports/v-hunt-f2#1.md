# v-hunt-f2#1 — PRIMED VERIFIER of hunt-f2 finding 1

Claim under test: **hunt-f2#1 [M] — "Candidate verification accepts expired operational certificates and
expired cards"** (`scratch/lattice-c1/reports/hunt-f2.md`), location
`lattice/topology.py:_verify_against_well_known` / `verify_candidate`.

Verdict: **CONFIRMED** (tier **M**, unchanged). Mechanism, trigger, and outcome all reproduced at the
statement level against the real code. One frequency sub-claim is **overstated** and corrected below; one
enabling detail of the claim (a stopped daemon / nginx-served static well-known) is not needed and is
partially unverifiable.

Reachability kind: **PRODUCTION** — a real network peer `POST`s `/lattice/v1/gossip` and the candidate's
domain serves a well-known document whose operational certificate is past `valid_until`. It is not
gated behind another defect.

---

## Frame re-derived from source (before checking the claim)

- **Candidate intake.** `POST /lattice/v1/gossip` → `api.py:receive_gossip` (api.py:249-285) →
  `GossipService.receive_batch` (gossip.py:63-155). Each card is `PeerCard.model_validate`d
  (gossip.py:82) then handed to `TopologyService.accept_candidate` (gossip.py:125-131). No time
  comparison against `now` on intake.
- **What `accept_candidate` stores.** `expires_at = model.expires_at` (topology.py:186) is written to the
  candidate row and to the transient card (gossip.py:145-150). Nothing rejects a card whose
  `expires_at` is already past.
- **What the card model enforces.** `PeerCard._check_expiry` (models.py:181-192) compares
  `expires_at` only to `issued_at + MAX_PEER_CARD_LIFETIME_SECONDS` (7 days) and to tz-awareness. It
  never compares to wall-clock now. Confirmed by reading.
- **What candidate verification does.** `_run_verify_candidates` (runtime.py:1124-1129, every
  `verify_interval_seconds = 60.0`) → `TopologyService.verify_candidate` (topology.py:201-281) →
  `_verify_against_well_known` (topology.py:283-352). The only certificate check is
  `cert.verify(root_identity)` (topology.py:322); `verify_peer_card` (topology.py:328) calls
  `certificate.verify` again (signing.py:43). `is_valid_at` is **not** called anywhere in
  `topology.py` (`rg -n "is_valid_at" lattice/topology.py` → no match).
- **The one window check in the tree.** `runtime.verify_gossip_sender_card` (runtime.py:563-566) does
  `if not cert.is_valid_at(self._clock.now()): return None`. `rg -n "is_valid_at" lattice/` → definition
  (identity.py:138) and this single call site.
- **Protocol MUSTs.** docs/PROTOCOL.md:61 — "A daemon MUST reject a certificate whose `valid_until` is
  in the past…"; docs/PROTOCOL.md:207 — "Reject if `expires_at` is past." Cert lifetimes are 30 days at
  creation (`cli.py:113-116`, `cli.py:766-771`), bounded ≤90 d (identity.py:256).

### Reproduction (fixture-equivalent, real code paths)

`.venv/bin/python` with real `TopologyService` + tmp durable/cache DBs + `MagicMock(spec=WellKnownResolver)`:

- Remote node cert `valid_from = now-40d`, `valid_until = now-10d` (`cert.is_valid_at(now) == False`);
  card `issued_at = now-1d`, `expires_at = now+1d`.
- `accept_candidate(...) → True`; `verify_candidate(node_id) → VerificationResult` (non-None);
  `peers` row `state == 'verified'`; `peer_operational_keys` row written with
  `valid_until = 2026-05-22T00:00:00Z` (expired); `refresh_topology_slots` puts the node in
  `list_discovery_set()`; `select_gossip_targets()` returns it; `get_transient_card()` is set (it is
  propagated).
- Card-expiry half: card `issued_at = now-5d`, `expires_at = now-2d` (model-valid, lifetime ≤7d) with a
  **valid** cert → `receive_batch` returns `accepted=True`; candidate and transient card are written
  with `expires_at` in the past; `verify_candidate →` result, `state == 'verified'`.

## Sub-claim disposition

| Sub-claim (as written in hunt-f2#1) | Verdict | Decisive artifact |
|---|---|---|
| `cert.verify(root_identity)` is the only certificate check in the topology path; `is_valid_at` absent from `topology.py` | CONFIRMED | topology.py:322 / 328; `rg` shows no `is_valid_at` in file |
| `verify_candidate` never compares `card.expires_at` to `now` | CONFIRMED | topology.py:201-281 — no now-vs-expires_at |
| Card model checks lifetime-vs-issued_at only | CONFIRMED | models.py:181-192 |
| Chain: gossip → `accept_candidate` → 60 s verify → `_verify_against_well_known` passes → VERIFIED + `record_operational_key` + discovery-eligible | CONFIRMED | reproduced end to end |
| Outcome: expired-cert peer durably VERIFIED, enters discovery, is gossiped with | CONFIRMED | reproduced (`state='verified'`, discovery set, transient card) |
| Divergence from the gossip sender path, which rejects the same expired cert | CONFIRMED | runtime.py:563-566 vs topology.py:322 |
| **Frequency: "the operation population is every gossiped card whose node's cert window has lapsed"** | **REFUTED as written / corrected** | `can_accept_candidate` refuses any card for a node already in the peer table (topology.py:144-146), so the population excludes already-known peers |
| Trigger detail "operator shut the daemon down but nginx still serves the static well-known file" | NOT REQUIRED / UNVERIFIED | a still-running daemon with a lapsed cert serves its own expired well-known (`well_known()` returns `runtime.well_known_document`); nginx static-file behavior is out of scope (invariant 7) |

**Refuted sub-claim (named):** the frequency phrase "every gossiped card whose node's cert window has
lapsed" is overstated. `TopologyService.can_accept_candidate` (`topology.py:144-146`) returns `False`
whenever `self._peers.get_peer(node_id) is not None`. A node we already verified cannot be re-admitted as
a candidate, so its lapsed cert is never re-verified at all. The reachable population is narrower:
**a gossiped card for a node not yet in our peer table whose cert has already lapsed** (e.g. a fresh
deployment joining a mesh of long-running, non-rotated nodes). The correction does not change the tier.

## Severity / frequency

- **Severity: M — unchanged.** Outcome is a wrong topology/trust state and a divergence between two
  verification paths that must agree, under a plausible normal operation. It is not an H: the cert is
  still root-signed and the signing key is the certificate's key, so identity is not forged and there is
  no cross-peer read reach. It is more than L: the peer is durably `VERIFIED`, discovery-eligible, and
  propagated, and THREAT_MODEL.md:75-76 makes `valid_until` a revocation boundary ("the attacker can
  sign messages and peer cards as the node until the certificate expires or is rotated"). M's clause
  "wrong state … divergence between two paths that must agree" is met exactly.
- **Frequency: DEMONSTRATED for the mechanism; corrected as to population.** The tree fixes the cert
  lifetime at 30 days (`cli.py`), provides only a manual `keys rotate-operational`, and never validates
  the daemon's own cert (`v-hunt-e1#4`), so "a node running past `valid_until` without rotating" is a
  permitted normal operation; the verifying node then accepts its card on every introduction. Cadence:
  one evaluation per candidate per 60 s verify cycle. The claim's "every gossiped card" is corrected to
  "every gossiped card for a not-yet-known node". The population rate (how many such nodes exist in a
  deployment) is not measurable from the tree — recorded as a bound, not used to demote to L.

## Additional mechanisms / earlier failure sites / new reachability (same trace)

1. **Earlier failure site — intake accepts an already-expired card.** `receive_batch` → `accept_candidate`
   store a card past `expires_at` (PROTOCOL.md:207 MUST). The transient card is re-propagated
   (`select_batch_to_send`, gossip.py:229-258, filters only `exclude`) and the candidate is verified if
   `_run_verify_candidates` wins the race against `expiry_cleanup` (both 60 s, verify registered first in
   `_build_scheduler`, runtime.py:369-385). This is a self-contained defect at the earliest site, before
   any outbound fetch is spent.
2. **No periodic certificate re-validation.** `verify_candidate` runs only for candidate rows; a peer
   verified while its cert was valid stays `VERIFIED` indefinitely after `valid_until` lapses — nothing
   re-checks it and `can_accept_candidate` blocks re-introduction. A repair that only rejects *new*
   expired candidates leaves every already-verified lapsed peer in place. Distinct reachability from the
   claim's, same root cause.
3. **Sequence monotonicity MUST is also unenforced — and inert.** PROTOCOL.md:61 requires rejecting a
   cert whose `sequence` is not greater than the previously accepted one. The topology path never
   compares; `record_operational_key` upserts by `(node_id, sequence)` (repositories.py:293-321) and
   `transition` overwrites `current_certificate_sequence` unconditionally (repositories.py:274-276).
   `rg current_certificate_sequence` shows the column is written but never read in any comparison, so the
   regression is currently harmless — recorded as an unenforced MUST, not as a live defect.
4. **The claim is one site of a systemic class.** The same missing `is_valid_at` was already reported at
   the inbound-message path (`hunt-e1#1`, confirmed M) and the resolution/pin path (`hunt-g1`). The class
   is ~5 cert-consuming sites (`rg` table below); the merge layer should dedupe, and a fix that patches
   only `topology.py` closes one of them.

## Fix-direction constraints

- Rejecting lapsed certs in `_verify_against_well_known` alone does **not** repair the class: the same
  key is still accepted by `resolution.resolve_with_ip` (resolution.py:107), `signing.verify_message`
  (signing.py:58), and `signing.verify_peer_card` (signing.py:43). The check belongs in (or beside)
  `certificate.verify`, or in every consumer.
- The card-`expires_at`-vs-`now` rejection belongs at **intake** (`receive_batch`/`accept_candidate`),
  before the outbound well-known fetch, and must also stop the expired transient card from being
  propagated.
- A repair must add re-validation for **already-verified** peers when their cert lapses; the candidate
  path cannot reach them.
- The `sequence` MUST has no existing consumer of `current_certificate_sequence`; enforcing it requires
  adding the comparison, not just writing the column.
- Do not "fix" by trusting the card's embedded `operational_certificate` — `_verify_against_well_known`
  deliberately verifies the card against the well-known's cert (topology.py:328); the validity window
  must be applied to that same cert.

## Checked and clean

- `cert.is_valid_at` itself (identity.py:138-141): half-open `valid_from <= when < valid_until`, correct.
- `PeerCard._check_expiry` max-lifetime bound (7 d) and tz handling: correct for what it claims; the
  now-vs-expiry check is simply absent (the finding).
- `verify_gossip_sender_card` (runtime.py:536-569): the only path with the window check; correct.
- `accept_candidate` cap arithmetic, self-card and blocked-node rejection: correct (verified by reading
  and by the sibling v-hunt-f2#2 pass).
- `record_operational_key` upsert semantics by `(node_id, sequence)`: correct for storage; it faithfully
  records the expired window it is handed.
- Candidate lifecycle on resolution failure (retained) and on verify failure (removed): correct.
- `list_discovery_set` expires rows with real `datetime.now(UTC)` even when a fake clock is injected —
  noted only because it made a first reproduction attempt return an empty discovery set; not a defect.

## Enumeration

Composed command (closes the class of certificate-consuming sites):

```
rg -n "cert\.verify|certificate\.verify|verify_peer_card|verify_message|is_valid_at" lattice/ --glob '!__pycache__'
```

| # | Site | Window check? | Disposition |
|---|------|---------------|-------------|
| 1 | resolution.py:107 `cert.verify` (well-known / pin) | no | same class — reported `hunt-g1` |
| 2 | topology.py:322 `cert.verify` + :328 `verify_peer_card` | **no** | **claim site — this finding** |
| 3 | protocol/signing.py:43 `verify_peer_card` | no | shared helper; callers 2 and gossip.py:272 |
| 4 | protocol/signing.py:58 `verify_message` | no | same class — reported `hunt-e1#1` |
| 5 | cli.py:366 `cert.verify` (contact import) | no | offline CLI; out of scope for this pass |
| 6 | runtime.py:563-566 gossip sender card | **yes** | examined-clean — the only complete path |

## Side discoveries (single-pass, not priced as findings)

- Expired-card propagation: an already-expired card is stored as a transient card and re-sent by
  `select_batch_to_send` for up to one `expiry_cleanup` interval (60 s). Bounded; overlaps added
  mechanism 1.
- Verify-loop outbound amplification: a candidate whose well-known fetch succeeds but whose cert is
  expired is re-fetched only once (removed on promote); not amplified.

## Bound

- Could not measure the in-deployment rate of lapsed-cert nodes; frequency is grounded to a permitted
  normal operation, not to a measured population.
- Did not run the daemon against live infrastructure; task cadences (60/300 s) and lifetimes (30/90/7 d)
  are from `RuntimeSettings`/constants defaults, operator-overridable.
- The claim's "nginx serves the static well-known after the daemon stopped" variant depends on nginx
  config, which invariant 7 places out of scope; I verified the daemon-running variant instead.
- Whether other nodes enforce cert expiry when consuming our cards (upstream strictness) was not
  reachable from this tree.
