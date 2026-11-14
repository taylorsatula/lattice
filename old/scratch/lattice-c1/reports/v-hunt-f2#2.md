# v-hunt-f2#2 — primed verification of hunt-f2 finding 2

Claim under test: hunt-f2 finding 2 ([L]) — "Stale candidate demotes a bootstrap-established peer back
to verified after restart". Source: `scratch/lattice-c1/reports/hunt-f2.md`.

## Verdict

**ADJUSTED.** The mechanism and the outcome are confirmed. The trigger and frequency, as written, are
refuted: the claim's chain (a)→(d) is internally inconsistent — a node that is bootstrap-listed is
pinned to `ESTABLISHED` at every startup, and `can_accept_candidate` refuses a candidate for any node
that already has a peer row (`get_peer(node_id) is not None`). A pending candidate for a bootstrap-listed
node therefore cannot exist under the routine restart the claim asserts. The real trigger requires the
bootstrap peer's domain to have *failed resolution during one startup* (so no peer row is created and
gossip can admit a candidate), followed by a later restart where resolution succeeds. Tier left at **L**.

## Re-derived frame

- `TopologyService.verify_candidate` (`lattice/topology.py:201-278`): on success, `existing =
  self._peers.get_peer(result.node_id)`; if `None` it `create_peer(..., VERIFIED, ...)` (`:243`); if not
  `None` it calls `self._peers.transition(result.node_id, PeerState.VERIFIED, ...)` (`:253`) with **no
  inspection of `existing.state`**. Read end to end; confirmed.
- `PeerRepository.transition_peer` (`lattice/storage/repositories.py:245-296`): builds `state = ?`,
  and for `"verified"` appends `verified_at = ?` with `ts = now` (`:262-271`). `established_at` is not
  touched. Confirmed.
- `RuntimeCoordinator._pin_bootstrap_peers` (`lattice/runtime.py:412-482`): for each configured
  bootstrap URL, if `get_peer_by_domain(domain)` is `None`, it resolves and then `create_peer(...,
  ESTABLISHED, ...)` (or `transition(..., ESTABLISHED, ...)` if the node_id is already known). It never
  removes a candidate row (`_cache.remove_candidate` appears nowhere in the function).
- `TopologyService.can_accept_candidate` (`lattice/topology.py:133-162`): `if self._peers.get_peer(node_id)
  is not None: return False`. So once a bootstrap peer is pinned, gossip cannot reintroduce it as a
  candidate.
- Candidate persistence: `lattice/storage/cache.py:34-70` reuses the cache DB file when the schema hash
  matches; the `candidates` table (`lattice/migrations/cache_schema.sql:10`) survives restart. Candidate
  TTL is 24 h (`candidate_expiry_seconds`), verify cycle 60 s, refresh cycle 300 s, maturity default 7
  days (`ESTABLISHED_MATURITY_DAYS`, `lattice/protocol/constants.py:30`).

Empirical reproduction (fixture-equivalent `TopologyService`, tmp durable+cache DBs, fake clock):
accept a valid card for node N while N has no peer row → `count_candidates == 1`; then create N as
`ESTABLISHED` (as pinning would) without clearing candidates; then `verify_candidate(N)` →
`state == verified`, `verified_at == now`, `established_at` retained, candidate removed. Demotion
confirmed at the statement level.

## Corrections

### Severity — unchanged (L)

Trace: outcome is a wrong peer state under a narrow coincidence. The peer is demoted
`ESTABLISHED → VERIFIED`, `verified_at` is overwritten with `now`, so `_maybe_promote`
(`topology.py:369-384`) refuses promotion for the 7-day maturity window; `_fill_guards`
(`topology.py:401-427`) sees it absent from `list_by_state(ESTABLISHED)` and calls `demote_guard` at the
next 300 s refresh, freeing its guard slot. The peer remains `VERIFIED` and is still discovery-eligible
(`_fill_discovery`, `:430-465`), and `observation_days` persist, so it self-heals after maturity
re-accrues. No data loss, no auth/trust bypass, no cross-peer reach. Narrow trigger + bounded,
self-healing outcome = **L**. Left unchanged.

### Frequency — corrected (claim: DEMONSTRATED routine restart → actual: narrow coincidence)

Refuted half of the claim: "any restart landing inside a pending-candidate window for a
**bootstrap-listed** node". For a node that is bootstrap-listed in the running config, the window cannot
exist: at every `start()` the pin creates its peer row before the scheduler runs, and
`can_accept_candidate` then rejects its card. "Candidates for well-known bootstrap nodes are exactly what
peers gossip most" is true of gossip traffic but does not produce a *stored* candidate for a pinned node.

The reachable trigger is narrower:
1. Run A: bootstrap URL for N fails to resolve at `start()` (`ResolutionError` → `continue`, no peer row).
   Gossip admits N's genuine card → candidate row (persisted in cache DB). `verify_candidate` fails
   resolution → keeps the candidate.
2. Restart into Run B while that candidate is unexpired (24 h) and N's domain now resolves: pin creates
   N as `ESTABLISHED`.
3. First 60 s verify cycle in Run B processes the surviving candidate → `transition(VERIFIED)` → demotion.

So the coincidence is *a transient bootstrap-resolution failure across one startup* (or an operator
adding N to the bootstrap list while a candidate for N already exists), not "restarts are routine".
Frequency is **not** groundable to a demonstrated operation population — ground it as LATENT, capped at
L: the leading event is a bootstrap DNS/resolution outage at process start, whose rate this pass cannot
measure. Reachability kind: **PRODUCTION, gated on a bootstrap-resolution failure at an earlier startup**.

### Sub-claims

- CONFIRMED: `verify_candidate` transitions an existing peer to `VERIFIED` without inspecting its state
  (`topology.py:241-266`).
- CONFIRMED: `transition_peer` overwrites `verified_at` with `now` and leaves `established_at` intact
  (`repositories.py:262-271`).
- CONFIRMED: no `ESTABLISHED` short-circuit exists.
- CONFIRMED: candidate rows persist across restart when the cache schema hash is unchanged
  (`cache.py:44-49`).
- REFUTED: trigger step (a) "gossip introduces node N whose peer row does not yet exist (normal for any
  peer not yet locally verified)" combined with step (c) "bootstrap-listed node". A bootstrap-listed node
  is pinned at startup; it cannot be "not yet locally verified" in the same config that pins it.
- REFUTED: frequency "DEMONSTRATED-population ... any restart landing inside a pending-candidate
  window".
- CONFIRMED with numbers: outcome (`verified_at` reset, 7-day maturity, guard dropped at ≤300 s,
  self-heal).

## Additional mechanisms / earlier failure site

1. **Root cause is asymmetric candidate cleanup, not the missing state guard.** `_pin_bootstrap_peers`
   creates/transitions a peer without clearing any candidate row keyed by the same `node_id`, whereas
   `verify_candidate` removes its own candidate on success (`topology.py:275`). The pinning path is where
   the peer and candidate are allowed to coexist; the demotion in `verify_candidate` is the downstream
   sink. A guard only at `verify_candidate` treats the symptom.
2. **Certificate-sequence regression (unverified, side observation).** The demoting `transition` also
   writes `current_certificate_sequence = result.certificate_sequence` from the (stale) candidate card,
   which may be lower than the sequence the bootstrap pin read from the live well-known document. I did
   not verify whether the sequence is later used in a comparison where regression matters; flagged as a
   single-pass candidate, not a finding.
3. **Bootstrap-transient-card asymmetry.** `_pin_bootstrap_peers` does not add a transient card either,
   so the pinned peer is not propagated via gossip until some other path adds it. Not a defect here
   (bootstrap is config, not gossip), noted for completeness of the pinning gap.

## Fix-direction constraints

- Fix at the pin site as well as the verify site: pinning a node must clear a surviving candidate for the
  same `node_id` (or `verify_candidate` must refuse to transition a peer whose state is `ESTABLISHED`,
  updating only metadata). Either alone leaves the other direction open.
- The repair must not reset `verified_at` when the peer is already established; maturity is derived from
  `verified_at` + persisted `observation_days`, so a metadata refresh that rewrites `verified_at` is the
  harm regardless of how the candidate leaked in.
- Do not fix by special-casing bootstrap node IDs; the same coexistence can arise from any future path
  that creates a peer without consuming its candidate.

## Checked and clean

- `can_accept_candidate` peer-existence check (`topology.py:144-146`): correctly excludes already-known
  peers; this is the reason the claim's stated frequency fails, and it is itself correct.
- `PeerRepository.transition_peer` timestamp semantics for `verified`/`established`/`blocked`: verified
  and established timestamp columns are set independently; no cross-clearing. Correct as written; the
  overwrite is the intended "record the moment of this transition", which is correct for a genuine first
  verification and only harmful when applied as a downgrade.
- `_maybe_promote` (`topology.py:369-384`): requires `state == VERIFIED`, age since `verified_at`, and
  `observation_days`; consistent with the observed re-maturity.
- `_fill_guards` demotion of non-established guards (`topology.py:410-415`): correctly drops the demoted
  peer; the guard loss follows deterministically.
- `initialize_cache_db` hash reuse (`cache.py:34-70`): schema-hash-stable reuse confirmed; candidate
  persistence across restart is real, not assumed.
- Reuse of the demotion sink by other paths: no other in-tree creator of `ESTABLISHED` peers
  (`rg` below shows `_maybe_promote` transitions from an already-existing peer, so it cannot coexist with
  a candidate). The bootstrap pin is the only coexistence source.

## Enumeration

Composed command:

```
rg -n "verify_candidate|remove_candidate|create_peer|\.transition\(|is_valid_at|PeerState\.(ESTABLISHED|VERIFIED)" \
   lattice/topology.py lattice/runtime.py lattice/gossip.py lattice/peers.py
```

Instance table (peer-creation and candidate-lifecycle sites that could produce the coexistence):

| # | Site | Disposition |
|---|------|-------------|
| 1 | topology.py:243 `create_peer(VERIFIED)` | examined-clean — candidate is the source, removed at :275 |
| 2 | topology.py:253 `transition(VERIFIED)` for existing peer | **claim site** — missing ESTABLISHED guard |
| 3 | topology.py:275 `remove_candidate` on success | examined-clean |
| 4 | runtime.py:464 `create_peer(ESTABLISHED)` (bootstrap pin) | **earlier failure site** — does not clear candidate |
| 5 | runtime.py:473 `transition(ESTABLISHED)` (bootstrap pin, known node) | examined-clean — node already a peer, no candidate can coexist |
| 6 | topology.py:383 `transition(ESTABLISHED)` (_maybe_promote) | examined-clean — peer already exists |
| 7 | runtime.py:1127 `verify_candidate` caller (_run_verify_candidates, 60 s) | examined-clean — iterates all candidates regardless of peer state |
| 8 | runtime.py:564 `cert.is_valid_at` (unrelated path) | out of scope — subject of finding 1 |

## Bound

- Could not measure the in-deployment rate of bootstrap-domain resolution failure at process start; the
  corrected frequency is therefore LATENT, not demonstrated.
- Did not execute the daemon against live infrastructure; task cadences (60/300 s) and maturity (7 d) are
  from `RuntimeSettings`/`TopologyConfig` defaults, overridable by the operator.
- Did not read `lattice/cli.py` end to end; the "operator adds a bootstrap entry" variant is inferred
  from config shape, not from a traced CLI surface.
- The certificate-sequence-regression side observation (additional mechanism 2) is unverified: I did not
  trace whether a lower `current_certificate_sequence` has a downstream consumer whose comparison breaks.
