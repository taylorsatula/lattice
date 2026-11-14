# hunt-f2 — topology & peer state machine

Files read end to end: `lattice/topology.py` (507 lines), `lattice/peers.py` (259 lines).
Traced into: `lattice/gossip.py`, `lattice/resolution.py`, `lattice/runtime.py`
(`_pin_bootstrap_peers`, `_run_gossip_round`, `_send_gossip_batch`, `_run_verify_candidates`,
`verify_gossip_sender_card`, `_certificate_for_node`), `lattice/api.py` (`receive_gossip`,
admin routes), `lattice/storage/repositories.py`, `lattice/storage/connection.py`,
`lattice/storage/cache.py`, `lattice/identity.py`, `lattice/protocol/models.py`,
`lattice/protocol/signing.py`, `lattice/config.py`, `docs/PROTOCOL.md` (§ certificate MUSTs).

## Findings

1. [M] — Candidate verification accepts expired operational certificates and expired cards
- Location: lattice/topology.py:_verify_against_well_known / verify_candidate (cert check at
  topology.py:319-324; promotion at topology.py:241-266)
- Evidence: `cert.verify(root_identity)` is the only certificate check — it verifies the
  signature and nothing else; `is_valid_at` appears nowhere in topology.py. Contrast
  lattice/runtime.py:564 (`verify_gossip_sender_card`): `if not cert.is_valid_at(self._clock.now()):
  return None`. Likewise `verify_candidate` never compares `card.expires_at` to `now`.
  docs/PROTOCOL.md line 61: "A daemon MUST reject a certificate whose `valid_until` is in the
  past ...".
- Trigger: any gossip-introduced candidate whose domain still serves its well-known document
  with an operational certificate past `valid_until` (e.g. an operator shut the daemon down but
  nginx still serves the static well-known file; the node's card is still being propagated by
  peers' transient-card stores within its ≤7-day lifetime). Path: peer POSTs gossip card →
  `receive_batch` → `accept_candidate` (card model validates only lifetime-vs-issued_at, not
  expiry-vs-now) → `_run_verify_candidates` (60 s) → `verify_candidate` → `_verify_against_well_known`
  passes (signature valid) → peer created/transitioned to VERIFIED, expired key recorded via
  `record_operational_key`, discovery-eligible.
- Frequency: DEMONSTRATED — the operation population is every gossiped card whose node's cert
  window has lapsed; abandoned-but-still-served nodes occur in normal network operation, and
  the check runs on every candidate verification (60 s cycle).
- Outcome: a peer with expired credentials is durably recorded as VERIFIED, enters discovery
  selection, and is gossiped with — a state the protocol says MUST be rejected. Divergence
  between two verification paths that must agree: the gossip rate-limit path
  (`verify_gossip_sender_card`) rejects the same expired cert that the topology verification
  path accepts.
- Confidence: traced (mechanism, trigger, frequency all verified against the tree; the
  PROTOCOL MUST is quoted verbatim).

2. [L] — Stale candidate demotes a bootstrap-established peer back to verified after restart
- Location: lattice/topology.py:verify_candidate (lines 241-263, `existing is not None` →
  `self._peers.transition(result.node_id, PeerState.VERIFIED, ...)`); interacts with
  lattice/runtime.py:_pin_bootstrap_peers (creates/transitions bootstrap peers straight to
  ESTABLISHED).
- Evidence: `existing = self._peers.get_peer(result.node_id)` / `else:
  self._peers.transition(result.node_id, PeerState.VERIFIED, ...)` — the existing peer's state
  is never inspected; `transition_peer` (repositories.py) overwrites `verified_at` with `now`.
  There is no ESTABLISHED short-circuit.
- Trigger: (a) during uptime, gossip introduces node N whose peer row does not yet exist
  (normal for any peer not yet locally verified) → candidate row written to the persistent
  cache DB; (b) the daemon restarts before the 60 s verify cycle processes it — or while N's
  domain resolution was failing, which retains the candidate (`except ResolutionError` at
  topology.py:224 does not remove it); (c) `_pin_bootstrap_peers` at startup finds no peer for
  N's domain and creates N as ESTABLISHED; (d) the next verify cycle transitions N
  ESTABLISHED→VERIFIED.
- Frequency: DEMONSTRATED-population but a coincidence race — any restart landing inside a
  pending-candidate window for a bootstrap-listed node (candidates for well-known bootstrap
  nodes are exactly what peers gossip most). Restarts are routine (deploys), the window is
  ≤60 s per candidate or longer during a resolution outage.
- Outcome: the config-trusted bootstrap peer is silently demoted from established to
  verified; `verified_at` resets so maturity must re-accrue (7 days), and `_fill_guards`
  drops it from its guard slot at the next 300 s refresh. Self-heals after re-maturing.
- Confidence: traced (mechanism fully verified including `transition_peer`'s verified_at
  overwrite and cache-DB persistence across restarts — `initialize_cache_db` reuses the file
  when the schema hash matches).

3. [M, reachability: TESTS ONLY] — block() does not clear the discovery set; blocked peers keep receiving gossip for up to 24 h
- Location: lattice/topology.py:block (lines 495-507) and select_gossip_targets (lines 467-471);
  lattice/runtime.py:_send_gossip_batch (checks only `peer is None or not peer.endpoints`).
- Evidence: `self._blocks.block(...)` / `self._cache.remove_candidate(node_id)` /
  `self._cache.remove_transient_card(node_id)` / `if self._peers.is_guard(node_id):
  self._peers.demote_guard(node_id)` — no discovery-set removal. `select_gossip_targets`
  returns `[nid for nid in self._cache.list_discovery_set() if nid not in guards]` with no
  `is_blocked` filter, and `_send_gossip_batch` sends regardless of peer state.
  `CacheRepository.remove_from_discovery_set` (repositories.py:586) has zero callers in the
  tree. Discovery rows expire only via `expires_at = now + timedelta(days=1)`.
- Trigger: an operator blocks a node that currently sits in the discovery set. Block writes
  the `blocks` row and sets `peers.state='blocked'` (repositories.add_block), but the
  discovery-set row persists; every gossip round (60 s) keeps POSTing our own card plus the
  full transient-card batch to the blocked node until its discovery row expires (≤1 day).
  `_fill_discovery` excludes blocked peers from new selection but never deletes existing rows.
- Frequency: mechanism DEMONSTRATED; trigger reachability is TESTS ONLY — `TopologyService.block`
  / `BlockStore.block` have no production caller today (no CLI command, no admin route; only
  tests/test_topology.py, tests/test_api.py, tests/test_runtime.py call them). The finding is
  therefore gated on the (documented, tested) block feature gaining its operator surface; a
  repair that only wires the route and ignores this ships the hidden defect underneath.
- Outcome: a containment block is not honored for outbound gossip: the blocked node keeps
  receiving our card and every transient card we hold, for up to 24 hours after the block.
- Confidence: traced (mechanism, trigger path, and the 24 h bound all verified); the only
  unproven component is production reachability of the block operation itself.

## Checked and clean

- **Prefix derivation**: `prefix_from_ip` — IPv4→/24, IPv6→/48, IPv4-mapped IPv6 normalized
  before grouping; invalid text returns None. `prefix_from_endpoints` — hostname-only, applied
  pre-fetch as documented, superseded by the real IP prefix at verification. Both correct;
  hostname-vs-CIDR strings cannot collide in `observed_prefix`.
- **Maturity arithmetic**: `_maybe_promote` requires state VERIFIED, `now - verified_at ≥
  maturity_days`, and `observation_days ≥ maturity_days`; `verified_at or now` fallback
  correctly defers promotion; `record_observation` dedupes by day key and refuses BLOCKED
  peers; promotion is idempotent.
- **Guard slot allocation**: `_fill_guards` demotes non-established/blocked guards, fills the
  lowest free slot among `slots` tracked in-run, respects `guard_count`, no duplicate-slot or
  double-promote path found; ordering by `established_at or now` is stable.
- **Discovery round-robin**: `_fill_discovery` groups by observed prefix with hostname/unknown
  fallback, terminates correctly (`any(by_prefix.values())`), caps at `discovery_count`;
  `select_gossip_targets` truncates discovery and de-dupes against guards. Config wiring
  verified: `guard_count=guard_slots`, `discovery_count=discovery_slots`
  (runtime.py:210-217) — no default-mismatch between TopologyConfig and GossipConfig.
- **Candidate caps (arithmetic)**: all four comparisons in `can_accept_candidate` are correct
  (≥, <) with the intended off-by-one behavior; self-card and blocked-node rejection correct;
  already-known peers excluded. The count-then-insert TOCTOU is noted under Side discoveries.
- **Block semantics on the state machine**: `add_block` atomically writes the blocks row and
  sets `peers.state='blocked'`; `record_observation`'s BLOCKED guard therefore holds;
  `unblock`'s leave-state-blocked contract is documented caller responsibility and has no
  production caller.
- **E4 broad-except sites in topology.py** (5, per `rg -n "except" lattice/topology.py`):
  line 179 (card parse → TopologyError, surfaced as per-card rejection by
  gossip.receive_batch), 214 (candidate card parse → TopologyError + candidate removal),
  303 (root key decode → TopologyError), 313 (well-known root signature → TopologyError),
  323 (`IdentityError` from cert.verify → TopologyError), 333 (verify_peer_card →
  TopologyError). All re-raise or convert; none swallow. `WellKnownDocument.model_validate`
  at ~line 288 has no except, but the resolver (`resolve_with_ip`) already validated the
  identical dict, so a ValidationError there is unreachable with the in-tree resolver.
- **Peer row mapping**: `Peer.from_row` / `_parse_ts` / `_json_loads` handle the stored
  formats correctly; `create_peer` raises on duplicates; `transition` raises on unknown peers.
- **Candidate lifecycle on failure**: card-invalid and verify-failure remove the candidate;
  resolution failure retains it for retry (intended, bounded by 24 h candidate TTL).

## Enumeration

Composed commands and instance tables:

State-transition sites — `rg -n "create_peer\(|\.transition\(|promote_guard\(|demote_guard\(|add_block\(|remove_block\(|add_to_discovery_set\(|remove_from_discovery_set\(" lattice/`:

| # | Site | Disposition |
|---|------|-------------|
| 1 | topology.py:243 `create_peer(VERIFIED)` (verify_candidate) | finding 1 (time-validity gap) |
| 2 | topology.py:253 `transition(VERIFIED)` for existing peer | finding 2 (ESTABLISHED demotion) |
| 3 | topology.py:383 `transition(ESTABLISHED)` (_maybe_promote) | examined-clean |
| 4 | topology.py:417/424 promote_guard/demote_guard (_fill_guards) | examined-clean |
| 5 | topology.py:461 `add_to_discovery_set` (_fill_discovery) | examined-clean (selection) |
| 6 | topology.py:503-506 block cleanup | finding 3 (discovery set not cleared) |
| 7 | peers.py:82 `create_peer`, peers.py:117 `transition` | examined-clean |
| 8 | peers.py:222 `BlockStore.block` → repositories.add_block ('blocked' state write) | examined-clean |
| 9 | peers.py:224 `unblock` (state left 'blocked') | documented contract; no production caller |
| 10 | repositories.py:586 `remove_from_discovery_set` | zero callers — dead method (see finding 3) |
| 11 | runtime.py:478/486 bootstrap create/transition ESTABLISHED | out-of-scope file, traced for findings 1-2; bypass-by-design (config trust) |

Quota/prefix arithmetic sites — `rg -n "count_candidates|count_candidates_by_introducer|count_candidates_by_prefix|max_candidates|discovery_count|guard_count|prefix_from_ip|prefix_from_endpoints|next_slot|expires_at = now" lattice/topology.py`:

| # | Site | Disposition |
|---|------|-------------|
| 1 | topology.py:105-121 `prefix_from_endpoints` | examined-clean |
| 2 | topology.py:126-131 `prefix_from_ip` | examined-clean |
| 3 | topology.py:133-162 `can_accept_candidate` (4 cap comparisons) | examined-clean (arithmetic); TOCTOU → side discovery |
| 4 | topology.py:408-427 `_fill_guards` slot allocation | examined-clean |
| 5 | topology.py:440-456 `_fill_discovery` round-robin | examined-clean |
| 6 | topology.py:461-464 `expires_at = now + 1 day` | examined-clean |
| 7 | topology.py:467-471 `select_gossip_targets` truncation | finding 3 (no blocked filter) |

## Design risks (max 2)

1. **Candidate caps are enforceable only against honest attribution.** `introduced_by` comes
   verbatim from the unauthenticated gossip body (api.py `body.get("introduced_by")`; "recorded
   but never trusted"), and intake prefix grouping uses the card's own hostname — so a single
   identity (rate limit: 30 gossip req/min, 32 cards each) can exceed `max_candidates_per_introducer`
   (8) and `max_candidates_per_prefix` (4) by varying the claimed introducer and card hostnames,
   filling all 256 candidate slots. Total-cap and per-fetch network policy still bound it.
2. **Discovery selection has no liveness input.** `_fill_discovery` deterministically selects
   the oldest verified peers; nothing ever demotes an unresponsive VERIFIED peer (observations
   only gate promotion, not retention), so a dead verified peer permanently occupies a
   discovery slot (default 2) while the circuit breaker silently suppresses its sends.

## Side discoveries (single-pass candidates, not confirmed work)

- `can_accept_candidate` count-then-insert is not atomic: per-statement RLock
  (connection.py `_LockedConnection`) serializes individual statements, but two concurrent
  `receive_gossip` requests (FastAPI sync handlers run in a threadpool) can both pass the count
  checks and both insert, overshooting caps by the concurrency factor. Bounded, transient.
- Verify-loop fetch amplification: candidates retained on resolution failure are retried every
  60 s for their full 24 h TTL, so a filled candidate table yields a sustained ~4 outbound
  HTTPS fetches/sec to gossip-chosen domains.
- `list_transient_cards` / `list_candidates` do not filter by `expires_at`; expired rows are
  visible to senders for up to the 60 s cleanup interval (bounded).

## Bound

- Did not execute the daemon against live infrastructure; runtime task cadences
  (60/300 s) are taken from `RuntimeSettings` defaults, which the operator may override.
- `lattice/cli.py` was searched for block/unblock surfaces (none) but not read end to end —
  it is outside this pass's assigned files.
- Concurrency behavior of the Uvicorn threadpool in the deployed systemd unit (workers=1
  default assumed) was not measured; the TOCTOU side discovery assumes default threading.
