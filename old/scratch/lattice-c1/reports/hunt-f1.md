# hunt-f1 — gossip propagation (lattice/gossip.py)

Pass type: blind hunter. Read `lattice/gossip.py` end to end (287 lines, complete), then traced
all callees (`TopologyService.accept_candidate`, `CacheRepository`, `PeerCard` model,
`verify_peer_card`/`sign_peer_card`) and all production callers (`api.py:receive_gossip`,
`runtime.py:_run_gossip_round`/`_send_gossip_batch`/`verify_gossip_sender_card`,
`rate_limit.py:RateLimiter`).

## Findings

1. [M] — Self-attested first card defeats gossip rate limiting
- Location: lattice/api.py:receive_gossip (keying) + lattice/runtime.py:verify_gossip_sender_card
  (verification), reached on the gossip receive path this pass was assigned.
- Evidence: api.py:264 `peer_id = sender_node_id or _peer_ip(request)`; runtime.py docstring:
  "Verification is self-consistent: the card's operational certificate must be signed by the root
  key the card itself advertises".
- Trigger: any network peer POSTs `/lattice/v1/gossip` (public fixed route, invariant 3) with
  `cards[0]` a freshly minted card — attacker generates an Ed25519 root keypair, self-signs an
  operational certificate, derives its own node_id, signs the card. Every field validates because
  nothing is checked against pinned or externally fetched state. Each distinct minted identity
  gets a brand-new gossip token bucket (capacity = `gossip_per_minute` = 30 tokens, default
  config), so the IP fallback is never reached and effective request rate is unbounded. A second
  trigger with the same root cause: replay a real peer's public card as `cards[0]` to drain that
  victim's bucket on our node, so the victim's genuine gossip round then receives 429 and
  `_send_gossip_batch` records a circuit failure against the victim.
- Frequency: DEMONSTRATED — the entire hostile-peer population of the public gossip route; one
  HTTP request per minted identity, each costing microseconds of attacker-side keygen. In a
  federation visible on the internet this is continuous background traffic, not a coincidence.
- Outcome: (a) the gossip rate limit — the endpoint's only quota enforcement — does not limit a
  hostile sender at all; (b) `RateLimiter._buckets` (rate_limit.py:99) is a dict with no
  eviction policy, keyed by attacker-chosen node_id strings, so buckets accumulate without bound
  and are persisted/restored via `save_rate_bucket` across restarts; (c) a victim peer's bucket
  can be drained and its gossip circuit opened by a third party (cross-peer effect: the victim's
  `record_observation` stops, retarding its maturity).
- Confidence: traced (mechanism, trigger, frequency all verified in code: `verify_gossip_sender_card`
  builds `RootIdentity` from the card's own `root_public_key`; `RateLimiter` has no deletion path).
  Note: docs/PROTOCOL.md §5.2 prescribes exactly this scheme ("verify it ... and rate limit gossip
  by its node ID"), so a repair is a protocol decision as much as a code change — the
  implementation faithfully matches a spec whose trust assumption (identity minting is costly)
  does not hold. Flagged in Disputes below.

2. [L] — Gossip batch attribution is always None
- Location: lattice/gossip.py:select_batch_to_send (line 251, `row.get("introduced_by")`).
- Evidence: `attributed_to.append(row.get("introduced_by"))` — but the `transient_cards` table
  (lattice/migrations/cache_schema.sql:26-31) has only `node_id, card_json, received_at,
  expires_at`; there is no `introduced_by` column, and `add_transient_card`
  (repositories.py:523-541) never records one.
- Trigger: every outbound gossip round — `runtime.py:_run_gossip_round` (default every
  `gossip_interval_seconds` = 60s) calls `select_batch_to_send`, which reads every transient-card
  row and collects `row.get("introduced_by")`, which is `None` for every row.
- Frequency: DEMONSTRATED — every gossip send round in every deployment, for every card.
- Outcome: `GossipBatch.attributed_to` is always a list of `None`s; the attribution the docstring
  promises ("Includes attribution only for local audit/logging") is silently lost. Bounded harm:
  no production consumer reads `attributed_to` today (only gossip.py itself references it), so
  nothing is mislogged — but the audit feature is structurally inert.
- Confidence: traced (mechanism verified against the schema; outcome verified by enumerating all
  readers of `attributed_to`).

## Checked and clean

- **Per-card failure isolation (E4, gossip.py:92)**: an invalid card produces a `ReceivedCard`
  with `accepted=False, reason="invalid card: ..."` and `continue`; the batch proceeds and the
  rejected tally counts it. No abort, no silent drop, no tally corruption.
- **Per-card failure isolation (E4, gossip.py:130)**: `accept_candidate` raising produces a
  rejected result with reason `"accept failed: ..."` and `continue`; isolation holds. (Note
  `TopologyService.accept_candidate` re-validates and raises `TopologyError` for invalid cards,
  but `receive_batch` pre-validates with the same `PeerCard` model, so this branch is only hit on
  DB-layer errors — reachable, handled.)
- **Per-card failure isolation (E4, gossip.py:246)**: outbound — a transient card row whose
  `card_json` fails `json.loads` or is not a dict is silently skipped from the outbound batch.
  There is no tally on the send path; the skip is bounded and does not affect the receiver. Clean
  as designed.
- **Batch bounds before any card works**: `receive_batch` slices `cards[:MAX_GOSSIP_BATCH_SIZE]`
  (32) before the loop; `api.py:receive_gossip` additionally 400s any body with more than 32
  cards, so the slice is defense-in-depth, never exercised via HTTP. Body size bounded by
  `require_content_length(MAX_GOSSIP_BODY_BYTES)` before rate limiting.
- **Self-card refusal**: `model.node_id == self._identity.node_id` is rejected before topology
  intake, and `can_accept_candidate` independently refuses the local node_id — two layers, both
  correct. Our own card therefore can never enter the transient store and be re-gossiped.
- **Card authenticity at receive**: no signature verification at intake is by design — cards
  become candidates awaiting independent well-known verification (`verify_candidate`), which does
  the full chain (root signature, node-id derivation, cert, card signature). The transient
  re-gossip of unverified cards is explicitly commented as intended (see Design risks).
- **Card lifetime bound**: `PeerCard._check_expiry` rejects any card whose `expires_at` exceeds
  `issued_at + MAX_PEER_CARD_LIFETIME_SECONDS` (7 days), so neither candidates nor transient
  cards can be planted with far-future expiry. (Cards already expired or with future
  `issued_at` do pass validation; they are pruned on the next `expiry_cleanup` cycle — noted,
  bounded, not reported.)
- **Candidate caps**: 256 total / 8 per introducer / 4 per prefix enforced in
  `can_accept_candidate` before any storage; `add_candidate` upserts on `node_id`, so duplicate
  cards in one batch cannot raise integrity errors into the reject path.
- **Invariant 6 (no relay beyond peer cards)**: `select_batch_to_send` reads only the
  `transient_cards` table; message bodies never enter gossip. `receive_batch` stores only
  peer-card JSON. No relay path exists.
- **build_own_card**: root public key only (invariant 2 respected — no root private key touched
  in the daemon); endpoint lookup `endpoints["gossip"]/["messages"]` is supplied by
  `runtime._run_gossip_round` from config at the only call site; card is signed with the
  operational key via `sign_peer_card`. Time formatting is self-consistent (the signed dict is
  the emitted dict).
- **Rate-limit consumption order (api.py)**: batch-shape checks and rate limiting occur before
  `receive_batch` does any storage work; 429 carries a proper problem-details body.
- `sign_card` and `verify_card_against_pin` have no production callers (public helpers); not
  reportable, noted for coverage.

## Enumeration

Composed command (closes the exception-handling class in the assigned file and the call graph
around it):

```
rg -n "except " lattice/gossip.py
rg -n "receive_batch\(|add_transient_card\(|list_transient_cards\(|select_batch_to_send\(|build_own_card\(" lattice/ tests/ | grep -v "def "
```

Exception sites in gossip.py (the class is closed — exactly three):

| Site | Context | Disposition |
|---|---|---|
| gossip.py:92 | `PeerCard.model_validate` in `receive_batch` | examined-clean (E4) |
| gossip.py:130 | `topology.accept_candidate` in `receive_batch` | examined-clean (E4) |
| gossip.py:246 | `json.loads(row["card_json"])` in `select_batch_to_send` | examined-clean (E4) |

Call-graph instances (all production callers traced):

| Instance | Disposition |
|---|---|
| `receive_batch` ← api.py:267 (only production caller) | traced; feeds findings 1 and 2 |
| `add_transient_card` ← gossip.py:145, topology.py:276 | traced; neither records `introduced_by` (finding 2) |
| `list_transient_cards` ← gossip.py:240 (only caller) | traced |
| `select_batch_to_send` ← runtime.py:1102 (only production caller, limit=16) | traced |
| `build_own_card` ← runtime.py:1083 (only production caller) | examined-clean |

## Design risks (max 2)

1. **Unverified transient cards are re-gossiped.** `receive_batch` stores an accepted card as a
   transient card "even before independent verification completes", and `select_batch_to_send`
   forwards transient cards to neighbors. A forged but well-formed card therefore transits at
   least two hops (attacker → us → our neighbors) before any well-known verification occurs
   anywhere. Intake caps (256/8/4) bound the volume, and the code comment marks it intended, so
   this is a documented design choice — but it makes every node a willing relay for unverified
   claims, and amplifies the propagation of junk candidates network-wide.

## Side discoveries (single-pass candidates, not confirmed work items)

1. **`candidate_ttl_seconds` config is dead** — `runtime.py:216` passes
   `config.gossip.candidate_ttl_seconds` into `TopologyConfig(candidate_expiry_seconds=...)`,
   but nothing reads it: `TopologyService.accept_candidate` (topology.py:190-210) sets the
   candidate row's expiry to the *card's self-declared* `expires_at` (model-bounded to 7 days
   after the card's own `issued_at`). Consequence reachable via gossip receive today: an
   adversary can fill all 256 candidate slots with cards declaring ~7-day validity, and because
   `_run_verify_candidates` leaves candidates in place on `ResolutionError` (topology.py raises
   without removing), those slots — plus a repeating well-known fetch to attacker-chosen domains
   every `verify_interval_seconds` — persist for up to a week, starving genuine peer discovery
   despite the operator's 24h TTL. Site is topology.py, outside this pass's assigned file;
   a topology-focused pass should confirm.

## Bound

- Assigned file `lattice/gossip.py` was read end to end in full; no lines skipped.
- `lattice/runtime.py`, `lattice/api.py`, `lattice/rate_limit.py`, `lattice/topology.py`,
  `lattice/storage/repositories.py`, `lattice/protocol/{models,signing,constants}.py`,
  `lattice/migrations/cache_schema.sql` were read only along the gossip call graph (regions
  cited above), not end to end — whole-file defects in those files outside the traced paths
  belong to their own passes.
- No live infrastructure: I did not run the daemon or send requests; all triggers are argued
  from code and the pinned protocol spec, not observed on the wire.
- `docs/PROTOCOL.md` was consulted only for §5.2/§6 (gossip and peer-card sections).
