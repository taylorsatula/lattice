# v-hunt-f1#2 — PRIMED VERIFIER verdict on finding hunt-f1#2

Claim under test: hunt-f1.md finding 2, tier L — "Gossip batch attribution is always None"
(`lattice/gossip.py:select_batch_to_send`, line 251).

## Verdict: CONFIRMED (tier L unchanged)

Re-derived the frame from source before checking the claim, in this order:

1. **What `list_transient_cards` returns.** `CacheRepository.list_transient_cards`
   (`lattice/storage/repositories.py:551`) runs `SELECT * FROM transient_cards ORDER BY
   received_at` and returns `[dict(row) for row in rows]`. The returned value is a list of plain
   dicts whose keys are exactly the table's columns.
2. **What the table's columns are.** `lattice/migrations/cache_schema.sql:26-31`:
   `transient_cards(node_id, card_json, received_at, expires_at)`. No `introduced_by`. `rg` over
   the whole tree (exit below) finds `introduced_by` in this schema only inside `candidates`;
   the only `ALTER TABLE`-free migration set contains no later column addition.
3. **What the writers supply.** `add_transient_card` (`repositories.py:523`) inserts exactly
   `node_id, card_json, received_at, expires_at`. Both production call sites —
   `gossip.py:145` and `topology.py:276` — call it with that same four-argument signature and
   never pass an introducer. So no row can ever carry the key.
4. **What the reader does.** `select_batch_to_send` appends `row.get("introduced_by")`. Because
   the dict has no such key, `.get` returns `None` for every row.

Mechanism, trigger, and frequency all resolve as the claim states. Sub-claims checked separately:

- **Mechanism (schema/code mismatch, always None):** CONFIRMED. `GossipBatch.attributed_to`
  is `[None, ...]` with one element per selected card, on every call.
- **Trigger (every outbound round):** CONFIRMED. The only production caller is
  `runtime.py:`_send_gossip_batch` (`runtime.py:1102`), invoked once per target from
  `_run_gossip_round`, default `gossip_interval_seconds = 60.0` (`runtime.py:103`).
- **Frequency (demonstrated):** CONFIRMED. Every gossip send round with ≥1 transient row —
  i.e. every round in every deployment once any card has been received/verified.
- **Outcome (always-None, no consumer):** CONFIRMED. `rg "attributed_to"` over the non-scratch
  tree returns only `gossip.py` itself (dataclass field, list construction, append, return) and
  no reader. `runtime.py:_send_gossip_batch` builds the wire payload's `introduced_by` from
  `self.node_id`, not from `batch.attributed_to`, so the field is produced and discarded. No
  cross-peer trust or protocol effect (the wire batch's `introduced_by` is protocol-correctly the
  immediate sender).
- **Harm framing ("structurally inert audit feature, bounded harm"):** CONFIRMED, not refuted.

## Severity correction

None. Tier **L** is correct and I leave it unchanged. The pinned scale places L at "a real defect
with a narrow trigger or a bounded bad outcome: a wrong log/audit field". This is exactly a wrong
local audit field, fully traced and mechanically certain, with a bounded outcome (value discarded,
nothing mislogged). It is not S- (the claim meets the evidence bar; the defect is proven, not
plausible-unproven) and it is below M (no wrong persisted state, no wrong custody, no divergence
between two paths that must agree — nothing consumes the value). Traced.

## Frequency correction

None. Left **demonstrated**: the producing population is "every gossip send round with ≥1
transient card", cadence 60 s default. Traced.

## Refuted sub-claims

None. Every component of the claim (mechanism, trigger, frequency, outcome, bounded-harm framing)
survives the trace. The claim is notable for already stating its own bound ("no production
consumer reads `attributed_to` today") rather than overstating impact.

Reportability note (not a refutation): this is at the lower edge of the calibration bar because
the produced value has no runtime consumer, so the code path executes but no observable end-state
misbehaves today. I do not kill it: the finding is not a bare "code shape" — a concretely wrong
value is produced on every round, the schema/code disagreement is unambiguous, and a working
engineer would either remove the dead field or fix the schema on sight. It is a legitimate L, not
noise.

## Reachability kind

**PRODUCTION.** The path is `runtime._run_gossip_round` → `_send_gossip_batch` →
`gossip.select_batch_to_send` → `CacheRepository.list_transient_cards`, on the daemon's normal
background timer. No test mock is required; a live deployment with any received card reaches it.

## Additional mechanisms / earlier failure sites / new reachability

1. **`.get` masks a schema mismatch that would otherwise abort the round.** Had the line been
   written `row["introduced_by"]`, every send round would raise `KeyError` and no gossip would
   egress. The `.get` turns a fatal schema/code desync into a silent `None`. This is the decisive
   artifact: the mismatch is real and only the defensive accessor hides it.
2. **Attribution is not lost everywhere — only on the send-side transient path.** `receive_batch`
   does record the introducer into `ReceivedCard.introduced_by`, and `accept_candidate` persists it
   into `candidates.introduced_by` (used by `count_candidates_by_introducer` for the 8-per-
   introducer cap, `topology.py:153-154`). So the cap-enforcement path is intact; the loss is
   scoped to `GossipBatch.attributed_to`. The claim's scope is correct.
3. **No new reachability.** No other reader or writer of the field exists (enumeration below).

## Fix-direction constraints

- Adding an `introduced_by` column to `transient_cards` is necessary but **not sufficient**: the
  column is never populated unless both writers thread a value, and `topology.py:276` must obtain
  it from the already-loaded `candidate["introduced_by"]` (in scope at that line via
  `get_candidate`) before the candidate row is removed.
- `gossip.py:145` has `introduced_by` in scope directly.
- A repair that merely deletes the dead field is also valid and lower-risk; the constraint is that
  whichever direction is chosen, the two writers and the one reader must agree, or the `row.get`
  silently yields `None` again.
- Do not "fix" this by changing `.get("introduced_by")` to `["introduced_by"]` without also adding
  the column: that converts a silent None into a `KeyError` that aborts the entire outbound gossip
  round (see Additional mechanism 1).
- No cross-peer trust implication: the field is documented "for local audit/logging, not for
  transitive trust", so the repair carries no trust-boundary requirement.

## Checked and clean

- `transient_cards` schema read in full (`cache_schema.sql`) — four columns, no later ALTER.
- `add_transient_card`, `list_transient_cards`, `get_transient_card` read in full — signatures and
  SQL agree; `SELECT *` returns exactly the table columns.
- Both `add_transient_card` call sites (`gossip.py:145`, `topology.py:276`) read in context.
- Sole production caller `runtime.py:_send_gossip_batch` read in full — reads `batch.cards` only.
- `GossipBatch` dataclass, its construction, and the tests (`tests/test_gossip.py:98,111`) read:
  the tests assert only on `batch.cards`, never `attributed_to`, so the suite does not encode the
  intended attribution value.
- `ReceivedCard.introduced_by` and `candidates.introduced_by` confirmed populated — attribution is
  not lost on the receive/enforcement path.

## Enumeration

Composed command closing the class (all producers, the schema, and all consumers of the field):

```
rg -n "introduced_by" --glob '!scratch/**' .          # writers/readers + schema
rg -n "attributed_to|select_batch_to_send" --glob '!scratch/**' .
rg -n "transient_cards|ALTER TABLE" lattice/migrations/
rg -n "add_transient_card" --glob '!scratch/**' .
```

Instance table:

| Instance | Disposition |
|---|---|
| `cache_schema.sql:12,20` — `introduced_by` in `candidates`, index | examined — different table |
| `cache_schema.sql:26-31` — `transient_cards` columns | examined — no `introduced_by` (root of defect) |
| `repositories.py:523` `add_transient_card` | examined — writes only four columns |
| `repositories.py:551` `list_transient_cards` | examined — `SELECT *`, dicts, no `introduced_by` |
| `gossip.py:145` add site | examined — no introducer passed |
| `topology.py:276` add site | examined — no introducer passed (available as `candidate["introduced_by"]`) |
| `gossip.py:251` read site | finding — always `None` |
| `runtime.py:1102` caller | examined — consumes `batch.cards` only |
| `tests/test_gossip.py:98,111` | examined — assert `batch.cards` only |
| all other `introduced_by` hits | receive/API/candidate-cap path — correct, out of scope for this claim |

## Bound

- No live infrastructure was exercised: the daemon was not run and no request was sent. The trace
  is from code, schema, and the test suite, not observation on the wire. Frequency is grounded in
  the timer default and the call graph, not a measured rate.
- Provider behaviour and upstream strictness are irrelevant to this finding (no network call is
  involved in the defective line).
- Whole-file defects in `repositories.py`, `topology.py`, and `runtime.py` outside the traced
  regions belong to their own passes; the region reads here are sufficient to close this claim.
