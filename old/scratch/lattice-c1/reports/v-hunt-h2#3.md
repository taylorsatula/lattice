# v-hunt-h2#3 — PRIMED VERIFIER

Claim under test: **hunt-h2#3** in `scratch/lattice-c1/reports/hunt-h2.md` (reported tier **L**) —
"Cross-sender message_id collision yields a final rejected receipt; identical-receipt MUST
unimplemented".

Verdict: **CONFIRMED** at tier **L**. Mechanism, trigger, and frequency all reproduced with the
repo's real classes. No severity or frequency correction. Reachability kind: **PRODUCTION** (a real
peer request), subject to the peer-fault condition the finding itself names.

## Frame re-derived independently from source

1. **Schema constraint** — `lattice/migrations/durable/001_initial.sql:142`:
   `message_id TEXT NOT NULL UNIQUE`. Global uniqueness on `message_id` alone; no
   `(message_id, from_node_id)` composite. Confirmed by exact read; `rg` over
   `lattice/migrations/` shows no later ALTER dropping/replacing it.
2. **Dedupe query** — `lattice/storage/repositories.py:918` (`InboundMessageRepository.
   get_existing_receipt`): `SELECT receipt FROM inbound_messages WHERE message_id = ? AND
   from_node_id = ?`. Scoped per sender.
3. **Caller** — `lattice/messages.py:259` (`InboundMessageService.accept`) consults
   `get_existing_receipt(model.message_id, from_node_id)` first; on miss it inserts. Insert failure
   path at `lattice/messages.py:283-290`: only `UNIQUE constraint` substrings are treated as a race;
   the fallback re-queries by `(message_id, from_node_id)`, and on `None` re-raises
   `CustodyError`.
4. **API mapping** — `lattice/api.py:338-345`: `except CustodyError:` builds a fresh `rejected`
   receipt via `build_receipt(..., "rejected")` and returns `JSONResponse(status_code=202, ...)`.
5. **Receipt has no sender field** — `lattice/protocol/models.py:302-313` (`Receipt`): fields
   `kind, message_id, node_id, status, received_at, signature`. Confirmed.

## Reproduction (real classes, real migrated DB)

`InboundMessageService` + `InboundMessageRepository` + `PeerRepository` over
`migrate()`-created SQLite; two independently generated `OperationalIdentity`s:

```
A accepted: accepted shared-id
B -> CustodyError: failed to accept message: UNIQUE constraint failed: inbound_messages.message_id
api 202 rejected: rejected shared-id
A duplicate identical: True
```

Combined with an isolated SQLite check that `str(sqlite3.IntegrityError)` is
`'UNIQUE constraint failed: <table>.<col>'` (so the substring test at `messages.py:285` fires), the
mechanism is closed end-to-end. `tests/test_messages.py::test_duplicate_returns_identical_receipt`
passes (same-sender path returns identical bytes).

## Component adjudication

- **Mechanism** — CONFIRMED. Per-sender dedupe query vs. global UNIQUE constraint; the UNIQUE-race
  fallback re-queries by `(message_id, from_node_id)` and finds nothing for a different sender, so
  `CustodyError` is re-raised and api.py converts it to a 202 `rejected` receipt.
- **Trigger** — CONFIRMED. Requires a second, **signature-valid** message (so sender B must be a
  pinned peer with a resolvable cert — `verify_inbound_message`, `runtime.py:619-663` — signature
  verified before the block check) whose `message_id` equals one already in custody, and B must pass
  the rate limiter. No other defect gates it; one HTTP request.
- **Frequency** — CONFIRMED as the finding states: **LATENT / ungroundable**. Protocol (`docs/
  PROTOCOL.md:218`) makes global id uniqueness the sender's obligation, and no in-tree code
  generates or validates `message_id` format (`rg` for `uuid|token_hex|secrets|randbytes` finds only
  bearer-key generation in `cli.py`); ids are caller-supplied end to end. The population of
  senders that reuse an in-custody id cannot be grounded from the tree. Latent by the frequency
  rule ⇒ capped at L.
- **Severity** — CONFIRMED at **L**, not M. The bad outcome (sender B's message refused custody and
  dropped after the final rejected receipt; deviation from the §5.3/§8 MUST) is real but reached
  only via a sender-side protocol violation, so it is not "plausible normal operation" as M
  requires. Not H: the peer can only lose *its own* message; it cannot touch A's custody
  (`get_existing_receipt`/`create` never overwrite the existing row) and cannot predict A's random
  id, so no cross-peer reach.

## Sub-claims refuted

None of substance. One scope refinement: the finding **title** ("identical-receipt MUST
unimplemented") overstates scope — the same-sender duplicate path *does* return identical bytes
(verified executable). The finding **body** scopes this correctly to the cross-sender case, and that
cross-sender case is exactly the reproduced failure. The MUST cited is `docs/PROTOCOL.md:185` (§5.3)
and `:250` (§8); both were checked and the citations are accurate.

## Additional mechanisms / earlier failure sites on the same trace

1. **The rejected receipt is never persisted.** `api.py:340-344` (and the `BlockedSenderError`
   branch `api.py:295-300`) build the `rejected` receipt on the fly with `received_at = now`, and do
   not store it. `docs/PROTOCOL.md:250` says "The receipt bytes MUST be persisted and returned
   identically for duplicate `message_id` values." Because a rejected receipt is final, no retry is
   expected, so the impact is bounded — but a repair that aims to satisfy the MUST must persist the
   rejected bytes too, or repeated submissions of the same colliding id will produce different
   receipt bytes each call.
2. **The `except Exception` at `messages.py:283` is broader than the UNIQUE case.** Any insert
   failure that does not contain the `UNIQUE constraint` substring is also re-raised as
   `CustodyError` (`messages.py:290`), and `api.py:339` maps *every* `CustodyError` to a final 202
   `rejected`. So a transient storage fault also yields a final rejection and sender-side drop. This
   is documented as intended in `docs/LOOSE_ENDS.md:9` ("custody-insert failures now return HTTP 202
   with a signed `rejected` receipt"), so it is not re-reported here; it is a constraint on any fix
   (see below).

## Fix-direction constraints

- The schema (`UNIQUE(message_id)`) and the dedupe query (`WHERE message_id = ? AND from_node_id =
  ?`) disagree by construction. A repair must reconcile both, not one. Widening the constraint to
  `UNIQUE(message_id, from_node_id)` alone would break the global-uniqueness model the protocol
  assumes and would create two `inbound_messages` rows with the same `message_id`, while
  `webhook_state.message_id` is a PRIMARY KEY with `REFERENCES inbound_messages(message_id)`
  (`001_initial.sql:170-175`) — the webhook idempotency row becomes ambiguous. Returning the stored
  receipt globally instead is implementable (Receipt carries no sender) but would acknowledge B's
  distinct message as accepted, i.e. trade one custody-semantics error for a false acceptance.
- A fix must not broaden the existing blanket `except Exception → CustodyError → 202 rejected`
  mapping (`messages.py:283-290` + `api.py:339`); distinguishing a cross-sender id collision from a
  transient insert failure requires inspecting the specific constraint violation, and the
  LOOSE_ENDS-documented transient-failure behavior must be preserved.
- If the chosen policy is to reject colliding cross-sender messages, the rejected receipt must be
  persisted to satisfy the §8 identical-bytes MUST; if the policy is to return the stored receipt,
  no new persistence is needed but the acceptance semantics for B must be stated.

## Checked and clean

- `InboundMessageService.accept` same-sender duplicate path returns byte-identical stored receipt
  before insert (`messages.py:259-261`) and on the UNIQUE-race fallback (`messages.py:285-288`) —
  correct; `test_duplicate_returns_identical_receipt` passes.
- `Receipt` model has no sender field (`protocol/models.py:302-313`) — the finding's premise for
  "implementable regardless of sender" holds.
- `verify_inbound_message` verifies the signature before the block/blind path
  (`runtime.py:648-663`), so a cross-sender collision reaching `accept` requires a validly signed
  message from a known peer — the finding's "signature-valid" qualifier is accurate.
- `get_existing_receipt` returns `None` when the stored receipt JSON is not a dict
  (`repositories.py:920-924`) — no partial/invalid receipt leak on that edge.
- Outbound custody is unaffected: `OutboundMessageRepository` keys reads by `message_id` only
  (`repositories.py:696`) and `OutboundMessageService.submit` maps UNIQUE to a distinct
  "message already exists" `CustodyError` (`messages.py:130-131`); no inbound/outbound interaction.

## Enumeration

Composed command:

```
rg -n "get_existing_receipt|message_id TEXT NOT NULL UNIQUE|WHERE message_id|INSERT INTO inbound_messages" \
   lattice/storage/repositories.py lattice/messages.py lattice/migrations/durable/001_initial.sql
```

Instance disposition:

| # | Site | Disposition |
|---|------|-------------|
| 1 | `001_initial.sql:142` global `UNIQUE(message_id)` | examined — the constraint under test |
| 2 | `repositories.py:918` per-sender dedupe query | examined — the mismatch |
| 3 | `repositories.py:909` `get` by `message_id` only | examined-clean (used by webhook claim, not accept) |
| 4 | `messages.py:259` accept dedupe consult | examined — the reproduced failure site |
| 5 | `messages.py:285-288` UNIQUE-race fallback re-query | examined — returns None for cross-sender |
| 6 | `api.py:338-345` CustodyError → 202 rejected | examined — the outcome mapping |
| 7 | `api.py:295-300` BlockedSenderError → 202 rejected | examined-clean for this claim (signature-verified gate) |

## Bound

- Could not ground the sender population's `message_id` conventions (protocol mandates global
  uniqueness; no in-tree generator or validator exists). Frequency therefore remains LATENT, as the
  finding states — I neither raise nor lower it.
- Did not reach live federated peers or any deployed node to observe an actual collision; the
  reproduction is in-process against the repo's own classes and migration.
- The exact runtime behaviour of a hypothetical conforming sender that reuses an id is a protocol
  question (whether "duplicate message_id" normatively covers a different-sender message); I read it
  as covered by `docs/PROTOCOL.md:185/250`, but the spec's cross-sender intent is underspecified and
  I cannot settle it from the tree alone.
