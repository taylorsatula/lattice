# v-hunt-b1c#4 — primed verifier

**Claim under test:** `hunt-b1c#4` in `scratch/lattice-c1/reports/hunt-b1c.md`, reported tier **L**,
reported frequency **LATENT**:

> Transient custody-write failure is converted into a final signed "rejected" receipt.

**Frame re-derivation performed before accepting the claim's phrasing.** The decisive facts
were read from source, not from the finding:

- `receive_message` (`lattice/api.py:283-353`) catches `CustodyError` from
  `InboundMessageService.accept` at line 339 and returns a **signed** receipt with
  `status="rejected"` and HTTP `202` (lines 341-345). It is *not* persisted: `build_receipt`
  signs, the handler returns; no `repo.create` / receipt-store call runs (grep for `rejected`
  under `lattice/` shows only `build_receipt` call sites — no store of rejected receipts).
- `InboundMessageService.accept` (`lattice/messages.py:246-291`) raises `CustodyError` only on
  (a) `Message.model_validate` failure (line 257) and (b) any `repo.create` `Exception` that is
  not a UNIQUE-constraint race (lines 289-290). By the time `accept` runs, `verify_inbound_message`
  (`lattice/runtime.py:632-636`) has already run `Message.model_validate`; a validation failure
  there raises `RuntimeError` → HTTP 401 at `api.py:301-302`. So on this route the *only* live
  producer of the `CustodyError` branch is a non-UNIQUE failure inside `InboundMessageRepository.create`.
- `InboundMessageRepository.create` (`lattice/storage/repositories.py:870-906`) does one
  `INSERT`; its only constraint that the pre-insert path does not already satisfy is the
  `message_id UNIQUE`, which is handled above it. `ensure_root_history` (called at
  `messages.py:270`) always inserts the FK parent (`ON CONFLICT DO NOTHING`,
  `repositories.py:161-172`), so the `peer_root_history` FK cannot fire. The remaining producers
  are SQLite/OS-level errors (`sqlite3.OperationalError` disk-full / I/O error, or
  `database is locked` after the 5000 ms `busy_timeout`, `storage/connection.py:70-74`).
- `docs/PROTOCOL.md` §8 (lines 237-251): `status` is `"accepted"`/`"rejected"`; "A `rejected`
  receipt indicates the destination node will not take custody (e.g., recipient blocked, message
  malformed after signature check). A `202 Accepted` with a rejected receipt is final."
- In-tree sender: `_send_outbound_message` (`lattice/runtime.py:977-993`) treats any 202 whose
  `status != "accepted"` as `record_failure(..., retryable=True)`; `record_failure`
  (`messages.py:158-198`) retries until `RetryPolicy.max_attempts = 10`, then marks `failed` and
  erases content.

## Findings

1. **[L] — CONFIRMED** — Transient custody-write failure is signed and returned as a final
   `rejected` receipt (202), not a retryable 5xx.

- Location: `lattice/api.py:receive_message` lines 337-345 (the `except CustodyError` block);
  root cause `lattice/messages.py:InboundMessageService.accept` lines 289-290.
- Evidence:
  - `accept`: `except Exception as exc: ... raise CustodyError(f"failed to accept message: {exc}") from exc`
  - handler: `except CustodyError:` → `build_receipt(..., "rejected")` → `JSONResponse(status_code=202, content=rejected)`
  - PROTOCOL §8: "A `202 Accepted` with a rejected receipt is final."
- Trigger (runtime path): an operator-run node whose durable SQLite DB hits a non-UNIQUE write
  failure *at the moment* `InboundMessageRepository.create` executes for an already
  signature-verified, rate-limit-admitted inbound message (disk full, I/O error during commit,
  or `database is locked` after 5 s while another process — e.g. a concurrent `lattice` offline
  CLI command holding a write txn — holds the write lock). The `except IOException/OperationalError`
  branch is entered, `CustodyError` is raised, and the handler signs a `rejected` receipt without
  ever having written a row. Signature verification, block check, ownership check and rate limit
  all precede the write and all pass, so the failure is purely infrastructural.
- Frequency: **LATENT (DEMONSTRATED mechanism / ungroundable cadence).** The producer is an
  infra fault; no operation population or cadence in the tree produces it deterministically. The
  concurrent-CLI contention variant is plausible but bounded by the 5 s busy timeout and I cannot
  ground its cadence either. Per the calibration rule this caps the finding at L.
- Outcome: A transient condition that a retry would recover is reported to the sender as a
  deliberate, final refusal. A §8-compliant sender stops retrying → permanent message loss. The
  in-tree sender's `_send_outbound_message` instead treats `status != "accepted"` as retryable and
  retries (up to 10 attempts over ~30 h), so within this repository a *single* transient error
  self-heals on the next attempt — the lasting harm is confined to protocol-compliant external
  senders. (If the DB failure persists, the in-tree sender also exhausts 10 attempts and erases,
  but that is the ordinary consequence of a persistent failure, not of the misreported finality.)
- Confidence: **traced** for mechanism, trigger, and the in-tree sender's handling. The
  *frequency* is unproven by construction (infra fault). Nothing about this path is test-only or
  gated: `tests/test_api.py` covers only the blocked-sender `rejected` receipt (line 281+); no
  test exercises the `except CustodyError` branch.
- Reachability kind: **PRODUCTION** (triggered by a live OS/SQLite write failure, not by the test
  suite and not gated behind another finding).

### Sub-claims

- Mechanism ("non-UNIQUE `repo.create` failure is wrapped in `CustodyError` and answered with a
  signed `rejected` 202"): **CONFIRMED**, `messages.py:289-290` → `api.py:339-345`.
- "rejected receipt is final per §8, sender stops retrying": **CONFIRMED** as the protocol's own
  text (`docs/PROTOCOL.md:250`).
- "in-tree sender treats a non-`accepted` receipt as a retryable failure": **CONFIRMED**,
  `runtime.py:977-993` → `messages.py:163-198`.
- "no loss inside this codebase": **CONFIRMED with a stated bound** — true for a transient fault
  (retry succeeds) but not for a persistent one (10 exhausted attempts erase the payload). The
  claim's "transient" qualifier keeps this accurate.
- No sub-claim refuted. Severity **L** and frequency **LATENT** left unchanged; the trace
  reproduces both. No correction issued.

## Additional mechanisms / earlier failure sites (same trace)

- **Rejected receipts are never persisted, so §8's byte-identical duplicate guarantee is not
  honored on this path.** Both `api.py:296-300` (blocked sender) and `api.py:341-345`
  (CustodyError) sign a fresh receipt (fresh `received_at`) and return it without storing it,
  while PROTOCOL §8 says "The receipt bytes MUST be persisted and returned identically for
  duplicate `message_id` values." Consequence on the finding-#4 trace: after the write failure
  clears, the same `message_id` is re-attempted and now yields an **`accepted`** receipt — two
  contradictory signed receipts for one `message_id`, the first unrecorded. Severity **L**,
  frequency **LATENT** (requires the infra-failure trigger); fix-direction constraint: if a
  rejected receipt is declared final it must be durably recorded so a later accept for the same
  `message_id` is refused (or the receipt must be re-emitted identically).
- **Sender/destination semantics diverge on "final".** The destination signs `rejected` as final
  (§8) while the in-tree sender retries it as transient (`runtime.py:985-993`). Reachable in
  PRODUCTION whenever a peer rejects (blocked us, or sent a malformed-after-signature message):
  the sender burns up to 10 delivery attempts across ~30 h and then erases the payload. Severity
  **L** (wasted work, bounded; no corruption). Fix-direction constraint: choose one semantics and
  apply it to both sides — the infra-failure fix (return 5xx) makes the sender's retry correct
  for that branch, but the `rejected`-is-retryable behavior still contradicts §8 for the
  deliberate-refusal branch.

## Fix-direction constraints (beyond the reported symptom)

- A correct repair must separate *cannot establish custody right now* from *will not take
  custody*. The latter is §8's `rejected` (final); the former must return a retryable status
  (503/5xx) so a compliant sender retries. Returning a `rejected` receipt for an infra failure —
  which is what the branch does today — is the defect, and simply catching more exception types
  does not address it.
- The repair must also resolve the finality/idempotency contract: a `rejected` receipt that is
  final must be durably recorded, or a later `accepted` receipt for the same `message_id`
  contradicts it. Today no rejected receipt is stored anywhere.
- Any repair on the destination side must decide the sender-side counterpart, because the
  in-tree sender currently retries a `rejected` receipt while the destination declares it final.

## Checked and clean

- `verify_inbound_message` (`runtime.py:632-636`) validates the message *before* `accept`, so the
  `CustodyError` branch on this route cannot be reached by a merely malformed body — the claim's
  "signature-verified" trigger qualifier is accurate.
- `ensure_root_history` always inserts the `peer_root_history` parent (`ON CONFLICT DO NOTHING`),
  so the inbound `FOREIGN KEY` cannot spuriously fire and be wrapped as a `CustodyError`; it is not
  an alternative producer.
- `except RuntimeError` at `api.py:346` cannot shadow `except CustodyError` (`CustodyError`
  subclasses `ValueError`, `messages.py:24`), and the order is correct.
- `get_existing_receipt` idempotency: an already-custodied `message_id` returns the stored receipt
  before `create`, so the rejected-receipt path cannot overwrite an existing accepted custody row.

## Enumeration

Composed command closing the class of reachable `CustodyError` producers on the inbound route:

```
rg -n "raise CustodyError|except CustodyError|except BlockedSenderError|except RuntimeError|build_receipt|repo\.create" lattice/messages.py lattice/api.py
```

Output (relevant): `messages.py:257` (`model_validate` — pre-empted by `verify_inbound_message`),
`messages.py:290` (`failed to accept message` — the live producer), `api.py:293/339`
(`BlockedSenderError` / `CustodyError` handlers), `api.py:296/341` (`build_receipt` rejected
call sites). Dispositioned: only `messages.py:290` reaches the `except CustodyError` branch on a
signature-verified production message; the other `CustodyError` sites (`messages.py:107,131,174,353`)
are outbound / lookup paths not on this route.

Composed command confirming no persisted rejected receipt:

```
rg -n "rejected" lattice/ --glob '!**/__pycache__/**' --glob '!tests/**'
```

Output: only `models.py:310` (`Receipt.status` literal), `runtime.py:63-64` (docstring),
`api.py:298/343` (`build_receipt` call sites), `api.py:269/277` (gossip batch counters),
`gossip.py:167`/`topology.py:103` (unrelated reason strings). Instance table: no rejected receipt
is ever written to any store — **finding (additional mechanism #1 above)**.

## Design risks

None added. The two design risks in `hunt-b1c.md` are outside this claim's trace and I did not
re-open them.

## Bound

- **Upstream sender strictness (unverifiable from this tree):** whether any real external sender
  acts on a `rejected` receipt as final is specified by `docs/PROTOCOL.md` §8 but not implemented
  by any in-tree client. The "message loss for a §8-compliant sender" outcome is therefore
  SUSPECTED at the external-client boundary; the in-tree client demonstrably retries instead, so
  the in-tree outcome is confirmed as self-healing for a single transient fault.
- **Infra-fault cadence (unverifiable):** no live deployment/disk was available, so the disk-full /
  I/O-error frequency is stated LATENT rather than measured. The concurrent-CLI `database is
  locked` variant depends on operator behavior and CLI transaction duration; not measured.
