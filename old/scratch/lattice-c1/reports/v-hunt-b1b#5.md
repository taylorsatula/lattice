# v-hunt-b1b#5 — PRIMED VERIFIER report

Claim under test: **hunt-b1b finding #5** in `scratch/lattice-c1/reports/hunt-b1b.md`
(`[L] — (latent) The custody receipt's signature is never verified; the sender trusts a
three-field match`). Reported tier: **L**.

## Verdict

**CONFIRMED** — mechanism, outcome, and reported frequency all reproduce from source. The
finding's tier (L) and its "latent" frequency cap are correct and unchanged. One component of its
reachability statement is incomplete: the claim attributes latency solely to the "requires a
misdirected/misbehaving endpoint" condition, and does not name the second, prior gate — the 202
branch is unreachable in production behind `hunt-b1b#1` (the `OutboundTransport.request` `TypeError`)
independently of any endpoint behaviour. Corrected reachability kind:
**gated-behind-hunt-b1b#1, and additionally latent for harm absent a non-genuine endpoint.**

## Re-derived frame (not the claim's phrasing)

- `lattice/runtime.py:976` `_send_outbound_message`, `if response.status == 202:` branch. Decisive
  artifact: the predicate
  `data.get("message_id") != message_id or data.get("node_id") != to_node_id or data.get("status") != "accepted"`.
  On pass → `self._outbound.record_success(message_id, owner)` (`runtime.py:1001`).
- `messages.py:143` `record_success` → `_repo.mark_terminal(..., "delivered", erase_content=True)`;
  `repositories.py:775` `mark_terminal` sets `status='delivered'`, `content=erase_value`,
  `extension=NULL`, `message_json=erase_value`. **Local content is erased on the three-field match.**
- `signing.py`: only `sign_receipt` (line 62), no `verify_receipt`. `identity.py:169/178`
  `verify_object(pubkey, obj, kind)` is the generic verifier; the sender never calls it.
- `protocol/models.py:302` `Receipt` — `kind, message_id, node_id, status, received_at, signature`,
  `extra="forbid"`. `docs/PROTOCOL.md` §8: `signature | string | Operational signature.`
- Caller path: `_run_outbound_delivery` → `_send_outbound_message`; only caller of both.
  `_certificate_for_node(to_node_id)` (`runtime.py:665`) is available to the sender and yields the
  destination operational certificate — verification is feasible and the infrastructure exists.

## Sub-claim adjudication

- **Mechanism — CONFIRMED.** "comment says Validate the signed custody receipt before transferring
  ownership, but the check is field comparison only (`message_id`, `node_id`, `status`); signature
  (and kind, received_at) ignored." Verified verbatim at `runtime.py:977` comment and lines
  980–986; `signature` never read; `kind`/`received_at` never read. No `verify_receipt` anywhere
  (enumeration below; only `verify_object(..., "receipt")` calls in tree are in `tests/`).
- **The docstring/comment mismatch — CONFIRMED.** `api.py:352` "Return the signed receipt so sender
  can validate custody transfer"; `messages.py:301` build_receipt docstring; `docs/PROTOCOL.md` §8.
  `tests/test_api.py:329` asserts a rejected receipt is "root-of-trust verifiable" — the system's
  own tests treat receipts as signature-bearing protocol objects.
- **Test evidence — CONFIRMED (line number corrected).** Claim cites `tests/test_runtime.py:283`;
  the unsigned body is at lines 283–285, response wiring at 288, terminal-delivery assertion at
  `assert row["status"] == "delivered"`. Body is a three-field JSON object with **no `signature`,
  no `received_at`, no `kind`** — and the message is marked delivered. This is a live demonstration
  that the field match alone transfers ownership.
- **Outcome — CONFIRMED.** On a false 202 the sender calls `record_success` → erases content,
  records `delivered`, and audits success (`_audit_outbound_delivered`) — silent loss with a clean
  audit trail. Verified against `mark_terminal`/`record_success` above.
- **Frequency "ungroundable → latent" — CONFIRMED, with one refinement.** No plausible
  normal-operation path produces the trigger; it needs an endpoint that is not the genuine
  destination (or a genuine destination whose operational key differs from the pin, e.g. rotation
  the sender has not absorbed). Correctly capped latent.

**Refuted sub-claims: none.** No component of the finding is factually wrong; one component
(reachability kind, below) is incomplete rather than incorrect.

## Corrected reachability kind (the one material correction)

The finding labels the trigger "latent … requires the endpoint … without being the destination's
Lattice daemon." That is true but omits a prior gate. `OutboundTransport.request`
(`transport.py:132`) passes `fields=` and `assert_hostname=` to `urllib3.PoolManager.urlopen`; in
urllib3 2.7.0 (`uv.lock:861`) neither is a `urlopen`/`_make_request` parameter — verified against
the repo venv:

```
PoolManager.urlopen params: ['self','method','url','redirect','kw']
_make_request params: ['self','conn','method','url','body','headers','retries','timeout',
                        'chunked','response_conn','preload_content','decode_content',
                        'enforce_content_length']
```

so both land in `**kw` and reach `_make_request` as unexpected keywords → `TypeError` (only
`TransportError` is caught at `runtime.py:963`). Therefore **no 202 response is ever produced in
production today, for any destination, genuine or not.** The correct reachability kind is
**gated-behind-hunt-b1b#1**; the misdirected-endpoint requirement is a second, independent
condition. This matters for repair sequencing: fixing `hunt-b1b#1` alone activates this latent
defect on the first legitimate 202 (which the three-field check accepts as-is); the receipt
verification must land in the same change (fix-direction constraint 4 below).

## Severity / frequency corrections

- **Severity: L — unchanged.** Mechanism fully traced, but the bad outcome requires a non-genuine
  endpoint (or pin/key divergence). The pinned scale reserves M for a fault "under a plausible
  normal operation"; this is not one. H (data loss) is not reached because the erasure is not
  triggered by ordinary traffic. L is correct.
- **Frequency: latent — unchanged.** Re-affirmed from the trace above. The branch fires **0 times
  in production today** (gated by hunt-b1b#1); in-tree it fires only under the mocked transport in
  `TestDeliveryTasks`. Not upgradeable to a grounded production frequency.
- **Reachability kind: corrected** from "latent (independent)" to
  "gated-behind-hunt-b1b#1 on the branch; latent for harm even after that gate opens."

## Additional mechanisms / earlier sites / new reachability

- **No earlier failure site on this trace.** The parse at `runtime.py:979` precedes the field check;
  a non-JSON 202 yields `data={}`, fails the field check, and is treated as a *retryable* failure —
  a directionally safe fallback, not a defect.
- **Kind and received_at are also unbound (part of the same defect).** The receipt's `kind` and
  `received_at` are ignored; the model (`extra="forbid"`) plus `verify_object` would bind `kind`
  into the preimage automatically, but the current field match does not require `kind=="receipt"`
  at all. Same mechanism, recorded so a repair does not "verify the signature" while still omitting
  the kind binding.
- **Certificate-rotation side path (new reachability, same trace).** `_certificate_for_node`
  (`runtime.py:665`) can return a *network-resolved* certificate (lines 678–682). A repair that
  verifies against the resolved cert rather than the pin can be raced by a rotation; a repair that
  verifies against a stale pin rejects a legitimate rotated receipt. Both directions are real; the
  current code sidesteps them only by not verifying at all.
- **Interaction with hunt-b1b#2.** The 202 branch also treats a signed `status:"rejected"` receipt
  as an "invalid custody receipt" and retries. A repair for #5 that parses and verifies the receipt
  must not collapse `accepted` and `rejected` handling — the two fixes touch the same predicate.

## Fix-direction constraints

1. Verify the receipt signature with the **destination node's operational key** from its pinned
   certificate (`_certificate_for_node(to_node_id)` → `verify_object(cert.operational_public_key,
   data, "receipt")`), not merely the TLS transport identity.
2. Validate the full `Receipt` model (`kind=="receipt"`, tz-aware `received_at`) — the current check
   ignores `kind`; `verify_object` binds `kind` into the canonical preimage, so model-validate then
   verify.
3. Do not introduce a blocking network resolve into the delivery worker: `_certificate_for_node`
   may perform `resolver.resolve()` (network) on the calling thread. Prefer the pin; if a fetch is
   required, account for holding the delivery worker across the wait.
4. **Land with hunt-b1b#1.** Repairing the transport without adding receipt verification promotes
   this latent defect to live: the first genuine 202 would erase local custody on an unverified
   three-field match.
5. Preserve `rejected` finality: the repaired branch must distinguish a verified `accepted` receipt
   (success) from a verified `rejected` receipt (terminal, no retry) — see hunt-b1b#2.

## Bound

- No live infrastructure: no running daemon and no real peer were available. The gating claim
  (hunt-b1b#1 → 202 unreachable) is established by static mechanism (urllib3 signature inspection
  + `except TransportError` guard), not by an observed outbound request; consistent with the frame
  the finding-1 verification would confirm.
- Provider/peer behaviour (whether a misdirected endpoint would actually emit a matching 202) is
  unobservable here; the finding's own trigger framing depends on it and is recorded as the
  finding's, not independently observed.
- Read for this pass: `lattice/runtime.py` (`_send_outbound_message`, `_run_outbound_delivery`,
  `_certificate_for_node`, `_domain_for_node`, `verify_inbound_message`), `lattice/messages.py`
  (`accept`/`build_receipt`/`record_success`/`record_failure`),
  `lattice/storage/repositories.py` (`mark_terminal`/`claim_pending`/`release_lease`),
  `lattice/protocol/signing.py`, `lattice/protocol/models.py` (`Receipt`), `lattice/api.py`
  (`receive_message`), `lattice/transport.py`, `docs/PROTOCOL.md` §8, and the cited tests.

## Checked and clean

- The three-field predicate uses the correct local `message_id` and the row's `to_node_id`
  (verified: `to_node_id=row["to_node_id"]` at `runtime.py:948`), so the check is not itself
  mis-keyed — the gap is the *omitted* signature, not a wrong operand.
- `record_success`/`mark_terminal` re-check `lease_owner` and `status='leased'`, so a stale success
  cannot erase a row re-claimed by another owner; the erasure semantics themselves are correct.
- The generic verifier exists and is correct: `verify_object` canonicalizes excluding `signature`
  and rebuilds the kind-prefixed preimage (`identity.py:178`); `tests/test_vectors.py:91–97` proves
  a receipt signature verifies with the destination operational key. The capability is present; only
  the sender's call site omits it.
- Enumeration (class = every receipt-signature verification site):
  `rg -n "verify_object\(.*receipt|\"receipt\"|sign_receipt|verify_receipt" lattice tests` →
  `lattice/` contains `sign_receipt` (`messages.py:16,316`; `signing.py:62`) and the `Receipt` model
  only; every `verify_object(..., "receipt")` call is in `tests/` (`test_api.py:333`,
  `test_vectors.py:97,131`, `test_vectors/generate_vectors.py`). **Class closed: zero verification
  sites in shipped code.** Disposition: the sender call site is the finding; all others checked and
  clean / test-only.

## Design risks (max 2)

1. **Receipt does not bind message content.** The receipt binds `message_id` only; `message_id` is
   client-supplied (`api.py:58`), not content-derived, so even a verified receipt does not prove
   custody of a specific payload. Orthogonal to this finding and not currently exploited by any
   path in tree — recorded so a "verify the signature" repair is not mistaken for content binding.
2. **Sender accepts an unverified receipt's `received_at`-free body.** No freshness check exists;
   combined with no signature check, a captured 202 from message X cannot be replayed to message Y
   (message_id differs), so this is not independently exploitable. Noted only.
