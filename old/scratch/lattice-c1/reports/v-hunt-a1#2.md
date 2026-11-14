# v-hunt-a1#2 — PRIMED VERIFIER of hunt-a1 finding #2

Claim under test: `scratch/lattice-c1/reports/hunt-a1.md` finding 2, tier M —
"Canonical to_address bypasses the recipient-ownership check."

Frame re-derived independently from source before reading the claim's own account.

## Frame (re-derived)

`lattice/api.py:receive_message` (lines 320-335):

```python
# Verify recipient ownership: refuse custody of messages not
# addressed to this node (when own_domains is configured).
to_domain = _extract_domain_from_address(message.get("to_address", ""))
if to_domain and runtime._own_domains and to_domain not in runtime._own_domains:
    return 403 ...
```

- `_extract_domain_from_address` (api.py:120) = `parse_address(address).domain or ""`.
- `parse_address` (`lattice/addressing.py:47`) returns `domain=None, node_id=host` for the
  `NODE_ID_RE` (`^lat_[a-z2-7]+$`) canonical form, and `domain=host` for human form.
- Interpreter proof:
  `parse_address('bob@lat_remote') -> domain=None, node_id='lat_remote', extract=''`;
  `parse_address('bob@example.com') -> domain='example.com', extract='example.com'`.
- `runtime._own_domains` is set (`lattice/runtime.py:253`) from
  `own_domains={config.domain}` (`lattice/cli.py:714`). `config.domain` is required and
  shape-validated (`lattice/config.py:128`), so `_own_domains` is always non-empty in a
  running daemon.
- `to_address` carries no format validation in the model:
  `lattice/protocol/models.py:226` is `Field(min_length=1, max_length=320)` only.
- `verify_inbound_message` (`lattice/runtime.py:619`) matches only `from_address`; it never
  inspects `to_address`.
- `InboundMessageService.accept` (`lattice/messages.py:241`) stores `model.to_address`
  verbatim and performs no ownership check.
- `_run_webhook_delivery` (`lattice/runtime.py:1021`) builds a signed envelope around the
  whole signed message and posts it to the local webhook URL with no `to_address` filter.
- The only ownership enforcement in the tree is api.py:322-323 (enumeration below).

Consequence of the `and` guard: for any canonical `to_address`, `to_domain == ""`, the guard
short-circuits, and the 403 branch is unreachable. A canonical `to_address` naming a foreign
node is accepted exactly like a self-addressed one.

## Findings

Verdict on hunt-a1#2: **CONFIRMED** — mechanism, trigger, and severity all hold.
One appended sub-claim is refuted (below); frequency phrasing corrected.

### Component verdicts

- **Mechanism — CONFIRMED.** `parse_address` returns `domain=None` for the `lat_` form;
  `_extract_domain_from_address` coerces that to `""`; the truthiness gate `if to_domain`
  is therefore False for every canonical address, regardless of the node id it names. The
  node-id half of the address is parsed and then discarded by
  `_extract_domain_from_address`, so the check structurally cannot see it.
- **Trigger — CONFIRMED.** A pinned (`from_address` resolves to a known node with a valid
  operational certificate and verifying signature) federated peer POSTs to
  `/lattice/v1/messages` a `Message`-valid body whose `to_address` is canonical for a node
  other than the receiver. `verify_inbound_message` (v1 `model_validate`, v2 from-node
  resolution + signature) succeeds, `cold_sender=False`, and the request reaches the
  ownership block, which skips. Reached through `receive_message` → `inbound_service.accept`
  → durable custody → `_run_webhook_delivery`. Reachability kind: **PRODUCTION** (public
  route, unauthenticated at the HTTP layer; the sender is an authenticated federation peer).
  Also **TESTS-CONFIRMED as current behavior**: `tests/test_api.py:218 test_receive_message`
  sends `to_address="bob@lat_remote"` (foreign node id, receiver is
  `operational_identity.node_id`) and asserts `202` + accepted receipt.
- **Frequency — ADJUSTED (precision).** The claim's "any federated peer, per message, using a
  canonical to_address" overcounts: a correctly-routed canonical message names the receiver's
  own node id and *should* be accepted. The demonstrated population is narrower and concrete:
  a pinned federated peer that posts a message whose `to_address` names a node other than the
  receiver, in canonical form. Per such message, no coincidence beyond the sender's choice;
  the population is hostile-or-misrouting peers, which the federation threat model assumes.
  Reachable in production. Not latent (the actor is concrete and the path is per-request).
- **Severity — CONFIRMED M, unchanged.** `PROTOCOL.md:235` lists "Reject messages addressed
  to a different node" as a message-validation requirement; the domain-form check implements
  it, the canonical form silently opts out. Outcome: the node takes durable custody of, and
  webhooks to its local consumer, a message addressed to a different node, and returns a
  signed `accepted` receipt that the sender treats as final (`PROTOCOL.md:250`), so the
  misrouted message is never delivered to its intended node. This is exactly the M scale's
  "wrong custody/acknowledgment semantics." Not H: the sender is already an authorized
  federation peer, and content injection into the local webhook is already possible with an
  own-domain `to_address`, so no new cross-user/cross-peer boundary is crossed.

### Sub-claims refuted (named individually)

1. **"also fires on stale canonical addresses after a node-id rotation" — REFUTED.**
   `docs/KEY_MANAGEMENT.md:52` states the node ID does not change during operational rotation.
   Canonical routing derives the destination node id directly from the address
   (`resolve_address` → canonical branch, `lattice/resolution.py`), so a stale canonical
   address still routes to the addressed (old) node, not to a foreign node. `lattice keys
   create-transfer` (`cli.py:452`) moves a *domain→node* binding, not a node id; canonical
   addresses do not involve domains. No path in the tree makes this node receive a canonical
   address naming a different node through rotation. The rotation addendum asserts a trigger
   population with no mechanism and is dropped.

## Checked and clean

- `parse_address` canonical/human discrimination and lowercasing: verified by interpreter;
  `bob@LAT_REMOTE` also yields `domain=None` (lowercased before match), so case is not an
  escape from the gap.
- `_own_domains` is always populated in a running daemon (`config.domain` is required), so the
  second conjunct of the guard is not the bypass; the bypass is the first conjunct.
- `InboundMessageService.accept` and the webhook envelope path apply no compensating
  `to_address` check — verified by reading `lattice/messages.py:241-292` and
  `lattice/runtime.py:1021-1070`. No second enforcement site exists to have been missed.
- Ordering: the ownership block sits after `verify_inbound_message` and before
  `allow_message`; a moved check does not affect the mechanism.
- The 403 branch has no test coverage in `tests/` (rg for `403|Not this node|different node|
  own_domains` returns nothing) — the behavior under test is the accept path, which is why the
  existing suite passes.

## Enumeration

Close the class "every consumer of message `to_address` that enforces node ownership":

```
rg -n "to_address|own_domains|addressed" lattice --glob '*.py'
```

| Site | Role | Disposition |
|---|---|---|
| api.py:322-323 | ownership gate (domain form only) | **finding confirmed** — canonical bypass |
| api.py:326-331 | 403 body | examined-clean (unreachable for canonical) |
| api.py:60 / models.py:226 | `to_address` model constraint (`min_length`,`max_length` only) | examined-clean — no format check by design |
| runtime.py:596-609 | outbound `sign_local_message` copies `to_address` verbatim | examined-clean — outbound; routing is by `to_node_id` |
| messages.py:119 / 276 | custody stores `to_address` verbatim | examined-clean — no check here either; this is *why* the api gate is the sole gate |
| runtime.py:1021-1070 | webhook build/deliver | examined-clean — no `to_address` filter |
| cli.py:714 | `own_domains={config.domain}` | source of `_own_domains`; see SD1 |

No other enforcement site exists.

## Side discoveries (separately priced)

- **SD1 [L] — `config.domain` is not normalized to lowercase; the ownership check compares a
  raw config value against lowercased parsed addresses.**
  - Location: `lattice/config.py:127` (`self.domain = node.get("domain", "")`, shape check only)
    consumed at `cli.py:714` and compared against `parse_address(...).domain` (lowercased) at
    `api.py:323` and `runtime.py:583`.
  - Trigger: `lattice init --domain Example.com` writes the raw value into the config
    (`cli.py:99,157`; only the well-known document uses `domain.lower()`, `cli.py:167`). The
    daemon then rejects `to_address="user@example.com"` as 403 "Not this node", and
    `resolve_local_address` (`runtime.py:583`) raises for a local `from_address` in lowercase,
    breaking local submission.
  - Frequency: LATENT — operator must supply a mixed-case domain; not groundable as a normal
    population, so capped at L per calibration.
  - Outcome: inbound mail for the node's own domain is refused as "addressed to a different
    node"; local outbound submission fails 400.
  - Fix-direction constraint: normalize at config load (single point) rather than in each
    comparison, or the fix must touch both api.py:323 and runtime.py:583 (and any future site).
- **SD2 [already reported]** — malformed `to_address` (e.g. `"alice"`, no `@`) raises
  `AddressError(ValueError)` through `_extract_domain_from_address`, escaping to a plain 500.
  This is hunt-a1 finding #4; noted only because the *same* call site is the earlier/lateral
  failure site on this trace. Not re-reported as new.

## Fix-direction constraints

1. A repair must handle both address forms: parse `to_address`; if `parsed.node_id` is present
   reject when it != `self.node_id`; if `parsed.domain` is present reject when it not in
   normalized `_own_domains`. The current helper discards `node_id`, so editing the condition
   alone cannot fix it — the helper or its call must be changed.
2. It must not reject a legitimate canonical `user@<self.node_id>` (the only canonical address
   a correct sender ever delivers here).
3. It must convert a malformed `to_address` to a 400 (the same call raises `AddressError`,
   currently a 500 — hunt-a1 finding #4). A fix that only adds the node-id comparison still
   leaves the 500 underneath.
4. Normalize case on both sides; `config.domain` is raw while `parse_address` lowercases (SD1).
5. Keep the check after signature verification and before custody; it must not run so late that
   `accept` has already stored the row.
6. api.py is the sole ownership gate; validating `to_address` in the Pydantic `Message` model
   instead would also cover the webhook/repo consumers, but changes the wire contract
   (`PROTOCOL.md` §7 allows both forms) — choose deliberately.

## Bound

- No live daemon or HTTP client was executed; all trigger paths are traced statically plus one
  `python3 -c` interpreter check of `parse_address`. Uvicorn/FastAPI default-500 behavior and
  real nginx forwarding were not exercised.
- Provider/DNS behavior and whether real senders emit canonical foreign `to_address` are not
  observed; that population is inferred from the federation threat model and the existing
  `tests/test_api.py` fixture, not from live traffic.
- `lattice/resolution.py` canonical routing was read at the `resolve_address` branch only.
- Tests were read, not run, for this site.
