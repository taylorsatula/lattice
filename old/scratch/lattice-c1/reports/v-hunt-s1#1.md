# v-hunt-s1#1 — PRIMED VERIFIER verdict on hunt-s1#1

Claim under test: **hunt-s1#1** in `scratch/lattice-c1/reports/seam-s1.md`, tier **M** —
"Canonical `to_address` (node-ID form) bypasses the not-this-node custody guard."

## Verdict: ADJUSTED — mechanism CONFIRMED, severity M→L, frequency DEMONSTRATED→LATENT,
## one sub-claim REFUTED.

The guard gap is real and exactly as described. The claim's severity and frequency are not: the
trigger is not a normal-operation cadence, and one of the two stated harms does not occur for a
repo-native sender.

## Re-derived frame (from source, before accepting the claim's phrasing)

- `lattice/api.py:322` — `to_domain = _extract_domain_from_address(message.get("to_address", ""))`.
- `lattice/api.py:120-122` — `_extract_domain_from_address` returns `parsed.domain if parsed.domain
  else ""`.
- `lattice/addressing.py:parse_address` — for a host matching `NODE_ID_RE` (`^lat_[a-z2-7]+$`) it
  returns `LatticeAddress(domain=None, node_id=host)`.
- `lattice/api.py:323` — `if to_domain and runtime._own_domains and to_domain not in
  runtime._own_domains:` → 403.
- `lattice/cli.py:714` — `own_domains={config.domain} if config.domain else None`;
  `lattice/config.py:127-129` makes `node.domain` required, so the daemon always arms the guard.
- `lattice/runtime.py:253` — `self._own_domains = own_domains or set()`.

Verified with the interpreter (lattice.addressing imports only `re`):

    python3 -c "from lattice.addressing import parse_address as p; \
      print([(a, p(a).domain, p(a).node_id) for a in ['bob@lat_remote','bob@remote.example.com']])"
    ->  'bob@lat_remote'  domain=None  node_id='lat_remote'   (guard_domain == "")
        'bob@remote.example.com' domain='remote.example.com'  node_id=None

`"" and <anything>` short-circuits, so a canonical `to_address` naming any node — including a node
other than this one — never reaches the 403. Mechanism **CONFIRMED**.

## Sub-claims

| Sub-claim | Verdict | Trace |
|---|---|---|
| Mechanism: canonical `to_address` ⇒ `domain=None` ⇒ `""` ⇒ guard short-circuits | CONFIRMED | addressing.py `NODE_ID_RE`; api.py:120-122, 322-323; interpreter check above |
| Guard is armed in every deployment | CONFIRMED | cli.py:714 + config.py:128-129 (domain required) |
| Trigger: a signature-valid message with canonical foreign `to_address` reaches `/messages` and is accepted | CONFIRMED as a code path | warm path in `verify_inbound_message` (runtime.py:638-663) does not inspect `to_address`; `accept` (messages.py:244) stores it verbatim; `_run_webhook_delivery` (runtime.py:1028-1070) delivers it |
| Trigger is a normal-operation cadence | **REFUTED** | see frequency correction |
| Outcome: "sender stops retrying, believing custody transferred" | **REFUTED** (for repo-native senders) | `_send_outbound_message` (runtime.py:964-985) compares `data.get("node_id") != to_node_id`. A misrouted canonical message has `to_node_id == lat_other`; this node signs the receipt with `node_id == lat_this` (messages.py:295-303, `self._identity.node_id`). Mismatch ⇒ `record_failure(retryable=True)` ⇒ the sender **keeps retrying**, it does not stop. |
| Outcome: body webhook-delivered to this deployment's local consumer | CONFIRMED | `_run_webhook_delivery` filters on neither `to_address` nor recipient; every accepted row is signed into a `webhook_envelope` and POSTed to `config.webhook.url` |
| "canonical to-addresses are the form the repo itself generates" | **OVERSTATED** | `sign_local_message`/`SubmitRequest.to_address` store the admin-supplied string **verbatim** (runtime.py:608-609). The end-to-end federation test uses human form (`tests/test_integration.py:21,53`); canonical appears in unit tests and `tests/vectors`. Frequency assertion built on this is unsupported. |
| Test suite never exercises the guard | CONFIRMED | `rg own_domains tests/` → no match; conftest.py:180-188 constructs `RuntimeCoordinator` without `own_domains` ⇒ `_own_domains == set()` ⇒ guard skipped. No test contradicts the finding; none demonstrates it either. |

## Severity correction: M → L (trace)

M requires "wrong custody … under a plausible normal operation". The mechanism does produce wrong
custody, but the trigger is not normal-operation:

1. A correctly-functioning sender routes by the node_id from `resolve_destination`. For
   `bob@lat_other` that is `lat_other`, and `peer_endpoint_for_node(lat_other)` yields
   *lat_other's* `/messages` endpoint (runtime.py:740-756). The message does not arrive here.
   A canonical message that reaches this node is either misrouted (stale pin after a domain/key
   transfer) or sent here deliberately.
2. The actor must be a **pinned** peer: `verify_inbound_message` reaches the guard only after
   signature verification against a known certificate (runtime.py:654-663); a cold sender returns
   503 at api.py:311-319 before the guard. "Any network peer" overstates the population.
3. The node does **not relay** (invariant 6): `accept` stores the row and the webhook delivers
   locally; the body is never forwarded to `lat_other`. So the bad outcome is a wrong custody row
   plus a spurious local webhook delivery, not propagation to a third party.
4. Warm-path rate limiting still applies after the guard (`allow_message(from_node_id)`,
   api.py:335), bounding deliberate volume.

The residual: an enforcement gap at a trust boundary that accepts mail for another node, bounded
in outcome. That is L ("real defect with a narrow trigger or a bounded bad outcome").

## Frequency correction: DEMONSTRATED → LATENT (trace)

The claim's population — "every foreign-destination message that reaches this node's /messages
route in canonical form" — is circular: the population is defined by the trigger. The concrete
population that produces the trigger is "a pinned peer that misroutes (stale pin / domain transfer)
or deliberately addresses mail for node X to node Y, using canonical form". Its cadence in a
correct deployment is zero; it is produced only by misconfiguration, transfer staleness, or abuse.
That is latent by the standing rule (no demonstrated normal-operation cadence), so severity is
capped at L. Reclassify as LATENT, not DEMONSTRATED.

Reachability kind: **PRODUCTION** (a real pinned peer or operator misroute reaches it), but
frequency LATENT.

## Additional mechanisms / earlier failure sites on the same trace

1. **Guard is domain-only; the authoritative recipient identifier is the node ID.**
   `docs/PROTOCOL.md:67` states "The canonical form is the authoritative recipient identifier for
   signatures and storage." The guard compares only `parsed.domain`, so the authoritative form is
   the one it cannot check. The correct predicate is `parsed.node_id != runtime.node_id` (or
   `parsed.domain in runtime._own_domains` for human form).
2. **The two failures compose into a retry loop, not a misdirected success.** As traced above, a
   repo-native sender's custody receipt is rejected on `node_id` mismatch, so the sender retries a
   message this node has already durably accepted, until dead-letter. This is a second-order effect
   of the same gap and is *not* what the claim described.
3. **No earlier failure site exists that discharges the guard's intent.** `Message`
   (protocol/models.py:218-227) constrains `to_address` only by length; nothing upstream validates
   recipient ownership. The guard is the only enforcement point, and it is bypassable.

## Fix-direction constraints

- A repair must compare the parsed **node_id** against `runtime.node_id`, not merely test
  `parsed.domain`; and must still accept this node's own canonical address
  (`bob@lat_<self.node_id>`), which today is accepted only by accident (the `""` short-circuit).
- The repair must keep the human-form branch (`parsed.domain in runtime._own_domains`) as-is.
- Rejecting all canonical `to_address` would break legitimate canonical delivery to this node; the
  test `test_receive_message` posts `bob@lat_remote` and expects acceptance, but only because the
  fixture omits `own_domains`. A correct guard plus that fixture would change that test's outcome —
  the fixture is not evidence the guard should accept foreign canonical addresses.
- Escaping the guard gamble is not the same as fixing the retry loop in (2): a fix that rejects the
  foreign canonical address at this node turns the outcome into a terminal 403 at the misrouter's
  endpoint (or a retryable receipt mismatch), which the outbound side must classify. State this.

## Checked and clean

- `_extract_domain_from_address` / `parse_address` behaviour against `NODE_ID_RE`: verified by
  interpreter for canonical, human, and vector node IDs.
- `own_domains` wiring: single producer `cli.py:714`; single consumer `api.py:323`;
  `runtime.py:173,253`; no other sites (`rg own_domains` closes the class).
- `_extract_domain_from_address` is called from exactly one site (`api.py:322`).
- `verify_inbound_message` does not inspect `to_address`; `accept` stores it verbatim — checked
  (runtime.py:619-663, messages.py:244-285).
- Webhook delivery performs no recipient filtering (runtime.py:1028-1070, webhook.py:74+).
- Sender-side receipt validation (`_send_outbound_message`, runtime.py:964-985) — this is where the
  claim's "sender stops retrying" harm dies.

## Enumeration

    rg -n "own_domains|_own_domains" -S .            # sites: runtime.py:173,253; api.py:321,323; cli.py:714
    rg -n "own_domains" tests/                        # no match (exit 1) — guard never exercised
    python3 -c "from lattice.addressing import parse_address as p; ..."   # domain=None for canonical

Instance table:

| # | Site | Disposition |
|---|------|-------------|
| 1 | api.py:322-323 guard | FINDING (bypass) — mechanism confirmed |
| 2 | api.py:120-122 helper | examined — correct for its stated contract, wrong contract |
| 3 | cli.py:714 producer | examined-clean — always armed |
| 4 | runtime.py:253 default | examined-clean |
| 5 | runtime.py:964-985 receipt check | examined — refutes claim sub-claim |
| 6 | tests/conftest.py:180-188 | examined — fixture omits own_domains (why tests don't contradict) |

## Bound

- No live federation was exercised: no pinned peer sent a canonical foreign message, no webhook
  consumer was reached. Trigger and outcome are traced through source and by interpreter checking
  of `parse_address`; the 403/202 HTTP outcomes follow from the handler code and were not observed
  over the wire.
- `rfc8785` is absent in this environment, so the package was not executed end-to-end; the receipt
  `node_id` field is read from `build_receipt`/`Receipt` source, not from a signed receipt.
- Whether a real deployment ever produces the misroute (stale transfer pin) is a deployment
  property I could not reach; that is exactly why frequency is LATENT rather than DEMONSTRATED.
