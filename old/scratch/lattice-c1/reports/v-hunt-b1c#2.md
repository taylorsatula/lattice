# v-hunt-b1c#2 — PRIMED VERIFIER

Claim under test: `hunt-b1c.md` finding 2, reported tier **M** —
"Recipient-ownership guard ignores canonical node-ID addressing: custody accepted for mail
addressed to another node."

Pass type: PRIMED VERIFIER (adversarial and symmetric). Read-only.

## Verdict

**ADJUSTED.** Mechanism and trigger CONFIRMED. One frequency sub-claim REFUTED. Severity left at
**M** on a corrected ground (custody/acknowledgment semantics), not on the confidentiality/data-loss
ground the report implies.

## Frame re-derived from source (not from the claim)

- `lattice/addressing.py:parse_address` — `user@lat_<b32>` matches `NODE_ID_RE`
  (`^lat_[a-z2-7]+$`), returns `LatticeAddress(username, domain=None, node_id=host)`. Human
  `user@host` returns `domain=host, node_id=None`. Whole string is `.strip().lower()`ed first.
- `lattice/api.py:120-124:_extract_domain_from_address` returns `parsed.domain if parsed.domain
  else ""`. For a canonical host this returns the empty string.
- `lattice/api.py:320-334` guard: `to_domain = _extract_domain_from_address(message["to_address"])`;
  `if to_domain and runtime._own_domains and to_domain not in runtime._own_domains: return 403`.
  Comment states the intent: *"refuse custody of messages not addressed to this node."*
- `lattice/runtime.py:253` — `self._own_domains = own_domains or set()`. `lattice/cli.py:714` passes
  `own_domains={config.domain} if config.domain else None`. `lattice/config.py:157-160` makes
  `node.domain` **required and validated** (`_is_valid_domain`: non-empty, ≤253, no `:/@`). So in
  every daemon start `_own_domains` is a non-empty, single-member set. The guard is live in
  production; the `runtime._own_domains` truthiness term is never the reason it no-ops.
- `lattice/runtime.py:619-663:verify_inbound_message` parses **only `from_address`**; it never
  inspects `to_address`. `lattice/messages.py:InboundMessageService.accept` stores `to_address` but
  never checks ownership. `grep -rn to_address lattice/*.py` shows the sole inbound inspection is
  `api.py:322`. So nothing downstream re-checks.
- `lattice/protocol/models.py:Message` does not validate address shape or ownership;
  `to_address: str = Field(min_length=1, max_length=320)`.
- Contract: `docs/PROTOCOL.md:235` §7 validation list — **"Reject messages addressed to a different
  node."** `docs/THREAT_MODEL.md:40` — "A peer does not learn the content of messages not addressed
  to it."

Conclusion of the frame: for `to_address = "user@lat_<other>"`, `to_domain == ""`, the `if` is
False, and the handler proceeds to rate-limit then `accept` → 202 accepted receipt → webhook
delivery. The claim's frame is accurate.

## Sub-claim disposition

| Sub-claim | Verdict |
|---|---|
| Guard ignores canonical `user@lat_<other>` addressing; `to_domain==""` skips the check | CONFIRMED |
| No other layer re-checks `to_address` ownership | CONFIRMED (`grep` above; `accept`/`verify_inbound_message` clean) |
| Node's own `node_id` is available and unused (`runtime.node_id`, `_own_domains`) | CONFIRMED |
| Outcome: durable custody + signed `accepted` receipt + webhook delivery for mail addressed to another node | CONFIRMED |
| Canonical addressing is first-class (`parse_address` accepts; `resolve_destination` resolves without lookup) | CONFIRMED (`lattice/resolution.py:154-166`) |
| Frequency "plausible in normal operation — any sender using canonical addressing that **mistypes** another node's ID" | **REFUTED** (see below) |
| Frequency "deliberately reachable by any verified peer that wants to dump content into this operator's webhook" | CONFIRMED as reachability, but **not an incremental capability** (see severity) |

### Refuted half — the "mistypes another node's ID" / "normal operation" frequency

A sender does not choose the endpoint from `to_address` text; it chooses it from the resolved
destination node. `runtime.resolve_destination` (`resolution.py:154`) returns
`parse_address(to_address).node_id` for canonical form directly, and
`runtime._run_outbound_delivery` (`runtime.py:922-933`) calls
`peer_endpoint_for_node(row["to_node_id"])`. A message addressed to `user@lat_other` therefore goes
to `lat_other`'s endpoint, not this node's. A mistyped canonical ID routes to the mistyped node (or,
if unknown, `peer_endpoint_for_node` returns `None` → retryable failure, never delivered here). The
in-tree sender cannot misroute to this node while `to_node_id` names another node. So the
"normal-operation / mistyping" trigger does not exist in this tree; it is not a production cadence.
The only concrete production trigger is a peer that **deliberately** POSTs to this node's
`/lattice/v1/messages` with a hand-built, validly signed message whose `to_address` names another
node.

## Severity correction — kept at M, ground corrected

Reported M. I leave the tier at **M**, but not for the reason the report gives.

- **H is not justified.** The outcome is not cross-peer/cross-user disclosure of another principal's
  data. The payload is attacker-authored; the attacker already achieves the identical end
  (arbitrary content stored and pushed to this operator's webhook) by addressing the message to this
  node's own domain, which passes the guard legitimately. The bypass grants no incremental reach,
  and no relay path exists (`invariant 6`; `_run_webhook_delivery` is the only sink for inbound
  content). `docs/THREAT_MODEL.md:40` is not meaningfully violated because the sender is the
  addressee's author.
- **M stands** on the scale's named category "wrong custody/acknowledgment semantics": the node
  returns a signed `accepted` receipt and takes durable custody for a message its own contract
  (`docs/PROTOCOL.md:235`, and the code comment at `api.py:320`) requires it to reject. It is an
  enforcement gap at a trust boundary, on a public route (invariant 3), reachable in production by
  any verified peer.
- The M definition's qualifier "under a plausible normal operation" is **not** met by the trigger
  (adversarial-only), which is why the frequency, not the tier, is corrected. A reviewer who reads
  M as requiring a non-adversarial trigger would fairly grade this **L** (narrow adversarial
  trigger, bounded outcome). I record that as the decision boundary and pick M.

## Frequency correction

- Claimed: DEMONSTRATED, "plausible in normal operation."
- Corrected: **DEMONSTRATED for the adversarial path only.** Population/cadence: any pinned,
  non-blocked peer (`verify_inbound_message` has already resolved its cert/root history) that sends
  one signed POST with a canonical `to_address` naming a different node. There is no recurring
  normal-operation cadence; the honest-sender path is refuted above. Because the honest path is
  ungrounded, the *frequency* term is LATENT; the trigger itself is production-reachable.
- Reachability kind: **PRODUCTION** (adversarial). Not tests-only, not gated.
  - Note: the guard has **zero test coverage**. `tests/test_api.py` builds `RuntimeCoordinator`
    without `own_domains` (`runtime` fixture, `tests/test_api.py:102`), so `_own_domains == set()`
    and the `to_domain and runtime._own_domains` conjunct is always False under test. The passing
    `test_receive_message` (to_address `"bob@lat_remote"`, expects 202) exercises the skipped guard,
    not the check. The claim's mechanism is source-traced, not test-confirmed; no test would catch a
    regression here.

## Additional mechanisms / earlier failure sites / new reachability on the same trace

1. **Same guard, opposite direction — case-sensitivity mismatch rejects mail addressed to the node's
   own domain.** `Config` does **not** lowercase `node.domain`
   (`lattice/config.py:157-160`; only `models._check_domain` lowercases, and `Config` never calls
   it), yet `parse_address` lowercases the parsed host (`addressing.py:47`). With
   `domain = "Example.COM"`, `_own_domains = {"Example.COM"}` and an inbound
   `to_address="bob@example.com"` yields `to_domain="example.com"` → 403. Verified:
   ```
   config.domain = 'Example.COM'
   parsed domain = 'example.com' in own? False
   would 403: True
   ```
   `cmd_init` accepts the mixed-case value (`cli.py:99`, no `.lower()`), writes it into `config.toml`
   (`cli.py:157`), while the served well-known document **is** lowercased (`cli.py:166`) — evidence
   the author knew domains are case-insensitive but did not normalize `Config.domain`. Side
   discovery, priced below.
2. **Earlier failure site on the trace:** `verify_inbound_message` (`runtime.py:619`) is the natural
   place to reject a foreign `to_address`, since it already holds `self.node_id`; the ownership check
   was instead bolted into the HTTP handler, which is why only one of the two address forms is
   handled. Fix-direction note, not a separate finding.
3. **Malformed `to_address` 500** (`api.py:322` → `AddressError`, uncaught — the handler catches only
   `BlockedSenderError`/`RuntimeError`) is the report's finding 3, on the same statement. Not
   re-reported; noted as coupling for the repair.

## Fix-direction constraints (what a repair must account for)

- Reject both forms: human `user@domain` with `domain ∉ own_domains`, **and** canonical
  `user@lat_<id>` with `id != runtime.node_id`. Canonical `user@lat_<this-node>` must stay accepted.
- The malformed-address case (finding 3) shares `api.py:322`; a fix that lowers the `AddressError`
  into a 4xx must not change the guard's ownership semantics, and a guard that starts parsing
  `node_id` must still not 500 on `from_address`-shaped garbage.
- Comparing against `runtime.node_id` alone is insufficient if the operator later wants aliases:
  the human-form branch still needs the domain set. Keep both branches.
- Do not conflate this with the cold-sender path (finding 1): it returns 503 before the guard, so a
  canonical foreign `to_address` from an unknown sender is answered 503 today and only reaches the
  guard once the sender is known.
- A repair must add the missing test coverage (`own_domains` is empty in every API fixture today),
  or the fix is unverifiable.

## Checked and clean

- `parse_address` / `LatticeAddress` canonical handling and `resolve_address`'s no-lookup canonical
  branch — correct per `docs/PROTOCOL.md` §"Addresses".
- `verify_inbound_message` order (signature before block check; recipient check and rate limit before
  custody write) — unchanged.
- `InboundMessageService.accept` idempotent duplicate path — unchanged; it is simply not the place
  ownership is enforced (by design of the current code).
- No relay/forward path from stored inbound content — invariant 6 holds; the misaddressed message is
  stored and webhooked only.
- `_own_domains` population path (`cli.py:714` + required `Config.domain`) — the guard is genuinely
  live in production, contrary to a possible reading that it is test-only.

## Enumeration

Composed command closing the class "inbound `to_address` inspection sites":

```
grep -rn "to_address" lattice/ --include=*.py | grep -v "protocol/models.py"
```

Instances and disposition:

| Site | Disposition |
|---|---|
| `runtime.py:596,609` (`sign_local_message` param/field) | outbound construction — out of class |
| `storage/repositories.py:659,673,681,875,887,896` | persistence of the field — no ownership check expected |
| `api.py:60` (`SubmitRequest` field) | admin submit route (bearer-gated) — out of class |
| `api.py:322` | **the only inbound ownership inspection** → finding |
| `api.py:392,400` | admin submit destination resolution — out of class |
| `messages.py:119` (outbound) / `messages.py:276` (`accept` insert) | `accept` stores, does not check → confirmed no downstream re-check |
| `runtime.py:619-663` `verify_inbound_message` | parses `from_address` only → confirmed |

## Side discoveries (single-pass candidates — not folded into the verdict)

- **[L, LATENT] Mixed-case configured domain makes the node reject mail addressed to itself.**
  Location: `lattice/config.py:Config.__init__` (`self.domain: str = node.get("domain","")`, no
  `.lower()`) interacting with `lattice/api.py:323` and `lattice/addressing.py:47`.
  Evidence: `would 403: True` reproduction above; `cli.py:166` lowercases the well-known domain while
  `cli.py:99,157` do not lowercase the config. Trigger: operator runs
  `lattice init --domain Example.COM` (or hand-edits `config.toml`) and a peer sends
  `to_address="bob@example.com"`. Frequency: LATENT — requires a mixed-case operator config; no code
  path in tree produces one, so ungroundable cadence, capped at L. Outcome: the node returns 403 to
  the legitimate sender; `_send_outbound_message` (`runtime.py:1008-1014`) treats any non-202,
  non-429/5xx status as terminal, records failure with `retryable=False`, and erases the outbound
  content — the message is **permanently lost**, not retried. Severity would be M on outcome
  (data loss) but is capped at L by the ungroundable frequency; a working engineer should still
  normalize `Config.domain` to lowercase (or compare case-insensitively). Fix-direction: normalize
  once at config load, and keep `own_domains` consistent with the lowercased values `parse_address`
  produces.

## Bound

- Not exercised end-to-end: a live daemon with a real `own_domains`, a real peer's signed POST, and a
  live webhook. The mechanism is traced through source and the arithmetic (`to_domain==""` for
  canonical hosts, `"Example.COM" ∉ {"example.com"}`) is interpreter-verified; the webhook operator's
  downstream use of `to_address` (whether a consumer would misroute on it) is unverifiable from the
  tree and is why no H tier is claimed.
- Did not audit `_resolve_pending_senders` / finding 1 or the other four findings beyond the shared
  statement; this pass is scoped to claim #2.
- Tests were read to establish coverage, not to derive behavior.
