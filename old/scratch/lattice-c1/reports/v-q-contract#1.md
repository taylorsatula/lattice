# v-q-contract#1 — verification of q-contract finding #1 (bootstrap restart rewrites a pinned domain binding)

Claim under test: **q-contract.md finding 1 [H]**, "Bootstrap restart silently rewrites a pinned
domain's node binding", reported as reachability **GATED** behind hunt-b1b #1 (transport TypeError).

Method: re-derived the frame from source before reading the claim's phrasing — the query, the guard
constant, the caller inputs, the upsert SQL, and the transport code path — then checked the claim
against what the source actually does.

## Verdict: CONFIRMED (tier H retained; reachability kind GATED)

All three components check out. The mechanism is exactly as claimed, the gate is real and
empirically reproduced, and the documentation the finding cites exists verbatim.

### Component 1 — mechanism (traced, confirmed)

`lattice/runtime.py:_pin_bootstrap_peers` (runtime.py:412–460):

```
425  if self._peer_store.get_peer_by_domain(domain) is not None:
426      continue  # already known
...
451  self._pin_repo.upsert(
452      domain=domain, node_id=node_id, root_public_key=root_pub_key, ...
```

The guard at :425 consults **only** the `peers` table (`PeerStore.get_peer_by_domain`,
peers.py:114–122 → `SELECT * FROM peers WHERE domain = ?`). It never consults `domain_pins`. The
upsert at :451 is reached whenever the domain has no peer row; there is no comparison of the freshly
resolved `doc["node_id"]`/`doc["root_public_key"]` against the existing pin.

`lattice/storage/repositories.py:DomainPinRepository.upsert` (repositories.py:76–109) is
unconditional-on-conflict:

```
91  ON CONFLICT(domain) DO UPDATE SET
92      node_id = excluded.node_id,
93      root_public_key = excluded.root_public_key,
...
97      transfer_node_id = NULL,
98      trust_reset_at = NULL
```

A fresh row is inserted; an existing pin is overwritten, including nulling the transfer/reset
markers.

`lattice/resolution.py:WellKnownResolver.resolve` (resolution.py:113–125) fetches, validates the
document **against itself only** (domain, node-ID-derivation, root signature, operational cert),
and returns it. No site compares the live `node_id` to a stored pin. The only pin-vs-live comparison
in the tree is `trust accept-transfer` (cli.py:578–601), which is the *intended* controlled path —
confirming that the automatic re-resolution path has no fail-closed check. `rg` for
`mismatch|fail closed|takeover` in `lattice/*.py` returns only the doc-internal
`node ID mismatch` at resolution.py:94 (derivation check) — nothing pin-vs-live.

**Mechanism half: CONFIRMED.**

### Component 2 — trigger (traced, precondition creatable only post-gate)

Pin-without-peer rows are created by `resolve_address` (resolution.py:163–182): `get_pin → None →
resolver.pin(domain)` which calls `resolve` then `DomainPinRepository.upsert`, writing no peer row.
The sole production caller of `resolve_destination` is `admin_submit` (api.py:392) —
`rg "resolve_destination" lattice/` returns only that call site. So an admin-submitted message to
`user@<bootstrap-domain>` pins the domain without creating a peer row.

Sequence that arms the trigger: a bootstrap domain X resolves at boot with the peer row **absent**
(prior bootstrap resolution failed transiently, or X was added to `gossip.bootstrap` after having
been pinned via outbound resolution), then an outbound `admin_submit` to `user@X` pins X
(pin-without-peer), then a restart occurs while X's live well-known is served by a new node
identity. On that restart the guard at :425 sees no peer, `resolve()` succeeds (post-transport-fix),
and the upsert overwrites the pin.

Because `resolve()` passes through `OutboundTransport.request`, the same transport fault that gates
the overwrite also gates creation of any new pin — so at present neither side of the trigger is
reachable. That is precisely the finding's stated gating.

**Trigger half: CONFIRMED as stated; reachability kind = GATED behind hunt-b1b #1.**

### Component 3 — gate (empirically reproduced)

`OutboundTransport.request` (transport.py:100–140) always passes `fields=fields` and
`assert_hostname=hostname` to `PoolManager.urlopen`. `PoolManager.urlopen` (poolmanager.py:423–457)
forwards `**kw` to `HTTPConnectionPool.urlopen`, which at connectionpool.py:791–806 forwards
`**response_kw` into `HTTPConnectionPool._make_request`. That signature
(connectionpool.py:377–391) accepts neither `fields` nor `assert_hostname`. Reproduced in the repo
venv (urllib3 2.7.0, `.venv`):

```
$ .venv/bin/python -c "import urllib3; urllib3.PoolManager().urlopen('GET','https://127.0.0.1:1/x', fields=None, assert_hostname='localhost')"
TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'
```

The TypeError is raised at call-binding, before any socket write. `_pin_bootstrap_peers` catches only
`ResolutionError` (:429), so the TypeError escapes; `RuntimeCoordinator.start()` (runtime.py:391–399)
does not catch it; `cmd_serve` calls `runtime.start()` at cli.py:718 before `uvicorn.run`, so the
daemon exits before the overwrite.

**Gate half: CONFIRMED.**

### Severity and frequency corrections

- **Severity: H retained, no correction.** The underlying defect is a trust-anchor overwrite: the
  pin (the mechanism THREAT_MODEL invariant 2 and ARCHITECTURE.md line 3 rely on to prevent silent
  domain takeover) is replaced by the live well-known's identity, with subsequent messages for
  `user@X` routed to the new node. That is an authorization/integrity boundary failure with
  cross-peer reach, squarely H. Per calibration a gated finding keeps its real severity and must be
  marked gated, which the finding does.
- **Frequency: ADJUSTED to LATENT (gated).** The claim's phrase "restarts are routine" correctly
  grounds the restart cadence, but the two co-preconditions — (a) a bootstrap domain in the
  pin-without-peer state, and (b) a live node-identity change — cannot be grounded from the tree in
  any live deployment today (the gate also prevents pin creation). Per the calibration rule, an
  ungroundable frequency is latent by definition. The finding already labels itself GATED; this
  report tightens "environment-armed" to LATENT so no reader treats the trigger as demonstrated.
- The claim's frequency honestly disclaims the precondition ("stated, not asserted as common"), so
  this is a labeling correction, not a refutation.

### Sub-claims refuted

None. Every enumerated sub-claim (guard uses peer table; upsert overwrites unconditionally;
`resolve_address` creates pin-without-peer; no fail-closed pin-vs-live check exists; path is gated
by the transport TypeError) survived re-derivation.

One sub-claim is **not fully traced and is downgraded to SUSPECTED**: the outcome sentence
"delivers subsequent messages for `user@domain` to the new node with valid 202 custody." The routing
mechanism follows (resolve_address returns the overwritten pin's `node_id`; `peer_endpoint_for_node`
reads the overwritten pin's `endpoints`), but the end-to-end delivery + 202 was not exercised live
(no controlled takeover domain / no resolvable bootstrap host in this environment). Mechanism
traced; delivery outcome suspected.

## Additional mechanisms / earlier failure sites on the same trace

1. **Shared root cause in `WellKnownResolver.pin()` (resolution.py:123–138) — the overwrite is not
   bootstrap-specific.** `pin()` re-resolves and upserts with no existing-pin comparison, so every
   caller is an overwrite site. A second caller exists: `_resolve_pending_senders`
   (runtime.py:900–920, `self._resolver.pin(domain)` at :913), driven by the scheduler task
   `"cold_sender_resolution"` (runtime.py:346–348). Normally its domain has no pin (the cold-sender
   branch of `verify_inbound_message`, runtime.py:645–647, is entered only when `get_pin` is None),
   so this is a narrow check-then-act TOCTOU rather than a standing overwrite — but it is the same
   missing-invariant site and shares the fix. Reachability kind: GATED behind the same transport
   fault (TypeError is not a `ResolutionError`, so it also escapes the `except ResolutionError` at
   runtime.py:915 — a secondary concern, see bound). Price: L, LATENT.
2. **`resolve_address` is itself a check-then-act (resolution.py:170–174):** `get_pin → None →
   pin() → get_pin`. A concurrent pin between the check and `pin()` is overwritten. Same class,
   L, LATENT.

## Fix-direction constraints

- Repairing hunt-b1b #1 (the transport TypeError) alone **ships this defect live**. Escaping the
  buggy kwargs is not the same as preventing the semantic overwrite.
- The fix must be a compare-and-refuse at the **re-resolution/pin boundary**, not only a guard edit
  in `_pin_bootstrap_peers`, because `_resolve_pending_senders` and `WellKnownResolver.pin()` share
  the same missing check. Either `DomainPinRepository.upsert` gains a compare-and-set, or
  `WellKnownResolver.pin()`/`_pin_bootstrap_peers` compare `doc["node_id"]` against an existing pin
  and fail closed (raise/refuse) — matching ADDRESSING.md "Lattice fails closed" and THREAT_MODEL
  invariant 2.
- `_pin_bootstrap_peers`'s guard should consult the **pin repository**, not only the peer store.
  Bootstrap config is first-contact authorization, not standing authorization to rewrite an
  established pin; THREAT_MODEL invariant 2 lists only transfer statement and explicit trust reset
  as pin-change events, and invariant 2 has no bootstrap exception.
- Repairs must preserve the intended `trust accept-transfer` rewrite (cli.py:552–611) — that path
  legitimately changes a pin, so a blanket refusal at `upsert` would break it. A compare-and-refuse
  belongs in the automatic-resolution callers, not in `upsert` unconditionally.

## Checked and clean

- Verbatim doc quotes in the finding exist: THREAT_MODEL.md:53 "A domain pin can change only through
  an old-root/new-root transfer statement or explicit local trust reset"; ADDRESSING.md:77 "If a
  pinned domain returns a different node ID on re-resolution, Lattice fails closed.";
  ARCHITECTURE.md:3 "a pinned public key prevents silent domain takeover."
- `_pin_bootstrap_peers` guard/upsert ordering and the `ON CONFLICT(domain) DO UPDATE` clause match
  the finding's evidence quotes exactly.
- `resolve_address` pins only when no pin exists (no standing overwrite on the admin path).
- `queue_domain_resolution(from_node_id)` at api.py:307 is **not** a node-id/domain mixup: in the
  cold-sender branch `verify_inbound_message` returns `(parsed.domain, True)` (runtime.py:645–647),
  so the argument is a domain. Examined, clean.
- The online `trust accept-transfer` path is the sole pin-vs-live comparison and is correct as
  designed.

## Enumeration

Composed command closing the re-pin/pin-check class:

```
$ rg -n "get_pin|\.pin\(|resolver\.pin|ON CONFLICT\(domain\)|get_peer_by_domain" lattice/runtime.py lattice/resolution.py lattice/storage/repositories.py
```

Instance table:

| site | kind | existing-pin check | disposition |
|---|---|---|---|
| runtime.py:425 `_pin_bootstrap_peers` guard | peer-store lookup | none (wrong table) | finding 1 |
| runtime.py:451 `_pin_repo.upsert` | overwrite | none | finding 1 (site) |
| resolution.py:172 `resolve_address` → `pin()` | insert-if-absent | `get_pin` (TOCTOU) | added mechanism 2 |
| runtime.py:913 `_resolve_pending_senders` → `pin()` | re-resolve+upsert | none | added mechanism 1 |
| resolution.py:127 `WellKnownResolver.pin()` | re-resolve+upsert | none | shared root cause |
| repositories.py:91 `ON CONFLICT ... DO UPDATE` | SQL overwrite | none | finding 1 (site) |
| cli.py:578 `trust accept-transfer` | compare-then-rewrite | full | intended controlled path, clean |

## Bound

- No live DNS/TLS well-known fetch: the transport gate prevents it and this environment has no
  controlled takeover domain. The TypeError gate was reproduced on the repo venv (urllib3 2.7.0);
  the runtime-coordinator path through `start()` was traced statically, not executed end-to-end.
- Whether operators in practice configure a bootstrap domain that also sits in the
  pin-without-peer state cannot be measured from the tree — frequency stays LATENT.
- `_resolve_pending_senders` under the gate: the escaping TypeError (not a `ResolutionError`) would
  propagate into the scheduler task; the scheduler's error handling was not read in this pass, so
  the secondary "scheduler thread crash" concern is out of scope here and unpriced.
