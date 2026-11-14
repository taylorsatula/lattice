# v-hunt-h2#1 — PRIMED VERIFIER

**Claim under test:** finding `hunt-h2#1` in `scratch/lattice-c1/reports/hunt-h2.md` (reported tier H)
— "Crafted from-address domain permanently wedges cold-sender resolution for all later domains."

## Verdict

**CONFIRMED** — mechanism, trigger, frequency, and severity all re-derived from source and
reproduced by execution. No component refuted.

## Frame re-derivation (done before reading the claim's conclusion)

Independently established from source:

1. `POST /lattice/v1/messages` is a public fixed route (assigned preamble invariant 3). Its body
   parameter is `dict[str, Any]`; Pydantic model validation happens *inside*
   `verify_inbound_message` (`lattice/runtime.py:630`), not at the FastAPI boundary.
2. `Message.from_address` is `Field(min_length=1, max_length=320)` with no shape validator
   (`lattice/protocol/models.py:218-236`). No in-tree code validates the domain portion.
3. `parse_address("user@![a")` returns `LatticeAddress(username='user', domain='![a', node_id=None)`
   — `![a` passes the only guards (`any(c in host for c in ":/@")`, `len<=253`).
   Empirically confirmed (`.venv` python): `domain == '![a'`.
4. `verify_inbound_message` (`runtime.py:619`): for a non-canonical address, it calls
   `self._resolver.get_pin(parsed.domain)`; on `None` it returns `(parsed.domain, True)` **before**
   the certificate lookup and **before** `verify_message`. No signature is checked on this branch.
5. `receive_message` (`lattice/api.py:289`): on `cold_sender` it calls
   `runtime.queue_domain_resolution(from_node_id)` — here `from_node_id` is the *domain* — and
   returns 503. This branch precedes the `rate_limiter.allow_message` call at `api.py:335` and the
   `_own_domains` check. There is no global rate-limit middleware (`rg middleware` → none).
6. `queue_domain_resolution` (`runtime.py:895-898`) lowercases and adds to `_unresolved_domains`
   with no validation.
7. `_resolve_pending_senders` (`runtime.py:900-922`) iterates `sorted(self._unresolved_domains)`
   and its only `except` is `ResolutionError` (`runtime.py:914`). The `discard` is only on success.
8. `WellKnownResolver.pin` → `resolve` → `resolve_with_ip` (`resolution.py:37-51`) wraps only
   `self._transport.request("GET", url)` and catches only `(TransportError, NetworkPolicyError)`.
9. `OutboundTransport.request` (`transport.py:114`) calls `parse_url(url)` **outside** the
   `try/except urllib3.exceptions.HTTPError` (which starts at `transport.py:141` and wraps only
   `self._pool.urlopen`).

## Reproduction of the decisive mechanism (executed)

```
$ .venv/bin/python -c "<real WellKnownResolver + real OutboundTransport + stub pin repo>"
pin('![a')            -> ESCAPED urllib3.exceptions.LocationParseError: Failed to parse: https://![a/.well-known/lattice
```

`LocationParseError` MRO (urllib3 2.7.0): `LocationParseError < LocationValueError < ValueError <
HTTPError`. It is **not** a subclass of `TransportError` and **not** of `ResolutionError` (verified
via `issubclass` against the real classes). So it escapes `resolve_with_ip`, escapes
`_resolve_pending_senders`, and is caught only by `_RecurringTask._run`'s blanket
`except Exception` (`runtime.py:134`).

Full batch-abort reproduced with the real unbound method:

```
unresolved = {'![a', 'alpha.example', 'beta.example'}
task handler caught: LocationParseError Failed to parse: https://![a/.well-known/lattice
set after: ['![a', 'alpha.example', 'beta.example']   # no entry discarded; later domains never reached
```

`sorted()` places `![a` (0x21) before every normal domain (letters ≥ 0x61, digits ≥ 0x30). The
attacker has a stronger choice: any domain that `parse_url` rejects but `parse_address` accepts,
e.g. `%` (0x25), `[a`, `a%`, `a[b` all reproduce the escape (verified), and `%` sorts before `!`.

## Per-component disposition

| Component | Verdict | Trace |
|---|---|---|
| Mechanism | CONFIRMED | `parse_url` outside HTTPError try → `LocationParseError` ∉ `{TransportError,NetworkPolicyError}` ∉ `ResolutionError` → `_RecurringTask._run` blanket catch aborts the batch. Reproduced by execution. |
| Trigger | CONFIRMED | One unauthenticated `POST /lattice/v1/messages` with `from_address:"user@![a"`, any `message_id` (1..128 chars), any `signature` string (never verified on this branch), tz-aware `timestamp`. Body must pass `Message.model_validate`; `![a` does. |
| Frequency | CONFIRMED | Every cold-sender POST enqueues; the recurring task re-runs every 30 s for process life and aborts at the same first-sorted entry. Demonstrated. |
| Severity | CONFIRMED at H | See below. |
| Reachability | PRODUCTION | Public fixed route, pre-rate-limit, pre-`_own_domains`, pre-signature. Not gated by any other defect. |

## Severity correction

Leave unchanged at **H**. The trace: `LOOSE_ENDS.md` records the cold-sender → 503 →
background-pin flow as the *designed* onboarding path, and `ARCHITECTURE.md:29` states "gossip
cannot establish or replace a domain pin" while `topology.verify_candidate` (the only other
resolver caller) calls `resolve_with_ip` but never `resolver.pin` — grep of `pin_repo.upsert` shows
the only pin writers are `_pin_bootstrap_peers` (config), `resolve_address` (outbound/operator), and
`_resolve_pending_senders` (this path). So this path is the sole mechanism by which an inbound
`user@domain` sender becomes pinnable.

Impact: one unauthenticated internet request permanently denies custody acceptance to **all**
subsequent cold senders (503 forever), i.e. one actor denies the node's core onboarding function
for every other actor. This is unauthenticated, remote, and persistent until restart. It matches the
H tier ("remote … reachable by a network peer"; cross-peer reach). Caveat recorded, not a downgrade:
there is no data loss/corruption — senders retain custody — so the tier rests on the
remote-persistent-Denial-of-Service + cross-peer clause, not the loss clause.

## Frequency correction

Leave unchanged at **DEMONSTRATED**. Operation population: every `POST /lattice/v1/messages` from an
unpinned `user@domain`; cadence: the attacker's one request; the `cold_sender_resolution` task fires
every 30.0 s (`runtime.py:345-350`) and re-aborts each cycle. The poison entry is never discarded
(discard only on success) and no other code removes it. Grounded in-tree; not latent.

## Sub-claims refuted

None. Every component of the claim checked out. Two minor factual discrepancies, neither affecting
the verdict:

- The claim's "Confidence" line cites urllib3 **2.3.0**; the local environment ships **2.7.0**
  (`.venv`). `LocationParseError`'s class hierarchy and `parse_url` rejection behavior are
  identical in both; the reproduction was run against 2.7.0. Citation nit only.
- The claim says the loop "aborts the whole batch" — correct. It is caught by
  `_RecurringTask._run`, not by the resolver or the per-domain loop. The claim states this
  accurately.

## Additional mechanisms / earlier failure sites (single-pass, priced)

1. **Earlier failure site for the same root cause:** `OutboundTransport.request`
   (`transport.py:114`) invokes `parse_url` before entering its HTTPError guard. This is the actual
   defect locus; the missing `ResolutionError` catch in `_resolve_pending_senders` is the amplifier.
   Priced under fix-direction below.
2. **Same escape, no batch-abort, requires operator action (L, production, operator-gated):**
   `resolve_address` (`resolution.py:172`) calls `resolver.pin`; its callers
   `RuntimeCoordinator.resolve_destination` → `api.admin_submit` catch only `RuntimeError`
   (`api.py:~398`), so a poison domain raises `LocationParseError` past the handler and FastAPI
   returns 500 instead of 400. Trigger: an admin bearer holder submits `to_address:"user@%"`
   (or similar). Narrow, operator-driven; wrong-status-code outcome. Not the claimed defect.
3. **Same escape at `_certificate_for_node` (`runtime.py:680`) and `_pin_bootstrap_peers`
   (`runtime.py:429`):** both catch only `ResolutionError`. Inputs are peer-store/pin domains and
   config bootstrap URLs respectively, not unverified request fields, so no hostile input was traced
   to them today. Single-pass, not priced as a finding.
4. **Topology variant is already contained:** `topology.verify_candidate` (`topology.py:223`) calls
   `resolve_with_ip`, which has the same escape, but `_run_verify_candidates`
   (`runtime.py:1124`) wraps each candidate in its own `except Exception`, so no batch abort. Also
   the card must pass signature verification first. Not a second wedge.

## Fix-direction constraints

- Do **not** stop at widening `_resolve_pending_senders` to `except Exception`/`HTTPError`. That
  stops the batch abort but (a) leaves the poison entry in `_unresolved_domains` re-attempted every
  30 s forever, and (b) defeats the function's documented "drops it from the queue" intent for the
  `ResolutionError` branch as well. Escaping structure-breaking is not the same as preventing the
  poison entry.
- The ingestion point must validate/normalize the domain before it enters the queue
  (`queue_domain_resolution` and/or `parse_address`), so a domain urllib3 cannot URL-parse never
  becomes a queue member. This is the actual boundary.
- The transport layer should convert URL-construction/parse failures into `TransportError` at
  `transport.py:114` so the class of "escapes every narrow handler" errors is closed at the source;
  the same conversion fixes the admin-route 500 in side discovery 2.
- On genuine failure the entry should be removed (matching the docstring), and a size cap/TTL is
  needed — otherwise the queue grows unbounded and keeps re-attempting attacker-chosen hostnames.
- A repair must preserve that other resolvable queued domains are still processed when one entry
  fails (per-entry isolation), not merely relocate the abort.

## Checked and clean

- Public route contract: `receive_message` ordering (validate → cold-sender → own-domain → rate
  limit → accept) is as the claim describes; the cold-sender branch is genuinely pre-rate-limit and
  pre-own-domain (api.py:289-337). No global middleware rate limiter exists.
- `queue_domain_resolution` lowercases and does no validation — confirmed, and confirmed reachable
  with the claimed value (the domain, not a node ID).
- `_RecurringTask.maybe_run`/`_run` (`runtime.py:118-139`): non-overlap lock, blanket `except
  Exception`, lock released in `finally`, scheduler thread survives the exception — so the wedge is
  per-cycle, not a one-shot crash. Confirmed.
- The claim's assertion that `verify_inbound_message` returns `(domain, True)` before any signature
  check is correct (runtime.py:646-650).
- `discard` appears only in the success branch; no other remover of `_unresolved_domains` exists.

## Enumeration

Assignment: enumerate pin writers, resolver callers, and catch sites for the resolution stack.

Command:
```
rg -n "\.pin\(|queue_domain_resolution|_resolver\.(resolve|resolve_with_ip)|pin_repo\.upsert|except \(TransportError, NetworkPolicyError\)|except ResolutionError|parsed = parse_url|except urllib3.exceptions.HTTPError" lattice/ --type py
```

| # | Site | Role | Disposition |
|---|---|---|---|
| 1 | resolution.py:51 | catches `TransportError, NetworkPolicyError` only | examined — misses LocationParseError (root) |
| 2 | resolution.py:172 `resolve_address` → `pin` | outbound pin | examined — side discovery 2 |
| 3 | runtime.py:429 `_pin_bootstrap_peers` | bootstrap pin | examined — config input, no hostile trace |
| 4 | runtime.py:680 `_certificate_for_node` | `resolve` | examined — peer/pin-store input, no hostile trace |
| 5 | runtime.py:914 `_resolve_pending_senders` | catches `ResolutionError` | **finding 1 site** — batch abort |
| 6 | runtime.py:895 `queue_domain_resolution` | ingestion | examined — no validation |
| 7 | transport.py:114 `parse_url` | pre-guard URL parse | earlier failure site |
| 8 | transport.py:141 `urlopen` guard | HTTPError→TransportError | examined-clean (does not cover parse_url) |
| 9 | topology.py:223 `resolve_with_ip` | candidate verify | same escape, per-item caught — contained |
| 10 | runtime.py:451 `pin_repo.upsert` (bootstrap) | pin writer | examined-clean |

## Bound

- Not exercised: the live FastAPI route end-to-end (no ASGI test server started); the trigger was
  established from the route's own code plus execution of every class it dispatches to
  (`parse_address`, `Message.model_validate` inputs, `WellKnownResolver.pin`, `OutboundTransport`).
- Provider/DNS behaviour for a *valid* domain was not exercised (would require network); the defect
  fires before any network I/O, at `parse_url`, so this is irrelevant to the verdict.
- Nginx/edge filtering (invariant 7) not inspected; the defect is in Python and assumes the request
  reaches the app, which is the stated in-scope assumption for `POST /lattice/v1/messages`.
- The exact class of host strings urllib3 rejects is version-dependent; the repo's pinned urllib3
  (2.7.0 in `.venv`, claim says 2.3.0) rejects at least `![a`, `[a`, `a[b`, `%`, `a%`. If a future
  urllib3 tightened `parse_address`-accepted strings too, the boundary would move, but at least `%`
  and `[` are reserved URL characters and will not become valid IPC hosts.

## Design risks (max 2)

1. **The domain-to-queue boundary is unvalidated everywhere.** `queue_domain_resolution` and
   `resolve_address` both accept any string `parse_address` lets through, deferring URL validity to
   urllib3. Centralizing domain-host validity at `parse_address` (or a dedicated validator) would
   prevent this and the queued-garbage class generally. (Design, not a confirmed second finding.)
2. **`_unresolved_domains` has no cap or TTL (hunt-h2#2's subject).** Independent of the escape,
   every distinct attacker domain persists for process life and is re-attempted each cycle; that is
   a separate reportable defect and is deliberately not re-adjudicated here.
