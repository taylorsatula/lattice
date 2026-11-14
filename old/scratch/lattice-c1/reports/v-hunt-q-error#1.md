# v-hunt-q-error#1 — PRIMED VERIFIER

Claim under test: `hunt-q-error#1` in `scratch/lattice-c1/reports/q-error.md`, reported tier **H**.
Verdict: **CONFIRMED**, with one sub-claim corrected (maintenance-pool starvation overstated).
Tier unchanged: **H**. Frequency unchanged: DEMONSTRATED. Reachability: **PRODUCTION**.

---

## Frame re-derived from source (before reading the claim's conclusion)

Enumeration command (closes the class — the only producers/consumers of the queue):

```
rg -n "queue_domain_resolution|_unresolved_domains|_resolve_pending_senders" lattice/ -g '*.py'
```

Output: producers/consumers exist only in `lattice/runtime.py` (definition `655?` no — `895`
`queue_domain_resolution`, `900` `_resolve_pending_senders`, `256-257` field) and one caller,
`lattice/api.py:307`. Nothing else reads or bounds the set. No TTL, no cap, no removal path other
than success.

Independently established facts:

- `RuntimeCoordinator._unresolved_domains: set[str]` (`runtime.py:257`), guarded by a plain
  `threading.Lock`; `queue_domain_resolution` (`895`) does `self._unresolved_domains.add(domain.lower())`
  only. No size check, no timestamp, no expiry.
- Scheduler registers `_RecurringTask("cold_sender_resolution", 30.0, self._resolve_pending_senders,
  self._maintenance_executor)` (`runtime.py:345-350`). Cadence 30 s confirmed.
- `_resolve_pending_senders` (`900`): copies `sorted(set)`, loops, on `ResolutionError` logs at
  `logger.debug` and `continue` — entry retained; only a successful `pin` removes it
  (`discard`, `919`). The docstring on the same method states "On failure, drops it from the queue."
  Code and docstring disagree; mechanism confirmed.
- Route `receive_message` (`api.py:288-316`): on `verify_inbound_message` returning
  `cold_sender=True`, it calls `runtime.queue_domain_resolution(from_node_id)` and returns 503 +
  `Retry-After: 60`. `runtime.rate_limiter.allow_message(...)` is at `api.py:335`, i.e. **after**
  the 503 return. No auth dependency on the route (`ROUTE_MESSAGES` is the fixed public route,
  guarded only by `require_content_length` and `require_ready`).
- `verify_inbound_message` (`runtime.py:619-663`): parses `Message.from_address` via
  `addressing.parse_address`; for domain-form (`parsed.node_id is None`) with no pin it returns
  `(parsed.domain, True)` at line ~645, **before** `_certificate_for_node`/signature verification and
  **before** the block check. `Message.signature` (`protocol/models.py:232`) has no validator —
  merely a `str` — and `from_address` is validated only to length 320. So a cold-sender POST need not
  carry a valid (or even non-empty) signature.
- `resolution.pin` → `resolve` → `transport.request` (`resolution.py:122,114`; `transport.py:100`)
  performs `socket.getaddrinfo` then an HTTPS GET against `https://{domain}/.well-known/lattice`.
  `DEFAULT_TIMEOUT = urllib3.Timeout(connect=10.0, read=30.0)` (`transport.py:22`). A domain resolving
  to a blackholed IP costs up to 10 s connect + 30 s read, serially, inside the single loop.
- `NetworkPolicy.hostname_allowed` returns `True` for **all** hostnames in public mode
  (`network_policy.py:85-87`); only internal IPs are rejected. Arbitrary attacker domains are
  therefore permitted egress targets (no internal SSRF, but full external egress).
- `RuntimeSettings.maintenance_workers = 2` (`runtime.py:106`), and production construction
  (`cli.py:705`) passes no `settings` override, so 2 is the live value.

---

## Sub-claim adjudication

| # | Sub-claim | Verdict |
|---|---|---|
| a | `_unresolved_domains` unbounded (no cap/expiry) | CONFIRMED |
| b | Failed resolutions are retried forever (until restart), never dropped | CONFIRMED |
| c | Failures logged at DEBUG only | CONFIRMED |
| d | Docstring says "drops it" but code does not | CONFIRMED |
| e | Trigger reachable by an unauthenticated peer with a schema-valid, signature-optional body | CONFIRMED — even stronger than claimed: no valid signature is required |
| f | Cold-sender path precedes signature verification and `allow_message` | CONFIRMED |
| g | One request → one permanently queued domain; N requests → N fetches every 30 s | CONFIRMED |
| h | Unbounded memory growth + perpetual outbound egress | CONFIRMED |
| i | "whole batch resolves serially on one maintenance worker, **starving** verify_candidates/gossip_round/refresh_topology" | **PARTIALLY REFUTED** — see below |

### Refuted half of sub-claim (i)

The claim asserts the growing queue starves the other maintenance tasks. `maintenance_workers = 2`,
not 1 (`runtime.py:106`, live default; `RuntimeCoordinator` built without a settings override at
`cli.py:705`). The cold-sender task holds `_RecurringTask._lock` for one non-overlapping run at a
time, so it occupies **one** of the two maintenance workers; the other worker continues to service
`gossip_round`, `verify_candidates`, `refresh_topology`, and `expiry`. The accurate statement is:
the serial loop monopolises one of two maintenance workers for its entire duration (which for a
large hostile queue with blackholed targets is longer than the 30 s interval), reducing all other
maintenance tasks to a single remaining worker and removing redundancy. It is a real degradation,
but it is not "starving" in the sense of preventing those tasks from running. This correction does
**not** change the verdict or the tier: the H-rating rests on unbounded memory and unbounded
perpetual egress, both fully traced.

---

## Verdict

**CONFIRMED.** Mechanism, trigger, and frequency all verified from source. The one imprecise
sentence in the claim (maintenance starvation) is corrected above; nothing in the core finding is
killed.

- **Severity: H — unchanged.** The standing scale makes "unbounded resource exhaustion reachable by
  a network peer" an H. Trace: `api.py:307` → `runtime.py:895` (unbounded set) plus `runtime.py:900`
  (perpetual serial egress loop, 30 s). Both halves are remote-input-driven and permanent for the
  process lifetime. No in-tree bound exists (`rg` above; the only removal is on success).
- **Frequency: DEMONSTRATED — unchanged.** Population: every unauthenticated POST to
  `/lattice/v1/messages`. Cadence: one request per fresh domain-form `from_address`; every such
  request enqueues one domain; each enqueued domain is retried every 30 s until process restart. A
  single spray of N requests yields N perpetual DNS+HTTPS attempts per 30 s window. The rate limiter
  cannot blunt it because it runs after the enqueue return (`api.py:335` vs `307`), and its key is
  the attacker-chosen `from_node_id`, so it is bypassable by rotating domains even if it ran.
- **Reachability kind: PRODUCTION.** Public route, no auth, no signature verification on this branch.

**Confidence:** traced (mechanism, trigger, frequency all read from source). The only unproven
component is empirical attacker throughput against live nginx/systemd edge limits — recorded as a
bound, not used to discount the finding.

---

## Additional mechanisms / earlier sites (same trace)

1. **Receiver-side durable growth (secondary, gated behind successful resolution).** `pin` also
   `upsert`s into `DomainPinRepository` (`resolution.py:133`). A hostile party that can serve a
   validly signed well-known document for arbitrarily many domains can grow the durable DB
   unboundedly through this same queue. Gated behind resolution success; noted, not a new top-tier
   finding.
2. **Permanent-failure re-fetch is a distinct sub-population.** A domain whose well-known doc is
   permanently invalid (wrong domain, bad signature, schema mismatch → `ResolutionError`) is never
   dropped, so it is re-fetched every 30 s forever although no transient condition exists. This is
   the `ResolutionError` branch itself, not a separate fix.
3. **Mid-batch abort on non-`ResolutionError`.** `_resolve_pending_senders` catches only
   `ResolutionError`; an unexpected exception from `pin` (e.g. repository `upsert` raise) escapes the
   loop, aborting resolution of the remaining domains that cycle (caught by `_RecurringTask._run` and
   logged). Domains after the failing one are delayed, not permanently blocked. Low impact; recorded
   for the fixer.

## Fix-direction constraints

- A repair must **bound and expire** the queue (max size + per-entry TTL) **and** decide retry
  policy per failure class. A blanket "drop on failure" (as the docstring currently claims) fixes the
  leak but removes retry for genuinely transient transport/DNS failures; permanent resolution
  failures (domain mismatch, invalid doc/signature) must be dropped or retry-capped, transient ones
  bounded-retried.
- Enqueue must not be reachable ahead of the abuse controls: either move `allow_message` (or an
  equivalent bounded admission check) before the cold-sender enqueue, or cap the queue per source
  and globally.
- The resolution loop must not consume an unbounded slice of the two-worker maintenance pool; a
  dedicated bounded worker and/or a per-attempt timeout shorter than `connect=10 s + read=30 s` is
  required.
- The fix must preserve legitimate cold-sender reachability (new-peer first contact is the intended
  purpose of the 503 path) — rejecting all cold senders is not an acceptable repair.

## Bound (could not reach)

- Live nginx/systemd edge rate limits and real ingress throughput are outside the Python layer and
  unobservable here; the defect is a design-level unbounded queue and holds regardless of any edge
  cap. SUSPECTED only insofar as the attacker's achieved request rate is unverified.
- The exact resolver behaviour of live DNS for hostile blackholed domains is not testable offline;
  the 10 s/30 s timeouts are read from `transport.py:22`.
- Default process log level: `cli.py:725` passes uvicorn `log_level="info"`; DEBUG output from
  `runtime.py:915` is below that level and is therefore invisible in the default deployment. (No
  `basicConfig`/`dictConfig` roots the `lattice.*` loggers to INFO; either way DEBUG is hidden.)
