# v-hunt-b1c#1 — PRIMED VERIFIER on hunt-b1c finding #1

Claim under test: **hunt-b1c#1 [H] — Cold-sender domain queue never drains failed domains: unbounded
growth and eternal outbound re-resolution** (report `scratch/lattice-c1/reports/hunt-b1c.md`).

Frame was re-derived from source before reading the claim's conclusion. The decisive artifacts are
`lattice/runtime.py:_resolve_pending_senders` (895-921), `RuntimeCoordinator.queue_domain_resolution`
(895-898), the scheduler definition (345-388), and `lattice/api.py:receive_message` (286-318).

## Verdict

**CONFIRMED.** Tier **H** and frequency **DEMONSTRATED** stand, with one scope qualification on the
thread-occupancy sub-claim (below). Reachability kind: **PRODUCTION** — an unauthenticated network
peer reaches every step with a single `POST /lattice/v1/messages`.

## Re-derived frame (what the code actually does)

1. Route `/lattice/v1/messages` (`ROUTE_MESSAGES`) is public; its only dependencies are
   `require_content_length(128 KiB)` and `require_ready` (`api.py:281-285`). No auth.
2. `receive_message` calls `runtime.verify_inbound_message(message)` first (`api.py:292`).
   `verify_inbound_message` (`runtime.py:619-660`) validates via `Message.model_validate`, then
   `parsed = parse_address(model.from_address)`.
3. If `parsed.node_id is None` and `parsed.domain is not None` and no pin exists for that domain, it
   returns **`(parsed.domain, True)` before any signature check** (`runtime.py:640-646`). The
   `Message.signature` field is `str` with **no base64url validator** (`models.py:288`,
   contrast `OperationalCertificateModel`/`WellKnownDocument` which do validate) — any string
   passes `model_validate`.
4. Back in the handler, `cold_sender` True ⇒ `runtime.queue_domain_resolution(from_node_id)` then
   `return 503` (`api.py:305-318`). This return is **before** `_extract_domain_from_address` and
   **before** `runtime.rate_limiter.allow_message` (`api.py:322-335`). So no token consumed, no
   ownership check reached, no signature required.
5. `queue_domain_resolution` does `self._unresolved_domains.add(domain.lower())`
   (`runtime.py:895-898`). No size cap, no TTL, no retry counter.
6. `_resolve_pending_senders` (`runtime.py:900-921`) copies `sorted(self._unresolved_domains)` and
   loops. On success it `discard`s the domain; on `ResolutionError` it logs at debug and
   **`continue`s without discarding**. The lock is released before the loop, so the network call is
   not under the lock.
7. The scheduler binds `cold_sender_resolution` at interval **30.0 s** to `_maintenance_executor`
   (`runtime.py:344-350`); that executor has `max_workers=2` and is shared by four more tasks
   (`gossip_round`, `verify_candidates`, `refresh_topology`, `expiry_cleanup` —
   `runtime.py:349,367,373,379,385`).
8. `WellKnownResolver.pin` (`resolution.py`) does `resolve()` → HTTPS `GET
   https://<domain>/.well-known/lattice` via `OutboundTransport` (connect timeout 10 s, read
   30 s), converting `TransportError`/`NetworkPolicyError` into `ResolutionError`. In the default
   `NetworkPolicy.public` mode `hostname_allowed` returns True for any host, so arbitrary public
   domains are attempted (SSRF to internal IPs is blocked by `validate_ip`; that part is clean).

## Sub-claim disposition

| Sub-claim | Disposition |
|---|---|
| Mechanism: only the success path discards; `except ResolutionError: continue` leaves the entry | **CONFIRMED** — `runtime.py:914-919`; docstring at 903-906 states "On failure, drops it from the queue", code does not. |
| Unbounded set (no cap/TTL/retry limit) | **CONFIRMED** — the only mutations are `add` (898) and `discard` (919); `rg -n "_unresolved_domains" lattice/` shows no other cleanup, no expiry task touches it. |
| Trigger: unauthenticated POST, cold `from_address`, signature irrelevant, no rate-limit token | **CONFIRMED** — ordering at `api.py:292-335`; `Message.signature` unvalidated (`models.py:288`). |
| Every 30 s, DNS + outbound HTTPS GET per unresolved queued domain, forever | **CONFIRMED** — interval 30.0 (`runtime.py:346`), loop re-runs the full set each pass; entries persist across passes on failure and only clear on process restart. |
| "Permanently occupies one of the 2 `maintenance_workers` threads" | **CONFIRMED AS A CONDITIONAL CONSEQUENCE, with scope note.** Not literally always: `_RecurringTask._run` releases its non-overlap lock between passes, so if a pass completes in <30 s the thread is only periodically busy. Under attacker-chosen queue size a single pass (per-domain up to 10 s connect + 30 s read) exceeds the 30 s interval, at which point the non-overlap lock makes the task run continuously and pins one of the two workers, starving the other four maintenance tasks. The queue size is attacker-controlled, so the condition is reachable, not hypothetical. |
| "adversarial amplification" (request loop) | **Nuance, not refutation.** Inbound→outbound is 1:1 per unique domain, not multiplicative amplification. The real properties are *unbounded growth* and *indefinite persistence* of the outbound attempt set, plus maintenance-worker occupancy. Severity does not rest on a multiplicative factor. |

No half of the claim is refuted. The mechanism, trigger, and frequency are all present in the tree.

## Severity and frequency corrections

- **Severity: H — unchanged.** The scale assigns H to "unbounded resource exhaustion reachable by a
  network peer." `_unresolved_domains` grows without bound from unauthenticated input, and every
  entry guarantees a recurring synchronous outbound network operation and a held maintenance
  worker. That is the H definition; the additional maintenance-thread starvation compounds it. I
  considered downgrading to M on the ground that each domain string is small and growth is
  request-bound, but the exhaustion is genuinely unbounded, network-reachable, and unthrottled on
  this path, and the worker-occupancy effect is an independent resource fault. H stays.
- **Frequency: DEMONSTRATED — unchanged.** Population/cadence: any peer (a) whose domain genuinely
  fails resolution (dead/renamed/typo'd domain) or (b) that deliberately emits unique
  attacker-chosen domains via `POST /lattice/v1/messages`. For (a) the trigger is every cold sender
  whose domain does not resolve, at whatever inbound rate that sender retries (a cold sender's own
  `Retry-After: 60` yields roughly one re-queue/outbound-attempt per minute per dead domain); for
  (b) it is every request of a plain unauthenticated loop. The persistence property (entries never
  leave until restart) is demonstrated by the code path, not inferred.

## Additional mechanisms / earlier failure sites on the same trace

- **No rate limiting on the cold path (earlier than the reported symptom).** Because the 503 return
  precedes `allow_message`, the `RateLimiter` never gates cold-sender traffic at all. Even after
  the discard bug is fixed, an adversary can enqueue an arbitrary number of fresh domains inside a
  single 30 s window; one pass then performs that many outbound attempts while holding a
  maintenance worker. The discard fix alone is insufficient. (This is the strongest fix-direction
  constraint, below.)
- **Reflected attacker content.** The 503 `detail` echoes the attacker-supplied domain
  (`api.py:315`). No header/response-splitting risk (JSON body); not a defect, noted for
  completeness.
- **`OutboundTransport._resolve_and_validate` ignores `hostname_allowed`'s return value**
  (`transport.py:74`). In `public` mode this is inert; in `private` mode the following
  `validate_ip` still enforces the CIDR/suffix restriction, so the policy is not actually violated.
  Examined-clean on the decisive path; listed so a later pass does not re-open it in isolation.

## Fix-direction constraints (beyond "discard on failure")

A correct repair must address all four, not just the loop body:
1. Discard-on-failure to match the stated contract (the literal symptom).
2. A bound on the queue — size cap and/or TTL — because the discard fix does not stop a single
   window from filling the set or the pass from taking O(queue) time.
3. Rate-limit / authenticate the cold path *before* enqueue; the current ordering lets
   unauthenticated traffic drive durable outbound work.
4. Do not hold a maintenance worker across an unbounded number of network waits: bound the batch
   processed per pass and/or move cold-sender resolution off the 2-worker maintenance pool.
   Escaping structure-breaking (fixing the `continue`) is not the same as preventing the semantic
   resource fault (unbounded, attacker-driven outbound work); state the latter explicitly so a
   narrow patch is not mistaken for closure.

## Bound (what I could not reach)

- Not measured live: DNS/connection latency for the specific domains an adversary would choose, so
  the exact queue size at which a pass exceeds 30 s is arithmetic, not observation. The
  unboundedness and persistence arguments do not depend on measurement.
- Upstream TLS/DNS resolver behaviour and nginx edge limits are out of scope (invariant 7); I did
  not verify whether a deployment's edge rate-limits `POST /lattice/v1/messages`. If an upstream
  layer throttles that route, the adversarial-growth case becomes harder but the legitimate
  dead-domain case (and the boundary check) is unaffected — the defect is in the Python layer.
- Tests were not consulted; no test firming or contradicting this path was read.

## Checked and clean (coverage)

- `_resolve_pending_senders` releases `_unresolved_domains_lock` before the network loop
  (`runtime.py:908-911`) — no lock held across the network wait, so no deadlock on this path.
- `_Constants`: `ROUTE_MESSAGES` is a fixed public route as intended (invariant 3).
- `NetworkPolicy.public` blocks private/loopback/link-local IPs (`network_policy.py:validate_ip`);
  the outbound fan-out is not an internal-SSRF primitive.
- The cold path never trusts message-supplied key material; it returns before
  `verify_message`/`_certificate_for_node`.
- `_RecurringTask._run` wraps the fn in `except Exception`, so an unexpected exception from
  `pin` (e.g. a `DomainPinRepository.upsert` failure that is not a `ResolutionError`) does not kill
  the scheduler — but it also leaves the domain queued, so it compounds, not cures, the defect.

## Enumeration

Composed closure over the defect class (every mutation of the queue, every entry point, every
scheduler binding):

```
rg -n "_unresolved_domains" lattice/ ; \
rg -n "queue_domain_resolution" lattice/ ; \
rg -n "_maintenance_executor" lattice/runtime.py
```

```
lattice/runtime.py:256:  self._unresolved_domains_lock = threading.Lock()
lattice/runtime.py:257:  self._unresolved_domains: set[str] = set()
lattice/runtime.py:897-898:  add(domain.lower())          # sole insertion
lattice/runtime.py:908-909:  batch = sorted(self._unresolved_domains)   # read
lattice/runtime.py:918-919:  discard(domain)               # sole removal (success only)
lattice/api.py:307:  runtime.queue_domain_resolution(from_node_id)      # sole caller
lattice/runtime.py:895:  def queue_domain_resolution
lattice/runtime.py:273/490: maintenance executor create/shutdown
lattice/runtime.py:349,367,373,379,385: five tasks bound to the 2-worker maintenance pool
```

Instance table: 1 insertion site (api cold path), 1 removal site (success only), 0 cleanup/TTL
sites, 0 rate-limit gates before insertion. **Class closed: the queue has no failure-path drain and
no bound.**
