# v-hunt-s1#2 — PRIMED VERIFIER — claim hunt-s1#2 (seam-s1.md Finding 2)

Claim under test: **Finding 2 in `scratch/lattice-c1/reports/seam-s1.md`** — "Failed cold-sender
domains are never evicted from `_unresolved_domains`; set grows without bound and is re-fetched
every 30s forever" (reported tier **M**). Pass type: adversarial and symmetric.

## Verdict

**ADJUSTED** — mechanism, trigger, and frequency CONFIRMED; severity corrected **M → H**; one
sub-claim (maintenance-executor monopolization) refuted as stated. Reachability kind: **PRODUCTION**
(unauthenticated public route, real network peer).

## Re-derived frame (before checking the claim)

Established independently from source, not from the claim's phrasing:

- Public route `POST /lattice/v1/messages` (`lattice/api.py:290` decorator) carries only
  `require_content_length(MAX_MESSAGE_BODY_BYTES)` and `require_ready`. **No authentication, no rate
  limit precedes the handler body.**
- `receive_message` (`lattice/api.py:299`) calls `runtime.verify_inbound_message(message)`.
  `verify_inbound_message` (`lattice/runtime.py:619`): for a domain-form `from_address` with no pin
  it **returns `(parsed.domain, True)` before any signature check** (runtime.py:640-643). So the
  attacker does not need a valid signature.
- `Message.model_validate` (`lattice/protocol/models.py:218`) constrains `from_address` only by
  `min_length=1, max_length=320` — no format constraint. `parse_address`
  (`lattice/addressing.py:48`) admits any host with no `:/@`, length ≤ 253, lowercased. Arbitrary
  distinct attacker domains pass.
- `receive_message` cold branch (`lattice/api.py:308-325`) calls
  `runtime.queue_domain_resolution(from_node_id)` and returns 503. `queue_domain_resolution`
  (`runtime.py:895-898`) does `self._unresolved_domains.add(domain.lower())` under a lock — **no
  cap, no dedup against node id, unconditional**.
- `_resolve_pending_senders` (`runtime.py:900`) is registered as recurring task
  `cold_sender_resolution`, interval `30.0`, on `self._maintenance_executor`
  (`runtime.py:344-349`). `maintenance_workers` defaults to **2** (`runtime.py:100`), and the
  scheduler thread is started by `runtime.start()`, called in `cli.py:718`.
- In the loop (runtime.py:913-921): `pin(domain)` is the only call; on `ResolutionError` the
  handler `continue`s. `self._unresolved_domains.discard(domain)` sits **after** the try/except —
  success only. Confirmed by `rg`: `discard` has exactly one call site (runtime.py:919).
- `WellKnownResolver.pin` (`lattice/resolution.py`) raises `ResolutionError` for every failure mode
  (transport error, non-200, bad content-type/JSON/schema, domain mismatch, key/cert failure). A
  DNS failure raises `TransportError` inside `_resolve_and_validate` → `ResolutionError`. A
  resolvable-but-blackholed host blocks on `DEFAULT_TIMEOUT = urllib3.Timeout(connect=10.0,
  read=30.0)` (`lattice/transport.py:19`) → up to ~40 s per fetch.
- `NetworkPolicy(mode="public").validate_ip` permits any public IP; attacker-chosen public hosts are
  fetched. Internal IPs are rejected (so not a classic internal SSRF).

## Sub-claim adjudication

| Component | Verdict | Evidence |
|---|---|---|
| Mechanism — failure leaves the domain in the set | **CONFIRMED** | `except ResolutionError: ... continue` skips the only `discard`; `discard` reached only on success (runtime.py:913-921). |
| Trigger — unauthenticated peer can force the enqueue | **CONFIRMED** | Cold return at runtime.py:640-643 before signature check; unconditional `add` at api.py:308 → runtime.py:898; no format constraint on `from_address`. |
| Frequency — grows without bound / re-fetched every 30s | **CONFIRMED with qualification** | Distinct attacker domains → distinct set entries; scheduler interval 30.0; route unthrottled on cold path (seam-s1 Finding 5). See below. |
| Outcome (b) — "monopolizing the 2-worker maintenance executor" | **REFUTED as stated** | The long `_resolve_pending_senders` holds the per-task lock and occupies **one of two** workers (`maintenance_workers=2`). The second worker still serves the other five tasks, degraded — not monopolized. The acute claim (worker occupied indefinitely; tasks serialized) survives; the "2-worker" phrasing overstates. |
| Outcome (a)/(c) — unbounded memory + unbounded outbound fetches | **CONFIRMED** | Set is a plain `set[str]` with no cap; per cycle the loop re-fetches the entire accumulated set, and each invocation is slower than the last (cumulative work is unbounded). |

## Severity correction: M → H

**Trace that produces the correction.** The pinned scale lists as **H**: "remote crash or
**unbounded resource exhaustion reachable by a network peer**." The hunter's own justification for M
("growth is gradual and per-request work is bounded, **not instant exhaustion**") applies an
"instant" criterion that is not in the scale. On this trace:

1. The attacker is **unauthenticated** (no signature, no rate token — cold path returns before
   `allow_message`). One request per distinct domain; distinct domains are freely chosen.
2. Memory: `_unresolved_domains` has **no bound** and entries are never removed on failure; only a
   process restart clears them.
3. Work: every 30 s the node serially issues `https://<domain>/.well-known/lattice` for the whole
   set. The attacker sets the latency by pointing domains at a host that accepts TCP and stalls
   (up to ~40 s/fetch). With N stalled domains one invocation runs ~40·N s while holding one
   maintenance worker; the next cycle re-does N plus new entries. The worker is effectively occupied
   indefinitely, which delays `expiry_cleanup`, `gossip_round`, `verify_candidates`,
   `refresh_topology` (all submit to the same 2-worker pool). `expiry_cleanup` delay is
   security-relevant; `gossip_round` delay is liveness.
4. Resource direction is attacker-selected: the node performs outbound connections to
   attacker-chosen public hosts, unbounded in count over time.

The combined unbounded-memory + unbounded-outbound-work + indefinite maintenance-worker occupancy,
all reachable by an unauthenticated network peer, meets the H bullet. The memory-only component
alone could be argued M; the fetch amplification and worker starvation are what lift it. **No
frequency correction**: DEMONSTRATED is correct and if anything understated — the cold path has no
rate limit, so the cadence is "every request," not merely "every distinct domain."

## Additional mechanisms / earlier failure sites on the same trace

- **Cold-path rate-limit gap compounds this defect.** `receive_message` returns 503 before
  `rate_limiter.allow_message(from_node_id)` (api.py:308 vs api.py:329), and `allow_message` has no
  `_peer_ip` fallback (contrast `receive_gossip`, api.py:271). The enqueue therefore occurs at full
  unthrottled request rate. This is independently reported as seam-s1 Finding 5; on this trace it is
  the frequency multiplier.
- **A DB error in `pin`'s `upsert` is not `ResolutionError`.** It propagates out of
  `_resolve_pending_senders`, is swallowed by `_RecurringTask._run`'s `logger.exception`, and the
  domain is likewise never discarded. Same defect class, additional failure path.
- **The docstring is a false contract**: "On failure, drops it from the queue" while the code does
  not. The intended behavior and the shipped behavior diverge at exactly this point.

## Fix-direction constraints (beyond the reported symptom)

1. Discarding in the `except ResolutionError` branch is the minimal fix, **but insufficient alone**:
   an attacker simply re-sends and re-adds the domain on the next request. A repair must also bound
   the set (size cap / eviction policy) and/or rate-limit the cold path (Finding 5), or the unbounded
   growth returns via re-adding.
2. Eviction alone does not close the **outbound-fetch amplification**: each accepted domain still
   triggers a fetch to an attacker-chosen host. The repair must bound outbound resolution work per
   cycle (batch cap, per-attempt timeout, and eligibility) in addition to bounding the set.
3. The docstring's retry-later intent for *legitimate* cold senders must be preserved: a repair
   should distinguish transient from permanent failure with a bounded retry (attempt count/TTL +
   backoff), not an unbounded set that retries forever.
4. Do not "fix" this by trusting the unsigned `from_address` more (e.g. verifying signature before
   enqueue) — cold senders cannot be verified by design; the boundary is bounded work, not verified
   identity.

## Checked and clean (coverage)

- `queue_domain_resolution` call sites: `rg -n "queue_domain_resolution"` → exactly
  `api.py:307` and the definition `runtime.py:895`. No other enqueue path.
- `_unresolved_domains` references: `rg -n "_unresolved_domains"` (initialization 256-257,
  add 898, snapshot 909, discard 919). No pruning path anywhere; no cap; no restart persistence.
- Scheduler wiring: `_build_scheduler` (runtime.py:341-388) registers the task unconditionally;
  `cli.py:718` starts it. Not gated behind config.
- `WellKnownResolver.pin` exception surface read end to end (resolution.py): all resolution failure
  modes raise `ResolutionError`; no hidden success-without-storing path.
- `tests/`: `rg "unresolved|resolve_pending|queue_domain" tests/` → no matches. The test suite does
  not exercise the queue or the eviction contract (consistent with claim's "no test contradicts
  this").

## Enumeration

Composed commands closing the class:

    rg -n "queue_domain_resolution|_unresolved_domains|_resolve_pending_senders" lattice/
    rg -n "discard|clear\(\)" lattice/runtime.py
    rg -n "own_domains|RuntimeCoordinator\(|\.start\(\)" lattice/cli.py

Result: enqueue sites = 1 (api.py:307); discard sites = 1 (runtime.py:919); cap/prune sites = 0;
scheduler registration = 1 (runtime.py:344); production start = cli.py:718. Class closed — the
defect is the missing failure-path eviction, not a missed second queue.

## Bound (what I could not reach)

- No live run: the package cannot be imported in this environment (missing `rfc8785`), so the
  ~40 s stalled-fetch cost and the maintenance-worker occupancy are derived from
  `DEFAULT_TIMEOUT` and `maintenance_workers=2`, not observed. Mechanism is source-verified;
  wall-clock impact is SUSPECTED (arithmetic, not measured).
- Upstream/provider behavior (whether a given attacker domain resolves, whether a public host can
  hold a TLS connection to timeout) is unverifiable here; the attacker-controllable-latency step is
  therefore SUSPECTED, though `connect=10/read=30` bounds it.
- Not opened: `lattice/storage/repositories.py` `DomainPinRepository.upsert` internals (the DB-error
  variant path is inferred from the call site, not traced into the repository).

## Design risks (max 2)

1. The cold-path design fetches a URL derived from an unsigned, attacker-supplied string before any
   identity is established. Network policy blocks internal IPs, so it is not internal SSRF, but the
   node is still a free fetcher for arbitrary public hosts. Bounding work, not verifying identity, is
   the only available control. Not counted as a separate finding.
2. Even with perfect eviction, an attacker rotating `from_address` domains keeps every cold path
   request incurring a resolution attempt. Whether a per-request resolution budget is acceptable to
   legitimate first-contact peers is a design decision, not a defect.
