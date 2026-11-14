# v-hunt-a1#3 — PRIMED VERIFIER on hunt-a1 finding 3

Claim under test: finding 3 in `scratch/lattice-c1/reports/hunt-a1.md` —
"[H] Cold-sender path: unbounded domain queue, no rate limit, eternal 30s retries"
(`lattice/api.py:receive_message` cold branch → `lattice/runtime.py:queue_domain_resolution` /
`_resolve_pending_senders`).

Method: re-derived the frame from source first (route dependency order, what
`verify_inbound_message` returns for a cold sender, what `_resolve_pending_senders` does with a
failed domain, the scheduler cadence, whether anything bounds the set), then checked the claim
against that, not against its wording. Read: `lattice/api.py` (route + dependencies + `_peer_ip`),
`lattice/runtime.py:596-720, 880-960, 111-175, 240-390, 480-500`,
`lattice/resolution.py`, `lattice/addressing.py`, `lattice/protocol/models.py`,
`lattice/protocol/constants.py`, `lattice/network_policy.py`, `lattice/transport.py`,
`lattice/rate_limit.py`, `deploy/lattice.nginx.conf`, `tests/test_integration.py`.

## Verdict: CONFIRMED (tier H)

Each component traced independently.

### Frame re-derived from source

- **Route dependency order.** `receive_message` is registered with
  `dependencies=[require_content_length(MAX_MESSAGE_BODY_BYTES), Depends(require_ready)]`
  (`lattice/api.py:284-289`). Neither is a rate limit. `runtime.rate_limiter.allow_message` is
  called at `lattice/api.py:335`, *after* the `cold_sender` early return at line 307. Confirmed:
  the cold path is unthrottled.
- **What the cold path requires.** `verify_inbound_message` (`lattice/runtime.py:619`) validates
  the `Message` model, parses `from_address`, and for a domain with no pin returns
  `(parsed.domain, True)` **before** `_certificate_for_node` / `verify_message` /
  `is_blocked`. So no signature, certificate, or quarantine is needed. `Message.from_address`
  is only `Field(min_length=1, max_length=320)` (`lattice/protocol/models.py:226`); `signature`
  is required as a field but is never read on this branch.
- **What the caller passes.** `lattice/api.py:307` calls `runtime.queue_domain_resolution(from_node_id)`
  where `from_node_id` is the attacker-supplied domain. `queue_domain_resolution`
  (`runtime.py:895`) lowercases and `add`s to `self._unresolved_domains`; there is no size check.
- **What the set holds / who bounds it.** `_unresolved_domains: set[str]` (`runtime.py:257`).
  The only mutations are `add` (line 898) and `discard` on **success** (line 919). Nothing
  else reads or caps it.
- **The decisive statement sequence** (`runtime.py:900-920`):
  ```
  for domain in batch:
      try:
          self._resolver.pin(domain)
      except ResolutionError as exc:
          logger.debug("async pin failed for %s: %s", domain, exc)
          continue            # <-- no discard on failure
      with self._unresolved_domains_lock:
          self._unresolved_domains.discard(domain)
  ```
  A domain that fails to pin stays forever. The method's own docstring claims the opposite
  ("On failure, drops it from the queue") — the code contradicts its stated contract, which
  is the strongest single artifact here.
- **Cadence.** `_build_scheduler` registers `("cold_sender_resolution", 30.0, self._resolve_pending_senders, ...)`
  (`runtime.py:344-350`). Confirmed 30 s. `_RecurringTask.maybe_run` prevents *overlap* but not
  repetition; a run longer than 30 s runs back-to-back.
- **Address shape.** `parse_address` (`addressing.py:43`) only requires an `@`, a non-empty
  username, and a host with no `:/@` and `len <= 253`. A random subdomain of a hostile wildcard
  domain passes. Confirmed.
- **Pinning cost.** `pin` → `resolve` → `transport.request("GET", https://{domain}/.well-known/lattice)`
  with `Timeout(connect=10.0, read=30.0)` (`transport.py:18`). A blackholed/controlled domain
  therefore costs up to a 10 s connect per attempt.

### Sub-claim disposition

- "Cold path before signature verification" — **CONFIRMED** (`verify_inbound_message` return order).
- "Cold path before the rate limiter" — **CONFIRMED** (api.py:307 vs 335).
- "Failed domains never discarded; set has no size bound" — **CONFIRMED** (`continue`, no cap).
- "Task re-runs every 30 s" — **CONFIRMED** (scheduler registration; non-overlap, not suppression).
- "Every 30 s DNS + HTTPS to attacker-chosen domains forever" — **CONFIRMED** (resolver + transport).
- "Unbounded memory + recurring resolution workload reachable in PRODUCTION" — **CONFIRMED**.

No sub-claim refuted.

## Corrections

- **Severity**: H, unchanged. The scale lists "unbounded resource exhaustion reachable by a
  network peer" as H, and the trigger is a public, unauthenticated, unthrottled POST. The trace
  that justifies H is the maintenance-worker/outbound-request side, not memory alone: each
  unique domain adds one permanent 30 s-cadence outbound HTTPS attempt costing up to 10 s
  connect; `cold_sender_resolution` shares the `maintenance_workers=2` pool with `gossip_round`,
  `verify_candidates`, `refresh_topology`, `expiry_cleanup` (`runtime.py:269-275, 343-388`).
  ~3 blackholed domains saturate one of two maintenance threads continuously, delaying gossip
  and topology maintenance. Memory growth is O(unique domains) of ≤253-byte strings and needs a
  very large request count to be the dominant cost.
- **Frequency**: DEMONSTRATED, with a population sharpened. The unbounded-growth population is
  "one entry per *unique* attacker-chosen from-domain, per POST", and it is grounded because the
  route is unauthenticated and unthrottled — a normal adversary on the public route, no
  coincidence required. The claim's supporting line "a single bogus domain from one buggy sender
  already persists forever" is accurate as a *leak* (one entry, one recurring attempt) but does
  not by itself demonstrate *unbounded* growth; that requires many unique domains. The tier is
  unaffected — the resource-exhaustion claim rests on the adversarial population, which is
  demonstrated.
- **Reachability kind**: PRODUCTION (public `POST /lattice/v1/messages`, no auth, no edge
  `limit_req` in `deploy/lattice.nginx.conf`; the route is only gated by `require_ready` and
  body size). Not tests-only, not gated.

## Additional mechanisms / earlier failure sites

1. **Head-of-line blocking of the maintenance pool (new).** Recorded above under Severity: the
   same trace consumes a `maintenance_workers=2` worker; `gossip_round` (60 s), `refresh_topology`
   (300 s), `verify_candidates` (60 s) and `expiry_cleanup` (60 s) queue behind it. This is an
   earlier failure site than memory exhaustion — it degrades federation before any memory limit
   is approached.
2. **Durable pin growth on the same trace (new).** If a hostile operator serves valid
   well-known documents from many controlled domains, each `pin` succeeds and writes a durable
   domain-pin row (`DomainPinRepository.upsert`, `resolution.py:122-137`) in the durable DB before
   the set entry is discarded. Pins are legitimate protocol state, but the population is
   attacker-chosen and unbounded; the cold path is the admission point.
3. **Docstring/behavior divergence (supporting artifact).** `verify_inbound_message`'s docstring
   says the caller should "accept the message into custody now ... caller stages via
   `inbound_service.stage()`", and `_resolve_pending_senders`'s docstring says failures are
   dropped. Neither is true of the code. Not reportable independently, but it establishes intent
   that the current behavior violates.

## Fix-direction constraints

- A repair must **bound and evict** `_unresolved_domains`: a cap alone (reject at
  `queue_domain_resolution`) stops memory growth but a failed domain remains queued forever and
  keeps consuming the maintenance worker; a discard-on-failure alone removes the leak but an
  attacker can re-add the same domain with one POST without limit. Both a per-run/per-set cap and
  a retry/expiry policy (or moving to a bounded durable table with backoff) are required.
- **Move the admission point past throttling.** The cold branch returns before
  `allow_message`; any fix that only bounds the queue leaves the *rate* of queueing unthrottled.
  The queue admission must be subject to a limiter keyed on something the attacker cannot mint
  per-request (note: the message key is `from_node_id`, which on this branch *is* the
  attacker-chosen domain, so the existing limiter is not a usable key here — see Side discovery).
- **Protect the maintenance executor.** A per-run time budget / batch cap is needed so N
  unresolved domains cannot monopolize a `maintenance_workers=2` thread and starve
  `gossip_round` / `topology`. Serial `pin` with a 10 s connect timeout makes N quickly saturating.
- **Do not fix by moving the cold branch after signature verification**: an unknown sender
  cannot be verified (no certificate), so that would drop first-contact mail entirely. Admission
  control must be on the queue operation itself.

## Checked and clean

- `verify_inbound_message` cold branch genuinely precedes the fast-path signature check; no
  hidden pre-auth certificate lookup (`_certificate_for_node` is only reached when a pin exists).
- `queue_domain_resolution` lowercases consistently with `_resolve_pending_senders` iterating
  the stored key, so no case-splitting duplicate entries.
- `_RecurringTask` non-overlap lock is correct and releases on exception (`runtime.py:129-137`);
  a task exception is logged, not fatal.
- `network_policy.public` rejects private/loopback/link-local/reserved/unspecified IPs, so the
  recurring outbound HTTPS is not a direct SSRF into internal networks (DNS-rebinding not
  evaluated — see Bound).
- No message relay: the cold path neither stores the body nor forwards it (invariant 6).
- No root-key operation on this path (invariant 2).
- `require_content_length` and `require_ready` behave as claimed; body size caps match nginx.
- `tests/test_integration.py:36` documents the 503/no-staging behavior as intended; the defect is
  the *queue accounting*, not the 503 itself.

## Enumeration

Class: producers/consumers of the unresolved-domain set.
```
rg -n "_unresolved_domains|queue_domain_resolution|_resolve_pending_senders" lattice/ tests/ --type py
```
Output:
```
lattice/api.py:307:            runtime.queue_domain_resolution(from_node_id)
lattice/runtime.py:256:        self._unresolved_domains_lock = threading.Lock()
lattice/runtime.py:257:        self._unresolved_domains: set[str] = set()
lattice/runtime.py:348:                self._resolve_pending_senders,
lattice/runtime.py:895:    def queue_domain_resolution(self, domain: str) -> None:
lattice/runtime.py:897:        with self._unresolved_domains_lock:
lattice/runtime.py:898:            self._unresolved_domains.add(domain.lower())
lattice/runtime.py:900:    def _resolve_pending_senders(self) -> None:
lattice/runtime.py:908:        with self._unresolved_domains_lock:
lattice/runtime.py:909:            batch = sorted(self._unresolved_domains)
lattice/runtime.py:918:            with self._unresolved_domains_lock:
lattice/runtime.py:919:                self._unresolved_domains.discard(domain)
```
Class is closed and consistent with the finding: one producer (api.py:307), one consumer
(runtime.py:900), no cap and no failure-eviction anywhere. No instance is out of scope.

## Side discoveries (single-pass, priced)

- **Cold-path limiter key is attacker-controlled.** On the cold branch `from_node_id` **is the
  attacker-supplied domain**; if the admission fix reuses `allow_message(from_node_id)`, the
  bucket key is attacker-minted per request, so the limiter is bypassable by rotating the
  from-domain — the same failure class as finding 1's XFF key. Severity M (wrong rate/quota
  decision at a public boundary), frequency DEMONSTRATED on the same per-request population,
  reachability PRODUCTION. Fix constraint: the cold-path limiter must key on
  `_peer_ip`/connection identity (with the XFF caveat) or be a global admission budget, not on
  `from_node_id`.
- **Stale docstrings** on `verify_inbound_message` (mentions `inbound_service.stage()`, which no
  caller performs) and `_resolve_pending_senders` ("drops it from the queue"). Cosmetic on its
  own; folded in as the intent/behavior artifact for the main finding, not priced separately.

## Design risks (max 2)

1. `_unresolved_domains` is in-process only, so the queue and any cap are per-process; a
   multi-process deployment would multiply the maintained population. Not a current fault.
2. `_RecurringTask` catches all exceptions per task, so if `_resolve_pending_senders` ever raised
   a non-`ResolutionError` (e.g. a repository error under load) the set survives untouched and
   the failure is only logged at exception level — observability, not a current defect. <200 words.

## Bound

- No daemon or HTTP client was run; all triggers are traced statically (FastAPI/uvicorn default
  behavior for 503/500, `urllib3` timeout semantics, and nginx request-limit absence are read,
  not executed). nginx `limit_req` is confirmed absent from the shipped conf, but an operator's
  surrounding config is unreachable from here and could mask the trigger (invariant 7).
- DNS behavior for hostile wildcard domains and the real cost of `pin` on a blackholed IP are
  inferred from `Timeout(connect=10.0)`; not measured live.
- DNS-rebinding and resolver-cache behavior of `OutboundTransport` were not audited beyond the
  public-mode IP check.
- Provider/DNS strictness and any upstream `limit_req`/connection limits outside the shipped conf
  are unverifiable from the tree.
