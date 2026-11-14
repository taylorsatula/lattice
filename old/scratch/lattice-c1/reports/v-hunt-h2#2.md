# v-hunt-h2#2 — PRIMED VERIFIER

Claim under test: **hunt-h2#2** in `scratch/lattice-c1/reports/hunt-h2.md` — "Failed domains are
never discarded from the resolution queue: unbounded permanent retry set" (reported tier **H**).

## Verdict

**CONFIRMED** at tier **H**. The mechanism, the trigger, and the frequency all trace. Two
qualifications, neither downgrading: (a) the "every 30 s forever" retry-amplification half is
conditional on the batch not aborting, and finding `hunt-h2#1` on this *same trace* can abort it —
the unbounded **memory** half is unconditional; (b) the *rate* of growth is bounded by edge limits I
cannot read. Neither half is refuted.

Decisive artifact: `lattice/runtime.py:900-921`, the only site that mutates `_unresolved_domains`.

## Frame re-derived from source (not from the claim)

- `lattice/api.py:283-312` — `receive_message` calls `verify_inbound_message(message)`; on
  `cold_sender is True` it calls `runtime.queue_domain_resolution(from_node_id)` (line 307) and
  returns 503. This statement sits **before** `require_ready` was already satisfied and, critically,
  **before** `runtime.rate_limiter.allow_message(...)` at line 335 and before the own-domains check at
  line 322. No signature verification has occurred at that point.
- `lattice/runtime.py:619-654` `verify_inbound_message`: `Message.model_validate` → `parse_address` →
  if `parsed.node_id is None and parsed.domain is not None` and `get_pin(domain) is None`, it
  `return (parsed.domain, True)` **before** `_certificate_for_node`/`verify_message`. So the value
  passed to `queue_domain_resolution` is the attacker-controlled **domain**, and the cold path is
  genuinely unauthenticated and pre-rate-limit.
- `lattice/addressing.py:60-77` `parse_address` accepts any host with no `:`/`/`/`@` and length
  ≤253. `parse_address("user@![a").domain == "![a"`.
- `Message` (`lattice/protocol/models.py:218-232`) requires a `signature: str` field that the cold
  path never checks; any non-empty string satisfies it. `content` has no `min_length`.
- `lattice/runtime.py:895-921`:
  ```
  def queue_domain_resolution(self, domain): with lock: self._unresolved_domains.add(domain.lower())
  ...
  for domain in batch:
      try: self._resolver.pin(domain)
      except ResolutionError as exc:
          logger.debug("async pin failed for %s: %s", domain, exc); continue
      with self._unresolved_domains_lock: self._unresolved_domains.discard(domain)
  ```
  `discard` is reachable only on the success path. Docstring: *"On failure, drops it from the
  queue"* — the code does the opposite.
- Enumeration (below) closes the class: the set is `add`ed at 898, read at 909, `discard`ed at 919,
  and nowhere else — no cap, TTL, backoff, or clear. In-memory instance attribute
  (`runtime.py:257`), so restart is the only reset.

## Component-by-component

| Component | Verdict | Trace |
|---|---|---|
| Mechanism — failed domains never discarded | CONFIRMED | `except ResolutionError: ... continue` at `runtime.py:916-917` skips the only `discard` (line 919). Enumeration shows no other mutator. |
| Trigger — unauthenticated cold-sender POST queues a forever-unresolvable domain | CONFIRMED | `api.py:307` ← `verify_inbound_message` returns `(domain, True)` at `runtime.py:646` before auth; rate limiter at `api.py:335` is downstream. |
| Frequency — every cold-sender POST with an unpinned domain enqueues; task retries the whole set every 30 s | CONFIRMED for enqueue; **conditional** for retry | Task registered at `runtime.py:345-350`, `cold_sender_resolution`, interval 30.0 s, `sorted(self._unresolved_domains)` each run. Retry of *every* entry holds only when no non-`ResolutionError` entry aborts the batch — see interaction below. |
| Outcome — unbounded growth + sustained work | CONFIRMED (memory unconditional; retry conditional) | Set has no bound; each never-resolving entry is re-pinned each cycle (`pin` → `resolve` → `resolve_with_ip` → `transport.request`). |
| Reachability kind | **PRODUCTION** (public fixed route `POST /lattice/v1/messages`, unauthenticated, not gated behind any other defect) | — |

## Severity — left at H, with the trace that produced the decision

The pinned scale is explicit: *"remote crash or unbounded resource exhaustion reachable by a network
peer"* is H. An attacker-chosen domain set admitted through a fixed public route with no auth, no
signature check, and no rate limiter feeding an ever-growing in-memory set is exactly that. The
single-request → indefinite-recurring-work amplification (one cheap POST makes the node re-resolve
that hostname on every 30 s cycle for the life of the process) is the H-grade element independent of
raw byte volume. Severity **unchanged (H)**.

I considered and rejected a downgrade to M (M is "wrong state/wrong custody/wrong rate decision":
this is resource, not state) and to L (L requires a *bounded* bad outcome; the growth is unbounded).
I also considered H-by-memory only: the bytes-per-request are small, so I rest H primarily on the
unbounded set + recurring-work amplification, not on fast RAM exhaustion.

## Frequency — left at DEMONSTRATED (enqueue) with one correction to the retry clause

The finding's frequency claim is demonstrated for the enqueue mechanism: every cold-sender POST whose
`from_address` host is unpinned adds one entry (`api.py:307` → `runtime.py:898`), independent of
signature, quota, or own-domains. **Correction to one clause:** the finding states the task "hits the
poison entry every cycle … Every domain sorted after the poison entry is never resolved" only in its
finding-1 text; for finding 2 it asserts every queued entry is retried every 30 s. That is true only
when the whole batch completes. `hunt-h2#1` (same trace) shows a single `LocationParseError`-shaped
entry aborts the batch at `runtime.py:915` (only `ResolutionError` is caught; `WellKnownResolver.pin`
→ `resolve_with_ip` catches only `(TransportError, NetworkPolicyError)`, and `parse_url` runs outside
the transport's try). So:

- No poison entry present → all entries retried every cycle (finding-2 retry claim holds).
- Poison entry present → batch aborts, no entry resolved, and the set only grows (memory half
  worsens; retry-amplification half disappears for that cycle).

Either way the **set is unbounded**. Frequency stays DEMONSTRATED; the retry-amplification sub-claim
is stated conditionally.

## Sub-claims refuted

None. Each of mechanism / trigger / frequency is at least partially true, and the core mechanism is
exactly as stated.

## Additional mechanisms / earlier failure sites on the same trace

1. **Earlier failure site: `hunt-h2#1`'s batch abort.** `runtime.py:915` catches only
   `ResolutionError`; a `LocationParseError` (MRO verified locally against urllib3 2.3.0:
   `LocationParseError → LocationValueError → ValueError → HTTPError`) escapes `pin` and the loop,
   caught by `_RecurringTask._run`'s blanket `except Exception` (`runtime.py:127-131`). This is an
   earlier failure on the same `_resolve_pending_senders` trace and changes the retry half of
   finding 2 (above). It is the same defect family and should be fixed together.
2. **Shutdown interaction (unreported by the hunter).** The queue is drained by a task submitted to
   `_maintenance_executor` (max 2 workers, `runtime.py:273-276`), and `stop()` calls
   `shutdown(wait=True)` (`runtime.py:490`). A large/slow batch (N entries each costing up to a DNS
   lookup, or a TCP connect timeout of 10 s for a host that resolves to a policy-allowed blackhole)
   therefore delays or stalls graceful shutdown proportionally to the unbounded set size. Secondary,
   same root cause; not separately priced.
3. **Pre-auth population of a shared in-memory structure** is the shared root of findings 1 and 2:
   `queue_domain_resolution` is the only unauthenticated write into `_unresolved_domains`, and it
   takes no validated-domain argument.

## Fix-direction constraints

A repair that only adds `self._unresolved_domains.discard(domain)` to the failure branch fixes the
code-vs-docstring mismatch but **not** the resource fault:

- The sender's 503 (`api.py:310-315`, `Retry-After: 60`) means a willing sender re-queues on every
  retry, so "drop on failure" does not bound the set against a sender that retries indefinitely; a
  size cap and/or per-domain backoff is still required, or the set must be keyed/capped by a
  bounded structure.
- Dropping only on `ResolutionError` is insufficient while `hunt-h2#1` stands: the non-`ResolutionError`
  escape still aborts the batch, so per-domain **exception isolation** (catch all exceptions per
  domain, or validate the domain before `pin`) is a separate, required change. A fix that repairs
  the discard without isolating exceptions ships the batch-abort underneath.
- Validating/normalizing the domain in `queue_domain_resolution` (reject shapes `parse_address`
  admits but urllib3 cannot parse) closes both findings at the source and is the smallest complete
  fix; it must not be a regex that silently accepts DNS-invalid labels, or the retry work remains.
- The memory half is unconditional; the retry-amplification half is not. A fix verified only against
  the poison-entry case must also be verified with an empty poison set.

## Checked and clean

- The cold-sender branch is unauthenticated and pre-rate-limit: verified by statement order in
  `api.py:292-341`.
- `queue_domain_resolution` normalizes with `.lower()` under a lock; no torn-write or duplicate-key
  concern.
- Enumeration shows no other mutator of the set, so the discard-skip is the complete mechanism.
- `Message.model_validate` is the only input gate on the cold path and it does not verify the
  signature — verified at `runtime.py:634-646` and `models.py:218-232`.
- Finding 1's empirical urllib3 claim: reproduced the exception class hierarchy locally (urllib3
  2.3.0).

## Enumeration

Assignment is enumerable ("every mutation of the resolution queue"). Composed command and output:

```
$ rg -n "_unresolved_domains" lattice/
lattice/runtime.py:256:        self._unresolved_domains_lock = threading.Lock()
lattice/runtime.py:257:        self._unresolved_domains: set[str] = set()
lattice/runtime.py:898:            self._unresolved_domains.add(domain.lower())
lattice/runtime.py:909:            batch = sorted(self._unresolved_domains)
lattice/runtime.py:919:                self._unresolved_domains.discard(domain)
$ rg -n "queue_domain_resolution" lattice/
lattice/api.py:307:            runtime.queue_domain_resolution(from_node_id)
lattice/runtime.py:895:    def queue_domain_resolution(self, domain: str) -> None:
$ rg -n "_unresolved_domains|queue_domain_resolution|_resolve_pending_senders" tests/
(no matches)
```

| Instance | Role | Disposition |
|---|---|---|
| 257 | declaration | examined-clean (in-memory, instance-scoped) |
| 898 | add | mechanism — unauthenticated write |
| 909 | read (sorted copy) | examined-clean |
| 919 | discard | success-only → **finding** |
| 895 / api.py:307 | enqueue caller | mechanism — trigger |

No cap, TTL, backoff, clear, or test coverage exists for the set. Class closed.

## Bound

- **Edge limits / nginx rate limiting** (invariant 7, out of Python scope): the *rate* at which an
  attacker can add entries is not determinable from the tree. The set is still unbounded over a
  long-lived process; only the time-to-exhaustion is uncertain.
- **systemd restart cadence**: if the service restarts periodically the set is cleared; the tree
  contains no restart schedule. Untested — stated as a boundary.
- **Live DNS/TLS behavior** against attacker-chosen hostnames (whether an entry costs a fast NXDOMAIN
  or a 10 s connect timeout) was not exercised; the retry *cost per entry* is bounded by this.
- Tests: `tests/` contains no reference to the queue, so no test-only reachability path was examined.
