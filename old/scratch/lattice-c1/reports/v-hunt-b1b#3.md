# v-hunt-b1b#3 — primed verification of hunt-b1b finding 3

Claim under test: **hunt-b1b#3** (`scratch/lattice-c1/reports/hunt-b1b.md`, §Findings item 3),
reported tier **M** — `_resolve_pending_senders` never drops failed domains; the unresolved set
grows without bound from an unauthenticated, pre-rate-limit path.

**Verdict: ADJUSTED.** Mechanism, trigger, and frequency are each independently reproduced from
source and are correct. Severity is corrected **M → H**. No component is refuted.

---

## Frame re-derived from source (not from the claim)

Before checking, I established the pieces the claim depends on from the tree itself:

- **What `cold_sender` means and what is queued.** `api.py:292`
  `from_node_id, cold_sender = runtime.verify_inbound_message(message)`. In
  `runtime.py:619` `verify_inbound_message`, a message whose `from_address` parses to a
  `domain` with no existing pin returns `(parsed.domain, True)` **before** any certificate
  lookup and **before** `verify_message(...)`. So the value passed to
  `queue_domain_resolution` on the cold path is the *attacker-supplied domain*, not a node id.
  (The variable name `from_node_id` in `api.py` is a misnomer on this branch.)
- **Order relative to auth and quota.** The cold branch `if cold_sender:` at `api.py:303`
  queues at `:307` and returns `503` at `:309–316`. The own-domains check is at `:323` and
  `runtime.rate_limiter.allow_message(...)` is at `:335`. Both run **after** the 503 return.
  Confirmed by `rg -n "cold_sender|allow_message|queue_domain_resolution|_own_domains" lattice/api.py`
  (output in Enumeration). The feed is unauthenticated and unthrottled.
- **What the message must satisfy to reach the branch.** `Message.model_validate` (`models.py:218`)
  requires `message_id`, `from_address`, `to_address`, `content`, `timestamp`, `signature` and
  bounds lengths; it performs **no signature check**. `parse_address` (`addressing.py:44`) requires
  an `@`, rejects `:` `/`, and caps host at 253 chars. A random `user@<rand>.example` therefore
  passes with an arbitrary `signature` string. The only upstream gates are
  `require_content_length(MAX_MESSAGE_BODY_BYTES)` and `require_ready`, neither of which bounds
  request count.
- **What the worker does with the set.** `_resolve_pending_senders` (`runtime.py:900`) snapshots
  `sorted(self._unresolved_domains)` and, per domain, calls `self._resolver.pin(domain)`; on
  `ResolutionError` it logs at DEBUG and `continue`s; only the success branch
  (`runtime.py:918–919`) discards. Scheduled as `"cold_sender_resolution"`, interval **30.0 s**,
  on `self._maintenance_executor` (`runtime.py:344–349`), whose pool is
  `maintenance_workers=2` (`runtime.py:100`).
- **What `pin` actually does per domain.** `resolution.py:122` `pin → resolve → resolve_with_ip`
  → `OutboundTransport.request("GET", "https://{domain}/.well-known/lattice")`
  (`resolution.py:48`). `transport.request` (`transport.py:99`) runs `_resolve_and_validate`
  (`getaddrinfo` + `NetworkPolicy.validate_ip`) **before** the `urlopen` call. So the DNS/policy
  work is executed **today**, independent of finding 1.

---

## Finding adjudication

### Claimed mechanism — CONFIRMED
`_unresolved_domains` is a bare `set[str]` (`runtime.py:257`). It has exactly one mutator that
adds (`queue_domain_resolution`, `:898`) and exactly one that removes (`:919`, success branch
only). Enumeration below shows no cap, no TTL, no failure-side discard, and no second feed.
The docstring at `runtime.py:902–903` states "On failure, drops it from the queue"; the code at
`:914–915` does the opposite. Code-vs-intent contradiction reproduced.

### Claimed trigger — CONFIRMED
One unauthenticated `POST /lattice/v1/messages` with a schema-valid `Message` whose
`from_address` is `user@<any-unpinned-domain>` adds one permanent entry. Signature is not
checked on this branch; the rate limiter is not consulted (it is downstream of the 503 return).
No coincidence is required — a hostile peer, or merely a peer with a typo'd/decommissioned
domain, drives it.

### Claimed frequency — CONFIRMED
Per unique from-domain, per POST. An attacker generates unbounded distinct domains (≤253 chars,
no `:/@`) at one small POST each; nothing caps the set. A benign sender with a permanently
unresolvable domain leaves one entry forever.

### Claimed outcome — CONFIRMED with additions
Unbounded in-process memory growth plus recurring per-entry network work every 30 s forever.
Additional mechanisms found on the same trace are listed below.

### Severity — CORRECTED, M → H
The severity scale defines **H** as including "unbounded resource exhaustion reachable by a
network peer." That clause is met literally here: the set has no bound, the trigger is an
unauthenticated network request on a fixed public route, and it sits *in front of* the very
rate limiter built to prevent this. The hunter's own text concedes the clause applies and
downgrades on "per-request growth is one set entry and no crash occurs"; that reasoning
conflates per-request cost with boundedness. Boundedness is the axis the clause names, and it
is absent: memory and recurring egress both grow linearly with attacker requests and are never
reclaimed except by process restart. Three sibling passes on the same site independently
reached H (`hunt-a1`#3, `hunt-h2`#2, `q-error`#1) — used as calibration, not as evidence; the
trace above is the evidence. Corrected tier: **H**.

---

## Added mechanisms / earlier failure sites (same trace)

1. **The recurring egress is partly live today, not fully gated behind finding 1.** The claim
   correctly says a full HTTPS fetch resumes post-fix, but `_resolve_and_validate` runs
   `socket.getaddrinfo` + network-policy validation **before** `urlopen` (`transport.py:104–119`).
   So every queued domain already costs a DNS lookup and a policy decision every 30 s today;
   only the TLS connect is withheld by finding 1's `TypeError`.
2. **Finding 1 makes today's per-cycle work non-uniform and can abort the whole batch.** For a
   domain that resolves to a policy-allowed IP, `urlopen` raises `TypeError`
   (`fields=`/`assert_hostname=` are invalid `urlopen` kwargs — verified against the pinned
   urllib3 2.7.0, `PoolManager.urlopen` forwards `**kw` to `_make_request`, which rejects them).
   `resolve_with_ip` catches only `(TransportError, NetworkPolicyError)`, so that `TypeError`
   escapes `pin`, escapes `_resolve_pending_senders` (which catches only `ResolutionError`), and
   is swallowed by `_RecurringTask._run`'s `except Exception` (`runtime.py:133`) — ending the
   batch for that cycle. Non-resolving domains instead produce `ResolutionError` → `continue`.
   Net effect today: the set still grows unconditionally, but the per-cycle walk stops at the
   first resolvable domain.
3. **Failure is logged at DEBUG (`runtime.py:914`).** At default INFO the queue's growth and its
   perpetual failures are invisible to operators. The docstring-promised "sender will retry"
   works, but the operator signal does not exist.
4. **One worker is consumed and can starve the other maintenance tasks.** `maintenance_workers=2`
   (`runtime.py:100`); `cold_sender_resolution`, `gossip_round`, `verify_candidates`,
   `refresh_topology`, and `expiry_cleanup` share that pool (`runtime.py:344–386`). The
   `_RecurringTask` non-overlap lock (`runtime.py:124–128`) prevents overlapping runs but not a
   run that exceeds 30 s; as the set grows the resolution walk occupies one of the two workers
   continuously, serializing `expiry_cleanup` (which erases expired message content) behind it.

## Sub-claims refuted
None. Mechanism, trigger, and frequency all survive re-derivation. The only correction is the
severity tier. One wording imprecision (not a refutation): the claim frames the recurring
network work as activating "once finding 1 is repaired"; in fact the DNS/policy half is live
today (mechanism 1 above).

## Fix-direction constraints
- Discarding failed domains (the literal docstring fix) bounds nothing on its own: the attacker
  re-adds each domain with the next POST, so memory still tracks request volume. A size cap
  and/or TTL on `_unresolved_domains` is required, and it should bound *work per cycle*, not
  just bytes.
- Moving at least an IP-keyed rate check **ahead** of the cold-sender queueing is required;
  while the queueing stays upstream of `allow_message` (`api.py:307` vs `:335`), any cap only
  slows the attack.
- The repair must not assume a failed pin is terminal for legitimate senders: the sender
  re-triggers this path on its next attempt (it receives a fresh 503 and re-queues), so dropping
  after one failure is correctness-safe — but it must be paired with the cap above.
- Decorating the `except ResolutionError` with `discard` alone would also drop the domain of a
  transiently-failing *legitimate* cold sender with no record; a cap+TTL (retain, bounded) is
  the safer shape than unconditional discard.

---

## Checked and clean (coverage)
- `api.py:receive_message` cold branch ordering vs own-domains check and rate limiter: traced,
  correct as described (the defect is the ordering, not a mis-trace).
- `verify_inbound_message` cold return precedes cert lookup and signature verification: confirmed
  by reading `runtime.py:619–661`.
- `Message.model_validate` / `parse_address` admission of an unsigned random-domain message:
  confirmed by reading `models.py:218–247` and `addressing.py:44–72`.
- Only one feed (`api.py:307`) and one removal site (`runtime.py:919`): confirmed by enumeration
  below.
- `_RecurringTask` scheduling/interval/lock and `maintenance_workers=2`: read `runtime.py:111–145,
  262–286, 344–349`.
- `WellKnownResolver.pin` → `transport.request` → `_resolve_and_validate` ordering: read
  `resolution.py:40–135`, `transport.py:99–145`.
- urllib3 2.7.0 `PoolManager.urlopen` kwargs handling (finding 1's premise, needed to state
  today's per-cycle behavior): inspected the installed source; `fields`/`assert_hostname` land
  in `**kw` and are forwarded to `_make_request`, which does not accept them. Confirmed.

## Enumeration

Command 1 — mutators of the set:
`rg -n "_unresolved_domains|queue_domain_resolution" lattice/`

| Site | Role | Disposition |
|---|---|---|
| `api.py:307` | `queue_domain_resolution(from_node_id)` on cold path, pre-auth / pre-rate-limit | **finding — feed** |
| `runtime.py:256` | lock init | examined-clean |
| `runtime.py:257` | `set[str]` declaration, no cap | **finding — no bound** |
| `runtime.py:898` | `.add(domain.lower())`, no size guard | **finding — add** |
| `runtime.py:909` | `sorted(...)` snapshot each cycle | **finding — work** |
| `runtime.py:919` | `.discard(domain)` success-only | **finding — no failure discard** |

No other removal (no TTL sweep, no `clear`, no eviction) exists in tree — the class is closed
at this table.

Command 2 — order on the public route:
`rg -n "cold_sender|allow_message|queue_domain_resolution|_own_domains" lattice/api.py`
→ `292` verify → `303` cold branch → `307` queue → `335` `allow_message` → `323` own-domains.
Confirms queueing precedes both quota and the recipient-domain check.

Command 3 (schedule): `rg -n "cold_sender_resolution|maintenance_workers" lattice/runtime.py`
→ `:346` task name, `:347` `30.0`, `:100` `maintenance_workers=2`.

## Side discoveries (single-pass, priced)

- **[L] Log injection via control characters in the queued domain.** `parse_address`
  (`addressing.py:64`) rejects only `:` `/` `@` and length; it does not reject `\n`/`\r`/control
  chars, and `Message` imposes no `from_address` format validator. On the failure branch
  `runtime.py:914` logs `logger.debug("async pin failed for %s: %s", domain, exc)` with the
  attacker-controlled domain. Trigger: production, same unauthenticated POST as the main finding,
  with a domain containing an embedded newline (fails DNS → `ResolutionError` → logged).
  Outcome: forged/multi-line log records when DEBUG logging is enabled. Frequency: every such
  POST while DEBUG is on; narrow (default level is above DEBUG). Fix-direction: validate the
  domain character class at admission (or `%r`/sanitize before logging). Marked production,
  L, needs one pass before merge.

## Bound
- No live daemon, DNS, or network was exercised; growth and cycle cost are traced from code and
  from the installed urllib3 2.7.0, not observed under load.
- Reached only through the Python layer. Nginx connection/request limits and process supervision
  are out of scope (invariant 7) and unavailable; if an edge cheaply bounds distinct-domain POST
  volume the memory ceiling is deferred, but the Python path itself imposes no bound and the
  recurring per-entry work is driven by whatever requests reach the app. SUSPECTED coupling, not
  verifiable here.
- The finding's "startup / production daemon" context: `_resolve_pending_senders` only runs once
  `RuntimeCoordinator.start()` schedules it (`cmd_serve` in-tree path); traced, not observed on a
  live host.
- Did not re-audit `_resolver.pin` internals beyond the transport ordering, nor the DNS
  resolver's timeout behaviour; a slow attacker-authoritative DNS was not measured.
