# v-seam-s2#2 — PRIMED VERIFIER of seam-s2 finding 2

Claim under test: **seam-s2#2 [M] — "Unbracketed IPv6 target URL fails to parse: IPv6-resolved peers
can never be fetched"** (`scratch/lattice-c1/reports/seam-s2.md`), location
`lattice/transport.py:OutboundTransport.request`, the `target_url = f"https://{ip}:{port}{parsed.request_uri}"`
statement (transport.py:125).

Verdict: **CONFIRMED** (tier **M**, unchanged). Mechanism and trigger reproduced at the statement level
against the real code with an in-process `getaddrinfo` stub — no file modified, no network. One
frequency/breadth sub-claim is **overstated and corrected** below; the affected-population rate is
recorded as a bound, not used to demote.

Reachability kind: **PRODUCTION** (not gated behind another defect). A daemon host with IPv6
connectivity, contacting any peer domain whose first policy-allowed `getaddrinfo` answer is AAAA
(candidate verification, pinning, message custody, gossip send) hits the failure site.

Environment: urllib3 **2.3.0** (installed), Python 3.12. All parse/exception/composition facts below were
run in this environment, not read from prose.

---

## Frame re-derived from source (before checking the claim)

- **Where the IP comes from.** `OutboundTransport._resolve_and_validate` (transport.py:73-96) calls
  `socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)` (transport.py:77), iterates
  the results in the order returned, normalizes IPv4-mapped IPv6 to IPv4, and **returns the first result
  that passes `policy.validate_ip`**. `NetworkPolicy.public.validate_ip` (network_policy.py:60-68) rejects
  only `is_private/loopback/link_local/reserved/unspecified`; a global IPv6 address passes. So an
  IPv6-first answer is returned as an `ipaddress.IPv6Address`. No fallback to a later IPv4 answer exists.
- **What the URL becomes.** transport.py:125: `target_url = f"https://{ip}:{port}{parsed.request_uri}"`.
  `str(IPv6Address('2606:4700::6810:84e5'))` is `2606:4700::6810:84e5` (no brackets), so the string is
  `https://2606:4700::6810:84e5:443/.well-known/lattice`. Confirmed by running the expression.
- **Where it fails.** `self._pool.urlopen(...)` (transport.py:132-139) is the next call. urllib3 2.3.0
  `PoolManager.urlopen` begins `u = parse_url(url)` (verified from installed source). `parse_url` raises
  `LocationParseError` for an unbracketed IPv6 authority — verified: `parse_url("https://2001:db8::1:443/x")`
  → `LocationParseError: Failed to parse`. `LocationParseError.__mro__` is
  `[LocationParseError, LocationValueError, ValueError, HTTPError, ...]`, so the `except
  urllib3.exceptions.HTTPError` at transport.py:141 catches it and wraps it as
  `TransportError("HTTP request failed: Failed to parse: ...")`.
- **Consumers of the failure.** `WellKnownResolver.resolve_with_ip` (resolution.py:40-112) wraps
  `TransportError` as `ResolutionError`; `TopologyService.verify_candidate` (topology.py:222-224) wraps
  that as `TopologyError`; `_run_verify_candidates` (runtime.py:1124-1129) catches and logs. The candidate
  is **not removed** on a resolution failure (topology.py:222-224 raises without
  `remove_candidate`), so it is retried every `verify_interval_seconds = 60.0` (runtime.py:104).

### End-to-end reproduction (real `OutboundTransport.request`, in-process stub)

```
socket.getaddrinfo := lambda host, ...: [(AF_INET6, SOCK_STREAM, 6, '', ('2606:4700::6810:84e5',0,0,0))]
OutboundTransport(NetworkPolicy.public()).request('GET', 'https://example.com/.well-known/lattice')
-> RAISED TransportError : HTTP request failed: Failed to parse:
   https://2606:4700::6810:84e5:443/.well-known/lattice
```

This exercises every statement on the claim's path (resolve → validate → composite → urlopen) with no
network and no edit.

---

## Sub-claim disposition

| Sub-claim (as written in seam-s2#2) | Verdict | Decisive artifact |
|---|---|---|
| `_resolve_and_validate` can return an `IPv6Address` in public mode | CONFIRMED | transport.py:77/85-96; network_policy.py:60-68 |
| `f"https://{ip}:{port}"` emits an unbracketed IPv6 literal | CONFIRMED | transport.py:125; `str(IPv6Address(...))` probe |
| `PoolManager.urlopen` calls `parse_url` first and it raises | CONFIRMED | urllib3 2.3.0 installed source; `parse_url` probe |
| `LocationParseError` is an `HTTPError` subclass → wrapped as `TransportError` | CONFIRMED | MRO probe; transport.py:141 |
| Trigger = candidate verification / pinning / outbound POST for an AAAA-first domain | CONFIRMED, tri-path | topology.py:223; resolution.py:40; runtime.py:964 & 1113; cadence runtime.py:104 |
| Consequence: `resolved_ip` is never an IPv6 string in production; `prefix_from_ip` IPv6 /48 branch dead | CONFIRMED | only producer is transport.py:149; only consumer topology.py:234 |
| **"on dual-stack hosts … so dual-stack peer domains hit this, not just IPv6-only ones"** | **PARTLY REFUTED — suspected, platform-dependent** | see below |
| **"Frequency: any peer domain resolving to IPv6-first, on any daemon host with IPv6 enabled"** | **Corrected** | `getaddrinfo` ordering is RFC 6724 / platform dependent and the peer population is ungrounded |

**Refuted / corrected sub-claims (named).**

1. *Breadth.* `getaddrinfo(..., AF_UNSPEC, SOCK_STREAM)` with `ai_flags=0` returns both families, but the
   **order** is not fixed by the Python call: RFC 6724 destination-address selection depends on the local
   source addresses. On a daemon host with no global IPv6 source, glibc/macOS typically sort A before
   AAAA, and the code then returns IPv4 and succeeds. The claim's "dual-stack hosts … hit this" is
   therefore true only on hosts that also have usable IPv6 connectivity — the report's own "Bound" section
   concedes this, but the trigger sentence states it without qualification. This does not refute the
   defect; it narrows the trigger.
2. *Affected-population rate.* The operation-level frequency is deterministic once triggered (100% of
   verification/pin/POST attempts for an AAAA-first domain fail), but the number of AAAA-first peer
   domains in a real deployment cannot be measured from the tree (no live DNS, no peer population). Per
   calibration this is a **bound**, not a demotion: the mechanism is fully traced, the code path is the
   *only* path for such a peer, and the code visibly intends IPv6 support (`isinstance` handling,
   `ipv4_mapped`, `prefix_from_ip` /48 branch, protocol models). Recorded as ungrounded population.

---

## Severity / frequency

- **Severity: M — unchanged.** Outcome is a correctness fault: a peer reachable only via IPv6 (or via a
  domain whose policy-allowed first answer is AAAA) can never be verified, pinned, or messaged. The
  candidate is retried and re-fails every 60 s until its TTL, and outbound sends record retryable
  failures and trip the per-peer circuit breaker (runtime.py:964-968; 1113-1116) — a stuck-queue /
  wrong-state outcome under the M clause. It is not H: no data loss, no secret exposure, no auth bypass,
  no cross-peer read; the failing requests never reach a peer. It is more than L: it is not a boundary
  off-by-one or a misreported field — it is an entire transport family that cannot function, and the
  IPv6 half of the recorded diversity contract (`prefix_from_ip`) is unreachable as a result.
- **Frequency: DEMONSTRATED at the operation level; corrected at the population level.** Callers and
  cadence: `verify_candidates` every 60 s per unverified candidate (runtime.py:104, 371), pinning on
  `resolve_address` (resolution.py:130-137), message custody and gossip POSTs per queued item / gossip
  round (runtime.py:964, 1113). For a domain whose first allowed answer is AAAA, every one of those
  operations fails. The population rate (how many such domains a deployment sees) is not groundable from
  the tree → bound.

---

## Additional mechanisms / earlier failure sites / new reachability (same seam)

1. **Second, earlier failure site for IPv6-literal endpoints (production).** When a peer advertises an
   endpoint whose host is a bracketed IPv6 literal (e.g. `https://[2001:db8::1]:8443/lattice/v1/messages`
   in its well-known `endpoints.messages`), `parse_url` returns `host == '[2001:db8::1]'` (brackets
   retained — verified), and `_resolve_and_validate` passes that bracketed string to
   `getaddrinfo` (transport.py:77), which raises `gaierror` → `TransportError("DNS resolution failed for
   [2001:db8::1]")`. Reproduced in-process. The protocol models only require `https://` and forbid `@`
   (`models.py:_validate_https_url`), so such an endpoint validates and is stored verbatim
   (`PeerRepository`); `peer_endpoint_for_node` (runtime.py:739-751) returns it unchanged. This is a
   *different* failure site (transport.py:77, not :125) reached by a different input class (literal
   endpoint, not AAAA-first hostname). Priced: **L** — narrow trigger (a peer that publishes an IPv6
   literal endpoint), bounded outcome (that peer's messages/gossip cannot be delivered), production
   reachability. A repair that only brackets the rewritten URL does not fix it.
2. **No address fallback.** `_resolve_and_validate` returns the first policy-allowed address and never
   retries the remaining answers on connection failure. Even after the URL bug is fixed, an AAAA-first
   host whose IPv6 route is down will not fall back to its working A record. Latent/enabling, not a
   separate live defect today; noted as a fix-direction constraint.
3. **Candidate not removed on resolution failure** (topology.py:222-224) → the stuck candidate is retried
   and logged at `exception` level every 60 s until TTL. Part of the M outcome; a repair that only fixes
   URL construction leaves the retry/log churn, and a repair that removes the candidate on transient
   resolution failure would silently drop recoverable peers. Not a separate finding.

---

## Checked and clean

- `prefix_from_ip` (topology.py:116-131): `ValueError → None`, `/24` IPv4, `/48` IPv6, `strict=False`,
  IPv4-mapped re-normalized — correct in isolation. Its IPv6 branch is correct code that simply cannot be
  fed by production (Finding 2 / additional-mechanism 1).
- IPv4-mapped normalization seam (transport.py:86-88): mapped IPv6 is converted to IPv4 **before**
  `str(ip)`, so `resolved_ip` never carries `::ffff:` and `prefix_from_ip`'s defensive re-normalization is
  not needed for that input. The two sides agree.
- `resolve_with_ip` `getattr(response, "resolved_ip", None)` and `verify_candidate`'s falsy→`None` mapping
  (resolution.py:111-112; topology.py:234): correct None handling; the None path is reached by the test
  fake only (tests/conftest.py:49-54, tests/test_cli.py:359/476) and is consistent with production.
- The IPv4, non-redirect path is genuinely the validated, actually-connected IP: the pool URL host is the
  literal IP, so a reused connection goes to the validated IP. (The redirect case is Finding 1, not in
  scope here.)
- `runtime.py:964` / `runtime.py:1113` consume the response but ignore `resolved_ip` — the misattribution
  in Finding 2 is confined to `verify_candidate`'s `prefix_from_ip` call, correct as claimed.
- No test exercises the IPv6 transport path end to end; `tests/test_topology.py:308-309` tests
  `prefix_from_ip` directly with a hand-supplied IPv6 string — which is exactly why the dead branch went
  unnoticed. Coverage gap, not a defect.

## Enumeration

Failure-site closure for the outbound URL-composition class:

```
rg -n "target_url|getaddrinfo|_resolve_and_validate|parse_url\(url\)|except urllib3" lattice/transport.py
grep -rn "getaddrinfo" lattice/            # transport.py:77 — the only resolver call
grep -n '"POST"' lattice/runtime.py        # 964, 1113 — the only non-well-known senders
```

| input class | host passed to `_resolve_and_validate` | site | disposition |
|---|---|---|---|
| hostname, IPv4-first | domain | transport.py:125 | works; `resolved_ip` = IPv4 → `/24` |
| hostname, IPv6-first | domain | transport.py:125 (unbracketed composite) | **Finding 2 (M)** |
| bracketed IPv6-literal endpoint | `[addr]` retained | transport.py:77 (getaddrinfo) | additional mechanism 1 (L) |
| hostname, IPv4-mapped AAAA | normalized to IPv4 | transport.py:86-88 → 125 | works |

## Fix-direction constraints

- Bracket only for IPv6: `host = f"[{ip}]" if isinstance(ip, ipaddress.IPv6Address) else str(ip)` in the
  rewritten authority — an unconditional bracket breaks IPv4 because `parse_url` would then see `[1.2.3.4]`
  as a registered name.
- Fix the literal-endpoint case separately: `parsed.host` retains the brackets, so `_resolve_and_validate`
  must strip `[`/`]` before `getaddrinfo` while the `Host` header keeps them (RFC 7230 IPv6 Host syntax).
  Bracketing the rewritten URL alone leaves additional mechanism 1 in place.
- Preserve `Host: <original hostname>` and `assert_hostname=<original hostname>` semantics: for a
  hostname-resolved IPv6 connection the Host header is the domain (correct), not the literal.
- Do not "fix" this by rejecting IPv6 in policy — the code explicitly supports it
  (`prefix_from_ip` /48, mapped normalization) and rejecting would silently break genuine IPv6 peers.
- A repair should also decide the address-fallback question (additional mechanism 2); the current
  first-allowed-address choice means a host with one dead family is unreachable even after bracketing.

## Side discoveries

None beyond additional mechanism 1 above (priced L, production, not folded into the verdict).

## Bound

- No live network: connection-level behaviour, TLS, and real `getaddrinfo` A/AAAA ordering were not
  observed. The ordering sub-claim rests on RFC 6724 and the report's own platform caveat, and is
  marked **SUSPECTED — platform-dependent**, not confirmed.
- The affected-population rate (how many AAAA-first peer domains a deployment sees) is not measurable
  from the tree; recorded as a bound, not used to demote the tier.
- `getaddrinfo` handling of a bracketed literal was verified on macOS/CPython 3.12 only; glibc's exact
  behaviour with `[...]` is upstream and unverified here — additional mechanism 1 is SUSPECTED on Linux
  for that detail, though the retained-bracket `parsed.host` and the unbracketed-composite path (the
  claim itself) are fully traced.
