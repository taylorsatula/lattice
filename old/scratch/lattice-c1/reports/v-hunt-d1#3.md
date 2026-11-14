# v-hunt-d1#3 — PRIMED VERIFIER report

Claim under test: **hunt-d1.md finding 3** (`scratch/lattice-c1/reports/hunt-d1.md`, reported tier
**M**) — "IPv6 destinations produce an unparseable unbracketed URL: all transport calls to
dual-stack or IPv6 peers fail."

Files read end to end for this verification: `lattice/transport.py` (153 lines),
`lattice/network_policy.py` (94 lines). Supporting reads: `lattice/resolution.py`,
`lattice/runtime.py` (`_send_outbound_message`, `_send_gossip_batch`,
`peer_endpoint_for_node`, `_run_expiry_cleanup`), `lattice/messages.py` (`record_failure`,
`RetryPolicy`, `expire`), `lattice/protocol/models.py` (`_validate_https_url`), `lattice/config.py`
(NetworkConfig). Empirical work run against the repo venv (`.venv`, urllib3 2.7.0, Python 3.11.13)
with the **unmodified** repo classes imported from the tree; all scaffolding (self-signed certs,
TLS server) lived in `/tmp/vh3`; no repo file was touched.

## Verdict

**CONFIRMED** (severity **M** unchanged; frequency corrected upward from "plausible" to
**DEMONSTRATED conditional on resolver ordering**; one stated trigger component **REFUTED**, one
frequency/erasure detail corrected). Reachability kind: **PRODUCTION** — the mechanism fires
independently and is *not* gated by the known kwargs fault (hunt-b1b#1); see the masking caveat
below.

## Re-derived frame (from source, before checking the claim's wording)

- `transport.py:125` builds the rewritten URL as `target_url = f"https://{ip}:{port}{parsed.request_uri}"`,
  where `ip` is whatever `_resolve_and_validate` (`:73`) returned: `ipaddress.ip_address(sockaddr[0])`,
  possibly an `IPv6Address`. `str(IPv6Address("2606:4700::6810:85e5"))` is `2606:4700::6810:85e5`
  with no brackets — verified.
- `_resolve_and_validate` iterates `socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, SOCK_STREAM)`
  (`:77`) and returns the **first** result that passes `policy.validate_ip`; there is no
  IPv4-preference and no fallback. So any hostname whose resolver orders an allowed address family
  before the other determines the returned type.
- In **public mode** (the default, `config.py` ships `mode = "public"`) a global-unicast IPv6
  address is not `is_private/is_loopback/is_link_local/is_reserved/is_unspecified`, so it passes
  `validate_ip` — verified: `ip_address("2606:4700:4700::1111").is_private` is `False`.
- `transport.py:132` calls `self._pool.urlopen(method, target_url, ...)`. urllib3 2.7.0
  `PoolManager.urlopen` (`poolmanager.py:417`) begins with `u = parse_url(url)` — **before**
  `connection_from_host` and before the `**kw` (`fields`/`assert_hostname`) reach
  `HTTPConnectionPool._make_request`. `parse_url` rejects an authority with multiple colons and no
  brackets: `LocationParseError("Failed to parse: https://2620:0:1234::1:443/path")` — verified
  directly, and `LocationParseError.__mro__` includes `HTTPError`, so `transport.py:141`'s
  `except urllib3.exceptions.HTTPError` catches it and re-raises
  `TransportError("HTTP request failed: ...")`.

## Findings (adjudication)

### 1. Mechanism — CONFIRMED (traced + empirically reproduced)

`target_url` is unbracketed, `parse_url` rejects it, the `HTTPError` catch converts it to
`TransportError`. Reproduced three independent ways against the unmodified repo classes:

- Constructed URL: `parse_url("https://2620:0:1234::1:443/path?q=1")` → `LocationParseError`.
- Live `OutboundTransport.request` to `https://localhost:55600/.well-known/lattice` (private
  policy, suffix `localhost`; macOS `getaddrinfo("localhost")` → `::1` first):
  `TransportError: HTTP request failed: Failed to parse: https://::1:55600/.well-known/lattice`,
  `__cause__ = LocationParseError`. Exactly the claim's "live confirmation".
- Live `OutboundTransport(NetworkPolicy.public()).request("GET", "https://cloudflare.com/.well-known/lattice")`
  → `TransportError: HTTP request failed: Failed to parse: https://2606:4700::6810:85e5:443/.well-known/lattice`
  (same for `google.com`). This is the default production mode, no private config needed.

### 2. Not gated by the known kwargs fault — CONFIRMED

`parse_url` is the first statement of `PoolManager.urlopen`; the kwargs fault fires later, inside
`HTTPConnectionPool._make_request`. The IPv6 failure therefore precedes it and survives its repair.
Verified by reading `poolmanager.py:417-457` and by the public-mode run above (which never reached
`_make_request`). The known fault, by contrast, raises an **uncaught `TypeError`** (not
`TransportError`) — recorded under Checked and clean; that is b1b#1's territory, not this finding's.

### 3. Trigger — CONFIRMED with one component REFUTED

- **Domain with AAAA ordered first — CONFIRMED.** `getaddrinfo` on this macOS host returns IPv6
  first for `one.one.one.one`, `cloudflare.com`, `google.com`, and the IPv6 addresses are `is_global`,
  so they pass public policy. Both `runtime.py:964` (`_send_outbound_message`) and `runtime.py:1113`
  (`_send_gossip_batch`) pass peer/pin-supplied endpoint URLs to `transport.request`, and
  `resolution.py:50` fetches `https://{domain}/.well-known/lattice`; any such host with an AAAA-first
  resolution hits the defect.
- **"or an IPv6 literal host" — REFUTED.** For a bracketed literal, urllib3 2.7.0
  `util.url._normalize_host` returns the host **with brackets** (`parse_url("https://[::1]:443/...").host`
  is `'[::1]'`), so `_resolve_and_validate` calls `getaddrinfo("[::1]", ...)`, which raises
  `gaierror [Errno 8]` → `TransportError("DNS resolution failed for [::1]")`. The literal case is
  still a defect (see Side discoveries) but it fails at a **different site** with a **different
  mechanism**; it does not reach the unbracketed-URL construction this finding is about.

### 4. Frequency correction — DEMONSTRATED (conditional), not merely "plausible"

The claim states frequency as "plausible in normal operation." The operation population is:
every outbound delivery (`_run_outbound_delivery` → `_send_outbound_message`, one call per pending
retry), every gossip round (`_run_gossip_round` → `_send_gossip_batch`, per peer), and every
well-known resolve (`_resolve_pending_senders` / `pin`), whenever the destination host resolves
AAAA-before-A. I demonstrated AAAA-first ordering and the resulting failure on real dual-stack
domains on this host, so the population is not hypothetical. The residual unproven condition is
**resolver ordering on the production host class** (macOS demonstrated; Linux/host without IPv6
routability unverified — see Bound). Hence: DEMONSTRATED on an IPv6-capable resolver, deployment-
dependent on RFC 6724 ordering. This is an upward correction of the claim's own hedge, not a change
to its substance.

### 5. Outcome / erasure detail — minor correction

The claim's "churn … until `_run_expiry_cleanup` erases them" is imprecise. A `TransportError` in
`_send_outbound_message` calls `record_failure(retryable=True)` (`runtime.py:967`); while
`RetryPolicy.should_retry(attempt_count)` holds (`max_attempts=10`, `messages.py:43`) the lease is
released and retried; on exhaustion `mark_terminal(..., erase_content=True)` erases the body
(`messages.py:174-185`). The TTL sweep (`expire()`, `_run_expiry_cleanup`) is a *separate* erasure
path. Either way the message body is eventually erased and the outcome ("eventual expiry-with-
erasure") stands; only the named mechanism is off. Gossip to such a peer instead catches
`TransportError`, logs, and calls `_circuit_record_failure(node_id)` — permanently degrading
topology rather than churning a message.

### 6. Severity — unchanged at M

Outcome is a permanent, silent delivery failure for one peer class, persisted as a stuck/lost queue
item with body erasure, plus circuit-breaker suppression of gossip to that peer. On the pinned
scale this is squarely **M** ("a stuck or lost queue item"). It is a subset of the already-H
hunt-b1b#1 (all outbound I/O dead); an argument for **H** exists on the "data loss" clause (the
erased queued body), but (a) the harm is the sender's own outbound copy, (b) no cross-peer/cross-user
reach, and (c) observable incremental harm today is masked by b1b#1 since no request completes
anyway. M retained.

### Reachability kind

**PRODUCTION.** Not gated: the parse failure fires before the kwargs fault and would remain after
that fault is repaired. Masking caveat (recorded, not a refutation): today every request fails for
every peer, so this finding's *incremental* observable effect is latent-until-b1b#1-repaired; its
significance is that a kwargs-only repair leaves IPv6 peers broken.

## Checked and clean

- `transport.py` scheme guard (`parsed.scheme != "https"` → `TransportError`) and missing-host
  guard: executed before any resolution; correct.
- `_resolve_and_validate` single-`getaddrinfo`, connect-to-validated-IP design: the returned `ip`
  is the exact value interpolated into `target_url`, so absent the IPv6 bracket defect there is no
  second resolution — the TOCTOU-free property the docstring claims holds.
- The `HTTPError` catch (`transport.py:141`) is correctly typed for `LocationParseError`; the IPv6
  failure is delivered to callers as a `TransportError`, which `resolution.py:51` and both runtime
  send paths do catch. (Contrast: the known kwargs fault's `TypeError` is not caught — b1b#1.)
- `NetworkPolicy._is_internal` coverage for public mode: the IPv6 addresses returned by real
  dual-stack resolvers here are `is_global` and correctly allowed by policy, so their rejection is
  *not* a policy false-negative — the defect is purely URL construction.
- Endpoint schema (`models.py:48 _validate_https_url`) admits IPv6-literal URLs (only scheme and
  `@` are checked), which is what makes the Side-discovery case a live (if narrow) path.
- Retry arithmetic (`RetryPolicy`, `record_failure`, `mark_terminal`, `expire`) re-read; the
  erasure-on-exhaustion path is as described in §5.

## Enumeration

Composed command (run from repo root):

```
rg -n 'target_url = |getaddrinfo|urlopen\(|except urllib3.exceptions.HTTPError' lattice/transport.py
```

Output (all instances, dispositioned):

| Instance | Disposition |
|---|---|
| `transport.py:125 target_url = f"https://{ip}:{port}{parsed.request_uri}"` | **finding** — unbracketed IPv6 |
| `transport.py:77 socket.getaddrinfo(..., AF_UNSPEC, SOCK_STREAM)` | examined-clean; supplies the IPv6 address that triggers the finding |
| `transport.py:132 self._pool.urlopen(...)` | examined-clean for *this* finding (parse_url precedes kwargs); the kwargs fault here is the known b1b#1 |
| `transport.py:141 except urllib3.exceptions.HTTPError` | examined-clean — correctly catches `LocationParseError` |

Caller enumeration: `rg -n "transport.request|\.request\(" lattice/ --type py` → only
`resolution.py:50` (well-known GET), `runtime.py:964` (message POST), `runtime.py:1113` (gossip
POST). All three feed a hostname that can resolve AAAA-first; none is IPv4-biased.

## Design risks (max 2)

1. `_resolve_and_validate` returns the *first* policy-valid result of an unordered `AF_UNSPEC`
   lookup, so peer reachability silently depends on resolver ordering; a dual-stack peer is reached
   or not depending on which family the resolver lists first. A bracket fix removes today's crash
   but leaves this ordering sensitivity.
2. `request()` re-derives nothing from `FederationResponse.resolved_ip`; once fixed, a dual-stack
   peer connects over IPv6 while the `Host` header stays the original name — correct, but it means
   topology-diversity accounting (Phase 6) records the IPv6 prefix, worth confirming downstream.

## Side discoveries

- **[L] IPv6-literal endpoint URLs are unservable and misreported.** `[L], latent.` Location:
  `transport.py:_resolve_and_validate` / `request`. `models.py:_validate_https_url` permits
  `https://[2001:db8::1]/lattice/v1/messages`, but `parse_url` returns the host **with brackets**
  (urllib3 2.7.0 `_normalize_host`), so `getaddrinfo("[2001:db8::1]")` raises `gaierror` →
  `TransportError("DNS resolution failed for [2001:db8::1]")`. Trigger: any peer or pin whose
  advertised `messages`/`gossip` endpoint is an IPv6 literal (schema-valid, operator/peer-authored).
  Frequency: LATENT — requires a peer configured with a literal endpoint; no default deployment
  produces one. Outcome: messages/gossip to that peer always fail with a misleading DNS error.
  Fix-direction constraint: strip brackets from `parsed.host` before `getaddrinfo`, and bracket the
  IP when reconstructing `target_url`; both must land together.
- **[recorded] The known kwargs fault raises an uncaught `TypeError`, not `TransportError`.**
  Unmodified `OutboundTransport` vs a local TLS server: `TypeError: HTTPConnectionPool._make_request()
  got an unexpected keyword argument 'fields'`, propagating out of `request()` (the `HTTPError` catch
  does not cover `TypeError`). This contradicts the "surfaces as TransportError" framing that some
  accounts apply generally, but it is hunt-b1b#1's finding; flagged for the merge layer, not
  re-reported.

## Bound

- Linux/RFC 6724 resolver ordering on the production host class is not reachable here; only macOS
  `getaddrinfo` ordering was demonstrated. The finding's mechanism does not depend on ordering — any
  AAAA-first result reproduces it — but the *frequency* retains this condition.
- No live daemon run was possible: the known kwargs fault blocks every real request, so no gated
  path was observed end to end; the IPv6 failure was reproduced at the `OutboundTransport` boundary
  with the repo classes, which is where it fires.
- `parse_url` host-bracket behavior is that of the pinned urllib3 2.7.0 in `.venv`; a different
  urllib3 minor could change it, which would move the literal-endpoint failure site (not the
  unbracketed-domain mechanism).
