# blind-seam-s2 — CONTRACT CHECK: `FederationResponse.resolved_ip`

Assignment: is `resolved_ip` always the policy-validated IP the connection was actually made to,
and does topology's prefix grouping / discovery-slot selection correctly consume it — including the
None and IPv4-mapped/IPv6 cases?

Method: read `lattice/transport.py`, `lattice/resolution.py`, `lattice/topology.py`,
`lattice/peers.py`, `lattice/gossip.py`, the relevant repositories, and `runtime.py` call sites end
to end. Two behaviours were settled by running the interpreter against the pinned HTTP client
(`urllib3`), not by reading alone. No live external probe was needed; the failures reproduce before
a socket is opened.

**Result: the contract is refuted on the producer side, twice.** `resolved_ip` is not merely a
sometimes-wrong value — the transport that is supposed to produce it cannot complete a request at
all under the pinned dependency, and when it can, an IPv6 destination cannot be connected to. The
topology consumer is, separately, correct for every `resolved_ip` value it can actually receive.

---

## Findings

### 1. [H] `OutboundTransport.request` raises `TypeError` on every call under pinned `urllib3>=2.0.0`

- Location: `lattice/transport.py:OutboundTransport.request` (call at lines 132–139)
- Evidence:
  ```python
  response = self._pool.urlopen(
      method,
      target_url,
      body=body,
      headers=request_headers,
      fields=fields,
      assert_hostname=hostname,
      preload_content=True,
  )
  ```
  `self._pool` is a `urllib3.PoolManager`. In urllib3 ≥ 2.0 `PoolManager.urlopen` forwards
  unrecognised keywords into `HTTPConnectionPool._make_request`, whose signature accepts neither
  `fields` nor `assert_hostname`. `pyproject.toml` declares `urllib3>=2.0.0` and `uv.lock` resolves
  `urllib3 2.7.0`. Both `assert_hostname` (a connection-construction parameter in 2.x) and `fields`
  (an argument of `request()`, not `urlopen()`) were 1.x-era `urlopen` keywords.

- Trigger: any call to `OutboundTransport.request`. The `try/except` at line 140 catches only
  `urllib3.exceptions.HTTPError`; `TypeError` is not an `HTTPError`, so it escapes `request()`
  uncaught and unwrapped. `WellKnownResolver.resolve_with_ip` (resolution.py:48) catches only
  `(TransportError, NetworkPolicyError)`, so the `TypeError` escapes resolution too. Concretely:
  - `runtime._run_verify_candidates` (runtime.py:1124) → `TopologyService.verify_candidate`
    (topology.py:223) → `resolve_with_ip` → `request`: caught by the broad `except Exception` at
    runtime.py:1128, logged as "candidate verification failed"; no candidate is ever verified.
  - `runtime._run_gossip_round` (runtime.py:1079) → `_send_gossip_batch` → `request` at
    runtime.py:1113, whose handler catches only `TransportError`: `TypeError` escapes to
    `_RecurringTask._run` (runtime.py:130) and is logged. No peer card is ever sent.
  - `runtime._send_outbound_message` (runtime.py:962, handler line 965 catches only
    `TransportError`): `TypeError` escapes `_run_outbound_delivery`, aborting the whole claimed
    batch; claimed rows are never `record_failure`d, so attempts do not advance.
  - `runtime._pin_bootstrap_peers` (runtime.py:419) catches only `ResolutionError`: with any
    configured `gossip.bootstrap` URL, the `TypeError` escapes `RuntimeCoordinator.start()` and
    the daemon fails to start.
  - CLI offline `resolve`/`pin` (`lattice/cli.py:576` constructs a real `OutboundTransport`)
    likewise crash with `TypeError`.

- Frequency: DEMONSTRATED — every outbound federation request. Operation population and cadence:
  gossip round (`gossip_interval_seconds`), candidate verification (`verify_interval_seconds`),
  outbound message delivery (`delivery_interval_seconds`), plus every daemon start with bootstrap
  configured and every offline `resolve`/`pin` invocation. This is not a rare branch; it is the
  only path through the function.

- Outcome: the entire outbound federation transport is non-functional. Candidates are never
  promoted (they expire after 24 h, topology.py `candidate_expiry_seconds`); gossip never leaves
  the node; outbound messages are reclaimed every 5 min (`claim_pending` lease) and fail again,
  never delivered and never advancing their attempt counter; a daemon with any bootstrap peer
  cannot start. `resolved_ip` is therefore never produced at all in production, and every
  `observed_prefix` remains `NULL` (topology.py:234 never runs).

- Confidence: traced. Proven by running both installed urllib3 2.3.0 and a freshly-installed 2.7.0
  (the lockfile version):
  ```
  TypeError HTTPConnectionPool._make_request() got an unexpected keyword argument 'assert_hostname'
  TypeError HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'
  ```
  and by invoking `OutboundTransport.request` with a stubbed `socket.getaddrinfo` returning an
  allowed public IPv4 (93.184.216.34), which raised the raw `TypeError` before any socket opened.
  No component is suspected.

- Reachability kind: PRODUCTION.

### 2. [M] IPv6 resolved addresses build a malformed target URL, so IPv6-first destinations are unreachable

- Location: `lattice/transport.py:OutboundTransport.request` (URL construction, line 121) and
  `_resolve_and_validate` (lines 70–96)
- Evidence:
  ```python
  port = parsed.port or 443
  target_url = f"https://{ip}:{port}{parsed.request_uri}"
  ```
  `str(ip)` for an `IPv6Address` is unbracketed (e.g. `2606:4700:4700::1111`), so the target becomes
  `https://2606:4700:4700::1111:443/...`. `urllib3` parses this at the top of `urlopen`
  (`urllib3/connectionpool.py:113 parsed_url = parse_url(url)`), before `_make_request`, and raises
  `LocationParseError("Failed to parse: ...")`. `LocationParseError` is an `HTTPError` subclass, so
  it is caught at transport.py:140 and re-raised as `TransportError` — a *clean* failure, not a
  `TypeError`. IPv6 literals require `[ ]` in a URL authority.

- Trigger: `socket.getaddrinfo(hostname, None, AF_UNSPEC, SOCK_STREAM)` returns a global unicast
  IPv6 address as the first policy-allowed result. This happens for IPv6-only domains and for
  dual-stack domains where the AAAA record sorts ahead of the A record (RFC 6724 ordering). Verified
  that `_resolve_and_validate` returns the plain IPv6 text `'2606:4700:4700::1111'` for such an
  input, and that `parse_url("https://2606:4700:4700::1111:443/x")` raises `LocationParseError`.
  Reached via the same paths as Finding 1 (verify_candidate, gossip, delivery, bootstrap, CLI).

- Frequency: DEMONSTRATED by the URL/parse mechanism; population = any well-known or endpoint
  domain whose first allowed resolved address is IPv6. Ungroundable at deployment scale (no live
  DNS population available to this pass) — the *trigger condition* is demonstrated, the deployment
  share of IPv6-first domains is not measured.

- Outcome: resolution of an IPv6-first domain always raises `ResolutionError` ("cannot fetch"),
  even though a valid, policy-allowed IPv6 address was found. Such peers can never be verified,
  gossiped with, or messaged. Independent of Finding 1: the parse failure occurs before the
  `TypeError` branch, so repairing Finding 1 does not repair this, and vice versa.

- Confidence: traced (mechanism and trigger proven in the interpreter; frequency population
  unmeasured). No component suspected.

- Reachability kind: PRODUCTION.

---

## Sub-claims refuted

- "`resolved_ip` is the policy-validated IP the connection was made to." — REFUTED. Under the
  pinned dependency it is never surfaced (Finding 1); for an IPv6 endpoint no connection is made at
  all (Finding 2). The docstring at transport.py:27–30 and 110–112 describes behaviour the code does
  not deliver.
- "The `assert_hostname=` kwarg preserves the original hostname for TLS certificate verification
  while connecting to the validated IP" (class docstring, lines 49–53) — REFUTED as an executable
  claim: the kwarg is invalid for `urlopen` in urllib3 2.x. (I did not attempt to prove what the
  *correct* 2.x equivalent would be; that is a fix-direction question, not a contract question.)
- "`resolve_with_ip` returns `(document, resolved_ip)`, None when the transport does not report
  one." — PARTIALLY REFUTED: it cannot return a document at all today (Finding 1). The `getattr`
  fallback (resolution.py:111) itself is correct.

## Checked and clean

- `TopologyService.prefix_from_ip` consumes every `resolved_ip` value correctly: verified for
  `"93.184.216.34"` → `"93.184.216.0/24"`, `"2606:4700:4700::1111"` → `"2606:4700:4700::/48"`,
  and `"::ffff:93.184.216.34"` → `"93.184.216.0/24"` (IPv4-mapped unwrapped). Invalid text returns
  `None`. The IPv4-mapped unwrap in the transport (`_resolve_and_validate`, lines 80–82) is
  consistent with `prefix_from_ip`; a mapped address is unwrapped once in transport and reaches
  topology already in IPv4 form.
- `None` handling: `verify_candidate` guards with `if resolved_ip else None` (topology.py:234), and
  `_fill_discovery` falls back to `prefix_from_endpoints` for a null prefix (topology.py:444–448).
  `PeerStore.transition` (peers.py:132) and `PeerRepository.transition_peer` (repositories.py:280)
  treat `observed_prefix=None` as "leave unchanged" (COALESCE), so a re-verification that reports
  no IP does not clobber a stored prefix. `upsert_peer` inserts NULL, not a sentinel. This path is
  correct.
- Discovery-slot selection (topology.py `_fill_discovery`): the round-robin over `by_prefix` does
  enforce one-per-prefix per round and bounds the result at `discovery_count`; no off-by-one
  observed. It correctly consumes both the real IP prefix and the hostname fallback in the same
  loop.
- `PeerRepository.claim_pending` lease recovery (5 min) means Finding 1's stranded deliveries are
  reclaimed rather than permanently lost — the queue does progress mechanically, it just never
  delivers.
- Redirect handling is not an SSRF hole on this trace: `HTTPConnectionPool.urlopen` recurses with
  `assert_same_host=True`, so a cross-host `Location` raises `HostChangedError` (an `HTTPError`),
  which the transport converts to `TransportError`; `resolved_ip` cannot silently point at the
  first hop while the final hop is elsewhere.
- `lattice/webhook.py:WebhookDeliveryService.deliver` (line 91) calls `self._pool.urlopen` without
  `fields`/`assert_hostname`, so it does not carry Finding 1. Out of the assigned file set, noted
  for containment only.

## Enumeration

Composed command (class-closing for `resolved_ip` producers/consumers and outbound `urlopen` sites):

```
rg -n "\.urlopen\(|OutboundTransport\(|resolved_ip|prefix_from_ip|prefix_from_endpoints|observed_prefix" \
   lattice --glob '!**/__pycache__/**'
```

Instances and disposition:

| Site | Kind | Disposition |
|---|---|---|
| transport.py:132 `self._pool.urlopen` | outbound request | **Finding 1** (invalid kwargs) |
| webhook.py:91 `self._pool.urlopen` | outbound webhook | examined-clean (no invalid kwargs) |
| runtime.py:209 `OutboundTransport(...)` | construction | feeds Finding 1; production |
| cli.py:576 `OutboundTransport(...)` | construction | feeds Finding 1; production (offline) |
| transport.py:149 `resolved_ip=str(ip)` | producer | **Finding 2** for IPv6 `ip`; correct for IPv4/mapped |
| resolution.py:111 `getattr(response,"resolved_ip",None)` | passthrough | examined-clean |
| topology.py:234 `prefix_from_ip(resolved_ip)` | consumer | examined-clean (Finding 1 prevents it running) |
| topology.py:444 `peer.observed_prefix or prefix_from_endpoints` | consumer | examined-clean |
| peers.py:31/47/89/132 `observed_prefix` | storage | examined-clean (COALESCE semantics intended) |
| repositories.py:280 `observed_prefix` update guard | storage | examined-clean |

## Design risks (max 2)

1. The `assert_hostname`-style SNI/host-verification design (connect to a validated IP while
   verifying the original hostname) has no urllib3-2.x implementation exercised anywhere in the
   tree, so it is unverified that the replacement actually preserves hostname verification. A fix
   must confirm SSL hostname checking against the original name, not merely stop the `TypeError`.
2. `prefix_from_endpoints` returns a *hostname* into the same `observed_prefix` namespace that
   `prefix_from_ip` populates with CIDR strings (topology.py:115–127 vs 141–156). A future consumer
   that assumes `observed_prefix` is always a CIDR would break on the fallback rows. No current
   consumer makes that assumption.

## Bound

- No live DNS population was queried, so Finding 2's deployment frequency (share of IPv6-first
  domains) is unmeasured; the trigger mechanism is proven in-process.
- Repo test-suite execution was not completed in this environment (`rfc8785` absent from the
  interpreter used); findings were established by direct in-process invocation of the real
  transport and HTTP client, and by reading. `uv.lock` pins `urllib3 2.7.0`, which was installed and
  tested directly.
- Upstream `urllib3` behaviour at versions beyond 2.7.0 is unverified; both 2.3.0 and the locked
  2.7.0 reproduce.
