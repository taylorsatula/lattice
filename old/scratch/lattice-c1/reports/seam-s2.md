# seam-s2 — transport ↔ topology contract (resolved_ip / prefix grouping)

Pass type: blind hunter. Files read end to end: `lattice/transport.py`,
`lattice/resolution.py`, `lattice/topology.py`, `lattice/peers.py`; traced into
`lattice/gossip.py`, `lattice/api.py` (gossip route), `lattice/runtime.py`
(outbound senders), `lattice/network_policy.py`, `lattice/storage/repositories.py`
(peer/candidate persistence). Environment urllib3 pinned at 2.3.0; its redirect
and URL-parsing behavior was verified from installed source plus local
no-network parsing probes.

## Findings

1. [H] — Redirect following in OutboundTransport bypasses NetworkPolicy and misreports `resolved_ip`
- Location: lattice/transport.py:OutboundTransport.request (the `self._pool.urlopen(...)` call)
- Evidence: `response = self._pool.urlopen(method, target_url, body=body, headers=request_headers, fields=fields, assert_hostname=hostname, preload_content=True)` — no `redirect=False` and no `retries` override. urllib3 2.3.0 `PoolManager.urlopen` has `redirect: bool = True` and, on any 301/302/303/307/308 with a Location header, recurses: `redirect_location = urljoin(url, redirect_location); ... return self.urlopen(method, redirect_location, **kw)`. The redirect target's DNS resolution and connection happen entirely inside urllib3 — `_resolve_and_validate` / `NetworkPolicy.validate_ip` are never consulted for it. Verified locally: `urljoin("https://198.51.100.7:443/.well-known/lattice", "http://169.254.169.254/latest/meta-data/")` → `http://169.254.169.254/latest/meta-data/` (scheme downgrade allowed; plain-HTTP pool, so `assert_hostname` is never applied either).
- Trigger: PRODUCTION. Any peer domain the daemon contacts whose endpoint answers 3xx with a Location header. Reachable today on all three outbound paths: candidate verification (`runtime._run_verify_candidates` → `TopologyService.verify_candidate` → `WellKnownResolver.resolve_with_ip` → transport GET), message custody (`runtime._send_outbound_message` → transport POST at runtime.py:964), gossip send (`runtime._send_gossip_batch` → transport POST at runtime.py:1113). A peer domain owner (anyone who can register a domain and publish a signed well-known doc — the exact population NetworkPolicy exists to constrain) or a compromised reverse proxy in front of a peer controls these responses.
- Frequency: requires a hostile or compromised peer domain (or a misconfigured redirect); no honest peer triggers it. This is an enforcement-gap finding, not a normal-operation failure — the "SSRF-safe synchronous HTTPS transport" docstring and `NetworkPolicy` exist precisely for this population. Demonstrated population: every well-known fetch and every outbound POST in the daemon.
- Outcome: (a) The daemon issues requests to policy-forbidden addresses — loopback, link-local (e.g. cloud metadata), private CIDRs — with attacker-chosen scheme, path, and query, over plain HTTP with no TLS and no hostname assertion; (b) on 307/308 the POST method and body are preserved, so gossip batch payloads and outbound message bodies (user message content) are delivered to an attacker-chosen URL; the manually set `Host: <original-domain>` header is also forwarded (not in urllib3's default `remove_headers_on_redirect` set); (c) seam contract broken: `FederationResponse.resolved_ip` still reports the originally policy-validated IP while the actual connection went to the redirect target, so `topology.prefix_from_ip` records a false prefix for the real destination.
- Confidence: traced — mechanism proven from urllib3 2.3.0 installed source (default `redirect=True`, recursion with no policy hook, default `Retry(3)` allows 3 hops); trigger production; frequency requires a hostile peer (ungroundable beyond the hostile-peer population, which is the threat model the code itself declares).

2. [M] — Unbracketed IPv6 target URL fails to parse: IPv6-resolved peers can never be fetched
- Location: lattice/transport.py:OutboundTransport.request — `target_url = f"https://{ip}:{port}{parsed.request_uri}"`
- Evidence: `_resolve_and_validate` returns an `ipaddress.IPv6Address` when the first policy-allowed `getaddrinfo` result is IPv6 (public-mode policy permits public IPv6), and `f"https://{ip}:{port}"` emits an unbracketed literal. Verified locally against the installed urllib3 2.3.0: `parse_url("https://2001:db8::1:443/.well-known/lattice")` raises `LocationParseError: Failed to parse: https://2001:db8::1:443/.well-known/lattice`. `PoolManager.urlopen` calls `parse_url(url)` first, so every such request raises; `LocationParseError` is a subclass of `urllib3.exceptions.HTTPError`, so transport.request wraps it as `TransportError("HTTP request failed: Failed to parse: ...")`.
- Trigger: PRODUCTION. Candidate verification (`_run_verify_candidates` → `verify_candidate` → `resolve_with_ip` → request) or pinning (`resolve_address` → `resolver.pin`) for any domain whose first policy-allowed DNS answer is an AAAA record. On dual-stack hosts `getaddrinfo(AF_UNSPEC)` returns IPv6 first per RFC 6724 destination selection, so dual-stack peer domains hit this, not just IPv6-only ones.
- Frequency: any peer domain resolving to IPv6-first, on any daemon host with IPv6 enabled (most modern servers). Exact cadence depends on deployment IPv6 enablement — mechanism and trigger proven, frequency grounded as "every verification attempt for such a domain" (it never succeeds).
- Outcome: an IPv6-reachable peer can never be verified or pinned; every attempt fails with a misreported cause (an HTTP-request failure message for what is a URL-construction bug). Consequence for the seam: `resolved_ip` is never an IPv6 string in production, so `prefix_from_ip`'s IPv6 /48 branch and the IPv6 half of the diversity contract are dead code reachable only through test fakes.
- Confidence: traced — mechanism proven (parse probe against installed urllib3), trigger production, frequency depends on IPv6 prevalence in the peer population (cannot ground a number; not latent, the code path is the only one).

## Checked and clean

- IPv4-mapped normalization seam: `_resolve_and_validate` maps `::ffff:a.b.c.d` → IPv4 before validation and before `str(ip)`, so `resolved_ip` never carries a mapped form; `prefix_from_ip` re-normalizes defensively. The two sides agree.
- None handling end to end: `resolve_with_ip` uses `getattr(response, "resolved_ip", None)` (safe for transports lacking the field); `verify_candidate` maps falsy `resolved_ip` to `observed_prefix=None`; `PeerRepository.upsert_peer` uses `observed_prefix = COALESCE(?, observed_prefix)` and `transition_peer` updates the column only when not None — so re-verification with no reported IP never erases a previously recorded prefix. `create_peer` passes it through directly on first insert. Correct.
- `_fill_discovery` prefix consumption: fallback chain `peer.observed_prefix → prefix_from_endpoints(hostname) → "_unknown"` round-robins across buckets, matching the documented intent for peers verified before prefixes were recorded.
- Candidate-intake grouping by hostname (gossip.py:116, `prefix_from_endpoints` at topology.py) is documented intent ("no network traffic before cap enforcement"); `api.py:267` calls `receive_batch` without `observed_prefix`, so the hostname fallback is the production path. `count_candidates_by_prefix` operates on the same hostname keyspace the intake writes. Consistent.
- `prefix_from_ip` itself: `ValueError → None`, `/24` for IPv4, `/48` for IPv6, `strict=False` — correct; its IPv6 branch is unreachable in production only because of Finding 2.
- Consumers of `FederationResponse` in `runtime.py` (`_send_outbound_message`, `_send_gossip_batch`) ignore `resolved_ip` — nothing else misattributes it.
- `FederationResponse.resolved_ip` for the normal (non-redirect, IPv4) path is genuinely the validated, actually-connected IP: the pool is keyed by the literal IP host in the rewritten URL, so a reused connection is to the same IP that was validated and reported.

## Enumeration

Producer → consumer disposition for `resolved_ip` (the assignment's table):

| producer path | sets resolved_ip? | consumer path | None / edge handling | disposition |
|---|---|---|---|---|
| `OutboundTransport.request` (transport.py:149) — IPv4, no redirect | yes — `str(ip)`, the validated IP | `WellKnownResolver.resolve_with_ip` → `TopologyService.verify_candidate` → `prefix_from_ip` → `peers.create_peer/transition` → `_fill_discovery` | None never occurs on this path; IPv4-mapped pre-normalized | examined-clean |
| `OutboundTransport.request` — IPv6 target | never returns (LocationParseError → TransportError) | — | — | Finding 2 |
| `OutboundTransport.request` — 3xx response | returns the originally validated IP; connection actually went to redirect target | same as above; `prefix_from_ip` validates a false prefix | None not involved | Finding 1 |
| `tests/conftest.py` FakeTransport (line 49-54) | optional, default None | `resolve_with_ip` getattr fallback; test_cli passes `resolved_ip=None` | None → `observed_prefix=None` → COALESCE preserves old value | out-of-scope (test-only), verified consistent with production None handling |
| `runtime.py:964` / `runtime.py:1113` POST senders | consume the response, ignore `resolved_ip` | — | — | examined-clean (no misattribution beyond Finding 1) |

## Design risks

Candidate-intake caps group by hostname while verified-peer diversity groups by IP prefix; a Sybil operator with many distinct hostnames on one /24 can occupy all 256 candidate slots before any verification runs (the 4-per-prefix cap never applies, since hostname keys differ). Bounded by `max_candidates` and superseded at verification — noting as design risk, not a finding. Also, `_fill_discovery`'s "_unknown" bucket merges all peers lacking both prefix and endpoints, weakening diversity for legacy rows; bounded, one-pass observation.

## Side discoveries

None beyond the above. `GossipService.receive_batch`'s `observed_prefix` parameter has no production caller (api.py:267 omits it) — dead-in-production parameter, not a defect.

## Bound

- No live network was available: connection-level behavior (redirect hops, TLS on redirect targets, getaddrinfo ordering) was verified from installed urllib3 2.3.0 source and pure local parse probes, not against a real peer. AAAA-first ordering is asserted from RFC 6724 and is platform-dependent; on IPv4-only daemon hosts getaddrinfo typically deprioritizes unreachable IPv6, narrowing Finding 2's trigger to IPv6-capable hosts.
- urllib3 version drift could change redirect defaults; pinned to the version installed in this environment (2.3.0).
