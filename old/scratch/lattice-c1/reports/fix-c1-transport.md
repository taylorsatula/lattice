# Fix report — C1 rows DEAD, SSRF, IPV6, POIS-root (transport.py)

Executor: swarm-executor (lattice/transport.py only). Status: EXECUTED.

## Files / functions changed

- `lattice/transport.py` — the only file written. Net +25/-7 across two named functions plus one
  dead import removed by the same change (`from typing import Any` was used only by the removed
  `fields` parameter; no other references).
  - `OutboundTransport.request`:
    - DEAD: dropped the `fields` parameter and the `fields=`/`assert_hostname=` per-request
      `urlopen` kwargs (urllib3 2.7.0 forwards unknown kwargs to `_make_request` → `TypeError`,
      which is not an `HTTPError`, so it escaped every caller). Verified no caller in the repo
      passes `fields=` (grep across tree: only the removed line in transport.py).
    - DEAD/TLS binding: hostname trust moved to pool construction —
      `self._pool.connection_from_url(target_url, pool_kwargs={"server_hostname": hostname})`,
      then `pool.urlopen(...)`. Under `check_hostname=True` (our ssl context) urllib3 binds the
      certificate and SNI via `server_hostname`, which is set when the pool/connection is
      constructed, not per request. Deliberate choice flagged for the orchestrator: HOW offered
      "assert_hostname/server_hostname at PoolManager construction time", but (1) a single
      `PoolManager(..., server_hostname=...)` binds one hostname for the entire multi-host
      transport, so the binding must be per-pool via `connection_from_url(pool_kwargs=...)`
      (urllib3's documented mechanism; `connection_pool_kw` is merged underneath, so timeout and
      ssl_context are preserved — read from installed urllib3 2.7.0 `_merge_pool_kwargs`), and
      (2) `assert_hostname` was NOT set: a truthy `assert_hostname` forces
      `context.check_hostname = False` on the *shared* ssl context (connection.py:943-951) and
      downgrades verification to urllib3's manual `_match_hostname`; HOW's own parenthetical
      ("urllib3 consults assert_hostname only when check_hostname is False") points at
      `server_hostname` as the binding under `check_hostname=True`. Probe N proves the binding.
    - DEAD (correctness found while executing): the pool must receive the origin-form request
      target, not the absolute URL — `pool.urlopen(method, parsed.request_uri, ...)`. With the
      absolute URL the request line is absolute-form (probe server observed
      `self.path == "https://[::1]:18443/v6"`), which origin servers reject. Mirrors
      `PoolManager.urlopen` (poolmanager.py:467: `conn.urlopen(method, u.request_uri, **kw)`).
    - SSRF: `redirect=False` — a 3xx is returned to the caller, never followed; the POST body,
      `Host` header, and connection never reach the `Location` target, and `resolved_ip` is the
      IP actually connected to (the validated IP, since no redirect occurs).
    - IPV6: authority is bracketed for IPv6 only —
      `authority = f"[{ip}]" if ip.version == 6 else str(ip)`; `parse_url` on the constructed
      URL now succeeds (unbracketed `LocationParseError` reproduced pre-fix).
    - POIS-root: `parse_url(url)` wrapped in
      `except urllib3.exceptions.HTTPError as exc: raise TransportError(f"invalid URL: {url}")`
      — `LocationParseError` is an `HTTPError` subclass in urllib3 2.7.0 but was raised outside
      the try block, so it escaped `request()` entirely (verified pre-fix: raised for
      `"https://[::1"`; urllib3 2.7 tolerates spaces in hosts, so the unterminated-IPv6-literal
      class is the one that trips it).
  - `OutboundTransport._resolve_and_validate`:
    - IPV6: strips brackets from a bracketed IPv6-literal hostname before
      `getaddrinfo` (parse_url keeps `host == "[2001:db8::1]"`; `getaddrinfo("[::1]")` →
      `gaierror`, reproduced). Bracket stripping happens before `hostname_allowed`/`validate_ip`
      so private-mode suffix/CIDR checks see the bare address.
    - Address-family fallback decision (named in the HOW): left delegated to
      `getaddrinfo(AF_UNSPEC)` — results arrive in the platform's RFC 6724 reachability order
      and the first policy-allowed address of either family wins. IPv6-only peers are reached
      (only AAAA records → only IPv6 results); dual-stack peers use the OS preference. No code
      change; documented in the docstring.

No same-hazard sibling branches found beyond the enumerated set. Exemplar mirrored: this file is
the transport exemplar; the `except urllib3.exceptions.HTTPError as exc: raise TransportError(...)`
idiom (pre-existing at the urlopen call) is the pattern the new parse_url handler reuses.

## Verification — EXECUTED

Repo venv `.venv/bin/python` (urllib3 2.7.0), real sockets and real TLS, no mocks, no test files.
Certs generated with openssl in `/tmp/lattice-c1-probe` (removed after; no repo residue, no
orphan processes — `lsof`/`ps` clean, single self-terminating probe process). Every probe bounded
by `timeout` (30–90s). Full probe: `/tmp/lattice-c1-probe/probe.py` (deleted after the run).

Live servers: `http.server.ThreadingHTTPServer` subclass (AF_INET6) on `[::1]:18443` and
`[::1]:18444`, wrapped with `ssl.SSLContext(PROTOCOL_TLS_SERVER)`; 18443's cert has SAN
`IP:::1` signed by the probe CA (loaded via `NetworkPolicy.private(cidrs=("::1/128",),
ca_path=...)`), 18444's cert is signed by the same CA but names `evil.example` only.

- **(a) DEAD — live public HTTPS host** (`NetworkPolicy.public()`):
  `request("GET", "https://example.com/")` →
  `status=200 resolved_ip=2606:4700:10::6814:179a bytes=713` — no `TypeError`; connection made
  to the validated IP over IPv6 with TLS verified against `example.com`. (First run returned
  403 from the CDN until the probe added a `User-Agent`; transport path itself was alive.)
- **(b) IPV6 — bracketed IPv6-literal destination**: `request("GET", "https://[::1]:18443/v6")`
  → `status=200 data=b"v6ok" resolved_ip=::1` over real TLS (cert SAN IP:::1 verified via
  server_hostname under check_hostname=True). Unbracketed form pre-fix:
  `parse_url("https://::1:1843/")` → `LocationParseError`; bracketed hostname pre-fix:
  `getaddrinfo("[::1]")` → `gaierror` — both reproduced before the fix.
- **SSRF redirect control**: `request("POST", "https://[::1]:18443/redir", body=b"secret=1")`
  where the server answers `301 Location: https://127.0.0.1:9/ssrf-target` →
  `status=301 hits={'/v6': 1, '/redir': 1} resolved_ip=::1` — the Location target (loopback,
  outside the private CIDR) was never contacted; server hit-count confirms exactly one request.
- **TLS trust binding (negative control)**: request to `[::1]:18444` whose cert is chained to
  the *trusted* CA but names `evil.example` →
  `TransportError: HTTP request failed: HTTPSConnectionPool(host='::1', port=18444): Max
  retries exceeded with ...` — verification fails loudly; nothing was silently disabled.
- **(c) POIS-root**: `request("GET", "https://[::1")` and `"https://[2001:db8::1"` →
  `TransportError: invalid URL: https://[::1` — previously these escaped `request()` as
  `LocationParseError`.
- Regression: `timeout 120 .venv/bin/python -m pytest tests/test_transport.py` → **3 passed**
  (existing suite, not authored by me). `ruff check lattice/transport.py` (repo-configured
  checker) → all checks passed. `py_compile` clean.

## Owed / out of boundary

- `hostname_allowed` is called for its side effects only (its boolean result is discarded in
  `_resolve_and_validate`) — pre-existing in a function I was not assigned... it is inside a
  named function, but it is not part of any assigned defect, so I left it. Flagging for the
  orchestrator.
- The `fields` parameter was removed from `request`'s public signature (HOW: "drop the dead
  fields kwarg"); no in-repo caller used it. If an external caller passed it, it now fails
  loudly at call time instead of crashing the pool.
