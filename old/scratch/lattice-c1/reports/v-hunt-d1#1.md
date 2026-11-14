# v-hunt-d1#1 — PRIMED VERIFIER report

Claim under test: **hunt-d1.md finding 1** — "3xx redirects bypass network policy entirely:
unvalidated second connection to any address" (reported tier **H**, GATED behind hunt-b1b finding 1).

Files read end to end for this verification: `lattice/transport.py`, `lattice/network_policy.py`.
Supporting reads: `lattice/resolution.py`, `lattice/runtime.py` (verify_inbound_message,
queue_domain_resolution, _resolve_pending_senders, _send_outbound_message, gossip send),
`lattice/api.py` (messages route + cold-sender branch), `lattice/protocol/models.py` (endpoint
validators), `scratch/lattice-c1/reports/hunt-b1b.md`. Empirical work run against the repo venv
(`.venv`, urllib3 2.7.0, Python 3.11.13) with the **unmodified** repo `NetworkPolicy` class;
all scaffolding in `/tmp/vt`; no repo file was touched. `transport.py` is untracked in the tree
(no concurrent writer); `git status` shows it unmodified.

## Verdict

**CONFIRMED.** Mechanism traced and reproduced; trigger, gate, and severity substantiated.
Tier **H** (unchanged). Reachability kind: **GATED behind hunt-b1b finding 1** (the
`fields`/`assert_hostname` per-request `urlopen` kwargs fault, still present at
`transport.py:132-140`).

## Re-derived frame (from source, not the claim)

- `OutboundTransport.request` (`transport.py:98`) parses the input URL, enforces `scheme ==
  "https"`, resolves + policy-validates the **original** hostname (`_resolve_and_validate:73`),
  rewrites the URL to `https://{validated_ip}:{port}{request_uri}` (`:125`), then calls
  `self._pool.urlopen(method, target_url, body=..., headers=..., fields=..., assert_hostname=...,
  preload_content=True)` (`:132-140`). No `redirect=` / `retries=` argument is supplied.
- urllib3 2.7.0 `PoolManager.urlopen` signature is `(self, method, url, redirect: bool = True,
  **kw)`. Verified at
  `.venv/lib/python3.11/site-packages/urllib3/poolmanager.py:418`: on a redirect it executes
  `return self.urlopen(method, redirect_location, **kw)` (line 486), where `kw` retains the
  original `body`, `headers`, `fields`, `assert_hostname`, `preload_content`. The recursive call
  re-runs `connection_from_host(u.host, port, scheme)` for the **Location** target. The
  connection pool chooses and connects to the redirect host with no call into
  `OutboundTransport` / `NetworkPolicy`.
- `NetworkPolicy.validate_ip` (`network_policy.py:63`) is the SSRF guard; it is only invoked from
  `transport.py:91` (inside `_resolve_and_validate`), i.e. only for the first hop.
- The `fields`/`assert_hostname` kwargs are rejected by `HTTPConnectionPool._make_request`
  (fixed signature, no `**response_kw`): verified live — `TypeError: HTTPConnectionPool._make_request()
  got an unexpected keyword argument 'fields'` against a local server. This is the gate.

## Empirical reproduction

Harness in `/tmp/vt` with the repo venv:
- `NetworkPolicy.public().validate_ip(127.0.0.1, "127.0.0.1")` → `NetworkPolicyError: public mode
  rejects internal address 127.0.0.1`.
- A first-hop TLS server returning `302 Location: http://127.0.0.1:<iport>/internal` was followed
  by `PoolManager.urlopen(..., redirect=True)` (the transport's call shape minus the broken
  kwargs): final status 200, body `b'INTERNAL-SECRET-DATA'` — a policy-rejected loopback address
  was connected to and its body returned. The `http://` scheme downgrade is accepted; TLS is
  bypassed for the second hop.
- Control: the same call with the kwargs present raises the `TypeError` before any request is sent,
  so the pathway is dead in the tree today.

## Sub-claim dispositions

1. "No `redirect=False`/`retries=Retry(redirect=False)`; PoolManager follows 3xx by default" —
   **CONFIRMED** (source + signature).
2. "Redirect re-enters urlopen and connects to the Location target with zero interaction with
   NetworkPolicy" — **CONFIRMED** (empirical).
3. "`http://` scheme downgrade accepted" — **CONFIRMED** (empirical).
4. Fetch population is outsider-controlled: cold-sender `POST /lattice/v1/messages` with
   `from_address user@<attacker-domain>` → `verify_inbound_message` returns `(domain, True)`
   without signature verification → `queue_domain_resolution(domain)` (`api.py:305`) →
   `_resolve_pending_senders` → `resolver.pin(domain)` → `transport.request("GET",
   "https://<domain>/.well-known/lattice")` (`resolution.py:48`) — **CONFIRMED**. The route has no
   auth dependency (`api.py:280-284`: only `require_content_length`, `require_ready`). Gossip and
   outbound POST paths (`runtime.py:964`, `runtime.py:1113`) confirmed present and POST-bodied.
5. "any private/loopback address" via redirect — **PARTIALLY REFUTED (narrowed)**. An
   `https://` redirect to a *different* host is blocked by the `assert_hostname` hostname check
   (the original hostname is retained in `kw` and reaches the second connection's TLS
   verification); empirically `MaxRetryError ... CertificateError: hostname 'first.example.com'
   does not match '127.0.0.1'` when assert_hostname is applied. The working vector is the
   **`http://` downgrade** (assert_hostname does not apply to HTTP pools) and any target reached
   without TLS. The claim does name `http://` explicitly in its own evidence, so its central
   example stands; only the general "any address" phrasing is too broad.
6. "processes the internal service's response as the federation response" — **OVERSCOPED for the
   discovery path**. On the well-known GET path the fetched body is validated (`status == 200`,
   Content-Type must contain `application/vnd.lattice+json`, JSON/schema/signature checks,
   `resolution.py:50-92`) and a metadata/plain-text body is therefore discarded — that vector is
   blind SSRF (request emitted, body not surfaced). The body *is* consumed as the final
   `FederationResponse` on the POST paths (`_send_outbound_message`, gossip), whose status drives
   `record_success`/`record_failure`. The claim is accurate for those paths, overstated for the
   well-known GET path.
7. Frequency "zero today; attacker-controlled once any transport call succeeds" — **CONFIRMED**
   as currently gated; frequency is not independently groundable as a live production cadence
   while the gate stands.

## Severity correction

**H — unchanged.** The network policy is the sole SSRF guard on outbound fetch; a redirect bypass
lets an outsider steer the daemon to loopback/link-local/RFC1918 (e.g. `http://169.254.169.254/`)
with the daemon's method, headers, and body. That is an authorization-boundary bypass meeting the
pinned H definition. Per the calibration rule a gated finding keeps its real severity and is
marked GATED (it is). Note within H: the discovery-path response is not exfiltrated (blind SSRF,
sub-claim 6); impact on that path is internal-endpoint triggering (GET-only) rather than direct
secret read-back. The POST paths can drive attacker-shaped JSON into an internal endpoint.

## Frequency correction

The claim's frequency is **conditional**, not demonstrated as a live cadence. It is sound as a
population statement (any host the daemon fetches, attacker-controlled, zero marginal cost once
live) but currently produces **zero** occurrences because every transport call dies at
`transport.py:132`. Classified **GATED (hunt-b1b finding 1)**; frequency once repaired would be
"every fetched host an attacker controls." No correction to the number claimed; correction to the
label (latent/gated, not observed).

## Additional mechanisms / earlier failure sites / new reachability (same trace)

- **Duplicate of hunt-b1b finding 4** — same mechanism, same gate, independently reproduced here.
  Dedupe should merge; do not count as two findings.
- **`Host` header is forwarded to the redirect target.** `request_headers` sets
  `Host: <original hostname>` and is retained across the redirect; an internal target using
  Host-based virtual routing receives the attacker's domain as `Host`.
- **Relative redirects resolve against the rewritten IP URL** (`urljoin` against
  `https://{ip}:{port}/...`), so a relative `Location` stays on the same validated IP — benign.
- **No redirect count is configured**; `Retry.DEFAULT` governs the redirect budget, so the
  bypass is bounded to the default number of hops but is not otherwise constrained.
- **Earlier failure site**: `transport.py:132` (kwargs) — nothing on this trace reaches the
  redirect today.
- **Repair hazard (new reachability after a naive fix)**: the arm that disables TLS verification
  for the second hop is the `http://` downgrade, which urllib3 performs with no scheme check
  against the policy; the transport's own `scheme == "https"` check applies only to the input URL,
  never to a `Location`.

## Fix-direction constraints

1. Repairing hunt-b1b finding 1 (kwargs) **must not ship the SSRF**. Set `redirect=False` /
   `Retry(redirect=False)` on the pool or per request, or intercept `Location` and re-run
   `_resolve_and_validate` on the redirect target.
2. Disabling redirects is required regardless of how `assert_hostname` is repaired: it does not
   apply to HTTP pools, so the `http://` downgrade is unaffected by hostname assertion.
3. Re-validating a redirect target is not sufficient alone: the scheme must be re-checked against
   the `https`-only invariant (`Location: http://…` must be rejected, not merely re-IP-checked).
4. If redirects are kept, the re-validation must use the same single-resolution /
   connect-to-validated-IP discipline as the first hop (otherwise the TOCTOU property that
   `_resolve_and_validate` was written to preserve is reintroduced).
5. The redirect response's `Host`/body forwarding to a different-origin host is a second leak of
   the original request (headers, POST body) and should be considered in the fix.

## Checked and clean

- Redirect default and recursive re-entry in the repo's pinned urllib3 (2.7.0). Verified.
- `NetworkPolicy.validate_ip` is invoked only from `transport.py:91`; no second validation site
  exists on the redirect path. Verified by `rg` (below).
- Transport enforces `https` on the input URL and rejects non-https — but not on redirect targets.
- Both POST call sites (`runtime.py:964`, `:1113`) pass body + headers through `transport.request`
  and consume `response.status`; confirmed.
- Cold-sender branch queues the parsed domain before rate limiting and without signature
  verification; confirmed (`api.py:303-318`).
- `resolve_with_ip` validates status, content type, JSON, domain, node ID, root signature, and
  operational cert on the fetched body — this is why the discovery-path response is not surfaced.

## Enumeration

```
rg -n 'redirect|Retry|urlopen|PoolManager' lattice/transport.py lattice/webhook.py
rg -n 'validate_ip|hostname_allowed|_is_internal' lattice/ --type py
rg -n 'transport\.request\(' lattice/ --type py
```

| Instance | Disposition |
|---|---|
| `transport.py:132-140 self._pool.urlopen(...)` | redirect default → finding 1 (CONFIRMED, gated) |
| `transport.py:125 target_url = f"https://{ip}:{port}..."` | rewritten-URL base for relative redirects — clean |
| `network_policy.py:63 validate_ip` (only caller `transport.py:91`) | class closed: no redirect-path caller — clean |
| `webhook.py` own `PoolManager`/`urlopen` | operator-configured URL, correct call shape — out of scope (inherits default redirect, noted for the record) |
| `runtime.py:964`, `runtime.py:1113 transport.request(...)` | POST body forwarded on redirect — confirmed blast radius |
| `resolution.py:48 f"https://{domain}/..."` | attacker-fed fetch population — confirmed |

## Bound

- Could not observe the bypass through a real daemon run: hunt-b1b finding 1 blocks every
  transport call today; all live evidence used the transport's exact pool construction with only
  that kwargs fault neutralized at the urllib3 boundary, and the `/tmp` harness substituted
  loopback for `169.254.169.254`/RFC1918.
- The exact behaviour of the HTTPS-redirect arm depends on how a future repair applies
  `assert_hostname` (per-pool vs per-request). Verified at the urllib3 layer that the original
  hostname is retained in `kw` and reaches the second connection's TLS check, blocking a
  different-host HTTPS redirect; unverified against a hypothetical repair that drops it.
- Provider/upstream behaviour (cloud metadata service responses, real dual-stack resolver
  ordering) not reachable here.
- Enumeration is identifier/literal-based `rg`; a redirect control introduced dynamically outside
  the named symbols would not match (none exists in-tree).
