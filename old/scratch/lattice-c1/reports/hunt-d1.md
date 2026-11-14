# hunt-d1 — network policy & SSRF boundary

Pass type: blind hunter. Files read end to end: `lattice/network_policy.py` (94 lines),
`lattice/transport.py` (153 lines). Supporting reads for trigger tracing: `lattice/resolution.py`,
`lattice/runtime.py` (policy construction, delivery/gossip/resolution paths, `verify_inbound_message`),
`lattice/config.py` (NetworkConfig), `lattice/addressing.py`, `lattice/api.py` (cold-sender path),
`lattice/cli.py:560-590`, `lattice/webhook.py` (disposition only), `lattice/protocol/models.py`
(endpoint scheme validators). Empirical work run against the repo venv (urllib3 2.7.0, Python
3.11.13) with the UNMODIFIED repo classes imported from the tree; all scaffolding (TLS certs,
HTTP servers, monkeypatches) lived in /tmp; no repo file was touched.

KNOWN (assignment): the transport call-shape defect — `OutboundTransport.request` passes `fields`/
`assert_hostname` as per-request `urlopen` kwargs, which urllib3 2.x rejects, so **no transport
call currently completes** (hunt-b1b finding 1). Every finding below that needs a live request is
marked GATED behind it; none re-reports that mechanism.

## Findings

1. [H] — 3xx redirects bypass network policy entirely: unvalidated second connection to any address (GATED behind known call-shape defect)
- Location: `lattice/transport.py:OutboundTransport.request` (the `self._pool.urlopen(...)` call); policy bypass mechanism in urllib3 `PoolManager.urlopen` (`redirect: bool = True` default, verified in the venv source)
- Evidence: `response = self._pool.urlopen(method, target_url, body=body, headers=request_headers, fields=fields, assert_hostname=hostname, preload_content=True)` — no `redirect=False`/`retries=Retry(redirect=False)`. `PoolManager.urlopen`'s default cross-host redirect logic re-enters `self.urlopen(method, redirect_location, **kw)`, resolving and connecting to the `Location` target with zero interaction with `NetworkPolicy`.
- Empirical: with the unmodified repo `OutboundTransport` + `NetworkPolicy.private(cidrs=[], suffixes=["localhost"], ca_path=<tmp CA>)` (the known kwargs fault neutralized only at the urllib3 boundary), a first hop at `https://localhost:<portA>/.well-known/lattice` responding `302 Location: http://127.0.0.1:<portB>/internal-target` was followed; the daemon connected to `http://127.0.0.1:<portB>/internal-target` and returned its 200 body as the `FederationResponse` — while `policy.validate_ip(127.0.0.1, ...)` for the same address raises `NetworkPolicyError` ("not in configured CIDRs or suffixes"). The `http://` scheme downgrade is also accepted.
- Trigger (GATED behind the known call-shape defect — becomes live the moment that fault is repaired without also disabling redirects): any HTTPS host the daemon fetches returns a 3xx. The fetch population is outsider-controlled today: (a) `POST /lattice/v1/messages` (public route, no auth, pre-rate-limit cold-sender branch at `api.py:303-315`) with `from_address` `user@<attacker-domain>` queues `WellKnownResolver.pin(attacker-domain)` → `GET https://attacker-domain/.well-known/lattice` (`resolution.py:48`); (b) gossip peer-card endpoints and pinned well-known endpoints (`runtime.py:964`, `runtime.py:1113`). Attacker returns `302 → http://169.254.169.254/...` or any private/loopback address; the daemon connects, forwards the request (POST bodies included — message JSON, gossip batches), and processes the internal service's response as the federation response.
- Frequency: attacker-controlled at zero cost per fetched host once any transport call succeeds; the cold-sender feed is unauthenticated and unrate-limited (b1b finding 3). Today: zero occurrences — every request dies at the known kwargs fault first. This exact mechanism was also filed by hunt-b1b as its finding 4 (latent, same gate); independently reproduced here — dedupe should merge.
- Outcome: full SSRF bypass of the public/private network policy — reach into link-local metadata services, loopback admin endpoints, RFC1918 space — with the daemon's POST body forwarded and the internal response surfaced into federation processing.
- Confidence: traced — mechanism empirically demonstrated on the repo venv with unmodified repo classes; trigger and frequency explicitly gated behind the known defect (nothing in tree completes a request today). Gate: hunt-b1b finding 1.

2. [M] — `private_suffixes` match is unanchored `endswith` (and the classmethod strips the operator's dot), so an attacker-registered lookalike domain passes private-mode policy
- Location: `lattice/network_policy.py:NetworkPolicy.validate_ip` / `NetworkPolicy.hostname_allowed` (`in_suffix = any(hostname_lower.endswith(s) for s in self.private_suffixes)`); normalization at `NetworkPolicy.private` (`s.lower().strip(".")`)
- Evidence: `in_suffix = any(hostname_lower.endswith(s) for s in self.private_suffixes)` with suffixes produced by `tuple(s.lower().strip(".") for s in suffixes)` — `strip(".")` deletes the leading dot an operator would use to anchor the boundary, and nothing else enforces one.
- Empirical (venv, trivial): `private_suffixes=["company.com"]` → `"notcompany.com".endswith("company.com")` is True; `"evilcorp.example".endswith("corp.example")` is True; only `"x.corp.example.evil.net"` is False. Any registrable sibling domain sharing the tail passes.
- Trigger: a deployment configured `[network] mode = "private"` with `private_suffixes = ["company.com"]` (config schema `config.py:115`, validated and constructed at `runtime.py:203-208` — a supported, first-class configuration). Then any remote peer presenting `from_address` `user@notcompany.com` (cold-sender path, unauthenticated) or a gossip card whose well-known/pin domain is a lookalike: `validate_ip` accepts the attacker's public IP purely on the suffix tail match. If `private_ca_path` is unset (allowed by config), the default public CA store is in use, so the attacker's ordinary publicly-trusted cert for `notcompany.com` completes TLS.
- Frequency: operator-configuration-dependent — LATENT by the frequency rule: no default deployment uses private mode (`config.py` example ships `mode = "public"`); once configured, fires on the first contact with any attacker-registered lookalike (one domain registration + one message POST). Mechanism and trigger are proven; only the deployed population is unproven.
- Outcome: the private-mode network restriction — the entire point of the mode — is bypassed; the daemon resolves, pins, and exchanges federation traffic with a fully attacker-controlled outside host that merely shares the suffix tail.
- Confidence: traced — mechanism demonstrated (both the endswith behavior and the `strip(".")` normalization, from the repo venv); trigger concrete; frequency ungrounded in-tree (latent), stated as such.

3. [M] — IPv6 destinations produce an unparseable unbracketed URL: all transport calls to dual-stack or IPv6 peers fail
- Location: `lattice/transport.py:OutboundTransport.request` — `target_url = f"https://{ip}:{port}{parsed.request_uri}"`
- Evidence: `target_url = f"https://{ip}:{port}{parsed.request_uri}"` — an `IPv6Address` formats without brackets. Empirical (venv): `f"https://{ip}:443/path"` → `https://2620:0:1234::1:443/path` → `parse_url` raises `LocationParseError` ("Failed to parse"). `LocationParseError` IS an `HTTPError` subclass (MRO verified), so it surfaces as `TransportError("HTTP request failed: ...")` → callers treat it as a retryable failure.
- Live confirmation: the first run of my redirect test (unmodified transport, hostname `localhost` on macOS) failed exactly here — `getaddrinfo("localhost", AF_UNSPEC)` returned `::1` first, `_resolve_and_validate` accepted it (loopback allowed by the private-mode suffix), and the request died with `TransportError: HTTP request failed: Failed to parse: https://::1:55600/.well-known/lattice`.
- Trigger: any destination whose `getaddrinfo` yields an allowed IPv6 result first — a federated peer domain with AAAA records (macOS and RFC 6724 Linux resolvers commonly order IPv6 first when routable), or an IPv6 literal host. Reachable in PRODUCTION for every such peer; NOT gated by the known kwargs fault (it fires before the kwargs reach `_make_request`, and — decisively — repairing the kwargs fault alone does not restore it).
- Frequency: plausible in normal operation — every transport call to a dual-stack peer domain; outbound messages to such peers then churn claim → TransportError → retry until `_run_expiry_cleanup` erases them (same queue behavior b1b traced for finding 1).
- Outcome: complete delivery failure to any IPv6-capable peer with misleading retry semantics (retryable forever) and eventual expiry-with-erasure of messages addressed there. hunt-b1b observed this as a "second failure mode" inside its finding 1's evidence; it is a distinct mechanism that survives that finding's repair, reported here in full.
- Confidence: traced — mechanism empirically demonstrated twice (constructed-URL parse failure; live `localhost` failure); trigger and frequency grounded (any AAAA-first resolution).

4. [L] — runtime constructs `NetworkPolicy` directly, skipping the classmethod's suffix normalization: uppercase or apex-form configured suffixes never match, rejecting all internal hosts
- Location: `lattice/runtime.py:205-208` (direct `NetworkPolicy(mode=..., private_suffixes=tuple(config.network.private_suffixes), ...)`) vs `lattice/network_policy.py:NetworkPolicy.private` (`tuple(s.lower().strip(".") for s in suffixes)`); `config.py:115` (`self.private_suffixes: list[str] = data.get("private_suffixes", [])` — raw, unnormalized)
- Evidence: the classmethod normalizes each suffix (`s.lower().strip(".")`); the daemon path passes config strings through verbatim, and neither `NetworkConfig` nor the dataclass `__post_init__` normalizes. `"Corp.Example"` or `".corp.example"` from config is compared raw against a lowercased, `rstrip(".")`-ed hostname (`hostname_lower.endswith(s)`), so it can never match.
- Trigger: a private-mode deployment whose operator writes any suffix with a capital letter or a leading dot — the two most natural ways to write one. Every `validate_ip` then fails `in_suffix` for all hosts (fail-closed), so all well-known resolution, pinning, gossip, and outbound delivery to internal peers fails with `TransportError("no allowed IP address found ...")`.
- Frequency: LATENT — operator-configuration-dependent, same unproven population as finding 2; fires on the first resolution attempt after such a config is loaded. Reachable in production (operator action), observable today because policy validation runs before the known kwargs fault.
- Outcome: fail-closed outage of the entire private-mode federation path with a confusing error; the two construction paths that must agree (`NetworkPolicy.private()` used by tests/CLI, direct construction used by the daemon) diverge.
- Confidence: traced — mechanism certain from code (normalization asymmetry verified by reading both paths); frequency ungrounded in-tree (latent).

5. [S-] — public mode does not reject CGNAT shared address space (100.64.0.0/10)
- Location: `lattice/network_policy.py:NetworkPolicy._is_internal` (checks `is_private / is_loopback / is_link_local / is_reserved / is_unspecified` only)
- Evidence: venv check on Python 3.11.13: `ipaddress.ip_address('100.64.0.1')` → `is_private=False, is_reserved=False, is_unspecified=False` — so it passes public-mode `validate_ip`.
- Trigger: a hostname resolving into 100.64.0.0/10 (attacker-controlled DNS for their own domain, or any redirect target — see finding 1). Harm is environment-armed: only deployments whose internal services live in CGNAT space (some k8s CNI / overlay networks, Tailscale-style meshes) are affected.
- Frequency: environment-armed, ungroundable in-tree — needs one more pass (confirm which, if any, documented deployment topology uses 100.64/10 internally). Multicast (224/4, also unflagged) is not reachable by TCP connect and is not a defect.
- Confidence: suspected — mechanism verified against the venv; trigger requires a specific (undocumented) network environment; frequency unproven.

## Checked and clean

- **DNS-rebinding / TOCTOU core design** — `transport.py:_resolve_and_validate` + connect-to-IP: the connection targets the policy-validated IP literal in the rewritten URL (single `getaddrinfo`, no independent re-resolution), with the original hostname preserved for SNI/cert verification via `assert_hostname`. Absent redirects (finding 1), rebinding between validation and connect is not possible. Sound.
- **IPv4-mapped IPv6 unwrapping** — `transport.py:86-89` converts `::ffff:a.b.c.d` to the IPv4 form before `validate_ip`, so mapped-loopback/mapped-RFC1916 cannot slip past `_is_internal` (venv confirms `::ffff:127.0.0.1` is caught either way).
- **`hostname_allowed` return value ignored** (`transport.py:75`) — benign: private-mode `validate_ip` independently re-checks suffix AND CIDR, so discarding the boolean cannot widen what passes; public mode returns True unconditionally.
- **Scheme enforcement** — `request()` rejects non-`https` input URLs; `models._validate_https_url` additionally rejects `@`-bearing endpoint URLs in well-known documents; `webhook` URL is the only http-permitting model field (operator config, see Enumeration).
- **Well-known URL construction from peer-supplied domains** — `addressing.parse_address` blocks `:` `/` `@` in the domain (no port/path/userinfo smuggling into `resolution.py:48`'s `f"https://{domain}/..."`); leftover fragment/query characters in a domain only alter the attacker's own fetch (host is still what `parse_url` extracts and what gets validated and connected to).
- **`_is_internal` coverage** (public mode) — verified in the venv: 0.0.0.0/8 (`0.1.2.3` → private True), 198.18.0.0/15 (benchmark, private True), 192.0.0.0/29, IPv6 ULA fc00::/7 and ::ffff:0:0/96 all rejected. Gaps found: 100.64/10 (finding 5) and multicast (not TCP-reachable — not a defect).
- **Cross-version CIDR containment** — `IPv6Address in IPv4Network` (and vice versa) returns False rather than raising (venv-verified), so a private-mode deployment with mixed-family CIDRs fails closed instead of crashing.
- **Private CA handling** — `OutboundTransport.__init__` loads `private_ca_path` into a `create_default_context()` (verification on); missing bundle fails construction fast. The public-CA fallback when `private_ca_path` is None is config surface, noted under finding 2.
- **`webhook.py` pool** — builds its own `PoolManager` (correct kwargs, unaffected by the known call-shape defect); its URL is operator config, not outsider content — out of scope by the trust model; it does inherit default redirect-following (operator-chosen receiver), noted for the record only.

## Enumeration

Composed commands (run from repo root, `rg ... --type py`):

```
rg -n 'validate_ip|hostname_allowed|_is_internal|NetworkPolicy\(|NetworkPolicy\.' lattice/ --type py
rg -n 'https?://|parse_url|PoolManager\(|\.urlopen\(|getaddrinfo' lattice/ --type py
```

| Instance | Disposition |
|---|---|
| `network_policy.py:54 _is_internal` (called only from `validate_ip:74`) | examined-clean except CGNAT gap → finding 5 (S-) |
| `network_policy.py:63 validate_ip` (only call site: `transport.py:91`) | suffix anchoring defect → finding 2 |
| `network_policy.py:89 hostname_allowed` (only call site: `transport.py:75`, return ignored) | examined-clean (see Checked and clean) |
| `cli.py:576 NetworkPolicy.public()` (domain-transfer offline command) | examined-clean — same transport machinery, operator-initiated, public mode |
| `runtime.py:203 NetworkPolicy(...)` (daemon construction) | normalization divergence → finding 4 |
| `transport.py:125 target_url = f"https://{ip}:{port}..."` | unbracketed IPv6 → finding 3 |
| `transport.py:132 self._pool.urlopen(...)` | kwargs fault KNOWN (not re-reported); redirect default → finding 1 |
| `transport.py:77 getaddrinfo(hostname, AF_UNSPEC, SOCK_STREAM)` | examined-clean — single resolution feeding validated connect-to-IP (see TOCTOU item); IPv6-first ordering is finding 3's trigger |
| `resolution.py:48 url = f"https://{domain}/.well-known/lattice"` | examined-clean as a construction (host always the validated connect target); it is finding 1's attacker-fed fetch population |
| `runtime.py:964 / :1113 transport.request(endpoint, ...)` | endpoints from pins/peer cards (outsider-influenced) — policy is the only guard → findings 1/3 blast radius |
| `webhook.py:58/91 own PoolManager + urlopen` | out-of-scope-with-reason — operator-configured URL, correct call shape, not peer-controlled |
| `models.py:49 _validate_https_url`, `models.py:213` extension namespace | examined-clean / not an outbound construction (schema-level URI check) |
| `config.py:39` webhook https check, `config.py:196` bootstrap comment | examined-clean / documentation string |

## Design risks (max 2)

1. Private mode with `private_ca_path = None` keeps the default public CA store (and public-mode TLS semantics), while the mode's stated purpose is restricting to a private network; combined with finding 2's unanchored suffix this is what makes an attacker's ordinary public cert acceptable. Config surface allows it today; no in-tree path misbehaves on its own.
2. `_resolve_and_validate` returns the *first* policy-allowed address across `AF_UNSPEC` results; a dual-homed internal host could steer connections between its addresses only via DNS ordering, which is operator/DNS-controlled — no defect demonstrated, noting the coupling with finding 3's family-preference assumption.

## Side discoveries

- The cold-sender queue (`api.py:303-315`) is fed before the rate limiter and without authentication; a syntactically valid message from any unpinned domain queues a background well-known fetch (b1b finding 3 covers the unbounded set growth; the fetch side is finding 1's trigger — noted for dedupe, not separately reported).
- In my redirect test the redirect's second request re-sent the original headers including `Host: <first-hop host>` to the internal target — cosmetic evidence that the redirected request is a full replay of the original, body included.

## Bound

- Both assigned files were read end to end in full; no assigned file was left unopened.
- Not reachable without live infrastructure: actual cross-internet behavior of a hostile redirect target (findings 1's demo used loopback addresses standing in for 169.254.169.254/RFC1918), and real dual-stack resolver ordering on the production host class (macOS verified; Linux assumed per RFC 6724).
- The known call-shape defect (hunt-b1b finding 1) blocks every live request today, so no gated finding could be observed through a real daemon run; all gated evidence is from the /tmp harness with only that fault neutralized at the urllib3 boundary.
- Enumeration patterns are string-based (`rg` on identifiers/literals); a dynamically-built call bypassing the named symbols (none exists in-tree — single transport class, single policy module) would not match.
