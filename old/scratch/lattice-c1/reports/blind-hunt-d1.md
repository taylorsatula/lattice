# blind-hunt-d1 — blind third pass: outbound network-policy / SSRF boundary

Pass type: blind hunter. Files read end to end: `lattice/network_policy.py` (94 lines),
`lattice/transport.py` (153 lines). Supporting reads for trigger tracing and enumeration:
`lattice/resolution.py`, `lattice/runtime.py` (`verify_inbound_message`,
`queue_domain_resolution`, `_resolve_pending_senders`, `_send_outbound_message`,
`_send_gossip_batch`, policy construction), `lattice/api.py` (messages route + cold-sender branch),
`lattice/config.py` (`NetworkConfig`), `lattice/addressing.py`, `lattice/protocol/models.py`
(endpoint validators), `lattice/webhook.py` (disposition only).

Empirical work run with the repo venv (`.venv`, urllib3 2.7.0, Python 3.11.13) and additionally
`/opt/homebrew/bin/python3.13` / `3.14` for `ipaddress` semantics. All scaffolding in `/tmp`; the
repo classes were imported unmodified; no repo file was touched.

Neutral question restated (re-derived, not assumed): does the SSRF-safe outbound boundary hold for
hostname/IP validation, public vs private mode, CIDR/CA policy, IPv4-mapped-IPv6, redirects, and
DNS-rebinding? Answer: **the first-hop boundary holds; it is defeated or broken at four other
points.** Findings 1–4 were independently reproduced here and coincide with the already-filed
`hunt-d1` set (noted per finding for dedupe). Nothing in this report re-files the known
`fields`/`assert_hostname` call-shape defect (`hunt-b1b#1`); that defect is the **gate** for
findings that require a completed request.

## Findings

1. [H] — 3xx redirects re-enter urllib3 with no policy re-validation (GATED behind hunt-b1b#1)
- Location: `lattice/transport.py:OutboundTransport.request` (`self._pool.urlopen(...)` at
  `transport.py:132`); mechanism in urllib3 2.7.0 `PoolManager.urlopen`.
- Evidence: the transport supplies no `redirect=` / `retries=`. `PoolManager.urlopen` signature is
  `(self, method, url, redirect: bool = True, **kw)`; on a redirect it executes
  `return self.urlopen(method, redirect_location, **kw)` (`.venv/.../urllib3/poolmanager.py:486`),
  which re-runs `connection_from_host(u.host, port, u.scheme)` for the **Location** target. There is
  no call back into `OutboundTransport`/`_resolve_and_validate`/`validate_ip`.
- Trigger: (GATED — requires hunt-b1b#1 repaired, because today every `urlopen` dies with
  `TypeError` before a response is received). Then any HTTPS host the daemon fetches answers 3xx.
  The fetch population is outsider-controlled today: `POST /lattice/v1/messages` (public, no auth
  dependency at `api.py:280-284`) with `from_address user@<attacker-domain>` →
  `verify_inbound_message` returns `(domain, True)` without signature verification →
  `api.py:311 queue_domain_resolution(domain)` → `_resolve_pending_senders` →
  `resolver.pin(domain)` → `resolution.py:48 f"https://{domain}/.well-known/lattice"`; also gossip
  peer/pin endpoints at `runtime.py:964` and `runtime.py:1113`.
- Frequency: GATED; zero live occurrences today (every request dies at `transport.py:132`). Once
  live, attacker-controlled per fetched host at zero marginal cost.
- Outcome: the policy-validated first hop yields a `Location` the transport connects to without
  validation. The working arm is an `http://` scheme downgrade (no TLS, so no hostname assertion);
  the daemon then issues the request (GET on the discovery path, POST with body on the
  delivery/gossip paths) to loopback/link-local/RFC1918 such as `http://169.254.169.254/`.
- Confidence: traced — mechanism read from the pinned urllib3 source at the exact recursive call;
  gate and trigger traced end to end. Sub-claim narrowed: a cross-host **HTTPS** redirect is blocked
  by the retained `assert_hostname` (original hostname is carried in `kw`), so the vector is the
  `http://` downgrade and any TLS-less target, not "any address" (see Refuted sub-claims).

2. [M] — IPv6 destinations build an unbracketed URL; every transport call to an IPv6-first or
   IPv6-literal host fails (PRODUCTION, NOT gated by hunt-b1b#1)
- Location: `lattice/transport.py:request` — `target_url = f"https://{ip}:{port}{parsed.request_uri}"`
  (`transport.py:125`), with `ip` a bare `IPv6Address`.
- Evidence: `str(ipaddress.ip_address("2606:4700::6810:85e5"))` has no brackets →
  `https://2606:4700::6810:85e5:443/...`. `urllib3.util.url.parse_url` raises
  `LocationParseError("Failed to parse: ...")`; `LocationParseError` is an `HTTPError` subclass, so
  `transport.py:141` converts it to `TransportError`.
- Trigger: PRODUCTION. Any peer/pin/well-known host whose `getaddrinfo(..., AF_UNSPEC, ...)` orders
  an allowed IPv6 address first. Verified live on this host: `getaddrinfo("localhost")`,
  `"cloudflare.com"`, `"google.com"` all return IPv6 first; a global-unicast IPv6 address passes
  public mode (`is_private/is_reserved/is_link_local/is_loopback/is_unspecified` all False), so
  `_resolve_and_validate` returns the `IPv6Address`, then
  `OutboundTransport(NetworkPolicy.public()).request("GET", "https://cloudflare.com/.well-known/lattice")`
  → `TransportError: HTTP request failed: Failed to parse: https://2606:4700::6810:85e5:443/.well-known/lattice`.
  Also live-confirmed in private mode (suffix `localhost`, `::1`): same `TransportError`.
- Frequency: DEMONSTRATED (resolver-ordering-conditional) — every outbound transport call to a
  dual-stack or IPv6-capable peer domain; `resolution.py:50` well-known fetches and both POST call
  sites (`runtime.py:964`, `:1113`). No IPv4 preference/fallback exists in `_resolve_and_validate`.
- Outcome: complete failure of well-known resolution, delivery, and gossip to any such peer.
  `_send_outbound_message` records `retryable=True`, so messages churn claim → TransportError →
  retry until expiry erases them (lost queue item). A separate sub-mechanism: an IPv6 **literal**
  URL (`https://[::1]/`) yields `parsed.host == "[::1]"` (brackets retained), and
  `getaddrinfo("[::1]")` raises `gaierror` → `TransportError("DNS resolution failed")`; IPv6
  literal peers are never supported.
- Confidence: traced — mechanism and both trigger arms reproduced live against the unmodified repo
  classes. NOT gated: `PoolManager.urlopen`'s first statement is `u = parse_url(url)`; the malformed
  IPv6 URL fails there, before the broken kwargs reach `_make_request`. A naive repair of hunt-b1b#1
  does not restore IPv6.

3. [M] — `private_suffixes` match is an unanchored `endswith`: a lookalike registrable domain passes
   private-mode policy (LATENT)
- Location: `lattice/network_policy.py:validate_ip` / `hostname_allowed`
  (`in_suffix = any(hostname_lower.endswith(s) for s in self.private_suffixes)`,
  `network_policy.py:83` and `:94`).
- Evidence: venv run against the repo class: `NetworkPolicy(mode="private",
  private_suffixes=("company.com",))` → `validate_ip(93.184.216.34, "notcompany.com")` **ALLOW**;
  `"evilcompany.com"` **ALLOW**; only `"company.com.evil.net"` rejects. `in_suffix` alone is
  sufficient: the guard is `if not in_cidr and not in_suffix`, so a suffix-matched host may resolve
  to **any** IP (loopback/link-local/RFC1918 included) and still be admitted.
- Trigger: a deployment configured `[network] mode = "private"` with a bare `private_suffixes`
  entry (config schema `config.py:115`; daemon construction `runtime.py:203-208`). An
  unauthenticated `POST /lattice/v1/messages` with `from_address user@notcompany.com` queues the
  lookalike domain → `_resolve_pending_senders` → `resolution.py:48` fetch → `validate_ip` accepts
  it. Same fetch reachable from the public gossip route (`topology.verify_candidate`).
- Frequency: LATENT — no in-tree deployment uses private mode (rendered default is
  `mode = "public"`, `config.py:210`). Once configured, fires on first contact with a
  tail-sharing registrable domain.
- Outcome: the entire point of private mode — restricting federation to the operator's private
  set — is bypassed; the daemon exchanges federation traffic with an attacker-controlled outside
  host. Bounded from a full internal pivot by the transport's TLS hostname pinning
  (`assert_hostname=hostname`, `create_default_context()`): an internal HTTPS service cannot present
  a cert valid for the attacker's domain, so harm stays at "external attacker host admitted", M not
  H. The policy *decision* executes today, before the gated `urlopen`.
- Confidence: traced — mechanism reproduced live on the repo class; trigger traced end to end;
  frequency ungroundable in-tree (latent), stated as such.

4. [L] — the daemon constructs `NetworkPolicy` directly, skipping the classmethod's normalization:
   uppercase / trailing-dot suffixes fail closed (LATENT)
- Location: `lattice/runtime.py:203-208` (direct `NetworkPolicy(mode=..., private_suffixes=tuple(
  config.network.private_suffixes), ...)`) vs `lattice/network_policy.py:50`
  (`tuple(s.lower().strip(".") for s in suffixes)`).
- Evidence: `validate_ip` compares a lowercased, dot-`rstrip`-ed hostname against the **raw**
  configured suffix (`network_policy.py:82-83`); `NetworkConfig.private_suffixes` is read raw
  (`config.py:115`) and never normalized. `"Corp.Example"` can never match any hostname;
  `"corp.example."` can never match because the hostname's trailing dot is stripped but the
  suffix's is not. Verified against the repo class.
- Trigger: a private-mode deployment whose operator writes a suffix with a capital letter or a
  trailing dot. Every `validate_ip` then raises (fail-closed) for hosts not covered by a CIDR;
  well-known resolution, pinning, gossip, and delivery to internal peers all fail with
  `TransportError("no allowed IP address found ...")`. Observable today: policy validation runs
  before the gated `urlopen`.
- Frequency: LATENT — same operator-dependent population as finding 3.
- Outcome: fail-closed outage of the private-mode federation path; the two construction paths that
  must agree (`NetworkPolicy.private()`, used only by tests/CLI; the daemon's direct construction)
  diverge. Availability, not confidentiality.
- Confidence: traced — normalization asymmetry read in both paths and reproduced on the repo class;
  frequency latent.

5. [S-] — public mode does not reject CGNAT shared address space 100.64.0.0/10 (and multicast)
- Location: `lattice/network_policy.py:_is_internal` (`network_policy.py:54-61`) — five flags, no
  `not ip.is_global`.
- Evidence: venv (3.11.13, and identically 3.13/3.14): `100.64.0.1` →
  `is_private=False, is_reserved=False, is_link_local=False, is_loopback=False,
  is_unspecified=False, is_global=False`; `Public().validate_ip(100.64.0.1, ...)` returns without
  raising. `224.0.0.1` / `233.1.1.1` also pass (multicast is not TCP-connect-addressable, not a
  defect; recorded for completeness).
- Trigger: a hostname resolving into 100.64.0.0/10 (attacker-controlled DNS via the cold-sender
  path, or a redirect target from finding 1). Harm is environment-armed: only deployments whose
  internal services live in CGNAT/overlay space are affected.
- Frequency: environment-armed, ungroundable in-tree — no deployment topology in the tree uses
  100.64/10. Needs one more pass; tier S-.
- Outcome: a defence-in-depth gap in the public-mode IP filter; effect is gated by finding 1's
  redirect (or requires attacker DNS in a CGNAT deployment).
- Confidence: suspected — mechanism verified against the interpreter; trigger requires a specific,
  undocumented network environment; frequency unproven.

## Checked and clean

- **First-hop DNS-rebinding / TOCTOU resistance** — `_resolve_and_validate` resolves once and the
  connection targets the policy-validated IP **literal** in the rewritten URL
  (`transport.py:125`); urllib3 keys the pool by that IP, so there is no independent re-resolution
  between validation and connect. Sound (finding 1's redirects are the only re-entry).
- **IPv4-mapped IPv6 unwrapping** — `transport.py:86-89` converts `::ffff:a.b.c.d` to IPv4 before
  `validate_ip`; venv confirms `::ffff:127.0.0.1` → `127.0.0.1` → loopback rejected, and
  `::ffff:10.0.0.1` rejected.
- **Scheme enforcement on the input URL** — `request()` rejects `parsed.scheme != "https"`;
  `parse_url` lowercases the scheme, so `HTTPS://` is accepted (correctly), and non-HTTPS input is
  rejected. The gap is that a *redirect* `Location` is never scheme-checked (finding 1).
- **`hostname_allowed` return value ignored** — benign: private-mode `validate_ip` independently
  re-checks CIDR **and** suffix, and public mode returns True; discarding the boolean cannot widen
  what passes.
- **`_is_internal` coverage** (public mode) — venv-verified rejected: `0.0.0.0/8`, `10/8`,
  `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `192.0.2/24`, `198.51.100/24`, `203.0.113/24`,
  `198.18/15`, `240/4`, IPv6 ULA `fc00::/7`, link-local `fe80::/10`, `::1`, `::`,
  `2001:db8::/32`, `2001::/32` (Teredo), `2002::/16` (6to4), `64:ff9b::/96`/`64:ff9b:1::/48`
  (NAT64). `2001:20::/28` (ORCHIDv2) and multicast are accepted; revisited under finding 5 and
  dismissed (not internal / not TCP-reachable). Gaps: `100.64/10` (finding 5) only.
- **Cross-version `ipaddress` semantics** — `is_private`/`is_reserved` for the rejected ranges are
  identical on 3.11 / 3.13 / 3.14; no version-dependent regression.
- **Cross-family CIDR containment** — `IPv6Address in IPv4Network` (and vice versa) returns False
  rather than raising; mixed-family private CIDRs fail closed.
- **`addressing.parse_address`** blocks `:` `/` `@` in the domain, so no port/path/userinfo can be
  smuggled into the `f"https://{domain}/..."` construction; leftover `#`/`?` characters only shift
  the attacker's own request_uri, not the validated host.
- **Private CA handling** — `OutboundTransport.__init__` fails fast if `private_ca_path` does not
  exist; TLS verification stays enabled. (The additivity of the CA load is a side discovery, below.)
- **`webhook.py` pool** — own `PoolManager` with correct call shape (unaffected by hunt-b1b#1);
  its URL is operator config, not outsider content, so out of scope by the trust model. It does
  inherit default redirect-following, recorded for the record only.

## Enumeration

Composed commands (repo root):

```
rg -n 'validate_ip|hostname_allowed|_is_internal|NetworkPolicy\(|NetworkPolicy\.' lattice/ --type py
rg -n 'parse_url|PoolManager\(|\.urlopen\(|getaddrinfo|target_url|redirect' lattice/ --type py
rg -n 'private_suffixes|private_cidrs|private_ca_path' lattice/ --type py
rg -n 'transport\.request\(|_transport\.request\(|resolver\.pin\(' lattice/ --type py
```

| Instance | Disposition |
|---|---|
| `network_policy.py:54 _is_internal` (caller `validate_ip:74`) | examined-clean except CGNAT gap → finding 5 (S-) |
| `network_policy.py:63 validate_ip` (only caller `transport.py:91`) | suffix anchor defect → finding 3 |
| `network_policy.py:89 hostname_allowed` (caller `transport.py:75`, return discarded) | examined-clean |
| `network_policy.py:50 NetworkPolicy.private` normalization | test-only path; divergence → finding 4 |
| `runtime.py:203 NetworkPolicy(...)` direct construction | live construction path → finding 4 |
| `cli.py:576 NetworkPolicy.public()` | examined-clean (public mode, operator command) |
| `transport.py:77 getaddrinfo(AF_UNSPEC, SOCK_STREAM)` | clean (single resolution → connect-to-IP); IPv6-first ordering is finding 2's trigger |
| `transport.py:114 parse_url(url)` | clean (scheme enforcement; the only parser used for validation and connection) |
| `transport.py:125 target_url = f"https://{ip}:{port}..."` | unbracketed IPv6 → finding 2 |
| `transport.py:132 self._pool.urlopen(...)` | kwargs fault KNOWN (not re-reported); redirect default → finding 1 |
| `resolution.py:50 transport.request("GET", ...)` | attacker-fed fetch population → findings 1/3 |
| `runtime.py:964`, `runtime.py:1113 transport.request("POST", ...)` | POST body forwardable on redirect → finding 1 blast radius |
| `webhook.py:58/91` own PoolManager/urlopen | out-of-scope-with-reason (operator-config URL, correct call shape) |

## Design risks (max 2)

1. **Outbound response body has no size cap.** `transport.py:132-147` runs `urlopen(..., preload_content=True)`
   with no `preload_content_length` / streaming, and `resolution.py:62` feeds `response.data`
   straight into `strict_json_loads`. The read timeout (30 s) bounds duration, not bytes. A host the
   daemon fetches (cold-sender domain, peer endpoint) can return an unbounded body and exhaust
   memory. Not a policy-boundary defect; noted as a hardening gap on the same path.
2. **Private CA bundle is additive, not exclusive.** `OutboundTransport.__init__` starts from
   `ssl.create_default_context()` (system CAs) and then `load_verify_locations(private_ca_path)`, so
   private mode with a private CA still accepts any publicly-trusted certificate. This is what makes
   finding 3's attacker cert acceptable even when `private_ca_path` is configured. Config surface,
   no standalone trigger; observed for the record.

## Side discoveries (priced, single-pass — not folded into a verdict)

- **SD1 — empty-suffix fail-open (LATENT, would be H if the config were reached).** Location:
  `network_policy.py:__post_init__:33` (truthiness check) + `config.py:115/118`. Evidence (venv,
  repo class): `NetworkPolicy(mode="private", private_suffixes=("",), private_cidrs=())` →
  `validate_ip(8.8.8.8, "anything.evil")` **ALLOW**, `hostname_allowed("anything.evil")` True
  (`"".endswith` is True for every hostname); `NetworkPolicy.private(suffixes=["."])` normalizes to
  `("",)` and fails open the same way. Trigger: operator config `private_suffixes = [""]`
  (`NetworkConfig` rejects an empty *list*, not an empty *element*). Frequency: LATENT
  (operator-config; no in-tree deployment). Fix constraint: reject empty/whitespace/dot-only
  suffixes in `NetworkConfig` **and** `NetworkPolicy.__post_init__`; anchoring alone (finding 3's
  fix) does not close this — `host.endswith("." + "")` is still True.
- **SD2 — `Host` header is forwarded to the redirect target (GATED).** Location:
  `transport.py:127` sets `Host: <original hostname>`; urllib3 re-uses `kw["headers"]` across the
  redirect and strips only `Authorization` by default, so an internal target receives the
  attacker's domain as `Host`. Frequency: GATED behind hunt-b1b#1 + finding 1. Fix constraint: the
  redirect repair must strip/replace the `Host` header and not forward the request body across
  origins.

## Bound

- **Gated claims.** Findings 1 (and SD2) cannot be exercised through the daemon today: hunt-b1b#1
  makes every `urlopen` raise before a response is received. Redirect evidence is read from the
  pinned urllib3 source (`poolmanager.py:486`) — not re-run end to end here — because the gate
  blocks it.
- **Provider/upstream behaviour.** Whether a real DNS resolver orders AAAA first for a given peer,
  whether an attacker can register a tail-lookalike domain with a publicly-trusted certificate, and
  cloud-metadata/CGNAT deployment topologies are outside the tree and unverified.
- **Deployed population.** Whether any real deployment runs private mode (findings 3/4/SD1) or CGNAT
  (finding 5) is unverifiable in-tree; this is exactly why those frequencies are LATENT. Not silent —
  stated as the boundary.
- **Enumeration** is identifier/literal `rg`; a redirect control or policy call introduced
  dynamically outside the named symbols would not match (none exists in-tree).
