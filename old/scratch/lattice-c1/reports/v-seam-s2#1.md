# v-seam-s2#1 — PRIMED VERIFIER verdict on seam-s2 finding 1

Claim under test: `scratch/lattice-c1/reports/seam-s2.md` finding 1, "Redirect following in
OutboundTransport bypasses NetworkPolicy and misreports `resolved_ip`" (reported tier H).

**Verdict: ADJUSTED.** The redirect mechanism is real and reproduced. The reachability claim
("PRODUCTION ... Reachable today on all three outbound paths") is **refuted**: no outbound request
in this tree reaches the network today, because `OutboundTransport.request` passes `urlopen` kwargs
that are invalid for the declared and locked urllib3 (`>=2.0.0`, lock 2.7.0). Every request raises
`TypeError` before a socket is opened. The finding is therefore **GATED behind the transport-kwargs
defect** below; it keeps its real security severity (H) but is latent until that defect is repaired.

## Frame re-derived from source (not from the claim)

- `OutboundTransport.request` (lattice/transport.py:100-147) resolves the hostname, validates the IP
  via `NetworkPolicy.validate_ip`, rewrites the URL to `https://{ip}:{port}{request_uri}`, and calls
  `self._pool.urlopen(method, target_url, body=body, headers=request_headers, fields=fields,
  assert_hostname=hostname, preload_content=True)`. No `redirect=` and no `retries=` are passed.
- Installed urllib3 is 2.3.0; `uv.lock` pins 2.7.0; `pyproject.toml:36` declares `urllib3>=2.0.0`.
  I downloaded 2.7.0 and 2.0.7 wheels and read their signatures. In every urllib3 >= 2.0,
  `HTTPConnectionPool.urlopen` has neither a `fields` nor an `assert_hostname` parameter; both fall
  through `**response_kw` into `_make_request`, which accepts neither → `TypeError`.
- Callers reachable in production: `runtime.py:209` constructs the transport;
  `runtime.py:964` (`_send_outbound_message`), `runtime.py:1113` (`_send_gossip_batch`), and
  `topology.verify_candidate` → `resolution.resolve_with_ip` (resolution.py:64) all call
  `transport.request`.

## Decisive artifacts

Executed against the real class and a local TLS server (no external network):

1. IPv4 target, real `OutboundTransport`, urllib3 2.7.0 (the locked version):
   `request("GET", "https://127.0.0.1:<port>/.well-known/lattice")`
   → `RAISED builtins.TypeError HTTPConnectionPool._make_request() got an unexpected keyword
   argument 'fields'`; **the server logged zero connections**.
2. Same with urllib3 2.3.0: same `TypeError` (`fields`); with `fields` removed, the next failure is
   `assert_hostname`. Both are 1.x `urlopen` kwargs removed in urllib3 2.0.
3. `PoolManager.urlopen` source (2.3.0): `redirect: bool = True`, recurses on any 3xx with a
   `Location` after `urljoin(url, redirect_location)`; no policy hook exists inside urllib3.
4. Live redirect probe (local http servers, default `PoolManager().urlopen(...)`, no kwargs):
   request to server A (302 `Location: http://127.0.0.1:B/latest/meta-data/`) hit server B and
   returned B's body; B received `Host: victim.example` (original host forwarded). `urljoin`
   admits a scheme downgrade: `urljoin("https://198.51.100.7:443/.well-known/lattice",
   "http://169.254.169.254/latest/meta-data/")` → `http://169.254.169.254/latest/meta-data/`.

So the mechanism is exactly as the claim describes; it simply cannot be exercised until the request
call is fixed.

## Sub-claims

CONFIRMED:
- urllib3 `PoolManager.urlopen` follows 301/302/303/307/308 by default with `urljoin` and no policy
  hook; `NetworkPolicy` is consulted only for the original hostname's IP, never the redirect target.
- `urljoin` allows scheme downgrade to plain HTTP, where `assert_hostname` would be irrelevant.
- Cross-host redirect forwards the caller's `Host` header (Host is not in the default
  `Retry.remove_headers_on_redirect` set: only Authorization/Cookie/Proxy-Authorization).
- If the request were made, `FederationResponse.resolved_ip` would still be `str(ip)` of the
  originally validated IP while the connection went to the redirect target — a real seam/prefix
  misattribution (topology.py:116 `prefix_from_ip`).

REFUTED:
- "Trigger: PRODUCTION ... Reachable today on all three outbound paths." Refuted: every
  `transport.request` today raises `TypeError` before connecting (artifacts 1-2). Reachability kind
  is **gated-behind the transport-kwargs defect** (new finding below).
- "Frequency: ... every well-known fetch and every outbound POST in the daemon." Refuted as an
  already-occurring population: the current successful-request population is zero. Latent.

CORRECTED (mechanism detail, not a refutation):
- The claim attributes body/method preservation to 307/308. urllib3 2.x only rewrites method to GET
  and drops the body on **303**; 301/302/307/308 all preserve method and body. So 301/302 are equally
  body-forwarding vectors, widening the stated condition.

## Severity and frequency (corrected)

- Severity: **H unchanged.** The gated defect is SSRF past `NetworkPolicy` to loopback/link-local
  (cloud metadata) with attacker-chosen scheme/path, plus forwarding of message bodies and gossip
  payloads on POST redirects. Per the gated-finding rule it keeps its real severity and is marked
  gated.
- Frequency: **latent/corrected.** Currently zero occurrences (no request completes). Once the gate
  is repaired, the population is "every outbound well-known fetch, message POST, and gossip POST to
  a peer that answers 3xx" — i.e. any hostile or compromised peer domain, not honest peers.

## Additional mechanisms / earlier failure sites

- **Gate (new finding, see Findings below):** `lattice/transport.py:132` `_pool.urlopen(...,
  fields=fields, assert_hostname=hostname)` is invalid for all urllib3 >= 2.0. `TypeError` is not an
  `urllib3.exceptions.HTTPError`, so the `except` at transport.py:141 does not catch it and it
  escapes as a raw `TypeError`. This is a live production defect independent of the redirect
  finding.
- **Earlier failure site, confirms seam-s2 #2:** with a hostname whose first allowed `getaddrinfo`
  answer is IPv6, `parse_url` inside `PoolManager.urlopen` fails before the kwargs are bound. I ran
  the real transport against `localhost` (resolved `::1` first under an IPv6-permitting policy) and
  got `LocationParseError: Failed to parse: https://::1:<port>/.well-known/lattice`, wrapped as
  `TransportError`. This reproduces seam-s2 #2 from the real class and shows it is reachable
  **without** clearing the kwargs gate (parse_url runs first). Not re-verdicting #2 here; recorded as
  an independent live defect on the same trace.

## Fix-direction constraints

- Removing `fields=`/`assert_hostname=` (to make requests work) does **not** fix the SSRF — it
  activates it. Any repair of the request call MUST also pass `redirect=False` (or a `Retry` with
  `redirect=0`/`raise_on_redirect=True`), or re-run `_resolve_and_validate`/`validate_ip` on every
  `Location` target before following it, and must re-key `resolved_ip` to the IP actually connected
  to. `assert_hostname` belongs on the pool/connection constructor (or `PoolManager(...)`),
  not on `urlopen`.
- The repair must preserve the TOCTOU property (connect to the validated literal IP, preserve SNI),
  so a naive "pass the hostname and let urllib3 resolve" fix reintroduces DNS-rebinding SSRF.

## Reachability kind

GATED behind the transport-kwargs defect (`findings` id `v-seam-s2#1-gate`). Production once that
defect is cleared; zero occurrences today.

## Bound

- No live federation peer or network was reachable. Redirect mechanics were proven with local HTTP/TLS
  servers and installed/locked urllib3 source; cross-network behaviour (a real peer's 3xx,
  cloud-metadata reachability) was not executed.
- Provider/deployment specific: I could not confirm the urllib3 version actually installed on the
  running daemon host. `pyproject.toml` and `uv.lock` both require >= 2.0, and the local environment
  has 2.3.0, so the gate is SUSPECTED in live infra rather than observed there; the mechanism is
  proven for every urllib3 >= 2.0 wheel inspected (2.0.7, 2.3.0, 2.7.0).
- `git blame`/history for `lattice/transport.py` was unavailable (file is untracked in the dirty
  tree); no history-based corroboration.

## Findings

1. [M] — `OutboundTransport.request` passes `urlopen` kwargs invalid for urllib3 >= 2.0; every
   outbound request raises `TypeError` before connecting
   - Location: lattice/transport.py:OutboundTransport.request, the `self._pool.urlopen(...)` call
     (transport.py:132-139, `fields=fields, assert_hostname=hostname`)
   - Evidence: `response = self._pool.urlopen(method, target_url, body=body, headers=request_headers, fields=fields, assert_hostname=hostname, preload_content=True)`
   - Trigger: PRODUCTION. Any outbound federation operation: candidate verification
     (`_run_verify_candidates` → `TopologyService.verify_candidate` → `resolve_with_ip` → request),
     message custody (`runtime._send_outbound_message`, runtime.py:964), gossip send
     (`runtime._send_gossip_batch`, runtime.py:1113). Reproduced locally against the real class with
     urllib3 2.3.0 and 2.7.0: `TypeError: ..._make_request() got an unexpected keyword argument
     'fields'`, zero server connections.
   - Frequency: DEMONSTRATED — every outbound request; the daemon's delivery/gossip/verify tasks run
     on every configured interval and every one of their network calls hits this. `_RecurringTask.
     _run` (runtime.py:130) catches the `Exception`, logs it, and retries next tick, so the failure
     is continuous, not one-shot.
   - Outcome: federation transport is entirely non-functional — no peer is ever verified, no
     outbound message is delivered (messages stay claimed and retried, aborted mid-batch), no gossip
     is sent. `TypeError` is not an `HTTPError`, so the intended `TransportError` contract at
     transport.py:141 is bypassed and callers that catch only `TransportError`/`ResolutionError`
     (`_send_outbound_message`, `_resolve_pending_senders`) see an unexpected exception instead.
   - Confidence: traced — mechanism proven (wheels + executed reproduction); trigger and frequency
     production, bounded only by the possibility that the live host runs an out-of-range urllib3.

## Checked and clean

- `webhook.py:91` `_pool.urlopen(...)` passes only `body`, `headers`, `preload_content` — no invalid
  kwargs; unaffected by the gate.
- `urljoin`/redirect mechanics inside urllib3, `Host` forwarding, and scheme-downgrade admission were
  reproduced as described in the claim.
- `FederationResponse.resolved_ip` reporting the original validated IP on the (hypothetical)
  redirect path is correct as a code fact (transport.py:145-151).
- The `except urllib3.exceptions.HTTPError` wrapping is otherwise correctly placed; it is
  insufficient only because `TypeError` is not an `HTTPError`.

## Enumeration

Command (closes the class of urllib3 request calls and their kwargs):

```
rg -n "urlopen\(|assert_hostname|fields=" lattice/
```

| instance | kwargs passed | urllib3>=2.0 valid? | disposition |
|---|---|---|---|
| transport.py:132 `_pool.urlopen` | body, headers, `fields`, `assert_hostname`, preload_content | no — `fields`/`assert_hostname` invalid → `TypeError` | Finding 1 (gate) |
| webhook.py:91 `_pool.urlopen` | body, headers, preload_content | yes | examined-clean |

## Design risks (max 2)

- Redirect-target trust is not part of the transport's contract at all; even a correct
  `redirect=False` leaves no assertion that a peer's advertised endpoint answered the request
  itself. Consider recording the redirect status in audit when a 3xx is returned, so a peer that
  tries this is visible.
- `assert_hostname` on a per-request `urlopen` has never been valid in the pinned dependency range;
  the seam between the transport and urllib3 is unguarded by any type check (`mypy` cannot see
  `**response_kw`), so a similar drift can recur silently.
