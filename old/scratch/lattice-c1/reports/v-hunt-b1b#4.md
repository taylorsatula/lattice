# v-hunt-b1b#4 — PRIMED VERIFIER

Claim under test: **hunt-b1b finding 4 [L]** — "(latent, gated behind finding 1) Redirect
following bypasses `NetworkPolicy` (SSRF)." Source: `scratch/lattice-c1/reports/hunt-b1b.md`.

Verdict: **ADJUSTED** — mechanism, trigger, gating, and frequency all CONFIRMED; **severity
corrected L → H** under the pilot calibration rule that a gated finding keeps its real severity.
The claim's own text already names the outcome "an H-class trust-boundary bypass if activated";
the `[L]` header is the only part that does not survive the calibration.

Reachability kind: **GATED behind hunt-b1b#1** (the `TypeError` on every `OutboundTransport.request`).
Not production-reachable today; not tests-only (no test exercises a real redirect).

---

## Frame re-derived from source (before checking the claim)

- **The transport call site** (`lattice/transport.py:OutboundTransport.request`, L98–150): the
  URL hostname is resolved and policy-validated once (`ip = self._resolve_and_validate(hostname)`,
  L121), then the URL is rewritten to `https://{ip}:{port}{parsed.request_uri}` (L127) and handed
  to `self._pool.urlopen(...)` (L132–139). Policy is applied to the *original* hostname only;
  nothing downstream re-validates.
- **The pool.** `urllib3.PoolManager(num_pools=…, maxsize=…, timeout=…, ssl_context=…)` (L66–71),
  no `retries=` override, no redirect control. `.venv` pins urllib3 **2.7.0**.
- **What urllib3 2.7.0 does.** `PoolManager.urlopen(self, method, url, redirect: bool = True, **kw)`
  (verified via `inspect.signature`). Its source (verified via `inspect.getsource`):
  `conn = self.connection_from_host(u.host, port=u.port, scheme=u.scheme)`, then
  `redirect_location = redirect and response.get_redirect_location()`; on a 3xx it does
  `redirect_location = urljoin(url, redirect_location)` and
  `return self.urlopen(method, redirect_location, **kw)` — a **fresh `connection_from_host` on
  the attacker-supplied host**, with no policy hook anywhere in the chain.
- **The gate.** `fields` and `assert_hostname` are not `PoolManager.urlopen` /
  `HTTPConnectionPool.urlopen` parameters (verified: neither name appears in either signature;
  `_make_request` accepts neither). Every call raises
  `TypeError: HTTPConnectionPool._make_request() got an unexpected keyword argument 'fields'`
  (and, with `fields` absent, `'assert_hostname'`). See hunt-b1b#1, independently reproduced below.
- **Policy semantics** (`lattice/network_policy.py`): public mode `_is_internal` rejects private /
  loopback / link-local / reserved / unspecified IPs; private mode restricts to configured
  CIDRs/suffixes. The control exists to prevent exactly this reach.

## Component-by-component

- **Mechanism — CONFIRMED (traced, empirically reproduced).** With the transport's pool
  construction (plain `PoolManager`, https replaced by http first-hop only to avoid TLS cert
  setup; the redirect path is scheme-agnostic and independent of `ssl_context`), a first-hop
  `302 Location: http://127.0.0.1:<port>/internal` was followed: the second hop received the
  original POST body `b'{"secret":1}'`, and its `200` became the final `BaseHTTPResponse`.
  Observed at the redirect target: `('/internal', b'{"secret":1}', 'pub.example.com')` — the body
  re-sent and the original `Host` header forwarded. `_resolve_and_validate` never sees the
  redirect host. No policy check fires.
- **Trigger — CONFIRMED, attacker-controlled, but GATED.** Two attacker-controlled fetches reach
  `OutboundTransport.request`: (a) peer-card endpoints `peer.endpoints["gossip"]` /
  `["messages"]` (`runtime.py:964`, `runtime.py:1113`), advertised by any peer; (b) cold-sender
  well-known resolution `https://{domain}/.well-known/lattice` (`resolution.py:50`), where
  `domain` is sender-supplied. A 3xx (e.g. `Location: http://169.254.169.254/…`) is followed with
  the daemon's body. Today no request completes: hunt-b1b#1's `TypeError` aborts at `urlopen`
  before any bytes are sent. GATED behind hunt-b1b#1.
- **Frequency — CONFIRMED but LATENT (0 today; attacker-paced once armed).** The finding's
  "attacker-controlled ... zero cost to trigger per request once live" is accurate *conditional on
  the gate being opened*. It is not groundable as a current operation population because the
  population is empty today (no request completes). Marked LATENT-by-gate, not asserted as live.

## Corrections

- **Severity: [L] → [H] (gated).** The calibration rule "a gated finding keeps its real severity
  but is marked as such" governs. The real outcome class is the rubric's H: a network peer (or a
  sender controlling a resolvable domain) directs the daemon to connect to and POST message/gossip
  bodies at private / loopback / link-local addresses that `NetworkPolicy` exists to forbid —
  cross-boundary reach, and a bypass of the system's stated SSRF control. The finding text itself
  says "H-class trust-boundary bypass if activated". The `[L]` label reflects latency, but the
  gated rule forbids downgrading on that basis; a repair of hunt-b1b#1 that ignores this ships the
  hidden SSRF, which is the precise harm the rule names. (Precedent aligned: v-hunt-b1b#2 left its
  gated finding's severity at the *outcome* class, not at a latency-discounted class.)
- **Frequency: left LATENT, restated with the gate.** Not corrected downward to "not a defect":
  the mechanism is proven and the trigger is concrete; only the cadence is zero until the gate
  opens. State plainly: today's demonstrated frequency is **0** (unreachable); post-repair it is
  **per-fetch, attacker-paced**.
- **No sub-claim refuted.** Every mechanism/trigger statement in the finding checked out,
  including the recursion-with-fresh-DNS, the body re-send, and the `http://` TLS-skip variant.

## Additional mechanisms / earlier failure sites (same trace, per instruction 6)

1. **`resolved_ip` becomes a false statement under redirect.** `request()` returns
   `resolved_ip=str(ip)` (the *original* validated IP, L149) even when the connection was made to
   a different redirect host. `resolution.resolve_with_ip` surfaces this to
   `topology.verify_candidate`, which records `prefix_from_ip(resolved_ip)` for diversity
   accounting (LOOSE_ENDS Phase 6). A redirected connection therefore records the wrong network
   prefix. Same gate; H-severity family is the SSRF itself.
2. **Cross-host redirect drops the per-host TLS/hostname controls.** Source: on redirect urllib3
   builds a new pool via `connection_from_host` for the target, so any `assert_hostname`/CA policy
   attached to the original pool does not carry; and an absolute `http://` Location connects in
   plaintext (reproduced: first-hop http, plaintext redirect followed). Even a repair that passes
   `assert_hostname` *correctly* would not close this.
3. **The original `Host` header is forwarded to the redirect target** (observed
   `Host: pub.example.com` on the loopback receiver). Minor, but it means virtual-host routing at
   the internal target is attacker-influenced.

## Fix-direction constraints (beyond the reported symptom)

- A repair of hunt-b1b#1 that merely removes/moves `fields` and `assert_hostname` **does not fix
  this and activates it**. The same edit must pass `redirect=False` (per-request) or configure the
  pool's `Retry` with `redirect=False`, or explicitly re-validate the final host. State this as a
  hard coupling: #4's gate IS #1's repair.
- Do not rely on `assert_hostname` or the `https`-only precondition to contain a redirect: an
  `http://` Location bypasses TLS entirely, and a cross-host `https` Location uses a fresh pool
  without the transport's validation or per-host assertion.
- Disabling redirects also restores the truth of `FederationResponse.resolved_ip`; alternative
  fixes (validate-then-follow) must keep that field meaning "the IP actually connected to".
- `lattice/webhook.py` builds its own `PoolManager` and passes only valid kwargs, so it makes
  working (non-raising) requests *today* and also follows redirects by default. Its URL is
  operator config, so no policy is bypassed there — but the same `redirect=False` hardening should
  be considered if a webhook URL ever becomes peer- or tenant-influenced.

## Checked and clean

- `parse_url` scheme gate and `host is None` gate (L114–118): correct; non-https URLs never reach
  the pool.
- `_resolve_and_validate` IPv4-mapped normalization and per-candidate `validate_ip` loop: correct;
  it validates only the first hop by design, which is the finding's root.
- `tests/test_transport.py`: only asserts URL rejection (http scheme, `localhost`, `10.0.0.1`) —
  all fail before `urlopen`, so they pass despite hunt-b1b#1 and exercise no redirect.
- No test anywhere exercises a redirect (`rg 'redirect|urlopen' tests/` → only `tests/test_webhook.py`
  patches `urlopen` with a static `MagicMock`); the defect is invisible to the suite.
- hunt-b1b#1's `TypeError` mechanism independently reproduced against the repo `.venv` (urllib3
  2.7.0): `fields` and, absent that, `assert_hostname` both rejected by `_make_request`.

## Enumeration

Command: `rg -n "urlopen|redirect|PoolManager" lattice --include=*.py` → all outbound call sites:
`transport.py:132` (this finding; `redirect` unset), `webhook.py:91` (valid kwargs, same default
redirect, no policy), and the two `OutboundTransport` construction sites. No `redirect`/`Retry`
control exists anywhere in `lattice/`. Class is closed: the redirect default is un-overridden at
both pools.

## Bounds (what I could not reach)

- **Live provider/peer behaviour.** Whether any real federation peer or resolved host returns a 3xx
  is unverifiable offline; the mechanism is attacker-controlled, so the local reproduction proves
  the path, but no live arming was observed. (Gate makes this moot today.)
- **Deployment mode.** Both public and private modes are affected (neither re-validates redirect
  targets); the *impact* differs by configured CIDRs/suffixes, which I did not enumerate from a
  live config.
- **Reproduction nuance.** The local redirect reproduction used an `http://` first hop to avoid TLS
  certificate setup; the redirect branch is scheme-agnostic and lives in `PoolManager.urlopen`
  (source-inspected), so the https first hop behaves identically, but I did not stand up a TLS
  first hop.
- Cloud-metadata / internal-service *reachability from this host* is out of scope (no live infra).
