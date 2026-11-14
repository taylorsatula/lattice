# v-hunt-d1#5 — PRIMED VERIFIER

Claim under test: **finding 5 of `scratch/lattice-c1/reports/hunt-d1.md`, tier S-** —
"public mode does not reject CGNAT shared address space (100.64.0.0/10)".

Method: frame re-derived from source before reading the finding's conclusion. Read end-to-end:
`lattice/network_policy.py`, `lattice/transport.py`; supporting reads `lattice/resolution.py`,
`lattice/config.py`, `lattice/addressing.py`, `docs/THREAT_MODEL.md`, `tests/test_network_policy.py`.
Empirical work run through the repo venv (Python 3.11.13, the interpreter the finding used and the
one shipped in `.venv`) and by reading urllib3 2.7.0 in that venv. No repo file modified.

## Verdict: ADJUSTED (tier S- unchanged)

The **mechanism is CONFIRMED** (a factual gap in the public-mode IP filter). The finding's
**harm and reachability are REFUTED** (the SSRF outcome it describes is blocked by the transport's
TLS layer and, for any live connection, gated behind the known call-shape defect b1b#1). Frequency
stays **latent** — my pass confirms the "one more pass" question resolves negative: no deployment
topology in the tree uses 100.64.0.0/10. Net: a genuine defence-in-depth control gap with no
reachable adverse outcome → S- is the correct tier, but for a stronger reason than "needs one more
pass".

## Frame re-derived from source (before applying the claim)

- `network_policy.py:54-61 _is_internal` is exactly
  `ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified` — five
  flags, no `not ip.is_global`.
- `network_policy.py:73-78 validate_ip` public branch: raises **only if `_is_internal(ip)`**; otherwise
  `return` (accept).
- `transport.py:73-96 _resolve_and_validate` calls `validate_ip` for every `AF_UNSPEC` result and returns
  the first that does not raise. The policy call therefore executes **before** `urlopen`.
- `transport.py:114-125 request()` requires `scheme == "https"`, then rewrites the target to
  `f"https://{ip}:{port}{parsed.request_uri}"` — TLS connects to the **IP literal**.
- `transport.py:59` builds `ssl.create_default_context()`; `check_hostname` defaults to `True`.
- `config.py`: `NetworkConfig.mode` defaults `"public"`; `render_default_config` ships `mode = "public"`.

Empirical (repo `.venv`, Python 3.11.13):
`ip_address('100.64.0.0').is_private/is_reserved/is_link_local/is_loopback/is_unspecified == all False`,
`is_global == False`; same for `100.127.255.255`. `100.128.0.0` is `is_global=True`. So every address in
100.64.0.0/10 passes the public-mode filter. Confirmed against the finding's claim.

## Mechanism — CONFIRMED

Public mode accepts 100.64.0.0/10. The finding's factual assertion is correct, on both the pinned
interpreter and by source. Nothing else in the tree rejects it (single policy module, single call site
`transport.py:91`; enumeration below).

## Trigger — half confirmed, half refuted

Confirmed: the *policy decision* is reachable today. A cold sender posting
`from_address = user@<attacker-domain>` (§ the finding's own trigger) causes
`WellKnownResolver.resolve` → `transport.request` → `_resolve_and_validate`, and `validate_ip` runs
before the broken `urlopen`. If attacker DNS returns a 100.64/10 address, the policy **accepts** it.
That much is live.

Refuted: the claimed **outcome** — "the daemon connects, forwards the request (POST bodies included —
message JSON, gossip batches), and processes the internal service's response." That requires the TLS
handshake against the internal service to succeed, and it does not:

1. `transport.py:125` connects to the validated **IP literal**. urllib3 2.7.0
   `connection.py:760` sets `server_hostname = self.host` (the IP); `connection.py:992-1012` consults
   the supplied `assert_hostname` **only when `context.check_hostname` is False**. `transport.py:59`
   uses `create_default_context()`, whose `check_hostname` is True, so the ssl module verifies the
   certificate against the IP literal and the intended `assert_hostname` is inert.
2. An internal third-party CGNAT service therefore must present a certificate valid for the
   attacker-chosen hostname (or for the IP literal) to let the request proceed. An attacker steering
   *someone else's* internal host via their own DNS cannot produce that certificate. No path in the
   tree does it.
3. Independently, no live connection completes today: `transport.py:132-140` passes `fields` and
   `assert_hostname` as per-request `urlopen` kwargs; venv-verified both raise
   `TypeError: ... unexpected keyword argument` (the known b1b#1 fault). The finding itself marks this.

So the CGNAT acceptance is a **defence-in-depth control gap**, not the SSRF it is filed as. The
attacker-controlled-DNS half of the trigger is real; the "reach internal service" half is refuted.

The finding also lists "or any redirect target — see finding 1" as a trigger. That is not an
independent trigger for finding 5: `request()` rejects non-`https` input, and scheme downgrade only
happens through a redirect, whose policy bypass is **finding 1's** mechanism (`redirect=True`). With
redirects disabled/ignored the redirect avenue disappears entirely; with them enabled CGNAT vs. RFC1918
is irrelevant because redirects bypass policy wholesale. Finding 5 standalone adds nothing over
finding 1 there.

## Frequency — latent, and confirmed ungrounded

The finding already states "environment-armed, ungroundable in-tree". My extra pass asked the question
the finding deferred: which deployment topology uses 100.64.0.0/10 internally?
`rg -n "100\.64|CGNAT|cgnat" -i` over the whole tree returns **only** the finding's own report lines —
no code, config, documentation, or test mentions CGNAT or 100.64/10. `docs/THREAT_MODEL.md` discusses
internal-services reach only through the honest-TLS assumption; the default config and the only
documented deployment (`deploy/lattice.service`, `deploy/lattice.nginx.conf`) bind loopback and use
public mode. No in-tree evidence of an occupant. Frequency remains **latent**, and I add that the
TLS barrier above makes it latent even in a hypothetical CGNAT-internal deployment unless that
deployment also certifies the attacker's hostname on the internal service.

## Sub-claims refuted (named)

1. **"the daemon connects ... and processes the internal service's response"** — refuted: TLS
   certificate verification is keyed to the connect target (the IP literal, because
   `check_hostname=True` makes urllib3's `assert_hostname` inert); a third-party internal service
   cannot present the attacker's certificate. No connection to a foreign internal CGNAT service.
2. **"forwards the request (POST bodies included) ... to the internal target"** — refuted for the same
   reason (handshake fails before any body is written to the internal service).
3. **"or any redirect target — see finding 1"** as a standalone trigger — refuted as independent:
   it is entirely finding 1's redirect-policy-bypass mechanism, not a distinct CGNAT trigger.
4. **"fires on the first contact with any attacker-registered lookalike"**-class frequency claim — not
   applicable here; frequency is environment-armed and ungrounded (kept latent).

The mechanism sub-claim (public mode does not reject 100.64/10) is **not** refuted; it is confirmed.

## Additional mechanisms / earlier failure sites / new reachability

- **The transport's hostname-preservation design is ineffective on urllib3 2.x.** `transport.py`'s
  docstring claims the connection "preserves the original hostname for TLS SNI and certificate
  verification via `assert_hostname`." Under `create_default_context()` (`check_hostname=True`),
  urllib3 consults `assert_hostname` only when `context.check_hostname` is False
  (`connection.py:992-1012`); the ssl module checks the certificate against `server_hostname`, which is
  the rewritten IP (`connection.py:760`). A repair that merely relocates `assert_hostname` to the pool
  kwarg therefore does **not** restore hostname verification — every real domain would fail cert
  check against the IP literal. This is a **new reachability/fix constraint**, not a re-report of
  b1b#1: it survives b1b#1's repair. It is gated behind b1b#1 (no connection today) so it is recorded
  as a fix-direction constraint, not promoted to a finding.
- **The CGNAT gap is the only unflagged non-global IPv4/IPv6 range** that passes the filter. IPv4: the
  only non-global ranges not caught are 100.64/10 (the claim). IPv6: every non-global range I checked
  (64:ff9b:1::/48, 2002::/16, 2001::/32, 2001:2::/48, 2001:db8::/32, 2001:10::/28, fc00::/7, fe80::/10,
  IPv4-mapped, ::1, ::) is caught by one of the five flags; 5f00::/16 and 2001:20::/28 are flagged
  `is_global=True` by Python 3.11 but are unallocated/ORCHIDv2 with no internal occupant. So the class
  is essentially closed except CGNAT — which raises the finding's own tier, not lowers it, as a
  *coverage* fact, while leaving the harm refuted.

## Fix-direction constraints

- Closing the gap is trivial (`add 100.64.0.0/10` to the public-mode check, or switch to
  `not ip.is_global`); `ip.is_global` is False for the whole block on 3.11. Switching to `is_global`
  changes semantics for several Python versions and needs its own test.
- The wider constraint: a 100.64/10 blocklist entry only matters if the transport's TLS trust binding
  is correct. Repairing b1b#1 by moving `assert_hostname` to the pool is insufficient under
  `check_hostname=True`; the repair must either set `ssl_context.check_hostname = False` and rely on a
  live `assert_hostname`, or connect with an explicit SNI + hostname verifier. **Escaping the
  structure-breaking kwargs fault is not the same as preserving the hostname trust binding** — a
  repair that does the former can leave the transport unable to verify any certificate, or (if it
  turns verification off) widen every SSRF finding at once.
- Dedupe: the CGNAT entry and the redirect finding (hunt-d1#1 / b1b#4) both bite the same
  `_is_internal` contract; a single SSRF-boundary fix should cover both, and finding 5 should not be
  credited as a separate live SSRF.

## Checked and clean

- `_is_internal` flag set: `0.0.0.0/8`, `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`,
  `198.18/15`, `192.0.0.0/24` (Python flags most of it private/reserved), `240/4`,
  `255.255.255.255`, IPv6 ULA/loopback/link-local/IPv4-mapped — all rejected; verified in the venv.
- `validate_ip` private branch is unaffected by the CGNAT gap (it requires CIDR/suffix match).
- `_resolve_and_validate` runs `validate_ip` before any socket write; the policy decision is
  observable today — the finding is right that this part is not gated.
- `request()` rejects non-`https` input (`transport.py:115`), so no plain-http SSRF path exists
  inside finding 5's own mechanism.
- `config.py` default `mode="public"` and `render_default_config`; no shipped config enables private
  mode or lists a CGNAT CIDR.
- `tests/test_network_policy.py` covers loopback/private/link-local rejection, not CGNAT (a
  coverage gap, not a code defect) — noted, not reported.

## Enumeration

```
rg -n "100\.64|CGNAT|cgnat|is_global|shared address|6598" -i --type py --type md .
rg -n "validate_ip|_is_internal|NetworkPolicy" lattice/ --type py
.venv/bin/python -c "import ipaddress as i; [print(a,(i.ip_address(a).is_private,i.ip_address(a).is_reserved,i.ip_address(a).is_global)) for a in ['100.64.0.1','100.127.255.255','100.128.0.0','224.0.0.1']]"
```

| Instance | Disposition |
|---|---|
| `network_policy.py:54 _is_internal` (only caller `validate_ip:74`) | examined — CGNAT gap (claim's mechanism) confirmed; harm refuted (TLS), frequency latent |
| `network_policy.py:63 validate_ip` (only call site `transport.py:91`) | examined-clean for private mode; public branch accepts 100.64/10 |
| `transport.py:59 create_default_context()` + `:125` IP rewrite + `:132` kwargs | hostname-verification ineffectiveness → fix-direction constraint; kwargs fault KNOWN (b1b#1, not re-reported) |
| `resolution.py:48` well-known URL from attacker domain | the policy-decision trigger population; harm still needs TLS cert match |
| whole tree, `rg "100\.64|CGNAT" -i` | only the finding's own report text — no deployment/topology uses CGNAT (frequency latent) |
| `tests/test_network_policy.py` | no CGNAT case (coverage gap, not reportable) |

## Side discoveries

1. **urllib3 2.x `assert_hostname` is inert under `create_default_context()`** (connection.py:992-1012;
   consulted only when `check_hostname` is False). Priced: severity **H if a naive b1b#1 repair changes
   behaviour** (either the transport cannot verify any cert after a partial fix, or a fix that disables
   verification enables every SSRF finding); frequency — every outbound federation request once b1b#1
   is repaired; reachability — GATED behind b1b#1 (no connection today). Fix constraint: pair
   `assert_hostname` with `check_hostname=False`, or connect via SNI+hostname verifier. Not promoted to
   a finding because it is unreachable until b1b#1 is repaired.
2. **CGNAT is the sole unflagged non-global IP range** across IPv4 and IPv6 in this policy (see
   Additional mechanisms). Priced: severity **L** as a defence-in-depth gap (harm refuted), frequency
   environment-armed/latent, reachability — production policy decision only. This is the claim itself,
   priced down by my pass.

## Bound

- Could not exercise a live daemon: the known call-shape defect (b1b#1) blocks every real request, so
  the TLS-barrier refutation is derived by reading urllib3 2.7.0's verification path
  (`connection.py:760, 992-1012`) plus `create_default_context()` semantics, not by a completed
  handshake through the repo transport. The specific component that is therefore *unproven* is the
  **mechanism** of "TLS blocks an internal third-party cert" — traced by code-read, not
  empirically demonstrated end-to-end.
- Not reachable without live infrastructure: real cloud/CGNAT/Tailscale deployments' internal address
  plans; whether any real operator runs 100.64/10 internally (no in-tree evidence either way).
- Cross-interpreter: the CGNAT classification is confirmed only on the pinned Python 3.11.13; I did not
  test 3.13, where `ipaddress` private-range semantics are known to differ. The deployed interpreter is
  what the shipped `.venv`/`pyproject` select (3.11), so this does not change the verdict.
