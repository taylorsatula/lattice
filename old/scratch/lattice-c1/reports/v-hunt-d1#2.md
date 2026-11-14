# v-hunt-d1#2 — PRIMED VERIFIER: `private_suffixes` unanchored `endswith` (hunt-d1 finding 2)

Claim under test: hunt-d1#2, reported tier **M** — "`private_suffixes` match is unanchored
`endswith` (and the classmethod strips the operator's dot), so an attacker-registered lookalike
domain passes private-mode policy."

Verdict: **CONFIRMED** (severity M retained; frequency LATENT confirmed; one stated mechanism
component REFUTED — see below).

## Re-derived frame (from source, before reading the claim's own wording)

- `lattice/network_policy.py:82-84` (private branch of `validate_ip`):
  `hostname_lower = hostname.lower().rstrip(".")`; `in_suffix = any(hostname_lower.endswith(s)
  for s in self.private_suffixes)`; the guard is `if not in_cidr and not in_suffix: raise`. Suffix
  match alone is sufficient — no CIDR required, and when `in_suffix` is true the **IP is not
  constrained at all**.
- `lattice/network_policy.py:49-50` (`NetworkPolicy.private`): `private_suffixes=tuple(s.lower().strip(".") for s in suffixes)`.
- `lattice/runtime.py:203-208` — the **daemon** constructs `NetworkPolicy(mode=..., private_cidrs=tuple(config.network.private_cidrs), private_suffixes=tuple(config.network.private_suffixes), ...)` **directly**, bytes verbatim from config; it does **not** call `NetworkPolicy.private`.
- `lattice/config.py:115` — `self.private_suffixes: list[str] = data.get("private_suffixes", [])`, raw, unnormalized.
- Caller/trigger path re-derived end to end: `api.py:287 receive_message` → `runtime.verify_inbound_message` (`runtime.py:619`) → for an unknown sender domain returns `(domain, True)` **without verifying a signature** → `api.py:311 runtime.queue_domain_resolution(from_node_id)` → `runtime.py:895` adds to `_unresolved_domains` → `_resolve_pending_senders` (`runtime.py:903`) → `self._resolver.pin(domain)` → `resolution.py:41 resolve_with_ip` → `transport.request("GET", f"https://{domain}/.well-known/lattice")` → `_resolve_and_validate` → `validate_ip(ip, hostname)`. The cold-sender branch returns at `api.py:317` **before** the message rate limiter at `api.py:335`; the public route has no auth dependency.
- `NetworkPolicy.private()` call sites (`rg 'NetworkPolicy\.private|NetworkPolicy\('`): **only** `tests/test_network_policy.py` (lines 36/39/43/47/52). Production sites: `runtime.py:203` (direct) and `cli.py:576` (`NetworkPolicy.public()`).

## Findings (adjudication of the claim)

### Verdict on hunt-d1#2 — CONFIRMED, M, LATENT

- **Mechanism — CONFIRMED (traced, empirically).** With the daemon's construction path
  (`NetworkPolicy(mode='private', private_suffixes=('company.com',))`), `validate_ip`:
  - `93.184.216.34` + `notcompany.com` → **ALLOW**
  - `93.184.216.34` + `evilcompany.com` → **ALLOW**
  - `93.184.216.34` + `company.com.evil.net` → REJECT
  The lookalike tail-match is real and executes on the live daemon path (raw config, no classmethod).
- **Trigger — CONFIRMED.** Private mode with a bare (dotless) suffix + an unauthenticated
  `POST /lattice/v1/messages` whose `from_address` domain is a registrable tail-lookalike
  (`user@notcompany.com` for suffix `company.com`). The cold-sender branch queues the attacker
  domain and `_resolve_pending_senders` fetches it; `validate_ip` accepts it purely on the suffix.
  This is production-reachable (an operator action configures private mode; a network peer supplies
  the message).
- **Frequency — CONFIRMED as LATENT.** No default deployment uses private mode
  (`config.py:210` ships `mode = "public"`; `render_default_config` does not emit
  `private_suffixes`). Fires on first contact with an attacker lookalike in a private-mode
  deployment. Per the frequency rule this is LATENT; the claim states it as such and the cap of 2
  latent findings is respected. Not corrected.

### Sub-claim REFUTED

- **"the classmethod strips the operator's dot" as part of the production bypass — REFUTED
  (mechanism attribution).** `NetworkPolicy.private()` is called **only in tests**; the daemon
  builds the policy directly (`runtime.py:203`), so `s.lower().strip(".")` never executes in
  production. Consequently, on the live path a leading-dot suffix (`.company.com`) **is** anchored
  correctly — `"notcompany.com".endswith(".company.com")` is `False` — and the operator is
  protected. The finding's title/body present the strip-normalization as widening the live defect;
  it does not. The classmethod behavior is accurate only for a test-only path (and is the mirror
  of hunt-d1 finding 4's divergence, not part of finding 2's production mechanism). The production
  defect reduces cleanly to the unanchored `endswith` against a bare suffix.

### Not a severity change

Severity stays **M**. An over-read to check and reject: finding 2 does **not** grant internal SSRF.
Although `in_suffix` short-circuits the IP check entirely (so the attacker's domain may resolve to
loopback/link-local/RFC1918 and still be admitted — a stronger statement than the finding's "the
attacker's public IP"), the transport pins TLS to the *hostname, not the IP* (`assert_hostname=hostname`
at `transport.py:131`; `ssl.create_default_context()` at `transport.py:59`). An internal HTTPS service
will not present a certificate valid for the attacker's domain, so the handshake fails and no
internal pivot occurs; only the attacker's own cert-bearing server is reachable. The realized harm is
therefore the private-mode boundary admitting an external attacker host — M, not H.
(TLS completion is additionally GATED behind the known call-shape defect hunt-b1b#1; the policy
*decision* — `validate_ip` accepting the lookalike — executes today, before `_pool.urlopen`.)

## Additional mechanisms / earlier failure sites / new reachability (same trace)

- **Empty-suffix fail-open (added mechanism, latent).** `NetworkPolicy(mode='private', private_suffixes=('',))`
  → `"".endswith`/`hostname.endswith("")` is `True` for **every** hostname; empirically
  `validate_ip(8.8.8.8, "anything.evil")` → ALLOW. Config accepts `private_suffixes = [""]`
  (`config.py:118` only rejects an *empty list*, not an empty *element*). Via the classmethod,
  `suffixes=["."]` normalizes to `''` (`strip(".")`) and produces the same fail-open. Operator-config,
  latent; a fix must reject empty suffixes.
- **New reachability — gossip route.** The same fetch is reachable from the public gossip route:
  `topology.verify_candidate` → `_verify_against_well_known` (`topology.py:288`) fetches a
  candidate card's domain well-known, so an unauthenticated `POST /lattice/v1/gossip` card for
  `notcompany.com` also drives the lookalike fetch in private mode. Broadens the trigger population
  named in the claim (which already listed gossip) but does not change the verdict.
- **Earlier failure site: none.** `validate_ip` is the decisive statement; nothing upstream rejects
  the lookalike hostname (`addressing.parse_address` permits it; `hostname_allowed`'s result is
  discarded at `transport.py:75` and, in private mode, uses the same unanchored predicate).

## Fix-direction constraints

- Anchor at a DNS label boundary, not a raw tail: accept `host == s or host.endswith("." + s)`, in
  **both** `validate_ip` and `hostname_allowed`; the two predicates must stay identical.
- Normalize **consistently across both construction paths** — the daemon's direct construction
  (`runtime.py:203`) and `NetworkPolicy.private()` — else `validate_ip`/`hostname_allowed` (and
  tests vs. production) diverge. Stripping a leading dot in the classmethod removes the operator's
  anchor; the anchoring must be intrinsic, not delegated to a dot the operator may or may not write.
- Reject empty/whitespace/dot-only suffixes in `config.NetworkConfig` (and in
  `NetworkPolicy.__post_init__`), since the empty suffix fail-opens the whole policy.
- The fix must preserve the intended redundancy: with `private_suffixes` there is no CIDR check, so
  anchoring is the *only* thing standing between a lookalike domain and policy admission.

## Checked and clean

- `hostname_allowed` and `validate_ip` share the same unanchored predicate — internally consistent
  (no divergence between them); the ignored return at `transport.py:75` cannot widen access because
  `validate_ip` re-checks (`private mode` also requires cidr-or-suffix in `__post_init__`).
- `config.NetworkConfig` rejects an empty *list* in private mode but not empty *elements* (see
  added mechanism).
- The cold-sender branch genuinely precedes the rate limiter (`api.py:317` vs `:335`) and needs no
  signature; the queued resolver fetch is real (`runtime.py:903` → `resolution.py:48`).
- `NetworkPolicy.private()` is test-only; `cli.py:576` uses public mode; the daemon uses direct
  construction. Verified by composed `rg`.

## Enumeration

```
rg -n 'NetworkPolicy\.private|NetworkPolicy\(' lattice/ tests/      # call sites
rg -n 'private_suffixes|private_cidrs|queue_domain_resolution|_resolve_pending_senders' lattice/
```
| Instance | Disposition |
|---|---|
| `network_policy.py:83` `endswith` in `validate_ip` | defect → CONFIRMED (production) |
| `network_policy.py:94` `endswith` in `hostname_allowed` | same predicate; consistent, examined-clean as a second guard (result discarded) |
| `network_policy.py:50` `strip(".")` in `private()` | REFUTED for production — test-only path |
| `runtime.py:203` direct construction | live construction path; carries the raw bare suffix → defect reachable |
| `tests/test_network_policy.py:36/39/43/47/52` | test-only call sites of the classmethod |
| `cli.py:576` | public mode, unrelated |
| `config.py:115/118` | accepts empty string element → added fail-open mechanism |

## Bound

- Cannot reach the deployed operator population: whether any real private-mode deployment configures
  a bare, tail-lookalike-exploitable suffix is unverifiable from the tree — this is exactly why the
  frequency is LATENT, not DEMONSTRATED.
- Cannot reach provider/DNS behaviour: whether an attacker can register and serve a publicly-trusted
  cert for a chosen tail-lookalike domain is assumed (standard registrability), not verified live.
- All connection-completion evidence is bounded by the known call-shape defect (hunt-b1b#1): the
  policy decision was exercised, but no live daemon request completes today.
