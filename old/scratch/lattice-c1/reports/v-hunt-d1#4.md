# v-hunt-d1#4 — primed verifier

Claim under test: **hunt-d1#4** (`scratch/lattice-c1/reports/hunt-d1.md`, reported tier **L**) —
*"runtime constructs `NetworkPolicy` directly, skipping the classmethod's suffix normalization:
uppercase or apex-form configured suffixes never match, rejecting all internal hosts."*

## Verdict: ADJUSTED

Mechanism **confirmed** for uppercase and (newly found) trailing-dot suffixes. The **leading-dot
("apex-form") half of the claim is refuted**: a leading-dot suffix matches subdomains and only fails
to match the bare apex, so it does **not** reject all internal hosts and is not fail-closed like the
uppercase case. Severity stays **L**; frequency stays **LATENT**.

### Frame re-derived from source (not from the claim)

- `lattice/runtime.py:203-208` — daemon constructs
  `NetworkPolicy(mode=config.network.mode, private_cidrs=tuple(config.network.private_cidrs),
  private_suffixes=tuple(config.network.private_suffixes), private_ca_path=...)`. No normalization.
- `lattice/config.py:115` — `self.private_suffixes: list[str] = data.get("private_suffixes", [])`;
  no format validation anywhere in `NetworkConfig`.
- `lattice/network_policy.py:30-34` — `__post_init__` validates mode and requires cidrs-or-suffixes
  only; it does **not** normalize `private_suffixes`.
- `lattice/network_policy.py:82-83` — private branch:
  `hostname_lower = hostname.lower().rstrip(".")`; `in_suffix = any(hostname_lower.endswith(s) ...)`.
  Comparison is case-sensitive against the raw configured string.
- `lattice/network_policy.py:50` — the classmethod normalizes: `tuple(s.lower().strip(".") for s in suffixes)`.
- Callers: `NetworkPolicy.private()` is used **only** by tests (`test_network_policy.py`) and
  `cli.py:576` (public mode). The production daemon is the **only** private-mode constructor, and it
  bypasses normalization. So the classmethod is effectively dead for production.

### Direct evidence (real `NetworkPolicy` class imported from the tree)

Constructed exactly as `runtime.py:203` does (raw suffix) vs. the classmethod, then `validate_ip`:

```
raw='Corp.Example'   daemon: corp.example REJECT / host.corp.example REJECT   classm: both ALLOW
raw='.corp.example'  daemon: corp.example REJECT / host.corp.example ALLOW    classm: both ALLOW
raw='corp.example.'  daemon: corp.example REJECT / host.corp.example REJECT   classm: both ALLOW
raw='corp.example'   daemon: both ALLOW                                       classm: both ALLOW
```

### Component verdicts

- **Mechanism — CONFIRMED (uppercase / trailing dot).** Case-sensitive `endswith` against a
  lowercased hostname means `"Corp.Example"` can never match any hostname; `"corp.example."` can never
  match because the hostname is `rstrip(".")`-ed while the suffix is not. Fail-closed: every
  `validate_ip` in private mode raises. The daemon and the classmethod genuinely diverge.
- **Mechanism — REFUTED (leading dot).** `".corp.example".endswith` against `host.corp.example` /
  `sub.host.corp.example` returns **True**. The hunter's evidence sentence "*`.corp.example` from
  config … can never match*" is false. Only the bare apex `corp.example` fails. So the claim's
  "rejecting all internal hosts" overstates: internal peers addressed as subdomains still resolve.
  A leading-dot suffix is in fact *more* anchored in the daemon path (subdomains only) than in the
  classmethod (apex + subdomains); the daemon's behaviour is defensible, not broken.
- **Trigger — CONFIRMED but narrower than claimed.** Requires `[network] mode = "private"` with
  `private_suffixes` containing an uppercase letter or a trailing dot, **and** no `private_cidrs`
  that already cover the peer hosts. A leading-dot suffix does not produce the claimed outage.
- **Frequency — CONFIRMED LATENT.** Default rendered config ships `mode = "public"` with no suffixes
  (`config.py:185-214`); no in-tree deployment uses private mode. Operator-configuration-dependent
  population, ungroundable in-tree → LATENT by the frequency rule. The claim states this correctly.
- **Severity — L unchanged.** Fail-closed self-inflicted outage in a non-default mode with a narrow
  config trigger; bounded bad outcome (availability, not confidentiality/integrity). Latent
  frequency caps at L under the standing rule. No basis to raise to M or drop below L.
- **Reachability kind — PRODUCTION (operator action at deploy), frequency LATENT.** The trigger is a
  real operator config write, not the test suite; nothing in tests constructs private-mode policies
  through the daemon path, so the divergence is untested.

## Refuted sub-claims (named individually)

1. *"`.corp.example` … can never match"* (evidence line 4 of hunt-d1#4) — **refuted**: it matches
   subdomain hostnames; only the bare apex fails.
2. *"apex-form configured suffixes … rejecting all internal hosts"* — **refuted as a total outage**:
   in the leading-dot case internal peers addressed as subdomains are still accepted; the outage
   exists only for uppercase and trailing-dot suffixes, and only for hosts not matched by a CIDR.

## Additional mechanisms / earlier sites (same defect class)

- **Trailing-dot suffix `"corp.example."` never matches** in the daemon path, because `validate_ip`
  rstrips the hostname's dot but not the suffix's; the classmethod's `strip(".")` handles it. Same
  missing-normalization defect, an input the claim did not name — strengthens the mechanism while
  confirming the defect is the missing normalization, not the specific uppercase case.
- **`NetworkConfig` performs no validation on `private_suffixes`** (`config.py:115`), so any
  malformed string is accepted and silently fail-closes at first resolution.

## Fix-direction constraints

- The repair must normalize **at construction** (`NetworkPolicy.__post_init__` or `NetworkConfig`),
  not only inside `NetworkPolicy.private`, because the classmethod is not on the production path.
  Editing the classmethod alone leaves the daemon broken.
- Coordinate with **hunt-d1#2** (unanchored `endswith`): the *same* line — `s.lower().strip(".")` —
  is what makes the classmethod's suffix match unanchored. A fix that normalizes uppercase by
  continuing to strip dots preserves the lookalike-domain acceptance (finding 2). One shared
  normalization must decide anchor semantics (reject a leading dot, or keep it and anchor) rather
  than lower-casing in one path and stripping in another.
- Public mode and the fail-closed rejection of genuinely out-of-policy hosts must be preserved.

## Checked and clean

- `NetworkPolicy.__post_init__` normalization absence — verified by reading, not by assumption.
- `config.NetworkConfig` raw read with no `__post_init__`/lower-casing — enumerated via
  `rg -n 'private_suffixes|lower\(\)|strip|rstrip|__post_init__' lattice/{config,runtime,network_policy}.py`;
  the only normalization in the tree is `network_policy.py:50`.
- Only production constructor of a private-mode policy is `runtime.py:203`; the classmethod is
  test/CLI-only (public for CLI) — verified by the composed caller enumeration.
- Tests construct policies exclusively via `NetworkPolicy.private()` with a lowercase undotted
  suffix (`test_network_policy.py:43-52`; `test_config.py:67`), so neither the divergence nor the
  uppercase/trailing-dot inputs are covered.

## Enumeration

```
rg -n 'validate_ip|hostname_allowed|_is_internal|NetworkPolicy\(|NetworkPolicy\.' lattice/ --type py
rg -n 'private_suffixes|lower\(\)|strip\("\."\)|rstrip\("\."\)|__post_init__' lattice/{config,runtime,network_policy}.py
rg -n 'NetworkPolicy\b|NetworkPolicy\.' --type py lattice/ tests/
```

| Instance | Disposition |
|---|---|
| `network_policy.py:50 NetworkPolicy.private` (`s.lower().strip(".")`) | normalization exists here only; not on production path → finding mechanism |
| `network_policy.py:30 __post_init__` | examined-clean for its own checks; does **not** normalize → finding |
| `network_policy.py:82-83 validate_ip` | raw-suffix comparison → finding |
| `config.py:115 NetworkConfig.private_suffixes` | raw read, no validation → added mechanism |
| `runtime.py:203-208 NetworkPolicy(...)` | direct construction skips normalization → finding location |
| `cli.py:576 NetworkPolicy.public()` | examined-clean — public mode, normalization irrelevant |
| `tests/test_network_policy.py:43-52` | test-only classmethod path; divergence untested → coverage gap |

## Bound

- No live private-mode deployment exists in-tree; the affected operator population is ungroundable,
  hence LATENT frequency. This is a population boundary, not a mechanism gap.
- Did not stand up the full `Runtime` (needs DB/identity/credentials); instead invoked the real
  `NetworkPolicy` class with the exact construction call shape from `runtime.py:203`. The construction
  call is a straight tuple pass-through, so this is equivalent to the production path for this defect.
- Git history for `network_policy.py` is unavailable in this checkout (`git log -S` returns nothing),
  so I cannot say whether the classmethod normalization predates or postdates the daemon constructor.
- `hostname_allowed` (`network_policy.py:94`) shares the raw-suffix comparison, but its only call site
  (`transport.py:75`) ignores the return, so it has no independent impact — no separate finding.
