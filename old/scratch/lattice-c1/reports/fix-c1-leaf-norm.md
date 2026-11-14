# Fix report — C1 rows LEAF (aefa) + NORM (zkm1)

Executor: swarm-executor (network_policy.py + config.py seam). Status: EXECUTED.

## Files / functions changed

- `lattice/network_policy.py`
  - `NetworkPolicy.__post_init__` — +9/-1: normalize every suffix (`s.strip().lower().strip(".")`),
    reject empty/whitespace/dot-only entries with `NetworkPolicyError`, store the normalized tuple
    via `object.__setattr__` (frozen dataclass). Production path now enforces the rule the
    `private` classmethod only pretended to enforce.
  - `NetworkPolicy.validate_ip` — +2/-1: suffix match anchored at a DNS label boundary
    (`hostname_lower == s or hostname_lower.endswith("." + s)`), replacing bare `endswith(s)`.
  - `NetworkPolicy.hostname_allowed` — +2/-1: identical anchoring; predicates remain identical.
  - `NetworkPolicy.private` (classmethod): not touched — its normalization is now redundant but
    harmless; its output passes through the normalizing `__post_init__`.
- `lattice/config.py`
  - `NetworkConfig.__init__` (private_suffixes block, ~line 115) — +8/-1: same normalization +
    rejection as `ConfigError`, plus an `isinstance(text, str)` guard (same-hazard extension inside
    the named region: a `None`/non-string entry previously crashed with an opaque
    `AttributeError` in the new loop; now a clean `ConfigError`). Config and daemon paths agree
    because runtime.py:203 passes `config.network.private_suffixes` straight into `NetworkPolicy`,
    whose `__post_init__` re-normalizes and would catch anything config missed (double-anchored at
    the seam; both sides are in this executor's scope).

Anchor semantics for leading dots (NORM decision): **retain and anchor** — `.corp.example`,
`Corp.Example`, `corp.example.`, and padded variants all normalize to `corp.example` and match the
apex and subdomains identically (matches the sibling exemplar's `.strip(".")` rule). Exemplar:
`network_policy.py:NetworkPolicy.private`.

Insertion/deletion counts: network_policy.py +13/-3 (net), config.py +8/-1 (net), per `git diff`
unavailable (files untracked in this tree); counts from manual review of the two hunks.

## Verification — EXECUTED

Repo venv, real imports, no mocks, no test files, every probe under `timeout 30`.

Probe (a) LEAF — `timeout 30 .venv/bin/python` inline script; policy
`NetworkPolicy(mode="private", private_suffixes=("company.com",))`, hostile IP 127.0.0.1:

```
notcompany.com   validate_ip=REJECT hostname_allowed=False
company.com      validate_ip=ADMIT  hostname_allowed=True
a.company.com    validate_ip=ADMIT  hostname_allowed=True
NotCompany.com/x.notcompany.com/evil.example -> REJECT
company.com. (trailing dot on host) -> ADMIT (rstrip preserved)
```

Probe (b) NORM — direct construction (the runtime.py:203 shape) with `Corp.Example`, trailing-dot,
leading-dot, padded, and classmethod variants: all stored `('corp.example',)` and produced
identical allow/reject vectors to the lowercased baseline across
`corp.example / a.corp.example / notcorp.example / other.example` (MATCH on all five). Through
`NetworkConfig({"private_suffixes": ["Corp.Example.", "  .company.com  "]})` the daemon-shaped
construction matched apex + subdomains for both suffixes and rejected `notcorp.example`.

Probe (c) fail-closed + guards — empty `""`, whitespace `"   "`, dot-only `"."`/`".."`/`" . "`
all rejected at construction (`NetworkPolicyError` / `ConfigError`); `evil.example/8.8.8.8` and
`notcompany.com/127.0.0.1` still REJECT; public mode unchanged (loopback still rejected,
`hostname_allowed` still True for any host). Note: `'corp.example..'` is correctly accepted — it
normalizes to the valid `corp.example` (my probe's "FAIL-OPEN BUG" label there was wrong; only
dot-ONLY entries are invalid).

Floor: `py_compile` clean, `ruff check` clean, `ruff format --check` clean on both files.
No fixtures created, no residue, no commits. runtime.py untouched, per assignment.

## Found but not touched

- `NetworkPolicy.validate_ip` in private mode still admits a suffix-matched host that resolves to
  an arbitrary IP (the CIDR check is an OR, not an AND). The LEAF row's text mentions this as
  severity context, but its HOW binds the fix to label-boundary anchoring only; changing the
  CIDR/suffix composition would widen the repair. Flagging for the orchestrator.
- Pre-existing tree state: many deletions and untracked lattice/ files (not mine; untouched).
