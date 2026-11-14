# v-hunt-d2#3 — PRIMED VERIFIER report

Claim under test: **hunt-d2.md finding 3** [L] — "a syntactically invalid TOML config escapes
`except ConfigError` in both `cmd_serve` and `lattice config`."

Method: frame re-derived from source before reading the claim's conclusion. Read
`lattice/config.py` end to end (214 lines); read the five `load_config` call sites and every
`except` in `lattice/cli.py` (lines 209-260, 410-430, 638-700, 795-830, 1000-1020); verified
the exception MRO and reproduced the failure through the real CLI. All live runs used `.venv`
Python 3.11.13 with the **unmodified** repo code; scratch configs were written to `/tmp`; no repo
file was touched.

## Verdict

**CONFIRMED.** Mechanism, trigger, and outcome all re-derived and reproduced. Tier **L**
(unchanged). Reachability kind: **PRODUCTION** (operator action / systemd start), not tests-only,
not gated.

## Re-derived frame (from source, not the claim)

- `lattice/config.py:171 load_config` → open file → `tomllib.load(f)` (`:177`) → `Config(data)`
  (`:178`). No `try/except` anywhere in the function. `tomllib` raises `TOMLDecodeError`.
- `lattice/config.py:14 class ConfigError(ValueError)`. The claim's key structural fact:
  `ConfigError` is a **sibling** of `ValueError`, not its base. `tomllib.TOMLDecodeError` is a
  `ValueError` (MRO verified: `TOMLDecodeError → ValueError → Exception → BaseException`), so
  `except ConfigError` does **not** catch it. `issubclass(tomllib.TOMLDecodeError, ConfigError)`
  → `False` (verified live).
- Every `load_config` caller catches `ConfigError` only: `cli.py:212` (`cmd_config_check`),
  `:256` (`cmd_status`), `:422` (`cmd_trust_reset_domain`), `:644` (`cmd_serve`), `:804`
  (`cmd_keys_rotate_operational`). `main()` (`cli.py:1002`) catches
  `(CLIError, ConfigError, CredentialError)` plus `KeyboardInterrupt` — no bare `ValueError`,
  no bare `Exception`. So the exception escapes the entire CLI and reaches the interpreter as an
  unhandled traceback.

## Empirical reproduction

Composed command (build a malformed config in /tmp, run the real CLI):

```
printf '[node]\ndomain = "x.example"\nserver = \n' > /tmp/badcfg.toml
.venv/bin/python -m lattice.cli --config /tmp/badcfg.toml config
```

Output: full traceback ending
`tomllib.TOMLDecodeError: Invalid value (at line 3, column 10)`; `EXIT=1`. The designed
`CONFIG INVALID: <reason>` message on stderr was not printed. Same handler shape at
`cmd_serve` (`cli.py:644-647`), so a `lattice serve` (the systemd `ExecStart`,
`deploy/lattice.service:26`) hits the identical escape at daemon start.

## Component disposition

1. **Mechanism — CONFIRMED.** `load_config` does not wrap `tomllib.load`; `except ConfigError`
   cannot catch a `ValueError` sibling. Live-verified MRO and live-reproduced traceback.
2. **Trigger — CONFIRMED.** Any config file containing a TOML syntax error (missing value,
   unterminated string, truncated line), on `lattice config`, any other `load_config` command,
   or `lattice serve`. No adversary, no coincidence, no race — deterministic given the input.
3. **Outcome — CONFIRMED.** Unhandled traceback instead of `CONFIG INVALID`; process exits 1
   either way (fail-closed preserved). Bounded bad outcome.
4. **Frequency — CONFIRMED as reported (DEMONSTRATED), with a scope correction.** The claimed
   population ("every config edit during setup or reconfiguration") is imprecise — a syntax slip
   is required, not every edit — but the population that *produces* the trigger is exactly the
   operation the tool exists for: validating/reloading a config. The added mechanism below widens
   this further (a syntactically *valid* config with a wrong-typed value also triggers). The rate
   is not measurable from the tree, but the trigger is a deterministic response to a routine
   operator action, not a coincidence; I leave the label DEMONSTRATED and the tier at L.

## Severity correction

**L — unchanged.** The pinned L definition explicitly covers "an error path that misreports"
and "a misreported error code". Exit status stays 1, no state is written, no lock is held, no
secret is surfaced (the TOMLDecodeError message carries a position, not file content). It is not
M: no wrong state, wrong custody semantics, lost queue item, or divergent-path pair is produced.
It is not S-: traced and live-reproduced on all four components.

## Frequency correction

**Unchanged (DEMONSTRATED).** Scope note only: the population is "config-validation /
config-reload attempts", not every edit; the trigger is the error class the command is built to
report, and the added type-mismatch mechanism (below) makes it broader than the claim's
syntax-only framing. No per-deployment rate is groundable from the tree; this does not change the
tier (L either way).

## Sub-claims refuted / narrowed

- **"the dead `isinstance` branch" (finding 2's framing)** — not at issue here; not part of
  finding 3.
- **None of finding 3's components refuted.** The one imprecision is the population phrasing
  ("every config edit"), corrected above; it does not affect mechanism, trigger, or tier.
- Location lines are accurate: `config.py:171 load_config`, `cli.py:209 cmd_config_check`,
  `cli.py:638 cmd_serve`.

## Additional mechanisms / earlier failure site / new reachability (same trace)

- **The escape class is broader than TOML syntax (added mechanism, live-verified).**
  `Config.__init__` coerces values and indexes subsections with no guard, so errors that are
  *not* `ConfigError` escape the same handlers. Verified live through the real CLI with a
  syntactically **valid** config:

  | Malformed-but-valid TOML | Exception that escapes |
  |---|---|
  | `[server] bind_port = "abc"` | `ValueError: invalid literal for int()...` |
  | `[server] workers = "x"` | `ValueError` |
  | `[gossip] guard_slots = "x"` | `ValueError` |
  | `[rate_limit] messages_per_minute = "x"` | `ValueError: could not convert string to float` |
  | `node = 5` (non-table) | `AttributeError: 'int' object has no attribute 'get'` |
  | `server = 5` / `gossip = 5` / `network = 5` | `AttributeError` |
  | `bootstrap = 5` | `TypeError: 'int' object is not iterable` |
  | `bootstrap = [5]` | `AttributeError: 'int' object has no attribute 'startswith'` |
  | `network.private_cidrs = 5` | `TypeError: 'int' object is not iterable` |
  | `message.default_ttl_seconds = "x"` | `ValueError` |

  So the trigger population is not just "a syntax typo" but "any schema-type mismatch"—including
  the common operator mistake of quoting a number. Same root cause (`load_config` normalizes
  nothing; callers catch `ConfigError` only), same outcome, same tier.
- **Earlier failure site / boundary where the fix belongs:** `lattice/config.py:171 load_config`
  is the single choke point through which all five call sites route; the module already knows the
  normalization pattern (`config.py:42-46` wraps `ipaddress`'s `ValueError` into `ConfigError` for
  CIDRs) but does not apply it to `tomllib.load` or to the `int()`/`float()` coercions.
- **Same handler-escape class in the daemon** (already a side discovery in hunt-d2, confirmed
  here): `cmd_serve` parses `identity.json` (`cli.py:653`) and `well-known.json` (`cli.py:662`)
  with bare `json.loads`; `json.JSONDecodeError` is a `ValueError` and likewise escapes the
  `main()` handlers. Related class, not part of finding 3.

## Fix-direction constraints

1. A fix that catches only `tomllib.TOMLDecodeError` is **insufficient**: the `int()`/`float()`
   `ValueError` and the structural `AttributeError`/`TypeError` sites escape the same handlers.
   Normalize at the `load_config` boundary (wrap `tomllib.load` **and** `Config(...)` construction,
   re-raising `ConfigError`) so all five call sites and `main()` are covered at once.
2. Do **not** solve it by adding a bare `except ValueError` in the CLI handlers: `ConfigError`
   *is* a `ValueError`, so the message text would still be mostly right, but config parsing bugs
   would be masked as user-input errors. The targeted wrap preserves the distinction.
3. Whatever is caught must still fail closed (non-zero exit). The current exit status is already
   correct; the repair is about the diagnostic, and must not weaken the "missing file → fail
   closed" behavior already in `load_config`.
4. If the wrap is added inside `load_config`, keep `ConfigError` as the public type so the tests
   asserting `pytest.raises(ConfigError)` (`tests/test_config.py:29,39,49,59`) continue to hold.

## Checked and clean (coverage)

- `ConfigError` is a strict `ValueError` subclass; `TOMLDecodeError` is a `ValueError` sibling —
  verified by MRO and `issubclass`.
- All five `load_config` call sites catch `ConfigError` only; `main()` catches
  `(CLIError, ConfigError, CredentialError)` and `KeyboardInterrupt` only — enumerated by `rg`,
  no broader handler exists.
- Live reproduction on the real CLI (`lattice config`) of both the TOML-syntax case and the
  type-mismatch case; both produce tracebacks with exit 1.
- `load_config` wraps nothing; the only existing normalization is `_parse_cidr`
  (`config.py:42-46`), correct.
- Exit status remains non-zero in every reproduced case (bounded outcome).

## Enumeration

```
rg -n "def load_config|tomllib.load|def cmd_config_check|def cmd_serve|CONFIG INVALID" lattice/config.py lattice/cli.py
rg -n "load_config\(" lattice/ tests/
rg -n "except ValueError|except Exception|except \(.*ValueError" lattice/cli.py lattice/config.py
```

| Instance | Disposition |
|---|---|
| `config.py:177 tomllib.load` (unwrapped) | finding 3 — escapes ConfigError handler |
| `config.py:133, 128, 125, 130, 132, 156` int()/float() coercions (unwrapped) | added mechanism — same escape class |
| `config.py:113, 132...` `data.get(...)`/subsection indexing (unwrapped) | added mechanism — AttributeError/TypeError escape |
| `cli.py:212, 256, 422, 644, 804 except ConfigError` | the handlers that miss the class — all five |
| `cli.py:1011 except (ConfigError, CredentialError)` | `main()` handler, also misses the class |
| `config.py:42-46 _parse_cidr except ValueError` | examined-clean — the correct normalization pattern |
| `tests/test_config.py` | no test covers syntax/type escape (tests-only coverage gap, not a finding) |

## Bound

- No live systemd unit was run: the `ExecStart=... lattice serve` traceback/journal behavior is
  reasoned from `deploy/lattice.service:26` and reproduced only via the CLI, not under a real
  `systemd` journal capture.
- The per-deployment rate of operator config typos is not measurable from the tree; frequency is
  grounded as a population and a deterministic trigger, not as an observed count.
- Enumeration is identifier/literal-based `rg`. A differently-shaped handler or an indirect
  `load_config` wrapper would not match (none exists in tree).
