# v-hunt-a2#3 — primed verifier, claim `hunt-a2#3`

Claim under test, from `scratch/lattice-c1/reports/hunt-a2.md` finding 3 (reported tier **L**):

> `lattice init` accepts `--domain`/`--public-base-url` values its own config validator rejects.

Adversarial and symmetric. Frame re-derived from source before checking the claim.

## Frame re-derivation (independent of claim phrasing)

- `_build_parser` (`lattice/cli.py:843–850`) declares `init.add_argument("--domain", required=True)`
  and `init.add_argument("--public-base-url", required=True)` with **no `type=`, no `choices=`, no
  validator** — both land in `argparse.Namespace` as raw `str`.
- `cmd_init` (`lattice/cli.py:93–206`) reads them at lines 99–100 as `domain: str = args.domain`,
  `public_base_url: str = args.public_base_url`. It never constructs `Config`, never calls
  `load_config`, never calls `_is_valid_domain`/`_is_https_url`. I read the function end to end
  (93–206); the only validation anywhere in the init path is `config_path.exists() and not
  args.force` (line 96).
- The validator that *would* reject the values lives in `lattice/config.py`: `Config.__init__`
  enforces `_is_valid_domain(node["domain"])` and `_is_https_url(server["public_base_url"])`.
- `render_default_config` (`lattice/config.py:181`) is a **plain f-string**:
  `domain = "{domain}"` / `public_base_url = "{public_base_url}"`, interpolated unescaped.
- Composed check (python3, `render_default_config` + `tomllib` + `Config`):

  | `--domain` | `--public-base-url` | rendered TOML | validator result |
  |---|---|---|---|
  | `example.com` | `example.com` | parses | `ConfigError: server.public_base_url is required and must be an https URL without credentials` |
  | `ex"ample.com` | `https://example.com` | **TOMLDecodeError** line 5 col 14 | unparseable — no `ConfigError` reached |
  | `Bad:Dom` | `https://ok.com` | parses | `ConfigError: node.domain is required and must be a valid domain` |
  | `a@b.com` | `https://ok.com` | parses | `ConfigError: node.domain is required and must be a valid domain` |

  `_is_valid_domain('ex"ample.com')` returns `True` (the predicate only rejects `:/@` and
  length), so the quote case is *not* caught by the domain predicate — it breaks TOML structure
  before any semantic check runs.

## Verdict — **CONFIRMED** (tier L, unchanged)

All three components verified against source:

- **Mechanism** — traced. `cmd_init` uses the two `argparse` strings verbatim; `render_default_config`
  f-string-interpolates them unescaped into `config.toml`; `Config`/`load_config` is the only place
  the predicates exist, and `cmd_init` never reaches it. Confirmed at `cli.py:99–100,157` and
  `config.py:181`.
- **Trigger** — traced, PRODUCTION. `docs/KEY_MANAGEMENT.md:19`, `docs/LATTICE_SYSTEMD.md:29`, and
  `README.md:21` document `lattice init --domain example.com --public-base-url https://example.com`
  as the operator's first-run procedure. A first-run operator who passes `--public-base-url
  example.com`, or a `--domain` containing `"`, `@`, `:`, or `/`, gets a **successful** init: root
  key generated, password accepted, `root_key.pem`, `operational_key.pem`, both bearers,
  `identity.json`, `well-known.json` (root-signed), and `config.toml` all written; return code 0.
  Nothing in the path validates or even re-reads the config it just wrote.
- **Outcome** — traced. The next reader (`lattice config`, `lattice status`, `lattice serve`,
  `lattice keys rotate-operational`) hits the invalid value. For the scheme/`:`/`@`/`/` classes it
  emits the clean `CONFIG INVALID: …` message (`cmd_config_check` 212–213, `cmd_serve` 644–645,
  `cmd_status` 256–257, rotate 804–805). `cmd_serve` then refuses to start, so the malformed
  root-signed `well-known.json` (endpoints `example.com/lattice/v1/gossip`) is not served until
  re-init. Bounded: single fresh node, no pre-existing state corrupted, but a root key and a signed
  public document are wasted and the node must be re-provisioned.

Severity stays **L**: bounded bad outcome, narrow (operator-error) trigger, no cross-peer/user
reach, no secret exposure.

## Sub-claims refuted / narrowed

1. **"`lattice config` reports `server.public_base_url …`"** holds only for the scheme/`:`/`@`/`/`
   triggers. It is **refuted for the quote trigger the claim itself lists**: a `"` in `--domain`
   yields an unparseable `config.toml`, so `load_config` raises `tomllib.TOMLDecodeError`, which is
   a `ValueError` but **not** `ConfigError`. The claim's stated outcome (a clean validator message)
   is wrong for that branch — the real outcome is an uncaught traceback (see added mechanism).
2. **"the node must be re-initialized with `--force`"** is slightly overstated. `cmd_init` produces
   *two* corrupt artifacts: an invalid `config.toml` **and** a root-signed `well-known.json` whose
   endpoints embed the bad base URL. Hand-editing `config.toml` alone repairs `lattice serve` but
   leaves the signed `well-known.json` malformed; the only in-tree command that regenerates
   `well-known.json` is `keys rotate-operational` (which rotates the key and needs the root
   password). So the practical remedy is re-init or manual file surgery — the claim's conclusion is
   right, its "must" is under-argued.
3. **Frequency "DEMONSTRATED"** — I leave it **unchanged**. The operation population is concrete
   (first-run `lattice init`, documented one per node), and the calibration explicitly admits
   operator-supplied-input triggers ("an operator who supplies a /?# password") as grounded. No
   correction.

## Additional mechanisms / earlier failure sites (same trace)

- **Uncaught `TOMLDecodeError` at every consumer.** `cmd_init` with a `"` in `--domain` writes a
  structurally invalid `config.toml`; all four `load_config` call sites catch **only**
  `ConfigError` (`cli.py:213, 257, 423, 645, 805`) and `main` (`cli.py:1002–1019`, except clause
  at 1011) catches only `CLIError`, `ConfigError`, `CredentialError`. Verified with python3:
  `load_config` raises `TOMLDecodeError`, `isinstance(e, ValueError)=True`,
  `type(e).__name__=='ConfigError'=False`. So `lattice config`/`status`/`serve`/rotate abort with a
  Python traceback on a config **their own sibling command `init` produced**. This is an earlier
  failure site than the claim's "clean message" outcome and is bounded (exit is still non-zero via
  the uncaught exception).
- **Early-failure site inside `init`:** the root key is generated (`cli.py:108`), the password is
  read and the root key is written (line 126) **before** the config string is even rendered
  (line 157). A validating fix placed after those writes would still leave a wasted root key; the
  fix must precede key generation.

## Fix-direction constraints

A repair must account for more than the reported symptom:

- Validate **both** `--domain` and `--public-base-url` against the *same* predicates
  `Config` uses (`_is_valid_domain`, `_is_https_url`) **before** generating keys / writing secrets —
  a check deferred to the end still burns a root key.
- **Escaping structure-breaking is not the same as validating semantics.** `_is_valid_domain`
  accepts `"` and whitespace (returns `True` for `ex"ample.com`), so the TOML must be emitted with a
  serializer (e.g., write the dict via a TOML writer, or `json`-style escaping of the string) rather
  than an f-string. Fixing only the semantic predicates leaves the unparseable-TOML branch open;
  fixing only the escaping leaves the config the validator rejects.
- Regardless of which check is added, `cmd_init` should round-trip its own output through
  `load_config(config_text)` before returning success — that closes both the semantic and the
  structural branch in one place.
- The consumers' `except ConfigError` handlers are a second defect surface: catching
  `(ConfigError, tomllib.TOMLDecodeError)` would convert the quote-branch traceback into a clean
  message. A fix that only guards `init` leaves any hand-edited/corrupt `config.toml` crashing the
  same four commands.

## Reachability kind

**PRODUCTION.** The trigger is a real operator command (`lattice init`, documented in three files),
not a test/mock and not gated behind another defect. The added `TOMLDecodeError` mechanism is
likewise production — reachable through `lattice config`/`status`/`serve`/`keys rotate-operational`
against a config `init` wrote.

## Checked and clean

- `_is_valid_domain` and `_is_https_url` in `lattice/config.py`: predicates are correct as written;
  the defect is that `cmd_init` never invokes them, not that they are wrong (they intentionally do
  not reject `"`, which is what makes the TOML-structure branch reachable).
- `cmd_serve`, `cmd_status`, `cmd_config_check`, `cmd_keys_rotate_operational`: all catch
  `ConfigError` correctly for the semantic branch; the gap is only the uncaught structural
  (`TOMLDecodeError`) branch.
- `tests/test_cli.py` `TestInit`: every test passes a **valid** `--domain`/`--public-base-url`
  (`test_cli.py:23–48`), so the test suite neither covers nor contradicts the finding — the defect
  is test-invisible by construction.
- No `type=`/`choices=`/custom `action=` on the two init args (`cli.py:843–850`) — verified by
  reading the parser block.

## Enumeration

Class: every place `init`'s raw args reach the validator, and every consumer that reads the
resulting config.

Command:

```
rg -n "args\.domain|args\.public_base_url|render_default_config" lattice/ ; \
rg -n "load_config\(|except ConfigError" lattice/
```

Output (dispositioned):

| Site | Disposition |
|---|---|
| `cli.py:99–100` `args.domain`, `args.public_base_url` | finding — raw, unvalidated |
| `cli.py:157` `render_default_config(domain, public_base_url)` | finding — unescaped interpolation |
| `cli.py:475` `args.domain.strip().lower()` (create-transfer) | examined-clean — `new_node_id`/`NODE_ID_RE` checked; separate path |
| `cli.py:440,444` `args.domain` (trust reset) | examined-clean — repository lowercases; no config write |
| `config.py:181` `render_default_config` | finding — f-string, no escaping |
| `cli.py:212–213, 256–257, 422–423, 644–645, 804–805` `load_config`/`except ConfigError` | finding (secondary) — structural `TOMLDecodeError` uncaught |

Four `load_config` consumers, all catch only `ConfigError`; one producer (`cmd_init`), no validator.

## Bound

- Did not execute `lattice init` (a state-changing command); the end-to-end outcome is derived by
  composing `render_default_config` + `tomllib` + `Config` in python3 and reading `cmd_init` 93–206
  line by line. The composition reproduces the exact rendered strings and the exact exception types,
  but a live run was not performed.
- `tomllib.TOMLDecodeError` inheritance confirmed at runtime (`ValueError` superclass, not
  `ConfigError`); this is a CPython 3.11+ property — on a different interpreter the TOML-breakage
  branch could surface a different exception type, but it would still escape the `ConfigError`
  handlers.
- Did not audit whether upstream Nginx/systemd or any deploy script pre-validate `--public-base-url`;
  `deploy/` and `docs/` were grepped for the init invocation only. If a wrapper validated before
  calling `init`, the production trigger would narrow to direct CLI use — I did not find such a
  wrapper.
