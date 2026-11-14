# hunt-d2 — credentials & configuration (blind hunter)

Assigned: `lattice/credentials.py` end to end; `lattice/config.py` with focus on the daemon
root-key invariant; E3 enumeration of `os.environ`/`open(` and key-material reads into the
serving process. `lattice/cli.py` was read end to end (all 1022 lines) as the sole consumer of
the credentials module, plus the credential-consuming surface of `lattice/crypto.py`,
`lattice/api.py`, `lattice/runtime.py`, `lattice/webhook.py`.

## Findings

1. [L] — `webhook.bearer_credential_name` is validated by the config schema but silently ignored by daemon credential loading
- Location: `lattice/config.py:WebhookConfig.__init__` vs `lattice/cli.py:cmd_serve`
- Evidence: config.py:85 `self.bearer_credential_name: str = data.get("bearer_credential_name", "webhook_bearer")` — but cmd_serve (cli.py:666) hardcodes `webhook_bearer = load_webhook_bearer(path=_credential_path("webhook_bearer", config_dir))`. A repo-wide grep for `bearer_credential_name` matches only `config.py`, `render_default_config`, and test fixtures: no runtime consumer exists.
- Trigger: an operator sets `[webhook] bearer_credential_name = "my_token"` in config.toml (the field is parsed, documented in the rendered default config, and never rejected), provisions the systemd credential under that name via `LoadCredential=`, and runs `lattice serve`. Reachability: PRODUCTION (operator action at deployment).
- Frequency: LATENT — the only trigger population is operators who customize this documented field; `init` and the docs always use `webhook_bearer`, so no groundable cadence. Mechanism and trigger are traced; frequency is the ungrounded component.
- Outcome: the daemon looks up `webhook_bearer` instead of the configured name. Under systemd it fails closed with `CREDENTIAL ERROR: credential file not found: .../webhook_bearer` — naming the wrong credential; in the non-systemd fallback it scans `config_dir` for `webhook_bearer{,.pem,.txt}` and misses. Divergence between the config schema and the loading path that must agree with it; bounded bad outcome (clean startup failure with a misleading message).
- Confidence: traced (mechanism and trigger); frequency ungrounded → capped at L.

2. [L] — malformed credential files raise exceptions that escape `CredentialError` handling; daemon exits with a raw traceback
- Location: `lattice/credentials.py:load_operational_key` / `load_webhook_bearer` / `load_admin_bearer`; root cause in `lattice/crypto.py:load_private_key`; uncaught in `lattice/cli.py:cmd_serve` and `main`
- Evidence: credentials.py:51-53 calls `load_private_key(data, password=password)` — crypto.py raises `TypeError("private key is not Ed25519")` for a non-Ed25519 PEM and `TypeError("Password was not given but private key is encrypted")` for an encrypted PEM, so the subsequent `if not isinstance(key, Ed25519PrivateKey): raise CredentialError(...)` branch in `load_operational_key` is dead code for the type case — clear evidence the author intended `CredentialError`. Bearers do `data.decode("utf-8").strip()` which raises `UnicodeDecodeError` on non-UTF-8 bytes. cmd_serve catches only `except CredentialError`; `main()` catches only `CLIError/ConfigError/CredentialError/KeyboardInterrupt`. Verified live: RSA PEM → `TypeError`; encrypted Ed25519 PEM → `TypeError`; `b"\xff\xfe garbage"` bearer → `UnicodeDecodeError`, all escaping the handlers.
- Trigger: a mis-staged credential at daemon start — the operator encrypts the wrong PEM (e.g. an RSA key) as `operational_key`, stages a password-protected PEM, or a bearer file that is not valid UTF-8. Reachability: PRODUCTION (deployment/staging step); no adversary needed.
- Frequency: LATENT — requires a misconfigured deployment; a correct `init` + systemd-creds flow never produces these bytes. Mechanism traced and live-verified; frequency is the ungrounded component.
- Outcome: the process still exits non-zero (fail-closed preserved) but with an unhandled traceback instead of the intended `CREDENTIAL ERROR: <reason>` message; the dead `isinstance` branch means the intended clean failure path can never fire for key-type mismatches.
- Confidence: traced and live-verified (mechanism, trigger); frequency ungrounded → capped at L.

3. [L] — a syntactically invalid TOML config escapes `except ConfigError` in both `cmd_serve` and `lattice config`
- Location: `lattice/config.py:load_config` (tomllib raises `TOMLDecodeError`); uncaught in `lattice/cli.py:cmd_config_check` and `lattice/cli.py:cmd_serve`
- Evidence: load_config calls `tomllib.load(f)`; `tomllib.TOMLDecodeError` is a `ValueError` sibling, NOT a subclass of `class ConfigError(ValueError)`. cmd_config_check wraps `load_config(args.config)` in `except ConfigError` only, and cmd_serve does the same before printing `CONFIG INVALID`. Verified live: a config with a trailing `server = ` fragment raises `TOMLDecodeError` (MRO: `ValueError`, not `ConfigError`) and escapes the handler.
- Trigger: any operator config edit containing a TOML syntax error (missing quote, truncated line), then `lattice config --config <path>` or a daemon restart. Reachability: PRODUCTION (plain operator typo).
- Frequency: DEMONSTRATED — the population is every config edit during setup or reconfiguration; a single syntax slip in any edit produces the trigger. No coincidence required.
- Outcome: instead of the designed `CONFIG INVALID: <reason>` message and clean exit, both the checker and the daemon abort with a raw traceback. Exit code is still 1, so the failure is bounded: a misreported error path, not a wrong-state fault.
- Confidence: traced and live-verified on all three components (mechanism, trigger, frequency).

## Checked and clean

- **No-root-key-in-daemon invariant (invariant 2) — holds.** `cmd_serve` loads exactly the operational private key, `webhook_bearer`, `admin_bearer`, and the root PUBLIC key from `identity.json`. `load_root_key`/`save_root_key` are called only from offline CLI commands (`cmd_init`, `cmd_keys_create_transfer`, `cmd_keys_cosign_transfer`, `cmd_keys_rotate_operational`) and tests — all intended per the invariant. `RuntimeCoordinator` receives `root_public_key` only; no serving-path module imports or invokes `load_root_key`.
- **`_credential_path` resolution (cli.py:627-637)**: `$CREDENTIALS_DIRECTORY` (set by systemd for both `LoadCredential=` and `LoadCredentialEncrypted=`, which decrypts in-flight) takes precedence; when set, a missing credential fails closed via `CredentialError`. The plaintext-staging fallback is limited to `name{,.pem,.txt}` in the config dir and cannot resolve to `root_key.pem` for any of the three daemon credentials. The documented init flow (`systemd-creds encrypt` then delete staging files) is consistent with this.
- **Credential file reads**: `_read_credential_file` exists-check then `read_bytes()` — a TOCTOU/symlink window exists but the directories involved (`$CREDENTIALS_DIRECTORY` on root-owned tmpfs, operator-owned config dir) have no hostile writer in the threat model; not reportable per preamble.
- **Bearer secret lifetime**: bearers are held in `RuntimeCoordinator` memory for auth and webhook Authorization headers only; `api.py:201` compares the admin bearer with `secrets.compare_digest`. No export, logging, or write path for the bearers or the operational key in the serving process.
- **config.py fail-closed defaults**: domain required and character-checked; `public_base_url` required https-no-userinfo; `webhook.url` required; private network mode requires cidrs or suffixes; `default_ttl_seconds` bounded by `MAX_TTL_SECONDS`; rate limits and candidate TTL must be positive; guard/discovery slots non-negative; `load_config` fails closed on a missing file. (Caveat: URL/domain checks are shallow — see design risks.)
- **`DEFAULT_CREDENTIAL_DIR`** (`/run/credentials/lattice.service`) is a dead default — no caller in tree passes `path=None` to `load_credential` (all go through `_credential_path`). No impact today.
- **`load_private_key` PEM→DER fallback and password handling** for the CLI root-key path: wrong password on an encrypted PEM raises `ValueError` from both loaders; `_read_password` rejects empty passwords; `_confirm_password` enforces confirmation. Consistent with the offline CLI's error handling via `main()`'s `CLIError` catch (which does catch the raw `ValueError` path only if wrapped — note `load_root_key` propagates `ValueError`-family crypto errors unwrapped into a traceback; same error-class as finding 2 but on the offline CLI where a traceback at a password prompt is cosmetic; not separately reported).
- **Webhook delivery target** (`runtime.py:1057`) is `config.webhook.url` only — no peer-controlled field reaches the webhook URL or bearer selection.

## Enumeration

Composed command (E3 — every env-var / file-read / key-material site in the package):

```
rg -n "os\.environ|open\(|read_bytes\(|read_text\(|load_credential|\.pem|root_key" lattice/*.py
```

Instance table (key-material focus; `transport.py:132` / `webhook.py:91` are `urlopen` network calls, not file reads; `runtime.py` `*_circuit_is_open` hits are name collisions, no I/O):

| Site | Serving process? | Disposition |
|---|---|---|
| cli.py:628 `os.environ.get("CREDENTIALS_DIRECTORY")` | yes (serve) | examined-clean — precedence + fail-closed |
| config.py:176 `open(path, "rb")` (config.toml) | yes | examined-clean re secrets (non-secret); TOMLDecodeError escape = finding 3 |
| credentials.py:27 `read_bytes()` (all 3 daemon creds) | yes | finding 2 (non-CredentialError exceptions) |
| credentials.py:96 root_key read | no — CLI offline only | out-of-scope-intended (invariant 2) |
| cli.py:103-190 `init` key generation/writes | no — CLI | out-of-scope-intended (modes 0600 set; staging plaintext is documented operator flow) |
| cli.py:758 old op key read (rotate) | no — CLI | out-of-scope-intended |
| cli.py manifest/well-known/identity/transfer/contact `read_text` | manifest + well-known: yes at serve startup | examined-clean re secrets (public material); unguarded `json.loads` noted in side discoveries |
| api.py / runtime.py / webhook.py / topology.py / resolution.py | yes | no file I/O or env reads; root-key hits are public-key verification only |

Serving-process key-material inventory (class closed): `operational_key` (Ed25519 private), `webhook_bearer`, `admin_bearer`, root public key from manifest. No site loads, derives, or exports a root private key into the daemon.

## Design risks (max 2)

1. `_is_https_url`/`_is_valid_domain` are shallow: `"https://"` (empty host), URLs with embedded whitespace, and domains with spaces pass validation; the failure surfaces only at request time in transport/resolver. Config is operator-written (non-hostile per preamble), so this is a delayed-failure gap, not a defense need.
2. Schema/runtime drift: `server.workers` is parsed and rendered in the default config but `cmd_serve` hardcodes `uvicorn.run(workers=1)` — plausibly intentional (in-process `RuntimeCoordinator` and sqlite connections cannot fork), but the knob is silently ignored, inviting operator confusion the same way finding 1's knob does.

## Side discoveries

- `cmd_serve` (cli.py:653, 662) parses `identity.json` and `well-known.json` with bare `json.loads` outside any handler — a malformed JSON manifest aborts startup with a traceback instead of an actionable message. Same class as findings 2/3; single-pass observation, not separately dispositioned.
- `lattice config` prints "Configuration is valid" without loading credentials or manifest — purely syntactic validation, consistent with its purpose.

## Bound

- `lattice/cli.py` was read in full because it is the only consumer of `lattice/credentials.py`; it was not otherwise assigned and its non-credential logic (contacts, trust, transfers) was only traced where it touched credential/key loading.
- Behavior under a real systemd unit (actual `$CREDENTIALS_DIRECTORY` semantics, `LoadCredentialEncrypted=` decryption in-flight) was reasoned from the code, not executed — no systemd service in tree; the live verifications used temporary directories with hand-built credential files.
- The enumeration pattern matches literal `os.environ`/`open(`/`read_bytes(`/`read_text(` and credential-module identifiers in `lattice/*.py`; indirect reads through `pathlib.Path.open` or library helpers (e.g. `tomllib.load`'s internal open at config.py:176, covered; anything else would have to be inside `storage/` or `protocol/`, which are outside this assignment's key-material question and were only checked via the grep above).
