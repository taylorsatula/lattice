# v-hunt-d2#1 — PRIMED VERIFIER of hunt-d2 finding 1

Claim under test: `scratch/lattice-c1/reports/hunt-d2.md` finding 1, reported tier **L** — "`webhook.bearer_credential_name` is validated by the config schema but silently ignored by daemon credential loading".

## Verdict

**CONFIRMED** — tier **L** unchanged. Reachability kind: **PRODUCTION (operator action at deployment)**.

The core mechanism is real and traced. One descriptive sub-claim is refuted; it changes no tier.

## Frame re-derived from source (before reading the claim)

- `lattice/config.py:85` — `WebhookConfig.__init__` executes `self.bearer_credential_name: str = data.get("bearer_credential_name", "webhook_bearer")`. This **stores** the value; it performs **no validation** at all (no type coercion beyond TOML's own, no character/emptiness check, no comparison against the hardcoded names). The schema does not validate it.
- `lattice/cli.py:665-667` — `cmd_serve` calls `load_operational_key(path=_credential_path("operational_key", config_dir))`, `load_webhook_bearer(path=_credential_path("webhook_bearer", config_dir))`, `load_admin_bearer(path=_credential_path("admin_bearer", config_dir))`. The webhook name passed to `_credential_path` is the **literal `"webhook_bearer"`**, not `config.webhook.bearer_credential_name`.
- `lattice/cli.py:626-637` — `_credential_path` resolves `path` from `$CREDENTIALS_DIRECTORY/<name>` when set, else scans `config_dir` for `<name>{,.pem,.txt}`; raises `CredentialError` if nothing found.
- `lattice/credentials.py:57-63` — `load_webhook_bearer` hardcodes `load_credential("webhook_bearer", path=path)` too.
- `lattice/runtime.py:1054` consumes `config.webhook.url`; `runtime.py:171-185,1057` receives only the already-loaded bearer **string**. No consumer reads the name field.

Decisive artifact: the string `"webhook_bearer"` at `cli.py:666` and `credentials.py:62` is a literal, while `config.webhook.bearer_credential_name` is read by nothing.

## Enumeration (class closed)

```
rg -n "bearer_credential_name" --glob '!scratch/**' .
```

| Instance | Disposition |
|---|---|
| `lattice/config.py:85` | schema parse (stores only) |
| `lattice/config.py:203` | `render_default_config` template line |
| `tests/test_runtime.py:54` | fixture, value `"webhook_bearer"` (= default) |
| `tests/test_api.py:56` | fixture, value `"webhook_bearer"` |
| `tests/conftest.py:148` | fixture, value `"webhook_bearer"` |

No runtime consumer exists. Every test fixture sets the field to the default value, so no test exercises a custom name either — the knob is untested in both directions. `git log -S 'bearer_credential_name'` returns nothing (config.py is currently untracked in this mid-rewrite tree), so there is no deleted historical consumer to resurrect; the field has only ever been inert.

## Sub-claims, checked individually

- **"silently ignored by daemon credential loading" — CONFIRMED.** No code reads the attribute; `cmd_serve` uses the literal. Divergence between the config schema and the loader is the decisive statement.
- **"validated by the config schema" — REFUTED.** The schema neither validates nor coerces the value; it merely stores whatever TOML produced. The finding's own body states this accurately ("parsed … and never rejected"), but its title mislabels it as validation. No tier impact.
- **Trigger — CONFIRMED.** Operator sets `[webhook] bearer_credential_name = "my_token"` in the config rendered by `init`, provisions the credential under that name (systemd `LoadCredentialEncrypted=my_token:...`), and runs `lattice serve`. With `CREDENTIALS_DIRECTORY` set, `_credential_path("webhook_bearer", …)` returns `<cred_dir>/webhook_bearer`; `_read_credential_file` finds no such file and raises `CredentialError("credential file not found: <cred_dir>/webhook_bearer")`; `cmd_serve` prints `CREDENTIAL ERROR: …` and returns 1. In the non-systemd fallback the scan for `webhook_bearer{,.pem,.txt}` misses likewise. Fail-closed preserved in both modes.
- **Outcome — CONFIRMED.** Bounded, clean startup failure naming the wrong credential. No wrong-state path: an operator who sets the knob but leaves the credential named `webhook_bearer` sees no failure at all (knob simply ignored); a stale `webhook_bearer` staging file can be silently used in the non-systemd fallback, but the operator controls both files, so no security consequence.
- **Frequency "LATENT" — CONFIRMED.** Population = operators who customize a field that `init`, the systemd unit, and `docs/` all pin to `webhook_bearer`. There is no groundable cadence; per the calibration rule an ungroundable frequency is latent and caps at L. Correctly stated.

## Severity / frequency correction

Neither corrected. **Severity L** stands: the outcome is a clean, fail-closed startup abort with a misleading name — no data loss, no secret exposure, no auth bypass, no cross-peer reach, no wrong persisted state. **M** would require wrong runtime state under plausible normal operation; the default deployment is unaffected, so M does not fit. **Frequency LATENT** stands, with the demonstrated population above.

## Additional mechanisms / earlier failure sites on the same trace

- **Parallel dead knob: `server.workers`.** `config.py:134` parses `self.workers` and `render_default_config` (config.py:193) emits `workers = 1`, but `cmd_serve` hardcodes `uvicorn.run(..., workers=1)` (`cli.py:724`). Same class as the claimed field: schema-parsed, default-config-rendered, never consumed. Same tier L, same LATENT frequency (population = operators who raise the worker count), same reachability kind (production operator action). Already flagged in the source report's Design-risks §2; noted here as a second instance of the class rather than a new finding.
- **No earlier failure site.** The name is resolved before any credential bytes are read; the only failure is the `CredentialError` at `_read_credential_file`, which is exactly where the claim places it.

## Fix-direction constraints

1. A repair that wires `config.webhook.bearer_credential_name` into `_credential_path`/`load_webhook_bearer` MUST validate the value first. `_credential_path` joins the name into both `$CREDENTIALS_DIRECTORY` and `config_dir` (cli.py:630-634); a free-form name containing `/`, `..`, or an empty string becomes path traversal or a directory join. Today the literal makes this unexploitable; naive wiring introduces the vector. Config is operator-written (non-hostile per preamble), so this is a hardening constraint, not a present vulnerability.
2. The knob cannot become live in isolation: the systemd unit (`deploy/lattice.service:23` `LoadCredentialEncrypted=webhook_bearer:...`), `cmd_init`'s staging name (`cli.py:135-137,197`), the `init` next-steps text, and `docs/KEY_MANAGEMENT.md`/`LATTICE_SYSTEMD.md` all hardcode `webhook_bearer`. Wiring the field without updating them yields a half-wired knob that still fails for the operator who follows the docs.
3. Any repair MUST preserve the fail-closed `CredentialError` on a missing credential. Do not add a silent fallback to the default name, which would convert a clean abort into a startup that authenticates the webhook with an unintended token.
4. The lower-cost correct alternative is to delete the field (and the `server.workers` field) from the schema and rendered default config, since neither is consumed.

## Checked and clean

- `lattice/runtime.py:1054` uses `config.webhook.url` — the webhook URL **is** consumed; only the credential-name sibling is dead. Examined clean.
- `operational_key` and `admin_bearer` have no config knobs, so their literal lookups in `cmd_serve` are consistent by construction; only the webhook name has a schema field that disagrees with the lookup.
- The default flow (`init` renders `bearer_credential_name = "webhook_bearer"`, unit loads `webhook_bearer`, `cmd_serve` looks up `webhook_bearer`) is internally consistent — the defect is only reachable on operator customization, consistent with the LATENT frequency.
- All five references to the identifier dispositioned above; class closed at zero runtime consumers.

## Bound

- Real `systemd-loadcredential`/`LoadCredentialEncrypted=` semantics were not executed (no systemd on this host); the mechanism is pure-Python name resolution, so this does not affect the verdict. Under systemd's documented behavior a credential loaded under name `my_token` lands at `<cred_dir>/my_token`, which the hardcoded lookup does not read.
- Whether a future commit intends to consume the field is unknowable from the tree; on current source it is inert. Recorded as a boundary, not guessed.
- `lattice/cli.py` beyond `cmd_serve`, `_credential_path`, and `cmd_init`'s staging block was not re-read for this claim; the identifier enumeration closes the consumer question regardless.
