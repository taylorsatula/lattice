# v-hunt-d2#2 — PRIMED VERIFIER

Claim under test: finding **hunt-d2#2** in `scratch/lattice-c1/reports/hunt-d2.md`
("malformed credential files raise exceptions that escape `CredentialError` handling; daemon exits
with a raw traceback"), reported tier **L**.

Frame re-derived from source before checking the claim. The claim's own phrasing was not used to
establish what the code does.

## Verdict: CONFIRMED — tier L (unchanged)

Mechanism, trigger, and outcome all trace. Frequency is LATENT and the claim already says so.
The claim's exception-type enumeration is **incomplete** (see Added mechanisms) but its stated
cases are all live-verified, so no reported half is refuted.

## Frame and trace

Entry: `pyproject.toml:49` `lattice = "lattice.cli:main"` → console-script wrapper `sys.exit(main())`.

Daemon startup path (`lattice/cli.py:cmd_serve`, lines 640–670):

1. `load_config` (guarded by `except ConfigError`).
2. bare `json.loads` of `identity.json`, `well-known.json` (unguarded — see Side discoveries).
3. ```
   try:
       op_key = load_operational_key(path=_credential_path("operational_key", config_dir))
       webhook_bearer = load_webhook_bearer(path=_credential_path("webhook_bearer", config_dir))
       admin_bearer = load_admin_bearer(path=_credential_path("admin_bearer", config_dir))
   except CredentialError as exc:      # cli.py:668
       print(f"CREDENTIAL ERROR: {exc}", file=sys.stderr); return 1
   ```

`lattice/credentials.py`:
- `load_operational_key` → `load_private_key(data, password=password)` (line 51), then
  `if not isinstance(key, Ed25519PrivateKey): raise CredentialError(...)` (line 53).
- `load_webhook_bearer` / `load_admin_bearer` → `data.decode("utf-8").strip()`.

`lattice/crypto.py:load_private_key`: `load_pem_private_key`; on `ValueError` falls back to
`load_der_private_key`; then `if not isinstance(key, Ed25519PrivateKey): raise TypeError(...)`.

`lattice/cli.py:main` (lines 1002–1014) catches only `CLIError`, `(ConfigError, CredentialError)`,
`KeyboardInterrupt`. The console entry point therefore prints a raw traceback for anything else.

### Live verification (cryptography 50.0.0)

```
RSA PEM staged as operational_key            -> TypeError  "private key is not Ed25519"
encrypted Ed25519 PEM, password=None         -> TypeError  "Password was not given..."
unparseable / truncated / empty bytes        -> ValueError "Could not deserialize key data..."
b"\xff\xfe garbage".decode("utf-8")           -> UnicodeDecodeError  (mro: UnicodeError, ValueError)
```

`issubclass(tomllib.TOMLDecodeError, ValueError)` and `CredentialError(ValueError)` both hold, but
the `except (ConfigError, CredentialError)` clause names the two concrete classes, so none of
`TypeError`, the raw `ValueError` from `crypto`, or `UnicodeDecodeError` is caught. Verified with an
interpreter, not by reading.

The claim's "dead code" evidence holds: `load_private_key` raises `TypeError` before ever returning
a non-Ed25519 key, so the `isinstance(...): raise CredentialError` branch in `load_operational_key`
(line 53) can never fire. Confirmed by the live RSA case above.

## Severity correction — none (L stands)

Trace producing the correction: the escaping exception occurs **before** `uvicorn.run` and **before**
`migrate`/`open_connection`/`initialize_cache_db` (cli.py:690–705). No durable or in-memory state is
created, no custody is acknowledged, no partial write. The process still exits non-zero (Python's
unhandled-exception exit code 1), so the fail-closed property is preserved. Outcome is exactly the L
definition — "a misreported error path ... with no lasting harm" — not M (no wrong state) and not H
(no secret exposure; `TypeError`/`UnicodeDecodeError` messages carry a byte offset, not key or bearer
bytes). L is correct.

## Frequency correction — none (LATENT stands)

The claim's LATENT label is right and I could not ground a higher cadence. The documented flow
(`docs/LATTICE_SYSTEMD.md` + `deploy/lattice.service`) uses `LoadCredentialEncrypted=` and stages
Ed25519 PKCS#8 PEM and UTF-8 bearers via `lattice init` (`cli.py:130–142`), so a correct deployment
never produces these bytes. The trigger population is operators who mis-stage a credential at
deployment: wrong/foreign PEM, a password-protected PEM (init writes the operational key with
`NoEncryption`), a non-UTF-8 bearer, or the systemd-creds `.cred` blob itself. Those are one-off
deployment mistakes with no normal-operation cadence. `lattice/__pycache__` and `tests/` contain no
coverage for malformed credentials (grep for `CredentialError`, `not Ed25519`, `UnicodeDecode`,
`malformed` in `tests/` returns only `LoadCredentialEncrypted` unit-file assertions and
`load_root_key` happy-path calls). Reachability kind: **PRODUCTION** (operator staging action),
frequency LATENT.

## Refuted sub-claims

None. Every stated component traces:

- `load_private_key` raises `TypeError` for RSA and password-protected PEMs — verified live.
- The `isinstance` branch in `load_operational_key` is dead for the type case — verified live.
- `cmd_serve` catches only `CredentialError`; `main` catches only `CLIError`/`ConfigError`/
  `CredentialError`/`KeyboardInterrupt` — verified by reading the exact clauses.
- `decode("utf-8")` raises `UnicodeDecodeError` (a `ValueError`, not a `CredentialError`) — verified.

One component is **incomplete rather than refuted**: the enumeration of exception classes. The claim
names `TypeError` (RSA / encrypted PEM) and `UnicodeDecodeError` (bearer). It omits the plain
`ValueError` path, which is the most plausible mis-staging (see Added mechanisms).

## Added mechanisms / earlier failure site / new reachability (same trace)

1. **Plain `ValueError` class is broader than the claimed `TypeError` class.** Unparseable,
   truncated, or zero-byte key material drives `load_pem_private_key` → `ValueError` →
   `load_der_private_key` → `ValueError` (crypto.py), which escapes the same handler. A wrong
   password on an encrypted PEM (`password=b"wrong"`) also yields `ValueError`. Same site, same
   outcome, wider trigger set. This does not change the tier; it is an enumeration gap in the claim.
2. **Concrete alternative trigger inside the documented deployment.** An operator who uses
   `LoadCredential=` (not `...Encrypted=`) with the `.cred` blob, or stages the still-encrypted
   `.cred` under a scanned name, feeds systemd-creds ciphertext to `load_private_key` → `ValueError`
   escape. Operator-error, latent, same outcome.
3. **No new network reachability.** The credential bytes are read from `$CREDENTIALS_DIRECTORY` or
   the operator-owned config dir; no peer- or request-controlled path reaches `load_*_credential`.
   The trace is not reachable by a network peer at any tier.

## Fix-direction constraints

- **Localize the wrap.** The clean fix is in `credentials.py`: catch `(ValueError, TypeError,
  UnicodeDecodeError)` around `load_private_key`/`decode` and re-raise `CredentialError`. Do **not**
  change `crypto.load_private_key`'s exception types — it is shared with the offline root-key path
  (`load_root_key` at cli.py:470/519/761), which relies on `ValueError` semantics and would change
  behavior there too.
- **Preserve fail-closed.** Any wrap must still exit non-zero and must not convert a parse failure
  into an empty/valid key or bearer.
- **Reconcile the dead branches.** The `isinstance` guards at `credentials.py:52-53` and `:98-99`
  cannot fire; a fix should either move the type check into `crypto` (typed error) or delete the
  dead branch, so intent and behavior agree.
- **Bounded-message requirement.** The repair must catch *all three* classes, not just the two the
  claim named; a fix that only handles `TypeError`/`UnicodeDecodeError` leaves the truncated-file
  `ValueError` escaping.

## Checked and clean

- `_credential_path` (cli.py:627–637) raises `CredentialError` for missing credentials and is
  caught — the not-found path is handled correctly.
- `main()` returns non-zero for all handled error families; `CredentialError` subclasses `ValueError`
  but is matched by name, and the console wrapper converts the return value to an exit code.
- `crypto.load_private_key` correctly transparently handles PEM **and** DER via the `ValueError`
  fallback; `load_public_key`'s raw-32-byte branch is not on this trace.
- Fail-closed is preserved end to end (startup aborts before any durable state).
- `deploy/lattice.service` and docs use `LoadCredentialEncrypted=`, consistent with the loader.

## Enumeration

Composed command closing the credential-parse class:

```
rg -n "CredentialError|load_operational_key|load_webhook_bearer|load_admin_bearer|load_private_key|\.decode\(" lattice/*.py
```

| Site | Serving process? | Disposition |
|---|---|---|
| cli.py:665–667 `load_operational_key`/`load_webhook_bearer`/`load_admin_bearer` | yes | **finding (claim)** — all three call sites in one `except CredentialError` |
| credentials.py:51 `load_private_key(data, password)` | yes | claim mechanism; missing `ValueError` class |
| credentials.py:53 / :99 dead `isinstance`→`CredentialError` | yes/offline | claim evidence confirmed |
| credentials.py:59,68 `data.decode("utf-8").strip()` | yes | claim mechanism confirmed |
| cli.py:668 `except CredentialError` | yes | confirmed narrow |
| cli.py:1011 `except (ConfigError, CredentialError)` | yes | confirmed narrow |
| cli.py:282 `load_operational_key` (`_load_local_identity`) | offline/CLI | same class, same latent outcome; not separately reported by hunt-d2 (acknowledged in its Checked-and-clean) |
| cli.py:758 `load_private_key(old_op_key_path.read_bytes())` | offline/CLI | same class, offline rotate path; out of the claim's daemon scope |
| crypto.py:26–28 `load_private_key` raise sites | shared | root cause, not independently reportable |

## Side discoveries (single-pass, priced)

1. **[L] bare `json.loads` on `identity.json` / `well-known.json` in `cmd_serve` (cli.py:653, 662).**
   A truncated or malformed manifest aborts startup with a raw traceback instead of an actionable
   message. Trigger: corrupted/partially-written manifest at startup; PRODUCTION; frequency LATENT
   (correct `init` writes both atomically enough). Fix-direction: wrap in the same handler family as
   the credential loads. Already noted by hunt-d2 as a side discovery; not folded into the claim.
2. **[L] wrong root-key password on the offline CLI escapes to a traceback.** `load_root_key`
   (cli.py:470/519/761) → `load_private_key` with a wrong password yields `ValueError` (verified
   live), uncaught by `main()`'s `(ConfigError, CredentialError)` clause, so `keys rotate-operational`
   / transfer commands print a traceback at a password prompt. Trigger: operator types the wrong root
   password; PRODUCTION; frequency LATENT-ish (any mistyped password at those commands). Lower
   practical impact (offline, cosmetic) and acknowledged but not separately reported by hunt-d2.

## Bound

- No real systemd unit was executed. `$CREDENTIALS_DIRECTORY` semantics and in-flight decryption by
  `LoadCredentialEncrypted=` are reasoned from `docs/LATTICE_SYSTEMD.md` and `deploy/lattice.service`,
  not observed. The live exception-type checks used temporary in-memory bytes.
- Exception types are from the installed `cryptography` **50.0.0** (`pyproject.toml` requires
  `>=42.0.0`). The exact `TypeError` vs `ValueError` split for malformed/password-protected keys is
  provider-version-dependent; the *escape* (no `CredentialError` raised) holds across versions because
  `credentials.py` performs no wrapping itself, but the specific class for any given input is bounded
  by that dependency.
- Secret-bearing input files and live credential files were not read; verification used generated
  material only.
