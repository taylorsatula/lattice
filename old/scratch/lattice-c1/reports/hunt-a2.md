# hunt-a2 — operator CLI (lattice/cli.py)

Blind hunter pass, read-only. `lattice/cli.py` (1020 lines) read end to end; supporting
modules (`config.py`, `credentials.py`, `identity.py`, `resolution.py`, `addressing.py`,
`crypto.py` via grep, `runtime.py` gossip/verify paths, `storage/repositories.py` pin paths,
`gossip.py build_own_card`, docs/KEY_MANAGEMENT.md, docs/LATTICE_SYSTEMD.md) read as needed
to trace candidates.

## Findings

1. [M] — Daemon starts and runs with an operational key that does not match its certificate
- Location: `lattice/cli.py:cmd_serve` (lines 638–731, identity assembly at ~676–687); same
  shape in `_load_local_identity` (lines 275–283). No check exists anywhere in the startup
  path (`grep -rn "public_key()\s*==\|== .*public_key" lattice/ --include=*.py` returns
  nothing outside tests).
- Evidence: `identity = OperationalIdentity(node_id=cert.node_id, private_key=op_key, certificate=cert)`
  — the only invariant checked is `cert.node_id != manifest["node_id"]`. The loaded private
  key is never compared to `cert.operational_public_key`.
- Trigger: PRODUCTION. Operator runs `lattice keys rotate-operational` (writes new
  `operational_key.pem` staging file, new cert into `identity.json`, new well-known), then
  restarts the daemon BEFORE re-encrypting the systemd credential — or the daemon
  crashes/auto-restarts/reboots in that window. On restart, `cmd_serve` sets
  `CREDENTIALS_DIRECTORY` (systemd unit) so `_credential_path` returns the cred-dir file,
  which still holds the OLD key, while `identity.json` now holds the NEW certificate. The
  rotate output explicitly leaves re-encryption as a printed "next step"
  (`print(f"Operational key staged at: {op_key_path} (encrypt with systemd-creds)")`), so
  the stale window is by design of the procedure, and nothing detects it.
- Frequency: DEMONSTRATED — every daemon restart (manual restart, crash-restart, host
  reboot) that lands between a periodic rotation (certs are issued with 30-day validity,
  so rotation is a routine cadence) and the manual `systemd-creds encrypt` step. Requires
  the operator's restart/crash to precede the re-encrypt, not any code coincidence.
- Outcome: the daemon serves and embeds the NEW certificate (peer card via
  `gossip.build_own_card` line 210: `"operational_certificate": self._identity.certificate.to_dict()`)
  but signs every peer card, gossip batch, and durable-custody receipt with the OLD key.
  Every peer's `verify_gossip_sender_card` → `verify_object(cert.operational_public_key, card,
  "peer_card")` (runtime.py:566) fails, so the node is silently isolated — the daemon
  itself logs no error and reports healthy. Same missing check in `_load_local_identity`
  makes `contacts export` sign cards with a stale key that fail verification at the
  importer. Fix-size is one comparison at startup; recoverable only by re-encrypting and
  restarting again.
- Confidence: traced (mechanism, trigger, and outcome all followed through
  `gossip.build_own_card` and `runtime.verify_gossip_sender_card`; no existing check found
  in `cmd_serve`, `create_app`, or `RuntimeCoordinator.start`).

2. [L] — `keys rotate-operational` performs all destructive writes before validating the config
- Location: `lattice/cli.py:cmd_keys_rotate_operational` (lines 734–831).
- Evidence: write order is `op_key_path.write_bytes(...)` (791) → `rotation_path.write_text(...)`
  (795) → `manifest_path.write_text(...)` (800) → `load_config(config_path)` (804) →
  well-known write (823). The first and only config validation happens after the old key
  has been overwritten and the manifest rewritten.
- Trigger: PRODUCTION. Operator runs `lattice keys rotate-operational` while `config.toml`
  fails `load_config` (e.g., a pending incomplete edit, missing `webhook.url`, bad TOML).
  The command prompts for the root password, does all writes, then prints
  `CONFIG INVALID: {exc}` and returns 1.
- Frequency: requires a coincidence — rotation (roughly monthly cadence) landing while the
  config is invalid. The command never prompts the operator to validate config first, and
  `cmd_serve` is the only other reader, so a broken config can sit unnoticed until this
  command half-executes on it.
- Outcome: `well-known.json` is left advertising the OLD certificate while `identity.json`
  and the staged key hold the NEW one. Once the operator fixes the config and the daemon
  starts, it serves a root-signed well-known whose operational certificate does not match
  the key it signs with — fresh peers resolving the domain pin an operational key that
  cannot verify the node's signatures. Re-running rotate "recovers" but produces a
  rotation.json whose `old_signature` is by a key that was never publicly certified
  (it loads whatever now sits in `operational_key.pem` as the "old" key).
- Confidence: traced (mechanism and trigger followed line by line; the config-error path
  is the only non-environmental failure between the first write and completion).

3. [L] — `lattice init` accepts `--domain`/`--public-base-url` values its own config validator rejects
- Location: `lattice/cli.py:cmd_init` (lines 93–206) vs `lattice/config.py:Config.__init__`.
- Evidence: `domain: str = args.domain` / `public_base_url: str = args.public_base_url` are
  used verbatim; `render_default_config` interpolates them unescaped into TOML
  (`domain = "{domain}"`). `Config` later enforces
  `url.startswith("https://") and "@" not in url` and `_is_valid_domain`.
- Trigger: PRODUCTION. First-run operator typos the base URL (`--public-base-url
  example.com`, missing scheme) or passes a domain containing a `"` (breaks the generated
  TOML) or a `@`/`:`/`/`. `init` completes successfully — generating the root key, prompting
  for and accepting the encryption password, writing all secrets, and root-signing a
  well-known with endpoints like `example.com/lattice/v1/gossip`.
- Frequency: DEMONSTRATED — any operator whose first-run `init` arguments contain a scheme
  omission or quoting character; the tool gives no feedback until the next command fails.
- Outcome: `lattice config` reports `server.public_base_url is required and must be an
  https URL` and `lattice serve` refuses to start; the node must be re-initialized with
  `--force` (new root key, new node ID). Bounded: fresh-node scenario, nothing
  pre-existing is corrupted, but the signed well-known and manifest produced are garbage.
- Confidence: traced.

## Checked and clean

- **Root-key confinement (invariant 2)**: `cmd_serve` loads only `operational_key`,
  `webhook_bearer`, `admin_bearer` via `_credential_path`, plus the root PUBLIC key from
  the manifest. No `load_root_key` on any serve path; `load_root_key` appears only in
  `cmd_keys_create_transfer` (470), `cmd_keys_cosign_transfer` (519), and
  `cmd_keys_rotate_operational` (761) — all offline, password-prompted, intended.
- **Transfer signature preimage parity**: `cli._transfer_signature_preimage` excludes
  `("signature", "new_signature")`, identical to `identity.verify_transfer` (identity.py
  bare-object construction). Co-signed statements verify.
- **`trust accept-transfer` chain**: resolver validates content type, strict JSON,
  WellKnownDocument schema, domain match, node-ID derivation from root key, root
  signature, and cert signature (`resolution.resolve_with_ip`); the command additionally
  requires the pinned root key to derive the statement's `old_node_id`, the live doc's
  `node_id` to equal `new_node_id`, and both transfer signatures to verify before
  upserting the pin. Fails closed throughout; network fetch goes through
  `NetworkPolicy.public()`.
- **`trust reset-domain`**: `DomainPinRepository.delete` lowercases the domain
  (repositories.py:132–135), matching how pins are stored (`upsert` lowercases), so
  mixed-case `--domain` actually deletes; the printed message matches. No false-success
  path.
- **`contacts import` verification**: card kind/address shape checked; node must be
  pinned; cert verified against the pinned root (`cert.verify(RootIdentity(...))` which
  re-derives node ID); card signature verified against `cert.operational_public_key`;
  malformed sigs caught (`SignatureError, IdentityError`) with exit 1. Username falls
  back to the parsed address's. Card/username round-trips through `parse_address`
  (refuted my export/import charset-mismatch candidate — parse_address accepts any
  non-empty username, so exported cards re-import).
- **E3 clock/credential sites** (see Enumeration): all four `datetime.now(UTC)` uses are
  UTC-aware and feed `_format_ts`/`_parse_ts` which require and normalize timezone-aware
  timestamps; `_credential_path` prefers `CREDENTIALS_DIRECTORY` (systemd semantics:
  name-keyed files, matching the `--name=` values init prints) and falls back to staging
  suffixes `""`, `.pem`, `.txt` exactly matching init's filenames
  (`operational_key.pem`, `webhook_bearer`, `admin_bearer`). Missing cred-dir files
  surface as clean `CredentialError` from `_read_credential_file`, caught in `main`.
- **Exit-code plumbing**: `main` catches `CLIError`, `ConfigError`, `CredentialError` → 1;
  `KeyboardInterrupt` → 130; every command-local failure path I traced prints to stderr
  and returns 1 rather than falling through to 0.
- **`cmd_upgrade`/`cmd_status`/`contacts list`**: migrate/init/read paths consistent
  through `_state_paths`; config has no state-dir key, so CLI `--state-dir` defaults
  cannot diverge from a config-file setting (none exists).
- **`cmd_init` secret handling**: root key encrypted with password before write
  (`save_root_key`), 0600; bearers staged 0600 with clear "encrypt with systemd-creds and
  delete" guidance; manifest/well-known contain only public material. The daemon never
  reads `root_key.pem`.

## Enumeration

E3 sites `cli.py:109,304,381,472,628,764` — command
`sed -n '109p;304p;381p;472p;628p;764p' lattice/cli.py`:

| Line | Site | Command | Disposition |
|---|---|---|---|
| 109 | `now = datetime.now(UTC)` → cert valid_from/until, manifest created_at | init | examined-clean — UTC-aware, 30-day lifetime < 90-day `MAX_OPERATIONAL_CERTIFICATE_LIFETIME_SECONDS` |
| 304 | `issued_at` in contact card | contacts export | examined-clean — UTC-aware, card is signed public material |
| 381 | `imported_at=datetime.now(UTC)` | contacts import | examined-clean — UTC-aware, repository `_format_ts` normalizes |
| 472 | `now = datetime.now(UTC)` → transfer issued_at | keys create-transfer | examined-clean — UTC-aware; domain lowered/stripped; `new_node_id` checked against `NODE_ID_RE` |
| 628 | `cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")` | `_credential_path` (serve, contacts export) | examined-clean — systemd name semantics correct; absence of the file is a clean CredentialError; fallback suffixes match init's filenames (see finding 1 for what the loaded key is NOT checked against) |
| 764 | `now = datetime.now(UTC)` → new cert, rotation issued_at, well-known issued_at | keys rotate-operational | examined-clean for the clock itself; ordering of surrounding writes is finding 2 |

## Design risks

1. **Create-then-chmod window on secret staging files**: `cmd_init` and `save_root_key`
   `write_text`/`write_bytes` then `chmod(0o600)`, so the operational key and bearers exist
   briefly with umask-default permissions. Local-observer race only; not promoted to a
   finding.
2. **CLI commands needing the operational key cannot reach systemd-encrypted
   credentials outside the unit**: after the documented staging-file deletion,
   `contacts export` on the host fails with `CredentialError` until the operator manually
   decrypts. Clean refusal, but it pushes operators toward keeping plaintext staging
   around — the same condition finding 1 depends on.

## Side discoveries (single-pass candidates, not confirmed work)

- `cmd_contacts_import` verifies the pinned cert's signature chain but never calls
  `cert.is_valid_at(...)`, while the gossip path (`runtime.verify_gossip_sender_card`,
   runtime.py:564) does enforce the validity window — a card whose cert window lapsed
   imports fine via CLI.
- Malformed operator-supplied JSON inputs (`co-sign-transfer --input`,
  `accept-transfer --input`, `contacts import --input`, corrupt `identity.json` in
  `serve`) raise uncaught `json.JSONDecodeError`/`KeyError`/`IdentityError` tracebacks
  instead of clean messages; exit code is still non-zero via the uncaught exception.

## Bound

- `lattice/cli.py` fully read; `runtime.py`, `gossip.py`, `repositories.py`,
  `resolution.py` read only along traced paths (gossip card build/verify, pin upsert/
  get/delete, well-known validation), not end to end — daemon-side defects in those files
  belong to other passes.
- Did not execute the CLI against a live systemd host; the `CREDENTIALS_DIRECTORY`
  behavior in finding 1 is traced from code and docs (LATTICE_SYSTEMD.md rotation
  procedure), not observed in a running unit.
- `crypto.py` (`save_private_key`/`load_private_key` PKCS#8 handling) inspected via
  signatures only; encryption-format defects there are out of my reach in this pass.
