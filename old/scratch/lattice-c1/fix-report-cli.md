# Fix report — lattice/cli.py (rows REC k60v, EXP-cli)

## Changed
File: `lattice/cli.py` (only file written)

- `cmd_init` (~93-200): +39 / -10 lines
  - Added `--reuse-root-key` handling: when set and `root_key.pem` exists, loads the existing root
    key via `load_root_key(root_key_path, password)` (passphrase prompted, no confirm — mirroring
    `cmd_keys_rotate_operational:760` / `cmd_keys_create_transfer:470`), and derives
    `node_id`/`identity.json`/`well-known.json`/operational certificate from it. `save_root_key`
    is skipped on reuse; prints "Root key reused from: ... (node identity preserved)".
  - Guard: without `--reuse-root-key`, an existing `root_key.pem` aborts init with a CLIError
    (regardless of `--force`, which stays scoped to config/operational/bearer overwrite). Fresh-dir
    behaviour unchanged: generate → prompt+confirm → `save_root_key`.
- `cmd_contacts_import` (~383): +6 lines — after `cert.verify(RootIdentity(...))`, added
  `if not cert.is_valid_at(datetime.now(UTC)): print(...); return 1`, mirroring
  `runtime.py:verify_gossip_sender_card` (`cert.verify(root_identity)` then `cert.is_valid_at(now)`).
- `_build_parser` init subparser (~852): +5 lines — added the `--reuse-root-key` flag.

## Exemplars mirrored
- Credential loading/prompt: `cmd_keys_rotate_operational` (lattice/cli.py:760) — `_read_password("Root key password: ")` + `load_root_key`.
- Validity check ordering: `runtime.py:verify_gossip_sender_card:536` — verify signature, then `is_valid_at(now)`.

## Verification — EXECUTED (repo venv `.venv/bin/lattice`)
All probes against live CLI + real sqlite + real Ed25519 crypto, in /tmp (cleaned up after).

(a1) Plain init over existing `root_key.pem` (hostile: the recovery trigger) — REFUSED:
  `lattice --config etc/config.toml init --force --domain example.com --public-base-url https://example.com`
  → `Error: root key already exists: ...; use --reuse-root-key to preserve this node's identity...`
  md5 of `root_key.pem` identical before/after → key not destroyed.

(a2) `--reuse-root-key` preserves node_id — `init --force --reuse-root-key` re-run over the same
  dir: `Initializing Lattice node lat_kjouiexut7rl666yplptwlavfeh32yprfjcfyl6c3wrpn55b4j3q`
  (identical old/new node_id and root_public_key in `identity.json`); output
  `Root key reused from: ... (node identity preserved)`; rc=0.

(b) Fresh dir, no reuse — unchanged: generates key, prompts password+confirm, writes
  `Root key written to: ... (mode 600)`, manifest/well-known/config written, rc=0.

(c) Expired certificate in contacts-import — REJECTED: fixture pinned a node with a
  backdated cert (valid_until = now-30d) and a correctly signed contact card (built with the
  repo's own `create_operational_certificate`/`DomainPinRepository.upsert`/`OperationalIdentity.sign_object`
  against a real migrated sqlite DB). `contacts import` →
  `pinned operational certificate is expired or not yet valid`, rc=1.
  Control with a currently-valid cert from the identical script → `Imported contact alice@lat_...`, rc=0 —
  proves the rejection is the expiry window, not a malformed fixture.

## Found but not touched
- `load_root_key` with a wrong passphrase raises a raw `ValueError` traceback (crypto.py
  `load_private_key` doesn't wrap it; `main()` only catches `CredentialError`). Pre-existing;
  identical in the sibling commands (`cmd_keys_create_transfer:470`, `cmd_keys_rotate_operational:760`).
  Fixing it would touch credentials.py/crypto.py — outside my file list.

## Floor
- `py_compile` clean; `ruff check lattice/cli.py` clean (one E501 in my new help text fixed).
- Diff re-read; no stray edits, no debug prints. Fixtures under /tmp/lattice-probe removed.
- Not committed; working tree left for review.
