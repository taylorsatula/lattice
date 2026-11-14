# Lattice Key Management

Lattice v1 uses two Ed25519 keys per node:

- **Root key:** Immutable. Derives the node ID and signs operational certificates.
- **Operational key:** Replaceable. Signs protocol traffic and durable-custody receipts.

## Key custody model

- The **root private key** is a root-only host credential. It is never loaded into the network-facing daemon.
- The **operational private key** is delivered to the daemon through systemd `LoadCredentialEncrypted=`.
- The daemon also receives a **webhook bearer credential** and an **admin bearer credential** through encrypted credentials.

## Initialization

Run `lattice init` on a trusted host as root:

```bash
sudo lattice init --domain example.com --public-base-url https://example.com
```

This creates in `/etc/lattice`:

- `root_key.pem` — password-encrypted PKCS#8 root key (mode 600).
- `operational_key.pem` — plaintext staging operational key (mode 600).
- `webhook_bearer` — plaintext staging webhook bearer (mode 600).
- `admin_bearer` — plaintext staging admin bearer (mode 600).
- `identity.json` — signed identity manifest (mode 644).
- `config.toml` — non-secret node configuration (mode 640).

Encrypt the staging credentials with systemd-creds and delete the plaintext files:

```bash
sudo systemd-creds encrypt --name=operational_key /etc/lattice/operational_key.pem /etc/lattice/operational_key.cred
sudo systemd-creds encrypt --name=webhook_bearer /etc/lattice/webhook_bearer /etc/lattice/webhook_bearer.cred
sudo systemd-creds encrypt --name=admin_bearer /etc/lattice/admin_bearer /etc/lattice/admin_bearer.cred
sudo rm /etc/lattice/operational_key.pem /etc/lattice/webhook_bearer /etc/lattice/admin_bearer
```

Configure the systemd unit with `LoadCredentialEncrypted=` for each credential.

## Operational key rotation

Rotate the operational key periodically or after suspected compromise:

```bash
sudo lattice keys rotate-operational
```

This prompts for the root key password, generates a new operational key, creates a new root-signed certificate with an incremented sequence number, and stages a new plaintext operational key. Re-encrypt it with systemd-creds and restart the daemon.

The node ID does not change during operational rotation.

Each rotation also produces a three-signed **rotation statement** at
`/etc/lattice/rotation.json`: the root signs `signature`, and the old and new
operational keys sign `old_signature` and `new_signature`. All three cover the
same canonical object (see `tests/vectors/generate_vectors.py`). The statement
is the durable audit artifact for the rotation; peers learn the new operational
key through peer cards, which they already validate by certificate-sequence
monotonicity.

## Domain transfer (transfer statements)

Moving a domain to a new node identity uses a dual-signed transfer statement:

```bash
# On the old node (root signs `signature`):
sudo lattice keys create-transfer --domain example.com --new-node-id lat_<new>

# On the new node (root signs `new_signature` over the same object):
sudo lattice keys co-sign-transfer --input transfer.json

# On any peer holding a pin for the domain, after the DNS cutover:
sudo lattice trust accept-transfer --input transfer.json
```

`accept-transfer` fails closed unless the current pin's root key matches the
statement's old node ID, the domain's live well-known document derives the
statement's new node ID, and both signatures verify. Trust reset remains the
manual fallback when no transfer statement exists.

## Backup and recovery

Back up `/etc/lattice/root_key.pem` and the passphrase used to encrypt it. Store the backup offline or in a separate encrypted vault.

To recover a node on a replacement host:

1. Copy the encrypted root key to `/etc/lattice/root_key.pem`.
2. Run `lattice init --force` to generate a new operational key and config.
3. Re-encrypt credentials with systemd-creds.

If the root key or its passphrase is lost, the node identity is lost. Create a new node and ask peers to reset their domain pins.

## Root key compromise

If the root private key is compromised:

1. Generate a new root identity with `lattice init`.
2. Publish the new node ID and root public key out of band.
3. Ask peers to run `lattice trust reset-domain --domain example.com` and re-verify the new binding.

There is no cryptographic undo in v1.

## Development and testing

For local testing, credentials may be read from explicit paths. Do not use plaintext credentials in production.
