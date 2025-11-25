# Lattice Vault Configuration

This document describes how to manually configure HashiCorp Vault for Lattice.

## Vault Structure

```
secret/lattice/
├── services         # APP_URL, bootstrap servers
└── keys             # Private key (auto-generated)
```

## Prerequisites

- Vault CLI installed and configured
- VAULT_ADDR environment variable set
- Valid Vault token with write permissions to `secret/lattice/`

## Step 1: Update APP_URL in services

The APP_URL must be your server's **publicly accessible** URL (not localhost).

### Check current configuration:
```bash
vault kv get secret/lattice/services
```

### Update APP_URL (preserving other fields):

First, get the current configuration to preserve other secrets:
```bash
# Get current services config
vault kv get -format=json secret/lattice/services | jq '.data.data' > /tmp/services.json

# Edit the JSON file to update app_url
# Example: Change "app_url": "http://localhost:1993"
#       to "app_url": "https://yourserver.com"

# Write updated config back
vault kv put secret/lattice/services @/tmp/services.json
rm /tmp/services.json
```

**Or use patch to update just APP_URL:**
```bash
vault kv patch secret/lattice/services app_url="https://yourserver.com"
```

## Step 2: Add Bootstrap Servers (Optional)

If you want to connect to existing Lattice networks:

```bash
vault kv patch secret/lattice/services \
  LATTICE_BOOTSTRAP_SERVERS="https://server1.com,https://server2.com"
```

## Step 3: Create keys path for private key

Lattice will auto-generate the private key on first run, but the path must exist:

```bash
# Create empty keys secret (private_key will be auto-generated)
vault kv put secret/lattice/keys placeholder="will_be_replaced_by_init"
```

## Step 4: Verify Configuration

Check that everything is set correctly:

```bash
# Verify services config
vault kv get secret/lattice/services

# Should show:
# app_url: https://yourserver.com (your public URL)
# LATTICE_BOOTSTRAP_SERVERS: (optional, comma-separated list)

# Verify keys path exists
vault kv get secret/lattice/keys

# Should show:
# placeholder: will_be_replaced_by_init
# (After initialization, this will contain the private_key)
```

## Next Steps After Vault Configuration

Once Vault is configured:

1. **Initialize Lattice identity** (generates keypair, stores private key in Vault):
   ```bash
   python -c "from lattice.init_lattice import ensure_lattice_identity; ensure_lattice_identity()"
   ```

2. **Apply database schema**:
   ```bash
   psql -U lattice_admin -h localhost -d lattice -f deploy/lattice_schema.sql
   ```

3. **Start discovery daemon**:
   ```bash
   python -m uvicorn lattice.discovery_daemon:app --host 0.0.0.0 --port 1113
   ```

4. **Register your server's domain name** (optional, for custom domain):
   ```python
   from lattice.domain_registration import DomainRegistrationService
   svc = DomainRegistrationService()
   result = svc.register_domain("myserver", "your-server-uuid", "your-public-key")
   ```

## Security Notes

- **Never commit Vault tokens** to version control
- **Use HTTPS** for APP_URL in production
- **Restrict Vault access** to only the Lattice service account
- **Backup private key** - losing it means losing your Lattice identity
- **Monitor failed auth attempts** - endpoints are public-facing

## Troubleshooting

### "VAULT_ADDR not set"
```bash
export VAULT_ADDR='http://localhost:8200'
```

### "Permission denied"
Ensure your Vault token has write access to `secret/lattice/`:
```bash
vault token lookup
```

### "APP_URL still shows localhost"
Make sure you preserved all other secrets when updating:
```bash
# Correct approach - patch individual field
vault kv patch secret/lattice/services app_url="https://yourserver.com"

# NOT: vault kv put secret/lattice/services app_url="..."
# (This would delete all other fields!)
```

### "Lattice private key not found"
The private key is auto-generated on first `ensure_lattice_identity()` call. If missing:
```bash
python -c "from lattice.init_lattice import ensure_lattice_identity; print(ensure_lattice_identity())"
```
