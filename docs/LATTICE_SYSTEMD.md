# Lattice Discovery Daemon systemd Service

This document describes how to set up the Lattice discovery daemon as a systemd service for production deployment.

## Service File

Create `/etc/systemd/system/lattice-discovery.service`:

```ini
[Unit]
Description=Lattice Discovery Daemon
Documentation=https://github.com/yourorg/botwithmemory
After=network.target postgresql.service vault.service
Wants=postgresql.service

[Service]
Type=simple
User=lattice
Group=lattice
WorkingDirectory=/opt/lattice

# Environment variables
Environment="PYTHONUNBUFFERED=1"
Environment="VAULT_ADDR=http://localhost:8200"
EnvironmentFile=/etc/lattice/lattice.env

# Start discovery daemon on port 1113
ExecStart=/opt/lattice/venv/bin/python -m uvicorn \
    lattice.discovery_daemon:app \
    --host 0.0.0.0 \
    --port 1113 \
    --log-level info

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/lattice/data
ReadOnlyPaths=/opt/lattice

# Resource limits
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

## Environment File

Create `/etc/lattice/lattice.env`:

```bash
# Vault configuration (AppRole authentication)
VAULT_ADDR=http://localhost:8200
VAULT_ROLE_ID=your-role-id-here
VAULT_SECRET_ID=your-secret-id-here

# Optional: Vault namespace (for Vault Enterprise)
# VAULT_NAMESPACE=lattice
```

**Security Note:** This file contains sensitive credentials. Protect it:
```bash
sudo chown root:lattice /etc/lattice/lattice.env
sudo chmod 640 /etc/lattice/lattice.env
```

## Installation Steps

### 1. Create Service User

```bash
# Create lattice system user if it doesn't exist
sudo useradd --system --no-create-home --shell /bin/false lattice

# Create necessary directories
sudo mkdir -p /opt/lattice/data
sudo chown -R lattice:lattice /opt/lattice/data
```

### 2. Install Service File

```bash
# Copy service file
sudo cp /path/to/lattice-discovery.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 3. Configure Environment

```bash
# Create config directory
sudo mkdir -p /etc/lattice

# Create environment file with your credentials
sudo nano /etc/lattice/lattice.env

# Set permissions
sudo chown root:lattice /etc/lattice/lattice.env
sudo chmod 640 /etc/lattice/lattice.env
```

### 4. Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable lattice-discovery

# Start service
sudo systemctl start lattice-discovery

# Check status
sudo systemctl status lattice-discovery
```

## Service Management

### View Logs

```bash
# Follow logs in real-time
sudo journalctl -u lattice-discovery -f

# View last 100 lines
sudo journalctl -u lattice-discovery -n 100

# View logs since boot
sudo journalctl -u lattice-discovery -b
```

### Control Service

```bash
# Start service
sudo systemctl start lattice-discovery

# Stop service
sudo systemctl stop lattice-discovery

# Restart service
sudo systemctl restart lattice-discovery

# Reload configuration (if supported)
sudo systemctl reload lattice-discovery

# Check status
sudo systemctl status lattice-discovery
```

### Troubleshooting

#### Service won't start

```bash
# Check service status for errors
sudo systemctl status lattice-discovery

# Check recent logs
sudo journalctl -u lattice-discovery -n 50

# Verify environment file
sudo cat /etc/lattice/lattice.env

# Test manually as lattice user
sudo -u lattice /opt/lattice/venv/bin/python -m uvicorn lattice.discovery_daemon:app --port 1113
```

#### Can't connect to Vault

```bash
# Verify Vault is running
sudo systemctl status vault

# Test Vault connection
vault status

# Check environment variables
sudo systemctl show lattice-discovery | grep Environment
```

#### Port 1113 already in use

```bash
# Check what's using the port
sudo lsof -i :1113

# Or use netstat
sudo netstat -tlnp | grep 1113
```

## Integration with Main Application

The main application schedules periodic HTTP calls to the discovery daemon:

- **Gossip rounds**: `POST http://localhost:1113/api/v1/announce` (every 10 minutes)
- **Neighbor updates**: `POST http://localhost:1113/api/v1/maintenance/update_neighbors` (every 6 hours)
- **Cleanup**: `POST http://localhost:1113/api/v1/maintenance/cleanup` (daily)

These are registered automatically when the application starts (see `lattice/init_lattice.py`).

## Monitoring

### Health Check

```bash
# Check if daemon is responding
curl http://localhost:1113/api/v1/peers

# Expected: JSON list of peer servers
```

### Service Metrics

```bash
# View service resource usage
systemctl status lattice-discovery

# Detailed resource stats
systemctl show lattice-discovery --property=MemoryCurrent,CPUUsage
```

## Security Best Practices

1. **Run as non-root user**: Service runs as `lattice` user with limited permissions
2. **Protect credentials**: Environment file is only readable by `root` and `lattice` group
3. **Filesystem restrictions**: Service has read-only access to application code
4. **Network binding**: Only binds to localhost (use reverse proxy for external access)
5. **Resource limits**: Memory and CPU limits prevent resource exhaustion
6. **Restart policy**: Automatic restart on failure with backoff

## Reverse Proxy Configuration (Nginx)

For external federation access, configure nginx:

```nginx
# Federation discovery daemon (port 1113)
location /discovery/ {
    proxy_pass http://localhost:1113/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Timeout settings for long-polling if needed
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

Then reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

## Upgrading

When deploying new versions:

```bash
# Stop service
sudo systemctl stop lattice-discovery

# Update code
cd /opt/lattice
sudo -u lattice git pull

# Restart service
sudo systemctl start lattice-discovery

# Verify
sudo systemctl status lattice-discovery
```

## Uninstallation

To remove the service:

```bash
# Stop and disable
sudo systemctl stop lattice-discovery
sudo systemctl disable lattice-discovery

# Remove service file
sudo rm /etc/systemd/system/lattice-discovery.service

# Reload systemd
sudo systemctl daemon-reload
```
