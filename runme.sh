#!/bin/bash
set -e

# Phase 1: Prerequisites
echo "Checking prerequisites..."

if [ "$EUID" -eq 0 ]; then
    echo "Error: Don't run as root"
    exit 1
fi

command -v python3 >/dev/null || { echo "Error: python3 not found"; exit 1; }
command -v git >/dev/null || { echo "Error: git not found"; exit 1; }
python3 -c "import venv" 2>/dev/null || { echo "Error: python3-venv not installed. Run: sudo apt install python3-venv"; exit 1; }

echo "Prerequisites OK"

# Phase 2: Get the Code
echo "Downloading Lattice..."

INSTALL_DIR="/opt/lattice"

if [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/requirements.txt" ]; then
    echo "Lattice already exists at $INSTALL_DIR"
else
    sudo mkdir -p "$INSTALL_DIR"
    sudo chown "$(whoami)" "$INSTALL_DIR"
    git clone --depth 1 https://github.com/taylorsatula/lattice.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
echo "Now in: $(pwd)"

# Phase 3: Python Environment
echo "Setting up Python environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

./venv/bin/pip install -q -r requirements.txt
echo "Dependencies installed"

# Phase 4: Configuration
echo ""
read -p "Enter your server URL (e.g., https://example.com): " APP_URL
if [ -z "$APP_URL" ]; then
    echo "Error: Server URL required"
    exit 1
fi

read -p "Server name, used in addresses like user@name (blank for random): " DOMAIN

ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"

sudo mkdir -p /etc/lattice
sudo chown -R "$(whoami)" /etc/lattice
cat > /etc/lattice/config.env <<EOF
APP_URL=$APP_URL
LATTICE_ADMIN_TOKEN=$ADMIN_TOKEN
EOF
if [ -n "$DOMAIN" ]; then
    echo "LATTICE_DOMAIN=$DOMAIN" >> /etc/lattice/config.env
fi
chmod 600 /etc/lattice/config.env
echo "Config written to /etc/lattice/config.env"

# Phase 5: Identity
echo "Initializing Lattice identity..."

mkdir -p "$INSTALL_DIR/data" "$INSTALL_DIR/logs"
LATTICE_DB_PATH="$INSTALL_DIR/data/lattice.db" ./venv/bin/python3 -c "
from lattice.identity import Identity
from lattice.sqlite_client import SQLiteClient
identity = Identity.load_or_create(SQLiteClient())
print(f'Server ID:  {identity.server_id}')
print(f'UUID:       {identity.server_uuid}')
print(f'Public key: {identity.public_key}')
"

# Phase 6: Systemd
echo "Setting up systemd service..."

if command -v useradd >/dev/null 2>&1; then
    if ! id -u lattice >/dev/null 2>&1; then
        sudo useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin lattice
    fi
    SERVICE_USER="lattice"
    SERVICE_GROUP="lattice"
else
    SERVICE_USER="$(whoami)"
    SERVICE_GROUP="$(id -gn)"
fi
sudo chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR" /etc/lattice

sudo tee /etc/systemd/system/lattice.service > /dev/null <<EOF
[Unit]
Description=Lattice Discovery Daemon
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
Environment="LATTICE_DB_PATH=$INSTALL_DIR/data/lattice.db"
LoadCredential=private_key:/etc/lattice/private_key.pem
LoadCredential=config:/etc/lattice/config.env
ExecStart=$INSTALL_DIR/venv/bin/uvicorn lattice.discovery_daemon:app --host 0.0.0.0 --port 1113 --workers 1
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_DIR/data $INSTALL_DIR/logs /etc/lattice

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable lattice
sudo systemctl start lattice

# Phase 7: Verify
echo "Waiting for service to start..."
sleep 3

if curl -s http://localhost:1113/status >/dev/null; then
    echo "SUCCESS: Lattice is running"
    curl -s http://localhost:1113/status
else
    echo "Warning: Service may not be running. Check: journalctl -u lattice -n 20"
fi

# Phase 8: Pair
echo ""
echo "Lattice servers trust each other only through invites carried out of band."
read -p "Paste an invite token from an existing Lattice server (blank to skip): " INVITE
if [ -n "$INVITE" ]; then
    LATTICE_ADMIN_TOKEN="$ADMIN_TOKEN" ./venv/bin/python3 -m lattice accept "$INVITE" || echo "Warning: pairing failed; retry with: python3 -m lattice accept TOKEN"
fi

echo ""
echo "Done. Manage with: sudo systemctl {start|stop|status} lattice"
echo "Invite another server: sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python3 -m lattice invite"
