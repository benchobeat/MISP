#!/usr/bin/env bash
# =============================================================================
# QRadar-MISP Sync - Installation Script
# =============================================================================
# Run as root or with sudo.
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/qradar-misp-sync"
CONFIG_DIR="/etc/qradar-misp-sync"
STATE_DIR="/var/lib/qradar-misp-sync"
SERVICE_USER="qradar-misp-sync"

echo "=== QRadar-MISP Sync Installer ==="

# 1. Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# 2. Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"

# 3. Install Python package
echo "Installing Python package..."
pip3 install --target="$INSTALL_DIR" -e .

# 4. Create symlink for CLI
echo "Creating CLI symlink..."
ln -sf "$INSTALL_DIR/bin/qradar-misp-sync" /usr/local/bin/qradar-misp-sync 2>/dev/null || true
# Fallback: install via pip into system path
pip3 install -e .

# 5. Copy config template (don't overwrite existing)
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo "Copying config template..."
    cp config/config.example.yaml "$CONFIG_DIR/config.yaml"
    chmod 600 "$CONFIG_DIR/config.yaml"
    chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.yaml"
    echo ""
    echo "*** IMPORTANT: Edit $CONFIG_DIR/config.yaml with your QRadar and MISP credentials ***"
    echo ""
else
    echo "Config file already exists at $CONFIG_DIR/config.yaml (not overwritten)"
fi

# 6. Install systemd service
echo "Installing systemd service..."
cp systemd/qradar-misp-sync.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:    sudo nano $CONFIG_DIR/config.yaml"
echo "  2. Test connection: qradar-misp-sync --config $CONFIG_DIR/config.yaml --test"
echo "  3. Test single run: qradar-misp-sync --config $CONFIG_DIR/config.yaml --once -v"
echo "  4. Enable service:  sudo systemctl enable qradar-misp-sync"
echo "  5. Start service:   sudo systemctl start qradar-misp-sync"
echo "  6. Check logs:      sudo journalctl -u qradar-misp-sync -f"
