#!/usr/bin/env bash
# ==============================================================================
# Setup Script for smonitor on Linux / Raspberry Pi (Least Privilege + systemd)
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] Please run this script as root (sudo)."
   exit 1
fi

ARCH=$(uname -m)
DEFAULT_BIN="bin/smonitor-linux-arm64"
if [[ "$ARCH" == "armv7l" || "$ARCH" == "armhf" ]]; then
    DEFAULT_BIN="bin/smonitor-linux-armv7"
elif [[ "$ARCH" == "x86_64" ]]; then
    DEFAULT_BIN="bin/smonitor-linux-amd64"
fi

BINARY_SRC="${1:-$DEFAULT_BIN}"
if [[ ! -f "$BINARY_SRC" && -f "bin/smonitor" ]]; then
    BINARY_SRC="bin/smonitor"
fi

if [[ ! -f "$BINARY_SRC" ]]; then
    echo "[ERROR] Binary not found at $BINARY_SRC. Build it first (e.g. 'make build-linux-arm64')."
    exit 1
fi

echo "[1/6] Creating dedicated service user 'smonitor'..."
if ! id -u smonitor >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -M -d /var/lib/smonitor smonitor
fi

echo "[2/6] Creating /var/lib/smonitor (0750)..."
mkdir -p /var/lib/smonitor
chown -R smonitor:smonitor /var/lib/smonitor
chmod 750 /var/lib/smonitor

echo "[3/6] Creating /etc/smonitor and installing default ranges.json if missing..."
mkdir -p /etc/smonitor
if [[ ! -f /etc/smonitor/ranges.json ]]; then
    cp ranges.example.json /etc/smonitor/ranges.json
fi
chown -R root:smonitor /etc/smonitor
chmod 750 /etc/smonitor
chmod 640 /etc/smonitor/ranges.json

echo "[4/6] Installing binary to /usr/local/bin/smonitor..."
install -m 755 "$BINARY_SRC" /usr/local/bin/smonitor

echo "[5/6] Granting CAP_NET_RAW capability for rootless ICMP ping & traceroute..."
setcap cap_net_raw+ep /usr/local/bin/smonitor
getcap /usr/local/bin/smonitor

echo "[6/6] Installing systemd unit..."
if [[ -f scripts/smonitor.service ]]; then
    cp scripts/smonitor.service /etc/systemd/system/smonitor.service
    systemctl daemon-reload
fi

echo ""
echo "=== Setup complete ==="
echo "1. Edit IP ranges:  sudo nano /etc/smonitor/ranges.json"
echo "2. Test single run: sudo -u smonitor /usr/local/bin/smonitor --scan-once --ranges /etc/smonitor/ranges.json --db /var/lib/smonitor/smonitor.db"
echo "3. Start daemon:    sudo systemctl enable --now smonitor"
