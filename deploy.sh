#!/bin/bash
# Quick deployment script for subscription-convert
# Usage: ./deploy.sh [systemd|docker|direct]

set -e

DEPLOY_MODE="${1:-direct}"
APP_DIR="$(cd "$(dirname "$0")" && pwd)"

case "$DEPLOY_MODE" in
  docker)
    echo "=== Deploying with Docker ==="
    cd "$APP_DIR"
    docker compose up -d --build
    echo "Service running at http://localhost:5000"
    ;;

  systemd)
    echo "=== Deploying with systemd ==="
    SERVICE_FILE="/etc/systemd/system/sub-convert.service"
    sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Subscription Converter (Mihomo -> Dae/daed)
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$HOME/.local/bin/uv run gunicorn -w 4 -b 0.0.0.0:5000 main:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable --now sub-convert
    echo "Service installed. Check: sudo systemctl status sub-convert"
    echo "Service running at http://localhost:5000"
    ;;

  direct)
    echo "=== Running directly (development mode) ==="
    cd "$APP_DIR"
    uv run python main.py
    ;;

  *)
    echo "Usage: $0 [docker|systemd|direct]"
    exit 1
    ;;
esac
