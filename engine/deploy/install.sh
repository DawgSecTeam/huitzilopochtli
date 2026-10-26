#!/usr/bin/env bash
# Install the huitzilopochtli engine on an Ubuntu/Debian host.
# Run as root from an unpacked bundle that contains common/ and engine/.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR=/opt/huitzilopochtli/engine
ETC_DIR=/etc/huitzilopochtli
STATE_DIR=/var/lib/huitzilopochtli
BACKUP_DIR=/var/backups/huitzilopochtli
ENV_FILE="$ETC_DIR/engine.env"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3 ca-certificates curl ufw qemu-guest-agent chrony >/dev/null

id -u huitz >/dev/null 2>&1 || useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin huitz
install -d -o root -g root -m 755 /opt/huitzilopochtli
install -d -o root -g root -m 755 "$APP_DIR" "$APP_DIR/common" "$APP_DIR/engine" "$APP_DIR/deploy"
chmod -R u+w "$APP_DIR" 2>/dev/null || true
cp -a "$SRC_DIR/common/." "$APP_DIR/common/"
cp -a "$SRC_DIR/engine/." "$APP_DIR/engine/"
cp -a "$SRC_DIR/engine/deploy/." "$APP_DIR/deploy/"
chown -R root:root /opt/huitzilopochtli
chmod -R a-w /opt/huitzilopochtli
install -d -o huitz -g huitz -m 700 "$STATE_DIR" "$BACKUP_DIR"
install -d -o root -g huitz -m 750 "$ETC_DIR"

if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASS="${HUITZ_ADMIN_PASSWORD:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(18))')}"
  SERVER_SECRET="${HUITZ_SERVER_SECRET:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')}"
  cat > "$ENV_FILE" <<EOF
HUITZILOPOCHTLI_BIND=${HUITZ_BIND:-0.0.0.0}
HUITZILOPOCHTLI_PORT=${HUITZ_PORT:-8080}
HUITZILOPOCHTLI_DB_PATH=$STATE_DIR/engine.db
HUITZILOPOCHTLI_ADMIN_USER=${HUITZ_ADMIN_USER:-admin}
HUITZILOPOCHTLI_ADMIN_PASSWORD=$ADMIN_PASS
HUITZILOPOCHTLI_SERVER_SECRET=$SERVER_SECRET
HUITZILOPOCHTLI_CHECKIN_INTERVAL_S=${HUITZ_CHECKIN_INTERVAL_S:-60}
HUITZILOPOCHTLI_RATE_LIMIT_PER_MIN=600
HUITZILOPOCHTLI_RATE_BURST=100
HUITZILOPOCHTLI_MAX_CONNS=128
HUITZILOPOCHTLI_MAX_VERIFY=4
HUITZILOPOCHTLI_WORKSHOP_URL=${HUITZ_WORKSHOP_URL:-}
HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD=${HUITZ_WORKSHOP_ADMIN_PASSWORD:-}
# Shared with the portal's HUITZ_PREBIND_SECRET. Setting only one side is
# harmless (the engine falls back to manual join), but you want both.
HUITZILOPOCHTLI_WORKSHOP_SECRET=${HUITZ_WORKSHOP_SECRET:-}
HUITZILOPOCHTLI_SWEEP_INTERVAL_S=${HUITZ_SWEEP_INTERVAL_S:-15}
HUITZILOPOCHTLI_PUBLIC_URL=${HUITZ_PUBLIC_URL:-http://127.0.0.1:8080}
EOF
  chmod 600 "$ENV_FILE"
  chown root:root "$ENV_FILE"
  install -m 600 /dev/null /root/huitz-engine-credentials.txt
  cat > /root/huitz-engine-credentials.txt <<EOF
HUITZILOPOCHTLI_ADMIN_USER=${HUITZ_ADMIN_USER:-admin}
HUITZILOPOCHTLI_ADMIN_PASSWORD=$ADMIN_PASS
EOF
  chmod 600 /root/huitz-engine-credentials.txt
fi

install -m 644 "$APP_DIR/deploy/huitzilopochtli-engine.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/huitzilopochtli-backup.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/huitzilopochtli-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now huitzilopochtli-engine.service
systemctl enable --now huitzilopochtli-backup.timer

ufw allow 22/tcp >/dev/null || true
ufw allow 8080/tcp >/dev/null || true
ufw --force enable >/dev/null || true

sleep 1
curl -fsS "http://127.0.0.1:${HUITZ_PORT:-8080}/health" || {
  echo "engine did not become healthy; check: journalctl -u huitzilopochtli-engine -n 50" >&2
  exit 1
}
echo "engine installed and healthy"
