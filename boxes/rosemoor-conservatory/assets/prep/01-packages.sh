#!/bin/sh
# Rosemoor prep 01/05 -- packages for the glasshouse stack: the dashboard's
# database, its session cache, the app runtime, the host firewall, and the
# audit trail. Everything else on the box arrives as a nakon plant.
set -eu
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
    mariadb-server \
    redis-server \
    python3 \
    python3-flask \
    ufw \
    auditd \
    curl

systemctl enable --now mariadb
systemctl enable --now redis-server || systemctl enable --now redis || true

echo "prep01: packages ready (mariadb, redis, flask, ufw, auditd)"
