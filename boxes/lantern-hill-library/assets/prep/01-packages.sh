#!/bin/sh
# Lantern Hill prep 01/05 -- packages.
# Everything the box's legitimate stack needs. Run as root (or via sudo)
# on the freshly cloned headless Debian 13 build box.
set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    sudo \
    apache2 \
    mariadb-server \
    python3 \
    python3-flask \
    python3-pymysql \
    python3-paramiko \
    auditd \
    rsyslog \
    iptables \
    curl

# rsyslog gives the box the classic flat logs (/var/log/auth.log,
# /var/log/syslog). The intrusion will target them later; the journal and
# audit trail are what survive.
systemctl enable --now rsyslog
echo "prep01: packages installed; rsyslog up"
