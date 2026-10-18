#!/bin/sh
# Lantern Hill prep 05/05 -- the flight recorders: auditd with the IR
# watchlist LOADED BEFORE ANY PLANT, and persistent journald so every log
# source survives reboots and the seal. The nakon plants that follow this
# script write files under watched paths, so the intrusion's own artifacts
# land in /var/log/audit/audit.log with timestamps.
set -eu

# -- auditd + rules --------------------------------------------------------------
systemctl enable --now auditd
install -m 0640 /root/lantern-prep/75-library-ir.rules /etc/audit/rules.d/75-library-ir.rules
augenrules --load
if [ "$(auditctl -l 2>/dev/null | grep -c .)" -lt 3 ]; then
    echo "prep05: FATAL -- audit rules did not load" >&2
    exit 1
fi

# -- persistent journal -----------------------------------------------------------
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
journalctl --flush

echo "prep05: auditd rules loaded ($(auditctl -l 2>/dev/null | grep -c .) rules); journal persistent"
