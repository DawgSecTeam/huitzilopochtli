#!/bin/sh
# Rosemoor prep 05/05 -- the audit trail + persistent journal. These are the
# records the anti-forensics plants (journal vacuum, log erasure) do NOT
# touch, which is what keeps this box's incident solvable; the journal disk
# finding and the vacuum cron ride on top of this baseline.
set -eu

systemctl enable --now auditd 2>/dev/null || true

install -m 0640 /dev/null /etc/audit/rules.d/75-glasshouse-ir.rules
cat > /etc/audit/rules.d/75-glasshouse-ir.rules <<'EOF'
# identity + privilege events (the IR spine)
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
# time tampering
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
# sudo usage
-a always,exit -F arch=b64 -S execve -F euid=0 -k sudo-exec
EOF
augenrules --load 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true

mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
systemctl restart systemd-journald 2>/dev/null || true

echo "prep05: auditd rules + persistent journal in place"
