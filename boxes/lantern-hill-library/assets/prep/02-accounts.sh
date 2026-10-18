#!/bin/sh
# Lantern Hill prep 02/05 -- accounts, hostname, clock, and the SSH root
# cause. The weak sshd drop-in is PREP-BAKED (a pre-existing vendor
# misconfiguration -- the root cause the intrusion exploited), not a nakon
# plant: the attacker replay in 90 needs password root login live so the
# journal records real "Accepted password" evidence. The three sshd checks
# in scenario.yaml grade the hardened effective state via `sshd -T`.
#
# Run as root. NOTE: this script deletes the stock `sysadmin`/`ubuntu`
# users (the base template ships them; the agent resolves the forensics
# file to the lowest-numbered real user and a stray uid-1000 hijacks it).
# After this script, connect to the box as `librarian` only.
set -eu

# -- the staff account (the player) ------------------------------------------
if ! id librarian >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo librarian
fi
echo 'librarian:librarian' | chpasswd
install -d -o librarian -g librarian -m 0755 /home/librarian/Desktop

# -- the catalog app's service identity (story-legitimate; KEEP) -------------
if ! id catalogsvc >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin catalogsvc
fi

# -- hostname + the library's real timezone (the plant will tamper it) -------
hostnamectl set-hostname lanternhill-catalog || true
timedatectl set-timezone America/New_York

# -- cloud-init must NEVER wipe the planted /etc/hosts redirect ---------------
# The Proxmox cloudinit seed (DataSourceNoCloud, /dev/sr0) ships user-data
# with `manage_etc_hosts: true`, and user-data outranks anything placed in
# /etc/cloud/cloud.cfg.d -- so on every fresh clone's first boot cloud-init
# re-renders /etc/hosts from its template, wiping anything planted into the
# live file (a scored finding AND a forensics answer). The durable fix:
# plant the redirect INTO the master template itself. The render is
# per-instance (once per clone's lifetime), so a player's fix still sticks
# after their first boot.
tmpl=/etc/cloud/templates/hosts.debian.tmpl
grep -qF '203.0.113.7' "$tmpl" || \
    printf '%s\n' "203.0.113.7   updates.lanternhill-library.org" >> "$tmpl"

# -- PRE-EXISTING weak sshd configuration (the root cause) --------------------
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-catalog-remote.conf <<'EOF'
PermitRootLogin yes
PermitEmptyPasswords yes
X11Forwarding yes
AllowTcpForwarding yes
EOF
if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
    printf '\nInclude /etc/ssh/sshd_config.d/*.conf\n' >> /etc/ssh/sshd_config
fi
systemctl restart ssh 2>/dev/null || systemctl restart sshd

# -- the credential the brute force will find (root cause #2) -----------------
echo 'root:LanternHill2026!' | chpasswd

# -- drop the base template's stray users (opochtli lesson) -------------------
userdel -r sysadmin 2>/dev/null || true
userdel -r ubuntu 2>/dev/null || true

echo "prep02: librarian/catalogsvc ready, sshd weakened, clock on America/New_York"
echo "prep02: from here on, reach the box as librarian (password: librarian)"
