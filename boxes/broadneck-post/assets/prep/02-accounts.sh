#!/bin/sh
# Broadneck Post template prep -- step 2: accounts, identity, journald.
set -eu

# --- the player and the mail users -----------------------------------------
if ! id postmaster >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo postmaster
fi
echo 'postmaster:postmaster' | chpasswd
install -d -m 0755 /home/postmaster/Desktop

# Mail users: dovecot auths them through PAM, so they need passwords (the
# depot used username=password for its shared terminals). nologin shells:
# nobody should ssh in as a mailbox owner.
for u in dispatch routes freight; do
    if ! id "$u" >/dev/null 2>&1; then
        useradd -m -s /usr/sbin/nologin "$u"
    fi
    echo "$u:$u" | chpasswd
done

# --- the entry point: an ex-contractor account nobody retired ---------------
# Weak password on purpose: the replay's guessing run lands on it in five
# tries. Its home keeps the intruder's partially-cleared bash history.
if ! id routeaudit >/dev/null 2>&1; then
    useradd -m -s /bin/bash routeaudit
fi
echo 'routeaudit:AutumnRoute88' | chpasswd
chage -d 2026-09-30 routeaudit 2>/dev/null || true   # last "contract day"

# --- root password for the replay -------------------------------------------
echo 'root:BroadneckRoot2026!' | chpasswd

# --- identity ----------------------------------------------------------------
hostnamectl set-hostname broadneck-mailer 2>/dev/null || {
    hostname broadneck-mailer
    echo broadneck-mailer > /etc/hostname
}
sed -i '/broadneck-mailer/d' /etc/hosts
echo "127.0.1.1	broadneck-mailer broadneck-mailer" >> /etc/hosts

timedatectl set-timezone America/New_York 2>/dev/null || \
    ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

# Password auth for REGULAR users stays on: the depot runs on shared
# terminal passwords, and the guessing run needs it live. (No root login
# drop-in here -- the base template's sshd hardening for root stays.)
cat > /etc/ssh/sshd_config.d/99-depot-remote.conf <<'EOF'
# depot shared-terminal logins (night contractor setup)
PasswordAuthentication yes
EOF
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true

# --- evict base-template strays (opochtli lesson: a stray uid-1000 hijacks
# forensics-path resolution) ---------------------------------------------------
for u in sysadmin ubuntu; do
    if id "$u" >/dev/null 2>&1; then
        userdel -r "$u" 2>/dev/null || userdel "$u" 2>/dev/null || true
    fi
done

# --- persistent journald: the ssh story must survive the auth.log wipe -----
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal 2>/dev/null || true
systemctl try-restart systemd-journald 2>/dev/null || true

echo "02-accounts: $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | tr '\n' ' ')"
