#!/bin/sh
# Tamarack Regional Airport template prep -- step 1: accounts & identity.
# The display stack itself (nginx / PostgreSQL / Redis) is planted by the
# nakon config at `boxbuilder plant` time; this script only builds the
# people and the places the story needs.
set -eu

# --- build-time tooling (broadneck lessons: the base image ships neither
# iptables nor paramiko; the firewall-rule plant and the replay need them)
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends iptables python3-paramiko curl

# --- the player: operations desk lead (sudo, ssh) --------------------------
if ! id flightops >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo flightops
fi
echo 'flightops:flightops' | chpasswd
install -d -m 0755 /home/flightops/Desktop

# --- the service identity that was built wrong -----------------------------
# Display renderer account. It should never own a shell -- the check grades
# the shell, the finding is "created with one".
if ! id svc-boards >/dev/null 2>&1; then
    useradd -r -m -s /bin/bash svc-boards
fi

# --- the entry point: a contractor account nobody retired ------------------
# Weak password on purpose: the replay's guessing run lands on it on the
# fifth try. The respawn machinery planted later keeps re-creating it with
# the SAME password, so the plant and the replay always agree.
if ! id fieldsvc >/dev/null 2>&1; then
    useradd -m -s /bin/bash fieldsvc
fi
echo 'fieldsvc:SkylarkField22!' | chpasswd

# --- root password for the build -------------------------------------------
echo 'root:TamarackRoot2026!' | chpasswd

# --- identity ---------------------------------------------------------------
hostnamectl set-hostname tamarack-fids 2>/dev/null || {
    hostname tamarack-fids
    echo tamarack-fids > /etc/hostname
}
sed -i '/tamarack-fids/d' /etc/hosts
echo "127.0.1.1	tamarack-fids tamarack-fids" >> /etc/hosts

timedatectl set-timezone America/New_York 2>/dev/null || \
    ln -sf /usr/share/zoneinfo/America/New_York /etc/localtime

# Password auth for regular users stays ON (broadneck precedent): it is the
# player's own access path, and the guessing run needs it live. No root
# drop-in here -- ssh-root-login plants that at plant time.

echo "01-accounts: roster ready: $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | tr '\n' ' ')"
