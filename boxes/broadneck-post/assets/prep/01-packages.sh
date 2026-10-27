#!/bin/sh
# Broadneck Post template prep -- step 1: packages.
# The mail stack stays INSTALLED through the whole incident; only its
# configuration, certs, and service state get destroyed later (90), so the
# players rebuild the config without ever needing apt on the sealed box.
set -eu

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
    postfix \
    dovecot-core dovecot-imapd dovecot-pop3d \
    rsyslog \
    iptables \
    curl \
    python3 python3-paramiko

# The flat logs are part of the story: the wiper truncates the live ones,
# the rotation saves the mail log, the journal survives everything.
systemctl enable --now rsyslog
systemctl restart rsyslog

# dovecot-imapd/pop3d pull in the protocols; make sure the services exist
# and are set to the post-install enabled state (03 configures them).
systemctl cat postfix >/dev/null 2>&1 || true
systemctl cat dovecot >/dev/null 2>&1 || true

echo "01-packages: stack installed: $(dpkg -l | grep -cE 'postfix|dovecot-')"
