#!/bin/sh
# Broadneck Post template prep -- step 5: the rotation that saves the
# evidence. The blast currently sits in the live /var/log/mail.log, which
# the wiper cron (planted right after the snapshot) will truncate every
# minute, and which the sabotage (90) truncates once more. Rotating NOW
# archives the whole run into mail.log.1, which neither the wiper (it
# only ever names the live file) nor the sabotage touches. This is the
# intruder's one mistake, and it is why the investigation is possible.
set -eu

[ -s /var/log/mail.log ] || { echo "85-rotate: mail.log missing/empty"; exit 1; }

mv /var/log/mail.log /var/log/mail.log.1
systemctl kill -s HUP rsyslog 2>/dev/null || kill -HUP "$(pidof rsyslogd)" 2>/dev/null || true
sleep 2
# rsyslog recreates the live file on its next write; seed it with the
# stock perms so nothing races (wiper cron, first inbound mail).
if [ ! -f /var/log/mail.log ]; then
    touch /var/log/mail.log
    chown root:adm /var/log/mail.log
    chmod 0640 /var/log/mail.log
    systemctl kill -s HUP rsyslog 2>/dev/null || true
fi

COUNT=$(grep -c 'client=unknown\[198.51.100.23\]' /var/log/mail.log.1)
if [ "$COUNT" -ne 40 ]; then
    echo "85-rotate: expected 40 alias-address lines in mail.log.1, got $COUNT"
    exit 1
fi
echo "85-rotate: archived mail.log -> mail.log.1 with $COUNT blast client lines; live log recreated"
