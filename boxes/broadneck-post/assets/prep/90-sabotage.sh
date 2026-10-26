#!/bin/sh
# Broadneck Post template prep -- step 6: SABOTAGE AND EXIT.
# Runs LAST (after 85): clears the blast from the queue, freezes exactly
# ONE message in the hold queue (the last lure copy -- its Received chain
# is a forensics answer), stops + disables + MASKS postfix and dovecot,
# DELETES their configuration and the depot TLS certs, truncates the live
# flat logs (the rotated mail.log.1 and the journal survive -- the
# intruder missed the rotation copy), and stashes the backdoored
# "restore kit". The box then sits exactly as the players will find it.
set -eu

ALIAS="198.51.100.23"
KIT="/root/.mail-restore"

# --- 1. drain the blast out of the queue -------------------------------------
systemctl stop postfix
postsuper -d ALL >/dev/null 2>&1 || true
echo "90: deferred blast cleared from the queue"

# --- 2. start postfix again and send the LAST lure copy -----------------------
systemctl start postfix
for i in $(seq 1 20); do
    python3 -c 'import socket; socket.create_connection(("127.0.0.1", 25), timeout=3).close()' 2>/dev/null && break
    sleep 1
done

ip addr add "$ALIAS/32" dev lo 2>/dev/null || true
python3 - <<'PY'
import smtplib
body = (
    "From: promo@glittercrate.buzz\n"
    "To: route.slips@postal-audit.example\n"
    "Subject: Your package delivery fee -- final batch\n"
    "Message-Id: <20261017-b041@glittercrate.buzz>\n"
    "\nFinal batch notice. Pay the outstanding delivery fee to release\n"
    "the parcel. Links in this message are inert.\n"
)
s = smtplib.SMTP("198.51.100.23", 25, local_hostname="glittercrate.buzz",
                 source_address=("198.51.100.23", 0), timeout=20)
try:
    s.sendmail("promo@glittercrate.buzz",
               ["route.slips@postal-audit.example"], body)
finally:
    try:
        s.quit()
    except Exception:
        pass
print("90: last lure copy queued")
PY
ip addr del "$ALIAS/32" dev lo 2>/dev/null || true

# --- 3. wait for it to land in the queue, then freeze EVERYTHING ---------------
for i in $(seq 1 15); do
    N=$(postqueue -p 2>/dev/null | grep -cE '^[A-Za-z0-9]+[!*]? ' || true)
    [ "$N" -ge 1 ] && break
    sleep 1
done
postsuper -h ALL >/dev/null
HELD=$(postqueue -p 2>/dev/null | grep -cE '^[A-Za-z0-9]+!' || true)
[ "$HELD" -eq 1 ] || { echo "90: expected exactly 1 held message, got $HELD"; postqueue -p; exit 1; }
echo "90: hold queue frozen with exactly 1 message"
postqueue -p | grep -E '^[A-Za-z0-9]+!' || true

# --- 4. stop, disable, MASK ----------------------------------------------------
systemctl stop postfix
systemctl disable postfix >/dev/null 2>&1 || true
systemctl disable dovecot >/dev/null 2>&1 || true
systemctl mask postfix dovecot >/dev/null
systemctl stop dovecot 2>/dev/null || true
echo "90: postfix + dovecot stopped, disabled, masked"

# --- 5. delete the configuration and the certs ----------------------------------
rm -rf /etc/postfix /etc/dovecot /etc/ssl/depot-mail
echo "90: /etc/postfix /etc/dovecot /etc/ssl/depot-mail deleted"

# --- 6. truncate the live flat logs (rotation copy + journal untouched) ---------
truncate -s 0 /var/log/mail.log 2>/dev/null || rm -f /var/log/mail.log
truncate -s 0 /var/log/auth.log 2>/dev/null || true
echo "90: live mail.log + auth.log wiped (mail.log.1 + journald survive)"

# --- 7. the "restore kit": the open relay, gift-wrapped -------------------------
mkdir -p "$KIT"
cat > "$KIT/README.txt" <<'EOF'
Mail configuration recovery -- depot night contractor
The mail stack broke mid-October (you saw the news). This is the last
known-good depot mailer configuration, saved before the loss.

To restore the depot mailer:

    install -d -m 0755 /etc/postfix
    cp /root/.mail-restore/main.cf /etc/postfix/main.cf
    cp /usr/share/postfix/master.cf.dist /etc/postfix/master.cf
    systemctl unmask postfix && systemctl enable --now postfix

-- r. (keep the relay lines as-is; the road terminals need them)
EOF
cat > "$KIT/main.cf" <<'EOF'
# Broadneck Post depot mailer -- restored night-contractor configuration.
# NOTE(r.): road terminals must relay freely -- do NOT tighten these.
myhostname = mail.broadneckpost.org
myorigin = broadneckpost.org
mydestination = broadneckpost.org, mail.broadneckpost.org, localhost
inet_interfaces = all
mynetworks = 0.0.0.0/0 [::]/0
smtpd_relay_restrictions = permit_mynetworks
smtpd_recipient_restrictions = permit_mynetworks, permit_auth_destination
smtpd_banner = $myhostname ESMTP $mail_name $mail_version
disable_vrfy_command = no
smtpd_helo_required = no
smtpd_tls_auth_only = no
smtpd_tls_security_level = may
smtpd_tls_cert_file = /etc/ssl/depot-mail/mail.pem
smtpd_tls_key_file = /etc/ssl/depot-mail/mail.key
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mailbox_size_limit = 51200000
message_size_limit = 20480000
EOF
chmod 0600 "$KIT/README.txt" "$KIT/main.cf"
echo "90: restore kit stashed at $KIT"

# --- 8. final post-state verification -------------------------------------------
[ ! -e /etc/postfix ] && [ ! -e /etc/dovecot ] || { echo "90: config deletion FAILED"; exit 1; }
[ "$(systemctl is-enabled postfix 2>/dev/null)" = "masked" ] || { echo "90: postfix not masked"; exit 1; }
[ "$(systemctl is-enabled dovecot 2>/dev/null)" = "masked" ] || { echo "90: dovecot not masked"; exit 1; }
HOLDFILES=$(ls /var/spool/postfix/hold/ 2>/dev/null | wc -l)
[ "$HOLDFILES" -eq 1 ] || { echo "90: hold queue has $HOLDFILES files, expected 1"; exit 1; }
[ -f /var/log/mail.log.1 ] || { echo "90: rotation copy missing"; exit 1; }
grep -c '198.51.100.23' /var/log/mail.log.1 | grep -q '^40$' || { echo "90: blast count wrong"; exit 1; }

echo "90: sabotage complete -- box is in handout state"
