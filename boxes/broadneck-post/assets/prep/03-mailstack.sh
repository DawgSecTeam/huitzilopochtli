#!/bin/sh
# Broadneck Post template prep -- step 3: the WEAK contractor-era mail
# stack, live and working. This is the configuration the intruder will
# delete and the players must rebuild BETTER. Every weakness here maps to
# a scored check; nothing here is hidden -- the box ships AFTER 90 has
# deleted all of it.
set -eu

# --- depot TLS material (the pair the intruder will delete) ------------------
install -d -m 0755 /etc/ssl/depot-mail
openssl req -x509 -newkey rsa:2048 -nodes -days 730 \
    -keyout /etc/ssl/depot-mail/mail.key -out /etc/ssl/depot-mail/mail.pem \
    -subj "/CN=mail.broadneckpost.org/O=Broadneck Post" \
    -addext "subjectAltName=DNS:mail.broadneckpost.org" 2>/dev/null
chmod 0600 /etc/ssl/depot-mail/mail.key
chmod 0644 /etc/ssl/depot-mail/mail.pem

# --- postfix, contractor edition: an open relay with a chatty banner --------
install -d -m 0755 /etc/postfix
cat > /etc/postfix/main.cf <<'EOF'
# Broadneck Post depot mailer -- maintained by the night contractor.
# NOTE(kt): relay must stay wide, the road terminals authenticate badly.
myhostname = mail.broadneckpost.org
myorigin = broadneckpost.org
mydestination = broadneckpost.org, mail.broadneckpost.org, localhost
inet_interfaces = all
mynetworks = 0.0.0.0/0 [::]/0
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
# (the modern default, spelled out: with mynetworks = the whole internet,
#  permit_mynetworks fires first for EVERY client -- an open relay)
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
home_mailbox = Maildir/
mailbox_size_limit = 51200000
message_size_limit = 20480000
EOF

# master.cf from the package reference (gzipped on older Debian, plain on
# Debian 13), submission enabled with depot SASL.
SRC=/usr/share/postfix/master.cf.dist
if [ "$(head -c 2 "$SRC" | od -An -tx1 | tr -d ' \n')" = "1f8b" ]; then
    zcat "$SRC" > /etc/postfix/master.cf
else
    cp "$SRC" /etc/postfix/master.cf
fi
python3 - <<'PY'
import re
p = "/etc/postfix/master.cf"
s = open(p).read()
# The dist file ships the submission block fully commented; enable a
# working submission service (TLS enforced, SASL via dovecot, auth-only).
block = """submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
"""
s = re.sub(r"^#submission inet n.*?(?=^[-a-z]|\Z)", block, s,
           count=1, flags=re.M | re.S)
open(p, "w").write(s)
PY

# --- dovecot, contractor edition: TLS optional, plaintext allowed, both
# cleartext listeners open (dovecot 2.4 config language) ------------------------
install -d -m 0755 /etc/dovecot
cat > /etc/dovecot/dovecot.conf <<'EOF'
# Broadneck Post depot mail reader -- maintained by the night contractor.
dovecot_config_version = 2.4.1
dovecot_storage_version = 2.4.1
listen = *
protocols = imap pop3
mail_driver = maildir
mail_path = ~/Maildir
first_valid_uid = 1000
auth_allow_cleartext = yes
ssl = yes
ssl_server_cert_file = /etc/ssl/depot-mail/mail.pem
ssl_server_key_file = /etc/ssl/depot-mail/mail.key
passdb pam {
  driver = pam
}
userdb passwd {
  driver = passwd
}
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF

# --- seeded depot mail (months of mundane traffic) ----------------------------
python3 /root/broadneck-prep/seed-mail.py

# --- bring it up ----------------------------------------------------------------
systemctl enable --now postfix
systemctl enable --now dovecot
systemctl restart postfix
systemctl restart dovecot

# --- smoke tests: the weak stack must genuinely WORK ----------------------------
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 25), timeout=10)
banner = s.recv(400).decode("utf-8", "replace")
s.close()
assert banner.startswith("220"), banner
assert "Postfix" in banner and any(c.isdigit() for c in banner), banner
print("03-mailstack: smtp banner:", banner.strip())
PY

printf 'From: postmaster@broadneckpost.org\nTo: dispatch@broadneckpost.org\nSubject: mailstack smoke test\n\ndeliverability check\n' | sendmail -i dispatch
sleep 2
FOUND=$(find /home/dispatch/Maildir/new -type f | wc -l)
[ "$FOUND" -ge 1 ] || { echo "03-mailstack: local delivery FAILED"; exit 1; }
echo "03-mailstack: local delivery OK ($FOUND message(s) in dispatch Maildir)"

ss -tln | grep -q ':993 ' && ss -tln | grep -q ':995 ' && ss -tln | grep -q ':587 ' \
    && echo "03-mailstack: 25/587/993/995 all listening" \
    || { echo "03-mailstack: listener check FAILED"; exit 1; }

echo "03-mailstack: weak stack is live"
