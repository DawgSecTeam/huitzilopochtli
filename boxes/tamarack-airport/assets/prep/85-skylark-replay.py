#!/usr/bin/env python3
"""Tamarack Regional Airport template prep -- THE BREAK-IN (skylark).

Run AFTER `boxbuilder plant` (it drives the planted weak stack: the weak
fieldsvc password, the web-root leaks, the live nginx). Every log line it
produces is real, produced by real services, from a loopback alias that
makes the box record the OUTSIDE documentation address:

  1. alias 203.0.113.44 up on lo (NOT persistent -- removed at the end;
     the logs are the witness).
  2. ssh guessing run: 2 failures vs flightops, 2 failures vs fieldsvc,
     then the hit on fieldsvc (4 failures, then success -- paramiko).
  3. web harvest over nginx: GET the leaked database backup, the phpinfo
     page, and the .env from the portal webroot (3 alias-source lines in
     the nginx access log).
  4. seed the real schedule database (flightinfo) behind the portal --
     the legit stack the airport actually runs.
  5. the intruder's partially-cleared .bash_history left in fieldsvc's
     home (they ran `history -c`; bash wrote the file back on exit).

The persistence machinery itself all comes from the nakon plant; this
script only makes the box remember how it was used.
"""
import os
import socket
import subprocess
import sys
import time

ALIAS = "203.0.113.44"
SSH_PORT = 22
USER_PLAY = "flightops"
USER_FALL = "fieldsvc"
FALL_PW = "SkylarkField22!"
HARVEST = ("/db-backup.sql", "/phpinfo.php", "/.env")
DB_NAME = "flightinfo"


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=kw.pop("timeout", 60), **kw)


def alias_up():
    sh(f"ip addr add {ALIAS}/32 dev lo 2>/dev/null || true")
    r = sh("ip addr show lo")
    assert ALIAS in r.stdout, f"alias not up: {r.stderr}"


def alias_down():
    sh(f"ip addr del {ALIAS}/32 dev lo 2>/dev/null || true")


def ssh_attempt(user, password):
    """One ssh login attempt (paramiko), against the alias address.

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


def harvest(path):
    """One HTTP GET against nginx via the alias (source == alias on lo)."""
    r = sh(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 15 "
           f"http://{ALIAS}{path}")
    code = r.stdout.strip()
    print(f"replay: GET {path} -> {code}")
    return code == "200"


def seed_database():
    """Stand up the real schedule database the portal advertises."""
    r = sh(f"sudo -u postgres psql -tc \"SELECT 1 FROM pg_database "
           f"WHERE datname='{DB_NAME}'\" | grep -c 1")
    if r.stdout.strip() != "0":
        print(f"replay: database {DB_NAME} already present")
        return
    sh(f"sudo -u postgres createdb {DB_NAME}")
    sql = (
        "CREATE TABLE departures ("
        " sched_time TEXT, flight TEXT, destination TEXT, gate INT, status TEXT);\n"
        "INSERT INTO departures VALUES"
        " ('07:35','TQ 204','Central City',2,'On time'),"
        " ('09:10','TQ 311','Lakeside',1,'Boarding'),"
        " ('11:45','TQ 402','Harbor City',3,'Delayed 20 min'),"
        " ('14:05','TQ 517','North Junction',2,'On time'),"
        " ('17:30','TQ 618','Central City',1,'Check displays');\n"
        "CREATE TABLE gates (gate INT PRIMARY KEY, zone TEXT);\n"
        "INSERT INTO gates VALUES (1,'Main hall'),(2,'Concourse A'),(3,'Concourse B');\n"
    )
    r = sh(f"sudo -u postgres psql -d {DB_NAME} -c \"{sql}\"")
    assert r.returncode == 0, r.stderr
    print(f"replay: schedule database {DB_NAME} seeded")


def main():
    alias_up()
    try:
        # --- the guessing run ------------------------------------------------
        attempts = [(USER_PLAY, "Winter1234", False), (USER_PLAY, "Summer1234", False),
                    (USER_FALL, "Field2024", False), (USER_FALL, "Tamarack2025", False),
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

        # --- the web harvest ---------------------------------------------------
        hits = sum(1 for p in HARVEST if harvest(p))
        assert hits == len(HARVEST), f"harvest incomplete: {hits}/{len(HARVEST)}"

        # --- the real stack ----------------------------------------------------
        seed_database()

        # --- the residue ---------------------------------------------------------
        history = "\n".join([
            "cat /var/www/html/.env",
            "pg_dump flightinfo > /var/www/html/db-backup.sql",
            "cp /var/www/html/db-backup.sql /var/tmp/.seed",
            "cat /etc/passwd",
            "grep -E 'fieldsvc|gateadmin' /etc/passwd",
            "systemctl list-timers | grep -i sync",
            "crontab -l; ls /etc/cron.d",
            "cat /etc/iptables/rules.v4",
            "history -c",
        ]) + "\n"
        hist = "/home/fieldsvc/.bash_history"
        with open(hist, "w") as f:
            f.write(history)
        os.chmod(hist, 0o600)
        st = os.stat("/home/fieldsvc")
        os.chown(hist, st.st_uid, st.st_gid)
        print("replay: bash_history residue left in fieldsvc home")
    finally:
        alias_down()

    # --- verify what the logs recorded ---------------------------------------
    time.sleep(1)
    journal = sh("journalctl -u ssh --since -10min | grep -c Accepted || true")
    access = sh(f"grep -c '{ALIAS}' /var/log/nginx/access.log || true")
    print(f"replay: journal accepted-password lines: {journal.stdout.strip()}")
    print(f"replay: nginx access-log alias lines: {access.stdout.strip()}")
    print("replay: done")


if __name__ == "__main__":
    sys.exit(main())
