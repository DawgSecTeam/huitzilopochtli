# Template prep artifacts (headless Debian 13 IR box)

What TEMPLATE PREP bakes in before any nakon plant (see box.yaml header for
the full build loop). These files are deployed, not scored — they are the
box's legitimate service stack plus its flight recorders. The IR premise of
the box depends on ORDER: the evidence sources exist and the attacker
replay runs BEFORE `plant`, so the intrusion reads as something that
happened days ago on a box that was already logging.

## Run order (as root; stage the prep dir at /root/lantern-prep)

1. `01-packages.sh` — apt stack: apache2, mariadb-server, python3(+flask,
   pymysql, paramiko), auditd, rsyslog, curl. Enables rsyslog (the classic
   flat logs exist so the anti-forensics plant has something to wipe).
2. `02-accounts.sh` — creates `librarian` (sudo, the player) +
   `catalogsvc` (app service identity, KEEP), sets hostname
   `lanternhill-catalog`, timezone America/New_York, writes the PRE-BAKED
   weak sshd drop-in (`99-catalog-remote.conf`: PermitRootLogin yes et al.),
   sets the root password the brute force will find, and deletes the base
   template's stray `sysadmin`/`ubuntu` users (opochtli lesson: a stray
   uid-1000 hijacks forensics-path resolution). From here on the box is
   reached as `librarian`/`librarian` only.
3. `03-database.sh` — `library` DB (books/patrons/holds + seed data),
   least-privilege `library_app` account, and MariaDB general query log ON
   → `/var/log/mysql/general.log` (the DB's flight recorder).
4. `04-app.sh` — deploys `app.py` to `/opt/library`, installs
   `library-app.service` (User=catalogsvc, stdout → journald) and the
   apache :80 reverse proxy. Smoke-tests the catalog end to end.
5. `05-auditd-journal.sh` — auditd + `75-library-ir.rules` loaded via
   `augenrules --load` (watched paths: identities, sudoers, sshd config,
   .ssh, cron, systemd units, ld.so.preload, hosts, /opt, /var/backups +
   identity/time-change syscalls) and persistent journald
   (`/var/log/journal`) so ALL sources survive reboot and seal.
6. `90-attacker-replay.py` — the break-in (see its docstring): loopback
   alias 203.0.113.7, ssh password-guessing run (4 fails → success for the
   compromised account), then the web session (spoofed X-Forwarded-For,
   patrons export + three hold cancellations through the unauthenticated
   admin hook). The holds rows really change; the app journal and the DB
   query log really record it.

SNAPSHOT AFTER ALL SIX STEPS (pre-deploy snapshot does not cover prep),
then compile/plant/install per boxbuilder. The plants then land under
auditd's watched paths — the artifacts write their own audit trail.

## The four evidence sources players correlate

- `journalctl -u ssh` (and the rsyslog flat log while it still has data) —
  the brute force and the successful password login from 203.0.113.7.
- `journalctl -u library-app` — every catalog request with the (spoofable)
  client IP, including the plugin hot-load line once the rogue module is
  dropped in.
- `/var/log/mysql/general.log` — the exact SQL: the export SELECT, the
  tamper UPDATEs, and (live, until evicted) the cron/timer payloads'
  recurring UPDATEs.
- `/var/log/audit/audit.log` — keyed watches (NOTE: this Debian 13 audit build needs the explicit
  input flag -- plain `ausearch -k X` returns "<no matches>"; use
  `ausearch --input /var/log/audit/audit.log -k identity |
  sched | units | optdrop | staging | time-change -i`) covering every
  planted artifact and the clock tamper.

## Accounts after prep

- `librarian` (uid ≥1000, sudo, bash, ~/Desktop) — the player.
- `catalogsvc` (system account, nologin) — the app's identity; KEEP.
- `root` password `LanternHill2026!` — the "leaked" credential the replay
  uses; changing it is good practice but unscored.

## Verification before snapshot

- `curl -fsS http://127.0.0.1/` renders the catalog; `/holds` shows rows.
- `journalctl -u library-app | tail` shows access lines incl. the replay's
  203.0.113.7 requests.
- `tail /var/log/mysql/general.log` shows the SELECT/UPDATE trail.
- `auditctl -l | wc -l` ≥ 18; `ausearch --input /var/log/audit/audit.log -k time-change -i`
  shows the later
  plant's clock tamper once it has run.
- `ssh -o StrictHostKeyChecking=no root@203.0.113.7` (wrong password) from
  the box lands in the journal with that source — proves the alias path.
- `grep 203.0.113.7 /etc/hosts` still shows the redirect AFTER a fresh
  clone's first boot (prep disables cloud-init's per-instance
  manage_etc_hosts; if that regresses, the redirect finding self-heals on
  every shipped clone).
