# Template prep artifacts (headless Debian 13 mail-server box)

What TEMPLATE PREP bakes in before any nakon plant (see box.yaml header for
the full build loop). These files are deployed, not scored — they are the
box's legitimate mail stack, its evidence trail, and the redtag incident
replay. ORDER IS LOAD-BEARING: the weak stack must be LIVE for the replay
(80) to write real log lines, the rotation (85) must run BEFORE the
sabotage (90) — it is what saves the relay blast from the wiper cron — and
the sabotage must run LAST so the box is handed over exactly as the story
left it.

## Run order (as root; stage the prep dir at /root/broadneck-prep)

1. `01-packages.sh` — apt stack: postfix, dovecot-core, dovecot-imapd,
   dovecot-pop3d, rsyslog, python3-paramiko (the replay), curl. Ensures
   rsyslog is enabled (the flat mail/auth logs exist so the wiper has
   something to wipe and the rotation has something to save).
2. `02-accounts.sh` — postmaster (sudo, the player), dispatch/routes/
   freight (mail users with passwords — dovecot auths via PAM),
   routeaudit (ex-contractor, weak password `AutumnRoute88`, the entry
   point), hostname broadneck-mailer, tz America/New_York, sshd drop-in
   keeping password auth on for REGULAR users, root password for the
   replay, stray sysadmin/ubuntu users deleted, persistent journald
   (/var/log/journal) so the ssh story survives the auth.log truncation.
3. `03-mailstack.sh` — the WEAK contractor-era stack: postfix open relay
   (mynetworks 0.0.0.0/0, relay restrictions that never refuse), version-
   leaking banner, VRFY on; dovecot ssl=yes (not required), plaintext auth
   allowed, cleartext 143/110 open; the depot self-signed cert pair in
   /etc/ssl/depot-mail; Maildirs for all four accounts with seeded depot
   mail (seed-mail.py); both services enabled + started and smoke-tested.
4. `80-redtag-replay.py` — THE BREAK-IN (see its docstring): loopback
   alias 198.51.100.23, ssh guessing run (2 fails vs postmaster, 3 fails
   vs routeaudit, 1 success via paramiko), the 40-message relay blast
   (one SMTP connection per message, EHLO glittercrate.buzz, bound to the
   alias so the logs record the outside address), the lure copy delivered
   back in to freight (sendmail/pickup — deliberately no client line, so
   mail.log.1 shows EXACTLY 40 alias-address lines), dispatch's mailbox
   packed to /var/backups/mailroom-export-2026-10-17.tar.gz, the .forward
   planted on postmaster, the /etc/aliases pipe backdoor
   (routesupport -> /usr/local/libexec/.queue-flush) + newaliases, and the
   intruder's partially-cleared .bash_history left in routeaudit's home.
5. `85-rotate-logs.sh` — mv /var/log/mail.log -> mail.log.1 + HUP rsyslog.
   THE step that defeats the wiper: the rotation copy keeps the whole
   blast (40 alias-address client lines — the script verifies the count);
   the live file the cron keeps truncating is the fresh one.
6. `90-sabotage.sh` — stop postfix, `postsuper -d ALL` (clear the blast
   remnants), start again, send the LAST lure copy to an outside address
   over SMTP from the alias (the held message — its Received header is a
   forensics answer), `postsuper -h ALL` to freeze exactly one message in
   the hold queue (verified), then stop + disable + MASK postfix/dovecot,
   DELETE /etc/postfix /etc/dovecot /etc/ssl/depot-mail, truncate the
   live mail.log + auth.log (mail.log.1 and the journal are untouched —
   the intruder missed the rotation copy), and write the backdoored
   /root/.mail-restore kit (the old open-relay main.cf with helpful
   comments).

SNAPSHOT AFTER ALL SIX STEPS (a pre-deploy snapshot does not cover prep),
then compile/plant/install per boxbuilder. The nakon plants land after
the snapshot: the wiper cron starts truncating the live mail.log every
minute from then on — that is the finding working, not a build failure.

## The evidence sources players correlate

- `/var/log/mail.log.1` — the relay blast: 40 `client=glittercrate.buzz
  [198.51.100.23]` lines (the count answer), message-id/from= lines (the
  sender-domain answers). The live mail.log is the wiper's victim.
- journald (`journalctl -u ssh`) — the guessing run and the accepted
  password for routeaudit (the flat auth.log was truncated).
- `lastb` / `last` (wtmp/btmp) — failed vs successful logins; the wiper
  never touched the binary ledgers.
- the held queue message (`postqueue -p` after the rebuild, `postcat -vq
  <id>`, or read /var/spool/postfix/hold/ directly) — the Received chain
  with the originating client IP.
- freight's Maildir — the delivered lure copy.
- `/home/routeaudit/.bash_history` — the interception phase: the tarball,
  the .forward, the alias, the restore-kit stash.
- `/var/log/apt/history.log` — the swaks install (planted post-snapshot;
  its timestamp is plant time — close enough to the story's same-day).
- `/root/.mail-restore/` — the kit itself (path + backdoored parameter).
- `systemctl cat redtag-harvest.timer` — the 20min re-fire cadence.

## Accounts after prep

- `postmaster` (uid ≥1000, sudo, bash, ~/Desktop) — the player.
- `dispatch`, `routes`, `freight` (mail users, nologin shell, PAM
  passwords = username) — the mailbox owners; KEEP (dovecot auths them).
- `routeaudit` (bash, password `AutumnRoute88`) — the entry point; its
  home holds the bash_history evidence. Players remove or lock it.
- `root` password `BroadneckRoot2026!` — the replay's privilege; changing
  it is good practice but unscored.

## Verification before snapshot

- `ls /etc/postfix /etc/dovecot` FAILS (both gone); `systemctl is-enabled
  postfix dovecot` reports `masked` for both.
- `mailq` (run BEFORE the config deletion — it is captured in 90's own
  verification) showed exactly ONE held message with `!`.
- `grep -c '198.51.100.23' /var/log/mail.log.1` prints 40.
- `ls /var/log/mail.log` exists (empty — rsyslog recreated it).
- `cat /home/postmaster/.forward` shows the drop address; `postmap -q
  routesupport hash:/etc/aliases.db` returns the pipe.
- `ls /var/spool/postfix/hold/` shows exactly one queue file.
- journalctl -u ssh shows the guessing run ending in an accepted password
  for routeaudit from 198.51.100.23.
