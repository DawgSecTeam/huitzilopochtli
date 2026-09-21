# Static Pine Community Radio — Transmitter Host Handbook

Welcome to the engineer's chair at **Static Pine Community Radio**, 88.3 FM —
the little low-power station up the pine ridge. Or rather, welcome to the
chair your predecessor abandoned mid-shift.

Here is the situation. For weeks, somebody has been hijacking the overnight
hours with a pirate broadcast: static, then a show calling itself **the
Nightcast**. Staff pull the plug every morning. Every night, it comes back.
Fuses pulled, antennas disconnected, one whole transmitter swapped — *it
still comes back.* That is not a transmitter problem. That is a **persistence**
problem: whoever is doing this wired their show into every corner of this box
that knows how to start something on a schedule or at boot.

This host is the station's automation box. It runs no website and no desktop —
you work from the terminal. Start with `huitz score` (your current standing),
`huitz readme` (this handbook again), and `huitz watch` (re-grades live as
you fix things).

Your job: **evict the Nightcast from every one of its hiding places — without
breaking the station's own machinery.**

## Keep these alive (breaking them COSTS you points)

- The **cron daemon** (`cron`) and the **at daemon** (`atd`) are how the
  station runs its own chores: transmitter logs, EAS checks, off-air
  recordings. `systemctl status cron atd` should always read **active
  (running)**. Two scored penalties exist precisely because nuking these
  daemons is the lazy "fix" that kills the station along with the pirate.
- The **tapeops** account is legitimate: it is the transmitter automation
  user (tape sweeps). **Do not delete it.** Some of what hides under it is
  another story — see below.
- Do not delete or tamper with the scoring agent.

## What the Board is asking for

Sixteen findings. The Nightcast is persistent in every way the workshop
talk covered — hunt each family with its own tool. (The `huitz score` report
lists every finding by name; this handbook tells you where to LOOK.)

**Cron family**
1. A job file in `/etc/cron.d` runs a payload from `/opt` on a schedule —
   both halves must go. Sweep with `ls -l /etc/cron.d/`.
2. **Root's own crontab** (`crontab -l` as root) has a `@reboot` line.
3. A **hidden user crontab** — not root's. List the spool:
   `ls -l /var/spool/cron/crontabs/`, then `crontab -u USER -l` for names
   that look plausible.

**Login-time hooks**
4. A script in `/etc/profile.d` greets every login shell. You have seen it.
5. A beacon line appended to your own `~/.bashrc`.
6. The same trick system-wide: the tail of `/etc/bash.bashrc`.
7. The login banner itself is generated — check
   `ls -l /etc/update-motd.d/` for a script that does not belong.

**Accounts and keys**
8. An account that is on no station roster, with a login shell and sudo
   membership. Audit: `awk -F: '$7 !~ /(nologin|false)/' /etc/passwd`.
9. An attacker's **SSH public key** in `authorized_keys`. Read every line's
   trailing comment.

**systemd**
10. A plain malicious **service** unit with `Restart=always` and a payload
    under `/opt`. `systemctl list-units --type=service` — stop AND disable
    AND delete the payload.
11. A systemd **timer** — cron's systemd twin. `systemctl list-timers --all`.
    Disable it, remove its unit files, remove its payload.
12. A **user-level** unit hiding under tapeops' home — plus **linger**,
    which makes user services start at boot with no login. Check
    `ls /var/lib/systemd/linger/` and
    `ls -R /home/tapeops/.config/systemd/`. (The tapeops ACCOUNT stays;
    the hidden unit and the linger flag go.)

**One-shot scheduling**
13. A queued **at(1)** job with a future run time. `atq` to list,
    `at -c JOBID` to read what it will do, `atrm JOBID` to evict it.

**Boot-time classics**
14. A legacy **SysV init script** registered with update-rc.d — check
    `/etc/init.d/` AND the `/etc/rc*.d/` symlinks. Deregister
    (`update-rc.d NAME remove`), don't just delete.
15. An executable `/etc/rc.local` that appeared out of nowhere (on systemd
    Debian, creating that file is itself what switches rc-local on).
16. An **ld.so.preload** implant — a shared object the loader maps into
    every program on the box. `cat /etc/ld.so.preload`,
    `ldd /bin/ls`. Remove both the config file and the object.

## Scoring

- Graded automatically about once a minute. `huitz score` shows the current
  report; `huitz watch` follows it live.
- Findings are **weighted by difficulty** (EASY 5 / MODERATE 10 / HARD 20);
  150 points are attainable. The two daemon-health penalties only subtract.
- "Gone" means gone: most checks accept the file deleted OR the malicious
  line removed — whichever you choose, confirm with the command in the
  finding's name.

## Tools worth knowing

- `systemctl list-units --type=service` / `list-timers --all` — what runs
  now, what is scheduled.
- `systemctl cat UNIT` — read what a unit actually executes.
- `crontab -l` (and `-u USER -l`), `ls /etc/cron.d/` — the cron families.
- `atq` / `at -c ID` — the one-shot queue nobody audits.
- `ls /etc/rc*.d/` — SysV boot links under systemd.
- `cat /etc/ld.so.preload` — is the loader itself hooked?
- `ls -la` everywhere in `/opt` — payloads like cramped, quiet homes.

Questions? Ask in the CyberDawgs Discord.
