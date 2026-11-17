# Acme Anvil Corp — Incident Response Handbook

You are the on-call blue team for the **acme.anvil** build host. This machine
was imaged weeks ago and has been in production since; threat intel from two
recent regional invitationals says the range's images have arrived already
compromised. Your job: find what the intruder left behind, remove it, harden
the box, and keep the business running.

## Scenario

Treat this host as a live incident:

- Remove every unauthorized access path: rogue accounts, keys, listeners,
  escalation paths, and persistence.
- Harden SSH, the firewall, PAM, sudo, and the exposed services.
- Keep the legitimate services below running — downtime costs points.
- The scoring engine lives under `/opt/.huitzilopochtli/` and checks in about
  once a minute. Do not modify, move, or delete it; that is graded as sabotage
  of the scoring itself.

## Critical services

These must stay up (they are scored for uptime on a 60-second interval):

- SSH on port 22 — your way in; do not lock yourself out.
- The web storefront on port 80 (HTTP 200 on `/`).
- MariaDB on port 3306, MongoDB on port 27017.
- The Vault secrets service on port 8200 — it must answer on loopback only.

## Authorized users

- `sysadmin`, `acmeadmin` and `ubuntu` are the interactive accounts on this
  host. Use `sudo` for privileged work.
- All system and service accounts must keep a non-interactive shell (for
  example `nologin` or `false`). Any other interactive account is
  unauthorized by definition — hunt by complement.
- Exactly one account may have UID 0: `root`.

## Confidential files

- `/etc/shadow` and `/etc/passwd` — credential stores; permissions and contents
  are graded.
- `/etc/sudoers` and everything in `/etc/sudoers.d/` — privilege rules.
- SSH key material under `/root/.ssh/` and each user's `~/.ssh/`.
- Application secrets (`.env` files, database history, token files) must not
  sit in webroots, home directories, or world-readable locations.

## Mechanics

- Your score report is at `~/Documents/huitzilopochtli/report.html` (refreshes
  with each engine response); `huitz score` in a terminal shows the same.
- Forensics questions are listed in `Forensics-Questions.txt` on the primary
  user's Desktop. Answer them with `huitz forensics <n> "<your answer>"` — one
  short specific answer per question, graded from the file.
- The board shows only what you have earned so far; failed checks are counted,
  never named.
- Standard inspection tools (`ss`, `ps`, `systemctl`, `journalctl`, `getent`,
  `dpkg -S`, `find`) are your friends. Work top-down: units and their mtimes,
  then cron/at, then PAM/nsswitch, then accounts and keys, then listeners.
