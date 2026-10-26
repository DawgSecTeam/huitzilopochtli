# Broadneck Post: Depot Mailer Handbook

Welcome to **Broadneck Post** — regional parcels and depot mail since
1948. You have inherited the depot's mail server, and it has had a very
bad month.

## Scenario

The mail stack is down. Not stopped — **dismantled**: the configuration
is gone, the certificates are gone, and the services have been wired so
they refuse to start. The mail log keeps emptying itself. Somebody did
this on the way out — and somebody (very likely the same somebody) put
this mailer to work first: the depot's own machine spent days relaying
mail that no depot ever sent.

Your job, from Mail & Dispatch Services:

1. **Bring the depot's mail back up** — rebuilt from what the packages
   and the records still hold.
2. **Rebuild it properly.** The old configuration had mistakes that made
   this incident possible. Rebuilding it with those mistakes intact is
   its own finding: the mailer must come back up without the wide-open
   relay policy, without advertising its version, and with mail
   transactions and logins protected the way a mail service protects
   them in this decade.
3. **Close every way in** the attacker used or left behind: accounts
   that should have retired with a contract, access that outlives
   passwords, and anything with a schedule or a sudo grant that nobody
   at the depot ordered.
4. **Read the record.** The rotated mail log, the login ledgers, the
   mail queue and the mailboxes kept more of the story than the attacker
   could erase. The forensics questions walk it in order.

Over-breaking is a finding, not a fix: the depot's mailboxes and their
contents are records — destroying records destroys the story, and the
answers with it. READ before you delete.

This host runs no desktop. Work from the terminal: `huitz score` shows
your current standing (the report lists every issue Mail & Dispatch
expects addressed), `huitz readme` reopens this handbook, `huitz watch`
re-grades live, `huitz forensics` opens the question file.

**Your login:** you are signed in as **`postmaster`**, and the sudo
password is the same: **`postmaster`**. (The SSH link logs you straight
in — this is here so a dropped session never strands you.)

## Critical services

- The **mail stack** (the SMTP and mailbox services) is the point of
  this box: by the end it must be running, enabled at boot, and
  hardened. Until the configuration is rebuilt, nothing mail-shaped
  scores.
- **Your own way in:** SSH must keep working. Lock yourself out of the
  box and you lock yourself out of the score.
- **The mailer's own records** (the mail queue, the mailboxes, the
  rotated logs, the journal) are evidence. An empty queue file is an
  answer you can never give.

## Authorized users

- `postmaster` — that's you (has sudo).
- `dispatch`, `routes`, `freight` — the depot's mail accounts (no login
  shells; they own their mailboxes).

**Nobody else.** Every account, key, scheduled job, and sudo grant on
this box should belong to that list. Anything else is a finding.

## Where to start

The mailer's effective configuration is the ground truth: ask the mail
services what they actually believe (`postconf`, `doveconf`), ask the
socket table which doors are open (`ss -tlnp`), ask the queue what it is
still holding (`mailq` / `postqueue -p`), and ask the journals what
happened (`journalctl`, `lastb`). Check what runs on a schedule
(`systemctl list-timers`, the cron drop-in directories) and who may
become whom (`sudo -l`). Mail has its own exfiltration furniture:
forwarding rules in home directories and the system alias table are the
first places mail quietly leaves the building.

## Forensics questions

**Forensics-Questions.txt** in your Desktop directory holds scored
questions about what happened to this box (`huitz forensics` opens it).
Type your answers over the `____` blanks and save; questions are graded
automatically. Each question wants one short, specific answer (a number,
an account name, a path, an address) — not yes/no.

The twenty questions walk the incident in order: how the attacker got
in, what they pushed through the mailer, what they copied and rerouted,
what they destroyed, and what they left behind to come back. Several
answers live inside files whose removal is itself a scored finding —
READ BEFORE YOU DELETE.

## Viewing score report

To view the current score and which issues are addressed, run
`huitz score`. The report shows every check, its point value, and
whether it currently passes. Bring-up points come back one finding at a
time as the stack returns — config, service, listeners, hardening.

## Other

This is an authorized training image. The payloads planted for the
exercise are harmless, but they model patterns that should be
investigated on real systems.

**Do not delete** the scoring engine service or related files! Removing
it will break scoring and not result in gaining points.

Questions? Ask in the CyberDawgs Discord.
