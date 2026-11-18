# Tamarack Regional Airport — Flight Information Display Server

You are the operations security team for Tamarack Regional Airport. The
server in front of you drives the terminal's flight information displays:
it serves the public departures portal, stores the schedule database, and
feeds the display boards. An outside contractor who helped build the
display system lost the airport's business last month — but apparently
never lost access. Since then, boards have frozen, the portal has been
slow, and a backup nobody remembers making has appeared on the public
site. Remove every trace of the intruder's access, harden the services
this box runs, and put the display system back in the airport's hands.

## Scenario

- Audit every account on this box against the roster below and remove the
  unauthorized ones — the intruder relied on more than one way back in,
  and one of them fights back when you remove it.
- Hunt for persistence: the intruder left several independent ways to
  return, at least one of which quietly repairs the others' removal.
- Harden the remote-access service: it currently tolerates far too much,
  including direct superuser login and unlimited guessing.
- The display stack must survive your work: the portal, the schedule
  database, and the board message queue all have to stay reachable, and
  the web root must stop leaking what does not belong on a public page.
- The display feed directory and this server's boot configuration are
  more permissive than they should be; tighten them.
- Restore the account, password, and audit policy basics a
  responsibility like this one expects.

The `flightops` password does not need to be changed, and password
logins for regular users are how the operations desk works — do not lock
the desk out of its own server.

## Critical services

Do not stop or uninstall these — the terminal's boards depend on them,
and breaking them costs points: the web server publishing the portal,
the schedule database, the board message queue, and the SSH service the
operations desk uses.

## Authorized users

- **flightops** — operations desk lead (your account; administrator)
- **root** — the system account
- **svc-boards** — the display renderer service identity (it exists to
  run one job, not to log in)

Any other account that can log in is unauthorized. The intruder's
accounts may look official — read who created them and why before
deciding what stays.

## Confidential files

- `/var/www/html/` — the public portal root. It publishes the departures
  board; nothing else belongs there.
- `/srv/fids/feed/` — the display board feed the renderers pull from.
- `/etc/shadow` — account credentials; nothing in this incident should
  ever have copied it anywhere.
- The schedule database — it holds the airport's operating data.

## Mechanics

- Run `huitz score` at any time for your standing; the report names each
  finding as it is earned or lost.
- Forensics questions are graded from `~/Desktop/Forensics-Questions.txt`
  (also readable with `huitz readme`): record short, specific answers
  with `huitz forensics <n> "<answer>"`. One attempt per question is
  normal — read the box, then answer.
- Do not delete, stop, or modify the scoring engine or anything under
  `/opt/.huitzilopochtli`. It is the grader, not an intruder artifact.

Good hunting. The boards are counting on you.
