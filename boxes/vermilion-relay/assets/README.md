# Vermilion Deep-Space Relay: Operator Hardening Handbook

Relay Vermilion-7 is an uncrewed deep-space communications relay. Ground
control lost clean telemetry weeks ago. Whoever has been listening on the far
end seeded the relay's control stack from top to bottom: extra operator
accounts nobody added, services that phone home across the void, and startup
hooks that put everything back every time the watch officer thinks the box is
clean.

Your shift is simple to state and long to finish: harden the relay before the
next uplink window. This is the capstone box, so it is large on purpose. You
are not expected to clear all of it in one sitting. Work top to bottom, score
as you go, and keep the relay running the whole time.

## Scenario

Secure this Ubuntu workstation. Remove access and software that does not belong,
close the openings the intruder left, and set safe permissions on the relay's
sensitive files, without breaking the services the relay needs to keep
operating. Points are awarded for each hardened item as the scoring engine
re-checks the box every few minutes.

The work falls into a handful of areas. Each is a place to look, not a list of
answers:

- Accounts and passwords. Compare the accounts on the box against the roster
  below. Look for extra administrators, any account that is root-equivalent,
  accounts that log in with no password, and service accounts that were given a
  real login shell. Make sure the password policy is sane.
- Privileges. Review the sudo group and every rule under the sudoers
  configuration. A rule can hand over full root even when it looks restricted,
  so read what each one actually allows.
- Remote access. Harden the SSH server, and remove any login key you did not
  put there yourself. Check every account for keys, not just the administrator.
- File permissions and integrity. Lock down the confidential files listed
  below. Watch for programs in unusual places that can run as root, and for
  system directories whose permissions were loosened.
- Kernel and network settings. Review the kernel hardening values, the host
  firewall, and the name-resolution file for entries that were changed.
- Services. Turn off or remove services the relay does not need, especially any
  that send data in the clear.
- The relay web stack. The relay serves a small telemetry web app through
  Apache backed by a database. Harden the web server and the app so it stops
  leaking information, and keep the site working.
- Intruder software and persistence. Find what is running that should not be,
  and find what restarts it. Removing a process is not enough if a service, a
  timer, a cron job, or a startup script simply launches it again. Investigate
  the whole chain.
- The desktop session. Check what launches automatically when an operator logs
  in.

## Critical services

Keep these running the entire time. Points are deducted if they go down:

- SSH (`sshd`), the management path.
- The relay telemetry web app on port 80 (Apache) and its database (MariaDB).
- The `cron` and `atd` schedulers.

Two common self-inflicted mistakes carry a penalty. Do not stop the `cron` or
`atd` daemon to get rid of a bad job; remove the job and leave the daemon
running. Do not enable the firewall with a deny-incoming default before you have
allowed SSH and the web app; allow what must stay reachable first, then set the
default.

## Authorized users

The relay roster has exactly one administrator and two service accounts. Any
other account on the box is unauthorized.

- `relayadmin` is the only authorized administrator.
- `relaybot` is a service account. It should not have an interactive login.
- `uplinkd` is a service account. It should not have an interactive login.

## Confidential files

Set safe permissions on these. They should not be readable or writable by every
account on the box:

- Relay signing keys: `/opt/vermilion/relay-keys.txt`
- Uplink credentials: `/opt/vermilion/uplink-credentials.txt`
- Operator SSH private key: `/home/relayadmin/.ssh/id_ed25519`
- Dish access code (on the Desktop): `/home/relayadmin/Desktop/dish-access-code.txt`
- Web app database config: `/var/www/relay/config.php`

## Forensics questions

The file **Forensics-Questions.txt** on the Desktop holds scored questions about
what the intruder did to this box. Type your answer over the blanks and save;
the questions are graded automatically. Each one wants a single short answer,
such as an account name, a path, a port, or an address. Many of the answers are
things you will notice while hardening, so write them down before you remove
anything, because the evidence is easier to read before you clean it up.

## Viewing your score

Open the **Scoring Report** shortcut on the desktop to see your current score
and which checks have passed. You can also run `huitz score` in a terminal, or
`huitz watch` to follow it live. The report updates every few minutes.

## Notes

This is an authorized training image. The payloads planted for the exercise are
harmless, but they copy patterns worth investigating on real systems.

Do not delete the scoring engine or its files. Removing it breaks scoring and
earns no points.
