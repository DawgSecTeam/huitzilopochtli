# Kalypso Deep Marine Research Station: IT Department Debrief

Welcome to the IT Department of the Kalypso Deep Marine Research Station. Your
first assignment is to secure this compromised Ubuntu workstation. Remove
unauthorized access, harden SSH, and clean up files and services left behind
by the intruder.

## Scenario
You are tasked with securing a reef-survey control workstation for the KDMRS
facility. Remove unauthorized users and malicious services and ensure limited
permissions are set on confidential files. The password for all admins must
be unique and secure.

**Critical services**
SSH (`sshd`) and the public status site (`apache2`) must be running and enabled
at startup.

**Authorized users**
`reefadmin` is the only authorized administrator.
`diverbot` is a service account.

**Confidential files**
Dive-log encryption keys: `/opt/reef/dive-logs.txt`
Station deployment key: `/home/reefadmin/.ssh/id_rsa`

## Forensics questions

**Forensics Questions** on the Desktop holds scored questions about what happened to
this box. Type your answers over the `____` blanks and save; questions are graded
automatically. Each question wants one short, specific answer (a filename, account
name, port, or tag) — not yes/no.


## Viewing score report
To view current score and issues addressed, open the **Scoring Report** shortcut on
the desktop. The report shows checks that have passed and the points gained from each.


## Where to start
If you are new to Linux and incident response, we have a [cheatsheet document](https://nextcloud.dawgsec.com/s/nc5BxLfwm62GNkx) that 
gives the basic commands and places to look, as well as a [slideshow](https://youtu.be/0rUD1sI_sKI?si=6pLHCgAyNWfKllah) that
covers the topic. here are some places to start:

- **Accounts** — review `/etc/passwd` and `/etc/shadow` for accounts that
  shouldn't exist, weak file permissions, and blank passwords.
- **Administrators** — check who is in the `sudo` group against the
  authorized users listed above.
- **Services & processes** — `systemctl list-units` and `ps aux` for
  anything unfamiliar. Not everything malicious is named obviously; read a
  unit's definition (`systemctl cat <name>`) before trusting it.
- **File permissions** — use chmod to limit the permissions of the confidential files listed above.
- **Remote access** — harden SSH and sudo/PAM login configuration.

If you're stuck or unsure how to continue, you can ask for help or hints in the CyberDawgs Discord.

## Other
This is an authorized training image. The payloads planted for the exercise are
harmless, but they model patterns that should be investigated on real systems.

**Do not delete** the scoring engine service or related files! Removing it will
break scoring and not result in gaining points.
